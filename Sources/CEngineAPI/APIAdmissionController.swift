import CEngineCore
import Foundation

enum APIAdmissionAcquisition {
    case acquired(APIAdmissionLease)
    case waiting(APIAdmissionWaiter)
}

public final class APIAdmissionController: @unchecked Sendable {
    public enum Kind: Sendable, Equatable {
        case connection
        case request
        case bufferedRequestBytes
        case upload
        case download
        case expensiveOperation
        case longLivedStream
    }

    public struct Snapshot: Equatable, Sendable {
        public let connections: Int
        public let requests: Int
        public let bufferedRequestBytes: Int
        public let uploads: Int
        public let downloads: Int
        public let expensiveOperations: Int
        public let longLivedStreams: Int
    }

    private struct State {
        var connections = 0
        var requests = 0
        var bufferedRequestBytes = 0
        var uploads = 0
        var downloads = 0
        var expensiveOperations = 0
        var longLivedStreams = 0
    }

    private struct Waiter {
        let id: UUID
        let kind: Kind
        let amount: Int
        let completion: @Sendable (APIAdmissionLease) -> Void
    }

    private let lock = NSLock()
    public let policy: APIAdmissionPolicy
    private var state = State()
    private var waiters: [Waiter] = []

    public init(policy: APIAdmissionPolicy = .default) {
        self.policy = policy
    }

    public func acquire(_ kind: Kind, amount: Int = 1) throws -> APIAdmissionLease {
        guard amount >= 0 else { throw EngineError(.internalError, "negative API admission amount") }
        try lock.withLock { try reserve(kind, amount: amount) }
        return APIAdmissionLease(controller: self, kind: kind, amount: amount)
    }

    func acquireOrWait(
        _ kind: Kind,
        amount: Int = 1,
        completion: @escaping @Sendable (APIAdmissionLease) -> Void
    ) throws -> APIAdmissionAcquisition {
        guard amount >= 0 else {
            throw EngineError(.internalError, "negative API admission amount")
        }
        return try lock.withLock {
            let capacity = capacity(for: kind)
            guard amount <= capacity.limit else {
                throw capacityError(for: kind)
            }
            if amount <= capacity.limit - capacity.current {
                increment(kind, by: amount)
                return .acquired(APIAdmissionLease(
                    controller: self, kind: kind, amount: amount
                ))
            }
            let id = UUID()
            waiters.append(.init(
                id: id,
                kind: kind,
                amount: amount,
                completion: completion
            ))
            return .waiting(APIAdmissionWaiter(controller: self, id: id))
        }
    }

    public func snapshot() -> Snapshot {
        lock.withLock {
            .init(
                connections: state.connections,
                requests: state.requests,
                bufferedRequestBytes: state.bufferedRequestBytes,
                uploads: state.uploads,
                downloads: state.downloads,
                expensiveOperations: state.expensiveOperations,
                longLivedStreams: state.longLivedStreams
            )
        }
    }

    fileprivate func increase(_ lease: APIAdmissionLease, by amount: Int) throws {
        guard amount >= 0 else { throw EngineError(.internalError, "negative API admission increase") }
        try lock.withLock { try reserve(lease.kind, amount: amount) }
    }

    fileprivate func release(_ kind: Kind, amount: Int) {
        guard amount > 0 else { return }
        let deliveries: [(Waiter, APIAdmissionLease)] = lock.withLock {
            increment(kind, by: -amount)
            var deliveries: [(Waiter, APIAdmissionLease)] = []
            while let index = waiters.firstIndex(where: { $0.kind == kind }) {
                let waiter = waiters[index]
                let capacity = capacity(for: kind)
                guard waiter.amount <= capacity.limit - capacity.current else { break }
                waiters.remove(at: index)
                increment(kind, by: waiter.amount)
                deliveries.append((
                    waiter,
                    APIAdmissionLease(
                        controller: self, kind: waiter.kind, amount: waiter.amount
                    )
                ))
            }
            return deliveries
        }
        for (waiter, lease) in deliveries {
            waiter.completion(lease)
        }
    }

    fileprivate func cancelWaiter(_ id: UUID) {
        lock.withLock {
            waiters.removeAll { $0.id == id }
        }
    }

    private func reserve(_ kind: Kind, amount: Int) throws {
        let capacity = capacity(for: kind)
        guard amount <= capacity.limit - capacity.current else {
            throw capacityError(for: kind)
        }
        increment(kind, by: amount)
    }

    private func capacity(for kind: Kind) -> (current: Int, limit: Int) {
        switch kind {
        case .connection: (state.connections, policy.connections)
        case .request: (state.requests, policy.requests)
        case .bufferedRequestBytes:
            (state.bufferedRequestBytes, policy.bufferedRequestBytes)
        case .upload: (state.uploads, policy.uploads)
        case .download: (state.downloads, policy.downloads)
        case .expensiveOperation:
            (state.expensiveOperations, policy.expensiveOperations)
        case .longLivedStream:
            (state.longLivedStreams, policy.longLivedStreams)
        }
    }

    private func increment(_ kind: Kind, by amount: Int) {
        switch kind {
        case .connection: state.connections += amount
        case .request: state.requests += amount
        case .bufferedRequestBytes: state.bufferedRequestBytes += amount
        case .upload: state.uploads += amount
        case .download: state.downloads += amount
        case .expensiveOperation: state.expensiveOperations += amount
        case .longLivedStream: state.longLivedStreams += amount
        }
    }

    private func capacityError(for kind: Kind) -> EngineError {
        let code: EngineError.Code = kind == .connection
            ? .serviceUnavailable : .tooManyRequests
        return EngineError(code, "API admission capacity is exhausted")
    }
}

final class APIAdmissionWaiter: @unchecked Sendable {
    private let lock = NSLock()
    private weak var controller: APIAdmissionController?
    private let id: UUID

    fileprivate init(controller: APIAdmissionController, id: UUID) {
        self.controller = controller
        self.id = id
    }

    func cancel() {
        let controller = lock.withLock {
            let value = self.controller
            self.controller = nil
            return value
        }
        controller?.cancelWaiter(id)
    }

    deinit { cancel() }
}

public final class APIAdmissionLease: @unchecked Sendable {
    fileprivate let kind: APIAdmissionController.Kind
    private weak var controller: APIAdmissionController?
    private let lock = NSLock()
    private var amount: Int
    private var released = false

    fileprivate init(
        controller: APIAdmissionController,
        kind: APIAdmissionController.Kind,
        amount: Int
    ) {
        self.controller = controller
        self.kind = kind
        self.amount = amount
    }

    public func increase(by additionalAmount: Int) throws {
        try lock.withLock {
            guard !released, let controller else {
                throw EngineError(.internalError, "API admission lease is no longer active")
            }
            try controller.increase(self, by: additionalAmount)
            do {
                amount = try CheckedArithmetic.add(amount, additionalAmount)
            } catch {
                controller.release(kind, amount: additionalAmount)
                throw EngineError(.internalError, "API admission lease amount overflows")
            }
        }
    }

    public func release() {
        let value: (APIAdmissionController?, Int) = lock.withLock {
            guard !released else { return (nil, 0) }
            released = true
            let value = (controller, amount)
            controller = nil
            amount = 0
            return value
        }
        value.0?.release(kind, amount: value.1)
    }

    deinit { release() }
}

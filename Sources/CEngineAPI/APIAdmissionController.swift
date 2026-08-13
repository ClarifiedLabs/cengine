import CEngineCore
import Foundation

public final class APIAdmissionController: @unchecked Sendable {
    public enum Kind: Sendable {
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

    private let lock = NSLock()
    public let policy: APIAdmissionPolicy
    private var state = State()

    public init(policy: APIAdmissionPolicy = .default) {
        self.policy = policy
    }

    public func acquire(_ kind: Kind, amount: Int = 1) throws -> APIAdmissionLease {
        guard amount >= 0 else { throw EngineError(.internalError, "negative API admission amount") }
        try lock.withLock { try reserve(kind, amount: amount) }
        return APIAdmissionLease(controller: self, kind: kind, amount: amount)
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
        lock.withLock {
            switch kind {
            case .connection: state.connections -= amount
            case .request: state.requests -= amount
            case .bufferedRequestBytes: state.bufferedRequestBytes -= amount
            case .upload: state.uploads -= amount
            case .download: state.downloads -= amount
            case .expensiveOperation: state.expensiveOperations -= amount
            case .longLivedStream: state.longLivedStreams -= amount
            }
        }
    }

    private func reserve(_ kind: Kind, amount: Int) throws {
        let current: Int
        let limit: Int
        switch kind {
        case .connection: (current, limit) = (state.connections, policy.connections)
        case .request: (current, limit) = (state.requests, policy.requests)
        case .bufferedRequestBytes:
            (current, limit) = (state.bufferedRequestBytes, policy.bufferedRequestBytes)
        case .upload: (current, limit) = (state.uploads, policy.uploads)
        case .download: (current, limit) = (state.downloads, policy.downloads)
        case .expensiveOperation:
            (current, limit) = (state.expensiveOperations, policy.expensiveOperations)
        case .longLivedStream:
            (current, limit) = (state.longLivedStreams, policy.longLivedStreams)
        }
        guard amount <= limit - current else {
            let code: EngineError.Code = kind == .connection
                ? .serviceUnavailable : .tooManyRequests
            throw EngineError(code, "API admission capacity is exhausted")
        }
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

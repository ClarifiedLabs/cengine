import Foundation

/// Coordinates cengine guest PREPARE copyup within one backend. NFS `nolock`
/// does not coordinate the guests' copyup flock; this is not an application
/// lock service, cross-process lock, or permission for a second block attachment.
final class SharedVolumeInitializationCoordinator: @unchecked Sendable {
    private final class Request: @unchecked Sendable {
        let id = UUID()
        let names: Set<String>
        // Accessed only under the coordinator's lock, including cancellation
        // before the continuation is installed.
        var cancelled = false

        init(names: [String]) { self.names = Set(names) }
    }

    private struct Waiter {
        let request: Request
        let continuation: CheckedContinuation<Lease, Error>
    }

    final class Lease: Sendable {
        private let coordinator: SharedVolumeInitializationCoordinator
        private let id: UUID

        fileprivate init(coordinator: SharedVolumeInitializationCoordinator, id: UUID) {
            self.coordinator = coordinator
            self.id = id
        }

        func release() { coordinator.release(id) }
        deinit { release() }
    }

    private let lock = NSLock()
    private var active: [UUID: Set<String>] = [:]
    private var heldNames: Set<String> = []
    private var waiters: [Waiter] = []
    var waitingCount: Int { lock.withLock { waiters.count } }

    func withInitialization<Result: Sendable>(
        of names: [String],
        isolation: isolated (any Actor)? = #isolation,
        operation: () async throws -> Result
    ) async throws -> Result {
        let lease = try await acquire(names)
        defer { lease.release() }
        try Task.checkCancellation()
        let result = try await operation()
        try Task.checkCancellation()
        return result
    }

    func acquire(_ names: [String], isolation: isolated (any Actor)? = #isolation) async throws -> Lease {
        let request = Request(names: names)
        let lease = try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                let result: Result<Lease, Error>? = lock.withLock {
                    if request.cancelled { return .failure(CancellationError()) }
                    if request.names.isDisjoint(with: heldNames) {
                        return .success(reserve(request))
                    }
                    waiters.append(Waiter(request: request, continuation: continuation))
                    return nil
                }
                if let result { continuation.resume(with: result) }
            }
        } onCancel: {
            self.cancel(request)
        }
        do {
            try Task.checkCancellation()
            return lease
        } catch {
            lease.release()
            throw error
        }
    }

    // All names are reserved together: a waiter never owns a partial set, so
    // reversed mount orders cannot deadlock. Disjoint requests may bypass it.
    private func reserve(_ request: Request) -> Lease {
        active[request.id] = request.names
        heldNames.formUnion(request.names)
        return Lease(coordinator: self, id: request.id)
    }

    private func release(_ id: UUID) {
        let ready: [(Waiter, Lease)] = lock.withLock {
            guard let names = active.removeValue(forKey: id) else { return [] }
            heldNames.subtract(names)
            var ready: [(Waiter, Lease)] = []
            waiters.removeAll { waiter in
                guard waiter.request.names.isDisjoint(with: heldNames) else { return false }
                ready.append((waiter, reserve(waiter.request)))
                return true
            }
            return ready
        }
        for (waiter, lease) in ready { waiter.continuation.resume(returning: lease) }
    }

    private func cancel(_ request: Request) {
        let continuation: CheckedContinuation<Lease, Error>? = lock.withLock {
            request.cancelled = true
            guard let index = waiters.firstIndex(where: { $0.request.id == request.id }) else {
                return nil
            }
            return waiters.remove(at: index).continuation
        }
        // Never release an active PREPARE on notification alone: its guest RPC
        // must finish/unwind before another initializer can touch live staging.
        continuation?.resume(throwing: CancellationError())
    }
}

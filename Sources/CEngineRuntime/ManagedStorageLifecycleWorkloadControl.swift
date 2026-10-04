#if os(macOS)
import CEngineCore
import Foundation
import Synchronization

/// Workload control adapter. Every send is joined on the owner's
/// dedicated worker; the owner checks the physical checkpoint, HOST intents,
/// pending/sealed/terminal fences and live service before AND after child IO.
/// This adapter owns no transport, key, TLS session or recovery authority.
nonisolated final class ManagedStorageLifecycleWorkloadControl: ManagedStorageControlling, @unchecked Sendable {
    let context: ManagedStorageControlClient.Context
    private weak var owner: ManagedStorageLifecycleOwner?
    private let maintenance: ManagedStorageLifecycleOwner.MaintenanceCapability?
    private struct State {
        var revoked = false
        var active = 0
        var joiners: [CheckedContinuation<Void, Never>] = []
    }
    private let state = Mutex(State())

    init(owner: ManagedStorageLifecycleOwner, context: ManagedStorageControlClient.Context,
         maintenance: ManagedStorageLifecycleOwner.MaintenanceCapability? = nil) {
        self.owner = owner; self.context = context; self.maintenance = maintenance
    }

    func revoke() { state.withLock { $0.revoked = true } }

    /// Permanent fence; completes only after every admitted call has joined.
    func invalidate() async {
        revoke()
        await withCheckedContinuation { continuation in
            let complete = state.withLock { s -> Bool in
                if s.active == 0 { return true }
                s.joiners.append(continuation); return false
            }
            if complete { continuation.resume() }
        }
    }

    /// Blocking by protocol contract; callers run it on a dedicated thread.
    func send(_ request: ManagedStorageControlProtocol.ControlRequest) throws -> ManagedStorageControlClient.Reply {
        // The owner is MainActor-isolated; waiting here on main would deadlock.
        guard !Thread.isMainThread else { throw ManagedStorageLifecycleOwner.Failure.blocked }
        try state.withLock {
            guard !$0.revoked else { throw ManagedStorageControlClient.Failure.revoked }
            $0.active += 1
        }
        let result = Result { try join(request) }
        let (final, joiners) = state.withLock { s -> (Result<ManagedStorageControlClient.Reply, any Error>, [CheckedContinuation<Void, Never>]) in
            // Completion and revocation share one linearization point.
            let final: Result<ManagedStorageControlClient.Reply, any Error> = s.revoked ? .failure(ManagedStorageControlClient.Failure.revoked) : result
            s.active -= 1
            guard s.active == 0 else { return (final, []) }
            defer { s.joiners.removeAll() }
            return (final, s.joiners)
        }
        for joiner in joiners { joiner.resume() }
        return try final.get()
    }

    private func join(_ request: ManagedStorageControlProtocol.ControlRequest) throws -> ManagedStorageControlClient.Reply {
        let box = Mutex<Result<ManagedStorageControlClient.Reply, any Error>?>(nil)
        let done = DispatchSemaphore(value: 0)
        let expected = context
        Task { @MainActor [self] in
            let result: Result<ManagedStorageControlClient.Reply, any Error>
            if let owner {
                do { result = .success(try await owner.workloadControl(request, context: expected, maintenance: maintenance)) }
                catch { result = .failure(error) }
            } else { result = .failure(ManagedStorageLifecycleOwner.Failure.blocked) }
            box.withLock { $0 = result }
            done.signal()
        }
        done.wait()
        return try box.withLock { try $0!.get() }
    }
}

#endif

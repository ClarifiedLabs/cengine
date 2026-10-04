import CEngineCore

/// MainActor reentrancy fence for one shim's boot/stop operations. The server
/// retains the VM and attachment leases; stop's operation must prove VZ stopped
/// before dropping them. A failed stop keeps this admission fence closed.
@MainActor final class VMShimBootGate {
    private var bootTask: Task<Void, Error>?
    private var stopTask: Task<Void, Error>?
    private(set) var isStopping = false
    private var stopResponses = 0
    private var shutdownRequested = false

    /// Stop owns admission until its reply has been written, not merely until
    /// VZ teardown's task returns. Shutdown never reopens admission.
    func beginStopResponse(shutdown: Bool) {
        stopResponses += 1
        shutdownRequested = shutdownRequested || shutdown
    }

    func endStopResponse() {
        precondition(stopResponses > 0)
        stopResponses -= 1
    }

    func boot(_ operation: @escaping @MainActor () async throws -> Void) async throws {
        guard !isStopping, stopTask == nil, stopResponses == 0, !shutdownRequested else {
            throw EngineError(.conflict, "VM teardown in progress")
        }
        if let bootTask { return try await bootTask.value }
        let task = Task { @MainActor in
            defer { self.bootTask = nil }
            try await operation()
        }
        bootTask = task
        try await task.value
    }

    func stop(
        willStop: @MainActor () -> Void = {},
        _ operation: @escaping @MainActor () async throws -> Void
    ) async throws {
        if let stopTask { return try await stopTask.value }
        isStopping = true
        willStop()
        let activeBoot = bootTask
        activeBoot?.cancel()
        let task = Task { @MainActor in
            defer { self.stopTask = nil }
            // Cancellation is a request, never evidence that the guest gate or
            // VZ-start callback has settled. Join before teardown can proceed.
            if let activeBoot { _ = await activeBoot.result }
            try await operation()
            self.isStopping = false
        }
        stopTask = task
        try await task.value
    }
}

#if os(macOS)
import CEngineCore
import Foundation

@MainActor final class GuestTimeSynchronizer {
    typealias Synchronize = @MainActor @Sendable () async throws -> Void
    typealias FailureHandler = @MainActor @Sendable (Error) -> Void

    private let interval: Duration
    private let synchronize: Synchronize
    private let failureHandler: FailureHandler
    private var generation: UUID?
    private var task: Task<Void, Never>?

    init(
        interval: Duration = .seconds(30),
        synchronize: @escaping Synchronize,
        failureHandler: @escaping FailureHandler
    ) {
        self.interval = interval
        self.synchronize = synchronize
        self.failureHandler = failureHandler
    }

    func synchronizeNow() async throws {
        try await synchronize()
    }

    func startPeriodic() {
        guard task == nil else { return }
        let token = UUID()
        generation = token
        task = Task { @MainActor [weak self] in
            guard let self else { return }
            while !Task.isCancelled, generation == token {
                do {
                    try await Task.sleep(for: interval)
                } catch {
                    return
                }
                guard !Task.isCancelled, generation == token else { return }
                do {
                    try await synchronize()
                } catch {
                    guard !Task.isCancelled, generation == token else { return }
                    failureHandler(error)
                }
            }
        }
    }

    func stop() async {
        generation = nil
        guard let task else { return }
        self.task = nil
        task.cancel()
        await task.value
    }

    func cancel() {
        generation = nil
        task?.cancel()
        task = nil
    }

    var hasPeriodicTask: Bool {
        task != nil
    }
}

@MainActor enum GuestTimeSynchronizationTransaction {
    static func start<Value>(
        operation: () async throws -> Value,
        teardown: () async throws -> Void
    ) async throws -> Value {
        do {
            return try await operation()
        } catch {
            let startError = error
            do {
                try await teardown()
            } catch {
                throw BackendResourceRollbackIncompleteError(
                    "guest startup failed: \(EngineError.message(for: startError)); "
                        + "VM teardown failed: \(EngineError.message(for: error))"
                )
            }
            throw startError
        }
    }

    static func resume(
        synchronize: () async throws -> Void,
        repause: () async throws -> Void,
        contain: () async throws -> Void
    ) async throws {
        do {
            try await synchronize()
            return
        } catch {
            let synchronizationError = error
            do {
                try await repause()
            } catch {
                let rollbackError = error
                do {
                    try await contain()
                } catch {
                    throw BackendResourceRollbackIncompleteError(
                        "guest time synchronization after resume failed: "
                            + "\(EngineError.message(for: synchronizationError)); re-pause failed: "
                            + "\(EngineError.message(for: rollbackError)); VM containment failed: "
                            + EngineError.message(for: error)
                    )
                }
                throw BackendResourceRollbackIncompleteError(
                    "guest time synchronization after resume failed: "
                        + "\(EngineError.message(for: synchronizationError)); re-pause failed and the VM "
                        + "was stopped: \(EngineError.message(for: rollbackError))"
                )
            }
            throw synchronizationError
        }
    }
}
#endif

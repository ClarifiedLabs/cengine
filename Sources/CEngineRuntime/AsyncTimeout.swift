import Foundation

enum AsyncTimeout {
    static func run<T: Sendable>(seconds: Int64, operation: @escaping @Sendable () async throws -> T) async throws -> T {
        try await run(for: .seconds(seconds), operation: operation)
    }

    static func run<T: Sendable>(
        for duration: Duration,
        operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        let gate = Gate<T>()
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                gate.install(continuation)
                let operationTask = Task {
                    do { gate.resume(.success(try await operation())) }
                    catch { gate.resume(.failure(error)) }
                }
                let timeoutTask = Task {
                    do {
                        try await Task.sleep(for: duration)
                        gate.resume(.failure(TimeoutError()))
                    } catch { }
                }
                gate.install(operation: operationTask, timeout: timeoutTask)
            }
        } onCancel: {
            gate.resume(.failure(CancellationError()))
        }
    }

    struct TimeoutError: Error {}

    private final class Gate<T: Sendable>: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<T, Error>?
        private var operation: Task<Void, Never>?
        private var timeout: Task<Void, Never>?
        private var terminalResult: Result<T, Error>?

        func install(_ continuation: CheckedContinuation<T, Error>) {
            lock.lock()
            if let terminalResult {
                lock.unlock()
                continuation.resume(with: terminalResult)
                return
            }
            self.continuation = continuation
            lock.unlock()
        }

        func install(operation: Task<Void, Never>, timeout: Task<Void, Never>) {
            lock.lock()
            if terminalResult != nil {
                lock.unlock()
                operation.cancel()
                timeout.cancel()
                return
            }
            self.operation = operation
            self.timeout = timeout
            lock.unlock()
        }
        func resume(_ result: Result<T, Error>) {
            lock.lock()
            guard terminalResult == nil else { lock.unlock(); return }
            terminalResult = result
            let continuation = continuation
            self.continuation = nil
            let operation = operation
            let timeout = timeout
            self.operation = nil
            self.timeout = nil
            lock.unlock()
            operation?.cancel()
            timeout?.cancel()
            continuation?.resume(with: result)
        }
    }
}

import Foundation

enum AsyncTimeout {
    static func run<T: Sendable>(seconds: Int64, operation: @escaping @Sendable () async throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            let gate = Gate(continuation)
            Task { do { gate.resume(.success(try await operation())) } catch { gate.resume(.failure(error)) } }
            Task {
                do { try await Task.sleep(for: .seconds(seconds)); gate.resume(.failure(TimeoutError())) }
                catch { }
            }
        }
    }

    struct TimeoutError: Error {}

    private final class Gate<T: Sendable>: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<T, Error>?
        init(_ continuation: CheckedContinuation<T, Error>) { self.continuation = continuation }
        func resume(_ result: Result<T, Error>) {
            lock.lock(); guard let continuation else { lock.unlock(); return }; self.continuation = nil; lock.unlock()
            continuation.resume(with: result)
        }
    }
}

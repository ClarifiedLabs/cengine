import Darwin
import Foundation

/// Socket admission, separate from data-store ownership. Never inherited by exec'd VM shims.
public final class DaemonSocketLock {
    let descriptor: CInt

    public init(url: URL) throws {
        descriptor = Darwin.open(url.path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, S_IRUSR | S_IWUSR)
        guard descriptor >= 0 else { throw EngineError(.internalError, "could not open daemon lock at \(url.path)") }
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            Darwin.close(descriptor)
            throw EngineError(.conflict, "another cengine daemon is already running")
        }
    }

    deinit {
        // Close rather than explicitly unlocking a potentially shared open-file description.
        Darwin.close(descriptor)
    }
}

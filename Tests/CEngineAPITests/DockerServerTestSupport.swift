import Darwin
import Foundation

// Xcode may run suites from one test target in separate worker processes. The actor keeps
// same-process waiters suspended, while the file lock coordinates those workers.
actor DockerServerTestIsolation {
    static let shared = DockerServerTestIsolation()

    private var isAcquired = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func acquire() async {
        if !isAcquired {
            isAcquired = true
            return
        }
        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }

    func release() {
        guard !waiters.isEmpty else {
            isAcquired = false
            return
        }
        waiters.removeFirst().resume()
    }
}

private func acquireDockerServerTestFileLock() async throws -> Int32 {
    let path = FileManager.default.temporaryDirectory
        .appending(path: "cengine-\(getuid())-docker-server-tests.lock")
        .path
    let descriptor = Darwin.open(path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
    guard descriptor >= 0 else {
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }

    let errorCode: Int32? = await withCheckedContinuation { continuation in
        DispatchQueue.global(qos: .userInitiated).async {
            var lock = flock()
            lock.l_type = Int16(F_WRLCK)
            lock.l_whence = Int16(SEEK_SET)
            let result = Darwin.fcntl(descriptor, F_SETLKW, &lock)
            continuation.resume(returning: result == 0 ? nil : errno)
        }
    }
    if let errorCode {
        Darwin.close(descriptor)
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(errorCode))
    }
    return descriptor
}

private func releaseDockerServerTestFileLock(_ descriptor: Int32) throws {
    var lock = flock()
    lock.l_type = Int16(F_UNLCK)
    lock.l_whence = Int16(SEEK_SET)
    let result = Darwin.fcntl(descriptor, F_SETLK, &lock)
    let errorCode = errno
    Darwin.close(descriptor)
    guard result == 0 else {
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(errorCode))
    }
}

func withDockerServerTestIsolation(
    operation: () async throws -> Void
) async throws {
    await DockerServerTestIsolation.shared.acquire()
    let descriptor: Int32
    do {
        descriptor = try await acquireDockerServerTestFileLock()
    } catch {
        await DockerServerTestIsolation.shared.release()
        throw error
    }
    do {
        try await operation()
    } catch {
        try? releaseDockerServerTestFileLock(descriptor)
        await DockerServerTestIsolation.shared.release()
        throw error
    }
    do {
        try releaseDockerServerTestFileLock(descriptor)
    } catch {
        await DockerServerTestIsolation.shared.release()
        throw error
    }
    await DockerServerTestIsolation.shared.release()
}

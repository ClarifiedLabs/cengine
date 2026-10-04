#if os(macOS)
import CEngineCore
import Darwin
import Foundation

/// One owned request descriptor. Cancellation only shuts down this descriptor
/// while its lifetime lock is held; the worker joins before close or transfer.
final class VMShimManagedTransport: @unchecked Sendable {
    /// Closed local transport refusal; never reflects peer-controlled error text.
    static func failure() -> EngineError {
        EngineError(.conflict, "private storage bootstrap refused; preserve storage generation evidence")
    }

    static let maximumNanoseconds: UInt64 = 15_000_000_000
    // Allow the full 4,093-network fabric snapshot as well as nested 64 KiB
    // storage commands, including Data/base64 and JSON escaping. Incremental
    // reads below mean a prefix alone reserves at most one 16 KiB chunk, not
    // this body limit (or the generic 16 MiB) for each of 64 admitted peers.
    static let maximumInitialStorageRequestFrameSize = 2 * 1_024 * 1_024
    let deadlineNanoseconds: UInt64
    private let lock = NSLock()
    private var descriptor: CInt?
    private var cancelled = false

    init(deadlineNanoseconds: UInt64? = nil) {
        let now = DispatchTime.now().uptimeNanoseconds
        self.deadlineNanoseconds = min(deadlineNanoseconds ?? now + Self.maximumNanoseconds,
                                      now + Self.maximumNanoseconds)
    }
    deinit { close() }

    func adopt(_ descriptor: CInt) throws {
        try lock.withLock {
            guard self.descriptor == nil, !cancelled else { throw CancellationError() }
            try UnixSocket.protectDescriptor(descriptor)
            var enabled: CInt = 1
            guard setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<CInt>.size)) == 0 else { throw POSIXError(.EIO) }
            // Darwin MSG_DONTWAIT alone can block a partial stream send. poll
            // owns the absolute deadline, so every adopted socket must be nonblocking.
            let flags = fcntl(descriptor, F_GETFL)
            guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else { throw POSIXError(.EIO) }
            self.descriptor = descriptor
        }
    }
    func cancel() {
        lock.withLock {
            cancelled = true
            if let descriptor { _ = Darwin.shutdown(descriptor, SHUT_RDWR) }
        }
    }
    func close() {
        lock.withLock {
            if let descriptor { Darwin.close(descriptor) }
            descriptor = nil
        }
    }
    func takeDescriptor() throws -> CInt {
        try lock.withLock {
            guard !cancelled, let descriptor else { throw CancellationError() }
            let flags = fcntl(descriptor, F_GETFL)
            guard flags >= 0, fcntl(descriptor, F_SETFL, flags & ~O_NONBLOCK) == 0 else { throw POSIXError(.EIO) }
            self.descriptor = nil
            return descriptor
        }
    }
    func ownedDescriptor() throws -> CInt {
        try lock.withLock {
            guard !cancelled, let descriptor else { throw CancellationError() }
            return descriptor
        }
    }
    func check() throws {
        if lock.withLock({ cancelled }) { throw CancellationError() }
        guard DispatchTime.now().uptimeNanoseconds < deadlineNanoseconds else { throw AsyncTimeout.TimeoutError() }
    }
    func run<Value: Sendable>(_ operation: @escaping @Sendable (VMShimManagedTransport) throws -> Value) async throws -> Value {
        try await withTaskCancellationHandler {
            let value: Value = try await withCheckedThrowingContinuation { continuation in
                Thread.detachNewThread { [self] in
                    do { try check(); continuation.resume(returning: try operation(self)) }
                    catch { continuation.resume(throwing: error) }
                }
            }
            try Task.checkCancellation()
            return value
        } onCancel: { self.cancel() }
    }
    func connect(path: String) throws {
        try check()
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw POSIXError(.EIO) }
        do { try adopt(fd) } catch { Darwin.close(fd); throw error }
        var enabled: CInt = 1
        guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<CInt>.size)) == 0,
              fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else { throw POSIXError(.EIO) }
        try UnixSocket.withAddress(path) { address, length in
            if Darwin.connect(fd, address, length) != 0 {
                guard errno == EINPROGRESS || errno == EAGAIN else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
                try wait(Int16(POLLOUT))
                var error: CInt = 0
                var size = socklen_t(MemoryLayout<CInt>.size)
                guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0, error == 0 else { throw POSIXError(.ECONNREFUSED) }
            }
        }
        try check()
    }
    private func wait(_ events: Int16) throws {
        let fd = try ownedDescriptor()
        while true {
            try check()
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadlineNanoseconds else { throw AsyncTimeout.TimeoutError() }
            let remaining = deadlineNanoseconds - now
            var item = pollfd(fd: fd, events: events, revents: 0)
            let result = Darwin.poll(&item, 1, Int32(min(100, max(1, remaining / 1_000_000))))
            if result < 0, errno == EINTR { continue }
            guard result >= 0 else { throw POSIXError(.EIO) }
            if result == 0 { continue }
            try check()
            guard item.revents & events != 0 else { throw POSIXError(.ECONNRESET) }
            return
        }
    }
    func write(_ data: Data) throws {
        let fd = try ownedDescriptor()
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                try wait(Int16(POLLOUT))
                let count = Darwin.send(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset, MSG_DONTWAIT)
                if count < 0, errno == EINTR || errno == EAGAIN { continue }
                guard count > 0 else { throw POSIXError(.EPIPE) }
                offset += count
            }
        }
    }
    func readExactly(_ count: Int) throws -> Data {
        let fd = try ownedDescriptor()
        guard count >= 0 else { throw EngineError(.badRequest, "invalid VM shim frame") }
        var data = Data()
        // A declared length alone must not reserve its entire body. Allocate
        // incrementally, only as bytes arrive, under the same absolute deadline.
        var chunk = [UInt8](repeating: 0, count: min(count, 16 * 1_024))
        try chunk.withUnsafeMutableBufferPointer { bytes in
            while data.count < count {
                try wait(Int16(POLLIN))
                let received = Darwin.recv(fd, bytes.baseAddress!, min(bytes.count, count - data.count), MSG_DONTWAIT)
                if received < 0, errno == EINTR || errno == EAGAIN { continue }
                guard received > 0 else { throw POSIXError(.ECONNRESET) }
                data.append(bytes.baseAddress!, count: received)
            }
        }
        return data
    }
    func readFrame(maximum: Int = VMShimProtocol.maximumFrameSize) throws -> Data {
        let prefix = try readExactly(4)
        let count = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard count > 0, count <= min(maximum, VMShimProtocol.maximumFrameSize) else { throw EngineError(.badRequest, "invalid VM shim frame") }
        return prefix + (try readExactly(Int(count)))
    }
}
/// Reserve before creating an actor task. Expired queued sockets close under
/// their own lifetime lock; their slot remains reserved until that task settles.
final class VMShimManagedAdmission: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func reserve(_ descriptor: CInt, deadline: UInt64) -> Permit? {
        lock.withLock {
            guard count < 64 else { return nil }
            do { try UnixSocket.protectDescriptor(descriptor) } catch { return nil }
            count += 1
            return Permit(descriptor: descriptor, deadline: deadline, owner: self)
        }
    }
    private func release() { lock.withLock { count -= 1 } }
    final class Permit: @unchecked Sendable {
        let deadline: UInt64
        private let owner: VMShimManagedAdmission
        private let lock = NSLock()
        private var descriptor: CInt?
        private var admissionReleased = false
        fileprivate init(descriptor: CInt, deadline: UInt64, owner: VMShimManagedAdmission) {
            self.descriptor = descriptor; self.deadline = deadline; self.owner = owner
            DispatchQueue.global().asyncAfter(deadline: DispatchTime(uptimeNanoseconds: deadline)) { [weak self] in self?.expire() }
        }
        private func expire() {
            lock.withLock { if let descriptor { Darwin.close(descriptor); self.descriptor = nil } }
        }
        func take() -> CInt? {
            lock.withLock {
                guard DispatchTime.now().uptimeNanoseconds < deadline else {
                    if let descriptor { Darwin.close(descriptor); self.descriptor = nil }; return nil
                }
                defer { descriptor = nil }; return descriptor
            }
        }
        /// Container admission ends after the initial authenticated frame, not
        /// after an ordinary guest wait that can last the workload's lifetime.
        func finishInitialFrame() {
            let release = lock.withLock {
                guard !admissionReleased else { return false }
                admissionReleased = true; return true
            }
            if release { owner.release() }
        }
        deinit { expire(); finishInitialFrame() }
    }
}
#endif

#if os(macOS)
import CEngineCore
import Darwin
import Foundation

/// Bounded framing and SCM_RIGHTS descriptor transfer for storage shim control.
/// Other runtime channels use separate framing or discard ancillary messages.
final class StorageLifecycleShimChannel: @unchecked Sendable {
    typealias Failure = StorageLifecycleShimProtocol.Failure
    // Darwin (including arm64) uses socklen_t32 and ALIGN32: cmsghdr is
    // 12 bytes; CMSG_LEN/SPACE(one Int32) are both 16. Not Linux's LP64 ABI.
    static let maximum = 65_536
    static let budget: TimeInterval = 110 // Includes queue admission; below ROOT's 120s budget.
    private let lock = NSLock()
    private var descriptor: Int32?

    init(borrowedFD: Int32) throws {
        let fd = fcntl(borrowedFD, F_DUPFD_CLOEXEC, 0)
        guard fd >= 0 else { throw Failure.closed }
        var type: Int32 = 0, one: Int32 = 1, info = stat()
        var size = socklen_t(MemoryLayout<Int32>.size)
        var address = sockaddr_un(), addressSize = socklen_t(MemoryLayout<sockaddr_un>.size)
        let connected = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getpeername(fd, $0, &addressSize) == 0 }
        }
        let flags = fcntl(fd, F_GETFL)
        guard connected, address.sun_family == AF_UNIX, fstat(fd, &info) == 0,
              info.st_mode & S_IFMT == S_IFSOCK, info.st_uid == geteuid(),
              getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size) == 0, type == SOCK_STREAM,
              flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0,
              setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            Darwin.close(fd); throw Failure.unauthorized
        }
        descriptor = fd
    }
    /// A worker's lease prevents close/reuse races without holding a lock over IO.
    func lease() throws -> FileHandle {
        try lock.withLock {
            guard let descriptor else { throw Failure.closed }
            let fd = fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
            guard fd >= 0 else { throw Failure.closed }
            return FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        }
    }
    func check() throws { try lock.withLock { guard descriptor != nil else { throw Failure.closed } } }
    func close() {
        lock.withLock {
            if let descriptor { _ = Darwin.shutdown(descriptor, SHUT_RDWR); Darwin.close(descriptor) }
            descriptor = nil
        }
    }
    deinit { close() }
    /// An idle server has no request deadline. Poll without consuming bytes so
    /// the first recvmsg still captures and rejects any attached SCM_RIGHTS.
    /// The worker's duplicated lease survives close/reuse; shutdown wakes poll.
    func waitForFirstByte(on lease: FileHandle) throws {
        while true {
            try check()
            var item = pollfd(fd: lease.fileDescriptor, events: Int16(POLLIN), revents: 0)
            let result = poll(&item, 1, 100)
            if result < 0 && errno == EINTR { continue }
            guard result >= 0 else { throw Failure.closed }
            if result == 0 { continue }
            try check()
            guard item.revents & Int16(POLLIN | POLLHUP) != 0 else { throw Failure.closed }
            return // EOF is readable too; receive will reject it immediately.
        }
    }
    static func deadline(_ seconds: TimeInterval = budget) -> DispatchTime { .now() + seconds }
    static func check(_ deadline: DispatchTime) throws {
        guard DispatchTime.now() < deadline else { throw Failure.timeout }
    }
    private static func wait(_ fd: Int32, _ events: Int32, _ deadline: DispatchTime) throws {
        while true {
            try check(deadline)
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline.uptimeNanoseconds else { throw Failure.timeout }
            let milliseconds = min(100, max(1, (deadline.uptimeNanoseconds - now) / 1_000_000))
            var item = pollfd(fd: fd, events: Int16(events), revents: 0)
            let result = poll(&item, 1, Int32(milliseconds))
            if result < 0 && errno == EINTR { continue }
            guard result >= 0 else { throw Failure.closed }
            if result == 0 { continue }
            guard item.revents & Int16(events) != 0 else { throw Failure.closed }
            return
        }
    }
    static func send(_ body: Data, fd: Int32, passing: Int32? = nil, deadline: DispatchTime) throws {
        guard !body.isEmpty, body.count <= maximum else { throw Failure.invalid }
        var header = UInt32(body.count).bigEndian
        try wait(fd, POLLOUT, deadline)
        let n = withUnsafeMutableBytes(of: &header) { raw in
            var vector = iovec(iov_base: raw.baseAddress, iov_len: 4)
            return withUnsafeMutablePointer(to: &vector) { pointer in
                var message = msghdr(); message.msg_iov = pointer; message.msg_iovlen = 1
                var control = [UInt32](repeating: 0, count: 4)
                return control.withUnsafeMutableBytes { bytes in
                    if let passing {
                        bytes.storeBytes(of: cmsghdr(cmsg_len: 16, cmsg_level: SOL_SOCKET, cmsg_type: SCM_RIGHTS), as: cmsghdr.self)
                        bytes.storeBytes(of: passing, toByteOffset: 12, as: Int32.self)
                        message.msg_control = bytes.baseAddress; message.msg_controllen = 16
                    }
                    return Darwin.sendmsg(fd, &message, MSG_DONTWAIT)
                }
            }
        }
        // An uncertain rights-bearing send is terminal; never retransmit it.
        guard n == 4 else { throw Failure.closed }
        try sendRaw(body, fd: fd, deadline: deadline)
    }
    /// Unframed protocol discriminator; never carries descriptors.
    static func sendRaw(_ body: Data, fd: Int32, deadline: DispatchTime) throws {
        guard !body.isEmpty, body.count <= maximum else { throw Failure.invalid }
        var offset = 0
        while offset < body.count {
            try wait(fd, POLLOUT, deadline)
            let n = body.withUnsafeBytes { Darwin.send(fd, $0.baseAddress!.advanced(by: offset), body.count - offset, MSG_DONTWAIT) }
            if n < 0 && (errno == EINTR || errno == EAGAIN) { continue }
            guard n > 0 else { throw Failure.closed }
            offset += n
        }
    }
    struct Packet: Sendable { let body: Data; let descriptor: FileHandle? }
    private static func readRaw(_ count: Int, fd: Int32, permitsDescriptor: Bool,
                                rights: inout [Int32], deadline: DispatchTime) throws -> Data {
            var bytes = Data(count: count), offset = 0
            while offset < count {
                try wait(fd, POLLIN, deadline)
                var control = [UInt32](repeating: 0, count: 256), controlCount = 0
                var flags: Int32 = 0
                let n = bytes.withUnsafeMutableBytes { raw in
                    var vector = iovec(iov_base: raw.baseAddress!.advanced(by: offset), iov_len: count - offset)
                    return withUnsafeMutablePointer(to: &vector) { pointer in
                        control.withUnsafeMutableBytes { ancillary in
                            var message = msghdr(); message.msg_iov = pointer; message.msg_iovlen = 1
                            message.msg_control = ancillary.baseAddress; message.msg_controllen = socklen_t(ancillary.count)
                            let n = Darwin.recvmsg(fd, &message, MSG_DONTWAIT)
                            flags = message.msg_flags; controlCount = Int(message.msg_controllen)
                            return n
                        }
                    }
                }
                if n < 0 && (errno == EINTR || errno == EAGAIN) { continue }
                var invalid = false
                if n >= 0 {
                    control.withUnsafeBytes { raw in
                        var cursor = 0
                        while cursor + 12 <= controlCount {
                            let header = raw.loadUnaligned(fromByteOffset: cursor, as: cmsghdr.self)
                            let length = Int(header.cmsg_len)
                            guard length >= 12, cursor + length <= controlCount else { invalid = true; break }
                            if header.cmsg_level == SOL_SOCKET && header.cmsg_type == SCM_RIGHTS {
                                for i in stride(from: cursor + 12, to: cursor + length - 3, by: 4) {
                                    rights.append(raw.loadUnaligned(fromByteOffset: i, as: Int32.self))
                                }
                                if (length - 12) % 4 != 0 { invalid = true }
                            } else { invalid = true }
                            cursor += (length + 3) & ~3
                        }
                        if cursor != controlCount { invalid = true }
                    }
                }
                guard n > 0, !invalid, flags & (MSG_CTRUNC | MSG_TRUNC) == 0,
                      rights.count <= (permitsDescriptor ? 1 : 0) else { throw Failure.invalid }
                offset += n
            }
            return bytes
    }
    /// Read the discriminator before any token decoding, rejecting SCM_RIGHTS on
    /// BOTH ordinary frames and the adopted path. The socket is already bounded.
    static func receiveInitialRoute(fd: Int32, maximum: Int, deadline: DispatchTime) throws -> Data {
        var rights: [Int32] = []
        defer { for descriptor in rights { Darwin.close(descriptor) } }
        let prefix = try readRaw(4, fd: fd, permitsDescriptor: false, rights: &rights, deadline: deadline)
        let preface = StorageLifecycleShimProtocol.adoptionPreface
        if prefix == preface.prefix(4) {
            let suffix = try readRaw(preface.count - 4, fd: fd, permitsDescriptor: false, rights: &rights, deadline: deadline)
            guard prefix + suffix == preface else { throw Failure.invalid }
            return preface
        }
        let count = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard count > 0, count <= maximum else { throw Failure.invalid }
        var result = prefix, remaining = Int(count)
        while remaining > 0 {
            let amount = min(remaining, 16 * 1_024)
            result += try readRaw(amount, fd: fd, permitsDescriptor: false, rights: &rights, deadline: deadline)
            remaining -= amount
        }
        return result
    }
    static func receive(fd: Int32, permitsDescriptor: Bool, deadline: DispatchTime) throws -> Packet {
        var rights: [Int32] = []
        defer { for fd in rights { Darwin.close(fd) } }
        let header = try readRaw(4, fd: fd, permitsDescriptor: permitsDescriptor, rights: &rights, deadline: deadline)
        let count = header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).bigEndian }
        guard count > 0, count <= maximum else { throw Failure.invalid }
        let body = try readRaw(Int(count), fd: fd, permitsDescriptor: permitsDescriptor, rights: &rights, deadline: deadline)
        guard rights.count == (permitsDescriptor ? 1 : 0) else { throw Failure.invalid }
        var handle: FileHandle?
        if let fd = rights.first {
            guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { throw Failure.closed }
            handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true); rights.removeAll()
        }
        return Packet(body: body, descriptor: handle)
    }
}
#endif

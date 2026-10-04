#if os(macOS)
import CEngineCore
@testable import CEngineRuntime
import Darwin
import Foundation
import Testing

@Suite("Lifecycle child attachment certificate", .serialized)
struct StorageLifecycleChildAttachmentTests {
    private typealias Child = StorageLifecycleChildProcess
    private typealias L = StorageLifecycleProtocol
    private static let store = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    private static let epoch = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    private static let pin = String(repeating: "a", count: 64)
    // Public fixture certificate only. The parent's check is DER syntax, not URI,
    // freshness or authority; those checks remain independently inside the child.
    private static let certificate = Data(base64Encoded: "MIIBQTCB9KADAgECAgEBMAUGAytlcDAnMSUwIwYDVQQDExxzdG9yYWdlIHN0YXJ0dXAgZml4dHVyZSBPTkxZMB4XDTI2MDkxMDAwMDAwMFoXDTI2MDkxMDAxMDAwMFowJzElMCMGA1UEAxMcc3RvcmFnZSBzdGFydHVwIGZpeHR1cmUgT05MWTAqMAUGAytlcAMhAO1JKMYo0cLG6ukDOJBZlWEpWSc6XGP5NjbBRhSshzfRo0UwQzAOBgNVHQ8BAf8EBAMCAgQwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUti6Gf6LzOv5i1daxZC4WIdVDMHgwBQYDK2VwA0EAepwr8ZfdBSPht2c3fXkG8e7GH6DrugyxFkhoze2M2D2Vbfnhl0IlGcgU0xR99U1T04WvXnz8sED2ejOQqaNpAA==")!

    private static func binding(role: ManagedStorageControlProtocol.Role = .runtime, prepare: String? = nil) throws -> ManagedStorageControlProtocol.Binding {
        try .init(store: store, volume: store, attachment: epoch, prepare: prepare,
                  container: pin, launch: epoch, key: pin, role: role, mode: .readWrite)
    }
    private static func request() throws -> Child.AttachmentCertificateRequest {
        try .init(binding: binding(), serviceEpoch: epoch, controllerEpoch: .max, csr: Data([1, 2, 3]),
                  identity: .init(store: store, generation: .max, binding: pin))
    }
    private static func envelope(_ data: Data, id: UInt64 = 1) -> Data {
        Data("{\"data\":\"\(data.base64EncodedString())\",\"request_id\":\(id),\"version\":\"storage-child-lifecycle.v2\"}".utf8)
    }
    private static func certificateResult(_ der: Data = certificate) -> Data {
        Data("{\"certificate\":\"\(der.base64EncodedString())\"}".utf8)
    }

    @Test func validatingConstructorClosesInputs() throws {
        let valid = try Self.request()
        #expect(valid.controllerEpoch == .max)
        for field in 0..<9 {
            #expect(throws: (any Error).self) {
                let binding = try Self.binding(role: field == 5 ? .prepare : .runtime,
                                               prepare: field == 6 ? Self.epoch : nil)
                return try Child.AttachmentCertificateRequest(binding: binding,
                    serviceEpoch: field == 0 ? Self.epoch.uppercased() : field == 1 ? "invalid" : Self.epoch,
                    controllerEpoch: field == 2 ? 0 : .max,
                    csr: field == 3 ? Data() : field == 4 ? Data(repeating: 1, count: 16 * 1024 + 1) : valid.csr,
                    identity: .init(store: field == 7 ? Self.epoch : Self.store,
                                    generation: field == 8 ? 0 : 1, binding: Self.pin))
            }
        }
        _ = try Child.AttachmentCertificateRequest(binding: Self.binding(role: .prepare, prepare: Self.epoch),
            serviceEpoch: Self.epoch, controllerEpoch: 1, csr: Data(repeating: 1, count: 16 * 1024), identity: valid.identity)
        // Binding's synthesized Decodable bypasses its initializer; reject it here.
        let encoded = try L.encode(valid.binding)
        let malformed = Data(String(decoding: encoded, as: UTF8.self).replacingOccurrences(of: Self.pin, with: "bad").utf8)
        let decoded = try JSONDecoder().decode(ManagedStorageControlProtocol.Binding.self, from: malformed)
        #expect(throws: (any Error).self) {
            try Child.AttachmentCertificateRequest(binding: decoded, serviceEpoch: Self.epoch,
                controllerEpoch: 1, csr: valid.csr, identity: valid.identity)
        }
    }

    @Test func canonicalBodyTransfersExactlyOneBorrowedSocketAndAcceptsCertificate() async throws {
        let channel = try AttachmentSocketPair(), stream = try AttachmentSocketPair()
        let child = try channel.adoptingChild(sequence: .max - 1)
        defer { child.close() }
        let request = try Self.request(), originalFlags = fcntl(stream.first, F_GETFL)
        let originalDescriptorFlags = fcntl(stream.first, F_GETFD)
        async let observed = attachmentThread {
            let frame = try AttachmentWire.readFrame(channel.second)
            defer { frame.rights.forEach { Darwin.close($0) } }
            guard frame.rights.count == 1 else { throw AttachmentTestFailure.invalidFrame }
            let right = frame.rights[0]
            // The transferred right is the same stream, not merely any valid FD.
            try AttachmentWire.send(Data([42]), on: right)
            try AttachmentWire.sendFrame(Self.envelope(Self.certificateResult(), id: .max), on: channel.second)
            return frame.data
        }
        let result = try await attachmentThread { try child.attachmentCertificate(socket: stream.first, request: request) }
        let actual = String(decoding: try await observed, as: UTF8.self)
        let expected = "{\"body\":{\"attachment\":{\"binding\":{\"attachment\":\"\(Self.epoch)\",\"container\":\"\(Self.pin)\",\"key\":\"\(Self.pin)\",\"launch\":\"\(Self.epoch)\",\"mode\":\"read-write\",\"role\":\"runtime\",\"store\":\"\(Self.store)\",\"volume\":\"\(Self.store)\"},\"epoch\":\"\(Self.epoch)\"},\"controller_epoch\":18446744073709551615,\"csr\":\"AQID\",\"identity\":{\"binding\":\"\(Self.pin)\",\"generation\":18446744073709551615,\"store\":\"\(Self.store)\"}},\"operation\":\"attachment-certificate\",\"request_id\":18446744073709551615,\"version\":\"storage-child-lifecycle.v2\"}"
        #expect(actual == expected)
        guard case .certificate(let certificate) = result else { Issue.record("expected certificate"); return }
        #expect(certificate.der == Self.certificate)
        #expect(try AttachmentWire.readBytes(stream.second, count: 1).data == Data([42]))
        // Darwin also exposes kernel bookkeeping (e.g. SCM_RIGHTS GC's FMARK)
        // through F_GETFL. Preserve the caller-controlled mode/status flags, not
        // those transient bits; the borrowed descriptor's flags are exact.
        let statusFlags = O_ACCMODE | O_NONBLOCK | O_APPEND | O_ASYNC | O_SYNC | O_DSYNC
        #expect(fcntl(stream.first, F_GETFL) & statusFlags == originalFlags & statusFlags)
        #expect(fcntl(stream.first, F_GETFD) == originalDescriptorFlags)
        child.close()
        // Closing the private child channel never closes the caller's stream.
        try AttachmentWire.send(Data([43]), on: stream.first)
        #expect(try AttachmentWire.readBytes(stream.second, count: 1).data == Data([43]))
    }

    @Test(arguments: [Child.AttachmentCertificateFailure.rejected, .unavailable])
    func typedFailureLeavesChannelUsable(_ failure: StorageLifecycleChildProcess.AttachmentCertificateFailure) async throws {
        let channel = try AttachmentSocketPair(), stream = try AttachmentSocketPair()
        let child = try channel.adoptingChild()
        defer { child.close() }
        let request = try Self.request()
        async let peer: Void = attachmentThread {
            let frame = try AttachmentWire.readFrame(channel.second)
            defer { frame.rights.forEach { Darwin.close($0) } }
            guard frame.rights.count == 1 else { throw AttachmentTestFailure.invalidFrame }
            try AttachmentWire.sendFrame(Self.envelope(Data("{\"error\":\"\(failure.rawValue)\"}".utf8)), on: channel.second)
            let next = try AttachmentWire.readFrame(channel.second)
            defer { next.rights.forEach { Darwin.close($0) } }
            guard next.rights.isEmpty else { throw AttachmentTestFailure.invalidFrame }
            try AttachmentWire.sendFrame(Self.envelope(Data([9]), id: 2), on: channel.second)
        }
        let result = try await attachmentThread { try child.attachmentCertificate(socket: stream.first, request: request) }
        guard case .failure(let received) = result else { Issue.record("expected typed failure"); return }
        #expect(received == failure)
        #expect(try await attachmentThread { try child.controllerCSR() } == Data([9]))
        try await peer
        #expect(fcntl(stream.first, F_GETFD) >= 0)
    }

    private static var malformedResults: [Data] {
        let valid = String(decoding: certificateResult(), as: UTF8.self)
        return ["{}", "[]", "{\"error\":\"unknown\"}", "{\"error\":null}",
                "{\"error\":\"rejected\",\"error\":\"rejected\"}", "{\"error\":\"rejected\",\"unknown\":0}",
                "{\"certificate\":null,\"error\":\"rejected\"}", "{\"certificate\":\"\",\"error\":\"rejected\"}",
                "{\"certificate\":\"\"}", "{\"certificate\":\"MAA=\"}", "{\"certificate\":\"!!!!\"}",
                "{\"error\":\"reject\\u0065d\"}", "{\"error\": \"rejected\"}", "{\"error\":\"rejected\"}\n",
                valid + "{}", String(valid.dropLast()), valid.replacingOccurrences(of: "==", with: "="),
                valid.replacingOccurrences(of: "/", with: "\\/")].map { Data($0.utf8) }
            + [Data(), certificateResult(certificate + Data([0])), certificateResult(Data(certificate.dropLast())),
               certificateResult(Data(repeating: 1, count: 16 * 1024 + 1))]
    }
    @Test func malformedResultsFenceBeforeConcurrentNextCall() async throws {
        for malformed in Self.malformedResults {
            try await assertFenced(reply: Self.envelope(malformed))
        }
    }
    @Test func closedEnvelopeCrossIDAndTruncationAreFenced() async throws {
        let valid = String(decoding: Self.envelope(Self.certificateResult()), as: UTF8.self)
        for raw in [valid.replacingOccurrences(of: "\"request_id\":1", with: "\"request_id\":2"),
                    valid.replacingOccurrences(of: "\"request_id\":1", with: "\"request_id\":1.0"),
                    valid.replacingOccurrences(of: "\"request_id\":1", with: "\"request_id\":1,\"request_id\":1"),
                    valid.replacingOccurrences(of: "lifecycle.v2", with: "lifecycle.v1"),
                    "{\"unknown\":0," + valid.dropFirst(), valid + "\n", String(valid.dropLast())] {
            try await assertFenced(reply: Data(raw.utf8))
        }
        try await assertFenced(reply: Data(valid.utf8), truncate: true)
        try await assertFenced(reply: Data(valid.utf8), replyRight: true)
    }

    private func assertFenced(reply: Data, truncate: Bool = false, replyRight: Bool = false) async throws {
        let channel = try AttachmentSocketPair(), stream = try AttachmentSocketPair(), unexpected = try AttachmentSocketPair()
        let child = try channel.adoptingChild()
        defer { child.close() }
        let request = try Self.request()
        let received = DispatchSemaphore(value: 0), waiting = DispatchSemaphore(value: 0)
        async let peer: Bool = attachmentThread {
            let frame = try AttachmentWire.readFrame(channel.second)
            defer { frame.rights.forEach { Darwin.close($0) }; received.signal() }
            guard frame.rights.count == 1 else { throw AttachmentTestFailure.invalidFrame }
            received.signal()
            guard waiting.wait(timeout: .now() + 3) == .success else { throw AttachmentTestFailure.timeout }
            do {
                try AttachmentWire.sendFrame(reply, on: channel.second, passing: replyRight ? unexpected.first : -1, truncate: truncate)
            } catch {
                // A forbidden right may fence the channel before its body sends.
                guard replyRight else { throw error }
            }
            if truncate { shutdown(channel.second, SHUT_WR) }
            var byte: UInt8 = 0
            return recv(channel.second, &byte, 1, 0) == 0
        }
        async let next: Bool = attachmentThread {
            guard received.wait(timeout: .now() + 3) == .success else { throw AttachmentTestFailure.timeout }
            waiting.signal()
            do { _ = try child.controllerCSR(); return false } catch { return true }
        }
        let failed = await attachmentThreadResult { try child.attachmentCertificate(socket: stream.first, request: request) }
        #expect(failed)
        let nextFailed = try await next, sawEOF = try await peer
        #expect(nextFailed)
        #expect(sawEOF)
        #expect(fcntl(stream.first, F_GETFD) >= 0)
        // The duplicate and transferred copy must both be gone on rejection.
        stream.closeFirst()
        var byte: UInt8 = 0
        #expect(recv(stream.second, &byte, 1, 0) == 0)
        if replyRight {
            unexpected.closeFirst()
            #expect(recv(unexpected.second, &byte, 1, 0) == 0)
        }
    }

    @Test func absentDisconnectedAndNonSocketInputsNeverSend() async throws {
        let channel = try AttachmentSocketPair()
        let child = try channel.adoptingChild()
        defer { child.close() }
        let disconnected = socket(AF_UNIX, SOCK_STREAM, 0), file = open("/dev/null", O_RDONLY)
        defer { Darwin.close(disconnected); Darwin.close(file) }
        let request = try Self.request()
        for fd in [Int32(-1), disconnected, file] {
            #expect(await attachmentThreadResult { try child.attachmentCertificate(socket: fd, request: request) })
            var byte: UInt8 = 0
            #expect(recv(channel.second, &byte, 1, MSG_DONTWAIT) == -1)
            #expect(errno == EAGAIN)
        }
        #expect(fcntl(disconnected, F_GETFD) >= 0)
        #expect(fcntl(file, F_GETFD) >= 0)
    }

    @Test func truncatedReplyUsesOriginalFixedDeadlineAndClosesDuplicate() async throws {
        let channel = try AttachmentSocketPair(), stream = try AttachmentSocketPair()
        let child = try channel.adoptingChild(timeout: 0.2)
        defer { child.close() }
        let request = try Self.request()
        async let peer: Void = attachmentThread {
            let frame = try AttachmentWire.readFrame(channel.second)
            defer { frame.rights.forEach { Darwin.close($0) } }
            var count = UInt32(100).bigEndian
            try withUnsafeBytes(of: &count) { try AttachmentWire.send(Data($0), on: channel.second) }
            for _ in 0..<20 {
                Thread.sleep(forTimeInterval: 0.05)
                // Keep making progress; it must not renew the original deadline.
                do { try AttachmentWire.send(Data([32]), on: channel.second) } catch { break }
            }
        }
        let start = ProcessInfo.processInfo.systemUptime
        #expect(await attachmentThreadResult { try child.attachmentCertificate(socket: stream.first, request: request) })
        #expect(ProcessInfo.processInfo.systemUptime - start < 0.8)
        try await peer
        stream.closeFirst()
        var byte: UInt8 = 0
        #expect(recv(stream.second, &byte, 1, 0) == 0)
    }
}

enum AttachmentTestFailure: Error { case invalidFrame, io, timeout }

// Only these immutable descriptors cross worker threads. Tests join all workers
// before closeFirst/deinit; syscall deadlines bound fixture failures.
final class AttachmentSocketPair: @unchecked Sendable {
    private(set) var first: Int32
    let second: Int32
    init() throws {
        var sockets: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0 else { throw AttachmentTestFailure.io }
        first = sockets[0]; second = sockets[1]
        for fd in sockets {
            var timeout = timeval(tv_sec: 3, tv_usec: 0), one: Int32 = 1
            guard setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
                  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
                  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
                Darwin.close(first); Darwin.close(second); throw AttachmentTestFailure.io
            }
        }
    }
    func adoptingChild(timeout: TimeInterval = 3, sequence: UInt64 = 0) throws -> StorageLifecycleChildProcess {
        let child = try StorageLifecycleChildProcess.adoptingTestSocket(first, timeout: timeout, sequence: sequence)
        // The test seam duplicates its input; native launch owns the sole parent
        // endpoint. Drop the fixture's extra FD to model that ownership exactly.
        // In particular, Darwin shutdown after a peer half-close can return
        // ENOTCONN, so an extra local FD would incorrectly prevent peer EOF.
        closeFirst()
        return child
    }
    func closeFirst() { Darwin.close(first); first = -1 }
    deinit { Darwin.close(first); Darwin.close(second) }
}
func attachmentThread<T: Sendable>(_ operation: @escaping @Sendable () throws -> T) async throws -> T {
    try await withCheckedThrowingContinuation { continuation in
        Thread.detachNewThread {
            do { continuation.resume(returning: try operation()) }
            catch { continuation.resume(throwing: error) }
        }
    }
}
func attachmentThreadResult<T: Sendable>(_ operation: @escaping @Sendable () throws -> T) async -> Bool {
    do { _ = try await attachmentThread(operation); return false } catch { return true }
}
enum AttachmentWire {
    struct Frame: Sendable { let data: Data; let rights: [Int32] }
    static func readBytes(_ fd: Int32, count: Int) throws -> Frame {
        var data = Data(count: count), offset = 0, rights: [Int32] = []
        var succeeded = false
        defer { if !succeeded { rights.forEach { Darwin.close($0) } } }
        while offset < count {
            var control = [UInt32](repeating: 0, count: 32), flags: Int32 = 0, controlCount = 0
            let n = data.withUnsafeMutableBytes { raw in
                var iov = iovec(iov_base: raw.baseAddress!.advanced(by: offset), iov_len: count - offset)
                return withUnsafeMutablePointer(to: &iov) { pointer in
                    control.withUnsafeMutableBytes { ancillary in
                        var message = msghdr()
                        message.msg_iov = pointer; message.msg_iovlen = 1
                        message.msg_control = ancillary.baseAddress; message.msg_controllen = socklen_t(ancillary.count)
                        let n = recvmsg(fd, &message, 0)
                        flags = message.msg_flags; controlCount = Int(message.msg_controllen)
                        return n
                    }
                }
            }
            if n < 0 && errno == EINTR { continue }
            control.withUnsafeBytes { raw in
                var cursor = 0
                while cursor + 12 <= controlCount {
                    let header = raw.loadUnaligned(fromByteOffset: cursor, as: cmsghdr.self)
                    let size = Int(header.cmsg_len)
                    guard size >= 12, cursor + size <= controlCount else { break }
                    if header.cmsg_level == SOL_SOCKET && header.cmsg_type == SCM_RIGHTS {
                        for position in stride(from: cursor + 12, to: cursor + size - 3, by: 4) {
                            rights.append(raw.loadUnaligned(fromByteOffset: position, as: Int32.self))
                        }
                    }
                    cursor += (size + 3) & ~3
                }
            }
            guard n > 0, flags & (MSG_CTRUNC | MSG_TRUNC) == 0 else { throw AttachmentTestFailure.io }
            offset += n
        }
        succeeded = true
        return Frame(data: data, rights: rights)
    }
    static func readFrame(_ fd: Int32) throws -> Frame {
        let header = try readBytes(fd, count: 4)
        do {
            let size = header.data.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).bigEndian }
            guard size > 0, size <= 64 * 1024 else { throw AttachmentTestFailure.invalidFrame }
            let body = try readBytes(fd, count: Int(size))
            return Frame(data: body.data, rights: header.rights + body.rights)
        } catch { header.rights.forEach { Darwin.close($0) }; throw error }
    }
    static func send(_ data: Data, on fd: Int32) throws {
        var offset = 0
        while offset < data.count {
            let n = data.withUnsafeBytes { Darwin.send(fd, $0.baseAddress!.advanced(by: offset), data.count - offset, 0) }
            if n < 0 && errno == EINTR { continue }
            guard n > 0 else { throw AttachmentTestFailure.io }
            offset += n
        }
    }
    static func sendFrame(_ data: Data, on fd: Int32, passing right: Int32 = -1, truncate: Bool = false) throws {
        var size = UInt32(data.count).bigEndian
        let n = withUnsafeMutableBytes(of: &size) { raw in
            var iov = iovec(iov_base: raw.baseAddress, iov_len: 4)
            return withUnsafeMutablePointer(to: &iov) { pointer in
                var control = [UInt32](repeating: 0, count: 4)
                return control.withUnsafeMutableBytes { ancillary in
                    var message = msghdr(); message.msg_iov = pointer; message.msg_iovlen = 1
                    if right >= 0 {
                        ancillary.storeBytes(of: cmsghdr(cmsg_len: 16, cmsg_level: SOL_SOCKET, cmsg_type: SCM_RIGHTS), as: cmsghdr.self)
                        ancillary.storeBytes(of: right, toByteOffset: 12, as: Int32.self)
                        message.msg_control = ancillary.baseAddress; message.msg_controllen = 16
                    }
                    return sendmsg(fd, &message, 0)
                }
            }
        }
        guard n == 4 else { throw AttachmentTestFailure.io }
        try send(truncate ? Data(data.dropLast()) : data, on: fd)
    }
}
#endif

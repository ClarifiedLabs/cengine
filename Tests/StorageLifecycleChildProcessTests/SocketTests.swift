import CEngineCore
import Darwin
import Foundation
import Testing
@testable import LifecycleChildRuntime

@Suite struct LifecycleChildSocketTests {
    typealias Child = StorageLifecycleChildProcess
    func sockets() throws -> [Int32] {
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { throw Child.Failure.system(errno) }
        for fd in pair {
            var timeout = timeval(tv_sec: 2, tv_usec: 0), one: Int32 = 1
            _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
            _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, 4)
        }
        return pair
    }
    func readExact(_ fd: Int32, _ n: Int) throws -> Data {
        var bytes = Data(count: n), offset = 0
        while offset < n {
            let got = bytes.withUnsafeMutableBytes { recv(fd, $0.baseAddress!.advanced(by: offset), n-offset, 0) }
            guard got > 0 else { throw Child.Failure.protocolViolation }
            offset += got
        }
        return bytes
    }
    func readFrame(_ fd: Int32, limit: Int = 65536) throws -> Data {
        let n = try readExact(fd, 4).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).bigEndian }
        guard n > 0, n <= limit else { throw Child.Failure.protocolViolation }
        return try readExact(fd, Int(n))
    }
    func write(_ fd: Int32, _ raw: Data) throws {
        var offset = 0
        while offset < raw.count {
            let sent = raw.withUnsafeBytes { send(fd, $0.baseAddress!.advanced(by: offset), raw.count - offset, 0) }
            guard sent > 0 else { throw Child.Failure.protocolViolation }
            offset += sent
        }
    }
    func frame(_ fd: Int32, _ string: String) throws {
        let raw = Data(string.utf8); var n = UInt32(raw.count).bigEndian
        try withUnsafeBytes(of: &n) { try write(fd, Data($0)) }; try write(fd, raw)
    }
    @Test func exactMonotonicFrames() throws {
        let pair = try sockets(); defer { pair.forEach { Darwin.close($0) } }
        let child = try Child.adoptingTestSocket(pair[0], timeout: 2); defer { child.close() }
        let done = DispatchSemaphore(value: 0)
        let worker = Thread {
            defer { done.signal() }
            do {
                let first = try readFrame(pair[1])
                #expect(String(decoding: first, as: UTF8.self) == "{\"operation\":\"controller-csr\",\"request_id\":1,\"version\":\"storage-child-lifecycle.v2\"}")
                try frame(pair[1], "{\"data\":\"AQID\",\"request_id\":1,\"version\":\"storage-child-lifecycle.v2\"}")
                let second = try readFrame(pair[1])
                #expect(String(decoding: second, as: UTF8.self) == "{\"operation\":\"takeover\",\"request_id\":2,\"version\":\"storage-child-lifecycle.v2\"}")
                try frame(pair[1], "{\"data\":\"\",\"request_id\":2,\"version\":\"storage-child-lifecycle.v2\"}")
            } catch { Issue.record(error) }
        }
        worker.start()
        defer { done.wait() }
        #expect(try child.controllerCSR() == Data([1,2,3])); try child.takeover()
        #expect(child.processIdentity == nil)
    }
    @Test(arguments: [
        "{\"data\":\"AQ==\",\"request_id\":2,\"version\":\"storage-child-lifecycle.v2\"}",
        "{\"data\":\"AQ==\",\"request_id\":1,\"version\":\"v1\"}",
        "{\"data\":\"AQ==\",\"extra\":0,\"request_id\":1,\"version\":\"storage-child-lifecycle.v2\"}",
        "{\"data\":\"AQ==\",\"request_id\":1,\"request_id\":1,\"version\":\"storage-child-lifecycle.v2\"}",
        "{\"data\":\"AQ==\",\"request_id\":1.0,\"version\":\"storage-child-lifecycle.v2\"}",
        "{\"data\":\"\",\"request_id\":1,\"version\":\"storage-child-lifecycle.v2\"}",
        "{\"data\":\"AQ\",\"request_id\":1,\"version\":\"storage-child-lifecycle.v2\"}"
    ], [false, true]) func malformedReplyCloses(reply: String, workload: Bool) throws {
        let pair = try sockets(); defer { pair.forEach { Darwin.close($0) } }
        let child = try Child.adoptingTestSocket(pair[0]); defer { child.close() }
        try frame(pair[1], reply)
        #expect(throws: (any Error).self) { try workload ? child.workloadCommand(request: .query) : child.controllerCSR() }
        #expect(throws: (any Error).self) { try child.controllerCSR() }
    }
    @Test func overflowAndTimeoutRefuse() throws {
        let pair = try sockets(); defer { pair.forEach { Darwin.close($0) } }
        let exhausted = try Child.adoptingTestSocket(pair[0], sequence: UInt64.max)
        #expect(throws: (any Error).self) { try exhausted.controllerCSR() }
        var byte: UInt8 = 0
        #expect(recv(pair[1], &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN)
        exhausted.close()
        let other = try sockets(); defer { other.forEach { Darwin.close($0) } }
        let child = try Child.adoptingTestSocket(other[0], timeout: 0.03)
        let start = ProcessInfo.processInfo.systemUptime
        #expect(throws: (any Error).self) { try child.controllerCSR() }
        #expect(ProcessInfo.processInfo.systemUptime - start < 1)
    }
    @Test(arguments: [UInt32(0), UInt32(65537)]) func frameBounds(size: UInt32) throws {
        let pair = try sockets(); defer { pair.forEach { Darwin.close($0) } }
        let child = try Child.adoptingTestSocket(pair[0]); defer { child.close() }
        var n = size.bigEndian
        try withUnsafeBytes(of: &n) { try write(pair[1], Data($0)) }
        #expect(throws: (any Error).self) { try child.controllerCSR() }
    }
    @Test func unsignedNativeLaunchRejected() throws {
        #expect(throws: (any Error).self) { try Child.launch(installedHelperTeam: "ABCDEFGHIJ") }
    }
    @Test func rejectsNonStreamDescriptors() throws {
        let fd = open("/dev/null", O_RDONLY); defer { Darwin.close(fd) }
        #expect(throws: (any Error).self) { try Child.duplicateConnectedSocket(fd) }
        #expect(fcntl(fd, F_GETFD) >= 0)
    }
    private func rights(_ fd: Int32, bytes: Data, passing: Int32) throws {
        let count = bytes.withUnsafeBytes { raw in
            var iov = iovec(iov_base: UnsafeMutableRawPointer(mutating: raw.baseAddress), iov_len: raw.count)
            return withUnsafeMutablePointer(to: &iov) { pointer in
                var buffer = [UInt32](repeating: 0, count: 4)
                return buffer.withUnsafeMutableBytes { control in
                    control.storeBytes(of: cmsghdr(cmsg_len: 16, cmsg_level: SOL_SOCKET, cmsg_type: SCM_RIGHTS), as: cmsghdr.self)
                    control.storeBytes(of: passing, toByteOffset: 12, as: Int32.self)
                    var message = msghdr(); message.msg_iov = pointer; message.msg_iovlen = 1
                    message.msg_control = control.baseAddress; message.msg_controllen = 16
                    return sendmsg(fd, &message, 0)
                }
            }
        }
        guard count == bytes.count else { throw Child.Failure.protocolViolation }
    }
    @Test(arguments: [false, true], [false, true]) func incomingRightsRejectedAndClosed(onBody: Bool, workload: Bool) throws {
        let pair = try sockets(), stream = try sockets()
        defer { (pair + [stream[1]]).forEach { Darwin.close($0) } }
        let child = try Child.adoptingTestSocket(pair[0]); defer { child.close() }
        let body = Data("{\"data\":\"AQ==\",\"request_id\":1,\"version\":\"storage-child-lifecycle.v2\"}".utf8)
        var n = UInt32(body.count).bigEndian
        let header = withUnsafeBytes(of: &n) { Data($0) }
        if onBody { try write(pair[1], header); try rights(pair[1], bytes: body, passing: stream[0]) }
        else { try rights(pair[1], bytes: header, passing: stream[0]); try write(pair[1], body) }
        Darwin.close(stream[0])
        #expect(throws: (any Error).self) { try workload ? child.workloadCommand(request: .query) : child.controllerCSR() }
        var byte: UInt8 = 0
        #expect(recv(stream[1], &byte, 1, 0) == 0)
    }
    @Test(arguments: [false, true]) func connectTransfersExactlyOneOwnedDuplicate(workload: Bool) throws {
        let pair = try sockets(), stream = try sockets()
        defer { (pair + stream).forEach { Darwin.close($0) } }
        let child = try Child.adoptingTestSocket(pair[0], timeout: 2); defer { child.close() }
        // Existing public startup fixture: DER shape only; not trusted boot evidence.
        let der = Data(base64Encoded: "MIIBQTCB9KADAgECAgEBMAUGAytlcDAnMSUwIwYDVQQDExxzdG9yYWdlIHN0YXJ0dXAgZml4dHVyZSBPTkxZMB4XDTI2MDkxMDAwMDAwMFoXDTI2MDkxMDAxMDAwMFowJzElMCMGA1UEAxMcc3RvcmFnZSBzdGFydHVwIGZpeHR1cmUgT05MWTAqMAUGAytlcAMhAO1JKMYo0cLG6ukDOJBZlWEpWSc6XGP5NjbBRhSshzfRo0UwQzAOBgNVHQ8BAf8EBAMCAgQwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUti6Gf6LzOv5i1daxZC4WIdVDMHgwBQYDK2VwA0EAepwr8ZfdBSPht2c3fXkG8e7GH6DrugyxFkhoze2M2D2Vbfnhl0IlGcgU0xR99U1T04WvXnz8sED2ejOQqaNpAA==")!
        let id = "11111111-1111-4111-8111-111111111111", key = String(repeating: "a", count: 64)
        let identity = try Child.Lifecycle.Identity(store: id, generation: 1, binding: key)
        let signed = try Child.Lifecycle.SignedGrant(grant: .init(operation: .initialize, id: id, identity: identity, serial: 1, expectedEpoch: 0, newKey: key), signature: Data(repeating: 0, count: 64))
        let boot = try Child.Boot(certificateDER: der, identity: identity, rootDER: der, serverSPKI: key, serviceEpoch: id, signed: signed)
        let done = DispatchSemaphore(value: 0)
        Thread.detachNewThread {
            defer { done.signal() }
            do {
                var header: UInt32 = 0, received: Int32 = -1
                defer { if received >= 0 { Darwin.close(received) } }
                let n = try withUnsafeMutableBytes(of: &header) { raw in
                    var iov = iovec(iov_base: raw.baseAddress, iov_len: 4)
                    return try withUnsafeMutablePointer(to: &iov) { pointer in
                        var control = [UInt32](repeating: 0, count: 16)
                        return try control.withUnsafeMutableBytes { ancillary in
                            var message = msghdr(); message.msg_iov = pointer; message.msg_iovlen = 1
                            message.msg_control = ancillary.baseAddress; message.msg_controllen = socklen_t(ancillary.count)
                            let n = recvmsg(pair[1], &message, 0)
                            try #require(n == 4 && message.msg_controllen == 16 && message.msg_flags & (MSG_CTRUNC | MSG_TRUNC) == 0)
                            let cmsg = ancillary.loadUnaligned(as: cmsghdr.self)
                            try #require(cmsg.cmsg_len == 16 && cmsg.cmsg_level == SOL_SOCKET && cmsg.cmsg_type == SCM_RIGHTS)
                            received = ancillary.loadUnaligned(fromByteOffset: 12, as: Int32.self)
                            return n
                        }
                    }
                }
                try #require(n == 4 && header.bigEndian <= 65536)
                let body = try readExact(pair[1], Int(header.bigEndian))
                let tree = try #require(JSONSerialization.jsonObject(with: body) as? [String: Any])
                if workload {
                    #expect(String(decoding: body, as: UTF8.self) == "{\"operation\":\"connect-workload\",\"request_id\":1,\"version\":\"storage-child-lifecycle.v2\"}")
                } else {
                    #expect(tree["operation"] as? String == "connect-boot")
                }
                try write(received, Data([42]))
                try frame(pair[1], "{\"data\":\"\",\"request_id\":1,\"version\":\"storage-child-lifecycle.v2\"}")
            } catch { Issue.record(error) }
        }
        defer { done.wait() }
        let originalFlags = fcntl(stream[0], F_GETFL)
        if workload { try child.connectWorkload(socket: stream[0]) }
        else { try child.connectBoot(socket: stream[0], boot: boot) }
        // Darwin may expose a transient SCM_RIGHTS GC mark in F_GETFL.
        // The transport must preserve the borrowed stream's blocking mode.
        #expect(fcntl(stream[0], F_GETFL) & O_NONBLOCK == originalFlags & O_NONBLOCK)
        #expect(try readExact(stream[1], 1) == Data([42]))
        #expect(fcntl(stream[0], F_GETFD) >= 0)
    }

    @Test func lastUInt64RequestIsExactAndNeverWraps() throws {
        let pair = try sockets(); defer { pair.forEach { Darwin.close($0) } }
        let child = try Child.adoptingTestSocket(pair[0], sequence: UInt64.max - 1); defer { child.close() }
        try frame(pair[1], "{\"data\":\"AQ==\",\"request_id\":18446744073709551615,\"version\":\"storage-child-lifecycle.v2\"}")
        #expect(try child.controllerCSR() == Data([1]))
        #expect(String(decoding: try readFrame(pair[1]), as: UTF8.self) == "{\"operation\":\"controller-csr\",\"request_id\":18446744073709551615,\"version\":\"storage-child-lifecycle.v2\"}")
        #expect(throws: (any Error).self) { try child.controllerCSR() }
        var byte: UInt8 = 0
        #expect(recv(pair[1], &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN)
    }

}

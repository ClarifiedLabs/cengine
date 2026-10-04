#if os(macOS) && DEBUG
import CEngineCore
@testable import CEngineRuntime
import Darwin
import Foundation
import Testing

@Suite struct StorageLifecycleAdoptedConnectionTests {
    private func status() throws -> StorageLifecycleAdoptionRootProtocol.Status {
        let uuid = try StorageIdentity.FilesystemUUID("11111111-1111-4111-8111-111111111111")
        let binding = try StorageIdentity.StoreBinding(storeID: .init(uuid.rawValue), root: .init(volumeUUID: uuid, inode: 2),
            backing: .init(identity: .init(volumeUUID: uuid, inode: 3), size: 4096), expectedExt4UUID: uuid)
        let origin = try StorageLifecycleAdoptionProtocol.Origin(binding: .init(binding), rootPublicKey: Data(repeating: 7, count: 32),
            shimLaunchUUID: uuid.rawValue, specSHA256: String(repeating: "a", count: 64))
        return try .init(origin: origin, shimAudit: Data(repeating: 3, count: 32), shimUniqueID: 3,
            baseEpoch: 1, committedEpoch: 1, allocatedEpoch: 1, pending: nil, latest: nil)
    }
    @Test func anonymousSocketCannotUseAdoptedConstructorAndSendsNoPreface() async throws {
        var fds: [Int32] = [-1, -1]
        try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        let a = FileHandle(fileDescriptor: fds[0], closeOnDealloc: true)
        let b = FileHandle(fileDescriptor: fds[1], closeOnDealloc: true)
        let status = try status()
        _ = await Task.detached {
            #expect(throws: (any Error).self) {
                try StorageLifecycleShimConnection(adoptedBorrowedFD: a.fileDescriptor, status: status)
            }
        }.value
        var byte: UInt8 = 0
        #expect(recv(b.fileDescriptor, &byte, 1, MSG_DONTWAIT) == 0)
    }
    @Test func namedWrongNativePeerIsRejectedBeforePreface() async throws {
        let path = "/tmp/cengine-adopt-\(UUID().uuidString).sock"
        let listener = try UnixSocket.listen(path: path)
        defer { close(listener); unlink(path) }
        let status = try status()
        // Public status remains strict: it cannot select upgrade-safe validation.
        let attempt = Task.detached {
            let fd = try UnixSocket.connect(path: path, timeoutMilliseconds: 5_000)
            defer { close(fd) }
            return try StorageLifecycleShimConnection(adoptedBorrowedFD: fd, status: status)
        }
        // The refusal can close before accept. UnixSocket.accept authenticates
        // peer credentials and rightly rejects that EOF, hiding our byte check.
        let peer = try await Task.detached {
            let fd = Darwin.accept(listener, nil, nil)
            guard fd >= 0 else { throw POSIXError(.EIO) }
            return fd
        }.value
        defer { close(peer) }
        await #expect(throws: (any Error).self) { try await attempt.value }
        var byte: UInt8 = 0
        #expect(recv(peer, &byte, 1, MSG_DONTWAIT) == 0)
    }
    @Test(arguments: [UInt32(0), 1, 0x10000, 0x10003, 0x10010001, 0x10010003])
    func adoptedCodeFlagsRejectInvalidNonRuntimeAdhocAndDebugged(_ flags: UInt32) {
        #expect(!StorageLifecycleShimConnection.validAdoptedCodeFlags(flags))
    }
    @Test func adoptedCodeFlagsRequireValidHardenedRuntime() {
        #expect(StorageLifecycleShimConnection.validAdoptedCodeFlags(0x10001))
        // Unrelated flags do not replace either mandatory bit.
        #expect(StorageLifecycleShimConnection.validAdoptedCodeFlags(0x10001 | 0x200))
    }
    @Test(arguments: [false, true])
    func initialRouterSeparatesAdoptionBeforeTokenDecoding(adopted: Bool) throws {
        var fds: [Int32] = [-1, -1]
        try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        defer { fds.forEach { close($0) } }
        let bytes = adopted ? StorageLifecycleShimProtocol.adoptionPreface
            : try VMShimProtocol.encode(.init(token: "not-an-adoption-proof", operation: .status))
        try StorageLifecycleShimChannel.sendRaw(bytes, fd: fds[0], deadline: .now() + 1)
        let routed = try StorageLifecycleShimChannel.receiveInitialRoute(fd: fds[1], maximum: 4096, deadline: .now() + 1)
        #expect(routed == bytes)
        if adopted { #expect(throws: (any Error).self) { try VMShimProtocol.decode(routed) } }
        else { #expect(try VMShimProtocol.decode(routed).operation == .status) }
    }
    @Test func initialRouterRejectsDescriptorAndMalformedPreface() throws {
        for ancillary in [false, true] {
            var fds: [Int32] = [-1, -1]
            try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
            defer { fds.forEach { close($0) } }
            if ancillary {
                try StorageLifecycleShimChannel.send(Data("not-control".utf8), fd: fds[0], passing: fds[0], deadline: .now() + 1)
            } else {
                var bytes = StorageLifecycleShimProtocol.adoptionPreface
                bytes[bytes.count - 1] = 0
                try StorageLifecycleShimChannel.sendRaw(bytes, fd: fds[0], deadline: .now() + 1)
            }
            #expect(throws: (any Error).self) {
                try StorageLifecycleShimChannel.receiveInitialRoute(fd: fds[1], maximum: 4096, deadline: .now() + 1)
            }
        }
    }
    @Test func currentReadyHasClosedEmptyRequestAndRequiredReply() throws {
        typealias W = StorageLifecycleShimProtocol
        let request = W.Frame(sequence: 1, operation: .currentReady, reply: false)
        #expect(try W.decode(W.encode(request)).operation == .currentReady)
        #expect(throws: (any Error).self) { try W.encode(W.Frame(sequence: 1, operation: .currentReady, reply: true)) }
    }
    @Test func adoptionDiscriminatorIsRawAndNotANormalFrame() throws {
        var fds: [Int32] = [-1, -1]
        try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        defer { fds.forEach { close($0) } }
        let preface = StorageLifecycleShimProtocol.adoptionPreface
        try StorageLifecycleShimChannel.sendRaw(preface, fd: fds[0], deadline: .now() + 1)
        var bytes = Data(count: preface.count)
        let count = bytes.withUnsafeMutableBytes { recv(fds[1], $0.baseAddress, $0.count, MSG_WAITALL) }
        #expect(count == preface.count)
        #expect(bytes == Data([255, 255, 255, 255]) + Data("cengine-lifecycle-adopt.v1\n".utf8))
        #expect(StorageLifecycleShimProtocol.Operation.currentReady.isRepeatable)
        #expect(throws: (any Error).self) { try StorageLifecycleShimProtocol.decode(bytes) }
    }
}
#endif

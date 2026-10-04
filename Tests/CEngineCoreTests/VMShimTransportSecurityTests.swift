#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

/// Native socket regressions only: no VM, helper, or private configuration.
@Suite(.serialized) struct VMShimTransportSecurityTests {
    @Test(arguments: [VMShimManagedTransport.maximumInitialStorageRequestFrameSize + 1,
                      VMShimProtocol.maximumFrameSize])
    func initialStorageRequestRejectsOversizedPrefixWithoutWaitingForBody(size: Int) throws {
        let pair = try SecurityTransportPair(milliseconds: 150)
        try pair.writer.write(securityFramePrefix(size))
        #expect(throws: EngineError.self) {
            try VMShimServer.readInitialManagedRequestFrame(using: pair.reader)
        }
    }

    @Test func everyAdmissionSlotRejectsGenericMaximumBeforeBodyAllocation() throws {
        let admission = VMShimManagedAdmission()
        var pairs: [SecurityTransportPair] = []
        var permits: [VMShimManagedAdmission.Permit] = []
        for _ in 0..<64 {
            let pair = try SecurityTransportPair()
            pairs.append(pair)
            let owned = fcntl(pair.readerDescriptor, F_DUPFD_CLOEXEC, 0)
            try #require(owned >= 0)
            guard let permit = admission.reserve(owned, deadline: pair.reader.deadlineNanoseconds) else {
                Darwin.close(owned)
                Issue.record("admission unexpectedly full")
                return
            }
            permits.append(permit)
            try pair.writer.write(securityFramePrefix(VMShimProtocol.maximumFrameSize))
        }
        for pair in pairs {
            #expect(throws: EngineError.self) {
                try VMShimServer.readInitialManagedRequestFrame(using: pair.reader)
            }
        }
        withExtendedLifetime(permits) {}
    }

    @Test func wireMaximumPayloadFitsOuterEnvelopeEvenWithBase64SlashEscaping() throws {
        // A conservative upper bound: any 64 KiB inner command, even one whose
        // outer Data encoding maximizes slash escaping, still fits comfortably.
        let payload = Data(repeating: 0xff, count: StorageServiceTypes.maxFrame)
        let frame = try VMShimProtocol.encode(.init(token: String(repeating: "a", count: 64),
            operation: .workloadStorageCommand, payload: payload, deadlineNanoseconds: .max))
        #expect(frame.count - 4 < VMShimManagedTransport.maximumInitialStorageRequestFrameSize)
        #expect(VMShimProtocol.maximumFrameSize == 16 * 1_024 * 1_024)
    }

    @Test func maximumSupportedFabricSnapshotFitsAndTransfers() async throws {
        struct Configuration: Encodable { let networks: [VMShimClient.FabricNetwork] }
        // synchronizeFabric sends empty port lists and every non-management
        // VLAN. Use full-width generated IDs and maximum-width IP strings.
        let networks = (1..<VMShimProtocol.managementVLAN).map { vlan in
            VMShimClient.FabricNetwork(id: String(repeating: "a", count: 60) + String(format: "%04x", vlan),
                vlan: vlan, subnet: "255.255.255.254/32", gateway: "255.255.255.254",
                ipv6Subnet: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
                internalNetwork: false, isolated: false, ports: [])
        }
        let payload = try JSONEncoder().encode(Configuration(networks: networks))
        let frame = try VMShimProtocol.encode(.init(token: String(repeating: "a", count: 64),
            operation: .configureFabric, payload: payload, deadlineNanoseconds: .max))
        #expect(networks.count == 4_093)
        #expect(frame.count - 4 > 512 * 1_024)
        try #require(frame.count - 4 <= VMShimManagedTransport.maximumInitialStorageRequestFrameSize)
        let pair = try SecurityTransportPair()
        let writer = Task.detached {
            try await pair.writer.run { try $0.write(frame); return true }
        }
        defer { writer.cancel() }
        let received = try await pair.reader.run { try VMShimServer.readInitialManagedRequestFrame(using: $0) }
        #expect(try VMShimProtocol.decode(received).payload == payload)
        #expect(try await writer.value)
    }

    @Test(arguments: [false, true])
    func cappedBoundaryAndLargerGenericFramesStillTransferInChunks(generic: Bool) async throws {
        let size = VMShimManagedTransport.maximumInitialStorageRequestFrameSize + (generic ? 1 : 0)
        let frame = securityFramePrefix(size) + Data(repeating: 0xa5, count: size)
        let pair = try SecurityTransportPair()
        let writer = Task.detached {
            try await pair.writer.run { try $0.write(frame); return true }
        }
        defer { writer.cancel() }
        let received = try await pair.reader.run {
            if generic { return try $0.readFrame() }
            return try VMShimServer.readInitialManagedRequestFrame(using: $0)
        }
        #expect(received == frame)
        #expect(try await writer.value)
    }

    @Test func incompletePermittedBodyStillUsesOriginalDeadline() throws {
        let pair = try SecurityTransportPair(milliseconds: 100)
        try pair.writer.write(securityFramePrefix(VMShimManagedTransport.maximumInitialStorageRequestFrameSize) + Data([1]))
        #expect(throws: AsyncTimeout.TimeoutError.self) {
            try VMShimServer.readInitialManagedRequestFrame(using: pair.reader)
        }
    }

    @Test func closedAcceptedPeerIsTypedAndNextLivePeerStillWorks() throws {
        let listener = try SecurityTestListener()
        let abandoned = try UnixSocket.connect(path: listener.path)
        Darwin.close(abandoned)
        // Real Darwin accept succeeds, then SO_NOSIGPIPE fails with EINVAL.
        // Only that accepted endpoint is discarded, not the listening socket.
        #expect(throws: UnixSocket.AcceptedPeerConfigurationError.peerDisconnected) {
            try UnixSocket.accept(listener.descriptor)
        }
        let live = try UnixSocket.connect(path: listener.path)
        defer { Darwin.close(live) }
        let accepted = try UnixSocket.accept(listener.descriptor)
        defer { Darwin.close(accepted) }
        #expect(fcntl(accepted, F_GETFD) & FD_CLOEXEC != 0)
        var enabled: CInt = 0
        var length = socklen_t(MemoryLayout<CInt>.size)
        #expect(getsockopt(accepted, SOL_SOCKET, SO_NOSIGPIPE, &enabled, &length) == 0)
        #expect(enabled == 1)
        var sent: UInt8 = 42
        #expect(Darwin.send(live, &sent, 1, MSG_DONTWAIT) == 1)
        var received: UInt8 = 0
        #expect(Darwin.recv(accepted, &received, 1, MSG_DONTWAIT) == 1)
        #expect(received == sent)
    }

    @Test func listenerErrorsAreNotRecoverablePeerConfigurationErrors() throws {
        var descriptors: [CInt] = [-1, -1]
        try #require(Darwin.pipe(&descriptors) == 0)
        defer { for descriptor in descriptors { Darwin.close(descriptor) } }
        for descriptor in [-1, descriptors[0]] { // EBADF and ENOTSOCK, respectively.
            do {
                let unexpected = try UnixSocket.accept(descriptor)
                Darwin.close(unexpected)
                Issue.record("invalid listener unexpectedly accepted")
            } catch {
                #expect(error is EngineError)
                #expect(!(error is UnixSocket.AcceptedPeerConfigurationError))
            }
        }
    }
}

private func securityFramePrefix(_ size: Int) -> Data {
    var value = UInt32(size).bigEndian
    return withUnsafeBytes(of: &value) { Data($0) }
}

private final class SecurityTransportPair: @unchecked Sendable {
    let reader: VMShimManagedTransport
    let writer: VMShimManagedTransport
    let readerDescriptor: CInt

    init(milliseconds: UInt64 = 3_000) throws {
        var descriptors: [CInt] = [-1, -1]
        try #require(Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0)
        let deadline = DispatchTime.now().uptimeNanoseconds + milliseconds * 1_000_000
        reader = VMShimManagedTransport(deadlineNanoseconds: deadline)
        writer = VMShimManagedTransport(deadlineNanoseconds: deadline)
        readerDescriptor = descriptors[0]
        do { try reader.adopt(descriptors[0]) }
        catch { Darwin.close(descriptors[0]); Darwin.close(descriptors[1]); throw error }
        do { try writer.adopt(descriptors[1]) }
        catch { reader.close(); Darwin.close(descriptors[1]); throw error }
    }
}

private final class SecurityTestListener {
    let path = "/tmp/ce-security-\(UUID().uuidString).sock"
    let descriptor: CInt
    init() throws { descriptor = try UnixSocket.listen(path: path) }
    deinit { Darwin.close(descriptor); unlink(path) }
}
#endif

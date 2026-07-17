import Foundation
import Darwin
import Testing
@testable import CEngineRuntime

@Suite struct TrunkNetworkFabricTests {
    private final class DisconnectState: @unchecked Sendable {
        private let lock = NSLock()
        private var value = 0

        var count: Int { lock.withLock { value } }
        func record() { lock.withLock { value += 1 } }
    }

    @Test func vlanFrameParsesTaggedEthernetHeader() {
        let bytes: [UInt8] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x81, 0x00, 0x00, 0x2a,
            0x08, 0x00,
        ]

        let frame = TrunkNetworkFabric.VLANFrame(Data(bytes))

        #expect(frame?.vlan == 42)
    }

    @Test func vlanFrameRejectsUntaggedTraffic() {
        #expect(TrunkNetworkFabric.VLANFrame(Data(repeating: 0, count: 18)) == nil)
    }

    @Test func socketBackpressureDoesNotDisconnectFabricEndpoints() {
        let nested = NSError(
            domain: NSCocoaErrorDomain,
            code: 512,
            userInfo: [NSUnderlyingErrorKey: NSError(domain: NSPOSIXErrorDomain, code: Int(ENOBUFS))]
        )
        #expect(TrunkNetworkFabric.isTransientPacketWriteError(nested))
        #expect(TrunkNetworkFabric.isTransientPacketWriteError(POSIXError(.EAGAIN)))
        #expect(!TrunkNetworkFabric.isTransientPacketWriteError(POSIXError(.EPIPE)))
    }

    @Test func peerClosureUnregistersEndpointAndReportsDisconnect() async throws {
        let fabric = TrunkNetworkFabric()
        let id = TrunkNetworkFabric.EndpointID("uplink")
        let trunk = try RawPacketTrunk()
        let sender = try RawPacketTrunk()
        let state = DisconnectState()

        await fabric.register(id, file: trunk.fabricFileHandle, vlans: [1]) { state.record() }
        await fabric.register(.init("sender"), file: sender.fabricFileHandle, vlans: [1])
        try trunk.virtualMachineFileHandle.close()
        let frame = Data([
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x81, 0x00, 0x00, 0x01,
            0x08, 0x00,
        ])
        try sender.virtualMachineFileHandle.write(contentsOf: frame)

        for _ in 0..<100 where state.count == 0 {
            try await Task.sleep(for: .milliseconds(10))
        }

        #expect(state.count == 1)
        #expect(await fabric.memberships(id).isEmpty)
    }

    @Test func intentionalUnregisterDoesNotReportDisconnect() async throws {
        let fabric = TrunkNetworkFabric()
        let id = TrunkNetworkFabric.EndpointID("uplink")
        let trunk = try RawPacketTrunk()
        let state = DisconnectState()

        await fabric.register(id, file: trunk.fabricFileHandle, vlans: [1]) { state.record() }
        await fabric.unregister(id)
        try trunk.virtualMachineFileHandle.close()
        try await Task.sleep(for: .milliseconds(50))

        #expect(state.count == 0)
    }

    @Test func staleRegistrationCannotUnregisterReplacementEndpoint() async throws {
        let fabric = TrunkNetworkFabric()
        let id = TrunkNetworkFabric.EndpointID("container")
        let first = try RawPacketTrunk()
        let second = try RawPacketTrunk()
        let firstRegistration = UUID()
        let secondRegistration = UUID()

        await fabric.register(id, file: first.fabricFileHandle, vlans: [1], registration: firstRegistration)
        await fabric.register(id, file: second.fabricFileHandle, vlans: [2], registration: secondRegistration)
        await fabric.unregister(id, registration: firstRegistration)

        #expect(await fabric.memberships(id) == [2])

        await fabric.unregister(id, registration: secondRegistration)
        #expect(await fabric.memberships(id).isEmpty)
    }
}

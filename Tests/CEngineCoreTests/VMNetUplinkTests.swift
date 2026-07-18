#if os(macOS)
import CEngineCore
import Foundation
import Testing
@testable import CEngineRuntime

@Suite struct VMNetUplinkTests {
    private final class EventState: @unchecked Sendable {
        private let lock = NSLock()
        private var value = 0

        var count: Int { lock.withLock { value } }
        func record() { lock.withLock { value += 1 } }
    }

    @Test func vlanTagRoundTripsWithoutChangingEthernetFrame() {
        let frame = Data([0,1,2,3,4,5,6,7,8,9,10,11,0x08,0x00,0x45,0,0,20])
        let tagged = VMNetUplink.tag(frame, vlan: 4094)
        #expect(tagged.count == frame.count + 4)
        #expect(tagged[12] == 0x81)
        #expect(tagged[13] == 0)
        #expect(VMNetUplink.untag(tagged, vlan: 4094) == frame)
        #expect(VMNetUplink.untag(tagged, vlan: 1) == nil)
    }

    @Test func privilegedVMNetRequestRoundTripsAcrossXPCPayload() throws {
        let request = PrivilegedVMNetRequest(
            id: "bridge", vlan: 42, subnet: "172.24.0.0/16", gateway: "172.24.0.1", ipv6Subnet: "fd00:24::/64",
            internalNetwork: false,
            dhcpEnabled: false,
            ports: [.init(proto: "tcp", externalPort: 8080, internalAddress: "172.24.0.2", internalPort: 80)]
        )
        #expect(PrivilegedPortProtocol.version == 4)
        let decoded = try JSONDecoder().decode(PrivilegedVMNetRequest.self, from: JSONEncoder().encode(request))
        #expect(decoded == request)
        #expect(decoded.dhcpEnabled == false)
    }

    @Test func automaticDockerNetworksUseVMNetSupportedPrivateRange() {
        let first = RawVirtualizationBackend.automaticIPv4Network(vlan: 1)
        #expect(first.subnet == "10.240.1.0/24")
        #expect(first.gateway == "10.240.1.1")

        let boundary = RawVirtualizationBackend.automaticIPv4Network(vlan: 256)
        #expect(boundary.subnet == "10.241.0.0/24")
        #expect(boundary.gateway == "10.241.0.1")

        let last = RawVirtualizationBackend.automaticIPv4Network(vlan: 4093)
        #expect(last.subnet == "10.255.253.0/24")
        #expect(last.gateway == "10.255.253.1")
        #expect(RawVirtualizationBackend.nextAvailableVLAN(used: Set(1...4093)) == nil)
    }

    @Test func failedNetworkCreateRollsBackRecordAndVLAN() {
        let network = NetworkRecord(
            id: "network-1",
            name: "rollback",
            subnet: "10.70.0.0/24",
            gateway: "10.70.0.1"
        )
        var networks: [String: NetworkRecord] = [:]
        var vlans: [String: UInt16] = [:]
        let transaction = RawNetworkStateTransaction(
            adding: network,
            vlan: 70,
            networks: networks,
            networkVLANs: vlans
        )

        transaction.apply(networks: &networks, networkVLANs: &vlans)
        #expect(networks[network.id]?.name == "rollback")
        #expect(vlans[network.id] == 70)

        // This is the state restoration used when fabric synchronization or
        // persistence throws during RawVirtualizationBackend.createNetwork.
        transaction.rollback(networks: &networks, networkVLANs: &vlans)
        #expect(networks[network.id] == nil)
        #expect(vlans[network.id] == nil)
    }

    @Test func uplinkDisconnectBeforeHandlerIsDeliveredExactlyOnce() {
        let events = VMNetUplinkEvents()
        let state = EventState()

        events.disconnect()
        events.setDisconnectHandler { state.record() }
        events.setDisconnectHandler { state.record() }
        events.disconnect()

        #expect(state.count == 1)
    }

    @Test func intentionalUplinkCancellationSuppressesDisconnect() {
        let events = VMNetUplinkEvents()
        let state = EventState()

        events.setDisconnectHandler { state.record() }
        events.cancel()
        events.disconnect()

        #expect(state.count == 0)
    }

    @Test func unavailablePrivilegedNetworkingHelperHasBoundedDeadline() async {
        let clock = ContinuousClock()
        let started = clock.now
        var didThrow = false

        do {
            _ = try await VMNetUplink.awaitUplinkReply(timeout: .milliseconds(25)) { _ in }
        } catch {
            didThrow = true
        }

        #expect(didThrow)
        #expect(clock.now - started < .seconds(1))
    }
}
#endif

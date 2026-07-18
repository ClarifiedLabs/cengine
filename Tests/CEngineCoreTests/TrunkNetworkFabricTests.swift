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

    private func dnsQuery(name: String, type: UInt16 = 1, vlan: UInt16 = 42) -> Data {
        var dns: [UInt8] = [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        for label in name.split(separator: ".") {
            dns.append(UInt8(label.utf8.count))
            dns.append(contentsOf: label.utf8)
        }
        dns.append(0)
        dns.append(contentsOf: [UInt8(type >> 8), UInt8(type & 0xff), 0, 1])
        let udpLength = 8 + dns.count
        let ipLength = 20 + udpLength
        var packet: [UInt8] = [
            0x5e, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x02, 0xce, 0x00, 0x00, 0x00, 0x02,
            0x81, 0x00, UInt8((vlan >> 8) & 0x0f), UInt8(vlan & 0xff),
            0x08, 0x00,
            0x45, 0x00, UInt8(ipLength >> 8), UInt8(ipLength & 0xff),
            0x00, 0x01, 0x40, 0x00, 64, 17, 0, 0,
            10, 240, 2, 2, 10, 240, 2, 1,
            0xcf, 0x08, 0x00, 0x35, UInt8(udpLength >> 8), UInt8(udpLength & 0xff), 0, 0,
        ]
        packet.append(contentsOf: dns)
        return Data(packet)
    }

    private func readUInt16(_ bytes: [UInt8], at offset: Int) -> UInt16 {
        UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }

    private func checksum(_ bytes: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        for index in stride(from: 0, to: bytes.count - 1, by: 2) {
            sum += UInt32(bytes[index]) << 8 | UInt32(bytes[index + 1])
        }
        if bytes.count % 2 == 1 { sum += UInt32(bytes[bytes.count - 1]) << 8 }
        while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
        return UInt16(sum)
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

    @Test func dockerHostDNSAnswersWithNetworkGateway() throws {
        var responder = DockerHostDNSResponder()
        responder.configure(gateways: [42: "10.240.2.1"])

        let response = [UInt8](try #require(responder.response(
            to: dnsQuery(name: "host.docker.internal")
        )))
        let dnsOffset = 18 + 20 + 8

        #expect(Array(response[0..<6]) == [0x02, 0xce, 0, 0, 0, 2])
        #expect(Array(response[6..<12]) == [0x5e, 0, 0, 0, 0, 1])
        #expect(Array(response[30..<34]) == [10, 240, 2, 1])
        #expect(Array(response[34..<38]) == [10, 240, 2, 2])
        #expect(readUInt16(response, at: 38) == 53)
        #expect(readUInt16(response, at: 40) == 53_000)
        #expect(readUInt16(response, at: dnsOffset + 2) & 0x8000 != 0)
        #expect(readUInt16(response, at: dnsOffset + 6) == 1)
        #expect(Array(response.suffix(4)) == [10, 240, 2, 1])
        #expect(checksum(Array(response[18..<38])) == UInt16.max)
        let udpLength = Int(readUInt16(response, at: 42))
        var udpChecksumInput = Array(response[30..<38]) + [0, 17]
        udpChecksumInput += [UInt8(udpLength >> 8), UInt8(udpLength & 0xff)]
        udpChecksumInput.append(contentsOf: response[38..<(38 + udpLength)])
        #expect(checksum(udpChecksumInput) == UInt16.max)
    }

    @Test func dockerHostDNSReturnsNoDataForIPv6AndForwardsOtherNames() throws {
        var responder = DockerHostDNSResponder()
        responder.configure(gateways: [42: "10.240.2.1"])

        let response = [UInt8](try #require(responder.response(
            to: dnsQuery(name: "HOST.DOCKER.INTERNAL", type: 28)
        )))
        let dnsOffset = 18 + 20 + 8
        #expect(readUInt16(response, at: dnsOffset + 6) == 0)
        #expect(readUInt16(response, at: dnsOffset + 2) & 0x000f == 0)
        #expect(responder.response(to: dnsQuery(name: "example.com")) == nil)
        #expect(responder.response(to: dnsQuery(name: "host.docker.internal", vlan: 43)) == nil)
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

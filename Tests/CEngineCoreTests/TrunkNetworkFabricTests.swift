import Foundation
import Testing
@testable import CEngineRuntime

@Suite struct TrunkNetworkFabricTests {
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
}

#if os(macOS)
import CEngineCore
import Testing

@Suite struct VMNetIPv4ConfigurationTests {
    @Test(arguments: [
        ("10.90.0.0", "10.90.0.0/31"),
        ("10.90.0.1", "10.90.0.0/31"),
    ])
    func privilegedHelperAcceptsEitherRFC3021Gateway(
        _ gateway: String,
        _ subnet: String
    ) throws {
        _ = try VMNetIPv4Configuration.gateway(gateway, in: subnet)
    }

    @Test func privilegedHelperStillRejectsReservedBoundariesOnLargerSubnets() {
        #expect(throws: EngineError.self) {
            _ = try VMNetIPv4Configuration.gateway("10.90.0.0", in: "10.90.0.0/30")
        }
        #expect(throws: EngineError.self) {
            _ = try VMNetIPv4Configuration.gateway("10.90.0.3", in: "10.90.0.0/30")
        }
        #expect(throws: EngineError.self) {
            _ = try VMNetIPv4Configuration.gateway("10.90.0.4", in: "10.90.0.0/30")
        }
    }
}
#endif

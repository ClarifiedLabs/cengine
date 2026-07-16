import Foundation
import Testing
@testable import CEngineCore

@Suite struct EndpointMacAddressTests {
    @Test func generatedMacIsDeterministicLocallyAdministeredUnicast() {
        let first = EndpointMacAddress.generated(seed: "container-a" + "network-1")
        let second = EndpointMacAddress.generated(seed: "container-a" + "network-1")
        #expect(first == second)
        #expect(first.hasPrefix("02:ce:"))
        #expect(EndpointMacAddress.isValid(first))
        #expect(first != EndpointMacAddress.generated(seed: "container-a" + "network-2"))
    }

    @Test func normalizationCanonicalizesValidAddresses() {
        #expect(EndpointMacAddress.normalized("02:42:AC:11:00:02") == "02:42:ac:11:00:02")
        #expect(EndpointMacAddress.normalized("02-42-ac-11-00-02") == "02:42:ac:11:00:02")
        #expect(EndpointMacAddress.normalized("de:ad:be:ef:00:0a") == "de:ad:be:ef:00:0a")
    }

    @Test func normalizationRejectsInvalidAddresses() {
        // Malformed shapes.
        #expect(EndpointMacAddress.normalized("") == nil)
        #expect(EndpointMacAddress.normalized("02:42:ac:11:00") == nil)
        #expect(EndpointMacAddress.normalized("02:42:ac:11:00:02:03") == nil)
        #expect(EndpointMacAddress.normalized("0242ac110002") == nil)
        #expect(EndpointMacAddress.normalized("02:42:ac:11:0:02") == nil)
        #expect(EndpointMacAddress.normalized("zz:42:ac:11:00:02") == nil)
        #expect(EndpointMacAddress.normalized("02:42:ac:11:00:0g") == nil)
        // Broadcast and multicast/group addresses (I/G bit set on first octet).
        #expect(EndpointMacAddress.normalized("ff:ff:ff:ff:ff:ff") == nil)
        #expect(EndpointMacAddress.normalized("01:00:5e:00:00:01") == nil)
        #expect(EndpointMacAddress.normalized("03:42:ac:11:00:02") == nil)
        // All-zero address.
        #expect(EndpointMacAddress.normalized("00:00:00:00:00:00") == nil)
    }
}

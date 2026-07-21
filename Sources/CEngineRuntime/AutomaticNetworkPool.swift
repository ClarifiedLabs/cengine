import CEngineCore
import Foundation

/// Host-level address ranges used when Docker omits IPAM configuration.
/// A /12 supplies one /24 for every allocatable VLAN; a /16 IPv6 prefix
/// supplies one /64 by placing the VLAN in the second hextet.
public struct AutomaticNetworkPool: Equatable, Sendable {
    public static let `default` = try! AutomaticNetworkPool(
        ipv4CIDR: "10.240.0.0/12",
        ipv6Prefix: "fdce::/16"
    )

    public let ipv4CIDR: String
    public let ipv6Prefix: String
    private let ipv4SecondOctet: Int
    private let ipv6FirstHextet: UInt16

    public init(ipv4CIDR: String, ipv6Prefix: String) throws {
        let ipv4Parts = ipv4CIDR.split(separator: "/", omittingEmptySubsequences: false)
        let octets = ipv4Parts.first?.split(separator: ".", omittingEmptySubsequences: false) ?? []
        guard ipv4Parts.count == 2, ipv4Parts[1] == "12", octets.count == 4,
              let first = Int(octets[0]), let second = Int(octets[1]),
              let third = Int(octets[2]), let fourth = Int(octets[3]),
              first == 10, (0...240).contains(second), second.isMultiple(of: 16),
              third == 0, fourth == 0 else {
            throw EngineError(
                .badRequest,
                "automatic IPv4 pool must be an aligned RFC 1918 /12, such as 10.240.0.0/12"
            )
        }

        let ipv6Parts = ipv6Prefix.split(separator: "/", omittingEmptySubsequences: false)
        guard ipv6Parts.count == 2, ipv6Parts[1] == "16",
              ipv6Parts[0].hasSuffix("::"),
              let hextet = UInt16(ipv6Parts[0].dropLast(2), radix: 16),
              (hextet & 0xfe00) == 0xfc00 else {
            throw EngineError(
                .badRequest,
                "automatic IPv6 prefix must be an aligned ULA /16, such as fdce::/16"
            )
        }

        self.ipv4CIDR = "10.\(second).0.0/12"
        self.ipv6Prefix = String(format: "%04x::/16", hextet)
        ipv4SecondOctet = second
        ipv6FirstHextet = hextet
    }

    func ipv4Network(vlan: UInt16) -> (subnet: String, gateway: String) {
        precondition((1..<VMShimProtocol.managementVLAN).contains(vlan))
        let slot = Int(vlan)
        let prefix = "10.\(ipv4SecondOctet + slot / 256).\(slot % 256)"
        return ("\(prefix).0/24", "\(prefix).1")
    }

    func ipv6Network(vlan: UInt16) -> (subnet: String, gateway: String) {
        precondition((1..<VMShimProtocol.managementVLAN).contains(vlan))
        let prefix = String(format: "%x:%x", ipv6FirstHextet, vlan)
        return ("\(prefix)::/64", "\(prefix)::1")
    }
}

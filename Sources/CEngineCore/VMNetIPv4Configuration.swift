#if os(macOS)
import Darwin

/// IPv4 subnet validation shared with the privileged vmnet helper.
public enum VMNetIPv4Configuration {
    public static func subnet(_ value: String) throws -> (address: in_addr, mask: in_addr) {
        let parts = value.split(separator: "/")
        guard parts.count == 2, let prefix = Int(parts[1]), (0...32).contains(prefix) else {
            throw EngineError(.badRequest, "invalid IPv4 subnet \(value)")
        }
        var subnet = in_addr()
        guard inet_pton(AF_INET, String(parts[0]), &subnet) == 1 else {
            throw EngineError(.badRequest, "invalid IPv4 subnet \(value)")
        }
        let bits: UInt32 = prefix == 0 ? 0 : UInt32.max << UInt32(32 - prefix)
        return (subnet, in_addr(s_addr: bits.bigEndian))
    }

    public static func gateway(_ value: String, in subnet: String) throws -> in_addr {
        let (networkAddress, maskAddress) = try self.subnet(subnet)
        var gateway = in_addr()
        guard inet_pton(AF_INET, value, &gateway) == 1 else {
            throw EngineError(.badRequest, "invalid IPv4 gateway \(value)")
        }
        let network = UInt32(bigEndian: networkAddress.s_addr)
        let mask = UInt32(bigEndian: maskAddress.s_addr)
        let address = UInt32(bigEndian: gateway.s_addr)
        let first = network & mask
        let last = first | ~mask
        let hasNetworkAndBroadcastReservations = ~mask > 1
        guard address & mask == first,
              !hasNetworkAndBroadcastReservations || (address != first && address != last) else {
            throw EngineError(.badRequest, "IPv4 gateway \(value) is outside subnet \(subnet)")
        }
        return gateway
    }
}
#endif

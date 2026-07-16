import CryptoKit
import Foundation

/// Shared helpers for endpoint MAC addresses so the Docker API inspect surface
/// and the virtualization backend derive and validate MACs identically.
public enum EndpointMacAddress {
    /// Deterministically derives a stable, locally-administered unicast MAC from
    /// a seed. The same seed always yields the same address so inspect output
    /// mirrors the value applied inside the guest and survives daemon recovery.
    public static func generated(seed: String) -> String {
        let digest = SHA256.hash(data: Data(seed.utf8))
        var bytes = Array(digest.prefix(4))
        while bytes.count < 4 { bytes.append(0) }
        return String(format: "02:ce:%02x:%02x:%02x:%02x", bytes[0], bytes[1], bytes[2], bytes[3])
    }

    /// Validates and normalizes a requested Ethernet (EUI-48) MAC address.
    ///
    /// Accepts six colon- or hyphen-separated hexadecimal octets,
    /// case-insensitively, and returns the canonical lowercase colon-separated
    /// form. Returns `nil` for malformed input, the all-zero address, and any
    /// broadcast or multicast/group address (least-significant bit of the first
    /// octet set), so callers can reject them explicitly instead of silently
    /// accepting an address the guest could never apply.
    public static func normalized(_ value: String) -> String? {
        let fields: [Substring]
        if value.contains(":") {
            fields = value.split(separator: ":", omittingEmptySubsequences: false)
        } else if value.contains("-") {
            fields = value.split(separator: "-", omittingEmptySubsequences: false)
        } else {
            return nil
        }
        guard fields.count == 6 else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(6)
        for field in fields {
            guard field.count == 2, field.allSatisfy(\.isHexDigit),
                  let byte = UInt8(field, radix: 16) else { return nil }
            bytes.append(byte)
        }
        // The least-significant bit of the first octet is the I/G bit; when set
        // the address is multicast (this also covers the broadcast address).
        if bytes[0] & 0x01 != 0 { return nil }
        // The all-zero address is not a usable unicast host address.
        if bytes.allSatisfy({ $0 == 0 }) { return nil }
        return bytes.map { String(format: "%02x", $0) }.joined(separator: ":")
    }

    /// Whether `value` is a valid unicast Ethernet MAC address.
    public static func isValid(_ value: String) -> Bool { normalized(value) != nil }
}

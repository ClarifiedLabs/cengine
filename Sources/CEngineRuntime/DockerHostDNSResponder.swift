#if os(macOS)
import Foundation

/// Answers Docker Desktop's host alias before DNS traffic leaves the container
/// fabric. Other names continue to the vmnet resolver unchanged.
struct DockerHostDNSResponder {
    private static let hostName = "host.docker.internal"
    private var gateways: [UInt16: [UInt8]] = [:]

    mutating func configure(gateways values: [UInt16: String]) {
        gateways = values.reduce(into: [:]) { result, entry in
            if let address = Self.ipv4Address(entry.value) {
                result[entry.key] = address
            }
        }
    }

    func response(to frame: Data) -> Data? {
        let ethernetHeaderLength = 18
        guard frame.count >= ethernetHeaderLength + 20 + 8 + 12 else { return nil }
        let start = frame.startIndex
        guard frame[start + 12] == 0x81, frame[start + 13] == 0x00,
              frame[start + 16] == 0x08, frame[start + 17] == 0x00 else { return nil }

        let vlan = (UInt16(frame[start + 14] & 0x0f) << 8) | UInt16(frame[start + 15])
        guard let gateway = gateways[vlan] else { return nil }

        let ipOffset = ethernetHeaderLength
        let ipHeaderLength = Int(frame[start + ipOffset] & 0x0f) * 4
        guard frame[start + ipOffset] >> 4 == 4, ipHeaderLength >= 20,
              frame.count >= ipOffset + ipHeaderLength + 8,
              frame[start + ipOffset + 9] == 17,
              (0..<4).allSatisfy({ frame[start + ipOffset + 16 + $0] == gateway[$0] }) else { return nil }

        let ipLength = Int(Self.readUInt16(frame, at: ipOffset + 2))
        let fragmentation = Self.readUInt16(frame, at: ipOffset + 6)
        guard fragmentation & 0x3fff == 0,
              ipLength >= ipHeaderLength + 8 + 12,
              frame.count >= ipOffset + ipLength else { return nil }

        let udpOffset = ipOffset + ipHeaderLength
        let udpLength = Int(Self.readUInt16(frame, at: udpOffset + 4))
        guard Self.readUInt16(frame, at: udpOffset + 2) == 53,
              udpLength >= 8 + 12,
              udpLength <= ipLength - ipHeaderLength else { return nil }

        // Copy only DNS traffic addressed to a configured gateway; ordinary
        // fabric traffic stays on the forwarding hot path without allocation.
        let input = [UInt8](frame)
        let dnsOffset = udpOffset + 8
        let dnsEnd = udpOffset + udpLength
        let queryFlags = Self.readUInt16(input, at: dnsOffset + 2)
        guard queryFlags & 0x8000 == 0,
              queryFlags & 0x7800 == 0,
              Self.readUInt16(input, at: dnsOffset + 4) == 1 else { return nil }

        var cursor = dnsOffset + 12
        var labels: [String] = []
        while cursor < dnsEnd {
            let length = Int(input[cursor])
            cursor += 1
            if length == 0 { break }
            guard length <= 63, cursor + length <= dnsEnd,
                  let label = String(bytes: input[cursor..<(cursor + length)], encoding: .ascii) else { return nil }
            labels.append(label)
            cursor += length
        }
        guard labels.joined(separator: ".").lowercased() == Self.hostName,
              cursor + 4 <= dnsEnd else { return nil }

        let queryType = Self.readUInt16(input, at: cursor)
        let queryClass = Self.readUInt16(input, at: cursor + 2)
        guard queryClass == 1 else { return nil }
        let questionEnd = cursor + 4
        let includeIPv4Answer = queryType == 1 || queryType == 255

        var dns: [UInt8] = []
        dns.append(contentsOf: input[dnsOffset..<(dnsOffset + 2)])
        Self.appendUInt16(0x8080 | (queryFlags & 0x0110), to: &dns)
        Self.appendUInt16(1, to: &dns)
        Self.appendUInt16(includeIPv4Answer ? 1 : 0, to: &dns)
        Self.appendUInt16(0, to: &dns)
        Self.appendUInt16(0, to: &dns)
        dns.append(contentsOf: input[(dnsOffset + 12)..<questionEnd])
        if includeIPv4Answer {
            Self.appendUInt16(0xc00c, to: &dns)
            Self.appendUInt16(1, to: &dns)
            Self.appendUInt16(1, to: &dns)
            dns.append(contentsOf: [0, 0, 2, 88]) // 600-second TTL.
            Self.appendUInt16(4, to: &dns)
            dns.append(contentsOf: gateway)
        }

        let responseIPLength = ipHeaderLength + 8 + dns.count
        let responseUDPLength = 8 + dns.count
        guard responseIPLength <= Int(UInt16.max), responseUDPLength <= Int(UInt16.max) else { return nil }

        var output = Array(input[..<dnsOffset])
        output.append(contentsOf: dns)
        for index in 0..<6 { output.swapAt(index, index + 6) }
        for index in 0..<4 { output.swapAt(ipOffset + 12 + index, ipOffset + 16 + index) }
        for index in 0..<2 { output.swapAt(udpOffset + index, udpOffset + 2 + index) }
        Self.writeUInt16(UInt16(responseIPLength), to: &output, at: ipOffset + 2)
        Self.writeUInt16(UInt16(responseUDPLength), to: &output, at: udpOffset + 4)
        Self.writeUInt16(0, to: &output, at: ipOffset + 10)
        Self.writeUInt16(0, to: &output, at: udpOffset + 6)

        let ipChecksum = Self.checksum(Array(output[ipOffset..<(ipOffset + ipHeaderLength)]))
        Self.writeUInt16(ipChecksum, to: &output, at: ipOffset + 10)

        var udpChecksumInput = Array(output[(ipOffset + 12)..<(ipOffset + 20)])
        udpChecksumInput.append(contentsOf: [0, 17])
        Self.appendUInt16(UInt16(responseUDPLength), to: &udpChecksumInput)
        udpChecksumInput.append(contentsOf: output[udpOffset..<(udpOffset + responseUDPLength)])
        let udpChecksum = Self.checksum(udpChecksumInput)
        Self.writeUInt16(udpChecksum == 0 ? UInt16.max : udpChecksum, to: &output, at: udpOffset + 6)
        return Data(output)
    }

    private static func ipv4Address(_ value: String) -> [UInt8]? {
        let components = value.split(separator: ".", omittingEmptySubsequences: false)
        guard components.count == 4 else { return nil }
        let bytes = components.compactMap { UInt8($0) }
        return bytes.count == 4 ? bytes : nil
    }

    private static func readUInt16(_ bytes: Data, at offset: Int) -> UInt16 {
        let index = bytes.startIndex + offset
        return UInt16(bytes[index]) << 8 | UInt16(bytes[index + 1])
    }

    private static func readUInt16(_ bytes: [UInt8], at offset: Int) -> UInt16 {
        UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }

    private static func appendUInt16(_ value: UInt16, to bytes: inout [UInt8]) {
        bytes.append(UInt8(value >> 8))
        bytes.append(UInt8(value & 0xff))
    }

    private static func writeUInt16(_ value: UInt16, to bytes: inout [UInt8], at offset: Int) {
        bytes[offset] = UInt8(value >> 8)
        bytes[offset + 1] = UInt8(value & 0xff)
    }

    private static func checksum(_ bytes: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        var index = 0
        while index + 1 < bytes.count {
            sum += UInt32(bytes[index]) << 8 | UInt32(bytes[index + 1])
            index += 2
        }
        if index < bytes.count { sum += UInt32(bytes[index]) << 8 }
        while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
        return ~UInt16(sum)
    }
}
#endif

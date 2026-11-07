import CEngineCore
import Darwin
import Foundation
import StorageBootstrapHelper
import Testing

@Suite(.serialized) struct UserspaceNetworkUplinkTests {
    private static let guestMAC: [UInt8] = [0x02, 0x42, 0x0a, 0xc0, 0x00, 0x02]
    private static let gatewayMAC: [UInt8] = [0x02, 0xce, 0x4e, 0x47, 0x00, 0x07]
    private static let guestIP: [UInt8] = [10, 192, 0, 2]
    private static let gatewayIP: [UInt8] = [10, 192, 0, 1]
    private static let guestIP6: [UInt8] = [0xfd, 0x00, 0x00, 0xce, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
    private static let gatewayIP6: [UInt8] = [0xfd, 0x00, 0x00, 0xce, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    private static let vlan: UInt16 = 7

    private static func readTaggedFrame(_ fd: CInt, timeoutMs: Int32 = 5000) async throws -> [UInt8] {
        try await withCheckedThrowingContinuation { continuation in
            Thread.detachNewThread {
                var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
                let ready = Darwin.poll(&pfd, 1, timeoutMs)
                guard ready > 0 else {
                    continuation.resume(throwing: EngineError(.internalError, "timed out waiting for frame on packet socket"))
                    return
                }
                var buffer = [UInt8](repeating: 0, count: 65_535)
                let n = buffer.withUnsafeMutableBytes { raw in
                    Darwin.recv(fd, raw.baseAddress, raw.count, 0)
                }
                guard n > 0 else {
                    continuation.resume(throwing: EngineError(.internalError, "failed reading frame from packet socket"))
                    return
                }
                let tagged = Data(buffer.prefix(n))
                guard let untagged = UserspaceNetworkUplink.untag(tagged, vlan: vlan) else {
                    continuation.resume(throwing: EngineError(.internalError, "failed untagging frame from packet socket"))
                    return
                }
                continuation.resume(returning: [UInt8](untagged))
            }
        }
    }

    private static func writeUntaggedFrame(_ fd: CInt, _ frame: [UInt8]) throws {
        let tagged = UserspaceNetworkUplink.tag(Data(frame), vlan: vlan)
        let written = tagged.withUnsafeBytes { raw in
            Darwin.send(fd, raw.baseAddress, raw.count, 0)
        }
        #expect(written == tagged.count)
    }

    @Test func arpAndNdpRespondOnlyForConfiguredGateways() async throws {
        let request = PrivilegedVMNetRequest(
            namespace: "compat",
            id: "net-arp-ndp",
            vlan: Self.vlan,
            subnet: "10.192.0.0/24",
            gateway: "10.192.0.1",
            ipv6Subnet: "fd00:ce::/64",
            internalNetwork: false,
            dhcpEnabled: false,
            ports: []
        )
        let (uplink, clientFD) = try UserspaceNetworkUplink.start(request: request)
        defer {
            Darwin.close(clientFD)
            Task { await uplink.stop() }
        }

        // 1. ARP request for another peer IP (10.192.0.3) must be ignored.
        var peerARP: [UInt8] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff] + Self.guestMAC + [0x08, 0x06]
        peerARP += [0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01]
        peerARP += Self.guestMAC + Self.guestIP
        peerARP += [0, 0, 0, 0, 0, 0] + [10, 192, 0, 3]
        try Self.writeUntaggedFrame(clientFD, peerARP)

        // 2. ARP request for gateway IP (10.192.0.1) must receive ARP reply.
        var gwARP: [UInt8] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff] + Self.guestMAC + [0x08, 0x06]
        gwARP += [0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01]
        gwARP += Self.guestMAC + Self.guestIP
        gwARP += [0, 0, 0, 0, 0, 0] + Self.gatewayIP
        try Self.writeUntaggedFrame(clientFD, gwARP)

        let arpReply = try await Self.readTaggedFrame(clientFD)
        #expect(arpReply.count == 42)
        #expect(Array(arpReply[0..<6]) == Self.guestMAC)
        #expect(Array(arpReply[6..<12]) == Self.gatewayMAC)
        #expect(Array(arpReply[20..<22]) == [0x00, 0x02])
        #expect(Array(arpReply[22..<28]) == Self.gatewayMAC)
        #expect(Array(arpReply[28..<32]) == Self.gatewayIP)

        // 3. IPv6 Neighbor Solicitation for gatewayIP6 (fd00:ce::1).
        var nsPayload: [UInt8] = [135, 0, 0, 0, 0, 0, 0, 0] + Self.gatewayIP6
        nsPayload += [1, 1] + Self.guestMAC
        var nsFrame: [UInt8] = [0x33, 0x33, 0xff, 0x00, 0x00, 0x01] + Self.guestMAC + [0x86, 0xdd]
        nsFrame += [0x60, 0x00, 0x00, 0x00, 0x00, UInt8(nsPayload.count), 58, 255]
        nsFrame += Self.guestIP6 + Self.gatewayIP6 + nsPayload
        try Self.writeUntaggedFrame(clientFD, nsFrame)

        let naReply = try await Self.readTaggedFrame(clientFD)
        #expect(naReply.count >= 14 + 40 + 32)
        #expect(naReply[14 + 6] == 58)
        #expect(naReply[14 + 40] == 136) // Neighbor Advertisement
        #expect(Array(naReply[(14 + 40 + 8)..<(14 + 40 + 24)]) == Self.gatewayIP6)
        #expect(Array(naReply[(14 + 40 + 26)..<(14 + 40 + 32)]) == Self.gatewayMAC)

        await uplink.stop()
    }

    @Test func udpAndDnsForwardingRoundTripToLocalHostServices() async throws {
        // Start a local UDP echo/DNS stub on 127.0.0.1:0.
        let serverFD = socket(AF_INET, SOCK_DGRAM, 0)
        #expect(serverFD >= 0)
        defer { Darwin.close(serverFD) }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bindStatus = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(serverFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        #expect(bindStatus == 0)
        var boundLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.getsockname(serverFD, $0, &boundLen)
            }
        }
        let serverPort = UInt16(bigEndian: addr.sin_port)

        let request = PrivilegedVMNetRequest(
            namespace: "compat",
            id: "net-udp-dns",
            vlan: Self.vlan,
            subnet: "10.192.0.0/24",
            gateway: "10.192.0.1",
            ipv6Subnet: "",
            internalNetwork: false,
            dhcpEnabled: false,
            ports: []
        )
        let (uplink, clientFD) = try UserspaceNetworkUplink.start(
            request: request,
            dnsOverride: .init(ipv4Address: [127, 0, 0, 1], port: serverPort)
        )
        defer {
            Darwin.close(clientFD)
            Task { await uplink.stop() }
        }

        // Send a UDP packet to gateway:53 (DNS query) and verify it reaches serverFD and returns from gateway:53.
        let dnsPayload: [UInt8] = [0x12, 0x34, 0x01, 0x00, 0x00, 0x01]
        let udpFrame = Self.makeIPv4UDPFrame(
            srcIP: Self.guestIP,
            dstIP: Self.gatewayIP,
            srcPort: 53_000,
            dstPort: 53,
            payload: dnsPayload
        )
        try Self.writeUntaggedFrame(clientFD, udpFrame)

        let serverReady = await withCheckedContinuation { continuation in
            Thread.detachNewThread {
                var pfd = pollfd(fd: serverFD, events: Int16(POLLIN), revents: 0)
                continuation.resume(returning: Darwin.poll(&pfd, 1, 5000) > 0)
            }
        }
        #expect(serverReady)
        var recvBuf = [UInt8](repeating: 0, count: 512)
        var peerAddr = sockaddr_in()
        var peerLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        let received = recvBuf.withUnsafeMutableBytes { raw in
            withUnsafeMutablePointer(to: &peerAddr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.recvfrom(serverFD, raw.baseAddress, raw.count, 0, $0, &peerLen)
                }
            }
        }
        #expect(Array(recvBuf.prefix(received)) == dnsPayload)

        let dnsResponse: [UInt8] = [0x12, 0x34, 0x81, 0x80, 0x00, 0x01]
        _ = dnsResponse.withUnsafeBytes { raw in
            withUnsafePointer(to: &peerAddr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.sendto(serverFD, raw.baseAddress, raw.count, 0, $0, peerLen)
                }
            }
        }

        let replyFrame = try await Self.readTaggedFrame(clientFD)
        #expect(replyFrame[14 + 9] == 17)
        #expect(Array(replyFrame[(14 + 12)..<(14 + 16)]) == Self.gatewayIP)
        #expect(Array(replyFrame[(14 + 16)..<(14 + 20)]) == Self.guestIP)
        let replySrcPort = UInt16(replyFrame[34]) << 8 | UInt16(replyFrame[35])
        let replyDstPort = UInt16(replyFrame[36]) << 8 | UInt16(replyFrame[37])
        #expect(replySrcPort == 53)
        #expect(replyDstPort == 53_000)
        #expect(Array(replyFrame[42...]) == dnsResponse)

        await uplink.stop()
    }

    @Test func tcpGatewayProxyAndInternalNetworkIsolation() async throws {
        // Start a local TCP listener on 127.0.0.1:0 that answers HTTP with "host-ok".
        let listenFD = socket(AF_INET, SOCK_STREAM, 0)
        #expect(listenFD >= 0)
        defer { Darwin.close(listenFD) }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        #expect(withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(listenFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        } == 0)
        #expect(Darwin.listen(listenFD, 4) == 0)
        var boundLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.getsockname(listenFD, $0, &boundLen)
            }
        }
        let hostPort = UInt16(bigEndian: addr.sin_port)

        let serverFinished: Task<Void, Never> = Task {
            await withCheckedContinuation { continuation in
                Thread.detachNewThread {
                    defer { continuation.resume() }
                    var pfd = pollfd(fd: listenFD, events: Int16(POLLIN), revents: 0)
                    guard Darwin.poll(&pfd, 1, 5000) > 0 else { return }
                    let conn = Darwin.accept(listenFD, nil, nil)
                    guard conn >= 0 else { return }
                    defer { Darwin.close(conn) }
                    var connPfd = pollfd(fd: conn, events: Int16(POLLIN), revents: 0)
                    guard Darwin.poll(&connPfd, 1, 5000) > 0 else { return }
                    var buf = [UInt8](repeating: 0, count: 256)
                    _ = buf.withUnsafeMutableBytes { Darwin.recv(conn, $0.baseAddress, $0.count, 0) }
                    let response = Array("host-ok".utf8)
                    _ = response.withUnsafeBytes { Darwin.send(conn, $0.baseAddress, $0.count, 0) }
                }
            }
        }

        // Use internalNetwork: true to prove gateway TCP works while external IP gets RST!
        let request = PrivilegedVMNetRequest(
            namespace: "compat",
            id: "net-tcp-internal",
            vlan: Self.vlan,
            subnet: "10.192.0.0/24",
            gateway: "10.192.0.1",
            ipv6Subnet: "",
            internalNetwork: true,
            dhcpEnabled: false,
            ports: []
        )
        let (uplink, clientFD) = try UserspaceNetworkUplink.start(request: request)
        defer {
            Darwin.close(clientFD)
            Task { await uplink.stop() }
        }

        // 1. Outbound TCP SYN to external IP 1.1.1.1:443 on internalNetwork must get immediate RST!
        let extSYN = Self.makeIPv4TCPFrame(
            srcIP: Self.guestIP,
            dstIP: [1, 1, 1, 1],
            srcPort: 40_001,
            dstPort: 443,
            seq: 1000,
            ack: 0,
            flags: 0x02,
            payload: []
        )
        try Self.writeUntaggedFrame(clientFD, extSYN)
        let rstFrame = try await Self.readTaggedFrame(clientFD)
        #expect(rstFrame[14 + 9] == 6)
        let rstFlags = rstFrame[14 + 20 + 13]
        #expect((rstFlags & 0x04) != 0) // RST set!

        // 2. TCP connection to gateway:hostPort must succeed and return "host-ok".
        let gwSYN = Self.makeIPv4TCPFrame(
            srcIP: Self.guestIP,
            dstIP: Self.gatewayIP,
            srcPort: 40_002,
            dstPort: hostPort,
            seq: 2000,
            ack: 0,
            flags: 0x02,
            payload: []
        )
        try Self.writeUntaggedFrame(clientFD, gwSYN)

        let synAckFrame = try await Self.readTaggedFrame(clientFD)
        #expect(synAckFrame[14 + 9] == 6)
        let synAckFlags = synAckFrame[14 + 20 + 13]
        #expect(synAckFlags == 0x12) // SYN | ACK
        let serverISN = Self.readUInt32(synAckFrame, at: 14 + 20 + 4)
        let ackNum = Self.readUInt32(synAckFrame, at: 14 + 20 + 8)
        #expect(ackNum == 2001)

        // Complete handshake + send GET request
        let httpReq = Array("GET / HTTP/1.0\r\n\r\n".utf8)
        let pshAck = Self.makeIPv4TCPFrame(
            srcIP: Self.guestIP,
            dstIP: Self.gatewayIP,
            srcPort: 40_002,
            dstPort: hostPort,
            seq: 2001,
            ack: serverISN &+ 1,
            flags: 0x18, // PSH | ACK
            payload: httpReq
        )
        try Self.writeUntaggedFrame(clientFD, pshAck)

        var receivedPayload: [UInt8] = []
        for _ in 0..<4 {
            let seg = try await Self.readTaggedFrame(clientFD)
            guard seg[14 + 9] == 6 else { continue }
            let ipHdrLen = Int(seg[14] & 0x0f) * 4
            let tcpOffset = 14 + ipHdrLen
            let tcpHdrLen = Int(seg[tcpOffset + 12] >> 4) * 4
            let dataStart = tcpOffset + tcpHdrLen
            if seg.count > dataStart {
                receivedPayload.append(contentsOf: seg[dataStart...])
                break
            }
        }
        #expect(String(bytes: receivedPayload, encoding: .utf8) == "host-ok")

        await serverFinished.value
        await uplink.stop()
    }

    private static func makeIPv4UDPFrame(
        srcIP: [UInt8],
        dstIP: [UInt8],
        srcPort: UInt16,
        dstPort: UInt16,
        payload: [UInt8]
    ) -> [UInt8] {
        let udpLen = UInt16(8 + payload.count)
        var udp: [UInt8] = [
            UInt8(srcPort >> 8), UInt8(srcPort & 0xff),
            UInt8(dstPort >> 8), UInt8(dstPort & 0xff),
            UInt8(udpLen >> 8), UInt8(udpLen & 0xff),
            0, 0,
        ]
        udp.append(contentsOf: payload)
        return makeIPv4Frame(proto: 17, srcIP: srcIP, dstIP: dstIP, payload: udp)
    }

    private static func makeIPv4TCPFrame(
        srcIP: [UInt8],
        dstIP: [UInt8],
        srcPort: UInt16,
        dstPort: UInt16,
        seq: UInt32,
        ack: UInt32,
        flags: UInt8,
        payload: [UInt8]
    ) -> [UInt8] {
        var tcp: [UInt8] = [
            UInt8(srcPort >> 8), UInt8(srcPort & 0xff),
            UInt8(dstPort >> 8), UInt8(dstPort & 0xff),
            UInt8((seq >> 24) & 0xff), UInt8((seq >> 16) & 0xff), UInt8((seq >> 8) & 0xff), UInt8(seq & 0xff),
            UInt8((ack >> 24) & 0xff), UInt8((ack >> 16) & 0xff), UInt8((ack >> 8) & 0xff), UInt8(ack & 0xff),
            0x50, flags,
            0xff, 0xff,
            0, 0, 0, 0,
        ]
        tcp.append(contentsOf: payload)
        return makeIPv4Frame(proto: 6, srcIP: srcIP, dstIP: dstIP, payload: tcp)
    }

    private static func makeIPv4Frame(
        proto: UInt8,
        srcIP: [UInt8],
        dstIP: [UInt8],
        payload: [UInt8]
    ) -> [UInt8] {
        let totalLen = UInt16(20 + payload.count)
        var frame: [UInt8] = gatewayMAC + guestMAC + [0x08, 0x00]
        frame += [
            0x45, 0x00,
            UInt8(totalLen >> 8), UInt8(totalLen & 0xff),
            0x00, 0x00, 0x40, 0x00,
            64, proto, 0x00, 0x00,
        ]
        frame += srcIP + dstIP + payload
        return frame
    }

    private static func readUInt32(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        (UInt32(bytes[offset]) << 24)
            | (UInt32(bytes[offset + 1]) << 16)
            | (UInt32(bytes[offset + 2]) << 8)
            | UInt32(bytes[offset + 3])
    }
}

import CEngineHelperSupport
import Darwin
import Foundation

public final class UserspaceNetworkUplink: @unchecked Sendable {
    public struct DNSForwardTarget: Sendable, Equatable {
        public let ipv4Address: [UInt8]
        public let port: UInt16

        public init(ipv4Address: [UInt8], port: UInt16 = 53) {
            self.ipv4Address = ipv4Address
            self.port = port
        }
    }

    private struct FlowKey: Hashable {
        let isIPv6: Bool
        let guestIP: [UInt8]
        let guestPort: UInt16
        let dstIP: [UInt8]
        let dstPort: UInt16
    }

    private static let tcpFIN: UInt8 = 0x01
    private static let tcpSYN: UInt8 = 0x02
    private static let tcpRST: UInt8 = 0x04
    private static let tcpPSH: UInt8 = 0x08
    private static let tcpACK: UInt8 = 0x10
    private static let maxSegmentPayload = 1400
    private static let maxInFlightBytes: Int32 = 32_768
    private static let resumeInFlightBytes: Int32 = 16_384

    private let queue: DispatchQueue
    private let vlan: UInt16
    private let internalNetwork: Bool
    private let gatewayMAC: [UInt8]
    private let ipv4Gateway: [UInt8]?
    private let ipv6Gateway: [UInt8]?
    private let ipv6LinkLocalGateway: [UInt8]
    private let ipv6AltLinkLocalGateway: [UInt8]
    private let dnsOverride: DNSForwardTarget?
    private let packetDescriptor: CInt
    private let lock = NSLock()
    private var stopTask: Task<Void, Never>?
    private var isStopped = false
    private var packetReadSource: DispatchSourceRead?
    private var maintenanceTimer: DispatchSourceTimer?

    private var arpTable: [[UInt8]: [UInt8]] = [:]
    private var ndpTable: [[UInt8]: [UInt8]] = [:]
    private var udpSessions: [FlowKey: UDPSession] = [:]
    private var tcpSessions: [FlowKey: TCPSession] = [:]

    public static func start(
        request: PrivilegedVMNetRequest,
        dnsOverride: DNSForwardTarget? = nil
    ) throws -> (UserspaceNetworkUplink, CInt) {
        let ipv4Gateway: [UInt8]?
        if request.subnet.isEmpty {
            ipv4Gateway = nil
        } else {
            let addr = try VMNetIPv4Configuration.gateway(request.gateway, in: request.subnet)
            ipv4Gateway = withUnsafeBytes(of: addr.s_addr) { Array($0) }
        }

        let ipv6Gateway: [UInt8]?
        if request.ipv6Subnet.isEmpty {
            ipv6Gateway = nil
        } else {
            ipv6Gateway = try Self.firstIPv6Address(in: request.ipv6Subnet)
        }

        var sockets: [CInt] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &sockets) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        do {
            for descriptor in sockets {
                var bufferSize: CInt = 4 * 1024 * 1024
                guard setsockopt(
                    descriptor, SOL_SOCKET, SO_SNDBUF,
                    &bufferSize, socklen_t(MemoryLayout.size(ofValue: bufferSize))
                ) == 0,
                setsockopt(
                    descriptor, SOL_SOCKET, SO_RCVBUF,
                    &bufferSize, socklen_t(MemoryLayout.size(ofValue: bufferSize))
                ) == 0 else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
            }
        } catch {
            sockets.forEach { close($0) }
            throw error
        }

        var one: CInt = 1
        _ = setsockopt(sockets[0], SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout.size(ofValue: one)))
        let flags = fcntl(sockets[0], F_GETFL)
        if flags >= 0 {
            _ = fcntl(sockets[0], F_SETFL, flags | O_NONBLOCK)
        }
        _ = fcntl(sockets[0], F_SETFD, FD_CLOEXEC)

        let queue = DispatchQueue(label: "dev.cengine.userspace-net.\(request.id)")
        let uplink = UserspaceNetworkUplink(
            queue: queue,
            vlan: request.vlan,
            internalNetwork: request.internalNetwork,
            ipv4Gateway: ipv4Gateway,
            ipv6Gateway: ipv6Gateway,
            dnsOverride: dnsOverride,
            packetDescriptor: sockets[0]
        )
        return (uplink, sockets[1])
    }

    private init(
        queue: DispatchQueue,
        vlan: UInt16,
        internalNetwork: Bool,
        ipv4Gateway: [UInt8]?,
        ipv6Gateway: [UInt8]?,
        dnsOverride: DNSForwardTarget?,
        packetDescriptor: CInt
    ) {
        self.queue = queue
        self.vlan = vlan
        self.internalNetwork = internalNetwork
        self.gatewayMAC = [
            0x02, 0xce, 0x4e, 0x47,
            UInt8((vlan >> 8) & 0xff),
            UInt8(vlan & 0xff),
        ]
        self.ipv4Gateway = ipv4Gateway
        self.ipv6Gateway = ipv6Gateway
        self.ipv6LinkLocalGateway = [
            0xfe, 0x80, 0, 0, 0, 0, 0, 0,
            0x00, 0xce, 0x4e, 0xff, 0xfe, 0x47,
            UInt8((vlan >> 8) & 0xff),
            UInt8(vlan & 0xff),
        ]
        self.ipv6AltLinkLocalGateway = [
            0xfe, 0x80, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1,
        ]
        self.dnsOverride = dnsOverride
        self.packetDescriptor = packetDescriptor

        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .milliseconds(200), repeating: .milliseconds(200))
        timer.setEventHandler { [weak self] in
            self?.performMaintenance()
        }
        self.maintenanceTimer = timer
        timer.resume()

        let readSource = DispatchSource.makeReadSource(fileDescriptor: packetDescriptor, queue: queue)
        readSource.setEventHandler { [weak self] in
            self?.readFromPacketSocket()
        }
        readSource.setCancelHandler {
            Darwin.close(packetDescriptor)
        }
        self.packetReadSource = readSource
        readSource.resume()
    }

    public func stop() async {
        let task = lock.withLock { () -> Task<Void, Never> in
            if let stopTask { return stopTask }
            let task = Task { [self] in await performStop() }
            stopTask = task
            return task
        }
        await task.value
    }

    private func performStop() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            queue.async { [self] in
                isStopped = true
                maintenanceTimer?.cancel()
                maintenanceTimer = nil
                packetReadSource?.cancel()
                packetReadSource = nil
                for session in udpSessions.values {
                    session.close()
                }
                udpSessions.removeAll()
                for session in tcpSessions.values {
                    session.close()
                }
                tcpSessions.removeAll()
                continuation.resume()
            }
        }
    }

    private func readFromPacketSocket() {
        guard !isStopped else { return }
        var buffer = [UInt8](repeating: 0, count: 65_535)
        while !isStopped {
            let count = buffer.withUnsafeMutableBytes { raw in
                Darwin.recv(packetDescriptor, raw.baseAddress, raw.count, 0)
            }
            if count > 0 {
                handleTaggedFrame(Data(buffer.prefix(count)))
            } else {
                break
            }
        }
    }

    private func performMaintenance() {
        guard !isStopped else { return }
        let now = DispatchTime.now().uptimeNanoseconds
        for (key, session) in udpSessions where session.isExpired(now: now) {
            session.close()
            udpSessions.removeValue(forKey: key)
        }
        for (key, session) in tcpSessions {
            session.onTimer(now: now)
            if session.isClosed {
                tcpSessions.removeValue(forKey: key)
            }
        }
    }

    private func sendUntaggedFrame(_ frame: [UInt8]) {
        guard !isStopped else { return }
        let tagged = Self.tag(Data(frame), vlan: vlan)
        _ = tagged.withUnsafeBytes { raw in
            Darwin.send(packetDescriptor, raw.baseAddress, raw.count, 0)
        }
    }

    private func handleTaggedFrame(_ data: Data) {
        guard !isStopped, let untagged = Self.untag(data, vlan: vlan) else { return }
        let frame = [UInt8](untagged)
        guard frame.count >= 14 else { return }
        let dstMAC = Array(frame[0..<6])
        let srcMAC = Array(frame[6..<12])
        let etherType = Self.readUInt16(frame, at: 12)

        switch etherType {
        case 0x0806:
            handleARP(frame, srcMAC: srcMAC)
        case 0x0800:
            handleIPv4(frame, dstMAC: dstMAC, srcMAC: srcMAC)
        case 0x86dd:
            handleIPv6(frame, dstMAC: dstMAC, srcMAC: srcMAC)
        default:
            break
        }
    }

    // MARK: - ARP

    private func handleARP(_ frame: [UInt8], srcMAC: [UInt8]) {
        guard let ipv4Gateway, frame.count >= 14 + 28 else { return }
        let hwType = Self.readUInt16(frame, at: 14)
        let protoType = Self.readUInt16(frame, at: 16)
        let hwSize = frame[18]
        let protoSize = frame[19]
        let operation = Self.readUInt16(frame, at: 20)
        guard hwType == 1, protoType == 0x0800, hwSize == 6, protoSize == 4 else { return }

        let senderMAC = Array(frame[22..<28])
        let senderIP = Array(frame[28..<32])
        let targetIP = Array(frame[38..<42])
        if senderIP != [0, 0, 0, 0] {
            arpTable[senderIP] = senderMAC
        }
        guard operation == 1, targetIP == ipv4Gateway else { return }

        var reply: [UInt8] = []
        reply.reserveCapacity(14 + 28)
        reply.append(contentsOf: senderMAC)
        reply.append(contentsOf: gatewayMAC)
        Self.appendUInt16(0x0806, to: &reply)
        Self.appendUInt16(1, to: &reply)
        Self.appendUInt16(0x0800, to: &reply)
        reply.append(6)
        reply.append(4)
        Self.appendUInt16(2, to: &reply)
        reply.append(contentsOf: gatewayMAC)
        reply.append(contentsOf: ipv4Gateway)
        reply.append(contentsOf: senderMAC)
        reply.append(contentsOf: senderIP)
        sendUntaggedFrame(reply)
    }

    // MARK: - IPv4

    private func handleIPv4(_ frame: [UInt8], dstMAC: [UInt8], srcMAC: [UInt8]) {
        guard dstMAC == gatewayMAC, frame.count >= 14 + 20 else { return }
        let ipOffset = 14
        let version = frame[ipOffset] >> 4
        let ihl = Int(frame[ipOffset] & 0x0f) * 4
        guard version == 4, ihl >= 20 else { return }
        let totalLength = Int(Self.readUInt16(frame, at: ipOffset + 2))
        guard totalLength >= ihl, frame.count >= ipOffset + totalLength else { return }

        let proto = frame[ipOffset + 9]
        let srcIP = Array(frame[(ipOffset + 12)..<(ipOffset + 16)])
        let dstIP = Array(frame[(ipOffset + 16)..<(ipOffset + 20)])
        arpTable[srcIP] = srcMAC

        let isToGateway = (ipv4Gateway != nil && dstIP == ipv4Gateway)
        let payload = Array(frame[(ipOffset + ihl)..<(ipOffset + totalLength)])

        if internalNetwork && !isToGateway {
            if proto == 6 {
                sendRefusedTCPRST(
                    isIPv6: false,
                    srcIP: srcIP,
                    dstIP: dstIP,
                    dstMAC: srcMAC,
                    tcpSegment: payload
                )
            }
            return
        }

        switch proto {
        case 1:
            handleICMPv4(payload, srcIP: srcIP, dstIP: dstIP, dstMAC: srcMAC)
        case 17:
            handleUDP(
                isIPv6: false,
                payload: payload,
                srcIP: srcIP,
                dstIP: dstIP,
                srcMAC: srcMAC,
                isToGateway: isToGateway
            )
        case 6:
            handleTCP(
                isIPv6: false,
                segment: payload,
                srcIP: srcIP,
                dstIP: dstIP,
                srcMAC: srcMAC,
                isToGateway: isToGateway
            )
        default:
            break
        }
    }

    private func handleICMPv4(
        _ payload: [UInt8],
        srcIP: [UInt8],
        dstIP: [UInt8],
        dstMAC: [UInt8]
    ) {
        guard payload.count >= 8, payload[0] == 8, payload[1] == 0 else { return }
        var icmp = payload
        icmp[0] = 0
        icmp[1] = 0
        Self.writeUInt16(0, to: &icmp, at: 2)
        let csum = Self.checksum(icmp)
        Self.writeUInt16(csum, to: &icmp, at: 2)
        sendIPv4Packet(
            proto: 1,
            srcIP: dstIP,
            dstIP: srcIP,
            dstMAC: dstMAC,
            payload: icmp
        )
    }

    // MARK: - IPv6

    private func handleIPv6(_ frame: [UInt8], dstMAC: [UInt8], srcMAC: [UInt8]) {
        guard frame.count >= 14 + 40 else { return }
        let ipOffset = 14
        let version = frame[ipOffset] >> 4
        guard version == 6 else { return }
        let payloadLength = Int(Self.readUInt16(frame, at: ipOffset + 4))
        let nextHeader = frame[ipOffset + 6]
        guard frame.count >= ipOffset + 40 + payloadLength else { return }

        let srcIP6 = Array(frame[(ipOffset + 8)..<(ipOffset + 24)])
        let dstIP6 = Array(frame[(ipOffset + 24)..<(ipOffset + 40)])
        let unspecified = [UInt8](repeating: 0, count: 16)
        if srcIP6 != unspecified {
            ndpTable[srcIP6] = srcMAC
        }
        let payload = Array(frame[(ipOffset + 40)..<(ipOffset + 40 + payloadLength)])

        if nextHeader == 58 {
            handleICMPv6(
                payload,
                srcIP6: srcIP6,
                dstIP6: dstIP6,
                dstMAC: dstMAC,
                srcMAC: srcMAC
            )
            return
        }

        guard dstMAC == gatewayMAC else { return }
        let isToGateway = isIPv6GatewayAddress(dstIP6)
        if internalNetwork && !isToGateway {
            if nextHeader == 6 {
                sendRefusedTCPRST(
                    isIPv6: true,
                    srcIP: srcIP6,
                    dstIP: dstIP6,
                    dstMAC: srcMAC,
                    tcpSegment: payload
                )
            }
            return
        }

        switch nextHeader {
        case 17:
            handleUDP(
                isIPv6: true,
                payload: payload,
                srcIP: srcIP6,
                dstIP: dstIP6,
                srcMAC: srcMAC,
                isToGateway: isToGateway
            )
        case 6:
            handleTCP(
                isIPv6: true,
                segment: payload,
                srcIP: srcIP6,
                dstIP: dstIP6,
                srcMAC: srcMAC,
                isToGateway: isToGateway
            )
        default:
            break
        }
    }

    private func isIPv6GatewayAddress(_ address: [UInt8]) -> Bool {
        if let ipv6Gateway, address == ipv6Gateway { return true }
        return address == ipv6LinkLocalGateway || address == ipv6AltLinkLocalGateway
    }

    private func handleICMPv6(
        _ payload: [UInt8],
        srcIP6: [UInt8],
        dstIP6: [UInt8],
        dstMAC: [UInt8],
        srcMAC: [UInt8]
    ) {
        guard payload.count >= 4 else { return }
        let icmpType = payload[0]
        switch icmpType {
        case 135: // Neighbor Solicitation
            guard payload.count >= 24 else { return }
            let targetIP6 = Array(payload[8..<24])
            guard isIPv6GatewayAddress(targetIP6) else { return }
            let unspecified = [UInt8](repeating: 0, count: 16)
            let isUnspecified = (srcIP6 == unspecified)
            let replyDstIP6: [UInt8] = isUnspecified
                ? [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
                : srcIP6
            var advertisement: [UInt8] = [
                136, 0, 0, 0,
                isUnspecified ? 0xa0 : 0xe0, 0, 0, 0,
            ]
            advertisement.append(contentsOf: targetIP6)
            advertisement.append(contentsOf: [2, 1])
            advertisement.append(contentsOf: gatewayMAC)
            let csum = Self.transportChecksumIPv6(
                srcIP6: targetIP6,
                dstIP6: replyDstIP6,
                nextHeader: 58,
                payload: advertisement
            )
            Self.writeUInt16(csum, to: &advertisement, at: 2)
            sendIPv6Packet(
                nextHeader: 58,
                hopLimit: 255,
                srcIP6: targetIP6,
                dstIP6: replyDstIP6,
                dstMAC: srcMAC,
                payload: advertisement
            )
        case 128: // Echo Request
            guard dstMAC == gatewayMAC, payload.count >= 8 else { return }
            let isToGateway = isIPv6GatewayAddress(dstIP6)
            guard !internalNetwork || isToGateway else { return }
            var reply = payload
            reply[0] = 129
            reply[1] = 0
            Self.writeUInt16(0, to: &reply, at: 2)
            let csum = Self.transportChecksumIPv6(
                srcIP6: dstIP6,
                dstIP6: srcIP6,
                nextHeader: 58,
                payload: reply
            )
            Self.writeUInt16(csum, to: &reply, at: 2)
            sendIPv6Packet(
                nextHeader: 58,
                hopLimit: 64,
                srcIP6: dstIP6,
                dstIP6: srcIP6,
                dstMAC: srcMAC,
                payload: reply
            )
        default:
            break
        }
    }

    // MARK: - UDP NAT & DNS Proxy

    private func resolveHostTarget(
        isIPv6: Bool,
        dstIP: [UInt8],
        dstPort: UInt16,
        isToGateway: Bool
    ) -> (isIPv6: Bool, ip: [UInt8], port: UInt16) {
        if isToGateway {
            if dstPort == 53 && !internalNetwork {
                if let dnsOverride {
                    return (false, dnsOverride.ipv4Address, dnsOverride.port)
                }
                let dnsServer = Self.systemIPv4DNSServers().first ?? [1, 1, 1, 1]
                return (false, dnsServer, 53)
            }
            if isIPv6 {
                return (true, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], dstPort)
            } else {
                return (false, [127, 0, 0, 1], dstPort)
            }
        }
        return (isIPv6, dstIP, dstPort)
    }

    private func handleUDP(
        isIPv6: Bool,
        payload: [UInt8],
        srcIP: [UInt8],
        dstIP: [UInt8],
        srcMAC: [UInt8],
        isToGateway: Bool
    ) {
        guard payload.count >= 8 else { return }
        let srcPort = Self.readUInt16(payload, at: 0)
        let dstPort = Self.readUInt16(payload, at: 2)
        let udpLength = Int(Self.readUInt16(payload, at: 4))
        guard udpLength >= 8, payload.count >= udpLength else { return }
        let datagram = Data(payload[8..<udpLength])

        let key = FlowKey(
            isIPv6: isIPv6,
            guestIP: srcIP,
            guestPort: srcPort,
            dstIP: dstIP,
            dstPort: dstPort
        )
        let target = resolveHostTarget(
            isIPv6: isIPv6,
            dstIP: dstIP,
            dstPort: dstPort,
            isToGateway: isToGateway
        )

        let session: UDPSession
        if let existing = udpSessions[key] {
            session = existing
        } else {
            if udpSessions.count >= 256, let oldestKey = udpSessions.keys.first {
                udpSessions.removeValue(forKey: oldestKey)?.close()
            }
            guard let created = UDPSession(
                key: key,
                guestMAC: srcMAC,
                targetIsIPv6: target.isIPv6,
                targetIP: target.ip,
                targetPort: target.port,
                queue: queue,
                onReceive: { [weak self] responseData, flowKey, guestMAC in
                    self?.sendUDPToGuest(
                        payload: [UInt8](responseData),
                        key: flowKey,
                        guestMAC: guestMAC
                    )
                }
            ) else { return }
            udpSessions[key] = created
            session = created
        }
        session.send(datagram, guestMAC: srcMAC)
    }

    private func sendUDPToGuest(payload: [UInt8], key: FlowKey, guestMAC: [UInt8]) {
        let udpLength = 8 + payload.count
        guard udpLength <= Int(UInt16.max) else { return }
        var udp: [UInt8] = []
        udp.reserveCapacity(udpLength)
        Self.appendUInt16(key.dstPort, to: &udp)
        Self.appendUInt16(key.guestPort, to: &udp)
        Self.appendUInt16(UInt16(udpLength), to: &udp)
        Self.appendUInt16(0, to: &udp)
        udp.append(contentsOf: payload)

        if key.isIPv6 {
            let csum = Self.transportChecksumIPv6(
                srcIP6: key.dstIP,
                dstIP6: key.guestIP,
                nextHeader: 17,
                payload: udp
            )
            Self.writeUInt16(csum == 0 ? UInt16.max : csum, to: &udp, at: 6)
            let mac = ndpTable[key.guestIP] ?? guestMAC
            sendIPv6Packet(
                nextHeader: 17,
                hopLimit: 64,
                srcIP6: key.dstIP,
                dstIP6: key.guestIP,
                dstMAC: mac,
                payload: udp
            )
        } else {
            let csum = Self.transportChecksumIPv4(
                srcIP: key.dstIP,
                dstIP: key.guestIP,
                proto: 17,
                payload: udp
            )
            Self.writeUInt16(csum == 0 ? UInt16.max : csum, to: &udp, at: 6)
            let mac = arpTable[key.guestIP] ?? guestMAC
            sendIPv4Packet(
                proto: 17,
                srcIP: key.dstIP,
                dstIP: key.guestIP,
                dstMAC: mac,
                payload: udp
            )
        }
    }

    // MARK: - Userspace TCP Proxy

    private func handleTCP(
        isIPv6: Bool,
        segment: [UInt8],
        srcIP: [UInt8],
        dstIP: [UInt8],
        srcMAC: [UInt8],
        isToGateway: Bool
    ) {
        guard segment.count >= 20 else { return }
        let srcPort = Self.readUInt16(segment, at: 0)
        let dstPort = Self.readUInt16(segment, at: 2)
        let seq = Self.readUInt32(segment, at: 4)
        let ack = Self.readUInt32(segment, at: 8)
        let dataOffset = Int(segment[12] >> 4) * 4
        let flags = segment[13]
        guard dataOffset >= 20, segment.count >= dataOffset else { return }
        let payload = Data(segment[dataOffset...])

        let key = FlowKey(
            isIPv6: isIPv6,
            guestIP: srcIP,
            guestPort: srcPort,
            dstIP: dstIP,
            dstPort: dstPort
        )

        if flags & Self.tcpRST != 0 {
            if let existing = tcpSessions.removeValue(forKey: key) {
                existing.close()
            }
            return
        }

        if (flags & Self.tcpSYN != 0) && (flags & Self.tcpACK == 0) {
            if let existing = tcpSessions[key] {
                if existing.handleDuplicateSYN(seq: seq) {
                    return
                }
                existing.close()
                tcpSessions.removeValue(forKey: key)
            }
            if tcpSessions.count >= 256, let oldestKey = tcpSessions.keys.first {
                tcpSessions.removeValue(forKey: oldestKey)?.close()
            }
            let target = resolveHostTarget(
                isIPv6: isIPv6,
                dstIP: dstIP,
                dstPort: dstPort,
                isToGateway: isToGateway
            )
            let session = TCPSession(
                key: key,
                guestMAC: srcMAC,
                initialGuestSeq: seq,
                targetIsIPv6: target.isIPv6,
                targetIP: target.ip,
                targetPort: target.port,
                queue: queue,
                sendSegment: { [weak self] flowKey, guestMAC, segSeq, segAck, segFlags, options, segPayload in
                    self?.sendTCPSegmentToGuest(
                        key: flowKey,
                        guestMAC: guestMAC,
                        seq: segSeq,
                        ack: segAck,
                        flags: segFlags,
                        options: options,
                        payload: segPayload
                    )
                }
            )
            tcpSessions[key] = session
            session.startConnect()
            if session.isClosed {
                tcpSessions.removeValue(forKey: key)
            }
            return
        }

        guard let session = tcpSessions[key] else {
            sendRefusedTCPRST(
                isIPv6: isIPv6,
                srcIP: srcIP,
                dstIP: dstIP,
                dstMAC: srcMAC,
                tcpSegment: segment
            )
            return
        }
        session.handleGuestSegment(
            seq: seq,
            ack: ack,
            flags: flags,
            payload: payload,
            guestMAC: srcMAC
        )
        if session.isClosed {
            tcpSessions.removeValue(forKey: key)
        }
    }

    private func sendRefusedTCPRST(
        isIPv6: Bool,
        srcIP: [UInt8],
        dstIP: [UInt8],
        dstMAC: [UInt8],
        tcpSegment: [UInt8]
    ) {
        guard tcpSegment.count >= 20 else { return }
        let flags = tcpSegment[13]
        guard flags & Self.tcpRST == 0 else { return }
        let srcPort = Self.readUInt16(tcpSegment, at: 0)
        let dstPort = Self.readUInt16(tcpSegment, at: 2)
        let segSeq = Self.readUInt32(tcpSegment, at: 4)
        let segAck = Self.readUInt32(tcpSegment, at: 8)
        let dataOffset = Int(tcpSegment[12] >> 4) * 4
        let payloadCount = max(0, tcpSegment.count - max(20, dataOffset))

        let rstSeq: UInt32
        let rstAck: UInt32
        let rstFlags: UInt8
        if flags & Self.tcpACK != 0 {
            rstSeq = segAck
            rstAck = 0
            rstFlags = Self.tcpRST
        } else {
            rstSeq = 0
            var advance = UInt32(payloadCount)
            if flags & Self.tcpSYN != 0 { advance &+= 1 }
            if flags & Self.tcpFIN != 0 { advance &+= 1 }
            rstAck = segSeq &+ advance
            rstFlags = Self.tcpRST | Self.tcpACK
        }

        let key = FlowKey(
            isIPv6: isIPv6,
            guestIP: srcIP,
            guestPort: srcPort,
            dstIP: dstIP,
            dstPort: dstPort
        )
        sendTCPSegmentToGuest(
            key: key,
            guestMAC: dstMAC,
            seq: rstSeq,
            ack: rstAck,
            flags: rstFlags,
            options: [],
            payload: []
        )
    }

    private func sendTCPSegmentToGuest(
        key: FlowKey,
        guestMAC: [UInt8],
        seq: UInt32,
        ack: UInt32,
        flags: UInt8,
        options: [UInt8],
        payload: [UInt8]
    ) {
        let paddedOptionsCount = (options.count + 3) & ~3
        let headerLength = 20 + paddedOptionsCount
        let totalTCPLength = headerLength + payload.count
        guard headerLength <= 60, totalTCPLength <= Int(UInt16.max) else { return }

        var tcp: [UInt8] = []
        tcp.reserveCapacity(totalTCPLength)
        Self.appendUInt16(key.dstPort, to: &tcp)
        Self.appendUInt16(key.guestPort, to: &tcp)
        Self.appendUInt32(seq, to: &tcp)
        Self.appendUInt32(ack, to: &tcp)
        tcp.append(UInt8(headerLength / 4) << 4)
        tcp.append(flags)
        Self.appendUInt16(65_535, to: &tcp)
        Self.appendUInt16(0, to: &tcp) // checksum placeholder
        Self.appendUInt16(0, to: &tcp) // urgent pointer
        if !options.isEmpty {
            tcp.append(contentsOf: options)
            while (tcp.count % 4) != 0 {
                tcp.append(0)
            }
        }
        tcp.append(contentsOf: payload)

        if key.isIPv6 {
            let csum = Self.transportChecksumIPv6(
                srcIP6: key.dstIP,
                dstIP6: key.guestIP,
                nextHeader: 6,
                payload: tcp
            )
            Self.writeUInt16(csum, to: &tcp, at: 16)
            let mac = ndpTable[key.guestIP] ?? guestMAC
            sendIPv6Packet(
                nextHeader: 6,
                hopLimit: 64,
                srcIP6: key.dstIP,
                dstIP6: key.guestIP,
                dstMAC: mac,
                payload: tcp
            )
        } else {
            let csum = Self.transportChecksumIPv4(
                srcIP: key.dstIP,
                dstIP: key.guestIP,
                proto: 6,
                payload: tcp
            )
            Self.writeUInt16(csum, to: &tcp, at: 16)
            let mac = arpTable[key.guestIP] ?? guestMAC
            sendIPv4Packet(
                proto: 6,
                srcIP: key.dstIP,
                dstIP: key.guestIP,
                dstMAC: mac,
                payload: tcp
            )
        }
    }

    // MARK: - Packet Builders & Helpers

    private func sendIPv4Packet(
        proto: UInt8,
        srcIP: [UInt8],
        dstIP: [UInt8],
        dstMAC: [UInt8],
        payload: [UInt8]
    ) {
        let totalLength = 20 + payload.count
        guard totalLength <= Int(UInt16.max) else { return }
        var frame: [UInt8] = []
        frame.reserveCapacity(14 + totalLength)
        frame.append(contentsOf: dstMAC)
        frame.append(contentsOf: gatewayMAC)
        Self.appendUInt16(0x0800, to: &frame)

        let ipOffset = frame.count
        frame.append(0x45)
        frame.append(0x00)
        Self.appendUInt16(UInt16(totalLength), to: &frame)
        Self.appendUInt16(0, to: &frame)
        Self.appendUInt16(0x4000, to: &frame) // Don't Fragment
        frame.append(64)
        frame.append(proto)
        Self.appendUInt16(0, to: &frame)
        frame.append(contentsOf: srcIP)
        frame.append(contentsOf: dstIP)

        let ipChecksum = Self.checksum(Array(frame[ipOffset..<(ipOffset + 20)]))
        Self.writeUInt16(ipChecksum, to: &frame, at: ipOffset + 10)
        frame.append(contentsOf: payload)
        sendUntaggedFrame(frame)
    }

    private func sendIPv6Packet(
        nextHeader: UInt8,
        hopLimit: UInt8,
        srcIP6: [UInt8],
        dstIP6: [UInt8],
        dstMAC: [UInt8],
        payload: [UInt8]
    ) {
        guard payload.count <= Int(UInt16.max) else { return }
        var frame: [UInt8] = []
        frame.reserveCapacity(14 + 40 + payload.count)
        frame.append(contentsOf: dstMAC)
        frame.append(contentsOf: gatewayMAC)
        Self.appendUInt16(0x86dd, to: &frame)
        frame.append(contentsOf: [0x60, 0x00, 0x00, 0x00])
        Self.appendUInt16(UInt16(payload.count), to: &frame)
        frame.append(nextHeader)
        frame.append(hopLimit)
        frame.append(contentsOf: srcIP6)
        frame.append(contentsOf: dstIP6)
        frame.append(contentsOf: payload)
        sendUntaggedFrame(frame)
    }

    public static func tag(_ frame: Data, vlan: UInt16) -> Data {
        guard frame.count >= 14 else { return frame }
        var output = Data(frame.prefix(12))
        output.append(contentsOf: [0x81, 0x00, UInt8((vlan >> 8) & 0x0f), UInt8(vlan & 0xff)])
        output.append(frame.dropFirst(12))
        return output
    }

    public static func untag(_ frame: Data, vlan: UInt16) -> Data? {
        guard frame.count >= 18, frame[12] == 0x81, frame[13] == 0x00 else { return nil }
        let value = (UInt16(frame[14] & 0x0f) << 8) | UInt16(frame[15])
        guard value == vlan else { return nil }
        var output = Data(frame.prefix(12))
        output.append(frame.dropFirst(16))
        return output
    }

    static func firstIPv6Address(in subnet: String) throws -> [UInt8] {
        let parts = subnet.split(separator: "/")
        guard parts.count == 2, let prefixLength = Int(parts[1]), (0...128).contains(prefixLength) else {
            throw EngineError(.badRequest, "invalid IPv6 prefix \(subnet)")
        }
        var addr = in6_addr()
        guard inet_pton(AF_INET6, String(parts[0]), &addr) == 1 else {
            throw EngineError(.badRequest, "invalid IPv6 prefix \(subnet)")
        }
        var bytes = withUnsafeBytes(of: addr) { Array($0) }
        var remaining = prefixLength
        for index in 0..<16 {
            if remaining >= 8 {
                remaining -= 8
            } else if remaining > 0 {
                let mask = UInt8(0xff << (8 - remaining))
                bytes[index] &= mask
                remaining = 0
            } else {
                bytes[index] = 0
            }
        }
        for index in (0..<16).reversed() {
            bytes[index] &+= 1
            if bytes[index] != 0 { break }
        }
        return bytes
    }

    static func systemIPv4DNSServers() -> [[UInt8]] {
        guard let contents = try? String(contentsOfFile: "/etc/resolv.conf", encoding: .utf8) else {
            return [[1, 1, 1, 1], [8, 8, 8, 8]]
        }
        var servers: [[UInt8]] = []
        for rawLine in contents.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.hasPrefix("#") else { continue }
            let parts = line.split(whereSeparator: \.isWhitespace)
            guard parts.count >= 2, parts[0] == "nameserver" else { continue }
            var addr = in_addr()
            if String(parts[1]).withCString({ inet_pton(AF_INET, $0, &addr) }) == 1 {
                let bytes = withUnsafeBytes(of: addr.s_addr) { Array($0) }
                servers.append(bytes)
            }
        }
        return servers.isEmpty ? [[1, 1, 1, 1], [8, 8, 8, 8]] : servers
    }

    private static func readUInt16(_ bytes: [UInt8], at offset: Int) -> UInt16 {
        UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }

    private static func readUInt32(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        (UInt32(bytes[offset]) << 24)
            | (UInt32(bytes[offset + 1]) << 16)
            | (UInt32(bytes[offset + 2]) << 8)
            | UInt32(bytes[offset + 3])
    }

    private static func appendUInt16(_ value: UInt16, to bytes: inout [UInt8]) {
        bytes.append(UInt8(value >> 8))
        bytes.append(UInt8(value & 0xff))
    }

    private static func appendUInt32(_ value: UInt32, to bytes: inout [UInt8]) {
        bytes.append(UInt8((value >> 24) & 0xff))
        bytes.append(UInt8((value >> 16) & 0xff))
        bytes.append(UInt8((value >> 8) & 0xff))
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
        if index < bytes.count {
            sum += UInt32(bytes[index]) << 8
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16)
        }
        return ~UInt16(sum)
    }

    private static func transportChecksumIPv4(
        srcIP: [UInt8],
        dstIP: [UInt8],
        proto: UInt8,
        payload: [UInt8]
    ) -> UInt16 {
        var pseudo: [UInt8] = []
        pseudo.reserveCapacity(12 + payload.count)
        pseudo.append(contentsOf: srcIP)
        pseudo.append(contentsOf: dstIP)
        pseudo.append(0)
        pseudo.append(proto)
        appendUInt16(UInt16(payload.count), to: &pseudo)
        pseudo.append(contentsOf: payload)
        return checksum(pseudo)
    }

    private static func transportChecksumIPv6(
        srcIP6: [UInt8],
        dstIP6: [UInt8],
        nextHeader: UInt8,
        payload: [UInt8]
    ) -> UInt16 {
        var pseudo: [UInt8] = []
        pseudo.reserveCapacity(40 + payload.count)
        pseudo.append(contentsOf: srcIP6)
        pseudo.append(contentsOf: dstIP6)
        appendUInt32(UInt32(payload.count), to: &pseudo)
        pseudo.append(contentsOf: [0, 0, 0, nextHeader])
        pseudo.append(contentsOf: payload)
        return checksum(pseudo)
    }

    // MARK: - UDP Session

    private final class UDPSession {
        private let key: FlowKey
        private var guestMAC: [UInt8]
        private let targetIsIPv6: Bool
        private let targetIP: [UInt8]
        private let targetPort: UInt16
        private let descriptor: CInt
        private let readSource: DispatchSourceRead
        private var lastActivityNanoseconds: UInt64
        private var closed = false

        init?(
            key: FlowKey,
            guestMAC: [UInt8],
            targetIsIPv6: Bool,
            targetIP: [UInt8],
            targetPort: UInt16,
            queue: DispatchQueue,
            onReceive: @escaping (Data, FlowKey, [UInt8]) -> Void
        ) {
            let family = targetIsIPv6 ? AF_INET6 : AF_INET
            let fd = socket(family, SOCK_DGRAM, 0)
            guard fd >= 0 else { return nil }
            var one: CInt = 1
            _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout.size(ofValue: one)))
            let flags = fcntl(fd, F_GETFL)
            guard flags >= 0,
                  fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0,
                  fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else {
                Darwin.close(fd)
                return nil
            }
            self.key = key
            self.guestMAC = guestMAC
            self.targetIsIPv6 = targetIsIPv6
            self.targetIP = targetIP
            self.targetPort = targetPort
            self.descriptor = fd
            self.lastActivityNanoseconds = DispatchTime.now().uptimeNanoseconds

            let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
            self.readSource = source
            source.setEventHandler { [weak self] in
                guard let self, !self.closed else { return }
                var buffer = [UInt8](repeating: 0, count: 65_535)
                while true {
                    let count = buffer.withUnsafeMutableBytes { raw in
                        Darwin.recv(self.descriptor, raw.baseAddress, raw.count, 0)
                    }
                    guard count > 0 else { break }
                    self.lastActivityNanoseconds = DispatchTime.now().uptimeNanoseconds
                    onReceive(Data(buffer.prefix(count)), self.key, self.guestMAC)
                }
            }
            source.setCancelHandler {
                Darwin.close(fd)
            }
            source.resume()
        }

        func send(_ data: Data, guestMAC: [UInt8]) {
            guard !closed else { return }
            self.guestMAC = guestMAC
            lastActivityNanoseconds = DispatchTime.now().uptimeNanoseconds
            data.withUnsafeBytes { raw in
                if targetIsIPv6 {
                    var addr = sockaddr_in6()
                    addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
                    addr.sin6_family = sa_family_t(AF_INET6)
                    addr.sin6_port = targetPort.bigEndian
                    _ = withUnsafeMutableBytes(of: &addr.sin6_addr) { dst in
                        targetIP.withUnsafeBytes { src in
                            memcpy(dst.baseAddress, src.baseAddress, 16)
                        }
                    }
                    _ = withUnsafePointer(to: &addr) {
                        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                            Darwin.sendto(
                                descriptor,
                                raw.baseAddress,
                                raw.count,
                                0,
                                $0,
                                socklen_t(MemoryLayout<sockaddr_in6>.size)
                            )
                        }
                    }
                } else {
                    var addr = sockaddr_in()
                    addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                    addr.sin_family = sa_family_t(AF_INET)
                    addr.sin_port = targetPort.bigEndian
                    _ = withUnsafeMutableBytes(of: &addr.sin_addr) { dst in
                        targetIP.withUnsafeBytes { src in
                            memcpy(dst.baseAddress, src.baseAddress, 4)
                        }
                    }
                    _ = withUnsafePointer(to: &addr) {
                        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                            Darwin.sendto(
                                descriptor,
                                raw.baseAddress,
                                raw.count,
                                0,
                                $0,
                                socklen_t(MemoryLayout<sockaddr_in>.size)
                            )
                        }
                    }
                }
            }
        }

        func isExpired(now: UInt64) -> Bool {
            now - lastActivityNanoseconds > 30_000_000_000
        }

        func close() {
            guard !closed else { return }
            closed = true
            readSource.cancel()
        }
    }

    // MARK: - TCP Session

    private final class TCPSession {
        private enum State {
            case connecting
            case synReceived
            case established
            case closing
            case closed
        }

        private struct UnackedSegment {
            let seq: UInt32
            let ack: UInt32
            let flags: UInt8
            let options: [UInt8]
            let payload: [UInt8]
            var sentAtNanoseconds: UInt64
            var retries: Int
            var sequenceLength: UInt32 {
                var len = UInt32(payload.count)
                if flags & UserspaceNetworkUplink.tcpSYN != 0 { len &+= 1 }
                if flags & UserspaceNetworkUplink.tcpFIN != 0 { len &+= 1 }
                return len
            }
        }

        private let key: FlowKey
        private var guestMAC: [UInt8]
        private let targetIsIPv6: Bool
        private let targetIP: [UInt8]
        private let targetPort: UInt16
        private let queue: DispatchQueue
        private let sendSegment: (FlowKey, [UInt8], UInt32, UInt32, UInt8, [UInt8], [UInt8]) -> Void

        private var descriptor: CInt = -1
        private var readSource: DispatchSourceRead?
        private var writeSource: DispatchSourceWrite?
        private var readSuspended = true
        private var writeSuspended = true

        private var state: State = .connecting
        private let iss: UInt32
        private var sndUna: UInt32
        private var sndNxt: UInt32
        private var rcvNxt: UInt32
        private var finSent = false
        private var finReceived = false
        private var hostWriteShutdown = false
        private var pendingToHost = Data()
        private var outOfOrder: [UInt32: Data] = [:]
        private var unacked: [UnackedSegment] = []
        private var lastActivityNanoseconds: UInt64

        var isClosed: Bool { state == .closed }

        init(
            key: FlowKey,
            guestMAC: [UInt8],
            initialGuestSeq: UInt32,
            targetIsIPv6: Bool,
            targetIP: [UInt8],
            targetPort: UInt16,
            queue: DispatchQueue,
            sendSegment: @escaping (FlowKey, [UInt8], UInt32, UInt32, UInt8, [UInt8], [UInt8]) -> Void
        ) {
            self.key = key
            self.guestMAC = guestMAC
            self.targetIsIPv6 = targetIsIPv6
            self.targetIP = targetIP
            self.targetPort = targetPort
            self.queue = queue
            self.sendSegment = sendSegment
            let randomISS = UInt32.random(in: 100_000...2_000_000_000)
            self.iss = randomISS
            self.sndUna = randomISS
            self.sndNxt = randomISS
            self.rcvNxt = initialGuestSeq &+ 1
            self.lastActivityNanoseconds = DispatchTime.now().uptimeNanoseconds
        }

        func startConnect() {
            let family = targetIsIPv6 ? AF_INET6 : AF_INET
            let fd = socket(family, SOCK_STREAM, 0)
            guard fd >= 0 else {
                sendRSTAndClose()
                return
            }
            var one: CInt = 1
            _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout.size(ofValue: one)))
            _ = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, socklen_t(MemoryLayout.size(ofValue: one)))
            let flags = fcntl(fd, F_GETFL)
            guard flags >= 0,
                  fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0,
                  fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else {
                Darwin.close(fd)
                sendRSTAndClose()
                return
            }
            self.descriptor = fd

            let connectResult: CInt
            if targetIsIPv6 {
                var addr = sockaddr_in6()
                addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
                addr.sin6_family = sa_family_t(AF_INET6)
                addr.sin6_port = targetPort.bigEndian
                _ = withUnsafeMutableBytes(of: &addr.sin6_addr) { dst in
                    targetIP.withUnsafeBytes { src in
                        memcpy(dst.baseAddress, src.baseAddress, 16)
                    }
                }
                connectResult = withUnsafePointer(to: &addr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
                    }
                }
            } else {
                var addr = sockaddr_in()
                addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                addr.sin_family = sa_family_t(AF_INET)
                addr.sin_port = targetPort.bigEndian
                _ = withUnsafeMutableBytes(of: &addr.sin_addr) { dst in
                    targetIP.withUnsafeBytes { src in
                        memcpy(dst.baseAddress, src.baseAddress, 4)
                    }
                }
                connectResult = withUnsafePointer(to: &addr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }

            if connectResult == 0 {
                setupDispatchSources()
                transitionToSynReceived()
                return
            }
            let err = errno
            guard err == EINPROGRESS else {
                close()
                sendSegment(
                    key, guestMAC, 0, rcvNxt,
                    UserspaceNetworkUplink.tcpRST | UserspaceNetworkUplink.tcpACK,
                    [], []
                )
                return
            }
            setupDispatchSources()
            resumeWriteSource()
        }

        private func setupDispatchSources() {
            guard descriptor >= 0 else { return }
            let fd = descriptor
            final class DescriptorCloser: @unchecked Sendable {
                private var remaining = 2
                private let fd: CInt
                init(_ fd: CInt) { self.fd = fd }
                func releaseOne() {
                    remaining -= 1
                    if remaining == 0 {
                        Darwin.close(fd)
                    }
                }
            }
            let closer = DescriptorCloser(fd)

            let rSource = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
            rSource.setEventHandler { [weak self] in
                self?.readFromHostSocket()
            }
            rSource.setCancelHandler {
                closer.releaseOne()
            }
            self.readSource = rSource
            self.readSuspended = true

            let wSource = DispatchSource.makeWriteSource(fileDescriptor: fd, queue: queue)
            wSource.setEventHandler { [weak self] in
                self?.writeToHostSocket()
            }
            wSource.setCancelHandler {
                closer.releaseOne()
            }
            self.writeSource = wSource
            self.writeSuspended = true
        }

        private func resumeReadSource() {
            guard readSuspended, let readSource, state != .closed else { return }
            readSuspended = false
            readSource.resume()
        }

        private func suspendReadSource() {
            guard !readSuspended, let readSource else { return }
            readSuspended = true
            readSource.suspend()
        }

        private func resumeWriteSource() {
            guard writeSuspended, let writeSource, state != .closed else { return }
            writeSuspended = false
            writeSource.resume()
        }

        private func suspendWriteSource() {
            guard !writeSuspended, let writeSource else { return }
            writeSuspended = true
            writeSource.suspend()
        }

        func handleDuplicateSYN(seq: UInt32) -> Bool {
            guard seq &+ 1 == rcvNxt else { return false }
            if state == .connecting {
                return true
            }
            if state == .synReceived {
                sendSegment(
                    key, guestMAC, iss, rcvNxt,
                    UserspaceNetworkUplink.tcpSYN | UserspaceNetworkUplink.tcpACK,
                    [0x02, 0x04, 0x05, 0xb4], []
                )
                return true
            }
            return false
        }

        private func transitionToSynReceived() {
            guard state == .connecting else { return }
            state = .synReceived
            let synAckOptions: [UInt8] = [0x02, 0x04, 0x05, 0xb4] // MSS 1460
            let seg = UnackedSegment(
                seq: iss,
                ack: rcvNxt,
                flags: UserspaceNetworkUplink.tcpSYN | UserspaceNetworkUplink.tcpACK,
                options: synAckOptions,
                payload: [],
                sentAtNanoseconds: DispatchTime.now().uptimeNanoseconds,
                retries: 0
            )
            sndNxt = iss &+ 1
            unacked.append(seg)
            sendSegment(key, guestMAC, seg.seq, seg.ack, seg.flags, seg.options, seg.payload)
        }

        func handleGuestSegment(
            seq: UInt32,
            ack: UInt32,
            flags: UInt8,
            payload: Data,
            guestMAC: [UInt8]
        ) {
            guard state != .closed && state != .connecting else { return }
            self.guestMAC = guestMAC
            lastActivityNanoseconds = DispatchTime.now().uptimeNanoseconds

            if flags & UserspaceNetworkUplink.tcpACK != 0 {
                if Self.seqLess(sndUna, ack) && Self.seqLessOrEqual(ack, sndNxt) {
                    sndUna = ack
                    unacked.removeAll { seg in
                        Self.seqLessOrEqual(seg.seq &+ seg.sequenceLength, ack)
                    }
                    if state == .synReceived {
                        state = .established
                        resumeReadSource()
                    }
                    let inFlight = Int32(bitPattern: sndNxt &- sndUna)
                    if state == .established && !finSent && inFlight < UserspaceNetworkUplink.resumeInFlightBytes {
                        resumeReadSource()
                    }
                }
            }

            guard state == .established || state == .closing else { return }

            var sendImmediateAck = false
            if !payload.isEmpty {
                let diff = Int32(bitPattern: seq &- rcvNxt)
                if diff <= 0 {
                    let overlap = Int(-diff)
                    if overlap < payload.count {
                        let newBytes = payload.dropFirst(overlap)
                        pendingToHost.append(newBytes)
                        rcvNxt &+= UInt32(newBytes.count)
                        drainOutOfOrder()
                        flushPendingToHost()
                    }
                    sendImmediateAck = true
                } else {
                    if outOfOrder.count < 16 {
                        outOfOrder[seq] = payload
                    }
                    sendImmediateAck = true
                }
            }

            if (flags & UserspaceNetworkUplink.tcpFIN != 0) && !finReceived {
                let finSeq = seq &+ UInt32(payload.count)
                if finSeq == rcvNxt {
                    finReceived = true
                    rcvNxt &+= 1
                    sendImmediateAck = true
                    if pendingToHost.isEmpty && !hostWriteShutdown && descriptor >= 0 {
                        hostWriteShutdown = true
                        Darwin.shutdown(descriptor, SHUT_WR)
                    }
                    if state == .established {
                        state = .closing
                    }
                }
            }

            if sendImmediateAck {
                sendSegment(
                    key, guestMAC, sndNxt, rcvNxt,
                    UserspaceNetworkUplink.tcpACK, [], []
                )
            }

            if finReceived && finSent && unacked.isEmpty && pendingToHost.isEmpty {
                close()
            }
        }

        private func drainOutOfOrder() {
            while let nextData = outOfOrder.removeValue(forKey: rcvNxt) {
                pendingToHost.append(nextData)
                rcvNxt &+= UInt32(nextData.count)
            }
        }

        private func writeToHostSocket() {
            guard state != .closed, descriptor >= 0 else { return }
            if state == .connecting {
                var socketError: CInt = 0
                var len = socklen_t(MemoryLayout<CInt>.size)
                if getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &socketError, &len) < 0 || socketError != 0 {
                    sendRSTAndClose()
                    return
                }
                suspendWriteSource()
                transitionToSynReceived()
                return
            }
            flushPendingToHost()
        }

        private func flushPendingToHost() {
            guard state != .closed, descriptor >= 0 else { return }
            while !pendingToHost.isEmpty {
                let written = pendingToHost.withUnsafeBytes { raw in
                    Darwin.write(descriptor, raw.baseAddress, raw.count)
                }
                if written > 0 {
                    pendingToHost.removeFirst(written)
                } else if written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
                    resumeWriteSource()
                    return
                } else {
                    sendRSTAndClose()
                    return
                }
            }
            suspendWriteSource()
            if finReceived && !hostWriteShutdown {
                hostWriteShutdown = true
                Darwin.shutdown(descriptor, SHUT_WR)
            }
            if finReceived && finSent && unacked.isEmpty {
                close()
            }
        }

        private func readFromHostSocket() {
            guard state == .established || state == .closing, descriptor >= 0 else {
                suspendReadSource()
                return
            }
            var buffer = [UInt8](repeating: 0, count: UserspaceNetworkUplink.maxSegmentPayload)
            while true {
                let inFlight = Int32(bitPattern: sndNxt &- sndUna)
                if inFlight >= UserspaceNetworkUplink.maxInFlightBytes {
                    suspendReadSource()
                    return
                }
                let count = buffer.withUnsafeMutableBytes { raw in
                    Darwin.read(descriptor, raw.baseAddress, raw.count)
                }
                if count > 0 {
                    lastActivityNanoseconds = DispatchTime.now().uptimeNanoseconds
                    let chunk = Array(buffer.prefix(count))
                    let seg = UnackedSegment(
                        seq: sndNxt,
                        ack: rcvNxt,
                        flags: UserspaceNetworkUplink.tcpPSH | UserspaceNetworkUplink.tcpACK,
                        options: [],
                        payload: chunk,
                        sentAtNanoseconds: lastActivityNanoseconds,
                        retries: 0
                    )
                    sndNxt &+= UInt32(chunk.count)
                    unacked.append(seg)
                    sendSegment(key, guestMAC, seg.seq, seg.ack, seg.flags, seg.options, seg.payload)
                } else if count == 0 {
                    suspendReadSource()
                    if !finSent {
                        finSent = true
                        let seg = UnackedSegment(
                            seq: sndNxt,
                            ack: rcvNxt,
                            flags: UserspaceNetworkUplink.tcpFIN | UserspaceNetworkUplink.tcpACK,
                            options: [],
                            payload: [],
                            sentAtNanoseconds: DispatchTime.now().uptimeNanoseconds,
                            retries: 0
                        )
                        sndNxt &+= 1
                        unacked.append(seg)
                        sendSegment(key, guestMAC, seg.seq, seg.ack, seg.flags, seg.options, seg.payload)
                        if state == .established {
                            state = .closing
                        }
                    }
                    return
                } else {
                    if errno == EAGAIN || errno == EWOULDBLOCK {
                        return
                    }
                    sendRSTAndClose()
                    return
                }
            }
        }

        func onTimer(now: UInt64) {
            guard state != .closed else { return }
            if state == .connecting && now - lastActivityNanoseconds > 5_000_000_000 {
                sendRSTAndClose()
                return
            }
            if now - lastActivityNanoseconds > 60_000_000_000 {
                close()
                return
            }
            for index in unacked.indices {
                if now - unacked[index].sentAtNanoseconds >= 400_000_000 {
                    if unacked[index].retries >= 6 {
                        sendRSTAndClose()
                        return
                    }
                    unacked[index].retries += 1
                    unacked[index].sentAtNanoseconds = now
                    let seg = unacked[index]
                    sendSegment(key, guestMAC, seg.seq, rcvNxt, seg.flags, seg.options, seg.payload)
                }
            }
        }

        private func sendRSTAndClose() {
            let ack = rcvNxt
            let seq = sndNxt
            close()
            sendSegment(
                key, guestMAC, seq, ack,
                UserspaceNetworkUplink.tcpRST | UserspaceNetworkUplink.tcpACK,
                [], []
            )
        }

        func close() {
            guard state != .closed else { return }
            state = .closed
            unacked.removeAll()
            outOfOrder.removeAll()
            pendingToHost.removeAll()
            let fd = descriptor
            descriptor = -1
            let hadSources = (readSource != nil || writeSource != nil)
            if let readSource {
                if readSuspended { readSource.resume() }
                readSource.cancel()
                self.readSource = nil
            }
            if let writeSource {
                if writeSuspended { writeSource.resume() }
                writeSource.cancel()
                self.writeSource = nil
            }
            if !hadSources && fd >= 0 {
                Darwin.close(fd)
            }
        }

        private static func seqLess(_ a: UInt32, _ b: UInt32) -> Bool {
            Int32(bitPattern: a &- b) < 0
        }

        private static func seqLessOrEqual(_ a: UInt32, _ b: UInt32) -> Bool {
            Int32(bitPattern: a &- b) <= 0
        }
    }
}

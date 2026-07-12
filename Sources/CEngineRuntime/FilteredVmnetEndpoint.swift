#if os(macOS)
import CEngineCore
import ContainerizationExtras
import Darwin
import Foundation
import Virtualization
import XPC
import vmnet

/// A vmnet endpoint whose frames pass through cengine before entering vmnet.
/// This is used only for Docker's isolated gateway modes; ordinary networks
/// retain the direct VZ vmnet attachment.
final class FilteredVmnetEndpoint: @unchecked Sendable {
    private final class StartState: @unchecked Sendable { var reference: interface_ref? }
    private let queue: DispatchQueue
    private let vmFile: FileHandle
    private let relayFD: CInt
    private let networkInterface: interface_ref
    private let filter: IsolatedGatewayPacketFilter
    private var readSource: DispatchSourceRead?
    private let stateLock = NSLock()
    private var stopped = false

    private init(
        queue: DispatchQueue,
        vmFile: FileHandle,
        relayFD: CInt,
        networkInterface: interface_ref,
        filter: IsolatedGatewayPacketFilter
    ) {
        self.queue = queue
        self.vmFile = vmFile
        self.relayFD = relayFD
        self.networkInterface = networkInterface
        self.filter = filter
    }

    static func start(
        network: vmnet_network_ref,
        subnet: CIDRv4,
        prefixV6: CIDRv6?,
        isolateIPv4: Bool,
        isolateIPv6: Bool
    ) async throws -> FilteredVmnetEndpoint {
        var sockets = [CInt](repeating: -1, count: 2)
        guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &sockets) == 0 else {
            throw EngineError(.internalError, "failed to create filtered vmnet socket pair: \(String(cString: strerror(errno)))")
        }
        var ownsSockets = true
        defer {
            if ownsSockets { sockets.forEach { if $0 >= 0 { Darwin.close($0) } } }
        }
        for descriptor in sockets {
            var size: CInt = 4 * 1024 * 1024
            _ = setsockopt(descriptor, SOL_SOCKET, SO_SNDBUF, &size, socklen_t(MemoryLayout<CInt>.size))
            size = 8 * 1024 * 1024
            _ = setsockopt(descriptor, SOL_SOCKET, SO_RCVBUF, &size, socklen_t(MemoryLayout<CInt>.size))
            _ = fcntl(descriptor, F_SETFL, fcntl(descriptor, F_GETFL) | O_NONBLOCK)
        }

        let queue = DispatchQueue(label: "dev.cengine.vmnet-filter.\(UUID().uuidString)")
        let descriptor = xpc_dictionary_create_empty()
        let startState = StartState()
        let started: interface_ref = try await withCheckedThrowingContinuation { continuation in
            guard let value = vmnet_interface_start_with_network(network, descriptor, queue, { status, _ in
                guard status == .VMNET_SUCCESS else {
                    continuation.resume(throwing: EngineError(.internalError, "failed to start filtered vmnet interface with status \(status)"))
                    return
                }
                guard let reference = startState.reference else {
                    continuation.resume(throwing: EngineError(.internalError, "filtered vmnet interface returned no handle"))
                    return
                }
                continuation.resume(returning: reference)
            }) else {
                continuation.resume(throwing: EngineError(.internalError, "failed to create filtered vmnet interface"))
                return
            }
            startState.reference = value
        }

        let endpoint = FilteredVmnetEndpoint(
            queue: queue,
            vmFile: FileHandle(fileDescriptor: sockets[0], closeOnDealloc: true),
            relayFD: sockets[1],
            networkInterface: started,
            filter: IsolatedGatewayPacketFilter(
                subnet: subnet, prefixV6: prefixV6,
                isolateIPv4: isolateIPv4, isolateIPv6: isolateIPv6
            )
        )
        ownsSockets = false
        try endpoint.startRelays()
        return endpoint
    }

    func device(mtu: UInt32, macAddress: MACAddress?) throws -> VZVirtioNetworkDeviceConfiguration {
        let configuration = VZVirtioNetworkDeviceConfiguration()
        if let macAddress {
            guard let value = VZMACAddress(string: macAddress.description) else {
                throw EngineError(.badRequest, "invalid MAC address \(macAddress)")
            }
            configuration.macAddress = value
        }
        let attachment = VZFileHandleNetworkDeviceAttachment(fileHandle: vmFile)
        attachment.maximumTransmissionUnit = Int(mtu)
        configuration.attachment = attachment
        return configuration
    }

    private func startRelays() throws {
        guard vmnet_interface_set_event_callback(
            networkInterface, .VMNET_INTERFACE_PACKETS_AVAILABLE, queue,
            { [weak self] _, _ in self?.drainVmnet() }
        ) == .VMNET_SUCCESS else {
            throw EngineError(.internalError, "failed to install filtered vmnet event callback")
        }
        let source = DispatchSource.makeReadSource(fileDescriptor: relayFD, queue: queue)
        source.setEventHandler { [weak self] in self?.drainGuest() }
        source.setCancelHandler { [relayFD] in Darwin.close(relayFD) }
        readSource = source
        source.resume()
    }

    private func drainGuest() {
        var bytes = [UInt8](repeating: 0, count: 65_536)
        while true {
            let count = recv(relayFD, &bytes, bytes.count, MSG_DONTWAIT)
            if count < 0 {
                if errno == EAGAIN || errno == EWOULDBLOCK { return }
                return
            }
            if count == 0 { return }
            let packet = Array(bytes.prefix(count))
            guard filter.allows(packet, direction: .guestToNetwork) else { continue }
            writeToVmnet(packet)
        }
    }

    private func drainVmnet() {
        while true {
            var bytes = [UInt8](repeating: 0, count: 65_536)
            let size = bytes.count
            var packetSize = 0
            let status = bytes.withUnsafeMutableBytes { raw in
                var vector = iovec(iov_base: raw.baseAddress, iov_len: size)
                return withUnsafeMutablePointer(to: &vector) { vectorPointer in
                    var packet = vmpktdesc(
                        vm_pkt_size: size, vm_pkt_iov: vectorPointer, vm_pkt_iovcnt: 1, vm_flags: 0
                    )
                    var count: CInt = 1
                    let status = vmnet_read(networkInterface, &packet, &count)
                    packetSize = count == 1 ? packet.vm_pkt_size : 0
                    return status
                }
            }
            guard status == .VMNET_SUCCESS, packetSize > 0 else { return }
            let packet = Array(bytes.prefix(packetSize))
            guard filter.allows(packet, direction: .networkToGuest) else { continue }
            packet.withUnsafeBytes { raw in
                _ = send(relayFD, raw.baseAddress, raw.count, MSG_DONTWAIT)
            }
        }
    }

    private func writeToVmnet(_ bytes: [UInt8]) {
        bytes.withUnsafeBytes { raw in
            var vector = iovec(iov_base: UnsafeMutableRawPointer(mutating: raw.baseAddress), iov_len: raw.count)
            withUnsafeMutablePointer(to: &vector) { vectorPointer in
                var packet = vmpktdesc(
                    vm_pkt_size: raw.count, vm_pkt_iov: vectorPointer, vm_pkt_iovcnt: 1, vm_flags: 0
                )
                var count: CInt = 1
                _ = vmnet_write(networkInterface, &packet, &count)
            }
        }
    }

    func stop() {
        stateLock.lock()
        guard !stopped else { stateLock.unlock(); return }
        stopped = true
        stateLock.unlock()
        if let readSource {
            readSource.cancel()
        } else {
            Darwin.close(relayFD)
        }
        readSource = nil
        _ = vmnet_interface_set_event_callback(networkInterface, [], nil, nil)
        _ = vmnet_stop_interface(networkInterface, queue, { _ in })
        try? vmFile.close()
    }

    deinit { stop() }
}

enum PacketDirection { case guestToNetwork, networkToGuest }

struct IsolatedGatewayPacketFilter: Sendable {
    private let subnet: CIDRv4
    private let gatewayV4: IPv4Address
    private let prefixV6: CIDRv6?
    private let gatewayV6: IPv6Address?
    private let isolateIPv4: Bool
    private let isolateIPv6: Bool

    init(subnet: CIDRv4, prefixV6: CIDRv6?, isolateIPv4: Bool, isolateIPv6: Bool) {
        self.subnet = subnet; self.gatewayV4 = subnet.gateway
        self.prefixV6 = prefixV6; self.gatewayV6 = prefixV6?.gateway
        self.isolateIPv4 = isolateIPv4; self.isolateIPv6 = isolateIPv6
    }

    func allows(_ frame: [UInt8], direction: PacketDirection) -> Bool {
        guard frame.count >= 14 else { return false }
        let etherType = UInt16(frame[12]) << 8 | UInt16(frame[13])
        switch etherType {
        case 0x0800: return allowsIPv4(frame, direction: direction)
        case 0x0806: return allowsARP(frame)
        case 0x86dd: return allowsIPv6(frame, direction: direction)
        default: return !(isolateIPv4 || isolateIPv6)
        }
    }

    private func allowsIPv4(_ frame: [UInt8], direction: PacketDirection) -> Bool {
        guard isolateIPv4 else { return true }
        guard frame.count >= 34, frame[14] >> 4 == 4, Int(frame[14] & 0x0f) >= 5 else { return false }
        let source = ipv4(frame, 26); let destination = ipv4(frame, 30)
        guard let source, let destination else { return false }
        switch direction {
        case .guestToNetwork:
            return subnet.contains(source) && subnet.contains(destination) &&
                destination != gatewayV4 && destination != subnet.upper
        case .networkToGuest:
            return subnet.contains(source) && source != gatewayV4 &&
                subnet.contains(destination) && destination != subnet.upper
        }
    }

    private func allowsARP(_ frame: [UInt8]) -> Bool {
        guard isolateIPv4 else { return true }
        guard frame.count >= 42,
              frame[14] == 0, frame[15] == 1, frame[16] == 0x08, frame[17] == 0,
              frame[18] == 6, frame[19] == 4,
              frame[20] == 0, frame[21] == 1 || frame[21] == 2 else { return false }
        guard let source = ipv4(frame, 28), let target = ipv4(frame, 38) else { return false }
        return subnet.contains(source) && subnet.contains(target) &&
            source != gatewayV4 && target != gatewayV4
    }

    private func allowsIPv6(_ frame: [UInt8], direction: PacketDirection) -> Bool {
        guard isolateIPv6 else { return true }
        guard frame.count >= 54, frame[14] >> 4 == 6, let prefixV6, let gatewayV6,
              let source = try? IPv6Address(Array(frame[22..<38])),
              let destination = try? IPv6Address(Array(frame[38..<54])) else { return false }
        switch direction {
        case .guestToNetwork:
            return prefixV6.contains(source) &&
                ((prefixV6.contains(destination) && destination != gatewayV6) || isIPv6NeighborDiscovery(frame))
        case .networkToGuest:
            return prefixV6.contains(source) && source != gatewayV6 &&
                (prefixV6.contains(destination) || isIPv6NeighborDiscovery(frame))
        }
    }

    private func isIPv6NeighborDiscovery(_ frame: [UInt8]) -> Bool {
        frame.count >= 55 && frame[20] == 58 && frame[38] == 0xff &&
            (frame[54] == 135 || frame[54] == 136)
    }

    private func ipv4(_ bytes: [UInt8], _ offset: Int) -> IPv4Address? {
        guard bytes.count >= offset + 4 else { return nil }
        return IPv4Address(
            UInt32(bytes[offset]) << 24 | UInt32(bytes[offset + 1]) << 16 |
            UInt32(bytes[offset + 2]) << 8 | UInt32(bytes[offset + 3])
        )
    }
}
#endif

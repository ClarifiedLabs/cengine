#if os(macOS)
import CEngineCore
import Containerization
import ContainerizationExtras
import CoreFoundation
import Darwin
import Synchronization
import Virtualization
import vmnet

/// Owns a vmnet reservation explicitly. Containerization's value-type
/// `VmnetNetwork` does not provide a place to release the retained C handle.
fileprivate final class ManagedVmnetHandle: @unchecked Sendable {
    let reference: vmnet_network_ref

    init(_ reference: vmnet_network_ref) {
        self.reference = reference
    }

    deinit {
        Unmanaged<AnyObject>.fromOpaque(UnsafeRawPointer(reference)).release()
    }
}

final class ManagedVmnetNetwork: @unchecked Sendable {
    private struct AllocationState: ~Copyable {
        var allocations: [String: (ipv4: UInt32, ipv6: UInt128?)] = [:]
        var nextIPv4Offset: UInt32 = 2
        var nextIPv6Offset: UInt32 = 2
    }

    struct Interface: Containerization.Interface, VZInterface, Sendable {
        fileprivate enum Attachment: Sendable {
            case direct(ManagedVmnetHandle)
            case filtered(FilteredVmnetEndpoint)
        }

        fileprivate let handle: ManagedVmnetHandle
        fileprivate let attachment: Attachment
        let ipv4Address: CIDRv4
        let ipv4Gateway: IPv4Address?
        let ipv6Address: CIDRv6?
        let ipv6Gateway: IPv6Address?
        let macAddress: MACAddress? = nil
        let mtu: UInt32 = 1500

        func device() throws -> VZVirtioNetworkDeviceConfiguration {
            switch attachment {
            case .direct(let handle):
                let configuration = VZVirtioNetworkDeviceConfiguration()
                configuration.attachment = VZVmnetNetworkDeviceAttachment(network: handle.reference)
                return configuration
            case .filtered(let endpoint):
                return try endpoint.device(mtu: mtu, macAddress: macAddress)
            }
        }

        func stop() {
            if case .filtered(let endpoint) = attachment { endpoint.stop() }
        }
    }

    private let handle: ManagedVmnetHandle
    private let allocationState = Mutex(AllocationState())
    let subnet: CIDRv4
    let prefixV6: CIDRv6?

    var ipv4Gateway: IPv4Address { subnet.gateway }
    var ipv6Gateway: IPv6Address? { prefixV6?.gateway }

    init(mode: vmnet.operating_modes_t, subnet: CIDRv4, prefixV6: CIDRv6) throws {
        var status: vmnet_return_t = .VMNET_FAILURE
        guard let configuration = vmnet_network_configuration_create(mode, &status) else {
            throw EngineError(.internalError, "failed to create vmnet configuration with status \(status)")
        }
        defer { Unmanaged<AnyObject>.fromOpaque(UnsafeRawPointer(configuration)).release() }
        vmnet_network_configuration_disable_dhcp(configuration)
        try Self.configureIPv4(configuration, subnet: subnet)
        try Self.configureIPv6(configuration, prefix: prefixV6)
        guard let reference = vmnet_network_create(configuration, &status), status == .VMNET_SUCCESS else {
            throw EngineError(.internalError, "failed to create vmnet network with status \(status)")
        }
        self.handle = ManagedVmnetHandle(reference)
        self.subnet = try Self.readIPv4(reference)
        self.prefixV6 = Self.readIPv6(reference)
    }

    func createInterface(
        _ id: String, withDefaultRoute: Bool, requestedIPv4: CIDRv4? = nil, requestedIPv6: CIDRv6? = nil,
        isolateIPv4: Bool = false, isolateIPv6: Bool = false
    ) async throws -> Interface {
        let (ipv4Value, ipv6Value) = try allocationState.withLock { state -> (UInt32, UInt128?) in
            guard state.allocations[id] == nil else {
                throw EngineError(.conflict, "network allocation already exists for \(id)")
            }
            let ipv4Value: UInt32
            if let requestedIPv4 {
                guard subnet.contains(requestedIPv4.address),
                      !state.allocations.values.contains(where: { $0.ipv4 == requestedIPv4.address.value }) else {
                    throw EngineError(.conflict, "requested IPv4 address is unavailable")
                }
                ipv4Value = requestedIPv4.address.value
            } else {
                let used = Set(state.allocations.values.map(\.ipv4))
                guard let offset = Self.availableOffset(
                    startingAt: state.nextIPv4Offset,
                    where: { !used.contains(subnet.lower.value + $0) }
                ) else {
                    throw EngineError(.conflict, "network has no available IPv4 addresses")
                }
                state.nextIPv4Offset = Self.nextOffset(after: offset)
                ipv4Value = subnet.lower.value + offset
            }
            let ipv6Value: UInt128?
            if let requestedIPv6 {
                guard prefixV6?.contains(requestedIPv6.address) == true,
                      !state.allocations.values.contains(where: { $0.ipv6 == requestedIPv6.address.value }) else {
                    throw EngineError(.conflict, "requested IPv6 address is unavailable")
                }
                ipv6Value = requestedIPv6.address.value
            } else if let prefixV6 {
                let used = Set(state.allocations.values.compactMap(\.ipv6))
                let base = prefixV6.address.value & prefixV6.prefix.prefixMask128
                guard let offset = Self.availableOffset(
                    startingAt: state.nextIPv6Offset,
                    where: { !used.contains(base | UInt128($0)) }
                ) else {
                    throw EngineError(.conflict, "network has no available IPv6 addresses")
                }
                state.nextIPv6Offset = Self.nextOffset(after: offset)
                ipv6Value = base | UInt128(offset)
            } else {
                ipv6Value = nil
            }
            state.allocations[id] = (ipv4Value, ipv6Value)
            return (ipv4Value, ipv6Value)
        }
        let ipv4 = try CIDRv4(IPv4Address(ipv4Value), prefix: subnet.prefix)
        let ipv6 = try ipv6Value.flatMap { value in
            try prefixV6.map { try CIDRv6(IPv6Address(value), prefix: $0.prefix) }
        }
        let attachment: Interface.Attachment
        if isolateIPv4 || isolateIPv6 {
            do {
                attachment = .filtered(try await FilteredVmnetEndpoint.start(
                    network: handle.reference, subnet: subnet, prefixV6: prefixV6,
                    isolateIPv4: isolateIPv4, isolateIPv6: isolateIPv6
                ))
            } catch {
                allocationState.withLock { _ = $0.allocations.removeValue(forKey: id) }
                throw error
            }
        } else {
            attachment = .direct(handle)
        }
        return Interface(
            handle: handle, attachment: attachment,
            ipv4Address: ipv4,
            ipv4Gateway: withDefaultRoute && !isolateIPv4 ? ipv4Gateway : nil,
            ipv6Address: ipv6,
            ipv6Gateway: withDefaultRoute && !isolateIPv6 ? ipv6Gateway : nil
        )
    }

    func releaseInterface(_ id: String) {
        allocationState.withLock { _ = $0.allocations.removeValue(forKey: id) }
    }

    private static func availableOffset(startingAt start: UInt32, where available: (UInt32) -> Bool) -> UInt32? {
        for distance in UInt32(0)..<UInt32(252) {
            let candidate = 2 + ((start - 2 + distance) % 252)
            if available(candidate) { return candidate }
        }
        return nil
    }

    private static func nextOffset(after offset: UInt32) -> UInt32 {
        2 + ((offset - 1) % 252)
    }

    private static func configureIPv4(_ configuration: vmnet_network_configuration_ref, subnet: CIDRv4) throws {
        var gateway = in_addr()
        var mask = in_addr()
        inet_pton(AF_INET, subnet.gateway.description, &gateway)
        inet_pton(AF_INET, IPv4Address(subnet.prefix.prefixMask32).description, &mask)
        guard vmnet_network_configuration_set_ipv4_subnet(configuration, &gateway, &mask) == .VMNET_SUCCESS else {
            throw EngineError(.internalError, "failed to configure vmnet IPv4 subnet \(subnet)")
        }
    }

    private static func configureIPv6(_ configuration: vmnet_network_configuration_ref, prefix: CIDRv6) throws {
        var address = in6_addr()
        inet_pton(AF_INET6, prefix.lower.description, &address)
        guard vmnet_network_configuration_set_ipv6_prefix(configuration, &address, prefix.prefix.length) == .VMNET_SUCCESS else {
            throw EngineError(.internalError, "failed to configure vmnet IPv6 prefix \(prefix)")
        }
    }

    private static func readIPv4(_ reference: vmnet_network_ref) throws -> CIDRv4 {
        var address = in_addr()
        var mask = in_addr()
        vmnet_network_get_ipv4_subnet(reference, &address, &mask)
        let value = UInt32(bigEndian: address.s_addr)
        let maskValue = UInt32(bigEndian: mask.s_addr)
        let lower = IPv4Address(value & maskValue)
        return try CIDRv4(lower: lower, upper: IPv4Address(lower.value + ~maskValue))
    }

    private static func readIPv6(_ reference: vmnet_network_ref) -> CIDRv6? {
        var address = in6_addr()
        var length: UInt8 = 0
        vmnet_network_get_ipv6_prefix(reference, &address, &length)
        guard length > 0, let prefix = Prefix.ipv6(length),
              let value = try? IPv6Address(withUnsafeBytes(of: address) { Array($0) }) else { return nil }
        return try? CIDRv6(value, prefix: prefix)
    }
}
#endif

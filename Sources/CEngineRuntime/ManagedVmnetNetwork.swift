#if os(macOS)
import CEngineCore
import Containerization
import ContainerizationExtras
import CoreFoundation
import Darwin
import Virtualization
import vmnet
import XPC

/// Owns a vmnet reservation explicitly. Containerization's value-type
/// `VmnetNetwork` does not provide a place to release the retained C handle.
private final class ManagedVmnetHandle: @unchecked Sendable {
    let reference: vmnet_network_ref

    init(_ reference: vmnet_network_ref) {
        self.reference = reference
    }

    deinit {
        Unmanaged<AnyObject>.fromOpaque(UnsafeRawPointer(reference)).release()
    }
}

struct ManagedVmnetNetwork {
    struct Interface: Containerization.Interface, VZInterface, Sendable {
        fileprivate let handle: ManagedVmnetHandle
        let ipv4Address: CIDRv4
        let ipv4Gateway: IPv4Address?
        let ipv6Address: CIDRv6?
        let ipv6Gateway: IPv6Address?
        let macAddress: MACAddress? = nil
        let mtu: UInt32 = 1500

        func device() throws -> VZVirtioNetworkDeviceConfiguration {
            let configuration = VZVirtioNetworkDeviceConfiguration()
            configuration.attachment = VZVmnetNetworkDeviceAttachment(network: handle.reference)
            return configuration
        }
    }

    private let handle: ManagedVmnetHandle
    private var allocations: [String: (ipv4: UInt32, ipv6: UInt128?)] = [:]
    private var nextIPv4Offset: UInt32 = 2
    private var nextIPv6Offset: UInt32 = 2
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

    init(serialization: Data) throws {
        let object = try XPCArchive.decode(serialization)
        var status: vmnet_return_t = .VMNET_FAILURE
        guard let reference = vmnet_network_create_with_serialization(object, &status), status == .VMNET_SUCCESS else {
            throw EngineError(.internalError, "failed to restore serialized vmnet network with status \(status)")
        }
        self.handle = ManagedVmnetHandle(reference)
        self.subnet = try Self.readIPv4(reference)
        self.prefixV6 = Self.readIPv6(reference)
    }

    func serialization() throws -> Data {
        var status: vmnet_return_t = .VMNET_FAILURE
        guard let object = vmnet_network_copy_serialization(handle.reference, &status), status == .VMNET_SUCCESS else {
            throw EngineError(.internalError, "failed to serialize vmnet network with status \(status)")
        }
        return try XPCArchive.encode(object)
    }

    mutating func createInterface(
        _ id: String, withDefaultRoute: Bool, requestedIPv4: CIDRv4? = nil, requestedIPv6: CIDRv6? = nil
    ) throws -> Interface {
        guard allocations[id] == nil else {
            throw EngineError(.conflict, "network allocation already exists for \(id)")
        }
        let ipv4Value: UInt32
        if let requestedIPv4 {
            guard subnet.contains(requestedIPv4.address), !allocations.values.contains(where: { $0.ipv4 == requestedIPv4.address.value }) else {
                throw EngineError(.conflict, "requested IPv4 address is unavailable")
            }
            ipv4Value = requestedIPv4.address.value
        } else {
            let used = Set(allocations.values.map(\.ipv4))
            guard let offset = Self.availableOffset(startingAt: nextIPv4Offset, where: { !used.contains(subnet.lower.value + $0) }) else {
                throw EngineError(.conflict, "network has no available IPv4 addresses")
            }
            nextIPv4Offset = Self.nextOffset(after: offset)
            ipv4Value = subnet.lower.value + offset
        }
        let ipv6Value: UInt128?
        if let requestedIPv6 {
            guard prefixV6?.contains(requestedIPv6.address) == true,
                  !allocations.values.contains(where: { $0.ipv6 == requestedIPv6.address.value }) else {
                throw EngineError(.conflict, "requested IPv6 address is unavailable")
            }
            ipv6Value = requestedIPv6.address.value
        } else if let prefixV6 {
            let used = Set(allocations.values.compactMap(\.ipv6))
            let base = prefixV6.address.value & prefixV6.prefix.prefixMask128
            guard let offset = Self.availableOffset(startingAt: nextIPv6Offset, where: { !used.contains(base | UInt128($0)) }) else {
                throw EngineError(.conflict, "network has no available IPv6 addresses")
            }
            nextIPv6Offset = Self.nextOffset(after: offset)
            ipv6Value = base | UInt128(offset)
        } else {
            ipv6Value = nil
        }
        allocations[id] = (ipv4Value, ipv6Value)
        let ipv4 = try CIDRv4(IPv4Address(ipv4Value), prefix: subnet.prefix)
        let ipv6 = try ipv6Value.flatMap { value in
            try prefixV6.map { try CIDRv6(IPv6Address(value), prefix: $0.prefix) }
        }
        return Interface(
            handle: handle,
            ipv4Address: ipv4,
            ipv4Gateway: withDefaultRoute ? ipv4Gateway : nil,
            ipv6Address: ipv6,
            ipv6Gateway: withDefaultRoute ? ipv6Gateway : nil
        )
    }

    mutating func releaseInterface(_ id: String) {
        allocations.removeValue(forKey: id)
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

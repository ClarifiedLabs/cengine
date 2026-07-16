import Foundation
import Darwin

public enum PrivilegedPortProtocol {
    public static let defaultServiceName = "dev.cengine.network-helper"
    public static let testCompatServiceName = "dev.cengine.network-helper.test-compat"
    public static let serviceNameInfoKey = "CEngineNetworkHelperServiceName"
    public static let serviceNameEnvironmentKey = "CENGINE_NETWORK_HELPER_SERVICE_NAME"
    public static var serviceName: String {
        serviceName(
            configured: Bundle.main.object(forInfoDictionaryKey: serviceNameInfoKey) as? String,
            environment: ProcessInfo.processInfo.environment
        )
    }
    public static let version: Int64 = 4
    public static let engineIdentifier = "dev.cengine.engine"
    public static let helperIdentifier = "dev.cengine.network-helper"

    public static func serviceName(environment: [String: String]) -> String {
        serviceName(configured: nil, environment: environment)
    }

    public static func serviceName(configured: String?, environment: [String: String]) -> String {
        if let configured = normalized(environment[serviceNameEnvironmentKey]) { return configured }
        if let configured = normalized(configured) { return configured }
        return defaultServiceName
    }

    private static func normalized(_ value: String?) -> String? {
        guard let configured = value?.trimmingCharacters(in: .whitespacesAndNewlines), !configured.isEmpty else {
            return nil
        }
        return configured
    }
}

public final class RetainedOpaquePointer: @unchecked Sendable {
    private let lock = NSLock()
    private var retainedValue: OpaquePointer?
    private let releaseValue: (OpaquePointer) -> Void

    public init(_ value: OpaquePointer, release: @escaping (OpaquePointer) -> Void) {
        retainedValue = value
        self.releaseValue = release
    }

    public var value: OpaquePointer {
        lock.withLock {
            guard let retainedValue else { preconditionFailure("retained pointer was already released") }
            return retainedValue
        }
    }

    public func release() {
        let value = lock.withLock { () -> OpaquePointer? in
            defer { retainedValue = nil }
            return retainedValue
        }
        if let value { releaseValue(value) }
    }

    deinit { release() }
}

public struct PrivilegedVMNetRequest: Codable, Equatable, Sendable {
    public struct Port: Codable, Equatable, Sendable {
        public let proto: String
        public let externalPort: UInt16
        public let internalAddress: String
        public let internalPort: UInt16

        public init(proto: String, externalPort: UInt16, internalAddress: String, internalPort: UInt16) {
            self.proto = proto
            self.externalPort = externalPort
            self.internalAddress = internalAddress
            self.internalPort = internalPort
        }
    }

    public let id: String
    public let vlan: UInt16
    public let subnet: String
    public let gateway: String
    public let ipv6Subnet: String
    public let internalNetwork: Bool
    public let dhcpEnabled: Bool
    public let ports: [Port]

    public init(
        id: String,
        vlan: UInt16,
        subnet: String,
        gateway: String,
        ipv6Subnet: String,
        internalNetwork: Bool,
        dhcpEnabled: Bool,
        ports: [Port]
    ) {
        self.id = id
        self.vlan = vlan
        self.subnet = subnet
        self.gateway = gateway
        self.ipv6Subnet = ipv6Subnet
        self.internalNetwork = internalNetwork
        self.dhcpEnabled = dhcpEnabled
        self.ports = ports
    }
}

public struct PrivilegedPortRequest: Equatable, Sendable {
    public enum Transport: String, Sendable { case tcp, udp }

    public let address: String
    public let port: UInt16
    public let transport: Transport

    public init(address: String, port: UInt16, transport: Transport) throws {
        guard port > 0, port < 1024 else {
            throw EngineError(.badRequest, "privileged helper only accepts ports 1 through 1023")
        }
        guard let canonical = Self.canonicalized(address) else {
            throw EngineError(.badRequest, "privileged helper requires an IPv4 or IPv6 address")
        }
        guard !Self.isWildcard(canonical) else {
            throw EngineError(.badRequest, "privileged helper requires a specific host address")
        }
        self.address = canonical
        self.port = port
        self.transport = transport
    }

    public static func isWildcard(_ address: String) -> Bool {
        address.isEmpty || address == "0.0.0.0" || address == "::"
    }

    public static func shouldUseHelper(errnoCode: CInt, address: String, port: UInt16) -> Bool {
        (errnoCode == EPERM || errnoCode == EACCES) && port > 0 && port < 1024 && !isWildcard(address)
    }

    /// The RFC 5952 canonical text form of an IPv4/IPv6 literal, or nil for anything else.
    /// The stored address must be canonical so it string-compares equal to addresses
    /// recovered from a bound socket via getnameinfo.
    public static func canonicalized(_ value: String) -> String? {
        var ipv4 = in_addr()
        if value.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            return inet_ntop(AF_INET, &ipv4, &buffer, socklen_t(buffer.count)).map(String.init(cString:))
        }
        var ipv6 = in6_addr()
        guard value.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 else { return nil }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        return inet_ntop(AF_INET6, &ipv6, &buffer, socklen_t(buffer.count)).map(String.init(cString:))
    }
}

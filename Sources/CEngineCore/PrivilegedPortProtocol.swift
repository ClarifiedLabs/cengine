import Foundation
import Darwin

public enum PrivilegedPortProtocol {
    public static let serviceName = "dev.cengine.network-helper"
    public static let version: Int64 = 1
    public static let engineIdentifier = "dev.cengine.engine"
    public static let helperIdentifier = "dev.cengine.network-helper"
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

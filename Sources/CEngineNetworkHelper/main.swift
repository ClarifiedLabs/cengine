import CEngineCore
import Darwin
import Foundation
@preconcurrency import XPC

@main enum CEngineNetworkHelper {
    static func main() {
        guard geteuid() == 0 else {
            FileHandle.standardError.write(Data("cengine-network-helper must run as root\n".utf8))
            exit(1)
        }
        let listener = xpc_connection_create_mach_service(
            PrivilegedPortProtocol.serviceName, nil, UInt64(XPC_CONNECTION_MACH_SERVICE_LISTENER)
        )
        xpc_connection_set_event_handler(listener) { event in
            guard xpc_get_type(event) == XPC_TYPE_CONNECTION else { return }
            let peer: xpc_connection_t = event
            let team = Bundle.main.object(forInfoDictionaryKey: "CEngineTeamIdentifier") as? String ?? ""
            let requirement: String
            if team.isEmpty {
                requirement = "identifier \"\(PrivilegedPortProtocol.engineIdentifier)\""
            } else {
                requirement = "anchor apple generic and identifier \"\(PrivilegedPortProtocol.engineIdentifier)\" and certificate leaf[subject.OU] = \"\(team)\""
            }
            let status = requirement.withCString {
                xpc_connection_set_peer_code_signing_requirement(peer, $0)
            }
            guard status == 0 else { xpc_connection_cancel(peer); return }
            xpc_connection_set_event_handler(peer) { message in handle(message, peer: peer) }
            xpc_connection_activate(peer)
        }
        xpc_connection_activate(listener)
        dispatchMain()
    }

    private static func handle(_ message: xpc_object_t, peer: xpc_connection_t) {
        guard xpc_get_type(message) == XPC_TYPE_DICTIONARY,
              let reply = xpc_dictionary_create_reply(message) else { return }
        do {
            guard xpc_dictionary_get_int64(message, "version") == PrivilegedPortProtocol.version else {
                throw EngineError(.unsupported, "incompatible privileged networking helper protocol")
            }
            guard xpc_dictionary_get_string(message, "operation").map({ String(cString: $0) }) == "bind" else {
                throw EngineError(.unsupported, "privileged networking helper only supports bind")
            }
            guard let addressValue = xpc_dictionary_get_string(message, "address"),
                  let transportValue = xpc_dictionary_get_string(message, "transport"),
                  let port = UInt16(exactly: xpc_dictionary_get_uint64(message, "port")),
                  let transport = PrivilegedPortRequest.Transport(rawValue: String(cString: transportValue)) else {
                throw EngineError(.badRequest, "malformed privileged bind request")
            }
            let request = try PrivilegedPortRequest(
                address: String(cString: addressValue), port: port, transport: transport
            )
            let descriptor = try boundSocket(for: request)
            xpc_dictionary_set_bool(reply, "ok", true)
            xpc_dictionary_set_fd(reply, "socket", descriptor)
            close(descriptor)
        } catch let error as EngineError {
            xpc_dictionary_set_bool(reply, "ok", false)
            error.message.withCString { xpc_dictionary_set_string(reply, "error", $0) }
        } catch {
            xpc_dictionary_set_bool(reply, "ok", false)
            String(describing: error).withCString { xpc_dictionary_set_string(reply, "error", $0) }
        }
        xpc_connection_send_message(peer, reply)
    }

    private static func boundSocket(for request: PrivilegedPortRequest) throws -> CInt {
        let family = request.address.contains(":") ? AF_INET6 : AF_INET
        let kind = request.transport == .tcp ? SOCK_STREAM : SOCK_DGRAM
        let descriptor = socket(family, kind, 0)
        guard descriptor >= 0 else { throw posixError("socket", address: request.address, port: request.port) }
        do {
            var one: CInt = 1
            guard setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout.size(ofValue: one))) == 0 else {
                throw posixError("setsockopt(SO_REUSEADDR)", address: request.address, port: request.port)
            }
            if family == AF_INET6 {
                guard setsockopt(descriptor, IPPROTO_IPV6, IPV6_V6ONLY, &one, socklen_t(MemoryLayout.size(ofValue: one))) == 0 else {
                    throw posixError("setsockopt(IPV6_V6ONLY)", address: request.address, port: request.port)
                }
            }
            let flags = fcntl(descriptor, F_GETFL)
            guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0,
                  fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0 else {
                throw posixError("fcntl", address: request.address, port: request.port)
            }
            if family == AF_INET6 {
                var value = sockaddr_in6()
                value.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
                value.sin6_family = sa_family_t(AF_INET6)
                value.sin6_port = request.port.bigEndian
                guard request.address.withCString({ inet_pton(AF_INET6, $0, &value.sin6_addr) }) == 1 else {
                    throw EngineError(.badRequest, "invalid IPv6 bind address")
                }
                let status = withUnsafePointer(to: &value) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
                    }
                }
                guard status == 0 else { throw posixError("bind", address: request.address, port: request.port) }
            } else {
                var value = sockaddr_in()
                value.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                value.sin_family = sa_family_t(AF_INET)
                value.sin_port = request.port.bigEndian
                guard request.address.withCString({ inet_pton(AF_INET, $0, &value.sin_addr) }) == 1 else {
                    throw EngineError(.badRequest, "invalid IPv4 bind address")
                }
                let status = withUnsafePointer(to: &value) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
                guard status == 0 else { throw posixError("bind", address: request.address, port: request.port) }
            }
            if request.transport == .tcp, listen(descriptor, SOMAXCONN) != 0 {
                throw posixError("listen", address: request.address, port: request.port)
            }
            return descriptor
        } catch {
            close(descriptor)
            throw error
        }
    }

    private static func posixError(_ operation: String, address: String, port: UInt16) -> EngineError {
        let code = errno
        return EngineError(
            .internalError,
            "\(operation) \(address):\(port) failed: \(String(cString: strerror(code))) (errno \(code))"
        )
    }
}

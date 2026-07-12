#if os(macOS)
import CEngineCore
import Darwin
import Foundation
@preconcurrency import XPC

final class PrivilegedPortClient: @unchecked Sendable {
    private let serviceName: String
    private let teamIdentifier: String

    init(serviceName: String = PrivilegedPortProtocol.serviceName, bundle: Bundle = .main) {
        self.serviceName = serviceName
        self.teamIdentifier = bundle.object(forInfoDictionaryKey: "CEngineTeamIdentifier") as? String ?? ""
    }

    func bind(_ request: PrivilegedPortRequest) async throws -> CInt {
        try await withCheckedThrowingContinuation { continuation in
            let connection = xpc_connection_create_mach_service(serviceName, nil, 0)
            let requirement = signingRequirement(identifier: PrivilegedPortProtocol.helperIdentifier)
            let status = requirement.withCString {
                xpc_connection_set_peer_code_signing_requirement(connection, $0)
            }
            guard status == 0 else {
                continuation.resume(throwing: EngineError(
                    .internalError, "could not secure privileged networking helper connection (status \(status))"
                ))
                return
            }
            xpc_connection_set_event_handler(connection) { _ in }
            xpc_connection_activate(connection)

            let message = xpc_dictionary_create(nil, nil, 0)
            xpc_dictionary_set_int64(message, "version", PrivilegedPortProtocol.version)
            xpc_dictionary_set_string(message, "operation", "bind")
            request.address.withCString { xpc_dictionary_set_string(message, "address", $0) }
            xpc_dictionary_set_uint64(message, "port", UInt64(request.port))
            request.transport.rawValue.withCString { xpc_dictionary_set_string(message, "transport", $0) }

            xpc_connection_send_message_with_reply(connection, message, nil) { reply in
                defer { xpc_connection_cancel(connection) }
                guard xpc_get_type(reply) == XPC_TYPE_DICTIONARY else {
                    continuation.resume(throwing: EngineError(
                        .unsupported,
                        "privileged port helper is unavailable; enable Privileged Ports in the cengine app"
                    ))
                    return
                }
                guard xpc_dictionary_get_bool(reply, "ok") else {
                    let message = xpc_dictionary_get_string(reply, "error").map(String.init(cString:))
                        ?? "privileged networking helper rejected the bind request"
                    continuation.resume(throwing: EngineError(.internalError, message))
                    return
                }
                let descriptor = xpc_dictionary_dup_fd(reply, "socket")
                guard descriptor >= 0 else {
                    continuation.resume(throwing: EngineError(.internalError, "privileged networking helper returned no socket"))
                    return
                }
                do {
                    try Self.validate(descriptor, request: request)
                    continuation.resume(returning: descriptor)
                } catch {
                    close(descriptor)
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    private func signingRequirement(identifier: String) -> String {
        guard !teamIdentifier.isEmpty else { return "identifier \"\(identifier)\"" }
        return "anchor apple generic and identifier \"\(identifier)\" and certificate leaf[subject.OU] = \"\(teamIdentifier)\""
    }

    private static func validate(_ descriptor: CInt, request: PrivilegedPortRequest) throws {
        var socketType: CInt = 0
        var typeLength = socklen_t(MemoryLayout<CInt>.size)
        guard getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &socketType, &typeLength) == 0 else {
            throw EngineError(.internalError, "could not validate privileged socket type")
        }
        let expected = request.transport == .tcp ? CInt(SOCK_STREAM) : CInt(SOCK_DGRAM)
        guard socketType == expected else {
            throw EngineError(.internalError, "privileged networking helper returned the wrong socket type")
        }

        var storage = sockaddr_storage()
        var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let result = withUnsafeMutablePointer(to: &storage) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(descriptor, $0, &length) }
        }
        guard result == 0 else { throw EngineError(.internalError, "could not validate privileged socket address") }
        let actual = try numericAddress(storage, length: length)
        guard actual.address == request.address, actual.port == request.port else {
            throw EngineError(
                .internalError,
                "privileged networking helper returned \(actual.address):\(actual.port), expected \(request.address):\(request.port)"
            )
        }
    }

    private static func numericAddress(_ storage: sockaddr_storage, length: socklen_t) throws -> (address: String, port: UInt16) {
        var storage = storage
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        var service = [CChar](repeating: 0, count: Int(NI_MAXSERV))
        let status = withUnsafePointer(to: &storage) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getnameinfo($0, length, &host, socklen_t(host.count), &service, socklen_t(service.count), NI_NUMERICHOST | NI_NUMERICSERV)
            }
        }
        guard status == 0, let port = UInt16(String(cString: service)) else {
            throw EngineError(.internalError, "could not decode privileged socket address")
        }
        return (String(cString: host), port)
    }
}
#endif

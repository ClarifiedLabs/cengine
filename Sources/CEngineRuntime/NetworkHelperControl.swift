#if os(macOS)
import CEngineCore
import Foundation
@preconcurrency import XPC

public struct NetworkHelperStatus: Codable, Equatable, Sendable {
    public let protocolVersion: Int64
    public let buildFingerprint: String
    public let serviceName: String
    public let ownerUID: UInt32
    public let processIdentifier: Int32
}

public enum NetworkHelperControl {
    public static func status() async throws -> NetworkHelperStatus {
        let reply = try await request(operation: "status")
        guard let fingerprint = xpc_dictionary_get_string(reply, "build-fingerprint"),
              let serviceName = xpc_dictionary_get_string(reply, "service-name"),
              let processIdentifier = Int32(exactly: xpc_dictionary_get_int64(reply, "pid")),
              let ownerUID = UInt32(exactly: xpc_dictionary_get_uint64(reply, "owner-uid")) else {
            throw EngineError(.internalError, "privileged networking helper returned malformed status")
        }
        return NetworkHelperStatus(
            protocolVersion: xpc_dictionary_get_int64(reply, "protocol-version"),
            buildFingerprint: String(cString: fingerprint),
            serviceName: String(cString: serviceName),
            ownerUID: ownerUID,
            processIdentifier: processIdentifier
        )
    }

    public static func restart() async throws -> NetworkHelperStatus {
        let previous = try await status()
        _ = try await request(operation: "restart")
        let deadline = ContinuousClock.now + .seconds(30)
        while ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(100))
            if let current = try? await status(),
               current.processIdentifier != previous.processIdentifier {
                return current
            }
        }
        throw EngineError(.internalError, "timed out waiting for networking helper to restart")
    }

    private static func request(operation: String) async throws -> xpc_object_t {
        try await withCheckedThrowingContinuation { continuation in
            let serviceName = PrivilegedPortProtocol.serviceName
            let connection = xpc_connection_create_mach_service(serviceName, nil, 0)
            let team = Bundle.main.object(forInfoDictionaryKey: "CEngineTeamIdentifier") as? String ?? ""
            let identifier = PrivilegedPortProtocol.helperIdentifier
            let requirement = team.isEmpty
                ? "identifier \"\(identifier)\""
                : "anchor apple generic and identifier \"\(identifier)\" and certificate leaf[subject.OU] = \"\(team)\""
            let status = requirement.withCString {
                xpc_connection_set_peer_code_signing_requirement(connection, $0)
            }
            guard status == 0 else {
                continuation.resume(throwing: EngineError(
                    .internalError,
                    "could not secure privileged networking helper connection (status \(status))"
                ))
                return
            }
            xpc_connection_set_event_handler(connection) { _ in }
            xpc_connection_activate(connection)
            let message = xpc_dictionary_create(nil, nil, 0)
            xpc_dictionary_set_int64(message, "version", PrivilegedPortProtocol.version)
            operation.withCString { xpc_dictionary_set_string(message, "operation", $0) }
            if let token = PrivilegedPortProtocol.authenticationToken() {
                token.withCString {
                    xpc_dictionary_set_string(message, "authentication-token", $0)
                }
            }
            xpc_connection_send_message_with_reply(connection, message, nil) { reply in
                defer { xpc_connection_cancel(connection) }
                guard xpc_get_type(reply) == XPC_TYPE_DICTIONARY else {
                    continuation.resume(throwing: EngineError(
                        .unsupported, "privileged networking helper is unavailable"
                    ))
                    return
                }
                guard xpc_dictionary_get_bool(reply, "ok") else {
                    let message = xpc_dictionary_get_string(reply, "error")
                        .map(String.init(cString:))
                        ?? "privileged networking helper rejected \(operation)"
                    continuation.resume(throwing: EngineError(.internalError, message))
                    return
                }
                continuation.resume(returning: reply)
            }
        }
    }
}
#endif

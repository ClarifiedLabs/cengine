#if os(macOS)
import CEngineCore
import Darwin
import Foundation
@preconcurrency import XPC

@_silgen_name("xpc_dictionary_get_audit_token")
nonisolated private func helperStatusAudit(_ message: xpc_object_t, _ token: UnsafeMutablePointer<audit_token_t>)

public struct NetworkHelperStatus: Codable, Equatable, Sendable {
    public let protocolVersion: Int64
    public let buildFingerprint: String
    public let serviceName: String
    public let ownerUID: UInt32
    public let processIdentifier: Int32
    public let capabilities: NetworkHelperCapabilities.Advertisement?
}

public enum NetworkHelperControl {
    /// Authenticated production enrollment snapshot only; never prompts or enrolls.
    public static func storageOwnerStatus() async throws -> StorageOwnerStatus {
        try Task.checkCancellation()
        let policy = try StorageLifecycleNativePolicy.current(role: .engine)
        guard policy.namespace == .production else {
            throw EngineError(.unsupported, "Storage owner status requires the signed production engine")
        }
        let identity = try policy.currentIdentity(role: .engine)
        return try await request(operation: StorageOwnerStatusProtocol.operation, serviceName: policy.serviceName,
            team: identity.teamIdentifier, identifier: policy.helperIdentifier, managed: true) { reply in
                var token = audit_token_t()
                helperStatusAudit(reply, &token)
                try StorageLifecycleRootClient.authenticate(token: token, team: identity.teamIdentifier, policy: policy)
                return try StorageOwnerStatusProtocol.decode(reply)
            }
    }

    public static func status(
        requirement: NetworkHelperCapabilities.Requirement? = nil
    ) async throws -> NetworkHelperStatus {
        try Task.checkCancellation()
        let policy: StorageLifecycleNativePolicy?
        if let requirement {
            policy = try managedPolicy(for: requirement)
        } else {
            policy = nil
        }
        let identity = try policy?.currentIdentity(role: .engine)
        let serviceName = policy?.serviceName ?? PrivilegedPortProtocol.serviceName
        let team = identity?.teamIdentifier
            ?? (Bundle.main.object(forInfoDictionaryKey: "CEngineTeamIdentifier") as? String ?? "")
        let identifier = policy?.helperIdentifier ?? PrivilegedPortProtocol.helperIdentifier
        return try await request(operation: "status", serviceName: serviceName,
                                 team: team, identifier: identifier, managed: policy != nil) { reply in
            var token = audit_token_t()
            if let policy {
                // Native authentication precedes trusting even the status DTO. No
                // supplied capability, environment override, or plist is a proof.
                helperStatusAudit(reply, &token)
                try StorageLifecycleRootClient.authenticate(token: token, team: team, policy: policy)
            }
            let status = try decodeStatus(reply, expectedService: serviceName)
            if let requirement {
                guard status.processIdentifier == Int32(bitPattern: token.val.5),
                      status.ownerUID == geteuid(),
                      let capabilities = status.capabilities else {
                    throw EngineError(.unsupported, "Privileged Helper managed status identity or capabilities are missing or incompatible")
                }
                try NetworkHelperCapabilities.validate(capabilities, for: requirement)
            }
            return status
        }
    }

    // The requirement only narrows rejection policy. The running signature is
    // always the source of the namespace, team and sealed native profile.
    static func managedPolicy(for requirement: NetworkHelperCapabilities.Requirement) throws -> StorageLifecycleNativePolicy {
        let policy: StorageLifecycleNativePolicy
        switch requirement {
        case .lifecycleV2:
            policy = try StorageLifecycleNativePolicy.current(role: .engine)
        case .lifecycleQualification:
            #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
            policy = try StorageLifecycleNativePolicy.qualification(role: .engine)
            #else
            throw EngineError(.unsupported, "Privileged Helper qualification requires a qualification build")
            #endif
        }
        guard policy.namespace == .compatibility else {
            throw EngineError(.unsupported, "Privileged Helper managed status requires the signed compatibility namespace")
        }
        return policy
    }

    /// Shape validation only, never a native authentication or authorization seam.
    static func decodeStatus(_ reply: xpc_object_t, expectedService: String) throws -> NetworkHelperStatus {
        try checkSuccess(reply)
        var keys = Set<String>()
        xpc_dictionary_apply(reply) { key, _ in keys.insert(String(cString: key)); return true }
        let required: Set<String> = ["ok", "protocol-version", "build-fingerprint", "service-name", "pid", "owner-uid"]
        guard keys == required || keys == required.union(["capabilities"]) else { throw malformed() }
        for (key, type) in [("protocol-version", XPC_TYPE_INT64), ("build-fingerprint", XPC_TYPE_STRING),
                            ("service-name", XPC_TYPE_STRING), ("pid", XPC_TYPE_INT64), ("owner-uid", XPC_TYPE_UINT64)] {
            guard let value = xpc_dictionary_get_value(reply, key), xpc_get_type(value) == type else { throw malformed() }
        }
        guard let fingerprint = xpc_dictionary_get_string(reply, "build-fingerprint"),
              let service = xpc_dictionary_get_string(reply, "service-name"),
              String(cString: service) == expectedService,
              let pid = Int32(exactly: xpc_dictionary_get_int64(reply, "pid")), pid > 0,
              let owner = UInt32(exactly: xpc_dictionary_get_uint64(reply, "owner-uid")) else { throw malformed() }
        let version = xpc_dictionary_get_int64(reply, "protocol-version")
        guard PrivilegedPortProtocol.isCompatible(version: version) else {
            throw EngineError(.unsupported, "Privileged Helper protocol version \(version) is incompatible with client version \(PrivilegedPortProtocol.version); update the Privileged Helper")
        }
        let capabilities: NetworkHelperCapabilities.Advertisement?
        if let value = xpc_dictionary_get_value(reply, "capabilities") {
            var count = 0
            guard xpc_get_type(value) == XPC_TYPE_DATA,
                  let bytes = xpc_dictionary_get_data(reply, "capabilities", &count),
                  count > 0, count <= NetworkHelperCapabilities.maximumBytes else { throw malformed() }
            capabilities = try NetworkHelperCapabilities.decode(Data(bytes: bytes, count: count))
        } else {
            capabilities = nil
        }
        return NetworkHelperStatus(protocolVersion: version, buildFingerprint: String(cString: fingerprint),
            serviceName: String(cString: service), ownerUID: owner, processIdentifier: pid, capabilities: capabilities)
    }

    public static func restart() async throws -> NetworkHelperStatus {
        let previous = try await status()
        let team = Bundle.main.object(forInfoDictionaryKey: "CEngineTeamIdentifier") as? String ?? ""
        let _: Bool = try await request(operation: "restart", serviceName: PrivilegedPortProtocol.serviceName,
            team: team, identifier: PrivilegedPortProtocol.helperIdentifier, managed: false) { reply in
                try checkSuccess(reply)
                return true
            }
        let deadline = ContinuousClock.now + .seconds(30)
        while ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(100))
            if let current = try? await status(), current.processIdentifier != previous.processIdentifier { return current }
        }
        throw EngineError(.internalError, "timed out waiting for Privileged Helper to restart")
    }

    private static func malformed() -> EngineError {
        EngineError(.internalError, "Privileged Helper returned malformed status")
    }

    private static func checkSuccess(_ reply: xpc_object_t) throws {
        guard xpc_get_type(reply) == XPC_TYPE_DICTIONARY,
              let ok = xpc_dictionary_get_value(reply, "ok"), xpc_get_type(ok) == XPC_TYPE_BOOL else { throw malformed() }
        guard xpc_bool_get_value(ok) else {
            throw EngineError(.internalError, "Privileged Helper rejected the request")
        }
    }

    private static func request<Value: Sendable>(operation: String, serviceName: String, team: String,
        identifier: String, managed: Bool,
        decode: @escaping @Sendable (xpc_object_t) throws -> Value) async throws -> Value {
        let pending = NetworkHelperRequestState<Value>()
        let signingRequirement = managed
            ? try SignedStorageIdentity.developerIDRequirement(identifiers: [identifier], team: team)
            : (team.isEmpty ? "identifier \"\(identifier)\""
                : "anchor apple generic and identifier \"\(identifier)\" and certificate leaf[subject.OU] = \"\(team)\"")
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                pending.start(continuation) {
                    let queue = DispatchQueue(label: "dev.cengine.helper.status")
                    let connection = xpc_connection_create_mach_service(serviceName, queue,
                        managed ? UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED) : 0)
                    let result = signingRequirement.withCString {
                        xpc_connection_set_peer_code_signing_requirement(connection, $0)
                    }
                    guard result == 0 else {
                        xpc_connection_cancel(connection)
                        throw EngineError(.internalError, "could not secure Privileged Helper connection (status \(result))")
                    }
                    // Authentication may block in Security; the deadline must not
                    // share its serial callback queue.
                    let timer = DispatchSource.makeTimerSource(queue: .global(qos: .userInitiated))
                    timer.schedule(deadline: .now() + .seconds(5))
                    timer.setEventHandler { [weak pending] in
                        pending?.finish(.failure(EngineError(.serviceUnavailable, "Privileged Helper status timed out")))
                    }
                    xpc_connection_set_event_handler(connection) { [weak pending] event in
                        if xpc_get_type(event) == XPC_TYPE_ERROR {
                            pending?.finish(.failure(EngineError(.unsupported, "Privileged Helper is unavailable")))
                        }
                    }
                    let message = xpc_dictionary_create(nil, nil, 0)
                    let ownerStatus = operation == StorageOwnerStatusProtocol.operation
                    xpc_dictionary_set_int64(message, "version", ownerStatus ? StorageOwnerStatusProtocol.version : PrivilegedPortProtocol.version)
                    operation.withCString { xpc_dictionary_set_string(message, "operation", $0) }
                    if !ownerStatus, let token = PrivilegedPortProtocol.authenticationToken() {
                        token.withCString { xpc_dictionary_set_string(message, "authentication-token", $0) }
                    }
                    timer.resume()
                    xpc_connection_activate(connection)
                    xpc_connection_send_message_with_reply(connection, message, queue) { [weak pending] reply in
                        guard let pending else { return }
                        guard xpc_get_type(reply) == XPC_TYPE_DICTIONARY else {
                            pending.finish(.failure(EngineError(.unsupported, "Privileged Helper is unavailable")))
                            return
                        }
                        pending.finish(Result { try decode(reply) })
                    }
                    return {
                        timer.cancel()
                        xpc_connection_cancel(connection)
                    }
                }
            }
        } onCancel: {
            pending.finish(.failure(CancellationError()))
        }
    }
}

/// One completion owns cleanup. It also records cancellation before continuation
/// installation. No retained connection/callback cycle or unbounded waiter.
nonisolated final class NetworkHelperRequestState<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var terminal: Result<Value, any Error>?
    private var continuation: CheckedContinuation<Value, any Error>?
    private var cleanup: (() -> Void)?

    func start(_ continuation: CheckedContinuation<Value, any Error>, setup: () throws -> (() -> Void)) {
        lock.lock()
        if let terminal {
            lock.unlock()
            continuation.resume(with: terminal)
            return
        }
        self.continuation = continuation
        do {
            cleanup = try setup()
            lock.unlock()
        } catch {
            lock.unlock()
            finish(.failure(error))
        }
    }

    func finish(_ result: Result<Value, any Error>) {
        lock.lock()
        guard terminal == nil else { lock.unlock(); return }
        terminal = result
        let continuation = continuation, cleanup = cleanup
        self.continuation = nil
        self.cleanup = nil
        lock.unlock()
        cleanup?()
        continuation?.resume(with: result)
    }
}
#endif

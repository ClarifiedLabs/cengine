#if os(macOS)
import CEngineCore
import Darwin
import Foundation
@preconcurrency import XPC

@_silgen_name("xpc_dictionary_get_audit_token")
nonisolated private func adoptionRootReplyAudit(_ message: xpc_object_t, _ token: UnsafeMutablePointer<audit_token_t>)

nonisolated extension StorageLifecycleRootClient {
    /// Call off-main after bindScope on this daemon. ROOT's scope binding is to
    /// the native process, not an XPC connection. No scope selectors or retries.
    /// Returned values (including service results) are not runtime capabilities.
    public func adoptionRequest(_ request: StorageLifecycleAdoptionRootProtocol.Request,
                                storeLock: CanonicalDataStoreLock, timeout: TimeInterval = 30) throws -> StorageLifecycleAdoptionRootProtocol.Reply {
        guard !Thread.isMainThread, timeout.isFinite, timeout > 0, timeout <= 30 else { throw Failure(.invalidRequest) }
        let deadline = DispatchTime.now() + timeout
        guard try policy.currentIdentity(role: .engine).teamIdentifier == installedTeam else { throw Failure(.unauthorized) }
        return try storeLock.withLeaseDescriptors { path, root, file in
            let message = try Self.adoptionMessage(request, pathFD: path, rootFD: root, lockFD: file)
            let queue = DispatchQueue(label: "dev.cengine.lifecycle.adoption-client")
            let connection = xpc_connection_create_mach_service(policy.serviceName, queue,
                UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED))
            let pending = AdoptionPending()
            xpc_connection_set_event_handler(connection) { event in
                if xpc_get_type(event) == XPC_TYPE_ERROR { pending.finish(.failure(Failure(.unavailable))) }
            }
            xpc_connection_activate(connection)
            defer { xpc_connection_cancel(connection) }
            let team = installedTeam, policy = policy
            xpc_connection_send_message_with_reply(connection, message, queue) { response in
                pending.finish(Result {
                    guard xpc_get_type(response) == XPC_TYPE_DICTIONARY else { throw Failure(.unavailable) }
                    var token = audit_token_t(); adoptionRootReplyAudit(response, &token)
                    try Self.authenticate(token: token, team: team, policy: policy)
                    return try Self.decodeResponse(response)
                })
            }
            guard pending.ready.wait(timeout: deadline) == .success, DispatchTime.now() < deadline,
                  let result = pending.lock.withLock({ pending.result }) else { throw Failure(.unavailable) }
            return try Self.decodeAdoptionResponse(result.get(), for: request)
        }
    }

    /// Shape-only seam. The real path borrows only retained lock descriptions;
    /// ROOT validates their kinds, identities, lock state and bound native owner.
    static func adoptionMessage(_ request: StorageLifecycleAdoptionRootProtocol.Request,
                                pathFD: Int32, rootFD: Int32, lockFD: Int32) throws -> xpc_object_t {
        for fd in [pathFD, rootFD, lockFD] {
            guard fd >= 0, fcntl(fd, F_GETFD) >= 0 else { throw Failure(.invalidRequest) }
        }
        let bytes = try StorageLifecycleAdoptionRootProtocol.encode(request)
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(message, "operation", StorageLifecycleAdoptionRootProtocol.xpcOperation)
        bytes.withUnsafeBytes { xpc_dictionary_set_data(message, "request", $0.baseAddress, $0.count) }
        xpc_dictionary_set_fd(message, "path-lock", pathFD)
        xpc_dictionary_set_fd(message, "store-root", rootFD)
        xpc_dictionary_set_fd(message, "daemon-lock", lockFD)
        return message
    }

    /// Correlation/error decoding only, always after actual native helper auth.
    static func decodeAdoptionResponse(_ bytes: Data, for request: StorageLifecycleAdoptionRootProtocol.Request) throws
        -> StorageLifecycleAdoptionRootProtocol.Reply {
        let reply = try StorageLifecycleAdoptionRootProtocol.decodeReply(bytes, for: request)
        if case .failure(let code) = reply.body { throw Failure(code) }
        return reply
    }
}

nonisolated private final class AdoptionPending: @unchecked Sendable {
    let lock = NSLock()
    let ready = DispatchSemaphore(value: 0)
    var result: Result<Data, any Error>?
    func finish(_ result: Result<Data, any Error>) {
        lock.withLock { if self.result == nil { self.result = result; ready.signal() } }
    }
}
#endif

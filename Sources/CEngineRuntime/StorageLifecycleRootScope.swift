#if os(macOS)
import CEngineCore
import Darwin
import Foundation
@preconcurrency import XPC

@_silgen_name("xpc_dictionary_get_audit_token")
nonisolated private func scopeRootReplyAudit(_ message: xpc_object_t, _ token: UnsafeMutablePointer<audit_token_t>)

nonisolated extension StorageLifecycleRootClient {
    /// Bind this actual daemon process to `store`/root before ROOT requests. The
    /// helper selects the journal root from its own namespace policy. Idempotent for
    /// the same daemon/root; binding survives connections, not helper restart.
    /// No retries, formatting, adoption, path, implementation, or policy selector.
    public func bindScope(store: StorageIdentity.StoreID,
                          rootFD: Int32, timeout: TimeInterval = 30) throws {
        guard !Thread.isMainThread, timeout.isFinite, timeout > 0, timeout <= 30 else { throw Failure(.invalidRequest) }
        let message = try Self.scopeMessage(store: store, rootFD: rootFD)
        _ = try policy.currentIdentity(role: .engine)
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        let queue = DispatchQueue(label: "dev.cengine.lifecycle.scope-client")
        let connection = xpc_connection_create_mach_service(policy.serviceName, queue,
            UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED))
        let pending = ScopeBindPending()
        xpc_connection_set_event_handler(connection) { event in
            if xpc_get_type(event) == XPC_TYPE_ERROR { pending.finish(.failure(Failure(.unavailable))) }
        }
        xpc_connection_activate(connection)
        defer { xpc_connection_cancel(connection) }
        let policy = policy, team = installedTeam
        xpc_connection_send_message_with_reply(connection, message, queue) { response in
            pending.finish(Result {
                guard xpc_get_type(response) == XPC_TYPE_DICTIONARY else { throw Failure(.unavailable) }
                var token = audit_token_t(); scopeRootReplyAudit(response, &token)
                try Self.authenticate(token: token, team: team, policy: policy)
                var keys = Set<String>()
                xpc_dictionary_apply(response) { key, _ in keys.insert(String(cString: key)); return true }
                guard keys == ["ok"], let ok = xpc_dictionary_get_value(response, "ok"),
                      xpc_get_type(ok) == XPC_TYPE_BOOL, xpc_bool_get_value(ok) else { throw Failure(.unauthorized) }
            })
        }
        let remaining = deadline - ProcessInfo.processInfo.systemUptime
        guard remaining > 0, pending.ready.wait(timeout: .now() + remaining) == .success,
              ProcessInfo.processInfo.systemUptime < deadline,
              let result = pending.lock.withLock({ pending.result }) else { throw Failure(.unavailable) }
        try result.get()
    }

    /// Closed three-key envelope: operation, canonical store DTO, root descriptor.
    static func scopeMessage(store: StorageIdentity.StoreID, rootFD: Int32) throws -> xpc_object_t {
        guard rootFD >= 0, fcntl(rootFD, F_GETFD) >= 0 else { throw Failure(.invalidRequest) }
        // Scope pins outlive the daemon. Reopen the held directory itself (never
        // its pathname) so XPC cannot carry the daemon's flock open description
        // into the helper's persistent scope. Dup/F_DUPFD would retain that lease
        // after daemon death and prevent authenticated restart or owned cleanup.
        let pin = openat(rootFD, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard pin >= 0 else { throw Failure(.invalidRequest) }
        defer { close(pin) }
        var held = stat(), reopened = stat()
        guard fstat(rootFD, &held) == 0, fstat(pin, &reopened) == 0,
              held.st_dev == reopened.st_dev, held.st_ino == reopened.st_ino else { throw Failure(.invalidRequest) }
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(message, "operation", StorageLifecycleScopeProtocol.xpcOperation)
        let bytes = try StorageLifecycleScopeProtocol.encode(.init(store: store))
        bytes.withUnsafeBytes { xpc_dictionary_set_data(message, "request", $0.baseAddress, $0.count) }
        xpc_dictionary_set_fd(message, "store-root", pin)
        return message
    }

    #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
    /// Qualification driver entry point; requires the signed qualification profile.
    public func bindQualificationScope(store: StorageIdentity.StoreID,
                                       rootFD: Int32, timeout: TimeInterval = 30) throws {
        guard policy.isQualification else { throw Failure(.invalidRequest) }
        try bindScope(store: store, rootFD: rootFD, timeout: timeout)
    }
    #endif
}

nonisolated private final class ScopeBindPending: @unchecked Sendable {
    let lock = NSLock()
    let ready = DispatchSemaphore(value: 0)
    var result: Result<Void, any Error>?
    func finish(_ result: Result<Void, any Error>) {
        lock.withLock { if self.result == nil { self.result = result; ready.signal() } }
    }
}
#endif

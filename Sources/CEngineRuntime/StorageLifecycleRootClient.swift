#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Security
@preconcurrency import XPC

@_silgen_name("xpc_dictionary_get_audit_token")
nonisolated private func lifecycleRootReplyAudit(_ message: xpc_object_t, _ token: UnsafeMutablePointer<audit_token_t>)

/// Fixed-policy root-helper transport. One attempt, original IDs/descriptors;
/// uncertainty never implies rollback, process death or permission to reprovision.
nonisolated public final class StorageLifecycleRootClient: @unchecked Sendable {
    public typealias Wire = StorageLifecycleRootProtocol
    public struct Failure: LocalizedError, Sendable {
        public let code: StorageIdentity.ErrorCode
        public init(_ code: StorageIdentity.ErrorCode) { self.code = code }
        public var errorDescription: String? { code.rawValue }
    }
    #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
    /// Local delivery uncertainty, never a ROOT failure or a rollback signal.
    public struct QualificationCompletionReplyLost: Error, Sendable {}
    /// Pure one-shot bookkeeping, not a receipt or native identity test seam.
    nonisolated struct QualificationCompletionLossState {
        private var armed = false
        private var attempted = false
        mutating func arm() throws {
            guard !attempted else { throw Failure(.invalidRequest) }
            attempted = true; armed = true
        }
        mutating func consume() -> Bool {
            guard armed else { return false }
            armed = false
            return true
        }
    }
    private let qualificationLock = NSLock()
    private var qualificationCompletionLoss = QualificationCompletionLossState()
    private var qualificationDiscardedReceipt: StorageLifecycleProtocol.Receipt?
    /// Diagnostic public DTO only. No setter or supplied-receipt injection path.
    public var qualificationDiscardedCompletion: StorageLifecycleProtocol.Receipt? {
        qualificationLock.withLock { qualificationDiscardedReceipt }
    }
    /// Local, one-shot arming. No ROOT RPC, rollback, or automatic replay.
    public func armQualificationCompletionLoss() throws {
        guard policy.isQualification else { throw Failure(.unauthorized) }
        let identity = try policy.currentIdentity(role: .engine)
        guard identity.teamIdentifier == team else { throw Failure(.unauthorized) }
        try qualificationLock.withLock { try qualificationCompletionLoss.arm() }
    }
    #endif
    private let team: String
    var installedTeam: String { team }
    public let policy: StorageLifecycleNativePolicy
    public init(installedHelperTeam: String, policy: StorageLifecycleNativePolicy = .production) throws {
        _ = try SignedStorageIdentity.developerIDRequirement(
            identifiers: [policy.helperIdentifier], team: installedHelperTeam)
        team = installedHelperTeam; self.policy = policy
    }
    nonisolated private final class Pending: @unchecked Sendable {
        let lock = NSLock()
        let ready = DispatchSemaphore(value: 0)
        var result: Result<Data, any Error>?
        func finish(_ value: Result<Data, any Error>) {
            lock.withLock { if result == nil { result = value; ready.signal() } }
        }
    }
    /// Must run off main. Dedicated callbacks never use the blocked caller queue.
    /// 120 seconds budgets nested child + fresh/service proofs; no automatic retries.
    public func request(_ request: Wire.Request, rootFD: Int32 = -1, backingFD: Int32 = -1,
                        timeout: TimeInterval = 120) throws -> Wire.Reply {
        guard !Thread.isMainThread, timeout.isFinite, timeout > 0, timeout <= 120 else { throw Failure(.invalidRequest) }
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        let message = try Self.message(request, rootFD: rootFD, backingFD: backingFD)
        let queue = DispatchQueue(label: "dev.cengine.storage-lifecycle.root-client-replies")
        let connection = xpc_connection_create_mach_service(policy.serviceName,
            queue, UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED))
        let pending = Pending()
        xpc_connection_set_event_handler(connection) { event in
            if xpc_get_type(event) == XPC_TYPE_ERROR { pending.finish(.failure(Failure(.unavailable))) }
        }
        xpc_connection_resume(connection)
        defer { xpc_connection_cancel(connection) }
        let team = team, policy = policy
        xpc_connection_send_message_with_reply(connection, message, queue) { response in
            pending.finish(Result {
                guard xpc_get_type(response) == XPC_TYPE_DICTIONARY else { throw Failure(.unavailable) }
                try Self.authenticate(response, team: team, policy: policy)
                return try Self.decodeResponse(response)
            })
        }
        let remaining = deadline - ProcessInfo.processInfo.systemUptime
        guard remaining > 0, pending.ready.wait(timeout: .now() + remaining) == .success,
              ProcessInfo.processInfo.systemUptime < deadline,
              let result = pending.lock.withLock({ pending.result }) else { throw Failure(.unavailable) }
        let reply = try Wire.decodeReply(result.get(), for: request)
        #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
        // The real native reply was authenticated, decoded and correlated above.
        // Only its public completion may be discarded; the next request must make
        // a new authenticated exchange and obtain ROOT's actual live proof again.
        if case .completed(let receipt) = reply.body {
            let discarded = qualificationLock.withLock {
                guard qualificationCompletionLoss.consume() else { return false }
                qualificationDiscardedReceipt = receipt
                return true
            }
            if discarded { throw QualificationCompletionReplyLost() }
        }
        #endif
        return reply
    }
    public func rootPublicKey(timeout: TimeInterval = 120) throws -> StorageIdentity.RootPublicKey {
        let request = try Wire.Request(requestID: .init(UUID().uuidString.lowercased()), body: .rootPublicKey)
        switch try self.request(request, timeout: timeout).body {
        case .rootPublicKey(let key): return key
        case .failure(let code): throw Failure(code)
        default: throw Failure(.invalidRequest)
        }
    }
    static func message(_ request: Wire.Request, rootFD: Int32, backingFD: Int32) throws -> xpc_object_t {
        guard (rootFD >= 0) == (backingFD >= 0), request.requiresDescriptors == (rootFD >= 0) else { throw Failure(.invalidRequest) }
        if rootFD >= 0 {
            guard fcntl(rootFD, F_GETFD) >= 0, fcntl(backingFD, F_GETFD) >= 0 else { throw Failure(.invalidRequest) }
        }
        let bytes = try Wire.encode(request), message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(message, "operation", Wire.xpcOperation)
        bytes.withUnsafeBytes { xpc_dictionary_set_data(message, "request", $0.baseAddress, $0.count) }
        if rootFD >= 0 { xpc_dictionary_set_fd(message, "store-root", rootFD); xpc_dictionary_set_fd(message, "store-backing", backingFD) }
        return message
    }
    /// Shape only, never authentication. Called only after native ROOT pinning.
    static func decodeResponse(_ message: xpc_object_t) throws -> Data {
        guard xpc_get_type(message) == XPC_TYPE_DICTIONARY else { throw Failure(.invalidRequest) }
        var keys = Set<String>()
        xpc_dictionary_apply(message) { key, _ in keys.insert(String(cString: key)); return true }
        var count = 0
        guard keys == ["ok", "reply"], let ok = xpc_dictionary_get_value(message, "ok"),
              xpc_get_type(ok) == XPC_TYPE_BOOL, xpc_bool_get_value(ok),
              let bytes = xpc_dictionary_get_data(message, "reply", &count), count > 0,
              count <= Wire.maximumPayloadBytes else { throw Failure(.invalidRequest) }
        return Data(bytes: bytes, count: count)
    }
    private static func authenticate(_ message: xpc_object_t, team: String, policy: StorageLifecycleNativePolicy) throws {
        var token = audit_token_t(); lifecycleRootReplyAudit(message, &token)
        try authenticate(token: token, team: team, policy: policy)
    }
    /// Kernel audit token seam for unsigned rejection tests, not a peer assertion API.
    static func authenticate(token: audit_token_t, team: String, policy: StorageLifecycleNativePolicy = .production) throws {
        let pid = Int32(bitPattern: token.val.5)
        guard pid > 0, token.val.1 == 0, token.val.3 == 0 else { throw Failure(.unauthorized) }
        func identity() -> Data? { RuntimeProcessIdentity.processIdentity(pid: pid, pidVersion: token.val.7) }
        guard let before = identity() else { throw Failure(.unauthorized) }
        let audit = withUnsafeBytes(of: token) { Data($0) }
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: audit] as CFDictionary, [], &code) == errSecSuccess,
              let code else { throw Failure(.unauthorized) }
        try policy.validatePeer(code, pid: pid, role: .helper, expectedTeam: team)
        guard identity() == before else { throw Failure(.unauthorized) }
    }
}
#endif

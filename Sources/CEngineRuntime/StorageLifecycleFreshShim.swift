#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Security
import Synchronization
@preconcurrency import XPC

@_silgen_name("xpc_dictionary_get_audit_token")
private func freshShimMessageAudit(_ message: xpc_object_t, _ token: UnsafeMutablePointer<audit_token_t>)

/// Answers fresh disk-binding challenges after the storage shim verifies initialization.
/// The pinned ROOT key must come from trusted private boot configuration, never
/// public VM metadata. This process is the production dev.cengine.engine shim.
/// Construct and start off-main; Security and disk checks run on a serial worker.
final class StorageLifecycleFreshShim: @unchecked Sendable {
    typealias Wire = StorageLifecycleFreshProtocol
    enum Failure: Error { case unauthorized, unavailable, invalidMessage }
    struct Processes: Equatable {
        let shimAudit: Data
        let daemonAudit: Data
        let shimIdentity: Data
        let daemonIdentity: Data
        var shimUniqueID: UInt64 { shimIdentity.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 16, as: UInt64.self) } }
        var daemonUniqueID: UInt64 { daemonIdentity.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 16, as: UInt64.self) } }
    }
    struct RootPeer: Equatable {
        let audit: Data
        let identity: Data
    }
    /// Independent of the worker: a blocked Security/disk call cannot prevent
    /// revocation. Never hold this lock across Security, filesystem I/O or waits.
    private final class Gate: @unchecked Sendable {
        let lock = NSLock()
        let ready = DispatchSemaphore(value: 0)
        var closed = false
        var started = false
        var acknowledged = false
        var connection: xpc_connection_t?
        func close() {
            let peer: xpc_connection_t? = lock.withLock {
                closed = true
                let peer = connection; connection = nil
                return peer
            }
            if let peer { xpc_connection_cancel(peer) }
            ready.signal()
        }
        func whileOpen(_ body: () throws -> Void) throws {
            try lock.withLock {
                guard !closed else { throw Failure.unavailable }
                try body()
            }
        }
        func acknowledge() throws {
            try whileOpen { acknowledged = true }
            ready.signal()
        }
    }
    private let capability: RawDiskBootTransaction.FreshStorageInitialization
    private let parent: FileHandle
    private let processes: Processes
    private let team: String
    private let policy: StorageLifecycleNativePolicy
    let greeting: Wire.Greeting
    private let gate = Gate()
    private let worker = DispatchQueue(label: "dev.cengine.storage-fresh-shim.worker")
    private let events = DispatchQueue(label: "dev.cengine.storage-fresh-shim.events")
    private var rootPeer: RootPeer? // Worker only; first native sender pins the channel.

    init(capability: RawDiskBootTransaction.FreshStorageInitialization,
         storeID: StorageIdentity.StoreID,
         pinnedRoot: StorageIdentity.RootPublicKey,
         parentBorrowedFD: Int32, policy: StorageLifecycleNativePolicy = .production) throws {
        guard !Thread.isMainThread else { throw Failure.unavailable }
        let descriptor = fcntl(parentBorrowedFD, F_DUPFD_CLOEXEC, 0)
        guard descriptor >= 0 else { throw Failure.unauthorized }
        let parent = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        let (observed, team) = try Self.authenticatedParent(parentFD: descriptor, policy: policy)
        self.capability = capability; self.parent = parent; processes = observed
        self.team = team; self.policy = policy
        greeting = try capability.greeting(storeID: storeID, root: pinnedRoot,
            channelID: UUID().uuidString.lowercased(), daemonUniqueID: observed.daemonUniqueID)
    }

    /// Authenticates the parent before the storage shim starts a VM or mutates a disk.
    /// Native socket/parent/signature evidence only; no supplied process DTO.
    static func authenticatedParent(parentFD: Int32, policy: StorageLifecycleNativePolicy = .production) throws -> (Processes, String) {
        guard !Thread.isMainThread else { throw Failure.unavailable }
        let identity = try policy.currentIdentity(role: .engine)
        let observed = try observe(parentFD: parentFD)
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: observed.daemonAudit] as CFDictionary,
            [], &code) == errSecSuccess, let code else { throw Failure.unauthorized }
        try policy.validatePeer(code, pid: getppid(), role: .engine, expectedTeam: identity.teamIdentifier)
        guard try observe(parentFD: parentFD) == observed else { throw Failure.unauthorized }
        return (observed, identity.teamIdentifier)
    }

    /// One channel only. A close, failed acknowledgement or timeout is terminal;
    /// re-instantiating cannot reset the underlying boot's first-claim freeze.
    func start() throws {
        guard !Thread.isMainThread else { throw Failure.unavailable }
        let gate = self.gate
        let connection = xpc_connection_create_mach_service(policy.serviceName,
            events, UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED))
        do {
            try gate.whileOpen {
                guard !gate.started else { throw Failure.unavailable }
                gate.started = true; gate.connection = connection
            }
        } catch { xpc_connection_cancel(connection); throw error }
        xpc_connection_set_event_handler(connection) { [weak self] message in
            guard xpc_get_type(message) == XPC_TYPE_DICTIONARY, let self else { gate.close(); return }
            let settled = Mutex(false)
            self.events.asyncAfter(deadline: .now() + 5) {
                if !settled.withLock({ $0 }) { gate.close() }
            }
            self.worker.async {
                defer { settled.withLock { $0 = true } }
                do { try self.respond(message, connection: connection) }
                catch { gate.close() }
            }
        }
        xpc_connection_resume(connection)
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_int64(message, "version", PrivilegedPortProtocol.version)
        xpc_dictionary_set_string(message, "role", "storage-shim")
        xpc_dictionary_set_string(message, "operation", "storage-lifecycle-fresh-shim")
        do {
            let bytes = try StorageLifecycleProtocol.encode(greeting)
            bytes.withUnsafeBytes { xpc_dictionary_set_data(message, "request", $0.baseAddress, $0.count) }
            try gate.whileOpen {
                xpc_connection_send_message_with_reply(connection, message, events) { [weak self] reply in
                    guard let self else { gate.close(); return }
                    self.worker.async {
                        do {
                            try self.authenticate(reply)
                            guard xpc_dictionary_get_bool(reply, "ok") else { throw Failure.invalidMessage }
                            try gate.acknowledge()
                        } catch { gate.close() }
                    }
                }
            }
            guard gate.ready.wait(timeout: .now() + 5) == .success,
                  gate.lock.withLock({ gate.acknowledged && !gate.closed }) else { throw Failure.unavailable }
        } catch { close(); throw error }
    }
    func close() { gate.close() }
    deinit { gate.close() }

    private func authenticate(_ message: xpc_object_t) throws {
        try gate.whileOpen {}
        let peer = try Self.authenticateRoot(message, team: team, policy: policy)
        if let rootPeer { guard rootPeer == peer else { throw Failure.unauthorized } }
        else { rootPeer = peer }
        guard try Self.observe(parentFD: parent.fileDescriptor) == processes else { throw Failure.unauthorized }
        try gate.whileOpen {}
    }
    private func respond(_ message: xpc_object_t, connection: xpc_connection_t) throws {
        // MUST precede decoding or invoking the unsigned capability component.
        try authenticate(message)
        guard let operation = xpc_dictionary_get_string(message, "operation"),
              String(cString: operation) == "storage-lifecycle-fresh-challenge" else { throw Failure.invalidMessage }
        var count = 0
        guard let bytes = xpc_dictionary_get_data(message, "request", &count), count > 0,
              count <= StorageLifecycleProtocol.maximumPayloadBytes else { throw Failure.invalidMessage }
        let challenge = try Wire.decodeChallenge(Data(bytes: bytes, count: count))
        guard challenge.greeting == greeting, challenge.shimAudit == processes.shimAudit,
              challenge.daemonAudit == processes.daemonAudit,
              challenge.shimUniqueID == processes.shimUniqueID else { throw Failure.unauthorized }
        let response = try capability.reply(to: challenge)
        // Recheck native identities after disk I/O as well as before it.
        try authenticate(message)
        guard challenge.isFresh(at: UInt64(Date().timeIntervalSince1970 * 1000)),
              let reply = xpc_dictionary_create_reply(message) else { throw Failure.invalidMessage }
        let encoded = try StorageLifecycleProtocol.encode(response)
        xpc_dictionary_set_bool(reply, "ok", true)
        encoded.withUnsafeBytes { xpc_dictionary_set_data(reply, "reply", $0.baseAddress, $0.count) }
        try gate.whileOpen { xpc_connection_send_message(connection, reply) }
    }

    /// Only actual Mach messages have a sender audit trailer; a locally created
    /// dictionary (even with plausible DTO fields) fails this native boundary.
    static func authenticateRoot(_ message: xpc_object_t, team: String, policy: StorageLifecycleNativePolicy = .production) throws -> RootPeer {
        guard xpc_get_type(message) == XPC_TYPE_DICTIONARY else { throw Failure.unauthorized }
        var token = audit_token_t()
        freshShimMessageAudit(message, &token)
        let pid = Int32(bitPattern: token.val.5)
        guard token.val.1 == 0, token.val.3 == 0,
              let before = RuntimeProcessIdentity.processIdentity(pid: pid, pidVersion: token.val.7) else {
            throw Failure.unauthorized
        }
        let audit = withUnsafeBytes(of: token) { Data($0) }
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: audit] as CFDictionary,
            [], &code) == errSecSuccess, let code else { throw Failure.unauthorized }
        try policy.validatePeer(code, pid: pid, role: .helper, expectedTeam: team)
        guard RuntimeProcessIdentity.processIdentity(pid: pid, pidVersion: token.val.7) == before else {
            throw Failure.unauthorized
        }
        return RootPeer(audit: audit, identity: before)
    }

    /// Audit values and unique/parent identities are observed from the kernel,
    /// never accepted from daemon JSON. The socket must genuinely name our parent.
    static func observe(parentFD: Int32) throws -> Processes {
        let pid = getpid(), parentPID = getppid()
        var info = stat(), kind: Int32 = 0
        var kindSize = socklen_t(MemoryLayout<Int32>.size)
        var address = sockaddr_un(), addressSize = socklen_t(MemoryLayout<sockaddr_un>.size)
        var peer = audit_token_t(), own = audit_token_t()
        var peerSize = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getuid() == geteuid(), fstat(parentFD, &info) == 0,
              info.st_mode & S_IFMT == S_IFSOCK, info.st_uid == geteuid(),
              getsockopt(parentFD, SOL_SOCKET, SO_TYPE, &kind, &kindSize) == 0, kind == SOCK_STREAM,
              withUnsafeMutablePointer(to: &address, { pointer in
                  pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getpeername(parentFD, $0, &addressSize) }
              }) == 0, address.sun_family == AF_UNIX,
              getsockopt(parentFD, SOL_LOCAL, LOCAL_PEERTOKEN, &peer, &peerSize) == 0,
              peerSize == MemoryLayout<audit_token_t>.size,
              peer.val.5 == UInt32(parentPID), peer.val.1 == geteuid(), peer.val.3 == getuid() else {
            throw Failure.unauthorized
        }
        var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<integer_t>.size)
        let status = withUnsafeMutablePointer(to: &own) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
            }
        }
        guard status == KERN_SUCCESS, count == 8, own.val.5 == UInt32(pid),
              own.val.1 == geteuid(), own.val.3 == getuid(),
              let child = RuntimeProcessIdentity.processIdentity(pid: pid, pidVersion: own.val.7),
              let parent = RuntimeProcessIdentity.processIdentity(pid: parentPID, pidVersion: peer.val.7),
              child.withUnsafeBytes({ $0.loadUnaligned(fromByteOffset: 24, as: UInt64.self) }) ==
                parent.withUnsafeBytes({ $0.loadUnaligned(fromByteOffset: 16, as: UInt64.self) }),
              child != parent, getppid() == parentPID,
              RuntimeProcessIdentity.processIdentity(pid: pid, pidVersion: own.val.7) == child,
              RuntimeProcessIdentity.processIdentity(pid: parentPID, pidVersion: peer.val.7) == parent else {
            throw Failure.unauthorized
        }
        return Processes(shimAudit: withUnsafeBytes(of: own) { Data($0) },
            daemonAudit: withUnsafeBytes(of: peer) { Data($0) }, shimIdentity: child, daemonIdentity: parent)
    }
}
#endif

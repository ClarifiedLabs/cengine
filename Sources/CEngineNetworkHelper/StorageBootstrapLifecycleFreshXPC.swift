import CEngineHelperSupport
import Darwin
import Foundation
@preconcurrency import XPC

@_silgen_name("xpc_dictionary_get_audit_token")
private func lifecycleFreshAudit(_ message: xpc_object_t, _ token: UnsafeMutablePointer<audit_token_t>)

/// Authenticates storage shims and challenges their fresh disk bindings over XPC.
/// Uses the same serial worker as the child transport and authority; reply and
/// disconnect handlers must stay outside that worker.
final class StorageBootstrapLifecycleFreshXPC: StorageLifecycleFreshBindingChecking, @unchecked Sendable {
    typealias Wire = StorageLifecycleFreshProtocol
    private struct Daemon { let process: BootstrapProcess; let deadline: TimeInterval }
    private final class Peer {
        let connection: xpc_connection_t
        let channel = StorageBootstrapChildChannel()
        var endpoint: StorageBootstrapLifecycleFreshEndpoint?
        init(_ connection: xpc_connection_t) { self.connection = connection }
    }
    private let worker: StorageBootstrapLifecycleChildWorker
    private let counter = StorageBootstrapLifecycleChildCounter()
    private let processes: StorageBootstrapProcesses
    private let bindings: StorageBootstrapBindings
    private let root: StorageIdentity.RootPublicKey
    private var daemons: [UInt64: Daemon] = [:] // Worker only.
    private let lock = NSLock()
    private var peers: [ObjectIdentifier: Peer] = [:]
    private let callbacks = DispatchQueue(label: "dev.cengine.storage-lifecycle.fresh-replies")

    init(ownerUID: uid_t, team: String, expectedRootPublicKey: StorageIdentity.RootPublicKey,
         worker: StorageBootstrapLifecycleChildWorker, policy: StorageLifecycleNativePolicy = .production) {
        processes = StorageBootstrapProcesses(ownerUID: ownerUID, team: team, policy: policy)
        bindings = StorageBootstrapBindings(ownerUID: ownerUID)
        root = expectedRootPublicKey; self.worker = worker
    }
    func remember(_ daemon: BootstrapProcess) throws {
        try worker.requireCurrent()
        guard try processes.daemon(audit: Self.audit(daemon)) == daemon else { throw BootstrapFailure(.unauthorized) }
        let now = ProcessInfo.processInfo.systemUptime
        daemons = daemons.filter { $0.value.deadline > now }
        guard daemons[daemon.uniqueID] == nil || daemons[daemon.uniqueID]?.process == daemon else { throw BootstrapFailure(.unauthorized) }
        guard daemons[daemon.uniqueID] != nil || daemons.count < 128 else { throw BootstrapFailure(.capacityExceeded) }
        daemons[daemon.uniqueID] = Daemon(process: daemon, deadline: now + Double(Wire.lifetimeMS) / 1000)
    }
    /// Input MUST be a genuinely received Mach message, never a local dictionary.
    func greet(_ message: xpc_object_t, reply: xpc_object_t, peer: xpc_connection_t) throws {
        try worker.requireCurrent()
        let record = try lock.withLock {
            peers = peers.filter { $0.value.channel.isOpen }
            if let value = peers[ObjectIdentifier(peer)] { return value }
            guard peers.count < 128 else { throw BootstrapFailure(.capacityExceeded) }
            let value = Peer(peer); peers[ObjectIdentifier(peer)] = value; return value
        }
        do {
            let greeting = try Self.decodeGreeting(message)
            guard greeting.rootPublicKey == root.publicData else { throw BootstrapFailure(.unauthorized) }
            let old = lock.withLock { record.endpoint }
            // The short remember window admits NEW channels only. An exact
            // duplicate on a live channel still re-pins both native processes.
            let remembered = daemons[greeting.daemonUniqueID]
            let daemon = try StorageBootstrapLifecycleEnrollment.daemon(existing: old?.daemon,
                uniqueID: greeting.daemonUniqueID, remembered: remembered?.process,
                deadline: remembered?.deadline, now: ProcessInfo.processInfo.systemUptime)
            var token = audit_token_t(); lifecycleFreshAudit(message, &token)
            let shim = try processes.storageShim(audit: BootstrapAuditIdentity(token: token), daemon: daemon)
            if let old {
                guard old.greeting == greeting, old.daemon == daemon, old.shim == shim, old.channel.isOpen else {
                    throw BootstrapFailure(.unauthorized)
                }
                xpc_dictionary_set_bool(reply, "ok", true); return
            }
            let processes = processes, callbacks = callbacks
            let endpoint = try StorageBootstrapLifecycleFreshEndpoint(greeting: greeting, daemon: daemon, shim: shim,
                channel: record.channel, expectedRoot: root, counter: counter, worker: worker,
                onRevoke: { xpc_connection_cancel(peer) }) { challenge, completion in
                let request = xpc_dictionary_create(nil, nil, 0)
                xpc_dictionary_set_string(request, "operation", "storage-lifecycle-fresh-challenge")
                let bytes = try Lifecycle.encode(challenge)
                bytes.withUnsafeBytes { xpc_dictionary_set_data(request, "request", $0.baseAddress, $0.count) }
                xpc_connection_send_message_with_reply(peer, request, callbacks) { response in
                    do {
                        guard xpc_get_type(response) == XPC_TYPE_DICTIONARY else { throw BootstrapFailure(.unavailable) }
                        var token = audit_token_t(); lifecycleFreshAudit(response, &token)
                        let sender = try processes.storageShim(audit: BootstrapAuditIdentity(token: token), daemon: daemon)
                        guard sender == shim else { throw BootstrapFailure(.unauthorized) }
                        completion(.success(.init(shim: sender, bytes: try Self.payload(response, key: "reply"))))
                    } catch { completion(.failure(error)) }
                }
            }
            try lock.withLock {
                guard record.channel.isOpen, !peers.values.contains(where: {
                    guard let old = $0.endpoint, old.channel.isOpen else { return false }
                    return old.shim.uniqueID == shim.uniqueID || old.greeting.channelID == greeting.channelID ||
                        (old.daemon == daemon && old.greeting.store == greeting.store)
                }) else { throw BootstrapFailure(.unauthorized) }
                record.endpoint = endpoint
            }
            xpc_dictionary_set_bool(reply, "ok", true)
        } catch {
            lock.withLock { record.channel.close(); record.endpoint?.revoke() }
            xpc_connection_cancel(peer); throw error
        }
    }
    /// No channel error is VM/process-exit evidence or permission to reuse a disk.
    func disconnected(_ peer: xpc_connection_t) {
        lock.withLock {
            guard let record = peers[ObjectIdentifier(peer)] else { return }
            record.channel.close(); record.endpoint?.revoke()
        }
    }
    /// Forms the authenticated format-completion origin ONLY from the independently
    /// pinned endpoint shim/daemon, the exact greeting, the grant, and ROOT's proven
    /// candidate principal. Never infers any part from the caller's binding/ext4
    /// fields or daemon metadata.
    func verifyFresh(_ binding: StorageIdentity.StoreBinding, grant: Lifecycle.Grant, daemon: BootstrapProcess,
                     principal: BootstrapPrincipal, rootFD: Int32, backingFD: Int32) throws -> StorageLifecycleFreshOrigin {
        try worker.requireCurrent()
        let endpoint = try lock.withLock {
            let matches = peers.values.compactMap(\.endpoint).filter {
                $0.channel.isOpen && $0.daemon == daemon && $0.greeting.matches(binding: binding)
            }
            guard matches.count == 1, let value = matches.first else { throw BootstrapFailure(.unauthorized) }
            return value
        }
        do {
            // ROOT proves the candidate principal; the native transport re-binds it
            // to the pinned daemon and exact grant before it enters the origin.
            guard principal.daemon == daemon,
                  try StorageIdentity.Ed25519SPKI(publicData: principal.controllerSPKI).fingerprint.rawValue == grant.newKey,
                  principal.child.boot == daemon.boot,
                  principal.child.pid > 0, principal.child.uniqueID > 0,
                  principal.child.uniqueID != daemon.uniqueID,
                  principal.child.pid != daemon.pid else { throw BootstrapFailure(.unauthorized) }
            // Held/named identities and ext4 are independently inspected on BOTH sides
            // of the direct shim proof. Those checks alone never establish freshness.
            let greeting = endpoint.greeting
            let expectedBacking = try StorageIdentity.DescriptorIdentity(volumeUUID: .init(greeting.volumeUUID),
                device: greeting.device, inode: greeting.inode)
            let pinnedRoot = try bindings.observe(rootFD, type: S_IFDIR, role: .root)
            try bindings.verify(binding, rootFD: rootFD, backingFD: backingFD, expectedBacking: expectedBacking)
            try endpoint.prove(binding: binding, grant: grant, daemon: daemon) {
                guard try processes.daemon(audit: Self.audit(daemon)) == daemon,
                      try processes.storageShim(audit: Self.audit(endpoint.shim), daemon: daemon) == endpoint.shim else {
                    throw BootstrapFailure(.unauthorized)
                }
            }
            try bindings.verify(binding, rootFD: rootFD, backingFD: backingFD, expectedBacking: expectedBacking)
            guard try bindings.observe(rootFD, type: S_IFDIR, role: .root) == pinnedRoot else { throw BootstrapFailure(.conflict) }
            let origin = StorageLifecycleFreshOrigin(greeting: endpoint.greeting, shim: endpoint.shim,
                daemon: endpoint.daemon, grant: grant, principal: principal)
            try origin.validate(binding: binding, root: root.publicData)
            return origin
        } catch { endpoint.revoke(); throw error }
    }
    static func decodeGreeting(_ message: xpc_object_t) throws -> Wire.Greeting {
        guard xpc_get_type(message) == XPC_TYPE_DICTIONARY,
              let operation = xpc_dictionary_get_string(message, "operation"), String(cString: operation) == "storage-lifecycle-fresh-shim",
              let role = xpc_dictionary_get_string(message, "role"), String(cString: role) == "storage-shim" else {
            throw BootstrapFailure(.invalidRequest)
        }
        return try Wire.decodeGreeting(payload(message, key: "request"))
    }
    private static func payload(_ message: xpc_object_t, key: String) throws -> Data {
        var count = 0
        guard let bytes = xpc_dictionary_get_data(message, key, &count), count > 0, count <= Lifecycle.maximumPayloadBytes else {
            throw BootstrapFailure(.invalidRequest)
        }
        return Data(bytes: bytes, count: count)
    }
    private static func audit(_ process: BootstrapProcess) throws -> BootstrapAuditIdentity {
        guard process.auditToken.count == MemoryLayout<audit_token_t>.size else { throw BootstrapFailure(.unauthorized) }
        return BootstrapAuditIdentity(token: process.auditToken.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) })
    }
}

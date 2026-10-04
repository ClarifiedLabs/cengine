import CEngineHelperSupport
import Darwin
import Foundation
@preconcurrency import XPC

@_silgen_name("xpc_dictionary_get_audit_token")
private func lifecycleServiceAudit(_ message: xpc_object_t, _ token: UnsafeMutablePointer<audit_token_t>)

/// Authenticates storage shims and obtains direct service-boot proofs over XPC.
/// Uses the same serial worker as the child transport and authority; reply and
/// disconnect handlers must stay outside that worker.
final class StorageBootstrapLifecycleServiceXPC: StorageLifecycleServiceChecking, @unchecked Sendable {
    typealias Wire = StorageLifecycleServiceProofProtocol
    private struct Daemon { let process: BootstrapProcess; let deadline: TimeInterval }
    private final class Peer {
        let connection: xpc_connection_t
        let channel = StorageBootstrapChildChannel()
        var endpoint: StorageBootstrapLifecycleServiceEndpoint?
        init(_ connection: xpc_connection_t) { self.connection = connection }
    }
    private let worker: StorageBootstrapLifecycleChildWorker
    private let counter = StorageBootstrapLifecycleChildCounter()
    private let processes: StorageBootstrapProcesses
    private let root: StorageIdentity.RootPublicKey
    private var daemons: [UInt64: Daemon] = [:] // Worker only.
    private let lock = NSLock()
    private var peers: [ObjectIdentifier: Peer] = [:]
    private let callbacks = DispatchQueue(label: "dev.cengine.storage-lifecycle.service-replies")
    /// Worker-only. ROOT's serial authority check for a same-channel successor boot
    /// (StorageBootstrapLifecycleAuthority.authorizeServiceBootUpdate). Unset: fail closed.
    var authorizeSuccessorBoot: ((_ predecessor: StorageLifecycleBootTrust, _ successor: StorageLifecycleBootTrust) throws -> Void)?

    init(ownerUID: uid_t, team: String, expectedRootPublicKey: StorageIdentity.RootPublicKey,
         worker: StorageBootstrapLifecycleChildWorker, policy: StorageLifecycleNativePolicy = .production) {
        processes = StorageBootstrapProcesses(ownerUID: ownerUID, team: team, policy: policy)
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
            var token = audit_token_t(); lifecycleServiceAudit(message, &token)
            let shim = try processes.storageShim(audit: BootstrapAuditIdentity(token: token), daemon: daemon)
            if let old {
                guard old.daemon == daemon, old.shim == shim, old.channel.isOpen else {
                    throw BootstrapFailure(.unauthorized)
                }
                try Self.update(old, to: greeting, authorize: authorizeSuccessorBoot)
                xpc_dictionary_set_bool(reply, "ok", true); return
            }
            let processes = processes, callbacks = callbacks
            let endpoint = try StorageBootstrapLifecycleServiceEndpoint(greeting: greeting, daemon: daemon, shim: shim,
                channel: record.channel, expectedRoot: root, counter: counter, worker: worker,
                onRevoke: { xpc_connection_cancel(peer) }) { challenge, completion in
                let request = xpc_dictionary_create(nil, nil, 0)
                xpc_dictionary_set_string(request, "operation", "storage-lifecycle-service-challenge")
                let bytes = try Lifecycle.encode(challenge)
                bytes.withUnsafeBytes { xpc_dictionary_set_data(request, "request", $0.baseAddress, $0.count) }
                xpc_connection_send_message_with_reply(peer, request, callbacks) { response in
                    do {
                        guard xpc_get_type(response) == XPC_TYPE_DICTIONARY else { throw BootstrapFailure(.unavailable) }
                        var token = audit_token_t(); lifecycleServiceAudit(response, &token)
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
                        (old.daemon == daemon && old.greeting.boot.identity == greeting.boot.identity)
                }) else { throw BootstrapFailure(.unauthorized) }
                record.endpoint = endpoint
            }
            xpc_dictionary_set_bool(reply, "ok", true)
        } catch {
            lock.withLock { record.channel.close(); record.endpoint?.revoke() }
            xpc_connection_cancel(peer); throw error
        }
    }
    /// Authenticated same-channel re-greet: an exact duplicate is idempotent; a
    /// changed boot requires ROOT's exact pending service change. Old trust is revoked.
    static func update(_ endpoint: StorageBootstrapLifecycleServiceEndpoint, to greeting: Wire.Greeting,
                       authorize: ((StorageLifecycleBootTrust, StorageLifecycleBootTrust) throws -> Void)?) throws {
        try endpoint.update(to: greeting) { predecessor, successor in
            guard let authorize else { throw BootstrapFailure(.unauthorized) }
            try authorize(predecessor, successor)
        }
    }
    /// No channel error is VM/process-exit evidence or permission to reuse a disk.
    func disconnected(_ peer: xpc_connection_t) {
        lock.withLock {
            guard let record = peers[ObjectIdentifier(peer)] else { return }
            record.channel.close(); record.endpoint?.revoke()
        }
    }
    /// Separate registered adoption proof; never changes ordinary storageShim pinning.
    var guardPublication: ((String) throws -> Void)?
    var adoptedBoot: ((Lifecycle.Grant, BootstrapProcess) throws -> StorageLifecycleBootTrust?)?
    func boot(grant: Lifecycle.Grant, daemon: BootstrapProcess) throws -> StorageLifecycleBootTrust {
        try worker.requireCurrent()
        if let boot = try adoptedBoot?(grant, daemon) { return boot }
        let endpoint = try lock.withLock {
            let matches = peers.values.compactMap(\.endpoint).filter {
                $0.channel.isOpen && $0.daemon == daemon && $0.greeting.boot.identity == grant.identity
            }
            guard matches.count == 1, let value = matches.first else { throw BootstrapFailure(.unauthorized) }
            return value
        }
        return try endpoint.prove(grant: grant, daemon: daemon) {
            guard try processes.daemon(audit: Self.audit(daemon)) == daemon,
                  try processes.storageShim(audit: Self.audit(endpoint.shim), daemon: daemon) == endpoint.shim else {
                throw BootstrapFailure(.unauthorized)
            }
        }
    }
    /// Resolve only the actually enrolled native endpoint, then freshly challenge it.
    /// The received adoption sender must be that exact original direct-child shim.
    func nativeOrigin(_ origin: Adoption.Origin, sender: BootstrapAuditIdentity,
                      grant: Lifecycle.Grant, principal: BootstrapPrincipal,
                      expectedBoot: StorageLifecycleBootTrust,
                      coldEnrollmentCheck: (() throws -> Void)? = nil) throws -> BootstrapProcess {
        try worker.requireCurrent()
        // Only the trusted cold adapter supplies this exact-L3 authorization.
        // Ordinary enrollment keeps the publication fence; greeting/boot proofs
        // remain available because proving cold completion depends on them.
        if let coldEnrollmentCheck { try coldEnrollmentCheck() }
        else { try guardPublication?(origin.binding.store) }
        let shim = try processes.storageShim(audit: sender, daemon: principal.daemon)
        let endpoint = try lock.withLock {
            let matches = peers.values.compactMap(\.endpoint).filter {
                $0.channel.isOpen && $0.shim == shim && $0.daemon == principal.daemon
            }
            guard matches.count == 1, let endpoint = matches.first else { throw BootstrapFailure(.unauthorized) }
            return endpoint
        }
        let greeting = endpoint.greeting
        try Self.validateOriginMetadata(origin, greeting: greeting, expectedBoot: expectedBoot)
        guard try boot(grant: grant, daemon: principal.daemon) == expectedBoot,
              endpoint.channel.isOpen, endpoint.greeting == greeting,
              try processes.storageShim(audit: sender, daemon: principal.daemon) == shim else {
            throw BootstrapFailure(.unauthorized)
        }
        try coldEnrollmentCheck?()
        return shim
    }

    /// Rejection-only metadata checks; nativeOrigin additionally requires a native
    /// sender, a unique live endpoint and its freshly authenticated boot challenge.
    static func validateOriginMetadata(_ origin: Adoption.Origin, greeting: Wire.Greeting,
                                       expectedBoot: StorageLifecycleBootTrust) throws {
        try origin.validate(); try greeting.validate()
        guard greeting.binding == origin.binding, greeting.rootPublicKey == origin.rootPublicKey,
              greeting.bootBinding.shimLaunchUUID == origin.shimLaunchUUID,
              greeting.boot == expectedBoot else { throw BootstrapFailure(.unauthorized) }
    }

    static func decodeGreeting(_ message: xpc_object_t) throws -> Wire.Greeting {
        guard xpc_get_type(message) == XPC_TYPE_DICTIONARY,
              let operation = xpc_dictionary_get_string(message, "operation"), String(cString: operation) == "storage-lifecycle-service-shim",
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

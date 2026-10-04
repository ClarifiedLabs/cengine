import CEngineHelperSupport
import Darwin
import Foundation
@preconcurrency import XPC

@_silgen_name("xpc_dictionary_get_audit_token")
private func lifecycleChildMessageAuditToken(_ message: xpc_object_t, _ token: UnsafeMutablePointer<audit_token_t>)

/// Authenticates controller children and performs direct proof exchanges over XPC.
/// Caller must run authority operations, remember and greet on `worker`. Reply and
/// disconnect handlers deliberately never acquire the lifecycle worker.
final class StorageBootstrapLifecycleChildXPC: StorageLifecycleProcessChecking, @unchecked Sendable {
    typealias Wire = StorageLifecycleChildProtocol
    private struct Daemon { let process: BootstrapProcess; let deadline: TimeInterval }
    private final class Peer {
        let connection: xpc_connection_t
        let id = UUID()
        let channel = StorageBootstrapChildChannel()
        var endpoint: StorageBootstrapLifecycleChildEndpoint?
        init(_ connection: xpc_connection_t) { self.connection = connection }
    }
    let worker: StorageBootstrapLifecycleChildWorker
    private let state = StorageBootstrapLifecycleChildState()
    private let processes: StorageBootstrapProcesses
    private let root: StorageIdentity.RootPublicKey
    private let lookupOrigin: (String) throws -> StorageLifecycleShimOrigin?
    private let services: any StorageLifecycleServiceChecking
    private var daemons: [UInt64: Daemon] = [:] // Worker only.
    private let peersLock = NSLock()
    private var peers: [ObjectIdentifier: Peer] = [:]
    private let callbacks = DispatchQueue(label: "dev.cengine.storage-lifecycle.replies")

    init(ownerUID: uid_t, team: String, expectedRootPublicKey: StorageIdentity.RootPublicKey,
         worker: StorageBootstrapLifecycleChildWorker, services: any StorageLifecycleServiceChecking,
         policy: StorageLifecycleNativePolicy = .production,
         lookupOrigin: @escaping (String) throws -> StorageLifecycleShimOrigin? = { _ in nil }) {
        self.lookupOrigin = lookupOrigin
        self.worker = worker
        processes = StorageBootstrapProcesses(ownerUID: ownerUID, team: team, policy: policy)
        root = expectedRootPublicKey; self.services = services
    }
    /// Input is re-pinned natively; a daemon-supplied DTO alone can never be remembered.
    func remember(_ daemon: BootstrapProcess) throws {
        try worker.requireCurrent()
        guard try processes.daemon(audit: Self.audit(daemon)) == daemon else { throw BootstrapFailure(.unauthorized) }
        let now = ProcessInfo.processInfo.systemUptime
        daemons = daemons.filter { $0.value.deadline > now }
        if let old = daemons[daemon.uniqueID], old.process != daemon { throw BootstrapFailure(.unauthorized) }
        guard daemons[daemon.uniqueID] != nil || daemons.count < StorageBootstrapLifecycleChildState.maximumEndpoints else {
            throw BootstrapFailure(.capacityExceeded)
        }
        daemons[daemon.uniqueID] = Daemon(process: daemon, deadline: now + Double(Wire.lifetimeMS) / 1000)
    }
    /// Only genuinely received Mach dictionaries may reach this method (audit SPI).
    func greet(_ message: xpc_object_t, reply: xpc_object_t, peer: xpc_connection_t) throws {
        try worker.requireCurrent()
        let record = try peersLock.withLock {
            peers = peers.filter { $0.value.channel.isOpen }
            if let existing = peers[ObjectIdentifier(peer)] { return existing }
            guard peers.count < StorageBootstrapLifecycleChildState.maximumEndpoints else { throw BootstrapFailure(.capacityExceeded) }
            let value = Peer(peer)
            peers[ObjectIdentifier(peer)] = value
            return value
        }
        do {
            let greeting = try Self.decodeGreeting(message)
            guard greeting.rootPublicKey == root.publicData else { throw BootstrapFailure(.unauthorized) }
            let old = peersLock.withLock { record.endpoint }
            let remembered = daemons[greeting.daemonUniqueID]
            let daemon = try StorageBootstrapLifecycleEnrollment.daemon(existing: old?.principal.daemon,
                uniqueID: greeting.daemonUniqueID, remembered: remembered?.process,
                deadline: remembered?.deadline, now: ProcessInfo.processInfo.systemUptime)
            var token = audit_token_t()
            lifecycleChildMessageAuditToken(message, &token)
            let child = try processes.child(audit: BootstrapAuditIdentity(token: token), daemon: daemon)
            if let old {
                guard old.principal.daemon == daemon, old.principal.child == child,
                      old.greeting == greeting, old.channel.isOpen else { throw BootstrapFailure(.unauthorized) }
                xpc_dictionary_set_bool(reply, "ok", true)
                return // Exact duplicate cannot reset the monotonic counter.
            }
            let processes = processes, callbacks = callbacks
            let send: (Data, @escaping StorageBootstrapLifecycleChildEndpoint.Completion) throws -> Void = { bytes, completion in
                let request = xpc_dictionary_create(nil, nil, 0)
                xpc_dictionary_set_string(request, "operation", "storage-lifecycle-root-challenge")
                bytes.withUnsafeBytes { xpc_dictionary_set_data(request, "request", $0.baseAddress, $0.count) }
                xpc_connection_send_message_with_reply(peer, request, callbacks) { response in
                    do {
                        guard xpc_get_type(response) == XPC_TYPE_DICTIONARY else { throw BootstrapFailure(.unavailable) }
                        var token = audit_token_t()
                        lifecycleChildMessageAuditToken(response, &token)
                        let sender = try processes.child(audit: BootstrapAuditIdentity(token: token), daemon: daemon)
                        guard sender == child else { throw BootstrapFailure(.unauthorized) }
                        let data = try Self.payload(response, key: "reply")
                        completion(.success(.init(child: sender, bytes: data)))
                    } catch { completion(.failure(error)) }
                }
            }
            let endpoint = try StorageBootstrapLifecycleChildEndpoint(greeting: greeting,
                daemon: daemon, child: child, connectionID: record.id, channel: record.channel,
                expectedRoot: root, counter: state.counter, worker: worker,
                onRevoke: { xpc_connection_cancel(peer) },
                identitySender: { challenge, completion in try send(Lifecycle.encode(challenge), completion) }) { challenge, completion in
                try send(Lifecycle.encode(challenge), completion)
            }
            try state.insert(endpoint)
            peersLock.withLock { record.endpoint = endpoint }
            guard record.channel.isOpen else { throw BootstrapFailure(.unavailable) }
            xpc_dictionary_set_bool(reply, "ok", true)
        } catch {
            peersLock.withLock { record.channel.close(); record.endpoint?.revoke() }
            xpc_connection_cancel(peer)
            throw error
        }
    }
    /// Call directly from connection error handlers, NEVER under the operation gate
    /// or queued behind a blocked proof. No channel error is process-exit evidence.
    func disconnected(_ peer: xpc_connection_t) {
        peersLock.withLock {
            guard let record = peers[ObjectIdentifier(peer)] else { return }
            record.channel.close()
            record.endpoint?.revoke()
        }
    }
    /// Request identities select an enrolled endpoint only. Incarnation and key
    /// always come from its stable greeting, never a caller-supplied candidate.
    func adoptionCandidate(request: StorageLifecycleAdoptionProtocol.Request,
                           daemon: BootstrapProcess, deadline: DispatchTime = .distantFuture) throws -> BootstrapPrincipal {
        try worker.requireCurrent()
        try request.validate()
        let endpoint = try state.endpoint(uniqueID: request.controllerUniqueID)
        do {
            let principal = endpoint.principal
            func pin() throws {
                try StorageBootstrapLifecycleAdoptionSelection.validate(request: request,
                    origin: lookupOrigin(request.origin.binding.store)?.wire, greeting: endpoint.greeting,
                    principal: principal, daemon: daemon, root: root)
                guard try processes.daemon(audit: Self.audit(daemon)) == daemon,
                      try processes.child(audit: Self.audit(principal.child), daemon: daemon) == principal.child else {
                    throw BootstrapFailure(.unauthorized)
                }
            }
            _ = try endpoint.proveIdentity(principal: principal, requestSHA256: Wire.adoptionRequestDigest(request), deadline: deadline, repin: pin)
            return principal
        } catch { endpoint.revoke(); throw error }
    }
    func candidate(_ candidate: StorageIdentity.Candidate, daemon: BootstrapProcess,
                   grant: Lifecycle.Grant) throws -> BootstrapPrincipal {
        try worker.requireCurrent()
        let endpoint = try state.endpoint(pid: candidate.childPIDHint)
        let expected = BootstrapPrincipal(daemon: daemon, child: endpoint.principal.child,
            incarnation: candidate.incarnationID.rawValue, controllerSPKI: candidate.publicKey.publicData)
        _ = try prove(endpoint, principal: expected, grant: grant, purpose: .candidate)
        return expected
    }
    func validateRecipient(_ principal: BootstrapPrincipal, daemon: BootstrapProcess, grant: Lifecycle.Grant) throws {
        try worker.requireCurrent()
        let endpoint = try state.endpoint(pid: principal.child.pid)
        guard principal.daemon == daemon else { endpoint.revoke(); throw BootstrapFailure(.unauthorized) }
        _ = try prove(endpoint, principal: principal, grant: grant, purpose: .candidate)
    }
    func receipt(_ principal: BootstrapPrincipal, daemon: BootstrapProcess,
                 grant: Lifecycle.Grant, nonce: Data) throws -> Lifecycle.Receipt {
        try worker.requireCurrent()
        let endpoint = try state.endpoint(pid: principal.child.pid)
        guard principal.daemon == daemon, nonce.count == 32 else { endpoint.revoke(); throw BootstrapFailure(.unauthorized) }
        // The child MUST compare its actual TLS inputs to this independently
        // proven shim boot. Parent-forwarded CA/pin values alone are insufficient.
        let boot = try services.boot(grant: grant, daemon: daemon)
        let reply = try prove(endpoint, principal: principal, grant: grant, purpose: .result, nonce: nonce, boot: boot)
        guard let receipt = reply.receipt, receipt.grant == grant, receipt.nonce == nonce else {
            endpoint.revoke(); throw BootstrapFailure(.unauthorized)
        }
        return receipt
    }
    func serviceBootTrust(_ principal: BootstrapPrincipal, daemon: BootstrapProcess,
                          grant: Lifecycle.Grant) throws -> StorageLifecycleBootTrust {
        try validateRecipient(principal, daemon: daemon, grant: grant)
        let boot = try services.boot(grant: grant, daemon: daemon)
        try validateRecipient(principal, daemon: daemon, grant: grant)
        return boot
    }
    func serviceResult(_ principal: BootstrapPrincipal, daemon: BootstrapProcess,
                       grant: Lifecycle.Grant, nonce: Data, boot: StorageLifecycleBootTrust,
                       changeRequest: Lifecycle.ServiceChangeRequest?,
                       confirmation: Lifecycle.ServiceChangeConfirmation?) throws -> Lifecycle.ServiceResult {
        try worker.requireCurrent()
        let endpoint = try state.endpoint(pid: principal.child.pid)
        guard principal.daemon == daemon, nonce.count == 32,
              try services.boot(grant: grant, daemon: daemon) == boot else {
            endpoint.revoke(); throw BootstrapFailure(.unauthorized)
        }
        let reply = try prove(endpoint, principal: principal, grant: grant,
            purpose: confirmation == nil ? .serviceResult : .serviceCommit, nonce: nonce, boot: boot,
            changeRequest: changeRequest, confirmation: confirmation)
        guard let result = reply.serviceResult, result.grant == grant, result.nonce == nonce else {
            endpoint.revoke(); throw BootstrapFailure(.unauthorized)
        }
        return result
    }
    func liveness(_ process: BootstrapProcess) -> BootstrapLiveness {
        // Native kernel identity only. A closed/timed-out endpoint never implies death.
        processes.liveness(process)
    }
    private func prove(_ endpoint: StorageBootstrapLifecycleChildEndpoint, principal: BootstrapPrincipal,
                       grant: Lifecycle.Grant, purpose: Wire.Purpose, nonce: Data? = nil,
                       boot: StorageLifecycleBootTrust? = nil,
                       changeRequest: Lifecycle.ServiceChangeRequest? = nil,
                       confirmation: Lifecycle.ServiceChangeConfirmation? = nil) throws -> Wire.Reply {
        try endpoint.prove(principal: principal, grant: grant, purpose: purpose, nonce: nonce, boot: boot,
                           changeRequest: changeRequest, confirmation: confirmation) {
            guard try processes.daemon(audit: Self.audit(principal.daemon)) == principal.daemon,
                  try processes.child(audit: Self.audit(principal.child), daemon: principal.daemon) == principal.child else {
                throw BootstrapFailure(.unauthorized)
            }
        }
    }
    private static func audit(_ process: BootstrapProcess) throws -> BootstrapAuditIdentity {
        guard process.auditToken.count == MemoryLayout<audit_token_t>.size else { throw BootstrapFailure(.unauthorized) }
        return BootstrapAuditIdentity(token: process.auditToken.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) })
    }
    static func decodeGreeting(_ message: xpc_object_t) throws -> Wire.Greeting {
        guard xpc_get_type(message) == XPC_TYPE_DICTIONARY,
              let operation = xpc_dictionary_get_string(message, "operation"), String(cString: operation) == "storage-lifecycle-child",
              let role = xpc_dictionary_get_string(message, "role"), String(cString: role) == "controller-child" else {
            throw BootstrapFailure(.invalidRequest)
        }
        return try Wire.decodeGreeting(payload(message, key: "request"))
    }
    private static func payload(_ message: xpc_object_t, key: String) throws -> Data {
        var count = 0
        guard let bytes = xpc_dictionary_get_data(message, key, &count), count > 0,
              count <= Lifecycle.maximumPayloadBytes else { throw BootstrapFailure(.invalidRequest) }
        return Data(bytes: bytes, count: count)
    }
}

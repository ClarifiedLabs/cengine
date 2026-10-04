import CEngineHelperSupport
import Darwin
import Foundation
import Security
@preconcurrency import XPC

@_silgen_name("xpc_dictionary_get_audit_token")
private func lifecycleAdoptionAudit(_ message: xpc_object_t, _ token: UnsafeMutablePointer<audit_token_t>)

/// Native adoption transport. The entire authority operation must run on
/// `worker`; replies and disconnects run independently so a silent shim cannot hold
/// ROOT indefinitely. No greeting, wire origin or reply is itself authority.
final class StorageBootstrapLifecycleAdoptionXPC: StorageLifecycleAdoptionChecking, StorageLifecycleHandoffChecking, @unchecked Sendable {
    static let greetingOperation = "storage-lifecycle-adoption-shim"
    static let coldEnrollmentOperation = "storage-lifecycle-cold-adoption-enroll"
    static let resumeEnrollmentOperation = "storage-lifecycle-resume-adoption-enroll"
    static let enrollmentOperation = "storage-lifecycle-adoption-enroll"
    private final class AuthorityReference { weak var value: StorageBootstrapLifecycleAdoptionAuthority? }

    /// Fixed scope factory. Candidate admission uses pregrant native child proof;
    /// the bound router supplies scoped lock observation and the overall deadline.
    static func native(ownerUID: uid_t, team: String, worker: StorageBootstrapLifecycleChildWorker,
                       policy: StorageLifecycleNativePolicy, directory: StorageLifecycleQualificationDirectory,
                       rpc: StorageBootstrapLifecycleXPC, service: StorageBootstrapLifecycleServiceXPC,
                       child: StorageBootstrapLifecycleChildXPC, journal: StorageBootstrapLifecycleAdoptionJournal) throws
        -> (StorageBootstrapLifecycleAdoptionXPC, StorageBootstrapLifecycleAdoptionAuthority) {
        let reference = AuthorityReference()
        let transport = StorageBootstrapLifecycleAdoptionXPC(ownerUID: ownerUID, team: team,
            expectedRootPublicKey: try directory.journal.lifecycleRootPublicKey(), worker: worker, policy: policy,
            lookupOrigin: { id in
                guard let authority = reference.value else { throw BootstrapFailure(.unavailable) }
                return try authority.registeredOrigin(store: id)
            }, verifyFreshOrigin: { origin, _, _ in
                try rpc.guardColdPublication(store: origin.wire.binding.store)
                let binding = try origin.wire.binding.value()
                try directory.requireBinding(binding, establish: false)
                let (grant, principal, boot) = try rpc.currentOriginPrincipal(binding: binding)
                guard principal.daemon == origin.originalDaemon, principal.child == origin.originalController,
                      try service.nativeOrigin(origin.wire, sender: Self.audit(origin.shim), grant: grant,
                        principal: principal, expectedBoot: boot) == origin.shim else { throw BootstrapFailure(.unauthorized) }
                return try rpc.freshEnrollmentBacking(origin: origin)
            }, verifyCandidate: { request, peer, deadline in
                let daemon = try StorageBootstrapProcesses(ownerUID: ownerUID, team: team, policy: policy).daemon(audit: peer)
                return try child.adoptionCandidate(request: request, daemon: daemon, deadline: deadline)
            })
        transport.guardPublication = { [weak rpc] store in
            guard let rpc else { throw BootstrapFailure(.unavailable) }
            try rpc.guardColdPublication(store: store)
        }
        let authority = try StorageBootstrapLifecycleAdoptionAuthority(journal: journal, processes: transport)
        reference.value = authority
        service.adoptedBoot = { [weak authority, weak transport, weak rpc] grant, daemon in
            guard let authority, let transport, let rpc,
                  let request = try authority.committedRequest(store: grant.identity.store, daemon: daemon) else { return nil }
            try rpc.guardColdPublication(store: grant.identity.store)
            return try transport.withRequest(deadline: .now() + 5, check: {
                guard try directory.journal.lifecycleRootPublicKey().publicData == request.origin.rootPublicKey else { throw BootstrapFailure(.unauthorized) }
                try directory.requireBinding(request.origin.binding.value(), establish: false)
            }) {
                let peer = try Self.audit(daemon)
                let (origin, principal) = try authority.committed(request, peer: peer)
                guard grant.operation == .takeover,
                      try grant.newKey == StorageIdentity.Ed25519SPKI(publicData: principal.controllerSPKI).fingerprint.rawValue else { throw BootstrapFailure(.unauthorized) }
                let expected = try rpc.adoptedService(identity: grant.identity, proving: grant)
                let proof = try transport.service(request, grant: grant, expected: expected, origin: origin)
                guard try authority.committed(request, peer: peer).1 == principal,
                      try rpc.adoptedService(identity: grant.identity, proving: grant) == expected else { throw BootstrapFailure(.unauthorized) }
                return proof.boot
            }
        }
        return (transport, authority)
    }

    /// Only a received, signed shim message can enroll. Origin is metadata, not
    /// authority: processes come from ROOT's current principal and native service.
    func enroll(_ message: xpc_object_t, reply: xpc_object_t, rootFD: Int32,
                directory: StorageLifecycleQualificationDirectory, rpc: StorageBootstrapLifecycleXPC,
                service: StorageBootstrapLifecycleServiceXPC, authority: StorageBootstrapLifecycleAdoptionAuthority) throws {
        try worker.requireCurrent()
        let wire = try Self.decodeEnrollment(message)
        try rpc.guardColdPublication(store: wire.binding.store)
        let binding = try wire.binding.value()
        try directory.requireBinding(binding, establish: false)
        guard wire.rootPublicKey == root.publicData else { throw BootstrapFailure(.unauthorized) }
        let (grant, principal, boot) = try rpc.currentOriginPrincipal(binding: binding)
        var token = audit_token_t(); lifecycleAdoptionAudit(message, &token)
        let shim = try service.nativeOrigin(wire, sender: .init(token: token), grant: grant,
                                            principal: principal, expectedBoot: boot)
        let fd = xpc_dictionary_dup_fd(message, "backing-fd")
        guard fd >= 0 else { throw BootstrapFailure(.invalidRequest) }
        defer { close(fd) }
        let origin = StorageLifecycleShimOrigin(wire: wire, shim: shim,
            originalDaemon: principal.daemon, originalController: principal.child)
        let expectedBacking = try rpc.freshEnrollmentBacking(origin: origin)
        try Self.withEnrollmentBacking(bindings, binding: binding, rootFD: rootFD, backingFD: fd,
            expectedBacking: expectedBacking) {
            try authority.recordOrigin(origin, rootFD: rootFD, backingFD: fd)
        }
        xpc_dictionary_set_bool(reply, "ok", true)
    }
    /// Cold registration acknowledges the already rotated protected origin. Never
    /// recordOrigin here: that is the distinct fresh-initialize enrollment path.
    func enrollCold(_ message: xpc_object_t, reply: xpc_object_t, rootFD: Int32,
                    directory: StorageLifecycleQualificationDirectory, rpc: StorageBootstrapLifecycleXPC,
                    service: StorageBootstrapLifecycleServiceXPC, authority: StorageBootstrapLifecycleAdoptionAuthority) throws {
        try worker.requireCurrent()
        let (wire, seed) = try Self.decodeColdEnrollment(message)
        let binding = try wire.binding.value()
        try directory.requireBinding(binding, establish: false)
        let (origin, principal, epoch, completed) = try rpc.coldOriginPrincipal(binding: binding)
        guard origin.wire == wire, epoch == seed.baseEpoch, completed.operationID == seed.operationID,
              completed.signedOpenSHA256 == seed.signedOpenSHA256,
              try authority.registeredOrigin(store: wire.binding.store) == origin else { throw BootstrapFailure(.unauthorized) }
        var token = audit_token_t(); lifecycleAdoptionAudit(message, &token)
        guard try service.nativeOrigin(wire, sender: .init(token: token), grant: completed.receipt.grant,
            principal: principal, expectedBoot: completed.successor.boot, coldEnrollmentCheck: {
                _ = try rpc.authorizeColdEnrollment(seed: seed, origin: origin, nativePrincipal: principal)
            }) == origin.shim else { throw BootstrapFailure(.unauthorized) }
        let expectedBacking = try rpc.authorizeColdEnrollment(seed: seed, origin: origin, nativePrincipal: principal)
        try StorageBootstrapLifecycleColdXPC.withBacking(message) { fd in
            try Self.withEnrollmentBacking(bindings, binding: binding, rootFD: rootFD, backingFD: fd,
                expectedBacking: expectedBacking) {
                let (again, samePrincipal, sameEpoch, sameCompletion) = try rpc.coldOriginPrincipal(binding: binding)
                guard again == origin, samePrincipal == principal, sameEpoch == epoch,
                      sameCompletion.successor == completed.successor,
                      sameCompletion.receipt.grant == completed.receipt.grant,
                      sameCompletion.receipt.serviceEpoch == completed.receipt.serviceEpoch,
                      sameCompletion.receipt.revision == completed.receipt.revision else { throw BootstrapFailure(.unauthorized) }
                try rpc.completeColdEnrollment(seed: seed, origin: origin, nativePrincipal: principal)
            }
        }
        let bytes = try StorageLifecycleColdShimProtocol.encode(StorageLifecycleColdShimProtocol.ColdEnrollmentAcknowledgement(for: seed))
        bytes.withUnsafeBytes { xpc_dictionary_set_data(reply, "reply", $0.baseAddress, $0.count) }
        xpc_dictionary_set_bool(reply, "ok", true)
    }
    static func decodeColdEnrollment(_ message: xpc_object_t) throws -> (Adoption.Origin, StorageLifecycleColdShimProtocol.ColdEnrollmentSeed) {
        guard let fd = xpc_dictionary_get_value(message, "backing-fd"), xpc_get_type(fd) == XPC_TYPE_FD else { throw BootstrapFailure(.invalidRequest) }
        let wire = try decodeOrigin(message, operation: coldEnrollmentOperation)
        let seed = try StorageLifecycleColdShimProtocol.decodeEnrollmentSeed(payload(message, key: "cold-seed"))
        guard seed.successorOrigin == wire else { throw BootstrapFailure(.unauthorized) }
        return (wire, seed)
    }
    /// Fresh-resume enrollment acknowledges the completed resume successor through
    /// the INITIAL adoption machinery: the protected store had NO adopted record.
    /// The resume-purpose seed and the fixed genesis base epoch are validated
    /// against the durable transaction before any adoption state is written.
    func enrollResume(_ message: xpc_object_t, reply: xpc_object_t, rootFD: Int32,
                      directory: StorageLifecycleQualificationDirectory, rpc: StorageBootstrapLifecycleXPC,
                      service: StorageBootstrapLifecycleServiceXPC, authority: StorageBootstrapLifecycleAdoptionAuthority) throws {
        try worker.requireCurrent()
        let (wire, seed) = try Self.decodeResumeEnrollment(message)
        let binding = try wire.binding.value()
        try directory.requireBinding(binding, establish: false)
        guard wire.rootPublicKey == root.publicData else { throw BootstrapFailure(.unauthorized) }
        let (origin, principal, epoch, completed) = try rpc.resumeOriginPrincipal(binding: binding)
        guard origin.wire == wire, epoch == seed.baseEpoch, completed.operationID == seed.operationID,
              completed.signedOpenSHA256 == seed.signedOpenSHA256 else { throw BootstrapFailure(.unauthorized) }
        var token = audit_token_t(); lifecycleAdoptionAudit(message, &token)
        guard try service.nativeOrigin(wire, sender: .init(token: token), grant: completed.receipt.grant,
            principal: principal, expectedBoot: completed.successor.boot, coldEnrollmentCheck: {
                _ = try rpc.authorizeResumeEnrollment(seed: seed, origin: origin, nativePrincipal: principal)
            }) == origin.shim else { throw BootstrapFailure(.unauthorized) }
        let fd = xpc_dictionary_dup_fd(message, "backing-fd")
        guard fd >= 0 else { throw BootstrapFailure(.invalidRequest) }
        defer { close(fd) }
        let expectedBacking = try rpc.authorizeResumeEnrollment(seed: seed, origin: origin, nativePrincipal: principal)
        try Self.withEnrollmentBacking(bindings, binding: binding, rootFD: rootFD, backingFD: fd,
            expectedBacking: expectedBacking) {
            // Existing initial enrollment machinery: recordOrigin fails closed when
            // any adopted record already exists; nothing is rotated or reconstructed.
            try withResumeEnrollment(origin: origin, expectedBacking: expectedBacking, check: {
                guard try service.nativeOrigin(wire, sender: .init(token: token), grant: completed.receipt.grant,
                    principal: principal, expectedBoot: completed.successor.boot, coldEnrollmentCheck: {
                        _ = try rpc.authorizeResumeEnrollment(seed: seed, origin: origin, nativePrincipal: principal)
                    }) == origin.shim else { throw BootstrapFailure(.unauthorized) }
            }) {
                try authority.recordOrigin(origin, rootFD: rootFD, backingFD: fd)
            }
            let (again, samePrincipal, sameEpoch, sameCompletion) = try rpc.resumeOriginPrincipal(binding: binding)
            guard again == origin, samePrincipal == principal, sameEpoch == epoch,
                  sameCompletion.successor == completed.successor,
                  sameCompletion.receipt.grant == completed.receipt.grant,
                  sameCompletion.receipt.serviceEpoch == completed.receipt.serviceEpoch,
                  sameCompletion.receipt.revision == completed.receipt.revision else { throw BootstrapFailure(.unauthorized) }
            try bindings.verify(binding, rootFD: rootFD, backingFD: fd, expectedBacking: expectedBacking)
            try rpc.completeResumeEnrollment(seed: seed, origin: origin, nativePrincipal: principal)
        }
        let bytes = try StorageLifecycleColdShimProtocol.encode(StorageLifecycleColdShimProtocol.ColdEnrollmentAcknowledgement(for: seed))
        bytes.withUnsafeBytes { xpc_dictionary_set_data(reply, "reply", $0.baseAddress, $0.count) }
        xpc_dictionary_set_bool(reply, "ok", true)
    }
    static func decodeResumeEnrollment(_ message: xpc_object_t) throws -> (Adoption.Origin, StorageLifecycleColdShimProtocol.ColdEnrollmentSeed) {
        guard let fd = xpc_dictionary_get_value(message, "backing-fd"), xpc_get_type(fd) == XPC_TYPE_FD else { throw BootstrapFailure(.invalidRequest) }
        let wire = try decodeOrigin(message, operation: resumeEnrollmentOperation)
        let seed = try StorageLifecycleColdShimProtocol.decodeEnrollmentSeed(payload(message, key: "resume-seed"))
        guard seed.successorOrigin == wire, seed.purpose == .resumeReadOnly else { throw BootstrapFailure(.unauthorized) }
        return (wire, seed)
    }
    /// Wired by the scope before any publication route is exposed.
    var guardPublication: ((String) throws -> Void)?
    static let fenceOperation = "storage-lifecycle-adoption-challenge"
    static let commitOperation = "storage-lifecycle-adoption-commit"
    private static let timeout: TimeInterval = 5
    private enum Expectation {
        case acknowledgement
        case service(Adoption.ServiceChallenge)
        case serviceChange(Adoption.ServiceChangeChallenge)
        case handoff(StorageLifecycleHandoffShimProtocol.Challenge)
    }
    private final class Pending: @unchecked Sendable {
        let digest: Data
        let deadline: DispatchTime
        let signal = DispatchSemaphore(value: 0)
        var response: Data?
        let expectation: Expectation
        var acknowledged = false // Protected by transport lock.
        var busy = false
        init(digest: Data, deadline: DispatchTime, expectation: Expectation) {
            self.digest = digest; self.deadline = deadline; self.expectation = expectation
        }
    }
    private final class Peer: @unchecked Sendable {
        let connection: xpc_connection_t
        var open = true // All mutable fields protected by transport lock.
        var origin: StorageLifecycleShimOrigin?
        var pending: Pending?
        init(_ connection: xpc_connection_t) { self.connection = connection }
    }
    private let worker: StorageBootstrapLifecycleChildWorker
    private let counter = StorageBootstrapLifecycleChildCounter()
    private let processes: StorageBootstrapProcesses
    private let bindings: StorageBootstrapBindings
    private let root: StorageIdentity.RootPublicKey
    private let lock = NSLock()
    private var peers: [ObjectIdentifier: Peer] = [:]
    private let callbacks = DispatchQueue(label: "dev.cengine.storage-lifecycle.adoption-replies")
    /// Worker-only, protected ROOT journal lookup. Never resolve from the greeting.
    private let lookupOrigin: (String) throws -> StorageLifecycleShimOrigin?
    /// Required trusted integration: direct live shim launch/spec proof, NOT a DTO
    /// equality check. Native parent and physical descriptor checks also run here.
    private let verifyFreshOrigin: (StorageLifecycleShimOrigin, Int32, Int32) throws -> StorageIdentity.DescriptorIdentity
    /// Required trusted integration: stable authenticated incarnation/SPKI and
    /// canonical lock pre/postflight observations. Must not retain lock descriptors.
    private let verifyCandidate: (Adoption.Request, BootstrapAuditIdentity, DispatchTime) throws -> BootstrapPrincipal

    init(ownerUID: uid_t, team: String, expectedRootPublicKey: StorageIdentity.RootPublicKey,
         worker: StorageBootstrapLifecycleChildWorker, policy: StorageLifecycleNativePolicy = .production,
         lookupOrigin: @escaping (String) throws -> StorageLifecycleShimOrigin?,
         verifyFreshOrigin: @escaping (StorageLifecycleShimOrigin, Int32, Int32) throws -> StorageIdentity.DescriptorIdentity,
         verifyCandidate: @escaping (Adoption.Request, BootstrapAuditIdentity, DispatchTime) throws -> BootstrapPrincipal) {
        processes = StorageBootstrapProcesses(ownerUID: ownerUID, team: team, policy: policy)
        bindings = StorageBootstrapBindings(ownerUID: ownerUID)
        root = expectedRootPublicKey; self.worker = worker
        self.lookupOrigin = lookupOrigin; self.verifyFreshOrigin = verifyFreshOrigin
        self.verifyCandidate = verifyCandidate
    }

    private var requestCheck: (() throws -> Void)?
    private var requestDeadline: DispatchTime?

    /// Worker-only dynamic scope; neither observation nor descriptors escape the RPC.
    func withRequest<T>(deadline: DispatchTime, check: () throws -> Void, _ body: () throws -> T) throws -> T {
        try worker.requireCurrent()
        guard requestCheck == nil else { throw BootstrapFailure(.unavailable) }
        return try withoutActuallyEscaping(check) { scoped in
            requestCheck = scoped; requestDeadline = deadline
            defer { requestCheck = nil; requestDeadline = nil }
            try checkRequest()
            let result = Result { try body() }
            try checkRequest()
            return try result.get()
        }
    }
    func checkRequest() throws {
        guard let requestCheck, let requestDeadline, DispatchTime.now() < requestDeadline else {
            throw BootstrapFailure(.unavailable)
        }
        try requestCheck()
    }

    private var resumeEnrollment: (origin: StorageLifecycleShimOrigin, expectedBacking: StorageIdentity.DescriptorIdentity, check: () throws -> Void)?

    /// Exact native enrollment proof, scoped to the worker. Ordinary routes keep
    /// their publication fence; no DTO can enable this override.
    private func withResumeEnrollment<T>(origin: StorageLifecycleShimOrigin, expectedBacking: StorageIdentity.DescriptorIdentity, check: () throws -> Void,
                                         _ body: () throws -> T) throws -> T {
        try worker.requireCurrent()
        guard resumeEnrollment == nil else { throw BootstrapFailure(.unavailable) }
        return try withoutActuallyEscaping(check) { scoped in
            resumeEnrollment = (origin, expectedBacking, scoped)
            defer { resumeEnrollment = nil }
            try scoped(); let result = try body(); try scoped(); return result
        }
    }

    /// Initial enrollment is separate from this transport's greeting. ROOT calls
    /// recordOrigin with real descriptors and this proof before accepting a channel.
    /// This method never persists/caches an origin itself or adopts an existing VM.
    func freshOrigin(_ origin: StorageLifecycleShimOrigin, rootFD: Int32, backingFD: Int32) throws {
        try worker.requireCurrent()
        let enrollment = resumeEnrollment
        if let enrollment {
            guard enrollment.origin == origin else { throw BootstrapFailure(.unauthorized) }
            try enrollment.check()
        } else { try guardPublication?(origin.wire.binding.store) }
        try origin.wire.validate()
        guard origin.wire.rootPublicKey == root.publicData else { throw BootstrapFailure(.unauthorized) }
        let binding = try origin.wire.binding.value()
        try pinOriginal(origin)
        let expectedBacking = try enrollment?.expectedBacking ?? verifyFreshOrigin(origin, rootFD, backingFD)
        try Self.withEnrollmentBacking(bindings, binding: binding, rootFD: rootFD, backingFD: backingFD,
            expectedBacking: expectedBacking) {
            if let enrollment { try enrollment.check() }
            else {
                guard try verifyFreshOrigin(origin, rootFD, backingFD) == expectedBacking else {
                    throw BootstrapFailure(.unauthorized)
                }
            }
        }
        try pinOriginal(origin)
    }

    /// The expectation comes only from the protected authenticated transaction.
    /// Both sides of enrollment writes/proofs must match its exact live device.
    static func withEnrollmentBacking<T>(_ bindings: StorageBootstrapBindings, binding: StorageIdentity.StoreBinding,
                                          rootFD: Int32, backingFD: Int32,
                                          expectedBacking: StorageIdentity.DescriptorIdentity,
                                          _ body: () throws -> T) throws -> T {
        try bindings.verify(binding, rootFD: rootFD, backingFD: backingFD, expectedBacking: expectedBacking)
        let result = try body()
        try bindings.verify(binding, rootFD: rootFD, backingFD: backingFD, expectedBacking: expectedBacking)
        return result
    }

    private func pinOriginal(_ origin: StorageLifecycleShimOrigin) throws {
        guard origin.shim.uniqueID != origin.originalController.uniqueID,
              origin.shim.pid != origin.originalController.pid,
              try processes.daemon(audit: Self.audit(origin.originalDaemon)) == origin.originalDaemon,
              try processes.child(audit: Self.audit(origin.originalController), daemon: origin.originalDaemon) == origin.originalController,
              try processes.storageShim(audit: Self.audit(origin.shim), daemon: origin.originalDaemon) == origin.shim else {
            throw BootstrapFailure(.unauthorized)
        }
    }

    func candidate(_ request: Adoption.Request, peer: BootstrapAuditIdentity) throws -> BootstrapPrincipal {
        try worker.requireCurrent(); try request.validate()
        try guardPublication?(request.origin.binding.store)
        guard peer.data == request.daemonAudit else { throw BootstrapFailure(.unauthorized) }
        let daemon = try processes.daemon(audit: peer)
        try checkRequest()
        guard let deadline = requestDeadline else { throw BootstrapFailure(.unavailable) }
        let result = Result { try verifyCandidate(request, peer, deadline) }
        try checkRequest()
        let principal = try result.get()
        _ = try StorageIdentity.IncarnationID(principal.incarnation)
        _ = try StorageIdentity.Ed25519SPKI(publicData: principal.controllerSPKI)
        guard principal.daemon == daemon, daemon.uniqueID == request.daemonUniqueID,
              principal.child.auditToken == request.controllerAudit,
              principal.child.uniqueID == request.controllerUniqueID,
              try processes.child(audit: Self.audit(principal.child), daemon: daemon) == principal.child,
              try processes.daemon(audit: peer) == daemon else { throw BootstrapFailure(.unauthorized) }
        return principal
    }

    func liveness(_ process: BootstrapProcess) -> BootstrapLiveness {
        guard (try? worker.requireCurrent()) != nil else { return .unknown }
        return processes.liveness(process)
    }

    /// Input MUST be an actually received Mach message, never a local dictionary.
    /// The wire origin selects a protected record only; it cannot enroll or update it.
    func greet(_ message: xpc_object_t, reply: xpc_object_t, peer: xpc_connection_t) throws {
        try worker.requireCurrent()
        let record = try lock.withLock {
            peers = peers.filter { $0.value.open }
            if let existing = peers[ObjectIdentifier(peer)] { return existing }
            guard peers.count < 128 else { throw BootstrapFailure(.capacityExceeded) }
            let value = Peer(peer); peers[ObjectIdentifier(peer)] = value; return value
        }
        do {
            let greeting = try Self.decodeGreeting(message)
            try guardPublication?(greeting.binding.store)
            guard let origin = try lookupOrigin(greeting.binding.store), origin.wire == greeting,
                  greeting.rootPublicKey == root.publicData else { throw BootstrapFailure(.unauthorized) }
            var token = audit_token_t(); lifecycleAdoptionAudit(message, &token)
            _ = try processes.registeredStorageShim(audit: BootstrapAuditIdentity(token: token), origin: origin.shim)
            try lock.withLock {
                guard record.open, record.pending == nil,
                      record.origin == nil || record.origin == origin,
                      !peers.values.contains(where: { other in
                          guard other !== record, other.open, let old = other.origin else { return false }
                          return old.shim.uniqueID == origin.shim.uniqueID || old.wire.binding.store == greeting.binding.store
                      }) else { throw BootstrapFailure(.unauthorized) }
                record.origin = origin
            }
            xpc_dictionary_set_bool(reply, "ok", true)
        } catch { revoke(record); throw error }
    }

    /// No disconnect or missing reply is positive native process-exit evidence.
    func disconnected(_ peer: xpc_connection_t) {
        let record = lock.withLock { peers[ObjectIdentifier(peer)] }
        if let record { revoke(record) }
    }

    func registeredShim(_ origin: StorageLifecycleShimOrigin) throws {
        try worker.requireCurrent()
        _ = try endpoint(origin)
        _ = try processes.registeredStorageShim(audit: Self.audit(origin.shim), origin: origin.shim)
    }

    private func endpoint(_ origin: StorageLifecycleShimOrigin) throws -> Peer {
        try guardPublication?(origin.wire.binding.store)
        try origin.wire.validate()
        guard origin.wire.rootPublicKey == root.publicData,
              try lookupOrigin(origin.wire.binding.store) == origin else { throw BootstrapFailure(.unauthorized) }
        // Missing transport after helper restart is recoverable only for the
        // exact protected, still-live native shim. It is not death or authority.
        _ = try processes.registeredStorageShim(audit: Self.audit(origin.shim), origin: origin.shim)
        return try lock.withLock {
            let matches = peers.values.filter { $0.open && $0.origin == origin }
            guard !matches.isEmpty else { throw BootstrapFailure(.unavailable) }
            guard matches.count == 1, let record = matches.first else { throw BootstrapFailure(.unauthorized) }
            return record
        }
    }

    func fence(_ challenge: Adoption.Challenge, origin: StorageLifecycleShimOrigin) throws {
        try worker.requireCurrent(); try challenge.validate()
        guard challenge.request.origin == origin.wire else { throw BootstrapFailure(.unauthorized) }
        try exchange(operation: Self.fenceOperation, bytes: Adoption.encode(challenge),
                     digest: challenge.digest, origin: origin)
    }

    /// Distinct commit wire/digest: a fence acknowledgement cannot authorize commit.
    /// ROOT must durably commit its owner record before invoking this method.
    func commit(_ request: Adoption.Request, origin: StorageLifecycleShimOrigin) throws {
        try worker.requireCurrent(); try request.validate()
        guard request.origin == origin.wire else { throw BootstrapFailure(.unauthorized) }
        let commit = try Adoption.Commit(request: request)
        try exchange(operation: Self.commitOperation, bytes: Adoption.encode(commit),
                     digest: commit.digest, origin: origin)
    }

    func service(_ adoption: Adoption.Request, grant: Lifecycle.Grant, expected: Lifecycle.ServiceState,
                 origin: StorageLifecycleShimOrigin) throws -> Adoption.ServiceReply {
        try worker.requireCurrent(); try checkRequest()
        var nonce = Data(count: 32)
        guard nonce.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }) == errSecSuccess else { throw BootstrapFailure(.unavailable) }
        let challenge = try Adoption.ServiceChallenge(adoption: adoption, grant: grant, expected: expected,
            counter: counter.next(), nonce: nonce, expiresUnixMS: UInt64(Date().timeIntervalSince1970 * 1000) + 30_000)
        let bytes = try exchange(operation: "storage-lifecycle-adopted-service", bytes: Adoption.encode(challenge),
            digest: challenge.digest, origin: origin, expectation: .service(challenge))
        return try Adoption.decodeServiceReply(bytes, challenge: challenge)
    }

    func serviceChange(_ adoption: Adoption.Request, change: Lifecycle.ServiceChangeRequest,
                       targetBoot: StorageLifecycleBootTrust?, completed: Lifecycle.ServiceChangeConfirmation?,
                       nonce: Data, origin: StorageLifecycleShimOrigin) throws -> Adoption.ServiceChangeReply {
        try worker.requireCurrent(); try checkRequest()
        guard adoption.origin == origin.wire else { throw BootstrapFailure(.unauthorized) }
        let challenge = try Adoption.ServiceChangeChallenge(adoption: adoption, change: change,
            targetBoot: targetBoot, completed: completed, counter: counter.next(), nonce: nonce,
            expiresUnixMS: UInt64(Date().timeIntervalSince1970 * 1000) + 30_000)
        let bytes = try exchange(operation: "storage-lifecycle-adopted-service-change", bytes: Adoption.encode(challenge),
            digest: challenge.digest, origin: origin, expectation: .serviceChange(challenge))
        return try Adoption.decodeServiceChangeReply(bytes, challenge: challenge)
    }

    func handoff(_ signed: StorageLifecycleHandoffProtocol.SignedRequest,
                 expectedService: Lifecycle.ServiceState, origin: StorageLifecycleShimOrigin,
                 daemon: BootstrapProcess, nonce: Data) throws -> StorageLifecycleHandoffProtocol.Result {
        try worker.requireCurrent(); try checkRequest()
        guard try processes.daemon(audit: Self.audit(daemon)) == daemon else { throw BootstrapFailure(.unauthorized) }
        let challenge = try StorageLifecycleHandoffShimProtocol.Challenge(origin: origin.wire, signed: signed,
            expected: expectedService, counter: counter.next(), nonce: nonce,
            expiresUnixMS: UInt64(Date().timeIntervalSince1970 * 1000) + 30_000)
        let bytes = try exchange(operation: StorageLifecycleHandoffShimProtocol.operation,
            bytes: StorageLifecycleHandoffShimProtocol.encode(challenge), digest: challenge.digest,
            origin: origin, expectation: .handoff(challenge))
        guard try processes.daemon(audit: Self.audit(daemon)) == daemon else { throw BootstrapFailure(.unauthorized) }
        return try StorageLifecycleHandoffShimProtocol.decodeReply(bytes, challenge: challenge).result
    }

    private enum ExchangeError: Error { case busy }

    @discardableResult
    private func exchange(operation: String, bytes: Data, digest: Data, origin: StorageLifecycleShimOrigin,
                          expectation: Expectation = .acknowledgement) throws -> Data {
        try checkRequest()
        let record = try endpoint(origin)
        do {
            _ = try processes.registeredStorageShim(audit: Self.audit(origin.shim), origin: origin.shim)
            guard let deadline = requestDeadline else { throw BootstrapFailure(.unavailable) }
            let pending = Pending(digest: digest, deadline: min(.now() + Self.timeout, deadline), expectation: expectation)
            try lock.withLock {
                guard record.open, record.origin == origin, record.pending == nil else { throw BootstrapFailure(.unauthorized) }
                record.pending = pending
            }
            let request = xpc_dictionary_create(nil, nil, 0)
            xpc_dictionary_set_string(request, "operation", operation)
            bytes.withUnsafeBytes { xpc_dictionary_set_data(request, "request", $0.baseAddress, $0.count) }
            // Never target the synchronous worker with a reply callback.
            xpc_connection_send_message_with_reply(record.connection, request, callbacks) { [self] response in
                receive(response, record: record, pending: pending, shim: origin.shim)
            }
            guard pending.signal.wait(timeout: pending.deadline) == .success else {
                throw BootstrapFailure(.unavailable)
            }
            try lock.withLock {
                guard record.open, record.pending === pending, pending.acknowledged else { throw BootstrapFailure(.unauthorized) }
            }
            _ = try processes.registeredStorageShim(audit: Self.audit(origin.shim), origin: origin.shim)
            try lock.withLock {
                guard record.open, record.pending === pending, pending.acknowledged else { throw BootstrapFailure(.unauthorized) }
                record.pending = nil
            }
            try checkRequest()
            if pending.busy { throw ExchangeError.busy }
            guard let response = pending.response else { throw BootstrapFailure(.unavailable) }
            return response
        } catch ExchangeError.busy {
            // A correlated authenticated refusal proves no completion. Preserve
            // the registered channel and exact durable ROOT transaction for retry.
            throw BootstrapFailure(.unavailable)
        } catch {
            revoke(record)
            try checkRequest()
            throw error
        }
    }

    private func receive(_ response: xpc_object_t, record: Peer, pending: Pending, shim: BootstrapProcess) {
        do {
            try lock.withLock {
                guard record.open, record.pending === pending, !pending.acknowledged,
                      DispatchTime.now() < pending.deadline else { throw BootstrapFailure(.unauthorized) }
            }
            guard xpc_get_type(response) == XPC_TYPE_DICTIONARY else { throw BootstrapFailure(.unavailable) }
            var token = audit_token_t(); lifecycleAdoptionAudit(response, &token)
            _ = try processes.registeredStorageShim(audit: BootstrapAuditIdentity(token: token), origin: shim)
            if case .handoff = pending.expectation,
               let ok = xpc_dictionary_get_value(response, "ok"), xpc_get_type(ok) == XPC_TYPE_BOOL,
               !xpc_bool_get_value(ok), let code = xpc_dictionary_get_string(response, "code"),
               String(cString: code) == "worker-busy" {
                try lock.withLock {
                    guard record.open, record.pending === pending, !pending.acknowledged,
                          DispatchTime.now() < pending.deadline else { throw BootstrapFailure(.unauthorized) }
                    pending.busy = true; pending.acknowledged = true; pending.signal.signal()
                }
                return
            }
            let bytes = try Self.payload(response, key: "reply")
            switch pending.expectation {
            case .handoff(let challenge):
                guard challenge.isFresh(at: UInt64(Date().timeIntervalSince1970 * 1000)) else { throw BootstrapFailure(.unavailable) }
                _ = try StorageLifecycleHandoffShimProtocol.decodeReply(bytes, challenge: challenge)
            case .service(let challenge):
                guard challenge.isFresh(at: UInt64(Date().timeIntervalSince1970 * 1000)) else { throw BootstrapFailure(.unavailable) }
                _ = try Adoption.decodeServiceReply(bytes, challenge: challenge)
            case .serviceChange(let challenge):
                guard challenge.isFresh(at: UInt64(Date().timeIntervalSince1970 * 1000)) else { throw BootstrapFailure(.unavailable) }
                _ = try Adoption.decodeServiceChangeReply(bytes, challenge: challenge)
            case .acknowledgement:
                let reply = try Adoption.decodeReply(bytes)
                guard reply.challengeSHA256 == pending.digest else { throw BootstrapFailure(.unauthorized) }
            }
            try lock.withLock {
                guard record.open, record.pending === pending, !pending.acknowledged,
                      DispatchTime.now() < pending.deadline else { throw BootstrapFailure(.unauthorized) }
                pending.response = bytes; pending.acknowledged = true; pending.signal.signal()
            }
        } catch { revoke(record) }
    }

    /// Cancel only this ROOT proof connection, never the shim's workload-control
    /// channel or committed session. A timed-out exchange retries after an exact
    /// journal-origin re-greet; neither fence nor commit state is rolled back.
    private func revoke(_ record: Peer) {
        let cancel = lock.withLock {
            guard record.open else { return false }
            record.open = false; record.pending?.signal.signal(); record.pending = nil
            if peers[ObjectIdentifier(record.connection)] === record {
                peers.removeValue(forKey: ObjectIdentifier(record.connection))
            }
            return true
        }
        if cancel { xpc_connection_cancel(record.connection) }
    }

    static func decodeEnrollment(_ message: xpc_object_t) throws -> Adoption.Origin {
        guard let fd = xpc_dictionary_get_value(message, "backing-fd"), xpc_get_type(fd) == XPC_TYPE_FD else {
            throw BootstrapFailure(.invalidRequest)
        }
        return try decodeOrigin(message, operation: enrollmentOperation)
    }

    static func decodeGreeting(_ message: xpc_object_t) throws -> Adoption.Origin {
        try decodeOrigin(message, operation: greetingOperation)
    }

    private static func decodeOrigin(_ message: xpc_object_t, operation expected: String) throws -> Adoption.Origin {
        guard xpc_get_type(message) == XPC_TYPE_DICTIONARY,
              let operation = xpc_dictionary_get_string(message, "operation"), String(cString: operation) == expected,
              let role = xpc_dictionary_get_string(message, "role"), String(cString: role) == "storage-shim" else {
            throw BootstrapFailure(.invalidRequest)
        }
        return try Adoption.decodeOrigin(payload(message, key: "request"))
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

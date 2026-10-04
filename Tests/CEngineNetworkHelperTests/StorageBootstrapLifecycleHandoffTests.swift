import CEngineCore
import CryptoKit
import Darwin
import Foundation
import Testing
@testable import StorageBootstrapHelper

private typealias L = StorageLifecycleProtocol
private typealias C = StorageLifecycleColdRootProtocol
private func uuid() -> String { UUID().uuidString.lowercased() }
private func process(_ pid: Int32) -> BootstrapProcess {
    var token = audit_token_t(); token.val = (501, 501, 20, 501, 20, UInt32(pid), 1, 2)
    return .init(pid: pid, startSeconds: 1, startMicroseconds: 0, boot: "test-boot",
        signingIdentity: "unsigned-test-seam", uniqueID: UInt64(pid), pidVersion: 2,
        auditToken: BootstrapAuditIdentity(token: token).data)
}
private final class HandoffJournal: StorageLifecycleJournal, StorageLifecycleAdoptionJournal {
    let key: Curve25519.Signing.PrivateKey
    var bytes: Data?
    var writes = 0, signs = 0
    var failAt: Int?
    var afterWrite: (() throws -> Void)?
    init(key: Curve25519.Signing.PrivateKey) { self.key = key }
    func load() throws -> Data? { bytes }
    func rootPublicKey() throws -> Data { key.publicKey.rawRepresentation }
    func lifecycleRootPublicKey() throws -> StorageIdentity.RootPublicKey { try .init(publicData: rootPublicKey()) }
    func checkpoint(_ bytes: Data) throws {
        writes += 1
        if failAt == writes { throw BootstrapFailure(.unavailable) }
        self.bytes = bytes; try afterWrite?()
    }
    func signLifecycle(_ grant: L.Grant) throws -> L.SignedGrant {
        signs += 1; return try .init(grant: grant, signature: key.signature(for: grant.signingBytes))
    }
    func signHandoff(_ request: StorageLifecycleHandoffProtocol.Request) throws -> StorageLifecycleHandoffProtocol.SignedRequest {
        signs += 1; return try .init(request: request, signature: key.signature(for: request.signingBytes))
    }
    func signColdOpen(_ request: StorageLifecycleColdProtocol.Request) throws -> StorageLifecycleColdProtocol.SignedOpen {
        signs += 1; return try .init(request: request, signature: key.signature(for: request.signingBytes))
    }
    func signServiceChange(_ request: L.ServiceChangeRequest) throws -> L.SignedServiceChange {
        try .init(request: request, signature: key.signature(for: request.signingBytes))
    }
}
/// Explicit unsigned logical seam; not native acceptance or production proof.
private final class HandoffChecks: StorageLifecycleProcessChecking, StorageLifecycleAdoptionChecking,
    StorageLifecycleFreshBindingChecking, StorageLifecycleColdChecking, StorageLifecycleHandoffChecking {
    var handoffCalls = 0
    var applyPending = false
    var predecessorRevision: UInt64 = 1, pendingRevision: UInt64 = 2, fenceRevision: UInt64 = 5
    var failProofAt: Int?
    var forgedNonce = false, forgedRevision = false
    var beforeProof: (() throws -> Void)?
    func handoff(_ signed: StorageLifecycleHandoffProtocol.SignedRequest, expectedService: L.ServiceState,
                 origin: StorageLifecycleShimOrigin, daemon: BootstrapProcess, nonce: Data) throws -> StorageLifecycleHandoffProtocol.Result {
        handoffCalls += 1; nonces.append(nonce); try beforeProof?()
        if failProofAt == handoffCalls { throw BootstrapFailure(.unavailable) }
        let request = signed.request
        return try .init(request: request, nonce: forgedNonce ? Data(repeating: 0, count: 32) : nonce,
            appliedGrant: applyPending ? request.pending : request.predecessor,
            appliedServiceEpoch: expectedService.context.serviceEpoch,
            appliedRevision: forgedRevision ? 4 : (applyPending ? pendingRevision : predecessorRevision), fenceRevision: fenceRevision)
    }
    var root = "", service = uuid(), ca = String(repeating: "a", count: 64), server = String(repeating: "b", count: 64)
    var rootPublicKey = Data()
    var revision: UInt64 = 1
    var lives: [Int32: BootstrapLiveness] = [:]
    var nonces: [Data] = []
    var mountedCalls = 0
    var mountedAllowed = true
    var adoptionPrincipal: BootstrapPrincipal?
    private var formed: [String: StorageLifecycleFreshOrigin] = [:]
    func candidate(_ c: StorageIdentity.Candidate, daemon: BootstrapProcess, grant: L.Grant) throws -> BootstrapPrincipal {
        let p = BootstrapPrincipal(daemon: daemon, child: process(c.childPIDHint), incarnation: c.incarnationID.rawValue,
            controllerSPKI: c.publicKey.publicData)
        try validateRecipient(p, daemon: daemon, grant: grant); return p
    }
    func liveness(_ p: BootstrapProcess) -> BootstrapLiveness { lives[p.pid] ?? .alive }
    func validateRecipient(_ p: BootstrapPrincipal, daemon: BootstrapProcess, grant: L.Grant) throws {
        guard p.daemon == daemon, liveness(p.daemon) == .alive, liveness(p.child) == .alive,
              try StorageIdentity.Ed25519SPKI(publicData: p.controllerSPKI).fingerprint.rawValue == grant.newKey else {
            throw BootstrapFailure(.unauthorized)
        }
    }
    func serviceBootTrust(_ p: BootstrapPrincipal, daemon: BootstrapProcess, grant: L.Grant) throws -> StorageLifecycleBootTrust {
        try validateRecipient(p, daemon: daemon, grant: grant)
        return try .init(identity: grant.identity, serviceEpoch: service, tlsRootSHA256: ca, serverSPKI: server, bootstrapKey: root)
    }
    func serviceResult(_ p: BootstrapPrincipal, daemon: BootstrapProcess, grant: L.Grant, nonce: Data,
                       boot: StorageLifecycleBootTrust, changeRequest: L.ServiceChangeRequest?,
                       confirmation: L.ServiceChangeConfirmation?) throws -> L.ServiceResult {
        try validateRecipient(p, daemon: daemon, grant: grant); nonces.append(nonce)
        return try .init(identity: grant.identity, grant: grant, nonce: nonce, serviceEpoch: service,
            controllerEpoch: grant.expectedEpoch + 1, controllerKey: grant.newKey, openRevision: revision)
    }
    func receipt(_ p: BootstrapPrincipal, daemon: BootstrapProcess, grant: L.Grant, nonce: Data) throws -> L.Receipt {
        try validateRecipient(p, daemon: daemon, grant: grant); nonces.append(nonce)
        return try .init(grant: grant, nonce: nonce, serviceEpoch: service, revision: revision)
    }
    func verifyFresh(_ binding: StorageIdentity.StoreBinding, grant: L.Grant, daemon: BootstrapProcess,
                     principal: BootstrapPrincipal, rootFD: Int32, backingFD: Int32) throws -> StorageLifecycleFreshOrigin {
        if let existing = formed[grant.id] { return existing }
        let greeting = try StorageLifecycleFreshProtocol.Greeting(channelID: uuid(), daemonUniqueID: daemon.uniqueID,
            rootPublicKey: rootPublicKey, store: binding.storeID.rawValue, shimLaunchUUID: uuid(),
            guestBootNonce: uuid(), operationUUID: uuid(), ext4UUID: binding.expectedExt4UUID.rawValue,
            bytes: binding.backing.size, initramfsSHA256: String(repeating: "c", count: 64),
            device: 1, inode: binding.backing.identity.inode,
            volumeUUID: binding.backing.identity.volumeUUID.rawValue)
        let origin = StorageLifecycleFreshOrigin(greeting: greeting, shim: process(22), daemon: daemon, grant: grant, principal: principal)
        formed[grant.id] = origin
        return origin
    }
    func freshOrigin(_ origin: StorageLifecycleShimOrigin, rootFD: Int32, backingFD: Int32) throws {}
    func candidate(_ request: StorageLifecycleAdoptionProtocol.Request, peer: BootstrapAuditIdentity) throws -> BootstrapPrincipal {
        guard let adoptionPrincipal else { throw BootstrapFailure(.unauthorized) }; return adoptionPrincipal
    }
    func registeredShim(_ origin: StorageLifecycleShimOrigin) throws {}
    func fence(_ challenge: StorageLifecycleAdoptionProtocol.Challenge, origin: StorageLifecycleShimOrigin) throws {}
    func commit(_ request: StorageLifecycleAdoptionProtocol.Request, origin: StorageLifecycleShimOrigin) throws {}
    func mounted(request: C.Prepare, unsignedGrant: L.Grant, signedOpenDigest: String,
                 baseEpoch: UInt64, daemon: BootstrapProcess) throws -> StorageLifecycleShimOrigin {
        mountedCalls += 1
        guard mountedAllowed else { throw BootstrapFailure(.unavailable) }
        return try .init(wire: request.mountedGreeting.successorOrigin, shim: process(22),
            originalDaemon: daemon, originalController: process(request.candidate.childPIDHint))
    }
}
private final class HandoffFixture {
    let journal: HandoffJournal, adoptionJournal: HandoffJournal
    let checks = HandoffChecks()
    let disk: StorageIdentity.StoreBinding
    let initial: StorageIdentity.Candidate, candidate: StorageIdentity.Candidate
    let daemon = process(20)
    var authority: StorageBootstrapLifecycleAuthority
    var adoption: StorageBootstrapLifecycleAdoptionAuthority
    let grant: L.Grant
    let request: C.Prepare
    init() throws {
        let key = Curve25519.Signing.PrivateKey()
        journal = HandoffJournal(key: key); adoptionJournal = HandoffJournal(key: key)
        checks.root = try journal.lifecycleRootPublicKey().fingerprint.rawValue
        checks.rootPublicKey = try journal.rootPublicKey()
        let volume = try StorageIdentity.FilesystemUUID("11111111-1111-4111-8111-111111111111")
        disk = try .init(storeID: .init(uuid()), root: .init(volumeUUID: volume, inode: 2),
            backing: .init(identity: .init(volumeUUID: volume, inode: 3), size: 4096), expectedExt4UUID: volume)
        initial = try .init(publicKey: .init(rawPublicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation),
            childPIDHint: 11, incarnationID: .init(uuid()))
        candidate = try .init(publicKey: .init(rawPublicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation),
            childPIDHint: 21, incarnationID: .init(uuid()))
        authority = try .init(journal: journal, processes: checks, bindings: checks)
        adoption = try .init(journal: adoptionJournal, processes: checks)
        grant = try authority.provision(id: uuid(), binding: disk, candidate: initial, daemon: process(10), rootFD: 1, backingFD: 2).grant
        _ = try authority.complete(identity: grant.identity, id: grant.id, daemon: process(10))
        let old = try StorageLifecycleAdoptionProtocol.Origin(binding: .init(disk), rootPublicKey: journal.rootPublicKey(),
            shimLaunchUUID: uuid(), specSHA256: String(repeating: "c", count: 64))
        try adoption.recordOrigin(.init(wire: old, shim: process(12), originalDaemon: process(10), originalController: process(11)),
            rootFD: 1, backingFD: 2)
        try authority.configureCold(adoption: adoption, mounted: checks)
        for pid: Int32 in [10, 11, 12] { checks.lives[pid] = .exited }
        let status = try authority.statusCold(identity: grant.identity)
        let launch = try StorageLifecycleColdProtocol.Launch(shimLaunchUUID: uuid(), specSHA256: String(repeating: "d", count: 64),
            initramfsSHA256: String(repeating: "e", count: 64), ext4UUID: volume.rawValue, bytes: 4096)
        let greeting = try StorageLifecycleColdShimProtocol.Greeting(channelID: uuid(), daemonUniqueID: 20,
            rootPublicKey: journal.rootPublicKey(), binding: .init(disk),
            bootBinding: .init(shimLaunchUUID: launch.shimLaunchUUID, guestBootNonce: uuid(), ext4UUID: volume.rawValue, bytes: 4096),
            launch: launch, heldBackingIdentity: .init(.init(stableIdentity: disk.backing.identity, device: 1)))
        request = try .init(operationID: uuid(), identity: grant.identity, expectedPredecessor: status.predecessor,
            expectedOrigin: old, expectedAllocatedEpoch: 1, candidate: candidate, mountedGreeting: greeting,
            nowUnixSeconds: 100, lifetimeSeconds: 100)
    }
    func prepareAdoption(pid: Int32 = 20, epoch: UInt64 = 1,
                         superseded: StorageLifecycleAdoptionProtocol.FenceIdentity? = nil) throws
        -> (StorageLifecycleAdoptionProtocol.Request, BootstrapAuditIdentity) {
        let principal = BootstrapPrincipal(daemon: process(pid), child: process(pid + 1), incarnation: uuid(),
            controllerSPKI: candidate.publicKey.publicData)
        checks.adoptionPrincipal = principal
        let request = try StorageLifecycleAdoptionProtocol.Request(id: uuid(),
            origin: adoption.status(store: disk.storeID.rawValue).origin, expectedEpoch: epoch,
            daemonAudit: principal.daemon.auditToken, daemonUniqueID: principal.daemon.uniqueID,
            controllerAudit: principal.child.auditToken, controllerUniqueID: principal.child.uniqueID,
            superseded: superseded)
        let peer = BootstrapAuditIdentity(token: principal.daemon.auditToken.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) })
        try adoption.prepare(request, peer: peer)
        return (request, peer)
    }
    func stage() throws -> L.Grant {
        checks.lives[12] = .alive
        try authority.configureHandoff(adoption: adoption, checking: checks)
        let pending = try authority.issue(operation: .takeover, id: uuid(), identity: grant.identity,
            expectedEpoch: 1, candidate: candidate, daemon: daemon).grant
        checks.lives[20] = .exited; checks.lives[21] = .exited
        return pending
    }
    func recover(_ id: String) throws -> StorageLifecycleHandoffRootProtocol.Completed {
        try authority.recoverHandoff(identity: grant.identity, operationID: id, daemon: process(30))
    }
    func handoffStatus() throws -> StorageLifecycleHandoffRootProtocol.Status {
        try authority.handoffStatus(identity: grant.identity, daemon: process(30))
    }
    func reloadHandoff() throws {
        try reload(); try authority.configureHandoff(adoption: adoption, checking: checks)
    }
    func open() { checks.service = uuid(); checks.ca = String(repeating: "1", count: 64); checks.server = String(repeating: "2", count: 64); checks.revision = 2 }
    func prepare() throws -> C.Prepared { try authority.prepareCold(request, daemon: daemon) }
    func complete(_ prepared: C.Prepared) throws -> C.Completed {
        try authority.completeCold(operationID: request.operationID, signedOpenSHA256: prepared.signedOpenSHA256, daemon: daemon)
    }
    func enroll() throws {
        let (origin, principal, epoch, completion) = try authority.coldOriginPrincipal(binding: disk)
        let seed = try StorageLifecycleColdShimProtocol.ColdEnrollmentSeed(operationID: completion.operationID,
            signedOpenSHA256: completion.signedOpenSHA256, successorOrigin: origin.wire, baseEpoch: epoch)
        try authority.completeColdEnrollment(seed: seed, origin: origin, nativePrincipal: principal)
    }
    func reload() throws {
        authority = try .init(journal: journal, processes: checks, bindings: checks)
        adoption = try .init(journal: adoptionJournal, processes: checks)
        try authority.configureCold(adoption: adoption, mounted: checks)
    }
}

@Suite struct StorageBootstrapLifecycleHandoffTests {
    @Test(arguments: [false, true]) func lostIssueReplyAndExactRecoveryRetry(applied: Bool) throws {
        let f = try HandoffFixture(), pending = try f.stage(), operation = uuid()
        let initial = try f.handoffStatus()
        #expect(initial.pending == pending && initial.operationID == nil)
        f.checks.applyPending = applied
        f.checks.beforeProof = {
            let stored = String(decoding: f.journal.bytes!, as: UTF8.self)
            #expect(stored.contains(operation)) // Prepared before signature release.
        }
        let completion = try f.recover(operation)
        #expect(completion.result.appliedGrant == (applied ? pending : f.grant))
        #expect(completion.service.openRevision == initial.currentService.openRevision)
        #expect(completion.service.boot == initial.currentService.boot)
        if !applied { #expect(completion.receipt == completion.predecessorReceipt) }
        try f.reloadHandoff()
        let status = try f.handoffStatus()
        #expect(status.pending == nil && status.operationID == operation)
        #expect(status.completion?.service == completion.service)
        let writes = f.journal.writes
        let repeated = try f.recover(operation)
        #expect(repeated.service == completion.service)
        #expect(repeated.receipt.revision == completion.receipt.revision)
        #expect(repeated.result.nonce != completion.result.nonce)
        #expect(f.journal.writes == writes)
        #expect(Set(f.checks.nonces).count == f.checks.nonces.count)
        let encoded = try StorageLifecycleHandoffRootProtocol.encode(repeated)
        #expect(try StorageLifecycleHandoffRootProtocol.decodeCompleted(encoded) == repeated)
        // Abandoned serial stays consumed even when Guest retained predecessor.
        let nextCandidate = try StorageIdentity.Candidate(publicKey: .init(rawPublicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation),
            childPIDHint: 31, incarnationID: .init(uuid()))
        let next = try f.authority.issue(operation: .takeover, id: uuid(), identity: f.grant.identity,
            expectedEpoch: repeated.service.context.controllerEpoch, candidate: nextCandidate, daemon: process(30))
        #expect(next.grant.serial > pending.serial)
        let nextStatus = try f.handoffStatus()
        #expect(nextStatus.operationID == nil && nextStatus.completion == nil)
        #expect(nextStatus.pending == next.grant)
        let calls = f.checks.handoffCalls
        #expect(throws: (any Error).self) { try f.recover(operation) } // New recipient is still alive.
        #expect(f.checks.handoffCalls == calls)
        f.checks.beforeProof = nil
        f.checks.revision = 3
        _ = try f.authority.complete(identity: f.grant.identity, id: next.grant.id, daemon: process(30))
        #expect(throws: (any Error).self) { try f.recover(operation) }
        #expect(try f.handoffStatus().operationID == nil)
    }
    @Test(arguments: [false, true], [false, true])
    func repeatedInterruptedRecoveries(firstApplied: Bool, secondApplied: Bool) throws {
        let f = try HandoffFixture(), firstPending = try f.stage(), firstOperation = uuid()
        f.checks.applyPending = firstApplied
        _ = try f.recover(firstOperation)
        let first = try #require(f.handoffStatus().completion)
        let candidate = try StorageIdentity.Candidate(
            publicKey: .init(rawPublicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation),
            childPIDHint: 41, incarnationID: .init(uuid()))
        let pending = try f.authority.issue(operation: .takeover, id: uuid(), identity: f.grant.identity,
            expectedEpoch: first.service.context.controllerEpoch, candidate: candidate, daemon: process(40)).grant
        #expect(pending.serial > firstPending.serial)
        let staged = try f.handoffStatus()
        #expect(staged.pending == pending && staged.operationID == nil && staged.completion == nil)
        try f.reloadHandoff()
        #expect(try f.handoffStatus() == staged)

        let operation = uuid(), calls = f.checks.handoffCalls
        f.checks.lives[40] = .exited; f.checks.lives[41] = .unknown
        #expect(throws: (any Error).self) { try f.recover(operation) }
        #expect(f.checks.handoffCalls == calls)
        f.checks.lives[41] = .exited
        f.checks.applyPending = secondApplied
        f.checks.predecessorRevision = first.receipt.revision
        f.checks.pendingRevision = 6; f.checks.fenceRevision = 8
        f.checks.failProofAt = calls + 1
        #expect(throws: (any Error).self) { try f.recover(operation) }
        let prepared = try f.handoffStatus()
        #expect(prepared.pending == pending && prepared.operationID == operation && prepared.completion == nil)
        #expect(throws: (any Error).self) { try f.recover(firstOperation) }
        try f.reloadHandoff(); f.checks.failProofAt = nil
        let second = try f.recover(operation)
        #expect(second.result.request.predecessor == first.service.grant)
        #expect(second.result.request.pending == pending)
        #expect(second.result.appliedGrant == (secondApplied ? pending : first.service.grant))
        #expect(second.predecessorReceipt == first.receipt)
        #expect(second.service.boot == first.service.boot)
        #expect(second.service.openRevision == first.service.openRevision)
        if !secondApplied { #expect(second.receipt == first.receipt) }
        let status = try f.handoffStatus()
        #expect(status.pending == nil && status.operationID == operation)
        #expect(status.completion?.service == second.service)
        #expect(throws: (any Error).self) { try f.recover(firstOperation) }
        #expect(Set(f.checks.nonces).count == f.checks.nonces.count)
    }
    @Test(arguments: [false, true]) func lostRecoveryCompletionReplyRetriesWithFreshProof(applied: Bool) throws {
        let f = try HandoffFixture(), pending = try f.stage(), operation = uuid()
        f.checks.applyPending = applied
        f.checks.failProofAt = 2 // Completion persisted, but post-publication proof/reply is lost.
        #expect(throws: (any Error).self) { try f.recover(operation) }
        let status = try f.handoffStatus()
        let completion = try #require(status.completion)
        #expect(status.pending == nil && status.operationID == operation)
        #expect(completion.result.appliedGrant == (applied ? pending : f.grant))
        let writes = f.journal.writes
        try f.reloadHandoff()
        f.checks.failProofAt = 3
        #expect(throws: (any Error).self) { try f.recover(operation) }
        #expect(f.journal.writes == writes) // Durable metadata alone cannot release a reply.
        f.checks.failProofAt = nil
        let repeated = try f.recover(operation)
        #expect(repeated.signedRequest == completion.signedRequest)
        #expect(repeated.service == completion.service)
        #expect(repeated.receipt.grant == completion.receipt.grant)
        #expect(repeated.receipt.revision == completion.receipt.revision)
        #expect(repeated.result.fenceRevision == completion.result.fenceRevision)
        #expect(repeated.result.nonce != completion.result.nonce)
        #expect(f.checks.handoffCalls == 5 && f.journal.writes == writes)
        #expect(Set(f.checks.nonces).count == f.checks.nonces.count)
    }
    @Test(arguments: [1, 2]) func nativeFailureKeepsPreparedOrCommittedForRetry(call: Int) throws {
        let f = try HandoffFixture(); _ = try f.stage(); let operation = uuid()
        f.checks.failProofAt = call
        #expect(throws: (any Error).self) { try f.recover(operation) }
        let status = try f.handoffStatus()
        #expect(status.operationID == operation)
        #expect((status.pending != nil) == (call == 1))
        if call == 1 {
            #expect(throws: (any Error).self) { try f.authority.read(identity: f.grant.identity, id: f.grant.id, daemon: process(10)) }
            #expect(throws: (any Error).self) { try f.authority.guardHandoffPublication(store: f.grant.identity.store) }
            try f.authority.guardColdPublication(store: f.grant.identity.store) // Greeting remains reachable.
        }
        try f.reloadHandoff(); f.checks.failProofAt = nil
        _ = try f.recover(operation)
    }
    @Test(arguments: [1, 2]) func checkpointFailureNeverClaimsRollback(offset: Int) throws {
        let f = try HandoffFixture(); _ = try f.stage(); let operation = uuid()
        f.journal.failAt = f.journal.writes + offset
        #expect(throws: (any Error).self) { try f.recover(operation) }
        #expect(f.checks.handoffCalls == (offset == 1 ? 0 : 1))
        f.journal.failAt = nil; try f.reloadHandoff()
        _ = try f.recover(operation)
    }
    @Test(arguments: [false, true]) func forgedNonceOrMixedPredecessorReceiptIsRejected(nonce: Bool) throws {
        let f = try HandoffFixture(); _ = try f.stage(); let operation = uuid()
        f.checks.forgedNonce = nonce; f.checks.forgedRevision = !nonce
        #expect(throws: (any Error).self) { try f.recover(operation) }
        #expect(try f.handoffStatus().pending != nil)
        f.checks.forgedNonce = false; f.checks.forgedRevision = false
        _ = try f.recover(operation)
    }
    @Test(arguments: [10, 11, 20, 21]) func ambiguousFormerTupleNeverReachesGuest(pid: Int32) throws {
        let f = try HandoffFixture(); _ = try f.stage()
        f.checks.lives[pid] = .unknown
        #expect(throws: (any Error).self) { try f.recover(uuid()) }
        #expect(f.checks.handoffCalls == 0)
    }
    @Test func pendingAdoptionCandidateMustAlsoBePositivelyDead() throws {
        let f = try HandoffFixture(); _ = try f.stage()
        _ = try f.prepareAdoption(pid: 40)
        #expect(throws: (any Error).self) { try f.recover(uuid()) }
        f.checks.lives[40] = .exited; f.checks.lives[41] = .unknown
        #expect(throws: (any Error).self) { try f.recover(uuid()) }
        #expect(f.checks.handoffCalls == 0)
        f.checks.lives[41] = .exited
        _ = try f.recover(uuid())
    }
    @Test func latestAdoptionAndPostflightDeathAmbiguityAreNotBypassed() throws {
        let f = try HandoffFixture(); _ = try f.stage()
        let (request, peer) = try f.prepareAdoption(pid: 40)
        _ = try f.adoption.complete(request, peer: peer)
        #expect(throws: (any Error).self) { try f.recover(uuid()) }
        f.checks.lives[40] = .exited; f.checks.lives[41] = .exited
        let operation = uuid()
        f.checks.beforeProof = { f.checks.lives[41] = .unknown }
        #expect(throws: (any Error).self) { try f.recover(operation) }
        #expect(try f.handoffStatus().pending != nil)
        f.checks.beforeProof = nil; f.checks.lives[41] = .exited
        _ = try f.recover(operation)
    }
    @Test func closedProjectionRejectsUnknownFieldsAndMixedOutcome() throws {
        let f = try HandoffFixture(); _ = try f.stage()
        let completion = try f.recover(uuid())
        var json = try JSONSerialization.jsonObject(with: StorageLifecycleHandoffRootProtocol.encode(completion)) as! [String: Any]
        json["forged"] = true
        let bytes = try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys, .withoutEscapingSlashes])
        #expect(throws: (any Error).self) { try StorageLifecycleHandoffRootProtocol.decodeCompleted(bytes) }
        let mixed = try StorageLifecycleHandoffProtocol.Result(request: completion.result.request,
            nonce: completion.result.nonce, appliedGrant: completion.result.request.pending,
            appliedServiceEpoch: completion.result.request.serviceEpoch, appliedRevision: 2, fenceRevision: 5)
        #expect(throws: (any Error).self) {
            try StorageLifecycleHandoffRootProtocol.Completed(signedRequest: completion.signedRequest, result: mixed,
                predecessorService: completion.predecessorService, predecessorReceipt: completion.predecessorReceipt,
                service: completion.service, receipt: completion.receipt)
        }
    }
    @Test(arguments: ["cold", "service", "retire"]) func conflictingTransitionsRefuseRecovery(kind: String) throws {
        let f = try HandoffFixture()
        try f.authority.configureHandoff(adoption: f.adoption, checking: f.checks)
        if kind == "cold" { _ = try f.prepare() }
        else {
            f.checks.lives[10] = .alive; f.checks.lives[11] = .alive
            if kind == "retire" {
                _ = try f.authority.issue(operation: .retire, id: uuid(), identity: f.grant.identity,
                    expectedEpoch: 1, candidate: f.initial, daemon: process(10))
            } else {
                let service = try f.handoffStatus().currentService
                _ = try f.authority.stageServiceChange(change: .init(operationID: uuid(), predecessor: service), daemon: process(10))
            }
        }
        #expect(throws: (any Error).self) { try f.handoffStatus() }
        #expect(throws: (any Error).self) { try f.recover(uuid()) }
        #expect(f.checks.handoffCalls == 0)
    }
    @Test func completedCheckpointCannotMixTheAppliedPrincipalOrReceipt() throws {
        let f = try HandoffFixture(); _ = try f.stage(); f.checks.applyPending = true
        _ = try f.recover(uuid())
        var object = try JSONSerialization.jsonObject(with: f.journal.bytes!) as! [String: Any]
        var stores = object["stores"] as! [String: [String: Any]]
        var store = stores[f.grant.identity.store]!
        let latest = store["latestHandoff"] as! [String: Any]
        var current = store["current"] as! [String: Any]
        let predecessor = latest["predecessor"] as! [String: Any]
        current["recipient"] = predecessor["recipient"]
        store["current"] = current; stores[f.grant.identity.store] = store; object["stores"] = stores
        f.journal.bytes = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        #expect(throws: (any Error).self) { try f.reloadHandoff() }
    }
    @Test(arguments: ["pendingHandoff", "latestHandoff"])
    func exactOperationCannotBeReplacedAndOldSnapshotIsNotSilentlyMigrated(missingField: String) throws {
        let f = try HandoffFixture(); _ = try f.stage(); f.checks.failProofAt = 1
        let operation = uuid()
        #expect(throws: (any Error).self) { try f.recover(operation) }
        #expect(throws: (any Error).self) { try f.recover(uuid()) }
        var object = try JSONSerialization.jsonObject(with: f.journal.bytes!) as! [String: Any]
        var stores = object["stores"] as! [String: [String: Any]]
        stores[f.grant.identity.store]!.removeValue(forKey: missingField)
        object["stores"] = stores
        f.journal.bytes = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        let saved = f.journal.bytes
        #expect(throws: (any Error).self) { try f.reloadHandoff() }
        #expect(f.journal.bytes == saved)
    }
}

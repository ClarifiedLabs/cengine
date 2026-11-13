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
    // Exercise the shared lifecycle/adoption metadata bounds, not tiny identities:
    // recovery retains process copies in current, dead-history and pending state.
    return .init(pid: pid, startSeconds: 1_790_963_862, startMicroseconds: 123456,
        boot: String(repeating: "b", count: 64),
        signingIdentity: String(repeating: "s", count: 256),
        uniqueID: UInt64(pid), pidVersion: 2,
        auditToken: BootstrapAuditIdentity(token: token).data)
}
private final class ColdJournal: StorageLifecycleJournal, StorageLifecycleAdoptionJournal {
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
    func signColdOpen(_ request: StorageLifecycleColdProtocol.Request) throws -> StorageLifecycleColdProtocol.SignedOpen {
        signs += 1; return try .init(request: request, signature: key.signature(for: request.signingBytes))
    }
    func signColdObservation(_ request: StorageLifecycleColdObservationProtocol.Request) throws -> StorageLifecycleColdObservationProtocol.SignedRequest {
        signs += 1; return try .init(request: request, signature: key.signature(for: request.signingBytes))
    }
    func signServiceChange(_ request: L.ServiceChangeRequest) throws -> L.SignedServiceChange {
        try .init(request: request, signature: key.signature(for: request.signingBytes))
    }
}
/// Explicit unsigned logical seam; not native acceptance or production proof.
private final class ColdChecks: StorageLifecycleProcessChecking, StorageLifecycleAdoptionChecking,
    StorageLifecycleFreshBindingChecking, StorageLifecycleColdChecking {
    var root = "", service = uuid(), ca = String(repeating: "a", count: 64), server = String(repeating: "b", count: 64)
    var rootPublicKey = Data()
    var revision: UInt64 = 1
    var lives: [Int32: BootstrapLiveness] = [:]
    var nonces: [Data] = []
    var observationCalls = 0
    var observationAllowed = true
    var observationApplied = false
    var beforeObservation: (() throws -> Void)?
    func observe(request: C.Observe, authorization: StorageLifecycleColdObservationProtocol.SignedRequest,
                 daemon: BootstrapProcess) throws -> StorageLifecycleColdObservationProtocol.Observation {
        observationCalls += 1; try beforeObservation?()
        guard observationAllowed else { throw BootstrapFailure(.unavailable) }
        let old = try authorization.request.subjectOpen().request
        let predecessor: StorageLifecycleColdProtocol.Predecessor
        if observationApplied {
            predecessor = try .init(currentGrant: old.takeover.grant, serviceEpoch: service,
                controllerEpoch: old.predecessor.controllerEpoch + 1, controllerKey: old.takeover.grant.newKey,
                openRevision: revision, bootstrapKey: old.predecessor.bootstrapKey)
        } else { predecessor = old.predecessor }
        return try .init(requestSHA256: authorization.request.digest,
            outcome: observationApplied ? .applied : .unchanged, predecessor: predecessor)
    }
    var mountedCalls = 0
    var mountedAllowed = true
    var mountedPID: Int32 = 22
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
        return try .init(wire: request.mountedGreeting.successorOrigin, shim: process(mountedPID),
            originalDaemon: daemon, originalController: process(request.candidate.childPIDHint))
    }
}
private final class ColdFixture {
    let journal: ColdJournal, adoptionJournal: ColdJournal
    let checks = ColdChecks()
    let disk: StorageIdentity.StoreBinding
    let initial: StorageIdentity.Candidate, candidate: StorageIdentity.Candidate
    let daemon = process(20)
    var authority: StorageBootstrapLifecycleAuthority
    var adoption: StorageBootstrapLifecycleAdoptionAuthority
    let grant: L.Grant
    let request: C.Prepare
    init(binding: StorageIdentity.StoreBinding? = nil, adoptedBeforeCold: Bool = false) throws {
        let key = Curve25519.Signing.PrivateKey()
        journal = ColdJournal(key: key); adoptionJournal = ColdJournal(key: key)
        checks.root = try journal.lifecycleRootPublicKey().fingerprint.rawValue
        checks.rootPublicKey = try journal.rootPublicKey()
        let volume = try StorageIdentity.FilesystemUUID("11111111-1111-4111-8111-111111111111")
        disk = try binding ?? .init(storeID: .init(uuid()), root: .init(volumeUUID: volume, inode: 2),
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
        for pid: Int32 in [10, 11] { checks.lives[pid] = .exited }
        if adoptedBeforeCold {
            // Supported strict shutdown first adopts the retained storage shim.
            // Its latest adoption remains in the cold predecessor snapshot.
            let principal = BootstrapPrincipal(daemon: process(40), child: process(41), incarnation: uuid(),
                controllerSPKI: initial.publicKey.publicData)
            checks.adoptionPrincipal = principal
            let adopted = try StorageLifecycleAdoptionProtocol.Request(id: uuid(), origin: old, expectedEpoch: 1,
                daemonAudit: principal.daemon.auditToken, daemonUniqueID: principal.daemon.uniqueID,
                controllerAudit: principal.child.auditToken, controllerUniqueID: principal.child.uniqueID)
            let peer = BootstrapAuditIdentity(token: principal.daemon.auditToken.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) })
            try adoption.prepare(adopted, peer: peer)
            _ = try adoption.complete(adopted, peer: peer)
            checks.lives[40] = .exited; checks.lives[41] = .exited
        }
        checks.lives[12] = .exited
        let status = try authority.statusCold(identity: grant.identity)
        let launch = try StorageLifecycleColdProtocol.Launch(shimLaunchUUID: uuid(), specSHA256: String(repeating: "d", count: 64),
            initramfsSHA256: String(repeating: "e", count: 64), ext4UUID: volume.rawValue, bytes: 4096)
        let greeting = try StorageLifecycleColdShimProtocol.Greeting(channelID: uuid(), daemonUniqueID: 20,
            rootPublicKey: journal.rootPublicKey(), binding: .init(disk),
            bootBinding: .init(shimLaunchUUID: launch.shimLaunchUUID, guestBootNonce: uuid(), ext4UUID: volume.rawValue, bytes: 4096),
            launch: launch, heldBackingIdentity: .init(.init(stableIdentity: disk.backing.identity, device: 1)))
        request = try .init(operationID: uuid(), identity: grant.identity, expectedPredecessor: status.predecessor,
            expectedOrigin: old, expectedAllocatedEpoch: status.allocatedEpoch, candidate: candidate, mountedGreeting: greeting,
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
    /// Reproduce the real shape: durable L2, then original candidate exits before A1.
    func strandAfterL2() throws -> C.Prepared {
        let prepared = try prepare(); open()
        journal.afterWrite = { self.checks.lives[20] = .exited; self.checks.lives[21] = .exited }
        #expect(throws: (any Error).self) { try complete(prepared) }
        journal.afterWrite = nil
        #expect(try adoption.status(store: disk.storeID.rawValue).allocatedEpoch == request.expectedAllocatedEpoch)
        return prepared
    }
    func resolution(_ prepared: C.Prepared) throws -> C.ResolveDead {
        try .init(resolutionID: uuid(), identity: grant.identity, operationID: request.operationID,
            signedOpenSHA256: prepared.signedOpenSHA256)
    }
    func successorRequest(after completion: C.Completed) throws -> C.Prepare {
        let service = completion.successor
        let predecessor = try StorageLifecycleColdProtocol.Predecessor(currentGrant: service.grant,
            serviceEpoch: service.context.serviceEpoch, controllerEpoch: service.context.controllerEpoch,
            controllerKey: service.context.controllerKey, openRevision: service.openRevision,
            bootstrapKey: service.boot.bootstrapKey)
        let old = request.mountedGreeting, oldLaunch = old.launch
        let launch = try StorageLifecycleColdProtocol.Launch(shimLaunchUUID: uuid(), specSHA256: oldLaunch.specSHA256,
            initramfsSHA256: oldLaunch.initramfsSHA256, ext4UUID: oldLaunch.ext4UUID, bytes: oldLaunch.bytes)
        let greeting = try StorageLifecycleColdShimProtocol.Greeting(channelID: uuid(), daemonUniqueID: 30,
            rootPublicKey: old.rootPublicKey, binding: old.binding,
            bootBinding: .init(shimLaunchUUID: launch.shimLaunchUUID, guestBootNonce: uuid(), ext4UUID: launch.ext4UUID, bytes: launch.bytes),
            launch: launch, heldBackingIdentity: old.heldBackingIdentity)
        let candidate = try StorageIdentity.Candidate(
            publicKey: .init(rawPublicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation),
            childPIDHint: 31, incarnationID: .init(uuid()))
        return try .init(operationID: uuid(), identity: grant.identity, expectedPredecessor: predecessor,
            expectedOrigin: completion.successorOrigin, expectedAllocatedEpoch: completion.baseEpoch,
            candidate: candidate, mountedGreeting: greeting, nowUnixSeconds: 101, lifetimeSeconds: 100)
    }
    func observer(_ prepared: C.Prepared) throws -> C.Observe {
        let old = request.mountedGreeting, oldLaunch = old.launch
        let launch = try StorageLifecycleColdProtocol.Launch(shimLaunchUUID: uuid(), specSHA256: oldLaunch.specSHA256,
            initramfsSHA256: oldLaunch.initramfsSHA256, ext4UUID: oldLaunch.ext4UUID, bytes: oldLaunch.bytes)
        let greeting = try StorageLifecycleColdShimProtocol.Greeting(channelID: uuid(), daemonUniqueID: 30,
            rootPublicKey: old.rootPublicKey, binding: old.binding,
            bootBinding: .init(shimLaunchUUID: launch.shimLaunchUUID, guestBootNonce: uuid(), ext4UUID: launch.ext4UUID, bytes: launch.bytes),
            launch: launch, heldBackingIdentity: old.heldBackingIdentity)
        return try .init(observationID: uuid(), identity: grant.identity, operationID: request.operationID,
            signedOpenSHA256: prepared.signedOpenSHA256, observerGreeting: greeting)
    }
    func observedPrepare(_ history: StorageLifecycleColdObservationProtocol.History) throws -> C.Prepare {
        let candidate = try StorageIdentity.Candidate(publicKey: .init(rawPublicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation),
            childPIDHint: 31, incarnationID: .init(uuid()))
        return try .init(operationID: uuid(), identity: grant.identity, expectedPredecessor: history.predecessor,
            expectedOrigin: request.expectedOrigin, expectedAllocatedEpoch: request.expectedAllocatedEpoch,
            candidate: candidate, mountedGreeting: history.request.observerGreeting, nowUnixSeconds: 102, lifetimeSeconds: 100,
            observationID: history.request.observationID)
    }
    func killFailed() { for pid: Int32 in [20, 21, 22] { checks.lives[pid] = .exited } }
    func reload() throws {
        authority = try .init(journal: journal, processes: checks, bindings: checks)
        adoption = try .init(journal: adoptionJournal, processes: checks)
        try authority.configureCold(adoption: adoption, mounted: checks)
    }
}

@Suite struct StorageBootstrapLifecycleColdTests {
    @Test(arguments: [false, true]) func observedRecoveryUsesConcretePredecessorAndOriginalAnchor(_ applied: Bool) throws {
        let f = try ColdFixture(), failed = try f.prepare()
        if applied { f.open(); f.checks.observationApplied = true }
        f.killFailed()
        #expect(try f.authority.statusCold(identity: f.grant.identity).eligibility == .observationRequired)
        #expect(throws: (any Error).self) { try f.authority.resolveDeadCold(f.resolution(failed)) }
        let observation = try f.observer(failed), before = f.adoptionJournal.bytes
        let history = try f.authority.observeCold(observation, daemon: process(30))
        #expect(history.authorization.request.subject == (try L.encode(failed.signedOpen)))
        #expect(history.observation.outcome == (applied ? .applied : .unchanged))
        #expect(f.adoptionJournal.bytes == before)
        #expect(try f.authority.statusCold(identity: f.grant.identity).predecessor == history.predecessor)
        let signs = f.journal.signs
        try f.reload()
        #expect(try f.authority.observeCold(observation, daemon: process(30)) == history)
        #expect(f.journal.signs == signs)
        let request = try f.observedPrepare(history)
        f.checks.mountedPID = 32
        let prepared = try f.authority.prepareCold(request, daemon: process(30))
        #expect(prepared.observedHistory == history && prepared.recoveryBridge == nil)
        #expect(prepared.signedOpen.request.takeover.grant.serial > failed.signedOpen.request.takeover.grant.serial)
        #expect(prepared.signedOpen.request.takeover.grant.expectedEpoch == history.predecessor.controllerEpoch)
        #expect(prepared.baseEpoch == failed.baseEpoch) // No abandoned enrollment allocation.
        f.checks.service = uuid(); f.checks.revision = applied ? 3 : 2
        f.checks.ca = String(repeating: "3", count: 64); f.checks.server = String(repeating: "4", count: 64)
        let completed = try f.authority.completeCold(operationID: request.operationID,
            signedOpenSHA256: prepared.signedOpenSHA256, daemon: process(30))
        #expect(completed.observedHistory == history)
        #expect(try f.adoption.status(store: f.disk.storeID.rawValue).origin == completed.successorOrigin)
        #expect(completed.successor.context.controllerEpoch == history.predecessor.controllerEpoch + 1)
        try f.reload()
        #expect(throws: (any Error).self) { try f.authority.guardColdPublication(store: f.disk.storeID.rawValue) }
        let (origin, principal, epoch, _) = try f.authority.coldOriginPrincipal(binding: f.disk)
        let seed = try StorageLifecycleColdShimProtocol.ColdEnrollmentSeed(operationID: request.operationID,
            signedOpenSHA256: prepared.signedOpenSHA256, successorOrigin: origin.wire, baseEpoch: epoch)
        try f.authority.completeColdEnrollment(seed: seed, origin: origin, nativePrincipal: principal)
        try f.authority.guardColdPublication(store: f.disk.storeID.rawValue)
    }

    @Test(arguments: [false, true], [false, true])
    func observedRecoveryCapacityKeepsProtectedStoreAndWireBudgetsSeparate(_ applied: Bool, _ adoptedBeforeCold: Bool) throws {
        let f = try ColdFixture(adoptedBeforeCold: adoptedBeforeCold), failed = try f.prepare()
        if applied { f.open(); f.checks.observationApplied = true }
        f.killFailed()
        func storeBytes() throws -> Int {
            let bytes = try #require(f.journal.bytes)
            let state = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
            let stores = try #require(state["stores"] as? [String: Any])
            return try JSONSerialization.data(withJSONObject: #require(stores[f.grant.identity.store]),
                options: [.sortedKeys, .withoutEscapingSlashes]).count
        }
        var peakStoreBytes = try storeBytes()
        f.journal.afterWrite = { peakStoreBytes = max(peakStoreBytes, try storeBytes()) }
        defer { f.journal.afterWrite = nil }
        func roundTrip(_ request: C.Request, _ body: C.ResultBody) throws {
            #expect(try C.decodeRequest(C.encode(request)) == request)
            let reply = try C.Reply(for: request, body: body)
            let bytes = try C.encode(reply)
            #expect(C.maximumPayloadBytes == 64 * 1024)
            #expect(bytes.count <= 64 * 1024)
            #expect(try C.decodeReply(bytes, for: request) == reply)
            print("observed capacity applied=\(applied) adopted=\(adoptedBeforeCold) \(reply.operation) wire=\(bytes.count)")
        }
        let observe = try f.observer(failed)
        let history = try f.authority.observeCold(observe, daemon: process(30))
        try roundTrip(C.Request(requestID: .init(uuid()), body: .observe(observe)), .observed(history))
        let request = try f.observedPrepare(history)
        f.checks.mountedPID = 32
        let prepared = try f.authority.prepareCold(request, daemon: process(30))
        try roundTrip(C.Request(requestID: .init(uuid()), body: .prepare(request)), .prepared(prepared))
        try f.reload()
        f.checks.service = uuid(); f.checks.revision = applied ? 3 : 2
        f.checks.ca = String(repeating: "3", count: 64); f.checks.server = String(repeating: "4", count: 64)
        let completed = try f.authority.completeCold(operationID: request.operationID,
            signedOpenSHA256: prepared.signedOpenSHA256, daemon: process(30))
        try roundTrip(C.Request(requestID: .init(uuid()), body: .complete(operationID: request.operationID,
            signedOpenSHA256: prepared.signedOpenSHA256)), .completed(completed))
        // L2 retains both the failed attempt and genuine successor. It exceeds
        // the transport budget, but fits the independent protected-store budget
        // including its completion reservation. L3 retires the paired history.
        #expect(peakStoreBytes > 64 * 1024)
        #expect(peakStoreBytes <= (192 - 16) * 1024)
        #expect(try storeBytes() < peakStoreBytes)
        print("observed capacity applied=\(applied) adopted=\(adoptedBeforeCold) protected peak=\(peakStoreBytes)")
        try f.reload()
    }

    @Test(arguments: [false, true], [false, true])
    func observedSuccessorWriteCutsPreserveOriginalAnchor(_ applied: Bool, _ after: Bool) throws {
        // Unlike O1/O2 cuts, these cross both journals with the frozen attempt retained.
        for cut in 0..<4 { // L1, L2, A1, L3
            let f = try ColdFixture(), failed = try f.prepare()
            if applied { f.open(); f.checks.observationApplied = true }
            f.killFailed()
            let history = try f.authority.observeCold(f.observer(failed), daemon: process(30))
            let request = try f.observedPrepare(history)
            let oldAdoption = f.adoptionJournal.bytes
            f.checks.mountedPID = 32
            var prepared: C.Prepared?
            if cut > 0 { prepared = try f.authority.prepareCold(request, daemon: process(30)) }
            let target = cut == 2 ? f.adoptionJournal : f.journal
            let failAt = target.writes + (cut == 3 ? 2 : 1)
            if after { target.afterWrite = { if target.writes == failAt { throw BootstrapFailure(.unavailable) } } }
            else { target.failAt = failAt }
            if cut == 0 {
                #expect(throws: (any Error).self) { try f.authority.prepareCold(request, daemon: process(30)) }
            } else {
                f.checks.service = uuid(); f.checks.revision = applied ? 3 : 2
                f.checks.ca = String(repeating: "3", count: 64); f.checks.server = String(repeating: "4", count: 64)
                #expect(throws: (any Error).self) {
                    try f.authority.completeCold(operationID: request.operationID,
                        signedOpenSHA256: prepared!.signedOpenSHA256, daemon: process(30))
                }
            }
            target.failAt = nil; target.afterWrite = nil
            let bytes = try #require(f.journal.bytes)
            let state = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
            let stores = try #require(state["stores"] as? [String: [String: Any]])
            let store = try #require(stores[f.disk.storeID.rawValue])
            let published = cut == 3 && after
            #expect((store["observedCold"] == nil) == published)
            if !published {
                let current = try #require(store["current"] as? [String: Any])
                let grant = try #require(current["grant"] as? [String: Any])
                #expect(grant["id"] as? String == f.grant.id) // Never publish the abandoned controller.
            }
            let transaction = try #require(store[published ? "latestCold" : "pendingCold"] as? [String: Any])
            var durablePrepared: C.Prepared?
            if cut != 0 || after {
                durablePrepared = try JSONDecoder().decode(C.Prepared.self,
                    from: JSONSerialization.data(withJSONObject: #require(transaction["prepared"])))
            }
            var durableCompletion: C.Completed?
            if let value = transaction["completion"], !(value is NSNull) {
                durableCompletion = try JSONDecoder().decode(C.Completed.self,
                    from: JSONSerialization.data(withJSONObject: value))
            }
            if cut < 2 || (cut == 2 && !after) { #expect(f.adoptionJournal.bytes == oldAdoption) }
            let signs = f.journal.signs
            try f.reload()
            #expect(throws: (any Error).self) { try f.authority.guardColdPublication(store: f.disk.storeID.rawValue) }
            let retry = try f.authority.prepareCold(request, daemon: process(30))
            if let durablePrepared {
                #expect(retry == durablePrepared)
                #expect(f.journal.signs == signs) // A lost L1 reply must not re-sign either envelope.
            }
            #expect(retry.observedHistory == history && retry.baseEpoch == failed.baseEpoch)
            #expect(retry.signedOpen.request.takeover.grant.serial > failed.signedOpen.request.takeover.grant.serial)
            #expect(retry.signedOpen.request.takeover.grant.expectedEpoch == history.predecessor.controllerEpoch)
            if cut == 0 {
                f.checks.service = uuid(); f.checks.revision = applied ? 3 : 2
                f.checks.ca = String(repeating: "3", count: 64); f.checks.server = String(repeating: "4", count: 64)
            }
            let completed = try f.authority.completeCold(operationID: request.operationID,
                signedOpenSHA256: retry.signedOpenSHA256, daemon: process(30))
            if let durableCompletion {
                #expect(completed.successor == durableCompletion.successor)
                #expect(completed.receipt.grant == durableCompletion.receipt.grant)
                #expect(completed.receipt.nonce != durableCompletion.receipt.nonce) // Fresh proof, same result.
            }
            #expect(completed.observedHistory == history)
            let adopted = try f.adoption.status(store: f.disk.storeID.rawValue)
            #expect(adopted.origin == completed.successorOrigin && adopted.baseEpoch == failed.baseEpoch)
            #expect(throws: (any Error).self) { try f.authority.prepareCold(f.request, daemon: f.daemon) }
            try f.reload()
            #expect(throws: (any Error).self) { try f.authority.guardColdPublication(store: f.disk.storeID.rawValue) }
            let (origin, principal, epoch, _) = try f.authority.coldOriginPrincipal(binding: f.disk)
            let seed = try StorageLifecycleColdShimProtocol.ColdEnrollmentSeed(operationID: request.operationID,
                signedOpenSHA256: retry.signedOpenSHA256, successorOrigin: origin.wire, baseEpoch: epoch)
            try f.authority.completeColdEnrollment(seed: seed, origin: origin, nativePrincipal: principal)
            try f.authority.guardColdPublication(store: f.disk.storeID.rawValue)
            #expect(try f.authority.adoptedService(identity: f.grant.identity) == completed.successor)
        }
    }

    @Test(arguments: ["frozen-attempt", "history-base-epoch", "observer-correlation", "request-correlation",
                      "successor-history", "base-epoch", "serial", "controller-epoch"])
    func observedProtectedStateCorruptionRefusesLoadWithoutRewriting(_ corruption: String) throws {
        let f = try ColdFixture(), failed = try f.prepare()
        f.open(); f.checks.observationApplied = true; f.killFailed()
        let history = try f.authority.observeCold(f.observer(failed), daemon: process(30))
        if ["successor-history", "base-epoch", "serial", "controller-epoch"].contains(corruption) {
            f.checks.mountedPID = 32
            _ = try f.authority.prepareCold(f.observedPrepare(history), daemon: process(30))
        }
        try f.reload() // The starting protected snapshot is valid, not already fenced by corruption.
        let original = try #require(f.journal.bytes)
        var state = try #require(JSONSerialization.jsonObject(with: original) as? [String: Any])
        func replace(_ object: inout [String: Any], path: ArraySlice<String>, with value: Any) throws {
            let key = try #require(path.first)
            _ = try #require(object[key]) // Never silently add an ignored JSON field.
            if path.count == 1 { object[key] = value; return }
            var child = try #require(object[key] as? [String: Any])
            try replace(&child, path: path.dropFirst(), with: value)
            object[key] = child
        }
        let prefix = ["stores", f.disk.storeID.rawValue]
        var path: [String], value: Any
        switch corruption {
        case "frozen-attempt":
            // A valid candidate incarnation substitution must still fail exact frozen/pending equality.
            path = prefix + ["observedCold", "failed", "request", "candidate", "incarnation"]; value = uuid()
        case "history-base-epoch":
            path = prefix + ["observedCold", "history", "failedBaseEpoch"]; value = failed.baseEpoch + 1
        case "observer-correlation":
            path = prefix + ["observedCold", "request", "observerGreeting"]
            value = try JSONSerialization.jsonObject(with: L.encode(f.observer(failed).observerGreeting))
        case "request-correlation":
            path = prefix + ["observedCold", "request", "observationID"]; value = uuid()
        case "successor-history":
            path = prefix + ["pendingCold", "prepared", "observedHistory", "failedBaseEpoch"]; value = failed.baseEpoch + 1
        case "base-epoch":
            // No allocation for the abandoned launch: successor must use equality, not +1.
            path = prefix + ["pendingCold", "prepared", "baseEpoch"]; value = failed.baseEpoch + 1
        case "serial":
            path = ["serial"]; value = failed.signedOpen.request.takeover.grant.serial
        default:
            // Structurally valid old C1 cannot replace the applied observation's concrete C2.
            path = prefix + ["pendingCold", "request", "expectedPredecessor"]
            value = try JSONSerialization.jsonObject(with: L.encode(failed.signedOpen.request.predecessor))
        }
        try replace(&state, path: path[...], with: value)
        f.journal.bytes = try JSONSerialization.data(withJSONObject: state, options: [.sortedKeys, .withoutEscapingSlashes])
        let bytes = f.journal.bytes, adoptionBytes = f.adoptionJournal.bytes
        let writes = f.journal.writes, adoptionWrites = f.adoptionJournal.writes, signs = f.journal.signs
        let observations = f.checks.observationCalls, mounts = f.checks.mountedCalls
        #expect(throws: (any Error).self) { try f.reload() }
        #expect(f.journal.bytes == bytes && f.journal.writes == writes && f.journal.signs == signs)
        #expect(f.adoptionJournal.bytes == adoptionBytes && f.adoptionJournal.writes == adoptionWrites)
        #expect(f.checks.observationCalls == observations && f.checks.mountedCalls == mounts)
    }

    @Test(arguments: [20, 21, 22]) func observationRequiresPositiveDeathOfEveryFailedBirth(_ pid: Int) throws {
        for life: BootstrapLiveness in [.alive, .unknown] {
            let f = try ColdFixture(), failed = try f.prepare(); f.killFailed()
            f.checks.lives[Int32(pid)] = life
            #expect(throws: (any Error).self) { try f.authority.observeCold(f.observer(failed), daemon: process(30)) }
            #expect(f.checks.observationCalls == 0)
        }
    }

    @Test func authorizedObservationReprovesNativeAndCannotReplayOldConfigure() throws {
        let f = try ColdFixture(), failed = try f.prepare(); f.killFailed()
        let request = try f.observer(failed)
        f.checks.observationAllowed = false
        #expect(throws: (any Error).self) { try f.authority.observeCold(request, daemon: process(30)) }
        let signs = f.journal.signs
        try f.reload()
        #expect(throws: (any Error).self) { try f.authority.observeCold(request, daemon: process(30)) }
        #expect(f.journal.signs == signs)
        #expect(throws: (any Error).self) { try f.authority.prepareCold(f.request, daemon: f.daemon) }
        #expect(throws: (any Error).self) { try f.authority.completeCold(operationID: f.request.operationID,
            signedOpenSHA256: failed.signedOpenSHA256, daemon: f.daemon) }
        #expect(throws: (any Error).self) { try f.authority.observeCold(f.observer(failed), daemon: process(30)) }
        f.checks.observationAllowed = true
        let history = try f.authority.observeCold(request, daemon: process(30))
        f.checks.observationAllowed = false
        #expect(throws: (any Error).self) { try f.authority.observeCold(request, daemon: process(30)) }
        #expect(throws: (any Error).self) { try f.authority.prepareCold(f.observedPrepare(history), daemon: process(30)) }
    }

    @Test(arguments: [1, 2], [false, true]) func observationWriteCutsRetainExactOriginal(_ cut: Int, _ after: Bool) throws {
        let f = try ColdFixture(), failed = try f.prepare(); f.killFailed()
        let request = try f.observer(failed), write = f.journal.writes + cut
        if after { f.journal.afterWrite = { if f.journal.writes == write { throw BootstrapFailure(.unavailable) } } }
        else { f.journal.failAt = write }
        #expect(throws: (any Error).self) { try f.authority.observeCold(request, daemon: process(30)) }
        f.journal.failAt = nil; f.journal.afterWrite = nil
        try f.reload()
        let history = try f.authority.observeCold(request, daemon: process(30))
        #expect(history.authorization.request.subject == (try L.encode(failed.signedOpen)))
        #expect(throws: (any Error).self) { try f.authority.guardColdPublication(store: f.disk.storeID.rawValue) }
    }

    @Test func observedHistoryCorruptionRefusesLoadWithoutRewriting() throws {
        let f = try ColdFixture(), failed = try f.prepare(); f.killFailed()
        _ = try f.authority.observeCold(f.observer(failed), daemon: process(30))
        let original = try #require(f.journal.bytes)
        var object = try #require(JSONSerialization.jsonObject(with: original) as? [String: Any])
        var stores = try #require(object["stores"] as? [String: Any])
        var store = try #require(stores[f.disk.storeID.rawValue] as? [String: Any])
        var observed = try #require(store["observedCold"] as? [String: Any])
        var authorization = try #require(observed["authorization"] as? [String: Any])
        authorization["signature"] = Data(repeating: 0, count: 64).base64EncodedString()
        observed["authorization"] = authorization; store["observedCold"] = observed
        stores[f.disk.storeID.rawValue] = store; object["stores"] = stores
        f.journal.bytes = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        let bytes = f.journal.bytes, writes = f.journal.writes
        #expect(throws: (any Error).self) { try f.reload() }
        #expect(f.journal.bytes == bytes && f.journal.writes == writes)
    }

    @Test func observationRechecksDeathAfterNativeReplyBeforeO2() throws {
        let f = try ColdFixture(), failed = try f.prepare(); f.killFailed()
        let request = try f.observer(failed)
        f.checks.beforeObservation = { f.checks.lives[21] = .unknown }
        #expect(throws: (any Error).self) { try f.authority.observeCold(request, daemon: process(30)) }
        f.checks.beforeObservation = nil; f.killFailed()
        try f.reload()
        _ = try f.authority.observeCold(request, daemon: process(30))
    }

    @Test func nativeResultMustStayExactAcrossO2AndRetries() throws {
        let f = try ColdFixture(), failed = try f.prepare(); f.killFailed()
        let request = try f.observer(failed)
        _ = try f.authority.observeCold(request, daemon: process(30))
        f.open(); f.checks.observationApplied = true
        #expect(throws: (any Error).self) { try f.authority.observeCold(request, daemon: process(30)) }
    }

    @Test func protectedClaimReachabilityRetainsL1ThroughL3ButNotL4() throws {
        let f = try ColdFixture()
        #expect(try f.authority.retainedColdClaimOperationIDs().isEmpty)
        let prepared = try f.prepare()
        #expect(try f.authority.retainedColdClaimOperationIDs() == [f.request.operationID])
        f.open(); _ = try f.complete(prepared)
        #expect(try f.authority.retainedColdClaimOperationIDs() == [f.request.operationID])
        // Channel/proof unavailability cannot make a durable L3 unreachable.
        f.checks.mountedAllowed = false
        #expect(try f.authority.retainedColdClaimOperationIDs() == [f.request.operationID])
        f.checks.mountedAllowed = true
        try f.enroll()
        #expect(try f.authority.retainedColdClaimOperationIDs().isEmpty)
        try f.reload()
        #expect(try f.authority.retainedColdClaimOperationIDs().isEmpty)
    }

    @Test func failedL4CheckpointCannotRetireUntilRecoveredDurableSnapshot() throws {
        for after in [false, true] {
            let f = try ColdFixture(), prepared = try f.prepare()
            f.open(); _ = try f.complete(prepared)
            var claims = StorageBootstrapLifecycleColdClaims<String>()
            claims[f.request.operationID] = "retained-peer"
            let failAt = f.journal.writes + 1
            if after {
                f.journal.afterWrite = { if f.journal.writes == failAt { throw BootstrapFailure(.unavailable) } }
            } else { f.journal.failAt = failAt }
            #expect(throws: BootstrapFailure.self) { try f.enroll() }
            #expect(throws: BootstrapFailure.self) {
                try claims.reconcile { try f.authority.retainedColdClaimOperationIDs() }
            }
            #expect(claims[f.request.operationID] == "retained-peer")
            f.journal.failAt = nil; f.journal.afterWrite = nil
            try f.reload()
            try claims.reconcile { try f.authority.retainedColdClaimOperationIDs() }
            #expect(claims.count == (after ? 0 : 1))
        }
    }

    @Test func deadResolutionRetiresOnlyAfterItsDurablePublication() throws {
        let f = try ColdFixture(), prepared = try f.strandAfterL2()
        f.checks.lives[22] = .exited
        #expect(try f.authority.retainedColdClaimOperationIDs() == [f.request.operationID])
        _ = try f.authority.resolveDeadCold(f.resolution(prepared))
        #expect(try f.authority.retainedColdClaimOperationIDs().isEmpty)
        try f.reload()
        #expect(try f.authority.retainedColdClaimOperationIDs().isEmpty)
    }

    @Test func deadResolutionKeepsCurrentAndEveryOrdinaryPublicationFenced() throws {
        let f = try ColdFixture(), prepared = try f.strandAfterL2(), request = try f.resolution(prepared)
        f.checks.lives[22] = .exited
        let signs = f.journal.signs, proofs = f.checks.nonces.count
        let resolved = try f.authority.resolveDeadCold(request)
        try resolved.validate(prepared: prepared, anchor: resolved.anchor)
        #expect(resolved.anchor.grant == f.grant && resolved.receipt.grant == prepared.signedOpen.request.takeover.grant)
        #expect(f.journal.signs == signs && f.checks.nonces.count == proofs)
        let bytes = try #require(f.journal.bytes)
        let state = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        let stores = try #require(state["stores"] as? [String: [String: Any]])
        let store = try #require(stores[f.disk.storeID.rawValue])
        let current = try #require(store["current"] as? [String: Any])
        let currentGrant = try #require(current["grant"] as? [String: Any])
        #expect(currentGrant["id"] as? String == f.grant.id)
        #expect(store["pendingCold"] is NSNull && store["latestCold"] is NSNull)
        #expect(store["resolvedDeadCold"] != nil)
        #expect(try f.authority.statusCold(identity: f.grant.identity).predecessor.currentGrant == resolved.receipt.grant)
        #expect(try f.authority.statusCold(identity: f.grant.identity).eligibility == .eligible)
        #expect(throws: (any Error).self) { try f.authority.guardColdPublication(store: f.disk.storeID.rawValue) }
        #expect(throws: (any Error).self) { try f.authority.status(identity: f.grant.identity) }
        #expect(throws: (any Error).self) { try f.authority.adoptedService(identity: f.grant.identity) }
        #expect(throws: (any Error).self) { try f.authority.coldOriginPrincipal(binding: f.disk) }
        #expect(throws: (any Error).self) { try f.prepare() }
        #expect(throws: (any Error).self) { try f.complete(prepared) }
        #expect(throws: (any Error).self) { try f.authority.issue(operation: .takeover, id: uuid(), identity: f.grant.identity,
            expectedEpoch: 1, candidate: f.candidate, daemon: process(30)) }
        let writes = f.journal.writes, adoptionWrites = f.adoptionJournal.writes
        try f.reload()
        #expect(try f.authority.resolveDeadCold(request) == resolved)
        #expect(f.journal.writes == writes && f.adoptionJournal.writes == adoptionWrites)
    }

    @Test func resolutionRefusesEveryAliveOrUnknownParticipantAndCallerLoss() throws {
        for pid: Int32 in [10, 11, 12, 20, 21, 22] {
            for life in [BootstrapLiveness.alive, .unknown] {
                let f = try ColdFixture(), prepared = try f.strandAfterL2(), request = try f.resolution(prepared)
                f.checks.lives[22] = .exited; f.checks.lives[pid] = life
                let before = f.journal.bytes, adoptionBefore = f.adoptionJournal.bytes
                #expect(throws: (any Error).self) { try f.authority.resolveDeadCold(request) }
                #expect(f.journal.bytes == before && f.adoptionJournal.bytes == adoptionBefore)
            }
        }
        let f = try ColdFixture(), prepared = try f.strandAfterL2(), request = try f.resolution(prepared)
        f.checks.lives[22] = .exited
        let before = f.journal.bytes
        #expect(throws: (any Error).self) {
            try f.authority.resolveDeadCold(request, check: { throw BootstrapFailure(.unauthorized) })
        }
        #expect(f.journal.bytes == before)
    }

    @Test func resolutionNeedsExactL2AndRejectsChangedRequestsAndNormalL3() throws {
        let f = try ColdFixture(), prepared = try f.prepare(), request = try f.resolution(prepared)
        for pid: Int32 in [20, 21, 22] { f.checks.lives[pid] = .exited }
        let before = f.journal.bytes
        #expect(throws: (any Error).self) { try f.authority.resolveDeadCold(request) }
        #expect(f.journal.bytes == before)
        let g = try ColdFixture(), p = try g.strandAfterL2(), r = try g.resolution(p)
        g.checks.lives[22] = .exited
        _ = try g.authority.resolveDeadCold(r)
        for altered in [try C.ResolveDead(resolutionID: uuid(), identity: r.identity, operationID: r.operationID, signedOpenSHA256: r.signedOpenSHA256),
                        try C.ResolveDead(resolutionID: r.resolutionID, identity: r.identity, operationID: uuid(), signedOpenSHA256: r.signedOpenSHA256),
                        try C.ResolveDead(resolutionID: r.resolutionID, identity: r.identity, operationID: r.operationID, signedOpenSHA256: String(repeating: "0", count: 64))] {
            let saved = g.journal.bytes
            #expect(throws: (any Error).self) { try g.authority.resolveDeadCold(altered) }
            #expect(g.journal.bytes == saved)
        }
        let h = try ColdFixture(), hp = try h.prepare(); h.open(); _ = try h.complete(hp)
        for pid: Int32 in [20, 21, 22] { h.checks.lives[pid] = .exited }
        #expect(throws: (any Error).self) { try h.authority.resolveDeadCold(h.resolution(hp)) }
    }

    @Test func everyResolutionWriteCutIsExactRetryableAndNeverCompletesTheDeadController() throws {
        // D1, original A1, D2: before-write and durable-write/lost-return cuts.
        for cut in 0..<3 {
            for after in [false, true] {
                let f = try ColdFixture(), prepared = try f.strandAfterL2(), request = try f.resolution(prepared)
                f.checks.lives[22] = .exited
                let target = cut == 1 ? f.adoptionJournal : f.journal
                let failAt = target.writes + (cut == 2 ? 2 : 1)
                if after { target.afterWrite = { if target.writes == failAt { throw BootstrapFailure(.unavailable) } } }
                else { target.failAt = failAt }
                #expect(throws: (any Error).self) { try f.authority.resolveDeadCold(request) }
                target.failAt = nil; target.afterWrite = nil
                try f.reload()
                let resolved = try f.authority.resolveDeadCold(request)
                #expect(resolved.anchor.grant == f.grant)
                #expect(try f.adoption.status(store: f.disk.storeID.rawValue).baseEpoch == 2)
                #expect(throws: (any Error).self) { try f.complete(prepared) }
                #expect(throws: (any Error).self) { try f.authority.guardColdPublication(store: f.disk.storeID.rawValue) }
            }
        }
    }

    @Test(arguments: [false, true])
    func resolvedDeadPredecessorRequiresAnEntirelyNewColdAndEnrollment(adoptedBeforeCold: Bool) throws {
        let f = try ColdFixture(adoptedBeforeCold: adoptedBeforeCold), prepared = try f.strandAfterL2(), resolution = try f.resolution(prepared)
        f.checks.lives[22] = .exited
        let bridge = try f.authority.resolveDeadCold(resolution)
        let status = try f.authority.statusCold(identity: f.grant.identity)
        let key = try StorageIdentity.Ed25519SPKI(rawPublicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)
        let candidate = try StorageIdentity.Candidate(publicKey: key, childPIDHint: 31, incarnationID: .init(uuid()))
        let old = f.request.mountedGreeting, oldLaunch = old.launch
        let launch = try StorageLifecycleColdProtocol.Launch(shimLaunchUUID: uuid(), specSHA256: oldLaunch.specSHA256,
            initramfsSHA256: oldLaunch.initramfsSHA256, ext4UUID: oldLaunch.ext4UUID, bytes: oldLaunch.bytes)
        let greeting = try StorageLifecycleColdShimProtocol.Greeting(channelID: uuid(), daemonUniqueID: 30,
            rootPublicKey: old.rootPublicKey, binding: old.binding,
            bootBinding: .init(shimLaunchUUID: launch.shimLaunchUUID, guestBootNonce: uuid(), ext4UUID: launch.ext4UUID, bytes: launch.bytes),
            launch: launch, heldBackingIdentity: old.heldBackingIdentity)
        let request = try C.Prepare(operationID: uuid(), identity: f.grant.identity,
            expectedPredecessor: status.predecessor, expectedOrigin: status.origin, expectedAllocatedEpoch: status.allocatedEpoch,
            candidate: candidate, mountedGreeting: greeting, nowUnixSeconds: 101, lifetimeSeconds: 100)
        f.checks.mountedPID = 32
        let next = try f.authority.prepareCold(request, daemon: process(30))
        #expect(next.recoveryBridge == bridge && next.signedOpen.request.takeover.grant.expectedEpoch == 2)
        #expect(!StorageBootstrapCompatibilityColdL2FaultPolicy.shouldInject(hasRecoveryBridge: next.recoveryBridge != nil))
        #expect(next.signedOpen.request.takeover.grant.newKey == key.fingerprint.rawValue)
        #expect(next.signedOpen.request.takeover.grant.serial > bridge.receipt.grant.serial)
        #expect(throws: (any Error).self) { try f.authority.resolveDeadCold(resolution) }
        f.open(); f.checks.revision = 3
        f.checks.ca = String(repeating: "3", count: 64); f.checks.server = String(repeating: "4", count: 64)
        func storeBytes() throws -> Int {
            let bytes = try #require(f.journal.bytes)
            let state = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
            let stores = try #require(state["stores"] as? [String: Any])
            let store = try #require(stores[f.grant.identity.store])
            return try JSONSerialization.data(withJSONObject: store, options: [.sortedKeys, .withoutEscapingSlashes]).count
        }
        let l1StoreBytes = try storeBytes()
        var peakStoreBytes = l1StoreBytes
        f.journal.afterWrite = { peakStoreBytes = max(peakStoreBytes, try storeBytes()) }
        defer { f.journal.afterWrite = nil }
        let completion = try f.authority.completeCold(operationID: request.operationID,
            signedOpenSHA256: next.signedOpenSHA256, daemon: process(30))
        #expect(completion.recoveryBridge == bridge && completion.successor.context.controllerEpoch == 3)
        if adoptedBeforeCold { #expect(peakStoreBytes > 48 * 1024) }
        #expect(peakStoreBytes <= 80 * 1024)
        #expect(peakStoreBytes - l1StoreBytes <= 16 * 1024)
        #expect(try storeBytes() < l1StoreBytes) // L3 retires the paired dead history.
        f.journal.afterWrite = nil
        #expect(completion.successor.context.serviceEpoch != bridge.successor.context.serviceEpoch)
        #expect(throws: (any Error).self) { try f.authority.guardColdPublication(store: f.disk.storeID.rawValue) }
        let (origin, principal, epoch, _) = try f.authority.coldOriginPrincipal(binding: f.disk)
        let seed = try StorageLifecycleColdShimProtocol.ColdEnrollmentSeed(operationID: request.operationID,
            signedOpenSHA256: next.signedOpenSHA256, successorOrigin: origin.wire, baseEpoch: epoch)
        try f.authority.completeColdEnrollment(seed: seed, origin: origin, nativePrincipal: principal)
        try f.authority.guardColdPublication(store: f.disk.storeID.rawValue)
        #expect(try f.authority.adoptedService(identity: f.grant.identity) == completion.successor)
    }

    @Test func enrollmentRequiresProtectedGreetingDeviceBeforeAndAfterWrites() throws {
        let native = try NativeBindingFixture(), f = try ColdFixture(binding: native.binding)
        let prepared = try f.prepare(); f.open(); _ = try f.complete(prepared)
        try f.reload() // Expectation must survive ROOT restart, never come from the seed.
        let (origin, principal, epoch, completion) = try f.authority.coldOriginPrincipal(binding: f.disk)
        let seed = try StorageLifecycleColdShimProtocol.ColdEnrollmentSeed(operationID: completion.operationID,
            signedOpenSHA256: completion.signedOpenSHA256, successorOrigin: origin.wire, baseEpoch: epoch)
        let expected = try f.authority.authorizeColdEnrollment(seed: seed, origin: origin, nativePrincipal: principal)
        #expect(expected == (try f.request.mountedGreeting.heldBackingIdentity.value()))
        #expect(expected.stableIdentity == native.binding.backing.identity)
        var device = expected.device &+ 1
        let verifier = StorageBootstrapBindings(ownerUID: geteuid(), diagnostic: { _ in }, observation: {
            .init(stableIdentity: $0.stableIdentity, device: device)
        })
        // Stable UUID/inode validation alone accepts the replacement observation.
        try verifier.verify(f.disk, rootFD: native.root, backingFD: native.backing)
        let before = f.journal.bytes, adoptionBefore = f.adoptionJournal.bytes
        var entered = false
        #expect(throws: (any Error).self) {
            try StorageBootstrapLifecycleAdoptionXPC.withEnrollmentBacking(verifier, binding: f.disk,
                rootFD: native.root, backingFD: native.backing, expectedBacking: expected) {
                entered = true
                try f.enroll()
            }
        }
        #expect(!entered && f.journal.bytes == before && f.adoptionJournal.bytes == adoptionBefore)
        device = expected.device
        // No successful acknowledgement if the device changes during a write/proof.
        #expect(throws: (any Error).self) {
            try StorageBootstrapLifecycleAdoptionXPC.withEnrollmentBacking(verifier, binding: f.disk,
                rootFD: native.root, backingFD: native.backing, expectedBacking: expected) {
                entered = true; device &+= 1
            }
        }
        #expect(entered)
        device = expected.device
        try StorageBootstrapLifecycleAdoptionXPC.withEnrollmentBacking(verifier, binding: f.disk,
            rootFD: native.root, backingFD: native.backing, expectedBacking: expected) {
            try f.enroll()
        }
    }

    @Test func liveStatusResumesPendingAndSupersededAdoptionWithoutColdEligibility() throws {
        let f = try ColdFixture(); f.checks.lives[12] = .alive
        let (first, _) = try f.prepareAdoption()
        func expectLive(_ epoch: UInt64) throws {
            let lifecycleBytes = f.journal.bytes, adoptionBytes = f.adoptionJournal.bytes
            let proofs = f.checks.nonces.count
            let status = try f.authority.statusCold(identity: f.grant.identity)
            #expect(status.eligibility == .live && status.allocatedEpoch == epoch)
            #expect(status.predecessor == f.request.expectedPredecessor)
            #expect(f.checks.nonces.count == proofs) // Protected expectation, not a service challenge.
            #expect(throws: (any Error).self) { try f.prepare() }
            #expect(f.journal.bytes == lifecycleBytes && f.adoptionJournal.bytes == adoptionBytes)
        }
        try f.reload(); try expectLive(2)
        f.checks.lives[20] = .exited; f.checks.lives[21] = .exited
        let (second, peer) = try f.prepareAdoption(pid: 30, epoch: 2, superseded: first.fenceIdentity)
        try f.reload(); try expectLive(3)
        #expect(try f.adoption.complete(second, peer: peer) == 3)
        try f.reload(); try expectLive(3) // Abandoned fence remains after the real commit.
        let bytes = f.adoptionJournal.bytes
        f.checks.lives[12] = .exited
        #expect(throws: (any Error).self) { try f.authority.statusCold(identity: f.grant.identity) }
        #expect(f.adoptionJournal.bytes == bytes) // Never auto-abandon to become cold.
    }

    @Test func deadShimWithPendingAdoptionNeverBecomesColdOrLive() throws {
        let f = try ColdFixture(); f.checks.lives[12] = .alive
        _ = try f.prepareAdoption(); try f.reload()
        let bytes = f.adoptionJournal.bytes
        f.checks.lives[12] = .exited
        #expect(throws: (any Error).self) { try f.authority.statusCold(identity: f.grant.identity) }
        #expect(throws: (any Error).self) { try f.prepare() }
        #expect(f.adoptionJournal.bytes == bytes)
    }

    @Test func liveStatusAllowsOrdinaryAdoptionAndPendingTakeoverToComplete() throws {
        let f = try ColdFixture(); f.checks.lives[12] = .alive
        let (request, peer) = try f.prepareAdoption()
        #expect(try f.authority.statusCold(identity: f.grant.identity).eligibility == .live)
        #expect(try f.adoption.complete(request, peer: peer) == 2)
        let takeover = try f.authority.issue(operation: .takeover, id: uuid(), identity: f.grant.identity,
            expectedEpoch: 1, candidate: f.candidate, daemon: f.daemon)
        try f.reload()
        let bytes = f.journal.bytes
        for life in [BootstrapLiveness.exited, .unknown] {
            f.checks.lives[12] = life
            #expect(try f.authority.statusCold(identity: f.grant.identity).eligibility == .unavailable)
            #expect(throws: (any Error).self) { try f.prepare() }
        }
        f.checks.lives[12] = .alive
        let status = try f.authority.statusCold(identity: f.grant.identity)
        #expect(status.eligibility == .live && status.predecessor == f.request.expectedPredecessor)
        #expect(f.journal.bytes == bytes)
        let receipt = try f.authority.complete(identity: f.grant.identity, id: takeover.grant.id, daemon: f.daemon)
        #expect(receipt.grant == takeover.grant)
        #expect(try f.authority.status(identity: f.grant.identity).epoch.rawValue == 2)
    }

    @Test func onlyPositiveRegisteredShimLivenessSelectsLive() throws {
        for shimLife in [BootstrapLiveness.exited, .unknown] {
            for pid: Int32 in [10, 11] {
                let f = try ColdFixture()
                f.checks.lives[12] = shimLife; f.checks.lives[pid] = .alive
                #expect(try f.authority.statusCold(identity: f.grant.identity).eligibility == .unavailable)
            }
            let f = try ColdFixture(); f.checks.lives[12] = .alive
            let (request, peer) = try f.prepareAdoption()
            _ = try f.adoption.complete(request, peer: peer)
            f.checks.lives[12] = shimLife // Latest adopter is alive, not the registered shim.
            #expect(try f.authority.statusCold(identity: f.grant.identity).eligibility == .unavailable)
        }
    }

    @Test func liveShimCannotBypassLifecycleServiceRetirementOrSealFences() throws {
        for seal in [false, true] {
            let f = try ColdFixture()
            for pid: Int32 in [10, 11, 12] { f.checks.lives[pid] = .alive }
            let retirement = try f.authority.issue(operation: .retire, id: uuid(), identity: f.grant.identity,
                expectedEpoch: 1, candidate: f.initial, daemon: process(10))
            if seal { _ = try f.authority.complete(identity: f.grant.identity, id: retirement.grant.id, daemon: process(10)) }
            try f.reload()
            #expect(throws: (any Error).self) { try f.authority.statusCold(identity: f.grant.identity) }
        }
        let f = try ColdFixture()
        for pid: Int32 in [10, 11, 12] { f.checks.lives[pid] = .alive }
        let service = try f.authority.adoptedService(identity: f.grant.identity)
        _ = try f.authority.stageServiceChange(change: .init(operationID: uuid(), predecessor: service), daemon: process(10))
        #expect(throws: (any Error).self) { try f.authority.statusCold(identity: f.grant.identity) }
    }

    @Test func liveStatusRequiresPhysicalBindingAndRootJoin() throws {
        for differentRoot in [false, true] {
            let f = try ColdFixture()
            let journal = ColdJournal(key: differentRoot ? Curve25519.Signing.PrivateKey() : f.journal.key)
            let adoption = try StorageBootstrapLifecycleAdoptionAuthority(journal: journal, processes: f.checks)
            let disk = differentRoot ? f.disk : try StorageIdentity.StoreBinding(storeID: f.disk.storeID, root: f.disk.root,
                backing: .init(identity: .init(volumeUUID: f.disk.backing.identity.volumeUUID, inode: 99), size: 4096),
                expectedExt4UUID: f.disk.expectedExt4UUID)
            let origin = try StorageLifecycleShimOrigin(wire: .init(binding: .init(disk), rootPublicKey: journal.rootPublicKey(),
                shimLaunchUUID: uuid(), specSHA256: String(repeating: "c", count: 64)),
                shim: process(12), originalDaemon: process(10), originalController: process(11))
            try adoption.recordOrigin(origin, rootFD: 1, backingFD: 2)
            let authority = try StorageBootstrapLifecycleAuthority(journal: f.journal, processes: f.checks, bindings: f.checks)
            try authority.configureCold(adoption: adoption, mounted: f.checks)
            f.checks.lives[12] = .alive
            #expect(throws: (any Error).self) { try authority.statusCold(identity: f.grant.identity) }
        }
    }

    @Test func exactBothSignaturesSurviveRetryReloadAndFreshCompletion() throws {
        let f = try ColdFixture(), prepared = try f.prepare()
        let signs = f.journal.signs
        #expect(try f.prepare() == prepared)
        try f.reload(); #expect(try f.prepare() == prepared)
        #expect(f.journal.signs == signs)
        f.open()
        let completed = try f.complete(prepared)
        try f.reload()
        let retry = try f.complete(prepared)
        #expect(completed.receipt.nonce != retry.receipt.nonce)
        #expect(completed.successor == retry.successor)
        #expect(try f.prepare() == prepared)
        #expect(f.journal.signs == signs)
        #expect(Set(f.checks.nonces).count == f.checks.nonces.count)
        let projection = try f.authority.coldOriginPrincipal(binding: f.disk)
        #expect(projection.2 == 2 && projection.0.originalDaemon == f.daemon)
        #expect(throws: (any Error).self) { try f.authority.currentOriginPrincipal(binding: f.disk) }
    }

    @Test func ordinaryRoutesAreFencedAtL1AndAfterReload() throws {
        let f = try ColdFixture(), p = try f.prepare()
        try f.reload()
        f.checks.lives[12] = .alive
        #expect(throws: (any Error).self) { try f.authority.statusCold(identity: f.grant.identity) }
        #expect(throws: (any Error).self) { try f.authority.guardColdPublication(store: f.disk.storeID.rawValue) }
        #expect(throws: (any Error).self) { try f.authority.status(identity: f.grant.identity) }
        #expect(throws: (any Error).self) { try f.authority.read(identity: f.grant.identity, id: f.grant.id, daemon: process(10)) }
        #expect(throws: (any Error).self) { try f.authority.complete(identity: f.grant.identity, id: p.signedOpen.request.takeover.grant.id, daemon: f.daemon) }
        #expect(throws: (any Error).self) { try f.authority.adoptedService(identity: f.grant.identity) }
        #expect(throws: (any Error).self) { try f.authority.serviceBootTrust(identity: f.grant.identity, grantID: f.grant.id, serviceChangeID: nil, daemon: process(10)) }
        #expect(throws: (any Error).self) { try f.authority.currentOriginPrincipal(binding: f.disk) }
        #expect(throws: (any Error).self) { try f.authority.issue(operation: .takeover, id: uuid(), identity: f.grant.identity, expectedEpoch: 1, candidate: f.candidate, daemon: f.daemon) }
        #expect(throws: (any Error).self) { try f.authority.reclaim(identity: f.grant.identity, id: f.grant.id, daemon: f.daemon) }
    }

    @Test func requiresPositiveOldExitAndUnchangedPrepare() throws {
        for pid: Int32 in [10, 11, 12] {
            for life in [BootstrapLiveness.unknown, .alive] {
                let f = try ColdFixture(); f.checks.lives[pid] = life
                #expect(try f.authority.statusCold(identity: f.grant.identity).eligibility != .eligible)
                let bytes = f.journal.bytes
                #expect(throws: (any Error).self) { try f.prepare() }
                #expect(f.journal.bytes == bytes)
            }
        }
        let f = try ColdFixture(); _ = try f.prepare()
        let r = f.request
        let changed = try C.Prepare(operationID: r.operationID, identity: r.identity, expectedPredecessor: r.expectedPredecessor,
            expectedOrigin: r.expectedOrigin, expectedAllocatedEpoch: r.expectedAllocatedEpoch, candidate: r.candidate,
            mountedGreeting: r.mountedGreeting, nowUnixSeconds: r.nowUnixSeconds + 1, lifetimeSeconds: r.lifetimeSeconds)
        #expect(throws: (any Error).self) { try f.authority.prepareCold(changed, daemon: f.daemon) }
    }

    @Test func interruptedL2RetainsOriginalResultWithoutCrossingA1() throws {
        let f = try ColdFixture(), prepared = try f.prepare()
        f.open()
        let adoptionBefore = f.adoptionJournal.bytes, adoptionWrites = f.adoptionJournal.writes
        let signs = f.journal.signs
        // Test-only journal cut, not a native selector. A lost checkpoint return
        // poisons this fixture authority, so reload before inspecting recovery.
        f.journal.afterWrite = { throw BootstrapFailure(.blocked) }
        #expect(throws: BootstrapFailure.self) { try f.complete(prepared) }
        f.journal.afterWrite = nil
        #expect(f.adoptionJournal.bytes == adoptionBefore && f.adoptionJournal.writes == adoptionWrites)
        let bytes = try #require(f.journal.bytes)
        let state = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        let stores = try #require(state["stores"] as? [String: [String: Any]])
        let store = try #require(stores[f.disk.storeID.rawValue])
        let pending = try #require(store["pendingCold"] as? [String: Any])
        let originalL2 = try JSONDecoder().decode(C.Completed.self,
            from: JSONSerialization.data(withJSONObject: #require(pending["completion"])))
        try originalL2.validate(prepared: prepared)
        #expect(originalL2.recoveryBridge == nil && store["latestCold"] is NSNull)
        #expect(pending["enrollmentAcknowledged"] as? Bool == false)
        #expect(StorageBootstrapCompatibilityColdL2FaultPolicy.shouldInject(hasRecoveryBridge: prepared.recoveryBridge != nil))
        try f.reload()
        #expect(try f.adoption.status(store: f.disk.storeID.rawValue).baseEpoch == 1)
        #expect(throws: BootstrapFailure.self) { try f.authority.guardColdPublication(store: f.disk.storeID.rawValue) }
        // Only actual dead-participant evidence in the logical fixture permits
        // resolution; its history must retain the exact original L2 result.
        for pid: Int32 in [20, 21, 22] { f.checks.lives[pid] = .exited }
        let resolved = try f.authority.resolveDeadCold(f.resolution(prepared))
        #expect(resolved.receipt == originalL2.receipt && resolved.successor == originalL2.successor)
        #expect(f.journal.signs == signs)
    }

    @Test func everyLogicalWriteCutRetainsRecoverableExactTransaction() throws {
        // L1, L2, A1, L3; before-write failures and durable-write/lost-return failures.
        for cut in 0..<4 {
            for after in [false, true] {
                let f = try ColdFixture()
                let target = cut == 2 ? f.adoptionJournal : f.journal
                var prepared: C.Prepared?
                if cut > 0 { prepared = try f.prepare(); f.open() }
                let offset = cut == 3 ? 2 : 1
                if after {
                    let failAt = target.writes + offset
                    target.afterWrite = { if target.writes == failAt { throw BootstrapFailure(.unavailable) } }
                } else { target.failAt = target.writes + offset }
                if cut == 0 { #expect(throws: (any Error).self) { try f.prepare() } }
                else { #expect(throws: (any Error).self) { try f.complete(prepared!) } }
                target.failAt = nil; target.afterWrite = nil
                try f.reload()
                let retry = try f.prepare()
                if let prepared { #expect(retry == prepared) }
                if cut == 0 { f.open() }
                _ = try f.complete(retry)
                #expect(try f.adoption.status(store: f.disk.storeID.rawValue).baseEpoch == 2)
                #expect(throws: (any Error).self) { try f.authority.guardColdPublication(store: f.disk.storeID.rawValue) }
                try f.enroll()
                try f.authority.guardColdPublication(store: f.disk.storeID.rawValue)
            }
        }
    }

    @Test func staleBootRevisionAndPostdurableMountLossNeverPublish() throws {
        let f = try ColdFixture(), prepared = try f.prepare()
        #expect(throws: (any Error).self) { try f.complete(prepared) }
        f.open(); f.checks.revision = 1
        #expect(throws: (any Error).self) { try f.complete(prepared) }
        f.checks.revision = 2; f.checks.ca = String(repeating: "a", count: 64)
        #expect(throws: (any Error).self) { try f.complete(prepared) }
        let g = try ColdFixture()
        g.journal.afterWrite = { g.checks.mountedAllowed = false }
        #expect(throws: (any Error).self) { try g.prepare() }
        g.journal.afterWrite = nil; g.checks.mountedAllowed = true
        let signs = g.journal.signs
        try g.reload(); _ = try g.prepare()
        #expect(g.journal.signs == signs)
    }

    @Test func laterPendingServiceRejectsStaleColdRetries() throws {
        let f = try ColdFixture(), prepared = try f.prepare()
        f.open(); let completion = try f.complete(prepared)
        try f.enroll()
        let change = try L.ServiceChangeRequest(operationID: uuid(), predecessor: completion.successor)
        _ = try f.authority.stageServiceChange(change: change, daemon: f.daemon)
        #expect(throws: (any Error).self) { try f.prepare() }
        #expect(throws: (any Error).self) { try f.complete(prepared) }
        #expect(throws: (any Error).self) { try f.authority.coldOriginPrincipal(binding: f.disk) }
    }

    @Test func laterAdoptionRejectsStaleColdRetryWithoutBlockingOrdinaryProjection() throws {
        let f = try ColdFixture(), prepared = try f.prepare()
        f.open(); _ = try f.complete(prepared)
        try f.enroll()
        let origin = try f.adoption.status(store: f.disk.storeID.rawValue).origin
        let principal = BootstrapPrincipal(daemon: process(30), child: process(31), incarnation: uuid(),
            controllerSPKI: f.candidate.publicKey.publicData)
        f.checks.adoptionPrincipal = principal
        f.checks.lives[20] = .exited; f.checks.lives[21] = .exited
        let request = try StorageLifecycleAdoptionProtocol.Request(id: uuid(), origin: origin, expectedEpoch: 2,
            daemonAudit: principal.daemon.auditToken, daemonUniqueID: principal.daemon.uniqueID,
            controllerAudit: principal.child.auditToken, controllerUniqueID: principal.child.uniqueID)
        let peer = BootstrapAuditIdentity(token: principal.daemon.auditToken.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) })
        try f.adoption.prepare(request, peer: peer); _ = try f.adoption.complete(request, peer: peer)
        try f.reload()
        #expect(throws: (any Error).self) { try f.prepare() }
        #expect(throws: (any Error).self) { try f.complete(prepared) }
        #expect(throws: (any Error).self) { try f.authority.coldOriginPrincipal(binding: f.disk) }
        try f.authority.guardColdPublication(store: f.disk.storeID.rawValue)
        #expect(try f.authority.adoptedService(identity: f.grant.identity).grant == prepared.signedOpen.request.takeover.grant)
    }

    @Test func l3SeedFailureOrSeedAcknowledgementAloneCannotReleasePublicationFence() throws {
        let f = try ColdFixture(), prepared = try f.prepare()
        f.open(); let completion = try f.complete(prepared)
        // Either failed seed delivery or a successful seed-only ACK leaves L3 fenced.
        for _ in 0..<2 {
            try f.reload()
            #expect(throws: (any Error).self) { try f.authority.guardColdPublication(store: f.disk.storeID.rawValue) }
            #expect(throws: (any Error).self) { try f.authority.status(identity: f.grant.identity) }
            #expect(throws: (any Error).self) { try f.authority.statusCold(identity: f.grant.identity) }
            #expect(throws: (any Error).self) { try f.authority.read(identity: f.grant.identity, id: completion.receipt.grant.id, daemon: f.daemon) }
            #expect(throws: (any Error).self) { try f.authority.complete(identity: f.grant.identity, id: completion.receipt.grant.id, daemon: f.daemon) }
            #expect(throws: (any Error).self) { try f.authority.adoptedService(identity: f.grant.identity) }
            #expect(throws: (any Error).self) { try f.authority.serviceResult(identity: f.grant.identity, grantID: completion.receipt.grant.id, daemon: f.daemon) }
            #expect(throws: (any Error).self) { try f.authority.serviceBootTrust(identity: f.grant.identity, grantID: completion.receipt.grant.id, serviceChangeID: nil, daemon: f.daemon) }
            #expect(throws: (any Error).self) { try f.authority.issue(operation: .retire, id: uuid(), identity: f.grant.identity, expectedEpoch: 2, candidate: f.candidate, daemon: f.daemon) }
            let change = try L.ServiceChangeRequest(operationID: uuid(), predecessor: completion.successor)
            #expect(throws: (any Error).self) { try f.authority.stageServiceChange(change: change, daemon: f.daemon) }
            #expect(throws: (any Error).self) { try f.authority.completeServiceChange(identity: f.grant.identity, operationID: change.operationID, daemon: f.daemon) }
            // Dedicated exact cold proofs remain fresh and usable under the fence.
            let retry = try f.complete(prepared)
            #expect(retry.receipt.nonce != completion.receipt.nonce)
            let projection = try f.authority.coldOriginPrincipal(binding: f.disk)
            let seed = try StorageLifecycleColdShimProtocol.ColdEnrollmentSeed(operationID: completion.operationID,
                signedOpenSHA256: completion.signedOpenSHA256, successorOrigin: projection.0.wire, baseEpoch: projection.2)
            _ = try StorageLifecycleColdShimProtocol.ColdEnrollmentAcknowledgement(for: seed)
            #expect(throws: (any Error).self) { try f.authority.guardColdPublication(store: f.disk.storeID.rawValue) }
        }
        try f.enroll(); try f.reload()
        try f.authority.guardColdPublication(store: f.disk.storeID.rawValue)
        #expect(try f.authority.serviceResult(identity: f.grant.identity, grantID: completion.receipt.grant.id, daemon: f.daemon).grant == completion.receipt.grant)
    }

    @Test(arguments: [false, true])
    func completedUnenrolledDeadOwnerPermitsOnlyFreshColdAndEnrollment(adoptedBeforeCold: Bool) throws {
        let f = try ColdFixture(adoptedBeforeCold: adoptedBeforeCold), prepared = try f.prepare()
        f.open(); let completed = try f.complete(prepared)
        let (oldOrigin, oldPrincipal, oldEpoch, _) = try f.authority.coldOriginPrincipal(binding: f.disk)
        let oldSeed = try StorageLifecycleColdShimProtocol.ColdEnrollmentSeed(operationID: completed.operationID,
            signedOpenSHA256: completed.signedOpenSHA256, successorOrigin: oldOrigin.wire, baseEpoch: oldEpoch)
        for pid: Int32 in [20, 21, 22] { f.checks.lives[pid] = .exited }
        try f.reload()
        let bytes = f.journal.bytes, adoptionBytes = f.adoptionJournal.bytes, signs = f.journal.signs
        let status = try f.authority.statusCold(identity: f.grant.identity)
        #expect(status.eligibility == .eligible && status.predecessor.currentGrant == completed.receipt.grant)
        #expect(status.origin == completed.successorOrigin && status.allocatedEpoch == completed.baseEpoch)
        let handoff = try f.authority.handoffStatus(identity: f.grant.identity, daemon: process(30))
        #expect(handoff.currentService == completed.successor && handoff.pending == nil && handoff.completion == nil)
        #expect(f.journal.bytes == bytes && f.adoptionJournal.bytes == adoptionBytes && f.journal.signs == signs)
        // Discovery is not enrollment, adoption, ordinary service authority or an L2 bridge.
        #expect(throws: (any Error).self) { try f.authority.guardColdPublication(store: f.disk.storeID.rawValue) }
        #expect(throws: (any Error).self) { try f.authority.status(identity: f.grant.identity) }
        #expect(throws: (any Error).self) { try f.authority.adoptedService(identity: f.grant.identity) }
        #expect(throws: (any Error).self) { try f.authority.recoverHandoff(identity: f.grant.identity, operationID: uuid(), daemon: process(30)) }
        #expect(throws: (any Error).self) { try f.authority.resolveDeadCold(f.resolution(prepared)) }
        #expect(throws: (any Error).self) { try f.prepare() }
        #expect(throws: (any Error).self) { try f.complete(prepared) }
        #expect(throws: (any Error).self) {
            try f.authority.completeColdEnrollment(seed: oldSeed, origin: oldOrigin, nativePrincipal: oldPrincipal)
        }
        let request = try f.successorRequest(after: completed)
        f.checks.mountedPID = 32
        let next = try f.authority.prepareCold(request, daemon: process(30))
        #expect(next.recoveryBridge == nil && next.signedOpen.request.takeover.grant.expectedEpoch == 2)
        #expect(next.signedOpen.request.takeover.grant.serial > completed.receipt.grant.serial)
        #expect(next.baseEpoch == completed.baseEpoch + 1)
        #expect(try f.authority.retainedColdClaimOperationIDs() == [request.operationID])
        try f.reload()
        #expect(throws: (any Error).self) { try f.authority.statusCold(identity: f.grant.identity) }
        #expect(throws: (any Error).self) { try f.authority.guardColdPublication(store: f.disk.storeID.rawValue) }
        f.open(); f.checks.revision = 3
        f.checks.ca = String(repeating: "3", count: 64); f.checks.server = String(repeating: "4", count: 64)
        let successor = try f.authority.completeCold(operationID: request.operationID,
            signedOpenSHA256: next.signedOpenSHA256, daemon: process(30))
        #expect(successor.recoveryBridge == nil && successor.successor.context.controllerEpoch == 3)
        #expect(successor.successor.context.serviceEpoch != completed.successor.context.serviceEpoch)
        #expect(throws: (any Error).self) { try f.authority.guardColdPublication(store: f.disk.storeID.rawValue) }
        #expect(throws: (any Error).self) {
            try f.authority.completeColdEnrollment(seed: oldSeed, origin: oldOrigin, nativePrincipal: oldPrincipal)
        }
        try f.enroll(); try f.reload()
        try f.authority.guardColdPublication(store: f.disk.storeID.rawValue)
        #expect(try f.authority.adoptedService(identity: f.grant.identity) == successor.successor)
    }

    @Test func unenrolledColdRequiresPositiveDeathOfEveryRetainedParticipant() throws {
        for pid: Int32 in [10, 11, 12, 20, 21, 22, 40, 41] {
            for life in [BootstrapLiveness.alive, .unknown] {
                let f = try ColdFixture(adoptedBeforeCold: true), prepared = try f.prepare()
                f.open(); let completed = try f.complete(prepared)
                let request = try f.successorRequest(after: completed)
                for dead: Int32 in [20, 21, 22] { f.checks.lives[dead] = .exited }
                f.checks.lives[pid] = life; f.checks.mountedPID = 32
                try f.reload()
                let bytes = f.journal.bytes, adoptionBytes = f.adoptionJournal.bytes, signs = f.journal.signs
                #expect(throws: (any Error).self) { try f.authority.statusCold(identity: f.grant.identity) }
                #expect(throws: (any Error).self) { try f.authority.handoffStatus(identity: f.grant.identity, daemon: process(30)) }
                // Direct prepare cannot rely on a previously observed eligible status.
                #expect(throws: (any Error).self) { try f.authority.prepareCold(request, daemon: process(30)) }
                #expect(f.journal.bytes == bytes && f.adoptionJournal.bytes == adoptionBytes && f.journal.signs == signs)
            }
        }
    }

    @Test(arguments: [false, true])
    func unenrolledColdRejectsMissingOrAdvancedAdoptionRotation(advanced: Bool) throws {
        let f = try ColdFixture(), oldAdoption = f.adoptionJournal.bytes, prepared = try f.prepare()
        f.open(); let completed = try f.complete(prepared)
        let request = try f.successorRequest(after: completed)
        for pid: Int32 in [20, 21] { f.checks.lives[pid] = .exited }
        if advanced {
            // Logical seam constructs a competing adoption; normal routes stay fenced.
            _ = try f.prepareAdoption(pid: 40, epoch: completed.baseEpoch)
        } else { f.adoptionJournal.bytes = oldAdoption }
        f.checks.lives[22] = .exited; f.checks.mountedPID = 32
        // Existing cross-journal consistency validation may refuse on reopen already.
        #expect(throws: (any Error).self) { try f.reload() }
        let bytes = f.journal.bytes, adoptionBytes = f.adoptionJournal.bytes
        #expect(throws: (any Error).self) { try f.authority.statusCold(identity: f.grant.identity) }
        #expect(throws: (any Error).self) { try f.authority.handoffStatus(identity: f.grant.identity, daemon: process(30)) }
        #expect(throws: (any Error).self) { try f.authority.prepareCold(request, daemon: process(30)) }
        #expect(f.journal.bytes == bytes && f.adoptionJournal.bytes == adoptionBytes)
    }

    @Test(arguments: [false, true])
    func unenrolledColdSuccessorL1CutsNeverReleasePublicationFence(afterWrite: Bool) throws {
        let f = try ColdFixture(), prepared = try f.prepare()
        f.open(); let completed = try f.complete(prepared)
        let request = try f.successorRequest(after: completed)
        for pid: Int32 in [20, 21, 22] { f.checks.lives[pid] = .exited }
        f.checks.mountedPID = 32
        let bytes = f.journal.bytes
        if afterWrite { f.journal.afterWrite = { throw BootstrapFailure(.unavailable) } }
        else { f.journal.failAt = f.journal.writes + 1 }
        #expect(throws: (any Error).self) { try f.authority.prepareCold(request, daemon: process(30)) }
        f.journal.afterWrite = nil; f.journal.failAt = nil
        try f.reload()
        #expect(throws: (any Error).self) { try f.authority.guardColdPublication(store: f.disk.storeID.rawValue) }
        if afterWrite {
            #expect(throws: (any Error).self) { try f.authority.statusCold(identity: f.grant.identity) }
            #expect(try f.authority.retainedColdClaimOperationIDs() == [request.operationID])
        } else {
            #expect(f.journal.bytes == bytes)
            #expect(try f.authority.statusCold(identity: f.grant.identity).eligibility == .eligible)
            #expect(try f.authority.retainedColdClaimOperationIDs() == [completed.operationID])
        }
        let retry = try f.authority.prepareCold(request, daemon: process(30))
        #expect(retry.recoveryBridge == nil && retry.signedOpen.request.takeover.grant.expectedEpoch == 2)
        #expect(throws: (any Error).self) { try f.authority.guardColdPublication(store: f.disk.storeID.rawValue) }
    }

    @Test func enrollmentCheckpointCutsAndLostReplyRequireFreshExactProof() throws {
        for after in [false, true] {
            let f = try ColdFixture(), prepared = try f.prepare()
            f.open(); _ = try f.complete(prepared)
            let failAt = f.journal.writes + 1
            if after { f.journal.afterWrite = { if f.journal.writes == failAt { throw BootstrapFailure(.unavailable) } } }
            else { f.journal.failAt = failAt }
            #expect(throws: (any Error).self) { try f.enroll() }
            f.journal.failAt = nil; f.journal.afterWrite = nil
            try f.reload()
            if after { try f.authority.guardColdPublication(store: f.disk.storeID.rawValue) }
            else { #expect(throws: (any Error).self) { try f.authority.guardColdPublication(store: f.disk.storeID.rawValue) } }
            f.checks.mountedAllowed = false
            #expect(throws: (any Error).self) { try f.enroll() }
            #expect(throws: (any Error).self) { try f.complete(prepared) }
            f.checks.mountedAllowed = true
            try f.enroll(); try f.authority.guardColdPublication(store: f.disk.storeID.rawValue)
            let writes = f.journal.writes, proofs = f.checks.nonces.count
            try f.enroll() // Exact lost-ACK retry proves again without another write.
            #expect(f.journal.writes == writes && f.checks.nonces.count > proofs)
        }
    }

    @Test func enrollmentRejectsMismatchedSeedAndNativePrincipal() throws {
        let f = try ColdFixture(), prepared = try f.prepare()
        f.open(); _ = try f.complete(prepared)
        let (origin, principal, epoch, completion) = try f.authority.coldOriginPrincipal(binding: f.disk)
        let seed = try StorageLifecycleColdShimProtocol.ColdEnrollmentSeed(operationID: completion.operationID,
            signedOpenSHA256: completion.signedOpenSHA256, successorOrigin: origin.wire, baseEpoch: epoch)
        let bad = try StorageLifecycleColdShimProtocol.ColdEnrollmentSeed(operationID: uuid(),
            signedOpenSHA256: completion.signedOpenSHA256, successorOrigin: origin.wire, baseEpoch: epoch)
        let writes = f.journal.writes
        #expect(throws: (any Error).self) { try f.authority.completeColdEnrollment(seed: bad, origin: origin, nativePrincipal: principal) }
        let stranger = BootstrapPrincipal(daemon: process(30), child: principal.child,
            incarnation: principal.incarnation, controllerSPKI: principal.controllerSPKI)
        #expect(throws: (any Error).self) { try f.authority.completeColdEnrollment(seed: seed, origin: origin, nativePrincipal: stranger) }
        f.checks.mountedAllowed = false
        #expect(throws: (any Error).self) { try f.authority.completeColdEnrollment(seed: seed, origin: origin, nativePrincipal: principal) }
        #expect(f.journal.writes == writes)
        #expect(throws: (any Error).self) { try f.authority.guardColdPublication(store: f.disk.storeID.rawValue) }
    }

    @Test func completedColdClearsFreshOriginAndReattachedHistoricalOriginFailsReload() throws {
        let f = try ColdFixture()
        let original = try #require(f.journal.bytes)
        var json = try #require(JSONSerialization.jsonObject(with: original) as? [String: Any])
        var stores = try #require(json["stores"] as? [String: Any])
        let originJSON = try #require((stores[f.grant.identity.store] as? [String: Any])?["freshOrigin"])
        let prepared = try f.prepare()
        // A pending cold transaction still carries the verified anchor.
        let pendingBytes = try #require(f.journal.bytes)
        var pendingJSON = try #require(JSONSerialization.jsonObject(with: pendingBytes) as? [String: Any])
        let pendingStore = try #require((pendingJSON["stores"] as? [String: Any])?[f.grant.identity.store] as? [String: Any])
        #expect(pendingStore["freshOrigin"] is [String: Any] && pendingStore["freshPhase"] as? String == "verified")
        f.open(); _ = try f.complete(prepared)
        // Completed cold successor: the historical anchor and phase are cleared.
        let clearedBytes = try #require(f.journal.bytes)
        var clearedJSON = try #require(JSONSerialization.jsonObject(with: clearedBytes) as? [String: Any])
        var clearedStores = try #require(clearedJSON["stores"] as? [String: Any])
        var clearedStore = try #require(clearedStores[f.grant.identity.store] as? [String: Any])
        #expect(clearedStore["freshOrigin"] is NSNull && clearedStore["freshPhase"] is NSNull)
        try f.reload() // Cleared anchor loads; publication stays fenced until enrollment.
        #expect(throws: (any Error).self) { try f.authority.guardColdPublication(store: f.disk.storeID.rawValue) }
        // Re-attaching the immutable historical origin is repair-level corruption.
        clearedStore["freshOrigin"] = originJSON; clearedStore["freshPhase"] = "verified"
        clearedStores[f.grant.identity.store] = clearedStore; clearedJSON["stores"] = clearedStores
        f.journal.bytes = try JSONSerialization.data(withJSONObject: clearedJSON, options: [.sortedKeys, .withoutEscapingSlashes])
        #expect(throws: (any Error).self) { try f.reload() }
    }

    @Test func requiredColdSchemaAndCrossJournalMismatchesFailClosed() throws {
        let f = try ColdFixture(), oldAdoption = f.adoptionJournal.bytes
        let prepared = try f.prepare(), l1 = f.journal.bytes
        f.open(); _ = try f.complete(prepared)
        let l3 = f.journal.bytes
        f.journal.bytes = l1 // L1 A1 is impossible, never repair automatically.
        #expect(throws: (any Error).self) { try f.reload() }
        f.journal.bytes = l3; f.adoptionJournal.bytes = oldAdoption // L3 A0.
        #expect(throws: (any Error).self) { try f.reload() }
        let l1Bytes = try #require(l1)
        for field in ["pendingCold", "latestCold"] {
            var json = try #require(JSONSerialization.jsonObject(with: l1Bytes) as? [String: Any])
            var stores = try #require(json["stores"] as? [String: [String: Any]])
            stores[f.disk.storeID.rawValue]?.removeValue(forKey: field); json["stores"] = stores
            f.journal.bytes = try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys, .withoutEscapingSlashes])
            #expect(throws: (any Error).self) { try f.reload() }
        }
    }
}

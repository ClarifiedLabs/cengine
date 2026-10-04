import CEngineCore
import CryptoKit
import Darwin
import Foundation
import Testing
@testable import StorageBootstrapHelper

private typealias L = StorageLifecycleProtocol
private typealias C = StorageLifecycleResumeRootProtocol
private func uuid() -> String { UUID().uuidString.lowercased() }
private func process(_ pid: Int32) -> BootstrapProcess {
    var token = audit_token_t(); token.val = (501, 501, 20, 501, 20, UInt32(pid), 1, 2)
    return .init(pid: pid, startSeconds: 1, startMicroseconds: 0, boot: "test-boot",
        signingIdentity: "unsigned-test-seam", uniqueID: UInt64(pid), pidVersion: 2,
        auditToken: BootstrapAuditIdentity(token: token).data)
}
private final class ResumeJournal: StorageLifecycleJournal, StorageLifecycleAdoptionJournal {
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
    func signResumeOpen(_ request: StorageLifecycleResumeProtocol.Request) throws -> StorageLifecycleResumeProtocol.SignedOpen {
        signs += 1; return try .init(request: request, signature: key.signature(for: request.signingBytes))
    }
    func signServiceChange(_ request: L.ServiceChangeRequest) throws -> L.SignedServiceChange {
        try .init(request: request, signature: key.signature(for: request.signingBytes))
    }
}
/// Explicit unsigned logical seam; not native acceptance or production proof.
private final class ResumeChecks: StorageLifecycleProcessChecking, StorageLifecycleAdoptionChecking,
    StorageLifecycleFreshBindingChecking, StorageLifecycleColdChecking, StorageLifecycleResumeChecking {
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
        let origin = StorageLifecycleFreshOrigin(greeting: greeting, shim: process(12), daemon: daemon, grant: grant, principal: principal)
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
    func mounted(request: StorageLifecycleColdRootProtocol.Prepare, unsignedGrant: L.Grant, signedOpenDigest: String,
                 baseEpoch: UInt64, daemon: BootstrapProcess) throws -> StorageLifecycleShimOrigin {
        throw BootstrapFailure(.unauthorized)
    }
    func mounted(request: C.Prepare, unsignedGrant: L.Grant, signedOpenDigest: String,
                 baseEpoch: UInt64, daemon: BootstrapProcess) throws -> StorageLifecycleShimOrigin {
        mountedCalls += 1
        guard mountedAllowed else { throw BootstrapFailure(.unavailable) }
        return try .init(wire: request.probeGreeting.successorOrigin, shim: process(22),
            originalDaemon: daemon, originalController: process(request.candidate.childPIDHint))
    }
}
private final class ResumeFixture {
    let journal: ResumeJournal, adoptionJournal: ResumeJournal
    let checks = ResumeChecks()
    let disk: StorageIdentity.StoreBinding
    let initial: StorageIdentity.Candidate, candidate: StorageIdentity.Candidate
    let daemon = process(20)
    var authority: StorageBootstrapLifecycleAuthority
    var adoption: StorageBootstrapLifecycleAdoptionAuthority
    let grant: L.Grant
    let request: C.Prepare
    init(completed: Bool = true, binding: StorageIdentity.StoreBinding? = nil) throws {
        let key = Curve25519.Signing.PrivateKey()
        journal = ResumeJournal(key: key); adoptionJournal = ResumeJournal(key: key)
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
        if completed { _ = try authority.complete(identity: grant.identity, id: grant.id, daemon: process(10)) }
        try authority.configureCold(adoption: adoption, mounted: checks)
        try authority.configureResume(mounted: checks)
        for pid: Int32 in [10, 11, 12] { checks.lives[pid] = .exited }
        let status = try authority.statusResume(identity: grant.identity)
        let launch = try StorageLifecycleColdProtocol.Launch(shimLaunchUUID: uuid(), specSHA256: String(repeating: "d", count: 64),
            initramfsSHA256: String(repeating: "e", count: 64), ext4UUID: volume.rawValue, bytes: 4096)
        let greeting = try StorageLifecycleColdShimProtocol.Greeting(channelID: uuid(), daemonUniqueID: 20,
            rootPublicKey: journal.rootPublicKey(), binding: .init(disk),
            bootBinding: .init(shimLaunchUUID: launch.shimLaunchUUID, guestBootNonce: uuid(), ext4UUID: volume.rawValue, bytes: 4096),
            launch: launch, heldBackingIdentity: .init(.init(stableIdentity: disk.backing.identity, device: 1)), purpose: .resumeReadOnly)
        request = try .init(operationID: uuid(), identity: grant.identity, expectedOriginal: status.original,
            candidate: candidate, probeGreeting: greeting, expectedOriginalShimLaunchUUID: status.originalShimLaunchUUID,
            nowUnixSeconds: 100, lifetimeSeconds: 100)
    }

    func open() { checks.service = uuid(); checks.ca = String(repeating: "1", count: 64); checks.server = String(repeating: "2", count: 64); checks.revision = 2 }
    func prepare() throws -> C.Prepared { try authority.prepareResume(request, daemon: daemon) }
    func complete(_ prepared: C.Prepared) throws -> C.Completed {
        try authority.completeResume(operationID: request.operationID, signedOpenSHA256: prepared.signedOpenSHA256, daemon: daemon)
    }
    func enroll() throws {
        let (origin, principal, epoch, completion) = try authority.resumeOriginPrincipal(binding: disk)
        let seed = try StorageLifecycleColdShimProtocol.ColdEnrollmentSeed(operationID: completion.operationID,
            signedOpenSHA256: completion.signedOpenSHA256, successorOrigin: origin.wire, baseEpoch: epoch, purpose: .resumeReadOnly)
        try adoption.recordOrigin(origin, rootFD: 1, backingFD: 2)
        try authority.completeResumeEnrollment(seed: seed, origin: origin, nativePrincipal: principal)
    }
    func reload() throws {
        authority = try .init(journal: journal, processes: checks, bindings: checks)
        adoption = try .init(journal: adoptionJournal, processes: checks)
        try authority.configureCold(adoption: adoption, mounted: checks)
        try authority.configureResume(mounted: checks)
    }
}

@Suite struct StorageBootstrapLifecycleResumeTests {
    @Test func enrollmentRequiresProtectedGreetingDeviceBeforeAndAfterWrites() throws {
        let native = try NativeBindingFixture(), f = try ResumeFixture(binding: native.binding)
        let prepared = try f.prepare(); f.open(); _ = try f.complete(prepared)
        try f.reload() // Expectation must survive ROOT restart, never come from the seed.
        let (origin, principal, epoch, completion) = try f.authority.resumeOriginPrincipal(binding: f.disk)
        let seed = try StorageLifecycleColdShimProtocol.ColdEnrollmentSeed(operationID: completion.operationID,
            signedOpenSHA256: completion.signedOpenSHA256, successorOrigin: origin.wire, baseEpoch: epoch, purpose: .resumeReadOnly)
        let expected = try f.authority.authorizeResumeEnrollment(seed: seed, origin: origin, nativePrincipal: principal)
        #expect(expected == (try f.request.probeGreeting.heldBackingIdentity.value()))
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

    @Test func lookupReturnsOnlyProtectedStatusWithoutWritingSigningOrMounting() throws {
        for completed in [false, true] {
            let f = try ResumeFixture(completed: completed)
            try f.reload()
            let bytes = f.journal.bytes, adoptionBytes = f.adoptionJournal.bytes
            let signs = f.journal.signs, writes = f.journal.writes, proofs = f.checks.nonces.count
            let binding = StorageLifecycleStoreBinding(f.disk)
            let status = try f.authority.lookupResume(binding: binding)
            #expect(status == (try f.authority.statusResume(identity: f.grant.identity)))
            #expect(status.original == f.grant && status.eligibility == .eligible)
            for pid: Int32 in [10, 11, 12] {
                f.checks.lives[pid] = .unknown
                #expect(try f.authority.lookupResume(binding: binding).eligibility == .unavailable)
                f.checks.lives[pid] = .exited
            }
            #expect(f.journal.bytes == bytes && f.adoptionJournal.bytes == adoptionBytes)
            #expect(f.journal.signs == signs && f.journal.writes == writes)
            #expect(f.checks.mountedCalls == 0 && f.checks.nonces.count == proofs)
            _ = try f.prepare()
            #expect(throws: (any Error).self) { try f.authority.lookupResume(binding: binding) }
        }
    }
    @Test func lookupRejectsEveryCopiedBindingFieldAndNeverEnumerates() throws {
        let f = try ResumeFixture(), binding = StorageLifecycleStoreBinding(f.disk)
        let object = try #require(JSONSerialization.jsonObject(with: L.encode(binding)) as? [String: Any])
        var mutations: [[String: Any]] = []
        for field in ["store", "ext4_uuid", "bytes"] {
            var changed = object
            changed[field] = field == "bytes" ? 8192 : uuid()
            mutations.append(changed)
        }
        for file in ["root", "backing"] {
            for field in ["inode", "volume_uuid"] {
                var changed = object
                var identity = try #require(changed[file] as? [String: Any])
                identity[field] = field == "volume_uuid" ? uuid() : 999
                changed[file] = identity; mutations.append(changed)
            }
        }
        let bytes = f.journal.bytes, signs = f.journal.signs, writes = f.journal.writes
        for changed in mutations {
            let data = try JSONSerialization.data(withJSONObject: changed, options: [.sortedKeys, .withoutEscapingSlashes])
            let wrong = try L.decode(StorageLifecycleStoreBinding.self, from: data)
            _ = try wrong.value()
            #expect(throws: (any Error).self) { try f.authority.lookupResume(binding: wrong) }
        }
        let empty = try StorageBootstrapLifecycleAuthority(journal: ResumeJournal(key: f.journal.key), processes: f.checks, bindings: f.checks)
        #expect(throws: (any Error).self) { try empty.lookupResume(binding: binding) }
        #expect(f.journal.bytes == bytes && f.journal.signs == signs && f.journal.writes == writes)
        #expect(try f.authority.lookupResume(binding: binding).original == f.grant)
    }
    @Test func exactSignaturesRetryPendingAndCompletedOriginalThroughEnrollment() throws {
        for completed in [false, true] {
            let f = try ResumeFixture(completed: completed), prepared = try f.prepare()
            let signs = f.journal.signs
            try f.reload(); #expect(try f.prepare() == prepared)
            #expect(f.journal.signs == signs)
            f.open(); let result = try f.complete(prepared)
            try f.reload()
            #expect(try f.complete(prepared).receipt.nonce != result.receipt.nonce)
            #expect(try f.prepare() == prepared)
            #expect(f.journal.signs == signs)
            #expect(try f.adoption.registeredOrigin(store: f.grant.identity.store) == nil)
            #expect(throws: (any Error).self) { try f.authority.guardColdPublication(store: f.grant.identity.store) }
            let (origin, principal, epoch, completion) = try f.authority.resumeOriginPrincipal(binding: f.disk)
            let seed = try StorageLifecycleColdShimProtocol.ColdEnrollmentSeed(operationID: completion.operationID,
                signedOpenSHA256: completion.signedOpenSHA256, successorOrigin: origin.wire, baseEpoch: epoch, purpose: .resumeReadOnly)
            // A seed (or seed ACK) is not an actual native enrollment.
            _ = try StorageLifecycleColdShimProtocol.ColdEnrollmentAcknowledgement(for: seed)
            #expect(throws: (any Error).self) { try f.authority.completeResumeEnrollment(seed: seed, origin: origin, nativePrincipal: principal) }
            try f.enroll(); try f.reload()
            try f.authority.guardColdPublication(store: f.grant.identity.store)
            #expect(try f.adoption.status(store: f.grant.identity.store).baseEpoch == 1)
            #expect(try f.authority.status(identity: f.grant.identity).epoch.rawValue == 2)
        }
    }
    @Test func requiresPositiveExitOfEveryOriginalTupleAndNoExistingAdoption() throws {
        for pid: Int32 in [10, 11, 12] {
            for life in [BootstrapLiveness.unknown, .alive] {
                let f = try ResumeFixture(); f.checks.lives[pid] = life
                let bytes = f.journal.bytes
                #expect(try f.authority.statusResume(identity: f.grant.identity).eligibility == .unavailable)
                #expect(throws: (any Error).self) { try f.prepare() }
                #expect(f.journal.bytes == bytes)
            }
        }
        let f = try ResumeFixture()
        let origin = try StorageLifecycleShimOrigin(wire: f.request.probeGreeting.successorOrigin,
            shim: process(12), originalDaemon: process(10), originalController: process(11))
        try f.adoption.recordOrigin(origin, rootFD: 1, backingFD: 2)
        #expect(throws: (any Error).self) { try f.prepare() }
    }
    @Test func ordinaryPublicationRemainsFencedBeforeAndAfterCompletion() throws {
        let f = try ResumeFixture(), prepared = try f.prepare()
        for completed in [false, true] {
            if completed { f.open(); _ = try f.complete(prepared) }
            try f.reload()
            #expect(throws: (any Error).self) { try f.authority.status(identity: f.grant.identity) }
            #expect(throws: (any Error).self) { try f.authority.currentOriginPrincipal(binding: f.disk) }
            #expect(throws: (any Error).self) { try f.authority.read(identity: f.grant.identity, id: f.grant.id, daemon: process(10)) }
            #expect(throws: (any Error).self) { try f.authority.complete(identity: f.grant.identity, id: prepared.signedOpen.request.takeover.grant.id, daemon: f.daemon) }
            #expect(throws: (any Error).self) { try f.authority.adoptedService(identity: f.grant.identity) }
            #expect(throws: (any Error).self) { try f.authority.issue(operation: .takeover, id: uuid(), identity: f.grant.identity, expectedEpoch: 2, candidate: f.candidate, daemon: f.daemon) }
            #expect(throws: (any Error).self) { try f.authority.serviceBootTrust(identity: f.grant.identity, grantID: f.grant.id, serviceChangeID: nil, daemon: process(10)) }
        }
        try f.enroll(); try f.authority.guardColdPublication(store: f.grant.identity.store)
    }
    @Test func everyCheckpointCutRetainsExactRetryAndEnrollmentFence() throws {
        // R1, R2, R3, initial adoption, R4; before-write and lost-return failures.
        for cut in 0..<5 {
            for after in [false, true] {
                let f = try ResumeFixture()
                var prepared: C.Prepared?
                if cut > 0 { prepared = try f.prepare(); f.open() }
                if cut > 2 { _ = try f.complete(prepared!) }
                let target = cut == 3 ? f.adoptionJournal : f.journal
                let failAt = target.writes + (cut == 2 ? 2 : 1)
                if after { target.afterWrite = { if target.writes == failAt { throw BootstrapFailure(.unavailable) } } }
                else { target.failAt = failAt }
                if cut == 0 { #expect(throws: (any Error).self) { try f.prepare() } }
                else if cut < 3 { #expect(throws: (any Error).self) { try f.complete(prepared!) } }
                else { #expect(throws: (any Error).self) { try f.enroll() } }
                target.failAt = nil; target.afterWrite = nil
                try f.reload()
                let retry = try f.prepare()
                if let prepared { #expect(retry == prepared) }
                if cut == 0 { f.open() }
                _ = try f.complete(retry)
                if cut != 4 || !after {
                    #expect(throws: (any Error).self) { try f.authority.guardColdPublication(store: f.grant.identity.store) }
                }
                try f.enroll(); try f.reload()
                try f.authority.guardColdPublication(store: f.grant.identity.store)
            }
        }
    }
    @Test func postdurableMountLossNeverReleasesSignaturesOrEnrollment() throws {
        let f = try ResumeFixture()
        f.journal.afterWrite = { f.checks.mountedAllowed = false }
        #expect(throws: (any Error).self) { try f.prepare() }
        f.journal.afterWrite = nil; f.checks.mountedAllowed = true
        let signs = f.journal.signs
        try f.reload(); let prepared = try f.prepare()
        #expect(f.journal.signs == signs)
        f.open(); _ = try f.complete(prepared)
        f.checks.mountedAllowed = false
        #expect(throws: (any Error).self) { try f.enroll() }
        #expect(throws: (any Error).self) { try f.authority.guardColdPublication(store: f.grant.identity.store) }
    }
    @Test func durableUnverifiedFormatWitnessCanResumeButNeverReleaseOriginal() throws {
        let f = try ResumeFixture(completed: false)
        let original = try #require(f.journal.bytes)
        var json = try #require(JSONSerialization.jsonObject(with: original) as? [String: Any])
        var stores = try #require(json["stores"] as? [String: [String: Any]])
        stores[f.grant.identity.store]?["freshPhase"] = "unverified"; json["stores"] = stores
        f.journal.bytes = try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys, .withoutEscapingSlashes])
        try f.reload()
        #expect(throws: (any Error).self) { try f.authority.read(identity: f.grant.identity, id: f.grant.id, daemon: process(10)) }
        let status = try f.authority.lookupResume(binding: .init(f.disk))
        #expect(status.original == f.grant && status.eligibility == .eligible)
        let prepared = try f.prepare(); f.open(); _ = try f.complete(prepared)
        try f.enroll(); try f.reload()
        try f.authority.guardColdPublication(store: f.grant.identity.store)
    }
    @Test func enrollmentRejectsWrongSeedAndPrincipalWithoutWriting() throws {
        let f = try ResumeFixture(), prepared = try f.prepare()
        f.open(); _ = try f.complete(prepared)
        let (origin, principal, epoch, completion) = try f.authority.resumeOriginPrincipal(binding: f.disk)
        let seed = try StorageLifecycleColdShimProtocol.ColdEnrollmentSeed(operationID: uuid(),
            signedOpenSHA256: completion.signedOpenSHA256, successorOrigin: origin.wire, baseEpoch: epoch, purpose: .resumeReadOnly)
        let bytes = f.journal.bytes
        #expect(throws: (any Error).self) { try f.authority.authorizeResumeEnrollment(seed: seed, origin: origin, nativePrincipal: principal) }
        let exact = try StorageLifecycleColdShimProtocol.ColdEnrollmentSeed(operationID: completion.operationID,
            signedOpenSHA256: completion.signedOpenSHA256, successorOrigin: origin.wire, baseEpoch: epoch, purpose: .resumeReadOnly)
        let stranger = BootstrapPrincipal(daemon: process(30), child: principal.child,
            incarnation: principal.incarnation, controllerSPKI: principal.controllerSPKI)
        #expect(throws: (any Error).self) { try f.authority.authorizeResumeEnrollment(seed: exact, origin: origin, nativePrincipal: stranger) }
        #expect(f.journal.bytes == bytes)
    }
    @Test func missingResumeStateCannotBeReconstructed() throws {
        let f = try ResumeFixture(); _ = try f.prepare()
        let original = try #require(f.journal.bytes)
        for field in ["pendingResume", "latestResume", "freshOrigin", "freshPhase"] {
            var json = try #require(JSONSerialization.jsonObject(with: original) as? [String: Any])
            var stores = try #require(json["stores"] as? [String: [String: Any]])
            stores[f.grant.identity.store]?.removeValue(forKey: field); json["stores"] = stores
            f.journal.bytes = try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys, .withoutEscapingSlashes])
            #expect(throws: (any Error).self) { try f.reload() }
        }
    }
}

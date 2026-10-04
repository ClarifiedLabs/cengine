import CEngineCore
import CryptoKit
import Darwin
import Foundation
import Testing
@testable import StorageBootstrapHelper

private typealias L = StorageLifecycleProtocol

private final class LifecycleMemory: StorageLifecycleJournal {
    let key = Curve25519.Signing.PrivateKey()
    var data: Data?
    var failWrite = false
    var failRead = false
    var afterWrite: (() -> Void)?
    var writes = 0
    var signatures = 0
    var peakBytes = 0
    func load() throws -> Data? { data }
    func lifecycleRootPublicKey() throws -> StorageIdentity.RootPublicKey {
        if failRead { throw BootstrapFailure(.repairRequired) }
        return try .init(publicData: key.publicKey.rawRepresentation)
    }
    func checkpoint(_ data: Data) throws {
        if failWrite { throw BootstrapFailure(.repairRequired) }
        self.data = data; writes += 1; peakBytes = max(peakBytes, data.count); afterWrite?()
    }
    func signLifecycle(_ grant: L.Grant) throws -> L.SignedGrant {
        signatures += 1
        return try .init(grant: grant, signature: key.signature(for: grant.signingBytes))
    }
    func signServiceChange(_ request: L.ServiceChangeRequest) throws -> L.SignedServiceChange {
        try .init(request: request, signature: key.signature(for: request.signingBytes))
    }
}
private func lifecycleID() -> String { UUID().uuidString.lowercased() }
private func lifecycleProcess(_ pid: Int32) -> BootstrapProcess {
    .init(pid: pid, startSeconds: 1, startMicroseconds: 2, boot: "unit-boot", signingIdentity: "unit-only",
          uniqueID: UInt64(pid), pidVersion: 1, auditToken: Data(repeating: UInt8(truncatingIfNeeded: pid), count: 32))
}
/// Exact authenticated fresh origin seam: greeting fields derive ONLY from the
/// exact binding/daemon/root key, never from caller-selected origin parts.
private func lifecycleFreshGreeting(binding: StorageIdentity.StoreBinding, daemon: BootstrapProcess,
                                    rootPublicKey: Data, guestBootNonce: String) throws -> StorageLifecycleFreshProtocol.Greeting {
    try .init(channelID: lifecycleID(), daemonUniqueID: daemon.uniqueID, rootPublicKey: rootPublicKey,
        store: binding.storeID.rawValue, shimLaunchUUID: lifecycleID(), guestBootNonce: guestBootNonce,
        operationUUID: lifecycleID(), ext4UUID: binding.expectedExt4UUID.rawValue,
        bytes: binding.backing.size, initramfsSHA256: String(repeating: "c", count: 64),
        device: 1, inode: binding.backing.identity.inode,
        volumeUUID: binding.backing.identity.volumeUUID.rawValue)
}
private final class LifecycleProcesses: StorageLifecycleProcessChecking {
    // Explicit unsigned test seam, not native process or TLS acceptance.
    var root: String = ""
    var ca = String(repeating: "a", count: 64)
    var server = String(repeating: "b", count: 64)
    var liveService: String?
    var openRevision: UInt64 = 1
    var allowServiceResult = true
    var adoptedBootProof: ((L.Grant) throws -> StorageLifecycleBootTrust)?
    var allowCommit = true
    var serviceNonces: [Data] = []
    var commits = 0
    var dead = Set<Int32>()
    var lives: [Int32: BootstrapLiveness] = [:]
    var allowReceipt = true
    var alterNonce = false
    var service = lifecycleID()
    var revisionOverride: UInt64?
    var nonces: [Data] = []
    var afterReceipt: (() -> Void)?
    var receiptCalls = 0
    func candidate(_ candidate: StorageIdentity.Candidate, daemon: BootstrapProcess, grant: L.Grant) throws -> BootstrapPrincipal {
        let principal = BootstrapPrincipal(daemon: daemon, child: lifecycleProcess(candidate.childPIDHint),
            incarnation: candidate.incarnationID.rawValue, controllerSPKI: candidate.publicKey.publicData)
        try validateRecipient(principal, daemon: daemon, grant: grant)
        return principal
    }
    func liveness(_ process: BootstrapProcess) -> BootstrapLiveness { lives[process.pid] ?? (dead.contains(process.pid) ? .exited : .unknown) }
    func validateRecipient(_ principal: BootstrapPrincipal, daemon: BootstrapProcess, grant: L.Grant) throws {
        guard principal.daemon == daemon, !dead.contains(principal.child.pid), !dead.contains(daemon.pid),
              try StorageIdentity.Ed25519SPKI(publicData: principal.controllerSPKI).fingerprint.rawValue == grant.newKey else { throw BootstrapFailure(.unauthorized) }
    }
    func serviceBootTrust(_ principal: BootstrapPrincipal, daemon: BootstrapProcess, grant: L.Grant) throws -> StorageLifecycleBootTrust {
        try validateRecipient(principal, daemon: daemon, grant: grant)
        if let adoptedBootProof { return try adoptedBootProof(grant) }
        return try .init(identity: grant.identity, serviceEpoch: liveService ?? service,
                         tlsRootSHA256: ca, serverSPKI: server, bootstrapKey: root)
    }
    func serviceResult(_ principal: BootstrapPrincipal, daemon: BootstrapProcess, grant: L.Grant,
                       nonce: Data, boot: StorageLifecycleBootTrust, changeRequest: L.ServiceChangeRequest?,
                       confirmation: L.ServiceChangeConfirmation?) throws -> L.ServiceResult {
        try validateRecipient(principal, daemon: daemon, grant: grant)
        guard allowServiceResult, confirmation == nil || allowCommit else { throw BootstrapFailure(.unavailable) }
        if confirmation != nil { commits += 1 }
        serviceNonces.append(nonce)
        return try .init(identity: grant.identity, grant: grant, nonce: nonce, serviceEpoch: liveService ?? service,
            controllerEpoch: grant.expectedEpoch + 1, controllerKey: grant.newKey, openRevision: openRevision)
    }
    func receipt(_ principal: BootstrapPrincipal, daemon: BootstrapProcess, grant: L.Grant, nonce: Data) throws -> L.Receipt {
        try validateRecipient(principal, daemon: daemon, grant: grant)
        // Mirror native receipt ordering: fresh shim proof, then independent child result.
        _ = try adoptedBootProof?(grant)
        guard allowReceipt else { throw BootstrapFailure(.unavailable) }
        receiptCalls += 1
        nonces.append(nonce)
        afterReceipt?()
        return try .init(grant: grant, nonce: alterNonce ? Data(repeating: 0, count: 32) : nonce,
                         serviceEpoch: service, revision: revisionOverride ?? grant.serial)
    }
}
private final class LifecycleBindings: StorageLifecycleFreshBindingChecking {
    var fresh = true
    var calls = 0
    var claims: [L.Grant] = []
    var rootPublicKey = Data()
    // Mismatch/foreign-origin injection seams for regression tests only.
    var alterRepublishedOrigin = false
    var foreignOrigin = false
    private var formed: [String: StorageLifecycleFreshOrigin] = [:]
    func verifyFresh(_ binding: StorageIdentity.StoreBinding, grant: L.Grant, daemon: BootstrapProcess,
                     principal: BootstrapPrincipal, rootFD: Int32, backingFD: Int32) throws -> StorageLifecycleFreshOrigin {
        calls += 1
        claims.append(grant)
        guard fresh else { throw BootstrapFailure(.conflict) }
        // A live shim greeting is stable across the pre/post publication proofs;
        // exact retries of the same grant return the identical formed origin.
        if let existing = formed[grant.id] {
            guard alterRepublishedOrigin else { return existing }
            let greeting = try lifecycleFreshGreeting(binding: binding, daemon: daemon,
                rootPublicKey: rootPublicKey, guestBootNonce: lifecycleID())
            return StorageLifecycleFreshOrigin(greeting: greeting, shim: existing.shim,
                daemon: existing.daemon, grant: existing.grant, principal: existing.principal)
        }
        let target = foreignOrigin ? try lifecycleBinding(99, store: lifecycleID()) : binding
        let greeting = try lifecycleFreshGreeting(binding: target, daemon: daemon,
            rootPublicKey: rootPublicKey, guestBootNonce: lifecycleID())
        let origin = StorageLifecycleFreshOrigin(greeting: greeting, shim: lifecycleProcess(Int32(daemon.uniqueID + 1000)),
            daemon: daemon, grant: grant, principal: principal)
        formed[grant.id] = origin
        return origin
    }
}
private func lifecycleCandidate(_ pid: Int32) throws -> StorageIdentity.Candidate {
    try .init(publicKey: .init(rawPublicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation),
              childPIDHint: pid, incarnationID: .init(lifecycleID()))
}
private func lifecycleBinding(_ number: UInt64, store: String = lifecycleID()) throws -> StorageIdentity.StoreBinding {
    let root = try StorageIdentity.RootIdentity(volumeUUID: .init("11111111-1111-4111-8111-111111111111"), inode: number * 2 + 1)
    return try .init(storeID: .init(store), root: root,
        backing: .init(identity: .init(volumeUUID: root.volumeUUID, inode: number * 2 + 2), size: 4096), expectedExt4UUID: root.volumeUUID)
}
private struct LifecycleFixture {
    let journal = LifecycleMemory()
    let processes = LifecycleProcesses()
    let bindings = LifecycleBindings()
    let authority: StorageBootstrapLifecycleAuthority
    let disk: StorageIdentity.StoreBinding
    let initial: StorageIdentity.Candidate
    let daemon = lifecycleProcess(10)
    let initialization: L.SignedGrant
    init(complete: Bool = true) throws {
        disk = try lifecycleBinding(1); initial = try lifecycleCandidate(11)
        processes.root = try journal.lifecycleRootPublicKey().fingerprint.rawValue
        bindings.rootPublicKey = try journal.lifecycleRootPublicKey().publicData
        authority = try .init(journal: journal, processes: processes, bindings: bindings)
        initialization = try authority.provision(id: lifecycleID(), binding: disk, candidate: initial, daemon: daemon, rootFD: 1, backingFD: 2)
        if complete { _ = try authority.complete(identity: initialization.grant.identity, id: initialization.grant.id, daemon: daemon) }
    }
    func die(_ daemon: BootstrapProcess, _ candidate: StorageIdentity.Candidate) {
        processes.dead.insert(daemon.pid); processes.dead.insert(candidate.childPIDHint)
    }
    func reopen() throws -> StorageBootstrapLifecycleAuthority { try .init(journal: journal, processes: processes, bindings: bindings) }
}

private final class AdoptedChangeJournal: StorageLifecycleAdoptionJournal {
    let root: Data
    var bytes: Data?
    init(root: Data) { self.root = root }
    func load() throws -> Data? { bytes }
    func rootPublicKey() throws -> Data { root }
    func checkpoint(_ bytes: Data) throws { self.bytes = bytes }
}
private func adoptedChangeProcess(_ pid: Int32) -> BootstrapProcess {
    var token = audit_token_t(); token.val = (501, 501, 20, 501, 20, UInt32(pid), 1, 2)
    return .init(pid: pid, startSeconds: 1, startMicroseconds: 0, boot: "unit-boot", signingIdentity: "test-only",
        uniqueID: UInt64(pid), pidVersion: 2, auditToken: BootstrapAuditIdentity(token: token).data)
}
private final class AdoptedChangeProcesses: StorageLifecycleAdoptionChecking {
    let principal: BootstrapPrincipal
    var candidateValid = true, shimValid = true
    init() throws {
        principal = .init(daemon: adoptedChangeProcess(60), child: adoptedChangeProcess(61),
            incarnation: lifecycleID(), controllerSPKI: try lifecycleCandidate(61).publicKey.publicData)
    }
    func freshOrigin(_ origin: StorageLifecycleShimOrigin, rootFD: Int32, backingFD: Int32) throws {}
    func candidate(_ request: Adoption.Request, peer: BootstrapAuditIdentity) throws -> BootstrapPrincipal {
        guard candidateValid else { throw BootstrapFailure(.unauthorized) }; return principal
    }
    func liveness(_ process: BootstrapProcess) -> BootstrapLiveness { .exited }
    func registeredShim(_ origin: StorageLifecycleShimOrigin) throws {
        guard shimValid else { throw BootstrapFailure(.unauthorized) }
    }
    func fence(_ challenge: Adoption.Challenge, origin: StorageLifecycleShimOrigin) throws {}
    func commit(_ request: Adoption.Request, origin: StorageLifecycleShimOrigin) throws {}
}
/// Unsigned authority seam, not a native permission. Distinct original and retained
/// recipients model the owner separation that survives lifecycle takeovers.
private final class AdoptedChangeFixture {
    let f: LifecycleFixture
    let processes: AdoptedChangeProcesses
    let adoption: StorageBootstrapLifecycleAdoptionAuthority
    let origin: StorageLifecycleShimOrigin
    let request: Adoption.Request
    let peer: BootstrapAuditIdentity
    let change: L.ServiceChangeRequest
    let boot: StorageLifecycleBootTrust
    var nonces: [Data] = []
    var targets: [StorageLifecycleBootTrust?] = []
    var completions: [L.ServiceChangeConfirmation?] = []
    var checkValid = true
    var afterProof: (() throws -> Void)?
    var failProof: Int?
    var replay: Adoption.ServiceChangeReply?
    var replies: [Adoption.ServiceChangeReply] = []
    init(target: Bool = false) throws {
        f = try LifecycleFixture(); processes = try AdoptedChangeProcesses()
        let root = try f.journal.lifecycleRootPublicKey().publicData
        origin = try .init(wire: .init(binding: .init(f.disk), rootPublicKey: root,
            shimLaunchUUID: lifecycleID(), specSHA256: String(repeating: "a", count: 64)),
            shim: adoptedChangeProcess(42), originalDaemon: adoptedChangeProcess(40), originalController: adoptedChangeProcess(41))
        adoption = try .init(journal: AdoptedChangeJournal(root: root), processes: processes)
        try adoption.recordOrigin(origin, rootFD: -1, backingFD: -1)
        request = try .init(id: lifecycleID(), origin: origin.wire, expectedEpoch: 1,
            daemonAudit: processes.principal.daemon.auditToken, daemonUniqueID: processes.principal.daemon.uniqueID,
            controllerAudit: processes.principal.child.auditToken, controllerUniqueID: processes.principal.child.uniqueID)
        peer = .init(token: processes.principal.daemon.auditToken.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) })
        try adoption.prepare(request, peer: peer); _ = try adoption.complete(request, peer: peer)
        change = try .init(operationID: lifecycleID(), predecessor: f.serviceState())
        _ = try f.authority.stageServiceChange(change: change, daemon: f.daemon)
        f.replaceService(2)
        boot = try f.processes.serviceBootTrust(.init(daemon: f.daemon, child: lifecycleProcess(11),
            incarnation: f.initial.incarnationID.rawValue, controllerSPKI: f.initial.publicKey.publicData),
            daemon: f.daemon, grant: f.initialization.grant)
        if target {
            _ = try f.authority.serviceBootTrust(identity: f.initialization.grant.identity,
                grantID: f.initialization.grant.id, serviceChangeID: change.operationID, daemon: f.daemon)
        }
        f.processes.dead.formUnion([10, 11, 40, 41])
    }
    func complete(_ authority: StorageBootstrapLifecycleAuthority? = nil,
                  request override: Adoption.Request? = nil, change other: L.ServiceChangeRequest? = nil) throws -> (L.ServiceChangeConfirmation, L.ServiceResult) {
        try (authority ?? f.authority).completeAdoptedServiceChange(adoption: override ?? request, change: other ?? change,
            peer: peer, adoptionAuthority: adoption, check: {
                guard self.checkValid else { throw BootstrapFailure(.unauthorized) }
            }, prove: { change, target, completed, nonce, origin in
                #expect(origin == self.origin)
                self.nonces.append(nonce); self.targets.append(target); self.completions.append(completed)
                try self.afterProof?()
                if self.failProof == self.nonces.count { throw BootstrapFailure(.unavailable) }
                if let replay = self.replay { return replay }
                let challenge = try Adoption.ServiceChangeChallenge(adoption: self.request, change: change,
                    targetBoot: target, completed: completed, counter: UInt64(self.nonces.count), nonce: nonce,
                    expiresUnixMS: UInt64(Date().timeIntervalSince1970 * 1000) + 30_000)
                let grant = change.predecessor.grant
                let result = try L.ServiceResult(identity: grant.identity, grant: grant, nonce: nonce,
                    serviceEpoch: self.boot.serviceEpoch, controllerEpoch: grant.expectedEpoch + 1,
                    controllerKey: grant.newKey, openRevision: 2)
                let reply = try Adoption.ServiceChangeReply(challenge: challenge, result: result, boot: self.boot)
                self.replies.append(reply)
                return reply
            })
    }
}

@Suite struct StorageBootstrapLifecycleAuthorityTests {
    @Test func bindingCheckpointUsesNeutralDTOAndRefusesRetiredEnvelopeWithoutWrites() throws {
        let f = try LifecycleFixture()
        let original = try #require(f.journal.data)
        var state = try #require(JSONSerialization.jsonObject(with: original) as? [String: Any])
        var stores = try #require(state["stores"] as? [String: Any])
        var store = try #require(stores[f.disk.storeID.rawValue] as? [String: Any])
        let encoded = try #require(store["binding"] as? String)
        let bytes = try #require(Data(base64Encoded: encoded))
        #expect(try JSONDecoder().decode(StorageLifecycleStoreBinding.self, from: bytes).value() == f.disk)
        _ = try f.reopen()
        let retired = Data("{\"version\":\"bootstrap.v1\",\"operation\":\"registerInitialController\",\"body\":{}}".utf8)
        for invalid in [retired, bytes + Data([10])] {
            store["binding"] = invalid.base64EncodedString()
            stores[f.disk.storeID.rawValue] = store; state["stores"] = stores
            f.journal.data = try JSONSerialization.data(withJSONObject: state, options: [.sortedKeys, .withoutEscapingSlashes])
            let before = f.journal.data, writes = f.journal.writes
            #expect(throws: (any Error).self) { try f.reopen() }
            #expect(f.journal.data == before && f.journal.writes == writes)
        }
    }

    @Test func nativeOriginPrincipalRequiresCompletedExactInitializationAndLiveController() throws {
        let pending = try LifecycleFixture(complete: false)
        #expect(throws: (any Error).self) { try pending.authority.currentOriginPrincipal(binding: pending.disk) }
        let f = try LifecycleFixture()
        let (grant, principal, boot) = try f.authority.currentOriginPrincipal(binding: f.disk)
        #expect(grant == f.initialization.grant)
        #expect(principal.daemon == f.daemon && principal.child.pid == f.initial.childPIDHint)
        #expect(boot.serviceEpoch == f.processes.service)
        #expect(throws: (any Error).self) { try f.authority.currentOriginPrincipal(binding: lifecycleBinding(2, store: f.disk.storeID.rawValue)) }
        f.die(f.daemon, f.initial)
        #expect(throws: (any Error).self) { try f.authority.currentOriginPrincipal(binding: f.disk) }
    }

    @Test func freshEnrollmentRetainsAuthenticatedDeviceAndRejectsOtherShim() throws {
        let f = try LifecycleFixture()
        let (_, principal, _) = try f.authority.currentOriginPrincipal(binding: f.disk)
        let fresh = try f.bindings.verifyFresh(f.disk, grant: f.initialization.grant,
            daemon: f.daemon, principal: principal, rootFD: 1, backingFD: 2)
        let wire = try Adoption.Origin(binding: .init(f.disk), rootPublicKey: fresh.greeting.rootPublicKey,
            shimLaunchUUID: fresh.greeting.shimLaunchUUID, specSHA256: String(repeating: "a", count: 64))
        let origin = StorageLifecycleShimOrigin(wire: wire, shim: fresh.shim,
            originalDaemon: fresh.daemon, originalController: principal.child)
        let expected = try f.reopen().freshEnrollmentBacking(origin: origin)
        #expect(expected.stableIdentity == f.disk.backing.identity && expected.device == fresh.greeting.device)
        let stranger = StorageLifecycleShimOrigin(wire: wire, shim: lifecycleProcess(9999),
            originalDaemon: fresh.daemon, originalController: principal.child)
        #expect(throws: (any Error).self) { try f.authority.freshEnrollmentBacking(origin: stranger) }
    }

    @Test func freshProofBindsAllocatedGrantAndIsRepeatedAfterPublication() throws {
        let f = try LifecycleFixture(complete: false)
        #expect(f.bindings.calls == 2)
        #expect(f.bindings.claims == [f.initialization.grant, f.initialization.grant])
    }

    @Test func freshnessLostDuringPublicationRetainsFenceWithoutReleasingSignature() throws {
        let journal = LifecycleMemory(), processes = LifecycleProcesses(), bindings = LifecycleBindings()
        bindings.rootPublicKey = try journal.lifecycleRootPublicKey().publicData
        let authority = try StorageBootstrapLifecycleAuthority(journal: journal, processes: processes, bindings: bindings)
        let disk = try lifecycleBinding(7), candidate = try lifecycleCandidate(11), daemon = lifecycleProcess(10)
        let id = lifecycleID()
        journal.afterWrite = { bindings.fresh = false }
        #expect(throws: (any Error).self) {
            try authority.provision(id: id, binding: disk, candidate: candidate, daemon: daemon, rootFD: 1, backingFD: 2)
        }
        #expect(journal.writes == 1 && journal.signatures == 0 && bindings.calls == 2)
        let grant = try #require(bindings.claims.first)
        #expect(throws: (any Error).self) { try authority.status(identity: grant.identity) }
        let reopened = try StorageBootstrapLifecycleAuthority(journal: journal, processes: processes, bindings: bindings)
        // The durable fence is explicitly unverified: an exact same-recipient
        // retry without FDs is blocked and completion cannot bypass the missing
        // verified phase. No signature ever escapes the failed attempt.
        #expect(throws: (any Error).self) {
            try reopened.provision(id: id, binding: disk, candidate: candidate, daemon: daemon)
        }
        #expect(throws: (any Error).self) { try reopened.complete(identity: grant.identity, id: grant.id, daemon: daemon) }
        #expect(throws: (any Error).self) { try reopened.status(identity: grant.identity) }
        #expect(journal.writes == 1 && journal.signatures == 0)
    }

    @Test func unverifiedPublicationBlocksExactRetryAndCompletionWithoutSignature() throws {
        let journal = LifecycleMemory(), processes = LifecycleProcesses(), bindings = LifecycleBindings()
        bindings.rootPublicKey = try journal.lifecycleRootPublicKey().publicData
        processes.root = try journal.lifecycleRootPublicKey().fingerprint.rawValue
        let authority = try StorageBootstrapLifecycleAuthority(journal: journal, processes: processes, bindings: bindings)
        let disk = try lifecycleBinding(7), candidate = try lifecycleCandidate(11), daemon = lifecycleProcess(10)
        let id = lifecycleID()
        bindings.alterRepublishedOrigin = true
        #expect(throws: (any Error).self) {
            try authority.provision(id: id, binding: disk, candidate: candidate, daemon: daemon, rootFD: 1, backingFD: 2)
        }
        bindings.alterRepublishedOrigin = false
        // Writes: one unverified commit; the mismatched post-commit proof never
        // reaches the verified phase commit, and no signature is released.
        #expect(journal.writes == 1 && journal.signatures == 0 && bindings.calls == 2)
        let grant = try #require(bindings.claims.first)
        let reopened = try StorageBootstrapLifecycleAuthority(journal: journal, processes: processes, bindings: bindings)
        for subject in [authority, reopened] {
            #expect(throws: (any Error).self) { try subject.provision(id: id, binding: disk, candidate: candidate, daemon: daemon) }
            #expect(throws: (any Error).self) { try subject.complete(identity: grant.identity, id: grant.id, daemon: daemon) }
            #expect(throws: (any Error).self) { try subject.read(identity: grant.identity, id: grant.id, daemon: daemon) }
            #expect(throws: (any Error).self) {
                try subject.serviceBootTrust(identity: grant.identity, grantID: grant.id, serviceChangeID: nil, daemon: daemon)
            }
        }
        #expect(journal.writes == 1 && journal.signatures == 0)
    }

    @Test func moreThan4096CompletedTakeoversStayBoundedAndOldGrantsDisappear() throws {
        let f = try LifecycleFixture()
        var authority = f.authority
        let identity = f.initialization.grant.identity
        var owner = f.daemon, candidate = f.initial, previous = f.initialization
        for epoch in UInt64(1)...4098 {
            f.die(owner, candidate)
            owner = lifecycleProcess(Int32(epoch * 2 + 20)); candidate = try lifecycleCandidate(owner.pid + 1)
            let grant = try authority.issue(operation: .takeover, id: lifecycleID(), identity: identity,
                expectedEpoch: epoch, candidate: candidate, daemon: owner)
            #expect(grant.grant.serial == epoch + 1)
            #expect(grant.isValidSignature(using: try f.journal.lifecycleRootPublicKey()))
            _ = try authority.complete(identity: identity, id: grant.grant.id, daemon: owner)
            #expect(try authority.status(identity: identity).epoch.rawValue == epoch + 1)
            #expect(throws: (any Error).self) { try authority.read(identity: identity, id: previous.grant.id, daemon: owner) }
            if epoch % 257 == 0 { authority = try f.reopen() }
            previous = grant
        }
        #expect(f.journal.peakBytes < 12_000)
        #expect(try authority.read(identity: identity, id: previous.grant.id, daemon: owner).grant == previous.grant)
        #expect(try f.reopen().status(identity: identity).epoch.rawValue == 4099)
    }

    @Test func moreThan128RetiredDatastoresReclaimOnlyAfterDurableSeal() throws {
        let journal = LifecycleMemory(), processes = LifecycleProcesses(), bindings = LifecycleBindings()
        processes.root = try journal.lifecycleRootPublicKey().fingerprint.rawValue
        bindings.rootPublicKey = try journal.lifecycleRootPublicKey().publicData
        var authority = try StorageBootstrapLifecycleAuthority(journal: journal, processes: processes, bindings: bindings)
        // Deliberately reuse the store UUID: generation, not historical UUID membership,
        // prevents the old signed initialization from becoming fresh authority again.
        let store = lifecycleID(), daemon = lifecycleProcess(10)
        var previous: L.Identity?
        for number in UInt64(1)...130 {
            let disk = try lifecycleBinding(number, store: store), candidate = try lifecycleCandidate(11)
            let grant = try authority.provision(id: lifecycleID(), binding: disk, candidate: candidate, daemon: daemon, rootFD: 1, backingFD: 2)
            #expect(grant.grant.identity.generation == number)
            if let previous { #expect(throws: (any Error).self) { try authority.status(identity: previous) } }
            let identity = grant.grant.identity
            _ = try authority.complete(identity: identity, id: grant.grant.id, daemon: daemon)
            let retirement = try authority.issue(operation: .retire, id: lifecycleID(), identity: identity, expectedEpoch: 1, candidate: candidate, daemon: daemon)
            #expect(throws: (any Error).self) { try authority.reclaim(identity: identity, id: retirement.grant.id, daemon: daemon) }
            _ = try authority.complete(identity: identity, id: retirement.grant.id, daemon: daemon)
            #expect(throws: (any Error).self) { try authority.status(identity: identity) }
            try authority.reclaim(identity: identity, id: retirement.grant.id, daemon: daemon)
            try authority.reclaim(identity: identity, id: retirement.grant.id, daemon: daemon)
            previous = identity
            authority = try .init(journal: journal, processes: processes, bindings: bindings)
        }
        #expect(journal.peakBytes < 16_000)
        let bytes = try #require(journal.data)
        let state = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        #expect((state["stores"] as? [String: Any])?.isEmpty == true)
        #expect((state["generation"] as? NSNumber)?.uint64Value == 130)
        #expect((state["serial"] as? NSNumber)?.uint64Value == 260)
    }

    @Test func provisioningAndPendingRecipientsNeverTimeoutOrSupersede() throws {
        let f = try LifecycleFixture(complete: false), identity = f.initialization.grant.identity
        #expect(throws: (any Error).self) { try f.authority.status(identity: identity) }
        let retry = try f.authority.provision(id: f.initialization.grant.id, binding: f.disk, candidate: f.initial, daemon: f.daemon)
        #expect(retry.grant == f.initialization.grant)
        f.die(f.daemon, f.initial)
        let reopened = try f.reopen()
        #expect(throws: (any Error).self) { try reopened.complete(identity: identity, id: retry.grant.id, daemon: f.daemon) }
        #expect(throws: (any Error).self) { try reopened.issue(operation: .takeover, id: lifecycleID(), identity: identity, expectedEpoch: 1, candidate: lifecycleCandidate(21), daemon: lifecycleProcess(20)) }
        #expect(f.journal.writes == 2)
    }

    @Test func completedTakeoverClearsFreshOriginAndReattachedHistoricalOriginFailsReopen() throws {
        let f = try LifecycleFixture(), identity = f.initialization.grant.identity
        let original = try #require(f.journal.data)
        var json = try #require(JSONSerialization.jsonObject(with: original) as? [String: Any])
        var stores = try #require(json["stores"] as? [String: Any])
        let originJSON = try #require((stores[identity.store] as? [String: Any])?["freshOrigin"])
        // A pending successor still carries the verified anchor.
        f.die(f.daemon, f.initial)
        let daemon = lifecycleProcess(20), candidate = try lifecycleCandidate(21)
        let grant = try f.authority.issue(operation: .takeover, id: lifecycleID(), identity: identity,
            expectedEpoch: 1, candidate: candidate, daemon: daemon)
        let pendingBytes = try #require(f.journal.data)
        let pendingJSON = try #require(JSONSerialization.jsonObject(with: pendingBytes) as? [String: Any])
        let pendingStore = try #require((pendingJSON["stores"] as? [String: Any])?[identity.store] as? [String: Any])
        #expect(pendingStore["freshOrigin"] is [String: Any] && pendingStore["freshPhase"] as? String == "verified")
        _ = try f.authority.complete(identity: identity, id: grant.grant.id, daemon: daemon)
        // First completed takeover: the historical anchor and phase are cleared.
        let clearedBytes = try #require(f.journal.data)
        var clearedJSON = try #require(JSONSerialization.jsonObject(with: clearedBytes) as? [String: Any])
        var clearedStores = try #require(clearedJSON["stores"] as? [String: Any])
        var clearedStore = try #require(clearedStores[identity.store] as? [String: Any])
        #expect(clearedStore["freshOrigin"] is NSNull && clearedStore["freshPhase"] is NSNull)
        #expect(try f.reopen().status(identity: identity).epoch.rawValue == 2)
        // Re-attaching the immutable historical origin is repair-level corruption.
        clearedStore["freshOrigin"] = originJSON; clearedStore["freshPhase"] = "verified"
        clearedStores[identity.store] = clearedStore; clearedJSON["stores"] = clearedStores
        f.journal.data = try JSONSerialization.data(withJSONObject: clearedJSON, options: [.sortedKeys, .withoutEscapingSlashes])
        #expect(throws: (any Error).self) { try f.reopen() }
    }

    @Test func freshOriginRoleAliasIdentityGenerationAndPhaseTamperFailsClosedReopen() throws {
        let f = try LifecycleFixture(complete: false), original = try #require(f.journal.data)
        let storeKey = f.initialization.grant.identity.store
        func reserialized(_ mutate: (inout [String: Any]) throws -> Void) throws -> Data {
            var json = try #require(JSONSerialization.jsonObject(with: original) as? [String: Any])
            try mutate(&json)
            return try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys, .withoutEscapingSlashes])
        }
        func tamperOrigin(_ json: inout [String: Any], _ mutate: (inout [String: Any]) throws -> Void) throws {
            var stores = try #require(json["stores"] as? [String: Any])
            var store = try #require(stores[storeKey] as? [String: Any])
            var origin = try #require(store["freshOrigin"] as? [String: Any])
            try mutate(&origin)
            store["freshOrigin"] = origin; stores[storeKey] = store; json["stores"] = stores
        }
        func tamperStore(_ json: inout [String: Any], _ mutate: (inout [String: Any]) throws -> Void) throws {
            var stores = try #require(json["stores"] as? [String: Any])
            var store = try #require(stores[storeKey] as? [String: Any])
            try mutate(&store)
            stores[storeKey] = store; json["stores"] = stores
        }
        // Role alias: the pinned shim assumes the proven controller child process.
        f.journal.data = try reserialized {
            try tamperOrigin(&$0) {
                let principal = try #require($0["principal"] as? [String: Any])
                $0["shim"] = try #require(principal["child"])
            }
        }
        #expect(throws: (any Error).self) { try f.reopen() }
        // Grant identity store tampered away from the durable binding.
        f.journal.data = try reserialized {
            try tamperOrigin(&$0) {
                var grant = try #require($0["grant"] as? [String: Any])
                var ident = try #require(grant["identity"] as? [String: Any])
                ident["store"] = "tampered-store"
                grant["identity"] = ident; $0["grant"] = grant
            }
        }
        #expect(throws: (any Error).self) { try f.reopen() }
        // Generation tampered away from the durable initialize intent.
        f.journal.data = try reserialized {
            try tamperOrigin(&$0) {
                var grant = try #require($0["grant"] as? [String: Any])
                var ident = try #require(grant["identity"] as? [String: Any])
                ident["generation"] = NSNumber(value: UInt64(999))
                grant["identity"] = ident; $0["grant"] = grant
            }
        }
        #expect(throws: (any Error).self) { try f.reopen() }
        // Phase corrupted to an unknown label, or dropped while the origin remains.
        f.journal.data = try reserialized {
            try tamperStore(&$0) { $0["freshPhase"] = "bogus" }
        }
        #expect(throws: (any Error).self) { try f.reopen() }
        f.journal.data = try reserialized {
            try tamperStore(&$0) { $0["freshPhase"] = NSNull() }
        }
        #expect(throws: (any Error).self) { try f.reopen() }
        // Untampered verified snapshot still loads and the exact retry releases
        // the same grant to the same proven recipient.
        f.journal.data = original
        let reopened = try f.reopen()
        #expect(try reopened.provision(id: f.initialization.grant.id, binding: f.disk,
            candidate: f.initial, daemon: f.daemon).grant == f.initialization.grant)
    }

    @Test func pendingTakeoverRetainsOriginalRecipientAcrossDeathAndRestart() throws {
        let f = try LifecycleFixture(), identity = f.initialization.grant.identity
        f.die(f.daemon, f.initial)
        let daemon = lifecycleProcess(20), candidate = try lifecycleCandidate(21)
        let grant = try f.authority.issue(operation: .takeover, id: lifecycleID(), identity: identity, expectedEpoch: 1, candidate: candidate, daemon: daemon)
        let writes = f.journal.writes
        #expect(try f.authority.issue(operation: .takeover, id: grant.grant.id, identity: identity, expectedEpoch: 1, candidate: candidate, daemon: daemon).grant == grant.grant)
        f.die(daemon, candidate)
        let reopened = try f.reopen()
        #expect(throws: (any Error).self) { try reopened.read(identity: identity, id: grant.grant.id, daemon: daemon) }
        #expect(throws: (any Error).self) { try reopened.issue(operation: .takeover, id: lifecycleID(), identity: identity, expectedEpoch: 1, candidate: lifecycleCandidate(31), daemon: lifecycleProcess(30)) }
        #expect(f.journal.writes == writes)
    }

    @Test func adoptedPendingTakeoverRequiresFreshNewControllerBeforeChildCompletion() throws {
        typealias A = StorageLifecycleAdoptionProtocol
        let f = try LifecycleFixture(), old = f.initialization.grant, identity = old.identity
        let protected = try f.authority.adoptedService(identity: identity)
        #expect(try f.authority.adoptedService(identity: identity, proving: old) == protected)
        let daemon = lifecycleProcess(20), candidate = try lifecycleCandidate(21)
        let adoption = try A.Request(id: lifecycleID(), origin: .init(binding: .init(f.disk),
            rootPublicKey: f.journal.key.publicKey.rawRepresentation, shimLaunchUUID: lifecycleID(),
            specSHA256: String(repeating: "a", count: 64)), expectedEpoch: 1,
            daemonAudit: daemon.auditToken, daemonUniqueID: daemon.uniqueID,
            controllerAudit: lifecycleProcess(21).auditToken, controllerUniqueID: 21)
        // Explicit Query seam: observations are independent of ROOT's expectation.
        var observedGrant = old
        var observedBoot = protected.boot
        var observedRevision = protected.openRevision
        var counter: UInt64 = 0
        func freshProof(_ grant: L.Grant) throws -> StorageLifecycleBootTrust {
            counter += 1
            let expected = try f.authority.adoptedService(identity: identity, proving: grant)
            let nonce = Data(repeating: UInt8(truncatingIfNeeded: counter), count: 32)
            let challenge = try A.ServiceChallenge(adoption: adoption, grant: grant, expected: expected,
                counter: counter, nonce: nonce, expiresUnixMS: 31_000)
            let result = try L.ServiceResult(identity: identity, grant: grant, nonce: nonce,
                serviceEpoch: observedBoot.serviceEpoch, controllerEpoch: observedGrant.expectedEpoch + 1,
                controllerKey: observedGrant.newKey, openRevision: observedRevision)
            return try A.ServiceReply(challenge: challenge, result: result, boot: observedBoot).boot
        }
        #expect(try freshProof(old) == protected.boot) // Pre-takeover old C proof succeeds.
        f.die(f.daemon, f.initial)
        let next = try f.authority.issue(operation: .takeover, id: lifecycleID(), identity: identity,
            expectedEpoch: 1, candidate: candidate, daemon: daemon).grant
        let writes = f.journal.writes
        let expected = try f.authority.adoptedService(identity: identity, proving: next)
        #expect(expected.grant == next && expected.context.controllerEpoch == 2)
        #expect(expected.context.controllerKey == next.newKey)
        #expect(expected.boot == protected.boot && expected.openRevision == protected.openRevision)
        #expect(try f.reopen().adoptedService(identity: identity, proving: next) == expected)
        #expect(f.journal.writes == writes) // Projection cannot publish success.
        #expect(throws: (any Error).self) { try f.authority.adoptedService(identity: identity) }
        #expect(throws: (any Error).self) { try f.authority.adoptedService(identity: identity, proving: old) }
        for wrong in [
            try L.Grant(operation: .takeover, id: lifecycleID(), identity: identity, serial: next.serial, expectedEpoch: 1, newKey: next.newKey),
            try L.Grant(operation: .takeover, id: next.id, identity: identity, serial: next.serial, expectedEpoch: 2, newKey: next.newKey),
            try L.Grant(operation: .takeover, id: next.id, identity: identity, serial: next.serial, expectedEpoch: 1, newKey: old.newKey)
        ] {
            #expect(throws: (any Error).self) { try f.authority.adoptedService(identity: identity, proving: wrong) }
        }
        f.processes.adoptedBootProof = freshProof
        defer { f.processes.adoptedBootProof = nil }
        #expect(throws: (any Error).self) { try f.authority.complete(identity: identity, id: next.id, daemon: daemon) }
        observedGrant = next // Child takeover + coordinator reconcile have advanced C/key.
        observedBoot = try .init(identity: identity, serviceEpoch: lifecycleID(),
            tlsRootSHA256: protected.boot.tlsRootSHA256, serverSPKI: protected.boot.serverSPKI,
            bootstrapKey: protected.boot.bootstrapKey)
        #expect(throws: (any Error).self) { try f.authority.complete(identity: identity, id: next.id, daemon: daemon) }
        observedBoot = protected.boot
        observedRevision += 1
        #expect(throws: (any Error).self) { try freshProof(next) }
        observedRevision = protected.openRevision
        #expect(try freshProof(next) == protected.boot)
        f.processes.allowReceipt = false
        #expect(throws: (any Error).self) { try f.authority.complete(identity: identity, id: next.id, daemon: daemon) }
        #expect(f.journal.writes == writes) // Even correct shim proof cannot replace child receipt.
        f.processes.allowReceipt = true
        #expect(try f.authority.complete(identity: identity, id: next.id, daemon: daemon).grant == next)
        #expect(try f.authority.adoptedService(identity: identity) == expected)
        #expect(try freshProof(next) == protected.boot) // Exact current-grant path after publication.
        #expect(throws: (any Error).self) { try freshProof(old) }
    }

    @Test func adoptedProjectionRejectsInitializationAndRetirementPendingStates() throws {
        let initializing = try LifecycleFixture(complete: false)
        #expect(throws: (any Error).self) {
            try initializing.authority.adoptedService(identity: initializing.initialization.grant.identity,
                proving: initializing.initialization.grant)
        }
        let f = try LifecycleFixture(), identity = f.initialization.grant.identity
        let retire = try f.authority.issue(operation: .retire, id: lifecycleID(), identity: identity,
            expectedEpoch: 1, candidate: f.initial, daemon: f.daemon).grant
        #expect(throws: (any Error).self) { try f.authority.adoptedService(identity: identity, proving: retire) }
    }

    @Test func activeProvisioningAndSealedAliasesAreExcluded() throws {
        let f = try LifecycleFixture(complete: false)
        let alias = StorageIdentity.StoreBinding(storeID: try .init(lifecycleID()), root: f.disk.root, backing: f.disk.backing, expectedExt4UUID: f.disk.expectedExt4UUID)
        for phase in 0..<3 {
            #expect(throws: (any Error).self) { try f.authority.provision(id: lifecycleID(), binding: alias, candidate: lifecycleCandidate(21), daemon: lifecycleProcess(20), rootFD: 1, backingFD: 2) }
            if phase == 0 { _ = try f.authority.complete(identity: f.initialization.grant.identity, id: f.initialization.grant.id, daemon: f.daemon) }
            if phase == 1 {
                let r = try f.authority.issue(operation: .retire, id: lifecycleID(), identity: f.initialization.grant.identity, expectedEpoch: 1, candidate: f.initial, daemon: f.daemon)
                _ = try f.authority.complete(identity: r.grant.identity, id: r.grant.id, daemon: f.daemon)
            }
        }
    }

    @Test func lostOrMismatchedSealReceiptRetainsFenceAndCannotReclaim() throws {
        let f = try LifecycleFixture(), identity = f.initialization.grant.identity
        let grant = try f.authority.issue(operation: .retire, id: lifecycleID(), identity: identity, expectedEpoch: 1, candidate: f.initial, daemon: f.daemon)
        let writes = f.journal.writes
        f.processes.allowReceipt = false
        #expect(throws: (any Error).self) { try f.authority.complete(identity: identity, id: grant.grant.id, daemon: f.daemon) }
        #expect(throws: (any Error).self) { try f.authority.reclaim(identity: identity, id: grant.grant.id, daemon: f.daemon) }
        f.processes.allowReceipt = true; f.processes.alterNonce = true
        #expect(throws: (any Error).self) { try f.authority.complete(identity: identity, id: grant.grant.id, daemon: f.daemon) }
        #expect(f.journal.writes == writes)
        f.processes.alterNonce = false
        _ = try f.authority.complete(identity: identity, id: grant.grant.id, daemon: f.daemon)
        f.processes.allowReceipt = false
        #expect(throws: (any Error).self) { try f.reopen().reclaim(identity: identity, id: grant.grant.id, daemon: f.daemon) }
        f.processes.allowReceipt = true
        try f.reopen().reclaim(identity: identity, id: grant.grant.id, daemon: f.daemon)
    }

    @Test func persistenceFailureAndRecipientLossNeverReleaseSignature() throws {
        for failWrite in [false, true] {
            let f = try LifecycleFixture(), identity = f.initialization.grant.identity
            f.die(f.daemon, f.initial)
            f.journal.failWrite = failWrite
            if !failWrite { f.journal.afterWrite = { f.processes.dead.insert(21) } }
            let signatures = f.journal.signatures
            #expect(throws: (any Error).self) { try f.authority.issue(operation: .takeover, id: lifecycleID(), identity: identity, expectedEpoch: 1, candidate: lifecycleCandidate(21), daemon: lifecycleProcess(20)) }
            #expect(f.journal.signatures == signatures)
            f.journal.failWrite = false
            if failWrite { #expect(throws: (any Error).self) { try f.authority.status(identity: identity) } }
            else { #expect(throws: (any Error).self) { try f.reopen().status(identity: identity) } }
        }
    }

    @Test func completedResultIsStableAcrossReopenAndFreshChallenges() throws {
        let f = try LifecycleFixture(), identity = f.initialization.grant.identity
        let writes = f.journal.writes, originalService = f.processes.service
        #expect(Set(f.processes.nonces).count == f.processes.nonces.count)
        f.processes.service = lifecycleID()
        #expect(throws: (any Error).self) { try f.reopen().complete(identity: identity, id: f.initialization.grant.id, daemon: f.daemon) }
        f.processes.service = originalService; f.processes.revisionOverride = 99
        #expect(throws: (any Error).self) { try f.reopen().complete(identity: identity, id: f.initialization.grant.id, daemon: f.daemon) }
        f.processes.revisionOverride = nil
        _ = try f.reopen().complete(identity: identity, id: f.initialization.grant.id, daemon: f.daemon)
        #expect(f.journal.writes == writes)
        #expect(Set(f.processes.nonces).count == f.processes.nonces.count)
    }

    @Test func resultLossAfterCommitRetainsConfirmedStateAndExactRetry() throws {
        let f = try LifecycleFixture(complete: false), identity = f.initialization.grant.identity
        f.journal.afterWrite = { f.processes.allowReceipt = false }
        #expect(throws: (any Error).self) { try f.authority.complete(identity: identity, id: f.initialization.grant.id, daemon: f.daemon) }
        #expect(try f.reopen().status(identity: identity).epoch.rawValue == 1)
        let writes = f.journal.writes
        f.processes.allowReceipt = true; f.journal.afterWrite = nil
        _ = try f.reopen().complete(identity: identity, id: f.initialization.grant.id, daemon: f.daemon)
        #expect(f.journal.writes == writes)
    }

    @Test func retirementAndReclaimRetriesNeverChangeTerminalTuple() throws {
        let f = try LifecycleFixture(), identity = f.initialization.grant.identity
        let grant = try f.authority.issue(operation: .retire, id: lifecycleID(), identity: identity, expectedEpoch: 1, candidate: f.initial, daemon: f.daemon)
        _ = try f.authority.complete(identity: identity, id: grant.grant.id, daemon: f.daemon)
        let writes = f.journal.writes
        _ = try f.reopen().complete(identity: identity, id: grant.grant.id, daemon: f.daemon)
        #expect(f.journal.writes == writes)
        try f.authority.reclaim(identity: identity, id: grant.grant.id, daemon: f.daemon)
        f.processes.service = lifecycleID()
        #expect(throws: (any Error).self) { try f.reopen().reclaim(identity: identity, id: grant.grant.id, daemon: f.daemon) }
        f.die(f.daemon, f.initial)
        // A tombstone does not manufacture a live child proof or delete permission.
        #expect(throws: (any Error).self) { try f.reopen().reclaim(identity: identity, id: grant.grant.id, daemon: f.daemon) }
    }

    @Test func v1MalformedAndCounterExhaustionNeverResetAuthority() throws {
        let f = try LifecycleFixture(), original = try #require(f.journal.data)
        f.journal.data = Data("{\"stores\":{}}".utf8)
        #expect(throws: (any Error).self) { try f.reopen() }
        f.journal.data = original
        var json = try #require(JSONSerialization.jsonObject(with: original) as? [String: Any])
        json["serial"] = NSNumber(value: UInt64.max)
        f.journal.data = try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys, .withoutEscapingSlashes])
        let reopened = try f.reopen()
        f.die(f.daemon, f.initial)
        #expect(throws: (any Error).self) { try reopened.issue(operation: .takeover, id: lifecycleID(), identity: f.initialization.grant.identity, expectedEpoch: 1, candidate: lifecycleCandidate(21), daemon: lifecycleProcess(20)) }
    }

    @Test func freshOriginPersistsAcrossReopenAndBindsInitialization() throws {
        let f = try LifecycleFixture(complete: false)
        // The exact durable pending retry after reopen proves the protected origin
        // survived closed canonical serialization and strong journal-load validation.
        let reopened = try f.reopen()
        let retry = try reopened.provision(id: f.initialization.grant.id, binding: f.disk, candidate: f.initial, daemon: f.daemon)
        #expect(retry.grant == f.initialization.grant)
        _ = try f.reopen().complete(identity: retry.grant.identity, id: retry.grant.id, daemon: f.daemon)
        // Completed initialization still matches the persisted format-completion origin.
        _ = try f.reopen().currentOriginPrincipal(binding: f.disk)
    }

    @Test func freshOriginRepublishMismatchRetainsFenceWithoutReleasingSignature() throws {
        let journal = LifecycleMemory(), processes = LifecycleProcesses(), bindings = LifecycleBindings()
        bindings.rootPublicKey = try journal.lifecycleRootPublicKey().publicData
        processes.root = try journal.lifecycleRootPublicKey().fingerprint.rawValue
        let authority = try StorageBootstrapLifecycleAuthority(journal: journal, processes: processes, bindings: bindings)
        let disk = try lifecycleBinding(7), candidate = try lifecycleCandidate(11), daemon = lifecycleProcess(10)
        let id = lifecycleID()
        bindings.alterRepublishedOrigin = true
        #expect(throws: (any Error).self) {
            try authority.provision(id: id, binding: disk, candidate: candidate, daemon: daemon, rootFD: 1, backingFD: 2)
        }
        // Durable pending fence retained; no signature escapes the mismatched attempt.
        #expect(journal.writes == 1 && journal.signatures == 0 && bindings.calls == 2)
        let grant = try #require(bindings.claims.first)
        bindings.alterRepublishedOrigin = false
        let reopened = try StorageBootstrapLifecycleAuthority(journal: journal, processes: processes, bindings: bindings)
        #expect(throws: (any Error).self) { try reopened.status(identity: grant.identity) }
        // The mismatched post-commit proof leaves the store durably unverified:
        // the exact retry is blocked and no signature is ever released.
        #expect(throws: (any Error).self) { try reopened.provision(id: id, binding: disk, candidate: candidate, daemon: daemon) }
        #expect(journal.writes == 1 && journal.signatures == 0)
    }

    @Test func foreignFormedOriginNeverWritesOrReleasesSignature() throws {
        let journal = LifecycleMemory(), processes = LifecycleProcesses(), bindings = LifecycleBindings()
        bindings.rootPublicKey = try journal.lifecycleRootPublicKey().publicData
        let authority = try StorageBootstrapLifecycleAuthority(journal: journal, processes: processes, bindings: bindings)
        let disk = try lifecycleBinding(7), candidate = try lifecycleCandidate(11), daemon = lifecycleProcess(10)
        bindings.foreignOrigin = true
        #expect(throws: (any Error).self) {
            try authority.provision(id: lifecycleID(), binding: disk, candidate: candidate, daemon: daemon, rootFD: 1, backingFD: 2)
        }
        // A conformer can never smuggle a caller-inferred origin past the strong
        // structural binding to the exact store, grant and proven principal.
        #expect(journal.writes == 0 && journal.signatures == 0)
    }

    @Test func freshOriginMissingNullTamperedOrMalformedInJournalFailsClosedReopen() throws {
        let f = try LifecycleFixture(complete: false), original = try #require(f.journal.data)
        func reserialized(_ mutate: (inout [String: Any]) throws -> Void) throws -> Data {
            var json = try #require(JSONSerialization.jsonObject(with: original) as? [String: Any])
            try mutate(&json)
            return try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys, .withoutEscapingSlashes])
        }
        func tamperStores(_ json: inout [String: Any], _ mutate: (inout [String: Any]) throws -> Void) throws {
            var stores = try #require(json["stores"] as? [String: Any])
            for (key, value) in stores {
                var store = try #require(value as? [String: Any])
                try mutate(&store)
                stores[key] = store
            }
            json["stores"] = stores
        }
        // Old v2 snapshots without the required nullable field refuse load.
        f.journal.data = try reserialized { try tamperStores(&$0) { $0["freshOrigin"] = nil } }
        #expect(throws: (any Error).self) { try f.reopen() }
        // An explicit null is never re-inferred from the binding: repair-required.
        f.journal.data = try reserialized { try tamperStores(&$0) { $0["freshOrigin"] = NSNull() } }
        #expect(throws: (any Error).self) { try f.reopen() }
        // Greeting disk identity tampered away from the durable binding.
        f.journal.data = try reserialized {
            try tamperStores(&$0) {
                var origin = try #require($0["freshOrigin"] as? [String: Any])
                var greeting = try #require(origin["greeting"] as? [String: Any])
                greeting["inode"] = NSNumber(value: UInt64(999))
                origin["greeting"] = greeting
                $0["freshOrigin"] = origin
            }
        }
        #expect(throws: (any Error).self) { try f.reopen() }
        // Proven candidate principal tampered away from the durable recipient.
        f.journal.data = try reserialized {
            try tamperStores(&$0) {
                var origin = try #require($0["freshOrigin"] as? [String: Any])
                var principal = try #require(origin["principal"] as? [String: Any])
                principal["incarnation"] = "tampered-incarnation"
                origin["principal"] = principal
                $0["freshOrigin"] = origin
            }
        }
        #expect(throws: (any Error).self) { try f.reopen() }
        // Pinned daemon tampered away from the proven principal's daemon.
        f.journal.data = try reserialized {
            try tamperStores(&$0) {
                var origin = try #require($0["freshOrigin"] as? [String: Any])
                var daemon = try #require(origin["daemon"] as? [String: Any])
                daemon["uniqueID"] = NSNumber(value: UInt64(999))
                origin["daemon"] = daemon
                $0["freshOrigin"] = origin
            }
        }
        #expect(throws: (any Error).self) { try f.reopen() }
        // Structurally malformed origin payload refuses decode entirely.
        f.journal.data = try reserialized { try tamperStores(&$0) { $0["freshOrigin"] = ["unexpected": true] } }
        #expect(throws: (any Error).self) { try f.reopen() }
        // Untampered snapshot still loads and operates.
        f.journal.data = original
        _ = try f.reopen()
    }
}

private extension LifecycleFixture {
    func serviceState() throws -> L.ServiceState {
        let grant = initialization.grant
        let boot = try authority.serviceBootTrust(identity: grant.identity, grantID: grant.id, serviceChangeID: nil, daemon: daemon)
        return try authority.serviceResult(identity: grant.identity, grantID: grant.id, daemon: daemon).state(boot: boot)
    }
    func replaceService(_ revision: UInt64) {
        processes.liveService = lifecycleID(); processes.openRevision = revision
        processes.ca = String(repeating: String(format: "%02x", revision % 251), count: 32)
        processes.server = String(repeating: String(format: "%02x", (revision + 1) % 251), count: 32)
    }
}

extension StorageBootstrapLifecycleAuthorityTests {
    @Test func pendingServicePersistsBeforeOpeningAndFencesEveryGrantPath() throws {
        let f = try LifecycleFixture(), g = f.initialization.grant
        let change = try L.ServiceChangeRequest(operationID: lifecycleID(), predecessor: f.serviceState())
        let writes = f.journal.writes
        let staged = try f.authority.stageServiceChange(change: change, daemon: f.daemon)
        let rootKey = try f.journal.lifecycleRootPublicKey()
        #expect(staged.request == change && staged.isValidSignature(using: rootKey))
        let otherKey = try StorageIdentity.RootPublicKey(publicData: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)
        #expect(!staged.isValidSignature(using: otherKey))
        #expect(f.journal.writes == writes + 1)
        let root = try f.reopen()
        let retried = try root.stageServiceChange(change: change, daemon: f.daemon)
        #expect(retried.request == change && retried.isValidSignature(using: rootKey))
        #expect(f.journal.writes == writes + 1)
        #expect(throws: (any Error).self) { try root.status(identity: g.identity) }
        #expect(throws: (any Error).self) { try root.read(identity: g.identity, id: g.id, daemon: f.daemon) }
        #expect(throws: (any Error).self) { try root.complete(identity: g.identity, id: g.id, daemon: f.daemon) }
        #expect(throws: (any Error).self) { try root.serviceResult(identity: g.identity, grantID: g.id, daemon: f.daemon) }
        #expect(throws: (any Error).self) { try root.issue(operation: .retire, id: lifecycleID(), identity: g.identity, expectedEpoch: 1, candidate: f.initial, daemon: f.daemon) }
        #expect(throws: (any Error).self) { try root.provision(id: g.id, binding: f.disk, candidate: f.initial, daemon: f.daemon) }
        #expect(throws: (any Error).self) { try root.completeServiceChange(identity: g.identity, operationID: change.operationID, daemon: f.daemon) }
        f.die(f.daemon, f.initial)
        #expect(throws: (any Error).self) { try f.reopen().stageServiceChange(change: change, daemon: f.daemon) }
        #expect(throws: (any Error).self) { try f.reopen().issue(operation: .takeover, id: lifecycleID(), identity: g.identity, expectedEpoch: 1, candidate: lifecycleCandidate(21), daemon: lifecycleProcess(20)) }
    }

    @Test func targetBootIsFrozenAndCannotBeSubstitutedAcrossRestart() throws {
        let f = try LifecycleFixture(), g = f.initialization.grant
        let change = try L.ServiceChangeRequest(operationID: lifecycleID(), predecessor: f.serviceState())
        _ = try f.authority.stageServiceChange(change: change, daemon: f.daemon)
        #expect(throws: (any Error).self) { try f.authority.serviceBootTrust(identity: g.identity, grantID: g.id, serviceChangeID: change.operationID, daemon: f.daemon) }
        f.replaceService(2)
        #expect(throws: (any Error).self) { try f.authority.serviceBootTrust(identity: g.identity, grantID: g.id, serviceChangeID: nil, daemon: f.daemon) }
        let boot = try f.authority.serviceBootTrust(identity: g.identity, grantID: g.id, serviceChangeID: change.operationID, daemon: f.daemon)
        let writes = f.journal.writes
        #expect(try f.reopen().serviceBootTrust(identity: g.identity, grantID: g.id, serviceChangeID: change.operationID, daemon: f.daemon) == boot)
        #expect(f.journal.writes == writes)
        f.replaceService(3)
        #expect(throws: (any Error).self) { try f.reopen().serviceBootTrust(identity: g.identity, grantID: g.id, serviceChangeID: change.operationID, daemon: f.daemon) }
        #expect(throws: (any Error).self) { try f.reopen().completeServiceChange(identity: g.identity, operationID: change.operationID, daemon: f.daemon) }
        #expect(f.journal.writes == writes)
    }

    @Test func lostCommitReplyRetriesExactPersistedConfirmationWithFreshProof() throws {
        let f = try LifecycleFixture(), g = f.initialization.grant
        let before = try f.serviceState()
        let change = try L.ServiceChangeRequest(operationID: lifecycleID(), predecessor: before)
        _ = try f.authority.stageServiceChange(change: change, daemon: f.daemon)
        f.replaceService(2)
        _ = try f.authority.serviceBootTrust(identity: g.identity, grantID: g.id, serviceChangeID: change.operationID, daemon: f.daemon)
        f.processes.allowCommit = false
        #expect(throws: (any Error).self) { try f.authority.completeServiceChange(identity: g.identity, operationID: change.operationID, daemon: f.daemon) }
        let writes = f.journal.writes
        f.processes.allowCommit = true
        let (confirmation, result) = try f.reopen().completeServiceChange(identity: g.identity, operationID: change.operationID, daemon: f.daemon)
        #expect(confirmation.request == change && confirmation.successor.openRevision == 2)
        #expect(result.serviceEpoch != before.context.serviceEpoch)
        #expect(f.journal.writes == writes && f.processes.commits == 1)
        let (retry, proof) = try f.reopen().completeServiceChange(identity: g.identity, operationID: change.operationID, daemon: f.daemon)
        #expect(retry == confirmation && proof.nonce != result.nonce)
        #expect(f.journal.writes == writes && f.processes.commits == 2)
        #expect(Set(f.processes.serviceNonces).count == f.processes.serviceNonces.count)
        let bytes = try #require(f.journal.data)
        let json = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        let stores = try #require(json["stores"] as? [String: [String: Any]])
        let receipt = try #require(stores[g.identity.store]?["result"] as? [String: Any])
        #expect(receipt["service_epoch"] as? String == before.context.serviceEpoch)
    }

    @Test func servicePublicationFailuresPoisonWithoutChildPromotion() throws {
        for cut in 0..<3 {
            let f = try LifecycleFixture(), g = f.initialization.grant
            let change = try L.ServiceChangeRequest(operationID: lifecycleID(), predecessor: f.serviceState())
            if cut == 0 { f.journal.failWrite = true }
            do { _ = try f.authority.stageServiceChange(change: change, daemon: f.daemon) } catch { #expect(cut == 0) }
            if cut > 0 {
                f.replaceService(2)
                if cut == 1 { f.journal.failWrite = true }
                do { _ = try f.authority.serviceBootTrust(identity: g.identity, grantID: g.id, serviceChangeID: change.operationID, daemon: f.daemon) } catch { #expect(cut == 1) }
            }
            if cut == 2 {
                f.journal.failWrite = true
                #expect(throws: (any Error).self) { try f.authority.completeServiceChange(identity: g.identity, operationID: change.operationID, daemon: f.daemon) }
            }
            #expect(f.processes.commits == 0)
            #expect(throws: (any Error).self) { try f.authority.status(identity: g.identity) }
        }
    }

    @Test func oldDevelopmentV2MissingServiceFieldsIsRefused() throws {
        let f = try LifecycleFixture(), original = try #require(f.journal.data)
        for field in ["currentService", "pendingService", "latestServiceChange"] {
            var json = try #require(JSONSerialization.jsonObject(with: original) as? [String: Any])
            var stores = try #require(json["stores"] as? [String: [String: Any]])
            stores[f.initialization.grant.identity.store]?.removeValue(forKey: field)
            json["stores"] = stores
            f.journal.data = try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys, .withoutEscapingSlashes])
            #expect(throws: (any Error).self) { try f.reopen() }
        }
    }

    @Test func moreThan4096ServiceChangesReplaceBoundedHistoryWithoutAllocatingSerials() throws {
        let f = try LifecycleFixture(), g = f.initialization.grant
        var root = f.authority, predecessor = try f.serviceState()
        let firstID = lifecycleID()
        for revision in UInt64(2)...4099 {
            let change = try L.ServiceChangeRequest(operationID: revision == 2 ? firstID : lifecycleID(), predecessor: predecessor)
            _ = try root.stageServiceChange(change: change, daemon: f.daemon)
            f.replaceService(revision)
            _ = try root.serviceBootTrust(identity: g.identity, grantID: g.id, serviceChangeID: change.operationID, daemon: f.daemon)
            let (confirmation, _) = try root.completeServiceChange(identity: g.identity, operationID: change.operationID, daemon: f.daemon)
            predecessor = confirmation.successor
            if revision % 257 == 0 { root = try f.reopen() }
        }
        #expect(f.journal.peakBytes < 16_000)
        #expect(throws: (any Error).self) { try root.completeServiceChange(identity: g.identity, operationID: firstID, daemon: f.daemon) }
        let bytes = try #require(f.journal.data)
        let json = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        #expect((json["serial"] as? NSNumber)?.uint64Value == g.serial)
    }
}

extension StorageBootstrapLifecycleAuthorityTests {
    @Test func sameChannelBootUpdateRequiresExactPendingChangeAndFrozenTarget() throws {
        let f = try LifecycleFixture(), g = f.initialization.grant
        let before = try f.serviceState(), old = before.boot
        func next(_ identity: L.Identity? = nil, key: String? = nil, epoch: String? = nil) throws -> StorageLifecycleBootTrust {
            try .init(identity: identity ?? old.identity, serviceEpoch: epoch ?? lifecycleID(),
                tlsRootSHA256: String(repeating: "1", count: 64), serverSPKI: String(repeating: "2", count: 64),
                bootstrapKey: key ?? old.bootstrapKey)
        }
        let successor = try next()
        // No staged change: a changed boot is never accepted.
        #expect(throws: (any Error).self) { try f.authority.authorizeServiceBootUpdate(predecessor: old, successor: successor) }
        let change = try L.ServiceChangeRequest(operationID: lifecycleID(), predecessor: before)
        _ = try f.authority.stageServiceChange(change: change, daemon: f.daemon)
        let writes = f.journal.writes
        try f.authority.authorizeServiceBootUpdate(predecessor: old, successor: successor)
        try f.reopen().authorizeServiceBootUpdate(predecessor: old, successor: successor) // Exact duplicate.
        #expect(f.journal.writes == writes)
        let otherGeneration = try L.Identity(store: old.identity.store, generation: old.identity.generation + 1,
                                             binding: old.identity.binding)
        for bad in [(successor, try next()), (old, try next(otherGeneration)),
                    (old, try next(key: String(repeating: "9", count: 64))), (old, try next(epoch: old.serviceEpoch)), (old, old)] {
            #expect(throws: (any Error).self) { try f.authority.authorizeServiceBootUpdate(predecessor: bad.0, successor: bad.1) }
        }
        // Once ROOT freezes the observed target, only that exact boot is accepted.
        f.replaceService(2)
        let target = try f.authority.serviceBootTrust(identity: g.identity, grantID: g.id, serviceChangeID: change.operationID, daemon: f.daemon)
        try f.authority.authorizeServiceBootUpdate(predecessor: old, successor: target)
        #expect(throws: (any Error).self) { try f.authority.authorizeServiceBootUpdate(predecessor: old, successor: successor) }
        // After completion there is no pending change; no further update is authorized.
        _ = try f.authority.completeServiceChange(identity: g.identity, operationID: change.operationID, daemon: f.daemon)
        #expect(throws: (any Error).self) { try f.authority.authorizeServiceBootUpdate(predecessor: old, successor: target) }
        #expect(throws: (any Error).self) { try f.authority.authorizeServiceBootUpdate(predecessor: target, successor: try next()) }
    }
}

extension StorageBootstrapLifecycleAuthorityTests {
    /// Both qualification and production scopes install this wiring on the service transport.
    @Test func scopeWiringForwardsSuccessorBootToRootPendingChange() throws {
        let f = try LifecycleFixture()
        let before = try f.serviceState(), old = before.boot
        let service = StorageBootstrapLifecycleServiceXPC(ownerUID: geteuid(), team: "ABCDEFGHIJ",
            expectedRootPublicKey: try f.journal.lifecycleRootPublicKey(), worker: StorageBootstrapLifecycleChildWorker())
        #expect(service.authorizeSuccessorBoot == nil)
        StorageBootstrapLifecycleRouter.wireSuccessorBoot(service) {
            try f.authority.authorizeServiceBootUpdate(predecessor: $0, successor: $1)
        }
        let authorize = try #require(service.authorizeSuccessorBoot)
        let successor = try StorageLifecycleBootTrust(identity: old.identity, serviceEpoch: lifecycleID(),
            tlsRootSHA256: String(repeating: "1", count: 64), serverSPKI: String(repeating: "2", count: 64),
            bootstrapKey: old.bootstrapKey)
        #expect(throws: (any Error).self) { try authorize(old, successor) } // No pending change.
        _ = try f.authority.stageServiceChange(change: try L.ServiceChangeRequest(operationID: lifecycleID(), predecessor: before),
            daemon: f.daemon)
        try authorize(old, successor)
    }
}


@Suite struct StorageBootstrapLifecycleAdoptedServiceChangeTests {
    @Test(arguments: [false, true])
    func targetFreezeCompletionAndReadOnlyRetryPreserveAuthority(_ target: Bool) throws {
        let a = try AdoptedChangeFixture(target: target), f = a.f
        let before = try #require(f.journal.data), writes = f.journal.writes, signatures = f.journal.signatures
        let (confirmation, result) = try a.complete(f.reopen())
        #expect(confirmation.request == a.change && confirmation.successor.boot == a.boot)
        #expect(result.grant == f.initialization.grant)
        #expect(f.journal.writes == writes + (target ? 1 : 2))
        #expect(a.targets.count == (target ? 2 : 3))
        #expect((a.targets.first! == nil) == !target)
        #expect(a.completions.last! == confirmation)
        let after = try #require(f.journal.data), completedWrites = f.journal.writes
        let (retry, fresh) = try a.complete(f.reopen())
        #expect(retry == confirmation && fresh.nonce != result.nonce)
        #expect(f.journal.data == after && f.journal.writes == completedWrites)
        #expect(f.journal.signatures == signatures && f.processes.commits == 0)
        #expect(Set(a.nonces).count == a.nonces.count)
        let old = try #require(JSONSerialization.jsonObject(with: before) as? [String: Any])
        let new = try #require(JSONSerialization.jsonObject(with: after) as? [String: Any])
        #expect((old["serial"] as? NSNumber) == (new["serial"] as? NSNumber))
        let oldStores = try #require(old["stores"] as? [String: [String: Any]])
        let newStores = try #require(new["stores"] as? [String: [String: Any]])
        let id = f.initialization.grant.identity.store
        for field in ["current", "result", "freshOrigin", "freshPhase", "latestResume"] {
            let prior = try #require(oldStores[id]?[field])
            let next = try #require(newStores[id]?[field])
            #expect(try JSONSerialization.data(withJSONObject: [prior], options: [.sortedKeys]) == JSONSerialization.data(withJSONObject: [next], options: [.sortedKeys]))
        }
        // The old recipient is still dead: ordinary routes have not gained adoption privileges.
        #expect(throws: (any Error).self) { try f.reopen().completeServiceChange(identity: f.initialization.grant.identity, operationID: a.change.operationID, daemon: f.daemon) }
        #expect(throws: (any Error).self) { try f.reopen().read(identity: f.initialization.grant.identity, id: f.initialization.grant.id, daemon: f.daemon) }
    }

    @Test func bothOriginalAndRetainedRecipientsRequirePositiveExit() throws {
        for pid: Int32 in [10, 11, 40, 41] {
            for life in [BootstrapLiveness.alive, .unknown] {
                let a = try AdoptedChangeFixture(), before = a.f.journal.data
                a.f.processes.lives[pid] = life
                #expect(throws: (any Error).self) { try a.complete() }
                #expect(a.nonces.isEmpty && a.f.journal.data == before)
            }
        }
    }

    @Test func exactPendingAndCommittedAdoptionAreRequired() throws {
        let a = try AdoptedChangeFixture(), before = a.f.journal.data
        let wrong = try Adoption.Request(id: lifecycleID(), origin: a.request.origin, expectedEpoch: 1,
            daemonAudit: a.request.daemonAudit, daemonUniqueID: a.request.daemonUniqueID,
            controllerAudit: a.request.controllerAudit, controllerUniqueID: a.request.controllerUniqueID)
        #expect(throws: (any Error).self) { try a.complete(request: wrong) }
        let changed = try L.ServiceChangeRequest(operationID: lifecycleID(), predecessor: a.change.predecessor)
        #expect(throws: (any Error).self) { try a.complete(change: changed) }
        #expect(a.f.journal.data == before && a.nonces.isEmpty)
        let next = try Adoption.Request(id: lifecycleID(), origin: a.request.origin, expectedEpoch: 2,
            daemonAudit: a.request.daemonAudit, daemonUniqueID: a.request.daemonUniqueID,
            controllerAudit: a.request.controllerAudit, controllerUniqueID: a.request.controllerUniqueID)
        try a.adoption.prepare(next, peer: a.peer)
        #expect(throws: (any Error).self) { try a.complete() }
        #expect(a.f.journal.data == before && a.nonces.isEmpty)
    }

    @Test func nativePinAndObservedLockLossBeforeAndAfterProofFailClosed() throws {
        for mode in 0..<3 {
            for after in [false, true] {
                let a = try AdoptedChangeFixture(), before = a.f.journal.data
                let invalidate = {
                    if mode == 0 { a.processes.candidateValid = false }
                    if mode == 1 { a.processes.shimValid = false }
                    if mode == 2 { a.checkValid = false }
                }
                if after { a.afterProof = invalidate } else { invalidate() }
                #expect(throws: (any Error).self) { try a.complete() }
                #expect(a.f.journal.data == before)
                #expect(a.nonces.count == (after ? 1 : 0))
            }
        }
    }

    @Test(arguments: [1, 2, 3])
    func lostProofReplyRetainsExactStageAndRetries(_ proof: Int) throws {
        let a = try AdoptedChangeFixture(), writes = a.f.journal.writes
        a.failProof = proof
        #expect(throws: (any Error).self) { try a.complete() }
        #expect(a.f.journal.writes == writes + proof - 1)
        let failedWrites = a.f.journal.writes
        a.failProof = nil
        let (confirmation, _) = try a.complete(a.f.reopen())
        #expect(confirmation.request == a.change)
        #expect(a.f.journal.writes == failedWrites + 3 - proof)
        #expect(Set(a.nonces).count == a.nonces.count)
    }

    @Test(arguments: [1, 2])
    func postCheckpointLockLossRetainsPublishedStateInMemoryAndOnDisk(_ checkpoint: Int) throws {
        let a = try AdoptedChangeFixture(), writes = a.f.journal.writes
        a.f.journal.afterWrite = { if a.f.journal.writes == writes + checkpoint { a.checkValid = false } }
        #expect(throws: (any Error).self) { try a.complete() }
        #expect(a.f.journal.writes == writes + checkpoint)
        let frozen = try #require(a.f.journal.data)
        a.checkValid = true; a.f.journal.afterWrite = nil
        _ = try a.complete() // Same in-memory authority must already see the durable stage.
        #expect(a.f.journal.writes == writes + 2)
        if checkpoint == 2 { #expect(a.f.journal.data == frozen) }
        let completed = a.f.journal.data
        _ = try a.complete(a.f.reopen())
        #expect(a.f.journal.data == completed && a.f.journal.writes == writes + 2)
    }

    @Test func replayedNativeResultCannotFinishFrozenTargetOrCompletedRetry() throws {
        let a = try AdoptedChangeFixture()
        a.failProof = 2
        #expect(throws: (any Error).self) { try a.complete() }
        let frozen = a.f.journal.data
        a.failProof = nil; a.replay = try #require(a.replies.first)
        #expect(throws: (any Error).self) { try a.complete(a.f.reopen()) }
        #expect(a.f.journal.data == frozen)
        a.replay = nil; _ = try a.complete(a.f.reopen())
        let completed = a.f.journal.data
        a.replay = try #require(a.replies.last)
        #expect(throws: (any Error).self) { try a.complete(a.f.reopen()) }
        #expect(a.f.journal.data == completed)
    }

    @Test func pendingGrantAndSealBlockCompletedRetryWithoutProof() throws {
        for sealed in [false, true] {
            let a = try AdoptedChangeFixture()
            _ = try a.complete()
            a.f.processes.dead.subtract([10, 11])
            let grant = try a.f.authority.issue(operation: .retire, id: lifecycleID(), identity: a.f.initialization.grant.identity,
                expectedEpoch: 1, candidate: a.f.initial, daemon: a.f.daemon)
            if sealed { _ = try a.f.authority.complete(identity: grant.grant.identity, id: grant.grant.id, daemon: a.f.daemon) }
            a.f.processes.dead.formUnion([10, 11])
            let before = a.f.journal.data, proofs = a.nonces.count
            #expect(throws: (any Error).self) { try a.complete(a.f.reopen()) }
            #expect(a.f.journal.data == before && a.nonces.count == proofs)
        }
    }

    @Test func pinsAndDeathAreRecheckedAfterEveryProof() throws {
        for proof in 1...3 {
            for mode in 0..<4 {
                let a = try AdoptedChangeFixture(), writes = a.f.journal.writes
                a.afterProof = {
                    guard a.nonces.count == proof else { return }
                    if mode == 0 { a.processes.candidateValid = false }
                    if mode == 1 { a.processes.shimValid = false }
                    if mode == 2 { a.checkValid = false }
                    if mode == 3 { a.f.processes.lives[11] = .unknown }
                }
                #expect(throws: (any Error).self) { try a.complete() }
                #expect(a.nonces.count == proof && a.f.journal.writes == writes + proof - 1)
            }
        }
    }

    @Test func dispatchRequiresExplicitCompletionCapabilityAndExactOrigin() throws {
        let a = try AdoptedChangeFixture()
        typealias Root = StorageLifecycleAdoptionRootProtocol
        let request = try Root.Request(requestID: .init(lifecycleID()), body: .completeServiceChange(adoption: a.request, change: a.change))
        #expect(throws: (any Error).self) {
            try StorageBootstrapLifecycleAdoptionRootXPC.dispatch(request, authority: a.adoption, origin: a.origin.wire, peer: a.peer)
        }
        var calls = 0
        let result = try StorageBootstrapLifecycleAdoptionRootXPC.dispatch(request, authority: a.adoption,
            origin: a.origin.wire, peer: a.peer, completeServiceChange: { adoption, change in
                calls += 1; #expect(adoption == a.request && change == a.change)
                return try a.complete()
            })
        guard case .serviceChanged(let confirmation, let proof) = result else { Issue.record("wrong dispatch result"); return }
        #expect(calls == 1 && confirmation.request == a.change && proof.grant == a.change.predecessor.grant)
        let foreign = try Adoption.Origin(binding: a.origin.wire.binding, rootPublicKey: a.origin.wire.rootPublicKey,
            shimLaunchUUID: lifecycleID(), specSHA256: a.origin.wire.specSHA256)
        #expect(throws: (any Error).self) {
            try StorageBootstrapLifecycleAdoptionRootXPC.dispatch(request, authority: a.adoption, origin: foreign,
                peer: a.peer, completeServiceChange: { _, _ in calls += 1; return try a.complete() })
        }
        #expect(calls == 1)
    }
}

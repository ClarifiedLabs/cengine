#if os(macOS) && DEBUG
import CEngineCore
import CryptoKit
import Foundation
import Synchronization
import Testing
@testable import CEngineRuntime

/// Isolated DTO/physical-journal coverage, not native authentication or VZ proof.
@Suite(.serialized) @MainActor struct ManagedStorageLifecycleResumeOwnerTests {
    typealias Base = ManagedStorageLifecycleOwnerTests
    typealias Owner = ManagedStorageLifecycleOwner
    typealias Checkpoint = ManagedStorageLifecycleCheckpoint
    typealias L = StorageLifecycleProtocol
    typealias Cold = StorageLifecycleResumeProtocol
    typealias RPC = StorageLifecycleResumeRootProtocol
    typealias Boot = StorageLifecycleServiceBootProtocol

    nonisolated final class Peer: @unchecked Sendable {
        struct State {
            var requests: [RPC.Request] = []
            var prepared: RPC.Prepared?
            var completed: RPC.Completed?
            var losePrepare = true
            var loseComplete = true
            var mutateAt: String?
            var mutateURL: URL?
            var unavailableLookups = 0
            var lookupFault: String?
            var lookupStatus: RPC.Status?
            var eligibleReturned = false
            var childLaunches = 0
        }
        let state = Mutex(State())
        let base: Base.Peer
        let status: RPC.Status
        let stateURL: URL
        init(base: Base.Peer, grant: L.Grant, stateURL: URL) throws {
            self.base = base; self.stateURL = stateURL
            status = try .init(original: grant, binding: .init(base.binding), rootPublicKey: base.rootKey.publicData,
                originalShimLaunchUUID: base.bootBinding.shimLaunchUUID, eligibility: .eligible)
        }
        func pending() throws -> ManagedStorageInitialization.Request {
            try JSONDecoder().decode(ManagedStorageInitialization.Request.self, from: Data(contentsOf: stateURL))
        }
        func request(_ envelope: RPC.Request) throws -> RPC.Reply {
            #expect(!Thread.isMainThread)
            return try state.withLock { s in
                s.requests.append(envelope)
                let phase: String
                switch envelope.body { case .lookup, .status: phase = "lookup"; case .prepare: phase = "prepare"; case .complete: phase = "complete" }
                if s.mutateAt == phase, let url = s.mutateURL {
                    try Data("preserved mutation".utf8).write(to: url)
                    s.mutateAt = nil
                }
                switch envelope.body {
                case .lookup, .status:
                    if s.lookupFault == "blocked" { return try .init(for: envelope, body: .failure(.blocked)) }
                    if let status = s.lookupStatus { return try .init(for: envelope, body: .status(status)) }
                    let eligibility: RPC.Eligibility = s.unavailableLookups > 0 ? .unavailable : .eligible
                    if s.unavailableLookups > 0 { s.unavailableLookups -= 1 }
                    let sampled = try RPC.Status(original: status.original, binding: status.binding,
                        rootPublicKey: status.rootPublicKey, originalShimLaunchUUID: status.originalShimLaunchUUID,
                        eligibility: eligibility)
                    let reply = try RPC.Reply(for: envelope, body: .status(sampled))
                    if s.lookupFault == "unknown" {
                        let bytes = try RPC.encode(reply)
                        let text = try #require(String(data: bytes, encoding: .utf8))
                        return try RPC.decodeReply(Data(text.replacingOccurrences(of: "\"eligible\"", with: "\"unknown\"").utf8), for: envelope)
                    }
                    s.eligibleReturned = eligibility == .eligible
                    #expect(s.childLaunches == 0)
                    #expect(base.state.withLock { $0.requests.isEmpty && $0.childActions == 0 })
                    return reply
                case .prepare(let request):
                    let durable = try pending()
                    #expect(durable.prepare == request)
                    #expect(durable.prepareRequestID == envelope.requestID.rawValue)
                    if s.prepared == nil {
                        let grant = try L.Grant(operation: .takeover, id: request.operationID,
                            identity: request.identity, serial: 2, expectedEpoch: 1,
                            newKey: request.candidate.publicKey.fingerprint.rawValue)
                        let signed = try L.SignedGrant(grant: grant, signature: base.rootPrivate.signature(for: grant.signingBytes))
                        let open = try Cold.Request(operationID: grant.id, original: request.expectedOriginal,
                            takeover: signed, launch: request.probeGreeting.launch,
                            nowUnixSeconds: request.nowUnixSeconds, lifetimeSeconds: request.lifetimeSeconds)
                        s.prepared = try .init(signedOpen: .init(request: open,
                            signature: base.rootPrivate.signature(for: open.signingBytes)),
                            successorOrigin: request.probeGreeting.successorOrigin, baseEpoch: 1)
                        base.state.withLock { $0.grants[grant.id] = signed }
                    }
                    if s.losePrepare { s.losePrepare = false; throw StorageLifecycleRootClient.Failure(.unavailable) }
                    return try .init(for: envelope, body: .prepared(#require(s.prepared)))
                case .complete:
                    let durable = try pending(), prepared = try #require(s.prepared)
                    #expect(FileManager.default.fileExists(atPath: stateURL.deletingLastPathComponent().appending(path: "attempt.json").path))
                    #expect(durable.completionRequestID == envelope.requestID.rawValue)
                    #expect(base.state.withLock { $0.childTakeovers } == 1)
                    if s.completed == nil {
                        let grant = prepared.signedOpen.request.takeover.grant
                        let ready = try base.ready(grant)
                        s.completed = try .init(operationID: grant.id, signedOpenSHA256: prepared.signedOpenSHA256,
                            successorOrigin: prepared.successorOrigin, baseEpoch: 1,
                            receipt: .init(grant: grant, nonce: Data(repeating: 8, count: 32),
                                serviceEpoch: ready.serviceEpoch, revision: ready.openRevision),
                            successor: base.live(grant, ready).state(boot: base.trust(ready)))
                    }
                    if s.loseComplete { s.loseComplete = false; throw StorageLifecycleRootClient.Failure(.unavailable) }
                    return try .init(for: envelope, body: .completed(#require(s.completed)))
                }
            }
        }
    }
    @MainActor final class Transport: ManagedStorageLifecycleServiceTransport {
        let inner: Base.Transport
        let greeting: StorageLifecycleColdShimProtocol.Greeting
        let peer: Peer
        var configurations = 0
        var failConfigure = false
        var reconcileTakeover = false
        init(inner: Base.Transport, greeting: StorageLifecycleColdShimProtocol.Greeting, peer: Peer) {
            self.inner = inner; self.greeting = greeting; self.peer = peer
        }
        nonisolated func cancel() {}
        func configure(_ configuration: Boot.Configuration) async throws -> ManagedStorageLifecycleServiceReady {
            configurations += 1
            let prepared = try JSONDecoder().decode(RPC.Prepared.self,
                from: Data(contentsOf: peer.stateURL.deletingLastPathComponent().appending(path: "prepared.json")))
            #expect(prepared.signedOpen == configuration.resume)
            #expect(configuration.action == .resumeOpenTakeover)
            #expect(peer.base.state.withLock { $0.binds } == 1)
            if failConfigure { throw Owner.Failure.incomplete }
            let ready = peer.base.successor(configuration.signed.grant, openRevision: 1)
            inner.readyOverride = ready
            peer.base.state.withLock { $0.simulatedReady = ready }
            return .init(binding: .init(shimLaunchUUID: greeting.bootBinding.shimLaunchUUID,
                guestBootNonce: greeting.bootBinding.guestBootNonce, ext4UUID: greeting.bootBinding.ext4UUID,
                bytes: greeting.bootBinding.bytes), ready: ready)
        }
        func command(_ frame: Boot.Frame) async throws -> Boot.Frame {
            if reconcileTakeover, frame.command == .reconcileController, let signed = frame.signed {
                let old = try peer.base.ready(signed.grant)
                let next = Boot.Ready(identity: old.identity, serviceEpoch: old.serviceEpoch, workerUUID: old.workerUUID,
                    controllerEpoch: signed.grant.expectedEpoch + 1, controllerKey: signed.grant.newKey,
                    revision: signed.grant.serial, openRevision: old.openRevision, bootstrapKey: old.bootstrapKey,
                    tlsRootDER: old.tlsRootDER, serverDER: old.serverDER, serverSPKI: old.serverSPKI)
                inner.readyOverride = next
                peer.base.state.withLock { $0.simulatedReady = next }
            }
            return try await inner.command(frame)
        }
        func connectLifecycle() async throws -> FileHandle { try await inner.connectLifecycle() }
        func connectWorkload() async throws -> FileHandle { try await inner.connectWorkload() }
        func connectAttachmentCSR() async throws -> FileHandle { try await inner.connectAttachmentCSR() }
    }
    func greeting(_ base: Base.Peer, backingDescriptor: Int32) throws -> StorageLifecycleColdShimProtocol.Greeting {
        let binding = StorageLifecycleStoreBinding(base.binding), launch = Base.id()
        return try .init(channelID: Base.id(), daemonUniqueID: 9, rootPublicKey: base.rootKey.publicData,
            binding: binding, bootBinding: .init(shimLaunchUUID: launch, guestBootNonce: Base.id(),
                ext4UUID: binding.ext4UUID, bytes: binding.bytes),
            launch: .init(shimLaunchUUID: launch, specSHA256: String(repeating: "c", count: 64),
                initramfsSHA256: String(repeating: "d", count: 64), ext4UUID: binding.ext4UUID, bytes: binding.bytes),
            heldBackingIdentity: .init(.init(stableIdentity: base.binding.backing.identity,
                device: PersistentFileIdentity.capture(descriptor: backingDescriptor).device)), purpose: .resumeReadOnly)
    }
    /// Time advances only at retry sleeps, never with scheduler or filesystem load.
    nonisolated final class ResumeClock: Sendable {
        struct State {
            var now: TimeInterval = 0
            var sleeps: [TimeInterval] = []
        }
        let state = Mutex(State())
        func timing(beforeSleep: @escaping @MainActor @Sendable () throws -> Void = {}) -> Owner.IsolatedTestSeam.RecoveryTiming {
            .init(now: { self.state.withLock { $0.now } }, sleep: { interval in
                try Task.checkCancellation()
                try await beforeSleep()
                try self.state.withLock {
                    // Fail closed if a regression stops advancing time or retries forever.
                    try #require(interval > 0 && interval <= 0.1 && $0.sleeps.count < 10)
                    $0.sleeps.append(interval)
                    $0.now += interval
                }
            })
        }
    }
    func owner(_ disk: Base.Disk, _ base: Base.Peer, _ peer: Peer,
               timing: Owner.IsolatedTestSeam.RecoveryTiming? = nil,
               afterWorkloadDecode: (() async throws -> Void)? = nil) throws -> Owner {
        var seam = try base.seam(child: Curve25519.Signing.PrivateKey(), childIncarnation: Base.id(), expectedEpoch: 1, daemon: 9)
        seam.resumeRequest = { try peer.request($0) }
        seam.resumeTiming = timing
        seam.childLaunch = {
            peer.state.withLock { s in
                #expect(s.eligibleReturned)
                s.childLaunches += 1
            }
        }
        return try Owner(isolatedTestInitialization: seam, root: disk.root, backingDescriptor: disk.backing, binding: disk.binding,
            afterWorkloadDecode: afterWorkloadDecode)
    }

    /// These fixtures persist through real checkpoint APIs; only native peers are modeled.
    func initialStore(_ disk: Base.Disk, _ base: Base.Peer, shape: String = "absent") throws -> L.Grant {
        _ = try ManagedStorageInitialization.create(in: disk.root, binding: disk.binding, provenance: String(repeating: "a", count: 64))
        let seam = try base.seam()
        let initial = try L.Grant(operation: .initialize, id: Base.id(), identity: .init(binding: disk.binding, generation: 1),
            serial: 1, expectedEpoch: 0,
            newKey: StorageIdentity.Ed25519SPKI(rawPublicKey: seam.recipient.publicKey).fingerprint.rawValue)
        if shape != "absent" {
            let signed = try L.SignedGrant(grant: initial, signature: base.rootPrivate.signature(for: initial.signingBytes))
            let checkpoint = try Checkpoint.fresh(in: disk.root, backingDescriptor: disk.backing, binding: disk.binding,
                rootPublicKey: base.rootKey.publicData, provenanceReference: String(repeating: "a", count: 64),
                initialize: .init(signed: signed, recipient: seam.recipient, requestID: Base.id(), serviceEpoch: nil))
            _ = try checkpoint.snapshot()
            if shape == "pair" {
                _ = try HostStorageIntents.initialize(in: disk.root, store: disk.binding.storeID.rawValue,
                    provenanceReference: String(repeating: "a", count: 64))
            }
        }
        return initial
    }
    func peer(_ disk: Base.Disk, _ base: Base.Peer, initial: L.Grant) throws -> Peer {
        try Peer(base: base, grant: initial, stateURL: disk.url.appending(path: "managed-storage-initialization/request.json"))
    }
    func completedStore(_ disk: Base.Disk, _ base: Base.Peer, _ lock: CanonicalDataStoreLock,
                        shape: String = "absent") async throws -> Peer {
        let peer = try peer(disk, base, initial: initialStore(disk, base, shape: shape))
        let owner = try owner(disk, base, peer), greeting = try greeting(base, backingDescriptor: disk.backing)
        _ = try await owner.prepareResume(storeLock: lock)
        try await owner.bootResume(using: Transport(inner: Base.Transport(peer: base, root: disk.root), greeting: greeting, peer: peer),
            greeting: greeting, storeLock: lock, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        await owner.close()
        return peer
    }

    @Test func unavailableLookupRetriesSameRequestWithoutChangingEvidence() async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let base = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        let peer = try peer(disk, base, initial: initialStore(disk, base, shape: "pair"))
        peer.state.withLock { $0.unavailableLookups = 2 }
        let clock = ResumeClock()
        let owner = try owner(disk, base, peer, timing: clock.timing())
        let before = try ManagedStorageLifecycleRestartTests().bytes(disk.url)
        #expect(try await owner.prepareResume(storeLock: lock, timeout: 2).greeting.expectedEpoch == 1)
        let requests = peer.state.withLock { $0.requests }
        #expect(requests.count == 3)
        #expect(clock.state.withLock { $0.sleeps } == [0.1, 0.1])
        #expect(requests.allSatisfy { $0 == requests.first })
        #expect(requests.allSatisfy { if case .lookup = $0.body { true } else { false } })
        #expect(peer.state.withLock { $0.childLaunches } == 1)
        #expect(base.state.withLock { $0.childActions == 0 && $0.allocations == 0 })
        #expect(try ManagedStorageLifecycleRestartTests().bytes(disk.url) == before)
        await owner.close()
    }

    @Test func foreverUnavailableLookupStopsAtOriginalDeadlineWithoutChild() async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let base = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        let peer = try peer(disk, base, initial: initialStore(disk, base))
        peer.state.withLock { $0.unavailableLookups = Int.max }
        let clock = ResumeClock()
        let owner = try owner(disk, base, peer, timing: clock.timing())
        let before = try ManagedStorageLifecycleRestartTests().bytes(disk.url)
        do {
            _ = try await owner.prepareResume(storeLock: lock, timeout: 0.25)
            Issue.record("unavailable lookup unexpectedly prepared a child")
        } catch let error as StorageLifecycleRootClient.Failure {
            #expect(error.code == .unavailable)
        }
        #expect(clock.state.withLock { $0.now } == 0.25)
        let sleeps = clock.state.withLock { $0.sleeps }
        #expect(sleeps == [0.1, 0.1, 0.25 - 0.2])
        let requests = peer.state.withLock { $0.requests }
        #expect(requests.count == 3)
        #expect(requests.allSatisfy { $0 == requests.first })
        #expect(peer.state.withLock { $0.childLaunches } == 0)
        #expect(base.state.withLock { $0.requests.isEmpty && $0.childActions == 0 })
        #expect(try ManagedStorageLifecycleRestartTests().bytes(disk.url) == before)
        await owner.close()
    }

    @Test func physicalEvidenceChangeWhileWaitingRefusesWithoutChild() async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let base = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        let peer = try peer(disk, base, initial: initialStore(disk, base))
        peer.state.withLock { $0.unavailableLookups = Int.max }
        let clock = ResumeClock()
        var changed: [String: Data]?
        let owner = try owner(disk, base, peer, timing: clock.timing {
            // The injected sleep is a handshake: the first lookup has returned,
            // its evidence was checked, and no retry can start before this writer.
            let requests = peer.state.withLock { $0.requests }
            try #require(requests.count == 1)
            guard case .lookup = requests[0].body else { throw Owner.Failure.invalid }
            // A valid, allowed marker: taking a new baseline would accept it.
            let marker = try ManagedStorageInitialization.open(in: disk.root)
            try marker.retain("admitted.json", true)
            changed = try ManagedStorageLifecycleRestartTests().bytes(disk.url)
        })
        do {
            _ = try await owner.prepareResume(storeLock: lock, timeout: 2)
            Issue.record("changed evidence unexpectedly admitted a child")
        } catch Owner.Failure.blocked { }
        let requests = peer.state.withLock { $0.requests }
        #expect(requests.count == 1)
        #expect(clock.state.withLock { $0.sleeps } == [0.1])
        #expect(requests.allSatisfy { $0 == requests.first })
        #expect(peer.state.withLock { $0.childLaunches } == 0)
        #expect(base.state.withLock { $0.requests.isEmpty && $0.childActions == 0 })
        #expect(try ManagedStorageLifecycleRestartTests().bytes(disk.url) == #require(changed))
        await owner.close()
    }

    @Test(arguments: ["blocked", "binding", "unknown"])
    func lookupRefusalsNeverRetryOrLaunchChild(fault: String) async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let otherDisk = try Base.Disk(); defer { otherDisk.remove() }
        let base = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        let peer = try peer(disk, base, initial: initialStore(disk, base))
        let otherBase = try Base.Peer(otherDisk.binding)
        let other = try self.peer(otherDisk, otherBase, initial: initialStore(otherDisk, otherBase))
        peer.state.withLock {
            $0.lookupFault = fault
            if fault == "binding" { $0.lookupStatus = other.status }
        }
        let owner = try owner(disk, base, peer)
        let before = try ManagedStorageLifecycleRestartTests().bytes(disk.url)
        await Base().fails { _ = try await owner.prepareResume(storeLock: lock, timeout: 1) }
        #expect(peer.state.withLock { $0.requests.count == 1 && $0.childLaunches == 0 })
        #expect(base.state.withLock { $0.requests.isEmpty && $0.childActions == 0 })
        #expect(try ManagedStorageLifecycleRestartTests().bytes(disk.url) == before)
        await owner.close()
    }

    @Test(arguments: ["absent", "checkpoint", "pair"])
    func completedPairWithoutAdmissionSelectsOnlyAuthenticatedExistingRecovery(shape: String) async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let base = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        let peer = try await completedStore(disk, base, lock, shape: shape)
        let marker = try ManagedStorageInitialization.open(in: disk.root)
        let before = try ManagedStorageLifecycleRestartTests().bytes(disk.url)
        #expect(try marker.value("admitted.json", as: Bool.self) == nil)
        #expect(try marker.hasCompletedPair(in: disk.root))
        #expect(try Owner.classify(root: disk.root) == .existingV2)
        #expect(try ManagedStorageLifecycleRestartTests().bytes(disk.url) == before)
        let completed = try #require(peer.state.withLock { $0.completed })
        for eligibility in [StorageLifecycleColdRootProtocol.Eligibility.live, .eligible, .unavailable] {
            let recorder = ManagedLifecycleStartupTests.Recorder()
            recorder.format = try Owner.classify(root: disk.root); recorder.eligibility = eligibility
            if eligibility == .unavailable {
                await #expect(throws: EngineError.self) { try await ManagedLifecycleStartup.run(recorder) }
                #expect(!recorder.calls.contains("adopt"))
            } else {
                try await ManagedLifecycleStartup.run(recorder)
                #expect(recorder.calls.contains("recover"))
            }
            #expect(recorder.calls.contains("coldStatus"))
            #expect(!recorder.calls.contains("resumeBoot") && !recorder.calls.contains("resumePrepare"))
        }
        var seam = try base.seam(child: Curve25519.Signing.PrivateKey(), expectedEpoch: 2, daemon: 11)
        seam.coldRequest = { request, _ in
            let service = completed.successor
            let status = try StorageLifecycleColdRootProtocol.Status(predecessor: .init(currentGrant: service.grant,
                serviceEpoch: service.context.serviceEpoch, controllerEpoch: 2, controllerKey: service.context.controllerKey,
                openRevision: service.openRevision, bootstrapKey: service.boot.bootstrapKey),
                origin: completed.successorOrigin, allocatedEpoch: 1, eligibility: .unavailable)
            return try .init(for: request, body: .status(status))
        }
        let existing = try Owner(isolatedTestExisting: seam, root: disk.root, backingDescriptor: disk.backing, binding: disk.binding)
        #expect(try await existing.statusCold(storeLock: lock).eligibility == .unavailable)
        await Base().fails { try await existing.recoverWorkload() }
        #expect(!existing.hasRecoveryPermission)
        #expect(throws: (any Error).self) { try existing.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator()) }
        #expect(try marker.value("admitted.json", as: Bool.self) == nil)
        #expect(try ManagedStorageLifecycleRestartTests().bytes(disk.url) == before)
        await existing.close()
    }

    @Test(arguments: ["admit", "mutate-query", "restart-before-hint", "restart-after-hint"])
    func completedPairRequiresNewRootProofAndQueryBeforeRecoveryAdmission(phase: String) async throws {
        let mutateQuery = phase == "mutate-query"
        let disk = try Base.Disk(); defer { disk.remove() }
        let base = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        let peer = try await completedStore(disk, base, lock)
        let completed = try #require(peer.state.withLock { $0.completed })
        let prepared = try #require(peer.state.withLock { $0.prepared })
        let marker = try ManagedStorageInitialization.open(in: disk.root)
        let request = try #require(try marker.value("request.json", as: ManagedStorageInitialization.Request.self))
        let greeting = request.prepare.probeGreeting
        let ready = try base.ready(completed.receipt.grant)
        let unknown = disk.url.appending(path: "managed-storage-initialization/commit-candidate")
        func recoverySeam(epoch: UInt64, daemon: UInt64) throws -> Owner.IsolatedTestSeam {
            let originalSeam = try base.seam(child: Curve25519.Signing.PrivateKey(), childIncarnation: Base.id(),
                expectedEpoch: epoch, daemon: daemon)
            return .init(preparation: originalSeam.preparation, recipient: originalSeam.recipient,
            rootRequest: { envelope, root, backing in
            if case .complete(_, let id) = envelope.body {
                let signed = try #require(base.state.withLock { $0.grants[id] })
                let actual = try base.ready(signed.grant)
                return try .init(for: envelope, body: .completed(.init(grant: signed.grant, nonce: Data(repeating: 3, count: 32),
                    serviceEpoch: actual.serviceEpoch, revision: actual.revision)))
            }
            return try base.request(envelope, root, backing)
            }, childAction: originalSeam.childAction)
        }
        var owner: Owner! = try Owner(isolatedTestExisting: recoverySeam(epoch: 2, daemon: 11), root: disk.root,
            backingDescriptor: disk.backing, binding: disk.binding,
            afterWorkloadDecode: { if mutateQuery { try Data([9]).write(to: unknown) } })
        #expect(!owner.hasRecoveryPermission)
        await Base().fails { try await owner.recoverWorkload() }
        _ = try await owner.prepareTakeover()
        let transport = Transport(inner: Base.Transport(peer: base, root: disk.root), greeting: greeting, peer: peer)
        transport.reconcileTakeover = true
        let current = ManagedStorageLifecycleServiceReady(binding: .init(shimLaunchUUID: greeting.bootBinding.shimLaunchUUID,
            guestBootNonce: greeting.bootBinding.guestBootNonce, ext4UUID: greeting.bootBinding.ext4UUID, bytes: greeting.bootBinding.bytes), ready: ready)
        base.state.withLock { $0.failServiceResult = true }
        await Base().fails { try await owner.takeover(using: transport, current: current) }
        #expect(base.state.withLock { $0.takeoverIssues } == 0)
        #expect(transport.configurations == 0 && transport.inner.commands.isEmpty)
        #expect(!owner.hasRecoveryPermission)
        base.state.withLock { $0.failServiceResult = false }
        try await owner.takeover(using: transport, current: current)
        #expect(!owner.hasRecoveryPermission)
        #expect(try owner.snapshot().currentContext?.controllerEpoch == 3)
        if phase.hasPrefix("restart-") {
            // C3 is durable but admission has not happened; C2 was legitimately
            // compacted. Neither the absent nor public admitted hint is authority.
            #expect(try owner.snapshot().contexts.allSatisfy { $0.context.controllerEpoch == 3 })
            #expect(try marker.value("admitted.json", as: Bool.self) == nil)
            if phase == "restart-after-hint" { try marker.retain("admitted.json", true) }
            await owner.close()
            owner = nil // Release the physical leases, just as process exit does.
            let before = try ManagedStorageLifecycleRestartTests().bytes(disk.url)
            #expect(try Owner.classify(root: disk.root) == .existingV2)
            owner = try Owner(isolatedTestExisting: recoverySeam(epoch: 3, daemon: 13), root: disk.root,
                backingDescriptor: disk.backing, binding: disk.binding)
            #expect(try ManagedStorageLifecycleRestartTests().bytes(disk.url) == before)
            await Base().fails { try await owner.recoverWorkload() }
            _ = try await owner.prepareTakeover()
            let laterReady = try base.ready(#require(owner.snapshot().current?.original.signed.grant))
            let later = ManagedStorageLifecycleServiceReady(binding: current.binding, ready: laterReady)
            let issueCount = base.state.withLock { $0.takeoverIssues }
            base.state.withLock { $0.failServiceResult = true }
            await Base().fails { try await owner.takeover(using: transport, current: later) }
            #expect(!owner.hasRecoveryPermission)
            #expect(base.state.withLock { $0.takeoverIssues } == issueCount)
            #expect(try ManagedStorageLifecycleRestartTests().bytes(disk.url) == before)
            base.state.withLock { $0.failServiceResult = false }
            try await owner.takeover(using: transport, current: later)
            #expect(try owner.snapshot().currentContext?.controllerEpoch == 4)
            #expect(!owner.hasRecoveryPermission)
        }
        if mutateQuery {
            await Base().fails { try await owner.recoverWorkload() }
            #expect(!owner.hasRecoveryPermission)
            #expect(try marker.value("admitted.json", as: Bool.self) == nil)
            #expect(try Data(contentsOf: unknown) == Data([9]))
        } else {
            try await owner.recoverWorkload()
            #expect(owner.hasRecoveryPermission)
            #expect(try marker.value("admitted.json", as: Bool.self) == true)
            #expect(try Owner.classify(root: disk.root) == .existingV2)
            _ = try owner.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator())
        }
        #expect(transport.configurations == 0)
        #expect(peer.state.withLock { $0.prepared } == prepared)
        #expect(try marker.value("request.json", as: ManagedStorageInitialization.Request.self) == request)
        #expect(base.state.withLock { $0.workloadEvents.contains("root-live") && $0.workloadEvents.contains("query") })
        await owner.close()
    }

    @Test(arguments: ["lookup", "prepare", "complete"])
    func physicalMutationDuringRootReplyNeverPublishes(phase: String) async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let base = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        let peer = try peer(disk, base, initial: initialStore(disk, base))
        let unknown = disk.url.appending(path: "managed-storage-initialization/commit-candidate")
        peer.state.withLock { $0.mutateAt = phase; $0.mutateURL = unknown }
        let owner = try owner(disk, base, peer), greeting = try greeting(base, backingDescriptor: disk.backing)
        let transport = Transport(inner: Base.Transport(peer: base, root: disk.root), greeting: greeting, peer: peer)
        if phase == "lookup" {
            await Base().fails { _ = try await owner.prepareResume(storeLock: lock) }
        } else {
            _ = try await owner.prepareResume(storeLock: lock)
            await Base().fails { try await owner.bootResume(using: transport, greeting: greeting, storeLock: lock,
                nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600) }
        }
        #expect(transport.configurations == (phase == "complete" ? 1 : 0))
        #expect(try Data(contentsOf: unknown) == Data("preserved mutation".utf8))
        #expect(!FileManager.default.fileExists(atPath: disk.url.appending(path: "managed-storage-initialization/completed.json").path))
        #expect(throws: (any Error).self) { try owner.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator()) }
        await owner.close()
    }

    @Test(arguments: ["marker", "intents"])
    func queryMutationCannotAdmitOrOverwriteEvidence(target: String) async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let base = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        let peer = try peer(disk, base, initial: initialStore(disk, base))
        let name = target == "marker" ? "managed-storage-initialization/commit-candidate" : "managed-storage/commit-candidate"
        let unknown = disk.url.appending(path: name)
        let owner = try owner(disk, base, peer, afterWorkloadDecode: { try Data([9]).write(to: unknown) })
        let greeting = try greeting(base, backingDescriptor: disk.backing)
        _ = try await owner.prepareResume(storeLock: lock)
        try await owner.bootResume(using: Transport(inner: Base.Transport(peer: base, root: disk.root), greeting: greeting, peer: peer),
            greeting: greeting, storeLock: lock, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        await Base().fails { try await owner.admitInitialization() }
        #expect(try Data(contentsOf: unknown) == Data([9]))
        #expect(!FileManager.default.fileExists(atPath: disk.url.appending(path: "managed-storage-initialization/admitted.json").path))
        #expect(throws: (any Error).self) { try owner.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator()) }
        await owner.close()
    }

    @Test(arguments: ["root", "query"])
    func failedAdmissionDoesNotPersistWorkerOrAdmit(phase: String) async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let base = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        let peer = try peer(disk, base, initial: initialStore(disk, base))
        let owner = try owner(disk, base, peer, afterWorkloadDecode: {
            if phase == "query" { throw Owner.Failure.incomplete }
        })
        let greeting = try greeting(base, backingDescriptor: disk.backing)
        _ = try await owner.prepareResume(storeLock: lock)
        try await owner.bootResume(using: Transport(inner: Base.Transport(peer: base, root: disk.root), greeting: greeting, peer: peer),
            greeting: greeting, storeLock: lock, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        let marker = try ManagedStorageInitialization.open(in: disk.root)
        let before = try marker.evidence(in: disk.root)
        #expect(try owner.snapshot().observedWorker == nil)
        base.state.withLock { $0.failServiceResult = phase == "root" }
        await Base().fails { try await owner.admitInitialization() }
        #expect(try marker.evidence(in: disk.root) == before)
        #expect(try owner.snapshot().observedWorker == nil)
        #expect(try marker.value("admitted.json", as: Bool.self) == nil)
        #expect(!owner.hasRecoveryPermission)
        #expect(throws: (any Error).self) { try owner.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator()) }
        await owner.close()
    }

    @Test(arguments: [false, true]) func exactLostRepliesAndUncertainConfigure(failConfigure: Bool) async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let base = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        _ = try ManagedStorageInitialization.create(in: disk.root, binding: disk.binding, provenance: String(repeating: "a", count: 64))
        let initial = try L.Grant(operation: .initialize, id: Base.id(), identity: .init(binding: disk.binding, generation: 1),
            serial: 1, expectedEpoch: 0, newKey: String(repeating: "a", count: 64))
        let peer = try Peer(base: base, grant: initial, stateURL: disk.url.appending(path: "managed-storage-initialization/request.json"))
        let owner = try owner(disk, base, peer, afterWorkloadDecode: {
            // Admission must keep even the diagnostic fields unchanged through Query.
            let state = try Checkpoint.decode(Data(contentsOf: disk.url.appending(path: "managed-storage-owner/state.json")))
            #expect(state.observedWorker == nil)
        })
        let bytes = try Data(contentsOf: disk.url.appending(path: "disk"))
        #expect(try await owner.prepareResume(storeLock: lock).greeting.expectedEpoch == 1)
        let greeting = try greeting(base, backingDescriptor: disk.backing)
        let transport = Transport(inner: Base.Transport(peer: base, root: disk.root), greeting: greeting, peer: peer)
        transport.failConfigure = failConfigure
        if failConfigure {
            await Base().fails { try await owner.bootResume(using: transport, greeting: greeting, storeLock: lock,
                nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600) }
            transport.failConfigure = false
            await Base().fails { try await owner.bootResume(using: transport, greeting: greeting, storeLock: lock,
                nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600) }
        } else {
            try await owner.bootResume(using: transport, greeting: greeting, storeLock: lock,
                nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
            #expect(try owner.snapshot().currentContext?.controllerEpoch == 2)
            #expect(try owner.snapshot().contexts.count == 1)
            #expect(throws: (any Error).self) { try owner.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator()) }
            var expected = try owner.snapshot()
            #expect(expected.observedWorker == nil)
            try await owner.admitInitialization()
            expected.observedWorker = .init(context: try #require(expected.currentContext),
                workerUUID: try base.ready(#require(expected.current?.original.signed.grant)).workerUUID)
            expected.revision += 1
            #expect(try owner.snapshot() == expected)
            #expect(try ManagedStorageInitialization.open(in: disk.root).value("admitted.json", as: Bool.self) == true)
            _ = try owner.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator())
            #expect(base.state.withLock { Array($0.workloadEvents.suffix(4)) } == ["root-live", "transport", "child", "query"])
        }
        #expect(transport.configurations == 1)
        let prepares = peer.state.withLock { $0.requests.filter { if case .prepare = $0.body { true } else { false } } }
        #expect(prepares.count == 2 && prepares[0] == prepares[1])
        if !failConfigure {
            let completions = peer.state.withLock { $0.requests.filter { if case .complete = $0.body { true } else { false } } }
            #expect(completions.count == 2 && completions[0] == completions[1])
        }
        #expect(try Data(contentsOf: disk.url.appending(path: "disk")) == bytes)
        await owner.close()
    }
}
#endif

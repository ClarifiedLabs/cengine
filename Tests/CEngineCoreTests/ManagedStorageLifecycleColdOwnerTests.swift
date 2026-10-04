#if os(macOS) && DEBUG
import CEngineCore
import CryptoKit
import Foundation
import Synchronization
import Testing
@testable import CEngineRuntime

/// Isolated DTO/physical-journal coverage, not native authentication or VZ proof.
@Suite(.serialized) @MainActor struct ManagedStorageLifecycleColdOwnerTests {
    typealias Base = ManagedStorageLifecycleOwnerTests
    typealias Owner = ManagedStorageLifecycleOwner
    typealias Checkpoint = ManagedStorageLifecycleCheckpoint
    typealias L = StorageLifecycleProtocol
    typealias Cold = StorageLifecycleColdProtocol
    typealias RPC = StorageLifecycleColdRootProtocol
    typealias Boot = StorageLifecycleServiceBootProtocol

    nonisolated final class Peer: @unchecked Sendable {
        struct State {
            var requests: [RPC.Request] = []
            var prepared: RPC.Prepared?
            var completed: RPC.Completed?
            var losePrepare = true
            var loseComplete = true
            var interruptComplete = false
            var resolved: RPC.ResolvedDead?
            var loseResolution = true
        }
        let state = Mutex(State())
        let base: Base.Peer
        let status: RPC.Status
        let stateURL: URL
        init(base: Base.Peer, grant: L.Grant, stateURL: URL) throws {
            self.base = base; self.stateURL = stateURL
            let ready = try base.ready(grant)
            status = try .init(predecessor: .init(currentGrant: grant, serviceEpoch: ready.serviceEpoch,
                controllerEpoch: ready.controllerEpoch, controllerKey: grant.newKey, openRevision: ready.openRevision,
                bootstrapKey: base.rootKey.fingerprint.rawValue), origin: .init(binding: .init(base.binding),
                    rootPublicKey: base.rootKey.publicData, shimLaunchUUID: base.bootBinding.shimLaunchUUID,
                    specSHA256: String(repeating: "a", count: 64)), allocatedEpoch: 1, eligibility: .eligible)
        }
        func effectiveStatus(_ resolved: RPC.ResolvedDead?) throws -> RPC.Status {
            guard let resolved else { return status }
            let service = resolved.successor
            return try .init(predecessor: .init(currentGrant: service.grant,
                serviceEpoch: service.context.serviceEpoch, controllerEpoch: service.context.controllerEpoch,
                controllerKey: service.context.controllerKey, openRevision: service.openRevision,
                bootstrapKey: service.boot.bootstrapKey), origin: resolved.successorOrigin,
                allocatedEpoch: resolved.baseEpoch, eligibility: .eligible)
        }
        var currentStatus: RPC.Status { get throws { try state.withLock { try effectiveStatus($0.resolved) } } }
        func pending() throws -> Checkpoint.PendingCold {
            let object = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: stateURL)) as? [String: Any])
            return try JSONDecoder().decode(Checkpoint.PendingCold.self,
                from: JSONSerialization.data(withJSONObject: #require(object["pendingCold"])))
        }
        func request(_ envelope: RPC.Request) throws -> RPC.Reply {
            #expect(!Thread.isMainThread)
            return try state.withLock { s in
                s.requests.append(envelope)
                switch envelope.body {
                case .status: return try .init(for: envelope, body: .status(effectiveStatus(s.resolved)))
                case .prepare(let request):
                    let durable = try pending()
                    #expect(durable.request.prepare == request)
                    #expect(durable.request.prepareRequestID == envelope.requestID.rawValue)
                    if s.prepared == nil {
                        let grant = try L.Grant(operation: .takeover, id: request.operationID,
                            identity: request.identity, serial: request.expectedPredecessor.currentGrant.serial + 1,
                            expectedEpoch: request.expectedPredecessor.controllerEpoch,
                            newKey: request.candidate.publicKey.fingerprint.rawValue)
                        let signed = try L.SignedGrant(grant: grant, signature: base.rootPrivate.signature(for: grant.signingBytes))
                        let open = try Cold.Request(operationID: grant.id, predecessor: request.expectedPredecessor,
                            takeover: signed, launch: request.mountedGreeting.launch,
                            nowUnixSeconds: request.nowUnixSeconds, lifetimeSeconds: request.lifetimeSeconds)
                        s.prepared = try .init(signedOpen: .init(request: open,
                            signature: base.rootPrivate.signature(for: open.signingBytes)),
                            successorOrigin: request.mountedGreeting.successorOrigin, baseEpoch: request.expectedAllocatedEpoch + 1,
                            recoveryBridge: s.resolved)
                        base.state.withLock { $0.grants[grant.id] = signed }
                    }
                    if s.losePrepare { s.losePrepare = false; throw StorageLifecycleRootClient.Failure(.unavailable) }
                    return try .init(for: envelope, body: .prepared(#require(s.prepared)))
                case .complete:
                    let durable = try pending(), prepared = try #require(s.prepared)
                    #expect(durable.bootAttempted && durable.prepared == prepared)
                    #expect(durable.request.completionRequestID == envelope.requestID.rawValue)
                    #expect(base.state.withLock { $0.childTakeovers } > 0)
                    if s.completed == nil {
                        let grant = prepared.signedOpen.request.takeover.grant
                        let ready = try base.ready(grant)
                        s.completed = try .init(operationID: grant.id, signedOpenSHA256: prepared.signedOpenSHA256,
                            successorOrigin: prepared.successorOrigin, baseEpoch: prepared.baseEpoch,
                            receipt: .init(grant: grant, nonce: Data(repeating: 8, count: 32),
                                serviceEpoch: ready.serviceEpoch, revision: ready.openRevision),
                            successor: base.live(grant, ready).state(boot: base.trust(ready)), recoveryBridge: prepared.recoveryBridge)
                    }
                    if s.interruptComplete { throw StorageLifecycleRootClient.Failure(.blocked) }
                    if s.loseComplete { s.loseComplete = false; throw StorageLifecycleRootClient.Failure(.unavailable) }
                    return try .init(for: envelope, body: .completed(#require(s.completed)))
                case .resolveDead(let request):
                    guard let completed = s.completed else { throw StorageLifecycleRootClient.Failure(.blocked) }
                    let durable = try pending(), prepared = try #require(durable.prepared)
                    #expect(durable.resolutionRequest?.value == request)
                    #expect(durable.resolutionRequest?.requestID == envelope.requestID.rawValue)
                    if s.resolved == nil {
                        let data = try Data(contentsOf: stateURL)
                        let metadata = try JSONDecoder().decode(Checkpoint.Metadata.self, from: data)
                        s.resolved = try .init(request: request, anchor: #require(metadata.currentService),
                            receipt: completed.receipt, successor: completed.successor,
                            successorOrigin: completed.successorOrigin, baseEpoch: completed.baseEpoch)
                        try #require(s.resolved).validate(prepared: prepared, anchor: #require(metadata.currentService))
                    }
                    if s.loseResolution { s.loseResolution = false; throw StorageLifecycleRootClient.Failure(.unavailable) }
                    return try .init(for: envelope, body: .resolvedDead(#require(s.resolved)))
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
        var beforeConfigure: (() throws -> Void)? = nil
        var configureDelay: Duration? = nil
        nonisolated let cancellations = Mutex(0)
        init(inner: Base.Transport, greeting: StorageLifecycleColdShimProtocol.Greeting, peer: Peer) {
            self.inner = inner; self.greeting = greeting; self.peer = peer
        }
        nonisolated func cancel() { cancellations.withLock { $0 += 1 } }
        func configure(_ configuration: Boot.Configuration) async throws -> ManagedStorageLifecycleServiceReady {
            configurations += 1
            try beforeConfigure?()
            if let configureDelay { try await Task.sleep(for: configureDelay) }
            let pending = try peer.pending()
            #expect(pending.bootAttempted)
            #expect(pending.prepared?.signedOpen == configuration.cold)
            #expect(configuration.action == .coldOpenTakeover)
            #expect(configuration.signed == configuration.cold?.request.takeover)
            #expect(peer.base.state.withLock { $0.binds } == (try peer.currentStatus.predecessor.controllerEpoch))
            if failConfigure { throw Owner.Failure.incomplete }
            let old = try peer.base.ready(peer.status.predecessor.currentGrant)
            let next = peer.base.successor(configuration.signed.grant,
                openRevision: try peer.currentStatus.predecessor.openRevision + 1)
            let ready = Boot.Ready(identity: next.identity, serviceEpoch: next.serviceEpoch, workerUUID: next.workerUUID,
                controllerEpoch: next.controllerEpoch, controllerKey: next.controllerKey, revision: next.revision,
                openRevision: next.openRevision, bootstrapKey: next.bootstrapKey,
                tlsRootDER: old.tlsRootDER + Data([2]), serverDER: next.serverDER,
                serverSPKI: HostStorageIntents.hash(Data(next.serviceEpoch.utf8)))
            inner.readyOverride = ready
            peer.base.state.withLock { $0.simulatedReady = ready }
            return .init(binding: .init(shimLaunchUUID: greeting.bootBinding.shimLaunchUUID,
                guestBootNonce: greeting.bootBinding.guestBootNonce, ext4UUID: greeting.bootBinding.ext4UUID,
                bytes: greeting.bootBinding.bytes), ready: ready)
        }
        func command(_ frame: Boot.Frame) async throws -> Boot.Frame { try await inner.command(frame) }
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
                device: PersistentFileIdentity.capture(descriptor: backingDescriptor).device)))
    }
    func owner(_ disk: Base.Disk, _ base: Base.Peer, _ peer: Peer,
               afterWorkloadDecode: (() async throws -> Void)? = nil,
               timing: Owner.IsolatedTestSeam.RecoveryTiming? = nil,
               beforeRequest: (@Sendable (RPC.Request, TimeInterval) throws -> Void)? = nil,
               epoch: UInt64 = 1) throws -> Owner {
        var seam = try base.seam(child: Curve25519.Signing.PrivateKey(), childIncarnation: Base.id(), expectedEpoch: epoch, daemon: 9)
        seam.coldTiming = timing
        seam.coldRequest = { request, remaining in
            try beforeRequest?(request, remaining)
            return try peer.request(request)
        }
        return try Owner(isolatedTestExisting: seam, root: disk.root, backingDescriptor: disk.backing, binding: disk.binding,
            afterWorkloadDecode: afterWorkloadDecode)
    }

    @Test func coldRetriesExactDurableTuplesAndDoesNotAdmitBeforeQuery() async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let base = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        let initial = try await ManagedStorageLifecycleRestartTests().freshStore(disk, base)
        let peer = try Peer(base: base, grant: initial, stateURL: disk.url.appending(path: "managed-storage-owner/state.json"))
        let owner = try owner(disk, base, peer)
        let originalIdentity = try PersistentFileIdentity.capture(descriptor: disk.backing)
        let originalBytes = try Data(contentsOf: disk.url.appending(path: "disk"))
        #expect(try await owner.statusCold(storeLock: lock).eligibility == .eligible)
        #expect(try await owner.prepareTakeover().greeting.expectedEpoch == 1)
        let greeting = try greeting(base, backingDescriptor: disk.backing)
        let transport = Transport(inner: Base.Transport(peer: base, root: disk.root), greeting: greeting, peer: peer)
        try await owner.bootCold(using: transport, greeting: greeting, storeLock: lock,
            nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        #expect(!owner.hasRecoveryPermission)
        #expect(try owner.snapshot().pendingCold == nil)
        #expect(try owner.snapshot().latestCold != nil)
        #expect(transport.configurations == 1)
        #expect(transport.inner.commands == [.issueController, .reconcileController])
        let prepares = peer.state.withLock { $0.requests.filter { if case .prepare = $0.body { true } else { false } } }
        let completions = peer.state.withLock { $0.requests.filter { if case .complete = $0.body { true } else { false } } }
        #expect(prepares.count == 2 && prepares[0] == prepares[1])
        #expect(completions.count == 2 && completions[0] == completions[1])
        try await owner.recoverWorkload()
        #expect(owner.hasRecoveryPermission)
        #expect(base.state.withLock { $0.workloadEvents.contains("query") })
        #expect(try PersistentFileIdentity.capture(descriptor: disk.backing) == originalIdentity)
        #expect(try Data(contentsOf: disk.url.appending(path: "disk")) == originalBytes)
        await owner.close()
    }

    @Test(arguments: ["valid", "query", "census", "cached"])
    func interruptedL2ResolvesHistoryThenFreshKeyBootRequiresQueryAndCensus(_ fault: String) async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let base = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        let retained = try await retainedStore(disk, base)
        let stateURL = disk.url.appending(path: "managed-storage-owner/state.json")
        let peer = try Peer(base: base, grant: retained.grant, stateURL: stateURL)
        peer.state.withLock { $0.losePrepare = false; $0.interruptComplete = true }
        let attempted: Checkpoint.PendingCold, anchor: Checkpoint.Completed
        do {
            let first = try owner(disk, base, peer)
            _ = try await first.statusCold(storeLock: lock)
            _ = try await first.prepareTakeover()
            let g = try greeting(base, backingDescriptor: disk.backing)
            let t = Transport(inner: Base.Transport(peer: base, root: disk.root), greeting: g, peer: peer)
            await Base().fails { try await first.bootCold(using: t, greeting: g, storeLock: lock,
                nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600) }
            attempted = try #require(first.snapshot().pendingCold)
            anchor = try #require(first.snapshot().current)
            #expect(t.configurations == 1 && peer.state.withLock { $0.completed != nil })
            await first.close()
        }
        var holder: Owner?
        var next: Owner! = try owner(disk, base, peer, afterWorkloadDecode: { @MainActor in
            if fault == "census" { try #require(holder?.isolatedTestIntents).reconciled() }
        }, epoch: 2)
        holder = next
        defer { holder = nil }
        let diskBytes = try Data(contentsOf: disk.url.appending(path: "disk"))
        #expect(try await next.prepareReplacementRecovery() == false)
        #expect(try await next.statusCold(storeLock: lock).predecessor.controllerEpoch == 2)
        let resolved = try #require(next.snapshot().resolvedDeadCold)
        #expect(try next.snapshot().current == anchor && next.snapshot().latestCold == nil)
        #expect(resolved.attempted.request == attempted.request && resolved.attempted.prepared == attempted.prepared)
        #expect(resolved.attempted.bootAttempted && resolved.attempted.resolutionRequest != nil)
        #expect(!next.hasRecoveryPermission)
        let resolutions = peer.state.withLock { $0.requests.filter { if case .resolveDead = $0.body { true } else { false } } }
        #expect(resolutions.count == 2 && resolutions[0] == resolutions[1])
        #expect(try await next.prepareTakeover().greeting.expectedEpoch == 2)
        peer.state.withLock { $0.prepared = nil; $0.completed = nil; $0.interruptComplete = false; $0.loseComplete = false }
        let g = try greeting(base, backingDescriptor: disk.backing)
        let t = Transport(inner: Base.Transport(peer: base, root: disk.root), greeting: g, peer: peer)
        try await next.bootCold(using: t, greeting: g, storeLock: lock, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        #expect(try next.snapshot().currentContext?.controllerEpoch == 3)
        #expect(try next.snapshot().latestCold?.deadPredecessor == resolved)
        #expect(t.configurations == 1 && !next.hasRecoveryPermission)
        if fault == "query" {
            base.state.withLock { $0.workloadResponder = { _ in try Self.query(base, intent: retained.intent, fault: "epoch") } }
        }
        if fault == "valid" {
            try await next.recoverWorkload()
            #expect(next.hasRecoveryPermission)
        } else if fault != "cached" {
            await Base().fails { try await next.recoverWorkload() }
            #expect(!next.hasRecoveryPermission)
        }
        #expect(try Data(contentsOf: disk.url.appending(path: "disk")) == diskBytes)
        #expect(try #require(next.isolatedTestIntents).checkedSnapshot().intents[retained.intent.id] == retained.intent)
        let completed = try next.snapshot()
        await next.close()
        holder = nil
        next = nil // Release physical journal leases before the new-process model.
        if fault == "cached" {
            let restarted = try ManagedStorageLifecycleRestartTests().existing(disk, base, epoch: 3, daemon: 11)
            _ = try await restarted.prepareTakeover()
            try await restarted.takeover(using: LiveTakeoverTransport(base, disk),
                current: .init(binding: base.bootBinding, ready: base.ready(#require(completed.current).original.signed.grant)))
            #expect(try restarted.snapshot().latestCold == completed.latestCold)
            await Base().fails { try await restarted.recoverWorkload() }
            #expect(!restarted.hasRecoveryPermission)
            await restarted.close()
        }
    }

    @Test func coldNestedProofsHaveOneBoundedBudgetIncludingLostReplies() async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let base = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        let initial = try await ManagedStorageLifecycleRestartTests().freshStore(disk, base)
        let peer = try Peer(base: base, grant: initial, stateURL: disk.url.appending(path: "managed-storage-owner/state.json"))
        peer.state.withLock { $0.losePrepare = false }
        let clock = Mutex(ProcessInfo.processInfo.systemUptime)
        let timing = Owner.IsolatedTestSeam.RecoveryTiming(now: { clock.withLock { $0 } },
            sleep: { seconds in clock.withLock { $0 += seconds } })
        let budgets = Mutex<[TimeInterval]>([])
        let owner = try owner(disk, base, peer, timing: timing, beforeRequest: { request, remaining in
            switch request.body {
            case .status, .resolveDead: break
            case .prepare:
                budgets.withLock { $0.append(remaining) }
                clock.withLock { $0 += 10 }
            case .complete:
                budgets.withLock { $0.append(remaining) }
                clock.withLock { $0 += 40 } // Nested native checks, L2 then reproof; first reply is lost.
            }
        })
        _ = try await owner.statusCold(storeLock: lock)
        _ = try await owner.prepareTakeover()
        let greeting = try greeting(base, backingDescriptor: disk.backing)
        let transport = Transport(inner: Base.Transport(peer: base, root: disk.root), greeting: greeting, peer: peer)
        transport.beforeConfigure = { clock.withLock { $0 += 5 } }
        try await owner.bootCold(using: transport, greeting: greeting, storeLock: lock,
            nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        let observed = budgets.withLock { $0 }
        #expect(observed.count == 3)
        #expect(observed[0] > 119 && observed[0] <= 120)
        #expect(observed[1] > 104 && observed[1] <= 105)
        #expect(observed[2] > 64 && observed[2] < 65)
        #expect(transport.configurations == 1)
        let completions = peer.state.withLock { $0.requests.filter { if case .complete = $0.body { true } else { false } } }
        #expect(completions.count == 2 && completions[0] == completions[1])
        #expect(try owner.snapshot().pendingCold == nil)
        #expect(!owner.hasRecoveryPermission)
        await owner.close()
    }

    @Test func coldDeadlineRejectsLateCompletionWithoutReplayOrPermission() async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let base = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        let initial = try await ManagedStorageLifecycleRestartTests().freshStore(disk, base)
        let peer = try Peer(base: base, grant: initial, stateURL: disk.url.appending(path: "managed-storage-owner/state.json"))
        peer.state.withLock { $0.losePrepare = false; $0.loseComplete = false }
        let clock = Mutex(ProcessInfo.processInfo.systemUptime)
        let timing = Owner.IsolatedTestSeam.RecoveryTiming(now: { clock.withLock { $0 } },
            sleep: { seconds in clock.withLock { $0 += seconds } })
        let owner = try owner(disk, base, peer, timing: timing, beforeRequest: { request, _ in
            if case .complete = request.body { clock.withLock { $0 += 120 } }
        })
        _ = try await owner.statusCold(storeLock: lock)
        _ = try await owner.prepareTakeover()
        let greeting = try greeting(base, backingDescriptor: disk.backing)
        let transport = Transport(inner: Base.Transport(peer: base, root: disk.root), greeting: greeting, peer: peer)
        let before = try owner.snapshot()
        for invalid in [0, -1, 121, TimeInterval.infinity, TimeInterval.nan] {
            await Base().fails { try await owner.bootCold(using: transport, greeting: greeting, storeLock: lock,
                nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600, timeout: invalid) }
            #expect(try owner.snapshot() == before)
        }
        #expect(transport.configurations == 0)
        await #expect(throws: StorageLifecycleRootClient.Failure.self) {
            try await owner.bootCold(using: transport, greeting: greeting, storeLock: lock,
                nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        }
        let pending = try #require(owner.snapshot().pendingCold)
        #expect(pending.bootAttempted && pending.prepared != nil)
        #expect(try owner.snapshot().currentContext == before.currentContext)
        #expect(!owner.hasRecoveryPermission)
        let completions = peer.state.withLock { $0.requests.filter { if case .complete = $0.body { true } else { false } } }
        #expect(completions.count == 1)
        await Base().fails { try await owner.bootCold(using: transport, greeting: greeting, storeLock: lock,
            nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600) }
        #expect(transport.configurations == 1 && !owner.hasRecoveryPermission)
        #expect(try owner.snapshot().pendingCold == pending)
        await owner.close()
    }

    @Test func coldDeadlineCancelsConfigureAndJoinsBeforeReturning() async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let base = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        let initial = try await ManagedStorageLifecycleRestartTests().freshStore(disk, base)
        let peer = try Peer(base: base, grant: initial, stateURL: disk.url.appending(path: "managed-storage-owner/state.json"))
        peer.state.withLock { $0.losePrepare = false; $0.loseComplete = false }
        let owner = try owner(disk, base, peer)
        _ = try await owner.statusCold(storeLock: lock)
        _ = try await owner.prepareTakeover()
        let greeting = try greeting(base, backingDescriptor: disk.backing)
        let transport = Transport(inner: Base.Transport(peer: base, root: disk.root), greeting: greeting, peer: peer)
        transport.configureDelay = .seconds(30)
        let started = ProcessInfo.processInfo.systemUptime
        await Base().fails { try await owner.bootCold(using: transport, greeting: greeting, storeLock: lock,
            nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600, timeout: 0.5) }
        #expect(ProcessInfo.processInfo.systemUptime - started < 3)
        #expect(transport.configurations == 1)
        #expect(transport.cancellations.withLock { $0 } > 0)
        #expect(transport.inner.commands.isEmpty)
        #expect(base.state.withLock { $0.childTakeovers } == 0)
        #expect(peer.state.withLock { $0.completed } == nil)
        #expect(try owner.snapshot().pendingCold?.bootAttempted == true)
        #expect(!owner.hasRecoveryPermission)
        await owner.close()
    }

    /// Create real HOST records through journal methods, never by injecting a census DTO.
    func retainedStore(_ disk: Base.Disk, _ base: Base.Peer, reopen: Bool = false) async throws
        -> (grant: L.Grant, intent: HostStorageIntents.Intent) {
        let fresh = try disk.owner(base)
        try await fresh.provisionFresh()
        try await fresh.bootFresh(using: Base.Transport(peer: base, root: disk.root), expectedBinding: base.bootBinding,
            nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        let state = try fresh.snapshot(), context = try #require(state.currentContext)
        let grant = try #require(state.current?.original.signed.grant)
        let journal = try #require(fresh.isolatedTestIntents)
        try journal.reconciled()
        let volume = HostStorageIntents.Volume(id: Base.id(), name: "retained", createOperation: Base.id(), deleteOperation: Base.id())
        try journal.planVolumes([volume])
        let intent = HostStorageIntents.Intent(id: Base.id(), store: state.identity.store,
            container: String(repeating: "b", count: 64), containerInstance: Base.id(), launch: Base.id(),
            specificationDigest: String(repeating: "c", count: 64), serviceEpoch: context.serviceEpoch,
            controllerEpoch: context.controllerEpoch, controllerKey: context.controllerKey,
            prepare: Base.id(), reserveOperation: Base.id(), completeOperation: Base.id(), replaceOperation: Base.id(),
            mounts: [.init(volume: volume.id, destination: "/data", subpath: "", mode: "read-write")],
            slots: ["prepare", "runtime"].map { .init(volume: volume.id, attachment: Base.id(), role: $0,
                mode: "read-write", registerOperation: Base.id(), retireOperation: Base.id()) },
            version: 1, phase: .planned, prepareCompleted: false, cleanUnmount: false)
        let token = try journal.plan(intent)
        let retained = try journal.intent(token)
        if reopen {
            try await fresh.stageServiceChange(operationID: Base.id(), nowUnixSeconds: 1_800_000_100, lifetimeSeconds: 1800)
            base.state.withLock { $0.newReady = base.successor(grant) }
            try await fresh.reopenService(using: Base.Transport(peer: base, root: disk.root), expectedBinding: base.bootBinding)
        }
        await fresh.close()
        base.state.withLock { $0.binds = 0 }
        return (grant, retained)
    }

    func cold(_ owner: Owner, _ disk: Base.Disk, _ base: Base.Peer, _ peer: Peer,
              _ lock: CanonicalDataStoreLock) async throws {
        _ = try await owner.statusCold(storeLock: lock)
        _ = try await owner.prepareTakeover()
        let greeting = try greeting(base, backingDescriptor: disk.backing)
        try await owner.bootCold(using: Transport(inner: Base.Transport(peer: base, root: disk.root), greeting: greeting, peer: peer),
            greeting: greeting, storeLock: lock, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        #expect(!owner.hasRecoveryPermission)
    }

    /// A schema-4 wire reply with a real, nonempty retained prepare and attachment.
    /// The fixture is an isolated authenticated-peer model, not native TLS proof.
    nonisolated static func query(_ base: Base.Peer, intent: HostStorageIntents.Intent,
                                  attestedEpoch: String? = nil, fault: String? = nil) throws -> Data {
        typealias Client = ManagedStorageControlClient
        let wire = try base.workloadQuery()
        var reply = try #require(JSONSerialization.jsonObject(with: wire) as? [String: Any])
        var snapshot = try #require(reply["snapshot"] as? [String: Any])
        if let attestedEpoch {
            let slot = try #require(intent.slots.first { $0.role == "prepare" })
            let binding = try ManagedStorageControlProtocol.Binding(store: intent.store, volume: slot.volume,
                attachment: slot.attachment, prepare: intent.prepare, container: intent.container,
                launch: intent.launch, key: String(repeating: "e", count: 64), role: .prepare, mode: .readWrite)
            let volume = Client.Volume(id: slot.volume, name: "retained", root: .init(device: 1, inode: 3))
            let prepare = Client.Prepare(id: intent.prepare, attachments: [binding], phase: .pending,
                successor: nil, attestation: nil, context: .init(serviceEpoch: attestedEpoch,
                    controllerEpoch: intent.controllerEpoch, controllerKey: intent.controllerKey))
            func object<T: Encodable>(_ value: T) throws -> Any {
                try JSONSerialization.jsonObject(with: JSONEncoder().encode(value))
            }
            snapshot["volumes"] = [slot.volume: try object(volume)]
            snapshot["volume_lifecycles"] = [slot.volume: try object(Client.VolumeLifecycle(phase: .ready,
                create: nil, delete: nil, createdRevision: nil, deletedRevision: nil))]
            snapshot["attachments"] = [slot.attachment: try object(Client.Attachment(binding: binding,
                phase: .reserved, receipt: nil, retirement: nil))]
            snapshot["prepares"] = [intent.prepare: try object(prepare)]
        }
        switch fault {
        case "epoch": snapshot["epoch"] = intent.serviceEpoch
        case "controller": snapshot["controller"] = ["epoch": intent.controllerEpoch, "key": intent.controllerKey]
        case "store":
            var store = try #require(snapshot["store"] as? [String: Any]); store["id"] = Base.id(); snapshot["store"] = store
        default: break
        }
        reply["snapshot"] = snapshot
        return try JSONSerialization.data(withJSONObject: reply, options: [.sortedKeys])
    }

    /// Fresh ROOT verification records only the held Ready's worker projection.
    /// Query admission (including refusal) must not change any other checkpoint field.
    func observingWorker(in before: Checkpoint.Metadata, base: Base.Peer) throws -> Checkpoint.Metadata {
        try #require(before.observedWorker == nil)
        let current = try #require(before.current)
        let ready = try base.ready(current.original.signed.grant)
        var expected = before
        expected.observedWorker = .init(context: try #require(before.currentContext), workerUUID: ready.workerUUID)
        expected.revision += 1
        return expected
    }

    @Test func coldRetainsOriginalIntentAcrossEpochAndMintsOnlyAfterFreshQuery() async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let base = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        let retained = try await retainedStore(disk, base)
        let peer = try Peer(base: base, grant: retained.grant, stateURL: disk.url.appending(path: "managed-storage-owner/state.json"))
        let owner = try owner(disk, base, peer)
        let bytes = try Data(contentsOf: disk.url.appending(path: "managed-storage/state.json"))
        try await cold(owner, disk, base, peer, lock)
        let state = try owner.snapshot(), live = try #require(state.currentContext)
        #expect(live.serviceEpoch != retained.intent.serviceEpoch)
        #expect(live.controllerEpoch == retained.intent.controllerEpoch + 1)
        #expect(live.controllerKey != retained.intent.controllerKey)
        #expect(try Checkpoint.censusMatches(state, intents: #require(owner.isolatedTestIntents).checkedSnapshot()))
        #expect(try #require(owner.isolatedTestIntents).checkedSnapshot().intents[retained.intent.id] == retained.intent)
        #expect(try Data(contentsOf: disk.url.appending(path: "managed-storage/state.json")) == bytes)
        #expect(!base.state.withLock { $0.workloadEvents.contains("query") })
        try await owner.recoverWorkload()
        #expect(owner.hasRecoveryPermission)
        #expect(base.state.withLock { Array($0.workloadEvents.suffix(4)) } == ["root-live", "transport", "child", "query"])
        _ = try owner.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator())
        #expect(try owner.snapshot() == observingWorker(in: state, base: base))
        #expect(try Data(contentsOf: disk.url.appending(path: "managed-storage/state.json")) == bytes)
        await owner.close()
    }

    @Test(arguments: ["matching", "missing", "different"])
    func olderRetainedContextRequiresFreshPrepareAttestation(_ attestation: String) async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let base = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        let retained = try await retainedStore(disk, base, reopen: true)
        let peer = try Peer(base: base, grant: retained.grant, stateURL: disk.url.appending(path: "managed-storage-owner/state.json"))
        #expect(peer.status.predecessor.serviceEpoch != retained.intent.serviceEpoch)
        let owner = try owner(disk, base, peer)
        try await cold(owner, disk, base, peer, lock)
        let before = try owner.snapshot()
        let epoch = attestation == "missing" ? nil : attestation == "matching" ? retained.intent.serviceEpoch : Base.id()
        base.state.withLock { $0.workloadResponder = { _ in try Self.query(base, intent: retained.intent, attestedEpoch: epoch) } }
        if attestation == "matching" {
            try await owner.recoverWorkload()
            #expect(owner.hasRecoveryPermission)
            _ = try owner.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator())
        } else {
            await Base().fails { try await owner.recoverWorkload() }
            #expect(!owner.hasRecoveryPermission)
            #expect(throws: (any Error).self) { try owner.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator()) }
        }
        #expect(base.state.withLock { $0.workloadEvents.contains("query") })
        #expect(try owner.snapshot() == observingWorker(in: before, base: base))
        #expect(try #require(owner.isolatedTestIntents).checkedSnapshot().intents[retained.intent.id] == retained.intent)
        await owner.close()
    }

    @Test(arguments: ["epoch", "controller", "store", "census", "unsigned-history"])
    func retainedColdRecoveryRejectsMismatchWithoutPublishing(_ fault: String) async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let base = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        let retained = try await retainedStore(disk, base)
        let stateURL = disk.url.appending(path: "managed-storage-owner/state.json")
        let peer = try Peer(base: base, grant: retained.grant, stateURL: stateURL)
        var holder: Owner?
        let owner = try owner(disk, base, peer, afterWorkloadDecode: { @MainActor in
            if fault == "census" { try #require(holder?.isolatedTestIntents).reconciled() }
        })
        holder = owner
        defer { holder = nil }
        try await cold(owner, disk, base, peer, lock)
        base.state.withLock { $0.workloadResponder = { _ in try Self.query(base, intent: retained.intent, fault: fault) } }
        if fault == "unsigned-history" {
            // Deliberate offline HOST forgery: a genuine grant is not authority
            // for an extra unsigned receipt/context, even after cold completion.
            var forged = try owner.snapshot()
            let old = try #require(forged.contexts.first { $0.context.serviceEpoch == retained.intent.serviceEpoch })
            let inventedEpoch = Base.id(), signed = old.controller.original.signed
            #expect(signed.isValidSignature(using: base.rootKey))
            let receipt = try L.Receipt(grant: signed.grant, nonce: Data(repeating: 9, count: 32),
                serviceEpoch: inventedEpoch, revision: old.controller.directResult.revision)
            forged.contexts.append(.init(context: .init(serviceEpoch: inventedEpoch,
                controllerEpoch: old.context.controllerEpoch, controllerKey: old.context.controllerKey),
                controller: .init(original: old.controller.original, directResult: receipt)))
            try Checkpoint.encode(forged).write(to: stateURL)
        }
        let before = try Data(contentsOf: stateURL)
        // Forged history fails the physical check before ROOT can observe a worker.
        // Other faults occur after ROOT verification, but must publish no recovery
        // permission or checkpoint mutation beyond that exact public projection.
        let expected = fault == "unsigned-history" ? before : try Checkpoint.encode(
            observingWorker(in: owner.snapshot(), base: base))
        await Base().fails { try await owner.recoverWorkload() }
        #expect(!owner.hasRecoveryPermission)
        #expect(throws: (any Error).self) { try owner.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator()) }
        #expect(try Data(contentsOf: stateURL) == expected)
        #expect(try #require(owner.isolatedTestIntents).checkedSnapshot().intents[retained.intent.id] == retained.intent)
        await owner.close()
    }

    /// Model a live controller change while retaining the cold-open Guest/TLS identity.
    @MainActor final class LiveTakeoverTransport: ManagedStorageLifecycleServiceTransport {
        let inner: Base.Transport
        let base: Base.Peer
        init(_ base: Base.Peer, _ disk: Base.Disk) {
            self.base = base; inner = Base.Transport(peer: base, root: disk.root)
        }
        nonisolated func cancel() {}
        func configure(_ configuration: Boot.Configuration) async throws -> ManagedStorageLifecycleServiceReady {
            throw Owner.Failure.invalid
        }
        func command(_ frame: Boot.Frame) async throws -> Boot.Frame {
            if frame.command == .reconcileController {
                let grant = try #require(frame.signed).grant
                let old = try base.ready(grant)
                let ready = Boot.Ready(identity: old.identity, serviceEpoch: old.serviceEpoch, workerUUID: old.workerUUID,
                    controllerEpoch: grant.expectedEpoch + 1, controllerKey: grant.newKey, revision: old.revision + 1,
                    openRevision: old.openRevision, bootstrapKey: old.bootstrapKey, tlsRootDER: old.tlsRootDER,
                    serverDER: old.serverDER, serverSPKI: old.serverSPKI)
                base.state.withLock { $0.simulatedReady = ready }
                return .init(operation: .reply, binding: frame.binding, ready: ready, sequence: frame.sequence,
                    serviceEpoch: frame.serviceEpoch, workerUUID: frame.workerUUID)
            }
            return try await inner.command(frame)
        }
        func connectLifecycle() async throws -> FileHandle { try await inner.connectLifecycle() }
        func connectWorkload() async throws -> FileHandle { try await inner.connectWorkload() }
        func connectAttachmentCSR() async throws -> FileHandle { try await inner.connectAttachmentCSR() }
    }

    @Test(arguments: ["empty", "matching", "missing", "different"])
    func liveRestartsAfterColdRequireOnlyReferencedAuthenticatedHistory(_ attestation: String) async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let base = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        let restarts = ManagedStorageLifecycleRestartTests()
        let retained = attestation == "empty" ? nil : try await retainedStore(disk, base)
        let initial: L.Grant
        if let retained { initial = retained.grant }
        else { initial = try await restarts.freshStore(disk, base) }
        let peer = try Peer(base: base, grant: initial, stateURL: disk.url.appending(path: "managed-storage-owner/state.json"))
        let completed: Checkpoint.Metadata
        do {
            let coldOwner = try owner(disk, base, peer)
            try await cold(coldOwner, disk, base, peer, lock)
            completed = try coldOwner.snapshot()
            await coldOwner.close()
        }
        if let retained {
            let epoch = attestation == "missing" ? nil : attestation == "matching" ? retained.intent.serviceEpoch : Base.id()
            base.state.withLock { $0.workloadResponder = { _ in try Self.query(base, intent: retained.intent, attestedEpoch: epoch) } }
        }
        var grant = try #require(completed.current?.original.signed.grant)
        for epoch in UInt64(2)...3 {
            let restarted = try restarts.existing(disk, base, epoch: epoch, daemon: epoch + 10)
            _ = try await restarted.prepareTakeover()
            try await restarted.takeover(using: LiveTakeoverTransport(base, disk),
                current: .init(binding: base.bootBinding, ready: base.ready(grant)))
            #expect(try restarted.snapshot().latestCold == completed.latestCold)
            if attestation == "empty" || attestation == "matching" {
                try await restarted.recoverWorkload()
                #expect(restarted.hasRecoveryPermission)
                _ = try restarted.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator())
            } else {
                await Base().fails { try await restarted.recoverWorkload() }
                #expect(!restarted.hasRecoveryPermission)
            }
            grant = try #require(restarted.snapshot().current?.original.signed.grant)
            await restarted.close()
        }
    }

    @Test func persistedColdCompletionCannotReconstructRecoveryPermission() async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let base = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        let retained = try await retainedStore(disk, base)
        let stateURL = disk.url.appending(path: "managed-storage-owner/state.json")
        let peer = try Peer(base: base, grant: retained.grant, stateURL: stateURL)
        let completed: Checkpoint.Metadata
        do {
            let owner = try owner(disk, base, peer)
            try await cold(owner, disk, base, peer, lock)
            completed = try owner.snapshot()
            #expect(completed.latestCold != nil)
            await owner.close()
        }
        let restarted = try ManagedStorageLifecycleRestartTests().existing(disk, base, epoch: 2, daemon: 11)
        _ = try await restarted.prepareTakeover()
        #expect(try restarted.snapshot() == completed)
        await Base().fails { try await restarted.recoverWorkload() }
        #expect(!restarted.hasRecoveryPermission)
        #expect(throws: (any Error).self) { try restarted.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator()) }
        #expect(try restarted.snapshot() == completed)
        #expect(!base.state.withLock { $0.workloadEvents.contains("query") })
        await restarted.close()
    }

    @Test func uncertainColdConfigureIsNeverReplayedOrReconstructed() async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let base = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        let initial = try await ManagedStorageLifecycleRestartTests().freshStore(disk, base)
        let peer = try Peer(base: base, grant: initial, stateURL: disk.url.appending(path: "managed-storage-owner/state.json"))
        let pending: Checkpoint.PendingCold
        do {
            let owner = try owner(disk, base, peer)
            _ = try await owner.statusCold(storeLock: lock)
            _ = try await owner.prepareTakeover()
            let greeting = try greeting(base, backingDescriptor: disk.backing)
            let transport = Transport(inner: Base.Transport(peer: base, root: disk.root), greeting: greeting, peer: peer)
            transport.failConfigure = true
            await Base().fails { try await owner.bootCold(using: transport, greeting: greeting, storeLock: lock,
                nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600) }
            pending = try #require(owner.snapshot().pendingCold)
            #expect(pending.bootAttempted && pending.prepared != nil)
            transport.failConfigure = false
            await Base().fails { try await owner.bootCold(using: transport, greeting: greeting, storeLock: lock,
                nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600) }
            #expect(transport.configurations == 1 && !owner.hasRecoveryPermission)
            await owner.close()
        } // Release the physical journal lease before simulating a new process.
        let restarted = try self.owner(disk, base, peer)
        await #expect(throws: StorageLifecycleRootClient.Failure.self) { _ = try await restarted.statusCold(storeLock: lock) }
        await Base().fails { _ = try await restarted.prepareTakeover() }
        let frozen = try #require(restarted.snapshot().pendingCold)
        #expect(frozen.bootAttempted && frozen.prepared == pending.prepared && frozen.request == pending.request)
        #expect(frozen.resolutionRequest != nil)
        await Base().fails { _ = try await restarted.statusCold(storeLock: lock) }
        #expect(try restarted.snapshot().pendingCold == frozen)
        let resolutions = peer.state.withLock { $0.requests.filter { if case .resolveDead = $0.body { true } else { false } } }
        #expect(resolutions.count == 2 && resolutions[0] == resolutions[1])
        await restarted.close()
    }
}
#endif

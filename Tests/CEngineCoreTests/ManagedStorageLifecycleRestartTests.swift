#if os(macOS) && DEBUG
import CEngineCore
import CryptoKit
import Darwin
import Foundation
import Testing
import Synchronization
@testable import CEngineRuntime

/// ISOLATED NON-NATIVE cold daemon-restart tests for an existing v2 store. These
/// do not authenticate ROOT/child/shim; ROOT's predecessor-exit check is modelled.
@Suite(.serialized) @MainActor struct ManagedStorageLifecycleRestartTests {
    typealias Base = ManagedStorageLifecycleOwnerTests
    typealias Owner = ManagedStorageLifecycleOwner
    typealias L = StorageLifecycleProtocol
    typealias R = StorageLifecycleRootProtocol

    @Test(arguments: [false, true], [false, true])
    func interruptedHandoffRecoversBeforeChildAndRetriesExactNativeEnvelope(applied: Bool, lostIssue: Bool) async throws {
        typealias C = ManagedStorageLifecycleCheckpoint
        typealias H = StorageLifecycleHandoffProtocol
        typealias RPC = StorageLifecycleAdoptionRootProtocol
        let disk = try Base.Disk(); defer { disk.remove() }
        let peer = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        let initial = try await freshStore(disk, peer)
        let manifest = try C.readManifest(in: disk.root)
        let candidate = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
        let grant = try L.Grant(operation: .takeover, id: Base.id(), identity: initial.identity, serial: 2,
            expectedEpoch: 1, newKey: StorageIdentity.Ed25519SPKI(rawPublicKey: candidate).fingerprint.rawValue)
        let signed = try L.SignedGrant(grant: grant, signature: peer.rootPrivate.signature(for: grant.signingBytes))
        let stateURL = disk.url.appending(path: "managed-storage-owner/state.json")
        let original: C.Metadata = try {
            let checkpoint = try C.open(in: disk.root, backingDescriptor: disk.backing, identity: initial.identity,
                rootPublicKey: peer.rootKey.publicData, provenanceReference: manifest.provenanceReference)
            let journal = try HostStorageIntents.open(in: disk.root, store: initial.identity.store, provenanceReference: manifest.provenanceReference)
            let state = try checkpoint.snapshot(), census = try journal.checkedSnapshot()
            let context = C.GrantContext(signed: signed, recipient: .init(publicKey: candidate, incarnation: Base.id(),
                daemonUniqueID: 7, childUniqueID: 8, childPID: 44), requestID: Base.id(), serviceEpoch: state.currentContext!.serviceEpoch)
            let change: C.Change = lostIssue ? .stageTakeoverRequest(.init(requestID: context.requestID,
                grantID: grant.id, recipient: context.recipient, expectedEpoch: 1, serviceEpoch: context.serviceEpoch!)) : .stage(context)
            try checkpoint.persist(change, intents: census, readIntents: { try journal.checkedSnapshot() })
            return state
        }()
        let predecessor = original.currentService!, operationID = Base.id()
        let request = try H.Request(operationID: operationID, predecessor: initial, pending: grant,
            serviceEpoch: predecessor.context.serviceEpoch, openRevision: predecessor.openRevision)
        let receipt = try applied ? L.Receipt(grant: grant, nonce: Data(repeating: 7, count: 32),
            serviceEpoch: predecessor.context.serviceEpoch, revision: 2) : original.current!.directResult
        let actual = try applied ? L.ServiceState(grant: grant,
            context: .init(serviceEpoch: predecessor.context.serviceEpoch, controllerEpoch: 2, controllerKey: grant.newKey),
            openRevision: predecessor.openRevision, boot: predecessor.boot) : predecessor
        let result = try H.Result(request: request, nonce: Data(repeating: 8, count: 32), appliedGrant: receipt.grant,
            appliedServiceEpoch: receipt.serviceEpoch, appliedRevision: receipt.revision, fenceRevision: 3)
        let completion = try StorageLifecycleHandoffRootProtocol.Completed(
            signedRequest: .init(request: request, signature: peer.rootPrivate.signature(for: request.signingBytes)), result: result,
            predecessorService: predecessor, predecessorReceipt: original.current!.directResult,
            service: actual, receipt: receipt, pendingSigned: signed)
        struct Calls { var requests: [RPC.Request] = []; var launches = 0; var committed = false; var unavailable = true; var lostHostReply = true }
        let calls = Mutex(Calls())
        func makeOwner() throws -> Owner {
            var seam = try peer.seam(child: Curve25519.Signing.PrivateKey(), childIncarnation: Base.id(),
                expectedEpoch: applied ? 2 : 1, daemon: 11)
            seam.childLaunch = { calls.withLock { $0.launches += 1 } }
            seam.adoptionRequest = { envelope in
                try calls.withLock { c in
                    c.requests.append(envelope)
                    switch envelope.body {
                    case .handoffStatus:
                        return try .init(for: envelope, body: .handoffStatus(.init(currentService: c.committed ? actual : predecessor,
                            pending: c.committed ? nil : grant, operationID: operationID, completion: c.committed ? completion : nil)))
                    case .recoverHandoff(_, let id):
                        #expect(id == operationID && c.launches == 0)
                        let durable = try JSONDecoder().decode(C.Metadata.self, from: Data(contentsOf: stateURL))
                        #expect(durable.handoffRetry?.recoveryRequestID == envelope.requestID.rawValue)
                        #expect(durable.handoffRetry?.operationID == id)
                        c.committed = true
                        if c.unavailable { c.unavailable = false; throw StorageLifecycleRootClient.Failure(.unavailable) }
                        if c.lostHostReply { c.lostHostReply = false; throw Owner.Failure.incomplete }
                        return try .init(for: envelope, body: .handoffRecovered(completion))
                    default: throw Owner.Failure.invalid
                    }
                }
            }
            return try Owner(isolatedTestExisting: seam, root: disk.root, backingDescriptor: disk.backing, binding: disk.binding)
        }
        // close() joins the child but the owner still holds HOST journal leases.
        // End its lifetime before constructing the replacement, as daemon exit does.
        let durable = try await { () async throws -> C.HandoffRetry in
            let owner = try makeOwner()
            await Base().fails { _ = try await owner.prepareTakeover() }
            await Base().fails { try await owner.recoverInterruptedHandoff(storeLock: lock) }
            #expect(calls.withLock { $0.launches } == 0)
            let durable = try #require(owner.snapshot().handoffRetry)
            await owner.close()
            return durable
        }()
        let owner = try makeOwner()
        try await owner.recoverInterruptedHandoff(storeLock: lock)
        let done = try owner.snapshot()
        #expect(done.currentService == actual && done.pending == nil && done.pendingTakeover == nil && done.handoffRetry == nil)
        #expect(try await owner.prepareTakeover().greeting.expectedEpoch == (applied ? 2 : 1))
        let recoveries = calls.withLock { $0.requests.filter { if case .recoverHandoff = $0.body { true } else { false } } }
        #expect(recoveries.count == 3 && Set(recoveries.map { $0.requestID.rawValue }) == [durable.recoveryRequestID])
        #expect(recoveries.allSatisfy { $0 == recoveries[0] })
        await owner.close()
    }

    /// Fresh provision + boot, then drop the owner so its leases are released.
    func freshStore(_ disk: Base.Disk, _ peer: Base.Peer) async throws -> L.Grant {
        let owner = try disk.owner(peer)
        try await owner.provisionFresh()
        try await owner.bootFresh(using: Base.Transport(peer: peer, root: disk.root), expectedBinding: peer.bootBinding,
            nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        let grant = try #require(owner.snapshot().current?.original.signed.grant)
        await owner.close()
        // bootFresh's own bind is not a takeover-era Guest mutation.
        peer.state.withLock { $0.binds = 0 }
        return grant
    }
    func existing(_ disk: Base.Disk, _ peer: Base.Peer, epoch: UInt64 = 1, daemon: UInt64 = 9,
                  afterWorkloadDecode: (() async throws -> Void)? = nil) throws -> Owner {
        try Owner(isolatedTestExisting: peer.seam(child: Curve25519.Signing.PrivateKey(), childIncarnation: Base.id(),
            expectedEpoch: epoch, daemon: daemon), root: disk.root, backingDescriptor: disk.backing, binding: disk.binding,
            afterWorkloadDecode: afterWorkloadDecode)
    }
    func current(_ peer: Base.Peer, _ grant: L.Grant) throws -> ManagedStorageLifecycleServiceReady {
        .init(binding: peer.bootBinding, ready: try peer.initialReady(grant))
    }
    func bytes(_ url: URL) throws -> [String: Data] {
        var result: [String: Data] = [:]
        for case let file as URL in FileManager.default.enumerator(at: url, includingPropertiesForKeys: nil)! {
            var directory: ObjCBool = false
            FileManager.default.fileExists(atPath: file.path, isDirectory: &directory)
            result[file.path] = directory.boolValue ? Data() : try Data(contentsOf: file)
        }
        return result
    }
    func takeoverRequests(_ peer: Base.Peer) -> [R.Request] {
        peer.state.withLock { $0.requests.filter { if case .issue(.takeover, _, _, _, _) = $0.body { true } else { false } } }
    }

    /// Isolated public RPC model; never native proof or a process capability.
    nonisolated final class AdoptionPeer: @unchecked Sendable {
        typealias A = StorageLifecycleAdoptionProtocol
        typealias RPC = StorageLifecycleAdoptionRootProtocol
        struct State {
            var requests: [RPC.Request] = []
            var pending: A.Request?
            var latest: A.Request?
            var dropPrepare = false
            var dropComplete = false
            var unavailablePrepare = 0
            var unavailableComplete = 0
            var dropServiceCompletionReplies = 0
            var prepareError: StorageIdentity.ErrorCode?
            var dedicatedServices = 0
            var serviceOverride: L.ServiceState?
        }
        let state = Mutex(State())
        let origin: A.Origin
        let peer: Base.Peer
        let stateURL: URL
        init(peer: Base.Peer, stateURL: URL) throws {
            self.peer = peer; self.stateURL = stateURL
            origin = try .init(binding: .init(peer.binding), rootPublicKey: peer.rootKey.publicData,
                shimLaunchUUID: peer.bootBinding.shimLaunchUUID, specSHA256: String(repeating: "a", count: 64))
        }
        func request(_ envelope: RPC.Request) throws -> RPC.Reply {
            #expect(!Thread.isMainThread)
            return try state.withLock { s in
                s.requests.append(envelope)
                switch envelope.body {
                case .handoffStatus:
                    let metadata = try JSONDecoder().decode(ManagedStorageLifecycleCheckpoint.Metadata.self, from: Data(contentsOf: stateURL))
                    return try .init(for: envelope, body: .handoffStatus(.init(currentService: #require(metadata.currentService),
                        pending: nil, operationID: nil, completion: nil)))
                case .recoverHandoff: throw Owner.Failure.blocked
                case .status:
                    let committed = try s.latest?.epoch ?? 1
                    return try .init(for: envelope, body: .status(.init(origin: origin,
                        shimAudit: Data(repeating: 3, count: 32), shimUniqueID: 77,
                        baseEpoch: 1, committedEpoch: committed, allocatedEpoch: s.pending?.epoch ?? committed,
                        pending: s.pending, latest: s.latest)))
                case .prepare(let request), .complete(let request):
                    let object = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: stateURL)) as? [String: Any])
                    let bytes = try JSONSerialization.data(withJSONObject: #require(object["adoptionRetry"]))
                    let durable = try JSONDecoder().decode(ManagedStorageLifecycleCheckpoint.AdoptionRetry.self, from: bytes)
                    #expect(durable.request == request) // persisted BEFORE both external side effects
                    if case .prepare = envelope.body {
                        #expect(durable.prepareRequestID == envelope.requestID.rawValue)
                        if s.latest != request { s.pending = request }
                        if s.dropPrepare { throw Owner.Failure.incomplete }
                        if let code = s.prepareError { throw StorageLifecycleRootClient.Failure(code) }
                        if s.unavailablePrepare > 0 {
                            s.unavailablePrepare -= 1
                            throw StorageLifecycleRootClient.Failure(.unavailable)
                        }
                        return try .init(for: envelope, body: .prepared(request.fenceIdentity))
                    }
                    #expect(durable.completeRequestID == envelope.requestID.rawValue)
                    #expect(s.pending == request || s.latest == request)
                    s.latest = request; s.pending = nil
                    if s.dropComplete { throw Owner.Failure.incomplete }
                    if s.unavailableComplete > 0 {
                        s.unavailableComplete -= 1
                        throw StorageLifecycleRootClient.Failure(.unavailable)
                    }
                    return try .init(for: envelope, body: .completed(request.fenceIdentity))
                case .completeServiceChange(let adoption, let change):
                    #expect(s.latest == adoption && s.pending == nil)
                    let metadata = try JSONDecoder().decode(ManagedStorageLifecycleCheckpoint.Metadata.self, from: Data(contentsOf: stateURL))
                    #expect((metadata.pendingService ?? metadata.latestServiceRequest)?.completionRequestID == envelope.requestID.rawValue)
                    let ready = try peer.ready(change.predecessor.grant)
                    let result = try peer.live(change.predecessor.grant, ready)
                    let confirmation = try L.ServiceChangeConfirmation(request: change, successor: result.state(boot: peer.trust(ready)))
                    peer.state.withLock { $0.serviceConfirmation = confirmation }
                    if s.dropServiceCompletionReplies > 0 {
                        s.dropServiceCompletionReplies -= 1
                        throw StorageLifecycleRootClient.Failure(.unavailable)
                    }
                    return try .init(for: envelope, body: .serviceChanged(confirmation, result))
                case .service(let adoption, let grant):
                    #expect(s.latest == adoption && s.pending == nil)
                    s.dedicatedServices += 1
                    let ready = try peer.ready(grant)
                    let service = try s.serviceOverride ?? peer.live(grant, ready).state(boot: peer.trust(ready))
                    return try .init(for: envelope, body: .service(service))
                }
            }
        }
    }
    func adoptionOwner(_ disk: Base.Disk, _ peer: Base.Peer, _ adoption: AdoptionPeer,
                       daemon: UInt64 = 9) throws -> Owner {
        var seam = try peer.seam(child: Curve25519.Signing.PrivateKey(), childIncarnation: Base.id(),
            expectedEpoch: 1, daemon: daemon)
        seam.daemonAudit = Data(repeating: UInt8(daemon), count: 32)
        seam.childAudit = Data(repeating: UInt8(daemon + 1), count: 32)
        seam.adoptionRequest = { try adoption.request($0) }
        return try Owner(isolatedTestExisting: seam, root: disk.root, backingDescriptor: disk.backing, binding: disk.binding)
    }

    @MainActor final class ReplacementTransport: ManagedStorageLifecycleServiceTransport {
        typealias Boot = StorageLifecycleServiceBootProtocol
        let base: Base.Transport
        let request: Boot.ReplacementRequest
        let nativeReady: Boot.Ready
        var frames: [Boot.Frame] = []
        var fail = false
        init(peer: Base.Peer, root: PersistentStateDirectory, request: Boot.ReplacementRequest, ready: Boot.Ready) {
            base = Base.Transport(peer: peer, root: root); self.request = request; nativeReady = ready
        }
        nonisolated func cancel() {}
        func configure(_ configuration: Boot.Configuration) async throws -> ManagedStorageLifecycleServiceReady {
            Issue.record("recovery must not configure"); throw Owner.Failure.blocked
        }
        func command(_ frame: Boot.Frame) async throws -> Boot.Frame {
            frames.append(frame)
            if frame.command == .replaceService || frame.command == .replacementStatus {
                #expect(frame.serviceEpoch == request.configuration.reopen?.request.predecessor.context.serviceEpoch)
                #expect(frame.workerUUID == request.predecessorWorkerUUID)
                if frame.command == .replaceService { #expect(frame.replacementRequest == request) }
                return .init(operation: .reply, binding: frame.binding, sequence: frame.sequence,
                    serviceEpoch: frame.serviceEpoch, workerUUID: frame.workerUUID,
                    replacement: .init(request: request, phase: fail ? .failed : .succeeded,
                        ready: fail ? nil : nativeReady, code: fail ? .workerUnreaped : nil))
            }
            if frame.command == .reconcileController {
                let grant = try #require(frame.signed?.grant)
                let ready = Boot.Ready(identity: nativeReady.identity, serviceEpoch: nativeReady.serviceEpoch,
                    workerUUID: nativeReady.workerUUID, controllerEpoch: grant.expectedEpoch + 1, controllerKey: grant.newKey,
                    revision: nativeReady.revision + 1, openRevision: nativeReady.openRevision,
                    bootstrapKey: nativeReady.bootstrapKey, tlsRootDER: nativeReady.tlsRootDER,
                    serverDER: nativeReady.serverDER, serverSPKI: nativeReady.serverSPKI)
                base.peer.state.withLock { $0.simulatedReady = ready }
                return .init(operation: .reply, binding: frame.binding, ready: ready, sequence: frame.sequence,
                    serviceEpoch: frame.serviceEpoch, workerUUID: frame.workerUUID)
            }
            return try await base.command(frame)
        }
        func connectLifecycle() async throws -> FileHandle { try await base.connectLifecycle() }
        func connectWorkload() async throws -> FileHandle { try await base.connectWorkload() }
        func connectAttachmentCSR() async throws -> FileHandle { try await base.connectAttachmentCSR() }
    }

    /// All three crash windows retain the identical signed replacement envelope.
    @Test(arguments: ["pending", "root-completed", "host-confirmed", "lost-completion", "failed", "missing-frozen", "mismatched-proof"], [false, true])
    func frozenReplacementRestart(window: String, nonempty: Bool) async throws {
        typealias C = ManagedStorageLifecycleCheckpoint
        let disk = try Base.Disk(); defer { disk.remove() }
        let peer = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        func stage() async throws -> C.Metadata {
            let owner = try disk.owner(peer)
            try await owner.provisionFresh()
            try await owner.bootFresh(using: Base.Transport(peer: peer, root: disk.root), expectedBinding: peer.bootBinding,
                nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
            if nonempty {
                let journal = try #require(owner.isolatedTestIntents)
                try journal.reconciled()
                let context = try #require(owner.snapshot().currentContext)
                let volume = Base.id()
                try journal.planVolumes([.init(id: volume, name: "recovery-volume", createOperation: Base.id(), deleteOperation: Base.id())])
                let slots: [HostStorageIntents.Slot] = ["prepare", "runtime"].map {
                    .init(volume: volume, attachment: Base.id(), role: $0, mode: "read-write",
                        registerOperation: Base.id(), retireOperation: Base.id())
                }
                _ = try journal.plan(.init(id: Base.id(), store: disk.binding.storeID.rawValue,
                    container: String(repeating: "a", count: 64), containerInstance: Base.id(), launch: Base.id(),
                    specificationDigest: String(repeating: "b", count: 64), serviceEpoch: context.serviceEpoch,
                    controllerEpoch: context.controllerEpoch, controllerKey: context.controllerKey,
                    prepare: Base.id(), reserveOperation: Base.id(), completeOperation: Base.id(), replaceOperation: Base.id(),
                    mounts: [.init(volume: volume, destination: "/data", subpath: "", mode: "read-write")],
                    slots: slots, version: 1, phase: .planned, prepareCompleted: false, cleanUnmount: false))
            }
            try await owner.stageServiceChange(operationID: Base.id(), nowUnixSeconds: 1_800_000_100, lifetimeSeconds: 1800)
            let result = try owner.snapshot()
            await owner.close()
            return result
        }
        var metadata = try await stage()
        let pending = try #require(metadata.pendingService), frozen = try #require(metadata.serviceReplacement)
        let native = peer.successor(pending.request.predecessor.grant)
        peer.state.withLock { $0.simulatedReady = native; $0.binds = 0; $0.childActions = 0; $0.deadRecipientGrantID = pending.request.predecessor.grant.id }
        let confirmation = try L.ServiceChangeConfirmation(request: pending.request,
            successor: peer.live(pending.request.predecessor.grant, native).state(boot: peer.trust(native)))
        let stateURL = disk.url.appending(path: "managed-storage-owner/state.json")
        if window == "root-completed" { peer.state.withLock { $0.serviceConfirmation = confirmation } }
        if window == "host-confirmed" {
            let journal = try HostStorageIntents.open(in: disk.root, store: metadata.identity.store, provenanceReference: metadata.provenanceReference)
            metadata = try C.applying(.attemptNativeReplacement, to: metadata, intents: journal.checkedSnapshot())
            metadata = try C.applying(.confirmService(confirmation), to: metadata, intents: journal.checkedSnapshot())
            try C.encode(metadata).write(to: stateURL)
        }
        if window == "missing-frozen" {
            metadata.serviceReplacement = nil
            try C.encode(metadata).write(to: stateURL)
        }
        let rpc = try AdoptionPeer(peer: peer, stateURL: stateURL)
        if window == "lost-completion" { rpc.state.withLock { $0.dropServiceCompletionReplies = 1 } }
        let owner = try adoptionOwner(disk, peer, rpc)
        let transport = ReplacementTransport(peer: peer, root: disk.root, request: frozen, ready: native)
        let proofs = oldGrantProofs(peer, pending.request.predecessor.grant)
        if window == "missing-frozen" {
            await Base().fails { _ = try await owner.prepareReplacementRecovery() }
            #expect(rpc.state.withLock { $0.requests.isEmpty })
            await owner.close(); return
        }
        if metadata.pendingService != nil {
            await Base().fails { _ = try await owner.prepareTakeover() }
        }
        #expect(try await owner.prepareReplacementRecovery())
        #expect(peer.state.withLock { $0.childActions == 0 && $0.binds == 0 && $0.takeoverIssues == 0 })
        _ = try await owner.adoptSurvivingShim(storeLock: lock)
        let ready = ManagedStorageLifecycleServiceReady(binding: peer.bootBinding, ready: native)
        if window == "failed" || window == "mismatched-proof" {
            transport.fail = window == "failed"
            if window == "mismatched-proof" {
                let wrong = peer.successor(pending.request.predecessor.grant)
                peer.state.withLock { $0.simulatedReady = wrong }
            }
            await Base().fails { try await owner.recoverReplacement(using: transport, current: ready) }
            #expect(peer.state.withLock { $0.binds == 0 && $0.takeoverIssues == 0 && $0.rebinds == 0 })
            #expect(try owner.snapshot().pendingService == pending)
            await owner.close(); return
        }
        try await owner.recoverReplacement(using: transport, current: ready)
        #expect(try owner.snapshot().pendingService == nil)
        #expect(try owner.snapshot().serviceReplacement == frozen)
        #expect(peer.state.withLock { $0.binds == 0 && $0.takeoverIssues == 0 && $0.rebinds == 0 })
        #expect(transport.frames.count == 1)
        let completions = rpc.state.withLock { $0.requests.filter { if case .completeServiceChange = $0.body { true } else { false } } }
        #expect(completions.count == (window == "lost-completion" ? 2 : 1))
        #expect(completions.allSatisfy { $0 == completions.first && $0.requestID.rawValue == pending.completionRequestID })
        #expect(peer.state.withLock { $0.childActions == 0 })
        try await owner.takeover(using: transport, current: ready)
        try await owner.recoverWorkload()
        #expect(owner.hasRecoveryPermission)
        if nonempty {
            #expect(try owner.snapshot().references.count == 1)
            #expect(try owner.snapshot().contexts.contains { $0.context.serviceEpoch == peer.serviceEpoch })
            let journal = try #require(owner.isolatedTestIntents)
            let intent = try #require(journal.checkedSnapshot().intents.values.first)
            let coordinator = try owner.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator())
            let settled = try await coordinator.settleExecution(intent.id, in: disk.root)
            #expect(settled.status == .neverLaunched)
            #expect(try journal.intent(settled.token).phase == .unlaunched)
            try await coordinator.reconcileStartup()
            #expect(try !journal.checkedSnapshot().reconciliationRequired)
        }
        #expect(oldGrantProofs(peer, pending.request.predecessor.grant) == proofs)
        #expect(peer.state.withLock { $0.binds == 1 && $0.takeoverIssues == 1 && $0.rebinds == 0 })
        await owner.close()
    }

    func oldGrantProofs(_ peer: Base.Peer, _ grant: L.Grant) -> Int {
        peer.state.withLock { $0.requests.filter {
            switch $0.body {
            case .serviceBootTrust(_, let id, _), .serviceResult(_, let id): return id == grant.id
            default: return false
            }
        }.count }
    }

    /// Production ordering contract (isolated RPC/native-ready model): the old
    /// child is dead before prepare, so neither ordinary proof route is usable.
    @Test(arguments: [false, true])
    func adoptedFullBootProofNeverContactsDeadRecipient(_ missingCheckpoint: Bool) async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let peer = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        let initial = try await freshStore(disk, peer)
        let stateURL = disk.url.appending(path: "managed-storage-owner/state.json")
        if missingCheckpoint {
            var metadata = try ManagedStorageLifecycleCheckpoint.decode(Data(contentsOf: stateURL))
            metadata.currentService = nil
            try ManagedStorageLifecycleCheckpoint.encode(metadata).write(to: stateURL)
        }
        let rpc = try AdoptionPeer(peer: peer, stateURL: stateURL)
        let owner = try adoptionOwner(disk, peer, rpc)
        let before = oldGrantProofs(peer, initial)
        peer.state.withLock { $0.deadRecipientGrantID = initial.id }
        _ = try await owner.prepareTakeover()
        _ = try await owner.adoptSurvivingShim(storeLock: lock)
        try await owner.takeover(using: Base.Transport(peer: peer, root: disk.root), current: current(peer, initial))
        #expect(oldGrantProofs(peer, initial) == before)
        #expect(try owner.snapshot().currentService?.context.controllerEpoch == 2)
        #expect(peer.state.withLock { $0.childTakeovers } == 1)
        await owner.close()
    }

    @Test(arguments: ["epoch", "ca", "spki"], [false, true])
    func adoptedProofRejectsDifferentFullBoot(_ field: String, _ missingCheckpoint: Bool) async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let peer = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        let initial = try await freshStore(disk, peer)
        let stateURL = disk.url.appending(path: "managed-storage-owner/state.json")
        if missingCheckpoint {
            var metadata = try ManagedStorageLifecycleCheckpoint.decode(Data(contentsOf: stateURL))
            metadata.currentService = nil
            try ManagedStorageLifecycleCheckpoint.encode(metadata).write(to: stateURL)
        }
        let rpc = try AdoptionPeer(peer: peer, stateURL: stateURL)
        let ready = try peer.ready(initial), trusted = try peer.trust(ready)
        let boot = try StorageLifecycleBootTrust(identity: trusted.identity,
            serviceEpoch: field == "epoch" ? Base.id() : trusted.serviceEpoch,
            tlsRootSHA256: field == "ca" ? String(repeating: "d", count: 64) : trusted.tlsRootSHA256,
            serverSPKI: field == "spki" ? String(repeating: "e", count: 64) : trusted.serverSPKI,
            bootstrapKey: trusted.bootstrapKey)
        let result = try peer.live(initial, ready)
        let proof = try L.ServiceState(grant: initial,
            context: .init(serviceEpoch: boot.serviceEpoch, controllerEpoch: result.controllerEpoch, controllerKey: result.controllerKey),
            openRevision: result.openRevision, boot: boot)
        // CA/SPKI are absent from ServiceResult: equal result fields must NOT
        // let the owner substitute checkpoint/ready boot metadata into ROOT proof.
        if field != "epoch" { #expect(try result.state(boot: boot) == proof) }
        rpc.state.withLock { $0.serviceOverride = proof }
        peer.state.withLock { $0.deadRecipientGrantID = initial.id }
        let owner = try adoptionOwner(disk, peer, rpc)
        _ = try await owner.prepareTakeover()
        _ = try await owner.adoptSurvivingShim(storeLock: lock)
        let before = try owner.snapshot(), ordinary = oldGrantProofs(peer, initial)
        let transport = Base.Transport(peer: peer, root: disk.root)
        await Base().fails { try await owner.takeover(using: transport, current: self.current(peer, initial)) }
        #expect(try owner.snapshot() == before)
        #expect(oldGrantProofs(peer, initial) == ordinary)
        #expect(takeoverRequests(peer).isEmpty && transport.commands.isEmpty)
        await owner.close()
    }

    @Test(arguments: ["prepare", "complete"])
    func liveAdoptionRetriesExactDurableTupleBeforeTakeover(_ lost: String) async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let peer = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        let initial = try await freshStore(disk, peer)
        let rpc = try AdoptionPeer(peer: peer, stateURL: disk.url.appending(path: "managed-storage-owner/state.json"))
        let owner = try adoptionOwner(disk, peer, rpc)
        let transport = Base.Transport(peer: peer, root: disk.root)
        await Base().fails { try await owner.takeover(using: transport, current: self.current(peer, initial)) }
        let prepared = try await owner.prepareTakeover()
        let again = try await owner.prepareTakeover()
        #expect(prepared.greeting == again.greeting && prepared.greeting.expectedEpoch == 1)
        #expect(transport.commands.isEmpty && peer.state.withLock { $0.binds } == 0)
        rpc.state.withLock { $0.dropPrepare = lost == "prepare"; $0.dropComplete = lost == "complete" }
        await Base().fails { _ = try await owner.adoptSurvivingShim(storeLock: lock) }
        let durable = try #require(owner.snapshot().adoptionRetry)
        rpc.state.withLock { $0.dropPrepare = false; $0.dropComplete = false }
        let adopted = try await owner.adoptSurvivingShim(storeLock: lock)
        // A successful fake ROOT complete (including exact retries) is metadata,
        // never authority to bypass ordinary native code-signature validation.
        #expect(adopted.connectionAuthorization == nil)
        #expect(adopted.request == durable.request)
        #expect(try owner.snapshot().adoptionRetry == durable)
        let prepares = rpc.state.withLock { $0.requests.filter { if case .prepare = $0.body { true } else { false } } }
        #expect(prepares.count == 2 && prepares[0] == prepares[1])
        let ordinaryProofs = oldGrantProofs(peer, initial)
        peer.state.withLock { $0.deadRecipientGrantID = initial.id }
        try await owner.takeover(using: transport, current: current(peer, initial))
        #expect(rpc.state.withLock { $0.dedicatedServices } >= 1)
        #expect(oldGrantProofs(peer, initial) == ordinaryProofs)
        #expect(transport.configurations == 0)
        let events = peer.state.withLock { $0.workloadEvents }
        let reconcile = try #require(events.lastIndex(of: "reconcile")), complete = try #require(events.lastIndex(of: "root"))
        #expect(reconcile < complete)
        try await owner.recoverWorkload()
        #expect(owner.hasRecoveryPermission)
        await owner.close()
    }

    @Test(arguments: ["prepare", "complete"])
    func delayedShimRegistrationRetriesOnlyFrozenEnvelope(_ stage: String) async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let peer = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        _ = try await freshStore(disk, peer)
        let rpc = try AdoptionPeer(peer: peer, stateURL: disk.url.appending(path: "managed-storage-owner/state.json"))
        rpc.state.withLock { $0.unavailablePrepare = stage == "prepare" ? 2 : 0; $0.unavailableComplete = stage == "complete" ? 2 : 0 }
        let owner = try adoptionOwner(disk, peer, rpc)
        _ = try await owner.prepareTakeover()
        let adopted = try await owner.adoptSurvivingShim(storeLock: lock)
        #expect(adopted.connectionAuthorization == nil)
        let durable = try #require(owner.snapshot().adoptionRetry)
        #expect(adopted.request == durable.request)
        let attempts = rpc.state.withLock { $0.requests.filter {
            switch $0.body { case .prepare: return stage == "prepare"; case .complete: return stage == "complete"; default: return false }
        } }
        #expect(attempts.count == 3)
        #expect(attempts.allSatisfy { $0 == attempts.first })
        #expect(takeoverRequests(peer).isEmpty && peer.state.withLock { $0.binds } == 0)
        await owner.close()
    }

    @Test(arguments: [false, true])
    func adoptionRetryBudgetOrCancellationPreservesPending(_ cancel: Bool) async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let peer = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        _ = try await freshStore(disk, peer)
        let rpc = try AdoptionPeer(peer: peer, stateURL: disk.url.appending(path: "managed-storage-owner/state.json"))
        rpc.state.withLock { $0.unavailablePrepare = 1_000 }
        let owner = try adoptionOwner(disk, peer, rpc)
        _ = try await owner.prepareTakeover()
        let task = Task { try await owner.adoptSurvivingShim(storeLock: lock, timeout: cancel ? 2 : 0.2) }
        defer { task.cancel() }
        if cancel {
            // Wait for the first durable request, not an arbitrary fixture delay.
            let limit = ContinuousClock.now + .seconds(2)
            while rpc.state.withLock({ $0.pending == nil }), ContinuousClock.now < limit {
                try await Task.sleep(for: .milliseconds(1))
            }
            task.cancel()
            #expect(rpc.state.withLock { $0.pending != nil })
        }
        await Base().fails { _ = try await task.value }
        let pending = try #require(owner.snapshot().adoptionRetry)
        #expect(rpc.state.withLock { $0.pending } == pending.request)
        #expect(rpc.state.withLock { $0.latest } == nil)
        #expect(takeoverRequests(peer).isEmpty && peer.state.withLock { $0.binds } == 0)
        await owner.close()
    }

    @Test(arguments: [StorageIdentity.ErrorCode.unauthorized, .conflict, .repairRequired])
    func adoptionNeverRetriesNonTransportFailure(_ code: StorageIdentity.ErrorCode) async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let peer = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        _ = try await freshStore(disk, peer)
        let rpc = try AdoptionPeer(peer: peer, stateURL: disk.url.appending(path: "managed-storage-owner/state.json"))
        rpc.state.withLock { $0.prepareError = code }
        let owner = try adoptionOwner(disk, peer, rpc)
        _ = try await owner.prepareTakeover()
        await Base().fails { _ = try await owner.adoptSurvivingShim(storeLock: lock) }
        #expect(rpc.state.withLock { $0.requests.filter { if case .prepare = $0.body { true } else { false } }.count } == 1)
        #expect(try owner.snapshot().adoptionRetry != nil)
        await owner.close()
    }

    @Test func deadPendingAdoptionIsSupersededWithoutReusingCheckpointNativeIdentity() async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let peer = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        _ = try await freshStore(disk, peer)
        let rpc = try AdoptionPeer(peer: peer, stateURL: disk.url.appending(path: "managed-storage-owner/state.json"))
        var abandoned: StorageLifecycleAdoptionProtocol.Request?
        do {
            let first = try adoptionOwner(disk, peer, rpc)
            _ = try await first.prepareTakeover()
            rpc.state.withLock { $0.dropPrepare = true }
            await Base().fails { _ = try await first.adoptSurvivingShim(storeLock: lock) }
            abandoned = try first.snapshot().adoptionRetry?.request
            await first.close()
        }
        let old = try #require(abandoned)
        let second = try adoptionOwner(disk, peer, rpc, daemon: 11)
        let preparation = try await second.prepareTakeover()
        rpc.state.withLock { $0.dropPrepare = false }
        let adopted = try await second.adoptSurvivingShim(storeLock: lock)
        #expect(adopted.request.id != old.id)
        #expect(adopted.request.daemonUniqueID == 11 && adopted.request.controllerUniqueID == 12)
        #expect(try adopted.request.superseded == old.fenceIdentity)
        #expect(try adopted.request.expectedEpoch == old.epoch)
        #expect(preparation.greeting.expectedEpoch == 1) // controller C is NOT adoption epoch
        let state = try second.snapshot()
        #expect(try ManagedStorageLifecycleCheckpoint.decode(ManagedStorageLifecycleCheckpoint.encode(state)) == state)
        let retry = try #require(state.adoptionRetry)
        var forged = state
        forged.adoptionRetry = .init(status: retry.status, request: old,
            prepareRequestID: retry.prepareRequestID, completeRequestID: retry.completeRequestID)
        #expect(throws: (any Error).self) { try ManagedStorageLifecycleCheckpoint.validate(forged) }
        await second.close()
    }

    @Test(arguments: [false, true])
    func startupRepairsExistingV2RootOnlyAfterReadOnlyValidation(corruptManifest: Bool) async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let peer = try Base.Peer(disk.binding)
        _ = try await freshStore(disk, peer)
        let lock = try CanonicalDataStoreLock(root: disk.url)
        if corruptManifest {
            let directory = try disk.root.openDirectory(named: "managed-storage-owner")
            try directory.replaceRegularFile(named: "manifest.json", data: Data("{}".utf8))
        }
        #expect(fchmod(disk.root.descriptor, 0o755) == 0)
        let contents = try bytes(disk.url)
        let before = try StoragePreflightSnapshot(disk.url)
        #expect(throws: Owner.UnsupportedStoreFormat.self) { try Owner.classify(root: disk.root) }
        if corruptManifest {
            #expect(throws: (any Error).self) {
                _ = try ManagedLifecycleStartupRoot.prepareForStartup(storeLock: lock)
            }
            #expect(try StoragePreflightSnapshot(disk.url) == before)
        } else {
            let repaired = try ManagedLifecycleStartupRoot.prepareForStartup(storeLock: lock)
            #expect(repaired.directory.identity == disk.root.identity)
            try repaired.validate()
            #expect(try Owner.classify(root: repaired.directory) == .existingV2)
        }
        #expect(try bytes(disk.url) == contents)
    }

    @Test func classifyFreshExistingAndRefusesPartialOrV1WithoutMutation() async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        // The fixture already has an initialized backing, but no owner pair.
        #expect(throws: Owner.UnsupportedStoreFormat.self) { try Owner.classify(root: disk.root) }
        let peer = try Base.Peer(disk.binding)
        _ = try await freshStore(disk, peer)
        #expect(try Owner.classify(root: disk.root) == .existingV2)

        for scenario in ["journal-only", "owner-only", "v1-manifest"] {
            let other = try Base.Disk(); defer { other.remove() }
            let fm = FileManager.default, attrs: [FileAttributeKey: Any] = [.posixPermissions: 0o700]
            if scenario != "owner-only" {
                try fm.createDirectory(at: other.url.appending(path: "managed-storage"), withIntermediateDirectories: false, attributes: attrs)
                try Data("{\"schema\":1}".utf8).write(to: other.url.appending(path: "managed-storage/state.json"))
            }
            if scenario != "journal-only" {
                try fm.createDirectory(at: other.url.appending(path: "managed-storage-owner"), withIntermediateDirectories: false, attributes: attrs)
                try Data("{\"version\":\"v1\"}".utf8).write(to: other.url.appending(path: "managed-storage-owner/manifest.json"))
            }
            let before = try StoragePreflightSnapshot(other.url)
            #expect(throws: Owner.UnsupportedStoreFormat.self) { try Owner.classify(root: other.root) }
            #expect(String(describing: Owner.UnsupportedStoreFormat()) == "unsupported storage format; data preserved")
            let peer2 = try Base.Peer(other.binding)
            #expect(throws: (any Error).self) {
                try Owner(isolatedTestExisting: peer2.seam(), root: other.root, backingDescriptor: other.backing, binding: other.binding)
            }
            #expect(try StoragePreflightSnapshot(other.url) == before)
        }
    }

    @Test func validV2TrackingIsAllowedButNFSResidueIsAlwaysRefused() async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let peer = try Base.Peer(disk.binding)
        _ = try await freshStore(disk, peer)
        try disk.root.writeExclusiveRegularFile(named: "volume-storage.json", data: Data("{}".utf8))
        let volumes = try disk.root.createDirectory(named: "volumes")
        try volumes.writeExclusiveRegularFile(named: "tracking", data: Data("v2".utf8))
        let before = try StoragePreflightSnapshot(disk.url)
        #expect(try Owner.classify(root: disk.root) == .existingV2)
        try ManagedLifecycleStartup.preflight(root: disk.root)
        #expect(try StoragePreflightSnapshot(disk.url) == before)
        let infrastructure = try disk.root.openDirectory(named: "infrastructure")
        try infrastructure.writeExclusiveRegularFile(named: "volume-token-secret", data: Data("NFS".utf8))
        let mixed = try StoragePreflightSnapshot(disk.url)
        #expect(throws: Owner.UnsupportedStoreFormat.self) { try ManagedLifecycleStartup.preflight(root: disk.root) }
        #expect(try StoragePreflightSnapshot(disk.url) == mixed)
    }

    @Test(arguments: ["undecodable", "unknown-schema", "symlink"])
    func v2OwnerDoesNotExcuseUnknownJournalFormat(fault: String) async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let peer = try Base.Peer(disk.binding)
        _ = try await freshStore(disk, peer)
        let journal = disk.url.appending(path: "managed-storage")
        let manifest = journal.appending(path: "manifest.json")
        if fault == "symlink" {
            let moved = disk.url.appending(path: "saved-journal")
            try FileManager.default.moveItem(at: journal, to: moved)
            try FileManager.default.createSymbolicLink(at: journal, withDestinationURL: moved)
        } else if fault == "unknown-schema" {
            var value = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: manifest)) as? [String: Any])
            value["schema"] = 99
            try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]).write(to: manifest)
        } else { try Data("partial".utf8).write(to: manifest) }
        let before = try StoragePreflightSnapshot(disk.url)
        #expect(throws: Owner.UnsupportedStoreFormat.self) { try ManagedLifecycleStartup.preflight(root: disk.root) }
        #expect(try StoragePreflightSnapshot(disk.url) == before)
    }

    private func classificationStore(_ disk: Base.Disk, phase: String) async throws {
        let peer = try Base.Peer(disk.binding)
        if phase == "completed" {
            let lock = try CanonicalDataStoreLock(root: disk.url)
            _ = try await ManagedStorageLifecycleResumeOwnerTests().completedStore(disk, peer, lock)
        } else {
            let marker = phase == "admitted" ? try ManagedStorageInitialization.create(in: disk.root,
                binding: disk.binding, provenance: String(repeating: "a", count: 64)) : nil
            _ = try await freshStore(disk, peer)
            try marker?.retain("admitted.json", true)
        }
        #expect(try Owner.classify(root: disk.root) == .existingV2)
    }

    @Test(arguments: ["ordinary", "admitted", "completed"],
        ["owner-state", "owner-lease", "journal-state", "journal-lease", "owner-garbage", "journal-garbage",
         "owner-extra", "journal-extra", "owner-lease-replaced", "journal-lease-replaced", "backing-replaced",
         "raw-legacy", "raw-spent", "storage-intents"])
    func everyV2ClassificationRequiresCompletePhysicalPair(phase: String, fault: String) async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        try await classificationStore(disk, phase: phase)
        let owner = disk.url.appending(path: "managed-storage-owner"), journal = disk.url.appending(path: "managed-storage")
        switch fault {
        case "owner-state", "owner-lease", "journal-state", "journal-lease":
            let directory = fault.hasPrefix("owner") ? owner : journal
            try FileManager.default.removeItem(at: directory.appending(path: fault.hasSuffix("state") ? "state.json" : "lease"))
        case "owner-garbage", "journal-garbage":
            try Data("{}".utf8).write(to: (fault.hasPrefix("owner") ? owner : journal).appending(path: "state.json"))
        case "owner-extra", "journal-extra":
            try Data("keep".utf8).write(to: (fault.hasPrefix("owner") ? owner : journal).appending(path: "unknown"))
        case "owner-lease-replaced", "journal-lease-replaced":
            let directory = fault.hasPrefix("owner") ? owner : journal
            let lease = directory.appending(path: "lease")
            try FileManager.default.moveItem(at: lease, to: disk.url.appending(path: "saved-lease"))
            try Data().write(to: lease)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: lease.path)
        case "backing-replaced":
            let path = disk.url.appending(path: "infrastructure/volumes.ext4")
            try FileManager.default.moveItem(at: path, to: disk.url.appending(path: "saved-backing"))
            try Data(repeating: 0, count: 4096).write(to: path)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        case "raw-legacy", "raw-spent":
            let infrastructure = try disk.root.openDirectory(named: "infrastructure")
            for name in try infrastructure.entryNames() where name.hasPrefix(".raw-init-") &&
                (fault == "raw-legacy" || name.hasSuffix(".initialized.json")) {
                try FileManager.default.removeItem(at: infrastructure.url.appending(path: name))
            }
        default: _ = try disk.root.createDirectory(named: "storage-intents")
        }
        let before = try StoragePreflightSnapshot(disk.url)
        #expect(throws: Owner.UnsupportedStoreFormat.self) { try ManagedLifecycleStartup.preflight(root: disk.root) }
        #expect(try StoragePreflightSnapshot(disk.url) == before)
    }

    @Test(arguments: ["ordinary", "completed"])
    func classificationPreservesSoundRetainedIntentCommitForLaterRecovery(phase: String) async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        try await classificationStore(disk, phase: phase)
        let directory = try disk.root.openDirectory(named: "managed-storage")
        let stateBytes = try #require(try directory.readRegularFile(named: "state.json"))
        let manifestBytes = try #require(try directory.readRegularFile(named: "manifest.json"))
        var next = try JSONDecoder().decode(HostStorageIntents.State.self, from: stateBytes)
        let priorRevision = next.revision
        next.revision += 1
        let nextBytes = try ManagedStorageLifecycleCheckpoint.encode(next)
        typealias Commit = HostStorageIntentCommit
        let proof = Commit.Proof(version: 1, attempt: Base.id(), manifestDigest: Commit.digest(manifestBytes),
            priorRevision: priorRevision, nextRevision: next.revision, priorSHA: Commit.digest(stateBytes),
            nextSHA: Commit.digest(nextBytes), ready: true)
        try directory.writeExclusiveRegularFile(named: Commit.candidateName, data: nextBytes)
        try directory.writeExclusiveRegularFile(named: Commit.proofName, data: Commit.encodeProof(proof))
        let before = try StoragePreflightSnapshot(disk.url)
        #expect(try Owner.classify(root: disk.root) == .existingV2)
        #expect(try StoragePreflightSnapshot(disk.url) == before)
        let recovered = try HostStorageIntents.open(in: disk.root, store: disk.binding.storeID.rawValue,
            provenanceReference: String(repeating: "a", count: 64))
        #expect(try recovered.snapshot().revision == priorRevision)
        #expect(try directory.entryNames() == ["lease", "manifest.json", "state.json"])
    }

    @Test func classificationDoesNotAcquireBackingOrRawInitializationLeases() async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        try await classificationStore(disk, phase: "ordinary")
        let infrastructure = try disk.root.openDirectory(named: "infrastructure")
        let lock = try infrastructure.openRegularFile(named: ".raw-init-volumes.ext4.lock", access: .readOnly)
        defer { try? lock.handle.close(); _ = flock(disk.backing, LOCK_UN) }
        try #require(flock(disk.backing, LOCK_EX | LOCK_NB) == 0)
        try #require(flock(lock.handle.fileDescriptor, LOCK_EX | LOCK_NB) == 0)
        let before = try StoragePreflightSnapshot(disk.url)
        #expect(try Owner.classify(root: disk.root) == .existingV2)
        #expect(try StoragePreflightSnapshot(disk.url) == before)
    }

    @Test func takeoverHappyPathThenRecoveryOnlyAfterFreshQueryAndCensus() async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let peer = try Base.Peer(disk.binding)
        let initial = try await freshStore(disk, peer)
        let owner = try existing(disk, peer), transport = Base.Transport(peer: peer, root: disk.root)
        try await owner.takeover(using: transport, current: current(peer, initial))
        let state = try owner.snapshot()
        let grant = try #require(state.current?.original.signed.grant)
        #expect(grant.operation == .takeover && grant.expectedEpoch == 1)
        #expect(state.pending == nil && state.pendingTakeover == nil && state.currentService?.grant == grant)
        #expect(state.currentContext?.controllerEpoch == 2)
        #expect(transport.commands == [.authorizeSuccessor, .reconcileController])
        #expect(peer.state.withLock { $0.binds == 1 && $0.childTakeovers == 1 && $0.takeoverIssues == 1 })
        // Checkpoint metadata and a bare connect never mint recovery.
        #expect(!owner.hasRecoveryPermission)
        try await owner.connectWorkload()
        #expect(!owner.hasRecoveryPermission)
        // Even a valid diagnostic Query is not the owner's sealed recovery proof.
        _ = try await owner.queryWorkload()
        #expect(!owner.hasRecoveryPermission)
        #expect(throws: (any Error).self) { try owner.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator()) }
        try await owner.recoverWorkload()
        #expect(owner.hasRecoveryPermission)
        _ = try owner.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator())
        await owner.close()
    }

    @Test func invalidReconcileReplyCannotCompleteEvenThroughExplicitRetry() async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let peer = try Base.Peer(disk.binding)
        let initial = try await freshStore(disk, peer)
        let owner = try existing(disk, peer), transport = Base.Transport(peer: peer, root: disk.root)
        transport.readyOverride = try peer.initialReady(initial) // stale C/key, otherwise valid Ready
        let completions = peer.state.withLock { $0.completions }
        await Base().fails { try await owner.takeover(using: transport, current: self.current(peer, initial)) }
        #expect(transport.commands == [.authorizeSuccessor, .reconcileController])
        #expect(peer.state.withLock { $0.completions } == completions)
        #expect(try owner.snapshot().pending?.signed.grant.operation == .takeover)
        await Base().fails { try await owner.complete() }
        #expect(peer.state.withLock { $0.completions } == completions)
        #expect(!owner.hasRecoveryPermission)
        await owner.close()
    }

    @Test func lostIssueReplyRetriesSameDurableTupleWithoutSecondGrant() async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let peer = try Base.Peer(disk.binding)
        let initial = try await freshStore(disk, peer)
        let owner = try existing(disk, peer), transport = Base.Transport(peer: peer, root: disk.root)
        peer.state.withLock { $0.dropIssueReply = true }
        await Base().fails { try await owner.takeover(using: transport, current: self.current(peer, initial)) }
        let tuple = try #require(owner.snapshot().pendingTakeover)
        #expect(try owner.snapshot().pending == nil && transport.commands.isEmpty)
        #expect(peer.state.withLock { $0.binds } == 0)
        peer.state.withLock { $0.dropIssueReply = false }
        try await owner.takeover(using: transport, current: current(peer, initial))
        let requests = takeoverRequests(peer)
        #expect(requests.count == 2 && requests[0] == requests[1])
        #expect(requests[0].requestID.rawValue == tuple.requestID)
        #expect(peer.state.withLock { $0.takeoverIssues } == 1)
        #expect(try owner.snapshot().current?.original.signed.grant.id == tuple.grantID)
        await owner.close()
    }

    @Test func rootRefusalWhenPredecessorNotExitedFailsClosedWithoutGuestMutation() async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let peer = try Base.Peer(disk.binding)
        let initial = try await freshStore(disk, peer)
        let owner = try existing(disk, peer), transport = Base.Transport(peer: peer, root: disk.root)
        let before = try owner.snapshot()
        peer.state.withLock { $0.refuseTakeover = true }
        await Base().fails { try await owner.takeover(using: transport, current: self.current(peer, initial)) }
        let after = try owner.snapshot()
        #expect(after.pending == nil && after.current == before.current && after.currentService == before.currentService)
        #expect(transport.commands.isEmpty && peer.state.withLock { $0.binds == 0 && $0.childTakeovers == 0 })
        await owner.close()
    }

    @Test(arguments: ["forged", "epoch", "id", "recipient"])
    func staleOrWrongGrantIsRejectedBeforeStagingOrGuestIO(_ fault: String) async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let peer = try Base.Peer(disk.binding)
        let initial = try await freshStore(disk, peer)
        let owner = try existing(disk, peer), transport = Base.Transport(peer: peer, root: disk.root)
        peer.state.withLock { $0.takeoverGrantFault = fault }
        await Base().fails { try await owner.takeover(using: transport, current: self.current(peer, initial)) }
        #expect(try owner.snapshot().pending == nil)
        #expect(try owner.snapshot().current?.original.signed.grant == initial)
        #expect(transport.commands.isEmpty && peer.state.withLock { $0.binds } == 0)
        await owner.close()
    }

    @Test func untrustedCurrentReadyMustMatchCheckpointedService() async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let peer = try Base.Peer(disk.binding)
        let initial = try await freshStore(disk, peer)
        let owner = try existing(disk, peer), transport = Base.Transport(peer: peer, root: disk.root)
        let wrong = ManagedStorageLifecycleServiceReady(binding: peer.bootBinding, ready: peer.successor(initial, openRevision: 1))
        await Base().fails { try await owner.takeover(using: transport, current: wrong) }
        #expect(try owner.snapshot().pendingTakeover == nil && takeoverRequests(peer).isEmpty)
        await owner.close()
    }

    @Test(arguments: ["changed", "damaged", "query"])
    func recoveryRefusesChangedCensusIncompleteJournalOrBadQuery(_ scenario: String) async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let peer = try Base.Peer(disk.binding)
        let initial = try await freshStore(disk, peer)
        var holder: Owner?
        let owner = try existing(disk, peer, afterWorkloadDecode: { @MainActor in
            switch scenario {
            case "changed": try holder?.isolatedTestIntents?.reconciled()
            case "damaged": try Data("uncertain".utf8).write(to: disk.url.appending(path: "managed-storage/state.json"))
            default: break
            }
        })
        holder = owner
        try await owner.takeover(using: Base.Transport(peer: peer, root: disk.root), current: current(peer, initial))
        if scenario == "query" { peer.state.withLock { $0.wrongWorkloadIdentity = true } }
        await Base().fails { try await owner.recoverWorkload() }
        #expect(!owner.hasRecoveryPermission)
        #expect(throws: (any Error).self) { try owner.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator()) }
        holder = nil
        await owner.close()
    }

    @Test func classifyPropagatesIOErrorsAndRefusesUndecodableManifestWithoutMutation() async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let peer = try Base.Peer(disk.binding)
        _ = try await freshStore(disk, peer)
        let owner = disk.url.appending(path: "managed-storage-owner")
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: owner.path)
        do {
            defer { try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: owner.path) }
            #expect(throws: Owner.StoreUnavailable.self) { try Owner.classify(root: disk.root) }
        }
        #expect(try Owner.classify(root: disk.root) == .existingV2)
        let manifest = owner.appending(path: "manifest.json")
        let original = try Data(contentsOf: manifest)
        try Data(original.prefix(original.count / 2)).write(to: manifest)
        let before = try bytes(disk.url)
        #expect(throws: Owner.UnsupportedStoreFormat.self) { try Owner.classify(root: disk.root) }
        #expect(try bytes(disk.url) == before)
    }

    @Test func stagedRetirePendingGrantBlocksTakeoverFailClosed() async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let peer = try Base.Peer(disk.binding)
        // Separate scope: the fresh owner must be released so its lease drops.
        func stageFreshRetire() async throws -> L.Grant {
            let fresh = try disk.owner(peer)
            try await fresh.provisionFresh()
            try await fresh.bootFresh(using: Base.Transport(peer: peer, root: disk.root), expectedBinding: peer.bootBinding,
                nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
            let initial = try #require(fresh.snapshot().current?.original.signed.grant)
            try await fresh.stageRetire()
            #expect(try fresh.snapshot().pending?.signed.grant.operation == .retire)
            await fresh.close()
            return initial
        }
        let initial = try await stageFreshRetire()
        peer.state.withLock { $0.binds = 0 }
        let owner = try existing(disk, peer), transport = Base.Transport(peer: peer, root: disk.root)
        let before = try owner.snapshot()
        await Base().fails { try await owner.takeover(using: transport, current: self.current(peer, initial)) }
        #expect(try owner.snapshot() == before)
        #expect(takeoverRequests(peer).isEmpty && transport.commands.isEmpty)
        #expect(peer.state.withLock { $0.binds == 0 && $0.childTakeovers == 0 })
        await owner.close()
    }

    @Test func checkpointRejectsSupersetHistoryEvenWithGenuineOldGrant() async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let peer = try Base.Peer(disk.binding)
        let initial = try await freshStore(disk, peer)
        let owner = try existing(disk, peer)
        let before = try owner.snapshot()
        try await owner.takeover(using: Base.Transport(peer: peer, root: disk.root), current: current(peer, initial))
        let after = try owner.snapshot()
        let old = try #require(before.contexts.first)
        #expect(!after.contexts.contains(old))
        var forged = after
        forged.contexts.append(old) // ROOT-signed initialize grant + its unsigned receipt.
        #expect(throws: (any Error).self) { try ManagedStorageLifecycleCheckpoint.validate(forged) }
        let encoded = try ManagedStorageLifecycleCheckpoint.encode(forged)
        #expect(throws: (any Error).self) { try ManagedStorageLifecycleCheckpoint.decode(encoded) }
        _ = try ManagedStorageLifecycleCheckpoint.decode(ManagedStorageLifecycleCheckpoint.encode(after))
        await owner.close()
    }

    @Test func recoveryHistoryRequiresGuestAndRootAttestation() async throws {
        typealias C = ManagedStorageLifecycleCheckpoint.Context
        let disk = try Base.Disk(); defer { disk.remove() }
        let peer = try Base.Peer(disk.binding)
        let initial = try await freshStore(disk, peer)
        let owner = try existing(disk, peer)
        let predecessor = try #require(owner.snapshot().currentContext)
        try await owner.takeover(using: Base.Transport(peer: peer, root: disk.root), current: current(peer, initial))
        let state = try owner.snapshot()
        let live = try #require(state.currentContext), grant = try #require(state.current?.original.signed.grant)
        let context = try ManagedStorageControlClient.Context(store: state.identity.store, serviceEpoch: live.serviceEpoch,
            controllerEpoch: live.controllerEpoch, controllerKey: live.controllerKey,
            provenanceReference: state.provenanceReference, lifecycleIdentity: state.identity)
        func query(epoch: String = live.serviceEpoch, controller: UInt64 = live.controllerEpoch,
                   owning: [C] = []) -> ManagedStorageControlClient.Snapshot {
            let prepares = Dictionary(uniqueKeysWithValues: owning.map { c in
                let id = Base.id()
                return (id, ManagedStorageControlClient.Prepare(id: id, attachments: [], phase: .pending, successor: nil,
                    attestation: nil, context: .init(serviceEpoch: c.serviceEpoch, controllerEpoch: c.controllerEpoch,
                    controllerKey: c.controllerKey)))
            })
            return .init(schema: 4, revision: 1, store: .init(id: state.identity.store, deviceID: "dev", root: .init(device: 1, inode: 2),
                exports: .init(device: 1, inode: 3)), epoch: epoch, controller: .init(epoch: controller, key: live.controllerKey),
                volumes: [:], volumeLifecycles: [:], attachments: [:], prepares: prepares)
        }
        // Genuine old grant key, fabricated unsigned receipt service epoch.
        let forged = C(serviceEpoch: Base.id(), controllerEpoch: predecessor.controllerEpoch, controllerKey: predecessor.controllerKey)
        func history(_ required: Set<C>, held: [C]? = nil, query q: ManagedStorageControlClient.Snapshot? = nil,
                     predecessor p: C?? = .none) throws -> [C] {
            try Owner.attestedHistory(required: required, held: held ?? Array(required), current: live, takeover: grant,
                query: q ?? query(), context: context, predecessor: p ?? predecessor)
        }
        #expect(try history([live]) == [])
        #expect(try history([live, predecessor]) == [predecessor])
        #expect(throws: (any Error).self) { try history([live, predecessor, forged]) }
        #expect(throws: (any Error).self) { try history([live, forged]) }
        #expect(throws: (any Error).self) { try history([live, predecessor], held: [live, predecessor, forged]) }
        #expect(throws: (any Error).self) { try history([live, predecessor], predecessor: .some(nil)) }
        #expect(throws: (any Error).self) { try history([live], query: query(epoch: forged.serviceEpoch)) }
        #expect(throws: (any Error).self) { try history([live], query: query(controller: predecessor.controllerEpoch)) }
        // Intent reserved under E1/C1, then same-C service change (E2), then takeover:
        // the E1/C1 context is admitted ONLY when the fresh Guest Query attests it.
        let e1c1 = C(serviceEpoch: Base.id(), controllerEpoch: predecessor.controllerEpoch, controllerKey: predecessor.controllerKey)
        #expect(throws: (any Error).self) { try history([live, predecessor, e1c1]) }
        #expect(try history([live, predecessor, e1c1], query: query(owning: [e1c1, live])).count == 2)
        #expect(try history([live, e1c1], query: query(owning: [e1c1]), predecessor: .some(nil)) == [e1c1])
        // Attestation of a DIFFERENT old context never admits the forged one.
        #expect(throws: (any Error).self) { try history([live, predecessor, forged], query: query(owning: [e1c1])) }
        #expect(throws: (any Error).self) { try history([live, forged], query: query(owning: [e1c1]), predecessor: .some(nil)) }
        // Attested-but-unrequired contexts are never added to recovery.
        #expect(try history([live, predecessor], query: query(owning: [e1c1, forged])) == [predecessor])
        // Plain attested history values are not a sealed recovery permission.
        #expect(!owner.hasRecoveryPermission)
        #expect(throws: (any Error).self) { try owner.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator()) }
        // End-to-end happy path still mints recovery from the attested set only.
        try await owner.recoverWorkload()
        #expect(owner.hasRecoveryPermission)
        await owner.close()
    }

    @Test func restartAfterPartialTakeoverResumesPendingGrantExactly() async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let peer = try Base.Peer(disk.binding)
        let initial = try await freshStore(disk, peer)
        var staleGrant: L.Grant?
        do {
            let first = try existing(disk, peer, daemon: 9)
            peer.state.withLock { $0.failComplete = true }
            await Base().fails { try await first.takeover(using: Base.Transport(peer: peer, root: disk.root), current: self.current(peer, initial)) }
            let pending = try #require(first.snapshot().pending)
            #expect(try pending.signed.grant.operation == .takeover && first.snapshot().current?.original.signed.grant == initial)
            staleGrant = pending.signed.grant
            // A second attempt on the same owner never repeats Guest mutation.
            await Base().fails { try await first.takeover(using: Base.Transport(peer: peer, root: disk.root), current: self.current(peer, initial)) }
            #expect(peer.state.withLock { $0.binds == 1 && $0.childTakeovers == 1 })
            await first.close()
        }
        peer.state.withLock { $0.failComplete = false }
        let stale = try #require(staleGrant)
        // Restarted daemon: completes the exact pending grant ID, then takes over from it.
        let second = try existing(disk, peer, epoch: 2, daemon: 11)
        try await second.takeover(using: Base.Transport(peer: peer, root: disk.root), current: current(peer, stale))
        let completes = peer.state.withLock { $0.requests.compactMap { if case .complete(_, let id) = $0.body { id } else { nil } } }
        #expect(completes.contains(stale.id))
        let state = try second.snapshot()
        let grant = try #require(state.current?.original.signed.grant)
        #expect(grant.operation == .takeover && grant.expectedEpoch == 2 && grant.id != stale.id)
        #expect(state.currentContext?.controllerEpoch == 3 && state.pending == nil)
        #expect(peer.state.withLock { $0.takeoverIssues } == 2)
        await second.close()
    }
}
#endif

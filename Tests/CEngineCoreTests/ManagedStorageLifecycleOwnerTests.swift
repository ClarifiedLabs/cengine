#if os(macOS) && DEBUG
import CEngineCore
import CryptoKit
import Darwin
import Foundation
import Synchronization
import Testing
@testable import CEngineRuntime

/// ISOLATED NON-NATIVE owner/transport and physical journal tests. These do not
/// authenticate ROOT/child/shim, boot VZ, establish recovery, or qualify power loss.
@Suite(.serialized) @MainActor struct ManagedStorageLifecycleOwnerTests {
    typealias Owner = ManagedStorageLifecycleOwner
    typealias L = StorageLifecycleProtocol
    typealias R = StorageLifecycleRootProtocol
    typealias W = StorageLifecycleServiceBootProtocol

    @Test func lostProvisionReplyRecoversSamePersistedGrantWithDescriptorFreeSecondCall() async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding), owner = try disk.owner(peer)
        let transport = Transport(peer: peer, root: disk.root)
        peer.state.withLock { $0.dropProvisionReply = true }
        await fails { try await owner.provisionFresh() }
        let attach = try #require(owner.attemptedProvision)
        let probe = try #require(peer.state.withLock { $0.requests.first })
        #expect(probe == (try Self.provisionEnvelope(attach, initialDescriptors: false)))
        #expect(peer.state.withLock { $0.requests } == [probe, attach])
        let persisted = try #require(peer.state.withLock { $0.grants.values.first })
        #expect(persisted.isValidSignature(using: peer.rootKey))
        #expect(peer.state.withLock { $0.allocations == 1 && $0.childActions == 0 })
        #expect(try disk.root.entryMetadata(named: "managed-storage-owner") == nil)
        #expect(try disk.root.entryMetadata(named: "managed-storage") == nil)
        await fails { try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600) }
        #expect(transport.configurations == 0)
        try await owner.provisionFresh()
        #expect(owner.attemptedProvision == probe)
        #expect(peer.state.withLock { $0.requests } == [probe, attach, probe])
        #expect(peer.state.withLock { $0.allocations == 1 && $0.descriptorResends == 0 && $0.childActions == 0 })
        let pending = try #require(owner.snapshot().pending)
        #expect(pending.signed.grant == persisted.grant)
        #expect(pending.signed.isValidSignature(using: peer.rootKey))
        #expect(pending.requestID == probe.requestID.rawValue)
        #expect(pending.signed.grant.id != probe.requestID.rawValue) // Grant ID is not the RPC ID.
        #expect(try owner.snapshot().current == nil)
        try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        #expect(transport.sawPhysicalPendingAndIntents)
        await owner.close()
        #expect(try disk.root.entryMetadata(named: "disk") != nil)
    }

    @Test func statefulRootSeamRejectsDescriptorResendAfterPersistedLostReply() async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding), owner = try disk.owner(peer)
        peer.state.withLock { $0.dropProvisionReply = true }
        await fails { try await owner.provisionFresh() }
        let attach = try #require(owner.attemptedProvision)
        let rootFD = disk.root.descriptor, backingFD = disk.backing
        let reply = try await Task.detached { try peer.request(attach, rootFD, backingFD) }.value
        #expect(reply.body == .failure(.conflict))
        #expect(peer.state.withLock { $0.allocations == 1 && $0.descriptorResends == 1 })
        await owner.close()
    }

    @Test func uncertainProbeNeverAttachesOnLaterMissingInitialReply() async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding), owner = try disk.owner(peer)
        peer.state.withLock { $0.failProbe = true }
        await fails { try await owner.provisionFresh() }
        let probe = try #require(owner.attemptedProvision)
        #expect(!probe.requiresDescriptors)
        peer.state.withLock { $0.failProbe = false }
        await fails { try await owner.provisionFresh() }
        await fails { try await owner.provisionFresh() }
        #expect(peer.state.withLock { $0.requests } == [probe, probe, probe])
        #expect(peer.state.withLock { $0.allocations == 0 })
        #expect(try disk.root.entryMetadata(named: "managed-storage-owner") == nil)
        await owner.close()
    }

    @Test func uncorrelatedClientInvalidRequestNeverPermitsDescriptorAttach() async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding), owner = try disk.owner(peer)
        peer.state.withLock { $0.clientInvalidRequest = true }
        await fails { try await owner.provisionFresh() }
        let probe = try #require(owner.attemptedProvision)
        #expect(!probe.requiresDescriptors)
        #expect(peer.state.withLock { $0.requests } == [probe])
        peer.state.withLock { $0.clientInvalidRequest = false }
        await fails { try await owner.provisionFresh() }
        #expect(peer.state.withLock { $0.requests } == [probe, probe])
        #expect(peer.state.withLock { $0.allocations == 0 })
        #expect(try disk.root.entryMetadata(named: "managed-storage-owner") == nil)
        await owner.close()
    }

    @Test func blockedAndConflictProbeRepliesNeverTriggerAttachOrSilentRetry() async throws {
        for code in [StorageIdentity.ErrorCode.blocked, .conflict] {
            let disk = try Disk(); defer { disk.remove() }
            let peer = try Peer(disk.binding), owner = try disk.owner(peer)
            peer.state.withLock { $0.probeFailure = code }
            await fails { try await owner.provisionFresh() }
            let probe = try #require(owner.attemptedProvision)
            #expect(peer.state.withLock { $0.requests } == [probe])
            await fails { try await owner.provisionFresh() }
            #expect(peer.state.withLock { $0.requests } == [probe, probe])
            #expect(peer.state.withLock { $0.allocations == 0 })
            await owner.close()
        }
    }

    @Test func provisionRepliesMustCorrelateToActualProbeOrAttachEnvelope() async throws {
        for corruptProbe in [true, false] {
            let disk = try Disk(); defer { disk.remove() }
            let peer = try Peer(disk.binding), owner = try disk.owner(peer)
            peer.state.withLock { $0.wrongProbeEnvelope = corruptProbe; $0.wrongAttachEnvelope = !corruptProbe }
            await fails { try await owner.provisionFresh() }
            #expect(peer.state.withLock { $0.requests.count } == (corruptProbe ? 1 : 2))
            #expect(try disk.root.entryMetadata(named: "managed-storage-owner") == nil)
            peer.state.withLock { $0.wrongProbeEnvelope = false; $0.wrongAttachEnvelope = false }
            if corruptProbe { await fails { try await owner.provisionFresh() } }
            else { try await owner.provisionFresh() }
            #expect(peer.state.withLock { $0.requests.count } == (corruptProbe ? 2 : 3))
            #expect(peer.state.withLock { $0.allocations } == (corruptProbe ? 0 : 1))
            await owner.close()
        }
    }

    @Test func checkpointOnlyPartialCreationRequiresRepairAndNeverBootsOrReinitializes() async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding)
        let owner = try disk.owner(peer, afterCheckpointFresh: { throw Owner.Failure.repairRequired })
        await fails { try await owner.provisionFresh() }
        let pending = try #require(owner.snapshot().pending)
        #expect(try disk.root.entryMetadata(named: "managed-storage-owner") != nil)
        #expect(try disk.root.entryMetadata(named: "managed-storage") == nil)
        let requestCount = peer.state.withLock { $0.requests.count }
        do {
            try await owner.provisionFresh(); Issue.record("partial creation was treated as ready")
        } catch Owner.Failure.repairRequired { } catch { Issue.record("expected repairRequired, got \(error)") }
        let transport = Transport(peer: peer, root: disk.root)
        await fails { try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600) }
        #expect(transport.configurations == 0)
        #expect(peer.state.withLock { $0.requests.count == requestCount && $0.childActions == 0 })
        #expect(try owner.snapshot().pending == pending)
        await owner.close()
        #expect(throws: (any Error).self) { _ = try disk.owner(peer) }
        #expect(try disk.root.entryMetadata(named: "managed-storage-owner") != nil)
        #expect(try disk.root.entryMetadata(named: "managed-storage") == nil)
        #expect(try disk.root.entryMetadata(named: "disk") != nil)
    }

    @Test func preexistingIntentDirectoryRefusesFreshOwnerWithoutNativeIO() throws {
        let disk = try Disk(); defer { disk.remove() }
        _ = try disk.root.createDirectory(named: "managed-storage")
        let peer = try Peer(disk.binding)
        #expect(throws: (any Error).self) { _ = try disk.owner(peer) }
        #expect(peer.state.withLock { $0.requests.isEmpty })
    }

    @Test func unsignedReadyAndTransportFailureNeverCompleteOrRetryGuestMutation() async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding), owner = try disk.owner(peer)
        try await owner.provisionFresh()
        let transport = Transport(peer: peer, root: disk.root)
        transport.failCommand = true
        await fails { try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600) }
        #expect(transport.sawPhysicalPendingAndIntents)
        #expect(try owner.snapshot().pending?.signed.grant.operation == .initialize)
        #expect(try owner.snapshot().current == nil)
        #expect(peer.state.withLock { $0.completions == 0 })
        await fails { try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600) }
        #expect(transport.configurations == 1)
        await owner.close()
    }

    @Test func mismatchedBootBindingOrFullIdentityRefusesUnsignedReady() async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding), owner = try disk.owner(peer)
        try await owner.provisionFresh()
        let grant = try #require(owner.snapshot().pending?.signed.grant)
        var altered = peer.bootBinding; altered.guestBootNonce = Self.id()
        let valid = try peer.ready(grant)
        #expect(throws: (any Error).self) { try Owner.validate(.init(binding: altered, ready: valid), binding: peer.bootBinding, grant: grant, root: peer.rootKey) }
        let other = try L.Grant(operation: .initialize, id: grant.id,
            identity: .init(store: grant.identity.store, generation: 2, binding: grant.identity.binding), serial: 1, expectedEpoch: 0, newKey: grant.newKey)
        #expect(throws: (any Error).self) { try Owner.validate(.init(binding: peer.bootBinding, ready: peer.ready(other)), binding: peer.bootBinding, grant: grant, root: peer.rootKey) }
        await owner.close()
    }

    @Test func completionAlwaysRechallengesAndRejectsDifferentGrant() async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding), owner = try disk.owner(peer)
        try await owner.provisionFresh()
        let pending = try #require(owner.snapshot().pending)
        peer.state.withLock { $0.wrongGrant = true }
        await fails { try await owner.complete() }
        #expect(try owner.snapshot().pending == pending)
        peer.state.withLock { $0.wrongGrant = false }
        try await owner.complete()
        let first = try owner.snapshot()
        try await owner.complete()
        #expect(peer.state.withLock { $0.completions == 3 })
        #expect(try owner.snapshot() == first) // Fresh nonce is not a new durable result.
        #expect(first.observedWorker == nil) // Metadata-only completion has no actual worker.
        peer.state.withLock { $0.failComplete = true }
        await fails { try await owner.complete() }
        #expect(try owner.snapshot() == first)
        await owner.close()
    }

    @Test func failedCompletionPublicationPoisonsWithoutDroppingIDsOrFiles() async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding)
        let owner = try disk.owner(peer, hook: { step, moment in
            if step == .statePublish, case .before = moment { throw Owner.Failure.incomplete }
        })
        try await owner.provisionFresh()
        let request = owner.attemptedProvision
        await fails { try await owner.complete() }
        #expect(throws: (any Error).self) { _ = try owner.snapshot() }
        #expect(owner.attemptedProvision == request)
        let directory = try disk.root.openDirectory(named: "managed-storage-owner")
        #expect(try directory.entryNames().contains("uncertain"))
        await owner.close()
        #expect(try disk.root.entryMetadata(named: "disk") != nil)
    }

    @Test func authenticatedReclaimNotUnsignedRetirementAckControlsTerminalMetadata() async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding), owner = try disk.owner(peer)
        try await owner.provisionFresh()
        let transport = Transport(peer: peer, root: disk.root)
        try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        try await owner.stageRetire()
        let pending = try #require(owner.snapshot().pending)
        peer.state.withLock { $0.failComplete = true }
        await fails { try await owner.seal() }
        #expect(try owner.snapshot().pending == pending)
        #expect(try owner.snapshot().sealed == nil)
        peer.state.withLock { $0.failComplete = false }
        try await owner.seal()
        #expect(try owner.snapshot().sealed != nil)
        #expect(try owner.snapshot().terminal == nil)
        peer.state.withLock { $0.failReclaim = true }
        await fails { try await owner.reclaim() }
        #expect(try owner.snapshot().terminal == nil)
        peer.state.withLock { $0.failReclaim = false }
        try await owner.reclaim()
        #expect(try owner.snapshot().terminal == owner.snapshot().sealed)
        let requests = peer.state.withLock { $0.requests }
        await fails { try await owner.connectWorkload() }
        #expect(transport.workloadConnections == 0)
        #expect(peer.state.withLock { $0.requests } == requests)
        #expect(try disk.root.entryMetadata(named: "disk") != nil)
        await owner.close()
    }

    @Test func delayedRootDoesNotBlockMainActorAndCancellationNeverPublishes() async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding), owner = try disk.owner(peer)
        try await owner.provisionFresh()
        let replyGate = ReplyGate()
        defer { replyGate.release.signal() }
        peer.state.withLock { $0.replyGate = replyGate }
        let task = Task {
            defer { replyGate.prepared.continuation.finish() }
            try await owner.complete()
        }
        var replyPrepared = false
        for await _ in replyGate.prepared.stream { replyPrepared = true; break }
        try #require(replyPrepared)
        #expect(peer.state.withLock { $0.completions } == 1)
        #expect(try owner.snapshot().current == nil) // MainActor serviced while ROOT worker waits.
        task.cancel()
        #expect(task.isCancelled)
        // Deliver the real completed ROOT reply only after cancellation, not
        // after a sleep that can finish before MainActor resumes under load.
        replyGate.release.signal()
        await fails { try await task.value }
        #expect(try owner.snapshot().current == nil)
        #expect(try owner.snapshot().pending != nil)
        let requests = peer.state.withLock { $0.requests }
        await fails { try await owner.complete() }
        await fails { try await owner.provisionFresh() }
        await fails { try await owner.connectWorkload() }
        #expect(peer.state.withLock { $0.requests } == requests)
        await owner.close()
    }

    @Test func connectWorkloadRequiresFreshRootLiveResultBeforeEveryTransportConnect() async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding), owner = try disk.owner(peer)
        try await owner.provisionFresh()
        let transport = Transport(peer: peer, root: disk.root)
        try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        #expect(try owner.snapshot().observedWorker == nil)
        peer.state.withLock { $0.failServiceResult = true; $0.workloadEvents = [] }
        await fails { try await owner.connectWorkload() }
        #expect(try owner.snapshot().observedWorker == nil)
        #expect(transport.workloadConnections == 0)
        #expect(peer.state.withLock { $0.workloadEvents } == ["root-live"])
        peer.state.withLock { $0.failServiceResult = false; $0.wrongLiveRevision = true }
        await fails { try await owner.connectWorkload() }
        #expect(try owner.snapshot().observedWorker == nil)
        #expect(transport.workloadConnections == 0)
        peer.state.withLock { $0.wrongLiveRevision = false; $0.workloadEvents = [] }
        try await owner.connectWorkload()
        let observed = try owner.snapshot()
        #expect(observed.observedWorker?.context == observed.currentContext)
        #expect(observed.observedWorker?.workerUUID == peer.workerUUID)
        try await owner.connectWorkload()
        #expect(try owner.snapshot() == observed) // No revision churn for the same fresh observation.
        #expect(transport.workloadConnections == 2)
        #expect(peer.state.withLock { $0.workloadEvents } == ["root-live", "transport", "child", "root-live", "transport", "child"])
        await owner.close()
    }

    @Test func workloadQueryUsesFullLifecycleContextAndCannotRunBeforeConnectOrDuringRetirement() async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding), owner = try disk.owner(peer)
        try await owner.provisionFresh()
        await fails { _ = try await owner.queryWorkload() }
        let transport = Transport(peer: peer, root: disk.root)
        try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        await fails { _ = try await owner.queryWorkload() }
        try await owner.connectWorkload()
        let snapshot = try await owner.queryWorkload()
        #expect(snapshot.schema == 4)
        #expect(snapshot.epoch == peer.serviceEpoch)
        #expect(peer.state.withLock { $0.workloadEvents.filter { $0 == "query" }.count } == 1)
        try await owner.stageRetire()
        await fails { _ = try await owner.queryWorkload() }
        #expect(peer.state.withLock { $0.workloadEvents.filter { $0 == "query" }.count } == 1)
        await owner.close()
    }

    @Test(arguments: ["owner-before", "intents-before", "owner-after", "intents-after", "cancel", "wrong-identity"])
    func workloadRechecksPhysicalJournalsAndFencesLateOrWrongReplies(_ scenario: String) async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding), owner = try disk.owner(peer)
        try await owner.provisionFresh()
        let transport = Transport(peer: peer, root: disk.root)
        try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        try await owner.connectWorkload()
        func damage() throws {
            let directory = disk.url.appending(path: scenario.hasPrefix("owner") ? "managed-storage-owner" : "managed-storage")
            try Data("uncertain".utf8).write(to: directory.appending(path: "unexpected"))
        }
        if scenario.hasSuffix("before") {
            try damage()
            await fails { _ = try await owner.queryWorkload() }
            #expect(peer.state.withLock { !$0.workloadEvents.contains("query") })
        } else {
            let gate = ReplyGate()
            defer { gate.release.signal() }
            peer.state.withLock { $0.workloadGate = gate; $0.wrongWorkloadIdentity = scenario == "wrong-identity" }
            let task = Task {
                defer { gate.prepared.continuation.finish() }
                return try await owner.queryWorkload()
            }
            var prepared = false
            for await _ in gate.prepared.stream { prepared = true; break }
            try #require(prepared)
            // While awaiting child IO the owner cannot overlap a retirement.
            await fails { try await owner.stageRetire() }
            if scenario == "cancel" { task.cancel() }
            else if scenario != "wrong-identity" { try damage() }
            gate.release.signal()
            await fails { _ = try await task.value }
            await fails { _ = try await owner.queryWorkload() }
            #expect(peer.state.withLock { $0.workloadEvents.filter { $0 == "query" }.count } == 1)
        }
        #expect(try disk.root.entryMetadata(named: "disk") != nil)
        await owner.close()
    }

    @Test func cancellationAfterDecodeFencesPublicationAndFutureQueries() async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding)
        let decoded = AsyncStream<Void>.makeStream(), release = AsyncStream<Void>.makeStream()
        defer { release.continuation.finish() }
        let owner = try disk.owner(peer, afterWorkloadDecode: {
            decoded.continuation.yield(()); decoded.continuation.finish()
            for await _ in release.stream { break }
        })
        try await owner.provisionFresh()
        let transport = Transport(peer: peer, root: disk.root)
        try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        try await owner.connectWorkload()
        let task = Task {
            defer { decoded.continuation.finish() }
            return try await owner.queryWorkload()
        }
        var reached = false
        for await _ in decoded.stream { reached = true; break }
        try #require(reached)
        task.cancel()
        release.continuation.finish()
        await fails { _ = try await task.value }
        await fails { _ = try await owner.queryWorkload() }
        await fails { try await owner.connectWorkload() }
        #expect(peer.state.withLock { $0.workloadEvents.filter { $0 == "query" }.count } == 1)
        await owner.close()
    }

    @Test func cancellationAfterConnectionValidationNeverAdmitsWorkload() async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding)
        let validated = AsyncStream<Void>.makeStream(), release = AsyncStream<Void>.makeStream()
        defer { release.continuation.finish() }
        let owner = try disk.owner(peer, beforeWorkloadConnectionPublication: {
            validated.continuation.yield(()); validated.continuation.finish()
            for await _ in release.stream { break }
        })
        try await owner.provisionFresh()
        let transport = Transport(peer: peer, root: disk.root)
        try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        let task = Task {
            defer { validated.continuation.finish() }
            try await owner.connectWorkload()
        }
        var reached = false
        for await _ in validated.stream { reached = true; break }
        try #require(reached)
        task.cancel(); release.continuation.finish()
        await fails { try await task.value }
        await fails { _ = try await owner.queryWorkload() }
        await fails { try await owner.connectWorkload() }
        #expect(transport.cancelled.withLock { $0 })
        #expect(peer.state.withLock { !$0.workloadEvents.contains("query") })
        await owner.close()
    }

    @Test func closeInterruptsSuspendedUntrustedTransportWithoutClearingPending() async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding), owner = try disk.owner(peer)
        try await owner.provisionFresh()
        let transport = Transport(peer: peer, root: disk.root)
        transport.suspendConfigure = true
        let task = Task { try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600) }
        try await Task.sleep(for: .milliseconds(30))
        await owner.close()
        await fails { try await task.value }
        #expect(transport.cancelled.withLock { $0 })
        #expect(try owner.snapshot().pending != nil)
        #expect(try owner.snapshot().current == nil)
    }

    @Test func serviceStageIsDurableBeforeRootAndConfigureAndLostReplyKeepsExactTuple() async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding), owner = try disk.owner(peer)
        try await owner.provisionFresh()
        let first = Transport(peer: peer, root: disk.root)
        try await owner.bootFresh(using: first, expectedBinding: peer.bootBinding, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        #expect(peer.state.withLock { Array($0.workloadEvents.suffix(3)) } == ["root", "root-boot", "root-live"])
        try await owner.connectWorkload()
        let before = try owner.snapshot(), operationID = Self.id()
        peer.state.withLock { $0.dropStageReply = true }
        await fails { try await owner.stageServiceChange(operationID: operationID, nowUnixSeconds: 1_800_000_100, lifetimeSeconds: 1800) }
        let pending = try #require(owner.snapshot().pendingService)
        #expect(pending.request.operationID == operationID)
        #expect(pending.request.predecessor == before.currentService)
        #expect(pending.nowUnixSeconds == 1_800_000_100 && pending.lifetimeSeconds == 1800)
        #expect(try peer.physicalPending(peer.state.withLock { $0.ownerStateURL }) == pending)
        #expect(peer.state.withLock { $0.sawDurableStage })
        let requests = peer.state.withLock { $0.requests }
        for (id, now, lifetime) in [(Self.id(), UInt64(1_800_000_100), UInt64(1800)),
                                     (operationID, 1_800_000_101, 1800), (operationID, 1_800_000_100, 1801)] {
            await fails { try await owner.stageServiceChange(operationID: id, nowUnixSeconds: now, lifetimeSeconds: lifetime) }
        }
        await fails { _ = try await owner.queryWorkload() }
        await fails { try await owner.connectWorkload() }
        await fails { try await owner.stageRetire() }
        await fails { try await owner.complete() }
        #expect(peer.state.withLock { $0.requests } == requests)
        #expect(try owner.snapshot().pendingService == pending)
        peer.state.withLock { $0.dropStageReply = false; $0.newReady = peer.successor(pending.request.predecessor.grant) }
        try await owner.stageServiceChange(operationID: operationID, nowUnixSeconds: pending.nowUnixSeconds, lifetimeSeconds: pending.lifetimeSeconds)
        let next = Transport(peer: peer, root: disk.root)
        try await owner.reopenService(using: next, expectedBinding: peer.bootBinding)
        #expect(next.sawPhysicalServicePending && next.configurations == 1)
        let staged = peer.state.withLock { $0.requests.filter { if case .stageServiceChange = $0.body { true } else { false } } }
        #expect(staged.count == 3 && Set(staged.map(\.requestID.rawValue)) == [pending.stageRequestID])
        #expect(staged.allSatisfy { $0 == staged.first })
        let config = try #require(next.receivedConfigurations.first)
        #expect(config.reopen?.request == pending.request && config.signed == before.current?.original.signed)
        #expect(config.reopen?.isValidSignature(using: peer.rootKey) == true)
        #expect(config.nowUnixSeconds == pending.nowUnixSeconds && config.lifetimeSeconds == pending.lifetimeSeconds)
        #expect(try owner.snapshot().latestServiceRequest == pending)
        await owner.close()
    }

    @Test func forgedRootServiceChangeSignatureNeverConfiguresReopen() async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding), owner = try disk.owner(peer)
        try await owner.provisionFresh()
        let first = Transport(peer: peer, root: disk.root)
        try await owner.bootFresh(using: first, expectedBinding: peer.bootBinding, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        let original = try #require(owner.snapshot().current)
        peer.state.withLock { $0.forgeStageSignature = true }
        await fails { try await owner.stageServiceChange(operationID: Self.id(), nowUnixSeconds: 1_800_000_100, lifetimeSeconds: 1800) }
        peer.state.withLock { $0.newReady = peer.successor(original.original.signed.grant) }
        let next = Transport(peer: peer, root: disk.root)
        await fails { try await owner.reopenService(using: next, expectedBinding: peer.bootBinding) }
        #expect(next.configurations == 0)
        #expect(try owner.snapshot().current == original)
        await owner.close()
    }
    @Test func lostServiceCompletionRetriesOnlyExactRootIDAndPreservesAppliedEpoch() async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding), owner = try disk.owner(peer)
        try await owner.provisionFresh()
        let first = Transport(peer: peer, root: disk.root)
        try await owner.bootFresh(using: first, expectedBinding: peer.bootBinding, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        let original = try #require(owner.snapshot().current)
        try await owner.stageServiceChange(operationID: Self.id(), nowUnixSeconds: 1_800_000_100, lifetimeSeconds: 1800)
        let pending = try #require(owner.snapshot().pendingService)
        let newReady = peer.successor(original.original.signed.grant)
        peer.state.withLock { $0.newReady = newReady; $0.dropServiceCompletionReply = true }
        let next = Transport(peer: peer, root: disk.root)
        await fails { try await owner.reopenService(using: next, expectedBinding: peer.bootBinding) }
        #expect(try owner.snapshot().pendingService == pending)
        #expect(try owner.snapshot().current == original)
        await fails { try await owner.reopenService(using: next, expectedBinding: peer.bootBinding) }
        let other = Transport(peer: peer, root: disk.root)
        await fails { try await owner.reopenService(using: other, expectedBinding: peer.bootBinding) }
        #expect(next.configurations == 1 && other.configurations == 0)
        #expect(peer.state.withLock { $0.rebinds == 1 && $0.serviceCompletions == 1 })
        peer.state.withLock { $0.dropServiceCompletionReply = false }
        try await owner.completeServiceChange()
        let completed = try owner.snapshot()
        try await owner.completeServiceChange()
        #expect(try owner.snapshot() == completed)
        #expect(completed.pendingService == nil && completed.latestServiceRequest == pending)
        #expect(completed.current == original && completed.current?.directResult.serviceEpoch == peer.serviceEpoch)
        #expect(completed.currentContext?.serviceEpoch == newReady.serviceEpoch)
        #expect(completed.observedWorker == nil) // New selection awaits fresh live-service observation.
        #expect(completed.currentService?.openRevision == newReady.openRevision)
        let completions = peer.state.withLock { $0.requests.filter { if case .completeServiceChange = $0.body { true } else { false } } }
        #expect(completions.count == 3 && completions.allSatisfy { $0 == completions.first })
        #expect(completions.first?.requestID.rawValue == pending.completionRequestID)
        #expect(peer.state.withLock { $0.rebinds } == 1)
        peer.state.withLock { $0.workloadEvents = [] }
        try await owner.complete() // Uses live E; must not replay immutable grant completion.
        #expect(peer.state.withLock { $0.workloadEvents } == ["root-live"])
        #expect(peer.state.withLock { $0.completions } == 1)
        #expect(try owner.snapshot().current == original)
        #expect(try owner.snapshot().observedWorker?.workerUUID == newReady.workerUUID)
        #expect(try owner.snapshot().observedWorker?.context == owner.snapshot().currentContext)
        peer.state.withLock { $0.failServiceResult = true; $0.workloadEvents = [] }
        await fails { try await owner.connectWorkload() }
        #expect(next.workloadConnections == 0)
        #expect(peer.state.withLock { $0.workloadEvents } == ["root-live"])
        peer.state.withLock { $0.failServiceResult = false; $0.workloadEvents = [] }
        try await owner.connectWorkload()
        let query = try await owner.queryWorkload()
        #expect(query.epoch == newReady.serviceEpoch && query.epoch != original.directResult.serviceEpoch)
        try await owner.connectWorkload()
        #expect(peer.state.withLock { $0.workloadEvents } == ["root-live", "transport", "child", "query", "root-live", "transport", "child"])
        #expect(next.configurations == 1 && first.workloadConnections == 0)
        await owner.close()
    }

    @Test(arguments: ["pending-before", "completed-before", "pending-during", "completed-during", "pending-malformed", "completed-malformed"])
    func serviceCompletionRechecksPhysicalIntentsEvenWhenRootReplyIsMalformed(_ scenario: String) async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding), owner = try disk.owner(peer)
        try await owner.provisionFresh()
        let first = Transport(peer: peer, root: disk.root)
        try await owner.bootFresh(using: first, expectedBinding: peer.bootBinding, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        try await owner.stageServiceChange(operationID: Self.id(), nowUnixSeconds: 1_800_000_100, lifetimeSeconds: 1800)
        let pending = try #require(owner.snapshot().pendingService)
        peer.state.withLock { $0.newReady = peer.successor(pending.request.predecessor.grant); $0.dropServiceCompletionReply = true }
        let next = Transport(peer: peer, root: disk.root)
        // ROOT may have committed while HOST still retains its pending tuple.
        // The synthetic peer models that uncertainty, not native authority.
        await fails { try await owner.reopenService(using: next, expectedBinding: peer.bootBinding) }
        #expect(try owner.snapshot().pendingService == pending)
        peer.state.withLock { $0.dropServiceCompletionReply = false }
        if scenario.hasPrefix("completed") { try await owner.completeServiceChange() }
        let before = try owner.snapshot()
        #expect((before.pendingService == nil) == scenario.hasPrefix("completed"))
        let stateURL = disk.url.appending(path: "managed-storage-owner/state.json")
        let stateBytes = try Data(contentsOf: stateURL)
        let rootRequests = peer.state.withLock { $0.requests }
        let rootConfirmation = try #require(peer.state.withLock { $0.serviceConfirmation })
        let childActions = peer.state.withLock { $0.childActions }
        let damageURL = disk.url.appending(path: "managed-storage/unexpected")
        func damageIntents() throws { try Data("uncertain".utf8).write(to: damageURL) }
        func expectPoisoned(_ body: () async throws -> Void) async {
            do { try await body(); Issue.record("damaged HOST intents admitted a service completion") }
            catch HostStorageIntents.Failure.poisoned { }
            catch { Issue.record("expected physical intent poison, got \(error)") }
        }
        let beforeRoot = scenario.hasSuffix("before")
        if beforeRoot {
            try damageIntents()
            await expectPoisoned { try await owner.completeServiceChange() }
            #expect(peer.state.withLock { $0.requests } == rootRequests)
        } else {
            let gate = ReplyGate(); defer { gate.release.signal() }
            peer.state.withLock { $0.replyGate = gate; $0.malformedServiceCompletion = scenario.hasSuffix("malformed") }
            let task = Task {
                defer { gate.prepared.continuation.finish() }
                try await owner.completeServiceChange()
            }
            var prepared = false
            for await _ in gate.prepared.stream { prepared = true; break }
            try #require(prepared)
            #expect(try owner.snapshot() == before)
            let attempted = try #require(peer.state.withLock { $0.requests.last })
            #expect(attempted.requestID.rawValue == pending.completionRequestID)
            #expect(attempted.body == .completeServiceChange(identity: before.identity, operationID: pending.request.operationID))
            try damageIntents()
            gate.release.signal()
            // The physical post-check must run even when Worker rejects the
            // malformed envelope; returning only correlationMismatch is unsafe.
            await expectPoisoned { try await task.value }
        }
        #expect(peer.state.withLock { $0.requests.count } == rootRequests.count + (beforeRoot ? 0 : 1))
        #expect(peer.state.withLock { $0.serviceConfirmation } == rootConfirmation)
        #expect(try owner.snapshot() == before)
        #expect(try Data(contentsOf: stateURL) == stateBytes)
        #expect(FileManager.default.fileExists(atPath: damageURL.path)) // Owner never cleans evidence.
        // Remove only our injected marker to prove that the failed physical check
        // poisoned this owner, rather than merely deferring work until the next call.
        try FileManager.default.removeItem(at: damageURL)
        peer.state.withLock { $0.malformedServiceCompletion = false }
        let requestsAfterFailure = peer.state.withLock { $0.requests }
        await expectPoisoned { try await owner.completeServiceChange() }
        await fails { try await owner.complete() }
        await fails { try await owner.connectWorkload() }
        await fails { _ = try await owner.queryWorkload() }
        await fails { try await owner.stageRetire() }
        await fails { try await owner.reopenService(using: next, expectedBinding: peer.bootBinding) }
        #expect(peer.state.withLock { $0.requests } == requestsAfterFailure)
        #expect(peer.state.withLock { $0.childActions } == childActions)
        #expect(peer.state.withLock { $0.rebinds } == 1)
        #expect(next.configurations == 1 && next.workloadConnections == 0)
        #expect(try owner.snapshot() == before)
        #expect(try Data(contentsOf: stateURL) == stateBytes)
        await owner.close()
    }

    @Test(arguments: ["wrong-ready", "same-epoch", "same-ca", "same-key", "stale-open", "malformed-ready", "wrong-root-result", "malformed-root-reply"])
    func serviceReopenRejectsUntrustedReadyAndMismatchedRoot(_ scenario: String) async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding), owner = try disk.owner(peer)
        try await owner.provisionFresh()
        let first = Transport(peer: peer, root: disk.root)
        try await owner.bootFresh(using: first, expectedBinding: peer.bootBinding, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        let original = try #require(owner.snapshot().current)
        try await owner.stageServiceChange(operationID: Self.id(), nowUnixSeconds: 1_800_000_100, lifetimeSeconds: 1800)
        let pending = try #require(owner.snapshot().pendingService)
        let grant = original.original.signed.grant
        peer.state.withLock {
            $0.newReady = peer.successor(grant, epoch: scenario == "same-epoch" ? peer.serviceEpoch : Self.id(),
                openRevision: scenario == "stale-open" ? 1 : scenario == "malformed-ready" ? 0 : 2,
                newCA: scenario != "same-ca", newKey: scenario != "same-key")
            $0.wrongServiceCompletion = scenario == "wrong-root-result"
            $0.malformedServiceCompletion = scenario == "malformed-root-reply"
        }
        let next = Transport(peer: peer, root: disk.root)
        if scenario == "wrong-ready" { next.readyOverride = peer.successor(grant) }
        await fails { try await owner.reopenService(using: next, expectedBinding: peer.bootBinding) }
        #expect(try owner.snapshot().pendingService == pending)
        #expect(try owner.snapshot().current == original)
        #expect(try owner.snapshot().latestServiceConfirmation == nil)
        let requests = peer.state.withLock { $0.requests }
        await fails { try await owner.reopenService(using: next, expectedBinding: peer.bootBinding) }
        await fails { try await owner.connectWorkload() }
        await fails { _ = try await owner.queryWorkload() }
        await fails { try await owner.stageRetire() }
        #expect(peer.state.withLock { $0.requests } == requests)
        #expect(next.configurations == 1 && next.workloadConnections == 0)
        #expect(peer.state.withLock { $0.rebinds } == (scenario.contains("root") ? 1 : 0))
        await owner.close()
    }

    @Test(arguments: ["configure", "command", "rebind"])
    func uncertainServiceMutationIsAttemptedOnlyOnce(_ scenario: String) async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding), owner = try disk.owner(peer)
        try await owner.provisionFresh()
        let first = Transport(peer: peer, root: disk.root)
        try await owner.bootFresh(using: first, expectedBinding: peer.bootBinding, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        try await owner.stageServiceChange(operationID: Self.id(), nowUnixSeconds: 1_800_000_100, lifetimeSeconds: 1800)
        let pending = try #require(owner.snapshot().pendingService)
        peer.state.withLock { $0.newReady = peer.successor(pending.request.predecessor.grant); $0.failRebind = scenario == "rebind" }
        let next = Transport(peer: peer, root: disk.root)
        next.failConfigure = scenario == "configure"; next.failCommand = scenario == "command"
        await fails { try await owner.reopenService(using: next, expectedBinding: peer.bootBinding) }
        next.failConfigure = false; next.failCommand = false
        peer.state.withLock { $0.failRebind = false }
        await fails { try await owner.reopenService(using: next, expectedBinding: peer.bootBinding) }
        #expect(next.configurations == 1)
        #expect(peer.state.withLock { $0.rebinds } == (scenario == "rebind" ? 1 : 0))
        #expect(try owner.snapshot().pendingService == pending)
        await owner.close()
    }

    @Test func cancelledLateServiceCompletionNeverPublishesOrRepeatsMutation() async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding), owner = try disk.owner(peer)
        try await owner.provisionFresh()
        let first = Transport(peer: peer, root: disk.root)
        try await owner.bootFresh(using: first, expectedBinding: peer.bootBinding, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        try await owner.stageServiceChange(operationID: Self.id(), nowUnixSeconds: 1_800_000_100, lifetimeSeconds: 1800)
        let pending = try #require(owner.snapshot().pendingService)
        peer.state.withLock { $0.newReady = peer.successor(pending.request.predecessor.grant); $0.dropServiceCompletionReply = true }
        let next = Transport(peer: peer, root: disk.root)
        await fails { try await owner.reopenService(using: next, expectedBinding: peer.bootBinding) }
        let gate = ReplyGate(); defer { gate.release.signal() }
        peer.state.withLock { $0.dropServiceCompletionReply = false; $0.replyGate = gate }
        let task = Task {
            defer { gate.prepared.continuation.finish() }
            try await owner.completeServiceChange()
        }
        var prepared = false
        for await _ in gate.prepared.stream { prepared = true; break }
        try #require(prepared)
        #expect(try owner.snapshot().pendingService == pending)
        task.cancel(); gate.release.signal()
        await fails { try await task.value }
        #expect(try owner.snapshot().pendingService == pending)
        #expect(try owner.snapshot().latestServiceConfirmation == nil)
        let requests = peer.state.withLock { $0.requests }
        await fails { try await owner.completeServiceChange() }
        await fails { try await owner.reopenService(using: next, expectedBinding: peer.bootBinding) }
        await fails { try await owner.connectWorkload() }
        #expect(peer.state.withLock { $0.requests } == requests)
        #expect(next.configurations == 1 && peer.state.withLock { $0.rebinds } == 1)
        await owner.close()
    }

    @Test(arguments: ["wrong-grant", "wrong-open", "cancel"])
    func reconnectRequiresMatchingFreshLiveResultAndFencesLateCancellation(_ scenario: String) async throws {
        let disk = try Disk(); defer { disk.remove() }
        let peer = try Peer(disk.binding), owner = try disk.owner(peer)
        try await owner.provisionFresh()
        let transport = Transport(peer: peer, root: disk.root)
        try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        try await owner.connectWorkload()
        let before = try owner.snapshot()
        peer.state.withLock { $0.wrongLiveGrant = scenario == "wrong-grant"; $0.wrongLiveRevision = scenario == "wrong-open"; $0.workloadEvents = [] }
        if scenario == "cancel" {
            let gate = ReplyGate(); defer { gate.release.signal() }
            peer.state.withLock { $0.replyGate = gate }
            let task = Task {
                defer { gate.prepared.continuation.finish() }
                try await owner.connectWorkload()
            }
            var prepared = false
            for await _ in gate.prepared.stream { prepared = true; break }
            try #require(prepared)
            task.cancel(); gate.release.signal()
            await fails { try await task.value }
            await fails { try await owner.connectWorkload() }
            #expect(transport.cancelled.withLock { $0 })
        } else { await fails { try await owner.connectWorkload() } }
        await fails { _ = try await owner.queryWorkload() }
        #expect(transport.workloadConnections == 1)
        #expect(peer.state.withLock { $0.workloadEvents } == ["root-live"])
        #expect(try owner.snapshot() == before)
        await owner.close()
    }

    func fails(_ body: () async throws -> Void) async {
        do { try await body(); Issue.record("isolated non-native failure was accepted") } catch { }
    }
    nonisolated static func id() -> String { UUID().uuidString.lowercased() }
    nonisolated private static func provisionEnvelope(_ request: R.Request, initialDescriptors: Bool) throws -> R.Request {
        guard case .provision(let id, let binding, let candidate, _) = request.body else { throw Owner.Failure.invalid }
        return try .init(requestID: request.requestID,
            body: .provision(id: id, binding: binding, candidate: candidate, initialDescriptors: initialDescriptors))
    }

    nonisolated final class ReplyGate: Sendable {
        let prepared = AsyncStream<Void>.makeStream()
        let release = DispatchSemaphore(value: 0)
        func holdReply() {
            prepared.continuation.yield(())
            prepared.continuation.finish()
            // Called on the owner's dedicated blocking ROOT queue, never a
            // cooperative executor. The test always releases it in defer.
            release.wait()
        }
    }

    nonisolated final class Peer: @unchecked Sendable {
        struct State {
            var requests: [R.Request] = []
            var grants: [String: L.SignedGrant] = [:]
            var completions = 0, allocations = 0, descriptorResends = 0, childActions = 0
            var provisionIntent: R.Request?
            var probeFailure: StorageIdentity.ErrorCode?
            var dropProvisionReply = false, failProbe = false, clientInvalidRequest = false
            var wrongProbeEnvelope = false, wrongAttachEnvelope = false
            var failComplete = false, failReclaim = false, wrongGrant = false
            var replyGate: ReplyGate?
            var workloadEvents: [String] = []
            var workloadGate: ReplyGate?
            var workloadConnect: (@Sendable () throws -> Void)?
            var wrongWorkloadIdentity = false
            var ownerStateURL: URL?
            var stagedService: R.Request?
            var serviceConfirmation: L.ServiceChangeConfirmation?
            var newReady: W.Ready?, simulatedReady: W.Ready?
            var dropStageReply = false, dropServiceCompletionReply = false, forgeStageSignature = false
            var failServiceResult = false, wrongLiveGrant = false, wrongLiveRevision = false
            var revokeOnServiceResult = false, rootRevoked = false
            var wrongServiceCompletion = false, malformedServiceCompletion = false, failRebind = false
            var rebinds = 0, serviceCompletions = 0
            var sawDurableStage = false
            var workloadResponder: (@Sendable (ManagedStorageControlProtocol.ControlRequest) throws -> Data)?
            var workloadRequests = 0
            var attachmentRequests: [StorageLifecycleChildProcess.AttachmentCertificateRequest] = []
            var attachmentReply: Data?
            // Takeover (cold restart) modelling.
            var refuseTakeover = false, dropIssueReply = false
            var deadRecipientGrantID: String?
            var takeoverGrantFault: String?
            var takeoverIssues = 0, binds = 0, childTakeovers = 0
        }
        let state = Mutex(State())
        let rootPrivate = Curve25519.Signing.PrivateKey()
        let controller = Curve25519.Signing.PrivateKey()
        let rootKey: StorageIdentity.RootPublicKey
        let binding: StorageIdentity.StoreBinding
        let bootBinding: W.Binding
        let serviceEpoch = ManagedStorageLifecycleOwnerTests.id()
        let workerUUID = ManagedStorageLifecycleOwnerTests.id()
        let incarnation = ManagedStorageLifecycleOwnerTests.id()
        let certificate: Data
        init(_ binding: StorageIdentity.StoreBinding) throws {
            self.binding = binding; rootKey = try .init(publicData: rootPrivate.publicKey.rawRepresentation)
            bootBinding = .init(shimLaunchUUID: ManagedStorageLifecycleOwnerTests.id(), guestBootNonce: ManagedStorageLifecycleOwnerTests.id(),
                ext4UUID: binding.expectedExt4UUID.rawValue, bytes: binding.backing.size)
            let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
                .appending(path: "Fixtures/storage-bootstrap/lifecycle-service-boot-v2.json")
            let frames = try JSONDecoder().decode([String].self, from: Data(contentsOf: url))
            certificate = try W.decode(Data(frames[2].utf8)).ready!.tlsRootDER
        }
        func request(_ request: R.Request, _ rootFD: Int32, _ backingFD: Int32) throws -> R.Reply {
            #expect(!Thread.isMainThread)
            let reply = try state.withLock { s -> R.Reply in
                s.requests.append(request)
                switch request.body {
                case .provision(let id, let requestedBinding, let candidate, let initial):
                    #expect(initial ? rootFD >= 0 && backingFD >= 0 : rootFD < 0 && backingFD < 0)
                    // Model ROOT's persisted intent before signature release, not a stateless echo.
                    let wrongEnvelope = initial ? s.wrongAttachEnvelope : s.wrongProbeEnvelope
                    let envelope = try wrongEnvelope ? ManagedStorageLifecycleOwnerTests.provisionEnvelope(request, initialDescriptors: !initial) : request
                    if !initial && s.failProbe { throw Owner.Failure.incomplete }
                    if !initial && s.clientInvalidRequest { throw StorageLifecycleRootClient.Failure(.invalidRequest) }
                    if !initial, let code = s.probeFailure { return try .init(for: envelope, body: .failure(code)) }
                    if let intent = s.provisionIntent {
                        if rootFD >= 0 || backingFD >= 0 { s.descriptorResends += 1 }
                        guard rootFD < 0, backingFD < 0,
                              request == (try ManagedStorageLifecycleOwnerTests.provisionEnvelope(intent, initialDescriptors: false)),
                              let old = s.grants[id] else { return try .init(for: envelope, body: .failure(.conflict)) }
                        let released = try L.SignedGrant(grant: old.grant, signature: rootPrivate.signature(for: old.grant.signingBytes))
                        return try .init(for: envelope, body: .grant(released))
                    }
                    guard initial else { return try .init(for: envelope, body: .failure(.invalidRequest)) }
                    guard requestedBinding == binding else { return try .init(for: envelope, body: .failure(.conflict)) }
                    let grant = try L.Grant(operation: .initialize, id: id, identity: .init(binding: binding, generation: 1), serial: 1,
                        expectedEpoch: 0, newKey: candidate.publicKey.fingerprint.rawValue)
                    let signed = try L.SignedGrant(grant: grant, signature: rootPrivate.signature(for: grant.signingBytes))
                    s.provisionIntent = request; s.grants[id] = signed; s.allocations += 1
                    if s.dropProvisionReply { throw Owner.Failure.incomplete }
                    return try .init(for: envelope, body: .grant(signed))
                case .rootPublicKey:
                    return try .init(for: request, body: .rootPublicKey(rootKey))
                case .issue(let op, let id, let identity, let epoch, let candidate):
                    // Models ROOT's predecessor-exited refusal and idempotent persisted intent.
                    if op == .takeover && s.refuseTakeover { return try .init(for: request, body: .failure(.blocked)) }
                    let signed: L.SignedGrant
                    if let old = s.grants[id] {
                        signed = try L.SignedGrant(grant: old.grant, signature: rootPrivate.signature(for: old.grant.signingBytes))
                    } else {
                        let serial = (s.grants.values.map(\.grant.serial).max() ?? 0) + 1
                        let grant = try L.Grant(operation: op, id: id, identity: identity, serial: serial, expectedEpoch: epoch, newKey: candidate.publicKey.fingerprint.rawValue)
                        signed = try L.SignedGrant(grant: grant, signature: rootPrivate.signature(for: grant.signingBytes))
                        s.grants[id] = signed
                        if op == .takeover { s.takeoverIssues += 1 }
                    }
                    if op == .takeover && s.dropIssueReply { throw Owner.Failure.incomplete }
                    switch s.takeoverGrantFault {
                    case "forged":
                        return try .init(for: request, body: .grant(.init(grant: signed.grant,
                            signature: Curve25519.Signing.PrivateKey().signature(for: signed.grant.signingBytes))))
                    case "epoch", "id":
                        let g = signed.grant
                        let wrong = try L.Grant(operation: g.operation, id: s.takeoverGrantFault == "id" ? ManagedStorageLifecycleOwnerTests.id() : g.id,
                            identity: g.identity, serial: g.serial, expectedEpoch: g.expectedEpoch + (s.takeoverGrantFault == "epoch" ? 1 : 0), newKey: g.newKey)
                        return try .init(for: request, body: .grant(.init(grant: wrong, signature: rootPrivate.signature(for: wrong.signingBytes))))
                    case "recipient":
                        // Validly ROOT-signed, but for a candidate other than the durable recipient.
                        let g = signed.grant
                        let other = try StorageIdentity.Ed25519SPKI(
                            rawPublicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation).fingerprint.rawValue
                        let wrong = try L.Grant(operation: g.operation, id: g.id, identity: g.identity, serial: g.serial,
                            expectedEpoch: g.expectedEpoch, newKey: other)
                        return try .init(for: request, body: .grant(.init(grant: wrong, signature: rootPrivate.signature(for: wrong.signingBytes))))
                    default: return try .init(for: request, body: .grant(signed))
                    }
                case .complete(_, let id):
                    s.completions += 1; s.workloadEvents.append("root")
                    if s.failComplete { throw Owner.Failure.incomplete }
                    var grant = s.grants[id]!.grant
                    if s.wrongGrant { grant = try .init(operation: grant.operation, id: grant.id, identity: grant.identity,
                        serial: grant.serial + 1, expectedEpoch: grant.expectedEpoch, newKey: grant.newKey) }
                    let receipt = try L.Receipt(grant: grant, nonce: Data(repeating: UInt8(s.completions), count: 32), serviceEpoch: s.simulatedReady?.serviceEpoch ?? serviceEpoch,
                        revision: grant.operation == .initialize ? 1 : max(grant.serial, s.simulatedReady?.revision ?? 0))
                    return try .init(for: request, body: .completed(receipt))
                case .serviceBootTrust(_, let id, let changeID):
                    guard id != s.deadRecipientGrantID else { throw Owner.Failure.blocked }
                    s.workloadEvents.append("root-boot")
                    if let changeID {
                        guard case .stageServiceChange(let change) = s.stagedService?.body,
                              change.operationID == changeID else { throw Owner.Failure.invalid }
                    }
                    let ready = try s.simulatedReady ?? initialReady(s.grants[id]!.grant)
                    return try .init(for: request, body: .serviceBootTrust(trust(ready), grantID: id, serviceChangeID: changeID))
                case .serviceResult(_, let id):
                    guard id != s.deadRecipientGrantID else { throw Owner.Failure.blocked }
                    s.workloadEvents.append("root-live")
                    if s.revokeOnServiceResult { s.rootRevoked = true; throw Owner.Failure.incomplete }
                    if s.failServiceResult { throw Owner.Failure.incomplete }
                    var grant = s.grants[id]!.grant
                    if s.wrongLiveGrant {
                        grant = try .init(operation: grant.operation, id: grant.id, identity: grant.identity,
                            serial: grant.serial + 1, expectedEpoch: grant.expectedEpoch, newKey: grant.newKey)
                    }
                    let ready = try s.simulatedReady ?? initialReady(grant)
                    return try .init(for: request, body: .serviceResult(live(grant, ready, revision: ready.openRevision + (s.wrongLiveRevision ? 1 : 0))))
                case .stageServiceChange(let change):
                    s.workloadEvents.append("root-stage")
                    let pending = try physicalPending(s.ownerStateURL)
                    #expect(pending.request == change && pending.stageRequestID == request.requestID.rawValue)
                    s.sawDurableStage = true
                    if let staged = s.stagedService { guard staged == request else { throw Owner.Failure.invalid } }
                    else { s.stagedService = request }
                    if s.dropStageReply { throw Owner.Failure.incomplete }
                    let signer = s.forgeStageSignature ? Curve25519.Signing.PrivateKey() : rootPrivate
                    return try .init(for: request, body: .serviceChangeStaged(.init(request: change,
                        signature: signer.signature(for: change.signingBytes))))
                case .completeServiceChange(_, let operationID):
                    s.workloadEvents.append("root-service-complete"); s.serviceCompletions += 1
                    guard case .stageServiceChange(let change) = s.stagedService?.body,
                          change.operationID == operationID, s.rebinds == 1,
                          let ready = s.simulatedReady else { throw Owner.Failure.invalid }
                    let result = try live(change.predecessor.grant, ready,
                        revision: ready.openRevision + (s.wrongServiceCompletion ? 1 : 0))
                    let confirmation = try L.ServiceChangeConfirmation(request: change, successor: result.state(boot: trust(ready)))
                    if let old = s.serviceConfirmation { #expect(old == confirmation) }
                    else { s.serviceConfirmation = confirmation }
                    if s.dropServiceCompletionReply { throw Owner.Failure.incomplete }
                    let envelope = try s.malformedServiceCompletion
                        ? R.Request(requestID: .init(ManagedStorageLifecycleOwnerTests.id()), body: request.body) : request
                    return try .init(for: envelope, body: .serviceChanged(confirmation, result))
                case .reclaim:
                    if s.failReclaim { return try .init(for: request, body: .failure(.unavailable)) }
                    return try .init(for: request, body: .reclaimed)
                default: throw Owner.Failure.invalid
                }
            }
            // Do not hold the state mutex while the test inspects the prepared
            // reply and cancels the owner before releasing this late result.
            let gate = state.withLock {
                let gate = $0.replyGate
                $0.replyGate = nil // A regression admitting another request must fail, not block again.
                return gate
            }
            gate?.holdReply()
            return reply
        }
        func initialReady(_ grant: L.Grant) throws -> W.Ready {
            .init(identity: grant.identity, serviceEpoch: serviceEpoch, workerUUID: workerUUID, controllerEpoch: grant.expectedEpoch + 1,
                controllerKey: grant.newKey, revision: 1, openRevision: 1, bootstrapKey: rootKey.fingerprint.rawValue,
                tlsRootDER: certificate, serverDER: certificate, serverSPKI: String(repeating: "b", count: 64))
        }
        func ready(_ grant: L.Grant) throws -> W.Ready {
            try state.withLock { try $0.simulatedReady ?? initialReady(grant) }
        }
        // Synthetic DTO bytes only: intentionally NOT native TLS/authentication evidence.
        func successor(_ grant: L.Grant, epoch: String = ManagedStorageLifecycleOwnerTests.id(),
                       openRevision: UInt64 = 2, newCA: Bool = true, newKey: Bool = true) -> W.Ready {
            .init(identity: grant.identity, serviceEpoch: epoch, workerUUID: ManagedStorageLifecycleOwnerTests.id(),
                controllerEpoch: grant.expectedEpoch + 1, controllerKey: grant.newKey,
                revision: max(2, openRevision), openRevision: openRevision, bootstrapKey: rootKey.fingerprint.rawValue,
                tlsRootDER: newCA ? certificate + Data([1]) : certificate, serverDER: certificate,
                serverSPKI: String(repeating: newKey ? "c" : "b", count: 64))
        }
        func trust(_ ready: W.Ready) throws -> StorageLifecycleBootTrust {
            try .init(identity: ready.identity, serviceEpoch: ready.serviceEpoch,
                tlsRootSHA256: SHA256.hash(data: ready.tlsRootDER).map { String(format: "%02x", $0) }.joined(),
                serverSPKI: ready.serverSPKI, bootstrapKey: ready.bootstrapKey)
        }
        func live(_ grant: L.Grant, _ ready: W.Ready, revision: UInt64? = nil) throws -> L.ServiceResult {
            try .init(identity: grant.identity, grant: grant, nonce: Data(repeating: 7, count: 32),
                serviceEpoch: ready.serviceEpoch, controllerEpoch: ready.controllerEpoch,
                controllerKey: ready.controllerKey, openRevision: revision ?? ready.openRevision)
        }
        func physicalPending(_ url: URL?) throws -> ManagedStorageLifecycleCheckpoint.PendingService {
            let url = try #require(url)
            let object = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
            let pending = try #require(object["pendingService"])
            return try JSONDecoder().decode(ManagedStorageLifecycleCheckpoint.PendingService.self,
                from: JSONSerialization.data(withJSONObject: pending))
        }
        func workloadQuery() throws -> Data {
            #expect(!Thread.isMainThread)
            let (grant, ready, wrong, gate) = try state.withLock { s in
                s.workloadEvents.append("query")
                let grant = try #require(s.grants.values.map(\.grant).filter { $0.operation != .retire }.max { $0.serial < $1.serial })
                let gate = s.workloadGate; s.workloadGate = nil
                return (grant, try s.simulatedReady ?? initialReady(grant), s.wrongWorkloadIdentity, gate)
            }
            let identity = try L.Identity(store: grant.identity.store,
                generation: wrong ? grant.identity.generation + 1 : grant.identity.generation, binding: grant.identity.binding)
            let root = ControllerJSON.object(["device": .number(1), "inode": .number(1)])
            let reply = ControllerJSON.object(["id": .number(1), "lifecycle_identity": try ControllerJSON.from(identity),
                "snapshot": .object(["schema": .number(4), "revision": .number(ready.revision),
                    "store": .object(["id": .string(grant.identity.store), "device_id": .string("ext4-test"), "root": root, "exports": root]),
                    "epoch": .string(ready.serviceEpoch), "controller": .object(["epoch": .number(ready.controllerEpoch), "key": .string(grant.newKey)]),
                    "volumes": .object([:]), "volume_lifecycles": .object([:]), "attachments": .object([:]), "prepares": .object([:])])])
            gate?.holdReply()
            return try reply.bytes()
        }
        /// Default: the fresh child. A takeover child passes its own key/incarnation.
        @MainActor func seam(child: Curve25519.Signing.PrivateKey? = nil, childIncarnation: String? = nil,
                             expectedEpoch: UInt64 = 0, daemon: UInt64 = 5) throws -> Owner.IsolatedTestSeam {
            let key = child ?? controller, incarnation = childIncarnation ?? self.incarnation
            let spki = try StorageIdentity.Ed25519SPKI(rawPublicKey: key.publicKey.rawRepresentation)
            let greeting = try StorageLifecycleChildProtocol.Greeting(channelID: ManagedStorageLifecycleOwnerTests.id(), incarnationID: incarnation,
                daemonUniqueID: daemon, controllerSPKI: spki.publicData, rootPublicKey: rootKey.publicData,
                store: binding.storeID.rawValue, binding: L.bindingDigest(binding), expectedEpoch: expectedEpoch)
            return .init(preparation: .init(rootPublicKey: rootKey, greeting: greeting),
                recipient: .init(publicKey: spki.rawPublicKey, incarnation: incarnation, daemonUniqueID: daemon, childUniqueID: daemon + 1, childPID: 42),
                rootRequest: { [self] in try request($0, $1, $2) }, childAction: { [self] action in
                    try state.withLock { s in
                        s.childActions += 1
                        if case .connectWorkload = action { s.workloadEvents.append("child") }
                        if case .bind = action { s.binds += 1 }
                        if case .takeover = action { s.childTakeovers += 1; s.workloadEvents.append("child-takeover") }
                        if case .stageServiceRebind(let change, let boot) = action {
                            s.rebinds += 1; s.workloadEvents.append("child-rebind")
                            #expect(s.stagedService?.body == .stageServiceChange(change: change))
                            #expect(boot.serviceEpoch == s.simulatedReady?.serviceEpoch)
                            if s.failRebind { throw Owner.Failure.incomplete }
                        }
                    }
                    if case .connectWorkload = action { try state.withLock { $0.workloadConnect }?() }
                    if case .csr = action { return Data([1]) }
                    if case .workload(let request) = action,
                       let responder = state.withLock({ s -> (@Sendable (ManagedStorageControlProtocol.ControlRequest) throws -> Data)? in
                           s.workloadRequests += 1; return s.workloadResponder }) {
                        return try responder(request)
                    }
                    if case .attachmentCertificate(let request) = action {
                        return state.withLock { s in
                            s.attachmentRequests.append(request)
                            return s.attachmentReply ?? Data(#"{"certificate":"\#(certificate.base64EncodedString())"}"#.utf8)
                        }
                    }
                    if case .workload(.query) = action { return try workloadQuery() }
                    return Data()
                })
        }
    }

    @MainActor final class Transport: ManagedStorageLifecycleServiceTransport {
        let peer: Peer
        let root: PersistentStateDirectory
        var configurations = 0, workloadConnections = 0, sawPhysicalPendingAndIntents = false, failCommand = false
        var suspendConfigure = false, failConfigure = false
        var sawPhysicalServicePending = false
        var readyOverride: W.Ready?
        var receivedConfigurations: [W.Configuration] = []
        nonisolated let cancelled = Mutex(false)
        nonisolated func cancel() { cancelled.withLock { $0 = true } }
        init(peer: Peer, root: PersistentStateDirectory) { self.peer = peer; self.root = root }
        func configure(_ configuration: W.Configuration) async throws -> ManagedStorageLifecycleServiceReady {
            configurations += 1; receivedConfigurations.append(configuration)
            while suspendConfigure {
                if cancelled.withLock({ $0 }) { throw CancellationError() }
                try await Task.sleep(for: .milliseconds(5))
            }
            let directory = try root.openDirectory(named: "managed-storage-owner")
            let bytes = try HostStorageIntentCommit.readPrivateFile(in: directory, named: "state.json", maximumBytes: 1_048_576)
            let state = try ManagedStorageLifecycleCheckpoint.decode(bytes)
            let hasIntents = try root.entryMetadata(named: "managed-storage") != nil
            sawPhysicalPendingAndIntents = state.pending?.signed == configuration.signed && hasIntents
            if configuration.action == .open {
                let pending = try #require(state.pendingService)
                sawPhysicalServicePending = pending.request == configuration.reopen?.request && hasIntents
                    && pending.nowUnixSeconds == configuration.nowUnixSeconds && pending.lifetimeSeconds == configuration.lifetimeSeconds
                #expect(sawPhysicalServicePending)
                try peer.state.withLock {
                    #expect($0.stagedService?.body == .stageServiceChange(change: pending.request))
                    $0.workloadEvents.append("configure-open")
                    $0.simulatedReady = try #require($0.newReady)
                }
            }
            if failConfigure { throw Owner.Failure.incomplete }
            return try .init(binding: peer.bootBinding, ready: readyOverride ?? peer.ready(configuration.signed.grant))
        }
        var commands: [W.Command] = []
        func command(_ frame: W.Frame) async throws -> W.Frame {
            if let command = frame.command { commands.append(command) }
            if failCommand { throw Owner.Failure.incomplete }
            if frame.command == .serviceStatus {
                return .init(operation: .reply, binding: frame.binding, sequence: frame.sequence,
                    serviceEpoch: frame.serviceEpoch, workerUUID: frame.workerUUID, status: .init(phase: .ready))
            }
            if frame.command == .reconcileController {
                let signed = try #require(frame.signed)
                #expect(frame.controller == .init(epoch: signed.grant.expectedEpoch + 1, key: signed.grant.newKey))
                peer.state.withLock { $0.workloadEvents.append("reconcile") }
                return try .init(operation: .reply, binding: frame.binding,
                    ready: readyOverride ?? peer.initialReady(signed.grant), sequence: frame.sequence,
                    serviceEpoch: frame.serviceEpoch, workerUUID: frame.workerUUID)
            }
            return .init(operation: .reply, binding: frame.binding, sequence: frame.sequence, serviceEpoch: frame.serviceEpoch,
                certificate: frame.command == .issueController || frame.command == .authorizeSuccessor ? peer.certificate : nil, ok: frame.command == .authorizeRetirement ? true : nil,
                workerUUID: frame.workerUUID)
        }
        func connectLifecycle() async throws -> FileHandle { FileHandle(fileDescriptor: open("/dev/null", O_RDONLY | O_CLOEXEC), closeOnDealloc: true) }
        var attachmentConnections = 0
        func connectAttachmentCSR() async throws -> FileHandle {
            attachmentConnections += 1
            return try await connectLifecycle()
        }
        func connectWorkload() async throws -> FileHandle {
            workloadConnections += 1
            peer.state.withLock { $0.workloadEvents.append("transport") }
            return try await connectLifecycle()
        }
    }
    @MainActor final class Disk {
        let url: URL, root: PersistentStateDirectory, backing: Int32, binding: StorageIdentity.StoreBinding
        init() throws {
            url = FileManager.default.temporaryDirectory.appending(path: "cengine-owner-isolated-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            root = try PersistentStateDirectory.open(url)
            let infrastructure = try root.createDirectory(named: "infrastructure")
            guard case .created(let created) = try RawDiskInitialization.createNewDisk(in: infrastructure, named: "volumes.ext4", size: 4096) else {
                throw Owner.Failure.invalid
            }
            backing = openat(infrastructure.descriptor, "volumes.ext4", O_RDWR | O_CLOEXEC | O_NOFOLLOW)
            let rawBinding = RawDiskInitialization.Binding(shimLaunchUUID: UUID(), guestBootNonce: UUID())
            _ = try RawDiskInitialization.begin(in: infrastructure, named: "volumes.ext4", expectedSize: 4096,
                binding: rawBinding, heldDiskDescriptor: backing)
            // Isolated format acknowledgement only; no guest/native proof.
            try RawDiskInitialization.completeAfterVerifiedGuestSync(in: infrastructure, named: "volumes.ext4", expectedSize: 4096,
                operationUUID: UUID(uuidString: created.record.operationUUID)!, ext4UUID: UUID(uuidString: created.record.ext4UUID)!,
                binding: rawBinding, heldDiskDescriptor: backing)
            // Keep older fixture assertions' locator, not an additional backing inode.
            try FileManager.default.createSymbolicLink(atPath: url.appending(path: "disk").path, withDestinationPath: "infrastructure/volumes.ext4")
            let identity = try PersistentFileIdentity.capture(descriptor: backing)
            binding = StorageIdentity.StoreBinding(storeID: try .init(ManagedStorageLifecycleOwnerTests.id()),
                root: try .init(volumeUUID: .init(root.identity.volumeUUID!.uuidString.lowercased()), inode: root.identity.inode),
                backing: try .init(identity: .init(volumeUUID: .init(identity.volumeUUID!.uuidString.lowercased()), inode: identity.inode), size: 4096),
                expectedExt4UUID: try .init(created.record.ext4UUID))
        }
        func owner(_ peer: Peer, hook: HostStorageIntentCommit.Hook? = nil,
                   afterCheckpointFresh: (() throws -> Void)? = nil,
                   afterWorkloadDecode: (() async throws -> Void)? = nil,
                   beforeWorkloadConnectionPublication: (() async throws -> Void)? = nil) throws -> Owner {
            peer.state.withLock { $0.ownerStateURL = url.appending(path: "managed-storage-owner/state.json") }
            return try Owner(isolatedTest: peer.seam(), root: root, backingDescriptor: backing, binding: binding,
                provenanceReference: String(repeating: "a", count: 64), commitHook: hook,
                afterCheckpointFresh: afterCheckpointFresh, afterWorkloadDecode: afterWorkloadDecode,
                beforeWorkloadConnectionPublication: beforeWorkloadConnectionPublication)
        }
        deinit { Darwin.close(backing) }
        func remove() { try? FileManager.default.removeItem(at: url) }
    }
}
#endif

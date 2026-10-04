#if os(macOS) && DEBUG
import CEngineCore
import Foundation
import Synchronization
import Testing
@testable import CEngineRuntime

/// Isolated owner + physical journals; no native ROOT/Guest authority is minted.
@Suite(.serialized) @MainActor struct ManagedLifecyclePrepareOwnerTests {
    typealias Owner = ManagedStorageLifecycleOwner
    typealias C = ManagedPrepareCompatibilityProtocol
    typealias W = StorageLifecycleServiceBootProtocol
    typealias K = ManagedPrepareWorkerCheckpointProtocol
    typealias Existing = ManagedStorageLifecycleOwnerTests

    @Test(arguments: ["admitted-queued", "full-frame-before-admit"])
    func workerExitPreservesBothFrozenCuts(_ stage: String) async throws {
        let f = try await Fixture(stage: stage); defer { f.disk.remove() }
        let before = try f.owner.snapshot()
        let wait = try await f.owner.exitPrepareStorageWorker(f.release, arm: f.arm, checkpoint: f.observed)
        #expect(wait.stage == stage && wait.token == f.release.token)
        #expect(wait.query == f.release.query && wait.requestSequence == 7)
        #expect(try f.owner.snapshot() == before)
        #expect(f.transport.frames.compactMap(\.command) == [.prepareCompatibilityWorkerExit])
        await f.owner.close()
    }

    @Test func cancelledWorkerExitSendsNothing() async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            await #expect(throws: CancellationError.self) {
                _ = try await f.owner.exitPrepareStorageWorker(f.release, arm: f.arm, checkpoint: f.observed)
            }
        }
        await task.value
        #expect(f.transport.frames.isEmpty)
        await f.owner.close()
    }

    @Test func allFiveFacadeCommandsPreserveCheckpointAndMonotonicEnvelope() async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        let before = try f.owner.snapshot(), journal = try f.owner.journalSnapshot()
        let (arm, status) = try await f.owner.armPrepareStorage(f.arm.arm)
        #expect(arm == f.arm && status.state == "armed")
        #expect(try await f.owner.observePrepareStorage(arm) == f.observed)
        let released = try await f.owner.releasePrepareStorage(f.release, arm: arm)
        #expect(released.state == "released")
        let wait = try await f.owner.exitPrepareStorageWorker(f.release, arm: arm, checkpoint: f.observed)
        #expect(wait.requestSequence == f.observed.observation?.admission?.requestSequence)
        let exit = try f.genericExit()
        let generic = try await f.owner.exitCheckpointWorker(exit)
        #expect(K.sameClaim(generic.claim, exit))
        #expect(try f.owner.snapshot() == before)
        let afterJournal = try f.owner.journalSnapshot()
        #expect(afterJournal.revision == journal.revision && afterJournal.volumes == journal.volumes)
        #expect(afterJournal.intents == journal.intents && afterJournal.reconciliationRequired == journal.reconciliationRequired)
        #expect(f.transport.frames.compactMap(\.command) == [.prepareCompatibilityArm, .prepareCompatibilityObserve,
            .prepareCompatibilityRelease, .prepareCompatibilityWorkerExit, .prepareCompatibilityCheckpointExit])
        let sequences = f.transport.frames.compactMap(\.sequence)
        #expect(sequences.count == 5 && zip(sequences, sequences.dropFirst()).allSatisfy { pair in pair.0 < pair.1 })
        #expect(f.transport.frames.allSatisfy { $0.binding == f.peer.bootBinding && $0.workerUUID == arm.workerUUID })
        await f.owner.close()
    }

    @Test(arguments: ["sequence", "worker", "binding", "epoch", "refused", "mixed", "token", "wait-sequence", "checkpoint"])
    func rejectsUnboundRefusedAndMixedReplies(_ fault: String) async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        let before = try f.owner.snapshot()
        f.transport.fault = fault
        if fault == "checkpoint" {
            let exit = try f.genericExit()
            await #expect(throws: (any Error).self) { _ = try await f.owner.exitCheckpointWorker(exit) }
        } else {
            await #expect(throws: (any Error).self) {
                _ = try await f.owner.exitPrepareStorageWorker(f.release, arm: f.arm, checkpoint: f.observed)
            }
        }
        #expect(try f.owner.snapshot() == before)
        await f.owner.close()
    }

    @Test(arguments: ["worker", "scope", "token", "claim", "profile"])
    func rejectsInvalidClaimsBeforeSending(_ fault: String) async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        var arm = f.arm, release = f.release
        switch fault {
        case "worker": arm.workerUUID = UUID().uuidString.lowercased()
        case "scope": arm.arm.scope.controllerEpoch += 1
        case "token": release.token = String(repeating: "b", count: 64)
        case "claim": release.query.requestID = UUID().uuidString.lowercased()
        default: arm.arm.profile = C.earlyProfile; arm.arm.version = 2
        }
        await #expect(throws: (any Error).self) {
            _ = try await f.owner.exitPrepareStorageWorker(release, arm: arm, checkpoint: f.observed)
        }
        #expect(f.transport.frames.isEmpty)
        await f.owner.close()
    }

    @Test func nonblockingPollSerialMutationsAndReplacementAdmissionStaySeparate() async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        f.transport.suspended = true
        let arm = Task { try await f.owner.armPrepareStorage(f.arm.arm) }
        try await f.waitForCommands(1)
        let release = Task { try await f.owner.releasePrepareStorage(f.release, arm: f.arm) }
        await Task.yield()
        #expect(try await f.owner.observePrepareStorage(f.arm) == nil)
        #expect(f.transport.frames.count == 1)
        #expect(!f.transport.cancelled.withLock { $0 })
        let scope = StorageServiceTypes.Scope(serviceEpoch: f.arm.arm.scope.serviceEpoch, workerUUID: f.arm.workerUUID)
        let replacement = StorageServiceTypes.ReplacementRequest(operationUUID: UUID().uuidString.lowercased(),
            predecessor: scope, nowUnixSeconds: 1_800_000_000)
        // Active PREPARE must fail fast, not join the replacement read-only wait.
        await #expect(throws: (any Error).self) { try await f.owner.awaitServiceReplacementAdmission(replacement) }
        #expect(!f.transport.cancelled.withLock { $0 })
        f.transport.suspended = false
        _ = try await arm.value; _ = try await release.value
        #expect(f.transport.frames.compactMap(\.command) == [.prepareCompatibilityArm, .prepareCompatibilityRelease])
        #expect(try await f.owner.observePrepareStorage(f.arm) == f.observed)
        await f.owner.close()
    }

    @Test(arguments: [W.Command.serviceStatus, .notifications])
    func busyReadOnlyLaneMakesDeadlineObservationsNonblocking(_ command: W.Command) async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        f.transport.suspended = true
        let readOnly = Task { try await f.readOnlyCommand(command) }
        try await f.waitForCommands(1)
        // Bound a regressed wait without cancelling the owner or its read-only IO.
        let watchdog = Task {
            try await Task.sleep(for: .seconds(2))
            f.transport.suspended = false
        }
        defer { watchdog.cancel(); f.transport.suspended = false }
        let start = DispatchTime.now().uptimeNanoseconds
        #expect(try await f.owner.observePrepareStorage(f.arm, deadlineNanoseconds: 0) == nil)
        #expect(try await f.owner.observePrepareStorage(f.arm,
            deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 1_000_000) == nil)
        #expect(DispatchTime.now().uptimeNanoseconds - start < 500_000_000)
        #expect(f.transport.suspended)
        #expect(f.transport.frames.compactMap(\.command) == [command])
        #expect(!f.transport.cancelled.withLock { $0 })
        f.transport.suspended = false
        try await readOnly.value
        #expect(try await f.owner.observePrepareStorage(f.arm) == f.observed)
        _ = try await f.owner.armPrepareStorage(f.arm.arm)
        #expect(!f.transport.cancelled.withLock { $0 })
        await f.owner.close()
    }

    @Test(arguments: [W.Command.serviceStatus, .notifications])
    func mutationWaitsForReadOnlyLaneAndCanCancelWithoutCancellingOwner(_ command: W.Command) async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        f.transport.suspended = true
        let readOnly = Task { try await f.readOnlyCommand(command) }
        try await f.waitForCommands(1)
        let cancelled = Task { try await f.owner.armPrepareStorage(f.arm.arm) }
        try await Task.sleep(for: .milliseconds(20))
        #expect(f.transport.frames.compactMap(\.command) == [command])
        cancelled.cancel()
        await #expect(throws: CancellationError.self) { _ = try await cancelled.value }
        #expect(!f.transport.cancelled.withLock { $0 })
        let mutation = Task { try await f.owner.armPrepareStorage(f.arm.arm) }
        try await Task.sleep(for: .milliseconds(20))
        #expect(f.transport.frames.compactMap(\.command) == [command])
        f.transport.suspended = false
        try await readOnly.value
        _ = try await mutation.value
        #expect(f.transport.frames.compactMap(\.command) == [command, .prepareCompatibilityArm])
        #expect(try await f.owner.observePrepareStorage(f.arm) == f.observed)
        #expect(!f.transport.cancelled.withLock { $0 })
        await f.owner.close()
    }

    @Test func prepareLaneDoesNotWaitForChildWorkloadQueue() async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        let context = try f.owner.workloadSession().context
        let gate = Existing.ReplyGate(); defer { gate.release.signal() }
        f.peer.state.withLock { $0.workloadGate = gate }
        let workload = Task {
            defer { gate.prepared.continuation.finish() }
            return try await f.owner.workloadControl(.query, context: context)
        }
        var entered = false
        for await _ in gate.prepared.stream { entered = true; break }
        try #require(entered)
        _ = try await f.owner.armPrepareStorage(f.arm.arm)
        #expect(try await f.owner.observePrepareStorage(f.arm) == f.observed)
        _ = try await f.owner.releasePrepareStorage(f.release, arm: f.arm)
        gate.release.signal()
        _ = try await workload.value
        await f.owner.close()
    }

    @Test(arguments: [W.Command.serviceStatus, .notifications, .prepareCompatibilityArm])
    func suspendedRetireAllowsPrivatePrepareRelease(_ alreadyActive: W.Command) async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        let context = try f.owner.workloadSession().context
        let before = try f.owner.snapshot(), id = Existing.id()
        let request = ManagedStorageControlProtocol.ControlRequest.retire(try .init(operation: id,
            store: context.store, volume: id, attachment: id, launch: id))
        let receipt = try ManagedStorageControlProtocol.Receipt(schema: 3, store: context.store,
            volume: id, attachment: id, launch: id, revision: 2)
        let bytes = try ControllerJSON.object(["id": .number(1), "receipt": ControllerJSON.from(receipt)]).bytes()
        let expectedRequest = try request.durableBytes()
        let gate = Existing.ReplyGate(), completed = Mutex(false)
        defer { gate.release.signal(); f.transport.suspended = false }
        f.peer.state.withLock { $0.workloadResponder = { actual in
            #expect((try? actual.durableBytes()) == expectedRequest)
            gate.holdReply()
            completed.withLock { $0 = true }
            return bytes
        } }
        // An already admitted private command must not deny Retire either.
        f.transport.suspended = true
        let privateCommand = Task {
            if alreadyActive == .prepareCompatibilityArm { _ = try await f.owner.armPrepareStorage(f.arm.arm) }
            else { try await f.readOnlyCommand(alreadyActive) }
        }
        try await f.waitForCommands(1)
        let retire = Task {
            defer { gate.prepared.continuation.finish() }
            return try await f.owner.workloadControl(request, context: context)
        }
        var entered = false
        for await _ in gate.prepared.stream { entered = true; break }
        try #require(entered)
        #expect(!completed.withLock { $0 })
        await #expect(throws: Owner.Failure.self) { _ = try await f.owner.workloadControl(.query, context: context) }
        await #expect(throws: Owner.Failure.self) { try await f.owner.stageRetire() }
        f.transport.suspended = false
        try await privateCommand.value
        try await f.readOnlyCommand(.serviceStatus)
        try await f.readOnlyCommand(.notifications)
        _ = try await f.owner.armPrepareStorage(f.arm.arm)
        #expect(try await f.owner.observePrepareStorage(f.arm) == f.observed)
        #expect(!completed.withLock { $0 })
        // Only the actual private release command opens the blocked child reply.
        // No timeout (or timeout error treated as success) can complete Retire.
        f.transport.onPrepareRelease = { gate.release.signal() }
        let released = try await f.owner.releasePrepareStorage(f.release, arm: f.arm)
        #expect(released.state == "released")
        guard case .receipt(let actual) = try await retire.value else {
            Issue.record("missing Retire receipt after PREPARE release"); await f.owner.close(); return
        }
        #expect(actual == receipt && completed.withLock { $0 })
        #expect(try f.owner.snapshot() == before)
        #expect(f.peer.state.withLock { $0.workloadRequests } == 1)
        await f.owner.close()
    }

    @Test(arguments: [W.Command.serviceStatus, .notifications], ["child-proof", "transport-connect"])
    func workerLossDuringRetireReconnectNeverRevivesGeneration(_ command: W.Command, _ suspension: String) async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        let context = try f.owner.workloadSession().context
        let before = try f.owner.snapshot(), id = Existing.id()
        let request = ManagedStorageControlProtocol.ControlRequest.retire(try .init(operation: id,
            store: context.store, volume: id, attachment: id, launch: id))
        let receipt = try ManagedStorageControlProtocol.Receipt(schema: 3, store: context.store,
            volume: id, attachment: id, launch: id, revision: 2)
        let bytes = try ControllerJSON.object(["id": .number(1), "receipt": ControllerJSON.from(receipt)]).bytes()
        let expectedRequest = try request.durableBytes(), calls = Mutex(0)
        f.peer.state.withLock { $0.workloadResponder = { actual in
            #expect((try? actual.durableBytes()) == expectedRequest)
            if calls.withLock({ $0 += 1; return $0 == 1 }) {
                throw StorageLifecycleChildProcess.Failure.serviceUnavailable
            }
            // A regressed reconnect receives a valid receipt, not a second loss
            // that could hide the revived-generation bug by fencing it again.
            return bytes
        } }
        let gate = Existing.ReplyGate()
        defer { gate.release.signal(); f.transport.suspendWorkloadConnection = false }
        let initialConnections = f.transport.base.workloadConnections
        f.peer.state.withLock {
            $0.workloadEvents = []
            $0.revokeOnServiceResult = true
            if suspension == "child-proof" { $0.workloadConnect = { gate.holdReply() } }
        }
        f.transport.suspendWorkloadConnection = suspension == "transport-connect"
        let retire = Task {
            defer {
                gate.prepared.continuation.finish()
                f.transport.workloadConnectionEntered.continuation.finish()
            }
            return try await f.owner.workloadControl(request, context: context)
        }
        let entered = suspension == "child-proof" ? gate.prepared.stream : f.transport.workloadConnectionEntered.stream
        var suspended = false
        for await _ in entered { suspended = true; break }
        try #require(suspended)
        #expect(calls.withLock { $0 } == 1)
        #expect(f.peer.state.withLock { $0.workloadEvents } == (suspension == "child-proof" ? ["transport", "child"] : []))
        // Preflight must have released its lane before child/workload reconnect:
        // a concurrent PREPARE release still has to reach the retained service.
        _ = try await f.owner.releasePrepareStorage(f.release, arm: f.arm)
        // The real owner validates binding, sequence, service epoch and worker
        // on this independent private-command reply before clearing admission.
        f.transport.workerLost = true
        do {
            try await f.readOnlyCommand(command)
            Issue.record("authenticated worker loss was accepted")
        } catch ManagedStorageControlFailure.serviceUnavailable { }
        #expect(f.transport.frames.compactMap(\.command) == [.serviceStatus, .prepareCompatibilityRelease, command])
        #expect(!f.transport.cancelled.withLock { $0 })
        #expect(throws: Owner.Failure.self) { _ = try f.owner.workloadSession() }
        gate.release.signal()
        f.transport.suspendWorkloadConnection = false
        await #expect(throws: Owner.Failure.self) { _ = try await retire.value }
        #expect(calls.withLock { $0 } == 1) // No second exchange or accepted receipt.
        #expect(f.peer.state.withLock { $0.workloadRequests } == 1)
        #expect(f.transport.base.workloadConnections == initialConnections + 1)
        #expect(f.peer.state.withLock { $0.workloadEvents.contains("child") } == (suspension == "child-proof"))
        #expect(!f.peer.state.withLock { $0.rootRevoked || $0.workloadEvents.contains("root-live") })
        #expect(!f.transport.cancelled.withLock { $0 })
        #expect(throws: (any Error).self) { _ = try f.owner.workloadSession() }
        await #expect(throws: (any Error).self) { _ = try await f.owner.queryWorkload() }
        #expect(f.peer.state.withLock { $0.workloadRequests } == 1)
        #expect(try f.owner.snapshot() == before)
        await f.owner.close()
    }

    @Test func readyPreflightThenDeathDuringChildConnectRetainsOwnerForReplacement() async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        let context = try f.owner.workloadSession().context
        let before = try f.owner.snapshot(), journal = try f.owner.journalSnapshot()
        let id = Existing.id(), exit = try f.genericExit()
        let request = ManagedStorageControlProtocol.ControlRequest.retire(try .init(operation: id,
            store: context.store, volume: id, attachment: id, launch: id))
        let expected = try request.durableBytes(), sent = Mutex<[Data]>([])
        let gate = Existing.ReplyGate(); defer { gate.release.signal() }
        let rootRequests = f.peer.state.withLock { $0.requests.count }
        let connections = f.transport.base.workloadConnections
        f.peer.state.withLock {
            // A repeated ROOT proof would revoke the actual retained child.
            $0.revokeOnServiceResult = true
            $0.workloadEvents = []
            $0.workloadResponder = { actual in
                try sent.withLock { $0.append(try actual.durableBytes()) }
                throw StorageLifecycleChildProcess.Failure.serviceUnavailable
            }
            $0.workloadConnect = {
                gate.holdReply()
                throw StorageLifecycleChildProcess.Failure.workloadFailed
            }
        }
        let retire = Task {
            defer { gate.prepared.continuation.finish() }
            return try await f.owner.workloadControl(request, context: context)
        }
        var entered = false
        for await _ in gate.prepared.stream { entered = true; break }
        try #require(entered)
        // Ready was true, but neither it nor EOF promises the worker survives.
        #expect(f.transport.frames.compactMap(\.command) == [.serviceStatus])
        #expect(f.peer.state.withLock { $0.workloadEvents } == ["transport", "child"])
        _ = try await f.owner.releasePrepareStorage(f.release, arm: f.arm)
        let wait = try await f.owner.exitCheckpointWorker(exit)
        #expect(K.sameClaim(wait.claim, exit) && wait.reaped && wait.exitCode == 74)
        f.transport.workerLost = true
        gate.release.signal()
        do { _ = try await retire.value; Issue.record("connect failure granted a receipt") }
        catch StorageLifecycleChildProcess.Failure.workloadFailed { }
        // Only a fresh authenticated private status after connect failure retains
        // lifecycle authority; the old ready observation is not death authority.
        #expect(f.transport.frames.compactMap(\.command) == [.serviceStatus,
            .prepareCompatibilityRelease, .prepareCompatibilityCheckpointExit, .serviceStatus])
        #expect(!f.transport.cancelled.withLock { $0 })
        #expect(!f.peer.state.withLock { $0.rootRevoked })
        #expect(f.peer.state.withLock { $0.requests.count } == rootRequests)
        #expect(sent.withLock { $0 } == [expected])
        #expect(f.transport.base.workloadConnections == connections + 1)
        let replacement = StorageServiceTypes.ReplacementRequest(operationUUID: Existing.id(),
            predecessor: .init(serviceEpoch: context.serviceEpoch, workerUUID: f.arm.workerUUID), nowUnixSeconds: 1_800_000_000)
        try await f.owner.awaitServiceReplacementAdmission(replacement)
        await #expect(throws: Owner.Failure.self) { try await f.owner.connectWorkload() }
        await #expect(throws: Owner.Failure.self) { _ = try await f.owner.queryWorkload() }
        #expect(sent.withLock { $0 } == [expected])
        #expect(try f.owner.snapshot() == before)
        let after = try f.owner.journalSnapshot()
        #expect(after.revision == journal.revision && after.intents == journal.intents && after.volumes == journal.volumes)
        await f.owner.close()
    }

    @Test(arguments: ["query", "retire", "retire-clean-eof", "retire-failed"])
    func workloadFailureJoinsCheckpointWaitBeforeAuthenticatedLoss(_ operation: String) async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        defer { f.transport.suspended = false; f.transport.suspendStatus = false }
        let context = try f.owner.workloadSession().context, before = try f.owner.snapshot()
        let journal = try f.owner.journalSnapshot(), exit = try f.genericExit(), id = Existing.id()
        let request: ManagedStorageControlProtocol.ControlRequest = operation != "query"
            ? .retire(try .init(operation: id, store: context.store, volume: id, attachment: id, launch: id)) : .query
        f.transport.suspended = true
        f.transport.suspendStatus = true
        let checkpoint = Task { try await f.owner.exitCheckpointWorker(exit) }
        try await f.waitForCommands(1)
        f.peer.state.withLock {
            // Model the real ROOT side effect, not merely a failed proof reply.
            $0.revokeOnServiceResult = true
            $0.workloadResponder = { _ in
                if operation == "retire-clean-eof" { throw StorageLifecycleChildProcess.Failure.serviceUnavailable }
                if operation == "retire-failed" { throw StorageLifecycleChildProcess.Failure.workloadFailed }
                throw Owner.Failure.incomplete
            }
        }
        let connections = f.transport.base.workloadConnections
        f.peer.state.withLock { $0.workloadEvents = [] }
        let workload = Task { try await f.owner.workloadControl(request, context: context) }
        if operation == "retire-clean-eof" {
            // Retire owns workload admission while its preflight joins PID1 Wait.
            let deadline = ContinuousClock.now + .seconds(2)
            while f.peer.state.withLock({ $0.workloadRequests }) == 0 {
                guard ContinuousClock.now < deadline else { throw Owner.Failure.blocked }
                try await Task.sleep(for: .milliseconds(1))
            }
        } else { try await f.waitForWorkloadFence() }
        // The private PID1 Wait must survive either workload failure path.
        #expect(!f.transport.cancelled.withLock { $0 })
        #expect(f.transport.frames.compactMap(\.command) == [.prepareCompatibilityCheckpointExit])
        await #expect(throws: Owner.Failure.self) { try await f.owner.connectWorkload() }
        await #expect(throws: Owner.Failure.self) { _ = try await f.owner.workloadControl(.query, context: context) }
        f.transport.suspended = false
        let wait = try await checkpoint.value
        #expect(K.sameClaim(wait.claim, exit) && wait.exitCode == 74 && wait.reaped)
        try await f.waitForCommands(2)
        #expect(f.transport.frames.compactMap(\.command) == [.prepareCompatibilityCheckpointExit, .serviceStatus])
        // Neither EOF nor the successful Wait has established authenticated loss.
        #expect(try await f.owner.retirementNotifications().isEmpty)
        #expect(!f.transport.cancelled.withLock { $0 })
        f.transport.workerLost = true
        f.transport.suspendStatus = false
        do { _ = try await workload.value; Issue.record("workload failure was swallowed") }
        catch Owner.Failure.incomplete { }
        catch StorageLifecycleChildProcess.Failure.workloadFailed { #expect(operation == "retire-failed") }
        catch StorageLifecycleChildProcess.Failure.serviceUnavailable { #expect(operation == "retire-clean-eof") }
        #expect(!f.transport.cancelled.withLock { $0 })
        #expect(f.transport.frames.compactMap(\.command) == [.prepareCompatibilityCheckpointExit, .serviceStatus])
        #expect(!f.peer.state.withLock { $0.rootRevoked })
        do { _ = try await f.owner.retirementNotifications(); Issue.record("authenticated loss was not surfaced") }
        catch ManagedStorageControlFailure.serviceUnavailable { }
        #expect(f.transport.frames.compactMap(\.command).last == .notifications)
        let replacement = StorageServiceTypes.ReplacementRequest(operationUUID: Existing.id(),
            predecessor: .init(serviceEpoch: context.serviceEpoch, workerUUID: f.arm.workerUUID), nowUnixSeconds: 1_800_000_000)
        try await f.owner.awaitServiceReplacementAdmission(replacement)
        await #expect(throws: Owner.Failure.self) { try await f.owner.connectWorkload() }
        await #expect(throws: Owner.Failure.self) { _ = try await f.owner.queryWorkload() }
        #expect(f.peer.state.withLock { $0.workloadRequests } == 1)
        #expect(f.transport.base.workloadConnections == connections)
        #expect(f.peer.state.withLock { $0.workloadEvents }.isEmpty)
        #expect(try f.owner.snapshot() == before)
        let after = try f.owner.journalSnapshot()
        #expect(after.revision == journal.revision && after.intents == journal.intents && after.volumes == journal.volumes)
        await f.owner.close()
    }

    @Test(arguments: ["alive", "sequence", "worker", "binding", "epoch", "mixed", "ambiguous", "context", "cancel", "timeout"], [false, true])
    func uncertainWorkloadRetainsOwnerOnlyForExactWorkerLoss(_ fault: String, _ cleanEOF: Bool) async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        defer { f.transport.suspendStatus = false }
        let context = try f.owner.workloadSession().context
        f.transport.suspendStatus = true
        f.transport.workerLost = fault != "alive"
        f.peer.state.withLock {
            $0.revokeOnServiceResult = true
            $0.workloadResponder = { _ in
                if cleanEOF { throw StorageLifecycleChildProcess.Failure.serviceUnavailable }
                throw Owner.Failure.incomplete
            }
        }
        let id = Existing.id()
        let request: ManagedStorageControlProtocol.ControlRequest = cleanEOF
            ? .retire(try .init(operation: id, store: context.store, volume: id, attachment: id, launch: id)) : .query
        let workload = Task { try await f.owner.workloadControl(request, context: context) }
        try await f.waitForCommands(1)
        #expect(f.transport.frames.compactMap(\.command) == [.serviceStatus])
        #expect(!f.transport.cancelled.withLock { $0 })
        if fault == "cancel" { workload.cancel() }
        else if fault == "context" {
            try Data("changed".utf8).write(to: f.disk.url.appending(path: "managed-storage-owner/state.json"))
        } else { f.transport.fault = fault }
        f.transport.suspendStatus = false
        do { _ = try await workload.value; Issue.record("workload failure was swallowed") }
        catch Owner.Failure.incomplete { #expect(!cleanEOF || fault == "alive") }
        catch StorageLifecycleChildProcess.Failure.serviceUnavailable { #expect(cleanEOF) }
        #expect(f.transport.cancelled.withLock { $0 })
        if cleanEOF && fault != "alive" {
            #expect(f.transport.frames.compactMap(\.command) == [.serviceStatus])
            #expect(!f.peer.state.withLock { $0.rootRevoked })
        }
        await #expect(throws: (any Error).self) { _ = try await f.owner.retirementNotifications() }
        await #expect(throws: (any Error).self) { try await f.owner.connectWorkload() }
        let replacement = StorageServiceTypes.ReplacementRequest(operationUUID: Existing.id(),
            predecessor: .init(serviceEpoch: context.serviceEpoch, workerUUID: f.arm.workerUUID), nowUnixSeconds: 1_800_000_000)
        await #expect(throws: (any Error).self) { try await f.owner.awaitServiceReplacementAdmission(replacement) }
        #expect(f.peer.state.withLock { $0.workloadRequests } == (cleanEOF && fault == "alive" ? 2 : 1))
        #expect(!f.peer.state.withLock { $0.rootRevoked })
        await f.owner.close()
    }

    @Test(arguments: [W.Command.serviceStatus, .notifications], ["alive", "sequence", "non-loss-code"])
    func retainedWorkerLossRejectsContradictoryObservation(_ command: W.Command, _ fault: String) async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        let context = try f.owner.workloadSession().context
        f.transport.workerLost = true
        f.peer.state.withLock { $0.workloadResponder = { _ in throw Owner.Failure.incomplete } }
        do { _ = try await f.owner.workloadControl(.query, context: context); Issue.record("workload failure was swallowed") }
        catch Owner.Failure.incomplete { }
        #expect(!f.transport.cancelled.withLock { $0 })
        f.transport.workerLost = fault != "alive"
        f.transport.fault = fault
        await #expect(throws: (any Error).self) { try await f.readOnlyCommand(command) }
        #expect(f.transport.cancelled.withLock { $0 })
        await #expect(throws: (any Error).self) { try await f.owner.connectWorkload() }
        await f.owner.close()
    }

    @Test func cancelledQueuedMutationSendsNothingAndDoesNotCancelOwner() async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        f.transport.suspended = true
        let active = Task { try await f.owner.armPrepareStorage(f.arm.arm) }
        try await f.waitForCommands(1)
        let queued = Task { try await f.owner.releasePrepareStorage(f.release, arm: f.arm) }
        await Task.yield(); queued.cancel()
        f.transport.suspended = false
        _ = try await active.value
        await #expect(throws: CancellationError.self) { _ = try await queued.value }
        #expect(f.transport.frames.count == 1 && !f.transport.cancelled.withLock { $0 })
        #expect(try await f.owner.observePrepareStorage(f.arm) == f.observed)
        await f.owner.close()
    }

    @Test func zeroDeadlineSendsNothingAndInFlightDeadlineInterruptsIO() async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        await #expect(throws: AsyncTimeout.TimeoutError.self) {
            _ = try await f.owner.observePrepareStorage(f.arm, deadlineNanoseconds: 0)
        }
        #expect(f.transport.frames.isEmpty && !f.transport.cancelled.withLock { $0 })
        #expect(try await f.owner.observePrepareStorage(f.arm) == f.observed)
        f.transport.suspended = true
        let start = DispatchTime.now().uptimeNanoseconds
        await #expect(throws: (any Error).self) {
            _ = try await f.owner.observePrepareStorage(f.arm, deadlineNanoseconds: start + 50_000_000)
        }
        #expect(DispatchTime.now().uptimeNanoseconds - start < 2_000_000_000)
        #expect(f.transport.cancelled.withLock { $0 })
        await f.owner.close()
    }

    @Test(arguments: ["cancel", "stale-owner"])
    func refusesLateReplyAfterCancellationOrPhysicalOwnerChange(_ fault: String) async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        f.transport.suspended = true
        let call = Task { try await f.owner.observePrepareStorage(f.arm) }
        try await f.waitForCommands(1)
        if fault == "cancel" { call.cancel() }
        else {
            try Data("invalid".utf8).write(to: f.disk.url.appending(path: "managed-storage-owner/state.json"))
            f.transport.suspended = false
        }
        await #expect(throws: (any Error).self) { _ = try await call.value }
        await #expect(throws: (any Error).self) { _ = try await f.owner.observePrepareStorage(f.arm) }
        await f.owner.close()
    }

    @MainActor final class Fixture {
        let disk: Existing.Disk
        let peer: Existing.Peer
        let owner: Owner
        let transport: Transport
        let arm: C.StorageArm
        let observed: C.StorageStatus
        let release: C.StorageRelease
        init(stage: String = "admitted-queued") async throws {
            disk = try Existing.Disk(); peer = try Existing.Peer(disk.binding)
            owner = try disk.owner(peer)
            transport = Transport(base: Existing.Transport(peer: peer, root: disk.root))
            try await owner.provisionFresh()
            try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding,
                nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
            try await owner.connectWorkload()
            _ = try owner.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator())
            struct Vector: Decodable { let name: String; let storageArm: C.StorageArm? }
            let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            let vectors = try JSONDecoder().decode([Vector].self,
                from: Data(contentsOf: root.appending(path: "Guest/internal/preparecompat/testdata/full-vectors.json")))
            var selected = try #require(vectors.first { $0.name == stage }?.storageArm)
            let session = try owner.workloadSession()
            selected.workerUUID = session.service.ready.workerUUID
            selected.arm.scope.store = session.context.store; selected.arm.scope.serviceEpoch = session.context.serviceEpoch
            selected.arm.scope.controllerEpoch = session.context.controllerEpoch; selected.arm.scope.controllerKey = session.context.controllerKey
            arm = selected
            let query = try C.query(selected)
            observed = C.StorageStatus(query: query, state: "observed", acceptedInFlight: stage == "admitted-queued" ? 1 : 0,
                observation: .init(requestID: query.requestID, armDigest: query.armDigest, workerUUID: query.workerUUID,
                    stage: selected.arm.caseName, targetAttachment: selected.arm.targetAttachment,
                    admission: .init(requestSequence: 7, admitted: stage == "admitted-queued", releaseToken: String(repeating: "a", count: 64))))
            release = .init(query: query, stage: selected.arm.caseName, token: String(repeating: "a", count: 64))
            transport.observed = observed
            try C.validateStorageWorkerExit(release, arm: arm, checkpoint: observed)
        }
        func genericExit() throws -> K.WorkerCheckpointExit {
            var value = arm.arm; value.caseName = "before-prepare-send"
            let early = C.EarlyObservation(version: 3, profile: C.fullProfile, requestID: value.requestID,
                armDigest: try C.digest(value), stage: value.caseName, count: 1, targetAttachment: value.targetAttachment,
                requestSequence: 8, prepareCommandsSent: 0, prepareCommandsAccepted: 0, dataBytesWritten: 0)
            return .init(arm: value, earlyCheckpoint: early, workerUUID: arm.workerUUID)
        }
        func readOnlyCommand(_ command: W.Command) async throws {
            if command == .serviceStatus {
                try await owner.validateServiceAvailability(.init(serviceEpoch: arm.arm.scope.serviceEpoch,
                    workerUUID: arm.workerUUID))
            } else {
                #expect(try await owner.retirementNotifications().isEmpty)
            }
        }
        func waitForWorkloadFence() async throws {
            let deadline = ContinuousClock.now + .seconds(2)
            while (try? owner.workloadSession()) != nil {
                guard ContinuousClock.now < deadline else { throw Owner.Failure.blocked }
                try await Task.sleep(for: .milliseconds(1))
            }
        }
        func waitForCommands(_ count: Int) async throws {
            let deadline = ContinuousClock.now + .seconds(2)
            while transport.frames.count < count {
                guard ContinuousClock.now < deadline else { throw Owner.Failure.blocked }
                try await Task.sleep(for: .milliseconds(1))
            }
        }
    }

    @MainActor final class Transport: ManagedStorageLifecycleServiceTransport {
        let base: Existing.Transport
        nonisolated let cancelled = Mutex(false)
        var frames: [W.Frame] = []
        var observed: C.StorageStatus?
        var suspended = false
        var workerLost = false
        var suspendStatus = false
        var suspendWorkloadConnection = false
        let workloadConnectionEntered = AsyncStream<Void>.makeStream()
        var onPrepareRelease: (() -> Void)?
        var fault: String?
        init(base: Existing.Transport) { self.base = base }
        nonisolated func cancel() { cancelled.withLock { $0 = true } }
        func configure(_ configuration: W.Configuration) async throws -> ManagedStorageLifecycleServiceReady {
            try await base.configure(configuration)
        }
        func connectLifecycle() async throws -> FileHandle { try await base.connectLifecycle() }
        func connectWorkload() async throws -> FileHandle {
            if suspendWorkloadConnection {
                workloadConnectionEntered.continuation.yield(())
                while suspendWorkloadConnection {
                    if cancelled.withLock({ $0 }) { throw CancellationError() }
                    try await Task.sleep(for: .milliseconds(1))
                }
            }
            return try await base.connectWorkload()
        }
        func connectAttachmentCSR() async throws -> FileHandle { try await base.connectAttachmentCSR() }
        func command(_ frame: W.Frame) async throws -> W.Frame {
            guard let observed else { return try await base.command(frame) }
            frames.append(frame)
            while suspended || (frame.command == .serviceStatus && suspendStatus) {
                if cancelled.withLock({ $0 }) { throw CancellationError() }
                try await Task.sleep(for: .milliseconds(1))
            }
            var reply = W.Frame(operation: .reply, binding: frame.binding, sequence: frame.sequence,
                serviceEpoch: frame.serviceEpoch, workerUUID: frame.workerUUID)
            switch frame.command {
            case .serviceStatus: reply.status = .init(phase: workerLost ? .workerLost : .ready)
            case .notifications:
                if workerLost { reply.code = .workerLost }
                else { reply.notifications = [] }
            case .prepareCompatibilityArm:
                reply.prepareCompatibilityStatus = .init(query: observed.query, state: "armed")
            case .prepareCompatibilityObserve: reply.prepareCompatibilityStatus = observed
            case .prepareCompatibilityRelease:
                var released = observed; released.state = "released"; reply.prepareCompatibilityStatus = released
                onPrepareRelease?()
            case .prepareCompatibilityWorkerExit:
                let exit = try #require(frame.prepareCompatibilityWorkerExit)
                reply.prepareCompatibilityWorkerWait = .init(query: exit.query, stage: exit.stage, token: exit.token,
                    requestSequence: 7, workerPID: 42, exitCode: 74, reaped: true)
            case .prepareCompatibilityCheckpointExit:
                let exit = try #require(frame.prepareCompatibilityCheckpointExit)
                reply.prepareCompatibilityCheckpointWait = .init(arm: exit.arm, checkpoint: exit.checkpoint,
                    earlyCheckpoint: exit.earlyCheckpoint, storageCheckpoint: exit.storageCheckpoint,
                    workerUUID: exit.workerUUID, workerPID: 42, exitCode: 74, reaped: true)
            default: throw Owner.Failure.invalid
            }
            switch fault {
            case "non-loss-code": reply.status = nil; reply.notifications = nil; reply.code = .workerBusy
            case "timeout": throw AsyncTimeout.TimeoutError()
            case "ambiguous": reply.status = .init(phase: .failed)
            case "sequence": reply.sequence = (frame.sequence ?? 0) + 1
            case "worker": reply.workerUUID = UUID().uuidString.lowercased()
            case "binding": reply.binding.guestBootNonce = UUID().uuidString.lowercased()
            case "epoch": reply.serviceEpoch = UUID().uuidString.lowercased()
            case "refused": reply.prepareCompatibilityWorkerWait = nil; reply.code = .command
            case "mixed": reply.code = .command
            case "token": reply.prepareCompatibilityWorkerWait?.token = String(repeating: "b", count: 64)
            case "wait-sequence": reply.prepareCompatibilityWorkerWait?.requestSequence = 8
            case "checkpoint": reply.prepareCompatibilityCheckpointWait?.earlyCheckpoint?.requestSequence = 9
            default: break
            }
            return reply
        }
    }
}
#endif

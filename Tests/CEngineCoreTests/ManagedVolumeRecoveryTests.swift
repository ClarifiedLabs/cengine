#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

@Suite @MainActor struct ManagedVolumeRecoveryTests {
    @Test(arguments: [false, true])
    func optionalLiveAuditCannotConsumePreviouslyReservedCapacity(previousAudit: Bool) throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        let oldAudit = previousAudit ? Data("previous-public-audit".utf8) : nil
        do {
            let journal = try f.initialize()
            try journal.reconciled()
            if let oldAudit { try journal.recordLiveAdoptionEvidence(oldAudit) }
            // 168 volumes fit the existing worst-case reservation, but leave less
            // than one maximum audit record. No admission limit is relaxed.
            let volumes: [HostStorageIntents.Volume] = (0..<168).map {
                .init(id: HostIntentFixture.id(), name: "reserved-\($0)",
                    createOperation: HostIntentFixture.id(), deleteOperation: HostIntentFixture.id())
            }
            try journal.planVolumes(volumes)
            let before = try journal.snapshot()
            let directory = try f.root.openDirectory(named: "managed-storage")
            let bytes = try directory.readRegularFile(named: "state.json")
            try journal.recordLiveAdoptionEvidence(Data(repeating: 0x61, count: HostStorageIntents.maximumBytes / 16))
            #expect(try journal.snapshot() == before)
            #expect(try directory.readRegularFile(named: "state.json") == bytes)
            #expect(Set(try directory.entryNames()) == ["lease", "manifest.json", "state.json"])
        }
        let reopened = try f.open()
        #expect(try reopened.snapshot().reconciliationRequired)
        #expect(try reopened.snapshot().liveAdoptionEvidence == oldAudit)
        #expect(throws: (any Error).self) { try reopened.recordLiveAdoptionEvidence(Data([1])) }
        try reopened.reconciled()
        try reopened.recordLiveAdoptionEvidence(Data([1]))
        #expect(try reopened.snapshot().liveAdoptionEvidence == Data([1]))
    }

    @Test func liveAuditEnforcesBoundsAndCannotClearReconciliationFence() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        let journal = try f.initialize()
        #expect(throws: (any Error).self) { try journal.recordLiveAdoptionEvidence(Data([1])) }
        try journal.reconciled()
        for evidence in [Data(), Data(repeating: 1, count: HostStorageIntents.maximumBytes / 16 + 1)] {
            let before = try journal.snapshot()
            #expect(throws: (any Error).self) { try journal.recordLiveAdoptionEvidence(evidence) }
            #expect(try journal.snapshot() == before)
        }
        let maximum = Data(repeating: 1, count: HostStorageIntents.maximumBytes / 16)
        try journal.recordLiveAdoptionEvidence(maximum)
        #expect(try journal.snapshot().liveAdoptionEvidence == maximum)
        try journal.requireReconciliation()
        #expect(throws: (any Error).self) { try journal.recordLiveAdoptionEvidence(Data([2])) }
        #expect(try journal.snapshot().reconciliationRequired)
        #expect(try journal.snapshot().liveAdoptionEvidence == maximum)
    }

    @Test(arguments: ["beforeMarker", "afterMarker", "afterState", "beforeUnmark", "afterUnmark"], [false, true])
    func optionalLiveAuditNeverSwallowsPersistenceFailure(boundary: String, capacityError: Bool) throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        var armed = false
        let journal = try f.initialize { point in
            if armed, String(describing: point) == boundary {
                throw capacityError ? HostStorageIntents.Failure.capacity : HostStorageIntents.Failure.persistence
            }
        }
        try journal.reconciled()
        armed = true
        #expect(throws: (any Error).self) { try journal.recordLiveAdoptionEvidence(Data([1])) }
        // Even a hook reporting .capacity after entering persistence is poisoned;
        // it cannot be treated as a harmless pre-write admission refusal.
        #expect(throws: (any Error).self) { _ = try journal.snapshot() }
    }

    @Test func liveRegistryValidationKeepsOriginalContextAndRetirementOperations() async throws {
        let f = try RecoveryFixture(); defer { f.files.remove() }
        let token = try await f.coordinator.start(f.plan, guest: f.guest)
        let intent = try f.journal.intent(token), state = try f.journal.snapshot()
        let c2 = try ManagedStorageControlClient.Context(store: intent.store, serviceEpoch: intent.serviceEpoch,
            controllerEpoch: intent.controllerEpoch + 1, controllerKey: String(repeating: "9", count: 64),
            provenanceReference: f.files.provenance)
        let current = f.control.copy(context: c2)
        guard case .snapshot(let snapshot) = try current.send(.query) else { Issue.record("snapshot absent"); return }
        try ManagedVolumeLifecycleCoordinator.validateLiveRuntime(intent, state: state, snapshot: snapshot, context: c2)
        #expect(try f.journal.intent(token) == intent) // Never promote C1 or mutate A keys.
        #expect(try f.journal.snapshot() == state)
        for slot in intent.slots where slot.role == "runtime" {
            let request = ManagedStorageControlProtocol.ControlRequest.retire(try .init(operation: slot.retireOperation,
                store: intent.store, volume: slot.volume, attachment: slot.attachment, launch: intent.launch))
            guard case .receipt(let first) = try current.send(request),
                  case .receipt(let second) = try current.send(request) else { Issue.record("retirement absent"); return }
            #expect(first == second && first.attachment == slot.attachment)
            #expect(current.attempts(for: slot.retireOperation).allSatisfy { $0 == (try? request.durableBytes()) })
        }
    }

    @Test(arguments: ["phase", "prepare", "clean", "completion", "quarantine", "register", "retire", "receipt", "epoch", "scope", "mounts", "terminal"])
    func liveAdoptionRejectsIncompleteOrChangedEvidence(fault: String) async throws {
        let f = try RecoveryFixture(); defer { f.files.remove() }
        let token = try await f.coordinator.start(f.plan, guest: f.guest)
        var intent = try f.journal.intent(token), state = try f.journal.snapshot()
        guard case .snapshot(let snapshot) = try f.control.send(.query) else { Issue.record("snapshot absent"); return }
        let runtime = try #require(intent.slots.firstIndex { $0.role == "runtime" })
        var context = f.control.context
        switch fault {
        case "phase": intent.phase = .runtimeFrozen
        case "prepare": intent.prepareCompleted = false
        case "clean": intent.cleanUnmount = false
        case "completion": intent.guestCompletion = nil
        case "quarantine": intent.quarantineReason = "unresolved"
        case "register": state.operations.removeValue(forKey: intent.slots[runtime].registerOperation)
        case "retire": state.operations[intent.slots[runtime].retireOperation] = Data([1])
        case "receipt": intent.slots[0].receipt = nil
        case "epoch": context = try .init(store: intent.store, serviceEpoch: HostIntentFixture.id(),
            controllerEpoch: intent.controllerEpoch, controllerKey: intent.controllerKey, provenanceReference: f.files.provenance)
        default:
            var reply = WorkloadStorageProtocol.Frame(operation: .reply,
                binding: .init(shimLaunchUUID: intent.launch, guestBootNonce: HostIntentFixture.id()),
                scope: RawManagedStorageBackend.scope(intent), sequence: 99, kind: .status,
                data: .init(phase: .running, mountedIDs: intent.slots.filter { $0.role == "runtime" }.map(\.attachment), terminalIDs: []))
            try ManagedVolumeLifecycleCoordinator.LiveRuntimePermit.validateStatus(reply, intent: intent)
            if fault == "scope" { reply.scope?.controllerEpoch += 1 }
            if fault == "mounts" { reply.data.mountedIDs = [] }
            if fault == "terminal" { reply.data.terminalIDs = [intent.slots[runtime].attachment] }
            #expect(throws: (any Error).self) { try ManagedVolumeLifecycleCoordinator.LiveRuntimePermit.validateStatus(reply, intent: intent) }
            return
        }
        #expect(throws: (any Error).self) {
            try ManagedVolumeLifecycleCoordinator.validateLiveRuntime(intent, state: state, snapshot: snapshot, context: context)
        }
    }

    @Test func prelaunchCreateFailureSettlesOnlyWithDurableCancelledBoundaryAcrossReopen() async throws {
        for accepted in [false, true] {
            let f = try RecoveryFixture(); defer { f.files.remove() }
            f.control.fail("create", afterAcceptance: accepted)
            do { _ = try await f.coordinator.start(f.plan, guest: f.guest) } catch {}
            #expect(try f.journal.intent(f.journal.token(for: f.plan.id)).launchBoundary == .planned)
            try f.reopen()
            let settled = try await f.coordinator.settleExecution(f.plan.id, in: f.files.root)
            #expect(settled.status == .neverLaunched)
            let intent = try f.journal.intent(settled.token)
            #expect(intent.phase == .unlaunched && intent.isTerminal)
            #expect(intent.launchBoundary == .cancelled && !intent.prepareCompleted)
            #expect(intent.slots.allSatisfy { $0.key == nil && $0.receipt == nil })
            #expect(!f.control.events.contains("reserve") && !f.control.events.contains("complete"))
            try await f.coordinator.reconcileStartup()
            try f.reopen()
            #expect(try f.journal.intent(f.journal.token(for: f.plan.id)) == intent)
            try await f.coordinator.reconcileStartup()
            _ = try await f.coordinator.start(f.newPlan(), guest: f.guest)
        }
    }

    @Test func callbackEntryIsDurableAttemptEvenWhenNoShimRecordWasPublished() async throws {
        let f = try RecoveryFixture(); defer { f.files.remove() }
        let guest = f.guest
        let interrupted = ManagedVolumeLifecycleCoordinator.GuestActions(offerKeys: { intent, _ in
            #expect(intent.launchBoundary == .attempted)
            #expect(try f.journal.intent(f.journal.token(for: intent.id)).launchBoundary == .attempted)
            throw ManagedVolumeLifecycleCoordinator.Failure.blocked
        }, credentialAndMount: guest.credentialAndMount, prepare: guest.prepare,
            closePrepare: guest.closePrepare, start: guest.start, beforePublication: guest.beforePublication)
        do { _ = try await f.coordinator.start(f.plan, guest: interrupted); Issue.record("interrupted callback succeeded") } catch {}
        try f.reopen()
        #expect(try f.journal.intent(f.journal.token(for: f.plan.id)).launchBoundary == .attempted)
        do { _ = try await f.coordinator.settleExecution(f.plan.id, in: f.files.root); Issue.record("missing attempted launch treated as death") } catch {}
        #expect(!f.control.events.contains("reserve"))
        #expect(!f.coordinator.canDelete(volume: f.files.volumes[0].id))
    }

    @Test func drainedFailedPrepareStillRequiresEveryNativeGenerationBeforeCleanup() async throws {
        let f = try RecoveryFixture(); defer { f.files.remove() }
        f.control.fail("register", afterAcceptance: true)
        do { _ = try await f.coordinator.start(f.plan, guest: f.guest) } catch {}
        _ = try await f.coordinator.recover(f.plan.id)
        let old = try f.journal.intent(f.journal.token(for: f.plan.id))
        #expect(old.slots.filter { $0.role == "prepare" }.allSatisfy { $0.receipt != nil })
        #expect(!old.prepareCompleted && old.phase == .quarantined)
        do { _ = try await f.coordinator.settleExecution(f.plan.id, in: f.files.root); Issue.record("drain substituted for native containment") } catch {}
        #expect(try f.journal.intent(f.journal.token(for: f.plan.id)) == old)
        #expect(!f.control.events.contains("complete"))
    }

    @Test func lostAdmissionRepliesReplayOriginalBytesWithoutGuestRestart() async throws {
        for kind in ["reserve", "register", "complete"] {
            for accepted in [false, true] {
                let f = try RecoveryFixture(); defer { f.files.remove() }
                f.control.fail(kind, afterAcceptance: accepted)
                do { _ = try await f.coordinator.start(f.plan, guest: f.guest); Issue.record("lost reply succeeded") } catch {}
                let before = try f.journal.snapshot()
                let token = try await f.coordinator.recover(f.plan.id)
                let recovered = try f.journal.intent(token)
                #expect(recovered.slots.filter { $0.role == "prepare" }.allSatisfy { $0.receipt != nil })
                #expect(recovered.prepareCompleted == (kind == "complete"))
                #expect(recovered.phase == (kind == "complete" ? .retired : .quarantined))
                #expect(try f.journal.snapshot().reconciliationRequired)
                #expect(!f.coordinator.canDelete(volume: f.files.volumes[0].id))
                let after = try f.journal.snapshot()
                for (id, bytes) in before.operations { #expect(after.operations[id] == bytes) }
                #expect(f.control.mismatchedReplay == false)
                #expect(f.control.registerAfterRetirement == 0)
            }
        }
    }

    @Test func lostCreateReplaysExactBytesBeforeReadyEvidenceIncludingReopen() async {
        // Like HostStorageIntentsTests, isolate immediate lease reacquisition from
        // unrelated Darwin fork/pre-exec children retaining CLOEXEC descriptions.
        // The child creates its own journals; no lock retry or early unlock.
        await #expect(processExitsWith: .success) {
            try await ManagedVolumeRecoveryTests().checkLostCreateReplaysExactBytesBeforeReadyEvidenceIncludingReopen()
        }
    }

    private func checkLostCreateReplaysExactBytesBeforeReadyEvidenceIncludingReopen() async throws {
        for accepted in [false, true] {
            for reopen in [false, true] {
                for skip in [0, 1] {
                    let f = try RecoveryFixture(); defer { f.files.remove() }
                    f.control.fail("create", afterAcceptance: accepted, skipping: skip)
                    do { _ = try await f.coordinator.start(f.plan, guest: f.guest); Issue.record("lost create succeeded") } catch {}
                    let before = try f.journal.snapshot()
                    let ids = f.files.volumes.map(\.id).sorted()
                    let failed = try #require(before.volumes[ids[skip]])
                    let bytes = try #require(before.operations[failed.createOperation])
                    #expect(failed.createdRevision == nil)
                    #expect(before.intents[f.plan.id]?.slots.allSatisfy { $0.key == nil } == true)
                    if reopen { try f.reopen() }
                    do { try await f.coordinator.reconcileStartup(); Issue.record("unsettled create reconciled") }
                    catch ManagedVolumeLifecycleCoordinator.Failure.repairRequired {}
                    #expect(try f.journal.snapshot().volumes[failed.id]?.createdRevision == nil)
                    let recovered = try f.journal.intent(await f.coordinator.recover(f.plan.id))
                    #expect(recovered.phase == .quarantined && !recovered.prepareCompleted)
                    #expect(recovered.slots.allSatisfy { $0.key == nil && $0.receipt == nil })
                    let after = try f.journal.snapshot()
                    #expect(after.operations == before.operations)
                    #expect(after.volumes[failed.id]?.rootInode != nil)
                    #expect(f.control.attempts(for: failed.createOperation) == [bytes, bytes])
                    #expect(!f.control.mismatchedReplay)
                    #expect(!f.control.events.contains("reserve"))
                    if skip == 0 {
                        let unattempted = try #require(after.volumes[ids[1]])
                        #expect(unattempted.createdRevision == nil)
                        #expect(after.operations[unattempted.createOperation] == nil)
                        #expect(f.control.attempts(for: unattempted.createOperation).isEmpty)
                    }
                    try await f.coordinator.reconcileStartup()
                    for id in ids { #expect(!f.coordinator.canDelete(volume: id)) }
                    do { _ = try await f.coordinator.start(f.newPlan(), guest: f.guest); Issue.record("unresolved plan replaced") } catch {}
                    // A second journal owner retains the exact create tuple/root.
                    try f.reopen()
                    #expect(try f.journal.snapshot().volumes[failed.id] == after.volumes[failed.id])
                    #expect(try f.journal.replayRequest(operation: failed.createOperation).durableBytes() == bytes)
                }
            }
        }
    }

    @Test func interruptedRuntimeRegistrationReplaysWholeFrozenSetIncludingReopen() async throws {
        for accepted in [false, true] {
            for reopen in [false, true] {
                let f = try RecoveryFixture(); defer { f.files.remove() }
                f.control.fail("register", afterAcceptance: accepted, skipping: f.files.volumes.count)
                do { _ = try await f.coordinator.start(f.plan, guest: f.guest); Issue.record("lost runtime register succeeded") } catch {}
                let before = try f.journal.snapshot()
                let old = try #require(before.intents[f.plan.id])
                let runtime = old.slots.filter { $0.role == "runtime" }
                #expect(old.prepareCompleted)
                #expect(runtime.allSatisfy { $0.key != nil && before.operations[$0.registerOperation] != nil })
                #expect(f.control.attempts(for: runtime[1].registerOperation).isEmpty)
                if reopen { try f.reopen() }
                let recovered = try f.journal.intent(await f.coordinator.recover(f.plan.id))
                #expect(recovered.phase == .retired)
                #expect(recovered.slots.allSatisfy { $0.receipt != nil })
                for slot in runtime {
                    #expect(f.control.attempts(for: slot.registerOperation).allSatisfy { $0 == before.operations[slot.registerOperation] })
                }
                #expect(!f.control.mismatchedReplay && f.control.registerAfterRetirement == 0)
                try await f.coordinator.reconcileStartup()
                for volume in f.files.volumes { #expect(f.coordinator.canDelete(volume: volume.id)) }
                try f.reopen()
                #expect(try f.journal.intent(f.journal.token(for: f.plan.id)) == recovered)
            }
        }
    }

    @Test func prepareFreezeRecoversUnsentOrLostReserveUsingExactBytesAcrossReopen() async throws {
        for send in ["unsent", "beforeAcceptance", "afterAcceptance"] {
            for reopen in [false, true] {
                let f = try RecoveryFixture(); defer { f.files.remove() }
                let token = try f.journal.plan(f.plan)
                for var volume in f.files.volumes {
                    let request = try f.journal.request(for: volume.createOperation)
                    try f.journal.recordOperation(id: volume.createOperation, request: request)
                    guard case .volumeReceipt(let receipt) = try f.control.send(request) else { Issue.record("create failed"); return }
                    volume.rootDevice = receipt.volume.root.device; volume.rootInode = receipt.volume.root.inode
                    volume.createdRevision = receipt.revision; try f.journal.recordVolume(volume)
                }
                _ = try f.journal.freezeKeys(token, role: .prepare, keys: f.files.offeredKeys(for: f.plan))
                let before = try f.journal.snapshot()
                let bytes = try #require(before.operations[f.plan.reserveOperation])
                let reserve = try f.journal.replayRequest(operation: f.plan.reserveOperation)
                #expect(try reserve.durableBytes() == bytes)
                #expect(f.control.attempts(for: f.plan.reserveOperation).isEmpty)
                if send != "unsent" {
                    f.control.fail("reserve", afterAcceptance: send == "afterAcceptance")
                    do { _ = try f.control.send(reserve); Issue.record("lost reserve succeeded") } catch {}
                }
                if reopen { try f.reopen() }
                let recovered = try f.journal.intent(await f.coordinator.recover(f.plan.id))
                #expect(recovered.phase == .quarantined && !recovered.prepareCompleted)
                #expect(recovered.guestCompletion == nil && !recovered.cleanUnmount)
                #expect(recovered.slots.filter { $0.role == "prepare" }.allSatisfy { $0.receipt != nil })
                #expect(recovered.slots.filter { $0.role == "runtime" }.allSatisfy { $0.key == nil && $0.receipt == nil })
                #expect(f.control.attempts(for: f.plan.reserveOperation) == (send == "unsent" ? [bytes] : [bytes, bytes]))
                #expect(!f.control.mismatchedReplay && f.control.registerAfterRetirement == 0)
                #expect(!f.control.events.contains("register") && !f.control.events.contains("complete"))
                for (operation, original) in before.operations {
                    #expect(try f.journal.snapshot().operations[operation] == original)
                }
                #expect(try f.journal.snapshot().reconciliationRequired)
                try await f.coordinator.reconcileStartup()
                for volume in f.files.volumes { #expect(!f.coordinator.canDelete(volume: volume.id)) }
                try f.reopen()
                #expect(try f.journal.intent(f.journal.token(for: f.plan.id)) == recovered)
                #expect(try f.journal.replayRequest(operation: f.plan.reserveOperation).durableBytes() == bytes)
            }
        }
    }

    @Test func prepareFreezeWithoutDurableReserveRemainsExplicitRepairAcrossReopen() async throws {
        let f = try RecoveryFixture(); defer { f.files.remove() }
        let token = try f.journal.plan(f.plan)
        for var volume in f.files.volumes {
            let request = try f.journal.request(for: volume.createOperation)
            try f.journal.recordOperation(id: volume.createOperation, request: request)
            guard case .volumeReceipt(let receipt) = try f.control.send(request) else { Issue.record("create failed"); return }
            volume.rootDevice = receipt.volume.root.device; volume.rootInode = receipt.volume.root.inode
            volume.createdRevision = receipt.revision; try f.journal.recordVolume(volume)
        }
        // Historical pre-atomic-freeze state: fixture update deliberately persists
        // only keys. Production freezeKeys now always retains the Reserve request.
        _ = try f.files.freeze(f.journal, token: token)
        let before = try f.journal.snapshot()
        #expect(before.operations[f.plan.reserveOperation] == nil)
        for _ in 0..<2 {
            try f.reopen()
            do { _ = try await f.coordinator.recover(f.plan.id); Issue.record("missing admission silently recovered") }
            catch ManagedVolumeLifecycleCoordinator.Failure.repairRequired {}
            do { try await f.coordinator.reconcileStartup(); Issue.record("missing admission reconciled") }
            catch ManagedVolumeLifecycleCoordinator.Failure.repairRequired {}
            #expect(try f.journal.snapshot().reconciliationRequired)
            #expect(try f.journal.snapshot().operations == before.operations)
            #expect(!f.control.events.contains("retire") && !f.control.events.contains("reserve"))
            for volume in f.files.volumes { #expect(!f.coordinator.canDelete(volume: volume.id)) }
        }
    }

    @Test func lostCreateChangedContextCannotReplayOrAdoptReady() async throws {
        let f = try RecoveryFixture(); defer { f.files.remove() }
        f.control.fail("create", afterAcceptance: true)
        do { _ = try await f.coordinator.start(f.plan, guest: f.guest) } catch {}
        let before = try f.journal.snapshot()
        for field in ["store", "epoch", "controller", "key"] {
            let context = try ManagedStorageControlClient.Context(store: field == "store" ? HostIntentFixture.id() : f.plan.store,
                serviceEpoch: field == "epoch" ? HostIntentFixture.id() : f.plan.serviceEpoch,
                controllerEpoch: field == "controller" ? 2 : f.plan.controllerEpoch,
                controllerKey: field == "key" ? String(repeating: "f", count: 64) : f.plan.controllerKey,
                provenanceReference: f.files.provenance)
            let other = f.control.copy(context: context)
            do {
                let coordinator = try ManagedVolumeLifecycleCoordinator(journal: f.journal, control: other, names: SharedVolumeInitializationCoordinator())
                do { _ = try await coordinator.recover(f.plan.id); Issue.record("changed context replayed") } catch {}
                #expect(other.events.isEmpty)
                do { try await coordinator.reconcileStartup(); Issue.record("changed context adopted") } catch {}
            } catch ManagedVolumeLifecycleCoordinator.Failure.wrongEvidence {}
            #expect(try f.journal.snapshot().volumes == before.volumes)
            #expect(try f.journal.snapshot().operations == before.operations)
        }
    }

    @Test func changedServiceEpochNeverReplaysHistoricalIntent() async throws {
        let f = try RecoveryFixture(); defer { f.files.remove() }
        f.control.fail("reserve", afterAcceptance: true)
        do { _ = try await f.coordinator.start(f.plan, guest: f.guest) } catch {}
        let context = try ManagedStorageControlClient.Context(store: f.files.store, serviceEpoch: HostIntentFixture.id(),
            controllerEpoch: f.plan.controllerEpoch, controllerKey: f.plan.controllerKey, provenanceReference: f.files.provenance)
        let other = RecoveryControl(context: context)
        let coordinator = try ManagedVolumeLifecycleCoordinator(journal: f.journal, control: other, names: SharedVolumeInitializationCoordinator())
        do { _ = try await coordinator.recover(f.plan.id); Issue.record("changed E accepted") } catch {}
        #expect(other.events.isEmpty)
    }

    @Test func retirementCannotBypassCrossServiceContainment() async throws {
        let f = try RecoveryFixture(); defer { f.files.remove() }
        _ = try await f.coordinator.start(f.plan, guest: f.guest)
        let before = try f.journal.snapshot()
        let context = try ManagedStorageControlClient.Context(store: f.files.store, serviceEpoch: HostIntentFixture.id(),
            controllerEpoch: f.plan.controllerEpoch, controllerKey: f.plan.controllerKey, provenanceReference: f.files.provenance)
        let other = f.control.copy(context: context)
        let coordinator = try ManagedVolumeLifecycleCoordinator(journal: f.journal, control: other, names: SharedVolumeInitializationCoordinator())
        do { try await coordinator.retireLaunch(f.plan.id); Issue.record("historical runtime retired without containment") }
        catch ManagedVolumeLifecycleCoordinator.Failure.blocked {}
        #expect(other.events.isEmpty)
        #expect(try f.journal.snapshot().intents == before.intents)
        #expect(!coordinator.canDelete(volume: f.files.volumes[0].id))
    }

    @Test func stoppedExecutionJoinsSubmittedRegisterBeforeRetirement() async throws {
        let f = try RecoveryFixture(); defer { f.files.remove() }
        f.control.blockRegister = true
        let start = Task { try await f.coordinator.start(f.plan, guest: f.guest) }
        for await _ in f.control.registerStarted.stream { break }
        let retirement = Task { try await f.coordinator.retireLaunch(f.plan.id) }
        await Task.yield()
        #expect(!f.control.events.contains("retire"))
        f.control.releaseRegister.signal()
        do { _ = try await start.value; Issue.record("stale execution published") } catch {}
        do { try await retirement.value; Issue.record("failed prepare retired") } catch {}
        let current = try f.journal.intent(f.journal.token(for: f.plan.id))
        #expect(current.phase == .quarantined)
        #expect(current.slots.filter { $0.role == "prepare" }.allSatisfy { $0.receipt != nil })
        #expect(!f.control.events.contains("complete"))
    }

    @Test func recoveryPreemptsSharedRetirementWithoutAcceptingStaleReceipts() async throws {
        let f = try RecoveryFixture(); defer { f.files.remove() }
        _ = try await f.coordinator.start(f.plan, guest: f.guest)
        let runtime = try #require(f.plan.slots.first { $0.role == "runtime" })
        f.control.blockRetirement = runtime.attachment
        defer { f.control.releaseRetirement.signal() }
        let first = Task { try await f.coordinator.retireLaunch(f.plan.id) }
        for await _ in f.control.retirementStarted.stream { break }
        let recovery = Task { @MainActor in
            let release = Task { @MainActor in f.control.releaseRetirement.signal() }
            let token = try await f.coordinator.recover(f.plan.id)
            await release.value
            return token
        }
        // Recovery starts only after this same-actor call has joined the first.
        do { try await f.coordinator.retireLaunch(f.plan.id); Issue.record("revoked join published") }
        catch ManagedVolumeLifecycleCoordinator.Failure.staleExecution {}
        do { try await first.value; Issue.record("revoked owner published") }
        catch ManagedVolumeLifecycleCoordinator.Failure.staleExecution {}
        let recovered = try f.journal.intent(await recovery.value)
        #expect(recovered.phase == .retired && recovered.slots.allSatisfy { $0.receipt != nil })
        #expect(recovered.launch == f.plan.launch && recovered.containerInstance == f.plan.containerInstance)
        let attempts = f.control.attempts(for: runtime.retireOperation)
        #expect(attempts.count == 2 && attempts[0] == attempts[1])
        #expect(!f.control.mismatchedReplay && f.control.registerAfterRetirement == 0)
    }

    @Test func freshContainmentRefreshesRetainedTerminalHistoryWithoutErasingReceipts() async throws {
        let f = try RecoveryFixture(); defer { f.files.remove() }
        let (pending, _) = try await f.retainedHistory()
        let historical = try f.journal.intent(f.journal.token(for: f.plan.id))
        #expect(historical.isTerminal && historical.prepareCompleted)
        #expect(historical.slots.allSatisfy { $0.receipt != nil })
        for generation: UInt64 in [3, 4] {
            try recordAbsentNativeLaunch(f.newPlan(), in: f.files.root, generation: generation)
        }
        let before = try f.journal.snapshot()
        let events = f.control.events
        // Match Raw's actual admission path: mint only the pending predecessor's
        // fresh sealed permit, then let replace refresh historical native evidence.
        let fresh = try await ManagedVolumeLifecycleCoordinator.ReplacementPermit.contain(pending, in: f.files.root)
        #expect(try f.journal.snapshot() == before)
        #expect(f.control.events == events)
        try await f.coordinator.reconcileStartup()
        _ = try await f.coordinator.replace(pending.id, with: f.newPlan(), permit: fresh, guest: f.guest)
        #expect(try f.journal.intent(f.journal.token(for: historical.id)) == historical)
        // Settlement may advance the local version, but must still pass exact
        // cached containment and retain every historical authority receipt.
        let settled = try await f.coordinator.settleExecution(historical.id, in: f.files.root)
        #expect(try f.journal.intent(settled.token).slots == historical.slots)
        #expect(!f.control.mismatchedReplay)
    }

    @Test func replacementRevalidatesAnUnchangedHistoricalCensus() async throws {
        let f = try RecoveryFixture(); defer { f.files.remove() }
        let (pending, _) = try await f.retainedHistory()
        let historical = try f.journal.intent(f.journal.token(for: f.plan.id))
        let fresh = try await ManagedVolumeLifecycleCoordinator.ReplacementPermit.contain(pending, in: f.files.root)
        _ = try await f.coordinator.replace(pending.id, with: f.newPlan(), permit: fresh, guest: f.guest)
        #expect(try f.journal.intent(f.journal.token(for: historical.id)) == historical)
        let settled = try await f.coordinator.settleExecution(historical.id, in: f.files.root)
        #expect(try f.journal.intent(settled.token).slots == historical.slots)
    }

    @Test(arguments: ["missing", "foreign-instance", "foreign-directory"])
    func historicalContainmentRefreshRejectsChangedOwnership(fault: String) async throws {
        let f = try RecoveryFixture(); defer { f.files.remove() }
        let (pending, first) = try await f.retainedHistory()
        let foreign = try HostIntentFixture(); defer { foreign.remove() }
        var directory = f.files.root
        switch fault {
        case "missing": try FileManager.default.removeItem(at: first.directory)
        case "foreign-instance":
            try recordAbsentNativeLaunch(f.files.intent(), in: f.files.root, generation: 3)
        default:
            directory = foreign.root
            try recordAbsentNativeLaunch(f.plan, in: directory, generation: 1)
            try recordAbsentNativeLaunch(pending, in: directory, generation: 2)
        }
        let before = try f.journal.snapshot(), events = f.control.events
        await #expect(throws: (any Error).self) {
            let fresh = try await ManagedVolumeLifecycleCoordinator.ReplacementPermit.contain(pending, in: directory)
            _ = try await f.coordinator.replace(pending.id, with: f.newPlan(), permit: fresh, guest: f.guest)
        }
        #expect(try f.journal.snapshot() == before)
        #expect(f.control.events == events)
    }

    @Test(arguments: ["invalidate", "journal", "census"])
    func replacementRefreshRejectsStaleNativeCallbacks(fault: String) async throws {
        let started = AsyncStream<Void>.makeStream(), release = AsyncStream<Void>.makeStream()
        var armed = false, observations = 0
        let f = try RecoveryFixture(nativeObservationCompleted: {
            guard armed else { return }
            observations += 1
            if observations == 2 {
                started.continuation.yield(())
                for await _ in release.stream { break }
            }
        })
        defer { f.files.remove() }
        let (pending, _) = try await f.retainedHistory()
        try recordAbsentNativeLaunch(f.newPlan(), in: f.files.root, generation: 3)
        let fresh = try await ManagedVolumeLifecycleCoordinator.ReplacementPermit.contain(pending, in: f.files.root)
        let successor = f.newPlan(), events = f.control.events
        armed = true
        let operation = Task { try await f.coordinator.replace(pending.id, with: successor, permit: fresh, guest: f.guest) }
        for await _ in started.stream { break }
        if fault == "invalidate" { await f.coordinator.invalidate() }
        else if fault == "journal" { _ = try f.journal.update(f.journal.token(for: f.plan.id)) { _ in } }
        else { try recordAbsentNativeLaunch(f.newPlan(), in: f.files.root, generation: 4) }
        let fenced = try f.journal.snapshot()
        release.continuation.yield(())
        await #expect(throws: (any Error).self) { _ = try await operation.value }
        #expect(try f.journal.snapshot() == fenced)
        #expect(try f.journal.snapshot().intents[successor.id] == nil)
        #expect(f.control.events == events)
    }

    @Test func replacementRefreshAllowsDisjointContainerExecution() async throws {
        let f = try RecoveryFixture(onlyFirstVolume: true); defer { f.files.remove() }
        let (pending, _) = try await f.retainedHistory()
        try recordAbsentNativeLaunch(f.newPlan(), in: f.files.root, generation: 3)
        let fresh = try await ManagedVolumeLifecycleCoordinator.ReplacementPermit.contain(pending, in: f.files.root)
        let other = f.files.replacement(f.files.intent([f.files.volumes[1]]),
            serviceEpoch: f.plan.serviceEpoch, controllerEpoch: f.plan.controllerEpoch, controllerKey: f.plan.controllerKey,
            selected: [f.files.volumes[1]])
        let started = AsyncStream<Void>.makeStream(), release = AsyncStream<Void>.makeStream(), guest = f.guest
        var paused = false
        let suspended = ManagedVolumeLifecycleCoordinator.GuestActions(offerKeys: { intent, role in
            if !paused {
                paused = true; started.continuation.yield(())
                for await _ in release.stream { break }
            }
            return try await guest.offerKeys(intent, role)
        }, credentialAndMount: guest.credentialAndMount, prepare: guest.prepare,
            closePrepare: guest.closePrepare, start: guest.start, beforePublication: guest.beforePublication)
        let work = Task { try await f.coordinator.start(other, guest: suspended) }
        for await _ in started.stream { break }
        let replacement = Task { try await f.coordinator.replace(pending.id, with: f.newPlan(), permit: fresh, guest: guest) }
        let result = await replacement.result
        release.continuation.yield(())
        _ = try await work.value
        #expect(try f.journal.intent(result.get()).phase == .running)
    }

    @Test func terminalCleanupRefreshIncludesOrdinaryRestartWithoutChangingStorageHistory() async throws {
        let f = try RecoveryFixture(onlyFirstVolume: true); defer { f.files.remove() }
        let ackDirectory = try f.files.root.createDirectory(named: "ack")
        let mainDirectory = try f.files.root.createDirectory(named: "main")
        _ = try await f.retiredNativeHistory(in: ackDirectory)
        let historical = try f.journal.intent(f.journal.token(for: f.plan.id))
        let main = f.disjointPlan()
        f.control.fail("register", afterAcceptance: true)
        do { _ = try await f.coordinator.start(main, guest: f.guest) } catch {}
        _ = try await f.coordinator.recover(main.id)
        try recordExitedNativeLaunch(main, in: mainDirectory, generation: 1)
        let ackPermit = try await f.coordinator.prepareContainment(historical.id, in: ackDirectory)
        let mainPermit = try await f.coordinator.prepareContainment(main.id, in: mainDirectory)
        try await f.coordinator.registerContainment([ackPermit, mainPermit])
        try await f.coordinator.reconcileStartup()

        // Ordinary start, not ReplacePrepare: PREPARE and runtime each publish a
        // real native generation after the ACK history's census was cached.
        let restart = f.newPlan(), guest = f.guest
        let native = ManagedVolumeLifecycleCoordinator.GuestActions(offerKeys: { intent, role in
            try recordExitedNativeLaunch(intent, in: ackDirectory, generation: role == .prepare ? 2 : 3)
            return try await guest.offerKeys(intent, role)
        }, credentialAndMount: guest.credentialAndMount, prepare: guest.prepare,
            closePrepare: guest.closePrepare, start: guest.start, beforePublication: guest.beforePublication)
        _ = try await f.coordinator.start(restart, guest: native)
        try await f.coordinator.retireLaunch(restart.id)
        let before = try f.journal.snapshot(), events = f.control.events
        let journalDirectory = try f.files.root.openDirectory(named: "managed-storage")
        let bytes = try journalDirectory.readRegularFile(named: "state.json")
        // Exact cached revalidation must still reject an expanded census.
        await #expect(throws: (any Error).self) {
            _ = try await f.coordinator.settleExecution(historical.id, in: ackDirectory)
        }
        try await f.coordinator.refreshTerminalContainment(containerID: historical.container,
            instanceID: try #require(UUID(uuidString: historical.containerInstance)), in: ackDirectory)
        #expect(try f.journal.snapshot() == before)
        #expect(try journalDirectory.readRegularFile(named: "state.json") == bytes)
        #expect(f.control.events == events)
        #expect(try f.journal.snapshot().operations == before.operations)
        #expect(try f.journal.intent(f.journal.token(for: historical.id)).slots == historical.slots)
        let settled = try await f.coordinator.settleExecution(historical.id, in: ackDirectory)
        #expect(settled.status == .prepareCompleted)
        #expect(try f.journal.intent(settled.token).slots == historical.slots)
        // The shared journal's disjoint main-container replacement remains usable.
        // This same-E fixture does not manufacture ROOT cross-E authorization.
        // Match Raw's post-settlement reconciliation before another admission.
        try await f.coordinator.reconcileStartup()
        let freshMain = try await f.coordinator.prepareContainment(main.id, in: mainDirectory)
        let successor = f.files.replacement(main, selected: [f.files.volumes[1]])
        let replaced = try await f.coordinator.replace(main.id, with: successor, permit: freshMain, guest: guest)
        #expect(try f.journal.intent(replaced).phase == .running)
        #expect(!f.control.mismatchedReplay)
    }

    @Test(arguments: ["missing", "foreign-instance", "foreign-directory", "foreign-generation"])
    func terminalCleanupRefreshRejectsChangedOwnership(fault: String) async throws {
        let f = try RecoveryFixture(); defer { f.files.remove() }
        let first = try await f.retiredNativeHistory(in: f.files.root)
        try recordExitedNativeLaunch(f.newPlan(), in: f.files.root, generation: 2)
        var directory = f.files.root
        var instance = try #require(UUID(uuidString: f.plan.containerInstance))
        switch fault {
        case "missing": try FileManager.default.removeItem(at: first.directory)
        case "foreign-instance": instance = UUID()
        case "foreign-generation":
            try recordExitedNativeLaunch(f.files.intent(), in: directory, generation: 3)
        default:
            directory = try f.files.root.createDirectory(named: "foreign")
            try recordExitedNativeLaunch(f.plan, in: directory, generation: 1)
            try recordExitedNativeLaunch(f.newPlan(), in: directory, generation: 2)
        }
        let before = try f.journal.snapshot(), events = f.control.events
        await #expect(throws: (any Error).self) {
            try await f.coordinator.refreshTerminalContainment(containerID: f.plan.container,
                instanceID: instance, in: directory)
        }
        #expect(try f.journal.snapshot() == before)
        #expect(f.control.events == events)
    }

    @Test(arguments: ["uncached", "planned", "running"])
    func terminalCleanupRefreshDoesNotSignalUncachedOrNonterminalLaunch(state: String) async throws {
        let f = try RecoveryFixture(); defer { f.files.remove() }
        _ = try await f.retiredNativeHistory(in: f.files.root, cache: state != "uncached")
        let next = f.newPlan()
        if state == "planned" { _ = try f.journal.plan(next) }
        if state == "running" { _ = try await f.coordinator.start(next, guest: f.guest) }
        let child = try recordSuspendedNativeLaunch(next, in: f.files.root, generation: 2)
        defer { child.terminateAndReap() }
        let before = try f.journal.snapshot(), events = f.control.events
        try await f.coordinator.refreshTerminalContainment(containerID: f.plan.container,
            instanceID: try #require(UUID(uuidString: f.plan.containerInstance)), in: f.files.root)
        child.expectStillRunning()
        #expect(try f.journal.snapshot() == before)
        #expect(f.control.events == events)
    }

    @Test(arguments: ["invalidate", "journal", "census"])
    func terminalCleanupRefreshRejectsStaleNativeCallbacks(fault: String) async throws {
        let started = AsyncStream<Void>.makeStream(), release = AsyncStream<Void>.makeStream()
        var armed = false, observations = 0
        let f = try RecoveryFixture(nativeObservationCompleted: {
            guard armed else { return }
            observations += 1
            if observations == 2 {
                started.continuation.yield(())
                for await _ in release.stream { break }
            }
        })
        defer { f.files.remove(); release.continuation.finish() }
        _ = try await f.retiredNativeHistory(in: f.files.root)
        let second = f.newPlan()
        _ = try await f.coordinator.start(second, guest: f.guest)
        try await f.coordinator.retireLaunch(second.id)
        try recordExitedNativeLaunch(second, in: f.files.root, generation: 2)
        var permits: [ManagedVolumeLifecycleCoordinator.ReplacementPermit] = []
        for id in [f.plan.id, second.id] {
            permits.append(try await f.coordinator.prepareContainment(id, in: f.files.root))
        }
        try await f.coordinator.registerContainment(permits)
        try recordExitedNativeLaunch(f.newPlan(), in: f.files.root, generation: 3)
        let events = f.control.events
        armed = true
        let operation = Task {
            try await f.coordinator.refreshTerminalContainment(containerID: f.plan.container,
                instanceID: try #require(UUID(uuidString: f.plan.containerInstance)), in: f.files.root)
        }
        for await _ in started.stream { break }
        if fault == "invalidate" { await f.coordinator.invalidate() }
        else if fault == "journal" { _ = try f.journal.update(f.journal.token(for: f.plan.id)) { _ in } }
        else { try recordExitedNativeLaunch(f.newPlan(), in: f.files.root, generation: 4) }
        let fenced = try f.journal.snapshot()
        release.continuation.yield(())
        await #expect(throws: (any Error).self) { try await operation.value }
        armed = false
        #expect(try f.journal.snapshot() == fenced)
        #expect(f.control.events == events)
        // Neither cached entry may have been published before the failed CAS.
        for id in [f.plan.id, second.id] {
            await #expect(throws: (any Error).self) {
                _ = try await f.coordinator.settleExecution(id, in: f.files.root)
            }
        }
        #expect(try f.journal.snapshot() == fenced)
        #expect(f.control.events == events)
        if fault != "invalidate" {
            try await f.coordinator.refreshTerminalContainment(containerID: f.plan.container,
                instanceID: try #require(UUID(uuidString: f.plan.containerInstance)), in: f.files.root)
            #expect(try f.journal.snapshot() == fenced)
            #expect(f.control.events == events)
            for id in [f.plan.id, second.id] {
                let settled = try await f.coordinator.settleExecution(id, in: f.files.root)
                #expect(try f.journal.intent(settled.token).slots == fenced.intents[id]?.slots)
            }
        }
    }

    @Test func terminalCleanupRefreshAllowsDisjointContainerExecutionDuringNativeCallback() async throws {
        let observed = AsyncStream<Void>.makeStream(), resumeRefresh = AsyncStream<Void>.makeStream()
        var armed = false
        let f = try RecoveryFixture(onlyFirstVolume: true, nativeObservationCompleted: {
            guard armed else { return }
            armed = false; observed.continuation.yield(())
            for await _ in resumeRefresh.stream { break }
        })
        defer { f.files.remove(); resumeRefresh.continuation.finish() }
        _ = try await f.retiredNativeHistory(in: f.files.root)
        try recordExitedNativeLaunch(f.newPlan(), in: f.files.root, generation: 2)
        armed = true
        let refresh = Task {
            try await f.coordinator.refreshTerminalContainment(containerID: f.plan.container,
                instanceID: try #require(UUID(uuidString: f.plan.containerInstance)), in: f.files.root)
        }
        for await _ in observed.stream { break }
        let started = AsyncStream<Void>.makeStream(), release = AsyncStream<Void>.makeStream(), guest = f.guest
        defer { release.continuation.finish() }
        var paused = false
        let suspended = ManagedVolumeLifecycleCoordinator.GuestActions(offerKeys: { intent, role in
            if !paused {
                paused = true; started.continuation.yield(())
                for await _ in release.stream { break }
            }
            return try await guest.offerKeys(intent, role)
        }, credentialAndMount: guest.credentialAndMount, prepare: guest.prepare,
            closePrepare: guest.closePrepare, start: guest.start, beforePublication: guest.beforePublication)
        let other = f.disjointPlan()
        let work = Task { try await f.coordinator.start(other, guest: suspended) }
        for await _ in started.stream { break }
        let before = try f.journal.snapshot(), events = f.control.events
        resumeRefresh.continuation.yield(())
        let result = await refresh.result
        #expect(try f.journal.snapshot() == before)
        #expect(f.control.events == events)
        release.continuation.yield(())
        _ = try await work.value
        try result.get()
        let settled = try await f.coordinator.settleExecution(f.plan.id, in: f.files.root)
        #expect(settled.status == .prepareCompleted)
    }

    @Test func crossEpochReplacementStillRequiresRootRecoveryCapability() async throws {
        let f = try RecoveryFixture(); defer { f.files.remove() }
        let (pending, _) = try await f.retainedHistory()
        try recordAbsentNativeLaunch(f.newPlan(), in: f.files.root, generation: 3)
        let nextEpoch = HostIntentFixture.id()
        let context = try ManagedStorageControlClient.Context(store: f.plan.store, serviceEpoch: nextEpoch,
            controllerEpoch: f.plan.controllerEpoch, controllerKey: f.plan.controllerKey, provenanceReference: f.files.provenance)
        let control = f.control.copy(context: context)
        let coordinator = try ManagedVolumeLifecycleCoordinator(journal: f.journal, control: control,
            names: SharedVolumeInitializationCoordinator())
        let before = try f.journal.snapshot(), events = control.events
        let fresh = try await ManagedVolumeLifecycleCoordinator.ReplacementPermit.contain(pending, in: f.files.root)
        do {
            _ = try await coordinator.replace(pending.id, with: f.files.replacement(pending, serviceEpoch: nextEpoch), permit: fresh, guest: f.guest)
            Issue.record("cross-E replacement accepted without ROOT recovery")
        } catch ManagedVolumeLifecycleCoordinator.Failure.wrongEvidence {}
        #expect(try f.journal.snapshot() == before)
        #expect(control.events == events)
    }

    @Test func runningRegistryWithoutNativeLiveProofCannotPreserveAWorkload() async throws {
        let f = try RecoveryFixture(); defer { f.files.remove() }
        let token = try await f.coordinator.start(f.plan, guest: f.guest)
        try recordAbsentNativeLaunch(f.plan, in: f.files.root, generation: 1)
        var container = ContainerRecord(id: f.plan.container, instanceID: try #require(UUID(uuidString: f.plan.containerInstance)),
            name: "unproven-live", image: "unused")
        container.phase = .running
        let before = try f.journal.snapshot()
        let proof = try await f.coordinator.prepareLiveRuntime(token.intent, container: container, in: f.files.root)
        #expect(proof == nil)
        #expect(try f.journal.snapshot() == before)
    }

    @Test func missingActualShimCannotMintReplacementPermit() async throws {
        let f = try RecoveryFixture(); defer { f.files.remove() }
        do {
            _ = try await ManagedVolumeLifecycleCoordinator.ReplacementPermit.contain(f.plan, in: f.files.root)
            Issue.record("missing VM ownership accepted")
        } catch {}
    }

    @Test func frozenReplacementRecoversUnsentOrLostReplyUsingOnlySameSuccessorAcrossReopen() async throws {
        for send in ["unsent", "beforeAcceptance", "afterAcceptance"] {
            for reopen in [false, true] {
                let f = try RecoveryFixture(); defer { f.files.remove() }
                f.control.fail("reserve", afterAcceptance: true)
                do { _ = try await f.coordinator.start(f.plan, guest: f.guest) } catch {}
                _ = try await f.coordinator.recover(f.plan.id)
                try await f.coordinator.reconcileStartup()
                let oldToken = try f.journal.token(for: f.plan.id)
                let old = try f.journal.intent(oldToken)
                let successor = f.newPlan()
                let token = try f.journal.planReplacement(predecessor: oldToken, successor: successor)
                _ = try f.journal.freezeKeys(token, role: .prepare, keys: f.files.offeredKeys(for: successor))
                let before = try f.journal.snapshot()
                let reserveBytes = try #require(before.operations[successor.reserveOperation])
                let replaceBytes = try #require(before.operations[old.replaceOperation])
                let replacement = try f.journal.replayRequest(operation: old.replaceOperation)
                #expect(f.control.attempts(for: old.replaceOperation).isEmpty)
                if send != "unsent" {
                    f.control.fail("replace", afterAcceptance: send == "afterAcceptance")
                    do { _ = try f.control.send(replacement); Issue.record("lost replace succeeded") } catch {}
                }
                guard case .snapshot(let observed) = try f.control.send(.query) else { Issue.record("missing query"); return }
                let missing = try ManagedVolumeLifecycleCoordinator.unacceptedSuccessor(predecessor: old.id,
                    state: f.journal.snapshot(), snapshot: observed)
                #expect(missing == (send == "afterAcceptance" ? nil : successor.id))
                #expect(throws: (any Error).self) {
                    _ = try ManagedVolumeLifecycleCoordinator.unacceptedSuccessor(predecessor: HostIntentFixture.id(),
                        state: f.journal.snapshot(), snapshot: observed)
                }
                if reopen { try f.reopen() }
                let recovered = try f.journal.intent(await f.coordinator.recover(successor.id))
                #expect(recovered.phase == .quarantined && !recovered.prepareCompleted)
                #expect(recovered.slots.filter { $0.role == "prepare" }.allSatisfy { $0.receipt != nil })
                let replaced = try f.journal.intent(f.journal.token(for: old.id))
                #expect(replaced.phase == .replaced && !replaced.prepareCompleted)
                #expect(replaced.successor == successor.id)
                #expect(replaced.slots == old.slots)
                #expect(!f.control.mismatchedReplay)
                #expect(f.control.attempts(for: successor.reserveOperation).isEmpty)
                #expect(f.control.attempts(for: old.replaceOperation) == (send == "unsent" ? [replaceBytes] : [replaceBytes, replaceBytes]))
                #expect(try f.journal.replayRequest(operation: successor.reserveOperation).durableBytes() == reserveBytes)
                #expect(try f.journal.replayRequest(operation: old.replaceOperation).durableBytes() == replaceBytes)
                try f.reopen()
                #expect(try f.journal.intent(f.journal.token(for: successor.id)) == recovered)
                #expect(try f.journal.intent(f.journal.token(for: old.id)) == replaced)
                #expect(try f.journal.replayRequest(operation: successor.reserveOperation).durableBytes() == reserveBytes)
                #expect(try f.journal.replayRequest(operation: old.replaceOperation).durableBytes() == replaceBytes)
            }
        }
    }

    @Test func replacementInterruptedBeforeKeyOfferCanBeSupersededWithoutErasingHistory() async throws {
        for attempted in [false, true] {
            let f = try RecoveryFixture(); defer { f.files.remove() }
            f.control.fail("reserve", afterAcceptance: true)
            do { _ = try await f.coordinator.start(f.plan, guest: f.guest) } catch {}
            _ = try await f.coordinator.recover(f.plan.id)
            try await f.coordinator.reconcileStartup()
            try recordExitedNativeLaunch(f.plan, in: f.files.root, generation: 1)
            let successor = f.newPlan()
            let planned = try f.journal.planReplacement(predecessor: f.journal.token(for: f.plan.id), successor: successor)
            if attempted {
                _ = try f.journal.attemptLaunch(planned)
                try recordExitedNativeLaunch(successor, in: f.files.root, generation: 2)
            }
            try f.reopen()
            var permits: [ManagedVolumeLifecycleCoordinator.ReplacementPermit] = []
            for id in try f.journal.snapshot().intents.keys.sorted() {
                permits.append(try await f.coordinator.prepareContainment(id, in: f.files.root))
            }
            let controlBefore = f.control.events
            try await f.coordinator.registerContainment(permits)
            #expect(f.control.events == controlBefore)
            let settled = try await f.coordinator.settleExecution(successor.id, in: f.files.root)
            #expect(settled.status == (attempted ? .abortedBeforeAdmission : .neverLaunched))
            try await f.coordinator.reconcileStartup()
            let predecessor = try f.journal.intent(f.journal.token(for: f.plan.id))
            let oldHistory = try f.journal.intent(f.journal.token(for: successor.id))
            #expect(predecessor.successor == successor.id)
            #expect(oldHistory.predecessor == predecessor.id && oldHistory.isPreAdmissionTerminal)
            let next = f.newPlan()
            let permit = try await f.coordinator.prepareContainment(predecessor.id, in: f.files.root)
            _ = try await f.coordinator.replace(predecessor.id, with: next, permit: permit, guest: f.guest)
            let completed = try f.journal.intent(f.journal.token(for: predecessor.id))
            #expect(completed.supersededSuccessors == [successor.id])
            #expect(completed.successor == next.id && completed.phase == .replaced)
            try recordExitedNativeLaunch(next, in: f.files.root, generation: 3)
            #expect(try f.journal.intent(f.journal.token(for: successor.id)) == oldHistory)
            #expect(try f.journal.snapshot().operations[successor.reserveOperation] == nil)
            try f.reopen()
            #expect(try f.journal.intent(f.journal.token(for: predecessor.id)) == completed)
            let repeated = try await f.coordinator.settleExecution(successor.id, in: f.files.root)
            #expect(repeated.status == settled.status)
            #expect(try f.journal.intent(repeated.token) == oldHistory)
        }
    }

    @Test func exitedKeylessLaunchSettlesAsAbortedNotNeverLaunched() async throws {
        let f = try RecoveryFixture(); defer { f.files.remove() }
        let guest = f.guest
        let interrupted = ManagedVolumeLifecycleCoordinator.GuestActions(offerKeys: { intent, _ in
            try recordExitedNativeLaunch(intent, in: f.files.root, generation: 1)
            throw ManagedVolumeLifecycleCoordinator.Failure.blocked
        }, credentialAndMount: guest.credentialAndMount, prepare: guest.prepare,
            closePrepare: guest.closePrepare, start: guest.start, beforePublication: guest.beforePublication)
        do { _ = try await f.coordinator.start(f.plan, guest: interrupted) } catch {}
        try f.reopen()
        let permit = try await f.coordinator.prepareContainment(f.plan.id, in: f.files.root)
        let before = f.control.events
        try await f.coordinator.registerContainment([permit])
        #expect(f.control.events == before)
        let settled = try await f.coordinator.settleExecution(f.plan.id, in: f.files.root)
        #expect(settled.status == .abortedBeforeAdmission)
        #expect(try f.journal.intent(settled.token).launchBoundary == .attempted)
        #expect(try f.journal.intent(settled.token).isTerminal)
        #expect(!f.control.events.contains("reserve") && !f.control.events.contains("complete"))
        try await f.coordinator.reconcileStartup()
        _ = try await f.coordinator.start(f.newPlan(), guest: f.guest)
    }

    @Test func actualNativeExitAndAllReceiptsSettleFailedPrepareWithoutCompletingIt() async throws {
        let f = try RecoveryFixture(); defer { f.files.remove() }
        f.control.fail("register", afterAcceptance: true)
        do { _ = try await f.coordinator.start(f.plan, guest: f.guest) } catch {}
        try recordExitedNativeLaunch(f.plan, in: f.files.root, generation: 1)
        let settled = try await f.coordinator.settleExecution(f.plan.id, in: f.files.root)
        let intent = try f.journal.intent(settled.token)
        #expect(settled.status == .preparePending && !intent.prepareCompleted)
        #expect(intent.phase == .quarantined && intent.slots.filter { $0.role == "prepare" }.allSatisfy { $0.receipt != nil })
        #expect(!f.control.events.contains("complete"))
        try await f.coordinator.reconcileStartup()
        let next = f.newPlan()
        let permit = try await f.coordinator.prepareContainment(intent.id, in: f.files.root)
        _ = try await f.coordinator.replace(intent.id, with: next, permit: permit, guest: f.guest)
        #expect(try f.journal.intent(f.journal.token(for: intent.id)).phase == .replaced)
    }

    @Test func completeContainmentSetRejectsOmissionsAndMakesNoControlRequests() async throws {
        let f = try RecoveryFixture(); defer { f.files.remove() }
        _ = try f.journal.plan(f.plan)
        let before = f.control.events
        let permit = try await f.coordinator.prepareContainment(f.plan.id, in: f.files.root)
        do { try await f.coordinator.registerContainment([]); Issue.record("missing census accepted") } catch {}
        #expect(f.control.events == before)
        try await f.coordinator.registerContainment([permit])
        #expect(f.control.events == before)
        #expect(try f.journal.intent(f.journal.token(for: f.plan.id)).launchBoundary == .cancelled)
    }

    @Test func disjointStartsKeepIndependentLocalVersions() async throws {
        let f = try RecoveryFixture(); defer { f.files.remove() }
        let first = f.newPlan(volumes: [f.files.volumes[0]])
        let second = f.newPlan(volumes: [f.files.volumes[1]])
        let a = Task { try await f.coordinator.start(first, guest: f.guest) }
        let b = Task { try await f.coordinator.start(second, guest: f.guest) }
        let one = try await a.value
        let two = try await b.value
        #expect(try f.journal.intent(one).phase == .running)
        #expect(try f.journal.intent(two).phase == .running)
    }
}

/// Retained launch metadata plus the production native absence observation. No
/// child, VM, helper, socket peer, injected process observer or signal is needed.
/// Int32.max must be absent before recording it; it is never a live authority.
@discardableResult
@MainActor private func recordAbsentNativeLaunch(_ intent: HostStorageIntents.Intent,
                                               in directory: PersistentStateDirectory, generation: UInt64) throws -> VMShimClient.PersistentSpawnFiles {
    guard case .absent = VMShimClient.observeProcess(Int32.max) else { throw POSIXError(.EBUSY) }
    let container = ContainerRecord(id: intent.container, instanceID: try #require(UUID(uuidString: intent.containerInstance)),
        name: "absent-proof", image: "unused")
    let specification = VMShimProtocol.Specification(containerID: intent.container, generation: generation,
        token: "absent-proof", kernelPath: "/unused", initialRamdiskPath: "/unused",
        rootDiskPath: directory.url.appending(path: "unused.ext4").path,
        cpus: 1, memoryBytes: 268_435_456, macAddress: "02:ce:00:00:00:01",
        socketPath: "/tmp/ce-absent-\(UUID().uuidString).sock", logPath: directory.url.appending(path: "shim.log").path,
        shimLaunchUUID: intent.launch, workloadStorageMode: .managed)
    let files = try VMShimClient.preparePersistentSpawn(specification: specification, container: container,
        containerDirectory: directory, executable: try #require(Bundle.main.executableURL))
    let persisted = try JSONDecoder().decode(VMShimClient.PersistentLaunchIntent.self, from: Data(contentsOf: files.intentURL))
    let record = VMShimClient.PersistentLaunchRecord(nonce: persisted.nonce, createdAt: persisted.createdAt,
        specificationPath: persisted.specificationPath, executablePath: persisted.executablePath,
        containerDirectoryIdentity: persisted.containerDirectoryIdentity, generationsDirectoryIdentity: persisted.generationsDirectoryIdentity,
        generationDirectoryIdentity: persisted.generationDirectoryIdentity, specification: specification,
        processIdentifier: Int32.max, processStartTime: UInt64.max, container: container)
    try PersistentStateDirectory.open(files.directory).replaceRegularFile(named: "launch.json", data: JSONEncoder().encode(record))
    return files
}

/// Real native child identity and exit: start the current test executable suspended
/// with exact shim arguments, publish through production proc inspection, then kill
/// and reap it before any user code runs. No VZ, guest, helper or fake PID provider.
@discardableResult
@MainActor private func recordExitedNativeLaunch(_ intent: HostStorageIntents.Intent,
                                               in directory: PersistentStateDirectory, generation: UInt64) throws -> VMShimClient.PersistentSpawnFiles {
    let child = try recordSuspendedNativeLaunch(intent, in: directory, generation: generation)
    child.terminateAndReap()
    return child.files
}

@MainActor private final class SuspendedRecoveryChild {
    let pid: pid_t
    let files: VMShimClient.PersistentSpawnFiles
    private var reaped = false
    init(pid: pid_t, files: VMShimClient.PersistentSpawnFiles) { self.pid = pid; self.files = files }
    func expectStillRunning() {
        guard case .process = VMShimClient.observeProcess(pid) else {
            Issue.record("cleanup refresh signaled an unowned live launch"); return
        }
        var status: Int32 = 0
        let result = waitpid(pid, &status, WNOHANG)
        if result == pid { reaped = true }
        #expect(result == 0)
    }
    func terminateAndReap() {
        guard !reaped else { return }
        _ = Darwin.kill(pid, SIGKILL)
        while waitpid(pid, nil, 0) < 0 && errno == EINTR {}
        reaped = true
    }
}

@MainActor private func recordSuspendedNativeLaunch(_ intent: HostStorageIntents.Intent,
                                                  in directory: PersistentStateDirectory, generation: UInt64) throws -> SuspendedRecoveryChild {
    let executable = try #require(Bundle.main.executableURL)
    let container = ContainerRecord(id: intent.container, instanceID: try #require(UUID(uuidString: intent.containerInstance)),
        name: "native-proof", image: "unused")
    let specification = VMShimProtocol.Specification(containerID: intent.container, generation: generation,
        token: "native-proof", kernelPath: "/unused", initialRamdiskPath: "/unused",
        rootDiskPath: directory.url.appending(path: "unused.ext4").path,
        cpus: 1, memoryBytes: 268_435_456, macAddress: "02:ce:00:00:00:01",
        socketPath: "/tmp/ce-proof-\(UUID().uuidString).sock", logPath: directory.url.appending(path: "shim.log").path,
        shimLaunchUUID: intent.launch, workloadStorageMode: .managed)
    let files = try VMShimClient.preparePersistentSpawn(specification: specification, container: container,
        containerDirectory: directory, executable: executable)
    var attributes: posix_spawnattr_t?
    guard posix_spawnattr_init(&attributes) == 0 else { throw POSIXError(.EIO) }
    defer { posix_spawnattr_destroy(&attributes) }
    guard posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0 else { throw POSIXError(.EIO) }
    let strings: [String] = [executable.path, "vm-shim", "--spec", files.specificationURL.path, "--launch-intent", files.intentURL.path]
    let args: [UnsafeMutablePointer<CChar>?] = strings.map { value in value.withCString { Darwin.strdup($0) } }
    guard args.allSatisfy({ $0 != nil }) else { throw POSIXError(.ENOMEM) }
    defer { args.forEach { free($0) } }
    var argv = args + [nil]
    var pid: pid_t = 0
    let code = posix_spawn(&pid, executable.path, nil, &attributes, &argv, environ)
    guard code == 0 else { throw POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO) }
    let child = SuspendedRecoveryChild(pid: pid, files: files)
    do {
        guard case .process(let identity) = VMShimClient.observeProcess(pid) else { throw POSIXError(.ESRCH) }
        let record = try VMShimClient.publishPersistentLaunchIdentity(intentURL: files.intentURL, expectedIdentity: identity)
        #expect(record.processIdentifier == pid && record.processStartTime == identity.startTime)
        #expect(record.kernelIdentity != nil)
        return child
    } catch {
        child.terminateAndReap()
        throw error
    }
}

@MainActor private final class RecoveryFixture {
    let files: HostIntentFixture
    private var ownedJournal: HostStorageIntents?
    var journal: HostStorageIntents { ownedJournal! }
    let plan: HostStorageIntents.Intent
    let control: RecoveryControl
    private var ownedCoordinator: ManagedVolumeLifecycleCoordinator?
    var coordinator: ManagedVolumeLifecycleCoordinator { ownedCoordinator! }
    init(onlyFirstVolume: Bool = false, nativeObservationCompleted: @escaping () async -> Void = {}) throws {
        files = try HostIntentFixture()
        let journal = try files.initialize(); ownedJournal = journal
        try journal.reconciled(); try journal.planVolumes(files.volumes)
        plan = files.intent(onlyFirstVolume ? [files.volumes[0]] : nil)
        control = RecoveryControl(context: try .init(store: plan.store, serviceEpoch: plan.serviceEpoch,
            controllerEpoch: plan.controllerEpoch, controllerKey: plan.controllerKey, provenanceReference: files.provenance))
        ownedCoordinator = try .init(journal: journal, control: control, names: SharedVolumeInitializationCoordinator(),
            nativeObservationCompleted: nativeObservationCompleted)
    }
    func retiredNativeHistory(in directory: PersistentStateDirectory, cache: Bool = true) async throws -> VMShimClient.PersistentSpawnFiles {
        _ = try await coordinator.start(plan, guest: guest)
        try await coordinator.retireLaunch(plan.id)
        let first = try recordExitedNativeLaunch(plan, in: directory, generation: 1)
        if cache {
            let permit = try await coordinator.prepareContainment(plan.id, in: directory)
            try await coordinator.registerContainment([permit])
        }
        try await coordinator.reconcileStartup()
        return first
    }
    func disjointPlan() -> HostStorageIntents.Intent {
        let p = newPlan(volumes: [files.volumes[1]])
        return .init(id: p.id, store: p.store, container: String(repeating: "a", count: 64),
            containerInstance: HostIntentFixture.id(), launch: p.launch, specificationDigest: p.specificationDigest,
            serviceEpoch: p.serviceEpoch, controllerEpoch: p.controllerEpoch, controllerKey: p.controllerKey,
            prepare: p.prepare, reserveOperation: p.reserveOperation, completeOperation: p.completeOperation,
            replaceOperation: p.replaceOperation, mounts: p.mounts, slots: p.slots,
            version: 1, phase: .planned, prepareCompleted: false, cleanUnmount: false)
    }
    func retainedHistory() async throws -> (HostStorageIntents.Intent, VMShimClient.PersistentSpawnFiles) {
        _ = try await coordinator.start(plan, guest: guest)
        try await coordinator.retireLaunch(plan.id)
        let first = try recordAbsentNativeLaunch(plan, in: files.root, generation: 1)
        let pending = newPlan()
        control.fail("register", afterAcceptance: true)
        do { _ = try await coordinator.start(pending, guest: guest) } catch {}
        _ = try await coordinator.recover(pending.id)
        try recordAbsentNativeLaunch(pending, in: files.root, generation: 2)
        var permits: [ManagedVolumeLifecycleCoordinator.ReplacementPermit] = []
        for id in try journal.snapshot().intents.keys.sorted() {
            permits.append(try await coordinator.prepareContainment(id, in: files.root))
        }
        try await coordinator.registerContainment(permits)
        try await coordinator.reconcileStartup()
        return (try journal.intent(journal.token(for: pending.id)), first)
    }
    func reopen() throws {
        ownedCoordinator = nil; ownedJournal = nil
        let journal = try files.open(); ownedJournal = journal
        ownedCoordinator = try .init(journal: journal, control: control, names: SharedVolumeInitializationCoordinator())
    }
    func newPlan(volumes: [HostStorageIntents.Volume]? = nil) -> HostStorageIntents.Intent {
        let p = files.intent(volumes ?? files.volumes.filter { volume in plan.mounts.contains { $0.volume == volume.id } })
        return .init(id: p.id, store: p.store, container: plan.container, containerInstance: plan.containerInstance,
            launch: p.launch, specificationDigest: plan.specificationDigest, serviceEpoch: plan.serviceEpoch,
            controllerEpoch: plan.controllerEpoch, controllerKey: plan.controllerKey, prepare: p.prepare,
            reserveOperation: p.reserveOperation, completeOperation: p.completeOperation, replaceOperation: p.replaceOperation,
            mounts: p.mounts, slots: p.slots, version: 1, phase: .planned, prepareCompleted: false, cleanUnmount: false)
    }
    var guest: ManagedVolumeLifecycleCoordinator.GuestActions {
        .init(offerKeys: { intent, role in intent.slots.filter { $0.role == role.rawValue }.map {
            .init(attachment: $0.attachment, key: HostStorageIntents.hash(Data($0.attachment.utf8)))
        } }, credentialAndMount: { _, _ in }, prepare: { intent in
            .init(prepare: intent.prepare, containerInstance: intent.containerInstance, launch: intent.launch,
                succeeded: true, cleanCopyUp: true, evidenceDigest: String(repeating: "e", count: 64))
        }, closePrepare: { _ in true }, start: { _ in }, beforePublication: { _ in })
    }
}

/// Coordinator-only fault seam. Mirrors authority's phase/replay ordering; does
/// not claim to authenticate TLS or establish real VM containment.
private final class RecoveryControl: ManagedStorageControlling, @unchecked Sendable {
    typealias C = ManagedStorageControlProtocol
    typealias M = ManagedStorageControlClient
    let context: M.Context
    private let lock = NSLock()
    private var volumes: [String: M.Volume] = [:]
    private var lives: [String: M.VolumeLifecycle] = [:]
    private var attachments: [String: M.Attachment] = [:]
    private var prepares: [String: M.Prepare] = [:]
    private var operations: [String: Data] = [:]
    private var log: [String] = []
    private var failure: (String, Bool)?
    private var skipFailures = 0
    private var attempted: [String: [Data]] = [:]
    private var revision: UInt64 = 1
    private var mismatch = false
    private var lateRegisters = 0
    var blockRegister = false
    let registerStarted = AsyncStream<Void>.makeStream()
    let releaseRegister = DispatchSemaphore(value: 0)
    var blockRetirement: String?
    let retirementStarted = AsyncStream<Void>.makeStream()
    let releaseRetirement = DispatchSemaphore(value: 0)
    var events: [String] { lock.withLock { log } }
    var mismatchedReplay: Bool { lock.withLock { mismatch } }
    var registerAfterRetirement: Int { lock.withLock { lateRegisters } }
    init(context: M.Context) { self.context = context }
    func fail(_ kind: String, afterAcceptance: Bool, skipping: Int = 0) {
        lock.withLock { failure = (kind, afterAcceptance); skipFailures = skipping }
    }
    func attempts(for operation: String) -> [Data] { lock.withLock { attempted[operation] ?? [] } }
    func copy(context: M.Context) -> RecoveryControl {
        lock.withLock {
            let result = RecoveryControl(context: context)
            result.volumes = volumes; result.lives = lives; result.attachments = attachments
            result.prepares = prepares; result.operations = operations; result.revision = revision
            return result
        }
    }
    func send(_ request: C.ControlRequest) throws -> M.Reply {
        if case .retire(let retiring) = request, blockRetirement == retiring.attachment {
            blockRetirement = nil; retirementStarted.continuation.yield(())
            guard releaseRetirement.wait(timeout: .now() + 5) == .success else { throw M.Failure.remote("TIMEOUT") }
        }
        if case .registerAttachment = request, blockRegister {
            blockRegister = false; registerStarted.continuation.yield(())
            guard releaseRegister.wait(timeout: .now() + 5) == .success else { throw M.Failure.remote("TIMEOUT") }
        }
        return try lock.withLock {
            let kind: String, operation: String?
            switch request {
            case .query: kind = "query"; operation = nil
            case .createVolume(let r): kind = "create"; operation = r.operation
            case .reservePrepare(let r): kind = "reserve"; operation = r.operation
            case .registerAttachment(let r): kind = "register"; operation = r.operation
            case .retire(let r): kind = "retire"; operation = r.operation
            case .completePrepare(let r): kind = "complete"; operation = r.operation
            case .replacePrepare(let r): kind = "replace"; operation = r.operation
            default: throw M.Failure.invalidRequest
            }
            log.append(kind)
            let bytes = try request.durableBytes()
            if let operation { attempted[operation, default: []].append(bytes) }
            let fault = failure?.0 == kind && skipFailures == 0 ? failure : nil
            if failure?.0 == kind, skipFailures > 0 { skipFailures -= 1 }
            if fault != nil { failure = nil }
            if fault?.1 == false { throw M.Failure.remote("TIMEOUT") }
            if let operation, let previous = operations[operation], previous != bytes {
                mismatch = true; throw M.Failure.remote("CONFLICT")
            }
            let repeatOperation = operation.map { operations[$0] != nil } ?? false
            var reply: M.Reply = .ok
            switch request {
            case .query:
                reply = .snapshot(.init(schema: 3, revision: revision,
                    store: .init(id: context.store, deviceID: "device", root: .init(device: 1, inode: 1), exports: .init(device: 1, inode: 2)),
                    epoch: context.serviceEpoch, controller: .init(epoch: context.controllerEpoch, key: context.controllerKey),
                    volumes: volumes, volumeLifecycles: lives, attachments: attachments, prepares: prepares))
            case .createVolume(let r):
                if volumes[r.volume] == nil {
                    revision += 1
                    volumes[r.volume] = .init(id: r.volume, name: r.name, root: .init(device: 1, inode: UInt64(volumes.count + 10)))
                    lives[r.volume] = .init(phase: .ready, create: r.operation, delete: nil, createdRevision: revision, deletedRevision: nil)
                }
                reply = .volumeReceipt(.init(schema: 3, operation: r.operation, store: r.store, volume: volumes[r.volume]!, phase: .ready, revision: lives[r.volume]!.createdRevision!))
            case .reservePrepare(let r):
                if !repeatOperation { reserve(r) }
            case .registerAttachment(let r):
                if let old = attachments[r.binding.attachment], old.phase == .drained || old.phase == .retiring {
                    lateRegisters += 1; throw M.Failure.remote("BLOCKED")
                }
                attachments[r.binding.attachment] = .init(binding: r.binding, phase: .active, receipt: nil, retirement: nil)
            case .retire(let r):
                guard let old = attachments[r.attachment] else { throw M.Failure.remote("UNKNOWN") }
                let receipt: C.Receipt
                if let previous = old.receipt { receipt = previous }
                else { revision += 1; receipt = try .init(schema: 3, store: r.store, volume: r.volume,
                    attachment: r.attachment, prepare: old.binding.prepare, launch: old.binding.launch, revision: revision) }
                attachments[r.attachment] = .init(binding: old.binding, phase: .drained, receipt: receipt, retirement: old.retirement ?? r.operation)
                reply = .receipt(receipt)
            case .completePrepare(let r):
                guard let old = prepares[r.prepare] else { throw M.Failure.remote("UNKNOWN") }
                prepares[r.prepare] = .init(id: r.prepare, attachments: old.attachments, phase: .completed, successor: nil, attestation: r.attestation)
            case .replacePrepare(let r):
                if !repeatOperation {
                    guard let old = prepares[r.prepare], old.phase == .pending,
                          old.attachments.map(\.volume) == r.successor.attachments.map(\.volume) else { throw M.Failure.remote("CONFLICT") }
                    reserve(r.successor)
                    operations[r.successor.operation] = try C.ControlRequest.reservePrepare(r.successor).durableBytes()
                    prepares[r.prepare] = .init(id: old.id, attachments: old.attachments, phase: .replaced, successor: r.successor.prepare, attestation: nil)
                }
            default: throw M.Failure.invalidRequest
            }
            if let operation { operations[operation] = bytes; revision += 1 }
            if fault?.1 == true { throw M.Failure.remote("TIMEOUT") }
            return reply
        }
    }
    private func reserve(_ request: C.ReserveRequest) {
        for b in request.attachments { attachments[b.attachment] = .init(binding: b, phase: .reserved, receipt: nil, retirement: nil) }
        prepares[request.prepare] = .init(id: request.prepare, attachments: request.attachments, phase: .pending, successor: nil, attestation: nil)
    }
}
#endif

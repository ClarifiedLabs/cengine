#if os(macOS)
import Foundation
import Testing
@testable import CEngineRuntime

@Suite @MainActor struct ManagedVolumeLifecycleCoordinatorTests {
    @Test(arguments: [false, true])
    func invalidationJoinsOwnerlessCallsWithoutPublishing(deleting: Bool) async throws {
        let f = try ManagedLifecycleFixture(); defer { f.files.remove() }
        var volume = f.files.volumes[0]
        if deleting {
            volume.rootDevice = 1; volume.rootInode = 100; volume.createdRevision = 2
            try f.journal.recordVolume(volume)
        }
        let control = ManagedOwnerlessControl(context: f.control.context, volume: volume)
        defer { control.gate.release.signal() }
        let coordinator = try ManagedVolumeLifecycleCoordinator(journal: f.journal, control: control,
            names: SharedVolumeInitializationCoordinator())
        let operation = Task {
            if deleting { try await coordinator.deleteVolume(volume.id) }
            else { try await coordinator.reconcileStartup() }
        }
        for await _ in control.gate.started.stream { break }
        let invalidation = ManagedInvalidationObservation()
        var fencedRevision: UInt64 = 0
        // This actor cannot release the reply until invalidate suspends joining it.
        let release = Task { @MainActor in
            #expect(!invalidation.returned)
            #expect(control.wasRevoked)
            fencedRevision = try f.journal.snapshot().revision
            control.gate.release.signal()
        }
        await coordinator.invalidate()
        invalidation.returned = true
        try await release.value
        do { try await operation.value; Issue.record("old ownerless reply published") }
        catch ManagedVolumeLifecycleCoordinator.Failure.staleExecution {}
        let state = try f.journal.snapshot()
        #expect(state.revision == fencedRevision)
        #expect(state.reconciliationRequired)
        #expect(state.volumes[volume.id]?.deletedRevision == nil)
        #expect(!control.replyGateTimedOut, "ownerless reply deadlock watchdog expired before the MainActor released it")
        #expect(control.completed)
    }

    @Test(.timeLimit(.minutes(1))) func suspendedNameAcquisitionCannotPlanAfterInvalidation() async throws {
        let f = try ManagedLifecycleFixture(); defer { f.files.remove() }
        let names = SharedVolumeInitializationCoordinator()
        let lease = try await names.acquire(f.files.volumes.map(\.name))
        let coordinator = try ManagedVolumeLifecycleCoordinator(journal: f.journal, control: f.control, names: names)
        defer { lease.release() }
        let operation = Task { try await coordinator.start(f.plan, guest: f.guest()) }
        defer { operation.cancel() }
        // Task submission alone does not prove acquire has registered its
        // continuation. Observe the real waiter before revocation.
        // A short wall deadline also counts unrelated MainActor work in the full
        // suite. Use the test watchdog instead, and suspend rather than spin on
        // yield. On timeout, cancellation unwinds this wait and cancels operation
        // before releasing the held lease; an unregistered task cannot plan later.
        while names.waitingCount == 0 {
            try await Task.sleep(for: .milliseconds(1))
        }
        let registered = names.waitingCount
        await coordinator.invalidate()
        lease.release()
        do { _ = try await operation.value; Issue.record("revoked name waiter planned") }
        catch ManagedVolumeLifecycleCoordinator.Failure.staleExecution {}
        try #require(registered == 1, "name acquisition never registered before invalidation")
        #expect(try f.journal.snapshot().intents.isEmpty)
        #expect(f.control.events.isEmpty)
    }

    @Test func suspendedNativeObservationCannotPublishAfterInvalidation() async throws {
        let f = try ManagedLifecycleFixture(); defer { f.files.remove() }
        _ = try f.journal.plan(f.plan)
        let started = AsyncStream<Void>.makeStream(), release = AsyncStream<Void>.makeStream()
        let coordinator = try ManagedVolumeLifecycleCoordinator(journal: f.journal, control: f.control,
            names: SharedVolumeInitializationCoordinator(), nativeObservationCompleted: {
                started.continuation.yield(())
                for await _ in release.stream { break }
            })
        // Real persisted never-launched containment, not a fabricated permit or
        // direct helper invocation. Pause after the native census, before return.
        let observation = Task { try await coordinator.prepareContainment(f.plan.id, in: f.files.root) }
        for await _ in started.stream { break }
        await coordinator.invalidate()
        let revision = try f.journal.snapshot().revision
        release.continuation.yield(())
        do { _ = try await observation.value; Issue.record("old native evidence published") }
        catch ManagedVolumeLifecycleCoordinator.Failure.staleExecution {}
        #expect(try f.journal.snapshot().revision == revision)
        #expect(f.control.events.isEmpty)
    }

    @Test(arguments: ["offer", "prepare", "publication"])
    func suspendedGuestCallbackCannotPublishAfterInvalidation(boundary: String) async throws {
        let f = try ManagedLifecycleFixture(); defer { f.files.remove() }
        let original = f.guest()
        let started = AsyncStream<Void>.makeStream(), release = AsyncStream<Void>.makeStream()
        func pause(_ point: String) async {
            if boundary == point {
                started.continuation.yield(())
                for await _ in release.stream { break }
            }
        }
        let guest = ManagedVolumeLifecycleCoordinator.GuestActions(offerKeys: { intent, role in
            await pause("offer")
            return try await original.offerKeys(intent, role)
        }, credentialAndMount: original.credentialAndMount, prepare: { intent in
            await pause("prepare")
            return try await original.prepare(intent)
        }, closePrepare: original.closePrepare, start: original.start, beforePublication: { intent in
            await pause("publication")
            try await original.beforePublication(intent)
        })
        let operation = Task { try await f.coordinator.start(f.plan, guest: guest) }
        for await _ in started.stream { break }
        await f.coordinator.invalidate()
        let revision = try f.journal.snapshot().revision
        release.continuation.yield(())
        do { _ = try await operation.value; Issue.record("old guest callback published") }
        catch ManagedVolumeLifecycleCoordinator.Failure.staleExecution {}
        #expect(try f.journal.snapshot().revision == revision)
        #expect(try f.journal.snapshot().reconciliationRequired)
    }

    @Test(arguments: [HostStorageIntents.Phase.retired, .replaced, .unlaunched, .abortedBeforeAdmission])
    func terminalHistoryDoesNotRevalidateObsoleteWholeContainerCensus(phase: HostStorageIntents.Phase) async throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        var historical = f.intent(); historical.phase = phase
        // RTM-079: sealed containment covered generations 1-2 at cross-E startup.
        // The same container later acquired generations 3-4, then drained them.
        // A query must retain ROOT/containment provenance without requiring that
        // obsolete whole-container census to equal the new retained inventory.
        let original = Set(["generation-1", "generation-2"])
        let current = original.union(["generation-3", "generation-4"])
        try await ManagedVolumeLifecycleCoordinator.validateHistoricalForQuery(historical,
            recoveryPermitted: true, containment: original) { proof in
                #expect(proof == current, "terminal query invoked an obsolete census")
                throw ManagedVolumeLifecycleCoordinator.Failure.wrongEvidence
            }
    }

    @Test(arguments: [false, true])
    func terminalQueryStillRequiresRootPermissionAndSealedContainment(missingContainment: Bool) async throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        var historical = f.intent(); historical.phase = .retired
        var revalidated = false
        do {
            try await ManagedVolumeLifecycleCoordinator.validateHistoricalForQuery(historical,
                recoveryPermitted: missingContainment, containment: missingContainment ? nil : 1) { _ in revalidated = true }
            Issue.record("terminal history bypassed recovery provenance")
        } catch ManagedVolumeLifecycleCoordinator.Failure.repairRequired {}
        #expect(!revalidated)
    }

    @Test(arguments: [HostStorageIntents.Phase.planned, .prepareFrozen, .prepareAdmitted, .prepareSucceeded,
                      .prepareDrained, .prepareCompleted, .runtimeFrozen, .running, .quarantined])
    func nonterminalQueryStillRequiresFreshExactContainment(phase: HostStorageIntents.Phase) async throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        var historical = f.intent(); historical.phase = phase
        var revalidated = false
        do {
            try await ManagedVolumeLifecycleCoordinator.validateHistoricalForQuery(historical,
                recoveryPermitted: true, containment: 1) { _ in
                    revalidated = true
                    throw ManagedVolumeLifecycleCoordinator.Failure.wrongEvidence
                }
            Issue.record("stale nonterminal containment accepted")
        } catch ManagedVolumeLifecycleCoordinator.Failure.wrongEvidence {}
        #expect(revalidated)
    }

    @Test func exactDeletionReplaySurvivesLostReplyAndReopenWithoutRepublishing() async throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        var volume = f.volumes[0]
        volume.rootDevice = 1; volume.rootInode = 100; volume.createdRevision = 2
        let plan = f.intent()
        let context = try ManagedStorageControlClient.Context(store: plan.store, serviceEpoch: plan.serviceEpoch,
            controllerEpoch: plan.controllerEpoch, controllerKey: plan.controllerKey, provenanceReference: f.provenance)
        let control = DeletionReplayControl(context: context, volume: volume)
        do {
            let journal = try f.initialize()
            try journal.reconciled(); try journal.planVolumes(f.volumes); try journal.recordVolume(volume)
            let coordinator = try ManagedVolumeLifecycleCoordinator(journal: journal, control: control, names: SharedVolumeInitializationCoordinator())
            await #expect(throws: (any Error).self) { _ = try await coordinator.settleDeletion(volume.id, name: volume.name) }
            #expect(try journal.snapshot().reconciliationRequired)
        }
        let journal = try f.open()
        let coordinator = try ManagedVolumeLifecycleCoordinator(journal: journal, control: control, names: SharedVolumeInitializationCoordinator())
        guard case .remote(let receipt) = try await coordinator.settleDeletion(volume.id, name: volume.name) else { Issue.record("not remote"); return }
        #expect(receipt.revision == 3)
        _ = try await coordinator.settleDeletion(volume.id, name: volume.name)
        #expect(control.requests.count == 2 && control.requests[0] == control.requests[1])
        #expect(try journal.snapshot().volumes[volume.id]?.isDeleted == true)
        #expect(!coordinator.canDelete(volume: volume.id))
        #expect(throws: (any Error).self) { _ = try coordinator.deletionSettlement(volume.id, name: "wrong") }
    }
    @Test func neverCreatedDeletionHasNoRemoteTrafficAndCannotBeRepublished() async throws {
        let f = try ManagedLifecycleFixture(); defer { f.files.remove() }
        let volume = f.files.volumes[0]
        guard case .local(let store, let id, let operation, _) = try await f.coordinator.settleDeletion(volume.id, name: volume.name) else {
            Issue.record("remote authority invented"); return
        }
        #expect(store == f.files.store && id == volume.id && operation == volume.deleteOperation)
        #expect(f.control.events.isEmpty)
        #expect(try f.journal.snapshot().volumes[volume.id]?.localDeletionRevision != nil)
    }

    @Test func prepareReceiptsPrecedeCompletionAndFreshRuntimeAuthority() async throws {
        let f = try ManagedLifecycleFixture(); defer { f.files.remove() }
        let token = try await f.coordinator.start(f.plan, guest: f.guest())
        let state = try f.journal.intent(token)
        #expect(state.phase == .running)
        #expect(state.prepareCompleted)
        #expect(state.slots.filter { $0.role == "prepare" }.allSatisfy { $0.receipt != nil })
        #expect(state.slots.filter { $0.role == "runtime" }.allSatisfy { $0.receipt == nil })
        let events = f.control.events
        #expect(events.firstIndex(of: "prepare")! < events.firstIndex(of: "unmount")!)
        #expect(events.firstIndex(of: "unmount")! < events.firstIndex(of: "complete")!)
        #expect(events.firstIndex(of: "complete")! < events.firstIndex(of: "offer-runtime")!)
        #expect(events.last == "publication")
        #expect(!f.coordinator.canDelete(volume: f.files.volumes[0].id))
        try await f.coordinator.retireLaunch(f.plan.id)
        #expect(f.coordinator.canDelete(volume: f.files.volumes[0].id))
        #expect(!f.coordinator.canDelete(volume: HostIntentFixture.id()))
        #expect(!f.coordinator.canChangeMode(volume: f.files.volumes[0].id))
    }
    @Test(arguments: [false, true]) func concurrentRetirementJoinsExactDrainWithoutPreempting(cancelFirst: Bool) async throws {
        let f = try ManagedLifecycleFixture(); defer { f.files.remove() }
        let running = try f.journal.intent(await f.coordinator.start(f.plan, guest: f.guest()))
        let runtime = try #require(running.slots.first { $0.role == "runtime" })
        let gate = f.control.blockRetirement(runtime.attachment)
        defer { gate.release.signal() }
        let first = Task { try await f.coordinator.retireLaunch(f.plan.id) }
        for await _ in gate.started.stream { break }
        #expect(!f.coordinator.canDelete(volume: runtime.volume))
        if cancelFirst { first.cancel() }
        // This actor cannot run the release until the second retirement suspends.
        // Thus both calls overlap the exact blocked control request, without sleeps.
        let release = Task { @MainActor in gate.release.signal() }
        try await f.coordinator.retireLaunch(f.plan.id)
        try await first.value
        await release.value
        let retired = try f.journal.intent(f.journal.token(for: f.plan.id))
        #expect(retired.phase == .retired && retired.prepareCompleted)
        #expect(retired.slots.allSatisfy { $0.receipt != nil })
        #expect(retired.launch == running.launch && retired.containerInstance == running.containerInstance)
        #expect(retired.slots.map(\.key) == running.slots.map(\.key))
        for slot in running.slots where slot.role == "runtime" {
            #expect(f.control.events.filter { $0 == "retire-" + slot.attachment }.count == 1)
        }
        #expect(f.coordinator.canDelete(volume: runtime.volume))
    }

    @Test(arguments: [false, true])
    func newStartJoinsOwnedRuntimeRetirementBeforePlanning(cancelStart: Bool) async throws {
        let f = try ManagedLifecycleFixture(); defer { f.files.remove() }
        let running = try f.journal.intent(await f.coordinator.start(f.plan, guest: f.guest()))
        let next = f.files.replacement(f.plan)
        let runtime = try #require(running.slots.first { $0.role == "runtime" })
        let gate = f.control.blockRetirement(runtime.attachment)
        defer { gate.release.signal() }
        let retirement = Task { try await f.coordinator.retireLaunch(running.id) }
        for await _ in gate.started.stream { break }
        let before = try f.journal.snapshot(), events = f.control.events
        let observation = ManagedStartObservation()
        let operation = Task { @MainActor in
            // Uncontended acquire inherits this actor. The release cannot run
            // until start actually suspends joining the owned retirement.
            let release = Task { @MainActor in
                defer { gate.release.signal() }
                #expect(!observation.returned)
                let waiting = try f.journal.snapshot()
                #expect(waiting.revision == before.revision)
                #expect(waiting.intents[next.id] == nil)
                #expect(f.control.events == events)
                if cancelStart { observation.operation?.cancel() }
            }
            do {
                _ = try await f.coordinator.start(next, guest: f.guestAfterRetirement(of: running.id))
                Issue.record("new start passed the key-offer sentinel")
            } catch is CancellationError {
                #expect(cancelStart)
            } catch ManagedStartSentinel.keysOffered {
                #expect(!cancelStart)
            } catch {
                Issue.record("new start did not join its owned retirement: \(error)")
            }
            observation.returned = true
            try await release.value
        }
        observation.operation = operation
        try await operation.value
        try await retirement.value
        let state = try f.journal.snapshot()
        let retired = try #require(state.intents[running.id])
        #expect(retired.phase == .retired && retired.prepareCompleted)
        #expect(retired.slots.allSatisfy { $0.receipt != nil })
        #expect(retired.slots.map(\.key) == running.slots.map(\.key))
        #expect((state.intents[next.id] == nil) == cancelStart)
        for slot in running.slots where slot.role == "runtime" {
            #expect(f.control.events.filter { $0 == "retire-" + slot.attachment }.count == 1)
        }
    }

    @Test func newStartPreservesOwnedRetirementFailureWithoutRetryingQuarantine() async throws {
        let f = try ManagedLifecycleFixture(); defer { f.files.remove() }
        let running = try f.journal.intent(await f.coordinator.start(f.plan, guest: f.guest()))
        let next = f.files.replacement(f.plan)
        let runtime = try #require(running.slots.first { $0.role == "runtime" })
        f.control.failRetirement = runtime.attachment
        let gate = f.control.blockRetirement(runtime.attachment)
        defer { gate.release.signal() }
        let retirement = Task { try await f.coordinator.retireLaunch(running.id) }
        for await _ in gate.started.stream { break }
        let before = try f.journal.snapshot(), events = f.control.events
        var returned = false
        let release = Task { @MainActor in
            defer { gate.release.signal() }
            #expect(!returned)
            let waiting = try f.journal.snapshot()
            #expect(waiting.revision == before.revision)
            #expect(waiting.intents[next.id] == nil)
            #expect(f.control.events == events)
        }
        do {
            _ = try await f.coordinator.start(next, guest: f.guestAfterRetirement(of: running.id))
            Issue.record("new start ignored failed retirement")
        } catch ManagedStorageControlClient.Failure.remote(let code) {
            #expect(code == "TIMEOUT")
        } catch { Issue.record("owned retirement failure was replaced: \(error)") }
        returned = true
        try await release.value
        do { try await retirement.value; Issue.record("retirement owner ignored lost reply") }
        catch ManagedStorageControlClient.Failure.remote(let code) { #expect(code == "TIMEOUT") }
        let failed = try f.journal.snapshot()
        #expect(failed.intents[next.id] == nil)
        let quarantined = try #require(failed.intents[running.id])
        #expect(quarantined.phase == .quarantined)
        #expect(quarantined.slots.first { $0.attachment == runtime.attachment }?.receipt == nil)
        #expect(quarantined.slots.filter { $0.attachment != runtime.attachment }.allSatisfy { $0.receipt != nil })
        for slot in running.slots where slot.role == "runtime" {
            #expect(f.control.events.filter { $0 == "retire-" + slot.attachment }.count == 1)
        }
        // Once the failed owner has unwound, quarantine remains a hard fence.
        // Removing the fault must not turn another start into implicit recovery.
        f.control.failRetirement = nil
        let failedEvents = f.control.events
        do {
            _ = try await f.coordinator.start(next, guest: f.guestAfterRetirement(of: running.id))
            Issue.record("unowned quarantine was implicitly retried")
        } catch HostStorageIntents.Failure.blocked {}
        #expect(try f.journal.snapshot().revision == failed.revision)
        #expect(try f.journal.snapshot().intents[next.id] == nil)
        #expect(f.control.events == failedEvents)
    }

    @Test func invalidationRevokesNewStartJoiningOwnedRetirement() async throws {
        let f = try ManagedLifecycleFixture(); defer { f.files.remove() }
        let running = try f.journal.intent(await f.coordinator.start(f.plan, guest: f.guest()))
        let next = f.files.replacement(f.plan)
        let runtime = try #require(running.slots.first { $0.role == "runtime" })
        let gate = f.control.blockRetirement(runtime.attachment)
        defer { gate.release.signal() }
        let retirement = Task { try await f.coordinator.retireLaunch(running.id) }
        for await _ in gate.started.stream { break }
        let before = try f.journal.snapshot(), events = f.control.events
        var returned = false
        var fencedRevision: UInt64 = 0
        let invalidation = Task { @MainActor in
            #expect(!returned)
            let waiting = try f.journal.snapshot()
            #expect(waiting.revision == before.revision)
            #expect(waiting.intents[next.id] == nil)
            #expect(f.control.events == events)
            // This nested release runs only after invalidate fences the start
            // and suspends joining the already-submitted retirement reply.
            let release = Task { @MainActor in
                defer { gate.release.signal() }
                fencedRevision = try f.journal.snapshot().revision
            }
            await f.coordinator.invalidate()
            try await release.value
        }
        do {
            _ = try await f.coordinator.start(next, guest: f.guestAfterRetirement(of: running.id))
            Issue.record("invalidated start joined stale retirement")
        } catch ManagedVolumeLifecycleCoordinator.Failure.staleExecution {}
        catch { Issue.record("start did not reach the owned retirement join: \(error)") }
        returned = true
        do { try await retirement.value; Issue.record("revoked retirement owner published") }
        catch ManagedVolumeLifecycleCoordinator.Failure.staleExecution {}
        try await invalidation.value
        let state = try f.journal.snapshot()
        #expect(state.revision == fencedRevision)
        #expect(state.reconciliationRequired)
        #expect(state.intents[next.id] == nil)
        let fenced = try #require(state.intents[running.id])
        #expect(fenced.phase == .quarantined)
        #expect(fenced.slots.filter { $0.role == "runtime" }.allSatisfy { $0.receipt == nil })
        #expect(f.control.events == events + ["retire-" + runtime.attachment])
    }

    @Test func runtimeDisconnectDuringRetirementPreservesRawExecution() async throws {
        let f = try ManagedLifecycleFixture(); defer { f.files.remove() }
        let running = try f.journal.intent(await f.coordinator.start(f.plan, guest: f.guest()))
        let runtime = try #require(running.slots.first { $0.role == "runtime" })
        var fence = RawBackendExecutionFence()
        let generation = fence.replace(running.container)
        var hints = RawManagedStorageBackend.RetirementHints()
        let close = hints.begin(intents: [running], container: running.container,
            instance: running.containerInstance, launch: running.launch)
        let gate = f.control.blockRetirement(runtime.attachment)
        defer { gate.release.signal() }
        let retirement = Task { try await f.coordinator.retireLaunch(running.id) }
        for await _ in gate.started.stream { break }
        let current = try f.journal.intent(f.journal.token(for: running.id))
        // Exercise the production watcher queue against the real journal while
        // the exact retirement reply is gated. A hint is not completion proof.
        try hints.enqueue(runtime.attachment)
        if let target = try hints.next(intents: [current], closingPrepare: []), target.launch == running.launch {
            _ = fence.replace(target.container)
        }
        #expect(fence.owns(running.container, token: generation))
        gate.release.signal()
        try await retirement.value
        hints.end(close)
        let retired = try f.journal.intent(f.journal.token(for: running.id))
        #expect(retired.slots.allSatisfy { $0.receipt != nil })
        #expect(try hints.next(intents: [retired], closingPrepare: []) == nil)
        #expect(hints.pending.isEmpty)
        let published = try await RawCompletionPublisher.run(fence: fence, identifier: running.container,
            generation: generation, publish: { RawCompletionPublication(value: 42, synchronizeFabric: false) },
            synchronizeFabric: {})
        #expect(published == 42)
    }

    @Test func joinedRetirementPreservesFailureAndRetriesOnlyUnsettledAttachments() async throws {
        let f = try ManagedLifecycleFixture(); defer { f.files.remove() }
        _ = try await f.coordinator.start(f.plan, guest: f.guest())
        let runtime = try #require(f.plan.slots.first { $0.role == "runtime" })
        f.control.failRetirement = runtime.attachment
        let gate = f.control.blockRetirement(runtime.attachment)
        defer { gate.release.signal() }
        let first = Task { try await f.coordinator.retireLaunch(f.plan.id) }
        for await _ in gate.started.stream { break }
        let release = Task { @MainActor in gate.release.signal() }
        do { try await f.coordinator.retireLaunch(f.plan.id); Issue.record("lost reply accepted") }
        catch ManagedStorageControlClient.Failure.remote(let code) { #expect(code == "TIMEOUT") }
        do { try await first.value; Issue.record("lost reply accepted by owner") }
        catch ManagedStorageControlClient.Failure.remote(let code) { #expect(code == "TIMEOUT") }
        await release.value
        let failed = try f.journal.intent(f.journal.token(for: f.plan.id))
        #expect(failed.phase == .quarantined)
        #expect(failed.slots.first { $0.attachment == runtime.attachment }?.receipt == nil)
        #expect(!f.coordinator.canDelete(volume: runtime.volume))
        let request = try f.journal.snapshot().operations[runtime.retireOperation]
        f.control.failRetirement = nil
        try await f.coordinator.retireLaunch(f.plan.id)
        let retired = try f.journal.intent(f.journal.token(for: f.plan.id))
        #expect(retired.phase == .retired && retired.slots.allSatisfy { $0.receipt != nil })
        #expect(try f.journal.snapshot().operations[runtime.retireOperation] == request)
        for slot in f.plan.slots where slot.role == "runtime" {
            #expect(f.control.events.filter { $0 == "retire-" + slot.attachment }.count == (slot.attachment == runtime.attachment ? 2 : 1))
        }
    }

    @Test func invalidationRevokesJoinedRetirementBeforeReceiptPublication() async throws {
        let f = try ManagedLifecycleFixture(); defer { f.files.remove() }
        _ = try await f.coordinator.start(f.plan, guest: f.guest())
        let runtime = try #require(f.plan.slots.first { $0.role == "runtime" })
        let gate = f.control.blockRetirement(runtime.attachment)
        defer { gate.release.signal() }
        let first = Task { try await f.coordinator.retireLaunch(f.plan.id) }
        for await _ in gate.started.stream { break }
        let invalidate = Task { @MainActor in
            let release = Task { @MainActor in gate.release.signal() }
            await f.coordinator.invalidate()
            await release.value
        }
        do { try await f.coordinator.retireLaunch(f.plan.id); Issue.record("revoked join published") }
        catch ManagedVolumeLifecycleCoordinator.Failure.staleExecution {}
        do { try await first.value; Issue.record("revoked owner published") }
        catch ManagedVolumeLifecycleCoordinator.Failure.staleExecution {}
        await invalidate.value
        let fenced = try f.journal.intent(f.journal.token(for: f.plan.id))
        #expect(fenced.phase == .quarantined)
        #expect(fenced.slots.filter { $0.role == "runtime" }.allSatisfy { $0.receipt == nil })
        #expect(f.control.events.filter { $0 == "retire-" + runtime.attachment }.count == 1)
        #expect(!f.coordinator.canDelete(volume: runtime.volume))
        do { try await f.coordinator.retireLaunch(f.plan.id); Issue.record("invalidated owner reused") }
        catch ManagedVolumeLifecycleCoordinator.Failure.blocked {}
    }

    @Test func unsuccessfulPrepareAndUnmountFailureStillAttemptEveryRetirement() async throws {
        for failure in ["prepare", "unmount"] {
            let f = try ManagedLifecycleFixture(); defer { f.files.remove() }
            do { _ = try await f.coordinator.start(f.plan, guest: f.guest(failure: failure)); Issue.record("unexpected success") }
            catch {}
            let current = try f.journal.intent(f.journal.token(for: f.plan.id))
            #expect(!current.prepareCompleted)
            #expect(current.phase == .quarantined)
            #expect(current.slots.filter { $0.role == "prepare" }.allSatisfy { $0.receipt != nil })
            #expect(!f.control.events.contains("complete"))
            #expect(!f.control.events.contains("offer-runtime"))
            #expect(!f.coordinator.canDelete(volume: f.files.volumes[0].id))
        }
    }
    @Test func runtimeSetupFailureAndPublicationFailureUseSameQuarantine() async throws {
        for failure in ["mount-runtime", "publication"] {
            let f = try ManagedLifecycleFixture(); defer { f.files.remove() }
            do { _ = try await f.coordinator.start(f.plan, guest: f.guest(failure: failure)); Issue.record("unexpected success") }
            catch {}
            let current = try f.journal.intent(f.journal.token(for: f.plan.id))
            #expect(current.phase == .quarantined)
            #expect(current.prepareCompleted)
            #expect(current.slots.allSatisfy { $0.receipt != nil })
            #expect(!f.coordinator.canDelete(volume: f.files.volumes[0].id))
        }
    }
    @Test func healthyRuntimePeerDoesNotBlockSharedInitialization() async throws {
        let f = try ManagedLifecycleFixture(); defer { f.files.remove() }
        _ = try await f.coordinator.start(f.plan, guest: f.guest())
        let shared = try f.journal.plan(f.files.intent())
        #expect(try f.journal.intent(shared).phase == .planned)
        #expect(!f.coordinator.canDelete(volume: f.files.volumes[0].id))
    }
    @Test func queryCannotOvertakeInFlightDeleteAndClearItsLostReplyFence() async throws {
        let f = try ManagedLifecycleFixture(); defer { f.files.remove() }
        var volume = f.files.volumes[0]
        volume.rootDevice = 1; volume.rootInode = 100; volume.createdRevision = 2
        try f.journal.recordVolume(volume)
        let control = ManagedDeleteControlFixture(context: f.control.context,
            journalURL: f.files.url.appending(path: "managed-storage/state.json"))
        let coordinator = try ManagedVolumeLifecycleCoordinator(journal: f.journal, control: control,
            names: SharedVolumeInitializationCoordinator())
        let deletion = Task { try await coordinator.deleteVolume(volume.id) }
        for await _ in control.started.stream { break }
        do { try await coordinator.reconcileStartup(); Issue.record("query overtook delete") } catch {}
        control.release.signal()
        do { try await deletion.value; Issue.record("lost reply treated as success") } catch {}
        #expect(control.queryCount == 0)
        #expect(try f.journal.snapshot().reconciliationRequired)
        #expect(!coordinator.canDelete(volume: volume.id))
    }
    @Test func lostRetireReplyDoesNotSkipOtherAttachmentsOrCompletePrepare() async throws {
        let f = try ManagedLifecycleFixture(); defer { f.files.remove() }
        f.control.failRetirement = f.plan.slots.first { $0.role == "prepare" }!.attachment
        do { _ = try await f.coordinator.start(f.plan, guest: f.guest()); Issue.record("unexpected success") }
        catch {}
        let current = try f.journal.intent(f.journal.token(for: f.plan.id))
        #expect(!current.prepareCompleted)
        #expect(current.slots.filter { $0.role == "prepare" && $0.receipt != nil }.count == 1)
        #expect(f.control.events.filter { $0.hasPrefix("retire-") }.count >= 2)
        #expect(!f.control.events.contains("complete"))
        #expect(!f.coordinator.canDelete(volume: f.files.volumes[0].id))
    }
    @Test func cancellationDoesNotCancelRetirementOwnership() async throws {
        let f = try ManagedLifecycleFixture(); defer { f.files.remove() }
        let operation = Task { try await f.coordinator.start(f.plan, guest: f.guest(failure: "cancel")) }
        do { _ = try await operation.value; Issue.record("unexpected success") } catch {}
        let current = try f.journal.intent(f.journal.token(for: f.plan.id))
        #expect(current.slots.filter { $0.role == "prepare" }.allSatisfy { $0.receipt != nil })
        #expect(!current.prepareCompleted)
    }
}

@MainActor private struct ManagedLifecycleFixture {
    let files: HostIntentFixture
    let journal: HostStorageIntents
    let plan: HostStorageIntents.Intent
    let control: ManagedLifecycleControlFixture
    let coordinator: ManagedVolumeLifecycleCoordinator
    init() throws {
        files = try HostIntentFixture(); journal = try files.initialize()
        try journal.reconciled(); try journal.planVolumes(files.volumes)
        plan = files.intent()
        control = try .init(plan: plan, volumes: files.volumes, provenance: files.provenance,
            journalURL: files.url.appending(path: "managed-storage/state.json"))
        coordinator = try .init(journal: journal, control: control, names: SharedVolumeInitializationCoordinator())
    }
    func guestAfterRetirement(of prior: String) -> ManagedVolumeLifecycleCoordinator.GuestActions {
        let original = guest()
        return .init(offerKeys: { _, role in
            #expect(role == .prepare)
            let retired = try journal.intent(journal.token(for: prior))
            #expect(retired.phase == .retired && retired.prepareCompleted)
            #expect(retired.slots.allSatisfy { $0.receipt != nil })
            // Stop before any fresh authority: the control fixture intentionally
            // supports only the original plan's attachment receipts.
            throw ManagedStartSentinel.keysOffered
        }, credentialAndMount: original.credentialAndMount, prepare: original.prepare,
            closePrepare: original.closePrepare, start: original.start, beforePublication: original.beforePublication)
    }
    func guest(failure: String? = nil) -> ManagedVolumeLifecycleCoordinator.GuestActions {
        let control = control
        func event(_ name: String) throws {
            control.append(name)
            if failure == name { throw ManagedStorageControlClient.Failure.remote("INTERNAL") }
        }
        return .init(offerKeys: { intent, role in
            try event("offer-" + role.rawValue)
            return intent.slots.filter { $0.role == role.rawValue }.map {
                .init(attachment: $0.attachment, key: HostStorageIntents.hash(Data($0.attachment.utf8)))
            }
        }, credentialAndMount: { _, role in try event("mount-" + role.rawValue) }, prepare: { intent in
            try event("prepare")
            if failure == "cancel" { withUnsafeCurrentTask { $0?.cancel() }; throw CancellationError() }
            return .init(prepare: intent.prepare, containerInstance: intent.containerInstance, launch: intent.launch,
                succeeded: true, cleanCopyUp: true, evidenceDigest: String(repeating: "e", count: 64))
        }, closePrepare: { _ in try event("unmount"); return true }, start: { _ in try event("start") },
            beforePublication: { _ in try event("publication") })
    }
}

/// Explicit internal control test seam: exercises coordinator ordering and faults,
/// not TLS/PKI identity. Native child/service TLS is tested separately in Go.
private final class ManagedLifecycleControlFixture: ManagedStorageControlling, @unchecked Sendable {
    let context: ManagedStorageControlClient.Context
    private let lock = NSLock()
    private var log: [String] = []
    private let plan: HostStorageIntents.Intent
    private let volumes: [HostStorageIntents.Volume]
    private let journalURL: URL
    var failRetirement: String?
    private var retirementGate: (String, ManagedRetirementGate)?
    func blockRetirement(_ attachment: String) -> ManagedRetirementGate {
        let gate = ManagedRetirementGate()
        lock.withLock { retirementGate = (attachment, gate) }
        return gate
    }
    var events: [String] { lock.withLock { log } }
    init(plan: HostStorageIntents.Intent, volumes: [HostStorageIntents.Volume], provenance: String, journalURL: URL) throws {
        self.plan = plan; self.volumes = volumes; self.journalURL = journalURL
        context = try .init(store: plan.store, serviceEpoch: plan.serviceEpoch, controllerEpoch: plan.controllerEpoch,
            controllerKey: plan.controllerKey, provenanceReference: provenance)
    }
    func append(_ event: String) { lock.withLock { log.append(event) } }
    func send(_ request: ManagedStorageControlProtocol.ControlRequest) throws -> ManagedStorageControlClient.Reply {
        if case .retire(let retiring) = request {
            let gate = lock.withLock { () -> ManagedRetirementGate? in
                guard retirementGate?.0 == retiring.attachment else { return nil }
                defer { retirementGate = nil }
                return retirementGate?.1
            }
            if let gate {
                gate.started.continuation.yield(())
                guard gate.release.wait(timeout: .now() + 10) == .success else {
                    throw ManagedStorageControlClient.Failure.remote("TIMEOUT")
                }
            }
        }
        return try lock.withLock {
            let operation: String
            let result: ManagedStorageControlClient.Reply
            switch request {
            case .createVolume(let request):
                operation = request.operation; log.append("create")
                let index = volumes.firstIndex { $0.id == request.volume }!
                result = .volumeReceipt(.init(schema: 3, operation: operation, store: context.store,
                    volume: .init(id: request.volume, name: request.name, root: .init(device: 1, inode: UInt64(100 + index))), phase: .ready, revision: 2))
            case .reservePrepare(let request): operation = request.operation; log.append("reserve"); result = .ok
            case .registerAttachment(let request): operation = request.operation; log.append("register-" + request.binding.role.rawValue); result = .ok
            case .completePrepare(let request): operation = request.operation; log.append("complete"); result = .ok
            case .retire(let request):
                operation = request.operation; log.append("retire-" + request.attachment)
                if request.attachment == failRetirement { throw ManagedStorageControlClient.Failure.remote("TIMEOUT") }
                let slot = plan.slots.first { $0.attachment == request.attachment }!
                result = .receipt(try .init(schema: 3, store: context.store, volume: request.volume,
                    attachment: request.attachment, prepare: slot.role == "prepare" ? plan.prepare : nil,
                    launch: plan.launch, revision: 4))
            default: throw ManagedStorageControlClient.Failure.invalidRequest
            }
            // This assertion reads the real fsynced journal, not an event mock.
            let state = try JSONDecoder().decode(HostStorageIntents.State.self, from: Data(contentsOf: journalURL))
            let bytes = try request.durableBytes()
            guard state.operations[operation] == bytes,
                  state.operationDigests[operation] == HostStorageIntents.hash(bytes), state.intents[plan.id] != nil else {
                throw ManagedStorageControlClient.Failure.invalidRequest
            }
            return result
        }
    }
}
private enum ManagedStartSentinel: Error { case keysOffered }
@MainActor private final class ManagedStartObservation {
    var returned = false
    var operation: Task<Void, Error>?
}

private final class ManagedRetirementGate: Sendable {
    let started = AsyncStream<Void>.makeStream()
    let release = DispatchSemaphore(value: 0)
}

private final class DeletionReplayControl: ManagedStorageControlling, @unchecked Sendable {
    let context: ManagedStorageControlClient.Context
    let volume: HostStorageIntents.Volume
    private let lock = NSLock()
    private var calls: [Data] = []
    var requests: [Data] { lock.withLock { calls } }
    init(context: ManagedStorageControlClient.Context, volume: HostStorageIntents.Volume) { self.context = context; self.volume = volume }
    func send(_ request: ManagedStorageControlProtocol.ControlRequest) throws -> ManagedStorageControlClient.Reply {
        try lock.withLock {
            guard case .deleteVolume(let deletion) = request, deletion.volume == volume.id else { throw ManagedStorageControlClient.Failure.invalidRequest }
            calls.append(try request.durableBytes())
            if calls.count == 1 { throw ManagedStorageControlClient.Failure.remote("TIMEOUT") }
            return .volumeReceipt(.init(schema: 3, operation: deletion.operation, store: context.store,
                volume: .init(id: volume.id, name: volume.name, root: .init(device: 1, inode: 100)), phase: .deleted, revision: 3))
        }
    }
}
private final class ManagedDeleteControlFixture: ManagedStorageControlling, @unchecked Sendable {
    let context: ManagedStorageControlClient.Context
    let journalURL: URL
    let started = AsyncStream<Void>.makeStream()
    let release = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var queries = 0
    var queryCount: Int { lock.withLock { queries } }
    init(context: ManagedStorageControlClient.Context, journalURL: URL) { self.context = context; self.journalURL = journalURL }
    func send(_ request: ManagedStorageControlProtocol.ControlRequest) throws -> ManagedStorageControlClient.Reply {
        if case .query = request { lock.withLock { queries += 1 }; throw ManagedStorageControlClient.Failure.invalidRequest }
        guard case .deleteVolume(let deletion) = request else { throw ManagedStorageControlClient.Failure.invalidRequest }
        let state = try JSONDecoder().decode(HostStorageIntents.State.self, from: Data(contentsOf: journalURL))
        guard state.reconciliationRequired, state.operations[deletion.operation] == (try request.durableBytes()) else {
            throw ManagedStorageControlClient.Failure.invalidRequest
        }
        started.continuation.yield(())
        guard release.wait(timeout: .now() + 3) == .success else { throw ManagedStorageControlClient.Failure.remote("TIMEOUT") }
        throw ManagedStorageControlClient.Failure.remote("TIMEOUT")
    }
}
@MainActor private final class ManagedInvalidationObservation { var returned = false }

/// Returns successful late replies so fencing cannot hide behind transport errors.
private final class ManagedOwnerlessControl: ManagedStorageControlling, @unchecked Sendable {
    let context: ManagedStorageControlClient.Context
    let volume: HostStorageIntents.Volume
    let gate = ManagedRetirementGate()
    private let lock = NSLock()
    private var revoked = false
    private var finished = false
    private var timedOut = false
    var wasRevoked: Bool { lock.withLock { revoked } }
    var completed: Bool { lock.withLock { finished } }
    var replyGateTimedOut: Bool { lock.withLock { timedOut } }
    init(context: ManagedStorageControlClient.Context, volume: HostStorageIntents.Volume) {
        self.context = context; self.volume = volume
    }
    func revoke() { lock.withLock { revoked = true } }
    func send(_ request: ManagedStorageControlProtocol.ControlRequest) throws -> ManagedStorageControlClient.Reply {
        gate.started.continuation.yield(())
        // Ordering is established by the started/revoke/release handshake, not
        // this wall clock. Loaded Core runs can delay MainActor resumption past
        // ten seconds; use the existing native-test deadlock watchdog convention.
        guard gate.release.wait(timeout: .now() + 60) == .success else {
            lock.withLock { timedOut = true }
            throw ManagedStorageControlClient.Failure.remote("TIMEOUT")
        }
        defer { lock.withLock { finished = true } }
        switch request {
        case .query:
            return .snapshot(.init(schema: 3, revision: 2,
                store: .init(id: context.store, deviceID: "device", root: .init(device: 1, inode: 1), exports: .init(device: 1, inode: 2)),
                epoch: context.serviceEpoch, controller: .init(epoch: context.controllerEpoch, key: context.controllerKey),
                volumes: [:], volumeLifecycles: [:], attachments: [:], prepares: [:]))
        case .deleteVolume(let request):
            return .volumeReceipt(.init(schema: 3, operation: request.operation, store: context.store,
                volume: .init(id: volume.id, name: volume.name, root: .init(device: 1, inode: 100)), phase: .deleted, revision: 3))
        default: throw ManagedStorageControlClient.Failure.invalidRequest
        }
    }
}
#endif

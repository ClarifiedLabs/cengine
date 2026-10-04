#if os(macOS)
import CEngineCore
import Foundation

/// Actual host orchestration lane.
/// Guest callbacks are trusted private-init operations, never workload/API hooks.
/// A local name lease schedules work only. Durable journal fences own authority.
@MainActor final class ManagedVolumeLifecycleCoordinator {
    typealias Journal = HostStorageIntents
    typealias Control = ManagedStorageControlProtocol
    enum Failure: Error { case blocked, staleExecution, wrongEvidence, unexpectedReply, repairRequired }
    struct KeyOffer: Sendable { let attachment: String; let key: String }
    struct GuestActions {
        // MUST be authority-free: no filesystem access, mount or data request.
        let offerKeys: (Journal.Intent, Control.Role) async throws -> [KeyOffer]
        // Main's private transport delivers child-issued certificates matching
        // exactly these frozen bindings, then mounts those same guest keys.
        let credentialAndMount: (Journal.Intent, Control.Role) async throws -> Void
        let prepare: (Journal.Intent) async throws -> Journal.GuestCompletion
        let closePrepare: (Journal.Intent) async throws -> Bool
        let start: (Journal.Intent) async throws -> Void
        let beforePublication: (Journal.Intent) async throws -> Void
    }
    private let journal: Journal
    private let control: any ManagedStorageControlling
    private let names: SharedVolumeInitializationCoordinator
    private let recovery: ManagedStorageControllerRecovery?
    private let nativeObservationCompleted: () async -> Void
    private var executions: [String: UUID] = [:]
    private var retirements: [String: (execution: UUID, task: Task<Void, Error>)] = [:]
    private var submitted: [String?: [UUID: Task<ManagedStorageControlClient.Reply, Error>]] = [:]
    private var recovering = Set<String>()
    private var destructiveOperations = Set<String>()
    private var reconciliationInProgress = false
    private var invalidated = false
    private var containedServiceRecovery: [String: ReplacementPermit] = [:]
    private var liveRuntimes: [String: LiveRuntimePermit] = [:]

    func invalidate() async {
        invalidated = true
        executions.removeAll()
        control.revoke()
        try? journal.requireReconciliation()
        let tasks = submitted.values.flatMap { $0.values }
        for task in tasks { _ = await task.result }
        await control.invalidate()
    }

    init(journal: Journal, control: any ManagedStorageControlling,
         names: SharedVolumeInitializationCoordinator, recovery: ManagedStorageControllerRecovery? = nil,
         nativeObservationCompleted: @escaping () async -> Void = {}) throws {
        guard journal.manifest.store == control.context.store,
              journal.manifest.provenanceReference == control.context.provenanceReference else { throw Failure.wrongEvidence }
        self.journal = journal; self.control = control; self.names = names; self.recovery = recovery
        self.nativeObservationCompleted = nativeObservationCompleted
    }
    /// Separate from starting: callers supply existing persisted VolumeInstance IDs,
    /// never name-only legacy records. This does not create any storage authority.
    func planVolumes(_ volumes: [Journal.Volume]) throws {
        guard !invalidated else { throw Failure.blocked }
        try journal.planVolumes(volumes)
    }

    func start(_ plan: Journal.Intent, guest: GuestActions) async throws -> Journal.Token {
        guard !invalidated else { throw Failure.blocked }
        let context = control.context
        guard plan.store == context.store, plan.serviceEpoch == context.serviceEpoch,
              plan.controllerEpoch == context.controllerEpoch, plan.controllerKey == context.controllerKey else { throw Failure.wrongEvidence }
        let state = try journal.snapshot()
        let volumeNames = try Set(plan.mounts.map(\.volume)).map { id in
            guard let volume = state.volumes[id] else { throw Failure.blocked }; return volume.name
        }
        let lease = try await names.acquire(volumeNames)
        defer { lease.release() }
        try await joinOwnedRetirements(overlapping: Set(plan.mounts.map(\.volume)))
        // The complete P/V/A/mount/op-ID set exists durably before key offers,
        // volume creation, reserve, credentials, mounts or PREPARE.
        let token = try journal.plan(plan)
        let execution = UUID(); executions[plan.id] = execution
        defer { if executions[plan.id] == execution { executions.removeValue(forKey: plan.id) } }
        return try await runPlanned(token, execution: execution, guest: guest)
    }

    /// A normal exit can quarantine a shared-volume peer while its exact drain
    /// is still owned here. Wait for that work, never initiate recovery or bypass
    /// the journal's admission fence. The caller holds the volume-name lease.
    private func joinOwnedRetirements(overlapping volumes: Set<String>) async throws {
        while true {
            guard !invalidated else { throw Failure.staleExecution }
            try Task.checkCancellation()
            let state = try journal.snapshot()
            guard let retiring = retirements.sorted(by: { $0.key < $1.key }).first(where: { id, retirement in
                guard executions[id] == retirement.execution, let intent = state.intents[id] else { return false }
                return !intent.isTerminal && !volumes.isDisjoint(with: intent.mounts.map(\.volume))
            })?.value else { return }
            // Joining does not cancel the retirement owner. On success it has
            // published terminal receipts, so a completed entry cannot spin here.
            // Rescan after every await: another overlapping peer may now retire.
            try await retiring.task.value
        }
    }

    private func runPlanned(_ initial: Journal.Token, execution: UUID, guest: GuestActions) async throws -> Journal.Token {
        var token = initial
        let plan = try journal.intent(token)
        do {
            for id in Set(plan.mounts.map(\.volume)).sorted() {
                var volume = try journal.snapshot().volumes[id]!
                if volume.createdRevision == nil {
                    let request = Control.ControlRequest.createVolume(try .init(operation: volume.createOperation,
                        store: plan.store, volume: id, name: volume.name))
                    try journal.recordOperation(id: volume.createOperation, request: request)
                    let response = try await send(request, owner: plan.id)
                    try check(token, execution)
                    guard case .volumeReceipt(let receipt) = response, receipt.volume.id == id,
                          receipt.store == plan.store, receipt.operation == volume.createOperation,
                          receipt.volume.name == volume.name, receipt.phase == .ready else { throw Failure.unexpectedReply }
                    volume.rootDevice = receipt.volume.root.device; volume.rootInode = receipt.volume.root.inode
                    volume.createdRevision = receipt.revision; try journal.recordVolume(volume)
                }
            }
            token = try await freeze(token, execution: execution, role: .prepare, guest: guest)
            var intent = try journal.intent(token)
            let bindings = try intent.slots.filter { $0.role == "prepare" }.map {
                try $0.binding(store: intent.store, prepare: intent.prepare, container: intent.container, launch: intent.launch)
            }.sorted { $0.volume < $1.volume }
            let reserve = Control.ControlRequest.reservePrepare(try .init(operation: intent.reserveOperation,
                prepare: intent.prepare, attachments: bindings))
            if let predecessor = intent.predecessor {
                let oldToken = try journal.token(for: predecessor)
                let old = try journal.intent(oldToken)
                try journal.recordOperation(id: intent.reserveOperation, request: reserve)
                let replacement = try journal.request(for: old.replaceOperation)
                try await perform(replacement, operation: old.replaceOperation, token: token, execution: execution)
                _ = try journal.confirmReplacement(predecessor: oldToken, successor: token)
            } else {
                try await perform(reserve, operation: intent.reserveOperation, token: token, execution: execution)
            }
            try await register(intent, role: .prepare, token: token, execution: execution)
            token = try journal.update(token) { $0.phase = .prepareAdmitted }
            intent = try journal.intent(token)
            try await guest.credentialAndMount(intent, .prepare); try check(token, execution)
            let completion = try await guest.prepare(intent); try check(token, execution)
            guard completion.prepare == intent.prepare, completion.containerInstance == intent.containerInstance,
                  completion.launch == intent.launch, completion.succeeded, completion.cleanCopyUp else { throw Failure.wrongEvidence }
            token = try journal.update(token) { $0.guestCompletion = completion; $0.phase = .prepareSucceeded }
            let unmounted = try await guest.closePrepare(try journal.intent(token)); try check(token, execution)
            guard unmounted else { throw Failure.wrongEvidence }
            token = try journal.update(token) { $0.cleanUnmount = true }
            token = try await drain(token, role: .prepare, execution: execution)
            try check(token, execution)
            token = try journal.update(token) { $0.phase = .prepareDrained }
            intent = try journal.intent(token)
            let receipts = try intent.slots.filter { $0.role == "prepare" }.map { slot in
                guard let receipt = slot.receipt else { throw Failure.blocked }; return try receipt.wire()
            }.sorted { $0.attachment < $1.attachment }
            let complete = Control.ControlRequest.completePrepare(try .init(operation: intent.completeOperation,
                prepare: intent.prepare, receipts: receipts,
                attestation: .init(prepare: intent.prepare, succeeded: true, cleanCopyUp: true)))
            try await perform(complete, operation: intent.completeOperation, token: token, execution: execution)
            token = try journal.update(token) { $0.prepareCompleted = true; $0.phase = .prepareCompleted }
            token = try await freeze(token, execution: execution, role: .runtime, guest: guest)
            intent = try journal.intent(token)
            try await register(intent, role: .runtime, token: token, execution: execution)
            try await guest.credentialAndMount(intent, .runtime); try check(token, execution)
            try await guest.start(intent); try check(token, execution)
            token = try journal.update(token) { $0.phase = .running }
            try await guest.beforePublication(try journal.intent(token)); try check(token, execution)
            return token
        } catch {
            // Do not allow an old execution's cleanup to mutate a replacement.
            // Cancellation is deliberately NOT inherited by individual retire calls.
            if executions[plan.id] == execution {
                do {
                    token = try journal.token(for: plan.id)
                    token = try journal.quarantine(token, reason: "start interrupted")
                } catch { /* prior durable intent remains the fence */ }
                _ = try? await drain(token, role: nil, execution: execution)
            }
            throw error
        }
    }

    /// Settles a previous execution; never reruns guest PREPARE, remounts a key,
    /// publishes a workload, or treats missing authority as drain evidence.
    /// The caller subsequently reconciles the complete registry before new work.
    func recover(_ id: String, containment: ReplacementPermit? = nil,
                 globalContainment: [ReplacementPermit] = []) async throws -> Journal.Token {
        guard !invalidated else { throw Failure.blocked }
        for permit in globalContainment {
            let owner = try journal.intent(journal.token(for: permit.intent.id))
            guard recovery?.crossesServiceEpoch(owner) == true else { throw Failure.wrongEvidence }
            try await withCurrentGeneration { try await permit.consume(for: owner) }
            containedServiceRecovery[owner.id] = permit
        }
        let initial = try journal.intent(journal.token(for: id))
        let related = Set([id, initial.predecessor, initial.successor].compactMap { $0 })
        // Deliberately preempt this target's execution, then join its submitted
        // control calls. Guest callbacks may still be unwinding; Retire fences
        // storage independently and never asserts guest unmount/process death.
        // Those callbacks cannot publish or submit authority after their next
        // execution check. Replacement still requires positive VM containment.
        // Related replacement executions must instead be entirely idle.
        guard !reconciliationInProgress, destructiveOperations.isEmpty, recovering.isDisjoint(with: related),
              related.allSatisfy({ $0 == id || executions[$0] == nil }) else { throw Failure.blocked }
        recovering.formUnion(related)
        defer { recovering.subtract(related) }
        let execution = UUID(); executions[id] = execution
        defer { if executions[id] == execution { executions.removeValue(forKey: id) } }
        await joinSubmitted(id)
        guard executions[id] == execution else { throw Failure.staleExecution }
        var token = try journal.token(for: id)
        var intent = try journal.intent(token)
        try requireContext(intent)
        if recovery?.crossesServiceEpoch(intent) == true, containedServiceRecovery[id] == nil {
            guard let containment else { throw Failure.blocked }
            try await withCurrentGeneration { try await containment.consume(for: intent) }
            containedServiceRecovery[id] = containment
        }
        if intent.isPreAdmissionTerminal { return token }
        try journal.requireReconciliation()
        // Validate S/E/C and the existing union before sending anything, but do
        // not demand READY evidence for a create whose reply was lost. Only an
        // already durable operation may be replayed; later, unattempted volumes
        // in the same whole-set plan remain untouched and fenced.
        var snapshot = try await recoverySnapshot(intent, token: token, execution: execution, pendingCreates: true)
        for id in Set(intent.mounts.map(\.volume)).sorted() {
            let state = try journal.snapshot()
            guard var volume = state.volumes[id] else { throw Failure.wrongEvidence }
            guard volume.createdRevision == nil, state.operations[volume.createOperation] != nil else { continue }
            let request = try journal.replayRequest(operation: volume.createOperation)
            let reply = try await send(request, owner: intent.id)
            try check(token, execution, cancellation: false)
            guard case .volumeReceipt(let receipt) = reply,
                  receipt.schema == 3, receipt.store == intent.store,
                  receipt.operation == volume.createOperation, receipt.volume.id == id,
                  receipt.volume.name == volume.name, receipt.phase == .ready, receipt.revision > 0,
                  receipt.volume.root.inode > 0,
                  receipt.volume.root.device == snapshot.store.root.device else { throw Failure.wrongEvidence }
            if let remote = snapshot.volumes[id], snapshot.volumeLifecycles[id]?.phase == .ready {
                guard remote == receipt.volume,
                      snapshot.volumeLifecycles[id]?.createdRevision == receipt.revision else { throw Failure.wrongEvidence }
            }
            volume.rootDevice = receipt.volume.root.device; volume.rootInode = receipt.volume.root.inode
            volume.createdRevision = receipt.revision
            try journal.recordVolume(volume)
        }
        snapshot = try await recoverySnapshot(intent, token: token, execution: execution)
        if intent.phase == .replaced { return token }
        // A crash between PREPARE key freeze and recording Reserve has no exact
        // authority request to replay. Do not manufacture one, infer a drain from
        // UNKNOWN, or report clean reconciliation: retain explicit repair.
        guard !Self.missingAdmissionRequest(intent, state: try journal.snapshot()) else { throw Failure.repairRequired }
        token = try journal.quarantine(token, reason: "recovering interrupted execution")
        intent = try journal.intent(token)
        if Journal.hasNoAdmission(intent, in: try journal.snapshot()) { return token }
        // A lost Replace reply is resolved only by replaying its exact original
        // request. The successor's nested Reserve is never sent independently.
        if let oldID = intent.predecessor {
            let oldToken = try journal.token(for: oldID)
            let old = try journal.intent(oldToken)
            try requireContext(old)
            if old.phase != .replaced {
                if old.serviceEpoch != control.context.serviceEpoch {
                    try await replacementReplayBarrier(owner: id, predecessor: oldID, execution: execution)
                    token = try journal.token(for: id)
                }
                try await replayOK(old.replaceOperation, token: token, execution: execution)
                _ = try journal.confirmReplacement(predecessor: journal.token(for: oldID), successor: token)
                snapshot = try await recoverySnapshot(intent, token: token, execution: execution)
            }
        }
        if let successorID = intent.successor,
           let successorPlan = try journal.snapshot().intents[successorID],
           !Journal.hasNoAdmission(successorPlan, in: try journal.snapshot()) {
            let successorToken = try journal.token(for: successorID)
            let successor = try journal.intent(successorToken)
            try requireContext(successor)
            if intent.serviceEpoch != control.context.serviceEpoch {
                try await replacementReplayBarrier(owner: id, predecessor: id, execution: execution)
                token = try journal.token(for: id)
            }
            try await replayOK(intent.replaceOperation, token: token, execution: execution)
            _ = try await recoverySnapshot(successor, token: token, execution: execution)
            return try journal.confirmReplacement(predecessor: token, successor: journal.token(for: successorID))
        }
        if intent.predecessor == nil, try journal.snapshot().operations[intent.reserveOperation] != nil {
            try await replayOK(intent.reserveOperation, token: token, execution: execution)
            snapshot = try await recoverySnapshot(intent, token: token, execution: execution)
        }
        for slot in intent.slots where slot.key != nil {
            guard try journal.snapshot().operations[slot.registerOperation] != nil else { continue }
            if let remote = snapshot.attachments[slot.attachment], remote.phase == .retiring || remote.phase == .drained {
                // Go deliberately refuses Register retries after retirement.
                let recordedRetirement = try journal.snapshot().operations[slot.retireOperation] != nil
                guard serviceOpenFence(remote, owner: intent) || (remote.retirement == slot.retireOperation &&
                      recordedRetirement) else { throw Failure.wrongEvidence }
                continue
            }
            try await replayOK(slot.registerOperation, token: token, execution: execution)
        }
        token = try await drain(token, role: nil, execution: execution)
        intent = try journal.intent(token)
        if intent.guestCompletion != nil, intent.cleanUnmount {
            let complete = try journal.request(for: intent.completeOperation)
            try journal.recordOperation(id: intent.completeOperation, request: complete)
            try await replayOK(intent.completeOperation, token: token, execution: execution)
            token = try journal.update(token) { $0.prepareCompleted = true }
            intent = try journal.intent(token)
            let verified = try await recoverySnapshot(intent, token: token, execution: execution)
            guard verified.prepares[intent.prepare]?.phase == .completed else { throw Failure.wrongEvidence }
        }
        if intent.prepareCompleted { token = try journal.update(token) { $0.phase = .retired } }
        return token
    }

    private func replayOK(_ operation: String, token: Journal.Token, execution: UUID) async throws {
        try check(token, execution, cancellation: false)
        guard try journal.snapshot().operations[operation] != nil else {
            // A planned replacement whose key offer never completed cannot be
            // replayed or silently unlinked. Keep the durable repair fence.
            try journal.requireReconciliation()
            throw Failure.repairRequired
        }
        let request = try journal.replayRequest(operation: operation)
        let reply = try await send(request, owner: token.intent)
        try check(token, execution, cancellation: false)
        guard case .ok = reply else { throw Failure.unexpectedReply }
    }

    private func recoverySnapshot(_ intent: Journal.Intent, token: Journal.Token, execution: UUID,
                                  pendingCreates: Bool = false) async throws -> ManagedStorageControlClient.Snapshot {
        guard case .snapshot(let snapshot) = try await send(.query, owner: token.intent) else { throw Failure.unexpectedReply }
        try check(token, execution, cancellation: false)
        try ManagedStorageControlClient.validate(snapshot, context: control.context)
        let state = try journal.snapshot()
        for volumeID in Set(intent.mounts.map(\.volume)) {
            guard let local = state.volumes[volumeID], !local.isDeleted else { throw Failure.wrongEvidence }
            if local.createdRevision == nil {
                guard intent.slots.filter({ $0.volume == volumeID }).allSatisfy({ $0.key == nil }) else { throw Failure.wrongEvidence }
                if state.operations[local.createOperation] == nil {
                    guard snapshot.volumes[volumeID] == nil else { throw Failure.wrongEvidence }
                } else {
                    guard pendingCreates else { throw Failure.wrongEvidence }
                    if let remote = snapshot.volumes[volumeID] {
                        guard let life = snapshot.volumeLifecycles[volumeID], remote.name == local.name,
                              life.create == local.createOperation, life.phase == .creating || life.phase == .ready else { throw Failure.wrongEvidence }
                    }
                }
                continue
            }
            guard let remote = snapshot.volumes[volumeID],
                  local.name == remote.name, local.rootDevice == remote.root.device,
                  local.rootInode == remote.root.inode,
                  snapshot.volumeLifecycles[volumeID]?.phase == .ready,
                  snapshot.volumeLifecycles[volumeID]?.createdRevision == local.createdRevision,
                  snapshot.volumeLifecycles[volumeID]?.create == local.createOperation else { throw Failure.wrongEvidence }
        }
        for slot in intent.slots {
            if let remote = snapshot.attachments[slot.attachment] {
                guard try slot.binding(store: intent.store, prepare: intent.prepare, container: intent.container, launch: intent.launch) == remote.binding else { throw Failure.wrongEvidence }
                if remote.phase == .retiring || remote.phase == .drained {
                    guard serviceOpenFence(remote, owner: intent) || (remote.retirement == slot.retireOperation &&
                          state.operations[slot.retireOperation] != nil) else { throw Failure.wrongEvidence }
                }
                if let receipt = slot.receipt, remote.receipt.map(Journal.DrainReceipt.init) != receipt { throw Failure.wrongEvidence }
            } else if slot.receipt != nil { throw Failure.wrongEvidence }
        }
        if let prepare = snapshot.prepares[intent.prepare] {
            let bindings = try intent.slots.filter { $0.role == "prepare" }.map {
                try $0.binding(store: intent.store, prepare: intent.prepare, container: intent.container, launch: intent.launch)
            }.sorted { $0.volume < $1.volume }
            guard prepare.attachments == bindings else { throw Failure.wrongEvidence }
            if prepare.phase == .completed {
                guard intent.guestCompletion != nil, intent.cleanUnmount,
                      prepare.attestation == (try .init(prepare: intent.prepare, succeeded: true, cleanCopyUp: true)) else { throw Failure.wrongEvidence }
            }
            if prepare.phase == .replaced {
                guard intent.successor.flatMap({ state.intents[$0]?.prepare }) == prepare.successor else { throw Failure.wrongEvidence }
            }
        } else if intent.prepareCompleted || intent.phase == .replaced { throw Failure.wrongEvidence }
        return snapshot
    }

    /// A surviving DATA session keeps its original C1 scope. Only the current
    /// ROOT-confirmed controller may adopt it; this does not issue credentials.
    @MainActor final class LiveRuntimePermit {
        fileprivate let intent: Journal.Intent
        fileprivate let client: VMShimClient
        private let directory: PersistentStateDirectory
        private let container: ContainerRecord
        private let ownership: Set<String>
        private init(intent: Journal.Intent, client: VMShimClient, directory: PersistentStateDirectory,
                     container: ContainerRecord, ownership: Set<String>) {
            self.intent = intent; self.client = client; self.directory = directory
            self.container = container; self.ownership = ownership
        }
        fileprivate static func observe(_ intent: Journal.Intent, container: ContainerRecord,
                                        in directory: PersistentStateDirectory) async throws -> LiveRuntimePermit? {
            guard container.phase == .running, container.id == intent.container,
                  container.instanceID.uuidString.lowercased() == intent.containerInstance,
                  let prepared = try RawVirtualizationBackend.loadPreparedShimState(from: directory, expectedContainerID: container.id),
                  prepared.currentContainer.instanceID == container.instanceID,
                  prepared.specification.shimLaunchUUID == intent.launch,
                  prepared.specification.workloadStorageMode == .managed else { return nil }
            let launches = try VMShimClient.persistedLaunches(in: directory, expectedContainerID: container.id,
                expectedInstanceID: container.instanceID)
            guard launches.quarantined.isEmpty else { throw Failure.wrongEvidence }
            let selected = launches.filter { RawVirtualizationBackend.launchRecordMatchesPrepared($0.record, prepared: prepared) }
            guard selected.count == 1, let launch = selected.first, launch.record.kernelIdentity != nil else { return nil }
            let proof = LiveRuntimePermit(intent: intent, client: launch.client, directory: directory,
                container: container, ownership: Set(launches.map { $0.client.persistentOwnershipKey }))
            do { try await proof.revalidate() } catch { return nil } // Lost runtime follows containment, never restart.
            return proof
        }
        fileprivate func revalidate() async throws {
            guard directory.pathStillNamesThisDirectory(),
                  let prepared = try RawVirtualizationBackend.loadPreparedShimState(from: directory, expectedContainerID: container.id),
                  prepared.currentContainer.instanceID == container.instanceID,
                  prepared.specification == client.specification else { throw Failure.wrongEvidence }
            let launches = try VMShimClient.persistedLaunches(in: directory, expectedContainerID: container.id,
                expectedInstanceID: container.instanceID)
            guard launches.quarantined.isEmpty, Set(launches.map { $0.client.persistentOwnershipKey }) == ownership,
                  launches.contains(where: { $0.client.persistentOwnershipKey == client.persistentOwnershipKey && $0.record.kernelIdentity != nil }) else {
                throw Failure.wrongEvidence
            }
            let reply = try await client.observeRunningWorkloadStorage(expectedScope: RawManagedStorageBackend.scope(intent),
                deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + VMShimManagedTransport.maximumNanoseconds)
            try Self.validateStatus(reply, intent: intent)
            guard directory.pathStillNamesThisDirectory() else { throw Failure.wrongEvidence }
        }
        static func validateStatus(_ reply: WorkloadStorageProtocol.Frame, intent: Journal.Intent) throws {
            let runtime = Set(intent.slots.filter { $0.role == "runtime" }.map(\.attachment))
            guard reply.operation == .reply, reply.kind == .status, reply.data.code == nil,
                  reply.scope == RawManagedStorageBackend.scope(intent), reply.binding.shimLaunchUUID == intent.launch,
                  reply.data.phase == .running, let mounted = reply.data.mountedIDs,
                  Set(mounted) == runtime, mounted.count == runtime.count,
                  reply.data.terminalIDs == [] else { throw Failure.wrongEvidence }
        }
        fileprivate func protects(_ client: VMShimClient) -> Bool {
            self.client.persistentOwnershipKey == client.persistentOwnershipKey
        }
    }

    /// Public values are predicates, not authority. The native/private-session
    /// factory above is still mandatory after this complete registry validation.
    static func validateLiveRuntime(_ intent: Journal.Intent, state: Journal.State,
                                   snapshot: ManagedStorageControlClient.Snapshot,
                                   context: ManagedStorageControlClient.Context) throws {
        try ManagedStorageControlClient.validate(snapshot, context: context)
        guard intent.store == context.store, intent.serviceEpoch == context.serviceEpoch,
              intent.phase == .running, intent.launchBoundary == .attempted,
              intent.prepareCompleted, intent.cleanUnmount, intent.quarantineReason == nil, intent.successor == nil,
              let completion = intent.guestCompletion, completion.succeeded, completion.cleanCopyUp,
              completion.prepare == intent.prepare, completion.containerInstance == intent.containerInstance,
              completion.launch == intent.launch, state.operations[intent.completeOperation] != nil,
              state.operations[intent.reserveOperation] != nil,
              let prepare = snapshot.prepares[intent.prepare], prepare.phase == .completed,
              prepare.attestation == (try .init(prepare: intent.prepare, succeeded: true, cleanCopyUp: true)) else { throw Failure.wrongEvidence }
        for (id, remote) in snapshot.volumes {
            guard let local = state.volumes[id], local.name == remote.name,
                  local.rootDevice == remote.root.device, local.rootInode == remote.root.inode else { throw Failure.wrongEvidence }
        }
        for (id, remote) in snapshot.prepares {
            guard let owner = state.intents.values.first(where: { $0.prepare == id }),
                  remote.attachments == (try owner.slots.filter { $0.role == "prepare" && $0.key != nil }.map {
                      try $0.binding(store: owner.store, prepare: owner.prepare, container: owner.container, launch: owner.launch)
                  }.sorted { $0.volume < $1.volume }) else { throw Failure.wrongEvidence }
        }
        for (id, remote) in snapshot.attachments {
            guard let owner = state.intents.values.first(where: { $0.slots.contains { $0.attachment == id } }),
                  let slot = owner.slots.first(where: { $0.attachment == id }),
                  try slot.binding(store: owner.store, prepare: owner.prepare, container: owner.container, launch: owner.launch) == remote.binding,
                  slot.receipt == nil || remote.receipt.map(Journal.DrainReceipt.init) == slot.receipt else { throw Failure.wrongEvidence }
        }
        for slot in intent.slots {
            guard slot.key != nil, state.operations[slot.registerOperation] != nil,
                  let volume = state.volumes[slot.volume], !volume.isDeleted,
                  let remoteVolume = snapshot.volumes[slot.volume], remoteVolume.name == volume.name,
                  let life = snapshot.volumeLifecycles[slot.volume], life.phase == .ready,
                  life.create == volume.createOperation, life.createdRevision == volume.createdRevision,
                  let remote = snapshot.attachments[slot.attachment] else { throw Failure.wrongEvidence }
            if slot.role == "prepare" {
                guard let receipt = slot.receipt, remote.phase == .drained,
                      remote.receipt.map(Journal.DrainReceipt.init) == receipt,
                      remote.retirement == slot.retireOperation, state.operations[slot.retireOperation] != nil else { throw Failure.wrongEvidence }
            } else {
                guard slot.role == "runtime", slot.receipt == nil, remote.phase == .active,
                      remote.receipt == nil, remote.retirement == nil, state.operations[slot.retireOperation] == nil else { throw Failure.wrongEvidence }
            }
        }
    }

    static func permitsLivePartition(_ intent: Journal.Intent, intents: [Journal.Intent]) -> Bool {
        intent.phase == .running && intent.prepareCompleted && intents.allSatisfy {
            $0.container != intent.container || $0.id == intent.id || $0.isTerminal
        }
    }

    func prepareLiveRuntime(_ id: String, container: ContainerRecord,
                            in directory: PersistentStateDirectory) async throws -> LiveRuntimePermit? {
        guard !invalidated, executions.isEmpty, recovering.isEmpty, !reconciliationInProgress else { throw Failure.blocked }
        let state = try journal.snapshot()
        guard let intent = state.intents[id], Self.permitsLivePartition(intent, intents: Array(state.intents.values)),
              intent.serviceEpoch == control.context.serviceEpoch else { return nil }
        do {
            try requireContext(intent)
            guard case .snapshot(let snapshot) = try await send(.query) else { throw Failure.unexpectedReply }
            try Self.validateLiveRuntime(intent, state: state, snapshot: snapshot, context: control.context)
        } catch { return nil } // Rejected authority never skips the native containment pass.
        let proof = try await withCurrentGeneration { try await LiveRuntimePermit.observe(intent, container: container, in: directory) }
        guard !invalidated, try journal.snapshot().revision == state.revision else { throw Failure.staleExecution }
        return proof
    }

    func validateLiveRuntimes(recordEvidence: Bool = false) async throws {
        guard !liveRuntimes.isEmpty else { return }
        let state = try journal.snapshot()
        guard !invalidated, case .snapshot(let snapshot) = try await send(.query) else { throw Failure.blocked }
        for proof in liveRuntimes.values {
            guard state.intents[proof.intent.id] == proof.intent else { throw Failure.staleExecution }
            try requireContext(proof.intent)
            try Self.validateLiveRuntime(proof.intent, state: state, snapshot: snapshot, context: control.context)
            try await withCurrentGeneration { try await proof.revalidate() }
        }
        guard !invalidated, try journal.snapshot().revision == state.revision else { throw Failure.staleExecution }
        if recordEvidence {
            struct Audit: Encodable {
                let store: String; let serviceEpoch: String; let controllerEpoch: UInt64
                let controllerKey: String; let provenanceReference: String; let registryRevision: UInt64
                let live: [String: String]
            }
            // Original intents retain C1, A keys and exact operation IDs. This
            // links them to the confirmed C2 without exporting private channels.
            let audit = Audit(store: control.context.store, serviceEpoch: control.context.serviceEpoch,
                controllerEpoch: control.context.controllerEpoch, controllerKey: control.context.controllerKey,
                provenanceReference: control.context.provenanceReference, registryRevision: snapshot.revision,
                live: Dictionary(uniqueKeysWithValues: liveRuntimes.values.map {
                    ($0.intent.id, Journal.hash(Data($0.client.persistentOwnershipKey.utf8)))
                }))
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            try journal.recordLiveAdoptionEvidence(encoder.encode(audit))
        }
    }

    func permitsLiveRecovery(container: ContainerRecord, shim: VMShimClient) async throws -> Bool {
        guard let proof = liveRuntimes.values.first(where: { $0.intent.container == container.id && $0.protects(shim) }) else { return false }
        guard proof.intent.containerInstance == container.instanceID.uuidString.lowercased(),
              try journal.intent(journal.token(for: proof.intent.id)) == proof.intent else { throw Failure.wrongEvidence }
        try await withCurrentGeneration { try await proof.revalidate() }
        return true
    }

    /// Actual authenticated Query, not the host journal. Keep all submitted
    /// control work on the existing tracked/joined lifecycle lane.
    func publicTakeoverRegistry() async throws -> ManagedStorageControlClient.Snapshot {
        let before = try journal.snapshot()
        guard !invalidated, executions.isEmpty, recovering.isEmpty, !reconciliationInProgress,
              case .snapshot(let value) = try await send(.query),
              !invalidated, try journal.snapshot().revision == before.revision,
              value.store.id == control.context.store, value.epoch == control.context.serviceEpoch,
              value.controller.epoch == control.context.controllerEpoch,
              value.controller.key == control.context.controllerKey else { throw Failure.staleExecution }
        return value
    }

    /// The NEW controller must first adopt the actual surviving session through
    /// registry + native + private-channel validation. Serialized bindings alone
    /// cannot select another client or create an observation.
    func resumeOriginalConsumer(_ binding: OriginalConsumerObservationProtocol.Binding) async throws -> VMShimClient.RecoveredOriginalPositive {
        guard let proof = liveRuntimes[binding.scope.intent],
              binding.scope == RawManagedStorageBackend.scope(proof.intent),
              binding.generation == proof.client.specification.generation,
              let slot = proof.intent.slots.first(where: { $0.attachment == binding.targetAttachment }),
              slot.role == "runtime", slot.receipt == nil, slot.key == binding.key else { throw Failure.wrongEvidence }
        let before = try journal.snapshot()
        guard before.intents[proof.intent.id] == proof.intent else { throw Failure.staleExecution }
        try await validateLiveRuntimes()
        let evidence = try await withCurrentGeneration { try await proof.client.recoverOriginalPositive(binding) }
        try await withCurrentGeneration { try await proof.revalidate() }
        guard !invalidated, try journal.snapshot().revision == before.revision else { throw Failure.staleExecution }
        return evidence
    }

    /// Sealed containment evidence. Only actual VMShimClient termination can
    /// construct this; tests and callers cannot supply an arbitrary death Bool.
    /// Backend must hold its exclusive container lifecycle ownership throughout
    /// contain -> replace -> fresh launch, and retain the old launch artifacts.
    @MainActor final class ReplacementPermit {
        fileprivate let intent: Journal.Intent
        private let directory: PersistentStateDirectory
        private let ownership: Set<String>
        private var consumed = false
        private let preserved: [LiveRuntimePermit]
        private init(intent: Journal.Intent, directory: PersistentStateDirectory, ownership: Set<String>, preserved: [LiveRuntimePermit]) {
            self.intent = intent; self.directory = directory; self.ownership = ownership; self.preserved = preserved
        }
        static func contain(_ intent: Journal.Intent, in directory: PersistentStateDirectory,
                            neverLaunched: Journal.NeverLaunched? = nil,
                            preserving preserved: [LiveRuntimePermit] = [],
                            expectedOwnership: Set<String>? = nil) async throws -> ReplacementPermit {
            guard let instance = UUID(uuidString: intent.containerInstance), directory.pathStillNamesThisDirectory() else { throw Failure.wrongEvidence }
            let launches = try VMShimClient.persistedLaunches(in: directory, expectedContainerID: intent.container, expectedInstanceID: instance)
            guard launches.quarantined.isEmpty,
                  (neverLaunched?.matches(intent) == true
                    ? !launches.contains(where: { $0.record.specification.shimLaunchUUID == intent.launch })
                    : launches.contains(where: { $0.record.specification.shimLaunchUUID == intent.launch })),
                  launches.allSatisfy({ $0.client.ownsPersistedContainer(id: intent.container, directoryIdentity: directory.identity) }) else { throw Failure.wrongEvidence }
            let ownership = Set(launches.map { $0.client.persistentOwnershipKey })
            guard expectedOwnership == nil || expectedOwnership == ownership else { throw Failure.wrongEvidence }
            for proof in preserved { try await proof.revalidate() }
            guard !preserved.contains(where: { $0.intent.launch == intent.launch }) else { throw Failure.wrongEvidence }
            for launch in launches where !preserved.contains(where: { $0.protects(launch.client) }) { try await launch.client.terminate() }
            guard directory.pathStillNamesThisDirectory() else { throw Failure.wrongEvidence }
            let current = try VMShimClient.persistedLaunches(in: directory, expectedContainerID: intent.container, expectedInstanceID: instance)
            guard current.quarantined.isEmpty, Set(current.map { $0.client.persistentOwnershipKey }) == ownership else { throw Failure.wrongEvidence }
            return ReplacementPermit(intent: intent, directory: directory, ownership: ownership, preserved: preserved)
        }
        /// Extend retained historical evidence only with a fresh, sealed census of
        /// the same physical container. Missing generations or live preservation
        /// cannot be converted into proof that the complete container has exited.
        fileprivate func refreshed(using fresh: ReplacementPermit) async throws -> ReplacementPermit {
            guard intent.store == fresh.intent.store, intent.container == fresh.intent.container,
                  intent.containerInstance == fresh.intent.containerInstance,
                  directory.identity == fresh.directory.identity,
                  ownership.isSubset(of: fresh.ownership),
                  preserved.allSatisfy({ ownership.contains($0.client.persistentOwnershipKey) }) else { throw Failure.wrongEvidence }
            if ownership == fresh.ownership {
                try await revalidate()
                return self
            }
            // A formerly preserved runtime may since have exited. Expansion
            // requires fresh proof that preserves nobody and contains the union.
            guard fresh.preserved.isEmpty else { throw Failure.wrongEvidence }
            try await fresh.revalidate()
            let result = ReplacementPermit(intent: intent, directory: directory,
                ownership: fresh.ownership, preserved: [])
            // Refreshed cache entries remain consumed, never admission permits.
            result.consumed = true
            try await result.revalidate()
            return result
        }
        fileprivate func consume(for expected: Journal.Intent) async throws {
            guard !consumed, intent == expected else { throw Failure.wrongEvidence }
            consumed = true
            try await revalidate()
        }
        /// Re-observe every exact process, not just its serialized ownership set.
        fileprivate func revalidate() async throws {
            guard directory.pathStillNamesThisDirectory(), let instance = UUID(uuidString: intent.containerInstance) else { throw Failure.wrongEvidence }
            let current = try VMShimClient.persistedLaunches(in: directory, expectedContainerID: intent.container, expectedInstanceID: instance)
            guard current.quarantined.isEmpty, Set(current.map { $0.client.persistentOwnershipKey }) == ownership else { throw Failure.wrongEvidence }
            var stillLive = Set<String>()
            for proof in preserved {
                do { try await proof.revalidate(); stillLive.insert(proof.client.persistentOwnershipKey) }
                catch {
                    // Preservation is not a permanent requirement to stay running.
                    // Once it ends, the exact former sibling needs real exit proof.
                    try await proof.client.terminate()
                }
            }
            for launch in current where !stillLive.contains(launch.client.persistentOwnershipKey) { try await launch.client.terminate() }
            guard directory.pathStillNamesThisDirectory() else { throw Failure.wrongEvidence }
            let final = try VMShimClient.persistedLaunches(in: directory, expectedContainerID: intent.container, expectedInstanceID: instance)
            guard final.quarantined.isEmpty, Set(final.map { $0.client.persistentOwnershipKey }) == ownership else { throw Failure.wrongEvidence }
        }
    }

    func replace(_ predecessor: String, with plan: Journal.Intent, permit: ReplacementPermit, guest: GuestActions) async throws -> Journal.Token {
        guard !invalidated, !reconciliationInProgress, !recovering.contains(predecessor), executions[predecessor] == nil else { throw Failure.blocked }
        try requireContext(plan)
        guard plan.controllerEpoch == control.context.controllerEpoch,
              plan.controllerKey == control.context.controllerKey else { throw Failure.wrongEvidence }
        let state = try journal.snapshot()
        let volumeNames = try Set(plan.mounts.map(\.volume)).map { id in
            guard let volume = state.volumes[id] else { throw Failure.blocked }; return volume.name
        }
        let lease = try await names.acquire(volumeNames); defer { lease.release() }
        guard !invalidated, !reconciliationInProgress, executions[predecessor] == nil, submitted[predecessor] == nil else { throw Failure.blocked }
        let oldToken = try journal.token(for: predecessor)
        let old = try journal.intent(oldToken)
        try requireContext(old)
        try await withCurrentGeneration { try await permit.consume(for: old) }
        try await refreshHistoricalContainment(using: permit)
        if recovery?.crossesServiceEpoch(old) == true { containedServiceRecovery[old.id] = permit }
        if recovery?.permits(old, context: control.context) == true {
            // The full remote union must reconcile before any fresh admission;
            // every historical-E workload has already been contained and drained.
            for historical in try journal.snapshot().intents.values where historical.phase != .unlaunched && historical.serviceEpoch != control.context.serviceEpoch {
                guard let proof = containedServiceRecovery[historical.id] else { throw Failure.blocked }
                try await withCurrentGeneration { try await proof.revalidate() }
            }
            try await reconcileStartup(allowContainedHistorical: true)
        }
        let token = try journal.planReplacement(predecessor: oldToken, successor: plan, recovery: recovery)
        let execution = UUID(); executions[plan.id] = execution; executions[predecessor] = execution
        defer {
            if executions[plan.id] == execution { executions.removeValue(forKey: plan.id) }
            if executions[predecessor] == execution { executions.removeValue(forKey: predecessor) }
        }
        return try await runPlanned(token, execution: execution, guest: guest)
    }

    struct NoAdmission {
        private let intent: Journal.Intent
        fileprivate init(_ intent: Journal.Intent) { self.intent = intent }
        var intentID: String { intent.id }
        func matches(_ expected: Journal.Intent) -> Bool { intent == expected }
    }
    struct ExecutionSettlement {
        enum Status { case prepareCompleted, preparePending, neverLaunched, abortedBeforeAdmission }
        let token: Journal.Token
        let status: Status
        fileprivate init(token: Journal.Token, status: Status) { self.token = token; self.status = status }
    }
    /// Execution cleanup is distinct from clearing P. Every possibly used A must
    /// have its exact durable receipt AND every native generation must be exited.
    /// A failed P remains quarantined and can only proceed through ReplacePrepare.
    func settleExecution(_ id: String, in directory: PersistentStateDirectory) async throws -> ExecutionSettlement {
        guard !invalidated, executions[id] == nil, !recovering.contains(id) else { throw Failure.blocked }
        let containment: ReplacementPermit
        if let cached = containedServiceRecovery[id] { containment = cached; try await withCurrentGeneration { try await cached.revalidate() } }
        else { containment = try await prepareContainment(id, in: directory) }
        var token = try await recover(id, containment: containment)
        var intent = try journal.intent(token)
        guard intent.slots.allSatisfy({ $0.key == nil || $0.receipt != nil }) else { throw Failure.blocked }
        if Journal.hasNoAdmission(intent, in: try journal.snapshot()) {
            try await validateNoAdmission(intent)
            try await withCurrentGeneration { try await containment.revalidate() }
            guard !invalidated, try journal.intent(token) == intent else { throw Failure.staleExecution }
            token = try journal.confirmNoAdmission(NoAdmission(intent))
            intent = try journal.intent(token)
            return ExecutionSettlement(token: token, status: intent.phase == .unlaunched ? .neverLaunched : .abortedBeforeAdmission)
        }
        try await withCurrentGeneration { try await containment.revalidate() }
        guard !invalidated, try journal.intent(token) == intent else { throw Failure.staleExecution }
        return ExecutionSettlement(token: token, status: intent.prepareCompleted ? .prepareCompleted : .preparePending)
    }

    /// First pass only: no storage control request or replay. Every planned launch
    /// is durably cancelled before absence may be considered; attempted requires
    /// its actual retained generation and positive native process exit.
    func prepareContainment(_ id: String, in directory: PersistentStateDirectory,
                            preserving live: [LiveRuntimePermit] = [],
                            expectedOwnership: Set<String>? = nil) async throws -> ReplacementPermit {
        guard !invalidated, executions.isEmpty, recovering.isEmpty, !reconciliationInProgress,
              destructiveOperations.isEmpty, submitted.isEmpty else { throw Failure.blocked }
        var token = try journal.token(for: id)
        var intent = try journal.intent(token)
        let never: Journal.NeverLaunched?
        if intent.launchBoundary == .planned || intent.launchBoundary == .cancelled {
            never = try journal.cancelUnlaunched(token)
            token = try journal.token(for: id); intent = try journal.intent(token)
        } else { never = nil }
        let proof = try await withCurrentGeneration {
            try await ReplacementPermit.contain(intent, in: directory, neverLaunched: never,
                preserving: live.filter { $0.intent.container == intent.container }, expectedOwnership: expectedOwnership)
        }
        guard !invalidated, executions.isEmpty, recovering.isEmpty, try journal.intent(token) == intent else { throw Failure.staleExecution }
        return proof
    }
    /// Refresh only this container's cached native evidence. Disjoint starts may
    /// progress while native observations suspend; their journals are not our CAS.
    private func refreshHistoricalContainment(using proof: ReplacementPermit) async throws {
        let intent = proof.intent
        func relevant(_ candidate: Journal.Intent) -> Bool {
            candidate.container == intent.container && candidate.containerInstance == intent.containerInstance
        }
        let state = try journal.snapshot().intents.filter { relevant($0.value) }
        let cached = containedServiceRecovery.filter { relevant($0.value.intent) }
        var refreshed: [String: ReplacementPermit] = [:]
        for (id, historical) in cached {
            refreshed[id] = try await withCurrentGeneration { try await historical.refreshed(using: proof) }
        }
        guard !invalidated, !reconciliationInProgress,
              state.keys.allSatisfy({ executions[$0] == nil && !recovering.contains($0) && submitted[$0] == nil }),
              try journal.snapshot().intents.filter({ relevant($0.value) }) == state,
              cached.count == containedServiceRecovery.values.filter({ relevant($0.intent) }).count,
              cached.allSatisfy({ containedServiceRecovery[$0.key] === $0.value }) else { throw Failure.staleExecution }
        // Publish the whole refresh together, never a partially validated history.
        // This changes native evidence only; ROOT permission and every historical
        // receipt are still checked by replace/reconcile/replay before admission.
        containedServiceRecovery.merge(refreshed) { _, fresh in fresh }
    }
    /// Owned cleanup has already terminated this container's complete native set.
    /// An ordinary restart can have extended that set after service recovery cached
    /// historical permits. Refresh only terminal history at this ownership seam,
    /// never by signalling another container from a later replacement operation.
    func refreshTerminalContainment(containerID: String, instanceID: UUID,
                                    in directory: PersistentStateDirectory) async throws {
        guard !invalidated, !reconciliationInProgress else { throw Failure.blocked }
        let instance = instanceID.uuidString.lowercased()
        let group = try journal.snapshot().intents.filter { $0.value.container == containerID }
        let cached = containedServiceRecovery.filter { $0.value.intent.container == containerID }
        guard group.values.allSatisfy({ $0.containerInstance == instance }),
              cached.values.allSatisfy({ $0.intent.containerInstance == instance }),
              cached.keys.allSatisfy({ group[$0] != nil }) else { throw Failure.wrongEvidence }
        guard !cached.isEmpty, group.values.allSatisfy(\.isTerminal) else { return }
        guard group.keys.allSatisfy({ executions[$0] == nil && !recovering.contains($0) && submitted[$0] == nil }) else {
            throw Failure.blocked
        }
        let ordered = group.values.sorted { $0.id < $1.id }
        guard let anchor = ordered.first(where: { $0.launchBoundary != .cancelled }) ?? ordered.first else {
            throw Failure.wrongEvidence
        }
        let never = anchor.launchBoundary == .cancelled
            ? try journal.cancelUnlaunched(journal.token(for: anchor.id)) : nil
        let fresh = try await withCurrentGeneration {
            try await ReplacementPermit.contain(anchor, in: directory, neverLaunched: never)
        }
        // Scope the CAS to this owned container. Unrelated starts may progress
        // while native observation suspends, but none of this group's history or
        // retained permits may change before the atomic refresh begins.
        guard !invalidated, !reconciliationInProgress,
              try journal.snapshot().intents.filter({ $0.value.container == containerID }) == group,
              cached.count == containedServiceRecovery.values.filter({ $0.intent.container == containerID }).count,
              cached.allSatisfy({ containedServiceRecovery[$0.key] === $0.value }) else { throw Failure.staleExecution }
        try await refreshHistoricalContainment(using: fresh)
    }

    /// Exact-set second pass, still no control traffic. Cache nothing until all
    /// current intents and native process censuses validate against the same CAS.
    func registerContainment(_ permits: [ReplacementPermit], preserving live: [LiveRuntimePermit] = []) async throws {
        guard !invalidated, executions.isEmpty, recovering.isEmpty, submitted.isEmpty,
              !reconciliationInProgress, destructiveOperations.isEmpty else { throw Failure.blocked }
        let state = try journal.snapshot()
        let allIDs = permits.map { $0.intent.id } + live.map { $0.intent.id }
        guard allIDs.count == state.intents.count, Set(allIDs) == Set(state.intents.keys) else { throw Failure.wrongEvidence }
        for proof in live {
            guard state.intents[proof.intent.id] == proof.intent else { throw Failure.wrongEvidence }
            try await withCurrentGeneration { try await proof.revalidate() }
        }
        var accepted: [String: ReplacementPermit] = [:]
        for permit in permits {
            guard let expected = state.intents[permit.intent.id] else { throw Failure.wrongEvidence }
            try await withCurrentGeneration { try await permit.consume(for: expected) }
            accepted[expected.id] = permit
        }
        guard !invalidated, executions.isEmpty, recovering.isEmpty, submitted.isEmpty,
              try journal.snapshot().revision == state.revision else { throw Failure.staleExecution }
        containedServiceRecovery = accepted
        liveRuntimes = Dictionary(uniqueKeysWithValues: live.map { ($0.intent.id, $0) })
        try await validateLiveRuntimes()
    }
    private func validateNoAdmission(_ intent: Journal.Intent) async throws {
        let state = try journal.snapshot()
        guard Journal.hasNoAdmission(intent, in: state),
              case .snapshot(let snapshot) = try await send(.query) else { throw Failure.wrongEvidence }
        try ManagedStorageControlClient.validate(snapshot, context: control.context)
        guard !invalidated, try journal.snapshot().revision == state.revision,
              snapshot.prepares[intent.prepare] == nil,
              intent.slots.allSatisfy({ snapshot.attachments[$0.attachment] == nil }) else { throw Failure.wrongEvidence }
        // Reject unknown or differently-bound authority anywhere in the registry.
        for attachment in snapshot.attachments.values {
            guard let owner = state.intents.values.first(where: { $0.slots.contains { $0.attachment == attachment.binding.attachment } }),
                  let slot = owner.slots.first(where: { $0.attachment == attachment.binding.attachment }),
                  try slot.binding(store: owner.store, prepare: owner.prepare, container: owner.container, launch: owner.launch) == attachment.binding else { throw Failure.wrongEvidence }
        }
        for (id, remote) in snapshot.prepares {
            guard let owner = state.intents.values.first(where: { $0.prepare == id }),
                  remote.attachments == (try owner.slots.filter { $0.role == "prepare" }.map {
                      try $0.binding(store: owner.store, prepare: owner.prepare, container: owner.container, launch: owner.launch)
                  }.sorted { $0.volume < $1.volume }) else { throw Failure.wrongEvidence }
        }
        for (id, remote) in snapshot.volumes {
            guard let local = state.volumes[id], local.name == remote.name,
                  local.rootDevice == remote.root.device, local.rootInode == remote.root.inode,
                  snapshot.volumeLifecycles[id]?.create == local.createOperation else { throw Failure.wrongEvidence }
        }
    }

    /// No VM-death or unmount inference. Only exact storage receipts can retire a
    /// runtime generation. Failed PREPARE remains pending even after all As drain.
    /// Retire one exact current runtime attachment without closing its live guest.
    /// The normal write-ahead request and receipt remain usable by later recovery.
    struct OriginalRetirement: Codable, Equatable, Sendable {
        let operation: String
        let receipt: Control.Receipt
        let queryRevision: UInt64
        let epoch: String
        let controller: ManagedStorageControlClient.Controller
        let attachment: ManagedStorageControlClient.Attachment
    }

    nonisolated static func reconcileOriginalRetirement(operation: String, binding: Control.Binding,
        receipt: Control.Receipt, query: ManagedStorageControlClient.Snapshot,
        context: ManagedStorageControlClient.Context) throws -> OriginalRetirement {
        try ManagedStorageControlClient.validate(query, context: context)
        guard binding.role == .runtime, binding.prepare == nil,
              receipt.schema == 3, receipt.store == binding.store, receipt.volume == binding.volume,
              receipt.attachment == binding.attachment, receipt.prepare == nil, receipt.launch == binding.launch,
              receipt.revision > 0,
              query.revision >= receipt.revision, query.epoch == context.serviceEpoch,
              query.controller.epoch == context.controllerEpoch, query.controller.key == context.controllerKey,
              let remote = query.attachments[binding.attachment], remote.binding == binding,
              remote.phase == .drained, remote.retirement == operation, remote.receipt == receipt
        else { throw Failure.wrongEvidence }
        return .init(operation: operation, receipt: receipt, queryRevision: query.revision,
            epoch: query.epoch, controller: query.controller, attachment: remote)
    }

    func retireOriginalConsumer(_ binding: OriginalConsumerObservationProtocol.Binding,
        revalidate: () throws -> Void) async throws -> OriginalRetirement {
        guard binding.caseName.isSameE, !invalidated, !reconciliationInProgress,
              !recovering.contains(binding.scope.intent), retirements[binding.scope.intent] == nil,
              executions[binding.scope.intent] == nil else { throw Failure.blocked }
        let id = binding.scope.intent
        let execution = UUID(); executions[id] = execution
        defer { if executions[id] == execution { executions.removeValue(forKey: id) } }
        var token = try journal.token(for: id)
        let intent = try journal.intent(token)
        _ = try ManagedStorageOriginalConsumerComparison.originalConsumerTuple(binding, intent: intent)
        try requireContext(intent)
        guard let slot = intent.slots.first(where: { $0.attachment == binding.targetAttachment }) else { throw Failure.blocked }
        let exact = try slot.binding(store: intent.store, prepare: intent.prepare, container: intent.container, launch: intent.launch)
        let request = Control.ControlRequest.retire(try .init(operation: slot.retireOperation,
            store: intent.store, volume: slot.volume, attachment: slot.attachment, launch: intent.launch))
        try revalidate(); try check(token, execution)
        try journal.recordOperation(id: slot.retireOperation, request: request)
        let reply = try await send(request, owner: id)
        try revalidate(); try check(token, execution)
        guard case .receipt(let receipt) = reply else { throw Failure.unexpectedReply }
        let queried = try await send(.query, owner: id)
        try revalidate(); try check(token, execution)
        guard case .snapshot(let query) = queried else { throw Failure.unexpectedReply }
        let proof = try Self.reconcileOriginalRetirement(operation: slot.retireOperation,
            binding: exact, receipt: receipt, query: query, context: control.context)
        token = try journal.update(token) { next in
            let index = next.slots.firstIndex { $0.attachment == slot.attachment }!
            next.slots[index].receipt = .init(receipt)
        }
        try check(token, execution)
        return proof
    }

    /// Authenticated registry evidence only. Neither this proof nor its root
    /// identities attest file contents: independent A/B readers are still required.
    struct OriginalRootAuthority: Codable, Equatable, Sendable {
        let before: ManagedStorageControlClient.Snapshot
        let atProbe: ManagedStorageControlClient.Snapshot
        let after: ManagedStorageControlClient.Snapshot
        let retirement: OriginalRetirement?
    }

    /// Keep the exact two runtime slots under one lifecycle execution lease across
    /// the original-client probe. Never release/reacquire the lease after Retire.
    /// The caller must supply its sealed guest operation with owned abort/join;
    /// cancellation or a thrown probe never publishes an authority proof.
    func withOriginalRootAuthority(_ binding: OriginalConsumerObservationProtocol.Binding,
        target: ConsumerObservationProtocol.Original, revalidate: (OriginalRetirement?) throws -> Void,
        probe: (OriginalRetirement?) async throws -> Void) async throws -> OriginalRootAuthority {
        guard binding.caseName.isRoot, !invalidated, !reconciliationInProgress,
              !recovering.contains(binding.scope.intent), retirements[binding.scope.intent] == nil,
              executions[binding.scope.intent] == nil else { throw Failure.blocked }
        try OriginalConsumerObservationProtocol.validate(binding)
        let id = binding.scope.intent, execution = UUID()
        executions[id] = execution
        defer { if executions[id] == execution { executions.removeValue(forKey: id) } }
        var token = try journal.token(for: id)
        let intent = try journal.intent(token)
        try requireContext(intent)
        let source = try ManagedStorageOriginalConsumerComparison.originalConsumerTuple(binding, intent: intent)
        let slots = intent.slots.filter { $0.role == "runtime" }.sorted { $0.attachment < $1.attachment }
        guard intent.prepareCompleted, slots.count == 2,
              Set(intent.slots.map(\.attachment)).count == intent.slots.count,
              slots[0].attachment == binding.targetAttachment,
              slots.allSatisfy({ $0.receipt == nil }), slots[0].volume != slots[1].volume,
              let key = slots[1].key, key != binding.key,
              target == ConsumerObservationProtocol.Original(epoch: intent.serviceEpoch,
                binding: .init(store: intent.store, volume: slots[1].volume, attachment: slots[1].attachment,
                    container: intent.container, launch: intent.launch, key: key, mode: slots[1].mode))
        else { throw Failure.wrongEvidence }
        let exact = try slots.map { try $0.binding(store: intent.store, prepare: intent.prepare,
            container: intent.container, launch: intent.launch) }
        let budget = OriginalConsumerPreflightDeadline()
        var retirement: OriginalRetirement?
        func current() throws {
            try revalidate(retirement); try check(token, execution)
            _ = try budget.remaining()
        }
        func query() async throws -> ManagedStorageControlClient.Snapshot {
            try current()
            let reply = try await send(.query, owner: id)
            try current()
            guard case .snapshot(let value) = reply else { throw Failure.unexpectedReply }
            try ManagedStorageControlClient.validate(value, context: control.context)
            return value
        }
        let before = try await query()
        for item in exact {
            guard let attachment = before.attachments[item.attachment], attachment.binding == item,
                  attachment.phase == .active, attachment.receipt == nil, attachment.retirement == nil,
                  before.volumeLifecycles[item.volume]?.phase == .ready,
                  before.volumes[item.volume] != nil else { throw Failure.wrongEvidence }
        }
        guard before.volumes[exact[0].volume]?.root != before.volumes[exact[1].volume]?.root
        else { throw Failure.wrongEvidence }
        var atProbe = before
        if binding.caseName == .retiredRootGrantReplay {
            let slot = slots[0]
            let request = Control.ControlRequest.retire(try .init(operation: slot.retireOperation,
                store: intent.store, volume: slot.volume, attachment: slot.attachment, launch: intent.launch))
            try current()
            try journal.recordOperation(id: slot.retireOperation, request: request)
            let reply = try await send(request, owner: id)
            try current()
            guard case .receipt(let receipt) = reply else { throw Failure.unexpectedReply }
            atProbe = try await query()
            let proof = try Self.reconcileOriginalRetirement(operation: slot.retireOperation,
                binding: exact[0], receipt: receipt, query: atProbe, context: control.context)
            var expected = before.attachments
            expected[slot.attachment] = proof.attachment
            guard atProbe.attachments == expected, atProbe.schema == before.schema,
                  atProbe.store == before.store, atProbe.epoch == before.epoch,
                  atProbe.controller == before.controller, atProbe.volumes == before.volumes,
                  atProbe.volumeLifecycles == before.volumeLifecycles, atProbe.prepares == before.prepares,
                  receipt.revision > before.revision else { throw Failure.wrongEvidence }
            retirement = proof
            token = try journal.update(token) { next in
                let index = next.slots.firstIndex { $0.attachment == slot.attachment }!
                next.slots[index].receipt = .init(receipt)
            }
        }
        try current()
        guard try ManagedStorageOriginalConsumerComparison.originalConsumerTuple(binding, intent: journal.intent(token),
            retiredReceipt: retirement?.receipt) == source else { throw Failure.wrongEvidence }
        try await probe(retirement)
        try current()
        let after = try await query()
        // Admission is fenced by the sealed owner. No unrelated registry churn
        // is allowed to excuse a revision change during the isolation probe.
        guard after == atProbe else { throw Failure.wrongEvidence }
        return .init(before: before, atProbe: atProbe, after: after, retirement: retirement)
    }

    /// Control-channel evidence is distinct from DATA/root admission evidence.
    /// Only this retained owner constructs the live result; serialization cannot
    /// manufacture an authenticated denial or authorize another operation.
    struct OriginalRegistrationAuthority: Sendable {
        let binding: OriginalConsumerObservationProtocol.Binding
        let operation: String
        let attempted: Control.Binding
        let originalRegisterOperation: String
        let denial: String
        let authority: OriginalRootAuthority
        fileprivate init(binding: OriginalConsumerObservationProtocol.Binding, operation: String,
            attempted: Control.Binding, originalRegisterOperation: String, denial: String, authority: OriginalRootAuthority) {
            self.binding = binding; self.operation = operation; self.attempted = attempted
            self.originalRegisterOperation = originalRegisterOperation
            self.denial = denial; self.authority = authority
        }
    }

    /// Exercise the real retained control client, keeping the lifecycle lease from
    /// the active baseline through Retire/Query, the denied registration and Query.
    /// Unexpected success/transport failure is not denial and requires containment
    /// by the sealed runtime caller. No speculative registration enters recovery.
    func observeOriginalRegistration(_ binding: OriginalConsumerObservationProtocol.Binding,
        revalidate: (OriginalRetirement?) throws -> Void,
        probe: (OriginalRetirement) async throws -> Void = { _ in }) async throws -> OriginalRegistrationAuthority {
        guard [.attachmentKeyReuse, .delayedRegistration].contains(binding.caseName),
              !invalidated, !reconciliationInProgress, !recovering.contains(binding.scope.intent),
              retirements[binding.scope.intent] == nil, executions[binding.scope.intent] == nil
        else { throw Failure.blocked }
        try OriginalConsumerObservationProtocol.validate(binding)
        let id = binding.scope.intent, execution = UUID()
        executions[id] = execution
        defer { if executions[id] == execution { executions.removeValue(forKey: id) } }
        var token = try journal.token(for: id)
        let intent = try journal.intent(token)
        try requireContext(intent)
        _ = try ManagedStorageOriginalConsumerComparison.originalConsumerTuple(binding, intent: intent)
        guard intent.prepareCompleted,
              let slot = intent.slots.first(where: { $0.attachment == binding.targetAttachment })
        else { throw Failure.wrongEvidence }
        let exact = try slot.binding(store: intent.store, prepare: intent.prepare,
            container: intent.container, launch: intent.launch)
        let registered = try journal.replayRequest(operation: slot.registerOperation)
        let originalRequest = Control.ControlRequest.registerAttachment(try .init(operation: slot.registerOperation, binding: exact))
        guard try registered.durableBytes() == originalRequest.durableBytes() else { throw Failure.wrongEvidence }
        let budget = OriginalConsumerPreflightDeadline()
        var retirement: OriginalRetirement?
        func current() throws {
            try revalidate(retirement); try check(token, execution); _ = try budget.remaining()
            try requireContext(journal.intent(token))
            _ = try ManagedStorageOriginalConsumerComparison.originalConsumerTuple(binding, intent: journal.intent(token),
                retiredReceipt: retirement?.receipt)
        }
        func query() async throws -> ManagedStorageControlClient.Snapshot {
            try current()
            let reply = try await send(.query, owner: id)
            try current()
            guard case .snapshot(let value) = reply else { throw Failure.unexpectedReply }
            try ManagedStorageControlClient.validate(value, context: control.context)
            return value
        }
        let before = try await query()
        guard let active = before.attachments[exact.attachment], active.binding == exact,
              active.phase == .active, active.receipt == nil, active.retirement == nil,
              before.volumeLifecycles[exact.volume]?.phase == .ready else { throw Failure.wrongEvidence }
        // Establish that the very same persisted registration is a valid retry
        // before retirement; malformed requests cannot satisfy the later negative.
        guard case .ok = try await send(registered, owner: id) else { throw Failure.unexpectedReply }
        try current()
        guard try await query() == before else { throw Failure.wrongEvidence }
        let retire = Control.ControlRequest.retire(try .init(operation: slot.retireOperation,
            store: intent.store, volume: slot.volume, attachment: slot.attachment, launch: intent.launch))
        try journal.recordOperation(id: slot.retireOperation, request: retire)
        let reply = try await send(retire, owner: id)
        try current()
        guard case .receipt(let receipt) = reply else { throw Failure.unexpectedReply }
        let atProbe = try await query()
        let proof = try Self.reconcileOriginalRetirement(operation: slot.retireOperation,
            binding: exact, receipt: receipt, query: atProbe, context: control.context)
        var expected = before.attachments; expected[slot.attachment] = proof.attachment
        guard atProbe.attachments == expected, atProbe.schema == before.schema,
              atProbe.store == before.store, atProbe.epoch == before.epoch,
              atProbe.controller == before.controller, atProbe.volumes == before.volumes,
              atProbe.volumeLifecycles == before.volumeLifecycles, atProbe.prepares == before.prepares,
              receipt.revision > before.revision else { throw Failure.wrongEvidence }
        retirement = proof
        token = try journal.update(token) { next in
            let index = next.slots.firstIndex { $0.attachment == slot.attachment }!
            next.slots[index].receipt = .init(receipt)
        }
        var attempted = exact, operation = slot.registerOperation
        let denial: String
        if binding.caseName == .attachmentKeyReuse {
            // New A/op, exact old K and all other authority fields unchanged.
            let attachment = UUID().uuidString.lowercased()
            operation = UUID().uuidString.lowercased()
            guard atProbe.attachments[attachment] == nil,
                  try journal.snapshot().operations[operation] == nil else { throw Failure.wrongEvidence }
            attempted = try .init(store: exact.store, volume: exact.volume, attachment: attachment,
                container: exact.container, launch: exact.launch, key: exact.key, role: .runtime, mode: exact.mode)
            denial = "CONFLICT"
        } else { denial = "BLOCKED" }
        let request = Control.ControlRequest.registerAttachment(try .init(operation: operation, binding: attempted))
        try current()
        do {
            _ = try await send(request, owner: id)
            throw Failure.unexpectedReply
        } catch ManagedStorageControlClient.Failure.remote(let code) {
            try current()
            guard code == denial else { throw Failure.wrongEvidence }
        }
        try current()
        try await probe(proof)
        try current()
        let after = try await query()
        guard after == atProbe else { throw Failure.wrongEvidence }
        return .init(binding: binding, operation: operation, attempted: attempted, originalRegisterOperation: slot.registerOperation, denial: denial,
            authority: .init(before: before, atProbe: atProbe, after: after, retirement: proof))
    }

    func retireLaunch(_ id: String) async throws {
        guard !invalidated, !reconciliationInProgress, !recovering.contains(id) else { throw Failure.blocked }
        // Stop, wait and a disconnect hint may all retire this same intent. They
        // must join its drain, not revoke each other's execution at every await.
        // Recovery/invalidation still revoke the token; never join that old task.
        if let retiring = retirements[id], executions[id] == retiring.execution {
            return try await retiring.task.value
        }
        let execution = UUID(); executions[id] = execution
        let task = Task { try await retireLaunch(id, execution: execution) }
        retirements[id] = (execution, task)
        defer {
            if retirements[id]?.execution == execution { retirements.removeValue(forKey: id) }
            if executions[id] == execution { executions.removeValue(forKey: id) }
        }
        // One caller's cancellation cannot abandon the shared retirement owner.
        try await task.value
    }

    private func retireLaunch(_ id: String, execution: UUID) async throws {
        await joinSubmitted(id)
        guard executions[id] == execution else { throw Failure.staleExecution }
        var token = try journal.token(for: id)
        let retiring = try journal.intent(token)
        try requireServiceContainment(retiring)
        try requireContext(retiring)
        token = try journal.quarantine(token, reason: "launch retirement")
        token = try await drain(token, role: nil, execution: execution)
        let intent = try journal.intent(token)
        guard intent.prepareCompleted else { throw Failure.blocked }
        _ = try journal.update(token) { $0.phase = .retired }
    }
    func canDelete(volume: String) -> Bool { journal.canDelete(volume: volume) }
    func canChangeMode(volume: String) -> Bool { journal.canChangeMode(volume: volume) }

    enum DeletionSettlement: Sendable {
        case local(store: String, volume: String, operation: String, revision: UInt64)
        case remote(ManagedStorageControlClient.VolumeReceipt)
    }
    func deletionSettlement(_ id: String, name: String) throws -> DeletionSettlement? {
        guard !invalidated else { throw Failure.blocked }
        let state = try journal.snapshot()
        guard let volume = state.volumes[id], volume.name == name else { throw Failure.wrongEvidence }
        if let revision = volume.localDeletionRevision {
            return .local(store: state.store, volume: id, operation: volume.deleteOperation, revision: revision)
        }
        if let revision = volume.deletedRevision {
            _ = try journal.replayRequest(operation: volume.deleteOperation)
            guard let device = volume.rootDevice, let inode = volume.rootInode else { throw Failure.wrongEvidence }
            return .remote(.init(schema: 3, operation: volume.deleteOperation, store: state.store,
                volume: .init(id: id, name: name, root: .init(device: device, inode: inode)), phase: .deleted, revision: revision))
        }
        return nil
    }
    func deleteVolume(_ id: String) async throws {
        guard let volume = try journal.snapshot().volumes[id] else { throw Failure.blocked }
        _ = try await settleDeletion(id, name: volume.name)
    }
    func settleDeletion(_ id: String, name: String) async throws -> DeletionSettlement {
        let lease = try await names.acquire([name]); defer { lease.release() }
        guard !invalidated, !reconciliationInProgress, destructiveOperations.isEmpty else { throw Failure.blocked }
        if let settled = try deletionSettlement(id, name: name) { return settled }
        let state = try journal.snapshot()
        guard let volume = state.volumes[id], volume.name == name else { throw Failure.wrongEvidence }
        if volume.createdRevision == nil, state.operations[volume.createOperation] == nil {
            _ = try journal.deleteUncreatedVolume(id)
            guard let settled = try deletionSettlement(id, name: name) else { throw Failure.wrongEvidence }
            return settled
        }
        let retry = state.operations[volume.deleteOperation] != nil
        guard (retry || journal.canDelete(volume: id)), !state.intents.values.contains(where: {
            !$0.isTerminal && $0.mounts.contains { $0.volume == id }
        }) else { throw Failure.blocked }
        destructiveOperations.insert(id); defer { destructiveOperations.remove(id) }
        let request = try journal.request(for: volume.deleteOperation)
        if retry { _ = try journal.replayRequest(operation: volume.deleteOperation) }
        else { try journal.recordOperation(id: volume.deleteOperation, request: request) }
        try journal.requireReconciliation()
        guard case .volumeReceipt(let receipt) = try await send(request), !invalidated,
              receipt.operation == volume.deleteOperation, receipt.store == state.store,
              receipt.volume.id == id, receipt.volume.name == name,
              receipt.volume.root.device == volume.rootDevice, receipt.volume.root.inode == volume.rootInode,
              receipt.phase == .deleted else { throw Failure.unexpectedReply }
        var deleted = volume; deleted.deletedRevision = receipt.revision
        try journal.recordVolume(deleted)
        return .remote(receipt)
    }

    /// Query's complete union is retained on ambiguity, including previously unknown
    /// server P/A identities. Unknown volumes/launches are repair-required, never
    /// adopted as legacy or discarded. This first pass does not resurrect guests.
    func reconcileStartup() async throws {
        guard !invalidated else { throw Failure.blocked }
        let state = try journal.snapshot()
        // A failed historical P stays pending, but need not permanently block
        // Replace after independently authorized recovery and complete containment.
        for intent in state.intents.values where intent.serviceEpoch != control.context.serviceEpoch && intent.phase != .unlaunched {
            try await Self.validateHistoricalForQuery(intent,
                recoveryPermitted: recovery?.permits(intent, context: control.context) == true,
                containment: containedServiceRecovery[intent.id]) { proof in
                    try await self.withCurrentGeneration { try await proof.revalidate() }
                }
        }
        guard !invalidated, try journal.snapshot().revision == state.revision else { throw Failure.staleExecution }
        try await reconcileStartup(allowContainedHistorical: true)
    }

    /// Query ordering only; this does not create a recovery or containment permit.
    /// The caller supplies ROOT authorization and previously sealed containment.
    static func validateHistoricalForQuery<Proof>(_ intent: Journal.Intent, recoveryPermitted: Bool,
                                                  containment: Proof?, revalidate: @MainActor (Proof) async throws -> Void) async throws {
        guard recoveryPermitted, let containment else { throw Failure.repairRequired }
        // Terminal storage history is still checked against the full registry and
        // its exact receipts. Its old whole-container census predates legitimate
        // later launches and must not be reused to contain those new generations.
        // Startup containment and authority-bearing recovery keep their own checks.
        if !intent.isTerminal { try await revalidate(containment) }
    }

    private func reconcileStartup(allowContainedHistorical: Bool, replayOwner: String? = nil, replayPredecessor: String? = nil) async throws {
        let permittedExecutions = replayOwner.map { Set([$0]) } ?? []
        guard !invalidated, !reconciliationInProgress, Set(executions.keys).isSubset(of: permittedExecutions), submitted.isEmpty,
              (replayOwner != nil || recovering.isEmpty), destructiveOperations.isEmpty else { throw Failure.blocked }
        reconciliationInProgress = true
        defer { reconciliationInProgress = false }
        try journal.requireReconciliation()
        let revision = try journal.snapshot().revision
        guard case .snapshot(let snapshot) = try await send(.query) else { throw Failure.unexpectedReply }
        let state = try journal.snapshot()
        guard !invalidated, state.revision == revision, Set(executions.keys).isSubset(of: permittedExecutions), destructiveOperations.isEmpty else { throw Failure.staleExecution }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        try ManagedStorageControlClient.validate(snapshot, context: control.context)
        let evidence = try encoder.encode(snapshot)
        // Do not freeze new public volume evidence into a historical intent's
        // journal under a different controller or service incarnation.
        do {
            for intent in state.intents.values where !intent.isTerminal {
                try requireContext(intent)
            }
        } catch {
            try journal.retainReconciliationFence(evidence)
            throw Failure.repairRequired
        }
        var blocked = false
        for (id, remote) in snapshot.volumes {
            guard var local = state.volumes[id], local.name == remote.name,
                  let life = snapshot.volumeLifecycles[id], life.create == local.createOperation else { blocked = true; continue }
            // Query is not a substitute for settling an ambiguous create. Its
            // exact durable request must be replayed by recover before adopting
            // READY evidence or considering this volume for deletion.
            guard local.createdRevision != nil else { blocked = true; continue }
            guard local.rootDevice == remote.root.device, local.rootInode == remote.root.inode,
                  local.createdRevision == life.createdRevision else { blocked = true; continue }
            if life.phase == .deleted, life.delete == local.deleteOperation, state.operations[local.deleteOperation] != nil {
                // Query is observation, not the exact Delete reply. An unresolved
                // operation must be replayed by settleDeletion before settlement.
                if local.deletedRevision == nil || local.deletedRevision != life.deletedRevision { blocked = true }
            } else if life.phase != .ready || local.isDeleted { blocked = true }
        }
        for (id, local) in state.volumes where snapshot.volumes[id] == nil {
            if local.createdRevision != nil || state.operations[local.createOperation] != nil { blocked = true }
        }
        let intents = Array(state.intents.values)
        let unacceptedSuccessor = try Self.unacceptedSuccessor(predecessor: replayPredecessor, state: state, snapshot: snapshot)
        for intent in intents {
            if Self.missingAdmissionRequest(intent, state: state) { blocked = true }
            if let successorID = intent.successor {
                guard let successor = state.intents[successorID] else { blocked = true; continue }
                if successor.isPreAdmissionTerminal && Journal.hasNoAdmission(successor, in: state) { continue }
                guard state.operations[intent.replaceOperation] != nil,
                      state.operations[successor.reserveOperation] != nil else { blocked = true; continue }
            }
        }
        for (id, remote) in snapshot.attachments {
            guard let owner = intents.first(where: { $0.slots.contains { $0.attachment == id } }),
                  let slot = owner.slots.first(where: { $0.attachment == id }), slot.key != nil,
                  try slot.binding(store: owner.store, prepare: owner.prepare, container: owner.container, launch: owner.launch) == remote.binding else {
                blocked = true; continue
            }
            if remote.phase == .retiring || remote.phase == .drained || remote.retirement != nil {
                if !serviceOpenFence(remote, owner: owner) && (remote.retirement != slot.retireOperation || state.operations[slot.retireOperation] == nil) { blocked = true }
            }
            if let localReceipt = slot.receipt, remote.receipt.map(Journal.DrainReceipt.init) != localReceipt { blocked = true }
            // Reconciliation cannot manufacture a new receipt or guest completion.
            // Exact replay of the already journaled Retire/Complete is required.
            if owner.phase == .retired && remote.phase != .drained { blocked = true }
        }
        for owner in intents {
            for slot in owner.slots where slot.key != nil && snapshot.attachments[slot.attachment] == nil {
                if owner.id != unacceptedSuccessor && (state.operations[slot.registerOperation] != nil || state.operations[owner.reserveOperation] != nil) { blocked = true }
            }
        }
        for (id, remote) in snapshot.prepares {
            guard let owner = intents.first(where: { $0.prepare == id }) else { blocked = true; continue }
            let expected = try owner.slots.filter { $0.role == "prepare" && $0.key != nil }.map {
                try $0.binding(store: owner.store, prepare: owner.prepare, container: owner.container, launch: owner.launch)
            }.sorted { $0.volume < $1.volume }
            if remote.attachments != expected || (owner.prepareCompleted && remote.phase != .completed) { blocked = true }
            if remote.phase == .replaced {
                let exactPendingReplay = replayOwner != nil && owner.successor != nil && state.operations[owner.replaceOperation] != nil
                if (owner.phase != .replaced && !exactPendingReplay) || owner.successor.flatMap({ state.intents[$0]?.prepare }) != remote.successor { blocked = true }
            } else if owner.phase == .replaced { blocked = true }
        }
        // A changed service incarnation needs containment and fresh VM recovery;
        // no old key may be remounted against a new E.
        for intent in intents where !intent.isTerminal && intent.serviceEpoch != control.context.serviceEpoch {
            if !allowContainedHistorical || recovery?.permits(intent, context: control.context) != true ||
                containedServiceRecovery[intent.id] == nil || (intent.id != unacceptedSuccessor && !intent.slots.allSatisfy({ $0.key == nil || $0.receipt != nil })) {
                blocked = true
            }
        }
        if blocked { try journal.retainReconciliationFence(evidence); throw Failure.repairRequired }
        try journal.reconciled()
    }

    /// A missing *exact planned successor* is not a receipt. It only permits
    /// replaying the already durable whole-set Replace before draining its As.
    static func unacceptedSuccessor(predecessor: String?, state: Journal.State,
                                    snapshot: ManagedStorageControlClient.Snapshot) throws -> String? {
        guard let predecessor else { return nil }
        guard let old = state.intents[predecessor], let successor = old.successor,
              let next = state.intents[successor], next.predecessor == old.id,
              state.operations[old.replaceOperation] != nil, state.operations[next.reserveOperation] != nil else { throw Failure.wrongEvidence }
        guard snapshot.prepares[next.prepare] == nil else { return nil }
        guard old.phase != .replaced, snapshot.prepares[old.prepare]?.phase != .replaced,
              snapshot.prepares[old.prepare] != nil,
              next.slots.allSatisfy({ snapshot.attachments[$0.attachment] == nil && $0.receipt == nil }),
              !next.prepareCompleted, next.guestCompletion == nil else { throw Failure.wrongEvidence }
        return next.id
    }

    /// Every replay obtains a fresh complete census and validates the entire
    /// authority union. Public historical links never stand in for these permits.
    private func replacementReplayBarrier(owner: String, predecessor: String, execution: UUID) async throws {
        guard executions.keys.allSatisfy({ $0 == owner }), submitted.isEmpty,
              destructiveOperations.isEmpty, !reconciliationInProgress else { throw Failure.blocked }
        let historical = try journal.snapshot().intents.values.filter {
            $0.phase != .unlaunched && $0.serviceEpoch != control.context.serviceEpoch
        }.sorted { $0.id < $1.id }
        // Validate ALL proof availability before even the first drain mutation.
        for intent in historical {
            guard recovery?.crossesServiceEpoch(intent) == true,
                  let proof = containedServiceRecovery[intent.id] else { throw Failure.blocked }
            try await withCurrentGeneration { try await proof.revalidate() }
        }
        // Terminal storage history may legitimately reference deleted volumes.
        // Keep its VM census requirement, but let the full tombstone-aware union
        // check validate storage history instead of requiring an active READY V.
        for intent in historical where !intent.isTerminal {
            var token = try journal.token(for: intent.id)
            let prior = executions[intent.id]; executions[intent.id] = execution
            do {
                let snapshot = try await recoverySnapshot(journal.intent(token), token: token, execution: execution)
                let unaccepted = try Self.unacceptedSuccessor(predecessor: predecessor, state: journal.snapshot(), snapshot: snapshot)
                if intent.id != unaccepted {
                    token = try await drain(token, role: nil, execution: execution)
                    guard try journal.intent(token).slots.allSatisfy({ $0.key == nil || $0.receipt != nil }) else { throw Failure.blocked }
                }
            } catch {
                if !invalidated { executions[intent.id] = prior }
                throw error
            }
            if !invalidated { executions[intent.id] = prior }
        }
        try await reconcileStartup(allowContainedHistorical: true, replayOwner: owner, replayPredecessor: predecessor)
        for intent in historical {
            guard let proof = containedServiceRecovery[intent.id] else { throw Failure.blocked }
            try await withCurrentGeneration { try await proof.revalidate() }
        }
        guard executions[owner] == execution else { throw Failure.staleExecution }
    }

    private func freeze(_ token: Journal.Token, execution: UUID, role: Control.Role, guest: GuestActions) async throws -> Journal.Token {
        var token = token
        if role == .prepare { token = try journal.attemptLaunch(token) }
        let intent = try journal.intent(token)
        let offers = try await guest.offerKeys(intent, role); try check(token, execution)
        let slots = intent.slots.filter { $0.role == role.rawValue }
        guard offers.count == slots.count, Set(offers.map(\.attachment)) == Set(slots.map(\.attachment)),
              Set(offers.map(\.key)).count == offers.count else { throw Failure.wrongEvidence }
        return try journal.freezeKeys(token, role: role,
            keys: Dictionary(uniqueKeysWithValues: offers.map { ($0.attachment, $0.key) }))
    }
    private func register(_ intent: Journal.Intent, role: Control.Role, token: Journal.Token, execution: UUID) async throws {
        for slot in intent.slots where slot.role == role.rawValue {
            let binding = try slot.binding(store: intent.store, prepare: intent.prepare, container: intent.container, launch: intent.launch)
            try await perform(.registerAttachment(try .init(operation: slot.registerOperation, binding: binding)),
                operation: slot.registerOperation, token: token, execution: execution)
        }
    }
    private func perform(_ request: Control.ControlRequest, operation: String, token: Journal.Token, execution: UUID) async throws {
        try check(token, execution)
        try journal.recordOperation(id: operation, request: request)
        let reply = try await send(request, owner: token.intent); try check(token, execution)
        guard case .ok = reply else { throw Failure.unexpectedReply }
    }
    private func drain(_ original: Journal.Token, role: Control.Role?, execution: UUID) async throws -> Journal.Token {
        var token = original
        let intent = try journal.intent(token)
        var firstError: (any Error)?
        for slot in intent.slots where slot.key != nil && slot.receipt == nil && (role == nil || slot.role == role?.rawValue) {
            do {
                try check(token, execution, cancellation: false)
                let request = Control.ControlRequest.retire(try .init(operation: slot.retireOperation,
                    store: intent.store, volume: slot.volume, attachment: slot.attachment, launch: intent.launch))
                try journal.recordOperation(id: slot.retireOperation, request: request)
                let reply = try await send(request, owner: token.intent)
                try check(token, execution, cancellation: false)
                guard case .receipt(let receipt) = reply, receipt.schema == 3, receipt.store == intent.store,
                      receipt.volume == slot.volume, receipt.attachment == slot.attachment, receipt.launch == intent.launch,
                      receipt.prepare == (slot.role == "prepare" ? intent.prepare : nil), receipt.revision > 0 else { throw Failure.wrongEvidence }
                token = try journal.update(token) { next in
                    let index = next.slots.firstIndex { $0.attachment == slot.attachment }!
                    next.slots[index].receipt = .init(receipt)
                }
            } catch {
                if firstError == nil { firstError = error }
            }
        }
        if let firstError {
            // Persist with the latest CAS after any preceding successful receipts.
            // An older execution must never quarantine its successor.
            if executions[token.intent] == execution {
                _ = try? journal.quarantine(token, reason: "attachment retirement incomplete")
            }
            throw firstError
        }
        return token
    }
    /// A native observation may finish containment after revocation, but its
    /// result must never become authority in this coordinator's old generation.
    private func withCurrentGeneration<Value>(_ operation: () async throws -> Value) async throws -> Value {
        guard !invalidated else { throw Failure.staleExecution }
        let value = try await operation()
        // Scheduling-only seam; cannot manufacture or replace native evidence.
        await nativeObservationCompleted()
        guard !invalidated else { throw Failure.staleExecution }
        return value
    }

    private func check(_ token: Journal.Token, _ execution: UUID, cancellation: Bool = true) throws {
        guard !invalidated, executions[token.intent] == execution else { throw Failure.staleExecution }
        _ = try journal.intent(token)
        if cancellation { try Task.checkCancellation() }
    }
    private func send(_ request: Control.ControlRequest, owner: String? = nil) async throws -> ManagedStorageControlClient.Reply {
        guard !invalidated else { throw Failure.blocked }
        let control = self.control
        // Retain submitted work before suspension. Invalidating an execution does
        // not cancel a request already queued behind the child's serial channel.
        let call = UUID()
        let task = Self.controlTask(control, request: request)
        submitted[owner, default: [:]][call] = task
        defer {
            submitted[owner]?.removeValue(forKey: call)
            if submitted[owner]?.isEmpty == true { submitted.removeValue(forKey: owner) }
        }
        // Check before any caller can record a reply or clear reconciliation,
        // including ownerless Query/Delete and failed late replies.
        let result = await task.result
        guard !invalidated else { throw Failure.staleExecution }
        return try result.get()
    }
    /// Retain the same uncancelled task lifetime without occupying a cooperative
    /// executor worker while child IPC/owner validation is synchronously blocked.
    nonisolated static func controlTask(_ control: any ManagedStorageControlling,
        request: Control.ControlRequest) -> Task<ManagedStorageControlClient.Reply, Error> {
        Task.detached {
            try await withCheckedThrowingContinuation { continuation in
                Thread.detachNewThread {
                    continuation.resume(with: Result { try control.send(request) })
                }
            }
        }
    }

    private func joinSubmitted(_ id: String) async {
        // The caller first revokes the old execution token. Old continuations may
        // finish but cannot submit another operation after their next check.
        let calls = submitted[id] ?? [:]
        for call in calls.values { _ = await call.result }
    }
    private static func missingAdmissionRequest(_ intent: Journal.Intent, state: Journal.State) -> Bool {
        intent.slots.contains { slot in
            slot.key != nil && state.operations[slot.registerOperation] == nil &&
                (slot.role == "runtime" || state.operations[intent.reserveOperation] == nil)
        }
    }
    private func requireServiceContainment(_ intent: Journal.Intent) throws {
        guard intent.serviceEpoch == control.context.serviceEpoch || containedServiceRecovery[intent.id] != nil else {
            throw Failure.blocked
        }
    }
    private func serviceOpenFence(_ remote: ManagedStorageControlClient.Attachment, owner: Journal.Intent) -> Bool {
        recovery?.crossesServiceEpoch(owner) == true && remote.phase == .retiring && remote.retirement == nil && remote.receipt == nil
    }
    private func requireContext(_ intent: Journal.Intent) throws {
        guard !invalidated else { throw Failure.blocked }
        let c = control.context
        guard intent.store == c.store,
              (intent.serviceEpoch == c.serviceEpoch && intent.controllerEpoch == c.controllerEpoch && intent.controllerKey == c.controllerKey) ||
                recovery?.permits(intent, context: c) == true else { throw Failure.wrongEvidence }
    }
}
#endif

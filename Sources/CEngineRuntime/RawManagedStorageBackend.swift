#if os(macOS)
import CEngineCore
import Darwin
import Foundation

extension RawVirtualizationBackend {
    /// Trusted daemon startup configuration only. No caller-selected CA, service
    /// address, private key or alternate guest transport is accepted here.
    public struct SharedStorageConfiguration: Sendable {
        public let installedHelperTeam: String
        public let policy: StorageLifecycleNativePolicy

        public init(installedHelperTeam: String, policy: StorageLifecycleNativePolicy) {
            self.installedHelperTeam = installedHelperTeam
            self.policy = policy
        }
    }
}

/// The raw backend's actual managed storage lifetime. All guest callbacks use the
/// authenticated shim's sealed 4105/4109 connection; names never confer authority.
@MainActor final class RawManagedStorageBackend {
    typealias Journal = HostStorageIntents
    typealias Wire = WorkloadStorageProtocol
    typealias Lifecycle = ManagedVolumeLifecycleCoordinator
    struct Replacement {
        let predecessor: String
        let permit: Lifecycle.ReplacementPermit
    }

    private let root: PersistentStateDirectory
    private let owner: ManagedStorageLifecycleOwner
    private let names: SharedVolumeInitializationCoordinator
    private var lifecycle: Lifecycle
    private var records: [String: VolumeRecord] = [:]
    private var reconciled = false
    private var maintenance = false
    private var workerUnavailable = false
    private var generation = UUID()
    private var maintenanceTask: Task<BackendServiceReplacementResult, Error>?
    private var replacements: [String: (StorageServiceTypes.ReplacementRequest, Task<BackendServiceReplacementResult, Error>)] = [:]
    private var notifications: Task<Void, Never>?
    private let notificationWork = RawServiceWorkTracker()
    private struct InstalledOriginalRuntime {
        let shim: VMShimClient
        let boot: VerifiedWorkloadStorageBoot
        let credentials: [ManagedPrepareCompatibilityProtocol.Credential]
    }
    private var installedOriginalRuntimes: [String: InstalledOriginalRuntime] = [:]
    private struct PendingFreshGetattr {
        let original: OriginalConsumerObservationProtocol.Binding
        let volume: String
        let claim: ManagedPrepareCompatibilityQueue.OriginalClaim
        var rootResult: OriginalConsumerRuntimeCarrier.RootResult? = nil
        var attempted = false
    }
    private var pendingFreshGetattr: [String: PendingFreshGetattr] = [:]
    private var originalPreflightGeneration: UUID?
    private var originalReplacementEvidence: [String: OriginalConsumerReplacementEvidence] = [:]
    private var originalRootEvidence: [String: OriginalRootEvidence] = [:]
    // Retain independently of the failed observation/cleanup task. Late adoption
    // must not resume reconciliation or turn an expired observation into success.
    private var originalLifecycleAdoptions: [String: OriginalConsumerAdoptionWait<ManagedStorageLifecycleOwner.ServiceReplacementMaintenance>] = [:]
    // Set before any observer preamble can fail. Omitting observation on replay
    // must never obtain an ordinary retry lease for a failed observation.
    private var originalLifecycleOperations = Set<String>()

    /// Synchronous admission closure; the retained whole-loop lease includes
    /// affected/serviceLost callbacks. Native exchanges drain without cancellation.
    func freezeOriginalConsumerWork() throws -> UUID {
        try requireReconciled()
        guard originalPreflightGeneration == nil else { throw Self.failure() }
        admission.close()
        OriginalConsumerNotificationFreeze.close(notificationWork, task: notifications,
            policy: .drainLifecycle)
        originalPreflightGeneration = generation
        return generation
    }
    func fenceOriginalConsumerFailure() {
        admission.close()
        OriginalConsumerNotificationFreeze.close(notificationWork, task: notifications,
            policy: .drainLifecycle)
    }
    func joinOriginalConsumerWork(_ epoch: UUID, deadline: OriginalConsumerPreflightDeadline) async throws {
        guard originalPreflightGeneration == epoch, generation == epoch else { throw Self.failure() }
        try await notificationWork.join(timeout: deadline.remaining())
        // The work lease ends only after affected/serviceLost callbacks return.
        await notifications?.value
        guard generation == epoch else { throw Self.failure() }
        try await admission.join(timeout: deadline.remaining())
        guard generation == epoch else { throw Self.failure() }
    }
    func originalRuntimeBinding(_ request: OriginalConsumerRuntimeCarrier.Request,
        replacement: StorageServiceTypes.ReplacementRequest, shim: VMShimClient) throws -> OriginalConsumerObservationProtocol.Binding {
        try requireReconciled(); try request.validate()
        guard let installed = installedOriginalRuntimes[request.container], installed.shim === shim,
              let scope = installed.boot.scope, scope.containerInstance == request.containerInstance,
              scope.launch == shim.specification.shimLaunchUUID,
              scope.serviceEpoch == replacement.predecessor.serviceEpoch,
              request.operationUUID == replacement.operationUUID,
              let intent = try owner.journalSnapshot().intents.first(where: { $0.id == scope.intent }) else { throw Self.failure() }
        let credential = try Self.selectOriginalRuntimeCredential(caseName: request.caseName, scope: scope,
            credentials: installed.credentials, intent: intent)
        let service = try owner.workloadSession().service.ready
        guard StorageServiceTypes.Scope(serviceEpoch: service.serviceEpoch, workerUUID: service.workerUUID) == replacement.predecessor else { throw Self.failure() }
        try Self.validateOriginalService(service, scope: scope, peer: installed.boot.configuredPeer)
        func binding(_ digest: String) -> OriginalConsumerObservationProtocol.Binding {
            .init(requestID: request.requestID, armDigest: digest, operationUUID: request.operationUUID,
                caseName: request.caseName, generation: shim.specification.generation,
                boot: installed.boot.binding, scope: scope, targetAttachment: credential.attachment,
                key: credential.key, certificateSHA256: credential.certificateSHA256)
        }
        let seed = OriginalConsumerRuntimeCarrier.Candidate(request: request,
            binding: binding(String(repeating: "0", count: 64)), ownerRequest: replacement)
        return binding(Wire.specificationDigest(try ManagedPrepareCompatibilityProtocol.canonicalData(seed)))
    }
    private static func validateOriginalService(_ ready: StorageLifecycleServiceBootProtocol.Ready,
        scope: WorkloadStorageProtocol.Scope, peer: WorkloadStorageProtocol.Peer?) throws {
        guard scope.store == ready.identity.store, scope.serviceEpoch == ready.serviceEpoch,
              scope.controllerEpoch == ready.controllerEpoch,
              scope.controllerKey == ready.controllerKey,
              let peer, peer.tlsRootDER == ready.tlsRootDER, peer.serverDER == ready.serverDER,
              peer.serverKey == ready.serverSPKI else { throw ManagedStorageFailure.invalid }
    }

    /// Selection only: production supplies credentials retained after actual mounted
    /// publication. This seam cannot issue credentials or construct a verified boot.
    static func selectOriginalRuntimeCredential(caseName: OriginalConsumerObservationProtocol.Case,
        scope: Wire.Scope, credentials: [ManagedPrepareCompatibilityProtocol.Credential],
        intent: Journal.Intent) throws -> ManagedPrepareCompatibilityProtocol.Credential {
        let count = caseName == .wrongVolume || caseName.isRoot ? 2 : 1
        let runtime = intent.slots.filter { $0.role == "runtime" }
        guard intent.phase == .running, intent.prepareCompleted, Self.scope(intent) == scope,
              credentials.count == count, runtime.count == count,
              Set(intent.slots.map(\.attachment)).count == intent.slots.count,
              Set(credentials.map(\.attachment)).count == count,
              Set(credentials.map(\.attachment)) == Set(runtime.map(\.attachment)),
              Set(credentials.map(\.key)).count == count,
              Set(credentials.map(\.certificateSHA256)).count == count,
              Set(runtime.map(\.volume)).count == count,
              credentials.allSatisfy({ credential in
                  DiskInitializationProtocol.validUUID(credential.attachment)
                      && OriginalConsumerObservationProtocol.hash(credential.key)
                      && OriginalConsumerObservationProtocol.hash(credential.certificateSHA256)
                      && runtime.contains(where: { $0.attachment == credential.attachment
                          && $0.key == credential.key && $0.receipt == nil })
              }), let selected = credentials.sorted(by: { $0.attachment < $1.attachment }).first,
              let slot = runtime.first(where: { $0.attachment == selected.attachment }),
              caseName != .wrongMode || slot.mode == "read-only" else { throw Self.failure() }
        return selected
    }

    /// Compare both guest positives with credentials retained only after actual
    /// mounted publication. A serialized root observation cannot supply its leaf.
    static func validateOriginalRootCredentials(_ binding: OriginalConsumerObservationProtocol.Binding,
        positive: OriginalConsumerObservationProtocol.Evidence,
        credentials: [ManagedPrepareCompatibilityProtocol.Credential], intent: Journal.Intent,
        retirement: ManagedVolumeLifecycleCoordinator.OriginalRetirement?) throws {
        guard binding.caseName.isRoot, positive.arm == .init(binding), let roots = positive.roots,
              let sourceIndex = intent.slots.firstIndex(where: { $0.attachment == binding.targetAttachment }),
              try ManagedStorageOriginalConsumerComparison.originalConsumerTuple(binding, intent: intent,
                retiredReceipt: retirement?.receipt) == roots.source.read.authority else { throw failure() }
        if let retirement {
            guard binding.caseName == .retiredRootGrantReplay,
                  retirement.operation == intent.slots[sourceIndex].retireOperation else { throw failure() }
        }
        // Only a comparison copy: the exact durable receipt was checked above;
        // the journal is never cleared or reconstructed to revive authority.
        var active = intent; active.slots[sourceIndex].receipt = nil
        let selected = try selectOriginalRuntimeCredential(caseName: binding.caseName, scope: binding.scope,
            credentials: credentials, intent: active)
        guard selected.attachment == binding.targetAttachment, selected.key == binding.key,
              selected.certificateSHA256 == binding.certificateSHA256 else { throw failure() }
        let pair = credentials.sorted { $0.attachment < $1.attachment }
        for (index, positive) in [roots.source, roots.target].enumerated() {
            let credential = pair[index]
            guard let slot = active.slots.first(where: { $0.attachment == credential.attachment }),
                  positive.leafSHA256 == credential.certificateSHA256,
                  positive.read.authority == ConsumerObservationProtocol.Original(epoch: intent.serviceEpoch,
                    binding: .init(store: intent.store, volume: slot.volume, attachment: slot.attachment,
                        container: intent.container, launch: intent.launch, key: credential.key, mode: slot.mode))
            else { throw failure() }
        }
    }

    func rootEvidence(operationUUID: String) throws -> OriginalConsumerRuntimeCarrier.RootResult {
        guard let evidence = originalRootEvidence[operationUUID] else { throw Self.failure() }
        return evidence.result
    }

    func armOriginalRuntime(_ binding: OriginalConsumerObservationProtocol.Binding,
        request: OriginalConsumerRuntimeCarrier.Request, replacement: StorageServiceTypes.ReplacementRequest,
        shim: VMShimClient) async throws -> VMShimClient.OriginalConsumerObservation {
        guard try originalRuntimeBinding(request, replacement: replacement, shim: shim) == binding,
              let installed = installedOriginalRuntimes[request.container],
              originalPreflightGeneration == generation else { throw Self.failure() }
        let observation = try await shim.originalConsumerArm(binding, boot: installed.boot)
        do {
            guard try originalRuntimeBinding(request, replacement: replacement, shim: shim) == binding,
                  originalPreflightGeneration == generation else { throw Self.failure() }
            return observation
        } catch {
            let failure = error
            return try await OriginalConsumerCleanup.run(operation: { throw failure },
                release: { _ = try await observation.release() }, contain: {})
        }
    }
    /// Identity rejection only: the public baseline digest never becomes authority.
    /// The harness obtains bytes from the independently started owned reader.
    func validateOriginalBaseline(_ baseline: OriginalConsumerRuntimeCarrier.Baseline) throws {
        try requireReconciled(); try baseline.validate()
        guard originalPreflightGeneration == generation else { throw Self.failure() }
        let state = try owner.journalSnapshot()
        let reader = try Self.originalBaselineReader(baseline, snapshot: state)
        guard let installed = installedOriginalRuntimes[reader.container],
              installed.boot.scope == Self.scope(reader),
              installed.shim.specification.shimLaunchUUID == reader.launch,
              installed.credentials.contains(where: { $0.attachment == baseline.readerAttachment && $0.key == baseline.readerKey }) else { throw Self.failure() }
        if let pair = baseline.rootPair {
            guard installed.credentials.count == 2, pair.allSatisfy({ item in
                installed.credentials.contains(where: { $0.attachment == item.readerAttachment && $0.key == item.readerKey })
            }) else { throw Self.failure() }
        }
        try installed.shim.validateOriginalBaselineReader(installed.boot)
    }
    static func originalBaselineReader(_ baseline: OriginalConsumerRuntimeCarrier.Baseline,
        snapshot: ManagedStorageJournalSnapshot) throws -> Journal.Intent {
        try baseline.validate()
        let binding = baseline.binding
        guard !snapshot.reconciliationRequired,
              let original = snapshot.intents.first(where: { $0.id == binding.scope.intent }),
              original.phase == .running, Self.scope(original) == binding.scope,
              let source = original.slots.first(where: { $0.attachment == binding.targetAttachment && $0.key == binding.key && $0.role == "runtime" && $0.receipt == nil }),
              source.mode == "read-write" || (binding.caseName.isRoot && source.mode == "read-only"),
              let reader = snapshot.intents.first(where: { $0.id == baseline.readerIntent }),
              reader.phase == .running, reader.prepareCompleted,
              reader.container != original.container, reader.launch != original.launch,
              reader.store == original.store, reader.serviceEpoch == original.serviceEpoch,
              reader.controllerEpoch == original.controllerEpoch, reader.controllerKey == original.controllerKey,
              reader.slots.contains(where: { $0.attachment == baseline.readerAttachment && $0.key == baseline.readerKey
                  && $0.volume == source.volume && $0.role == "runtime" && $0.mode == "read-write" && $0.receipt == nil })
        else { throw Self.failure() }
        if let pair = baseline.rootPair {
            let sourceSlots = original.slots.filter { $0.role == "runtime" }.sorted { $0.attachment < $1.attachment }
            let readerSlots = reader.slots.filter { $0.role == "runtime" }
            guard original.prepareCompleted, sourceSlots.count == 2, readerSlots.count == 2,
                  sourceSlots[0].attachment == binding.targetAttachment,
                  Set(original.slots.map(\.attachment)).count == original.slots.count,
                  Set(reader.slots.map(\.attachment)).count == reader.slots.count else { throw Self.failure() }
            for (item, source) in zip(pair, sourceSlots) {
                guard source.receipt == nil, item.volume == source.volume,
                      item.readerAttachment != source.attachment, item.readerKey != source.key,
                      readerSlots.contains(where: { $0.volume == item.volume && $0.attachment == item.readerAttachment
                        && $0.key == item.readerKey && $0.mode == "read-write" && $0.receipt == nil })
                else { throw Self.failure() }
            }
        }
        return reader
    }
    func originalEvidence(operationUUID: String) throws -> OriginalConsumerReplacementEvidence {
        guard let evidence = originalReplacementEvidence[operationUUID] else { throw Self.failure() }
        return evidence
    }

    private var closingPrepareAttachments = Set<String>()
    // Retain observations independently of the caller's serial PREPARE task.
    // A failed observer is not cleanup or drain evidence.
    private var prepareObservations: [String: Task<Void, Error>] = [:]
    private var storagePrepareObservations: [String: Task<Void, Error>] = [:]
    private var retirementHints = RetirementHints()
    private var workerExitLossFences: [String: PrepareWorkerExitLossFence] = [:]
    private var completedWorkerLossGeneration: UUID?

    /// Closed, bounded diagnostics only; never an input to loss or recovery gates.
    enum WorkerExitDiagnosticStage: String, CaseIterable {
        case claimed, commandReturned = "command-returned", commandFailed = "command-failed"
        case observerLost = "observer-lost", observerFailed = "observer-failed", fenceReturned = "fence-returned"
    }
    static func workerExitDiagnostic(_ stage: WorkerExitDiagnosticStage, error: (any Error)? = nil,
                                    firstClose: ManagedStorageCloseDiagnostic? = nil) -> String {
        let category = ManagedStorageCloseDiagnostic(site: .owner, operation: .other, phase: .close, error: error).category
        let ownerFailure: String
        switch error {
        case ManagedStorageFailure.invalid?: ownerFailure = "invalid"
        case ManagedStorageFailure.blocked?: ownerFailure = "blocked"
        case ManagedStorageFailure.repairRequired?: ownerFailure = "repair-required"
        case ManagedStorageFailure.changedServiceEpoch?: ownerFailure = "changed-service-epoch"
        case ManagedStorageFailure.unavailable?: ownerFailure = "unavailable"
        case ManagedStorageFailure.daemonRestartRequired?: ownerFailure = "daemon-restart-required"
        default: ownerFailure = "none"
        }
        let closed = firstClose.map { "\($0.site.rawValue)/\($0.operation.rawValue)/\($0.phase.rawValue)/\($0.category.rawValue)" } ?? "none"
        return "cengine worker-exit stage=\(stage.rawValue) category=\(category.rawValue) owner=\(ownerFailure) first-close=\(closed)\n"
    }
    private func logWorkerExit(_ stage: WorkerExitDiagnosticStage, error: (any Error)? = nil) {
        FileHandle.standardError.write(Data(Self.workerExitDiagnostic(stage, error: error,
            firstClose: nil).utf8))
    }

    /// Scheduling only for an explicitly claimed compatibility action. At most
    /// one start failure and one wait publisher may wait; cancellation, JSON and
    /// the worker wait reply cannot complete the real service-loss callback.
    /// The 16-request/two-waiter cap bounds retained memory, not elapsed time.
    /// If the observer fails ambiguously or is cancelled before serviceLost returns,
    /// selected waits deliberately remain held, including during backend cancellation.
    /// The external compatibility owner must contain that failed run within its budget;
    /// generic errors cannot stand in for a completed loss fence or authorize recovery.
    @MainActor final class PrepareWorkerExitLossFence {
        enum Waiter: Hashable { case startFailure, waitPublication }
        let generation: UUID
        private(set) var completed = false
        private var waiters: [Waiter: CheckedContinuation<Void, Never>] = [:]
        var waitingCount: Int { waiters.count }
        init(generation: UUID) { self.generation = generation }
        func wait(_ waiter: Waiter) async {
            guard !completed else { return }
            precondition(waiters[waiter] == nil)
            await withCheckedContinuation { waiters[waiter] = $0 }
        }
        func observedLossReturned() {
            guard !completed else { return }
            completed = true
            let pending = waiters.values; waiters.removeAll()
            for waiter in pending { waiter.resume() }
        }
    }

    private func claimWorkerExitLossFence(requestID: String, generation: UUID) throws -> PrepareWorkerExitLossFence {
        // Same bounded request population as the retained compatibility queue.
        guard workerExitLossFences[requestID] == nil, workerExitLossFences.count < 16 else { throw Self.failure() }
        let fence = PrepareWorkerExitLossFence(generation: generation)
        if completedWorkerLossGeneration == generation { fence.observedLossReturned() }
        else { workerExitLossFences[requestID] = fence }
        return fence
    }
    private func completeWorkerExitLossFences(generation: UUID) {
        completedWorkerLossGeneration = generation
        for requestID in Array(workerExitLossFences.keys) {
            guard let fence = workerExitLossFences[requestID], fence.generation == generation else { continue }
            workerExitLossFences.removeValue(forKey: requestID)
            fence.observedLossReturned()
        }
    }

    /// Scheduling only: an owned close defers a hint, never supplies a receipt.
    /// Keep deferred attachments after the last caller leaves so a failed close
    /// is contained on the next poll; only fresh journal evidence settles a hint.
    @MainActor struct RetirementHints {
        struct Close: Hashable, Sendable { private let id = UUID() }
        private var closes: [Close: Set<String>] = [:]
        private(set) var pending = Set<String>()

        mutating func begin(intents: [Journal.Intent], container: String,
                            instance: String, launch: String) -> Close {
            let close = Close()
            closes[close] = Set(intents.filter {
                $0.container == container && $0.containerInstance == instance && $0.launch == launch && !$0.isTerminal
            }.flatMap { $0.slots.filter { $0.role == "runtime" && $0.key != nil }.map(\.attachment) })
            return close
        }
        mutating func end(_ close: Close) { closes.removeValue(forKey: close) }
        mutating func enqueue(_ attachment: String) throws {
            pending.insert(attachment)
            guard pending.count <= Journal.maximumIntents * Journal.maximumAttachments else { throw failure() }
        }
        mutating func next(intents: [Journal.Intent], closingPrepare: Set<String>) throws -> (container: String, launch: String)? {
            for attachment in pending.sorted() {
                guard let target = try retirementTarget(attachment: attachment, intents: intents, closingPrepare: closingPrepare) else {
                    pending.remove(attachment)
                    continue
                }
                if closes.values.contains(where: { $0.contains(attachment) }) { continue }
                pending.remove(attachment)
                return target
            }
            return nil
        }
    }

    func beginRuntimeClose(container: ContainerRecord, launch: String) -> RetirementHints.Close? {
        // A broken journal cannot authorize deferral or prevent the caller from
        // attempting stop. Normal retirement still reports its ownership error.
        guard let intents = try? owner.journalSnapshot().intents else { return nil }
        return retirementHints.begin(intents: intents, container: container.id,
            instance: container.instanceID.uuidString.lowercased(), launch: launch)
    }
    func endRuntimeClose(_ close: RetirementHints.Close) { retirementHints.end(close) }

    private func retireIntent(_ intent: Journal.Intent) async throws {
        let close = retirementHints.begin(intents: [intent], container: intent.container,
            instance: intent.containerInstance, launch: intent.launch)
        defer { retirementHints.end(close) }
        try await lifecycle.retireLaunch(intent.id)
    }
    @MainActor final class Admission {
        typealias Lease = RawServiceWorkTracker.Lease
        private let work = RawServiceWorkTracker()
        private var starts = Set<Lease>()
        private var deleting: Lease?
        func beginStart() throws -> Lease {
            guard deleting == nil else { throw RawManagedStorageBackend.failure("managed volume deletion is in progress") }
            let lease = try work.begin(); starts.insert(lease); return lease
        }
        func endStart(_ lease: Lease) {
            starts.remove(lease); work.end(lease)
        }
        func beginDeletion() throws -> Lease {
            guard starts.isEmpty, deleting == nil else { throw RawManagedStorageBackend.failure("managed storage operation is in progress") }
            let lease = try work.begin(); deleting = lease; return lease
        }
        func endDeletion(_ lease: Lease) {
            if deleting == lease { deleting = nil }
            work.end(lease)
        }
        func close() { work.close() }
        func join(timeout: Duration = .seconds(30)) async throws { try await work.join(timeout: timeout) }
        func reopen() throws {
            guard starts.isEmpty, deleting == nil else { throw RawManagedStorageBackend.failure() }
            try work.reopen()
        }
    }
    private let admission = Admission()

    private init(root: PersistentStateDirectory, owner: ManagedStorageLifecycleOwner, lifecycle: Lifecycle,
                 names: SharedVolumeInitializationCoordinator = SharedVolumeInitializationCoordinator()) {
        self.root = root; self.owner = owner; self.lifecycle = lifecycle; self.names = names
    }

    /// Adopts an owner whose workload channel is already connected and creates
    /// the sole workload coordinator for its host journal.
    /// Existing stores require the owner's freshly proven takeover recovery gate.
    static func adoptConnectedOwner(root: PersistentStateDirectory, owner: ManagedStorageLifecycleOwner,
                                    names: SharedVolumeInitializationCoordinator) throws -> RawManagedStorageBackend {
        guard !owner.isExistingStore || owner.hasRecoveryPermission else {
            throw RawManagedStorageUnsupported(operation: "existing-store open without verified recovery")
        }
        let lifecycle = try owner.makeWorkloadCoordinator(names: names)
        _ = try owner.workloadSession()
        return RawManagedStorageBackend(root: root, owner: owner, lifecycle: lifecycle, names: names)
    }

    nonisolated static func failure(_ message: String = "managed storage ownership unresolved; preserve generation evidence") -> EngineError {
        EngineError(.conflict, message)
    }

    private func requireGeneration(_ expected: UUID) throws {
        try requireReconciled()
        guard expected == generation else { throw Self.failure() }
    }

    func requireReconciled() throws { guard reconciled, !maintenance, !workerUnavailable else { throw Self.failure() } }

    func synchronize(_ volumes: [VolumeRecord]) throws {
        try requireReconciled()
        let state = try owner.journalSnapshot()
        // Exact deletion evidence may precede EngineRuntime's pending-removal
        // publication. Retain that identity without readmitting it as a live V.
        let live = try volumes.filter { volume in
            guard let id = volume.instanceID?.uuidString.lowercased() else { throw Self.failure() }
            if let old = state.volumes.first(where: { $0.id == id }), old.isDeleted {
                guard old.name == volume.name, try lifecycle.deletionSettlement(id, name: volume.name) != nil else { throw Self.failure() }
                return false
            }
            return true
        }
        try owner.planVolumes(live)
        // Omission can mean a fenced volume, never deletion. Preserve its identity.
        for volume in volumes {
            guard let id = volume.instanceID else { throw Self.failure("managed volume requires its immutable instance UUID") }
            if let prior = records[volume.name], prior.instanceID != id {
                let state = try owner.journalSnapshot()
                guard state.volumes.contains(where: { $0.id == prior.instanceID?.uuidString.lowercased() && $0.isDeleted }) else {
                    throw Self.failure("volume name still belongs to a different instance")
                }
            }
            records[volume.name] = volume
        }
    }

    func reconcile(volumes: [VolumeRecord], containers: [ContainerRecord]) async throws {
        guard !maintenance, !workerUnavailable else { throw Self.failure() }
        guard !reconciled else { try synchronize(volumes); return }
        try await reconcileInventory(volumes: volumes, containers: containers)
        try await owner.resumePublicTakeoverOriginal()
        reconciled = true
        do { try synchronize(volumes) } catch { reconciled = false; throw error }
    }

    private func reconcileInventory(volumes: [VolumeRecord], containers: [ContainerRecord],
        replacementLifecycle: Lifecycle? = nil, replacementSnapshot: ManagedStorageJournalSnapshot? = nil) async throws {
        let lifecycle = replacementLifecycle ?? self.lifecycle
        let snapshot = try replacementSnapshot ?? owner.journalSnapshot()
        let containerDirectory = try root.openDirectory(named: "containers")
        // Validate the whole canonical inventory before touching any generation.
        // Terminal means storage authority settled, NOT proof that an old VM died.
        var directories: [String: PersistentStateDirectory] = [:]
        for intent in snapshot.intents {
            if let record = containers.first(where: { $0.id == intent.container }),
               record.instanceID.uuidString.lowercased() != intent.containerInstance { throw Self.failure() }
            directories[intent.id] = try containerDirectory.openDirectory(named: intent.container)
        }
        // Partition the complete native inventory before the first termination.
        // A historical terminal intent must not kill its selected live sibling.
        var ownership: [String: Set<String>] = [:]
        for intent in snapshot.intents where ownership[intent.container] == nil {
            guard let directory = directories[intent.id], let instance = UUID(uuidString: intent.containerInstance) else { throw Self.failure() }
            let launches = try VMShimClient.persistedLaunches(in: directory, expectedContainerID: intent.container,
                expectedInstanceID: instance)
            guard launches.quarantined.isEmpty,
                  launches.allSatisfy({ $0.client.ownsPersistedContainer(id: intent.container, directoryIdentity: directory.identity) }) else { throw Self.failure() }
            ownership[intent.container] = Set(launches.map { $0.client.persistentOwnershipKey })
        }
        var live: [Lifecycle.LiveRuntimePermit] = []
        var liveIDs = Set<String>()
        for intent in snapshot.intents where replacementLifecycle == nil {
            guard let directory = directories[intent.id],
                  let container = containers.first(where: { $0.id == intent.container }) else { continue }
            if let proof = try await lifecycle.prepareLiveRuntime(intent.id, container: container, in: directory) {
                live.append(proof); liveIDs.insert(intent.id)
            }
        }
        try await Self.reconcileExecutions(snapshot.intents, preserving: liveIDs, prepare: { intent in
            guard let directory = directories[intent.id] else { throw Self.failure() }
            return try await lifecycle.prepareContainment(intent.id, in: directory, preserving: live,
                expectedOwnership: ownership[intent.container])
        }, register: { permits in
            // The owner checks exact complete IDs, current intent values, native
            // evidence and a journal revision CAS before caching ANY permit.
            try await lifecycle.registerContainment(permits, preserving: live)
        }, settle: { intent in
            guard let directory = directories[intent.id] else { throw Self.failure() }
            _ = try await lifecycle.settleExecution(intent.id, in: directory)
        }, ready: {
            try await lifecycle.validateLiveRuntimes()
            try await lifecycle.reconcileStartup()
            try await lifecycle.validateLiveRuntimes(recordEvidence: true)
        })

    }

    func validateServiceReplacement(_ request: StorageServiceTypes.ReplacementRequest) async throws {
        try await owner.awaitServiceReplacementAdmission(request)
    }

    func validateServiceAvailability(_ scope: StorageServiceTypes.Scope) async throws {
        try requireReconciled()
        let epoch = generation
        do { try await owner.validateServiceAvailability(scope) }
        catch ManagedStorageControlFailure.serviceUnavailable {
            if generation == epoch, !maintenance {
                workerUnavailable = true; reconciled = false; generation = UUID()
            }
            throw ManagedStorageControlFailure.serviceUnavailable
        }
        try requireGeneration(epoch)
    }

    func joinServiceReplacementWork() async throws {
        try await admission.join()
        try await notificationWork.join()
        await notifications?.value
        notifications = nil
    }

    /// The retained task owns the entire replacement, not the requesting caller.
    /// No old PREPARE callback is joined as evidence of drain before worker death.
    func replaceService(_ request: StorageServiceTypes.ReplacementRequest,
        volumes: [VolumeRecord], containers: [ContainerRecord],
        observation: VMShimClient.OriginalConsumerObservation? = nil,
        originalClaim: ManagedPrepareCompatibilityQueue.OriginalClaim? = nil,
        compatibility: ManagedPrepareCompatibilityCoordinator? = nil,
        contain: @escaping @Sendable () async throws -> Set<String>) async throws -> BackendServiceReplacementResult {
        try await replaceLifecycleService(request, owner: owner, volumes: volumes,
            containers: containers, observation: observation, originalClaim: originalClaim,
            compatibility: compatibility, contain: contain)
    }

    /// Native lifecycle maintenance uses the same full inventory/containment path,
    /// but never converts v2 metadata into a v1 verified boot or maintenance token.
    private func replaceLifecycleService(_ request: StorageServiceTypes.ReplacementRequest,
        owner runtime: ManagedStorageLifecycleOwner, volumes: [VolumeRecord], containers: [ContainerRecord],
        observation: VMShimClient.OriginalConsumerObservation?,
        originalClaim: ManagedPrepareCompatibilityQueue.OriginalClaim?,
        compatibility: ManagedPrepareCompatibilityCoordinator?,
        contain: @escaping @Sendable () async throws -> Set<String>) async throws -> BackendServiceReplacementResult {
        if let (original, task) = replacements[request.operationUUID] {
            guard original == request else { throw Self.failure("replacement request changed") }
            // Observation failures are terminal even when the next caller omits
            // its observation. A late owner result cannot renew the Begin lease.
            guard !originalLifecycleOperations.contains(request.operationUUID) else { return try await task.value }
            // Ordinary concurrent callers join this attempt; only an explicit
            // later retry may consume the owner's typed retry boundary.
            guard let boundary = try? runtime.validateServiceReplacementRetry(request) else { return try await task.value }
            do { return try await task.value }
            catch let retry as ManagedStorageLifecycleOwner.RetryableReplacementTimeout {
                guard retry.request == request, retry.id == boundary.id else { throw retry }
                if let (_, current) = replacements[request.operationUUID], current != task {
                    return try await current.value
                }
                _ = try runtime.validateServiceReplacementRetry(request)
            }
        } else {
            if observation == nil {
                try await runtime.awaitServiceReplacementAdmission(request)
                if replacements[request.operationUUID] != nil {
                    return try await replaceLifecycleService(request, owner: runtime, volumes: volumes,
                        containers: containers, observation: observation, originalClaim: originalClaim,
                        compatibility: compatibility, contain: contain)
                }
            }
            guard !maintenance else {
                if let observation {
                    fenceOriginalConsumerFailure()
                    return try await OriginalConsumerCleanup.run(operation: {
                        throw Self.failure("service replacement is in progress")
                    }, release: { _ = try await observation.release() }, contain: { _ = try await contain() })
                }
                throw Self.failure("service replacement is in progress")
            }
            admission.close(); notificationWork.close()
            maintenance = true; reconciled = false; generation = UUID()
            // Do not cancel a native 4106 exchange: its onCancel fences the owner.
        }
        if observation != nil { originalLifecycleOperations.insert(request.operationUUID) }
        let task = Task { @MainActor in
            typealias D = OriginalConsumerFailureDiagnostic
            let diagnosticsEnabled = observation != nil
            @MainActor func preamble() async throws {
                // The whole-loop lease includes all affected/serviceLost callbacks.
                try await self.notificationWork.join(timeout: .seconds(5))
                await self.notifications?.value
                self.notifications = nil
                try await runtime.awaitServiceReplacementAdmission(request)
            }
            // Keep ordinary native retry semantics unchanged. Observer preamble
            // failures, however, must always release and contain the armed guest.
            if observation == nil { try await preamble() }
            var contained = Set<String>()
            let session = try await OriginalConsumerCleanup.run(operation: {
                if observation != nil { try await preamble() }
                let dispatch = try observation.map { try OriginalConsumerObservationDispatch($0.binding.caseName) }
                if let observation {
                    guard let claim = originalClaim, let compatibility,
                          claim.request.operationUUID == request.operationUUID,
                          claim.request.requestID == observation.binding.requestID,
                          claim.request.caseName == observation.binding.caseName,
                          claim.request.container == observation.binding.scope.container,
                          claim.request.containerInstance == observation.binding.scope.containerInstance,
                          observation.binding.operationUUID == request.operationUUID,
                          observation.binding.scope.serviceEpoch == request.predecessor.serviceEpoch,
                          let installed = self.installedOriginalRuntimes[claim.request.container],
                          installed.boot.binding == observation.binding.boot,
                          installed.boot.scope == observation.binding.scope,
                          installed.boot.binding == observation.boot.binding,
                          installed.boot.scope == observation.boot.scope,
                          installed.shim.specification.generation == observation.binding.generation,
                          let intent = try self.owner.journalSnapshot().intents.first(where: { $0.id == observation.binding.scope.intent }),
                          intent.phase == .running, Self.scope(intent) == observation.binding.scope,
                          intent.slots.contains(where: { $0.attachment == observation.binding.targetAttachment && $0.key == observation.binding.key && $0.role == "runtime" && $0.receipt == nil })
                    else { throw Self.failure() }
                    try claim.request.validate()
                    let service = try self.owner.workloadSession().service.ready
                    guard StorageServiceTypes.Scope(serviceEpoch: service.serviceEpoch, workerUUID: service.workerUUID) == request.predecessor else { throw Self.failure() }
                    try Self.validateOriginalService(service, scope: observation.binding.scope, peer: installed.boot.configuredPeer)
                    let credential = try Self.selectOriginalRuntimeCredential(caseName: observation.binding.caseName,
                        scope: observation.binding.scope, credentials: installed.credentials, intent: intent)
                    guard credential.attachment == observation.binding.targetAttachment,
                          credential.key == observation.binding.key,
                          credential.certificateSHA256 == observation.binding.certificateSHA256 else { throw Self.failure() }
                    try observation.validateInstalled(client: installed.shim, boot: installed.boot)
                    _ = try await observation.begin()
                    guard self.installedOriginalRuntimes[claim.request.container]?.shim === installed.shim,
                          installed.shim.specification.shimLaunchUUID == observation.binding.boot.shimLaunchUUID,
                          installed.shim.specification.generation == observation.binding.generation else { throw Self.failure() }
                    guard self.installedOriginalRuntimes[claim.request.container]?.credentials == installed.credentials,
                          try self.owner.workloadSession().service.ready == service,
                          let currentIntent = try self.owner.journalSnapshot().intents.first(where: { $0.id == intent.id }),
                          try Self.selectOriginalRuntimeCredential(caseName: observation.binding.caseName,
                            scope: observation.binding.scope, credentials: installed.credentials, intent: currentIntent) == credential
                    else { throw Self.failure() }
                    try observation.validateInstalled(client: installed.shim, boot: installed.boot)
                    _ = try observation.remainingDeadline()
                    // Wrong-Hello denial belongs to the CURRENT worker, before
                    // replacement changes E/trust. It consumes the same Begin lease.
                    try compatibility.originalPublish(observation.binding, phase: .begun, claim: claim)
                    if dispatch == .roots {
                        let generation = self.generation, positive = observation.evidence
                        self.originalRootEvidence[request.operationUUID] = try await runtime.observeOriginalConsumerRoots(
                            observation, request: request, installed: { retirement in
                                guard self.generation == generation, self.maintenance,
                                      let current = self.installedOriginalRuntimes[claim.request.container],
                                      current.shim === installed.shim, current.boot.binding == installed.boot.binding,
                                      current.boot.scope == installed.boot.scope, current.credentials == installed.credentials,
                                      current.shim.specification.generation == observation.binding.generation,
                                      let intent = try self.owner.journalSnapshot().intents.first(where: { $0.id == observation.binding.scope.intent })
                                else { throw Self.failure() }
                                try current.shim.validateOriginalBaselineReader(current.boot)
                                try Self.validateOriginalRootCredentials(observation.binding, positive: positive,
                                    credentials: current.credentials, intent: intent, retirement: retirement)
                            })
                    } else if dispatch == .sameE {
                        let registrationGeneration = self.generation
                        self.originalReplacementEvidence[request.operationUUID] = try await runtime.observeOriginalConsumerSameE(
                            observation, request: request, installed: { retirement in
                                guard let current = self.installedOriginalRuntimes[claim.request.container],
                                      self.maintenance, self.generation == registrationGeneration, current.shim === installed.shim,
                                      current.boot.binding == installed.boot.binding, current.boot.scope == installed.boot.scope,
                                      current.credentials == installed.credentials,
                                      current.shim.specification.generation == observation.binding.generation else { throw Self.failure() }
                                try current.shim.validateOriginalBaselineReader(current.boot)
                                _ = try ManagedStorageOriginalConsumerComparison.originalConsumerTuple(observation.binding,
                                    intent: self.owner.journalSnapshot().intents.first(where: { $0.id == observation.binding.scope.intent }),
                                    retiredReceipt: retirement?.receipt)
                            })
                    } else if dispatch == .wrongHello {
                        self.originalReplacementEvidence[request.operationUUID] = try await runtime.observeOriginalConsumerWrongHello(
                            observation, request: request)
                    }
                }
                let adopted: ManagedStorageLifecycleOwner.ServiceReplacementMaintenance
                if let observation {
                    let deadline = try observation.remainingDeadline()
                    let adoption = OriginalConsumerAdoptionWait {
                        try await runtime.replaceService(operationID: request.operationUUID,
                            predecessor: request.predecessor, nowUnixSeconds: request.nowUnixSeconds,
                            lifetimeSeconds: 3600, names: self.names)
                    }
                    self.originalLifecycleAdoptions[request.operationUUID] = adoption
                    adopted = try await adoption.wait(deadline: deadline)
                    try D.step(diagnosticsEnabled ? .adoptionReturn : nil) { _ = try observation.remainingDeadline() }
                } else {
                    adopted = try await runtime.replaceService(operationID: request.operationUUID,
                        predecessor: request.predecessor, nowUnixSeconds: request.nowUnixSeconds,
                        lifetimeSeconds: 3600, names: self.names)
                }
                // Publish actual new TLS bytes before cross-consumer/new-proof reads.
                // Keep the route from the real original workload configuration.
                if let compatibility, compatibility.profile == ManagedPrepareCompatibilityProtocol.fullProfile {
                    let routes = self.installedOriginalRuntimes.values.compactMap { installed -> String? in
                        guard installed.boot.scope?.serviceEpoch == request.predecessor.serviceEpoch else { return nil }
                        return installed.boot.configuredPeer?.dataAddress
                    }
                    let route = observation?.boot.configuredPeer?.dataAddress ?? routes.first
                    if observation != nil && route == nil { throw Self.failure() }
                    if let route {
                        guard observation != nil || routes.allSatisfy({ $0 == route }) else { throw Self.failure() }
                        let service = try runtime.maintenanceServiceProjection(adopted)
                        try compatibility.lifecyclePeerPublish(.init(binding: service.binding, ready: service.ready,
                            peer: .init(tlsRootDER: service.ready.tlsRootDER, serverDER: service.ready.serverDER,
                                serverKey: service.ready.serverSPKI, dataAddress: route)))
                    }
                }
                // Observe replacement through the adopted request and its live owner.
                if let observation, dispatch == .replacement {
                    self.originalReplacementEvidence[request.operationUUID] =
                        try await observation.observeReplacement(adopted, owner: runtime)
                }
                return adopted
            }, release: {
                try await D.step(diagnosticsEnabled ? .release : nil) {
                    if let observation { _ = try await observation.release() }
                }
            }, contain: {
                contained = try await D.step(diagnosticsEnabled ? .containment : nil) { try await contain() }
                try await D.step(diagnosticsEnabled ? .joinWork : nil) { try await self.joinServiceReplacementWork() }
            })
            let before = try D.step(diagnosticsEnabled ? .inventorySnapshot : nil) { try runtime.maintenanceSnapshot(session) }
            try D.step(diagnosticsEnabled ? .volumePlan : nil) {
                try runtime.planReplacementVolumes(Self.replacementVolumes(volumes, snapshot: before), session: session)
            }
            try await D.step(diagnosticsEnabled ? .inventoryReconcile : nil) {
                try await self.reconcileInventory(volumes: volumes, containers: containers,
                    replacementLifecycle: session.lifecycle, replacementSnapshot: runtime.maintenanceSnapshot(session))
            }
            try D.step(diagnosticsEnabled ? .completionCommit : nil) {
                try runtime.completeServiceReplacement(session) {
                    let settled = try runtime.maintenanceSnapshot(session)
                    let exact = try Self.replacementVolumes(volumes, snapshot: settled)
                    guard !settled.reconciliationRequired,
                          Set(exact.compactMap { $0.instanceID?.uuidString.lowercased() }) ==
                            Set(settled.volumes.filter { !$0.isDeleted }.map(\.id)) else { throw Self.failure() }
                    self.records = Dictionary(uniqueKeysWithValues: volumes.map { ($0.name, $0) })
                }
            }
            // Validate exact negative evidence and containment before ANY reopen.
            try D.step(diagnosticsEnabled ? .freshObservation : nil) {
                if let observation, let claim = originalClaim,
                   OriginalConsumerRuntimeCarrier.FreshGetattr.required(observation.binding.caseName) {
                    guard contained.contains(claim.request.container),
                          let negative = self.originalReplacementEvidence[request.operationUUID],
                          negative.original.arm == .init(observation.binding),
                          self.pendingFreshGetattr[claim.request.container] == nil else { throw Self.failure() }
                    self.pendingFreshGetattr[claim.request.container] = .init(original: observation.binding,
                        volume: negative.worker.query.original.binding.volume, claim: claim)
                }
                if let observation, let claim = originalClaim, observation.binding.caseName.isRoot {
                    guard contained.contains(claim.request.container),
                          let roots = self.originalRootEvidence[request.operationUUID]?.result,
                          roots.binding == observation.binding,
                          let source = roots.positive.roots?.source.read.authority.binding.volume,
                          self.pendingFreshGetattr[claim.request.container] == nil else { throw Self.failure() }
                    self.pendingFreshGetattr[claim.request.container] = .init(original: observation.binding,
                        volume: source, claim: claim, rootResult: roots)
                }
            }
            self.lifecycle = session.lifecycle
            try D.step(diagnosticsEnabled ? .admissionReopen : nil) {
                try self.admission.reopen(); try self.notificationWork.reopen()
            }
            self.originalPreflightGeneration = nil; self.installedOriginalRuntimes.removeAll()
            self.maintenance = false; self.workerUnavailable = false; self.reconciled = true
            return BackendServiceReplacementResult(request: request, successor: session.serviceScope,
                containedContainerIDs: contained)
        }
        maintenanceTask = task; replacements[request.operationUUID] = (request, task)
        return try await task.value
    }

    static func replacementVolumes(_ volumes: [VolumeRecord], snapshot: ManagedStorageJournalSnapshot) throws -> [VolumeRecord] {
        guard Set(volumes.map(\.name)).count == volumes.count,
              Set(volumes.compactMap(\.instanceID)).count == volumes.count else { throw failure() }
        return try volumes.filter { volume in
            guard let id = volume.instanceID?.uuidString.lowercased() else { throw failure() }
            if let existing = snapshot.volumes.first(where: { $0.id == id }) {
                guard existing.name == volume.name else { throw failure() }
                return !existing.isDeleted
            }
            guard !snapshot.volumes.contains(where: { $0.name == volume.name && !$0.isDeleted }) else { throw failure() }
            return true
        }
    }

    /// Ordering seam only: Proof is supplied by the lifecycle's sealed native
    /// containment factory, never constructed from a decoded journal/receipt.
    static func reconcileExecutions<Proof>(_ intents: [Journal.Intent], preserving live: Set<String> = [],
        prepare: (Journal.Intent) async throws -> Proof,
        register: ([Proof]) async throws -> Void,
        settle: (Journal.Intent) async throws -> Void,
        ready: () async throws -> Void) async throws {
        guard Set(intents.map(\.id)).count == intents.count, live.isSubset(of: Set(intents.map(\.id))),
              intents.filter({ live.contains($0.id) }).allSatisfy({ $0.phase == .running && $0.prepareCompleted }) else { throw failure() }
        // The production caller supplies only IDs from sealed native/session proofs.
        let ordered = intents.filter { !live.contains($0.id) }.sorted { $0.id < $1.id }
        var proofs: [Proof] = []
        for intent in ordered { proofs.append(try await prepare(intent)) }
        try await register(proofs)
        for intent in ordered where !intent.isTerminal { try await settle(intent) }
        try await ready()
    }

    func permitsLiveRecovery(container: ContainerRecord, shim: VMShimClient) async throws -> Bool {
        try requireReconciled()
        return try await lifecycle.permitsLiveRecovery(container: container, shim: shim)
    }

    func volumeID(named name: String) throws -> String {
        try requireReconciled()
        guard let id = records[name]?.instanceID?.uuidString.lowercased() else {
            throw Self.failure("managed volume has no reconciled immutable instance UUID")
        }
        return id
    }

    func delete(_ volume: VolumeRecord) async throws {
        guard !maintenance, !workerUnavailable else { throw Self.failure() }
        let epoch = generation
        let lifecycle = self.lifecycle
        let lease = try admission.beginDeletion()
        defer { admission.endDeletion(lease) }
        if !reconciled {
            try await lifecycle.reconcileStartup()
            guard !maintenance, !workerUnavailable, generation == epoch else { throw Self.failure() }
            reconciled = true
        }
        try requireReconciled()
        guard let id = volume.instanceID?.uuidString.lowercased(),
              records[volume.name]?.instanceID == volume.instanceID else { throw Self.failure() }
        guard records[volume.name]?.instanceID?.uuidString.lowercased() == id else { throw Self.failure() }
        _ = try owner.workloadSession()
        _ = try await lifecycle.settleDeletion(id, name: volume.name)
        guard !maintenance, !workerUnavailable, generation == epoch else { throw Self.failure() }
        reconciled = false
        try await lifecycle.reconcileStartup()
        guard !maintenance, !workerUnavailable, generation == epoch else { throw Self.failure() }
        reconciled = true
        // Retain the exact record until canonical publication. Repeated deletion
        // uses the same durable settlement rather than manufacturing authority.
    }

    func replacement(for container: ContainerRecord, in directory: PersistentStateDirectory) async throws -> Replacement? {
        try requireReconciled()
        let epoch = generation
        for previous in try owner.journalSnapshot().intents where previous.container == container.id
            && previous.containerInstance == container.instanceID.uuidString.lowercased()
            && previous.prepareCompleted && !previous.isTerminal {
            try requireGeneration(epoch)
            try await retireIntent(previous)
        }
        try requireGeneration(epoch)
        let candidates = try owner.journalSnapshot().intents.filter {
            $0.container == container.id && $0.containerInstance == container.instanceID.uuidString.lowercased()
                && !$0.prepareCompleted && !$0.isTerminal
        }
        guard candidates.count <= 1 else { throw Self.failure() }
        guard let previous = candidates.first else { return nil }
        return Replacement(predecessor: previous.id,
            permit: try await Lifecycle.ReplacementPermit.contain(previous, in: directory))
    }

    func retire(containerID: String, instanceID: UUID? = nil, launch: String? = nil) async throws {
        try requireReconciled()
        let epoch = generation
        let intents = try owner.journalSnapshot().intents.filter {
            $0.container == containerID && (instanceID == nil || $0.containerInstance == instanceID!.uuidString.lowercased())
                && (launch == nil || $0.launch == launch)
                && !$0.isTerminal
        }
        for intent in intents {
            try requireGeneration(epoch)
            try await retireIntent(intent)
        }
    }

    func settleExecution(container: ContainerRecord, in directory: PersistentStateDirectory) async throws {
        try requireReconciled()
        let epoch = generation
        let lifecycle = self.lifecycle
        let intents = try owner.journalSnapshot().intents.filter {
            $0.container == container.id && $0.containerInstance == container.instanceID.uuidString.lowercased() && !$0.isTerminal
        }
        for intent in intents {
            try requireGeneration(epoch)
            _ = try await lifecycle.settleExecution(intent.id, in: directory)
        }
        try requireGeneration(epoch)
        try await lifecycle.reconcileStartup()
    }

    func refreshTerminalContainment(container: ContainerRecord, in directory: PersistentStateDirectory) async throws {
        try requireReconciled()
        let epoch = generation
        let lifecycle = self.lifecycle
        try await lifecycle.refreshTerminalContainment(containerID: container.id, instanceID: container.instanceID, in: directory)
        try requireGeneration(epoch)
    }

    func hasIntents(containerID: String) throws -> Bool {
        try owner.journalSnapshot().intents.contains { $0.container == containerID }
    }

    func start(container: ContainerRecord, launchUUID: String, directory: PersistentStateDirectory,
               workload: GuestProtocol.Workload, compatibility: ManagedPrepareCompatibilityCoordinator? = nil, launchShim: @escaping @Sendable () async throws -> VMShimClient,
               check: @escaping @Sendable (VMShimClient?) async throws -> Void,
               consumeIOClaim: @escaping @Sendable (VMShimClient, String) async throws -> Void,
               beforePublication: @escaping @Sendable (VMShimClient) async throws -> [PortBinding]) async throws -> [PortBinding] {
        try requireReconciled()
        let epoch = generation
        let lifecycle = self.lifecycle
        let originalCheck = check
        let check: @Sendable (VMShimClient?) async throws -> Void = { shim in
            try await self.requireGeneration(epoch)
            try await originalCheck(shim)
            try await self.requireGeneration(epoch)
        }
        let lease = try admission.beginStart()
        defer { admission.endStart(lease) }
        try await check(nil)
        let replacement = try await replacement(for: container, in: directory)
        try await check(nil)
        let context = try owner.workloadSession().context
        let bytes = try Self.workloadBytes(workload)
        let plan = try Self.plan(container: container, launch: launchUUID,
            context: context, workload: workload, serializedWorkload: bytes)
        let peer = try owner.workloadSession().service.ready
        let bindings = workload.mounts.enumerated().compactMap { index, mount -> Wire.MountBinding? in
            guard mount.kind == "volume", mount.device == nil else { return nil }
            return .init(index: UInt32(index), volume: mount.source, destination: mount.destination,
                subpath: mount.subpath ?? "", mode: mount.readOnly ? .readOnly : .readWrite, noCopy: mount.noCopy)
        }
        let capture = try compatibility?.capture(container: container.id,
            instance: container.instanceID.uuidString.lowercased(), digest: plan.specificationDigest, mounts: bindings)
        let configuration = WorkloadStorageConfiguration(scope: Self.scope(plan),
            peer: .init(tlsRootDER: peer.tlsRootDER, serverDER: peer.serverDER,
                serverKey: peer.serverSPKI, dataAddress: RawVirtualizationBackend.managementServerAddress),
            mounts: bindings, slots: plan.slots.map {
                .init(volume: $0.volume, attachment: $0.attachment,
                    role: $0.role == "prepare" ? .prepare : .runtime,
                    mode: $0.mode == "read-only" ? .readOnly : .readWrite)
            })
        if let compatibility, compatibility.profile == ManagedPrepareCompatibilityProtocol.fullProfile {
            let service = try owner.workloadSession().service
            try compatibility.lifecyclePeerPublish(.init(binding: service.binding, ready: service.ready,
                peer: configuration.peer))
        }
        let prepareAttachments = Set(plan.slots.filter { $0.role == "prepare" }.map(\.attachment))
        defer { closingPrepareAttachments.subtract(prepareAttachments) }
        var shim: VMShimClient?
        var published: [PortBinding]?
        var configured: VerifiedWorkloadStorageBoot?
        var offers: [String: Wire.Offer] = [:]
        var prepareCredentials: [ManagedPrepareCompatibilityProtocol.Credential] = []
        var runtimeCredentials: [ManagedPrepareCompatibilityProtocol.Credential] = []
        var normalPrepareObservation: Task<Void, Error>?
        var earlyPrepareObservation: Task<Void, Error>?
        var successfulStorageObservation: Task<Void, Error>?
        var workloadIOObservation: Task<Void, Error>?
        var authorityIOObservation: Task<Void, Error>?
        var selectedIO = false
        var workerExitLossFence: PrepareWorkerExitLossFence?
        var storageCheckpointExitObservation: Task<Void, Error>?
        var checkpointWorkerExitObservation: Task<Void, Error>?
        var workerExitAllowed = true
        defer { workerExitAllowed = false }
        func command(_ kind: Wire.Kind, _ data: Wire.Payload = .init()) async throws -> Wire.Payload {
            try await check(shim)
            guard let shim, let configured, let scope = configured.scope else { throw Self.failure() }
            let reply = try await shim.workloadStorageCommand(.init(operation: .command,
                binding: configured.binding, scope: scope, sequence: 1, kind: kind, data: data), boot: configured)
            try await check(shim)
            return try Self.workloadCommandPayload(reply, kind: kind, role: data.role)
        }
        let guest = Lifecycle.GuestActions(offerKeys: { intent, role in
            try await check(shim)
            if configured == nil {
                // Both start and replace durably journal the entire plan before
                // this first callback. Replacement consumes the exact OLD launch
                // set before launchShim can persist the successor generation.
                let launched = try await launchShim()
                shim = launched
                try await check(launched)
                guard launched.specification.shimLaunchUUID == plan.launch else { throw Self.failure() }
                let boot = try await launched.bootWorkloadStorage()
                try await check(launched)
                guard boot.scope == nil, boot.binding.shimLaunchUUID == plan.launch,
                      boot.compatibilityProfile == compatibility?.profile else { throw Self.failure() }
                configured = try await launched.configureWorkloadStorage(boot: boot, configuration: configuration)
                try await check(launched)
            }
            let response = try await command(.offerKeys, .init(role: role == .prepare ? .prepare : .runtime))
            guard let offered = response.offers else { throw Self.failure() }
            for offer in offered { offers[offer.attachment] = offer }
            return offered.map { .init(attachment: $0.attachment, key: $0.key) }
        }, credentialAndMount: { intent, role in
            for slot in intent.slots where slot.role == role.rawValue {
                try await check(shim)
                guard let offer = offers.removeValue(forKey: slot.attachment), offer.key == slot.key else { throw Self.failure() }
                let certificate = try await self.owner.attachmentCertificate(intent: self.owner.token(for: intent.id),
                    attachment: slot.attachment, csr: offer.csrDER)
                try await check(shim)
                _ = try await command(.installCertificate, .init(attachment: slot.attachment, certificateDER: certificate))
                if role == .runtime {
                    runtimeCredentials.append(.init(attachment: slot.attachment, key: offer.key,
                        certificateSHA256: Wire.specificationDigest(certificate)))
                }
                if role == .prepare {
                    prepareCredentials.append(.init(attachment: slot.attachment, key: offer.key,
                        certificateSHA256: Wire.specificationDigest(certificate)))
                }
            }
            if role == .prepare, let compatibility, let capture {
                guard let live = shim, let boot = configured, let scope = boot.scope else { throw Self.failure() }
                try await check(live)
                let candidate = ManagedPrepareCompatibilityProtocol.Candidate(version: compatibility.version,
                    profile: compatibility.profile, requestID: capture.request.requestID,
                    binding: boot.binding, scope: scope, mounts: configuration.mounts.sorted { $0.index < $1.index },
                    slots: configuration.slots.sorted { $0.attachment < $1.attachment },
                    credentials: prepareCredentials.sorted { $0.attachment < $1.attachment })
                try compatibility.candidate(candidate, claim: capture)
                var selected: ManagedPrepareCompatibilityProtocol.Arm?
                while selected == nil {
                    try await check(live)
                    // No serial command/observer lock is held at this rendezvous.
                    selected = try compatibility.arm(capture, candidate: candidate)
                    if selected == nil {
                        // Caller cancellation is not owner death or arm release.
                        await Task.detached { try? await Task.sleep(for: .milliseconds(100)) }.value
                    }
                }
                guard let arm = selected else { throw Self.failure() }
                selectedIO = ManagedPrepareCompatibilityProtocol.ioCase(arm.caseName) != nil
                try await check(live)
                let response = try await command(.prepareCompatibilityArm, .init(compatibilityArm: arm))
                guard response.compatibilityDigest == (try ManagedPrepareCompatibilityProtocol.digest(arm)) else { throw Self.failure() }
                try await check(live)
                if arm.profile == ManagedPrepareCompatibilityProtocol.fullProfile,
                   ManagedPrepareCompatibilityProtocol.isStorageCase(arm.caseName) {
                    let (storageArm, armed) = try await self.owner.armPrepareStorage(arm)
                    // No DATA mount can precede both ACKs and durable storage arm.
                    try compatibility.storageStatus(armed, arm: storageArm, claim: capture)
                    try compatibility.armed(arm, claim: capture)
                    guard self.storagePrepareObservations[arm.requestID] == nil else { throw Self.failure() }
                    let pump = Task {
                        var checkpointClaimPolled = false
                        // One absolute budget includes the in-flight authenticated RPC,
                        // not merely the gaps between polls. Expiry is observation
                        // failure, never an IO checkpoint or evidence of drain.
                        let ioDeadline: UInt64? = selectedIO
                            ? DispatchTime.now().uptimeNanoseconds + 30_000_000_000 : nil
                        while true {
                            if let ioDeadline, DispatchTime.now().uptimeNanoseconds >= ioDeadline { throw Self.failure() }
                            if let status = try await self.owner.observePrepareStorage(storageArm, deadlineNanoseconds: ioDeadline) {
                                try compatibility.storageStatus(status, arm: storageArm, claim: capture)
                                if status.observation?.io != nil { return } // already durably published, never drain/success
                                // The reply-gap witness is complete, not the held Retire or start.
                                // Its DTO permits no release, replay or finished promotion.
                                if arm.caseName == ManagedPrepareCompatibilityProtocol.twoVolumeDrainReplyGap,
                                   status.state == "held" { return }
                                // A6/A8 can finish naturally before the parent sees the
                                // durable checkpoint. Retain this one claim rendezvous
                                // even for a finished status, not the service RPC lock.
                                var checkpointExit: ManagedPrepareWorkerCheckpointProtocol.WorkerCheckpointExit?
                                if ManagedPrepareWorkerCheckpointProtocol.checkpointExitCut(arm.caseName),
                                   status.observation != nil, !checkpointClaimPolled {
                                    checkpointClaimPolled = true
                                    checkpointExit = try await Self.pollCheckpointWorkerExit(
                                        allowed: { workerExitAllowed }, claim: { try compatibility.checkpointWorkerExit(capture) })
                                }
                                if let exit = checkpointExit {
                                    // RTM098 generic carrier for A6/A8: the exact retained
                                    // Bound/Drain observation, never a release token. Claim
                                    // and install the loss fence on this actor before the
                                    // command can kill the worker; only the genuine
                                    // serviceLost callback completes that fence.
                                    let lossFence = try self.claimWorkerExitLossFence(requestID: arm.requestID, generation: epoch)
                                    workerExitLossFence = lossFence
                                    self.logWorkerExit(.claimed)
                                    let wait: ManagedPrepareWorkerCheckpointProtocol.WorkerCheckpointWait
                                    do {
                                        wait = try await self.owner.exitCheckpointWorker(exit)
                                    } catch {
                                        self.logWorkerExit(.commandFailed, error: error)
                                        throw error
                                    }
                                    self.logWorkerExit(.commandReturned)
                                    await lossFence.wait(.waitPublication)
                                    self.logWorkerExit(.fenceReturned)
                                    try compatibility.checkpointWorkerWait(wait, claim: capture)
                                    return // Never observe the dead old-E worker again or auto-replace it.
                                }
                                if status.state == "finished" { return }
                                switch try compatibility.storageAction(storageArm, claim: capture, workerExitAllowed: workerExitAllowed) {
                                case .workerExit(let exit):
                                    // Claim and install on this actor before the command can kill
                                    // the worker. Only this start's error/publication waits below.
                                    let lossFence = try self.claimWorkerExitLossFence(requestID: arm.requestID, generation: epoch)
                                    workerExitLossFence = lossFence
                                    self.logWorkerExit(.claimed)
                                    let wait: ManagedPrepareCompatibilityProtocol.StorageWorkerWait
                                    do {
                                        wait = try await self.owner.exitPrepareStorageWorker(exit, arm: storageArm, checkpoint: status)
                                    } catch {
                                        self.logWorkerExit(.commandFailed, error: error)
                                        throw error
                                    }
                                    self.logWorkerExit(.commandReturned)
                                    await lossFence.wait(.waitPublication)
                                    self.logWorkerExit(.fenceReturned)
                                    try compatibility.storageWorkerWait(wait, arm: storageArm, claim: capture)
                                    return // Never observe the dead old-E worker again or auto-replace it.
                                case .release(let release):
                                    let released = try await self.owner.releasePrepareStorage(release, arm: storageArm)
                                    try compatibility.storageStatus(released, arm: storageArm, claim: capture)
                                    if released.state == "finished" { return }
                                case nil: break
                                }
                            }
                            // Observation/cancellation never supplies a release.
                            try await Task.sleep(for: .milliseconds(100))
                        }
                    }
                    self.storagePrepareObservations[arm.requestID] = pump
                    if ManagedPrepareWorkerCheckpointProtocol.checkpointExitCut(arm.caseName) {
                        storageCheckpointExitObservation = pump
                        checkpointWorkerExitObservation = pump
                    }
                    if arm.caseName == "drain-durable-reply-lost" { successfulStorageObservation = pump }
                    if selectedIO { authorityIOObservation = pump }
                } else { try compatibility.armed(arm, claim: capture) }
                // Both armed cases emit pre-read source timestamp evidence. This
                // observer never acquires the PREPARE serial lock or cancels it.
                guard self.prepareObservations[arm.requestID] == nil else { throw Self.failure() }
                if ManagedPrepareCompatibilityProtocol.expectsPhysicalObservation(arm) || ManagedPrepareCompatibilityProtocol.isEarlyCase(arm.caseName) || ManagedPrepareCompatibilityProtocol.ioCase(arm.caseName)?.workload == true {
                    let observer = Task {
                        let frame = try await live.workloadStoragePrepareObservation(arm, boot: boot)
                        try compatibility.checkpoint(frame, arm: arm, claim: capture)
                        // RTM098 generic checkpoint exit for the five guest cuts. The
                        // private child ACKs the exact sealed claim and then self-exits
                        // 74; the ACK is never death proof. Only PID1's sole actual Wait
                        // projection published below, followed by the genuine serviceLost
                        // loss fence, may conclude the interrupted start.
                        if ManagedPrepareWorkerCheckpointProtocol.checkpointExitCut(arm.caseName),
                           !ManagedPrepareCompatibilityProtocol.isStorageCase(arm.caseName) {
                            // The parent's sealed claim request is published only after
                            // this observation lands on its side; poll (bounded) until
                            // the claim is selectable instead of one doomed attempt.
                            if let exit = try await Self.pollCheckpointWorkerExit(
                                allowed: { workerExitAllowed }, claim: { try compatibility.checkpointWorkerExit(capture) }) {
                                let lossFence = try self.claimWorkerExitLossFence(requestID: arm.requestID, generation: epoch)
                                workerExitLossFence = lossFence
                                self.logWorkerExit(.claimed)
                                let wait: ManagedPrepareWorkerCheckpointProtocol.WorkerCheckpointWait
                                do {
                                    wait = try await self.owner.exitCheckpointWorker(exit)
                                } catch {
                                    self.logWorkerExit(.commandFailed, error: error)
                                    throw error
                                }
                                self.logWorkerExit(.commandReturned)
                                await lossFence.wait(.waitPublication)
                                self.logWorkerExit(.fenceReturned)
                                try compatibility.checkpointWorkerWait(wait, claim: capture)
                            }
                        }
                    }
                    self.prepareObservations[arm.requestID] = observer
                    if selectedIO { workloadIOObservation = observer }
                    if ManagedPrepareCompatibilityProtocol.allowsPrepareSuccess(arm) { normalPrepareObservation = observer }
                    if ManagedPrepareCompatibilityProtocol.isEarlyCase(arm.caseName) { earlyPrepareObservation = observer }
                    if ManagedPrepareWorkerCheckpointProtocol.checkpointExitCut(arm.caseName),
                       !ManagedPrepareCompatibilityProtocol.isStorageCase(arm.caseName) { checkpointWorkerExitObservation = observer }
                }
            }
            _ = try await command(.mountPhase, .init(role: role == .prepare ? .prepare : .runtime))
        }, prepare: { intent in
            guard let shim else { throw Self.failure() }
            let ioClaim = RawContainerDirectIOHandles.containerGuestClaim(instanceID: container.instanceID, generation: shim.specification.generation)
            let response = try await command(.prepare, .init(workloadJSON: bytes, ioClaim: ioClaim))
            guard let prepare = response.prepare, let instance = response.containerInstance, let launch = response.launch,
                  let succeeded = response.succeeded, let clean = response.cleanCopyUp,
                  let evidence = response.evidenceDigest else { throw Self.failure() }
            guard prepare == intent.prepare, instance == intent.containerInstance, launch == intent.launch,
                  succeeded, clean else { throw Self.failure() }
            if let normalPrepareObservation {
                // Only normal success joins durable host publication before any
                // runtime activation. Errors use the existing quarantine path.
                // A7 never joins/cancels its observer or releases the held owner.
                try await normalPrepareObservation.value
                try await check(shim)
            }
            try await consumeIOClaim(shim, ioClaim)
            try await check(shim)
            return .init(prepare: prepare, containerInstance: instance, launch: launch,
                succeeded: succeeded, cleanCopyUp: clean, evidenceDigest: evidence)
        }, closePrepare: { _ in
            self.closingPrepareAttachments.formUnion(prepareAttachments)
            return try await command(.closePhase, .init(role: .prepare)).clean == true
        }, start: { _ in
            guard !selectedIO else { throw Self.failure() } // an IO arm never publishes a running container
            let response = try await command(.start)
            guard response.status == "running" else { throw Self.failure() }
        }, beforePublication: { _ in
            guard let shim else { throw Self.failure() }
            try await check(shim); published = try await beforePublication(shim); try await check(shim)
        })
        do {
            if let replacement {
                _ = try await lifecycle.replace(replacement.predecessor, with: plan, permit: replacement.permit, guest: guest)
            } else {
                _ = try await lifecycle.start(plan, guest: guest)
            }
        } catch {
            // Natural A6 failure can precede its parent's exit request. Join the
            // bounded storage rendezvous before closing its claim gate. Once
            // selected, only genuine Wait and serviceLost can finish that task.
            if let storageCheckpointExitObservation { _ = await storageCheckpointExitObservation.result }
            // Once this catch resumes on MainActor, disallow further pump claims.
            // A pump scheduled before this catch may already have claimed/dispatched
            // the action; that selected failure must still await its genuine loss fence.
            workerExitAllowed = false
            if let workerExitLossFence { await workerExitLossFence.wait(.startFailure) }
            // Lifecycle has already quarantined/drained the failed start. Stop
            // the exact authenticated VM (not the shim process) before joining:
            // pre-mount failure may otherwise leave an observer waiting forever.
            // The shim retains early/IO evidence independently of the stopped VM.
            if let observation = workloadIOObservation ?? earlyPrepareObservation ?? authorityIOObservation ?? checkpointWorkerExitObservation, let shim {
                try? await Self.joinFailedPrepareObservation(observation) {
                    _ = try await shim.stop()
                }
            }
            // Authority IO also stops only this workload VM, never the storage
            // VM. Its retained RPC/pump has an absolute deadline even if stop
            // fails; a missed checkpoint cannot mask the original start error.
            throw error
        }
        // A8 has now executed actual production Retire/retry. Never join the
        // A4/A5 held witness ahead of externally authorized release.
        if let successfulStorageObservation { try await successfulStorageObservation.value }
        // RTM098: a claimed generic checkpoint exit must have published its Wait
        // and completed the genuine serviceLost fence before the start may conclude.
        if let checkpointWorkerExitObservation { try await checkpointWorkerExitObservation.value }
        try requireGeneration(epoch)
        guard let published, let shim, let configured else { throw Self.failure() }
        // Retain the actual configure receipt and installed certificate hashes,
        // only after production mounted/runtime-running publication succeeds.
        installedOriginalRuntimes[container.id] = .init(shim: shim, boot: configured, credentials: runtimeCredentials)
        if let compatibility, let claim = try compatibility.publicTakeoverArmCapture(
            container: container.id, instance: container.instanceID.uuidString.lowercased()) {
            try await armPublicTakeoverOriginal(claim, shim: shim, compatibility: compatibility, check: check)
        }
        if pendingFreshGetattr[container.id] != nil {
            guard let compatibility else { throw Self.failure() }
            try await attestFreshGetattr(container: container.id, shim: shim, compatibility: compatibility, check: check)
        }
        return published
    }

    /// Independent pre-restart Arm: no replacement request, retirement or Begin.
    /// The live shim, not this daemon/child, owns the unbegun observation.
    private func armPublicTakeoverOriginal(_ claim: ManagedPrepareCompatibilityQueue.PublicTakeoverArmClaim,
        shim: VMShimClient, compatibility: ManagedPrepareCompatibilityCoordinator,
        check: @escaping @Sendable (VMShimClient?) async throws -> Void) async throws {
        typealias O = OriginalConsumerObservationProtocol
        let request = claim.request, epoch = generation
        guard pendingFreshGetattr[request.container] == nil,
              let installed = installedOriginalRuntimes[request.container], installed.shim === shim,
              let scope = installed.boot.scope else { throw Self.failure() }
        func current() throws -> ManagedPrepareCompatibilityProtocol.Credential {
            try requireGeneration(epoch); try requireReconciled()
            try owner.validatePublicTakeoverArm(request)
            guard scope.store == request.store, scope.serviceEpoch == request.serviceEpoch,
                  scope.controllerEpoch == request.epoch, scope.container == request.container,
                  scope.containerInstance == request.containerInstance,
                  let intent = try owner.journalSnapshot().intents.first(where: { $0.id == scope.intent }) else { throw Self.failure() }
            return try Self.selectOriginalRuntimeCredential(caseName: .sameEExistingData,
                scope: scope, credentials: installed.credentials, intent: intent)
        }
        let credential = try current()
        func binding(_ digest: String) -> O.Binding {
            .init(requestID: request.requestID, armDigest: digest, operationUUID: request.operationUUID,
                caseName: .sameEExistingData, generation: shim.specification.generation,
                boot: installed.boot.binding, scope: scope, targetAttachment: credential.attachment,
                key: credential.key, certificateSHA256: credential.certificateSHA256)
        }
        struct Candidate: Encodable {
            let request: ManagedPrepareCompatibilityQueue.PublicTakeoverArmCapture
            let binding: O.Binding
        }
        let seed = Candidate(request: request, binding: binding(String(repeating: "0", count: 64)))
        let selected = binding(Wire.specificationDigest(try ManagedPrepareCompatibilityProtocol.canonicalData(seed)))
        var releaseJoined = false
        try await PublicTakeoverArmScheduling.run(arm: {
            try await check(shim); guard try current() == credential else { throw Self.failure() }
            try compatibility.publicTakeoverArmPublish(try ManagedPrepareCompatibilityProtocol.canonicalData(
                Candidate(request: request, binding: selected)), phase: "candidate", claim: claim)
            return try await shim.originalConsumerArm(selected, boot: installed.boot)
        }, publish: { observation in
            try await check(shim); guard try current() == credential else { throw Self.failure() }
            try compatibility.publicTakeoverArmPublish(try ManagedPrepareCompatibilityProtocol.canonicalData(
                observation.evidence), phase: "armed", claim: claim)
            let registry = try await owner.publicTakeoverRegistryEvidence(request)
            try await check(shim); guard try current() == credential else { throw Self.failure() }
            try compatibility.publicTakeoverArmPublish(registry, phase: "registry", claim: claim)
            if request.isolationCase != nil {
                let proof = try await owner.probeServiceIsolation(request, original: selected)
                try await check(shim); guard try current() == credential else { throw Self.failure() }
                try compatibility.publicTakeoverArmPublish(try ManagedPrepareCompatibilityProtocol.canonicalData(proof), phase: "isolation", claim: claim)
                let positive = try await shim.recoverOriginalPositive(selected)
                releaseJoined = true
                try await check(shim); guard try current() == credential else { throw Self.failure() }
                try compatibility.publicTakeoverArmPublish(try ManagedPrepareCompatibilityProtocol.canonicalData(positive), phase: "positive", claim: claim)
                try compatibility.publicTakeoverArmPublish(try ManagedPrepareCompatibilityProtocol.canonicalData(positive.released), phase: "released", claim: claim)
            } else if request.positiveOnly == true {
                let released = try await observation.release()
                releaseJoined = true
                try await check(shim); guard try current() == credential else { throw Self.failure() }
                try compatibility.publicTakeoverArmPublish(released, phase: "released", claim: claim)
            }
        }, release: { observation in if !releaseJoined { _ = try await observation.release() } })
    }

    /// No caller can supply a fresh binding or positive. This runs only after
    /// real replacement containment/reconcile, and fresh mounted publication.
    private func attestFreshGetattr(container: String, shim: VMShimClient,
        compatibility: ManagedPrepareCompatibilityCoordinator,
        check: @escaping @Sendable (VMShimClient?) async throws -> Void) async throws {
        typealias O = OriginalConsumerObservationProtocol
        guard var pending = pendingFreshGetattr[container], !pending.attempted,
              let installed = installedOriginalRuntimes[container], installed.shim === shim,
              let scope = installed.boot.scope else { throw Self.failure() }
        pending.attempted = true; pendingFreshGetattr[container] = pending
        let epoch = generation, service = try owner.workloadSession().service.ready
        func current() throws {
            try requireGeneration(epoch); try requireReconciled()
            guard installedOriginalRuntimes[container]?.shim === shim,
                  installedOriginalRuntimes[container]?.boot.binding == installed.boot.binding,
                  let intent = try owner.journalSnapshot().intents.first(where: { $0.id == scope.intent }),
                  intent.phase == .running, Self.scope(intent) == scope,
                  intent.slots.contains(where: { $0.role == "runtime" && $0.volume == pending.volume && $0.receipt == nil }),
                  try owner.workloadSession().service.ready == service else { throw Self.failure() }
            try Self.validateOriginalService(service, scope: scope, peer: installed.boot.configuredPeer)
            if let previous = pending.rootResult {
                guard let pair = previous.baseline.rootPair,
                      installedOriginalRuntimes[container]?.credentials == installed.credentials,
                      Set(intent.slots.filter { $0.role == "runtime" }.map(\.volume)) == Set(pair.map(\.volume)) else { throw Self.failure() }
                _ = try Self.selectOriginalRuntimeCredential(caseName: .crossMountRootGrant, scope: scope,
                    credentials: installed.credentials, intent: intent)
            }
        }
        var observation: VMShimClient.OriginalConsumerObservation?
        var releaseJoined = false
        do {
            try current(); try await check(shim); try current()
            guard let intent = try owner.journalSnapshot().intents.first(where: { $0.id == scope.intent }) else { throw Self.failure() }
            let freshCase: O.Case = pending.rootResult == nil ? .sameEExistingData : .crossMountRootGrant
            let credential = try Self.selectOriginalRuntimeCredential(caseName: freshCase,
                scope: scope, credentials: installed.credentials, intent: intent)
            let binding = O.Binding(requestID: pending.original.requestID, armDigest: pending.original.armDigest,
                operationUUID: pending.original.operationUUID, caseName: freshCase,
                generation: shim.specification.generation, boot: installed.boot.binding, scope: scope,
                targetAttachment: credential.attachment, key: credential.key, certificateSHA256: credential.certificateSHA256)
            let armed = try await shim.originalConsumerArm(binding, boot: installed.boot)
            observation = armed
            try current(); try await check(shim); try current()
            let evidence = armed.evidence
            if pending.rootResult != nil {
                guard let currentIntent = try owner.journalSnapshot().intents.first(where: { $0.id == scope.intent }) else { throw Self.failure() }
                try Self.validateOriginalRootCredentials(binding, positive: evidence, credentials: installed.credentials,
                    intent: currentIntent, retirement: nil)
            }
            _ = try await armed.release()
            releaseJoined = true
            try current(); try await check(shim); try current()
            if let previous = pending.rootResult {
                let proof = OriginalConsumerRuntimeCarrier.FreshRootRead(original: pending.original, binding: binding,
                    service: .init(serviceEpoch: service.serviceEpoch, workerUUID: service.workerUUID),
                    serverDERSHA256: Wire.specificationDigest(service.serverDER), evidence: evidence, released: true)
                try proof.validate(previous: previous)
                try compatibility.originalPublish(proof, phase: .freshRootRead, claim: pending.claim)
            } else {
                let proof = OriginalConsumerRuntimeCarrier.FreshGetattr(original: pending.original, binding: binding,
                    service: .init(serviceEpoch: service.serviceEpoch, workerUUID: service.workerUUID),
                    serverDERSHA256: Wire.specificationDigest(service.serverDER), evidence: evidence, released: true)
                try proof.validate(original: pending.original)
                try compatibility.originalPublish(proof, phase: .freshGetattr, claim: pending.claim)
            }
            // The pinned queue retains the one-shot terminal proof. Only a new
            // real replacement may schedule a later fresh observation.
            pendingFreshGetattr.removeValue(forKey: container)
        } catch {
            let failure = error
            fenceOriginalConsumerFailure()
            // Retain installed shim/pending attempt if release or stop cannot join.
            // Failure is never exported as a fresh positive, and cannot be retried.
            return try await OriginalConsumerCleanup.run(operation: { throw failure },
                release: { if let observation, !releaseJoined { _ = try await observation.release() } },
                contain: { _ = try await shim.stop() })
        }
    }

    /// The exit is optional (other matrices use the same arms), but a late
    /// parent must get a bounded rendezvous after checkpoint publication. Nil
    /// is never Wait/death proof; selected claims use the separate loss fence.
    static func pollCheckpointWorkerExit(budget: Duration = .seconds(50),
        interval: Duration = .milliseconds(100), allowed: () -> Bool,
        claim: () throws -> ManagedPrepareWorkerCheckpointProtocol.WorkerCheckpointExit?) async throws
        -> ManagedPrepareWorkerCheckpointProtocol.WorkerCheckpointExit? {
        let clock = ContinuousClock(), deadline = ContinuousClock.now.advanced(by: budget)
        while allowed(), clock.now < deadline {
            try Task.checkCancellation()
            if let exit = try claim() { return exit }
            try await clock.sleep(until: min(clock.now.advanced(by: interval), deadline))
        }
        return nil
    }

    /// Containment ordering only. If authenticated stop fails, do not block the
    /// outer production rollback on an observer whose source may still be live.
    /// Neither observation failure nor a successful stop supplies drain evidence.
    static func joinFailedPrepareObservation(_ observation: Task<Void, Error>,
        contain: () async throws -> Void) async throws {
        try await contain()
        _ = await observation.result
    }

    /// Called only after VMShimClient authenticates the shim and checks the
    /// closed reply schema plus boot/scope/kind bindings. Never forward text,
    /// workload bytes, attachment IDs, credentials, or arbitrary server errors.
    nonisolated static func workloadCommandPayload(_ reply: Wire.Frame, kind: Wire.Kind,
                                                  role: Wire.Role?) throws -> Wire.Payload {
        if let code = reply.data.code {
            let phaseRole = role.map { " role=\($0.rawValue)" } ?? ""
            throw failure("private workload storage operation refused [operation=\(kind.rawValue)\(phaseRole) guest=\(code.rawValue)]")
        }
        return reply.data
    }

    static func workloadBytes(_ workload: GuestProtocol.Workload) throws -> Data {
        guard workload.ioClaim.isEmpty, workload.volumeServer == nil,
              workload.mounts.allSatisfy({ $0.managedAttachment == nil }) else { throw failure() }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(workload)
        guard bytes.count <= Wire.maximumWorkloadBytes else { throw failure("managed workload exceeds private frame limit") }
        return bytes
    }

    static func plan(container: ContainerRecord, launch: String, context: ManagedStorageControlClient.Context,
                     workload: GuestProtocol.Workload, serializedWorkload: Data? = nil) throws -> Journal.Intent {
        let bytes = try serializedWorkload ?? workloadBytes(workload)
        var slots: [Journal.Slot] = [], seen = Set<String>()
        let mounts = try workload.mounts.filter { $0.kind == "volume" && $0.device == nil }.map { mount in
            try Journal.uuid(mount.source)
            for (role, mode) in [("prepare", "read-write"), ("runtime", mount.readOnly ? "read-only" : "read-write")] {
                if seen.insert(mount.source + ":" + role + ":" + mode).inserted {
                    slots.append(.init(volume: mount.source, attachment: uuid(), role: role, mode: mode,
                        registerOperation: uuid(), retireOperation: uuid()))
                }
            }
            return Journal.Mount(volume: mount.source, destination: mount.destination,
                subpath: mount.subpath ?? "", mode: mount.readOnly ? "read-only" : "read-write")
        }
        guard !mounts.isEmpty, slots.count <= Wire.maximumSlots else { throw failure() }
        return .init(id: uuid(), store: context.store, container: container.id,
            containerInstance: container.instanceID.uuidString.lowercased(), launch: launch,
            specificationDigest: Wire.specificationDigest(bytes), serviceEpoch: context.serviceEpoch,
            controllerEpoch: context.controllerEpoch, controllerKey: context.controllerKey,
            prepare: uuid(), reserveOperation: uuid(), completeOperation: uuid(), replaceOperation: uuid(),
            mounts: mounts, slots: slots, version: 1, phase: .planned, prepareCompleted: false, cleanUnmount: false)
    }

    static func scope(_ intent: Journal.Intent) -> Wire.Scope {
        .init(intent: intent.id, store: intent.store, serviceEpoch: intent.serviceEpoch,
            controllerEpoch: intent.controllerEpoch, controllerKey: intent.controllerKey,
            container: intent.container, containerInstance: intent.containerInstance, launch: intent.launch,
            prepare: intent.prepare, specificationDigest: intent.specificationDigest)
    }
    private static func uuid() -> String { UUID().uuidString.lowercased() }

    /// A private authenticated disconnect is a hint, never mutation authority.
    /// Expected PREPARE close is settled by the in-flight coordinator's exact
    /// drain receipts; delayed hints for already-settled A do nothing.
    static func retirementTarget(attachment: String, intents: [Journal.Intent],
        closingPrepare: Set<String>) throws -> (container: String, launch: String)? {
        guard let intent = intents.first(where: { $0.slots.contains { $0.attachment == attachment } }),
              let slot = intent.slots.first(where: { $0.attachment == attachment }) else { throw failure() }
        if slot.receipt != nil || intent.isTerminal { return nil }
        if slot.role == "prepare", closingPrepare.contains(attachment) || intent.cleanUnmount || intent.prepareCompleted { return nil }
        return (intent.container, intent.launch)
    }

    func observeRetirements(_ affected: @escaping @Sendable (String, String) async -> Void,
        serviceLost: @escaping @Sendable () async -> Void) {
        guard notifications == nil, !maintenance, let lease = try? notificationWork.begin() else { return }
        let work = notificationWork
        let observedGeneration = generation
        notifications = Task { [weak self] in
            defer { work.end(lease) }
            while !Task.isCancelled {
                do { try await Task.sleep(for: .milliseconds(250)) } catch { return }
                guard let self, (try? work.require(lease)) != nil else { return }
                do {
                    let notices = try await owner.retirementNotifications()
                    try work.require(lease)
                    for notice in notices { try retirementHints.enqueue(notice.binding.attachment) }
                    // Containment suspends. Re-read receipt/launch evidence for
                    // every hint rather than reusing a now-stale batch snapshot.
                    while let target = try retirementHints.next(intents: owner.journalSnapshot().intents,
                        closingPrepare: closingPrepareAttachments) {
                        await affected(target.container, target.launch)
                        try work.require(lease)
                    }
                } catch ManagedStorageControlFailure.serviceUnavailable {
                    // Worker loss does not revoke the controller key owner. Keep
                    // explicit same-process replacement available, but freeze work.
                    guard !maintenance, (try? work.require(lease)) != nil else { return }
                    if !workerExitLossFences.isEmpty { logWorkerExit(.observerLost) }
                    workerUnavailable = true; reconciled = false; generation = UUID()
                    await serviceLost()
                    // The genuine worker-loss callback has now fenced the raw
                    // backend AND EngineRuntime lifecycle tokens. Never signal
                    // from a wait reply, cancellation, timeout or compatibility file.
                    completeWorkerExitLossFences(generation: observedGeneration)
                    guard (try? work.require(lease)) != nil else { return }
                    notifications = nil
                    return
                } catch ManagedStorageLifecycleOwner.Failure.blocked {
                    guard (try? work.require(lease)) != nil else { return }
                    continue // Retry on the same serialized workload channel.
                } catch {
                    // An ambiguous control error is not the completed serviceLost
                    // callback. Keep any selected compatibility loss fence held.
                    guard (try? work.require(lease)) != nil else { return }
                    if !workerExitLossFences.isEmpty { logWorkerExit(.observerFailed, error: error) }
                    let unresolved = (try? owner.journalSnapshot().intents) ?? []
                    reconciled = false // Unknown control state is a durable ownership fence.
                    await lifecycle.invalidate()
                    await owner.close()
                    guard (try? work.require(lease)) != nil else { return }
                    for intent in unresolved where !intent.isTerminal {
                        await affected(intent.container, intent.launch)
                        guard (try? work.require(lease)) != nil else { return }
                    }
                    return
                }
            }
        }
    }
}

/// Unsupported managed-storage operation, rejected before any side effect.
struct RawManagedStorageUnsupported: Error, Equatable, CustomStringConvertible, LocalizedError {
    let operation: String
    var description: String { "managed storage does not support \(operation)" }
    var errorDescription: String? { description }
}

#endif

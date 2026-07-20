import CEngineCore
import Darwin
import Foundation

public struct ResourceUpdateIntentRecord: Codable, Sendable {
    public enum TransactionPhase: String, Codable, Sendable {
        case prepared
        case backendApplied
    }

    public let containerID: String
    public let originalPhase: ContainerPhase
    public let old: ContainerRecord
    public let desired: ContainerRecord
    public var phase: TransactionPhase

    public init(
        containerID: String,
        originalPhase: ContainerPhase,
        old: ContainerRecord,
        desired: ContainerRecord,
        phase: TransactionPhase
    ) {
        self.containerID = containerID
        self.originalPhase = originalPhase
        self.old = old
        self.desired = desired
        self.phase = phase
    }
}

public struct EngineSnapshot: Codable, Sendable {
    public var containers: [ContainerRecord]
    public var networks: [NetworkRecord]
    public var volumes: [VolumeRecord]
    public var images: [ImageRecord]
    /// Container executions that crossed, or may have crossed, a backend
    /// launch boundary without durably publishing the resulting generation.
    /// Optional so snapshots written before launch-intent tracking still load.
    public var cleanupPendingContainerIDs: Set<String>?
    /// Containers whose metadata must not survive verified backend removal.
    /// Optional so snapshots written before removal-intent tracking still load.
    public var removalPendingContainerIDs: Set<String>?
    /// Removal intents that also include anonymous-volume deletion.
    /// Kept separate from the required removal fence so Docker's `v=0`
    /// semantics remain recoverable across a daemon restart.
    public var removalVolumesPendingContainerIDs: Set<String>?
    /// Immutable container incarnation owned by cleanup/removal fences.
    public var containerFenceInstanceIDs: [String: UUID]?
    /// Resource mutations are journaled before the backend is touched. An
    /// unresolved entry is a durable recovery fence: startup must reapply the
    /// old resources or contain the execution before accepting it.
    public var resourceUpdateIntents: [ResourceUpdateIntentRecord]?

    public init(
        containers: [ContainerRecord] = [], networks: [NetworkRecord] = [], volumes: [VolumeRecord] = [],
        images: [ImageRecord] = [], cleanupPendingContainerIDs: Set<String>? = nil,
        removalPendingContainerIDs: Set<String>? = nil,
        removalVolumesPendingContainerIDs: Set<String>? = nil,
        containerFenceInstanceIDs: [String: UUID]? = nil,
        resourceUpdateIntents: [ResourceUpdateIntentRecord]? = nil
    ) {
        self.containers = containers
        self.networks = networks
        self.volumes = volumes
        self.images = images
        self.cleanupPendingContainerIDs = cleanupPendingContainerIDs
        self.removalPendingContainerIDs = removalPendingContainerIDs
        self.removalVolumesPendingContainerIDs = removalVolumesPendingContainerIDs
        let fenced = (cleanupPendingContainerIDs ?? [])
            .union(removalPendingContainerIDs ?? [])
            .union(removalVolumesPendingContainerIDs ?? [])
        let derived = Dictionary(uniqueKeysWithValues: containers.compactMap { record in
            fenced.contains(record.id) ? (record.id, record.instanceID) : nil
        })
        self.containerFenceInstanceIDs = containerFenceInstanceIDs ?? (derived.isEmpty ? nil : derived)
        self.resourceUpdateIntents = resourceUpdateIntents
    }
}

public struct ContainerWaitSubscription: Sendable {
    public let stream: AsyncStream<Int32>

    init(stream: AsyncStream<Int32>) { self.stream = stream }
}

public enum ImagePruneScope: Equatable, Sendable {
    case dangling
    case allUnused
}

public enum VolumePruneScope: Equatable, Sendable {
    case anonymous
    case allUnused
}

public actor EngineRuntime {
    private struct LandedResourceCommitCouldNotBeReconfirmed: Error {
        let underlying: Error
    }

    private struct ResourceCommitStateCouldNotBeClassified: Error {
        let underlying: Error
    }

    private struct LandedRemovalCommitCouldNotBeReconfirmed: Error {
        let underlying: Error
    }

    private struct RemovalCommitStateCouldNotBeClassified: Error {
        let underlying: Error
    }

    private enum AmbiguousSnapshotReload: Error {
        case unavailable(
            ambiguity: AtomicStorePersistenceAmbiguousError,
            reloadFailure: Error
        )
    }

    private struct CanonicalSnapshotPersistenceUnavailable: Error, LocalizedError, Sendable {
        let detail: String

        var errorDescription: String? {
            "canonical engine state is unavailable; refusing to overwrite it: \(detail)"
        }
    }

    private struct ConcurrentSnapshotReconciliationFailed: Error, LocalizedError, Sendable {
        let detail: String

        var errorDescription: String? {
            "concurrent engine state could not be reconciled after an ambiguous save: \(detail)"
        }
    }

    private enum ResourceCommitReconciliation {
        case desired
        case old
        case unknown
    }

    private enum RemovalCommitReconciliation {
        case absent
        case fencedOld
        case unknown
    }

    private struct LifecycleIntent: Equatable {
        enum Operation: Equatable { case start, stop, restart, remove, update, pause, resume, rename, network }

        let operation: Operation
        let token = UUID()
    }

    private struct RemovalPublicationReservation {
        let containerID: String
        let containerInstanceID: UUID
        let containerName: String
        let volumeNames: Set<String>
    }

    var snapshot: EngineSnapshot {
        didSet { snapshotRevision &+= 1 }
    }
    private var snapshotRevision: UInt64 = 0
    private let store: AtomicStore<EngineSnapshot>
    private let endpointAllocationStore: AtomicStore<[String: Int]>
    private let beforePersistence: (@Sendable () async throws -> Void)?
    private let beforeEndpointAllocationPersistence: (@Sendable () async throws -> Void)?
    private let beforeCompletionMonitoring: (@Sendable () async -> Void)?
    let backend: any ContainerBackend
    private var endpointAllocationCursors: [String: Int]
    private var execs: [String: ExecRecord] = [:]
    private var eventContinuations: [UUID: AsyncStream<RuntimeEvent>.Continuation] = [:]
    private var eventHistory: [RuntimeEvent] = []
    private var healthTasks: [String: Task<Void, Never>] = [:]
    private var completionMonitorTasks: [String: (token: UUID, task: Task<Void, Never>)] = [:]
    private var exitWaiters: [String: [UUID: AsyncStream<Int32>.Continuation]] = [:]
    private var removalWaiters: [String: [UUID: AsyncStream<Int32>.Continuation]] = [:]
    private var lifecycleIntents: [String: LifecycleIntent] = [:]
    private var pendingContainerNames: [String: String] = [:]
    private var pendingContainerIDs = Set<String>()
    private var pendingContainerInstances: [String: UUID] = [:]
    private var pendingVolumeNames: [String: Int] = [:]
    private var pendingContainers: [String: ContainerRecord] = [:]
    private var startingContainerIDs = Set<String>()
    private var startingExecIDs = Set<String>()
    private var activeExecOperations: [String: Int] = [:]
    /// `EngineRuntime` is reentrant across the persistence hook and atomic-store
    /// await. Serialize every snapshot write so resource journal phases and
    /// unrelated saves have one total order.
    private var persistenceActive = false
    private var persistenceWaiters: [CheckedContinuation<Void, Never>] = []
    /// Once an ambiguity reload cannot classify the canonical state, this
    /// actor may continue containing already-started backend work but must
    /// never publish another snapshot from its stale in-memory selection.
    private var canonicalSnapshotUnavailableDetail: String?

    public init(root: URL, backend: any ContainerBackend = MetadataOnlyBackend()) async throws {
        try await self.init(
            root: root,
            backend: backend,
            beforePersistence: nil,
            beforeEndpointAllocationPersistence: nil,
            beforeCompletionMonitoring: nil,
            atomicStoreSaveBoundaryHook: nil
        )
    }

    init(
        root: URL,
        backend: any ContainerBackend,
        beforePersistence: (@Sendable () async throws -> Void)? = nil,
        beforeEndpointAllocationPersistence: (@Sendable () async throws -> Void)? = nil,
        beforeCompletionMonitoring: (@Sendable () async -> Void)? = nil,
        atomicStoreSaveBoundaryHook: (@Sendable (AtomicStoreSaveBoundary) throws -> Void)? = nil
    ) async throws {
        let root = try Self.canonicalDataRoot(root)
        self.store = AtomicStore(
            url: root.appending(path: "engine.json"),
            saveBoundaryHook: atomicStoreSaveBoundaryHook
        )
        self.endpointAllocationStore = AtomicStore(url: root.appending(path: "endpoint-allocation.json"))
        self.beforePersistence = beforePersistence
        self.beforeEndpointAllocationPersistence = beforeEndpointAllocationPersistence
        self.beforeCompletionMonitoring = beforeCompletionMonitoring
        self.backend = backend
        self.endpointAllocationCursors = [:]
        self.snapshot = try await store.load(default: EngineSnapshot())
        try Self.validateEngineSnapshotInvariants(snapshot)
        // Explicit remove/prune publishes this intent before crossing backend
        // teardown. Resolve it before generic cleanup or restart policy so a
        // container whose backend was already deleted can never be resurrected.
        try await resolvePendingContainerRemovals()
        // Resolve resource journals before generic execution recovery. A
        // recovered running shim is not trusted until the old durable resource
        // selection has been reapplied successfully.
        try await resolvePendingResourceUpdates()
        // A cleanup-pending marker is written before every backend launch
        // boundary. It is the first recovered state: no other backend await may
        // trust or mutate the persisted execution until teardown is verified.
        let pendingCleanup = snapshot.cleanupPendingContainerIDs ?? []
        var verifiedCleanupIDs = Set<String>()
        if !pendingCleanup.isEmpty {
            for identifier in pendingCleanup {
                guard let index = try? containerIndex(identifier) else {
                    throw EngineError(
                        .internalError,
                        "backend cleanup is pending for missing container record \(identifier)"
                    )
                }
                let pending = snapshot.containers[index]
                do {
                    try await cleanupBackendExecution(pending)
                } catch {
                    quarantineCleanupPendingContainer(identifier)
                    try? await persist()
                    throw error
                }
                verifiedCleanupIDs.insert(identifier)
                switch pending.phase {
                case .running, .paused:
                    snapshot.containers[index].phase = .exited
                    snapshot.containers[index].finishedAt = pending.finishedAt ?? Date()
                    snapshot.containers[index].exitCode = pending.exitCode ?? 137
                case .dead where pending.startedAt == nil:
                    snapshot.containers[index].phase = .created
                    snapshot.containers[index].finishedAt = nil
                    snapshot.containers[index].exitCode = nil
                case .dead:
                    snapshot.containers[index].phase = .exited
                    snapshot.containers[index].finishedAt = pending.finishedAt ?? Date()
                    snapshot.containers[index].exitCode = pending.exitCode ?? 127
                case .created, .exited:
                    break
                }
                clearCleanupPending(identifier)
            }
            // Do not proceed to restore networks or another policy-driven
            // launch until the safe phase and cleared marker are durable.
            try await persist()
        }
        self.endpointAllocationCursors = try await endpointAllocationStore.load(default: [:])
        let persistedNetworks = Dictionary(uniqueKeysWithValues: snapshot.networks.map { ($0.id, $0) })
        self.snapshot.networks = try await backend.restoreNetworks(snapshot.networks)
        let remappedNetworkIDs = Set(snapshot.networks.compactMap { network -> String? in
            guard let old = persistedNetworks[network.id],
                  old.subnet != network.subnet || old.ipv6Subnet != network.ipv6Subnet else { return nil }
            return network.id
        })
        if !remappedNetworkIDs.isEmpty {
            endpointAllocationCursors = endpointAllocationCursors.filter {
                !remappedNetworkIDs.contains(Self.networkID(fromAllocationCursorKey: $0.key))
            }
            for container in snapshot.containers.indices {
                for endpoint in snapshot.containers[container].networks.indices
                    where remappedNetworkIDs.contains(snapshot.containers[container].networks[endpoint].networkID) {
                    if !snapshot.containers[container].networks[endpoint].ipv4AddressIsStatic {
                        snapshot.containers[container].networks[endpoint].ipv4Address = nil
                    }
                    if !snapshot.containers[container].networks[endpoint].ipv6AddressIsStatic {
                        snapshot.containers[container].networks[endpoint].ipv6Address = nil
                    }
                }
            }
        }
        if !snapshot.networks.contains(where: { $0.name == "default" }) {
            snapshot.networks.append(try await backend.createNetwork(NetworkRecord(
                id: "cengine-default-network", name: "default", subnet: "", gateway: ""
            )))
        }
        let defaultNetworkID = snapshot.networks.first(where: { $0.name == "default" })?.id
        if let defaultNetworkID {
            for index in snapshot.containers.indices
                where snapshot.containers[index].networks.isEmpty && snapshot.containers[index].networkDisabled != true {
                snapshot.containers[index].networks = [.init(networkID: defaultNetworkID)]
            }
        }
        try await backend.cleanupOrphans(keeping: Set(snapshot.containers.map(\.id)))
        // `.dead` is a durable quarantine for an execution whose cleanup could
        // not be verified. It must never be treated as an inert record: a
        // backend process may still be live even though no monitor survived the
        // previous daemon. Refuse to finish recovery until definitive deletion
        // succeeds; stop is best-effort diagnostic context for delete failure.
        for index in snapshot.containers.indices where snapshot.containers[index].phase == .dead {
            let quarantined = snapshot.containers[index]
            do {
                try await cleanupBackendExecution(quarantined)
            } catch {
                try? await persist()
                throw error
            }
            verifiedCleanupIDs.insert(quarantined.id)
            if quarantined.startedAt == nil {
                snapshot.containers[index].phase = .created
                snapshot.containers[index].finishedAt = nil
                snapshot.containers[index].exitCode = nil
            } else {
                snapshot.containers[index].phase = .exited
                snapshot.containers[index].finishedAt = quarantined.finishedAt ?? Date()
                snapshot.containers[index].exitCode = quarantined.exitCode ?? 127
            }
        }
        // Remove records that were already terminal before recovery before
        // considering restart policy. Cleanup itself publishes a durable fence.
        verifiedCleanupIDs = try await removeRecoveredAutoRemoveContainers(
            verifiedCleanupIDs: verifiedCleanupIDs
        )
        var recovered: [(String, Date)] = []
        for index in snapshot.containers.indices {
            let stale = snapshot.containers[index]
            if stale.phase == .running || stale.phase == .paused {
                let recovery = (try? await backend.recover(stale)) ?? .unavailable
                switch recovery {
                case .running, .paused:
                    snapshot.containers[index].phase = recovery == .paused ? .paused : .running
                    let startedAt = snapshot.containers[index].startedAt ?? Date()
                    snapshot.containers[index].startedAt = startedAt
                    recovered.append((stale.id, startedAt))
                    continue
                case .exited(let code):
                    snapshot.containers[index].exitCode = code
                case .unavailable:
                    snapshot.containers[index].exitCode = 137
                }
                snapshot.containers[index].phase = .exited
                snapshot.containers[index].finishedAt = Date()
                guard !stale.autoRemove else { continue }
                guard Self.shouldRestart(stale, exitCode: snapshot.containers[index].exitCode ?? 137) else { continue }
            } else {
                guard stale.phase == .exited, stale.restartPolicy.name == "always" else { continue }
            }
            var launchAttempted = false
            do {
                var restarted = snapshot.containers[index]
                restarted.restartCount += 1
                try await backend.prepare(restarted)
                markCleanupPending(restarted.id)
                do {
                    try await persist()
                } catch {
                    clearCleanupPending(restarted.id)
                    throw error
                }
                launchAttempted = true
                restarted.ports = try await backend.start(restarted)
                restarted.phase = .running; restarted.exitCode = nil; restarted.finishedAt = nil
                let addresses = await backend.endpointAddresses(for: restarted)
                for endpoint in restarted.networks.indices {
                    guard let address = addresses[restarted.networks[endpoint].networkID] else { continue }
                    restarted.networks[endpoint].ipv4Address = Self.nonEmptyBackendAddress(address.ipv4Address)
                    restarted.networks[endpoint].ipv6Address = Self.nonEmptyBackendAddress(address.ipv6Address)
                }
                let startedAt = Date(); restarted.startedAt = startedAt
                snapshot.containers[index] = restarted
                clearCleanupPending(restarted.id)
                try await persist()
                recovered.append((restarted.id, startedAt))
            } catch {
                guard launchAttempted else {
                    snapshot.containers[index].phase = .dead
                    snapshot.containers[index].exitCode = 127
                    continue
                }
                markCleanupPending(stale.id)
                do {
                    try await cleanupBackendExecution(snapshot.containers[index])
                } catch {
                    quarantineCleanupPendingContainer(stale.id)
                    try? await persist()
                    throw error
                }
                snapshot.containers[index].phase = .exited
                snapshot.containers[index].finishedAt = Date()
                snapshot.containers[index].exitCode = 127
                clearCleanupPending(stale.id)
                do {
                    try await persist()
                } catch {
                    markCleanupPending(stale.id)
                    throw error
                }
            }
        }
        // A running auto-remove record can become terminal only after backend
        // recovery. Remove it now, before any later startup work can publish or
        // restart that generation.
        verifiedCleanupIDs = try await removeRecoveredAutoRemoveContainers(
            verifiedCleanupIDs: verifiedCleanupIDs
        )
        if let backendImages = try await backend.listImages() {
            snapshot.images = Self.imageRecords(from: backendImages)
        }
        for index in snapshot.containers.indices where snapshot.containers[index].phase == .created {
            do {
                try await backend.prepare(snapshot.containers[index])
            } catch {
                snapshot.containers[index].phase = .dead
                snapshot.containers[index].exitCode = 127
                snapshot.containers[index].finishedAt = Date()
            }
        }
        try await persist()
        for (id, startedAt) in recovered {
            startCompletionMonitor(id, startedAt: startedAt)
            startHealthMonitor(id)
        }
    }

    private static func canonicalDataRoot(_ requested: URL) throws -> URL {
        let standardized = requested.standardizedFileURL
        try FileManager.default.createDirectory(
            at: standardized, withIntermediateDirectories: true
        )
        return standardized.resolvingSymlinksInPath().standardizedFileURL
    }

    public func shutdown() async {
        healthTasks.values.forEach { $0.cancel() }
        healthTasks.removeAll()
        completionMonitorTasks.values.forEach { $0.task.cancel() }
        completionMonitorTasks.removeAll()
        await backend.shutdown()
    }

    public func listContainers(all: Bool) -> [ContainerRecord] {
        snapshot.containers.filter {
            !startingContainerIDs.contains($0.id) && (all || $0.phase == .running || $0.phase == .paused)
        }
            .sorted { $0.createdAt > $1.createdAt }
    }

    public func container(_ identifier: String) throws -> ContainerRecord {
        let matches = snapshot.containers.filter {
            $0.id == identifier || $0.name == identifier.normalizedContainerName || $0.id.hasPrefix(identifier)
        }
        guard matches.count == 1, let value = matches.first else {
            throw EngineError(.notFound, matches.isEmpty ? "No such container: \(identifier)" : "container identifier is ambiguous: \(identifier)")
        }
        return value
    }

    @discardableResult
    public func createContainer(_ input: ContainerRecord) async throws -> ContainerRecord {
        try requireCanonicalSnapshotWritable()
        var record = input.withFreshInstanceID()
        guard Identifier.validateName(record.name) else { throw EngineError(.badRequest, "invalid container name: \(record.name)") }
        if let conflictingID = pendingContainerNames[record.name]
            ?? snapshot.containers.first(where: { $0.name == record.name || $0.id == record.id })?.id
            ?? resourceUpdateReservation(for: record)
            ?? (pendingContainerIDs.contains(record.id) ? record.id : nil) {
            throw Self.containerNameConflict(name: record.name, conflictingID: conflictingID)
        }
        try Self.validatePortProtocols(record.ports)
        pendingContainerNames[record.name] = record.id
        pendingContainerIDs.insert(record.id)
        defer {
            pendingContainerNames.removeValue(forKey: record.name)
            pendingContainerIDs.remove(record.id)
            pendingContainers.removeValue(forKey: record.id)
        }
        if record.networks.isEmpty, record.networkDisabled != true,
           let network = snapshot.networks.first(where: { $0.name == "default" }) {
            record.networks = [.init(networkID: network.id)]
        }
        record = try normalizingEndpointConfiguration(record)
        try validateEndpoints(record)
        record = try allocatingEndpointAddresses(to: record)
        pendingContainers[record.id] = record
        try await persistEndpointAllocationCursors()
        try await backend.prepare(record)
        if let backendImages = try await backend.listImages() {
            snapshot.images = Self.imageRecords(from: backendImages)
        }
        if let image = try? image(record.image) {
            if let platform = try? OCIPlatform(record.platform) {
                let selected = image.manifests.first {
                    $0.kind == .image && $0.available && $0.platform?.matches(platform) == true
                }
                record.imageID = selected?.imageID ?? image.id
                record.imageManifestDescriptor = selected?.descriptor
            }
        }
        snapshot.containers.append(record)
        try await backend.updateNetworkRecords(snapshot.containers)
        try await persist()
        emit(containerEvent("create", record))
        return record
    }

    private static func containerNameConflict(name: String, conflictingID: String) -> EngineError {
        EngineError(
            .conflict,
            "Conflict. The container name \"/\(name)\" is already in use by container \"\(conflictingID)\". "
                + "You have to remove (or rename) that container to be able to reuse that name."
        )
    }

    public func startContainer(_ identifier: String) async throws {
        try requireCanonicalSnapshotWritable()
        let index = try containerIndex(identifier)
        let record = snapshot.containers[index]
        try requireBackendExecutionAvailable(record)
        guard lifecycleIntents[record.id] == nil else {
            throw EngineError(.conflict, "container \(identifier) has a lifecycle operation in progress")
        }
        guard !cleanupIsPending(record.id) else {
            throw EngineError(.conflict, "container \(identifier) has backend cleanup pending")
        }
        guard record.phase != .running else { return }
        let intent = try beginLifecycleIntent(.start, for: record.id)
        guard startingContainerIDs.insert(record.id).inserted else {
            endLifecycleIntent(intent, for: record.id)
            throw EngineError(.conflict, "container \(identifier) is already starting")
        }
        do {
            if record.phase == .dead {
                try await backend.delete(record)
                guard ownsLifecycleExecution(intent, record: record) else {
                    throw EngineError(.conflict, "container was removed or changed while it was starting")
                }
            }
            try await backend.prepare(record)
            guard ownsLifecycleExecution(intent, record: record) else {
                throw EngineError(.conflict, "container was removed or changed while it was starting")
            }
            markCleanupPending(record.id)
            do {
                try await persist()
            } catch {
                clearCleanupPending(record.id)
                throw error
            }
            guard ownsLifecycleExecution(intent, record: record) else {
                clearCleanupPending(record.id)
                try await persist()
                throw EngineError(.conflict, "container was removed or changed while it was starting")
            }
            let resolvedPorts: [PortBinding]
            do {
                resolvedPorts = try await backend.start(record)
            } catch {
                // `start` may fail after installing a partially-running backend
                // execution. Preparation failures have not crossed that boundary
                // and remain available for a later retry, but every attempted
                // start must reset both the execution and its preparation.
                let startError = error
                try await rollbackFailedStart(original: record, started: record)
                throw startError
            }
            guard ownsLifecycleExecution(intent, record: record),
                  let current = try? containerIndex(record.id) else {
                try await rollbackFailedStart(original: record, started: record)
                throw EngineError(.conflict, "container was removed or changed while it was starting")
            }

            var started = snapshot.containers[current]
            started.phase = .running
            started.ports = resolvedPorts
            let startedAt = Date()
            started.startedAt = startedAt
            started.finishedAt = nil
            started.exitCode = nil
            started = await applyingEndpointAddresses(to: started)
            guard ownsLifecycleExecution(intent, record: record),
                  let current = try? containerIndex(record.id) else {
                try await rollbackFailedStart(original: record, started: started)
                throw EngineError(.conflict, "container was removed or changed while it was starting")
            }
            snapshot.containers[current] = started
            clearCleanupPending(record.id)
            do {
                try await persist()
            } catch {
                let persistenceError = error
                try await rollbackFailedStart(original: record, started: started)
                throw persistenceError
            }
            guard lifecycleIntents[record.id] == intent,
                  let published = try? container(record.id),
                  published.phase == .running,
                  published.startedAt == startedAt else {
                try await rollbackFailedStart(original: record, started: started)
                throw EngineError(.conflict, "container was removed or changed while it was starting")
            }
            emit(containerEvent("start", published))
            startHealthMonitor(record.id)
            startCompletionMonitor(record.id, startedAt: startedAt)
            startingContainerIDs.remove(record.id)
            endLifecycleIntent(intent, for: record.id)
            await reconcileDeferredCompletion(record.id)
        } catch {
            startingContainerIDs.remove(record.id)
            endLifecycleIntent(intent, for: record.id)
            await reconcileDeferredCompletion(record.id)
            throw error
        }
    }

    public func containerIO(_ identifier: String) async throws -> ContainerIOBridge {
        let record = try container(identifier)
        try requireBackendExecutionAvailable(record)
        return try await backend.io(for: record)
    }

    public func resizeContainer(_ identifier: String, width: UInt16, height: UInt16) async throws {
        try requireCanonicalSnapshotWritable()
        let record = try container(identifier)
        try requireBackendExecutionAvailable(record)
        try await backend.resize(record, width: width, height: height)
    }

    public func containerLogs(_ identifier: String, options: DockerLogOptions = .init()) async throws -> Data {
        try await backend.logs(for: container(identifier), options: options)
    }

    public func containerStatistics(_ identifier: String) async throws -> BackendStatistics {
        let record = try container(identifier)
        try requireBackendExecutionAvailable(record)
        guard record.phase == .running else { throw EngineError(.conflict, "Container is not running") }
        return try await backend.statistics(record)
    }

    public func containerTop(_ identifier: String, arguments: [String]) async throws -> (titles: [String], processes: [[String]]) {
        let record = try container(identifier)
        try requireBackendExecutionAvailable(record)
        guard record.phase == .running else { throw EngineError(.conflict, "Container is not running") }
        return try await backend.top(record, arguments: arguments)
    }

    public func updateContainer(_ identifier: String, memoryBytes: Int64?, nanoCPUs: Int64?,
                                pidsLimit: Int64?, restartPolicy: RestartPolicyRecord?,
                                blockIOReadBps: [BlockIOThrottleDeviceRecord]? = nil,
                                blockIOWriteBps: [BlockIOThrottleDeviceRecord]? = nil,
                                blockIOReadIOps: [BlockIOThrottleDeviceRecord]? = nil,
                                blockIOWriteIOps: [BlockIOThrottleDeviceRecord]? = nil) async throws -> ContainerRecord {
        try requireCanonicalSnapshotWritable()
        let index = try containerIndex(identifier)
        let old = snapshot.containers[index]
        try requireBackendExecutionAvailable(old)
        guard !startingContainerIDs.contains(old.id) else {
            throw EngineError(.conflict, "container \(identifier) is starting")
        }
        let intent = try beginLifecycleIntent(.update, for: old.id)
        do {
            var updated = old
            if let memoryBytes, memoryBytes > 0 { updated.memoryBytes = UInt64(memoryBytes) }
            if let nanoCPUs, nanoCPUs > 0 { updated.cpus = max(1, Int((nanoCPUs + 999_999_999) / 1_000_000_000)) }
            if let pidsLimit { updated.pidsLimit = pidsLimit }
            if let restartPolicy { updated.restartPolicy = restartPolicy }
            if let blockIOReadBps { updated.blockIOReadBps = blockIOReadBps }
            if let blockIOWriteBps { updated.blockIOWriteBps = blockIOWriteBps }
            if let blockIOReadIOps { updated.blockIOReadIOps = blockIOReadIOps }
            if let blockIOWriteIOps { updated.blockIOWriteIOps = blockIOWriteIOps }
            let resourcesChanged = old.memoryBytes != updated.memoryBytes || old.cpus != updated.cpus
                || old.pidsLimit != updated.pidsLimit
                || old.blockIOReadBps != updated.blockIOReadBps
                || old.blockIOWriteBps != updated.blockIOWriteBps
                || old.blockIOReadIOps != updated.blockIOReadIOps
                || old.blockIOWriteIOps != updated.blockIOWriteIOps
            if resourcesChanged {
                let resourceIntent = ResourceUpdateIntentRecord(
                    containerID: old.id,
                    originalPhase: old.phase,
                    old: old,
                    desired: updated,
                    phase: .prepared
                )
                // The old public record and the full reconciliation intent are
                // durable before the backend can observe the desired resources.
                try await persistInstallingResourceIntent(resourceIntent)
                do {
                    try await backend.updateResources(updated)
                } catch let error as BackendResourceRollbackIncompleteError {
                    let containmentFailure = await containTaintedResourceUpdate(old)
                    throw Self.taintedResourceUpdateError(
                        cause: error, containmentFailure: containmentFailure
                    )
                } catch {
                    let updateError = error
                    do {
                        // A non-structured backend failure promises its own
                        // rollback completed. Clear the journal only through a
                        // durable old-state transition.
                        try await persistResourceRollback(containerID: old.id, old: old)
                    } catch {
                        throw EngineError(
                            .internalError,
                            "resource update failed: \(EngineError.message(for: updateError)); "
                                + "old resource journal could not be cleared: \(EngineError.message(for: error))"
                        )
                    }
                    throw updateError
                }
                do {
                    try await persistResourceIntentPhase(.backendApplied, containerID: old.id)
                } catch {
                    try await rollbackResourceUpdateAfterPersistenceFailure(
                        old: old,
                        persistenceError: error
                    )
                }
            }
            guard let current = try? containerIndex(old.id) else {
                throw EngineError(.conflict, "container \(identifier) was removed while it was being updated")
            }
            var merged = snapshot.containers[current]
            if let memoryBytes, memoryBytes > 0 { merged.memoryBytes = UInt64(memoryBytes) }
            if let nanoCPUs, nanoCPUs > 0 {
                merged.cpus = max(1, Int((nanoCPUs + 999_999_999) / 1_000_000_000))
            }
            if let pidsLimit { merged.pidsLimit = pidsLimit }
            if let restartPolicy { merged.restartPolicy = restartPolicy }
            if let blockIOReadBps { merged.blockIOReadBps = blockIOReadBps }
            if let blockIOWriteBps { merged.blockIOWriteBps = blockIOWriteBps }
            if let blockIOReadIOps { merged.blockIOReadIOps = blockIOReadIOps }
            if let blockIOWriteIOps { merged.blockIOWriteIOps = blockIOWriteIOps }
            do {
                let publishedRecord: ContainerRecord
                if resourcesChanged {
                    publishedRecord = try await persistResourceCommit(
                        containerID: old.id,
                        desired: merged
                    )
                } else {
                    publishedRecord = try await persistContainerUpdate(
                        containerID: old.id,
                        desired: merged
                    )
                }
                emit(containerEvent("update", publishedRecord))
                endLifecycleIntent(intent, for: old.id)
                await reconcileDeferredCompletion(old.id)
                return publishedRecord
            } catch {
                if resourcesChanged {
                    if let uncertain = error as? LandedResourceCommitCouldNotBeReconfirmed {
                        throw uncertain.underlying
                    }
                    if let unclassified = error as? ResourceCommitStateCouldNotBeClassified {
                        let containmentFailure = await containUnclassifiedResourceUpdate(old)
                        let outcome = containmentFailure.map {
                            "containment failed: \($0)"
                        } ?? "workload was contained"
                        throw EngineError(
                            .internalError,
                            "resource update durable state could not be classified: "
                                + "\(EngineError.message(for: unclassified.underlying)); \(outcome)"
                        )
                    }
                    try await rollbackResourceUpdateAfterPersistenceFailure(
                        old: old, persistenceError: error
                    )
                }
                throw error
            }
        } catch {
            endLifecycleIntent(intent, for: old.id)
            await reconcileDeferredCompletion(old.id)
            throw error
        }
    }

    public func killContainer(_ identifier: String, signal: String) async throws {
        try requireCanonicalSnapshotWritable()
        let record = try container(identifier)
        try requireBackendExecutionAvailable(record)
        guard !startingContainerIDs.contains(record.id) else {
            throw EngineError(.conflict, "container \(identifier) is starting")
        }
        guard record.phase == .running else { throw EngineError(.conflict, "Container \(identifier) is not running") }
        try await backend.kill(record, signal: signal)
        emit(containerEvent("kill", record, extra: ["signal": signal]))
        let normalized = signal.uppercased()
        if normalized == "KILL" || normalized == "SIGKILL", let startedAt = record.startedAt {
            let code = try await backend.wait(record)
            await recordCompletion(record.id, startedAt: startedAt, code: code)
        }
    }

    public func pauseContainer(_ identifier: String) async throws {
        try requireCanonicalSnapshotWritable()
        let index = try containerIndex(identifier)
        let record = snapshot.containers[index]
        try requireBackendExecutionAvailable(record)
        guard !startingContainerIDs.contains(record.id) else {
            throw EngineError(.conflict, "container \(identifier) is starting")
        }
        guard record.phase == .running else {
            throw EngineError(.conflict, "Container \(identifier) is not running")
        }
        let intent = try beginLifecycleIntent(.pause, for: record.id)
        do {
            try await backend.pause(record)
            guard ownsLifecycleExecution(intent, record: record) else {
                throw EngineError(.conflict, "container \(identifier) changed state while it was being paused")
            }
            let current = try containerIndex(record.id)
            snapshot.containers[current].phase = .paused
            let paused = snapshot.containers[current]
            try await persist()
            emit(containerEvent("pause", paused))
            endLifecycleIntent(intent, for: record.id)
            await reconcileDeferredCompletion(record.id)
        } catch {
            endLifecycleIntent(intent, for: record.id)
            await reconcileDeferredCompletion(record.id)
            throw error
        }
    }

    public func resumeContainer(_ identifier: String) async throws {
        try requireCanonicalSnapshotWritable()
        let index = try containerIndex(identifier)
        let record = snapshot.containers[index]
        try requireBackendExecutionAvailable(record)
        guard !startingContainerIDs.contains(record.id) else {
            throw EngineError(.conflict, "container \(identifier) is starting")
        }
        guard record.phase == .paused else {
            throw EngineError(.conflict, "Container \(identifier) is not paused")
        }
        let intent = try beginLifecycleIntent(.resume, for: record.id)
        do {
            try await backend.resume(record)
            guard ownsLifecycleExecution(intent, record: record) else {
                throw EngineError(.conflict, "container \(identifier) changed state while it was being resumed")
            }
            let current = try containerIndex(record.id)
            snapshot.containers[current].phase = .running
            let resumed = snapshot.containers[current]
            try await persist()
            emit(containerEvent("unpause", resumed))
            endLifecycleIntent(intent, for: record.id)
            await reconcileDeferredCompletion(record.id)
        } catch {
            endLifecycleIntent(intent, for: record.id)
            await reconcileDeferredCompletion(record.id)
            throw error
        }
    }

    public func restartContainer(_ identifier: String, timeoutSeconds: Int? = nil) async throws {
        try requireCanonicalSnapshotWritable()
        let index = try containerIndex(identifier)
        let record = snapshot.containers[index]
        try requireBackendExecutionAvailable(record)
        guard activeExecOperations[record.id, default: 0] == 0 else {
            throw EngineError(.conflict, "container \(identifier) has an exec operation in progress")
        }
        guard !cleanupIsPending(record.id) else {
            throw EngineError(.conflict, "container \(identifier) has backend cleanup pending")
        }
        guard record.phase == .running || record.phase == .paused else {
            try await startContainer(identifier)
            return
        }
        let intent = try beginLifecycleIntent(.restart, for: record.id)
        guard startingContainerIDs.insert(record.id).inserted else {
            endLifecycleIntent(intent, for: record.id)
            throw EngineError(.conflict, "container \(identifier) is already starting")
        }
        markCleanupPending(record.id)
        do {
            try await persist()
        } catch {
            clearCleanupPending(record.id)
            startingContainerIDs.remove(record.id)
            endLifecycleIntent(intent, for: record.id)
            throw error
        }
        guard ownsRestartExecution(intent, record: record) else {
            clearCleanupPending(record.id)
            do {
                try await persist()
            } catch {
                startingContainerIDs.remove(record.id)
                endLifecycleIntent(intent, for: record.id)
                throw error
            }
            startingContainerIDs.remove(record.id)
            endLifecycleIntent(intent, for: record.id)
            throw EngineError(.conflict, "container was removed or changed while it was restarting")
        }
        do {
            try await backend.restart(record, timeoutSeconds: timeoutSeconds ?? record.stopTimeoutSeconds)
            guard ownsRestartExecution(intent, record: record) else {
                throw EngineError(.conflict, "container was removed or changed while it was restarting")
            }
            // The backend has replaced the old execution. A health check that
            // began against that generation must not publish into the new one.
            if let task = healthTasks.removeValue(forKey: record.id) {
                task.cancel()
            }
            cancelCompletionMonitor(record.id)
            // A restart creates a new container execution generation. Terminalize
            // every child of the old generation before publishing the new start
            // time; its completion monitor may still be suspended in the backend.
            await reconcileExecs(for: record.id)
            guard ownsRestartExecution(intent, record: record),
                  let current = try? containerIndex(record.id) else {
                throw EngineError(.conflict, "container was removed or changed while it was restarting")
            }

            var restarted = snapshot.containers[current]
            restarted.phase = .running
            let startedAt = Date()
            restarted.startedAt = startedAt
            restarted.finishedAt = nil
            restarted.exitCode = nil
            restarted.restartCount += 1
            let addresses = await backend.endpointAddresses(for: restarted)
            guard ownsRestartExecution(intent, record: record),
                  let current = try? containerIndex(record.id) else {
                throw EngineError(.conflict, "container was removed or changed while it was restarting")
            }

            // Re-resolve after the backend suspension and merge only fields the
            // restart owns. Health, metadata, resource, and network mutations
            // committed by other actor work must survive this publication.
            restarted = snapshot.containers[current]
            restarted.phase = .running
            restarted.startedAt = startedAt
            restarted.finishedAt = nil
            restarted.exitCode = nil
            restarted.restartCount += 1
            for endpoint in restarted.networks.indices {
                guard let address = addresses[restarted.networks[endpoint].networkID] else { continue }
                restarted.networks[endpoint].ipv4Address = Self.nonEmptyBackendAddress(address.ipv4Address)
                restarted.networks[endpoint].ipv6Address = Self.nonEmptyBackendAddress(address.ipv6Address)
            }
            snapshot.containers[current] = restarted
            clearCleanupPending(record.id)
            try await persist()
            guard lifecycleIntents[record.id] == intent,
                  let published = try? container(record.id),
                  published.phase == .running,
                  published.startedAt == startedAt else {
                throw EngineError(.conflict, "container was removed or changed while it was restarting")
            }
            emit(containerEvent("restart", published))
            startHealthMonitor(record.id)
            startCompletionMonitor(record.id, startedAt: startedAt)
            startingContainerIDs.remove(record.id)
            endLifecycleIntent(intent, for: record.id)
            await reconcileDeferredCompletion(record.id)
        } catch {
            let restartError = error
            do {
                try await terminalizeFailedRestart(record, intent: intent)
            } catch {
                startingContainerIDs.remove(record.id)
                endLifecycleIntent(intent, for: record.id)
                await reconcileDeferredCompletion(record.id)
                throw error
            }
            startingContainerIDs.remove(record.id)
            endLifecycleIntent(intent, for: record.id)
            await reconcileDeferredCompletion(record.id)
            throw restartError
        }
    }

    public func createExec(container identifier: String, configuration: ExecConfiguration) async throws -> ExecRecord {
        try requireCanonicalSnapshotWritable()
        let container = try container(identifier)
        try requireBackendExecutionAvailable(container)
        guard container.phase == .running else { throw EngineError(.conflict, "Container \(identifier) is not running") }
        guard !configuration.arguments.isEmpty else { throw EngineError(.badRequest, "exec command cannot be empty") }
        try beginExecOperation(for: container.id)
        defer { endExecOperation(for: container.id) }
        let exec = ExecRecord(
            containerID: container.id,
            containerInstanceID: container.instanceID,
            configuration: configuration
        )
        do {
            _ = try await backend.prepareExec(exec, container: container)
            guard let current = try? self.container(container.id),
                  current.phase == .running,
                  current.startedAt == container.startedAt else {
                throw EngineError(
                    .conflict,
                    "container \(identifier) changed execution generation while the exec was being prepared"
                )
            }
            execs[exec.id] = exec
            return exec
        } catch {
            await backend.discardExec(exec)
            throw error
        }
    }

    public func exec(_ identifier: String) throws -> ExecRecord {
        guard let exec = execs[identifier] else { throw EngineError(.notFound, "No such exec instance: \(identifier)") }
        return exec
    }

    public func inspectExec(_ identifier: String) async throws -> ExecRecord {
        var value = try exec(identifier)
        if value.running {
            try requireBackendExecutionAvailable(container(value.containerID))
            if let code = await backend.execStatus(value) {
                let refreshedPID = await backend.execPID(value)
                if var current = execs[identifier], current.exitCode == nil {
                    current.running = false
                    current.exitCode = code
                    if refreshedPID > 0 { current.pid = refreshedPID }
                    execs[identifier] = current
                    await backend.retireExec(current)
                }
                value = try exec(identifier)
            }
        }
        return value
    }

    public func execIO(_ identifier: String) async throws -> ContainerIOBridge {
        let value = try exec(identifier)
        try requireBackendExecutionAvailable(container(value.containerID))
        return try await backend.execIO(value)
    }

    public func startExec(_ identifier: String) async throws {
        try requireCanonicalSnapshotWritable()
        var exec = try exec(identifier)
        guard !exec.running, exec.exitCode == nil else { throw EngineError(.conflict, "exec instance has already run") }
        try beginExecOperation(for: exec.containerID)
        defer { endExecOperation(for: exec.containerID) }
        guard startingExecIDs.insert(identifier).inserted else {
            throw EngineError(.conflict, "exec instance is already starting")
        }
        defer { startingExecIDs.remove(identifier) }
        do {
            try await backend.startExec(exec)
        } catch let contained as BackendExecStartContainedError {
            // A crossed start boundary is never retryable. The backend has
            // selected a terminal result and retired (or durably quarantined)
            // the exact guest resources, so publish that result before
            // returning the original start failure to Docker.
            if var current = execs[identifier], current.exitCode == nil {
                current.running = false
                current.exitCode = contained.exitCode
                execs[identifier] = current
            }
            if contained.containerTerminated,
               let owner = try? container(exec.containerID) {
                await recordCompletion(
                    owner.id, startedAt: owner.startedAt, code: 137
                )
            }
            throw contained
        } catch let quarantined as BackendExecStartQuarantinedError {
            if var current = execs[identifier], current.exitCode == nil {
                current.running = false
                current.exitCode = quarantined.exitCode
                execs[identifier] = current
            }
            throw quarantined
        }
        guard execs[identifier]?.exitCode == nil,
              let container = try? container(exec.containerID), container.phase == .running else {
            throw EngineError(.conflict, "container stopped while exec instance was starting")
        }
        exec.running = true
        execs[identifier] = exec
        let pid = await backend.execPID(exec)
        if pid > 0 { execs[identifier]?.pid = pid }
        Task { [weak self] in await self?.monitorExec(identifier) }
    }

    public func startAttachedExec(_ identifier: String) async throws -> CInt? {
        try requireCanonicalSnapshotWritable()
        var exec = try exec(identifier)
        guard !exec.running, exec.exitCode == nil else {
            throw EngineError(.conflict, "exec instance has already run")
        }
        try beginExecOperation(for: exec.containerID)
        defer { endExecOperation(for: exec.containerID) }
        guard startingExecIDs.insert(identifier).inserted else {
            throw EngineError(.conflict, "exec instance is already starting")
        }
        defer { startingExecIDs.remove(identifier) }
        guard let descriptor = try await backend.startAttachedExec(exec) else { return nil }
        guard execs[identifier]?.exitCode == nil,
              let container = try? container(exec.containerID), container.phase == .running else {
            Darwin.close(descriptor)
            throw EngineError(.conflict, "container stopped while exec instance was starting")
        }
        exec.running = true
        execs[identifier] = exec
        let pid = await backend.execPID(exec)
        if pid > 0 { execs[identifier]?.pid = pid }
        Task { [weak self] in await self?.monitorExec(identifier) }
        return descriptor
    }

    public func resizeExec(_ identifier: String, width: UInt16, height: UInt16) async throws {
        try requireCanonicalSnapshotWritable()
        let value = try exec(identifier)
        try requireBackendExecutionAvailable(container(value.containerID))
        try await backend.resizeExec(value, width: width, height: height)
    }

    public func stopContainer(_ identifier: String, timeoutSeconds: Int? = nil) async throws {
        try requireCanonicalSnapshotWritable()
        let index = try containerIndex(identifier)
        let record = snapshot.containers[index]
        try requireBackendExecutionAvailable(record)
        guard !startingContainerIDs.contains(record.id) else {
            throw EngineError(.conflict, "container \(identifier) is starting")
        }
        guard record.phase == .running || record.phase == .paused else { return }
        let intent = try beginLifecycleIntent(.stop, for: record.id)
        defer { endLifecycleIntent(intent, for: record.id) }
        guard record.phase == .running || record.phase == .paused else { return }
        let code = try await backend.stop(record, timeoutSeconds: timeoutSeconds ?? record.stopTimeoutSeconds)
        await recordCompletion(record.id, startedAt: record.startedAt, code: code)
    }

    public func waitContainer(_ identifier: String, condition: String? = nil) async throws -> Int32 {
        let subscription = try subscribeContainerWait(identifier, condition: condition)
        for await code in subscription.stream { return code }
        throw EngineError(.internalError, "container wait ended without a result")
    }

    public func subscribeContainerWait(_ identifier: String, condition: String? = nil) throws -> ContainerWaitSubscription {
        let index = try containerIndex(identifier)
        let record = snapshot.containers[index]
        switch condition ?? "not-running" {
        case "", "not-running":
            // Force removal publishes a terminal-looking `.dead` fence before
            // backend.stop returns. That fence is not an exit result: keep the
            // default wait attached until the removal path records the
            // backend's authoritative stop code (or a later retry does so).
            if snapshot.removalPendingContainerIDs?.contains(record.id) == true,
               record.exitCode == nil {
                return waitSubscription(containerID: record.id, removal: false)
            }
            guard record.phase == .running || record.phase == .paused else {
                return immediateWaitSubscription(code: record.exitCode ?? 0)
            }
            return waitSubscription(containerID: record.id, removal: false)
        case "next-exit":
            return waitSubscription(containerID: record.id, removal: false)
        case "removed":
            return waitSubscription(containerID: record.id, removal: true)
        default:
            throw EngineError(.badRequest, "unsupported wait condition: \(condition ?? "")")
        }
    }

    public func removeContainer(_ identifier: String, force: Bool, removeVolumes: Bool = false) async throws {
        try requireCanonicalSnapshotWritable()
        let index = try containerIndex(identifier)
        let removed = snapshot.containers[index]
        let intent = try beginLifecycleIntent(.remove, for: removed.id)
        defer { endLifecycleIntent(intent, for: removed.id) }
        if removed.phase == .running || removed.phase == .paused {
            guard force else { throw EngineError(.conflict, "You cannot remove a running container. Stop the container before attempting removal or force remove.") }
            // Force-stop is itself a destructive backend boundary. Publish the
            // complete removal intent first so a crash or a side-effecting
            // stop failure can only recover by finishing removal.
            snapshot.containers[index].phase = .dead
            markCleanupPending(removed.id)
            markRemovalPending(removed.id, removeVolumes: removeVolumes)
            do {
                try await persist()
            } catch {
                try? await persist()
                throw error
            }
            guard lifecycleIntents[removed.id] == intent,
                  snapshot.containers.contains(where: { $0.id == removed.id }) else {
                throw EngineError(.conflict, "container \(identifier) removal reservation was lost")
            }
            let code = try await backend.stop(removed, timeoutSeconds: 0)
            try await recordForcedRemovalStop(
                removed.id, startedAt: removed.startedAt, code: code, intent: intent
            )
        }
        try await removeClaimedContainer(removed.id, removeVolumes: removeVolumes, intent: intent)
    }

    private func removeClaimedContainer(
        _ identifier: String,
        removeVolumes: Bool,
        intent: LifecycleIntent
    ) async throws {
        guard lifecycleIntents[identifier] == intent else {
            throw EngineError(.conflict, "container \(identifier) removal reservation was lost")
        }
        guard (try? containerIndex(identifier)) != nil else { return }
        // Once `rm -v` is durable, a retry (including prune, which normally
        // does not remove volumes) must finish that original request.
        let effectiveRemoveVolumes = removeVolumes
            || snapshot.removalVolumesPendingContainerIDs?.contains(identifier) == true
        await reconcileExecs(for: identifier)
        guard lifecycleIntents[identifier] == intent,
              let fencedIndex = try? containerIndex(identifier) else {
            throw EngineError(.conflict, "container \(identifier) removal reservation was lost")
        }
        // Re-resolve after force-stop/reconciliation. The originally captured
        // running record may now have authoritative exit metadata.
        let removed = snapshot.containers[fencedIndex]
        snapshot.containers[fencedIndex].phase = .dead
        markCleanupPending(identifier)
        markRemovalPending(identifier, removeVolumes: effectiveRemoveVolumes)
        do {
            try await persist()
        } catch {
            // Never cross the backend boundary without a durable fence. Keep a
            // live-daemon quarantine and make one bounded durability retry.
            try? await persist()
            throw error
        }

        if let exitCode = removed.exitCode {
            resumeExitWaiters(identifier, code: exitCode)
        }
        healthTasks.removeValue(forKey: identifier)?.cancel()
        cancelCompletionMonitor(identifier)
        let removedVolumeMetadata = effectiveRemoveVolumes ? anonymousVolumeMetadata(usedBy: removed) : []
        let publicationReservation = reserveRemovalPublication(
            removed, removedVolumes: removedVolumeMetadata.map(\.element)
        )
        do {
            let cleanupCode = try await cleanupBackendExecution(
                removed, publishRemovalStopResult: true
            )
            if let current = try? containerIndex(identifier),
               snapshot.containers[current].exitCode == nil {
                // A failed stop followed by a successful definitive delete has
                // no backend exit result. Publish Docker's explicit forced
                // cleanup fallback only after deletion verifies teardown.
                let exitCode = cleanupCode ?? 137
                snapshot.containers[current].exitCode = exitCode
                snapshot.containers[current].finishedAt = Date()
                resumeExitWaiters(identifier, code: exitCode)
            }
            try await backend.deleteLogs(for: removed)
            if effectiveRemoveVolumes { try await removeAnonymousVolumes(usedBy: removed) }
        } catch {
            quarantineRemovalPendingContainer(
                identifier, record: removed, removeVolumes: effectiveRemoveVolumes
            )
            releaseRemovalPublication(publicationReservation)
            try? await persist()
            throw error
        }

        guard lifecycleIntents[identifier] == intent,
              let current = try? containerIndex(identifier) else {
            restoreRemovalQuarantine(
                removed, at: fencedIndex, removeVolumes: effectiveRemoveVolumes,
                removedVolumes: removedVolumeMetadata
            )
            releaseRemovalPublication(publicationReservation)
            throw EngineError(.conflict, "container \(identifier) removal reservation was lost")
        }
        do {
            let durableRemovalRecord = try await persistContainerRemovalCommit(
                expected: snapshot.containers[current]
            )
            releaseRemovalPublication(publicationReservation)
            resumeRemovalWaiters(identifier, code: durableRemovalRecord.exitCode ?? 0)
            emit(containerEvent("destroy", durableRemovalRecord))
        } catch let uncertain as LandedRemovalCommitCouldNotBeReconfirmed {
            // Backend teardown and the selected snapshot both say removed.
            // Do not resurrect stale metadata merely because the independent
            // durability reconfirmation also failed.
            releaseRemovalPublication(publicationReservation)
            throw uncertain.underlying
        } catch let unclassified as RemovalCommitStateCouldNotBeClassified {
            // Canonical state is unknown. Backend deletion is already final;
            // hide the stale record and retain the in-memory publication
            // reservation for this actor's lifetime. The poisoned persistence
            // gate prevents any stale snapshot from overwriting the unknown
            // canonical path, while the reservation prevents ID/name reuse.
            if let stale = snapshot.containers.firstIndex(where: {
                Self.resourceUpdateIdentityMatches($0, removed)
            }) {
                snapshot.containers.remove(at: stale)
            }
            throw unclassified.underlying
        } catch {
            restoreRemovedVolumeMetadata(removedVolumeMetadata)
            quarantineRemovalPendingContainer(
                identifier, record: removed, removeVolumes: effectiveRemoveVolumes
            )
            releaseRemovalPublication(publicationReservation)
            try? await persist()
            throw error
        }
    }

    public func renameContainer(_ identifier: String, name: String) async throws {
        try requireCanonicalSnapshotWritable()
        guard Identifier.validateName(name) else { throw EngineError(.badRequest, "invalid container name: \(name)") }
        let normalized = name.normalizedContainerName
        let index = try containerIndex(identifier)
        let record = snapshot.containers[index]
        try requireBackendExecutionAvailable(record)
        let intent = try beginLifecycleIntent(.rename, for: record.id)
        do {
            if let conflictingID = pendingContainerNames[normalized], conflictingID != record.id {
                throw Self.containerNameConflict(name: normalized, conflictingID: conflictingID)
            }
            if let conflicting = snapshot.containers.indices.first(where: {
                $0 != index && snapshot.containers[$0].name == normalized
            }) {
                throw Self.containerNameConflict(
                    name: normalized, conflictingID: snapshot.containers[conflicting].id
                )
            }
            snapshot.containers[index].name = normalized
            try await persist()
            let current = try containerIndex(record.id)
            emit(containerEvent("rename", snapshot.containers[current]))
            endLifecycleIntent(intent, for: record.id)
            await reconcileDeferredCompletion(record.id)
        } catch {
            endLifecycleIntent(intent, for: record.id)
            await reconcileDeferredCompletion(record.id)
            throw error
        }
    }

    public func listNetworks() -> [NetworkRecord] { snapshot.networks }
    public func listVolumes() -> [VolumeRecord] { snapshot.volumes }

    public func network(_ identifier: String) throws -> NetworkRecord {
        guard let value = snapshot.networks.first(where: { $0.id == identifier || $0.id.hasPrefix(identifier) || $0.name == identifier }) else {
            throw EngineError(.notFound, "network \(identifier) not found")
        }
        return value
    }

    public func volume(_ name: String) throws -> VolumeRecord {
        guard let value = snapshot.volumes.first(where: { $0.name == name }) else {
            throw EngineError(.notFound, "get \(name): no such volume")
        }
        return value
    }
    public func listImages() -> [ImageRecord] { snapshot.images }

    @discardableResult
    public func pullImage(_ reference: String, platform: String = "linux/arm64",
                          credentials: RegistryCredentials? = nil,
                          progress: @escaping ImagePullProgressHandler = { _ in }) async throws -> ImageRecord {
        try requireCanonicalSnapshotWritable()
        try await backend.pullImage(reference, platform: platform, credentials: credentials, progress: progress)
        let image: ImageRecord
        if let backendImages = try await backend.listImages() {
            snapshot.images = Self.imageRecords(from: backendImages)
            if let stored = snapshot.images.first(where: { $0.references.contains(reference) }) {
                image = stored
            } else {
                image = ImageRecord(
                    id: "sha256:\(Identifier.random())", references: [reference], createdAt: Date(), size: 0,
                    architecture: platform.hasSuffix("amd64") ? "amd64" : "arm64", os: "linux"
                )
                snapshot.images.append(image)
            }
        } else {
            image = ImageRecord(
                id: "sha256:\(Identifier.random())", references: [reference], createdAt: Date(), size: 0,
                architecture: platform.hasSuffix("amd64") ? "amd64" : "arm64", os: "linux"
            )
            snapshot.images.append(image)
        }
        try await persist()
        emitImageEvent(
            "pull",
            id: Self.familiarImageReference(reference),
            name: Self.familiarImageName(reference)
        )
        return image
    }

    public func image(_ identifier: String) throws -> ImageRecord {
        let normalized = ImageReference.normalized(identifier)
        guard let image = snapshot.images.first(where: {
            $0.id == identifier || $0.id.hasPrefix(identifier) || $0.references.contains(identifier) || $0.references.contains(normalized)
        }) else {
            throw EngineError(.notFound, "No such image: \(identifier)")
        }
        return image
    }

    public func imageHistory(_ identifier: String, platform: OCIPlatform? = nil) async throws -> (ImageRecord, [ImageHistoryEntry]) {
        let image = try image(identifier)
        guard let reference = image.references.first else { return (image, []) }
        return (image, try await backend.imageHistory(reference: reference, platform: platform))
    }

    @discardableResult
    public func removeImage(_ identifier: String, force: Bool, platforms: [OCIPlatform] = []) async throws -> [String] {
        try requireCanonicalSnapshotWritable()
        let image = try image(identifier)
        guard force || !snapshot.containers.contains(where: {
            $0.imageID == image.id || image.references.contains($0.image) || image.references.contains(ImageReference.normalized($0.image))
        }) else {
            throw EngineError(.conflict, "conflict: image is being used by a container")
        }
        let reference = image.references.first(where: {
            $0 == identifier || $0 == ImageReference.normalized(identifier)
        }) ?? identifier
        let removed: [String]
        if platforms.isEmpty {
            for storedReference in image.references { try await backend.deleteImage(reference: storedReference) }
            removed = [image.id]
        } else {
            removed = try await backend.deleteImage(reference: reference, platforms: platforms)
        }
        if let backendImages = try await backend.listImages() {
            snapshot.images = Self.imageRecords(from: backendImages)
        } else if platforms.isEmpty {
            snapshot.images.removeAll { $0.id == image.id }
        } else if let index = snapshot.images.firstIndex(where: { $0.id == image.id }) {
            for manifest in snapshot.images[index].manifests.indices where removed.contains(snapshot.images[index].manifests[manifest].descriptor.digest) {
                snapshot.images[index].manifests[manifest].available = false
            }
            snapshot.images[index].preferredManifestDigest = snapshot.images[index].manifests.first {
                $0.kind == .image && $0.available
            }?.descriptor.digest
        }
        try await persist()
        return removed
    }

    public func tagImage(_ identifier: String, reference: String) async throws {
        try requireCanonicalSnapshotWritable()
        let image = try image(identifier)
        let normalized = ImageReference.normalized(reference)
        guard let existing = image.references.first else { throw EngineError(.notFound, "No such image: \(identifier)") }
        try await backend.tagImage(existing: existing, new: normalized)
        if let backendImages = try await backend.listImages() {
            snapshot.images = Self.imageRecords(from: backendImages)
        } else if let index = snapshot.images.firstIndex(where: { $0.id == image.id }),
                  !snapshot.images[index].references.contains(normalized) {
            snapshot.images[index].references.append(normalized)
        }
        try await persist()
    }

    public func pushImage(_ identifier: String, platform: OCIPlatform? = nil, credentials: RegistryCredentials?) async throws {
        try requireCanonicalSnapshotWritable()
        let image = try image(identifier)
        let normalized = ImageReference.normalized(identifier)
        let reference = image.references.first(where: { $0 == identifier || $0 == normalized }) ?? normalized
        try await backend.pushImage(reference: reference, platform: platform, credentials: credentials)
    }

    public func saveImage(_ identifier: String, platforms: [OCIPlatform] = []) async throws -> Data {
        _ = try image(identifier)
        return try await backend.saveImages(references: [ImageReference.normalized(identifier)], platforms: platforms)
    }

    public func imageAttestations(
        _ identifier: String,
        platform: OCIPlatform?,
        predicateTypes: [String],
        includeStatement: Bool
    ) async throws -> [ImageAttestationRecord] {
        let image = try image(identifier)
        let normalized = ImageReference.normalized(identifier)
        let reference = image.references.first(where: { $0 == identifier || $0 == normalized })
            ?? image.references.first ?? normalized
        return try await backend.imageAttestations(
            reference: reference,
            platform: platform,
            predicateTypes: predicateTypes,
            includeStatement: includeStatement
        )
    }

    public func createNetwork(name: String, subnet: String? = nil, gateway: String? = nil,
                              ipv6Subnet: String? = nil, ipv6Gateway: String? = nil,
                              enableIPv4: Bool = true, enableIPv6: Bool = true,
                              driver: String? = nil, internalNetwork: Bool = false,
                              labels: [String: String] = [:], options: [String: String] = [:]) async throws -> NetworkRecord {
        try requireCanonicalSnapshotWritable()
        guard Identifier.validateName(name) else { throw EngineError(.badRequest, "invalid network name: \(name)") }
        guard enableIPv4 || enableIPv6 else {
            throw EngineError(.badRequest, "network must enable IPv4, IPv6, or both")
        }
        let selectedDriver = driver.flatMap { $0.isEmpty ? nil : $0 } ?? "bridge"
        guard selectedDriver == "bridge" || selectedDriver == "default" else {
            throw EngineError(.unsupported, "network driver \(selectedDriver) is not supported")
        }
        let gatewayModeOptions = [
            NetworkRecord.gatewayModeIPv4Option,
            NetworkRecord.gatewayModeIPv6Option,
        ]
        let supportedOptions = Set(gatewayModeOptions + [NetworkRecord.enableIPMasqueradeOption])
        if let option = options.keys.first(where: { !supportedOptions.contains($0) }) {
            throw EngineError(.unsupported, "bridge network option \(option) is not supported")
        }
        // Non-internal vmnet shared networks already provide Docker's requested masqueraded egress.
        if let value = options[NetworkRecord.enableIPMasqueradeOption], value != "true" {
            throw EngineError(
                .unsupported,
                "bridge network option \(NetworkRecord.enableIPMasqueradeOption)=\(value) is not supported"
            )
        }
        for key in gatewayModeOptions {
            guard let raw = options[key] else { continue }
            guard let mode = NetworkGatewayMode(rawValue: raw) else {
                throw EngineError(.badRequest, "invalid bridge gateway mode \(raw) for \(key)")
            }
            if mode == .isolated && !internalNetwork {
                throw EngineError(.badRequest, "bridge gateway mode isolated requires an internal network")
            }
        }
        let enabledGatewayModes = Set([
            enableIPv4 ? NetworkGatewayMode(rawValue: options[NetworkRecord.gatewayModeIPv4Option] ?? "nat") : nil,
            enableIPv6 ? NetworkGatewayMode(rawValue: options[NetworkRecord.gatewayModeIPv6Option] ?? "nat") : nil,
        ].compactMap { $0 })
        guard enabledGatewayModes.count <= 1 else {
            throw EngineError(
                .unsupported,
                "asymmetric IPv4 and IPv6 gateway modes are not supported by the vmnet fabric"
            )
        }
        let requestedSubnet = subnet ?? ""
        let requestedIPv6 = ipv6Subnet ?? ""
        if !enableIPv4, !requestedSubnet.isEmpty || gateway?.isEmpty == false {
            throw EngineError(.badRequest, "IPv4 addressing cannot be configured when IPv4 is disabled")
        }
        if !enableIPv6, !requestedIPv6.isEmpty || ipv6Gateway?.isEmpty == false {
            throw EngineError(.badRequest, "IPv6 addressing cannot be configured when IPv6 is disabled")
        }
        let ipv4 = try Self.normalizeNetworkAddressing(
            subnet: requestedSubnet, gateway: gateway ?? "", family: AF_INET
        )
        let ipv6 = try Self.normalizeNetworkAddressing(
            subnet: requestedIPv6, gateway: ipv6Gateway ?? "", family: AF_INET6
        )
        if let existing = snapshot.networks.first(where: { $0.name == name }) { return existing }
        let requested = NetworkRecord(
            id: Identifier.random(), name: name, createdAt: Date(), subnet: ipv4.subnet, gateway: ipv4.gateway,
            ipv6Subnet: ipv6.subnet, ipv6Gateway: ipv6.gateway,
            ipv4AllocationMode: subnet == nil ? .automatic : .explicit,
            ipv6AllocationMode: ipv6Subnet == nil ? .automatic : .explicit,
            enableIPv4: enableIPv4, enableIPv6: enableIPv6,
            internalNetwork: internalNetwork, labels: labels, options: options
        )
        let record = try await backend.createNetwork(requested)
        snapshot.networks.append(record)
        do { try await persist() }
        catch { try? await backend.deleteNetwork(record); snapshot.networks.removeAll { $0.id == record.id }; throw error }
        return record
    }

    public func removeNetwork(_ identifier: String) async throws {
        try requireCanonicalSnapshotWritable()
        guard let index = snapshot.networks.firstIndex(where: { $0.id == identifier || $0.id.hasPrefix(identifier) || $0.name == identifier }) else {
            throw EngineError(.notFound, "network \(identifier) not found")
        }
        guard snapshot.networks[index].name != "default" else {
            throw EngineError(.conflict, "default is a pre-defined network and cannot be removed")
        }
        let networkID = snapshot.networks[index].id
        guard !(snapshot.containers + Array(pendingContainers.values)).contains(where: { container in
            container.networks.contains { $0.networkID == networkID }
        }) else {
            throw EngineError(.conflict, "network \(snapshot.networks[index].name) has active endpoints")
        }
        let removed = snapshot.networks.remove(at: index)
        try await backend.deleteNetwork(removed)
        try await persist()
    }

    public func connectNetwork(_ networkIdentifier: String, container containerIdentifier: String,
                               aliases: [String] = [], ipv4Address: String? = nil,
                               ipv6Address: String? = nil, macAddress: String? = nil,
                               gatewayPriority: Int? = nil,
                               driverOptions: [String: String]? = nil) async throws {
        try requireCanonicalSnapshotWritable()
        let network = try network(networkIdentifier)
        let index = try containerIndex(containerIdentifier)
        let record = snapshot.containers[index]
        try requireBackendExecutionAvailable(record)
        guard !startingContainerIDs.contains(record.id) else {
            throw EngineError(.conflict, "container \(containerIdentifier) is starting")
        }
        guard record.phase != .running && record.phase != .paused else {
            throw EngineError(.conflict, "cannot connect a network while container \(record.name) is running")
        }
        let intent = try beginLifecycleIntent(.network, for: record.id)
        var attemptedNetworks: [NetworkEndpointRecord]?
        do {
            guard !record.networks.contains(where: { $0.networkID == network.id }) else {
                endLifecycleIntent(intent, for: record.id)
                return
            }
            try validateStaticEndpointModes(
                network: network, ipv4IsStatic: ipv4Address != nil, ipv6IsStatic: ipv6Address != nil
            )
            try Self.validateEndpointDriverOptions(driverOptions)
            let normalizedMac = try macAddress.map(Self.normalizeMacAddress)
            var updated = record
            updated.networks.append(.init(
                networkID: network.id, aliases: aliases, ipv4Address: ipv4Address,
                ipv6Address: ipv6Address, ipv4AddressIsStatic: ipv4Address != nil,
                ipv6AddressIsStatic: ipv6Address != nil, macAddress: normalizedMac,
                gatewayPriority: gatewayPriority, driverOptions: driverOptions
            ))
            updated = try normalizingEndpointConfiguration(updated)
            try validateEndpoints(updated)
            updated = try allocatingEndpointAddresses(to: updated)
            attemptedNetworks = updated.networks
            snapshot.containers[index] = updated
            try await persistEndpointAllocationCursors()
            guard ownsNetworkMutation(intent, record: record, networks: updated.networks) else {
                throw EngineError(.conflict, "container \(containerIdentifier) changed while its network was being connected")
            }
            try validateEndpoints(updated)
            try await backend.updateNetworkRecords(snapshot.containers)
            guard ownsNetworkMutation(intent, record: record, networks: updated.networks) else {
                throw EngineError(.conflict, "container \(containerIdentifier) changed while its network was being connected")
            }
            try await persist()
            endLifecycleIntent(intent, for: record.id)
            await reconcileDeferredCompletion(record.id)
        } catch {
            if let attemptedNetworks,
               lifecycleIntents[record.id] == intent,
               let current = try? containerIndex(record.id),
               snapshot.containers[current].networks == attemptedNetworks {
                snapshot.containers[current].networks = record.networks
                try? await backend.updateNetworkRecords(snapshot.containers)
            }
            endLifecycleIntent(intent, for: record.id)
            await reconcileDeferredCompletion(record.id)
            throw error
        }
    }

    public func disconnectNetwork(_ networkIdentifier: String, container containerIdentifier: String, force: Bool) async throws {
        try requireCanonicalSnapshotWritable()
        let network = try network(networkIdentifier)
        let index = try containerIndex(containerIdentifier)
        let record = snapshot.containers[index]
        try requireBackendExecutionAvailable(record)
        guard !startingContainerIDs.contains(record.id) else {
            throw EngineError(.conflict, "container \(containerIdentifier) is starting")
        }
        guard record.phase != .running && record.phase != .paused else {
            throw EngineError(.conflict, "cannot disconnect a network while container \(record.name) is running")
        }
        let intent = try beginLifecycleIntent(.network, for: record.id)
        var attemptedNetworks: [NetworkEndpointRecord]?
        do {
            guard record.networks.contains(where: { $0.networkID == network.id }) else {
                endLifecycleIntent(intent, for: record.id)
                if force { return }
                throw EngineError(.notFound, "container is not connected to network \(network.name)")
            }
            var updated = record
            updated.networks.removeAll { $0.networkID == network.id }
            attemptedNetworks = updated.networks
            snapshot.containers[index] = updated
            try await backend.updateNetworkRecords(snapshot.containers)
            guard ownsNetworkMutation(intent, record: record, networks: updated.networks) else {
                throw EngineError(.conflict, "container \(containerIdentifier) changed while its network was being disconnected")
            }
            try await persist()
            endLifecycleIntent(intent, for: record.id)
            await reconcileDeferredCompletion(record.id)
        } catch {
            if let attemptedNetworks,
               lifecycleIntents[record.id] == intent,
               let current = try? containerIndex(record.id),
               snapshot.containers[current].networks == attemptedNetworks {
                snapshot.containers[current].networks = record.networks
                try? await backend.updateNetworkRecords(snapshot.containers)
            }
            endLifecycleIntent(intent, for: record.id)
            await reconcileDeferredCompletion(record.id)
            throw error
        }
    }

    public func pruneNetworks(identifiers: Set<String>? = nil) async throws -> [String] {
        try requireCanonicalSnapshotWritable()
        let used = Set(
            (snapshot.containers + Array(pendingContainers.values)).flatMap(\.networks).map(\.networkID)
        )
        let removable: (NetworkRecord) -> Bool = {
            $0.name != "default" && !used.contains($0.id) && (identifiers?.contains($0.id) ?? true)
        }
        let removed = snapshot.networks.filter(removable)
        snapshot.networks.removeAll(where: removable)
        for network in removed { try await backend.deleteNetwork(network) }
        try await persist()
        return removed.map(\.name)
    }

    public func pruneContainers(ids: Set<String>? = nil) async throws -> [String] {
        try requireCanonicalSnapshotWritable()
        let candidates = snapshot.containers.filter {
            $0.phase != .running && $0.phase != .paused
                && !startingContainerIDs.contains($0.id)
                && lifecycleIntents[$0.id] == nil
                && (ids?.contains($0.id) ?? true)
        }
        var claims: [(record: ContainerRecord, intent: LifecycleIntent)] = []
        for candidate in candidates {
            guard let current = try? containerIndex(candidate.id),
                  snapshot.containers[current].phase != .running,
                  snapshot.containers[current].phase != .paused,
                  !startingContainerIDs.contains(candidate.id),
                  lifecycleIntents[candidate.id] == nil else { continue }
            claims.append((snapshot.containers[current], try beginLifecycleIntent(.remove, for: candidate.id)))
        }
        defer {
            for claim in claims { endLifecycleIntent(claim.intent, for: claim.record.id) }
        }
        var removed: [String] = []
        for claim in claims {
            try await removeClaimedContainer(claim.record.id, removeVolumes: false, intent: claim.intent)
            removed.append(claim.record.id)
        }
        return removed
    }

    public func pruneImages(scope: ImagePruneScope = .dangling) async throws -> [ImageRecord] {
        try requireCanonicalSnapshotWritable()
        let removed = snapshot.images.filter { image in
            let used = snapshot.containers.contains { container in
                container.image == image.id
                    || container.imageID == image.id
                    || image.manifests.contains { $0.imageID == container.imageID }
                    || image.references.contains(container.image)
                    || image.references.contains(ImageReference.normalized(container.image))
            }
            guard !used else { return false }
            return scope == .allUnused || image.references.isEmpty
        }
        for image in removed { for reference in image.references { try await backend.deleteImage(reference: reference) } }
        let ids = Set(removed.map(\.id)); snapshot.images.removeAll { ids.contains($0.id) }
        try await persist(); return removed
    }

    public func pruneVolumes(scope: VolumePruneScope = .anonymous) async throws -> [String] {
        try requireCanonicalSnapshotWritable()
        let used = Set(snapshot.containers.flatMap(\.mounts).filter { $0.kind == .volume }.map(\.source))
        let removed = snapshot.volumes.filter {
            !used.contains($0.name) && (scope == .allUnused || $0.anonymous == true)
        }
        for volume in removed { try await backend.deleteVolume(volume.name) }
        let names = Set(removed.map(\.name))
        snapshot.volumes.removeAll { names.contains($0.name) }
        try await persist(); return removed.map(\.name)
    }

    public func createVolume(name: String, sizeBytes: UInt64 = VolumeRecord.defaultSizeBytes, labels: [String: String] = [:], options: [String: String] = [:], anonymous: Bool = false) async throws -> VolumeRecord {
        try requireCanonicalSnapshotWritable()
        guard Identifier.validateName(name) else { throw EngineError(.badRequest, "invalid volume name: \(name)") }
        guard pendingVolumeNames[name, default: 0] == 0 else {
            throw EngineError(.conflict, "volume \(name) is being removed")
        }
        if let existing = snapshot.volumes.first(where: { $0.name == name }) { return existing }
        let record = VolumeRecord(name: name, createdAt: Date(), sizeBytes: sizeBytes, labels: labels, options: options, anonymous: anonymous)
        snapshot.volumes.append(record)
        try await persist()
        return record
    }

    public func removeVolume(_ name: String, force: Bool) async throws {
        try requireCanonicalSnapshotWritable()
        guard let index = snapshot.volumes.firstIndex(where: { $0.name == name }) else {
            throw EngineError(.notFound, "get \(name): no such volume")
        }
        let inUse = snapshot.containers.contains { container in container.mounts.contains { $0.kind == .volume && $0.source == name } }
        guard force || !inUse else { throw EngineError(.conflict, "remove \(name): volume is in use") }
        try await backend.deleteVolume(name)
        snapshot.volumes.remove(at: index)
        try await persist()
    }

    private func containerIndex(_ identifier: String) throws -> Int {
        let indices = snapshot.containers.indices.filter {
            snapshot.containers[$0].id == identifier || snapshot.containers[$0].name == identifier.normalizedContainerName || snapshot.containers[$0].id.hasPrefix(identifier)
        }
        guard indices.count == 1, let index = indices.first else {
            throw EngineError(.notFound, indices.isEmpty ? "No such container: \(identifier)" : "container identifier is ambiguous: \(identifier)")
        }
        return index
    }

    private func validateEndpoints(_ record: ContainerRecord) throws {
        for endpoint in record.networks {
            guard let network = snapshot.networks.first(where: { $0.id == endpoint.networkID }) else {
                throw EngineError(.notFound, "network \(endpoint.networkID) not found")
            }
            try validateStaticEndpointModes(
                network: network,
                ipv4IsStatic: endpoint.ipv4AddressIsStatic,
                ipv6IsStatic: endpoint.ipv6AddressIsStatic
            )
            try Self.validateEndpointDriverOptions(endpoint.driverOptions)
            for peer in snapshot.containers + Array(pendingContainers.values) where peer.id != record.id {
                for existing in peer.networks where existing.networkID == endpoint.networkID {
                    if endpoint.ipv4AddressIsStatic,
                       let requested = endpoint.ipv4Address,
                       requested == existing.ipv4Address.flatMap({ Self.canonicalAddress($0, family: AF_INET) }) {
                        throw EngineError(.conflict, "IPv4 address \(endpoint.ipv4Address ?? "") is already allocated")
                    }
                    if endpoint.ipv6AddressIsStatic,
                       let requested = endpoint.ipv6Address,
                       requested == existing.ipv6Address.flatMap({ Self.canonicalAddress($0, family: AF_INET6) }) {
                        throw EngineError(.conflict, "IPv6 address \(endpoint.ipv6Address ?? "") is already allocated")
                    }
                    let mac = endpoint.macAddress
                        ?? EndpointMacAddress.generated(seed: record.id + endpoint.networkID)
                    let existingMac = existing.macAddress
                        ?? EndpointMacAddress.generated(seed: peer.id + existing.networkID)
                    if mac == existingMac {
                        throw EngineError(.conflict, "MAC address \(mac) is already in use on this network")
                    }
                }
            }
        }
    }

    /// The transport protocols cengine can publish to the host. SCTP is an
    /// intentional compatibility gap: the vmnet-backed port forwarder only bridges
    /// TCP and UDP, so an SCTP publish is rejected explicitly rather than being
    /// silently accepted and never forwarded.
    private static let supportedPortProtocols: Set<String> = ["tcp", "udp"]

    /// Rejects published ports whose protocol cengine cannot forward, so an
    /// unsupported request fails at create time instead of starting a container
    /// whose published port would never receive traffic.
    private static func validatePortProtocols(_ ports: [PortBinding]) throws {
        for port in ports {
            let proto = port.proto.lowercased()
            guard supportedPortProtocols.contains(proto) else {
                throw EngineError(.badRequest, "unsupported port protocol \(port.proto); cengine publishes only tcp and udp")
            }
        }
    }

    /// Normalizes an explicitly requested endpoint MAC to canonical lowercase
    /// form, rejecting malformed, broadcast, and multicast/group addresses.
    private static func normalizeMacAddress(_ value: String) throws -> String {
        guard let normalized = EndpointMacAddress.normalized(value) else {
            throw EngineError(.badRequest, "invalid MAC address \(value)")
        }
        return normalized
    }

    /// Normalizes requested endpoint addresses and MACs before conflict checks,
    /// allocation, and persistence. Static addresses must belong to their pool
    /// and may not consume a gateway or protocol-reserved address.
    private func normalizingEndpointConfiguration(_ input: ContainerRecord) throws -> ContainerRecord {
        var record = input
        for index in record.networks.indices {
            let endpoint = record.networks[index]
            guard let network = snapshot.networks.first(where: { $0.id == endpoint.networkID }) else {
                throw EngineError(.notFound, "network \(endpoint.networkID) not found")
            }
            if let requested = endpoint.macAddress {
                record.networks[index].macAddress = try Self.normalizeMacAddress(requested)
            }
            if let requested = endpoint.ipv4Address {
                record.networks[index].ipv4Address = try Self.normalizeEndpointAddress(
                    requested, family: AF_INET, network: network
                )
            } else if endpoint.ipv4AddressIsStatic {
                throw EngineError(.badRequest, "static IPv4 address is missing")
            }
            if let requested = endpoint.ipv6Address {
                record.networks[index].ipv6Address = try Self.normalizeEndpointAddress(
                    requested, family: AF_INET6, network: network
                )
            } else if endpoint.ipv6AddressIsStatic {
                throw EngineError(.badRequest, "static IPv6 address is missing")
            }
        }
        return record
    }

    private static func normalizeEndpointAddress(
        _ value: String, family: Int32, network: NetworkRecord
    ) throws -> String {
        let familyName = family == AF_INET6 ? "IPv6" : "IPv4"
        guard let address = addressBytes(value, family: family),
              let canonical = addressString(address, family: family) else {
            throw EngineError(.badRequest, "invalid static \(familyName) address \(value)")
        }
        let subnet = family == AF_INET6 ? network.ipv6Subnet : network.subnet
        let gateway = family == AF_INET6 ? network.ipv6Gateway : network.gateway
        let components = subnet.split(separator: "/", maxSplits: 1).map(String.init)
        let byteCount = family == AF_INET6 ? 16 : 4
        guard components.count == 2,
              let prefix = Int(components[1]),
              (0...(byteCount * 8)).contains(prefix),
              let subnetAddress = addressBytes(components[0], family: family) else {
            throw EngineError(.badRequest, "invalid \(familyName) network subnet \(subnet)")
        }
        let networkAddress = maskedAddress(subnetAddress, prefix: prefix)
        guard maskedAddress(address, prefix: prefix) == networkAddress else {
            throw EngineError(.badRequest, "static \(familyName) address \(canonical) is outside subnet \(subnet)")
        }
        if canonical == canonicalAddress(gateway, family: family) {
            throw EngineError(.badRequest, "static \(familyName) address \(canonical) is reserved as the network gateway")
        }
        if family == AF_INET6, address == networkAddress {
            throw EngineError(.badRequest, "static IPv6 address \(canonical) is the reserved network address")
        }
        if family == AF_INET, prefix < 31 {
            if address == networkAddress {
                throw EngineError(.badRequest, "static IPv4 address \(canonical) is the reserved network address")
            }
            if address == broadcastAddress(networkAddress, prefix: prefix) {
                throw EngineError(.badRequest, "static IPv4 address \(canonical) is the reserved broadcast address")
            }
        }
        return canonical
    }

    private func allocatingEndpointAddresses(to input: ContainerRecord) throws -> ContainerRecord {
        var record = input
        for index in record.networks.indices {
            guard let network = snapshot.networks.first(where: { $0.id == record.networks[index].networkID }) else {
                throw EngineError(.notFound, "network \(record.networks[index].networkID) not found")
            }
            let peers = (snapshot.containers + Array(pendingContainers.values))
                .filter { $0.id != record.id }
                .flatMap(\.networks)
                .filter { $0.networkID == network.id }
            if record.networks[index].ipv4Address == nil, network.enableIPv4, !network.subnet.isEmpty {
                let cursorKey = Self.allocationCursorKey(networkID: network.id, family: AF_INET)
                let allocation = try Self.nextAddress(
                    in: network.subnet,
                    gateway: network.gateway,
                    used: Set(peers.compactMap(\.ipv4Address) + record.networks.compactMap(\.ipv4Address)),
                    after: endpointAllocationCursors[cursorKey] ?? 0
                )
                record.networks[index].ipv4Address = allocation.address
                endpointAllocationCursors[cursorKey] = allocation.offset
            }
            if record.networks[index].ipv6Address == nil, network.enableIPv6, !network.ipv6Subnet.isEmpty {
                let cursorKey = Self.allocationCursorKey(networkID: network.id, family: AF_INET6)
                let allocation = try Self.nextAddress(
                    in: network.ipv6Subnet,
                    gateway: network.ipv6Gateway,
                    used: Set(peers.compactMap(\.ipv6Address) + record.networks.compactMap(\.ipv6Address)),
                    after: endpointAllocationCursors[cursorKey] ?? 0
                )
                record.networks[index].ipv6Address = allocation.address
                endpointAllocationCursors[cursorKey] = allocation.offset
            }
        }
        return record
    }

    private static func nextAddress(
        in subnet: String, gateway: String, used: Set<String>, after cursor: Int
    ) throws -> (address: String, offset: Int) {
        let components = subnet.split(separator: "/", maxSplits: 1).map(String.init)
        guard components.count == 2, let prefix = Int(components[1]) else {
            throw EngineError(.badRequest, "invalid network subnet \(subnet)")
        }
        let family = components[0].contains(":") ? AF_INET6 : AF_INET
        let byteCount = family == AF_INET6 ? 16 : 4
        guard (0...(byteCount * 8)).contains(prefix), var network = addressBytes(components[0], family: family) else {
            throw EngineError(.badRequest, "invalid network subnet \(subnet)")
        }
        for index in network.indices {
            let remaining = prefix - index * 8
            if remaining >= 8 { continue }
            network[index] &= remaining <= 0 ? 0 : UInt8(truncatingIfNeeded: 0xff << (8 - remaining))
        }
        let hostBits = byteCount * 8 - prefix
        let lastOffset = hostBits >= 16 ? 65_535 : (1 << hostBits) - 1
        let reserved = Set(
            used.compactMap { canonicalAddress($0, family: family) }
                + [canonicalAddress(gateway, family: family)].compactMap { $0 }
        )
        var candidateOffsets = Array(0...lastOffset)
        if family == AF_INET {
            if hostBits > 1 {
                candidateOffsets.removeAll { offset in
                    offset == 0 || (hostBits <= 16 && offset == lastOffset)
                }
            }
            // RFC 3021 makes both addresses in an IPv4 /31 usable. In
            // particular, offset zero is not a network-address reservation.
        } else {
            candidateOffsets.removeAll { $0 == 0 }
        }
        guard !candidateOffsets.isEmpty else {
            throw EngineError(.conflict, "network \(subnet) has no allocatable addresses")
        }
        let offsets = candidateOffsets.filter { $0 > cursor } + candidateOffsets.filter { $0 <= cursor }
        for offset in offsets {
            var candidate = network
            var carry = offset
            for index in candidate.indices.reversed() where carry > 0 {
                let value = Int(candidate[index]) + carry
                candidate[index] = UInt8(value & 0xff)
                carry = value >> 8
            }
            guard let value = addressString(candidate, family: family), !reserved.contains(value) else { continue }
            return (value, offset)
        }
        throw EngineError(.conflict, "network \(subnet) has no free addresses")
    }

    private static func allocationCursorKey(networkID: String, family: Int32) -> String {
        "\(networkID)/\(family == AF_INET6 ? "ipv6" : "ipv4")"
    }

    private static func networkID(fromAllocationCursorKey key: String) -> String {
        key.split(separator: "/", maxSplits: 1).first.map(String.init) ?? key
    }

    private func persistEndpointAllocationCursors() async throws {
        try await beforeEndpointAllocationPersistence?()
        try await endpointAllocationStore.save(endpointAllocationCursors)
    }

    private static func addressBytes(_ value: String, family: Int32) -> [UInt8]? {
        var bytes = [UInt8](repeating: 0, count: family == AF_INET6 ? 16 : 4)
        let result = value.withCString { source in
            bytes.withUnsafeMutableBytes { destination in inet_pton(family, source, destination.baseAddress) }
        }
        return result == 1 ? bytes : nil
    }

    private static func addressString(_ bytes: [UInt8], family: Int32) -> String? {
        var source = bytes
        var destination = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        return source.withUnsafeMutableBytes { source in
            inet_ntop(family, source.baseAddress, &destination, socklen_t(destination.count)).map { _ in String(cString: destination) }
        }
    }

    private static func maskedAddress(_ bytes: [UInt8], prefix: Int) -> [UInt8] {
        var masked = bytes
        for index in masked.indices {
            let remaining = prefix - index * 8
            if remaining >= 8 { continue }
            masked[index] &= remaining <= 0 ? 0 : UInt8(truncatingIfNeeded: 0xff << (8 - remaining))
        }
        return masked
    }

    private static func broadcastAddress(_ network: [UInt8], prefix: Int) -> [UInt8] {
        var broadcast = network
        for index in broadcast.indices {
            let remaining = prefix - index * 8
            if remaining >= 8 { continue }
            let networkMask = remaining <= 0 ? UInt8(0) : UInt8(truncatingIfNeeded: 0xff << (8 - remaining))
            broadcast[index] |= ~networkMask
        }
        return broadcast
    }

    private static func normalizeNetworkAddressing(
        subnet: String, gateway: String, family: Int32
    ) throws -> (subnet: String, gateway: String) {
        let familyName = family == AF_INET6 ? "IPv6" : "IPv4"
        guard !subnet.isEmpty else {
            guard gateway.isEmpty else {
                throw EngineError(.badRequest, "\(familyName) gateway requires an explicit subnet")
            }
            return ("", "")
        }
        let components = subnet.split(
            separator: "/", maxSplits: 1, omittingEmptySubsequences: false
        ).map(String.init)
        let byteCount = family == AF_INET6 ? 16 : 4
        guard components.count == 2,
              let prefix = Int(components[1]),
              (0...(byteCount * 8)).contains(prefix),
              let requestedAddress = addressBytes(components[0], family: family) else {
            throw EngineError(.badRequest, "invalid \(familyName) subnet \(subnet)")
        }
        let networkAddress = maskedAddress(requestedAddress, prefix: prefix)
        guard let canonicalNetwork = addressString(networkAddress, family: family) else {
            throw EngineError(.badRequest, "invalid \(familyName) subnet \(subnet)")
        }
        let canonicalSubnet = "\(canonicalNetwork)/\(prefix)"
        let implicitGateway = firstAddress(in: canonicalSubnet)
        let gatewayAddress: [UInt8]
        let canonicalGateway: String
        if gateway.isEmpty {
            guard let implicitGateway,
                  let address = addressBytes(implicitGateway, family: family) else {
                throw EngineError(.badRequest, "\(familyName) subnet \(canonicalSubnet) has no usable gateway address")
            }
            gatewayAddress = address
            canonicalGateway = implicitGateway
        } else {
            guard let address = addressBytes(gateway, family: family),
                  let canonical = addressString(address, family: family) else {
                throw EngineError(.badRequest, "invalid \(familyName) gateway \(gateway)")
            }
            gatewayAddress = address
            canonicalGateway = canonical
        }
        guard maskedAddress(gatewayAddress, prefix: prefix) == networkAddress else {
            throw EngineError(
                .badRequest, "\(familyName) gateway \(canonicalGateway) is outside subnet \(canonicalSubnet)"
            )
        }
        if family == AF_INET6, gatewayAddress == networkAddress {
            throw EngineError(.badRequest, "IPv6 gateway \(canonicalGateway) is the reserved network address")
        }
        if family == AF_INET, prefix < 31 {
            if gatewayAddress == networkAddress {
                throw EngineError(.badRequest, "IPv4 gateway \(canonicalGateway) is the reserved network address")
            }
            if gatewayAddress == broadcastAddress(networkAddress, prefix: prefix) {
                throw EngineError(.badRequest, "IPv4 gateway \(canonicalGateway) is the reserved broadcast address")
            }
        }
        if family == AF_INET6, canonicalGateway != implicitGateway {
            throw EngineError(
                .unsupported,
                "custom IPv6 gateway \(canonicalGateway) is not supported; vmnet uses \(implicitGateway ?? "") for prefix \(canonicalSubnet)"
            )
        }
        return (canonicalSubnet, canonicalGateway)
    }

    private static func firstAddress(in subnet: String) -> String? {
        let components = subnet.split(separator: "/", maxSplits: 1).map(String.init)
        guard components.count == 2, let prefix = Int(components[1]) else { return nil }
        let family = components[0].contains(":") ? AF_INET6 : AF_INET
        let byteCount = family == AF_INET6 ? 16 : 4
        guard (0..<(byteCount * 8)).contains(prefix),
              let subnetAddress = addressBytes(components[0], family: family) else { return nil }
        var network = maskedAddress(subnetAddress, prefix: prefix)
        for index in network.indices.reversed() {
            network[index] &+= 1
            if network[index] != 0 { break }
        }
        return addressString(network, family: family)
    }

    private static func canonicalAddress(_ value: String, family: Int32) -> String? {
        addressBytes(value, family: family).flatMap { addressString($0, family: family) }
    }

    private func validateStaticEndpointModes(
        network: NetworkRecord, ipv4IsStatic: Bool, ipv6IsStatic: Bool
    ) throws {
        if ipv4IsStatic, !network.enableIPv4 {
            throw EngineError(.badRequest, "IPv4 addresses cannot be assigned when IPv4 is disabled")
        }
        if ipv6IsStatic, !network.enableIPv6 {
            throw EngineError(.badRequest, "IPv6 addresses cannot be assigned when IPv6 is disabled")
        }
        if ipv4IsStatic, network.ipv4AllocationMode != .explicit {
            throw EngineError(.badRequest, "static IPv4 addresses require an explicitly configured IPv4 subnet")
        }
        if ipv6IsStatic, network.ipv6AllocationMode != .explicit {
            throw EngineError(.badRequest, "static IPv6 addresses require an explicitly configured IPv6 subnet")
        }
    }

    private static func validateEndpointDriverOptions(_ options: [String: String]?) throws {
        guard let options else { return }
        for key in options.keys where key != NetworkEndpointRecord.sysctlsDriverOption {
            throw EngineError(.unsupported, "endpoint driver option \(key) is not supported")
        }
        guard let value = options[NetworkEndpointRecord.sysctlsDriverOption] else { return }
        for assignment in value.components(separatedBy: ",") {
            let pair = assignment.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            let name = pair.first.map(String.init) ?? ""
            let components = name.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
            let familyAllowed = components.count == 5 && ["ipv4", "ipv6", "mpls"].contains(components[1])
            let interfacePlaceholder = components.count == 5 && components[3].lowercased() == "ifname"
            let safeComponents = components.allSatisfy(Self.isSafeSysctlComponent)
            guard pair.count == 2, components.first == "net", familyAllowed, interfacePlaceholder, safeComponents,
                  !pair[1].contains("\n"), !pair[1].contains("\0") else {
                throw EngineError(
                    .badRequest,
                    "invalid endpoint sysctl \(assignment); use net.(ipv4|ipv6|mpls).X.IFNAME.Y=value"
                )
            }
        }
    }

    private static func isSafeSysctlComponent(_ value: String) -> Bool {
        !value.isEmpty && value.unicodeScalars.allSatisfy { scalar in
            let value = scalar.value
            return (65...90).contains(value) || (97...122).contains(value) || (48...57).contains(value)
                || value == 95 || value == 45
        }
    }

    private func applyingEndpointAddresses(to input: ContainerRecord) async -> ContainerRecord {
        var record = input
        let addresses = await backend.endpointAddresses(for: input)
        for endpoint in record.networks.indices {
            guard let address = addresses[record.networks[endpoint].networkID] else { continue }
            record.networks[endpoint].ipv4Address = Self.nonEmptyBackendAddress(address.ipv4Address)
            record.networks[endpoint].ipv6Address = Self.nonEmptyBackendAddress(address.ipv6Address)
        }
        return record
    }

    private static func nonEmptyBackendAddress(_ address: String) -> String? {
        address.isEmpty ? nil : address
    }

    func persist() async throws {
        try await acquirePersistence()
        defer { releasePersistence() }
        try await beforePersistence?()
        try await saveEngineSnapshot(snapshot)
    }

    func requireCanonicalSnapshotWritable() throws {
        if let detail = canonicalSnapshotUnavailableDetail {
            throw CanonicalSnapshotPersistenceUnavailable(detail: detail)
        }
    }

    /// A failed parent-directory sync is reported as ambiguous after rename.
    /// Re-read the selected old/new state before returning the error so later
    /// operations cannot overwrite a newly durable teardown/resource fence with
    /// the actor's pre-save snapshot.
    private func saveEngineSnapshot(_ value: EngineSnapshot) async throws {
        try requireCanonicalSnapshotWritable()
        let base = snapshot
        let revision = snapshotRevision
        do {
            try await store.save(value)
        } catch let ambiguity as AtomicStorePersistenceAmbiguousError {
            do {
                let saved = try await store.loadRequired()
                try Self.validateEngineSnapshotInvariants(saved)
                let reconciled = if snapshotRevision == revision {
                    saved
                } else {
                    try Self.reconcilingConcurrentSnapshotChanges(
                        base: base,
                        saved: saved,
                        current: snapshot
                    )
                }
                try Self.validateEngineSnapshotInvariants(reconciled)
                snapshot = reconciled
            } catch let reloadFailure {
                canonicalSnapshotUnavailableDetail = reloadFailure.localizedDescription
                throw AmbiguousSnapshotReload.unavailable(
                    ambiguity: ambiguity, reloadFailure: reloadFailure
                )
            }
            throw ambiguity
        }
    }

    private static func reconcilingConcurrentSnapshotChanges(
        base: EngineSnapshot,
        saved: EngineSnapshot,
        current: EngineSnapshot
    ) throws -> EngineSnapshot {
        var merged = saved
        merged.containers = try reconcileRecords(
            base: base.containers,
            saved: saved.containers,
            current: current.containers,
            collection: "containers",
            key: { "\($0.id):\($0.instanceID.uuidString)" }
        )
        merged.networks = try reconcileRecords(
            base: base.networks,
            saved: saved.networks,
            current: current.networks,
            collection: "networks",
            key: { $0.id }
        )
        merged.volumes = try reconcileRecords(
            base: base.volumes,
            saved: saved.volumes,
            current: current.volumes,
            collection: "volumes",
            key: { $0.name }
        )
        merged.images = try reconcileRecords(
            base: base.images,
            saved: saved.images,
            current: current.images,
            collection: "images",
            key: { $0.id }
        )
        merged.cleanupPendingContainerIDs = reconcileSet(
            base: base.cleanupPendingContainerIDs,
            saved: saved.cleanupPendingContainerIDs,
            current: current.cleanupPendingContainerIDs
        )
        merged.removalPendingContainerIDs = reconcileSet(
            base: base.removalPendingContainerIDs,
            saved: saved.removalPendingContainerIDs,
            current: current.removalPendingContainerIDs
        )
        merged.removalVolumesPendingContainerIDs = reconcileSet(
            base: base.removalVolumesPendingContainerIDs,
            saved: saved.removalVolumesPendingContainerIDs,
            current: current.removalVolumesPendingContainerIDs
        )
        merged.containerFenceInstanceIDs = try reconcileDictionary(
            base: base.containerFenceInstanceIDs,
            saved: saved.containerFenceInstanceIDs,
            current: current.containerFenceInstanceIDs,
            collection: "container fence identities"
        )
        merged.resourceUpdateIntents = try reconcileRecords(
            base: base.resourceUpdateIntents ?? [],
            saved: saved.resourceUpdateIntents ?? [],
            current: current.resourceUpdateIntents ?? [],
            collection: "resource update intents",
            key: { $0.containerID }
        )
        if merged.resourceUpdateIntents?.isEmpty == true {
            merged.resourceUpdateIntents = nil
        }
        return merged
    }

    private static func reconcileRecords<Record: Encodable>(
        base: [Record],
        saved: [Record],
        current: [Record],
        collection: String,
        key: (Record) -> String
    ) throws -> [Record] {
        let baseByKey = try uniquelyKeyedRecords(base, collection: collection, key: key)
        let savedByKey = try uniquelyKeyedRecords(saved, collection: collection, key: key)
        let currentByKey = try uniquelyKeyedRecords(current, collection: collection, key: key)
        var result = saved
        for identifier in Set(baseByKey.keys).union(currentByKey.keys) {
            let baseValue = baseByKey[identifier]
            let savedValue = savedByKey[identifier]
            let currentValue = currentByKey[identifier]
            guard try !persistenceValuesEqual(currentValue, baseValue) else { continue }
            if try !persistenceValuesEqual(savedValue, baseValue),
               try !persistenceValuesEqual(savedValue, currentValue) {
                throw ConcurrentSnapshotReconciliationFailed(
                    detail: "conflicting concurrent mutation of \(collection) entry \(identifier)"
                )
            }
            result.removeAll { key($0) == identifier }
            if let currentValue { result.append(currentValue) }
        }
        return result
    }

    private static func uniquelyKeyedRecords<Record>(
        _ records: [Record],
        collection: String,
        key: (Record) -> String
    ) throws -> [String: Record] {
        var keyed: [String: Record] = [:]
        for record in records {
            let identifier = key(record)
            guard keyed.updateValue(record, forKey: identifier) == nil else {
                throw ConcurrentSnapshotReconciliationFailed(
                    detail: "duplicate \(collection) entry \(identifier)"
                )
            }
        }
        return keyed
    }

    private static func persistenceValuesEqual<Value: Encodable>(
        _ lhs: Value?,
        _ rhs: Value?
    ) throws -> Bool {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(lhs) == encoder.encode(rhs)
    }

    private static func reconcileSet<Element: Hashable>(
        base: Set<Element>?,
        saved: Set<Element>?,
        current: Set<Element>?
    ) -> Set<Element>? {
        let base = base ?? []
        let current = current ?? []
        var merged = saved ?? []
        merged.formUnion(current.subtracting(base))
        merged.subtract(base.subtracting(current))
        return merged.isEmpty ? nil : merged
    }

    private static func reconcileDictionary<Key: Hashable, Value: Equatable>(
        base: [Key: Value]?,
        saved: [Key: Value]?,
        current: [Key: Value]?,
        collection: String
    ) throws -> [Key: Value]? {
        let base = base ?? [:]
        let current = current ?? [:]
        var merged = saved ?? [:]
        for key in Set(base.keys).union(current.keys) where current[key] != base[key] {
            if merged[key] != base[key], merged[key] != current[key] {
                throw ConcurrentSnapshotReconciliationFailed(
                    detail: "conflicting concurrent mutation of \(collection)"
                )
            }
            merged[key] = current[key]
        }
        return merged.isEmpty ? nil : merged
    }

    private func acquirePersistence() async throws {
        if !persistenceActive {
            persistenceActive = true
            do {
                try Task.checkCancellation()
            } catch {
                releasePersistence()
                throw error
            }
            return
        }
        await withCheckedContinuation { persistenceWaiters.append($0) }
        do {
            try Task.checkCancellation()
        } catch {
            releasePersistence()
            throw error
        }
    }

    private func releasePersistence() {
        guard !persistenceWaiters.isEmpty else {
            persistenceActive = false
            return
        }
        persistenceWaiters.removeFirst().resume()
    }

    private func persistInstallingResourceIntent(_ intent: ResourceUpdateIntentRecord) async throws {
        try await acquirePersistence()
        defer { releasePersistence() }
        try await beforePersistence?()
        var value = snapshot
        var intents = value.resourceUpdateIntents ?? []
        guard !intents.contains(where: { $0.containerID == intent.containerID }) else {
            throw EngineError(.conflict, "container \(intent.containerID) already has a resource update pending")
        }
        guard let current = value.containers.first(where: { $0.id == intent.containerID }),
              Self.resourceUpdateIdentityMatches(intent.old, intent.desired),
              Self.resourceUpdateIdentityMatches(current, intent.old) else {
            throw EngineError(.conflict, "container identity changed before its resource update was journaled")
        }
        intents.append(intent)
        value.resourceUpdateIntents = intents
        try await saveEngineSnapshot(value)
        snapshot.resourceUpdateIntents = intents
    }

    private func persistResourceIntentPhase(
        _ phase: ResourceUpdateIntentRecord.TransactionPhase,
        containerID: String
    ) async throws {
        try await acquirePersistence()
        defer { releasePersistence() }
        try await beforePersistence?()
        var value = snapshot
        guard var intents = value.resourceUpdateIntents,
              let index = intents.firstIndex(where: { $0.containerID == containerID }),
              let current = value.containers.first(where: { $0.id == containerID }),
              Self.resourceUpdateIntentIsValid(intents[index], current: current) else {
            throw EngineError(.internalError, "resource update intent disappeared for container \(containerID)")
        }
        intents[index].phase = phase
        value.resourceUpdateIntents = intents
        try await saveEngineSnapshot(value)
        snapshot.resourceUpdateIntents = intents
    }

    /// Atomically commits the desired resource fields and removes the journal.
    /// The public snapshot remains old+journal until the atomic-store save has
    /// succeeded, so an unrelated save cannot publish the candidate first.
    private func persistResourceCommit(
        containerID: String,
        desired: ContainerRecord
    ) async throws -> ContainerRecord {
        try await acquirePersistence()
        defer { releasePersistence() }
        try await beforePersistence?()
        var value = snapshot
        guard let index = value.containers.firstIndex(where: { $0.id == containerID }),
              let intent = value.resourceUpdateIntents?.first(where: { $0.containerID == containerID }),
              Self.resourceUpdateIntentIsValid(intent, current: value.containers[index]),
              Self.resourceUpdateIdentityMatches(intent.desired, desired) else {
            throw EngineError(.conflict, "container \(containerID) disappeared during its resource update")
        }
        let committed = Self.mergingResourceFields(from: desired, into: value.containers[index])
        value.containers[index] = committed
        Self.removeResourceIntent(containerID, from: &value)
        do {
            try await saveEngineSnapshot(value)
        } catch let ambiguity as AtomicStorePersistenceAmbiguousError {
            switch classifyResourceCommit(
                containerID: containerID, desired: desired
            ) {
            case .desired:
                // The rename appears to have landed, but canonical directory
                // durability was ambiguous. Re-save the exact selected state
                // through an independently successful parent fsync before the
                // API reports success.
                do {
                    try await saveEngineSnapshot(snapshot)
                } catch let repeated as AtomicStorePersistenceAmbiguousError {
                    switch classifyResourceCommit(
                        containerID: containerID, desired: desired
                    ) {
                    case .desired:
                        throw LandedResourceCommitCouldNotBeReconfirmed(
                            underlying: repeated
                        )
                    case .old:
                        throw repeated
                    case .unknown:
                        throw ResourceCommitStateCouldNotBeClassified(
                            underlying: repeated
                        )
                    }
                } catch let reload as AmbiguousSnapshotReload {
                    throw ResourceCommitStateCouldNotBeClassified(
                        underlying: reload
                    )
                } catch {
                    throw LandedResourceCommitCouldNotBeReconfirmed(
                        underlying: error
                    )
                }
            case .old:
                // The old+journal side of the transaction is still selected.
                // Let the caller compensate the backend and durably clear it.
                throw ambiguity
            case .unknown:
                throw ResourceCommitStateCouldNotBeClassified(
                    underlying: EngineError(
                        .internalError,
                        "resource commit for container \(containerID) has an unclassifiable durable state after: "
                            + ambiguity.localizedDescription
                    )
                )
            }
        } catch let reload as AmbiguousSnapshotReload {
            throw ResourceCommitStateCouldNotBeClassified(underlying: reload)
        }
        guard let current = snapshot.containers.firstIndex(where: { $0.id == containerID }) else {
            throw EngineError(.conflict, "container \(containerID) disappeared during its resource update")
        }
        let published = Self.mergingResourceFields(from: desired, into: snapshot.containers[current])
        snapshot.containers[current] = published
        Self.removeResourceIntent(containerID, from: &snapshot)
        return published
    }

    private func classifyResourceCommit(
        containerID: String,
        desired: ContainerRecord
    ) -> ResourceCommitReconciliation {
        if let landed = snapshot.containers.first(where: { $0.id == containerID }),
           Self.resourceUpdateIdentityMatches(landed, desired),
           Self.resourceFieldsMatch(landed, desired),
           snapshot.resourceUpdateIntents?.contains(where: {
               $0.containerID == containerID
           }) != true {
            return .desired
        }
        if let landed = snapshot.containers.first(where: { $0.id == containerID }),
           let intent = snapshot.resourceUpdateIntents?.first(where: {
               $0.containerID == containerID
           }), Self.resourceUpdateIntentIsValid(intent, current: landed),
           Self.resourceFieldsMatch(landed, intent.old),
           Self.resourceUpdateIdentityMatches(intent.desired, desired) {
            return .old
        }
        return .unknown
    }

    /// Persists update fields that did not require a backend resource
    /// transaction, preserving any runtime state published while waiting for
    /// the serialized store write.
    private func persistContainerUpdate(
        containerID: String,
        desired: ContainerRecord
    ) async throws -> ContainerRecord {
        try await acquirePersistence()
        defer { releasePersistence() }
        try await beforePersistence?()
        var value = snapshot
        guard let index = value.containers.firstIndex(where: { $0.id == containerID }),
              Self.resourceUpdateIdentityMatches(value.containers[index], desired),
              !resourceUpdateIsPending(containerID) else {
            throw EngineError(.conflict, "container \(containerID) changed during its update")
        }
        let committed = Self.mergingResourceFields(from: desired, into: value.containers[index])
        value.containers[index] = committed
        try await saveEngineSnapshot(value)
        guard let current = snapshot.containers.firstIndex(where: { $0.id == containerID }),
              Self.resourceUpdateIdentityMatches(snapshot.containers[current], desired) else {
            throw EngineError(.conflict, "container \(containerID) changed during its update")
        }
        let published = Self.mergingResourceFields(from: desired, into: snapshot.containers[current])
        snapshot.containers[current] = published
        return published
    }

    /// Atomically chooses the old resource fields and clears an incomplete
    /// journal after the backend has been successfully restored.
    private func persistResourceRollback(
        containerID: String,
        old: ContainerRecord
    ) async throws {
        try await acquirePersistence()
        defer { releasePersistence() }
        try await beforePersistence?()
        var value = snapshot
        guard let index = value.containers.firstIndex(where: { $0.id == containerID }),
              let intent = value.resourceUpdateIntents?.first(where: { $0.containerID == containerID }),
              Self.resourceUpdateIntentIsValid(intent, current: value.containers[index]),
              Self.resourceUpdateIdentityMatches(intent.old, old) else {
            throw EngineError(.conflict, "container \(containerID) disappeared during resource rollback")
        }
        value.containers[index] = Self.mergingResourceFields(from: old, into: value.containers[index])
        Self.removeResourceIntent(containerID, from: &value)
        try await saveEngineSnapshot(value)
        guard let current = snapshot.containers.firstIndex(where: { $0.id == containerID }) else { return }
        snapshot.containers[current] = Self.mergingResourceFields(from: old, into: snapshot.containers[current])
        Self.removeResourceIntent(containerID, from: &snapshot)
    }

    private func persistResourceContainmentCompletion(_ stopped: ContainerRecord) async throws {
        try await acquirePersistence()
        defer { releasePersistence() }
        try await beforePersistence?()
        var value = snapshot
        guard let index = value.containers.firstIndex(where: { $0.id == stopped.id }),
              let intent = value.resourceUpdateIntents?.first(where: {
                $0.containerID == stopped.id
              }),
              Self.resourceUpdateIntentIsValid(intent, current: value.containers[index]) else {
            throw EngineError(.conflict, "container \(stopped.id) disappeared during resource containment")
        }
        value.containers[index] = stopped
        if var cleanup = value.cleanupPendingContainerIDs {
            cleanup.remove(stopped.id)
            value.cleanupPendingContainerIDs = cleanup.isEmpty ? nil : cleanup
        }
        if value.removalPendingContainerIDs?.contains(stopped.id) != true,
           var identities = value.containerFenceInstanceIDs {
            identities.removeValue(forKey: stopped.id)
            value.containerFenceInstanceIDs = identities.isEmpty ? nil : identities
        }
        Self.removeResourceIntent(stopped.id, from: &value)
        try await saveEngineSnapshot(value)
        guard let current = snapshot.containers.firstIndex(where: { $0.id == stopped.id }) else { return }
        snapshot.containers[current] = stopped
        clearCleanupPending(stopped.id)
        Self.removeResourceIntent(stopped.id, from: &snapshot)
    }

    private static func removeResourceIntent(_ containerID: String, from snapshot: inout EngineSnapshot) {
        guard var intents = snapshot.resourceUpdateIntents else { return }
        intents.removeAll { $0.containerID == containerID }
        snapshot.resourceUpdateIntents = intents.isEmpty ? nil : intents
    }

    private static func resourceUpdateIdentityMatches(
        _ lhs: ContainerRecord,
        _ rhs: ContainerRecord
    ) -> Bool {
        lhs.id == rhs.id
            && lhs.name == rhs.name
            && lhs.instanceID == rhs.instanceID
    }

    private static func validateEngineSnapshotInvariants(
        _ snapshot: EngineSnapshot
    ) throws {
        try validateUnique(snapshot.containers.map(\.id), collection: "container public IDs")
        try validateUnique(snapshot.containers.map(\.name), collection: "container names")
        try validateUnique(snapshot.containers.map(\.instanceID), collection: "container instance IDs")
        try validateUnique(
            snapshot.containers.map { "\($0.id):\($0.instanceID.uuidString)" },
            collection: "container exact keys"
        )
        try validateUnique(snapshot.networks.map(\.id), collection: "network IDs")
        try validateUnique(snapshot.networks.map(\.name), collection: "network names")
        try validateUnique(snapshot.volumes.map(\.name), collection: "volume names")
        try validateUnique(snapshot.images.map(\.id), collection: "image IDs")

        let identifiers = (snapshot.cleanupPendingContainerIDs ?? [])
            .union(snapshot.removalPendingContainerIDs ?? [])
            .union(snapshot.removalVolumesPendingContainerIDs ?? [])
        let identities = snapshot.containerFenceInstanceIDs ?? [:]
        guard Set(identities.keys) == identifiers else {
            throw EngineError(
                .internalError,
                "container fence identities do not exactly match pending cleanup/removal intents"
            )
        }
        for identifier in identifiers {
            guard let record = snapshot.containers.first(where: { $0.id == identifier }),
                  identities[identifier] == record.instanceID else {
                throw EngineError(
                    .internalError,
                    "container fence \(identifier) has missing or mismatched instance ownership"
                )
            }
        }

        let intents = snapshot.resourceUpdateIntents ?? []
        try validateUnique(intents.map(\.containerID), collection: "resource update intent container IDs")
        for intent in intents {
            guard let record = snapshot.containers.first(where: { $0.id == intent.containerID }),
                  resourceUpdateIntentIsValid(intent, current: record) else {
                throw EngineError(
                    .internalError,
                    "resource update intent \(intent.containerID) has missing or mismatched instance ownership"
                )
            }
        }
    }

    private static func validateUnique<Value: Hashable>(
        _ values: [Value],
        collection: String
    ) throws {
        var seen = Set<Value>()
        for value in values where !seen.insert(value).inserted {
            throw EngineError(.internalError, "duplicate \(collection) entry \(value)")
        }
    }

    private static func resourceUpdateIntentIsValid(
        _ intent: ResourceUpdateIntentRecord,
        current: ContainerRecord
    ) -> Bool {
        intent.containerID == intent.old.id
            && intent.containerID == intent.desired.id
            && resourceUpdateIdentityMatches(intent.old, intent.desired)
            && resourceUpdateIdentityMatches(current, intent.old)
            && intent.old.phase == intent.originalPhase
            && intent.desired.phase == intent.originalPhase
    }

    private static func mergingResourceFields(
        from candidate: ContainerRecord,
        into current: ContainerRecord
    ) -> ContainerRecord {
        var merged = current
        merged.memoryBytes = candidate.memoryBytes
        merged.cpus = candidate.cpus
        merged.pidsLimit = candidate.pidsLimit
        merged.restartPolicy = candidate.restartPolicy
        merged.blockIOReadBps = candidate.blockIOReadBps
        merged.blockIOWriteBps = candidate.blockIOWriteBps
        merged.blockIOReadIOps = candidate.blockIOReadIOps
        merged.blockIOWriteIOps = candidate.blockIOWriteIOps
        return merged
    }

    private static func resourceFieldsMatch(
        _ lhs: ContainerRecord,
        _ rhs: ContainerRecord
    ) -> Bool {
        lhs.memoryBytes == rhs.memoryBytes
            && lhs.cpus == rhs.cpus
            && lhs.pidsLimit == rhs.pidsLimit
            && lhs.restartPolicy.name == rhs.restartPolicy.name
            && lhs.restartPolicy.maximumRetryCount == rhs.restartPolicy.maximumRetryCount
            && lhs.blockIOReadBps == rhs.blockIOReadBps
            && lhs.blockIOWriteBps == rhs.blockIOWriteBps
            && lhs.blockIOReadIOps == rhs.blockIOReadIOps
            && lhs.blockIOWriteIOps == rhs.blockIOWriteIOps
    }

    private func rollbackResourceUpdateAfterPersistenceFailure(
        old: ContainerRecord,
        persistenceError: Error
    ) async throws -> Never {
        do {
            try await backend.updateResources(old)
        } catch {
            let compensationError = error
            let containmentFailure = await containTaintedResourceUpdate(old)
            let details = [
                "resource update persistence failed: \(EngineError.message(for: persistenceError))",
                "backend compensation failed: \(EngineError.message(for: compensationError))",
                containmentFailure.map { "containment failed: \($0)" },
            ].compactMap { $0 }.joined(separator: "; ")
            throw EngineError(.internalError, details)
        }
        do {
            try await persistResourceRollback(containerID: old.id, old: old)
        } catch {
            throw EngineError(
                .internalError,
                "resource update persistence failed: \(EngineError.message(for: persistenceError)); "
                    + "backend was restored but the durable old-state journal could not be cleared: "
                    + EngineError.message(for: error)
            )
        }
        throw persistenceError
    }

    /// Resolve every incomplete resource transaction before normal backend
    /// recovery. Old resources are the rollback choice until the desired record
    /// and journal removal have committed in one durable snapshot.
    private func resolvePendingResourceUpdates() async throws {
        let intents = snapshot.resourceUpdateIntents ?? []
        guard !intents.isEmpty else { return }
        var seen = Set<String>()
        for intent in intents {
            guard seen.insert(intent.containerID).inserted,
                  let index = snapshot.containers.firstIndex(where: { $0.id == intent.containerID }),
                  Self.resourceUpdateIntentIsValid(
                    intent, current: snapshot.containers[index]
                  ) else {
                throw EngineError(.internalError, "invalid durable resource update intent")
            }
            let current = snapshot.containers[index]
            let chosen = Self.mergingResourceFields(from: intent.old, into: current)
            if current.phase == .dead || cleanupIsPending(current.id) {
                if let failure = await containTaintedResourceUpdate(chosen) {
                    throw EngineError(
                        .internalError,
                        "could not contain unresolved resource update for container \(current.id): \(failure)"
                    )
                }
                continue
            }
            do {
                try await backend.updateResources(chosen)
            } catch {
                let applyError = error
                if let failure = await containTaintedResourceUpdate(chosen) {
                    throw EngineError(
                        .internalError,
                        "could not reapply durable resources for container \(current.id): "
                            + "\(EngineError.message(for: applyError)); containment failed: \(failure)"
                    )
                }
                continue
            }
            do {
                try await persistResourceRollback(containerID: current.id, old: chosen)
            } catch {
                throw EngineError(
                    .internalError,
                    "durable resources were reapplied for container \(current.id), but its recovery journal "
                        + "could not be cleared: \(EngineError.message(for: error))"
                )
            }
        }
    }

    private static func taintedResourceUpdateError(
        cause: Error,
        containmentFailure: String?
    ) -> EngineError {
        let outcome = containmentFailure.map { "workload remains quarantined: \($0)" }
            ?? "workload was stopped and removed from the backend execution"
        return EngineError(
            .internalError,
            "resource update rollback was incomplete: \(EngineError.message(for: cause)); \(outcome)"
        )
    }

    /// Canonical state could not be classified after publication. Contain the
    /// backend execution and retain only an in-memory fence; writing any
    /// snapshot here could overwrite an unknown canonical selection.
    private func containUnclassifiedResourceUpdate(
        _ record: ContainerRecord
    ) async -> String? {
        healthTasks.removeValue(forKey: record.id)?.cancel()
        cancelCompletionMonitor(record.id)
        if let index = try? containerIndex(record.id),
           Self.resourceUpdateIdentityMatches(snapshot.containers[index], record) {
            snapshot.containers[index].phase = .dead
            markCleanupPending(record.id)
        }
        do {
            _ = try await cleanupBackendExecution(record)
            if let index = try? containerIndex(record.id),
               Self.resourceUpdateIdentityMatches(snapshot.containers[index], record) {
                snapshot.containers[index].phase = .exited
                snapshot.containers[index].finishedAt = Date()
                snapshot.containers[index].exitCode =
                    snapshot.containers[index].exitCode ?? 137
            }
            return nil
        } catch {
            return EngineError.message(for: error)
        }
    }

    /// Fail closed when live cgroup state can no longer be proven to match the
    /// old durable record. The public record is quarantined before teardown;
    /// only verified backend deletion permits an exited publication.
    private func containTaintedResourceUpdate(_ record: ContainerRecord) async -> String? {
        healthTasks.removeValue(forKey: record.id)?.cancel()
        cancelCompletionMonitor(record.id)
        guard let index = try? containerIndex(record.id) else {
            do {
                try await cleanupBackendExecution(record)
                return nil
            } catch {
                return EngineError.message(for: error)
            }
        }

        snapshot.containers[index].phase = .dead
        markCleanupPending(record.id)
        // The pre-mutation resource journal is already a durable fence. Still
        // try to publish the stronger dead+cleanup fence and retain its failure
        // for diagnostics if physical teardown cannot be verified either.
        let fenceFailure: Error?
        do {
            try await persist()
            fenceFailure = nil
        } catch {
            fenceFailure = error
        }

        let stopCode: Int32?
        do {
            stopCode = try await cleanupBackendExecution(record)
        } catch {
            let cleanupFailure = error
            quarantineCleanupPendingContainer(record.id)
            markCleanupPending(record.id)
            let retryFailure: Error?
            do {
                try await persist()
                retryFailure = nil
            } catch {
                retryFailure = error
            }
            return [
                fenceFailure.map { "durable quarantine fence failed: \(EngineError.message(for: $0))" },
                "backend cleanup failed: \(EngineError.message(for: cleanupFailure))",
                retryFailure.map { "durable quarantine retry failed: \(EngineError.message(for: $0))" },
            ].compactMap { $0 }.joined(separator: "; ")
        }

        await reconcileExecs(for: record.id)
        guard let current = try? containerIndex(record.id) else {
            clearCleanupPending(record.id)
            do {
                try await persist()
                return nil
            } catch {
                return EngineError.message(for: error)
            }
        }
        var stopped = snapshot.containers[current]
        stopped.phase = .exited
        stopped.finishedAt = Date()
        stopped.exitCode = stopCode ?? 137
        do {
            try await persistResourceContainmentCompletion(stopped)
        } catch {
            guard let quarantined = try? containerIndex(record.id) else {
                return "backend teardown succeeded but the safe terminal state could not be persisted: \(EngineError.message(for: error))"
            }
            snapshot.containers[quarantined].phase = .dead
            markCleanupPending(record.id)
            return "backend teardown succeeded but the safe terminal state could not be persisted: \(EngineError.message(for: error))"
        }
        resumeExitWaiters(record.id, code: stopped.exitCode ?? 137)
        emit(containerEvent("die", stopped, extra: ["exitCode": String(stopped.exitCode ?? 137)]))
        return nil
    }

    private func markCleanupPending(_ identifier: String) {
        var pending = snapshot.cleanupPendingContainerIDs ?? []
        pending.insert(identifier)
        snapshot.cleanupPendingContainerIDs = pending
        markContainerFenceIdentity(identifier)
    }

    private func clearCleanupPending(_ identifier: String) {
        guard var pending = snapshot.cleanupPendingContainerIDs else { return }
        pending.remove(identifier)
        snapshot.cleanupPendingContainerIDs = pending.isEmpty ? nil : pending
        clearContainerFenceIdentityIfUnused(identifier)
    }

    private func markRemovalPending(_ identifier: String, removeVolumes: Bool) {
        var pending = snapshot.removalPendingContainerIDs ?? []
        pending.insert(identifier)
        snapshot.removalPendingContainerIDs = pending
        markContainerFenceIdentity(identifier)
        guard removeVolumes else { return }
        var volumePending = snapshot.removalVolumesPendingContainerIDs ?? []
        volumePending.insert(identifier)
        snapshot.removalVolumesPendingContainerIDs = volumePending
    }

    private func clearRemovalPending(_ identifier: String) {
        if var pending = snapshot.removalPendingContainerIDs {
            pending.remove(identifier)
            snapshot.removalPendingContainerIDs = pending.isEmpty ? nil : pending
        }
        if var volumePending = snapshot.removalVolumesPendingContainerIDs {
            volumePending.remove(identifier)
            snapshot.removalVolumesPendingContainerIDs = volumePending.isEmpty ? nil : volumePending
        }
        clearContainerFenceIdentityIfUnused(identifier)
    }

    private func markContainerFenceIdentity(_ identifier: String) {
        guard let record = snapshot.containers.first(where: { $0.id == identifier }) else {
            return
        }
        var identities = snapshot.containerFenceInstanceIDs ?? [:]
        if let existing = identities[identifier], existing != record.instanceID {
            return
        }
        identities[identifier] = record.instanceID
        snapshot.containerFenceInstanceIDs = identities
    }

    private func clearContainerFenceIdentityIfUnused(_ identifier: String) {
        guard snapshot.cleanupPendingContainerIDs?.contains(identifier) != true,
              snapshot.removalPendingContainerIDs?.contains(identifier) != true,
              snapshot.removalVolumesPendingContainerIDs?.contains(identifier) != true,
              var identities = snapshot.containerFenceInstanceIDs else { return }
        identities.removeValue(forKey: identifier)
        snapshot.containerFenceInstanceIDs = identities.isEmpty ? nil : identities
    }

    /// Publish definitive removal as one durable transition. The container
    /// record, every cleanup/removal fence, and any resource-update journal are
    /// removed together. Until the save succeeds the live snapshot continues
    /// to reserve the original ID/name and retains the recovery journal.
    private func persistContainerRemovalCommit(
        expected: ContainerRecord
    ) async throws -> ContainerRecord {
        try await acquirePersistence()
        defer { releasePersistence() }
        try await beforePersistence?()

        var value = snapshot
        guard let valueIndex = value.containers.firstIndex(where: {
            Self.resourceUpdateIdentityMatches($0, expected)
        }) else {
            throw EngineError(.conflict, "container \(expected.id) changed during removal")
        }
        if let intent = value.resourceUpdateIntents?.first(where: {
            $0.containerID == expected.id
        }), !Self.resourceUpdateIntentIsValid(intent, current: value.containers[valueIndex]) {
            throw EngineError(.internalError, "resource update intent does not belong to removed container \(expected.id)")
        }
        value.containers.remove(at: valueIndex)
        Self.clearContainerFences(expected.id, from: &value)
        Self.removeResourceIntent(expected.id, from: &value)
        do {
            try await saveEngineSnapshot(value)
        } catch let ambiguity as AtomicStorePersistenceAmbiguousError {
            switch classifyRemovalCommit(expected: expected) {
            case .absent:
                do {
                    try await saveEngineSnapshot(snapshot)
                } catch let repeated as AtomicStorePersistenceAmbiguousError {
                    switch classifyRemovalCommit(expected: expected) {
                    case .absent:
                        purgeExecRecords(ownedBy: expected)
                        throw LandedRemovalCommitCouldNotBeReconfirmed(
                            underlying: repeated
                        )
                    case .fencedOld:
                        throw repeated
                    case .unknown:
                        throw RemovalCommitStateCouldNotBeClassified(
                            underlying: repeated
                        )
                    }
                } catch let reload as AmbiguousSnapshotReload {
                    throw RemovalCommitStateCouldNotBeClassified(
                        underlying: reload
                    )
                } catch {
                    purgeExecRecords(ownedBy: expected)
                    throw LandedRemovalCommitCouldNotBeReconfirmed(
                        underlying: error
                    )
                }
            case .fencedOld:
                throw ambiguity
            case .unknown:
                throw RemovalCommitStateCouldNotBeClassified(
                    underlying: EngineError(
                        .internalError,
                        "container removal commit for \(expected.id) has an unclassifiable durable state after: "
                            + ambiguity.localizedDescription
                    )
                )
            }
        } catch let reload as AmbiguousSnapshotReload {
            throw RemovalCommitStateCouldNotBeClassified(underlying: reload)
        }

        guard let current = snapshot.containers.firstIndex(where: {
            Self.resourceUpdateIdentityMatches($0, expected)
        }) else {
            purgeExecRecords(ownedBy: expected)
            return expected
        }
        let removed = snapshot.containers.remove(at: current)
        Self.clearContainerFences(expected.id, from: &snapshot)
        Self.removeResourceIntent(expected.id, from: &snapshot)
        purgeExecRecords(ownedBy: removed)
        return removed
    }

    private func purgeExecRecords(ownedBy container: ContainerRecord) {
        let identifiers = Self.execIdentifiersOwned(by: container, in: execs)
        for identifier in identifiers {
            execs.removeValue(forKey: identifier)
            startingExecIDs.remove(identifier)
        }
    }

    static func execIdentifiersOwned(
        by container: ContainerRecord,
        in records: [String: ExecRecord]
    ) -> [String] {
        records.compactMap { identifier, exec in
            exec.containerID == container.id
                && exec.containerInstanceID == container.instanceID ? identifier : nil
        }
    }

    private func classifyRemovalCommit(
        expected: ContainerRecord
    ) -> RemovalCommitReconciliation {
        let sameInstance = snapshot.containers.contains(where: {
            Self.resourceUpdateIdentityMatches($0, expected)
        })
        let conflictingIdentity = snapshot.containers.contains(where: {
            $0.id == expected.id || $0.name == expected.name
        }) && !sameInstance
        let hasFence = snapshot.cleanupPendingContainerIDs?.contains(expected.id) == true
            || snapshot.removalPendingContainerIDs?.contains(expected.id) == true
            || snapshot.removalVolumesPendingContainerIDs?.contains(expected.id) == true
            || snapshot.resourceUpdateIntents?.contains(where: {
                $0.containerID == expected.id
            }) == true
        let fenceMatches = snapshot.containerFenceInstanceIDs?[expected.id]
            == expected.instanceID
        if !sameInstance, !conflictingIdentity, !hasFence { return .absent }
        if sameInstance,
           fenceMatches,
           snapshot.removalPendingContainerIDs?.contains(expected.id) == true,
           snapshot.cleanupPendingContainerIDs?.contains(expected.id) == true {
            return .fencedOld
        }
        return .unknown
    }

    private static func clearContainerFences(
        _ identifier: String,
        from snapshot: inout EngineSnapshot
    ) {
        if var cleanup = snapshot.cleanupPendingContainerIDs {
            cleanup.remove(identifier)
            snapshot.cleanupPendingContainerIDs = cleanup.isEmpty ? nil : cleanup
        }
        if var removal = snapshot.removalPendingContainerIDs {
            removal.remove(identifier)
            snapshot.removalPendingContainerIDs = removal.isEmpty ? nil : removal
        }
        if var volumes = snapshot.removalVolumesPendingContainerIDs {
            volumes.remove(identifier)
            snapshot.removalVolumesPendingContainerIDs = volumes.isEmpty ? nil : volumes
        }
        if var identities = snapshot.containerFenceInstanceIDs {
            identities.removeValue(forKey: identifier)
            snapshot.containerFenceInstanceIDs = identities.isEmpty ? nil : identities
        }
    }

    private func reserveRemovalPublication(
        _ record: ContainerRecord,
        removedVolumes: [VolumeRecord]
    ) -> RemovalPublicationReservation {
        let volumeNames = Set(removedVolumes.map(\.name))
        pendingContainerNames[record.name] = record.id
        pendingContainerIDs.insert(record.id)
        pendingContainerInstances[record.id] = record.instanceID
        for name in volumeNames {
            pendingVolumeNames[name, default: 0] += 1
        }
        return RemovalPublicationReservation(
            containerID: record.id,
            containerInstanceID: record.instanceID,
            containerName: record.name,
            volumeNames: volumeNames
        )
    }

    private func releaseRemovalPublication(_ reservation: RemovalPublicationReservation) {
        if pendingContainerNames[reservation.containerName] == reservation.containerID {
            pendingContainerNames.removeValue(forKey: reservation.containerName)
        }
        if pendingContainerInstances[reservation.containerID]
            == reservation.containerInstanceID {
            pendingContainerInstances.removeValue(forKey: reservation.containerID)
            pendingContainerIDs.remove(reservation.containerID)
        }
        for name in reservation.volumeNames {
            guard let count = pendingVolumeNames[name] else { continue }
            if count == 1 { pendingVolumeNames.removeValue(forKey: name) }
            else { pendingVolumeNames[name] = count - 1 }
        }
    }

    private func cleanupIsPending(_ identifier: String) -> Bool {
        snapshot.cleanupPendingContainerIDs?.contains(identifier) == true
    }

    private func resourceUpdateIsPending(_ identifier: String) -> Bool {
        snapshot.resourceUpdateIntents?.contains(where: { $0.containerID == identifier }) == true
    }

    private func resourceUpdateReservation(for candidate: ContainerRecord) -> String? {
        snapshot.resourceUpdateIntents?.first(where: {
            $0.containerID == candidate.id
                || $0.old.id == candidate.id
                || $0.desired.id == candidate.id
                || $0.old.name == candidate.name
                || $0.desired.name == candidate.name
        })?.containerID
    }

    /// Reject every backend operation that could attach to or mutate an
    /// execution while its identity is unverifiable. The durable marker is the
    /// primary fence during actor reentrancy; `.dead` keeps the public record in
    /// quarantine after cleanup returns an error.
    func requireBackendExecutionAvailable(_ record: ContainerRecord) throws {
        guard !cleanupIsPending(record.id), !resourceUpdateIsPending(record.id), record.phase != .dead else {
            throw EngineError(.conflict, "container \(record.id) has backend cleanup pending")
        }
    }

    private func quarantineCleanupPendingContainer(_ identifier: String) {
        guard let index = try? containerIndex(identifier) else { return }
        // Preserve the generation's timestamps and exit result. In particular,
        // the old generation may have completed while an explicit restart was
        // suspended, and that real result must remain the sole die event.
        snapshot.containers[index].phase = .dead
    }

    private func quarantineRemovalPendingContainer(
        _ identifier: String,
        record: ContainerRecord,
        removeVolumes: Bool
    ) {
        if let index = try? containerIndex(identifier) {
            var quarantined = snapshot.containers[index]
            quarantined.phase = .dead
            snapshot.containers[index] = quarantined
        } else {
            var quarantined = record
            quarantined.phase = .dead
            snapshot.containers.append(quarantined)
        }
        markCleanupPending(identifier)
        markRemovalPending(identifier, removeVolumes: removeVolumes)
    }

    /// Publish a successful force-stop without allowing restart policy or
    /// auto-remove reconciliation to run ahead of the explicit removal claim.
    /// The container remains publicly quarantined until final removal commits.
    private func recordForcedRemovalStop(
        _ identifier: String,
        startedAt: Date?,
        code: Int32,
        intent: LifecycleIntent
    ) async throws {
        guard lifecycleIntents[identifier] == intent,
              let index = snapshot.containers.firstIndex(where: { $0.id == identifier }),
              snapshot.containers[index].startedAt == startedAt else {
            throw EngineError(.conflict, "container \(identifier) removal reservation was lost")
        }
        cancelCompletionMonitor(identifier)
        healthTasks.removeValue(forKey: identifier)?.cancel()
        snapshot.containers[index].phase = .dead
        snapshot.containers[index].exitCode = code
        snapshot.containers[index].finishedAt = Date()
        markCleanupPending(identifier)
        let stopped = snapshot.containers[index]
        resumeExitWaiters(identifier, code: code)
        emit(containerEvent("die", stopped, extra: ["exitCode": String(code)]))
        await reconcileExecs(for: identifier)
        guard lifecycleIntents[identifier] == intent,
              let current = snapshot.containers.firstIndex(where: { $0.id == identifier }) else {
            throw EngineError(.conflict, "container \(identifier) removal reservation was lost")
        }
        snapshot.containers[current].phase = .dead
        markCleanupPending(identifier)
    }

    /// A backend start can partially launch before throwing, or succeed before
    /// publishing the running record fails. The pre-launch cleanup marker stays
    /// set until definitive teardown and restoration are both durable.
    private func rollbackFailedStart(original: ContainerRecord, started: ContainerRecord) async throws {
        healthTasks.removeValue(forKey: original.id)?.cancel()
        cancelCompletionMonitor(original.id)
        markCleanupPending(original.id)
        // This is normally a repeat of the marker save performed before launch.
        // Best-effort persistence also covers a failure detected after a
        // successful running publication.
        try? await persist()
        guard (try? containerIndex(original.id)) != nil else {
            try await cleanupBackendExecution(started)
            clearCleanupPending(original.id)
            try await persist()
            return
        }
        do {
            try await cleanupBackendExecution(started)
        } catch {
            quarantineCleanupPendingContainer(original.id)
            // The original pre-launch save is the safety boundary. These
            // bounded retries improve diagnostics/durability when storage
            // transiently recovers, but correctness does not depend on them.
            try? await persist()
            throw error
        }
        guard let restored = try? containerIndex(original.id) else {
            clearCleanupPending(original.id)
            try await persist()
            return
        }
        snapshot.containers[restored] = original
        clearCleanupPending(original.id)
        do {
            try await persist()
        } catch {
            markCleanupPending(original.id)
            throw error
        }
    }

    /// `ContainerBackend.restart` may have already stopped the old execution or
    /// launched its replacement before throwing. Compensate by publishing a
    /// terminal generation under the restart claim, then cleaning every backend
    /// execution. Restart-policy and auto-remove reconciliation runs only after
    /// the caller releases that claim.
    private func terminalizeFailedRestart(_ original: ContainerRecord, intent: LifecycleIntent) async throws {
        healthTasks.removeValue(forKey: original.id)?.cancel()
        cancelCompletionMonitor(original.id)
        markCleanupPending(original.id)
        try? await persist()

        guard lifecycleIntents[original.id] == intent,
              (try? containerIndex(original.id)) != nil else {
            try await cleanupBackendExecution(original)
            clearCleanupPending(original.id)
            try await persist()
            return
        }
        do {
            try await cleanupBackendExecution(original)
        } catch {
            quarantineCleanupPendingContainer(original.id)
            try? await persist()
            throw error
        }

        await reconcileExecs(for: original.id)
        guard let terminal = try? containerIndex(original.id) else {
            clearCleanupPending(original.id)
            try await persist()
            return
        }
        let completedOldGeneration = snapshot.containers[terminal].phase == .exited
            && snapshot.containers[terminal].startedAt == original.startedAt
            && snapshot.containers[terminal].exitCode != nil
        var failed = snapshot.containers[terminal]
        if !completedOldGeneration {
            failed.phase = .exited
            failed.startedAt = original.startedAt
            failed.finishedAt = Date()
            failed.exitCode = 127
            failed.restartCount = original.restartCount
            snapshot.containers[terminal] = failed
        }
        clearCleanupPending(original.id)
        do {
            try await persist()
        } catch {
            markCleanupPending(original.id)
            throw error
        }
        if !completedOldGeneration {
            resumeExitWaiters(original.id, code: 127)
            emit(containerEvent("die", failed, extra: ["exitCode": "127"]))
        }
    }

    /// `delete` is the backend's definitive teardown operation. Always attempt
    /// it after a stop failure; a successful delete verifies cleanup on its own,
    /// while a delete failure retains the quarantine and includes any preceding
    /// stop failure as diagnostic context.
    @discardableResult
    private func cleanupBackendExecution(
        _ record: ContainerRecord,
        publishRemovalStopResult: Bool = false
    ) async throws -> Int32? {
        var stopFailure: String?
        var stopCode: Int32?
        do {
            stopCode = try await backend.stop(record, timeoutSeconds: 0)
            if publishRemovalStopResult, let stopCode,
               let current = try? containerIndex(record.id),
               snapshot.containers[current].exitCode == nil {
                // A successful stop is authoritative even if the following
                // delete fails. Publish it before crossing that second backend
                // boundary so default waiters cannot remain stranded in a
                // quarantined, already-stopped generation.
                snapshot.containers[current].exitCode = stopCode
                snapshot.containers[current].finishedAt = Date()
                resumeExitWaiters(record.id, code: stopCode)
            }
        } catch {
            stopFailure = EngineError.message(for: error)
        }
        do {
            try await backend.delete(record)
            return stopCode
        } catch {
            let failures = [stopFailure.map { "stop: \($0)" }, "delete: \(EngineError.message(for: error))"]
                .compactMap { $0 }
            throw EngineError(
                .internalError,
                "backend cleanup for container \(record.id) could not be verified (\(failures.joined(separator: "; ")))"
            )
        }
    }

    /// Drain explicit remove/prune intents before any generic execution
    /// recovery. The record and both fences remain durable until backend,
    /// logs, requested anonymous volumes, and metadata have all been removed.
    private func resolvePendingContainerRemovals() async throws {
        let pendingRemovalIDs = snapshot.removalPendingContainerIDs ?? []
        for identifier in pendingRemovalIDs {
            guard let fencedIndex = try? containerIndex(identifier) else {
                throw EngineError(
                    .internalError,
                    "container removal is pending for missing container record \(identifier)"
                )
            }
            let removed = snapshot.containers[fencedIndex]
            let removeVolumes = snapshot.removalVolumesPendingContainerIDs?.contains(identifier) == true
            let removedVolumeMetadata = removeVolumes ? anonymousVolumeMetadata(usedBy: removed) : []

            // Normalize partially written/corrupt intent state before teardown.
            // A failed save here must leave the backend completely untouched.
            snapshot.containers[fencedIndex].phase = .dead
            markCleanupPending(identifier)
            markRemovalPending(identifier, removeVolumes: removeVolumes)
            try await persist()

            do {
                try await cleanupBackendExecution(removed)
                try await backend.deleteLogs(for: removed)
                if removeVolumes { try await removeAnonymousVolumes(usedBy: removed) }
            } catch {
                quarantineRemovalPendingContainer(identifier, record: removed, removeVolumes: removeVolumes)
                try? await persist()
                throw error
            }

            guard let current = try? containerIndex(identifier) else {
                throw EngineError(.internalError, "container \(identifier) disappeared during removal recovery")
            }
            do {
                _ = try await persistContainerRemovalCommit(
                    expected: snapshot.containers[current]
                )
            } catch let uncertain as LandedRemovalCommitCouldNotBeReconfirmed {
                throw uncertain.underlying
            } catch let unclassified as RemovalCommitStateCouldNotBeClassified {
                throw unclassified.underlying
            } catch {
                restoreRemovedVolumeMetadata(removedVolumeMetadata)
                quarantineRemovalPendingContainer(
                    identifier, record: removed, removeVolumes: removeVolumes
                )
                try? await persist()
                throw error
            }
        }
    }

    private func anonymousVolumeMetadata(
        usedBy record: ContainerRecord
    ) -> [(offset: Int, element: VolumeRecord)] {
        let names = Set(record.mounts.filter { $0.kind == .volume }.map(\.source))
        return snapshot.volumes.enumerated().filter {
            names.contains($0.element.name) && $0.element.anonymous == true
        }
    }

    private func restoreRemovalQuarantine(
        _ record: ContainerRecord,
        at index: Int,
        removeVolumes: Bool,
        removedVolumes: [(offset: Int, element: VolumeRecord)]
    ) {
        if let existing = snapshot.containers.firstIndex(where: {
            Self.resourceUpdateIdentityMatches($0, record)
        }) {
            // Preserve mutations to the original object made by unrelated
            // actor work; removal owns only its quarantine and durable fences.
            snapshot.containers[existing].phase = .dead
        } else if !snapshot.containers.contains(where: {
            $0.id == record.id || $0.name == record.name
        }) {
            var quarantined = record
            quarantined.phase = .dead
            snapshot.containers.insert(quarantined, at: min(index, snapshot.containers.endIndex))
        }
        for volume in removedVolumes.sorted(by: { $0.offset < $1.offset })
            where !snapshot.volumes.contains(where: { $0.name == volume.element.name }) {
            snapshot.volumes.insert(volume.element, at: min(volume.offset, snapshot.volumes.endIndex))
        }
        markCleanupPending(record.id)
        markRemovalPending(record.id, removeVolumes: removeVolumes)
    }

    private func restoreRemovedVolumeMetadata(
        _ removedVolumes: [(offset: Int, element: VolumeRecord)]
    ) {
        for volume in removedVolumes.sorted(by: { $0.offset < $1.offset })
            where !snapshot.volumes.contains(where: { $0.name == volume.element.name }) {
            snapshot.volumes.insert(
                volume.element, at: min(volume.offset, snapshot.volumes.endIndex)
            )
        }
    }

    /// Finish startup reconciliation for terminal auto-remove records. A fresh
    /// record is fenced before teardown; one already cleaned through a pending
    /// marker reuses that proof so recovery never issues a duplicate delete.
    private func removeRecoveredAutoRemoveContainers(
        verifiedCleanupIDs input: Set<String>
    ) async throws -> Set<String> {
        var verifiedCleanupIDs = input
        let recoveredAutoRemoveIDs = snapshot.containers.compactMap { record in
            record.autoRemove && record.phase == .exited ? record.id : nil
        }
        for identifier in recoveredAutoRemoveIDs {
            guard let index = try? containerIndex(identifier) else { continue }
            let removed = snapshot.containers[index]
            guard !resourceUpdateIsPending(identifier) else { continue }
            let removedVolumeMetadata = anonymousVolumeMetadata(usedBy: removed)
            if !verifiedCleanupIDs.contains(identifier) {
                markCleanupPending(identifier)
                try await persist()
                do {
                    try await cleanupBackendExecution(removed)
                } catch {
                    quarantineCleanupPendingContainer(identifier)
                    try? await persist()
                    throw error
                }
                verifiedCleanupIDs.insert(identifier)
            }
            try await backend.deleteLogs(for: removed)
            try await removeAnonymousVolumes(usedBy: removed)
            guard let current = try? containerIndex(identifier) else { continue }
            do {
                _ = try await persistContainerRemovalCommit(
                    expected: snapshot.containers[current]
                )
            } catch let uncertain as LandedRemovalCommitCouldNotBeReconfirmed {
                throw uncertain.underlying
            } catch let unclassified as RemovalCommitStateCouldNotBeClassified {
                throw unclassified.underlying
            } catch {
                restoreRemovedVolumeMetadata(removedVolumeMetadata)
                quarantineCleanupPendingContainer(identifier)
                markCleanupPending(identifier)
                try? await persist()
                throw error
            }
        }
        return verifiedCleanupIDs
    }

    public func events(since: Date? = nil, until: Date? = nil) -> AsyncStream<RuntimeEvent> {
        let id = UUID()
        let (stream, continuation) = AsyncStream.makeStream(of: RuntimeEvent.self)
        for event in eventHistory where (since == nil || event.date >= since!) && (until == nil || event.date <= until!) {
            continuation.yield(event)
        }
        if let until, until <= Date() {
            continuation.finish()
            return stream
        }
        eventContinuations[id] = continuation
        continuation.onTermination = { [weak self] _ in Task { await self?.removeEventContinuation(id) } }
        if let until {
            Task {
                let delay = max(until.timeIntervalSinceNow, 0)
                try? await Task.sleep(for: .seconds(delay))
                continuation.finish()
            }
        }
        return stream
    }

    private func removeEventContinuation(_ id: UUID) { eventContinuations.removeValue(forKey: id) }
    private func emit(_ event: RuntimeEvent) {
        eventHistory.append(event)
        if eventHistory.count > 256 { eventHistory.removeFirst(eventHistory.count - 256) }
        eventContinuations.values.forEach { $0.yield(event) }
    }
    func emitImageEvent(_ action: String, id: String, name: String) {
        emit(RuntimeEvent(type: "image", action: action, id: id, attributes: ["name": name]))
    }
    private static func familiarImageReference(_ reference: String) -> String {
        if reference.hasPrefix("docker.io/library/") {
            return String(reference.dropFirst("docker.io/library/".count))
        }
        if reference.hasPrefix("docker.io/") {
            return String(reference.dropFirst("docker.io/".count))
        }
        return reference
    }
    private static func familiarImageName(_ reference: String) -> String {
        let familiar = familiarImageReference(reference)
        let withoutDigest = familiar.split(separator: "@", maxSplits: 1).first.map(String.init) ?? familiar
        let slash = withoutDigest.lastIndex(of: "/")
        guard let colon = withoutDigest.lastIndex(of: ":") else {
            return withoutDigest
        }
        if let slash, colon < slash { return withoutDigest }
        return String(withoutDigest[..<colon])
    }
    private func containerEvent(_ action: String, _ record: ContainerRecord,
                                extra: [String: String] = [:]) -> RuntimeEvent {
        RuntimeEvent(type: "container", action: action, id: record.id,
                     attributes: record.labels.merging(["name": record.name, "image": record.image]) { current, _ in current }
                        .merging(extra) { _, new in new })
    }

    private func startHealthMonitor(_ identifier: String) {
        healthTasks.removeValue(forKey: identifier)?.cancel()
        guard let record = try? container(identifier), record.healthcheck != nil else { return }
        healthTasks[identifier] = Task { [weak self] in await self?.runHealthMonitor(identifier) }
    }

    private func removeAnonymousVolumes(usedBy record: ContainerRecord) async throws {
        let names = Set(record.mounts.filter { $0.kind == .volume }.map(\.source))
        let removable = snapshot.volumes.filter { names.contains($0.name) && $0.anonymous == true }
        for volume in removable { try await backend.deleteVolume(volume.name) }
        let removedNames = Set(removable.map(\.name))
        snapshot.volumes.removeAll { removedNames.contains($0.name) }
    }

    private func runHealthMonitor(_ identifier: String) async {
        guard let initial = try? container(identifier), let health = initial.healthcheck else { return }
        let startedAt = initial.startedAt
        if health.startPeriodNanoseconds > 0 {
            do {
                try await Task.sleep(for: .nanoseconds(health.startPeriodNanoseconds))
            } catch {
                return
            }
        }
        while !Task.isCancelled {
            guard let index = try? containerIndex(identifier),
                  snapshot.containers[index].phase == .running,
                  snapshot.containers[index].startedAt == startedAt else { return }
            if resourceUpdateIsPending(identifier) || cleanupIsPending(identifier) {
                do {
                    try await Task.sleep(for: .milliseconds(25))
                } catch {
                    return
                }
                continue
            }
            let record = snapshot.containers[index]
            let arguments: [String]
            switch health.test.first {
            case "CMD": arguments = Array(health.test.dropFirst())
            case "CMD-SHELL": arguments = ["/bin/sh", "-c", health.test.dropFirst().joined(separator: " ")]
            default: arguments = health.test
            }
            guard !arguments.isEmpty else { return }
            let result = try? await backend.runHealthcheck(
                record, arguments: arguments,
                timeoutSeconds: max(1, health.timeoutNanoseconds / 1_000_000_000)
            )
            guard !Task.isCancelled,
                  let current = try? containerIndex(identifier),
                  snapshot.containers[current].phase == .running,
                  snapshot.containers[current].startedAt == startedAt else { return }
            if result?.exitCode == 0 {
                snapshot.containers[current].healthStatus = "healthy"
                snapshot.containers[current].healthFailingStreak = 0
            } else {
                let failures = (snapshot.containers[current].healthFailingStreak ?? 0) + 1
                snapshot.containers[current].healthFailingStreak = failures
                snapshot.containers[current].healthStatus = failures >= max(health.retries, 1) ? "unhealthy" : "starting"
            }
            let status = snapshot.containers[current].healthStatus ?? "starting"
            emit(containerEvent("health_status: \(status)", snapshot.containers[current]))
            try? await persist()
            let delay = max(health.intervalNanoseconds, 100_000_000)
            do {
                try await Task.sleep(for: .nanoseconds(delay))
            } catch {
                return
            }
        }
    }

    private static func imageRecords(from images: [BackendImage]) -> [ImageRecord] {
        Dictionary(grouping: images, by: \ .id).map { id, values in
            let preferred = values.first(where: { $0.preferredManifestDigest != nil }) ?? values[0]
            return ImageRecord(
                id: id,
                references: Array(Set(values.map(\ .reference))).sorted(),
                createdAt: values.map(\ .createdAt).min() ?? Date(timeIntervalSince1970: 0),
                size: values.map(\ .size).max() ?? 0,
                architecture: preferred.architecture,
                os: preferred.os,
                targetDescriptor: preferred.targetDescriptor,
                manifests: preferred.manifests,
                preferredManifestDigest: preferred.preferredManifestDigest,
                identity: preferred.identity
            )
        }.sorted { $0.references.first ?? "" < $1.references.first ?? "" }
    }

    private func startCompletionMonitor(_ identifier: String, startedAt: Date) {
        cancelCompletionMonitor(identifier)
        let token = UUID()
        let beforeCompletionMonitoring = beforeCompletionMonitoring
        let task = Task<Void, Never> { [weak self] in
            await beforeCompletionMonitoring?()
            guard let self else { return }
            await self.monitorContainer(identifier, startedAt: startedAt, token: token)
        }
        completionMonitorTasks[identifier] = (token, task)
    }

    private func monitorContainer(_ identifier: String, startedAt: Date, token: UUID) async {
        defer { removeCompletionMonitor(identifier, token: token) }
        while !Task.isCancelled {
            guard let record = try? container(identifier),
                  record.startedAt == startedAt,
                  record.phase == .running || record.phase == .paused else { return }
            guard let code = await backend.completion(record) else {
                // A backend that has observed process exit may still be
                // retrying its durable final log drain. Retain this exact
                // execution monitor and retry without inventing an exit code.
                try? await Task.sleep(for: .milliseconds(25))
                continue
            }
            guard !Task.isCancelled else { return }
            await recordCompletion(
                identifier, startedAt: startedAt, code: code, monitorToken: token
            )
            return
        }
    }

    private func cancelCompletionMonitor(_ identifier: String, preserving token: UUID? = nil) {
        guard let monitor = completionMonitorTasks.removeValue(forKey: identifier) else { return }
        if monitor.token != token { monitor.task.cancel() }
    }

    private func removeCompletionMonitor(_ identifier: String, token: UUID) {
        guard completionMonitorTasks[identifier]?.token == token else { return }
        completionMonitorTasks.removeValue(forKey: identifier)
    }

    private func recordCompletion(
        _ identifier: String,
        startedAt: Date?,
        code: Int32,
        monitorToken: UUID? = nil
    ) async {
        guard let index = try? containerIndex(identifier),
              snapshot.containers[index].phase == .running || snapshot.containers[index].phase == .paused,
              snapshot.containers[index].startedAt == startedAt else { return }
        cancelCompletionMonitor(identifier, preserving: monitorToken)
        snapshot.containers[index].phase = .exited
        snapshot.containers[index].exitCode = code
        snapshot.containers[index].finishedAt = Date()
        resumeExitWaiters(identifier, code: code)
        let record = snapshot.containers[index]
        let intent = lifecycleIntents[identifier]
        healthTasks.removeValue(forKey: record.id)?.cancel()
        emit(containerEvent("die", record, extra: ["exitCode": String(code)]))
        await reconcileExecs(for: identifier)
        await reconcileCompletedContainer(identifier, code: code, suppressing: intent)
    }

    private func reconcileDeferredCompletion(_ identifier: String) async {
        guard lifecycleIntents[identifier] == nil,
              !cleanupIsPending(identifier),
              !resourceUpdateIsPending(identifier),
              let index = try? containerIndex(identifier),
              snapshot.containers[index].phase == .exited,
              let code = snapshot.containers[index].exitCode else { return }
        await reconcileCompletedContainer(identifier, code: code, suppressing: nil)
    }

    private func reconcileCompletedContainer(
        _ identifier: String,
        code: Int32,
        suppressing intent: LifecycleIntent?
    ) async {
        guard let index = try? containerIndex(identifier),
              snapshot.containers[index].phase == .exited else { return }
        guard !resourceUpdateIsPending(identifier) else {
            // The resource journal fences backend reconciliation, but the
            // independently observed process exit is still durable state.
            try? await persist()
            return
        }
        let autoRemove = snapshot.containers[index].autoRemove
        let record = snapshot.containers[index]
        if intent == nil, !autoRemove, !cleanupIsPending(identifier), Self.shouldRestart(record, exitCode: code) {
            let restartIntent: LifecycleIntent
            do {
                restartIntent = try beginLifecycleIntent(.restart, for: identifier)
            } catch {
                return
            }
            guard startingContainerIDs.insert(identifier).inserted else {
                endLifecycleIntent(restartIntent, for: identifier)
                return
            }
            defer {
                startingContainerIDs.remove(identifier)
                endLifecycleIntent(restartIntent, for: identifier)
            }
            var crossedLaunchBoundary = false
            do {
                var restarted = record; restarted.restartCount += 1
                try await backend.delete(record)
                guard ownsReconciliation(restartIntent, record: record) else { return }
                try await backend.prepare(restarted)
                guard ownsReconciliation(restartIntent, record: record) else { return }
                markCleanupPending(identifier)
                do {
                    try await persist()
                } catch {
                    clearCleanupPending(identifier)
                    throw error
                }
                guard ownsReconciliation(restartIntent, record: record) else {
                    clearCleanupPending(identifier)
                    try await persist()
                    return
                }
                crossedLaunchBoundary = true
                restarted.ports = try await backend.start(restarted)
                guard ownsReconciliation(restartIntent, record: record) else {
                    throw EngineError(.conflict, "container changed while restart policy was launching it")
                }
                restarted = await applyingEndpointAddresses(to: restarted)
                guard ownsReconciliation(restartIntent, record: record),
                      let current = try? containerIndex(identifier) else {
                    throw EngineError(.conflict, "container changed while restart policy was publishing it")
                }
                restarted.phase = .running; restarted.exitCode = nil; restarted.finishedAt = nil
                let restartedAt = Date(); restarted.startedAt = restartedAt
                snapshot.containers[current] = restarted
                clearCleanupPending(identifier)
                try await persist(); emit(containerEvent("restart", restarted)); startHealthMonitor(identifier)
                startCompletionMonitor(identifier, startedAt: restartedAt)
                return
            } catch {
                guard crossedLaunchBoundary else { return }
                markCleanupPending(identifier)
                do {
                    try await cleanupBackendExecution(record)
                    if let current = try? containerIndex(identifier) {
                        snapshot.containers[current].phase = .exited
                        snapshot.containers[current].startedAt = record.startedAt
                        snapshot.containers[current].finishedAt = record.finishedAt
                        snapshot.containers[current].exitCode = record.exitCode
                        snapshot.containers[current].restartCount = record.restartCount
                    }
                    clearCleanupPending(identifier)
                    do {
                        try await persist()
                    } catch {
                        markCleanupPending(identifier)
                    }
                } catch {
                    // The pre-launch marker is already durable. Recovery must
                    // verify teardown before this record can launch again.
                    quarantineCleanupPendingContainer(identifier)
                    try? await persist()
                }
            }
            return
        }

        if autoRemove, intent == nil || intent?.operation == .stop {
            let removeIntent: LifecycleIntent
            let ownsIntent: Bool
            if let intent {
                guard lifecycleIntents[identifier] == intent else { return }
                removeIntent = intent
                ownsIntent = false
            } else {
                do {
                    removeIntent = try beginLifecycleIntent(.remove, for: identifier)
                } catch {
                    return
                }
                ownsIntent = true
            }
            defer {
                if ownsIntent { endLifecycleIntent(removeIntent, for: identifier) }
            }
            guard ownsReconciliation(removeIntent, record: record) else { return }
            guard !resourceUpdateIsPending(identifier) else { return }
            if !cleanupIsPending(identifier) {
                // Publish the cleanup fence before crossing the backend
                // teardown boundary. If the save fails, leave the terminal
                // record intact and do not risk losing track of its execution.
                markCleanupPending(identifier)
                do {
                    try await persist()
                } catch {
                    // Keep the live daemon fenced even when the first durable
                    // cleanup marker cannot be published. The terminal result
                    // remains intact while `.dead` prevents any backend
                    // operation from trusting the residual execution. If this
                    // bounded retry also fails, startup recovery still sees the
                    // durable running auto-remove record and must reconcile it.
                    quarantineCleanupPendingContainer(identifier)
                    try? await persist()
                    return
                }
            }
            guard ownsReconciliation(removeIntent, record: record) else { return }
            do {
                try await cleanupBackendExecution(record)
            } catch {
                // Delete is the definitive cleanup proof. Retain both the
                // record and marker when it fails so reload must retry before
                // any restart policy or backend operation can proceed.
                quarantineCleanupPendingContainer(identifier)
                try? await persist()
                return
            }
            guard ownsReconciliation(removeIntent, record: record) else { return }
            try? await backend.deleteLogs(for: record)
            guard ownsReconciliation(removeIntent, record: record) else { return }
            let removedVolumeMetadata = anonymousVolumeMetadata(usedBy: record)
            try? await removeAnonymousVolumes(usedBy: record)
            guard ownsReconciliation(removeIntent, record: record),
                  let current = try? containerIndex(identifier) else { return }
            do {
                _ = try await persistContainerRemovalCommit(
                    expected: snapshot.containers[current]
                )
            } catch is LandedRemovalCommitCouldNotBeReconfirmed {
                // The container remains absent and the backend has already
                // been deleted. A later reload will select the canonical side;
                // never recreate the removed object in this daemon.
                return
            } catch is RemovalCommitStateCouldNotBeClassified {
                return
            } catch {
                // Backend deletion succeeded, but keep the cleanup fence in
                // memory when its metadata removal could not be committed.
                // The durable pending record will finish removal on reload.
                restoreRemovedVolumeMetadata(removedVolumeMetadata)
                quarantineCleanupPendingContainer(identifier)
                markCleanupPending(identifier)
                return
            }
            resumeRemovalWaiters(identifier, code: code)
            emit(containerEvent("destroy", record))
            return
        }
        try? await persist()
    }

    private func ownsReconciliation(_ intent: LifecycleIntent, record: ContainerRecord) -> Bool {
        guard lifecycleIntents[record.id] == intent,
              let index = try? containerIndex(record.id) else { return false }
        let current = snapshot.containers[index]
        return current.instanceID == record.instanceID
            && current.phase == .exited
            && current.startedAt == record.startedAt
            && current.exitCode == record.exitCode
    }

    private func ownsLifecycleExecution(_ intent: LifecycleIntent, record: ContainerRecord) -> Bool {
        guard lifecycleIntents[record.id] == intent,
              let index = try? containerIndex(record.id) else { return false }
        let current = snapshot.containers[index]
        return current.instanceID == record.instanceID
            && current.phase == record.phase
            && current.startedAt == record.startedAt
    }

    private func ownsRestartExecution(_ intent: LifecycleIntent, record: ContainerRecord) -> Bool {
        guard lifecycleIntents[record.id] == intent,
              let index = try? containerIndex(record.id) else { return false }
        let current = snapshot.containers[index]
        // The old execution may report its expected terminal transition while
        // backend.restart is replacing it. No other phase or generation change
        // is safe for this restart operation to overwrite.
        return current.instanceID == record.instanceID
            && (current.phase == record.phase || current.phase == .exited)
            && current.startedAt == record.startedAt
    }

    private func ownsNetworkMutation(
        _ intent: LifecycleIntent,
        record: ContainerRecord,
        networks: [NetworkEndpointRecord]
    ) -> Bool {
        guard ownsLifecycleExecution(intent, record: record),
              let index = try? containerIndex(record.id) else { return false }
        return snapshot.containers[index].networks == networks
    }

    private func beginLifecycleIntent(_ operation: LifecycleIntent.Operation, for identifier: String) throws -> LifecycleIntent {
        guard lifecycleIntents[identifier] == nil else {
            throw EngineError(.conflict, "container \(identifier) already has a lifecycle operation in progress")
        }
        let intent = LifecycleIntent(operation: operation)
        lifecycleIntents[identifier] = intent
        return intent
    }

    private func endLifecycleIntent(_ intent: LifecycleIntent, for identifier: String) {
        if lifecycleIntents[identifier] == intent { lifecycleIntents.removeValue(forKey: identifier) }
    }

    private func beginExecOperation(for containerID: String) throws {
        let record = try container(containerID)
        try requireBackendExecutionAvailable(record)
        guard record.phase == .running else {
            throw EngineError(.conflict, "Container \(containerID) is not running")
        }
        guard lifecycleIntents[containerID]?.operation != .restart else {
            throw EngineError(.conflict, "container \(containerID) is restarting")
        }
        activeExecOperations[containerID, default: 0] += 1
    }

    private func endExecOperation(for containerID: String) {
        guard let count = activeExecOperations[containerID] else { return }
        if count == 1 { activeExecOperations.removeValue(forKey: containerID) }
        else { activeExecOperations[containerID] = count - 1 }
    }

    private func waitSubscription(containerID: String, removal: Bool) -> ContainerWaitSubscription {
        let token = UUID()
        let (stream, continuation) = AsyncStream<Int32>.makeStream(bufferingPolicy: .bufferingNewest(1))
        continuation.onTermination = { [weak self] _ in
            Task { await self?.removeWaiter(containerID: containerID, token: token, removal: removal) }
        }
        if removal {
            removalWaiters[containerID, default: [:]][token] = continuation
        } else {
            exitWaiters[containerID, default: [:]][token] = continuation
        }
        return ContainerWaitSubscription(stream: stream)
    }

    private func immediateWaitSubscription(code: Int32) -> ContainerWaitSubscription {
        let (stream, continuation) = AsyncStream<Int32>.makeStream(bufferingPolicy: .bufferingNewest(1))
        continuation.yield(code)
        continuation.finish()
        return ContainerWaitSubscription(stream: stream)
    }

    private func removeWaiter(containerID: String, token: UUID, removal: Bool) {
        if removal {
            removalWaiters[containerID]?.removeValue(forKey: token)
            if removalWaiters[containerID]?.isEmpty == true { removalWaiters.removeValue(forKey: containerID) }
        } else {
            exitWaiters[containerID]?.removeValue(forKey: token)
            if exitWaiters[containerID]?.isEmpty == true { exitWaiters.removeValue(forKey: containerID) }
        }
    }

    private func resumeExitWaiters(_ identifier: String, code: Int32) {
        finishWaiters(exitWaiters.removeValue(forKey: identifier) ?? [:], code: code)
    }

    private func resumeRemovalWaiters(_ identifier: String, code: Int32) {
        finishWaiters(removalWaiters.removeValue(forKey: identifier) ?? [:], code: code)
    }

    private func finishWaiters(_ waiters: [UUID: AsyncStream<Int32>.Continuation], code: Int32) {
        for continuation in waiters.values {
            continuation.yield(code)
            continuation.finish()
        }
    }

    private static func shouldRestart(_ record: ContainerRecord, exitCode: Int32) -> Bool {
        switch record.restartPolicy.name {
        case "always", "unless-stopped": return true
        case "on-failure":
            return exitCode != 0 && (record.restartPolicy.maximumRetryCount == 0 || record.restartCount < record.restartPolicy.maximumRetryCount)
        default: return false
        }
    }

    private func monitorExec(_ identifier: String) async {
        while !Task.isCancelled {
            guard let exec = try? exec(identifier), exec.running, exec.exitCode == nil else {
                return
            }
            guard let code = await backend.execCompletion(exec) else {
                try? await Task.sleep(for: .milliseconds(25))
                continue
            }
            let refreshedPID = await backend.execPID(exec)
            guard var current = execs[identifier], current.exitCode == nil else { return }
            current.running = false
            current.exitCode = code
            if refreshedPID > 0 { current.pid = refreshedPID }
            execs[identifier] = current
            await backend.retireExec(current)
            return
        }
    }

    private func reconcileExecs(for containerID: String) async {
        let identifiers = execs.values.filter {
            $0.containerID == containerID && $0.exitCode == nil
        }.map(\.id)
        for identifier in identifiers {
            guard let candidate = execs[identifier], candidate.exitCode == nil else { continue }
            let code = candidate.running ? await backend.execStatus(candidate) : nil
            guard var current = execs[identifier], current.exitCode == nil else { continue }
            current.running = false
            current.exitCode = code ?? 137
            execs[identifier] = current
            await backend.retireExec(current)
        }
    }
}

import CEngineCore
import Darwin
import Foundation

public struct EngineSnapshot: Codable, Sendable {
    public var containers: [ContainerRecord]
    public var networks: [NetworkRecord]
    public var volumes: [VolumeRecord]
    public var images: [ImageRecord]

    public init(containers: [ContainerRecord] = [], networks: [NetworkRecord] = [], volumes: [VolumeRecord] = [], images: [ImageRecord] = []) {
        self.containers = containers
        self.networks = networks
        self.volumes = volumes
        self.images = images
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
    private struct LifecycleIntent: Equatable {
        enum Operation: Equatable { case start, stop, restart, remove, update, pause, resume, rename, network }

        let operation: Operation
        let token = UUID()
    }

    var snapshot: EngineSnapshot
    private let store: AtomicStore<EngineSnapshot>
    private let endpointAllocationStore: AtomicStore<[String: Int]>
    private let beforeEndpointAllocationPersistence: (@Sendable () async throws -> Void)?
    let backend: any ContainerBackend
    private var endpointAllocationCursors: [String: Int]
    private var execs: [String: ExecRecord] = [:]
    private var eventContinuations: [UUID: AsyncStream<RuntimeEvent>.Continuation] = [:]
    private var eventHistory: [RuntimeEvent] = []
    private var healthTasks: [String: Task<Void, Never>] = [:]
    private var exitWaiters: [String: [UUID: AsyncStream<Int32>.Continuation]] = [:]
    private var removalWaiters: [String: [UUID: AsyncStream<Int32>.Continuation]] = [:]
    private var lifecycleIntents: [String: LifecycleIntent] = [:]
    private var pendingContainerNames: [String: String] = [:]
    private var pendingContainerIDs = Set<String>()
    private var pendingContainers: [String: ContainerRecord] = [:]
    private var startingContainerIDs = Set<String>()
    private var startingExecIDs = Set<String>()
    private var activeExecOperations: [String: Int] = [:]

    public init(root: URL, backend: any ContainerBackend = MetadataOnlyBackend()) async throws {
        try await self.init(root: root, backend: backend, beforeEndpointAllocationPersistence: nil)
    }

    init(
        root: URL,
        backend: any ContainerBackend,
        beforeEndpointAllocationPersistence: (@Sendable () async throws -> Void)?
    ) async throws {
        self.store = AtomicStore(url: root.appending(path: "engine.json"))
        self.endpointAllocationStore = AtomicStore(url: root.appending(path: "endpoint-allocation.json"))
        self.beforeEndpointAllocationPersistence = beforeEndpointAllocationPersistence
        self.backend = backend
        self.snapshot = try await store.load(default: EngineSnapshot())
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
                guard Self.shouldRestart(stale, exitCode: snapshot.containers[index].exitCode ?? 137) else { continue }
            } else {
                guard stale.phase == .exited, stale.restartPolicy.name == "always" else { continue }
            }
            do {
                var restarted = snapshot.containers[index]
                restarted.restartCount += 1
                try await backend.prepare(restarted)
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
                recovered.append((restarted.id, startedAt))
            } catch {
                snapshot.containers[index].phase = .dead
                snapshot.containers[index].exitCode = 127
            }
        }
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
            Task { [weak self] in await self?.monitorContainer(id, startedAt: startedAt) }
            startHealthMonitor(id)
        }
    }

    public func shutdown() async {
        healthTasks.values.forEach { $0.cancel() }
        healthTasks.removeAll()
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
        var record = input
        guard Identifier.validateName(record.name) else { throw EngineError(.badRequest, "invalid container name: \(record.name)") }
        if let conflictingID = pendingContainerNames[record.name]
            ?? snapshot.containers.first(where: { $0.name == record.name || $0.id == record.id })?.id
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
        let index = try containerIndex(identifier)
        let record = snapshot.containers[index]
        guard lifecycleIntents[record.id] == nil else {
            throw EngineError(.conflict, "container \(identifier) has a lifecycle operation in progress")
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
            let resolvedPorts = try await backend.start(record)
            guard ownsLifecycleExecution(intent, record: record),
                  let current = try? containerIndex(record.id) else {
                _ = try? await backend.stop(record, timeoutSeconds: 0)
                try? await backend.delete(record)
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
                _ = try? await backend.stop(started, timeoutSeconds: 0)
                try? await backend.delete(started)
                throw EngineError(.conflict, "container was removed or changed while it was starting")
            }
            snapshot.containers[current] = started
            try await persist()
            guard lifecycleIntents[record.id] == intent,
                  let published = try? container(record.id),
                  published.phase == .running,
                  published.startedAt == startedAt else {
                _ = try? await backend.stop(started, timeoutSeconds: 0)
                try? await backend.delete(started)
                throw EngineError(.conflict, "container was removed or changed while it was starting")
            }
            emit(containerEvent("start", published))
            startHealthMonitor(record.id)
            Task { [weak self] in await self?.monitorContainer(record.id, startedAt: startedAt) }
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
        try await backend.io(for: container(identifier))
    }

    public func resizeContainer(_ identifier: String, width: UInt16, height: UInt16) async throws {
        try await backend.resize(container(identifier), width: width, height: height)
    }

    public func containerLogs(_ identifier: String, options: DockerLogOptions = .init()) async throws -> Data {
        try await backend.logs(for: container(identifier), options: options)
    }

    public func containerStatistics(_ identifier: String) async throws -> BackendStatistics {
        let record = try container(identifier)
        guard record.phase == .running else { throw EngineError(.conflict, "Container is not running") }
        return try await backend.statistics(record)
    }

    public func containerTop(_ identifier: String, arguments: [String]) async throws -> (titles: [String], processes: [[String]]) {
        let record = try container(identifier)
        guard record.phase == .running else { throw EngineError(.conflict, "Container is not running") }
        return try await backend.top(record, arguments: arguments)
    }

    public func updateContainer(_ identifier: String, memoryBytes: Int64?, nanoCPUs: Int64?,
                                pidsLimit: Int64?, restartPolicy: RestartPolicyRecord?) async throws -> ContainerRecord {
        let index = try containerIndex(identifier)
        let old = snapshot.containers[index]
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
            let resourcesChanged = old.memoryBytes != updated.memoryBytes || old.cpus != updated.cpus
                || old.pidsLimit != updated.pidsLimit
            if resourcesChanged { try await backend.updateResources(updated) }
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
            snapshot.containers[current] = merged
            try await persist()
            emit(containerEvent("update", merged))
            endLifecycleIntent(intent, for: old.id)
            await reconcileDeferredCompletion(old.id)
            return merged
        } catch {
            endLifecycleIntent(intent, for: old.id)
            await reconcileDeferredCompletion(old.id)
            throw error
        }
    }

    public func killContainer(_ identifier: String, signal: String) async throws {
        let record = try container(identifier)
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
        let index = try containerIndex(identifier)
        let record = snapshot.containers[index]
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
        let index = try containerIndex(identifier)
        let record = snapshot.containers[index]
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
        let index = try containerIndex(identifier)
        let record = snapshot.containers[index]
        guard activeExecOperations[record.id, default: 0] == 0 else {
            throw EngineError(.conflict, "container \(identifier) has an exec operation in progress")
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
        var cancelledHealthMonitor = false
        do {
            try await backend.restart(record, timeoutSeconds: timeoutSeconds ?? record.stopTimeoutSeconds)
            guard ownsRestartExecution(intent, record: record) else {
                throw EngineError(.conflict, "container was removed or changed while it was restarting")
            }
            // The backend has replaced the old execution. A health check that
            // began against that generation must not publish into the new one.
            if let task = healthTasks.removeValue(forKey: record.id) {
                task.cancel()
                cancelledHealthMonitor = true
            }
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
            try await persist()
            guard lifecycleIntents[record.id] == intent,
                  let published = try? container(record.id),
                  published.phase == .running,
                  published.startedAt == startedAt else {
                throw EngineError(.conflict, "container was removed or changed while it was restarting")
            }
            emit(containerEvent("restart", published))
            startHealthMonitor(record.id)
            Task { [weak self] in await self?.monitorContainer(record.id, startedAt: startedAt) }
            startingContainerIDs.remove(record.id)
            endLifecycleIntent(intent, for: record.id)
            await reconcileDeferredCompletion(record.id)
        } catch {
            startingContainerIDs.remove(record.id)
            endLifecycleIntent(intent, for: record.id)
            if cancelledHealthMonitor,
               let current = try? container(record.id),
               current.phase == .running || current.phase == .paused {
                startHealthMonitor(record.id)
            }
            await reconcileDeferredCompletion(record.id)
            throw error
        }
    }

    public func createExec(container identifier: String, configuration: ExecConfiguration) async throws -> ExecRecord {
        let container = try container(identifier)
        guard container.phase == .running else { throw EngineError(.conflict, "Container \(identifier) is not running") }
        guard !configuration.arguments.isEmpty else { throw EngineError(.badRequest, "exec command cannot be empty") }
        try beginExecOperation(for: container.id)
        defer { endExecOperation(for: container.id) }
        let exec = ExecRecord(containerID: container.id, configuration: configuration)
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
        if value.running, let code = await backend.execStatus(value) {
            value.running = false
            value.exitCode = code
            let refreshedPID = await backend.execPID(value)
            if refreshedPID > 0 { value.pid = refreshedPID }
            execs[identifier] = value
        }
        return value
    }

    public func execIO(_ identifier: String) async throws -> ContainerIOBridge {
        try await backend.execIO(exec(identifier))
    }

    public func startExec(_ identifier: String) async throws {
        var exec = try exec(identifier)
        guard !exec.running, exec.exitCode == nil else { throw EngineError(.conflict, "exec instance has already run") }
        try beginExecOperation(for: exec.containerID)
        defer { endExecOperation(for: exec.containerID) }
        guard startingExecIDs.insert(identifier).inserted else {
            throw EngineError(.conflict, "exec instance is already starting")
        }
        defer { startingExecIDs.remove(identifier) }
        try await backend.startExec(exec)
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
        try await backend.resizeExec(exec(identifier), width: width, height: height)
    }

    public func stopContainer(_ identifier: String, timeoutSeconds: Int? = nil) async throws {
        let index = try containerIndex(identifier)
        let record = snapshot.containers[index]
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
        let index = try containerIndex(identifier)
        let removed = snapshot.containers[index]
        let intent = try beginLifecycleIntent(.remove, for: removed.id)
        defer { endLifecycleIntent(intent, for: removed.id) }
        if removed.phase == .running || removed.phase == .paused {
            guard force else { throw EngineError(.conflict, "You cannot remove a running container. Stop the container before attempting removal or force remove.") }
            let code = try await backend.stop(removed, timeoutSeconds: 0)
            await recordCompletion(removed.id, startedAt: removed.startedAt, code: code)
        }
        try await removeClaimedContainer(removed, removeVolumes: removeVolumes, intent: intent)
    }

    private func removeClaimedContainer(
        _ removed: ContainerRecord,
        removeVolumes: Bool,
        intent: LifecycleIntent
    ) async throws {
        guard lifecycleIntents[removed.id] == intent else {
            throw EngineError(.conflict, "container \(removed.id) removal reservation was lost")
        }
        guard (try? containerIndex(removed.id)) != nil else { return }
        await reconcileExecs(for: removed.id)
        resumeExitWaiters(removed.id, code: removed.exitCode ?? 137)
        healthTasks.removeValue(forKey: removed.id)?.cancel()
        try await backend.delete(removed)
        try await backend.deleteLogs(for: removed)
        guard let current = try? containerIndex(removed.id) else { return }
        snapshot.containers.remove(at: current)
        if removeVolumes { try await removeAnonymousVolumes(usedBy: removed) }
        resumeRemovalWaiters(removed.id, code: removed.exitCode ?? 0)
        try await persist()
        emit(containerEvent("destroy", removed))
    }

    public func renameContainer(_ identifier: String, name: String) async throws {
        guard Identifier.validateName(name) else { throw EngineError(.badRequest, "invalid container name: \(name)") }
        let normalized = name.normalizedContainerName
        let index = try containerIndex(identifier)
        let record = snapshot.containers[index]
        let intent = try beginLifecycleIntent(.rename, for: record.id)
        do {
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
        let network = try network(networkIdentifier)
        let index = try containerIndex(containerIdentifier)
        let record = snapshot.containers[index]
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
        let network = try network(networkIdentifier)
        let index = try containerIndex(containerIdentifier)
        let record = snapshot.containers[index]
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
            try await removeClaimedContainer(claim.record, removeVolumes: false, intent: claim.intent)
            removed.append(claim.record.id)
        }
        return removed
    }

    public func pruneImages(scope: ImagePruneScope = .dangling) async throws -> [ImageRecord] {
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
        guard Identifier.validateName(name) else { throw EngineError(.badRequest, "invalid volume name: \(name)") }
        if let existing = snapshot.volumes.first(where: { $0.name == name }) { return existing }
        let record = VolumeRecord(name: name, createdAt: Date(), sizeBytes: sizeBytes, labels: labels, options: options, anonymous: anonymous)
        snapshot.volumes.append(record)
        try await persist()
        return record
    }

    public func removeVolume(_ name: String, force: Bool) async throws {
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

    func persist() async throws { try await store.save(snapshot) }

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

    private func monitorContainer(_ identifier: String, startedAt: Date) async {
        guard let record = try? container(identifier), let code = await backend.completion(record) else { return }
        await recordCompletion(identifier, startedAt: startedAt, code: code)
    }

    private func recordCompletion(_ identifier: String, startedAt: Date?, code: Int32) async {
        guard let index = try? containerIndex(identifier),
              snapshot.containers[index].phase == .running || snapshot.containers[index].phase == .paused,
              snapshot.containers[index].startedAt == startedAt else { return }
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
        guard let index = try? containerIndex(identifier), snapshot.containers[index].phase == .exited else { return }
        let autoRemove = snapshot.containers[index].autoRemove
        let record = snapshot.containers[index]
        if intent == nil, !autoRemove, Self.shouldRestart(record, exitCode: code) {
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
            do {
                var restarted = record; restarted.restartCount += 1
                try await backend.delete(record)
                guard ownsReconciliation(restartIntent, record: record) else { return }
                try await backend.prepare(restarted)
                guard ownsReconciliation(restartIntent, record: record) else { return }
                restarted.ports = try await backend.start(restarted)
                guard ownsReconciliation(restartIntent, record: record) else {
                    _ = try? await backend.stop(restarted, timeoutSeconds: 0)
                    try? await backend.delete(restarted)
                    return
                }
                restarted = await applyingEndpointAddresses(to: restarted)
                guard ownsReconciliation(restartIntent, record: record),
                      let current = try? containerIndex(identifier) else {
                    _ = try? await backend.stop(restarted, timeoutSeconds: 0)
                    try? await backend.delete(restarted)
                    return
                }
                restarted.phase = .running; restarted.exitCode = nil; restarted.finishedAt = nil
                let restartedAt = Date(); restarted.startedAt = restartedAt
                snapshot.containers[current] = restarted
                try await persist(); emit(containerEvent("restart", restarted)); startHealthMonitor(identifier)
                Task { [weak self] in await self?.monitorContainer(identifier, startedAt: restartedAt) }
                return
            } catch {
                if ownsReconciliation(restartIntent, record: record),
                   let current = try? containerIndex(identifier) {
                    snapshot.containers[current].phase = .dead
                }
            }
            try? await persist()
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
            try? await backend.delete(record)
            guard ownsReconciliation(removeIntent, record: record) else { return }
            try? await backend.deleteLogs(for: record)
            guard ownsReconciliation(removeIntent, record: record) else { return }
            try? await removeAnonymousVolumes(usedBy: record)
            guard ownsReconciliation(removeIntent, record: record),
                  let current = try? containerIndex(identifier) else { return }
            snapshot.containers.remove(at: current)
            resumeRemovalWaiters(identifier, code: code)
            emit(containerEvent("destroy", record))
        }
        try? await persist()
    }

    private func ownsReconciliation(_ intent: LifecycleIntent, record: ContainerRecord) -> Bool {
        guard lifecycleIntents[record.id] == intent,
              let index = try? containerIndex(record.id) else { return false }
        let current = snapshot.containers[index]
        return current.phase == .exited
            && current.startedAt == record.startedAt
            && current.exitCode == record.exitCode
    }

    private func ownsLifecycleExecution(_ intent: LifecycleIntent, record: ContainerRecord) -> Bool {
        guard lifecycleIntents[record.id] == intent,
              let index = try? containerIndex(record.id) else { return false }
        let current = snapshot.containers[index]
        return current.phase == record.phase && current.startedAt == record.startedAt
    }

    private func ownsRestartExecution(_ intent: LifecycleIntent, record: ContainerRecord) -> Bool {
        guard lifecycleIntents[record.id] == intent,
              let index = try? containerIndex(record.id) else { return false }
        let current = snapshot.containers[index]
        // The old execution may report its expected terminal transition while
        // backend.restart is replacing it. No other phase or generation change
        // is safe for this restart operation to overwrite.
        return (current.phase == record.phase || current.phase == .exited)
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
        guard let exec = try? exec(identifier), let code = await backend.execCompletion(exec) else { return }
        let refreshedPID = await backend.execPID(exec)
        guard var current = execs[identifier] else { return }
        current.running = false
        current.exitCode = code
        if refreshedPID > 0 { current.pid = refreshedPID }
        execs[identifier] = current
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
        }
    }
}

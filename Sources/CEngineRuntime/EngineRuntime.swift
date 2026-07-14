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

public actor EngineRuntime {
    private struct LifecycleIntent: Equatable {
        enum Operation: Equatable { case stop, restart, remove, update }

        let operation: Operation
        let token = UUID()
    }

    var snapshot: EngineSnapshot
    private let store: AtomicStore<EngineSnapshot>
    let backend: any ContainerBackend
    private var execs: [String: ExecRecord] = [:]
    private var eventContinuations: [UUID: AsyncStream<RuntimeEvent>.Continuation] = [:]
    private var eventHistory: [RuntimeEvent] = []
    private var healthTasks: [String: Task<Void, Never>] = [:]
    private var exitWaiters: [String: [UUID: AsyncStream<Int32>.Continuation]] = [:]
    private var removalWaiters: [String: [UUID: AsyncStream<Int32>.Continuation]] = [:]
    private var lifecycleIntents: [String: LifecycleIntent] = [:]

    public init(root: URL, backend: any ContainerBackend = MetadataOnlyBackend()) async throws {
        self.store = AtomicStore(url: root.appending(path: "engine.json"))
        self.backend = backend
        self.snapshot = try await store.load(default: EngineSnapshot())
        let persistedNetworks = Dictionary(uniqueKeysWithValues: snapshot.networks.map { ($0.id, $0) })
        self.snapshot.networks = try await backend.restoreNetworks(snapshot.networks)
        let remappedNetworkIDs = Set(snapshot.networks.compactMap { network -> String? in
            guard let old = persistedNetworks[network.id],
                  old.subnet != network.subnet || old.ipv6Subnet != network.ipv6Subnet else { return nil }
            return network.id
        })
        if !remappedNetworkIDs.isEmpty {
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
                    restarted.networks[endpoint].ipv4Address = address.ipv4Address
                    restarted.networks[endpoint].ipv6Address = address.ipv6Address
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
        snapshot.containers.filter { all || $0.phase == .running || $0.phase == .paused }
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
        guard !snapshot.containers.contains(where: { $0.name == record.name || $0.id == record.id }) else {
            throw EngineError(.conflict, "Conflict. The container name \"/\(record.name)\" is already in use.")
        }
        if record.networks.isEmpty, record.networkDisabled != true,
           let network = snapshot.networks.first(where: { $0.name == "default" }) {
            record.networks = [.init(networkID: network.id)]
        }
        record = try allocatingEndpointAddresses(to: record)
        try validateEndpoints(record)
        try await backend.prepare(record)
        snapshot.containers.append(record)
        try await backend.updateNetworkRecords(snapshot.containers)
        try await persist()
        emit(containerEvent("create", record))
        return record
    }

    public func startContainer(_ identifier: String) async throws {
        let index = try containerIndex(identifier)
        guard snapshot.containers[index].phase != .running else { return }
        let record = snapshot.containers[index]
        if record.phase == .dead {
            try await backend.delete(record)
        }
        try await backend.prepare(record)
        let resolvedPorts = try await backend.start(record)
        guard let current = try? containerIndex(record.id) else {
            _ = try? await backend.stop(record, timeoutSeconds: 0)
            try? await backend.delete(record)
            throw EngineError(.conflict, "container was removed while it was starting")
        }
        snapshot.containers[current].phase = .running
        snapshot.containers[current].ports = resolvedPorts
        let startedAt = Date()
        snapshot.containers[current].startedAt = startedAt
        snapshot.containers[current].finishedAt = nil
        snapshot.containers[current].exitCode = nil
        let addresses = await backend.endpointAddresses(for: record)
        for endpoint in snapshot.containers[current].networks.indices {
            guard let address = addresses[snapshot.containers[current].networks[endpoint].networkID] else { continue }
            snapshot.containers[current].networks[endpoint].ipv4Address = address.ipv4Address
            snapshot.containers[current].networks[endpoint].ipv6Address = address.ipv6Address
        }
        try await persist()
        emit(containerEvent("start", snapshot.containers[current]))
        startHealthMonitor(record.id)
        Task { [weak self] in await self?.monitorContainer(record.id, startedAt: startedAt) }
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
                                restartPolicy: RestartPolicyRecord?) async throws -> ContainerRecord {
        let index = try containerIndex(identifier)
        let old = snapshot.containers[index]
        var updated = old
        if let memoryBytes, memoryBytes > 0 { updated.memoryBytes = UInt64(memoryBytes) }
        if let nanoCPUs, nanoCPUs > 0 { updated.cpus = max(1, Int((nanoCPUs + 999_999_999) / 1_000_000_000)) }
        if let restartPolicy { updated.restartPolicy = restartPolicy }
        let resourcesChanged = old.memoryBytes != updated.memoryBytes || old.cpus != updated.cpus
        if resourcesChanged, old.phase == .running || old.phase == .paused {
            let intent = try beginLifecycleIntent(.update, for: old.id)
            defer { endLifecycleIntent(intent, for: old.id) }
            let code = try await backend.stop(old, timeoutSeconds: old.stopTimeoutSeconds)
            await recordCompletion(old.id, startedAt: old.startedAt, code: code)
            try await backend.delete(old)
            try await backend.prepare(updated)
            updated.ports = try await backend.start(updated)
            updated = await applyingEndpointAddresses(to: updated)
            updated.phase = .running; updated.startedAt = Date(); updated.finishedAt = nil; updated.exitCode = nil
        }
        snapshot.containers[index] = updated
        try await persist()
        emit(containerEvent("update", updated))
        if updated.phase == .running, let startedAt = updated.startedAt {
            let updatedID = updated.id
            Task { [weak self] in await self?.monitorContainer(updatedID, startedAt: startedAt) }
        }
        return updated
    }

    public func killContainer(_ identifier: String, signal: String) async throws {
        let record = try container(identifier)
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
        guard snapshot.containers[index].phase == .running else { throw EngineError(.conflict, "Container (identifier) is not running") }
        try await backend.pause(snapshot.containers[index])
        snapshot.containers[index].phase = .paused
        try await persist()
        emit(containerEvent("pause", snapshot.containers[index]))
    }

    public func resumeContainer(_ identifier: String) async throws {
        let index = try containerIndex(identifier)
        guard snapshot.containers[index].phase == .paused else { throw EngineError(.conflict, "Container (identifier) is not paused") }
        try await backend.resume(snapshot.containers[index])
        snapshot.containers[index].phase = .running
        try await persist()
        emit(containerEvent("unpause", snapshot.containers[index]))
    }

    public func restartContainer(_ identifier: String, timeoutSeconds: Int? = nil) async throws {
        let index = try containerIndex(identifier)
        let record = snapshot.containers[index]
        guard record.phase == .running || record.phase == .paused else {
            try await startContainer(identifier)
            return
        }
        let intent = try beginLifecycleIntent(.restart, for: record.id)
        defer { endLifecycleIntent(intent, for: record.id) }
        try await backend.restart(record, timeoutSeconds: timeoutSeconds ?? record.stopTimeoutSeconds)
        guard let current = try? containerIndex(record.id) else { throw EngineError(.conflict, "container was removed while restarting") }
        snapshot.containers[current].phase = .running
        let startedAt = Date()
        snapshot.containers[current].startedAt = startedAt
        snapshot.containers[current].finishedAt = nil
        snapshot.containers[current].exitCode = nil
        snapshot.containers[current].restartCount += 1
        snapshot.containers[current] = await applyingEndpointAddresses(to: snapshot.containers[current])
        try await persist()
        emit(containerEvent("restart", snapshot.containers[current]))
        startHealthMonitor(record.id)
        Task { [weak self] in await self?.monitorContainer(record.id, startedAt: startedAt) }
    }

    public func createExec(container identifier: String, configuration: ExecConfiguration) async throws -> ExecRecord {
        let container = try container(identifier)
        guard container.phase == .running else { throw EngineError(.conflict, "Container \(identifier) is not running") }
        guard !configuration.arguments.isEmpty else { throw EngineError(.badRequest, "exec command cannot be empty") }
        let exec = ExecRecord(containerID: container.id, configuration: configuration)
        _ = try await backend.prepareExec(exec, container: container)
        execs[exec.id] = exec
        return exec
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
            value.pid = await backend.execPID(value)
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
        try await backend.startExec(exec)
        exec.running = true
        exec.pid = await backend.execPID(exec)
        execs[identifier] = exec
        Task { [weak self] in await self?.monitorExec(identifier) }
    }

    public func resizeExec(_ identifier: String, width: UInt16, height: UInt16) async throws {
        try await backend.resizeExec(exec(identifier), width: width, height: height)
    }

    public func stopContainer(_ identifier: String, timeoutSeconds: Int? = nil) async throws {
        let index = try containerIndex(identifier)
        guard snapshot.containers[index].phase == .running || snapshot.containers[index].phase == .paused else { return }
        let record = snapshot.containers[index]
        let intent = try beginLifecycleIntent(.stop, for: record.id)
        defer { endLifecycleIntent(intent, for: record.id) }
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
        guard (try? containerIndex(removed.id)) != nil else { return }
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
        guard !snapshot.containers.indices.contains(where: { $0 != index && snapshot.containers[$0].name == normalized }) else {
            throw EngineError(.conflict, "Conflict. The container name \"/\(normalized)\" is already in use.")
        }
        snapshot.containers[index].name = normalized
        try await persist()
        emit(containerEvent("rename", snapshot.containers[index]))
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
        if let existing = snapshot.images.first(where: { $0.references.contains(reference) }) { return existing }
        try await backend.pullImage(reference, platform: platform, credentials: credentials, progress: progress)
        if let backendImages = try await backend.listImages() {
            snapshot.images = Self.imageRecords(from: backendImages)
            try await persist()
            if let image = snapshot.images.first(where: { $0.references.contains(reference) }) { return image }
        }
        let image = ImageRecord(
            id: "sha256:\(Identifier.random())", references: [reference], createdAt: Date(), size: 0,
            architecture: platform.hasSuffix("amd64") ? "amd64" : "arm64", os: "linux"
        )
        snapshot.images.append(image)
        try await persist()
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

    public func imageHistory(_ identifier: String) async throws -> (ImageRecord, [ImageHistoryEntry]) {
        let image = try image(identifier)
        guard let reference = image.references.first else { return (image, []) }
        return (image, try await backend.imageHistory(
            reference: reference, platform: "\(image.os)/\(image.architecture)"
        ))
    }

    public func removeImage(_ identifier: String, force: Bool) async throws {
        let image = try image(identifier)
        guard force || !snapshot.containers.contains(where: { image.references.contains($0.image) }) else {
            throw EngineError(.conflict, "conflict: image is being used by a container")
        }
        for reference in image.references { try await backend.deleteImage(reference: reference) }
        snapshot.images.removeAll { $0.id == image.id }
        try await persist()
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

    public func pushImage(_ identifier: String, credentials: RegistryCredentials?) async throws {
        let image = try image(identifier)
        let normalized = ImageReference.normalized(identifier)
        let reference = image.references.first(where: { $0 == identifier || $0 == normalized }) ?? normalized
        try await backend.pushImage(
            reference: reference, platform: "\(image.os)/\(image.architecture)", credentials: credentials
        )
    }

    public func saveImage(_ identifier: String) async throws -> Data {
        let image = try image(identifier)
        return try await backend.saveImages(
            references: [ImageReference.normalized(identifier)], platform: "\(image.os)/\(image.architecture)"
        )
    }

    public func createNetwork(name: String, subnet: String? = nil, gateway: String? = nil,
                              ipv6Subnet: String? = nil, ipv6Gateway: String? = nil,
                              driver: String? = nil, internalNetwork: Bool = false,
                              labels: [String: String] = [:], options: [String: String] = [:]) async throws -> NetworkRecord {
        guard Identifier.validateName(name) else { throw EngineError(.badRequest, "invalid network name: \(name)") }
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
        if let existing = snapshot.networks.first(where: { $0.name == name }) { return existing }
        let requestedSubnet = subnet ?? ""
        let requestedIPv6 = ipv6Subnet ?? ""
        let requested = NetworkRecord(
            id: Identifier.random(), name: name, createdAt: Date(), subnet: requestedSubnet, gateway: gateway ?? "",
            ipv6Subnet: requestedIPv6, ipv6Gateway: ipv6Gateway ?? "",
            ipv4AllocationMode: subnet == nil ? .automatic : .explicit,
            ipv6AllocationMode: ipv6Subnet == nil ? .automatic : .explicit,
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
        guard !snapshot.containers.contains(where: { container in container.networks.contains { $0.networkID == snapshot.networks[index].id } }) else {
            throw EngineError(.conflict, "network \(snapshot.networks[index].name) has active endpoints")
        }
        let removed = snapshot.networks.remove(at: index)
        try await backend.deleteNetwork(removed)
        try await persist()
    }

    public func connectNetwork(_ networkIdentifier: String, container containerIdentifier: String,
                               aliases: [String] = [], ipv4Address: String? = nil,
                               ipv6Address: String? = nil) async throws {
        let network = try network(networkIdentifier)
        let index = try containerIndex(containerIdentifier)
        guard snapshot.containers[index].phase != .running && snapshot.containers[index].phase != .paused else {
            throw EngineError(.conflict, "cannot connect a network while container \(snapshot.containers[index].name) is running")
        }
        guard !snapshot.containers[index].networks.contains(where: { $0.networkID == network.id }) else { return }
        try validateStaticEndpointModes(
            network: network, ipv4IsStatic: ipv4Address != nil, ipv6IsStatic: ipv6Address != nil
        )
        let previous = snapshot.containers[index]
        snapshot.containers[index].networks.append(.init(
            networkID: network.id, aliases: aliases, ipv4Address: ipv4Address, ipv6Address: ipv6Address,
            ipv4AddressIsStatic: ipv4Address != nil, ipv6AddressIsStatic: ipv6Address != nil
        ))
        snapshot.containers[index] = try allocatingEndpointAddresses(to: snapshot.containers[index])
        do {
            try validateEndpoints(snapshot.containers[index])
            try await backend.updateNetworkRecords(snapshot.containers)
        } catch { snapshot.containers[index] = previous; try? await backend.updateNetworkRecords(snapshot.containers); throw error }
        try await persist()
    }

    public func disconnectNetwork(_ networkIdentifier: String, container containerIdentifier: String, force: Bool) async throws {
        let network = try network(networkIdentifier)
        let index = try containerIndex(containerIdentifier)
        guard snapshot.containers[index].phase != .running && snapshot.containers[index].phase != .paused else {
            throw EngineError(.conflict, "cannot disconnect a network while container \(snapshot.containers[index].name) is running")
        }
        guard snapshot.containers[index].networks.contains(where: { $0.networkID == network.id }) else {
            if force { return }
            throw EngineError(.notFound, "container is not connected to network \(network.name)")
        }
        let previous = snapshot.containers[index]
        snapshot.containers[index].networks.removeAll { $0.networkID == network.id }
        do { try await backend.updateNetworkRecords(snapshot.containers) }
        catch { snapshot.containers[index] = previous; try? await backend.updateNetworkRecords(snapshot.containers); throw error }
        try await persist()
    }

    public func pruneNetworks() async throws -> [String] {
        let used = Set(snapshot.containers.flatMap(\.networks).map(\.networkID))
        let removed = snapshot.networks.filter { $0.name != "default" && !used.contains($0.id) }
        snapshot.networks.removeAll { $0.name != "default" && !used.contains($0.id) }
        for network in removed { try await backend.deleteNetwork(network) }
        try await persist()
        return removed.map(\.name)
    }

    public func pruneContainers() async throws -> [String] {
        let removed = snapshot.containers.filter { $0.phase != .running && $0.phase != .paused }
        for record in removed { try await backend.delete(record); try await backend.deleteLogs(for: record) }
        let ids = Set(removed.map(\.id)); snapshot.containers.removeAll { ids.contains($0.id) }
        try await persist()
        removed.forEach { emit(containerEvent("destroy", $0)) }
        return removed.map(\.id)
    }

    public func pruneImages() async throws -> [ImageRecord] {
        let used = Set(snapshot.containers.map(\.image))
        let removed = snapshot.images.filter { image in image.references.allSatisfy { !used.contains($0) } }
        for image in removed { for reference in image.references { try await backend.deleteImage(reference: reference) } }
        let ids = Set(removed.map(\.id)); snapshot.images.removeAll { ids.contains($0.id) }
        try await persist(); return removed
    }

    public func pruneVolumes() async throws -> [String] {
        let used = Set(snapshot.containers.flatMap(\.mounts).filter { $0.kind == .volume }.map(\.source))
        let removed = snapshot.volumes.filter { !used.contains($0.name) }
        for volume in removed { try await backend.deleteVolume(volume.name) }
        snapshot.volumes.removeAll { !used.contains($0.name) }
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
            for peer in snapshot.containers where peer.id != record.id {
                for existing in peer.networks where existing.networkID == endpoint.networkID {
                    if endpoint.ipv4AddressIsStatic, endpoint.ipv4Address == existing.ipv4Address {
                        throw EngineError(.conflict, "IPv4 address \(endpoint.ipv4Address ?? "") is already allocated")
                    }
                    if endpoint.ipv6AddressIsStatic, endpoint.ipv6Address == existing.ipv6Address {
                        throw EngineError(.conflict, "IPv6 address \(endpoint.ipv6Address ?? "") is already allocated")
                    }
                }
            }
        }
    }

    private func allocatingEndpointAddresses(to input: ContainerRecord) throws -> ContainerRecord {
        var record = input
        for index in record.networks.indices {
            guard let network = snapshot.networks.first(where: { $0.id == record.networks[index].networkID }) else {
                throw EngineError(.notFound, "network \(record.networks[index].networkID) not found")
            }
            let peers = snapshot.containers
                .filter { $0.id != record.id }
                .flatMap(\.networks)
                .filter { $0.networkID == network.id }
            if record.networks[index].ipv4Address == nil, !network.subnet.isEmpty {
                record.networks[index].ipv4Address = try Self.nextAddress(
                    in: network.subnet,
                    gateway: network.gateway,
                    used: Set(peers.compactMap(\.ipv4Address) + record.networks.compactMap(\.ipv4Address))
                )
            }
            if record.networks[index].ipv6Address == nil, !network.ipv6Subnet.isEmpty {
                record.networks[index].ipv6Address = try Self.nextAddress(
                    in: network.ipv6Subnet,
                    gateway: network.ipv6Gateway,
                    used: Set(peers.compactMap(\.ipv6Address) + record.networks.compactMap(\.ipv6Address))
                )
            }
        }
        return record
    }

    private static func nextAddress(in subnet: String, gateway: String, used: Set<String>) throws -> String {
        let components = subnet.split(separator: "/", maxSplits: 1).map(String.init)
        guard components.count == 2, let prefix = Int(components[1]) else {
            throw EngineError(.badRequest, "invalid network subnet \(subnet)")
        }
        let family = components[0].contains(":") ? AF_INET6 : AF_INET
        let byteCount = family == AF_INET6 ? 16 : 4
        guard (0..<(byteCount * 8)).contains(prefix), var network = addressBytes(components[0], family: family) else {
            throw EngineError(.badRequest, "invalid network subnet \(subnet)")
        }
        for index in network.indices {
            let remaining = prefix - index * 8
            if remaining >= 8 { continue }
            network[index] &= remaining <= 0 ? 0 : UInt8(0xff << (8 - remaining))
        }
        let hostBits = byteCount * 8 - prefix
        let lastOffset = hostBits >= 16 ? 65_535 : (1 << hostBits) - 1
        let reserved = Set(used.map { $0.split(separator: "/", maxSplits: 1).first.map(String.init) ?? $0 } + [gateway])
        guard lastOffset >= 1 else { throw EngineError(.conflict, "network \(subnet) has no allocatable addresses") }
        for offset in 1...lastOffset {
            if family == AF_INET, offset == lastOffset { continue }
            var candidate = network
            var carry = offset
            for index in candidate.indices.reversed() where carry > 0 {
                let value = Int(candidate[index]) + carry
                candidate[index] = UInt8(value & 0xff)
                carry = value >> 8
            }
            guard let value = addressString(candidate, family: family), !reserved.contains(value) else { continue }
            return value
        }
        throw EngineError(.conflict, "network \(subnet) has no free addresses")
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

    private func validateStaticEndpointModes(
        network: NetworkRecord, ipv4IsStatic: Bool, ipv6IsStatic: Bool
    ) throws {
        if ipv4IsStatic, network.ipv4AllocationMode != .explicit {
            throw EngineError(.badRequest, "static IPv4 addresses require an explicitly configured IPv4 subnet")
        }
        if ipv6IsStatic, network.ipv6AllocationMode != .explicit {
            throw EngineError(.badRequest, "static IPv6 addresses require an explicitly configured IPv6 subnet")
        }
    }

    private func applyingEndpointAddresses(to input: ContainerRecord) async -> ContainerRecord {
        var record = input
        let addresses = await backend.endpointAddresses(for: input)
        for endpoint in record.networks.indices {
            guard let address = addresses[record.networks[endpoint].networkID] else { continue }
            record.networks[endpoint].ipv4Address = address.ipv4Address
            record.networks[endpoint].ipv6Address = address.ipv6Address
        }
        return record
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
        if health.startPeriodNanoseconds > 0 {
            try? await Task.sleep(for: .nanoseconds(health.startPeriodNanoseconds))
        }
        while !Task.isCancelled {
            guard let index = try? containerIndex(identifier), snapshot.containers[index].phase == .running else { return }
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
            guard let current = try? containerIndex(identifier), snapshot.containers[current].phase == .running else { return }
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
            try? await Task.sleep(for: .nanoseconds(delay))
        }
    }

    private static func imageRecords(from images: [BackendImage]) -> [ImageRecord] {
        Dictionary(grouping: images, by: \ .id).map { id, values in
            ImageRecord(id: id, references: values.map(\ .reference).sorted(), createdAt: Date(),
                        size: values.map(\ .size).max() ?? 0,
                        architecture: values.first?.architecture ?? "arm64", os: values.first?.os ?? "linux")
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
        let autoRemove = snapshot.containers[index].autoRemove
        let record = snapshot.containers[index]
        let intent = lifecycleIntents[identifier]?.operation
        healthTasks.removeValue(forKey: record.id)?.cancel()
        emit(containerEvent("die", record, extra: ["exitCode": String(code)]))
        if intent == nil, !autoRemove, Self.shouldRestart(record, exitCode: code) {
            do {
                var restarted = record; restarted.restartCount += 1
                try await backend.delete(record); try await backend.prepare(restarted)
                restarted.ports = try await backend.start(restarted)
                restarted = await applyingEndpointAddresses(to: restarted)
                restarted.phase = .running; restarted.exitCode = nil; restarted.finishedAt = nil
                let restartedAt = Date(); restarted.startedAt = restartedAt
                if let current = try? containerIndex(identifier) { snapshot.containers[current] = restarted }
                try await persist(); emit(containerEvent("restart", restarted)); startHealthMonitor(identifier)
                Task { [weak self] in await self?.monitorContainer(identifier, startedAt: restartedAt) }
                return
            } catch {
                if let current = try? containerIndex(identifier) { snapshot.containers[current].phase = .dead }
            }
        }
        if autoRemove, intent == nil || intent == .stop {
            try? await backend.delete(record)
            try? await backend.deleteLogs(for: record)
            try? await removeAnonymousVolumes(usedBy: record)
            if let current = try? containerIndex(identifier) { snapshot.containers.remove(at: current) }
            resumeRemovalWaiters(identifier, code: code)
            emit(containerEvent("destroy", record))
        }
        try? await persist()
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
        guard var current = execs[identifier] else { return }
        current.running = false
        current.exitCode = code
        current.pid = await backend.execPID(current)
        execs[identifier] = current
    }
}

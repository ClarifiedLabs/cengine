import CEngineCore
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

public actor EngineRuntime {
    var snapshot: EngineSnapshot
    private let store: AtomicStore<EngineSnapshot>
    let backend: any ContainerBackend
    private var execs: [String: ExecRecord] = [:]
    private var eventContinuations: [UUID: AsyncStream<RuntimeEvent>.Continuation] = [:]

    public init(root: URL, backend: any ContainerBackend = MetadataOnlyBackend()) async throws {
        self.store = AtomicStore(url: root.appending(path: "engine.json"))
        self.backend = backend
        self.snapshot = try await store.load(default: EngineSnapshot())
        if !snapshot.networks.contains(where: { $0.name == "default" }) {
            snapshot.networks.append(NetworkRecord(
                id: "cengine-default-network", name: "default", subnet: "192.168.64.0/24", gateway: "192.168.64.1"
            ))
        }
        for index in snapshot.containers.indices where snapshot.containers[index].phase == .running || snapshot.containers[index].phase == .paused {
            snapshot.containers[index].phase = .exited
            snapshot.containers[index].exitCode = 137
            snapshot.containers[index].finishedAt = Date()
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
    public func createContainer(_ record: ContainerRecord) async throws -> ContainerRecord {
        guard Identifier.validateName(record.name) else { throw EngineError(.badRequest, "invalid container name: \(record.name)") }
        guard !snapshot.containers.contains(where: { $0.name == record.name || $0.id == record.id }) else {
            throw EngineError(.conflict, "Conflict. The container name \"/\(record.name)\" is already in use.")
        }
        try await backend.prepare(record)
        snapshot.containers.append(record)
        try await persist()
        emit(containerEvent("create", record))
        return record
    }

    public func startContainer(_ identifier: String) async throws {
        let index = try containerIndex(identifier)
        guard snapshot.containers[index].phase != .running else { return }
        let record = snapshot.containers[index]
        if record.phase == .exited || record.phase == .dead {
            try await backend.delete(record)
            try await backend.prepare(record)
        }
        try await backend.start(record)
        guard let current = try? containerIndex(record.id) else {
            _ = try? await backend.stop(record, timeoutSeconds: 0)
            try? await backend.delete(record)
            throw EngineError(.conflict, "container was removed while it was starting")
        }
        snapshot.containers[current].phase = .running
        let startedAt = Date()
        snapshot.containers[current].startedAt = startedAt
        snapshot.containers[current].finishedAt = nil
        snapshot.containers[current].exitCode = nil
        if let address = await backend.ipv4Address(for: record) {
            if snapshot.containers[current].networks.isEmpty {
                if let network = snapshot.networks.first(where: { $0.name == "default" }) {
                    snapshot.containers[current].networks = [.init(networkID: network.id, ipv4Address: address)]
                }
            } else {
                for endpoint in snapshot.containers[current].networks.indices {
                    snapshot.containers[current].networks[endpoint].ipv4Address = address
                }
            }
        }
        try await persist()
        emit(containerEvent("start", snapshot.containers[current]))
        Task { [weak self] in await self?.monitorContainer(record.id, startedAt: startedAt) }
    }

    public func containerIO(_ identifier: String) async throws -> ContainerIOBridge {
        try await backend.io(for: container(identifier))
    }

    public func resizeContainer(_ identifier: String, width: UInt16, height: UInt16) async throws {
        try await backend.resize(container(identifier), width: width, height: height)
    }

    public func containerLogs(_ identifier: String) async throws -> Data {
        try await backend.logs(for: container(identifier))
    }

    public func killContainer(_ identifier: String, signal: String) async throws {
        let record = try container(identifier)
        guard record.phase == .running else { throw EngineError(.conflict, "Container \(identifier) is not running") }
        try await backend.kill(record, signal: signal)
        emit(containerEvent("kill", record, extra: ["signal": signal]))
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
        try await backend.restart(record, timeoutSeconds: timeoutSeconds ?? record.stopTimeoutSeconds)
        guard let current = try? containerIndex(record.id) else { throw EngineError(.conflict, "container was removed while restarting") }
        snapshot.containers[current].phase = .running
        let startedAt = Date()
        snapshot.containers[current].startedAt = startedAt
        snapshot.containers[current].finishedAt = nil
        snapshot.containers[current].exitCode = nil
        snapshot.containers[current].restartCount += 1
        try await persist()
        emit(containerEvent("restart", snapshot.containers[current]))
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
        let code = try await backend.stop(record, timeoutSeconds: timeoutSeconds ?? record.stopTimeoutSeconds)
        guard let current = try? containerIndex(record.id) else { return }
        snapshot.containers[current].phase = .exited
        snapshot.containers[current].exitCode = code
        snapshot.containers[current].finishedAt = Date()
        try await persist()
        emit(containerEvent("die", snapshot.containers[current], extra: ["exitCode": String(code)]))
    }

    public func waitContainer(_ identifier: String) async throws -> Int32 {
        let index = try containerIndex(identifier)
        if snapshot.containers[index].phase != .running { return snapshot.containers[index].exitCode ?? 0 }
        let record = snapshot.containers[index]
        let code = try await backend.wait(record)
        guard let current = try? containerIndex(record.id) else { return code }
        snapshot.containers[current].phase = .exited
        snapshot.containers[current].exitCode = code
        snapshot.containers[current].finishedAt = Date()
        try await persist()
        emit(containerEvent("die", snapshot.containers[current], extra: ["exitCode": String(code)]))
        return code
    }

    public func removeContainer(_ identifier: String, force: Bool) async throws {
        let index = try containerIndex(identifier)
        if snapshot.containers[index].phase == .running || snapshot.containers[index].phase == .paused {
            guard force else { throw EngineError(.conflict, "You cannot remove a running container. Stop the container before attempting removal or force remove.") }
            _ = try await backend.stop(snapshot.containers[index], timeoutSeconds: 0)
        }
        let removed = snapshot.containers[index]
        try await backend.delete(removed)
        snapshot.containers.remove(at: index)
        try await persist()
        emit(containerEvent("destroy", removed))
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
    public func pullImage(_ reference: String, platform: String = "linux/arm64") async throws -> ImageRecord {
        if let existing = snapshot.images.first(where: { $0.references.contains(reference) }) { return existing }
        try await backend.pullImage(reference, platform: platform)
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

    public func removeImage(_ identifier: String, force: Bool) async throws {
        let image = try image(identifier)
        guard force || !snapshot.containers.contains(where: { image.references.contains($0.image) }) else {
            throw EngineError(.conflict, "conflict: image is being used by a container")
        }
        for reference in image.references { try await backend.deleteImage(reference: reference) }
        snapshot.images.removeAll { $0.id == image.id }
        try await persist()
    }

    public func createNetwork(name: String, subnet: String = "172.30.0.0/24", gateway: String = "172.30.0.1", labels: [String: String] = [:]) async throws -> NetworkRecord {
        guard Identifier.validateName(name) else { throw EngineError(.badRequest, "invalid network name: \(name)") }
        if let existing = snapshot.networks.first(where: { $0.name == name }) { return existing }
        let record = NetworkRecord(id: Identifier.random(), name: name, createdAt: Date(), subnet: subnet, gateway: gateway, internalNetwork: false, labels: labels)
        snapshot.networks.append(record)
        try await persist()
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
        snapshot.networks.remove(at: index)
        try await persist()
    }

    public func connectNetwork(_ networkIdentifier: String, container containerIdentifier: String,
                               aliases: [String] = [], ipv4Address: String? = nil,
                               ipv6Address: String? = nil) async throws {
        let network = try network(networkIdentifier)
        let index = try containerIndex(containerIdentifier)
        guard snapshot.containers[index].phase == .created else {
            throw EngineError(.unsupported, "live network attachment is not supported by the VM backend")
        }
        guard !snapshot.containers[index].networks.contains(where: { $0.networkID == network.id }) else { return }
        snapshot.containers[index].networks.append(.init(
            networkID: network.id, aliases: aliases, ipv4Address: ipv4Address, ipv6Address: ipv6Address
        ))
        try await persist()
    }

    public func disconnectNetwork(_ networkIdentifier: String, container containerIdentifier: String, force: Bool) async throws {
        let network = try network(networkIdentifier)
        let index = try containerIndex(containerIdentifier)
        guard snapshot.containers[index].phase == .created || force else {
            throw EngineError(.unsupported, "live network detachment is not supported by the VM backend")
        }
        guard snapshot.containers[index].networks.contains(where: { $0.networkID == network.id }) else {
            if force { return }
            throw EngineError(.notFound, "container is not connected to network (network.name)")
        }
        snapshot.containers[index].networks.removeAll { $0.networkID == network.id }
        try await persist()
    }

    public func pruneNetworks() async throws -> [String] {
        let used = Set(snapshot.containers.flatMap(\.networks).map(\.networkID))
        let removed = snapshot.networks.filter { $0.name != "default" && !used.contains($0.id) }
        snapshot.networks.removeAll { $0.name != "default" && !used.contains($0.id) }
        try await persist()
        return removed.map(\.name)
    }

    public func createVolume(name: String, sizeBytes: UInt64 = 512 * 1024 * 1024 * 1024, labels: [String: String] = [:], options: [String: String] = [:]) async throws -> VolumeRecord {
        guard Identifier.validateName(name) else { throw EngineError(.badRequest, "invalid volume name: \(name)") }
        if let existing = snapshot.volumes.first(where: { $0.name == name }) { return existing }
        let record = VolumeRecord(name: name, createdAt: Date(), sizeBytes: sizeBytes, labels: labels, options: options)
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

    func persist() async throws { try await store.save(snapshot) }

    public func events() -> AsyncStream<RuntimeEvent> {
        let id = UUID()
        return AsyncStream { continuation in
            eventContinuations[id] = continuation
            continuation.onTermination = { [weak self] _ in Task { await self?.removeEventContinuation(id) } }
        }
    }

    private func removeEventContinuation(_ id: UUID) { eventContinuations.removeValue(forKey: id) }
    private func emit(_ event: RuntimeEvent) { eventContinuations.values.forEach { $0.yield(event) } }
    private func containerEvent(_ action: String, _ record: ContainerRecord,
                                extra: [String: String] = [:]) -> RuntimeEvent {
        RuntimeEvent(type: "container", action: action, id: record.id,
                     attributes: record.labels.merging(["name": record.name, "image": record.image]) { current, _ in current }
                        .merging(extra) { _, new in new })
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

    private func recordCompletion(_ identifier: String, startedAt: Date, code: Int32) async {
        guard let index = try? containerIndex(identifier), snapshot.containers[index].phase == .running,
              snapshot.containers[index].startedAt == startedAt else { return }
        snapshot.containers[index].phase = .exited
        snapshot.containers[index].exitCode = code
        snapshot.containers[index].finishedAt = Date()
        let autoRemove = snapshot.containers[index].autoRemove
        let record = snapshot.containers[index]
        emit(containerEvent("die", record, extra: ["exitCode": String(code)]))
        if autoRemove {
            try? await backend.delete(record)
            if let current = try? containerIndex(identifier) { snapshot.containers.remove(at: current) }
            emit(containerEvent("destroy", record))
        }
        try? await persist()
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

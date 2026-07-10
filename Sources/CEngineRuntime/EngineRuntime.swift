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
    private var snapshot: EngineSnapshot
    private let store: AtomicStore<EngineSnapshot>
    private let backend: any ContainerBackend

    public init(root: URL, backend: any ContainerBackend = MetadataOnlyBackend()) async throws {
        self.store = AtomicStore(url: root.appending(path: "engine.json"))
        self.backend = backend
        self.snapshot = try await store.load(default: EngineSnapshot())
        for index in snapshot.containers.indices where snapshot.containers[index].phase == .running || snapshot.containers[index].phase == .paused {
            snapshot.containers[index].phase = .exited
            snapshot.containers[index].exitCode = 137
            snapshot.containers[index].finishedAt = Date()
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
        return record
    }

    public func startContainer(_ identifier: String) async throws {
        let index = try containerIndex(identifier)
        guard snapshot.containers[index].phase != .running else { return }
        let record = snapshot.containers[index]
        try await backend.start(record)
        snapshot.containers[index].phase = .running
        snapshot.containers[index].startedAt = Date()
        snapshot.containers[index].finishedAt = nil
        snapshot.containers[index].exitCode = nil
        try await persist()
    }

    public func containerIO(_ identifier: String) async throws -> ContainerIOBridge {
        try await backend.io(for: container(identifier))
    }

    public func resizeContainer(_ identifier: String, width: UInt16, height: UInt16) async throws {
        try await backend.resize(container(identifier), width: width, height: height)
    }

    public func stopContainer(_ identifier: String, timeoutSeconds: Int? = nil) async throws {
        let index = try containerIndex(identifier)
        guard snapshot.containers[index].phase == .running || snapshot.containers[index].phase == .paused else { return }
        let code = try await backend.stop(snapshot.containers[index], timeoutSeconds: timeoutSeconds ?? snapshot.containers[index].stopTimeoutSeconds)
        snapshot.containers[index].phase = .exited
        snapshot.containers[index].exitCode = code
        snapshot.containers[index].finishedAt = Date()
        try await persist()
    }

    public func waitContainer(_ identifier: String) async throws -> Int32 {
        let index = try containerIndex(identifier)
        if snapshot.containers[index].phase != .running { return snapshot.containers[index].exitCode ?? 0 }
        let code = try await backend.wait(snapshot.containers[index])
        snapshot.containers[index].phase = .exited
        snapshot.containers[index].exitCode = code
        snapshot.containers[index].finishedAt = Date()
        try await persist()
        return code
    }

    public func removeContainer(_ identifier: String, force: Bool) async throws {
        let index = try containerIndex(identifier)
        if snapshot.containers[index].phase == .running || snapshot.containers[index].phase == .paused {
            guard force else { throw EngineError(.conflict, "You cannot remove a running container. Stop the container before attempting removal or force remove.") }
            _ = try await backend.stop(snapshot.containers[index], timeoutSeconds: 0)
        }
        try await backend.delete(snapshot.containers[index])
        snapshot.containers.remove(at: index)
        try await persist()
    }

    public func listNetworks() -> [NetworkRecord] { snapshot.networks }
    public func listVolumes() -> [VolumeRecord] { snapshot.volumes }
    public func listImages() -> [ImageRecord] { snapshot.images }

    @discardableResult
    public func pullImage(_ reference: String, platform: String = "linux/arm64") async throws -> ImageRecord {
        if let existing = snapshot.images.first(where: { $0.references.contains(reference) }) { return existing }
        try await backend.pullImage(reference, platform: platform)
        let image = ImageRecord(
            id: "sha256:\(Identifier.random())", references: [reference], createdAt: Date(), size: 0,
            architecture: platform.hasSuffix("amd64") ? "amd64" : "arm64", os: "linux"
        )
        snapshot.images.append(image)
        try await persist()
        return image
    }

    public func image(_ identifier: String) throws -> ImageRecord {
        guard let image = snapshot.images.first(where: { $0.id == identifier || $0.id.hasPrefix(identifier) || $0.references.contains(identifier) }) else {
            throw EngineError(.notFound, "No such image: \(identifier)")
        }
        return image
    }

    public func removeImage(_ identifier: String, force: Bool) async throws {
        let image = try image(identifier)
        guard force || !snapshot.containers.contains(where: { image.references.contains($0.image) }) else {
            throw EngineError(.conflict, "conflict: image is being used by a container")
        }
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
        guard !snapshot.containers.contains(where: { container in container.networks.contains { $0.networkID == snapshot.networks[index].id } }) else {
            throw EngineError(.conflict, "network \(snapshot.networks[index].name) has active endpoints")
        }
        snapshot.networks.remove(at: index)
        try await persist()
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

    private func persist() async throws { try await store.save(snapshot) }
}

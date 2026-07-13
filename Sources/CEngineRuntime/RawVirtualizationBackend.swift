#if os(macOS)
import CEngineCore
import CryptoKit
import Darwin
import Foundation

public actor RawVirtualizationBackend: ContainerBackend {
    public static let defaultRootDiskBytes: UInt64 = 64 * 1_024 * 1_024 * 1_024
    public static let defaultStorageDiskBytes: UInt64 = 512 * 1_024 * 1_024 * 1_024

    private let root: URL
    private let kernel: URL
    private let containerInitialRamdisk: URL
    private let store: OCIContentStore
    private let tokenIssuer: VolumeAccessToken
    private let infrastructure: VMShimClient
    private let storageAdmin: StorageAdministrativeClient
    private var shims: [String: VMShimClient] = [:]
    private var completions: [String: Int32] = [:]
    private var networks: [String: NetworkRecord] = [:]
    private var networkVLANs: [String: UInt16] = [:]
    private var appliedNetworks: [String: Set<String>] = [:]
    private var activeContainers: [String: ContainerRecord] = [:]
    private var knownContainers: [String: ContainerRecord] = [:]
    private var bridges: [String: ContainerIOBridge] = [:]
    private var logMonitors: [String: ContainerLogMonitor] = [:]
    private var execBridges: [String: ContainerIOBridge] = [:]
    private var execMonitors: [String: ContainerLogMonitor] = [:]
    private var execShims: [String: VMShimClient] = [:]

    public init(root: URL, kernel: URL, containerInitialRamdisk: URL, storageInitialRamdisk: URL) async throws {
        self.root = root
        self.kernel = kernel
        self.containerInitialRamdisk = containerInitialRamdisk
        let containers = root.appending(path: "containers", directoryHint: .isDirectory)
        let infrastructureRoot = root.appending(path: "infrastructure", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: containers, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: infrastructureRoot, withIntermediateDirectories: true)
        store = try OCIContentStore(root: root.appending(path: "content"))
        if let data = try? Data(contentsOf: root.appending(path: "networks.json")),
           let state = try? JSONDecoder().decode([String: NetworkState].self, from: data) {
            networks = state.mapValues(\.record)
            networkVLANs = state.mapValues(\.vlan)
        }

        let secretURL = infrastructureRoot.appending(path: "volume-token-secret")
        let secret: Data
        if FileManager.default.fileExists(atPath: secretURL.path) {
            secret = try Data(contentsOf: secretURL)
        } else {
            secret = VolumeAccessToken.random().secret
            try secret.write(to: secretURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: secretURL.path)
        }
        tokenIssuer = try VolumeAccessToken(secret: secret)

        let disk = infrastructureRoot.appending(path: "volumes.ext4")
        try Self.createSparseFile(at: disk, size: Self.defaultStorageDiskBytes)
        let infrastructureSpec = VMShimProtocol.Specification(
            kind: .storage,
            containerID: "cengine-storage",
            generation: 1,
            token: Self.randomToken(),
            kernelPath: kernel.path,
            initialRamdiskPath: storageInitialRamdisk.path,
            rootDiskPath: disk.path,
            cpus: 2,
            memoryBytes: 1 * 1_024 * 1_024 * 1_024,
            macAddress: "02:ce:00:00:00:01",
            socketPath: try Self.makeRuntimeSocketPath(),
            logPath: infrastructureRoot.appending(path: "shim.log").path,
            kernelArguments: [tokenIssuer.kernelArgument],
            fileSystemSocketPath: try Self.makeRuntimeSocketPath(),
            networkSocketPath: try Self.makeRuntimeSocketPath()
        )
        infrastructure = try await Self.recoverOrLaunch(infrastructureSpec)
        _ = try await infrastructure.boot()
        guard let storageSocketPath = infrastructure.specification.fileSystemSocketPath else {
            throw EngineError(.internalError, "storage shim has no filesystem transport socket")
        }
        storageAdmin = StorageAdministrativeClient(socketPath: storageSocketPath, tokenIssuer: tokenIssuer)

        let entries = (try? FileManager.default.contentsOfDirectory(at: containers, includingPropertiesForKeys: [.isDirectoryKey])) ?? []
        for directory in entries {
            let specURL = directory.appending(path: "shim.json")
            guard let data = try? Data(contentsOf: specURL),
                  let specification = try? JSONDecoder().decode(VMShimProtocol.Specification.self, from: data) else { continue }
            let client = VMShimClient(specification: specification)
            if (try? await client.status()) != nil { shims[specification.containerID] = client }
        }
    }

    public func shutdown() async {
        // Shims own running VMs. Daemon shutdown intentionally only drops control connections.
        for monitor in logMonitors.values { monitor.stop(finishOutput: false) }
        logMonitors.removeAll()
        for monitor in execMonitors.values { monitor.stop(finishOutput: false) }
        execMonitors.removeAll()
    }

    public func pullImage(_ reference: String, platform: String) async throws {
        _ = try await pull(reference, platform: platform, credentials: nil) { _ in }
    }

    public func pullImage(_ reference: String, platform: String, credentials: RegistryCredentials?, progress: @escaping ImagePullProgressHandler) async throws {
        _ = try await pull(reference, platform: platform, credentials: credentials, progress: progress)
    }

    public func listImages() async throws -> [BackendImage]? { try await store.summaries() }

    public func deleteImage(reference: String) async throws {
        try await store.remove(reference: reference)
        _ = try await store.prune()
    }

    public func tagImage(existing: String, new: String) async throws {
        guard let descriptor = await store.descriptor(for: existing) else { throw EngineError(.notFound, "image \(existing) not found") }
        try await store.tag(descriptor, as: new)
    }

    public func loadImages(fromOCILayout directory: URL) async throws -> [BackendImage] { try await store.importLayout(directory) }

    public func saveImages(references: [String], platform: String) async throws -> Data {
        try await store.exportLayout(references: references, platform: platform)
    }

    public func pushImage(reference: String, platform: String, credentials: RegistryCredentials?) async throws {
        try await store.push(reference: reference, platform: platform, credentials: credentials)
    }

    public func imageHistory(reference: String, platform: String) async throws -> [ImageHistoryEntry] {
        try await store.history(reference: reference, platform: platform)
    }

    public func prepare(_ container: ContainerRecord) async throws {
        if shims[container.id] != nil { return }
        let image = try await resolvedImage(container.image, platform: container.platform)
        let directory = root.appending(path: "containers/\(container.id)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let disk = directory.appending(path: "root.ext4")
        let ioDirectory = directory.appending(path: "io", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: ioDirectory, withIntermediateDirectories: true)
        for name in ["stdout", "stderr", "stdin"] {
            let path = ioDirectory.appending(path: name).path
            if !FileManager.default.fileExists(atPath: path) { FileManager.default.createFile(atPath: path, contents: nil) }
        }
        try Self.prepareBindSources(container.mounts)
        try Self.createSparseFile(at: disk, size: Self.defaultRootDiskBytes)
        let specification = VMShimProtocol.Specification(
            containerID: container.id,
            generation: 1,
            token: Self.randomToken(),
            kernelPath: kernel.path,
            initialRamdiskPath: containerInitialRamdisk.path,
            rootDiskPath: disk.path,
            cpus: max(container.cpus, 1),
            memoryBytes: max(container.memoryBytes, 256 * 1_024 * 1_024),
            macAddress: Self.macAddress(container.id),
            bindShares: container.mounts.enumerated().compactMap { index, mount in
                guard mount.kind == .bind else { return nil }
                let source = URL(filePath: mount.source)
                let isDirectory = (try? source.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true
                return .init(tag: "bind-\(index)", source: (isDirectory ? source : source.deletingLastPathComponent()).path, readOnly: mount.readOnly)
            } + [.init(tag: "cengine-io", source: ioDirectory.path, readOnly: false)],
            socketPath: try Self.makeRuntimeSocketPath(),
            logPath: directory.appending(path: "shim.log").path,
            fileSystemSocketPath: infrastructure.specification.fileSystemSocketPath,
            networkSocketPath: infrastructure.specification.networkSocketPath,
            vlans: container.networks.compactMap { networkVLANs[$0.networkID] }
        )
        let shim = try await VMShimClient.launch(specification: specification)
        do {
            _ = try await shim.boot()
            try await shim.prepareRootFS(contentStorePath: root.appending(path: "content").path, layers: image.manifest.layers)
            _ = try await shim.stop()
            shims[container.id] = shim
        } catch {
            _ = try? await shim.shutdown()
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
    }

    public func start(_ container: ContainerRecord) async throws -> [PortBinding] {
        guard let shim = shims[container.id] else { throw EngineError(.notFound, "container VM shim is unavailable") }
        let image = try await resolvedImage(container.image, platform: container.platform)
        let stdin = root.appending(path: "containers/\(container.id)/io/stdin")
        if FileManager.default.fileExists(atPath: stdin.path) { let handle = try FileHandle(forWritingTo: stdin); try handle.truncate(atOffset: 0); try handle.close() }
        _ = try ensureIO(container)
        _ = try await shim.boot()
        struct Prepared: Decodable { let status: String }
        let prepared: Prepared = try await shim.guest(operation: "prepare", payload: try workload(container, image: image), response: Prepared.self)
        guard prepared.status == "prepared" else { throw EngineError(.internalError, "guest did not prepare workload") }
        struct Empty: Encodable {}
        struct Status: Decodable { let status: String; let pid: Int? }
        let response: Status = try await shim.guest(operation: "start", payload: Empty(), response: Status.self)
        guard response.status == "running" else { throw EngineError(.internalError, "workload did not start") }
        completions.removeValue(forKey: container.id)
        activeContainers[container.id] = container
        try await synchronizeFabric()
        return container.ports
    }

    public func stop(_ container: ContainerRecord, timeoutSeconds: Int) async throws -> Int32 {
        guard let shim = shims[container.id] else { return completions[container.id] ?? container.exitCode ?? 0 }
        struct Signal: Encodable { let signal: Int }
        struct Empty: Encodable {}
        struct Status: Decodable { let status: String; let exitCode: Int? }
        _ = try? await shim.guest(operation: "signal", payload: Signal(signal: Self.signalNumber(container.stopSignal)), response: Status.self)
        let code: Int32
        do {
            code = try await AsyncTimeout.run(seconds: Int64(timeoutSeconds)) { let value: Status = try await shim.guest(operation: "wait", payload: Empty(), response: Status.self); return Int32(value.exitCode ?? 0) }
        } catch {
            _ = try? await shim.guest(operation: "signal", payload: Signal(signal: 9), response: Status.self)
            let value: Status = try await shim.guest(operation: "wait", payload: Empty(), response: Status.self)
            code = Int32(value.exitCode ?? 137)
        }
        completions[container.id] = code
        activeContainers.removeValue(forKey: container.id)
        try? await synchronizeFabric()
        _ = try? await shim.stop()
        return code
    }

    public func wait(_ container: ContainerRecord) async throws -> Int32 {
        if let code = completions[container.id] { return code }
        guard let shim = shims[container.id] else { return container.exitCode ?? 0 }
        struct Empty: Encodable {}; struct Status: Decodable { let exitCode: Int? }
        let value: Status = try await shim.guest(operation: "wait", payload: Empty(), response: Status.self)
        let code = Int32(value.exitCode ?? 0)
        completions[container.id] = code
        activeContainers.removeValue(forKey: container.id)
        try? await synchronizeFabric()
        logMonitors[container.id]?.stop()
        _ = try? await shim.stop()
        return code
    }

    public func completion(_ container: ContainerRecord) async -> Int32? { completions[container.id] }

    public func io(for container: ContainerRecord) async throws -> ContainerIOBridge { try ensureIO(container) }

    public func logs(for container: ContainerRecord) async throws -> Data { try ensureIO(container).logData() }

    public func logs(for container: ContainerRecord, options: DockerLogOptions) async throws -> Data { try ensureIO(container).logData(options: options) }

    public func deleteLogs(for container: ContainerRecord) async throws {
        logMonitors.removeValue(forKey: container.id)?.stop()
        bridges.removeValue(forKey: container.id)?.finishOutput()
        let directory = root.appending(path: "containers/\(container.id)/io")
        for name in ["stdout", "stderr", "stdin", "docker.log", "docker.log.entries"] { try? FileManager.default.removeItem(at: directory.appending(path: name)) }
    }

    public func prepareExec(_ exec: ExecRecord, container: ContainerRecord) async throws -> ContainerIOBridge {
        guard let shim = shims[container.id] else { throw EngineError(.notFound, "container VM shim is unavailable") }
        let ioDirectory = root.appending(path: "containers/\(container.id)/io")
        let stdout = ioDirectory.appending(path: "exec-\(exec.id)-stdout"); let stderr = ioDirectory.appending(path: "exec-\(exec.id)-stderr"); let stdin = ioDirectory.appending(path: "exec-\(exec.id)-stdin")
        for url in [stdout,stderr,stdin] { if !FileManager.default.fileExists(atPath: url.path) { FileManager.default.createFile(atPath: url.path, contents: nil) } }
        let bridge = ContainerIOBridge(tty: exec.configuration.tty, logURL: ioDirectory.appending(path: "exec-\(exec.id)-docker.log"))
        let monitor = ContainerLogMonitor(stdoutURL: stdout, stderrURL: stderr, inputURL: stdin, bridge: bridge); monitor.start()
        execBridges[exec.id] = bridge; execMonitors[exec.id] = monitor; execShims[exec.id] = shim
        struct Spec: Encodable { let id: String; let arguments, environment: [String]; let workingDirectory, user: String; let terminal: Bool }
        struct Status: Decodable { let status: String }
        let configuration = exec.configuration
        _ = try await shim.guest(operation: "prepare-exec", payload: Spec(id: exec.id, arguments: configuration.arguments, environment: configuration.environment, workingDirectory: configuration.workingDirectory, user: configuration.user, terminal: configuration.tty), response: Status.self)
        return bridge
    }

    public func startExec(_ exec: ExecRecord) async throws {
        guard let shim = execShims[exec.id] else { throw EngineError(.notFound, "exec is unavailable") }
        struct Request: Encodable { let id: String }; struct Status: Decodable { let status: String; let pid: Int? }
        let status: Status = try await shim.guest(operation: "start-exec", payload: Request(id: exec.id), response: Status.self)
        guard status.status == "running" else { throw EngineError(.internalError, "exec did not start") }
    }

    public func execCompletion(_ exec: ExecRecord) async -> Int32? {
        guard let shim = execShims[exec.id] else { return exec.exitCode }
        struct Request: Encodable { let id: String }; struct Status: Decodable { let status: String; let exitCode: Int? }
        guard let value: Status = try? await shim.guest(operation: "exec-status", payload: Request(id: exec.id), response: Status.self), value.status == "exited" else { return nil }
        execMonitors.removeValue(forKey: exec.id)?.stop(); return Int32(value.exitCode ?? 0)
    }

    public func execIO(_ exec: ExecRecord) async throws -> ContainerIOBridge { guard let bridge = execBridges[exec.id] else { throw EngineError(.notFound, "exec I/O is unavailable") }; return bridge }

    public func execPID(_ exec: ExecRecord) async -> Int32 {
        guard let shim = execShims[exec.id] else { return 0 }; struct Request: Encodable { let id: String }; struct Status: Decodable { let pid: Int? }
        let value: Status? = try? await shim.guest(operation: "exec-status", payload: Request(id: exec.id), response: Status.self); return Int32(value?.pid ?? 0)
    }

    public func execStatus(_ exec: ExecRecord) async -> Int32? { await execCompletion(exec) }

    public func runHealthcheck(_ container: ContainerRecord, arguments: [String], timeoutSeconds: Int64) async throws -> (exitCode: Int32, output: String) {
        let record = ExecRecord(containerID: container.id, configuration: .init(arguments: arguments, environment: container.environment, workingDirectory: container.workingDirectory, user: container.user))
        let bridge = try await prepareExec(record, container: container); try await startExec(record)
        guard let shim = execShims[record.id] else { throw EngineError(.notFound, "healthcheck exec is unavailable") }
        struct Request: Encodable { let id: String }; struct Signal: Encodable { let id: String; let signal: Int }; struct Status: Decodable { let status: String; let exitCode: Int? }
        let code: Int32
        do {
            code = try await AsyncTimeout.run(seconds: timeoutSeconds) { let value: Status = try await shim.guest(operation: "wait-exec", payload: Request(id: record.id), response: Status.self); return Int32(value.exitCode ?? 0) }
        } catch {
            _ = try? await shim.guest(operation: "signal-exec", payload: Signal(id: record.id, signal: 9), response: Status.self)
            let value: Status = try await shim.guest(operation: "wait-exec", payload: Request(id: record.id), response: Status.self); code = Int32(value.exitCode ?? 137)
        }
        execMonitors.removeValue(forKey: record.id)?.stop()
        let ioDirectory = root.appending(path: "containers/\(container.id)/io")
        let rawOutput = ((try? Data(contentsOf: ioDirectory.appending(path: "exec-\(record.id)-stdout"))) ?? Data()) + ((try? Data(contentsOf: ioDirectory.appending(path: "exec-\(record.id)-stderr"))) ?? Data())
        let output = String(decoding: rawOutput, as: UTF8.self)
        execBridges.removeValue(forKey: record.id); execShims.removeValue(forKey: record.id)
        return (code, output)
    }

    public func kill(_ container: ContainerRecord, signal: String) async throws {
        guard let shim = shims[container.id] else { throw EngineError(.notFound, "container VM shim is unavailable") }
        struct Signal: Encodable { let signal: Int }; struct Status: Decodable { let status: String }
        _ = try await shim.guest(operation: "signal", payload: Signal(signal: Self.signalNumber(signal)), response: Status.self)
    }

    public func pause(_ container: ContainerRecord) async throws { guard let shim = shims[container.id] else { throw EngineError(.notFound, "container VM shim is unavailable") }; _ = try await shim.pause() }
    public func resume(_ container: ContainerRecord) async throws { guard let shim = shims[container.id] else { throw EngineError(.notFound, "container VM shim is unavailable") }; _ = try await shim.resume() }
    public func restart(_ container: ContainerRecord, timeoutSeconds: Int) async throws { _ = try await stop(container, timeoutSeconds: timeoutSeconds); _ = try await start(container) }

    public func delete(_ container: ContainerRecord) async throws {
        if let shim = shims.removeValue(forKey: container.id) { _ = try? await shim.shutdown() }
        completions.removeValue(forKey: container.id)
        activeContainers.removeValue(forKey: container.id)
        logMonitors.removeValue(forKey: container.id)?.stop()
        bridges.removeValue(forKey: container.id)?.finishOutput()
        try? FileManager.default.removeItem(at: root.appending(path: "containers/\(container.id)"))
    }

    public func cleanupOrphans(keeping containerIDs: Set<String>) async throws {
        let orphanIDs = shims.keys.filter { !containerIDs.contains($0) }
        for id in orphanIDs {
            if let shim = shims.removeValue(forKey: id) { _ = try? await shim.shutdown() }
        }
    }

    public func deleteVolume(_ name: String) async throws {
        guard !name.isEmpty, !name.contains("/") else { throw EngineError(.badRequest, "invalid volume name") }
        try await storageAdmin.deleteVolume(name)
    }

    public func restoreNetworks(_ values: [NetworkRecord]) async throws -> [NetworkRecord] {
        var restored: [NetworkRecord] = []
        for value in values {
            if let existing = networks[value.id] { restored.append(existing) }
            else { restored.append(try await createNetwork(value)) }
        }
        return restored
    }

    public func createNetwork(_ network: NetworkRecord) async throws -> NetworkRecord {
        if let existing = networks[network.id] { return existing }
        let vlan = try allocateVLAN()
        var value = network
        if value.subnet.isEmpty {
            let automaticNetwork = Self.automaticIPv4Network(vlan: vlan)
            value.subnet = automaticNetwork.subnet
            value.gateway = automaticNetwork.gateway
        } else if value.gateway.isEmpty { value.gateway = Self.firstAddress(value.subnet) }
        if value.ipv6Subnet.isEmpty {
            value.ipv6Subnet = String(format: "fdce:%x::/64", vlan)
            value.ipv6Gateway = String(format: "fdce:%x::1", vlan)
        } else if value.ipv6Gateway.isEmpty { value.ipv6Gateway = Self.firstAddress(value.ipv6Subnet) }
        networks[value.id] = value
        networkVLANs[value.id] = vlan
        try persistNetworks()
        try await synchronizeFabric()
        return value
    }

    public func deleteNetwork(_ network: NetworkRecord) async throws {
        networks.removeValue(forKey: network.id)
        networkVLANs.removeValue(forKey: network.id)
        try persistNetworks()
        try await synchronizeFabric()
    }

    public func updateNetworkRecords(_ containers: [ContainerRecord]) async throws {
        knownContainers = Dictionary(uniqueKeysWithValues: containers.map { ($0.id, $0) })
        activeContainers = Dictionary(uniqueKeysWithValues: containers.filter { $0.phase == .running || $0.phase == .paused }.map { ($0.id, $0) })
        for container in containers {
            guard let shim = shims[container.id], (try? await shim.status().state) == .running else { continue }
            let desired = Set(container.networks.map(\.networkID))
            let existing = appliedNetworks[container.id] ?? []
            struct NetworkRequest: Encodable { let endpoint: GuestProtocol.NetworkEndpoint?; let name: String? }
            struct Status: Decodable { let status: String }
            _ = try await shim.configureNetwork(vlans: desired.compactMap { networkVLANs[$0] })
            for id in existing.subtracting(desired) {
                _ = try? await shim.guest(operation: "disconnect-network", payload: NetworkRequest(endpoint: nil, name: id), response: Status.self)
            }
            for endpoint in networkEndpoints(container) where !existing.contains(endpoint.networkID) {
                _ = try await shim.guest(operation: "connect-network", payload: NetworkRequest(endpoint: endpoint, name: nil), response: Status.self)
            }
            appliedNetworks[container.id] = desired
        }
        try await synchronizeFabric()
    }

    public func endpointAddresses(for container: ContainerRecord) async -> [String: BackendEndpointAddress] {
        Dictionary(uniqueKeysWithValues: container.networks.map {
            ($0.networkID, BackendEndpointAddress(ipv4Address: $0.ipv4Address ?? "", ipv6Address: $0.ipv6Address ?? ""))
        })
    }

    public func statistics(_ container: ContainerRecord) async throws -> BackendStatistics {
        guard let shim = shims[container.id] else { throw EngineError(.notFound, "container VM shim is unavailable") }
        struct Network: Decodable { let name: String; let rxBytes, rxPackets, rxErrors, txBytes, txPackets, txErrors: UInt64 }
        struct Value: Decodable { let cpuTotalNanoseconds, cpuUserNanoseconds, cpuSystemNanoseconds, memoryUsage, memoryCache, pids, blockReadBytes, blockWriteBytes: UInt64; let networks: [Network] }
        struct Empty: Encodable {}
        let value: Value = try await shim.guest(operation: "statistics", payload: Empty(), response: Value.self)
        return .init(cpuTotalNanoseconds: value.cpuTotalNanoseconds, cpuUserNanoseconds: value.cpuUserNanoseconds, cpuSystemNanoseconds: value.cpuSystemNanoseconds, memoryUsage: value.memoryUsage, memoryLimit: container.memoryBytes, memoryCache: value.memoryCache, pids: value.pids, blockReadBytes: value.blockReadBytes, blockWriteBytes: value.blockWriteBytes, networks: value.networks.map { .init(name: $0.name, rxBytes: $0.rxBytes, rxPackets: $0.rxPackets, rxErrors: $0.rxErrors, txBytes: $0.txBytes, txPackets: $0.txPackets, txErrors: $0.txErrors) })
    }

    public func top(_ container: ContainerRecord, arguments: [String]) async throws -> (titles: [String], processes: [[String]]) {
        guard let shim = shims[container.id] else { throw EngineError(.notFound, "container VM shim is unavailable") }
        struct ProcessValue: Decodable { let pid: Int; let user: String; let command: String }; struct Empty: Encodable {}
        let values: [ProcessValue] = try await shim.guest(operation: "top", payload: Empty(), response: [ProcessValue].self)
        return (["UID", "PID", "CMD"], values.map { [$0.user, String($0.pid), $0.command] })
    }

    public func copyIn(_ container: ContainerRecord, extractedDirectory: URL, destination: String, ownership: [ArchiveOwnership]) async throws {
        guard let shim = shims[container.id] else { throw EngineError(.notFound, "container VM shim is unavailable") }
        let transfer = UUID().uuidString; let hostTransfer = root.appending(path: "containers/\(container.id)/io/\(transfer)")
        try FileManager.default.createDirectory(at: hostTransfer, withIntermediateDirectories: true); defer { try? FileManager.default.removeItem(at: hostTransfer) }
        for entry in try FileManager.default.contentsOfDirectory(at: extractedDirectory, includingPropertiesForKeys: nil) { try FileManager.default.copyItem(at: entry, to: hostTransfer.appending(path: entry.lastPathComponent)) }
        struct Owner: Encodable { let path: String; let user: UInt32; let group: UInt32 }; struct Request: Encodable { let source: String; let destination: String; let ownership: [Owner] }; struct Status: Decodable { let status: String }
        _ = try await shim.boot(); _ = try await shim.guest(operation: "copy-in", payload: Request(source: transfer, destination: destination, ownership: ownership.map { .init(path: $0.path, user: $0.user, group: $0.group) }), response: Status.self)
        if container.phase != .running { _ = try? await shim.stop() }
    }

    public func copyOut(_ container: ContainerRecord, source: String, destinationDirectory: URL) async throws {
        guard let shim = shims[container.id] else { throw EngineError(.notFound, "container VM shim is unavailable") }
        let transfer = UUID().uuidString; let hostTransfer = root.appending(path: "containers/\(container.id)/io/\(transfer)"); defer { try? FileManager.default.removeItem(at: hostTransfer) }
        struct Request: Encodable { let source: String; let destination: String }; struct Status: Decodable { let status: String }
        _ = try await shim.guest(operation: "copy-out", payload: Request(source: source, destination: transfer), response: Status.self)
        for entry in try FileManager.default.contentsOfDirectory(at: hostTransfer, includingPropertiesForKeys: nil) { try FileManager.default.copyItem(at: entry, to: destinationDirectory.appending(path: entry.lastPathComponent)) }
    }

    private func resolvedImage(_ reference: String, platform: String) async throws -> OCIStoredImage {
        if let value = try? await store.image(reference: reference, platform: platform) { return value }
        return try await pull(reference, platform: platform, credentials: nil) { _ in }
    }

    private func ensureIO(_ container: ContainerRecord) throws -> ContainerIOBridge {
        if let existing = bridges[container.id] { return existing }
        let directory = root.appending(path: "containers/\(container.id)/io", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        for name in ["docker.log", "docker.log.entries"] { try? FileManager.default.removeItem(at: directory.appending(path: name)) }
        let bridge = ContainerIOBridge(tty: container.tty, logURL: directory.appending(path: "docker.log"))
        let monitor = ContainerLogMonitor(directory: directory, bridge: bridge)
        bridges[container.id] = bridge; logMonitors[container.id] = monitor; monitor.start()
        return bridge
    }

    private func pull(_ reference: String, platform: String, credentials: RegistryCredentials?, progress: @escaping ImagePullProgressHandler) async throws -> OCIStoredImage {
        try await store.pull(reference: reference, platform: platform, credentials: credentials, progress: progress)
    }

    private func workload(_ container: ContainerRecord, image: OCIStoredImage) async throws -> GuestProtocol.Workload {
        let config = image.configuration.config
        let arguments = (container.entrypoint ?? config?.entrypoint ?? []) + (container.command ?? config?.command ?? [])
        guard !arguments.isEmpty else { throw EngineError(.badRequest, "container has no command") }
        let environment = Self.mergeEnvironment(image: config?.environment ?? [], container: container.environment)
        let mounts = container.mounts.enumerated().map { index, mount in
            let bindSubpath: String? = {
                guard mount.kind == .bind else { return mount.subpath }
                let source = URL(filePath: mount.source)
                let isDirectory = (try? source.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true
                let base = isDirectory ? nil : source.lastPathComponent
                return [base, mount.subpath].compactMap { $0 }.joined(separator: "/").nilIfEmpty
            }()
            let options = mount.kind == .tmpfs ? ["size=\(max(mount.tmpfsSizeBytes ?? 64 * 1_024 * 1_024, 0))", String(format: "mode=%o", mount.tmpfsMode ?? 0o1777)] : []
            return GuestProtocol.Mount(
                kind: mount.kind.rawValue,
                source: mount.kind == .bind ? "bind-\(index)" : mount.source,
                destination: mount.destination,
                readOnly: mount.readOnly,
                options: options,
                token: mount.kind == .volume ? tokenIssuer.token(for: mount.source) : nil,
                subpath: bindSubpath,
                noCopy: mount.noCopy
            )
        }
        return GuestProtocol.Workload(
            id: container.id, rootDevice: "/dev/vda", arguments: arguments,
            environment: environment,
            workingDirectory: container.workingDirectory.isEmpty ? (config?.workingDirectory ?? "/") : container.workingDirectory,
            hostname: container.hostname, user: Self.user(container.user.isEmpty ? config?.user : container.user),
            terminal: container.tty, readOnlyRoot: container.readOnlyRootfs, stopSignal: container.stopSignal,
            mounts: mounts, networks: networkEndpoints(container), hosts: networkHosts(container), resources: .init(memoryBytes: container.memoryBytes, cpuQuota: Int64(container.cpus * 100_000), cpuPeriod: 100_000, pids: 0), privileged: container.privileged
        )
    }

    private func networkEndpoints(_ container: ContainerRecord) -> [GuestProtocol.NetworkEndpoint] {
        container.networks.compactMap { endpoint in
            guard let network = networks[endpoint.networkID], let vlan = networkVLANs[endpoint.networkID] else { return nil }
            var addresses: [String] = []
            if let address = endpoint.ipv4Address, !address.isEmpty { addresses.append(Self.withPrefix(address, from: network.subnet)) }
            if let address = endpoint.ipv6Address, !address.isEmpty { addresses.append(Self.withPrefix(address, from: network.ipv6Subnet)) }
            var gateways: [String] = []
            if endpoint.ipv4Address != nil, !network.gateway.isEmpty { gateways.append(network.gateway) }
            if endpoint.ipv6Address != nil, !network.ipv6Gateway.isEmpty { gateways.append(network.ipv6Gateway) }
            return .init(
                networkID: endpoint.networkID,
                vlan: vlan,
                name: "v\(vlan)",
                macAddress: Self.macAddress(container.id + endpoint.networkID),
                addresses: addresses,
                gateways: gateways,
                dns: network.internalNetwork ? [] : [network.gateway].filter { !$0.isEmpty },
                aliases: endpoint.aliases
            )
        }
    }

    private func networkHosts(_ container: ContainerRecord) -> [String: String] {
        var result: [String: String] = [:]
        let networkIDs = Set(container.networks.map(\.networkID))
        for peer in knownContainers.values {
            for endpoint in peer.networks where networkIDs.contains(endpoint.networkID) {
                guard let address = endpoint.ipv4Address ?? endpoint.ipv6Address, !address.isEmpty else { continue }
                for name in Set(endpoint.aliases + [peer.name, peer.hostname]).filter({ !$0.isEmpty }) { result[name] = address }
            }
        }
        return result
    }

    static func automaticIPv4Network(vlan: UInt16) -> (subnet: String, gateway: String) {
        precondition((1...4094).contains(vlan), "VLAN must be in the allocatable range")
        let slot = Int(vlan)
        let secondOctet = 240 + (slot / 256)
        let thirdOctet = slot % 256
        let prefix = "10.\(secondOctet).\(thirdOctet)"
        return ("\(prefix).0/24", "\(prefix).1")
    }

    private func allocateVLAN() throws -> UInt16 {
        let used = Set(networkVLANs.values)
        guard let vlan = (1...4094).first(where: { !used.contains(UInt16($0)) }) else { throw EngineError(.conflict, "all VLAN identifiers are allocated") }
        return UInt16(vlan)
    }

    private func persistNetworks() throws {
        let state = Dictionary(uniqueKeysWithValues: networks.compactMap { id, record in networkVLANs[id].map { (id, NetworkState(record: record, vlan: $0)) } })
        try JSONEncoder().encode(state).write(to: root.appending(path: "networks.json"), options: .atomic)
    }

    private func synchronizeFabric() async throws {
        let values = networks.compactMap { id, network -> VMShimClient.FabricNetwork? in
            guard let vlan = networkVLANs[id], !network.subnet.isEmpty else { return nil }
            let ports = activeContainers.values.flatMap { container -> [VMShimClient.FabricPort] in
                guard let endpoint = container.networks.first(where: { $0.networkID == id }), let address = endpoint.ipv4Address, !address.isEmpty else { return [] }
                return container.ports.compactMap { binding in
                    guard binding.hostPort != 0 else { return nil }
                    return .init(proto: binding.proto, externalPort: binding.hostPort, internalAddress: address, internalPort: binding.containerPort)
                }
            }
            return .init(id: id, vlan: vlan, subnet: network.subnet, ipv6Subnet: network.ipv6Subnet, internalNetwork: network.internalNetwork, isolated: network.ipv4GatewayMode == .isolated, ports: ports)
        }
        _ = try await infrastructure.configureFabric(networks: values.sorted { $0.id < $1.id })
    }

    private static func recoverOrLaunch(_ specification: VMShimProtocol.Specification) async throws -> VMShimClient {
        let specURL = VMShimClient.specificationURL(for: specification)
        if let data = try? Data(contentsOf: specURL), let existing = try? JSONDecoder().decode(VMShimProtocol.Specification.self, from: data) {
            let client = VMShimClient(specification: existing)
            if (try? await client.status()) != nil { return client }
        }
        return try await VMShimClient.launch(specification: specification)
    }

    static func makeRuntimeSocketPath() throws -> String {
        let directory = "/tmp/cengine-\(getuid())"
        if Darwin.mkdir(directory, 0o700) != 0, errno != EEXIST {
            throw EngineError(.internalError, "could not create shim runtime directory: \(String(cString: strerror(errno)))")
        }
        var metadata = stat()
        guard Darwin.lstat(directory, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFDIR,
              metadata.st_uid == getuid() else {
            throw EngineError(.unauthorized, "shim runtime directory is not owned by the current user")
        }
        guard Darwin.chmod(directory, 0o700) == 0 else {
            throw EngineError(.internalError, "could not secure shim runtime directory: \(String(cString: strerror(errno)))")
        }
        return "\(directory)/\(UUID().uuidString).sock"
    }

    private static func randomToken() -> String {
        let data = VolumeAccessToken.random().secret
        return data.map { String(format: "%02x", $0) }.joined()
    }

    private static func mergeEnvironment(image: [String], container: [String]) -> [String] {
        var order: [String] = []; var values: [String: String] = [:]
        for entry in image + container {
            let key = entry.split(separator: "=", maxSplits: 1).first.map(String.init) ?? entry
            if values[key] == nil { order.append(key) }
            values[key] = entry
        }
        return order.compactMap { values[$0] }
    }

    private static func user(_ value: String?) -> GuestProtocol.User {
        let raw = value ?? ""; if raw.isEmpty { return .init() }
        let parts = raw.split(separator: ":", omittingEmptySubsequences: false)
        guard let uid = UInt32(parts[0]) else { return .init(username: raw) }
        let components = parts.compactMap { UInt32($0) }
        return .init(uid: uid, gid: components.count > 1 ? components[1] : uid)
    }

    private static func signalNumber(_ value: String) -> Int {
        let normalized = value.uppercased().replacingOccurrences(of: "SIG", with: "")
        if let number = Int(normalized) { return number }
        return ["HUP": 1, "INT": 2, "QUIT": 3, "KILL": 9, "USR1": 10, "USR2": 12, "PIPE": 13, "ALRM": 14, "TERM": 15, "CHLD": 17, "CONT": 18, "STOP": 19, "TSTP": 20][normalized] ?? 15
    }

    private static func macAddress(_ id: String) -> String {
        let digest = SHA256.hash(data: Data(id.utf8))
        var bytes = Array(digest.prefix(4)); while bytes.count < 4 { bytes.append(0) }
        return String(format: "02:ce:%02x:%02x:%02x:%02x", bytes[0], bytes[1], bytes[2], bytes[3])
    }

    private static func withPrefix(_ address: String, from subnet: String) -> String {
        if address.contains("/") { return address }
        return address + "/" + (subnet.split(separator: "/").dropFirst().first.map(String.init) ?? (address.contains(":") ? "64" : "24"))
    }

    private static func firstAddress(_ subnet: String) -> String {
        let address = String(subnet.split(separator: "/").first ?? "")
        if address.contains(":") { return address.trimmingCharacters(in: CharacterSet(charactersIn: ":")) + "::1" }
        var parts = address.split(separator: ".").map(String.init)
        if parts.count == 4 { parts[3] = "1"; return parts.joined(separator: ".") }
        return ""
    }

    private static func createSparseFile(at url: URL, size: UInt64) throws {
        guard !FileManager.default.fileExists(atPath: url.path) else { return }
        guard FileManager.default.createFile(atPath: url.path, contents: nil) else { throw EngineError(.internalError, "could not create sparse disk") }
        let handle = try FileHandle(forWritingTo: url); try handle.truncate(atOffset: size); try handle.close()
    }

    private static func prepareBindSources(_ mounts: [MountRecord]) throws {
        for mount in mounts where mount.kind == .bind {
            let source = URL(filePath: mount.source)
            if FileManager.default.fileExists(atPath: source.path) { continue }
            guard mount.createSourceIfMissing != false else { throw EngineError(.notFound, "bind source \(mount.source) does not exist") }
            try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        }
    }

    private struct NetworkState: Codable { let record: NetworkRecord; let vlan: UInt16 }
}

private extension String { var nilIfEmpty: String? { isEmpty ? nil : self } }
#endif

#if os(macOS)
import CEngineCore
import CryptoKit
import Darwin
import Foundation

public actor RawVirtualizationBackend: ContainerBackend {
    enum VolumeStorageMode: String, Codable, Sendable { case block, shared }

    struct ResolvedExecContext: Equatable, Sendable {
        let environment: [String]
        let workingDirectory: String
        let user: GuestProtocol.User
        let noNewPrivileges: Bool
        let privileged: Bool
    }

    public static let defaultRootDiskBytes: UInt64 = 64 * 1_024 * 1_024 * 1_024
    public static let defaultVolumeDiskBytes = VolumeRecord.defaultSizeBytes
    public static let defaultStorageDiskBytes = VolumeRecord.defaultSizeBytes
    static let managementServerAddress = "100.64.0.1"

    private let root: URL
    private let kernel: URL
    private let containerInitialRamdisk: URL
    private let store: OCIContentStore
    private let tokenIssuer: VolumeAccessToken
    private let infrastructure: VMShimClient
    private let storage: StorageAdministrativeClient
    private let portForwarder = PortForwarder()
    private var shims: [String: VMShimClient] = [:]
    private var completions: [String: Int32] = [:]
    private var completionTasks: [String: Task<Int32, Never>] = [:]
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
    private var preparedBindSources: [String: [Int: PreparedBindSource]] = [:]
    private var volumeStorageModes: [String: VolumeStorageMode] = [:]

    public init(root: URL, kernel: URL, containerInitialRamdisk: URL, storageInitialRamdisk: URL) async throws {
        self.root = root
        self.kernel = kernel
        self.containerInitialRamdisk = containerInitialRamdisk
        let containers = root.appending(path: "containers", directoryHint: .isDirectory)
        let volumes = root.appending(path: "volumes", directoryHint: .isDirectory)
        let infrastructureRoot = root.appending(path: "infrastructure", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: containers, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: volumes, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: infrastructureRoot, withIntermediateDirectories: true)
        store = try OCIContentStore(root: root.appending(path: "content"))
        if let data = try? Data(contentsOf: root.appending(path: "networks.json")),
           let state = try? JSONDecoder().decode([String: NetworkState].self, from: data) {
            networks = state.mapValues(\.record)
            networkVLANs = state.mapValues(\.vlan)
        }
        if let data = try? Data(contentsOf: root.appending(path: "volume-storage.json")),
           let state = try? JSONDecoder().decode([String: VolumeStorageMode].self, from: data) {
            volumeStorageModes = state
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
            kernelArguments: [
                tokenIssuer.kernelArgument,
                "cengine.management_address=\(Self.managementServerAddress)/10",
                "cengine.management_vlan=\(VMShimProtocol.managementVLAN)",
            ],
            fileSystemSocketPath: try Self.makeRuntimeSocketPath(),
            networkSocketPath: try Self.makeRuntimeSocketPath(),
            vlans: [VMShimProtocol.managementVLAN]
        )
        infrastructure = try await Self.recoverOrLaunch(infrastructureSpec)
        storage = StorageAdministrativeClient(
            socketPath: infrastructureSpec.fileSystemSocketPath!,
            tokenIssuer: tokenIssuer
        )
        _ = try await infrastructure.boot()
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
        portForwarder.stopAll()
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

    public func deleteImage(reference: String, platforms: [OCIPlatform]) async throws -> [String] {
        let removed = try await store.remove(reference: reference, platforms: platforms)
        _ = try await store.prune()
        return removed
    }

    public func tagImage(existing: String, new: String) async throws {
        guard let descriptor = await store.descriptor(for: existing) else { throw EngineError(.notFound, "image \(existing) not found") }
        try await store.tag(descriptor, as: new)
    }

    public func loadImages(fromOCILayout directory: URL) async throws -> [BackendImage] { try await store.importLayout(directory) }

    public func loadImages(fromOCILayout directory: URL, platforms: [OCIPlatform]) async throws -> [BackendImage] {
        try await store.importLayout(directory, platforms: platforms)
    }

    public func saveImages(references: [String], platform: String) async throws -> Data {
        try await store.exportLayout(references: references, platforms: [try OCIPlatform(platform)])
    }

    public func saveImages(references: [String], platforms: [OCIPlatform]) async throws -> Data {
        try await store.exportLayout(references: references, platforms: platforms)
    }

    public func pushImage(reference: String, platform: String, credentials: RegistryCredentials?) async throws {
        try await store.push(reference: reference, platform: try OCIPlatform(platform), credentials: credentials)
    }

    public func pushImage(reference: String, platform: OCIPlatform?, credentials: RegistryCredentials?) async throws {
        try await store.push(reference: reference, platform: platform, credentials: credentials)
    }

    public func imageHistory(reference: String, platform: String) async throws -> [ImageHistoryEntry] {
        try await store.history(reference: reference, platform: try OCIPlatform(platform))
    }

    public func imageHistory(reference: String, platform: OCIPlatform?) async throws -> [ImageHistoryEntry] {
        try await store.history(reference: reference, platform: platform)
    }

    public func imageAttestations(reference: String, platform: OCIPlatform?, predicateTypes: [String], includeStatement: Bool) async throws -> [ImageAttestationRecord] {
        try await store.attestations(
            reference: reference,
            platform: platform,
            predicateTypes: predicateTypes,
            includeStatement: includeStatement
        )
    }

    public func prepare(_ container: ContainerRecord) async throws {
        if shims[container.id] != nil { return }
        if try await relaunchPreparedShim(container) != nil { return }
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
        let bindSources = try HostBindSourceResolver(root: root.appending(path: "bind-sources")).resolve(container.mounts)
        preparedBindSources[container.id] = bindSources
        try Self.createSparseFile(at: disk, size: Self.defaultRootDiskBytes)
        let specification = try containerShimSpecification(
            container,
            directory: directory,
            bindSources: bindSources,
            generation: 1,
            volumeDisks: []
        )
        let shim = try await VMShimClient.launch(specification: specification)
        do {
            _ = try await shim.boot()
            try await shim.prepareRootFS(contentStorePath: root.appending(path: "content").path, layers: image.manifest.layers)
            _ = try await shim.stop()
            shims[container.id] = shim
        } catch {
            _ = try? await shim.shutdown()
            preparedBindSources.removeValue(forKey: container.id)
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
    }

    public func start(_ container: ContainerRecord) async throws -> [PortBinding] {
        guard let preparedShim = shims[container.id] else { throw EngineError(.notFound, "container VM shim is unavailable") }
        let image = try await resolvedImage(container.image, platform: container.platform)
        let modes = try resolveVolumeStorageModes(for: container)
        let shim = try await reconfigureVolumeDisks(preparedShim, container: container, modes: modes)
        _ = try ensureIO(container, replacingStoppedSession: true)
        _ = try await shim.boot()
        struct Prepared: Decodable { let status: String }
        let prepared: Prepared = try await shim.guest(operation: "prepare", payload: try workload(container, image: image, volumeModes: modes), response: Prepared.self)
        guard prepared.status == "prepared" else { throw EngineError(.internalError, "guest did not prepare workload") }
        struct Empty: Encodable {}
        struct Status: Decodable { let status: String; let pid: Int? }
        let response: Status = try await shim.guest(operation: "start", payload: Empty(), response: Status.self)
        guard response.status == "running" else { throw EngineError(.internalError, "workload did not start") }
        completionTasks.removeValue(forKey: container.id)?.cancel()
        completions.removeValue(forKey: container.id)
        do {
            var active = container
            if !container.ports.isEmpty {
                let hasIPv4 = container.networks.contains { $0.ipv4Address != nil }
                guard hasIPv4 || container.networks.contains(where: { $0.ipv6Address != nil }) else {
                    throw EngineError(.conflict, "published ports require a container network endpoint")
                }
                active.ports = try await portForwarder.start(
                    containerID: container.id,
                    bindings: container.ports,
                    connect: { binding in
                        try await shim.startPortStream(
                            transport: binding.proto.lowercased(),
                            port: binding.containerPort,
                            ipv6: !hasIPv4
                        )
                    }
                )
            }
            activeContainers[container.id] = active
            try await synchronizeFabric()
            return active.ports
        } catch {
            portForwarder.stop(containerID: container.id)
            activeContainers.removeValue(forKey: container.id)
            _ = try? await shim.stop()
            throw error
        }
    }

    public func stop(_ container: ContainerRecord, timeoutSeconds: Int) async throws -> Int32 {
        if let code = completions[container.id] { return code }
        guard let shim = shims[container.id] else { return completions[container.id] ?? container.exitCode ?? 0 }
        struct Signal: Encodable { let signal: Int }
        struct Empty: Encodable {}
        struct Status: Decodable { let status: String; let exitCode: Int? }
        _ = try? await shim.guest(operation: "signal", payload: Signal(signal: Self.signalNumber(container.stopSignal)), response: Status.self)
        if let existing = completionTasks[container.id] {
            let code: Int32
            do {
                code = try await AsyncTimeout.run(seconds: Int64(timeoutSeconds)) { await existing.value }
            } catch {
                _ = try? await shim.guest(operation: "signal", payload: Signal(signal: 9), response: Status.self)
                code = await existing.value
            }
            return await recordCompletion(container, code: code)
        }
        let task = Task {
            let code: Int32
            do {
                code = try await AsyncTimeout.run(seconds: Int64(timeoutSeconds)) {
                    let value: Status = try await shim.guest(operation: "wait", payload: Empty(), response: Status.self)
                    return Int32(value.exitCode ?? 0)
                }
            } catch {
                _ = try? await shim.guest(operation: "signal", payload: Signal(signal: 9), response: Status.self)
                let value: Status? = try? await shim.guest(operation: "wait", payload: Empty(), response: Status.self)
                code = Int32(value?.exitCode ?? 137)
            }
            _ = try? await shim.stop()
            return code
        }
        completionTasks[container.id] = task
        return await recordCompletion(container, code: task.value)
    }

    public func wait(_ container: ContainerRecord) async throws -> Int32 {
        if let code = completions[container.id] { return code }
        guard let shim = shims[container.id] else { return container.exitCode ?? 0 }
        struct Empty: Encodable {}; struct Status: Decodable { let exitCode: Int? }
        let task: Task<Int32, Never>
        if let existing = completionTasks[container.id] {
            task = existing
        } else {
            task = Task {
                let value: Status? = try? await shim.guest(operation: "wait", payload: Empty(), response: Status.self)
                _ = try? await shim.stop()
                return value.map { Int32($0.exitCode ?? 0) } ?? container.exitCode ?? 137
            }
            completionTasks[container.id] = task
        }
        return await recordCompletion(container, code: task.value)
    }

    public func completion(_ container: ContainerRecord) async -> Int32? {
        if let code = completions[container.id] { return code }
        return try? await wait(container)
    }

    public func recover(_ container: ContainerRecord) async throws -> BackendContainerRecovery {
        guard let shim = shims[container.id] else { return .unavailable }
        let status = try await shim.status()
        switch status.state {
        case .running:
            struct Empty: Encodable {}
            struct WorkloadStatus: Decodable { let status: String; let exitCode: Int? }
            let workload: WorkloadStatus = try await shim.guest(
                operation: "status", payload: Empty(), response: WorkloadStatus.self
            )
            guard workload.status == "running" else {
                let code = Int32(workload.exitCode ?? 0)
                completions[container.id] = code
                _ = try? await shim.stop()
                return .exited(code)
            }
            try await restoreLiveContainer(container)
            return .running
        case .paused:
            try await restoreLiveContainer(container)
            return .paused
        default:
            return .unavailable
        }
    }

    public func io(for container: ContainerRecord) async throws -> ContainerIOBridge {
        try ensureIO(container, replacingStoppedSession: true)
    }

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
        let image = try await resolvedImage(container.image, platform: container.platform)
        let ioDirectory = root.appending(path: "containers/\(container.id)/io")
        let stdout = ioDirectory.appending(path: "exec-\(exec.id)-stdout"); let stderr = ioDirectory.appending(path: "exec-\(exec.id)-stderr"); let stdin = ioDirectory.appending(path: "exec-\(exec.id)-stdin")
        for url in [stdout,stderr,stdin] { if !FileManager.default.fileExists(atPath: url.path) { FileManager.default.createFile(atPath: url.path, contents: nil) } }
        let stdinClosed = stdin.appendingPathExtension("closed")
        try? FileManager.default.removeItem(at: stdinClosed)
        if !exec.configuration.attachStdin { FileManager.default.createFile(atPath: stdinClosed.path, contents: nil) }
        let bridge = ContainerIOBridge(tty: exec.configuration.tty, logURL: ioDirectory.appending(path: "exec-\(exec.id)-docker.log"))
        let monitor = ContainerLogMonitor(stdoutURL: stdout, stderrURL: stderr, inputURL: stdin, bridge: bridge); monitor.start()
        execBridges[exec.id] = bridge; execMonitors[exec.id] = monitor; execShims[exec.id] = shim
        struct Status: Decodable { let status: String }
        let configuration = exec.configuration
        let context = Self.resolveExecContext(
            configuration: configuration,
            containerEnvironment: container.environment,
            containerWorkingDirectory: container.workingDirectory,
            containerUser: container.user,
            containerPrivileged: container.privileged,
            imageEnvironment: image.configuration.config?.environment ?? [],
            imageWorkingDirectory: image.configuration.config?.workingDirectory,
            imageUser: image.configuration.config?.user
        )
        _ = try await shim.guest(
            operation: "prepare-exec",
            payload: GuestProtocol.Exec(
                id: exec.id, arguments: configuration.arguments, environment: context.environment,
                workingDirectory: context.workingDirectory, user: context.user,
                terminal: configuration.tty, attachStdin: configuration.attachStdin,
                attachStdout: configuration.attachStdout, attachStderr: configuration.attachStderr,
                noNewPrivileges: context.noNewPrivileges, privileged: context.privileged,
                capabilityAdd: container.capabilityAdd, capabilityDrop: container.capabilityDrop
            ),
            response: Status.self
        )
        return bridge
    }

    public func startExec(_ exec: ExecRecord) async throws {
        guard let shim = execShims[exec.id] else { throw EngineError(.notFound, "exec is unavailable") }
        struct Request: Encodable { let id: String }; struct Status: Decodable { let status: String; let pid: Int? }
        let status: Status = try await shim.guest(operation: "start-exec", payload: Request(id: exec.id), response: Status.self)
        guard status.status == "running" else { throw EngineError(.internalError, "exec did not start") }
    }

    public func startAttachedExec(_ exec: ExecRecord) async throws -> CInt? {
        guard let shim = execShims[exec.id] else { throw EngineError(.notFound, "exec is unavailable") }
        return try await shim.startExecStream(id: exec.id)
    }

    public func execCompletion(_ exec: ExecRecord) async -> Int32? {
        guard let shim = execShims[exec.id] else { return exec.exitCode }
        struct Request: Encodable { let id: String }; struct Status: Decodable { let status: String; let exitCode: Int? }
        guard let value: Status = try? await shim.guest(operation: "wait-exec", payload: Request(id: exec.id), response: Status.self), value.status == "exited" else { return nil }
        execMonitors.removeValue(forKey: exec.id)?.stop(); return Int32(value.exitCode ?? 0)
    }

    public func execIO(_ exec: ExecRecord) async throws -> ContainerIOBridge { guard let bridge = execBridges[exec.id] else { throw EngineError(.notFound, "exec I/O is unavailable") }; return bridge }

    public func execPID(_ exec: ExecRecord) async -> Int32 {
        guard let shim = execShims[exec.id] else { return 0 }
        struct Request: Encodable { let id: String }
        struct Status: Decodable { let status: String; let pid: Int? }
        for _ in 0..<1_000 where !Task.isCancelled {
            guard let value: Status = try? await shim.guest(
                operation: "exec-status", payload: Request(id: exec.id), response: Status.self
            ) else { return 0 }
            if let pid = value.pid, pid > 0 { return Int32(pid) }
            guard value.status == "created" || value.status == "starting" else { return 0 }
            try? await Task.sleep(for: .milliseconds(10))
        }
        return 0
    }

    public func execStatus(_ exec: ExecRecord) async -> Int32? {
        guard let shim = execShims[exec.id] else { return exec.exitCode }
        struct Request: Encodable { let id: String }; struct Status: Decodable { let status: String; let exitCode: Int? }
        guard let value: Status = try? await shim.guest(operation: "exec-status", payload: Request(id: exec.id), response: Status.self), value.status == "exited" else { return nil }
        return Int32(value.exitCode ?? 0)
    }

    public func runHealthcheck(_ container: ContainerRecord, arguments: [String], timeoutSeconds: Int64) async throws -> (exitCode: Int32, output: String) {
        let record = ExecRecord(containerID: container.id, configuration: .init(arguments: arguments))
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

    public func updateResources(_ container: ContainerRecord) async throws {
        guard container.phase != .paused else {
            throw EngineError(.conflict, "cannot update resources while container \(container.id) is paused")
        }
        if container.phase != .running {
            if let shim = shims.removeValue(forKey: container.id) { _ = try? await shim.shutdown() }
            guard try await relaunchPreparedShim(container) != nil else {
                throw EngineError(.notFound, "container VM preparation is unavailable")
            }
            knownContainers[container.id] = container
            return
        }
        guard let shim = shims[container.id] else {
            throw EngineError(.notFound, "container VM shim is unavailable")
        }
        guard container.cpus <= shim.specification.cpus else {
            throw EngineError(
                .conflict,
                "requested CPU limit of \(container.cpus) exceeds running VM capacity of \(shim.specification.cpus); stop the container before increasing its VM capacity"
            )
        }
        let requiredMemoryBytes = try VirtualMachineMemory.capacity(forHardLimit: container.memoryBytes)
        guard requiredMemoryBytes <= shim.specification.memoryBytes else {
            throw EngineError(
                .conflict,
                "requested memory limit of \(container.memoryBytes) bytes exceeds running VM capacity of \(shim.specification.memoryBytes) bytes; stop the container before increasing its VM capacity"
            )
        }
        let resources = GuestProtocol.Resources(
            memoryBytes: container.memoryBytes,
            cpuQuota: Int64(container.cpus * 100_000),
            cpuPeriod: 100_000,
            pids: container.pidsLimit
        )
        struct Status: Decodable { let status: String }
        let response: Status = try await shim.guest(
            operation: "update-resources", payload: resources, response: Status.self
        )
        guard response.status == "running" else {
            throw EngineError(.conflict, "workload is not running")
        }
        knownContainers[container.id] = container
        activeContainers[container.id] = container
    }

    public func delete(_ container: ContainerRecord) async throws {
        portForwarder.stop(containerID: container.id)
        if let shim = shims.removeValue(forKey: container.id) { _ = try? await shim.shutdown() }
        completionTasks.removeValue(forKey: container.id)?.cancel()
        completions.removeValue(forKey: container.id)
        activeContainers.removeValue(forKey: container.id)
        logMonitors.removeValue(forKey: container.id)?.stop()
        bridges.removeValue(forKey: container.id)?.finishOutput()
        try? FileManager.default.removeItem(at: root.appending(path: "containers/\(container.id)"))
    }

    public func cleanupOrphans(keeping containerIDs: Set<String>) async throws {
        let orphanIDs = shims.keys.filter { !containerIDs.contains($0) }
        for id in orphanIDs {
            portForwarder.stop(containerID: id)
            if let shim = shims.removeValue(forKey: id) { _ = try? await shim.shutdown() }
        }
    }

    public func deleteVolume(_ name: String) async throws {
        guard !name.isEmpty, !name.contains("/") else { throw EngineError(.badRequest, "invalid volume name") }
        try await storage.deleteVolume(name)
        try? FileManager.default.removeItem(at: volumeDiskURL(name: name))
        volumeStorageModes.removeValue(forKey: name)
        try persistVolumeStorageModes()
    }

    public func restoreNetworks(_ values: [NetworkRecord]) async throws -> [NetworkRecord] {
        var restored: [NetworkRecord] = []
        for value in values {
            if let existing = networks[value.id] { restored.append(existing) }
            else { restored.append(try await createNetwork(value)) }
        }
        try await synchronizeFabric()
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
            guard activeContainers[container.id] != nil, let shim = shims[container.id],
                  (try? await shim.status().state) == .running else { continue }
            let desired = Set(container.networks.map(\.networkID))
            let existing = appliedNetworks[container.id] ?? []
            struct NetworkRequest: Encodable { let endpoint: GuestProtocol.NetworkEndpoint?; let name: String? }
            struct Status: Decodable { let status: String }
            _ = try await shim.configureNetwork(vlans: desired.compactMap { networkVLANs[$0] } + [VMShimProtocol.managementVLAN])
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

    private func recordCompletion(_ container: ContainerRecord, code: Int32) async -> Int32 {
        completionTasks.removeValue(forKey: container.id)
        if let existing = completions[container.id] { return existing }
        completions[container.id] = code
        activeContainers.removeValue(forKey: container.id)
        try? await synchronizeFabric()
        portForwarder.stop(containerID: container.id)
        logMonitors.removeValue(forKey: container.id)?.stop()
        return code
    }

    private func ensureIO(_ container: ContainerRecord, replacingStoppedSession: Bool = false,
                          preservingExistingFiles: Bool = false) throws -> ContainerIOBridge {
        if let existing = bridges[container.id] {
            if !replacingStoppedSession || logMonitors[container.id] != nil { return existing }
            existing.finishOutput()
            bridges.removeValue(forKey: container.id)
        }
        let directory = root.appending(path: "containers/\(container.id)/io", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        for name in ["stdout", "stderr", "stdin"] {
            let url = directory.appending(path: name)
            if !FileManager.default.fileExists(atPath: url.path) { FileManager.default.createFile(atPath: url.path, contents: nil) }
            if !preservingExistingFiles {
                let handle = try FileHandle(forWritingTo: url); try handle.truncate(atOffset: 0); try handle.close()
            }
        }
        let stdinClosed = directory.appending(path: "stdin.closed")
        if !preservingExistingFiles {
            try? FileManager.default.removeItem(at: stdinClosed)
            if !container.openStdin { FileManager.default.createFile(atPath: stdinClosed.path, contents: nil) }
        }
        let bridge = ContainerIOBridge(tty: container.tty, logURL: directory.appending(path: "docker.log"))
        let monitor = ContainerLogMonitor(directory: directory, bridge: bridge)
        bridges[container.id] = bridge; logMonitors[container.id] = monitor
        monitor.start(atEnd: preservingExistingFiles)
        return bridge
    }

    private func restoreLiveContainer(_ container: ContainerRecord) async throws {
        preparedBindSources[container.id] = try HostBindSourceResolver(
            root: root.appending(path: "bind-sources")
        ).resolve(container.mounts)
        _ = try ensureIO(container, preservingExistingFiles: true)
        var active = container
        if !container.ports.isEmpty {
            guard let shim = shims[container.id] else {
                throw EngineError(.notFound, "container VM shim is unavailable")
            }
            let hasIPv4 = container.networks.contains { $0.ipv4Address != nil }
            guard hasIPv4 || container.networks.contains(where: { $0.ipv6Address != nil }) else {
                throw EngineError(.conflict, "published ports require a container network endpoint")
            }
            active.ports = try await portForwarder.start(
                containerID: container.id,
                bindings: container.ports,
                connect: { binding in
                    try await shim.startPortStream(
                        transport: binding.proto.lowercased(),
                        port: binding.containerPort,
                        ipv6: !hasIPv4
                    )
                }
            )
        }
        knownContainers[container.id] = active
        activeContainers[container.id] = active
    }

    private func pull(_ reference: String, platform: String, credentials: RegistryCredentials?, progress: @escaping ImagePullProgressHandler) async throws -> OCIStoredImage {
        try await store.pull(reference: reference, platform: platform, credentials: credentials, progress: progress)
    }

    private func relaunchPreparedShim(_ container: ContainerRecord) async throws -> VMShimClient? {
        let directory = root.appending(path: "containers/\(container.id)", directoryHint: .isDirectory)
        let specificationURL = directory.appending(path: "shim.json")
        let disk = directory.appending(path: "root.ext4")
        guard FileManager.default.fileExists(atPath: specificationURL.path),
              FileManager.default.fileExists(atPath: disk.path) else { return nil }
        let persisted = try JSONDecoder().decode(
            VMShimProtocol.Specification.self,
            from: Data(contentsOf: specificationURL)
        )
        guard persisted.kind == .container, persisted.containerID == container.id else {
            throw EngineError(.conflict, "persisted VM shim does not belong to container \(container.id)")
        }
        let ioDirectory = directory.appending(path: "io", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: ioDirectory, withIntermediateDirectories: true)
        let bindSources = try HostBindSourceResolver(
            root: root.appending(path: "bind-sources")
        ).resolve(container.mounts)
        let specification = try containerShimSpecification(
            container,
            directory: directory,
            bindSources: bindSources,
            generation: persisted.generation + 1,
            volumeDisks: persisted.volumeDisks
        )
        let shim = try await VMShimClient.launch(specification: specification)
        preparedBindSources[container.id] = bindSources
        shims[container.id] = shim
        return shim
    }

    private func containerShimSpecification(
        _ container: ContainerRecord,
        directory: URL,
        bindSources: [Int: PreparedBindSource],
        generation: UInt64,
        volumeDisks: [VMShimProtocol.VolumeDisk]
    ) throws -> VMShimProtocol.Specification {
        let ioDirectory = directory.appending(path: "io", directoryHint: .isDirectory)
        return VMShimProtocol.Specification(
            containerID: container.id,
            generation: generation,
            token: Self.randomToken(),
            kernelPath: kernel.path,
            initialRamdiskPath: containerInitialRamdisk.path,
            rootDiskPath: directory.appending(path: "root.ext4").path,
            volumeDisks: volumeDisks,
            cpus: max(container.cpus, 1),
            memoryBytes: try VirtualMachineMemory.capacity(forHardLimit: container.memoryBytes),
            macAddress: Self.macAddress(container.id),
            bindShares: container.mounts.enumerated().compactMap { index, mount in
                guard mount.kind == .bind, let source = bindSources[index],
                      case .virtioFS(let share) = source else { return nil }
                return .init(tag: "bind-\(index)", source: share.shareRoot.path, readOnly: mount.readOnly)
            } + [.init(tag: "cengine-io", source: ioDirectory.path, readOnly: false)],
            socketRelays: bindSources.values.compactMap { source in
                guard case .socket(let socket) = source else { return nil }
                return .init(path: socket.path.path, port: socket.port)
            }.sorted { $0.port < $1.port },
            socketPath: try Self.makeRuntimeSocketPath(),
            logPath: directory.appending(path: "shim.log").path,
            kernelArguments: [
                "cengine.management_address=\(Self.managementAddress(for: container.id))",
                "cengine.management_vlan=\(VMShimProtocol.managementVLAN)",
            ],
            networkSocketPath: infrastructure.specification.networkSocketPath,
            vlans: container.networks.compactMap { networkVLANs[$0.networkID] } + [VMShimProtocol.managementVLAN]
        )
    }

    private func workload(_ container: ContainerRecord, image: OCIStoredImage, volumeModes: [String: VolumeStorageMode]) async throws -> GuestProtocol.Workload {
        let config = image.configuration.config
        let arguments = (container.entrypoint ?? config?.entrypoint ?? []) + (container.command ?? config?.command ?? [])
        guard !arguments.isEmpty else { throw EngineError(.badRequest, "container has no command") }
        let environment = Self.mergeEnvironment(image: config?.environment ?? [], container: container.environment)
        let bindSources = preparedBindSources[container.id] ?? [:]
        let blockVolumes = Self.volumeNames(in: container.mounts).filter { volumeModes[$0] != .shared }
        let volumeDevices = try Dictionary(uniqueKeysWithValues: blockVolumes.enumerated().map {
            ($0.element, try Self.volumeDevicePath(index: $0.offset))
        })
        let mounts = container.mounts.enumerated().map { index, mount -> GuestProtocol.Mount in
            if let source = bindSources[index], case .socket(let socket) = source {
                return GuestProtocol.Mount(
                    kind: "socket", source: mount.source, destination: mount.destination,
                    readOnly: mount.readOnly, socketPort: socket.port, socketMode: socket.mode,
                    socketUID: socket.uid, socketGID: socket.gid
                )
            }
            let bindSubpath: String? = {
                guard mount.kind == .bind else { return mount.subpath }
                guard let source = bindSources[index], case .virtioFS(let share) = source else { return mount.subpath }
                return [share.subpath, mount.subpath].compactMap { $0 }.joined(separator: "/").nilIfEmpty
            }()
            let options = mount.kind == .tmpfs ? ["size=\(max(mount.tmpfsSizeBytes ?? 64 * 1_024 * 1_024, 0))", String(format: "mode=%o", mount.tmpfsMode ?? 0o1777)] : []
            return GuestProtocol.Mount(
                kind: mount.kind.rawValue,
                source: mount.kind == .bind ? "bind-\(index)" : mount.source,
                device: mount.kind == .volume ? volumeDevices[mount.source] : nil,
                destination: mount.destination,
                readOnly: mount.readOnly,
                options: options,
                subpath: bindSubpath,
                noCopy: mount.noCopy,
                propagation: mount.propagation?.rawValue ?? ""
            )
        }
        return GuestProtocol.Workload(
            id: container.id, rootDevice: "/dev/vda", arguments: arguments,
            environment: environment,
            workingDirectory: container.workingDirectory.isEmpty ? (config?.workingDirectory ?? "/") : container.workingDirectory,
            hostname: container.hostname, user: Self.user(container.user.isEmpty ? config?.user : container.user),
            terminal: container.tty, readOnlyRoot: container.readOnlyRootfs, stopSignal: container.stopSignal,
            volumeServer: volumeModes.values.contains(.shared) ? Self.managementServerAddress : nil,
            mounts: mounts, networks: networkEndpoints(container), hosts: networkHosts(container), resources: .init(memoryBytes: container.memoryBytes, cpuQuota: Int64(container.cpus * 100_000), cpuPeriod: 100_000, pids: container.pidsLimit), privileged: container.privileged,
            capabilityAdd: container.capabilityAdd, capabilityDrop: container.capabilityDrop
        )
    }

    private func ensureVolumeDisks(names: [String]) throws -> [VMShimProtocol.VolumeDisk] {
        try names.map { name in
            guard !name.isEmpty, !name.contains("/") else {
                throw EngineError(.badRequest, "invalid volume name")
            }
            let disk = volumeDiskURL(name: name)
            try Self.createSparseFile(at: disk, size: Self.defaultVolumeDiskBytes)
            return .init(name: name, path: disk.path)
        }
    }

    private func resolveVolumeStorageModes(for container: ContainerRecord) throws -> [String: VolumeStorageMode] {
        let names = Self.volumeNames(in: container.mounts)
        var referenceCounts: [String: Int] = [:]
        for known in knownContainers.values {
            for name in Self.volumeNames(in: known.mounts) {
                referenceCounts[name, default: 0] += 1
            }
        }
        if knownContainers[container.id] == nil {
            for name in names { referenceCounts[name, default: 0] += 1 }
        }
        let resolved = try Self.resolveVolumeStorageModes(
            names: names,
            referenceCounts: referenceCounts,
            existing: volumeStorageModes
        )
        if resolved != volumeStorageModes {
            volumeStorageModes = resolved
            try persistVolumeStorageModes()
        }
        return resolved
    }

    static func resolveVolumeStorageModes(
        names: [String],
        referenceCounts: [String: Int],
        existing: [String: VolumeStorageMode]
    ) throws -> [String: VolumeStorageMode] {
        var resolved = existing
        for name in names {
            if resolved[name] == .block, referenceCounts[name, default: 1] > 1 {
                throw EngineError(.conflict, "volume \(name) is block-backed and cannot be attached to multiple container VMs")
            }
            if resolved[name] == nil {
                resolved[name] = referenceCounts[name, default: 1] > 1 ? .shared : .block
            }
        }
        return resolved
    }

    private func reconfigureVolumeDisks(
        _ shim: VMShimClient,
        container: ContainerRecord,
        modes: [String: VolumeStorageMode]
    ) async throws -> VMShimClient {
        let desiredNames = Self.volumeNames(in: container.mounts).filter { modes[$0] != .shared }
        if shim.specification.volumeDisks.map(\.name) == desiredNames { return shim }
        let status = try await shim.status()
        guard status.state != .running && status.state != .paused else {
            throw EngineError(.conflict, "cannot change volume storage while the container VM is running")
        }
        _ = try await shim.shutdown()
        var specification = shim.specification
        specification.generation += 1
        specification.token = Self.randomToken()
        specification.socketPath = try Self.makeRuntimeSocketPath()
        specification.volumeDisks = try ensureVolumeDisks(names: desiredNames)
        let replacement = try await VMShimClient.launch(specification: specification)
        shims[container.id] = replacement
        return replacement
    }

    private func volumeDiskURL(name: String) -> URL {
        let digest = SHA256.hash(data: Data(name.utf8)).map { String(format: "%02x", $0) }.joined()
        return root.appending(path: "volumes/\(digest).ext4")
    }

    private func persistVolumeStorageModes() throws {
        let data = try JSONEncoder().encode(volumeStorageModes)
        try data.write(to: root.appending(path: "volume-storage.json"), options: .atomic)
    }

    static func volumeNames(in mounts: [MountRecord]) -> [String] {
        var seen = Set<String>()
        return mounts.compactMap { mount in
            guard mount.kind == .volume, seen.insert(mount.source).inserted else { return nil }
            return mount.source
        }
    }

    static func volumeDevicePath(index: Int) throws -> String {
        guard (0..<25).contains(index), let suffix = UnicodeScalar(98 + index) else {
            throw EngineError(.badRequest, "a container may mount at most 25 volumes")
        }
        return "/dev/vd\(Character(suffix))"
    }

    private func networkEndpoints(_ container: ContainerRecord) -> [GuestProtocol.NetworkEndpoint] {
        // Docker gives a multi-homed container a single default gateway, chosen by
        // endpoint gateway priority (ties broken lexicographically by network
        // name). Selecting across every endpoint means a single-network container
        // always keeps its only network's gateway.
        let defaultGatewayNetworkID = EndpointGatewayPriority.defaultGatewayNetworkID(
            among: container.networks.compactMap { endpoint in
                guard let network = networks[endpoint.networkID] else { return nil }
                return .init(
                    networkID: endpoint.networkID,
                    priority: endpoint.gatewayPriority ?? 0,
                    networkName: network.name
                )
            }
        )
        return container.networks.enumerated().compactMap { index, endpoint in
            guard let network = networks[endpoint.networkID], let vlan = networkVLANs[endpoint.networkID] else { return nil }
            var addresses: [String] = []
            if let address = endpoint.ipv4Address, !address.isEmpty { addresses.append(Self.withPrefix(address, from: network.subnet)) }
            if let address = endpoint.ipv6Address, !address.isEmpty { addresses.append(Self.withPrefix(address, from: network.ipv6Subnet)) }
            var gateways: [String] = []
            // Only the winning endpoint installs default routes; the others keep
            // their addresses and DNS but do not compete for the default gateway.
            if endpoint.networkID == defaultGatewayNetworkID {
                if endpoint.ipv4Address != nil, !network.gateway.isEmpty { gateways.append(network.gateway) }
                if endpoint.ipv6Address != nil, !network.ipv6Gateway.isEmpty { gateways.append(network.ipv6Gateway) }
            }
            return .init(
                networkID: endpoint.networkID,
                vlan: vlan,
                name: "eth\(index)",
                macAddress: endpoint.macAddress ?? Self.endpointMacAddress(container: container.id, network: endpoint.networkID),
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
        precondition((1..<VMShimProtocol.managementVLAN).contains(vlan), "VLAN must be in the allocatable range")
        let slot = Int(vlan)
        let secondOctet = 240 + (slot / 256)
        let thirdOctet = slot % 256
        let prefix = "10.\(secondOctet).\(thirdOctet)"
        return ("\(prefix).0/24", "\(prefix).1")
    }

    private func allocateVLAN() throws -> UInt16 {
        let used = Set(networkVLANs.values)
        guard let vlan = Self.nextAvailableVLAN(used: used) else { throw EngineError(.conflict, "all VLAN identifiers are allocated") }
        return vlan
    }

    static func nextAvailableVLAN(used: Set<UInt16>) -> UInt16? {
        (1..<VMShimProtocol.managementVLAN).first(where: { !used.contains($0) })
    }

    static func managementAddress(for containerID: String) -> String {
        let digest = Array(SHA256.hash(data: Data(containerID.utf8)))
        let second = 64 | Int(digest[0] & 0x3f)
        let third = Int(digest[1])
        var fourth = Int(digest[2])
        if second == 64, third == 0, fourth < 2 { fourth = 2 }
        return "100.\(second).\(third).\(fourth)/10"
    }

    private func persistNetworks() throws {
        let state = Dictionary(uniqueKeysWithValues: networks.compactMap { id, record in networkVLANs[id].map { (id, NetworkState(record: record, vlan: $0)) } })
        try JSONEncoder().encode(state).write(to: root.appending(path: "networks.json"), options: .atomic)
    }

    private func synchronizeFabric() async throws {
        let values = networks.compactMap { id, network -> VMShimClient.FabricNetwork? in
            guard let vlan = networkVLANs[id], !network.subnet.isEmpty else { return nil }
            return .init(id: id, vlan: vlan, subnet: network.subnet, gateway: network.gateway, ipv6Subnet: network.ipv6Subnet, internalNetwork: network.internalNetwork, isolated: network.ipv4GatewayMode == .isolated, ports: [])
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

    static func resolveExecContext(
        configuration: ExecConfiguration,
        containerEnvironment: [String],
        containerWorkingDirectory: String,
        containerUser: String,
        containerPrivileged: Bool,
        imageEnvironment: [String],
        imageWorkingDirectory: String?,
        imageUser: String?
    ) -> ResolvedExecContext {
        let inheritedEnvironment = mergeEnvironment(
            image: imageEnvironment, container: containerEnvironment
        )
        return ResolvedExecContext(
            environment: mergeEnvironment(
                image: inheritedEnvironment, container: configuration.environment
            ),
            workingDirectory: configuration.workingDirectory.nilIfEmpty
                ?? containerWorkingDirectory.nilIfEmpty
                ?? imageWorkingDirectory?.nilIfEmpty
                ?? "/",
            user: user(
                configuration.user.nilIfEmpty
                    ?? containerUser.nilIfEmpty
                    ?? imageUser?.nilIfEmpty
            ),
            noNewPrivileges: !(containerPrivileged || configuration.privileged),
            privileged: containerPrivileged || configuration.privileged
        )
    }

    private static func user(_ value: String?) -> GuestProtocol.User {
        let raw = value ?? ""; if raw.isEmpty { return .init() }
        let parts = raw.split(separator: ":", omittingEmptySubsequences: false)
        guard let uid = UInt32(parts[0]) else { return .init(username: raw) }
        guard parts.count > 1, !parts[1].isEmpty else { return .init(uid: uid, gid: uid) }
        guard let gid = UInt32(parts[1]) else {
            return .init(uid: uid, gid: uid, username: raw)
        }
        return .init(uid: uid, gid: gid)
    }

    private static func signalNumber(_ value: String) -> Int {
        let normalized = value.uppercased().replacingOccurrences(of: "SIG", with: "")
        if let number = Int(normalized) { return number }
        return ["HUP": 1, "INT": 2, "QUIT": 3, "KILL": 9, "USR1": 10, "USR2": 12, "PIPE": 13, "ALRM": 14, "TERM": 15, "CHLD": 17, "CONT": 18, "STOP": 19, "TSTP": 20][normalized] ?? 15
    }

    private static func macAddress(_ id: String) -> String {
        EndpointMacAddress.generated(seed: id)
    }

    /// Deterministic MAC for a container's endpoint on a given network, shared
    /// with the Docker inspect surface so reported and applied MACs never diverge.
    static func endpointMacAddress(container: String, network: String) -> String {
        EndpointMacAddress.generated(seed: container + network)
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

    private struct NetworkState: Codable { let record: NetworkRecord; let vlan: UInt16 }
}

struct PreparedVirtioFSBind: Sendable, Equatable {
    let shareRoot: URL
    let subpath: String?
}

struct PreparedSocketBind: Sendable, Equatable {
    let path: URL
    let port: UInt32
    let mode: UInt32
    let uid: UInt32
    let gid: UInt32
}

enum PreparedBindSource: Sendable, Equatable {
    case virtioFS(PreparedVirtioFSBind)
    case socket(PreparedSocketBind)
}

struct HostBindSourceResolver: Sendable {
    let root: URL

    func resolve(_ mounts: [MountRecord]) throws -> [Int: PreparedBindSource] {
        var resolved: [Int: PreparedBindSource] = [:]
        for (index, mount) in mounts.enumerated() where mount.kind == .bind {
            let requested = URL(filePath: mount.source)
            if FileManager.default.fileExists(atPath: requested.path) {
                let canonical = requested.resolvingSymlinksInPath()
                var metadata = stat()
                if lstat(canonical.path, &metadata) == 0,
                   metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFSOCK) {
                    guard let offset = UInt32(exactly: index) else {
                        throw EngineError(.badRequest, "too many container mounts")
                    }
                    let (port, overflow) = GuestProtocol.socketProxyPortBase.addingReportingOverflow(offset)
                    guard !overflow else { throw EngineError(.badRequest, "too many container mounts") }
                    resolved[index] = .socket(.init(
                        path: canonical, port: port,
                        mode: UInt32(metadata.st_mode & mode_t(0o7777)),
                        uid: UInt32(metadata.st_uid), gid: UInt32(metadata.st_gid)
                    ))
                    continue
                }
                let isDirectory = (try? requested.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true
                resolved[index] = .virtioFS(.init(
                    shareRoot: isDirectory ? requested : requested.deletingLastPathComponent(),
                    subpath: isDirectory ? nil : requested.lastPathComponent
                ))
                continue
            }
            guard mount.createSourceIfMissing != false else {
                throw EngineError(.notFound, "bind source \(mount.source) does not exist")
            }
            do {
                try FileManager.default.createDirectory(at: requested, withIntermediateDirectories: true)
                resolved[index] = .virtioFS(.init(shareRoot: requested, subpath: nil))
            } catch {
                guard Self.isHostNamespaceWriteRestriction(error) else { throw error }
                let digest = SHA256.hash(data: Data(requested.path.utf8)).map { String(format: "%02x", $0) }.joined()
                let managed = root.appending(path: digest, directoryHint: .isDirectory)
                try FileManager.default.createDirectory(at: managed, withIntermediateDirectories: true)
                resolved[index] = .virtioFS(.init(shareRoot: managed, subpath: nil))
            }
        }
        return resolved
    }

    private static func isHostNamespaceWriteRestriction(_ error: Error) -> Bool {
        let value = error as NSError
        if value.domain == NSCocoaErrorDomain,
           value.code == CocoaError.fileWriteNoPermission.rawValue || value.code == CocoaError.fileWriteVolumeReadOnly.rawValue {
            return true
        }
        if value.domain == NSPOSIXErrorDomain,
           value.code == EACCES || value.code == EPERM || value.code == EROFS {
            return true
        }
        if let underlying = value.userInfo[NSUnderlyingErrorKey] as? Error {
            return isHostNamespaceWriteRestriction(underlying)
        }
        return false
    }
}

private extension String { var nilIfEmpty: String? { isEmpty ? nil : self } }
#endif

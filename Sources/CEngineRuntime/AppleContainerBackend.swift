#if os(macOS)
import CEngineCore
import Containerization
import ContainerizationOCI
import ContainerizationOS
import Foundation

/// Executes Linux containers with Apple's Virtualization.framework-backed runtime.
/// The actor owns ContainerManager because its image/network bookkeeping is mutable.
public actor AppleContainerBackend: ContainerBackend {
    public static let defaultVminitReference = "ghcr.io/apple/containerization/vminit:0.37.0"

    private var manager: ContainerManager
    private var containers: [String: LinuxContainer] = [:]
    private var ioBridges: [String: ContainerIOBridge] = [:]
    private var waitTasks: [String: Task<Int32, Never>] = [:]
    private let volumeRoot: URL
    private let logRoot: URL

    public init(
        root: URL,
        kernel: URL,
        vminitReference: String = defaultVminitReference,
        rosetta: Bool = true
    ) async throws {
        let runtimeRoot = root.appending(path: "runtime", directoryHint: .isDirectory)
        self.volumeRoot = root.appending(path: "volumes", directoryHint: .isDirectory)
        self.logRoot = root.appending(path: "container-logs", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: runtimeRoot, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: volumeRoot, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: logRoot, withIntermediateDirectories: true)
        self.manager = try await ContainerManager(
            kernel: Kernel(path: kernel, platform: .linuxArm),
            initfsReference: vminitReference,
            root: runtimeRoot,
            network: try VmnetNetwork(),
            rosetta: rosetta
        )
    }

    public func pullImage(_ reference: String, platform: String) async throws {
        guard platform == "linux/arm64" || platform == "linux/amd64" else {
            throw EngineError(.unsupported, "unsupported platform \(platform)")
        }
        _ = try await manager.imageStore.get(reference: reference, pull: true)
    }

    public func prepare(_ record: ContainerRecord) async throws {
        guard record.platform == "linux/arm64" || record.platform == "linux/amd64" else {
            throw EngineError(.unsupported, "unsupported platform \(record.platform); expected linux/arm64 or linux/amd64")
        }

        let volumeRoot = self.volumeRoot
        let io = ContainerIOBridge(tty: record.tty, logURL: logRoot.appending(path: "\(record.id).log"))
        var manager = self.manager
        let container = try await manager.create(
            record.id,
            reference: record.image,
            rootfsSizeInBytes: max(record.memoryBytes * 4, 8 * 1_024 * 1_024 * 1_024),
            readOnly: record.readOnlyRootfs,
            networking: true
        ) { config in
            config.cpus = max(record.cpus, 1)
            config.memoryInBytes = max(record.memoryBytes, 256 * 1_024 * 1_024)
            config.hostname = record.hostname
            config.useInit = record.useInit
            if !record.processArguments.isEmpty { config.process.arguments = record.processArguments }
            if !record.environment.isEmpty { config.process.environmentVariables.append(contentsOf: record.environment) }
            if !config.process.environmentVariables.contains(where: { $0.hasPrefix("PATH=") }) {
                config.process.environmentVariables.append("PATH=\(LinuxProcessConfiguration.defaultPath)")
            }
            if !record.workingDirectory.isEmpty { config.process.workingDirectory = record.workingDirectory }
            config.process.terminal = record.tty
            if record.openStdin { config.process.stdin = io }
            config.process.stdout = io.writer(.stdout)
            if !record.tty { config.process.stderr = io.writer(.stderr) }
            if !record.user.isEmpty { config.process.user = Self.parseUser(record.user) }
            if record.privileged {
                config.process.capabilities = .allCapabilities
            }

            for mount in record.mounts {
                let source: String
                switch mount.kind {
                case .bind:
                    source = URL(filePath: mount.source).standardizedFileURL.path
                case .volume:
                    let directory = volumeRoot.appending(path: mount.source, directoryHint: .isDirectory)
                    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                    source = directory.path
                case .tmpfs:
                    // Containerization's default OCI mounts already provide /tmp and /run.
                    // Additional tmpfs destinations need guest-side mount orchestration.
                    throw EngineError(.unsupported, "tmpfs mount \(mount.destination) is not supported yet")
                }
                config.mounts.append(.share(
                    source: source,
                    destination: mount.destination,
                    options: mount.readOnly ? ["ro"] : []
                ))
            }
        }
        self.manager = manager
        containers[record.id] = container
        ioBridges[record.id] = io
    }

    public func start(_ record: ContainerRecord) async throws {
        guard let container = containers[record.id] else {
            throw EngineError(.notFound, "runtime state for container \(record.id) is unavailable; recreate the container")
        }
        try await container.create()
        try await container.start()
        let io = ioBridges[record.id]
        waitTasks[record.id] = Task {
            do {
                let status = try await container.wait()
                io?.finishOutput()
                try? await container.stop()
                return status.exitCode
            } catch {
                io?.finishOutput()
                return 127
            }
        }
    }

    public func wait(_ record: ContainerRecord) async throws -> Int32 {
        guard containers[record.id] != nil else { return record.exitCode ?? 137 }
        guard let task = waitTasks[record.id] else {
            throw EngineError(.conflict, "container has not been started")
        }
        return await task.value
    }

    public func stop(_ record: ContainerRecord, timeoutSeconds: Int) async throws -> Int32 {
        guard let container = containers[record.id] else { return record.exitCode ?? 137 }
        let signal = try Signal(record.stopSignal)
        try await container.kill(timeoutSeconds == 0 ? .kill : signal)

        let status: ExitStatus
        do {
            status = try await container.wait(timeoutInSeconds: Int64(max(timeoutSeconds, 1)))
        } catch {
            try await container.kill(.kill)
            status = try await container.wait(timeoutInSeconds: 5)
        }
        try await container.stop()
        return status.exitCode
    }

    public func delete(_ record: ContainerRecord) async throws {
        if let container = containers.removeValue(forKey: record.id) {
            try? await container.stop()
        }
        waitTasks.removeValue(forKey: record.id)?.cancel()
        ioBridges.removeValue(forKey: record.id)?.finishOutput()
        try? FileManager.default.removeItem(at: logRoot.appending(path: "\(record.id).log"))
        try manager.delete(record.id)
    }

    public func io(for record: ContainerRecord) async throws -> ContainerIOBridge {
        guard let io = ioBridges[record.id] else { throw EngineError(.notFound, "container I/O is unavailable") }
        return io
    }

    public func resize(_ record: ContainerRecord, width: UInt16, height: UInt16) async throws {
        guard let container = containers[record.id] else { throw EngineError(.notFound, "container runtime is unavailable") }
        try await container.resize(to: Terminal.Size(width: width, height: height))
    }

    public func completion(_ record: ContainerRecord) async -> Int32? {
        guard let task = waitTasks[record.id] else { return nil }
        return await task.value
    }

    public func logs(for record: ContainerRecord) async throws -> Data {
        guard let io = ioBridges[record.id] else {
            let url = logRoot.appending(path: "\(record.id).log")
            guard FileManager.default.fileExists(atPath: url.path) else { return Data() }
            return try Data(contentsOf: url)
        }
        return try io.logData()
    }

    private static func parseUser(_ value: String) -> ContainerizationOCI.User {
        guard !value.isEmpty else { return ContainerizationOCI.User() }
        let components = value.split(separator: ":", maxSplits: 1).map(String.init)
        if let uid = UInt32(components[0]) {
            return ContainerizationOCI.User(uid: uid, gid: components.count == 2 ? UInt32(components[1]) ?? uid : uid)
        }
        return ContainerizationOCI.User(username: value)
    }
}
#endif

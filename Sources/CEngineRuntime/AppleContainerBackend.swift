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
    private var execProcesses: [String: LinuxProcess] = [:]
    private var execBridges: [String: ContainerIOBridge] = [:]
    private var execWaitTasks: [String: Task<Int32, Never>] = [:]
    private var execExitCodes: [String: Int32] = [:]
    private var preparedRecords: [String: ContainerRecord] = [:]
    private struct StagedCopy: Sendable { let source: URL; let destination: String }
    private var stagedCopies: [String: [StagedCopy]] = [:]
    private let volumeRoot: URL
    private let logRoot: URL
    private let stagingRoot: URL

    public init(
        root: URL,
        kernel: URL,
        vminitReference: String = defaultVminitReference,
        rosetta: Bool = true
    ) async throws {
        let runtimeRoot = root.appending(path: "runtime", directoryHint: .isDirectory)
        self.volumeRoot = root.appending(path: "volumes", directoryHint: .isDirectory)
        self.logRoot = root.appending(path: "container-logs", directoryHint: .isDirectory)
        self.stagingRoot = root.appending(path: "staged-copies", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: runtimeRoot, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: volumeRoot, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: logRoot, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: stagingRoot, withIntermediateDirectories: true)
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

        let io = ContainerIOBridge(tty: record.tty, logURL: logRoot.appending(path: "\(record.id).log"))
        _ = try await manager.imageStore.get(reference: record.image, pull: true)
        preparedRecords[record.id] = record
        ioBridges[record.id] = io
    }

    private func createPreparedContainer(_ record: ContainerRecord) async throws -> LinuxContainer {
        guard let io = ioBridges[record.id] else { throw EngineError(.notFound, "container I/O is unavailable") }
        let volumeRoot = self.volumeRoot
        let staged = stagedCopies[record.id] ?? []
        var manager = self.manager
        let image = try await manager.imageStore.get(reference: record.image, pull: true)
        let imageConfig = try await image.config(for: .current).config
        let resolvedArguments = (record.entrypoint ?? imageConfig?.entrypoint ?? []) + (record.command ?? imageConfig?.cmd ?? [])
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
            config.process.arguments = resolvedArguments
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
                    config.mounts.append(.any(
                        type: "tmpfs", source: "tmpfs", destination: mount.destination,
                        options: (["nosuid", "nodev"] + (mount.readOnly ? ["ro"] : []))
                    ))
                    continue
                }
                config.mounts.append(.share(
                    source: source,
                    destination: mount.destination,
                    options: mount.readOnly ? ["ro"] : []
                ))
            }
            for copy in staged {
                let entries = try FileManager.default.contentsOfDirectory(
                    at: copy.source, includingPropertiesForKeys: nil, options: []
                )
                for entry in entries {
                    let destination = URL(filePath: copy.destination, directoryHint: .isDirectory)
                        .appending(path: entry.lastPathComponent).path
                    config.mounts.append(.share(source: entry.path, destination: destination))
                }
            }
        }
        self.manager = manager
        return container
    }

    public func start(_ record: ContainerRecord) async throws {
        guard preparedRecords[record.id] != nil else { throw EngineError(.notFound, "container was not prepared") }
        let container = try await createPreparedContainer(record)
        containers[record.id] = container
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
        preparedRecords.removeValue(forKey: record.id)
        stagedCopies.removeValue(forKey: record.id)
        try? FileManager.default.removeItem(at: stagingRoot.appending(path: record.id))
        try? FileManager.default.removeItem(at: logRoot.appending(path: "\(record.id).log"))
        try? manager.delete(record.id)
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

    public func kill(_ record: ContainerRecord, signal: String) async throws {
        guard let container = containers[record.id] else { throw EngineError(.notFound, "container runtime is unavailable") }
        try await container.kill(try Signal(signal))
    }

    public func prepareExec(_ exec: ExecRecord, container record: ContainerRecord) async throws -> ContainerIOBridge {
        guard let container = containers[record.id] else { throw EngineError(.notFound, "container runtime is unavailable") }
        let io = ContainerIOBridge(tty: exec.configuration.tty)
        let process = try await container.exec(exec.id) { config in
            config.arguments = exec.configuration.arguments
            config.environmentVariables = record.environment + exec.configuration.environment
            if !config.environmentVariables.contains(where: { $0.hasPrefix("PATH=") }) {
                config.environmentVariables.append("PATH=\(LinuxProcessConfiguration.defaultPath)")
            }
            config.workingDirectory = exec.configuration.workingDirectory.isEmpty
                ? (record.workingDirectory.isEmpty ? "/" : record.workingDirectory)
                : exec.configuration.workingDirectory
            let user = exec.configuration.user.isEmpty ? record.user : exec.configuration.user
            if !user.isEmpty { config.user = Self.parseUser(user) }
            config.terminal = exec.configuration.tty
            if exec.configuration.attachStdin { config.stdin = io }
            if exec.configuration.attachStdout { config.stdout = io.writer(.stdout) }
            if exec.configuration.attachStderr && !exec.configuration.tty { config.stderr = io.writer(.stderr) }
            if exec.configuration.privileged { config.capabilities = .allCapabilities }
        }
        execProcesses[exec.id] = process
        execBridges[exec.id] = io
        return io
    }

    public func startExec(_ exec: ExecRecord) async throws {
        guard let process = execProcesses[exec.id], let io = execBridges[exec.id] else {
            throw EngineError(.notFound, "No such exec instance: \(exec.id)")
        }
        try await process.start()
        execWaitTasks[exec.id] = Task { [weak self] in
            do {
                let status = try await process.wait()
                await self?.recordExecExit(exec.id, code: status.exitCode, io: io, process: process)
                return status.exitCode
            } catch {
                await self?.recordExecExit(exec.id, code: 127, io: io, process: process)
                return 127
            }
        }
    }

    public func execCompletion(_ exec: ExecRecord) async -> Int32? {
        guard let task = execWaitTasks[exec.id] else { return nil }
        return await task.value
    }

    public func execIO(_ exec: ExecRecord) async throws -> ContainerIOBridge {
        guard let io = execBridges[exec.id] else { throw EngineError(.notFound, "No such exec instance: \(exec.id)") }
        return io
    }

    public func execPID(_ exec: ExecRecord) async -> Int32 { execProcesses[exec.id]?.pid ?? 0 }
    public func execStatus(_ exec: ExecRecord) async -> Int32? { execExitCodes[exec.id] }

    public func resizeExec(_ exec: ExecRecord, width: UInt16, height: UInt16) async throws {
        guard let process = execProcesses[exec.id] else { throw EngineError(.notFound, "No such exec instance: \(exec.id)") }
        try await process.resize(to: Terminal.Size(width: width, height: height))
    }

    private func recordExecExit(_ id: String, code: Int32, io: ContainerIOBridge, process: LinuxProcess) async {
        execExitCodes[id] = code
        io.finishOutput()
        try? await process.delete()
    }

    public func copyIn(_ record: ContainerRecord, extractedDirectory: URL, destination: String) async throws {
        if containers[record.id] == nil {
            guard preparedRecords[record.id] != nil else { throw EngineError(.notFound, "container runtime is unavailable") }
            let directory = stagingRoot.appending(path: record.id).appending(path: UUID().uuidString, directoryHint: .isDirectory)
            try FileManager.default.createDirectory(at: directory.deletingLastPathComponent(), withIntermediateDirectories: true)
            try FileManager.default.copyItem(at: extractedDirectory, to: directory)
            stagedCopies[record.id, default: []].append(.init(source: directory, destination: destination))
            return
        }
        guard let container = containers[record.id] else { throw EngineError(.notFound, "container runtime is unavailable") }
        let entries = try FileManager.default.contentsOfDirectory(
            at: extractedDirectory, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]
        )
        for entry in entries {
            try await container.copyIn(from: entry, to: URL(filePath: destination, directoryHint: .isDirectory))
        }
    }

    public func copyOut(_ record: ContainerRecord, source: String, destinationDirectory: URL) async throws {
        guard let container = containers[record.id] else { throw EngineError(.notFound, "container runtime is unavailable") }
        try FileManager.default.createDirectory(at: destinationDirectory, withIntermediateDirectories: true)
        let destination = destinationDirectory.appending(path: URL(filePath: source).lastPathComponent)
        try await container.copyOut(from: URL(filePath: source), to: destination)
    }

    public func loadImages(fromOCILayout directory: URL) async throws -> [BackendImage] {
        let images = try await manager.imageStore.load(from: directory)
        return try await images.asyncMap { image in
            let config = try await image.config(for: .current)
            return BackendImage(
                id: image.digest, reference: image.reference, size: image.descriptor.size,
                architecture: config.architecture, os: config.os
            )
        }
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

private extension Sequence {
    func asyncMap<T>(_ transform: (Element) async throws -> T) async rethrows -> [T] {
        var result: [T] = []
        for element in self { result.append(try await transform(element)) }
        return result
    }
}
#endif

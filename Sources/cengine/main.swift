import CEngineAPI
import CEngineCore
import CEngineRuntime
import Darwin
import Dispatch
import Foundation
import NIOPosix
import OSLog

private final class DaemonLock {
    private let descriptor: Int32

    init(url: URL) throws {
        descriptor = open(url.path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
        guard descriptor >= 0 else { throw EngineError(.internalError, "could not open daemon lock at \(url.path)") }
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            close(descriptor)
            throw EngineError(.conflict, "another cengine daemon is already running")
        }
    }

    deinit {
        flock(descriptor, LOCK_UN)
        close(descriptor)
    }
}

@main enum CEngineMain {
    static let logger = Logger(subsystem: "dev.cengine.engine", category: "main")
    private static let retryDelays: [Duration] = [.seconds(30), .seconds(120)]

    static func main() async {
        do {
            var arguments = Array(CommandLine.arguments.dropFirst())
            let command = arguments.first ?? "help"
            if !arguments.isEmpty { arguments.removeFirst() }
            switch command {
            case "daemon": try await daemon(arguments, managed: false)
            case "service": try await service(arguments)
            case "builder": try await builder(arguments)
            case "container": try container(arguments)
            case "run": try await run(arguments)
            case "vm-shim": try await vmShim(arguments)
            case "network-helper": try await networkHelper(arguments)
            case "version", "--version": print("cengine \(CEngineVersion.shortVersion())")
            case "system": try await system(arguments)
            case "help", "--help", "-h": usage()
            default: throw EngineError(.badRequest, "unknown command: \(command)")
            }
        } catch {
            FileHandle.standardError.write(Data("cengine: \(error.localizedDescription)\n".utf8))
            Foundation.exit(1)
        }
    }

    private static func daemon(_ arguments: [String], managed: Bool) async throws {
        let paths = EnginePaths()
        try paths.createDirectories()
        let socket = option("--socket", in: arguments) ?? paths.socket.path
        let lockURL = URL(filePath: socket + ".lock")
        let daemonLock = try DaemonLock(url: lockURL)
        _ = daemonLock
        let requestedRoot = option("--root", in: arguments).map {
            URL(filePath: $0, directoryHint: .isDirectory)
        } ?? paths.data
        try FileManager.default.createDirectory(
            at: requestedRoot, withIntermediateDirectories: true
        )
        let root = requestedRoot.resolvingSymlinksInPath().standardizedFileURL
        let backend: any ContainerBackend
        if arguments.contains("--metadata-only") {
            backend = MetadataOnlyBackend()
        } else {
            let kernel = option("--kernel", in: arguments).map { URL(filePath: $0) } ?? paths.kernel
            let containerInitialRamdisk = option("--container-initramfs", in: arguments).map { URL(filePath: $0) } ?? paths.containerInitialRamdisk
            let storageInitialRamdisk = option("--storage-initramfs", in: arguments).map { URL(filePath: $0) } ?? paths.storageInitialRamdisk
            guard FileManager.default.fileExists(atPath: kernel.path) else {
                throw EngineError(.notFound, "Linux kernel not found at \(kernel.path); run `cengine system install`")
            }
            guard FileManager.default.fileExists(atPath: containerInitialRamdisk.path),
                  FileManager.default.fileExists(atPath: storageInitialRamdisk.path) else {
                throw EngineError(.notFound, "cengine guest initramfs assets are not installed; run `cengine system install`")
            }
            let automaticNetworkPool = try AutomaticNetworkPool(
                ipv4CIDR: option("--automatic-ipv4-pool", in: arguments)
                    ?? AutomaticNetworkPool.default.ipv4CIDR,
                ipv6Prefix: option("--automatic-ipv6-prefix", in: arguments)
                    ?? AutomaticNetworkPool.default.ipv6Prefix
            )
            backend = try await RawVirtualizationBackend(
                root: root,
                kernel: kernel,
                containerInitialRamdisk: containerInitialRamdisk,
                storageInitialRamdisk: storageInitialRamdisk,
                automaticNetworkPool: automaticNetworkPool
            )
        }
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let resourceScopes = ContainerResourceScopeManager(runtime: runtime, root: root)
        let server = DockerServer(
            socketPath: socket,
            router: DockerRouter(runtime: runtime, root: root, resourceScopeManager: resourceScopes)
        )
        do {
            try await server.start()
        } catch {
            try? await server.shutdown()
            try? await resourceScopes.shutdown()
            throw error
        }
        if managed {
            try SystemManager.writeState(.running, message: nil, paths: paths)
            SystemManager.configureBuildx()
        }
        logger.info("listening on \(socket, privacy: .public)")

        signal(SIGTERM, SIG_IGN)
        signal(SIGINT, SIG_IGN)
        let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())
        let interrupt = DispatchSource.makeSignalSource(signal: SIGINT, queue: .global())
        let shutdown: @Sendable () -> Void = { Task { try? await server.stop() } }
        term.setEventHandler(handler: shutdown)
        interrupt.setEventHandler(handler: shutdown)
        term.resume()
        interrupt.resume()
        defer { term.cancel(); interrupt.cancel() }

        do {
            try await server.wait()
            try await server.shutdown()
            try await resourceScopes.shutdown()
            await runtime.shutdown()
        } catch {
            try? await server.shutdown()
            try? await resourceScopes.shutdown()
            await runtime.shutdown()
            throw error
        }
        if managed { try? SystemManager.writeState(.stopped, message: nil, paths: paths) }
    }

    private static func vmShim(_ arguments: [String]) async throws -> Never {
        guard let path = option("--spec", in: arguments) else { throw EngineError(.badRequest, "vm-shim requires --spec") }
        let launchIntentURL = option("--launch-intent", in: arguments).map { URL(filePath: $0) }
        return try await VMShimServer.run(
            specificationURL: URL(filePath: path),
            launchIntentURL: launchIntentURL
        )
    }

    private static func service(_ arguments: [String]) async throws {
        guard arguments.first ?? "run" == "run" else {
            throw EngineError(.badRequest, "service command is not implemented")
        }
        guard geteuid() != 0 else {
            try? SystemManager.writeState(.failed, message: "cengine services must run as a user, not root", paths: EnginePaths())
            return
        }
        let paths = EnginePaths()
        let finishDaemonLog: (@Sendable () -> Void)?
        do {
            finishDaemonLog = try DaemonLog.redirectStandardStreams(to: paths.logs.appending(path: "daemon.log"))
        } catch {
            finishDaemonLog = nil
            FileHandle.standardError.write(Data("cengine: could not open daemon log: \(error.localizedDescription)\n".utf8))
        }
        defer { finishDaemonLog?() }
        signal(SIGTERM, SIG_IGN)
        signal(SIGINT, SIG_IGN)
        let runner = Task { try await runManagedService(paths: paths) }
        let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())
        let interrupt = DispatchSource.makeSignalSource(signal: SIGINT, queue: .global())
        let cancel: @Sendable () -> Void = { runner.cancel() }
        term.setEventHandler(handler: cancel)
        interrupt.setEventHandler(handler: cancel)
        term.resume()
        interrupt.resume()
        defer { term.cancel(); interrupt.cancel() }
        do {
            try await runner.value
        } catch is CancellationError {
            try? SystemManager.writeState(.stopped, message: nil, paths: paths)
        }
    }

    private static func runManagedService(paths: EnginePaths) async throws {
        for attempt in 0...retryDelays.count {
            do {
                try SystemManager.writeState(.starting, message: nil, paths: paths)
                try await SystemManager.prepare(paths: paths)
                try await daemon([], managed: true)
                return
            } catch {
                if error is CancellationError || Task.isCancelled { throw CancellationError() }
                let message = EngineError.message(for: error)
                let permanent = isPermanentProvisioningError(error)
                if permanent || attempt == retryDelays.count {
                    try? SystemManager.writeState(.failed, message: message, paths: paths)
                    FileHandle.standardError.write(Data("cengine: service provisioning failed: \(message)\nRelaunch the cengine app after correcting the problem.\n".utf8))
                    return
                }
                let delay = retryDelays[attempt]
                FileHandle.standardError.write(Data("cengine: transient startup failure: \(message); retrying in \(delay)\n".utf8))
                try await Task.sleep(for: delay)
            }
        }
    }

    private static func isPermanentProvisioningError(_ error: Error) -> Bool {
        if error is DecodingError { return true }
        guard let engine = error as? EngineError else { return false }
        if engine.message.localizedCaseInsensitiveContains("checksum") { return true }
        switch engine.code {
        case .badRequest, .conflict, .unsupported, .unauthorized: return true
        case .notFound, .internalError: return false
        }
    }

    private static func system(_ arguments: [String]) async throws {
        switch arguments.first ?? "status" {
        case "status":
            let paths = EnginePaths()
            if await socketIsReachable(paths.socket.path) {
                print("running")
            } else if let state = SystemManager.readState(paths: paths) {
                let phase: EngineServicePhase = state.phase == .running ? .stopped : state.phase
                print(phase.rawValue + (state.message.map { ": \($0)" } ?? ""))
            } else {
                print("stopped")
            }
        case "doctor":
            guard ProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 26 else { throw EngineError(.unsupported, "macOS 26 or newer is required") }
            #if arch(arm64)
            print("macOS and Apple silicon checks passed")
            #else
            throw EngineError(.unsupported, "Apple silicon is required")
            #endif
        case "shutdown":
            let count = try await VMShimTeardown.terminateAll(in: EnginePaths().data)
            print("stopped \(count) cengine VM shim\(count == 1 ? "" : "s")")
        case "install": try await SystemManager.install(paths: EnginePaths())
        case "uninstall": try SystemManager.uninstall(paths: EnginePaths())
        default: throw EngineError(.badRequest, "system command is not implemented yet")
        }
    }

    private static func networkHelper(_ arguments: [String]) async throws {
        let status: NetworkHelperStatus
        switch arguments.first ?? "status" {
        case "status": status = try await NetworkHelperControl.status()
        case "restart": status = try await NetworkHelperControl.restart()
        default: throw EngineError(.badRequest, "network-helper command is not implemented")
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(status)
        guard let output = String(data: data, encoding: .utf8) else {
            throw EngineError(.internalError, "could not encode networking helper status")
        }
        print(output)
    }

    private static func builder(_ arguments: [String]) async throws {
        guard arguments.first ?? "resources" == "resources" else {
            throw EngineError(.badRequest, "builder command is not implemented")
        }
        let values = Array(arguments.dropFirst())
        let paths = EnginePaths()
        var settings = try BuilderSettings.load(from: paths.builderSettings)
        guard !values.isEmpty else {
            print("CPUs: \(settings.cpus)")
            print("Memory: \(settings.memoryGiB) GiB")
            return
        }

        try parseResources(values, cpus: &settings.cpus, memory: &settings.memoryGiB, subject: "builder")

        try settings.save(to: paths.builderSettings)
        if await socketIsReachable(paths.socket.path) {
            do {
                try DockerIntegration.configureBuilder(settings)
                print("Builder resources updated to \(settings.cpus) CPUs and \(settings.memoryGiB) GiB memory.")
            } catch {
                throw EngineError(
                    .internalError,
                    "builder resources were saved but could not be applied now: \(error.localizedDescription)"
                )
            }
        } else {
            print("Builder resources saved; they will apply when cengine next starts.")
        }
    }

    private static func container(_ arguments: [String]) throws {
        guard arguments.first ?? "resources" == "resources" else {
            throw EngineError(.badRequest, "container command is not implemented")
        }
        let values = Array(arguments.dropFirst())
        let paths = EnginePaths()
        var settings = try ContainerSettings.load(from: paths.containerSettings)
        guard !values.isEmpty else {
            print("CPUs: \(settings.cpus)")
            print("Memory: \(settings.memoryGiB) GiB")
            return
        }

        try parseResources(values, cpus: &settings.cpus, memory: &settings.memoryGiB, subject: "container")
        try settings.save(to: paths.containerSettings)
        print("Default container resources updated to \(settings.cpus) CPUs and \(settings.memoryGiB) GiB memory.")
    }

    private static func run(_ arguments: [String]) async throws {
        guard let separator = arguments.firstIndex(of: "--") else {
            throw EngineError(.badRequest, "run requires `--` before the command")
        }
        let options = arguments[..<separator]
        let command = Array(arguments[arguments.index(after: separator)...])
        guard !command.isEmpty else { throw EngineError(.badRequest, "run requires a command after `--`") }

        var resources = ContainerResourceOverride()
        var socket = EnginePaths().socket.path
        var index = options.startIndex
        while index < options.endIndex {
            let name = options[index]
            let valueIndex = options.index(after: index)
            guard valueIndex < options.endIndex else { throw EngineError(.badRequest, "\(name) requires a value") }
            let value = options[valueIndex]
            switch name {
            case "--cpus":
                guard let cpus = Int(value) else { throw EngineError(.badRequest, "invalid CPU count: \(value)") }
                resources.cpus = cpus
            case "--memory":
                resources.memoryGiB = try memoryGiB(value)
            case "--socket":
                socket = value
            default:
                throw EngineError(.badRequest, "unknown run option: \(name)")
            }
            index = options.index(valueIndex, offsetBy: 1)
        }
        try resources.validate()

        let scope = try await CEngineControlClient.createResourceScope(
            socketPath: socket,
            ownerPID: getpid(),
            resources: resources
        )
        guard setenv("DOCKER_HOST", scope.dockerHost, 1) == 0 else {
            await CEngineControlClient.removeResourceScope(socketPath: socket, id: scope.id)
            throw EngineError(.internalError, "could not configure DOCKER_HOST")
        }
        for name in ["DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"] {
            unsetenv(name)
        }

        let executionError = replaceProcess(with: command)
        await CEngineControlClient.removeResourceScope(socketPath: socket, id: scope.id)
        throw EngineError(
            executionError == ENOENT ? .notFound : .internalError,
            "could not execute \(command[0]): \(String(cString: strerror(executionError)))"
        )
    }

    private static func replaceProcess(with arguments: [String]) -> Int32 {
        var pointers = arguments.map { strdup($0) } + [nil]
        defer { for pointer in pointers where pointer != nil { free(pointer) } }
        _ = pointers.withUnsafeMutableBufferPointer { buffer in
            execvp(buffer[0], buffer.baseAddress)
        }
        return errno
    }

    private static func parseResources(
        _ values: [String], cpus: inout Int, memory: inout Int, subject: String
    ) throws {
        var index = 0
        while index < values.count {
            let name = values[index]
            guard values.indices.contains(index + 1) else {
                throw EngineError(.badRequest, "\(name) requires a value")
            }
            let value = values[index + 1]
            switch name {
            case "--cpus":
                guard let parsed = Int(value) else { throw EngineError(.badRequest, "invalid CPU count: \(value)") }
                cpus = parsed
            case "--memory":
                memory = try memoryGiB(value)
            default:
                throw EngineError(.badRequest, "unknown \(subject) resource option: \(name)")
            }
            index += 2
        }
    }

    private static func memoryGiB(_ value: String) throws -> Int {
        let normalized = value.lowercased()
        let suffixes = ["gib", "gb", "g"]
        let numeric = suffixes.first(where: normalized.hasSuffix).map {
            String(normalized.dropLast($0.count))
        } ?? normalized
        guard let memory = Int(numeric), memory > 0 else {
            throw EngineError(.badRequest, "invalid memory: \(value); use whole GiB such as 4g")
        }
        return memory
    }

    private static func option(_ name: String, in arguments: [String]) -> String? {
        guard let index = arguments.firstIndex(of: name), arguments.indices.contains(index + 1) else { return nil }
        return arguments[index + 1]
    }

    private static func socketIsReachable(_ path: String) async -> Bool {
        guard FileManager.default.fileExists(atPath: path) else { return false }
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let channel = try? await ClientBootstrap(group: group).connect(unixDomainSocketPath: path).get()
        if let channel { try? await channel.close().get() }
        try? await group.shutdownGracefully()
        return channel != nil
    }

    private static func usage() {
        print("""
        Usage: cengine <command>
          builder resources [--cpus COUNT] [--memory GiB]
          container resources [--cpus COUNT] [--memory GiB]
          run [--socket PATH] [--cpus COUNT] [--memory GiB] -- COMMAND [ARGS...]
          daemon [--socket PATH] [--root PATH] [--kernel PATH] [--container-initramfs PATH] [--storage-initramfs PATH] [--automatic-ipv4-pool CIDR] [--automatic-ipv6-prefix CIDR] [--metadata-only]
          network-helper status|restart
          service run
          system status|doctor|shutdown|install|uninstall
          version
        """)
    }
}

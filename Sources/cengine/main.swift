import CEngineAPI
import CEngineCore
import CEngineRuntime
import Darwin
import Dispatch
import Foundation
import NIOPosix
import OSLog

@main enum CEngineMain {
    static let logger = Logger(subsystem: "dev.cengine.engine", category: "main")
    private static let retryDelays: [Duration] = [.seconds(30), .seconds(120)]

    static func main() async {
        do {
            var arguments = Array(CommandLine.arguments.dropFirst())
            let command = arguments.first ?? "help"
            if !arguments.isEmpty { arguments.removeFirst() }
            switch command {
            #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
            case "storage-lifecycle-qualification": try await StorageLifecycleQualification.run(arguments: arguments)
            case StorageLifecycleQualificationShim.argument: try await StorageLifecycleQualificationShim.run(arguments: [command] + arguments)
            #endif
            case "daemon": try await daemon(arguments, managed: false)
            case "service": try await service(arguments)
            case "builder": try await builder(arguments)
            case "container": try container(arguments)
            case "run": try await run(arguments)
            case "vm-shim": try await vmShim(arguments)
            case "helper": try await helper(arguments)
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
        guard !arguments.contains(where: { $0 == "--shared-storage" || $0.hasPrefix("--shared-storage=") }) else {
            throw EngineError(.badRequest, "unsupported option: --shared-storage; storage is selected automatically")
        }
        let metadataOnly = arguments.contains("--metadata-only")
        let paths = EnginePaths()
        try paths.createDirectories()
        let socket = option("--socket", in: arguments) ?? paths.socket.path
        let lockURL = URL(filePath: socket + ".lock")
        let daemonLock = try DaemonSocketLock(url: lockURL)
        defer { withExtendedLifetime(daemonLock) {} }
        let requestedRoot = option("--root", in: arguments).map {
            URL(filePath: $0, directoryHint: .isDirectory)
        } ?? paths.data
        let storeLock = try CanonicalDataStoreLock(root: requestedRoot)
        defer { withExtendedLifetime(storeLock) {} }
        let root = storeLock.root
        let backend: any ContainerBackend
        if metadataOnly {
            backend = MetadataOnlyBackend()
        } else {
            // Metadata-only never resolves signing, ownership, helper or assets.
            let sharedStorage = try ManagedStorageStartup.lifecycleConfiguration()
            if sharedStorage.policy.namespace == .production {
                try await ProductionStorageOwnerSetup.checkCurrentOwner()
            }
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
            try GuestAssetInstaller.diskBootstrapMetadata(kernel: kernel,
                containerInitialRamdisk: containerInitialRamdisk,
                storageInitialRamdisk: storageInitialRamdisk).requireLifecycleStorageSupport(policy: sharedStorage.policy)
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
                automaticNetworkPool: automaticNetworkPool,
                sharedStorage: sharedStorage,
                compatibilityStoreLock: storeLock
            )
        }
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let replacementTrigger: ManagedStorageReplacementTrigger?
        do {
            replacementTrigger = metadataOnly ? nil : try ManagedStorageReplacementTrigger.start(
                storeLock: storeLock, runtime: runtime)
        } catch {
            await runtime.shutdown()
            throw error
        }
        let admission = APIAdmissionController()
        let resourceScopes = ContainerResourceScopeManager(
            runtime: runtime, root: root, admission: admission
        )
        let server = DockerServer(
            socketPath: socket,
            router: DockerRouter(
                runtime: runtime,
                root: root,
                resourceScopeManager: resourceScopes
            ),
            admission: admission
        )
        do {
            try await server.start()
            if managed {
                try SystemManager.writeState(.running, message: nil, paths: paths)
                SystemManager.configureBuildx()
            }
        } catch {
            await replacementTrigger?.stop()
            try? await server.shutdown()
            try? await resourceScopes.shutdown()
            await runtime.shutdown()
            await replacementTrigger?.join()
            throw error
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
            await replacementTrigger?.stop()
            try await server.shutdown()
            try await resourceScopes.shutdown()
            await runtime.shutdown()
            await replacementTrigger?.join()
        } catch {
            await replacementTrigger?.stop()
            try? await server.shutdown()
            try? await resourceScopes.shutdown()
            await runtime.shutdown()
            await replacementTrigger?.join()
            throw error
        }
        if managed { try? SystemManager.writeState(.stopped, message: nil, paths: paths) }
    }

    private static func vmShim(_ arguments: [String]) async throws -> Never {
        guard let path = option("--spec", in: arguments) else { throw EngineError(.badRequest, "vm-shim requires --spec") }
        let launchIntentURL = option("--launch-intent", in: arguments).map { URL(filePath: $0) }
        let specificationSHA256 = option("--spec-sha256", in: arguments)
        guard launchIntentURL != nil || specificationSHA256 != nil else {
            throw EngineError(.badRequest, "vm-shim requires --spec-sha256 without --launch-intent")
        }
        if let specificationSHA256 {
            guard specificationSHA256.utf8.count == 64,
                  specificationSHA256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
                throw EngineError(.badRequest, "invalid vm-shim specification digest")
            }
        }
        let storageDiskDescriptor: Int32?
        if let value = option("--storage-disk-fd", in: arguments) {
            guard let descriptor = Int32(value), descriptor > STDERR_FILENO else {
                throw EngineError(.badRequest, "invalid storage disk descriptor")
            }
            storageDiskDescriptor = descriptor
        } else {
            storageDiskDescriptor = nil
        }
        let storageLifecycleDescriptor: Int32?
        if let value = option("--storage-lifecycle-fd", in: arguments) {
            guard let descriptor = Int32(value), descriptor > STDERR_FILENO else {
                throw EngineError(.badRequest, "invalid storage lifecycle descriptor")
            }
            storageLifecycleDescriptor = descriptor
        } else {
            storageLifecycleDescriptor = nil
        }
        return try await VMShimServer.run(
            specificationURL: URL(filePath: path),
            launchIntentURL: launchIntentURL,
            expectedSpecificationSHA256: specificationSHA256,
            storageDiskDescriptor: storageDiskDescriptor,
            storageLifecycleDescriptor: storageLifecycleDescriptor
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
        case .badRequest, .conflict, .unsupported, .unauthorized, .forbidden,
             .payloadTooLarge: return true
        case .notFound, .tooManyRequests, .serviceUnavailable, .upstream, .internalError: return false
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
            let options = try shutdownOptions(Array(arguments.dropFirst()))
            let count: Int
            if options.forUpgrade {
                // SMAppService unregistration is asynchronous. Hold the same
                // lock as daemon startup until every old disk writer is gone.
                try FileManager.default.createDirectory(
                    at: options.lock.deletingLastPathComponent(), withIntermediateDirectories: true
                )
                let lock = try await acquireUpgradeLock { try DaemonSocketLock(url: options.lock) }
                defer { withExtendedLifetime(lock) {} }
                try FileManager.default.createDirectory(at: options.root, withIntermediateDirectories: true)
                let rootLock = try await acquireUpgradeLock { try CanonicalDataStoreLock(root: options.root) }
                defer { withExtendedLifetime(rootLock) {} }
                count = try await VMShimTeardown.terminateAll(
                    in: options.root, requireCompleteShutdown: true, storeLock: rootLock
                )
            } else {
                count = try await VMShimTeardown.terminateAll(in: options.root)
            }
            print("stopped \(count) cengine VM shim\(count == 1 ? "" : "s")")
        case "configure-docker":
            let options = try dockerConfigurationOptions(Array(arguments.dropFirst()))
            let paths = EnginePaths(home: options.home)
            try SystemManager.configureDocker(paths: paths, socket: options.socket ?? paths.socket)
            print("configured Docker context and Buildx builder for cengine")
        case "install": try await SystemManager.install(paths: EnginePaths())
        case "uninstall": try SystemManager.uninstall(paths: EnginePaths())
        default: throw EngineError(.badRequest, "system command is not implemented yet")
        }
    }

    private static func shutdownOptions(_ arguments: [String]) throws -> (root: URL, lock: URL, forUpgrade: Bool) {
        var root: URL?
        var socket: URL?
        var forUpgrade = false
        var index = 0
        while index < arguments.count {
            let flag = arguments[index]
            if flag == "--for-upgrade", !forUpgrade {
                forUpgrade = true
                index += 1
                continue
            }
            guard index + 1 < arguments.count,
                  arguments[index + 1].hasPrefix("/") else {
                throw EngineError(.badRequest, "system shutdown requires absolute --root and --socket paths")
            }
            let value = URL(filePath: arguments[index + 1]).standardizedFileURL
            switch flag {
            case "--root" where root == nil: root = value.resolvingSymlinksInPath()
            case "--socket" where socket == nil: socket = value
            default: throw EngineError(.badRequest, "invalid system shutdown option: \(flag)")
            }
            index += 2
        }
        guard (root == nil) == (socket == nil) else {
            throw EngineError(.badRequest, "system shutdown --root and --socket must be supplied together")
        }
        let paths = EnginePaths()
        return (root ?? paths.data, socket.map { URL(filePath: $0.path + ".lock") } ?? paths.lock, forUpgrade)
    }

    private static func acquireUpgradeLock<Lock>(_ acquire: () throws -> Lock) async throws -> Lock {
        let deadline = ContinuousClock.now + .seconds(10)
        while true {
            try Task.checkCancellation()
            do { return try acquire() }
            catch let error as EngineError where error.code == .conflict {
                guard ContinuousClock.now < deadline else {
                    throw EngineError(.conflict, "engine is still running; stop its service before upgrading VMs")
                }
                try await Task.sleep(for: .milliseconds(100))
            }
        }
    }

    private static func helper(_ arguments: [String]) async throws {
        let status: NetworkHelperStatus
        switch arguments.first ?? "status" {
        case "status":
            let options = Array(arguments.dropFirst())
            let requirement: NetworkHelperCapabilities.Requirement?
            if options.isEmpty {
                requirement = nil
            } else if options.count == 2, options[0] == "--require-managed",
                      let parsed = NetworkHelperCapabilities.Requirement(rawValue: options[1]) {
                requirement = parsed
            } else {
                throw EngineError(.badRequest, "helper status accepts only --require-managed lifecycle-v2|lifecycle-qualification")
            }
            status = try await NetworkHelperControl.status(requirement: requirement)
        case "check-storage-owner", "setup-storage-owner":
            guard arguments.count == 1 else {
                throw EngineError(.badRequest, "storage owner commands accept no arguments")
            }
            if arguments[0] == "setup-storage-owner" {
                try await ProductionStorageOwnerSetup.setupCurrentOwner()
            } else {
                try await ProductionStorageOwnerSetup.checkCurrentOwner()
            }
            print("Storage owner is enrolled")
            return
        case "restart":
            guard arguments.count == 1 else {
                throw EngineError(.badRequest, "helper restart accepts no arguments")
            }
            status = try await NetworkHelperControl.restart()
        default: throw EngineError(.badRequest, "unknown Privileged Helper command")
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(status)
        guard let output = String(data: data, encoding: .utf8) else {
            throw EngineError(.internalError, "could not encode Privileged Helper status")
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
                try DockerIntegration.configureBuilder(settings, socket: paths.socket)
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

    private static func dockerConfigurationOptions(
        _ arguments: [String]
    ) throws -> (home: URL, socket: URL?) {
        var home = FileManager.default.homeDirectoryForCurrentUser
        var socket: URL?
        var index = 0
        while index < arguments.count {
            let name = arguments[index]
            guard ["--home", "--socket"].contains(name), index + 1 < arguments.count else {
                throw EngineError(
                    .badRequest,
                    "configure-docker accepts only --home PATH and --socket PATH"
                )
            }
            let value = arguments[index + 1]
            guard !value.isEmpty else {
                throw EngineError(.badRequest, "\(name) requires a path")
            }
            if name == "--home" {
                home = URL(filePath: value, directoryHint: .isDirectory)
            } else {
                socket = URL(filePath: value, directoryHint: .notDirectory)
            }
            index += 2
        }
        return (home, socket)
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
          helper status [--require-managed lifecycle-v2|lifecycle-qualification]
          helper restart (Privileged Helper test control)
          helper check-storage-owner
          helper setup-storage-owner (explicit administrator approval)
          service run
          system status|doctor|shutdown|install|uninstall
          system configure-docker [--socket PATH] [--home PATH]
          version
        """)
    }
}

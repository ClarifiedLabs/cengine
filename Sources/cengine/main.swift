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
        let root = option("--root", in: arguments).map { URL(filePath: $0, directoryHint: .isDirectory) } ?? paths.data
        let backend: any ContainerBackend
        if arguments.contains("--metadata-only") {
            backend = MetadataOnlyBackend()
        } else {
            let kernel = option("--kernel", in: arguments).map { URL(filePath: $0) } ?? paths.kernel
            guard FileManager.default.fileExists(atPath: kernel.path) else {
                throw EngineError(.notFound, "Linux kernel not found at \(kernel.path); run `cengine system install`")
            }
            backend = try await AppleContainerBackend(root: root, kernel: kernel)
        }
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let server = DockerServer(socketPath: socket, router: DockerRouter(runtime: runtime, root: root))
        do {
            try await server.start()
        } catch {
            try? await server.shutdown()
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
        } catch {
            try? await server.shutdown()
            throw error
        }
        if managed { try? SystemManager.writeState(.stopped, message: nil, paths: paths) }
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
                let message = error.localizedDescription
                let permanent = isPermanentProvisioningError(error)
                if permanent || attempt == retryDelays.count {
                    try? SystemManager.writeState(.failed, message: message, paths: paths)
                    FileHandle.standardError.write(Data("cengine: service provisioning failed: \(message)\nRun `brew services restart cengine` after correcting the problem.\n".utf8))
                    return
                }
                let delay = retryDelays[attempt]
                FileHandle.standardError.write(Data("cengine: transient startup failure: \(message); retrying in \(delay)\n".utf8))
                try await Task.sleep(for: delay)
            }
        }
    }

    private static func isPermanentProvisioningError(_ error: Error) -> Bool {
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
                let phase: SystemManager.ServicePhase = state.phase == .running ? .stopped : state.phase
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
        case "install": try await SystemManager.install(paths: EnginePaths())
        case "uninstall": try SystemManager.uninstall(paths: EnginePaths())
        default: throw EngineError(.badRequest, "system command is not implemented yet")
        }
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
          daemon [--socket PATH] [--root PATH] [--kernel PATH] [--metadata-only]
          service run
          system status|doctor|install|uninstall
          version
        """)
    }
}

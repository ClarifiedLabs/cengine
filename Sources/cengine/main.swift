import CEngineAPI
import CEngineCore
import CEngineRuntime
import Foundation
import OSLog

@main enum CEngineMain {
    static let logger = Logger(subsystem: "dev.cengine.engine", category: "main")

    static func main() async {
        do {
            var arguments = Array(CommandLine.arguments.dropFirst())
            let command = arguments.first ?? "help"
            if !arguments.isEmpty { arguments.removeFirst() }
            switch command {
            case "daemon": try await daemon(arguments)
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

    private static func daemon(_ arguments: [String]) async throws {
        let paths = EnginePaths()
        try paths.createDirectories()
        let socket = option("--socket", in: arguments) ?? paths.socket.path
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
        try await server.start()
        logger.info("listening on \(socket, privacy: .public)")
        try await server.wait()
    }

    private static func system(_ arguments: [String]) async throws {
        switch arguments.first ?? "status" {
        case "status":
            let socket = EnginePaths().socket.path
            print(FileManager.default.fileExists(atPath: socket) ? "running" : "stopped")
        case "doctor":
            guard ProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 26 else { throw EngineError(.unsupported, "macOS 26 or newer is required") }
            #if arch(arm64)
            print("macOS and Apple silicon checks passed")
            #else
            throw EngineError(.unsupported, "Apple silicon is required")
            #endif
        case "install":
            try await SystemManager.install(paths: EnginePaths())
        case "uninstall":
            try SystemManager.uninstall(paths: EnginePaths())
        default: throw EngineError(.badRequest, "system command is not implemented yet")
        }
    }

    private static func option(_ name: String, in arguments: [String]) -> String? {
        guard let index = arguments.firstIndex(of: name), arguments.indices.contains(index + 1) else { return nil }
        return arguments[index + 1]
    }

    private static func usage() {
        print("""
        Usage: cengine <command>
          daemon [--socket PATH] [--root PATH] [--kernel PATH] [--metadata-only]
          system status|doctor|install|uninstall
          version
        """)
    }
}

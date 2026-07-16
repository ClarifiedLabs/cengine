import CEngineCore
import CEngineRuntime
import Darwin
import Foundation

enum SystemManager {
    static let label = "dev.cengine.engine"

    static func install(paths: EnginePaths) async throws {
        try await prepare(paths: paths)
        try installLaunchAgent(paths: paths)
        print("cengine is installed; use `docker --context cengine info`")
    }

    static func uninstall(paths: EnginePaths) throws {
        let domain = "gui/\(getuid())"
        _ = try? run("/bin/launchctl", ["bootout", domain + "/" + label])
        try? FileManager.default.removeItem(at: launchAgentURL)
        DockerIntegration.remove()
        try? writeState(.stopped, message: nil, paths: paths)
        print("cengine service and Docker integration removed; data was preserved at \(paths.data.path)")
    }

    static func prepare(paths: EnginePaths) async throws {
        try paths.createDirectories()
        if GuestAssetInstaller.needsInstall(paths: paths) {
            print("Installing cengine kernel and guest initramfs assets...")
            try GuestAssetInstaller.install(paths: paths)
        }
        configureDockerContext(paths: paths)
    }

    static func configureBuildx() {
        guard DockerIntegration.executable(named: "docker") != nil else { return }
        do {
            let paths = EnginePaths()
            try DockerIntegration.configureBuilder(BuilderSettings.load(from: paths.builderSettings))
        } catch {
            warn("could not configure Buildx: \(error.localizedDescription)")
        }
    }

    static func writeState(_ phase: EngineServicePhase, message: String?, paths: EnginePaths) throws {
        try paths.createDirectories()
        let state = EngineServiceState(phase: phase, message: message)
        try JSONEncoder().encode(state).write(to: paths.serviceState, options: .atomic)
    }

    static func readState(paths: EnginePaths) -> EngineServiceState? {
        try? EngineServiceState.load(from: paths.serviceState)
    }

    private static var launchAgentURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appending(path: "Library/LaunchAgents/\(label).plist")
    }

    private static func installLaunchAgent(paths: EnginePaths) throws {
        guard let executable = Bundle.main.executableURL else {
            throw EngineError(.internalError, "could not locate cengine executable")
        }
        let plist: [String: Any] = [
            "Label": label,
            "ProgramArguments": [executable.path, "service", "run"],
            "RunAtLoad": true,
            "KeepAlive": ["SuccessfulExit": false],
            "ThrottleInterval": 60,
            "ProcessType": "Interactive",
            "StandardOutPath": paths.logs.appending(path: "daemon.log").path,
            "StandardErrorPath": paths.logs.appending(path: "daemon.log").path,
        ]
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        try FileManager.default.createDirectory(at: launchAgentURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: launchAgentURL, options: .atomic)
        let domain = "gui/\(getuid())"
        _ = try? run("/bin/launchctl", ["bootout", domain + "/" + label])
        for _ in 0..<20 {
            if (try? run("/bin/launchctl", ["print", domain + "/" + label])) == nil { break }
            usleep(100_000)
        }
        do {
            try run("/bin/launchctl", ["bootstrap", domain, launchAgentURL.path])
        } catch {
            if (try? run("/bin/launchctl", ["print", domain + "/" + label])) == nil { throw error }
        }
    }

    private static func configureDockerContext(paths: EnginePaths) {
        guard DockerIntegration.executable(named: "docker") != nil else {
            print("Docker CLI not found; skipping context and Buildx configuration")
            return
        }
        let expected = "unix://\(paths.socket.path)"
        if let current = try? DockerIntegration.runDocker(["context", "inspect", "cengine", "--format", "{{.Endpoints.docker.Host}}"]),
           current.trimmingCharacters(in: .whitespacesAndNewlines) == expected { return }
        do {
            _ = try? DockerIntegration.runDocker(["context", "rm", "-f", "cengine"])
            try DockerIntegration.runDocker(["context", "create", "cengine", "--docker", "host=\(expected)", "--description", "cengine (one container per VM)"])
        } catch {
            warn("could not configure Docker context: \(error.localizedDescription)")
        }
    }

    private static func warn(_ message: String) {
        FileHandle.standardError.write(Data("cengine: warning: \(message)\n".utf8))
    }

    @discardableResult private static func run(_ executable: String, _ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(filePath: executable)
        process.arguments = arguments
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        try process.run()
        process.waitUntilExit()
        let text = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        guard process.terminationStatus == 0 else {
            throw EngineError(.internalError, "\(([executable] + arguments).joined(separator: " ")) failed: \(text)")
        }
        return text
    }
}

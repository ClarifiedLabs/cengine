import CEngineCore
import CEngineRuntime
import Darwin
import Foundation

enum SystemManager {
    static let label = "dev.cengine.engine"

    static func install(paths: EnginePaths) async throws {
        try paths.createDirectories()
        if !FileManager.default.fileExists(atPath: paths.kernel.path) {
            print("Installing Kata Linux kernel \(KernelInstaller.version)…")
            try await KernelInstaller.install(to: paths.kernel)
        }
        try installLaunchAgent(paths: paths)
        try configureDocker(paths: paths)
        print("cengine is installed; use `docker --context cengine info`")
    }

    static func uninstall(paths: EnginePaths) throws {
        let domain = "gui/\(getuid())"
        _ = try? run("/bin/launchctl", ["bootout", domain + "/" + label])
        try? FileManager.default.removeItem(at: launchAgentURL)
        _ = try? runDocker(["context", "rm", "-f", "cengine"])
        print("cengine service and Docker context removed; data was preserved at \(paths.data.path)")
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
            "ProgramArguments": [executable.path, "daemon"],
            "RunAtLoad": true,
            "KeepAlive": true,
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
            // launchd can report EIO when a bootout/bootstrap pair races even
            // though the new job was loaded. Verify state before failing.
            if (try? run("/bin/launchctl", ["print", domain + "/" + label])) == nil { throw error }
        }
    }

    private static func configureDocker(paths: EnginePaths) throws {
        guard executable(named: "docker") != nil else {
            print("Docker CLI not found; skipping context and Buildx configuration")
            return
        }
        _ = try? runDocker(["context", "rm", "-f", "cengine"])
        try runDocker(["context", "create", "cengine", "--docker", "host=unix://\(paths.socket.path)", "--description", "cengine (Apple Containerization)"])
        guard (try? runDocker(["buildx", "version"])) != nil else {
            print("Docker Buildx not found; container builds will be unavailable")
            return
        }
        // BuildKit's overlayfs snapshotter cannot use a VirtioFS-backed named
        // volume as its upper/work filesystem. The native snapshotter retains
        // the managed builder's state on that volume without nested overlayfs.
        _ = try? runDocker(["buildx", "rm", "--force", "cengine-builder"])
        try runDocker([
            "buildx", "create", "--name", "cengine-builder", "--driver", "docker-container",
            "--driver-opt", "image=moby/buildkit:v0.27.1",
            "--buildkitd-flags", "--oci-worker-snapshotter=native", "cengine",
        ])
    }

    @discardableResult private static func runDocker(_ arguments: [String]) throws -> String {
        guard let docker = executable(named: "docker") else { throw EngineError(.notFound, "docker CLI not found") }
        return try run(docker, arguments)
    }

    private static func executable(named name: String) -> String? {
        for directory in (ProcessInfo.processInfo.environment["PATH"] ?? "").split(separator: ":") {
            let candidate = URL(filePath: String(directory)).appending(path: name).path
            if FileManager.default.isExecutableFile(atPath: candidate) { return candidate }
        }
        return nil
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

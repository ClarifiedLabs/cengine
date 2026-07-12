import Foundation

/// The Docker CLI integration cengine creates (a `cengine` context and a
/// `cengine-builder` Buildx builder), shared by the CLI, the app, and the
/// headless cask uninstall so setup and teardown stay in sync.
public enum DockerIntegration {
    public static let contextName = "cengine"
    public static let builderName = "cengine-builder"
    public static let buildkitImage = "moby/buildkit:v0.27.1"
    private static let cpuPeriod = 100_000

    /// Locates an executable on PATH, falling back to the standard Homebrew
    /// locations for launchd-spawned processes whose PATH omits them.
    public static func executable(
        named name: String,
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> String? {
        let path = (environment["PATH"] ?? "") + ":/opt/homebrew/bin:/usr/local/bin"
        for directory in path.split(separator: ":") {
            let candidate = URL(filePath: String(directory)).appending(path: name).path
            if FileManager.default.isExecutableFile(atPath: candidate) { return candidate }
        }
        return nil
    }

    /// Removes the cengine Docker context and Buildx builder. A missing docker
    /// CLI or already-removed integration is a no-op.
    public static func remove() {
        guard executable(named: "docker") != nil else { return }
        _ = try? runDocker(["buildx", "rm", "--force", builderName])
        _ = try? runDocker(["context", "rm", "-f", contextName])
    }

    /// Creates the managed Buildx builder or reconciles its VM resource
    /// settings while retaining the builder's cache volume.
    public static func configureBuilder(_ settings: BuilderSettings) throws {
        try settings.validate()
        guard executable(named: "docker") != nil else {
            throw EngineError(.notFound, "docker CLI not found")
        }
        _ = try runDocker(["buildx", "version"])

        let inspected = try? runDocker(["buildx", "inspect", builderName])
        if let inspected {
            guard !builder(inspected, matches: settings) else { return }
            _ = try runDocker(["buildx", "rm", "--force", "--keep-state", builderName])
        }
        _ = try runDocker(createBuilderArguments(settings))
    }

    public static func createBuilderArguments(_ settings: BuilderSettings) -> [String] {
        [
            "buildx", "create", "--name", builderName, "--driver", "docker-container",
            "--driver-opt", "image=\(buildkitImage)",
            "--driver-opt", "memory=\(settings.memoryBytes)",
            "--driver-opt", "cpu-period=\(cpuPeriod)",
            "--driver-opt", "cpu-quota=\(settings.cpus * cpuPeriod)",
            "--buildkitd-flags", "--oci-worker-snapshotter=native", contextName,
        ]
    }

    public static func builder(_ inspection: String, matches settings: BuilderSettings) -> Bool {
        let expected = [
            "image=\"\(buildkitImage)\"",
            "memory=\"\(settings.memoryBytes)\"",
            "cpu-period=\"\(cpuPeriod)\"",
            "cpu-quota=\"\(settings.cpus * cpuPeriod)\"",
        ]
        return expected.allSatisfy(inspection.contains)
    }

    @discardableResult public static func runDocker(_ arguments: [String]) throws -> String {
        guard let docker = executable(named: "docker") else {
            throw EngineError(.notFound, "docker CLI not found")
        }
        let process = Process()
        process.executableURL = URL(filePath: docker)
        process.arguments = arguments
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        try process.run()
        process.waitUntilExit()
        let text = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        guard process.terminationStatus == 0 else {
            throw EngineError(.internalError, "\(([docker] + arguments).joined(separator: " ")) failed: \(text)")
        }
        return text
    }
}

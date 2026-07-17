import Foundation

public enum DockerRemovalOutcome: Sendable, Equatable {
    case completed
    case dockerUnavailable
    case contextRemovalSkipped(String)
    case contextRemovalFailed(String)

    public var warning: String? {
        switch self {
        case .completed, .dockerUnavailable:
            nil
        case let .contextRemovalSkipped(message):
            "Docker context removal was skipped to preserve the active context: \(message)"
        case let .contextRemovalFailed(message):
            "Docker context removal failed: \(message)"
        }
    }
}

/// The Docker CLI integration cengine creates (a `cengine` context and a
/// `cengine-builder` Buildx builder), shared by the CLI, the app, and the
/// headless cask uninstall so setup and teardown stay in sync.
public enum DockerIntegration {
    public static let contextName = "cengine"
    public static let builderName = "cengine-builder"
    public static let buildkitImage = "moby/buildkit:v0.27.1"
    public static let buildkitSnapshotter = "overlayfs"
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

    /// Removes the cengine Docker context and Buildx builder without resetting
    /// an active managed context unless its restoration marker was recorded.
    @discardableResult
    public static func remove(recordingActiveContextTo marker: URL?) -> DockerRemovalOutcome {
        guard executable(named: "docker") != nil else { return .dockerUnavailable }
        return remove(
            recordingActiveContextTo: marker,
            runDocker: runDockerForPersistedContext
        )
    }

    static func remove(
        recordingActiveContextTo marker: URL?,
        runDocker: ([String]) throws -> String,
        fileManager: FileManager = .default
    ) -> DockerRemovalOutcome {
        if let marker {
            do {
                let current = try runDocker(["context", "show"])
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                if current == contextName {
                    try fileManager.createDirectory(
                        at: marker.deletingLastPathComponent(),
                        withIntermediateDirectories: true
                    )
                    try Data("\(contextName)\n".utf8).write(to: marker, options: .atomic)
                } else if fileManager.fileExists(atPath: marker.path) {
                    try fileManager.removeItem(at: marker)
                }
            } catch {
                _ = try? runDocker(["buildx", "rm", "--force", builderName])
                return .contextRemovalSkipped(error.localizedDescription)
            }
        }

        _ = try? runDocker(["buildx", "rm", "--force", builderName])
        do {
            _ = try runDocker(["context", "rm", "-f", contextName])
            return .completed
        } catch {
            return .contextRemovalFailed(error.localizedDescription)
        }
    }

    /// Creates or reconciles the cengine context, then restores it only after
    /// verifying that it points at this installation's socket.
    public static func configureContext(
        socket: URL,
        restoringActiveContextFrom marker: URL
    ) throws {
        guard executable(named: "docker") != nil else {
            throw EngineError(.notFound, "docker CLI not found")
        }
        try configureContext(
            socket: socket,
            restoringActiveContextFrom: marker,
            runDocker: runDockerForPersistedContext
        )
    }

    static func configureContext(
        socket: URL,
        restoringActiveContextFrom marker: URL,
        runDocker: ([String]) throws -> String,
        fileManager: FileManager = .default
    ) throws {
        let expected = "unix://\(socket.path)"
        let inspectArguments = [
            "context", "inspect", contextName,
            "--format", "{{.Endpoints.docker.Host}}",
        ]
        let inspectedHost = try? runDocker(inspectArguments)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if inspectedHost != expected {
            _ = try? runDocker(["context", "rm", "-f", contextName])
            _ = try runDocker([
                "context", "create", contextName,
                "--docker", "host=\(expected)",
                "--description", "cengine (one container per VM)",
            ])
        }

        let verifiedHost = try runDocker(inspectArguments)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard verifiedHost == expected else {
            throw EngineError(
                .internalError,
                "Docker context '\(contextName)' points at \(verifiedHost), expected \(expected)"
            )
        }
        guard fileManager.fileExists(atPath: marker.path) else { return }

        let markerContext = try String(contentsOf: marker, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard markerContext == contextName else {
            try fileManager.removeItem(at: marker)
            return
        }
        _ = try runDocker(["context", "use", contextName])
        try fileManager.removeItem(at: marker)
    }

    /// Creates the managed Buildx builder or reconciles its configuration,
    /// retaining the cache only when its snapshotter remains compatible.
    public static func configureBuilder(_ settings: BuilderSettings) throws {
        try settings.validate()
        guard executable(named: "docker") != nil else {
            throw EngineError(.notFound, "docker CLI not found")
        }
        try configureBuilder(settings, runDocker: runDocker)
    }

    static func configureBuilder(
        _ settings: BuilderSettings,
        runDocker: ([String]) throws -> String
    ) throws {
        _ = try runDocker(["buildx", "version"])
        let inspected = try? runDocker(["buildx", "inspect", builderName])
        if let inspected {
            if !builder(inspected, matches: settings) {
                var removal = ["buildx", "rm", "--force"]
                if builderUsesManagedSnapshotter(inspected) { removal.append("--keep-state") }
                removal.append(builderName)
                _ = try runDocker(removal)
                _ = try runDocker(createBuilderArguments(settings))
            }
        } else {
            _ = try runDocker(createBuilderArguments(settings))
        }
        _ = try runDocker([
            "--context", contextName, "buildx", "use", "--default", builderName,
        ])
    }

    public static func createBuilderArguments(_ settings: BuilderSettings) -> [String] {
        [
            "buildx", "create", "--name", builderName, "--driver", "docker-container",
            "--driver-opt", "image=\(buildkitImage)",
            "--driver-opt", "memory=\(settings.memoryBytes)",
            "--driver-opt", "cpu-period=\(cpuPeriod)",
            "--driver-opt", "cpu-quota=\(settings.cpus * cpuPeriod)",
            "--buildkitd-flags", "--oci-worker-snapshotter=\(buildkitSnapshotter)", contextName,
        ]
    }

    public static func builder(_ inspection: String, matches settings: BuilderSettings) -> Bool {
        let expected = [
            "image=\"\(buildkitImage)\"",
            "memory=\"\(settings.memoryBytes)\"",
            "cpu-period=\"\(cpuPeriod)\"",
            "cpu-quota=\"\(settings.cpus * cpuPeriod)\"",
            "--oci-worker-snapshotter=\(buildkitSnapshotter)",
        ]
        return expected.allSatisfy(inspection.contains)
    }

    static func builderUsesManagedSnapshotter(_ inspection: String) -> Bool {
        inspection.contains("--oci-worker-snapshotter=\(buildkitSnapshotter)")
    }

    @discardableResult public static func runDocker(_ arguments: [String]) throws -> String {
        try runDocker(arguments, environment: ProcessInfo.processInfo.environment)
    }

    static func runDocker(
        _ arguments: [String],
        environment: [String: String]
    ) throws -> String {
        guard let docker = executable(named: "docker", environment: environment) else {
            throw EngineError(.notFound, "docker CLI not found")
        }
        let process = Process()
        process.executableURL = URL(filePath: docker)
        process.arguments = arguments
        process.environment = environment
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

    private static func runDockerForPersistedContext(_ arguments: [String]) throws -> String {
        let environment = persistedContextEnvironment(ProcessInfo.processInfo.environment)
        return try runDocker(arguments, environment: environment)
    }

    static func persistedContextEnvironment(
        _ processEnvironment: [String: String]
    ) -> [String: String] {
        var environment = processEnvironment
        environment.removeValue(forKey: "DOCKER_CONTEXT")
        environment.removeValue(forKey: "DOCKER_HOST")
        return environment
    }
}

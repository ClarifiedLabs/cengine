import CEngineCore
import Darwin
import Dispatch
import Foundation
import ServiceManagement

/// The launchd services the app registers, shared by the in-app uninstall and
/// the headless `--uninstall-support` mode the Homebrew cask invokes.
enum CEngineServices {
    static let engineLabel = "dev.cengine.engine"
    static let agentPlist = "dev.cengine.engine.plist"
    static let helperPlist = "dev.cengine.network-helper.plist"

    /// A newly installed bundled service can be absent from Background Task
    /// Management's database and report `.notFound` until its first registration.
    /// Register both absent and explicitly unregistered services.
    static func needsRegistration(_ status: SMAppService.Status) -> Bool {
        status == .notRegistered || status == .notFound
    }

    static func restartEngine(runLaunchctl: ([String]) throws -> Void = runLaunchctl) throws {
        try runLaunchctl(["kickstart", "-k", "gui/\(getuid())/\(engineLabel)"])
    }

    /// Quiesces the engine, stops every provably owned VM shim, and then
    /// unregisters the privileged helper. Every phase is attempted even when
    /// an earlier one fails so uninstall can still remove all services.
    @MainActor static func teardownServices(
        agent: any AppService = SMAppService.agent(plistName: agentPlist),
        helper: any AppService = SMAppService.daemon(plistName: helperPlist),
        waitForEngineExit: @MainActor () async throws -> Void = {
            try await Task.sleep(for: .seconds(2))
        },
        stopVirtualMachines: @MainActor () async throws -> Void = {
            try await runVirtualMachineShutdown()
        }
    ) async throws {
        var failures: [String] = []
        let agentWasRegistered = !needsRegistration(agent.status)
        if agentWasRegistered {
            do {
                try await agent.unregister()
            } catch {
                failures.append("engine service: \(EngineError.message(for: error))")
            }
            do {
                try await waitForEngineExit()
            } catch {
                failures.append("engine exit: \(EngineError.message(for: error))")
            }
        }
        do {
            try await stopVirtualMachines()
        } catch {
            failures.append("VM shutdown: \(EngineError.message(for: error))")
        }
        if !needsRegistration(helper.status) {
            do {
                try await helper.unregister()
            } catch {
                failures.append("network helper: \(EngineError.message(for: error))")
            }
        }
        guard failures.isEmpty else {
            throw EngineError(
                .internalError,
                "cengine service teardown was incomplete: \(failures.joined(separator: "; "))"
            )
        }
    }

    private static func runVirtualMachineShutdown() async throws {
        let executable = Bundle.main.bundleURL
            .appending(path: "Contents/MacOS/cengine-engine")
        guard FileManager.default.isExecutableFile(atPath: executable.path) else {
            throw EngineError(.notFound, "bundled cengine engine is missing")
        }
        try await Task.detached {
            try run(executable.path, ["system", "shutdown"])
        }.value
    }

    private static func runLaunchctl(_ arguments: [String]) throws {
        try run("/bin/launchctl", arguments)
    }

    private static func run(_ executable: String, _ arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(filePath: executable)
        process.arguments = arguments
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        try process.run()
        process.waitUntilExit()
        let message = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard process.terminationStatus == 0 else {
            throw EngineError(
                .internalError,
                "\(([executable] + arguments).joined(separator: " ")) failed"
                    + (message.isEmpty ? "" : ": \(message)")
            )
        }
    }
}

enum CEngineUserData {
    static let appIdentifier = "dev.cengine.app"
    static let relativePaths = [
        ".cengine",
        "Library/Application Support/cengine",
        "Library/Caches/dev.cengine.app",
        "Library/Logs/cengine",
        "Library/Preferences/dev.cengine.app.plist",
        "Library/Saved Application State/dev.cengine.app.savedState",
    ]

    static func locations(home: URL) -> [URL] {
        relativePaths.map { home.appending(path: $0) }
    }

    /// Permanently removes all per-user engine resources and app state. Unlike
    /// Homebrew's zap, which moves these paths to Trash, the in-app purge is
    /// intentionally irreversible after the user confirms it.
    static func removeAll(
        home: URL = FileManager.default.homeDirectoryForCurrentUser,
        fileManager: FileManager = .default,
        defaults: UserDefaults = .standard,
        preferencesDomain: String = appIdentifier
    ) throws {
        var failures: [(URL, Error)] = []
        for location in locations(home: home) where fileManager.fileExists(atPath: location.path) {
            do {
                try fileManager.removeItem(at: location)
            } catch {
                failures.append((location, error))
            }
        }
        defaults.removePersistentDomain(forName: preferencesDomain)
        guard failures.isEmpty else {
            let details = failures.map { "\($0.0.path): \($0.1.localizedDescription)" }
                .joined(separator: "; ")
            throw EngineError(.internalError, "could not delete all cengine data: \(details)")
        }
    }
}

enum UninstallSupport {
    @MainActor static func performBestEffortTeardown(
        teardownServices: @MainActor () async throws -> Void = {
            try await CEngineServices.teardownServices()
        },
        removeDockerIntegration: () -> DockerRemovalOutcome = {
            DockerIntegration.remove(
                recordingActiveContextTo: EnginePaths().activeContextMarker
            )
        }
    ) async -> [String] {
        var warnings: [String] = []
        do {
            try await teardownServices()
        } catch {
            warnings.append(error.localizedDescription)
        }
        if let warning = removeDockerIntegration().warning {
            warnings.append(warning)
        }
        return warnings
    }

    /// Headless teardown for `brew uninstall --cask cengine`: unregister both
    /// launchd services and drop the Docker integration, then exit. User data is
    /// deliberately left to the cask's delete/zap stanzas. Cleanup is best
    /// effort: warnings must never prevent Homebrew from removing the app.
    static func main() -> Never {
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 20) {
            FileHandle.standardError.write(Data(
                "cengine uninstall warning: cleanup timed out; continuing removal\n".utf8
            ))
            exit(0) // watchdog: cleanup must never block application removal
        }
        Task { @MainActor in
            for warning in await performBestEffortTeardown() {
                FileHandle.standardError.write(Data(
                    "cengine uninstall warning: \(warning)\n".utf8
                ))
            }
            exit(0)
        }
        dispatchMain()
    }
}

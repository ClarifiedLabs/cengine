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

    /// Unregisters the network-helper daemon and then the engine agent,
    /// tolerating already-removed services so repeated teardowns stay idempotent.
    static func teardownServices() async {
        let services = [
            SMAppService.daemon(plistName: helperPlist),
            SMAppService.agent(plistName: agentPlist),
        ]
        for service in services {
            let status = service.status
            guard status != .notRegistered, status != .notFound else { continue }
            do {
                try await service.unregister()
            } catch {
                FileHandle.standardError.write(Data("cengine uninstall: \(error.localizedDescription)\n".utf8))
            }
        }
    }

    private static func runLaunchctl(_ arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(filePath: "/bin/launchctl")
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
                "launchctl \(arguments.joined(separator: " ")) failed"
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
    /// Headless teardown for `brew uninstall --cask cengine`: unregister both
    /// launchd services and drop the Docker integration, then exit. User data is
    /// deliberately left to the cask's delete/zap stanzas.
    static func main() -> Never {
        DispatchQueue.main.asyncAfter(deadline: .now() + 20) {
            exit(1) // watchdog: brew must never hang on a wedged teardown
        }
        Task {
            await CEngineServices.teardownServices()
            DockerIntegration.remove()
            exit(0)
        }
        dispatchMain()
    }
}

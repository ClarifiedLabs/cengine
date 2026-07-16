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

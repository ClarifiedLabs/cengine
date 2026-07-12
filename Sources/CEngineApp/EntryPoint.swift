import AppKit
import Foundation

@main
enum CEngineEntryPoint {
    @MainActor static func main() {
        if CommandLine.arguments.dropFirst().contains("--uninstall-support") {
            UninstallSupport.main()
        } else if isTestHost {
            // Hosted unit tests inject into this process; run a bare AppKit loop so
            // the real app (and its SMAppService registration side effect) never starts.
            NSApplication.shared.run()
        } else {
            CEngineApplication.main()
        }
    }

    private static var isTestHost: Bool {
        let environment = ProcessInfo.processInfo.environment
        return environment["XCTestConfigurationFilePath"] != nil
            || environment["XCTestBundlePath"] != nil
            || environment["XCTestSessionIdentifier"] != nil
    }
}

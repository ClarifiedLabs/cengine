import AppKit
import CEngineCore
import Foundation

@main
enum CEngineEntryPoint {
    @MainActor static func main() {
        let route = AppLaunchPolicy.route(
            isTestHost: isTestHost,
            defaults: .standard,
            legacyServiceStateURL: EnginePaths().serviceState
        )
        switch route {
        case .uninstallSupport:
            UninstallSupport.main()
        case .testHost:
            // Hosted unit tests inject into this process; run a bare AppKit loop so
            // the real app (and its SMAppService registration side effect) never starts.
            NSApplication.shared.run()
        case .exitAfterInstallerLaunch:
            return
        case let .launchApplication(migrateLegacyEnginePreference):
            if migrateLegacyEnginePreference {
                UserDefaults.standard.set(true, forKey: AppPreferenceKeys.engineServiceEnabled)
            }
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

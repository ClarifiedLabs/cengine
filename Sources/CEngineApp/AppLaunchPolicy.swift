import CEngineCore
import Foundation

enum AppPreferenceKeys {
    static let completedOnboarding = "completedOnboarding"
    static let engineServiceEnabled = "engineServiceEnabled"
}

enum AppLaunchOptions {
    static let openedByInstaller = "--opened-by-installer"
    static let uninstallSupport = "--uninstall-support"
}

enum AppLaunchRoute: Equatable {
    case uninstallSupport
    case testHost
    case exitAfterInstallerLaunch
    case launchApplication(migrateLegacyEnginePreference: Bool)
}

enum AppLaunchPolicy {
    static func route(
        arguments: [String] = CommandLine.arguments,
        isTestHost: Bool,
        defaults: UserDefaults = .standard,
        legacyServiceStateURL: URL = EnginePaths().serviceState
    ) -> AppLaunchRoute {
        let applicationArguments = arguments.dropFirst()
        if applicationArguments.contains(AppLaunchOptions.uninstallSupport) {
            return .uninstallSupport
        }
        if isTestHost { return .testHost }
        guard applicationArguments.contains(AppLaunchOptions.openedByInstaller) else {
            return .launchApplication(migrateLegacyEnginePreference: false)
        }
        if let explicitlyEnabled = defaults.object(
            forKey: AppPreferenceKeys.engineServiceEnabled
        ) as? Bool {
            return explicitlyEnabled
                ? .launchApplication(migrateLegacyEnginePreference: false)
                : .exitAfterInstallerLaunch
        }
        guard (try? EngineServiceState.load(from: legacyServiceStateURL)) != nil else {
            return .exitAfterInstallerLaunch
        }
        return .launchApplication(migrateLegacyEnginePreference: true)
    }
}

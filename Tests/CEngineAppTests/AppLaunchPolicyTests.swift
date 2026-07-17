import CEngineCore
import Foundation
import Testing
@testable import CEngineApp

@Suite struct AppLaunchPolicyTests {
    @Test func uninstallAndTestHostRoutesTakePrecedence() {
        #expect(AppLaunchPolicy.route(
            arguments: ["cengine", "--opened-by-installer", "--uninstall-support"],
            isTestHost: true
        ) == .uninstallSupport)
        #expect(AppLaunchPolicy.route(
            arguments: ["cengine", "--opened-by-installer"],
            isTestHost: true
        ) == .testHost)
    }

    @Test func normalUserLaunchAlwaysStartsApplication() {
        #expect(AppLaunchPolicy.route(
            arguments: ["cengine"],
            isTestHost: false
        ) == .launchApplication(migrateLegacyEnginePreference: false))
    }

    @Test func freshInstallerLaunchExits() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let suiteName = "AppLaunchPolicyTests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suiteName))
        defer {
            try? FileManager.default.removeItem(at: root)
            defaults.removePersistentDomain(forName: suiteName)
        }

        #expect(AppLaunchPolicy.route(
            arguments: ["cengine", "--opened-by-installer"],
            isTestHost: false,
            defaults: defaults,
            legacyServiceStateURL: root.appending(path: "service-state.json")
        ) == .exitAfterInstallerLaunch)
    }

    @Test func explicitEnginePreferenceControlsInstallerResume() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let stateURL = root.appending(path: "service-state.json")
        let suiteName = "AppLaunchPolicyTests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suiteName))
        defer {
            try? FileManager.default.removeItem(at: root)
            defaults.removePersistentDomain(forName: suiteName)
        }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try JSONEncoder().encode(EngineServiceState(phase: .stopped, message: nil))
            .write(to: stateURL)

        defaults.set(false, forKey: AppPreferenceKeys.engineServiceEnabled)
        #expect(AppLaunchPolicy.route(
            arguments: ["cengine", "--opened-by-installer"],
            isTestHost: false,
            defaults: defaults,
            legacyServiceStateURL: stateURL
        ) == .exitAfterInstallerLaunch)

        defaults.set(true, forKey: AppPreferenceKeys.engineServiceEnabled)
        #expect(AppLaunchPolicy.route(
            arguments: ["cengine", "--opened-by-installer"],
            isTestHost: false,
            defaults: defaults,
            legacyServiceStateURL: root.appending(path: "missing-state.json")
        ) == .launchApplication(migrateLegacyEnginePreference: false))
    }

    @Test func validLegacyServiceStateResumesAndRequestsMigration() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let stateURL = root.appending(path: "service-state.json")
        let suiteName = "AppLaunchPolicyTests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suiteName))
        defer {
            try? FileManager.default.removeItem(at: root)
            defaults.removePersistentDomain(forName: suiteName)
        }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        for phase in [
            EngineServicePhase.starting,
            .running,
            .failed,
            .stopped,
        ] {
            try JSONEncoder().encode(EngineServiceState(phase: phase, message: nil))
                .write(to: stateURL)
            #expect(AppLaunchPolicy.route(
                arguments: ["cengine", "--opened-by-installer"],
                isTestHost: false,
                defaults: defaults,
                legacyServiceStateURL: stateURL
            ) == .launchApplication(migrateLegacyEnginePreference: true))
        }
    }

    @Test func corruptLegacyServiceStateDoesNotResume() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let stateURL = root.appending(path: "service-state.json")
        let suiteName = "AppLaunchPolicyTests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suiteName))
        defer {
            try? FileManager.default.removeItem(at: root)
            defaults.removePersistentDomain(forName: suiteName)
        }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try Data("not-json".utf8).write(to: stateURL)

        #expect(AppLaunchPolicy.route(
            arguments: ["cengine", "--opened-by-installer"],
            isTestHost: false,
            defaults: defaults,
            legacyServiceStateURL: stateURL
        ) == .exitAfterInstallerLaunch)
    }
}

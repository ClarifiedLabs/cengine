import Darwin
import Foundation
import NIOCore
import ServiceManagement
import Testing
import CEngineCore
@testable import CEngineApp

@Suite struct ServiceRegistrationTests {
    @Test func registersServicesMissingFromBackgroundTaskManagement() {
        #expect(CEngineServices.needsRegistration(.notFound))
    }

    @Test func registersExplicitlyUnregisteredServices() {
        #expect(CEngineServices.needsRegistration(.notRegistered))
    }

    @Test func doesNotReregisterKnownServices() {
        #expect(!CEngineServices.needsRegistration(.enabled))
        #expect(!CEngineServices.needsRegistration(.requiresApproval))
    }

    @Test func restartKicksTheRegisteredUserAgent() throws {
        var arguments: [String] = []

        try CEngineServices.restartEngine { arguments = $0 }

        #expect(arguments == ["kickstart", "-k", "gui/\(getuid())/dev.cengine.engine"])
    }

    @MainActor @Test func uninstallStopsShimsAfterEngineAndBeforeNetworkingHelper() async throws {
        let sequence = TeardownSequenceRecorder()
        let agent = MockAppService(
            status: .enabled,
            statusAfterRegistration: .enabled,
            onUnregister: { sequence.record("engine") }
        )
        let helper = MockAppService(
            status: .enabled,
            statusAfterRegistration: .enabled,
            onUnregister: { sequence.record("helper") }
        )

        try await CEngineServices.teardownServices(
            agent: agent,
            helper: helper,
            waitForEngineExit: { sequence.record("engine-exited") },
            stopVirtualMachines: { sequence.record("shims") }
        )

        #expect(sequence.entries == ["engine", "engine-exited", "shims", "helper"])
    }

    @MainActor @Test func uninstallContinuesAfterVMShutdownFailure() async throws {
        enum Failure: Error { case shutdown }
        let sequence = TeardownSequenceRecorder()
        let agent = MockAppService(
            status: .enabled,
            statusAfterRegistration: .enabled,
            onUnregister: { sequence.record("engine") }
        )
        let helper = MockAppService(
            status: .enabled,
            statusAfterRegistration: .enabled,
            onUnregister: { sequence.record("helper") }
        )

        await #expect(throws: EngineError.self) {
            try await CEngineServices.teardownServices(
                agent: agent,
                helper: helper,
                waitForEngineExit: { sequence.record("engine-exited") },
                stopVirtualMachines: {
                    sequence.record("shims")
                    throw Failure.shutdown
                }
            )
        }

        #expect(sequence.entries == ["engine", "engine-exited", "shims", "helper"])
        #expect(helper.unregisterCount == 1)
    }

    @MainActor @Test func headlessUninstallReportsCleanupFailuresWithoutFailing() async {
        enum Failure: Error { case shutdown }

        let warnings = await UninstallSupport.performBestEffortTeardown(
            teardownServices: { throw Failure.shutdown },
            removeDockerIntegration: {
                .contextRemovalFailed("synthetic Docker cleanup failure")
            }
        )

        #expect(warnings.count == 2)
        #expect(warnings[1].contains("synthetic Docker cleanup failure"))
    }

    @MainActor @Test func requiredNetworkingRegistersBeforeEngineAndOpensApprovalFromOnboarding() async {
        let suiteName = "AppModelTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let agent = MockAppService(status: .notFound, statusAfterRegistration: .enabled)
        let helper = MockAppService(
            status: .notFound,
            statusAfterRegistration: .requiresApproval,
            registrationError: NSError(domain: SMAppServiceErrorDomain, code: 1)
        )
        var settingsOpenCount = 0
        let model = AppModel(
            agent: agent,
            helper: helper,
            client: UnavailableEngineClient(),
            serviceRegistrationRevision: nil,
            serviceRegistrationDefaults: defaults,
            openLoginItemsSettings: { settingsOpenCount += 1 }
        )
        defer { model.setActive(false) }

        await model.start()

        #expect(helper.registerCount == 1)
        #expect(agent.registerCount == 0)
        #expect(settingsOpenCount == 0)
        #expect(model.error == nil)
        #expect(model.helperNeedsApproval)
        #expect(model.helperStatus == "Needs approval")

        await model.completeOnboarding()
        #expect(settingsOpenCount == 1)
        #expect(defaults.bool(forKey: AppPreferenceKeys.completedOnboarding))
        #expect(defaults.bool(forKey: AppPreferenceKeys.engineServiceEnabled))
    }

    @MainActor @Test func enabledNetworkingRegistersEngineService() async {
        let home = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let suiteName = "AppModelTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer {
            try? FileManager.default.removeItem(at: home)
            defaults.removePersistentDomain(forName: suiteName)
        }
        let agent = MockAppService(status: .notFound, statusAfterRegistration: .enabled)
        let helper = MockAppService(status: .enabled, statusAfterRegistration: .enabled)
        let model = AppModel(
            home: home,
            agent: agent,
            helper: helper,
            client: UnavailableEngineClient(),
            serviceRegistrationRevision: nil,
            serviceRegistrationDefaults: defaults
        )
        defer { model.setActive(false) }

        await model.start()

        #expect(helper.registerCount == 0)
        #expect(agent.registerCount == 1)
        #expect(model.engineStatus == "Starting…")
        #expect(defaults.bool(forKey: AppPreferenceKeys.engineServiceEnabled))
    }

    @MainActor @Test func disabledStartupRegistersNoServices() async {
        let suiteName = "AppModelTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        defaults.set(false, forKey: AppPreferenceKeys.engineServiceEnabled)
        let agent = MockAppService(status: .notFound, statusAfterRegistration: .enabled)
        let helper = MockAppService(status: .notFound, statusAfterRegistration: .enabled)
        let model = AppModel(
            agent: agent,
            helper: helper,
            client: UnavailableEngineClient(),
            serviceRegistrationRevision: nil,
            serviceRegistrationDefaults: defaults
        )
        defer { model.setActive(false) }

        await model.start()

        #expect(helper.registerCount == 0)
        #expect(agent.registerCount == 0)
        #expect(model.engineStatus == "Disabled")
    }

    @MainActor @Test func registrationFailureWithoutPendingApprovalIsReported() async {
        let suiteName = "AppModelTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let agent = MockAppService(status: .notFound, statusAfterRegistration: .enabled)
        let helper = MockAppService(
            status: .notFound,
            statusAfterRegistration: .notFound,
            registrationError: NSError(domain: SMAppServiceErrorDomain, code: 1)
        )
        var settingsOpenCount = 0
        let model = AppModel(
            agent: agent,
            helper: helper,
            client: UnavailableEngineClient(),
            serviceRegistrationRevision: nil,
            serviceRegistrationDefaults: defaults,
            openLoginItemsSettings: { settingsOpenCount += 1 }
        )
        defer { model.setActive(false) }

        await model.start()

        #expect(settingsOpenCount == 0)
        #expect(agent.registerCount == 0)
        #expect(model.error?.contains("Could not enable required cengine services") == true)
    }

    @MainActor @Test func appUpgradeRefreshesEnabledServiceRegistrations() async {
        let suiteName = "AppModelTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        defaults.set("24", forKey: AppModel.serviceRegistrationRevisionKey)
        var unregistrationWaitCount = 0
        let agent = MockAppService(status: .enabled, statusAfterRegistration: .enabled)
        let helper = MockAppService(status: .enabled, statusAfterRegistration: .enabled)
        let model = AppModel(
            agent: agent,
            helper: helper,
            client: UnavailableEngineClient(),
            serviceRegistrationRevision: "25",
            serviceRegistrationDefaults: defaults,
            waitForServiceUnregistration: { unregistrationWaitCount += 1 },
            stopVirtualMachinesForUpgrade: {}
        )
        defer { model.setActive(false) }

        await model.start()

        #expect(agent.unregisterCount == 1)
        #expect(helper.unregisterCount == 1)
        #expect(helper.registerCount == 1)
        #expect(agent.registerCount == 1)
        #expect(unregistrationWaitCount == 1)
        #expect(defaults.string(forKey: AppModel.serviceRegistrationRevisionKey) == "25")
    }

    @MainActor @Test(arguments: ["engine", "vms", "helper", "settled"])
    func upgradeFencesReentrantLifecycleAndServiceActions(phase: String) async {
        let suiteName = "AppModelTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        defaults.set("24", forKey: AppModel.serviceRegistrationRevisionKey)
        defaults.set(true, forKey: AppModel.engineServiceEnabledKey)
        let sequence = TeardownSequenceRecorder()
        let suspension = ServiceTransitionSuspension()
        let record: (String) async -> Void = { entry in
            sequence.record(entry)
            if entry == phase { await suspension.suspend() }
        }
        let agent = MockAppService(
            status: .enabled,
            statusAfterRegistration: .enabled,
            onRegister: { sequence.record("register-engine") },
            onUnregister: { await record("engine") }
        )
        let helper = MockAppService(
            status: .enabled,
            statusAfterRegistration: .enabled,
            onRegister: { sequence.record("register-helper") },
            onUnregister: { await record("helper") }
        )
        let client = UnavailableEngineClient()
        let model = AppModel(
            agent: agent,
            helper: helper,
            client: client,
            serviceRegistrationRevision: "25",
            serviceRegistrationDefaults: defaults,
            waitForServiceUnregistration: { await record("settled") },
            stopVirtualMachinesForUpgrade: { await record("vms") },
            restartRegisteredEngine: { Issue.record("unexpected engine restart") },
            openLoginItemsSettings: { Issue.record("unexpected approval request") }
        )
        defer { model.setActive(false) }

        // Activation may precede the window's startup task.
        model.setActive(true)
        await model.refresh()
        #expect(await client.requestCount == 0)
        let startup = Task { await model.start() }
        await suspension.waitUntilSuspended()
        let entriesWhileSuspended = sequence.entries

        #expect(model.isManagingEngineService)
        #expect(!model.canRestartEngineService)
        model.setActive(false)
        model.setActive(true)
        await model.refresh()
        await model.start()
        await model.enableEngineService()
        await model.disableEngineService()
        await model.restartEngineService()
        await model.completeOnboarding()
        await Task.yield()

        #expect(sequence.entries == entriesWhileSuspended)
        #expect(agent.registerCount == 0)
        #expect(helper.registerCount == 0)
        #expect(await client.requestCount == 0)
        #expect(defaults.string(forKey: AppModel.serviceRegistrationRevisionKey) == "24")
        #expect(defaults.bool(forKey: AppModel.engineServiceEnabledKey))
        #expect(!defaults.bool(forKey: AppPreferenceKeys.completedOnboarding))
        #expect(model.showOnboarding)

        suspension.resume()
        await startup.value
        await model.start()

        #expect(sequence.entries == ["engine", "vms", "helper", "settled", "register-helper", "register-engine"])
        #expect(defaults.string(forKey: AppModel.serviceRegistrationRevisionKey) == "25")
        #expect(model.engineServiceEnabled)
        #expect(!model.isManagingEngineService)
        #expect(model.error == nil)
    }

    @MainActor @Test(arguments: ["engine", "vms", "helper", "settled", "register-helper", "register-engine"])
    func failedUpgradeStaysFencedUntilExplicitRestartRetry(phase: String) async {
        enum Failure: Error { case upgrade }
        let suiteName = "AppModelTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        defaults.set("24", forKey: AppModel.serviceRegistrationRevisionKey)
        defaults.set(true, forKey: AppModel.engineServiceEnabledKey)
        let sequence = TeardownSequenceRecorder()
        var shouldFail = true
        let record: (String) throws -> Void = { entry in
            sequence.record(entry)
            if shouldFail, entry == phase { throw Failure.upgrade }
        }
        let agent = MockAppService(
            status: .enabled,
            statusAfterRegistration: .enabled,
            onRegister: { try record("register-engine") },
            onUnregister: { try record("engine") }
        )
        let helper = MockAppService(
            status: .enabled,
            statusAfterRegistration: .enabled,
            onRegister: { try record("register-helper") },
            onUnregister: { try record("helper") }
        )
        let client = UnavailableEngineClient()
        let model = AppModel(
            agent: agent,
            helper: helper,
            client: client,
            serviceRegistrationRevision: "25",
            serviceRegistrationDefaults: defaults,
            waitForServiceUnregistration: { try record("settled") },
            stopVirtualMachinesForUpgrade: { try record("vms") },
            restartRegisteredEngine: { Issue.record("retry must redo migration, not kickstart") }
        )
        defer { model.setActive(false) }

        await model.start()
        let fullSequence = ["engine", "vms", "helper", "settled", "register-helper", "register-engine"]
        let failureIndex = fullSequence.firstIndex(of: phase)!
        #expect(sequence.entries == Array(fullSequence.prefix(failureIndex + 1)))
        #expect(defaults.string(forKey: AppModel.serviceRegistrationRevisionKey) == "24")
        #expect(model.error != nil)
        #expect(!model.isManagingEngineService)
        #expect(model.engineServiceEnabled)
        #expect(defaults.bool(forKey: AppModel.engineServiceEnabledKey))
        #expect(model.canRestartEngineService)
        let entriesAfterFailure = sequence.entries

        model.setActive(true)
        await model.refresh()
        await model.start()
        await Task.yield()
        #expect(sequence.entries == entriesAfterFailure)
        #expect(await client.requestCount == 0)
        if phase == "engine" || phase == "vms" {
            #expect(helper.unregisterCount == 0)
            #expect(helper.status == .enabled)
        }

        shouldFail = false
        await model.restartEngineService()

        #expect(sequence.entries.filter { $0 == "vms" }.count == (phase == "engine" ? 1 : 2))
        #expect(sequence.entries.suffix(2) == ["register-helper", "register-engine"])
        #expect(defaults.string(forKey: AppModel.serviceRegistrationRevisionKey) == "25")
        #expect(defaults.bool(forKey: AppModel.engineServiceEnabledKey))
        #expect(agent.status == .enabled)
        #expect(helper.status == .enabled)
        #expect(model.error == nil)
    }

    @MainActor @Test(arguments: [true, false], [nil, "24"] as [String?])
    func upgradeStopsOrphanedVMsWithoutChangingEnabledPreference(enabled: Bool, previousRevision: String?) async {
        let suiteName = "AppModelTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        defaults.set(previousRevision, forKey: AppModel.serviceRegistrationRevisionKey)
        defaults.set(enabled, forKey: AppModel.engineServiceEnabledKey)
        let sequence = TeardownSequenceRecorder()
        let agent = MockAppService(status: .notFound, statusAfterRegistration: .enabled)
        let helper = MockAppService(status: .notFound, statusAfterRegistration: .enabled)
        let model = AppModel(
            agent: agent,
            helper: helper,
            client: UnavailableEngineClient(),
            serviceRegistrationRevision: "25",
            serviceRegistrationDefaults: defaults,
            waitForServiceUnregistration: { Issue.record("no registrations to settle") },
            stopVirtualMachinesForUpgrade: { sequence.record("vms") }
        )
        defer { model.setActive(false) }

        await model.start()
        await model.refresh()

        #expect(sequence.entries == ["vms"])
        #expect(agent.unregisterCount == 0)
        #expect(helper.unregisterCount == 0)
        #expect(agent.registerCount == (enabled ? 1 : 0))
        #expect(helper.registerCount == (enabled ? 1 : 0))
        #expect(model.engineServiceEnabled == enabled)
        #expect(defaults.bool(forKey: AppModel.engineServiceEnabledKey) == enabled)
        #expect(defaults.string(forKey: AppModel.serviceRegistrationRevisionKey) == "25")
        #expect(model.showOnboarding)
    }

    @MainActor @Test(arguments: ["enable", "onboarding"])
    func explicitEnablePathsRetryPendingUpgrade(action: String) async {
        enum Failure: Error { case shutdown }
        let suiteName = "AppModelTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        defaults.set("24", forKey: AppModel.serviceRegistrationRevisionKey)
        defaults.set(false, forKey: AppModel.engineServiceEnabledKey)
        let agent = MockAppService(status: .notFound, statusAfterRegistration: .enabled)
        let helper = MockAppService(status: .notFound, statusAfterRegistration: .enabled)
        var shutdownCount = 0
        let model = AppModel(
            agent: agent,
            helper: helper,
            client: UnavailableEngineClient(),
            serviceRegistrationRevision: "25",
            serviceRegistrationDefaults: defaults,
            waitForServiceUnregistration: { Issue.record("no registrations to settle") },
            stopVirtualMachinesForUpgrade: {
                shutdownCount += 1
                if shutdownCount == 1 { throw Failure.shutdown }
            }
        )
        defer { model.setActive(false) }

        await model.start()
        #expect(defaults.string(forKey: AppModel.serviceRegistrationRevisionKey) == "24")
        #expect(!model.engineServiceEnabled)
        #expect(!defaults.bool(forKey: AppModel.engineServiceEnabledKey))
        #expect(agent.registerCount == 0)
        #expect(helper.registerCount == 0)

        if action == "enable" {
            await model.enableEngineService()
        } else {
            await model.completeOnboarding()
        }

        #expect(shutdownCount == 2)
        #expect(agent.registerCount == 1)
        #expect(helper.registerCount == 1)
        #expect(model.engineServiceEnabled)
        #expect(defaults.bool(forKey: AppModel.engineServiceEnabledKey))
        #expect(defaults.string(forKey: AppModel.serviceRegistrationRevisionKey) == "25")
        #expect(defaults.bool(forKey: AppPreferenceKeys.completedOnboarding) == (action == "onboarding"))
        #expect(model.error == nil)
    }

    @MainActor @Test func currentAppBuildKeepsEnabledServiceRegistrations() async {
        let suiteName = "AppModelTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        defaults.set("25", forKey: AppModel.serviceRegistrationRevisionKey)
        let agent = MockAppService(status: .enabled, statusAfterRegistration: .enabled)
        let helper = MockAppService(status: .enabled, statusAfterRegistration: .enabled)
        let model = AppModel(
            agent: agent,
            helper: helper,
            client: UnavailableEngineClient(),
            serviceRegistrationRevision: "25",
            serviceRegistrationDefaults: defaults,
            waitForServiceUnregistration: { Issue.record("unexpected registration delay") },
            stopVirtualMachinesForUpgrade: { Issue.record("unexpected VM shutdown") }
        )
        defer { model.setActive(false) }

        await model.start()

        #expect(agent.unregisterCount == 0)
        #expect(helper.unregisterCount == 0)
        #expect(agent.registerCount == 0)
        #expect(helper.registerCount == 0)
    }

    @MainActor @Test func explicitlyDisabledEngineIsNotReregisteredByRefresh() async {
        let home = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let suiteName = "AppModelTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let agent = MockAppService(status: .enabled, statusAfterRegistration: .enabled)
        let helper = MockAppService(status: .enabled, statusAfterRegistration: .enabled)
        let model = AppModel(
            home: home,
            agent: agent,
            helper: helper,
            client: UnavailableEngineClient(),
            serviceRegistrationRevision: nil,
            serviceRegistrationDefaults: defaults
        )

        await model.disableEngineService()
        await model.refresh()

        #expect(agent.unregisterCount == 1)
        #expect(agent.registerCount == 0)
        #expect(model.engineStatus == "Disabled")
        #expect(defaults.bool(forKey: AppModel.engineServiceEnabledKey) == false)

        await model.enableEngineService()

        #expect(agent.registerCount == 1)
        #expect(model.engineStatus == "Starting…")
        #expect(defaults.bool(forKey: AppModel.engineServiceEnabledKey))
    }

    @MainActor @Test func restartUsesLaunchctlController() async {
        let suiteName = "AppModelTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let recorder = RestartRecorder()
        let agent = MockAppService(status: .enabled, statusAfterRegistration: .enabled)
        let helper = MockAppService(status: .enabled, statusAfterRegistration: .enabled)
        let model = AppModel(
            agent: agent,
            helper: helper,
            client: UnavailableEngineClient(),
            serviceRegistrationRevision: nil,
            serviceRegistrationDefaults: defaults,
            restartRegisteredEngine: { await recorder.record() }
        )

        await model.restartEngineService()

        #expect(await recorder.count == 1)
        #expect(model.engineStatus == "Starting…")
        #expect(model.engineServiceActionStatus == "Restart requested")
    }
}

private actor RestartRecorder {
    private(set) var count = 0
    func record() { count += 1 }
}

@Suite struct UserDataPurgeTests {
    @Test func removesEngineResourcesLogsAndAppState() throws {
        let home = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let suiteName = "UserDataPurgeTests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suiteName))
        defer {
            try? FileManager.default.removeItem(at: home)
            defaults.removePersistentDomain(forName: suiteName)
        }
        let expectedRelativePaths = [
            ".cengine",
            "Library/Application Support/cengine",
            "Library/Caches/dev.cengine.app",
            "Library/Logs/cengine",
            "Library/Preferences/dev.cengine.app.plist",
            "Library/Saved Application State/dev.cengine.app.savedState",
        ]
        #expect(CEngineUserData.relativePaths == expectedRelativePaths)

        let locations = CEngineUserData.locations(home: home)
        for location in locations {
            try FileManager.default.createDirectory(at: location, withIntermediateDirectories: true)
            try Data("owned by cengine".utf8).write(to: location.appending(path: "marker"))
        }
        defaults.set(true, forKey: AppPreferenceKeys.completedOnboarding)

        try CEngineUserData.removeAll(
            home: home,
            defaults: defaults,
            preferencesDomain: suiteName
        )

        #expect(locations.allSatisfy { !FileManager.default.fileExists(atPath: $0.path) })
        #expect(defaults.object(forKey: AppPreferenceKeys.completedOnboarding) == nil)
    }
}

@MainActor private final class MockAppService: AppService {
    var status: SMAppService.Status
    let statusAfterRegistration: SMAppService.Status
    let registrationError: Error?
    let onRegister: (() throws -> Void)?
    let onUnregister: (() async throws -> Void)?
    var registerCount = 0
    var unregisterCount = 0

    init(
        status: SMAppService.Status,
        statusAfterRegistration: SMAppService.Status,
        registrationError: Error? = nil,
        onRegister: (() throws -> Void)? = nil,
        onUnregister: (() async throws -> Void)? = nil
    ) {
        self.status = status
        self.statusAfterRegistration = statusAfterRegistration
        self.registrationError = registrationError
        self.onRegister = onRegister
        self.onUnregister = onUnregister
    }

    func register() throws {
        registerCount += 1
        try onRegister?()
        status = statusAfterRegistration
        if let registrationError { throw registrationError }
    }

    func unregister() async throws {
        unregisterCount += 1
        status = .notRegistered
        try await onUnregister?()
    }
}

@MainActor private final class ServiceTransitionSuspension {
    private var suspended = false
    private var entered: CheckedContinuation<Void, Never>?
    private var release: CheckedContinuation<Void, Never>?

    func suspend() async {
        await withCheckedContinuation { continuation in
            release = continuation
            suspended = true
            entered?.resume()
            entered = nil
        }
    }

    func waitUntilSuspended() async {
        if suspended { return }
        await withCheckedContinuation { entered = $0 }
    }

    func resume() {
        release?.resume()
        release = nil
    }
}

@MainActor private final class TeardownSequenceRecorder {
    private(set) var entries: [String] = []
    func record(_ value: String) { entries.append(value) }
}

@Suite struct EngineAvailabilityTests {
    @MainActor @Test func loadsSharedBuilderSettings() throws {
        let home = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let paths = EnginePaths(home: home)
        try BuilderSettings(cpus: 2, memoryGiB: 1).save(to: paths.builderSettings)
        try ContainerSettings(cpus: 2, memoryGiB: 1).save(to: paths.containerSettings)

        let model = AppModel(home: home)

        #expect(model.builderCPUs == 2)
        #expect(model.builderMemoryGiB == 1)
        #expect(model.containerCPUs == 2)
        #expect(model.containerMemoryGiB == 1)

        model.containerCPUs = 1
        model.applyContainerSettings()
        #expect(try ContainerSettings.load(from: paths.containerSettings).cpus == 1)
        #expect(model.containerSettingsStatus == "Saved; applies to new containers")
    }

    @Test func missingSocketMeansEngineIsStillStarting() {
        let path = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString).path
        #expect(AppModel.isEngineUnavailable(DashboardError("connect failed"), socketPath: path))
    }

    @Test func connectionFailuresOnExistingSocketMeanEngineIsStillStarting() throws {
        let url = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try Data().write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        #expect(AppModel.isEngineUnavailable(IOError(errnoCode: ECONNREFUSED, reason: "connect"), socketPath: url.path))
        #expect(AppModel.isEngineUnavailable(IOError(errnoCode: ENOENT, reason: "connect"), socketPath: url.path))
    }

    @Test func apiFailuresOnExistingSocketSurfaceAsErrors() throws {
        let url = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try Data().write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        #expect(!AppModel.isEngineUnavailable(DashboardError("Docker API returned HTTP 500"), socketPath: url.path))
        #expect(!AppModel.isEngineUnavailable(IOError(errnoCode: EPIPE, reason: "write"), socketPath: url.path))
    }

    @MainActor @Test func failedServiceStateIsSurfacedWhenSocketIsMissing() async throws {
        let home = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let suiteName = "AppModelTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer {
            try? FileManager.default.removeItem(at: home)
            defaults.removePersistentDomain(forName: suiteName)
        }
        let paths = EnginePaths(home: home)
        try paths.createDirectories()
        let state = EngineServiceState(
            phase: .failed,
            message: "state file is incompatible: missing required field 'imageID'",
            updatedAt: Date()
        )
        try JSONEncoder().encode(state).write(to: paths.serviceState)
        let agent = MockAppService(status: .enabled, statusAfterRegistration: .enabled)
        let helper = MockAppService(status: .enabled, statusAfterRegistration: .enabled)
        let model = AppModel(
            home: home,
            agent: agent,
            helper: helper,
            client: UnavailableEngineClient(),
            serviceRegistrationRevision: nil,
            serviceRegistrationDefaults: defaults
        )

        await model.refresh()

        #expect(model.engineStatus == "Failed")
        #expect(model.refreshError == "Engine failed to start: state file is incompatible: missing required field 'imageID'")
        #expect(model.engineServiceState?.phase == .failed)
    }
}

private actor UnavailableEngineClient: AppEngineClient {
    private(set) var requestCount = 0
    func get(_: String) async throws -> Data {
        requestCount += 1
        throw DashboardError("unavailable")
    }
    func post(_: String, body _: Data) async throws -> Data { throw DashboardError("unavailable") }
}

@MainActor @Suite struct OnboardingViewTests {
    @Test func enablingVMNetworkingCompletesOnboarding() async {
        var completed = false
        let view = OnboardingView { completed = true }

        await view.complete()

        #expect(completed)
    }
}

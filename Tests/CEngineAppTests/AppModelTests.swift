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

    @MainActor @Test func requiredNetworkingRegistersBeforeEngineAndOpensApprovalFromOnboarding() async {
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
            serviceRegistrationRevision: nil,
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
    }

    @MainActor @Test func enabledNetworkingRegistersEngineService() async {
        let home = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let agent = MockAppService(status: .notFound, statusAfterRegistration: .enabled)
        let helper = MockAppService(status: .enabled, statusAfterRegistration: .enabled)
        let model = AppModel(home: home, agent: agent, helper: helper, serviceRegistrationRevision: nil)
        defer { model.setActive(false) }

        await model.start()

        #expect(helper.registerCount == 0)
        #expect(agent.registerCount == 1)
        #expect(model.engineStatus == "Starting…")
    }

    @MainActor @Test func registrationFailureWithoutPendingApprovalIsReported() async {
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
            serviceRegistrationRevision: nil,
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
            serviceRegistrationRevision: "25",
            serviceRegistrationDefaults: defaults,
            waitForServiceUnregistration: { unregistrationWaitCount += 1 }
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
            serviceRegistrationRevision: "25",
            serviceRegistrationDefaults: defaults,
            waitForServiceUnregistration: { Issue.record("unexpected registration delay") }
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
        let recorder = RestartRecorder()
        let agent = MockAppService(status: .enabled, statusAfterRegistration: .enabled)
        let helper = MockAppService(status: .enabled, statusAfterRegistration: .enabled)
        let model = AppModel(
            agent: agent,
            helper: helper,
            serviceRegistrationRevision: nil,
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

@MainActor private final class MockAppService: AppService {
    var status: SMAppService.Status
    let statusAfterRegistration: SMAppService.Status
    let registrationError: Error?
    var registerCount = 0
    var unregisterCount = 0

    init(
        status: SMAppService.Status,
        statusAfterRegistration: SMAppService.Status,
        registrationError: Error? = nil
    ) {
        self.status = status
        self.statusAfterRegistration = statusAfterRegistration
        self.registrationError = registrationError
    }

    func register() throws {
        registerCount += 1
        status = statusAfterRegistration
        if let registrationError { throw registrationError }
    }

    func unregister() async throws {
        unregisterCount += 1
        status = .notRegistered
    }
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
        defer { try? FileManager.default.removeItem(at: home) }
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
            serviceRegistrationRevision: nil
        )

        await model.refresh()

        #expect(model.engineStatus == "Failed")
        #expect(model.refreshError == "Engine failed to start: state file is incompatible: missing required field 'imageID'")
        #expect(model.engineServiceState?.phase == .failed)
    }
}

private actor UnavailableEngineClient: AppEngineClient {
    func get(_: String) async throws -> Data { throw DashboardError("unavailable") }
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

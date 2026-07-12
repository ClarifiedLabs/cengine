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

    @MainActor @Test func launchDeniedRegistrationOpensApprovalSettingsWithoutAnError() async {
        let helper = MockAppService(
            status: .notFound,
            statusAfterRegistration: .requiresApproval,
            registrationError: NSError(domain: SMAppServiceErrorDomain, code: 1)
        )
        var settingsOpenCount = 0
        let model = AppModel(helper: helper) { settingsOpenCount += 1 }

        await model.setHelperEnabled(true)

        #expect(helper.registerCount == 1)
        #expect(settingsOpenCount == 1)
        #expect(model.error == nil)
        #expect(model.helperNeedsApproval)
        #expect(model.helperStatus == "Needs approval")
    }

    @MainActor @Test func registrationFailureWithoutPendingApprovalIsReported() async {
        let helper = MockAppService(
            status: .notFound,
            statusAfterRegistration: .notFound,
            registrationError: NSError(domain: SMAppServiceErrorDomain, code: 1)
        )
        var settingsOpenCount = 0
        let model = AppModel(helper: helper) { settingsOpenCount += 1 }

        await model.setHelperEnabled(true)

        #expect(settingsOpenCount == 0)
        #expect(model.error?.contains("Could not update privileged-port support") == true)
    }
}

@MainActor private final class MockAppService: AppService {
    var status: SMAppService.Status
    let statusAfterRegistration: SMAppService.Status
    let registrationError: Error?
    var registerCount = 0

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
}

@MainActor @Suite struct OnboardingViewTests {
    @Test func enablingPrivilegedPortsCompletesOnboardingWithHelperEnabled() async {
        var requestedHelperState: Bool?
        let view = OnboardingView { requestedHelperState = $0 }

        await view.complete(enableHelper: true)

        #expect(requestedHelperState == true)
    }
}

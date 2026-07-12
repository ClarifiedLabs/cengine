import Foundation
import NIOCore
import ServiceManagement
import Testing
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
}

@Suite struct EngineAvailabilityTests {
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

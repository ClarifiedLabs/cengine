import CEngineCore
import Testing
@testable import CEngineApp

@MainActor @Suite struct UpgradeUninstallTests {
    @Test func headlessUninstallQuitsGUIBeforeRemovingServices() async {
        var steps: [String] = []
        let warnings = await UninstallSupport.performHeadlessTeardown(
            quitApplication: { steps.append("quit") },
            teardown: { steps.append("teardown"); return ["cleanup warning"] }
        )
        #expect(steps == ["quit", "teardown"])
        #expect(warnings == ["cleanup warning"])
    }

    @Test func headlessUninstallDoesNotRaceGUIThatCannotQuit() async {
        let warnings = await UninstallSupport.performHeadlessTeardown(
            quitApplication: { throw EngineError(.conflict, "app is still running") },
            teardown: { Issue.record("must not unregister services while app can respawn them"); return [] }
        )
        #expect(warnings.count == 1)
        #expect(warnings.first?.contains("app is still running") == true)
    }
}

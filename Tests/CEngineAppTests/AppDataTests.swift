import AppKit
import Foundation
import ServiceManagement
import SwiftUI
import Testing
@testable import CEngineApp

@Suite struct AppDataTests {
    @Test func parsesMultiplexedStdoutAndStderrLogs() {
        var data = frame(stream: 1, "2026-07-14T10:00:00Z hello\n")
        data.append(frame(stream: 2, "2026-07-14T10:00:01Z warning\n"))

        let lines = DockerLogParser.parse(data, tty: false)

        #expect(lines.map(\.stream) == [.stdout, .stderr])
        #expect(lines.map(\.text) == [
            "2026-07-14T10:00:00Z hello",
            "2026-07-14T10:00:01Z warning",
        ])
    }

    @Test func parsesTTYLogsAndBoundsTheTail() {
        let data = Data("one\ntwo\nthree\n".utf8)

        let lines = DockerLogParser.parse(data, tty: true, limit: 2)

        #expect(lines.map(\.stream) == [.terminal, .terminal])
        #expect(lines.map(\.text) == ["two", "three"])
    }

    @Test func keepsCompleteFramesBeforeMalformedTrailingData() {
        var data = frame(stream: 1, "complete\n")
        data.append(Data([2, 0, 0, 0, 0, 0, 0, 40, 1, 2]))

        let lines = DockerLogParser.parse(data, tty: false)

        #expect(lines.map(\.text) == ["complete"])
    }

    @Test func calculatesTelemetryFromConsecutiveSamples() throws {
        let previous = try JSONDecoder().decode(ContainerStatsSample.self, from: statsJSON(
            read: "2026-07-14T10:00:00.000Z",
            cpu: 1_000_000_000,
            memory: 256,
            readBytes: 10,
            writeBytes: 20,
            receiveBytes: 30,
            transmitBytes: 40
        ))
        let current = try JSONDecoder().decode(ContainerStatsSample.self, from: statsJSON(
            read: "2026-07-14T10:00:01.000Z",
            cpu: 2_000_000_000,
            memory: 512,
            readBytes: 110,
            writeBytes: 220,
            receiveBytes: 330,
            transmitBytes: 440
        ))

        let telemetry = ContainerTelemetry(sample: current, previous: previous)

        #expect(telemetry.cpuPercentage == 100)
        #expect(telemetry.memoryUsage == 512)
        #expect(telemetry.memoryLimit == 1_024)
        #expect(telemetry.pids == 3)
        #expect(telemetry.blockReadBytes == 110)
        #expect(telemetry.blockWriteBytes == 220)
        #expect(telemetry.networkReceiveBytes == 330)
        #expect(telemetry.networkTransmitBytes == 440)
    }

    @Test func validatesTypedResourceSettings() {
        #expect(AppModel.validationMessage(
            cpus: 4,
            memoryGiB: 8,
            maximumCPUs: 12,
            maximumMemoryGiB: 32
        ) == nil)
        #expect(AppModel.validationMessage(
            cpus: 0,
            memoryGiB: 8,
            maximumCPUs: 12,
            maximumMemoryGiB: 32
        ) == "CPUs must be between 1 and 12.")
        #expect(AppModel.validationMessage(
            cpus: 4,
            memoryGiB: 33,
            maximumCPUs: 12,
            maximumMemoryGiB: 32
        ) == "Memory must be between 1 and 32 GiB.")
    }

    private func frame(stream: UInt8, _ value: String) -> Data {
        let payload = Data(value.utf8)
        var result = Data([stream, 0, 0, 0])
        var count = UInt32(payload.count).bigEndian
        withUnsafeBytes(of: &count) { result.append(contentsOf: $0) }
        result.append(payload)
        return result
    }

    private func statsJSON(
        read: String,
        cpu: UInt64,
        memory: UInt64,
        readBytes: UInt64,
        writeBytes: UInt64,
        receiveBytes: UInt64,
        transmitBytes: UInt64
    ) -> Data {
        Data("""
        {
          "read":"\(read)",
          "pids_stats":{"current":3},
          "blkio_stats":{"io_service_bytes_recursive":[
            {"op":"Read","value":\(readBytes)},
            {"op":"Write","value":\(writeBytes)}
          ]},
          "cpu_stats":{"cpu_usage":{"total_usage":\(cpu)},"online_cpus":4},
          "memory_stats":{"usage":\(memory),"limit":1024},
          "networks":{"default":{"rx_bytes":\(receiveBytes),"tx_bytes":\(transmitBytes)}}
        }
        """.utf8)
    }
}

@MainActor @Suite struct AppModelDashboardTests {
    @Test func comparesReleaseVersionsNumerically() {
        #expect(AppModel.isVersion("0.0.34", olderThan: "0.0.35"))
        #expect(AppModel.isVersion("0.9.9", olderThan: "0.10.0"))
        #expect(!AppModel.isVersion("0.0.35", olderThan: "0.0.35"))
        #expect(!AppModel.isVersion("0.0.36", olderThan: "0.0.35"))
        #expect(!AppModel.isVersion("development", olderThan: "0.0.35"))
    }

    @Test func refreshesTypedSnapshotAndPostsContainerLifecycleAction() async throws {
        let client = MockEngineClient(responses: Self.responses)
        let agent = DashboardMockAppService(status: .enabled)
        let helper = DashboardMockAppService(status: .enabled)
        let home = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let suiteName = "AppDataTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer {
            try? FileManager.default.removeItem(at: home)
            defaults.removePersistentDomain(forName: suiteName)
        }
        let model = AppModel(
            home: home,
            agent: agent,
            helper: helper,
            client: client,
            serviceRegistrationRevision: nil,
            serviceRegistrationDefaults: defaults
        )

        await model.refresh()

        #expect(model.snapshot?.version.Version == "0.1.0")
        #expect(model.containers.map(\.name) == ["web"])
        #expect(model.images.first?.primaryReference == "demo:latest")
        #expect(model.networks.first?.modeDisplay == "NAT")
        #expect(model.volumes.first?.virtualCapacity == 536_870_912_000)
        #expect(model.containersAttached(to: model.networks[0]).map(\.id) == ["container-1"])

        await model.perform(.start, on: "container-1")
        await model.loadVolumeConsumers("data")

        #expect(await client.postedPaths() == ["/v1.55/containers/container-1/start"])
        #expect(model.containerDetails["container-1"]?.Config.Hostname == "web")
        #expect(model.volumeConsumerIDs["data"] == ["container-1"])

        await client.failRequests()
        await model.refresh()

        #expect(model.snapshotIsStale)
        #expect(model.snapshot?.version.Version == "0.1.0")
    }

    @Test func olderRunningEngineIsFlaggedForDashboardRestart() async {
        let client = MockEngineClient(responses: Self.responses)
        let agent = DashboardMockAppService(status: .enabled)
        let helper = DashboardMockAppService(status: .enabled)
        let home = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let suiteName = "AppDataTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer {
            try? FileManager.default.removeItem(at: home)
            defaults.removePersistentDomain(forName: suiteName)
        }
        let model = AppModel(
            home: home,
            agent: agent,
            helper: helper,
            client: client,
            appVersion: "0.2.0",
            serviceRegistrationRevision: nil,
            serviceRegistrationDefaults: defaults
        )
        await model.refresh()

        #expect(model.isRunningEngineOutdated)
        #expect(model.canRestartEngineService)
    }

    @Test func invalidSettingsRemainDirtyAndAreNotSaved() throws {
        let home = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let model = AppModel(home: home, serviceRegistrationRevision: nil)
        model.containerCPUs = 0

        model.applyContainerSettings()

        #expect(model.containerSettingsDirty)
        #expect(model.containerSettingsStatus == nil)
    }

    @Test func settingsViewLeftAlignsEqualWidthSections() throws {
        let home = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let model = AppModel(home: home, serviceRegistrationRevision: nil)
        var sectionFrames: [CGRect] = []
        let root = SettingsView { sectionFrames = $0 }
            .environmentObject(model)
            .frame(width: 900, height: 900)
        let hostingView = NSHostingView(rootView: root)
        hostingView.frame = NSRect(x: 0, y: 0, width: 900, height: 900)
        hostingView.layoutSubtreeIfNeeded()
        hostingView.displayIfNeeded()

        #expect(hostingView.fittingSize.width <= 900)
        #expect(hostingView.fittingSize.height <= 900)
        #expect(sectionFrames.count == 5)
        let firstSectionFrame = try #require(sectionFrames.first)
        #expect(abs(firstSectionFrame.minX - AppLayout.pagePadding) < 1)
        #expect(sectionFrames.allSatisfy { abs($0.minX - firstSectionFrame.minX) < 1 })
        #expect(sectionFrames.allSatisfy { abs($0.width - firstSectionFrame.width) < 1 })
    }

    @Test func settingsResourceFieldsAlignEditableControls() throws {
        let root = ResourceSettingsFields(
            cpus: .constant(4),
            memoryGiB: .constant(8),
            maximumCPUs: 12,
            maximumMemoryGiB: 32,
            accessibilityIdentifierPrefix: "test"
        )
            .frame(width: 400, height: 120, alignment: .topLeading)
        let hostingView = NSHostingView(rootView: root)
        hostingView.frame = NSRect(x: 0, y: 0, width: 400, height: 120)
        hostingView.layoutSubtreeIfNeeded()
        hostingView.displayIfNeeded()

        let textFieldFrames = allTextFields(in: hostingView)
            .filter(\.isEditable)
            .map { $0.convert($0.bounds, to: hostingView) }
        #expect(textFieldFrames.count == 2)
        let firstTextFieldFrame = try #require(textFieldFrames.first)
        #expect(textFieldFrames.allSatisfy { abs($0.minX - firstTextFieldFrame.minX) < 1 })

        let stepperFrames = allSteppers(in: hostingView)
            .map { $0.convert($0.bounds, to: hostingView) }
        #expect(stepperFrames.count == 2)
        let firstStepperFrame = try #require(stepperFrames.first)
        #expect(stepperFrames.allSatisfy { abs($0.minX - firstStepperFrame.minX) < 1 })
    }

    @Test func sidebarWidthIsStableWhenResourceSearchIsVisible() throws {
        let home = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let model = AppModel(home: home, serviceRegistrationRevision: nil)
        let navigation = SidebarLayoutTestNavigation()
        let root = SidebarLayoutTestView(navigation: navigation)
            .environmentObject(model)
            .frame(width: 1_100, height: 720)
        let hostingView = NSHostingView(rootView: root)
        hostingView.frame = NSRect(x: 0, y: 0, width: 1_100, height: 720)
        hostingView.layoutSubtreeIfNeeded()
        hostingView.displayIfNeeded()
        let splitView = try #require(allSplitViews(in: hostingView).first)
        let dashboardWidth = try #require(splitView.arrangedSubviews.first).frame.width

        navigation.section = .containers
        RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.05))
        hostingView.layoutSubtreeIfNeeded()
        hostingView.displayIfNeeded()
        let containersWidth = try #require(splitView.arrangedSubviews.first).frame.width

        #expect(dashboardWidth >= AppLayout.sidebarWidth)
        #expect(dashboardWidth <= AppLayout.maximumSidebarWidth)
        #expect(abs(containersWidth - dashboardWidth) < 1)
    }

    @Test func containersViewFillsAvailableHeightWithoutSelection() async throws {
        let client = MockEngineClient(responses: Self.responses)
        let home = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let model = AppModel(
            home: home,
            client: client,
            serviceRegistrationRevision: nil
        )
        await model.refresh()
        let root = NavigationSplitView {
            Text("Sidebar")
                .navigationSplitViewColumnWidth(180)
        } detail: {
            ContainersView(selection: .constant(nil))
        }
            .environmentObject(model)
            .frame(width: 1_000, height: 700)
        let hostingView = NSHostingView(rootView: root)
        hostingView.frame = NSRect(x: 0, y: 0, width: 1_000, height: 700)
        hostingView.layoutSubtreeIfNeeded()

        let splitViews = allSplitViews(in: hostingView)
        #expect(splitViews.count == 2)
        let resourceSplitView = try #require(splitViews.last)
        #expect(resourceSplitView.frame.height == 700)
    }

    @Test func emptyContainersViewKeepsHeaderAtTop() throws {
        let home = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let model = AppModel(
            home: home,
            serviceRegistrationRevision: nil
        )
        let root = NavigationSplitView {
            Text("Sidebar")
                .navigationSplitViewColumnWidth(180)
        } detail: {
            ContainersView(selection: .constant(nil))
        }
            .environmentObject(model)
            .frame(width: 1_000, height: 700)
        let hostingView = NSHostingView(rootView: root)
        hostingView.frame = NSRect(x: 0, y: 0, width: 1_000, height: 700)
        hostingView.layoutSubtreeIfNeeded()

        let splitViews = allSplitViews(in: hostingView)
        #expect(splitViews.count == 2)
        let resourceSplitView = try #require(splitViews.last)
        #expect(resourceSplitView.frame.height == 700)
        let listPane = try #require(resourceSplitView.subviews.first)
        let refreshButton = try #require(allButtons(in: listPane).first)
        let buttonFrame = refreshButton.convert(refreshButton.bounds, to: resourceSplitView)
        #expect(buttonFrame.midY < resourceSplitView.bounds.height / 4)
    }

    private static let responses: [String: Data] = [
        "/v1.55/version": Data("""
        {"Version":"0.1.0","ApiVersion":"1.55","GitCommit":"abc123","BuildTime":"2026-07-14T10:00:00Z","Os":"linux","Arch":"arm64","KernelVersion":"6.18"}
        """.utf8),
        "/v1.55/info": Data("""
        {"Containers":1,"ContainersRunning":0,"ContainersPaused":0,"ContainersStopped":1,"Driver":"cengine-raw-vm","DockerRootDir":"/tmp/cengine","Name":"test-mac","ServerVersion":"0.1.0","OperatingSystem":"macOS / cengine","Architecture":"arm64","NCPU":8,"MemTotal":17179869184}
        """.utf8),
        "/v1.55/containers/json?all=1": Data("""
        [{"Id":"container-1","Names":["/web"],"Image":"demo:latest","Command":"server","Created":1784023200,"State":"exited","Status":"Exited","Ports":[],"Labels":{"com.example":"demo"},"NetworkSettings":{"Networks":{"default":{"NetworkID":"network-1"}}},"Health":null}]
        """.utf8),
        "/v1.55/images/json": Data("""
        [{"Id":"sha256:image-1","RepoTags":["demo:latest"],"RepoDigests":[],"Containers":1,"Created":1784023200,"Size":1048576,"Labels":{}}]
        """.utf8),
        "/v1.55/networks": Data("""
        [{"Name":"default","Id":"network-1","Created":"2026-07-14T10:00:00Z","Scope":"local","Driver":"bridge","EnableIPv6":true,"IPAM":{"Driver":"default","Config":[{"Subnet":"192.168.64.0/24","Gateway":"192.168.64.1"}]},"Internal":false,"Options":{},"Labels":{}}]
        """.utf8),
        "/v1.55/system/df?verbose=true": Data("""
        {"LayersSize":1048576,"Volumes":[{"Name":"data","Driver":"local","Mountpoint":"cengine://volumes/data","CreatedAt":"2026-07-14T10:00:00Z","Labels":{},"Scope":"local","Options":{},"UsageData":{"RefCount":1,"Size":536870912000}}]}
        """.utf8),
        "/v1.55/containers/container-1/json": Data("""
        {"Id":"container-1","Name":"/web","Created":"2026-07-14T10:00:00Z","Path":"server","Args":[],"Image":"demo:latest","State":{"Status":"exited","Running":false,"Paused":false,"OOMKilled":false,"Dead":false,"ExitCode":0,"Error":"","StartedAt":"2026-07-14T10:00:01Z","FinishedAt":"2026-07-14T10:00:02Z"},"Config":{"Hostname":"web","User":"","Tty":false,"Env":[],"Cmd":["server"],"Image":"demo:latest","WorkingDir":"/","Labels":{}},"RestartCount":0,"NetworkSettings":{"Networks":{}},"HostConfig":{"Memory":1073741824,"NanoCpus":4000000000,"AutoRemove":false,"Privileged":false,"ReadonlyRootfs":false,"Init":false,"RestartPolicy":{"Name":"no","MaximumRetryCount":0},"NetworkMode":"default"},"Mounts":[{"Type":"volume","Name":"data","Source":"data","Destination":"/data","Driver":"local","RW":true}]}
        """.utf8),
    ]
}

@MainActor private final class SidebarLayoutTestNavigation: ObservableObject {
    @Published var section: AppSection? = .dashboard
}

private struct SidebarLayoutTestView: View {
    @ObservedObject var navigation: SidebarLayoutTestNavigation

    var body: some View {
        NavigationSplitView {
            AppSidebar(selection: $navigation.section)
        } detail: {
            switch navigation.section {
            case .containers:
                ContainersView(selection: .constant(nil))
            default:
                DashboardView(navigation: AppNavigation())
            }
        }
    }
}

@MainActor private func allTextFields(in view: NSView) -> [NSTextField] {
    let current = (view as? NSTextField).map { [$0] } ?? []
    return current + view.subviews.flatMap(allTextFields)
}

@MainActor private func allSteppers(in view: NSView) -> [NSStepper] {
    let current = (view as? NSStepper).map { [$0] } ?? []
    return current + view.subviews.flatMap(allSteppers)
}

@MainActor private func allButtons(in view: NSView) -> [NSButton] {
    let current = (view as? NSButton).map { [$0] } ?? []
    return current + view.subviews.flatMap(allButtons)
}

@MainActor private func allSplitViews(in view: NSView) -> [NSSplitView] {
    let current = (view as? NSSplitView).map { [$0] } ?? []
    return current + view.subviews.flatMap(allSplitViews)
}

private actor MockEngineClient: AppEngineClient {
    private let responses: [String: Data]
    private var posts: [String] = []
    private var failing = false

    init(responses: [String: Data]) {
        self.responses = responses
    }

    func get(_ path: String) async throws -> Data {
        if failing { throw DashboardError("engine unavailable") }
        guard let data = responses[path] else { throw DashboardError("No fixture for \(path)") }
        return data
    }

    func post(_ path: String, body _: Data) async throws -> Data {
        posts.append(path)
        return Data()
    }

    func postedPaths() -> [String] { posts }
    func failRequests() { failing = true }
}

@MainActor private final class DashboardMockAppService: AppService {
    var status: SMAppService.Status

    init(status: SMAppService.Status) { self.status = status }
    func register() throws { status = .enabled }
    func unregister() async throws { status = .notRegistered }
}

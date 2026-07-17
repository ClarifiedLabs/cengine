import AppKit
import CEngineCore
import Foundation
import NIOCore
import ServiceManagement

@MainActor protocol AppService {
    var status: SMAppService.Status { get }
    func register() throws
    func unregister() async throws
}

extension SMAppService: AppService {}

@MainActor final class AppModel: ObservableObject {
    @Published var engineStatus = "Starting…"
    @Published var helperStatus = "Disabled"
    @Published var error: String?
    @Published var refreshError: String?
    @Published private(set) var engineServiceEnabled: Bool
    @Published private(set) var engineServiceState: EngineServiceState?
    @Published private(set) var isManagingEngineService = false
    @Published var engineServiceActionStatus: String?
    @Published private(set) var snapshot: EngineSnapshot?
    @Published private(set) var snapshotIsStale = false
    @Published private(set) var isRefreshing = false
    @Published private(set) var containerDetails: [String: ContainerDetail] = [:]
    @Published private(set) var imageDetails: [String: ImageDetail] = [:]
    @Published private(set) var containerTelemetry: [String: ContainerTelemetry] = [:]
    @Published private(set) var containerLogs: [String: [ContainerLogLine]] = [:]
    @Published private(set) var detailErrors: [String: String] = [:]
    @Published private(set) var volumeConsumerIDs: [String: [String]] = [:]
    @Published private(set) var containerActionInProgress: String?
    @Published var helperNeedsApproval = false
    @Published var builderCPUs: Int
    @Published var builderMemoryGiB: Int
    @Published var builderSettingsStatus: String?
    @Published private(set) var isApplyingBuilderSettings = false
    @Published var containerCPUs: Int
    @Published var containerMemoryGiB: Int
    @Published var containerSettingsStatus: String?
    @Published var showOnboarding: Bool

    let maximumCPUs = ProcessInfo.processInfo.activeProcessorCount
    let maximumMemoryGiB = VirtualMachineMemory.maximumHardLimitGiB(
        maximumCapacityBytes: ProcessInfo.processInfo.physicalMemory
    )

    var containers: [ContainerSummary] { snapshot?.containers ?? [] }
    var images: [ImageSummary] { snapshot?.images ?? [] }
    var networks: [NetworkSummary] { snapshot?.networks ?? [] }
    var volumes: [VolumeSummary] { snapshot?.volumes ?? [] }
    var isRunningEngineOutdated: Bool {
        guard let runningVersion = snapshot?.version.Version else { return false }
        return Self.isVersion(runningVersion, olderThan: appVersion)
    }
    var canRestartEngineService: Bool {
        engineServiceEnabled && agent.status == .enabled && !isManagingEngineService
    }

    var containerSettingsValidationMessage: String? {
        Self.validationMessage(
            cpus: containerCPUs,
            memoryGiB: containerMemoryGiB,
            maximumCPUs: maximumCPUs,
            maximumMemoryGiB: maximumMemoryGiB
        )
    }
    var builderSettingsValidationMessage: String? {
        Self.validationMessage(
            cpus: builderCPUs,
            memoryGiB: builderMemoryGiB,
            maximumCPUs: maximumCPUs,
            maximumMemoryGiB: maximumMemoryGiB
        )
    }
    var containerSettingsDirty: Bool {
        containerCPUs != savedContainerCPUs || containerMemoryGiB != savedContainerMemoryGiB
    }
    var builderSettingsDirty: Bool {
        builderCPUs != savedBuilderCPUs || builderMemoryGiB != savedBuilderMemoryGiB
    }

    private let agent: any AppService
    private let helper: any AppService
    private let openLoginItemsSettings: () -> Void
    private let client: any AppEngineClient
    private let socketPath: String
    private let serviceStateURL: URL
    private let builderSettingsURL: URL
    private let containerSettingsURL: URL
    private let activeContextMarkerURL: URL
    let appVersion: String
    private let serviceRegistrationRevision: String?
    private let serviceRegistrationDefaults: UserDefaults
    private let waitForServiceUnregistration: () async throws -> Void
    private let restartRegisteredEngine: @Sendable () async throws -> Void
    private var refreshTask: Task<Void, Never>?
    private var previousStats: [String: ContainerStatsSample] = [:]
    private var savedBuilderCPUs: Int
    private var savedBuilderMemoryGiB: Int
    private var savedContainerCPUs: Int
    private var savedContainerMemoryGiB: Int

    static let serviceRegistrationRevisionKey = "serviceRegistrationRevision"
    static let engineServiceEnabledKey = AppPreferenceKeys.engineServiceEnabled
    private static let serviceFailurePrefix = "Engine failed to start: "

    init(
        home: URL = FileManager.default.homeDirectoryForCurrentUser,
        agent: any AppService = SMAppService.agent(plistName: CEngineServices.agentPlist),
        helper: any AppService = SMAppService.daemon(plistName: CEngineServices.helperPlist),
        client: (any AppEngineClient)? = nil,
        appVersion: String = CEngineVersion.shortVersion(),
        serviceRegistrationRevision: String? = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String,
        serviceRegistrationDefaults: UserDefaults = .standard,
        waitForServiceUnregistration: @escaping () async throws -> Void = {
            try await Task.sleep(for: .seconds(2))
        },
        restartRegisteredEngine: @escaping @Sendable () async throws -> Void = {
            try await Task.detached { try CEngineServices.restartEngine() }.value
        },
        openLoginItemsSettings: @escaping () -> Void = { SMAppService.openSystemSettingsLoginItems() }
    ) {
        self.agent = agent
        self.helper = helper
        self.openLoginItemsSettings = openLoginItemsSettings
        let paths = EnginePaths(home: home)
        socketPath = paths.socket.path
        serviceStateURL = paths.serviceState
        builderSettingsURL = paths.builderSettings
        containerSettingsURL = paths.containerSettings
        activeContextMarkerURL = paths.activeContextMarker
        self.client = client ?? DockerSocketClient(socketPath: paths.socket.path)
        self.appVersion = appVersion
        self.serviceRegistrationRevision = serviceRegistrationRevision
        self.serviceRegistrationDefaults = serviceRegistrationDefaults
        self.waitForServiceUnregistration = waitForServiceUnregistration
        self.restartRegisteredEngine = restartRegisteredEngine
        engineServiceEnabled = serviceRegistrationDefaults.object(forKey: Self.engineServiceEnabledKey) as? Bool ?? true
        engineServiceState = try? EngineServiceState.load(from: paths.serviceState)
        let builderSettings = (try? BuilderSettings.load(from: builderSettingsURL)) ?? .default
        builderCPUs = builderSettings.cpus
        builderMemoryGiB = builderSettings.memoryGiB
        savedBuilderCPUs = builderSettings.cpus
        savedBuilderMemoryGiB = builderSettings.memoryGiB
        let containerSettings = (try? ContainerSettings.load(from: containerSettingsURL)) ?? .default
        containerCPUs = containerSettings.cpus
        containerMemoryGiB = containerSettings.memoryGiB
        savedContainerCPUs = containerSettings.cpus
        savedContainerMemoryGiB = containerSettings.memoryGiB
        showOnboarding = !serviceRegistrationDefaults.bool(forKey: AppPreferenceKeys.completedOnboarding)
        if !engineServiceEnabled { engineStatus = "Disabled" }
    }

    static func isVersion(_ runningVersion: String, olderThan appVersion: String) -> Bool {
        guard let runningComponents = releaseVersionComponents(runningVersion),
              let appComponents = releaseVersionComponents(appVersion)
        else { return false }

        for (running, app) in zip(runningComponents, appComponents) where running != app {
            return running < app
        }
        return false
    }

    private static func releaseVersionComponents(_ version: String) -> [Int]? {
        let components = version.split(separator: ".", omittingEmptySubsequences: false)
        guard components.count == 3 else { return nil }
        let numbers = components.compactMap { Int($0) }
        return numbers.count == components.count && numbers.allSatisfy { $0 >= 0 } ? numbers : nil
    }

    func start() async {
        do {
            let registrationChanged = try await unregisterOutdatedServicesIfNeeded()
            if engineServiceEnabled {
                try registerRequiredNetworking()
                try registerEngineIfNetworkingIsReady()
            }
            if registrationChanged, let serviceRegistrationRevision {
                serviceRegistrationDefaults.set(
                    serviceRegistrationRevision,
                    forKey: Self.serviceRegistrationRevisionKey
                )
            }
        } catch {
            self.error = "Could not enable required cengine services: \(error.localizedDescription)"
        }
        updateServiceStatus()
        startPolling()
    }

    func setActive(_ active: Bool) {
        if active {
            if refreshTask == nil { startPolling() }
        } else {
            refreshTask?.cancel()
            refreshTask = nil
        }
    }

    private func startPolling() {
        refreshTask?.cancel()
        refreshTask = Task {
            while !Task.isCancelled {
                await refresh()
                try? await Task.sleep(for: .seconds(3))
            }
        }
    }

    func completeOnboarding() async {
        serviceRegistrationDefaults.set(true, forKey: AppPreferenceKeys.completedOnboarding)
        serviceRegistrationDefaults.set(true, forKey: Self.engineServiceEnabledKey)
        showOnboarding = false
        do {
            try registerRequiredNetworking()
            try registerEngineIfNetworkingIsReady()
            if helper.status == .requiresApproval { openLoginItemsSettings() }
            error = nil
        } catch {
            self.error = "Could not enable required networking: \(error.localizedDescription)"
        }
        updateServiceStatus()
    }

    func openNetworkingApproval() {
        openLoginItemsSettings()
    }

    func enableEngineService() async {
        guard !isManagingEngineService else { return }
        isManagingEngineService = true
        engineServiceActionStatus = "Enabling…"
        engineServiceEnabled = true
        serviceRegistrationDefaults.set(true, forKey: Self.engineServiceEnabledKey)
        defer { isManagingEngineService = false }
        do {
            try registerRequiredNetworking()
            try registerEngineIfNetworkingIsReady()
            engineServiceActionStatus = helper.status == .enabled ? "Enabled" : "Waiting for networking approval"
            refreshError = nil
        } catch {
            engineServiceActionStatus = "Could not enable"
            self.error = "Could not enable the cengine engine service: \(error.localizedDescription)"
        }
        updateServiceStatus()
    }

    func disableEngineService() async {
        guard !isManagingEngineService else { return }
        isManagingEngineService = true
        engineServiceActionStatus = "Disabling…"
        engineServiceEnabled = false
        serviceRegistrationDefaults.set(false, forKey: Self.engineServiceEnabledKey)
        defer { isManagingEngineService = false }
        do {
            if !CEngineServices.needsRegistration(agent.status) {
                try await agent.unregister()
            }
            engineServiceActionStatus = "Disabled"
            snapshotIsStale = snapshot != nil
        } catch {
            engineServiceEnabled = true
            serviceRegistrationDefaults.set(true, forKey: Self.engineServiceEnabledKey)
            engineServiceActionStatus = "Could not disable"
            self.error = "Could not disable the cengine engine service: \(error.localizedDescription)"
        }
        updateServiceStatus()
    }

    func restartEngineService() async {
        guard !isManagingEngineService else { return }
        guard engineServiceEnabled, agent.status == .enabled else {
            error = "Enable the cengine engine service before restarting it."
            return
        }
        isManagingEngineService = true
        engineServiceActionStatus = "Restarting…"
        engineStatus = "Restarting…"
        refreshError = nil
        defer { isManagingEngineService = false }
        do {
            try await restartRegisteredEngine()
            engineServiceActionStatus = "Restart requested"
            engineStatus = "Starting…"
        } catch {
            engineServiceActionStatus = "Could not restart"
            self.error = "Could not restart the cengine engine service: \(error.localizedDescription)"
            updateServiceStatus()
        }
    }

    func applyBuilderSettings() async {
        guard builderSettingsValidationMessage == nil else { return }
        let settings = BuilderSettings(cpus: builderCPUs, memoryGiB: builderMemoryGiB)
        isApplyingBuilderSettings = true
        builderSettingsStatus = "Applying…"
        defer { isApplyingBuilderSettings = false }
        do {
            try settings.save(to: builderSettingsURL)
            savedBuilderCPUs = builderCPUs
            savedBuilderMemoryGiB = builderMemoryGiB
        } catch {
            builderSettingsStatus = "Could not save"
            self.error = "Builder resources could not be saved: \(error.localizedDescription)"
            return
        }
        guard FileManager.default.fileExists(atPath: socketPath) else {
            builderSettingsStatus = "Saved; applies when cengine starts"
            return
        }
        do {
            try await Task.detached {
                try DockerIntegration.configureBuilder(settings)
            }.value
            builderSettingsStatus = "Applied"
        } catch {
            builderSettingsStatus = "Saved; applies when cengine restarts"
            self.error = "Builder resources could not be applied now: \(error.localizedDescription)"
        }
    }

    func applyContainerSettings() {
        guard containerSettingsValidationMessage == nil else { return }
        let settings = ContainerSettings(cpus: containerCPUs, memoryGiB: containerMemoryGiB)
        do {
            try settings.save(to: containerSettingsURL)
            savedContainerCPUs = containerCPUs
            savedContainerMemoryGiB = containerMemoryGiB
            containerSettingsStatus = "Saved; applies to new containers"
        } catch {
            containerSettingsStatus = "Could not save"
            self.error = "Container defaults could not be saved: \(error.localizedDescription)"
        }
    }

    func refresh() async {
        guard !isRefreshing else { return }
        isRefreshing = true
        defer { isRefreshing = false }
        do {
            try registerEngineIfNetworkingIsReady()
        } catch {
            self.error = "Could not enable the cengine background service: \(error.localizedDescription)"
        }
        updateServiceStatus()
        guard agent.status == .enabled else {
            snapshotIsStale = snapshot != nil
            return
        }
        do {
            async let versionData = client.get("/v1.55/version")
            async let infoData = client.get("/v1.55/info")
            async let containerData = client.get("/v1.55/containers/json?all=1")
            async let imageData = client.get("/v1.55/images/json")
            async let networkData = client.get("/v1.55/networks")
            async let diskData = client.get("/v1.55/system/df?verbose=true")
            let payloads = try await (versionData, infoData, containerData, imageData, networkData, diskData)
            let decoder = JSONDecoder()
            let version = try decoder.decode(VersionResponse.self, from: payloads.0)
            let info = try decoder.decode(InfoResponse.self, from: payloads.1)
            let containers = try decoder.decode([ContainerSummary].self, from: payloads.2)
            let images = try decoder.decode([ImageSummary].self, from: payloads.3)
            let networks = try decoder.decode([NetworkSummary].self, from: payloads.4)
            let diskUsage = try decoder.decode(DiskUsageResponse.self, from: payloads.5)
            snapshot = EngineSnapshot(
                version: version,
                info: info,
                containers: containers,
                images: images,
                networks: networks,
                volumes: diskUsage.Volumes,
                imageLayerBytes: diskUsage.LayersSize,
                refreshedAt: Date()
            )
            engineStatus = "Running"
            engineServiceState = try? EngineServiceState.load(from: serviceStateURL)
            snapshotIsStale = false
            refreshError = nil
            pruneCaches(for: containers, images: images)
        } catch {
            snapshotIsStale = snapshot != nil
            if Self.isEngineUnavailable(error, socketPath: socketPath) {
                updateServiceStatus()
                if engineStatus == "Running" {
                    engineStatus = "Starting…"
                    refreshError = "The engine service is registered, but its Docker socket is unavailable."
                }
            } else {
                refreshError = "Engine data is unavailable: \(error.localizedDescription)"
            }
        }
    }

    func loadContainerDetail(_ id: String, force: Bool = false) async {
        if !force, containerDetails[id] != nil { return }
        do {
            let data = try await client.get("/v1.55/containers/\(id)/json")
            containerDetails[id] = try JSONDecoder().decode(ContainerDetail.self, from: data)
            detailErrors[id] = nil
        } catch {
            detailErrors[id] = "Container details are unavailable: \(error.localizedDescription)"
        }
    }

    func loadContainerStatistics(_ id: String) async {
        guard containers.first(where: { $0.id == id })?.isRunning == true else {
            previousStats[id] = nil
            containerTelemetry[id] = nil
            return
        }
        do {
            let data = try await client.get("/v1.55/containers/\(id)/stats?stream=false")
            let sample = try JSONDecoder().decode(ContainerStatsSample.self, from: data)
            containerTelemetry[id] = ContainerTelemetry(sample: sample, previous: previousStats[id])
            previousStats[id] = sample
            detailErrors["stats:\(id)"] = nil
        } catch {
            detailErrors["stats:\(id)"] = "Live statistics are unavailable: \(error.localizedDescription)"
        }
    }

    func loadContainerLogs(_ id: String) async {
        await loadContainerDetail(id)
        do {
            let data = try await client.get(
                "/v1.55/containers/\(id)/logs?stdout=1&stderr=1&timestamps=1&tail=500"
            )
            containerLogs[id] = DockerLogParser.parse(data, tty: containerDetails[id]?.Config.Tty ?? false)
            detailErrors["logs:\(id)"] = nil
        } catch {
            detailErrors["logs:\(id)"] = "Logs are unavailable: \(error.localizedDescription)"
        }
    }

    func loadImageDetail(_ id: String, force: Bool = false) async {
        if !force, imageDetails[id] != nil { return }
        let escaped = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        do {
            let data = try await client.get("/v1.55/images/\(escaped)/json")
            imageDetails[id] = try JSONDecoder().decode(ImageDetail.self, from: data)
            detailErrors[id] = nil
        } catch {
            detailErrors[id] = "Image details are unavailable: \(error.localizedDescription)"
        }
    }

    func loadVolumeConsumers(_ name: String) async {
        let ids = containers.map(\.id)
        let missing = ids.filter { containerDetails[$0] == nil }
        let client = self.client
        let loaded = await withTaskGroup(of: (String, ContainerDetail?).self) { group in
            for id in missing {
                group.addTask {
                    do {
                        let data = try await client.get("/v1.55/containers/\(id)/json")
                        return (id, try JSONDecoder().decode(ContainerDetail.self, from: data))
                    } catch {
                        return (id, nil)
                    }
                }
            }
            var result: [String: ContainerDetail] = [:]
            for await (id, detail) in group {
                if let detail { result[id] = detail }
            }
            return result
        }
        containerDetails.merge(loaded) { _, new in new }
        volumeConsumerIDs[name] = ids.filter { id in
            containerDetails[id]?.Mounts.contains {
                $0.Type == "volume" && ($0.Name == name || $0.Source == name)
            } == true
        }
    }

    func containersAttached(to network: NetworkSummary) -> [ContainerSummary] {
        containers.filter { container in
            container.NetworkSettings.Networks.values.contains { $0.NetworkID == network.Id }
                || container.NetworkSettings.Networks.keys.contains(network.Name)
        }
    }

    func perform(_ action: ContainerAction, on id: String) async {
        guard containerActionInProgress == nil else { return }
        containerActionInProgress = id
        defer { containerActionInProgress = nil }
        do {
            _ = try await client.post("/v1.55/containers/\(id)/\(action.rawValue)", body: Data())
            detailErrors[id] = nil
            await refresh()
            await loadContainerDetail(id, force: true)
        } catch {
            self.error = "Could not \(action.rawValue) the container: \(error.localizedDescription)"
        }
    }

    nonisolated static func isEngineUnavailable(_ error: Error, socketPath: String) -> Bool {
        if !FileManager.default.fileExists(atPath: socketPath) { return true }
        guard let ioError = error as? IOError else { return false }
        return ioError.errnoCode == ECONNREFUSED || ioError.errnoCode == ENOENT
    }

    nonisolated static func validationMessage(
        cpus: Int,
        memoryGiB: Int,
        maximumCPUs: Int,
        maximumMemoryGiB: Int
    ) -> String? {
        if !(1...maximumCPUs).contains(cpus) { return "CPUs must be between 1 and \(maximumCPUs)." }
        if !(1...maximumMemoryGiB).contains(memoryGiB) {
            return "Memory must be between 1 and \(maximumMemoryGiB) GiB."
        }
        return nil
    }

    func uninstall(deleteData: Bool) async {
        guard let package = Bundle.main.url(forResource: "cengine-uninstall", withExtension: "pkg") else {
            error = "The signed cengine uninstaller is missing."
            return
        }
        refreshTask?.cancel()
        await CEngineServices.teardownServices()
        let removal = DockerIntegration.remove(
            recordingActiveContextTo: deleteData ? nil : activeContextMarkerURL
        )
        if let warning = removal.warning {
            FileHandle.standardError.write(Data("cengine uninstall: \(warning)\n".utf8))
        }
        if deleteData {
            do {
                try CEngineUserData.removeAll()
            } catch {
                self.error = "cengine was stopped, but uninstall did not continue because some data could not be deleted: \(error.localizedDescription)"
                return
            }
        }
        NSWorkspace.shared.open(package)
        NSApplication.shared.terminate(nil)
    }

    private func pruneCaches(for containers: [ContainerSummary], images: [ImageSummary]) {
        let containerIDs = Set(containers.map(\.id))
        let imageIDs = Set(images.map(\.id))
        containerDetails = containerDetails.filter { containerIDs.contains($0.key) }
        containerTelemetry = containerTelemetry.filter { containerIDs.contains($0.key) }
        containerLogs = containerLogs.filter { containerIDs.contains($0.key) }
        previousStats = previousStats.filter { containerIDs.contains($0.key) }
        imageDetails = imageDetails.filter { imageIDs.contains($0.key) }
    }

    private func updateServiceStatus() {
        helperStatus = Self.label(helper.status)
        helperNeedsApproval = helper.status == .requiresApproval
        engineServiceState = try? EngineServiceState.load(from: serviceStateURL)
        guard engineServiceEnabled else {
            engineStatus = "Disabled"
            refreshError = nil
            return
        }
        guard agent.status == .enabled else {
            engineStatus = Self.label(agent.status)
            clearReportedServiceFailure()
            return
        }
        guard let engineServiceState else {
            engineStatus = "Starting…"
            clearReportedServiceFailure()
            return
        }
        switch engineServiceState.phase {
        case .starting:
            engineStatus = "Starting…"
            clearReportedServiceFailure()
        case .running:
            engineStatus = "Running"
            clearReportedServiceFailure()
        case .failed:
            engineStatus = "Failed"
            refreshError = Self.serviceFailurePrefix + (engineServiceState.message ?? "No failure details were reported.")
        case .stopped:
            engineStatus = "Stopped"
            clearReportedServiceFailure()
        }
    }

    private func clearReportedServiceFailure() {
        if refreshError?.hasPrefix(Self.serviceFailurePrefix) == true { refreshError = nil }
    }

    private func registerRequiredNetworking() throws {
        guard CEngineServices.needsRegistration(helper.status) else { return }
        do {
            try helper.register()
        } catch {
            if helper.status != .requiresApproval { throw error }
        }
    }

    private func unregisterOutdatedServicesIfNeeded() async throws -> Bool {
        guard let serviceRegistrationRevision,
              serviceRegistrationDefaults.string(forKey: Self.serviceRegistrationRevisionKey) != serviceRegistrationRevision
        else { return false }

        var unregisteredService = false
        if agent.status == .enabled || agent.status == .requiresApproval {
            try await agent.unregister()
            unregisteredService = true
        }
        if helper.status == .enabled || helper.status == .requiresApproval {
            try await helper.unregister()
            unregisteredService = true
        }
        if unregisteredService { try await waitForServiceUnregistration() }
        return true
    }

    private func registerEngineIfNetworkingIsReady() throws {
        guard engineServiceEnabled,
              helper.status == .enabled,
              CEngineServices.needsRegistration(agent.status)
        else { return }
        try agent.register()
        serviceRegistrationDefaults.set(true, forKey: Self.engineServiceEnabledKey)
    }

    private static func label(_ status: SMAppService.Status) -> String {
        switch status {
        case .enabled: "Running"
        case .requiresApproval: "Needs approval"
        case .notRegistered: "Disabled"
        case .notFound: "Unavailable"
        @unknown default: "Unknown"
        }
    }
}

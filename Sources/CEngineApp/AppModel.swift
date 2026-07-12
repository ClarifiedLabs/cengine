import AppKit
import CEngineCore
import Foundation
import NIOCore
import ServiceManagement

struct ResourceItem: Identifiable, Hashable {
    let id: String
    let title: String
    let detail: String
}

@MainActor final class AppModel: ObservableObject {
    @Published var engineStatus = "Starting…"
    @Published var helperStatus = "Disabled"
    @Published var version = "—"
    @Published var diskUsage = "—"
    @Published var error: String?
    @Published var containers: [ResourceItem] = []
    @Published var images: [ResourceItem] = []
    @Published var networks: [ResourceItem] = []
    @Published var volumes: [ResourceItem] = []
    @Published var helperEnabled = false
    @Published var showOnboarding: Bool

    private let agent = SMAppService.agent(plistName: CEngineServices.agentPlist)
    private let helper = SMAppService.daemon(plistName: CEngineServices.helperPlist)
    private let client: DockerSocketClient
    private let socketPath: String
    private var refreshTask: Task<Void, Never>?

    init() {
        socketPath = EnginePaths().socket.path
        client = DockerSocketClient(socketPath: socketPath)
        showOnboarding = !UserDefaults.standard.bool(forKey: "completedOnboarding")
    }

    func start() {
        do {
            if agent.status == .notRegistered { try agent.register() }
        } catch {
            self.error = "Could not enable the cengine background service: \(error.localizedDescription)"
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

    func completeOnboarding(enableHelper: Bool) async {
        UserDefaults.standard.set(true, forKey: "completedOnboarding")
        showOnboarding = false
        if enableHelper { await setHelperEnabled(true) }
    }

    func setHelperEnabled(_ enabled: Bool) async {
        do {
            if enabled {
                if helper.status == .notRegistered { try helper.register() }
                if helper.status == .requiresApproval { SMAppService.openSystemSettingsLoginItems() }
            } else if helper.status != .notRegistered && helper.status != .notFound {
                try await helper.unregister()
            }
        } catch {
            self.error = "Could not update privileged-port support: \(error.localizedDescription)"
        }
        updateServiceStatus()
    }

    func refresh() async {
        updateServiceStatus()
        guard agent.status == .enabled else { return }
        do {
            async let versionData = client.get("/v1.55/version")
            async let infoData = client.get("/v1.55/info")
            async let containerData = client.get("/v1.55/containers/json?all=1")
            async let imageData = client.get("/v1.55/images/json")
            async let networkData = client.get("/v1.55/networks")
            async let volumeData = client.get("/v1.55/volumes")
            let decoder = JSONDecoder()
            let version = try decoder.decode(VersionResponse.self, from: await versionData)
            let info = try decoder.decode(InfoResponse.self, from: await infoData)
            let containers = try decoder.decode([ContainerResponse].self, from: await containerData)
            let images = try decoder.decode([ImageResponse].self, from: await imageData)
            let networks = try decoder.decode([NetworkResponse].self, from: await networkData)
            let volumes = try decoder.decode(VolumeEnvelope.self, from: await volumeData)
            self.version = version.Version
            diskUsage = "\(info.Containers) containers · \(images.count) images"
            self.containers = containers.map {
                ResourceItem(id: $0.Id, title: $0.Names.first?.trimmingCharacters(in: CharacterSet(charactersIn: "/")) ?? String($0.Id.prefix(12)), detail: "\($0.Image) · \($0.State)")
            }
            self.images = images.map {
                ResourceItem(id: $0.Id, title: $0.RepoTags?.first ?? String($0.Id.prefix(19)), detail: ByteCountFormatter.string(fromByteCount: $0.Size, countStyle: .file))
            }
            self.networks = networks.map { ResourceItem(id: $0.Id, title: $0.Name, detail: $0.Driver) }
            self.volumes = (volumes.Volumes ?? []).map {
                ResourceItem(id: $0.Name, title: $0.Name, detail: $0.Mountpoint)
            }
            error = nil
        } catch {
            if Self.isEngineUnavailable(error, socketPath: socketPath) {
                // Expected while the daemon provisions on first start (which can take
                // minutes) — show it inline rather than re-alerting every poll.
                engineStatus = "Starting…"
            } else {
                self.error = "Engine data is unavailable: \(error.localizedDescription)"
            }
        }
    }

    nonisolated static func isEngineUnavailable(_ error: Error, socketPath: String) -> Bool {
        if !FileManager.default.fileExists(atPath: socketPath) { return true }
        guard let ioError = error as? IOError else { return false }
        return ioError.errnoCode == ECONNREFUSED || ioError.errnoCode == ENOENT
    }

    func uninstall(deleteData: Bool) async {
        refreshTask?.cancel()
        await CEngineServices.teardownServices()
        DockerIntegration.remove()
        if deleteData {
            try? FileManager.default.removeItem(at: FileManager.default.homeDirectoryForCurrentUser
                .appending(path: "Library/Application Support/cengine"))
            try? FileManager.default.removeItem(at: FileManager.default.homeDirectoryForCurrentUser
                .appending(path: ".cengine"))
        }
        guard let package = Bundle.main.url(forResource: "cengine-uninstall", withExtension: "pkg") else {
            error = "The signed cengine uninstaller is missing."
            return
        }
        NSWorkspace.shared.open(package)
        NSApplication.shared.terminate(nil)
    }

    private func updateServiceStatus() {
        engineStatus = Self.label(agent.status)
        helperStatus = Self.label(helper.status)
        helperEnabled = helper.status == .enabled || helper.status == .requiresApproval
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

private struct VersionResponse: Decodable { let Version: String }
private struct InfoResponse: Decodable { let Containers: Int }
private struct ContainerResponse: Decodable { let Id: String; let Names: [String]; let Image: String; let State: String }
private struct ImageResponse: Decodable { let Id: String; let RepoTags: [String]?; let Size: Int64 }
private struct NetworkResponse: Decodable { let Id: String; let Name: String; let Driver: String }
private struct VolumeEnvelope: Decodable { let Volumes: [VolumeResponse]? }
private struct VolumeResponse: Decodable { let Name: String; let Mountpoint: String }

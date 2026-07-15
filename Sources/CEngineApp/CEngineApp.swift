import SwiftUI

struct CEngineApplication: App {
    @StateObject private var model = AppModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 920, minHeight: 600)
                .task { await model.start() }
                .sheet(isPresented: $model.showOnboarding) {
                    OnboardingView {
                        await model.completeOnboarding()
                    }
                }
        }
        .defaultSize(width: 1_100, height: 720)
        .onChange(of: scenePhase) { _, phase in model.setActive(phase == .active) }
        .commands { IntegratedSettingsCommands() }
    }
}

@MainActor final class AppNavigation: ObservableObject {
    @Published var section: AppSection? = .dashboard
    @Published var selectedContainerID: String?
    @Published var selectedImageID: String?
    @Published var selectedNetworkID: String?
    @Published var selectedVolumeID: String?

    func showContainer(_ id: String) {
        selectedContainerID = id
        section = .containers
    }
}

struct ContentView: View {
    @EnvironmentObject private var model: AppModel
    @StateObject private var navigation = AppNavigation()

    var body: some View {
        NavigationSplitView {
            VStack(spacing: 0) {
                List(AppSection.resourceSections, selection: $navigation.section) { section in
                    Label(section.title, systemImage: section.icon).tag(Optional(section))
                }
                Divider()
                Button {
                    navigation.section = .settings
                } label: {
                    Label("Settings", systemImage: "gearshape")
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .contentShape(Rectangle())
                        .padding(.horizontal, 8)
                        .padding(.vertical, 7)
                        .background(
                            navigation.section == .settings ? Color.accentColor.opacity(0.16) : .clear,
                            in: RoundedRectangle(cornerRadius: 6)
                        )
                }
                .buttonStyle(.plain)
                .padding(.horizontal, 8)
                .padding(.vertical, 8)
            }
            .navigationSplitViewColumnWidth(min: 155, ideal: 180, max: 220)
        } detail: {
            switch navigation.section {
            case .dashboard, nil:
                DashboardView(navigation: navigation)
            case .containers:
                ContainersView(selection: $navigation.selectedContainerID)
            case .images:
                ImagesView(selection: $navigation.selectedImageID)
            case .networks:
                NetworksView(selection: $navigation.selectedNetworkID)
            case .volumes:
                VolumesView(selection: $navigation.selectedVolumeID)
            case .settings:
                SettingsView()
            }
        }
        .focusedSceneValue(\.navigateToIntegratedSettings) {
            navigation.section = .settings
        }
        .alert("cengine", isPresented: Binding(
            get: { model.error != nil },
            set: { if !$0 { model.error = nil } }
        )) {
            Button("OK") { model.error = nil }
        } message: {
            Text(model.error ?? "")
        }
    }
}

enum AppSection: String, CaseIterable, Identifiable {
    case dashboard, containers, images, networks, volumes, settings

    static let resourceSections: [AppSection] = [.dashboard, .containers, .images, .networks, .volumes]

    var id: Self { self }
    var title: String { rawValue.capitalized }
    var icon: String {
        switch self {
        case .dashboard: "gauge"
        case .containers: "shippingbox"
        case .images: "square.stack.3d.up"
        case .networks: "network"
        case .volumes: "externaldrive"
        case .settings: "gearshape"
        }
    }
}

private struct NavigateToIntegratedSettingsKey: FocusedValueKey {
    typealias Value = () -> Void
}

extension FocusedValues {
    var navigateToIntegratedSettings: (() -> Void)? {
        get { self[NavigateToIntegratedSettingsKey.self] }
        set { self[NavigateToIntegratedSettingsKey.self] = newValue }
    }
}

private struct IntegratedSettingsCommands: Commands {
    @FocusedValue(\.navigateToIntegratedSettings) private var navigateToSettings

    var body: some Commands {
        CommandGroup(replacing: .appSettings) {
            Button("Settings…") { navigateToSettings?() }
                .keyboardShortcut(",", modifiers: .command)
                .disabled(navigateToSettings == nil)
        }
    }
}

struct OnboardingView: View {
    let onComplete: @MainActor () async -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Welcome to cengine").font(.largeTitle.bold())
            Text("cengine uses a privileged networking service to connect each container VM to macOS through vmnet.")
            Text("macOS requires administrator approval before the engine can start.")
                .foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Enable VM Networking") { Task { await complete() } }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(28)
        .frame(width: 520)
    }

    func complete() async {
        await onComplete()
    }
}

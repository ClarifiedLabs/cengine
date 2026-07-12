import SwiftUI

struct CEngineApplication: App {
    @StateObject private var model = AppModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 760, minHeight: 500)
                .task { model.start() }
                .sheet(isPresented: $model.showOnboarding) {
                    OnboardingView { enableHelper in
                        await model.completeOnboarding(enableHelper: enableHelper)
                    }
                }
        }
        .onChange(of: scenePhase) { _, phase in model.setActive(phase == .active) }
        Settings { SettingsView().environmentObject(model).frame(width: 480) }
    }
}

private struct ContentView: View {
    @EnvironmentObject private var model: AppModel
    @State private var selection: AppSection? = .dashboard

    var body: some View {
        NavigationSplitView {
            List(AppSection.allCases, selection: $selection) { section in
                Label(section.title, systemImage: section.icon).tag(section)
            }
            .navigationSplitViewColumnWidth(min: 150, ideal: 180)
        } detail: {
            Group {
                switch selection {
                case .dashboard, nil: DashboardView()
                case .containers: ResourceList(title: "Containers", items: model.containers)
                case .images: ResourceList(title: "Images", items: model.images)
                case .networks: ResourceList(title: "Networks", items: model.networks)
                case .volumes: ResourceList(title: "Volumes", items: model.volumes)
                }
            }
            .padding()
        }
        .alert("cengine", isPresented: Binding(
            get: { model.error != nil }, set: { if !$0 { model.error = nil } }
        )) { Button("OK") { model.error = nil } } message: { Text(model.error ?? "") }
    }
}

private enum AppSection: String, CaseIterable, Identifiable {
    case dashboard, containers, images, networks, volumes
    var id: Self { self }
    var title: String { rawValue.capitalized }
    var icon: String {
        switch self {
        case .dashboard: "gauge"
        case .containers: "shippingbox"
        case .images: "square.stack.3d.up"
        case .networks: "network"
        case .volumes: "externaldrive"
        }
    }
}

private struct DashboardView: View {
    @EnvironmentObject private var model: AppModel
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("cengine").font(.largeTitle.bold())
            Grid(alignment: .leading, horizontalSpacing: 28, verticalSpacing: 10) {
                row("Engine", model.engineStatus)
                row("Privileged ports", model.helperStatus)
                row("Version", model.version)
                row("Resources", model.diskUsage)
            }
            Button("Refresh") { Task { await model.refresh() } }
            Spacer()
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
    private func row(_ name: String, _ value: String) -> some View {
        GridRow { Text(name).foregroundStyle(.secondary); Text(value).textSelection(.enabled) }
    }
}

private struct ResourceList: View {
    let title: String
    let items: [ResourceItem]
    var body: some View {
        VStack(alignment: .leading) {
            Text(title).font(.title.bold())
            List(items) { item in
                VStack(alignment: .leading) { Text(item.title); Text(item.detail).font(.caption).foregroundStyle(.secondary) }
            }
        }
    }
}

struct OnboardingView: View {
    let onComplete: @MainActor (Bool) async -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Welcome to cengine").font(.largeTitle.bold())
            Text("The cengine background service has been enabled. Privileged Ports allows exact host-IP bindings below port 1024 and requires administrator approval.")
            Text("You can enable it later in Settings.").foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Not Now") { Task { await complete(enableHelper: false) } }
                    .keyboardShortcut(.defaultAction)
                Button("Enable Privileged Ports") { Task { await complete(enableHelper: true) } }
            }
        }.padding(28).frame(width: 520)
    }

    func complete(enableHelper: Bool) async {
        await onComplete(enableHelper)
    }
}

private struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var showingUninstall = false
    @State private var deleteData = false
    var body: some View {
        Form {
            Section("Container Defaults") {
                Stepper("CPUs: \(model.containerCPUs)", value: $model.containerCPUs, in: 1...model.maximumCPUs)
                Stepper(
                    "Memory: \(model.containerMemoryGiB) GiB",
                    value: $model.containerMemoryGiB,
                    in: 1...model.maximumMemoryGiB
                )
                Text("Used for new containers when Docker or Compose does not specify resource limits.")
                    .font(.caption).foregroundStyle(.secondary)
                HStack {
                    Button("Save Container Defaults") { model.applyContainerSettings() }
                    if let status = model.containerSettingsStatus {
                        Text(status).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            Section("Builder Resources") {
                Stepper("CPUs: \(model.builderCPUs)", value: $model.builderCPUs, in: 1...model.maximumCPUs)
                Stepper(
                    "Memory: \(model.builderMemoryGiB) GiB",
                    value: $model.builderMemoryGiB,
                    in: 1...model.maximumMemoryGiB
                )
                Text("Changing resources recreates the managed builder VM while preserving its build cache.")
                    .font(.caption).foregroundStyle(.secondary)
                HStack {
                    Button("Apply Builder Resources") { Task { await model.applyBuilderSettings() } }
                    if let status = model.builderSettingsStatus {
                        Text(status).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            Divider()
            Toggle("Privileged Ports", isOn: Binding(
                get: { model.helperEnabled },
                set: { value in Task { await model.setHelperEnabled(value) } }
            ))
            Text("Allows exact specific-IP bindings for host ports below 1024.").font(.caption).foregroundStyle(.secondary)
            Divider()
            Button("Uninstall cengine…", role: .destructive) { showingUninstall = true }
        }.padding()
        .sheet(isPresented: $showingUninstall) {
            VStack(alignment: .leading, spacing: 16) {
                Text("Uninstall cengine?").font(.title2.bold())
                Text("Services, Docker integration, the app, and CLI will be removed.")
                Toggle("Delete containers, images, and volumes", isOn: $deleteData)
                Text(deleteData ? "Engine data will be permanently deleted." : "Engine data will be preserved.")
                    .font(.caption).foregroundStyle(.secondary)
                HStack {
                    Spacer()
                    Button("Cancel") { showingUninstall = false }.keyboardShortcut(.cancelAction)
                    Button("Uninstall", role: .destructive) {
                        showingUninstall = false
                        Task { await model.uninstall(deleteData: deleteData) }
                    }
                }
            }
            .padding(24)
            .frame(width: 460)
        }
    }
}

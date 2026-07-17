import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var showingUninstall = false
    @State private var deleteData = false
    private let onSectionFramesChange: (([CGRect]) -> Void)?

    init(onSectionFramesChange: (([CGRect]) -> Void)? = nil) {
        self.onSectionFramesChange = onSectionFramesChange
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Settings").font(.largeTitle.bold())
                engineService
                containerDefaults
                builderResources
                networking
                uninstall
            }
            .onPreferenceChange(SettingsSectionFramesKey.self) { frames in
                onSectionFramesChange?(frames)
            }
            .appPageContent(maxWidth: AppLayout.settingsMaximumContentWidth)
        }
        .coordinateSpace(.named("settings-view"))
        .navigationTitle("Settings")
        .sheet(isPresented: $showingUninstall) { uninstallConfirmation }
    }

    private var engineService: some View {
        SettingsSection("Engine", systemImage: "gearshape.2") {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("Engine Service")
                    Spacer()
                    StatusBadge(
                        text: model.engineStatus,
                        color: StatusBadge.color(for: model.engineStatus)
                    )
                }
                Text("Controls the dev.cengine.engine launch agent. Disabling it prevents cengine from starting automatically.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let state = model.engineServiceState, model.engineServiceEnabled {
                    HStack(spacing: 5) {
                        Text("Last reported \(state.phase.rawValue)")
                        Text("·")
                        Text(AppFormat.relative(state.updatedAt))
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
                if model.engineStatus == "Failed", let message = model.engineServiceState?.message {
                    InlineMessage(systemImage: "exclamationmark.circle.fill", text: message, color: .red)
                }
                HStack {
                    Button("Enable") { Task { await model.enableEngineService() } }
                        .disabled(model.engineServiceEnabled || model.isManagingEngineService)
                        .accessibilityIdentifier("enable-engine-service")
                    Button("Disable") { Task { await model.disableEngineService() } }
                        .disabled(!model.engineServiceEnabled || model.isManagingEngineService)
                        .accessibilityIdentifier("disable-engine-service")
                    Button("Restart") { Task { await model.restartEngineService() } }
                        .disabled(!model.canRestartEngineService)
                        .accessibilityIdentifier("restart-engine-service")
                    if let status = model.engineServiceActionStatus, !model.isManagingEngineService {
                        Text(status).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    private var containerDefaults: some View {
        SettingsSection("Container Defaults", systemImage: "shippingbox") {
            VStack(alignment: .leading, spacing: 14) {
                ResourceSettingsFields(
                    cpus: $model.containerCPUs,
                    memoryGiB: $model.containerMemoryGiB,
                    maximumCPUs: model.maximumCPUs,
                    maximumMemoryGiB: model.maximumMemoryGiB,
                    accessibilityIdentifierPrefix: "container"
                )
                Text("Used for new containers when Docker or Compose does not specify resource limits. Existing containers are unchanged.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let validation = model.containerSettingsValidationMessage {
                    InlineMessage(systemImage: "exclamationmark.circle.fill", text: validation, color: .red)
                }
                HStack {
                    Button("Save Container Defaults") { model.applyContainerSettings() }
                        .disabled(model.containerSettingsValidationMessage != nil || !model.containerSettingsDirty)
                        .accessibilityIdentifier("save-container-defaults")
                    if let status = model.containerSettingsStatus {
                        Text(status).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    private var builderResources: some View {
        SettingsSection("Builder Resources", systemImage: "hammer") {
            VStack(alignment: .leading, spacing: 14) {
                ResourceSettingsFields(
                    cpus: $model.builderCPUs,
                    memoryGiB: $model.builderMemoryGiB,
                    maximumCPUs: model.maximumCPUs,
                    maximumMemoryGiB: model.maximumMemoryGiB,
                    accessibilityIdentifierPrefix: "builder"
                )
                Text("Applying resource changes recreates the managed builder VM while preserving its BuildKit cache.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let validation = model.builderSettingsValidationMessage {
                    InlineMessage(systemImage: "exclamationmark.circle.fill", text: validation, color: .red)
                }
                HStack {
                    Button {
                        Task { await model.applyBuilderSettings() }
                    } label: {
                        if model.isApplyingBuilderSettings {
                            HStack(spacing: 7) {
                                ProgressView().controlSize(.small)
                                Text("Applying…")
                            }
                        } else {
                            Text("Apply Builder Resources")
                        }
                    }
                    .disabled(
                        model.builderSettingsValidationMessage != nil
                            || !model.builderSettingsDirty
                            || model.isApplyingBuilderSettings
                    )
                    .accessibilityIdentifier("apply-builder-resources")
                    if let status = model.builderSettingsStatus, !model.isApplyingBuilderSettings {
                        Text(status).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    private var networking: some View {
        SettingsSection("Networking", systemImage: "network") {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("VM Networking")
                    Spacer()
                    StatusBadge(
                        text: model.helperStatus,
                        color: StatusBadge.color(for: model.helperStatus)
                    )
                }
                Text("Required for vmnet NAT, DNS, macOS host access, and published container ports.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if model.helperNeedsApproval {
                    HStack(alignment: .center, spacing: 12) {
                        InlineMessage(
                            systemImage: "exclamationmark.triangle.fill",
                            text: "Administrator approval is required.",
                            color: .orange
                        )
                        Spacer()
                        Button("Open Login Items & Extensions…") { model.openNetworkingApproval() }
                    }
                }
            }
        }
    }

    private var uninstall: some View {
        SettingsSection("Uninstall", systemImage: "trash") {
            HStack(alignment: .center, spacing: 16) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Remove cengine from this Mac").fontWeight(.medium)
                    Text("Services, Docker integration, the app, and CLI will be removed.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                Button("Uninstall cengine…", role: .destructive) { showingUninstall = true }
                    .accessibilityIdentifier("uninstall-cengine")
            }
        }
    }

    private var uninstallConfirmation: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Uninstall cengine?").font(.title2.bold())
            Text("Services, Docker integration, the app, and CLI will be removed.")
            Toggle("Delete all cengine data", isOn: $deleteData)
            Text(deleteData
                ? "Containers, images, volumes, VM disks, logs, and settings will be permanently deleted."
                : "Engine data, logs, and settings will be preserved.")
                .font(.caption)
                .foregroundStyle(deleteData ? .red : .secondary)
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

private struct SettingsSection<Content: View>: View {
    let title: String
    let systemImage: String
    @ViewBuilder let content: Content

    init(_ title: String, systemImage: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.systemImage = systemImage
        self.content = content()
    }

    var body: some View {
        GroupBox {
            content
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(4)
        } label: {
            Label(title, systemImage: systemImage)
                .labelStyle(AlignedIconLabelStyle())
                .font(.headline)
        }
        .reportSettingsSectionFrame()
        .frame(maxWidth: .infinity)
    }
}

private struct SettingsSectionFramesKey: PreferenceKey {
    static let defaultValue: [CGRect] = []

    static func reduce(value: inout [CGRect], nextValue: () -> [CGRect]) {
        value.append(contentsOf: nextValue())
    }
}

private extension View {
    func reportSettingsSectionFrame() -> some View {
        background {
            GeometryReader { geometry in
                Color.clear.preference(
                    key: SettingsSectionFramesKey.self,
                    value: [geometry.frame(in: .named("settings-view"))]
                )
            }
        }
    }
}

struct ResourceSettingsFields: View {
    @Binding var cpus: Int
    @Binding var memoryGiB: Int
    let maximumCPUs: Int
    let maximumMemoryGiB: Int
    let accessibilityIdentifierPrefix: String

    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 14) {
            NumericSettingField(
                label: "CPUs",
                value: $cpus,
                range: 1...maximumCPUs,
                unit: "CPUs",
                accessibilityIdentifier: "\(accessibilityIdentifierPrefix)-cpus-field"
            )
            NumericSettingField(
                label: "Memory",
                value: $memoryGiB,
                range: 1...maximumMemoryGiB,
                unit: "GiB",
                accessibilityIdentifier: "\(accessibilityIdentifierPrefix)-memory-field"
            )
        }
    }
}

private struct NumericSettingField: View {
    let label: String
    @Binding var value: Int
    let range: ClosedRange<Int>
    let unit: String
    let accessibilityIdentifier: String

    var body: some View {
        GridRow(alignment: .center) {
            Text(label)
            TextField(label, value: $value, format: .number)
                .labelsHidden()
                .multilineTextAlignment(.trailing)
                .monospacedDigit()
                .frame(width: 72)
                .accessibilityIdentifier(accessibilityIdentifier)
            Text(unit)
                .foregroundStyle(.secondary)
                .frame(width: 36, alignment: .leading)
            Stepper(label, value: $value, in: range)
                .labelsHidden()
        }
    }
}

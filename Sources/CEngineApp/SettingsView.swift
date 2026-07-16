import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var showingUninstall = false
    @State private var deleteData = false

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
            .padding(24)
            .frame(maxWidth: 760, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .center)
        }
        .navigationTitle("Settings")
        .sheet(isPresented: $showingUninstall) { uninstallConfirmation }
    }

    private var engineService: some View {
        GroupBox {
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
            .padding(4)
        } label: {
            Label("Engine", systemImage: "gearshape.2")
                .font(.headline)
        }
        .frame(maxWidth: .infinity)
    }

    private var containerDefaults: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 14) {
                NumericSettingField(
                    label: "CPUs",
                    value: $model.containerCPUs,
                    range: 1...model.maximumCPUs,
                    unit: "CPUs",
                    accessibilityIdentifier: "container-cpus-field"
                )
                NumericSettingField(
                    label: "Memory",
                    value: $model.containerMemoryGiB,
                    range: 1...model.maximumMemoryGiB,
                    unit: "GiB",
                    accessibilityIdentifier: "container-memory-field"
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
            .padding(4)
        } label: {
            Label("Container Defaults", systemImage: "shippingbox")
                .font(.headline)
        }
        .frame(maxWidth: .infinity)
    }

    private var builderResources: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 14) {
                NumericSettingField(
                    label: "CPUs",
                    value: $model.builderCPUs,
                    range: 1...model.maximumCPUs,
                    unit: "CPUs",
                    accessibilityIdentifier: "builder-cpus-field"
                )
                NumericSettingField(
                    label: "Memory",
                    value: $model.builderMemoryGiB,
                    range: 1...model.maximumMemoryGiB,
                    unit: "GiB",
                    accessibilityIdentifier: "builder-memory-field"
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
            .padding(4)
        } label: {
            Label("Builder Resources", systemImage: "hammer")
                .font(.headline)
        }
        .frame(maxWidth: .infinity)
    }

    private var networking: some View {
        GroupBox {
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
            .padding(4)
        } label: {
            Label("Networking", systemImage: "network")
                .font(.headline)
        }
        .frame(maxWidth: .infinity)
    }

    private var uninstall: some View {
        GroupBox {
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
            .padding(4)
        } label: {
            Label("Uninstall", systemImage: "trash")
                .font(.headline)
        }
        .frame(maxWidth: .infinity)
    }

    private var uninstallConfirmation: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Uninstall cengine?").font(.title2.bold())
            Text("Services, Docker integration, the app, and CLI will be removed.")
            Toggle("Delete containers, images, and volumes", isOn: $deleteData)
            Text(deleteData ? "Engine data will be permanently deleted." : "Engine data will be preserved.")
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

struct NumericSettingField: View {
    let label: String
    @Binding var value: Int
    let range: ClosedRange<Int>
    let unit: String
    let accessibilityIdentifier: String

    var body: some View {
        LabeledContent(label) {
            HStack(spacing: 8) {
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
}

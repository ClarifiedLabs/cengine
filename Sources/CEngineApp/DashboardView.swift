import SwiftUI

struct DashboardView: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var navigation: AppNavigation

    private let cardColumns = [GridItem(.adaptive(minimum: 145), spacing: 12)]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header
                serviceMessages
                if let snapshot = model.snapshot {
                    metrics(snapshot)
                    HStack(alignment: .top, spacing: 16) {
                        storageAndDefaults(snapshot)
                        environment(snapshot)
                    }
                    recentContainers(snapshot)
                } else {
                    ContentUnavailableView(
                        unavailableTitle,
                        systemImage: unavailableSystemImage,
                        description: Text(unavailableDescription)
                    )
                    .frame(maxWidth: .infinity, minHeight: 280)
                }
            }
            .padding(24)
            .frame(maxWidth: 1_100, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .center)
        }
        .navigationTitle("Dashboard")
    }

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 10) {
                    Text("cengine").font(.largeTitle.bold())
                    StatusBadge(
                        text: model.engineStatus,
                        color: StatusBadge.color(for: model.engineStatus)
                    )
                    if model.snapshotIsStale {
                        StatusBadge(text: "Stale", color: .orange)
                    }
                }
                if let refreshedAt = model.snapshot?.refreshedAt {
                    Text("Updated \(AppFormat.relative(refreshedAt))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            Button {
                Task { await model.refresh() }
            } label: {
                if model.isRefreshing {
                    ProgressView().controlSize(.small)
                } else {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
            }
            .disabled(model.isRefreshing)
        }
    }

    @ViewBuilder private var serviceMessages: some View {
        if model.helperNeedsApproval {
            GroupBox {
                HStack(alignment: .center, spacing: 14) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.title2)
                        .foregroundStyle(.orange)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("VM networking needs administrator approval").font(.headline)
                        Text("Allow cengine in Login Items & Extensions before container networking can start.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Open System Settings…") { model.openNetworkingApproval() }
                }
                .padding(3)
            }
        }
        if let refreshError = model.refreshError {
            GroupBox {
                HStack(alignment: .center, spacing: 14) {
                    Image(systemName: "exclamationmark.circle.fill")
                        .font(.title2)
                        .foregroundStyle(.red)
                    Text(refreshError)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    if model.engineStatus == "Failed", model.engineServiceEnabled {
                        Button("Restart Engine") { Task { await model.restartEngineService() } }
                            .disabled(model.isManagingEngineService)
                    } else {
                        Button("Open Settings") { navigation.section = .settings }
                    }
                }
                .padding(3)
            }
        }
    }

    private var unavailableTitle: String {
        switch model.engineStatus {
        case "Failed": "Engine failed to start"
        case "Disabled": "Engine is disabled"
        case "Stopped": "Engine is stopped"
        default: "Engine is starting"
        }
    }

    private var unavailableSystemImage: String {
        switch model.engineStatus {
        case "Failed": "exclamationmark.triangle"
        case "Disabled", "Stopped": "stop.circle"
        default: "gearshape.2"
        }
    }

    private var unavailableDescription: String {
        switch model.engineStatus {
        case "Failed": "Review the failure above, then restart the engine when the problem is corrected."
        case "Disabled": "Enable the engine service in Settings to use cengine."
        case "Stopped": "Restart the engine service in Settings to continue."
        default: "Resource information will appear when the cengine service is ready."
        }
    }

    private func metrics(_ snapshot: EngineSnapshot) -> some View {
        LazyVGrid(columns: cardColumns, spacing: 12) {
            MetricCard(title: "Running", value: String(snapshot.info.ContainersRunning), icon: "play.fill", color: .green) {
                navigation.section = .containers
            }
            MetricCard(title: "Stopped", value: String(snapshot.info.ContainersStopped), icon: "stop.fill", color: .secondary) {
                navigation.section = .containers
            }
            MetricCard(title: "Images", value: String(snapshot.images.count), icon: "square.stack.3d.up", color: .blue) {
                navigation.section = .images
            }
            MetricCard(title: "Networks", value: String(snapshot.networks.count), icon: "network", color: .purple) {
                navigation.section = .networks
            }
            MetricCard(title: "Volumes", value: String(snapshot.volumes.count), icon: "externaldrive", color: .indigo) {
                navigation.section = .volumes
            }
        }
    }

    private func storageAndDefaults(_ snapshot: EngineSnapshot) -> some View {
        let volumeCapacity = snapshot.volumes.reduce(Int64(0)) { partial, volume in
            let (sum, overflow) = partial.addingReportingOverflow(volume.virtualCapacity)
            return overflow ? Int64.max : sum
        }
        return VStack(alignment: .leading, spacing: 16) {
            DetailGroup("Storage") {
                DetailRow(label: "Image layers", value: AppFormat.bytes(snapshot.imageLayerBytes))
                DetailRow(label: "Volume virtual capacity", value: AppFormat.bytes(volumeCapacity))
            }
            DetailGroup("Resource defaults") {
                DetailRow(
                    label: "New containers",
                    value: "\(model.containerCPUs) CPUs · \(model.containerMemoryGiB) GiB"
                )
                DetailRow(
                    label: "Builder VM",
                    value: "\(model.builderCPUs) CPUs · \(model.builderMemoryGiB) GiB"
                )
                GridRow {
                    Color.clear.frame(width: 1, height: 1)
                    Button("Open Settings") { navigation.section = .settings }
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    private func environment(_ snapshot: EngineSnapshot) -> some View {
        DetailGroup("Engine") {
            DetailRow(label: "Version", value: snapshot.version.Version, selectable: true)
            DetailRow(label: "Docker API", value: snapshot.version.ApiVersion)
            DetailRow(label: "Driver", value: snapshot.info.Driver)
            DetailRow(label: "Architecture", value: snapshot.info.Architecture)
            DetailRow(label: "Kernel", value: snapshot.version.KernelVersion)
            DetailRow(label: "VM networking", value: model.helperStatus)
            DetailRow(label: "Git commit", value: snapshot.version.GitCommit, selectable: true)
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    private func recentContainers(_ snapshot: EngineSnapshot) -> some View {
        let recent = snapshot.containers.sorted { $0.createdAt > $1.createdAt }.prefix(5)
        return GroupBox {
            if recent.isEmpty {
                ContentUnavailableView("No containers", systemImage: "shippingbox")
                    .frame(maxWidth: .infinity, minHeight: 100)
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(recent)) { container in
                        Button {
                            navigation.showContainer(container.id)
                        } label: {
                            HStack(spacing: 12) {
                                StatusBadge(
                                    text: container.State,
                                    color: StatusBadge.color(for: container.State)
                                )
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(container.name).fontWeight(.medium)
                                    Text(container.Image).font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                Text(AppFormat.relative(container.createdAt))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                Image(systemName: "chevron.right").foregroundStyle(.tertiary)
                            }
                            .padding(.vertical, 8)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        if container.id != recent.last?.id { Divider() }
                    }
                }
            }
        } label: {
            Text("Recent containers").font(.headline)
        }
    }
}

private struct MetricCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            GroupBox {
                HStack {
                    VStack(alignment: .leading, spacing: 5) {
                        Text(value).font(.title.bold()).monospacedDigit()
                        Text(title).font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Image(systemName: icon).font(.title2).foregroundStyle(color)
                }
                .padding(4)
            }
        }
        .buttonStyle(.plain)
    }
}

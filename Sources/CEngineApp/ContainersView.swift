import SwiftUI

struct ContainersView: View {
    @EnvironmentObject private var model: AppModel
    @Binding var selection: String?
    @State private var searchText = ""
    @State private var sortOrder = [KeyPathComparator(\ContainerSummary.name)]

    private var rows: [ContainerSummary] {
        let values = model.containers.filter { container in
            searchText.isEmpty
                || container.name.localizedCaseInsensitiveContains(searchText)
                || container.Image.localizedCaseInsensitiveContains(searchText)
                || container.Id.localizedCaseInsensitiveContains(searchText)
                || container.Labels.contains { key, value in
                    key.localizedCaseInsensitiveContains(searchText)
                        || value.localizedCaseInsensitiveContains(searchText)
                }
        }
        return values.sorted(using: sortOrder)
    }

    var body: some View {
        HSplitView {
            VStack(spacing: 0) {
                ResourceHeader(title: "Containers", count: model.containers.count)
                if rows.isEmpty {
                    ContentUnavailableView(
                        searchText.isEmpty ? "No containers" : "No matching containers",
                        systemImage: "shippingbox",
                        description: Text(searchText.isEmpty ? "Containers created through Docker or Compose will appear here." : "Try a different search.")
                    )
                } else {
                    Table(rows, selection: $selection, sortOrder: $sortOrder) {
                        TableColumn("Name", value: \ContainerSummary.name)
                        TableColumn("State", value: \ContainerSummary.State) { container in
                            StatusBadge(
                                text: container.stateDisplay,
                                color: StatusBadge.color(for: container.Health?.Status ?? container.State)
                            )
                        }
                        TableColumn("Image", value: \ContainerSummary.Image)
                        TableColumn("Ports", value: \ContainerSummary.portsDisplay)
                        TableColumn("Created", value: \ContainerSummary.createdAt) { container in
                            Text(AppFormat.relative(container.createdAt))
                        }
                    }
                }
            }
            .frame(minWidth: 430, maxHeight: .infinity)

            Group {
                if let id = selection, let container = model.containers.first(where: { $0.id == id }) {
                    ContainerInspector(container: container)
                } else {
                    ContentUnavailableView(
                        "Select a container",
                        systemImage: "shippingbox",
                        description: Text("Inspect configuration, live usage, networking, storage, and logs.")
                    )
                }
            }
            .frame(minWidth: 340, idealWidth: 420, maxHeight: .infinity)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .searchable(text: $searchText, prompt: "Search containers")
        .navigationTitle("Containers")
        .onChange(of: model.containers.map(\.id)) { _, ids in
            if let selection, !ids.contains(selection) { self.selection = nil }
        }
    }
}

private struct ContainerInspector: View {
    enum Tab: String, CaseIterable, Identifiable {
        case overview = "Overview"
        case logs = "Logs"
        var id: Self { self }
    }

    @EnvironmentObject private var model: AppModel
    let container: ContainerSummary
    @State private var tab: Tab = .overview

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .top, spacing: 10) {
                    VStack(alignment: .leading, spacing: 5) {
                        Text(container.name).font(.title2.bold()).textSelection(.enabled)
                        HStack {
                            StatusBadge(
                                text: container.stateDisplay,
                                color: StatusBadge.color(for: container.Health?.Status ?? container.State)
                            )
                            Text(container.shortID)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                        }
                    }
                    Spacer()
                    lifecycleActions
                }
                Picker("Container detail", selection: $tab) {
                    ForEach(Tab.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
            }
            .padding(18)
            Divider()
            switch tab {
            case .overview: ContainerOverview(container: container)
            case .logs: ContainerLogs(container: container)
            }
        }
        .task(id: container.id) { await model.loadContainerDetail(container.id) }
    }

    @ViewBuilder private var lifecycleActions: some View {
        let pending = model.containerActionInProgress == container.id
        if pending {
            ProgressView().controlSize(.small).padding(.top, 5)
        } else if container.isStartable {
            Button {
                Task { await model.perform(.start, on: container.id) }
            } label: {
                Label("Start", systemImage: "play.fill")
            }
            .disabled(model.snapshotIsStale)
        } else if container.isRunning {
            HStack(spacing: 7) {
                Button {
                    Task { await model.perform(.stop, on: container.id) }
                } label: {
                    Label("Stop", systemImage: "stop.fill")
                }
                .disabled(model.snapshotIsStale)
                Button {
                    Task { await model.perform(.restart, on: container.id) }
                } label: {
                    Label("Restart", systemImage: "arrow.clockwise")
                }
                .disabled(model.snapshotIsStale)
            }
        }
    }
}

private struct ContainerOverview: View {
    @EnvironmentObject private var model: AppModel
    let container: ContainerSummary

    private var detail: ContainerDetail? { model.containerDetails[container.id] }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                if let error = model.detailErrors[container.id] {
                    InlineMessage(systemImage: "exclamationmark.circle", text: error, color: .red)
                }
                runtime
                resources
                connectivity
                storage
                configuration
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .task(id: "stats:\(container.id):\(container.State)") {
            while !Task.isCancelled {
                await model.loadContainerStatistics(container.id)
                try? await Task.sleep(for: .seconds(3))
            }
        }
    }

    private var runtime: some View {
        DetailGroup("Runtime") {
            DetailRow(label: "Image", value: container.Image, selectable: true)
            DetailRow(label: "Command", value: detail?.Config.Cmd.joined(separator: " ") ?? container.Command, selectable: true)
            DetailRow(label: "Created", value: detail.map { AppFormat.dockerDate($0.Created) } ?? AppFormat.date(container.createdAt))
            DetailRow(label: "Started", value: detail.map { AppFormat.dockerDate($0.State.StartedAt) } ?? "—")
            DetailRow(label: "Finished", value: detail.map { AppFormat.dockerDate($0.State.FinishedAt) } ?? "—")
            DetailRow(label: "Exit code", value: detail.map { String($0.State.ExitCode) } ?? "—")
            DetailRow(label: "Restarts", value: detail.map { String($0.RestartCount) } ?? "—")
        }
    }

    private var resources: some View {
        let telemetry = model.containerTelemetry[container.id]
        return DetailGroup("Resources") {
            DetailRow(
                label: "CPU limit",
                value: detail.map { String(max($0.HostConfig.NanoCpus / 1_000_000_000, 1)) } ?? "—"
            )
            DetailRow(
                label: "CPU usage",
                value: telemetry?.cpuPercentage.map { String(format: "%.1f%%", $0) } ?? "Collecting…"
            )
            DetailRow(label: "Memory limit", value: detail.map { AppFormat.bytes($0.HostConfig.Memory) } ?? "—")
            DetailRow(
                label: "Memory usage",
                value: telemetry.map { "\(AppFormat.bytes($0.memoryUsage)) / \(AppFormat.bytes($0.memoryLimit))" } ?? "—"
            )
            DetailRow(label: "Processes", value: telemetry.map { String($0.pids) } ?? "—")
            DetailRow(
                label: "Block I/O",
                value: telemetry.map { "↓ \(AppFormat.bytes($0.blockReadBytes))  ↑ \(AppFormat.bytes($0.blockWriteBytes))" } ?? "—"
            )
            DetailRow(
                label: "Network I/O",
                value: telemetry.map { "↓ \(AppFormat.bytes($0.networkReceiveBytes))  ↑ \(AppFormat.bytes($0.networkTransmitBytes))" } ?? "—"
            )
        }
    }

    private var connectivity: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                if container.Ports.isEmpty {
                    Text("No published ports").foregroundStyle(.secondary)
                } else {
                    ForEach(container.Ports, id: \.self) { port in
                        Label(port.display, systemImage: "arrow.left.arrow.right")
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                    }
                }
                Divider()
                if let networks = detail?.NetworkSettings.Networks, !networks.isEmpty {
                    ForEach(networks.keys.sorted(), id: \.self) { name in
                        let endpoint = networks[name]
                        VStack(alignment: .leading, spacing: 3) {
                            Text(name).fontWeight(.medium)
                            Text(networkAddress(endpoint))
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                        }
                    }
                } else {
                    Text("No attached networks").foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(3)
        } label: {
            Text("Connectivity").font(.headline)
        }
    }

    private var storage: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 9) {
                if let mounts = detail?.Mounts, !mounts.isEmpty {
                    ForEach(mounts, id: \.self) { mount in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(mount.Destination).fontWeight(.medium).textSelection(.enabled)
                            Text("\(mount.Type) · \(mount.Source) · \(mount.RW ? "read/write" : "read-only")")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                        }
                    }
                } else {
                    Text("No mounts").foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(3)
        } label: {
            Text("Storage").font(.headline)
        }
    }

    private var configuration: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                DetailLabel("Working directory", detail?.Config.WorkingDir ?? "—")
                DetailLabel("User", detail?.Config.User.isEmpty == false ? detail?.Config.User ?? "—" : "default")
                DetailLabel("Hostname", detail?.Config.Hostname ?? "—")
                DetailLabel("Restart policy", detail?.HostConfig.RestartPolicy.Name ?? "—")
                DetailLabel("Privileged", detail.map { $0.HostConfig.Privileged ? "Yes" : "No" } ?? "—")
                Divider()
                Text("Labels").font(.caption).foregroundStyle(.secondary)
                KeyValueRows(values: detail?.Config.Labels ?? container.Labels)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(3)
        } label: {
            Text("Configuration").font(.headline)
        }
    }

    private func networkAddress(_ endpoint: ContainerDetail.EndpointResponse?) -> String {
        guard let endpoint else { return "—" }
        return [
            endpoint.IPAddress.isEmpty ? nil : "\(endpoint.IPAddress)/\(endpoint.IPPrefixLen)",
            endpoint.GlobalIPv6Address.isEmpty ? nil : "\(endpoint.GlobalIPv6Address)/\(endpoint.GlobalIPv6PrefixLen)",
        ].compactMap { $0 }.joined(separator: " · ")
    }
}

private struct ContainerLogs: View {
    @EnvironmentObject private var model: AppModel
    let container: ContainerSummary

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Last 500 lines").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button {
                    Task { await model.loadContainerLogs(container.id) }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .controlSize(.small)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
            Divider()
            if let error = model.detailErrors["logs:\(container.id)"] {
                ContentUnavailableView("Logs unavailable", systemImage: "exclamationmark.circle", description: Text(error))
            } else if let lines = model.containerLogs[container.id], !lines.isEmpty {
                ScrollView([.horizontal, .vertical]) {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(lines) { line in
                            HStack(alignment: .firstTextBaseline, spacing: 8) {
                                Text(line.stream == .stderr ? "ERR" : line.stream == .stdout ? "OUT" : "TTY")
                                    .font(.caption2.monospaced().bold())
                                    .foregroundStyle(line.stream == .stderr ? .red : .secondary)
                                Text(line.text)
                                    .font(.system(.caption, design: .monospaced))
                                    .textSelection(.enabled)
                            }
                        }
                    }
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .background(Color(nsColor: .textBackgroundColor))
            } else {
                ContentUnavailableView("No log output", systemImage: "text.alignleft")
            }
        }
        .task(id: "logs:\(container.id)") {
            while !Task.isCancelled {
                await model.loadContainerLogs(container.id)
                try? await Task.sleep(for: .seconds(3))
            }
        }
    }
}

private struct DetailLabel: View {
    let label: String
    let value: String

    init(_ label: String, _ value: String) {
        self.label = label
        self.value = value
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label).foregroundStyle(.secondary)
            Spacer(minLength: 12)
            Text(value).textSelection(.enabled)
        }
    }
}

struct ResourceHeader: View {
    @EnvironmentObject private var model: AppModel
    let title: String
    let count: Int

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(title).font(.title2.bold())
            Text(String(count)).font(.caption).foregroundStyle(.secondary)
            Spacer()
            if model.snapshotIsStale { StatusBadge(text: "Stale", color: .orange) }
            Button {
                Task { await model.refresh() }
            } label: {
                if model.isRefreshing {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: "arrow.clockwise")
                }
            }
            .buttonStyle(.borderless)
            .help("Refresh")
            .disabled(model.isRefreshing)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
    }
}

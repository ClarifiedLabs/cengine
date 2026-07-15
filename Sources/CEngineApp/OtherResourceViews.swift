import SwiftUI

struct ImagesView: View {
    @EnvironmentObject private var model: AppModel
    @Binding var selection: String?
    @State private var searchText = ""
    @State private var sortOrder = [KeyPathComparator(\ImageSummary.createdAt, order: .reverse)]

    private var rows: [ImageSummary] {
        model.images.filter { image in
            searchText.isEmpty
                || image.Id.localizedCaseInsensitiveContains(searchText)
                || (image.RepoTags + image.RepoDigests).contains {
                    $0.localizedCaseInsensitiveContains(searchText)
                }
                || image.Labels.contains { key, value in
                    key.localizedCaseInsensitiveContains(searchText)
                        || value.localizedCaseInsensitiveContains(searchText)
                }
        }.sorted(using: sortOrder)
    }

    var body: some View {
        HSplitView {
            VStack(spacing: 0) {
                ResourceHeader(title: "Images", count: model.images.count)
                if rows.isEmpty {
                    ResourceEmptyState(
                        title: searchText.isEmpty ? "No images" : "No matching images",
                        icon: "square.stack.3d.up"
                    )
                } else {
                    Table(rows, selection: $selection, sortOrder: $sortOrder) {
                        TableColumn("Repository / tag", value: \ImageSummary.referencesDisplay)
                        TableColumn("Size", value: \ImageSummary.Size) { image in
                            Text(AppFormat.bytes(image.Size))
                        }
                        TableColumn("Containers", value: \ImageSummary.Containers) { image in
                            Text(image.Containers < 0 ? "—" : String(image.Containers))
                        }
                        TableColumn("Created", value: \ImageSummary.createdAt) { image in
                            Text(AppFormat.relative(image.createdAt))
                        }
                    }
                }
            }
            .frame(minWidth: 430)
            Group {
                if let id = selection, let image = model.images.first(where: { $0.id == id }) {
                    ImageInspector(image: image)
                } else {
                    ResourceSelectionState(title: "Select an image", icon: "square.stack.3d.up")
                }
            }
            .frame(minWidth: 340, idealWidth: 420)
        }
        .searchable(text: $searchText, prompt: "Search images")
        .navigationTitle("Images")
        .onChange(of: model.images.map(\.id)) { _, ids in
            if let selection, !ids.contains(selection) { self.selection = nil }
        }
    }
}

private struct ImageInspector: View {
    @EnvironmentObject private var model: AppModel
    let image: ImageSummary

    private var detail: ImageDetail? { model.imageDetails[image.id] }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                InspectorTitle(title: image.primaryReference, subtitle: image.shortID, state: nil)
                if let error = model.detailErrors[image.id] {
                    InlineMessage(systemImage: "exclamationmark.circle", text: error, color: .red)
                }
                DetailGroup("Image") {
                    DetailRow(label: "ID", value: image.Id, selectable: true)
                    DetailRow(label: "Size", value: AppFormat.bytes(image.Size))
                    DetailRow(label: "Created", value: AppFormat.date(image.createdAt))
                    DetailRow(label: "Architecture", value: detail?.Architecture ?? "Loading…")
                    DetailRow(label: "Operating system", value: detail?.Os ?? "Loading…")
                    DetailRow(
                        label: "Containers",
                        value: image.Containers < 0 ? "—" : String(image.Containers)
                    )
                }
                ReferenceGroup(title: "Tags", values: image.RepoTags)
                ReferenceGroup(title: "Digests", values: image.RepoDigests)
                GroupBox {
                    KeyValueRows(values: detail?.Config.Labels ?? image.Labels)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(3)
                } label: {
                    Text("Labels").font(.headline)
                }
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .task(id: image.id) { await model.loadImageDetail(image.id) }
    }
}

struct NetworksView: View {
    @EnvironmentObject private var model: AppModel
    @Binding var selection: String?
    @State private var searchText = ""
    @State private var sortOrder = [KeyPathComparator(\NetworkSummary.Name)]

    private var rows: [NetworkSummary] {
        model.networks.filter { network in
            searchText.isEmpty
                || network.Name.localizedCaseInsensitiveContains(searchText)
                || network.Id.localizedCaseInsensitiveContains(searchText)
                || network.Labels.contains { key, value in
                    key.localizedCaseInsensitiveContains(searchText)
                        || value.localizedCaseInsensitiveContains(searchText)
                }
        }.sorted(using: sortOrder)
    }

    var body: some View {
        HSplitView {
            VStack(spacing: 0) {
                ResourceHeader(title: "Networks", count: model.networks.count)
                if rows.isEmpty {
                    ResourceEmptyState(
                        title: searchText.isEmpty ? "No networks" : "No matching networks",
                        icon: "network"
                    )
                } else {
                    Table(rows, selection: $selection, sortOrder: $sortOrder) {
                        TableColumn("Name", value: \NetworkSummary.Name)
                        TableColumn("Mode", value: \NetworkSummary.modeDisplay)
                        TableColumn("IPv4 subnet", value: \NetworkSummary.ipv4SubnetDisplay)
                        TableColumn("IPv6 subnet", value: \NetworkSummary.ipv6SubnetDisplay)
                        TableColumn("Containers", value: \NetworkSummary.Id) { network in
                            Text(String(model.containersAttached(to: network).count))
                        }
                    }
                }
            }
            .frame(minWidth: 430)
            Group {
                if let id = selection, let network = model.networks.first(where: { $0.id == id }) {
                    NetworkInspector(network: network)
                } else {
                    ResourceSelectionState(title: "Select a network", icon: "network")
                }
            }
            .frame(minWidth: 340, idealWidth: 420)
        }
        .searchable(text: $searchText, prompt: "Search networks")
        .navigationTitle("Networks")
        .onChange(of: model.networks.map(\.id)) { _, ids in
            if let selection, !ids.contains(selection) { self.selection = nil }
        }
    }
}

private struct NetworkInspector: View {
    @EnvironmentObject private var model: AppModel
    let network: NetworkSummary

    private var attached: [ContainerSummary] { model.containersAttached(to: network) }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                InspectorTitle(title: network.Name, subtitle: network.shortID, state: network.modeDisplay)
                InlineMessage(systemImage: "network", text: network.reachabilityDescription)
                DetailGroup("Network") {
                    DetailRow(label: "ID", value: network.Id, selectable: true)
                    DetailRow(label: "Driver", value: network.Driver)
                    DetailRow(label: "Scope", value: network.Scope)
                    DetailRow(label: "Created", value: AppFormat.date(network.createdAt))
                    DetailRow(label: "Internal", value: network.Internal ? "Yes" : "No")
                    DetailRow(label: "IPv4 gateway mode", value: network.ipv4Mode)
                    DetailRow(label: "IPv6 gateway mode", value: network.ipv6Mode)
                }
                DetailGroup("Addressing") {
                    DetailRow(label: "IPv4 subnet", value: network.ipv4?.Subnet ?? "—", selectable: true)
                    DetailRow(label: "IPv4 gateway", value: network.ipv4?.Gateway ?? "—", selectable: true)
                    DetailRow(label: "IPv6 subnet", value: network.ipv6?.Subnet ?? "—", selectable: true)
                    DetailRow(label: "IPv6 gateway", value: network.ipv6?.Gateway ?? "—", selectable: true)
                }
                AttachedContainersGroup(containers: attached)
                MetadataGroups(labels: network.Labels, options: network.Options)
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct VolumesView: View {
    @EnvironmentObject private var model: AppModel
    @Binding var selection: String?
    @State private var searchText = ""
    @State private var sortOrder = [KeyPathComparator(\VolumeSummary.Name)]

    private var rows: [VolumeSummary] {
        model.volumes.filter { volume in
            searchText.isEmpty
                || volume.Name.localizedCaseInsensitiveContains(searchText)
                || volume.Labels.contains { key, value in
                    key.localizedCaseInsensitiveContains(searchText)
                        || value.localizedCaseInsensitiveContains(searchText)
                }
        }.sorted(using: sortOrder)
    }

    var body: some View {
        HSplitView {
            VStack(spacing: 0) {
                ResourceHeader(title: "Volumes", count: model.volumes.count)
                if rows.isEmpty {
                    ResourceEmptyState(
                        title: searchText.isEmpty ? "No volumes" : "No matching volumes",
                        icon: "externaldrive"
                    )
                } else {
                    Table(rows, selection: $selection, sortOrder: $sortOrder) {
                        TableColumn("Name", value: \VolumeSummary.Name)
                        TableColumn("Virtual capacity", value: \VolumeSummary.virtualCapacity) { volume in
                            Text(AppFormat.bytes(volume.virtualCapacity))
                        }
                        TableColumn("In use", value: \VolumeSummary.referenceCount) { volume in
                            Text(volume.referenceCount == 0 ? "No" : "\(volume.referenceCount) container(s)")
                        }
                        TableColumn("Created", value: \VolumeSummary.CreatedAt) { volume in
                            Text(AppFormat.date(volume.createdAt))
                        }
                    }
                }
            }
            .frame(minWidth: 430)
            Group {
                if let id = selection, let volume = model.volumes.first(where: { $0.id == id }) {
                    VolumeInspector(volume: volume)
                } else {
                    ResourceSelectionState(title: "Select a volume", icon: "externaldrive")
                }
            }
            .frame(minWidth: 340, idealWidth: 420)
        }
        .searchable(text: $searchText, prompt: "Search volumes")
        .navigationTitle("Volumes")
        .onChange(of: model.volumes.map(\.id)) { _, ids in
            if let selection, !ids.contains(selection) { self.selection = nil }
        }
    }
}

private struct VolumeInspector: View {
    @EnvironmentObject private var model: AppModel
    let volume: VolumeSummary

    private var consumers: [ContainerSummary] {
        let ids = Set(model.volumeConsumerIDs[volume.Name] ?? [])
        return model.containers.filter { ids.contains($0.id) }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                InspectorTitle(
                    title: volume.Name,
                    subtitle: volume.Driver,
                    state: volume.referenceCount == 0 ? "Unused" : "In use"
                )
                InlineMessage(
                    systemImage: "info.circle",
                    text: "Capacity is the volume's virtual maximum, not allocated disk usage."
                )
                DetailGroup("Volume") {
                    DetailRow(label: "Driver", value: volume.Driver)
                    DetailRow(label: "Scope", value: volume.Scope)
                    DetailRow(label: "Created", value: AppFormat.date(volume.createdAt))
                    DetailRow(label: "Virtual capacity", value: AppFormat.bytes(volume.virtualCapacity))
                    DetailRow(label: "References", value: String(volume.referenceCount))
                    DetailRow(label: "Mountpoint", value: volume.Mountpoint, selectable: true)
                }
                AttachedContainersGroup(containers: consumers)
                MetadataGroups(labels: volume.Labels, options: volume.Options)
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .task(id: "\(volume.Name):\(model.containers.map(\.id).joined(separator: ","))") {
            await model.loadVolumeConsumers(volume.Name)
        }
    }
}

private struct InspectorTitle: View {
    let title: String
    let subtitle: String
    let state: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.title2.bold()).textSelection(.enabled)
            HStack {
                if let state { StatusBadge(text: state, color: StatusBadge.color(for: state)) }
                Text(subtitle)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        }
    }
}

private struct ReferenceGroup: View {
    let title: String
    let values: [String]

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 5) {
                if values.isEmpty {
                    Text("None").foregroundStyle(.secondary)
                } else {
                    ForEach(values, id: \.self) { value in
                        Text(value).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(3)
        } label: {
            Text(title).font(.headline)
        }
    }
}

private struct AttachedContainersGroup: View {
    let containers: [ContainerSummary]

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                if containers.isEmpty {
                    Text("No attached containers").foregroundStyle(.secondary)
                } else {
                    ForEach(containers.sorted { $0.name < $1.name }) { container in
                        HStack {
                            Text(container.name).fontWeight(.medium)
                            Spacer()
                            StatusBadge(
                                text: container.State,
                                color: StatusBadge.color(for: container.State)
                            )
                        }
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(3)
        } label: {
            Text("Attached containers").font(.headline)
        }
    }
}

private struct MetadataGroups: View {
    let labels: [String: String]
    let options: [String: String]

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                Text("Labels").font(.caption).foregroundStyle(.secondary)
                KeyValueRows(values: labels)
                Divider()
                Text("Options").font(.caption).foregroundStyle(.secondary)
                KeyValueRows(values: options)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(3)
        } label: {
            Text("Metadata").font(.headline)
        }
    }
}

private struct ResourceEmptyState: View {
    let title: String
    let icon: String

    var body: some View {
        ContentUnavailableView(title, systemImage: icon)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

private struct ResourceSelectionState: View {
    let title: String
    let icon: String

    var body: some View {
        ContentUnavailableView(
            title,
            systemImage: icon,
            description: Text("Choose a row to inspect its configuration and relationships.")
        )
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

private extension NetworkSummary {
    var ipv4SubnetDisplay: String { ipv4?.Subnet ?? "—" }
    var ipv6SubnetDisplay: String { ipv6?.Subnet ?? "—" }
}

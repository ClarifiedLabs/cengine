import SwiftUI

enum AppLayout {
    static let minimumWindowWidth: CGFloat = 960
    static let minimumWindowHeight: CGFloat = 600
    static let sidebarWidth: CGFloat = 180
    static let maximumSidebarWidth: CGFloat = 220
    static let pagePadding: CGFloat = 24
    static let dashboardMaximumContentWidth: CGFloat = 1_100
    static let settingsMaximumContentWidth: CGFloat = 760
}

extension View {
    func appPageContent(maxWidth: CGFloat) -> some View {
        padding(AppLayout.pagePadding)
            .frame(maxWidth: maxWidth, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct AlignedIconLabelStyle: LabelStyle {
    var iconWidth: CGFloat = 18
    var spacing: CGFloat = 8

    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: spacing) {
            configuration.icon
                .frame(width: iconWidth)
            configuration.title
        }
    }
}

enum AppFormat {
    static func bytes(_ value: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: value, countStyle: .file)
    }

    static func bytes(_ value: UInt64) -> String {
        bytes(Int64(clamping: value))
    }

    static func date(_ value: Date?) -> String {
        guard let value else { return "—" }
        return value.formatted(date: .abbreviated, time: .shortened)
    }

    static func relative(_ value: Date) -> String {
        value.formatted(.relative(presentation: .named))
    }

    static func dockerDate(_ value: String) -> String {
        guard !value.hasPrefix("0001-"), !value.isEmpty else { return "—" }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let date = fractional.date(from: value) ?? ISO8601DateFormatter().date(from: value)
        return self.date(date)
    }
}

struct StatusBadge: View {
    let text: String
    var color: Color = .secondary

    var body: some View {
        Text(text.capitalized)
            .font(.caption.weight(.medium))
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .foregroundStyle(color)
            .background(color.opacity(0.12), in: Capsule())
    }

    static func color(for state: String) -> Color {
        switch state.lowercased() {
        case "running", "healthy": .green
        case "paused", "starting", "restarting": .orange
        case "exited", "created", "stopped", "disabled": .secondary
        case "dead", "unhealthy", "failed": .red
        default: .secondary
        }
    }
}

struct DetailGroup<Content: View>: View {
    let title: String
    @ViewBuilder let content: Content

    init(_ title: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }

    var body: some View {
        GroupBox {
            Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 8) {
                content
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(3)
        } label: {
            Text(title).font(.headline)
        }
    }
}

struct DetailRow: View {
    let label: String
    let value: String
    var selectable = false

    var body: some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value.isEmpty ? "—" : value)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct KeyValueRows: View {
    let values: [String: String]

    var body: some View {
        if values.isEmpty {
            Text("None").foregroundStyle(.secondary)
        } else {
            ForEach(values.keys.sorted(), id: \.self) { key in
                HStack(alignment: .firstTextBaseline) {
                    Text(key).foregroundStyle(.secondary)
                    Spacer(minLength: 16)
                    Text(values[key] ?? "")
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
        }
    }
}

struct InlineMessage: View {
    let systemImage: String
    let text: String
    var color: Color = .secondary

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: systemImage)
            Text(text).fixedSize(horizontal: false, vertical: true)
        }
        .font(.caption)
        .foregroundStyle(color)
    }
}

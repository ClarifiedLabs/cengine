import Foundation

protocol AppEngineClient: Sendable {
    func get(_ path: String) async throws -> Data
    func post(_ path: String, body: Data) async throws -> Data
}

extension DockerSocketClient: AppEngineClient {}

struct EngineSnapshot: Sendable {
    let version: VersionResponse
    let info: InfoResponse
    let containers: [ContainerSummary]
    let images: [ImageSummary]
    let networks: [NetworkSummary]
    let volumes: [VolumeSummary]
    let imageLayerBytes: Int64
    let refreshedAt: Date
}

struct VersionResponse: Decodable, Sendable {
    let Version: String
    let ApiVersion: String
    let GitCommit: String
    let BuildTime: String
    let Os: String
    let Arch: String
    let KernelVersion: String
}

struct InfoResponse: Decodable, Sendable {
    let Containers: Int
    let ContainersRunning: Int
    let ContainersPaused: Int
    let ContainersStopped: Int
    let Driver: String
    let DockerRootDir: String
    let Name: String
    let ServerVersion: String
    let OperatingSystem: String
    let Architecture: String
    let NCPU: Int
    let MemTotal: UInt64
}

struct ContainerSummary: Decodable, Identifiable, Hashable, Sendable {
    struct Port: Decodable, Hashable, Sendable {
        let IP: String
        let PrivatePort: UInt16
        let PublicPort: UInt16
        let `Type`: String

        var display: String {
            let host = IP.isEmpty || IP == "0.0.0.0" ? "localhost" : IP
            return "\(host):\(PublicPort) → \(PrivatePort)/\(`Type`)"
        }
    }

    struct NetworkSettingsSummary: Decodable, Hashable, Sendable {
        let Networks: [String: EndpointSummary]
    }

    struct EndpointSummary: Decodable, Hashable, Sendable {
        let NetworkID: String
    }

    struct HealthSummary: Decodable, Hashable, Sendable {
        let Status: String
        let FailingStreak: Int
    }

    let Id: String
    let Names: [String]
    let Image: String
    let Command: String
    let Created: Int64
    let State: String
    let Status: String
    let Ports: [Port]
    let Labels: [String: String]
    let NetworkSettings: NetworkSettingsSummary
    let Health: HealthSummary?

    var id: String { Id }
    var name: String {
        Names.first?.trimmingCharacters(in: CharacterSet(charactersIn: "/")) ?? String(Id.prefix(12))
    }
    var createdAt: Date { Date(timeIntervalSince1970: TimeInterval(Created)) }
    var shortID: String { String(Id.replacingOccurrences(of: "sha256:", with: "").prefix(12)) }
    var healthStatus: String? { Health.flatMap { $0.Status == "none" ? nil : $0.Status } }
    var stateDisplay: String { healthStatus.map { "\(State) · \($0)" } ?? State }
    var portsDisplay: String { Ports.map(\.display).joined(separator: ", ") }
    var networksDisplay: String { NetworkSettings.Networks.keys.sorted().joined(separator: ", ") }
    var isRunning: Bool { State == "running" || State == "paused" }
    var isStartable: Bool { State == "created" || State == "exited" || State == "dead" }
}

struct ImageSummary: Decodable, Identifiable, Hashable, Sendable {
    let Id: String
    let RepoTags: [String]
    let RepoDigests: [String]
    let Containers: Int
    let Created: Int64
    let Size: Int64
    let Labels: [String: String]

    var id: String { Id }
    var primaryReference: String { RepoTags.first ?? RepoDigests.first ?? shortID }
    var shortID: String { String(Id.replacingOccurrences(of: "sha256:", with: "").prefix(12)) }
    var createdAt: Date { Date(timeIntervalSince1970: TimeInterval(Created)) }
    var referencesDisplay: String {
        let count = RepoTags.count + RepoDigests.count
        return count > 1 ? "\(primaryReference) +\(count - 1)" : primaryReference
    }
}

struct NetworkSummary: Decodable, Identifiable, Hashable, Sendable {
    struct IPAMResponse: Decodable, Hashable, Sendable {
        let Driver: String
        let Config: [ConfigResponse]
    }

    struct ConfigResponse: Decodable, Hashable, Sendable {
        let Subnet: String
        let Gateway: String
    }

    let Name: String
    let Id: String
    let Created: String
    let Scope: String
    let Driver: String
    let EnableIPv6: Bool
    let IPAM: IPAMResponse
    let Internal: Bool
    let Options: [String: String]
    let Labels: [String: String]

    var id: String { Id }
    var shortID: String { String(Id.prefix(12)) }
    var ipv4: ConfigResponse? { IPAM.Config.first { !$0.Subnet.contains(":") } }
    var ipv6: ConfigResponse? { IPAM.Config.first { $0.Subnet.contains(":") } }
    var createdAt: Date? { ISO8601DateFormatter().date(from: Created) }
    var ipv4Mode: String { Options["com.docker.network.bridge.gateway_mode_ipv4"] ?? "nat" }
    var ipv6Mode: String { Options["com.docker.network.bridge.gateway_mode_ipv6"] ?? "nat" }
    var modeDisplay: String {
        guard Internal else { return "NAT" }
        if ipv4Mode == "isolated" && (ipv6?.Subnet.isEmpty != false || ipv6Mode == "isolated") { return "Isolated" }
        return "Internal"
    }
    var reachabilityDescription: String {
        switch modeDisplay {
        case "NAT": "Peers, macOS host services, and Internet access"
        case "Isolated": "Network peers only; no host or Internet access"
        default: "Network peers and macOS host services; no Internet access"
        }
    }
}

struct VolumeSummary: Decodable, Identifiable, Hashable, Sendable {
    struct Usage: Decodable, Hashable, Sendable {
        let RefCount: Int
        let Size: Int64
    }

    let Name: String
    let Driver: String
    let Mountpoint: String
    let CreatedAt: String
    let Labels: [String: String]
    let Scope: String
    let Options: [String: String]
    let UsageData: Usage?

    var id: String { Name }
    var createdAt: Date? { ISO8601DateFormatter().date(from: CreatedAt) }
    var virtualCapacity: Int64 { UsageData?.Size ?? 0 }
    var referenceCount: Int { UsageData?.RefCount ?? 0 }
}

struct DiskUsageResponse: Decodable, Sendable {
    let LayersSize: Int64
    let Volumes: [VolumeSummary]
}

struct ContainerDetail: Decodable, Sendable {
    struct StateResponse: Decodable, Sendable {
        let Status: String
        let Running: Bool
        let Paused: Bool
        let OOMKilled: Bool
        let Dead: Bool
        let ExitCode: Int32
        let Error: String
        let StartedAt: String
        let FinishedAt: String
        let Health: HealthStateResponse?
    }

    struct HealthStateResponse: Decodable, Sendable {
        let Status: String
        let FailingStreak: Int
    }

    struct ConfigResponse: Decodable, Sendable {
        let Hostname: String
        let User: String
        let Tty: Bool
        let Env: [String]
        let Cmd: [String]
        let Image: String
        let WorkingDir: String
        let Labels: [String: String]
    }

    struct HostConfigResponse: Decodable, Sendable {
        struct RestartPolicy: Decodable, Sendable {
            let Name: String
            let MaximumRetryCount: Int
        }

        let Memory: UInt64
        let NanoCpus: Int64
        let AutoRemove: Bool
        let Privileged: Bool
        let ReadonlyRootfs: Bool
        let Init: Bool
        let RestartPolicy: RestartPolicy
        let NetworkMode: String
    }

    struct MountResponse: Decodable, Hashable, Sendable {
        let `Type`: String
        let Name: String?
        let Source: String
        let Destination: String
        let Driver: String
        let RW: Bool
    }

    struct NetworkSettingsResponse: Decodable, Sendable {
        let Networks: [String: EndpointResponse]
    }

    struct EndpointResponse: Decodable, Sendable {
        let Aliases: [String]
        let NetworkID: String
        let Gateway: String
        let IPAddress: String
        let IPPrefixLen: Int
        let IPv6Gateway: String
        let GlobalIPv6Address: String
        let GlobalIPv6PrefixLen: Int
        let DNSNames: [String]
    }

    let Id: String
    let Name: String
    let Created: String
    let Path: String
    let Args: [String]
    let Image: String
    let State: StateResponse
    let Config: ConfigResponse
    let RestartCount: Int
    let NetworkSettings: NetworkSettingsResponse
    let HostConfig: HostConfigResponse
    let Mounts: [MountResponse]
}

struct ImageDetail: Decodable, Sendable {
    struct ConfigResponse: Decodable, Sendable {
        let Labels: [String: String]?
    }

    let Id: String
    let RepoTags: [String]
    let RepoDigests: [String]
    let Created: String
    let Architecture: String
    let Os: String
    let Size: Int64
    let Config: ConfigResponse
}

struct ContainerStatsSample: Decodable, Sendable {
    struct PIDs: Decodable, Sendable { let current: UInt64 }
    struct BlockIO: Decodable, Sendable {
        struct Entry: Decodable, Sendable { let op: String; let value: UInt64 }
        let io_service_bytes_recursive: [Entry]
    }
    struct CPU: Decodable, Sendable {
        struct Usage: Decodable, Sendable { let total_usage: UInt64 }
        let cpu_usage: Usage
        let online_cpus: Int
    }
    struct Memory: Decodable, Sendable { let usage: UInt64; let limit: UInt64 }
    struct Network: Decodable, Sendable { let rx_bytes: UInt64; let tx_bytes: UInt64 }

    let read: String
    let pids_stats: PIDs
    let blkio_stats: BlockIO
    let cpu_stats: CPU
    let memory_stats: Memory
    let networks: [String: Network]

    var readAt: Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: read)
    }
}

struct ContainerTelemetry: Sendable {
    let cpuPercentage: Double?
    let memoryUsage: UInt64
    let memoryLimit: UInt64
    let pids: UInt64
    let blockReadBytes: UInt64
    let blockWriteBytes: UInt64
    let networkReceiveBytes: UInt64
    let networkTransmitBytes: UInt64

    init(sample: ContainerStatsSample, previous: ContainerStatsSample?) {
        if let previous,
           let readAt = sample.readAt,
           let previousReadAt = previous.readAt,
           sample.cpu_stats.cpu_usage.total_usage >= previous.cpu_stats.cpu_usage.total_usage,
           readAt > previousReadAt {
            let cpuDelta = sample.cpu_stats.cpu_usage.total_usage - previous.cpu_stats.cpu_usage.total_usage
            cpuPercentage = Double(cpuDelta) / 1_000_000_000 / readAt.timeIntervalSince(previousReadAt) * 100
        } else {
            cpuPercentage = nil
        }
        memoryUsage = sample.memory_stats.usage
        memoryLimit = sample.memory_stats.limit
        pids = sample.pids_stats.current
        blockReadBytes = sample.blkio_stats.io_service_bytes_recursive
            .filter { $0.op.caseInsensitiveCompare("read") == .orderedSame }
            .reduce(0) { $0 + $1.value }
        blockWriteBytes = sample.blkio_stats.io_service_bytes_recursive
            .filter { $0.op.caseInsensitiveCompare("write") == .orderedSame }
            .reduce(0) { $0 + $1.value }
        networkReceiveBytes = sample.networks.values.reduce(0) { $0 + $1.rx_bytes }
        networkTransmitBytes = sample.networks.values.reduce(0) { $0 + $1.tx_bytes }
    }
}

struct ContainerLogLine: Identifiable, Hashable, Sendable {
    enum Stream: String, Sendable { case stdout, stderr, terminal }
    let id: Int
    let stream: Stream
    let text: String
}

enum DockerLogParser {
    static func parse(_ data: Data, tty: Bool, limit: Int = 500) -> [ContainerLogLine] {
        if tty { return lines(in: data, stream: .terminal, startingAt: 0).suffix(limit).map { $0 } }
        let bytes = [UInt8](data)
        var offset = 0
        var values: [ContainerLogLine] = []
        while offset + 8 <= bytes.count {
            guard let stream = stream(bytes[offset]) else {
                return lines(in: data, stream: .terminal, startingAt: 0).suffix(limit).map { $0 }
            }
            let length = Int(bytes[offset + 4]) << 24
                | Int(bytes[offset + 5]) << 16
                | Int(bytes[offset + 6]) << 8
                | Int(bytes[offset + 7])
            let payloadStart = offset + 8
            guard length >= 0, payloadStart + length <= bytes.count else { break }
            let payload = Data(bytes[payloadStart..<(payloadStart + length)])
            values.append(contentsOf: lines(in: payload, stream: stream, startingAt: values.count))
            offset = payloadStart + length
        }
        if values.isEmpty, !data.isEmpty {
            values = lines(in: data, stream: .terminal, startingAt: 0)
        }
        return Array(values.suffix(limit)).enumerated().map {
            ContainerLogLine(id: $0.offset, stream: $0.element.stream, text: $0.element.text)
        }
    }

    private static func stream(_ byte: UInt8) -> ContainerLogLine.Stream? {
        switch byte {
        case 1: .stdout
        case 2: .stderr
        default: nil
        }
    }

    private static func lines(
        in data: Data,
        stream: ContainerLogLine.Stream,
        startingAt start: Int
    ) -> [ContainerLogLine] {
        let value = String(decoding: data, as: UTF8.self)
        let parts = value.split(separator: "\n", omittingEmptySubsequences: false)
        let content = parts.prefix(value.hasSuffix("\n") ? max(parts.count - 1, 0) : parts.count)
        return content.enumerated().map {
            ContainerLogLine(id: start + $0.offset, stream: stream, text: String($0.element))
        }
    }
}

enum ContainerAction: String, Sendable {
    case start, stop, restart
}

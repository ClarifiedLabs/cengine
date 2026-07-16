import CEngineCore
import CEngineRuntime
import Foundation

public struct DockerErrorBody: Codable, Sendable { public let message: String }
public struct ContainerResourceScopeCreateRequest: Codable, Sendable {
    public let ownerPID: Int32
    public let cpus: Int?
    public let memoryGiB: Int?

    public init(ownerPID: Int32, cpus: Int? = nil, memoryGiB: Int? = nil) {
        self.ownerPID = ownerPID
        self.cpus = cpus
        self.memoryGiB = memoryGiB
    }
}
public struct DockerEventResponse: Encodable, Sendable {
    public let status: String?; public let id: String?; public let `Type`: String; public let Action: String
    public let Actor: ActorResponse; public let time: Int64; public let timeNano: Int64
    public struct ActorResponse: Encodable, Sendable { public let ID: String; public let Attributes: [String: String] }
    public init(_ event: RuntimeEvent, version: DockerAPIVersion = .maximum) {
        status = version < .init(major: 1, minor: 52) ? event.action : nil
        id = version < .init(major: 1, minor: 52) ? event.id : nil
        Type = event.type; Action = event.action
        Actor = .init(ID: event.id, Attributes: event.attributes)
        time = Int64(event.date.timeIntervalSince1970); timeNano = Int64(event.date.timeIntervalSince1970 * 1_000_000_000)
    }
}

public struct DockerVersionResponse: Encodable, Sendable {
    public let Platform: PlatformInfo
    public let Components: [Component]
    public let Version: String
    public let ApiVersion = DockerAPIVersion.maximum.description
    public let MinAPIVersion = DockerAPIVersion.minimum.description
    public let GitCommit: String
    public let GoVersion = ""
    public let Os = "linux"
    public let Arch = "arm64"
    public let KernelVersion = "6.18"
    public let Experimental = true
    public let BuildTime: String

    public struct PlatformInfo: Encodable, Sendable { public let Name: String }
    public struct Component: Encodable, Sendable { public let Name: String; public let Version: String; public let Details: [String: String] }

    public init(bundle: Bundle = .main) {
        Version = CEngineVersion.shortVersion(bundle: bundle)
        GitCommit = CEngineVersion.gitCommit(bundle: bundle)
        BuildTime = CEngineVersion.buildTime(bundle: bundle)
        Platform = .init(Name: "cengine")
        Components = [.init(Name: "Engine", Version: Version, Details: [
            "ApiVersion": DockerAPIVersion.maximum.description,
            "MinAPIVersion": DockerAPIVersion.minimum.description,
            "Arch": "arm64",
            "Os": "linux",
            "GitCommit": GitCommit,
            "BuildTime": Self.displayBuildTime(BuildTime),
        ])]
    }

    private static func displayBuildTime(_ value: String) -> String {
        guard !value.isEmpty, let date = ISO8601DateFormatter().date(from: value) else { return value }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "EEE MMM"
        let prefix = formatter.string(from: date)
        formatter.dateFormat = "HH:mm:ss yyyy"
        let suffix = formatter.string(from: date)
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        let day = calendar.component(.day, from: date)
        return String(format: "%@ %2d %@", prefix, day, suffix)
    }
}

public struct DockerInfoResponse: Encodable, Sendable {
    public let ID = "cengine"
    public let Containers: Int
    public let ContainersRunning: Int
    public let ContainersPaused: Int
    public let ContainersStopped: Int
    public let Images = 0
    public let Driver = "cengine-raw-vm"
    public let DriverStatus = [[String]]()
    public let DockerRootDir: String
    public let Name = Host.current().localizedName ?? "mac"
    public let ServerVersion = CEngineVersion.shortVersion()
    public let OperatingSystem = "macOS / cengine"
    public let OSType = "linux"
    public let Architecture = "arm64"
    public let NCPU = ProcessInfo.processInfo.activeProcessorCount
    public let MemTotal = ProcessInfo.processInfo.physicalMemory
    public let CgroupDriver = "cgroupfs"
    public let CgroupVersion = "2"
    public let SecurityOptions = ["name=vm"]
}

public struct ContainerCreateRequest: Decodable, Sendable {
    public var Hostname: String?
    public var User: String?
    public var AttachStdin: Bool?
    public var Tty: Bool?
    public var OpenStdin: Bool?
    public var Env: [String]?
    public var Cmd: [String]?
    public var Image: String
    public var WorkingDir: String?
    public var Entrypoint: [String]?
    public var Labels: [String: String]?
    public var Volumes: [String: EmptyObject]?
    public var StopSignal: String?
    public var StopTimeout: Int?
    public var HostConfig: HostConfig?
    public var Mounts: [Mount]?
    public var NetworkingConfig: NetworkingConfigRequest?
    public var Healthcheck: HealthcheckRequest?

    public struct EmptyObject: Decodable, Sendable {}

    public struct HealthcheckRequest: Decodable, Sendable {
        public var Test: [String]?; public var Interval: Int64?; public var Timeout: Int64?
        public var Retries: Int?; public var StartPeriod: Int64?
    }

    public struct NetworkingConfigRequest: Decodable, Sendable {
        public var EndpointsConfig: [String: EndpointSettingsRequest?]

        private enum CodingKeys: String, CodingKey { case EndpointsConfig }

        public init(from decoder: Decoder) throws {
            let keyed = try decoder.container(keyedBy: CodingKeys.self)
            if keyed.contains(.EndpointsConfig) {
                EndpointsConfig = try keyed.decode([String: EndpointSettingsRequest?].self, forKey: .EndpointsConfig)
            } else {
                EndpointsConfig = try decoder.singleValueContainer().decode([String: EndpointSettingsRequest?].self)
            }
        }
    }
    public struct EndpointSettingsRequest: Decodable, Sendable {
        public var Aliases: [String]?
        public var IPAddress: String?
        public var GlobalIPv6Address: String?
        public var MacAddress: String?
        public var GwPriority: Int?
        public var IPAMConfig: EndpointIPAMRequest?
    }
    public struct EndpointIPAMRequest: Decodable, Sendable {
        public var IPv4Address: String?
        public var IPv6Address: String?
    }

    public struct Mount: Decodable, Sendable {
        public var `Type`: String
        public var Source: String?
        public var Target: String
        public var ReadOnly: Bool?
        public var VolumeOptions: VolumeOptionsRequest?
        public var TmpfsOptions: TmpfsOptionsRequest?
        public struct VolumeOptionsRequest: Decodable, Sendable { public var NoCopy: Bool?; public var Subpath: String? }
        public struct TmpfsOptionsRequest: Decodable, Sendable { public var SizeBytes: Int64?; public var Mode: UInt32? }
    }

    public struct HostConfig: Decodable, Sendable {
        public var AutoRemove: Bool?
        public var Privileged: Bool?
        public var ReadonlyRootfs: Bool?
        public var Init: Bool?
        public var Memory: Int64?
        public var NanoCpus: Int64?
        public var CpuPeriod: Int64?
        public var CpuQuota: Int64?
        public var RestartPolicy: RestartPolicy?
        public var NetworkMode: String?
        public var Binds: [String]?
        public var Mounts: [Mount]?
        public var PortBindings: [String: [PortBindingRequest]]?
        public var Tmpfs: [String: String]?
        public struct RestartPolicy: Decodable, Sendable { public var Name: String?; public var MaximumRetryCount: Int? }
        public struct PortBindingRequest: Decodable, Sendable { public var HostIp: String?; public var HostPort: String? }
    }
}

public struct ContainerCreateResponse: Codable, Sendable { public let Id: String; public let Warnings: [String] }
public struct ContainerWaitResponse: Encodable, Sendable {
    public let StatusCode: Int32
    public let Error: DockerErrorBody?
}
public struct ContainerUpdateRequest: Decodable, Sendable {
    public var Memory: Int64?; public var NanoCpus: Int64?; public var CpuPeriod: Int64?; public var CpuQuota: Int64?
    public var RestartPolicy: RestartPolicy?
    public struct RestartPolicy: Decodable, Sendable { public var Name: String; public var MaximumRetryCount: Int? }
}
public struct ContainerUpdateResponse: Encodable, Sendable { public let Warnings: [String] }
public struct ContainerTopResponse: Encodable, Sendable { public let Titles: [String]; public let Processes: [[String]] }
public struct ContainerStatsResponse: Encodable, Sendable {
    public let id: String; public let name: String
    public let os_type: String?
    public let read: String; public let preread: String; public let pids_stats: Pids
    public let blkio_stats: BlockIO; public let num_procs: UInt64
    public let cpu_stats: CPU; public let precpu_stats: CPU; public let memory_stats: Memory
    public let networks: [String: Network]
    public struct Pids: Encodable, Sendable { let current: UInt64; let limit: UInt64 }
    public struct BlockIO: Encodable, Sendable { let io_service_bytes_recursive: [Entry] }
    public struct Entry: Encodable, Sendable { let major: Int; let minor: Int; let op: String; let value: UInt64 }
    public struct CPU: Encodable, Sendable {
        let cpu_usage: Usage; let system_cpu_usage: UInt64; let online_cpus: Int; let throttling_data: Throttling
    }
    public struct Usage: Encodable, Sendable {
        let total_usage: UInt64; let usage_in_kernelmode: UInt64; let usage_in_usermode: UInt64; let percpu_usage: [UInt64]
    }
    public struct Throttling: Encodable, Sendable { let periods: UInt64 = 0; let throttled_periods: UInt64 = 0; let throttled_time: UInt64 = 0 }
    public struct Memory: Encodable, Sendable { let usage: UInt64; let max_usage: UInt64; let stats: [String: UInt64]; let limit: UInt64 }
    public struct Network: Encodable, Sendable {
        let rx_bytes: UInt64; let rx_packets: UInt64; let rx_errors: UInt64; let rx_dropped: UInt64 = 0
        let tx_bytes: UInt64; let tx_packets: UInt64; let tx_errors: UInt64; let tx_dropped: UInt64 = 0
    }
    public init(_ value: BackendStatistics, container: ContainerRecord, version: DockerAPIVersion = .maximum) {
        id = container.id; name = container.name
        os_type = version >= .init(major: 1, minor: 52) ? "linux" : nil
        let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        read = formatter.string(from: value.read); preread = formatter.string(from: value.read.addingTimeInterval(-1))
        pids_stats = .init(current: value.pids, limit: UInt64.max); num_procs = value.pids
        blkio_stats = .init(io_service_bytes_recursive: [
            .init(major: 0, minor: 0, op: "Read", value: value.blockReadBytes),
            .init(major: 0, minor: 0, op: "Write", value: value.blockWriteBytes),
        ])
        let usage = Usage(total_usage: value.cpuTotalNanoseconds, usage_in_kernelmode: value.cpuSystemNanoseconds,
                          usage_in_usermode: value.cpuUserNanoseconds, percpu_usage: [value.cpuTotalNanoseconds])
        let system = UInt64(ProcessInfo.processInfo.systemUptime * 1_000_000_000) * UInt64(max(container.cpus, 1))
        cpu_stats = .init(cpu_usage: usage, system_cpu_usage: system, online_cpus: container.cpus, throttling_data: .init())
        precpu_stats = .init(cpu_usage: usage, system_cpu_usage: system, online_cpus: container.cpus, throttling_data: .init())
        memory_stats = .init(usage: value.memoryUsage, max_usage: value.memoryUsage,
                             stats: ["cache": value.memoryCache], limit: value.memoryLimit)
        networks = Dictionary(uniqueKeysWithValues: value.networks.map {
            ($0.name, .init(rx_bytes: $0.rxBytes, rx_packets: $0.rxPackets, rx_errors: $0.rxErrors,
                            tx_bytes: $0.txBytes, tx_packets: $0.txPackets, tx_errors: $0.txErrors))
        })
    }
}

public struct ExecCreateRequest: Decodable, Sendable {
    public var AttachStdin: Bool?; public var AttachStdout: Bool?; public var AttachStderr: Bool?
    public var DetachKeys: String?; public var Tty: Bool?; public var Cmd: [String]
    public var Env: [String]?; public var WorkingDir: String?; public var Privileged: Bool?; public var User: String?
}
public struct ExecCreateResponse: Encodable, Sendable { public let Id: String }
public struct ExecStartRequest: Decodable, Sendable { public var Detach: Bool?; public var Tty: Bool? }
public struct ExecInspectResponse: Encodable, Sendable {
    public let ID: String; public let Running: Bool; public let ExitCode: Int32; public let ProcessConfig: Process
    public let OpenStdin: Bool; public let OpenStdout: Bool; public let OpenStderr: Bool; public let ContainerID: String
    public let CanRemove = false; public let DetachKeys = ""; public let Pid: Int32
    public struct Process: Encodable, Sendable {
        public let entrypoint: String; public let arguments: [String]; public let privileged: Bool; public let tty: Bool
    }
    public init(_ exec: ExecRecord) {
        ID = exec.id; Running = exec.running; ExitCode = exec.exitCode ?? 0; ContainerID = exec.containerID; Pid = exec.pid
        OpenStdin = exec.configuration.attachStdin; OpenStdout = exec.configuration.attachStdout; OpenStderr = exec.configuration.attachStderr
        ProcessConfig = .init(
            entrypoint: exec.configuration.arguments.first ?? "",
            arguments: Array(exec.configuration.arguments.dropFirst()),
            privileged: exec.configuration.privileged,
            tty: exec.configuration.tty
        )
    }
}
public struct ContainerPathStat: Codable, Sendable {
    public let name: String; public let size: Int64; public let mode: UInt32; public let mtime: String; public let linkTarget: String
}

public struct ContainerSummaryResponse: Codable, Sendable {
    public let Id: String
    public let Names: [String]
    public let Image: String
    public let ImageID: String
    public let ImageManifestDescriptor: OCIDescriptor?
    public let Command: String
    public let Created: Int64
    public let State: String
    public let Status: String
    public let Ports: [Port]
    public let Labels: [String: String]
    public let NetworkSettings: NetworkSettingsSummary
    public let Health: HealthSummary?

    public init(_ record: ContainerRecord, networks: [NetworkRecord] = [], version: DockerAPIVersion = .maximum) {
        Id = record.id; Names = ["/\(record.name)"]; Image = record.image; ImageID = record.imageID
        ImageManifestDescriptor = version >= .init(major: 1, minor: 48) ? record.imageManifestDescriptor : nil
        Command = record.processArguments.joined(separator: " "); Created = Int64(record.createdAt.timeIntervalSince1970)
        State = record.phase.rawValue
        Status = record.phase == .running ? "Up" : record.phase.rawValue.capitalized
        Ports = record.ports.map { .init(IP: $0.hostIP, PrivatePort: $0.containerPort, PublicPort: $0.hostPort, Type: $0.proto) }
        Labels = record.labels
        Health = version >= .init(major: 1, minor: 52)
            ? .init(Status: record.healthStatus ?? "none", FailingStreak: record.healthFailingStreak ?? 0)
            : nil
        NetworkSettings = .init(Networks: Dictionary(uniqueKeysWithValues: record.networks.compactMap { endpoint in
            guard let network = networks.first(where: { $0.id == endpoint.networkID }) else { return nil }
            return (network.name, EndpointSummary(NetworkID: network.id))
        }))
    }

    public struct NetworkSettingsSummary: Codable, Sendable { public let Networks: [String: EndpointSummary] }
    public struct EndpointSummary: Codable, Sendable { public let NetworkID: String }
    public struct HealthSummary: Codable, Sendable { public let Status: String; public let FailingStreak: Int }

    public struct Port: Codable, Sendable {
        public let IP: String; public let PrivatePort: UInt16; public let PublicPort: UInt16; public let `Type`: String
    }
}

public struct NetworkCreateRequest: Decodable, Sendable {
    public let Name: String
    public var Driver: String?
    public var Internal: Bool?
    public var EnableIPv6: Bool?
    public var Labels: [String: String]?
    public var Options: [String: String]?
    public var IPAM: IPAMRequest?
    public struct IPAMRequest: Decodable, Sendable { public var Config: [ConfigRequest]? }
    public struct ConfigRequest: Decodable, Sendable { public var Subnet: String?; public var Gateway: String? }
}
public struct NetworkCreateResponse: Codable, Sendable { public let Id: String; public let Warning: String }
public struct NetworkConnectRequest: Decodable, Sendable {
    public let Container: String
    public var EndpointConfig: ContainerCreateRequest.EndpointSettingsRequest?
}
public struct NetworkDisconnectRequest: Decodable, Sendable { public let Container: String; public var Force: Bool? }
public struct PruneResponse: Encodable, Sendable {
    public let ContainersDeleted: [String]?
    public let ImagesDeleted: [ImageDeleteResponse]?
    public let NetworksDeleted: [String]?
    public let VolumesDeleted: [String]?
    public let SpaceReclaimed: UInt64
    public init(networks: [String]) {
        ContainersDeleted = nil; ImagesDeleted = nil; NetworksDeleted = networks; VolumesDeleted = nil; SpaceReclaimed = 0
    }
    public init(containers: [String]) {
        ContainersDeleted = containers; ImagesDeleted = nil; NetworksDeleted = nil; VolumesDeleted = nil; SpaceReclaimed = 0
    }
    public init(images: [ImageRecord]) {
        ContainersDeleted = nil; ImagesDeleted = images.map { .init(Deleted: $0.id) }
        NetworksDeleted = nil; VolumesDeleted = nil; SpaceReclaimed = UInt64(images.reduce(0) { $0 + $1.size })
    }
    public init(volumes: [String]) {
        ContainersDeleted = nil; ImagesDeleted = nil; NetworksDeleted = nil; VolumesDeleted = volumes; SpaceReclaimed = 0
    }
}
public struct VolumeCreateRequest: Decodable, Sendable { public var Name: String?; public var Driver: String?; public var DriverOpts: [String: String]?; public var Labels: [String: String]? }

public struct DockerVolumeResponse: Encodable, Sendable {
    public let Name: String; public let Driver = "local"; public let Mountpoint: String
    public let CreatedAt: String; public let Status: [String: String]? = nil
    public let Labels: [String: String]; public let Scope = "local"; public let Options: [String: String]
    public let UsageData: Usage?
    public struct Usage: Encodable, Sendable { public let RefCount: Int; public let Size: Int64 }
    public init(_ volume: VolumeRecord, refCount: Int? = nil) {
        Name = volume.name; Mountpoint = "cengine://volumes/\(volume.name)"
        CreatedAt = ISO8601DateFormatter().string(from: volume.createdAt); Labels = volume.labels; Options = volume.options
        UsageData = refCount.map { .init(RefCount: $0, Size: Int64(volume.sizeBytes)) }
    }
}

public struct SystemDiskUsageResponse: Encodable, Sendable {
    public let LayersSize: Int64
    public let Images: [ImageSummaryResponse]
    public let Containers: [Container]
    public let Volumes: [DockerVolumeResponse]
    public let BuildCache: [BuildCacheRecord]

    public struct Container: Encodable, Sendable {
        public let Id: String; public let Names: [String]; public let Image: String; public let ImageID: String
        public let Command: String; public let Created: Int64; public let State: String; public let Status: String
        public let SizeRw: Int64; public let SizeRootFs: Int64; public let Labels: [String: String]
        init(_ record: ContainerRecord, image: ImageRecord?) {
            Id = record.id; Names = ["/\(record.name)"]; Image = record.image; ImageID = image?.id ?? ""
            Command = record.processArguments.joined(separator: " "); Created = Int64(record.createdAt.timeIntervalSince1970)
            State = record.phase.rawValue; Status = record.phase == .running ? "Up" : record.phase.rawValue.capitalized
            SizeRw = 0; SizeRootFs = image?.size ?? 0; Labels = record.labels
        }
    }

    public struct BuildCacheRecord: Encodable, Sendable {}

    public init(containers: [ContainerRecord], images: [ImageRecord], volumes: [VolumeRecord]) {
        LayersSize = images.reduce(0) { $0 + max($1.size, 0) }
        Images = images.map { image in
            ImageSummaryResponse(image, containers: containers.filter { $0.image == image.id || image.references.contains($0.image) }.count)
        }
        Containers = containers.map { container in
            Container(container, image: images.first { $0.id == container.image || $0.references.contains(container.image) })
        }
        Volumes = volumes.map { volume in
            DockerVolumeResponse(volume, refCount: containers.filter { container in
                container.mounts.contains { $0.kind == .volume && $0.source == volume.name }
            }.count)
        }
        BuildCache = []
    }
}

public struct DockerNetworkResponse: Encodable, Sendable {
    public let Name: String; public let Id: String; public let Created: String
    public let Scope = "local"; public let Driver = "bridge"; public let EnableIPv6 = true
    public let IPAM: IPAMResponse; public let Internal: Bool; public let Attachable = false; public let Ingress = false
    public let ConfigFrom: [String: String] = [:]; public let ConfigOnly = false
    public let Containers: [String: String] = [:]; public let Options: [String: String]; public let Labels: [String: String]
    public struct IPAMResponse: Encodable, Sendable {
        public let Driver = "default"; public let Options: [String: String]? = nil; public let Config: [ConfigResponse]
    }
    public struct ConfigResponse: Encodable, Sendable { public let Subnet: String; public let Gateway: String }
    public init(_ network: NetworkRecord) {
        Name = network.name; Id = network.id; Created = ISO8601DateFormatter().string(from: network.createdAt)
        IPAM = .init(Config: [
            .init(Subnet: network.subnet, Gateway: network.gateway),
            .init(Subnet: network.ipv6Subnet, Gateway: network.ipv6Gateway),
        ])
        Internal = network.internalNetwork; Labels = network.labels; Options = network.options ?? [:]
    }
}

public struct ImageSummaryResponse: Encodable, Sendable {
    public let Id: String; public let RepoTags: [String]; public let RepoDigests: [String]
    public let ParentId: String; public let Containers: Int
    public let Created: Int64; public let Size: Int64; public let SharedSize: Int64
    public let Labels: [String: String]
    public let Descriptor: OCIDescriptor?
    public let Manifests: [ImageManifestSummaryResponse]?
    public init(
        _ image: ImageRecord,
        containers: Int = -1,
        containerRecords: [ContainerRecord] = [],
        includeDescriptor: Bool = true,
        includeManifests: Bool = false,
        includeIdentity: Bool = false
    ) {
        Id = image.preferredManifest?.imageID ?? image.id
        RepoTags = image.references.filter { !$0.contains("@") }.map(dockerDisplayReference)
        RepoDigests = image.references.filter { $0.contains("@") }.map(dockerDisplayReference)
        ParentId = ""; Containers = containers
        Created = Int64(image.createdAt.timeIntervalSince1970); Size = image.size; SharedSize = 0; Labels = [:]
        Descriptor = includeDescriptor ? image.targetDescriptor : nil
        Manifests = includeManifests ? image.manifests.map { manifest in
            ImageManifestSummaryResponse(
                manifest,
                containers: containerRecords.filter {
                    $0.imageManifestDescriptor?.digest == manifest.descriptor.digest
                }.map(\.id),
                identity: includeIdentity ? image.identity : nil
            )
        } : nil
    }
}

public struct ImageInspectResponse: Encodable, Sendable {
    public let Id: String; public let RepoTags: [String]; public let RepoDigests: [String]
    public let Created: String; public let Architecture: String; public let Os: String; public let Size: Int64
    public let Config: ConfigResponse
    public let RootFS: RootFSResponse
    public let Descriptor: OCIDescriptor?
    public let Manifests: [ImageManifestSummaryResponse]?
    public let Identity: ImageIdentityResponse?
    public struct ConfigResponse: Encodable, Sendable {
        public let Env: [String]?
        public let Cmd: [String]?
        public let Entrypoint: [String]?
        public let WorkingDir: String?
        public let User: String?
        public let Labels: [String: String]?
        public let ExposedPorts: [String: EmptyObject]?
        public let Volumes: [String: EmptyObject]?
        init(_ configuration: ImageConfigurationRecord?, omitEmpty: Bool) {
            Env = configuration?.environment ?? (omitEmpty ? nil : [])
            Cmd = configuration?.command
            Entrypoint = configuration?.entrypoint
            WorkingDir = configuration?.workingDirectory ?? (omitEmpty ? nil : "")
            User = configuration?.user ?? (omitEmpty ? nil : "")
            Labels = configuration?.labels ?? (omitEmpty ? nil : [:])
            ExposedPorts = configuration?.exposedPorts.map { Dictionary(uniqueKeysWithValues: $0.map { ($0, EmptyObject()) }) }
                ?? (omitEmpty ? nil : [:])
            Volumes = configuration?.volumes.map { Dictionary(uniqueKeysWithValues: $0.map { ($0, EmptyObject()) }) }
                ?? (omitEmpty ? nil : [:])
        }
    }
    public struct RootFSResponse: Encodable, Sendable {
        public let `Type` = "layers"
        public let Layers: [String]
    }
    public struct EmptyObject: Encodable, Sendable {}
    public init(
        _ image: ImageRecord,
        selectedManifest: ImageManifestRecord? = nil,
        includeManifests: Bool = false,
        version: DockerAPIVersion = .maximum
    ) {
        let selected = selectedManifest ?? image.preferredManifest
        Id = selected?.imageID ?? image.id
        RepoTags = image.references.filter { !$0.contains("@") }.map(dockerDisplayReference)
        RepoDigests = image.references.filter { $0.contains("@") }.map(dockerDisplayReference)
        Created = ISO8601DateFormatter().string(from: selected?.createdAt ?? image.createdAt)
        Architecture = selected?.platform?.architecture ?? image.architecture
        Os = selected?.platform?.os ?? image.os
        Size = selected?.contentSize ?? image.size
        Config = .init(selected?.configuration, omitEmpty: version >= .init(major: 1, minor: 52))
        RootFS = .init(Layers: selected?.configuration?.rootFSDiffIDs ?? [])
        Descriptor = version >= .init(major: 1, minor: 48) ? image.targetDescriptor : nil
        Manifests = version >= .init(major: 1, minor: 48) && includeManifests
            ? image.manifests.map { ImageManifestSummaryResponse($0) }
            : nil
        Identity = version >= .init(major: 1, minor: 53) ? image.identity.map(ImageIdentityResponse.init) : nil
    }
}

public struct ImageIdentityResponse: Encodable, Sendable {
    public struct PullIdentity: Encodable, Sendable { public let Repository: String }
    public let Pull: [PullIdentity]

    public init(_ identity: ImageIdentityRecord) {
        Pull = identity.pullRepositories.map(PullIdentity.init)
    }
}

public struct ImageManifestSummaryResponse: Encodable, Sendable {
    public struct SizeResponse: Encodable, Sendable { public let Content: Int64; public let Total: Int64 }
    public struct ImageDataResponse: Encodable, Sendable {
        public struct SizeResponse: Encodable, Sendable { public let Unpacked: Int64 }
        public let Platform: OCIPlatform
        public let Identity: ImageIdentityResponse?
        public let Containers: [String]
        public let Size: SizeResponse
    }
    public struct AttestationDataResponse: Encodable, Sendable { public let `For`: String }

    public let ID: String
    public let Descriptor: OCIDescriptor
    public let Available: Bool
    public let Size: SizeResponse
    public let Kind: String
    public let ImageData: ImageDataResponse?
    public let AttestationData: AttestationDataResponse?

    public init(
        _ manifest: ImageManifestRecord,
        containers: [String] = [],
        identity: ImageIdentityRecord? = nil
    ) {
        ID = manifest.descriptor.digest
        Descriptor = manifest.descriptor
        Available = manifest.available
        Size = .init(Content: manifest.contentSize, Total: manifest.contentSize)
        Kind = manifest.kind.rawValue
        ImageData = manifest.kind == .image ? manifest.platform.map {
            .init(Platform: $0, Identity: identity.map(ImageIdentityResponse.init), Containers: containers, Size: .init(Unpacked: 0))
        } : nil
        AttestationData = manifest.kind == .attestation ? manifest.attestationFor.map { .init(For: $0) } : nil
    }
}

public enum JSONValue: Codable, Sendable {
    case object([String: JSONValue]), array([JSONValue]), string(String), number(Double), bool(Bool), null

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() { self = .null }
        else if let value = try? container.decode([String: JSONValue].self) { self = .object(value) }
        else if let value = try? container.decode([JSONValue].self) { self = .array(value) }
        else if let value = try? container.decode(Bool.self) { self = .bool(value) }
        else if let value = try? container.decode(Double.self) { self = .number(value) }
        else { self = .string(try container.decode(String.self)) }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .object(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .bool(let value): try container.encode(value)
        case .null: try container.encodeNil()
        }
    }
}

public struct AttestationStatementResponse: Encodable, Sendable {
    public let Descriptor: OCIDescriptor
    public let PredicateType: String
    public let Statement: JSONValue?

    public init(_ value: ImageAttestationRecord) throws {
        Descriptor = value.descriptor
        PredicateType = value.predicateType
        Statement = try value.statement.map { try JSONDecoder().decode(JSONValue.self, from: $0) }
    }
}

private func dockerDisplayReference(_ value: String) -> String {
    if value.hasPrefix("docker.io/library/") { return String(value.dropFirst("docker.io/library/".count)) }
    if value.hasPrefix("docker.io/") { return String(value.dropFirst("docker.io/".count)) }
    return value
}

public struct ImageDeleteResponse: Encodable, Sendable { public let Deleted: String }
public struct ImageHistoryResponse: Encodable, Sendable {
    public let Id: String; public let Created: Int64; public let CreatedBy: String
    public let Tags: [String]; public let Size: Int64; public let Comment: String
}

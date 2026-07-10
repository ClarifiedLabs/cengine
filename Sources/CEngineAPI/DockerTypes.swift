import CEngineCore
import CEngineRuntime
import Foundation

public struct DockerErrorBody: Codable, Sendable { public let message: String }

public struct DockerVersionResponse: Encodable, Sendable {
    public let Platform: PlatformInfo
    public let Components: [Component]
    public let Version = "0.1.0"
    public let ApiVersion = "1.44"
    public let MinAPIVersion = "1.44"
    public let GitCommit = "unknown"
    public let GoVersion = ""
    public let Os = "linux"
    public let Arch = "arm64"
    public let KernelVersion = "6.18"
    public let Experimental = true
    public let BuildTime = ""

    public struct PlatformInfo: Encodable, Sendable { public let Name: String }
    public struct Component: Encodable, Sendable { public let Name: String; public let Version: String; public let Details: [String: String] }

    public init() {
        Platform = .init(Name: "cengine")
        Components = [.init(Name: "Engine", Version: "0.1.0", Details: ["ApiVersion": "1.44", "Arch": "arm64", "Os": "linux"])]
    }
}

public struct DockerInfoResponse: Encodable, Sendable {
    public let ID = "cengine"
    public let Containers: Int
    public let ContainersRunning: Int
    public let ContainersPaused: Int
    public let ContainersStopped: Int
    public let Images = 0
    public let Driver = "apple-containerization"
    public let DriverStatus = [[String]]()
    public let DockerRootDir: String
    public let Name = Host.current().localizedName ?? "mac"
    public let ServerVersion = "0.1.0"
    public let OperatingSystem = "macOS / cengine"
    public let OSType = "linux"
    public let Architecture = "arm64"
    public let NCPU = ProcessInfo.processInfo.activeProcessorCount
    public let MemTotal = ProcessInfo.processInfo.physicalMemory
    public let CgroupDriver = "cgroupfs"
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
    public var StopSignal: String?
    public var StopTimeout: Int?
    public var HostConfig: HostConfig?
    public var Mounts: [Mount]?

    public struct Mount: Decodable, Sendable {
        public var `Type`: String
        public var Source: String?
        public var Target: String
        public var ReadOnly: Bool?
    }

    public struct HostConfig: Decodable, Sendable {
        public var AutoRemove: Bool?
        public var Privileged: Bool?
        public var ReadonlyRootfs: Bool?
        public var Init: Bool?
        public var Memory: Int64?
        public var NanoCpus: Int64?
        public var RestartPolicy: RestartPolicy?
        public var Binds: [String]?
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
    public let Command: String
    public let Created: Int64
    public let State: String
    public let Status: String
    public let Ports: [String]
    public let Labels: [String: String]

    public init(_ record: ContainerRecord) {
        Id = record.id; Names = ["/\(record.name)"]; Image = record.image; ImageID = ""
        Command = record.processArguments.joined(separator: " "); Created = Int64(record.createdAt.timeIntervalSince1970)
        State = record.phase.rawValue
        Status = record.phase == .running ? "Up" : record.phase.rawValue.capitalized
        Ports = []; Labels = record.labels
    }
}

public struct NetworkCreateRequest: Decodable, Sendable { public let Name: String; public var Internal: Bool?; public var Labels: [String: String]? }
public struct NetworkCreateResponse: Codable, Sendable { public let Id: String; public let Warning: String }
public struct VolumeCreateRequest: Decodable, Sendable { public var Name: String?; public var Driver: String?; public var DriverOpts: [String: String]?; public var Labels: [String: String]? }

public struct DockerVolumeResponse: Encodable, Sendable {
    public let Name: String; public let Driver = "local"; public let Mountpoint: String
    public let CreatedAt: String; public let Status: [String: String]? = nil
    public let Labels: [String: String]; public let Scope = "local"; public let Options: [String: String]
    public init(_ volume: VolumeRecord) {
        Name = volume.name; Mountpoint = "cengine://volumes/\(volume.name)"
        CreatedAt = ISO8601DateFormatter().string(from: volume.createdAt); Labels = volume.labels; Options = volume.options
    }
}

public struct DockerNetworkResponse: Encodable, Sendable {
    public let Name: String; public let Id: String; public let Created: String
    public let Scope = "local"; public let Driver = "bridge"; public let EnableIPv6 = false
    public let IPAM: IPAMResponse; public let Internal: Bool; public let Attachable = false; public let Ingress = false
    public let ConfigFrom: [String: String] = [:]; public let ConfigOnly = false
    public let Containers: [String: String] = [:]; public let Options: [String: String] = [:]; public let Labels: [String: String]
    public struct IPAMResponse: Encodable, Sendable {
        public let Driver = "default"; public let Options: [String: String]? = nil; public let Config: [ConfigResponse]
    }
    public struct ConfigResponse: Encodable, Sendable { public let Subnet: String; public let Gateway: String }
    public init(_ network: NetworkRecord) {
        Name = network.name; Id = network.id; Created = ISO8601DateFormatter().string(from: network.createdAt)
        IPAM = .init(Config: [.init(Subnet: network.subnet, Gateway: network.gateway)])
        Internal = network.internalNetwork; Labels = network.labels
    }
}

public struct ImageSummaryResponse: Encodable, Sendable {
    public let Id: String; public let RepoTags: [String]; public let RepoDigests: [String]
    public let Created: Int64; public let Size: Int64; public let SharedSize: Int64; public let VirtualSize: Int64
    public let Labels: [String: String]
    public init(_ image: ImageRecord) {
        Id = image.id; RepoTags = image.references; RepoDigests = []
        Created = Int64(image.createdAt.timeIntervalSince1970); Size = image.size; SharedSize = 0; VirtualSize = image.size; Labels = [:]
    }
}

public struct ImageInspectResponse: Encodable, Sendable {
    public let Id: String; public let RepoTags: [String]; public let RepoDigests: [String]
    public let Created: String; public let Architecture: String; public let Os: String; public let Size: Int64
    public init(_ image: ImageRecord) {
        Id = image.id; RepoTags = image.references; RepoDigests = []; Created = ISO8601DateFormatter().string(from: image.createdAt)
        Architecture = image.architecture; Os = image.os; Size = image.size
    }
}

public struct ImageDeleteResponse: Encodable, Sendable { public let Deleted: String }

import Foundation

public enum ContainerPhase: String, Codable, Sendable {
    case created
    case running
    case paused
    case exited
    case dead
}

public struct PortBinding: Codable, Hashable, Sendable {
    public var hostIP: String
    public var hostPort: UInt16
    public var containerPort: UInt16
    public var proto: String

    public init(hostIP: String = "0.0.0.0", hostPort: UInt16, containerPort: UInt16, proto: String = "tcp") {
        self.hostIP = hostIP
        self.hostPort = hostPort
        self.containerPort = containerPort
        self.proto = proto
    }
}

public struct MountRecord: Codable, Hashable, Sendable {
    public enum Kind: String, Codable, Sendable { case bind, volume, tmpfs }
    public var kind: Kind
    public var source: String
    public var destination: String
    public var readOnly: Bool
    public var noCopy: Bool
    public var subpath: String?
    public var tmpfsSizeBytes: Int64?
    public var tmpfsMode: UInt32?
    public var createSourceIfMissing: Bool?

    public init(kind: Kind, source: String, destination: String, readOnly: Bool = false, noCopy: Bool = false,
                subpath: String? = nil, tmpfsSizeBytes: Int64? = nil, tmpfsMode: UInt32? = nil,
                createSourceIfMissing: Bool? = nil) {
        self.kind = kind; self.source = source; self.destination = destination; self.readOnly = readOnly
        self.noCopy = noCopy; self.subpath = subpath; self.tmpfsSizeBytes = tmpfsSizeBytes; self.tmpfsMode = tmpfsMode
        self.createSourceIfMissing = createSourceIfMissing
    }
}

public struct NetworkEndpointRecord: Codable, Hashable, Sendable {
    public var networkID: String
    public var aliases: [String]
    public var ipv4Address: String?
    public var ipv6Address: String?

    public init(networkID: String, aliases: [String] = [], ipv4Address: String? = nil, ipv6Address: String? = nil) {
        self.networkID = networkID; self.aliases = aliases
        self.ipv4Address = ipv4Address; self.ipv6Address = ipv6Address
    }
}

public struct RestartPolicyRecord: Codable, Hashable, Sendable {
    public var name: String
    public var maximumRetryCount: Int

    public init(name: String = "no", maximumRetryCount: Int = 0) {
        self.name = name
        self.maximumRetryCount = maximumRetryCount
    }
}

public struct HealthcheckRecord: Codable, Hashable, Sendable {
    public var test: [String]
    public var intervalNanoseconds: Int64
    public var timeoutNanoseconds: Int64
    public var retries: Int
    public var startPeriodNanoseconds: Int64
    public init(test: [String], intervalNanoseconds: Int64, timeoutNanoseconds: Int64,
                retries: Int, startPeriodNanoseconds: Int64) {
        self.test = test; self.intervalNanoseconds = intervalNanoseconds
        self.timeoutNanoseconds = timeoutNanoseconds; self.retries = retries
        self.startPeriodNanoseconds = startPeriodNanoseconds
    }
}

public struct ContainerRecord: Codable, Sendable {
    public var id: String
    public var name: String
    public var image: String
    public var platform: String
    public var createdAt: Date
    public var phase: ContainerPhase
    public var startedAt: Date?
    public var finishedAt: Date?
    public var exitCode: Int32?
    public var processArguments: [String]
    public var entrypoint: [String]?
    public var command: [String]?
    public var environment: [String]
    public var workingDirectory: String
    public var user: String
    public var hostname: String
    public var labels: [String: String]
    public var tty: Bool
    public var openStdin: Bool
    public var privileged: Bool
    public var readOnlyRootfs: Bool
    public var autoRemove: Bool
    public var useInit: Bool
    public var memoryBytes: UInt64
    public var cpus: Int
    public var stopSignal: String
    public var stopTimeoutSeconds: Int
    public var restartPolicy: RestartPolicyRecord
    public var healthcheck: HealthcheckRecord?
    public var healthStatus: String?
    public var healthFailingStreak: Int?
    public var mounts: [MountRecord]
    public var ports: [PortBinding]
    public var networks: [NetworkEndpointRecord]
    public var restartCount: Int

    public init(
        id: String = Identifier.random(), name: String, image: String,
        platform: String = "linux/arm64", processArguments: [String] = []
    ) {
        self.id = id
        self.name = name
        self.image = image
        self.platform = platform
        self.createdAt = Date()
        self.phase = .created
        self.processArguments = processArguments
        self.entrypoint = nil
        self.command = processArguments.isEmpty ? nil : processArguments
        self.environment = []
        self.workingDirectory = ""
        self.user = ""
        self.hostname = String(id.prefix(12))
        self.labels = [:]
        self.tty = false
        self.openStdin = false
        self.privileged = false
        self.readOnlyRootfs = false
        self.autoRemove = false
        self.useInit = false
        self.memoryBytes = 1_073_741_824
        self.cpus = 4
        self.stopSignal = "SIGTERM"
        self.stopTimeoutSeconds = 10
        self.restartPolicy = .init()
        self.healthStatus = nil
        self.healthFailingStreak = nil
        self.mounts = []
        self.ports = []
        self.networks = []
        self.restartCount = 0
    }
}

public struct NetworkRecord: Codable, Sendable {
    public var id: String
    public var name: String
    public var createdAt: Date
    public var subnet: String
    public var gateway: String
    public var internalNetwork: Bool
    public var labels: [String: String]

    public init(id: String, name: String, createdAt: Date = Date(), subnet: String, gateway: String, internalNetwork: Bool = false, labels: [String: String] = [:]) {
        self.id = id; self.name = name; self.createdAt = createdAt; self.subnet = subnet; self.gateway = gateway
        self.internalNetwork = internalNetwork; self.labels = labels
    }
}

public struct VolumeRecord: Codable, Sendable {
    public var name: String
    public var createdAt: Date
    public var sizeBytes: UInt64
    public var labels: [String: String]
    public var options: [String: String]
    public var anonymous: Bool?

    public init(name: String, createdAt: Date = Date(), sizeBytes: UInt64, labels: [String: String] = [:], options: [String: String] = [:], anonymous: Bool = false) {
        self.name = name; self.createdAt = createdAt; self.sizeBytes = sizeBytes; self.labels = labels; self.options = options
        self.anonymous = anonymous
    }
}

public struct ImageRecord: Codable, Sendable {
    public var id: String
    public var references: [String]
    public var createdAt: Date
    public var size: Int64
    public var architecture: String
    public var os: String

    public init(id: String, references: [String], createdAt: Date, size: Int64, architecture: String, os: String) {
        self.id = id; self.references = references; self.createdAt = createdAt; self.size = size
        self.architecture = architecture; self.os = os
    }
}

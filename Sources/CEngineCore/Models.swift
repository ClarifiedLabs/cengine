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
    public enum Propagation: String, Codable, Sendable {
        case `private`, rprivate, shared, rshared, slave, rslave
    }
    public var kind: Kind
    public var source: String
    public var destination: String
    public var readOnly: Bool
    public var noCopy: Bool
    public var subpath: String?
    public var tmpfsSizeBytes: Int64?
    public var tmpfsMode: UInt32?
    public var createSourceIfMissing: Bool?
    public var propagation: Propagation?

    public init(kind: Kind, source: String, destination: String, readOnly: Bool = false, noCopy: Bool = false,
                subpath: String? = nil, tmpfsSizeBytes: Int64? = nil, tmpfsMode: UInt32? = nil,
                createSourceIfMissing: Bool? = nil, propagation: Propagation? = nil) {
        self.kind = kind; self.source = source; self.destination = destination; self.readOnly = readOnly
        self.noCopy = noCopy; self.subpath = subpath; self.tmpfsSizeBytes = tmpfsSizeBytes; self.tmpfsMode = tmpfsMode
        self.createSourceIfMissing = createSourceIfMissing
        self.propagation = propagation
    }
}

public struct NetworkEndpointRecord: Codable, Hashable, Sendable {
    public static let sysctlsDriverOption = "com.docker.network.endpoint.sysctls"

    public var networkID: String
    public var aliases: [String]
    public var ipv4Address: String?
    public var ipv6Address: String?
    public var ipv4AddressIsStatic: Bool
    public var ipv6AddressIsStatic: Bool
    /// An explicitly requested endpoint MAC address in canonical lowercase
    /// colon-separated form, or `nil` when the backend assigns one automatically.
    /// Optional so snapshots persisted before MAC support decode successfully.
    public var macAddress: String?
    /// The endpoint's gateway priority. The endpoint with the highest priority
    /// provides the container's default gateway; ties break lexicographically by
    /// network name. `nil` means the client did not request one (treated as 0),
    /// so snapshots persisted before gateway-priority support decode successfully.
    public var gatewayPriority: Int?
    /// Driver-specific endpoint options accepted from Docker's EndpointSettings.
    /// Cengine currently supports only per-interface sysctls.
    public var driverOptions: [String: String]?

    public init(networkID: String, aliases: [String] = [], ipv4Address: String? = nil, ipv6Address: String? = nil,
                ipv4AddressIsStatic: Bool = false, ipv6AddressIsStatic: Bool = false, macAddress: String? = nil,
                gatewayPriority: Int? = nil, driverOptions: [String: String]? = nil) {
        self.networkID = networkID; self.aliases = aliases
        self.ipv4Address = ipv4Address; self.ipv6Address = ipv6Address
        self.ipv4AddressIsStatic = ipv4AddressIsStatic; self.ipv6AddressIsStatic = ipv6AddressIsStatic
        self.macAddress = macAddress
        self.gatewayPriority = gatewayPriority
        self.driverOptions = driverOptions
    }

    public var interfaceSysctls: [String] {
        driverOptions?[Self.sysctlsDriverOption]?.components(separatedBy: ",") ?? []
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
    public var imageID: String
    public var imageManifestDescriptor: OCIDescriptor?
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
    public var annotations: [String: String]
    public var tty: Bool
    public var attachStdin: Bool
    public var openStdin: Bool
    public var privileged: Bool
    public var capabilityAdd: [String]
    public var capabilityDrop: [String]
    public var readOnlyRootfs: Bool
    public var autoRemove: Bool
    public var useInit: Bool
    public var memoryBytes: UInt64
    public var cpus: Int
    /// Docker's configured process limit. `0` and `-1` both mean unlimited.
    public var pidsLimit: Int64
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
    public var networkDisabled: Bool?

    public init(
        id: String = Identifier.random(), name: String, image: String,
        platform: String = "linux/arm64", processArguments: [String] = []
    ) {
        self.id = id
        self.name = name
        self.image = image
        self.imageID = ""
        self.imageManifestDescriptor = nil
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
        self.annotations = [:]
        self.tty = false
        self.attachStdin = false
        self.openStdin = false
        self.privileged = false
        self.capabilityAdd = []
        self.capabilityDrop = []
        self.readOnlyRootfs = false
        self.autoRemove = false
        self.useInit = false
        self.memoryBytes = ContainerSettings.default.memoryBytes
        self.cpus = ContainerSettings.default.cpus
        self.pidsLimit = 0
        self.stopSignal = "SIGTERM"
        self.stopTimeoutSeconds = 10
        self.restartPolicy = .init()
        self.healthStatus = nil
        self.healthFailingStreak = nil
        self.mounts = []
        self.ports = []
        self.networks = []
        self.restartCount = 0
        self.networkDisabled = false
    }
}

public enum NetworkAllocationMode: String, Codable, Sendable { case automatic, explicit }

public enum NetworkGatewayMode: String, Codable, Sendable {
    case nat
    case isolated
}

public struct NetworkRecord: Codable, Sendable {
    public static let enableIPMasqueradeOption = "com.docker.network.bridge.enable_ip_masquerade"
    public static let gatewayModeIPv4Option = "com.docker.network.bridge.gateway_mode_ipv4"
    public static let gatewayModeIPv6Option = "com.docker.network.bridge.gateway_mode_ipv6"

    public var id: String
    public var name: String
    public var createdAt: Date
    public var subnet: String
    public var gateway: String
    public var ipv6Subnet: String
    public var ipv6Gateway: String
    public var ipv4AllocationMode: NetworkAllocationMode
    public var ipv6AllocationMode: NetworkAllocationMode
    public var enableIPv4: Bool
    public var enableIPv6: Bool
    public var internalNetwork: Bool
    public var labels: [String: String]
    public var options: [String: String]?

    public init(id: String, name: String, createdAt: Date = Date(), subnet: String, gateway: String,
                ipv6Subnet: String = "", ipv6Gateway: String = "",
                ipv4AllocationMode: NetworkAllocationMode = .automatic,
                ipv6AllocationMode: NetworkAllocationMode = .automatic,
                enableIPv4: Bool = true, enableIPv6: Bool = true,
                internalNetwork: Bool = false, labels: [String: String] = [:],
                options: [String: String] = [:]) {
        self.id = id; self.name = name; self.createdAt = createdAt; self.subnet = subnet; self.gateway = gateway
        self.ipv6Subnet = ipv6Subnet; self.ipv6Gateway = ipv6Gateway
        self.ipv4AllocationMode = ipv4AllocationMode; self.ipv6AllocationMode = ipv6AllocationMode
        self.enableIPv4 = enableIPv4; self.enableIPv6 = enableIPv6
        self.internalNetwork = internalNetwork; self.labels = labels
        self.options = options
    }

    public var ipv4GatewayMode: NetworkGatewayMode {
        NetworkGatewayMode(rawValue: options?[Self.gatewayModeIPv4Option] ?? "nat") ?? .nat
    }

    public var ipv6GatewayMode: NetworkGatewayMode {
        NetworkGatewayMode(rawValue: options?[Self.gatewayModeIPv6Option] ?? "nat") ?? .nat
    }

    /// Whether every enabled address family is isolated from a vmnet uplink.
    /// EngineRuntime rejects asymmetric enabled-family modes before persistence,
    /// so checking either enabled isolated family is sufficient here while also
    /// handling IPv6-only networks correctly.
    public var fabricIsolated: Bool {
        (enableIPv4 && ipv4GatewayMode == .isolated)
            || (enableIPv6 && ipv6GatewayMode == .isolated)
    }

}

public struct VolumeRecord: Codable, Sendable {
    public static let defaultSizeBytes: UInt64 = 512 * 1_024 * 1_024 * 1_024

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
    public var targetDescriptor: OCIDescriptor?
    public var manifests: [ImageManifestRecord]
    public var preferredManifestDigest: String?
    public var identity: ImageIdentityRecord?

    public init(
        id: String,
        references: [String],
        createdAt: Date,
        size: Int64,
        architecture: String,
        os: String,
        targetDescriptor: OCIDescriptor? = nil,
        manifests: [ImageManifestRecord] = [],
        preferredManifestDigest: String? = nil,
        identity: ImageIdentityRecord? = nil
    ) {
        self.id = id; self.references = references; self.createdAt = createdAt; self.size = size
        self.architecture = architecture; self.os = os
        self.targetDescriptor = targetDescriptor
        self.manifests = manifests
        self.preferredManifestDigest = preferredManifestDigest
        self.identity = identity
    }

    public var preferredManifest: ImageManifestRecord? {
        preferredManifestDigest.flatMap { digest in manifests.first { $0.descriptor.digest == digest } }
            ?? manifests.first { $0.kind == .image && $0.available }
    }
}

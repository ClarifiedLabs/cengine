import Foundation

public enum GuestProtocol {
    public static let version: UInt32 = 14
    public static let controlPort: UInt32 = 4_100
    public static let fileSystemPort: UInt32 = 4_101
    public static let rootFSContentPort: UInt32 = 4_102
    public static let execIOPort: UInt32 = 4_103
    public static let portProxyPort: UInt32 = 4_104
    public static let socketProxyPortBase: UInt32 = 4_200
    public static let maximumControlFrameSize = 16 * 1_024 * 1_024
    public static let resourceRollbackIncompleteErrorCode = "resource_rollback_incomplete"

    public struct Envelope: Sendable, Equatable {
        public var version: UInt32
        public var id: String
        public var operation: String
        public var payload: Data?
        public var error: Failure?

        public init(
            version: UInt32 = GuestProtocol.version,
            id: String = UUID().uuidString,
            operation: String,
            payload: Data? = nil,
            error: Failure? = nil
        ) {
            self.version = version
            self.id = id
            self.operation = operation
            self.payload = payload
            self.error = error
        }
    }

    public struct Failure: Codable, Sendable, Equatable {
        public var code: String
        public var message: String

        public init(code: String, message: String) {
            self.code = code
            self.message = message
        }
    }

    public struct Workload: Codable, Sendable, Equatable {
        public var id: String
        public var rootDevice: String
        public var arguments: [String]
        public var environment: [String]
        public var workingDirectory: String
        public var hostname: String
        public var user: User
        public var terminal: Bool
        public var readOnlyRoot: Bool
        public var maskedPaths: [String]
        public var readonlyPaths: [String]
        public var stopSignal: String
        public var volumeServer: String?
        public var mounts: [Mount]
        public var networks: [NetworkEndpoint]
        public var hosts: [String: String]
        public var resources: Resources
        public var privileged: Bool
        public var noNewPrivileges: Bool
        public var annotations: [String: String]
        public var capabilityAdd: [String]
        public var capabilityDrop: [String]
        public var rlimits: [Rlimit]
        public var ipcMode: String
        public var ioClaim: String

        public init(id: String, rootDevice: String, arguments: [String], environment: [String], workingDirectory: String, hostname: String, user: User, terminal: Bool, readOnlyRoot: Bool, maskedPaths: [String] = [], readonlyPaths: [String] = [], stopSignal: String, volumeServer: String? = nil, mounts: [Mount], networks: [NetworkEndpoint], hosts: [String: String] = [:], resources: Resources, privileged: Bool = false, noNewPrivileges: Bool = true, annotations: [String: String] = [:], capabilityAdd: [String] = [], capabilityDrop: [String] = [], rlimits: [Rlimit] = [], ipcMode: String = "private", ioClaim: String = "") {
            self.id = id; self.rootDevice = rootDevice; self.arguments = arguments; self.environment = environment
            self.workingDirectory = workingDirectory; self.hostname = hostname; self.user = user; self.terminal = terminal
            self.readOnlyRoot = readOnlyRoot; self.maskedPaths = maskedPaths; self.readonlyPaths = readonlyPaths
            self.stopSignal = stopSignal; self.volumeServer = volumeServer; self.mounts = mounts; self.networks = networks; self.hosts = hosts; self.resources = resources; self.privileged = privileged; self.noNewPrivileges = noNewPrivileges
            self.annotations = annotations; self.capabilityAdd = capabilityAdd; self.capabilityDrop = capabilityDrop
            self.rlimits = rlimits
            self.ipcMode = ipcMode
            self.ioClaim = ioClaim
        }
    }

    public struct User: Codable, Sendable, Equatable {
        public var uid: UInt32
        public var gid: UInt32
        public var additionalGroups: [UInt32]
        public var username: String?
        public init(uid: UInt32 = 0, gid: UInt32 = 0, additionalGroups: [UInt32] = [], username: String? = nil) { self.uid = uid; self.gid = gid; self.additionalGroups = additionalGroups; self.username = username }
    }

    public struct Exec: Codable, Sendable, Equatable {
        public var id: String
        public var arguments: [String]
        public var environment: [String]
        public var workingDirectory: String
        public var user: User
        public var terminal: Bool
        public var attachStdin: Bool
        public var attachStdout: Bool
        public var attachStderr: Bool
        public var noNewPrivileges: Bool
        public var privileged: Bool
        public var capabilityAdd: [String]
        public var capabilityDrop: [String]
        public var rlimits: [Rlimit]
        public var ioClaim: String

        public init(
            id: String, arguments: [String], environment: [String], workingDirectory: String,
            user: User, terminal: Bool, attachStdin: Bool, attachStdout: Bool,
            attachStderr: Bool, noNewPrivileges: Bool, privileged: Bool = false,
            capabilityAdd: [String] = [], capabilityDrop: [String] = [], rlimits: [Rlimit] = [],
            ioClaim: String = ""
        ) {
            self.id = id
            self.arguments = arguments
            self.environment = environment
            self.workingDirectory = workingDirectory
            self.user = user
            self.terminal = terminal
            self.attachStdin = attachStdin
            self.attachStdout = attachStdout
            self.attachStderr = attachStderr
            self.noNewPrivileges = noNewPrivileges
            self.privileged = privileged
            self.capabilityAdd = capabilityAdd
            self.capabilityDrop = capabilityDrop
            self.rlimits = rlimits
            self.ioClaim = ioClaim
        }
    }

    public struct Rlimit: Codable, Sendable, Equatable {
        public var type: String
        public var soft: UInt64
        public var hard: UInt64

        public init(type: String, soft: UInt64, hard: UInt64) {
            self.type = type
            self.soft = soft
            self.hard = hard
        }
    }

    public struct Mount: Codable, Sendable, Equatable {
        public var kind: String
        public var source: String
        public var device: String?
        public var destination: String
        public var readOnly: Bool
        public var options: [String]
        public var subpath: String?
        public var noCopy: Bool
        public var propagation: String
        public var nonRecursive: Bool
        public var readOnlyNonRecursive: Bool
        public var readOnlyForceRecursive: Bool
        public var socketPort: UInt32?
        public var socketMode: UInt32?
        public var socketUID: UInt32?
        public var socketGID: UInt32?
        public init(kind: String, source: String, device: String? = nil, destination: String, readOnly: Bool, options: [String] = [], subpath: String? = nil, noCopy: Bool = false, propagation: String = "rprivate", nonRecursive: Bool = false, readOnlyNonRecursive: Bool = false, readOnlyForceRecursive: Bool = false, socketPort: UInt32? = nil, socketMode: UInt32? = nil, socketUID: UInt32? = nil, socketGID: UInt32? = nil) {
            self.kind = kind; self.source = source; self.device = device; self.destination = destination; self.readOnly = readOnly; self.options = options; self.subpath = subpath; self.noCopy = noCopy
            self.socketPort = socketPort; self.socketMode = socketMode; self.socketUID = socketUID; self.socketGID = socketGID
            self.propagation = propagation
            self.nonRecursive = nonRecursive
            self.readOnlyNonRecursive = readOnlyNonRecursive
            self.readOnlyForceRecursive = readOnlyForceRecursive
        }
    }

    public struct NetworkEndpoint: Codable, Sendable, Equatable {
        public var networkID: String
        public var vlan: UInt16
        public var name: String
        public var macAddress: String
        public var addresses: [String]
        public var gateways: [String]
        public var dns: [String]
        public var aliases: [String]
        public var sysctls: [String]
        public init(networkID: String, vlan: UInt16, name: String, macAddress: String, addresses: [String], gateways: [String], dns: [String], aliases: [String], sysctls: [String] = []) {
            self.networkID = networkID; self.vlan = vlan; self.name = name; self.macAddress = macAddress; self.addresses = addresses; self.gateways = gateways; self.dns = dns; self.aliases = aliases; self.sysctls = sysctls
        }
    }

    public struct Resources: Codable, Sendable, Equatable {
        public var memoryBytes: UInt64
        public var cpuQuota: Int64
        public var cpuPeriod: UInt64
        public var pids: Int64
        public var blockIOReadBps: [BlockIOThrottle]
        public var blockIOWriteBps: [BlockIOThrottle]
        public var blockIOReadIOps: [BlockIOThrottle]
        public var blockIOWriteIOps: [BlockIOThrottle]
        public var devices: [DeviceMapping]
        public var deviceCgroupRules: [DeviceCgroupRule]
        public init(
            memoryBytes: UInt64, cpuQuota: Int64, cpuPeriod: UInt64, pids: Int64,
            blockIOReadBps: [BlockIOThrottle] = [], blockIOWriteBps: [BlockIOThrottle] = [],
            blockIOReadIOps: [BlockIOThrottle] = [], blockIOWriteIOps: [BlockIOThrottle] = [],
            devices: [DeviceMapping] = [], deviceCgroupRules: [DeviceCgroupRule] = []
        ) {
            self.memoryBytes = memoryBytes; self.cpuQuota = cpuQuota; self.cpuPeriod = cpuPeriod; self.pids = pids
            self.blockIOReadBps = blockIOReadBps; self.blockIOWriteBps = blockIOWriteBps
            self.blockIOReadIOps = blockIOReadIOps; self.blockIOWriteIOps = blockIOWriteIOps
            self.devices = devices; self.deviceCgroupRules = deviceCgroupRules
        }
    }

    public struct DeviceMapping: Codable, Sendable, Equatable {
        public var pathOnHost: String
        public var pathInContainer: String
        public var cgroupPermissions: String

        public init(pathOnHost: String, pathInContainer: String, cgroupPermissions: String) {
            self.pathOnHost = pathOnHost
            self.pathInContainer = pathInContainer
            self.cgroupPermissions = cgroupPermissions
        }
    }

    public struct DeviceCgroupRule: Codable, Sendable, Equatable {
        public var deviceType: String
        public var major: UInt32?
        public var minor: UInt32?
        public var access: String

        public init(deviceType: String, major: UInt32?, minor: UInt32?, access: String) {
            self.deviceType = deviceType
            self.major = major
            self.minor = minor
            self.access = access
        }
    }

    public struct BlockIOThrottle: Codable, Sendable, Equatable {
        public var path: String
        public var rate: UInt64

        public init(path: String, rate: UInt64) {
            self.path = path
            self.rate = rate
        }
    }

    public struct ResourceUpdate: Codable, Sendable, Equatable {
        public var resources: Resources
        public var compatibilityFailureAfterWrites: UInt32?

        public init(resources: Resources, compatibilityFailureAfterWrites: UInt32? = nil) {
            self.resources = resources
            self.compatibilityFailureAfterWrites = compatibilityFailureAfterWrites
        }
    }

    public struct MemoryStatus: Codable, Sendable, Equatable {
        public var totalBytes: UInt64
        public var availableBytes: UInt64

        public init(totalBytes: UInt64, availableBytes: UInt64) {
            self.totalBytes = totalBytes
            self.availableBytes = availableBytes
        }
    }

    public struct RootFSLayer: Codable, Sendable, Equatable {
        public var mediaType: String
        public var digest: String
        public var size: Int64

        public init(mediaType: String, digest: String, size: Int64) {
            self.mediaType = mediaType; self.digest = digest; self.size = size
        }
    }

    public struct RootFSRequest: Codable, Sendable, Equatable {
        public var rootDevice: String
        public var layers: [RootFSLayer]

        public init(rootDevice: String, layers: [RootFSLayer]) {
            self.rootDevice = rootDevice; self.layers = layers
        }
    }

    public static func encode(_ envelope: Envelope) throws -> Data {
        var object: [String: Any] = [
            "version": envelope.version,
            "id": envelope.id,
            "operation": envelope.operation,
        ]
        if let payload = envelope.payload {
            object["payload"] = try JSONSerialization.jsonObject(with: payload, options: [.fragmentsAllowed])
        }
        if let error = envelope.error {
            object["error"] = ["code": error.code, "message": error.message]
        }
        let body = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        guard !body.isEmpty, body.count <= maximumControlFrameSize else {
            throw EngineError(.badRequest, "invalid guest control frame size \(body.count)")
        }
        var size = UInt32(body.count).bigEndian
        return Data(bytes: &size, count: MemoryLayout<UInt32>.size) + body
    }

    public static func decode(_ frame: Data) throws -> Envelope {
        guard frame.count >= MemoryLayout<UInt32>.size else {
            throw EngineError(.badRequest, "guest control frame is truncated")
        }
        let size = frame.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard size > 0, size <= maximumControlFrameSize, frame.count == Int(size) + 4 else {
            throw EngineError(.badRequest, "invalid guest control frame size \(size)")
        }
        guard let object = try JSONSerialization.jsonObject(with: frame.dropFirst(4)) as? [String: Any],
              let versionNumber = object["version"] as? NSNumber,
              versionNumber.uint64Value <= UInt32.max,
              let id = object["id"] as? String,
              let operation = object["operation"] as? String else {
            throw EngineError(.badRequest, "invalid guest control envelope")
        }
        let payload = try object["payload"].map {
            try JSONSerialization.data(withJSONObject: $0, options: [.fragmentsAllowed, .sortedKeys])
        }
        let failure: Failure?
        if let value = object["error"] {
            guard let error = value as? [String: Any],
                  let code = error["code"] as? String,
                  let message = error["message"] as? String else {
                throw EngineError(.badRequest, "invalid guest control failure")
            }
            failure = Failure(code: code, message: message)
        } else {
            failure = nil
        }
        let envelope = Envelope(
            version: versionNumber.uint32Value,
            id: id,
            operation: operation,
            payload: payload,
            error: failure
        )
        guard envelope.version == version else {
            throw EngineError(.unsupported, "unsupported guest protocol version \(envelope.version)")
        }
        guard !envelope.id.isEmpty, !envelope.operation.isEmpty else {
            throw EngineError(.badRequest, "guest control envelope requires id and operation")
        }
        return envelope
    }
}

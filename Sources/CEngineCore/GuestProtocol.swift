import Foundation

public enum GuestProtocol {
    public static let version: UInt32 = 3
    public static let controlPort: UInt32 = 4_100
    public static let fileSystemPort: UInt32 = 4_101
    public static let rootFSContentPort: UInt32 = 4_102
    public static let execIOPort: UInt32 = 4_103
    public static let portProxyPort: UInt32 = 4_104
    public static let socketProxyPortBase: UInt32 = 4_200
    public static let maximumControlFrameSize = 16 * 1_024 * 1_024

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
        public var stopSignal: String
        public var volumeServer: String?
        public var mounts: [Mount]
        public var networks: [NetworkEndpoint]
        public var hosts: [String: String]
        public var resources: Resources
        public var privileged: Bool

        public init(id: String, rootDevice: String, arguments: [String], environment: [String], workingDirectory: String, hostname: String, user: User, terminal: Bool, readOnlyRoot: Bool, stopSignal: String, volumeServer: String? = nil, mounts: [Mount], networks: [NetworkEndpoint], hosts: [String: String] = [:], resources: Resources, privileged: Bool = false) {
            self.id = id; self.rootDevice = rootDevice; self.arguments = arguments; self.environment = environment
            self.workingDirectory = workingDirectory; self.hostname = hostname; self.user = user; self.terminal = terminal
            self.readOnlyRoot = readOnlyRoot; self.stopSignal = stopSignal; self.volumeServer = volumeServer; self.mounts = mounts; self.networks = networks; self.hosts = hosts; self.resources = resources; self.privileged = privileged
        }
    }

    public struct User: Codable, Sendable, Equatable {
        public var uid: UInt32
        public var gid: UInt32
        public var additionalGroups: [UInt32]
        public var username: String?
        public init(uid: UInt32 = 0, gid: UInt32 = 0, additionalGroups: [UInt32] = [], username: String? = nil) { self.uid = uid; self.gid = gid; self.additionalGroups = additionalGroups; self.username = username }
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
        public var socketPort: UInt32?
        public var socketMode: UInt32?
        public var socketUID: UInt32?
        public var socketGID: UInt32?
        public init(kind: String, source: String, device: String? = nil, destination: String, readOnly: Bool, options: [String] = [], subpath: String? = nil, noCopy: Bool = false, socketPort: UInt32? = nil, socketMode: UInt32? = nil, socketUID: UInt32? = nil, socketGID: UInt32? = nil) {
            self.kind = kind; self.source = source; self.device = device; self.destination = destination; self.readOnly = readOnly; self.options = options; self.subpath = subpath; self.noCopy = noCopy
            self.socketPort = socketPort; self.socketMode = socketMode; self.socketUID = socketUID; self.socketGID = socketGID
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
        public init(networkID: String, vlan: UInt16, name: String, macAddress: String, addresses: [String], gateways: [String], dns: [String], aliases: [String]) {
            self.networkID = networkID; self.vlan = vlan; self.name = name; self.macAddress = macAddress; self.addresses = addresses; self.gateways = gateways; self.dns = dns; self.aliases = aliases
        }
    }

    public struct Resources: Codable, Sendable, Equatable {
        public var memoryBytes: UInt64
        public var cpuQuota: Int64
        public var cpuPeriod: UInt64
        public var pids: Int64
        public init(memoryBytes: UInt64, cpuQuota: Int64, cpuPeriod: UInt64, pids: Int64) { self.memoryBytes = memoryBytes; self.cpuQuota = cpuQuota; self.cpuPeriod = cpuPeriod; self.pids = pids }
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

import Foundation

public enum VMShimProtocol {
    public static let execStreamActivationByte: UInt8 = 1
    public static let version: UInt32 = 5
    public static let maximumFrameSize = 16 * 1_024 * 1_024
    public static let managementVLAN: UInt16 = 4_094

    public enum Operation: String, Codable, Sendable {
        case boot
        case guest
        case prepareRootFS
        case startExecStream
        case startPortStream
        case configureNetwork
        case configureFabric
        case pause
        case resume
        case stop
        case status
        case shutdown
    }

    public enum State: String, Codable, Sendable {
        case created
        case starting
        case running
        case paused
        case stopping
        case stopped
        case failed
    }

    public struct Envelope: Codable, Sendable, Equatable {
        public var version: UInt32
        public var id: String
        public var token: String
        public var operation: Operation
        public var payload: Data?
        public var error: GuestProtocol.Failure?

        public init(
            version: UInt32 = VMShimProtocol.version,
            id: String = UUID().uuidString,
            token: String,
            operation: Operation,
            payload: Data? = nil,
            error: GuestProtocol.Failure? = nil
        ) {
            self.version = version
            self.id = id
            self.token = token
            self.operation = operation
            self.payload = payload
            self.error = error
        }
    }

    public struct Status: Codable, Sendable, Equatable {
        public var containerID: String
        public var generation: UInt64
        public var state: State
        public var processIdentifier: Int32
        /// Microseconds since the Unix epoch at which this exact shim process
        /// was born. A PID alone is not a stable process identity because
        /// Darwin may reuse it after the shim exits.
        public var processStartTime: UInt64?
        public var exitCode: Int32?
        public var error: String?

        public init(
            containerID: String,
            generation: UInt64,
            state: State,
            processIdentifier: Int32,
            processStartTime: UInt64? = nil,
            exitCode: Int32? = nil,
            error: String? = nil
        ) {
            self.containerID = containerID; self.generation = generation; self.state = state
            self.processIdentifier = processIdentifier; self.processStartTime = processStartTime
            self.exitCode = exitCode; self.error = error
        }
    }

    public struct Specification: Codable, Sendable, Equatable {
        public enum Kind: String, Codable, Sendable { case container, storage }
        public var kind: Kind
        public var containerID: String
        public var generation: UInt64
        public var token: String
        public var kernelPath: String
        public var initialRamdiskPath: String
        public var rootDiskPath: String
        public var rootDiskIdentity: FileIdentity?
        public var rootDiskSize: UInt64?
        public var rootDiskReadOnly: Bool
        public var volumeDisks: [VolumeDisk]
        public var cpus: Int
        public var memoryBytes: UInt64
        public var macAddress: String
        public var bindShares: [BindShare]
        public var socketRelays: [SocketRelay]
        public var socketPath: String
        public var logPath: String
        public var kernelArguments: [String]
        public var fileSystemSocketPath: String?
        public var networkSocketPath: String?
        public var networkNamespace: String
        public var vlans: [UInt16]
        public var rosetta: Bool
        public var outputSpool: OutputSpool?

        public init(
            kind: Kind = .container,
            containerID: String,
            generation: UInt64,
            token: String,
            kernelPath: String,
            initialRamdiskPath: String,
            rootDiskPath: String,
            rootDiskIdentity: FileIdentity? = nil,
            rootDiskSize: UInt64? = nil,
            rootDiskReadOnly: Bool = false,
            volumeDisks: [VolumeDisk] = [],
            cpus: Int,
            memoryBytes: UInt64,
            macAddress: String,
            bindShares: [BindShare] = [],
            socketRelays: [SocketRelay] = [],
            socketPath: String,
            logPath: String,
            kernelArguments: [String] = [],
            fileSystemSocketPath: String? = nil,
            networkSocketPath: String? = nil,
            networkNamespace: String = "",
            vlans: [UInt16] = [],
            rosetta: Bool = false,
            outputSpool: OutputSpool? = nil
        ) {
            self.kind = kind
            self.containerID = containerID
            self.generation = generation
            self.token = token
            self.kernelPath = kernelPath
            self.initialRamdiskPath = initialRamdiskPath
            self.rootDiskPath = rootDiskPath
            self.rootDiskIdentity = rootDiskIdentity
            self.rootDiskSize = rootDiskSize
            self.rootDiskReadOnly = rootDiskReadOnly
            self.volumeDisks = volumeDisks
            self.cpus = cpus
            self.memoryBytes = memoryBytes
            self.macAddress = macAddress
            self.bindShares = bindShares
            self.socketRelays = socketRelays
            self.socketPath = socketPath
            self.logPath = logPath
            self.kernelArguments = kernelArguments
            self.fileSystemSocketPath = fileSystemSocketPath
            self.networkSocketPath = networkSocketPath
            self.networkNamespace = networkNamespace
            self.vlans = vlans
            self.rosetta = rosetta
            self.outputSpool = outputSpool
        }

        // Persisted specifications and prepared-shim journals written before
        // the Rosetta share existed carry no `rosetta` key; decode them as
        // disabled instead of failing daemon recovery.
        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            kind = try container.decode(Kind.self, forKey: .kind)
            containerID = try container.decode(String.self, forKey: .containerID)
            generation = try container.decode(UInt64.self, forKey: .generation)
            token = try container.decode(String.self, forKey: .token)
            kernelPath = try container.decode(String.self, forKey: .kernelPath)
            initialRamdiskPath = try container.decode(String.self, forKey: .initialRamdiskPath)
            rootDiskPath = try container.decode(String.self, forKey: .rootDiskPath)
            rootDiskIdentity = try container.decodeIfPresent(FileIdentity.self, forKey: .rootDiskIdentity)
            rootDiskSize = try container.decodeIfPresent(UInt64.self, forKey: .rootDiskSize)
            rootDiskReadOnly = try container.decode(Bool.self, forKey: .rootDiskReadOnly)
            volumeDisks = try container.decode([VolumeDisk].self, forKey: .volumeDisks)
            cpus = try container.decode(Int.self, forKey: .cpus)
            memoryBytes = try container.decode(UInt64.self, forKey: .memoryBytes)
            macAddress = try container.decode(String.self, forKey: .macAddress)
            bindShares = try container.decode([BindShare].self, forKey: .bindShares)
            socketRelays = try container.decode([SocketRelay].self, forKey: .socketRelays)
            socketPath = try container.decode(String.self, forKey: .socketPath)
            logPath = try container.decode(String.self, forKey: .logPath)
            kernelArguments = try container.decode([String].self, forKey: .kernelArguments)
            fileSystemSocketPath = try container.decodeIfPresent(String.self, forKey: .fileSystemSocketPath)
            networkSocketPath = try container.decodeIfPresent(String.self, forKey: .networkSocketPath)
            networkNamespace = try container.decode(String.self, forKey: .networkNamespace)
            vlans = try container.decode([UInt16].self, forKey: .vlans)
            rosetta = try container.decodeIfPresent(Bool.self, forKey: .rosetta) ?? false
            outputSpool = try container.decodeIfPresent(
                OutputSpool.self, forKey: .outputSpool
            )
        }
    }

    public struct VolumeDisk: Codable, Sendable, Equatable {
        public var name: String
        public var path: String
        public var identity: FileIdentity?
        public var size: UInt64?

        public init(
            name: String,
            path: String,
            identity: FileIdentity? = nil,
            size: UInt64? = nil
        ) {
            self.name = name
            self.path = path
            self.identity = identity
            self.size = size
        }
    }

    public struct FileIdentity: Codable, Sendable, Equatable {
        public var device: UInt64
        public var inode: UInt64

        public init(device: UInt64, inode: UInt64) {
            self.device = device
            self.inode = inode
        }
    }

    public struct OutputSpool: Codable, Sendable, Equatable {
        public var directoryPath: String
        public var directoryIdentity: FileIdentity
        public var stdoutIdentity: FileIdentity
        public var stderrIdentity: FileIdentity
        public var stdoutSpoolDirectoryIdentity: FileIdentity
        public var stderrSpoolDirectoryIdentity: FileIdentity
        public var retainedBytes: Int
        public var segmentBytes: Int
        public var maximumSegments: Int

        public init(
            directoryPath: String,
            directoryIdentity: FileIdentity,
            stdoutIdentity: FileIdentity,
            stderrIdentity: FileIdentity,
            stdoutSpoolDirectoryIdentity: FileIdentity,
            stderrSpoolDirectoryIdentity: FileIdentity,
            retainedBytes: Int,
            segmentBytes: Int,
            maximumSegments: Int
        ) {
            self.directoryPath = directoryPath
            self.directoryIdentity = directoryIdentity
            self.stdoutIdentity = stdoutIdentity
            self.stderrIdentity = stderrIdentity
            self.stdoutSpoolDirectoryIdentity = stdoutSpoolDirectoryIdentity
            self.stderrSpoolDirectoryIdentity = stderrSpoolDirectoryIdentity
            self.retainedBytes = retainedBytes
            self.segmentBytes = segmentBytes
            self.maximumSegments = maximumSegments
        }
    }

    public struct BindShare: Codable, Sendable, Equatable {
        public var tag: String
        public var source: String
        public var readOnly: Bool
        public var sourceIdentity: FileIdentity?

        public init(
            tag: String,
            source: String,
            readOnly: Bool,
            sourceIdentity: FileIdentity? = nil
        ) {
            self.tag = tag
            self.source = source
            self.readOnly = readOnly
            self.sourceIdentity = sourceIdentity
        }
    }

    public struct SocketRelay: Codable, Sendable, Equatable {
        public var path: String
        public var port: UInt32

        public init(path: String, port: UInt32) {
            self.path = path
            self.port = port
        }
    }

    public static func encode(_ envelope: Envelope, encoder: JSONEncoder = JSONEncoder()) throws -> Data {
        let body = try encoder.encode(envelope)
        guard !body.isEmpty, body.count <= maximumFrameSize else {
            throw EngineError(.badRequest, "invalid shim frame size \(body.count)")
        }
        var size = UInt32(body.count).bigEndian
        return Data(bytes: &size, count: 4) + body
    }

    public static func decode(_ frame: Data, decoder: JSONDecoder = JSONDecoder()) throws -> Envelope {
        guard frame.count >= 4 else { throw EngineError(.badRequest, "shim frame is truncated") }
        let size = frame.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard size > 0, size <= maximumFrameSize, frame.count == Int(size) + 4 else {
            throw EngineError(.badRequest, "invalid shim frame size \(size)")
        }
        let envelope = try decoder.decode(Envelope.self, from: frame.dropFirst(4))
        guard envelope.version == version else {
            throw EngineError(.unsupported, "unsupported shim protocol version \(envelope.version)")
        }
        guard !envelope.id.isEmpty, !envelope.token.isEmpty else {
            throw EngineError(.badRequest, "shim envelope requires id and token")
        }
        return envelope
    }
}

import Foundation

/// One-shot, private host/PID1 bootstrap transport. Use these entry points rather
/// than JSONDecoder directly: Codable alone does not enforce the closed schema.
public enum DiskInitializationProtocol {
    public static let version: UInt32 = 1
    public static let port: UInt32 = 4_105
    public static let maxFrame = 65_536
    public static let maximumDisks = 26

    public enum ValidationError: Error, Equatable, Sendable {
        case invalidFrame
    }

    public struct Binding: Codable, Equatable, Sendable {
        public var shimLaunchUUID: String
        public var guestBootNonce: String
        public var ext4UUID: String
        public var bytes: UInt64
        public init(shimLaunchUUID: String, guestBootNonce: String, ext4UUID: String, bytes: UInt64) {
            self.shimLaunchUUID = shimLaunchUUID; self.guestBootNonce = guestBootNonce
            self.ext4UUID = ext4UUID; self.bytes = bytes
        }
    }

    public struct InventoryDisk: Codable, Equatable, Sendable {
        public var ordinal: Int
        public var blockIdentifier: String
        public var bytes: UInt64
        public init(ordinal: Int, blockIdentifier: String, bytes: UInt64) {
            self.ordinal = ordinal; self.blockIdentifier = blockIdentifier; self.bytes = bytes
        }
    }

    public struct Hello: Codable, Equatable, Sendable {
        public var version: UInt32
        public var type: String
        public var kind: String
        public var guestBootNonce: String
        public var disks: [InventoryDisk]
        public init(version: UInt32 = DiskInitializationProtocol.version, type: String = "hello",
                    kind: String, guestBootNonce: String, disks: [InventoryDisk]) {
            self.version = version; self.type = type; self.kind = kind
            self.guestBootNonce = guestBootNonce; self.disks = disks
        }
    }

    public struct ManifestDisk: Codable, Equatable, Sendable {
        public var ordinal: Int
        public var role: String
        public var action: String
        public var expectedBytes: UInt64
        public var ext4UUID: String?
        public var operationUUID: String?
        public var volumeName: String?
        public init(ordinal: Int, role: String, action: String, expectedBytes: UInt64,
                    ext4UUID: String? = nil, operationUUID: String? = nil, volumeName: String? = nil) {
            self.ordinal = ordinal; self.role = role; self.action = action
            self.expectedBytes = expectedBytes; self.ext4UUID = ext4UUID
            self.operationUUID = operationUUID; self.volumeName = volumeName
        }
    }

    public struct Manifest: Codable, Equatable, Sendable {
        public var version: UInt32
        public var type: String
        public var kind: String
        public var shimLaunchUUID: String
        public var guestBootNonce: String
        public var disks: [ManifestDisk]
        public init(version: UInt32 = DiskInitializationProtocol.version, type: String = "manifest",
                    kind: String, shimLaunchUUID: String, guestBootNonce: String, disks: [ManifestDisk]) {
            self.version = version; self.type = type; self.kind = kind
            self.shimLaunchUUID = shimLaunchUUID; self.guestBootNonce = guestBootNonce; self.disks = disks
        }
    }

    public struct SyncedDisk: Codable, Equatable, Sendable {
        public var ordinal: Int
        public var bytes: UInt64
        public var ext4UUID: String
        public var operationUUID: String?
        public init(ordinal: Int, bytes: UInt64, ext4UUID: String, operationUUID: String? = nil) {
            self.ordinal = ordinal; self.bytes = bytes; self.ext4UUID = ext4UUID
            self.operationUUID = operationUUID
        }
    }

    public struct Synced: Codable, Equatable, Sendable {
        public var version: UInt32
        public var type: String
        public var shimLaunchUUID: String
        public var guestBootNonce: String
        public var sync: String
        public var disks: [SyncedDisk]
        public init(version: UInt32 = DiskInitializationProtocol.version, type: String = "synced",
                    shimLaunchUUID: String, guestBootNonce: String,
                    sync: String = "filesystem-and-block", disks: [SyncedDisk]) {
            self.version = version; self.type = type; self.shimLaunchUUID = shimLaunchUUID
            self.guestBootNonce = guestBootNonce; self.sync = sync; self.disks = disks
        }
    }

    public struct Commit: Codable, Equatable, Sendable {
        public var version: UInt32
        public var type: String
        public var shimLaunchUUID: String
        public var guestBootNonce: String
        public init(version: UInt32 = DiskInitializationProtocol.version, type: String = "commit",
                    shimLaunchUUID: String, guestBootNonce: String) {
            self.version = version; self.type = type
            self.shimLaunchUUID = shimLaunchUUID; self.guestBootNonce = guestBootNonce
        }
    }

    public struct ErrorFrame: Codable, Equatable, Sendable {
        public var version: UInt32
        public var type: String
        public var code: String
        public var ordinal: Int?
        public init(version: UInt32 = DiskInitializationProtocol.version, type: String = "error",
                    code: String, ordinal: Int? = nil) {
            self.version = version; self.type = type; self.code = code; self.ordinal = ordinal
        }
    }

    public static func validUUID(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard bytes.count == 36, value != "00000000-0000-0000-0000-000000000000" else { return false }
        return bytes.enumerated().allSatisfy { index, byte in
            [8, 13, 18, 23].contains(index) ? byte == 45
                : (48...57).contains(byte) || (97...102).contains(byte)
        }
    }

    /// Includes the uint32 big-endian length prefix. The limit excludes the prefix.
    public static func encode<T: Encodable>(_ message: T) throws -> Data {
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let body = try encoder.encode(message)
            try validate(body, expectedType: messageType(T.self))
            var length = UInt32(body.count).bigEndian
            return Data(bytes: &length, count: 4) + body
        } catch { throw ValidationError.invalidFrame }
    }

    /// Accepts exactly one unframed JSON body, not a length-prefixed frame.
    public static func decode<T: Decodable>(_ type: T.Type, from body: Data) throws -> T {
        do {
            try validate(body, expectedType: messageType(type))
            return try JSONDecoder().decode(type, from: body)
        } catch { throw ValidationError.invalidFrame }
    }

    private static func messageType<T>(_ type: T.Type) throws -> String {
        switch type {
        case is Hello.Type: "hello"
        case is Manifest.Type: "manifest"
        case is Synced.Type: "synced"
        case is Commit.Type: "commit"
        case is ErrorFrame.Type: "error"
        default: throw ValidationError.invalidFrame
        }
    }

    private static func validate(_ body: Data, expectedType: String) throws {
        guard !body.isEmpty, body.count <= maxFrame else { throw ValidationError.invalidFrame }
        var parser = Parser(bytes: Array(body))
        let message = try parser.parse().object()
        guard try message.number("version") == UInt64(version),
              try message.string("type") == expectedType else { throw ValidationError.invalidFrame }
        switch expectedType {
        case "hello":
            try message.keys(required: ["version", "type", "kind", "guestBootNonce", "disks"])
            try message.uuid("guestBootNonce")
            let kind = try message.kind()
            let disks = try message.disks()
            guard kind != "storage" || disks.count == 1 else { throw ValidationError.invalidFrame }
            for (ordinal, disk) in disks.enumerated() {
                try disk.keys(required: ["ordinal", "blockIdentifier", "bytes"])
                try disk.ordinal(ordinal)
                try disk.capacity("bytes")
                guard try disk.string("blockIdentifier") == (ordinal == 0 ? "root" : "volume\(ordinal - 1)") else {
                    throw ValidationError.invalidFrame
                }
            }
        case "manifest":
            try message.keys(required: ["version", "type", "kind", "shimLaunchUUID", "guestBootNonce", "disks"])
            try message.session()
            let kind = try message.kind()
            let disks = try message.disks()
            guard kind != "storage" || disks.count == 1 else { throw ValidationError.invalidFrame }
            var names = Set<String>()
            var operations = Set<String>()
            for (ordinal, disk) in disks.enumerated() {
                try disk.keys(required: ["ordinal", "role", "action", "expectedBytes"],
                              optional: ["ext4UUID", "operationUUID", "volumeName"])
                try disk.ordinal(ordinal)
                try disk.capacity("expectedBytes")
                let role = kind == "storage" ? "storage-root" : ordinal == 0 ? "container-root" : "direct-volume"
                guard try disk.string("role") == role else { throw ValidationError.invalidFrame }
                if role == "direct-volume" {
                    let name = try disk.string("volumeName")
                    guard !name.isEmpty, name != ".", name != "..", name.utf8.count <= 255,
                          !name.contains("/"), !name.contains("\\"), !name.utf8.contains(0),
                          names.insert(name).inserted else { throw ValidationError.invalidFrame }
                } else if disk["volumeName"] != nil { throw ValidationError.invalidFrame }
                if disk["ext4UUID"] != nil { try disk.uuid("ext4UUID") }
                switch try disk.string("action") {
                case "initialize-ext4":
                    try disk.uuid("ext4UUID")
                    try disk.uuid("operationUUID")
                    let bytes = try disk.number("expectedBytes")
                    guard bytes >= 16 * 1_024 * 1_024, bytes % 4_096 == 0,
                          operations.insert(try disk.string("operationUUID")).inserted else {
                        throw ValidationError.invalidFrame
                    }
                case "mount-existing-ext4":
                    guard disk["operationUUID"] == nil else { throw ValidationError.invalidFrame }
                case "probe-read-only":
                    guard kind == "storage", disk["operationUUID"] == nil else { throw ValidationError.invalidFrame }
                    try disk.uuid("ext4UUID")
                default: throw ValidationError.invalidFrame
                }
            }
        case "synced":
            try message.keys(required: ["version", "type", "shimLaunchUUID", "guestBootNonce", "sync", "disks"])
            try message.session()
            let sync = try message.string("sync")
            guard ["filesystem-and-block", "read-only-no-replay"].contains(sync) else { throw ValidationError.invalidFrame }
            if sync == "read-only-no-replay" {
                let disks = try message.disks()
                guard disks.count == 1, disks[0]["operationUUID"] == nil else { throw ValidationError.invalidFrame }
            }
            var operations = Set<String>()
            for (ordinal, disk) in try message.disks().enumerated() {
                try disk.keys(required: ["ordinal", "bytes", "ext4UUID"], optional: ["operationUUID"])
                try disk.ordinal(ordinal)
                try disk.capacity("bytes")
                try disk.uuid("ext4UUID")
                if disk["operationUUID"] != nil {
                    try disk.uuid("operationUUID")
                    guard operations.insert(try disk.string("operationUUID")).inserted else {
                        throw ValidationError.invalidFrame
                    }
                }
            }
        case "commit":
            try message.keys(required: ["version", "type", "shimLaunchUUID", "guestBootNonce"])
            try message.session()
        case "error":
            try message.keys(required: ["version", "type", "code"], optional: ["ordinal"])
            guard ["invalid-peer", "invalid-frame", "invalid-manifest", "disk-mismatch", "disk-operation", "sync", "commit"]
                .contains(try message.string("code")) else { throw ValidationError.invalidFrame }
            if message["ordinal"] != nil {
                guard try message.number("ordinal") < UInt64(maximumDisks) else { throw ValidationError.invalidFrame }
            }
        default: throw ValidationError.invalidFrame
        }
    }

    fileprivate indirect enum Value {
        case object([String: Value]), array([Value]), string(String), number(UInt64)
        func object() throws -> [String: Value] {
            guard case .object(let value) = self else { throw ValidationError.invalidFrame }
            return value
        }
    }

    /// A deliberately small JSON grammar: this schema has no null, boolean,
    /// negative or fractional values. Inspect tokens before Foundation can erase
    /// duplicate keys or normalize exponent/fractional integer spellings.
    private struct Parser {
        let bytes: [UInt8]
        var index = 0

        mutating func parse() throws -> Value {
            let value = try value(depth: 0)
            whitespace()
            guard index == bytes.count else { throw ValidationError.invalidFrame }
            return value
        }

        mutating func whitespace() {
            while index < bytes.count, [9, 10, 13, 32].contains(bytes[index]) { index += 1 }
        }

        mutating func consume(_ byte: UInt8) -> Bool {
            whitespace()
            guard index < bytes.count, bytes[index] == byte else { return false }
            index += 1
            return true
        }

        mutating func value(depth: Int) throws -> Value {
            whitespace()
            guard depth <= 8, index < bytes.count else { throw ValidationError.invalidFrame }
            switch bytes[index] {
            case 123:
                index += 1
                var fields: [String: Value] = [:]
                if consume(125) { return .object(fields) }
                repeat {
                    whitespace()
                    let key = try string()
                    guard fields[key] == nil, consume(58) else { throw ValidationError.invalidFrame }
                    fields[key] = try value(depth: depth + 1)
                    if consume(125) { return .object(fields) }
                } while consume(44)
                throw ValidationError.invalidFrame
            case 91:
                index += 1
                var values: [Value] = []
                if consume(93) { return .array(values) }
                repeat {
                    values.append(try value(depth: depth + 1))
                    guard values.count <= maximumDisks else { throw ValidationError.invalidFrame }
                    if consume(93) { return .array(values) }
                } while consume(44)
                throw ValidationError.invalidFrame
            case 34: return .string(try string())
            case 48...57:
                let start = index
                while index < bytes.count, (48...57).contains(bytes[index]) { index += 1 }
                guard index == start + 1 || bytes[start] != 48,
                      let number = UInt64(String(decoding: bytes[start..<index], as: UTF8.self)),
                      number <= UInt64(Int64.max) else { throw ValidationError.invalidFrame }
                return .number(number)
            default: throw ValidationError.invalidFrame
            }
        }

        mutating func string() throws -> String {
            guard index < bytes.count, bytes[index] == 34 else { throw ValidationError.invalidFrame }
            let start = index
            index += 1
            while index < bytes.count {
                let byte = bytes[index]
                index += 1
                if byte == 34 {
                    let data = Data(bytes[start..<index])
                    guard String(data: data, encoding: .utf8) != nil else { throw ValidationError.invalidFrame }
                    return try JSONDecoder().decode(String.self, from: data)
                }
                guard byte >= 32 else { throw ValidationError.invalidFrame }
                if byte == 92 {
                    guard index < bytes.count else { throw ValidationError.invalidFrame }
                    index += 1
                }
            }
            throw ValidationError.invalidFrame
        }
    }
}

private extension Dictionary where Key == String, Value == DiskInitializationProtocol.Value {
    func keys(required: Set<String>, optional: Set<String> = []) throws {
        let actual = Set(keys)
        guard required.isSubset(of: actual), actual.isSubset(of: required.union(optional)) else {
            throw DiskInitializationProtocol.ValidationError.invalidFrame
        }
    }
    func string(_ key: String) throws -> String {
        guard case .string(let value) = self[key] else { throw DiskInitializationProtocol.ValidationError.invalidFrame }
        return value
    }
    func number(_ key: String) throws -> UInt64 {
        guard case .number(let value) = self[key] else { throw DiskInitializationProtocol.ValidationError.invalidFrame }
        return value
    }
    func uuid(_ key: String) throws {
        guard try DiskInitializationProtocol.validUUID(string(key)) else { throw DiskInitializationProtocol.ValidationError.invalidFrame }
    }
    func session() throws {
        try uuid("shimLaunchUUID")
        try uuid("guestBootNonce")
    }
    func kind() throws -> String {
        let value = try string("kind")
        guard ["container", "storage"].contains(value) else { throw DiskInitializationProtocol.ValidationError.invalidFrame }
        return value
    }
    func capacity(_ key: String) throws {
        guard try number(key) > 0 else { throw DiskInitializationProtocol.ValidationError.invalidFrame }
    }
    func ordinal(_ expected: Int) throws {
        guard try number("ordinal") == UInt64(expected) else { throw DiskInitializationProtocol.ValidationError.invalidFrame }
    }
    func disks() throws -> [[String: Value]] {
        guard case .array(let disks) = self["disks"], !disks.isEmpty,
              disks.count <= DiskInitializationProtocol.maximumDisks else { throw DiskInitializationProtocol.ValidationError.invalidFrame }
        return try disks.map { try $0.object() }
    }
}

import CryptoKit
import Darwin
import Foundation

/// Private 4109 wire values, not authority. Use encode/decode, never Codable alone.
/// A session must pin the sealed 4105 boot binding and scope, serialize commands,
/// and enforce strictly increasing sequences. No private keys belong here.
public enum WorkloadStorageProtocol {
    public static let version: UInt32 = 1
    public static let type = "workload-storage.v1"
    public static let port: UInt32 = 4_109
    public static let dataPort: UInt16 = 2_049
    public static let maxFrame = 1_024 * 1_024
    public static let maximumWorkloadBytes = 512 * 1_024
    public static let maximumArrayElements = 64
    public static let maximumMounts = 64
    public static let maximumSlots = 64
    public static let maximumCSRBytes = 4 * 1_024
    public static let maximumDERBytes = 16 * 1_024
    public static let maximumTerminalIDs = 32
    public static let maximumEvents = 32
    public static let maximumStringBytes = 4 * 1_024
    public enum ValidationError: Error, Equatable, Sendable { case invalidFrame }
    public enum Operation: String, Codable, Sendable { case hello, configure, configured, command, reply, terminal, prepareCheckpoint = "prepare-checkpoint", prepareEarlyCheckpoint = "prepare-early-checkpoint" }
    public enum Kind: String, Codable, Sendable {
        case offerKeys = "offer-keys", installCertificate = "install-certificate", mountPhase = "mount-phase"
        case prepareCompatibilityArm = "prepare-compatibility-arm"
        case prepare, closePhase = "close-phase", start, status, abort
    }
    public enum Role: String, Codable, Sendable { case prepare, runtime }
    public enum Mode: String, Codable, Sendable { case readOnly = "read-only", readWrite = "read-write" }
    public enum Phase: String, Codable, Sendable {
        case configured, keysOffered = "keys-offered", certificatesInstalled = "certificates-installed"
        case prepareMounted = "prepare-mounted", prepared, prepareClosed = "prepare-closed"
        case runtimeMounted = "runtime-mounted", running, aborted, terminal
    }
    public enum Code: String, Codable, Sendable {
        case invalidFrame = "invalid-frame", bindingMismatch = "binding-mismatch", scopeMismatch = "scope-mismatch"
        case configuration, sequence, phase, certificate, mount, prepare, start, aborted, terminal
        case internalError = "internal"
    }

    public struct BootBinding: Codable, Equatable, Sendable {
        public var shimLaunchUUID: String
        public var guestBootNonce: String
        public init(shimLaunchUUID: String, guestBootNonce: String) {
            self.shimLaunchUUID = shimLaunchUUID
            self.guestBootNonce = guestBootNonce
        }
    }

    public struct Scope: Codable, Equatable, Sendable {
        public var intent: String
        public var store: String
        public var serviceEpoch: String
        public var controllerEpoch: UInt64
        public var controllerKey: String
        public var container: String
        public var containerInstance: String
        public var launch: String
        public var prepare: String
        public var specificationDigest: String
        public init(intent: String, store: String, serviceEpoch: String, controllerEpoch: UInt64, controllerKey: String, container: String, containerInstance: String, launch: String, prepare: String, specificationDigest: String) {
            self.intent = intent
            self.store = store
            self.serviceEpoch = serviceEpoch
            self.controllerEpoch = controllerEpoch
            self.controllerKey = controllerKey
            self.container = container
            self.containerInstance = containerInstance
            self.launch = launch
            self.prepare = prepare
            self.specificationDigest = specificationDigest
        }
    }

    public struct Peer: Codable, Equatable, Sendable {
        public var tlsRootDER: Data
        public var serverDER: Data
        public var serverKey: String
        public var dataAddress: String
        public init(tlsRootDER: Data, serverDER: Data, serverKey: String, dataAddress: String) {
            self.tlsRootDER = tlsRootDER
            self.serverDER = serverDER
            self.serverKey = serverKey
            self.dataAddress = dataAddress
        }
    }

    public struct Slot: Codable, Equatable, Sendable {
        public var volume: String
        public var attachment: String
        public var role: Role
        public var mode: Mode
        public init(volume: String, attachment: String, role: Role, mode: Mode) {
            self.volume = volume
            self.attachment = attachment
            self.role = role
            self.mode = mode
        }
    }

    public struct MountBinding: Codable, Equatable, Sendable {
        public var index: UInt32
        public var volume: String
        public var destination: String
        public var subpath: String
        public var mode: Mode
        public var noCopy: Bool
        public init(index: UInt32, volume: String, destination: String, subpath: String, mode: Mode, noCopy: Bool) {
            self.index = index
            self.volume = volume
            self.destination = destination
            self.subpath = subpath
            self.mode = mode
            self.noCopy = noCopy
        }
    }

    public struct Offer: Codable, Equatable, Sendable {
        public var attachment: String
        public var key: String
        public var csrDER: Data
        public init(attachment: String, key: String, csrDER: Data) {
            self.attachment = attachment
            self.key = key
            self.csrDER = csrDER
        }
    }

    public struct Payload: Codable, Equatable, Sendable {
        public var compatibilityProfile: String?
        public var compatibilityArm: ManagedPrepareCompatibilityProtocol.Arm?
        public var compatibilityDigest: String?
        public var compatibilityObservation: ManagedPrepareCompatibilityProtocol.Observation?
        public var compatibilityIOObservation: ManagedPrepareCompatibilityProtocol.IOObservation?
        public var compatibilityEarlyObservation: ManagedPrepareCompatibilityProtocol.EarlyObservation?
        public var peer: Peer?
        public var mounts: [MountBinding]?
        public var slots: [Slot]?
        public var role: Role?
        public var attachment: String?
        public var certificateDER: Data?
        public var workloadJSON: Data?
        public var ioClaim: String?
        public var offers: [Offer]?
        public var attachmentIDs: [String]?
        public var prepare: String?
        public var containerInstance: String?
        public var launch: String?
        public var succeeded: Bool?
        public var cleanCopyUp: Bool?
        public var evidenceDigest: String?
        public var clean: Bool?
        public var status: String?
        public var pid: UInt32?
        public var phase: Phase?
        public var mountedIDs: [String]?
        public var terminalIDs: [String]?
        public var code: Code?
        public init(compatibilityProfile: String? = nil, compatibilityArm: ManagedPrepareCompatibilityProtocol.Arm? = nil, compatibilityDigest: String? = nil, compatibilityObservation: ManagedPrepareCompatibilityProtocol.Observation? = nil, compatibilityEarlyObservation: ManagedPrepareCompatibilityProtocol.EarlyObservation? = nil, compatibilityIOObservation: ManagedPrepareCompatibilityProtocol.IOObservation? = nil, peer: Peer? = nil, mounts: [MountBinding]? = nil, slots: [Slot]? = nil, role: Role? = nil, attachment: String? = nil, certificateDER: Data? = nil, workloadJSON: Data? = nil, ioClaim: String? = nil, offers: [Offer]? = nil, attachmentIDs: [String]? = nil, prepare: String? = nil, containerInstance: String? = nil, launch: String? = nil, succeeded: Bool? = nil, cleanCopyUp: Bool? = nil, evidenceDigest: String? = nil, clean: Bool? = nil, status: String? = nil, pid: UInt32? = nil, phase: Phase? = nil, mountedIDs: [String]? = nil, terminalIDs: [String]? = nil, code: Code? = nil) {
            self.compatibilityProfile = compatibilityProfile
            self.compatibilityArm = compatibilityArm
            self.compatibilityDigest = compatibilityDigest
            self.compatibilityObservation = compatibilityObservation
            self.compatibilityEarlyObservation = compatibilityEarlyObservation
            self.compatibilityIOObservation = compatibilityIOObservation
            self.peer = peer
            self.mounts = mounts
            self.slots = slots
            self.role = role
            self.attachment = attachment
            self.certificateDER = certificateDER
            self.workloadJSON = workloadJSON
            self.ioClaim = ioClaim
            self.offers = offers
            self.attachmentIDs = attachmentIDs
            self.prepare = prepare
            self.containerInstance = containerInstance
            self.launch = launch
            self.succeeded = succeeded
            self.cleanCopyUp = cleanCopyUp
            self.evidenceDigest = evidenceDigest
            self.clean = clean
            self.status = status
            self.pid = pid
            self.phase = phase
            self.mountedIDs = mountedIDs
            self.terminalIDs = terminalIDs
            self.code = code
        }
    }

    public struct Frame: Codable, Equatable, Sendable {
        public var version: UInt32
        public var type: String
        public var operation: Operation
        public var binding: BootBinding
        public var scope: Scope?
        public var sequence: UInt64?
        public var kind: Kind?
        public var data: Payload
        public init(version: UInt32 = WorkloadStorageProtocol.version, type: String = WorkloadStorageProtocol.type, operation: Operation, binding: BootBinding, scope: Scope? = nil, sequence: UInt64? = nil, kind: Kind? = nil, data: Payload = Payload()) {
            self.version = version
            self.type = type
            self.operation = operation
            self.binding = binding
            self.scope = scope
            self.sequence = sequence
            self.kind = kind
            self.data = data
        }
    }

    /// SHA-256 of the exact serialized workload bytes, not of a decoded/reencoded object.
    /// The caller MUST set Workload.ioClaim to "" before its single serialization.
    public static func specificationDigest(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    /// Returns a uint32 big-endian length prefix followed by a closed JSON body.
    public static func encode(_ frame: Frame) throws -> Data {
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            let body = try encoder.encode(frame)
            _ = try decode(from: body)
            var length = UInt32(body.count).bigEndian
            return Data(bytes: &length, count: 4) + body
        } catch { throw ValidationError.invalidFrame }
    }

    /// Validate the four-byte prefix BEFORE allocating or reading its body.
    public static func frameBodyLength(from prefix: Data) throws -> Int {
        guard prefix.count == 4 else { throw ValidationError.invalidFrame }
        let count = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard count > 0, count <= maxFrame else { throw ValidationError.invalidFrame }
        return Int(count)
    }

    /// Caller owns I/O, absolute deadlines and cancellation. No requested read
    /// exceeds maxFrame; readExactly must return precisely the requested count.
    public static func readFrame(readExactly: (Int) throws -> Data) throws -> Frame {
        let length = try frameBodyLength(from: readExactly(4))
        let body = try readExactly(length)
        guard body.count == length else { throw ValidationError.invalidFrame }
        return try decode(from: body)
    }

    /// Exactly one unframed JSON body. Rejects unknown/duplicate/null fields,
    /// noncanonical integers/base64, trailing data, and mismatched union payloads.
    public static func decode(from body: Data) throws -> Frame {
        do {
            guard !body.isEmpty, body.count <= maxFrame else { throw ValidationError.invalidFrame }
            var parser = Parser(bytes: Array(body))
            let original = try parser.parse()
            let frame = try JSONDecoder().decode(Frame.self, from: body)
            // Synthesized Codable alone ignores unknown fields. Comparing token trees
            // after typed encoding closes every nested DTO without a second schema.
            var typed = Parser(bytes: Array(try JSONEncoder().encode(frame)))
            guard try original == typed.parse() else { throw ValidationError.invalidFrame }
            try validate(frame, fields: original.object().object("data").keys)
            return frame
        } catch { throw ValidationError.invalidFrame }
    }

    public static func validID(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard bytes.count == 36, bytes[14] == 52, [56, 57, 97, 98].contains(bytes[19]) else { return false }
        return bytes.enumerated().allSatisfy { index, byte in
            [8, 13, 18, 23].contains(index) ? byte == 45 : hex(byte)
        }
    }
    private static func hex(_ byte: UInt8) -> Bool { (48...57).contains(byte) || (97...102).contains(byte) }
    private static func pin(_ value: String) -> Bool { value.utf8.count == 64 && value.utf8.allSatisfy(hex) }
    private static func bounded(_ data: Data?, _ maximum: Int) -> Bool {
        guard let data else { return false }
        return !data.isEmpty && data.count <= maximum
    }
    private static func text(_ value: String) -> Bool {
        value.utf8.count <= maximumStringBytes && !value.utf8.contains(0)
    }
    private static func ids(_ values: [String]?, maximum: Int = maximumSlots) -> Bool {
        guard let values else { return false }
        return values.count <= maximum && values.allSatisfy(validID) && Set(values).count == values.count
    }
    private static func literalIP(_ value: String) -> Bool {
        // Darwin inet_pton accepts zones and leading-zero IPv4 components;
        // Go netip deliberately rejects both. Enforce the common strict grammar.
        guard !value.isEmpty, value.utf8.allSatisfy({ hex($0) || (65...70).contains($0) || $0 == 58 || $0 == 46 }) else { return false }
        if value.contains(".") {
            let tail = value.split(separator: ":", omittingEmptySubsequences: false).last ?? ""
            let parts = tail.split(separator: ".", omittingEmptySubsequences: false)
            guard parts.count == 4, parts.allSatisfy({ part in
                !part.isEmpty && part.utf8.allSatisfy({ (48...57).contains($0) }) &&
                (part.count == 1 || part.first != "0") && UInt8(part) != nil
            }) else { return false }
        }
        var v4 = in_addr()
        var v6 = in6_addr()
        return value.withCString { inet_pton(AF_INET, $0, &v4) == 1 || inet_pton(AF_INET6, $0, &v6) == 1 }
    }
    private static func require(_ condition: Bool) throws {
        guard condition else { throw ValidationError.invalidFrame }
    }

    /// Structural plan validation only. Path confinement and session authority are
    /// deliberately not established here; an empty subpath is explicitly legal.
    public static func validateConfiguration(mounts: [MountBinding], slots: [Slot]) throws {
        try require(mounts.count <= maximumMounts && slots.count <= maximumSlots)
        var indexes = Set<UInt32>(), attachments = Set<String>()
        var volumes = Set<String>(), expected = Set<String>(), actual = Set<String>()
        for mount in mounts {
            try require(mount.index < maximumMounts && indexes.insert(mount.index).inserted && validID(mount.volume))
            try require(text(mount.destination) && mount.destination.hasPrefix("/") && text(mount.subpath))
            volumes.insert(mount.volume)
            expected.insert(mount.volume + ":prepare:read-write")
            expected.insert(mount.volume + ":runtime:" + mount.mode.rawValue)
        }
        for slot in slots {
            try require(validID(slot.volume) && validID(slot.attachment) && attachments.insert(slot.attachment).inserted)
            try require(volumes.contains(slot.volume))
            try require(actual.insert(slot.volume + ":" + slot.role.rawValue + ":" + slot.mode.rawValue).inserted)
        }
        try require(actual == expected)
    }

    private static func validate(_ frame: Frame, fields: Dictionary<String, Value>.Keys) throws {
        try require(frame.version == version && frame.type == type)
        try require(validID(frame.binding.shimLaunchUUID) && validID(frame.binding.guestBootNonce))
        let keys = Set(fields)
        func shape(_ expected: Set<String>) throws { try require(keys == expected) }
        let data = frame.data
        if frame.operation == .hello {
            try require(frame.scope == nil && frame.sequence == nil && frame.kind == nil)
            if let profile = data.compatibilityProfile {
                try shape(["compatibilityProfile"]); try require(ManagedPrepareCompatibilityProtocol.profileVersion(profile) != nil)
            } else { try shape([]) }
            return
        }
        guard let scope = frame.scope else { throw ValidationError.invalidFrame }
        try require([scope.intent, scope.store, scope.serviceEpoch, scope.containerInstance, scope.launch, scope.prepare].allSatisfy(validID))
        try require(scope.controllerEpoch > 0 && [scope.controllerKey, scope.container, scope.specificationDigest].allSatisfy(pin))
        try require(frame.binding.shimLaunchUUID == scope.launch)
        if frame.operation == .command || frame.operation == .reply {
            try require(frame.sequence != nil && frame.sequence! > 0 && frame.kind != nil)
        } else { try require(frame.sequence == nil && frame.kind == nil) }
        switch frame.operation {
        case .hello: throw ValidationError.invalidFrame
        case .configure:
            try shape(["peer", "mounts", "slots"])
            guard let peer = data.peer, let mounts = data.mounts, let slots = data.slots else { throw ValidationError.invalidFrame }
            try require(bounded(peer.tlsRootDER, maximumDERBytes) && bounded(peer.serverDER, maximumDERBytes))
            try require(pin(peer.serverKey) && literalIP(peer.dataAddress))
            try validateConfiguration(mounts: mounts, slots: slots)
        case .prepareCheckpoint:
            if let observation = data.compatibilityIOObservation {
                try shape(["compatibilityIOObservation"])
                try ManagedPrepareCompatibilityProtocol.validate(observation)
                return
            }
            try shape(["compatibilityObservation"])
            guard let observation = data.compatibilityObservation else { throw ValidationError.invalidFrame }
            try ManagedPrepareCompatibilityProtocol.validate(observation)
        case .prepareEarlyCheckpoint:
            try shape(["compatibilityEarlyObservation"])
            guard let observation = data.compatibilityEarlyObservation else { throw ValidationError.invalidFrame }
            try ManagedPrepareCompatibilityProtocol.validate(observation)
        case .configured: try shape([])
        case .terminal:
            try shape(["attachmentIDs", "code"])
            try require(ids(data.attachmentIDs, maximum: maximumTerminalIDs) && !(data.attachmentIDs?.isEmpty ?? true) && data.code != nil)
        case .command:
            switch frame.kind! {
            case .prepareCompatibilityArm:
                try shape(["compatibilityArm"])
                guard let arm = data.compatibilityArm, arm.binding == frame.binding, arm.scope == scope else { throw ValidationError.invalidFrame }
                try ManagedPrepareCompatibilityProtocol.validate(arm)
            case .offerKeys, .mountPhase, .closePhase:
                try shape(["role"]); try require(data.role != nil)
            case .installCertificate:
                try shape(["attachment", "certificateDER"])
                try require(validID(data.attachment ?? "") && bounded(data.certificateDER, maximumDERBytes))
            case .prepare:
                try shape(["workloadJSON", "ioClaim"])
                guard let workload = data.workloadJSON, let claim = data.ioClaim else { throw ValidationError.invalidFrame }
                try require(bounded(workload, maximumWorkloadBytes) && text(claim))
                try require(specificationDigest(workload) == scope.specificationDigest)
            case .start, .status, .abort: try shape([])
            }
        case .reply:
            if data.code != nil { try shape(["code"]); return }
            switch frame.kind! {
            case .prepareCompatibilityArm:
                try shape(["compatibilityDigest"]); try require(pin(data.compatibilityDigest ?? ""))
            case .offerKeys:
                try shape(["offers"])
                guard let offers = data.offers else { throw ValidationError.invalidFrame }
                try require(ids(offers.map(\.attachment)))
                for offer in offers { try require(pin(offer.key) && bounded(offer.csrDER, maximumCSRBytes)) }
            case .installCertificate:
                try shape(["attachment"]); try require(validID(data.attachment ?? ""))
            case .mountPhase:
                try shape(["attachmentIDs"]); try require(ids(data.attachmentIDs))
            case .prepare:
                try shape(["prepare", "containerInstance", "launch", "succeeded", "cleanCopyUp", "evidenceDigest"])
                try require(data.prepare == scope.prepare && data.containerInstance == scope.containerInstance && data.launch == scope.launch)
                try require(data.succeeded != nil && data.cleanCopyUp != nil && pin(data.evidenceDigest ?? ""))
            case .closePhase:
                try shape(["role", "attachmentIDs", "clean"])
                try require(data.role != nil && ids(data.attachmentIDs) && data.clean != nil)
            case .start:
                try shape(["status", "pid"])
                try require(data.status == "running" && data.pid != nil && data.pid! > 0 && data.pid! <= Int32.max)
            case .status:
                try shape(["phase", "mountedIDs", "terminalIDs"])
                try require(data.phase != nil && ids(data.mountedIDs) && ids(data.terminalIDs, maximum: maximumTerminalIDs))
                try require(Set(data.mountedIDs!).isDisjoint(with: data.terminalIDs!))
            case .abort:
                try shape(["terminalIDs"]); try require(ids(data.terminalIDs, maximum: maximumTerminalIDs))
            }
        }
    }

    // Token-preserving closed JSON grammar.
    // Bool is needed for noCopy/completion. Null, negative/fraction/exponent numbers
    // are never part of this envelope; workload bytes remain opaque base64.
    indirect enum Value: Equatable {
        case object([String: Value]), array([Value]), string(String), number(UInt64), boolean(Bool)
        func object() throws -> [String: Value] {
            guard case .object(let object) = self else { throw ValidationError.invalidFrame }
            return object
        }
    }
    struct Parser {
        let bytes: [UInt8]
        var index = 0
        var maximumDepth = 8
        mutating func parse() throws -> Value {
            let result = try value(depth: 0)
            whitespace()
            guard index == bytes.count else { throw ValidationError.invalidFrame }
            return result
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
            guard depth <= maximumDepth, index < bytes.count else { throw ValidationError.invalidFrame }
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
                    guard values.count < maximumArrayElements else { throw ValidationError.invalidFrame }
                    values.append(try value(depth: depth + 1))
                    if consume(93) { return .array(values) }
                } while consume(44)
                throw ValidationError.invalidFrame
            case 34: return .string(try string())
            case 48...57:
                let start = index
                while index < bytes.count, (48...57).contains(bytes[index]) { index += 1 }
                guard index == start + 1 || bytes[start] != 48,
                      let number = UInt64(String(decoding: bytes[start..<index], as: UTF8.self)) else { throw ValidationError.invalidFrame }
                return .number(number)
            case 116:
                guard bytes[index...].starts(with: [116, 114, 117, 101]) else { throw ValidationError.invalidFrame }
                index += 4; return .boolean(true)
            case 102:
                guard bytes[index...].starts(with: [102, 97, 108, 115, 101]) else { throw ValidationError.invalidFrame }
                index += 5; return .boolean(false)
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

private extension Dictionary where Key == String, Value == WorkloadStorageProtocol.Value {
    func object(_ key: String) throws -> [String: Value] {
        guard let value = self[key] else { throw WorkloadStorageProtocol.ValidationError.invalidFrame }
        return try value.object()
    }
}

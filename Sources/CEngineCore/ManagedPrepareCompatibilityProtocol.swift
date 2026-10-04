import Foundation

/// Closed compatibility vocabulary. These values are evidence, never storage authority.
public enum ManagedPrepareCompatibilityProtocol {
    public static let profile = "rtm096-normal-a7-v1"
    public static let earlyProfile = "rtm096-early-a1-a3-v2"
    public static let fullProfile = "rtm096-full-nine-v3"
    public static func ioCase(_ stage: String) -> (point: String, errno: String, workload: Bool)? {
        let point: String, errno: String
        if stage.hasPrefix("io-eio-") { point = String(stage.dropFirst(7)); errno = "EIO" }
        else if stage.hasPrefix("io-enospc-") { point = String(stage.dropFirst(10)); errno = "ENOSPC" }
        else { return nil }
        switch point {
        case "child-data-fsync", "manifest-write", "manifest-fsync", "manifest-rename-parent-sync", "public-child-rename", "public-directory-sync", "root-metadata", "root-fsync":
            return (point, errno, true)
        case "copy-operation-write", "copy-operation-sync", "provision-rename", "provision-parent-sync", "seal-persist", "cleaning-persist", "child-unlink-parent-sync", "manifest-unlink-parent-sync", "transaction-unlink-parent-sync", "root-restoration-syncfs", "finish-persist", "retire-intent-persist", "retire-barrier-persist", "retire-receipt-persist", "retire-barrier-clear-persist":
            return (point, errno, false)
        default: return nil
        }
    }
    public static func allowsIORetirePrepare(_ arm: Arm) -> Bool {
        arm.profile == fullProfile && ioCase(arm.caseName)?.point.hasPrefix("retire-") == true
    }
    public static let twoVolumeDrainReplyGap = "vm-two-volume-drain-reply-gap"
    public static func isVMCase(_ value: String) -> Bool {
        ["vm-private-bound", "vm-root-synced-before-cleanup", "vm-cleaning-transaction-removed"].contains(value)
    }
    public static func isStorageCase(_ value: String) -> Bool {
        ["full-frame-before-admit", "admitted-queued", "transaction-published-bind-reply-lost", "drain-durable-reply-lost", "vm-private-bound", "vm-cleaning-transaction-removed", twoVolumeDrainReplyGap].contains(value) || ioCase(value)?.workload == false
    }
    public static func allowsPrepareSuccess(_ arm: Arm) -> Bool {
        arm.caseName == "normal" || (arm.profile == fullProfile && ["drain-durable-reply-lost", twoVolumeDrainReplyGap].contains(arm.caseName))
    }
    public static func expectsPhysicalObservation(_ arm: Arm) -> Bool {
        // CLEANING retains the earlier first-child witness, never PREPARE success.
        (arm.profile == fullProfile && ["vm-root-synced-before-cleanup", "vm-cleaning-transaction-removed"].contains(arm.caseName)) || (arm.caseName == "normal" || (arm.profile == fullProfile && ["drain-durable-reply-lost", twoVolumeDrainReplyGap].contains(arm.caseName))) || (arm.caseName == "first-child-published" && arm.profile != earlyProfile)
    }
    public static func profileVersion(_ value: String) -> UInt32? {
        switch value { case profile: return 1; case earlyProfile: return 2; case fullProfile: return 3; default: return nil }
    }
    public static func isEarlyCase(_ value: String) -> Bool {
        ["before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame"].contains(value)
    }
    public enum Failure: Error { case invalid, changed, unsupported }
    public struct Credential: Codable, Equatable, Sendable {
        public var attachment: String
        public var key: String
        public var certificateSHA256: String
        public init(attachment: String, key: String, certificateSHA256: String) {
            self.attachment = attachment
            self.key = key
            self.certificateSHA256 = certificateSHA256
        }
    }
    public struct Arm: Codable, Equatable, Sendable {
        public var version: UInt32
        public var profile: String
        public var requestID: String
        public var caseName: String
        public var targetAttachment: String
        public var binding: WorkloadStorageProtocol.BootBinding
        public var scope: WorkloadStorageProtocol.Scope
        public var mounts: [WorkloadStorageProtocol.MountBinding]
        public var slots: [WorkloadStorageProtocol.Slot]
        public var credentials: [Credential]
        public init(version: UInt32, profile: String, requestID: String, caseName: String, targetAttachment: String, binding: WorkloadStorageProtocol.BootBinding, scope: WorkloadStorageProtocol.Scope, mounts: [WorkloadStorageProtocol.MountBinding], slots: [WorkloadStorageProtocol.Slot], credentials: [Credential]) {
            self.version = version
            self.profile = profile
            self.requestID = requestID
            self.caseName = caseName
            self.targetAttachment = targetAttachment
            self.binding = binding
            self.scope = scope
            self.mounts = mounts
            self.slots = slots
            self.credentials = credentials
        }
    }
    public struct Capture: Codable, Equatable, Sendable {
        public var version: UInt32
        public var requestID: String
        public var container: String
        public var containerInstance: String
        public var specificationDigest: String
        public var mounts: [WorkloadStorageProtocol.MountBinding]
        public init(version: UInt32, requestID: String, container: String, containerInstance: String, specificationDigest: String, mounts: [WorkloadStorageProtocol.MountBinding]) {
            self.version = version
            self.requestID = requestID
            self.container = container
            self.containerInstance = containerInstance
            self.specificationDigest = specificationDigest
            self.mounts = mounts
        }
    }
    public struct Candidate: Codable, Equatable, Sendable {
        public var version: UInt32
        public var profile: String
        public var requestID: String
        public var binding: WorkloadStorageProtocol.BootBinding
        public var scope: WorkloadStorageProtocol.Scope
        public var mounts: [WorkloadStorageProtocol.MountBinding]
        public var slots: [WorkloadStorageProtocol.Slot]
        public var credentials: [Credential]
        public init(version: UInt32, profile: String, requestID: String, binding: WorkloadStorageProtocol.BootBinding, scope: WorkloadStorageProtocol.Scope, mounts: [WorkloadStorageProtocol.MountBinding], slots: [WorkloadStorageProtocol.Slot], credentials: [Credential]) {
            self.version = version
            self.profile = profile
            self.requestID = requestID
            self.binding = binding
            self.scope = scope
            self.mounts = mounts
            self.slots = slots
            self.credentials = credentials
        }
    }
    public struct Armed: Codable, Equatable, Sendable {
        public var version: UInt32
        public var requestID: String
        public var armDigest: String
        public init(version: UInt32, requestID: String, armDigest: String) {
            self.version = version
            self.requestID = requestID
            self.armDigest = armDigest
        }
    }
    public struct ObjectIdentity: Codable, Equatable, Sendable {
        public var inode: UInt64
        public var generation: UInt32
        public var fileType: UInt32
        public var handle: String
        public init(inode: UInt64, generation: UInt32, fileType: UInt32, handle: String) {
            self.inode = inode
            self.generation = generation
            self.fileType = fileType
            self.handle = handle
        }
    }
    /// Actual pre-read source timestamps, evidence only. Zero is valid; omission
    /// is not. Codable checks the signed-nanosecond range on decode and encode.
    public struct SourceAtimes: Codable, Equatable, Sendable {
        public var root: UInt64
        public var a: UInt64
        public var z: UInt64
        public init(root: UInt64, a: UInt64, z: UInt64) {
            self.root = root; self.a = a; self.z = z
        }
        private enum CodingKeys: String, CodingKey { case root, a, z }
        public init(from decoder: any Decoder) throws {
            let fields = try decoder.container(keyedBy: CodingKeys.self)
            root = try fields.decode(UInt64.self, forKey: .root)
            a = try fields.decode(UInt64.self, forKey: .a)
            z = try fields.decode(UInt64.self, forKey: .z)
            guard [root, a, z].allSatisfy({ $0 <= UInt64(Int64.max) }) else {
                throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "invalid source atimes"))
            }
        }
        public func encode(to encoder: any Encoder) throws {
            guard [root, a, z].allSatisfy({ $0 <= UInt64(Int64.max) }) else { throw Failure.invalid }
            var fields = encoder.container(keyedBy: CodingKeys.self)
            try fields.encode(root, forKey: .root)
            try fields.encode(a, forKey: .a)
            try fields.encode(z, forKey: .z)
        }
    }
    public struct Observation: Codable, Equatable, Sendable {
        public var version: UInt32
        public var profile: String
        public var requestID: String
        public var armDigest: String
        public var stage: String
        public var count: UInt32
        public var targetAttachment: String
        public var copyIntent: String
        public var filesystemUUID: String
        public var manifestDigest: String
        public var manifestSize: UInt64
        public var sourceAtimes: SourceAtimes
        public var root: ObjectIdentity
        public var transaction: ObjectIdentity
        public var published: ObjectIdentity
        public var staged: ObjectIdentity
        public init(version: UInt32, profile: String, requestID: String, armDigest: String, stage: String, count: UInt32, targetAttachment: String, copyIntent: String, filesystemUUID: String, manifestDigest: String, manifestSize: UInt64, sourceAtimes: SourceAtimes, root: ObjectIdentity, transaction: ObjectIdentity, published: ObjectIdentity, staged: ObjectIdentity) {
            self.version = version
            self.profile = profile
            self.requestID = requestID
            self.armDigest = armDigest
            self.stage = stage
            self.count = count
            self.targetAttachment = targetAttachment
            self.copyIntent = copyIntent
            self.filesystemUUID = filesystemUUID
            self.manifestDigest = manifestDigest
            self.manifestSize = manifestSize
            self.sourceAtimes = sourceAtimes
            self.root = root
            self.transaction = transaction
            self.published = published
            self.staged = staged
        }
    }

    public struct IOObservation: Codable, Equatable, Sendable {
        public var version: UInt32
        public var profile: String
        public var requestID: String
        public var armDigest: String
        public var stage: String
        public var count: UInt32
        public var targetAttachment: String
        public var copyIntent: String
        public var point: String
        public var errno: String
        public var occurrence: UInt32
        public init(version: UInt32 = 3, profile: String = fullProfile, requestID: String, armDigest: String,
                    stage: String, count: UInt32 = 1, targetAttachment: String, copyIntent: String,
                    point: String, errno: String, occurrence: UInt32 = 1) {
            self.version = version; self.profile = profile; self.requestID = requestID; self.armDigest = armDigest
            self.stage = stage; self.count = count; self.targetAttachment = targetAttachment; self.copyIntent = copyIntent
            self.point = point; self.errno = errno; self.occurrence = occurrence
        }
    }
    public static func validate(_ value: IOObservation) throws {
        guard let cut = ioCase(value.stage), cut.workload, value.version == 3, value.profile == fullProfile,
              value.count == 1, value.occurrence == 1, value.point == cut.point, value.errno == cut.errno,
              [value.requestID, value.targetAttachment, value.copyIntent].allSatisfy(WorkloadStorageProtocol.validID),
              pin(value.armDigest) else { throw Failure.invalid }
    }
    public static func validate(_ value: IOObservation, arm: Arm) throws {
        try validate(value)
        guard arm.version == value.version, arm.profile == value.profile, arm.caseName == value.stage,
              arm.requestID == value.requestID, arm.targetAttachment == value.targetAttachment,
              value.armDigest == (try digest(arm)) else { throw Failure.changed }
    }

    /// Selected-request transport evidence only; never a physical identity or Admit proof.
    public struct EarlyObservation: Codable, Equatable, Sendable {
        public var version: UInt32
        public var profile: String
        public var requestID: String
        public var armDigest: String
        public var stage: String
        public var count: UInt32
        public var targetAttachment: String
        public var requestSequence: UInt64
        public var prepareCommandsSent: UInt32
        public var prepareCommandsAccepted: UInt32
        public var dataBytesWritten: UInt32
        public init(version: UInt32, profile: String, requestID: String, armDigest: String, stage: String,
                    count: UInt32, targetAttachment: String, requestSequence: UInt64,
                    prepareCommandsSent: UInt32, prepareCommandsAccepted: UInt32, dataBytesWritten: UInt32) {
            self.version = version; self.profile = profile; self.requestID = requestID; self.armDigest = armDigest
            self.stage = stage; self.count = count; self.targetAttachment = targetAttachment
            self.requestSequence = requestSequence; self.prepareCommandsSent = prepareCommandsSent
            self.prepareCommandsAccepted = prepareCommandsAccepted; self.dataBytesWritten = dataBytesWritten
        }
    }

    public static func validate(_ observation: EarlyObservation) throws {
        guard [earlyProfile, fullProfile].contains(observation.profile), profileVersion(observation.profile) == observation.version,
              isEarlyCase(observation.stage), observation.count == 1, observation.requestSequence > 0,
              WorkloadStorageProtocol.validID(observation.requestID), WorkloadStorageProtocol.validID(observation.targetAttachment),
              pin(observation.armDigest) else { throw Failure.invalid }
        let sent: UInt32 = observation.stage == "before-prepare-send" ? 0 : 1
        let bytes: UInt32 = observation.stage == "data-partial-frame" ? 5 : 0
        guard observation.prepareCommandsSent == sent, observation.prepareCommandsAccepted == sent,
              observation.dataBytesWritten == bytes else { throw Failure.invalid }
    }
    public static func validate(_ observation: EarlyObservation, arm: Arm) throws {
        try validate(observation)
        guard arm.version == observation.version, arm.profile == observation.profile,
              arm.caseName == observation.stage, arm.requestID == observation.requestID,
              arm.targetAttachment == observation.targetAttachment,
              observation.armDigest == (try digest(arm)) else { throw Failure.changed }
    }
    public static func validateObservation(_ frame: WorkloadStorageProtocol.Frame, arm: Arm) throws {
        _ = try WorkloadStorageProtocol.encode(frame)
        guard frame.binding == arm.binding, frame.scope == arm.scope else { throw Failure.changed }
        switch frame.operation {
        case .prepareCheckpoint:
            if let observation = frame.data.compatibilityIOObservation {
                try validate(observation, arm: arm)
                return
            }
            guard let observation = frame.data.compatibilityObservation else { throw Failure.invalid }
            try validate(observation, arm: arm)
        case .prepareEarlyCheckpoint:
            guard let observation = frame.data.compatibilityEarlyObservation else { throw Failure.invalid }
            try validate(observation, arm: arm)
        default: throw Failure.invalid
        }
    }

    public static func pin(_ value: String) -> Bool { hex(value, count: 64) }
    private static func hex(_ value: String, count: Int) -> Bool {
        value.utf8.count == count && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    public static func validateProfile(_ value: String?, sourceSHA256: String?) throws {
        guard (value == nil && sourceSHA256 == nil) || (value.flatMap(profileVersion) != nil && sourceSHA256.map(pin) == true) else { throw Failure.unsupported }
    }
    /// Token grammar rejects duplicate/unknown/null/noninteger values. Unlike
    /// Foundation sortedKeys, lexical sorting and string escaping are explicit.
    public static func canonicalData<T: Encodable>(_ value: T) throws -> Data {
        var parser = WorkloadStorageProtocol.Parser(bytes: Array(try JSONEncoder().encode(value)), maximumDepth: 12)
        return Data(try canonical(parser.parse()).utf8)
    }
    public static func decode<T: Codable>(_ type: T.Type, from bytes: Data, maximum: Int = 65536) throws -> T {
        guard !bytes.isEmpty, bytes.count <= maximum else { throw Failure.invalid }
        var parser = WorkloadStorageProtocol.Parser(bytes: Array(bytes), maximumDepth: 12)
        _ = try parser.parse()
        let value = try JSONDecoder().decode(type, from: bytes)
        guard try canonicalData(value) == bytes else { throw Failure.invalid }
        return value
    }
    private static func quoted(_ text: String) -> String {
        var result = "\""
        for scalar in text.unicodeScalars {
            switch scalar.value {
            case 34: result += "\\\""
            case 92: result += "\\\\"
            case 8: result += "\\b"
            case 9: result += "\\t"
            case 10: result += "\\n"
            case 12: result += "\\f"
            case 13: result += "\\r"
            case 0...31, 0x2028, 0x2029: result += String(format: "\\u%04x", scalar.value)
            default: result.unicodeScalars.append(scalar)
            }
        }
        return result + "\""
    }
    private static func canonical(_ value: WorkloadStorageProtocol.Value) throws -> String {
        switch value {
        case .object(let fields): return "{" + (try fields.keys.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }.map { quoted($0) + ":" + (try canonical(fields[$0]!)) }).joined(separator: ",") + "}"
        case .array(let values): return "[" + (try values.map(canonical)).joined(separator: ",") + "]"
        case .string(let text): return quoted(text)
        case .number(let number): return String(number)
        case .boolean(let flag): return flag ? "true" : "false"
        }
    }
    public static func normalized(_ arm: Arm) -> Arm {
        var arm = arm
        arm.mounts.sort { $0.index < $1.index }
        arm.slots.sort { $0.attachment < $1.attachment }
        arm.credentials.sort { $0.attachment < $1.attachment }
        return arm
    }
    public static func armData(_ arm: Arm) throws -> Data {
        try validate(arm)
        let data = try canonicalData(normalized(arm))
        guard data.count <= 65536 else { throw Failure.invalid }
        return data
    }
    public static func digest(_ arm: Arm) throws -> String { WorkloadStorageProtocol.specificationDigest(try armData(arm)) }
    public static func validate(_ arm: Arm) throws {
        let wire = WorkloadStorageProtocol.self
        guard profileVersion(arm.profile) == arm.version,
              (arm.profile == profile ? ["normal", "first-child-published"].contains(arm.caseName)
                : arm.caseName == "normal" || isEarlyCase(arm.caseName) ||
                    (arm.profile == fullProfile && (isStorageCase(arm.caseName) || isVMCase(arm.caseName) || ioCase(arm.caseName) != nil || arm.caseName == "first-child-published"))),
              wire.validID(arm.requestID),
              wire.validID(arm.binding.guestBootNonce), arm.binding.shimLaunchUUID == arm.scope.launch,
              [arm.scope.intent, arm.scope.store, arm.scope.serviceEpoch, arm.scope.containerInstance, arm.scope.launch, arm.scope.prepare].allSatisfy(wire.validID),
              arm.scope.controllerEpoch > 0, [arm.scope.controllerKey, arm.scope.container, arm.scope.specificationDigest].allSatisfy(pin) else { throw Failure.invalid }
        try wire.validateConfiguration(mounts: arm.mounts, slots: arm.slots)
        let prepares = arm.slots.filter { $0.role == .prepare }
        guard arm.credentials.count <= 64, Set(arm.credentials.map(\.attachment)).count == arm.credentials.count,
              Set(arm.credentials.map(\.key)).count == arm.credentials.count,
              Set(arm.credentials.map(\.certificateSHA256)).count == arm.credentials.count,
              Set(arm.credentials.map(\.attachment)) == Set(prepares.map(\.attachment)),
              arm.credentials.allSatisfy({ wire.validID($0.attachment) && pin($0.key) && pin($0.certificateSHA256) }),
              let target = prepares.first(where: { $0.attachment == arm.targetAttachment }), target.mode == .readWrite else { throw Failure.invalid }
        if arm.caseName == twoVolumeDrainReplyGap {
            guard arm.profile == fullProfile, arm.mounts.count == 2, arm.slots.count == 4,
                  arm.credentials.count == 2, Set(arm.mounts.map(\.volume)).count == 2,
                  Set(arm.mounts.map(\.destination)).count == 2,
                  arm.mounts.allSatisfy({ $0.mode == .readWrite && !$0.noCopy && $0.subpath.isEmpty }) else { throw Failure.invalid }
        }
        if isVMCase(arm.caseName) {
            guard arm.mounts.count == 1, arm.slots.count == 2, arm.credentials.count == 1 else { throw Failure.invalid }
        }
        let mounts = arm.mounts.filter { $0.volume == target.volume }
        guard mounts.count == 1, mounts[0].mode == .readWrite, !mounts[0].noCopy, mounts[0].subpath.isEmpty else { throw Failure.invalid }
    }
    public static func validate(_ capture: Capture) throws {
        guard capture.version == 1, WorkloadStorageProtocol.validID(capture.requestID),
              WorkloadStorageProtocol.validID(capture.containerInstance), pin(capture.container), pin(capture.specificationDigest),
              !capture.mounts.isEmpty, capture.mounts.count <= 64,
              Set(capture.mounts.map(\.index)).count == capture.mounts.count,
              capture.mounts == capture.mounts.sorted(by: { $0.index < $1.index }) else { throw Failure.invalid }
    }
    public static func matches(_ arm: Arm, candidate: Candidate) throws {
        try validate(arm)
        guard arm.version == candidate.version, arm.profile == candidate.profile, arm.requestID == candidate.requestID,
              arm.binding == candidate.binding, arm.scope == candidate.scope,
              arm.mounts.sorted(by: { $0.index < $1.index }) == candidate.mounts.sorted(by: { $0.index < $1.index }),
              arm.slots.sorted(by: { $0.attachment < $1.attachment }) == candidate.slots.sorted(by: { $0.attachment < $1.attachment }),
              arm.credentials.sorted(by: { $0.attachment < $1.attachment }) == candidate.credentials.sorted(by: { $0.attachment < $1.attachment }) else { throw Failure.changed }
    }
    public static func validate(_ observation: Observation) throws {
        guard profileVersion(observation.profile) == observation.version, (observation.stage == "first-child-published" || (observation.version == 3 && observation.profile == fullProfile && observation.stage == "vm-root-synced-before-cleanup")), observation.count == 1,
              [observation.requestID, observation.targetAttachment, observation.copyIntent].allSatisfy(WorkloadStorageProtocol.validID),
              pin(observation.armDigest), pin(observation.manifestDigest), hex(observation.filesystemUUID, count: 32),
              observation.filesystemUUID != String(repeating: "0", count: 32), (1...67108864).contains(observation.manifestSize),
              try canonicalData(observation).count <= 8192 else { throw Failure.invalid }
        for (identity, kind) in [(observation.root, UInt32(16384)), (observation.transaction, 16384), (observation.published, 32768), (observation.staged, 32768)] {
            guard identity.inode > 0, identity.inode <= UInt32.max, identity.fileType == kind, hex(identity.handle, count: 16) else { throw Failure.invalid }
            let bytes = stride(from: 0, to: 16, by: 2).map { offset -> UInt8 in
                let start = identity.handle.index(identity.handle.startIndex, offsetBy: offset)
                return UInt8(identity.handle[start..<identity.handle.index(start, offsetBy: 2)], radix: 16)!
            }
            func little(_ range: Range<Int>) -> UInt64 { range.enumerated().reduce(0) { $0 | UInt64(bytes[$1.element]) << (8 * $1.offset) } }
            guard little(0..<4) == identity.inode, little(4..<8) == identity.generation else { throw Failure.invalid }
        }
        guard Set([observation.root.inode, observation.transaction.inode, observation.published.inode, observation.staged.inode]).count == 4 else { throw Failure.invalid }
    }
    public static func validate(_ observation: Observation, arm: Arm) throws {
        try validate(observation)
        guard observation.version == arm.version, observation.profile == arm.profile,
              expectsPhysicalObservation(arm),
              observation.stage == (arm.caseName == "vm-root-synced-before-cleanup" ? arm.caseName : "first-child-published"),
              observation.requestID == arm.requestID,
              observation.targetAttachment == arm.targetAttachment, observation.armDigest == (try digest(arm)) else { throw Failure.changed }
    }
}

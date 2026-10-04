import Foundation

extension ManagedPrepareCompatibilityProtocol {
    public struct StorageArm: Codable, Equatable, Sendable {
        public var arm: Arm
        public var workerUUID: String
        public init(arm: Arm, workerUUID: String) { self.arm = arm; self.workerUUID = workerUUID }
    }
    public struct StorageQuery: Codable, Equatable, Sendable {
        public var version: UInt32
        public var profile: String
        public var requestID: String
        public var armDigest: String
        public var workerUUID: String
        public init(version: UInt32 = 3, profile: String = fullProfile, requestID: String, armDigest: String, workerUUID: String) {
            self.version = version; self.profile = profile; self.requestID = requestID; self.armDigest = armDigest; self.workerUUID = workerUUID
        }
    }
    public struct StorageRelease: Codable, Equatable, Sendable {
        public var query: StorageQuery
        public var stage: String
        public var token: String
        public init(query: StorageQuery, stage: String, token: String) { self.query = query; self.stage = stage; self.token = token }
    }
    /// PID1's projection of its owned, reaped worker. Public data, never authority.
    public struct StorageWorkerWait: Codable, Equatable, Sendable {
        public var query: StorageQuery
        public var stage: String
        public var token: String
        public var requestSequence: UInt64
        public var workerPID: UInt32
        public var exitCode: UInt32
        public var reaped: Bool
        public init(query: StorageQuery, stage: String, token: String, requestSequence: UInt64,
                    workerPID: UInt32, exitCode: UInt32, reaped: Bool) {
            self.query = query; self.stage = stage; self.token = token; self.requestSequence = requestSequence
            self.workerPID = workerPID; self.exitCode = exitCode; self.reaped = reaped
        }
    }
    public struct AdmissionCut: Codable, Equatable, Sendable {
        public var requestSequence: UInt64
        public var admitted: Bool
        public var releaseToken: String
        public init(requestSequence: UInt64, admitted: Bool, releaseToken: String) {
            self.requestSequence = requestSequence; self.admitted = admitted; self.releaseToken = releaseToken
        }
    }
    /// Compatibility-only projection. Existing authority and DATA JSON are untouched.
    public struct StorageObject: Codable, Equatable, Sendable {
        public var inode: UInt64
        public var generation: UInt32
        public var fileType: UInt32
        public var handleType: UInt32
        public var handleSize: UInt32
        public var handle: String
        enum CodingKeys: String, CodingKey { case inode, generation, fileType = "file_type", handleType = "handle_type", handleSize = "handle_size", handle }
    }
    public struct StorageRoot: Codable, Equatable, Sendable {
        public var store: String
        public var volume: String
        public var backingUUID: String
        public var root: StorageObject
        enum CodingKeys: String, CodingKey { case store, volume, backingUUID = "backing_uuid", root }
    }
    public struct StorageCleanup: Codable, Equatable, Sendable {
        public var uid: UInt32
        public var gid: UInt32
        public var mode: UInt32
        public var atimeSeconds: String
        public var mtimeSeconds: String
        public var atimeNanos: UInt32
        public var mtimeNanos: UInt32
        public var manifest: StorageObject
        public var staging: StorageObject
        enum CodingKeys: String, CodingKey {
            case uid, gid, mode, atimeSeconds = "atime_seconds", mtimeSeconds = "mtime_seconds"
            case atimeNanos = "atime_nanos", mtimeNanos = "mtime_nanos", manifest, staging
        }
    }
    public struct StorageCopyIntent: Codable, Equatable, Sendable {
        public var id: String
        public var owner: StorageServiceTypes.AttachmentBinding
        public var epoch: String
        public var root: StorageRoot
        public var transaction: StorageObject
        public var manifestDigest: String
        public var manifestSize: UInt64
        public var phase: String
        public var initial: StorageCleanup
        public var cleanup: StorageCleanup
        public var initialCaptured: Bool
        enum CodingKeys: String, CodingKey {
            case id, owner, epoch, root, transaction, manifestDigest = "manifest_digest", manifestSize = "manifest_size", phase
            case initial, cleanup, initialCaptured = "initial_captured"
        }
    }
    public struct BoundCut: Codable, Equatable, Sendable {
        public var requestSequence: UInt64
        public var intent: StorageCopyIntent
    }
    public struct StorageReceipt: Codable, Equatable, Sendable {
        public var schema: UInt32
        public var store: String
        public var volume: String
        public var attachment: String
        public var prepare: String
        public var launch: String
        public var revision: UInt64
    }
    public struct DrainCut: Codable, Equatable, Sendable {
        public var retireOperation: String
        public var receipt: StorageReceipt
    }
    public struct IOCut: Codable, Equatable, Sendable {
        public var point: String
        public var errno: String
        public var occurrence: UInt32
        public var requestSequence: UInt64
        public var retireOperation: String
        public init(point: String, errno: String, occurrence: UInt32 = 1, requestSequence: UInt64 = 0, retireOperation: String = "") {
            self.point = point; self.errno = errno; self.occurrence = occurrence
            self.requestSequence = requestSequence; self.retireOperation = retireOperation
        }
    }
    public struct StorageObservation: Codable, Equatable, Sendable {
        public var version: UInt32
        public var profile: String
        public var requestID: String
        public var armDigest: String
        public var workerUUID: String
        public var stage: String
        public var count: UInt32
        public var targetAttachment: String
        public var io: IOCut?
        public var admission: AdmissionCut?
        public var bound: BoundCut?
        public var drain: DrainCut?
        public init(version: UInt32 = 3, profile: String = fullProfile, requestID: String, armDigest: String,
                    workerUUID: String, stage: String, count: UInt32 = 1, targetAttachment: String,
                    io: IOCut? = nil, admission: AdmissionCut? = nil, bound: BoundCut? = nil, drain: DrainCut? = nil) {
            self.version = version; self.profile = profile; self.requestID = requestID; self.armDigest = armDigest
            self.workerUUID = workerUUID; self.stage = stage; self.count = count; self.targetAttachment = targetAttachment
            self.io = io; self.admission = admission; self.bound = bound; self.drain = drain
        }
        public var query: StorageQuery { .init(version: version, profile: profile, requestID: requestID, armDigest: armDigest, workerUUID: workerUUID) }
    }
    public struct StorageStatus: Codable, Equatable, Sendable {
        public var query: StorageQuery
        public var state: String
        public var retirementStarted: Bool
        public var acceptedInFlight: UInt32
        public var lateAdmissionRejected: Bool
        public var receiptReplayCount: UInt32
        public var observation: StorageObservation?
        public init(query: StorageQuery, state: String, retirementStarted: Bool = false, acceptedInFlight: UInt32 = 0,
                    lateAdmissionRejected: Bool = false, receiptReplayCount: UInt32 = 0, observation: StorageObservation? = nil) {
            self.query = query; self.state = state; self.retirementStarted = retirementStarted; self.acceptedInFlight = acceptedInFlight
            self.lateAdmissionRejected = lateAdmissionRejected; self.receiptReplayCount = receiptReplayCount; self.observation = observation
        }
    }
    public static func query(_ value: StorageArm) throws -> StorageQuery {
        try validate(value)
        return .init(requestID: value.arm.requestID, armDigest: try digest(value.arm), workerUUID: value.workerUUID)
    }
    public static func validate(_ value: StorageArm) throws {
        try validate(value.arm)
        guard value.arm.version == 3, value.arm.profile == fullProfile, isStorageCase(value.arm.caseName),
              WorkloadStorageProtocol.validID(value.workerUUID), try canonicalData(value).count <= 65536 else { throw Failure.invalid }
    }
    public static func validate(_ value: StorageQuery) throws {
        guard value.version == 3, value.profile == fullProfile, WorkloadStorageProtocol.validID(value.requestID),
              WorkloadStorageProtocol.validID(value.workerUUID), pin(value.armDigest) else { throw Failure.invalid }
    }
    public static func validate(_ value: StorageRelease) throws {
        try validate(value.query)
        guard ["full-frame-before-admit", "admitted-queued"].contains(value.stage), pin(value.token) else { throw Failure.invalid }
    }
    public static func validateStorageWorkerExit(_ value: StorageRelease) throws {
        // Only the two actually held admission cuts have an exit token.
        try validate(value)
    }
    public static func validate(_ value: StorageWorkerWait) throws {
        try validateStorageWorkerExit(.init(query: value.query, stage: value.stage, token: value.token))
        guard value.requestSequence > 0, value.workerPID > 1, value.workerPID <= UInt32(Int32.max),
              value.exitCode == 74, value.reaped else { throw Failure.invalid }
    }
    public static func decodeStorageWorkerWait(from bytes: Data) throws -> StorageWorkerWait {
        let value = try decode(StorageWorkerWait.self, from: bytes)
        try validate(value)
        return value
    }
    public static func validate(_ value: StorageWorkerWait, arm: StorageArm) throws {
        try validate(value)
        guard value.stage == arm.arm.caseName, value.query == (try query(arm)) else { throw Failure.changed }
    }
    public static func validateStorageWorkerExit(_ value: StorageRelease, arm: StorageArm, checkpoint: StorageStatus) throws {
        try validateStorageWorkerExit(value)
        try validate(checkpoint, arm: arm)
        guard value.stage == arm.arm.caseName, checkpoint.state == "observed", !checkpoint.retirementStarted,
              let observation = checkpoint.observation,
              let admission = observation.admission,
              admission.admitted == (value.stage == "admitted-queued"),
              value.stage != "full-frame-before-admit" || checkpoint.acceptedInFlight == 0,
              value.query == checkpoint.query, value.stage == observation.stage,
              value.token == admission.releaseToken else { throw Failure.changed }
    }
    public static func validate(_ value: StorageWorkerWait, arm: StorageArm, checkpoint: StorageStatus) throws {
        try validate(value, arm: arm)
        try validateStorageWorkerExit(.init(query: value.query, stage: value.stage, token: value.token), arm: arm, checkpoint: checkpoint)
        guard value.requestSequence == checkpoint.observation?.admission?.requestSequence else { throw Failure.changed }
    }
    private static func storageHex(_ value: String, _ count: Int) -> Bool {
        value.utf8.count == count && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    private static func validateStorageObject(_ value: StorageObject, zero: Bool = false) throws {
        if zero, value.inode == 0, value.generation == 0, value.fileType == 0, value.handleType == 0,
           value.handleSize == 0, value.handle == String(repeating: "0", count: 16) { return }
        guard value.inode > 0, value.inode <= UInt32.max, value.handleType == 1, value.handleSize == 8,
              [4096,8192,16384,24576,32768,40960,49152].contains(value.fileType), storageHex(value.handle, 16) else { throw Failure.invalid }
        let bytes = stride(from: 0, to: 16, by: 2).map { i -> UInt8 in
            let start = value.handle.index(value.handle.startIndex, offsetBy: i)
            return UInt8(value.handle[start..<value.handle.index(start, offsetBy: 2)], radix: 16)!
        }
        func little(_ range: Range<Int>) -> UInt64 { range.enumerated().reduce(0) { $0 | UInt64(bytes[$1.element]) << (8 * $1.offset) } }
        guard little(0..<4) == value.inode, little(4..<8) == value.generation else { throw Failure.invalid }
    }
    private static func validateStorageCleanup(_ value: StorageCleanup) throws {
        guard let a = Int64(value.atimeSeconds), String(a) == value.atimeSeconds,
              let m = Int64(value.mtimeSeconds), String(m) == value.mtimeSeconds,
              value.atimeNanos < 1_000_000_000, value.mtimeNanos < 1_000_000_000 else { throw Failure.invalid }
        try validateStorageObject(value.manifest, zero: true); try validateStorageObject(value.staging, zero: true)
    }
    public static func validate(_ value: StorageObservation) throws {
        try validate(value.query)
        let id = WorkloadStorageProtocol.validID
        guard value.count == 1, id(value.targetAttachment), isStorageCase(value.stage),
              [value.io != nil, value.admission != nil, value.bound != nil, value.drain != nil].filter({ $0 }).count == 1,
              try canonicalData(value).count <= 8192 else { throw Failure.invalid }
        if let cut = value.io {
            guard let selected = ioCase(value.stage), !selected.workload, cut.point == selected.point,
                  cut.errno == selected.errno, cut.occurrence == 1 else { throw Failure.invalid }
            if selected.point.hasPrefix("retire-") {
                guard cut.requestSequence == 0, id(cut.retireOperation) else { throw Failure.invalid }
            } else { guard cut.requestSequence > 0, cut.retireOperation.isEmpty else { throw Failure.invalid } }
            return
        }
        switch value.stage {
        case "full-frame-before-admit", "admitted-queued":
            guard let cut = value.admission, cut.requestSequence > 0, pin(cut.releaseToken),
                  cut.admitted == (value.stage == "admitted-queued") else { throw Failure.invalid }
        case "transaction-published-bind-reply-lost", "vm-private-bound", "vm-cleaning-transaction-removed":
            guard let cut = value.bound, cut.requestSequence > 0 else { throw Failure.invalid }
            var intent = cut.intent
            if value.stage == "vm-cleaning-transaction-removed" {
                guard intent.phase == "CLEANING", (1...67108864).contains(intent.manifestSize),
                      pin(intent.manifestDigest), intent.manifestDigest != String(repeating: "0", count: 64),
                      intent.cleanup.mode & ~UInt32(0o7777) == 0, intent.cleanup.uid != UInt32.max, intent.cleanup.gid != UInt32.max,
                      intent.cleanup.manifest.fileType == 32768, intent.cleanup.staging.fileType == 16384 else { throw Failure.invalid }
                try validateStorageCleanup(intent.cleanup)
                // These are four physical objects, not merely different handle projections.
                guard Set([intent.root.root.inode, intent.transaction.inode,
                           intent.cleanup.manifest.inode, intent.cleanup.staging.inode]).count == 4 else { throw Failure.invalid }
                intent.phase = "BOUND"; intent.manifestSize = 0; intent.manifestDigest = String(repeating: "0", count: 64)
                let zero = StorageObject(inode: 0, generation: 0, fileType: 0, handleType: 0, handleSize: 0, handle: String(repeating: "0", count: 16))
                intent.cleanup = StorageCleanup(uid: 0, gid: 0, mode: 0, atimeSeconds: "0", mtimeSeconds: "0", atimeNanos: 0, mtimeNanos: 0, manifest: zero, staging: zero)
            }
            let owner = intent.owner
            guard id(intent.id), id(intent.epoch), intent.phase == "BOUND", intent.initialCaptured,
                  intent.manifestDigest == String(repeating: "0", count: 64), intent.manifestSize == 0,
                  [owner.store, owner.volume, owner.attachment, owner.launch, owner.prepare ?? ""].allSatisfy(id),
                  pin(owner.container), pin(owner.key), owner.role == .prepare, owner.mode == .readWrite,
                  owner.attachment == value.targetAttachment, intent.root.store == owner.store, intent.root.volume == owner.volume,
                  storageHex(intent.root.backingUUID, 32), intent.root.backingUUID != String(repeating: "0", count: 32),
                  intent.root.root.fileType == 16384, intent.transaction.fileType == 16384,
                  intent.root.root != intent.transaction else { throw Failure.invalid }
            try validateStorageObject(intent.root.root); try validateStorageObject(intent.transaction)
            try validateStorageCleanup(intent.initial); try validateStorageCleanup(intent.cleanup)
            let zero = StorageObject(inode: 0, generation: 0, fileType: 0, handleType: 0, handleSize: 0, handle: String(repeating: "0", count: 16))
            guard intent.initial.mode & ~UInt32(0o7777) == 0, intent.initial.uid != UInt32.max, intent.initial.gid != UInt32.max,
                  intent.initial.manifest == zero, intent.initial.staging == zero,
                  intent.cleanup == StorageCleanup(uid: 0, gid: 0, mode: 0, atimeSeconds: "0", mtimeSeconds: "0",
                    atimeNanos: 0, mtimeNanos: 0, manifest: zero, staging: zero) else { throw Failure.invalid }
        case "drain-durable-reply-lost", twoVolumeDrainReplyGap:
            guard let cut = value.drain, id(cut.retireOperation), cut.receipt.schema == 3, cut.receipt.revision > 0,
                  [cut.receipt.store, cut.receipt.volume, cut.receipt.attachment, cut.receipt.prepare,
                   cut.receipt.launch].allSatisfy(id),
                  cut.receipt.attachment == value.targetAttachment else { throw Failure.invalid }
        default: throw Failure.invalid
        }
    }
    public static func validate(_ value: StorageStatus) throws {
        try validate(value.query)
        guard ["armed", "observed", "released", "finished", "held"].contains(value.state) else { throw Failure.invalid }
        if value.state == "armed" { guard value.observation == nil, !value.lateAdmissionRejected, value.receiptReplayCount == 0 else { throw Failure.invalid }; return }
        guard let observation = value.observation, observation.query == value.query else { throw Failure.invalid }
        try validate(observation)
        if observation.stage == twoVolumeDrainReplyGap {
            guard value.state == "held", value.retirementStarted, value.acceptedInFlight == 0,
                  !value.lateAdmissionRejected, value.receiptReplayCount == 0 else { throw Failure.invalid }
        } else if value.state == "held" { throw Failure.invalid }
        if observation.io != nil || isVMCase(observation.stage) {
            guard value.state == "observed", !value.lateAdmissionRejected, value.receiptReplayCount == 0 else { throw Failure.invalid }
        }
        if isVMCase(observation.stage) {
            guard value.acceptedInFlight > 0, !value.retirementStarted else { throw Failure.invalid }
        }
        guard value.state != "released" || ["full-frame-before-admit", "admitted-queued"].contains(observation.stage) else { throw Failure.invalid }
        guard !value.lateAdmissionRejected || (observation.stage == "full-frame-before-admit" && value.retirementStarted && value.state != "observed"),
              value.receiptReplayCount == 0 || observation.stage == "drain-durable-reply-lost" else { throw Failure.invalid }
        if observation.stage == "admitted-queued", value.state == "observed", value.retirementStarted {
            guard value.acceptedInFlight > 0 else { throw Failure.invalid }
        }
    }
    public static func validate(_ value: StorageStatus, arm: StorageArm) throws {
        try validate(value)
        guard value.query == (try query(arm)) else { throw Failure.changed }
        guard let observation = value.observation else { return }
        guard observation.stage == arm.arm.caseName, observation.targetAttachment == arm.arm.targetAttachment,
              let slot = arm.arm.slots.first(where: { $0.attachment == arm.arm.targetAttachment }),
              let credential = arm.arm.credentials.first(where: { $0.attachment == arm.arm.targetAttachment }) else { throw Failure.changed }
        if let intent = observation.bound?.intent {
            let s = arm.arm.scope, owner = intent.owner
            guard intent.epoch == s.serviceEpoch, owner.store == s.store, owner.prepare == s.prepare,
                  owner.volume == slot.volume, owner.container == s.container, owner.launch == s.launch,
                  owner.key == credential.key else { throw Failure.changed }
        }
        if let receipt = observation.drain?.receipt {
            guard receipt.store == arm.arm.scope.store, receipt.prepare == arm.arm.scope.prepare,
                  receipt.volume == slot.volume, receipt.launch == arm.arm.scope.launch else { throw Failure.changed }
        }
    }
}

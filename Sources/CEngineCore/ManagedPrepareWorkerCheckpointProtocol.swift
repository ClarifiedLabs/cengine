import Foundation

/// RTM098 generic full-profile-only checkpoint exit vocabulary for the seven
/// guest-visible cuts: NORMAL/A7 (physical), A1/A2/A3 (early partial-frame),
/// A6/A8 (storage-owned Bound/Drain). Exactly one checkpoint carrier is present,
/// selected by the arm's case, and each is bound to the arm by its actual
/// existing arm-specific validator. These values are evidence, never storage
/// authority: decoding validates structure and arm binding, not process death
/// or PREPARE authority. This carrier never holds or fabricates a storage
/// Admission, release token, or made-up sequence: A4/A5 stay on the distinct
/// strict StorageRelease path, and the VM/IO cuts stay on their own paths.
public enum ManagedPrepareWorkerCheckpointProtocol {
    public typealias C = ManagedPrepareCompatibilityProtocol
    /// Guest/internal/preparecompat/full.go: MaximumStorageFrameBytes.
    public static let maximumFrameBytes = 65_536

    /// The generic full-profile-only checkpoint exit claim for one owned worker.
    public struct WorkerCheckpointExit: Codable, Equatable, Sendable {
        public var arm: C.Arm
        public var checkpoint: C.Observation?
        public var earlyCheckpoint: C.EarlyObservation?
        public var storageCheckpoint: C.StorageObservation?
        public var workerUUID: String
        public init(arm: C.Arm, checkpoint: C.Observation? = nil, earlyCheckpoint: C.EarlyObservation? = nil,
                    storageCheckpoint: C.StorageObservation? = nil, workerUUID: String) {
            self.arm = arm; self.checkpoint = checkpoint; self.earlyCheckpoint = earlyCheckpoint
            self.storageCheckpoint = storageCheckpoint; self.workerUUID = workerUUID
        }
        private enum CodingKeys: String, CodingKey {
            case arm, checkpoint, earlyCheckpoint, storageCheckpoint, workerUUID
        }
        /// Hand-written flat Codable: the synthesized conformance materializes
        /// every nested optional in one generated init(from:) frame large enough
        /// to overrun Swift Testing cooperative thread stacks (SIGBUS in
        /// ___chkstk_darwin during combined runs). Sequential per-field coding
        /// keeps one temporary alive at a time; key names and encodeIfPresent
        /// semantics are identical to the synthesized form.
        public init(from decoder: any Decoder) throws {
            let fields = try decoder.container(keyedBy: CodingKeys.self)
            self.arm = try fields.decode(C.Arm.self, forKey: .arm)
            self.checkpoint = try fields.decodeIfPresent(C.Observation.self, forKey: .checkpoint)
            self.earlyCheckpoint = try fields.decodeIfPresent(C.EarlyObservation.self, forKey: .earlyCheckpoint)
            self.storageCheckpoint = try fields.decodeIfPresent(C.StorageObservation.self, forKey: .storageCheckpoint)
            self.workerUUID = try fields.decode(String.self, forKey: .workerUUID)
        }
        public func encode(to encoder: any Encoder) throws {
            var fields = encoder.container(keyedBy: CodingKeys.self)
            try fields.encode(arm, forKey: .arm)
            try fields.encodeIfPresent(checkpoint, forKey: .checkpoint)
            try fields.encodeIfPresent(earlyCheckpoint, forKey: .earlyCheckpoint)
            try fields.encodeIfPresent(storageCheckpoint, forKey: .storageCheckpoint)
            try fields.encode(workerUUID, forKey: .workerUUID)
        }
    }

    /// PID1's projection of the sole actual Wait of the owned worker that
    /// acknowledged this exact claim. Decoding it is not process-death or
    /// PREPARE authority.
    public struct WorkerCheckpointWait: Codable, Equatable, Sendable {
        public var arm: C.Arm
        public var checkpoint: C.Observation?
        public var earlyCheckpoint: C.EarlyObservation?
        public var storageCheckpoint: C.StorageObservation?
        public var workerUUID: String
        public var workerPID: UInt32
        public var exitCode: UInt32
        public var reaped: Bool
        public init(arm: C.Arm, checkpoint: C.Observation? = nil, earlyCheckpoint: C.EarlyObservation? = nil,
                    storageCheckpoint: C.StorageObservation? = nil, workerUUID: String,
                    workerPID: UInt32, exitCode: UInt32, reaped: Bool) {
            self.arm = arm; self.checkpoint = checkpoint; self.earlyCheckpoint = earlyCheckpoint
            self.storageCheckpoint = storageCheckpoint; self.workerUUID = workerUUID
            self.workerPID = workerPID; self.exitCode = exitCode; self.reaped = reaped
        }
        /// The sealed full claim this wait projection echoes field-for-field.
        private enum CodingKeys: String, CodingKey {
            case arm, checkpoint, earlyCheckpoint, storageCheckpoint, workerUUID, workerPID, exitCode, reaped
        }
        /// Flat sequential Codable; see the exit claim's note on frame size.
        public init(from decoder: any Decoder) throws {
            let fields = try decoder.container(keyedBy: CodingKeys.self)
            self.arm = try fields.decode(C.Arm.self, forKey: .arm)
            self.checkpoint = try fields.decodeIfPresent(C.Observation.self, forKey: .checkpoint)
            self.earlyCheckpoint = try fields.decodeIfPresent(C.EarlyObservation.self, forKey: .earlyCheckpoint)
            self.storageCheckpoint = try fields.decodeIfPresent(C.StorageObservation.self, forKey: .storageCheckpoint)
            self.workerUUID = try fields.decode(String.self, forKey: .workerUUID)
            self.workerPID = try fields.decode(UInt32.self, forKey: .workerPID)
            self.exitCode = try fields.decode(UInt32.self, forKey: .exitCode)
            self.reaped = try fields.decode(Bool.self, forKey: .reaped)
        }
        public func encode(to encoder: any Encoder) throws {
            var fields = encoder.container(keyedBy: CodingKeys.self)
            try fields.encode(arm, forKey: .arm)
            try fields.encodeIfPresent(checkpoint, forKey: .checkpoint)
            try fields.encodeIfPresent(earlyCheckpoint, forKey: .earlyCheckpoint)
            try fields.encodeIfPresent(storageCheckpoint, forKey: .storageCheckpoint)
            try fields.encode(workerUUID, forKey: .workerUUID)
            try fields.encode(workerPID, forKey: .workerPID)
            try fields.encode(exitCode, forKey: .exitCode)
            try fields.encode(reaped, forKey: .reaped)
        }
        public var claim: WorkerCheckpointExit {
            .init(arm: arm, checkpoint: checkpoint, earlyCheckpoint: earlyCheckpoint,
                  storageCheckpoint: storageCheckpoint, workerUUID: workerUUID)
        }
    }

    /// The closed set of cuts claimable through the generic checkpoint exit
    /// path. NORMAL/A7/A1/A2/A3/A6/A8 only.
    public static func checkpointExitCut(_ stage: String) -> Bool {
        ["normal", "before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame",
         "first-child-published", "transaction-published-bind-reply-lost", "drain-durable-reply-lost"].contains(stage)
    }

    enum Carrier: Sendable { case physical, early, storage }

    /// Selects the single permitted checkpoint carrier for a cut.
    static func carrier(_ stage: String) -> Carrier? {
        switch stage {
        case "normal", "first-child-published": return .physical
        case "before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame": return .early
        case "transaction-published-bind-reply-lost", "drain-durable-reply-lost": return .storage
        default: return nil
        }
    }

    /// Binds an actual storage-owned Bound/Drain observation to its arm and
    /// owned worker. It is the exact actually retained observation, never a
    /// fabricated admission cut or synthetic physical observation.
    static func validateStorageCheckpoint(_ observation: C.StorageObservation, arm: C.Arm, workerUUID: String) throws {
        try C.validate(observation)
        try C.validate(C.StorageArm(arm: arm, workerUUID: workerUUID))
        guard observation.version == 3, observation.profile == C.fullProfile,
              observation.workerUUID == workerUUID,
              observation.requestID == arm.requestID,
              observation.armDigest == (try C.digest(arm)),
              observation.stage == arm.caseName,
              observation.targetAttachment == arm.targetAttachment,
              let slot = arm.slots.first(where: { $0.attachment == arm.targetAttachment }),
              let credential = arm.credentials.first(where: { $0.attachment == arm.targetAttachment }) else {
            throw C.Failure.changed
        }
        let scope = arm.scope
        if let intent = observation.bound?.intent {
            let owner = intent.owner
            guard intent.epoch == scope.serviceEpoch, owner.store == scope.store,
                  owner.volume == slot.volume, owner.attachment == slot.attachment,
                  owner.prepare == scope.prepare, owner.container == scope.container,
                  owner.launch == scope.launch, owner.key == credential.key,
                  owner.role == .prepare, owner.mode == .readWrite else { throw C.Failure.changed }
        }
        if let receipt = observation.drain?.receipt {
            guard receipt.store == scope.store, receipt.volume == slot.volume,
                  receipt.attachment == slot.attachment, receipt.prepare == scope.prepare,
                  receipt.launch == scope.launch else { throw C.Failure.changed }
        }
    }

    public static func validate(_ exit: WorkerCheckpointExit) throws {
        try C.validate(exit.arm)
        guard exit.arm.version == 3, exit.arm.profile == C.fullProfile,
              checkpointExitCut(exit.arm.caseName),
              WorkloadStorageProtocol.validID(exit.workerUUID) else { throw C.Failure.invalid }
        let set = [exit.checkpoint != nil, exit.earlyCheckpoint != nil, exit.storageCheckpoint != nil].filter { $0 }.count
        guard set == 1, let carrier = carrier(exit.arm.caseName) else { throw C.Failure.invalid }
        switch carrier {
        case .physical:
            // The arm's existing physical validator binds the actual guest
            // observation: immutable digest/request/target identity plus the
            // arm's physical stage.
            guard let checkpoint = exit.checkpoint else { throw C.Failure.invalid }
            try C.validate(checkpoint, arm: exit.arm)
        case .early:
            // The early carrier, never a synthetic physical observation.
            guard let checkpoint = exit.earlyCheckpoint else { throw C.Failure.invalid }
            try C.validate(checkpoint, arm: exit.arm)
        case .storage:
            guard let checkpoint = exit.storageCheckpoint else { throw C.Failure.invalid }
            try validateStorageCheckpoint(checkpoint, arm: exit.arm, workerUUID: exit.workerUUID)
        }
        guard try C.canonicalData(exit).count <= maximumFrameBytes else { throw C.Failure.invalid }
    }

    public static func validate(_ wait: WorkerCheckpointWait) throws {
        try validate(wait.claim)
        guard wait.workerPID > 1, wait.workerPID <= UInt32(Int32.max),
              wait.exitCode == 74, wait.reaped else { throw C.Failure.invalid }
    }

    /// Requires the wait projection to match the exact full claim: same arm,
    /// same actual checkpoint carrier, same owned worker. Canonical comparison
    /// covers every sealed union field.
    public static func validate(_ wait: WorkerCheckpointWait, for exit: WorkerCheckpointExit) throws {
        try validate(exit)
        try validate(wait)
        guard sameClaim(wait.claim, exit) else { throw C.Failure.changed }
    }

    /// Compares two full claims by canonical bytes.
    public static func sameClaim(_ a: WorkerCheckpointExit, _ b: WorkerCheckpointExit) -> Bool {
        guard let first = try? C.canonicalData(a), let second = try? C.canonicalData(b) else { return false }
        return first == second
    }

    /// Exact canonical roundtrip decode: required fields, no null/duplicate/
    /// unknown keys, non-integer numbers rejected, then full claim validation.
    public static func decodeWorkerCheckpointExit(from bytes: Data) throws -> WorkerCheckpointExit {
        let value = try C.decode(WorkerCheckpointExit.self, from: bytes, maximum: maximumFrameBytes)
        try validate(value)
        return value
    }

    public static func decodeWorkerCheckpointWait(from bytes: Data) throws -> WorkerCheckpointWait {
        let value = try C.decode(WorkerCheckpointWait.self, from: bytes, maximum: maximumFrameBytes)
        try validate(value)
        return value
    }
}

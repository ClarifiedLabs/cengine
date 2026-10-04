import CEngineCore
import Darwin
import Foundation

/// The only live activation path: no injectable identity, callback, or environment gate.
final class ManagedPrepareCompatibilityCoordinator: Sendable {
    typealias Carrier = ManagedPrepareCompatibilityProtocol
    typealias Checkpoint = ManagedPrepareWorkerCheckpointProtocol
    typealias Claim = ManagedPrepareCompatibilityQueue.Claim
    private let queue: ManagedPrepareCompatibilityQueue
    let profile: String
    let version: UInt32

    init(storeLock: CanonicalDataStoreLock, profile: String) throws {
        guard let version = Carrier.profileVersion(profile) else { throw Carrier.Failure.unsupported }
        self.profile = profile; self.version = version
        _ = try SignedCompatibilityIdentity.current(role: .engine)
        queue = try ManagedPrepareCompatibilityQueue(storeLock: storeLock)
    }
    /// Explicit signed full-profile publication only; ordinary daemon output is unchanged.
    func lifecyclePeerPublish(_ observation: ManagedStorageLifecyclePeerObservation) throws {
        guard profile == Carrier.fullProfile else { return }
        _ = try SignedCompatibilityIdentity.current(role: .engine)
        try queue.lifecyclePeerPublish(observation)
    }
    func publicTakeoverArmCapture(container: String, instance: String) throws -> ManagedPrepareCompatibilityQueue.PublicTakeoverArmClaim? {
        guard profile == Carrier.fullProfile else { return nil }
        _ = try SignedCompatibilityIdentity.current(role: .engine)
        return try queue.publicTakeoverArmCapture(container: container, instance: instance)
    }
    func publicTakeoverArmPublish(_ data: Data, phase: String, claim: ManagedPrepareCompatibilityQueue.PublicTakeoverArmClaim) throws {
        _ = try SignedCompatibilityIdentity.current(role: .engine)
        try queue.publicTakeoverArmPublish(data, phase: phase, claim: claim)
    }
    func publicTakeoverCapture(store: String, epoch: UInt64, serviceEpoch: String) throws -> ManagedPrepareCompatibilityQueue.PublicTakeoverClaim? {
        guard profile == Carrier.fullProfile else { return nil }
        _ = try SignedCompatibilityIdentity.current(role: .engine)
        return try queue.publicTakeoverCapture(store: store, epoch: epoch, serviceEpoch: serviceEpoch)
    }
    func publicTakeoverPublish(_ data: Data, phase: String, claim: ManagedPrepareCompatibilityQueue.PublicTakeoverClaim) throws {
        _ = try SignedCompatibilityIdentity.current(role: .engine)
        try queue.publicTakeoverPublish(data, phase: phase, claim: claim)
    }
    func originalBaseline(binding: OriginalConsumerObservationProtocol.Binding,
        claim: ManagedPrepareCompatibilityQueue.OriginalClaim) throws -> OriginalConsumerRuntimeCarrier.Baseline? {
        try queue.originalBaseline(binding: binding, claim: claim)
    }
    func originalCapture(_ request: StorageServiceTypes.ReplacementRequest) throws -> ManagedPrepareCompatibilityQueue.OriginalClaim? {
        guard profile == Carrier.fullProfile else { return nil }
        _ = try SignedCompatibilityIdentity.current(role: .engine)
        let claim = try queue.originalCapture(request)
        try claim?.request.validate()
        return claim
    }
    func originalCandidate(_ candidate: OriginalConsumerRuntimeCarrier.Candidate,
        claim: ManagedPrepareCompatibilityQueue.OriginalClaim) throws {
        try queue.originalCandidate(candidate, claim: claim)
    }
    func originalPublish<T: Encodable>(_ value: T, phase: ManagedPrepareCompatibilityQueue.OriginalPhase,
        claim: ManagedPrepareCompatibilityQueue.OriginalClaim) throws {
        try queue.originalPublish(value, phase: phase, claim: claim)
    }
    func capture(container: String, instance: String, digest: String, mounts: [WorkloadStorageProtocol.MountBinding]) throws -> Claim? {
        try queue.capture(container: container, instance: instance, digest: digest, mounts: mounts)
    }
    func candidate(_ candidate: Carrier.Candidate, claim: Claim) throws { try queue.candidate(candidate, claim: claim) }
    func arm(_ claim: Claim, candidate: Carrier.Candidate) throws -> Carrier.Arm? { try queue.arm(claim, candidate: candidate) }
    func armed(_ arm: Carrier.Arm, claim: Claim) throws { try queue.armed(arm, claim: claim) }
    func checkpoint(_ observation: Carrier.Observation, arm: Carrier.Arm, claim: Claim) throws {
        try queue.checkpoint(observation, arm: arm, claim: claim)
    }
    func storageStatus(_ status: Carrier.StorageStatus, arm: Carrier.StorageArm, claim: Claim) throws {
        try queue.storageStatus(status, arm: arm, claim: claim)
    }
    func storageRelease(_ arm: Carrier.StorageArm, claim: Claim) throws -> Carrier.StorageRelease? {
        try queue.storageRelease(arm, claim: claim)
    }
    func storageWorkerExit(_ arm: Carrier.StorageArm, claim: Claim) throws -> Carrier.StorageRelease? {
        try queue.storageWorkerExit(arm, claim: claim)
    }
    func storageAction(_ arm: Carrier.StorageArm, claim: Claim, workerExitAllowed: Bool) throws -> ManagedPrepareCompatibilityQueue.StorageAction? {
        try queue.storageAction(arm, claim: claim, workerExitAllowed: workerExitAllowed)
    }
    func storageWorkerWait(_ wait: Carrier.StorageWorkerWait, arm: Carrier.StorageArm, claim: Claim) throws {
        try queue.storageWorkerWait(wait, arm: arm, claim: claim)
    }
    func checkpointWorkerExit(_ claim: Claim) throws -> Checkpoint.WorkerCheckpointExit? {
        try queue.checkpointWorkerExit(claim)
    }
    func checkpointWorkerWait(_ wait: Checkpoint.WorkerCheckpointWait, claim: Claim) throws {
        try queue.checkpointWorkerWait(wait, claim: claim)
    }
    func checkpoint(_ frame: WorkloadStorageProtocol.Frame, arm: Carrier.Arm, claim: Claim) throws {
        try Carrier.validateObservation(frame, arm: arm)
        if let observation = frame.data.compatibilityIOObservation {
            try queue.checkpoint(observation, arm: arm, claim: claim)
        } else if let observation = frame.data.compatibilityEarlyObservation {
            try queue.checkpoint(observation, arm: arm, claim: claim)
        } else if let observation = frame.data.compatibilityObservation {
            try queue.checkpoint(observation, arm: arm, claim: claim)
        } else { throw Carrier.Failure.invalid }
    }
}

/// Authority-free FD bookkeeping. Tests can construct the queue, but cannot
/// create a signed coordinator, send a guest command, or install a witness.
final class ManagedPrepareCompatibilityQueue: @unchecked Sendable {
    typealias Carrier = ManagedPrepareCompatibilityProtocol
    typealias Checkpoint = ManagedPrepareWorkerCheckpointProtocol
    enum Failure: Error { case unsafe, invalid, changed, full, io }
    static let directoryName = "managed-prepare-compatibility"
    private let storeLock: CanonicalDataStoreLock
    private let rootFD: Int32
    private let directoryFD: Int32
    private let serial = NSLock()
    private let identity = UUID()
    private var lifecyclePeers: [String: PinnedFile] = [:]

    /// Test-constructible bookkeeping only, never signed activation or authority.
    func lifecyclePeerPublish(_ observation: ManagedStorageLifecyclePeerObservation) throws {
        let data = try observation.canonicalData(), name = observation.filename
        try serial.withLock {
            try validate()
            func check(_ file: PinnedFile) throws {
                try Self.validateFile(file.fd, directory: directoryFD, name: file.name)
                guard try Self.read(file.fd, maximum: 65536) == file.data else { throw Failure.changed }
                try Self.validateFile(file.fd, directory: directoryFD, name: file.name)
            }
            for file in lifecyclePeers.values { try check(file) }
            let names = try entries().filter { $0.hasPrefix("lifecycle-peer-") && $0.hasSuffix(".json") }
            guard names.count <= 64 else { throw Failure.full }
            if let file = lifecyclePeers[name] {
                guard file.data == data else { throw Failure.changed }
            } else if names.contains(name) {
                guard lifecyclePeers.count < 64 else { throw Failure.full }
                let fd = openat(directoryFD, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
                guard fd >= 0 else { throw Failure.unsafe }
                let file = PinnedFile(fd: fd, name: name, data: data)
                try check(file)
                lifecyclePeers[name] = file
            } else {
                guard names.count < 64, lifecyclePeers.count < 64 else { throw Failure.full }
                lifecyclePeers[name] = try publish(name, data: data)
            }
            try validate()
            for file in lifecyclePeers.values { try check(file) }
        }
    }

    fileprivate final class PinnedFile {
        let fd: Int32
        let name: String
        let data: Data
        init(fd: Int32, name: String, data: Data) { self.fd = fd; self.name = name; self.data = data }
        deinit { close(fd) }
    }
    final class Claim: @unchecked Sendable {
        let request: Carrier.Capture
        fileprivate let owner: UUID
        fileprivate let capture: PinnedFile
        // Mutable state is accessed only under this claim's owning queue lock.
        fileprivate var candidate: Carrier.Candidate?
        fileprivate var acceptedArm: Carrier.Arm?
        fileprivate var acknowledged = false
        fileprivate var storageStatus: Carrier.StorageStatus?
        fileprivate var storageReleaseClaimed = false
        fileprivate var storageWorkerExitCheckpoint: Carrier.StorageStatus?
        fileprivate var storageWorkerWaitPublished = false
        fileprivate var checkpointWorkerExitClaimed = false
        fileprivate var checkpointWorkerExitClaim: Checkpoint.WorkerCheckpointExit?
        fileprivate var checkpointWorkerWaitPublished = false
        fileprivate var files: [PinnedFile] = []
        fileprivate init(request: Carrier.Capture, owner: UUID, capture: PinnedFile) {
            self.request = request; self.owner = owner; self.capture = capture
        }
    }

    init(storeLock: CanonicalDataStoreLock) throws {
        try storeLock.validateRetainedOwnership()
        self.storeLock = storeLock
        rootFD = try storeLock.duplicateRetainedDirectory()
        do {
            if mkdirat(rootFD, Self.directoryName, 0o700) != 0, errno != EEXIST { throw Failure.io }
            directoryFD = try Self.openDirectory(rootFD, Self.directoryName)
            guard fsync(rootFD) == 0 else { close(directoryFD); throw Failure.io }
        } catch { close(rootFD); throw error }
    }
    deinit { close(directoryFD); close(rootFD) }

    private func validate() throws {
        try storeLock.validateRetainedOwnership()
        try Self.validateDirectory(directoryFD, parent: rootFD, name: Self.directoryName)
    }
    /// A capture never supplies a launch/slot/key. Unselected starts never wait.
    func capture(container: String, instance: String, digest: String, mounts: [WorkloadStorageProtocol.MountBinding]) throws -> Claim? {
        try serial.withLock {
            try validate()
            let fd = openat(directoryFD, "capture.json", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            guard fd >= 0 else { if errno == ENOENT { return nil }; throw Failure.unsafe }
            var retained = false
            defer { if !retained { close(fd) } }
            try Self.validateFile(fd, directory: directoryFD, name: "capture.json")
            let bytes = try Self.read(fd, maximum: 65536)
            let request = try Carrier.decode(Carrier.Capture.self, from: bytes)
            try Carrier.validate(request)
            guard request.container == container else { return nil }
            guard request.containerInstance == instance, request.specificationDigest == digest,
                  request.mounts == mounts.sorted(by: { $0.index < $1.index }) else { throw Failure.changed }
            let names = try entries()
            guard names.filter({ $0.hasSuffix(".capture.json") }).count < 16 else { throw Failure.full }
            let name = request.requestID + ".capture.json"
            try Self.validateFile(fd, directory: directoryFD, name: "capture.json")
            guard renameatx_np(directoryFD, "capture.json", directoryFD, name, UInt32(RENAME_EXCL)) == 0 else { throw Failure.changed }
            try Self.validateFile(fd, directory: directoryFD, name: name)
            guard try Self.read(fd, maximum: 65536) == bytes, fsync(fd) == 0, fsync(directoryFD) == 0 else { throw Failure.changed }
            try validate()
            try Self.validateFile(fd, directory: directoryFD, name: name)
            retained = true
            return Claim(request: request, owner: identity, capture: PinnedFile(fd: fd, name: name, data: bytes))
        }
    }
    private func check(_ claim: Claim) throws {
        try validate()
        guard claim.owner == identity else { throw Failure.changed }
        for file in [claim.capture] + claim.files {
            try Self.validateFile(file.fd, directory: directoryFD, name: file.name)
            guard try Self.read(file.fd, maximum: 65536) == file.data else { throw Failure.changed }
            try Self.validateFile(file.fd, directory: directoryFD, name: file.name)
        }
    }
    func candidate(_ candidate: Carrier.Candidate, claim: Claim) throws {
        try serial.withLock {
            try check(claim)
            guard claim.candidate == nil, Carrier.profileVersion(candidate.profile) == candidate.version,
                  candidate.requestID == claim.request.requestID, candidate.scope.container == claim.request.container,
                  candidate.scope.containerInstance == claim.request.containerInstance,
                  candidate.scope.specificationDigest == claim.request.specificationDigest,
                  candidate.mounts == claim.request.mounts else { throw Failure.changed }
            claim.files.append(try publish(claim.request.requestID + ".candidate.json", data: Carrier.canonicalData(candidate)))
            try check(claim)
            claim.candidate = candidate
        }
    }
    func arm(_ claim: Claim, candidate: Carrier.Candidate) throws -> Carrier.Arm? {
        try serial.withLock {
            try check(claim)
            guard claim.acceptedArm == nil, claim.candidate == candidate else { throw Failure.changed }
            let name = claim.request.requestID + ".arm.json"
            let fd = openat(directoryFD, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            guard fd >= 0 else { if errno == ENOENT { return nil }; throw Failure.unsafe }
            var retained = false
            defer { if !retained { close(fd) } }
            try Self.validateFile(fd, directory: directoryFD, name: name)
            let bytes = try Self.read(fd, maximum: 65536)
            let arm = try Carrier.decode(Carrier.Arm.self, from: bytes)
            try Carrier.matches(arm, candidate: candidate)
            guard try Carrier.armData(arm) == bytes else { throw Failure.invalid }
            try Self.validateFile(fd, directory: directoryFD, name: name)
            let claimed = claim.request.requestID + ".arm.claimed.json"
            guard renameatx_np(directoryFD, name, directoryFD, claimed, UInt32(RENAME_EXCL)) == 0 else { throw Failure.changed }
            try Self.validateFile(fd, directory: directoryFD, name: claimed)
            guard try Self.read(fd, maximum: 65536) == bytes, fsync(fd) == 0, fsync(directoryFD) == 0 else { throw Failure.changed }
            try check(claim)
            try Self.validateFile(fd, directory: directoryFD, name: claimed)
            claim.files.append(PinnedFile(fd: fd, name: claimed, data: bytes))
            claim.acceptedArm = arm
            retained = true
            return arm
        }
    }
    func armed(_ arm: Carrier.Arm, claim: Claim) throws {
        try serial.withLock {
            try check(claim)
            guard claim.acceptedArm == arm, !claim.acknowledged else { throw Failure.changed }
            claim.files.append(try publish(arm.requestID + ".armed.json", data: Carrier.canonicalData(Carrier.Armed(version: arm.version, requestID: arm.requestID, armDigest: Carrier.digest(arm)))))
            try check(claim)
            claim.acknowledged = true
        }
    }
    func checkpoint(_ observation: Carrier.Observation, arm: Carrier.Arm, claim: Claim) throws {
        try serial.withLock {
            try check(claim)
            guard claim.acceptedArm == arm, claim.acknowledged else { throw Failure.changed }
            try Carrier.validate(observation, arm: arm)
            claim.files.append(try publish(arm.requestID + ".checkpoint.json", data: Carrier.canonicalData(observation)))
            try check(claim)
        }
    }
    func checkpoint(_ observation: Carrier.IOObservation, arm: Carrier.Arm, claim: Claim) throws {
        try serial.withLock {
            try check(claim)
            guard claim.acceptedArm == arm, claim.acknowledged else { throw Failure.changed }
            try Carrier.validate(observation, arm: arm)
            claim.files.append(try publish(arm.requestID + ".checkpoint.json", data: Carrier.canonicalData(observation)))
            try check(claim)
        }
    }
    func checkpoint(_ observation: Carrier.EarlyObservation, arm: Carrier.Arm, claim: Claim) throws {
        try serial.withLock {
            try check(claim)
            guard claim.acceptedArm == arm, claim.acknowledged else { throw Failure.changed }
            try Carrier.validate(observation, arm: arm)
            claim.files.append(try publish(arm.requestID + ".checkpoint.json", data: Carrier.canonicalData(observation)))
            try check(claim)
        }
    }
    func storageStatus(_ status: Carrier.StorageStatus, arm: Carrier.StorageArm, claim: Claim) throws {
        try serial.withLock {
            try check(claim)
            guard claim.acceptedArm == arm.arm, claim.storageWorkerExitCheckpoint == nil else { throw Failure.changed }
            try Carrier.validate(status, arm: arm)
            if let old = claim.storageStatus {
                let ranks = ["armed": 0, "observed": 1, "held": 1, "released": 2, "finished": 3]
                guard status.query == old.query, ranks[status.state]! >= ranks[old.state]!, !old.retirementStarted || status.retirementStarted,
                      !old.lateAdmissionRejected || status.lateAdmissionRejected,
                      status.receiptReplayCount >= old.receiptReplayCount,
                      old.observation == nil || old.observation == status.observation else { throw Failure.changed }
            } else { guard status.state == "armed" else { throw Failure.changed } }
            func publishOnce<T: Encodable>(_ suffix: String, _ value: T) throws {
                let name = arm.arm.requestID + suffix
                if !claim.files.contains(where: { $0.name == name }) {
                    claim.files.append(try publish(name, data: Carrier.canonicalData(value)))
                }
            }
            if status.state == "armed" { try publishOnce(".storage-armed.json", status) }
            else {
                guard claim.acknowledged, let observation = status.observation else { throw Failure.changed }
                try publishOnce(".storage-checkpoint.json", observation)
                if ["vm-private-bound", "vm-cleaning-transaction-removed", Carrier.twoVolumeDrainReplyGap].contains(observation.stage) {
                    // Publish the independently queried, arm-validated active hold,
                    // never a status reconstructed from the checkpoint. publish()
                    // fsyncs both the bytes and exclusive directory publication.
                    try publishOnce(".storage-held.json", status)
                }
                if observation.io != nil { try publishOnce(".storage-io.json", status) }
                if observation.admission != nil, status.state == "observed", status.retirementStarted {
                    try publishOnce(".storage-pending.json", status)
                }
                if status.state == "finished" {
                    guard status.retirementStarted, status.acceptedInFlight == 0,
                          status.lateAdmissionRejected == (observation.stage == "full-frame-before-admit"),
                          (status.receiptReplayCount > 0) == (observation.stage == "drain-durable-reply-lost") else { throw Failure.changed }
                    try publishOnce(".storage-finished.json", status)
                }
            }
            try check(claim)
            claim.storageStatus = status
        }
    }
    enum StorageAction: Equatable, Sendable {
        case release(Carrier.StorageRelease)
        case workerExit(Carrier.StorageRelease)
    }

    /// Select and claim under one queue lock. The strict single-route APIs still
    /// reject the other route even on an empty poll; they are not dispatch probes.
    func storageAction(_ arm: Carrier.StorageArm, claim: Claim, workerExitAllowed: Bool) throws -> StorageAction? {
        try serial.withLock {
            try check(claim)
            try Task.checkCancellation()
            guard claim.acceptedArm == arm.arm, claim.acknowledged else { throw Failure.changed }
            let requestID = arm.arm.requestID
            let releaseSuffixes = [".storage-release.json", ".storage-release.claimed.json"]
            let exitSuffixes = [".storage-worker-exit.json", ".storage-worker-exit.claimed.json", ".storage-worker-wait.json"]
            let genericSuffixes = [".checkpoint-worker-exit.json", ".checkpoint-worker-exit.claimed.json", ".checkpoint-worker-wait.json"]
            try requireAbsent(requestID, suffixes: genericSuffixes)
            guard !claim.checkpointWorkerExitClaimed else { throw Failure.changed }
            func present(_ suffix: String) throws -> Bool {
                var info = stat()
                if fstatat(directoryFD, requestID + suffix, &info, AT_SYMLINK_NOFOLLOW) == 0 { return true }
                guard errno == ENOENT else { throw Failure.unsafe }
                return false
            }
            let releasePresent = try releaseSuffixes.contains(where: present)
            let exitPresent = try exitSuffixes.contains(where: present)
            let releaseSelected = claim.storageReleaseClaimed || releasePresent
            let exitSelected = claim.storageWorkerExitCheckpoint != nil || exitPresent
            guard !(releaseSelected && exitSelected) else { throw Failure.changed }
            if releaseSelected {
                // An orphan/replayed claimed file is not our remembered route.
                if !claim.storageReleaseClaimed {
                    try requireAbsent(requestID, suffixes: [".storage-release.claimed.json"])
                } else {
                    try requireAbsent(requestID, suffixes: [".storage-release.json"])
                }
                try requireAbsent(requestID, suffixes: exitSuffixes + genericSuffixes)
                let release = try storageReleaseLocked(arm, claim: claim)
                // External writers do not take serial: recheck after the claim,
                // including nil polls, before any caller can send a guest action.
                try requireAbsent(requestID, suffixes: exitSuffixes + genericSuffixes)
                return release.map(StorageAction.release)
            }
            if exitSelected {
                if claim.storageWorkerExitCheckpoint == nil {
                    try requireAbsent(requestID, suffixes: [".storage-worker-exit.claimed.json", ".storage-worker-wait.json"])
                } else {
                    try requireAbsent(requestID, suffixes: [".storage-worker-exit.json"])
                }
                try requireAbsent(requestID, suffixes: releaseSuffixes + genericSuffixes)
                guard workerExitAllowed else { return nil }
                return try storageWorkerExitLocked(arm, claim: claim).map(StorageAction.workerExit)
            }
            return nil
        }
    }

    func storageRelease(_ arm: Carrier.StorageArm, claim: Claim) throws -> Carrier.StorageRelease? {
        try serial.withLock { try storageReleaseLocked(arm, claim: claim) }
    }
    private func storageReleaseLocked(_ arm: Carrier.StorageArm, claim: Claim) throws -> Carrier.StorageRelease? {
        try check(claim)
        guard claim.acceptedArm == arm.arm, claim.acknowledged else { throw Failure.changed }
        guard claim.storageWorkerExitCheckpoint == nil else { return nil }
        guard !claim.storageReleaseClaimed, let status = claim.storageStatus,
              status.state == "observed", status.retirementStarted,
              let observation = status.observation, let cut = observation.admission else { return nil }
        try requireAbsent(arm.arm.requestID, suffixes: [".storage-worker-exit.json", ".storage-worker-exit.claimed.json",
            ".checkpoint-worker-exit.json", ".checkpoint-worker-exit.claimed.json", ".checkpoint-worker-wait.json"])
        let name = arm.arm.requestID + ".storage-release.json"
        let fd = openat(directoryFD, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { if errno == ENOENT { return nil }; throw Failure.unsafe }
        var retained = false
        defer { if !retained { close(fd) } }
        try Self.validateFile(fd, directory: directoryFD, name: name)
        let bytes = try Self.read(fd, maximum: 65536)
        let release = try Carrier.decode(Carrier.StorageRelease.self, from: bytes)
        try Carrier.validate(release)
        guard release.query == status.query, release.stage == observation.stage,
              release.token == cut.releaseToken else { throw Failure.changed }
        try Self.validateFile(fd, directory: directoryFD, name: name)
        let claimed = arm.arm.requestID + ".storage-release.claimed.json"
        guard renameatx_np(directoryFD, name, directoryFD, claimed, UInt32(RENAME_EXCL)) == 0 else { throw Failure.changed }
        try Self.validateFile(fd, directory: directoryFD, name: claimed)
        guard try Self.read(fd, maximum: 65536) == bytes, fsync(fd) == 0, fsync(directoryFD) == 0 else { throw Failure.changed }
        claim.files.append(PinnedFile(fd: fd, name: claimed, data: bytes))
        retained = true
        try check(claim)
        claim.storageReleaseClaimed = true
        return release
    }
    /// Consumes only an explicit held A4/A5 action. Cancellation never releases or retries it.
    func storageWorkerExit(_ arm: Carrier.StorageArm, claim: Claim) throws -> Carrier.StorageRelease? {
        try serial.withLock { try storageWorkerExitLocked(arm, claim: claim) }
    }
    private func storageWorkerExitLocked(_ arm: Carrier.StorageArm, claim: Claim) throws -> Carrier.StorageRelease? {
        try check(claim)
        try Task.checkCancellation()
        // The cross-route exclusion fence runs BEFORE the own-file open so a
        // merely present generic-route file fails closed instead of looking
        // like an unconsumed empty poll (ENOENT must not mask the fence).
        try requireAbsent(arm.arm.requestID, suffixes: [".storage-release.json", ".storage-release.claimed.json", ".storage-worker-wait.json",
            ".checkpoint-worker-exit.json", ".checkpoint-worker-exit.claimed.json", ".checkpoint-worker-wait.json"])
        guard claim.acceptedArm == arm.arm, claim.acknowledged else { throw Failure.changed }
        if claim.storageWorkerExitCheckpoint != nil { return nil }
        let name = arm.arm.requestID + ".storage-worker-exit.json"
        let fd = openat(directoryFD, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { if errno == ENOENT { return nil }; throw Failure.unsafe }
        var retained = false
        defer { if !retained { close(fd) } }
        guard !claim.storageReleaseClaimed, let checkpoint = claim.storageStatus else { throw Failure.changed }
        try Self.validateFile(fd, directory: directoryFD, name: name)
        let bytes = try Self.read(fd, maximum: 65536)
        let exit = try Carrier.decode(Carrier.StorageRelease.self, from: bytes)
        try Carrier.validateStorageWorkerExit(exit, arm: arm, checkpoint: checkpoint)
        try Self.validateFile(fd, directory: directoryFD, name: name)
        let claimed = arm.arm.requestID + ".storage-worker-exit.claimed.json"
        guard renameatx_np(directoryFD, name, directoryFD, claimed, UInt32(RENAME_EXCL)) == 0 else { throw Failure.changed }
        try Self.validateFile(fd, directory: directoryFD, name: claimed)
        guard try Self.read(fd, maximum: 65536) == bytes, fsync(fd) == 0, fsync(directoryFD) == 0 else { throw Failure.changed }
        claim.files.append(PinnedFile(fd: fd, name: claimed, data: bytes))
        retained = true
        claim.storageWorkerExitCheckpoint = checkpoint
        try check(claim)
        try requireAbsent(arm.arm.requestID, suffixes: [".storage-release.json", ".storage-release.claimed.json",
            ".checkpoint-worker-exit.json", ".checkpoint-worker-exit.claimed.json", ".checkpoint-worker-wait.json"])
        return exit
    }
    func storageWorkerWait(_ wait: Carrier.StorageWorkerWait, arm: Carrier.StorageArm, claim: Claim) throws {
        try serial.withLock {
            try check(claim)
            try Task.checkCancellation()
            guard claim.acceptedArm == arm.arm, claim.acknowledged, !claim.storageReleaseClaimed,
                  !claim.storageWorkerWaitPublished, let checkpoint = claim.storageWorkerExitCheckpoint else { throw Failure.changed }
            try requireAbsent(arm.arm.requestID, suffixes: [".storage-release.json", ".storage-release.claimed.json", ".storage-worker-exit.json",
                ".checkpoint-worker-exit.json", ".checkpoint-worker-exit.claimed.json", ".checkpoint-worker-wait.json"])
            try Carrier.validate(wait, arm: arm, checkpoint: checkpoint)
            claim.files.append(try publish(arm.arm.requestID + ".storage-worker-wait.json", data: Carrier.canonicalData(wait)))
            claim.storageWorkerWaitPublished = true
            try check(claim)
        }
    }
    /// Consumes only an explicit RTM098 generic checkpoint exit action for one
    /// of the seven full-profile guest-visible cuts. Cancellation never
    /// releases or retries it. Never mixes with the A4/A5 storage release flow:
    /// both directions fence with requireAbsent on the other's suffixes.
    func checkpointWorkerExit(_ claim: Claim) throws -> Checkpoint.WorkerCheckpointExit? {
        try serial.withLock {
            try check(claim)
            try Task.checkCancellation()
            guard claim.acknowledged, let arm = claim.acceptedArm else { throw Failure.changed }
            // Cross-route fence BEFORE the own-file open: a merely present
            // A4/A5-route file fails closed instead of masquerading as an
            // unconsumed empty poll.
            try requireAbsent(arm.requestID, suffixes: [".storage-worker-exit.json", ".storage-worker-exit.claimed.json",
                ".storage-release.json", ".storage-release.claimed.json", ".storage-worker-wait.json"])
            if claim.checkpointWorkerExitClaimed { return nil }
            let name = arm.requestID + ".checkpoint-worker-exit.json"
            let fd = openat(directoryFD, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            guard fd >= 0 else { if errno == ENOENT { return nil }; throw Failure.unsafe }
            var retained = false
            defer { if !retained { close(fd) } }
            try Self.validateFile(fd, directory: directoryFD, name: name)
            let bytes = try Self.read(fd, maximum: Checkpoint.maximumFrameBytes)
            let exit = try Checkpoint.decodeWorkerCheckpointExit(from: bytes)
            try Self.validateFile(fd, directory: directoryFD, name: name)
            // Bind to this claim's exact accepted arm and the REAL retained
            // checkpoint publication already pinned under .checkpoint.json
            // (physical/early observation) or .storage-checkpoint.json (the
            // exact storage-owned Bound/Drain observation). Never a synthetic
            // or reconstructed checkpoint.
            guard exit.arm == arm else { throw Failure.changed }
            let suffix: String
            let carrier: Data
            if let checkpoint = exit.checkpoint {
                suffix = ".checkpoint.json"; carrier = try Carrier.canonicalData(checkpoint)
            } else if let checkpoint = exit.earlyCheckpoint {
                suffix = ".checkpoint.json"; carrier = try Carrier.canonicalData(checkpoint)
            } else if let checkpoint = exit.storageCheckpoint {
                suffix = ".storage-checkpoint.json"; carrier = try Carrier.canonicalData(checkpoint)
            } else { throw Failure.invalid }
            guard claim.files.contains(where: { $0.name == arm.requestID + suffix && $0.data == carrier }) else { throw Failure.changed }
            let claimed = arm.requestID + ".checkpoint-worker-exit.claimed.json"
            guard renameatx_np(directoryFD, name, directoryFD, claimed, UInt32(RENAME_EXCL)) == 0 else { throw Failure.changed }
            try Self.validateFile(fd, directory: directoryFD, name: claimed)
            guard try Self.read(fd, maximum: Checkpoint.maximumFrameBytes) == bytes, fsync(fd) == 0, fsync(directoryFD) == 0 else { throw Failure.changed }
            claim.files.append(PinnedFile(fd: fd, name: claimed, data: bytes))
            retained = true
            claim.checkpointWorkerExitClaimed = true
            claim.checkpointWorkerExitClaim = exit
            try check(claim)
            try requireAbsent(arm.requestID, suffixes: [".storage-worker-exit.json", ".storage-worker-exit.claimed.json",
                ".storage-release.json", ".storage-release.claimed.json"])
            return exit
        }
    }
    /// Publishes PID1's sole actual Wait projection of the claimed exit. The
    /// wait must echo the exact sealed claim field-for-field; one-shot.
    func checkpointWorkerWait(_ wait: Checkpoint.WorkerCheckpointWait, claim: Claim) throws {
        try serial.withLock {
            try check(claim)
            try Task.checkCancellation()
            guard claim.acknowledged, !claim.checkpointWorkerWaitPublished,
                  let exit = claim.checkpointWorkerExitClaim else { throw Failure.changed }
            try requireAbsent(exit.arm.requestID, suffixes: [".storage-worker-exit.json", ".storage-worker-exit.claimed.json",
                ".storage-release.json", ".storage-release.claimed.json", ".storage-worker-wait.json"])
            try Checkpoint.validate(wait, for: exit)
            claim.files.append(try publish(exit.arm.requestID + ".checkpoint-worker-wait.json", data: Carrier.canonicalData(wait)))
            claim.checkpointWorkerWaitPublished = true
            try check(claim)
        }
    }
    private func requireAbsent(_ requestID: String, suffixes: [String]) throws {
        for suffix in suffixes {
            var info = stat()
            guard fstatat(directoryFD, requestID + suffix, &info, AT_SYMLINK_NOFOLLOW) != 0, errno == ENOENT else { throw Failure.changed }
        }
    }
    private func publish(_ name: String, data: Data) throws -> PinnedFile {
        guard data.count <= 65536 else { throw Failure.full }
        let staging = name + ".writing"
        let fd = openat(directoryFD, staging, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
        guard fd >= 0 else { throw Failure.io }
        var retained = false
        defer { if !retained { close(fd) } }
        try Self.validateFile(fd, directory: directoryFD, name: staging)
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw Failure.io }; offset += count
            }
        }
        guard fsync(fd) == 0, try Self.read(fd, maximum: 65536) == data else { throw Failure.io }
        try validate()
        try Self.validateFile(fd, directory: directoryFD, name: staging)
        guard renameatx_np(directoryFD, staging, directoryFD, name, UInt32(RENAME_EXCL)) == 0,
              fsync(directoryFD) == 0 else { throw Failure.io }
        try Self.validateFile(fd, directory: directoryFD, name: name)
        guard try Self.read(fd, maximum: 65536) == data else { throw Failure.changed }
        try validate()
        try Self.validateFile(fd, directory: directoryFD, name: name)
        retained = true
        return PinnedFile(fd: fd, name: name, data: data)
    }
    /// Selection only: no boot, key, signed grant or positive supplied by disk.
    struct PublicTakeoverArmCapture: Codable, Equatable, Sendable {
        let version: String
        let requestID: String
        let operationUUID: String
        let store: String
        let epoch: UInt64
        let serviceEpoch: String
        let container: String
        let containerInstance: String
        var positiveOnly: Bool? = nil
        var isolationCase: String? = nil
    }
    final class PublicTakeoverArmClaim: @unchecked Sendable {
        let request: PublicTakeoverArmCapture
        fileprivate let owner: UUID
        fileprivate var files: [PinnedFile]
        fileprivate var phase = 0
        fileprivate init(_ request: PublicTakeoverArmCapture, owner: UUID, file: PinnedFile) {
            self.request = request; self.owner = owner; files = [file]
        }
    }
    func publicTakeoverArmCapture(container: String, instance: String) throws -> PublicTakeoverArmClaim? {
        try serial.withLock {
            try validate()
            let name = "public-takeover-arm.capture.json"
            let fd = openat(directoryFD, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            guard fd >= 0 else { if errno == ENOENT { return nil }; throw Failure.unsafe }
            var retained = false; defer { if !retained { close(fd) } }
            try Self.validateFile(fd, directory: directoryFD, name: name)
            let bytes = try Self.read(fd, maximum: 4096)
            let request = try Carrier.decode(PublicTakeoverArmCapture.self, from: bytes)
            for id in [request.requestID, request.operationUUID, request.store, request.serviceEpoch, request.containerInstance] {
                _ = try StorageIdentity.RequestID(id)
            }
            guard request.isolationCase == nil || (request.positiveOnly == true &&
                ["legacy-connection", "second-service-exclusivity"].contains(request.isolationCase!)) else { throw Failure.invalid }
            guard request.version == "original-takeover-arm.v1", request.epoch >= 2, request.positiveOnly == nil || request.positiveOnly == true,
                  OriginalConsumerObservationProtocol.hash(request.container) else { throw Failure.invalid }
            guard request.container == container else { return nil }
            guard request.containerInstance == instance,
                  try entries().filter({ $0.hasSuffix(".public-takeover-arm.capture.json") }).count < 16 else { throw Failure.invalid }
            let target = request.requestID + ".public-takeover-arm.capture.json"
            try Self.validateFile(fd, directory: directoryFD, name: name)
            guard renameatx_np(directoryFD, name, directoryFD, target, UInt32(RENAME_EXCL)) == 0,
                  fsync(fd) == 0, fsync(directoryFD) == 0 else { throw Failure.changed }
            try Self.validateFile(fd, directory: directoryFD, name: target)
            guard try Self.read(fd, maximum: 4096) == bytes else { throw Failure.changed }
            retained = true
            return PublicTakeoverArmClaim(request, owner: identity, file: PinnedFile(fd: fd, name: target, data: bytes))
        }
    }
    func publicTakeoverArmPublish(_ data: Data, phase: String, claim: PublicTakeoverArmClaim) throws {
        try serial.withLock {
            try validate()
            let phases = claim.request.isolationCase != nil ? ["candidate", "armed", "registry", "isolation", "positive", "released"] :
                (claim.request.positiveOnly == true ? ["candidate", "armed", "registry", "released"] : ["candidate", "armed", "registry"])
            guard claim.owner == identity, phases.indices.contains(claim.phase), phases[claim.phase] == phase else { throw Failure.changed }
            for file in claim.files {
                try Self.validateFile(file.fd, directory: directoryFD, name: file.name)
                guard try Self.read(file.fd, maximum: 65536) == file.data else { throw Failure.changed }
            }
            claim.files.append(try publish(claim.request.requestID + ".public-takeover-arm." + phase + ".json", data: data))
            claim.phase += 1
        }
    }
    struct PublicTakeoverCapture: Codable, Equatable, Sendable {
        let version: String
        let requestID: String
        let store: String
        let epoch: UInt64
        let serviceEpoch: String
        var original: OriginalConsumerObservationProtocol.Binding? = nil
    }
    final class PublicTakeoverClaim: @unchecked Sendable {
        let request: PublicTakeoverCapture
        fileprivate let owner: UUID
        fileprivate var files: [PinnedFile]
        fileprivate var phase = 0
        fileprivate init(_ request: PublicTakeoverCapture, owner: UUID, file: PinnedFile) {
            self.request = request; self.owner = owner; files = [file]
        }
    }
    func publicTakeoverCapture(store: String, epoch: UInt64, serviceEpoch: String) throws -> PublicTakeoverClaim? {
        try serial.withLock {
            try validate()
            let name = "public-takeover.capture.json"
            let fd = openat(directoryFD, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            guard fd >= 0 else { if errno == ENOENT { return nil }; throw Failure.unsafe }
            var retained = false; defer { if !retained { close(fd) } }
            try Self.validateFile(fd, directory: directoryFD, name: name)
            let bytes = try Self.read(fd, maximum: 4096)
            let request = try Carrier.decode(PublicTakeoverCapture.self, from: bytes)
            _ = try StorageIdentity.RequestID(request.requestID)
            guard request.version == "original-takeover-public.v1", request.store == store,
                  request.epoch == epoch, epoch >= 2, request.serviceEpoch == serviceEpoch,
                  try entries().filter({ $0.hasSuffix(".public-takeover.capture.json") }).count < 16 else { throw Failure.invalid }
            if let original = request.original {
                try OriginalConsumerObservationProtocol.validate(original)
                guard original.caseName == .sameEExistingData, original.scope.store == store,
                      original.scope.serviceEpoch == serviceEpoch, original.scope.controllerEpoch <= epoch else { throw Failure.invalid }
            }
            let target = request.requestID + ".public-takeover.capture.json"
            try Self.validateFile(fd, directory: directoryFD, name: name)
            guard renameatx_np(directoryFD, name, directoryFD, target, UInt32(RENAME_EXCL)) == 0,
                  fsync(fd) == 0, fsync(directoryFD) == 0 else { throw Failure.changed }
            try Self.validateFile(fd, directory: directoryFD, name: target)
            guard try Self.read(fd, maximum: 4096) == bytes else { throw Failure.changed }
            retained = true
            return PublicTakeoverClaim(request, owner: identity, file: PinnedFile(fd: fd, name: target, data: bytes))
        }
    }
    func publicTakeoverPublish(_ data: Data, phase: String, claim: PublicTakeoverClaim) throws {
        try serial.withLock {
            try validate()
            let phases = claim.request.original == nil ? ["begun", "denied", "confirmed"] : ["begun", "denied", "attestation", "confirmed", "resumed", "positive", "registry"]
            guard claim.owner == identity, phases.indices.contains(claim.phase), phases[claim.phase] == phase else { throw Failure.changed }
            for file in claim.files {
                try Self.validateFile(file.fd, directory: directoryFD, name: file.name)
                guard try Self.read(file.fd, maximum: 65536) == file.data else { throw Failure.changed }
            }
            claim.files.append(try publish(claim.request.requestID + ".public-takeover." + phase + ".json", data: data))
            claim.phase += 1
        }
    }
    private func entries() throws -> [String] {
        let fd = openat(directoryFD, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw Failure.io }
        guard let stream = fdopendir(fd) else { close(fd); throw Failure.io }
        defer { closedir(stream) }
        var names: [String] = []
        while true {
            errno = 0
            guard let entry = readdir(stream) else { guard errno == 0 else { throw Failure.io }; break }
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) { String(cString: $0) }
            }
            if name == "." || name == ".." { continue }
            guard names.count < 16 * 16 + 1 else { throw Failure.full }
            names.append(name)
        }
        return names
    }
    private static func openDirectory(_ parent: Int32, _ name: String) throws -> Int32 {
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw Failure.unsafe }
        do { try validateDirectory(fd, parent: parent, name: name); return fd }
        catch { close(fd); throw error }
    }

    private static func validateDirectory(_ fd: Int32, parent: Int32, name: String) throws {
        var held = stat(), named = stat()
        guard fstat(fd, &held) == 0, fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              held.st_mode & S_IFMT == S_IFDIR, held.st_uid == geteuid(), held.st_mode & 0o7777 == 0o700,
              held.st_dev == named.st_dev, held.st_ino == named.st_ino, held.st_mode == named.st_mode,
              held.st_uid == named.st_uid else { throw Failure.unsafe }
    }

    @discardableResult static func validateFile(_ fd: Int32, directory: Int32, name: String,
                                                expectedUID: uid_t = geteuid()) throws -> stat {
        var held = stat(), named = stat(), parent = stat()
        guard fstat(fd, &held) == 0, fstat(directory, &parent) == 0,
              fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              held.st_mode & S_IFMT == S_IFREG, held.st_uid == expectedUID,
              held.st_mode & 0o7777 == 0o600, held.st_nlink == 1,
              held.st_dev == parent.st_dev, held.st_dev == named.st_dev, held.st_ino == named.st_ino,
              held.st_mode == named.st_mode, held.st_uid == named.st_uid, named.st_nlink == 1 else { throw Failure.unsafe }
        return held
    }

    private static func read(_ fd: Int32, maximum: Int) throws -> Data {
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_size >= 0, info.st_size <= maximum,
              lseek(fd, 0, SEEK_SET) == 0 else { throw Failure.invalid }
        var bytes = [UInt8](repeating: 0, count: Int(info.st_size) + 1)
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeMutableBytes {
                Darwin.read(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset)
            }
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw Failure.io }
            if count == 0 { break }; offset += count
        }
        guard offset == info.st_size else { throw Failure.changed }
        return Data(bytes.prefix(offset))
    }
}

#if os(macOS)
extension ManagedPrepareCompatibilityQueue {
    enum OriginalPhase: String { case armed, baselineAccepted = "baseline-accepted", begun, result, freshGetattr = "fresh-getattr", freshRootRead = "fresh-root-read", failed }
    final class OriginalClaim: @unchecked Sendable {
        let request: OriginalConsumerRuntimeCarrier.Request
        fileprivate let owner: UUID
        fileprivate var files: [PinnedFile]
        fileprivate var candidate: OriginalConsumerRuntimeCarrier.Candidate?
        fileprivate var phases = Set<String>()
        fileprivate init(request: OriginalConsumerRuntimeCarrier.Request, owner: UUID, file: PinnedFile) {
            self.request = request; self.owner = owner; files = [file]
        }
    }
    private func checkOriginal(_ claim: OriginalClaim) throws {
        try validate()
        guard claim.owner == identity else { throw Failure.changed }
        for file in claim.files {
            try Self.validateFile(file.fd, directory: directoryFD, name: file.name)
            guard try Self.read(file.fd, maximum: 65536) == file.data else { throw Failure.changed }
            try Self.validateFile(file.fd, directory: directoryFD, name: file.name)
        }
    }
    func originalCapture(_ replacement: StorageServiceTypes.ReplacementRequest) throws -> OriginalClaim? {
        try serial.withLock {
            try validate()
            let name = "original-consumer.capture.json"
            let fd = openat(directoryFD, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            guard fd >= 0 else { if errno == ENOENT { return nil }; throw Failure.unsafe }
            var retained = false
            defer { if !retained { close(fd) } }
            try Self.validateFile(fd, directory: directoryFD, name: name)
            let bytes = try Self.read(fd, maximum: 65536)
            let request = try Carrier.decode(OriginalConsumerRuntimeCarrier.Request.self, from: bytes)
            try request.validateShape()
            guard request.operationUUID == replacement.operationUUID else { throw Failure.changed }
            guard try entries().filter({ $0.hasSuffix(".original-consumer.capture.json") }).count < 16 else { throw Failure.full }
            let claimed = request.requestID + ".original-consumer.capture.json"
            try Self.validateFile(fd, directory: directoryFD, name: name)
            guard renameatx_np(directoryFD, name, directoryFD, claimed, UInt32(RENAME_EXCL)) == 0 else { throw Failure.changed }
            try Self.validateFile(fd, directory: directoryFD, name: claimed)
            guard try Self.read(fd, maximum: 65536) == bytes, fsync(fd) == 0, fsync(directoryFD) == 0 else { throw Failure.changed }
            try validate()
            retained = true
            return OriginalClaim(request: request, owner: identity, file: PinnedFile(fd: fd, name: claimed, data: bytes))
        }
    }
    func originalCandidate(_ candidate: OriginalConsumerRuntimeCarrier.Candidate, claim: OriginalClaim) throws {
        try serial.withLock {
            try checkOriginal(claim)
            guard claim.candidate == nil, candidate.request == claim.request,
                  candidate.binding.requestID == claim.request.requestID,
                  candidate.binding.operationUUID == claim.request.operationUUID,
                  candidate.binding.caseName == claim.request.caseName,
                  candidate.ownerRequest.operationUUID == claim.request.operationUUID,
                  candidate.ownerRequest.predecessor.serviceEpoch == candidate.binding.scope.serviceEpoch,
                  candidate.binding.scope.container == claim.request.container,
                  candidate.binding.scope.containerInstance == claim.request.containerInstance else { throw Failure.changed }
            try OriginalConsumerObservationProtocol.validate(candidate.binding)
            claim.files.append(try publish(claim.request.requestID + ".original-consumer.candidate.json", data: Carrier.canonicalData(candidate)))
            try checkOriginal(claim)
            claim.candidate = candidate
        }
    }
    func originalBaseline(binding: OriginalConsumerObservationProtocol.Binding,
        claim: OriginalClaim) throws -> OriginalConsumerRuntimeCarrier.Baseline? {
        try serial.withLock {
            try checkOriginal(claim)
            guard claim.candidate?.binding == binding, (binding.caseName.isWritableFD || binding.caseName.isRoot),
                  claim.phases == ["armed"] else { throw Failure.changed }
            let name = claim.request.requestID + ".original-consumer.baseline.json"
            guard !claim.files.contains(where: { $0.name == name }) else { throw Failure.changed }
            let fd = openat(directoryFD, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            guard fd >= 0 else { if errno == ENOENT { return nil }; throw Failure.unsafe }
            var retained = false
            defer { if !retained { close(fd) } }
            try Self.validateFile(fd, directory: directoryFD, name: name)
            let bytes = try Self.read(fd, maximum: 65536)
            let baseline = try Carrier.decode(OriginalConsumerRuntimeCarrier.Baseline.self, from: bytes)
            try baseline.validate()
            guard baseline.binding == binding else { throw Failure.changed }
            try Self.validateFile(fd, directory: directoryFD, name: name)
            guard try Self.read(fd, maximum: 65536) == bytes else { throw Failure.changed }
            claim.files.append(PinnedFile(fd: fd, name: name, data: bytes)); retained = true
            try checkOriginal(claim)
            return baseline
        }
    }
    /// Use only observations independently published from the sealed lifecycle
    /// session, never a result's registry or the workload shim generation.
    /// Called under serial; disk-only entries are not eligible provenance.
    private func originalLifecycleIdentity(_ candidate: OriginalConsumerRuntimeCarrier.Candidate) throws -> StorageLifecycleProtocol.Identity? {
        let scope = candidate.binding.scope, predecessor = candidate.ownerRequest.predecessor
        let name = "lifecycle-peer-" + predecessor.workerUUID + "-" + String(scope.controllerEpoch) + ".json"
        guard let file = lifecyclePeers[name] else {
            guard lifecyclePeers.isEmpty else { throw Failure.changed }
            return nil
        }
        try Self.validateFile(file.fd, directory: directoryFD, name: file.name)
        guard try Self.read(file.fd, maximum: 65536) == file.data else { throw Failure.changed }
        let observation = try ManagedStorageLifecyclePeerObservation.decode(file.data)
        let ready = observation.ready
        guard ready.identity.store == scope.store, ready.serviceEpoch == scope.serviceEpoch,
              ready.serviceEpoch == predecessor.serviceEpoch, ready.workerUUID == predecessor.workerUUID,
              ready.controllerEpoch == scope.controllerEpoch, ready.controllerKey == scope.controllerKey else { throw Failure.changed }
        try Self.validateFile(file.fd, directory: directoryFD, name: file.name)
        return ready.identity
    }
    func originalPublish<T: Encodable>(_ value: T, phase: OriginalPhase, claim: OriginalClaim) throws {
        try serial.withLock {
            try checkOriginal(claim)
            guard !claim.phases.contains(phase.rawValue), !claim.phases.contains("failed"),
                  (!claim.phases.contains("result") || phase == .freshGetattr || phase == .freshRootRead) else { throw Failure.changed }
            switch phase {
            case .armed: guard claim.candidate != nil, claim.phases.isEmpty else { throw Failure.changed }
            case .baselineAccepted:
                guard (claim.candidate?.binding.caseName.isWritableFD == true || claim.candidate?.binding.caseName.isRoot == true), claim.phases == ["armed"],
                      claim.files.contains(where: { $0.name == claim.request.requestID + ".original-consumer.baseline.json" }) else { throw Failure.changed }
            case .begun:
                let required: Set<String> = (claim.candidate?.binding.caseName.isWritableFD == true || claim.candidate?.binding.caseName.isRoot == true) ? ["armed", "baseline-accepted"] : ["armed"]
                guard claim.phases == required else { throw Failure.changed }
            case .result:
                let required: Set<String> = (claim.candidate?.binding.caseName.isWritableFD == true || claim.candidate?.binding.caseName.isRoot == true) ? ["armed", "baseline-accepted", "begun"] : ["armed", "begun"]
                guard claim.phases == required else { throw Failure.changed }
                if let candidate = claim.candidate, candidate.binding.caseName.isRoot {
                    let binding = candidate.binding
                    let proof = try Carrier.decode(OriginalConsumerRuntimeCarrier.RootResult.self,
                        from: Carrier.canonicalData(value))
                    try proof.validate(original: binding, service: .init(storeUUID: binding.scope.store,
                        serviceEpoch: candidate.ownerRequest.predecessor.serviceEpoch,
                        workerUUID: candidate.ownerRequest.predecessor.workerUUID),
                        lifecycleIdentity: originalLifecycleIdentity(candidate))
                }
                if let candidate = claim.candidate, candidate.binding.caseName.isRegistration {
                    let proof = try Carrier.decode(OriginalConsumerRuntimeCarrier.Result.self, from: Carrier.canonicalData(value))
                    try proof.validateRegistration(binding: candidate.binding, service: .init(storeUUID: candidate.binding.scope.store,
                        serviceEpoch: candidate.ownerRequest.predecessor.serviceEpoch, workerUUID: candidate.ownerRequest.predecessor.workerUUID),
                        lifecycleIdentity: originalLifecycleIdentity(candidate))
                }
            case .freshRootRead:
                guard claim.phases.contains("result"), let original = claim.candidate?.binding, original.caseName.isRoot,
                      let result = claim.files.first(where: { $0.name == claim.request.requestID + ".original-consumer.result.json" }) else { throw Failure.changed }
                let previous = try Carrier.decode(OriginalConsumerRuntimeCarrier.RootResult.self, from: result.data)
                let proof = try Carrier.decode(OriginalConsumerRuntimeCarrier.FreshRootRead.self, from: Carrier.canonicalData(value))
                guard previous.binding == original else { throw Failure.changed }
                try proof.validate(previous: previous)
            case .freshGetattr:
                guard claim.phases.contains("result"), let original = claim.candidate?.binding else { throw Failure.changed }
                let proof = try Carrier.decode(OriginalConsumerRuntimeCarrier.FreshGetattr.self, from: Carrier.canonicalData(value))
                try proof.validate(original: original)
            case .failed: break
            }
            claim.files.append(try publish(claim.request.requestID + ".original-consumer." + phase.rawValue + ".json", data: Carrier.canonicalData(value)))
            try checkOriginal(claim)
            claim.phases.insert(phase.rawValue)
        }
    }
}
#endif

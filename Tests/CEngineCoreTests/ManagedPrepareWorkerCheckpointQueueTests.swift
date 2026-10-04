#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

/// RTM098 generic checkpoint-exit queue claim gating: one-shot consumption of
/// <requestID>.checkpoint-worker-exit.json into .claimed.json, exact wait
/// binding to the sealed claim, and strict cross-route exclusion against the
/// A4/A5 storageWorkerExit/storageRelease flow. Mirrors ManagedPrepareWorkerExitTests.
// Serialized: pairs with ManagedPrepareWorkerCheckpointTests on the same
// recursive validators; concurrent execution overflows the test runner's
// per-test thread stack (each test passes in isolation).
@Suite(.serialized) struct ManagedPrepareWorkerCheckpointQueueTests {
    typealias C = ManagedPrepareCompatibilityProtocol
    typealias Checkpoint = ManagedPrepareWorkerCheckpointProtocol

    @Test func claimIsOneShotAndWaitBindsExactSealedClaim() throws {
        let q = try CheckpointQueueFixture(stage: "normal"); defer { q.remove() }
        let exit = try q.exit
        // Nothing dropped: nothing claimed, and no wait may publish.
        #expect(try q.queue.checkpointWorkerExit(q.claim) == nil)
        #expect(throws: (any Error).self) { try q.queue.checkpointWorkerWait(try q.wait, claim: q.claim) }
        try q.put(exit, ".checkpoint-worker-exit.json")
        #expect(try q.queue.checkpointWorkerExit(q.claim) == exit)
        #expect(!q.exists(".checkpoint-worker-exit.json"))
        #expect(try q.bytes(".checkpoint-worker-exit.claimed.json") == C.canonicalData(exit))
        // One-shot: the claimed action is never re-consumed.
        #expect(try q.queue.checkpointWorkerExit(q.claim) == nil)
        // The wait must echo the exact sealed claim plus the sole actual Wait.
        var tampered = try q.wait; tampered.workerPID = 1
        #expect(throws: (any Error).self) { try q.queue.checkpointWorkerWait(tampered, claim: q.claim) }
        tampered = try q.wait; tampered.exitCode = 0
        #expect(throws: (any Error).self) { try q.queue.checkpointWorkerWait(tampered, claim: q.claim) }
        tampered = try q.wait; tampered.reaped = false
        #expect(throws: (any Error).self) { try q.queue.checkpointWorkerWait(tampered, claim: q.claim) }
        tampered = try q.wait; tampered.workerUUID = UUID().uuidString.lowercased()
        #expect(throws: (any Error).self) { try q.queue.checkpointWorkerWait(tampered, claim: q.claim) }
        tampered = try q.wait; tampered.checkpoint = nil
        tampered.earlyCheckpoint = try CheckpointRow(stage: "data-partial-frame").earlyObservation
        #expect(throws: (any Error).self) { try q.queue.checkpointWorkerWait(tampered, claim: q.claim) }
        #expect(!q.exists(".checkpoint-worker-wait.json"))
        try q.queue.checkpointWorkerWait(try q.wait, claim: q.claim)
        #expect(try q.bytes(".checkpoint-worker-wait.json") == C.canonicalData(try q.wait))
        // One-shot: the exact published wait is never republished.
        #expect(throws: (any Error).self) { try q.queue.checkpointWorkerWait(try q.wait, claim: q.claim) }
    }

    @Test func earlyCutBindsActualEarlyPublicationNeverPhysical() throws {
        let q = try CheckpointQueueFixture(stage: "data-partial-frame"); defer { q.remove() }
        let exit = try q.exit
        try q.put(exit, ".checkpoint-worker-exit.json")
        #expect(try q.queue.checkpointWorkerExit(q.claim) == exit)
        try q.queue.checkpointWorkerWait(try q.wait, claim: q.claim)
        #expect(try q.bytes(".checkpoint-worker-wait.json") == C.canonicalData(try q.wait))
        // A physical carrier can never stand in for an early partial-frame cut:
        // the carrier kind is selected by the arm's case.
        let physical = try CheckpointRow(stage: "normal")
        let wrong = Checkpoint.WorkerCheckpointExit(arm: exit.arm, checkpoint: try physical.observation,
                                                    workerUUID: exit.workerUUID)
        #expect(throws: (any Error).self) { try Checkpoint.validate(wrong) }
        // And the early checkpoint bytes are bound exactly: a different early
        // observation for the same arm is not the retained publication.
        var otherArm = exit.arm
        let otherRow = try CheckpointRow(stage: "guest-accepted-before-prepare")
        // full-vectors.json shares ONE requestID across every row, so mutating
        // only the case still yields a digest-valid guest-accepted arm carrying
        // its own retained publication. To keep this a genuinely FOREIGN early
        // observation (another request's cut, never this arm's retained
        // publication) the arm needs that other request's identity; structural
        // validate then rejects it at the requestID binding. The same-arm
        // retained-bytes binding for THIS claim lives in checkpointWorkerExit.
        otherArm.caseName = "guest-accepted-before-prepare"
        otherArm.requestID = UUID().uuidString.lowercased()
        let foreign = Checkpoint.WorkerCheckpointExit(arm: otherArm, earlyCheckpoint: try otherRow.earlyObservation,
                                                      workerUUID: exit.workerUUID)
        #expect(throws: (any Error).self) { try Checkpoint.validate(foreign) }
    }

    @Test(arguments: ["unacknowledged", "no-checkpoint", "mismatched-arm", "foreign-queue"])
    func claimRequiresAcknowledgedArmAndRealCheckpoint(_ scenario: String) throws {
        let q = try CheckpointQueueFixture(stage: "guest-accepted-before-prepare",
                                           publishCheckpoint: scenario != "no-checkpoint",
                                           acknowledge: scenario != "unacknowledged"); defer { q.remove() }
        let exit = try q.exit
        if scenario == "mismatched-arm" {
            // Structurally valid arm that this claim never accepted.
            var arm = exit.arm; arm.requestID = UUID().uuidString.lowercased()
            try q.put(Checkpoint.WorkerCheckpointExit(arm: arm, earlyCheckpoint: exit.earlyCheckpoint,
                                                      workerUUID: exit.workerUUID), ".checkpoint-worker-exit.json")
        } else {
            try q.put(exit, ".checkpoint-worker-exit.json")
        }
        let queue = scenario == "foreign-queue" ? try ManagedPrepareCompatibilityQueue(storeLock: q.lock) : q.queue
        #expect(throws: (any Error).self) { try queue.checkpointWorkerExit(q.claim) }
        #expect(!q.exists(".checkpoint-worker-exit.claimed.json"))
        #expect(!q.exists(".checkpoint-worker-wait.json"))
    }

    @Test(arguments: ["checkpoint-first", "storage-exit-first"])
    func crossRouteExclusionWithA4A5Flow(_ scenario: String) throws {
        let q = try CheckpointStorageQueueFixture(); defer { q.remove() }
        let f = q.vector
        if scenario == "checkpoint-first" {
            // A generic-route file merely present fences the A4/A5 claim.
            try q.put(q.exit, ".checkpoint-worker-exit.json")
            #expect(throws: (any Error).self) { try q.queue.storageWorkerExit(f.arm, claim: q.claim) }
            #expect(!q.exists(".storage-worker-exit.claimed.json"))
            // It stays unconsumed: a generic claim can never bind this A4/A5 arm.
            #expect(q.exists(".checkpoint-worker-exit.json"))
        } else {
            try q.put(f.exit, ".storage-worker-exit.json")
            #expect(try q.queue.storageWorkerExit(f.arm, claim: q.claim) == f.exit)
            try q.put(q.exit, ".checkpoint-worker-exit.json")
            // A4/A5 claimed first: the generic route must refuse to mix.
            #expect(throws: (any Error).self) { try q.queue.checkpointWorkerExit(q.claim) }
            #expect(!q.exists(".checkpoint-worker-exit.claimed.json"))
            #expect(!q.exists(".checkpoint-worker-wait.json"))
        }
    }
}

private struct CheckpointRow: Sendable {
    struct Vector: Decodable { var name: String; var arm: ManagedPrepareCompatibilityProtocol.Arm; var observationCanonical: String }
    let arm: ManagedPrepareCompatibilityProtocol.Arm
    let row: Vector
    init(stage: String) throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appending(path: "Guest/internal/preparecompat/testdata/full-vectors.json")
        let rows = try JSONDecoder().decode([Vector].self, from: Data(contentsOf: root))
        row = try #require(rows.first { $0.name == stage })
        arm = ManagedPrepareCompatibilityProtocol.normalized(row.arm)
    }
    var observation: ManagedPrepareCompatibilityProtocol.Observation {
        get throws { try ManagedPrepareCompatibilityProtocol.decode(ManagedPrepareCompatibilityProtocol.Observation.self,
                                                                    from: Data(row.observationCanonical.utf8)) }
    }
    var earlyObservation: ManagedPrepareCompatibilityProtocol.EarlyObservation {
        get throws { try ManagedPrepareCompatibilityProtocol.decode(ManagedPrepareCompatibilityProtocol.EarlyObservation.self,
                                                                    from: Data(row.observationCanonical.utf8)) }
    }
}

/// Guest-cut queue fixture: real capture/candidate/arm/armed plus the actual
/// published checkpoint, then the externally dropped checkpoint exit claim.
private final class CheckpointQueueFixture: @unchecked Sendable {
    typealias C = ManagedPrepareCompatibilityProtocol
    typealias Checkpoint = ManagedPrepareWorkerCheckpointProtocol
    let root: URL
    let lock: CanonicalDataStoreLock
    let queue: ManagedPrepareCompatibilityQueue
    let claim: ManagedPrepareCompatibilityQueue.Claim
    let row: CheckpointRow
    init(stage: String, publishCheckpoint: Bool = true, acknowledge: Bool = true) throws {
        row = try CheckpointRow(stage: stage)
        root = FileManager.default.temporaryDirectory.appending(path: "checkpoint-worker-exit-" + UUID().uuidString)
        lock = try CanonicalDataStoreLock(root: root)
        queue = try ManagedPrepareCompatibilityQueue(storeLock: lock)
        let directory = lock.root.appending(path: ManagedPrepareCompatibilityQueue.directoryName)
        func put(_ value: some Encodable, _ name: String) throws {
            let path = directory.appending(path: name)
            try C.canonicalData(value).write(to: path)
            #expect(chmod(path.path, 0o600) == 0)
        }
        let arm = row.arm
        let capture = C.Capture(version: 1, requestID: arm.requestID, container: arm.scope.container,
            containerInstance: arm.scope.containerInstance, specificationDigest: arm.scope.specificationDigest, mounts: arm.mounts)
        try put(capture, "capture.json")
        claim = try #require(try queue.capture(container: capture.container, instance: capture.containerInstance,
            digest: capture.specificationDigest, mounts: capture.mounts))
        let candidate = C.Candidate(version: 3, profile: C.fullProfile, requestID: arm.requestID, binding: arm.binding,
            scope: arm.scope, mounts: arm.mounts, slots: arm.slots, credentials: arm.credentials)
        try queue.candidate(candidate, claim: claim)
        try put(arm, arm.requestID + ".arm.json")
        _ = try #require(try queue.arm(claim, candidate: candidate))
        if acknowledge {
            try queue.armed(arm, claim: claim)
            if ManagedPrepareCompatibilityProtocol.isEarlyCase(arm.caseName) {
                if publishCheckpoint { try queue.checkpoint(try row.earlyObservation, arm: arm, claim: claim) }
            } else if publishCheckpoint {
                try queue.checkpoint(try row.observation, arm: arm, claim: claim)
            }
        }
    }
    var exit: ManagedPrepareWorkerCheckpointProtocol.WorkerCheckpointExit {
        get throws {
            let arm = row.arm
            if ManagedPrepareCompatibilityProtocol.isEarlyCase(arm.caseName) {
                return .init(arm: arm, earlyCheckpoint: try row.earlyObservation, workerUUID: arm.requestID)
            }
            return .init(arm: arm, checkpoint: try row.observation, workerUUID: arm.requestID)
        }
    }
    var wait: ManagedPrepareWorkerCheckpointProtocol.WorkerCheckpointWait {
        get throws {
            let value = try exit
            return .init(arm: value.arm, checkpoint: value.checkpoint, earlyCheckpoint: value.earlyCheckpoint,
                         storageCheckpoint: value.storageCheckpoint, workerUUID: value.workerUUID,
                         workerPID: 42, exitCode: 74, reaped: true)
        }
    }
    func path(_ suffix: String) -> URL { lock.root.appending(path: ManagedPrepareCompatibilityQueue.directoryName).appending(path: row.arm.requestID + suffix) }
    func write(_ bytes: Data, _ suffix: String) throws { try bytes.write(to: path(suffix)); #expect(chmod(path(suffix).path, 0o600) == 0) }
    func put(_ value: some Encodable, _ suffix: String) throws { try write(C.canonicalData(value), suffix) }
    func bytes(_ suffix: String) throws -> Data { try Data(contentsOf: path(suffix)) }
    func exists(_ suffix: String) -> Bool { FileManager.default.fileExists(atPath: path(suffix).path) }
    func remove() { try? FileManager.default.removeItem(at: root) }
}

/// A4/A5 storage vector fixture, mirroring WorkerExitQueueFixture, to prove
/// the two routes never mix on one claim. The dropped generic-route file holds
/// a canonical normal-cut claim: exclusion must fire on its mere presence,
/// since a generic claim can never bind this A4/A5 arm.
private final class CheckpointStorageQueueFixture: @unchecked Sendable {
    typealias C = ManagedPrepareCompatibilityProtocol
    typealias Checkpoint = ManagedPrepareWorkerCheckpointProtocol
    struct Vector {
        var arm: C.StorageArm
        var status: C.StorageStatus
        var exit: C.StorageRelease { .init(query: status.query, stage: arm.arm.caseName,
                                           token: status.observation!.admission!.releaseToken) }
    }
    let root: URL
    let lock: CanonicalDataStoreLock
    let queue: ManagedPrepareCompatibilityQueue
    let claim: ManagedPrepareCompatibilityQueue.Claim
    let vector: Vector
    init() throws {
        struct Row: Decodable { var storageArm: C.StorageArm?; var storageStatus: C.StorageStatus? }
        let path = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appending(path: "Guest/internal/preparecompat/testdata/full-vectors.json")
        let row = try #require(try JSONDecoder().decode([Row].self, from: Data(contentsOf: path))
            .first { $0.storageArm != nil && $0.storageStatus != nil })
        var arm = try #require(row.storageArm)
        arm.arm = C.normalized(arm.arm)
        vector = Vector(arm: arm, status: try #require(row.storageStatus))
        root = FileManager.default.temporaryDirectory.appending(path: "checkpoint-storage-exit-" + UUID().uuidString)
        lock = try CanonicalDataStoreLock(root: root)
        queue = try ManagedPrepareCompatibilityQueue(storeLock: lock)
        let directory = lock.root.appending(path: ManagedPrepareCompatibilityQueue.directoryName)
        func put(_ value: some Encodable, _ name: String) throws {
            let path = directory.appending(path: name)
            try C.canonicalData(value).write(to: path)
            #expect(chmod(path.path, 0o600) == 0)
        }
        let value = vector.arm.arm
        let capture = C.Capture(version: 1, requestID: value.requestID, container: value.scope.container,
            containerInstance: value.scope.containerInstance, specificationDigest: value.scope.specificationDigest, mounts: value.mounts)
        try put(capture, "capture.json")
        claim = try #require(try queue.capture(container: capture.container, instance: capture.containerInstance,
            digest: capture.specificationDigest, mounts: capture.mounts))
        let candidate = C.Candidate(version: 3, profile: C.fullProfile, requestID: value.requestID, binding: value.binding,
            scope: value.scope, mounts: value.mounts, slots: value.slots, credentials: value.credentials)
        try queue.candidate(candidate, claim: claim)
        try put(value, value.requestID + ".arm.json")
        _ = try #require(try queue.arm(claim, candidate: candidate))
        try queue.storageStatus(.init(query: vector.status.query, state: "armed"), arm: vector.arm, claim: claim)
        try queue.armed(value, claim: claim)
        try queue.storageStatus(vector.status, arm: vector.arm, claim: claim)
    }
    var exit: Checkpoint.WorkerCheckpointExit {
        get throws {
            let physical = try CheckpointRow(stage: "normal")
            return .init(arm: physical.arm, checkpoint: try physical.observation, workerUUID: physical.arm.requestID)
        }
    }
    func path(_ suffix: String) -> URL { lock.root.appending(path: ManagedPrepareCompatibilityQueue.directoryName).appending(path: vector.arm.arm.requestID + suffix) }
    func put(_ value: some Encodable, _ suffix: String) throws {
        let path = path(suffix)
        try C.canonicalData(value).write(to: path)
        #expect(chmod(path.path, 0o600) == 0)
    }
    func exists(_ suffix: String) -> Bool { FileManager.default.fileExists(atPath: path(suffix).path) }
    func remove() { try? FileManager.default.removeItem(at: root) }
}
#endif

import CEngineCore
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

/// Host-only real queue/observer checks. No VM, signed activation or drain inference.
@Suite struct ManagedPrepareVMRuntimeTests {
    typealias C = ManagedPrepareCompatibilityProtocol
    typealias Q = ManagedPrepareCompatibilityQueue
    static let stages = ["vm-private-bound", "vm-root-synced-before-cleanup", "vm-cleaning-transaction-removed"]
    struct Vector: Decodable {
        var name: String
        var arm: C.Arm
        var observationCanonical: String
        var storageStatus: C.StorageStatus?
    }
    func vector(_ name: String) throws -> Vector {
        // The standalone runner supplies an absolute scoped fixture path.
        let fallback = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appending(path: "Guest/internal/preparecompat/testdata/full-vectors.json").path
        let path = ProcessInfo.processInfo.environment["VM_RUNTIME_VECTORS"] ?? fallback
        return try #require(JSONDecoder().decode([Vector].self, from: Data(contentsOf: URL(fileURLWithPath: path))).first { $0.name == name })
    }
    func arm(_ stage: String) throws -> C.Arm {
        var arm = C.normalized(try vector("normal").arm)
        let slot = try #require(arm.slots.first { $0.attachment == arm.targetAttachment })
        arm.mounts = arm.mounts.filter { $0.volume == slot.volume }
        arm.slots = arm.slots.filter { $0.volume == slot.volume }
        arm.credentials = arm.credentials.filter { $0.attachment == arm.targetAttachment }
        arm.caseName = stage
        try C.validate(arm)
        return arm
    }
    func physical(_ arm: C.Arm) throws -> C.Observation {
        var value = try C.decode(C.Observation.self, from: Data(vector("normal").observationCanonical.utf8))
        value.armDigest = try C.digest(arm)
        value.stage = arm.caseName == "vm-root-synced-before-cleanup" ? arm.caseName : "first-child-published"
        return value
    }
    func storage(_ arm: C.StorageArm) throws -> C.StorageStatus {
        var status = try #require(vector("transaction-published-bind-reply-lost").storageStatus)
        status.query = try C.query(arm); status.state = "observed"
        status.retirementStarted = false; status.acceptedInFlight = 1
        status.lateAdmissionRejected = false; status.receiptReplayCount = 0
        status.observation!.stage = arm.arm.caseName
        status.observation!.armDigest = status.query.armDigest
        status.observation!.workerUUID = arm.workerUUID
        if arm.arm.caseName == Self.stages[2] {
            var intent = status.observation!.bound!.intent
            intent.phase = "CLEANING"; intent.manifestSize = 100
            intent.manifestDigest = String(repeating: "1", count: 64)
            intent.cleanup = intent.initial
            let next = max(intent.root.root.inode, intent.transaction.inode) + 1
            intent.cleanup.manifest = object(intent.transaction, inode: next, fileType: 32768)
            intent.cleanup.staging = object(intent.transaction, inode: next + 1, fileType: 16384)
            status.observation!.bound!.intent = intent
        }
        try C.validate(status, arm: arm)
        return status
    }
    func object(_ template: C.StorageObject, inode: UInt64, fileType: UInt32, generation: UInt32? = nil) -> C.StorageObject {
        var value = template
        value.inode = inode; value.fileType = fileType; value.generation = generation ?? template.generation
        value.handle = [UInt32(inode), value.generation].flatMap { word in
            (0..<4).map { String(format: "%02x", (word >> ($0 * 8)) & 255) }
        }.joined()
        return value
    }
    func put(_ value: some Encodable, at path: URL) throws {
        try C.canonicalData(value).write(to: path)
        #expect(chmod(path.path, 0o600) == 0)
    }
    func fixture(_ arm: C.Arm) throws -> (Q, Q.Claim, URL, CanonicalDataStoreLock) {
        let root = FileManager.default.temporaryDirectory.appending(path: "vm-runtime-" + UUID().uuidString)
        // Retained on purpose: this scoped check performs no filesystem cleanup.
        let lock = try CanonicalDataStoreLock(root: root), queue = try Q(storeLock: lock)
        let dir = root.appending(path: Q.directoryName)
        let capture = C.Capture(version: 1, requestID: arm.requestID, container: arm.scope.container,
            containerInstance: arm.scope.containerInstance, specificationDigest: arm.scope.specificationDigest, mounts: arm.mounts)
        try put(capture, at: dir.appending(path: "capture.json"))
        let claim = try #require(try queue.capture(container: capture.container, instance: capture.containerInstance,
            digest: capture.specificationDigest, mounts: capture.mounts))
        let candidate = C.Candidate(version: arm.version, profile: arm.profile, requestID: arm.requestID,
            binding: arm.binding, scope: arm.scope, mounts: arm.mounts, slots: arm.slots, credentials: arm.credentials)
        try queue.candidate(candidate, claim: claim)
        try put(arm, at: dir.appending(path: arm.requestID + ".arm.json"))
        #expect(try queue.arm(claim, candidate: candidate) == arm)
        return (queue, claim, dir, lock)
    }

    @Test func cleaningPhysicalWitnessRequiresExactFullProfileAndCase() throws {
        let selected = try arm(Self.stages[2])
        #expect(C.expectsPhysicalObservation(selected))
        for (profile, version) in [(C.profile, UInt32(1)), (C.earlyProfile, UInt32(2)), ("other", UInt32(3))] {
            var wrong = selected; wrong.profile = profile; wrong.version = version
            #expect(!C.expectsPhysicalObservation(wrong))
            #expect(throws: (any Error).self) { try C.validate(wrong) }
        }
        for stage in ["vm-private-bound", "VM-CLEANING-TRANSACTION-REMOVED", "vm-cleaning-transaction-removed-extra"] {
            var wrong = selected; wrong.caseName = stage
            #expect(!C.expectsPhysicalObservation(wrong))
        }
        let privateArm = try arm(Self.stages[0]), privateObservation = try physical(privateArm)
        #expect(throws: (any Error).self) { try C.validate(privateObservation, arm: privateArm) }
        let rootArm = try arm(Self.stages[1]), rootObservation = try physical(rootArm)
        #expect(C.expectsPhysicalObservation(rootArm))
        try C.validate(rootObservation, arm: rootArm)
        for stage in Self.stages { #expect(!C.allowsPrepareSuccess(try arm(stage))) }
    }

    @Test func cleaningSourceAtimesRoundTripWithoutPrepareSuccess() throws {
        let selected = try arm(Self.stages[2])
        var observation = try physical(selected)
        observation.sourceAtimes = .init(root: 0, a: 1, z: UInt64(Int64.max))
        #expect(observation.stage == "first-child-published")
        try C.validate(observation, arm: selected)
        let bytes = try C.canonicalData(observation)
        #expect(String(decoding: bytes, as: UTF8.self).contains(#""sourceAtimes":{"a":1,"root":0,"z":9223372036854775807}"#))
        #expect(try C.decode(C.Observation.self, from: bytes) == observation)
        let frame = WorkloadStorageProtocol.Frame(operation: .prepareCheckpoint, binding: selected.binding, scope: selected.scope,
            data: .init(compatibilityObservation: observation))
        let decoded = try WorkloadStorageProtocol.decode(from: Data(WorkloadStorageProtocol.encode(frame).dropFirst(4)))
        #expect(decoded == frame)
        try C.validateObservation(decoded, arm: selected)
        #expect(!C.allowsPrepareSuccess(selected))
        #expect(!PrivateWorkloadStorageCoordinator.allowsSuccessfulPrepare(selected, checkpoint: nil))
        #expect(!PrivateWorkloadStorageCoordinator.allowsSuccessfulPrepare(selected, checkpoint: decoded))
    }

    @Test(arguments: ["profile", "requestID", "armDigest", "stage", "root-stage", "caseName", "targetAttachment", "binding", "scope"])
    func cleaningObserverRejectsMismatchedWitnessWithoutConsumingPublication(_ mutation: String) throws {
        let selected = try arm(Self.stages[2]), observation = try physical(selected)
        let valid = WorkloadStorageProtocol.Frame(operation: .prepareCheckpoint, binding: selected.binding, scope: selected.scope,
            data: .init(compatibilityObservation: observation))
        var wrong = valid
        switch mutation {
        case "profile":
            wrong.data.compatibilityObservation?.profile = C.earlyProfile
            wrong.data.compatibilityObservation?.version = 2
        case "requestID": wrong.data.compatibilityObservation?.requestID = UUID().uuidString.lowercased()
        case "armDigest": wrong.data.compatibilityObservation?.armDigest = String(repeating: "f", count: 64)
        case "stage": wrong.data.compatibilityObservation?.stage = selected.caseName
        case "root-stage": wrong.data.compatibilityObservation?.stage = Self.stages[1]
        case "caseName":
            var other = selected; other.caseName = "first-child-published"
            wrong.data.compatibilityObservation?.armDigest = try C.digest(other)
        case "targetAttachment": wrong.data.compatibilityObservation?.targetAttachment = UUID().uuidString.lowercased()
        case "binding": wrong.binding.guestBootNonce = UUID().uuidString.lowercased()
        default: wrong.scope?.prepare = UUID().uuidString.lowercased()
        }
        #expect(throws: (any Error).self) { try C.validateObservation(wrong, arm: selected) }
        let observer = PrivatePrepareObservation()
        try observer.install(selected)
        #expect(throws: (any Error).self) { try observer.publish(wrong) }
        try observer.publish(valid)
        #expect(throws: (any Error).self) { try observer.publish(valid) }
        #expect(try observer.observe(selected) == valid)
        #expect(throws: (any Error).self) { try observer.observe(selected) }
        #expect(!observer.permitsTerminalOperation(.workloadStoragePrepareObservation))
    }

    @Test func cleaningRetainsIndependentPhysicalWitnessBeforeStorageHold() throws {
        let selected = try arm(Self.stages[2])
        let wrapped = C.StorageArm(arm: selected, workerUUID: selected.binding.guestBootNonce)
        let status = try storage(wrapped), observation = try physical(selected)
        let (queue, claim, dir, lock) = try fixture(selected)
        defer { withExtendedLifetime(lock) {} }
        try queue.storageStatus(.init(query: status.query, state: "armed"), arm: wrapped, claim: claim)
        try queue.armed(selected, claim: claim)
        let physicalPath = dir.appending(path: selected.requestID + ".checkpoint.json")
        let storagePath = dir.appending(path: selected.requestID + ".storage-checkpoint.json")
        let heldPath = dir.appending(path: selected.requestID + ".storage-held.json")
        try queue.checkpoint(observation, arm: selected, claim: claim)
        let retained = try Data(contentsOf: physicalPath)
        #expect(retained == (try C.canonicalData(observation)))
        #expect(!FileManager.default.fileExists(atPath: storagePath.path))
        #expect(!FileManager.default.fileExists(atPath: heldPath.path))
        try queue.storageStatus(status, arm: wrapped, claim: claim)
        #expect(try Data(contentsOf: physicalPath) == retained)
        #expect(try Data(contentsOf: storagePath) == C.canonicalData(status.observation!))
        #expect(try Data(contentsOf: heldPath) == C.canonicalData(status))
        #expect(throws: (any Error).self) { try queue.checkpoint(observation, arm: selected, claim: claim) }
        #expect(try queue.storageRelease(wrapped, claim: claim) == nil)
    }

    @Test(arguments: stages)
    func exactOwnedCheckpointNeverBecomesReleaseOrDrain(_ stage: String) throws {
        let arm = try arm(stage)
        let (queue, claim, dir, lock) = try fixture(arm)
        let foreign = try Q(storeLock: lock)
        #expect(throws: (any Error).self) { try foreign.armed(arm, claim: claim) }
        #expect(!C.allowsPrepareSuccess(arm))
        if stage == Self.stages[1] {
            let observation = try physical(arm)
            #expect(throws: (any Error).self) { try queue.checkpoint(observation, arm: arm, claim: claim) }
            try queue.armed(arm, claim: claim)
            var early = observation; early.stage = "first-child-published"
            #expect(throws: (any Error).self) { try queue.checkpoint(early, arm: arm, claim: claim) }
            var wrong = observation; wrong.armDigest = String(repeating: "f", count: 64)
            #expect(throws: (any Error).self) { try queue.checkpoint(wrong, arm: arm, claim: claim) }
            try queue.checkpoint(observation, arm: arm, claim: claim)
            #expect(throws: (any Error).self) { try queue.checkpoint(observation, arm: arm, claim: claim) }
            #expect(try Data(contentsOf: dir.appending(path: arm.requestID + ".checkpoint.json")) == C.canonicalData(observation))
        } else {
            let wrapped = C.StorageArm(arm: arm, workerUUID: arm.binding.guestBootNonce)
            let status = try storage(wrapped)
            #expect(throws: (any Error).self) { try queue.storageStatus(status, arm: wrapped, claim: claim) }
            try queue.storageStatus(.init(query: status.query, state: "armed"), arm: wrapped, claim: claim)
            #expect(throws: (any Error).self) { try queue.storageStatus(status, arm: wrapped, claim: claim) }
            try queue.armed(arm, claim: claim)
            var wrong = status; wrong.observation!.workerUUID = UUID().uuidString.lowercased()
            #expect(throws: (any Error).self) { try queue.storageStatus(wrong, arm: wrapped, claim: claim) }
            wrong = status; wrong.observation!.bound!.intent.owner.launch = UUID().uuidString.lowercased()
            #expect(throws: (any Error).self) { try queue.storageStatus(wrong, arm: wrapped, claim: claim) }
            try queue.storageStatus(status, arm: wrapped, claim: claim)
            // Same observation can be polled, but its first pinned checkpoint is immutable.
            try queue.storageStatus(status, arm: wrapped, claim: claim)
            wrong = status; wrong.observation!.bound!.requestSequence += 1
            #expect(throws: (any Error).self) { try queue.storageStatus(wrong, arm: wrapped, claim: claim) }
            for state in ["released", "finished"] {
                wrong = status; wrong.state = state
                #expect(throws: (any Error).self) { try queue.storageStatus(wrong, arm: wrapped, claim: claim) }
            }
            #expect(try queue.storageRelease(wrapped, claim: claim) == nil)
            #expect(try Data(contentsOf: dir.appending(path: arm.requestID + ".storage-checkpoint.json")) == C.canonicalData(status.observation!))
            #expect(!FileManager.default.fileExists(atPath: dir.appending(path: arm.requestID + ".storage-finished.json").path))
        }
    }

    // Reject before queue publication, then accept the valid status on the same claim.
    // Rejection after publication must also preserve the original checkpoint bytes.
    func rejectsWithoutPublishing(_ invalid: C.StorageStatus, valid: C.StorageStatus, arm: C.StorageArm) throws {
        #expect(throws: (any Error).self) { try C.validate(invalid) }
        #expect(throws: (any Error).self) { try C.validate(invalid, arm: arm) }
        let (queue, claim, dir, lock) = try fixture(arm.arm)
        defer { withExtendedLifetime(lock) {} }
        try queue.storageStatus(.init(query: valid.query, state: "armed"), arm: arm, claim: claim)
        try queue.armed(arm.arm, claim: claim)
        let path = dir.appending(path: arm.arm.requestID + ".storage-checkpoint.json")
        #expect(throws: (any Error).self) { try queue.storageStatus(invalid, arm: arm, claim: claim) }
        #expect(!FileManager.default.fileExists(atPath: path.path))
        let heldPath = dir.appending(path: arm.arm.requestID + ".storage-held.json")
        #expect(!FileManager.default.fileExists(atPath: heldPath.path))
        try queue.storageStatus(valid, arm: arm, claim: claim)
        let retained = try Data(contentsOf: path)
        let held = try Data(contentsOf: heldPath)
        #expect(held == (try C.canonicalData(valid)))
        #expect(retained == (try C.canonicalData(valid.observation!)))
        #expect(throws: (any Error).self) { try queue.storageStatus(invalid, arm: arm, claim: claim) }
        #expect(try Data(contentsOf: path) == retained)
        #expect(try Data(contentsOf: heldPath) == held)
        try queue.storageStatus(valid, arm: arm, claim: claim)
        #expect(try queue.storageRelease(arm, claim: claim) == nil)
        #expect(!FileManager.default.fileExists(atPath: dir.appending(path: arm.arm.requestID + ".storage-finished.json").path))
    }

    @Test(arguments: ["vm-private-bound", "vm-cleaning-transaction-removed"], ["zero", "retired", "zero-retired"])
    func observedStorageRequiresActiveHold(_ stage: String, _ mutation: String) throws {
        let selected = try arm(stage)
        let wrapped = C.StorageArm(arm: selected, workerUUID: selected.binding.guestBootNonce)
        let valid = try storage(wrapped)
        var invalid = valid
        if mutation.contains("zero") { invalid.acceptedInFlight = 0 }
        if mutation.contains("retired") { invalid.retirementStarted = true }
        try rejectsWithoutPublishing(invalid, valid: valid, arm: wrapped)
        var multiple = valid; multiple.acceptedInFlight = UInt32.max
        try C.validate(multiple, arm: wrapped) // Positive, not exactly one.
    }

    /// A valid count change is not an observation/authority change. Preserve the
    /// first published evidence, rather than rewriting it on subsequent polls.
    /// The real VM hook parks under authority.mu, so its captured count is stable;
    /// these synthetic repolls test the queue contract, not later guest admission.
    @Test(arguments: ["vm-private-bound", "vm-cleaning-transaction-removed"])
    func changedValidCountRepollPreservesFirstHeldEvidence(_ stage: String) throws {
        let selected = try arm(stage)
        let wrapped = C.StorageArm(arm: selected, workerUUID: selected.binding.guestBootNonce)
        let first = try storage(wrapped)
        let (queue, claim, dir, lock) = try fixture(selected)
        defer { withExtendedLifetime(lock) {} }
        try queue.storageStatus(.init(query: first.query, state: "armed"), arm: wrapped, claim: claim)
        try queue.armed(selected, claim: claim)
        try queue.storageStatus(first, arm: wrapped, claim: claim)
        let heldPath = dir.appending(path: selected.requestID + ".storage-held.json")
        let checkpointPath = dir.appending(path: selected.requestID + ".storage-checkpoint.json")
        let held = try Data(contentsOf: heldPath)
        let checkpoint = try Data(contentsOf: checkpointPath)
        #expect(held == (try C.canonicalData(first)))
        #expect(checkpoint == (try C.canonicalData(first.observation!)))
        for count: UInt32 in [2, .max, 1] {
            var repoll = first; repoll.acceptedInFlight = count
            try C.validate(repoll, arm: wrapped)
            try queue.storageStatus(repoll, arm: wrapped, claim: claim)
            #expect(try Data(contentsOf: heldPath) == held)
            #expect(try Data(contentsOf: checkpointPath) == checkpoint)
        }
        // A valid counter must not permit changed scope/checkpoint or lost hold.
        for mutation in ["query", "observation", "zero", "retired"] {
            var invalid = first; invalid.acceptedInFlight = 2
            if mutation == "query" { invalid.query.armDigest = String(repeating: "f", count: 64) }
            if mutation == "observation" { invalid.observation!.bound!.requestSequence += 1 }
            if mutation == "zero" { invalid.acceptedInFlight = 0 }
            if mutation == "retired" { invalid.retirementStarted = true }
            #expect(throws: (any Error).self) { try queue.storageStatus(invalid, arm: wrapped, claim: claim) }
            #expect(try Data(contentsOf: heldPath) == held)
            #expect(try Data(contentsOf: checkpointPath) == checkpoint)
        }
        try queue.storageStatus(first, arm: wrapped, claim: claim)
        #expect(try queue.storageRelease(wrapped, claim: claim) == nil)
        #expect(!FileManager.default.fileExists(atPath: dir.appending(path: selected.requestID + ".storage-finished.json").path))
        // Even replacement by otherwise valid status bytes is carrier tampering.
        var replacement = first; replacement.acceptedInFlight = 2
        try C.validate(replacement, arm: wrapped)
        try put(replacement, at: heldPath)
        #expect(throws: (any Error).self) { try queue.storageStatus(replacement, arm: wrapped, claim: claim) }
    }

    @Test(arguments: ["0-1", "0-2", "0-3", "1-2", "1-3", "2-3"], [false, true])
    func cleaningRequiresFourDistinctInodes(_ pair: String, _ differentGeneration: Bool) throws {
        let selected = try arm(Self.stages[2])
        let wrapped = C.StorageArm(arm: selected, workerUUID: selected.binding.guestBootNonce)
        let valid = try storage(wrapped)
        var invalid = valid, intent = valid.observation!.bound!.intent
        var objects = [intent.root.root, intent.transaction, intent.cleanup.manifest, intent.cleanup.staging]
        #expect(Set(objects.map(\.inode)).count == 4)
        let indexes = pair.split(separator: "-").map { Int($0)! }
        let source = objects[indexes[0]], target = objects[indexes[1]]
        // Keep each object's required type and internally consistent handle. Even a
        // different generation must not disguise a reused physical provenance inode.
        objects[indexes[1]] = object(target, inode: source.inode, fileType: target.fileType,
            generation: source.generation + (differentGeneration ? 1 : 0))
        intent.root.root = objects[0]; intent.transaction = objects[1]
        intent.cleanup.manifest = objects[2]; intent.cleanup.staging = objects[3]
        invalid.observation!.bound!.intent = intent
        #expect(throws: (any Error).self) { try C.validate(invalid.observation!) }
        try rejectsWithoutPublishing(invalid, valid: valid, arm: wrapped)
    }

    @Test func rootObserverIsOneShotExactAndCannotSurviveTerminalAsSuccess() throws {
        let arm = try arm(Self.stages[1]), observer = PrivatePrepareObservation()
        try observer.install(arm)
        var observation = try physical(arm)
        func frame(_ value: C.Observation) -> WorkloadStorageProtocol.Frame {
            .init(operation: .prepareCheckpoint, binding: arm.binding, scope: arm.scope,
                data: .init(compatibilityObservation: value))
        }
        observation.stage = "first-child-published"
        #expect(throws: (any Error).self) { try observer.publish(frame(observation)) }
        observation.stage = arm.caseName
        var wrong = frame(observation); wrong.binding.guestBootNonce = UUID().uuidString.lowercased()
        #expect(throws: (any Error).self) { try observer.publish(wrong) }
        try observer.publish(frame(observation))
        #expect(throws: (any Error).self) { try observer.publish(frame(observation)) }
        var wrongArm = arm; wrongArm.scope.launch = UUID().uuidString.lowercased()
        #expect(throws: (any Error).self) { try observer.observe(wrongArm) }
        #expect(try observer.observe(arm) == frame(observation))
        #expect(throws: (any Error).self) { try observer.observe(arm) }
        #expect(!observer.permitsTerminalOperation(.workloadStoragePrepareObservation))
        let ended = PrivatePrepareObservation(); try ended.install(arm)
        try ended.publish(frame(observation)); ended.finish()
        #expect(throws: (any Error).self) { try ended.observe(arm) }
        let lost = PrivatePrepareObservation(); try lost.install(arm); lost.finish()
        #expect(throws: (any Error).self) { try lost.observe(arm) }
        #expect(throws: (any Error).self) { try lost.publish(frame(observation)) }
    }

    @Test(arguments: ["vm-private-bound", "vm-cleaning-transaction-removed"])
    func storageCutsCannotBorrowRootPhasePhysicalObservation(_ stage: String) throws {
        let arm = try arm(stage), observer = PrivatePrepareObservation()
        try observer.install(arm)
        var observation = try physical(try self.arm(Self.stages[1]))
        observation.armDigest = try C.digest(arm)
        let frame = WorkloadStorageProtocol.Frame(operation: .prepareCheckpoint, binding: arm.binding, scope: arm.scope,
            data: .init(compatibilityObservation: observation))
        #expect(throws: (any Error).self) { try observer.publish(frame) }
        observer.finish()
        #expect(throws: (any Error).self) { try observer.observe(arm) }
    }
}

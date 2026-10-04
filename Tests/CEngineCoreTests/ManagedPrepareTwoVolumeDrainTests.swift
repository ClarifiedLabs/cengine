import CEngineCore
import Foundation
import Testing
@testable import CEngineRuntime

/// Host carrier/queue evidence only; these tests do not prove a guest durable commit.
extension ManagedPrepareVMRuntimeTests {
    func twoVolumeArm() throws -> C.Arm {
        var value = C.normalized(try vector("normal").arm)
        value.caseName = C.twoVolumeDrainReplyGap
        for index in value.mounts.indices { value.mounts[index].mode = .readWrite; value.mounts[index].noCopy = false }
        for index in value.slots.indices { value.slots[index].mode = .readWrite }
        try C.validate(value)
        return value
    }
    func twoVolumeHeld(_ arm: C.StorageArm) throws -> C.StorageStatus {
        var value = try #require(vector("drain-durable-reply-lost").storageStatus)
        value.query = try C.query(arm); value.state = "held"; value.retirementStarted = true
        value.observation!.stage = arm.arm.caseName
        value.observation!.armDigest = value.query.armDigest
        try C.validate(value, arm: arm)
        return value
    }

    @Test(arguments: ["one-volume", "three-mounts", "missing-slot", "missing-credential", "readonly", "nocopy", "subpath", "same-destination", "early", "legacy"])
    func twoVolumeArmIsExact(_ mutation: String) throws {
        var value = try twoVolumeArm()
        switch mutation {
        case "one-volume":
            let volume = value.mounts[0].volume
            value.mounts = [value.mounts[0]]; value.slots.removeAll { $0.volume != volume }
            value.credentials.removeAll { $0.attachment != value.targetAttachment }
        case "three-mounts": var mount = value.mounts[0]; mount.index = 3; value.mounts.append(mount)
        case "missing-slot": value.slots.removeLast()
        case "missing-credential": value.credentials.removeLast()
        case "readonly": value.mounts[1].mode = .readOnly
        case "nocopy": value.mounts[1].noCopy = true
        case "subpath": value.mounts[1].subpath = "child"
        case "same-destination": value.mounts[1].destination = value.mounts[0].destination
        case "early": value.profile = C.earlyProfile; value.version = 2
        default: value.profile = C.profile; value.version = 1
        }
        #expect(throws: (any Error).self) { try C.validate(value) }
    }

    @Test func twoVolumeReturningPhysicalObservationIsRequestBound() throws {
        let arm = try twoVolumeArm()
        #expect(C.allowsPrepareSuccess(arm)); #expect(C.expectsPhysicalObservation(arm))
        var observation = try C.decode(C.Observation.self, from: Data(vector("normal").observationCanonical.utf8))
        observation.armDigest = try C.digest(arm)
        try C.validate(observation, arm: arm)
        let frame = WorkloadStorageProtocol.Frame(operation: .prepareCheckpoint, binding: arm.binding,
            scope: arm.scope, data: .init(compatibilityObservation: observation))
        let observer = PrivatePrepareObservation(); try observer.install(arm)
        var wrong = arm; wrong.requestID = UUID().uuidString.lowercased()
        #expect(throws: (any Error).self) { try observer.observe(wrong) }
        try observer.publish(frame)
        #expect(try observer.observe(arm) == frame)
        #expect(throws: (any Error).self) { try observer.observe(arm) }
        #expect(!observer.permitsTerminalOperation(.workloadStoragePrepareObservation))
        observation.stage = arm.caseName
        #expect(throws: (any Error).self) { try C.validate(observation, arm: arm) }
    }

    @Test(arguments: ["observed", "released", "finished", "not-retired", "inflight", "replay", "late", "missing-drain", "revision", "schema", "attachment"])
    func twoVolumeHeldNeverPromotesToSuccess(_ mutation: String) throws {
        let selected = try twoVolumeArm(), arm = C.StorageArm(arm: selected, workerUUID: selected.binding.guestBootNonce)
        let valid = try twoVolumeHeld(arm)
        var invalid = valid
        switch mutation {
        case "observed", "released", "finished": invalid.state = mutation
        case "not-retired": invalid.retirementStarted = false
        case "inflight": invalid.acceptedInFlight = 1
        case "replay": invalid.receiptReplayCount = 1
        case "late": invalid.lateAdmissionRejected = true
        case "missing-drain": invalid.observation!.drain = nil
        case "revision": invalid.observation!.drain!.receipt.revision = 0
        case "schema": invalid.observation!.drain!.receipt.schema = 1
        default: invalid.observation!.drain!.receipt.attachment = UUID().uuidString.lowercased()
        }
        try rejectsWithoutPublishing(invalid, valid: valid, arm: arm)
    }

    @Test(arguments: ["worker", "request", "digest", "store", "volume", "prepare", "revision", "operation"])
    func twoVolumeHeldBindsAndPinsOldReceipt(_ mutation: String) throws {
        let selected = try twoVolumeArm(), arm = C.StorageArm(arm: selected, workerUUID: selected.binding.guestBootNonce)
        let held = try twoVolumeHeld(arm), (queue, claim, dir, lock) = try fixture(selected)
        defer { withExtendedLifetime(lock) {} }
        try queue.storageStatus(.init(query: held.query, state: "armed"), arm: arm, claim: claim)
        try queue.armed(selected, claim: claim)
        try queue.storageStatus(held, arm: arm, claim: claim)
        var changed = held
        let other = UUID().uuidString.lowercased()
        switch mutation {
        case "worker": changed.query.workerUUID = other; changed.observation!.workerUUID = other
        case "request": changed.query.requestID = other; changed.observation!.requestID = other
        case "digest": changed.query.armDigest = String(repeating: "0", count: 64); changed.observation!.armDigest = changed.query.armDigest
        case "store": changed.observation!.drain!.receipt.store = other
        case "volume": changed.observation!.drain!.receipt.volume = other
        case "prepare": changed.observation!.drain!.receipt.prepare = other
        case "revision": changed.observation!.drain!.receipt.revision -= 1
        default: changed.observation!.drain!.retireOperation = other
        }
        #expect(throws: (any Error).self) { try queue.storageStatus(changed, arm: arm, claim: claim) }
        try queue.storageStatus(held, arm: arm, claim: claim)
        #expect(try Data(contentsOf: dir.appending(path: selected.requestID + ".storage-held.json")) == C.canonicalData(held))
        #expect(try queue.storageRelease(arm, claim: claim) == nil)
        #expect(!FileManager.default.fileExists(atPath: dir.appending(path: selected.requestID + ".storage-finished.json").path))
        #expect(throws: (any Error).self) { try C.validate(C.StorageRelease(query: held.query, stage: selected.caseName, token: String(repeating: "a", count: 64))) }
    }

    @Test(arguments: stages)
    func twoVolumeCaseDoesNotRelaxExistingVMArms(_ stage: String) throws {
        var value = try twoVolumeArm(); value.caseName = stage
        #expect(throws: (any Error).self) { try C.validate(value) }
    }

    @Test(arguments: ["drain-durable-reply-lost", "vm-private-bound", "vm-cleaning-transaction-removed"])
    func heldStateIsExclusiveToTwoVolumeCase(_ stage: String) throws {
        var status: C.StorageStatus
        if stage == "drain-durable-reply-lost" { status = try #require(vector(stage).storageStatus) }
        else { let selected = try arm(stage); status = try storage(.init(arm: selected, workerUUID: selected.binding.guestBootNonce)) }
        status.state = "held"
        #expect(throws: (any Error).self) { try C.validate(status) }
    }
}

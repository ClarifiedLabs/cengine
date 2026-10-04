#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

@Suite struct ManagedPrepareWorkerExitTests {
    typealias C = ManagedPrepareCompatibilityProtocol
    typealias B = StorageLifecycleServiceBootProtocol

    @Test func requiredWaitFieldsAndStrictCodec() throws {
        let f = try WorkerExitVector.load()
        let wait = f.wait
        let bytes = try C.canonicalData(wait)
        #expect(try C.decodeStorageWorkerWait(from: bytes) == wait)
        try C.validate(wait, arm: f.arm, checkpoint: f.status)
        let object = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        #expect(Set(object.keys) == ["query", "stage", "token", "requestSequence", "workerPID", "exitCode", "reaped"])
        for field in object.keys {
            var missing = object; missing.removeValue(forKey: field)
            var null = object; null[field] = NSNull()
            for changed in [missing, null] {
                let data = try JSONSerialization.data(withJSONObject: changed, options: [.sortedKeys, .withoutEscapingSlashes])
                #expect(throws: (any Error).self) { try C.decodeStorageWorkerWait(from: data) }
                var reply = try #require(JSONSerialization.jsonObject(with: Data(B.encode(f.reply).dropFirst(4))) as? [String: Any])
                reply["prepareCompatibilityWorkerWait"] = changed
                #expect(throws: (any Error).self) { try B.decode(JSONSerialization.data(withJSONObject: reply)) }
            }
        }
        let text = String(decoding: bytes, as: UTF8.self)
        for replacement in ["\"workerPID\":0", "\"workerPID\":1", "\"workerPID\":2147483648", "\"workerPID\":4294967296",
                            "\"workerPID\":2.0", "\"workerPID\":2e0", "\"workerPID\":-2", "\"workerPID\":true",
                            "\"workerPID\":2,\"workerPID\":2", "\"workerPID\":2,\"worker\\u0050ID\":2", "\"workerPID\":2,\"invented\":2"] {
            let changed = text.replacingOccurrences(of: "\"workerPID\":2", with: replacement)
            #expect(changed != text)
            #expect(throws: (any Error).self) { try C.decodeStorageWorkerWait(from: Data(changed.utf8)) }
        }
        for suffix in [" ", "{}"] {
            #expect(throws: (any Error).self) { try C.decodeStorageWorkerWait(from: bytes + Data(suffix.utf8)) }
        }
        var changed = wait; changed.requestSequence = UInt64.max; changed.workerPID = UInt32(Int32.max)
        #expect(try C.decodeStorageWorkerWait(from: C.canonicalData(changed)) == changed)
    }

    @Test func waitRejectsInvalidAndMismatchedProjection() throws {
        let f = try WorkerExitVector.load()
        var invalid: [C.StorageWorkerWait] = []
        var value = f.wait; value.stage = "transaction-published-bind-reply-lost"; invalid.append(value)
        value = f.wait; value.token = "not-a-pin"; invalid.append(value)
        value = f.wait; value.requestSequence = 0; invalid.append(value)
        value = f.wait; value.exitCode = 0; invalid.append(value)
        value = f.wait; value.exitCode = 137; invalid.append(value)
        value = f.wait; value.reaped = false; invalid.append(value)
        value = f.wait; value.query.profile = C.earlyProfile; invalid.append(value)
        value = f.wait; value.query.version = 2; invalid.append(value)
        for wait in invalid {
            #expect(throws: (any Error).self) { try C.validate(wait) }
            #expect(throws: (any Error).self) { try C.decodeStorageWorkerWait(from: C.canonicalData(wait)) }
            var reply = f.reply; reply.prepareCompatibilityWorkerWait = wait
            #expect(throws: (any Error).self) { try B.encode(reply) }
        }
        var mismatches: [C.StorageWorkerWait] = []
        value = f.wait; value.stage = "full-frame-before-admit"; mismatches.append(value)
        value = f.wait; value.query.workerUUID = UUID().uuidString.lowercased(); mismatches.append(value)
        value = f.wait; value.query.requestID = UUID().uuidString.lowercased(); mismatches.append(value)
        value = f.wait; value.query.armDigest = String(repeating: "f", count: 64); mismatches.append(value)
        value = f.wait; value.token = String(repeating: "f", count: 64); mismatches.append(value)
        value = f.wait; value.requestSequence += 1; mismatches.append(value)
        for wait in mismatches {
            try C.validate(wait) // Structurally valid is not bound evidence.
            #expect(throws: (any Error).self) { try C.validate(wait, arm: f.arm, checkpoint: f.status) }
        }
    }

    @Test func actualPreRetirementA5CountIsNotAnAdmissionPredicate() throws {
        let f = try WorkerExitVector.load()
        #expect(f.status.acceptedInFlight == 0)
        try C.validateStorageWorkerExit(f.exit, arm: f.arm, checkpoint: f.status)
        var unadmitted = f.status; unadmitted.observation!.admission!.admitted = false
        #expect(throws: (any Error).self) { try C.validateStorageWorkerExit(f.exit, arm: f.arm, checkpoint: unadmitted) }
        var unsequenced = f.status; unsequenced.observation!.admission!.requestSequence = 0
        #expect(throws: (any Error).self) { try C.validateStorageWorkerExit(f.exit, arm: f.arm, checkpoint: unsequenced) }
    }

    @Test func beforeAdmissionRequiresUnadmittedEmptyCut() throws {
        let f = try WorkerExitVector.load(stage: "full-frame-before-admit")
        try C.validateStorageWorkerExit(f.exit, arm: f.arm, checkpoint: f.status)
        #expect(try B.decode(Data(B.encode(f.command).dropFirst(4))) == f.command)
        #expect(try B.decode(Data(B.encode(f.reply).dropFirst(4))) == f.reply)
        for kind in ["admitted", "accepted", "retired", "stage"] {
            var status = f.status
            if kind == "admitted" { status.observation!.admission!.admitted = true }
            if kind == "accepted" { status.acceptedInFlight = 1 }
            if kind == "retired" { status.retirementStarted = true }
            if kind == "stage" { status.observation!.stage = "admitted-queued" }
            #expect(throws: (any Error).self) { try C.validateStorageWorkerExit(f.exit, arm: f.arm, checkpoint: status) }
        }
        var wrong = f.wait; wrong.stage = "admitted-queued"
        #expect(throws: (any Error).self) { try C.validate(wrong, arm: f.arm, checkpoint: f.status) }
    }

    @Test func closedBootCommandAndReplyUnions() throws {
        let f = try WorkerExitVector.load()
        #expect(try B.decode(Data(B.encode(f.command).dropFirst(4))) == f.command)
        #expect(try B.decode(Data(B.encode(f.reply).dropFirst(4))) == f.reply)
        var commands: [B.Frame] = []
        var command = f.command; command.prepareCompatibilityWorkerExit = nil; commands.append(command)
        command = f.command; command.prepareCompatibilityRelease = f.exit; commands.append(command)
        command = f.command; command.prepareCompatibilityArm = f.arm; commands.append(command)
        command = f.command; command.prepareCompatibilityQuery = f.exit.query; commands.append(command)
        command = f.command; command.workerUUID = UUID().uuidString.lowercased(); commands.append(command)
        command = f.command; command.command = .query; commands.append(command)
        command = f.command; command.prepareCompatibilityWorkerExit!.stage = "transaction-published-bind-reply-lost"; commands.append(command)
        for value in commands { #expect(throws: (any Error).self) { try B.encode(value) } }
        var replies: [B.Frame] = []
        var reply = f.reply; reply.code = .command; replies.append(reply)
        reply = f.reply; reply.prepareCompatibilityStatus = f.status; replies.append(reply)
        reply = f.reply; reply.notifications = []; replies.append(reply)
        reply = f.reply; reply.status = .init(phase: .workerLost); replies.append(reply)
        for value in replies { #expect(throws: (any Error).self) { try B.encode(value) } }
    }

    @Test(arguments: ["full-frame-before-admit", "admitted-queued"])
    func consumedActionAndWaitAreExactOneShotOwnedFiles(_ stage: String) throws {
        let q = try WorkerExitQueueFixture(stage: stage); defer { q.remove() }
        let f = q.vector
        #expect(try q.queue.storageWorkerExit(f.arm, claim: q.claim) == nil)
        #expect(throws: (any Error).self) { try q.queue.storageWorkerWait(f.wait, arm: f.arm, claim: q.claim) }
        try q.put(f.exit, ".storage-worker-exit.json")
        #expect(try q.queue.storageWorkerExit(f.arm, claim: q.claim) == f.exit)
        #expect(!q.exists(".storage-worker-exit.json"))
        #expect(try q.bytes(".storage-worker-exit.claimed.json") == C.canonicalData(f.exit))
        #expect(try q.queue.storageWorkerExit(f.arm, claim: q.claim) == nil)
        #expect(try q.queue.storageRelease(f.arm, claim: q.claim) == nil)
        var mismatch = f.wait; mismatch.requestSequence += 1
        #expect(throws: (any Error).self) { try q.queue.storageWorkerWait(mismatch, arm: f.arm, claim: q.claim) }
        #expect(!q.exists(".storage-worker-wait.json"))
        try q.queue.storageWorkerWait(f.wait, arm: f.arm, claim: q.claim)
        #expect(try q.bytes(".storage-worker-wait.json") == C.canonicalData(f.wait))
        #expect(throws: (any Error).self) { try q.queue.storageWorkerWait(f.wait, arm: f.arm, claim: q.claim) }
        #expect(throws: (any Error).self) { try q.queue.storageStatus(f.status, arm: f.arm, claim: q.claim) }
    }

    @Test(arguments: ["early", "retired", "wrong-token", "release", "claimed-release", "replayed-claim", "noncanonical", "foreign-queue"])
    func queueRefusesUnownedOrIneligibleAction(_ scenario: String) throws {
        let q = try WorkerExitQueueFixture(observe: scenario != "early"); defer { q.remove() }
        let f = q.vector
        var exit = f.exit
        if scenario == "retired" {
            var status = f.status
            status.retirementStarted = true; status.acceptedInFlight = 1
            try q.queue.storageStatus(status, arm: f.arm, claim: q.claim)
        }
        if scenario == "wrong-token" { exit.token = String(repeating: "f", count: 64) }
        if scenario == "release" { try q.put(exit, ".storage-release.json") }
        if scenario == "claimed-release" { try q.put(exit, ".storage-release.claimed.json") }
        if scenario == "replayed-claim" { try q.put(exit, ".storage-worker-exit.claimed.json") }
        try q.put(exit, ".storage-worker-exit.json")
        if scenario == "noncanonical" { try q.write(try C.canonicalData(exit) + Data([32]), ".storage-worker-exit.json") }
        let queue = scenario == "foreign-queue" ? try ManagedPrepareCompatibilityQueue(storeLock: q.lock) : q.queue
        #expect(throws: (any Error).self) { try queue.storageWorkerExit(f.arm, claim: q.claim) }
        #expect(!q.exists(".storage-worker-wait.json"))
    }

    @Test(arguments: ["action-bytes", "action-inode", "checkpoint", "arm", "late-release", "replay-request"])
    func retainedDescriptorsAndFrozenBytesFencePublication(_ scenario: String) throws {
        let q = try WorkerExitQueueFixture(); defer { q.remove() }
        let f = q.vector
        try q.put(f.exit, ".storage-worker-exit.json")
        _ = try #require(try q.queue.storageWorkerExit(f.arm, claim: q.claim))
        switch scenario {
        case "action-bytes": try q.write(Data([32]), ".storage-worker-exit.claimed.json")
        case "action-inode":
            try FileManager.default.removeItem(at: q.path(".storage-worker-exit.claimed.json"))
            try q.put(f.exit, ".storage-worker-exit.claimed.json")
        case "checkpoint": try q.write(Data([32]), ".storage-checkpoint.json")
        case "arm": try q.write(Data([32]), ".arm.claimed.json")
        case "late-release": try q.put(f.exit, ".storage-release.json")
        default: try q.put(f.exit, ".storage-worker-exit.json")
        }
        #expect(throws: (any Error).self) { try q.queue.storageWorkerWait(f.wait, arm: f.arm, claim: q.claim) }
        #expect(!q.exists(".storage-worker-wait.json"))
    }

    @Test func consumedReleaseCannotBeReusedAsWorkerExit() throws {
        let q = try WorkerExitQueueFixture(); defer { q.remove() }
        let f = q.vector
        var retired = f.status; retired.retirementStarted = true; retired.acceptedInFlight = 1
        try q.queue.storageStatus(retired, arm: f.arm, claim: q.claim)
        try q.put(f.exit, ".storage-release.json")
        #expect(try q.queue.storageRelease(f.arm, claim: q.claim) == f.exit)
        try q.put(f.exit, ".storage-worker-exit.json")
        #expect(throws: (any Error).self) { try q.queue.storageWorkerExit(f.arm, claim: q.claim) }
        #expect(!q.exists(".storage-worker-exit.claimed.json"))
        #expect(!q.exists(".storage-worker-wait.json"))
    }

    @Test(arguments: ["full-frame-before-admit", "admitted-queued"], [true, false])
    func pumpSelectorReleasesPendingThroughFinished(_ stage: String, _ workerExitAllowed: Bool) throws {
        let q = try WorkerExitQueueFixture(stage: stage); defer { q.remove() }
        let f = q.vector
        #expect(try q.queue.storageAction(f.arm, claim: q.claim, workerExitAllowed: workerExitAllowed) == nil)
        var pending = f.status; pending.retirementStarted = true
        pending.acceptedInFlight = stage == "admitted-queued" ? 1 : 0
        try q.queue.storageStatus(pending, arm: f.arm, claim: q.claim)
        #expect(q.exists(".storage-pending.json"))
        #expect(try q.queue.storageAction(f.arm, claim: q.claim, workerExitAllowed: workerExitAllowed) == nil)
        try q.put(f.exit, ".storage-release.json")
        // The strict API must still reject the release, even with no exit file.
        #expect(throws: (any Error).self) { try q.queue.storageWorkerExit(f.arm, claim: q.claim) }
        #expect(try q.queue.storageAction(f.arm, claim: q.claim, workerExitAllowed: workerExitAllowed) == .release(f.exit))
        #expect(try q.bytes(".storage-release.claimed.json") == C.canonicalData(f.exit))
        #expect(!q.exists(".storage-release.json"))
        #expect(!q.exists(".storage-worker-exit.claimed.json"))
        #expect(try q.queue.storageAction(f.arm, claim: q.claim, workerExitAllowed: true) == nil)
        var released = pending; released.state = "released"
        try q.queue.storageStatus(released, arm: f.arm, claim: q.claim)
        #expect(try q.queue.storageAction(f.arm, claim: q.claim, workerExitAllowed: true) == nil)
        var finished = released; finished.state = "finished"; finished.acceptedInFlight = 0
        finished.lateAdmissionRejected = stage == "full-frame-before-admit"
        try q.queue.storageStatus(finished, arm: f.arm, claim: q.claim)
        #expect(q.exists(".storage-finished.json"))
        #expect(try q.queue.storageAction(f.arm, claim: q.claim, workerExitAllowed: true) == nil)
    }

    @Test(arguments: ["release-first", "exit-first"], [true, false])
    func pumpSelectorRejectsBothRequestsInEitherPublicationOrder(_ order: String, _ workerExitAllowed: Bool) throws {
        let q = try WorkerExitQueueFixture(); defer { q.remove() }
        let f = q.vector
        var pending = f.status; pending.retirementStarted = true; pending.acceptedInFlight = 1
        try q.queue.storageStatus(pending, arm: f.arm, claim: q.claim)
        let suffixes = [".storage-release.json", ".storage-worker-exit.json"]
        for suffix in order == "release-first" ? suffixes : Array(suffixes.reversed()) { try q.put(f.exit, suffix) }
        #expect(throws: (any Error).self) {
            try q.queue.storageAction(f.arm, claim: q.claim, workerExitAllowed: workerExitAllowed)
        }
        #expect(q.exists(".storage-release.json") && q.exists(".storage-worker-exit.json"))
        #expect(!q.exists(".storage-release.claimed.json") && !q.exists(".storage-worker-exit.claimed.json"))
    }

    @Test(arguments: ["release-first", "exit-first"])
    func pumpSelectorRejectsLateCompetingRouteAfterClaim(_ order: String) throws {
        let q = try WorkerExitQueueFixture(); defer { q.remove() }
        let f = q.vector
        if order == "release-first" {
            var pending = f.status; pending.retirementStarted = true; pending.acceptedInFlight = 1
            try q.queue.storageStatus(pending, arm: f.arm, claim: q.claim)
            try q.put(f.exit, ".storage-release.json")
            #expect(try q.queue.storageAction(f.arm, claim: q.claim, workerExitAllowed: true) == .release(f.exit))
            try q.put(f.exit, ".storage-worker-exit.json")
        } else {
            try q.put(f.exit, ".storage-worker-exit.json")
            #expect(try q.queue.storageAction(f.arm, claim: q.claim, workerExitAllowed: true) == .workerExit(f.exit))
            #expect(try q.queue.storageAction(f.arm, claim: q.claim, workerExitAllowed: true) == nil)
            try q.put(f.exit, ".storage-release.json")
        }
        #expect(throws: (any Error).self) { try q.queue.storageAction(f.arm, claim: q.claim, workerExitAllowed: true) }
        #expect(!q.exists(".storage-worker-wait.json"))
    }

    @Test(arguments: [".checkpoint-worker-exit.json", ".checkpoint-worker-exit.claimed.json", ".checkpoint-worker-wait.json",
                      ".storage-release.claimed.json", ".storage-worker-exit.claimed.json", ".storage-worker-wait.json"])
    func pumpSelectorRejectsGenericAndUnownedClaimedRoutes(_ suffix: String) throws {
        let q = try WorkerExitQueueFixture(); defer { q.remove() }
        let f = q.vector
        try q.put(f.exit, suffix)
        #expect(throws: (any Error).self) { try q.queue.storageAction(f.arm, claim: q.claim, workerExitAllowed: true) }
    }

    @Test(arguments: ["full-frame-before-admit", "admitted-queued"])
    func pumpSelectorRespectsExitWindowAndOneShotClaim(_ stage: String) throws {
        let q = try WorkerExitQueueFixture(stage: stage); defer { q.remove() }
        let f = q.vector
        try q.put(f.exit, ".storage-worker-exit.json")
        #expect(try q.queue.storageAction(f.arm, claim: q.claim, workerExitAllowed: false) == nil)
        #expect(q.exists(".storage-worker-exit.json"))
        #expect(try q.queue.storageAction(f.arm, claim: q.claim, workerExitAllowed: true) == .workerExit(f.exit))
        #expect(try q.queue.storageAction(f.arm, claim: q.claim, workerExitAllowed: true) == nil)
        try q.queue.storageWorkerWait(f.wait, arm: f.arm, claim: q.claim)
        #expect(q.exists(".storage-worker-wait.json"))
        #expect(!q.exists(".storage-release.claimed.json"))
    }

    @Test(arguments: ["release", "worker-exit"])
    func cancelledPumpSelectorLeavesEitherRequestUnconsumed(_ route: String) async throws {
        let q = try WorkerExitQueueFixture(); defer { q.remove() }
        let f = q.vector
        if route == "release" {
            var pending = f.status; pending.retirementStarted = true; pending.acceptedInFlight = 1
            try q.queue.storageStatus(pending, arm: f.arm, claim: q.claim)
        }
        let suffix = ".storage-" + route
        try q.put(f.exit, suffix + ".json")
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            #expect(throws: CancellationError.self) { try q.queue.storageAction(f.arm, claim: q.claim, workerExitAllowed: true) }
        }
        await task.value
        #expect(q.exists(suffix + ".json"))
        #expect(!q.exists(suffix + ".claimed.json"))
    }

    @Test func cancellationBeforeClaimLeavesExternalRequestUnconsumed() async throws {
        let q = try WorkerExitQueueFixture(); defer { q.remove() }
        let f = q.vector
        try q.put(f.exit, ".storage-worker-exit.json")
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            #expect(throws: CancellationError.self) { try q.queue.storageWorkerExit(f.arm, claim: q.claim) }
        }
        await task.value
        #expect(q.exists(".storage-worker-exit.json"))
        #expect(!q.exists(".storage-worker-exit.claimed.json"))
        #expect(!q.exists(".storage-worker-wait.json"))
    }

    @Test func cancellationDoesNotPublishWaitOrReleaseConsumedAction() async throws {
        let q = try WorkerExitQueueFixture(); defer { q.remove() }
        let f = q.vector
        try q.put(f.exit, ".storage-worker-exit.json")
        _ = try #require(try q.queue.storageWorkerExit(f.arm, claim: q.claim))
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            #expect(throws: CancellationError.self) { try q.queue.storageWorkerWait(f.wait, arm: f.arm, claim: q.claim) }
        }
        await task.value
        #expect(q.exists(".storage-worker-exit.claimed.json"))
        #expect(!q.exists(".storage-worker-wait.json"))
        #expect(try q.queue.storageWorkerExit(f.arm, claim: q.claim) == nil)
        #expect(try q.queue.storageRelease(f.arm, claim: q.claim) == nil)
    }
}

// Shared engine-free data fixture; no owner or PID1 authority is manufactured.
struct WorkerExitVector: Sendable {
    typealias C = ManagedPrepareCompatibilityProtocol
    typealias B = StorageLifecycleServiceBootProtocol
    var arm: C.StorageArm
    var status: C.StorageStatus
    var exit: C.StorageRelease {
        .init(query: status.query, stage: arm.arm.caseName, token: status.observation!.admission!.releaseToken)
    }
    var wait: C.StorageWorkerWait {
        .init(query: exit.query, stage: exit.stage, token: exit.token,
              requestSequence: status.observation!.admission!.requestSequence, workerPID: 2, exitCode: 74, reaped: true)
    }
    var binding: DiskInitializationProtocol.Binding {
        .init(shimLaunchUUID: arm.arm.binding.shimLaunchUUID, guestBootNonce: arm.arm.binding.guestBootNonce,
              ext4UUID: arm.arm.scope.store, bytes: 16 << 20)
    }
    var command: B.Frame {
        .init(operation: .command, binding: binding, sequence: 1, serviceEpoch: arm.arm.scope.serviceEpoch,
              command: .prepareCompatibilityWorkerExit, workerUUID: arm.workerUUID, prepareCompatibilityWorkerExit: exit)
    }
    var reply: B.Frame { .init(operation: .reply, binding: binding, sequence: 1, serviceEpoch: arm.arm.scope.serviceEpoch, workerUUID: arm.workerUUID, prepareCompatibilityWorkerWait: wait) }
    static func load(stage: String = "admitted-queued") throws -> Self {
        struct Vector: Decodable { var name: String; var storageArm: C.StorageArm?; var storageStatus: C.StorageStatus? }
        let path = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appending(path: "Guest/internal/preparecompat/testdata/full-vectors.json")
        let vector = try #require(JSONDecoder().decode([Vector].self, from: Data(contentsOf: path)).first { $0.name == stage })
        var arm = try #require(vector.storageArm)
        let status = try #require(vector.storageStatus)
        arm.arm = C.normalized(arm.arm)
        #expect(status.state == "observed" && !status.retirementStarted && status.acceptedInFlight == 0)
        try C.validate(status, arm: arm)
        return Self(arm: arm, status: status)
    }
}

private final class WorkerExitQueueFixture: @unchecked Sendable {
    typealias C = ManagedPrepareCompatibilityProtocol
    let root: URL
    let lock: CanonicalDataStoreLock
    let queue: ManagedPrepareCompatibilityQueue
    let claim: ManagedPrepareCompatibilityQueue.Claim
    let vector: WorkerExitVector
    init(observe: Bool = true, stage: String = "admitted-queued") throws {
        let f = try WorkerExitVector.load(stage: stage); vector = f
        root = FileManager.default.temporaryDirectory.appending(path: "worker-exit-" + UUID().uuidString)
        lock = try CanonicalDataStoreLock(root: root)
        queue = try ManagedPrepareCompatibilityQueue(storeLock: lock)
        let directory = lock.root.appending(path: ManagedPrepareCompatibilityQueue.directoryName)
        func put(_ value: some Encodable, _ name: String) throws {
            let path = directory.appending(path: name)
            try C.canonicalData(value).write(to: path)
            #expect(chmod(path.path, 0o600) == 0)
        }
        let arm = f.arm.arm
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
        try queue.storageStatus(.init(query: f.status.query, state: "armed"), arm: f.arm, claim: claim)
        try queue.armed(arm, claim: claim)
        if observe { try queue.storageStatus(f.status, arm: f.arm, claim: claim) }
    }
    func path(_ suffix: String) -> URL { lock.root.appending(path: ManagedPrepareCompatibilityQueue.directoryName).appending(path: vector.arm.arm.requestID + suffix) }
    func write(_ bytes: Data, _ suffix: String) throws { try bytes.write(to: path(suffix)); #expect(chmod(path(suffix).path, 0o600) == 0) }
    func put(_ value: some Encodable, _ suffix: String) throws { try write(C.canonicalData(value), suffix) }
    func bytes(_ suffix: String) throws -> Data { try Data(contentsOf: path(suffix)) }
    func exists(_ suffix: String) -> Bool { FileManager.default.fileExists(atPath: path(suffix).path) }
    func remove() { try? FileManager.default.removeItem(at: root) }
}
#endif

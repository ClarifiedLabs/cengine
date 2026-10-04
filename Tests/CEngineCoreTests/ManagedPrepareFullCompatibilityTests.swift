#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

@Suite struct ManagedPrepareFullCompatibilityTests {
    typealias C = ManagedPrepareCompatibilityProtocol
    typealias B = StorageLifecycleServiceBootProtocol
    private struct Vector: Decodable {
        var name: String
        var arm: C.Arm
        var canonical: String
        var sha256: String
        var observationCanonical: String
        var observationSHA256: String
        var storageArm: C.StorageArm?
        var storageQuery: C.StorageQuery?
        var storageStatus: C.StorageStatus?
        var storageRelease: C.StorageRelease?
    }
    private func vectors() throws -> [Vector] {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode([Vector].self, from: Data(contentsOf: root.appending(path: "Guest/internal/preparecompat/testdata/full-vectors.json")))
    }
    private func binding(_ arm: C.StorageArm) -> DiskInitializationProtocol.Binding {
        .init(shimLaunchUUID: arm.arm.binding.shimLaunchUUID, guestBootNonce: arm.arm.binding.guestBootNonce,
            ext4UUID: arm.arm.scope.store, bytes: 16 << 20)
    }
    private func command(_ arm: C.StorageArm) -> B.Frame {
        .init(operation: .command, binding: binding(arm), sequence: 1, serviceEpoch: arm.arm.scope.serviceEpoch,
            command: .prepareCompatibilityArm, workerUUID: arm.workerUUID, prepareCompatibilityArm: arm)
    }
    @Test func allNineSharedVectorsAndClosedStorageFrames() throws {
        let all = try vectors()
        #expect(all.count == 9)
        #expect(Set(all.map(\.name)).count == 9)
        for vector in all {
            try C.validate(vector.arm)
            #expect(try C.armData(vector.arm) == Data(vector.canonical.utf8))
            #expect(try C.digest(vector.arm) == vector.sha256)
            let bytes = Data(vector.observationCanonical.utf8)
            #expect(WorkloadStorageProtocol.specificationDigest(bytes) == vector.observationSHA256)
            if let arm = vector.storageArm {
                try C.validate(arm)
                let observation = try C.decode(C.StorageObservation.self, from: bytes)
                try C.validate(observation)
                let status = try #require(vector.storageStatus)
                try C.validate(status, arm: arm)
                #expect(status.observation == observation)
                #expect(try C.query(arm) == vector.storageQuery)
                let request = command(arm)
                #expect(try B.decode(Data(B.encode(request).dropFirst(4))) == request)
                let reply = B.Frame(operation: .reply, binding: binding(arm), sequence: 1, serviceEpoch: arm.arm.scope.serviceEpoch, workerUUID: arm.workerUUID, prepareCompatibilityStatus: status)
                #expect(try B.decode(Data(B.encode(reply).dropFirst(4))) == reply)
                if let release = vector.storageRelease { try C.validate(release); #expect(release.query == status.query) }
            } else if C.isEarlyCase(vector.name) {
                let observation = try C.decode(C.EarlyObservation.self, from: bytes)
                try C.validate(observation, arm: vector.arm)
            } else {
                let observation = try C.decode(C.Observation.self, from: bytes)
                try C.validate(observation, arm: vector.arm)
            }
        }
    }
    @Test func strictStorageUnionScopeAndMissingFields() throws {
        let vector = try #require(try vectors().first { $0.name == "admitted-queued" })
        let arm = try #require(vector.storageArm), status = try #require(vector.storageStatus)
        var request = command(arm)
        request.prepareCompatibilityQuery = try C.query(arm)
        #expect(throws: (any Error).self) { try B.encode(request) }
        request = command(arm); request.workerUUID = UUID().uuidString.lowercased()
        #expect(throws: (any Error).self) { try B.encode(request) }
        var reply = B.Frame(operation: .reply, binding: binding(arm), sequence: 1, serviceEpoch: arm.arm.scope.serviceEpoch, code: .command, workerUUID: arm.workerUUID, prepareCompatibilityStatus: status)
        #expect(throws: (any Error).self) { try B.encode(reply) }
        reply.code = nil
        let bytes = try B.encode(reply).dropFirst(4), text = String(decoding: bytes, as: UTF8.self)
        for changed in [text.replacingOccurrences(of: "\"count\":1", with: "\"count\":1,\"count\":1"),
                        text.replacingOccurrences(of: "\"count\":1", with: "\"count\":null"),
                        text.replacingOccurrences(of: "\"count\":1", with: "\"count\":1.0"),
                        text.replacingOccurrences(of: "\"count\":1", with: "\"count\":4294967296"),
                        text.replacingOccurrences(of: "\"count\":1,", with: ""),
                        text.replacingOccurrences(of: "\"count\":1", with: "\"count\":1,\"invented\":true")] {
            #expect(changed != text)
            #expect(throws: (any Error).self) { try B.decode(Data(changed.utf8)) }
        }
        var changed = status
        changed.retirementStarted = true; changed.acceptedInFlight = 0; changed.state = "observed"
        #expect(throws: (any Error).self) { try C.validate(changed) }
        changed = status; changed.observation!.admission!.admitted = false
        #expect(throws: (any Error).self) { try C.validate(changed) }
        changed = status; changed.observation!.workerUUID = UUID().uuidString.lowercased()
        #expect(throws: (any Error).self) { try C.validate(changed, arm: arm) }
    }
    @Test func boundProjectionRejectsForgedSealedAndCleanupEvidence() throws {
        let vector = try #require(try vectors().first { $0.name == "transaction-published-bind-reply-lost" })
        let arm = try #require(vector.storageArm), status = try #require(vector.storageStatus)
        var changed = status
        changed.observation!.bound!.intent.manifestSize = 1
        #expect(throws: (any Error).self) { try C.validate(changed, arm: arm) }
        changed = status; changed.observation!.bound!.intent.cleanup.uid = 1
        #expect(throws: (any Error).self) { try C.validate(changed) }
        changed = status; changed.observation!.bound!.intent.owner.key = String(repeating: "1", count: 64)
        #expect(throws: (any Error).self) { try C.validate(changed, arm: arm) }
        for bad in ["-0", "+1", "01", "9223372036854775808", "-9223372036854775809"] {
            changed = status; changed.observation!.bound!.intent.initial.atimeSeconds = bad
            #expect(throws: (any Error).self) { try C.validate(changed) }
        }
        changed = status; changed.observation!.bound!.intent.initial.atimeSeconds = String(Int64.min)
        try C.validate(changed)
        let encoded = try C.canonicalData(changed)
        #expect(try C.decode(C.StorageStatus.self, from: encoded) == changed)
    }
    @Test func oldProfilesKeepTheirClosedCaseSets() throws {
        for vector in try vectors() {
            for (profile, version) in [(C.profile, UInt32(1)), (C.earlyProfile, UInt32(2))] {
                var arm = vector.arm; arm.version = version; arm.profile = profile
                let allowed = vector.name == "normal" || (version == 1 ? vector.name == "first-child-published" : C.isEarlyCase(vector.name))
                if allowed { try C.validate(arm) }
                else { #expect(throws: (any Error).self) { try C.validate(arm) } }
            }
        }
    }
    @Test func storageQueueRequiresExternalExactOneShotReleaseAndPreservesFirstCut() throws {
        let vector = try #require(try vectors().first { $0.name == "admitted-queued" })
        var arm = try #require(vector.storageArm)
        arm.arm = C.normalized(arm.arm)
        let status = try #require(vector.storageStatus), release = try #require(vector.storageRelease)
        let root = FileManager.default.temporaryDirectory.appending(path: "full-queue-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let lock = try CanonicalDataStoreLock(root: root), queue = try ManagedPrepareCompatibilityQueue(storeLock: lock)
        let directory = lock.root.appending(path: ManagedPrepareCompatibilityQueue.directoryName)
        func put(_ value: some Encodable, _ name: String) throws {
            let path = directory.appending(path: name); try C.canonicalData(value).write(to: path); #expect(chmod(path.path, 0o600) == 0)
        }
        let inner = arm.arm
        let capture = C.Capture(version: 1, requestID: inner.requestID, container: inner.scope.container,
            containerInstance: inner.scope.containerInstance, specificationDigest: inner.scope.specificationDigest, mounts: inner.mounts)
        try put(capture, "capture.json")
        let claim = try #require(try queue.capture(container: capture.container, instance: capture.containerInstance, digest: capture.specificationDigest, mounts: capture.mounts))
        let candidate = C.Candidate(version: 3, profile: C.fullProfile, requestID: inner.requestID, binding: inner.binding,
            scope: inner.scope, mounts: inner.mounts, slots: inner.slots, credentials: inner.credentials)
        try queue.candidate(candidate, claim: claim)
        try put(inner, inner.requestID + ".arm.json")
        _ = try #require(try queue.arm(claim, candidate: candidate))
        try queue.storageStatus(.init(query: status.query, state: "armed"), arm: arm, claim: claim)
        try queue.armed(inner, claim: claim)
        var pending = status; pending.state = "observed"; pending.retirementStarted = true; pending.acceptedInFlight = 1
        try queue.storageStatus(pending, arm: arm, claim: claim)
        #expect(try queue.storageRelease(arm, claim: claim) == nil)
        let checkpoint = directory.appending(path: inner.requestID + ".storage-checkpoint.json")
        #expect(try Data(contentsOf: checkpoint) == C.canonicalData(status.observation!))
        #expect(FileManager.default.fileExists(atPath: directory.appending(path: inner.requestID + ".storage-pending.json").path))
        try put(release, inner.requestID + ".storage-release.json")
        #expect(try queue.storageRelease(arm, claim: claim) == release)
        #expect(try queue.storageRelease(arm, claim: claim) == nil)
        var changed = pending; changed.observation!.admission!.requestSequence += 1
        #expect(throws: (any Error).self) { try queue.storageStatus(changed, arm: arm, claim: claim) }
        #expect(try Data(contentsOf: checkpoint) == C.canonicalData(status.observation!))
    }
}
#endif

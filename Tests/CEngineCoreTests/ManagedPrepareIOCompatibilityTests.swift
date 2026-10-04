import CEngineCore
import Foundation
import Testing
#if os(macOS)
@testable import CEngineRuntime
#endif

@Suite struct ManagedPrepareIOCompatibilityTests {
    typealias C = ManagedPrepareCompatibilityProtocol
    private func arm(_ stage: String) throws -> C.Arm {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        struct Vector: Decodable { var arm: C.Arm }
        var arm = try JSONDecoder().decode([Vector].self, from: Data(contentsOf: root.appending(path: "Guest/internal/preparecompat/testdata/full-vectors.json")))[0].arm
        arm.caseName = stage
        return arm
    }
    @Test func closedIOInventoryAndProfiles() throws {
        let points = ["copy-operation-write", "copy-operation-sync", "provision-rename", "provision-parent-sync", "child-data-fsync", "manifest-write", "manifest-fsync", "manifest-rename-parent-sync", "seal-persist", "public-child-rename", "public-directory-sync", "root-metadata", "root-fsync", "cleaning-persist", "child-unlink-parent-sync", "manifest-unlink-parent-sync", "transaction-unlink-parent-sync", "root-restoration-syncfs", "finish-persist", "retire-intent-persist", "retire-barrier-persist", "retire-receipt-persist", "retire-barrier-clear-persist"]
        var storage = 0, workload = 0
        for point in points { for errno in ["EIO", "ENOSPC"] {
            let stage = "io-\(errno.lowercased())-\(point)"
            let selected = try arm(stage)
            try C.validate(selected)
            #expect(!C.expectsPhysicalObservation(selected))
            #expect(!C.allowsPrepareSuccess(selected))
            var old = selected; old.profile = C.profile; old.version = 1
            #expect(throws: (any Error).self) { try C.validate(old) }
            if C.ioCase(stage)?.workload == true { workload += 1; continue }
            storage += 1
            let wrapped = C.StorageArm(arm: selected, workerUUID: selected.binding.guestBootNonce)
            let query = try C.query(wrapped)
            let io = C.IOCut(point: point, errno: errno, requestSequence: point.hasPrefix("retire-") ? 0 : 42,
                             retireOperation: point.hasPrefix("retire-") ? selected.scope.intent : "")
            var observation = C.StorageObservation(requestID: query.requestID, armDigest: query.armDigest,
                workerUUID: query.workerUUID, stage: stage, targetAttachment: selected.targetAttachment, io: io)
            var status = C.StorageStatus(query: query, state: "observed", observation: observation)
            try C.validate(status, arm: wrapped)
            #expect(try C.decode(C.StorageStatus.self, from: C.canonicalData(status)) == status)
            status.state = "finished"
            #expect(throws: (any Error).self) { try C.validate(status) }
            observation.io?.occurrence = 2
            #expect(throws: (any Error).self) { try C.validate(observation) }
            #expect(throws: (any Error).self) { try C.validate(C.StorageRelease(query: query, stage: stage, token: String(repeating: "a", count: 64))) }
        }}
        #expect(storage == 30 && workload == 16)
        for stage in ["io-eio-any", "io-eperm-root-fsync", "io-EIO-root-fsync"] {
            #expect(throws: (any Error).self) { try C.validate(arm(stage)) }
        }
    }
    #if os(macOS)
    private func ioFrame(_ selected: C.Arm) throws -> WorkloadStorageProtocol.Frame {
        let cut = try #require(C.ioCase(selected.caseName))
        return .init(operation: .prepareCheckpoint, binding: selected.binding, scope: selected.scope,
            data: .init(compatibilityIOObservation: .init(requestID: selected.requestID,
                armDigest: try C.digest(selected), stage: selected.caseName,
                // Authority copy intent is independently allocated, not host launch intent.
                targetAttachment: selected.targetAttachment, copyIntent: UUID().uuidString.lowercased(),
                point: cut.point, errno: cut.errno)))
    }

    @Test func terminalRetainsPublishedIOButRejectsLatePublicationAndDuplicateClaim() throws {
        let selected = try arm("io-eio-root-fsync"), frame = try ioFrame(selected)
        let retained = PrivatePrepareObservation()
        try retained.install(selected)
        try retained.publish(frame)
        retained.finish()
        #expect(try retained.observe(selected) == frame)
        #expect(throws: (any Error).self) { _ = try retained.observe(selected) }
        #expect(throws: (any Error).self) { try retained.publish(frame) }
        let late = PrivatePrepareObservation()
        try late.install(selected)
        late.finish()
        #expect(throws: (any Error).self) { try late.publish(frame) }
        #expect(throws: (any Error).self) { _ = try late.observe(selected) }
    }

    @Test(arguments: ["requestID", "armDigest", "stage", "targetAttachment", "copyIntent", "point", "errno", "binding", "scope"])
    func ioCheckpointMustMatchExactInstalledArm(field: String) throws {
        let selected = try arm("io-eio-root-fsync")
        var frame = try ioFrame(selected)
        let other = UUID().uuidString.lowercased()
        switch field {
        case "requestID": frame.data.compatibilityIOObservation?.requestID = other
        case "armDigest": frame.data.compatibilityIOObservation?.armDigest = String(repeating: "f", count: 64)
        case "stage":
            frame.data.compatibilityIOObservation?.stage = "io-eio-root-metadata"
            frame.data.compatibilityIOObservation?.point = "root-metadata"
        case "targetAttachment": frame.data.compatibilityIOObservation?.targetAttachment = other
        case "copyIntent": frame.data.compatibilityIOObservation?.copyIntent = "not-a-copy-intent"
        case "point": frame.data.compatibilityIOObservation?.point = "root-metadata"
        case "errno": frame.data.compatibilityIOObservation?.errno = "ENOSPC"
        case "binding": frame.binding.guestBootNonce = other
        default: frame.scope?.intent = other
        }
        // The private reader and authenticated shim forwarding share this validator.
        #expect(throws: (any Error).self) { try C.validateObservation(frame, arm: selected) }
        let observer = PrivatePrepareObservation()
        try observer.install(selected)
        #expect(throws: (any Error).self) { try observer.publish(frame) }
        // Rejection must not consume the one valid publication slot.
        let valid = try ioFrame(selected)
        try observer.publish(valid)
        observer.finish()
        #expect(try observer.observe(selected) == valid)
    }

    @Test func onlyFourRetirementPointsPermitPrepareWithoutCheckpoint() throws {
        let points = ["copy-operation-write", "copy-operation-sync", "provision-rename", "provision-parent-sync", "child-data-fsync", "manifest-write", "manifest-fsync", "manifest-rename-parent-sync", "seal-persist", "public-child-rename", "public-directory-sync", "root-metadata", "root-fsync", "cleaning-persist", "child-unlink-parent-sync", "manifest-unlink-parent-sync", "transaction-unlink-parent-sync", "root-restoration-syncfs", "finish-persist", "retire-intent-persist", "retire-barrier-persist", "retire-receipt-persist", "retire-barrier-clear-persist"]
        let retire = Set(["retire-intent-persist", "retire-barrier-persist", "retire-receipt-persist", "retire-barrier-clear-persist"])
        let checkpoint = try ioFrame(arm("io-eio-root-fsync"))
        for point in points { for errno in ["eio", "enospc"] {
            let selected = try arm("io-\(errno)-\(point)")
            #expect(PrivateWorkloadStorageCoordinator.allowsSuccessfulPrepare(selected, checkpoint: nil) == retire.contains(point))
            #expect(PrivateWorkloadStorageCoordinator.allowsSuccessfulPrepare(selected, checkpoint: checkpoint) == retire.contains(point))
        }}
        for stage in ["normal", "drain-durable-reply-lost"] {
            let selected = try arm(stage)
            #expect(!PrivateWorkloadStorageCoordinator.allowsSuccessfulPrepare(selected, checkpoint: nil))
            #expect(PrivateWorkloadStorageCoordinator.allowsSuccessfulPrepare(selected, checkpoint: checkpoint))
        }
        #expect(!PrivateWorkloadStorageCoordinator.allowsSuccessfulPrepare(try arm("first-child-published"), checkpoint: checkpoint))
    }

    @Test @MainActor func missedWorkloadIOIsContainedBeforeObservationJoin() async throws {
        let selected = try arm("io-eio-root-fsync")
        let observer = PrivatePrepareObservation()
        try observer.install(selected)
        let observation = Task<Void, Error> { _ = try await observer.observation(selected) }
        // No cut was published: stopping the source must release the pending wait.
        try await RawManagedStorageBackend.joinFailedPrepareObservation(observation) {
            observer.finish()
        }
        switch await observation.result {
        case .failure: break
        case .success: Issue.record("missed IO checkpoint unexpectedly succeeded")
        }
    }
    #endif

    #if os(macOS)
    @Test(arguments: [false, true]) @MainActor
    func failedObservationPreservesOriginalStartError(stopFails: Bool) async throws {
        enum Failure: Error, Equatable { case start, observation, stop }
        let entered = AsyncStream<Void>.makeStream()
        let release = AsyncStream<Void>.makeStream()
        let observation = Task<Void, Error> {
            entered.continuation.yield(()); entered.continuation.finish()
            for await _ in release.stream { break }
            throw Failure.observation
        }
        for await _ in entered.stream { break } // observer is actually pending
        var stopped = false
        do {
            do { throw Failure.start }
            catch {
                try? await RawManagedStorageBackend.joinFailedPrepareObservation(observation) {
                    stopped = true
                    if stopFails { throw Failure.stop }
                    release.continuation.yield(()); release.continuation.finish()
                }
                throw error
            }
        } catch { #expect(error as? Failure == .start) }
        #expect(stopped)
        // Stop failure cannot wait on an uncontained source. Release only here;
        // both branches join explicitly before fixture cleanup.
        release.continuation.yield(()); release.continuation.finish()
        await #expect(throws: Failure.observation) { try await observation.value }
    }
    #endif

    @Test func guestIOUsesExistingCheckpointAndCannotMasqueradeAsPhysical() throws {
        let selected = try arm("io-enospc-root-fsync")
        let value = C.IOObservation(requestID: selected.requestID, armDigest: try C.digest(selected), stage: selected.caseName,
            targetAttachment: selected.targetAttachment, copyIntent: selected.scope.intent, point: "root-fsync", errno: "ENOSPC")
        var frame = WorkloadStorageProtocol.Frame(operation: .prepareCheckpoint, binding: selected.binding, scope: selected.scope,
            data: .init(compatibilityIOObservation: value))
        try C.validateObservation(frame, arm: selected)
        #expect(try WorkloadStorageProtocol.decode(from: Data(WorkloadStorageProtocol.encode(frame).dropFirst(4))) == frame)
        frame.data.compatibilityIOObservation?.errno = "28"
        #expect(throws: (any Error).self) { try C.validateObservation(frame, arm: selected) }
    }
}

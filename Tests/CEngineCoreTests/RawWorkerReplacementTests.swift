#if os(macOS)
import CEngineCore
import Foundation
import Testing
@testable import CEngineRuntime

@Suite @MainActor struct RawWorkerReplacementTests {
    private final class Client: Sendable {}
    private struct FailedLaunch: Error { let client: Client }
    private struct Revoked: Error {}

    @Test(arguments: [false, true])
    func lateLaunchSuccessAndErrorCleanOnlyCapturedClient(rollbackIncomplete: Bool) async throws {
        let predecessor = Client()
        let successor = Client()
        var selected = predecessor
        var cleaned: [Client] = []
        var retained: [Client] = []
        await #expect(throws: (any Error).self) {
            _ = try await RawTrackedShimLaunch.run(launch: {
                selected = successor // replacement won while launch was suspended
                if rollbackIncomplete { throw FailedLaunch(client: predecessor) }
                return predecessor
            }, failedClient: { ($0 as? FailedLaunch)?.client }, validate: { _ in
                throw Revoked()
            }, cleanup: { cleaned.append($0) }, retain: { retained.append($0) })
        }
        #expect(selected === successor)
        #expect(cleaned.count == 1 && cleaned.first === predecessor)
        #expect(retained.isEmpty)
    }

    @Test func oldStopCannotCancelSuccessorCompletionEvenWhenClientIsReused() {
        let original = Client()
        let successor = Client()
        var fence = RawBackendExecutionFence()
        let old = fence.replace("container")
        let next = fence.replace("container")
        #expect(!RawTrackedShimLaunch.ownsCompletion(captured: original, current: successor,
            generation: old, completion: next))
        #expect(!RawTrackedShimLaunch.ownsCompletion(captured: original, current: original,
            generation: old, completion: next))
        #expect(RawTrackedShimLaunch.ownsCompletion(captured: successor, current: successor,
            generation: next, completion: next))
    }

    @Test func revokedCleanupCannotPublishOrDisposeAfterSuccessorAdmission() async throws {
        let work = RawServiceWorkTracker()
        let cleanup = try work.begin()
        work.close()
        #expect(throws: (any Error).self) { try work.require(cleanup) }
        #expect(throws: (any Error).self) { try work.reopen() }
        work.end(cleanup)
        try await work.join()
        try work.reopen()
        let successor = try work.begin()
        #expect(throws: (any Error).self) { try work.require(cleanup) }
        work.end(cleanup) // late release must not release the successor
        try work.require(successor)
        work.close()
        await #expect(throws: (any Error).self) { try await work.join(timeout: .milliseconds(1)) }
        work.end(successor)
        try await work.join()
    }

    @Test func finalCensusWaitsForNativePublicationAndPostContainmentDisposal() async throws {
        let native = RawServiceWorkTracker()
        let work = RawServiceWorkTracker()
        let launch = try native.begin()
        let prepare = try work.begin()
        let deletion = try work.begin()
        native.close(); work.close() // production fence, before the worker is killed
        let contained = Signal()
        var events: [String] = ["worker-reaped"]
        let replacement = Task {
            try await RawServiceContainment.run(native: native, work: work, contain: {
                events.append("initial-containment")
                work.end(prepare) // PREPARE is allowed to need VM death to unwind
                contained.signal()
            }, joinManaged: {
                events.append("managed-joined")
            }, census: {
                events.append("final-census")
                return ["old-container"]
            })
        }
        await Task.yield()
        #expect(events == ["worker-reaped"])
        events.append("native-publication-complete")
        native.end(launch)
        await contained.wait()
        #expect(events == ["worker-reaped", "native-publication-complete", "initial-containment"])
        #expect(throws: (any Error).self) { try native.begin() }
        #expect(throws: (any Error).self) { try work.begin() }
        events.append("disposal-complete")
        work.end(deletion)
        #expect(try await replacement.value == ["old-container"])
        #expect(events.suffix(3) == ["disposal-complete", "managed-joined", "final-census"])
        try native.reopen(); try work.reopen()
    }

    @Test func delayedNotificationErrorCannotFenceOrCloseSuccessor() async throws {
        let work = RawServiceWorkTracker()
        let notification = try work.begin()
        let suspended = Signal()
        let resume = Signal()
        var closedSuccessor = false
        let oldPoll = Task {
            defer { work.end(notification) }
            suspended.signal()
            await resume.wait()
            // Same lease check used by every production notification catch.
            guard (try? work.require(notification)) != nil else { return }
            closedSuccessor = true
        }
        await suspended.wait()
        work.close()
        resume.signal()
        try await work.join()
        try work.reopen()
        await oldPoll.value
        #expect(!closedSuccessor)
    }

    @Test func censusRejectsRenamedDisposalClaimsWithoutDeletingEvidence() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = try PersistentStateDirectory.open(root)
        let id = String(repeating: "a", count: 64)
        let container = try directory.createDirectory(named: id)
        try container.writeExclusiveRegularFile(named: "evidence", data: Data("retain".utf8))
        #expect(try RawVirtualizationBackend.serviceExecutionCensus(in: directory) == [id])
        #expect(throws: Revoked.self) {
            try directory.disposeDirectory(named: id, expectedIdentity: container.identity, hook: {
                if case .rootClaimed = $0 { throw Revoked() }
            })
        }
        let names = try directory.entryNames()
        #expect(!names.contains(id))
        #expect(throws: (any Error).self) { try RawVirtualizationBackend.serviceExecutionCensus(in: directory) }
        #expect(try directory.entryNames() == names)
        #expect(try container.readRegularFile(named: "evidence") == Data("retain".utf8))
    }

    @Test func containedExecRetirementReclaimsAll64ArtifactSlots() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = try PersistentStateDirectory.open(root)
        let artifacts = try RawContainerPreparationArtifacts.create(in: directory, rootDiskSize: 4096)
        let id = String(repeating: "b", count: 64)
        for index in 0..<RawExecArtifactJournal.maximumActiveRecordCount {
            _ = try RawExecArtifactTransaction.prepare(containerID: id, execID: "old-\(index)",
                attachStdin: false, in: directory, artifacts: artifacts)
            // Each fixture transaction is complete. Do not monopolize MainActor
            // across 64 durable preparations while other tests prove progress.
            await Task.yield()
        }
        #expect(throws: (any Error).self) {
            _ = try RawExecArtifactTransaction.prepare(containerID: id, execID: "overflow",
                attachStdin: false, in: directory, artifacts: artifacts)
        }
        // This production routine is called only after exact VM containment and
        // the admitted-operation join; this test supplies no fabricated VM proof.
        try RawVirtualizationBackend.retireContainedExecArtifacts(containerID: id, in: directory, artifacts: artifacts)
        #expect(try RawExecArtifactJournal.activeRecords(containerID: id, in: directory, artifacts: artifacts).isEmpty)
        _ = try RawExecArtifactTransaction.prepare(containerID: id, execID: "successor",
            attachStdin: false, in: directory, artifacts: artifacts)
        #expect(try RawExecArtifactJournal.activeRecords(containerID: id, in: directory, artifacts: artifacts).count == 1)
    }

    @Test func containedExecSnapshotsReleaseDescriptorsAndRemainBudgeted() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        var budget = RawCompletedExecSnapshotBudget(perExecBytes: 16, perContainerBytes: 64,
            globalBytes: 64, minimumSnapshotBytes: 16)
        var bridges: [String: ContainerIOBridge] = [:]
        let instance = UUID()
        for index in 0..<65 {
            let id = "exec-\(index)"
            let bridge = ContainerIOBridge(tty: false, logURL: root.appending(path: id))
            bridges[id] = bridge
            for evicted in RawVirtualizationBackend.freezeCompletedExecOutput(bridge, execID: id,
                containerID: "container", instanceID: instance, budget: &budget) {
                bridges.removeValue(forKey: evicted)?.discardCompletedOutput()
            }
            #expect(bridge.retainedPersistentDescriptorCount == 0)
        }
        #expect(budget.entries.count == 4)
        #expect(bridges.count == 4)
        #expect(budget.retainedBytes == 64)
    }

    @MainActor private final class Signal {
        private var signalled = false
        private var continuation: CheckedContinuation<Void, Never>?
        func signal() { signalled = true; continuation?.resume(); continuation = nil }
        func wait() async {
            guard !signalled else { return }
            await withCheckedContinuation { continuation = $0 }
        }
    }
}
#endif

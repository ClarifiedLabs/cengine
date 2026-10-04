#if os(macOS)
import CEngineCore
import Foundation
import Testing
@testable import CEngineRuntime

/// Pure actor/mock scheduling tests: no native peer, helper, VM or fabricated reaping.
@Suite @MainActor struct ManagedPrepareWorkerExitLossFenceTests {
    typealias Fence = RawManagedStorageBackend.PrepareWorkerExitLossFence
    typealias Gate = EngineServiceReplacementTests.Gate

    private enum WaitFailure: Error { case watchdog }

    @Test func workerExitDiagnosticsAreClosedAndDoNotReleaseFence() {
        struct SecretError: Error, CustomStringConvertible {
            var description: String { "private-key=/sensitive/path\nforged-success" }
        }
        let fence = Fence(generation: UUID())
        let errors: [any Error] = [SecretError(), EngineError(.conflict, "secret-token"),
            ManagedStorageFailure.blocked, ManagedStorageFailure.repairRequired,
            CancellationError(), ManagedStorageControlFailure.system(123456)]
        for stage in RawManagedStorageBackend.WorkerExitDiagnosticStage.allCases {
            for error in errors {
                let close = ManagedStorageCloseDiagnostic(site: .adapter, operation: .query,
                    phase: .reconnectStream, error: error)
                let text = RawManagedStorageBackend.workerExitDiagnostic(stage, error: error, firstClose: close)
                #expect(text.utf8.count < 300)
                #expect(text.filter { $0 == "\n" }.count == 1 && text.hasSuffix("\n"))
                #expect(!text.contains("secret") && !text.contains("sensitive") && !text.contains("123456"))
                #expect(text.contains("stage=\(stage.rawValue)"))
                #expect(!fence.completed && fence.waitingCount == 0)
            }
        }
        #expect(RawManagedStorageBackend.workerExitDiagnostic(.commandReturned) ==
            "cengine worker-exit stage=command-returned category=none owner=none first-close=none\n")
        #expect(RawManagedStorageBackend.workerExitDiagnostic(.observerFailed,
            error: ManagedStorageFailure.repairRequired).contains("owner=repair-required"))
    }

    private func waitForWaiters(_ count: Int, on fence: Fence, budget: Duration = .seconds(5)) async throws {
        let deadline = ContinuousClock.now + budget
        while fence.waitingCount != count {
            guard ContinuousClock.now < deadline else { throw WaitFailure.watchdog }
            await Task.yield()
        }
    }

    @Test func missingWaiterFailsInsteadOfPassingAtDeadline() async throws {
        let fence = Fence(generation: UUID())
        do {
            try await waitForWaiters(1, on: fence, budget: .zero)
            Issue.record("missing waiter unexpectedly observed")
        } catch WaitFailure.watchdog {
            #expect(!fence.completed && fence.waitingCount == 0)
        }
        // The actual condition, not elapsed time, is required even at a zero budget.
        try await waitForWaiters(0, on: fence, budget: .zero)
    }

    @Test func cancellationCannotCompleteEitherSelectedWaiter() async throws {
        let fence = Fence(generation: UUID())
        defer { fence.observedLossReturned() } // Test cleanup if a scheduling assertion throws.
        var startReturned = false, publicationReturned = false
        let start = Task { await fence.wait(.startFailure); startReturned = true }
        let publication = Task { await fence.wait(.waitPublication); publicationReturned = true }
        try await waitForWaiters(2, on: fence)
        start.cancel(); publication.cancel()
        await Task.yield()
        #expect(!fence.completed && !startReturned && !publicationReturned)
        fence.observedLossReturned()
        await start.value; await publication.value
        #expect(fence.completed && startReturned && publicationReturned)
        #expect(fence.waitingCount == 0)
        // Late arrival and duplicate notification cannot lose/resume a continuation twice.
        await fence.wait(.startFailure)
        fence.observedLossReturned()
    }

    @Test(arguments: [false, true])
    func selectedStartErrorWaitsForReturnedObserverThenEngineConflicts(errorFirst: Bool) async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "worker-loss-fence-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let fence = Fence(generation: UUID()), backend = Backend(fence: fence)
        defer { fence.observedLossReturned() } // Test-only continuation cleanup on failure.
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let other = try await runtime.createContainer(.init(name: "normal-owned", image: "fixture"))
        let selected = try await runtime.createContainer(.init(name: "selected-a5", image: "fixture"))
        await backend.select(selected.id)
        let starting = Task { try await runtime.startContainer(selected.id) }
        await backend.startError.wait()
        var published = false
        let publication = Task { await fence.wait(.waitPublication); published = true }
        try await waitForWaiters(1, on: fence)
        if errorFirst {
            await backend.startError.resume()
            try await waitForWaiters(2, on: fence)
        }
        let notification = Task { await backend.deliverNotificationWorkerLoss() }
        await backend.callbackEntered.wait()
        #expect(!fence.completed && !published)
        #expect(await backend.cleanupCount == 0)
        await backend.callbackEntered.resume()
        await backend.callbackReturning.wait()
        // EngineRuntime's real observer has now cleared lifecycle tokens, but
        // the outer serviceLost callback has not returned to its producer yet.
        #expect(!fence.completed && !published)
        #expect(fence.waitingCount == (errorFirst ? 2 : 1))
        #expect(await backend.cleanupCount == 0)
        await backend.callbackReturning.resume()
        await notification.value
        await publication.value
        if !errorFirst { await backend.startError.resume() }
        do {
            try await starting.value
            Issue.record("stale selected start unexpectedly succeeded")
        } catch let error as EngineError {
            #expect(error.code == .conflict) // Docker's exact existing 409 mapping.
        }
        #expect(published && fence.completed)
        #expect(await backend.cleanupCount == 0) // rollbackFailedStart was bypassed, not cleared afterward.
        #expect(try await runtime.container(selected.id).phase == .created)
        let failed = try await AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json")).loadRequired()
        #expect(failed.containers.first { $0.id == selected.id }?.phase == .created)
        #expect(failed.cleanupPendingContainerIDs == [selected.id]) // Preserve real pre-start fence.

        let predecessor = StorageServiceTypes.Scope(serviceEpoch: UUID().uuidString.lowercased(), workerUUID: UUID().uuidString.lowercased())
        _ = try await runtime.replaceManagedStorageService(operationUUID: UUID().uuidString.lowercased(), predecessor: predecessor)
        #expect(await backend.replacementInventory == Set([selected.id, other.id]))
        let recovered = try await AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json")).loadRequired()
        #expect(recovered.cleanupPendingContainerIDs == nil)
        #expect(recovered.containers.first { $0.id == selected.id }?.phase == .created)
        try await runtime.startContainer(selected.id)
        #expect(await backend.selectedStartCount == 2)
        #expect(await backend.cleanupCount == 0)
        await runtime.shutdown()
    }

    @Test func unselectedStartDoesNotWaitForCompatibilityLoss() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "worker-loss-inert-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let fence = Fence(generation: UUID()), backend = Backend(fence: fence)
        defer { fence.observedLossReturned() } // Test-only continuation cleanup on failure.
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let record = try await runtime.createContainer(.init(name: "unselected", image: "fixture"))
        try await runtime.startContainer(record.id)
        #expect(!fence.completed && fence.waitingCount == 0)
        #expect(await backend.cleanupCount == 0)
        await runtime.shutdown()
    }

    actor Backend: ContainerBackend {
        let fence: Fence
        let startError = Gate(), callbackEntered = Gate(), callbackReturning = Gate()
        var lossObserver: (@Sendable () async -> Void)?
        var selected: String?
        var faultPending = false
        var selectedStartCount = 0
        var cleanupCount = 0
        var replacementInventory = Set<String>()
        init(fence: Fence) { self.fence = fence }
        func select(_ id: String) { selected = id; faultPending = true }
        func observeManagedStorageLoss(_ observer: @escaping @Sendable () async -> Void) async { lossObserver = observer }
        func deliverNotificationWorkerLoss() async {
            // Model only the observer callback ordering. Production's sole signal
            // site is the genuine retirementNotifications serviceUnavailable catch.
            await callbackEntered.pause()
            await lossObserver?()
            await callbackReturning.pause()
            await fence.observedLossReturned()
        }
        func pullImage(_: String, platform _: String) async throws {}
        func prepare(_: ContainerRecord) async throws {}
        func start(_ container: ContainerRecord) async throws -> [PortBinding] {
            if container.id == selected { selectedStartCount += 1 }
            if container.id == selected, faultPending {
                faultPending = false
                await startError.pause()
                await fence.wait(.startFailure)
                throw EngineError(.internalError, "selected old worker PREPARE failed")
            }
            return container.ports
        }
        func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
        func wait(_: ContainerRecord) async throws -> Int32 { throw EngineError(.unsupported, "no mock completion") }
        func delete(_: ContainerRecord) async throws {}
        func cleanupExecution(_: ContainerRecord) async throws {
            cleanupCount += 1
            throw BackendResourceRollbackIncompleteError("old worker is unavailable")
        }
        func validateManagedStorageReplacement(_: StorageServiceTypes.ReplacementRequest) async throws {}
        func validateManagedStorageAvailability(_: StorageServiceTypes.Scope) async throws {}
        func replaceManagedStorageService(_ request: StorageServiceTypes.ReplacementRequest,
            volumes: [VolumeRecord], containers: [ContainerRecord]) async throws -> BackendServiceReplacementResult {
            replacementInventory = Set(containers.map(\.id))
            return .init(request: request, successor: .init(serviceEpoch: UUID().uuidString.lowercased(), workerUUID: UUID().uuidString.lowercased()),
                         containedContainerIDs: replacementInventory)
        }
    }
}
#endif

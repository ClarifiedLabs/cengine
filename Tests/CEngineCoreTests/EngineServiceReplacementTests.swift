import CEngineCore
import Foundation
import Testing
@testable import CEngineRuntime

@Suite struct EngineServiceReplacementTests {
    actor Gate {
        private var arrived = false
        private var arrival: CheckedContinuation<Void, Never>?
        private var release: CheckedContinuation<Void, Never>?
        func pause() async {
            arrived = true; arrival?.resume(); arrival = nil
            await withCheckedContinuation { release = $0 }
        }
        func signal() { arrived = true; arrival?.resume(); arrival = nil }
        func wait() async { if !arrived { await withCheckedContinuation { arrival = $0 } } }
        func resume() { release?.resume(); release = nil }
    }
    actor Backend: ContainerBackend {
        let replacement = Gate()
        let fenced = Gate()
        let secondFenced = Gate()
        let nextReplacement = Gate()
        let nextOperation = Gate()
        var lossObserver: (@Sendable () async -> Void)?
        func observeManagedStorageLoss(_ observer: @escaping @Sendable () async -> Void) async { lossObserver = observer }
        func fenceManagedStorageService() async {
            fenceCount += 1
            if fenceCount == 2 { await secondFenced.signal() }
            await fenced.signal()
        }
        func loseWorker() async { await lossObserver?() }
        let operation = Gate()
        var pausePreparation = false
        var pauseNextPreparation = false
        var omitLiveCensus = false
        func configureNextPreparation() { pauseNextPreparation = true }
        func configureIncompleteCensus() { omitLiveCensus = true }
        var pauseSynchronization = false
        var failReplacement = false
        var rejectPreflight = false
        var rejectAvailability = false
        var availabilityWorkerLost = false
        var pauseResize = false
        var preflightCount = 0
        var availabilityScopes: [StorageServiceTypes.Scope] = []
        var fenceCount = 0
        var pauseStop = false
        var pauseResources = false
        var pauseExecPreparation = false
        var resourceResult = 0
        var deleteCount = 0
        var cleanupCount = 0
        var resourceCount = 0
        func validateManagedStorageReplacement(_ request: StorageServiceTypes.ReplacementRequest) async throws {
            preflightCount += 1
            if rejectPreflight { throw EngineError(.badRequest, "replacement admission unavailable") }
        }
        func validateManagedStorageAvailability(_ scope: StorageServiceTypes.Scope) async throws {
            availabilityScopes.append(scope)
            if availabilityWorkerLost {
                availabilityWorkerLost = false
                throw ManagedStorageControlFailure.serviceUnavailable
            }
            if rejectAvailability { throw EngineError(.conflict, "successor unavailable") }
        }
        func configurePreflightRejection() { rejectPreflight = true }
        func configureAvailabilityRejection() { rejectAvailability = true }
        func configureAvailabilityWorkerLoss() { availabilityWorkerLost = true }
        func configureResize() { pauseResize = true }
        func configureStop() { pauseStop = true }
        func configureResources(result: Int) { pauseResources = true; resourceResult = result }
        func configureExecPreparation() { pauseExecPreparation = true }
        var requests: [StorageServiceTypes.ReplacementRequest] = []
        func configure(prepare: Bool = false, synchronize: Bool = false, fail: Bool = false) {
            pausePreparation = prepare; pauseSynchronization = synchronize; failReplacement = fail
        }
        func pullImage(_: String, platform _: String) async throws {}
        func prepare(_: ContainerRecord) async throws {
            if pausePreparation { pausePreparation = false; await operation.pause() }
            else if pauseNextPreparation { pauseNextPreparation = false; await nextOperation.pause() }
        }
        func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
        func resize(_: ContainerRecord, width _: UInt16, height _: UInt16) async throws {
            if pauseResize { pauseResize = false; await operation.pause() }
        }
        func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 {
            if pauseStop { pauseStop = false; await operation.pause() }
            return 0
        }
        func wait(_: ContainerRecord) async throws -> Int32 { 0 }
        func delete(_: ContainerRecord) async throws { deleteCount += 1 }
        func cleanupExecution(_: ContainerRecord) async throws { cleanupCount += 1 }
        func updateResources(_: ContainerRecord) async throws {
            resourceCount += 1
            if pauseResources {
                pauseResources = false
                let result = resourceResult
                await operation.pause()
                if result == 1 { throw EngineError(.internalError, "old resource update failed") }
                if result == 2 { throw BackendResourceRollbackIncompleteError("old resource rollback incomplete") }
            }
        }
        func prepareExec(_: ExecRecord, container _: ContainerRecord) async throws -> ContainerIOBridge {
            if pauseExecPreparation { pauseExecPreparation = false; await operation.pause() }
            throw EngineError(.unsupported, "fixture exec preparation ended")
        }
        func synchronizeVolumes(_: [VolumeRecord]) async throws { if pauseSynchronization { pauseSynchronization = false; await operation.pause() } }
        func replaceManagedStorageService(_ request: StorageServiceTypes.ReplacementRequest,
            volumes: [VolumeRecord], containers: [ContainerRecord]) async throws -> BackendServiceReplacementResult {
            requests.append(request)
            if requests.count == 2 { await nextReplacement.pause() }
            else { await replacement.pause() }
            if failReplacement { throw EngineError(.conflict, "replacement failed") }
            return .init(request: request, successor: .init(serviceEpoch: UUID().uuidString.lowercased(),
                workerUUID: UUID().uuidString.lowercased()), containedContainerIDs: omitLiveCensus ? [] : Set(containers.map(\.id)))
        }
    }
    actor PersistenceHook {
        let gate = Gate()
        var armed = false
        func arm() { armed = true }
        func run() async { if armed { armed = false; await gate.pause() } }
    }
    @Test func replacementSelectsDurableInventoryAndReleasesStalePersistenceLane() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend(), hook = PersistenceHook()
        let runtime = try await EngineRuntime(root: root, backend: backend, beforePersistence: { await hook.run() })
        await hook.arm()
        let stale = Task { try await runtime.createVolume(name: "not-durable") }
        await hook.gate.wait()
        let previous = predecessor
        let replacing = Task { try await runtime.replaceManagedStorageService(operationUUID: UUID().uuidString.lowercased(), predecessor: previous) }
        await backend.fenced.wait()
        await hook.gate.resume()
        await #expect(throws: EngineError.self) { try await stale.value }
        await backend.replacement.wait(); await backend.replacement.resume()
        _ = try await replacing.value
        let durable = try await AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json")).loadRequired()
        #expect(!durable.volumes.contains { $0.name == "not-durable" })
        _ = try await runtime.createVolume(name: "after-persistence")
    }
    @Test func workerLossFencesEngineButAllowsExplicitReplacement() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        await backend.loseWorker()
        await #expect(throws: EngineError.self) { try await runtime.createVolume(name: "lost-worker") }
        let previous = predecessor
        let replacing = Task { try await runtime.replaceManagedStorageService(operationUUID: UUID().uuidString.lowercased(), predecessor: previous) }
        await backend.replacement.wait(); await backend.replacement.resume()
        _ = try await replacing.value
        _ = try await runtime.createVolume(name: "recovered")
    }
    private var predecessor: StorageServiceTypes.Scope {
        .init(serviceEpoch: "11111111-1111-4111-8111-111111111111", workerUUID: "22222222-2222-4222-8222-222222222222")
    }
    @Test func cancellationRetainsReplacementAndExactRequestReplay() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let operation = UUID().uuidString.lowercased(), previous = predecessor
        let first = Task { try await runtime.replaceManagedStorageService(operationUUID: operation, predecessor: previous) }
        await backend.replacement.wait()
        first.cancel()
        await #expect(throws: EngineError.self) { try await runtime.createVolume(name: "fenced") }
        await #expect(throws: EngineError.self) {
            try await runtime.replaceManagedStorageService(operationUUID: UUID().uuidString.lowercased(), predecessor: previous)
        }
        await backend.replacement.resume()
        let result = try await first.value
        let replay = try await runtime.replaceManagedStorageService(operationUUID: operation, predecessor: previous)
        #expect(result == replay)
        #expect(await backend.requests.count == 1)
        _ = try await runtime.createVolume(name: "after")
    }
    @Test(arguments: [false, true]) func suspendedReservationCannotPublishAfterReplacement(volume: Bool) async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        await backend.configure(prepare: !volume, synchronize: volume)
        let stale = Task {
            if volume { _ = try await runtime.createVolume(name: "reserved") }
            else { _ = try await runtime.createContainer(.init(name: "stale", image: "fixture")) }
        }
        await backend.operation.wait()
        let previous = predecessor
        let replacement = Task { try await runtime.replaceManagedStorageService(operationUUID: UUID().uuidString.lowercased(), predecessor: previous) }
        await backend.replacement.wait()
        await backend.replacement.resume()
        _ = try await replacement.value
        // Revoked leases must not wait for the stale backend reply to return.
        if volume { _ = try await runtime.createVolume(name: "reserved") }
        else { _ = try await runtime.createContainer(.init(name: "stale", image: "fixture")) }
        await backend.operation.resume()
        await #expect(throws: EngineError.self) { try await stale.value }
        #expect(await runtime.listContainers(all: true).count == (volume ? 0 : 1))
    }
    @Test func staleReservationReleaseCannotReleaseSuccessorReservation() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        await backend.configure(prepare: true)
        let stale = Task { try await runtime.createContainer(.init(name: "reserved", image: "fixture")) }
        await backend.operation.wait()
        let previous = predecessor
        let replacing = Task { try await runtime.replaceManagedStorageService(operationUUID: UUID().uuidString.lowercased(), predecessor: previous) }
        await backend.replacement.wait(); await backend.replacement.resume()
        _ = try await replacing.value
        await backend.configureNextPreparation()
        let successor = Task { try await runtime.createContainer(.init(name: "reserved", image: "fixture")) }
        await backend.nextOperation.wait()
        await backend.operation.resume()
        await #expect(throws: EngineError.self) { try await stale.value }
        await #expect(throws: EngineError.self) { try await runtime.createContainer(.init(name: "reserved", image: "fixture")) }
        await backend.nextOperation.resume()
        _ = try await successor.value
    }

    @Test func staleStartCannotReleaseRecoveredStartLease() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let record = try await runtime.createContainer(.init(name: "starting", image: "fixture"))
        await backend.configure(prepare: true)
        let stale = Task { try await runtime.startContainer(record.id) }
        await backend.operation.wait()
        let previous = predecessor
        let replacing = Task { try await runtime.replaceManagedStorageService(operationUUID: UUID().uuidString.lowercased(), predecessor: previous) }
        await backend.replacement.wait(); await backend.replacement.resume()
        _ = try await replacing.value
        #expect(try await runtime.container(record.id).phase == .created)
        await backend.configureNextPreparation()
        let successor = Task { try await runtime.startContainer(record.id) }
        await backend.nextOperation.wait()
        await backend.operation.resume()
        await #expect(throws: EngineError.self) { try await stale.value }
        #expect(await runtime.listContainers(all: true).isEmpty)
        await #expect(throws: EngineError.self) { try await runtime.startContainer(record.id) }
        await backend.nextOperation.resume()
        try await successor.value
        #expect(try await runtime.container(record.id).phase == .running)
    }

    @Test func olderReplacementCannotThawNewerReplacement() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend(), hook = PersistenceHook()
        let runtime = try await EngineRuntime(root: root, backend: backend, beforePersistence: { await hook.run() })
        let previous = predecessor
        let first = Task { try await runtime.replaceManagedStorageService(operationUUID: UUID().uuidString.lowercased(), predecessor: previous) }
        await backend.replacement.wait(); await hook.arm(); await backend.replacement.resume()
        await hook.gate.wait(); await backend.loseWorker()
        let second = Task { try await runtime.replaceManagedStorageService(operationUUID: UUID().uuidString.lowercased(), predecessor: previous) }
        await backend.secondFenced.wait()
        await hook.gate.resume()
        await #expect(throws: EngineError.self) { try await first.value }
        await backend.nextReplacement.wait()
        await #expect(throws: EngineError.self) { try await runtime.createVolume(name: "still-replacing") }
        await backend.nextReplacement.resume()
        _ = try await second.value
        _ = try await runtime.createVolume(name: "after-second")
    }

    @Test func incompleteCensusCannotReopenLiveExecution() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let record = try await runtime.createContainer(.init(name: "live", image: "fixture"))
        try await runtime.startContainer(record.id)
        await backend.configureIncompleteCensus()
        let previous = predecessor
        let replacing = Task { try await runtime.replaceManagedStorageService(operationUUID: UUID().uuidString.lowercased(), predecessor: previous) }
        await backend.replacement.wait(); await backend.replacement.resume()
        await #expect(throws: EngineError.self) { try await replacing.value }
        await #expect(throws: EngineError.self) { try await runtime.createVolume(name: "unaccounted") }
    }

    @Test func finalSuccessorValidationFailureDoesNotThawWithoutLossCallback() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend(), hook = PersistenceHook()
        let runtime = try await EngineRuntime(root: root, backend: backend, beforePersistence: { await hook.run() })
        let previous = predecessor
        let replacing = Task { try await runtime.replaceManagedStorageService(operationUUID: UUID().uuidString.lowercased(), predecessor: previous) }
        await backend.replacement.wait(); await hook.arm(); await backend.replacement.resume()
        await hook.gate.wait()
        await backend.configureAvailabilityRejection()
        await hook.gate.resume()
        await #expect(throws: EngineError.self) { try await replacing.value }
        await #expect(throws: EngineError.self) { try await runtime.createVolume(name: "invalid-successor") }
        await #expect(throws: EngineError.self) {
            try await runtime.replaceManagedStorageService(operationUUID: UUID().uuidString.lowercased(), predecessor: previous)
        }
        #expect(await backend.requests.count == 1)
    }

    @Test func finalWorkerLossAllowsExplicitReplacementWithoutObserver() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        await backend.configureAvailabilityWorkerLoss()
        let previous = predecessor
        let first = Task { try await runtime.replaceManagedStorageService(operationUUID: UUID().uuidString.lowercased(), predecessor: previous) }
        await backend.replacement.wait(); await backend.replacement.resume()
        do {
            _ = try await first.value
            Issue.record("replacement unexpectedly accepted a lost successor")
        } catch ManagedStorageControlFailure.serviceUnavailable {}
        let scopes = await backend.availabilityScopes
        let deadSuccessor = try #require(scopes.first)
        await #expect(throws: EngineError.self) { try await runtime.createVolume(name: "lost-successor") }

        // No loseWorker()/observer delivery: the typed final status result alone
        // must admit another explicit operation against this exact dead successor.
        let second = Task { try await runtime.replaceManagedStorageService(operationUUID: UUID().uuidString.lowercased(), predecessor: deadSuccessor) }
        await backend.nextReplacement.wait()
        await #expect(throws: EngineError.self) { try await runtime.createVolume(name: "still-replacing") }
        await backend.nextReplacement.resume()
        _ = try await second.value
        #expect(await backend.requests.count == 2)
        #expect(await backend.requests.last?.predecessor == deadSuccessor)
        _ = try await runtime.createVolume(name: "after-lost-successor")
    }

    @Test func staleResizeCannotSucceedOrEmitAfterReplacement() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        var input = ContainerRecord(name: "resized", image: "fixture")
        input.tty = true
        let record = try await runtime.createContainer(input)
        try await runtime.startContainer(record.id)
        await backend.configureResize()
        let stale = Task { try await runtime.resizeContainer(record.id, width: 80, height: 24) }
        await backend.operation.wait()
        let previous = predecessor
        let replacing = Task { try await runtime.replaceManagedStorageService(operationUUID: UUID().uuidString.lowercased(), predecessor: previous) }
        await backend.replacement.wait(); await backend.replacement.resume()
        _ = try await replacing.value
        try await runtime.startContainer(record.id)
        await backend.operation.resume()
        await #expect(throws: EngineError.self) { try await stale.value }
        for await event in await runtime.events(until: Date()) {
            #expect(event.action != "resize")
        }
        try await runtime.resizeContainer(record.id, width: 120, height: 40)
        var resizeCount = 0
        for await event in await runtime.events(until: Date()) where event.action == "resize" {
            resizeCount += 1
            #expect(event.attributes["width"] == "120")
            #expect(event.attributes["height"] == "40")
        }
        #expect(resizeCount == 1)
    }

    @Test func finalAvailabilityDoesNotRequireAnotherReplacementAdmission() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend(), hook = PersistenceHook()
        let runtime = try await EngineRuntime(root: root, backend: backend, beforePersistence: { await hook.run() })
        let previous = predecessor
        let replacing = Task { try await runtime.replaceManagedStorageService(operationUUID: UUID().uuidString.lowercased(), predecessor: previous) }
        await backend.replacement.wait(); await hook.arm(); await backend.replacement.resume()
        await hook.gate.wait()
        // The accepted replacement can consume the final history slot. A fresh
        // replacement preflight would now fail, but successor readiness must not.
        await backend.configurePreflightRejection()
        await hook.gate.resume()
        let result = try await replacing.value
        #expect(await backend.preflightCount == 1)
        #expect(await backend.availabilityScopes == [result.successor])
        _ = try await runtime.createVolume(name: "available-at-capacity")
    }

    @Test(arguments: [0, 1, 2]) func invalidReplacementIDsAreRejectedBeforeBackendPreflight(field: Int) async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let invalid = "11111111-1111-1111-8111-111111111111" // Valid UUID, not UUIDv4.
        let operation = field == 0 ? invalid : UUID().uuidString.lowercased()
        let previous = StorageServiceTypes.Scope(
            serviceEpoch: field == 1 ? invalid : predecessor.serviceEpoch,
            workerUUID: field == 2 ? invalid : predecessor.workerUUID)
        await #expect(throws: EngineError.self) {
            try await runtime.replaceManagedStorageService(operationUUID: operation, predecessor: previous)
        }
        #expect(await backend.preflightCount == 0)
        #expect(await backend.fenceCount == 0)
        _ = try await runtime.createVolume(name: "invalid-request-unfenced")
    }

    @Test func failedReplacementNeverThawsOrdinaryWork() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        await backend.configure(fail: true)
        let operation = UUID().uuidString.lowercased(), previous = predecessor
        let task = Task { try await runtime.replaceManagedStorageService(operationUUID: operation, predecessor: previous) }
        await backend.replacement.wait(); await backend.replacement.resume()
        await #expect(throws: EngineError.self) { try await task.value }
        await #expect(throws: EngineError.self) { try await runtime.createVolume(name: "still-fenced") }
        await #expect(throws: EngineError.self) { try await runtime.replaceManagedStorageService(operationUUID: operation, predecessor: previous) }
        #expect(await backend.requests.count == 1)
    }
    @Test func invalidPreflightDoesNotFenceOrdinaryWork() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let record = try await runtime.createContainer(.init(name: "kept", image: "fixture"))
        try await runtime.startContainer(record.id)
        await backend.configurePreflightRejection()
        await #expect(throws: EngineError.self) {
            try await runtime.replaceManagedStorageService(operationUUID: UUID().uuidString.lowercased(), predecessor: predecessor)
        }
        #expect(await backend.fenceCount == 0)
        #expect(try await runtime.container(record.id).phase == .running)
        _ = try await runtime.createVolume(name: "unfenced")
    }

    @Test(arguments: [0, 1, 2]) func staleResourceResponsesCannotTouchRecoveredExecution(result: Int) async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let record = try await runtime.createContainer(.init(name: "resources", image: "fixture"))
        try await runtime.startContainer(record.id)
        await backend.configureResources(result: result)
        let stale = Task { try await runtime.updateContainer(record.id, memoryBytes: 128 * 1024 * 1024,
            nanoCPUs: nil, pidsLimit: nil, restartPolicy: nil) }
        await backend.operation.wait()
        let previous = predecessor
        let replacing = Task { try await runtime.replaceManagedStorageService(operationUUID: UUID().uuidString.lowercased(), predecessor: previous) }
        await backend.replacement.wait(); await backend.replacement.resume()
        _ = try await replacing.value
        // Start and commit new resources BEFORE releasing the old callback.
        try await runtime.startContainer(record.id)
        let successor = try await runtime.updateContainer(record.id, memoryBytes: 192 * 1024 * 1024,
            nanoCPUs: nil, pidsLimit: nil, restartPolicy: nil)
        await backend.operation.resume()
        await #expect(throws: EngineError.self) { try await stale.value }
        let current = try await runtime.container(record.id)
        #expect(current.phase == .running)
        #expect(current.startedAt == successor.startedAt)
        #expect(current.memoryBytes == successor.memoryBytes)
        #expect(await backend.resourceCount == 2)
        #expect(await backend.cleanupCount == 0)
        let durable = try await AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json")).loadRequired()
        #expect(durable.resourceUpdateIntents == nil)
        #expect(durable.containerFenceInstanceIDs == nil)
    }

    @Test func suspendedRemovalCannotDeleteRecreatedContainer() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let record = try await runtime.createContainer(.init(name: "removed", image: "fixture"))
        await backend.configureStop()
        let stale = Task { try await runtime.removeContainer(record.id, force: false) }
        await backend.operation.wait()
        let previous = predecessor
        let replacing = Task { try await runtime.replaceManagedStorageService(operationUUID: UUID().uuidString.lowercased(), predecessor: previous) }
        await backend.replacement.wait(); await backend.replacement.resume()
        _ = try await replacing.value
        let fenced = try await AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json")).loadRequired()
        #expect(fenced.cleanupPendingContainerIDs == [record.id])
        #expect(fenced.removalPendingContainerIDs == [record.id])
        #expect(fenced.containerFenceInstanceIDs == [record.id: record.instanceID])
        await #expect(throws: EngineError.self) { try await runtime.startContainer(record.id) }
        try await runtime.removeContainer(record.id, force: false)
        let successor = try await runtime.createContainer(record)
        try await runtime.startContainer(successor.id)
        await backend.operation.resume()
        await #expect(throws: EngineError.self) { try await stale.value }
        #expect(await backend.deleteCount == 1)
        #expect(try await runtime.container(successor.id).instanceID == successor.instanceID)
        #expect(try await runtime.container(successor.id).phase == .running)
    }

    @Test func replacementCensusPreservesCreatedAndHistoricalExitMetadata() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        var created = ContainerRecord(name: "created", image: "fixture")
        created.phase = .created
        var exited = ContainerRecord(name: "exited", image: "fixture")
        exited.phase = .exited; exited.exitCode = 23; exited.finishedAt = Date(timeIntervalSince1970: 1234)
        var running = ContainerRecord(name: "running", image: "fixture")
        running.phase = .running
        var paused = ContainerRecord(name: "paused", image: "fixture")
        paused.phase = .paused
        var quarantined = ContainerRecord(name: "quarantined", image: "fixture")
        quarantined.phase = .dead
        try await runtime.installReplacementInventory([created, exited, running, paused, quarantined], cleanup: [quarantined.id])
        let previous = predecessor
        let replacing = Task { try await runtime.replaceManagedStorageService(operationUUID: UUID().uuidString.lowercased(), predecessor: previous) }
        await backend.replacement.wait(); await backend.replacement.resume()
        _ = try await replacing.value
        #expect(try await runtime.container(created.id).phase == .created)
        #expect(try await runtime.container(created.id).finishedAt == nil)
        #expect(try await runtime.container(exited.id).exitCode == 23)
        #expect(try await runtime.container(exited.id).finishedAt == exited.finishedAt)
        for id in [running.id, paused.id] {
            #expect(try await runtime.container(id).phase == .exited)
            #expect(try await runtime.container(id).exitCode == 137)
        }
        let durable = try await AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json")).loadRequired()
        #expect(durable.cleanupPendingContainerIDs == [quarantined.id])
        #expect(durable.containerFenceInstanceIDs == [quarantined.id: quarantined.instanceID])
    }

    @Test func successorLossDuringFinalPersistenceNeverThawsEngine() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend(), hook = PersistenceHook()
        let runtime = try await EngineRuntime(root: root, backend: backend, beforePersistence: { await hook.run() })
        let previous = predecessor
        let replacing = Task { try await runtime.replaceManagedStorageService(operationUUID: UUID().uuidString.lowercased(), predecessor: previous) }
        await backend.replacement.wait()
        await hook.arm(); await backend.replacement.resume()
        await hook.gate.wait()
        await backend.loseWorker()
        await hook.gate.resume()
        await #expect(throws: EngineError.self) { try await replacing.value }
        await #expect(throws: EngineError.self) { try await runtime.createVolume(name: "must-stay-fenced") }
    }

    @Test func revokedExecCountDoesNotBlockRecoveredRestart() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let record = try await runtime.createContainer(.init(name: "exec", image: "fixture"))
        try await runtime.startContainer(record.id)
        await backend.configureExecPreparation()
        let stale = Task { try await runtime.createExec(container: record.id, configuration: .init(arguments: ["true"])) }
        await backend.operation.wait()
        let previous = predecessor
        let replacing = Task { try await runtime.replaceManagedStorageService(operationUUID: UUID().uuidString.lowercased(), predecessor: previous) }
        await backend.replacement.wait(); await backend.replacement.resume()
        _ = try await replacing.value
        try await runtime.startContainer(record.id)
        try await runtime.restartContainer(record.id)
        await backend.operation.resume()
        await #expect(throws: EngineError.self) { try await stale.value }
        #expect(try await runtime.container(record.id).phase == .running)
    }

}


private extension EngineRuntime {
    func installReplacementInventory(_ records: [ContainerRecord], cleanup: Set<String>) async throws {
        snapshot = EngineSnapshot(containers: records, networks: snapshot.networks, cleanupPendingContainerIDs: cleanup)
        try await persist()
    }
}

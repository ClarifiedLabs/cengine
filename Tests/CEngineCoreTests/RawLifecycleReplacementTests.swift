#if os(macOS) && DEBUG
import CEngineCore
import Foundation
import Synchronization
import Testing
@testable import CEngineRuntime

/// Backend orchestration over isolated native-protocol peers, not VM evidence.
@Suite(.serialized) @MainActor struct RawLifecycleReplacementTests {
    typealias Fixture = ManagedStorageLifecycleOwnerTests
    typealias Maintenance = ManagedStorageLifecycleReplacementMaintenanceTests

    @Test(arguments: [false, true]) func replacementReconcilesBeforeReopeningAdmission(dropFirst: Bool) async throws {
        let disk = try Fixture.Disk(); defer { disk.remove() }
        _ = try disk.root.createDirectory(named: "containers")
        let peer = try Fixture.Peer(disk.binding), owner = try disk.owner(peer)
        let transport = Maintenance.Transport(peer: peer, root: disk.root)
        transport.dropFirst = dropFirst
        try await owner.provisionFresh()
        try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding,
            nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        try await owner.connectWorkload()
        let backend = try RawManagedStorageBackend.adoptConnectedOwner(root: disk.root, owner: owner,
            names: SharedVolumeInitializationCoordinator())
        try await backend.reconcile(volumes: [], containers: [])
        let request = StorageServiceTypes.ReplacementRequest(operationUUID: UUID().uuidString.lowercased(),
            predecessor: .init(serviceEpoch: peer.serviceEpoch, workerUUID: peer.workerUUID), nowUnixSeconds: 1_800_000_100)
        let containments = Mutex(0)
        let result = try await backend.replaceService(request, volumes: [], containers: [], contain: {
            containments.withLock { $0 += 1 }
            return []
        })
        #expect(result.request == request)
        #expect(result.successor.serviceEpoch != request.predecessor.serviceEpoch)
        #expect(result.successor.workerUUID != request.predecessor.workerUUID)
        #expect(containments.withLock { $0 } == 1)
        #expect(transport.replaceCalls == (dropFirst ? 2 : 1))
        #expect(transport.base.configurations == 1)
        #expect(try !owner.journalSnapshot().reconciliationRequired)
        try backend.requireReconciled()
        _ = try owner.workloadSession()
        let replay = try await backend.replaceService(request, volumes: [], containers: [], contain: {
            Issue.record("completed replay repeated containment")
            return []
        })
        #expect(replay.successor == result.successor)
        #expect(containments.withLock { $0 } == 1)
        await owner.close()
    }

    @Test(arguments: [false, true], [false, true]) func readOnlyControlOverlapWaitsBeforeReplacement(notifications: Bool, publicPreflight: Bool) async throws {
        let disk = try Fixture.Disk(); defer { disk.remove() }
        _ = try disk.root.createDirectory(named: "containers")
        let peer = try Fixture.Peer(disk.binding), owner = try disk.owner(peer)
        let transport = Maintenance.Transport(peer: peer, root: disk.root)
        try await owner.provisionFresh()
        try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding,
            nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        try await owner.connectWorkload()
        let backend = try RawManagedStorageBackend.adoptConnectedOwner(root: disk.root, owner: owner,
            names: SharedVolumeInitializationCoordinator())
        try await backend.reconcile(volumes: [], containers: [])
        let request = StorageServiceTypes.ReplacementRequest(operationUUID: UUID().uuidString.lowercased(),
            predecessor: .init(serviceEpoch: peer.serviceEpoch, workerUUID: peer.workerUUID), nowUnixSeconds: 1_800_000_100)
        let gate = EngineServiceReplacementTests.Gate(), waiting = EngineServiceReplacementTests.Gate()
        transport.controlGate = gate
        let ready = try owner.workloadSession().service.ready
        peer.state.withLock { $0.simulatedReady = ready }
        var control: Task<Void, Error>?
        if notifications {
            backend.observeRetirements({ _, _ in Issue.record("unexpected retirement") },
                serviceLost: { Issue.record("replacement cancelled the live owner") })
        } else {
            control = Task { try await owner.validateServiceAvailability(request.predecessor) }
        }
        await gate.wait()
        let before = try owner.snapshot()
        owner.replacementAdmissionTimingForTesting = .init(now: { ProcessInfo.processInfo.systemUptime }, sleep: { interval in
            await waiting.signal()
            try await Task.sleep(for: .seconds(interval))
        })
        let replacements = Mutex(0)
        let replacement = Task {
            if publicPreflight { try await backend.validateServiceReplacement(request) }
            return try await backend.replaceService(request, volumes: [], containers: [], contain: {
                replacements.withLock { $0 += 1 }; return []
            })
        }
        await waiting.wait()
        #expect(try owner.snapshot() == before)
        #expect(transport.replaceCalls == 0 && peer.state.withLock { $0.rebinds } == 0)
        #expect(transport.cancellations.withLock { $0 } == 0)
        await gate.resume()
        try await control?.value
        let result = try await replacement.value
        #expect(result.request == request)
        #expect(transport.replaceCalls == 1 && peer.state.withLock { $0.rebinds } == 1)
        #expect(replacements.withLock { $0 } == 1)
        #expect(transport.cancellations.withLock { $0 } == 0)
        try backend.requireReconciled()
        await owner.close()
    }

    @Test func originalPreflightDrainsNativeNotificationWithoutCancellingOwner() async throws {
        let disk = try Fixture.Disk(); defer { disk.remove() }
        _ = try disk.root.createDirectory(named: "containers")
        let peer = try Fixture.Peer(disk.binding), owner = try disk.owner(peer)
        let transport = Maintenance.Transport(peer: peer, root: disk.root)
        try await owner.provisionFresh()
        try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding,
            nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        try await owner.connectWorkload()
        let backend = try RawManagedStorageBackend.adoptConnectedOwner(root: disk.root, owner: owner,
            names: SharedVolumeInitializationCoordinator())
        try await backend.reconcile(volumes: [], containers: [])
        let gate = EngineServiceReplacementTests.Gate()
        transport.controlGate = gate
        let ready = try owner.workloadSession().service.ready
        peer.state.withLock { $0.simulatedReady = ready }
        backend.observeRetirements({ _, _ in Issue.record("unexpected retirement") },
            serviceLost: { Issue.record("preflight cancelled live native owner") })
        await gate.wait()
        let before = try owner.snapshot()
        let epoch = try backend.freezeOriginalConsumerWork()
        backend.fenceOriginalConsumerFailure() // Same graceful policy for failure fencing.
        let join = Task { try await backend.joinOriginalConsumerWork(epoch, deadline: .init()) }
        #expect(transport.cancellations.withLock { $0 } == 0)
        #expect(try owner.snapshot() == before)
        await gate.resume()
        try await join.value
        #expect(transport.cancellations.withLock { $0 } == 0)
        #expect(try owner.snapshot() == before)
        _ = try owner.workloadSession()
        await owner.close()
    }

    @Test func originalServiceComparisonRetainsFullNativeReady() async throws {
        let disk = try Fixture.Disk(); defer { disk.remove() }
        let peer = try Fixture.Peer(disk.binding), owner = try disk.owner(peer)
        let transport = Maintenance.Transport(peer: peer, root: disk.root)
        try await owner.provisionFresh()
        try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding,
            nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        try await owner.connectWorkload()
        // A connected transport alone cannot expose a workload generation.
        #expect(throws: Maintenance.Owner.Failure.self) { _ = try owner.workloadSession() }
        _ = try owner.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator())
        let value = try owner.workloadSession().service.ready
        let configuration = try #require(transport.base.receivedConfigurations.first)
        let ready = try peer.ready(configuration.signed.grant)
        #expect(value == ready)
        // Comparison data may be copied, but cannot become a verified boot.
        let changed = StorageLifecycleServiceBootProtocol.Ready(identity: ready.identity,
            serviceEpoch: ready.serviceEpoch, workerUUID: ready.workerUUID,
            controllerEpoch: ready.controllerEpoch, controllerKey: ready.controllerKey,
            revision: ready.revision + 1, openRevision: ready.openRevision, bootstrapKey: ready.bootstrapKey,
            tlsRootDER: ready.tlsRootDER, serverDER: ready.serverDER, serverSPKI: ready.serverSPKI)
        #expect(value != changed)
        await owner.close()
        #expect(throws: (any Error).self) { _ = try owner.workloadSession() }
    }

    @Test(arguments: [false, true]) func notificationCallbackDrainIsGracefulAndTimeoutStaysFenced(timeout: Bool) async throws {
        let disk = try Fixture.Disk(); defer { disk.remove() }
        _ = try disk.root.createDirectory(named: "containers")
        let peer = try Fixture.Peer(disk.binding), owner = try disk.owner(peer)
        let transport = Maintenance.Transport(peer: peer, root: disk.root)
        try await owner.provisionFresh()
        try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding,
            nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        try await owner.connectWorkload()
        let backend = try RawManagedStorageBackend.adoptConnectedOwner(root: disk.root, owner: owner,
            names: SharedVolumeInitializationCoordinator())
        try await backend.reconcile(volumes: [], containers: [])
        let request = StorageServiceTypes.ReplacementRequest(operationUUID: UUID().uuidString.lowercased(),
            predecessor: .init(serviceEpoch: peer.serviceEpoch, workerUUID: peer.workerUUID), nowUnixSeconds: 1_800_000_100)
        let callback = EngineServiceReplacementTests.Gate(), preflight = EngineServiceReplacementTests.Gate()
        let cancelled = Mutex(0), containments = Mutex(0)
        transport.notificationWorkerLost = true
        backend.observeRetirements({ _, _ in Issue.record("unexpected retirement") }, serviceLost: {
            await withTaskCancellationHandler { await callback.pause() } onCancel: { cancelled.withLock { $0 += 1 } }
        })
        await callback.wait()
        let before = try owner.snapshot()
        owner.replacementAdmissionTimingForTesting = .init(now: {
            Task { await preflight.signal() }
            return ProcessInfo.processInfo.systemUptime
        }, sleep: { try await Task.sleep(for: .seconds($0)) })
        let replacement = Task {
            try await backend.replaceService(request, volumes: [], containers: [], contain: {
                containments.withLock { $0 += 1 }; return []
            })
        }
        await preflight.wait()
        #expect(try owner.snapshot() == before)
        #expect(transport.replaceCalls == 0 && peer.state.withLock { $0.rebinds } == 0)
        replacement.cancel() // The retained maintenance task still owns the drain.
        if timeout {
            await #expect(throws: (any Error).self) { _ = try await replacement.value }
            #expect(throws: (any Error).self) { try backend.requireReconciled() }
            #expect(try owner.snapshot() == before)
            #expect(transport.replaceCalls == 0 && containments.withLock { $0 } == 0)
        }
        await callback.resume()
        if timeout {
            await #expect(throws: (any Error).self) {
                _ = try await backend.replaceService(request, volumes: [], containers: [], contain: {
                    Issue.record("unknown drain must not retry or contain as replacement"); return []
                })
            }
            #expect(transport.replaceCalls == 0)
        } else {
            #expect(try await replacement.value.request == request)
            #expect(transport.replaceCalls == 1 && containments.withLock { $0 } == 1)
            try backend.requireReconciled()
        }
        #expect(cancelled.withLock { $0 } == 0 && transport.cancellations.withLock { $0 } == 0)
        await owner.close()
    }

    @Test(arguments: [false, true]) func expiredPollOnlyRetriesAfterContainment(containmentFails: Bool) async throws {
        let disk = try Fixture.Disk(); defer { disk.remove() }
        _ = try disk.root.createDirectory(named: "containers")
        let peer = try Fixture.Peer(disk.binding), owner = try disk.owner(peer)
        let transport = Maintenance.Transport(peer: peer, root: disk.root)
        try await owner.provisionFresh()
        try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding,
            nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        try await owner.connectWorkload()
        let backend = try RawManagedStorageBackend.adoptConnectedOwner(root: disk.root, owner: owner,
            names: SharedVolumeInitializationCoordinator())
        try await backend.reconcile(volumes: [], containers: [])
        let request = StorageServiceTypes.ReplacementRequest(operationUUID: UUID().uuidString.lowercased(),
            predecessor: .init(serviceEpoch: peer.serviceEpoch, workerUUID: peer.workerUUID), nowUnixSeconds: 1_800_000_100)
        owner.replacementAttemptTimeoutForTesting = 0.02
        transport.keepPending = true
        let containments = Mutex(0)
        do {
            _ = try await backend.replaceService(request, volumes: [], containers: [], contain: {
                containments.withLock { $0 += 1 }
                if containmentFails { throw Maintenance.Owner.Failure.incomplete }
                return []
            })
            Issue.record("expired attempt succeeded")
        } catch {
            #expect((error is Maintenance.Owner.RetryableReplacementTimeout) == !containmentFails)
        }
        #expect(containments.withLock { $0 } == 1)
        #expect(throws: (any Error).self) { try backend.requireReconciled() }
        #expect(throws: (any Error).self) { _ = try owner.workloadSession() }
        var mismatch = request; mismatch.nowUnixSeconds += 1
        await Fixture().fails { _ = try await backend.replaceService(mismatch, volumes: [], containers: [], contain: { [] }) }
        owner.replacementAttemptTimeoutForTesting = 30
        transport.keepPending = false
        if containmentFails {
            await Fixture().fails { _ = try await backend.replaceService(request, volumes: [], containers: [], contain: {
                Issue.record("failed containment must remain cached"); return []
            }) }
            #expect(transport.statusCalls == 0)
        } else {
            let gate = EngineServiceReplacementTests.Gate()
            transport.statusGate = gate
            let first = Task { try await backend.replaceService(request, volumes: [], containers: [], contain: {
                containments.withLock { $0 += 1 }; return []
            }) }
            await gate.wait()
            let second = Task { try await backend.replaceService(request, volumes: [], containers: [], contain: {
                Issue.record("concurrent retry repeated containment"); return []
            }) }
            await gate.resume()
            let firstResult = try await first.value
            let secondResult = try await second.value
            #expect(firstResult == secondResult)
            #expect(containments.withLock { $0 } == 2)
            #expect(transport.replaceCalls == 1 && transport.statusCalls == 1)
            #expect(throws: (any Error).self) { _ = try owner.validateServiceReplacementRetry(request) }
            let completed = try await backend.replaceService(request, volumes: [], containers: [], contain: {
                Issue.record("completed retry repeated containment"); return []
            })
            #expect(completed == firstResult)
            #expect(containments.withLock { $0 } == 2)
            #expect(transport.replaceCalls == 1 && transport.statusCalls == 1)
            try backend.requireReconciled()
        }
        await owner.close()
    }

    /// Fake VM backend delegates to the real owner/cache/containment path. No
    /// public error constructor is needed to test the Engine retry boundary.
    @MainActor final class EngineBackend: ContainerBackend {
        let managed: RawManagedStorageBackend
        var requests: [StorageServiceTypes.ReplacementRequest] = []
        let containments = Mutex(0)
        init(_ managed: RawManagedStorageBackend) { self.managed = managed }
        func pullImage(_: String, platform _: String) async throws {}
        func prepare(_: ContainerRecord) async throws {}
        func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
        func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
        func wait(_: ContainerRecord) async throws -> Int32 { 0 }
        func delete(_: ContainerRecord) async throws {}
        func validateManagedStorageReplacement(_ request: StorageServiceTypes.ReplacementRequest) async throws {
            try await managed.validateServiceReplacement(request)
        }
        func validateManagedStorageAvailability(_ scope: StorageServiceTypes.Scope) async throws {
            try await managed.validateServiceAvailability(scope)
        }
        func replaceManagedStorageService(_ request: StorageServiceTypes.ReplacementRequest,
            volumes: [VolumeRecord], containers: [ContainerRecord]) async throws -> BackendServiceReplacementResult {
            requests.append(request)
            return try await managed.replaceService(request, volumes: volumes, containers: containers, contain: { @MainActor [self] in
                containments.withLock { $0 += 1 }; return []
            })
        }
    }

    @Test func engineDelayedTimeoutKeepsIdentityFenceAndJoinsConcurrentRetry() async throws {
        let disk = try Fixture.Disk(); defer { disk.remove() }
        _ = try disk.root.createDirectory(named: "containers")
        let peer = try Fixture.Peer(disk.binding), owner = try disk.owner(peer)
        let transport = Maintenance.Transport(peer: peer, root: disk.root)
        try await owner.provisionFresh()
        try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding,
            nowUnixSeconds: UInt64(Date().timeIntervalSince1970) - 100, lifetimeSeconds: 3600)
        try await owner.connectWorkload()
        let managed = try RawManagedStorageBackend.adoptConnectedOwner(root: disk.root, owner: owner,
            names: SharedVolumeInitializationCoordinator())
        try await managed.reconcile(volumes: [], containers: [])
        let backend = EngineBackend(managed)
        let runtime = try await EngineRuntime(root: disk.url.appending(path: "engine-test"), backend: backend)
        let operation = UUID().uuidString.lowercased()
        let predecessor = StorageServiceTypes.Scope(serviceEpoch: peer.serviceEpoch, workerUUID: peer.workerUUID)
        owner.replacementAttemptTimeoutForTesting = 0.02
        let delayed = EngineServiceReplacementTests.Gate()
        transport.replacementGate = delayed
        let first = Task { try await runtime.replaceManagedStorageService(operationUUID: operation, predecessor: predecessor) }
        await delayed.wait()
        first.cancel() // Cannot abandon owned native IO.
        try await Task.sleep(for: .milliseconds(40))
        #expect(backend.containments.withLock { $0 } == 0)
        await #expect(throws: EngineError.self) { _ = try await runtime.createVolume(name: "still-fenced") }
        await delayed.resume()
        await #expect(throws: Maintenance.Owner.RetryableReplacementTimeout.self) { _ = try await first.value }
        #expect(backend.containments.withLock { $0 } == 1)
        let frozen = try #require(backend.requests.first)
        #expect(try owner.validateServiceReplacementRetry(frozen).request == frozen)
        await #expect(throws: EngineError.self) { _ = try await runtime.createVolume(name: "timeout-fenced") }
        let wrong = StorageServiceTypes.Scope(serviceEpoch: predecessor.serviceEpoch, workerUUID: UUID().uuidString.lowercased())
        await #expect(throws: EngineError.self) { _ = try await runtime.replaceManagedStorageService(operationUUID: operation, predecessor: wrong) }
        await Fixture().fails { _ = try await runtime.replaceManagedStorageService(operationUUID: UUID().uuidString.lowercased(), predecessor: predecessor) }
        // Cross a wall-clock second so reminting Engine's request time fails.
        try await Task.sleep(for: .milliseconds(1100))
        #expect(transport.replaceCalls == 1 && transport.statusCalls == 0)
        #expect(transport.availabilityScopes.isEmpty)
        owner.replacementAttemptTimeoutForTesting = 30
        let retryGate = EngineServiceReplacementTests.Gate()
        transport.statusGate = retryGate
        let retry = Task { try await runtime.replaceManagedStorageService(operationUUID: operation, predecessor: predecessor) }
        await retryGate.wait()
        let concurrent = Task { try await runtime.replaceManagedStorageService(operationUUID: operation, predecessor: predecessor) }
        await retryGate.resume()
        let result = try await retry.value
        #expect(try await concurrent.value == result)
        #expect(result.request == frozen)
        #expect(backend.requests == [frozen, frozen])
        #expect(backend.containments.withLock { $0 } == 2)
        #expect(transport.replaceCalls == 1 && transport.statusCalls == 1)
        #expect(transport.base.configurations == 1)
        #expect(transport.availabilityScopes == [result.successor])
        #expect(throws: (any Error).self) { _ = try owner.validateServiceReplacementRetry(frozen) }
        #expect(try await runtime.replaceManagedStorageService(operationUUID: operation, predecessor: predecessor) == result)
        #expect(backend.requests == [frozen, frozen])
        #expect(backend.containments.withLock { $0 } == 2)
        #expect(transport.availabilityScopes == [result.successor])
        _ = try await runtime.createVolume(name: "reopened")
        await owner.close()
    }

    @Test func failedNativeReplacementStillContainsAndNeverReopensAdmission() async throws {
        let disk = try Fixture.Disk(); defer { disk.remove() }
        _ = try disk.root.createDirectory(named: "containers")
        let peer = try Fixture.Peer(disk.binding), owner = try disk.owner(peer)
        let transport = Maintenance.Transport(peer: peer, root: disk.root)
        transport.failReplacement = true
        try await owner.provisionFresh()
        try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding,
            nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        try await owner.connectWorkload()
        let backend = try RawManagedStorageBackend.adoptConnectedOwner(root: disk.root, owner: owner,
            names: SharedVolumeInitializationCoordinator())
        try await backend.reconcile(volumes: [], containers: [])
        let request = StorageServiceTypes.ReplacementRequest(operationUUID: UUID().uuidString.lowercased(),
            predecessor: .init(serviceEpoch: peer.serviceEpoch, workerUUID: peer.workerUUID), nowUnixSeconds: 1_800_000_100)
        let containments = Mutex(0)
        for _ in 0..<2 {
            await Fixture().fails {
                _ = try await backend.replaceService(request, volumes: [], containers: [], contain: {
                    containments.withLock { $0 += 1 }
                    return []
                })
            }
        }
        #expect(containments.withLock { $0 } == 1)
        #expect(transport.replaceCalls == 1)
        #expect(transport.base.configurations == 1)
        #expect(try owner.snapshot().nativeReplacementAttempted == true)
        #expect(throws: (any Error).self) { try backend.requireReconciled() }
        #expect(throws: (any Error).self) { _ = try owner.workloadSession() }
        await owner.close()
    }
}
#endif

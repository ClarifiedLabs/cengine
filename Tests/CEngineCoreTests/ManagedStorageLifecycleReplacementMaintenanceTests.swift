#if os(macOS) && DEBUG
import CEngineCore
import Foundation
import Synchronization
import Testing
@testable import CEngineRuntime

/// Isolated metadata/transport tests only, not native replacement qualification.
@Suite(.serialized) @MainActor struct ManagedStorageLifecycleReplacementMaintenanceTests {
    typealias Fixture = ManagedStorageLifecycleOwnerTests
    typealias Owner = ManagedStorageLifecycleOwner
    typealias Boot = StorageLifecycleServiceBootProtocol

    @Test(arguments: [false, true]) func exactNativeReplacementAndMandatoryAdmission(dropFirst: Bool) async throws {
        let disk = try Fixture.Disk(); defer { disk.remove() }
        let peer = try Fixture.Peer(disk.binding), owner = try disk.owner(peer)
        let transport = Transport(peer: peer, root: disk.root)
        transport.dropFirst = dropFirst
        try await owner.provisionFresh()
        try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding,
            nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        try await owner.connectWorkload()
        let names = SharedVolumeInitializationCoordinator()
        let original = try owner.makeWorkloadCoordinator(names: names)
        let operation = UUID().uuidString.lowercased()
        let scope = StorageServiceTypes.Scope(serviceEpoch: peer.serviceEpoch, workerUUID: peer.workerUUID)
        let session = try await owner.replaceService(operationID: operation, predecessor: scope,
            nowUnixSeconds: 1_800_000_100, lifetimeSeconds: 1800, names: names)
        #expect(session.lifecycle !== original)
        #expect(session.serviceScope.serviceEpoch != session.request.configuration.reopen?.request.predecessor.context.serviceEpoch)
        await Fixture().fails { _ = try await owner.queryWorkload() }
        await Fixture().fails { try await owner.connectWorkload() }
        await Fixture().fails { try await owner.validateServiceAvailability(session.serviceScope) }
        await Fixture().fails { _ = try await owner.retirementNotifications() }
        #expect(throws: (any Error).self) { _ = try owner.workloadSession() }
        let context = try ManagedStorageControlClient.Context(store: peer.binding.storeID.rawValue,
            serviceEpoch: session.serviceScope.serviceEpoch, controllerEpoch: 1,
            controllerKey: session.request.configuration.signed.grant.newKey,
            provenanceReference: owner.snapshot().provenanceReference,
            lifecycleIdentity: session.request.configuration.signed.grant.identity)
        await Fixture().fails { _ = try await owner.workloadControl(.query, context: context) }

        #expect(session.request.predecessorWorkerUUID == peer.workerUUID)
        #expect(transport.replaceCalls == (dropFirst ? 2 : 1))
        #expect(transport.statusCalls == 1)
        #expect(transport.base.configurations == 1) // Never configure a second VM.
        #expect(transport.requests.allSatisfy { $0 == session.request })
        #expect(peer.state.withLock { $0.rebinds } == 1)
        #expect(owner.hasRecoveryPermission)
        #expect(try owner.maintenanceSnapshot(session).reconciliationRequired)
        var commits = 0
        #expect(throws: (any Error).self) {
            try owner.completeServiceReplacement(session) { commits += 1 }
        }
        #expect(commits == 0)
        #expect(throws: (any Error).self) { _ = try owner.makeWorkloadCoordinator(names: names) }
        try await session.lifecycle.reconcileStartup()
        var inventoryCommitted = false, commitAttempts = 0
        #expect(throws: (any Error).self) {
            try owner.completeServiceReplacement(session) {
                commitAttempts += 1
                inventoryCommitted = true // Durable side effect before a lost completion.
                do {
                    try owner.completeServiceReplacement(session) { Issue.record("reentrant commit") }
                    Issue.record("reentrant completion was admitted")
                } catch {}
                do {
                    try owner.planReplacementVolumes([], session: session)
                    Issue.record("reentrant planning was admitted")
                } catch {}
                throw Owner.Failure.incomplete
            }
        }
        #expect(inventoryCommitted && commitAttempts == 1)
        let retry = try await owner.replaceService(operationID: operation, predecessor: scope,
            nowUnixSeconds: 1_800_000_100, lifetimeSeconds: 1800, names: names)
        #expect(retry.lifecycle === session.lifecycle)
        #expect(transport.replaceCalls == (dropFirst ? 2 : 1))
        try owner.completeServiceReplacement(session) {
            commitAttempts += 1
            if !inventoryCommitted { inventoryCommitted = true }
            commits += 1
        }
        #expect(commitAttempts == 2 && inventoryCommitted)
        #expect(commits == 1)
        #expect(throws: (any Error).self) { _ = try owner.maintenanceSnapshot(session) }
        #expect(try owner.snapshot().pendingService == nil)
        #expect(try owner.snapshot().serviceReplacement == session.request)
        await owner.close()
    }

    @Test func authorizedMaintenanceRetireReconnectsExactlyOnce() async throws {
        let disk = try Fixture.Disk(); defer { disk.remove() }
        let peer = try Fixture.Peer(disk.binding), owner = try disk.owner(peer)
        let transport = Transport(peer: peer, root: disk.root)
        try await owner.provisionFresh()
        try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding,
            nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        try await owner.connectWorkload()
        let names = SharedVolumeInitializationCoordinator()
        _ = try owner.makeWorkloadCoordinator(names: names)
        let session = try await owner.replaceService(operationID: Fixture.id(),
            predecessor: .init(serviceEpoch: peer.serviceEpoch, workerUUID: peer.workerUUID),
            nowUnixSeconds: 1_800_000_100, lifetimeSeconds: 1800, names: names)
        try await session.lifecycle.reconcileStartup()
        let journal = try #require(owner.isolatedTestIntents)
        let files = try HostIntentFixture(); defer { files.remove() }
        let volume = files.volumes[0], template = files.intent([volume])
        try session.lifecycle.planVolumes([volume])
        let ready = try owner.maintenanceServiceProjection(session).ready
        let plan = HostStorageIntents.Intent(id: template.id, store: ready.identity.store,
            container: template.container, containerInstance: template.containerInstance,
            launch: template.launch, specificationDigest: template.specificationDigest,
            serviceEpoch: ready.serviceEpoch, controllerEpoch: ready.controllerEpoch, controllerKey: ready.controllerKey,
            prepare: template.prepare, reserveOperation: template.reserveOperation,
            completeOperation: template.completeOperation, replaceOperation: template.replaceOperation,
            mounts: template.mounts, slots: template.slots, version: 1, phase: .planned,
            prepareCompleted: false, cleanUnmount: false)
        let token = try journal.plan(plan)
        // Seed a drained PREPARE plus a live runtime attachment in the real journal.
        // The maintenance coordinator, not a fabricated capability, submits Retire.
        _ = try journal.update(token) { intent in
            for index in intent.slots.indices {
                let slot = intent.slots[index]
                intent.slots[index].key = HostStorageIntents.hash(Data(slot.attachment.utf8))
                if slot.role == "prepare" {
                    intent.slots[index].receipt = .init(try .init(schema: 3, store: intent.store,
                        volume: slot.volume, attachment: slot.attachment, prepare: intent.prepare,
                        launch: intent.launch, revision: 2))
                }
            }
            intent.guestCompletion = .init(prepare: intent.prepare, containerInstance: intent.containerInstance,
                launch: intent.launch, succeeded: true, cleanCopyUp: true, evidenceDigest: String(repeating: "e", count: 64))
            intent.prepareCompleted = true; intent.cleanUnmount = true; intent.phase = .running
        }
        let runtime = try #require(plan.slots.first { $0.role == "runtime" })
        let request = ManagedStorageControlProtocol.ControlRequest.retire(try .init(operation: runtime.retireOperation,
            store: plan.store, volume: runtime.volume, attachment: runtime.attachment, launch: plan.launch))
        let context = try ManagedStorageControlClient.Context(store: plan.store, serviceEpoch: plan.serviceEpoch,
            controllerEpoch: plan.controllerEpoch, controllerKey: plan.controllerKey,
            provenanceReference: owner.snapshot().provenanceReference, lifecycleIdentity: ready.identity)
        await #expect(throws: Owner.Failure.self) { _ = try await owner.workloadControl(request, context: context) }
        let receipt = try ManagedStorageControlProtocol.Receipt(schema: 3, store: plan.store,
            volume: runtime.volume, attachment: runtime.attachment, launch: plan.launch, revision: 3)
        let bytes = try ControllerJSON.object(["id": .number(1), "receipt": ControllerJSON.from(receipt)]).bytes()
        let sent = Mutex<[Data]>([])
        peer.state.withLock { $0.workloadEvents = []; $0.workloadResponder = { actual in
            let count = try sent.withLock { values in values.append(try actual.durableBytes()); return values.count }
            if count == 1 { throw StorageLifecycleChildProcess.Failure.serviceUnavailable }
            return bytes
        } }
        let before = try owner.snapshot(), connections = transport.base.workloadConnections
        let allocations = peer.state.withLock { $0.allocations }
        try await session.lifecycle.retireLaunch(plan.id)
        let expected = try request.durableBytes()
        #expect(sent.withLock { $0 } == [expected, expected])
        #expect(transport.base.workloadConnections == connections + 1)
        #expect(peer.state.withLock { $0.workloadEvents } == ["transport", "child"])
        #expect(peer.state.withLock { $0.allocations } == allocations)
        #expect(try owner.snapshot() == before)
        let retired = try journal.intent(journal.token(for: plan.id))
        #expect(retired.phase == .retired && retired.slots.allSatisfy { $0.receipt != nil })
        #expect(try journal.snapshot().operations[runtime.retireOperation] == expected)
        _ = try owner.maintenanceSnapshot(session) // Permission remains the same retained session.
        await owner.close()
    }

    @Test func mismatchedScopeCannotStageAndFailedResultRetainsFence() async throws {
        let disk = try Fixture.Disk(); defer { disk.remove() }
        let peer = try Fixture.Peer(disk.binding), owner = try disk.owner(peer)
        let transport = Transport(peer: peer, root: disk.root)
        transport.failReplacement = true
        try await owner.provisionFresh()
        try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding,
            nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        try await owner.connectWorkload()
        let names = SharedVolumeInitializationCoordinator()
        _ = try owner.makeWorkloadCoordinator(names: names)
        let operation = UUID().uuidString.lowercased()
        let wrong = StorageServiceTypes.Scope(serviceEpoch: peer.serviceEpoch, workerUUID: UUID().uuidString.lowercased())
        await Fixture().fails {
            _ = try await owner.replaceService(operationID: operation, predecessor: wrong,
                nowUnixSeconds: 1_800_000_100, lifetimeSeconds: 1800, names: names)
        }
        #expect(try owner.snapshot().pendingService == nil)
        let scope = StorageServiceTypes.Scope(serviceEpoch: peer.serviceEpoch, workerUUID: peer.workerUUID)
        for id in [operation, operation, UUID().uuidString.lowercased()] {
            await Fixture().fails {
                _ = try await owner.replaceService(operationID: id, predecessor: scope,
                    nowUnixSeconds: 1_800_000_100, lifetimeSeconds: 1800, names: names)
            }
        }
        #expect(transport.replaceCalls == 1)
        #expect(peer.state.withLock { $0.rebinds } == 0)
        #expect(try owner.snapshot().pendingService?.request.operationID == operation)
        #expect(try owner.snapshot().serviceReplacement != nil)
        #expect(try owner.snapshot().nativeReplacementAttempted == true)
        await Fixture().fails { try await owner.reopenService(using: transport, expectedBinding: peer.bootBinding) }
        #expect(transport.base.configurations == 1)
        await Fixture().fails { _ = try await owner.queryWorkload() }
        await owner.close()
    }

    @Test(arguments: [false, true]) func expiredAttemptRetainsExactRequestAndAdmission(admitted: Bool) async throws {
        let disk = try Fixture.Disk(); defer { disk.remove() }
        let peer = try Fixture.Peer(disk.binding), owner = try disk.owner(peer)
        let transport = Transport(peer: peer, root: disk.root)
        try await owner.provisionFresh()
        try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding,
            nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        try await owner.connectWorkload()
        let names = SharedVolumeInitializationCoordinator()
        _ = try owner.makeWorkloadCoordinator(names: names)
        let operation = UUID().uuidString.lowercased()
        let scope = StorageServiceTypes.Scope(serviceEpoch: peer.serviceEpoch, workerUUID: peer.workerUUID)
        let request = StorageServiceTypes.ReplacementRequest(operationUUID: operation,
            predecessor: scope, nowUnixSeconds: 1_800_000_100)
        try owner.validateServiceReplacement(request)
        var invalid = request; invalid.predecessor.workerUUID = UUID().uuidString.lowercased()
        #expect(throws: (any Error).self) { try owner.validateServiceReplacement(invalid) }
        transport.dropAll = !admitted; transport.keepPending = admitted
        owner.replacementAttemptTimeoutForTesting = 0.02
        await #expect(throws: Owner.RetryableReplacementTimeout.self) {
            _ = try await owner.replaceService(operationID: operation, predecessor: scope,
                nowUnixSeconds: request.nowUnixSeconds, lifetimeSeconds: 1800, names: names)
        }
        let boundary = try owner.validateServiceReplacementRetry(request)
        #expect(boundary.request == request)
        var changedTime = request; changedTime.nowUnixSeconds += 1
        #expect(throws: (any Error).self) { _ = try owner.validateServiceReplacementRetry(changedTime) }
        #expect(throws: (any Error).self) { _ = try owner.validateServiceReplacementRetry(invalid) }
        let frozen = try #require(owner.snapshot().serviceReplacement)
        let calls = transport.replaceCalls + transport.statusCalls
        try await Task.sleep(for: .milliseconds(40))
        #expect(transport.replaceCalls + transport.statusCalls == calls) // No unbounded background poll.
        #expect(try owner.snapshot().nativeReplacementAttempted == true)
        #expect(peer.state.withLock { $0.rebinds } == 0)
        await Fixture().fails { try await owner.reopenService(using: transport, expectedBinding: peer.bootBinding) }
        await Fixture().fails {
            _ = try await owner.replaceService(operationID: UUID().uuidString.lowercased(), predecessor: scope,
                nowUnixSeconds: request.nowUnixSeconds, lifetimeSeconds: 1800, names: names)
        }
        #expect(transport.replaceCalls + transport.statusCalls == calls)
        try owner.validateServiceReplacement(request)
        transport.dropAll = false; transport.keepPending = false
        owner.replacementAttemptTimeoutForTesting = 30
        let replaceCalls = transport.replaceCalls
        let session = try await owner.replaceService(operationID: operation, predecessor: scope,
            nowUnixSeconds: request.nowUnixSeconds, lifetimeSeconds: 1800, names: names)
        #expect(session.request == frozen)
        #expect(transport.requests.allSatisfy { $0 == frozen })
        #expect(transport.replaceCalls == replaceCalls + (admitted ? 0 : 1))
        #expect(transport.base.configurations == 1)
        try await session.lifecycle.reconcileStartup()
        try owner.completeServiceReplacement(session) {}
        await owner.close()
    }

    @Test(arguments: ["timeout", "cancel", "invalid-pair", "invalid-operation"]) func admissionRefusesWithoutMutation(reason: String) async throws {
        let disk = try Fixture.Disk(); defer { disk.remove() }
        let peer = try Fixture.Peer(disk.binding), owner = try disk.owner(peer)
        let transport = Transport(peer: peer, root: disk.root)
        try await owner.provisionFresh()
        try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding,
            nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        try await owner.connectWorkload()
        _ = try owner.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator())
        var request = StorageServiceTypes.ReplacementRequest(operationUUID: UUID().uuidString.lowercased(),
            predecessor: .init(serviceEpoch: peer.serviceEpoch, workerUUID: peer.workerUUID), nowUnixSeconds: 1_800_000_100)
        let gate = EngineServiceReplacementTests.Gate(), waiting = EngineServiceReplacementTests.Gate()
        transport.controlGate = gate
        let control = Task { try await owner.retirementNotifications() }
        await gate.wait()
        let before = try owner.snapshot()
        #expect(throws: Owner.Failure.self) { try owner.validateServiceReplacement(request) }
        let elapsed = Mutex<TimeInterval>(0), sleeps = Mutex(0)
        owner.replacementAdmissionTimingForTesting = .init(now: { elapsed.withLock { $0 } }, sleep: { interval in
            sleeps.withLock { $0 += 1 }
            if reason == "cancel" {
                await waiting.signal()
                try await Task.sleep(for: .seconds(30))
            } else { elapsed.withLock { $0 += interval } }
        })
        if reason == "invalid-pair" { request.predecessor.workerUUID = UUID().uuidString.lowercased() }
        if reason == "invalid-operation" { request.operationUUID = "invalid" }
        let attempt = Task { try await owner.awaitServiceReplacementAdmission(request) }
        if reason == "cancel" { await waiting.wait(); attempt.cancel() }
        await #expect(throws: (any Error).self) { try await attempt.value }
        if reason == "timeout" { #expect(elapsed.withLock { $0 } == 5) }
        if reason.hasPrefix("invalid") { #expect(sleeps.withLock { $0 } == 0) }
        #expect(try owner.snapshot() == before)
        #expect(transport.replaceCalls == 0 && transport.cancellations.withLock { $0 } == 0)
        #expect(peer.state.withLock { $0.rebinds } == 0)
        await gate.resume()
        _ = try await control.value
        await owner.close()
    }

    @Test func genuineBlockedStateIsNotRetried() async throws {
        let disk = try Fixture.Disk(); defer { disk.remove() }
        let peer = try Fixture.Peer(disk.binding), owner = try disk.owner(peer)
        let transport = Transport(peer: peer, root: disk.root)
        try await owner.provisionFresh()
        try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding,
            nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        try await owner.connectWorkload()
        // No workload lifecycle: this is not a transient read-only command.
        let request = StorageServiceTypes.ReplacementRequest(operationUUID: UUID().uuidString.lowercased(),
            predecessor: .init(serviceEpoch: peer.serviceEpoch, workerUUID: peer.workerUUID), nowUnixSeconds: 1_800_000_100)
        owner.replacementAdmissionTimingForTesting = .init(now: { 0 }, sleep: { _ in
            Issue.record("genuine blocked state was retried")
            throw CancellationError()
        })
        await #expect(throws: Owner.Failure.self) { try await owner.awaitServiceReplacementAdmission(request) }
        #expect(transport.replaceCalls == 0 && transport.cancellations.withLock { $0 } == 0)
        #expect(try owner.snapshot().pendingService == nil)
        await owner.close()
    }

    @MainActor final class Transport: ManagedStorageLifecycleServiceTransport {
        let base: Fixture.Transport
        let peer: Fixture.Peer
        let root: PersistentStateDirectory
        var requests: [Boot.ReplacementRequest] = []
        var replaceCalls = 0, statusCalls = 0
        var availabilityScopes: [StorageServiceTypes.Scope] = []
        var dropFirst = false, failReplacement = false, dropAll = false, keepPending = false
        var replacementGate: EngineServiceReplacementTests.Gate?
        var statusGate: EngineServiceReplacementTests.Gate?
        var controlGate: EngineServiceReplacementTests.Gate?
        var notificationWorkerLost = false
        nonisolated let cancellations = Mutex(0)
        init(peer: Fixture.Peer, root: PersistentStateDirectory) {
            self.peer = peer; self.root = root; base = Fixture.Transport(peer: peer, root: root)
        }
        nonisolated func cancel() { cancellations.withLock { $0 += 1 } }
        func configure(_ configuration: Boot.Configuration) async throws -> ManagedStorageLifecycleServiceReady {
            try await base.configure(configuration)
        }
        func command(_ frame: Boot.Frame) async throws -> Boot.Frame {
            if frame.command == .notifications || frame.command == .serviceStatus {
                if let gate = controlGate { controlGate = nil; await gate.pause() }
            }
            if frame.command == .notifications {
                try frame.validate()
                return .init(operation: .reply, binding: frame.binding, sequence: frame.sequence,
                    serviceEpoch: frame.serviceEpoch, code: notificationWorkerLost ? .workerLost : nil,
                    workerUUID: frame.workerUUID, notifications: notificationWorkerLost ? nil : [])
            }
            if frame.command == .serviceStatus {
                try frame.validate()
                // Engine checks the current successor after durable publication;
                // the base owner fixture has no serviceStatus response.
                let ready = try #require(peer.state.withLock { $0.simulatedReady })
                let scope = StorageServiceTypes.Scope(serviceEpoch: ready.serviceEpoch, workerUUID: ready.workerUUID)
                #expect(frame.binding == peer.bootBinding)
                #expect(frame.serviceEpoch == scope.serviceEpoch && frame.workerUUID == scope.workerUUID)
                availabilityScopes.append(scope)
                return .init(operation: .reply, binding: frame.binding, sequence: frame.sequence,
                    serviceEpoch: scope.serviceEpoch, workerUUID: scope.workerUUID,
                    status: .init(phase: .ready))
            }
            guard frame.command == .replaceService || frame.command == .replacementStatus else {
                return try await base.command(frame)
            }
            try frame.validate()
            #expect(frame.workerUUID == peer.workerUUID && frame.serviceEpoch == peer.serviceEpoch)
            let directory = try root.openDirectory(named: ManagedStorageLifecycleCheckpoint.directoryName)
            let bytes = try HostStorageIntentCommit.readPrivateFile(in: directory, named: "state.json", maximumBytes: 1_048_576)
            let state = try ManagedStorageLifecycleCheckpoint.decode(bytes)
            let exact = try #require(state.serviceReplacement)
            #expect(exact.configuration.reopen?.isValidSignature(using: peer.rootKey) == true)
            #expect(state.pendingService?.predecessorWorkerUUID == peer.workerUUID)
            if frame.command == .replaceService {
                replaceCalls += 1
                let request = try #require(frame.replacementRequest)
                #expect(request == exact)
                requests.append(request)
                if let gate = replacementGate { replacementGate = nil; await gate.pause() }
                if dropAll || (dropFirst && replaceCalls == 1) { throw Owner.Failure.incomplete }
                let phase: Boot.ReplacementStatus.Phase = failReplacement ? .failed : .pending
                return .init(operation: .reply, binding: frame.binding, sequence: frame.sequence,
                    serviceEpoch: frame.serviceEpoch, workerUUID: frame.workerUUID,
                    replacement: .init(request: exact, phase: phase, code: failReplacement ? .workerUnreaped : nil))
            }
            statusCalls += 1
            if let gate = statusGate { statusGate = nil; await gate.pause() }
            #expect(frame.replacementRequest == nil)
            if keepPending {
                return .init(operation: .reply, binding: frame.binding, sequence: frame.sequence,
                    serviceEpoch: frame.serviceEpoch, workerUUID: frame.workerUUID,
                    replacement: .init(request: exact, phase: .pending))
            }
            let ready = peer.successor(exact.configuration.signed.grant)
            peer.state.withLock { $0.simulatedReady = ready }
            return .init(operation: .reply, binding: frame.binding, sequence: frame.sequence,
                serviceEpoch: frame.serviceEpoch, workerUUID: frame.workerUUID,
                replacement: .init(request: exact, phase: .succeeded, ready: ready))
        }
        func connectLifecycle() async throws -> FileHandle { try await base.connectLifecycle() }
        func connectWorkload() async throws -> FileHandle { try await base.connectWorkload() }
        func connectAttachmentCSR() async throws -> FileHandle { try await base.connectAttachmentCSR() }
    }
}
#endif

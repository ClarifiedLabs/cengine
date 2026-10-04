#if os(macOS) && DEBUG
import CEngineCore
import Darwin
import Foundation
import Synchronization
import Testing
@testable import CEngineRuntime

/// ISOLATED NON-NATIVE v2 workload adapter tests: the coordinator's durable
/// journal, the owner's joined worker and physical fences. No native child/TLS.
@Suite(.serialized) @MainActor struct ManagedStorageLifecycleWorkloadControlTests {
    typealias T = ManagedStorageLifecycleOwnerTests
    typealias Owner = ManagedStorageLifecycleOwner

    @MainActor final class Hook { var owner: Owner?; var action: (() throws -> Void)? }
    struct Fixture {
        let disk: T.Disk, peer: T.Peer, owner: Owner, transport: T.Transport
        let coordinator: ManagedVolumeLifecycleCoordinator
        var store: String { disk.binding.storeID.rawValue }
    }

    private func connected(_ hook: Hook? = nil) async throws -> Fixture {
        let disk = try T.Disk(), peer = try T.Peer(disk.binding)
        let owner = try disk.owner(peer, afterWorkloadDecode: hook.map { hook in { try hook.action?() } })
        hook?.owner = owner
        try await owner.provisionFresh()
        let transport = T.Transport(peer: peer, root: disk.root)
        try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        try await owner.connectWorkload()
        let coordinator = try owner.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator())
        // A fresh journal requires reconciliation before planning; use the real
        // startup path (a joined v2 Query), not a direct journal bypass.
        try await coordinator.reconcileStartup()
        // Tests count only the requests they cause, not the startup Query.
        peer.state.withLock { $0.workloadRequests = 0 }
        return .init(disk: disk, peer: peer, owner: owner, transport: transport, coordinator: coordinator)
    }

    private func createdVolume(_ f: Fixture) throws -> HostStorageIntents.Volume {
        let journal = try #require(f.owner.isolatedTestIntents)
        var volume = HostStorageIntents.Volume(id: T.id(), name: "data", createOperation: T.id(), deleteOperation: T.id())
        try f.coordinator.planVolumes([volume])
        volume.rootDevice = 1; volume.rootInode = 7; volume.createdRevision = 1
        try journal.recordVolume(volume)
        return volume
    }

    nonisolated private static func deleteReply(_ volume: HostStorageIntents.Volume, store: String) throws -> Data {
        try ControllerJSON.object(["id": .number(1), "volume_receipt": .object(["schema": .number(3),
            "operation": .string(volume.deleteOperation), "store": .string(store),
            "volume": .object(["id": .string(volume.id), "name": .string(volume.name),
                "root": .object(["device": .number(1), "inode": .number(7)])]),
            "phase": .string("DELETED"), "revision": .number(2)])]).bytes()
    }

    nonisolated private static func durableOperations(_ url: URL) throws -> Set<String> {
        let data = try Data(contentsOf: url.appending(path: "managed-storage/state.json"))
        let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        return Set((object["operations"] as? [String: Any] ?? [:]).keys)
    }

    private func fails(_ body: () async throws -> Void) async {
        do { try await body(); Issue.record("isolated non-native failure was accepted") } catch { }
    }

    @Test(arguments: ["success", "second-loss", "second-remote", "nonretire", "protocol", "remote", "cancel", "host-tamper", "child-proof-refusal"])
    func retireRetriesOnlyOneCorrelatedLoss(_ scenario: String) async throws {
        let f = try await connected(); defer { f.disk.remove() }
        let state = try f.owner.snapshot(), peer = f.peer, url = f.disk.url
        let current = try #require(state.currentContext)
        let context = try ManagedStorageControlClient.Context(store: f.store, serviceEpoch: current.serviceEpoch,
            controllerEpoch: current.controllerEpoch, controllerKey: current.controllerKey,
            provenanceReference: state.provenanceReference, lifecycleIdentity: state.identity)
        let id = T.id()
        let request: ManagedStorageControlProtocol.ControlRequest = scenario == "nonretire" ? .query :
            .retire(try .init(operation: id, store: f.store, volume: id, attachment: id, launch: id))
        let receipt = try ManagedStorageControlProtocol.Receipt(schema: 3, store: f.store,
            volume: id, attachment: id, launch: id, revision: 2)
        let response = try ControllerJSON.object(["id": .number(1), "receipt": ControllerJSON.from(receipt)]).bytes()
        let sent = Mutex<[Data]>([])
        f.peer.state.withLock { $0.workloadResponder = { actual in
            let count = try sent.withLock { values in values.append(try actual.durableBytes()); return values.count }
            if count == 1 {
                switch scenario {
                case "protocol": throw StorageLifecycleChildProcess.Failure.protocolViolation
                case "remote": return Data(#"{"error":"CLOSED","id":1}"#.utf8)
                case "cancel": throw CancellationError()
                case "host-tamper": try Data("damaged".utf8).write(to: url.appending(path: "managed-storage-owner/unexpected"))
                case "child-proof-refusal": peer.state.withLock {
                    $0.workloadConnect = { throw Owner.Failure.incomplete }
                }
                default: break
                }
                throw StorageLifecycleChildProcess.Failure.serviceUnavailable
            }
            if scenario == "second-loss" { throw StorageLifecycleChildProcess.Failure.serviceUnavailable }
            if scenario == "second-remote" { return Data(#"{"error":"CLOSED","id":1}"#.utf8) }
            return response
        } }
        let initialConnections = f.transport.workloadConnections
        let initialCommands = f.transport.commands.count
        let initialAllocations = f.peer.state.withLock { $0.allocations }
        f.peer.state.withLock { $0.workloadEvents = [] }
        if scenario == "success" {
            guard case .receipt(let actual) = try await f.owner.workloadControl(request, context: context) else {
                Issue.record("missing replay receipt"); await f.owner.close(); return
            }
            #expect(actual == receipt)
            #expect(try f.owner.snapshot() == state) // Fresh proof must not write observation history.
        } else {
            await fails { _ = try await f.owner.workloadControl(request, context: context) }
        }
        let retries = ["success", "second-loss", "second-remote"].contains(scenario) ? 1 : 0
        #expect(f.transport.workloadConnections == initialConnections + retries + (scenario == "child-proof-refusal" ? 1 : 0))
        let bytes = sent.withLock { $0 }
        #expect(bytes.count == 1 + retries)
        #expect(bytes.allSatisfy { $0 == bytes[0] })
        #expect(f.peer.state.withLock { $0.allocations } == initialAllocations)
        if retries == 1 {
            #expect(f.transport.commands.dropFirst(initialCommands).first == .serviceStatus)
            #expect(f.peer.state.withLock { $0.workloadEvents } == ["transport", "child"])
        }
        if scenario != "success" && scenario != "remote" {
            await fails { _ = try await f.owner.queryWorkload() }
            #expect(sent.withLock { $0.count } == bytes.count)
        }
        await f.owner.close()
    }

    @Test(arguments: [false, true]) func retireOwnsLaneAndCancellationNeverReconnects(cancel: Bool) async throws {
        let f = try await connected(); defer { f.disk.remove() }
        let state = try f.owner.snapshot(), current = try #require(state.currentContext), id = T.id()
        let context = try ManagedStorageControlClient.Context(store: f.store, serviceEpoch: current.serviceEpoch,
            controllerEpoch: current.controllerEpoch, controllerKey: current.controllerKey,
            provenanceReference: state.provenanceReference, lifecycleIdentity: state.identity)
        let request = ManagedStorageControlProtocol.ControlRequest.retire(try .init(operation: id,
            store: f.store, volume: id, attachment: id, launch: id))
        let receipt = try ManagedStorageControlProtocol.Receipt(schema: 3, store: f.store,
            volume: id, attachment: id, launch: id, revision: 2)
        let response = try ControllerJSON.object(["id": .number(1), "receipt": ControllerJSON.from(receipt)]).bytes()
        let gate = T.ReplyGate(), calls = Mutex(0)
        defer { gate.release.signal() }
        f.peer.state.withLock { $0.workloadResponder = { _ in
            let first = calls.withLock { $0 += 1; return $0 == 1 }
            if first { gate.holdReply(); throw StorageLifecycleChildProcess.Failure.serviceUnavailable }
            return response
        } }
        let initialConnections = f.transport.workloadConnections
        let task = Task { try await f.owner.workloadControl(request, context: context) }
        for await _ in gate.prepared.stream { break }
        await fails { _ = try await f.owner.workloadControl(.query, context: context) }
        await fails { try await f.owner.connectWorkload() }
        await fails { try await f.owner.stageRetire() }
        if cancel { task.cancel() }
        gate.release.signal()
        if cancel {
            await fails { _ = try await task.value }
            await fails { _ = try await f.owner.queryWorkload() }
        } else { _ = try await task.value }
        #expect(calls.withLock { $0 } == (cancel ? 1 : 2))
        #expect(f.transport.workloadConnections == initialConnections + (cancel ? 0 : 1))
        await f.owner.close()
    }

    @Test func coordinatorRecordsDurableOperationBeforeJoinedSend() async throws {
        let f = try await connected(); defer { f.disk.remove() }
        let volume = try createdVolume(f)
        let url = f.disk.url, store = f.store
        let sawDurable = Mutex(false)
        f.peer.state.withLock { $0.workloadResponder = { request in
            #expect(!Thread.isMainThread)
            guard case .deleteVolume(let deletion) = request, deletion.operation == volume.deleteOperation else {
                throw ManagedStorageControlClient.Failure.invalidRequest
            }
            let durable = try Self.durableOperations(url).contains(volume.deleteOperation)
            sawDurable.withLock { $0 = durable }
            return try Self.deleteReply(volume, store: store)
        } }
        try await f.coordinator.deleteVolume(volume.id)
        #expect(sawDurable.withLock { $0 })
        #expect(f.peer.state.withLock { $0.workloadRequests } == 1)
        #expect(try f.owner.journalSnapshot().volumes.first { $0.id == volume.id }?.deletedRevision == 2)
        await f.owner.close()
    }

    @Test func remoteErrorPassesThroughWithoutFencingGeneration() async throws {
        let f = try await connected(); defer { f.disk.remove() }
        let volume = try createdVolume(f)
        let peer = f.peer
        f.peer.state.withLock { $0.workloadResponder = { request in
            if case .query = request { return try peer.workloadQuery() }
            // Canonical sorted-key controller JSON; a non-canonical reply is
            // (correctly) a protocol violation that fences the generation.
            return Data(#"{"error":"CONFLICT","id":1}"#.utf8)
        } }
        do {
            try await f.coordinator.deleteVolume(volume.id)
            Issue.record("remote refusal accepted")
        } catch let error as ManagedStorageControlClient.Failure {
            #expect(error == .remote("CONFLICT"))
        }
        // Remote refusal is not uncertainty: the same generation still serves.
        _ = try await f.owner.queryWorkload()
        #expect(try Self.durableOperations(f.disk.url).contains(volume.deleteOperation))
        await f.owner.close()
    }

    @Test(arguments: ["lost", "corrupt", "wrong-operation", "cancel", "damage-after", "damage-before", "service-stale"])
    func uncertainOrStaleRepliesFenceWithoutPublication(_ scenario: String) async throws {
        let hook = Hook()
        let f = try await connected(hook); defer { f.disk.remove() }
        let volume = try createdVolume(f)
        let store = f.store, url = f.disk.url
        f.peer.state.withLock { $0.workloadResponder = { _ in
            switch scenario {
            case "lost": throw Owner.Failure.incomplete
            case "corrupt": return Data("{".utf8)
            case "wrong-operation":
                var other = volume
                other = .init(id: volume.id, name: volume.name, createOperation: volume.createOperation, deleteOperation: T.id())
                return try Self.deleteReply(other, store: store)
            default: return try Self.deleteReply(volume, store: store)
            }
        } }
        switch scenario {
        case "cancel": hook.action = { hook.owner?.cancel() }
        case "damage-after":
            hook.action = { try Data("uncertain".utf8).write(to: url.appending(path: "managed-storage-owner/unexpected")) }
        case "damage-before":
            try Data("uncertain".utf8).write(to: url.appending(path: "managed-storage-owner/unexpected"))
        case "service-stale":
            try await f.owner.stageServiceChange(operationID: T.id(), nowUnixSeconds: 1_800_000_100, lifetimeSeconds: 3600)
        default: break
        }
        await fails { try await f.coordinator.deleteVolume(volume.id) }
        let sent = f.peer.state.withLock { $0.workloadRequests }
        #expect(sent == (scenario == "damage-before" || scenario == "service-stale" ? 0 : 1))
        // No later exchange on this generation, and the volume is never tombstoned.
        await fails { _ = try await f.owner.queryWorkload() }
        #expect(f.peer.state.withLock { $0.workloadRequests } == sent)
        let journal = try #require(f.owner.isolatedTestIntents)
        #expect((try? journal.snapshot().volumes[volume.id]?.deletedRevision) ?? nil == nil)
        #expect(try f.disk.root.entryMetadata(named: "disk") != nil)
        await f.owner.close()
    }

    @Test func workloadIOExcludesLifecycleMutationAndCoordinatorIsSingleUse() async throws {
        let f = try await connected(); defer { f.disk.remove() }
        await fails { _ = try f.owner.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator()) }
        let volume = try createdVolume(f)
        let gate = T.ReplyGate(), store = f.store
        defer { gate.release.signal() }
        f.peer.state.withLock { $0.workloadResponder = { _ in
            gate.holdReply(); return try Self.deleteReply(volume, store: store)
        } }
        let task = Task { try await f.coordinator.deleteVolume(volume.id) }
        var prepared = false
        for await _ in gate.prepared.stream { prepared = true; break }
        try #require(prepared)
        await fails { try await f.owner.stageRetire() }
        gate.release.signal()
        try await task.value
        try await f.owner.stageRetire()
        await f.owner.close()
    }

    @Test func attachmentCertificateRequiresCurrentEligibleIntentBeforeAnyStream() async throws {
        let disk = try T.Disk(); defer { disk.remove() }
        let peer = try T.Peer(disk.binding), owner = try disk.owner(peer)
        try await owner.provisionFresh()
        let transport = T.Transport(peer: peer, root: disk.root)
        try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        try await owner.connectWorkload()
        let token = HostStorageIntents.Token(intent: T.id(), version: 1)
        // No coordinator yet: blocked before journal or transport IO.
        await fails { _ = try await owner.attachmentCertificate(intent: token, attachment: T.id(), csr: Data([1])) }
        _ = try owner.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator())
        await fails { _ = try owner.token(for: token.intent) }
        await fails { _ = try await owner.attachmentCertificate(intent: token, attachment: T.id(), csr: Data([1])) }
        #expect(transport.attachmentConnections == 0)
        #expect(peer.state.withLock { $0.attachmentRequests.isEmpty })
        await owner.close()
    }

    @Test func nativeShimAttachmentCSRRouteRequiresShimDescriptorReply() async throws {
        var descriptors: [Int32] = [0, 0]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0)
        defer { Darwin.close(descriptors[0]); Darwin.close(descriptors[1]) }
        let connection = try StorageLifecycleShimConnection.testing(borrowedFD: descriptors[0])
        // No shim replies: the route is attempted over IPC and fails closed.
        await #expect(throws: (any Error).self) { _ = try await connection.connectAttachmentCSR() }
    }
}
#endif

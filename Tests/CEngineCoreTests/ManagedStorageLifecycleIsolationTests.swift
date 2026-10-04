#if os(macOS) && DEBUG
import CEngineCore
import CryptoKit
import Foundation
import Testing
@testable import CEngineRuntime

/// Real v2 journals/owner with isolated ROOT and transport peers. These tests do
/// not claim native signed-code, TLS, lock-exclusion or mounted-VM qualification.
@Suite(.serialized) @MainActor struct ManagedStorageLifecycleIsolationTests {
    typealias Owner = ManagedStorageLifecycleOwner
    typealias Base = ManagedStorageLifecycleOwnerTests
    typealias Boot = StorageLifecycleServiceBootProtocol
    typealias Capture = ManagedPrepareCompatibilityQueue.PublicTakeoverArmCapture

    @Test(arguments: ["legacy-connection", "second-service-exclusivity"])
    func actualC2RegistryAndTripleLeaveAuthorityUnchanged(_ kind: String) async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        let request = f.request(kind), original = try f.original(request)
        let before = try f.owner.snapshot(), session = try f.owner.workloadSession()
        try f.owner.validatePublicTakeoverArm(request)
        let count = f.peer.state.withLock { $0.workloadRequests }
        let query = try await f.owner.publicTakeoverRegistry(request)
        #expect(query.schema == 4 && query.controller.epoch == 2)
        #expect(f.peer.state.withLock { $0.workloadRequests } == count + 1)
        let registryBytes = try await f.owner.publicTakeoverRegistryEvidence(request)
        let registryProof = try JSONDecoder().decode(Owner.PublicTakeoverRegistryEvidence.self, from: registryBytes)
        #expect(registryProof.version == 2)
        #expect(registryProof.lifecycleIdentity == session.context.lifecycleIdentity)
        #expect(registryProof.registry.schema == 4 && registryProof.registry.controller.epoch == 2)
        let fields = try #require(JSONSerialization.jsonObject(with: registryBytes) as? [String: Any])
        #expect(Set(fields.keys) == ["version", "lifecycleIdentity", "registry"])
        let proof = try await f.owner.probeServiceIsolation(request, original: original)
        #expect(proof.before == proof.after)
        #expect(proof.observation.caseName == kind)
        #expect(f.transport.frames.compactMap(\.command) == [.isolationState, Boot.Command(rawValue: kind)!, .isolationState])
        #expect(Set(f.transport.deadlines).count == 1)
        #expect(f.transport.frames.allSatisfy { $0.isolationRequest == proof.before.request && $0.binding == f.peer.bootBinding })
        #expect(try f.owner.snapshot() == before)
        #expect(try f.owner.workloadSession().context == session.context)
        #expect(try f.owner.workloadSession().service == session.service)
        await f.owner.close()
    }

    @Test(arguments: ["wrong-worker", "wrong-store", "wrong-request", "wrong-case", "malformed", "after-state", "changed-physical", "changed-census", "timeout"])
    func rejectsUncorrelatedOrChangedIO(_ fault: String) async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        let request = f.request(), original = try f.original(request)
        f.transport.fault = fault
        f.transport.afterReply = {
            if fault == "changed-physical" {
                try Data("invalid".utf8).write(to: f.disk.url.appending(path: "managed-storage-owner/state.json"))
            }
            if fault == "changed-census" {
                try f.owner.isolatedTestIntents?.requireReconciliation()
            }
        }
        // The absolute budget includes physical/signature checks and ROOT IO.
        // The timeout peer stalls to that deadline after recording its first send;
        // a 10ms total budget can correctly expire before any frame is sent.
        await #expect(throws: (any Error).self) {
            _ = try await f.owner.probeServiceIsolation(request, original: original, timeout: 5)
        }
        #expect(f.transport.frames.count == (fault == "after-state" ? 3 : 1))
        await f.owner.close()
    }

    @Test(arguments: ["wrong-scope", "wrong-operation", "unsigned", "stale-physical", "invalid-timeout"])
    func rejectsBeforeSending(_ fault: String) async throws {
        let f = try await Fixture(policyAllowed: fault != "unsigned"); defer { f.disk.remove() }
        let request = f.request()
        let original = try f.original(request, wrongScope: fault == "wrong-scope", wrongOperation: fault == "wrong-operation")
        if fault == "stale-physical" {
            try Data("invalid".utf8).write(to: f.disk.url.appending(path: "managed-storage-owner/state.json"))
        }
        await #expect(throws: (any Error).self) {
            _ = try await f.owner.probeServiceIsolation(request, original: original, timeout: fault == "invalid-timeout" ? .infinity : 5)
        }
        #expect(f.transport.frames.isEmpty)
        await f.owner.close()
    }

    @Test func boundedJoinDoesNotCancelIndependentNotification() async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        let request = f.request(), original = try f.original(request)
        f.transport.holdNotification = true
        let notification = Task { try await f.owner.retirementNotifications() }
        while !f.transport.notificationStarted { try await Task.sleep(for: .milliseconds(1)) }
        await #expect(throws: AsyncTimeout.TimeoutError.self) {
            _ = try await f.owner.probeServiceIsolation(request, original: original, timeout: 0.02)
        }
        #expect(f.transport.frames.isEmpty)
        #expect(!f.transport.base.cancelled.withLock { $0 })
        f.transport.holdNotification = false
        #expect(try await notification.value.isEmpty)
        _ = try f.owner.workloadSession()
        await f.owner.close()
    }

    @Test func freshC1IsNotAPublicArmBaseline() async throws {
        let f = try await ManagedStorageLifecycleOriginalConsumerTests.Fixture(); defer { f.disk.remove() }
        let request = Capture(version: "original-takeover-arm.v1", requestID: Base.id(), operationUUID: Base.id(),
            store: f.disk.binding.storeID.rawValue, epoch: 2, serviceEpoch: f.peer.serviceEpoch,
            container: String(repeating: "a", count: 64), containerInstance: Base.id())
        #expect(throws: (any Error).self) { try f.owner.validatePublicTakeoverArm(request) }
        await f.owner.close()
    }

    @Test func registryRechecksPhysicalEvidenceAfterQuery() async throws {
        let f = try await Fixture(afterQuery: true); defer { f.disk.remove() }
        await #expect(throws: (any Error).self) { _ = try await f.owner.publicTakeoverRegistry(f.request()) }
        await f.owner.close()
    }

    @MainActor final class Fixture {
        let disk: Base.Disk
        let peer: Base.Peer
        let owner: Owner
        let transport: Transport
        let lifecycle: ManagedVolumeLifecycleCoordinator
        let container = String(repeating: "a", count: 64), instance = Base.id()
        init(policyAllowed: Bool = true, afterQuery: Bool = false) async throws {
            disk = try Base.Disk(); peer = try Base.Peer(disk.binding)
            let restart = ManagedStorageLifecycleRestartTests()
            let grant = try await restart.freshStore(disk, peer)
            var seam = try peer.seam(child: Curve25519.Signing.PrivateKey(), childIncarnation: Base.id(), expectedEpoch: 1, daemon: 9)
            seam.isolationCompatibilityIdentity = { if !policyAllowed { throw Owner.Failure.blocked } }
            let stateURL = disk.url.appending(path: "managed-storage-owner/state.json")
            var armed = false
            owner = try Owner(isolatedTestExisting: seam, root: disk.root, backingDescriptor: disk.backing, binding: disk.binding,
                afterWorkloadDecode: {
                    if afterQuery && armed { try Data("invalid".utf8).write(to: stateURL) }
                })
            transport = Transport(base: .init(peer: peer, root: disk.root))
            try await owner.takeover(using: transport, current: restart.current(peer, grant))
            try await owner.recoverWorkload()
            lifecycle = try owner.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator())
            try await lifecycle.reconcileStartup()
            armed = true
        }
        func request(_ kind: String = "legacy-connection") -> Capture {
            .init(version: "original-takeover-arm.v1", requestID: Base.id(), operationUUID: Base.id(),
                store: disk.binding.storeID.rawValue, epoch: 2, serviceEpoch: peer.serviceEpoch,
                container: container, containerInstance: instance, positiveOnly: true, isolationCase: kind)
        }
        func original(_ request: Capture, wrongScope: Bool = false, wrongOperation: Bool = false) throws -> OriginalConsumerObservationProtocol.Binding {
            let context = try owner.workloadSession().context, launch = Base.id()
            return .init(requestID: request.requestID, armDigest: String(repeating: "b", count: 64),
                operationUUID: wrongOperation ? Base.id() : request.operationUUID, caseName: .sameEExistingData, generation: 1,
                boot: .init(shimLaunchUUID: launch, guestBootNonce: Base.id()),
                scope: .init(intent: Base.id(), store: request.store, serviceEpoch: wrongScope ? Base.id() : request.serviceEpoch,
                    controllerEpoch: request.epoch, controllerKey: context.controllerKey, container: request.container,
                    containerInstance: request.containerInstance, launch: launch, prepare: Base.id(), specificationDigest: String(repeating: "c", count: 64)),
                targetAttachment: Base.id(), key: String(repeating: "d", count: 64), certificateSHA256: String(repeating: "e", count: 64))
        }
    }
    @MainActor final class Transport: ManagedStorageLifecycleServiceTransport {
        let base: Base.Transport
        var frames: [Boot.Frame] = [], deadlines: [UInt64] = []
        var fault = "", afterReply: (() throws -> Void)?
        var holdNotification = false, notificationStarted = false
        init(base: Base.Transport) { self.base = base }
        nonisolated func cancel() { base.cancel() }
        func configure(_ value: Boot.Configuration) async throws -> ManagedStorageLifecycleServiceReady { try await base.configure(value) }
        func command(_ frame: Boot.Frame) async throws -> Boot.Frame {
            if frame.command == .notifications {
                notificationStarted = true
                while holdNotification { try await Task.sleep(for: .milliseconds(1)) }
                return .init(operation: .reply, binding: frame.binding, sequence: frame.sequence,
                    serviceEpoch: frame.serviceEpoch, workerUUID: frame.workerUUID, notifications: [])
            }
            return try await base.command(frame)
        }
        func command(_ frame: Boot.Frame, deadlineNanoseconds: UInt64?) async throws -> Boot.Frame {
            try frame.validate()
            let selected = try #require(frame.isolationRequest), deadline = try #require(deadlineNanoseconds)
            frames.append(frame); deadlines.append(deadline)
            if fault == "timeout" {
                let now = DispatchTime.now().uptimeNanoseconds
                if now < deadline { try await Task.sleep(nanoseconds: deadline - now) }
            }
            var request = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(selected)) as? [String: Any])
            if fault == "wrong-request" { request["challenge"] = Base.id() }
            let kind = fault == "wrong-case" ? "legacy-connection" : try #require(frame.command).rawValue
            let fields: [String: Any] = ["request": request, "workerUUID": fault == "wrong-worker" ? Base.id() : frame.workerUUID!,
                "caseName": kind, "store": fault == "wrong-store" ? Base.id() : base.peer.binding.storeID.rawValue,
                "serviceEpoch": frame.serviceEpoch!, "revision": fault == "malformed" ? 0 : 1,
                "registrySHA256": String(repeating: fault == "after-state" && frames.count == 3 ? "c" : "b", count: 64),
                "result": kind == "isolation-state" ? "registry-state" : kind == "legacy-connection" ? "legacy-tls-header-rejected" : "second-owner-locked"]
            let proof = try JSONDecoder().decode(Boot.IsolationProof.self, from: JSONSerialization.data(withJSONObject: fields))
            try afterReply?()
            return .init(operation: .reply, binding: frame.binding, sequence: frame.sequence, serviceEpoch: frame.serviceEpoch,
                workerUUID: frame.workerUUID, isolationProof: proof)
        }
        func connectLifecycle() async throws -> FileHandle { try await base.connectLifecycle() }
        func connectWorkload() async throws -> FileHandle { try await base.connectWorkload() }
        func connectAttachmentCSR() async throws -> FileHandle { try await base.connectAttachmentCSR() }
    }
}
#endif

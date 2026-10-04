#if os(macOS) && DEBUG
import CEngineCore
import Foundation
import Testing
@testable import CEngineRuntime

/// Real v2 owner and durable journals, injected private service IO. These are
/// owner-fence tests, not native TLS or VM-backed original-consumer qualification.
@Suite(.serialized) @MainActor struct ManagedStorageLifecycleOriginalConsumerTests {
    typealias Owner = ManagedStorageLifecycleOwner
    typealias Existing = ManagedStorageLifecycleOwnerTests
    typealias C = ConsumerObservationProtocol
    typealias B = StorageLifecycleServiceBootProtocol

    @Test(arguments: [false, true]) func currentAndCrossEUseRetainedPrivateService(crossE: Bool) async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        let maintenance = try await crossE ? f.replace() : nil
        let deadline = DispatchTime.now().uptimeNanoseconds + 5_000_000_000
        try await f.owner.withOriginalConsumerSession(request: crossE ? nil : f.request,
            maintenance: maintenance, deadlineNanoseconds: deadline) { session in
            let arm = f.arm(session, crossE: crossE)
            @MainActor func revalidate() throws { try session.check() }
            let armed = try await session.command(.consumerObservationArm, arm: arm, revalidate: revalidate)
            let queried = try await session.command(.consumerObservationQuery, arm: arm, revalidate: revalidate)
            #expect(armed.state == .armed)
            #expect(queried.query == arm)
            if crossE { #expect(throws: (any Error).self) { _ = try f.owner.workloadSession() } }
        }
        #expect(f.transport.frames.count == 2)
        #expect(f.transport.deadlines == [deadline, deadline])
        #expect(f.transport.frames[0].sequence! < f.transport.frames[1].sequence!)
        #expect(f.transport.frames.allSatisfy { $0.binding == f.peer.bootBinding })
        await #expect(throws: (any Error).self) {
            try await f.owner.withOriginalConsumerSession(request: crossE ? nil : f.request,
                maintenance: maintenance, deadlineNanoseconds: deadline) { _ in Issue.record("duplicate worker admitted") }
        }
        #expect(f.transport.frames.count == 2)
        if let maintenance {
            try await maintenance.lifecycle.reconcileStartup()
            try f.owner.completeServiceReplacement(maintenance) {}
            await #expect(throws: (any Error).self) {
                try await f.owner.withOriginalConsumerSession(maintenance: maintenance,
                    deadlineNanoseconds: deadline) { _ in Issue.record("completed maintenance admitted") }
            }
        }
        await f.owner.close()
    }

    @Test(arguments: ["stale-owner", "retirement-mismatch", "wrong-reply", "expired-reply"])
    func fencesEveryReturnedPrivateReply(_ fault: String) async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        let deadline = DispatchTime.now().uptimeNanoseconds + (fault == "expired-reply" ? 50_000_000 : 5_000_000_000)
        var installedReceiptMatches = true
        f.transport.afterReply = {
            if fault == "stale-owner" {
                try Data("invalid".utf8).write(to: f.disk.url.appending(path: "managed-storage-owner/state.json"))
            }
            if fault == "retirement-mismatch" { installedReceiptMatches = false }
        }
        f.transport.wrongReply = fault == "wrong-reply"
        f.transport.expireReply = fault == "expired-reply"
        await #expect(throws: (any Error).self) {
            try await f.owner.withOriginalConsumerSession(request: f.request, deadlineNanoseconds: deadline) { session in
                let arm = f.arm(session, crossE: false)
                _ = try await session.command(.consumerObservationArm, arm: arm) {
                    guard installedReceiptMatches else { throw Owner.Failure.invalid }
                }
                Issue.record("unfenced private reply escaped")
            }
        }
        #expect(f.transport.frames.count == 1)
        await f.owner.close()
    }

    @Test func expiredAdmissionSendsNothingAndDoesNotConsumeWorker() async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        await #expect(throws: AsyncTimeout.TimeoutError.self) {
            try await f.owner.withOriginalConsumerSession(request: f.request, deadlineNanoseconds: 0) { _ in
                Issue.record("expired observation admitted")
            }
        }
        #expect(f.transport.frames.isEmpty)
        try await f.owner.withOriginalConsumerSession(request: f.request,
            deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 5_000_000_000) { session in
            _ = try await session.command(.consumerObservationArm, arm: f.arm(session, crossE: false), revalidate: {})
        }
        #expect(f.transport.frames.count == 1)
        await f.owner.close()
    }

    @Test(arguments: [OriginalConsumerObservationProtocol.Case.sameEExistingData, .attachmentKeyReuse, .delayedRegistration])
    func retiredSessionRejectsRetirementAndRegistrationBeforeCallbacks(_ name: OriginalConsumerObservationProtocol.Case) async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        let session = try await f.owner.withOriginalConsumerSession(request: f.request,
            deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 5_000_000_000) { session in
            try session.check()
            return session
        }
        let (binding, _, _, _) = SameEConsumerObservationProtocolTests().fixture(name)
        try OriginalConsumerObservationProtocol.validate(binding)
        let requests = f.peer.state.withLock { $0.workloadRequests }
        var callbacks = 0
        @MainActor func revalidate() throws { callbacks += 1 }
        @MainActor func revalidateRegistration(_ receipt: ManagedVolumeLifecycleCoordinator.OriginalRetirement?) throws {
            callbacks += 1
        }
        @MainActor func probe(_ receipt: ManagedVolumeLifecycleCoordinator.OriginalRetirement?) async throws {
            callbacks += 1
        }
        do {
            if name.isRegistration {
                _ = try await session.observeOriginalRegistration(binding, revalidate: revalidateRegistration, probe: probe)
            } else {
                _ = try await session.retireOriginalConsumer(binding, revalidate: revalidate)
            }
            Issue.record("retired observation session admitted lifecycle work")
        } catch Owner.Failure.blocked { }
        #expect(callbacks == 0)
        #expect(f.peer.state.withLock { $0.workloadRequests } == requests)
        #expect(f.transport.frames.isEmpty)
        await f.owner.close()
    }

    @MainActor final class Fixture {
        let disk: Existing.Disk
        let peer: Existing.Peer
        let owner: Owner
        let transport: Transport
        let request: StorageServiceTypes.ReplacementRequest
        let names = SharedVolumeInitializationCoordinator()
        init() async throws {
            disk = try Existing.Disk(); peer = try Existing.Peer(disk.binding); owner = try disk.owner(peer)
            transport = Transport(base: .init(peer: peer, root: disk.root))
            try await owner.provisionFresh()
            try await owner.bootFresh(using: transport, expectedBinding: peer.bootBinding,
                nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
            try await owner.connectWorkload()
            _ = try owner.makeWorkloadCoordinator(names: names)
            request = .init(operationUUID: UUID().uuidString.lowercased(),
                predecessor: .init(serviceEpoch: peer.serviceEpoch, workerUUID: peer.workerUUID), nowUnixSeconds: 1_800_000_100)
        }
        func replace() async throws -> Owner.ServiceReplacementMaintenance {
            try await owner.replaceService(operationID: request.operationUUID, predecessor: request.predecessor,
                nowUnixSeconds: request.nowUnixSeconds, lifetimeSeconds: 1800, names: names)
        }
        func arm(_ session: Owner.OriginalConsumerSession, crossE: Bool) -> C.Arm {
            let ready = session.service.ready, launch = UUID().uuidString.lowercased()
            return .init(requestID: UUID().uuidString.lowercased(), armDigest: String(repeating: "a", count: 64),
                operationUUID: request.operationUUID, caseName: crossE ? .crossE : .wrongEpoch,
                originalBootBinding: .init(shimLaunchUUID: launch, guestBootNonce: UUID().uuidString.lowercased()),
                original: .init(epoch: request.predecessor.serviceEpoch, binding: .init(store: ready.identity.store,
                    volume: UUID().uuidString.lowercased(), attachment: UUID().uuidString.lowercased(),
                    container: String(repeating: "b", count: 64), launch: launch, key: String(repeating: "c", count: 64), mode: "read-only")),
                originalLeafSHA256: String(repeating: "d", count: 64),
                workerScope: .init(storeUUID: ready.identity.store, serviceEpoch: ready.serviceEpoch, workerUUID: ready.workerUUID))
        }
    }
    @MainActor final class Transport: ManagedStorageLifecycleServiceTransport {
        let base: ManagedStorageLifecycleReplacementMaintenanceTests.Transport
        var frames: [B.Frame] = []
        var deadlines: [UInt64] = []
        var afterReply: (() throws -> Void)?
        var wrongReply = false, expireReply = false
        init(base: ManagedStorageLifecycleReplacementMaintenanceTests.Transport) { self.base = base }
        func configure(_ configuration: B.Configuration) async throws -> ManagedStorageLifecycleServiceReady { try await base.configure(configuration) }
        func command(_ frame: B.Frame) async throws -> B.Frame { try await base.command(frame) }
        func command(_ frame: B.Frame, deadlineNanoseconds: UInt64?) async throws -> B.Frame {
            try frame.validate()
            let arm = try #require(frame.consumerObservationArm ?? frame.consumerObservationQuery)
            let deadline = try #require(deadlineNanoseconds)
            frames.append(frame); deadlines.append(deadline)
            if expireReply {
                let now = DispatchTime.now().uptimeNanoseconds
                if now < deadline { try await Task.sleep(nanoseconds: deadline - now) }
            }
            try afterReply?()
            return .init(operation: .reply, binding: frame.binding, sequence: frame.sequence,
                serviceEpoch: frame.serviceEpoch, workerUUID: wrongReply ? UUID().uuidString.lowercased() : frame.workerUUID,
                consumerObservationStatus: .init(query: arm, state: .armed, selectedCount: 0))
        }
        func connectLifecycle() async throws -> FileHandle { try await base.connectLifecycle() }
        func connectWorkload() async throws -> FileHandle { try await base.connectWorkload() }
        func connectAttachmentCSR() async throws -> FileHandle { try await base.connectAttachmentCSR() }
        nonisolated func cancel() {}
    }
}
#endif

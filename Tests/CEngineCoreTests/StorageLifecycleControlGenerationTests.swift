#if os(macOS) && DEBUG
import CEngineCore
@testable import CEngineRuntime
import Darwin
import Foundation
import Synchronization
import Testing

@Suite struct StorageLifecycleControlGenerationTests {
    private typealias Gate = StorageLifecycleControlLifetime
    private typealias W = StorageLifecycleAdoptionProtocol
    private func request(epoch: UInt64 = 1) throws -> W.Request {
        let uuid = try StorageIdentity.FilesystemUUID("11111111-1111-4111-8111-111111111111")
        let binding = try StorageIdentity.StoreBinding(storeID: .init(uuid.rawValue), root: .init(volumeUUID: uuid, inode: 2),
            backing: .init(identity: .init(volumeUUID: uuid, inode: 3), size: 4096), expectedExt4UUID: uuid)
        return try .init(id: UUID().uuidString.lowercased(),
            origin: .init(binding: .init(binding), rootPublicKey: Data(repeating: 7, count: 32),
                shimLaunchUUID: uuid.rawValue, specSHA256: String(repeating: "a", count: 64)), expectedEpoch: epoch,
            daemonAudit: Data(repeating: 1, count: 32), daemonUniqueID: 1,
            controllerAudit: Data(repeating: 2, count: 32), controllerUniqueID: 2)
    }
    private func enrolled() throws -> Gate {
        let gate = Gate()
        try gate.beginEnrollment(); try gate.enroll()
        return gate
    }
    @Test func exactCommittedRetryPreservesSuccessorAndStaleCleanupCannotTouchIt() throws {
        let gate = try enrolled(), original = try gate.captureGeneration(), adoption = try request()
        try gate.fence(adoption)
        let successor = try gate.testingAdopt(adoption), revoked = Mutex(false)
        try gate.hold(.transport, generation: successor) { revoked.withLock { $0 = true } }
        try gate.fence(adoption) // ROOT complete's exact lost-reply retry.
        #expect(!revoked.withLock { $0 })
        #expect(gate.detach(original) == .stale)
        #expect(throws: (any Error).self) { try gate.withOperation(original) {} }
        #expect(throws: (any Error).self) { try gate.reservePrivateStop(original) }
        try gate.withAdmission(successor) {}
        #expect(!revoked.withLock { $0 })
        #expect(throws: (any Error).self) { try gate.testingAdopt(adoption) }
        try gate.fence(request(epoch: 2))
        #expect(revoked.withLock { $0 })
        #expect(throws: (any Error).self) { try gate.withAdmission(successor) {} }
    }
    @Test func nestedVMStopCallbacksRetainReplyUntilMatchingControlEnds() throws {
        let gate = try enrolled(), first = try gate.captureGeneration(), adoption = try request()
        try gate.fence(adoption)
        let current = try gate.testingAdopt(adoption), revoked = Mutex(false)
        try gate.hold(.transport, generation: current) { revoked.withLock { $0 = true } }
        var stop = StorageLifecycleStopReplyLifetime()
        #expect(!stop.finish(current) && !stop.permitsProcessExit)
        try gate.reservePrivateStop(current); try stop.begin(current)
        #expect(!stop.permitsProcessExit)
        #expect(throws: (any Error).self) { try stop.begin(current) }
        // Raw.stop and RawContainerVirtualMachine.forceStop both call terminate.
        for _ in 0..<2 { gate.terminate(revokeTransport: !stop.preservesReply) }
        #expect(!revoked.withLock { $0 })
        #expect(!stop.finish(first) && stop.preservesReply && !stop.permitsProcessExit)
        #expect(stop.finish(current) && !stop.preservesReply && stop.permitsProcessExit)
        #expect(!stop.finish(current) && stop.permitsProcessExit)
        #expect(throws: (any Error).self) { try stop.begin(current) }
        gate.terminate(revokeTransport: !stop.preservesReply)
        #expect(revoked.withLock { $0 })
        #expect(throws: (any Error).self) { try gate.testingAdopt(adoption) }
    }
    @Test func sameAuthorizationReconnectGetsNewLocalGeneration() throws {
        let gate = try enrolled(), adoption = try request()
        try gate.fence(adoption)
        let first = try gate.testingAdopt(adoption)
        #expect(gate.detach(first) == .preserved)
        let second = try gate.testingAdopt(adoption)
        #expect(first != second)
        #expect(gate.detach(first) == .stale)
        try gate.withAdmission(second) {}
        // Unversioned startup callbacks remain initial-only.
        #expect(throws: (any Error).self) { try gate.withAdmission {} }
        #expect(throws: (any Error).self) { try gate.captureGeneration() }
        try gate.reservePrivateStop(second)
        gate.terminate()
        #expect(throws: (any Error).self) { try gate.testingAdopt(adoption) }
    }
    @Test func reentrantRevocationCannotPublishDrainedEarly() throws {
        let gate = try enrolled(), original = try gate.captureGeneration(), adoption = try request()
        try gate.hold(.transport) {
            #expect(gate.detach(original) == .preserved)
            #expect(throws: (any Error).self) { try gate.testingAdopt(adoption) }
        }
        try gate.fence(adoption)
        let next = try gate.testingAdopt(adoption)
        try gate.withAdmission(next) {}
    }
    @Test func displacedStreamTeardownCompletesBeforeFenceAcknowledgement() throws {
        let gate = try enrolled(), original = try gate.captureGeneration(), adoption = try request()
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let replacementDone = DispatchSemaphore(value: 0), fenceDone = DispatchSemaphore(value: 0)
        let oldRevoked = Mutex(false), newRevoked = Mutex(false)
        try gate.hold(.stream(4_107)) {
            entered.signal(); release.wait(); oldRevoked.withLock { $0 = true }
        }
        Thread.detachNewThread {
            defer { replacementDone.signal() }
            do { try gate.hold(.stream(4_107), generation: original) { newRevoked.withLock { $0 = true } } }
            catch { Issue.record("replacement failed: \(error)") }
        }
        #expect(entered.wait(timeout: .now() + 2) == .success)
        Thread.detachNewThread {
            defer { fenceDone.signal() }
            do { try gate.fence(adoption) } catch { Issue.record("fence failed: \(error)") }
        }
        #expect(fenceDone.wait(timeout: .now() + 0.05) == .timedOut)
        release.signal()
        #expect(replacementDone.wait(timeout: .now() + 2) == .success)
        #expect(fenceDone.wait(timeout: .now() + 2) == .success)
        #expect(oldRevoked.withLock { $0 } && newRevoked.withLock { $0 })
    }
    @Test func admittedOperationDrainsBeforeReplacement() throws {
        let gate = try enrolled(), original = try gate.captureGeneration(), adoption = try request()
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let operationDone = DispatchSemaphore(value: 0), fenceDone = DispatchSemaphore(value: 0)
        Thread.detachNewThread {
            defer { operationDone.signal() }
            do {
                try gate.withOperation(original) { entered.signal(); release.wait() }
            } catch { Issue.record("admitted operation failed: \(error)") }
        }
        #expect(entered.wait(timeout: .now() + 2) == .success)
        Thread.detachNewThread {
            defer { fenceDone.signal() }
            do { try gate.fence(adoption) } catch { Issue.record("fence failed: \(error)") }
        }
        #expect(fenceDone.wait(timeout: .now() + 0.05) == .timedOut)
        #expect(throws: (any Error).self) { try gate.testingAdopt(adoption) }
        release.signal()
        #expect(operationDone.wait(timeout: .now() + 2) == .success)
        #expect(fenceDone.wait(timeout: .now() + 2) == .success)
        let next = try gate.testingAdopt(adoption)
        try gate.withOperation(next) {}
    }
}
#endif

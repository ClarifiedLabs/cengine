#if os(macOS)
import CEngineCore
import Foundation
import Darwin
import Testing
import Synchronization
@preconcurrency import XPC
@testable import CEngineRuntime

@Suite struct StorageLifecycleAdoptionShimTests {
    private typealias W = StorageLifecycleAdoptionProtocol
    private func request(epoch: UInt64 = 1, origin: W.Origin? = nil) throws -> W.Request {
        let uuid = try StorageIdentity.FilesystemUUID("11111111-1111-4111-8111-111111111111")
        let binding = try StorageIdentity.StoreBinding(storeID: .init(uuid.rawValue), root: .init(volumeUUID: uuid, inode: 2),
            backing: .init(identity: .init(volumeUUID: uuid, inode: 3), size: 4096), expectedExt4UUID: uuid)
        return try .init(id: UUID().uuidString.lowercased(),
            origin: origin ?? .init(binding: .init(binding), rootPublicKey: Data(repeating: 7, count: 32),
                shimLaunchUUID: uuid.rawValue, specSHA256: String(repeating: "a", count: 64)), expectedEpoch: epoch,
            daemonAudit: Data(repeating: 1, count: 32), daemonUniqueID: 1,
            controllerAudit: Data(repeating: 2, count: 32), controllerUniqueID: 2)
    }
    @Test func coldFenceStartsAtRequiredBaseAndRejectsOldEpochsAndOrigins() throws {
        let old = try request(), origin = try W.Origin(binding: old.origin.binding, rootPublicKey: old.origin.rootPublicKey,
            shimLaunchUUID: UUID().uuidString.lowercased(), specSHA256: old.origin.specSHA256)
        var gate = StorageLifecycleAdoptionFence(origin: origin, baseEpoch: 8)
        #expect(throws: (any Error).self) { try gate.fence(request(epoch: 7, origin: origin)) }
        #expect(throws: (any Error).self) { try gate.fence(request(epoch: 8, origin: old.origin)) }
        let first = try request(epoch: 8, origin: origin)
        #expect(try gate.fence(first))
        #expect(gate.committed == nil)
        try gate.commit(first)
        #expect(try !gate.fence(first))
        #expect(gate.committed == first)
        var invalid = StorageLifecycleAdoptionFence(origin: origin, baseEpoch: 0)
        #expect(throws: (any Error).self) { try invalid.fence(first) }
        var maximum = StorageLifecycleAdoptionFence(origin: origin, baseEpoch: UInt64.max)
        #expect(throws: (any Error).self) { try maximum.fence(request(epoch: UInt64.max - 1, origin: origin)) }
    }
    @Test func fenceNeverAdmitsBeforeCommitAndLostCommitRetryPreservesSession() throws {
        let r = try request()
        var gate = StorageLifecycleAdoptionFence(origin: r.origin, baseEpoch: 1)
        #expect(throws: (any Error).self) { try gate.commit(r) }
        #expect(try gate.fence(r))
        #expect(gate.committed == nil)
        #expect(try !gate.fence(r))
        #expect(gate.committed == nil)
        try gate.commit(r)
        #expect(gate.committed == r)
        // Lost commit ACK: fresh nonce fence plus exact commit must not revoke.
        #expect(try !gate.fence(r))
        #expect(gate.committed == r)
        try gate.commit(r)
        #expect(gate.committed == r)
        let next = try request(epoch: 9)
        #expect(try gate.fence(next)) // Missed intermediate allocations are legal.
        #expect(gate.committed == nil)
        #expect(throws: (any Error).self) { try gate.commit(r) }
        #expect(throws: (any Error).self) { try gate.fence(r) }
        try gate.commit(next)
        #expect(gate.committed == next)
    }
    @Test func equalDifferentAndCrossOriginCannotChangeLiveGate() throws {
        let r = try request(), other = try request()
        var gate = StorageLifecycleAdoptionFence(origin: r.origin, baseEpoch: 1)
        _ = try gate.fence(r); try gate.commit(r)
        #expect(throws: (any Error).self) { try gate.fence(other) }
        #expect(throws: (any Error).self) { try gate.commit(other) }
        let changed = try W.Origin(binding: r.origin.binding, rootPublicKey: r.origin.rootPublicKey,
            shimLaunchUUID: UUID().uuidString.lowercased(), specSHA256: r.origin.specSHA256)
        #expect(throws: (any Error).self) { try gate.fence(request(epoch: 3, origin: changed)) }
        #expect(gate.committed == r)
    }
    @Test func enrollmentTransfersBackingAndGreetingDoesNot() throws {
        let origin = try request().origin
        let pipe = Pipe()
        let enroll = try StorageLifecycleAdoptionShim.registration(origin: origin,
            enrolling: pipe.fileHandleForReading.fileDescriptor)
        #expect(xpc_dictionary_get_int64(enroll, "version") == PrivilegedPortProtocol.version)
        #expect(String(cString: try #require(xpc_dictionary_get_string(enroll, "role"))) == "storage-shim")
        #expect(String(cString: try #require(xpc_dictionary_get_string(enroll, "operation"))) == "storage-lifecycle-adoption-enroll")
        var size = 0
        let bytes = try #require(xpc_dictionary_get_data(enroll, "request", &size))
        #expect(try W.decodeOrigin(Data(bytes: bytes, count: size)) == origin)
        let transferred = xpc_dictionary_dup_fd(enroll, "backing-fd")
        #expect(transferred >= 0)
        guard transferred >= 0 else { return }
        defer { Darwin.close(transferred) }
        var original = stat(), duplicate = stat()
        #expect(fstat(pipe.fileHandleForReading.fileDescriptor, &original) == 0)
        #expect(fstat(transferred, &duplicate) == 0)
        #expect(original.st_dev == duplicate.st_dev && original.st_ino == duplicate.st_ino)
        let greeting = try StorageLifecycleAdoptionShim.registration(origin: origin, enrolling: nil)
        #expect(String(cString: try #require(xpc_dictionary_get_string(greeting, "operation"))) == "storage-lifecycle-adoption-shim")
        #expect(xpc_dictionary_get_value(greeting, "backing-fd") == nil)
    }

    @Test func reconnectRequiresAcknowledgedEnrollmentAndJoinsRunningAttempt() throws {
        var transport = StorageLifecycleAdoptionReconnectState()
        let initial = try #require({ transport.begin() }())
        #expect({ transport.begin() }() == nil)
        transport.acknowledgeEnrollment(UUID()) // Stale/foreign ACK is not enrollment.
        #expect(!transport.enrolled)
        #expect({ transport.disconnected(initial) }() == nil)
        #expect({ transport.finished(initial, succeeded: false) }() == nil)
        #expect(transport.scheduled == nil)

        let acknowledged = try #require({ transport.begin() }())
        // Even if transport loss races an already authenticated ACK, retain it.
        #expect({ transport.disconnected(acknowledged) }() == nil)
        transport.acknowledgeEnrollment(acknowledged)
        #expect(transport.enrolled)
        for _ in 0..<20 {
            #expect({ transport.disconnected(acknowledged) }() == nil)
            #expect({ transport.begin() }() == nil)
            #expect(transport.scheduled == nil)
            #expect(transport.running == acknowledged)
        }
        // Timeout/cancellation alone cannot release this slot. Native auth must
        // settle before finished() makes another attempt schedulable.
        let retry = try #require({ transport.finished(acknowledged, succeeded: false) }())
        #expect(retry.delay == 0.25)
        #expect(transport.running == nil)
        #expect(transport.scheduled == retry)
        #expect({ transport.disconnected(acknowledged) }() == nil)
        #expect({ transport.finished(acknowledged, succeeded: false) }() == nil)
        #expect({ transport.begin() }() == nil)
    }

    // Synthetic monotonic instants exercise timing/scheduling only, never mint
    // a native peer, verified boot, seed, ACK, or enrollment capability.
    private func instant(_ seconds: UInt64) -> DispatchTime {
        DispatchTime(uptimeNanoseconds: seconds * 1_000_000_000)
    }

    @Test func compositeEnrollmentCanExceedFiveSecondsWithinThirty() {
        var attempt = StorageLifecycleAdoptionDeadline(start: instant(100), initial: true)
        #expect(attempt.deadline == instant(130))
        // Several freshly authenticated proofs can cumulatively take >5s.
        for elapsed: UInt64 in [2, 4, 7, 12, 21] {
            #expect(attempt.permitsProgress(at: instant(100 + elapsed)))
        }
        #expect({ attempt.finish(at: instant(129), succeeded: true) }())
        #expect(attempt.result == true)
        let reconnect = StorageLifecycleAdoptionDeadline(start: instant(100), initial: false)
        #expect(reconnect.deadline == instant(105))
        #expect(!reconnect.permitsProgress(at: instant(105)))
    }

    @Test func recoveryEnrollmentCanFinishAfterFreshBudgetWithoutRenewingGreeting() {
        var attempt = StorageLifecycleAdoptionDeadline(start: instant(100), initial: true, recovering: true)
        #expect(attempt.deadline == instant(190))
        #expect(attempt.deadline < instant(100) + StorageLifecycleShimChannel.budget)
        // A cold/resume proof chain that outlasts the old 30s budget is valid.
        #expect({ attempt.acceptReply(at: instant(135)) }())
        #expect(attempt.acceptedReplies == 1)
        #expect(attempt.deadline == instant(190))
        #expect({ attempt.acceptReply(at: instant(189)) }()) // Greeting.
        #expect({ attempt.finish(at: instant(189), succeeded: true) }())
        let reconnect = StorageLifecycleAdoptionDeadline(start: instant(100), initial: false, recovering: true)
        #expect(reconnect.deadline == instant(105))
    }

    @Test func recoveryDeadlineStillRejectsLateAuthenticationAndFailedPendingRetry() throws {
        var attempt = StorageLifecycleAdoptionDeadline(start: instant(100), initial: true, recovering: true)
        var transport = StorageLifecycleAdoptionReconnectState()
        let generation = try #require({ transport.begin() }())
        #expect(!attempt.permitsProgress(at: instant(190)))
        #expect({ !attempt.acceptReply(at: instant(190)) }())
        #expect({ !attempt.finish(at: instant(191), succeeded: true) }())
        #expect(attempt.acceptedReplies == 0)
        #expect({ transport.disconnected(generation) }() == nil)
        #expect({ transport.finished(generation, succeeded: false) }() == nil)
        #expect(!transport.enrolled && transport.scheduled == nil)
    }

    @Test func greetingGetsOnlyRemainingCompositeBudget() {
        var attempt = StorageLifecycleAdoptionDeadline(start: instant(100), initial: true)
        #expect(attempt.permitsProgress(at: instant(128))) // Enrollment ACK.
        #expect(attempt.deadline == instant(130)) // Greeting does not renew it.
        #expect(attempt.permitsProgress(at: instant(129)))
        #expect(!attempt.permitsProgress(at: instant(130)))
        #expect({ !attempt.finish(at: instant(131), succeeded: true) }())
    }

    @Test func expiredQueueAdmissionCannotSendOrScheduleFailedPendingRetry() throws {
        var attempt = StorageLifecycleAdoptionDeadline(start: instant(100), initial: true)
        var transport = StorageLifecycleAdoptionReconnectState()
        let generation = try #require({ transport.begin() }())
        // Serial queue first runs at the boundary; the send guard must fail.
        #expect(!attempt.permitsProgress(at: instant(130)))
        #expect({ !attempt.finish(at: instant(130), succeeded: false) }())
        #expect({ transport.disconnected(generation) }() == nil)
        #expect(transport.running == generation)
        #expect({ transport.finished(generation, succeeded: false) }() == nil)
        #expect(!transport.enrolled)
        #expect(transport.scheduled == nil)
    }

    @Test func authenticationFinishingAfterDeadlineCannotEnrollEvenBeforeTimerRuns() {
        var attempt = StorageLifecycleAdoptionDeadline(start: instant(100), initial: true)
        // Authentication began on time but the typed ACK finished after expiry.
        #expect(attempt.permitsProgress(at: instant(104)))
        #expect({ !attempt.acceptReply(at: instant(131)) }())
        #expect(attempt.acceptedReplies == 0)
        #expect({ !attempt.finish(at: instant(131), succeeded: true) }())
        #expect(attempt.result == false)
    }

    @Test func stalledAuthenticationFailsWaiterButKeepsRunningSlotUntilJoined() throws {
        var attempt = StorageLifecycleAdoptionDeadline(start: instant(100), initial: true)
        var transport = StorageLifecycleAdoptionReconnectState()
        let generation = try #require({ transport.begin() }())
        #expect(attempt.permitsProgress(at: instant(101))) // Native auth starts.
        #expect({ !attempt.finish(at: instant(130), succeeded: false) }()) // Waiter returns.
        #expect({ transport.disconnected(generation) }() == nil)
        for _ in 0..<20 {
            #expect({ transport.begin() }() == nil)
            #expect(transport.running == generation)
            #expect(transport.scheduled == nil)
        }
        #expect(!attempt.permitsProgress(at: instant(140))) // Late ACK is inert.
        #expect({ !attempt.finish(at: instant(140), succeeded: true) }())
        #expect(!transport.enrolled)
        #expect({ transport.finished(generation, succeeded: false) }() == nil) // Join.
        #expect(transport.running == nil)
        #expect(transport.scheduled == nil)
    }

    @Test func acceptedEnrollmentSurvivesGreetingDeadlineAndRetriesOnlyAfterJoin() throws {
        var attempt = StorageLifecycleAdoptionDeadline(start: instant(100), initial: true)
        var transport = StorageLifecycleAdoptionReconnectState()
        let generation = try #require({ transport.begin() }())
        #expect({ attempt.acceptReply(at: instant(125)) }())
        transport.acknowledgeEnrollment(generation) // Existing value-only model.
        #expect({ !attempt.finish(at: instant(130), succeeded: false) }()) // Greeting lost.
        #expect({ transport.disconnected(generation) }() == nil)
        #expect(transport.enrolled)
        #expect(transport.running == generation)
        #expect(transport.scheduled == nil)
        let retry = try #require({ transport.finished(generation, succeeded: false) }())
        #expect(retry.delay == 0.25)
        #expect(transport.enrolled)
    }

    @Test func acceptedEnrollmentPublishesOwnerBeforeTimeoutContainment() throws {
        // Exercise the actual owner publication and containment gates, not a fake
        // native ACK/capability. Pause before transport publication, as the real
        // reply worker can be descheduled immediately after owner publication.
        let control = StorageLifecycleControlLifetime()
        try control.beginEnrollment()
        let gate = Mutex(StorageLifecycleAdoptionDeadline(start: .now(), initial: true))
        let published = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let joined = DispatchSemaphore(value: 0)
        let transport = Mutex(StorageLifecycleAdoptionReconnectState())
        let generation = try #require(transport.withLock { $0.begin() })
        DispatchQueue(label: "adoption-publication-test").async {
            defer { joined.signal() }
            do {
                try control.publishEnrollment(acknowledging: gate)
                published.signal()
                release.wait()
                transport.withLock { $0.acknowledgeEnrollment(generation) }
            } catch { Issue.record("owner publication failed: \(error)"); published.signal() }
        }
        defer { release.signal() }
        try #require(published.wait(timeout: .now() + 5) == .success)
        #expect(gate.withLock { $0.acceptedReplies } == 1)
        #expect(control.isEnrolled)
        #expect(!transport.withLock { $0.enrolled }) // Worker still paused.
        #expect(!gate.withLock { $0.finish(at: $0.deadline, succeeded: false) })
        #expect(control.detach()) // Same decision used by containControlFailure().
        #expect(control.preservesOwner)
        #expect(transport.withLock { $0.disconnected(generation) } == nil)
        #expect(transport.withLock { $0.running } == generation)
        release.signal()
        try #require(joined.wait(timeout: .now() + 5) == .success)
        #expect(transport.withLock { $0.enrolled })
        #expect(transport.withLock { $0.finished(generation, succeeded: false) } != nil)
    }

    @Test func admissionContentionCannotBlockDeadlineOrPublishAfterExpiry() throws {
        let control = StorageLifecycleControlLifetime()
        try control.beginEnrollment()
        let gate = Mutex(StorageLifecycleAdoptionDeadline(start: .now(), initial: true))
        let held = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let holdingDone = DispatchSemaphore(value: 0), publisherStarted = DispatchSemaphore(value: 0)
        let publicationDone = DispatchSemaphore(value: 0), failed = Mutex(false)
        DispatchQueue(label: "adoption-admission-holder-test").async {
            defer { holdingDone.signal() }
            do { try control.withAdmission { held.signal(); release.wait() } }
            catch { Issue.record("admission failed: \(error)"); held.signal() }
        }
        defer { release.signal() }
        try #require(held.wait(timeout: .now() + 5) == .success)
        DispatchQueue(label: "adoption-contended-publication-test").async {
            defer { publicationDone.signal() }
            publisherStarted.signal()
            do { try control.publishEnrollment(acknowledging: gate) }
            catch { failed.withLock { $0 = true } }
        }
        try #require(publisherStarted.wait(timeout: .now() + 5) == .success)
        // Expiration needs no owner-admission lock; publication has not claimed ACK.
        #expect(!gate.withLock { $0.finish(at: $0.deadline, succeeded: false) })
        #expect(gate.withLock { $0.acceptedReplies } == 0)
        release.signal()
        try #require(holdingDone.wait(timeout: .now() + 5) == .success)
        try #require(publicationDone.wait(timeout: .now() + 5) == .success)
        #expect(failed.withLock { $0 })
        #expect(!control.isEnrolled)
        #expect(!control.detach()) // Failed pending owner must terminate, not retry.
        #expect(gate.withLock { $0.acceptedReplies } == 0)
    }

    @Test func revokedOwnerCannotAcceptEnrollmentOrEnableReconnect() throws {
        let control = StorageLifecycleControlLifetime()
        try control.beginEnrollment()
        let gate = Mutex(StorageLifecycleAdoptionDeadline(start: .now(), initial: true))
        var transport = StorageLifecycleAdoptionReconnectState()
        let generation = try #require({ transport.begin() }())
        #expect(!control.detach()) // Containment won before ACK publication.
        #expect(throws: (any Error).self) { try control.publishEnrollment(acknowledging: gate) }
        #expect(gate.withLock { $0.acceptedReplies } == 0)
        #expect(!control.isEnrolled)
        #expect(!transport.enrolled)
        #expect({ transport.finished(generation, succeeded: false) }() == nil)
        #expect(transport.scheduled == nil)
    }

    @Test func deadlineTerminalWinnerMakesStaleCompletionAndTimeoutInert() {
        var completed = StorageLifecycleAdoptionDeadline(start: instant(100), initial: true)
        #expect({ completed.finish(at: instant(129), succeeded: true) }())
        #expect({ completed.finish(at: instant(130), succeeded: false) }())
        #expect(!completed.permitsProgress(at: instant(129)))
        var expired = StorageLifecycleAdoptionDeadline(start: instant(100), initial: true)
        #expect({ !expired.finish(at: instant(130), succeeded: false) }())
        #expect({ !expired.finish(at: instant(131), succeeded: true) }())
        #expect(!expired.permitsProgress(at: instant(129)))
    }

    @Test func missingRootScopeRetriesIndefinitelyWithCappedBackoffAndSuccessResetsIt() throws {
        var transport = StorageLifecycleAdoptionReconnectState()
        let initial = try #require({ transport.begin() }())
        transport.acknowledgeEnrollment(initial)
        var retry = try #require({ transport.finished(initial, succeeded: false) }())
        let delays: [TimeInterval] = [0.25, 0.5, 1, 2, 5]
        // No retry limit: ROOT can be alive before the daemon restores its scope.
        for index in 0..<40 {
            #expect(retry.delay == delays[min(index, delays.count - 1)])
            let generation = try #require({ transport.beginRetry(retry) }())
            #expect(transport.enrolled)
            #expect(transport.scheduled == nil)
            #expect(transport.running == generation)
            #expect({ transport.beginRetry(retry) }() == nil)
            retry = try #require({ transport.finished(generation, succeeded: false) }())
        }
        let restored = try #require({ transport.beginRetry(retry) }())
        #expect({ transport.finished(restored, succeeded: true) }() == nil)
        #expect(transport.current == restored)
        #expect(transport.running == nil)
        let restarted = try #require({ transport.disconnected(restored) }())
        #expect(restarted.delay == 0.25)
    }

    @Test func staleChannelCallbacksAndTimersCannotAffectNewTransport() throws {
        var transport = StorageLifecycleAdoptionReconnectState()
        let old = try #require({ transport.begin() }())
        transport.acknowledgeEnrollment(old)
        #expect({ transport.finished(old, succeeded: true) }() == nil)
        let timer = try #require({ transport.disconnected(old) }())
        let current = try #require({ transport.beginRetry(timer) }())
        #expect(current != old)
        #expect({ transport.disconnected(old) }() == nil)
        #expect({ transport.finished(old, succeeded: false) }() == nil)
        #expect({ transport.beginRetry(timer) }() == nil)
        transport.acknowledgeEnrollment(old)
        #expect(transport.current == current)
        #expect(transport.running == current)
        #expect(transport.scheduled == nil)
        #expect({ transport.finished(current, succeeded: true) }() == nil)
        let nextTimer = try #require({ transport.disconnected(current) }())
        #expect({ transport.beginRetry(timer) }() == nil)
        #expect({ transport.disconnected(old) }() == nil)
        #expect(transport.scheduled == nextTimer)
    }

    @Test func terminationPermanentlyCancelsScheduledAndRunningReconnects() throws {
        var scheduled = StorageLifecycleAdoptionReconnectState()
        let first = try #require({ scheduled.begin() }())
        scheduled.acknowledgeEnrollment(first)
        let timer = try #require({ scheduled.finished(first, succeeded: false) }())
        scheduled.terminate()
        scheduled.terminate()
        #expect(scheduled.enrolled)
        #expect(scheduled.terminated)
        #expect(scheduled.scheduled == nil)
        #expect({ scheduled.beginRetry(timer) }() == nil)
        #expect({ scheduled.begin() }() == nil)
        #expect({ scheduled.disconnected(first) }() == nil)

        var running = StorageLifecycleAdoptionReconnectState()
        let active = try #require({ running.begin() }())
        running.terminate()
        running.acknowledgeEnrollment(active)
        #expect(!running.enrolled)
        #expect(running.running == active)
        #expect({ running.finished(active, succeeded: true) }() == nil)
        #expect(running.running == nil)
        #expect(running.current == nil)
        #expect(running.scheduled == nil)
        #expect({ running.begin() }() == nil)

        var reconnecting = StorageLifecycleAdoptionReconnectState()
        let enrolled = try #require({ reconnecting.begin() }())
        reconnecting.acknowledgeEnrollment(enrolled)
        let pending = try #require({ reconnecting.finished(enrolled, succeeded: false) }())
        let retrying = try #require({ reconnecting.beginRetry(pending) }())
        reconnecting.terminate()
        #expect({ reconnecting.disconnected(retrying) }() == nil)
        #expect(reconnecting.running == retrying)
        #expect({ reconnecting.finished(retrying, succeeded: false) }() == nil)
        #expect(reconnecting.enrolled)
        #expect(reconnecting.scheduled == nil)
        #expect({ reconnecting.beginRetry(pending) }() == nil)
        #expect({ reconnecting.begin() }() == nil)
    }

    @Test func reconnectAndTerminationDoNotChangeFenceHighWaterOrCommittedSession() throws {
        let committed = try request(epoch: 9)
        var gate = StorageLifecycleAdoptionFence(origin: committed.origin, baseEpoch: 1)
        _ = try gate.fence(committed)
        try gate.commit(committed)
        var transport = StorageLifecycleAdoptionReconnectState()
        let initial = try #require({ transport.begin() }())
        transport.acknowledgeEnrollment(initial)
        #expect({ transport.finished(initial, succeeded: true) }() == nil)
        var timer = try #require({ transport.disconnected(initial) }())
        for _ in 0..<10 {
            let next = try #require({ transport.beginRetry(timer) }())
            timer = try #require({ transport.finished(next, succeeded: false) }())
            #expect(gate.origin == committed.origin)
            #expect(gate.current == committed)
            #expect(gate.committed == committed)
        }
        let restored = try #require({ transport.beginRetry(timer) }())
        #expect({ transport.finished(restored, succeeded: true) }() == nil)
        #expect(try !gate.fence(committed))
        try gate.commit(committed)
        #expect(throws: (any Error).self) { try gate.fence(request(epoch: 1)) }
        transport.terminate() // Admission checks termination, not a synthetic fence.
        #expect(gate.current == committed)
        #expect(gate.committed == committed)
    }

    @Test func commitWireIsClosedAndDomainSeparatedFromFence() throws {
        let r = try request(), commit = try W.Commit(request: r)
        #expect(try W.decodeCommit(W.encode(commit)) == commit)
        #expect(try W.decodeOrigin(W.encode(r.origin)) == r.origin)
        #expect(try commit.digest != W.Challenge(request: r, nonce: Data(repeating: 1, count: 32)).digest)
        let bytes = try W.encode(commit), text = String(decoding: bytes, as: UTF8.self)
        #expect(throws: (any Error).self) { try W.decodeCommit(Data((text + "\n").utf8)) }
        #expect(throws: (any Error).self) {
            try W.decodeCommit(Data(text.replacingOccurrences(of: "\"request\":{", with: "\"request\":{\"admitted\":true,").utf8))
        }
    }
}
#endif

#if os(macOS)
import CEngineCore
import Foundation
import Testing
@testable import CEngineRuntime

@Suite @MainActor struct OriginalConsumerPreflightTests {
    private struct ArmFailure: Error {}
    private struct ReleaseFailure: Error {}
    private struct ContainmentFailure: Error {}
    @MainActor private final class Signal {
        private var signalled = false
        private var waiters: [CheckedContinuation<Void, Never>] = []
        func wait() async {
            if signalled { return }
            await withCheckedContinuation { waiters.append($0) }
        }
        func signal() {
            signalled = true
            let pending = waiters; waiters.removeAll()
            for waiter in pending { waiter.resume() }
        }
    }

    @Test(arguments: [false, true])
    func freezeClosesAdmissionAndOnlyCancelsLegacyLoop(lifecycle: Bool) async throws {
        let notifications = RawServiceWorkTracker()
        let lease = try notifications.begin()
        let entered = Signal(), resume = Signal(), cancelled = Signal()
        let loop = Task {
            defer { notifications.end(lease) }
            entered.signal()
            await resume.wait() // the real callback need not honor cancellation
            if Task.isCancelled { cancelled.signal() }
        }
        await entered.wait()
        OriginalConsumerNotificationFreeze.close(notifications, task: loop,
            policy: lifecycle ? .drainLifecycle : .cancelLegacy)
        #expect(loop.isCancelled == !lifecycle)
        #expect(throws: (any Error).self) { try notifications.begin() }
        #expect(throws: (any Error).self) { try notifications.requireQuiescent() }
        resume.signal()
        try await notifications.join()
        if !lifecycle { await cancelled.wait() }
        await loop.value
        try notifications.requireQuiescent()
    }

    @Test(arguments: [false, true])
    func callbackEnteringDestructionAfterFreezeIsStillPositivelyJoined(lifecycle: Bool) async throws {
        let notifications = RawServiceWorkTracker(), destruction = RawServiceWorkTracker()
        let loopLease = try notifications.begin()
        let callbackEntered = Signal(), allowDestruction = Signal(), destructiveEntered = Signal(), finish = Signal()
        let loop = Task {
            defer { notifications.end(loopLease) }
            callbackEntered.signal()
            await allowDestruction.wait()
            let lease = destruction.retainDestructiveWork()
            defer { destruction.end(lease) }
            destructiveEntered.signal()
            await finish.wait()
        }
        await callbackEntered.wait()
        OriginalConsumerNotificationFreeze.close(notifications, task: loop,
            policy: lifecycle ? .drainLifecycle : .cancelLegacy)
        destruction.close()
        allowDestruction.signal()
        await destructiveEntered.wait()
        #expect(throws: (any Error).self) { try destruction.requireQuiescent() }
        #expect(throws: (any Error).self) { try notifications.requireQuiescent() }
        // Closing admission did not erase either exact lease or the callback.
        finish.signal()
        try await notifications.join(); await loop.value
        try await destruction.join(); try destruction.requireQuiescent()
    }

    @Test(arguments: OriginalConsumerObservationProtocol.Case.allCases)
    func nativeObservationDispatchIsClosed(_ name: OriginalConsumerObservationProtocol.Case) throws {
        if name.isRoot {
            #expect(try OriginalConsumerObservationDispatch(name) == .roots)
        } else if name.isSameE {
            #expect(try OriginalConsumerObservationDispatch(name) == .sameE)
        } else if name.isWrongHello {
            #expect(try OriginalConsumerObservationDispatch(name) == .wrongHello)
        } else if [.crossEExistingData, .crossEOldLeafReconnect, .crossERetainedFD].contains(name) {
            #expect(try OriginalConsumerObservationDispatch(name) == .replacement)
        } else {
            #expect(throws: OriginalConsumerObservationProtocol.Failure.self) {
                try OriginalConsumerObservationDispatch(name)
            }
        }
    }

    @Test func unjoinedWorkCannotReopenOrBecomeArmProof() async throws {
        let work = RawServiceWorkTracker()
        let original = try work.begin()
        work.close()
        await #expect(throws: (any Error).self) { try await work.join(timeout: .milliseconds(1)) }
        #expect(throws: (any Error).self) { try work.requireQuiescent() }
        #expect(throws: (any Error).self) { try work.reopen() }
        work.end(original)
        try await work.join(); try work.reopen()
        let successor = try work.begin()
        #expect(throws: (any Error).self) { try work.require(original) }
        work.end(original)
        try work.require(successor)
        work.end(successor)
    }

    @Test func mismatchedGenerationCannotReachArmOrFault() throws {
        final class Client {}
        let client = Client(), replacement = Client()
        let epoch = UUID()
        let original = OriginalConsumerPreflightIdentity(serviceGeneration: epoch, shimGeneration: 1, launch: "old", instance: "instance")
        let changed = OriginalConsumerPreflightIdentity(serviceGeneration: epoch, shimGeneration: 2, launch: "new", instance: "instance")
        #expect(throws: (any Error).self) {
            try OriginalConsumerPreflightIdentity.requireMatch(original, changed, captured: client, currentClient: client)
        }
        #expect(throws: (any Error).self) {
            try OriginalConsumerPreflightIdentity.requireMatch(original, original, captured: client, currentClient: replacement)
        }
        try OriginalConsumerPreflightIdentity.requireMatch(original, original, captured: client, currentClient: client)
    }

    @Test(arguments: OriginalConsumerFailureDiagnostic.Stage.allCases.filter { $0.rawValue.hasPrefix("preflight-") })
    func preflightDiagnosticsSurviveCleanupAndEncodeOnlyClosedMetadata(_ stage: OriginalConsumerFailureDiagnostic.Stage) async throws {
        typealias D = OriginalConsumerFailureDiagnostic
        var events: [String] = []
        do {
            let _: Void = try await OriginalConsumerCleanup.run(operation: {
                throw D.annotate(ArmFailure(), at: stage)
            }, release: {
                events.append("release"); throw ReleaseFailure()
            }, contain: {
                events.append("contain"); throw ContainmentFailure()
            })
            Issue.record("expected preflight failure")
        } catch {
            let outer = try #require(error as? OriginalConsumerContainmentFailure)
            let inner = try #require(outer.observation as? OriginalConsumerContainmentFailure)
            #expect(D.underlying(inner.observation) is ArmFailure)
            #expect(inner.containment is ReleaseFailure && outer.containment is ContainmentFailure)
            let metadata = try #require(D.find(in: D.annotate(error, at: .containment)))
            #expect(metadata == D(stage: stage, error: ArmFailure()))
            let receipt = OriginalConsumerRuntimeCarrier.Failed(requestID: "request", diagnostic: metadata)
            let json = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(receipt)) as? [String: Any])
            #expect(Set(json.keys) == ["requestID", "code", "diagnostic"])
            #expect(json["diagnostic"] as? [String: String] == ["stage": stage.rawValue, "category": "other"])
        }
        #expect(events == ["release", "contain"])
        let cancelled = D.annotate(CancellationError(), at: stage)
        #expect(D.underlying(cancelled) is CancellationError)
        #expect(D.find(in: cancelled)?.category == .cancelled)
    }

    @Test func failedArmReleasesAndContainsWithoutFault() async throws {
        var events: [String] = []
        var faulted = false
        await #expect(throws: ArmFailure.self) {
            let _: Void = try await OriginalConsumerCleanup.run(operation: {
                events.append("arm-failed")
                throw ArmFailure()
            }, release: { events.append("release") }, contain: { events.append("contain") })
            faulted = true
        }
        #expect(!faulted)
        #expect(events == ["arm-failed", "release", "contain"])
    }

    @Test(arguments: [false, true])
    func releaseFailureStillContainsAndRetainsBothErrors(containmentFails: Bool) async throws {
        var contained = false
        do {
            let _: Int = try await OriginalConsumerCleanup.run(operation: { 1 }, release: { throw ReleaseFailure() }, contain: {
                contained = true
                if containmentFails { throw ContainmentFailure() }
            })
            Issue.record("release failure escaped as success")
        } catch {
            if containmentFails { #expect(error is OriginalConsumerContainmentFailure) }
            else { #expect(error is ReleaseFailure) }
        }
        #expect(contained)
    }

    @MainActor private final class Clock {
        var now: UInt64 = 1
        let timerEntered = Signal()
        let deadlineReached = Signal()
        func sleep(until deadline: UInt64) async {
            #expect(deadline == 10)
            timerEntered.signal()
            await deadlineReached.wait()
        }
        func expire() { now = 10; deadlineReached.signal() }
    }

    @Test(arguments: [false, true])
    func suspendedAdoptionExpiresAndCleansBeforeOwnerReturns(lateFailure: Bool) async throws {
        let clock = Clock(), entered = Signal(), resume = Signal()
        let ownership = RawServiceWorkTracker()
        let original = try ownership.begin()
        ownership.close()
        var events: [String] = []
        var observed = false
        let adoption = OriginalConsumerAdoptionWait<Int> {
            defer { ownership.end(original) }
            entered.signal()
            await resume.wait() // models non-cooperative authoritative polling/adoption
            #expect(!Task.isCancelled)
            if lateFailure { throw ArmFailure() }
            return 42
        }
        let replacement = Task {
            try await OriginalConsumerCleanup.run(operation: {
                let value = try await adoption.wait(deadline: 10, now: { clock.now },
                    sleepUntil: { await clock.sleep(until: $0) })
                observed = true
                return value
            }, release: { events.append("release") }, contain: { events.append("contain") })
        }
        await entered.wait(); await clock.timerEntered.wait()
        clock.expire()
        await #expect(throws: OriginalConsumerAdoptionWait<Int>.Failure.self) { try await replacement.value }
        #expect(events == ["release", "contain"])
        #expect(!observed && adoption.expired && !adoption.task.isCancelled)
        // Cleanup completed with the original owner STILL suspended and owned.
        #expect(throws: (any Error).self) { try ownership.requireQuiescent() }
        #expect(throws: (any Error).self) { try ownership.reopen() }
        resume.signal()
        _ = await adoption.task.result
        await adoption.completion?.value // deterministically process the late result
        #expect(!observed && adoption.expired)
        // Replaying the retained terminal task cannot renew the failed lease,
        // even after authoritative adoption eventually returned.
        await #expect(throws: OriginalConsumerAdoptionWait<Int>.Failure.self) { try await replacement.value }
        #expect(events == ["release", "contain"])
        #expect(throws: (any Error).self) { try ownership.begin() }
        // A late result cannot re-enter the original observation's success path.
        await #expect(throws: OriginalConsumerAdoptionWait<Int>.Failure.self) {
            try await adoption.wait(deadline: 100)
        }
    }

    @Test func adoptionBeforeOriginalDeadlineCanSucceed() async throws {
        let clock = Clock(), entered = Signal(), resume = Signal()
        let adoption = OriginalConsumerAdoptionWait<Int> {
            entered.signal(); await resume.wait(); return 42
        }
        var events: [String] = []
        let replacement = Task {
            try await OriginalConsumerCleanup.run(operation: {
                try await adoption.wait(deadline: 10, now: { clock.now },
                    sleepUntil: { await clock.sleep(until: $0) })
            }, release: { events.append("release") }, contain: { events.append("contain") })
        }
        await entered.wait(); await clock.timerEntered.wait()
        resume.signal()
        #expect(try await replacement.value == 42)
        #expect(!adoption.expired && !adoption.task.isCancelled)
        #expect(events == ["release", "contain"])
        clock.expire() // release the cancelled test timer; never change the outcome
        await Task.yield()
        #expect(!adoption.expired)
    }

    @Test func lateAdoptionIsRejectedEvenBeforeTimerRuns() async throws {
        let clock = Clock(), entered = Signal(), resume = Signal()
        let adoption = OriginalConsumerAdoptionWait<Int> {
            entered.signal(); await resume.wait(); return 42
        }
        let wait = Task {
            try await adoption.wait(deadline: 10, now: { clock.now },
                sleepUntil: { await clock.sleep(until: $0) })
        }
        await entered.wait(); await clock.timerEntered.wait()
        clock.now = 10 // deliberately leave the timer suspended
        resume.signal()
        await #expect(throws: OriginalConsumerAdoptionWait<Int>.Failure.self) { try await wait.value }
        #expect(adoption.expired)
        clock.expire()
    }

    @Test(arguments: [false, true])
    func unjoinedLaunchStillContainsAllExactKnownOwners(containmentFails: Bool) async throws {
        @MainActor final class Owner {
            var running = true
            var attempts = 0
        }
        let native = RawServiceWorkTracker(), work = RawServiceWorkTracker()
        let launch = try native.begin()
        let known = [Owner(), Owner()]
        native.close(); work.close()
        var events: [String] = []
        do {
            _ = try await RawServiceContainment.run(native: native, work: work,
                nativeTimeout: .zero, containKnown: {
                    try await RawServiceContainment.containKnown(owners: known) { owner in
                        #expect(throws: (any Error).self) { try native.requireQuiescent() }
                        #expect(throws: (any Error).self) { try native.reopen() }
                        owner.attempts += 1
                        events.append("terminate-known")
                        if containmentFails && owner === known[0] { throw ContainmentFailure() }
                        owner.running = false
                    }
                }, contain: { events.append("full-containment") },
                joinManaged: { events.append("managed-join") }, census: {
                    events.append("complete-census"); return ["known"]
                })
            Issue.record("unjoined native launch reported complete containment")
        } catch {
            if containmentFails {
                let dual = try #require(error as? RawServiceContainment.JoinFailure)
                #expect(dual.join is EngineError)
                let failures = try #require(dual.containment as? RawServiceContainment.KnownOwnersFailure)
                #expect(failures.failures.count == 1 && failures.failures[0] is ContainmentFailure)
            } else { #expect(error is EngineError) }
        }
        #expect(events == ["terminate-known", "terminate-known"])
        #expect(known.allSatisfy { $0.attempts == 1 })
        #expect(!known[1].running)
        #expect(known[0].running == containmentFails)
        // Attempts finished before the unknown launch released its original lease.
        #expect(throws: (any Error).self) { try native.requireQuiescent() }
        #expect(throws: (any Error).self) { try native.require(launch) }
        native.end(launch)
        #expect(throws: (any Error).self) { try native.begin() }
        #expect(throws: (any Error).self) { try work.begin() }
    }

    @Test func rejectedInitialCensusStillAttemptsKnownContainment() async throws {
        let native = RawServiceWorkTracker(), work = RawServiceWorkTracker()
        native.close(); work.close()
        var events: [String] = []
        await #expect(throws: ArmFailure.self) {
            try await RawServiceContainment.run(native: native, work: work, containKnown: {
                events.append("known-owner-termination")
            }, contain: {
                events.append("census-rejected"); throw ArmFailure()
            }, joinManaged: { events.append("managed-join") }, census: {
                events.append("complete-census"); return []
            })
        }
        #expect(events == ["census-rejected", "known-owner-termination"])
        #expect(throws: (any Error).self) { try native.begin() }
        #expect(throws: (any Error).self) { try work.begin() }
    }

    @Test func operationReleaseAndContainmentFailuresAreNotDiscarded() async throws {
        var events: [String] = []
        do {
            let _: Void = try await OriginalConsumerCleanup.run(operation: { throw ArmFailure() }, release: {
                events.append("release"); throw ReleaseFailure()
            }, contain: { events.append("contain"); throw ContainmentFailure() })
            Issue.record("expected paired failure")
        } catch {
            let outer = try #require(error as? OriginalConsumerContainmentFailure)
            let inner = try #require(outer.observation as? OriginalConsumerContainmentFailure)
            #expect(inner.observation is ArmFailure)
            #expect(inner.containment is ReleaseFailure)
            #expect(outer.containment is ContainmentFailure)
        }
        #expect(events == ["release", "contain"])
    }
}
#endif

#if os(macOS)
import CEngineCore
@testable import CEngineRuntime
import Foundation
import Testing

@Suite @MainActor struct StorageLifecycleFreshAbortTests {
    private final class FakeMachine {}

    @Test func neverStartedEOFSafelyReleasesWithoutGraceWaitOrForce() async throws {
        var starts = StorageLifecycleVMStartLifetime()
        let owner = VMShimMachineOwner<FakeMachine>()
        owner.machine = FakeMachine()
        let abort = StorageLifecycleFreshAbort(), exit = StorageLifecycleGuestExit()
        var closes = 0, forces = 0, clockReads = 0, waits = 0
        var instant: TimeInterval = 0
        let neverStarted = starts.freezeForAbort()
        abort.begin(exit: exit, neverStarted: neverStarted,
                    now: { clockReads += 1; return instant },
                    wait: { waits += 1; instant += 1 },
                    close: { _ in closes += 1 }, fallback: { forces += 1 })
        #expect(abort.neverStarted) // Proof is published synchronously, before scheduling.
        try await owner.stopAndRelease { _ in
            let clean = await abort.task?.value ?? false
            #expect(!clean) // This is a no-VM proof, not a clean Guest shutdown.
            guard StorageLifecycleFreshAbort.permitsRelease(clean: clean, forcedExit: false,
                                                             neverStarted: abort.neverStarted) else {
                throw CancellationError()
            }
        }
        #expect(owner.machine == nil)
        #expect(closes == 0 && forces == 0 && !abort.usedFallback)
        #expect(exit.stoppedAt == nil && starts.frozenAttemptCount == 0)
        #expect(clockReads == 0 && waits == 0) // No grace period, regardless of executor load.
        #expect(throws: CancellationError.self) { try starts.beginStart() }
    }

    @Test func startedAbortObservesTheFullTenSecondGraceBudget() async {
        let abort = StorageLifecycleFreshAbort()
        var instant: TimeInterval = 0
        var waits = 0, forces = 0
        abort.begin(exit: StorageLifecycleGuestExit(),
                    now: { instant }, wait: { waits += 1; instant += 1 },
                    close: { deadline in #expect(deadline == 10) },
                    fallback: { forces += 1 })
        #expect(await abort.task?.value == false)
        #expect(waits == 10 && instant == 10 && forces == 1 && abort.usedFallback)
    }

    @Test func attemptedStartCannotRegainNeverStartedProofOrReleaseLease() async throws {
        var starts = StorageLifecycleVMStartLifetime()
        try starts.beginStart() // VZ may throw or later report .stopped; count stays one.
        let neverStarted = starts.freezeForAbort()
        let owner = VMShimMachineOwner<FakeMachine>(), machine = FakeMachine()
        owner.machine = machine
        let abort = StorageLifecycleFreshAbort()
        var forces = 0
        abort.begin(exit: StorageLifecycleGuestExit(), neverStarted: neverStarted, timeout: 0,
                    close: { _ in }, fallback: { forces += 1 })
        await #expect(throws: CancellationError.self) {
            try await owner.stopAndRelease { _ in
                let clean = await abort.task?.value ?? false
                guard StorageLifecycleFreshAbort.permitsRelease(clean: clean, forcedExit: false,
                                                                 neverStarted: abort.neverStarted) else {
                    throw CancellationError()
                }
            }
        }
        #expect(owner.machine === machine && forces == 1 && abort.usedFallback)
        #expect(starts.attemptCount == 1 && starts.frozenAttemptCount == 1)
        let retry = starts.freezeForAbort()
        #expect(!retry)
        #expect(throws: CancellationError.self) { try starts.beginStart() }
    }

    @Test func enrolledLostDaemonACKPreservesVMAndDoesNotFreezeStartup() throws {
        var starts = StorageLifecycleVMStartLifetime()
        try starts.beginStart()
        let control = StorageLifecycleControlLifetime(), abort = StorageLifecycleFreshAbort()
        let generation = try control.captureGeneration()
        try control.beginEnrollment(); try control.enroll()
        let owner = VMShimMachineOwner<FakeMachine>(), machine = FakeMachine()
        owner.machine = machine
        if control.detach(generation) == .terminateUnenrolled {
            let neverStarted = starts.freezeForAbort()
            abort.begin(exit: StorageLifecycleGuestExit(), neverStarted: neverStarted,
                        close: { _ in Issue.record("enrolled DATA was closed") },
                        fallback: { Issue.record("enrolled VM was forced") })
        }
        #expect(control.preservesOwner && owner.machine === machine)
        #expect(abort.task == nil && starts.frozenAttemptCount == nil)
    }

    @Test(arguments: [false, true])
    func bootstrapConnectionCloseHasOneOwner(abortFirst: Bool) {
        var closes = 0, revocations = 0
        let lifetime = StorageLifecycleBootstrapConnectionLifetime(
            revoke: { revocations += 1 }, close: { closes += 1 })
        if abortFirst { lifetime.close(revoking: true) }
        lifetime.close() // Joined worker's defer.
        lifetime.close(revoking: true) // Repeated terminal notification.
        #expect(closes == 1 && revocations == (abortFirst ? 1 : 0))
    }

    @Test(arguments: [false, true])
    func lateHardStopCompletionIsExitEvidenceNotCleanSuccess(succeeded: Bool) async {
        var forcedExit = false
        var finish: (@MainActor (Result<Void, any Error>) -> Void)?
        let abort = StorageLifecycleFreshAbort()
        abort.begin(exit: StorageLifecycleGuestExit(), timeout: 0, close: { _ in }, fallback: {
            do {
                let _: Void = try await RawContainerVirtualMachine.awaitBoundedResult(
                    timeout: .milliseconds(1), start: { reply in
                        finish = { result in
                            // Match production: successful actual VZ completion
                            // records exit independently of the expired waiter.
                            if case .success = result { forcedExit = true }
                            reply(result)
                        }
                    })
            } catch {}
        })
        #expect(await abort.task?.value == false)
        #expect(!StorageLifecycleFreshAbort.permitsRelease(clean: false, forcedExit: forcedExit))
        finish?(succeeded ? .success(()) : .failure(CancellationError()))
        #expect(forcedExit == succeeded && abort.usedFallback)
        #expect(await abort.task?.value == false)
        #expect(StorageLifecycleFreshAbort.permitsRelease(clean: false, forcedExit: forcedExit) == succeeded)
    }

    @Test func earlyPositiveCallbackIsLatched() async {
        let exit = StorageLifecycleGuestExit(), abort = StorageLifecycleFreshAbort()
        exit.guestDidStop()
        var closes = 0, forces = 0
        abort.begin(exit: exit, close: { _ in closes += 1 }, fallback: { forces += 1 })
        #expect(await abort.task?.value == true)
        #expect(closes == 1 && forces == 0 && !abort.usedFallback)
    }

    @Test func errorIsNotCleanEvenWithPositiveCallback() async {
        let exit = StorageLifecycleGuestExit(), abort = StorageLifecycleFreshAbort()
        exit.didStopWithError(); exit.guestDidStop()
        var forces = 0
        abort.begin(exit: exit, close: { _ in }, fallback: { forces += 1 })
        #expect(await abort.task?.value == false)
        #expect(forces == 1 && abort.usedFallback)
    }

    @Test func timeoutAndLateCallbackNeverBecomeClean() async {
        let exit = StorageLifecycleGuestExit(), abort = StorageLifecycleFreshAbort()
        var forces = 0
        abort.begin(exit: exit, timeout: 0.01, close: { _ in }, fallback: {
            #expect(abort.usedFallback)
            forces += 1
            exit.guestDidStop()
        })
        #expect(await abort.task?.value == false)
        #expect(exit.stoppedAt != nil && abort.usedFallback && forces == 1)
        #expect(await abort.task?.value == false)
    }

    @Test func deadlineIncludesCloseAndRejectsLatePositive() async {
        let exit = StorageLifecycleGuestExit(), abort = StorageLifecycleFreshAbort()
        abort.begin(exit: exit, timeout: 0.01, close: { _ in
            try? await Task.sleep(for: .milliseconds(25))
            exit.guestDidStop()
        }, fallback: {})
        #expect(await abort.task?.value == false)
        #expect(abort.usedFallback)
    }

    @Test func concurrentCleanupJoinsSingleFlightDespiteCallerCancellation() async {
        let exit = StorageLifecycleGuestExit(), abort = StorageLifecycleFreshAbort()
        var closes = 0, forces = 0
        let caller = Task {
            abort.begin(exit: exit, timeout: 0.02, close: { _ in closes += 1 }, fallback: { forces += 1 })
            return await abort.task?.value
        }
        caller.cancel()
        await Task.yield()
        abort.begin(exit: exit, timeout: 0.02, close: { _ in closes += 1 }, fallback: { forces += 1 })
        #expect(await caller.value == false)
        #expect(await abort.task?.value == false)
        #expect(closes == 1 && forces == 1)
    }

    @Test func rollbackRequiresCleanResultOrPositiveForcedExit() {
        #expect(!StorageLifecycleFreshAbort.permitsRelease(clean: false, forcedExit: false))
        #expect(StorageLifecycleFreshAbort.permitsRelease(clean: true, forcedExit: false))
        #expect(StorageLifecycleFreshAbort.permitsRelease(clean: false, forcedExit: true))
        // Late/error notifications cannot replace the clean task's false result.
    }

    @Test func connectionIsConsumedBeforeCoordinatorOrConfiguration() {
        var established = StorageLifecycleBootPortOwnership()
        established.connectedOrUncertain()
        // Coordinator construction/configuration can fail, but never reconnect.
        let duplicate = established.claimEOFConnection()
        #expect(!duplicate)
        var first = StorageLifecycleBootPortOwnership()
        let firstClaim = first.claimEOFConnection(), secondClaim = first.claimEOFConnection()
        #expect(firstClaim && !secondClaim)
        #expect(StorageLifecycleFreshAbort.eligible(.journalDriven))
        #expect(StorageLifecycleFreshAbort.eligible(.resumeReadOnly))
        #expect(!StorageLifecycleFreshAbort.eligible(.requireInitializedStorage))
    }

    @Test func enrollmentEOFSelectsTerminationButLostDaemonACKPreserves() throws {
        let pending = StorageLifecycleControlLifetime()
        let generation = try pending.captureGeneration()
        try pending.beginEnrollment()
        #expect(pending.detach(generation) == .terminateUnenrolled)
        #expect(throws: (any Error).self) { try pending.enroll() }
        let acknowledged = StorageLifecycleControlLifetime()
        let acknowledgedGeneration = try acknowledged.captureGeneration()
        try acknowledged.beginEnrollment(); try acknowledged.enroll()
        // No daemon reply ACK follows the actual ROOT enrollment callback.
        #expect(acknowledged.detach(acknowledgedGeneration) == .preserved)
        #expect(acknowledged.preservesOwner)
    }
}
#endif

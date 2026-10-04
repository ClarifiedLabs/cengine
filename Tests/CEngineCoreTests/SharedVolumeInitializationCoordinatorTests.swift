import Foundation
import Testing
@testable import CEngineRuntime

@Suite(.timeLimit(.minutes(1))) struct SharedVolumeInitializationCoordinatorTests {
    private enum Failure: Error { case expected }

    private actor Signal {
        private var signalled = false
        private var waiters: [CheckedContinuation<Void, Never>] = []

        func wait() async {
            if signalled { return }
            await withCheckedContinuation { waiters.append($0) }
        }

        func signal() {
            signalled = true
            let pending = waiters
            waiters.removeAll()
            for waiter in pending { waiter.resume() }
        }
    }

    private func waitForQueue(
        _ coordinator: SharedVolumeInitializationCoordinator, count: Int
    ) async throws {
        let deadline = ContinuousClock.now + .seconds(5)
        while coordinator.waitingCount != count, ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(1))
        }
        try #require(coordinator.waitingCount == count)
    }

    @Test func overlappingNamesWaitWhileDisjointNamesProceedWithoutPartialReservation() async throws {
        let coordinator = SharedVolumeInitializationCoordinator()
        let first = try await coordinator.acquire(["a", "b"])
        defer { first.release() }
        let overlapping = Task { try await coordinator.acquire(["b", "c"]) }
        defer { overlapping.cancel() }
        try await waitForQueue(coordinator, count: 1)

        // The blocked {b,c} request must not hold c while waiting for b.
        let disjoint = try await coordinator.acquire(["c"])
        disjoint.release()
        #expect(coordinator.waitingCount == 1)
        let empty = try await coordinator.acquire([])
        empty.release()

        first.release()
        let next = try await overlapping.value
        next.release()
        // Releasing the old lease again cannot release a replacement owner.
        let owner = try await coordinator.acquire(["b"])
        first.release()
        let last = Task { try await coordinator.acquire(["b"]) }
        defer { last.cancel() }
        try await waitForQueue(coordinator, count: 1)
        owner.release()
        try await last.value.release()
    }

    @Test func reversedAndDuplicateNamesAcquireAtomically() async throws {
        let coordinator = SharedVolumeInitializationCoordinator()
        let blocker = try await coordinator.acquire(["a", "b"])
        defer { blocker.release() }
        let forward = Task { try await coordinator.acquire(["a", "b", "a"]) }
        defer { forward.cancel() }
        try await waitForQueue(coordinator, count: 1)
        let reverse = Task { try await coordinator.acquire(["b", "a"]) }
        defer { reverse.cancel() }
        try await waitForQueue(coordinator, count: 2)
        blocker.release()
        let forwardLease = try await forward.value
        #expect(coordinator.waitingCount == 1)
        forwardLease.release()
        try await reverse.value.release()
    }

    @Test func successAndErrorReleaseEveryName() async throws {
        let coordinator = SharedVolumeInitializationCoordinator()
        #expect(try await coordinator.withInitialization(of: ["a", "b"]) { 42 } == 42)
        await #expect(throws: Failure.self) {
            try await coordinator.withInitialization(of: ["b", "a"]) {
                throw Failure.expected
            }
        }
        let next = try await coordinator.acquire(["a", "b"])
        next.release()
    }

    @Test func cancelledWaiterExitsBeforeHolderReleasesAndDoesNotRunPrepare() async throws {
        let coordinator = SharedVolumeInitializationCoordinator()
        let holder = try await coordinator.acquire(["a"])
        defer { holder.release() }
        let cancelled = Task {
            try await coordinator.withInitialization(of: ["a", "b"]) { () -> Void in
                Issue.record("cancelled waiter must not prepare")
            }
        }
        try await waitForQueue(coordinator, count: 1)
        cancelled.cancel()
        await #expect(throws: CancellationError.self) { try await cancelled.value }
        #expect(coordinator.waitingCount == 0)
        let free = try await coordinator.acquire(["b"])
        free.release()
        holder.release()
        let next = try await coordinator.acquire(["a", "b"])
        next.release()
    }

    @Test func alreadyCancelledTaskDoesNotAcquire() async throws {
        let coordinator = SharedVolumeInitializationCoordinator()
        let proceed = Signal()
        let cancelled = Task {
            await proceed.wait()
            try await coordinator.withInitialization(of: ["a"]) { () -> Void in
                Issue.record("already cancelled task must not prepare")
            }
        }
        cancelled.cancel()
        await proceed.signal()
        await #expect(throws: CancellationError.self) { try await cancelled.value }
        let next = try await coordinator.acquire(["a"])
        next.release()
    }

    @Test func cancellationRacingGrantDoesNotLeakNames() async throws {
        let coordinator = SharedVolumeInitializationCoordinator()
        for _ in 0..<100 {
            let holder = try await coordinator.acquire(["a", "b"])
            let waiter = Task {
                try await coordinator.withInitialization(of: ["b", "a"]) {
                    await Task.yield()
                }
            }
            try await waitForQueue(coordinator, count: 1)
            await withTaskGroup(of: Void.self) { group in
                group.addTask { holder.release() }
                group.addTask { waiter.cancel() }
            }
            do { try await waiter.value }
            catch is CancellationError { }
            #expect(coordinator.waitingCount == 0)
            let next = try await coordinator.acquire(["a", "b"])
            next.release()
        }
    }

    @Test func cancellationKeepsActivePrepareProtectedUntilItUnwinds() async throws {
        let coordinator = SharedVolumeInitializationCoordinator()
        let entered = Signal()
        let finish = Signal()
        let active = Task {
            try await coordinator.withInitialization(of: ["a", "b"]) {
                await entered.signal()
                // Like the guest RPC, this does not return on notification alone.
                await finish.wait()
            }
        }
        await entered.wait()
        active.cancel()
        let next = Task { try await coordinator.acquire(["b", "a"]) }
        defer { next.cancel() }
        try await waitForQueue(coordinator, count: 1)
        await finish.signal()
        await #expect(throws: CancellationError.self) { try await active.value }
        try await next.value.release()
    }
}

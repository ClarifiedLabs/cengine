#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

@MainActor private final class ObservationBarrier {
    private var signaled = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    func wait() async {
        if signaled { return }
        await withCheckedContinuation { waiters.append($0) }
    }
    func signal() {
        signaled = true
        let pending = waiters; waiters.removeAll()
        for waiter in pending { waiter.resume() }
    }
}

@Suite @MainActor struct OriginalConsumerObservationLifetimeTests {
    // Functional fixture budget, not the responsiveness assertion: stop must run
    // after positive readiness while the partial-frame operation is unfinished.
    private static let functionalFixtureBudgetNanoseconds: UInt64 = 15_000_000_000
    private enum FixtureReadinessFailure: Error { case endedBeforeStop }

    private func requireFixtureReadiness<Value: Sendable>(
        _ events: AsyncStream<Void>, task: Task<Value, any Error>, isFinished: () -> Bool
    ) async throws {
        var iterator = events.makeAsyncIterator()
        let ready = await iterator.next()
        guard ready != nil, !isFinished() else {
            // A closed stream is not readiness. Surface the original transport
            // error (including expiration before the worker enters), not success.
            _ = try await task.value
            throw FixtureReadinessFailure.endedBeforeStop
        }
    }

    @Test func staleProbeCleanupCannotClearReleaseOwnership() async throws {
        let lease = OriginalConsumerObservationLease()
        let old = try lease.reserveExchange()
        let cleanupEntered = ObservationBarrier(), finishCleanup = ObservationBarrier(), joined = ObservationBarrier()
        let probe = Task {
            cleanupEntered.signal() // Inner IO has returned; full exchange cleanup has not.
            await finishCleanup.wait()
            #expect(lease.finishExchange(old))
        }
        await cleanupEntered.wait()
        let teardown = Task {
            probe.cancel()
            await probe.value
            joined.signal()
        }
        #expect(throws: (any Error).self) { try lease.reserveExchange() }
        finishCleanup.signal()
        await joined.wait(); await teardown.value
        let release = try lease.reserveExchange()
        #expect(!lease.finishExchange(old)) // Delayed old wrapper cannot clear Release.
        #expect(lease.exchangeID == release)
        #expect(lease.finishExchange(release))
    }

    @Test func forcedStopJoinsReleaseCleanupBeforeNativeStop() async throws {
        let lease = OriginalConsumerObservationLease()
        try lease.arm("arm"); try lease.begin("arm", now: 1)
        let release = try lease.reserveExchange()
        let entered = ObservationBarrier(), finish = ObservationBarrier(), stopEntered = ObservationBarrier()
        var stopped = false, cleaned = false
        let releaseTask = Task {
            entered.signal(); await finish.wait()
            cleaned = true; #expect(lease.finishExchange(release))
        }
        await entered.wait()
        let stop = Task {
            #expect(lease.stop(.forced, now: 2) == nil)
            releaseTask.cancel(); stopEntered.signal()
            await releaseTask.value
            #expect(cleaned && lease.exchangeID == nil)
            stopped = true
        }
        await stopEntered.wait()
        #expect(!stopped)
        finish.signal(); await stop.value
        #expect(stopped)
    }

    @Test func postArmValidationFailureConsumesLeaseAndRetainsContainmentFailure() async throws {
        let lease = OriginalConsumerObservationLease()
        try lease.arm("original")
        lease.cancel() // The outer shim guard does this for every post-Arm failure.
        #expect(lease.stop(.forced, now: 1) == nil)
        #expect(throws: (any Error).self) { try lease.begin("original", now: 2) }
        let error = OriginalConsumerContainmentFailure(
            observation: EngineError(.badRequest, "bad binding"),
            containment: EngineError(.internalError, "disk retained"))
        #expect(error.localizedDescription.contains("bad binding"))
        #expect(error.localizedDescription.contains("disk retained"))
    }

    @Test func observerIdentityCannotRetainMachineAfterPositiveOwnerRelease() async throws {
        final class Machine {}
        let owner = VMShimMachineOwner<Machine>(), lease = OriginalConsumerObservationLease()
        var machine: Machine? = Machine()
        weak var weakMachine = machine
        owner.machine = machine
        try lease.arm("arm"); try lease.bindMachine(try #require(machine))
        machine = nil
        try await owner.stopAndRelease(stop: { _ in })
        #expect(weakMachine == nil) // Lease has no disk-owning reference.
        #expect(!lease.matchesMachine(Machine()))
        #expect(throws: (any Error).self) { try lease.bindMachine(Machine()) }
        lease.releaseMachineIdentity()
        #expect(lease.armID == "arm")
        #expect(throws: (any Error).self) { try lease.arm("replacement") }
    }

    @Test func terminalDuringStreamConnectRejectsBeforeSetupOrAcknowledgement() async throws {
        let connectEntered = ObservationBarrier(), connected = ObservationBarrier()
        var terminal = false, setup = false, acknowledgement = false
        let stream = Task {
            connectEntered.signal(); await connected.wait()
            try VMShimServer.requireStreamAdmission(isCurrent: true, terminal: terminal, stopping: false, state: .running)
            setup = true; acknowledgement = true
        }
        await connectEntered.wait()
        terminal = true; connected.signal()
        await #expect(throws: (any Error).self) { try await stream.value }
        #expect(!setup && !acknowledgement)
        #expect(throws: (any Error).self) {
            try VMShimServer.requireStreamAdmission(isCurrent: false, terminal: false, stopping: false, state: .running)
        }
    }

    @Test func partialManagedContainerFrameDoesNotBlockMainActorStop() async throws {
        var specification = VMShimProtocol.Specification(containerID: "test", generation: 1, token: "unused",
            kernelPath: "/unused", initialRamdiskPath: "/unused", rootDiskPath: "/unused",
            cpus: 1, memoryBytes: 1_073_741_824, macAddress: "02:00:00:00:00:01",
            socketPath: "/unused", logPath: "/unused", workloadStorageMode: .managed)
        #expect(VMShimServer.requiresBoundedInitialFrame(specification))
        specification.workloadStorageMode = .none
        #expect(!VMShimServer.requiresBoundedInitialFrame(specification))
        var fds: [CInt] = [-1, -1]
        try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        let accepted = fds[0], peer = fds[1]
        defer { Darwin.close(accepted); Darwin.close(peer) }
        let bytes = Data([0, 0])
        try bytes.withUnsafeBytes { try #require(Darwin.write(peer, $0.baseAddress, $0.count) == 2) }
        let events = AsyncStream<Void>.makeStream()
        var readFinished = false
        let readerTask = Task {
            defer { readFinished = true; events.continuation.finish() }
            return try await VMShimServer.managedSocketIO(accepted,
                deadline: DispatchTime.now().uptimeNanoseconds + Self.functionalFixtureBudgetNanoseconds) { transport in
                events.continuation.yield(())
                return try VMShimServer.readInitialManagedRequestFrame(using: transport)
            }
        }
        do {
            try await requireFixtureReadiness(events.stream, task: readerTask, isFinished: { readFinished })
            try #require(!readFinished)
            let lease = OriginalConsumerObservationLease()
            try lease.arm("arm"); try lease.begin("arm", now: 1)
            #expect(lease.stop(.forced, now: 2) == nil) // Executes while peer is stalled.
        } catch {
            _ = Darwin.shutdown(peer, SHUT_RDWR)
            _ = await readerTask.result // Join before deferred descriptor cleanup, even on assertion failure.
            throw error
        }
        _ = Darwin.shutdown(peer, SHUT_RDWR)
        await #expect(throws: POSIXError.self) { try await readerTask.value } // EOF, not a fixture timeout.
    }

    @Test func partialPortSetupReplyDoesNotBlockMainActorStop() async throws {
        var fds: [CInt] = [-1, -1]
        try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        let accepted = fds[0]
        let peerFD = fds[1]
        defer { Darwin.close(accepted); Darwin.close(peerFD) }
        let events = AsyncStream<Void>.makeStream()
        var setupFinished = false
        let setup = Task {
            defer { setupFinished = true; events.continuation.finish() }
            // Start both transport budgets together, after this MainActor task is
            // scheduled. Suite startup must not consume the fixture peer's budget.
            let deadline = DispatchTime.now().uptimeNanoseconds + Self.functionalFixtureBudgetNanoseconds
            let peer = VMShimManagedTransport(deadlineNanoseconds: deadline)
            let owned = dup(peerFD)
            try #require(owned >= 0)
            do { try peer.adopt(owned) } catch { Darwin.close(owned); throw error }
            defer { peer.close() }
            async let writer = peer.run { io in
                _ = try io.readFrame() // Positive setup request, then stall in its reply prefix.
                try io.write(Data([0, 0]))
                events.continuation.yield(())
                return Data()
            }
            do {
                try await VMShimServer.preparePortStreamSetup(accepted, payload: Data("{}".utf8),
                    deadline: deadline)
                _ = try await writer
            } catch {
                peer.cancel()
                _ = try? await writer // Join before closing the peer, including on failure.
                throw error
            }
        }
        do {
            try await requireFixtureReadiness(events.stream, task: setup, isFinished: { setupFinished })
            try #require(!setupFinished)
            let lease = OriginalConsumerObservationLease()
            try lease.arm("arm"); try lease.begin("arm", now: 1)
            #expect(lease.stop(.forced, now: 2) == nil)
        } catch {
            _ = Darwin.shutdown(peerFD, SHUT_RDWR)
            _ = await setup.result
            throw error
        }
        _ = Darwin.shutdown(peerFD, SHUT_RDWR)
        await #expect(throws: POSIXError.self) { try await setup.value }
    }

    @Test func expiredManagedReaderPropagatesErrorThroughReadinessWait() async throws {
        var fds: [CInt] = [-1, -1]
        try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        let accepted = fds[0], peer = fds[1]
        defer { Darwin.close(accepted); Darwin.close(peer) }
        let events = AsyncStream<Void>.makeStream()
        var readFinished = false
        let readerTask = Task {
            defer { readFinished = true; events.continuation.finish() }
            return try await VMShimServer.managedSocketIO(accepted, deadline: 0) { transport in
                Issue.record("Expired transport entered its operation")
                events.continuation.yield(())
                return try VMShimServer.readInitialManagedRequestFrame(using: transport)
            }
        }
        await #expect(throws: AsyncTimeout.TimeoutError.self) {
            try await requireFixtureReadiness(events.stream, task: readerTask, isFinished: { readFinished })
        }
        _ = Darwin.shutdown(peer, SHUT_RDWR)
        _ = await readerTask.result
        #expect(readFinished)
    }

    @Test(arguments: [false, true])
    func finishedFixtureCannotCountAsReadiness(yieldBeforeFinishing: Bool) async {
        let events = AsyncStream<Void>.makeStream()
        var finished = false
        let task = Task<Void, any Error> {
            defer { finished = true; events.continuation.finish() }
            if yieldBeforeFinishing { events.continuation.yield(()) }
        }
        _ = await task.result // Deterministically test both nil and stale buffered readiness.
        await #expect(throws: FixtureReadinessFailure.self) {
            try await requireFixtureReadiness(events.stream, task: task, isFinished: { finished })
        }
    }

    @Test func initialFramePermitReleasesBeforeLongLivedOperationAndOnlyOnce() throws {
        let admission = VMShimManagedAdmission()
        var fds: [CInt] = [-1, -1]
        try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        defer { Darwin.close(fds[1]) }
        let permit = try #require(admission.reserve(fds[0], deadline: DispatchTime.now().uptimeNanoseconds + 1_000_000_000))
        let owned = try #require(permit.take())
        defer { Darwin.close(owned) }
        permit.finishInitialFrame(); permit.finishInitialFrame()
        var retained: [VMShimManagedAdmission.Permit] = []
        defer { withExtendedLifetime(retained) {} }
        for _ in 0..<64 {
            let fd = dup(owned); try #require(fd >= 0)
            guard let next = admission.reserve(fd, deadline: DispatchTime.now().uptimeNanoseconds + 1_000_000_000) else {
                Darwin.close(fd); Issue.record("initial frame permit still held admission"); return
            }
            retained.append(next)
        }
        let extra = dup(owned); defer { Darwin.close(extra) }
        #expect(admission.reserve(extra, deadline: DispatchTime.now().uptimeNanoseconds + 1_000_000_000) == nil)
    }
}
#endif

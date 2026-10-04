#if os(macOS)
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

@Suite @MainActor struct VMShimBootGateTests {
    @Test func concurrentBootRequestsJoinOneOperation() async throws {
        let gate = VMShimBootGate()
        let entered = BootLatch(), release = BootLatch(), secondEntered = BootLatch()
        var boots = 0
        let first = Task { try await gate.boot { boots += 1; entered.signal(); await release.wait() } }
        await entered.wait()
        let second = Task {
            secondEntered.signal()
            try await gate.boot { boots += 1 }
        }
        await secondEntered.wait()
        #expect(boots == 1)
        release.signal()
        try await first.value
        try await second.value
        #expect(boots == 1)
    }

    @Test func stopWaitsForCancelledBootstrapBeforeTeardown() async throws {
        let gate = VMShimBootGate()
        let entered = BootLatch(), release = BootLatch(), stopEntered = BootLatch()
        var bootSettled = false, stopped = false, published = false
        let boot = Task {
            try await gate.boot {
                entered.signal()
                await release.wait() // Models an in-flight callback that must settle.
                defer { bootSettled = true }
                try Task.checkCancellation()
                published = true
            }
        }
        await entered.wait()
        let stop = Task {
            stopEntered.signal()
            try await gate.stop {
                #expect(bootSettled)
                stopped = true
            }
        }
        await stopEntered.wait()
        #expect(gate.isStopping)
        #expect(!stopped)
        await #expect(throws: (any Error).self) { try await gate.boot { published = true } }
        release.signal()
        await #expect(throws: CancellationError.self) { try await boot.value }
        try await stop.value
        #expect(stopped)
        #expect(!published)
    }

    @Test func concurrentStopsCannotClearAReplacementGeneration() async throws {
        let gate = VMShimBootGate()
        let entered = BootLatch(), release = BootLatch(), secondEntered = BootLatch()
        var stops = 0, generation = 1
        let first = Task {
            try await gate.stop {
                stops += 1
                let captured = generation
                entered.signal()
                await release.wait()
                #expect(generation == captured)
                generation = 0
            }
        }
        await entered.wait()
        let second = Task {
            secondEntered.signal()
            try await gate.stop { stops += 1; generation = 0 }
        }
        await secondEntered.wait()
        await #expect(throws: (any Error).self) { try await gate.boot { generation = 2 } }
        #expect(stops == 1)
        release.signal()
        try await first.value
        try await second.value
        #expect(stops == 1)
        try await gate.boot { generation = 2 }
        #expect(generation == 2)
    }

    @Test func completionBookkeepingPrecedesStopWaiters() async throws {
        let gate = VMShimBootGate()
        let completed = BootLatch()
        var stopping = false, admissions = 0, teardowns = 0
        let first = Task {
            try await gate.stop(willStop: { stopping = true; admissions += 1 }) {
                teardowns += 1
                stopping = false
                completed.signal()
            }
        }
        await completed.wait()
        // This request can run before the original stop caller resumes. Either
        // joining or admitting a fresh no-op stop must leave the final status stopped.
        try await gate.stop(willStop: { stopping = true; admissions += 1 }) {
            teardowns += 1
            stopping = false
        }
        try await first.value
        #expect(!stopping)
        #expect(admissions == teardowns)
        #expect(!gate.isStopping)
    }

    @Test func completedStopKeepsAdmissionClosedUntilEveryResponseIsWritten() async throws {
        let gate = VMShimBootGate()
        gate.beginStopResponse(shutdown: false)
        gate.beginStopResponse(shutdown: false)
        try await gate.stop {}
        await #expect(throws: (any Error).self) { try await gate.boot { Issue.record("boot before stop reply") } }
        gate.endStopResponse()
        await #expect(throws: (any Error).self) { try await gate.boot { Issue.record("boot before joined stop reply") } }
        gate.endStopResponse()
        var booted = false
        try await gate.boot { booted = true }
        #expect(booted)
    }

    @Test func shutdownNeverReopensBootAdmission() async throws {
        let gate = VMShimBootGate()
        gate.beginStopResponse(shutdown: true)
        try await gate.stop {}
        gate.endStopResponse()
        await #expect(throws: (any Error).self) { try await gate.boot { Issue.record("boot after shutdown") } }
    }

    @Test func lateOperationAndOldCallbackCannotPublishForReplacement() async throws {
        final class Machine {}
        let owner = VMShimMachineOwner<Machine>()
        let old = Machine(), replacement = Machine()
        owner.machine = old
        let entered = BootLatch(), release = BootLatch()
        var published = false
        let delayedResume = Task {
            entered.signal()
            await release.wait()
            try owner.requireCurrent(old)
            published = true
        }
        await entered.wait()
        try await owner.stopAndRelease(stop: { _ in })
        owner.machine = replacement
        // The same check guards queued spool failure callbacks before admission.
        #expect(!owner.isCurrent(old))
        #expect(owner.isCurrent(replacement))
        release.signal()
        await #expect(throws: (any Error).self) { try await delayedResume.value }
        #expect(!published)
        #expect(owner.machine === replacement)
    }

    @Test func lateOperationCannotPublishWhileSameMachineIsTearingDown() async throws {
        final class Machine {}
        let owner = VMShimMachineOwner<Machine>()
        let machine = Machine()
        owner.machine = machine
        let gate = VMShimBootGate()
        let operationEntered = BootLatch(), operationReleased = BootLatch()
        let stopEntered = BootLatch(), stopReleased = BootLatch()
        var published = false
        let operation = Task {
            operationEntered.signal()
            await operationReleased.wait()
            try owner.requireCurrent(machine, teardownInProgress: gate.isStopping)
            published = true
        }
        await operationEntered.wait()
        let stop = Task {
            try await gate.stop {
                try await owner.stopAndRelease(stop: { _ in
                    stopEntered.signal()
                    await stopReleased.wait()
                })
            }
        }
        await stopEntered.wait()
        #expect(owner.isCurrent(machine))
        #expect(gate.isStopping)
        operationReleased.signal()
        await #expect(throws: (any Error).self) { try await operation.value }
        #expect(!published)
        stopReleased.signal()
        try await stop.value
        #expect(owner.machine == nil)
    }

    @Test func failedTeardownKeepsAdmissionClosedAndActualDiskLeaseHeld() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "cengine-boot-gate-\(UUID())")
        try Data().write(to: root)
        defer { try? FileManager.default.removeItem(at: root) }
        let owner = VMShimMachineOwner<BootOwnedMachine>()
        owner.machine = try BootOwnedMachine(path: root)
        weak var owned = owner.machine
        let gate = VMShimBootGate()
        await #expect(throws: POSIXError.self) {
            try await gate.stop {
                try await owner.stopAndRelease(stop: { _ in throw POSIXError(.EIO) })
            }
        }
        #expect(owner.machine != nil)
        #expect(owned != nil)
        #expect(gate.isStopping)
        await #expect(throws: (any Error).self) { try await gate.boot { Issue.record("boot escaped failed teardown") } }
        let competing = try FileHandle(forUpdating: root)
        defer { try? competing.close() }
        #expect(flock(competing.fileDescriptor, LOCK_EX | LOCK_NB) == -1)
        #expect(errno == EWOULDBLOCK)
        // Explicit stop retry may release ownership only after its operation succeeds.
        try await gate.stop {
            try await owner.stopAndRelease(stop: { $0.stopped = true })
        }
        #expect(!gate.isStopping)
        #expect(owner.machine == nil)
        #expect(owned == nil)
    }

    @Test func cleanupFailureAlsoRetainsTheProductionOwner() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "cengine-boot-owner-\(UUID())")
        try Data().write(to: root)
        defer { try? FileManager.default.removeItem(at: root) }
        let owner = VMShimMachineOwner<BootOwnedMachine>()
        owner.machine = try BootOwnedMachine(path: root)
        await #expect(throws: POSIXError.self) {
            try await owner.stopAndRelease(stop: { $0.stopped = true }) { throw POSIXError(.EIO) }
        }
        #expect(owner.machine?.stopped == true)
        let competing = try FileHandle(forUpdating: root)
        defer { try? competing.close() }
        #expect(flock(competing.fileDescriptor, LOCK_EX | LOCK_NB) == -1)
        #expect(errno == EWOULDBLOCK)
        try await owner.stopAndRelease(stop: { $0.stopped = true })
        #expect(owner.machine == nil)
    }
}

@MainActor private final class BootOwnedMachine {
    let handle: FileHandle
    var stopped = false
    init(path: URL) throws {
        handle = try FileHandle(forUpdating: path)
        guard flock(handle.fileDescriptor, LOCK_EX | LOCK_NB) == 0 else { throw POSIXError(.EIO) }
    }
}

@MainActor private final class BootLatch {
    private var signaled = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    func signal() {
        signaled = true
        let pending = waiters
        waiters.removeAll()
        pending.forEach { $0.resume() }
    }
    func wait() async {
        if signaled { return }
        await withCheckedContinuation { waiters.append($0) }
    }
}
#endif

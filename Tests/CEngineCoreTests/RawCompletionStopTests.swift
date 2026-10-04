#if os(macOS)
import Foundation
import Testing
@testable import CEngineRuntime

@Suite @MainActor struct RawCompletionStopTests {
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

    @MainActor private final class Harness {
        final class Shim { var stops = 0 }
        let work = RawServiceWorkTracker()
        var fence = RawBackendExecutionFence()
        var epoch = UUID()
        var shim = Shim()
        var retirements = 0
        var publications = 0
        var replacementOwned = false

        func wait(completionEntered: Signal, resumeCompletion: Signal,
            fabricEntered: Signal? = nil, resumeFabric: Signal? = nil,
            stopEntered: Signal? = nil, resumeStop: Signal? = nil,
            stopThrows: Bool = false) async throws -> Int32 {
            let generation = fence.currentOrInstall("container")
            let capturedEpoch = epoch, capturedShim = shim
            return try await RawCompletionStop.run(work: work, complete: {
                completionEntered.signal()
                await resumeCompletion.wait()
                // recordCompletion skips managed retirement for a stale execution.
                if self.fence.owns("container", token: generation) { self.retirements += 1 }
                return try await RawCompletionPublisher.run(fence: self.fence,
                    identifier: "container", generation: generation, publish: {
                        self.publications += 1
                        self.replacementOwned = false
                        return RawCompletionPublication(value: Int32(42), synchronizeFabric: true)
                    }, synchronizeFabric: {
                        fabricEntered?.signal()
                        await resumeFabric?.wait()
                    }) ?? 42
            }, ownsExecution: {
                self.fence.owns("container", token: generation)
                    && self.epoch == capturedEpoch && self.shim === capturedShim
            }, stop: {
                capturedShim.stops += 1
                stopEntered?.signal()
                await resumeStop?.wait()
                if stopThrows { throw StopFailure() }
            })
        }
    }
    private struct StopFailure: Error {}

    @Test func staleCompletionReturnsCodeWithoutRetiringSuccessorOrStoppingOldShim() async throws {
        let h = Harness(), entered = Signal(), resume = Signal()
        let oldShim = h.shim
        let wait = Task { try await h.wait(completionEntered: entered, resumeCompletion: resume) }
        await entered.wait()
        // Preflight closes and joins destruction before Arm; replacement then fences E.
        h.work.close(); try await h.work.join(); try h.work.requireQuiescent()
        h.epoch = UUID(); _ = h.fence.replace("container")
        h.shim = Harness.Shim(); h.replacementOwned = true
        resume.signal()
        #expect(try await wait.value == 42)
        #expect(h.retirements == 0 && h.publications == 0)
        #expect(h.replacementOwned && oldShim.stops == 0 && h.shim.stops == 0)
        try h.work.requireQuiescent()
    }

    @Test(arguments: ["execution", "shim", "service", "closed-admission"])
    func publicationSuspensionRequiresFreshOwnershipAndAdmission(change: String) async throws {
        let h = Harness(), entered = Signal(), resume = Signal()
        let fabric = Signal(), resumeFabric = Signal(), oldShim = h.shim
        resume.signal()
        let wait = Task { try await h.wait(completionEntered: entered, resumeCompletion: resume,
            fabricEntered: fabric, resumeFabric: resumeFabric) }
        await fabric.wait()
        #expect(h.publications == 1)
        switch change {
        case "execution": _ = h.fence.replace("container")
        case "shim": h.shim = Harness.Shim()
        case "service": h.epoch = UUID()
        default:
            // No execution/epoch change yet: the admission gate alone must reject.
            h.work.close(); try await h.work.join(); try h.work.requireQuiescent()
        }
        h.replacementOwned = true
        resumeFabric.signal()
        #expect(try await wait.value == 42)
        #expect(h.replacementOwned && oldShim.stops == 0 && h.shim.stops == 0)
    }

    @Test(arguments: [false, true])
    func begunStopMustFinishBeforePreflightCanArm(stopThrows: Bool) async throws {
        let h = Harness(), entered = Signal(), resume = Signal()
        let stopping = Signal(), finishStop = Signal(), joining = Signal()
        resume.signal()
        let wait = Task { try await h.wait(completionEntered: entered, resumeCompletion: resume,
            stopEntered: stopping, resumeStop: finishStop, stopThrows: stopThrows) }
        await stopping.wait()
        h.work.close()
        #expect(throws: (any Error).self) { try h.work.requireQuiescent() }
        // A bounded join cannot claim Arm eligibility while stop is suspended.
        await #expect(throws: (any Error).self) { try await h.work.join(timeout: .zero) }
        var armed = false
        let preflight = Task {
            joining.signal()
            try await h.work.join()
            try h.work.requireQuiescent()
            armed = true
        }
        await joining.wait()
        #expect(!armed)
        finishStop.signal()
        #expect(try await wait.value == 42)
        try await preflight.value
        #expect(armed && h.shim.stops == 1)
        try h.work.requireQuiescent()
        // Successful replacement reopens this lane for the next current execution.
        try h.work.reopen()
        #expect(try await h.wait(completionEntered: entered, resumeCompletion: resume) == 42)
        #expect(h.shim.stops == 2)
    }

    @Test func ordinaryCurrentCompletionPublishesThenStops() async throws {
        let h = Harness(), entered = Signal(), resume = Signal()
        resume.signal()
        #expect(try await h.wait(completionEntered: entered, resumeCompletion: resume) == 42)
        #expect(h.retirements == 1 && h.publications == 1 && h.shim.stops == 1)
        h.work.close(); try await h.work.join(); try h.work.requireQuiescent()
    }

    @Test func completionFailureDoesNotStopOrRetainWork() async throws {
        let work = RawServiceWorkTracker()
        var stops = 0
        await #expect(throws: StopFailure.self) {
            let _: Int32 = try await RawCompletionStop.run(work: work,
                complete: { throw StopFailure() }, ownsExecution: { true }, stop: { stops += 1 })
        }
        #expect(stops == 0)
        work.close(); try await work.join(); try work.requireQuiescent()
    }
}
#endif

import CEngineCore
import Dispatch
import Foundation
import Testing
@testable import CEngineRuntime

@Suite struct OriginalConsumerHostDiagnosticTests {
    private final class PrivateError: Error, CustomStringConvertible, @unchecked Sendable {
        var description: String { fatalError("must not inspect arbitrary error text") }
    }
    private func binding(_ caseName: OriginalConsumerObservationProtocol.Case = .crossEOldLeafReconnect) -> OriginalConsumerObservationProtocol.Binding {
        let id = "11111111-1111-4111-8111-111111111111"
        let other = "22222222-2222-4222-8222-222222222222"
        let hash = String(repeating: "ab", count: 32)
        return .init(requestID: id, armDigest: hash, operationUUID: other, caseName: caseName, generation: 7,
            boot: .init(shimLaunchUUID: id, guestBootNonce: other),
            scope: .init(intent: id, store: other, serviceEpoch: other, controllerEpoch: 1,
                controllerKey: hash, container: hash, containerInstance: other, launch: id,
                prepare: other, specificationDigest: hash),
            targetAttachment: other, key: hash, certificateSHA256: hash)
    }
    @Test func onlyValidRetainedFullDiagnosticCasesEnable() throws {
        #expect(!OriginalConsumerHostDiagnostic.enabled(nil))
        for name in OriginalConsumerObservationProtocol.Case.allCases {
            #expect(OriginalConsumerHostDiagnostic.enabled(binding(name)))
        }
        let data = try JSONEncoder().encode(binding())
        for (key, value) in [("profile", "other"), ("requestID", "private invalid"), ("armDigest", "secret"), ("version", 9)] as [(String, Any)] {
            var object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
            object[key] = value
            let bad = try JSONDecoder().decode(OriginalConsumerObservationProtocol.Binding.self,
                from: JSONSerialization.data(withJSONObject: object))
            #expect(!OriginalConsumerHostDiagnostic.enabled(bad))
        }
    }
    private final class Lines: @unchecked Sendable {
        private let condition = NSCondition()
        private var values: [String] = []
        func append(_ data: Data) {
            condition.lock()
            values.append(String(decoding: data, as: UTF8.self))
            condition.broadcast()
            condition.unlock()
        }
        func waitForCount(_ count: Int) -> [String] {
            condition.lock()
            defer { condition.unlock() }
            let deadline = Date().addingTimeInterval(3)
            while values.count < count {
                if !condition.wait(until: deadline) { break }
            }
            return values
        }
    }
    @Test func closedVocabularyAndThrowingSinkNeverChangeErrorIdentity() {
        let original = PrivateError()
        let lines = Lines()
        let writes = Lines()
        let sink = OriginalConsumerHostDiagnostic.Sink { lines.append($0) }
        let throwingSink = OriginalConsumerHostDiagnostic.Sink {
            writes.append($0)
            throw CancellationError()
        }
        var expected: [String] = []
        for stage in OriginalConsumerHostDiagnostic.Stage.allCases {
            let diagnostic = OriginalConsumerHostDiagnostic(enabled: true, stage: stage)
            diagnostic.report(original, sink: sink)
            expected.append("cengine original-host-failure stage=\(stage.rawValue) category=other\n")
            #expect(lines.waitForCount(expected.count) == expected)
            do {
                do { throw original }
                catch {
                    diagnostic.report(error, sink: throwingSink)
                    throw error
                }
            } catch { #expect((error as? PrivateError) === original) }
            #expect(writes.waitForCount(expected.count) == expected)
        }
        let disabled = OriginalConsumerHostDiagnostic(enabled: false, stage: .clientExchange)
        disabled.report(original, sink: sink)
        // A subsequent enabled entry fences the disabled report on the same worker.
        OriginalConsumerHostDiagnostic(enabled: true, stage: .clientExchange).report(original, sink: sink)
        expected.append("cengine original-host-failure stage=client-exchange category=other\n")
        #expect(lines.waitForCount(expected.count) == expected)
    }

    @Test @MainActor func blockedWriterBoundsQueueAndAllowsRethrowAndContainment() throws {
        let entered = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let finished = DispatchSemaphore(value: 0)
        let watchdogDone = DispatchSemaphore(value: 0)
        let lines = Lines()
        let sink = OriginalConsumerHostDiagnostic.Sink { data in
            entered.signal()
            release.wait()
            lines.append(data)
        }
        // Failure-only escape hatch: a synchronous-report regression must fail,
        // not hang the suite. Normal progress never depends on this timeout.
        Thread.detachNewThread {
            if finished.wait(timeout: .now() + 3) == .timedOut {
                Issue.record("report/containment stalled behind the blocked writer")
                for _ in 0...OriginalConsumerHostDiagnostic.Sink.capacity { release.signal() }
            }
            watchdogDone.signal()
        }
        defer {
            finished.signal()
            for _ in 0...OriginalConsumerHostDiagnostic.Sink.capacity { release.signal() }
        }
        let original = PrivateError()
        let diagnostic = OriginalConsumerHostDiagnostic(enabled: true, stage: .clientSocketWrite)
        diagnostic.report(original, sink: sink)
        try #require(entered.wait(timeout: .now() + 2) == .success)
        let lease = OriginalConsumerObservationLease()
        try lease.arm("blocked-sink")
        try lease.begin("blocked-sink", now: 0)
        do {
            do { throw original }
            catch {
                // Fill the queue while the first write is deterministically held.
                for _ in 0..<1_000 {
                    OriginalConsumerHostDiagnostic.report(.init(stage: .retireReturnValidation, error: error), sink: sink)
                }
                throw error
            }
        } catch {
            #expect((error as? PrivateError) === original)
            lease.cancel()
        }
        #expect(lease.closed)
        #expect(throws: OriginalConsumerObservationLease.Failure.changed) {
            try lease.require("blocked-sink", now: 1)
        }
        #expect(sink.pendingCount == OriginalConsumerHostDiagnostic.Sink.capacity)
        // The worker must use the report-time snapshot, not this later stage.
        diagnostic.stage = .shimLeaseTransition
        finished.signal()
        #expect(watchdogDone.wait(timeout: .now() + 2) == .success)
        for _ in 0...OriginalConsumerHostDiagnostic.Sink.capacity { release.signal() }
        let expected = ["cengine original-host-failure stage=client-socket-write category=other\n"] +
            Array(repeating: "cengine original-host-failure stage=retire-return-validation category=other\n",
                count: OriginalConsumerHostDiagnostic.Sink.capacity)
        #expect(lines.waitForCount(expected.count) == expected)
        #expect(sink.pendingCount == 0)
        // Fence the drained queue: none of the 968 dropped reports reappears.
        release.signal()
        diagnostic.report(CancellationError(), sink: sink)
        #expect(lines.waitForCount(expected.count + 1) == expected + [
            "cengine original-host-failure stage=shim-lease-transition category=cancelled\n"
        ])
    }
    @Test(arguments: [OriginalConsumerFailureDiagnostic.Stage.originalRetire, .retireReturnValidation,
        .originalProbe, .workerQuery, .workerQueryReply, .sameECorrelation,
        .workerFinalize, .workerFinalizeReply, .finalValidation, .ownerFence, .observationDeadline])
    func sameEStagesPreserveErrorsAndEmitOnlyClosedMetadata(_ stage: OriginalConsumerFailureDiagnostic.Stage) async throws {
        typealias D = OriginalConsumerFailureDiagnostic
        let original = PrivateError(), cleanup = PrivateError()
        let lines = Lines()
        let sink = OriginalConsumerHostDiagnostic.Sink { lines.append($0) }
        do {
            try await D.step(stage) { () async throws -> Void in throw original }
            Issue.record("expected failure")
        } catch {
            #expect((D.underlying(error) as? PrivateError) === original)
            let compound = OriginalConsumerContainmentFailure(observation: error, containment: cleanup)
            let propagated = D.annotate(compound, at: .containment)
            let kept = try #require(propagated as? OriginalConsumerContainmentFailure)
            #expect((D.underlying(kept.observation) as? PrivateError) === original)
            #expect((kept.containment as? PrivateError) === cleanup)
            let metadata = try #require(D.find(in: propagated))
            #expect(metadata.stage == stage && metadata.category == .other)
            OriginalConsumerHostDiagnostic.report(metadata, sink: sink)
            #expect(lines.waitForCount(1) == ["cengine original-host-failure stage=\(stage.rawValue) category=other\n"])
            let json = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(metadata)) as? [String: String])
            #expect(json == ["stage": stage.rawValue, "category": "other"])
            let cancellation = D.annotate(CancellationError(), at: stage)
            #expect(D.underlying(cancellation) is CancellationError)
            OriginalConsumerHostDiagnostic.report(try #require(D.find(in: cancellation)), sink: sink)
            #expect(lines.waitForCount(2).last == "cengine original-host-failure stage=\(stage.rawValue) category=cancelled\n")
        }
    }

    @Test func sameERuntimeWiringKeepsFiniteBoundaries() throws {
        let root = URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let source = try String(contentsOf: root.appending(path: "Sources/CEngineRuntime/ManagedStorageLifecycleOriginalConsumer.swift"), encoding: .utf8)
        #expect(source.contains("installed: installed, diagnostic: point"))
        for stage in ["originalRetire", "retireReturnValidation", "originalProbe", "sameECorrelation", "finalValidation"] {
            #expect(source.contains("point.stage = ." + stage))
        }
        #expect(source.contains("retireOriginalConsumer(binding, revalidate: check)"))
        #expect(source.contains("catch { try check(); throw error }"))
    }

    @Test func concreteCategoriesDoNotUnwrapOrFormatUnknownErrors() {
        typealias D = OriginalConsumerHostDiagnostic
        #expect(D.category(CancellationError()) == .cancelled)
        #expect(D.category(AsyncTimeout.TimeoutError()) == .deadline)
        #expect(D.category(OriginalConsumerObservationProtocol.Failure.invalid) == .protocolRejected)
        #expect(D.category(POSIXError(.ECONNRESET)) == .posix)
        #expect(D.category(DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "private"))) == .decoding)
        #expect(D.category(EncodingError.invalidValue("private", .init(codingPath: [], debugDescription: "private"))) == .encoding)
        #expect(D.category(PrivateError()) == .other)
        #expect(D.category(OriginalConsumerContainmentFailure(observation: CancellationError(), containment: PrivateError())) == .other)
    }
    @Test func productionWiringKeepsRethrowsAndCancellationOwnership() throws {
        let root = URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let client = try String(contentsOf: root.appending(path: "Sources/CEngineRuntime/VMShimClient.swift"), encoding: .utf8)
        let server = try String(contentsOf: root.appending(path: "Sources/CEngineRuntime/VMShimServer.swift"), encoding: .utf8)
        for stage in OriginalConsumerHostDiagnostic.Stage.allCases {
            // Case name, not raw string: production can only set the closed enum.
            let name = String(describing: stage)
            #expect((client + server).contains(".\(name)"))
        }
        let arm = try #require(client.components(separatedBy: "@MainActor func originalConsumerArm(").last)
            .components(separatedBy: "private func originalConsumerExchange(")[0]
        #expect(arm.contains("OriginalConsumerHostDiagnostic.enabled(binding)"))
        #expect(arm.contains("deadline: DispatchTime.now().uptimeNanoseconds + 1_000_000_000, hostDiagnostic: diagnostic.enabled"))
        #expect(arm.contains("catch { diagnostic.report(error); throw error }"))
        let releaseParts = client.components(separatedBy: "public func release() async throws -> Data {")
        try #require(releaseParts.count == 2)
        let release = releaseParts[1].components(separatedBy: "/// Identity comparison")[0]
        #expect(release.contains("hostDiagnostic: OriginalConsumerHostDiagnostic.enabled(binding)"))
        #expect(release.contains("deadline: DispatchTime.now().uptimeNanoseconds + 1_000_000_000"))
        #expect(client.contains("previous: previous, hostDiagnostic: diagnostic.enabled"))
        #expect(client.contains("deadlineNanoseconds: deadline, hostDiagnostic: hostDiagnostic"))
        #expect(client.contains("catch { diagnostic.report(error); throw error }"))
        #expect(server.contains("catch { diagnostic.report(error); throw error }"))
        #expect(server.contains("onCancel: { transport.cancel(); task.cancel() }"))
        #expect(server.contains("self.originalConsumerLease.cancel()\n                    throw error"))
        #expect(server.contains("active?.cancel()\n            if let active { _ = await active.result }"))
        #expect(server.contains("OriginalConsumerHostDiagnostic.enabled(originalConsumerBinding)"))
    }
}

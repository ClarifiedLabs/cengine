#if os(macOS)
import CEngineCore
import Foundation
import Testing
@testable import CEngineRuntime

@Suite struct PrepareCheckpointTerminalAdmissionTests {
    typealias C = ManagedPrepareCompatibilityProtocol
    typealias W = WorkloadStorageProtocol

    private func fixture(_ stage: String) throws -> (C.Arm, W.Frame) {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        struct Vector: Decodable {
            var arm: C.Arm
            var observation: C.Observation?
            enum CodingKeys: String, CodingKey { case arm, observation }
            init(from decoder: any Decoder) throws {
                let values = try decoder.container(keyedBy: CodingKeys.self)
                arm = try values.decode(C.Arm.self, forKey: .arm)
                observation = arm.caseName == "normal"
                    ? try values.decode(C.Observation.self, forKey: .observation) : nil
            }
        }
        let vectors = try JSONDecoder().decode([Vector].self, from: Data(contentsOf: root.appending(path: "Guest/internal/preparecompat/testdata/full-vectors.json")))
        var arm = vectors[0].arm
        arm.caseName = stage
        if let cut = C.ioCase(stage) {
            return (arm, .init(operation: .prepareCheckpoint, binding: arm.binding, scope: arm.scope,
                data: .init(compatibilityIOObservation: .init(requestID: arm.requestID,
                    armDigest: try C.digest(arm), stage: stage, targetAttachment: arm.targetAttachment,
                    copyIntent: UUID().uuidString.lowercased(), point: cut.point, errno: cut.errno))))
        }
        if stage == "guest-accepted-before-prepare" {
            return (arm, .init(operation: .prepareEarlyCheckpoint, binding: arm.binding, scope: arm.scope,
                data: .init(compatibilityEarlyObservation: .init(version: 3, profile: C.fullProfile,
                    requestID: arm.requestID, armDigest: try C.digest(arm), stage: stage, count: 1,
                    targetAttachment: arm.targetAttachment, requestSequence: 5,
                    prepareCommandsSent: 1, prepareCommandsAccepted: 1, dataBytesWritten: 0))))
        }
        let vector = try #require(vectors.first { $0.arm.caseName == stage && $0.observation != nil })
        return (vector.arm, .init(operation: .prepareCheckpoint, binding: vector.arm.binding,
            scope: vector.arm.scope, data: .init(compatibilityObservation: vector.observation)))
    }

    // Source-contract coverage of the real server wiring, not a live VM integration test.
    @Test func serverTerminalAdmissionSourceContract() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let source = try String(contentsOf: root.appending(path: "Sources/CEngineRuntime/VMShimServer.swift"), encoding: .utf8)
        func function(_ signature: String) throws -> String {
            let start = try #require(source.range(of: signature)).lowerBound
            let end = try #require(source.range(of: "\n    }", range: start..<source.endIndex)).upperBound
            // Ignore formatting and line comments, but keep assertions scoped to actual functions.
            return source[start..<end].split(separator: "\n").map {
                String($0).components(separatedBy: "//")[0]
            }.joined().filter { !$0.isWhitespace }
        }
        let admission = try function("private func requireOrdinaryAdmission(")
        let expected = """
            private func requireOrdinaryAdmission(_ operation: VMShimProtocol.Operation) throws {
                guard specification.workloadStorageMode == .managed,
                      machine?.workloadStorageIsTerminal == true || observationStopInProgress else { return }
                guard [.status, .stop, .shutdown, .originalConsumerObservation].contains(operation)
                        || earlyPrepareObserver?.permitsTerminalOperation(operation) == true else {
                    throw PrivateWorkloadStorageCoordinator.failure()
                }
            }
            """.filter { !$0.isWhitespace }
        #expect(admission == expected)

        let handle = try function("private func handle(")
        #expect(handle.contains("""
            requestAuthenticated = true
            if decoded.operation == .originalConsumerObservation {
                hostDiagnostic = OriginalConsumerHostDiagnostic(
                    enabled: OriginalConsumerHostDiagnostic.enabled(originalConsumerBinding), stage: .shimDispatchAdmission)
            }
            try requireOrdinaryAdmission(decoded.operation)
            try Self.requireLifecycleHostingAdmission(decoded.operation, specification: specification,
                enrolled: lifecycleHost?.owner.controlLifetime.isEnrolled == true)
            """.filter { !$0.isWhitespace }))
        // Additional stop/enrollment admission may live between the terminal
        // guards and dispatch; require ordering rather than adjacency.
        let terminalAdmission = try #require(handle.range(of: "tryrequireOrdinaryAdmission(decoded.operation)"))
        let lifecycleAdmission = try #require(handle.range(of: "trySelf.requireLifecycleHostingAdmission("))
        let stopReservation = try #require(handle.range(of: "trycontrol.reserveTokenStop()"))
        let dispatch = try #require(handle.range(of: "switchdecoded.operation{"))
        #expect(terminalAdmission.upperBound <= lifecycleAdmission.lowerBound)
        #expect(lifecycleAdmission.upperBound <= stopReservation.lowerBound)
        #expect(stopReservation.upperBound <= dispatch.lowerBound)
        #expect(handle.contains("""
            let payload = try await perform(decoded)
            hostDiagnostic?.stage = .shimReplyAdmission
            try requireOrdinaryAdmission(decoded.operation)
            hostDiagnostic?.stage = .shimReplyEncode
            let response = try VMShimProtocol.encode(
            """.filter { !$0.isWhitespace }))
        let perform = try function("private func perform(")
        #expect(perform.contains("""
            try requireOrdinaryAdmission(request.operation)
            switch request.operation {
            """.filter { !$0.isWhitespace }))
    }

    @Test(arguments: ["io-eio-manifest-rename-parent-sync", "io-enospc-manifest-rename-parent-sync", "guest-accepted-before-prepare"])
    func terminalBeforeRequestAndBetweenObservationAndReply(stage: String) async throws {
        let (arm, frame) = try fixture(stage)
        let observer = PrivatePrepareObservation()
        try observer.install(arm)
        #expect(!observer.permitsTerminalOperation(.workloadStoragePrepareObservation))
        try observer.publish(frame)
        observer.finish()
        // Entry admission after teardown must allow the retained evidence RPC.
        #expect(observer.permitsTerminalOperation(.workloadStoragePrepareObservation))
        let observed = try await observer.observation(arm)
        #expect(observed == frame)
        // The post-await response admission must remain open after the claim.
        #expect(observer.permitsTerminalOperation(.workloadStoragePrepareObservation))
        #expect(throws: (any Error).self) { _ = try observer.observe(arm) }
        #expect(throws: (any Error).self) { try observer.publish(frame) }
        for operation: VMShimProtocol.Operation in [.workloadStorageCommand, .workloadStorageConfigure, .workloadStorageBoot, .boot] {
            #expect(!observer.permitsTerminalOperation(operation))
        }
    }

    @Test func noEvidenceOrPhysicalCheckpointCannotOpenTerminalAdmission() throws {
        let (arm, frame) = try fixture("io-eio-manifest-rename-parent-sync")
        let missing = PrivatePrepareObservation()
        try missing.install(arm)
        missing.finish()
        #expect(!missing.permitsTerminalOperation(.workloadStoragePrepareObservation))
        #expect(throws: (any Error).self) { try missing.publish(frame) }
        #expect(throws: (any Error).self) { _ = try missing.observe(arm) }
        let (physicalArm, physicalFrame) = try fixture("normal")
        let physical = PrivatePrepareObservation()
        try physical.install(physicalArm)
        try physical.publish(physicalFrame)
        physical.finish()
        #expect(!physical.permitsTerminalOperation(.workloadStoragePrepareObservation))
        #expect(throws: (any Error).self) { _ = try physical.observe(physicalArm) }
    }

    @Test func admissionDoesNotReplaceExactArmValidation() throws {
        let (arm, frame) = try fixture("io-eio-manifest-rename-parent-sync")
        let observer = PrivatePrepareObservation()
        try observer.install(arm)
        try observer.publish(frame)
        observer.finish()
        var wrong = arm
        wrong.requestID = UUID().uuidString.lowercased()
        #expect(throws: (any Error).self) { _ = try observer.observe(wrong) }
        #expect(try observer.observe(arm) == frame)
    }
}
#endif

#if os(macOS)
import CEngineCore
@testable import CEngineRuntime
import Foundation
import Testing

@Suite @MainActor struct StorageLifecycleStartupDiagnosticTests {
    private final class SensitiveFailure: Error, LocalizedError {
        var errorDescription: String? { "secret credential and untrusted peer response" }
    }
    private let operationID = "dd4f9bbd-372a-41ed-8ea5-ea1bbfb8555c"

    @Test func preservesOriginalErrorAndReportsPhaseWithoutSensitiveValues() async {
        let original = SensitiveFailure()
        var lines: [String] = []
        do {
            let _: Void = try await StorageLifecycleStartupDiagnostic.perform(.configureGuest,
                operationID: operationID, report: { lines.append($0) }) { throw original }
            Issue.record("failure was swallowed")
        } catch {
            #expect((error as? SensitiveFailure) === original)
        }
        #expect(lines.count == 1)
        #expect(lines.first?.contains("phase=configure-guest operation=\(operationID)") == true)
        #expect(lines.first?.contains("SensitiveFailure code=unclassified\n") == true)
        #expect(lines.first?.contains("secret") == false)
        #expect(lines.first?.contains("untrusted peer response") == false)
    }

    @Test func successAddsNoFailureDiagnostic() async throws {
        var lines: [String] = []
        let result = try await StorageLifecycleStartupDiagnostic.perform(.completeCold,
            operationID: operationID, report: { lines.append($0) }) { 42 }
        #expect(result == 42 && lines.isEmpty)
    }

    @Test(arguments: StorageLifecycleStartupDiagnostic.Phase.allCases)
    func rootFailureKeepsConcreteTypeAndCode(_ phase: StorageLifecycleStartupDiagnostic.Phase) {
        let line = StorageLifecycleStartupDiagnostic.line(phase: phase, operationID: operationID,
            error: StorageLifecycleRootClient.Failure(.unauthorized))
        #expect(line.contains("phase=\(phase.rawValue) operation=\(operationID)"))
        #expect(line.contains("error_type=CEngineRuntime.StorageLifecycleRootClient.Failure code=unauthorized\n"))
        #expect(line.count < 512 && line.filter { $0 == "\n" }.count == 1)
    }

    @Test func transportFailureIsDistinguishedFromHelperAndCancellation() {
        let transport = StorageLifecycleStartupDiagnostic.line(phase: .configureGuest, operationID: operationID,
            error: StorageLifecycleShimProtocol.Failure.unauthorized)
        #expect(transport.contains("StorageLifecycleShimProtocol.Failure code=unauthorized"))
        let cancelled = StorageLifecycleStartupDiagnostic.line(phase: .connectController, operationID: operationID,
            error: CancellationError())
        #expect(cancelled.contains("code=cancelled\n"))
        #expect(!cancelled.contains("unauthorized"))
    }

    @Test func rejectsUntrustedOperationTextAndEngineMessages() {
        let line = StorageLifecycleStartupDiagnostic.line(phase: .prepareCold,
            operationID: "token=secret\nforged diagnostic", error: EngineError(.forbidden, "secret key"))
        #expect(line.contains("operation=unknown"))
        #expect(line.contains("code=forbidden\n"))
        #expect(!line.contains("secret") && !line.contains("forged"))
        #expect(line.filter { $0 == "\n" }.count == 1)
    }
}
#endif

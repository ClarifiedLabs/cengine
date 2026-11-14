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

    @Test func scopeBindClientDiagnosticIsClosedAndSecretFree() {
        typealias D = StorageLifecycleScopeBindClientDiagnostic
        for phase in D.Phase.allCases {
            let diagnostic = D(phase: phase, error: SensitiveFailure())
            #expect(diagnostic.category == .other)
            #expect(diagnostic.line == "cengine.lifecycle.scope-bind.failed phase=\(phase.rawValue) category=other\n")
        }
        for code in StorageIdentity.ErrorCode.allCases {
            let diagnostic = D(phase: .authenticate, error: StorageLifecycleRootClient.Failure(code))
            #expect(diagnostic.category.rawValue == code.rawValue)
            #expect(diagnostic.line == "cengine.lifecycle.scope-bind.failed phase=authenticate category=\(code.rawValue)\n")
        }
        #expect(D.Category(rawValue: "token=secret\nforged") == nil)
        #expect(D.Phase.allCases.map(\.rawValue) == ["reply-transport", "authenticate", "reply-shape", "rejected", "timeout"])
    }

    @Test func scopeBindDiagnosticsDoNotChangeWireOrAuthority() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let client = try String(contentsOf: root.appendingPathComponent("Sources/CEngineRuntime/StorageLifecycleRootScope.swift"), encoding: .utf8)
        let helper = try String(contentsOf: root.appendingPathComponent("Sources/CEngineNetworkHelper/StorageBootstrapLifecycleQualification.swift"), encoding: .utf8)
        // Pure formatters must never accept or reflect arbitrary request/error text.
        for (text, name) in [(client, "StorageLifecycleScopeBindClientDiagnostic"), (helper, "StorageLifecycleScopeBindDiagnostic")] {
            let diagnostic = try #require(text.components(separatedBy: "struct \(name):").last)
                .components(separatedBy: "\n}\n")[0]
            for forbidden in ["localizedDescription", "String(describing:", "String(reflecting:", "store.rawValue", "auditToken", "rootHash"] {
                #expect(!diagnostic.contains(forbidden))
            }
            #expect(diagnostic.contains("let phase: Phase") && diagnostic.contains("let category: Category"))
            #expect(diagnostic.contains("?? .other"))
        }
        #expect(client.contains("guard keys == [\"ok\"]"))
        #expect(client.contains("xpc_get_type(ok) == XPC_TYPE_BOOL else { throw Failure(.unauthorized) }"))
        #expect(client.contains("guard xpc_bool_get_value(ok) else { throw Failure(.unauthorized) }"))
        #expect(client.range(of: "try Self.authenticate(token:")!.lowerBound < client.range(of: "guard keys == [\"ok\"]")!.lowerBound)
        #expect(client.contains("ProcessInfo.processInfo.systemUptime < deadline"))
        #expect(helper.contains("guard keys == [\"operation\", \"request\", \"store-root\"]"))
        #expect(helper.contains("guard try daemon(message) == sender else { throw BootstrapFailure(.unauthorized) }"))
        #expect(helper.contains("if operation == Self.scopeBindOperation {\n                    StorageLifecycleScopeBindDiagnostic.emit"))
        #expect(helper.contains("if isScopeBind { StorageLifecycleScopeBindDiagnostic.emit(.init(phase: .admission, error: error)) }"))
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

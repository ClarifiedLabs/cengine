#if os(macOS)
import CEngineCore
import Foundation

/// Failure breadcrumbs only, never recovery evidence. Do not log reflected error
/// values: transport errors can carry credentials or untrusted peer messages.
enum StorageLifecycleStartupDiagnostic {
    enum Phase: String, CaseIterable {
        case coldStatus = "cold-status"
        case resolveCold = "resolve-cold"
        case prepareCold = "prepare-cold"
        case bindController = "bind-controller"
        case configureGuest = "configure-guest"
        case controllerCSR = "controller-csr"
        case issueController = "issue-controller"
        case connectLifecycle = "connect-lifecycle"
        case connectController = "connect-controller"
        case takeover = "takeover"
        case reconcileController = "reconcile-controller"
        case completeCold = "complete-cold"
    }

    static func line(phase: Phase, operationID: String?, error: any Error) -> String {
        // Only a canonical public operation ID is accepted, not arbitrary text.
        let operation = operationID.flatMap { UUID(uuidString: $0)?.uuidString.lowercased() } ?? "unknown"
        let code: String
        switch error {
        case is CancellationError: code = "cancelled"
        case let failure as StorageLifecycleRootClient.Failure: code = failure.code.rawValue
        case let failure as StorageLifecycleShimProtocol.Failure: code = String(describing: failure)
        case let failure as ManagedStorageLifecycleOwner.Failure: code = String(describing: failure)
        case let failure as EngineError: code = String(describing: failure.code)
        default: code = "unclassified"
        }
        return "cengine.lifecycle.startup.failed phase=\(phase.rawValue) operation=\(operation) "
            + "error_type=\(String(reflecting: type(of: error))) code=\(code)\n"
    }

    /// Rethrow the original error so retry and authorization decisions are unchanged.
    @MainActor static func perform<Value>(
        _ phase: Phase, operationID: String? = nil,
        report: (String) -> Void = { FileHandle.standardError.write(Data($0.utf8)) },
        operation: () async throws -> Value
    ) async throws -> Value {
        do { return try await operation() }
        catch {
            report(line(phase: phase, operationID: operationID, error: error))
            throw error
        }
    }
}
#endif

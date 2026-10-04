#if os(macOS)
import CEngineCore
import Darwin
import Foundation

/// Shared transport failures, independent of the process implementation.
nonisolated public enum ManagedStorageControlFailure: Error { case invalidConfiguration, unauthorized, system(Int32), protocolViolation, serviceUnavailable }

/// Evidence only. Captured at the first actual close under the channel lock;
/// never an error override, reconnect permission or process-exit observation.
nonisolated struct ManagedStorageCloseDiagnostic: Codable, Sendable, Equatable {
    enum Site: String, Codable, Sendable { case exchange, rebind, adapter, explicit, owner, initialization, destruction, launch }
    enum Operation: String, Codable, Sendable {
        case rootConnect = "root-connect", bind = "bind-service-epoch", rebind = "rebind-service"
        case csr = "controller-csr", successorCSR = "successor-csr", install = "install-certificate"
        case connect = "control-connect", attachment = "attachment-certificate", close
        case query, retire, reserve, register, complete, replace, create, delete, takeover, other
        init(_ request: ManagedStorageControlProtocol.ControlRequest) {
            switch request {
            case .query: self = .query
            case .retire: self = .retire
            case .reservePrepare: self = .reserve
            case .registerAttachment: self = .register
            case .completePrepare: self = .complete
            case .replacePrepare: self = .replace
            case .createVolume: self = .create
            case .deleteVolume: self = .delete
            }
        }
    }
    enum Phase: String, Codable, Sendable, CaseIterable {
        case ipcWrite = "ipc-write", ipcRead = "ipc-read", replyValidation = "reply-validation"
        case ownerValidation = "owner-validation", controlExchange = "control-exchange"
        case reconnectStream = "reconnect-stream", reconnectStatus = "reconnect-status"
        case reconnectConnect = "reconnect-connect", decode, close
    }
    enum Category: String, Codable, Sendable, CaseIterable {
        case none, invalidConfiguration = "invalid-configuration", protocolViolation = "protocol-violation"
        case unauthorized, serviceUnavailable = "service-unavailable", timeout, system
        case ownerRejected = "owner-rejected", cancelled, engineConflict = "engine-conflict"
        case engineInternal = "engine-internal", other
    }
    let site: Site
    let operation: Operation
    let phase: Phase
    let category: Category
    init(site: Site, operation: Operation, phase: Phase, error: (any Error)? = nil) {
        self.site = site; self.operation = operation; self.phase = phase
        switch error {
        case nil: category = .none
        case ManagedStorageControlFailure.invalidConfiguration?: category = .invalidConfiguration
        case ManagedStorageControlFailure.protocolViolation?: category = .protocolViolation
        case ManagedStorageControlFailure.unauthorized?: category = .unauthorized
        case ManagedStorageControlFailure.serviceUnavailable?: category = .serviceUnavailable
        case ManagedStorageControlFailure.system(let code)?: category = code == ETIMEDOUT ? .timeout : .system
        case is ManagedStorageFailure: category = .ownerRejected
        case is CancellationError: category = .cancelled
        case let error as EngineError:
            switch error.code {
            case .conflict: category = .engineConflict
            case .internalError: category = .engineInternal
            default: category = .other
            }
        default: category = .other
        }
    }
}
#endif

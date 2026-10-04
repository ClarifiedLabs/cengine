import CEngineHelperSupport
import Foundation

/// Shared helper identity and verification values, independent of request protocols.
struct BootstrapFailure: Error {
    let code: StorageIdentity.ErrorCode
    init(_ code: StorageIdentity.ErrorCode) { self.code = code }
}

/// Kernel unique ID, audit PID version, start time and boot identity; never PID alone.
struct BootstrapProcess: Codable, Equatable, Sendable {
    let pid: Int32
    let startSeconds: UInt64
    let startMicroseconds: UInt64
    let boot: String
    let signingIdentity: String
    let uniqueID: UInt64
    let pidVersion: UInt32
    let auditToken: Data
}
struct BootstrapPrincipal: Codable, Equatable {
    let daemon: BootstrapProcess
    let child: BootstrapProcess
    let incarnation: String
    let controllerSPKI: Data
}

enum BootstrapLiveness { case alive, exited, unknown }

protocol BootstrapBindingChecking {
    func verify(_ binding: StorageIdentity.StoreBinding, rootFD: Int32, backingFD: Int32) throws
}

/// Channel revocation stays observable while a lifecycle worker persists state.
final class StorageBootstrapChildChannel: @unchecked Sendable {
    private let lock = NSLock()
    private var closed = false
    var isOpen: Bool { lock.withLock { !closed } }
    func close() { lock.withLock { closed = true } }
}

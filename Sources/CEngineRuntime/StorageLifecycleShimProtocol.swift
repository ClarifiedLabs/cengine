#if os(macOS)
import CEngineCore
import Foundation

/// Private daemon-to-shim IPC. Every value here is untrusted metadata, never ROOT
/// proof or a VerifiedBoot. No path, process assertion or private key is accepted.
enum StorageLifecycleShimProtocol {
    typealias Boot = StorageLifecycleServiceBootProtocol
    enum Failure: Error { case invalid, closed, timeout, unauthorized }
    // Reserved outside ordinary frame lengths. Never decoded as a token envelope.
    static let adoptionPreface = Data([0xff, 0xff, 0xff, 0xff]) + Data("cengine-lifecycle-adopt.v1\n".utf8)
    enum Operation: String, Codable, Sendable {
        case prepare, prepareCold, prepareResume, configure, currentReady, command, connectLifecycle, connectWorkload, connectAttachmentCSR, enrollAdoption, stop
        #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
        case qualificationRevokeServiceProof, qualificationCheckLiveVM
        #endif
        var transfersDescriptor: Bool { self == .connectLifecycle || self == .connectWorkload || self == .connectAttachmentCSR }
        var isRepeatable: Bool {
            #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
            if self == .qualificationCheckLiveVM { return true }
            #endif
            // The shim bounds stream generations; the client may reconnect.
            return self == .command || self == .currentReady || transfersDescriptor
        }
    }
    struct Frame: Codable, Sendable {
        var version = "storage-lifecycle-shim.v1"
        let sequence: UInt64
        let operation: Operation
        let reply: Bool
        var configuration: Boot.Configuration?
        var command: Boot.Frame?
        var greeting: StorageLifecycleFreshProtocol.Greeting?
        var coldGreeting: StorageLifecycleColdShimProtocol.Greeting?
        var resumeGreeting: StorageLifecycleColdShimProtocol.Greeting?
        var binding: Boot.Binding?
        var ready: Boot.Ready?

        func validate() throws {
            guard version == "storage-lifecycle-shim.v1", sequence > 0 else { throw Failure.invalid }
            let present = [configuration != nil, command != nil, greeting != nil, binding != nil, ready != nil, coldGreeting != nil, resumeGreeting != nil]
            var expected = [false, false, false, false, false, false, false]
            switch (operation, reply) {
            case (.configure, false):
                expected[0] = true
                // initialize (fresh) or open (existing store, ROOT-signed reopen).
                try configuration?.validate()
            case (.command, _):
                expected[1] = true
                try command?.validate()
                guard command?.operation == (reply ? .reply : .command) else { throw Failure.invalid }
            case (.prepare, true): expected[2] = true; try greeting?.validate()
            case (.prepareCold, true):
                expected[5] = true; try coldGreeting?.validate()
                guard coldGreeting?.purpose == .cold else { throw Failure.invalid }
            case (.prepareResume, true):
                expected[6] = true; try resumeGreeting?.validate()
                guard resumeGreeting?.purpose == .resumeReadOnly else { throw Failure.invalid }
            case (.configure, true), (.currentReady, true):
                expected[3] = true; expected[4] = true
                if let binding, let ready { try Boot.Frame(operation: .ready, binding: binding, ready: ready).validate() }
            default: break
            }
            guard present == expected else { throw Failure.invalid }
        }
    }
    static func encode(_ value: Frame) throws -> Data {
        try value.validate()
        return try StorageLifecycleProtocol.encode(value)
    }
    static func decode(_ bytes: Data) throws -> Frame {
        let value = try StorageLifecycleProtocol.decode(Frame.self, from: bytes)
        try value.validate()
        return value
    }

    /// Production host bootstrap: sent by the daemon on the inherited FD4 channel
    /// ONLY after it authenticated the suspended child and the child authenticated
    /// its parent. Carries no path, disk, PID or proof; the disk stays at FD3.
    struct HostBootstrap: Codable, Equatable, Sendable {
        static let version = "lifecycle-v2-host-v1"
        static let bound = Data("lifecycle-v2-host-v1:bound".utf8)
        enum DiskMode: String, Codable, Sendable {
            case initialize, open, resumeReadOnly
            var policy: RawDiskBootTransaction.Policy {
                switch self {
                case .initialize: .journalDriven
                case .open: .requireInitializedStorage
                case .resumeReadOnly: .resumeReadOnly
                }
            }
        }
        let profile: String
        /// Frozen before resolving/inspecting attachments, not chosen by configure.
        let diskMode: DiskMode
        let rootPublicKey: Data
        let binding: StorageLifecycleStoreBinding
        func validate() throws {
            guard profile == Self.version, rootPublicKey.count == 32 else { throw Failure.invalid }
            _ = try binding.value()
        }
    }
    static func encodeHost(_ value: HostBootstrap) throws -> Data {
        try value.validate()
        return try StorageLifecycleProtocol.encode(value)
    }
    static func decodeHost(_ bytes: Data) throws -> HostBootstrap {
        let value = try StorageLifecycleProtocol.decode(HostBootstrap.self, from: bytes)
        try value.validate()
        return value
    }
}
#endif

import CEngineCore
import Darwin
import Foundation

/// Public comparison data only. Never constructs a verified boot, installs a
/// witness, or substitutes for the reader's independent ROOT checkpoint match.
struct ManagedStorageLifecyclePeerObservation: Codable, Equatable, Sendable {
    typealias Boot = StorageLifecycleServiceBootProtocol
    let version: UInt32
    let binding: Boot.Binding
    let ready: Boot.Ready
    let peer: WorkloadStorageProtocol.Peer

    init(binding: Boot.Binding, ready: Boot.Ready, peer: WorkloadStorageProtocol.Peer) throws {
        version = 1
        self.binding = binding; self.ready = ready; self.peer = peer
        try validate()
    }

    // A controller takeover can retain the worker. Keep each actual Ready immutable.
    var filename: String { "lifecycle-peer-" + ready.workerUUID + "-" + String(ready.controllerEpoch) + ".json" }

    func validate() throws {
        try Boot.Frame(operation: .ready, binding: binding, ready: ready).validate()
        var v4 = in_addr(), v6 = in6_addr()
        guard version == 1, peer.tlsRootDER == ready.tlsRootDER,
              peer.serverDER == ready.serverDER, peer.serverKey == ready.serverSPKI,
              !peer.dataAddress.isEmpty, peer.dataAddress.utf8.count <= 45,
              !peer.dataAddress.utf8.contains(0),
              peer.dataAddress.withCString({ inet_pton(AF_INET, $0, &v4) == 1 || inet_pton(AF_INET6, $0, &v6) == 1 })
        else { throw ManagedPrepareCompatibilityProtocol.Failure.invalid }
    }

    func canonicalData() throws -> Data {
        try validate()
        let bytes = try ManagedPrepareCompatibilityProtocol.canonicalData(self)
        guard bytes.count <= 65536 else { throw ManagedPrepareCompatibilityProtocol.Failure.invalid }
        return bytes
    }

    /// Exact canonical round-trip rejects unknown fields at every nesting level,
    /// duplicate keys, nulls, alternate numeric spellings, and trailing data.
    static func decode(_ bytes: Data) throws -> Self {
        let value = try ManagedPrepareCompatibilityProtocol.decode(Self.self, from: bytes)
        try value.validate()
        return value
    }
}

import Foundation

/// Value-only binding of a fresh boot's TLS inputs. This DTO is NOT authority:
/// ROOT must independently check it before sending it on an authenticated channel.
public struct StorageLifecycleBootTrust: Codable, Equatable, Sendable {
    public let identity: StorageLifecycleProtocol.Identity
    public let serviceEpoch: String
    public let tlsRootSHA256: String
    public let serverSPKI: String
    public let bootstrapKey: String

    public init(identity: StorageLifecycleProtocol.Identity, serviceEpoch: String,
                tlsRootSHA256: String, serverSPKI: String, bootstrapKey: String) throws {
        self.identity = identity; self.serviceEpoch = serviceEpoch
        self.tlsRootSHA256 = tlsRootSHA256; self.serverSPKI = serverSPKI
        self.bootstrapKey = bootstrapKey
        try validate()
    }

    public func validate() throws {
        try identity.validate()
        _ = try StorageIdentity.IncarnationID(serviceEpoch)
        for fingerprint in [tlsRootSHA256, serverSPKI, bootstrapKey] {
            _ = try StorageIdentity.SPKISHA256(fingerprint)
        }
    }

    private enum CodingKeys: String, CodingKey {
        case identity
        case serviceEpoch = "service_epoch", tlsRootSHA256 = "tls_root_sha256"
        case serverSPKI = "server_spki", bootstrapKey = "bootstrap_key"
    }
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(identity: c.decode(StorageLifecycleProtocol.Identity.self, forKey: .identity),
                      serviceEpoch: c.decode(String.self, forKey: .serviceEpoch),
                      tlsRootSHA256: c.decode(String.self, forKey: .tlsRootSHA256),
                      serverSPKI: c.decode(String.self, forKey: .serverSPKI),
                      bootstrapKey: c.decode(String.self, forKey: .bootstrapKey))
    }
}

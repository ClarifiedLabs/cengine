import CEngineCore
import Foundation

public struct BackendImage: Sendable {
    public let id: String
    public let reference: String
    public let createdAt: Date
    public let size: Int64
    public let architecture: String
    public let os: String
    public let targetDescriptor: OCIDescriptor?
    public let manifests: [ImageManifestRecord]
    public let preferredManifestDigest: String?
    public let identity: ImageIdentityRecord?

    public init(
        id: String,
        reference: String,
        createdAt: Date = Date(),
        size: Int64,
        architecture: String,
        os: String,
        targetDescriptor: OCIDescriptor? = nil,
        manifests: [ImageManifestRecord] = [],
        preferredManifestDigest: String? = nil,
        identity: ImageIdentityRecord? = nil
    ) {
        self.id = id; self.reference = reference; self.createdAt = createdAt; self.size = size
        self.architecture = architecture; self.os = os
        self.targetDescriptor = targetDescriptor
        self.manifests = manifests
        self.preferredManifestDigest = preferredManifestDigest
        self.identity = identity
    }
}

import Foundation

public struct OCIPlatform: Codable, Hashable, Sendable {
    public var architecture: String
    public var os: String
    public var variant: String?
    public var osVersion: String?
    public var osFeatures: [String]?

    public init(
        architecture: String,
        os: String,
        variant: String? = nil,
        osVersion: String? = nil,
        osFeatures: [String]? = nil
    ) {
        self.architecture = architecture
        self.os = os
        self.variant = variant
        self.osVersion = osVersion
        self.osFeatures = osFeatures
    }

    public init(_ value: String) throws {
        let components = value.split(separator: "/").map(String.init)
        guard components.count == 2 || components.count == 3 else {
            throw EngineError(.badRequest, "invalid OCI platform \(value)")
        }
        os = components[0]
        architecture = components[1]
        variant = components.count == 3 ? components[2] : nil
        osVersion = nil
        osFeatures = nil
    }

    enum CodingKeys: String, CodingKey {
        case architecture, os, variant
        case osVersion = "os.version"
        case osFeatures = "os.features"
    }

    public var description: String {
        [os, architecture, variant].compactMap { $0 }.joined(separator: "/")
    }

    public func matches(_ requested: OCIPlatform) -> Bool {
        guard os == requested.os, architecture == requested.architecture else { return false }
        if let variant = requested.variant, self.variant != variant { return false }
        if let osVersion = requested.osVersion, self.osVersion != osVersion { return false }
        if let features = requested.osFeatures, !features.allSatisfy({ osFeatures?.contains($0) == true }) {
            return false
        }
        return true
    }
}

public struct OCIDescriptor: Codable, Hashable, Sendable {
    public var mediaType: String
    public var digest: String
    public var size: Int64
    public var urls: [String]?
    public var annotations: [String: String]?
    public var data: Data?
    public var platform: OCIPlatform?
    public var artifactType: String?

    public init(
        mediaType: String,
        digest: String,
        size: Int64,
        urls: [String]? = nil,
        annotations: [String: String]? = nil,
        data: Data? = nil,
        platform: OCIPlatform? = nil,
        artifactType: String? = nil
    ) {
        self.mediaType = mediaType
        self.digest = digest
        self.size = size
        self.urls = urls
        self.annotations = annotations
        self.data = data
        self.platform = platform
        self.artifactType = artifactType
    }
}

public enum ImageManifestKind: String, Codable, Sendable {
    case image
    case attestation
    case unknown
}

public struct ImageConfigurationRecord: Codable, Sendable {
    public var environment: [String]?
    public var command: [String]?
    public var entrypoint: [String]?
    public var workingDirectory: String?
    public var user: String?
    public var labels: [String: String]?
    public var exposedPorts: [String]?
    public var volumes: [String]?
    public var rootFSDiffIDs: [String]

    public init(
        environment: [String]? = nil,
        command: [String]? = nil,
        entrypoint: [String]? = nil,
        workingDirectory: String? = nil,
        user: String? = nil,
        labels: [String: String]? = nil,
        exposedPorts: [String]? = nil,
        volumes: [String]? = nil,
        rootFSDiffIDs: [String] = []
    ) {
        self.environment = environment
        self.command = command
        self.entrypoint = entrypoint
        self.workingDirectory = workingDirectory
        self.user = user
        self.labels = labels
        self.exposedPorts = exposedPorts
        self.volumes = volumes
        self.rootFSDiffIDs = rootFSDiffIDs
    }
}

public struct ImageHistoryEntry: Codable, Sendable {
    public let created: Int64
    public let createdBy: String
    public let comment: String
    public let emptyLayer: Bool

    public init(created: Int64, createdBy: String, comment: String, emptyLayer: Bool) {
        self.created = created
        self.createdBy = createdBy
        self.comment = comment
        self.emptyLayer = emptyLayer
    }
}

public struct ImageManifestRecord: Codable, Sendable {
    public var descriptor: OCIDescriptor
    public var imageID: String?
    public var available: Bool
    public var kind: ImageManifestKind
    public var platform: OCIPlatform?
    public var createdAt: Date?
    public var contentSize: Int64
    public var configuration: ImageConfigurationRecord?
    public var history: [ImageHistoryEntry]
    public var attestationFor: String?

    public init(
        descriptor: OCIDescriptor,
        imageID: String? = nil,
        available: Bool,
        kind: ImageManifestKind,
        platform: OCIPlatform? = nil,
        createdAt: Date? = nil,
        contentSize: Int64 = 0,
        configuration: ImageConfigurationRecord? = nil,
        history: [ImageHistoryEntry] = [],
        attestationFor: String? = nil
    ) {
        self.descriptor = descriptor
        self.imageID = imageID
        self.available = available
        self.kind = kind
        self.platform = platform
        self.createdAt = createdAt
        self.contentSize = contentSize
        self.configuration = configuration
        self.history = history
        self.attestationFor = attestationFor
    }
}

public struct ImageIdentityRecord: Codable, Sendable {
    public var pullRepositories: [String]

    public init(pullRepositories: [String] = []) {
        self.pullRepositories = pullRepositories
    }
}

public struct ImageAttestationRecord: Sendable {
    public var descriptor: OCIDescriptor
    public var predicateType: String
    public var statement: Data?

    public init(descriptor: OCIDescriptor, predicateType: String, statement: Data? = nil) {
        self.descriptor = descriptor
        self.predicateType = predicateType
        self.statement = statement
    }
}

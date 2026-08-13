import CEngineCore
import CryptoKit
import Darwin
import Foundation

public struct OCIManifest: Codable, Sendable {
    public var schemaVersion: Int
    public var mediaType: String?
    public var artifactType: String?
    public var config: OCIDescriptor
    public var layers: [OCIDescriptor]
    public var subject: OCIDescriptor?
    public var annotations: [String: String]?

    public init(
        schemaVersion: Int,
        mediaType: String?,
        artifactType: String? = nil,
        config: OCIDescriptor,
        layers: [OCIDescriptor],
        subject: OCIDescriptor? = nil,
        annotations: [String: String]?
    ) {
        self.schemaVersion = schemaVersion
        self.mediaType = mediaType
        self.artifactType = artifactType
        self.config = config
        self.layers = layers
        self.subject = subject
        self.annotations = annotations
    }
}

public struct OCIIndex: Codable, Sendable {
    public var schemaVersion: Int
    public var mediaType: String?
    public var artifactType: String?
    public var manifests: [OCIDescriptor]
    public var subject: OCIDescriptor?
    public var annotations: [String: String]?

    public init(
        schemaVersion: Int,
        mediaType: String?,
        artifactType: String? = nil,
        manifests: [OCIDescriptor],
        subject: OCIDescriptor? = nil,
        annotations: [String: String]?
    ) {
        self.schemaVersion = schemaVersion
        self.mediaType = mediaType
        self.artifactType = artifactType
        self.manifests = manifests
        self.subject = subject
        self.annotations = annotations
    }
}

public struct OCIImageConfiguration: Codable, Sendable {
    public struct History: Codable, Sendable {
        public var created: String?
        public var createdBy: String?
        public var comment: String?
        public var emptyLayer: Bool?

        enum CodingKeys: String, CodingKey { case created; case createdBy = "created_by"; case comment; case emptyLayer = "empty_layer" }
    }
    public struct RootFS: Codable, Sendable {
        public var type: String
        public var diffIDs: [String]

        enum CodingKeys: String, CodingKey { case type; case diffIDs = "diff_ids" }
    }

    public struct Configuration: Codable, Sendable {
        public struct Healthcheck: Codable, Sendable {
            public var test: [String]?
            public var interval: Int64?
            public var timeout: Int64?
            public var retries: Int?
            public var startPeriod: Int64?
            public var startInterval: Int64?

            enum CodingKeys: String, CodingKey {
                case test = "Test"
                case interval = "Interval"
                case timeout = "Timeout"
                case retries = "Retries"
                case startPeriod = "StartPeriod"
                case startInterval = "StartInterval"
            }
        }

        public var user: String?
        public var exposedPorts: [String: [String: String]]?
        public var environment: [String]?
        public var entrypoint: [String]?
        public var command: [String]?
        public var volumes: [String: [String: String]]?
        public var workingDirectory: String?
        public var labels: [String: String]?
        public var stopSignal: String?
        public var healthcheck: Healthcheck?

        enum CodingKeys: String, CodingKey {
            case user = "User"
            case exposedPorts = "ExposedPorts"
            case environment = "Env"
            case entrypoint = "Entrypoint"
            case command = "Cmd"
            case volumes = "Volumes"
            case workingDirectory = "WorkingDir"
            case labels = "Labels"
            case stopSignal = "StopSignal"
            case healthcheck = "Healthcheck"
        }
    }

    public var architecture: String
    public var os: String
    public var variant: String?
    public var osVersion: String?
    public var created: String?
    public var config: Configuration?
    public var rootfs: RootFS
    public var history: [History]?
}

public struct OCIStoredImage: Sendable {
    public let reference: String
    public let rootDescriptor: OCIDescriptor
    public let manifestDescriptor: OCIDescriptor
    public let manifest: OCIManifest
    public let configuration: OCIImageConfiguration
}

public actor OCIContentStore {
    public static let manifestMediaTypes = [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
    public static let indexMediaTypes = [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ]
    public static let attestationManifestArtifactType = "application/vnd.docker.attestation.manifest.v1+json"
    public static let attestationReferenceType = "attestation-manifest"
    public static let attestationReferenceTypeAnnotation = "vnd.docker.reference.type"
    public static let attestationReferenceDigestAnnotation = "vnd.docker.reference.digest"
    public static let inTotoPredicateTypeAnnotation = "in-toto.io/predicate-type"
    public static let hostPlatform = OCIPlatform(architecture: "arm64", os: "linux")

    private struct ReferenceIndex: Codable {
        var references: [String: OCIDescriptor] = [:]
        var pullRepositories: [String: [String]] = [:]

        enum CodingKeys: String, CodingKey { case references, pullRepositories }

        init() {}

        init(from decoder: Decoder) throws {
            let values = try decoder.container(keyedBy: CodingKeys.self)
            references = try values.decodeIfPresent([String: OCIDescriptor].self, forKey: .references) ?? [:]
            pullRepositories = try values.decodeIfPresent([String: [String]].self, forKey: .pullRepositories) ?? [:]
        }
    }

    private struct DockerArchiveEntry: Codable {
        let config: String
        let repoTags: [String]?
        let layers: [String]

        init(config: String, repoTags: [String]?, layers: [String] = []) {
            self.config = config
            self.repoTags = repoTags
            self.layers = layers
        }

        enum CodingKeys: String, CodingKey {
            case config = "Config"
            case repoTags = "RepoTags"
            case layers = "Layers"
        }

        init(from decoder: Decoder) throws {
            let values = try decoder.container(keyedBy: CodingKeys.self)
            config = try values.decode(String.self, forKey: .config)
            repoTags = try values.decodeIfPresent([String].self, forKey: .repoTags)
            layers = try values.decodeIfPresent([String].self, forKey: .layers) ?? []
        }

        var configDigest: String { "sha256:" + URL(filePath: config).lastPathComponent }
    }

    private struct DescriptorIdentity: Equatable {
        let mediaType: String
        let size: Int64
    }

    private struct GraphBudget {
        let policy: OCITransferPolicy
        var errorCode: EngineError.Code = .upstream
        var descriptors: [String: DescriptorIdentity] = [:]
        var totalBytes: UInt64 = 0

        mutating func admit(_ descriptor: OCIDescriptor, depth: Int) throws -> Bool {
            let validated = try descriptor.validated(
                policy: policy, errorCode: errorCode
            )
            guard depth <= policy.maximumGraphDepth else {
                throw EngineError(errorCode, "OCI descriptor graph exceeds its depth limit")
            }
            let identity = DescriptorIdentity(
                mediaType: descriptor.mediaType, size: descriptor.size
            )
            if let existing = descriptors[descriptor.digest] {
                guard existing == identity else {
                    throw EngineError(errorCode, "OCI graph repeats a digest with conflicting metadata")
                }
                return false
            }
            guard descriptors.count < policy.maximumGraphDescriptors else {
                throw EngineError(errorCode, "OCI descriptor graph exceeds its descriptor limit")
            }
            totalBytes = try CheckedArithmetic.add(totalBytes, validated.size)
            guard totalBytes <= policy.maximumGraphBytes else {
                throw EngineError(errorCode, "OCI descriptor graph exceeds its aggregate size limit")
            }
            descriptors[descriptor.digest] = identity
            return true
        }
    }

    private let root: URL
    private let blobRoot: URL
    private let indexURL: URL
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder
    private let transferPolicy: OCITransferPolicy
    private var index: ReferenceIndex

    public init(root: URL, transferPolicy: OCITransferPolicy = .default) throws {
        self.root = root
        blobRoot = root.appending(path: "blobs/sha256", directoryHint: .isDirectory)
        indexURL = root.appending(path: "references.json")
        encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        decoder = JSONDecoder()
        self.transferPolicy = transferPolicy
        try FileManager.default.createDirectory(at: blobRoot, withIntermediateDirectories: true)
        if FileManager.default.fileExists(atPath: indexURL.path) {
            index = try decoder.decode(
                ReferenceIndex.self,
                from: Self.readRegularFile(
                    at: indexURL, maximumBytes: transferPolicy.metadataBytes
                )
            )
        } else {
            index = ReferenceIndex()
        }
    }

    public func references() -> [String] { index.references.keys.sorted() }

    public func summaries() throws -> [BackendImage] {
        var values: [BackendImage] = []
        for reference in index.references.keys.sorted() {
            guard let rootDescriptor = index.references[reference] else { continue }
            let manifests = try manifestRecords(in: rootDescriptor)
            guard let preferred = preferredManifest(in: manifests) else { continue }
            values.append(.init(
                id: preferred.imageID ?? rootDescriptor.digest,
                reference: reference,
                createdAt: preferred.createdAt ?? Date(timeIntervalSince1970: 0),
                size: preferred.contentSize,
                architecture: preferred.platform?.architecture ?? "arm64",
                os: preferred.platform?.os ?? "linux",
                targetDescriptor: rootDescriptor,
                manifests: manifests,
                preferredManifestDigest: preferred.descriptor.digest,
                identity: identity(for: rootDescriptor)
            ))
        }
        return values
    }

    public func descriptor(for reference: String) -> OCIDescriptor? {
        try? rootDescriptor(for: reference)
    }

    public func contains(_ digest: String) -> Bool {
        guard (try? blobURL(for: digest)) != nil,
              let input = try? openBlob(digest) else { return false }
        defer { try? input.close() }
        do {
            let size = try regularFileSize(input, digest: digest)
            guard size <= transferPolicy.maximumBlobBytes else { return false }
            var hasher = SHA256()
            var count: UInt64 = 0
            while let chunk = try input.read(upToCount: 1 * 1_024 * 1_024),
                  !chunk.isEmpty {
                count = try CheckedArithmetic.add(count, UInt64(chunk.count))
                guard count <= transferPolicy.maximumBlobBytes else { return false }
                hasher.update(data: chunk)
            }
            return count == size && Self.digest(hasher.finalize()) == digest
        } catch {
            return false
        }
    }

    @discardableResult public func put(
        _ data: Data,
        mediaType: String,
        expectedDigest: String? = nil
    ) throws -> OCIDescriptor {
        guard let size = Int64(exactly: data.count) else {
            throw EngineError(.badRequest, "OCI content is too large")
        }
        let digest = Self.digest(data)
        if let expectedDigest, expectedDigest != digest {
            throw EngineError(.badRequest, "content digest mismatch: expected \(expectedDigest), received \(digest)")
        }
        let descriptor = OCIDescriptor(mediaType: mediaType, digest: digest, size: size)
        _ = try descriptor.validated(policy: transferPolicy, errorCode: .badRequest)
        let destination = try blobURL(for: digest)
        if !FileManager.default.fileExists(atPath: destination.path) {
            try atomicWrite(data, to: destination)
        } else {
            try verifyBlob(descriptor, errorCode: .internalError)
        }
        return descriptor
    }

    public func data(for digest: String) throws -> Data {
        try readVerifiedBlob(
            digest: digest,
            expectedSize: nil,
            maximumBytes: transferPolicy.maximumBlobBytes,
            errorCode: .internalError
        )
    }

    private func data(
        for descriptor: OCIDescriptor,
        errorCode: EngineError.Code = .internalError
    ) throws -> Data {
        let validated = try descriptor.validated(
            policy: transferPolicy, errorCode: errorCode
        )
        if let embedded = descriptor.data { return embedded }
        return try readVerifiedBlob(
            digest: descriptor.digest,
            expectedSize: validated.size,
            maximumBytes: validated.size,
            errorCode: errorCode
        )
    }

    public func copyBlob(
        _ descriptor: OCIDescriptor,
        to output: FileHandle
    ) throws {
        let validated = try descriptor.validated(
            policy: transferPolicy, errorCode: .internalError
        )
        if let embedded = descriptor.data {
            try output.write(contentsOf: embedded)
            return
        }
        let input = try openBlob(descriptor.digest)
        defer { try? input.close() }
        let actualSize = try regularFileSize(input, digest: descriptor.digest)
        guard actualSize == validated.size else {
            throw EngineError(.internalError, "OCI content \(descriptor.digest) has the wrong size")
        }
        var hasher = SHA256()
        var copied: UInt64 = 0
        while let chunk = try input.read(upToCount: 1 * 1_024 * 1_024), !chunk.isEmpty {
            copied = try CheckedArithmetic.add(copied, UInt64(chunk.count))
            guard copied <= validated.size else {
                throw EngineError(.internalError, "OCI content \(descriptor.digest) exceeds its descriptor size")
            }
            hasher.update(data: chunk)
            try output.write(contentsOf: chunk)
        }
        guard copied == validated.size,
              Self.digest(hasher.finalize()) == descriptor.digest else {
            throw EngineError(.internalError, "OCI content \(descriptor.digest) failed verification")
        }
    }

    public func tag(_ descriptor: OCIDescriptor, as reference: String) throws {
        _ = try descriptor.validated(policy: transferPolicy, errorCode: .badRequest)
        do {
            try verifyBlob(descriptor, errorCode: .internalError)
        } catch let error as EngineError where error.code == .notFound {
            throw EngineError(.notFound, "OCI content \(descriptor.digest) not found")
        }
        index.references[ImageReference.normalized(reference)] = descriptor
        try saveIndex()
    }

    public func remove(reference: String) throws {
        let normalized = ImageReference.normalized(reference)
        let removedRoot = index.references.removeValue(forKey: normalized)
        var removed = removedRoot != nil
        if !removed && reference.hasPrefix("sha256:") {
            let previousCount = index.references.count
            index.references = index.references.filter { $0.value.digest != reference }
            removed = index.references.count != previousCount
        }
        guard removed else {
            throw EngineError(.notFound, "image \(reference) not found")
        }
        let retainedRoots = Set(index.references.values.map(\.digest))
        if let digest = removedRoot?.digest, !retainedRoots.contains(digest) {
            index.pullRepositories.removeValue(forKey: digest)
        }
        index.pullRepositories = index.pullRepositories.filter { retainedRoots.contains($0.key) }
        try saveIndex()
    }

    public func image(reference: String, platform: String) throws -> OCIStoredImage {
        try image(reference: reference, platform: OCIPlatform(platform))
    }

    public func image(reference: String, platform: OCIPlatform? = nil) throws -> OCIStoredImage {
        let normalized = ImageReference.normalized(reference)
        let rootDescriptor = try rootDescriptor(for: reference)
        let records = try manifestRecords(in: rootDescriptor).filter { $0.kind == .image && $0.available }
        let selectedRecord: ImageManifestRecord?
        if let platform {
            selectedRecord = records.first { $0.platform?.matches(platform) == true }
        } else {
            selectedRecord = preferredManifest(in: records)
        }
        guard let selectedRecord else {
            let suffix = platform.map { " has no \($0.description) manifest" } ?? " has no locally available manifest"
            throw EngineError(.notFound, "image \(normalized)\(suffix)")
        }
        let manifestDescriptor = selectedRecord.descriptor
        let manifest = try decoder.decode(
            OCIManifest.self, from: data(for: manifestDescriptor)
        )
        let configuration = try decoder.decode(
            OCIImageConfiguration.self, from: data(for: manifest.config)
        )
        return OCIStoredImage(
            reference: normalized,
            rootDescriptor: rootDescriptor,
            manifestDescriptor: manifestDescriptor,
            manifest: manifest,
            configuration: configuration
        )
    }

    public func pull(
        reference: String,
        platform: String,
        credentials: RegistryCredentials?,
        progress: @escaping ImagePullProgressHandler
    ) async throws -> OCIStoredImage {
        let parsed = try OCIRegistryReference(reference)
        let client = OCIRegistryClient(
            reference: parsed, credentials: credentials, policy: transferPolicy
        )
        let rootResponse = try await client.fetchManifest(parsed.selector)
        if let advertised = rootResponse.digest {
            let advertisedDescriptor = OCIDescriptor(
                mediaType: rootResponse.mediaType,
                digest: advertised,
                size: Int64(rootResponse.data.count)
            )
            _ = try advertisedDescriptor.validated(
                policy: transferPolicy, errorCode: .upstream
            )
            guard Self.digest(rootResponse.data) == advertised else {
                throw EngineError(.upstream, "registry root manifest digest mismatch")
            }
        }
        let rootDescriptor = try put(
            rootResponse.data,
            mediaType: rootResponse.mediaType,
            expectedDigest: rootResponse.digest
        )
        var graphBudget = GraphBudget(policy: transferPolicy)
        _ = try graphBudget.admit(rootDescriptor, depth: 0)
        var activeIndexes = Set<String>()
        try await downloadIndexNodes(
            rootDescriptor,
            contents: rootResponse.data,
            client: client,
            depth: 0,
            budget: &graphBudget,
            active: &activeIndexes
        )
        let requested = try OCIPlatform(platform)
        let leaves = try leafDescriptors(in: rootDescriptor)
        guard let selected = leaves.first(where: {
            !isAttestationDescriptor($0) && $0.platform?.matches(requested) == true
        }) ?? (leaves.count == 1 && !Self.indexMediaTypes.contains(rootDescriptor.mediaType) ? leaves[0] : nil) else {
            throw EngineError(.notFound, "image \(parsed.normalized) has no \(platform) manifest")
        }
        let selectedManifest = try await downloadManifestGraph(
            selected, client: client, depth: 1, budget: &graphBudget
        )
        let configurationData = try data(
            for: selectedManifest.config, errorCode: .upstream
        )
        let configuration = try decoder.decode(OCIImageConfiguration.self, from: configurationData)
        guard OCIPlatform(
            architecture: configuration.architecture,
            os: configuration.os,
            variant: configuration.variant,
            osVersion: configuration.osVersion
        ).matches(requested) else {
            throw EngineError(.notFound, "image \(parsed.normalized) has no \(platform) manifest")
        }
        let attestationDescriptors = leaves.filter {
            attestationTarget(for: $0) == selected.digest
        }
        for descriptor in attestationDescriptors {
            _ = try await downloadManifestGraph(
                descriptor, client: client, depth: 1, budget: &graphBudget
            )
        }
        let descriptors = [selectedManifest.config] + selectedManifest.layers
        var totalBytes: Int64 = 0
        for descriptor in descriptors {
            _ = try descriptor.validated(policy: transferPolicy, errorCode: .upstream)
            do {
                totalBytes = try CheckedArithmetic.add(totalBytes, descriptor.size)
            } catch {
                throw EngineError(.upstream, "OCI descriptor total overflows")
            }
        }
        var completedBytes: Int64 = 0
        for (index, descriptor) in descriptors.enumerated() {
            do {
                completedBytes = try CheckedArithmetic.add(completedBytes, descriptor.size)
            } catch {
                throw EngineError(.upstream, "OCI pull progress overflows")
            }
            await progress(.init(
                completedItems: index + 1,
                totalItems: descriptors.count,
                completedBytes: completedBytes,
                totalBytes: totalBytes
            ))
        }
        try tag(rootDescriptor, as: parsed.normalized)
        try recordPullRepository("\(parsed.registry)/\(parsed.repository)", for: rootDescriptor)
        return try image(reference: parsed.normalized, platform: platform)
    }

    public func push(reference: String, platform: OCIPlatform?, credentials: RegistryCredentials?) async throws {
        let parsed = try OCIRegistryReference(reference)
        let client = OCIRegistryClient(
            reference: parsed, credentials: credentials, policy: transferPolicy
        )
        let rootDescriptor = try rootDescriptor(for: reference)
        if let platform {
            let selected = try image(reference: reference, platform: platform)
            try await pushManifestGraph(selected.manifestDescriptor, client: client)
            try await client.pushManifest(
                data(for: selected.manifestDescriptor.digest),
                mediaType: selected.manifestDescriptor.mediaType,
                selector: parsed.selector
            )
        } else {
            let available = try leafDescriptors(in: rootDescriptor).filter(isGraphAvailable)
            for descriptor in available { try await pushManifestGraph(descriptor, client: client) }
            if Self.indexMediaTypes.contains(rootDescriptor.mediaType) {
                let original = try decoder.decode(OCIIndex.self, from: data(for: rootDescriptor.digest))
                let filtered = OCIIndex(
                    schemaVersion: original.schemaVersion,
                    mediaType: original.mediaType,
                    artifactType: original.artifactType,
                    manifests: available,
                    subject: original.subject,
                    annotations: original.annotations
                )
                try await client.pushManifest(
                    encoder.encode(filtered),
                    mediaType: rootDescriptor.mediaType,
                    selector: parsed.selector
                )
            } else {
                try await client.pushManifest(
                    data(for: rootDescriptor.digest),
                    mediaType: rootDescriptor.mediaType,
                    selector: parsed.selector
                )
            }
        }
        try recordPullRepository("\(parsed.registry)/\(parsed.repository)", for: rootDescriptor)
    }

    public func history(reference: String, platform: OCIPlatform?) throws -> [ImageHistoryEntry] {
        let value = try image(reference: reference, platform: platform)
        return (value.configuration.history ?? []).map {
            let date = $0.created.flatMap { ISO8601DateFormatter().date(from: $0) } ?? Date(timeIntervalSince1970: 0)
            return .init(created: Int64(date.timeIntervalSince1970), createdBy: $0.createdBy ?? "", comment: $0.comment ?? "", emptyLayer: $0.emptyLayer ?? false)
        }
    }

    public func importLayout(_ directory: URL, platforms: [OCIPlatform] = []) throws -> [BackendImage] {
        let indexData = try readLayoutFile(
            directory: directory,
            relativePath: "index.json",
            maximumBytes: UInt64(transferPolicy.metadataBytes)
        )
        let layoutIndex = try decoder.decode(OCIIndex.self, from: indexData)
        let archiveURL = directory.appending(path: "manifest.json")
        let archiveEntries = (try? decoder.decode(
            [DockerArchiveEntry].self,
            from: readLayoutFile(
                directory: directory,
                relativePath: archiveURL.lastPathComponent,
                maximumBytes: UInt64(transferPolicy.metadataBytes)
            )
        )) ?? []
        var references = Set<String>()
        var pendingReferences: [(String, OCIDescriptor)] = []
        for descriptor in layoutIndex.manifests {
            let leaves = try layoutLeafDescriptors(in: descriptor, directory: directory)
            let presentLeaves = leaves.filter { layoutContains($0, directory: directory) }
            let runnable = try presentLeaves.filter { descriptor in
                try !isLayoutAttestation(descriptor, directory: directory)
            }
            let selectedImages: [OCIDescriptor]
            if platforms.isEmpty {
                selectedImages = runnable
            } else {
                selectedImages = try platforms.map { platform in
                    guard let selected = try runnable.first(where: {
                        try layoutPlatform(for: $0, directory: directory)?.matches(platform) == true
                    }) else {
                        throw EngineError(.notFound, "image archive has no \(platform.description) manifest")
                    }
                    return selected
                }
            }
            let selectedImageDigests = Set(selectedImages.map(\.digest))
            let selectedAttestations = try presentLeaves.filter {
                guard let target = try layoutAttestationTarget(for: $0, directory: directory) else { return false }
                return selectedImageDigests.contains(target)
            }
            let selected = Set((selectedImages + selectedAttestations).map(\.digest))
            var seen = Set<String>()
            try importDescriptor(descriptor, selectedLeaves: selected, from: directory, seen: &seen)
            var descriptorReferences: [String] = []
            if let reference = descriptor.annotations?["org.opencontainers.image.ref.name"]
                ?? descriptor.annotations?["io.containerd.image.name"] {
                descriptorReferences.append(reference)
            }
            let configurations = try Set(selectedImages.map {
                try decoder.decode(OCIManifest.self, from: layoutData(for: $0, directory: directory)).config.digest
            })
            descriptorReferences.append(contentsOf: archiveEntries.compactMap { entry in
                configurations.contains(entry.configDigest) ? entry.repoTags : nil
            }.flatMap { $0 })
            if descriptorReferences.isEmpty { descriptorReferences = [descriptor.digest] }
            for reference in Set(descriptorReferences) {
                let normalized = ImageReference.normalized(reference)
                pendingReferences.append((normalized, descriptor))
                references.insert(normalized)
            }
        }
        let previousIndex = index
        do {
            for (reference, descriptor) in pendingReferences {
                try verifyBlob(descriptor, errorCode: .badRequest)
                index.references[reference] = descriptor
            }
            try saveIndex()
        } catch {
            index = previousIndex
            throw error
        }
        let all = try summaries()
        return all.filter { references.contains($0.reference) }
    }

    public func exportLayout(
        references requested: [String],
        platforms: [OCIPlatform] = []
    ) throws -> Data {
        let temporary = FileManager.default.temporaryDirectory.appending(
            path: ".cengine-oci-export-\(UUID().uuidString).tar"
        )
        defer { try? FileManager.default.removeItem(at: temporary) }
        try exportLayout(
            references: requested, platforms: platforms, to: temporary
        )
        return try Data(contentsOf: temporary)
    }

    public func exportLayout(
        references requested: [String],
        platforms: [OCIPlatform] = [],
        to destination: URL
    ) throws {
        let names = requested.isEmpty ? references() : requested.map(ImageReference.normalized)
        var roots: [OCIDescriptor] = []
        var descriptors: [String: OCIDescriptor] = [:]
        var generatedBlobs: [String: Data] = [:]
        var archiveEntries: [DockerArchiveEntry] = []
        for name in names {
            let rootDescriptor = try rootDescriptor(for: name)
            let runnable = try manifestRecords(in: rootDescriptor).filter { $0.kind == .image && $0.available }
            let selectedImages: [ImageManifestRecord]
            if platforms.isEmpty {
                selectedImages = runnable
            } else {
                selectedImages = try platforms.map { platform in
                    guard let selected = runnable.first(where: { $0.platform?.matches(platform) == true }) else {
                        throw EngineError(.notFound, "image \(name) has no \(platform.description) manifest")
                    }
                    return selected
                }
            }
            let selectedImageDigests = Set(selectedImages.map { $0.descriptor.digest })
            let selectedAttestations = try manifestRecords(in: rootDescriptor).filter {
                $0.kind == .attestation && $0.available && $0.attestationFor.map(selectedImageDigests.contains) == true
            }
            let selectedLeaves = Set((selectedImages + selectedAttestations).map { $0.descriptor.digest })
            let selectedRecords = selectedImages + selectedAttestations
            let descriptor: OCIDescriptor
            if Self.indexMediaTypes.contains(rootDescriptor.mediaType) {
                let original = try decoder.decode(OCIIndex.self, from: data(for: rootDescriptor.digest))
                let filtered = OCIIndex(
                    schemaVersion: original.schemaVersion,
                    mediaType: original.mediaType,
                    artifactType: original.artifactType,
                    manifests: selectedRecords.map(\.descriptor),
                    subject: original.subject,
                    annotations: original.annotations
                )
                let contents = try encoder.encode(filtered)
                descriptor = OCIDescriptor(
                    mediaType: rootDescriptor.mediaType,
                    digest: Self.digest(contents),
                    size: Int64(contents.count),
                    artifactType: rootDescriptor.artifactType
                )
                generatedBlobs[descriptor.digest] = contents
                descriptors[descriptor.digest] = descriptor
                for record in selectedRecords {
                    try collect(
                        record.descriptor,
                        selectedLeaves: [record.descriptor.digest],
                        into: &descriptors
                    )
                }
            } else {
                descriptor = rootDescriptor
                try collect(
                    descriptor,
                    selectedLeaves: selectedLeaves,
                    into: &descriptors
                )
            }
            var annotatedDescriptor = descriptor
            var annotations = annotatedDescriptor.annotations ?? [:]
            annotations["org.opencontainers.image.ref.name"] = name
            annotations["io.containerd.image.name"] = name
            annotatedDescriptor.annotations = annotations
            roots.append(annotatedDescriptor)
            archiveEntries.append(contentsOf: try selectedImages.map { record in
                let manifest = try decoder.decode(
                    OCIManifest.self, from: data(for: record.descriptor)
                )
                return DockerArchiveEntry(
                    config: "blobs/sha256/\(manifest.config.digest.dropFirst(7))",
                    repoTags: [name],
                    layers: manifest.layers.map { "blobs/sha256/\($0.digest.dropFirst(7))" }
                )
            })
        }
        let layout = try encoder.encode(["imageLayoutVersion": "1.0.0"])
        let layoutIndex = try encoder.encode(OCIIndex(schemaVersion: 2, mediaType: "application/vnd.oci.image.index.v1+json", manifests: roots, annotations: nil))
        var dataEntries: [(String, Data)] = [
            ("oci-layout", layout),
            ("index.json", layoutIndex),
            ("manifest.json", try encoder.encode(archiveEntries)),
        ]
        var blobEntries: [(String, OCIDescriptor)] = []
        for digest in descriptors.keys.sorted() {
            let name = "blobs/sha256/" + String(digest.dropFirst(7))
            if let generated = generatedBlobs[digest] {
                dataEntries.append((name, generated))
            } else if let descriptor = descriptors[digest] {
                blobEntries.append((name, descriptor))
            }
        }
        try OCIArchive.write(
            dataEntries: dataEntries,
            blobEntries: blobEntries,
            to: destination,
            copyBlob: { descriptor, output in
                try copyBlob(descriptor, to: output)
            }
        )
    }

    private func importDescriptor(
        _ descriptor: OCIDescriptor,
        selectedLeaves: Set<String>,
        from directory: URL,
        seen: inout Set<String>
    ) throws {
        guard seen.insert(descriptor.digest).inserted else { return }
        if !Self.indexMediaTypes.contains(descriptor.mediaType), !selectedLeaves.contains(descriptor.digest) { return }
        let contents = try layoutData(for: descriptor, directory: directory)
        _ = try put(contents, mediaType: descriptor.mediaType, expectedDigest: descriptor.digest)
        if Self.indexMediaTypes.contains(descriptor.mediaType) {
            for child in try decoder.decode(OCIIndex.self, from: contents).manifests {
                try importDescriptor(child, selectedLeaves: selectedLeaves, from: directory, seen: &seen)
            }
        } else if Self.manifestMediaTypes.contains(descriptor.mediaType) {
            let manifest = try decoder.decode(OCIManifest.self, from: contents)
            for child in [manifest.config] + manifest.layers {
                try importDescriptor(child, selectedLeaves: [child.digest], from: directory, seen: &seen)
            }
        }
    }

    private func collect(
        _ descriptor: OCIDescriptor,
        selectedLeaves: Set<String>,
        into descriptors: inout [String: OCIDescriptor]
    ) throws {
        _ = try descriptor.validated(
            policy: transferPolicy, errorCode: .internalError
        )
        if let existing = descriptors[descriptor.digest] {
            guard existing.mediaType == descriptor.mediaType,
                  existing.size == descriptor.size else {
                throw EngineError(
                    .internalError,
                    "persisted OCI graph repeats a digest with conflicting metadata"
                )
            }
            return
        }
        descriptors[descriptor.digest] = descriptor
        if Self.indexMediaTypes.contains(descriptor.mediaType) {
            let contents = try data(for: descriptor)
            for child in try decoder.decode(OCIIndex.self, from: contents).manifests {
                if Self.indexMediaTypes.contains(child.mediaType)
                    || selectedLeaves.contains(child.digest) {
                    try collect(
                        child, selectedLeaves: selectedLeaves, into: &descriptors
                    )
                }
            }
        } else if Self.manifestMediaTypes.contains(descriptor.mediaType) {
            let contents = try data(for: descriptor)
            let manifest = try decoder.decode(OCIManifest.self, from: contents)
            for child in [manifest.config] + manifest.layers {
                guard hasVerifiedBlob(child) else { continue }
                try collect(
                    child, selectedLeaves: [child.digest], into: &descriptors
                )
            }
        }
    }

    public func remove(reference: String, platforms: [OCIPlatform]) throws -> [String] {
        guard !platforms.isEmpty else {
            let descriptor = try rootDescriptor(for: reference)
            try remove(reference: reference)
            return [descriptor.digest]
        }
        let rootDescriptor = try rootDescriptor(for: reference)
        let records = try manifestRecords(in: rootDescriptor)
        var selected: [ImageManifestRecord] = []
        for platform in platforms {
            guard let record = records.first(where: {
                $0.kind == .image && $0.available && $0.platform?.matches(platform) == true
            }) else {
                throw EngineError(.notFound, "image \(reference) has no \(platform.description) manifest")
            }
            selected.append(record)
        }
        let selectedDigests = Set(selected.map { $0.descriptor.digest })
        let attached = records.filter {
            $0.kind == .attestation && $0.attestationFor.map(selectedDigests.contains) == true
        }
        var candidates = Set<String>()
        for record in selected + attached {
            try collectPresentDigests(record.descriptor, into: &candidates)
        }
        var protected = Set<String>()
        for record in records where !selectedDigests.contains(record.descriptor.digest)
            && !(record.kind == .attestation && attached.contains(where: { $0.descriptor.digest == record.descriptor.digest })) {
            try collectPresentDigests(record.descriptor, into: &protected)
        }
        candidates.subtract(protected)
        candidates.remove(rootDescriptor.digest)
        for digest in candidates {
            try? FileManager.default.removeItem(at: blobURL(for: digest))
        }
        return selected.map { $0.descriptor.digest }
    }

    public func attestations(
        reference: String,
        platform: OCIPlatform?,
        predicateTypes: [String],
        includeStatement: Bool
    ) throws -> [ImageAttestationRecord] {
        let image = try image(reference: reference, platform: platform)
        let rootDescriptor = image.rootDescriptor
        let records = try manifestRecords(in: rootDescriptor).filter {
            $0.kind == .attestation && $0.attestationFor == image.manifestDescriptor.digest
        }
        var result: [ImageAttestationRecord] = []
        for record in records where contains(record.descriptor.digest) {
            let manifest = try decoder.decode(OCIManifest.self, from: data(for: record.descriptor.digest))
            for layer in manifest.layers {
                guard let predicate = layer.annotations?[Self.inTotoPredicateTypeAnnotation],
                      predicateTypes.isEmpty || predicateTypes.contains(predicate) else { continue }
                let statement: Data?
                if includeStatement {
                    let value = try data(for: layer.digest)
                    _ = try JSONSerialization.jsonObject(with: value)
                    statement = value
                } else {
                    statement = nil
                }
                result.append(.init(descriptor: layer, predicateType: predicate, statement: statement))
            }
        }
        return result
    }

    private func rootDescriptor(for reference: String) throws -> OCIDescriptor {
        let normalized = ImageReference.normalized(reference)
        if let descriptor = index.references[normalized] { return descriptor }
        let candidate = reference.lowercased()
        let matches = index.references.values.filter { descriptor in
            descriptor.digest == candidate || descriptor.digest.hasPrefix(candidate)
        }
        if let descriptor = matches.first { return descriptor }
        for descriptor in index.references.values {
            if (try? graphContains(descriptor, digestPrefix: candidate)) == true { return descriptor }
        }
        throw EngineError(.notFound, "image \(reference) not found")
    }

    private func graphContains(_ descriptor: OCIDescriptor, digestPrefix: String) throws -> Bool {
        if descriptor.digest.hasPrefix(digestPrefix) { return true }
        guard contains(descriptor.digest) else { return false }
        if Self.indexMediaTypes.contains(descriptor.mediaType) {
            return try decoder.decode(OCIIndex.self, from: data(for: descriptor.digest)).manifests.contains {
                (try? graphContains($0, digestPrefix: digestPrefix)) == true
            }
        }
        if Self.manifestMediaTypes.contains(descriptor.mediaType) {
            let manifest = try decoder.decode(OCIManifest.self, from: data(for: descriptor.digest))
            return ([manifest.config] + manifest.layers).contains { $0.digest.hasPrefix(digestPrefix) }
        }
        return false
    }

    private func identity(for descriptor: OCIDescriptor) -> ImageIdentityRecord? {
        guard let repositories = index.pullRepositories[descriptor.digest], !repositories.isEmpty else { return nil }
        return .init(pullRepositories: repositories.sorted())
    }

    private func recordPullRepository(_ repository: String, for descriptor: OCIDescriptor) throws {
        var values = Set(index.pullRepositories[descriptor.digest] ?? [])
        values.insert(repository)
        index.pullRepositories[descriptor.digest] = values.sorted()
        try saveIndex()
    }

    private func leafDescriptors(in descriptor: OCIDescriptor) throws -> [OCIDescriptor] {
        var budget = GraphBudget(policy: transferPolicy, errorCode: .internalError)
        var active = Set<String>()
        return try leafDescriptors(
            in: descriptor, depth: 0, budget: &budget, active: &active
        )
    }

    private func leafDescriptors(
        in descriptor: OCIDescriptor,
        depth: Int,
        budget: inout GraphBudget,
        active: inout Set<String>
    ) throws -> [OCIDescriptor] {
        if Self.indexMediaTypes.contains(descriptor.mediaType),
           active.contains(descriptor.digest) {
            throw EngineError(.internalError, "persisted OCI descriptor graph contains a cycle")
        }
        let inserted = try budget.admit(descriptor, depth: depth)
        guard Self.indexMediaTypes.contains(descriptor.mediaType) else {
            return inserted ? [descriptor] : []
        }
        guard inserted, hasVerifiedBlob(descriptor) else { return [] }
        active.insert(descriptor.digest)
        defer { active.remove(descriptor.digest) }
        let value = try decoder.decode(OCIIndex.self, from: data(for: descriptor))
        return try value.manifests.flatMap { child in
            try leafDescriptors(
                in: child, depth: depth + 1, budget: &budget, active: &active
            )
        }
    }

    private func manifestRecords(in rootDescriptor: OCIDescriptor) throws -> [ImageManifestRecord] {
        try leafDescriptors(in: rootDescriptor).map(manifestRecord).sorted {
            ($0.platform?.description ?? "~", $0.descriptor.digest) <
                ($1.platform?.description ?? "~", $1.descriptor.digest)
        }
    }

    private func manifestRecord(_ descriptor: OCIDescriptor) throws -> ImageManifestRecord {
        let annotatedTarget = attestationTarget(for: descriptor)
        _ = try descriptor.validated(policy: transferPolicy, errorCode: .internalError)
        guard hasVerifiedBlob(descriptor), Self.manifestMediaTypes.contains(descriptor.mediaType) else {
            let kind: ImageManifestKind
            if annotatedTarget != nil || isAttestationDescriptor(descriptor) {
                kind = .attestation
            } else if descriptor.platform != nil || Self.manifestMediaTypes.contains(descriptor.mediaType) {
                kind = .image
            } else {
                kind = .unknown
            }
            return .init(
                descriptor: descriptor,
                available: false,
                kind: kind,
                platform: descriptor.platform,
                contentSize: hasVerifiedBlob(descriptor) ? descriptor.size : 0,
                attestationFor: annotatedTarget
            )
        }
        let manifest = try decoder.decode(OCIManifest.self, from: data(for: descriptor))
        let target = annotatedTarget ?? manifest.subject?.digest
        let isAttestation = target != nil && (
            isAttestationDescriptor(descriptor) || manifest.artifactType == Self.attestationManifestArtifactType
        )
        let children = [manifest.config] + manifest.layers
        for child in children {
            _ = try child.validated(policy: transferPolicy, errorCode: .internalError)
        }
        let available = children.allSatisfy(hasVerifiedBlob)
        var contentSize = descriptor.size
        for child in children where hasVerifiedBlob(child) {
            do {
                contentSize = try CheckedArithmetic.add(contentSize, child.size)
            } catch {
                throw EngineError(.internalError, "OCI image content size overflows")
            }
        }
        if isAttestation {
            return .init(
                descriptor: descriptor,
                available: available,
                kind: .attestation,
                platform: descriptor.platform,
                contentSize: contentSize,
                attestationFor: target
            )
        }
        guard hasVerifiedBlob(manifest.config),
              let configuration = try? decoder.decode(
                OCIImageConfiguration.self, from: data(for: manifest.config)
              ),
              !configuration.os.isEmpty, !configuration.architecture.isEmpty else {
            return .init(
                descriptor: descriptor,
                available: available,
                kind: .unknown,
                platform: descriptor.platform,
                contentSize: contentSize
            )
        }
        let platform = descriptor.platform ?? OCIPlatform(
            architecture: configuration.architecture,
            os: configuration.os,
            variant: configuration.variant,
            osVersion: configuration.osVersion
        )
        let created = configuration.created.flatMap { ISO8601DateFormatter().date(from: $0) }
        let history = (configuration.history ?? []).map { entry in
            let date = entry.created.flatMap { ISO8601DateFormatter().date(from: $0) } ?? Date(timeIntervalSince1970: 0)
            return ImageHistoryEntry(
                created: Int64(date.timeIntervalSince1970),
                createdBy: entry.createdBy ?? "",
                comment: entry.comment ?? "",
                emptyLayer: entry.emptyLayer ?? false
            )
        }
        return .init(
            descriptor: descriptor,
            imageID: manifest.config.digest,
            available: available,
            kind: .image,
            platform: platform,
            createdAt: created,
            contentSize: contentSize,
            configuration: .init(
                environment: configuration.config?.environment,
                command: configuration.config?.command,
                entrypoint: configuration.config?.entrypoint,
                workingDirectory: configuration.config?.workingDirectory,
                user: configuration.config?.user,
                labels: configuration.config?.labels,
                exposedPorts: configuration.config?.exposedPorts.map { Array($0.keys).sorted() },
                volumes: configuration.config?.volumes.map { Array($0.keys).sorted() },
                healthcheck: configuration.config?.healthcheck.flatMap { health in
                    guard let test = health.test else { return nil }
                    return HealthcheckRecord(
                        test: test,
                        intervalNanoseconds: health.interval ?? 0,
                        timeoutNanoseconds: health.timeout ?? 0,
                        retries: health.retries ?? 0,
                        startPeriodNanoseconds: health.startPeriod ?? 0,
                        startIntervalNanoseconds: health.startInterval ?? 0
                    )
                },
                rootFSDiffIDs: configuration.rootfs.diffIDs
            ),
            history: history
        )
    }

    private func preferredManifest(in records: [ImageManifestRecord]) -> ImageManifestRecord? {
        records.first {
            $0.kind == .image && $0.available && $0.platform?.matches(Self.hostPlatform) == true
        } ?? records.first { $0.kind == .image && $0.available }
    }

    private func isAttestationDescriptor(_ descriptor: OCIDescriptor) -> Bool {
        descriptor.annotations?[Self.attestationReferenceTypeAnnotation] == Self.attestationReferenceType ||
            descriptor.artifactType == Self.attestationManifestArtifactType ||
            (descriptor.platform?.os == "unknown" && descriptor.platform?.architecture == "unknown")
    }

    private func attestationTarget(for descriptor: OCIDescriptor) -> String? {
        descriptor.annotations?[Self.attestationReferenceDigestAnnotation]
    }

    private func isGraphAvailable(_ descriptor: OCIDescriptor) -> Bool {
        guard contains(descriptor.digest) else { return false }
        if Self.indexMediaTypes.contains(descriptor.mediaType) {
            guard let value = try? decoder.decode(OCIIndex.self, from: data(for: descriptor.digest)) else { return false }
            return value.manifests.allSatisfy(isGraphAvailable)
        }
        if Self.manifestMediaTypes.contains(descriptor.mediaType) {
            guard let value = try? decoder.decode(OCIManifest.self, from: data(for: descriptor.digest)) else { return false }
            return ([value.config] + value.layers).allSatisfy { contains($0.digest) }
        }
        return true
    }

    private func collectPresentDigests(_ descriptor: OCIDescriptor, into values: inout Set<String>) throws {
        guard contains(descriptor.digest), values.insert(descriptor.digest).inserted else { return }
        if Self.indexMediaTypes.contains(descriptor.mediaType) {
            for child in try decoder.decode(OCIIndex.self, from: data(for: descriptor.digest)).manifests {
                try collectPresentDigests(child, into: &values)
            }
        } else if Self.manifestMediaTypes.contains(descriptor.mediaType) {
            let manifest = try decoder.decode(OCIManifest.self, from: data(for: descriptor.digest))
            for child in [manifest.config] + manifest.layers { try collectPresentDigests(child, into: &values) }
        }
    }

    private func downloadIndexNodes(
        _ descriptor: OCIDescriptor,
        contents: Data? = nil,
        client: OCIRegistryClient,
        depth: Int,
        budget: inout GraphBudget,
        active: inout Set<String>
    ) async throws {
        guard Self.indexMediaTypes.contains(descriptor.mediaType) else { return }
        guard active.insert(descriptor.digest).inserted else {
            throw EngineError(.upstream, "OCI descriptor graph contains a cycle")
        }
        defer { active.remove(descriptor.digest) }
        let valueData: Data
        if let contents {
            valueData = contents
        } else if hasVerifiedBlob(descriptor) {
            valueData = try data(for: descriptor, errorCode: .upstream)
        } else {
            let response = try await client.fetchManifest(descriptor.digest)
            try requireRegistryResponse(response, matches: descriptor)
            _ = try put(
                response.data,
                mediaType: descriptor.mediaType,
                expectedDigest: descriptor.digest
            )
            valueData = response.data
        }
        let value = try decoder.decode(OCIIndex.self, from: valueData)
        for child in value.manifests {
            _ = try budget.admit(child, depth: depth + 1)
            if Self.indexMediaTypes.contains(child.mediaType) {
                try await downloadIndexNodes(
                    child,
                    client: client,
                    depth: depth + 1,
                    budget: &budget,
                    active: &active
                )
            }
        }
    }

    private func downloadManifestGraph(
        _ descriptor: OCIDescriptor,
        client: OCIRegistryClient,
        depth: Int,
        budget: inout GraphBudget
    ) async throws -> OCIManifest {
        _ = try budget.admit(descriptor, depth: depth)
        let contents: Data
        if hasVerifiedBlob(descriptor) {
            contents = try data(for: descriptor, errorCode: .upstream)
        } else {
            let response = try await client.fetchManifest(descriptor.digest)
            try requireRegistryResponse(response, matches: descriptor)
            _ = try put(
                response.data,
                mediaType: descriptor.mediaType,
                expectedDigest: descriptor.digest
            )
            contents = response.data
        }
        let manifest = try decoder.decode(OCIManifest.self, from: contents)
        for child in [manifest.config] + manifest.layers {
            _ = try budget.admit(child, depth: depth + 1)
            if hasVerifiedBlob(child) { continue }
            let temporary = blobRoot.appending(
                path: ".\(child.digest.dropFirst(7)).\(UUID().uuidString).download"
            )
            defer { try? FileManager.default.removeItem(at: temporary) }
            try await client.fetchBlob(child, to: temporary)
            try installDownloadedBlob(temporary, descriptor: child)
        }
        return manifest
    }

    private func pushManifestGraph(_ descriptor: OCIDescriptor, client: OCIRegistryClient) async throws {
        let manifest = try decoder.decode(OCIManifest.self, from: data(for: descriptor))
        for child in [manifest.config] + manifest.layers {
            if try await client.blobExists(child.digest) == false {
                let temporary = blobRoot.appending(
                    path: ".\(child.digest.dropFirst(7)).\(UUID().uuidString).upload"
                )
                let outputFD = Darwin.open(
                    temporary.path,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    mode_t(0o600)
                )
                guard outputFD >= 0 else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
                let output = FileHandle(
                    fileDescriptor: outputFD, closeOnDealloc: true
                )
                do {
                    try copyBlob(child, to: output)
                    try output.synchronize()
                    try output.close()
                    try await client.pushBlob(
                        file: temporary, descriptor: child
                    )
                    try FileManager.default.removeItem(at: temporary)
                } catch {
                    try? output.close()
                    try? FileManager.default.removeItem(at: temporary)
                    throw error
                }
            }
        }
        try await client.pushManifest(
            data(for: descriptor),
            mediaType: descriptor.mediaType,
            selector: descriptor.digest
        )
    }

    private func requireRegistryResponse(
        _ response: OCIRegistryClient.ManifestResponse,
        matches descriptor: OCIDescriptor
    ) throws {
        let validated = try descriptor.validated(
            policy: transferPolicy, errorCode: .upstream
        )
        guard UInt64(response.data.count) == validated.size,
              Self.digest(response.data) == descriptor.digest else {
            throw EngineError(.upstream, "registry manifest failed descriptor size or digest verification")
        }
        if let advertised = response.digest, advertised != descriptor.digest {
            throw EngineError(.upstream, "registry manifest returned a conflicting digest")
        }
    }

    private func hasVerifiedBlob(_ descriptor: OCIDescriptor) -> Bool {
        do {
            try verifyBlob(descriptor, errorCode: .upstream)
            return true
        } catch {
            return false
        }
    }

    private func installDownloadedBlob(
        _ temporary: URL,
        descriptor: OCIDescriptor
    ) throws {
        try verifyFile(temporary, descriptor: descriptor, errorCode: .upstream)
        let destination = try blobURL(for: descriptor.digest)
        if FileManager.default.fileExists(atPath: destination.path) {
            try verifyBlob(descriptor, errorCode: .upstream)
            try FileManager.default.removeItem(at: temporary)
            return
        }
        guard Darwin.renamex_np(
            temporary.path, destination.path, UInt32(RENAME_EXCL)
        ) == 0 else {
            if errno == EEXIST {
                try verifyBlob(descriptor, errorCode: .upstream)
                try FileManager.default.removeItem(at: temporary)
                return
            }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try verifyBlob(descriptor, errorCode: .upstream)
    }

    private func verifyFile(
        _ url: URL,
        descriptor: OCIDescriptor,
        errorCode: EngineError.Code
    ) throws {
        let validated = try descriptor.validated(
            policy: transferPolicy, errorCode: errorCode
        )
        let descriptorFD = Darwin.open(
            url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
        )
        guard descriptorFD >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let input = FileHandle(fileDescriptor: descriptorFD, closeOnDealloc: true)
        defer { try? input.close() }
        guard try regularFileSize(input, digest: descriptor.digest) == validated.size else {
            throw EngineError(errorCode, "OCI content \(descriptor.digest) has the wrong size")
        }
        var hasher = SHA256()
        var count: UInt64 = 0
        while let chunk = try input.read(upToCount: 1 * 1_024 * 1_024), !chunk.isEmpty {
            count = try CheckedArithmetic.add(count, UInt64(chunk.count))
            guard count <= validated.size else {
                throw EngineError(errorCode, "OCI content \(descriptor.digest) exceeds its descriptor size")
            }
            hasher.update(data: chunk)
        }
        guard count == validated.size,
              Self.digest(hasher.finalize()) == descriptor.digest else {
            throw EngineError(errorCode, "OCI content \(descriptor.digest) failed verification")
        }
    }

    private func layoutData(for descriptor: OCIDescriptor, directory: URL) throws -> Data {
        if let embedded = descriptor.data {
            guard Self.digest(embedded) == descriptor.digest else {
                throw EngineError(.badRequest, "embedded OCI content \(descriptor.digest) failed verification")
            }
            return embedded
        }
        let validated = try descriptor.validated(
            policy: transferPolicy, errorCode: .badRequest
        )
        let contents = try readLayoutFile(
            directory: directory,
            relativePath: "blobs/sha256/" + String(descriptor.digest.dropFirst(7)),
            maximumBytes: validated.size
        )
        guard UInt64(contents.count) == validated.size,
              Self.digest(contents) == descriptor.digest else {
            throw EngineError(.badRequest, "OCI archive content \(descriptor.digest) failed verification")
        }
        return contents
    }

    private func layoutContains(_ descriptor: OCIDescriptor, directory: URL) -> Bool {
        (try? layoutData(for: descriptor, directory: directory)) != nil
    }

    private func layoutLeafDescriptors(in descriptor: OCIDescriptor, directory: URL) throws -> [OCIDescriptor] {
        guard Self.indexMediaTypes.contains(descriptor.mediaType) else { return [descriptor] }
        let value = try decoder.decode(OCIIndex.self, from: layoutData(for: descriptor, directory: directory))
        return try value.manifests.flatMap { try layoutLeafDescriptors(in: $0, directory: directory) }
    }

    private func layoutPlatform(for descriptor: OCIDescriptor, directory: URL) throws -> OCIPlatform? {
        if let platform = descriptor.platform { return platform }
        guard Self.manifestMediaTypes.contains(descriptor.mediaType) else { return nil }
        let manifest = try decoder.decode(OCIManifest.self, from: layoutData(for: descriptor, directory: directory))
        let config = try decoder.decode(OCIImageConfiguration.self, from: layoutData(for: manifest.config, directory: directory))
        return OCIPlatform(
            architecture: config.architecture,
            os: config.os,
            variant: config.variant,
            osVersion: config.osVersion
        )
    }

    private func isLayoutAttestation(_ descriptor: OCIDescriptor, directory: URL) throws -> Bool {
        if isAttestationDescriptor(descriptor) { return true }
        guard Self.manifestMediaTypes.contains(descriptor.mediaType) else { return false }
        let manifest = try decoder.decode(OCIManifest.self, from: layoutData(for: descriptor, directory: directory))
        return manifest.artifactType == Self.attestationManifestArtifactType && manifest.subject != nil
    }

    private func layoutAttestationTarget(for descriptor: OCIDescriptor, directory: URL) throws -> String? {
        if let annotated = attestationTarget(for: descriptor) { return annotated }
        guard Self.manifestMediaTypes.contains(descriptor.mediaType) else { return nil }
        let manifest = try decoder.decode(OCIManifest.self, from: layoutData(for: descriptor, directory: directory))
        guard manifest.artifactType == Self.attestationManifestArtifactType else { return nil }
        return manifest.subject?.digest
    }

    private func readLayoutFile(
        directory: URL,
        relativePath: String,
        maximumBytes: UInt64
    ) throws -> Data {
        let components = relativePath.split(
            separator: "/", omittingEmptySubsequences: false
        )
        guard !components.isEmpty,
              components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw EngineError(.badRequest, "OCI layout path is unsafe")
        }
        var descriptor = Darwin.open(
            directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )
        guard descriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        defer { Darwin.close(descriptor) }
        for component in components.dropLast() {
            let next = Darwin.openat(
                descriptor,
                String(component),
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
            )
            guard next >= 0 else {
                throw EngineError(.badRequest, "OCI layout directory is unsafe")
            }
            Darwin.close(descriptor)
            descriptor = next
        }
        let fileDescriptor = Darwin.openat(
            descriptor,
            String(components.last!),
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
        )
        guard fileDescriptor >= 0 else {
            throw EngineError(.badRequest, "OCI layout file is unavailable or unsafe")
        }
        let input = FileHandle(
            fileDescriptor: fileDescriptor, closeOnDealloc: true
        )
        defer { try? input.close() }
        var information = stat()
        guard Darwin.fstat(fileDescriptor, &information) == 0,
              information.st_mode & S_IFMT == S_IFREG,
              information.st_size >= 0,
              let size = UInt64(exactly: information.st_size),
              size <= maximumBytes,
              let capacity = Int(exactly: size) else {
            throw EngineError(.badRequest, "OCI layout file exceeds its size limit")
        }
        var result = Data()
        result.reserveCapacity(capacity)
        while result.count < capacity {
            guard let chunk = try input.read(
                upToCount: min(1 * 1_024 * 1_024, capacity - result.count)
            ), !chunk.isEmpty else {
                throw EngineError(.badRequest, "OCI layout file is truncated")
            }
            result.append(chunk)
        }
        guard try input.read(upToCount: 1)?.isEmpty != false else {
            throw EngineError(.badRequest, "OCI layout file grew beyond its size limit")
        }
        return result
    }

    public func prune() throws -> [String] {
        var descriptors: [String: OCIDescriptor] = [:]
        for descriptor in index.references.values { descriptors[descriptor.digest] = descriptor }
        var reachable = Set(descriptors.keys)
        var pending = Array(reachable)
        while let digest = pending.popLast() {
            guard let descriptor = descriptors[digest],
                  let contents = try? data(for: digest) else { continue }
            let children: [OCIDescriptor]
            if Self.indexMediaTypes.contains(descriptor.mediaType),
               let value = try? decoder.decode(OCIIndex.self, from: contents) {
                children = value.manifests
            } else if Self.manifestMediaTypes.contains(descriptor.mediaType),
                      let value = try? decoder.decode(OCIManifest.self, from: contents) {
                children = [value.config] + value.layers
            } else {
                children = []
            }
            for child in children where reachable.insert(child.digest).inserted {
                descriptors[child.digest] = child
                pending.append(child.digest)
            }
        }
        var removed: [String] = []
        for file in try FileManager.default.contentsOfDirectory(at: blobRoot, includingPropertiesForKeys: nil) {
            let digest = "sha256:\(file.lastPathComponent)"
            if !reachable.contains(digest) {
                try FileManager.default.removeItem(at: file)
                removed.append(digest)
            }
        }
        return removed.sorted()
    }

    private func saveIndex() throws {
        let data = try encoder.encode(index)
        guard data.count <= transferPolicy.metadataBytes else {
            throw EngineError(.internalError, "OCI reference index exceeds its size limit")
        }
        try atomicWrite(data, to: indexURL)
    }

    private func blobURL(for digest: String) throws -> URL {
        guard digest.hasPrefix("sha256:"), digest.count == 71,
              digest.dropFirst(7).allSatisfy({ $0.isHexDigit }) else {
            throw EngineError(.badRequest, "unsupported OCI digest \(digest)")
        }
        return blobRoot.appending(path: String(digest.dropFirst(7)))
    }

    private static func readRegularFile(
        at url: URL,
        maximumBytes: Int
    ) throws -> Data {
        let descriptor = Darwin.open(
            url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
        )
        guard descriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let input = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? input.close() }
        var information = stat()
        guard Darwin.fstat(descriptor, &information) == 0,
              information.st_mode & S_IFMT == S_IFREG,
              information.st_size >= 0,
              information.st_size <= off_t(maximumBytes),
              let count = Int(exactly: information.st_size) else {
            throw EngineError(.internalError, "persisted OCI metadata exceeds its size limit")
        }
        var result = Data()
        result.reserveCapacity(count)
        while result.count < count {
            guard let chunk = try input.read(
                upToCount: min(64 * 1_024, count - result.count)
            ), !chunk.isEmpty else {
                throw EngineError(.internalError, "persisted OCI metadata is truncated")
            }
            result.append(chunk)
        }
        guard try input.read(upToCount: 1)?.isEmpty != false else {
            throw EngineError(.internalError, "persisted OCI metadata grew during read")
        }
        return result
    }

    private func openBlob(_ digest: String) throws -> FileHandle {
        let url = try blobURL(for: digest)
        let descriptor = Darwin.open(
            url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
        )
        guard descriptor >= 0 else {
            if errno == ENOENT { throw EngineError(.notFound, "OCI content \(digest) not found") }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        var information = stat()
        guard Darwin.fstat(descriptor, &information) == 0,
              information.st_mode & S_IFMT == S_IFREG else {
            Darwin.close(descriptor)
            throw EngineError(.internalError, "OCI content \(digest) is not a regular file")
        }
        return FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    }

    private func regularFileSize(_ handle: FileHandle, digest: String) throws -> UInt64 {
        var information = stat()
        guard Darwin.fstat(handle.fileDescriptor, &information) == 0,
              information.st_mode & S_IFMT == S_IFREG,
              information.st_size >= 0,
              let size = UInt64(exactly: information.st_size) else {
            throw EngineError(.internalError, "OCI content \(digest) has invalid metadata")
        }
        return size
    }

    private func readVerifiedBlob(
        digest: String,
        expectedSize: UInt64?,
        maximumBytes: UInt64,
        errorCode: EngineError.Code
    ) throws -> Data {
        let input = try openBlob(digest)
        defer { try? input.close() }
        let actualSize = try regularFileSize(input, digest: digest)
        guard actualSize <= maximumBytes,
              expectedSize.map({ $0 == actualSize }) ?? true,
              let capacity = Int(exactly: actualSize) else {
            throw EngineError(errorCode, "OCI content \(digest) has the wrong size")
        }
        var result = Data()
        result.reserveCapacity(capacity)
        var hasher = SHA256()
        while let chunk = try input.read(upToCount: 1 * 1_024 * 1_024), !chunk.isEmpty {
            guard chunk.count <= capacity - result.count else {
                throw EngineError(errorCode, "OCI content \(digest) exceeds its size limit")
            }
            hasher.update(data: chunk)
            result.append(chunk)
        }
        guard result.count == capacity, Self.digest(hasher.finalize()) == digest else {
            throw EngineError(errorCode, "OCI content \(digest) failed verification")
        }
        return result
    }

    private func verifyBlob(
        _ descriptor: OCIDescriptor,
        errorCode: EngineError.Code
    ) throws {
        let validated = try descriptor.validated(
            policy: transferPolicy, errorCode: errorCode
        )
        if descriptor.data != nil { return }
        let input = try openBlob(descriptor.digest)
        defer { try? input.close() }
        guard try regularFileSize(input, digest: descriptor.digest) == validated.size else {
            throw EngineError(errorCode, "OCI content \(descriptor.digest) has the wrong size")
        }
        var hasher = SHA256()
        var count: UInt64 = 0
        while let chunk = try input.read(upToCount: 1 * 1_024 * 1_024), !chunk.isEmpty {
            count = try CheckedArithmetic.add(count, UInt64(chunk.count))
            guard count <= validated.size else {
                throw EngineError(errorCode, "OCI content \(descriptor.digest) exceeds its descriptor size")
            }
            hasher.update(data: chunk)
        }
        guard count == validated.size,
              Self.digest(hasher.finalize()) == descriptor.digest else {
            throw EngineError(errorCode, "OCI content \(descriptor.digest) failed verification")
        }
    }

    private func atomicWrite(_ data: Data, to destination: URL) throws {
        let temporary = destination.deletingLastPathComponent().appending(
            path: ".\(destination.lastPathComponent).\(UUID().uuidString).tmp"
        )
        let descriptor = Darwin.open(
            temporary.path,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            mode_t(0o600)
        )
        guard descriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        do {
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
            if FileManager.default.fileExists(atPath: destination.path) {
                _ = try FileManager.default.replaceItemAt(
                    destination,
                    withItemAt: temporary,
                    backupItemName: nil,
                    options: .usingNewMetadataOnly
                )
            } else {
                try FileManager.default.moveItem(at: temporary, to: destination)
            }
        } catch {
            try? handle.close()
            try? FileManager.default.removeItem(at: temporary)
            throw error
        }
    }

    fileprivate static func digest(_ data: Data) -> String {
        digest(SHA256.hash(data: data))
    }

    fileprivate static func digest(_ value: SHA256.Digest) -> String {
        "sha256:" + value.map { String(format: "%02x", $0) }.joined()
    }
}

struct OCIRegistryReference: Sendable {
    let registry: String
    let repository: String
    let selector: String
    let normalized: String
    let insecure: Bool

    init(_ value: String) throws {
        normalized = ImageReference.normalized(value)
        let slash = normalized.firstIndex(of: "/")
        guard let slash else { throw EngineError(.badRequest, "invalid image reference \(value)") }
        registry = String(normalized[..<slash])
        let remainder = String(normalized[normalized.index(after: slash)...])
        if let at = remainder.lastIndex(of: "@") {
            let named = String(remainder[..<at])
            if let colon = named.lastIndex(of: ":"),
               !named[named.index(after: colon)...].contains("/") {
                repository = String(named[..<colon])
            } else {
                repository = named
            }
            selector = String(remainder[remainder.index(after: at)...])
        } else if let colon = remainder.lastIndex(of: ":"),
                  !remainder[remainder.index(after: colon)...].contains("/") {
            repository = String(remainder[..<colon])
            selector = String(remainder[remainder.index(after: colon)...])
        } else {
            repository = remainder
            selector = "latest"
        }
        guard !repository.isEmpty, !selector.isEmpty else {
            throw EngineError(.badRequest, "invalid image reference \(value)")
        }
        insecure = registry.hasPrefix("localhost:") || registry.hasPrefix("127.0.0.1:")
    }

    var APIHost: String { registry == "docker.io" ? "registry-1.docker.io" : registry }
}

private final class OCIRegistrySessionDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        var redirected = request
        let original = task.currentRequest?.url
        let destination = request.url
        if original?.scheme?.lowercased() != destination?.scheme?.lowercased()
            || original?.host?.lowercased() != destination?.host?.lowercased()
            || original?.port != destination?.port {
            redirected.setValue(nil, forHTTPHeaderField: "Authorization")
        }
        completionHandler(redirected)
    }
}

private actor OCIRegistryClient {
    struct ManifestResponse: Sendable { let data: Data; let mediaType: String; let digest: String? }
    private let reference: OCIRegistryReference
    private let credentials: RegistryCredentials?
    private let session: URLSession
    private let sessionDelegate: OCIRegistrySessionDelegate
    private let policy: OCITransferPolicy
    private var authorization: String?

    init(
        reference: OCIRegistryReference,
        credentials: RegistryCredentials?,
        policy: OCITransferPolicy
    ) {
        self.reference = reference
        self.credentials = credentials
        self.policy = policy
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 120
        configuration.timeoutIntervalForResource = 600
        configuration.httpShouldSetCookies = false
        let sessionDelegate = OCIRegistrySessionDelegate()
        self.sessionDelegate = sessionDelegate
        session = URLSession(
            configuration: configuration,
            delegate: sessionDelegate,
            delegateQueue: nil
        )
    }

    func fetchManifest(_ selector: String) async throws -> ManifestResponse {
        var request = URLRequest(url: try url("manifests/\(selector)"))
        request.setValue(
            (OCIContentStore.manifestMediaTypes + OCIContentStore.indexMediaTypes).joined(separator: ", "),
            forHTTPHeaderField: "Accept"
        )
        let (data, response) = try await perform(
            request, maximumBytes: policy.metadataBytes
        )
        let mediaType = response.value(forHTTPHeaderField: "Content-Type")?.split(separator: ";").first.map(String.init)
            ?? "application/vnd.oci.image.manifest.v1+json"
        return .init(data: data, mediaType: mediaType, digest: response.value(forHTTPHeaderField: "Docker-Content-Digest"))
    }

    func fetchBlob(
        _ descriptor: OCIDescriptor,
        to destination: URL
    ) async throws {
        let validated = try descriptor.validated(policy: policy, errorCode: .upstream)
        let request = URLRequest(url: try url("blobs/\(descriptor.digest)"))
        let (bytes, response) = try await responseBytes(request)
        guard (200..<300).contains(response.statusCode) else {
            let body = try await readBounded(bytes, maximumBytes: policy.errorBodyBytes)
            throw registryHTTPError(response, body: body)
        }
        try validateContentLength(
            response, maximumBytes: validated.size, expectedBytes: validated.size
        )
        let descriptorFD = Darwin.open(
            destination.path,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            mode_t(0o600)
        )
        guard descriptorFD >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let output = FileHandle(fileDescriptor: descriptorFD, closeOnDealloc: true)
        do {
            var buffer = Data()
            buffer.reserveCapacity(64 * 1_024)
            var count: UInt64 = 0
            var hasher = SHA256()
            for try await byte in bytes {
                count = try CheckedArithmetic.add(count, 1)
                guard count <= validated.size else {
                    throw EngineError(.upstream, "registry blob exceeds descriptor size")
                }
                buffer.append(byte)
                if buffer.count == 64 * 1_024 {
                    hasher.update(data: buffer)
                    try output.write(contentsOf: buffer)
                    buffer.removeAll(keepingCapacity: true)
                }
            }
            if !buffer.isEmpty {
                hasher.update(data: buffer)
                try output.write(contentsOf: buffer)
            }
            guard count == validated.size,
                  OCIContentStore.digest(hasher.finalize()) == descriptor.digest else {
                throw EngineError(.upstream, "registry blob failed descriptor size or digest verification")
            }
            try output.synchronize()
            try output.close()
        } catch {
            try? output.close()
            try? FileManager.default.removeItem(at: destination)
            throw error
        }
    }

    func blobExists(_ digest: String) async throws -> Bool {
        var request = URLRequest(url: try url("blobs/\(digest)")); request.httpMethod = "HEAD"
        do { _ = try await perform(request); return true }
        catch let error as EngineError where error.message.contains("HTTP 404") { return false }
    }

    func pushBlob(
        file: URL,
        descriptor: OCIDescriptor
    ) async throws {
        let validated = try descriptor.validated(
            policy: policy, errorCode: .internalError
        )
        var start = URLRequest(url: try url("blobs/uploads/"))
        start.httpMethod = "POST"
        let (_, response) = try await perform(start)
        guard let location = response.value(forHTTPHeaderField: "Location"),
              let locationURL = URL(string: location, relativeTo: response.url),
              var components = URLComponents(
                url: locationURL, resolvingAgainstBaseURL: true
              ) else {
            throw EngineError(.upstream, "registry blob upload has no location")
        }
        var items = components.queryItems ?? []
        items.append(.init(name: "digest", value: descriptor.digest))
        components.queryItems = items
        guard let destination = components.url else {
            throw EngineError(.upstream, "invalid registry upload location")
        }
        var upload = URLRequest(url: destination)
        upload.httpMethod = "PUT"
        upload.httpBodyStream = InputStream(url: file)
        upload.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        upload.setValue(String(validated.size), forHTTPHeaderField: "Content-Length")
        _ = try await perform(upload)
    }

    func pushManifest(_ data: Data, mediaType: String, selector: String) async throws {
        var request = URLRequest(url: try url("manifests/\(selector)")); request.httpMethod = "PUT"; request.httpBody = data
        request.setValue(mediaType, forHTTPHeaderField: "Content-Type")
        _ = try await perform(request)
    }

    private func perform(
        _ original: URLRequest,
        maximumBytes: Int? = nil
    ) async throws -> (Data, HTTPURLResponse) {
        let limit = maximumBytes ?? policy.errorBodyBytes
        let (bytes, response) = try await responseBytes(original)
        try validateContentLength(
            response, maximumBytes: UInt64(limit), expectedBytes: nil
        )
        let data = try await readBounded(bytes, maximumBytes: limit)
        guard (200..<300).contains(response.statusCode) else {
            throw registryHTTPError(response, body: data)
        }
        return (data, response)
    }

    private func responseBytes(
        _ original: URLRequest
    ) async throws -> (URLSession.AsyncBytes, HTTPURLResponse) {
        var request = original
        if let authorization {
            request.setValue(authorization, forHTTPHeaderField: "Authorization")
        } else if let identityAuthorization {
            request.setValue(identityAuthorization, forHTTPHeaderField: "Authorization")
        } else if let basic = basicAuthorization {
            request.setValue(basic, forHTTPHeaderField: "Authorization")
        }
        var (bytes, response) = try await session.bytes(for: request)
        guard var http = response as? HTTPURLResponse else {
            throw EngineError(.upstream, "registry returned a non-HTTP response")
        }
        if http.statusCode == 401,
           let challenge = http.value(forHTTPHeaderField: "WWW-Authenticate") {
            _ = try await readBounded(bytes, maximumBytes: policy.errorBodyBytes)
            authorization = try await bearerAuthorization(challenge)
            request.setValue(authorization, forHTTPHeaderField: "Authorization")
            (bytes, response) = try await session.bytes(for: request)
            guard let retried = response as? HTTPURLResponse else {
                throw EngineError(.upstream, "registry returned a non-HTTP response")
            }
            http = retried
        }
        return (bytes, http)
    }

    private func readBounded(
        _ bytes: URLSession.AsyncBytes,
        maximumBytes: Int
    ) async throws -> Data {
        var data = Data()
        data.reserveCapacity(min(maximumBytes, 64 * 1_024))
        for try await byte in bytes {
            guard data.count < maximumBytes else {
                throw EngineError(.upstream, "registry response exceeds its size limit")
            }
            data.append(byte)
        }
        return data
    }

    private func validateContentLength(
        _ response: HTTPURLResponse,
        maximumBytes: UInt64,
        expectedBytes: UInt64?
    ) throws {
        guard let raw = response.value(forHTTPHeaderField: "Content-Length") else { return }
        guard !raw.isEmpty,
              raw.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
              let length = UInt64(raw),
              length <= maximumBytes,
              expectedBytes.map({ $0 == length }) ?? true else {
            throw EngineError(.upstream, "registry returned an invalid Content-Length")
        }
    }

    private func registryHTTPError(
        _ response: HTTPURLResponse,
        body: Data
    ) -> EngineError {
        let fallback = HTTPURLResponse.localizedString(forStatusCode: response.statusCode)
        let message = String(data: body, encoding: .utf8) ?? fallback
        return EngineError(
            .upstream,
            "registry request failed (HTTP \(response.statusCode)): \(message)"
        )
    }

    private func bearerAuthorization(_ challenge: String) async throws -> String {
        guard challenge.lowercased().hasPrefix("bearer ") else {
            throw EngineError(.internalError, "unsupported registry authentication challenge")
        }
		let parameters = Self.authenticationParameters(String(challenge.dropFirst(7)))
        guard let realm = parameters["realm"], var components = URLComponents(string: realm) else {
            throw EngineError(.internalError, "registry bearer challenge has no realm")
        }
        var items = components.queryItems ?? []
        if let service = parameters["service"] { items.append(.init(name: "service", value: service)) }
        items.append(.init(name: "scope", value: parameters["scope"] ?? "repository:\(reference.repository):pull,push"))
        components.queryItems = items
        guard let tokenURL = components.url else { throw EngineError(.internalError, "invalid registry token URL") }
        var request = URLRequest(url: tokenURL)
        let registryHost = reference.APIHost.split(separator: ":").first.map(String.init)?
            .lowercased()
        let tokenHost = tokenURL.host?.lowercased()
        let expectedScheme = reference.insecure ? "http" : "https"
        let trustedCredentialHost = tokenURL.scheme?.lowercased() == expectedScheme
            && (tokenHost == registryHost
                || (reference.registry == "docker.io"
                    && tokenHost == "auth.docker.io"))
        if trustedCredentialHost, let basic = basicAuthorization {
            request.setValue(basic, forHTTPHeaderField: "Authorization")
        }
        let (bytes, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw EngineError(.upstream, "registry token returned a non-HTTP response")
        }
        try validateContentLength(
            http, maximumBytes: UInt64(policy.tokenBytes), expectedBytes: nil
        )
        let data = try await readBounded(bytes, maximumBytes: policy.tokenBytes)
        guard (200..<300).contains(http.statusCode) else {
            throw registryHTTPError(http, body: data)
        }
        struct Token: Decodable { let token: String?; let access_token: String? }
        let decoded = try JSONDecoder().decode(Token.self, from: data)
        guard let token = decoded.token ?? decoded.access_token, !token.isEmpty else {
            throw EngineError(.internalError, "registry token response is empty")
        }
        return "Bearer \(token)"
    }

    private var basicAuthorization: String? {
        guard let credentials, !credentials.username.isEmpty || !credentials.password.isEmpty else { return nil }
        return "Basic " + Data("\(credentials.username):\(credentials.password)".utf8).base64EncodedString()
    }

    private var identityAuthorization: String? {
        guard let credentials, !credentials.identityToken.isEmpty else { return nil }
        return "Bearer \(credentials.identityToken)"
    }

    private func url(_ suffix: String) throws -> URL {
        var components = URLComponents()
        components.scheme = reference.insecure ? "http" : "https"
        components.host = reference.APIHost.split(separator: ":").first.map(String.init)
        components.port = reference.APIHost.split(separator: ":").dropFirst().first.flatMap { Int($0) }
        components.path = "/v2/\(reference.repository)/\(suffix)"
        guard let value = components.url else { throw EngineError(.badRequest, "invalid registry URL") }
        return value
    }

	private static func authenticationParameters(_ value: String) -> [String: String] {
		var result: [String: String] = [:]; var start = value.startIndex; var quoted = false; var escaped = false
		func consume(_ end: String.Index) {
			let component = value[start..<end]; let pair = component.split(separator: "=", maxSplits: 1)
			if pair.count == 2 { result[String(pair[0]).trimmingCharacters(in: .whitespaces)] = String(pair[1]).trimmingCharacters(in: CharacterSet(charactersIn: " \"")) }
		}
		var index = value.startIndex
		while index < value.endIndex {
			let character = value[index]
			if escaped { escaped = false }
			else if character == "\\" && quoted { escaped = true }
			else if character == "\"" { quoted.toggle() }
			else if character == "," && !quoted { consume(index); start = value.index(after: index) }
			index = value.index(after: index)
		}
		consume(value.endIndex); return result
	}
}

import CEngineCore
import CryptoKit
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
        public var user: String?
        public var exposedPorts: [String: [String: String]]?
        public var environment: [String]?
        public var entrypoint: [String]?
        public var command: [String]?
        public var volumes: [String: [String: String]]?
        public var workingDirectory: String?
        public var labels: [String: String]?
        public var stopSignal: String?

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

    private let root: URL
    private let blobRoot: URL
    private let indexURL: URL
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder
    private var index: ReferenceIndex

    public init(root: URL) throws {
        self.root = root
        blobRoot = root.appending(path: "blobs/sha256", directoryHint: .isDirectory)
        indexURL = root.appending(path: "references.json")
        encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        decoder = JSONDecoder()
        try FileManager.default.createDirectory(at: blobRoot, withIntermediateDirectories: true)
        if FileManager.default.fileExists(atPath: indexURL.path) {
            index = try decoder.decode(ReferenceIndex.self, from: Data(contentsOf: indexURL))
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
        guard let url = try? blobURL(for: digest) else { return false }
        return FileManager.default.fileExists(atPath: url.path)
    }

    @discardableResult public func put(
        _ data: Data,
        mediaType: String,
        expectedDigest: String? = nil
    ) throws -> OCIDescriptor {
        let digest = Self.digest(data)
        if let expectedDigest, expectedDigest != digest {
            throw EngineError(.badRequest, "content digest mismatch: expected \(expectedDigest), received \(digest)")
        }
        let destination = try blobURL(for: digest)
        if !FileManager.default.fileExists(atPath: destination.path) {
            try atomicWrite(data, to: destination)
        }
        return OCIDescriptor(mediaType: mediaType, digest: digest, size: Int64(data.count))
    }

    public func data(for digest: String) throws -> Data {
        let url = try blobURL(for: digest)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw EngineError(.notFound, "OCI content \(digest) not found")
        }
        let data = try Data(contentsOf: url)
        guard Self.digest(data) == digest else {
            throw EngineError(.internalError, "OCI content \(digest) failed verification")
        }
        return data
    }

    private func data(for descriptor: OCIDescriptor) throws -> Data {
        if let embedded = descriptor.data {
            guard Self.digest(embedded) == descriptor.digest else {
                throw EngineError(.badRequest, "embedded OCI content \(descriptor.digest) failed verification")
            }
            return embedded
        }
        return try data(for: descriptor.digest)
    }

    public func tag(_ descriptor: OCIDescriptor, as reference: String) throws {
        guard contains(descriptor.digest) else {
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
        let manifest = try decoder.decode(OCIManifest.self, from: data(for: manifestDescriptor.digest))
        let configuration = try decoder.decode(OCIImageConfiguration.self, from: data(for: manifest.config.digest))
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
        let client = OCIRegistryClient(reference: parsed, credentials: credentials)
        let rootResponse = try await client.fetchManifest(parsed.selector)
        let rootDescriptor = try put(
            rootResponse.data,
            mediaType: rootResponse.mediaType,
            expectedDigest: rootResponse.digest
        )
        try await downloadIndexNodes(rootDescriptor, contents: rootResponse.data, client: client)
        let requested = try OCIPlatform(platform)
        let leaves = try leafDescriptors(in: rootDescriptor)
        guard let selected = leaves.first(where: {
            !isAttestationDescriptor($0) && $0.platform?.matches(requested) == true
        }) ?? (leaves.count == 1 && !Self.indexMediaTypes.contains(rootDescriptor.mediaType) ? leaves[0] : nil) else {
            throw EngineError(.notFound, "image \(parsed.normalized) has no \(platform) manifest")
        }
        let selectedManifest = try await downloadManifestGraph(selected, client: client)
        let configurationData = try data(for: selectedManifest.config.digest)
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
            _ = try await downloadManifestGraph(descriptor, client: client)
        }
        let descriptors = [selectedManifest.config] + selectedManifest.layers
        var completedBytes: Int64 = 0
        let totalBytes = descriptors.reduce(Int64(0)) { $0 + max($1.size, 0) }
        for (index, descriptor) in descriptors.enumerated() {
            completedBytes += max(descriptor.size, 0)
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
        let client = OCIRegistryClient(reference: parsed, credentials: credentials)
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
        let indexData = try Data(contentsOf: directory.appending(path: "index.json"))
        let layoutIndex = try decoder.decode(OCIIndex.self, from: indexData)
        let archiveURL = directory.appending(path: "manifest.json")
        let archiveEntries = (try? decoder.decode(
            [DockerArchiveEntry].self,
            from: Data(contentsOf: archiveURL)
        )) ?? []
        var references = Set<String>()
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
                try tag(descriptor, as: reference)
                references.insert(ImageReference.normalized(reference))
            }
        }
        let all = try summaries()
        return all.filter { references.contains($0.reference) }
    }

    public func exportLayout(references requested: [String], platforms: [OCIPlatform] = []) throws -> Data {
        let names = requested.isEmpty ? references() : requested.map(ImageReference.normalized)
        var roots: [OCIDescriptor] = []
        var digests = Set<String>()
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
                digests.insert(descriptor.digest)
                for record in selectedRecords {
                    try collect(record.descriptor, selectedLeaves: [record.descriptor.digest], into: &digests)
                }
            } else {
                descriptor = rootDescriptor
                try collect(descriptor, selectedLeaves: selectedLeaves, into: &digests)
            }
            var annotatedDescriptor = descriptor
            var annotations = annotatedDescriptor.annotations ?? [:]
            annotations["org.opencontainers.image.ref.name"] = name
            annotations["io.containerd.image.name"] = name
            annotatedDescriptor.annotations = annotations
            roots.append(annotatedDescriptor)
            archiveEntries.append(contentsOf: try selectedImages.map { record in
                let manifest = try decoder.decode(OCIManifest.self, from: data(for: record.descriptor.digest))
                return DockerArchiveEntry(
                    config: "blobs/sha256/\(manifest.config.digest.dropFirst(7))",
                    repoTags: [name],
                    layers: manifest.layers.map { "blobs/sha256/\($0.digest.dropFirst(7))" }
                )
            })
        }
        let layout = try encoder.encode(["imageLayoutVersion": "1.0.0"])
        let layoutIndex = try encoder.encode(OCIIndex(schemaVersion: 2, mediaType: "application/vnd.oci.image.index.v1+json", manifests: roots, annotations: nil))
        var entries: [(String, Data)] = [
            ("oci-layout", layout),
            ("index.json", layoutIndex),
            ("manifest.json", try encoder.encode(archiveEntries)),
        ]
        for digest in digests.sorted() {
            entries.append((
                "blobs/sha256/" + String(digest.dropFirst(7)),
                try generatedBlobs[digest] ?? data(for: digest)
            ))
        }
        return OCIArchive.tar(entries: entries)
    }

    private func importDescriptor(
        _ descriptor: OCIDescriptor,
        selectedLeaves: Set<String>,
        from directory: URL,
        seen: inout Set<String>
    ) throws {
        guard seen.insert(descriptor.digest).inserted else { return }
        if !Self.indexMediaTypes.contains(descriptor.mediaType), !selectedLeaves.contains(descriptor.digest) { return }
        let source = directory.appending(path: "blobs/sha256/" + String(descriptor.digest.dropFirst(7)))
        let contents = try Data(contentsOf: source)
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

    private func collect(_ descriptor: OCIDescriptor, selectedLeaves: Set<String>, into digests: inout Set<String>) throws {
        guard digests.insert(descriptor.digest).inserted else { return }
        let contents = try data(for: descriptor.digest)
        if Self.indexMediaTypes.contains(descriptor.mediaType) {
            for child in try decoder.decode(OCIIndex.self, from: contents).manifests {
                if Self.indexMediaTypes.contains(child.mediaType) || selectedLeaves.contains(child.digest) {
                    try collect(child, selectedLeaves: selectedLeaves, into: &digests)
                }
            }
        } else if Self.manifestMediaTypes.contains(descriptor.mediaType) {
            let manifest = try decoder.decode(OCIManifest.self, from: contents)
            for child in [manifest.config] + manifest.layers {
                guard contains(child.digest) else { continue }
                try collect(child, selectedLeaves: [child.digest], into: &digests)
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
        guard Self.indexMediaTypes.contains(descriptor.mediaType) else { return [descriptor] }
        guard contains(descriptor.digest) else { return [] }
        let value = try decoder.decode(OCIIndex.self, from: data(for: descriptor.digest))
        return try value.manifests.flatMap { child in
            Self.indexMediaTypes.contains(child.mediaType) ? try leafDescriptors(in: child) : [child]
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
        guard contains(descriptor.digest), Self.manifestMediaTypes.contains(descriptor.mediaType) else {
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
                contentSize: contains(descriptor.digest) ? max(descriptor.size, 0) : 0,
                attestationFor: annotatedTarget
            )
        }
        let manifest = try decoder.decode(OCIManifest.self, from: data(for: descriptor.digest))
        let target = annotatedTarget ?? manifest.subject?.digest
        let isAttestation = target != nil && (
            isAttestationDescriptor(descriptor) || manifest.artifactType == Self.attestationManifestArtifactType
        )
        let children = [manifest.config] + manifest.layers
        let available = children.allSatisfy { contains($0.digest) }
        let contentSize = max(descriptor.size, 0) + children.reduce(Int64(0)) {
            $0 + (contains($1.digest) ? max($1.size, 0) : 0)
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
        guard contains(manifest.config.digest),
              let configuration = try? decoder.decode(OCIImageConfiguration.self, from: data(for: manifest.config.digest)),
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
        client: OCIRegistryClient
    ) async throws {
        guard Self.indexMediaTypes.contains(descriptor.mediaType) else { return }
        let valueData: Data
        if let contents {
            valueData = contents
        } else if contains(descriptor.digest) {
            valueData = try data(for: descriptor.digest)
        } else {
            let response = try await client.fetchManifest(descriptor.digest)
            _ = try put(response.data, mediaType: response.mediaType, expectedDigest: descriptor.digest)
            valueData = response.data
        }
        let value = try decoder.decode(OCIIndex.self, from: valueData)
        for child in value.manifests where Self.indexMediaTypes.contains(child.mediaType) {
            try await downloadIndexNodes(child, client: client)
        }
    }

    private func downloadManifestGraph(_ descriptor: OCIDescriptor, client: OCIRegistryClient) async throws -> OCIManifest {
        let contents: Data
        if contains(descriptor.digest) {
            contents = try data(for: descriptor.digest)
        } else {
            let response = try await client.fetchManifest(descriptor.digest)
            _ = try put(response.data, mediaType: response.mediaType, expectedDigest: descriptor.digest)
            contents = response.data
        }
        let manifest = try decoder.decode(OCIManifest.self, from: contents)
        for child in [manifest.config] + manifest.layers where !contains(child.digest) {
            let blob = try await client.fetchBlob(child.digest)
            _ = try put(blob, mediaType: child.mediaType, expectedDigest: child.digest)
        }
        return manifest
    }

    private func pushManifestGraph(_ descriptor: OCIDescriptor, client: OCIRegistryClient) async throws {
        let manifest = try decoder.decode(OCIManifest.self, from: data(for: descriptor.digest))
        for child in [manifest.config] + manifest.layers {
            if try await client.blobExists(child.digest) == false {
                try await client.pushBlob(data(for: child.digest), digest: child.digest)
            }
        }
        try await client.pushManifest(data(for: descriptor.digest), mediaType: descriptor.mediaType, selector: descriptor.digest)
    }

    private func layoutData(for descriptor: OCIDescriptor, directory: URL) throws -> Data {
        if let embedded = descriptor.data {
            guard Self.digest(embedded) == descriptor.digest else {
                throw EngineError(.badRequest, "embedded OCI content \(descriptor.digest) failed verification")
            }
            return embedded
        }
        let source = directory.appending(path: "blobs/sha256/" + String(descriptor.digest.dropFirst(7)))
        let contents = try Data(contentsOf: source)
        guard Self.digest(contents) == descriptor.digest else {
            throw EngineError(.badRequest, "OCI archive content \(descriptor.digest) failed verification")
        }
        return contents
    }

    private func layoutContains(_ descriptor: OCIDescriptor, directory: URL) -> Bool {
        if descriptor.data != nil { return true }
        return FileManager.default.fileExists(atPath: directory.appending(
            path: "blobs/sha256/" + String(descriptor.digest.dropFirst(7))
        ).path)
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

    private func saveIndex() throws { try atomicWrite(encoder.encode(index), to: indexURL) }

    private func blobURL(for digest: String) throws -> URL {
        guard digest.hasPrefix("sha256:"), digest.count == 71,
              digest.dropFirst(7).allSatisfy({ $0.isHexDigit }) else {
            throw EngineError(.badRequest, "unsupported OCI digest \(digest)")
        }
        return blobRoot.appending(path: String(digest.dropFirst(7)))
    }

    private func atomicWrite(_ data: Data, to destination: URL) throws {
        let temporary = destination.deletingLastPathComponent().appending(path: ".\(destination.lastPathComponent).\(UUID().uuidString).tmp")
        try data.write(to: temporary, options: .withoutOverwriting)
        let handle = try FileHandle(forWritingTo: temporary)
        try handle.synchronize()
        try handle.close()
        do {
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
        }
        catch {
            try? FileManager.default.removeItem(at: temporary)
            throw error
        }
    }

    private static func digest(_ data: Data) -> String {
        "sha256:" + SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
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

private actor OCIRegistryClient {
    struct ManifestResponse: Sendable { let data: Data; let mediaType: String; let digest: String? }
    private let reference: OCIRegistryReference
    private let credentials: RegistryCredentials?
    private let session: URLSession
    private var authorization: String?

    init(reference: OCIRegistryReference, credentials: RegistryCredentials?) {
        self.reference = reference
        self.credentials = credentials
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 120
        configuration.timeoutIntervalForResource = 600
        session = URLSession(configuration: configuration)
    }

    func fetchManifest(_ selector: String) async throws -> ManifestResponse {
        var request = URLRequest(url: try url("manifests/\(selector)"))
        request.setValue(
            (OCIContentStore.manifestMediaTypes + OCIContentStore.indexMediaTypes).joined(separator: ", "),
            forHTTPHeaderField: "Accept"
        )
        let (data, response) = try await perform(request)
        let mediaType = response.value(forHTTPHeaderField: "Content-Type")?.split(separator: ";").first.map(String.init)
            ?? "application/vnd.oci.image.manifest.v1+json"
        return .init(data: data, mediaType: mediaType, digest: response.value(forHTTPHeaderField: "Docker-Content-Digest"))
    }

    func fetchBlob(_ digest: String) async throws -> Data {
        let (data, _) = try await perform(URLRequest(url: try url("blobs/\(digest)")))
        return data
    }

    func blobExists(_ digest: String) async throws -> Bool {
        var request = URLRequest(url: try url("blobs/\(digest)")); request.httpMethod = "HEAD"
        do { _ = try await perform(request); return true }
        catch let error as EngineError where error.message.contains("HTTP 404") { return false }
    }

    func pushBlob(_ data: Data, digest: String) async throws {
        var start = URLRequest(url: try url("blobs/uploads/")); start.httpMethod = "POST"
        let (_, response) = try await perform(start)
        guard let location = response.value(forHTTPHeaderField: "Location"),
              let locationURL = URL(string: location, relativeTo: response.url),
              var components = URLComponents(url: locationURL, resolvingAgainstBaseURL: true) else {
            throw EngineError(.internalError, "registry blob upload has no location")
        }
        var items = components.queryItems ?? []; items.append(.init(name: "digest", value: digest)); components.queryItems = items
        guard let destination = components.url else { throw EngineError(.internalError, "invalid registry upload location") }
        var upload = URLRequest(url: destination); upload.httpMethod = "PUT"; upload.httpBody = data
        upload.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        _ = try await perform(upload)
    }

    func pushManifest(_ data: Data, mediaType: String, selector: String) async throws {
        var request = URLRequest(url: try url("manifests/\(selector)")); request.httpMethod = "PUT"; request.httpBody = data
        request.setValue(mediaType, forHTTPHeaderField: "Content-Type")
        _ = try await perform(request)
    }

    private func perform(_ original: URLRequest) async throws -> (Data, HTTPURLResponse) {
        var request = original
        if let authorization { request.setValue(authorization, forHTTPHeaderField: "Authorization") }
        else if let identityAuthorization { request.setValue(identityAuthorization, forHTTPHeaderField: "Authorization") }
        else if let basic = basicAuthorization { request.setValue(basic, forHTTPHeaderField: "Authorization") }
        var (data, response) = try await session.data(for: request)
        guard var http = response as? HTTPURLResponse else {
            throw EngineError(.internalError, "registry returned a non-HTTP response")
        }
        if http.statusCode == 401, let challenge = http.value(forHTTPHeaderField: "WWW-Authenticate") {
            authorization = try await bearerAuthorization(challenge)
            request.setValue(authorization, forHTTPHeaderField: "Authorization")
            (data, response) = try await session.data(for: request)
            guard let retried = response as? HTTPURLResponse else {
                throw EngineError(.internalError, "registry returned a non-HTTP response")
            }
            http = retried
        }
        guard (200..<300).contains(http.statusCode) else {
            let message = String(data: data, encoding: .utf8) ?? HTTPURLResponse.localizedString(forStatusCode: http.statusCode)
            throw EngineError(.internalError, "registry request failed (HTTP \(http.statusCode)): \(message)")
        }
        return (data, http)
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
        if let basic = basicAuthorization { request.setValue(basic, forHTTPHeaderField: "Authorization") }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw EngineError(.internalError, "registry token request failed")
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

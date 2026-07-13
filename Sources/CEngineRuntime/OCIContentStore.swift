import CEngineCore
import CryptoKit
import Foundation

public struct OCIDescriptor: Codable, Hashable, Sendable {
    public var mediaType: String
    public var digest: String
    public var size: Int64
    public var platform: OCIPlatform?
    public var annotations: [String: String]?

    public init(
        mediaType: String,
        digest: String,
        size: Int64,
        platform: OCIPlatform? = nil,
        annotations: [String: String]? = nil
    ) {
        self.mediaType = mediaType
        self.digest = digest
        self.size = size
        self.platform = platform
        self.annotations = annotations
    }
}

public struct OCIPlatform: Codable, Hashable, Sendable {
    public var architecture: String
    public var os: String
    public var variant: String?

    public init(architecture: String, os: String, variant: String? = nil) {
        self.architecture = architecture
        self.os = os
        self.variant = variant
    }

    public init(_ value: String) throws {
        let components = value.split(separator: "/").map(String.init)
        guard components.count == 2 || components.count == 3 else {
            throw EngineError(.badRequest, "invalid OCI platform \(value)")
        }
        os = components[0]
        architecture = components[1]
        variant = components.count == 3 ? components[2] : nil
    }

    func matches(_ other: OCIPlatform) -> Bool {
        os == other.os && architecture == other.architecture &&
            (other.variant == nil || variant == other.variant)
    }
}

public struct OCIManifest: Codable, Sendable {
    public var schemaVersion: Int
    public var mediaType: String?
    public var config: OCIDescriptor
    public var layers: [OCIDescriptor]
    public var annotations: [String: String]?
}

public struct OCIIndex: Codable, Sendable {
    public var schemaVersion: Int
    public var mediaType: String?
    public var manifests: [OCIDescriptor]
    public var annotations: [String: String]?
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
    public var created: String?
    public var config: Configuration?
    public var rootfs: RootFS
    public var history: [History]?
}

public struct OCIStoredImage: Sendable {
    public let reference: String
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

    private struct ReferenceIndex: Codable {
        var references: [String: OCIDescriptor] = [:]
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
            let manifestDescriptor: OCIDescriptor
            if Self.indexMediaTypes.contains(rootDescriptor.mediaType) {
                let imageIndex = try decoder.decode(OCIIndex.self, from: data(for: rootDescriptor.digest))
                guard let available = imageIndex.manifests.first(where: { contains($0.digest) }) else { continue }
                manifestDescriptor = available
            } else { manifestDescriptor = rootDescriptor }
            let manifest = try decoder.decode(OCIManifest.self, from: data(for: manifestDescriptor.digest))
            let configuration = try decoder.decode(OCIImageConfiguration.self, from: data(for: manifest.config.digest))
            let size = ([manifest.config] + manifest.layers).reduce(Int64(0)) { $0 + max($1.size, 0) }
            let created = configuration.created.flatMap { ISO8601DateFormatter().date(from: $0) } ?? Date(timeIntervalSince1970: 0)
            values.append(.init(id: manifestDescriptor.digest, reference: reference, createdAt: created, size: size, architecture: configuration.architecture, os: configuration.os))
        }
        return values
    }

    public func descriptor(for reference: String) -> OCIDescriptor? {
        index.references[ImageReference.normalized(reference)]
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

    public func tag(_ descriptor: OCIDescriptor, as reference: String) throws {
        guard contains(descriptor.digest) else {
            throw EngineError(.notFound, "OCI content \(descriptor.digest) not found")
        }
        index.references[ImageReference.normalized(reference)] = descriptor
        try saveIndex()
    }

    public func remove(reference: String) throws {
        let normalized = ImageReference.normalized(reference)
        var removed = index.references.removeValue(forKey: normalized) != nil
        if !removed && reference.hasPrefix("sha256:") {
            let previousCount = index.references.count
            index.references = index.references.filter { $0.value.digest != reference }
            removed = index.references.count != previousCount
        }
        guard removed else {
            throw EngineError(.notFound, "image \(reference) not found")
        }
        try saveIndex()
    }

    public func image(reference: String, platform: String) throws -> OCIStoredImage {
        let normalized = ImageReference.normalized(reference)
        guard let rootDescriptor = index.references[normalized] else {
            throw EngineError(.notFound, "image \(normalized) not found")
        }
        let selectedPlatform = try OCIPlatform(platform)
        let manifestDescriptor: OCIDescriptor
        if Self.indexMediaTypes.contains(rootDescriptor.mediaType) {
            let imageIndex = try decoder.decode(OCIIndex.self, from: data(for: rootDescriptor.digest))
            guard let selected = imageIndex.manifests.first(where: { descriptor in
                descriptor.platform.map { $0.matches(selectedPlatform) } ?? false
            }) else {
                throw EngineError(.notFound, "image \(normalized) has no \(platform) manifest")
            }
            manifestDescriptor = selected
        } else {
            manifestDescriptor = rootDescriptor
        }
        let manifest = try decoder.decode(OCIManifest.self, from: data(for: manifestDescriptor.digest))
        let configuration = try decoder.decode(OCIImageConfiguration.self, from: data(for: manifest.config.digest))
        return OCIStoredImage(
            reference: normalized,
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
        let root = try await client.fetchManifest(parsed.selector)
        let rootDescriptor = try put(root.data, mediaType: root.mediaType, expectedDigest: root.digest)
        var manifestDescriptor = rootDescriptor
        var manifestData = root.data
        if Self.indexMediaTypes.contains(root.mediaType) {
            let requested = try OCIPlatform(platform)
            let imageIndex = try decoder.decode(OCIIndex.self, from: root.data)
            guard let selected = imageIndex.manifests.first(where: { $0.platform?.matches(requested) == true }) else {
                throw EngineError(.notFound, "image \(parsed.normalized) has no \(platform) manifest")
            }
            let selectedManifest = try await client.fetchManifest(selected.digest)
            manifestDescriptor = try put(
                selectedManifest.data,
                mediaType: selectedManifest.mediaType,
                expectedDigest: selected.digest
            )
            manifestData = selectedManifest.data
        }
        let manifest = try decoder.decode(OCIManifest.self, from: manifestData)
        let descriptors = [manifest.config] + manifest.layers
        var completedBytes: Int64 = 0
        let totalBytes = descriptors.reduce(Int64(0)) { $0 + max($1.size, 0) }
        for (index, descriptor) in descriptors.enumerated() {
            if !contains(descriptor.digest) {
                let blob = try await client.fetchBlob(descriptor.digest)
                _ = try put(blob, mediaType: descriptor.mediaType, expectedDigest: descriptor.digest)
            }
            completedBytes += max(descriptor.size, 0)
            await progress(.init(
                completedItems: index + 1,
                totalItems: descriptors.count,
                completedBytes: completedBytes,
                totalBytes: totalBytes
            ))
        }
        try tag(rootDescriptor, as: parsed.normalized)
        return try image(reference: parsed.normalized, platform: platform)
    }

    public func push(reference: String, platform: String, credentials: RegistryCredentials?) async throws {
        let parsed = try OCIRegistryReference(reference)
        let image = try image(reference: reference, platform: platform)
        let client = OCIRegistryClient(reference: parsed, credentials: credentials)
        for descriptor in [image.manifest.config] + image.manifest.layers {
            if try await client.blobExists(descriptor.digest) == false {
                try await client.pushBlob(data(for: descriptor.digest), digest: descriptor.digest)
            }
        }
        let manifestData = try data(for: image.manifestDescriptor.digest)
        try await client.pushManifest(manifestData, mediaType: image.manifestDescriptor.mediaType, selector: parsed.selector)
    }

    public func history(reference: String, platform: String) throws -> [ImageHistoryEntry] {
        let value = try image(reference: reference, platform: platform)
        return (value.configuration.history ?? []).map {
            let date = $0.created.flatMap { ISO8601DateFormatter().date(from: $0) } ?? Date(timeIntervalSince1970: 0)
            return .init(created: Int64(date.timeIntervalSince1970), createdBy: $0.createdBy ?? "", comment: $0.comment ?? "", emptyLayer: $0.emptyLayer ?? false)
        }
    }

    public func importLayout(_ directory: URL) throws -> [BackendImage] {
        let indexData = try Data(contentsOf: directory.appending(path: "index.json"))
        let layoutIndex = try decoder.decode(OCIIndex.self, from: indexData)
        var imported: [BackendImage] = []
        for descriptor in layoutIndex.manifests {
            var seen = Set<String>()
            try importDescriptor(descriptor, from: directory, seen: &seen)
            let reference = descriptor.annotations?["org.opencontainers.image.ref.name"] ?? descriptor.digest
            try tag(descriptor, as: reference)
        }
        let all = try summaries()
        let references = Set(layoutIndex.manifests.map { $0.annotations?["org.opencontainers.image.ref.name"] ?? $0.digest })
        imported = all.filter { references.contains($0.reference) }
        return imported
    }

    public func exportLayout(references requested: [String], platform: String) throws -> Data {
        let names = requested.isEmpty ? references() : requested.map(ImageReference.normalized)
        var roots: [OCIDescriptor] = []
        var digests = Set<String>()
        for name in names {
            guard var descriptor = index.references[name] else { throw EngineError(.notFound, "image \(name) not found") }
            var annotations = descriptor.annotations ?? [:]
            annotations["org.opencontainers.image.ref.name"] = name
            descriptor.annotations = annotations
            roots.append(descriptor)
            try collect(descriptor, into: &digests)
        }
        let layout = try encoder.encode(["imageLayoutVersion": "1.0.0"])
        let layoutIndex = try encoder.encode(OCIIndex(schemaVersion: 2, mediaType: "application/vnd.oci.image.index.v1+json", manifests: roots, annotations: nil))
        var entries: [(String, Data)] = [("oci-layout", layout), ("index.json", layoutIndex)]
        for digest in digests.sorted() { entries.append(("blobs/sha256/" + String(digest.dropFirst(7)), try data(for: digest))) }
        return OCIArchive.tar(entries: entries)
    }

    private func importDescriptor(_ descriptor: OCIDescriptor, from directory: URL, seen: inout Set<String>) throws {
        guard seen.insert(descriptor.digest).inserted else { return }
        let source = directory.appending(path: "blobs/sha256/" + String(descriptor.digest.dropFirst(7)))
        let contents = try Data(contentsOf: source)
        _ = try put(contents, mediaType: descriptor.mediaType, expectedDigest: descriptor.digest)
        if Self.indexMediaTypes.contains(descriptor.mediaType) {
            for child in try decoder.decode(OCIIndex.self, from: contents).manifests { try importDescriptor(child, from: directory, seen: &seen) }
        } else if Self.manifestMediaTypes.contains(descriptor.mediaType) {
            let manifest = try decoder.decode(OCIManifest.self, from: contents)
            for child in [manifest.config] + manifest.layers { try importDescriptor(child, from: directory, seen: &seen) }
        }
    }

    private func collect(_ descriptor: OCIDescriptor, into digests: inout Set<String>) throws {
        guard digests.insert(descriptor.digest).inserted else { return }
        let contents = try data(for: descriptor.digest)
        if Self.indexMediaTypes.contains(descriptor.mediaType) {
            for child in try decoder.decode(OCIIndex.self, from: contents).manifests { try collect(child, into: &digests) }
        } else if Self.manifestMediaTypes.contains(descriptor.mediaType) {
            let manifest = try decoder.decode(OCIManifest.self, from: contents)
            for child in [manifest.config] + manifest.layers { try collect(child, into: &digests) }
        }
    }

    public func prune() throws -> [String] {
        var descriptors = Dictionary(uniqueKeysWithValues: index.references.values.map { ($0.digest, $0) })
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
        do { try FileManager.default.moveItem(at: temporary, to: destination) }
        catch {
            try? FileManager.default.removeItem(at: temporary)
            if !FileManager.default.fileExists(atPath: destination.path) { throw error }
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
            repository = String(remainder[..<at])
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

import Foundation
import CryptoKit
import Testing
@testable import CEngineCore
@testable import CEngineRuntime

@Suite struct OCIContentStoreTests {
    @Test func descriptorsRejectInvalidDigestSizeAndEmbeddedContent() throws {
        let validData = Data("manifest".utf8)
        let digest = "sha256:" + SHA256.hash(data: validData).map {
            String(format: "%02x", $0)
        }.joined()
        let valid = OCIDescriptor(
            mediaType: "application/vnd.oci.image.manifest.v1+json",
            digest: digest,
            size: Int64(validData.count),
            data: validData
        )
        #expect(try valid.validated().size == UInt64(validData.count))

        #expect(throws: EngineError.self) {
            try OCIDescriptor(
                mediaType: valid.mediaType,
                digest: "sha256:" + String(repeating: "A", count: 64),
                size: 1
            ).validated()
        }
        #expect(throws: EngineError.self) {
            try OCIDescriptor(
                mediaType: valid.mediaType, digest: digest, size: -1
            ).validated()
        }
        #expect(throws: EngineError.self) {
            try OCIDescriptor(
                mediaType: valid.mediaType,
                digest: digest,
                size: Int64(OCITransferPolicy.default.metadataBytes) + 1
            ).validated()
        }
        let attestation = OCIDescriptor(
            mediaType: "application/vnd.in-toto+json",
            digest: digest,
            size: Int64(OCITransferPolicy.default.metadataBytes) + 1
        )
        #expect(try attestation.validated().size == UInt64(attestation.size))
        #expect(throws: EngineError.self) {
            try OCIDescriptor(
                mediaType: valid.mediaType,
                digest: digest,
                size: Int64(validData.count) + 1,
                data: validData
            ).validated()
        }
    }

    @Test func layoutImportRejectsSymlinkedMetadata() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let layout = root.appending(path: "layout")
        let outside = root.appending(path: "outside-index.json")
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(
            at: layout, withIntermediateDirectories: true
        )
        try Data(#"{"schemaVersion":2,"manifests":[]}"#.utf8).write(to: outside)
        try FileManager.default.createSymbolicLink(
            at: layout.appending(path: "index.json"),
            withDestinationURL: outside
        )
        let store = try OCIContentStore(root: root.appending(path: "content"))

        await #expect(throws: EngineError.self) {
            _ = try await store.importLayout(layout)
        }
    }

    @Test func registryReferenceSeparatesTagFromDigestRepository() throws {
        let digest = "sha256:" + String(repeating: "a", count: 64)
        let reference = try OCIRegistryReference("kindest/node:v1.36.1@\(digest)")

        #expect(reference.registry == "docker.io")
        #expect(reference.repository == "kindest/node")
        #expect(reference.selector == digest)
        #expect(reference.normalized == "docker.io/kindest/node:v1.36.1@\(digest)")
    }

    @Test func identityTokenForImageOperationsIsExchangedOnlyAtBearerRealm() throws {
        let reference = try OCIRegistryReference("registry.example.test/team/app:latest")
        let request = try OCIRegistryClient.bearerTokenRequest(
            challenge: #"Basic realm="legacy", Bearer realm="https://auth.example.test/token",service="registry.example.test",scope="repository:team/app:pull""#,
            reference: reference,
            credentials: .init(username: "push", identityToken: "refresh-secret")
        )

        #expect(request.url?.absoluteString == "https://auth.example.test/token")
        #expect(request.httpMethod == "POST")
        #expect(request.value(forHTTPHeaderField: "Authorization") == nil)
        let formBody = String(decoding: try #require(request.httpBody), as: UTF8.self)
        let form = URLComponents(string: "?\(formBody)")?.queryItems ?? []
        #expect(form.first(where: { $0.name == "grant_type" })?.value == "refresh_token")
        #expect(form.first(where: { $0.name == "refresh_token" })?.value == "refresh-secret")
        #expect(form.first(where: { $0.name == "scope" })?.value == "repository:team/app:pull")
        #expect(form.first(where: { $0.name == "service" })?.value == "registry.example.test")
    }

    @Test func registryRedirectsStripAccessTokensAndRejectSecretDowngrades() throws {
        var registry = URLRequest(url: try #require(URL(string: "https://registry.example.test/v2/team/app/blobs/value")))
        registry.setValue("Bearer scoped-access", forHTTPHeaderField: "Authorization")
        let external = URLRequest(url: try #require(URL(string: "https://cdn.example.test/blob")))
        let stripped = try #require(OCIRegistrySessionDelegate.redirectedRequest(
            from: registry, to: external
        ))
        #expect(stripped.value(forHTTPHeaderField: "Authorization") == nil)

        let downgrade = URLRequest(url: try #require(URL(string: "http://registry.example.test/blob")))
        #expect(OCIRegistrySessionDelegate.redirectedRequest(from: registry, to: downgrade) == nil)

        var token = URLRequest(url: try #require(URL(string: "https://auth.example.test/token")))
        token.httpMethod = "POST"
        token.httpBody = Data("refresh_token=refresh-secret".utf8)
        token.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        #expect(OCIRegistrySessionDelegate.redirectedRequest(from: token, to: external) == nil)
    }

    @Test func contentIsAddressedAndVerifiedByDigest() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try OCIContentStore(root: root)
        let data = Data("manifest".utf8)

        let descriptor = try await store.put(data, mediaType: "application/vnd.oci.image.manifest.v1+json")

        #expect(descriptor.digest.hasPrefix("sha256:"))
        #expect(try await store.data(for: descriptor.digest) == data)
    }

    @Test func imageCreationDatesAcceptFractionalSecondsAndManifestAnnotations() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try OCIContentStore(root: root)
        let encoder = JSONEncoder()

        func addImage(reference: String, configCreated: String?, annotationCreated: String?) async throws {
            var configObject: [String: Any] = [
                "architecture": "arm64",
                "os": "linux",
                "rootfs": ["type": "layers", "diff_ids": [String]()] as [String: Any],
                "history": [["created": "2026-01-28T01:18:09.724934761Z"]],
            ]
            if let configCreated { configObject["created"] = configCreated }
            let configData = try JSONSerialization.data(withJSONObject: configObject)
            let config = try await store.put(
                configData, mediaType: "application/vnd.oci.image.config.v1+json"
            )
            let manifestData = try encoder.encode(OCIManifest(
                schemaVersion: 2,
                mediaType: "application/vnd.oci.image.manifest.v1+json",
                config: config,
                layers: [],
                annotations: annotationCreated.map { ["org.opencontainers.image.created": $0] }
            ))
            let manifest = try await store.put(
                manifestData, mediaType: "application/vnd.oci.image.manifest.v1+json"
            )
            try await store.tag(manifest, as: reference)
        }

        try await addImage(
            reference: "example:config-date",
            configCreated: "2026-01-29T11:03:47.54684059Z",
            annotationCreated: "2026-01-29T11:01:35.546Z"
        )
        try await addImage(
            reference: "example:annotation-date",
            configCreated: nil,
            annotationCreated: "2026-01-29T11:01:35.546Z"
        )

        let summaries = try await store.summaries()
        let configDate = try #require(summaries.first { $0.reference.hasSuffix("example:config-date") })
        let annotationDate = try #require(summaries.first { $0.reference.hasSuffix("example:annotation-date") })
        #expect(abs(configDate.createdAt.timeIntervalSince1970 - 1_769_684_627.54684059) < 0.001)
        #expect(abs(annotationDate.createdAt.timeIntervalSince1970 - 1_769_684_495.546) < 0.001)
        #expect(configDate.manifests.first?.history.first?.created == 1_769_563_089)
    }

    @Test func updatedReferencesPersistAcrossStoreInstances() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let first = try OCIContentStore(root: root)
        let descriptor = try await first.put(Data("manifest".utf8), mediaType: "application/vnd.oci.image.manifest.v1+json")
        try await first.tag(descriptor, as: "alpine:latest")
        try await first.tag(descriptor, as: "example:latest")

        let second = try OCIContentStore(root: root)

        #expect(await second.descriptor(for: "alpine:latest") == descriptor)
        #expect(await second.descriptor(for: "example:latest") == descriptor)
    }

    @Test func pruneDeduplicatesDescriptorsSharedByMultipleTags() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try OCIContentStore(root: root)
        let descriptor = try await store.put(
            Data("manifest".utf8),
            mediaType: "application/vnd.oci.image.manifest.v1+json"
        )
        try await store.tag(descriptor, as: "example:first")
        try await store.tag(descriptor, as: "example:second")

        #expect(try await store.prune().isEmpty)
        #expect(await store.descriptor(for: "example:first") == descriptor)
        #expect(await store.descriptor(for: "example:second") == descriptor)
    }

    @Test func mismatchedDigestIsRejected() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try OCIContentStore(root: root)

        do {
            _ = try await store.put(
                Data("content".utf8),
                mediaType: "application/octet-stream",
                expectedDigest: "sha256:" + String(repeating: "0", count: 64)
            )
            Issue.record("expected a digest mismatch")
        } catch {
            #expect(error is EngineError)
        }
    }

    @Test func summariesUseTheDownloadedManifestFromAMultiplatformIndex() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try OCIContentStore(root: root)
        let encoder = JSONEncoder()
        let configData = Data(#"{"architecture":"arm64","os":"linux","config":{"Healthcheck":{"Test":["CMD","true"],"Interval":9000000000,"Timeout":8000000000,"Retries":4,"StartPeriod":7000000000,"StartInterval":6000000000}},"rootfs":{"type":"layers","diff_ids":[]}}"#.utf8)
        let config = try await store.put(configData, mediaType: "application/vnd.oci.image.config.v1+json")
        let manifestData = try encoder.encode(OCIManifest(
            schemaVersion: 2,
            mediaType: "application/vnd.oci.image.manifest.v1+json",
            config: config,
            layers: [],
            annotations: nil
        ))
        let storedManifest = try await store.put(manifestData, mediaType: "application/vnd.oci.image.manifest.v1+json")
        let missingManifest = OCIDescriptor(
            mediaType: "application/vnd.oci.image.manifest.v1+json",
            digest: "sha256:" + String(repeating: "0", count: 64),
            size: 1,
            platform: OCIPlatform(architecture: "amd64", os: "linux")
        )
        let availableManifest = OCIDescriptor(
            mediaType: storedManifest.mediaType,
            digest: storedManifest.digest,
            size: storedManifest.size,
            platform: OCIPlatform(architecture: "arm64", os: "linux")
        )
        let indexData = try encoder.encode(OCIIndex(
            schemaVersion: 2,
            mediaType: "application/vnd.oci.image.index.v1+json",
            manifests: [missingManifest, availableManifest],
            annotations: nil
        ))
        let index = try await store.put(indexData, mediaType: "application/vnd.oci.image.index.v1+json")
        try await store.tag(index, as: "alpine:latest")

        let summaries = try await store.summaries()

        #expect(summaries.count == 1)
        #expect(summaries.first?.id == config.digest)
        #expect(summaries.first?.architecture == "arm64")
        #expect(summaries.first?.targetDescriptor?.digest == index.digest)
        #expect(summaries.first?.manifests.count == 2)
        let available = summaries.first?.manifests.first {
            $0.descriptor.digest == storedManifest.digest
        }
        #expect(available?.available == true)
        #expect(available?.configuration?.healthcheck?.test == ["CMD", "true"])
        #expect(available?.configuration?.healthcheck?.intervalNanoseconds == 9_000_000_000)
        #expect(available?.configuration?.healthcheck?.startIntervalNanoseconds == 6_000_000_000)
        #expect(summaries.first?.manifests.first(where: { $0.descriptor.digest == missingManifest.digest })?.available == false)
    }

    @Test func exportIncludesOnlyTheSelectedPlatformFromAMultiplatformIndex() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try OCIContentStore(root: root)
        let encoder = JSONEncoder()
        let configData = Data(#"{"architecture":"arm64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}"#.utf8)
        let config = try await store.put(configData, mediaType: "application/vnd.oci.image.config.v1+json")
        let manifestData = try encoder.encode(OCIManifest(
            schemaVersion: 2,
            mediaType: "application/vnd.oci.image.manifest.v1+json",
            config: config,
            layers: [],
            annotations: nil
        ))
        let storedManifest = try await store.put(manifestData, mediaType: "application/vnd.oci.image.manifest.v1+json")
        let missingManifest = OCIDescriptor(
            mediaType: "application/vnd.oci.image.manifest.v1+json",
            digest: "sha256:" + String(repeating: "0", count: 64),
            size: 1,
            platform: OCIPlatform(architecture: "amd64", os: "linux")
        )
        let availableManifest = OCIDescriptor(
            mediaType: storedManifest.mediaType,
            digest: storedManifest.digest,
            size: storedManifest.size,
            platform: OCIPlatform(architecture: "arm64", os: "linux")
        )
        let indexData = try encoder.encode(OCIIndex(
            schemaVersion: 2,
            mediaType: "application/vnd.oci.image.index.v1+json",
            manifests: [missingManifest, availableManifest],
            annotations: nil
        ))
        let index = try await store.put(indexData, mediaType: "application/vnd.oci.image.index.v1+json")
        try await store.tag(index, as: "alpine:latest")

        let archive = try await store.exportLayout(
            references: ["alpine:latest"],
            platforms: [OCIPlatform(architecture: "arm64", os: "linux")]
        )

        #expect(!archive.isEmpty)
    }

    @Test func multiPlatformGraphsCanBeSelectedExportedAndRemovedIndependently() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try OCIContentStore(root: root.appending(path: "store"))
        let encoder = JSONEncoder()

        func makeManifest(architecture: String) async throws -> OCIDescriptor {
            let configData = Data(
                #"{"architecture":"\#(architecture)","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}"#.utf8
            )
            let config = try await store.put(
                configData,
                mediaType: "application/vnd.oci.image.config.v1+json"
            )
            let manifestData = try encoder.encode(OCIManifest(
                schemaVersion: 2,
                mediaType: "application/vnd.oci.image.manifest.v1+json",
                config: config,
                layers: [],
                annotations: nil
            ))
            let manifest = try await store.put(
                manifestData,
                mediaType: "application/vnd.oci.image.manifest.v1+json"
            )
            return OCIDescriptor(
                mediaType: manifest.mediaType,
                digest: manifest.digest,
                size: manifest.size,
                platform: OCIPlatform(architecture: architecture, os: "linux")
            )
        }

        let arm64 = try await makeManifest(architecture: "arm64")
        let amd64 = try await makeManifest(architecture: "amd64")
        let indexData = try encoder.encode(OCIIndex(
            schemaVersion: 2,
            mediaType: "application/vnd.oci.image.index.v1+json",
            manifests: [amd64, arm64],
            annotations: nil
        ))
        let index = try await store.put(indexData, mediaType: "application/vnd.oci.image.index.v1+json")
        try await store.tag(index, as: "example:multi")

        let summary = try #require(try await store.summaries().first)
        #expect(summary.id == summary.preferredManifestDigest.flatMap { digest in
            summary.manifests.first { $0.descriptor.digest == digest }?.imageID
        })
        #expect(summary.preferredManifestDigest == arm64.digest)
        #expect(summary.manifests.filter { $0.kind == .image && $0.available }.count == 2)
        #expect(try await store.image(
            reference: "example:multi",
            platform: OCIPlatform(architecture: "amd64", os: "linux")
        ).manifestDescriptor.digest == amd64.digest)

        let archive = try await store.exportLayout(
            references: ["example:multi"],
            platforms: [OCIPlatform(architecture: "amd64", os: "linux")]
        )
        let archiveURL = root.appending(path: "selected.tar")
        let layout = root.appending(path: "selected")
        try archive.write(to: archiveURL)
        try SystemTar.extract(archiveURL, to: layout)
        #expect(FileManager.default.fileExists(atPath: layout.appending(path: "blobs/sha256/\(amd64.digest.dropFirst(7))").path))
        #expect(!FileManager.default.fileExists(atPath: layout.appending(path: "blobs/sha256/\(arm64.digest.dropFirst(7))").path))

        let removed = try await store.remove(
            reference: "example:multi",
            platforms: [OCIPlatform(architecture: "arm64", os: "linux")]
        )
        #expect(removed == [arm64.digest])
        #expect(await store.contains(index.digest))
        #expect(await store.contains(amd64.digest))
        #expect(await store.contains(arm64.digest) == false)
        let after = try #require(try await store.summaries().first)
        #expect(after.manifests.first(where: { $0.descriptor.digest == arm64.digest })?.available == false)
        #expect(after.manifests.first(where: { $0.descriptor.digest == amd64.digest })?.available == true)
    }

    @Test func attachedInTotoStatementsAreDiscoveredAndReadOnlyOnRequest() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try OCIContentStore(root: root)
        let encoder = JSONEncoder()
        let configData = Data(#"{"architecture":"arm64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}"#.utf8)
        let config = try await store.put(configData, mediaType: "application/vnd.oci.image.config.v1+json")
        let imageData = try encoder.encode(OCIManifest(
            schemaVersion: 2,
            mediaType: "application/vnd.oci.image.manifest.v1+json",
            config: config,
            layers: [],
            annotations: nil
        ))
        let imageContent = try await store.put(imageData, mediaType: "application/vnd.oci.image.manifest.v1+json")
        let image = OCIDescriptor(
            mediaType: imageContent.mediaType,
            digest: imageContent.digest,
            size: imageContent.size,
            platform: OCIPlatform(architecture: "arm64", os: "linux")
        )
        let statementData = Data(#"{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://spdx.dev/Document","subject":[]}"#.utf8)
        var statement = try await store.put(statementData, mediaType: "application/vnd.in-toto+json")
        statement.annotations = [OCIContentStore.inTotoPredicateTypeAnnotation: "https://spdx.dev/Document"]
        let attestationData = try encoder.encode(OCIManifest(
            schemaVersion: 2,
            mediaType: "application/vnd.oci.image.manifest.v1+json",
            artifactType: OCIContentStore.attestationManifestArtifactType,
            config: config,
            layers: [statement],
            subject: image,
            annotations: nil
        ))
        let attestationContent = try await store.put(
            attestationData,
            mediaType: "application/vnd.oci.image.manifest.v1+json"
        )
        let attestation = OCIDescriptor(
            mediaType: attestationContent.mediaType,
            digest: attestationContent.digest,
            size: attestationContent.size,
            platform: OCIPlatform(architecture: "unknown", os: "unknown"),
            artifactType: OCIContentStore.attestationManifestArtifactType
        )
        let indexData = try encoder.encode(OCIIndex(
            schemaVersion: 2,
            mediaType: "application/vnd.oci.image.index.v1+json",
            manifests: [image, attestation],
            annotations: nil
        ))
        let index = try await store.put(indexData, mediaType: "application/vnd.oci.image.index.v1+json")
        try await store.tag(index, as: "example:attested")

        let metadataOnly = try await store.attestations(
            reference: "example:attested",
            platform: nil,
            predicateTypes: [],
            includeStatement: false
        )
        #expect(metadataOnly.count == 1)
        #expect(metadataOnly.first?.predicateType == "https://spdx.dev/Document")
        #expect(metadataOnly.first?.statement == nil)
        let included = try await store.attestations(
            reference: "example:attested",
            platform: nil,
            predicateTypes: ["https://spdx.dev/Document"],
            includeStatement: true
        )
        #expect(included.first?.statement == statementData)
        #expect(try await store.attestations(
            reference: "example:attested",
            platform: nil,
            predicateTypes: ["https://slsa.dev/provenance/v1"],
            includeStatement: true
        ).isEmpty)
    }

    @Test func dockerArchiveRepoTagsOverrideBuildKitLocalAnnotationsAcrossLoads() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let firstReference = "compat-buildx:first"
        let secondReference = "compat-buildx:second"
        let first = try writeBuildKitDockerLayout(
            at: root.appending(path: "first"),
            reference: firstReference,
            configuration: Data(#"{"architecture":"arm64","os":"linux","config":{"Labels":{"target":"first"}},"rootfs":{"type":"layers","diff_ids":[]}}"#.utf8)
        )
        let second = try writeBuildKitDockerLayout(
            at: root.appending(path: "second"),
            reference: secondReference,
            configuration: Data(#"{"architecture":"arm64","os":"linux","config":{"Labels":{"target":"second"}},"rootfs":{"type":"layers","diff_ids":[]}}"#.utf8)
        )
        let store = try OCIContentStore(root: root.appending(path: "store"))

        let firstImport = try await store.importLayout(root.appending(path: "first"))
        let secondImport = try await store.importLayout(root.appending(path: "second"))

        #expect(firstImport.map(\.reference) == ["docker.io/library/compat-buildx:first"])
        #expect(secondImport.map(\.reference) == ["docker.io/library/compat-buildx:second"])
        #expect(await store.descriptor(for: firstReference) == first)
        #expect(await store.descriptor(for: secondReference) == second)
        #expect(await store.descriptor(for: "local:latest") == nil)
    }

    @Test func layerlessBuildKitDockerArchiveAcceptsNullDiffIDs() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let layout = root.appending(path: "layout")
        let configuration = Data(
            #"{"architecture":"arm64","os":"linux","config":{"Labels":{"probe.marker":"layerless"}},"rootfs":{"type":"layers","diff_ids":null}}"#.utf8
        )
        _ = try writeBuildKitDockerLayout(
            at: layout,
            reference: "compat-buildx:layerless",
            configuration: configuration
        )
        let store = try OCIContentStore(root: root.appending(path: "store"))

        let imported = try await store.importLayout(layout)
        let decoded = try JSONDecoder().decode(OCIImageConfiguration.self, from: configuration)

        #expect(imported.map(\.reference) == ["docker.io/library/compat-buildx:layerless"])
        #expect(decoded.rootfs.diffIDs.isEmpty)
        #expect(imported.first?.manifests.first?.configuration?.rootFSDiffIDs == [])
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(
                OCIImageConfiguration.self,
                from: Data(#"{"architecture":"arm64","os":"linux","rootfs":{"type":"layers"}}"#.utf8)
            )
        }
    }
}

private func writeBuildKitDockerLayout(
    at layout: URL,
    reference: String,
    configuration: Data
) throws -> OCIDescriptor {
    let blobs = layout.appending(path: "blobs/sha256")
    try FileManager.default.createDirectory(at: blobs, withIntermediateDirectories: true)
    let configDigest = SHA256.hash(data: configuration).map {
        String(format: "%02x", $0)
    }.joined()
    try configuration.write(to: blobs.appending(path: configDigest))
    let config = OCIDescriptor(
        mediaType: "application/vnd.oci.image.config.v1+json",
        digest: "sha256:\(configDigest)",
        size: Int64(configuration.count)
    )
    let manifestData = try JSONEncoder().encode(OCIManifest(
        schemaVersion: 2,
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        config: config,
        layers: [],
        annotations: nil
    ))
    let manifestDigest = SHA256.hash(data: manifestData).map {
        String(format: "%02x", $0)
    }.joined()
    try manifestData.write(to: blobs.appending(path: manifestDigest))
    let manifest = OCIDescriptor(
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        digest: "sha256:\(manifestDigest)",
        size: Int64(manifestData.count),
        annotations: [
            "io.containerd.image.name": reference,
            "org.opencontainers.image.ref.name": "local",
        ]
    )
    try JSONEncoder().encode(OCIIndex(
        schemaVersion: 2,
        mediaType: "application/vnd.oci.image.index.v1+json",
        manifests: [manifest],
        annotations: nil
    )).write(to: layout.appending(path: "index.json"))
    try JSONSerialization.data(withJSONObject: [[
        "Config": "blobs/sha256/\(configDigest)",
        "RepoTags": [reference],
        "Layers": [],
    ]], options: [.sortedKeys]).write(to: layout.appending(path: "manifest.json"))
    return manifest
}

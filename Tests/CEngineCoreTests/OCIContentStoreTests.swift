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

    @Test(arguments: [0, 1, 2])
    func standardDockerSaveArchiveImportsWithoutOCIIndex(layerCount: Int) async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appending(path: "source")
        let layout = root.appending(path: "layout")
        let layers = (0..<layerCount).map { _ in Data(repeating: 0, count: 1_024) }
        let configuration = try writeStandardDockerLayout(at: source, layers: layers)
        let archive = root.appending(path: "image.tar")
        try SystemTar.create(from: source, at: archive)
        try SystemTar.extract(archive, to: layout)
        #expect(!FileManager.default.fileExists(atPath: layout.appending(path: "index.json").path))
        let store = try OCIContentStore(root: root.appending(path: "store"))

        let imported = try await store.importLayout(layout, platforms: [.init(architecture: "arm64", os: "linux")])
        let image = try await store.image(reference: "compat-save:latest")
        let configDigest = "sha256:" + SHA256.hash(data: configuration).map { String(format: "%02x", $0) }.joined()

        #expect(imported.map(\.reference).sorted() == ["docker.io/library/compat-save:alias", "docker.io/library/compat-save:latest"])
        #expect(imported.allSatisfy { $0.id == configDigest })
        #expect(image.configuration.config?.command == ["/probe", "serve"])
        #expect(image.configuration.config?.volumes?["/data"] != nil)
        #expect(image.manifest.layers.count == layerCount)
        for (descriptor, contents) in zip(image.manifest.layers, layers) {
            #expect(descriptor.mediaType == "application/vnd.oci.image.layer.v1.tar")
            #expect(try await store.data(for: descriptor.digest) == contents)
        }
        let reopened = try OCIContentStore(root: root.appending(path: "store"))
        #expect(await reopened.references() == imported.map(\.reference).sorted())
    }

    @Test(arguments: ["traversal", "absolute", "nul", "config-symlink", "layer-symlink", "directory-symlink", "index-symlink", "invalid-index"])
    func standardDockerSaveRejectsUnsafePathsAndDoesNotBypassOCIIndex(kind: String) async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let layout = root.appending(path: "layout")
        let layer = Data(repeating: 0, count: 1_024)
        let configuration = try writeStandardDockerLayout(at: layout, layers: [layer])
        let outside = root.appending(path: "outside.json")
        try configuration.write(to: outside)
        var configPath = "config.json"
        let layerPath = "layer0/layer.tar"
        switch kind {
        case "traversal": configPath = "../outside.json"
        case "absolute": configPath = outside.path
        case "nul": configPath = "config.json\0ignored"
        case "config-symlink":
            try FileManager.default.removeItem(at: layout.appending(path: configPath))
            try FileManager.default.createSymbolicLink(at: layout.appending(path: configPath), withDestinationURL: outside)
        case "layer-symlink":
            let outsideLayer = root.appending(path: "outside.tar")
            try layer.write(to: outsideLayer)
            try FileManager.default.removeItem(at: layout.appending(path: layerPath))
            try FileManager.default.createSymbolicLink(at: layout.appending(path: layerPath), withDestinationURL: outsideLayer)
        case "directory-symlink":
            try FileManager.default.createSymbolicLink(at: layout.appending(path: "escape"), withDestinationURL: root)
            configPath = "escape/outside.json"
        case "index-symlink":
            // A dangling OCI index must not fall back to a valid Docker manifest.
            try FileManager.default.createSymbolicLink(at: layout.appending(path: "index.json"), withDestinationURL: root.appending(path: "missing"))
        default:
            try Data("not JSON".utf8).write(to: layout.appending(path: "index.json"))
        }
        try JSONSerialization.data(withJSONObject: [[
            "Config": configPath, "RepoTags": ["compat-save:latest"], "Layers": [layerPath],
        ]]).write(to: layout.appending(path: "manifest.json"))
        let store = try OCIContentStore(root: root.appending(path: "store"))

        await #expect(throws: (any Error).self) { _ = try await store.importLayout(layout) }
        #expect(await store.references().isEmpty)
    }

    @Test(arguments: ["digest", "count", "platform"])
    func standardDockerSaveRejectsInvalidLayersAndMissingPlatforms(kind: String) async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let layout = root.appending(path: "layout")
        _ = try writeStandardDockerLayout(at: layout, layers: [Data(repeating: 0, count: 1_024)])
        if kind == "digest" {
            try Data("corrupt layer".utf8).write(to: layout.appending(path: "layer0/layer.tar"))
        } else if kind == "count" {
            try JSONSerialization.data(withJSONObject: [[
                "Config": "config.json", "RepoTags": ["compat-save:latest"], "Layers": [String](),
            ]]).write(to: layout.appending(path: "manifest.json"))
        }
        let store = try OCIContentStore(root: root.appending(path: "store"))
        let platforms: [OCIPlatform] = kind == "platform" ? [.init(architecture: "amd64", os: "linux")] : []

        await #expect(throws: EngineError.self) { _ = try await store.importLayout(layout, platforms: platforms) }
        #expect(await store.references().isEmpty)
    }

    @Test(arguments: ["layer", "entry", "platform", "empty-os", "empty-architecture"])
    func standardDockerSaveValidationFailureLeavesNoNewBlobs(kind: String) async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let storeRoot = root.appending(path: "store")
        let store = try OCIContentStore(root: storeRoot)
        let shared = Data(repeating: 0, count: 1_024)
        let seed = root.appending(path: "seed")
        _ = try writeStandardDockerLayout(at: seed, layers: [shared])
        _ = try await store.importLayout(seed)
        let previousBlobs = try storedBlobContents(at: storeRoot)
        let previousReferences = await store.references()
        let previousIndex = try Data(contentsOf: storeRoot.appending(path: "references.json"))
        let previousEntries = try FileManager.default.contentsOfDirectory(atPath: storeRoot.path).sorted()

        let layout = root.appending(path: "layout")
        _ = try writeStandardDockerLayout(at: layout, layers: [shared, Data(repeating: 1, count: 2_048), Data("last layer".utf8)])
        if kind == "layer" {
            try Data("invalid trailing layer".utf8).write(to: layout.appending(path: "layer2/layer.tar"))
        } else if kind.hasPrefix("empty-") {
            let configURL = layout.appending(path: "config.json")
            var config = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: configURL)) as? [String: Any])
            config[String(kind.dropFirst(6))] = ""
            try JSONSerialization.data(withJSONObject: config).write(to: configURL)
        } else if kind == "entry" {
            try JSONSerialization.data(withJSONObject: [
                ["Config": "config.json", "RepoTags": ["compat-save:latest"], "Layers": ["layer0/layer.tar", "layer1/layer.tar", "layer2/layer.tar"]],
                ["Config": "missing.json", "RepoTags": ["compat-save:trailing"], "Layers": [String]()],
            ]).write(to: layout.appending(path: "manifest.json"))
        }
        // Validate one selected image before discovering that another requested platform is absent.
        let platforms: [OCIPlatform] = kind == "platform"
            ? [.init(architecture: "arm64", os: "linux"), .init(architecture: "amd64", os: "linux")]
            : []
        await #expect(throws: EngineError.self) { _ = try await store.importLayout(layout, platforms: platforms) }

        #expect(try storedBlobContents(at: storeRoot) == previousBlobs)
        #expect(await store.references() == previousReferences)
        #expect(try Data(contentsOf: storeRoot.appending(path: "references.json")) == previousIndex)
        #expect(try FileManager.default.contentsOfDirectory(atPath: storeRoot.path).sorted() == previousEntries)
        let reopened = try OCIContentStore(root: storeRoot)
        #expect(await reopened.descriptor(for: "compat-save:latest") == store.descriptor(for: "compat-save:latest"))
    }

    @Test(arguments: [false, true])
    func standardDockerSaveReferenceWriteFailureRollsBackOnlyNewBlobs(preexisting: Bool) async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let storeRoot = root.appending(path: "store")
        let store = try OCIContentStore(root: storeRoot)
        let layout = root.appending(path: "layout")
        let shared = Data(repeating: 0, count: 1_024)
        let configuration = try writeStandardDockerLayout(at: layout, layers: [shared, Data(repeating: 1, count: 2_048)])
        if preexisting {
            let seed = root.appending(path: "seed")
            _ = try writeStandardDockerLayout(at: seed, layers: [shared])
            _ = try await store.importLayout(seed)
            // Preserve both a referenced shared layer and an identical unreferenced config.
            _ = try await store.put(configuration, mediaType: "application/vnd.oci.image.config.v1+json")
        }
        let previousBlobs = try storedBlobContents(at: storeRoot)
        let previousReferences = await store.references()
        let previousDescriptor = await store.descriptor(for: "compat-save:latest")
        let indexURL = storeRoot.appending(path: "references.json")
        let backup = storeRoot.appending(path: "saved-references.json")
        if preexisting { try FileManager.default.moveItem(at: indexURL, to: backup) }
        // A directory at the ref-file destination deterministically fails the final rename,
        // after all missing blobs have been published. It works even in privileged tests.
        try FileManager.default.createDirectory(at: indexURL, withIntermediateDirectories: false)
        let sentinel = indexURL.appending(path: "sentinel")
        let sentinelData = Data("must not change".utf8)
        try sentinelData.write(to: sentinel)
        let previousEntries = try FileManager.default.contentsOfDirectory(atPath: storeRoot.path).sorted()

        await #expect(throws: POSIXError.self) { _ = try await store.importLayout(layout) }

        #expect(try storedBlobContents(at: storeRoot) == previousBlobs)
        #expect(await store.references() == previousReferences)
        #expect(await store.descriptor(for: "compat-save:latest") == previousDescriptor)
        #expect(try Data(contentsOf: sentinel) == sentinelData)
        #expect(try FileManager.default.contentsOfDirectory(atPath: storeRoot.path).sorted() == previousEntries)
        try FileManager.default.removeItem(at: indexURL)
        if preexisting { try FileManager.default.moveItem(at: backup, to: indexURL) }
        let reopened = try OCIContentStore(root: storeRoot)
        #expect(await reopened.references() == previousReferences)
        #expect(await reopened.descriptor(for: "compat-save:latest") == previousDescriptor)
        // Rollback leaves the actor usable for a later successful retry.
        #expect(try await store.importLayout(layout).count == 2)
    }

    @Test(arguments: [false, true])
    func standardDockerSaveWithoutTagsKeepsImageIDReference(nullTags: Bool) async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let layout = root.appending(path: "layout")
        let config = try writeStandardDockerLayout(at: layout, layers: [])
        let entry: [String: Any] = [
            "Config": "config.json", "Layers": [String](),
            "RepoTags": nullTags ? NSNull() : [String]() as Any,
        ]
        try JSONSerialization.data(withJSONObject: [entry]).write(to: layout.appending(path: "manifest.json"))
        let store = try OCIContentStore(root: root.appending(path: "store"))

        let imported = try await store.importLayout(layout)
        let digest = "sha256:" + SHA256.hash(data: config).map { String(format: "%02x", $0) }.joined()
        #expect(imported.map(\.id) == [digest])
        #expect(await store.references() == [digest])
    }

    @Test(arguments: [false, true])
    func standardDockerSaveBoundsRepeatedSourceReads(repeated: Bool) async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let layout = root.appending(path: "layout")
        let layer = Data(repeating: 0, count: 1_024)
        let config = try writeStandardDockerLayout(at: layout, layers: [layer])
        if repeated {
            let entry: [String: Any] = ["Config": "config.json", "RepoTags": ["compat-save:latest"], "Layers": ["layer0/layer.tar"]]
            try JSONSerialization.data(withJSONObject: [entry, entry, entry]).write(to: layout.appending(path: "manifest.json"))
        }
        let policy = OCITransferPolicy(
            metadataBytes: 8_192, tokenBytes: 1_024, errorBodyBytes: 1_024,
            maximumBlobBytes: 8_192,
            maximumGraphBytes: repeated ? 2_048 : UInt64(config.count + layer.count - 1),
            maximumGraphDescriptors: 100, maximumGraphDepth: 32
        )
        let store = try OCIContentStore(root: root.appending(path: "store"), transferPolicy: policy)

        await #expect(throws: EngineError.self) { _ = try await store.importLayout(layout) }
        #expect(await store.references().isEmpty)
        #expect(try storedBlobContents(at: root.appending(path: "store")).isEmpty)
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.appending(path: "store").path) == ["blobs"])

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

private func storedBlobContents(at root: URL) throws -> [String: Data] {
    let blobs = root.appending(path: "blobs/sha256")
    return try Dictionary(uniqueKeysWithValues: FileManager.default.contentsOfDirectory(
        at: blobs, includingPropertiesForKeys: nil
    ).map { ($0.lastPathComponent, try Data(contentsOf: $0)) })
}

private func writeStandardDockerLayout(at layout: URL, layers: [Data]) throws -> Data {
    try FileManager.default.createDirectory(at: layout, withIntermediateDirectories: true)
    let diffIDs = layers.map { data in
        "sha256:" + SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
    let configuration = try JSONSerialization.data(withJSONObject: [
        "architecture": "arm64", "os": "linux",
        "config": ["Cmd": ["/probe", "serve"], "Volumes": ["/data": [String: String]()]] as [String: Any],
        "rootfs": ["type": "layers", "diff_ids": diffIDs] as [String: Any],
    ], options: [.sortedKeys])
    try configuration.write(to: layout.appending(path: "config.json"))
    var paths: [String] = []
    for (index, contents) in layers.enumerated() {
        let directory = layout.appending(path: "layer\(index)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        try contents.write(to: directory.appending(path: "layer.tar"))
        paths.append("layer\(index)/layer.tar")
    }
    try JSONSerialization.data(withJSONObject: [[
        "Config": "config.json", "RepoTags": ["compat-save:latest", "compat-save:alias"], "Layers": paths,
    ]], options: [.sortedKeys]).write(to: layout.appending(path: "manifest.json"))
    return configuration
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

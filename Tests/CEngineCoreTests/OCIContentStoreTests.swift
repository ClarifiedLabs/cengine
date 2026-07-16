import Foundation
import CryptoKit
import Testing
@testable import CEngineCore
@testable import CEngineRuntime

@Suite struct OCIContentStoreTests {
    @Test func registryReferenceSeparatesTagFromDigestRepository() throws {
        let digest = "sha256:" + String(repeating: "a", count: 64)
        let reference = try OCIRegistryReference("kindest/node:v1.36.1@\(digest)")

        #expect(reference.registry == "docker.io")
        #expect(reference.repository == "kindest/node")
        #expect(reference.selector == digest)
        #expect(reference.normalized == "docker.io/kindest/node:v1.36.1@\(digest)")
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

        let summaries = try await store.summaries()

        #expect(summaries.count == 1)
        #expect(summaries.first?.id == config.digest)
        #expect(summaries.first?.architecture == "arm64")
        #expect(summaries.first?.targetDescriptor?.digest == index.digest)
        #expect(summaries.first?.manifests.count == 2)
        #expect(summaries.first?.manifests.first(where: { $0.descriptor.digest == storedManifest.digest })?.available == true)
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

    @Test func dockerArchiveRepoTagsNameUnannotatedOCIRoots() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let layout = root.appending(path: "layout")
        let blobs = layout.appending(path: "blobs/sha256")
        try FileManager.default.createDirectory(at: blobs, withIntermediateDirectories: true)
        let configData = Data(#"{"architecture":"arm64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}"#.utf8)
        let configDigest = SHA256.hash(data: configData).map { String(format: "%02x", $0) }.joined()
        try configData.write(to: blobs.appending(path: configDigest))
        let config = OCIDescriptor(
            mediaType: "application/vnd.oci.image.config.v1+json",
            digest: "sha256:\(configDigest)",
            size: Int64(configData.count)
        )
        let manifestData = try JSONEncoder().encode(OCIManifest(
            schemaVersion: 2,
            mediaType: "application/vnd.oci.image.manifest.v1+json",
            config: config,
            layers: [],
            annotations: nil
        ))
        let manifestDigest = SHA256.hash(data: manifestData).map { String(format: "%02x", $0) }.joined()
        try manifestData.write(to: blobs.appending(path: manifestDigest))
        let manifest = OCIDescriptor(
            mediaType: "application/vnd.oci.image.manifest.v1+json",
            digest: "sha256:\(manifestDigest)",
            size: Int64(manifestData.count)
        )
        try JSONEncoder().encode(OCIIndex(
            schemaVersion: 2,
            mediaType: "application/vnd.oci.image.index.v1+json",
            manifests: [manifest],
            annotations: nil
        )).write(to: layout.appending(path: "index.json"))
        try Data(#"[{"Config":"blobs/sha256/\#(configDigest)","RepoTags":["compat-buildx:test"],"Layers":[]}]"#.utf8)
            .write(to: layout.appending(path: "manifest.json"))

        let store = try OCIContentStore(root: root.appending(path: "store"))
        let imported = try await store.importLayout(layout)

        #expect(imported.map(\.reference) == ["docker.io/library/compat-buildx:test"])
        #expect(await store.descriptor(for: "compat-buildx:test") == manifest)
    }
}

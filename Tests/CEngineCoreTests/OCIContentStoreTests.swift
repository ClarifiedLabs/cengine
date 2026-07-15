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
        #expect(summaries.first?.id == storedManifest.digest)
        #expect(summaries.first?.architecture == "arm64")
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

        let archive = try await store.exportLayout(references: ["alpine:latest"], platform: "linux/arm64")

        #expect(!archive.isEmpty)
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

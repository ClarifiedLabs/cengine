import Foundation
import Testing
@testable import CEngineCore
@testable import CEngineRuntime

@Suite struct OCIContentStoreTests {
    @Test func contentIsAddressedAndVerifiedByDigest() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try OCIContentStore(root: root)
        let data = Data("manifest".utf8)

        let descriptor = try await store.put(data, mediaType: "application/vnd.oci.image.manifest.v1+json")

        #expect(descriptor.digest.hasPrefix("sha256:"))
        #expect(try await store.data(for: descriptor.digest) == data)
    }

    @Test func referencesPersistAcrossStoreInstances() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let first = try OCIContentStore(root: root)
        let descriptor = try await first.put(Data("manifest".utf8), mediaType: "application/vnd.oci.image.manifest.v1+json")
        try await first.tag(descriptor, as: "alpine:latest")

        let second = try OCIContentStore(root: root)

        #expect(await second.descriptor(for: "alpine:latest") == descriptor)
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
}

import CEngineCore
import Darwin
import Foundation

extension EngineRuntime {
    public func loadImages(
        archive: Data,
        platforms: [OCIPlatform] = []
    ) async throws -> [ImageRecord] {
        guard UInt64(archive.count) <= ArchivePolicy.default.wireBytes else {
            throw EngineError(.payloadTooLarge, "image archive exceeds its wire size limit")
        }
        let temporary = FileManager.default.temporaryDirectory.appending(
            path: "cengine-image-upload-\(UUID().uuidString)", directoryHint: .isDirectory
        )
        let archiveURL = temporary.appending(path: "image.tar")
        defer { try? FileManager.default.removeItem(at: temporary) }
        try FileManager.default.createDirectory(
            at: temporary,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        try writeOwnerOnly(archive, to: archiveURL)
        return try await loadImages(archiveURL: archiveURL, platforms: platforms)
    }

    public func loadImages(
        archiveURL: URL,
        platforms: [OCIPlatform] = []
    ) async throws -> [ImageRecord] {
        try requireCanonicalSnapshotWritable()
        let temporary = FileManager.default.temporaryDirectory.appending(
            path: "cengine-image-load-\(UUID().uuidString)", directoryHint: .isDirectory
        )
        let layout = temporary.appending(path: "layout", directoryHint: .isDirectory)
        defer { try? FileManager.default.removeItem(at: temporary) }
        try FileManager.default.createDirectory(
            at: temporary,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        _ = try SystemTar.extract(archiveURL, to: layout)
        let loaded = try await backend.loadImages(
            fromOCILayout: layout, platforms: platforms
        )
        var referenceOwners: [String: String] = [:]
        for image in loaded {
            referenceOwners[image.reference] = image.id
        }
        var recordsByID: [String: ImageRecord] = [:]
        for image in loaded where recordsByID[image.id] == nil {
            let importedReferences = referenceOwners.compactMap { reference, owner in
                owner == image.id ? reference : nil
            }
            guard !importedReferences.isEmpty else { continue }
            let existingReferences = snapshot.images.first(where: {
                $0.id == image.id
            })?.references.filter {
                referenceOwners[$0].map { $0 == image.id } ?? true
            } ?? []
            recordsByID[image.id] = ImageRecord(
                id: image.id,
                references: Array(Set(existingReferences + importedReferences)).sorted(),
                createdAt: image.createdAt,
                size: image.size,
                architecture: image.architecture,
                os: image.os,
                targetDescriptor: image.targetDescriptor,
                manifests: image.manifests,
                preferredManifestDigest: image.preferredManifestDigest,
                identity: image.identity
            )
        }
        let records = recordsByID.values.sorted { $0.id < $1.id }
        let loadedIDs = Set(records.map(\.id))
        let loadedReferences = Set(records.flatMap(\.references))
        snapshot.images = snapshot.images.compactMap { existing in
            guard !loadedIDs.contains(existing.id) else { return nil }
            var retained = existing
            retained.references.removeAll(where: loadedReferences.contains)
            return retained.references.isEmpty ? nil : retained
        }
        snapshot.images.append(contentsOf: records)
        try await persist()
        for record in records {
            emitImageEvent("load", id: record.id, name: record.id)
        }
        return records
    }

    private func writeOwnerOnly(_ data: Data, to url: URL) throws {
        let descriptor = Darwin.open(
            url.path,
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
        } catch {
            try? handle.close()
            throw error
        }
    }
}

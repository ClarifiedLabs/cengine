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
        var recordsByID: [String: ImageRecord] = [:]
        for image in loaded {
            if var record = recordsByID[image.id] {
                record.references = Array(Set(record.references + [image.reference])).sorted()
                recordsByID[image.id] = record
            } else {
                let existingReferences = snapshot.images.first(where: {
                    $0.id == image.id
                })?.references ?? []
                recordsByID[image.id] = ImageRecord(
                    id: image.id,
                    references: Array(
                        Set(existingReferences + [image.reference])
                    ).sorted(),
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
        }
        let records = recordsByID.values.sorted { $0.id < $1.id }
        for record in records {
            snapshot.images.removeAll {
                $0.id == record.id
                    || !$0.references.filter(record.references.contains).isEmpty
            }
            snapshot.images.append(record)
        }
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

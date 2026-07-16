import CEngineCore
import Foundation

extension EngineRuntime {
    public func loadImages(archive: Data, platforms: [OCIPlatform] = []) async throws -> [ImageRecord] {
        let temporary = FileManager.default.temporaryDirectory.appending(path: "cengine-image-load-\(UUID().uuidString)", directoryHint: .isDirectory)
        let archiveURL = temporary.appending(path: "image.tar")
        let layout = temporary.appending(path: "layout", directoryHint: .isDirectory)
        defer { try? FileManager.default.removeItem(at: temporary) }
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
        try archive.write(to: archiveURL, options: .atomic)
        try SystemTar.extract(archiveURL, to: layout)
        let loaded = try await backend.loadImages(fromOCILayout: layout, platforms: platforms)
        var recordsByID: [String: ImageRecord] = [:]
        for image in loaded {
            if var record = recordsByID[image.id] {
                record.references = Array(Set(record.references + [image.reference])).sorted()
                recordsByID[image.id] = record
            } else {
                let existingReferences = snapshot.images.first(where: { $0.id == image.id })?.references ?? []
                recordsByID[image.id] = ImageRecord(
                    id: image.id,
                    references: Array(Set(existingReferences + [image.reference])).sorted(),
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
            snapshot.images.removeAll { $0.id == record.id || !$0.references.filter(record.references.contains).isEmpty }
            snapshot.images.append(record)
        }
        try await persist()
        return records
    }
}

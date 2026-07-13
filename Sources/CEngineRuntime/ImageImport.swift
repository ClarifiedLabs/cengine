import CEngineCore
import Foundation

extension EngineRuntime {
    public func loadImages(archive: Data) async throws -> [ImageRecord] {
        let temporary = FileManager.default.temporaryDirectory.appending(path: "cengine-image-load-\(UUID().uuidString)", directoryHint: .isDirectory)
        let archiveURL = temporary.appending(path: "image.tar")
        let layout = temporary.appending(path: "layout", directoryHint: .isDirectory)
        defer { try? FileManager.default.removeItem(at: temporary) }
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
        try archive.write(to: archiveURL, options: .atomic)
        try SystemTar.extract(archiveURL, to: layout)
        let loaded = try await backend.loadImages(fromOCILayout: layout)
        let records = loaded.map { ImageRecord(id: $0.id, references: [$0.reference], createdAt: $0.createdAt, size: $0.size, architecture: $0.architecture, os: $0.os) }
        for record in records {
            snapshot.images.removeAll { $0.id == record.id || !$0.references.filter(record.references.contains).isEmpty }
            snapshot.images.append(record)
        }
        try await persist()
        return records
    }
}

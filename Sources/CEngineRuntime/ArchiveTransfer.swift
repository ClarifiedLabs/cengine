import CEngineCore
import Foundation

extension EngineRuntime {
    public func copyArchiveIntoContainer(_ identifier: String, path: String, archive: Data) async throws {
        let container = try container(identifier)
        guard container.phase == .created || container.phase == .running else { throw EngineError(.conflict, "archive copy requires a created or running container") }
        guard path.hasPrefix("/") else { throw EngineError(.badRequest, "container path must be absolute") }
        if archive.count >= 1_024 && archive.allSatisfy({ $0 == 0 }) { return }
        let temporary = FileManager.default.temporaryDirectory.appending(path: "cengine-archive-\(UUID().uuidString)", directoryHint: .isDirectory)
        let archiveURL = temporary.appending(path: "upload.tar")
        let extracted = temporary.appending(path: "contents", directoryHint: .isDirectory)
        defer { try? FileManager.default.removeItem(at: temporary) }
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
        try archive.write(to: archiveURL, options: .atomic)
        let ownership = try SystemTar.ownership(in: archive)
        try SystemTar.extract(archiveURL, to: extracted)
        try await backend.copyIn(container, extractedDirectory: extracted, destination: path, ownership: ownership)
    }

    public func copyArchiveOutOfContainer(_ identifier: String, path: String) async throws -> Data {
        let container = try container(identifier)
        guard container.phase == .running else { throw EngineError(.conflict, "archive copy requires a running container") }
        guard path.hasPrefix("/") else { throw EngineError(.badRequest, "container path must be absolute") }
        let temporary = FileManager.default.temporaryDirectory.appending(path: "cengine-copyout-\(UUID().uuidString)", directoryHint: .isDirectory)
        let contents = temporary.appending(path: "contents", directoryHint: .isDirectory)
        let archiveURL = temporary.appending(path: "download.tar")
        defer { try? FileManager.default.removeItem(at: temporary) }
        try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
        try await backend.copyOut(container, source: path, destinationDirectory: contents)
        try SystemTar.create(from: contents, at: archiveURL)
        return try Data(contentsOf: archiveURL)
    }
}

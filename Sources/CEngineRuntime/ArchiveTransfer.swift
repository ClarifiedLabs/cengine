import CEngineCore
import ContainerizationArchive
import Foundation

extension EngineRuntime {
    public func copyArchiveIntoContainer(_ identifier: String, path: String, archive: Data) async throws {
        let container = try container(identifier)
        guard container.phase == .running else {
            throw EngineError(.conflict, "archive copy currently requires a running container")
        }
        guard path.hasPrefix("/") else { throw EngineError(.badRequest, "container path must be absolute") }

        let temporary = FileManager.default.temporaryDirectory.appending(path: "cengine-archive-\(UUID().uuidString)", directoryHint: .isDirectory)
        let archiveURL = temporary.appending(path: "upload.tar")
        let extracted = temporary.appending(path: "contents", directoryHint: .isDirectory)
        defer { try? FileManager.default.removeItem(at: temporary) }
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
        try archive.write(to: archiveURL, options: .atomic)
        let rejected = try ArchiveReader(file: archiveURL).extractContents(to: extracted)
        guard rejected.isEmpty else {
            throw EngineError(.badRequest, "archive contains unsafe paths: \(rejected.joined(separator: ", "))")
        }
        try await backend.copyIn(container, extractedDirectory: extracted, destination: path)
    }
}

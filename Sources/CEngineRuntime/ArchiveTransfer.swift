import CEngineCore
import ContainerizationArchive
import Foundation

extension EngineRuntime {
    public func copyArchiveIntoContainer(_ identifier: String, path: String, archive: Data) async throws {
        let container = try container(identifier)
        guard container.phase == .created || container.phase == .running else {
            throw EngineError(.conflict, "archive copy requires a created or running container")
        }
        guard path.hasPrefix("/") else { throw EngineError(.badRequest, "container path must be absolute") }
        // An empty tar is two 512-byte zero blocks. Buildx sends this when no
        // optional builder configuration files need to be installed.
        if archive.count >= 1_024 && archive.allSatisfy({ $0 == 0 }) { return }

        let temporary = FileManager.default.temporaryDirectory.appending(path: "cengine-archive-\(UUID().uuidString)", directoryHint: .isDirectory)
        let archiveURL = temporary.appending(path: "upload.tar")
        let extracted = temporary.appending(path: "contents", directoryHint: .isDirectory)
        defer { try? FileManager.default.removeItem(at: temporary) }
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
        try archive.write(to: archiveURL, options: .atomic)
        let rejected: [String]
        do {
            rejected = try ArchiveReader(file: archiveURL).extractContents(to: extracted)
        } catch let error as LibArchiveError {
            throw EngineError(.badRequest, "invalid archive (\(archive.count) bytes): \(error.description)")
        } catch let error as ArchiveError {
            throw EngineError(.badRequest, "invalid archive (\(archive.count) bytes): \(error.description)")
        }
        guard rejected.isEmpty else {
            throw EngineError(.badRequest, "archive contains unsafe paths: \(rejected.joined(separator: ", "))")
        }
        try await backend.copyIn(container, extractedDirectory: extracted, destination: path)
    }
}

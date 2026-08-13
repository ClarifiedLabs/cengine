import CEngineCore
import Darwin
import Foundation

extension EngineRuntime {
    public func copyArchiveIntoContainer(
        _ identifier: String,
        path: String,
        archive: Data
    ) async throws {
        guard UInt64(archive.count) <= ArchivePolicy.default.wireBytes else {
            throw EngineError(.payloadTooLarge, "archive upload exceeds its wire size limit")
        }
        if archive.count >= 1_024 && archive.allSatisfy({ $0 == 0 }) { return }
        let temporary = FileManager.default.temporaryDirectory.appending(
            path: "cengine-archive-upload-\(UUID().uuidString)", directoryHint: .isDirectory
        )
        let archiveURL = temporary.appending(path: "upload.tar")
        defer { try? FileManager.default.removeItem(at: temporary) }
        try FileManager.default.createDirectory(
            at: temporary,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        try writeArchiveUploadOwnerOnly(archive, to: archiveURL)
        try await copyArchiveIntoContainer(
            identifier, path: path, archiveURL: archiveURL
        )
    }

    public func copyArchiveIntoContainer(
        _ identifier: String,
        path: String,
        archiveURL: URL
    ) async throws {
        try requireCanonicalSnapshotWritable()
        let container = try container(identifier)
        try requireBackendExecutionAvailable(container)
        guard container.phase == .created || container.phase == .running else {
            throw EngineError(
                .conflict,
                "archive copy requires a created or running container"
            )
        }
        try validateArchiveContainerPath(path)
        let temporary = FileManager.default.temporaryDirectory.appending(
            path: "cengine-archive-\(UUID().uuidString)", directoryHint: .isDirectory
        )
        let extracted = temporary.appending(path: "contents", directoryHint: .isDirectory)
        defer { try? FileManager.default.removeItem(at: temporary) }
        try FileManager.default.createDirectory(
            at: temporary,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let ownership = try SystemTar.extract(archiveURL, to: extracted)
        try await backend.copyIn(
            container,
            extractedDirectory: extracted,
            destination: path,
            ownership: ownership
        )
    }

    public func copyArchiveOutOfContainer(
        _ identifier: String,
        path: String
    ) async throws -> Data {
        let temporary = FileManager.default.temporaryDirectory.appending(
            path: ".cengine-copyout-\(UUID().uuidString).tar"
        )
        defer { try? FileManager.default.removeItem(at: temporary) }
        try await copyArchiveOutOfContainer(
            identifier, path: path, to: temporary
        )
        return try Data(contentsOf: temporary)
    }

    public func copyArchiveOutOfContainer(
        _ identifier: String,
        path: String,
        to archiveURL: URL
    ) async throws {
        let container = try container(identifier)
        try requireBackendExecutionAvailable(container)
        guard container.phase == .running else {
            throw EngineError(.conflict, "archive copy requires a running container")
        }
        try validateArchiveContainerPath(path)
        let temporary = FileManager.default.temporaryDirectory.appending(
            path: "cengine-copyout-\(UUID().uuidString)", directoryHint: .isDirectory
        )
        let contents = temporary.appending(path: "contents", directoryHint: .isDirectory)
        defer { try? FileManager.default.removeItem(at: temporary) }
        try FileManager.default.createDirectory(
            at: contents,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try await backend.copyOut(
            container, source: path, destinationDirectory: contents
        )
        try SystemTar.create(from: contents, at: archiveURL)
    }

    private func validateArchiveContainerPath(_ path: String) throws {
        guard path.hasPrefix("/"), !path.utf8.contains(0),
              !path.split(separator: "/", omittingEmptySubsequences: false)
                .contains("..") else {
            throw EngineError(.badRequest, "container path must be a confined absolute path")
        }
    }

    private func writeArchiveUploadOwnerOnly(_ data: Data, to url: URL) throws {
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

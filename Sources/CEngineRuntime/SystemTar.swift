import CEngineCore
import Darwin
import Foundation

/// Archive facade retained for call-site compatibility. Untrusted extraction
/// and ownership derivation use the same one-pass bounded parser.
enum SystemTar {
    static func ownership(
        in archive: Data,
        policy: ArchivePolicy = .default
    ) throws -> [ArchiveOwnership] {
        guard UInt64(archive.count) <= policy.wireBytes else {
            throw EngineError(.payloadTooLarge, "archive input exceeds its wire size limit")
        }
        let temporary = FileManager.default.temporaryDirectory.appending(
            path: ".cengine-tar-inspect-\(UUID().uuidString)"
        )
        defer { try? FileManager.default.removeItem(at: temporary) }
        try ownerOnlyWrite(archive, to: temporary)
        return try TarArchive.inspect(temporary, policy: policy)
    }

    @discardableResult
    static func extract(
        _ archive: URL,
        to destination: URL,
        policy: ArchivePolicy = .default
    ) throws -> [ArchiveOwnership] {
        try TarArchive.extract(archive, to: destination, policy: policy)
    }

    /// Creation currently delegates formatting to the system tar for broad GNU
    /// and PAX interoperability. Its input is a private, descriptor-copied
    /// staging tree; output is owner-only and checked before publication.
    static func create(
        from directory: URL,
        at archive: URL,
        policy: ArchivePolicy = .default
    ) throws {
        let archiveFD = Darwin.open(
            archive.path,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            mode_t(0o600)
        )
        guard archiveFD >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        Darwin.close(archiveFD)

        let errors = archive.deletingLastPathComponent().appending(
            path: ".\(archive.lastPathComponent).\(UUID().uuidString).stderr"
        )
        let errorFD = Darwin.open(
            errors.path,
            O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            mode_t(0o600)
        )
        guard errorFD >= 0 else {
            try? FileManager.default.removeItem(at: archive)
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let errorHandle = FileHandle(fileDescriptor: errorFD, closeOnDealloc: true)
        defer {
            try? errorHandle.close()
            try? FileManager.default.removeItem(at: errors)
        }

        let process = Process()
        process.executableURL = URL(filePath: "/usr/bin/tar")
        process.arguments = ["-cpf", archive.path, "-C", directory.path, "."]
        var environment = ProcessInfo.processInfo.environment
        environment["COPYFILE_DISABLE"] = "1"
        process.environment = environment
        process.standardOutput = FileHandle.nullDevice
        process.standardError = errorHandle
        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            try? FileManager.default.removeItem(at: archive)
            throw error
        }
        guard process.terminationStatus == 0 else {
            try errorHandle.seek(toOffset: 0)
            let errorData = try errorHandle.read(upToCount: 64 * 1_024) ?? Data()
            try? FileManager.default.removeItem(at: archive)
            throw EngineError(
                .badRequest,
                "could not create tar archive: \(String(decoding: errorData, as: UTF8.self))"
            )
        }
        let output = Darwin.open(
            archive.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
        )
        guard output >= 0 else {
            try? FileManager.default.removeItem(at: archive)
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        defer { Darwin.close(output) }
        var information = stat()
        guard Darwin.fstat(output, &information) == 0,
              information.st_mode & S_IFMT == S_IFREG,
              information.st_size >= 0,
              UInt64(information.st_size) <= policy.outputBytes else {
            try? FileManager.default.removeItem(at: archive)
            throw EngineError(.payloadTooLarge, "archive output exceeds its size limit")
        }
        guard Darwin.fsync(output) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }

    private static func ownerOnlyWrite(_ data: Data, to url: URL) throws {
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
            try? FileManager.default.removeItem(at: url)
            throw error
        }
    }
}

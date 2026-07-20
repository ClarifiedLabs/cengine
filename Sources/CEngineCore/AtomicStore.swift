import Darwin
import Foundation

public enum AtomicStoreSaveBoundary: Equatable, Sendable {
    case replacementCompleted
    case directorySynchronized
}

public enum AtomicStoreLoadBoundary: Equatable, Sendable {
    case dataRead
}

public struct AtomicStorePersistenceAmbiguousError: Error, LocalizedError, Sendable {
    public let path: String
    public let detail: String

    public var errorDescription: String? {
        "state replacement at \(path) may have committed, but parent-directory durability "
            + "could not be confirmed: \(detail)"
    }
}

public struct AtomicStoreCanonicalStateUnavailableError: Error, LocalizedError, Sendable {
    public let path: String
    public let detail: String

    public var errorDescription: String? {
        "canonical state at \(path) is unavailable or cannot be proven reachable: \(detail)"
    }
}

public actor AtomicStore<Value: Codable & Sendable> {
    public static var schemaVersion: Int { 1 }
    private static var maximumStateBytes: Int { 64 * 1_024 * 1_024 }

    private struct Envelope: Codable {
        let schemaVersion: Int
        let value: Value
    }

    public let url: URL
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder
    private let loadBoundaryHook: (@Sendable (AtomicStoreLoadBoundary) throws -> Void)?
    private let saveBoundaryHook: (@Sendable (AtomicStoreSaveBoundary) throws -> Void)?
    /// Freeze the physical path once. `/var` is intentionally resolved to
    /// `/private/var` here; every later operation walks this exact path from
    /// the filesystem root without following symlinks.
    private let physicalDirectoryPath: String

    public init(
        url: URL,
        loadBoundaryHook: (@Sendable (AtomicStoreLoadBoundary) throws -> Void)? = nil,
        saveBoundaryHook: (@Sendable (AtomicStoreSaveBoundary) throws -> Void)? = nil
    ) {
        self.url = url
        self.physicalDirectoryPath = Self.frozenPhysicalPath(
            url.deletingLastPathComponent().standardizedFileURL.path
        )
        self.encoder = JSONEncoder()
        self.encoder.outputFormatting = [.sortedKeys]
        self.encoder.dateEncodingStrategy = .iso8601
        self.decoder = JSONDecoder()
        self.decoder.dateDecodingStrategy = .iso8601
        self.loadBoundaryHook = loadBoundaryHook
        self.saveBoundaryHook = saveBoundaryHook
    }

    public func load(default defaultValue: @autoclosure () -> Value) throws -> Value {
        do { return try loadRequired() }
        catch let error as POSIXError where error.code == .ENOENT { return defaultValue() }
        catch let error as AtomicStoreCanonicalStateUnavailableError
            where error.detail.contains("does not exist") { return defaultValue() }
    }

    /// Load only a canonical, descriptor-owned state file. This is required
    /// after an ambiguous save: absence must not fabricate a caller-provided
    /// snapshot and every ancestor must still name the directory selected at
    /// store initialization.
    public func loadRequired() throws -> Value {
        let directoryDescriptor: CInt
        do {
            directoryDescriptor = try Self.openPhysicalDirectory(
                physicalDirectoryPath
            )
        } catch let error as POSIXError where error.code == .ENOENT {
            throw AtomicStoreCanonicalStateUnavailableError(
                path: url.path, detail: "the canonical parent directory does not exist"
            )
        } catch {
            throw AtomicStoreCanonicalStateUnavailableError(
                path: url.path, detail: error.localizedDescription
            )
        }
        defer { Darwin.close(directoryDescriptor) }
        let identity = try Self.directoryIdentity(directoryDescriptor)
        let targetName = try Self.validatedTargetName(url.lastPathComponent)
        let descriptor = Darwin.openat(
            directoryDescriptor, targetName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            let code = POSIXErrorCode(rawValue: errno) ?? .EIO
            if code == .ENOENT {
                throw AtomicStoreCanonicalStateUnavailableError(
                    path: url.path, detail: "the canonical state file does not exist"
                )
            }
            throw AtomicStoreCanonicalStateUnavailableError(
                path: url.path, detail: POSIXError(code).localizedDescription
            )
        }
        defer { Darwin.close(descriptor) }
        var information = stat()
        guard Darwin.fstat(descriptor, &information) == 0,
              information.st_mode & S_IFMT == S_IFREG else {
            throw AtomicStoreCanonicalStateUnavailableError(
                path: url.path, detail: "the canonical state entry is not a regular file"
            )
        }
        guard information.st_size >= 0,
              information.st_size <= off_t(Self.maximumStateBytes) else {
            throw AtomicStoreCanonicalStateUnavailableError(
                path: url.path, detail: "the canonical state file exceeds the size limit"
            )
        }
        let targetIdentity = FileIdentity(information)
        let data: Data
        do {
            data = try Self.readAll(
                from: descriptor, maximumBytes: Self.maximumStateBytes
            )
            try loadBoundaryHook?(.dataRead)
        } catch {
            throw AtomicStoreCanonicalStateUnavailableError(
                path: url.path, detail: error.localizedDescription
            )
        }
        let envelope: Envelope
        do {
            envelope = try decoder.decode(Envelope.self, from: data)
        } catch let error as DecodingError {
            throw EngineError(
                .conflict,
                "state file at \(url.path) is incompatible: \(Self.describe(error))"
            )
        }
        guard envelope.schemaVersion == Self.schemaVersion else {
            throw EngineError(
                .conflict,
                "state file at \(url.path) uses unsupported schema \(envelope.schemaVersion)"
            )
        }
        guard Self.physicalPathStillNamesRegularFile(
            physicalDirectoryPath,
            directoryIdentity: identity,
            targetName: targetName,
            targetIdentity: targetIdentity
        ) else {
            throw AtomicStoreCanonicalStateUnavailableError(
                path: url.path,
                detail: "the canonical state path changed during the load"
            )
        }
        return envelope.value
    }

    public func save(_ value: Value) throws {
        let directory = URL(filePath: physicalDirectoryPath, directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let directoryDescriptor = try Self.openPhysicalDirectory(physicalDirectoryPath)
        defer { Darwin.close(directoryDescriptor) }
        let directoryIdentity = try Self.directoryIdentity(directoryDescriptor)
        let targetName = try Self.validatedTargetName(url.lastPathComponent)
        let temporaryName = ".\(targetName).\(UUID().uuidString).tmp"
        let data = try encoder.encode(Envelope(schemaVersion: Self.schemaVersion, value: value))
        guard data.count <= Self.maximumStateBytes else {
            throw EngineError(.conflict, "state file at \(url.path) exceeds the size limit")
        }
        let temporaryDescriptor = Darwin.openat(
            directoryDescriptor,
            temporaryName,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            S_IRUSR | S_IWUSR
        )
        guard temporaryDescriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        var temporaryIsOpen = true
        var replaced = false
        defer {
            if temporaryIsOpen { Darwin.close(temporaryDescriptor) }
            if !replaced { _ = Darwin.unlinkat(directoryDescriptor, temporaryName, 0) }
        }
        try Self.writeAll(data, to: temporaryDescriptor)
        guard Darwin.fsync(temporaryDescriptor) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let publishedIdentity = try Self.regularFileIdentity(temporaryDescriptor)
        guard Darwin.close(temporaryDescriptor) == 0 else {
            temporaryIsOpen = false
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        temporaryIsOpen = false
        guard Darwin.renameat(
            directoryDescriptor, temporaryName, directoryDescriptor, targetName
        ) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        replaced = true
        do {
            try saveBoundaryHook?(.replacementCompleted)
            guard Darwin.fsync(directoryDescriptor) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            try saveBoundaryHook?(.directorySynchronized)
            guard Self.physicalPathStillNamesRegularFile(
                physicalDirectoryPath,
                directoryIdentity: directoryIdentity,
                targetName: targetName,
                targetIdentity: publishedIdentity
            ) else {
                throw EngineError(
                    .conflict,
                    "atomic-store canonical path changed after state publication"
                )
            }
        } catch {
            throw AtomicStorePersistenceAmbiguousError(
                path: url.path,
                detail: error.localizedDescription
            )
        }
    }

    private struct FileIdentity: Equatable {
        let device: UInt64
        let inode: UInt64

        init(_ information: stat) {
            device = UInt64(information.st_dev)
            inode = UInt64(information.st_ino)
        }
    }

    private static func validatedTargetName(_ name: String) throws -> String {
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/") else {
            throw EngineError(.internalError, "invalid atomic-store filename")
        }
        return name
    }

    /// `URL.resolvingSymlinksInPath()` does not reliably resolve an existing
    /// symlinked ancestor when the final directory does not exist yet. Resolve
    /// the longest existing prefix with `realpath(3)`, then append the missing
    /// lexical suffix. This freezes `/var` as `/private/var` even for a brand
    /// new store and remains deterministic under parallel store creation.
    private nonisolated static func frozenPhysicalPath(_ path: String) -> String {
        var existing = URL(filePath: path, directoryHint: .isDirectory)
        var missing: [String] = []
        while true {
            if let resolved = Darwin.realpath(existing.path, nil) {
                defer { free(resolved) }
                var physical = URL(
                    filePath: String(cString: resolved), directoryHint: .isDirectory
                )
                for component in missing.reversed() {
                    physical.append(path: component, directoryHint: .isDirectory)
                }
                // `standardizedFileURL` rewrites the physical `/private/var`
                // spelling back to the public `/var` symlink on macOS. Keep
                // the exact path returned by realpath(3).
                return physical.path
            }
            guard existing.path != "/" else { return path }
            missing.append(existing.lastPathComponent)
            existing.deleteLastPathComponent()
        }
    }

    private static func directoryIdentity(_ descriptor: CInt) throws -> FileIdentity {
        var information = stat()
        guard Darwin.fstat(descriptor, &information) == 0,
              information.st_mode & S_IFMT == S_IFDIR else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        return FileIdentity(information)
    }

    private static func regularFileIdentity(_ descriptor: CInt) throws -> FileIdentity {
        var information = stat()
        guard Darwin.fstat(descriptor, &information) == 0,
              information.st_mode & S_IFMT == S_IFREG else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        return FileIdentity(information)
    }

    /// Resolve an already-physical absolute path by walking from `/` and
    /// refusing every symlink. Holding each parent until its child is opened
    /// prevents a detached ancestor descriptor from masquerading as canonical.
    private static func openPhysicalDirectory(_ path: String) throws -> CInt {
        guard path.hasPrefix("/") else {
            throw EngineError(.internalError, "atomic-store path is not absolute")
        }
        let standardized = path
        var descriptor = Darwin.open(
            "/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        if standardized == "/" { return descriptor }
        do {
            for component in standardized.split(separator: "/").map(String.init) {
                guard component != ".", component != ".." else {
                    throw EngineError(.internalError, "invalid atomic-store path component")
                }
                let child = Darwin.openat(
                    descriptor, component,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
                )
                guard child >= 0 else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
                Darwin.close(descriptor)
                descriptor = child
            }
            return descriptor
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }

    private static func physicalPathStillNamesRegularFile(
        _ path: String,
        directoryIdentity: FileIdentity,
        targetName: String,
        targetIdentity: FileIdentity
    ) -> Bool {
        guard let descriptor = try? openPhysicalDirectory(path) else { return false }
        defer { Darwin.close(descriptor) }
        guard (try? Self.directoryIdentity(descriptor)) == directoryIdentity else {
            return false
        }
        var information = stat()
        guard Darwin.fstatat(
            descriptor, targetName, &information, AT_SYMLINK_NOFOLLOW
        ) == 0, information.st_mode & S_IFMT == S_IFREG else { return false }
        return FileIdentity(information) == targetIdentity
    }

    private static func writeAll(_ data: Data, to descriptor: CInt) throws {
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(
                    descriptor,
                    bytes.baseAddress!.advanced(by: offset),
                    bytes.count - offset
                )
                if count > 0 { offset += count; continue }
                if errno == EINTR { continue }
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        }
    }

    private static func readAll(from descriptor: CInt, maximumBytes: Int) throws -> Data {
        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
        while true {
            let count = Darwin.read(descriptor, &buffer, buffer.count)
            if count > 0 {
                guard count <= maximumBytes - result.count else {
                    throw EngineError(.conflict, "atomic-store state exceeds the size limit")
                }
                result.append(contentsOf: buffer.prefix(count))
                continue
            }
            if count == 0 { return result }
            if errno == EINTR { continue }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }

    private static func describe(_ error: DecodingError) -> String {
        switch error {
        case .keyNotFound(let key, let context):
            return "missing required field '\(key.stringValue)' at \(path(context.codingPath))"
        case .valueNotFound(_, let context):
            return "missing required value at \(path(context.codingPath))"
        case .typeMismatch(_, let context):
            return "invalid value at \(path(context.codingPath)): \(context.debugDescription)"
        case .dataCorrupted(let context):
            return "invalid data at \(path(context.codingPath)): \(context.debugDescription)"
        @unknown default:
            return String(describing: error)
        }
    }

    private static func path(_ codingPath: [any CodingKey]) -> String {
        guard !codingPath.isEmpty else { return "the document root" }
        var result = ""
        for key in codingPath {
            if let index = key.intValue {
                result += "[\(index)]"
            } else {
                if !result.isEmpty { result += "." }
                result += key.stringValue
            }
        }
        return result
    }
}

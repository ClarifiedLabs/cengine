#if os(macOS)
import CEngineCore
import Darwin
import Foundation

struct PersistentFileIdentity: Codable, Equatable, Hashable, Sendable {
    let device: UInt64
    let inode: UInt64

    init(device: UInt64, inode: UInt64) {
        self.device = device
        self.inode = inode
    }

    init(_ information: stat) {
        device = UInt64(information.st_dev)
        inode = UInt64(information.st_ino)
    }
}

struct PersistentFilesystemIdentity: Equatable, Sendable {
    let device: UInt64
    let fileSystemIdentifier: [UInt8]
    let mountPoint: [UInt8]

    init(
        device: UInt64,
        fileSystemIdentifier: [UInt8],
        mountPoint: [UInt8] = []
    ) {
        self.device = device
        self.fileSystemIdentifier = fileSystemIdentifier
        self.mountPoint = mountPoint
    }
}

enum PersistentRegularFileAccess {
    case readOnly
    case writeOnly
    case readWrite

    var openFlag: CInt {
        switch self {
        case .readOnly: O_RDONLY
        case .writeOnly: O_WRONLY
        case .readWrite: O_RDWR
        }
    }
}

enum PersistentDisposalBoundary: String, CaseIterable, Sendable {
    case journalWritten
    case journalFileSynchronized
    case journalDirectorySynchronized
    case rootClaimed
    case rootClaimSynchronized
    case rootClaimRecorded
    case childClaimed
    case childClaimSynchronized
    case childRemoved
    case rootRemoved
    case rootRemovalSynchronized
    case journalRemoved
    case journalRemovalSynchronized
    case claimRecordRemoved
    case claimRecordRemovalSynchronized
}

typealias PersistentDisposalHook = (PersistentDisposalBoundary) throws -> Void

enum PersistentRuntimeArtifactBoundary: Equatable, Sendable {
    case creationJournalSynchronized
    case stagingDirectorySynchronized
    case stagedOwnershipSynchronized
    case artifactExposed(String)
    case runtimeDirectorySynchronized
    case publicationSynchronized
    case deletionObserved(String)
    case deletionClaimed(String)
    case deletionRemoved(String)
}

typealias PersistentRuntimeArtifactHook = (PersistentRuntimeArtifactBoundary) throws -> Void

private struct PersistentDisposalRecord: Codable, Sendable {
    static let currentSchemaVersion = 1

    let schemaVersion: Int
    let originalName: String
    let claimName: String
    let parentIdentity: PersistentFileIdentity
    let originalIdentity: PersistentFileIdentity
}

private struct PersistentDisposalTraversalConflict: Error {
    let underlying: Error
}

/// Descriptor-owned directory access for recovery metadata. Holding the
/// directory descriptor makes every child read independent of later path
/// replacement, while openat/O_NOFOLLOW and fstat reject symlinks, devices,
/// sockets, and FIFOs before any potentially blocking read.
final class PersistentStateDirectory: @unchecked Sendable {
    static let maximumStateBytes = 1 * 1_024 * 1_024

    let descriptor: CInt
    let identity: PersistentFileIdentity
    let url: URL

    private init(descriptor: CInt, identity: PersistentFileIdentity, url: URL) {
        self.descriptor = descriptor
        self.identity = identity
        self.url = url
    }

    deinit { Darwin.close(descriptor) }

    static func open(_ url: URL) throws -> PersistentStateDirectory {
        let logicalURL = url.standardizedFileURL
        let physicalURL = URL(
            filePath: physicalPath(for: logicalURL.path),
            directoryHint: .isDirectory
        )
        let descriptor = try openPhysicalDirectory(physicalURL.path)
        do {
            // Keep the caller's lexical `/var` or `/tmp` spelling in durable
            // ownership records. Descriptor acquisition still walks the
            // corresponding physical `/private/...` chain without symlinks.
            return try validated(descriptor: descriptor, url: logicalURL)
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }

    static func openIfPresent(_ url: URL) throws -> PersistentStateDirectory? {
        do { return try open(url) }
        catch let error as POSIXError where error.code == .ENOENT { return nil }
    }

    func openDirectory(named name: String) throws -> PersistentStateDirectory {
        try Self.validateComponent(name)
        let child = Darwin.openat(
            descriptor,
            name,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
        )
        guard child >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        do {
            return try Self.validated(
                descriptor: child, url: url.appending(path: name, directoryHint: .isDirectory)
            )
        } catch {
            Darwin.close(child)
            throw error
        }
    }

    func openDirectoryIfPresent(named name: String) throws -> PersistentStateDirectory? {
        do { return try openDirectory(named: name) }
        catch let error as POSIXError where error.code == .ENOENT { return nil }
    }

    func openOrCreateDirectory(
        named name: String, permissions: mode_t = 0o700
    ) throws -> PersistentStateDirectory {
        do {
            return try openDirectory(named: name)
        } catch let error as POSIXError where error.code == .ENOENT {
            guard Darwin.mkdirat(descriptor, name, permissions) == 0 else {
                if errno == EEXIST { return try openDirectory(named: name) }
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            guard Darwin.fsync(descriptor) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            return try openDirectory(named: name)
        }
    }

    func createDirectory(
        named name: String, permissions: mode_t = 0o700
    ) throws -> PersistentStateDirectory {
        try Self.validateComponent(name)
        guard Darwin.mkdirat(descriptor, name, permissions) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        guard Darwin.fsync(descriptor) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        return try openDirectory(named: name)
    }

    func pathStillNamesThisDirectory() -> Bool {
        guard let current = try? Self.open(url) else { return false }
        return current.identity == identity
    }

    func entryNames() throws -> [String] {
        // dup(2) shares the directory stream offset with its source descriptor.
        // Opening "." relative to the held descriptor creates an independent
        // open-file description so every enumeration starts at the beginning.
        let scan = Darwin.openat(
            descriptor, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
        )
        guard scan >= 0, let stream = fdopendir(scan) else {
            if scan >= 0 { Darwin.close(scan) }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        defer { closedir(stream) }
        var names: [String] = []
        errno = 0
        while let entry = readdir(stream) {
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) {
                    String(cString: $0)
                }
            }
            if name != "." && name != ".." { names.append(name) }
            errno = 0
        }
        guard errno == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        return names.sorted()
    }

    func readRegularFile(
        named name: String,
        maximumBytes: Int = maximumStateBytes,
        required: Bool = true
    ) throws -> Data? {
        try Self.validateComponent(name)
        let file = Darwin.openat(
            descriptor, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
        )
        guard file >= 0 else {
            if errno == ENOENT, !required { return nil }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        defer { Darwin.close(file) }
        var information = stat()
        guard Darwin.fstat(file, &information) == 0,
              information.st_mode & S_IFMT == S_IFREG,
              information.st_size >= 0,
              information.st_size <= off_t(maximumBytes) else {
            throw EngineError(.internalError, "unsafe persistent state file \(url.appending(path: name).path)")
        }
        var data = Data()
        data.reserveCapacity(Int(information.st_size))
        var buffer = [UInt8](repeating: 0, count: 16 * 1_024)
        while true {
            let count = buffer.withUnsafeMutableBytes {
                Darwin.read(file, $0.baseAddress, min($0.count, maximumBytes + 1 - data.count))
            }
            if count > 0 {
                data.append(contentsOf: buffer.prefix(count))
                guard data.count <= maximumBytes else {
                    throw EngineError(.internalError, "persistent state file exceeds size limit")
                }
                continue
            }
            if count == 0 { return data }
            if errno == EINTR { continue }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }

    func containsRegularFile(named name: String) throws -> Bool {
        try Self.validateComponent(name)
        var information = stat()
        guard Darwin.fstatat(
            descriptor, name, &information, AT_SYMLINK_NOFOLLOW
        ) == 0 else {
            if errno == ENOENT { return false }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        return information.st_mode & S_IFMT == S_IFREG
    }

    /// Creates a new sparse regular file relative to the held directory. The
    /// exclusive, no-follow open is intentional: preparation must never adopt
    /// an old writable disk or follow a path that was replaced with a symlink.
    func createSparseRegularFile(
        named name: String,
        size: UInt64,
        permissions: mode_t = S_IRUSR | S_IWUSR
    ) throws -> PersistentFileIdentity {
        try Self.validateComponent(name)
        guard size <= UInt64(Int64.max) else {
            throw EngineError(.internalError, "sparse persistent file size is too large")
        }
        let file = Darwin.openat(
            descriptor,
            name,
            O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
            permissions
        )
        guard file >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        var createdIdentity: PersistentFileIdentity?
        var completed = false
        defer {
            Darwin.close(file)
            if !completed, let createdIdentity,
               let current = try? entryMetadata(named: name),
               current.identity == createdIdentity,
               current.type == S_IFREG {
                _ = Darwin.unlinkat(descriptor, name, 0)
                _ = Darwin.fsync(descriptor)
            }
        }

        var information = stat()
        guard Darwin.fstat(file, &information) == 0,
              information.st_mode & S_IFMT == S_IFREG else {
            throw EngineError(
                .internalError,
                "unsafe persistent sparse file \(url.appending(path: name).path)"
            )
        }
        let identity = PersistentFileIdentity(information)
        createdIdentity = identity
        guard Darwin.ftruncate(file, off_t(size)) == 0,
              Darwin.fchmod(file, permissions) == 0,
              Darwin.fsync(file) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        var finalInformation = stat()
        guard Darwin.fstat(file, &finalInformation) == 0,
              finalInformation.st_mode & S_IFMT == S_IFREG,
              PersistentFileIdentity(finalInformation) == identity,
              finalInformation.st_size == off_t(size),
              let current = try entryMetadata(named: name),
              current.identity == identity,
              current.type == S_IFREG,
              Darwin.fsync(descriptor) == 0 else {
            throw EngineError(
                .internalError,
                "persistent sparse file changed during creation"
            )
        }
        completed = true
        return identity
    }

    /// Opens and validates a regular file without following its final path
    /// component, then proves the name still identifies the opened inode.
    func regularFileIdentity(
        named name: String,
        expectedIdentity: PersistentFileIdentity? = nil,
        expectedSize: UInt64? = nil
    ) throws -> PersistentFileIdentity {
        try Self.validateComponent(name)
        let file = Darwin.openat(
            descriptor, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
        )
        guard file >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        defer { Darwin.close(file) }
        var information = stat()
        guard Darwin.fstat(file, &information) == 0,
              information.st_mode & S_IFMT == S_IFREG,
              information.st_size >= 0 else {
            throw EngineError(
                .internalError,
                "unsafe persistent regular file \(url.appending(path: name).path)"
            )
        }
        let identity = PersistentFileIdentity(information)
        guard expectedIdentity == nil || expectedIdentity == identity,
              expectedSize == nil || UInt64(information.st_size) == expectedSize,
              let current = try entryMetadata(named: name),
              current.identity == identity,
              current.type == S_IFREG else {
            throw EngineError(
                .conflict,
                "persistent regular file changed during validation"
            )
        }
        return identity
    }

    /// Returns an owned handle only after the descriptor and its directory
    /// entry both exactly match the expected regular-file identity. Callers
    /// may safely keep using the handle if the path is subsequently replaced.
    func openRegularFile(
        named name: String,
        expectedIdentity: PersistentFileIdentity? = nil,
        access: PersistentRegularFileAccess
    ) throws -> (handle: FileHandle, identity: PersistentFileIdentity) {
        try Self.validateComponent(name)
        let file = Darwin.openat(
            descriptor,
            name,
            access.openFlag | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
        )
        guard file >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        var information = stat()
        guard Darwin.fstat(file, &information) == 0,
              information.st_mode & S_IFMT == S_IFREG else {
            Darwin.close(file)
            throw EngineError(
                .internalError,
                "unsafe persistent regular file \(url.appending(path: name).path)"
            )
        }
        let identity = PersistentFileIdentity(information)
        guard expectedIdentity == nil || expectedIdentity == identity,
              let current = try entryMetadata(named: name),
              current.identity == identity,
              current.type == S_IFREG else {
            Darwin.close(file)
            throw EngineError(
                .conflict,
                "persistent regular file changed while opening its handle"
            )
        }
        return (
            FileHandle(fileDescriptor: file, closeOnDealloc: true),
            identity
        )
    }

    func openOrCreateRegularFile(
        named name: String,
        access: PersistentRegularFileAccess = .readWrite,
        permissions: mode_t = S_IRUSR | S_IWUSR
    ) throws -> (handle: FileHandle, identity: PersistentFileIdentity) {
        do {
            return try openRegularFile(named: name, access: access)
        } catch let error as POSIXError where error.code == .ENOENT {
            do {
                let identity = try createSparseRegularFile(
                    named: name, size: 0, permissions: permissions
                )
                return try openRegularFile(
                    named: name, expectedIdentity: identity, access: access
                )
            } catch let creationError as POSIXError where creationError.code == .EEXIST {
                return try openRegularFile(named: name, access: access)
            }
        }
    }

    func removeRegularFileIfPresent(named name: String) throws {
        guard let metadata = try entryMetadata(named: name) else { return }
        guard metadata.type == S_IFREG else {
            throw EngineError(
                .conflict,
                "refusing to remove non-regular persistent file \(name)"
            )
        }
        let removed = try removeEntryIfMatching(
            named: name,
            identity: metadata.identity,
            type: S_IFREG,
            claimName: ".cengine-remove-\(UUID().uuidString.lowercased())"
        )
        if removed { return }
        guard try entryMetadata(named: name) == nil else {
            throw EngineError(.conflict, "persistent file changed before removal")
        }
    }

    func ensureEmptyRegularFile(named name: String) throws {
        if let metadata = try entryMetadata(named: name) {
            guard metadata.type == S_IFREG else {
                throw EngineError(
                    .conflict,
                    "persistent marker \(name) is not a regular file"
                )
            }
            _ = try regularFileIdentity(
                named: name,
                expectedIdentity: metadata.identity,
                expectedSize: 0
            )
            return
        }
        _ = try createSparseRegularFile(named: name, size: 0)
    }

    func entryMetadata(named name: String) throws -> (identity: PersistentFileIdentity, type: mode_t)? {
        try Self.validateComponent(name)
        var information = stat()
        guard Darwin.fstatat(
            descriptor, name, &information, AT_SYMLINK_NOFOLLOW
        ) == 0 else {
            if errno == ENOENT { return nil }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        return (PersistentFileIdentity(information), information.st_mode & S_IFMT)
    }

    func removeEntryIfMatching(
        named name: String,
        identity expectedIdentity: PersistentFileIdentity,
        type expectedType: mode_t,
        claimName: String,
        hook: PersistentRuntimeArtifactHook? = nil
    ) throws -> Bool {
        try Self.validateComponent(claimName)

        if let claimed = try entryMetadata(named: claimName) {
            guard claimed.identity == expectedIdentity,
                  claimed.type == expectedType else {
                if try entryMetadata(named: name) == nil,
                   Darwin.renameatx_np(
                       descriptor, claimName, descriptor, name, UInt32(RENAME_EXCL)
                   ) == 0 {
                    try synchronize()
                    return false
                }
                throw EngineError(
                    .conflict, "runtime artifact deletion claim contains a replacement"
                )
            }
            // Replay of a durable claim must revalidate the final component
            // after the same injectable boundary used by a fresh rename. A
            // claim-name ABA between initial observation and unlink must never
            // authorize deletion of the replacement inode.
            try hook?(.deletionClaimed(name))
            guard let revalidated = try entryMetadata(named: claimName),
                  revalidated.identity == expectedIdentity,
                  revalidated.type == expectedType else {
                if try entryMetadata(named: name) == nil,
                   Darwin.renameatx_np(
                       descriptor, claimName, descriptor, name, UInt32(RENAME_EXCL)
                   ) == 0 {
                    try synchronize()
                    return false
                }
                throw EngineError(
                    .conflict, "runtime artifact deletion claim changed before removal"
                )
            }
            guard Darwin.unlinkat(descriptor, claimName, 0) == 0 else {
                if errno == ENOENT { return false }
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            try hook?(.deletionRemoved(name))
            try synchronize()
            return true
        }

        guard let metadata = try entryMetadata(named: name),
              metadata.identity == expectedIdentity,
              metadata.type == expectedType else { return false }
        try hook?(.deletionObserved(name))
        guard Darwin.renameatx_np(
            descriptor, name, descriptor, claimName, UInt32(RENAME_EXCL)
        ) == 0 else {
            if errno == ENOENT { return false }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try hook?(.deletionClaimed(name))
        guard let claimed = try entryMetadata(named: claimName),
              claimed.identity == expectedIdentity,
              claimed.type == expectedType else {
            guard try entryMetadata(named: name) == nil,
                  Darwin.renameatx_np(
                      descriptor, claimName, descriptor, name, UInt32(RENAME_EXCL)
                  ) == 0 else {
                throw EngineError(
                    .conflict, "runtime artifact replacement could not be restored"
                )
            }
            try synchronize()
            return false
        }
        guard Darwin.unlinkat(descriptor, claimName, 0) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try hook?(.deletionRemoved(name))
        try synchronize()
        return true
    }

    func synchronize() throws {
        guard Darwin.fsync(descriptor) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }

    func writeExclusiveRegularFile(
        named name: String,
        data: Data,
        permissions: mode_t = S_IRUSR | S_IWUSR
    ) throws {
        try Self.validateComponent(name)
        guard data.count <= Self.maximumStateBytes else {
            throw EngineError(.internalError, "persistent state file exceeds size limit")
        }
        let file = Darwin.openat(
            descriptor,
            name,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
            permissions
        )
        guard file >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        var completed = false
        defer {
            Darwin.close(file)
            if !completed { _ = Darwin.unlinkat(descriptor, name, 0) }
        }
        try Self.writeAll(data, to: file)
        guard Darwin.fsync(file) == 0, Darwin.fsync(descriptor) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        completed = true
    }

    func replaceRegularFile(
        named name: String,
        data: Data,
        permissions: mode_t = S_IRUSR | S_IWUSR
    ) throws {
        try Self.validateComponent(name)
        guard data.count <= Self.maximumStateBytes else {
            throw EngineError(.internalError, "persistent state file exceeds size limit")
        }
        let temporaryName = ".cengine-state-\(UUID().uuidString.lowercased())"
        let file = Darwin.openat(
            descriptor,
            temporaryName,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
            permissions
        )
        guard file >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        var fileIsOpen = true
        var renamed = false
        defer {
            if fileIsOpen { Darwin.close(file) }
            if !renamed { _ = Darwin.unlinkat(descriptor, temporaryName, 0) }
        }
        try Self.writeAll(data, to: file)
        guard Darwin.fchmod(file, permissions) == 0, Darwin.fsync(file) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        guard Darwin.close(file) == 0 else {
            fileIsOpen = false
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        fileIsOpen = false
        guard Darwin.renameat(descriptor, temporaryName, descriptor, name) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        renamed = true
        guard Darwin.fsync(descriptor) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }

    /// Recovers every identity-bound deletion that was durably announced in
    /// this directory. Callers run this before interpreting ordinary entries.
    /// A journal always precedes its rename claim, so a restart can determine
    /// whether to claim the original inode, resume the claim, or finish journal
    /// retirement after the inode was already removed.
    func reconcileDisposals(hook: PersistentDisposalHook? = nil) throws {
        for (journalName, record) in try disposalRecords() {
            try resumeDisposal(
                journalName: journalName,
                record: record,
                hook: hook
            )
        }
        for name in try entryNames() where Self.isClaimedRecordName(name) {
            guard try containsRegularFile(named: name),
                  Darwin.unlinkat(descriptor, name, 0) == 0 else {
                throw EngineError(.internalError, "unsafe persistent disposal claim record")
            }
            guard Darwin.fsync(descriptor) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        }
        let remainingClaims = try entryNames().filter { Self.isDisposalClaimName($0) }
        guard remainingClaims.isEmpty else {
            throw EngineError(
                .internalError,
                "persistent disposal claim has no recoverable identity journal"
            )
        }
    }

    func reconciledEntryNames() throws -> [String] {
        try reconcileDisposals()
        return try entryNames()
    }

    func pendingDisposalIdentity(named name: String) throws -> PersistentFileIdentity? {
        try Self.validateComponent(name)
        let matches = try disposalRecords().filter { $0.record.originalName == name }
        guard matches.count <= 1 else {
            throw EngineError(.internalError, "duplicate persistent disposal journals")
        }
        return matches.first?.record.originalIdentity
    }

    func containsDisposalClaim(identity: PersistentFileIdentity) throws -> Bool {
        for name in try entryNames() where Self.isDisposalClaimName(name) {
            if try entryMetadata(named: name)?.identity == identity { return true }
        }
        return false
    }

    /// Durably announces and atomically claims the verified name before walking
    /// any descendants. A replacement at the original name is never traversed.
    /// Retrying with the original name resumes the identity-bound claim.
    func disposeDirectory(
        named name: String,
        expectedIdentity: PersistentFileIdentity,
        hook: PersistentDisposalHook? = nil
    ) throws {
        try Self.validateComponent(name)
        let existing = try disposalRecords().filter { $0.record.originalName == name }
        guard existing.count <= 1 else {
            throw EngineError(.internalError, "duplicate persistent disposal journals")
        }
        if let existing = existing.first {
            guard existing.record.originalIdentity == expectedIdentity else {
                throw EngineError(.conflict, "persistent disposal identity changed")
            }
            try resumeDisposal(
                journalName: existing.journalName,
                record: existing.record,
                hook: hook
            )
            return
        }

        guard let original = try openDirectoryIfPresent(named: name) else {
            // Successful disposal is idempotent, including a retry after the
            // root and its journal were both durably removed.
            return
        }
        guard original.identity == expectedIdentity else {
            throw EngineError(.conflict, "persistent directory identity changed before disposal")
        }
        let identifier = UUID().uuidString.lowercased()
        let journalName = "\(Self.disposalJournalPrefix)\(identifier).json"
        let record = PersistentDisposalRecord(
            schemaVersion: PersistentDisposalRecord.currentSchemaVersion,
            originalName: name,
            claimName: "\(Self.disposalClaimPrefix)\(identifier)",
            parentIdentity: identity,
            originalIdentity: expectedIdentity
        )
        try writeDisposalJournal(named: journalName, record: record, hook: hook)
        try resumeDisposal(journalName: journalName, record: record, hook: hook)
    }

    private static let disposalJournalPrefix = ".cengine-disposal-"
    private static let disposalClaimPrefix = ".cengine-disposal-claim-"
    private static let disposalClaimedSuffix = ".claimed"
    private static let childClaimPrefix = ".cengine-entry-claim-"

    private func disposalRecords() throws -> [(
        journalName: String, record: PersistentDisposalRecord
    )] {
        var records: [(String, PersistentDisposalRecord)] = []
        for name in try entryNames() where Self.isDisposalJournalName(name) {
            guard let data = try readRegularFile(named: name),
                  let record = try? JSONDecoder().decode(
                    PersistentDisposalRecord.self, from: data
                  ) else {
                let identifier = Self.disposalJournalIdentifier(name)
                let hasClaim = identifier.map {
                    (try? entryIdentity(named: "\(Self.disposalClaimPrefix)\($0)")) != nil
                } ?? true
                if !hasClaim {
                    // The rename is ordered after a complete, synchronized
                    // journal. An undecodable pre-rename fragment is safe to
                    // retire only when its UUID has no claim.
                    guard Darwin.unlinkat(descriptor, name, 0) == 0,
                          Darwin.fsync(descriptor) == 0 else {
                        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                    }
                    continue
                }
                throw EngineError(.internalError, "invalid persistent disposal journal")
            }
            try validate(record: record, journalName: name)
            records.append((name, record))
        }
        return records.sorted { $0.0 < $1.0 }
    }

    private func validate(
        record: PersistentDisposalRecord, journalName: String
    ) throws {
        try Self.validateComponent(record.originalName)
        try Self.validateComponent(record.claimName)
        guard record.schemaVersion == PersistentDisposalRecord.currentSchemaVersion,
              record.parentIdentity == identity,
              Self.isDisposalClaimName(record.claimName),
              let identifier = Self.disposalJournalIdentifier(journalName),
              record.claimName == "\(Self.disposalClaimPrefix)\(identifier)" else {
            throw EngineError(.internalError, "invalid persistent disposal journal ownership")
        }
    }

    private func writeDisposalJournal(
        named journalName: String,
        record: PersistentDisposalRecord,
        hook: PersistentDisposalHook?
    ) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(record)
        let file = Darwin.openat(
            descriptor,
            journalName,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
            S_IRUSR | S_IWUSR
        )
        guard file >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        defer { Darwin.close(file) }
        try Self.writeAll(data, to: file)
        try hook?(.journalWritten)
        guard Darwin.fsync(file) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try hook?(.journalFileSynchronized)
        guard Darwin.fsync(descriptor) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try hook?(.journalDirectorySynchronized)
    }

    private func resumeDisposal(
        journalName: String,
        record: PersistentDisposalRecord,
        hook: PersistentDisposalHook?
    ) throws {
        try validate(record: record, journalName: journalName)
        let claimRecordName = try claimedRecordName(forJournal: journalName)
        let claimWasRecorded = try containsRegularFile(named: claimRecordName)
        let claimIdentity = try entryIdentity(named: record.claimName)
        if let claimIdentity {
            guard claimIdentity == record.originalIdentity else {
                try restoreMismatchedRootClaimAndRetireJournal(
                    journalName: journalName, record: record
                )
                throw EngineError(.conflict, "persistent disposal claim identity changed")
            }
            if !claimWasRecorded {
                try recordClaim(named: claimRecordName, hook: hook)
            }
        } else if claimWasRecorded {
            if try entryIdentity(named: record.originalName) == record.originalIdentity {
                throw EngineError(
                    .conflict,
                    "claimed persistent disposal root unexpectedly returned to its original name"
                )
            }
            // A replacement may already occupy the original name. It is not
            // the identity that was claimed and must remain untouched.
            try retireDisposalJournal(named: journalName, hook: hook)
            return
        } else if let originalIdentity = try entryIdentity(named: record.originalName) {
            guard originalIdentity == record.originalIdentity else {
                try retireDisposalJournal(named: journalName, hook: nil)
                throw EngineError(
                    .conflict,
                    "persistent disposal target was replaced before it could be claimed"
                )
            }
            guard Darwin.renameatx_np(
                descriptor,
                record.originalName,
                descriptor,
                record.claimName,
                UInt32(RENAME_EXCL)
            ) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            try hook?(.rootClaimed)
            guard Darwin.fsync(descriptor) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            try hook?(.rootClaimSynchronized)
            guard try entryIdentity(named: record.claimName) == record.originalIdentity else {
                try restoreMismatchedRootClaimAndRetireJournal(
                    journalName: journalName, record: record
                )
                throw EngineError(.conflict, "persistent disposal claim changed while claimed")
            }
            try recordClaim(named: claimRecordName, hook: hook)
        } else {
            try retireDisposalJournal(named: journalName, hook: nil)
            throw EngineError(
                .conflict,
                "persistent disposal target disappeared before it could be claimed"
            )
        }

        let claimed: PersistentStateDirectory
        do {
            claimed = try openDirectory(named: record.claimName)
        } catch {
            if try entryIdentity(named: record.claimName) != record.originalIdentity {
                try restoreMismatchedRootClaimAndRetireJournal(
                    journalName: journalName, record: record
                )
            }
            throw error
        }
        guard claimed.identity == record.originalIdentity else {
            try restoreMismatchedRootClaimAndRetireJournal(
                journalName: journalName, record: record
            )
            throw EngineError(.conflict, "claimed persistent directory identity changed")
        }
        let filesystem = try Self.filesystemIdentity(
            descriptor: claimed.descriptor, identity: claimed.identity
        )
        var visited: Set<PersistentFileIdentity> = []
        do {
            try claimed.removeAllEntries(
                rootFilesystem: filesystem,
                visited: &visited,
                hook: hook
            )
        } catch let conflict as PersistentDisposalTraversalConflict {
            if try entryIdentity(named: record.originalName) == nil,
               try entryIdentity(named: record.claimName) == record.originalIdentity,
               Darwin.renameatx_np(
                descriptor,
                record.claimName,
                descriptor,
                record.originalName,
                UInt32(RENAME_EXCL)
               ) == 0 {
                guard Darwin.fsync(descriptor) == 0 else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
                try retireDisposalJournal(named: journalName, hook: nil)
            }
            throw conflict.underlying
        }
        guard try entryIdentity(named: record.claimName) == record.originalIdentity else {
            throw EngineError(.conflict, "persistent disposal claim moved during traversal")
        }
        guard Darwin.unlinkat(descriptor, record.claimName, AT_REMOVEDIR) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try hook?(.rootRemoved)
        guard Darwin.fsync(descriptor) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try hook?(.rootRemovalSynchronized)
        try retireDisposalJournal(named: journalName, hook: hook)
    }

    private func recordClaim(
        named claimRecordName: String, hook: PersistentDisposalHook?
    ) throws {
        try writeExclusiveRegularFile(named: claimRecordName, data: Data())
        try hook?(.rootClaimRecorded)
    }

    private func restoreMismatchedRootClaimAndRetireJournal(
        journalName: String, record: PersistentDisposalRecord
    ) throws {
        guard try entryIdentity(named: record.originalName) == nil,
              Darwin.renameatx_np(
                descriptor,
                record.claimName,
                descriptor,
                record.originalName,
                UInt32(RENAME_EXCL)
              ) == 0 else {
            throw EngineError(
                .conflict,
                "persistent disposal could not safely restore a changed root claim"
            )
        }
        guard Darwin.fsync(descriptor) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try retireDisposalJournal(named: journalName, hook: nil)
    }

    private func retireDisposalJournal(
        named journalName: String, hook: PersistentDisposalHook?
    ) throws {
        if Darwin.unlinkat(descriptor, journalName, 0) != 0, errno != ENOENT {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try hook?(.journalRemoved)
        // Synchronize the journal unlink while the independently durable
        // claim record still proves that an absent claim/original means the
        // root was removed, not that it disappeared before the claim.
        guard Darwin.fsync(descriptor) == 0 else { return }
        try hook?(.journalRemovalSynchronized)
        let claimRecordName = try claimedRecordName(forJournal: journalName)
        if Darwin.unlinkat(descriptor, claimRecordName, 0) != 0, errno != ENOENT {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try hook?(.claimRecordRemoved)
        // The owned root was already durably removed. If this metadata fsync
        // fails, an orphaned claim record is itself safe to retire on replay.
        guard Darwin.fsync(descriptor) == 0 else { return }
        try hook?(.claimRecordRemovalSynchronized)
    }

    private func removeAllEntries(
        rootFilesystem: PersistentFilesystemIdentity,
        visited: inout Set<PersistentFileIdentity>,
        hook: PersistentDisposalHook?
    ) throws {
        guard visited.insert(identity).inserted else {
            throw PersistentDisposalTraversalConflict(underlying: EngineError(
                .conflict, "persistent directory traversal cycle detected"
            ))
        }
        defer { visited.remove(identity) }
        guard try Self.filesystemIdentity(
            descriptor: descriptor, identity: identity
        ) == rootFilesystem else {
            throw PersistentDisposalTraversalConflict(underlying: EngineError(
                .conflict, "persistent disposal refused to cross a mount boundary"
            ))
        }

        while let name = try entryNames().first {
            try Self.validateComponent(name)
            var observed = stat()
            guard Darwin.fstatat(
                descriptor, name, &observed, AT_SYMLINK_NOFOLLOW
            ) == 0 else {
                if errno == ENOENT { continue }
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            let observedIdentity = PersistentFileIdentity(observed)
            let observedType = observed.st_mode & S_IFMT
            let claim = "\(Self.childClaimPrefix)\(UUID().uuidString.lowercased())"
            guard Darwin.renameatx_np(
                descriptor, name, descriptor, claim, UInt32(RENAME_EXCL)
            ) == 0 else {
                if errno == ENOENT { continue }
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            try hook?(.childClaimed)
            guard Darwin.fsync(descriptor) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            try hook?(.childClaimSynchronized)

            var claimedInformation = stat()
            guard Darwin.fstatat(
                descriptor, claim, &claimedInformation, AT_SYMLINK_NOFOLLOW
            ) == 0,
                  PersistentFileIdentity(claimedInformation) == observedIdentity,
                  claimedInformation.st_mode & S_IFMT == observedType else {
                let error = EngineError(
                    .conflict, "persistent disposal child changed while claimed"
                )
                do { try restoreClaim(named: claim, to: name) }
                catch {
                    throw PersistentDisposalTraversalConflict(underlying: error)
                }
                throw PersistentDisposalTraversalConflict(underlying: error)
            }

            if observedType == S_IFDIR {
                let child: PersistentStateDirectory
                do {
                    child = try openDirectory(named: claim)
                } catch {
                    try? restoreClaim(named: claim, to: name)
                    throw PersistentDisposalTraversalConflict(underlying: error)
                }
                let childFilesystem = try Self.filesystemIdentity(
                    descriptor: child.descriptor, identity: child.identity
                )
                guard child.identity == observedIdentity,
                      Self.mayTraverse(
                        identity: child.identity,
                        filesystem: childFilesystem,
                        rootFilesystem: rootFilesystem,
                        visited: visited
                      ) else {
                    let error = EngineError(
                        .conflict,
                        "persistent disposal child changed identity or crossed a mount"
                    )
                    do { try restoreClaim(named: claim, to: name) }
                    catch {
                        throw PersistentDisposalTraversalConflict(underlying: error)
                    }
                    throw PersistentDisposalTraversalConflict(underlying: error)
                }
                try child.removeAllEntries(
                    rootFilesystem: rootFilesystem,
                    visited: &visited,
                    hook: hook
                )
                guard child.identity == observedIdentity,
                      try entryIdentity(named: claim) == observedIdentity else {
                    throw PersistentDisposalTraversalConflict(underlying: EngineError(
                        .conflict, "persistent disposal child moved during traversal"
                    ))
                }
                guard Darwin.unlinkat(descriptor, claim, AT_REMOVEDIR) == 0 else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
            } else {
                guard try entryIdentity(named: claim) == observedIdentity else {
                    let error = EngineError(
                        .conflict, "persistent disposal child moved before removal"
                    )
                    do { try restoreClaim(named: claim, to: name) }
                    catch {
                        throw PersistentDisposalTraversalConflict(underlying: error)
                    }
                    throw PersistentDisposalTraversalConflict(underlying: error)
                }
                guard Darwin.unlinkat(descriptor, claim, 0) == 0 else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
            }
            try hook?(.childRemoved)
            guard Darwin.fsync(descriptor) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        }
        guard Darwin.fsync(descriptor) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }

    private func restoreClaim(named claim: String, to original: String) throws {
        guard Darwin.renameatx_np(
            descriptor, claim, descriptor, original, UInt32(RENAME_EXCL)
        ) == 0 else {
            throw EngineError(
                .conflict,
                "persistent disposal could not safely restore a changed child"
            )
        }
        guard Darwin.fsync(descriptor) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }

    private func entryIdentity(named name: String) throws -> PersistentFileIdentity? {
        try entryMetadata(named: name)?.identity
    }

    private static func filesystemIdentity(
        descriptor: CInt, identity: PersistentFileIdentity
    ) throws -> PersistentFilesystemIdentity {
        var information = statfs()
        guard Darwin.fstatfs(descriptor, &information) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let identifier = withUnsafeBytes(of: &information.f_fsid) { Array($0) }
        let mountPoint = withUnsafeBytes(of: &information.f_mntonname) {
            Array($0.prefix { $0 != 0 })
        }
        return PersistentFilesystemIdentity(
            device: identity.device,
            fileSystemIdentifier: identifier,
            mountPoint: mountPoint
        )
    }

    static func mayTraverse(
        identity: PersistentFileIdentity,
        filesystem: PersistentFilesystemIdentity,
        rootFilesystem: PersistentFilesystemIdentity,
        visited: Set<PersistentFileIdentity>
    ) -> Bool {
        filesystem == rootFilesystem && !visited.contains(identity)
    }

    private static func isDisposalJournalName(_ name: String) -> Bool {
        name.hasPrefix(disposalJournalPrefix) && name.hasSuffix(".json")
    }

    private static func disposalJournalIdentifier(_ name: String) -> String? {
        guard isDisposalJournalName(name) else { return nil }
        return String(name.dropFirst(disposalJournalPrefix.count).dropLast(5))
    }

    private func claimedRecordName(forJournal journalName: String) throws -> String {
        guard let identifier = Self.disposalJournalIdentifier(journalName),
              !identifier.isEmpty else {
            throw EngineError(.internalError, "invalid persistent disposal journal name")
        }
        return "\(Self.disposalJournalPrefix)\(identifier)\(Self.disposalClaimedSuffix)"
    }

    private static func isClaimedRecordName(_ name: String) -> Bool {
        name.hasPrefix(disposalJournalPrefix) && name.hasSuffix(disposalClaimedSuffix)
    }

    private static func isDisposalClaimName(_ name: String) -> Bool {
        name.hasPrefix(disposalClaimPrefix)
    }

    private static func validated(
        descriptor: CInt, url: URL
    ) throws -> PersistentStateDirectory {
        var information = stat()
        guard Darwin.fstat(descriptor, &information) == 0,
              information.st_mode & S_IFMT == S_IFDIR else {
            throw EngineError(.internalError, "unsafe persistent state directory \(url.path)")
        }
        return PersistentStateDirectory(
            descriptor: descriptor, identity: .init(information), url: url
        )
    }

    private static func physicalPath(for path: String) -> String {
        if path == "/var" { return "/private/var" }
        if path.hasPrefix("/var/") { return "/private" + path }
        if path == "/tmp" { return "/private/tmp" }
        if path.hasPrefix("/tmp/") { return "/private" + path }
        return path
    }

    private static func openPhysicalDirectory(_ path: String) throws -> CInt {
        guard path.first == "/" else {
            throw EngineError(.internalError, "persistent state path is not absolute")
        }
        var descriptor = Darwin.open(
            "/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
        )
        guard descriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        if path == "/" { return descriptor }
        do {
            for component in path.split(separator: "/").map(String.init) {
                try validateComponent(component)
                let child = Darwin.openat(
                    descriptor, component,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
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

    private static func validateComponent(_ name: String) throws {
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/"),
              name.utf8.count <= Int(NAME_MAX) else {
            throw EngineError(.internalError, "invalid persistent state path component")
        }
    }

    private static func writeAll(_ data: Data, to descriptor: CInt) throws {
        try data.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let written = Darwin.write(
                    descriptor, raw.baseAddress!.advanced(by: offset), raw.count - offset
                )
                if written > 0 { offset += written; continue }
                if errno == EINTR { continue }
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        }
    }
}

/// A shim process crossed `Process.run()` but its launch-path cleanup could not
/// be verified. The caller must retain this client until a later termination
/// succeeds; dropping it would lose the only generation-specific PID/socket
/// handle capable of safe containment.
struct VMShimLaunchRollbackIncompleteError: Error, LocalizedError, @unchecked Sendable {
    let message: String
    let client: VMShimClient

    var errorDescription: String? { message }
}

struct PersistentRuntimeArtifactOwnershipUnresolvedError: Error, LocalizedError, Sendable {
    let message: String
    var errorDescription: String? { message }
}

public final class VMShimClient: @unchecked Sendable {
    struct ProcessIdentity: Hashable, Sendable {
        let processIdentifier: CInt
        let startTime: UInt64
    }

    struct ProcessInspection: Equatable, Sendable {
        let identityBefore: ProcessIdentity
        let executablePath: String
        let arguments: [String]
        let identityAfter: ProcessIdentity
    }

    enum ProcessIdentifierScan: Equatable, Sendable {
        case complete([CInt])
        case incomplete([CInt])
        case failed

        var identifiers: [CInt] {
            switch self {
            case .complete(let identifiers), .incomplete(let identifiers): identifiers
            case .failed: []
            }
        }

        var isComplete: Bool {
            if case .complete = self { return true }
            return false
        }
    }

    private struct PersistentLaunchState {
        let containerDirectory: PersistentStateDirectory
        let generationsDirectory: PersistentStateDirectory
        let directory: PersistentStateDirectory
        let intentURL: URL
        let specificationURL: URL
        let recordURL: URL
        let intent: PersistentLaunchIntent
        let specification: VMShimProtocol.Specification
    }

    /// Immutable ownership evidence for one shim process generation. Raw VM
    /// launches use a unique directory per spawn, so a later candidate can
    /// never overwrite the spec or PID/start identity needed to contain an
    /// older generation after a daemon crash.
    struct PersistentLaunchRecord: Codable, Sendable {
        static let currentSchemaVersion = 2

        let schemaVersion: Int
        let nonce: String
        let createdAt: Date
        let specificationPath: String
        let executablePath: String
        let containerDirectoryIdentity: PersistentFileIdentity
        let generationsDirectoryIdentity: PersistentFileIdentity
        let generationDirectoryIdentity: PersistentFileIdentity
        let specification: VMShimProtocol.Specification
        let processIdentifier: CInt
        let processStartTime: UInt64
        let container: ContainerRecord

        init(
            nonce: String,
            createdAt: Date = Date(),
            specificationPath: String,
            executablePath: String,
            containerDirectoryIdentity: PersistentFileIdentity,
            generationsDirectoryIdentity: PersistentFileIdentity,
            generationDirectoryIdentity: PersistentFileIdentity,
            specification: VMShimProtocol.Specification,
            processIdentifier: CInt,
            processStartTime: UInt64,
            container: ContainerRecord
        ) {
            schemaVersion = Self.currentSchemaVersion
            self.nonce = nonce
            self.createdAt = createdAt
            self.specificationPath = specificationPath
            self.executablePath = executablePath
            self.containerDirectoryIdentity = containerDirectoryIdentity
            self.generationsDirectoryIdentity = generationsDirectoryIdentity
            self.generationDirectoryIdentity = generationDirectoryIdentity
            self.specification = specification
            self.processIdentifier = processIdentifier
            self.processStartTime = processStartTime
            self.container = container
        }
    }

    struct PersistentLaunchIntent: Codable, Sendable {
        static let currentSchemaVersion = 2

        let schemaVersion: Int
        let nonce: String
        let createdAt: Date
        let specificationPath: String
        let executablePath: String
        let containerDirectoryIdentity: PersistentFileIdentity
        let generationsDirectoryIdentity: PersistentFileIdentity
        let generationDirectoryIdentity: PersistentFileIdentity
        let specification: VMShimProtocol.Specification
        let container: ContainerRecord

        init(
            nonce: String,
            createdAt: Date = Date(),
            specificationPath: String,
            executablePath: String,
            containerDirectoryIdentity: PersistentFileIdentity,
            generationsDirectoryIdentity: PersistentFileIdentity,
            generationDirectoryIdentity: PersistentFileIdentity,
            specification: VMShimProtocol.Specification,
            container: ContainerRecord
        ) {
            schemaVersion = Self.currentSchemaVersion
            self.nonce = nonce
            self.createdAt = createdAt
            self.specificationPath = specificationPath
            self.executablePath = executablePath
            self.containerDirectoryIdentity = containerDirectoryIdentity
            self.generationsDirectoryIdentity = generationsDirectoryIdentity
            self.generationDirectoryIdentity = generationDirectoryIdentity
            self.specification = specification
            self.container = container
        }
    }

    struct QuarantinedPersistentGeneration: Sendable {
        let name: String
        let directoryIdentity: PersistentFileIdentity?
        let ownerIdentities: [ProcessIdentity]
        let reason: String
    }

    struct PersistentLaunchEnumeration: Collection {
        typealias Element = (client: VMShimClient, record: PersistentLaunchRecord)
        typealias Index = Array<Element>.Index

        let launches: [Element]
        let quarantined: [QuarantinedPersistentGeneration]

        var startIndex: Index { launches.startIndex }
        var endIndex: Index { launches.endIndex }
        func index(after index: Index) -> Index { launches.index(after: index) }
        subscript(position: Index) -> Element { launches[position] }
    }

    struct PersistentRuntimeArtifactRecord: Codable, Equatable, Sendable {
        enum Phase: String, Codable, Sendable {
            case preparing
            case creating
            case staged
            case published
        }

        struct Artifact: Codable, Equatable, Sendable {
            let name: String
            let stagingName: String
            let claimName: String
            var identity: PersistentFileIdentity?
            let fileType: UInt16
        }

        static let currentSchemaVersion = 2

        let schemaVersion: Int
        let generationDirectoryIdentity: PersistentFileIdentity
        let runtimeDirectoryPath: String
        let runtimeDirectoryIdentity: PersistentFileIdentity
        let stagingDirectoryName: String
        var stagingDirectoryIdentity: PersistentFileIdentity?
        var phase: Phase
        var artifacts: [Artifact]

        init(
            generationDirectoryIdentity: PersistentFileIdentity,
            runtimeDirectoryPath: String,
            runtimeDirectoryIdentity: PersistentFileIdentity,
            stagingDirectoryName: String,
            stagingDirectoryIdentity: PersistentFileIdentity? = nil,
            phase: Phase,
            artifacts: [Artifact]
        ) {
            schemaVersion = Self.currentSchemaVersion
            self.generationDirectoryIdentity = generationDirectoryIdentity
            self.runtimeDirectoryPath = runtimeDirectoryPath
            self.runtimeDirectoryIdentity = runtimeDirectoryIdentity
            self.stagingDirectoryName = stagingDirectoryName
            self.stagingDirectoryIdentity = stagingDirectoryIdentity
            self.phase = phase
            self.artifacts = artifacts
        }
    }

    struct PersistentRuntimeArtifactPublication: Sendable {
        let intentURL: URL
        let runtimeDirectoryPath: String
        let stagingDirectoryPath: String
        let artifacts: [PersistentRuntimeArtifactRecord.Artifact]

        func stagedPath(for finalPath: String) throws -> String {
            let finalName = URL(filePath: finalPath).lastPathComponent
            guard let artifact = artifacts.first(where: { $0.name == finalName }) else {
                throw EngineError(.internalError, "runtime artifact path was not planned")
            }
            return URL(filePath: stagingDirectoryPath)
                .appending(path: artifact.stagingName).path
        }
    }

    struct PersistentSpawnFiles: Sendable {
        let directory: URL
        let specificationURL: URL
        let intentURL: URL
        let recordURL: URL
        let directoryIdentity: PersistentFileIdentity
        let logIdentity: PersistentFileIdentity
        let containerDirectory: PersistentStateDirectory
        let generationsDirectory: PersistentStateDirectory
    }

    public struct FabricPort: Codable, Hashable, Sendable { public var proto: String; public var externalPort: UInt16; public var internalAddress: String; public var internalPort: UInt16 }
    public struct FabricNetwork: Codable, Hashable, Sendable { public var id: String; public var vlan: UInt16; public var subnet: String; public var gateway: String; public var ipv6Subnet: String; public var internalNetwork: Bool; public var isolated: Bool; public var ports: [FabricPort] }
    public struct GuestCall: Codable, Sendable {
        public var operation: String
        public var payload: Data
        public var deadlineNanoseconds: UInt64?

        public init(
            operation: String,
            payload: Data,
            deadlineNanoseconds: UInt64? = nil
        ) {
            self.operation = operation
            self.payload = payload
            self.deadlineNanoseconds = deadlineNanoseconds
        }
    }
    public struct RootFSRequest: Codable, Sendable { public var contentStorePath: String; public var layers: [OCIDescriptor] }
    public struct ExecStreamRequest: Codable, Sendable { public var id: String }
    public struct PortStreamRequest: Codable, Sendable {
        public var transport: String
        public var port: UInt16
        public var ipv6: Bool

        public init(transport: String, port: UInt16, ipv6: Bool) {
            self.transport = transport
            self.port = port
            self.ipv6 = ipv6
        }
    }

    public let specification: VMShimProtocol.Specification
    private let stateLock = NSLock()
    private let descriptorInvalidationHook: (@Sendable (CInt) -> Void)?
    private let descriptorReleaseHook: (@Sendable (CInt) -> Void)?
    private let persistentLaunchRecordURL: URL?
    private let persistentContainerDirectory: PersistentStateDirectory?
    private let persistentGenerationsDirectory: PersistentStateDirectory?
    private let persistentGenerationIdentity: PersistentFileIdentity?
    private var acceptsRequests = true
    private var activeDescriptors = Set<CInt>()
    private var processIdentity: ProcessIdentity?

    public init(specification: VMShimProtocol.Specification, processIdentifier: CInt? = nil) {
        self.specification = specification
        descriptorInvalidationHook = nil
        descriptorReleaseHook = nil
        persistentLaunchRecordURL = nil
        persistentContainerDirectory = nil
        persistentGenerationsDirectory = nil
        persistentGenerationIdentity = nil
        processIdentity = processIdentifier.flatMap(Self.identity(for:))
    }

    private init(
        specification: VMShimProtocol.Specification,
        processIdentity: ProcessIdentity,
        persistentLaunchRecordURL: URL,
        persistentContainerDirectory: PersistentStateDirectory,
        persistentGenerationsDirectory: PersistentStateDirectory,
        persistentGenerationIdentity: PersistentFileIdentity
    ) {
        self.specification = specification
        descriptorInvalidationHook = nil
        descriptorReleaseHook = nil
        self.persistentLaunchRecordURL = persistentLaunchRecordURL
        self.persistentContainerDirectory = persistentContainerDirectory
        self.persistentGenerationsDirectory = persistentGenerationsDirectory
        self.persistentGenerationIdentity = persistentGenerationIdentity
        self.processIdentity = processIdentity
    }

    init(
        specification: VMShimProtocol.Specification,
        processIdentifier: CInt? = nil,
        descriptorInvalidationHook: @escaping @Sendable (CInt) -> Void,
        descriptorReleaseHook: @escaping @Sendable (CInt) -> Void
    ) {
        self.specification = specification
        self.descriptorInvalidationHook = descriptorInvalidationHook
        self.descriptorReleaseHook = descriptorReleaseHook
        persistentLaunchRecordURL = nil
        persistentContainerDirectory = nil
        persistentGenerationsDirectory = nil
        persistentGenerationIdentity = nil
        processIdentity = processIdentifier.flatMap(Self.identity(for:))
    }

    public static func launch(
        specification: VMShimProtocol.Specification,
        executable: URL = Bundle.main.executableURL ?? URL(filePath: CommandLine.arguments[0])
    ) async throws -> VMShimClient {
        try await launch(
            specification: specification,
            executable: executable,
            cleanupPartialProcess: {
                try await $0.terminate(
                    gracePeriodMilliseconds: 0, forceWaitMilliseconds: 1_000
                )
            }
        )
    }

    static func launch(
        specification: VMShimProtocol.Specification,
        executable: URL,
        cleanupPartialProcess: @escaping @Sendable (VMShimClient) async throws -> Void
    ) async throws -> VMShimClient {
        let specURL = specificationURL(for: specification)
        let client = try spawn(
            specification: specification,
            executable: executable,
            specificationURL: specURL,
            persistentRecordURL: nil
        )
        return try await awaitReadiness(
            client,
            cleanupPartialProcess: cleanupPartialProcess
        )
    }

    /// Launches one Raw VM generation beneath an immutable, unique directory.
    /// The process identity record is atomically durable before this method
    /// performs its first readiness await.
    static func launchPersisted(
        specification: VMShimProtocol.Specification,
        container: ContainerRecord,
        generationsDirectory: URL,
        expectedLogIdentity: PersistentFileIdentity? = nil,
        executable: URL = Bundle.main.executableURL ?? URL(filePath: CommandLine.arguments[0]),
        cleanupPartialProcess: @escaping @Sendable (VMShimClient) async throws -> Void = {
            try await $0.terminate(
                gracePeriodMilliseconds: 0, forceWaitMilliseconds: 1_000
            )
        }
    ) async throws -> VMShimClient {
        guard generationsDirectory.lastPathComponent == "shim-generations" else {
            throw EngineError(.internalError, "invalid VM shim generations directory")
        }
        let containerDirectory = try PersistentStateDirectory.open(
            generationsDirectory.deletingLastPathComponent()
        )
        return try await launchPersisted(
            specification: specification,
            container: container,
            containerDirectory: containerDirectory,
            expectedLogIdentity: expectedLogIdentity,
            executable: executable,
            cleanupPartialProcess: cleanupPartialProcess
        )
    }

    static func launchPersisted(
        specification: VMShimProtocol.Specification,
        container: ContainerRecord,
        containerDirectory: PersistentStateDirectory,
        expectedLogIdentity: PersistentFileIdentity? = nil,
        executable: URL = Bundle.main.executableURL ?? URL(filePath: CommandLine.arguments[0]),
        cleanupPartialProcess: @escaping @Sendable (VMShimClient) async throws -> Void = {
            try await $0.terminate(
                gracePeriodMilliseconds: 0, forceWaitMilliseconds: 1_000
            )
        }
    ) async throws -> VMShimClient {
        let client = try spawnPersisted(
            specification: specification,
            container: container,
            containerDirectory: containerDirectory,
            expectedLogIdentity: expectedLogIdentity,
            executable: executable
        )
        do {
            return try await awaitReadiness(
                client,
                cleanupPartialProcess: cleanupPartialProcess
            )
        } catch {
            let launchError = error
            if !(launchError is VMShimLaunchRollbackIncompleteError) {
                do {
                    try client.removePersistentLaunchArtifacts()
                } catch {
                    throw VMShimLaunchRollbackIncompleteError(
                        message: "VM shim launch failed: \(EngineError.message(for: launchError)); "
                            + "generation cleanup failed: \(EngineError.message(for: error))",
                        client: client
                    )
                }
            }
            throw launchError
        }
    }

    /// Testable crash boundary: returns immediately after `Process.run()` and
    /// durable launch-record publication, before any readiness polling.
    static func spawnPersisted(
        specification: VMShimProtocol.Specification,
        container: ContainerRecord,
        generationsDirectory: URL,
        expectedLogIdentity: PersistentFileIdentity? = nil,
        executable: URL
    ) throws -> VMShimClient {
        guard generationsDirectory.lastPathComponent == "shim-generations" else {
            throw EngineError(.internalError, "invalid VM shim generations directory")
        }
        return try spawnPersisted(
            specification: specification,
            container: container,
            containerDirectory: try PersistentStateDirectory.open(
                generationsDirectory.deletingLastPathComponent()
            ),
            expectedLogIdentity: expectedLogIdentity,
            executable: executable
        )
    }

    static func spawnPersisted(
        specification: VMShimProtocol.Specification,
        container: ContainerRecord,
        containerDirectory: PersistentStateDirectory,
        expectedLogIdentity: PersistentFileIdentity? = nil,
        executable: URL
    ) throws -> VMShimClient {
        let files = try preparePersistentSpawn(
            specification: specification,
            container: container,
            containerDirectory: containerDirectory,
            expectedLogIdentity: expectedLogIdentity,
            executable: executable
        )
        return try spawn(
            specification: specification,
            executable: executable,
            arguments: [
                "vm-shim", "--spec", files.specificationURL.path,
                "--launch-intent", files.intentURL.path,
            ],
            specificationURL: files.specificationURL,
            persistentRecordURL: files.recordURL,
            intentURL: files.intentURL,
            generationDirectoryIdentity: files.directoryIdentity,
            expectedLogIdentity: files.logIdentity,
            persistentContainerDirectory: files.containerDirectory,
            persistentGenerationsDirectory: files.generationsDirectory
        )
    }

    /// Writes the immutable generation intent before `Process.run()`. If the
    /// parent dies immediately after spawning, recovery can locate the child by
    /// this unique argv path and safely publish/adopt its PID/start identity.
    static func preparePersistentSpawn(
        specification: VMShimProtocol.Specification,
        container: ContainerRecord,
        generationsDirectory: URL,
        expectedLogIdentity: PersistentFileIdentity? = nil,
        executable: URL
    ) throws -> PersistentSpawnFiles {
        guard generationsDirectory.lastPathComponent == "shim-generations" else {
            throw EngineError(.internalError, "invalid VM shim generations directory")
        }
        return try preparePersistentSpawn(
            specification: specification,
            container: container,
            containerDirectory: try PersistentStateDirectory.open(
                generationsDirectory.deletingLastPathComponent()
            ),
            expectedLogIdentity: expectedLogIdentity,
            executable: executable
        )
    }

    static func preparePersistentSpawn(
        specification: VMShimProtocol.Specification,
        container: ContainerRecord,
        containerDirectory: PersistentStateDirectory,
        expectedLogIdentity: PersistentFileIdentity? = nil,
        executable: URL
    ) throws -> PersistentSpawnFiles {
        guard specification.containerID == container.id else {
            throw EngineError(.conflict, "VM shim specification does not belong to its container")
        }
        let log = try persistentLogHandle(
            specification.logPath,
            containerDirectory: containerDirectory,
            expectedIdentity: expectedLogIdentity
        )
        try log.handle.close()
        let nonce = UUID().uuidString.lowercased()
        let directoryName = "\(String(format: "%020llu", specification.generation))-\(nonce)"
        let generations = try containerDirectory.openOrCreateDirectory(
            named: "shim-generations"
        )
        try generations.reconcileDisposals()
        let generationsDirectory = generations.url
        let directory = generationsDirectory.appending(
            path: directoryName,
            directoryHint: .isDirectory
        )
        let specURL = directory.appending(path: "spec.json")
        let intentURL = directory.appending(path: "intent.json")
        let recordURL = directory.appending(path: "launch.json")
        guard Darwin.mkdirat(generations.descriptor, directoryName, 0o700) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let generationDirectory = try generations.openDirectory(named: directoryName)
        do {
            let specificationData = try JSONEncoder().encode(specification)
            try generationDirectory.writeExclusiveRegularFile(
                named: "spec.json", data: specificationData
            )
            let intent = PersistentLaunchIntent(
                nonce: nonce,
                specificationPath: specURL.path,
                executablePath: executable.resolvingSymlinksInPath().path,
                containerDirectoryIdentity: containerDirectory.identity,
                generationsDirectoryIdentity: generations.identity,
                generationDirectoryIdentity: generationDirectory.identity,
                specification: specification,
                container: container
            )
            try generationDirectory.writeExclusiveRegularFile(
                named: "intent.json", data: try JSONEncoder().encode(intent)
            )
            guard Darwin.fsync(generations.descriptor) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        } catch {
            let preparationError = error
            do {
                try generations.disposeDirectory(
                    named: directoryName,
                    expectedIdentity: generationDirectory.identity
                )
            } catch {
                throw EngineError(
                    .internalError,
                    "VM shim intent preparation failed: \(EngineError.message(for: preparationError)); "
                        + "generation cleanup failed: \(EngineError.message(for: error))"
                )
            }
            throw preparationError
        }
        return .init(
            directory: directory,
            specificationURL: specURL,
            intentURL: intentURL,
            recordURL: recordURL,
            directoryIdentity: generationDirectory.identity,
            logIdentity: log.identity,
            containerDirectory: containerDirectory,
            generationsDirectory: generations
        )
    }

    private static func spawn(
        specification: VMShimProtocol.Specification,
        executable: URL,
        arguments: [String]? = nil,
        specificationURL specURL: URL,
        persistentRecordURL: URL?,
        intentURL: URL? = nil,
        generationDirectoryIdentity: PersistentFileIdentity? = nil,
        expectedLogIdentity: PersistentFileIdentity? = nil,
        persistentContainerDirectory: PersistentStateDirectory? = nil,
        persistentGenerationsDirectory: PersistentStateDirectory? = nil
    ) throws -> VMShimClient {
        let data = try JSONEncoder().encode(specification)
        let persistentStateDirectory: PersistentStateDirectory?
        if intentURL != nil {
            guard let persistentGenerationsDirectory else {
                throw EngineError(.internalError, "missing descriptor-owned VM shim state")
            }
            let stateDirectory = try persistentGenerationsDirectory.openDirectory(
                named: specURL.deletingLastPathComponent().lastPathComponent
            )
            guard generationDirectoryIdentity == stateDirectory.identity,
                  let specificationData = try stateDirectory.readRegularFile(
                    named: "spec.json"
                  ) else {
                throw EngineError(.conflict, "immutable VM shim generation directory changed")
            }
            let persisted = try JSONDecoder().decode(
                VMShimProtocol.Specification.self, from: specificationData
            )
            guard persisted == specification else {
                throw EngineError(.conflict, "immutable VM shim specification changed before spawn")
            }
            persistentStateDirectory = stateDirectory
        } else {
            try FileManager.default.createDirectory(
                at: specURL.deletingLastPathComponent(), withIntermediateDirectories: true
            )
            try data.write(to: specURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: specURL.path)
            persistentStateDirectory = nil
        }
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments ?? ["vm-shim", "--spec", specURL.path]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = try logHandle(
            specification.logPath,
            persistentContainerDirectory: persistentContainerDirectory,
            expectedIdentity: expectedLogIdentity
        )
        process.standardError = process.standardOutput
        try process.run()
        guard let launchedIdentity = identity(for: process.processIdentifier) else {
            process.terminate()
            throw EngineError(
                .internalError,
                "could not capture VM shim process identity after launch"
            )
        }
        let client: VMShimClient
        if let persistentRecordURL, let intentURL, let generationDirectoryIdentity,
           let persistentContainerDirectory, let persistentGenerationsDirectory {
            client = VMShimClient(
                specification: specification,
                processIdentity: launchedIdentity,
                persistentLaunchRecordURL: persistentRecordURL,
                persistentContainerDirectory: persistentContainerDirectory,
                persistentGenerationsDirectory: persistentGenerationsDirectory,
                persistentGenerationIdentity: generationDirectoryIdentity
            )
            do {
                _ = try publishPersistentLaunchIdentity(
                    intentURL: intentURL,
                    expectedIdentity: launchedIdentity,
                    stateDirectory: persistentStateDirectory,
                    containerDirectory: persistentContainerDirectory,
                    generationsDirectory: persistentGenerationsDirectory
                )
            } catch {
                let persistenceError = error
                if identity(for: launchedIdentity.processIdentifier) == launchedIdentity {
                    _ = Darwin.kill(launchedIdentity.processIdentifier, SIGKILL)
                }
                if waitForExit(launchedIdentity, timeoutMilliseconds: 1_000) {
                    do {
                        try client.removePersistentLaunchArtifacts()
                    } catch {
                        throw VMShimLaunchRollbackIncompleteError(
                            message: "VM shim launch ownership could not be persisted: "
                                + "\(EngineError.message(for: persistenceError)); "
                                + "generation cleanup failed: \(EngineError.message(for: error))",
                            client: client
                        )
                    }
                    throw persistenceError
                }
                throw VMShimLaunchRollbackIncompleteError(
                    message: "VM shim launch ownership could not be persisted: "
                        + EngineError.message(for: persistenceError),
                    client: client
                )
            }
        } else {
            client = VMShimClient(
                specification: specification, processIdentifier: process.processIdentifier
            )
        }
        return client
    }

    /// Called by both the parent and the shim as its first action. The launch
    /// record uses exclusive creation, so whichever process wins publishes the
    /// same immutable PID/start identity and the other only validates it.
    static func publishPersistentLaunchIdentity(
        intentURL: URL,
        expectedIdentity: ProcessIdentity? = nil,
        identityProvider: ((CInt) -> ProcessIdentity?)? = nil,
        inspectionProvider: ((CInt) -> ProcessInspection?)? = nil,
        stateDirectory: PersistentStateDirectory? = nil,
        containerDirectory: PersistentStateDirectory? = nil,
        generationsDirectory: PersistentStateDirectory? = nil
    ) throws -> PersistentLaunchRecord {
        let identityProvider = identityProvider ?? identity(for:)
        let inspectionProvider = inspectionProvider ?? {
            inspectProcess($0, identityProvider: identityProvider)
        }
        let publicationIdentity: ProcessIdentity
        if let expectedIdentity {
            publicationIdentity = expectedIdentity
        } else {
            guard let value = identityProvider(getpid()) else {
                throw EngineError(.internalError, "could not capture VM shim process identity")
            }
            publicationIdentity = value
        }
        guard identityProvider(publicationIdentity.processIdentifier) == publicationIdentity else {
            throw EngineError(.conflict, "VM shim process identity changed before publication")
        }
        let directory: PersistentStateDirectory
        if let stateDirectory {
            directory = stateDirectory
        } else {
            directory = try PersistentStateDirectory.open(intentURL.deletingLastPathComponent())
        }
        let state = try validatedLaunchState(
            in: directory,
            expectedIntentURL: intentURL,
            containerDirectory: containerDirectory,
            generationsDirectory: generationsDirectory
        )
        guard directory.pathStillNamesThisDirectory() else {
            throw EngineError(.conflict, "VM shim generation directory was replaced")
        }
        guard let inspection = inspectionProvider(publicationIdentity.processIdentifier) else {
            throw EngineError(.internalError, "could not inspect VM shim launch owner")
        }
        guard inspection.identityBefore == publicationIdentity,
              inspection.identityAfter == publicationIdentity else {
            throw EngineError(.conflict, "VM shim process identity changed during inspection")
        }
        guard launchInspectionMatches(
            inspection,
            intentURL: state.intentURL,
            specificationURL: state.specificationURL,
            executablePath: state.intent.executablePath
        ) else {
            throw EngineError(
                .internalError, "VM shim launch owner has unexpected executable or arguments"
            )
        }
        guard identityProvider(publicationIdentity.processIdentifier) == publicationIdentity else {
            throw EngineError(.conflict, "VM shim process identity changed after inspection")
        }
        let record = PersistentLaunchRecord(
            nonce: state.intent.nonce,
            createdAt: state.intent.createdAt,
            specificationPath: state.intent.specificationPath,
            executablePath: state.intent.executablePath,
            containerDirectoryIdentity: state.intent.containerDirectoryIdentity,
            generationsDirectoryIdentity: state.intent.generationsDirectoryIdentity,
            generationDirectoryIdentity: state.intent.generationDirectoryIdentity,
            specification: state.intent.specification,
            processIdentifier: publicationIdentity.processIdentifier,
            processStartTime: publicationIdentity.startTime,
            container: state.intent.container
        )
        do {
            try writeImmutableLaunchRecord(record, in: state.directory)
        } catch let error as POSIXError where error.code == .EEXIST {
            guard let recordData = try state.directory.readRegularFile(named: "launch.json") else {
                throw EngineError(.internalError, "missing VM shim launch record")
            }
            let existing = try JSONDecoder().decode(
                PersistentLaunchRecord.self, from: recordData
            )
            guard try persistentLaunchRecordsMatch(existing, record) else {
                throw EngineError(.conflict, "VM shim launch identity was already claimed")
            }
            guard identityProvider(publicationIdentity.processIdentifier) == publicationIdentity else {
                throw EngineError(.conflict, "VM shim process identity changed during publication")
            }
            guard directory.pathStillNamesThisDirectory() else {
                throw EngineError(.conflict, "VM shim generation directory was replaced")
            }
            return existing
        }
        guard identityProvider(publicationIdentity.processIdentifier) == publicationIdentity else {
            throw EngineError(.conflict, "VM shim process identity changed during publication")
        }
        guard directory.pathStillNamesThisDirectory() else {
            throw EngineError(.conflict, "VM shim generation directory was replaced")
        }
        return record
    }

    private static func writeImmutableLaunchRecord(
        _ record: PersistentLaunchRecord,
        in directory: PersistentStateDirectory
    ) throws {
        try directory.writeExclusiveRegularFile(
            named: "launch.json", data: try JSONEncoder().encode(record)
        )
    }

    /// Durably plans a private staging namespace before the shim creates any
    /// socket or status path. No public runtime name is exposed until every
    /// staged inode has been captured in the generation journal.
    static func preparePersistentRuntimeArtifacts(
        intentURL: URL,
        socketPaths: [String],
        statusPath: String,
        hook: PersistentRuntimeArtifactHook? = nil
    ) throws -> PersistentRuntimeArtifactPublication {
        let generation = try PersistentStateDirectory.open(
            intentURL.deletingLastPathComponent()
        )
        let state = try validatedLaunchState(
            in: generation, expectedIntentURL: intentURL
        )
        guard let launchData = try generation.readRegularFile(
            named: "launch.json", required: false
        ),
              let launch = try? JSONDecoder().decode(
                PersistentLaunchRecord.self, from: launchData
              ),
              try validatedLaunchRecord(launch, state: state),
              generation.pathStillNamesThisDirectory() else {
            throw EngineError(.conflict, "VM shim launch ownership is not durably published")
        }
        let expected = socketPaths.map { ($0, mode_t(S_IFSOCK)) }
            + [(statusPath, mode_t(S_IFREG))]
        guard let firstPath = expected.first?.0 else {
            throw EngineError(.internalError, "VM shim has no runtime artifacts")
        }
        let runtimeURL = URL(filePath: firstPath).deletingLastPathComponent()
        guard exactLaunchPathKey(runtimeURL.path) != nil,
              expected.allSatisfy({ path, _ in
                  launchPathsMatch(
                    URL(filePath: path).deletingLastPathComponent().path,
                    runtimeURL.path
                  )
              }) else {
            throw EngineError(.conflict, "VM shim runtime artifacts do not share one safe directory")
        }
        let runtime = try PersistentStateDirectory.open(runtimeURL)
        let noncePrefix = String(state.intent.nonce.prefix(8))
        let artifacts = try expected.enumerated().map { offset, entry in
            let (path, expectedType) = entry
            let name = URL(filePath: path).lastPathComponent
            guard !name.isEmpty else {
                throw EngineError(.conflict, "VM shim runtime artifact has no filename")
            }
            return PersistentRuntimeArtifactRecord.Artifact(
                name: name,
                stagingName: "a\(offset)",
                claimName: ".cengine-artifact-\(noncePrefix)-\(offset)",
                identity: nil,
                fileType: UInt16(expectedType)
            )
        }
        guard Set(artifacts.map(\.name)).count == artifacts.count else {
            throw EngineError(.conflict, "VM shim runtime artifact paths overlap")
        }
        let stagingDirectoryName = ".c-" + String(UUID().uuidString
            .replacingOccurrences(of: "-", with: "").lowercased().prefix(12))
        var record = PersistentRuntimeArtifactRecord(
            generationDirectoryIdentity: state.directory.identity,
            runtimeDirectoryPath: runtime.url.path,
            runtimeDirectoryIdentity: runtime.identity,
            stagingDirectoryName: stagingDirectoryName,
            phase: .preparing,
            artifacts: artifacts.sorted { $0.name < $1.name }
        )
        do {
            try generation.writeExclusiveRegularFile(
                named: "runtime-artifacts.json",
                data: try JSONEncoder().encode(record)
            )
        } catch let error as POSIXError where error.code == .EEXIST {
            throw EngineError(.conflict, "VM shim runtime ownership was already planned")
        }
        do {
            try hook?(.creationJournalSynchronized)
            let staging = try runtime.createDirectory(named: record.stagingDirectoryName)
            record.stagingDirectoryIdentity = staging.identity
            record.phase = .creating
            try generation.replaceRegularFile(
                named: "runtime-artifacts.json",
                data: try JSONEncoder().encode(record)
            )
            try hook?(.stagingDirectorySynchronized)
            guard generation.pathStillNamesThisDirectory(),
                  runtime.pathStillNamesThisDirectory(),
                  staging.pathStillNamesThisDirectory() else {
                throw EngineError(.conflict, "VM shim runtime publication directory was replaced")
            }
            return PersistentRuntimeArtifactPublication(
                intentURL: intentURL,
                runtimeDirectoryPath: runtime.url.path,
                stagingDirectoryPath: staging.url.path,
                artifacts: record.artifacts
            )
        } catch {
            try? cleanupPersistentRuntimeArtifacts(
                in: generation, specification: state.specification, hook: nil
            )
            throw error
        }
    }

    /// Captures all staged inode identities durably, atomically exposes each
    /// final name without replacement, and synchronizes the runtime directory
    /// before readiness can be announced.
    static func publishPersistentRuntimeArtifacts(
        _ publication: PersistentRuntimeArtifactPublication,
        hook: PersistentRuntimeArtifactHook? = nil
    ) throws -> PersistentRuntimeArtifactRecord {
        let generation = try PersistentStateDirectory.open(
            publication.intentURL.deletingLastPathComponent()
        )
        let state = try validatedLaunchState(
            in: generation, expectedIntentURL: publication.intentURL
        )
        guard var record = try runtimeArtifactRecord(in: generation),
              record.phase == .creating,
              record.generationDirectoryIdentity == generation.identity,
              launchPathsMatch(record.runtimeDirectoryPath, publication.runtimeDirectoryPath),
              record.artifacts == publication.artifacts,
              let stagingIdentity = record.stagingDirectoryIdentity else {
            throw EngineError(.conflict, "VM shim runtime staging ownership changed")
        }
        let runtime = try PersistentStateDirectory.open(
            URL(filePath: record.runtimeDirectoryPath)
        )
        guard runtime.identity == record.runtimeDirectoryIdentity,
              let staging = try runtime.openDirectoryIfPresent(
                  named: record.stagingDirectoryName
              ), staging.identity == stagingIdentity else {
            throw EngineError(.conflict, "VM shim runtime staging directory changed")
        }
        do {
            for index in record.artifacts.indices {
                let expectedType = mode_t(record.artifacts[index].fileType)
                guard let metadata = try staging.entryMetadata(
                    named: record.artifacts[index].stagingName
                ), metadata.type == expectedType else {
                    throw EngineError(.conflict, "VM shim staged runtime artifact is missing or unsafe")
                }
                record.artifacts[index].identity = metadata.identity
            }
            try staging.synchronize()
            record.phase = .staged
            try generation.replaceRegularFile(
                named: "runtime-artifacts.json",
                data: try JSONEncoder().encode(record)
            )
            try hook?(.stagedOwnershipSynchronized)
            try requireCanonicalArtifactDirectories(
                generation: generation, runtime: runtime
            )

            for artifact in record.artifacts {
                guard let identity = artifact.identity,
                      let staged = try staging.entryMetadata(named: artifact.stagingName),
                      staged.identity == identity,
                      staged.type == mode_t(artifact.fileType),
                      try runtime.entryMetadata(named: artifact.name) == nil else {
                    throw EngineError(.conflict, "VM shim runtime artifact changed before exposure")
                }
                guard Darwin.renameatx_np(
                    staging.descriptor,
                    artifact.stagingName,
                    runtime.descriptor,
                    artifact.name,
                    UInt32(RENAME_EXCL)
                ) == 0 else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
                try hook?(.artifactExposed(artifact.name))
                try requireCanonicalArtifactDirectories(
                    generation: generation, runtime: runtime
                )
                guard let exposed = try runtime.entryMetadata(named: artifact.name),
                      exposed.identity == identity,
                      exposed.type == mode_t(artifact.fileType) else {
                    throw EngineError(.conflict, "VM shim runtime artifact changed during exposure")
                }
            }
            guard Darwin.unlinkat(
                runtime.descriptor, record.stagingDirectoryName, AT_REMOVEDIR
            ) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            try runtime.synchronize()
            try hook?(.runtimeDirectorySynchronized)
            try requireCanonicalArtifactDirectories(
                generation: generation, runtime: runtime
            )
            record.phase = .published
            try generation.replaceRegularFile(
                named: "runtime-artifacts.json",
                data: try JSONEncoder().encode(record)
            )
            try hook?(.publicationSynchronized)
            try requireCanonicalArtifactDirectories(
                generation: generation, runtime: runtime
            )
            return record
        } catch {
            try? cleanupPersistentRuntimeArtifacts(
                in: generation, specification: state.specification, hook: nil
            )
            throw error
        }
    }

    static func cleanupPersistentRuntimeArtifacts(
        intentURL: URL,
        hook: PersistentRuntimeArtifactHook? = nil
    ) throws {
        do {
            let generation = try PersistentStateDirectory.open(
                intentURL.deletingLastPathComponent()
            )
            let state = try validatedLaunchState(
                in: generation, expectedIntentURL: intentURL
            )
            try cleanupPersistentRuntimeArtifacts(
                in: generation, specification: state.specification, hook: hook
            )
        } catch let error as PersistentRuntimeArtifactOwnershipUnresolvedError {
            throw error
        } catch {
            throw PersistentRuntimeArtifactOwnershipUnresolvedError(
                message: "VM shim generation ownership is unavailable for artifact cleanup: "
                    + EngineError.message(for: error)
            )
        }
    }

    private static func cleanupPersistentRuntimeArtifacts(
        in generation: PersistentStateDirectory,
        specification: VMShimProtocol.Specification,
        hook: PersistentRuntimeArtifactHook? = nil
    ) throws {
        guard generation.pathStillNamesThisDirectory() else {
            throw PersistentRuntimeArtifactOwnershipUnresolvedError(
                message: "VM shim generation is no longer canonically reachable"
            )
        }
        let expectedPaths = VMShimServer.ownedSocketPaths(specification)
            + [specification.socketPath + ".status"]
        guard let record = try runtimeArtifactRecord(in: generation) else {
            guard let runtimePath = expectedPaths.first.map({
                URL(filePath: $0).deletingLastPathComponent().path
            }), expectedPaths.allSatisfy({
                launchPathsMatch(
                    URL(filePath: $0).deletingLastPathComponent().path, runtimePath
                )
            }), let runtime = try PersistentStateDirectory.openIfPresent(
                URL(filePath: runtimePath)
            ), runtime.pathStillNamesThisDirectory() else {
                throw PersistentRuntimeArtifactOwnershipUnresolvedError(
                    message: "VM shim runtime ownership journal and directory are unavailable"
                )
            }
            for path in expectedPaths {
                if try runtime.entryMetadata(named: URL(filePath: path).lastPathComponent) != nil {
                    throw PersistentRuntimeArtifactOwnershipUnresolvedError(
                        message: "unjournaled VM shim runtime artifact remains at \(path)"
                    )
                }
            }
            return
        }
        guard record.schemaVersion == PersistentRuntimeArtifactRecord.currentSchemaVersion,
              record.generationDirectoryIdentity == generation.identity,
              exactLaunchPathKey(record.runtimeDirectoryPath) != nil,
              !record.stagingDirectoryName.isEmpty,
              record.artifacts.count == expectedPaths.count,
              Set(record.artifacts.map(\.name)).count == record.artifacts.count,
              Set(record.artifacts.map(\.stagingName)).count == record.artifacts.count,
              Set(record.artifacts.map(\.claimName)).count == record.artifacts.count,
              expectedPaths.allSatisfy({ path in
                  launchPathsMatch(
                    URL(filePath: path).deletingLastPathComponent().path,
                    record.runtimeDirectoryPath
                  )
              }),
              Set(record.artifacts.map(\.name)) == Set(expectedPaths.map {
                  URL(filePath: $0).lastPathComponent
              }) else {
            throw EngineError(.conflict, "invalid VM shim runtime artifact ownership record")
        }
        guard let runtime = try PersistentStateDirectory.openIfPresent(
            URL(filePath: record.runtimeDirectoryPath)
        ), runtime.identity == record.runtimeDirectoryIdentity,
              runtime.pathStillNamesThisDirectory() else {
            throw PersistentRuntimeArtifactOwnershipUnresolvedError(
                message: "VM shim runtime directory ownership is missing or changed"
            )
        }
        let statusName = URL(
            filePath: specification.socketPath + ".status"
        ).lastPathComponent
        guard record.artifacts.allSatisfy({ artifact in
            mode_t(artifact.fileType) == (artifact.name == statusName ? S_IFREG : S_IFSOCK)
        }) else {
            throw EngineError(.conflict, "invalid VM shim runtime artifact type")
        }

        if record.phase == .preparing {
            // No artifact may be created before the staging-directory identity
            // is journaled. Because this phase does not durably identify the
            // directory, even an empty entry cannot safely be attributed to
            // this generation and must remain fenced for explicit repair.
            if try runtime.entryMetadata(named: record.stagingDirectoryName) != nil {
                throw PersistentRuntimeArtifactOwnershipUnresolvedError(
                    message: "unjournaled VM shim runtime staging directory remains"
                )
            }
            return
        }
        guard let stagingIdentity = record.stagingDirectoryIdentity else {
            throw EngineError(.conflict, "runtime staging identity is missing")
        }
        if record.phase == .creating {
            if let staging = try runtime.openDirectoryIfPresent(
                named: record.stagingDirectoryName
            ) {
                guard staging.identity == stagingIdentity else {
                    throw PersistentRuntimeArtifactOwnershipUnresolvedError(
                        message: "runtime staging directory was replaced"
                    )
                }
                try runtime.disposeDirectory(
                    named: record.stagingDirectoryName,
                    expectedIdentity: stagingIdentity
                )
            }
            try requireCanonicalArtifactDirectories(
                generation: generation, runtime: runtime
            )
            return
        }
        guard record.artifacts.allSatisfy({ $0.identity != nil }) else {
            throw EngineError(.conflict, "staged runtime ownership identity is missing")
        }
        let staging = try runtime.openDirectoryIfPresent(named: record.stagingDirectoryName)
        if let staging, staging.identity != stagingIdentity {
            throw PersistentRuntimeArtifactOwnershipUnresolvedError(
                message: "runtime staging directory was replaced"
            )
        }
        for artifact in record.artifacts {
            guard let identity = artifact.identity else { continue }
            let expectedType: mode_t = artifact.name == statusName ? S_IFREG : S_IFSOCK
            try requireOwnedArtifactOrAbsence(
                in: runtime,
                name: artifact.name,
                claimName: artifact.claimName,
                identity: identity,
                type: expectedType
            )
            _ = try runtime.removeEntryIfMatching(
                named: artifact.name,
                identity: identity,
                type: expectedType,
                claimName: artifact.claimName,
                hook: hook
            )
            try requireArtifactAbsence(
                in: runtime,
                name: artifact.name,
                claimName: artifact.claimName
            )
            guard generation.pathStillNamesThisDirectory(),
                  runtime.pathStillNamesThisDirectory() else {
                throw PersistentRuntimeArtifactOwnershipUnresolvedError(
                    message: "runtime artifact cleanup lost canonical directory ownership"
                )
            }
            if let staging {
                try requireOwnedArtifactOrAbsence(
                    in: staging,
                    name: artifact.stagingName,
                    claimName: artifact.claimName,
                    identity: identity,
                    type: expectedType
                )
                _ = try staging.removeEntryIfMatching(
                    named: artifact.stagingName,
                    identity: identity,
                    type: expectedType,
                    claimName: artifact.claimName,
                    hook: hook
                )
                try requireArtifactAbsence(
                    in: staging,
                    name: artifact.stagingName,
                    claimName: artifact.claimName
                )
                guard generation.pathStillNamesThisDirectory(),
                      runtime.pathStillNamesThisDirectory(),
                      staging.pathStillNamesThisDirectory() else {
                    throw PersistentRuntimeArtifactOwnershipUnresolvedError(
                        message: "staged artifact cleanup lost canonical directory ownership"
                    )
                }
            }
        }
        if let staging {
            guard try staging.entryNames().isEmpty else {
                throw EngineError(.conflict, "runtime staging directory contains unowned entries")
            }
            try runtime.disposeDirectory(
                named: record.stagingDirectoryName,
                expectedIdentity: stagingIdentity
            )
        }
        try requireCanonicalArtifactDirectories(
            generation: generation, runtime: runtime
        )
    }

    private static func requireOwnedArtifactOrAbsence(
        in directory: PersistentStateDirectory,
        name: String,
        claimName: String,
        identity: PersistentFileIdentity,
        type: mode_t
    ) throws {
        for candidate in [name, claimName] {
            guard let metadata = try directory.entryMetadata(named: candidate) else {
                continue
            }
            guard metadata.identity == identity, metadata.type == type else {
                throw PersistentRuntimeArtifactOwnershipUnresolvedError(
                    message: "runtime artifact \(candidate) was replaced"
                )
            }
        }
    }

    private static func requireArtifactAbsence(
        in directory: PersistentStateDirectory,
        name: String,
        claimName: String
    ) throws {
        for candidate in [name, claimName] {
            if try directory.entryMetadata(named: candidate) != nil {
                throw PersistentRuntimeArtifactOwnershipUnresolvedError(
                    message: "runtime artifact \(candidate) remained after cleanup"
                )
            }
        }
    }

    private static func requireCanonicalArtifactDirectories(
        generation: PersistentStateDirectory,
        runtime: PersistentStateDirectory
    ) throws {
        guard generation.pathStillNamesThisDirectory(),
              runtime.pathStillNamesThisDirectory() else {
            throw PersistentRuntimeArtifactOwnershipUnresolvedError(
                message: "VM shim generation or runtime ancestor chain changed during publication"
            )
        }
    }

    private static func runtimeArtifactRecord(
        in generation: PersistentStateDirectory
    ) throws -> PersistentRuntimeArtifactRecord? {
        guard let data = try generation.readRegularFile(
            named: "runtime-artifacts.json", required: false
        ) else { return nil }
        guard let record = try? JSONDecoder().decode(
            PersistentRuntimeArtifactRecord.self, from: data
        ) else {
            throw EngineError(.conflict, "invalid VM shim runtime artifact ownership record")
        }
        return record
    }

    /// A launch path is ownership evidence, not a path-resolution request.
    /// Accept only lexical absolute paths and the one spelling alias macOS can
    /// report for the leading `/private/var` data-volume component.
    static func exactLaunchPathKey(_ path: String) -> [UInt8]? {
        guard path.first == "/", path.utf8.count > 1,
              !path.contains("\0"), !path.contains("%") else { return nil }
        let components = path.split(
            separator: "/", omittingEmptySubsequences: false
        )
        guard components.first?.isEmpty == true,
              components.dropFirst().allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." })
        else { return nil }
        if path.utf8.elementsEqual("/private/var".utf8) {
            return Array("/var".utf8)
        }
        if path.hasPrefix("/private/var/") {
            return Array(path.dropFirst("/private".count).utf8)
        }
        return Array(path.utf8)
    }

    static func launchPathsMatch(_ lhs: String, _ rhs: String) -> Bool {
        guard let left = exactLaunchPathKey(lhs), let right = exactLaunchPathKey(rhs) else {
            return false
        }
        return left == right
    }

    static func launchInspectionMatches(
        _ inspection: ProcessInspection,
        intentURL: URL,
        specificationURL: URL,
        executablePath: String
    ) -> Bool {
        guard launchTupleMatches(
                  inspection,
                  intentURL: intentURL,
                  specificationURL: specificationURL
              ),
              launchPathsMatch(inspection.executablePath, executablePath),
              launchPathsMatch(inspection.arguments[0], executablePath) else { return false }
        return true
    }

    /// Ownership evidence is the exact generation-specific argv tuple. The
    /// executable may be foreign, but proc_pidpath must name argv[0] exactly
    /// (apart from Darwin's documented `/var` physical-path alias).
    static func launchTupleMatches(
        _ inspection: ProcessInspection,
        intentURL: URL,
        specificationURL: URL
    ) -> Bool {
        guard inspection.identityBefore == inspection.identityAfter,
              inspection.arguments.count == 6,
              launchPathsMatch(inspection.executablePath, inspection.arguments[0]),
              inspection.arguments[1] == "vm-shim",
              inspection.arguments[2] == "--spec",
              launchPathsMatch(inspection.arguments[3], specificationURL.path),
              inspection.arguments[4] == "--launch-intent",
              launchPathsMatch(inspection.arguments[5], intentURL.path) else { return false }
        return true
    }

    static func inspectProcess(
        _ processIdentifier: CInt,
        identityProvider: (CInt) -> ProcessIdentity?
    ) -> ProcessInspection? {
        guard let before = identityProvider(processIdentifier),
              let executablePath = processExecutablePath(for: processIdentifier) else { return nil }
        let arguments = processArguments(for: processIdentifier)
        guard let after = identityProvider(processIdentifier) else { return nil }
        return ProcessInspection(
            identityBefore: before,
            executablePath: executablePath,
            arguments: arguments,
            identityAfter: after
        )
    }

    private static func processExecutablePath(for processIdentifier: CInt) -> String? {
        var bytes = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        let count = bytes.withUnsafeMutableBytes {
            proc_pidpath(processIdentifier, $0.baseAddress, UInt32($0.count))
        }
        guard count > 0 else { return nil }
        return String(
            decoding: bytes.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) },
            as: UTF8.self
        )
    }

    private static func validatedLaunchState(
        in directory: PersistentStateDirectory,
        expectedIntentURL: URL? = nil,
        expectedContainerID: String? = nil,
        containerDirectory suppliedContainerDirectory: PersistentStateDirectory? = nil,
        generationsDirectory suppliedGenerationsDirectory: PersistentStateDirectory? = nil
    ) throws -> PersistentLaunchState {
        let state = try validatedIntentState(
            in: directory,
            expectedIntentURL: expectedIntentURL,
            expectedContainerID: expectedContainerID,
            containerDirectory: suppliedContainerDirectory,
            generationsDirectory: suppliedGenerationsDirectory
        )
        guard let specificationData = try directory.readRegularFile(named: "spec.json"),
              let specification = try? JSONDecoder().decode(
                VMShimProtocol.Specification.self, from: specificationData
              ),
              state.intent.specification == specification else {
            throw EngineError(.internalError, "incomplete VM shim launch specification")
        }
        return PersistentLaunchState(
            containerDirectory: state.containerDirectory,
            generationsDirectory: state.generationsDirectory,
            directory: state.directory,
            intentURL: state.intentURL,
            specificationURL: state.specificationURL,
            recordURL: state.recordURL,
            intent: state.intent,
            specification: specification
        )
    }

    private static func validatedIntentState(
        in directory: PersistentStateDirectory,
        expectedIntentURL: URL? = nil,
        expectedContainerID: String? = nil,
        containerDirectory suppliedContainerDirectory: PersistentStateDirectory? = nil,
        generationsDirectory suppliedGenerationsDirectory: PersistentStateDirectory? = nil
    ) throws -> PersistentLaunchState {
        let generationsDirectory = try suppliedGenerationsDirectory
            ?? PersistentStateDirectory.open(directory.url.deletingLastPathComponent())
        let containerDirectory = try suppliedContainerDirectory
            ?? PersistentStateDirectory.open(generationsDirectory.url.deletingLastPathComponent())
        let intentURL = directory.url.appending(path: "intent.json")
        let specificationURL = directory.url.appending(path: "spec.json")
        let recordURL = directory.url.appending(path: "launch.json")
        if let expectedIntentURL {
            guard launchPathsMatch(expectedIntentURL.path, intentURL.path) else {
                throw EngineError(.internalError, "VM shim intent path does not match its directory")
            }
        }
        guard let intentData = try directory.readRegularFile(named: "intent.json") else {
            throw EngineError(.internalError, "incomplete VM shim launch intent")
        }
        let intent = try JSONDecoder().decode(PersistentLaunchIntent.self, from: intentData)
        let components = directory.url.lastPathComponent.split(
            separator: "-", maxSplits: 1, omittingEmptySubsequences: false
        )
        let generationComponent = components.first.map(String.init) ?? ""
        let nonceComponent = components.count == 2 ? String(components[1]) : ""
        guard intent.schemaVersion == PersistentLaunchIntent.currentSchemaVersion,
              components.count == 2,
              generationComponent.count == 20,
              generationComponent.allSatisfy(\.isNumber),
              intent.specification.generation == UInt64(generationComponent),
              intent.nonce == nonceComponent,
              UUID(uuidString: intent.nonce)?.uuidString.lowercased() == intent.nonce,
              launchPathsMatch(intent.specificationPath, specificationURL.path),
              exactLaunchPathKey(intent.executablePath) != nil,
              intent.containerDirectoryIdentity == containerDirectory.identity,
              intent.generationsDirectoryIdentity == generationsDirectory.identity,
              intent.generationDirectoryIdentity == directory.identity,
              intent.specification.containerID == intent.container.id,
              expectedContainerID == nil || intent.container.id == expectedContainerID else {
            throw EngineError(.internalError, "invalid VM shim launch intent \(intentURL.path)")
        }
        return PersistentLaunchState(
            containerDirectory: containerDirectory,
            generationsDirectory: generationsDirectory,
            directory: directory,
            intentURL: intentURL,
            specificationURL: specificationURL,
            recordURL: recordURL,
            intent: intent,
            specification: intent.specification
        )
    }

    private static func persistentLaunchRecordsMatch(
        _ lhs: PersistentLaunchRecord,
        _ rhs: PersistentLaunchRecord
    ) throws -> Bool {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let leftContainer = try encoder.encode(lhs.container)
        let rightContainer = try encoder.encode(rhs.container)
        return lhs.schemaVersion == PersistentLaunchRecord.currentSchemaVersion
            && rhs.schemaVersion == PersistentLaunchRecord.currentSchemaVersion
            && lhs.nonce == rhs.nonce
            && lhs.createdAt == rhs.createdAt
            && launchPathsMatch(lhs.specificationPath, rhs.specificationPath)
            && launchPathsMatch(lhs.executablePath, rhs.executablePath)
            && lhs.containerDirectoryIdentity == rhs.containerDirectoryIdentity
            && lhs.generationsDirectoryIdentity == rhs.generationsDirectoryIdentity
            && lhs.generationDirectoryIdentity == rhs.generationDirectoryIdentity
            && lhs.specification == rhs.specification
            && lhs.processIdentifier == rhs.processIdentifier
            && lhs.processStartTime == rhs.processStartTime
            && leftContainer == rightContainer
    }

    private static func validatedLaunchRecord(
        _ record: PersistentLaunchRecord,
        state: PersistentLaunchState
    ) throws -> Bool {
        guard record.processIdentifier > 1 else { return false }
        let expected = PersistentLaunchRecord(
            nonce: state.intent.nonce,
            createdAt: state.intent.createdAt,
            specificationPath: state.intent.specificationPath,
            executablePath: state.intent.executablePath,
            containerDirectoryIdentity: state.intent.containerDirectoryIdentity,
            generationsDirectoryIdentity: state.intent.generationsDirectoryIdentity,
            generationDirectoryIdentity: state.intent.generationDirectoryIdentity,
            specification: state.intent.specification,
            processIdentifier: record.processIdentifier,
            processStartTime: record.processStartTime,
            container: state.intent.container
        )
        return try persistentLaunchRecordsMatch(record, expected)
    }

    private static func awaitReadiness(
        _ client: VMShimClient,
        cleanupPartialProcess: @escaping @Sendable (VMShimClient) async throws -> Void
    ) async throws -> VMShimClient {
        do {
            for _ in 0..<200 {
                if (try? await client.status()) != nil { return client }
                try await Task.sleep(for: .milliseconds(25))
            }
        } catch {
            let launchError = error
            do {
                try await cleanupPartialProcess(client)
            } catch {
                throw VMShimLaunchRollbackIncompleteError(
                    message: "VM shim launch was interrupted: \(EngineError.message(for: launchError)); "
                        + "partial shim cleanup failed: \(EngineError.message(for: error))",
                    client: client
                )
            }
            throw launchError
        }
        let readinessFailure = "VM shim did not become ready at \(client.specification.socketPath)"
        do {
            try await cleanupPartialProcess(client)
        } catch {
            throw VMShimLaunchRollbackIncompleteError(
                message: "\(readinessFailure); partial shim cleanup failed: \(EngineError.message(for: error))",
                client: client
            )
        }
        throw EngineError(.internalError, readinessFailure)
    }

    static func specificationURL(for specification: VMShimProtocol.Specification) -> URL {
        URL(filePath: specification.logPath).deletingLastPathComponent().appending(path: "shim.json")
    }

    static func persistedLaunches(
        in generationsDirectory: URL,
        expectedContainerID: String,
        expectedInstanceID: UUID? = nil,
        expectedExecutable: URL = Bundle.main.executableURL
            ?? URL(filePath: CommandLine.arguments[0]),
        processIdentifiersProvider: (() -> ProcessIdentifierScan)? = nil,
        identityProvider: ((CInt) -> ProcessIdentity?)? = nil,
        inspectionProvider: ((CInt) -> ProcessInspection?)? = nil
    ) throws -> PersistentLaunchEnumeration {
        guard generationsDirectory.lastPathComponent == "shim-generations" else {
            throw EngineError(.internalError, "invalid VM shim generations directory")
        }
        let containerDirectoryURL = generationsDirectory.deletingLastPathComponent()
        guard let containerDirectory = try PersistentStateDirectory.openIfPresent(
            containerDirectoryURL
        ) else { return .init(launches: [], quarantined: []) }
        return try persistedLaunches(
            in: containerDirectory,
            expectedContainerID: expectedContainerID,
            expectedInstanceID: expectedInstanceID,
            expectedExecutable: expectedExecutable,
            processIdentifiersProvider: processIdentifiersProvider,
            identityProvider: identityProvider,
            inspectionProvider: inspectionProvider
        )
    }

    static func persistedLaunches(
        in containerDirectory: PersistentStateDirectory,
        expectedContainerID: String,
        expectedInstanceID: UUID? = nil,
        expectedExecutable: URL = Bundle.main.executableURL
            ?? URL(filePath: CommandLine.arguments[0]),
        processIdentifiersProvider: (() -> ProcessIdentifierScan)? = nil,
        identityProvider: ((CInt) -> ProcessIdentity?)? = nil,
        inspectionProvider: ((CInt) -> ProcessInspection?)? = nil
    ) throws -> PersistentLaunchEnumeration {
        guard let generations = try containerDirectory.openDirectoryIfPresent(
            named: "shim-generations"
        ) else { return .init(launches: [], quarantined: []) }
        try generations.reconcileDisposals()
        let identifiersProvider = processIdentifiersProvider ?? allProcessIdentifiers
        let identityProvider = identityProvider ?? identity(for:)
        let inspectionProvider = inspectionProvider ?? {
            inspectProcess($0, identityProvider: identityProvider)
        }
        var quarantinedGenerations = try reconcileIncompleteGenerations(
            in: generations,
            containerDirectory: containerDirectory,
            expectedContainerID: expectedContainerID,
            expectedInstanceID: expectedInstanceID,
            expectedExecutable: expectedExecutable,
            processIdentifiersProvider: identifiersProvider,
            inspectionProvider: inspectionProvider
        )
        var launches: [(client: VMShimClient, record: PersistentLaunchRecord)] = []
        for name in try generations.entryNames() where quarantinedGenerations[name] == nil {
            let generation = try generations.openDirectory(named: name)
            let state = try validatedLaunchState(
                in: generation,
                expectedContainerID: expectedContainerID,
                containerDirectory: containerDirectory,
                generationsDirectory: generations
            )
            guard launchPathsMatch(
                state.intent.executablePath,
                expectedExecutable.resolvingSymlinksInPath().path
            ) else {
                throw EngineError(
                    .internalError,
                    "VM shim generation names an unexpected executable"
                )
            }
            var recordData = try generation.readRegularFile(
                named: "launch.json", required: false
            )
            if recordData == nil {
                var owners: [ProcessIdentity] = []
                var lastScan: ProcessIdentifierScan = .failed
                for attempt in 0..<25 {
                    lastScan = identifiersProvider()
                    owners = matchingLaunchOwners(
                        state: state,
                        processIdentifiers: lastScan.identifiers,
                        inspectionProvider: inspectionProvider
                    )
                    if !owners.isEmpty || attempt == 24 { break }
                    usleep(4_000)
                }
                guard owners.count <= 1 else {
                    throw EngineError(
                        .internalError,
                        "multiple processes claim VM shim generation \(state.intent.nonce)"
                    )
                }
                guard let owner = owners.first else {
                    guard lastScan.isComplete else {
                        quarantinedGenerations[name] = .init(
                            name: name,
                            directoryIdentity: generation.identity,
                            ownerIdentities: [],
                            reason: "process enumeration was incomplete while recovering launch intent"
                        )
                        continue
                    }
                    // This descriptor-owned directory has a complete pre-spawn
                    // intent but no exact executable/argv owner. Retiring only
                    // its known state files cannot affect a replacement path.
                    try generations.disposeDirectory(
                        named: name,
                        expectedIdentity: generation.identity
                    )
                    continue
                }
                _ = try publishPersistentLaunchIdentity(
                    intentURL: state.intentURL,
                    expectedIdentity: owner,
                    identityProvider: identityProvider,
                    inspectionProvider: inspectionProvider,
                    stateDirectory: generation,
                    containerDirectory: containerDirectory,
                    generationsDirectory: generations
                )
                recordData = try generation.readRegularFile(named: "launch.json")
            }
            guard let recordData else {
                throw EngineError(.internalError, "missing VM shim launch record")
            }
            let record = try JSONDecoder().decode(
                PersistentLaunchRecord.self, from: recordData
            )
            guard try validatedLaunchRecord(record, state: state) else {
                throw EngineError(
                    .internalError,
                    "invalid VM shim generation record \(state.recordURL.path)"
                )
            }
            launches.append((
                VMShimClient(
                    specification: state.specification,
                    processIdentity: .init(
                        processIdentifier: record.processIdentifier,
                        startTime: record.processStartTime
                    ),
                    persistentLaunchRecordURL: state.recordURL,
                    persistentContainerDirectory: containerDirectory,
                    persistentGenerationsDirectory: generations,
                    persistentGenerationIdentity: generation.identity
                ),
                record
            ))
        }
        return .init(
            launches: launches,
            quarantined: quarantinedGenerations.values.sorted { $0.name < $1.name }
        )
    }

    private static func reconcileIncompleteGenerations(
        in generations: PersistentStateDirectory,
        containerDirectory: PersistentStateDirectory,
        expectedContainerID: String,
        expectedInstanceID: UUID?,
        expectedExecutable: URL,
        processIdentifiersProvider: () -> ProcessIdentifierScan,
        inspectionProvider: (CInt) -> ProcessInspection?
    ) throws -> [String: QuarantinedPersistentGeneration] {
        var quarantined: [String: QuarantinedPersistentGeneration] = [:]
        for name in try generations.entryNames() {
            let generationURL = generations.url.appending(
                path: name, directoryHint: .isDirectory
            )
            let intentURL = generationURL.appending(path: "intent.json")
            let specificationURL = generationURL.appending(path: "spec.json")
            let expectedExecutablePath = expectedExecutable.resolvingSymlinksInPath().path
            let processScan = processIdentifiersProvider()
            let owners = matchingLaunchOwners(
                intentURL: intentURL,
                specificationURL: specificationURL,
                processIdentifiers: processScan.identifiers,
                inspectionProvider: inspectionProvider
            )
            guard let generation = try? generations.openDirectory(named: name) else {
                quarantined[name] = .init(
                    name: name, directoryIdentity: nil,
                    ownerIdentities: owners,
                    reason: "generation entry is not an owned directory"
                )
                continue
            }
            let partial = try? validatedIntentState(
                in: generation,
                containerDirectory: containerDirectory,
                generationsDirectory: generations
            )
            let entries = try generation.entryNames()
            let specification = (try? generation.readRegularFile(
                named: "spec.json", required: false
            )).flatMap { data in
                data.flatMap {
                    try? JSONDecoder().decode(VMShimProtocol.Specification.self, from: $0)
                }
            }
            let complete = try? validatedLaunchState(
                in: generation,
                containerDirectory: containerDirectory,
                generationsDirectory: generations
            )
            let hasLaunchEvidence = entries.contains("launch.json")

            if let complete {
                guard complete.intent.container.id == expectedContainerID,
                      expectedInstanceID == nil
                        || complete.intent.container.instanceID == expectedInstanceID,
                      launchPathsMatch(
                          complete.intent.executablePath, expectedExecutablePath
                      ) else {
                    quarantined[name] = .init(
                        name: name, directoryIdentity: generation.identity,
                        ownerIdentities: owners,
                        reason: "generation belongs to a foreign container instance or executable"
                    )
                    continue
                }
                if hasLaunchEvidence {
                    guard let recordData = try? generation.readRegularFile(
                        named: "launch.json"
                    ), let record = try? JSONDecoder().decode(
                              PersistentLaunchRecord.self, from: recordData
                          ), (try? validatedLaunchRecord(record, state: complete)) == true else {
                        quarantined[name] = .init(
                            name: name, directoryIdentity: generation.identity,
                            ownerIdentities: owners,
                            reason: "launch identity evidence is malformed or mismatched"
                        )
                        continue
                    }
                }
                continue
            }

            // Files and exact launch-tuple process ownership are independent
            // evidence. Retain any credible generation and quarantine only
            // that entry; dispose solely evidence-free pre-spawn debris.
            if !owners.isEmpty || hasLaunchEvidence || partial != nil || specification != nil {
                quarantined[name] = .init(
                    name: name, directoryIdentity: generation.identity,
                    ownerIdentities: owners,
                    reason: "incomplete generation retains ownership evidence"
                )
                continue
            }
            guard processScan.isComplete else {
                quarantined[name] = .init(
                    name: name,
                    directoryIdentity: generation.identity,
                    ownerIdentities: owners,
                    reason: "process enumeration was incomplete for evidence-free generation"
                )
                continue
            }
            try generations.disposeDirectory(
                named: name, expectedIdentity: generation.identity
            )
        }
        return quarantined
    }

    private static func matchingLaunchOwners(
        intentURL: URL,
        specificationURL: URL,
        processIdentifiers: [CInt],
        inspectionProvider: (CInt) -> ProcessInspection?
    ) -> [ProcessIdentity] {
        var owners: [ProcessIdentity] = []
        for processIdentifier in processIdentifiers where processIdentifier > 1 {
            guard let inspection = inspectionProvider(processIdentifier),
                  launchTupleMatches(
                      inspection,
                      intentURL: intentURL,
                      specificationURL: specificationURL
                  ) else { continue }
            owners.append(inspection.identityBefore)
        }
        return Array(Set(owners)).sorted {
            ($0.processIdentifier, $0.startTime) < ($1.processIdentifier, $1.startTime)
        }
    }

    private static func matchingLaunchOwners(
        state: PersistentLaunchState,
        processIdentifiers: [CInt],
        inspectionProvider: (CInt) -> ProcessInspection?
    ) -> [ProcessIdentity] {
        var owners: [ProcessIdentity] = []
        for processIdentifier in processIdentifiers where processIdentifier > 1 {
            guard let inspection = inspectionProvider(processIdentifier),
                  launchInspectionMatches(
                    inspection,
                    intentURL: state.intentURL,
                    specificationURL: state.specificationURL,
                    executablePath: state.intent.executablePath
                  ) else { continue }
            owners.append(inspection.identityBefore)
        }
        return Array(Set(owners)).sorted {
            ($0.processIdentifier, $0.startTime) < ($1.processIdentifier, $1.startTime)
        }
    }

    private static func allProcessIdentifiers() -> ProcessIdentifierScan {
        enumerateProcessIdentifiers { buffer, capacity in
            let bytes = capacity.multipliedReportingOverflow(
                by: MemoryLayout<CInt>.stride
            )
            guard !bytes.overflow, let byteCount = Int32(exactly: bytes.partialValue) else {
                return -1
            }
            return proc_listallpids(buffer, byteCount)
        }
    }

    static func enumerateProcessIdentifiers(
        using provider: (_ buffer: UnsafeMutablePointer<CInt>?, _ capacity: Int) -> Int32
    ) -> ProcessIdentifierScan {
        let estimatedCount = provider(nil, 0)
        guard estimatedCount > 0 else { return .failed }
        let maximumCapacity = Int(Int32.max) / MemoryLayout<CInt>.stride
        guard Int(estimatedCount) <= maximumCapacity - 32 else { return .failed }
        var capacity = Int(estimatedCount) + 32
        while true {
            var identifiers = [CInt](repeating: 0, count: capacity)
            let result = identifiers.withUnsafeMutableBufferPointer {
                provider($0.baseAddress, $0.count)
            }
            guard result > 0 else { return .failed }
            guard let returnedCount = Int(exactly: result), returnedCount <= capacity else {
                return .incomplete(identifiers)
            }
            guard returnedCount == capacity else {
                return .complete(Array(identifiers.prefix(returnedCount)))
            }
            guard capacity < maximumCapacity else {
                return .incomplete(Array(identifiers.prefix(returnedCount)))
            }
            let doubled = capacity.multipliedReportingOverflow(by: 2)
            capacity = doubled.overflow
                ? maximumCapacity : min(doubled.partialValue, maximumCapacity)
        }
    }

    private static func processArguments(for processIdentifier: CInt) -> [String] {
        var mib = [CTL_KERN, KERN_PROCARGS2, processIdentifier]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > MemoryLayout<CInt>.size else {
            return []
        }
        var bytes = [UInt8](repeating: 0, count: size)
        let result = bytes.withUnsafeMutableBytes {
            sysctl(&mib, 3, $0.baseAddress, &size, nil, 0)
        }
        guard result == 0 else { return [] }
        return parseProcessArguments(Array(bytes.prefix(size))) ?? []
    }

    static func parseProcessArguments(
        _ bytes: [UInt8], pointerSize: Int = MemoryLayout<UnsafeRawPointer>.size
    ) -> [String]? {
        guard bytes.count > MemoryLayout<CInt>.size else { return nil }
        guard pointerSize == 4 || pointerSize == 8 else { return nil }
        var rawCount: CInt = 0
        withUnsafeMutableBytes(of: &rawCount) { target in
            bytes.withUnsafeBytes { source in
                target.copyBytes(from: source.prefix(MemoryLayout<CInt>.size))
            }
        }
        let argumentCount = Int(rawCount)
        guard argumentCount >= 0, argumentCount <= 4_096 else { return nil }
        var index = MemoryLayout<CInt>.size
        let executableStart = index
        while index < bytes.count, bytes[index] != 0 { index += 1 }
        guard index < bytes.count else { return nil }
        let executableByteCount = index - executableStart
        let paddingByteCount = (
            pointerSize - ((executableByteCount + 1) % pointerSize)
        ) % pointerSize
        index += 1
        guard index + paddingByteCount <= bytes.count,
              bytes[index..<(index + paddingByteCount)].allSatisfy({ $0 == 0 }) else {
            return nil
        }
        index += paddingByteCount
        var arguments: [String] = []
        arguments.reserveCapacity(argumentCount)
        for _ in 0..<argumentCount {
            let start = index
            while index < bytes.count, bytes[index] != 0 { index += 1 }
            guard index < bytes.count,
                  let argument = String(bytes: bytes[start..<index], encoding: .utf8) else {
                return nil
            }
            arguments.append(argument)
            index += 1
        }
        guard arguments.count == argumentCount else { return nil }
        // Darwin places the environment immediately after argv (with optional
        // NUL padding). Validate the remaining non-empty entries as KEY=value
        // strings so a truncated/count-shifted argv cannot borrow malformed
        // bytes from the environment and still establish process ownership.
        while index < bytes.count {
            while index < bytes.count, bytes[index] == 0 { index += 1 }
            if index == bytes.count { break }
            let start = index
            while index < bytes.count, bytes[index] != 0 { index += 1 }
            guard index < bytes.count,
                  let equals = bytes[start..<index].firstIndex(of: UInt8(ascii: "=")),
                  equals > start else { return nil }
            index += 1
        }
        return arguments
    }

    var persistentOwnershipKey: String {
        guard let persistentLaunchRecordURL, let persistentContainerDirectory,
              let persistentGenerationIdentity else {
            return "memory:\(ObjectIdentifier(self))"
        }
        return "\(persistentContainerDirectory.identity.device):"
            + "\(persistentContainerDirectory.identity.inode):"
            + "\(persistentGenerationIdentity.device):\(persistentGenerationIdentity.inode):"
            + persistentLaunchRecordURL.deletingLastPathComponent().lastPathComponent
    }

    var hasPersistentLaunchRecord: Bool {
        guard let persistentLaunchRecordURL, let persistentGenerationsDirectory,
              let persistentGenerationIdentity else { return false }
        do {
            let directory = try persistentGenerationsDirectory.openDirectory(
                named: persistentLaunchRecordURL.deletingLastPathComponent().lastPathComponent
            )
            guard directory.identity == persistentGenerationIdentity else { return false }
            return try directory.readRegularFile(
                named: "launch.json", required: false
            ) != nil
        } catch { return false }
    }

    func removePersistentLaunchArtifacts() throws {
        guard let persistentLaunchRecordURL, let persistentGenerationsDirectory,
              let persistentGenerationIdentity else { return }
        let directory = persistentLaunchRecordURL.deletingLastPathComponent()
        do {
            let generation = try persistentGenerationsDirectory.openDirectory(
                named: directory.lastPathComponent
            )
            guard generation.identity == persistentGenerationIdentity else {
                throw EngineError(.conflict, "VM shim generation directory was replaced")
            }
            try Self.cleanupPersistentRuntimeArtifacts(
                in: generation, specification: specification
            )
            try persistentGenerationsDirectory.disposeDirectory(
                named: directory.lastPathComponent,
                expectedIdentity: persistentGenerationIdentity
            )
        } catch let error as POSIXError where error.code == .ENOENT {
            throw PersistentRuntimeArtifactOwnershipUnresolvedError(
                message: "VM shim generation ownership disappeared before artifact cleanup"
            )
        }
    }

    func ownsPersistedContainer(
        id: String,
        directoryIdentity: PersistentFileIdentity
    ) -> Bool {
        specification.containerID == id
            && persistentContainerDirectory?.identity == directoryIdentity
    }

    public func status() async throws -> VMShimProtocol.Status {
        let status = try await request(.status, response: VMShimProtocol.Status.self)
        remember(status)
        return status
    }
    public func boot() async throws -> VMShimProtocol.Status { try await request(.boot, response: VMShimProtocol.Status.self) }
    public func pause() async throws -> VMShimProtocol.Status { try await request(.pause, response: VMShimProtocol.Status.self) }
    public func resume() async throws -> VMShimProtocol.Status { try await request(.resume, response: VMShimProtocol.Status.self) }
    public func stop() async throws -> VMShimProtocol.Status { try await request(.stop, response: VMShimProtocol.Status.self) }
    public func shutdown() async throws -> VMShimProtocol.Status { try await request(.shutdown, response: VMShimProtocol.Status.self) }

    /// Permanently invalidates this client and terminates its exact shim generation.
    /// Existing request sockets are shut down before the bounded shutdown request,
    /// so a timed-out guest call cannot complete after a replacement shim starts.
    func terminate(
        gracePeriodMilliseconds: Int32 = 5_000,
        forceWaitMilliseconds: Int32 = 1_000
    ) async throws {
        let knownIdentity = storedProcessIdentity()
        if let knownIdentity, Self.identity(for: knownIdentity.processIdentifier) != knownIdentity {
            // The exact process generation recorded at launch/status no longer
            // exists. A reused PID is not ours to signal, but is definitive
            // proof that this shim generation has already terminated.
            invalidateRequests()
            try cleanupPublishedRuntimeArtifacts()
            return
        }
        // Keep the exact generation observed above even if it exits between
        // the first identity check and status inspection. The later pre-signal
        // revalidation turns that race into cleanup, never a signal to reuse.
        let identity = recordedProcessIdentity() ?? knownIdentity
        invalidateRequests()

        let deadline = Self.deadline(afterMilliseconds: gracePeriodMilliseconds)
        let graceful: Bool = await (try? runBlocking { [self] in
            let payload = try requestData(
                .shutdown,
                payloadData: nil,
                allowInvalidated: true,
                deadlineNanoseconds: deadline
            )
            _ = try JSONDecoder().decode(VMShimProtocol.Status.self, from: payload)
            return true
        }) ?? false

        if let identity, graceful,
           Self.waitForExit(identity, timeoutMilliseconds: forceWaitMilliseconds) {
            try cleanupPublishedRuntimeArtifacts()
            return
        }
        guard let identity else {
            guard graceful else {
                throw EngineError(
                    .internalError,
                    "could not identify unresponsive VM shim for container \(specification.containerID)"
                )
            }
            return
        }
        // Revalidate as close to the destructive syscall as Darwin permits. If
        // the PID now belongs to another process, the original shim is already
        // gone and the replacement must not receive our signal.
        guard Self.identity(for: identity.processIdentifier) == identity else {
            try cleanupPublishedRuntimeArtifacts()
            return
        }
        if Darwin.kill(identity.processIdentifier, SIGKILL) != 0, errno != ESRCH {
            throw EngineError(
                .internalError,
                "could not terminate VM shim \(identity.processIdentifier): \(String(cString: strerror(errno)))"
            )
        }
        guard Self.waitForExit(identity, timeoutMilliseconds: forceWaitMilliseconds) else {
            throw EngineError(
                .internalError,
                "VM shim \(identity.processIdentifier) did not exit after SIGKILL"
            )
        }
        try cleanupPublishedRuntimeArtifacts()
    }

    private func cleanupPublishedRuntimeArtifacts() throws {
        guard let persistentLaunchRecordURL, let persistentGenerationsDirectory,
              let persistentGenerationIdentity else { return }
        let generationName = persistentLaunchRecordURL
            .deletingLastPathComponent().lastPathComponent
        guard let generation = try persistentGenerationsDirectory.openDirectoryIfPresent(
            named: generationName
        ), generation.identity == persistentGenerationIdentity else {
            throw PersistentRuntimeArtifactOwnershipUnresolvedError(
                message: "VM shim generation ownership is unresolved during artifact cleanup"
            )
        }
        try Self.cleanupPersistentRuntimeArtifacts(
            in: generation, specification: specification
        )
    }

    public func startExecStream(id: String) async throws -> CInt {
        try await upgradedStream(.startExecStream, payload: ExecStreamRequest(id: id))
    }

    public func startPortStream(transport: String, port: UInt16, ipv6: Bool) async throws -> CInt {
        try await upgradedStream(
            .startPortStream,
            payload: PortStreamRequest(transport: transport, port: port, ipv6: ipv6)
        )
    }

    public func guest<Payload: Encodable, Response: Decodable>(operation: String, payload: Payload, response: Response.Type) async throws -> Response {
        let call = GuestCall(operation: operation, payload: try JSONEncoder().encode(payload))
        return try await request(.guest, payload: call, response: response)
    }

    /// Sends a guest request whose outer shim socket and inner virtio socket
    /// share one absolute deadline. Closing only the caller-side shim socket is
    /// insufficient: without the propagated deadline the shim could retain a
    /// blocked guest request after its caller had already abandoned ownership.
    func guest<Payload: Encodable, Response: Decodable>(
        operation: String,
        payload: Payload,
        response: Response.Type,
        deadlineNanoseconds: UInt64
    ) async throws -> Response {
        let call = GuestCall(
            operation: operation,
            payload: try JSONEncoder().encode(payload),
            deadlineNanoseconds: deadlineNanoseconds
        )
        return try await request(
            .guest,
            payloadData: try JSONEncoder().encode(call),
            response: response,
            deadlineNanoseconds: deadlineNanoseconds
        )
    }

    public func prepareRootFS(contentStorePath: String, layers: [OCIDescriptor]) async throws {
        struct Empty: Decodable {}
        _ = try await request(.prepareRootFS, payload: RootFSRequest(contentStorePath: contentStorePath, layers: layers), response: Empty.self)
    }

    public func configureNetwork(vlans: [UInt16]) async throws -> VMShimProtocol.Status {
        struct Configuration: Encodable { let vlans: [UInt16] }
        return try await request(.configureNetwork, payload: Configuration(vlans: vlans), response: VMShimProtocol.Status.self)
    }

    public func configureFabric(networks: [FabricNetwork]) async throws -> VMShimProtocol.Status {
        struct Configuration: Encodable { let networks: [FabricNetwork] }
        return try await request(.configureFabric, payload: Configuration(networks: networks), response: VMShimProtocol.Status.self)
    }

    private func request<Response: Decodable>(_ operation: VMShimProtocol.Operation, response: Response.Type) async throws -> Response {
        try await request(operation, payloadData: nil, response: response)
    }

    private func request<Payload: Encodable, Response: Decodable>(_ operation: VMShimProtocol.Operation, payload: Payload, response: Response.Type) async throws -> Response {
        try await request(operation, payloadData: try JSONEncoder().encode(payload), response: response)
    }

    private func request<Response: Decodable>(
        _ operation: VMShimProtocol.Operation,
        payloadData: Data?,
        response: Response.Type,
        deadlineNanoseconds: UInt64? = nil
    ) async throws -> Response {
        let payload = try await runBlocking { [self] in
            try requestData(
                operation,
                payloadData: payloadData,
                deadlineNanoseconds: deadlineNanoseconds
            )
        }
        return try JSONDecoder().decode(response, from: payload)
    }

    // Container wait requests can remain blocked for the workload's lifetime. Keep
    // their synchronous socket reads off Swift's cooperative executor so a group
    // of running containers cannot starve unrelated shim operations.
    private func runBlocking<Result: Sendable>(
        _ operation: @escaping @Sendable () throws -> Result
    ) async throws -> Result {
        try await withCheckedThrowingContinuation { continuation in
            Thread.detachNewThread {
                do { continuation.resume(returning: try operation()) }
                catch { continuation.resume(throwing: error) }
            }
        }
    }

    private func requestData(
        _ operation: VMShimProtocol.Operation,
        payloadData: Data?,
        allowInvalidated: Bool = false,
        deadlineNanoseconds: UInt64? = nil
    ) throws -> Data {
        let envelope = VMShimProtocol.Envelope(token: specification.token, operation: operation, payload: payloadData)
        let timeout = deadlineNanoseconds.map { Self.remainingMilliseconds(until: $0) }
        let descriptor = try UnixSocket.connect(
            path: specification.socketPath, timeoutMilliseconds: timeout
        )
        do {
            try register(descriptor, allowInvalidated: allowInvalidated)
        } catch {
            Darwin.close(descriptor)
            throw error
        }
        defer { unregisterAndClose(descriptor) }
        let frame: Data
        if let deadlineNanoseconds {
            let flags = fcntl(descriptor, F_GETFL)
            guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
                throw EngineError(.internalError, "could not configure VM shim request deadline")
            }
            try Self.writeExactly(
                VMShimProtocol.encode(envelope), to: descriptor, deadlineNanoseconds: deadlineNanoseconds
            )
            frame = try Self.readFrame(from: descriptor, deadlineNanoseconds: deadlineNanoseconds)
        } else {
            let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
            try file.write(contentsOf: VMShimProtocol.encode(envelope))
            frame = try readFrame(file)
        }
        let reply = try VMShimProtocol.decode(frame)
        guard reply.id == envelope.id else { throw EngineError(.internalError, "VM shim response id mismatch") }
        if let failure = reply.error {
            if failure.code == GuestProtocol.resourceRollbackIncompleteErrorCode {
                throw BackendResourceRollbackIncompleteError(failure.message)
            }
            throw EngineError(.internalError, "VM shim \(failure.code): \(failure.message)")
        }
        guard let payload = reply.payload else { throw EngineError(.internalError, "VM shim response has no payload") }
        return payload
    }

    private func upgradedStream<Payload: Encodable & Sendable>(
        _ operation: VMShimProtocol.Operation,
        payload: Payload
    ) async throws -> CInt {
        let payloadData = try JSONEncoder().encode(payload)
        return try await runBlocking { [self] in
            try requestUpgradedStream(operation, payloadData: payloadData)
        }
    }

    private func requestUpgradedStream(
        _ operation: VMShimProtocol.Operation,
        payloadData: Data
    ) throws -> CInt {
        let descriptor = try UnixSocket.connect(path: specification.socketPath)
        do {
            try register(descriptor, allowInvalidated: false)
            defer { unregister(descriptor) }
            let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
            let envelope = VMShimProtocol.Envelope(
                token: specification.token,
                operation: operation,
                payload: payloadData
            )
            try file.write(contentsOf: VMShimProtocol.encode(envelope))
            let reply = try VMShimProtocol.decode(try readFrame(file))
            guard reply.id == envelope.id else {
                throw EngineError(.internalError, "VM shim response id mismatch")
            }
            if let failure = reply.error {
                throw EngineError(.internalError, "VM shim \(failure.code): \(failure.message)")
            }
            return descriptor
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }

    private func readFrame(_ file: FileHandle) throws -> Data {
        let prefix = try readExactly(file, count: 4)
        let size = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard size > 0, size <= VMShimProtocol.maximumFrameSize else { throw EngineError(.badRequest, "invalid VM shim frame") }
        return prefix + (try readExactly(file, count: Int(size)))
    }

    private func readExactly(_ file: FileHandle, count: Int) throws -> Data {
        var data = Data()
        while data.count < count {
            guard let next = try file.read(upToCount: count - data.count), !next.isEmpty else { throw EngineError(.internalError, "VM shim closed connection") }
            data.append(next)
        }
        return data
    }

    private func register(_ descriptor: CInt, allowInvalidated: Bool) throws {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard acceptsRequests || allowInvalidated else {
            throw EngineError(.conflict, "VM shim client is being terminated")
        }
        activeDescriptors.insert(descriptor)
    }

    private func unregister(_ descriptor: CInt) {
        stateLock.lock()
        activeDescriptors.remove(descriptor)
        stateLock.unlock()
    }

    private func unregisterAndClose(_ descriptor: CInt) {
        descriptorReleaseHook?(descriptor)
        stateLock.lock()
        activeDescriptors.remove(descriptor)
        Darwin.close(descriptor)
        stateLock.unlock()
    }

    /// Stops new requests and shuts down every descriptor while the registry
    /// lock still owns its lifetime. Request cleanup must unregister before its
    /// FileHandle can close the descriptor, so the integer cannot be recycled
    /// between selection and shutdown.
    func invalidateRequests() {
        stateLock.lock()
        acceptsRequests = false
        for descriptor in activeDescriptors {
            descriptorInvalidationHook?(descriptor)
            _ = Darwin.shutdown(descriptor, SHUT_RDWR)
        }
        stateLock.unlock()
    }

    private func remember(_ status: VMShimProtocol.Status) {
        guard status.containerID == specification.containerID,
              status.generation == specification.generation,
              let startTime = status.processStartTime else { return }
        let identity = ProcessIdentity(
            processIdentifier: status.processIdentifier,
            startTime: startTime
        )
        guard Self.identity(for: status.processIdentifier) == identity else { return }
        stateLock.lock()
        processIdentity = identity
        stateLock.unlock()
    }

    private func recordedProcessIdentity() -> ProcessIdentity? {
        let knownIdentity = storedProcessIdentity()
        if let knownIdentity, Self.identity(for: knownIdentity.processIdentifier) == knownIdentity {
            return knownIdentity
        }

        let statusURL = URL(filePath: specification.socketPath + ".status")
        if let data = try? Data(contentsOf: statusURL),
           let status = try? JSONDecoder().decode(VMShimProtocol.Status.self, from: data),
           status.containerID == specification.containerID,
           status.generation == specification.generation,
           status.processIdentifier > 1,
           status.processStartTime != nil {
            remember(status)
        }
        stateLock.lock()
        let identity = processIdentity
        stateLock.unlock()
        guard let identity, Self.identity(for: identity.processIdentifier) == identity else { return nil }
        return identity
    }

    private func storedProcessIdentity() -> ProcessIdentity? {
        stateLock.lock()
        defer { stateLock.unlock() }
        return processIdentity
    }

    var ownedProcessIdentifier: CInt? { storedProcessIdentity()?.processIdentifier }

    private static func deadline(afterMilliseconds milliseconds: Int32) -> UInt64 {
        DispatchTime.now().uptimeNanoseconds
            &+ UInt64(max(0, milliseconds)) * 1_000_000
    }

    private static func remainingMilliseconds(until deadline: UInt64) -> Int32 {
        let now = DispatchTime.now().uptimeNanoseconds
        guard deadline > now else { return 0 }
        let roundedUp = (deadline - now + 999_999) / 1_000_000
        return Int32(min(roundedUp, UInt64(Int32.max)))
    }

    private static func waitForExit(
        _ identity: ProcessIdentity,
        timeoutMilliseconds: Int32
    ) -> Bool {
        let deadline = deadline(afterMilliseconds: timeoutMilliseconds)
        while Self.identity(for: identity.processIdentifier) == identity {
            if remainingMilliseconds(until: deadline) == 0 { return false }
            usleep(10_000)
        }
        return true
    }

    static func processStartTime(for processIdentifier: CInt) -> UInt64? {
        identity(for: processIdentifier)?.startTime
    }

    private static func identity(for processIdentifier: CInt) -> ProcessIdentity? {
        guard processIdentifier > 1 else { return nil }
        var information = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(
            processIdentifier,
            PROC_PIDTBSDINFO,
            0,
            &information,
            size
        ) == size,
        information.pbi_start_tvsec >= 0,
        information.pbi_start_tvusec >= 0 else { return nil }
        let seconds = UInt64(information.pbi_start_tvsec)
        let microseconds = UInt64(information.pbi_start_tvusec)
        return ProcessIdentity(
            processIdentifier: processIdentifier,
            startTime: seconds &* 1_000_000 &+ microseconds
        )
    }

    private static func wait(
        for events: Int16, descriptor: CInt, deadlineNanoseconds: UInt64
    ) throws {
        var event = pollfd(fd: descriptor, events: events, revents: 0)
        while true {
            let timeout = remainingMilliseconds(until: deadlineNanoseconds)
            guard timeout > 0 else { throw AsyncTimeout.TimeoutError() }
            let result = Darwin.poll(&event, 1, timeout)
            if result > 0 { return }
            if result == 0 { throw AsyncTimeout.TimeoutError() }
            if errno != EINTR {
                throw EngineError(
                    .internalError, "VM shim socket poll failed: \(String(cString: strerror(errno)))"
                )
            }
        }
    }

    private static func writeExactly(
        _ data: Data, to descriptor: CInt, deadlineNanoseconds: UInt64
    ) throws {
        try data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var offset = 0
            while offset < raw.count {
                try wait(for: Int16(POLLOUT), descriptor: descriptor, deadlineNanoseconds: deadlineNanoseconds)
                let count = Darwin.write(descriptor, base.advanced(by: offset), raw.count - offset)
                if count > 0 { offset += count; continue }
                if count < 0, errno == EINTR || errno == EAGAIN { continue }
                throw EngineError(.internalError, "VM shim socket write failed")
            }
        }
    }

    private static func readExactly(
        from descriptor: CInt, count: Int, deadlineNanoseconds: UInt64
    ) throws -> Data {
        var data = Data(count: count)
        try data.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            var offset = 0
            while offset < count {
                try wait(for: Int16(POLLIN), descriptor: descriptor, deadlineNanoseconds: deadlineNanoseconds)
                let received = Darwin.read(descriptor, base.advanced(by: offset), count - offset)
                if received > 0 { offset += received; continue }
                if received < 0, errno == EINTR || errno == EAGAIN { continue }
                throw EngineError(.internalError, "VM shim closed connection")
            }
        }
        return data
    }

    private static func readFrame(from descriptor: CInt, deadlineNanoseconds: UInt64) throws -> Data {
        let prefix = try readExactly(from: descriptor, count: 4, deadlineNanoseconds: deadlineNanoseconds)
        let size = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard size > 0, size <= VMShimProtocol.maximumFrameSize else {
            throw EngineError(.badRequest, "invalid VM shim frame")
        }
        return prefix + (try readExactly(
            from: descriptor, count: Int(size), deadlineNanoseconds: deadlineNanoseconds
        ))
    }

    private static func logHandle(
        _ path: String,
        persistentContainerDirectory: PersistentStateDirectory?,
        expectedIdentity: PersistentFileIdentity?
    ) throws -> FileHandle {
        if let persistentContainerDirectory {
            guard let expectedIdentity else {
                throw EngineError(.internalError, "missing persistent VM shim log identity")
            }
            return try persistentLogHandle(
                path,
                containerDirectory: persistentContainerDirectory,
                expectedIdentity: expectedIdentity
            ).handle
        }
        let url = URL(filePath: path).standardizedFileURL
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true
        )
        let directory = try PersistentStateDirectory.open(url.deletingLastPathComponent())
        let opened = try directory.openOrCreateRegularFile(
            named: url.lastPathComponent, access: .writeOnly
        )
        guard directory.pathStillNamesThisDirectory(),
              let current = try directory.entryMetadata(named: url.lastPathComponent),
              current.identity == opened.identity,
              current.type == S_IFREG else {
            throw EngineError(.conflict, "VM shim log changed while opening")
        }
        try opened.handle.seekToEnd()
        return opened.handle
    }

    private static func persistentLogHandle(
        _ path: String,
        containerDirectory: PersistentStateDirectory,
        expectedIdentity: PersistentFileIdentity?
    ) throws -> (handle: FileHandle, identity: PersistentFileIdentity) {
        let expectedURL = containerDirectory.url.appending(path: "shim.log").standardizedFileURL
        guard URL(filePath: path).standardizedFileURL == expectedURL else {
            throw EngineError(.conflict, "persistent VM shim log path changed")
        }
        let opened: (handle: FileHandle, identity: PersistentFileIdentity)
        if let expectedIdentity {
            opened = try containerDirectory.openRegularFile(
                named: "shim.log", expectedIdentity: expectedIdentity, access: .writeOnly
            )
        } else {
            opened = try containerDirectory.openOrCreateRegularFile(
                named: "shim.log", access: .writeOnly
            )
        }
        guard containerDirectory.pathStillNamesThisDirectory(),
              let current = try containerDirectory.entryMetadata(named: "shim.log"),
              current.identity == opened.identity,
              current.type == S_IFREG else {
            throw EngineError(.conflict, "persistent VM shim log changed while opening")
        }
        try opened.handle.seekToEnd()
        return opened
    }
}
#endif

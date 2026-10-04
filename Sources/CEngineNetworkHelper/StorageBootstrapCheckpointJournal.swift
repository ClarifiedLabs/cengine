import CEngineHelperSupport
import CryptoKit
import Darwin
import Foundation

/// Durable authority checkpoints accessed through a protected directory descriptor.
/// The caller serializes access and supplies a complete, independently bounded snapshot;
/// replacing the checkpoint file does not bound the authority's logical state.
final class StorageBootstrapCheckpointJournal {
    enum Failure: Error, Equatable { case repairRequired, unavailable, capacityExceeded }
    static let maximumBytes = 32 * 1024 * 1024
    static let maximumPayloadBytes = maximumBytes - 88

    /// Internal fault injection only; default I/O uses full durability barriers.
    enum Phase: CaseIterable {
        case lockCreated, lockWritten, lockSynced
        case markerCreated, markerWritten, markerSynced, intentDirectorySynced
        case candidateCreated, candidateWritten, candidateSynced
        case published, publicationDirectorySynced, markerRemoved, committed
    }
    typealias Read = (Int32, UnsafeMutableRawPointer, Int, off_t) -> Int
    private let ownerUID: uid_t
    private let configuredOwnerUID: uid_t
    private let sync: (Int32) throws -> Void
    private let fault: (Phase) throws -> Void
    private let read: Read
    private var directory: Int32 = -1
    private var lock: Int32 = -1
    private var current: Int32 = -1
    private var lockInfo = stat()
    private var currentInfo = stat()
    private var lockBytes = Data()
    private var currentHash = Data()
    private var rootKey = Data()
    private var publicKey = Data()
    private var sequence: UInt64 = 0
    private var latest: Data?
    private var poisoned = false
    private static let markerName = "authority.checkpoint-in-progress"
    private static let markerBytes = Data("CEBSP001".utf8)

    /// Production callers supply the protected fixed directory with ownerUID=0,
    /// never a request-selected path. Tests may supply an unprivileged directory.
    init(directoryFD: Int32, fresh: Bool, ownerUID: uid_t, configuredOwnerUID: uid_t,
         read: @escaping Read = { Darwin.pread($0, $1, $2, $3) },
         sync: @escaping (Int32) throws -> Void = { fd in
             guard fcntl(fd, F_FULLFSYNC) == 0 else { throw Failure.repairRequired }
         }, fault: @escaping (Phase) throws -> Void = { _ in }) throws {
        self.ownerUID = ownerUID
        self.configuredOwnerUID = configuredOwnerUID
        self.read = read
        self.sync = sync
        self.fault = fault
        directory = fcntl(directoryFD, F_DUPFD_CLOEXEC, 0)
        do {
            try validateDirectory()
            if fresh { try requireEmptyDirectory() }
            try requireAbsent(Self.markerName)
            try requireAbsent("authority.next")
            lock = try openFile("authority.lock", create: fresh)
            guard flock(lock, LOCK_EX | LOCK_NB) == 0 else { throw Failure.unavailable }
            if fresh {
                try fault(.lockCreated)
                let key = Curve25519.Signing.PrivateKey()
                rootKey = key.rawRepresentation
                publicKey = key.publicKey.rawRepresentation
                lockBytes = Data("CEBSL001".utf8) + Self.bytes(configuredOwnerUID) + publicKey
                lockBytes.append(Data(SHA256.hash(data: lockBytes)))
                try Self.writeAll(lock, lockBytes)
                try fault(.lockWritten)
                try sync(lock)
                try fault(.lockSynced)
                lockInfo = try namedFile(lock, "authority.lock")
                // The fresh journal is published exclusively; an existing v1 file is
                // never overwritten, migrated, or interpreted as an empty authority.
                try publish(Data(), sequence: 0, fresh: true)
            } else {
                lockInfo = try namedFile(lock, "authority.lock")
                lockBytes = try readFile(lock, name: "authority.lock", maximum: 76)
                guard lockBytes.count == 76,
                      lockBytes.prefix(8) == Data("CEBSL001".utf8),
                      Self.uint32(lockBytes, at: 8) == configuredOwnerUID,
                      SHA256.hash(data: lockBytes.prefix(44)) == lockBytes.suffix(32) else {
                    throw Failure.repairRequired
                }
                publicKey = lockBytes.subdata(in: 12..<44)
                current = try openFile("authority.journal", create: false)
                currentInfo = try namedFile(current, "authority.journal")
                let bytes = try readFile(current, name: "authority.journal", maximum: Self.maximumBytes)
                try decode(bytes)
                currentHash = Data(SHA256.hash(data: bytes))
            }
            try validateCurrent()
        } catch {
            closeDescriptors()
            throw error
        }
    }

    deinit { closeDescriptors() }
    private func closeDescriptors() {
        for fd in [current, lock, directory] where fd >= 0 { close(fd) }
        current = -1; lock = -1; directory = -1
    }

    func load() throws -> Data? {
        try checkedValidation()
        return latest
    }

    /// Raw Ed25519 verifier only, deliberately independent of v1 grant/wire types.
    func readRootPublicKey() throws -> Data {
        try checkedValidation()
        return publicKey
    }

    /// Capacity is a bound on the complete final snapshot, not cumulative append bytes
    /// or pending-operation counts. No logical admission/reservation policy lives here.
    func checkpoint(_ state: Data) throws {
        try checkedValidation()
        guard state.count <= Self.maximumPayloadBytes else { throw Failure.capacityExceeded }
        guard sequence < UInt64.max else { poisoned = true; throw Failure.repairRequired }
        do {
            try publish(state, sequence: sequence + 1, fresh: false)
        } catch {
            poisoned = true
            throw Failure.repairRequired
        }
    }

    /// Signs only the defined lifecycle grant type, not arbitrary caller data.
    /// The authority persists its complete intent before calling this.
    func signLifecycle(_ grant: StorageLifecycleProtocol.Grant) throws -> StorageLifecycleProtocol.SignedGrant {
        try checkedValidation()
        do {
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: rootKey)
            return try .init(grant: grant, signature: key.signature(for: grant.signingBytes))
        } catch { poisoned = true; throw Failure.repairRequired }
    }

    /// Signs only a validated closed lifecycle service-change request (distinct domain).
    func signServiceChange(_ request: StorageLifecycleProtocol.ServiceChangeRequest) throws -> StorageLifecycleProtocol.SignedServiceChange {
        try checkedValidation()
        do {
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: rootKey)
            return try .init(request: request, signature: key.signature(for: request.signingBytes))
        } catch { poisoned = true; throw Failure.repairRequired }
    }

    /// Closed cold-open domain only. Inner signature and protected ROOT binding are
    /// checked before signing; the coordinator retains BOTH exact signatures at L1.
    func signColdOpen(_ request: StorageLifecycleColdProtocol.Request) throws -> StorageLifecycleColdProtocol.SignedOpen {
        try checkedValidation()
        try request.validate()
        let root = try StorageIdentity.RootPublicKey(publicData: publicKey)
        guard request.predecessor.bootstrapKey == root.fingerprint.rawValue,
              request.takeover.isValidSignature(using: root) else { throw Failure.repairRequired }
        do {
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: rootKey)
            return try .init(request: request, signature: key.signature(for: request.signingBytes))
        } catch { poisoned = true; throw Failure.repairRequired }
    }

    /// Closed fresh-resume open domain only: a previously witnessed, unused
    /// initialization and a valid inner takeover signature are checked before
    /// signing; the coordinator retains BOTH exact signatures at R1.
    func signResumeOpen(_ request: StorageLifecycleResumeProtocol.Request) throws -> StorageLifecycleResumeProtocol.SignedOpen {
        try checkedValidation()
        try request.validate()
        let root = try StorageIdentity.RootPublicKey(publicData: publicKey)
        guard request.original.newKey != root.fingerprint.rawValue,
              request.takeover.isValidSignature(using: root) else { throw Failure.repairRequired }
        do {
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: rootKey)
            return try .init(request: request, signature: key.signature(for: request.signingBytes))
        } catch { poisoned = true; throw Failure.repairRequired }
    }

    func signHandoff(_ request: StorageLifecycleHandoffProtocol.Request) throws -> StorageLifecycleHandoffProtocol.SignedRequest {
        try checkedValidation(); try request.validate()
        let root = try StorageIdentity.RootPublicKey(publicData: publicKey)
        guard request.predecessor.newKey != root.fingerprint.rawValue,
              request.pending.newKey != root.fingerprint.rawValue else { throw Failure.repairRequired }
        do {
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: rootKey)
            return try .init(request: request, signature: key.signature(for: request.signingBytes))
        } catch { poisoned = true; throw Failure.repairRequired }
    }

    private func checkedValidation() throws {
        guard !poisoned else { throw Failure.repairRequired }
        do { try validateCurrent() }
        catch { poisoned = true; throw Failure.repairRequired }
    }

    private func validateLock() throws {
        try validateDirectory()
        guard Self.sameFile(lockInfo, try namedFile(lock, "authority.lock")),
              try readFile(lock, name: "authority.lock", maximum: 76) == lockBytes else {
            throw Failure.repairRequired
        }
    }

    private func validateCurrent(allowIntent: Bool = false) throws {
        try validateLock()
        if !allowIntent {
            try requireAbsent(Self.markerName)
            try requireAbsent("authority.next")
        }
        guard Self.sameFile(currentInfo, try namedFile(current, "authority.journal")),
              SHA256.hash(data: try readFile(current, name: "authority.journal", maximum: Self.maximumBytes)) == currentHash,
              Self.sameFile(currentInfo, try namedFile(current, "authority.journal")) else {
            throw Failure.repairRequired
        }
        try validateLock()
    }

    private func publish(_ state: Data, sequence nextSequence: UInt64, fresh: Bool) throws {
        let bytes = encode(state, sequence: nextSequence)
        var marker: Int32 = -1, candidate: Int32 = -1
        var started = false
        defer { if marker >= 0 { close(marker) }; if candidate >= 0 { close(candidate) } }
        do {
            marker = try openFile(Self.markerName, create: true)
            started = true
            try fault(.markerCreated)
            try Self.writeAll(marker, Self.markerBytes)
            try fault(.markerWritten)
            try sync(marker)
            try fault(.markerSynced)
            // Persist intent (and the initial lock) BEFORE any candidate/publication.
            try sync(directory)
            try fault(.intentDirectorySynced)
            candidate = try openFile("authority.next", create: true)
            try fault(.candidateCreated)
            try Self.writeAll(candidate, bytes)
            try fault(.candidateWritten)
            try sync(candidate)
            try fault(.candidateSynced)
            if fresh { try validateLock(); try requireAbsent("authority.journal") }
            else { try validateCurrent(allowIntent: true) }
            let markerInfo = try namedFile(marker, Self.markerName)
            guard markerInfo.st_size == Self.markerBytes.count,
                  try readFile(marker, name: Self.markerName, maximum: 8) == Self.markerBytes,
                  try readFile(candidate, name: "authority.next", maximum: Self.maximumBytes) == bytes else {
                throw Failure.repairRequired
            }
            let result = fresh
                ? renameatx_np(directory, "authority.next", directory, "authority.journal", UInt32(RENAME_EXCL))
                : renameat(directory, "authority.next", directory, "authority.journal")
            guard result == 0 else { throw Failure.repairRequired }
            if current >= 0 { close(current) }
            current = candidate; candidate = -1
            currentInfo = try namedFile(current, "authority.journal")
            currentHash = Data(SHA256.hash(data: bytes))
            try fault(.published)
            try sync(directory)
            try fault(.publicationDirectorySynced)
            try validateCurrent(allowIntent: true)
            try requireAbsent("authority.next")
            guard Self.sameFile(markerInfo, try namedFile(marker, Self.markerName)),
                  unlinkat(directory, Self.markerName, 0) == 0 else { throw Failure.repairRequired }
            try fault(.markerRemoved)
            try sync(directory)
            try fault(.committed)
            sequence = nextSequence
            latest = nextSequence == 0 ? nil : state
        } catch {
            // Never remove candidates or roll back to the old snapshot on uncertainty.
            // If marker unlink succeeded but its final barrier failed, reinstall an
            // exclusive refusal marker best-effort. A real crash after durable publication
            // may leave marker absent: reopen then accepts ONLY the durable new snapshot.
            if started { retainFailureMarker() }
            throw error
        }
    }

    private func retainFailureMarker() {
        let fd = openat(directory, Self.markerName, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600)
        guard fd >= 0 else { return } // Existing artifacts are never overwritten.
        defer { close(fd) }
        try? Self.writeAll(fd, Self.markerBytes)
        // Do not reuse an injected failing barrier for the refusal marker.
        _ = fcntl(fd, F_FULLFSYNC)
        _ = fsync(directory)
    }

    private func encode(_ state: Data, sequence: UInt64) -> Data {
        var bytes = Data("CEBSC001".utf8) + Self.bytes(configuredOwnerUID) + rootKey
        bytes.append(Self.bytes(sequence))
        bytes.append(Self.bytes(UInt32(state.count)))
        bytes.append(state)
        bytes.append(Data(HMAC<SHA256>.authenticationCode(for: bytes, using: SymmetricKey(data: rootKey))))
        return bytes
    }

    private func decode(_ bytes: Data) throws {
        guard bytes.count >= 88, bytes.prefix(8) == Data("CEBSC001".utf8),
              Self.uint32(bytes, at: 8) == configuredOwnerUID,
              Int(Self.uint32(bytes, at: 52)) == bytes.count - 88 else { throw Failure.repairRequired }
        let raw = bytes.subdata(in: 12..<44)
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: raw)
        guard key.publicKey.rawRepresentation == publicKey,
              HMAC<SHA256>.isValidAuthenticationCode(bytes.suffix(32), authenticating: bytes.dropLast(32),
                  using: SymmetricKey(data: raw)) else { throw Failure.repairRequired }
        sequence = bytes.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 44, as: UInt64.self).bigEndian }
        guard sequence != 0 || bytes.count == 88 else { throw Failure.repairRequired }
        rootKey = raw
        latest = sequence == 0 ? nil : bytes.subdata(in: 56..<(bytes.count - 32))
    }

    private static func bytes<T: FixedWidthInteger>(_ value: T) -> Data {
        var big = value.bigEndian
        return withUnsafeBytes(of: &big) { Data($0) }
    }
    private static func uint32(_ bytes: Data, at offset: Int) -> UInt32 {
        bytes.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self).bigEndian }
    }

    private func requireAbsent(_ name: String) throws {
        var info = stat()
        guard fstatat(directory, name, &info, AT_SYMLINK_NOFOLLOW) == -1, errno == ENOENT else {
            throw Failure.repairRequired
        }
    }

    private func requireEmptyDirectory() throws {
        let fd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw Failure.repairRequired }
        guard let stream = fdopendir(fd) else { close(fd); throw Failure.repairRequired }
        defer { closedir(stream) }
        while true {
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw Failure.repairRequired }
                return
            }
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) { String(cString: $0) }
            }
            guard name == "." || name == ".." else { throw Failure.repairRequired }
        }
    }

    private func openFile(_ name: String, create: Bool) throws -> Int32 {
        // NONBLOCK prevents FIFO substitution from hanging before regular-file validation.
        let fd = openat(directory, name, O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (create ? O_CREAT | O_EXCL : 0), 0o600)
        guard fd >= 0 else { throw Failure.repairRequired }
        do { _ = try namedFile(fd, name); return fd }
        catch { close(fd); throw error }
    }

    private func validateDirectory() throws { _ = try validate(directory, isDirectory: true) }
    private func validate(_ fd: Int32, isDirectory: Bool = false) throws -> stat {
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == ownerUID,
              info.st_mode & S_IFMT == (isDirectory ? S_IFDIR : S_IFREG),
              info.st_mode & 0o7777 == (isDirectory ? 0o700 : 0o600),
              (isDirectory ? info.st_nlink > 0 : info.st_nlink == 1) else { throw Failure.repairRequired }
        if let acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) {
            defer { acl_free(UnsafeMutableRawPointer(acl)) }
            var entry: acl_entry_t?
            errno = 0
            guard acl_get_entry(acl, ACL_FIRST_ENTRY.rawValue, &entry) == -1, errno == EINVAL else {
                throw Failure.repairRequired
            }
        } else if errno != ENOENT {
            throw Failure.repairRequired
        }
        var fs = statfs()
        guard fstatfs(fd, &fs) == 0, fs.f_flags & UInt32(MNT_LOCAL) != 0 else { throw Failure.repairRequired }
        return info
    }

    private func namedFile(_ fd: Int32, _ name: String) throws -> stat {
        let held = try validate(fd)
        var named = stat()
        guard fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              Self.sameFile(held, named) else { throw Failure.repairRequired }
        return held
    }
    private static func sameFile(_ lhs: stat, _ rhs: stat) -> Bool {
        lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino && lhs.st_size == rhs.st_size &&
            lhs.st_mode == rhs.st_mode && lhs.st_uid == rhs.st_uid && lhs.st_nlink == rhs.st_nlink &&
            lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec && lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec &&
            lhs.st_ctimespec.tv_sec == rhs.st_ctimespec.tv_sec && lhs.st_ctimespec.tv_nsec == rhs.st_ctimespec.tv_nsec
    }

    /// Bounded allocation and <=64KiB pread requests, with before/after identity checks.
    private func readFile(_ fd: Int32, name: String, maximum: Int) throws -> Data {
        let before = try namedFile(fd, name)
        guard before.st_size >= 0, before.st_size <= maximum else { throw Failure.repairRequired }
        let count = Int(before.st_size)
        var data = Data(count: count), offset = 0
        while offset < count {
            let requested = min(64 * 1024, count - offset)
            let n = data.withUnsafeMutableBytes { read(fd, $0.baseAddress!.advanced(by: offset), requested, off_t(offset)) }
            if n < 0, errno == EINTR { continue }
            guard n > 0, n <= requested else { throw Failure.repairRequired }
            offset += n
        }
        guard Self.sameFile(before, try namedFile(fd, name)) else { throw Failure.repairRequired }
        return data
    }
    private static func writeAll(_ fd: Int32, _ data: Data) throws {
        var offset = 0
        while offset < data.count {
            let n = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), data.count - offset) }
            if n < 0, errno == EINTR { continue }
            guard n > 0 else { throw Failure.repairRequired }
            offset += n
        }
    }
}

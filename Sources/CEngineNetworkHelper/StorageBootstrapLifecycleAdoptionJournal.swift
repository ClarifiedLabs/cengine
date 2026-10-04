import CEngineHelperSupport
import Darwin
import Foundation

/// Serialized, scope-owned adoption checkpoint; not an RPC or a startup hook.
/// The nested journal's generated signing key is only its private integrity key.
/// It MUST NOT become the lifecycle/adoption authority: that is always parent ROOT.
final class StorageBootstrapLifecycleAdoptionJournal: StorageLifecycleAdoptionJournal {
    static let maximumPayloadBytes = 2 * 1024 * 1024
    static let leafName = "adoption-v3"
    private static let enrollmentName = "adoption-v3.enrolled"
    private let scope: StorageLifecycleQualificationDirectory // Owns parent FD and ROOT lock.
    private let owner: uid_t
    private let root: Data
    private let prefix: Data
    private let leaf: Int32
    private let journal: StorageBootstrapCheckpointJournal
    private var poisoned = false

    /// Called by the protected scope factory; owner/sync injection is an internal test seam.
    init(scope: StorageLifecycleQualificationDirectory, owner: uid_t, enrollIfNoState: Bool,
         sync: @escaping (Int32) throws -> Void) throws {
        self.scope = scope; self.owner = owner
        try Self.validateScope(scope, owner: owner)
        root = try scope.journal.readRootPublicKey()
        _ = try StorageIdentity.RootPublicKey(publicData: root)
        let metadata = scope.binding.metadata
        guard metadata.count <= 4096 - 44 else { throw BootstrapFailure(.repairRequired) }
        prefix = Data("CEBSA003".utf8) + Self.bytes(UInt32(metadata.count)) + metadata + root
        if enrollIfNoState {
            // Explicit enrollment only before any lifecycle binding/state exists.
            // A durable, exclusive receipt precedes mkdir. A partial enrollment or
            // lost leaf can therefore never silently regenerate a fresh authority.
            guard try scope.recordedBinding() == nil, try scope.journal.load() == nil else {
                throw BootstrapFailure(.repairRequired)
            }
            try Self.absent(scope.fd, Self.leafName)
            try Self.absent(scope.fd, Self.enrollmentName)
            try StorageLifecycleQualificationFiles.write(prefix, parent: scope.fd,
                name: Self.enrollmentName, owner: owner, sync: sync)
        }
        guard try StorageLifecycleQualificationFiles.read(scope.fd, Self.enrollmentName, owner: owner) == prefix else {
            throw BootstrapFailure(.repairRequired)
        }
        let (fd, fresh) = try StorageLifecycleQualificationFiles.directory(scope.fd, Self.leafName,
            owner: owner, create: enrollIfNoState)
        do {
            guard fresh == enrollIfNoState else { throw BootstrapFailure(.repairRequired) }
            try Self.names(fd, allowed: fresh ? [] : ["authority.lock", "authority.journal"])
            if fresh { try sync(fd); try sync(scope.fd) }
            let checkpoint = try StorageBootstrapCheckpointJournal(directoryFD: fd, fresh: fresh,
                ownerUID: owner, configuredOwnerUID: scope.binding.ownerUID, sync: sync)
            if fresh { try checkpoint.checkpoint(prefix + Self.bytes(UInt32.max)) }
            guard let bytes = try checkpoint.load() else { throw BootstrapFailure(.repairRequired) }
            _ = try Self.payload(bytes, prefix: prefix)
            try Self.validateScope(scope, owner: owner)
            guard try scope.journal.readRootPublicKey() == root else { throw BootstrapFailure(.repairRequired) }
            leaf = fd; journal = checkpoint
        } catch { close(fd); throw error }
    }

    deinit { close(leaf) }

    func rootPublicKey() throws -> Data {
        _ = try load() // Validate the wrapper and both authorities, not the internal signing key.
        return root
    }

    func load() throws -> Data? {
        try checked {
            try validate()
            guard let bytes = try journal.load() else { throw BootstrapFailure(.repairRequired) }
            let result = try Self.payload(bytes, prefix: prefix)
            try validate()
            return result
        }
    }

    func checkpoint(_ bytes: Data) throws {
        // Capacity rejection is not uncertain I/O and does not poison a healthy journal.
        guard bytes.count <= Self.maximumPayloadBytes else { throw BootstrapFailure(.capacityExceeded) }
        try checked {
            try validate()
            try journal.checkpoint(prefix + Self.bytes(UInt32(bytes.count)) + bytes)
            try validate()
        }
    }

    private func checked<T>(_ body: () throws -> T) throws -> T {
        guard !poisoned else { throw BootstrapFailure(.repairRequired) }
        do { return try body() }
        catch { poisoned = true; throw BootstrapFailure(.repairRequired) }
    }

    private func validate() throws {
        try Self.validateScope(scope, owner: owner)
        guard try scope.journal.readRootPublicKey() == root,
              try StorageLifecycleQualificationFiles.read(scope.fd, Self.enrollmentName, owner: owner) == prefix else {
            throw BootstrapFailure(.repairRequired)
        }
        try StorageLifecycleQualificationFiles.validate(leaf, owner: owner, directory: true)
        var held = stat(), named = stat()
        guard fstat(leaf, &held) == 0,
              fstatat(scope.fd, Self.leafName, &named, AT_SYMLINK_NOFOLLOW) == 0,
              held.st_dev == named.st_dev, held.st_ino == named.st_ino,
              named.st_mode & S_IFMT == S_IFDIR else { throw BootstrapFailure(.repairRequired) }
        try Self.names(leaf, allowed: ["authority.lock", "authority.journal"])
    }

    private static func validateScope(_ scope: StorageLifecycleQualificationDirectory, owner: uid_t) throws {
        try StorageLifecycleQualificationFiles.validate(scope.fd, owner: owner, directory: true)
        _ = try scope.recordedBinding() // Includes exact immutable scope metadata validation.
        _ = try scope.journal.readRootPublicKey()
        try names(scope.fd, allowed: ["scope", "binding", "journal", leafName, enrollmentName])
        let (parentLeaf, _) = try StorageLifecycleQualificationFiles.directory(scope.fd, "journal", owner: owner, create: false)
        defer { close(parentLeaf) }
        try names(parentLeaf, allowed: ["authority.lock", "authority.journal"])
    }

    /// Fixed binary wrapper is canonical and adds only metadata + 48 bytes (no base64).
    /// UInt32.max means enrolled but no authority payload; zero means an empty payload.
    private static func payload(_ bytes: Data, prefix: Data) throws -> Data? {
        guard bytes.count >= prefix.count + 4,
              bytes.count <= prefix.count + 4 + maximumPayloadBytes,
              bytes.prefix(prefix.count) == prefix else { throw BootstrapFailure(.repairRequired) }
        let count = bytes.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: prefix.count, as: UInt32.self).bigEndian }
        if count == UInt32.max {
            guard bytes.count == prefix.count + 4 else { throw BootstrapFailure(.repairRequired) }
            return nil
        }
        guard Int(count) == bytes.count - prefix.count - 4 else { throw BootstrapFailure(.repairRequired) }
        return Data(bytes.dropFirst(prefix.count + 4))
    }

    private static func bytes(_ value: UInt32) -> Data {
        var big = value.bigEndian
        return withUnsafeBytes(of: &big) { Data($0) }
    }

    private static func absent(_ fd: Int32, _ name: String) throws {
        var info = stat()
        guard fstatat(fd, name, &info, AT_SYMLINK_NOFOLLOW) == -1, errno == ENOENT else {
            throw BootstrapFailure(.repairRequired)
        }
    }

    private static func names(_ fd: Int32, allowed: Set<String>) throws {
        let duplicate = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard duplicate >= 0 else { throw BootstrapFailure(.repairRequired) }
        guard let stream = fdopendir(duplicate) else { close(duplicate); throw BootstrapFailure(.repairRequired) }
        defer { closedir(stream) }
        while true {
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw BootstrapFailure(.repairRequired) }
                return
            }
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) { String(cString: $0) }
            }
            guard name == "." || name == ".." || allowed.contains(name) else { throw BootstrapFailure(.repairRequired) }
        }
    }
}

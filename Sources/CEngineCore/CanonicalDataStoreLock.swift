import CryptoKit
import Darwin
import Foundation

/// Host-daemon ownership only: VM shims may outlive this lock. This is not a
/// storage-VM writer lock, nor descriptor-pinned runtime path I/O. Administrative
/// root replacement requires stopping the daemon. Keep alive through shutdown.
// Immutable owned descriptors are retained until the last reference is released.
// Validation/duplication never unlock, close, or change their file offsets.
public final class CanonicalDataStoreLock: Sendable {
    public let root: URL
    static let fileName = ".daemon.lock"
    let directoryDescriptor: CInt
    let descriptor: CInt
    let pathDescriptor: CInt
    private let namespaceDescriptor: CInt
    // Fixed physical namespace, independent of --root, --socket, HOME and TMPDIR.
    // Root-owned sticky ancestors protect the private per-user directory.
    public static func leaseNamespacePath(forOwnerUID uid: uid_t) -> String {
        "/private/var/tmp/dev.cengine.store-locks-\(uid)"
    }

    static func physicalPath(_ requested: URL) throws -> String {
        guard let resolved = Darwin.realpath(requested.path, nil) else { throw posixError() }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    static func pathLeaseName(_ root: URL) -> String {
        SHA256.hash(data: Data(root.path.utf8)).map { String(format: "%02x", $0) }.joined() + ".lock"
    }

    public init(root requested: URL) throws {
        try FileManager.default.createDirectory(
            at: requested, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
        )
        root = URL(filePath: try Self.physicalPath(requested), directoryHint: .isDirectory)
        let namespace = try Self.openLeaseNamespace()
        var pathFile: CInt = -1
        var directory: CInt = -1
        var file: CInt = -1
        do {
            try Self.requireLockingSupport(namespace)
            let name = Self.pathLeaseName(root)
            pathFile = Darwin.openat(
                namespace, name, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
                S_IRUSR | S_IWUSR
            )
            guard pathFile >= 0 else { throw Self.posixError() }
            try Self.validateFile(pathFile, in: namespace, name: name)
            try Self.lock(pathFile, root: root)
            // The path lease still blocks the original pathname after root rename;
            // inode leases below also block a second owner via the moved alias.
            directory = try Self.openDirectory(root)
            try Self.requireLockingSupport(directory)
            // The directory inode is a stable anchor even if a same-user process
            // replaces the lock-file entry while the daemon owns the store.
            try Self.lock(directory, root: root)
            file = Darwin.openat(
                directory, Self.fileName,
                O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
                S_IRUSR | S_IWUSR
            )
            guard file >= 0 else { throw Self.posixError() }
            try Self.validateFile(file, in: directory)
            try Self.lock(file, root: root)
            try Self.validateFile(file, in: directory)
            try Self.validateDirectory(directory, root: root)
            try Self.validateFile(pathFile, in: namespace, name: name)
            try Self.validateDirectory(namespace, root: URL(filePath: Self.leaseNamespacePath(forOwnerUID: geteuid())))
        } catch {
            if file >= 0 { Darwin.close(file) }
            if directory >= 0 { Darwin.close(directory) }
            if pathFile >= 0 { Darwin.close(pathFile) }
            Darwin.close(namespace)
            throw error
        }
        namespaceDescriptor = namespace
        pathDescriptor = pathFile
        directoryDescriptor = directory
        descriptor = file
    }

    deinit {
        // Never unlink or rewrite a lock file, including after failed acquisition.
        // close releases flock without risking an unlock through an inherited fd.
        Darwin.close(descriptor)
        Darwin.close(directoryDescriptor)
        Darwin.close(pathDescriptor)
        Darwin.close(namespaceDescriptor)
    }

    /// Rejection-only proof for a retained private compatibility queue.
    public func validateRetainedOwnership() throws { try validateIdentity() }

    public func duplicateRetainedDirectory() throws -> CInt {
        try validateIdentity()
        let fd = fcntl(directoryDescriptor, F_DUPFD_CLOEXEC, 0)
        guard fd >= 0 else { throw Self.posixError() }
        return fd
    }

    /// Borrow CLOEXEC duplicates of the three retained lock descriptions for one
    /// synchronous descriptor transfer/verification. Never reopen by pathname.
    /// The receiver must close transferred copies within its bounded exchange;
    /// neither helper nor shim may retain them or issue LOCK_UN on shared locks.
    /// Duplicates share an open description: the sender can still LOCK_UN. They
    /// provide current consistency evidence, not irrevocable adoption authorization.
    /// Descriptor numbers are process-local, not serializable capabilities.
    public func withLeaseDescriptors<T>(
        _ body: (_ path: CInt, _ root: CInt, _ file: CInt) throws -> T
    ) throws -> T {
        try validateIdentity()
        var copies: [CInt] = []
        defer { copies.forEach { Darwin.close($0) } }
        for retained in [pathDescriptor, directoryDescriptor, descriptor] {
            let copy = fcntl(retained, F_DUPFD_CLOEXEC, 0)
            guard copy >= 0 else { throw Self.posixError() }
            copies.append(copy)
        }
        try validateIdentity()
        let result = try body(copies[0], copies[1], copies[2])
        try validateIdentity()
        return result
    }

    func validateIdentity() throws {
        try Self.validateFile(pathDescriptor, in: namespaceDescriptor, name: Self.pathLeaseName(root))
        try Self.validateDirectory(namespaceDescriptor, root: URL(filePath: Self.leaseNamespacePath(forOwnerUID: geteuid())))
        try Self.validateFile(descriptor, in: directoryDescriptor)
        try Self.validateDirectory(directoryDescriptor, root: root)
    }

    private static func lock(_ descriptor: CInt, root: URL) throws {
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            let code = errno
            if code == EWOULDBLOCK || code == EAGAIN {
                throw EngineError(.conflict, "another cengine daemon owns data store at \(root.path)")
            }
            if code == ENOTSUP || code == ENOSYS {
                throw EngineError(.unsupported, "data store filesystem does not support flock at \(root.path)")
            }
            throw POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO)
        }
    }

    private static func requireLockingSupport(_ descriptor: CInt) throws {
        var filesystem = statfs()
        guard Darwin.fstatfs(descriptor, &filesystem) == 0 else { throw posixError() }
        var attributes = attrlist()
        attributes.bitmapcount = UInt16(ATTR_BIT_MAP_COUNT)
        attributes.volattr = ATTR_VOL_INFO | UInt32(ATTR_VOL_CAPABILITIES)
        var buffer = [UInt8](repeating: 0, count: 4 + MemoryLayout<vol_capabilities_attr_t>.size)
        let result = buffer.withUnsafeMutableBytes {
            Darwin.fgetattrlist(descriptor, &attributes, $0.baseAddress, $0.count, 0)
        }
        guard filesystem.f_flags & UInt32(MNT_LOCAL) != 0, result == 0,
              buffer.withUnsafeBytes({ $0.loadUnaligned(as: UInt32.self) }) == buffer.count else {
            throw EngineError(.unsupported, "data store requires a local filesystem with verifiable flock support")
        }
        let capabilities = buffer.withUnsafeBytes {
            $0.loadUnaligned(fromByteOffset: 4, as: vol_capabilities_attr_t.self)
        }
        guard capabilities.valid.1 & UInt32(VOL_CAP_INT_FLOCK) != 0,
              capabilities.capabilities.1 & UInt32(VOL_CAP_INT_FLOCK) != 0 else {
            throw EngineError(.unsupported, "data store filesystem does not advertise flock support")
        }
    }

    private static func validateFile(_ file: CInt, in directory: CInt, name: String = fileName) throws {
        var held = stat()
        var named = stat()
        var parent = stat()
        guard Darwin.fstat(file, &held) == 0,
              Darwin.fstat(directory, &parent) == 0,
              Darwin.fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) == 0 else {
            throw posixError()
        }
        guard held.st_mode & S_IFMT == S_IFREG,
              held.st_uid == geteuid(), held.st_nlink == 1,
              held.st_mode & 0o7777 == 0o600,
              held.st_dev == parent.st_dev,
              held.st_dev == named.st_dev, held.st_ino == named.st_ino,
              named.st_mode == held.st_mode, named.st_uid == held.st_uid,
              named.st_nlink == 1 else {
            throw EngineError(.conflict, "unsafe or replaced data store lock file")
        }
    }

    private static func validateDirectory(_ directory: CInt, root: URL) throws {
        let current = try openDirectory(root)
        defer { Darwin.close(current) }
        var held = stat()
        var named = stat()
        guard Darwin.fstat(directory, &held) == 0, Darwin.fstat(current, &named) == 0 else {
            throw posixError()
        }
        guard held.st_dev == named.st_dev, held.st_ino == named.st_ino else {
            throw EngineError(.conflict, "data store directory was replaced during lock acquisition")
        }
    }

    private static func openDirectory(_ root: URL) throws -> CInt {
        // realpath resolves aliases once; never follow symlinks during this walk.
        var descriptor = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard descriptor >= 0 else { throw posixError() }
        do {
            for component in root.path.split(separator: "/") {
                guard component != ".", component != "..", !component.utf8.contains(0) else {
                    throw EngineError(.badRequest, "invalid data store path component")
                }
                let child = Darwin.openat(
                    descriptor, String(component), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
                )
                guard child >= 0 else { throw posixError() }
                Darwin.close(descriptor)
                descriptor = child
            }
            return descriptor
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }

    // Internal path argument lets tests exercise unsafe namespaces without
    // changing the production namespace or any system directory.
    static func openLeaseNamespace(path: String = leaseNamespacePath(forOwnerUID: geteuid())) throws -> CInt {
        guard path.hasPrefix("/"), let leaf = path.split(separator: "/").last else {
            throw EngineError(.badRequest, "invalid data store lease namespace")
        }
        let components = path.split(separator: "/")
        var directory = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard directory >= 0 else { throw posixError() }
        do {
            try validateNamespaceDirectory(directory, privateLeaf: false)
            for (index, component) in components.enumerated() {
                guard component != ".", component != "..", !component.utf8.contains(0) else {
                    throw EngineError(.badRequest, "invalid data store lease namespace component")
                }
                let isLeaf = index == components.count - 1
                if isLeaf, Darwin.mkdirat(directory, String(leaf), 0o700) != 0, errno != EEXIST {
                    throw posixError()
                }
                let child = Darwin.openat(
                    directory, String(component), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
                )
                guard child >= 0 else { throw posixError() }
                Darwin.close(directory)
                directory = child
                try validateNamespaceDirectory(directory, privateLeaf: isLeaf)
            }
            return directory
        } catch {
            Darwin.close(directory)
            throw error
        }
    }

    private static func validateNamespaceDirectory(_ descriptor: CInt, privateLeaf: Bool) throws {
        var info = stat()
        guard Darwin.fstat(descriptor, &info) == 0 else { throw posixError() }
        let mode = info.st_mode & 0o7777
        let safeOwner = info.st_uid == 0 || info.st_uid == geteuid()
        let safeAncestor = safeOwner && (mode & 0o022 == 0 || (info.st_uid == 0 && mode == 0o1777))
        guard info.st_mode & S_IFMT == S_IFDIR,
              privateLeaf ? (info.st_uid == geteuid() && mode == 0o700) : safeAncestor else {
            throw EngineError(.conflict, "unsafe data store lease namespace owner or mode")
        }
    }

    private static func posixError() -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}

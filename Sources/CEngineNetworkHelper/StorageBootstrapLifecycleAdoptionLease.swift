import CEngineHelperSupport
import CryptoKit
import Darwin
import Foundation

/// Scoped, nonserialized current consistency evidence, NEVER adoption authority.
/// Same-source unlock/rename races cannot be excluded during the callback, even
/// after validate(). Escaped observations are invalidated and own no descriptors.
final class ObservedCanonicalStoreLocks {
    private let owner: BootstrapProcess
    private let root: StorageIdentity.RootIdentity
    private var descriptors: [Int32]
    private var check: (() throws -> Void)?
    fileprivate init(owner: BootstrapProcess, root: StorageIdentity.RootIdentity,
                     descriptors: [Int32], check: @escaping () throws -> Void) {
        self.owner = owner; self.root = root; self.descriptors = descriptors; self.check = check
    }
    /// The returned snapshot is not authorization and must not become a capability DTO.
    /// All future adoption I/O must validate immediately before and after the operation.
    func validate() throws -> (owner: BootstrapProcess, root: StorageIdentity.RootIdentity) {
        guard let check, !descriptors.isEmpty else { throw BootstrapFailure(.unauthorized) }
        try check()
        return (owner, root)
    }
    fileprivate func closeDescriptors() {
        check = nil
        descriptors.forEach { close($0) }
        descriptors.removeAll()
    }
    deinit { closeDescriptors() }
}

/// Checks filesystem and lock consistency for reattachment requests. The router
/// supplies its authenticated owner and received descriptors, never a decoded owner claim.
/// These checks do not authenticate signatures, process ancestry or the shim.
enum StorageBootstrapLifecycleAdoptionLease {
    /// Received descriptors remain owned by the transport, which must close them
    /// before replying. Our CLOEXEC duplicates live only through this bounded body.
    /// Shared open descriptions remain unlockable by the sender. Checks can only
    /// reject inconsistent observations, not establish an irrevocable lock lease.
    /// A racing release may let flock acquire on the shared description; we never
    /// LOCK_UN it. Transport/caller must close rejected descriptions, never retain
    /// them in a shim or move long-lived daemon lock ownership into this helper.
    ///
    /// Callback results/DTOs never authorize adoption or continued VM control.
    /// Independent authority remains ROOT's durable serialized origin/epoch and
    /// pending intent, positive old-owner death, native peers and shim epoch fencing.
    /// The fixed descriptor root identity is the target; paths only reject changes.
    /// Postflight may throw AFTER callback side effects: this is not rollback.
    /// Uncertain adoption completion must retain pending intent, never undo/delete it.
    static func withObservedLocks<T>(
        owner: BootstrapProcess, expectedRoot: StorageIdentity.RootIdentity,
        pathFD: Int32, rootFD: Int32, fileFD: Int32,
        observe: @escaping (StorageIdentity.DescriptorIdentity) -> StorageIdentity.DescriptorIdentity = { $0 },
        _ body: (ObservedCanonicalStoreLocks) throws -> T
    ) throws -> T {
        guard owner.auditToken.count == MemoryLayout<audit_token_t>.size else { throw denied() }
        let audit = BootstrapAuditIdentity(token: owner.auditToken.withUnsafeBytes {
            $0.loadUnaligned(as: audit_token_t.self)
        })
        guard audit.pid == owner.pid, owner.pid > 0, audit.pidVersion == owner.pidVersion,
              audit.effectiveUID == audit.realUID else { throw denied() }
        let uid = audit.effectiveUID
        var held: [Int32] = []
        var observation: ObservedCanonicalStoreLocks?
        defer {
            if let observation { observation.closeDescriptors() }
            else { held.forEach { close($0) } }
        }
        for fd in [pathFD, rootFD, fileFD] {
            let copy = fcntl(fd, F_DUPFD_CLOEXEC, 0)
            guard copy >= 0 else { throw denied() }
            held.append(copy)
        }
        let physicalPath = try path(held[1])
        let namespacePath = CanonicalDataStoreLock.leaseNamespacePath(forOwnerUID: uid)
        let namespace = try walk(namespacePath, uid: uid, namespace: true)
        defer { close(namespace) }
        let name = SHA256.hash(data: Data(physicalPath.utf8)).map { String(format: "%02x", $0) }.joined() + ".lock"
        let bindings = StorageBootstrapBindings(ownerUID: uid, observation: observe)
        let descriptors = held + [namespace]
        func observations() throws -> [StorageIdentity.DescriptorIdentity] {
            try descriptors.enumerated().map { index, fd in
                try bindings.observe(fd, type: index == 1 || index == 3 ? S_IFDIR : S_IFREG, role: .root)
            }
        }
        let pinned = try observations()
        guard pinned[1].stableIdentity == expectedRoot else { throw denied() }
        func validateIdentity() throws {
            guard try path(held[1]) == physicalPath,
                  try observations() == pinned else { throw denied() }
            let current = try walk(physicalPath, uid: uid, namespace: false)
            defer { close(current) }
            try same(held[1], current)
            let currentNamespace = try walk(namespacePath, uid: uid, namespace: true)
            defer { close(currentNamespace) }
            try same(namespace, currentNamespace)
            try file(held[0], parent: namespace, name: name, uid: uid)
            try file(held[2], parent: held[1], name: ".daemon.lock", uid: uid)
            for fd in held + [namespace] { try lockingSupport(fd) }
        }
        func validate() throws {
            try validateIdentity()
            try verifyLocks(held, physicalPath: physicalPath, uid: uid, namespace: namespace, name: name)
            try validateIdentity()
        }
        let observed = ObservedCanonicalStoreLocks(owner: owner, root: expectedRoot,
                                                   descriptors: held, check: validate)
        observation = observed
        _ = try observed.validate()
        let result = Result { try body(observed) }
        _ = try observed.validate()
        return try result.get()
    }

    private static func verifyLocks(_ held: [Int32], physicalPath: String, uid: uid_t,
                                    namespace: Int32, name: String) throws {
        // F_GETLK alone observes a lock, not its owner. Successful duplicate flock
        // plus independent-open contention checks current consistency only: the
        // sender can unlock the shared description immediately after any check.
        for fd in held {
            var query = flock(l_start: 0, l_len: 0, l_pid: 0, l_type: Int16(F_WRLCK), l_whence: Int16(SEEK_SET))
            guard fcntl(fd, F_GETLK, &query) == 0,
                  query.l_type == F_WRLCK, query.l_pid == -1 else { throw denied() }
        }
        for fd in held {
            guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw denied() }
        }
        let rootProbe = try walk(physicalPath, uid: uid, namespace: false)
        defer { close(rootProbe) }
        try exclusive(held[1], probe: rootProbe)
        for (fd, parent, leaf) in [(held[0], namespace, name), (held[2], held[1], ".daemon.lock")] {
            let probe = openat(parent, leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            guard probe >= 0 else { throw denied() }
            defer { close(probe) }
            try exclusive(fd, probe: probe)
        }
    }

    private static func denied() -> BootstrapFailure { BootstrapFailure(.unauthorized) }
    private static func path(_ fd: Int32) throws -> String {
        var bytes = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(fd, F_GETPATH, &bytes) == 0 else { throw denied() }
        return String(cString: bytes)
    }
    private static func same(_ a: Int32, _ b: Int32) throws {
        var x = stat(), y = stat()
        guard fstat(a, &x) == 0, fstat(b, &y) == 0,
              x.st_dev == y.st_dev, x.st_ino == y.st_ino else { throw denied() }
    }
    private static func file(_ fd: Int32, parent: Int32, name: String, uid: uid_t) throws {
        var held = stat(), named = stat(), directory = stat()
        guard fstat(fd, &held) == 0, fstat(parent, &directory) == 0,
              fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              held.st_mode & S_IFMT == S_IFREG, held.st_uid == uid,
              held.st_mode & 0o7777 == 0o600, held.st_nlink == 1,
              held.st_dev == directory.st_dev, held.st_dev == named.st_dev,
              held.st_ino == named.st_ino, held.st_mode == named.st_mode,
              named.st_uid == uid, named.st_nlink == 1 else { throw denied() }
        try StorageBootstrapSecureFilesystem.requireNoACL(fd)
    }
    // Deliberately stricter than the host daemon's general root-path support:
    // privileged storage binding requires owner/mode/ACL checks (see identity).
    // Keep its special-bit rejection, including setgid; this is not a compatibility
    // promise for every path accepted by CanonicalDataStoreLock.
    private static func walk(_ path: String, uid: uid_t, namespace: Bool) throws -> Int32 {
        guard path.hasPrefix("/"), !path.utf8.contains(0) else { throw denied() }
        let components = path.split(separator: "/")
        var cursor = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard cursor >= 0 else { throw denied() }
        do {
            for (index, component) in components.enumerated() {
                guard component != ".", component != ".." else { throw denied() }
                let child = openat(cursor, String(component), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
                guard child >= 0 else { throw denied() }
                close(cursor); cursor = child
                var info = stat()
                guard fstat(cursor, &info) == 0 else { throw denied() }
                let mode = info.st_mode & 0o7777
                let leaf = index == components.count - 1
                let safe = (info.st_uid == 0 || info.st_uid == uid) &&
                    (mode & 0o7022 == 0 || (info.st_uid == 0 && mode == 0o1777))
                guard safe, !leaf || info.st_uid == uid,
                      !namespace || !leaf || mode == 0o700 else { throw denied() }
            }
            return cursor
        } catch { close(cursor); throw error }
    }
    private static func exclusive(_ held: Int32, probe: Int32) throws {
        try same(held, probe)
        guard flock(probe, LOCK_EX | LOCK_NB) == -1, errno == EWOULDBLOCK else { throw denied() }
    }
    private static func lockingSupport(_ fd: Int32) throws {
        var fs = statfs(), attributes = attrlist()
        attributes.bitmapcount = UInt16(ATTR_BIT_MAP_COUNT)
        attributes.volattr = ATTR_VOL_INFO | UInt32(ATTR_VOL_CAPABILITIES)
        var bytes = [UInt8](repeating: 0, count: 4 + MemoryLayout<vol_capabilities_attr_t>.size)
        guard fstatfs(fd, &fs) == 0, fs.f_flags & UInt32(MNT_LOCAL) != 0,
              fgetattrlist(fd, &attributes, &bytes, bytes.count, 0) == 0,
              bytes.withUnsafeBytes({ $0.loadUnaligned(as: UInt32.self) }) == bytes.count else { throw denied() }
        let caps = bytes.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 4, as: vol_capabilities_attr_t.self) }
        guard caps.valid.1 & UInt32(VOL_CAP_INT_FLOCK) != 0,
              caps.capabilities.1 & UInt32(VOL_CAP_INT_FLOCK) != 0 else { throw denied() }
    }
}

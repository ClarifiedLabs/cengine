import CEngineHelperSupport
import Darwin
import Foundation
import Security
@preconcurrency import XPC

@_silgen_name("xpc_dictionary_get_audit_token")
private func productionPeerAudit(_ message: xpc_object_t, _ token: UnsafeMutablePointer<audit_token_t>)

/// Fixed, request-independent directories for scoped storage authorities.
enum StorageLifecycleScopeNamespace: Sendable, Equatable {
    case compatibility, production
    init(_ namespace: SignedStorageIdentity.Namespace) {
        switch namespace {
        case .production: self = .production
        case .compatibility: self = .compatibility
        }
    }
    /// Production enrollment is read live; compatibility uses ONLY the owner
    /// installed in the dedicated test helper's launchd configuration.
    func configuredOwner(environment: [String: String] = ProcessInfo.processInfo.environment,
                         productionOwner: () throws -> uid_t = { try StorageLifecycleOwnerEnrollment.enrolledOwner() }) throws -> uid_t {
        switch self {
        case .production: return try productionOwner()
        case .compatibility:
            guard let text = environment[PrivilegedPortProtocol.ownerUIDEnvironmentKey],
                  let owner = uid_t(text), owner != 0, String(owner) == text else {
                throw BootstrapFailure(.unauthorized)
            }
            return owner
        }
    }
    var components: [String] {
        switch self {
        case .compatibility:
            ["Library", "Application Support", "cengine", "compat",
             "dev.cengine.network-helper.test-compat", "storage-lifecycle-v2"]
        // The existing fixed production storage namespace itself, NOT a versioned
        // sibling: a present v1 (`v1/`) or unknown authority refuses instead of being bypassed.
        case .production: ["Library", "Application Support", "cengine", "storage-bootstrap"]
        }
    }
}

struct StorageLifecycleUnsupportedFormat: Error, CustomStringConvertible, Equatable {
    let entry: String
    var description: String {
        "unsupported existing storage authority format in the fixed lifecycle namespace " +
            "(entry \(entry)); v1 or unknown authorities are never migrated, reset or bypassed and their bytes were preserved"
    }
}

/// Production namespace marker. Only an EMPTY protected directory is initialized;
/// every other layout (v1 `v1/`, `authority.*`, unknown entries) refuses unchanged.
enum StorageLifecycleProductionFormat {
    static let name = "format"
    static let bytes = Data("cengine.storage.lifecycle.production.v3\n".utf8)
    static func isScope(_ name: String) -> Bool {
        name.utf8.count == 64 && name.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    static func entries(_ fd: Int32) throws -> [String] {
        let dup = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard dup >= 0 else { throw BootstrapFailure(.repairRequired) }
        guard let stream = fdopendir(dup) else { close(dup); throw BootstrapFailure(.repairRequired) }
        defer { closedir(stream) }
        var names: [String] = []
        while true {
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw BootstrapFailure(.repairRequired) }
                return names.sorted()
            }
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) { String(cString: $0) }
            }
            if name != "." && name != ".." { names.append(name) }
            guard names.count <= StorageLifecycleQualificationRegistry.maximum + 1 else { throw BootstrapFailure(.capacityExceeded) }
        }
    }
    static func require(_ base: Int32, owner: uid_t, namespace: StorageLifecycleScopeNamespace = .production, sync: (Int32) throws -> Void) throws {
        let bytes = namespace == .production ? Self.bytes : Data("cengine.storage.lifecycle.compatibility.v3\n".utf8)
        try StorageLifecycleQualificationFiles.validate(base, owner: owner, directory: true)
        let names = try entries(base)
        if names.isEmpty {
            try StorageLifecycleQualificationFiles.write(bytes, parent: base, name: name, owner: owner, sync: sync)
            return
        }
        guard names.contains(name) else { throw StorageLifecycleUnsupportedFormat(entry: names[0]) }
        guard (try? StorageLifecycleQualificationFiles.read(base, name, owner: owner)) == bytes else {
            throw StorageLifecycleUnsupportedFormat(entry: name)
        }
        if let other = names.first(where: { $0 != name && !isScope($0) }) { throw StorageLifecycleUnsupportedFormat(entry: other) }
    }
}

/// ASSUMPTION: exactly one administratively enrolled storage owner per host, set ONLY by
/// the root CLI (`cengine-helper enroll-storage-owner --uid N`); the engine can
/// never self-enroll over XPC. Every read-modify-write holds an EXCLUSIVE flock on the
/// root-owned 0600 `storage-owner.lock` (interprocess, not just in-process); the running
/// helper re-reads the owner under a SHARED flock per request/scope bind, never cached.
/// Unenroll writes a durable `disabled` tombstone (never a bare unlink) and only an
/// explicit enroll under the same lock clears it. Change the owner only with the storage
/// lifecycle quiesced (engine stopped): already-bound scopes keep the owner they bound with.
enum StorageLifecycleOwnerEnrollment {
    static let parentComponents = ["Library", "Application Support", "cengine"]
    static let name = "storage-owner"
    static let lockName = "storage-owner.lock"
    static let temporaryName = "storage-owner.tmp"
    private static let header = "cengine.storage.owner.v1\n"
    typealias State = StorageOwnerStatus
    static func encode(_ uid: uid_t) -> Data { Data("\(header)\(uid)\n".utf8) }
    static let tombstone = Data("cengine.storage.owner.v1\ndisabled\n".utf8)
    static func state(parent: Int32, owner: uid_t) throws -> State {
        guard let data = try StorageLifecycleQualificationFiles.read(parent, name, owner: owner) else { return .absent }
        if data == tombstone { return .disabled }
        let lines = String(decoding: data, as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: false)
        guard lines.count == 3, let uid = uid_t(lines[1]), uid != 0, encode(uid) == data else {
            throw BootstrapFailure(.repairRequired)
        }
        return .enrolled(uid)
    }
    static func load(parent: Int32, owner: uid_t) throws -> uid_t? {
        if case .enrolled(let uid) = try state(parent: parent, owner: owner) { return uid }
        return nil
    }
    /// flock(2) on the fixed lock file, descriptor-relative and O_NOFOLLOW. Only exclusive
    /// (administrative) holders may create it; a missing lock means never enrolled.
    static func withLock<T>(parent: Int32, owner: uid_t, exclusive: Bool, _ body: () throws -> T) throws -> T {
        let flags = (exclusive ? (O_RDWR | O_CREAT) : O_RDONLY) | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
        let fd = openat(parent, lockName, flags, 0o600)
        guard fd >= 0 else {
            if errno == ENOENT { throw BootstrapFailure(.unavailable) }
            throw BootstrapFailure(.repairRequired)
        }
        defer { close(fd) } // Closing the only descriptor releases the flock.
        try StorageLifecycleQualificationFiles.validate(fd, owner: owner, directory: false)
        while flock(fd, exclusive ? LOCK_EX : LOCK_SH) != 0 {
            guard errno == EINTR else { throw BootstrapFailure(.repairRequired) }
        }
        return try body()
    }
    /// Exclusive-lock holders only: atomic durable replacement via a fixed temporary.
    private static func replace(_ data: Data, parent: Int32, owner: uid_t, sync: (Int32) throws -> Void) throws {
        guard unlinkat(parent, temporaryName, 0) == 0 || errno == ENOENT else { throw BootstrapFailure(.repairRequired) }
        try StorageLifecycleQualificationFiles.write(data, parent: parent, name: temporaryName, owner: owner, sync: sync)
        guard renameat(parent, temporaryName, parent, name) == 0 else { throw BootstrapFailure(.repairRequired) }
        try sync(parent)
    }
    /// Idempotent for the same UID (returns false); a different UID never replaces an
    /// enrollment (conflict). Absent or tombstoned state is enrolled under the lock.
    @discardableResult
    static func enroll(_ uid: uid_t, parent: Int32, owner: uid_t,
                       sync: (Int32) throws -> Void = StorageLifecycleQualificationFiles.sync) throws -> Bool {
        guard uid != 0 else { throw BootstrapFailure(.unauthorized) }
        return try withLock(parent: parent, owner: owner, exclusive: true) {
            switch try state(parent: parent, owner: owner) {
            case .enrolled(let old):
                guard old == uid else { throw BootstrapFailure(.conflict) }
                return false
            case .absent, .disabled:
                try replace(encode(uid), parent: parent, owner: owner, sync: sync)
                return true
            }
        }
    }
    /// Writes the durable tombstone; returns whether an owner was enrolled.
    @discardableResult
    static func unenroll(parent: Int32, owner: uid_t,
                         sync: (Int32) throws -> Void = StorageLifecycleQualificationFiles.sync) throws -> Bool {
        try withLock(parent: parent, owner: owner, exclusive: true) {
            let old = try state(parent: parent, owner: owner)
            if old != .disabled { try replace(tombstone, parent: parent, owner: owner, sync: sync) }
            if case .enrolled = old { return true }
            return false
        }
    }
    static func openParent(create: Bool) throws -> Int32 {
        try StorageLifecycleQualificationFiles.fixedDirectory(parentComponents, privateLeaf: false, create: create)
    }
    /// Shared-lock read; absent/tombstoned refuses `unavailable`.
    static func enrolledOwner(parent: Int32, owner: uid_t) throws -> uid_t {
        try withLock(parent: parent, owner: owner, exclusive: false) {
            guard case .enrolled(let uid) = try state(parent: parent, owner: owner) else { throw BootstrapFailure(.unavailable) }
            return uid
        }
    }
    /// Descriptor-relative read-only traversal. Only genuine ENOENT means absent;
    /// symlinks, unsafe ancestors, permissions and I/O errors remain failures.
    static func statusParent(root: Int32, components: [String], owner: uid_t) throws -> Int32? {
        var fd = dup(root)
        guard fd >= 0 else { throw BootstrapFailure(.repairRequired) }
        do {
            try StorageLifecycleQualificationFiles.validate(fd, owner: owner, directory: true, privateMode: false)
            for component in components {
                guard !component.isEmpty, component != ".", component != "..", !component.contains("/"), !component.contains("\0") else {
                    throw BootstrapFailure(.invalidRequest)
                }
                let next = openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
                guard next >= 0 else {
                    if errno == ENOENT { close(fd); return nil }
                    throw BootstrapFailure(.repairRequired)
                }
                close(fd); fd = next
                try StorageLifecycleQualificationFiles.validate(fd, owner: owner, directory: true, privateMode: false)
            }
            return fd
        } catch { close(fd); throw error }
    }

    /// No creation, sync or repair. Busy administrative locks fail promptly rather
    /// than blocking the helper listener. A record without its lock is corruption.
    static func status(parent: Int32, owner: uid_t) throws -> State {
        try StorageLifecycleQualificationFiles.validate(parent, owner: owner, directory: true, privateMode: false)
        let fd = openat(parent, lockName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else {
            guard errno == ENOENT else { throw BootstrapFailure(.repairRequired) }
            var record = stat()
            guard fstatat(parent, name, &record, AT_SYMLINK_NOFOLLOW) != 0, errno == ENOENT else {
                throw BootstrapFailure(.repairRequired)
            }
            return .absent
        }
        defer { close(fd) }
        try StorageLifecycleQualificationFiles.validate(fd, owner: owner, directory: false)
        guard flock(fd, LOCK_SH | LOCK_NB) == 0 else { throw BootstrapFailure(.unavailable) }
        return try state(parent: parent, owner: owner)
    }

    static func status() throws -> State {
        let root = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { throw BootstrapFailure(.repairRequired) }
        defer { close(root) }
        guard let parent = try statusParent(root: root, components: parentComponents, owner: 0) else { return .absent }
        defer { close(parent) }
        return try status(parent: parent, owner: 0)
    }

    /// Live production owner; unsafe/unreadable state is never reclassified as absent.
    static func enrolledOwner() throws -> uid_t {
        guard case .enrolled(let uid) = try status() else { throw BootstrapFailure(.unavailable) }
        return uid
    }
}

/// Separate, read-only endpoint: production ordinary ENGINE only, regardless of
/// whether any owner is enrolled. Authentication never opens enrollment state.
enum StorageLifecycleOwnerStatus {
    static func authenticate(token: audit_token_t, team: String) throws {
        guard token.val.1 != 0 else { throw BootstrapFailure(.unauthorized) }
        _ = try StorageBootstrapProcesses(ownerUID: token.val.1, team: team, policy: .production)
            .daemon(audit: BootstrapAuditIdentity(token: token))
    }
    static func handle(_ message: xpc_object_t, reply: xpc_object_t) throws {
        try StorageOwnerStatusProtocol.validateRequest(message)
        let policy = try StorageLifecycleNativePolicy.current(role: .helper)
        guard policy.namespace == .production else { throw BootstrapFailure(.unauthorized) }
        let identity = try policy.currentIdentity(role: .helper)
        var token = audit_token_t(); productionPeerAudit(message, &token)
        try authenticate(token: token, team: identity.teamIdentifier)
        try StorageOwnerStatusProtocol.encode(StorageLifecycleOwnerEnrollment.status(), into: reply)
    }
}

/// Root-only administrative CLI: `enroll-storage-owner --uid N` / `unenroll-storage-owner`.
/// Seams (euid, user lookup, parent, owner, sync) exist for unprivileged tests only.
enum StorageLifecycleOwnerAdministration {
    static let enrollCommand = "enroll-storage-owner"
    static let unenrollCommand = "unenroll-storage-owner"
    struct Outcome: Equatable, Sendable {
        let status: Int32
        let message: String
    }
    static func handles(_ arguments: [String]) -> Bool {
        arguments.count >= 2 && [enrollCommand, unenrollCommand].contains(arguments[1])
    }
    static let usage = "usage: cengine-helper enroll-storage-owner --uid <uid> | unenroll-storage-owner"
    static func run(_ arguments: [String], euid: uid_t, userExists: (uid_t) -> Bool, owner: uid_t,
                    openParent: () throws -> Int32,
                    sync: (Int32) throws -> Void = StorageLifecycleQualificationFiles.sync) -> Outcome {
        guard euid == 0 else { return .init(status: 1, message: "storage owner enrollment must be run as root (sudo)") }
        let arguments = Array(arguments.dropFirst())
        var uid: uid_t?
        if arguments.count == 3, arguments[0] == enrollCommand, arguments[1] == "--uid" {
            guard let value = uid_t(arguments[2]), value > 0, String(value) == arguments[2], userExists(value) else {
                return .init(status: 1, message: "refusing storage owner uid \(arguments[2]): not an existing non-root local user")
            }
            uid = value
        } else if arguments != [unenrollCommand] {
            return .init(status: 2, message: usage)
        }
        do {
            let parent = try openParent(); defer { close(parent) }
            if let uid {
                let changed = try StorageLifecycleOwnerEnrollment.enroll(uid, parent: parent, owner: owner, sync: sync)
                return .init(status: 0, message: changed ? "storage owner enrolled: uid \(uid)" : "storage owner already enrolled: uid \(uid)")
            }
            let removed = try StorageLifecycleOwnerEnrollment.unenroll(parent: parent, owner: owner, sync: sync)
            return .init(status: 0, message: removed ? "storage owner unenrolled (disabled)" : "no storage owner is enrolled (disabled)")
        } catch let failure as BootstrapFailure where failure.code == .conflict {
            return .init(status: 1, message: "a different storage owner is enrolled; run unenroll-storage-owner first")
        } catch {
            return .init(status: 1, message: "storage owner enrollment failed: \(error)")
        }
    }
    static func live(_ arguments: [String]) -> Outcome {
        run(arguments, euid: geteuid(), userExists: { getpwuid($0) != nil }, owner: 0,
            openParent: { try StorageLifecycleOwnerEnrollment.openParent(create: true) })
    }
}

/// Exact signed-role check of a received message sender, independent of listener policy.
enum StorageLifecycleSignedPeer {
    static func euid(_ message: xpc_object_t, identifier: String, team: String) throws -> uid_t {
        var token = audit_token_t(); productionPeerAudit(message, &token)
        let data = withUnsafeBytes(of: &token) { Data($0) }
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: data] as CFDictionary, [], &code) == errSecSuccess,
              let code else { throw BootstrapFailure(.unauthorized) }
        let text = try SignedStorageIdentity.developerIDRequirement(identifiers: [identifier], team: team)
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess, let requirement,
              SecCodeCheckValidity(code, [], requirement) == errSecSuccess else { throw BootstrapFailure(.unauthorized) }
        let uid = token.val.1 // audit token euid
        guard uid != 0 else { throw BootstrapFailure(.unauthorized) }
        return uid
    }
}

extension StorageBootstrapLifecycleRouter {
    private static let compatibilityLock = NSLock()
    nonisolated(unsafe) private static var compatibilityValue: StorageBootstrapLifecycleRouter?

    /// Ordinary routing selects the actual signed helper namespace, never a request,
    /// environment toggle, failed qualification policy, or production fallback.
    /// Qualification envelopes are claimed separately by the compile-gated adapter.
    static func ordinaryRouter() throws -> StorageBootstrapLifecycleRouter {
        let policy = try StorageLifecycleNativePolicy.current(role: .helper)
        let team = try policy.currentIdentity(role: .helper).teamIdentifier
        switch policy.namespace {
        case .production: return try productionRouter(team: team)
        case .compatibility:
            return try compatibilityLock.withLock {
                _ = try StorageLifecycleScopeNamespace.compatibility.configuredOwner()
                if let compatibilityValue { return compatibilityValue }
                let value = try StorageBootstrapLifecycleRouter(namespace: .compatibility, policy: policy, team: team,
                    owner: { try StorageLifecycleScopeNamespace.compatibility.configuredOwner() })
                compatibilityValue = value
                return value
            }
        }
    }
    /// Disconnect/quiesce must not authenticate, create a router, or open state.
    static var existingCompatibilityRouter: StorageBootstrapLifecycleRouter? {
        compatibilityLock.withLock { compatibilityValue }
    }
    /// Listener policy while production v2 is enabled: exact engine + controller roles.
    /// Networking additionally requires the engine role per message.
    static func productionListenerRequirement(team: String) throws -> String {
        let p = StorageLifecycleNativePolicy.production
        return try SignedStorageIdentity.developerIDRequirement(identifiers: [p.engineIdentifier, p.controllerIdentifier], team: team)
    }
    static let productionTeam: String? = try? StorageLifecycleNativePolicy.production.currentIdentity(role: .helper).teamIdentifier
    private static let productionLock = NSLock()
    nonisolated(unsafe) private static var productionValue: StorageBootstrapLifecycleRouter?
    /// Lazily created on the first v2 production envelope. Nothing in the production
    /// namespace (directory or format marker) is created until an owner is enrolled;
    /// only success is cached, so a refused (e.g. v1) namespace keeps refusing unmodified.
    /// Seams are for unprivileged tests only.
    static func productionRouter(
        owner: () throws -> uid_t = { try StorageLifecycleOwnerEnrollment.enrolledOwner() },
        base: () throws -> Int32 = { try StorageLifecycleQualificationFiles.fixedBase(.production) },
        team: String? = productionTeam
    ) throws -> StorageBootstrapLifecycleRouter {
        try productionLock.withLock {
            if let productionValue { return productionValue }
            _ = try owner() // Unenrolled: `unavailable` with zero namespace bytes written.
            guard let team else { throw BootstrapFailure(.unavailable) }
            close(try base())
            let value = try StorageBootstrapLifecycleRouter(namespace: .production, policy: .production, team: team,
                owner: { try StorageLifecycleScopeNamespace.production.configuredOwner() })
            productionValue = value
            return value
        }
    }
    /// Disconnect/quiesce never create the namespace.
    static var existingProductionRouter: StorageBootstrapLifecycleRouter? { productionLock.withLock { productionValue } }
}

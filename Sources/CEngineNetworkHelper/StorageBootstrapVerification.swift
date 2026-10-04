import CEngineHelperSupport
import Darwin
import Foundation
import Security

@_silgen_name("csops")
private func bootstrapControllerCodeStatus(_ pid: Int32, _ operation: UInt32, _ buffer: UnsafeMutableRawPointer, _ size: Int) -> Int32

@_silgen_name("csops_audittoken")
private func bootstrapRegisteredCodeStatus(_ pid: Int32, _ operation: UInt32,
    _ buffer: UnsafeMutableRawPointer, _ size: Int, _ audit: UnsafeMutablePointer<audit_token_t>) -> Int32

/// Pure rejection policy, not a native authorization or an enrollment mechanism.
/// The hash is the frozen ROOT checkpoint hash, never the current executable path.
struct BootstrapRegisteredShimCodePin {
    let hash: Data

    init?(signingIdentity: String, identifier: String, team: String) {
        let fields = signingIdentity.split(separator: ":", omittingEmptySubsequences: false)
        guard [PrivilegedPortProtocol.defaultEngineIdentifier, PrivilegedPortProtocol.testCompatEngineIdentifier].contains(identifier),
              team.utf8.count == 10,
              team.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) }),
              fields.count == 3, fields[0] == identifier, fields[1] == team,
              let hash = Data(base64Encoded: String(fields[2])), hash.count == 20,
              hash.base64EncodedString() == fields[2] else { return nil }
        self.hash = hash
    }

    func accepts(hash: Data, beforeStatus: UInt32, afterStatus: UInt32) -> Bool {
        // SDK Kernel.framework/Headers/kern/cs_blobs.h: CS_VALID, CS_RUNTIME,
        // CS_ADHOC, CS_DEBUGGED (0x10000000, NOT CS_KILLED 0x01000000).
        let required: UInt32 = 0x0000_0001 | 0x0001_0000
        let forbidden: UInt32 = 0x0000_0002 | 0x1000_0000
        return hash.count == 20 && hash == self.hash && beforeStatus == afterStatus &&
            beforeStatus & required == required && beforeStatus & forbidden == 0
    }
}

/// Darwin audit_token_t ABI: auid, euid, egid, ruid, rgid, pid, asid, pidversion.
/// Only construct production identities from xpc_dictionary_get_audit_token's trailer.
struct BootstrapAuditIdentity {
    let token: audit_token_t
    init(token: audit_token_t) { self.token = token }
    var effectiveUID: uid_t { token.val.1 }
    var realUID: uid_t { token.val.3 }
    var pid: Int32 { Int32(bitPattern: token.val.5) }
    var pidVersion: UInt32 { token.val.7 }
    var data: Data { withUnsafeBytes(of: token) { Data($0) } }

    func matches(_ identity: BootstrapKernelIdentity, owner: uid_t) -> Bool {
        pid > 0 && effectiveUID == owner && realUID == owner && pidVersion == identity.pidVersion
    }
}

struct BootstrapKernelIdentity: Equatable {
    let uniqueID: UInt64
    let parentUniqueID: UInt64
    let pidVersion: UInt32

    func hasPinnedParent(_ daemon: BootstrapProcess) -> Bool {
        uniqueID != daemon.uniqueID && parentUniqueID == daemon.uniqueID
    }

    /// XNU bsd/sys/proc_info_private.h: PROC_PIDUNIQIDENTIFIERINFO (17),
    /// proc_uniqidentifierinfo is 56 bytes, uniqueid at 16, puniqueid at 24,
    /// idversion at 32. An unavailable/changed ABI fails closed, never falls back.
    static func read(_ pid: Int32) -> Self? {
        var bytes = [UInt8](repeating: 0, count: 56)
        guard proc_pidinfo(pid, 17, 0, &bytes, 56) == 56 else { return nil }
        return bytes.withUnsafeBytes {
            Self(uniqueID: $0.loadUnaligned(fromByteOffset: 16, as: UInt64.self),
                 parentUniqueID: $0.loadUnaligned(fromByteOffset: 24, as: UInt64.self),
                 pidVersion: $0.loadUnaligned(fromByteOffset: 32, as: UInt32.self))
        }
    }
}

/// Nonserializable native pin. Construction stays inside this verifier file; an
/// Origin DTO or same-UID signed sibling cannot be cast into this authorization.
struct StorageBootstrapRegisteredShim {
    let process: BootstrapProcess
    fileprivate init(process: BootstrapProcess) { self.process = process }
}

struct StorageBootstrapProcesses: Sendable {
    let ownerUID: uid_t
    let team: String
    private let lifecyclePolicy: StorageLifecycleNativePolicy

    init(ownerUID: uid_t, team: String, policy: StorageLifecycleNativePolicy) {
        self.ownerUID = ownerUID; self.team = team; lifecyclePolicy = policy
    }

    func daemon(audit: BootstrapAuditIdentity) throws -> BootstrapProcess {
        try pin(audit, identifier: lifecyclePolicy.engineIdentifier)
    }
    func child(audit: BootstrapAuditIdentity, daemon: BootstrapProcess) throws -> BootstrapProcess {
        guard try self.daemon(audit: Self.audit(daemon)) == daemon,
              let before = BootstrapKernelIdentity.read(audit.pid),
              before.hasPinnedParent(daemon) else { throw BootstrapFailure(.unauthorized) }
        let child = try pin(audit, identifier: lifecyclePolicy.controllerIdentifier)
        guard let after = BootstrapKernelIdentity.read(audit.pid), before == after,
              after.hasPinnedParent(daemon), child.boot == daemon.boot,
              try self.daemon(audit: Self.audit(daemon)) == daemon else { throw BootstrapFailure(.unauthorized) }
        return child
    }
    /// A storage shim is the signed engine executable, but must be a distinct
    /// live child of this exact independently pinned daemon. The direct fresh
    /// responder (not its role string) restricts proof to actual disk initialization.
    func storageShim(audit: BootstrapAuditIdentity, daemon: BootstrapProcess) throws -> BootstrapProcess {
        guard try self.daemon(audit: Self.audit(daemon)) == daemon,
              let before = BootstrapKernelIdentity.read(audit.pid), before.hasPinnedParent(daemon) else {
            throw BootstrapFailure(.unauthorized)
        }
        let shim = try pin(audit, identifier: lifecyclePolicy.engineIdentifier)
        guard BootstrapKernelIdentity.read(audit.pid) == before, shim.boot == daemon.boot,
              try self.daemon(audit: Self.audit(daemon)) == daemon else { throw BootstrapFailure(.unauthorized) }
        return shim
    }
    /// Separate reattachment check. `origin` MUST be read from the protected ROOT
    /// origin checkpoint, never from a requesting daemon's wire payload. A surviving
    /// shim need not remain a child of the replacement daemon (or of a live parent).
    /// This authenticates a process only: no session adoption or lock proof implied.
    func registeredStorageShim(audit: BootstrapAuditIdentity,
                               origin: BootstrapProcess) throws -> StorageBootstrapRegisteredShim {
        guard let pin = BootstrapRegisteredShimCodePin(signingIdentity: origin.signingIdentity,
                identifier: lifecyclePolicy.engineIdentifier, team: team) else { throw BootstrapFailure(.unauthorized) }
        // Enrollment already authenticated Developer ID, namespace, profile and
        // entitlements. An atomic upgrade changes the path's static code, not this
        // live image. Do not reopen that path or replace the checkpoint's CDHash.
        let before = try registeredIdentity(audit, origin: origin)
        var token = audit.token
        var beforeStatus: UInt32 = 0, afterStatus: UInt32 = 0
        var hash = Data(count: 20)
        // XNU CS_OPS_STATUS = 0, CS_OPS_CDHASH = 5. The audit token binds each
        // syscall to this exact exec generation, not merely a reusable PID.
        guard bootstrapRegisteredCodeStatus(audit.pid, 0, &beforeStatus, MemoryLayout<UInt32>.size, &token) == 0,
              hash.withUnsafeMutableBytes({
                  bootstrapRegisteredCodeStatus(audit.pid, 5, $0.baseAddress!, $0.count, &token)
              }) == 0,
              bootstrapRegisteredCodeStatus(audit.pid, 0, &afterStatus, MemoryLayout<UInt32>.size, &token) == 0,
              pin.accepts(hash: hash, beforeStatus: beforeStatus, afterStatus: afterStatus),
              try registeredIdentity(audit, origin: origin) == before else { throw BootstrapFailure(.unauthorized) }
        return StorageBootstrapRegisteredShim(process: origin)
    }

    private func registeredIdentity(_ audit: BootstrapAuditIdentity, origin: BootstrapProcess) throws -> BootstrapKernelIdentity {
        guard audit.data == origin.auditToken, audit.pid == origin.pid,
              let current = BootstrapKernelIdentity.read(audit.pid), audit.matches(current, owner: ownerUID),
              current.uniqueID == origin.uniqueID, current.pidVersion == origin.pidVersion,
              let info = Self.info(audit.pid), info.pbi_uid == ownerUID, info.pbi_ruid == ownerUID,
              info.pbi_start_tvsec == origin.startSeconds, info.pbi_start_tvusec == origin.startMicroseconds,
              try Self.boot() == origin.boot else { throw BootstrapFailure(.unauthorized) }
        return current
    }

    private static func audit(_ process: BootstrapProcess) throws -> BootstrapAuditIdentity {
        guard process.auditToken.count == MemoryLayout<audit_token_t>.size else { throw BootstrapFailure(.unauthorized) }
        return BootstrapAuditIdentity(token: process.auditToken.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) })
    }

    // FD checks are identity evidence only: formatter/adoption authorization, disk
    // exclusivity and verified child TLS-result integration remain pending.

    func liveness(_ process: BootstrapProcess) -> BootstrapLiveness {
        guard let boot = try? Self.boot() else { return .unknown }
        if boot != process.boot { return .exited }
        errno = 0
        guard let current = BootstrapKernelIdentity.read(process.pid) else {
            return errno == ESRCH ? .exited : .unknown
        }
        // Exec changes pidversion but does not prove the process (or key) exited.
        return current.uniqueID != process.uniqueID ? .exited : .alive
    }
    private func pin(_ audit: BootstrapAuditIdentity, identifier: String) throws -> BootstrapProcess {
        let pid = audit.pid
        guard team.count == 10, team.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) }),
              let before = BootstrapKernelIdentity.read(pid), audit.matches(before, owner: ownerUID),
              let beforeInfo = Self.info(pid), beforeInfo.pbi_uid == ownerUID, beforeInfo.pbi_ruid == ownerUID else {
            throw BootstrapFailure(.unauthorized)
        }
        let boot = try Self.boot()
        let text = try SignedCompatibilityIdentity.developerIDRequirement(identifiers: [identifier], team: team)
        var requirement: SecRequirement?
        var code: SecCode?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
              let requirement,
              SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: audit.data] as CFDictionary, [], &code) == errSecSuccess,
              let code, SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else {
            throw BootstrapFailure(.unauthorized)
        }
        if identifier == PrivilegedPortProtocol.testCompatEngineIdentifier || identifier == PrivilegedPortProtocol.defaultEngineIdentifier {
            try lifecyclePolicy.validatePeer(code, pid: pid, role: .engine, expectedTeam: team)
        }
        var information: CFDictionary?
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let dictionary = information as? [String: Any], let hash = dictionary[kSecCodeInfoUnique as String] as? Data,
              let after = BootstrapKernelIdentity.read(pid), before == after, audit.matches(after, owner: ownerUID),
              let afterInfo = Self.info(pid), beforeInfo.pbi_start_tvsec == afterInfo.pbi_start_tvsec,
              beforeInfo.pbi_start_tvusec == afterInfo.pbi_start_tvusec,
              afterInfo.pbi_uid == ownerUID, afterInfo.pbi_ruid == ownerUID,
              try Self.boot() == boot else { throw BootstrapFailure(.unauthorized) }
        if identifier == "dev.cengine.storage-control" || identifier == "dev.cengine.storage-control.test-compat" {
            try lifecyclePolicy.validateControllerCode(staticCode, expectedTeam: team)
            let entitlements = dictionary[kSecCodeInfoEntitlementsDict as String]
            guard entitlements == nil || entitlements is [String: Any],
                  let flags = dictionary[kSecCodeInfoFlags as String] as? NSNumber,
                  SignedStorageIdentity.acceptsControllerCodeSigning(flags: flags.uint32Value,
                    entitlementKeys: Set((entitlements as? [String: Any] ?? [:]).keys)) else { throw BootstrapFailure(.unauthorized) }
            var status: UInt32 = 0
            guard bootstrapControllerCodeStatus(pid, 0, &status, MemoryLayout<UInt32>.size) == 0,
                  status & SignedStorageIdentity.controllerRuntimeFlag != 0,
                  BootstrapKernelIdentity.read(pid) == after else { throw BootstrapFailure(.unauthorized) }
        }
        return BootstrapProcess(pid: pid, startSeconds: afterInfo.pbi_start_tvsec, startMicroseconds: afterInfo.pbi_start_tvusec,
            boot: boot, signingIdentity: identifier + ":" + team + ":" + hash.base64EncodedString(),
            uniqueID: after.uniqueID, pidVersion: after.pidVersion, auditToken: audit.data)
    }
    private static func info(_ pid: Int32) -> proc_bsdinfo? {
        var value = proc_bsdinfo()
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &value, Int32(MemoryLayout.size(ofValue: value))) == MemoryLayout.size(ofValue: value) else { return nil }
        return value
    }
    private static func boot() throws -> String {
        var bytes = [CChar](repeating: 0, count: 128)
        var size = bytes.count
        guard sysctlbyname("kern.bootsessionuuid", &bytes, &size, nil, 0) == 0, size > 1, size <= bytes.count,
              let uuid = UUID(uuidString: String(cString: bytes)) else { throw BootstrapFailure(.unavailable) }
        return uuid.uuidString.lowercased()
    }
}

/// Closed diagnostic vocabulary: never carries paths, descriptor numbers, identities,
/// request contents or arbitrary error descriptions. errno is captured only at a failed syscall.
struct StorageBootstrapBindingDiagnostic: Equatable, Sendable {
    enum Stage: String, CaseIterable, Sendable {
        case identityStat, identityType, identityOwner, identityMode, identityFilesystem
        case identityLocal, identityACL, identityAttributes, identityAttributeLength, identityValue
        case backingStat, backingLinks, backingLength, rootBinding, backingBinding, backingSize
        case descriptorPath, pathContainment, pathComponents, rootDuplicate
        case componentOpen, componentStat, componentType, componentDescriptor, componentBinding
        case superblockRead, superblockLength, superblockMagic, superblockUUID
        case finalRootBinding, finalBackingBinding, finalBackingStat, finalBackingSize
    }
    enum Role: String, CaseIterable, Sendable { case root, backing, component }
    let stage: Stage
    let role: Role
    var syscallErrno: Int32? = nil

    var line: String {
        "storage-bootstrap-binding-rejected stage=\(stage.rawValue) role=\(role.rawValue)" +
            (syscallErrno.map { " errno=\($0)" } ?? "") + "\n"
    }
    static func emit(_ diagnostic: Self) {
        // One bounded, best-effort line to the helper LaunchDaemon's existing stderr log.
        // Logging failure neither changes authorization nor retries the failed operation.
        diagnostic.line.utf8CString.withUnsafeBytes { bytes in
            _ = Darwin.write(STDERR_FILENO, bytes.baseAddress, bytes.count - 1)
        }
    }
}

struct StorageBootstrapBindings: BootstrapBindingChecking {
    typealias Diagnostic = StorageBootstrapBindingDiagnostic
    let ownerUID: uid_t
    // Internal observation seam only; no XPC request can choose the sink or its contents.
    var diagnostic: (Diagnostic) -> Void = Diagnostic.emit
    // Internal fault seam; native ownership/mode/ACL checks always run first.
    var observation: (StorageIdentity.DescriptorIdentity) -> StorageIdentity.DescriptorIdentity = { $0 }

    private func reject(_ stage: Diagnostic.Stage, _ role: Diagnostic.Role,
                        code: StorageIdentity.ErrorCode = .conflict, syscallErrno: Int32? = nil) -> BootstrapFailure {
        diagnostic(.init(stage: stage, role: role, syscallErrno: syscallErrno))
        return BootstrapFailure(code)
    }

    /// Native greetings are live evidence, not merely stable store correlation.
    func verify(_ binding: StorageIdentity.StoreBinding, rootFD: Int32, backingFD: Int32,
                expectedBacking: StorageIdentity.DescriptorIdentity) throws {
        let root = try observe(rootFD, type: S_IFDIR, role: .root)
        guard try observe(backingFD, type: S_IFREG, role: .backing) == expectedBacking else {
            throw reject(.backingBinding, .backing)
        }
        try verify(binding, rootFD: rootFD, backingFD: backingFD)
        guard try observe(rootFD, type: S_IFDIR, role: .root) == root else { throw reject(.finalRootBinding, .root) }
        guard try observe(backingFD, type: S_IFREG, role: .backing) == expectedBacking else {
            throw reject(.finalBackingBinding, .backing)
        }
    }

    func verify(_ binding: StorageIdentity.StoreBinding, rootFD: Int32, backingFD: Int32) throws {
        let root = try observe(rootFD, type: S_IFDIR, role: .root)
        let backing = try observe(backingFD, type: S_IFREG, role: .backing)
        var info = stat()
        guard fstat(backingFD, &info) == 0 else { throw reject(.backingStat, .backing, syscallErrno: errno) }
        guard info.st_nlink == 1 else { throw reject(.backingLinks, .backing) }
        guard info.st_size > 0 else { throw reject(.backingLength, .backing) }
        guard root.stableIdentity == binding.root else { throw reject(.rootBinding, .root) }
        guard backing.stableIdentity == binding.backing.identity else { throw reject(.backingBinding, .backing) }
        guard UInt64(info.st_size) == binding.backing.size else { throw reject(.backingSize, .backing) }
        // Resolve kernel-provided descriptor paths only, then reopen each component beneath
        // the pinned root with NOFOLLOW. No caller-supplied pathname is ever opened.
        let rootPath = try path(rootFD, role: .root), backingPath = try path(backingFD, role: .backing)
        guard backingPath.hasPrefix(rootPath + "/") else { throw reject(.pathContainment, .backing) }
        let components = backingPath.dropFirst(rootPath.count + 1).split(separator: "/").map(String.init)
        guard !components.isEmpty, components.allSatisfy({ $0 != "." && $0 != ".." }) else {
            throw reject(.pathComponents, .component)
        }
        var cursor = dup(rootFD)
        guard cursor >= 0 else { throw reject(.rootDuplicate, .root, code: .unavailable, syscallErrno: errno) }
        defer { close(cursor) }
        for (index, component) in components.enumerated() {
            let last = index == components.count - 1
            let next = try Self.openComponent(cursor, name: component, last: last, diagnostic: diagnostic)
            guard next >= 0 else { throw reject(.componentDescriptor, .component) }
            close(cursor); cursor = next
            _ = try observe(cursor, type: last ? S_IFREG : S_IFDIR, role: .component)
        }
        guard try observe(cursor, type: S_IFREG, role: .component) == backing else {
            throw reject(.componentBinding, .component)
        }
        var superblock = [UInt8](repeating: 0, count: 120)
        let count = pread(backingFD, &superblock, superblock.count, 1024)
        guard count >= 0 else { throw reject(.superblockRead, .backing, syscallErrno: errno) }
        guard count == superblock.count else { throw reject(.superblockLength, .backing) }
        guard superblock[56] == 0x53, superblock[57] == 0xef else { throw reject(.superblockMagic, .backing) }
        let hex = superblock[104..<120].map { String(format: "%02x", $0) }.joined()
        let expected = binding.expectedExt4UUID.rawValue.replacingOccurrences(of: "-", with: "")
        guard hex == expected else { throw reject(.superblockUUID, .backing) }
        guard try observe(rootFD, type: S_IFDIR, role: .root) == root else { throw reject(.finalRootBinding, .root) }
        guard try observe(backingFD, type: S_IFREG, role: .backing) == backing else {
            throw reject(.finalBackingBinding, .backing)
        }
        guard fstat(backingFD, &info) == 0 else { throw reject(.finalBackingStat, .backing, syscallErrno: errno) }
        guard UInt64(info.st_size) == binding.backing.size else { throw reject(.finalBackingSize, .backing) }
    }
    // NONBLOCK is essential: a concurrent FIFO replacement must not stall ROOT's lock.
    static func openComponent(_ directory: Int32, name: String, last: Bool,
                              diagnostic: (Diagnostic) -> Void = Diagnostic.emit) throws -> Int32 {
        let fd = openat(directory, name, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW | (last ? 0 : O_DIRECTORY))
        guard fd >= 0 else {
            diagnostic(.init(stage: .componentOpen, role: .component, syscallErrno: errno))
            throw BootstrapFailure(.conflict)
        }
        var info = stat()
        guard fstat(fd, &info) == 0 else {
            let savedErrno = errno
            close(fd)
            diagnostic(.init(stage: .componentStat, role: .component, syscallErrno: savedErrno))
            throw BootstrapFailure(.conflict)
        }
        guard info.st_mode & S_IFMT == (last ? S_IFREG : S_IFDIR) else {
            close(fd)
            diagnostic(.init(stage: .componentType, role: .component))
            throw BootstrapFailure(.conflict)
        }
        return fd
    }
    func identity(_ fd: Int32, type: mode_t, role: Diagnostic.Role) throws -> StorageIdentity.RootIdentity {
        try observe(fd, type: type, role: role).stableIdentity
    }
    func observe(_ fd: Int32, type: mode_t, role: Diagnostic.Role) throws -> StorageIdentity.DescriptorIdentity {
        var info = stat(), fs = statfs()
        guard fstat(fd, &info) == 0 else { throw reject(.identityStat, role, syscallErrno: errno) }
        guard info.st_mode & S_IFMT == type else { throw reject(.identityType, role) }
        guard info.st_uid == ownerUID else { throw reject(.identityOwner, role) }
        guard info.st_mode & 0o7022 == 0 else { throw reject(.identityMode, role) }
        guard fstatfs(fd, &fs) == 0 else { throw reject(.identityFilesystem, role, syscallErrno: errno) }
        guard fs.f_flags & UInt32(MNT_LOCAL) != 0 else { throw reject(.identityLocal, role) }
        do { try StorageBootstrapSecureFilesystem.requireNoACL(fd) }
        catch {
            // The ACL helper includes policy failures and cleanup: errno is not evidence here.
            diagnostic(.init(stage: .identityACL, role: role))
            throw error
        }
        var attributes = attrlist()
        attributes.bitmapcount = UInt16(ATTR_BIT_MAP_COUNT)
        attributes.volattr = ATTR_VOL_INFO | UInt32(ATTR_VOL_UUID)
        var bytes = [UInt8](repeating: 0, count: 20)
        guard fgetattrlist(fd, &attributes, &bytes, bytes.count, 0) == 0 else {
            throw reject(.identityAttributes, role, syscallErrno: errno)
        }
        guard bytes.withUnsafeBytes({ $0.loadUnaligned(as: UInt32.self) }) == 20 else {
            throw reject(.identityAttributeLength, role)
        }
        let uuid = bytes.withUnsafeBytes { UUID(uuid: $0.loadUnaligned(fromByteOffset: 4, as: uuid_t.self)) }
        do {
            return observation(try StorageIdentity.DescriptorIdentity(volumeUUID: StorageIdentity.FilesystemUUID(uuid.uuidString.lowercased()),
                device: UInt64(UInt32(bitPattern: info.st_dev)), inode: info.st_ino))
        } catch {
            diagnostic(.init(stage: .identityValue, role: role))
            throw error
        }
    }
    private func path(_ fd: Int32, role: Diagnostic.Role) throws -> String {
        var bytes = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(fd, F_GETPATH, &bytes) == 0 else { throw reject(.descriptorPath, role, syscallErrno: errno) }
        return String(cString: bytes)
    }
}

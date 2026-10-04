#if os(macOS) && CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
import CEngineCore
import Darwin
import Foundation
import Security

/// Trusted fresh-only qualification spawn owner. The canonical daemon lock and
/// exact leased disk description remain retained through actual child waitpid.
/// No PID, executable, environment, arbitrary specification or proof DTO input.
final class StorageLifecycleShimProcess: @unchecked Sendable {
    let connection: StorageLifecycleShimConnection
    let pid: Int32
    private let lock = NSLock()
    private var reaped = false
    private var retained: (CanonicalDataStoreLock, VMShimAttachmentResources)?

    private init(connection: StorageLifecycleShimConnection, pid: Int32,
                 storeLock: CanonicalDataStoreLock, attachments: VMShimAttachmentResources) {
        self.connection = connection; self.pid = pid; retained = (storeLock, attachments)
    }

    /// Both asset digests are trusted caller inputs. Source-pin metadata alone
    /// is not a signature over guest bytes and cannot supply replacement hashes.
    static func launch(root: StorageIdentity.RootPublicKey, binding: StorageIdentity.StoreBinding,
                       storeLock: CanonicalDataStoreLock, backingFile: URL, kernel: URL,
                       initialRamdisk: URL, expectedInitramfsSHA256: String, expectedKernelSHA256: String,
                       policy: StorageLifecycleNativePolicy) async throws -> StorageLifecycleShimProcess {
        let process = try await StorageLifecycleQualificationShim.worker {
            // Closed policy is a native value minted from this signed process,
            // never a caller-selectable namespace or decoded profile.
            guard policy.isQualification,
                  try policy == .qualification(role: .engine) else { throw failure() }
            let identity = try policy.currentIdentity(role: .engine)
            guard backingFile.isFileURL, kernel.isFileURL, initialRamdisk.isFileURL else { throw failure() }
            try storeLock.validateRetainedOwnership()
            let frozen = StorageLifecycleShimBootstrap(profile: StorageLifecycleShimBootstrap.version,
                rootPublicKey: root.publicData, binding: .init(binding), storeRoot: storeLock.root.path,
                backingFile: backingFile.path, kernel: kernel.path, initialRamdisk: initialRamdisk.path,
                initramfsSHA256: expectedInitramfsSHA256, kernelSHA256: expectedKernelSHA256,
                launchUUID: UUID().uuidString.lowercased())
            try frozen.validate()
            let directory = try storeLock.duplicateRetainedDirectory()
            defer { Darwin.close(directory) }
            try frozen.validateRoot(descriptor: directory)
            let backingDirectory = try PersistentStateDirectory.open(backingFile.deletingLastPathComponent())
            let observed = try backingDirectory.openRegularFile(named: backingFile.lastPathComponent, access: .readOnly)
            defer { try? observed.handle.close() }
            let specification = try frozen.specification(backingIdentity: observed.identity.shimIdentity)
            let attachments = try VMShimAttachmentResolver.resolve(specification)
            guard attachments.disks.count == 1, let disk = attachments.disks.first,
                  disk.identity.device == observed.identity.device,
                  disk.identity == observed.identity else { throw failure() }
            try frozen.validateFreshDisk(disk)
            let bytes = try StorageLifecycleProtocol.encode(frozen)
            return try spawn(executable: identity.executable, team: identity.teamIdentifier,
                policy: policy, bytes: bytes, storeLock: storeLock, attachments: attachments)
        }
        do { try Task.checkCancellation(); return process }
        catch { try await process.teardown(); throw error }
    }

    private static func spawn(executable: URL, team: String, policy: StorageLifecycleNativePolicy,
        bytes: Data, storeLock: CanonicalDataStoreLock,
        attachments: VMShimAttachmentResources) throws -> StorageLifecycleShimProcess {
        // Static preflight never substitutes for checking the actual suspended child.
        var code: SecStaticCode?, requirement: SecRequirement?
        let text = try SignedStorageIdentity.developerIDRequirement(identifiers: [policy.engineIdentifier], team: team)
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess, let requirement,
              SecStaticCodeCreateWithPath(executable as CFURL, [], &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else {
            throw failure()
        }
        var sockets: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0 else { throw systemError() }
        defer { Darwin.close(sockets[0]); Darwin.close(sockets[1]) }
        for fd in sockets {
            guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { throw systemError() }
        }
        let flags = fcntl(sockets[0], F_GETFL)
        var one: Int32 = 1
        guard flags >= 0, fcntl(sockets[0], F_SETFL, flags | O_NONBLOCK) == 0,
              setsockopt(sockets[0], SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            throw systemError()
        }
        var childFD = fcntl(sockets[1], F_DUPFD_CLOEXEC, 10)
        guard childFD >= 0 else { throw systemError() }
        defer { Darwin.close(childFD) }
        let originalNull = open("/dev/null", O_RDWR | O_CLOEXEC)
        guard originalNull >= 0 else { throw systemError() }
        let nullFD = fcntl(originalNull, F_DUPFD_CLOEXEC, 10)
        Darwin.close(originalNull)
        guard nullFD >= 0 else { throw systemError() }
        defer { Darwin.close(nullFD) }
        var actions: posix_spawn_file_actions_t?, attributes: posix_spawnattr_t?
        try check(posix_spawn_file_actions_init(&actions))
        defer { posix_spawn_file_actions_destroy(&actions) }
        try check(posix_spawnattr_init(&attributes))
        defer { posix_spawnattr_destroy(&attributes) }
        // FD allowlist: three /dev/null streams and the private socket at FD3.
        // Disk rights are sent only after actual-child authentication, not inherited.
        for (source, target) in [(childFD, Int32(3)), (nullFD, Int32(0)), (nullFD, Int32(1)), (nullFD, Int32(2))] {
            try check(posix_spawn_file_actions_adddup2(&actions, source, target))
        }
        try check(posix_spawnattr_setflags(&attributes,
            Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_START_SUSPENDED)))
        let strings = [executable.path, StorageLifecycleQualificationShim.argument]
        let pointers = strings.map { strdup($0) }
        defer { pointers.forEach { free($0) } }
        guard pointers.allSatisfy({ $0 != nil }) else { throw POSIXError(.ENOMEM) }
        var argv = pointers + [nil]
        var environment: [UnsafeMutablePointer<CChar>?] = [nil]
        var pid: pid_t = 0
        try check(posix_spawn(&pid, executable.path, &actions, &attributes, &argv, &environment))
        // Close every parent copy of the child's socket before any IO/EOF wait.
        Darwin.close(sockets[1]); sockets[1] = -1
        Darwin.close(childFD); childFD = -1
        var process: StorageLifecycleShimProcess?
        do {
            // Uses task_name_for_pid audit token + direct-parent unique IDs and
            // policy.validatePeer (Developer ID, sealed profile, csops runtime).
            // Crucially this runs BEFORE SIGCONT and before any bootstrap bytes.
            let connection = try StorageLifecycleShimConnection(parentBorrowedFD: sockets[0],
                expectedChildPID: pid, policy: policy)
            let owner = StorageLifecycleShimProcess(connection: connection, pid: pid,
                storeLock: storeLock, attachments: attachments)
            process = owner
            guard kill(pid, SIGCONT) == 0 else { throw systemError() }
            try storeLock.validateRetainedOwnership()
            let deadline = StorageLifecycleShimChannel.deadline(30)
            try StorageLifecycleShimChannel.send(bytes, fd: sockets[0],
                passing: attachments.disks[0].handle.fileDescriptor, deadline: deadline)
            let reply = try StorageLifecycleShimChannel.receive(fd: sockets[0], permitsDescriptor: false, deadline: deadline)
            guard reply.body == Data("lifecycle-v2-native-v1:bound".utf8) else { throw failure() }
            return owner
        } catch {
            if let process { process.destroyAndReap() }
            else { kill(pid, SIGKILL); waitForKilledChild(pid) }
            throw error
        }
    }

    /// Only proves the existing shim stop exchange; not ROOT retirement/deletion.
    func stop() async throws { try await connection.stop() }

    /// Reap without signaling. Timeout retains both datastore and backing leases.
    func reap(timeout: TimeInterval = 10) async throws {
        guard timeout.isFinite, timeout > 0, timeout <= 120 else { throw Self.failure() }
        try await StorageLifecycleQualificationShim.worker { [self] in
            try lock.withLock {
                if reaped { return }
                let deadline = ProcessInfo.processInfo.systemUptime + timeout
                while true {
                    var status: Int32 = 0
                    let result = waitpid(pid, &status, WNOHANG)
                    if result == pid { reaped = true; retained = nil; return }
                    if result < 0 && errno != EINTR { throw Self.systemError() }
                    guard ProcessInfo.processInfo.systemUptime < deadline else { throw Self.failure() }
                    usleep(10_000)
                }
            }
        }
    }
    /// Forced containment plus actual reap, never a drain receipt. No file removal.
    func teardown() async throws {
        connection.cancel()
        try await StorageLifecycleQualificationShim.worker { [self] in
            try lock.withLock {
                guard !reaped else { return }
                guard kill(pid, SIGKILL) == 0 || errno == ESRCH else { throw Self.systemError() }
            }
        }
        try await reap()
    }
    private func destroyAndReap() {
        connection.cancel()
        lock.withLock {
            guard !reaped else { return }
            kill(pid, SIGKILL)
            Self.waitForKilledChild(pid)
            reaped = true; retained = nil
        }
    }
    deinit { destroyAndReap() }
    private static func waitForKilledChild(_ pid: Int32) {
        var status: Int32 = 0
        while waitpid(pid, &status, 0) < 0 && errno == EINTR {}
    }
    private static func check(_ code: Int32) throws {
        guard code == 0 else { throw POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO) }
    }
    private static func systemError() -> POSIXError { POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    private static func failure() -> EngineError { StorageLifecycleShimBootstrap.failure() }
}
#endif

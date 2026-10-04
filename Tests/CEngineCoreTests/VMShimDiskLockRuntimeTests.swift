#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

// Darwin may briefly retain CLOEXEC file descriptions while another thread
// spawns, before the child reaches exec. Keep immediate-release assertions in
// isolated processes, not serialized suites or retry loops. Nested expectations
// are still reported to the parent by Swift Testing.
@Suite struct VMShimDiskLockRuntimeTests {
    @Test func locksExactDescriptorsBeforeHooksAndRetainsUntilRelease() async {
        await #expect(processExitsWith: .success) {
            try VMShimDiskLockRuntimeTests().checkLocksExactDescriptorsBeforeHooksAndRetainsUntilRelease()
        }
    }

    private func checkLocksExactDescriptorsBeforeHooksAndRetainsUntilRelease() throws {
        let fixture = try DiskLockFixture()
        defer { fixture.remove() }
        let specification = try fixture.specification(volumes: ["volume"])
        var boundaries: [VMShimAttachmentBoundary] = []
        do {
            let resources = try VMShimAttachmentResolver.resolve(specification) { boundary in
                boundaries.append(boundary)
                let name = boundary == .rootDiskOpened ? "root" : "volume"
                try expectDiskLock(fixture.url(name), available: false)
            }
            defer { withExtendedLifetime(resources) {} }
            #expect(boundaries == [.rootDiskOpened, .volumeDiskOpened("volume")])
            for handle in resources.retainedHandles {
                #expect(fcntl(handle.fileDescriptor, F_GETFD) & FD_CLOEXEC != 0)
                #expect(fcntl(handle.fileDescriptor, F_GETFL) & O_ACCMODE == O_RDWR)
            }
            #expect(resources.rootDisk.path == "/dev/fd/\(resources.retainedHandles[0].fileDescriptor)")
            #expect(resources.additionalDisks[0].source.path == "/dev/fd/\(resources.retainedHandles[1].fileDescriptor)")
            expectConflict { _ = try VMShimAttachmentResolver.resolve(specification) }
            try expectDiskLock(fixture.url("root"), available: false)
            try expectDiskLock(fixture.url("volume"), available: false)
        }
        try expectDiskLock(fixture.url("root"), available: true)
        try expectDiskLock(fixture.url("volume"), available: true)
        try fixture.expectUnchanged()
    }

    @Test func sharedReadOnlyRootsCoexistButExcludeEveryWriter() async {
        await #expect(processExitsWith: .success) {
            try VMShimDiskLockRuntimeTests().checkSharedReadOnlyRootsCoexistButExcludeEveryWriter()
        }
    }

    private func checkSharedReadOnlyRootsCoexistButExcludeEveryWriter() throws {
        let fixture = try DiskLockFixture()
        defer { fixture.remove() }
        let readOnly = try fixture.specification(readOnly: true)
        do {
            let first = try VMShimAttachmentResolver.resolve(readOnly)
            let second = try VMShimAttachmentResolver.resolve(readOnly)
            defer { withExtendedLifetime((first, second)) {} }
            #expect(fcntl(first.retainedHandles[0].fileDescriptor, F_GETFL) & O_ACCMODE == O_RDONLY)
            try expectDiskLock(fixture.url("root"), available: true, shared: true)
            expectConflict { _ = try VMShimAttachmentResolver.resolve(fixture.specification()) }
            // An additional disk is always writable, even with a read-only root.
            expectConflict {
                _ = try VMShimAttachmentResolver.resolve(fixture.specification(root: "volume", volumes: ["root"]))
            }
            try expectDiskLock(fixture.url("volume"), available: true)
        }
        let writer = try VMShimAttachmentResolver.resolve(fixture.specification())
        defer { withExtendedLifetime(writer) {} }
        expectConflict { _ = try VMShimAttachmentResolver.resolve(readOnly) }
        try fixture.expectUnchanged()
    }

    @Test(arguments: ["root", "volume", "hardlink"])
    func duplicateDiskFailsWithoutWaitingAndReleasesPartialHandles(duplicate: String) async {
        await #expect(processExitsWith: .success) { [duplicate] in
            try VMShimDiskLockRuntimeTests().checkDuplicateDiskFailsWithoutWaitingAndReleasesPartialHandles(duplicate: duplicate)
        }
    }

    private func checkDuplicateDiskFailsWithoutWaitingAndReleasesPartialHandles(duplicate: String) throws {
        let fixture = try DiskLockFixture()
        defer { fixture.remove() }
        #expect(link(fixture.url("volume").path, fixture.url("hardlink").path) == 0)
        let volumes = duplicate == "root" ? ["root"] : ["volume", duplicate]
        var boundaries: [VMShimAttachmentBoundary] = []
        expectConflict {
            _ = try VMShimAttachmentResolver.resolve(fixture.specification(volumes: volumes)) {
                boundaries.append($0)
            }
        }
        #expect(boundaries == (duplicate == "root" ? [.rootDiskOpened] : [.rootDiskOpened, .volumeDiskOpened("volume")]))
        try expectDiskLock(fixture.url("root"), available: true)
        try expectDiskLock(fixture.url("volume"), available: true)
        try fixture.expectUnchanged()
    }

    @Test func laterContentionAndHookFailureReleaseOnlyPartialAcquisitions() async {
        await #expect(processExitsWith: .success) {
            try VMShimDiskLockRuntimeTests().checkLaterContentionAndHookFailureReleaseOnlyPartialAcquisitions()
        }
    }

    private func checkLaterContentionAndHookFailureReleaseOnlyPartialAcquisitions() throws {
        let fixture = try DiskLockFixture()
        defer { fixture.remove() }
        do {
            let owner = try VMShimAttachmentResolver.resolve(fixture.specification(root: "volume"))
            defer { withExtendedLifetime(owner) {} }
            var boundaries: [VMShimAttachmentBoundary] = []
            expectConflict {
                _ = try VMShimAttachmentResolver.resolve(fixture.specification(volumes: ["volume"])) {
                    boundaries.append($0)
                }
            }
            #expect(boundaries == [.rootDiskOpened])
            try expectDiskLock(fixture.url("root"), available: true)
            try expectDiskLock(fixture.url("volume"), available: false)
        }
        expectConflict {
            _ = try VMShimAttachmentResolver.resolve(fixture.specification(volumes: ["volume"])) { boundary in
                if boundary == .volumeDiskOpened("volume") {
                    throw EngineError(.conflict, "injected hook failure")
                }
            }
        }
        try expectDiskLock(fixture.url("root"), available: true)
        try expectDiskLock(fixture.url("volume"), available: true)
        try fixture.expectUnchanged()
    }

    @Test func renamedAndHardlinkedInodeRemainsLockedNotItsReplacement() async {
        await #expect(processExitsWith: .success) {
            try VMShimDiskLockRuntimeTests().checkRenamedAndHardlinkedInodeRemainsLockedNotItsReplacement()
        }
    }

    private func checkRenamedAndHardlinkedInodeRemainsLockedNotItsReplacement() throws {
        let fixture = try DiskLockFixture()
        defer { fixture.remove() }
        do {
            let resources = try VMShimAttachmentResolver.resolve(fixture.specification())
            defer { withExtendedLifetime(resources) {} }
            #expect(link(fixture.url("root").path, fixture.url("alias").path) == 0)
            try FileManager.default.moveItem(at: fixture.url("root"), to: fixture.url("renamed"))
            try DiskLockFixture.contents.write(to: fixture.url("root"))
            try expectDiskLock(fixture.url("alias"), available: false)
            try expectDiskLock(fixture.url("renamed"), available: false)
            try expectDiskLock(fixture.url("root"), available: true)
            #expect(try Data(contentsOf: resources.rootDisk) == DiskLockFixture.contents)
        }
        try expectDiskLock(fixture.url("alias"), available: true)
        try expectDiskLock(fixture.url("renamed"), available: true)
    }

    @Test func ownedShimDoesNotInheritUnrelatedTestDescriptors() async {
        await #expect(processExitsWith: .success) {
            try VMShimDiskLockRuntimeTests().checkOwnedShimDoesNotInheritUnrelatedTestDescriptors()
        }
    }

    private func checkOwnedShimDoesNotInheritUnrelatedTestDescriptors() throws {
        let fixture = try DiskLockFixture()
        defer { fixture.remove() }
        let executable = try buildDiskLeaseHelper(in: fixture.directory)
        let resources = try VMShimAttachmentResolver.resolve(fixture.specification())
        defer { withExtendedLifetime(resources) {} }

        // Model descriptors belonging to concurrent tests, including temporary
        // Foundation opens. Neither deliberately has FD_CLOEXEC set.
        var unrelatedDisk = open(fixture.url("volume").path, O_RDWR)
        try #require(unrelatedDisk >= 0)
        defer { if unrelatedDisk >= 0 { close(unrelatedDisk) } }
        try #require(flock(unrelatedDisk, LOCK_EX | LOCK_NB) == 0)
        var sockets: [CInt] = [-1, -1]
        try #require(socketpair(AF_UNIX, CInt(SOCK_DGRAM), 0, &sockets) == 0)
        defer { for descriptor in sockets where descriptor >= 0 { close(descriptor) } }

        let owner = try DiskLeaseOwner(executable: executable, descriptor: resources.retainedHandles[0].fileDescriptor)
        defer { owner.stop() }
        // READY proves the child is holding its inherited descriptors, without
        // depending on scheduler speed or a sleep before the release checks.
        try #require(owner.readLine().hasPrefix("READY "))
        owner.stopDaemon()
        close(unrelatedDisk)
        unrelatedDisk = -1
        close(sockets[0])
        sockets[0] = -1
        try expectDiskLock(fixture.url("volume"), available: true)
        var byte: UInt8 = 0
        let result = Darwin.send(sockets[1], &byte, 1, 0)
        let code = errno
        #expect(result == -1)
        #expect(code == ECONNRESET)
        try owner.send("q")
        #expect(try owner.readLine() == "")
    }

    @Test(arguments: [false, true])
    func exactDiskLeaseSurvivesDaemonDeathUntilOwnedShimExits(readOnly: Bool) async {
        await #expect(processExitsWith: .success) { [readOnly] in
            try VMShimDiskLockRuntimeTests().checkExactDiskLeaseSurvivesDaemonDeathUntilOwnedShimExits(readOnly: readOnly)
        }
    }

    private func checkExactDiskLeaseSurvivesDaemonDeathUntilOwnedShimExits(readOnly: Bool) throws {
        let fixture = try DiskLockFixture()
        defer { fixture.remove() }
        let executable = try buildDiskLeaseHelper(in: fixture.directory)
        let owner: DiskLeaseOwner
        let identity = try PersistentStateDirectory.open(fixture.directory).regularFileIdentity(named: "root")
        do {
            let resources = try VMShimAttachmentResolver.resolve(fixture.specification(readOnly: readOnly))
            defer { withExtendedLifetime(resources) {} }
            // Transfer this production open-file description explicitly, solely
            // to model a shim retaining it. Normal exec must NOT inherit it.
            owner = try DiskLeaseOwner(executable: executable, descriptor: resources.retainedHandles[0].fileDescriptor)
        }
        defer { owner.stop() }
        let ready = try owner.readLine().split(separator: " ")
        try #require(ready.count == 5)
        #expect(ready.first == "READY")
        #expect(ready[2] == String(try #require(owner.daemonPID)))
        #expect(ready[3] == String(identity.device))
        #expect(ready[4] == String(identity.inode))
        #expect(link(fixture.url("root").path, fixture.url("alias").path) == 0)
        try FileManager.default.moveItem(at: fixture.url("root"), to: fixture.url("renamed"))
        owner.stopDaemon() // Reaps only our direct child, never an inferred PID.
        try owner.send("p")
        let alive = try owner.readLine().split(separator: " ")
        #expect(alive.first == "ALIVE")
        #expect(alive.dropFirst().first == ready[1]) // Same owned child over its private pipe.
        for name in ["alias", "renamed"] {
            #expect(try probeDiskLease(executable: executable, url: fixture.url(name)) == "DENIED")
            #expect(try probeDiskLease(executable: executable, url: fixture.url(name), shared: true) == (readOnly ? "LOCKED" : "DENIED"))
        }
        try owner.send("q")
        #expect(try owner.readLine() == "") // Kernel closes the disk and pipe on shim exit.
        for name in ["alias", "renamed"] {
            #expect(try probeDiskLease(executable: executable, url: fixture.url(name)) == "LOCKED")
            #expect(try Data(contentsOf: fixture.url(name)) == DiskLockFixture.contents)
        }
    }
}

private struct DiskLockFixture {
    static let contents = Data(repeating: 0x5a, count: 4_096)
    let directory: URL

    init() throws {
        directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        for name in ["root", "volume"] { try Self.contents.write(to: url(name)) }
    }

    func url(_ name: String) -> URL { directory.appending(path: name) }
    func remove() { try? FileManager.default.removeItem(at: directory) }
    func expectUnchanged() throws {
        for name in ["root", "volume"] { #expect(try Data(contentsOf: url(name)) == Self.contents) }
    }

    func specification(root: String = "root", readOnly: Bool = false, volumes: [String] = []) throws -> VMShimProtocol.Specification {
        let parent = try PersistentStateDirectory.open(directory)
        return try .init(
            containerID: "disk-lock", generation: 1, token: "test",
            kernelPath: "/unused-kernel", initialRamdiskPath: "/unused-initramfs",
            rootDiskPath: url(root).path,
            rootDiskIdentity: parent.regularFileIdentity(named: root).shimIdentity,
            rootDiskSize: UInt64(Self.contents.count), rootDiskReadOnly: readOnly,
            volumeDisks: volumes.map {
                try .init(name: $0, path: url($0).path, identity: parent.regularFileIdentity(named: $0).shimIdentity, size: UInt64(Self.contents.count))
            },
            cpus: 1, memoryBytes: 512 * 1_024 * 1_024, macAddress: "02:ce:00:00:00:01",
            socketPath: url("shim.sock").path, logPath: url("shim.log").path
        )
    }
}

private func expectConflict(_ operation: () throws -> Void) {
    do {
        try operation()
        Issue.record("expected VM disk lock conflict")
    } catch let error as EngineError {
        #expect(error.code == .conflict)
    } catch {
        Issue.record("expected EngineError.conflict, got \(error)")
    }
}

private func expectDiskLock(_ url: URL, available: Bool, shared: Bool = false) throws {
    let fd = open(url.path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { throw POSIXError(.EIO) }
    defer { close(fd) }
    let result = flock(fd, (shared ? LOCK_SH : LOCK_EX) | LOCK_NB)
    let code = errno
    #expect((result == 0) == available, "disk \(url.lastPathComponent), errno \(code)")
    if !available { #expect(code == EWOULDBLOCK) }
}

private final class DiskLeaseOwner {
    private(set) var daemonPID: pid_t?
    private let input = Pipe()
    private let output = Pipe()

    init(executable: URL, descriptor: Int32) throws {
        var actions: posix_spawn_file_actions_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw POSIXError(.EIO) }
        defer { posix_spawn_file_actions_destroy(&actions) }
        var attributes: posix_spawnattr_t?
        guard posix_spawnattr_init(&attributes) == 0 else { throw POSIXError(.EIO) }
        defer { posix_spawnattr_destroy(&attributes) }
        // Never inherit another concurrent test's sockets or temporary disk
        // descriptions. Only our explicit dup2 transfers cross this exec.
        guard posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0 else { throw POSIXError(.EIO) }
        let descriptorFlags = fcntl(descriptor, F_GETFD)
        guard descriptorFlags >= 0 else { throw POSIXError(.EIO) }
        for (source, target) in [(descriptor, Int32(198)), (input.fileHandleForReading.fileDescriptor, STDIN_FILENO), (output.fileHandleForWriting.fileDescriptor, STDOUT_FILENO)] {
            guard source != 198, posix_spawn_file_actions_adddup2(&actions, source, target) == 0 else { throw POSIXError(.EIO) }
            guard posix_spawn_file_actions_addclose(&actions, source) == 0 else { throw POSIXError(.EIO) }
        }
        // dup2 clears CLOEXEC. The isolated helper restores the production
        // descriptor's actual flags before its own ordinary exec check.
        let values: [String] = [executable.path, "owner", String(descriptorFlags)]
        let arguments = values.map { strdup($0) } + [nil]
        defer { arguments.forEach { free($0) } }
        var pid: pid_t = 0
        let result = arguments.withUnsafeBufferPointer {
            posix_spawn(&pid, executable.path, &actions, &attributes, $0.baseAddress!, environ)
        }
        guard result == 0 else { throw POSIXError(POSIXErrorCode(rawValue: result) ?? .EIO) }
        daemonPID = pid
        try input.fileHandleForReading.close()
        try output.fileHandleForWriting.close()
    }

    func readLine() throws -> String {
        var line = Data()
        while line.count < 256 {
            var event = pollfd(fd: output.fileHandleForReading.fileDescriptor, events: Int16(POLLIN), revents: 0)
            guard poll(&event, 1, 10_000) > 0 else { throw EngineError(.internalError, "disk lease child timed out") }
            guard let byte = try output.fileHandleForReading.read(upToCount: 1), !byte.isEmpty else { break }
            if byte == Data([10]) { break }
            line.append(byte)
        }
        return String(decoding: line, as: UTF8.self)
    }

    func send(_ command: String) throws { try input.fileHandleForWriting.write(contentsOf: Data(command.utf8)) }
    func stopDaemon() {
        guard let pid = daemonPID else { return }
        kill(pid, SIGKILL)
        while waitpid(pid, nil, 0) < 0 && errno == EINTR {}
        daemonPID = nil
    }
    func stop() {
        stopDaemon()
        try? input.fileHandleForWriting.close() // EOF releases our shim; no PID-based orphan kill.
    }
}

private func probeDiskLease(executable: URL, url: URL, shared: Bool = false) throws -> String {
    let process = Process()
    let output = Pipe()
    process.executableURL = executable
    process.arguments = ["probe", url.path, shared ? "shared" : "exclusive"]
    process.standardOutput = output
    try process.run()
    process.waitUntilExit()
    #expect(process.terminationStatus == 0)
    return String(decoding: try output.fileHandleForReading.readToEnd() ?? Data(), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
}

private func buildDiskLeaseHelper(in directory: URL) throws -> URL {
    let source = directory.appending(path: "disk-lease-helper.c")
    let executable = directory.appending(path: "disk-lease-helper")
    // Only async-signal-safe syscalls between fork and exec. The surrogate
    // inherits the exact resolver-owned description; it never acquires a
    // substitute lock or opens the disk again. No VM or daemon is launched.
    try Data(#"""
    #include <sys/file.h>
    #include <sys/stat.h>
    #include <sys/wait.h>
    #include <errno.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    int main(int argc, char **argv) {
        alarm(30);
        setbuf(stdout, NULL);
        if (argc == 4 && strcmp(argv[1], "probe") == 0) {
            int fd = open(argv[2], O_RDWR | O_NOFOLLOW | O_CLOEXEC);
            if (fd < 0) return 10;
            int mode = strcmp(argv[3], "shared") == 0 ? LOCK_SH : LOCK_EX;
            int result = flock(fd, mode | LOCK_NB);
            if (result != 0 && errno != EWOULDBLOCK) return 11;
            puts(result == 0 ? "LOCKED" : "DENIED");
            close(fd);
            return 0;
        }
        if (argc == 2 && strcmp(argv[1], "exec-check") == 0)
            return fcntl(198, F_GETFD) == -1 && errno == EBADF ? 0 : 12;
        if (argc != 3 || strcmp(argv[1], "owner") != 0) return 13;
        struct stat disk;
        if (fstat(198, &disk) != 0) return 14;
        // The harness exec is isolated from concurrent tests. Test ordinary
        // exec behavior below using the production descriptor's actual flags
        // on its transferred open-file description, not a hard-coded CLOEXEC.
        if (fcntl(198, F_SETFD, atoi(argv[2])) != 0) return 16;
        pid_t shim = fork();
        if (shim < 0) return 17;
        if (shim > 0) {
            close(198);
            close(STDIN_FILENO);
            close(STDOUT_FILENO);
            while (1) pause();
        }
        alarm(30);
        pid_t child = fork();
        if (child < 0) return 18;
        if (child == 0) {
            execl(argv[0], argv[0], "exec-check", (char *)0);
            _exit(19);
        }
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 20;
        printf("READY %d %d %llu %llu\n", getpid(), getppid(),
            (unsigned long long)disk.st_dev, (unsigned long long)disk.st_ino);
        char command;
        while (read(STDIN_FILENO, &command, 1) == 1) {
            if (command == 'q') break;
            if (command == 'p') printf("ALIVE %d\n", getpid());
        }
        // No explicit close/unlock: the kernel releases the lease at exit.
        _exit(0);
    }
    """#.utf8).write(to: source)
    let compiler = Process()
    compiler.executableURL = URL(filePath: "/usr/bin/xcrun")
    compiler.arguments = ["clang", "-Wall", "-Wextra", "-Werror", source.path, "-o", executable.path]
    try compiler.run()
    compiler.waitUntilExit()
    guard compiler.terminationStatus == 0 else { throw EngineError(.internalError, "could not compile disk lease helper") }
    return executable
}
#endif

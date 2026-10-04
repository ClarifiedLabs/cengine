import Darwin
import Foundation
import Testing
@testable import CEngineCore

@Suite struct CanonicalDataStoreLockTests {
    @Test(arguments: [false, true])
    func createsPrivateRootWithoutChangingExistingMetadata(existing: Bool) throws {
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }
        let root = parent.appending(path: "store")
        var before = stat()
        if existing {
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            #expect(chmod(root.path, 0o755) == 0)
            #expect(lstat(root.path, &before) == 0)
        }

        let lock = try CanonicalDataStoreLock(root: root)
        defer { withExtendedLifetime(lock) {} }
        var after = stat()
        #expect(lstat(root.path, &after) == 0)
        #expect(after.st_mode & 0o7777 == (existing ? 0o755 : 0o700))
        if existing {
            #expect(after.st_ino == before.st_ino)
            #expect(after.st_uid == before.st_uid)
            #expect(after.st_gid == before.st_gid)
        }
    }

    // A concurrent Darwin spawn can briefly retain even CLOEXEC descriptions
    // before exec. Check immediate release in a process without unrelated spawns.
    @Test func preservesContentsAndClosesOnExec() async {
        await #expect(processExitsWith: .success) {
            try CanonicalDataStoreLockTests().checkContentsAndCloseOnExec()
        }
    }

    private func checkContentsAndCloseOnExec() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appending(path: CanonicalDataStoreLock.fileName)
        try Data("existing lock evidence".utf8).write(to: file)
        #expect(chmod(file.path, 0o600) == 0)
        do {
            let lock = try CanonicalDataStoreLock(root: root)
            defer { withExtendedLifetime(lock) {} }
            #expect(fcntl(lock.descriptor, F_GETFD) & FD_CLOEXEC != 0)
            #expect(fcntl(lock.directoryDescriptor, F_GETFD) & FD_CLOEXEC != 0)
            #expect(fcntl(lock.pathDescriptor, F_GETFD) & FD_CLOEXEC != 0)
            var info = stat()
            #expect(fstat(lock.pathDescriptor, &info) == 0)
            #expect(info.st_mode & 0o7777 == 0o600)
            #expect(info.st_uid == geteuid())
            #expect(info.st_nlink == 1)
            let evidence = "persistent path lease"
            #expect(evidence.withCString { Darwin.write(lock.pathDescriptor, $0, evidence.utf8.count) } == evidence.utf8.count)
            #expect(throws: EngineError.self) { try CanonicalDataStoreLock(root: root) }
            #expect(try String(contentsOf: file, encoding: .utf8) == "existing lock evidence")
        }
        let restarted = try CanonicalDataStoreLock(root: root)
        defer { withExtendedLifetime(restarted) {} }
        #expect(try String(contentsOf: file, encoding: .utf8) == "existing lock evidence")
        let pathFile = URL(filePath: CanonicalDataStoreLock.leaseNamespacePath(forOwnerUID: geteuid()))
            .appending(path: CanonicalDataStoreLock.pathLeaseName(restarted.root))
        #expect(try String(contentsOf: pathFile, encoding: .utf8) == "persistent path lease")
    }

    @Test func exportsBorrowedHeldDescriptionsAndCleansUpOnThrow() async {
        await #expect(processExitsWith: .success) {
            try CanonicalDataStoreLockTests().checkExportCleanup()
        }
    }

    private func checkExportCleanup() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let lock = try CanonicalDataStoreLock(root: root)
        defer { withExtendedLifetime(lock) {} }
        var exported: [CInt] = []
        #expect(throws: EngineError.self) {
            try lock.withLeaseDescriptors { path, directory, file in
                exported = [path, directory, file]
                for fd in exported {
                    #expect(fcntl(fd, F_GETFD) & FD_CLOEXEC != 0)
                    #expect(flock(fd, LOCK_EX | LOCK_NB) == 0)
                }
                throw EngineError(.conflict, "test body failed")
            }
        }
        for fd in exported { #expect(fcntl(fd, F_GETFD) == -1) }
        #expect(throws: EngineError.self) { try CanonicalDataStoreLock(root: root) }
        try lock.withLeaseDescriptors { _, _, _ in }
    }

    @Test func exportRevalidatesAfterBody() async {
        await #expect(processExitsWith: .success) {
            try CanonicalDataStoreLockTests().checkExportRevalidation()
        }
    }

    private func checkExportRevalidation() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let lock = try CanonicalDataStoreLock(root: root)
        defer { withExtendedLifetime(lock) {} }
        var exported: [CInt] = []
        #expect(throws: (any Error).self) {
            try lock.withLeaseDescriptors { p, r, f in
                exported = [p, r, f]
                try FileManager.default.removeItem(at: root.appending(path: ".daemon.lock"))
            }
        }
        for fd in exported { #expect(fcntl(fd, F_GETFD) == -1) }
        var called = false
        #expect(throws: (any Error).self) {
            try lock.withLeaseDescriptors { _, _, _ in called = true }
        }
        #expect(!called)
    }

    @Test func resolvesSystemAndUserAliasesPhysically() throws {
        // No writes under /etc: Foundation's alias preservation previously made
        // the no-follow directory walk reject /etc with ENOTDIR.
        #expect(try CanonicalDataStoreLock.physicalPath(URL(filePath: "/etc")) == "/private/etc")
        #expect(try CanonicalDataStoreLock.physicalPath(URL(filePath: "/var/tmp")) == "/private/var/tmp")
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }
        let target = parent.appending(path: "target")
        let alias = parent.appending(path: "alias")
        try FileManager.default.createDirectory(at: target, withIntermediateDirectories: false)
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: target)
        #expect(try CanonicalDataStoreLock.physicalPath(alias) == CanonicalDataStoreLock.physicalPath(target))
    }

    @Test func namespaceIsPurelySelectedByOwnerUID() {
        #expect(CanonicalDataStoreLock.leaseNamespacePath(forOwnerUID: 501) == "/private/var/tmp/dev.cengine.store-locks-501")
        #expect(CanonicalDataStoreLock.leaseNamespacePath(forOwnerUID: 0) == "/private/var/tmp/dev.cengine.store-locks-0")
        // Never mutate the shared real namespace to exercise rejection paths.
    }

    @Test(arguments: ["leaf-mode", "ancestor-mode", "leaf-symlink", "ancestor-symlink"])
    func rejectsUnsafeLeaseNamespaces(kind: String) throws {
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }
        let physical = URL(filePath: try CanonicalDataStoreLock.physicalPath(parent))
        let ancestor = physical.appending(path: "ancestor")
        let leaf = ancestor.appending(path: "leases")
        try FileManager.default.createDirectory(at: leaf, withIntermediateDirectories: true)
        #expect(chmod(leaf.path, 0o700) == 0)
        let safe = try CanonicalDataStoreLock.openLeaseNamespace(path: leaf.path)
        #expect(fcntl(safe, F_GETFD) & FD_CLOEXEC != 0)
        close(safe)
        switch kind {
        case "leaf-mode": #expect(chmod(leaf.path, 0o755) == 0)
        case "ancestor-mode": #expect(chmod(ancestor.path, 0o777) == 0)
        default:
            let replaced = kind == "leaf-symlink" ? leaf : ancestor
            let moved = physical.appending(path: "moved")
            try FileManager.default.moveItem(at: replaced, to: moved)
            try FileManager.default.createSymbolicLink(at: replaced, withDestinationURL: moved)
        }
        #expect(throws: (any Error).self) { try CanonicalDataStoreLock.openLeaseNamespace(path: leaf.path) }
    }

    @Test func socketLockRejectsSymlinkAndClosesOnExec() throws {
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }
        let target = parent.appending(path: "socket.lock")
        let alias = parent.appending(path: "alias.lock")
        do {
            let lock = try DaemonSocketLock(url: target)
            defer { withExtendedLifetime(lock) {} }
            #expect(fcntl(lock.descriptor, F_GETFD) & FD_CLOEXEC != 0)
        }
        // The target is unlocked: rejection must be NOFOLLOW, not contention.
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: target)
        #expect(throws: EngineError.self) { try DaemonSocketLock(url: alias) }
    }

    @Test(arguments: ["symlink", "hardlink", "fifo", "directory", "mode"])
    func refusesUnsafeLockFiles(kind: String) throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appending(path: "untouched")
        try Data("do not modify".utf8).write(to: target)
        #expect(chmod(target.path, 0o600) == 0)
        let file = root.appending(path: CanonicalDataStoreLock.fileName)
        switch kind {
        case "symlink": try FileManager.default.createSymbolicLink(at: file, withDestinationURL: target)
        case "hardlink": #expect(link(target.path, file.path) == 0)
        case "fifo": #expect(mkfifo(file.path, 0o600) == 0)
        case "directory": try FileManager.default.createDirectory(at: file, withIntermediateDirectories: false)
        default:
            try Data("unsafe mode".utf8).write(to: file)
            #expect(chmod(file.path, 0o666) == 0)
        }
        #expect(throws: (any Error).self) { try CanonicalDataStoreLock(root: root) }
        #expect(try String(contentsOf: target, encoding: .utf8) == "do not modify")
        var information = stat()
        #expect(lstat(file.path, &information) == 0)
    }

    @Test(arguments: ["symlink", "hardlink", "regular"])
    func replacementCannotAdmitAnotherOwner(kind: String) throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let lock = try CanonicalDataStoreLock(root: root)
        defer { withExtendedLifetime(lock) {} }
        let file = root.appending(path: CanonicalDataStoreLock.fileName)
        let old = root.appending(path: "original-lock")
        try FileManager.default.moveItem(at: file, to: old)
        switch kind {
        case "symlink": try FileManager.default.createSymbolicLink(at: file, withDestinationURL: old)
        case "hardlink": #expect(link(old.path, file.path) == 0)
        default:
            try Data("replacement".utf8).write(to: file)
            #expect(chmod(file.path, 0o600) == 0)
        }
        #expect(throws: EngineError.self) { try lock.validateIdentity() }
        #expect(throws: EngineError.self) { try CanonicalDataStoreLock(root: root) }
        #expect(FileManager.default.fileExists(atPath: old.path))
    }

    @Test func pinnedDirectoryRejectsPathReplacement() throws {
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }
        let root = parent.appending(path: "store")
        let moved = parent.appending(path: "moved")
        let lock = try CanonicalDataStoreLock(root: root)
        defer { withExtendedLifetime(lock) {} }
        try FileManager.default.moveItem(at: root, to: moved)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        #expect(throws: EngineError.self) { try lock.validateIdentity() }
        #expect(throws: EngineError.self) { try CanonicalDataStoreLock(root: root) }
        #expect(throws: EngineError.self) { try CanonicalDataStoreLock(root: moved) }
        #expect(!FileManager.default.fileExists(atPath: root.appending(path: CanonicalDataStoreLock.fileName).path))
    }

    @Test func childProcessAlternateSocketsAliasesSeparateStoresAndRestart() throws {
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }
        let executable = try buildLockOwner(in: parent)
        let root = parent.appending(path: "store")
        let alias = parent.appending(path: "alias")
        let first = try LockOwner(executable: executable, root: root, socket: parent.appending(path: "first.sock"))
        defer { first.stop() }
        #expect(first.response == "READY")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: root)
        let alternate = try LockOwner(executable: executable, root: root, socket: parent.appending(path: "alternate.sock"))
        defer { alternate.stop() }
        #expect(alternate.response == "DENIED")
        let aliased = try LockOwner(executable: executable, root: alias, socket: parent.appending(path: "alias.sock"))
        defer { aliased.stop() }
        #expect(aliased.response == "DENIED")
        let separate = try LockOwner(executable: executable, root: parent.appending(path: "other-store"), socket: parent.appending(path: "separate.sock"))
        defer { separate.stop() }
        #expect(separate.response == "READY")
        let moved = parent.appending(path: "moved")
        let movedAlias = parent.appending(path: "moved-alias")
        try FileManager.default.moveItem(at: root, to: moved)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        try FileManager.default.createSymbolicLink(at: movedAlias, withDestinationURL: moved)
        for (index, deniedRoot) in [root, moved, movedAlias].enumerated() {
            let denied = try LockOwner(executable: executable, root: deniedRoot, socket: parent.appending(path: "denied-\(index).sock"))
            defer { denied.stop() }
            #expect(denied.response == "DENIED")
        }
        first.stop() // SIGKILL tests kernel release, not a Swift destructor.
        let restarted = try LockOwner(executable: executable, root: alias, socket: parent.appending(path: "restart.sock"))
        defer { restarted.stop() }
        #expect(restarted.response == "READY")
        let movedRestart = try LockOwner(executable: executable, root: movedAlias, socket: parent.appending(path: "moved-restart.sock"))
        defer { movedRestart.stop() }
        #expect(movedRestart.response == "READY")
    }

    @Test(arguments: [false, true])
    func execChildCannotKeepSocketOrStoreLockedAfterOwnerDies(inheritSocketControl: Bool) throws {
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }
        let executable = try buildLockOwner(in: parent)
        let root = parent.appending(path: "store")
        let socket = parent.appending(path: "daemon.sock")
        let owner = try LockOwner(
            executable: executable, root: root, socket: socket,
            spawnMode: inheritSocketControl ? "inherit-socket-control" : "spawn"
        )
        defer { owner.stop() }
        let child = try #require(pid_t(owner.response.replacingOccurrences(of: "READY:", with: "")))
        defer { kill(child, SIGKILL) }
        #expect(kill(child, 0) == 0)
        owner.stop()
        #expect(kill(child, 0) == 0)
        let replacement = try LockOwner(executable: executable, root: root, socket: socket)
        defer { replacement.stop() }
        // Negative control recreates the old missing-CLOEXEC bug and proves
        // this spawn really inherits descriptors (unlike Foundation.Process).
        #expect(replacement.response == (inheritSocketControl ? "DENIED" : "READY"))
    }

    private func temporaryDirectory() throws -> URL {
        let result = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: result, withIntermediateDirectories: true)
        return result
    }
}

private final class LockOwner {
    let process = Process()
    let input = Pipe()
    let response: String

    init(executable: URL, root: URL, socket: URL, spawnMode: String? = nil) throws {
        let output = Pipe()
        process.executableURL = executable
        process.arguments = [root.path, socket.path] + (spawnMode.map { [$0] } ?? [])
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        try process.run()
        do {
            var line = Data()
            while line.count < 128 {
                var event = pollfd(fd: output.fileHandleForReading.fileDescriptor, events: Int16(POLLIN), revents: 0)
                guard poll(&event, 1, 15_000) > 0,
                      let byte = try output.fileHandleForReading.read(upToCount: 1), !byte.isEmpty else {
                    throw EngineError(.internalError, "lock test child did not report readiness")
                }
                if byte == Data([10]) { break }
                line.append(byte)
            }
            response = String(decoding: line, as: UTF8.self)
        } catch {
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            process.waitUntilExit()
            throw error
        }
    }

    func stop() {
        if process.isRunning { kill(process.processIdentifier, SIGKILL) }
        process.waitUntilExit()
    }
}

private func buildLockOwner(in directory: URL) throws -> URL {
    let repository = URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let driver = directory.appending(path: "LockOwner.swift")
    let executable = directory.appending(path: "lock-owner")
    try Data("""
    import Darwin
    import Foundation
    @main enum LockOwnerMain {
        static func main() {
            do {
                let socket = try DaemonSocketLock(url: URL(filePath: CommandLine.arguments[2] + ".lock"))
                defer { withExtendedLifetime(socket) {} }
                let lock = try CanonicalDataStoreLock(root: URL(filePath: CommandLine.arguments[1]))
                defer { withExtendedLifetime(lock) {} }
                var response = "READY"
                if CommandLine.arguments.count > 3 {
                    // No CLOEXEC_DEFAULT spawn attribute: only each production
                    // lock's own O_CLOEXEC prevents this exec from retaining it.
                    if CommandLine.arguments[3] == "inherit-socket-control" {
                        guard fcntl(socket.descriptor, F_SETFD, 0) == 0 else { exit(4) }
                    }
                    var child: pid_t = 0
                    let arguments = [strdup("/bin/sleep"), strdup("60"), nil]
                    defer { arguments.forEach { free($0) } }
                    let result = arguments.withUnsafeBufferPointer {
                        posix_spawn(&child, "/bin/sleep", nil, nil, $0.baseAddress!, environ)
                    }
                    guard result == 0 else { exit(3) }
                    response += ":\\(child)"
                }
                FileHandle.standardOutput.write(Data("\\(response)\\n".utf8))
                _ = try FileHandle.standardInput.read(upToCount: 1)
            } catch {
                FileHandle.standardOutput.write(Data("DENIED\\n".utf8))
                exit(1)
            }
        }
    }
    """.utf8).write(to: driver)
    let compiler = Process()
    compiler.executableURL = URL(filePath: "/usr/bin/xcrun")
    compiler.arguments = [
        "swiftc", "-parse-as-library", "-O",
        repository.appending(path: "Sources/CEngineCore/EngineError.swift").path,
        repository.appending(path: "Sources/CEngineCore/CanonicalDataStoreLock.swift").path,
        repository.appending(path: "Sources/CEngineCore/DaemonSocketLock.swift").path,
        driver.path, "-o", executable.path,
    ]
    try compiler.run()
    compiler.waitUntilExit()
    guard compiler.terminationStatus == 0 else {
        throw EngineError(.internalError, "could not compile lock-owner test child")
    }
    return executable
}

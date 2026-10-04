import CEngineCore
import Darwin
import Foundation
import Testing
@testable import StorageBootstrapHelper

@Suite(.serialized) struct StorageBootstrapLifecycleAdoptionLeaseTests {
    // This fixture does not attest a signature. Production must receive the
    // BootstrapProcess from the trusted native router, not this test constructor.
    private func owner(uid: uid_t = geteuid()) -> BootstrapProcess {
        var token = audit_token_t()
        token.val = (uid, uid, getegid(), uid, getgid(), UInt32(getpid()), 1, 1)
        return BootstrapProcess(pid: getpid(), startSeconds: 1, startMicroseconds: 0,
            boot: "test", signingIdentity: "test-not-attested", uniqueID: 1,
            pidVersion: 1, auditToken: withUnsafeBytes(of: token) { Data($0) })
    }
    private func fixture(_ body: (URL, CanonicalDataStoreLock) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let lock = try CanonicalDataStoreLock(root: root)
        defer { withExtendedLifetime(lock) {} }
        try body(lock.root, lock)
    }
    private func identity(_ fd: Int32) throws -> StorageIdentity.RootIdentity {
        try StorageBootstrapBindings(ownerUID: geteuid()).identity(fd, type: S_IFDIR, role: .root)
    }
    private func verify(_ p: Int32, _ r: Int32, _ f: Int32,
                        expected: StorageIdentity.RootIdentity? = nil, uid: uid_t = geteuid()) throws {
        try StorageBootstrapLifecycleAdoptionLease.withObservedLocks(
            owner: owner(uid: uid), expectedRoot: try expected ?? identity(r),
            pathFD: p, rootFD: r, fileFD: f
        ) { observation in
            let snapshot = try observation.validate()
            #expect(snapshot.owner == owner(uid: uid))
            let actual = try identity(r)
            #expect(snapshot.root == actual)
        }
    }
    @Test(arguments: [0, 1, 2, 3])
    func callbackCannotChangeAnyPinnedDescriptorObservation(index: Int) throws {
        try fixture { _, lock in
            try lock.withLeaseDescriptors { p, r, f in
                var changed = false, calls = 0
                #expect(throws: (any Error).self) {
                    try StorageBootstrapLifecycleAdoptionLease.withObservedLocks(owner: owner(), expectedRoot: identity(r),
                        pathFD: p, rootFD: r, fileFD: f, observe: { actual in
                            defer { calls += 1 }
                            return changed && calls % 4 == index
                                ? .init(stableIdentity: actual.stableIdentity, device: actual.device &+ 1) : actual
                        }) { observed in
                            _ = try observed.validate()
                            changed = true
                        }
                }
            }
        }
    }

    @Test func heldExportSucceedsAndClosingDuplicatesPreservesOwner() throws {
        try fixture { root, lock in
            try lock.withLeaseDescriptors { p, r, f in
                try verify(p, r, f)
                for fd in [p, r, f] { #expect(fcntl(fd, F_GETFD) & FD_CLOEXEC != 0) }
            }
            #expect(throws: (any Error).self) { try CanonicalDataStoreLock(root: root) }
            // Check each lock independently, not just the first path lease.
            try lock.withLeaseDescriptors { p, r, f in
                for fd in [p, r, f] {
                    var bytes = [CChar](repeating: 0, count: Int(MAXPATHLEN))
                    #expect(fcntl(fd, F_GETPATH, &bytes) == 0)
                    let fresh = open(String(cString: bytes), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
                    #expect(fresh >= 0)
                    defer { close(fresh) }
                    #expect(flock(fresh, LOCK_EX | LOCK_NB) == -1)
                    #expect(errno == EWOULDBLOCK)
                }
            }
        }
    }
    @Test(arguments: [0, 1, 2])
    func independentlyOpenedDescriptionCannotBorrowForeignLock(index: Int) throws {
        try fixture { _, lock in
            try lock.withLeaseDescriptors { p, r, f in
                var fds = [p, r, f]
                var bytes = [CChar](repeating: 0, count: Int(MAXPATHLEN))
                #expect(fcntl(fds[index], F_GETPATH, &bytes) == 0)
                let foreign = open(String(cString: bytes), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
                #expect(foreign >= 0)
                defer { close(foreign) }
                fds[index] = foreign
                #expect(throws: (any Error).self) { try verify(fds[0], fds[1], fds[2]) }
                try verify(p, r, f)
            }
        }
    }
    @Test(arguments: ["copy", "symlink", "replacement", "moved-root", "wrong-root", "wrong-owner", "mode", "hardlink", "invalid-fd"])
    func rejectsNoncanonicalEvidence(kind: String) throws {
        try fixture { root, lock in
            // Mutations deliberately make export's post-check fail too.
            var verifiedRejection = false
            do {
                try lock.withLeaseDescriptors { p, r, f in
                    var suppliedFile = f
                    var extra: Int32 = -1
                    defer { if extra >= 0 { close(extra) } }
                    let entry = root.appending(path: ".daemon.lock")
                    let copy = root.appending(path: "copy")
                    if ["copy", "symlink", "replacement"].contains(kind) {
                        try Data().write(to: copy); #expect(chmod(copy.path, 0o600) == 0)
                    }
                    switch kind {
                    case "copy": extra = open(copy.path, O_RDWR | O_CLOEXEC); suppliedFile = extra
                    case "symlink":
                        try FileManager.default.removeItem(at: entry)
                        try FileManager.default.createSymbolicLink(at: entry, withDestinationURL: copy)
                    case "replacement":
                        try FileManager.default.removeItem(at: entry)
                        try FileManager.default.moveItem(at: copy, to: entry)
                        extra = open(entry.path, O_RDWR | O_CLOEXEC); suppliedFile = extra
                    case "moved-root":
                        let moved = root.appendingPathExtension("moved")
                        try FileManager.default.moveItem(at: root, to: moved)
                        defer { try? FileManager.default.moveItem(at: moved, to: root) }
                        #expect(throws: (any Error).self) { try verify(p, r, f) }
                        verifiedRejection = true; return
                    case "mode": #expect(chmod(entry.path, 0o644) == 0)
                    case "hardlink": #expect(link(entry.path, copy.path) == 0)
                    case "invalid-fd": suppliedFile = -1
                    default: break
                    }
                    let actual = try identity(r)
                    let expected = try StorageIdentity.RootIdentity(volumeUUID: actual.volumeUUID,
                        inode: actual.inode + (kind == "wrong-root" ? 1 : 0))
                    #expect(throws: (any Error).self) {
                        try verify(p, r, suppliedFile, expected: expected,
                                   uid: kind == "wrong-owner" ? geteuid() + 1 : geteuid())
                    }
                    verifiedRejection = true
                }
            } catch { #expect(verifiedRejection) }
            #expect(verifiedRejection)
        }
    }
    @Test func unlockedCanonicalEntriesAreDeniedWithoutAcquiring() async {
        await #expect(processExitsWith: .success) {
            try StorageBootstrapLifecycleAdoptionLeaseTests().checkUnlocked()
        }
    }
    private func checkUnlocked() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        var paths: [String] = []
        do {
            let lock = try CanonicalDataStoreLock(root: root)
            try lock.withLeaseDescriptors { p, r, f in
                for fd in [p, r, f] {
                    var bytes = [CChar](repeating: 0, count: Int(MAXPATHLEN))
                    #expect(fcntl(fd, F_GETPATH, &bytes) == 0)
                    paths.append(String(cString: bytes))
                }
            }
        }
        let fds = paths.map { open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW) }
        defer { fds.forEach { close($0) } }
        #expect(fds.allSatisfy { $0 >= 0 })
        #expect(throws: (any Error).self) { try verify(fds[0], fds[1], fds[2]) }
        for path in paths {
            let independent = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
            #expect(independent >= 0)
            defer { close(independent) }
            #expect(flock(independent, LOCK_EX | LOCK_NB) == 0)
        }
    }
    @Test func verifierClosesAllDuplicatesOnSuccessAndBodyFailure() async {
        await #expect(processExitsWith: .success) {
            try StorageBootstrapLifecycleAdoptionLeaseTests().checkCleanup()
        }
    }
    private func checkCleanup() throws {
        try fixture { _, lock in
            try lock.withLeaseDescriptors { p, r, f in
                let before = openDescriptors()
                var escaped: ObservedCanonicalStoreLocks?
                for fail in [false, true] {
                    do {
                        try StorageBootstrapLifecycleAdoptionLease.withObservedLocks(
                            owner: owner(), expectedRoot: identity(r), pathFD: p, rootFD: r, fileFD: f
                        ) { observation in
                            _ = try observation.validate()
                            escaped = observation
                            if fail { throw BootstrapFailure(.blocked) }
                        }
                    } catch { #expect(fail) }
                    let expired = try #require(escaped)
                    // The only owner/root accessor validates; neither is readable
                    // on an expired observation, even when the body threw.
                    #expect(throws: (any Error).self) { _ = try expired.validate().owner }
                    #expect(throws: (any Error).self) { _ = try expired.validate().root }
                    #expect(openDescriptors() == before)
                    #expect(throws: (any Error).self) { try verify(p, r, -1) }
                    #expect(openDescriptors() == before)
                    try verify(p, r, f)
                }
            }
        }
    }
    @Test(arguments: [0, 1, 2])
    func callbackSourceUnlockAndContenderRejectPostflight(index: Int) throws {
        try fixture { _, lock in
            try lock.withLeaseDescriptors { p, r, f in
                let source = [p, r, f][index]
                var bytes = [CChar](repeating: 0, count: Int(MAXPATHLEN))
                #expect(fcntl(source, F_GETPATH, &bytes) == 0)
                let contender = open(String(cString: bytes), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
                #expect(contender >= 0)
                defer { close(contender) }
                var called = false
                var returned = false
                #expect(throws: (any Error).self) {
                    try StorageBootstrapLifecycleAdoptionLease.withObservedLocks(
                        owner: owner(), expectedRoot: identity(r), pathFD: p, rootFD: r, fileFD: f
                    ) { observation in
                        _ = try observation.validate()
                        called = true
                        // A source duplicate really can revoke the observed lock.
                        #expect(flock(source, LOCK_UN) == 0)
                        #expect(flock(contender, LOCK_EX | LOCK_NB) == 0)
                    }
                    returned = true
                }
                #expect(called && !returned)
                // Postflight neither stole the contender's lock nor rolled back.
                #expect(flock(source, LOCK_EX | LOCK_NB) == -1)
                #expect(errno == EWOULDBLOCK)
            }
        }
    }

    @Test func callbackRootReplacementRejectsWithoutSelectingNewTargetOrRollback() throws {
        try fixture { root, lock in
            try lock.withLeaseDescriptors { p, r, f in
                let original = try identity(r)
                let moved = root.appendingPathExtension("moved")
                var movedRoot = false
                defer {
                    if movedRoot {
                        try? FileManager.default.removeItem(at: root)
                        try? FileManager.default.moveItem(at: moved, to: root)
                    }
                }
                var called = false
                #expect(throws: (any Error).self) {
                    try StorageBootstrapLifecycleAdoptionLease.withObservedLocks(
                        owner: owner(), expectedRoot: original, pathFD: p, rootFD: r, fileFD: f
                    ) { observation in
                        #expect(try observation.validate().root == original)
                        try FileManager.default.moveItem(at: root, to: moved)
                        movedRoot = true
                        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
                        // Deliberate side effect on the pinned target survives failure.
                        let marker = openat(r, "side-effect", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0o600)
                        #expect(marker >= 0)
                        if marker >= 0 { close(marker) }
                        called = true
                    }
                }
                #expect(called)
                #expect(try identity(r) == original)
                #expect(FileManager.default.fileExists(atPath: moved.appending(path: "side-effect").path))
                #expect(!FileManager.default.fileExists(atPath: root.appending(path: "side-effect").path))
                #expect(throws: (any Error).self) { try CanonicalDataStoreLock(root: root) }
                #expect(!FileManager.default.fileExists(atPath: root.appending(path: ".daemon.lock").path))
            }
        }
    }

    @Test func rejectsACLOnFixtureLockFile() throws {
        try fixture { root, lock in
            try lock.withLeaseDescriptors { p, r, f in
                let chmod = Process()
                chmod.executableURL = URL(filePath: "/bin/chmod")
                chmod.arguments = ["+a", "everyone allow read", root.appending(path: ".daemon.lock").path]
                try chmod.run(); chmod.waitUntilExit()
                #expect(chmod.terminationStatus == 0)
                // Only the unique fixture file is modified, never the shared namespace.
                #expect(throws: (any Error).self) { try verify(p, r, f) }
            }
        }
    }

    @Test(arguments: [mode_t(0o2770), mode_t(0o2750)])
    func helperRetainsStricterStorageRootModePolicy(mode: mode_t) throws {
        try fixture { root, lock in
            try lock.withLeaseDescriptors { p, r, f in
                let expected = try identity(r)
                #expect(chmod(root.path, mode) == 0)
                defer { _ = chmod(root.path, 0o700) }
                #expect(throws: (any Error).self) { try verify(p, r, f, expected: expected) }
            }
        }
    }

    private func openDescriptors() -> Set<Int32> {
        Set((0..<Int32(getdtablesize())).filter { fcntl($0, F_GETFD) >= 0 })
    }
}

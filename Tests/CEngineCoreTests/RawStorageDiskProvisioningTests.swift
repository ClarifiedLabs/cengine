#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Synchronization
import Testing
@testable import CEngineRuntime

@Suite struct RawStorageDiskProvisioningTests {
    @Test func createsExactSizedDiskAndReusesItsIdentity() throws {
        let fixture = try StorageDiskFixture()
        defer { fixture.remove() }
        let identity = try fixture.prepare()
        #expect(identity == (try fixture.directory.regularFileIdentity(
            named: "volumes.ext4", expectedSize: StorageDiskFixture.size
        )))
        #expect(identity.volumeUUID != nil)
        #expect(try Data(contentsOf: fixture.disk) == Data(repeating: 0, count: Int(StorageDiskFixture.size)))
        #expect(try fixture.prepare() == identity)
        guard case .journal(let record) = try RawDiskInitialization.inspectExisting(
            in: fixture.directory, named: "volumes.ext4", expectedSize: StorageDiskFixture.size
        ) else { Issue.record("new storage disk has no CREATED journal"); return }
        #expect(record.state == .created)
        var metadata = stat()
        try #require(lstat(fixture.disk.path, &metadata) == 0)
        #expect(metadata.st_mode & 0o777 == 0o600)
    }

    @Test func existingDiskRetainsBytesInodeSizeAndPermissions() throws {
        let fixture = try StorageDiskFixture()
        defer { fixture.remove() }
        try StorageDiskFixture.contents.write(to: fixture.disk)
        try #require(chmod(fixture.disk.path, 0o640) == 0)
        let identity = try fixture.directory.regularFileIdentity(named: "volumes.ext4")
        #expect(try fixture.prepare() == identity)
        try fixture.expectPreserved(identity)
        var metadata = stat()
        try #require(lstat(fixture.disk.path, &metadata) == 0)
        #expect(metadata.st_mode & 0o777 == 0o640)
    }

    @Test(arguments: [0, 17, 8192])
    func wrongSizedExistingDiskIsRejectedWithoutMutation(size: Int) throws {
        let fixture = try StorageDiskFixture()
        defer { fixture.remove() }
        let bytes = Data(repeating: 0xA5, count: size)
        try bytes.write(to: fixture.disk)
        let identity = try fixture.directory.regularFileIdentity(named: "volumes.ext4")
        #expect(throws: (any Error).self) { try fixture.prepare() }
        #expect(try fixture.directory.regularFileIdentity(
            named: "volumes.ext4", expectedSize: UInt64(size)
        ) == identity)
        #expect(try Data(contentsOf: fixture.disk) == bytes)
    }

    @Test(arguments: ["directory", "fifo", "symlink", "dangling-symlink"])
    func unsafeExistingEntryIsRejectedWithoutFollowingIt(kind: String) throws {
        let fixture = try StorageDiskFixture()
        defer { fixture.remove() }
        try fixture.installUnsafeEntry(kind)
        let before = try #require(try fixture.directory.entryMetadata(named: "volumes.ext4"))
        #expect(throws: (any Error).self) { try fixture.prepare() }
        // The provisioning helper deliberately retains the primitive's policy.
        #expect(throws: (any Error).self) {
            try fixture.directory.regularFileIdentity(named: "volumes.ext4", expectedSize: StorageDiskFixture.size)
        }
        let after = try #require(try fixture.directory.entryMetadata(named: "volumes.ext4"))
        #expect(after.identity == before.identity)
        #expect(after.type == before.type)
        #expect(try Data(contentsOf: fixture.root.appending(path: "target")) == StorageDiskFixture.contents)
        #expect(!FileManager.default.fileExists(atPath: fixture.root.appending(path: "absent").path))
    }

    @Test func hardlinkedRegularDiskIsRejectedAndNeverModified() throws {
        let fixture = try StorageDiskFixture()
        defer { fixture.remove() }
        let alias = fixture.root.appending(path: "alias")
        try StorageDiskFixture.contents.write(to: alias)
        try #require(link(alias.path, fixture.disk.path) == 0)
        let identity = try fixture.directory.regularFileIdentity(
            named: "volumes.ext4", expectedSize: StorageDiskFixture.size
        )
        #expect(throws: (any Error).self) { try fixture.prepare() }
        try fixture.expectPreserved(identity)
        #expect(try Data(contentsOf: alias) == StorageDiskFixture.contents)
        var metadata = stat()
        try #require(lstat(alias.path, &metadata) == 0)
        #expect(metadata.st_nlink == 2)
        #expect(UInt64(metadata.st_ino) == identity.inode)
    }

    @Test func concurrentMissingObserversAllAdoptCompletedWinnerWithoutOverwrite() async throws {
        let observation = try await peerFixtureOnThread { try Self.checkConcurrentMissingObservers() }
        #expect(observation.identities.count == 4)
        #expect(observation.identities.allSatisfy { $0 == observation.winner })
        #expect(observation.preservedIdentity == observation.winner)
        #expect(observation.contents == StorageDiskFixture.contents)
    }

    private struct ConcurrentMissingObserversObservation: Sendable {
        let identities: [PersistentFileIdentity]
        let winner: PersistentFileIdentity
        let preservedIdentity: PersistentFileIdentity
        let contents: Data
    }

    private static func checkConcurrentMissingObservers() throws -> ConcurrentMissingObserversObservation {
        let fixture = try StorageDiskFixture()
        defer { fixture.remove() }
        let observed = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let group = DispatchGroup()
        let results = Mutex<[Result<PersistentFileIdentity, any Error>]>([])
        let directory = fixture.directory
        for _ in 0..<4 {
            group.enter()
            Thread.detachNewThread {
                defer { group.leave() }
                let result = Result {
                    try RawStorageDiskProvisioning.prepare(in: directory, size: StorageDiskFixture.size) {
                        observed.signal()
                        guard release.wait(timeout: .now() + 10) == .success else {
                            throw EngineError(.internalError, "test creator was not released")
                        }
                    }
                }
                results.withLock { $0.append(result) }
            }
        }
        defer {
            for _ in 0..<4 { release.signal() }
            precondition(group.wait(timeout: .now() + 15) == .success, "disk workers did not join before fixture cleanup")
        }
        for _ in 0..<4 {
            guard observed.wait(timeout: .now() + 10) == .success else {
                throw PeerFixtureFailure.prerequisite("disk contender did not observe ENOENT")
            }
        }
        // Every contender saw ENOENT. Complete the winner before releasing their
        // O_EXCL attempts, deterministically covering EEXIST rather than relying
        // on scheduler timing or accepting a partially sized disk.
        let winner = try fixture.prepare()
        let opened = try directory.openRegularFile(
            named: "volumes.ext4", expectedIdentity: winner, access: .writeOnly
        )
        try opened.handle.write(contentsOf: StorageDiskFixture.contents)
        try opened.handle.close()
        for _ in 0..<4 { release.signal() }
        guard group.wait(timeout: .now() + 15) == .success else {
            throw PeerFixtureFailure.prerequisite("disk contenders did not finish")
        }
        let identities = try results.withLock { try $0.map { try $0.get() } }
        return try .init(identities: identities, winner: winner,
            preservedIdentity: directory.regularFileIdentity(named: "volumes.ext4", expectedSize: StorageDiskFixture.size),
            contents: Data(contentsOf: fixture.disk))
    }

    @Test(arguments: ["wrong-size", "directory", "fifo", "symlink", "dangling-symlink"])
    func invalidRacingWinnerIsRejectedWithoutMutation(kind: String) throws {
        let fixture = try StorageDiskFixture()
        defer { fixture.remove() }
        var winner: PersistentFileIdentity?
        #expect(throws: (any Error).self) {
            try RawStorageDiskProvisioning.prepare(in: fixture.directory, size: StorageDiskFixture.size) {
                if kind == "wrong-size" {
                    // Also models a competing creator visible before ftruncate.
                    try Data().write(to: fixture.disk)
                } else {
                    try fixture.installUnsafeEntry(kind)
                }
                winner = try fixture.directory.entryMetadata(named: "volumes.ext4")?.identity
            }
        }
        #expect(winner != nil)
        #expect(try fixture.directory.entryMetadata(named: "volumes.ext4")?.identity == winner)
        if kind == "wrong-size" {
            #expect(try Data(contentsOf: fixture.disk).isEmpty)
        } else {
            #expect(try Data(contentsOf: fixture.root.appending(path: "target")) == StorageDiskFixture.contents)
        }
    }

    @Test func partialCreationRemainsQuarantinedAcrossPreparationRetries() throws {
        enum Injected: Error { case failure }
        let fixture = try StorageDiskFixture()
        defer { fixture.remove() }
        #expect(throws: Injected.self) {
            try RawDiskInitialization.createNewDisk(
                in: fixture.directory, named: "volumes.ext4", size: StorageDiskFixture.size,
                hook: { boundary, _ in if boundary == .diskSynchronized { throw Injected.failure } }
            )
        }
        let identity = try fixture.directory.regularFileIdentity(named: "volumes.ext4")
        let names = try fixture.directory.entryNames()
        for _ in 0..<2 {
            #expect(throws: (any Error).self) { try fixture.prepare() }
            #expect(try fixture.directory.regularFileIdentity(named: "volumes.ext4") == identity)
            #expect(Set(try fixture.directory.entryNames()) == Set(names))
        }
    }

    @Test func ACLParentIsRejectedWithoutRepair() throws {
        let fixture = try StorageDiskFixture()
        defer { fixture.remove() }
        let command = Process()
        command.executableURL = URL(filePath: "/bin/chmod")
        command.arguments = ["+a", "everyone allow read,write,delete", fixture.directory.url.path]
        try command.run()
        command.waitUntilExit()
        try #require(command.terminationStatus == 0)
        #expect(throws: (any Error).self) { try fixture.prepare() }
        #expect(try fixture.directory.entryNames().isEmpty)
        #expect(throws: (any Error).self) {
            try RawDiskJournalDirectory.requireNoACL(fixture.directory.descriptor)
        }
    }

    @Test func legacyRootRemainsDisposableAfterMountOnlyInspection() throws {
        let fixture = try StorageDiskFixture()
        defer { fixture.remove() }
        try RawDiskJournalDirectory.prepare(fixture.directory)
        let identity = try fixture.directory.createSparseRegularFile(
            named: "root.ext4", size: StorageDiskFixture.size
        )
        #expect(try RawDiskInitialization.inspectExisting(
            in: fixture.directory, named: "root.ext4", expectedSize: StorageDiskFixture.size
        ) == .mountOnly)
        #expect(try fixture.directory.entryMetadata(named: ".raw-init-root.ext4.lock") != nil)
        try RawDiskJournalDirectory.requireSafeAutomaticRootDisposal(fixture.directory)
        #expect(try fixture.directory.regularFileIdentity(named: "root.ext4") == identity)

        // Only the exact lock name is exempt: malformed artifacts remain evidence.
        _ = try fixture.directory.createSparseRegularFile(named: ".raw-init-root.ext4.lock.bak", size: 0)
        #expect(throws: BackendResourceRollbackIncompleteError.self) {
            try RawDiskJournalDirectory.requireSafeAutomaticRootDisposal(fixture.directory)
        }
        #expect(try fixture.directory.regularFileIdentity(named: "root.ext4") == identity)
        #expect(try fixture.directory.entryMetadata(named: ".raw-init-root.ext4.lock.bak") != nil)
    }

    @Test func unfinishedRootCannotBeAutomaticallyDiscardedOrRecreated() throws {
        let fixture = try StorageDiskFixture()
        defer { fixture.remove() }
        let artifacts = try RawContainerPreparationArtifacts.create(
            in: fixture.directory, rootDiskSize: StorageDiskFixture.size
        )
        #expect(throws: BackendResourceRollbackIncompleteError.self) {
            try RawDiskJournalDirectory.requireSafeAutomaticRootDisposal(fixture.directory)
        }
        #expect(throws: BackendResourceRollbackIncompleteError.self) {
            try RawFreshContainerStateCoordinator.recreateUnclaimed(
                in: PersistentStateDirectory.open(fixture.root), containerID: "infrastructure",
                existing: fixture.directory
            )
        }
        #expect(try fixture.directory.regularFileIdentity(named: "root.ext4") == artifacts.rootDiskIdentity)
        #expect(throws: POSIXError.self) {
            try RawContainerPreparationArtifacts.create(in: fixture.directory, rootDiskSize: StorageDiskFixture.size)
        }
        #expect(try fixture.directory.regularFileIdentity(named: "root.ext4") == artifacts.rootDiskIdentity)
    }

    @Test(arguments: [0o700, 0o750, 0o755, 0o770, 0o777])
    func parentPermissionsAreSafelyTightenedOrRejected(mode: Int) throws {
        let fixture = try StorageDiskFixture()
        defer { fixture.remove() }
        try #require(fchmod(fixture.directory.descriptor, mode_t(mode)) == 0)
        if mode & 0o022 == 0 {
            _ = try fixture.prepare()
        } else {
            #expect(throws: (any Error).self) { try fixture.prepare() }
            #expect(try fixture.directory.entryNames().isEmpty)
        }
        var metadata = stat()
        try #require(fstat(fixture.directory.descriptor, &metadata) == 0)
        #expect(metadata.st_mode & 0o777 == mode_t(mode & 0o022 == 0 ? 0o700 : mode))
    }

    @Test(arguments: [false, true])
    func racedParentReplacementIsRejectedAndReplacementDiskIsUntouched(symlink: Bool) throws {
        let fixture = try StorageDiskFixture()
        defer { fixture.remove() }
        let displaced = fixture.root.appending(path: "displaced")
        let replacement = try PersistentStateDirectory.open(fixture.root).createDirectory(named: "replacement")
        let replacementDisk = replacement.url.appending(path: "volumes.ext4")
        try StorageDiskFixture.contents.write(to: replacementDisk)
        let replacementIdentity = try replacement.regularFileIdentity(named: "volumes.ext4")
        #expect(throws: (any Error).self) {
            try RawStorageDiskProvisioning.prepare(in: fixture.directory, size: StorageDiskFixture.size) {
                try FileManager.default.moveItem(at: fixture.directory.url, to: displaced)
                if symlink {
                    try #require(Darwin.symlink(replacement.url.path, fixture.directory.url.path) == 0)
                } else {
                    try FileManager.default.moveItem(at: replacement.url, to: fixture.directory.url)
                }
            }
        }
        #expect(!fixture.directory.pathStillNamesThisDirectory())
        #expect(try replacement.regularFileIdentity(named: "volumes.ext4", expectedSize: StorageDiskFixture.size) == replacementIdentity)
        #expect(try replacement.readRegularFile(named: "volumes.ext4") == StorageDiskFixture.contents)
        // Parent identity is checked again before the creator opens a disk.
        #expect(try fixture.directory.entryMetadata(named: "volumes.ext4") == nil)
        #expect(throws: (any Error).self) { try fixture.prepare() }
    }
}

private struct StorageDiskFixture {
    static let size: UInt64 = 4096
    static let contents = Data((0..<Int(size)).map { UInt8($0 % 251) })
    let root: URL
    let directory: PersistentStateDirectory
    var disk: URL { directory.url.appending(path: "volumes.ext4") }

    init() throws {
        root = FileManager.default.temporaryDirectory.appending(path: "cengine-storage-provisioning-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        directory = try PersistentStateDirectory.open(root).createDirectory(named: "infrastructure")
    }

    func prepare() throws -> PersistentFileIdentity {
        try RawStorageDiskProvisioning.prepare(in: directory, size: Self.size)
    }

    func expectPreserved(_ identity: PersistentFileIdentity) throws {
        #expect(try directory.regularFileIdentity(named: "volumes.ext4", expectedSize: Self.size) == identity)
        #expect(try Data(contentsOf: disk) == Self.contents)
    }

    func installUnsafeEntry(_ kind: String) throws {
        let target = root.appending(path: "target")
        try Self.contents.write(to: target)
        switch kind {
        case "directory":
            _ = try directory.createDirectory(named: "volumes.ext4")
        case "fifo":
            try #require(mkfifo(disk.path, 0o600) == 0)
        case "symlink":
            try #require(symlink(target.path, disk.path) == 0)
        case "dangling-symlink":
            try #require(symlink(root.appending(path: "absent").path, disk.path) == 0)
        default:
            Issue.record("unexpected fixture kind \(kind)")
        }
    }

    func remove() { try? FileManager.default.removeItem(at: root) }
}
#endif

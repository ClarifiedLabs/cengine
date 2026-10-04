#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

@Suite struct ManagedLifecycleRetainedRootTests {
    private func temporaryRoot() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appending(path: "lifecycle-retained-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        return url
    }

    @Test @MainActor func preflightAndNamespacePreparationKeepTheLockedDirectory() throws {
        let url = try temporaryRoot()
        defer { try? FileManager.default.removeItem(at: url) }
        let lock = try CanonicalDataStoreLock(root: url)
        let root = try ManagedLifecycleStartupRoot(storeLock: lock)
        let descriptor = try lock.duplicateRetainedDirectory()
        defer { Darwin.close(descriptor) }
        #expect(root.directory.identity == (try PersistentFileIdentity.capture(descriptor: descriptor)))
        try ManagedLifecycleStartup.preflight(root: root.directory)
        for name in ["containers", "deleted-containers", "volumes", "infrastructure"] {
            let child = try root.openOrCreateDirectory(named: name)
            #expect(try root.directory.entryMetadata(named: name)?.identity == child.identity)
        }
        let infrastructure = try root.directory.openDirectory(named: "infrastructure")
        let namespace = try root.networkNamespace(in: infrastructure)
        let before = try StoragePreflightSnapshot(url)
        #expect(try root.networkNamespace(in: infrastructure) == namespace)
        #expect(try ManagedStorageLifecycleOwner.classify(root: root.directory) == .fresh)
        #expect(try StoragePreflightSnapshot(url) == before)
    }

    @Test(arguments: [0o700, 0o705, 0o750, 0o755]) @MainActor
    func startupTightensOwnedRootWithoutChangingContents(mode: Int) throws {
        let url = try temporaryRoot()
        defer { try? FileManager.default.removeItem(at: url) }
        let lock = try CanonicalDataStoreLock(root: url)
        let directory = try PersistentStateDirectory.retaining(lock)
        let infrastructure = try directory.createDirectory(named: "infrastructure")
        let childBefore = try StoragePreflightSnapshot(infrastructure.url)
        let assets = try directory.createDirectory(named: "assets")
        try assets.writeExclusiveRegularFile(named: "kernel", data: Data("preserve assets".utf8))
        #expect(fchmod(directory.descriptor, mode_t(mode)) == 0)
        let contents = try StoragePreflightSnapshot(assets.url)
        let root = try ManagedLifecycleStartupRoot.prepareForStartup(storeLock: lock)
        var information = stat()
        #expect(fstat(root.directory.descriptor, &information) == 0)
        #expect(information.st_mode & 0o7777 == 0o700)
        #expect(root.directory.identity == directory.identity)
        #expect(try StoragePreflightSnapshot(assets.url) == contents)
        #expect(try StoragePreflightSnapshot(infrastructure.url) == childBefore)
        #expect(try directory.entryNames() == [".daemon.lock", "assets", "infrastructure"])
        try root.validate()
        let repaired = try StoragePreflightSnapshot(url)
        _ = try ManagedLifecycleStartupRoot.prepareForStartup(storeLock: lock)
        #expect(try StoragePreflightSnapshot(url) == repaired)
    }

    @Test(arguments: [0o777, 0o775, 0o757, 0o1755, 0o2755, 0o555]) @MainActor
    func startupDoesNotBroadenOrRepairUnsafeModes(mode: Int) throws {
        let url = try temporaryRoot()
        defer { try? FileManager.default.removeItem(at: url) }
        let lock = try CanonicalDataStoreLock(root: url)
        let directory = try PersistentStateDirectory.retaining(lock)
        #expect(fchmod(directory.descriptor, mode_t(mode)) == 0)
        defer { _ = fchmod(directory.descriptor, 0o700) }
        let before = try StoragePreflightSnapshot(url)
        #expect(throws: EngineError.self) { _ = try ManagedLifecycleStartupRoot.prepareForStartup(storeLock: lock) }
        #expect(try StoragePreflightSnapshot(url) == before)
    }

    @Test(arguments: ["acl", "old-store", "unsafe-child"]) @MainActor
    func startupRefusesAmbiguousRootWithoutPermissionRepair(condition: String) throws {
        let url = try temporaryRoot()
        defer { try? FileManager.default.removeItem(at: url) }
        let lock = try CanonicalDataStoreLock(root: url)
        let directory = try PersistentStateDirectory.retaining(lock)
        #expect(fchmod(directory.descriptor, 0o755) == 0)
        if condition == "acl" { try addACL(to: url) }
        if condition == "old-store" {
            try directory.writeExclusiveRegularFile(named: "shared-storage-mode.json", data: Data("old".utf8))
        }
        if condition == "unsafe-child" {
            let child = try directory.createDirectory(named: "infrastructure")
            #expect(fchmod(child.descriptor, 0o755) == 0)
        }
        let before = try StoragePreflightSnapshot(url), acl = try aclText(directory)
        #expect(throws: (any Error).self) { _ = try ManagedLifecycleStartupRoot.prepareForStartup(storeLock: lock) }
        #expect(try StoragePreflightSnapshot(url) == before)
        #expect(try aclText(directory) == acl)
    }

    @Test(arguments: [false, true]) @MainActor
    func startupNeverRepairsAReplacedRoot(symlink: Bool) throws {
        let url = try temporaryRoot(), moved = url.appendingPathExtension("held")
        defer { try? FileManager.default.removeItem(at: url); try? FileManager.default.removeItem(at: moved) }
        let lock = try CanonicalDataStoreLock(root: url)
        let directory = try PersistentStateDirectory.retaining(lock)
        #expect(fchmod(directory.descriptor, 0o755) == 0)
        try FileManager.default.moveItem(at: url, to: moved)
        if symlink { try FileManager.default.createSymbolicLink(at: url, withDestinationURL: moved) }
        else { try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false) }
        let before = try StoragePreflightSnapshot(url), held = try StoragePreflightSnapshot(moved)
        #expect(throws: (any Error).self) { _ = try ManagedLifecycleStartupRoot.prepareForStartup(storeLock: lock) }
        #expect(try StoragePreflightSnapshot(url) == before)
        #expect(try StoragePreflightSnapshot(moved) == held)
    }

    private func addACL(to url: URL) throws {
        let process = Process()
        process.executableURL = URL(filePath: "/bin/chmod")
        process.arguments = ["+a", "everyone allow readattr", url.path]
        try process.run()
        process.waitUntilExit()
        #expect(process.terminationStatus == 0)
    }

    private func aclText(_ directory: PersistentStateDirectory) throws -> String {
        guard let acl = acl_get_fd_np(directory.descriptor, ACL_TYPE_EXTENDED) else {
            if errno == ENOENT { return "" }
            throw POSIXError(.init(rawValue: errno) ?? .EIO)
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        let text = try #require(acl_to_text(acl, nil))
        defer { acl_free(UnsafeMutableRawPointer(text)) }
        return String(cString: text)
    }

    @Test(arguments: ["0777", "0755", "acl"]) @MainActor
    func unsafeExistingRootRefusesBeforeStartupWritesWithoutRepair(condition: String) throws {
        let url = try temporaryRoot()
        defer { try? FileManager.default.removeItem(at: url) }
        let lock = try CanonicalDataStoreLock(root: url)
        let root = try ManagedLifecycleStartupRoot(storeLock: lock)
        try root.directory.writeExclusiveRegularFile(named: "evidence", data: Data("preserve every byte".utf8))
        if condition == "acl" { try addACL(to: url) }
        else { #expect(Darwin.fchmod(root.directory.descriptor, condition == "0777" ? 0o777 : 0o755) == 0) }
        let before = try StoragePreflightSnapshot(url), acl = try aclText(root.directory)
        #expect(throws: (any Error).self) { _ = try ManagedLifecycleStartupRoot(storeLock: lock) }
        #expect(throws: (any Error).self) { try ManagedLifecycleStartup.preflight(root: root.directory) }
        #expect(throws: (any Error).self) { _ = try ManagedLifecycleStartup.acquireRuntimeNamespace(root: root) }
        #expect(try StoragePreflightSnapshot(url) == before)
        #expect(try aclText(root.directory) == acl)
    }

    @Test(arguments: ["infrastructure", "volumes", "containers", "deleted-containers"], [false, true]) @MainActor
    func unsafeExistingParentsRefuseBeforeNamespaceOrSelectorWrites(name: String, withACL: Bool) throws {
        let url = try temporaryRoot()
        defer { try? FileManager.default.removeItem(at: url) }
        let root = try ManagedLifecycleStartupRoot(storeLock: CanonicalDataStoreLock(root: url))
        let parent = try root.openOrCreateDirectory(named: name)
        if withACL { try addACL(to: parent.url) }
        else { #expect(Darwin.fchmod(parent.descriptor, 0o750) == 0) }
        let before = try StoragePreflightSnapshot(url), acl = try aclText(parent)
        // Exercise the same boundary used by RawVirtualizationBackend before its
        // first mutation, not merely the low-level directory validation helper.
        #expect(throws: (any Error).self) { try ManagedLifecycleStartup.preflight(root: root.directory) }
        #expect(throws: (any Error).self) { _ = try ManagedLifecycleStartup.acquireRuntimeNamespace(root: root) }
        #expect(try StoragePreflightSnapshot(url) == before)
        #expect(try aclText(parent) == acl)
        #expect(try root.directory.entryMetadata(named: VMShimRuntimeNamespace.epochRecordName) == nil)
        #expect(try root.directory.entryMetadata(named: "shared-storage-mode.json") == nil)
    }

    @Test @MainActor func safePreflightCreatesNoMissingParentsAndAllowsNonstorageInfrastructure() throws {
        let url = try temporaryRoot()
        defer { try? FileManager.default.removeItem(at: url) }
        let root = try ManagedLifecycleStartupRoot(storeLock: CanonicalDataStoreLock(root: url))
        let empty = try StoragePreflightSnapshot(url)
        try ManagedLifecycleStartup.preflight(root: root.directory)
        #expect(try StoragePreflightSnapshot(url) == empty)
        let infrastructure = try root.openOrCreateDirectory(named: "infrastructure")
        _ = try root.networkNamespace(in: infrastructure)
        let before = try StoragePreflightSnapshot(url)
        try ManagedLifecycleStartup.preflight(root: root.directory)
        #expect(try StoragePreflightSnapshot(url) == before)
        let namespace = try ManagedLifecycleStartup.acquireRuntimeNamespace(root: root)
        defer { try? FileManager.default.removeItem(at: namespace.url) }
        #expect(try root.directory.entryMetadata(named: VMShimRuntimeNamespace.epochRecordName) != nil)
        #expect(try root.directory.entryMetadata(named: "volumes") == nil)
        #expect(try ManagedStorageLifecycleOwner.classify(root: root.directory) == .fresh)
    }

    @Test(arguments: ["volumes.ext4", ".raw-init-volumes.ext4.lock", "volume-token-secret"]) @MainActor
    func namespaceStartupStillRefusesOwnerlessStorageEvidence(name: String) throws {
        let url = try temporaryRoot()
        defer { try? FileManager.default.removeItem(at: url) }
        let root = try ManagedLifecycleStartupRoot(storeLock: CanonicalDataStoreLock(root: url))
        let infrastructure = try root.openOrCreateDirectory(named: "infrastructure")
        try infrastructure.writeExclusiveRegularFile(named: name, data: Data("ownerless evidence".utf8))
        let before = try StoragePreflightSnapshot(url)
        #expect(throws: ManagedStorageLifecycleOwner.UnsupportedStoreFormat.self) {
            _ = try ManagedLifecycleStartup.acquireRuntimeNamespace(root: root)
        }
        #expect(try StoragePreflightSnapshot(url) == before)
    }

    @Test func lifecycleJournalValidationNeverRepairsExistingPermissions() throws {
        let url = try temporaryRoot()
        defer { try? FileManager.default.removeItem(at: url) }
        let root = try ManagedLifecycleStartupRoot(storeLock: CanonicalDataStoreLock(root: url))
        let infrastructure = try root.openOrCreateDirectory(named: "infrastructure")
        #expect(Darwin.fchmod(infrastructure.descriptor, 0o750) == 0)
        let before = try StoragePreflightSnapshot(url)
        #expect(throws: (any Error).self) {
            try RawDiskJournalDirectory.prepare(infrastructure, repairPermissions: false)
        }
        #expect(try StoragePreflightSnapshot(url) == before)
    }

    @Test @MainActor func rootSwapAfterPreflightRefusesWithoutTouchingEitherStore() throws {
        let url = try temporaryRoot(), moved = url.appendingPathExtension("held")
        defer { try? FileManager.default.removeItem(at: url); try? FileManager.default.removeItem(at: moved) }
        let lock = try CanonicalDataStoreLock(root: url)
        let root = try ManagedLifecycleStartupRoot(storeLock: lock)
        let infrastructure = try root.openOrCreateDirectory(named: "infrastructure")
        let identity = root.directory.identity
        try ManagedLifecycleStartup.preflight(root: root.directory)
        try FileManager.default.moveItem(at: url, to: moved)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
        try Data("replacement must stay untouched".utf8).write(to: url.appending(path: "evidence"))
        let replacement = try StoragePreflightSnapshot(url), retained = try StoragePreflightSnapshot(moved)
        #expect(throws: (any Error).self) { try root.validate() }
        #expect(throws: (any Error).self) { try root.openOrCreateDirectory(named: "containers") }
        #expect(throws: (any Error).self) { try root.networkNamespace(in: infrastructure) }
        #expect(throws: (any Error).self) { try PersistentStateDirectory.retaining(lock) }
        #expect(root.directory.identity == identity)
        #expect(try StoragePreflightSnapshot(url) == replacement)
        #expect(try StoragePreflightSnapshot(moved) == retained)
        // Restore the path: classification still uses the very same retained root.
        try FileManager.default.removeItem(at: url)
        try FileManager.default.moveItem(at: moved, to: url)
        try root.validate(infrastructure: infrastructure)
        #expect(try ManagedStorageLifecycleOwner.classify(root: root.directory) == .fresh)
    }

    @Test @MainActor func infrastructureSwapRefusesBeforeNamespaceWrite() throws {
        let url = try temporaryRoot()
        defer { try? FileManager.default.removeItem(at: url) }
        let root = try ManagedLifecycleStartupRoot(storeLock: CanonicalDataStoreLock(root: url))
        let infrastructure = try root.openOrCreateDirectory(named: "infrastructure")
        try ManagedLifecycleStartup.preflight(root: root.directory)
        try FileManager.default.moveItem(at: infrastructure.url, to: url.appending(path: "held-infrastructure"))
        try FileManager.default.createDirectory(at: infrastructure.url, withIntermediateDirectories: false)
        let before = try StoragePreflightSnapshot(url)
        #expect(throws: (any Error).self) { try root.networkNamespace(in: infrastructure) }
        #expect(try StoragePreflightSnapshot(url) == before)
    }

    @Test(arguments: [false, true]) @MainActor
    func actorHopRevalidatesRootAndInfrastructureBeforeProvisioning(swapInfrastructure: Bool) async throws {
        let url = try temporaryRoot(), moved = url.appendingPathExtension("held")
        defer { try? FileManager.default.removeItem(at: url); try? FileManager.default.removeItem(at: moved) }
        let root = try ManagedLifecycleStartupRoot(storeLock: CanonicalDataStoreLock(root: url))
        let infrastructure = try root.openOrCreateDirectory(named: "infrastructure")
        var replacement: StoragePreflightSnapshot?
        var retained: StoragePreflightSnapshot?
        let source = swapInfrastructure ? infrastructure.url : url
        let steps = GuardedSteps(root: root, infrastructure: infrastructure) {
            try await Task.detached {
                try FileManager.default.moveItem(at: source, to: moved)
                try FileManager.default.createDirectory(at: source, withIntermediateDirectories: false)
            }.value
            replacement = try StoragePreflightSnapshot(url)
            retained = try StoragePreflightSnapshot(moved)
        }
        await #expect(throws: (any Error).self) { try await ManagedLifecycleStartup.run(steps) }
        #expect(steps.recorder.calls == ["classify", "disk", "bind", "abandon"])
        #expect(try StoragePreflightSnapshot(url) == replacement)
        #expect(try StoragePreflightSnapshot(moved) == retained)
    }

    @MainActor private final class GuardedSteps: ManagedLifecycleStartupSteps {
        let recorder = ManagedLifecycleStartupTests.Recorder()
        let root: ManagedLifecycleStartupRoot
        let infrastructure: PersistentStateDirectory
        let afterBind: () async throws -> Void
        init(root: ManagedLifecycleStartupRoot, infrastructure: PersistentStateDirectory,
             afterBind: @escaping () async throws -> Void) {
            self.root = root; self.infrastructure = infrastructure; self.afterBind = afterBind
        }
        func validateRetainedDirectories() throws { try root.validate(infrastructure: infrastructure) }
        func classify() throws -> ManagedStorageLifecycleOwner.StoreFormat { try recorder.classify() }
        func validateExistingGeneration() async throws { try await recorder.validateExistingGeneration() }
        func provisionDisk() throws { try recorder.provisionDisk() }
        func openExistingDisk() throws { try recorder.openExistingDisk() }
        func prepareTakeover() async throws { try await recorder.prepareTakeover() }
        func adoptShim() async throws { try await recorder.adoptShim() }
        func reattachShim() async throws { try await recorder.reattachShim() }
        func takeover() async throws { try await recorder.takeover() }
        func recoverWorkload() async throws { try await recorder.recoverWorkload() }
        func bindScope() async throws { try await recorder.bindScope(); try await afterBind() }
        func prepareOwner() async throws { try await recorder.prepareOwner() }
        func launchShim() async throws { try await recorder.launchShim() }
        func prepareFreshDisk() async throws { try await recorder.prepareFreshDisk() }
        func provisionFresh() async throws { try await recorder.provisionFresh() }
        func bootFresh() async throws { try await recorder.bootFresh() }
        func enrollAdoption() async throws { try await recorder.enrollAdoption() }
        func connectWorkload() async throws { try await recorder.connectWorkload() }
        func queryWorkload() async throws { try await recorder.queryWorkload() }
        func adopt() async throws { try await recorder.adopt() }
        func abandon() async { await recorder.abandon() }
    }
}
#endif

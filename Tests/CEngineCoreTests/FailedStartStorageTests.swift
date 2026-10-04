#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

/// No VM is started: storage and initialization journals are real, while the
/// backend models partial execution launch and positively acknowledged teardown.
@Suite struct FailedStartStorageTests {
    @Test func repeatedFailedStartsAndReloadPreserveInitializedWritableRoot() async throws {
        let fixture = StorageFixture()
        defer { fixture.remove() }
        let backend = StorageBackend(root: fixture.root)
        let runtime = try await EngineRuntime(root: fixture.root, backend: backend)
        let record = try await runtime.createContainer(ContainerRecord(name: "persistent-root", image: "fixture"))
        try await runtime.startContainer(record.id)
        try await runtime.stopContainer(record.id)
        let original = try await runtime.container(record.id)
        let before = try fixture.snapshot(record)
        await backend.failLaunch()

        for _ in 0..<3 {
            await #expect(throws: StorageBackend.Failure.launch) {
                try await runtime.startContainer(record.id)
            }
            let restored = try await runtime.container(record.id)
            #expect(restored.phase == .exited)
            #expect(restored.startedAt == original.startedAt)
            #expect(restored.exitCode == original.exitCode)
            #expect(try fixture.snapshot(record) == before)
            #expect(!(await backend.executionMayBeLive))
            #expect(await backend.deletes == 0)
        }
        #expect(await backend.cleanups == 3)
        await runtime.shutdown()

        // A new backend has no retained descriptors or in-memory preparation.
        let reloadedBackend = StorageBackend(root: fixture.root, failStart: true)
        let reloaded = try await EngineRuntime(root: fixture.root, backend: reloadedBackend)
        await #expect(throws: StorageBackend.Failure.launch) {
            try await reloaded.startContainer(record.id)
        }
        #expect(try fixture.snapshot(record) == before)
        #expect(await reloadedBackend.cleanups == 1)
        #expect(await reloadedBackend.deletes == 0)
        await reloadedBackend.allowLaunch()
        try await reloaded.startContainer(record.id)
        try await reloaded.stopContainer(record.id)
        #expect(try fixture.snapshot(record) == before)
        #expect(try await fixture.durableSnapshot().cleanupPendingContainerIDs == nil)
        await reloaded.shutdown()
    }

    @Test func cleanupFailurePersistsQuarantineUntilPositiveCleanupThenExplicitRemoval() async throws {
        let fixture = StorageFixture()
        defer { fixture.remove() }
        let backend = StorageBackend(root: fixture.root)
        let runtime = try await EngineRuntime(root: fixture.root, backend: backend)
        let record = try await runtime.createContainer(ContainerRecord(name: "quarantined-root", image: "fixture"))
        try await runtime.startContainer(record.id)
        try await runtime.stopContainer(record.id)
        let before = try fixture.snapshot(record)
        await backend.failLaunch(rejectCleanup: true)
        do {
            try await runtime.startContainer(record.id)
            Issue.record("failed launch and cleanup reported success")
        } catch let error as EngineError {
            #expect(error.code == .internalError)
            #expect(error.message.contains(
                "container launch failed (\(String(reflecting: StorageBackend.Failure.self))): \(EngineError.message(for: StorageBackend.Failure.launch))"
            ))
            #expect(error.message.contains(
                "rollback failed (\(String(reflecting: EngineError.self))): backend cleanup for container \(record.id) could not be verified"
            ))
            #expect(error.message.contains("stop: \(EngineError.message(for: StorageBackend.Failure.cleanup))"))
            #expect(error.message.contains("execution cleanup: \(EngineError.message(for: StorageBackend.Failure.cleanup))"))
        }
        #expect(try await runtime.container(record.id).phase == .dead)
        let quarantinedSnapshot = try await fixture.durableSnapshot()
        #expect(quarantinedSnapshot.containers.first { $0.id == record.id }?.phase == .dead)
        #expect(quarantinedSnapshot.cleanupPendingContainerIDs == [record.id])
        #expect(try fixture.snapshot(record) == before)
        #expect(await backend.executionMayBeLive)
        #expect(await backend.deletes == 0)
        await runtime.shutdown()

        let refusingBackend = StorageBackend(root: fixture.root, rejectCleanup: true, executionMayBeLive: true)
        let quarantined = try await EngineRuntime(root: fixture.root, backend: refusingBackend)
        #expect(try await quarantined.container(record.id).phase == .dead)
        #expect(try await fixture.durableSnapshot().cleanupPendingContainerIDs == [record.id])
        #expect(try fixture.snapshot(record) == before)
        #expect(await refusingBackend.cleanups == 1)
        #expect(await refusingBackend.deletes == 0)
        do {
            try await quarantined.startContainer(record.id)
            Issue.record("quarantined execution became restartable")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }
        #expect(await refusingBackend.starts == 0)
        #expect(await refusingBackend.executionMayBeLive)
        await quarantined.shutdown()

        let recoveredBackend = StorageBackend(root: fixture.root, executionMayBeLive: true)
        let recovered = try await EngineRuntime(root: fixture.root, backend: recoveredBackend)
        #expect(try await recovered.container(record.id).phase == .exited)
        #expect(try await fixture.durableSnapshot().cleanupPendingContainerIDs == nil)
        #expect(await recoveredBackend.cleanups == 1)
        #expect(!(await recoveredBackend.executionMayBeLive))
        #expect(await recoveredBackend.deletes == 0)
        #expect(try fixture.snapshot(record) == before)

        try await recovered.removeContainer(record.id, force: false)
        #expect(await recoveredBackend.deletes == 1)
        #expect(!FileManager.default.fileExists(atPath: fixture.directory(record).path))
        #expect(try await fixture.durableSnapshot().containers.isEmpty)
        await recovered.shutdown()
    }

    @Test func unsupportedExecutionCleanupFailsClosedWithoutDestructiveFallback() async throws {
        let fixture = StorageFixture()
        defer { fixture.remove() }
        let storage = StorageBackend(root: fixture.root)
        let backend = UnsupportedCleanupBackend(storage: storage)
        let runtime = try await EngineRuntime(root: fixture.root, backend: backend)
        let record = try await runtime.createContainer(ContainerRecord(name: "unsupported-cleanup", image: "fixture"))
        try await runtime.startContainer(record.id)
        try await runtime.stopContainer(record.id)
        let before = try fixture.snapshot(record)

        do {
            try await backend.cleanupExecution(record)
            Issue.record("backend without execution cleanup reported success")
        } catch let error as EngineError {
            #expect(error.code == .unsupported)
        }
        #expect(await storage.deletes == 0)
        await storage.failLaunch()
        do {
            try await runtime.startContainer(record.id)
            Issue.record("failed launch with unsupported cleanup reported success")
        } catch let error as EngineError {
            #expect(error.code == .internalError)
            #expect(error.message.contains(
                "container launch failed (\(String(reflecting: StorageBackend.Failure.self))): \(EngineError.message(for: StorageBackend.Failure.launch))"
            ))
            #expect(error.message.contains(
                "rollback failed (\(String(reflecting: EngineError.self))): backend cleanup for container \(record.id) could not be verified"
            ))
            #expect(error.message.contains(
                "execution cleanup: non-destructive execution cleanup is unavailable for this backend"
            ))
        }
        #expect(try await runtime.container(record.id).phase == .dead)
        let quarantinedSnapshot = try await fixture.durableSnapshot()
        #expect(quarantinedSnapshot.containers.first { $0.id == record.id }?.phase == .dead)
        #expect(quarantinedSnapshot.cleanupPendingContainerIDs == [record.id])
        #expect(try fixture.snapshot(record) == before)
        #expect(await storage.cleanups == 0)
        #expect(await storage.deletes == 0)
        await runtime.shutdown()

        let reloaded = try await EngineRuntime(root: fixture.root, backend: backend)
        #expect(try await reloaded.container(record.id).phase == .dead)
        #expect(try await fixture.durableSnapshot().cleanupPendingContainerIDs == [record.id])
        #expect(try fixture.snapshot(record) == before)
        #expect(await storage.cleanups == 0)
        #expect(await storage.deletes == 0)
        await reloaded.shutdown()
    }
}

private struct StorageFixture {
    let root = FileManager.default.temporaryDirectory.appending(path: "cengine-failed-start-\(UUID())")

    func directory(_ record: ContainerRecord) -> URL {
        root.appending(path: "containers/\(record.id)")
    }

    func remove() { try? FileManager.default.removeItem(at: root) }

    func durableSnapshot() async throws -> EngineSnapshot {
        try await AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json")).load(default: EngineSnapshot())
    }

    struct Artifact: Equatable {
        let device: dev_t
        let inode: ino_t
        let mode: mode_t
        let bytes: Data?
    }

    func snapshot(_ record: ContainerRecord) throws -> [String: Artifact] {
        let url = directory(record)
        let directory = try PersistentStateDirectory.open(url)
        guard case .journal(let journal) = try RawDiskInitialization.inspectExisting(
            in: directory, named: "root.ext4", expectedSize: 4096
        ) else {
            throw EngineError(.internalError, "initialized writable root lost its journal")
        }
        try #require(journal.state == .initialized)
        for state in ["created", "spent", "initialized"] {
            try #require(FileManager.default.fileExists(atPath: url.appending(path: ".raw-init-root.ext4.\(state).json").path))
        }
        let enumerator = try #require(FileManager.default.enumerator(at: url, includingPropertiesForKeys: nil))
        var result: [String: Artifact] = [:]
        for item in [url] + enumerator.allObjects.compactMap({ $0 as? URL }) {
            var info = stat()
            try #require(lstat(item.path, &info) == 0)
            let bytes = info.st_mode & S_IFMT == S_IFREG ? try Data(contentsOf: item) : nil
            result[String(item.path.dropFirst(url.path.count))] = Artifact(
                device: info.st_dev, inode: info.st_ino, mode: info.st_mode, bytes: bytes
            )
        }
        return result
    }
}

private actor StorageBackend: ContainerBackend {
    enum Failure: Error, Equatable { case launch, cleanup }

    let root: URL
    private var failStart: Bool
    private var rejectCleanup: Bool
    private(set) var executionMayBeLive: Bool
    private(set) var starts = 0
    private(set) var cleanups = 0
    private(set) var deletes = 0

    init(root: URL, failStart: Bool = false, rejectCleanup: Bool = false, executionMayBeLive: Bool = false) {
        self.root = root
        self.failStart = failStart
        self.rejectCleanup = rejectCleanup
        self.executionMayBeLive = executionMayBeLive
    }

    private func directory(_ record: ContainerRecord) -> URL {
        root.appending(path: "containers/\(record.id)")
    }

    func pullImage(_: String, platform _: String) async throws {}

    func prepare(_ record: ContainerRecord) async throws {
        let url = directory(record)
        if FileManager.default.fileExists(atPath: url.path) {
            try RawContainerPreparationArtifacts.validateExisting(in: PersistentStateDirectory.open(url))
            return
        }
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        _ = try RawContainerPreparationArtifacts.create(in: PersistentStateDirectory.open(url), rootDiskSize: 4096)
        try Data("persistent userdata\n".utf8).write(to: url.appending(path: "userdata"))
        try Data(#"{"image":"fixture","rootDiskSize":4096}"#.utf8).write(to: url.appending(path: "rootmetadata.json"))
    }

    func start(_ record: ContainerRecord) async throws -> [PortBinding] {
        starts += 1
        executionMayBeLive = true
        if failStart { throw Failure.launch }
        let directory = try PersistentStateDirectory.open(directory(record))
        let binding = RawDiskInitialization.Binding(shimLaunchUUID: UUID(), guestBootNonce: UUID())
        if let authorization = try RawDiskInitialization.begin(
            in: directory, named: "root.ext4", expectedSize: 4096, binding: binding
        ) {
            // Model the first guest write without mounting/formatting or replacing
            // the inode. Real journal transitions exercise one-shot authority.
            let disk = try FileHandle(forUpdating: directory.url.appending(path: "root.ext4"))
            defer { try? disk.close() }
            try disk.write(contentsOf: Data("guest-created persistent file contents\n".utf8))
            try disk.synchronize()
            try RawDiskInitialization.completeAfterVerifiedGuestSync(
                in: directory, named: "root.ext4", expectedSize: 4096,
                operationUUID: try #require(UUID(uuidString: authorization.record.operationUUID)),
                ext4UUID: try #require(UUID(uuidString: authorization.record.ext4UUID)), binding: binding,
                heldDiskDescriptor: disk.fileDescriptor
            )
        }
        return record.ports
    }

    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 {
        if rejectCleanup { throw Failure.cleanup }
        executionMayBeLive = false
        return 0
    }

    func wait(_: ContainerRecord) async throws -> Int32 { 0 }

    func cleanupExecution(_: ContainerRecord) async throws {
        cleanups += 1
        if rejectCleanup { throw Failure.cleanup }
        executionMayBeLive = false
        // Keep the root, every initialization journal, metadata, and prepared I/O.
    }

    func delete(_ record: ContainerRecord) async throws {
        deletes += 1
        if rejectCleanup { throw Failure.cleanup }
        executionMayBeLive = false
        try FileManager.default.removeItem(at: directory(record))
    }

    func failLaunch(rejectCleanup: Bool = false) {
        failStart = true
        self.rejectCleanup = rejectCleanup
    }
    func allowLaunch() { failStart = false }
}

/// Intentionally omits cleanupExecution: the protocol default must reject it,
/// even though this backend can stop and destructively delete containers.
private struct UnsupportedCleanupBackend: ContainerBackend {
    let storage: StorageBackend
    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_ record: ContainerRecord) async throws { try await storage.prepare(record) }
    func start(_ record: ContainerRecord) async throws -> [PortBinding] { try await storage.start(record) }
    func stop(_ record: ContainerRecord, timeoutSeconds: Int) async throws -> Int32 {
        try await storage.stop(record, timeoutSeconds: timeoutSeconds)
    }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_ record: ContainerRecord) async throws { try await storage.delete(record) }
}
#endif

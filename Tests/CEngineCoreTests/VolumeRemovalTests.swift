import Foundation
#if os(macOS)
import Darwin
#endif
import Testing
@testable import CEngineCore
@testable import CEngineRuntime

@Suite struct VolumeRemovalTests {
    private actor Gate {
        private var arrived = false
        private var arrival: CheckedContinuation<Void, Never>?
        private var release: CheckedContinuation<Void, Never>?

        func pause() async {
            guard !arrived else { return }
            arrived = true
            arrival?.resume()
            arrival = nil
            await withCheckedContinuation { release = $0 }
        }

        func wait() async {
            if !arrived { await withCheckedContinuation { arrival = $0 } }
        }

        func resume() { release?.resume(); release = nil }
    }

    private actor CleanupBarrier {
        private var releases: [CheckedContinuation<Void, Never>] = []
        private var arrival: CheckedContinuation<Void, Never>?
        func pause() async {
            await withCheckedContinuation {
                releases.append($0)
                if releases.count == 2 { arrival?.resume(); arrival = nil }
            }
        }
        func waitForBoth() async {
            if releases.count < 2 { await withCheckedContinuation { arrival = $0 } }
        }
        func resume() { for release in releases { release.resume() }; releases.removeAll() }
    }

    private actor Backend: ContainerBackend {
        enum Failure: Error { case deletion }
        var deleted: [String] = []
        let deletionGate: Gate?
        let preparationGate: Gate?
        let failDeletion: Bool
        let failedVolume: String?
        let failAfterDeletion: Bool
        let cleanupBarrier: CleanupBarrier?

        init(
            deletionGate: Gate? = nil, preparationGate: Gate? = nil,
            failDeletion: Bool = false, failedVolume: String? = nil,
            failAfterDeletion: Bool = false, cleanupBarrier: CleanupBarrier? = nil
        ) {
            self.deletionGate = deletionGate
            self.preparationGate = preparationGate
            self.failDeletion = failDeletion
            self.failedVolume = failedVolume
            self.failAfterDeletion = failAfterDeletion
            self.cleanupBarrier = cleanupBarrier
        }

        func pullImage(_: String, platform _: String) async throws {}
        func prepare(_: ContainerRecord) async throws { await preparationGate?.pause() }
        func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
        func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
        func wait(_: ContainerRecord) async throws -> Int32 { 0 }
        func cleanupExecution(_: ContainerRecord) async throws {}
        func delete(_: ContainerRecord) async throws { await cleanupBarrier?.pause() }
        func deleteVolume(_ name: String) async throws {
            if name == "data" { await deletionGate?.pause() }
            if failDeletion || name == failedVolume { throw Failure.deletion }
            deleted.append(name)
            // Models shared storage deletion succeeding before volume-storage.json fails.
            if failAfterDeletion { throw Failure.deletion }
        }
    }

    private func consumer() -> ContainerRecord {
        var record = ContainerRecord(name: "consumer", image: "example")
        record.mounts = [.init(kind: .volume, source: "data", destination: "/data")]
        return record
    }

    @Test(arguments: [false, true])
    func referencedVolumeCannotBeForcedAway(running: Bool) async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        _ = try await runtime.createVolume(name: "data")
        let container = try await runtime.createContainer(consumer())
        if running { try await runtime.startContainer(container.id) }
        for force in [false, true] {
            await #expect(throws: EngineError.self) {
                try await runtime.removeVolume("data", force: force)
            }
        }
        #expect(await backend.deleted.isEmpty)
        #expect(await runtime.listVolumes().map(\.name) == ["data"])
    }

    @Test func preparingContainerReservesItsVolumeAgainstRemovalAndPrune() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let gate = Gate()
        let backend = Backend(preparationGate: gate)
        let runtime = try await EngineRuntime(root: root, backend: backend)
        _ = try await runtime.createVolume(name: "data")
        let record = consumer()
        let creation = Task { try await runtime.createContainer(record) }
        await gate.wait()
        await #expect(throws: EngineError.self) {
            try await runtime.removeVolume("data", force: true)
        }
        #expect(try await runtime.pruneVolumes(scope: .allUnused).isEmpty)
        #expect(await backend.deleted.isEmpty)
        await gate.resume()
        _ = try await creation.value
    }

    @Test(arguments: [false, true])
    func deletionReservesNameAndDoesNotRemoveAnUnrelatedVolume(pruning: Bool) async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let gate = Gate()
        let runtime = try await EngineRuntime(root: root, backend: Backend(deletionGate: gate))
        _ = try await runtime.createVolume(name: "prefix")
        _ = try await runtime.createVolume(name: "data")
        // Keep only data eligible for prune. In the remove case, deleting prefix
        // during suspension shifts the old data index to an unrelated volume.
        if pruning {
            try await runtime.removeVolume("prefix", force: false)
        }
        let removal = Task {
            if pruning { _ = try await runtime.pruneVolumes(scope: .allUnused) }
            else { try await runtime.removeVolume("data", force: false) }
        }
        await gate.wait()
        await #expect(throws: EngineError.self) {
            _ = try await runtime.createVolume(name: "data")
        }
        let record = consumer()
        await #expect(throws: EngineError.self) { _ = try await runtime.createContainer(record) }
        await #expect(throws: EngineError.self) {
            try await runtime.removeVolume("data", force: true)
        }
        if !pruning { try await runtime.removeVolume("prefix", force: false) }
        _ = try await runtime.createVolume(name: "keep")
        await gate.resume()
        try await removal.value
        #expect(await runtime.listVolumes().map(\.name) == ["keep"])
        _ = try await runtime.createVolume(name: "data", labels: ["generation": "new"])
        #expect(await runtime.listVolumes().first { $0.name == "data" }?.labels == ["generation": "new"])
    }

    @Test func removingOneConsumerPreservesItsSharedAnonymousVolume() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        _ = try await runtime.createVolume(name: "data", anonymous: true)
        let first = try await runtime.createContainer(consumer())
        var peer = consumer()
        peer.name = "peer"
        let second = try await runtime.createContainer(peer)
        try await runtime.removeContainer(first.id, force: true, removeVolumes: true)
        #expect(await backend.deleted.isEmpty)
        #expect(await runtime.listVolumes().map(\.name) == ["data"])
        try await runtime.removeContainer(second.id, force: true, removeVolumes: true)
        #expect(await backend.deleted == ["data"])
        #expect(await runtime.listVolumes().isEmpty)
    }

    @Test func autoRemoveReservesAnonymousVolumeThroughDurableCommit() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let deletionGate = Gate()
        let commitGate = Gate()
        let backend = Backend(deletionGate: deletionGate)
        let runtime = try await EngineRuntime(
            root: root, backend: backend,
            beforePersistence: {
                if await backend.deleted.contains("data") { await commitGate.pause() }
            }
        )
        _ = try await runtime.createVolume(name: "data", anonymous: true)
        var record = consumer()
        record.autoRemove = true
        let container = try await runtime.createContainer(record)
        try await runtime.startContainer(container.id)
        let stopping = Task { try await runtime.stopContainer(container.id) }
        var peer = consumer()
        peer.name = "peer"
        let newConsumer = peer

        await deletionGate.wait()
        await #expect(throws: EngineError.self) {
            _ = try await runtime.createContainer(newConsumer)
        }
        await #expect(throws: EngineError.self) {
            _ = try await runtime.createVolume(name: "data")
        }
        await deletionGate.resume()

        // Deletion has finished, but the recoverable metadata/intent union stays
        // visible until the same atomic commit removes the container and volume.
        await commitGate.wait()
        #expect(await runtime.listVolumes().map(\.name) == ["data"])
        await #expect(throws: EngineError.self) {
            _ = try await runtime.createContainer(newConsumer)
        }
        await #expect(throws: EngineError.self) {
            _ = try await runtime.createVolume(name: "data")
        }
        await commitGate.resume()
        try await stopping.value
        #expect(await runtime.listContainers(all: true).isEmpty)
        #expect(await backend.deleted == ["data"])
        _ = try await runtime.createVolume(name: "data", labels: ["generation": "new"])
        _ = try await runtime.createContainer(newConsumer)
        await runtime.shutdown()
    }

    @Test func autoRemoveQuarantinesPartialVolumeDeletionForRecovery() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let deletionGate = Gate()
        let backend = Backend(deletionGate: deletionGate, failedVolume: "data")
        let runtime = try await EngineRuntime(root: root, backend: backend)
        _ = try await runtime.createVolume(name: "prefix", anonymous: true)
        _ = try await runtime.createVolume(name: "data", anonymous: true)
        var record = consumer()
        record.autoRemove = true
        record.mounts.insert(.init(kind: .volume, source: "prefix", destination: "/prefix"), at: 0)
        let container = try await runtime.createContainer(record)
        try await runtime.startContainer(container.id)
        let stopping = Task { try await runtime.stopContainer(container.id) }
        await deletionGate.wait()
        #expect(await backend.deleted == ["prefix"])
        var peer = consumer()
        peer.name = "peer"
        let newConsumer = peer
        await #expect(throws: EngineError.self) {
            _ = try await runtime.createContainer(newConsumer)
        }
        await deletionGate.resume()
        try await stopping.value

        #expect(try await runtime.container(container.id).phase == .dead)
        #expect(await runtime.listVolumes().map(\.name) == ["prefix", "data"])
        for name in ["prefix", "data"] {
            var peer = consumer()
            peer.name = "after-failure-\(name)"
            peer.mounts = [.init(kind: .volume, source: name, destination: "/data")]
            let candidate = peer
            await #expect(throws: EngineError.self) {
                _ = try await runtime.createContainer(candidate)
            }
            await #expect(throws: EngineError.self) {
                _ = try await runtime.createVolume(name: name)
            }
        }
        await #expect(throws: EngineError.self) { try await runtime.startContainer(container.id) }
        let store = AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json"))
        let durable = try await store.loadRequired()
        #expect(durable.containers.first { $0.id == container.id }?.phase == .dead)
        #expect(durable.volumes.map(\.name) == ["prefix", "data"])
        #expect(durable.removalPendingContainerIDs == [container.id])
        #expect(durable.removalVolumesPendingContainerIDs == [container.id])
        #expect(durable.cleanupPendingContainerIDs == [container.id])
        #expect(durable.containerFenceInstanceIDs == [container.id: container.instanceID])
        let events = await runtime.events(until: Date())
        for await event in events { #expect(event.action != "destroy") }
        await runtime.shutdown()

        // Like explicit rm -v recovery, startup fails closed until storage is repaired.
        // Retrying must preserve the exact quarantine, not discard its journal.
        let quarantine = try Data(contentsOf: root.appending(path: "engine.json"))
        for _ in 0..<2 {
            let failingRecoveryBackend = Backend(failedVolume: "data")
            await #expect(throws: Backend.Failure.self) {
                _ = try await EngineRuntime(root: root, backend: failingRecoveryBackend)
            }
            #expect(await failingRecoveryBackend.deleted == ["prefix"])
            #expect(try Data(contentsOf: root.appending(path: "engine.json")) == quarantine)
        }

        let recoveryBackend = Backend()
        let recovered = try await EngineRuntime(root: root, backend: recoveryBackend)
        #expect(await recovered.listContainers(all: true).isEmpty)
        #expect(await recovered.listVolumes().isEmpty)
        #expect(await recoveryBackend.deleted == ["prefix", "data"])
        let removed = try await store.loadRequired()
        #expect(removed.containers.isEmpty)
        #expect(removed.volumes.isEmpty)
        #expect(removed.removalPendingContainerIDs == nil)
        #expect(removed.removalVolumesPendingContainerIDs == nil)
        #expect(removed.cleanupPendingContainerIDs == nil)
        #expect(removed.containerFenceInstanceIDs == nil)
        await recovered.shutdown()
    }

    @Test func failedStorageDeletionRetainsVolumeMetadata() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root, backend: Backend(failDeletion: true))
        _ = try await runtime.createVolume(name: "data", labels: ["generation": "old"])
        await #expect(throws: Backend.Failure.self) {
            try await runtime.removeVolume("data", force: false)
        }
        #expect(await runtime.listVolumes().first?.labels == ["generation": "old"])
        await #expect(throws: EngineError.self) { _ = try await runtime.createVolume(name: "data") }
    }

    @Test func concurrentLastConsumersDeleteSharedAnonymousVolumeExactlyOnce() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let barrier = CleanupBarrier()
        let backend = Backend(cleanupBarrier: barrier)
        let runtime = try await EngineRuntime(root: root, backend: backend)
        _ = try await runtime.createVolume(name: "data", anonymous: true)
        let first = try await runtime.createContainer(consumer())
        var peer = consumer()
        peer.name = "peer"
        let second = try await runtime.createContainer(peer)
        let firstRemoval = Task { try await runtime.removeContainer(first.id, force: true, removeVolumes: true) }
        let secondRemoval = Task { try await runtime.removeContainer(second.id, force: true, removeVolumes: true) }
        await barrier.waitForBoth()
        #expect(await backend.deleted.isEmpty)
        peer.name = "new-consumer"
        let candidate = peer
        await #expect(throws: EngineError.self) { _ = try await runtime.createContainer(candidate) }
        await barrier.resume()
        try await firstRemoval.value
        try await secondRemoval.value
        #expect(await backend.deleted == ["data"])
        #expect(await runtime.listVolumes().isEmpty)
        #expect(await runtime.listContainers(all: true).isEmpty)
        await runtime.shutdown()
    }

    @Test(arguments: [false, true])
    func destructiveFailureFencesExactGenerationAcrossReload(snapshotFailure: Bool) async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend(failAfterDeletion: !snapshotFailure)
        let runtime = try await EngineRuntime(root: root, backend: backend, beforePersistence: {
            if snapshotFailure, await !backend.deleted.isEmpty { throw Backend.Failure.deletion }
        })
        let original = try await runtime.createVolume(name: "data", labels: ["generation": "old"])
        await #expect(throws: Backend.Failure.self) { try await runtime.removeVolume("data", force: false) }
        #expect(await backend.deleted == ["data"])
        await #expect(throws: EngineError.self) { _ = try await runtime.createVolume(name: "data") }
        let candidate = consumer()
        await #expect(throws: EngineError.self) { _ = try await runtime.createContainer(candidate) }
        // This is the same availability guard used by start/restart: even an
        // already captured consumer cannot bypass the generation fence.
        await #expect(throws: EngineError.self) { try await runtime.requireBackendExecutionAvailable(candidate) }
        let store = AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json"))
        let durable = try await store.loadRequired()
        #expect(durable.volumes.first?.instanceID == original.instanceID)
        #expect(durable.volumeRemovalIntents?.first?.instanceID == original.instanceID)
        await runtime.shutdown()
        let failingRecovery = Backend(failAfterDeletion: true)
        await #expect(throws: Backend.Failure.self) {
            _ = try await EngineRuntime(root: root, backend: failingRecovery)
        }
        #expect(try await store.loadRequired().volumeRemovalIntents?.first?.instanceID == original.instanceID)
        let recovery = Backend()
        let recovered = try await EngineRuntime(root: root, backend: recovery)
        #expect(await recovery.deleted == ["data"])
        #expect(await recovered.listVolumes().isEmpty)
        #expect(try await store.loadRequired().volumeRemovalIntents == nil)
        let replacement = try await recovered.createVolume(name: "data")
        #expect(replacement.instanceID != original.instanceID)
        _ = try await recovered.createContainer(candidate)
        await recovered.shutdown()
    }

    @Test func prunePersistsEachCompletedVolumeBeforeNextDestruction() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend(failedVolume: "data")
        let runtime = try await EngineRuntime(root: root, backend: backend)
        for name in ["prefix", "data", "untouched"] { _ = try await runtime.createVolume(name: name) }
        await #expect(throws: Backend.Failure.self) { _ = try await runtime.pruneVolumes(scope: .allUnused) }
        #expect(await backend.deleted == ["prefix"])
        #expect(await runtime.listVolumes().map(\.name) == ["data", "untouched"])
        let store = AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json"))
        let durable = try await store.loadRequired()
        #expect(durable.volumes.map(\.name) == ["data", "untouched"])
        #expect(durable.volumeRemovalIntents?.map(\.name) == ["data"])
        await #expect(throws: EngineError.self) { _ = try await runtime.createVolume(name: "data") }
        _ = try await runtime.createVolume(name: "untouched")
        let replacement = try await runtime.createVolume(name: "prefix")
        await runtime.shutdown()
        let recovery = Backend()
        let recovered = try await EngineRuntime(root: root, backend: recovery)
        #expect(await recovery.deleted == ["data"])
        #expect(await recovered.listVolumes().first { $0.name == "prefix" }?.instanceID == replacement.instanceID)
        await recovered.shutdown()
    }

    @Test func removalIntentRejectsReplacementGenerationBeforeBackendDeletion() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root, backend: Backend(failDeletion: true))
        _ = try await runtime.createVolume(name: "data")
        await #expect(throws: Backend.Failure.self) { try await runtime.removeVolume("data", force: false) }
        await runtime.shutdown()
        let store = AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json"))
        var durable = try await store.loadRequired()
        var volumeJSON = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(durable.volumes[0])) as? [String: Any])
        volumeJSON["instanceID"] = UUID().uuidString
        durable.volumes[0] = try JSONDecoder().decode(VolumeRecord.self, from: JSONSerialization.data(withJSONObject: volumeJSON))
        try await store.save(durable)
        let backend = Backend()
        await #expect(throws: EngineError.self) { _ = try await EngineRuntime(root: root, backend: backend) }
        #expect(await backend.deleted.isEmpty)
    }

    #if os(macOS)
    @Test func blockDiskRemovalDoesNotHideFailuresOrReuseOldContents() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let disk = root.appending(path: "disk.ext4")
        try Data("old dump".utf8).write(to: disk)
        try RawVirtualizationBackend.removeVolumeDisk(at: disk)
        try RawVirtualizationBackend.removeVolumeDisk(at: disk) // Shared/missing is idempotent.
        try Data().write(to: disk)
        #expect(try Data(contentsOf: disk).isEmpty)
        try FileManager.default.removeItem(at: disk)
        try FileManager.default.createDirectory(at: disk, withIntermediateDirectories: false)
        try Data("keep".utf8).write(to: disk.appending(path: "sentinel"))
        #expect(throws: (any Error).self) { try RawVirtualizationBackend.removeVolumeDisk(at: disk) }
        #expect(try Data(contentsOf: disk.appending(path: "sentinel")) == Data("keep".utf8))
    }
    @Test func journaledVolumeRemovalRecreatesFreshDiskAndAuthorization() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let volumes = try PersistentStateDirectory.open(root)
        let original = try RawVolumeDiskProvisioning.prepare(in: volumes, name: "data", size: 4096)
        let disk = URL(filePath: original.path)
        #expect(disk.lastPathComponent == "disk.ext4")
        #expect(disk.deletingLastPathComponent().lastPathComponent.hasSuffix(".disk"))
        let directory = try PersistentStateDirectory.open(disk.deletingLastPathComponent())
        guard case .journal(let first) = try RawDiskInitialization.inspectExisting(
            in: directory, named: "disk.ext4", expectedSize: 4096
        ) else { Issue.record("missing CREATED record"); return }
        let held = try directory.openRegularFile(named: "disk.ext4", access: .readWrite)
        defer { try? held.handle.close() }
        try held.handle.write(contentsOf: Data("old-data".utf8))
        // The actual attachment FD, not a separate sidecar, prevents deletion.
        try #require(flock(held.handle.fileDescriptor, LOCK_EX | LOCK_NB) == 0)
        #expect(throws: (any Error).self) { try RawVirtualizationBackend.removeVolumeDisk(at: disk) }
        #expect(directory.pathStillNamesThisDirectory())
        try #require(flock(held.handle.fileDescriptor, LOCK_UN) == 0)
        try RawVirtualizationBackend.removeVolumeDisk(at: disk)
        #expect(try volumes.entryNames().isEmpty)
        try RawVirtualizationBackend.removeVolumeDisk(at: disk)
        let replacement = try RawVolumeDiskProvisioning.prepare(in: volumes, name: "data", size: 4096)
        #expect(replacement.identity != original.identity)
        let replacementDirectory = try PersistentStateDirectory.open(disk.deletingLastPathComponent())
        guard case .journal(let second) = try RawDiskInitialization.inspectExisting(
            in: replacementDirectory, named: "disk.ext4", expectedSize: 4096
        ) else { Issue.record("missing replacement CREATED record"); return }
        #expect(second.operationUUID != first.operationUUID)
        #expect(second.ext4UUID != first.ext4UUID)
        #expect(try Data(contentsOf: disk) == Data(repeating: 0, count: 4096))
    }

    @Test func legacyVolumeIsMountOnlyAndDualLayoutsAreRejected() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let volumes = try PersistentStateDirectory.open(root)
        let proposed = try RawVolumeDiskProvisioning.diskURL(in: volumes, name: "data")
        let directoryName = proposed.deletingLastPathComponent().lastPathComponent
        let legacyName = String(directoryName.dropLast(5)) + ".ext4"
        let identity = try volumes.createSparseRegularFile(named: legacyName, size: 4096)
        let legacy = try RawVolumeDiskProvisioning.prepare(in: volumes, name: "data", size: 4096)
        #expect(legacy.path == root.appending(path: legacyName).path)
        #expect(legacy.identity == identity.shimIdentity)
        #expect(try RawDiskInitialization.inspectExisting(
            in: volumes, named: legacyName, expectedSize: 4096
        ) == .mountOnly)
        _ = try volumes.createDirectory(named: directoryName)
        #expect(throws: (any Error).self) { try RawVolumeDiskProvisioning.prepare(in: volumes, name: "data", size: 4096) }
        #expect(throws: (any Error).self) { try RawVirtualizationBackend.removeVolumeDisk(at: URL(filePath: legacy.path)) }
        #expect(throws: (any Error).self) { try RawVirtualizationBackend.removeVolumeDisk(at: proposed) }
        #expect(try volumes.regularFileIdentity(named: legacyName) == identity)
    }

    @Test func partialVolumeDirectoryIsPreservedInsteadOfRetried() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let volumes = try PersistentStateDirectory.open(root)
        let disk = try RawVolumeDiskProvisioning.diskURL(in: volumes, name: "data")
        let partial = try volumes.createDirectory(named: disk.deletingLastPathComponent().lastPathComponent)
        for _ in 0..<2 {
            #expect(throws: (any Error).self) { try RawVolumeDiskProvisioning.prepare(in: volumes, name: "data", size: 4096) }
            #expect(partial.pathStillNamesThisDirectory())
            #expect(try partial.entryMetadata(named: "disk.ext4") == nil)
        }
    }

    @Test func unresolvedLegacyRemovalClaimBlocksSameNameRecreation() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let volumes = try PersistentStateDirectory.open(root)
        let proposed = try RawVolumeDiskProvisioning.diskURL(in: volumes, name: "data")
        let directoryName = proposed.deletingLastPathComponent().lastPathComponent
        let legacyName = String(directoryName.dropLast(5)) + ".ext4"
        let disk = root.appending(path: legacyName)
        let bytes = Data(repeating: 0xA5, count: 4096)
        try bytes.write(to: disk)
        let identity = try volumes.regularFileIdentity(named: legacyName)
        let claimName = ".cengine-remove-\(UUID().uuidString.lowercased())"
        let claim = root.appending(path: claimName)
        // Model interruption after the exact legacy disk was renamed into its claim.
        try FileManager.default.moveItem(at: disk, to: claim)
        let retainedNames = Set(try volumes.entryNames())
        for _ in 0..<2 {
            #expect(throws: EngineError.self) { try RawVolumeDiskProvisioning.diskURL(in: volumes, name: "data") }
            #expect(throws: EngineError.self) { try RawVolumeDiskProvisioning.prepare(in: volumes, name: "data", size: 4096) }
            #expect(throws: EngineError.self) { try RawVirtualizationBackend.removeVolumeDisk(at: disk) }
            #expect(Set(try volumes.entryNames()) == retainedNames)
            #expect(try volumes.regularFileIdentity(named: claimName) == identity)
            #expect(try Data(contentsOf: claim) == bytes)
            #expect(try volumes.entryMetadata(named: directoryName) == nil)
        }
    }

    @Test func interruptedWholeVolumeDisposalBlocksSameNameRecreation() throws {
        enum Injected: Error { case crash }
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let volumes = try PersistentStateDirectory.open(root)
        let original = try RawVolumeDiskProvisioning.prepare(in: volumes, name: "data", size: 4096)
        let disk = URL(filePath: original.path)
        #expect(throws: Injected.self) {
            try RawVolumeDiskProvisioning.remove(at: disk, hook: { boundary in
                if boundary == .rootClaimed { throw Injected.crash }
            })
        }
        let retainedNames = Set(try volumes.entryNames())
        for _ in 0..<2 {
            #expect(throws: (any Error).self) { try RawVolumeDiskProvisioning.prepare(in: volumes, name: "data", size: 4096) }
            #expect(throws: (any Error).self) { try RawVirtualizationBackend.removeVolumeDisk(at: disk) }
            #expect(Set(try volumes.entryNames()) == retainedNames)
        }
    }
    #endif
}

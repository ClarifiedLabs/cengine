import Foundation
import Testing
@testable import CEngineCore
@testable import CEngineRuntime

@Suite struct StorageIdentityCouplingTests {
    private enum Failure: Error { case injected }

    private actor Counter {
        var value = 0
        func increment() { value += 1 }
    }

    private actor RemovalSnapshotCapture {
        var runtime: EngineRuntime?
        var value: EngineSnapshot?
        func attach(_ runtime: EngineRuntime) { self.runtime = runtime }
        func capture() async {
            guard value == nil, let runtime else { return }
            value = await runtime.snapshot
        }
    }

    private actor Gate {
        private var entered = false
        private var observer: CheckedContinuation<Void, Never>?
        private var release: CheckedContinuation<Void, Never>?
        func pause() async {
            guard !entered else { return }
            entered = true
            observer?.resume(); observer = nil
            await withCheckedContinuation { release = $0 }
        }
        func wait() async {
            if !entered { await withCheckedContinuation { observer = $0 } }
        }
        func resume() { release?.resume(); release = nil }
    }

    private actor Backend: ContainerBackend {
        let store: AtomicStore<EngineSnapshot>
        let counter: Counter?
        let synchronizationGate: Gate?
        let preparationGate: Gate?
        var failReconcile = false
        var failSync = false
        var failDelete = false
        var failCommit = false
        func armCommitFailure() { failCommit = true }
        func consumeCommitFailure() -> Bool {
            guard failCommit, !deleted.isEmpty else { return false }
            failCommit = false
            return true
        }
        var events: [String] = []
        var reconciled: [VolumeRecord] = []
        var synchronized: [[VolumeRecord]] = []
        var deleted: [VolumeRecord] = []
        var migrationSaves: Int?

        init(root: URL, counter: Counter? = nil, synchronizationGate: Gate? = nil, preparationGate: Gate? = nil) {
            store = AtomicStore(url: root.appending(path: "engine.json"))
            self.counter = counter
            self.synchronizationGate = synchronizationGate
            self.preparationGate = preparationGate
        }
        func failures(reconcile: Bool = false, sync: Bool = false, delete: Bool = false) {
            failReconcile = reconcile; failSync = sync; failDelete = delete
        }
        func pullImage(_: String, platform _: String) async throws {}
        func prepare(_ record: ContainerRecord) async throws {
            events.append("prepare")
            let durable = try await store.loadRequired()
            for mount in record.mounts where mount.kind == .volume {
                #expect(durable.volumes.contains { $0.name == mount.source && $0.instanceID != nil })
            }
            await preparationGate?.pause()
        }
        func start(_ container: ContainerRecord) async throws -> [PortBinding] {
            events.append("start"); return container.ports
        }
        func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { events.append("stop"); return 0 }
        func wait(_: ContainerRecord) async throws -> Int32 { 0 }
        func cleanupExecution(_: ContainerRecord) async throws { events.append("cleanup") }
        func delete(_: ContainerRecord) async throws { events.append("delete-container") }
        func cleanupOrphans(keeping _: Set<String>) async throws { events.append("orphans") }
        func reconcileStorage(volumes: [VolumeRecord], containers _: [ContainerRecord]) async throws {
            events.append("reconcile")
            if failReconcile { throw Failure.injected }
            reconciled = volumes
            migrationSaves = await counter?.value
            if !volumes.isEmpty {
                let durable = try await store.loadRequired()
                #expect(durable.volumes.map(\.instanceID) == volumes.map(\.instanceID))
                #expect(volumes.allSatisfy { $0.instanceID != nil })
            }
        }
        func synchronizeVolumes(_ volumes: [VolumeRecord]) async throws {
            events.append("synchronize")
            let durable = try await store.loadRequired()
            #expect(durable.volumes.map(\.instanceID) == volumes.map(\.instanceID))
            await synchronizationGate?.pause()
            if failSync { throw Failure.injected }
            synchronized.append(volumes)
        }
        func deleteVolume(_: String) async throws { Issue.record("untyped volume deletion") }
        func deleteVolume(_ volume: VolumeRecord) async throws {
            events.append("delete-volume")
            let durable = try await store.loadRequired()
            #expect(durable.volumes.contains { $0.name == volume.name && $0.instanceID == volume.instanceID })
            #expect(durable.volumeRemovalIntents?.contains {
                $0.name == volume.name && $0.instanceID == volume.instanceID
            } == true)
            deleted.append(volume)
            if failDelete { throw Failure.injected }
        }
    }

    private func root() -> URL { FileManager.default.temporaryDirectory.appending(path: UUID().uuidString) }
    private func decodedVolume(_ name: String, identity: String?) throws -> VolumeRecord {
        let original = VolumeRecord(name: name, sizeBytes: 4096)
        var object = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(original)) as? [String: Any])
        object["instanceID"] = identity
        return try JSONDecoder().decode(VolumeRecord.self, from: JSONSerialization.data(withJSONObject: object))
    }
    private func container(_ name: String = "consumer") -> ContainerRecord {
        var value = ContainerRecord(name: name, image: "example")
        value.mounts = [.init(kind: .volume, source: "data", destination: "/data")]
        return value
    }

    @Test func implicitNamedVolumeSetIsDurableBeforeSynchronizationAndPrepare() async throws {
        let root = root(); defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend(root: root), runtime = try await EngineRuntime(root: root, backend: backend)
        var input = container()
        input.mounts.append(.init(kind: .volume, source: "second", destination: "/second"))
        input.mounts.append(.init(kind: .volume, source: "data", destination: "/again"))
        _ = try await runtime.createContainer(input)
        let durable = try await AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json")).loadRequired()
        #expect(Set(durable.volumes.map(\.name)) == ["data", "second"])
        #expect(Set(durable.volumes.compactMap(\.instanceID)).count == 2)
        #expect(await backend.synchronized.count == 1)
        #expect(await backend.events.firstIndex(of: "synchronize")! < backend.events.firstIndex(of: "prepare")!)
        await runtime.shutdown()
    }

    @Test func implicitVolumeSaveFailureNeverSynchronizesOrPrepares() async throws {
        let root = root(); defer { try? FileManager.default.removeItem(at: root) }
        let counter = Counter(), backend = Backend(root: root)
        let runtime = try await EngineRuntime(root: root, backend: backend, beforePersistence: {
            if await counter.value > 0 { throw Failure.injected }
        })
        await counter.increment()
        await #expect(throws: Failure.self) { _ = try await runtime.createContainer(container()) }
        #expect(await !backend.events.contains("synchronize"))
        #expect(await !backend.events.contains("prepare"))
        await runtime.shutdown()
    }

    @Test(arguments: [false, true]) func mountedGenerationCannotBeDeletedDuringPrepare(anonymous: Bool) async throws {
        let root = root(); defer { try? FileManager.default.removeItem(at: root) }
        let gate = Gate(), backend = Backend(root: root, preparationGate: gate)
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let volume = try await runtime.createVolume(name: "data", anonymous: anonymous)
        let creation = Task { try await runtime.createContainer(container(), expectedVolumeInstances: ["data": try #require(volume.instanceID)]) }
        await gate.wait()
        await #expect(throws: EngineError.self) { try await runtime.removeVolume("data", force: true) }
        #expect(await backend.deleted.isEmpty)
        await gate.resume()
        _ = try await creation.value
        #expect(await runtime.listVolumes().first?.instanceID == volume.instanceID)
        await runtime.shutdown()
    }

    @Test(arguments: [false, true]) func callerPinnedGenerationCannotAdoptRemovedOrRecreatedName(recreate: Bool) async throws {
        let root = root(); defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend(root: root), runtime = try await EngineRuntime(root: root, backend: backend)
        let volume = try await runtime.createVolume(name: "data", anonymous: true)
        try await runtime.removeVolume("data", force: true)
        if recreate { _ = try await runtime.createVolume(name: "data", anonymous: true) }
        await #expect(throws: EngineError.self) {
            _ = try await runtime.createContainer(container(), expectedVolumeInstances: ["data": try #require(volume.instanceID)])
        }
        #expect(await !backend.events.contains("prepare"))
        if !recreate { #expect(await runtime.listVolumes().isEmpty) }
        await runtime.shutdown()
    }

    @Test func missingLegacyMountedVolumeRequiresRepairBeforeBackendHooks() async throws {
        let root = root(); defer { try? FileManager.default.removeItem(at: root) }
        try await AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json")).save(.init(containers: [container()]))
        let backend = Backend(root: root)
        await #expect(throws: EngineError.self) { _ = try await EngineRuntime(root: root, backend: backend) }
        #expect(await backend.events.isEmpty)
    }

    @Test func legacyIdentitiesAreSavedTogetherBeforeFirstBackendHook() async throws {
        let root = root(); defer { try? FileManager.default.removeItem(at: root) }
        let store = AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json"))
        try await store.save(.init(volumes: [try decodedVolume("a", identity: nil), try decodedVolume("b", identity: nil)]))
        let counter = Counter(), backend = Backend(root: root, counter: counter)
        let runtime = try await EngineRuntime(root: root, backend: backend, beforePersistence: { await counter.increment() })
        #expect(await backend.migrationSaves == 1)
        #expect(await backend.events.first == "reconcile")
        let identities = await backend.reconciled.compactMap(\.instanceID)
        #expect(Set(identities).count == 2)
        #expect(try await store.loadRequired().volumes.compactMap(\.instanceID) == identities)
        await runtime.shutdown()
    }

    @Test func legacyMigrationSaveFailureNeverEntersBackend() async throws {
        let root = root(); defer { try? FileManager.default.removeItem(at: root) }
        let store = AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json"))
        try await store.save(.init(volumes: [try decodedVolume("data", identity: nil)]))
        let backend = Backend(root: root)
        await #expect(throws: Failure.self) {
            _ = try await EngineRuntime(root: root, backend: backend, beforePersistence: { throw Failure.injected })
        }
        #expect(await backend.events.isEmpty)
        #expect(try await store.loadRequired().volumes[0].instanceID == nil)
    }

    @Test func reconcileFailurePrecedesPendingDeletionCleanupAndRecovery() async throws {
        let root = root(); defer { try? FileManager.default.removeItem(at: root) }
        let volume = VolumeRecord(name: "data", sizeBytes: 4096)
        var workload = ContainerRecord(name: "workload", image: "example")
        workload.phase = .running; workload.restartPolicy.name = "always"
        let store = AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json"))
        try await store.save(.init(containers: [workload], volumes: [volume], cleanupPendingContainerIDs: [workload.id],
                                   volumeRemovalIntents: [.init(name: volume.name, instanceID: try #require(volume.instanceID))]))
        let backend = Backend(root: root); await backend.failures(reconcile: true)
        await #expect(throws: Failure.self) { _ = try await EngineRuntime(root: root, backend: backend) }
        #expect(await backend.events == ["reconcile"])
    }

    @Test(arguments: [false, true]) func invalidVolumeIdentitiesNeverReachBackend(zero: Bool) async throws {
        let root = root(); defer { try? FileManager.default.removeItem(at: root) }
        let identity = zero ? "00000000-0000-0000-0000-000000000000" : UUID().uuidString
        let volumes = try [decodedVolume("a", identity: identity), decodedVolume("b", identity: identity)]
        try await AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json")).save(.init(volumes: zero ? [volumes[0]] : volumes))
        let backend = Backend(root: root)
        await #expect(throws: EngineError.self) { _ = try await EngineRuntime(root: root, backend: backend) }
        #expect(await backend.events.isEmpty)
    }

    @Test func migrationMethodCannotReplaceExistingIdentity() throws {
        var volume = try decodedVolume("data", identity: nil)
        let migrated = volume.ensureInstanceID()
        #expect(migrated)
        let identity = volume.instanceID
        let repeated = volume.ensureInstanceID()
        #expect(!repeated)
        #expect(volume.instanceID == identity)
    }

    @Test func namedRecreationUsesNewIdentityAndTypedDeletion() async throws {
        let root = root(); defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend(root: root), runtime = try await EngineRuntime(root: root, backend: backend)
        let old = try await runtime.createVolume(name: "data")
        try await runtime.removeVolume("data", force: false)
        let replacement = try await runtime.createVolume(name: "data")
        #expect(old.instanceID != replacement.instanceID)
        #expect(await backend.deleted.map(\.instanceID) == [old.instanceID])
        #expect(await backend.synchronized.last?.first?.instanceID == replacement.instanceID)
        await runtime.shutdown()
    }

    @Test func failedSynchronizationCannotPrepareAndRetryKeepsDurableIdentity() async throws {
        let root = root(); defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend(root: root), runtime = try await EngineRuntime(root: root, backend: backend)
        await backend.failures(sync: true)
        await #expect(throws: Failure.self) { _ = try await runtime.createVolume(name: "data") }
        let durable = try await AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json")).loadRequired()
        await #expect(throws: Failure.self) { _ = try await runtime.createContainer(container()) }
        #expect(await !backend.events.contains("prepare"))
        await backend.failures()
        let retry = try await runtime.createVolume(name: "data")
        #expect(retry.instanceID == durable.volumes[0].instanceID)
        _ = try await runtime.createContainer(container())
        #expect(await backend.events.contains("prepare"))
        await runtime.shutdown()
    }

    @Test func delayedSnapshotCannotOverwriteLaterVolumePublication() async throws {
        let root = root(); defer { try? FileManager.default.removeItem(at: root) }
        let gate = Gate(), backend = Backend(root: root, synchronizationGate: gate)
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let first = Task { try await runtime.createVolume(name: "a") }
        await gate.wait()
        let second = Task { try await runtime.createVolume(name: "b") }
        await gate.resume()
        let a = try await first.value, b = try await second.value
        #expect(await backend.synchronized.map { $0.map(\.instanceID) } == [[a.instanceID], [a.instanceID, b.instanceID]])
        await runtime.shutdown()
    }

    @Test func anonymousDeletionKeepsRecoverableUnionUntilContainerCommit() async throws {
        let root = root(), crashRoot = self.root()
        defer { try? FileManager.default.removeItem(at: root); try? FileManager.default.removeItem(at: crashRoot) }
        let backend = Backend(root: root), captured = RemovalSnapshotCapture()
        let runtime = try await EngineRuntime(root: root, backend: backend, beforePersistence: {
            if await !backend.deleted.isEmpty { await captured.capture() }
        })
        await captured.attach(runtime)
        let volume = try await runtime.createVolume(name: "data", anonymous: true)
        let workload = try await runtime.createContainer(container())
        try await runtime.removeContainer(workload.id, force: true, removeVolumes: true)
        // Exactly the shared state visible to an unrelated save after remote
        // deletion, but before the atomic container-removal commit.
        let intermediate = try #require(await captured.value)
        #expect(intermediate.containers.contains { $0.id == workload.id })
        #expect(intermediate.volumes.contains { $0.name == volume.name && $0.instanceID == volume.instanceID })
        #expect(intermediate.volumeRemovalIntents?.contains { $0.instanceID == volume.instanceID } == true)
        try await AtomicStore<EngineSnapshot>(url: crashRoot.appending(path: "engine.json")).save(intermediate)
        let recovery = Backend(root: crashRoot), recovered = try await EngineRuntime(root: crashRoot, backend: recovery)
        #expect(await recovery.deleted.map(\.instanceID) == [volume.instanceID])
        #expect(await recovered.listVolumes().isEmpty)
        await recovered.shutdown(); await runtime.shutdown()
    }

    @Test func failedAnonymousCommitRestoresExactRemovalIntent() async throws {
        let root = root(); defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend(root: root)
        let runtime = try await EngineRuntime(root: root, backend: backend, beforePersistence: {
            if await backend.consumeCommitFailure() { throw Failure.injected }
        })
        let volume = try await runtime.createVolume(name: "data", anonymous: true)
        let workload = try await runtime.createContainer(container())
        await backend.armCommitFailure()
        await #expect(throws: Failure.self) { try await runtime.removeContainer(workload.id, force: true, removeVolumes: true) }
        let durable = try await AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json")).loadRequired()
        #expect(durable.volumes.first?.instanceID == volume.instanceID)
        #expect(durable.volumeRemovalIntents?.first?.instanceID == volume.instanceID)
        await runtime.shutdown()
        let recovery = Backend(root: root), recovered = try await EngineRuntime(root: root, backend: recovery)
        #expect(await recovery.deleted.map(\.instanceID) == [volume.instanceID])
        await recovered.shutdown()
    }

    @Test func anonymousDeletionPersistsExactIntentAndRestartRetriesSameGeneration() async throws {
        let root = root(); defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend(root: root), runtime = try await EngineRuntime(root: root, backend: backend)
        let volume = try await runtime.createVolume(name: "data", anonymous: true)
        let workload = try await runtime.createContainer(container())
        await backend.failures(delete: true)
        await #expect(throws: Failure.self) { try await runtime.removeContainer(workload.id, force: true, removeVolumes: true) }
        await #expect(throws: EngineError.self) { _ = try await runtime.createVolume(name: "data") }
        await runtime.shutdown()
        let recovery = Backend(root: root), recovered = try await EngineRuntime(root: root, backend: recovery)
        #expect(await recovery.events.first == "reconcile")
        #expect(await recovery.deleted.map(\.instanceID) == [volume.instanceID])
        #expect(await recovered.listVolumes().isEmpty)
        await recovered.shutdown()
    }
}

import CEngineCore
import Foundation
import Testing
@testable import CEngineRuntime

@Suite struct KillCancellationDurabilityTests {
    actor Backend: ContainerBackend {
        let root: URL
        var recovery: BackendContainerRecovery = .unavailable
        private(set) var kills = 0
        private(set) var starts = 0
        private(set) var durableAtSignal = false
        init(root: URL) { self.root = root }
        func pullImage(_: String, platform _: String) async throws {}
        func prepare(_: ContainerRecord) async throws {}
        func start(_ record: ContainerRecord) async throws -> [PortBinding] { starts += 1; return record.ports }
        func completion(_: ContainerRecord) async -> Int32? { nil }
        func kill(_ record: ContainerRecord, signal _: String) async throws {
            let saved = try await AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json")).loadRequired()
            durableAtSignal = saved.manuallyStoppedContainerInstances?[record.id] == record.instanceID
            kills += 1 // signal handler deliberately does not exit yet
        }
        func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 137 }
        func wait(_: ContainerRecord) async throws -> Int32 { 137 }
        func delete(_: ContainerRecord) async throws {}
        func cleanupExecution(_: ContainerRecord) async throws {}
        func synchronizeVolumes(_: [VolumeRecord]) async throws {}
        func recover(_: ContainerRecord) async throws -> BackendContainerRecovery { recovery }
    }
    actor PersistenceFailure {
        var armed = false
        struct Failure: Error {}
        func arm() { armed = true }
        func run() throws { if armed { throw Failure() } }
    }
    func root() -> URL { FileManager.default.temporaryDirectory.appending(path: UUID().uuidString) }
    func load(_ root: URL) async throws -> EngineSnapshot {
        try await AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json")).loadRequired()
    }

    @Test(arguments: ["unless-stopped", "always"])
    func nonKillCancellationPrecedesSignalAndSurvivesCrash(_ policy: String) async throws {
        let original = root(), recovered = root()
        defer { try? FileManager.default.removeItem(at: original); try? FileManager.default.removeItem(at: recovered) }
        let backend = Backend(root: original)
        let runtime = try await EngineRuntime(root: original, backend: backend)
        var input = ContainerRecord(name: "durable-kill", image: "fixture")
        input.restartPolicy = .init(name: policy)
        let record = try await runtime.createContainer(input)
        try await runtime.startContainer(record.id)
        try await runtime.killContainer(record.id, signal: "SIGTERM")
        #expect(await backend.durableAtSignal)
        let interrupted = try await load(original)
        #expect(interrupted.containers.first?.phase == .running)
        #expect(interrupted.manuallyStoppedContainerInstances?[record.id] == record.instanceID)
        // Restart from exactly the pre-exit checkpoint, not a graceful shutdown.
        try FileManager.default.createDirectory(at: recovered, withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: original.appending(path: "engine.json"), to: recovered.appending(path: "engine.json"))
        await runtime.shutdown()
        let nextBackend = Backend(root: recovered)
        let next = try await EngineRuntime(root: recovered, backend: nextBackend)
        let current = try await next.container(record.id)
        #expect(current.phase == (policy == "always" ? .running : .exited))
        #expect(await nextBackend.starts == (policy == "always" ? 1 : 0))
        if policy == "unless-stopped" { try await next.startContainer(record.id) }
        #expect(try await load(recovered).manuallyStoppedContainerInstances == nil)
        try await next.killContainer(record.id, signal: "SIGTERM")
        try await next.removeContainer(record.id, force: true)
        #expect(try await load(recovered).manuallyStoppedContainerInstances == nil)
        await next.shutdown()
    }

    @Test func persistenceFailureDoesNotSendSignal() async throws {
        let directory = root()
        defer { try? FileManager.default.removeItem(at: directory) }
        let hook = PersistenceFailure(), backend = Backend(root: directory)
        let runtime = try await EngineRuntime(root: directory, backend: backend, beforePersistence: { try await hook.run() })
        let record = try await runtime.createContainer(.init(name: "failed-kill", image: "fixture"))
        try await runtime.startContainer(record.id)
        await hook.arm()
        await #expect(throws: (any Error).self) { try await runtime.killContainer(record.id, signal: "SIGTERM") }
        #expect(await backend.kills == 0)
        #expect(try await load(directory).manuallyStoppedContainerInstances == nil)
        await runtime.shutdown()
    }

    @Test func oldSnapshotsRemainReadableAndForeignManualStopIsRejected() async throws {
        let decoded = try JSONDecoder().decode(EngineSnapshot.self, from: Data(#"{"containers":[],"networks":[],"volumes":[],"images":[]}"#.utf8))
        #expect(decoded.manuallyStoppedContainerInstances == nil)
        let directory = root()
        defer { try? FileManager.default.removeItem(at: directory) }
        let record = ContainerRecord(name: "identity", image: "fixture")
        let snapshot = EngineSnapshot(containers: [record], manuallyStoppedContainerInstances: [record.id: UUID()])
        try await AtomicStore<EngineSnapshot>(url: directory.appending(path: "engine.json")).save(snapshot)
        await #expect(throws: (any Error).self) { _ = try await EngineRuntime(root: directory, backend: Backend(root: directory)) }
    }
}

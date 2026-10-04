import CEngineCore
import Foundation
import Testing
@testable import CEngineRuntime

/// A manual stop reply must follow durable persistence of the exited phase even
/// when the completion monitor observed the exit first. Otherwise a daemon
/// crash right after the reply recovers the container as `running` and its
/// `unless-stopped` policy resurrects a container the user just stopped.
@Suite struct ManualStopDurabilityTests {
    typealias Gate = EngineServiceReplacementTests.Gate

    actor Flag {
        private(set) var raised = false
        func raise() { raised = true }
    }

    /// Persistence pauses exactly once after it is armed, and announces that
    /// it has entered the lane so the backend can order its stop reply after
    /// the monitor's in-flight persist.
    actor PersistenceHook {
        let gate = Gate()
        let entered = Gate()
        private var armed = false
        func arm() { armed = true }
        func run() async {
            guard armed else { return }
            armed = false
            await entered.signal()
            await gate.pause()
        }
    }

    /// The execution exits only once the manual stop arrives, and the backend
    /// stop returns only after the completion monitor has entered canonical
    /// persistence: the exact ordering that lost the exited phase.
    actor Backend: ContainerBackend {
        let exitRequested = Gate()
        let persistenceEntered: Gate
        init(persistenceEntered: Gate) { self.persistenceEntered = persistenceEntered }
        func pullImage(_: String, platform _: String) async throws {}
        func prepare(_: ContainerRecord) async throws {}
        func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
        func completion(_: ContainerRecord) async -> Int32? {
            await exitRequested.wait()
            return 137
        }
        func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 {
            await exitRequested.signal()
            await persistenceEntered.wait()
            return 137
        }
        func wait(_: ContainerRecord) async throws -> Int32 { 137 }
        func delete(_: ContainerRecord) async throws {}
        func cleanupExecution(_: ContainerRecord) async throws {}
        func synchronizeVolumes(_: [VolumeRecord]) async throws {}
        func recover(_: ContainerRecord) async throws -> BackendContainerRecovery { .unavailable }
    }

    private func durablePhase(_ root: URL, _ id: String) async throws -> ContainerPhase? {
        let snapshot = try await AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json")).loadRequired()
        return snapshot.containers.first { $0.id == id }?.phase
    }

    @Test func manualStopReplyFollowsDurableExitedPhase() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let hook = PersistenceHook()
        let backend = Backend(persistenceEntered: hook.entered)
        let runtime = try await EngineRuntime(root: root, backend: backend, beforePersistence: { await hook.run() })
        var input = ContainerRecord(name: "manual-stop", image: "fixture")
        input.restartPolicy = RestartPolicyRecord(name: "unless-stopped")
        let record = try await runtime.createContainer(input)
        try await runtime.startContainer(record.id)
        #expect(try await durablePhase(root, record.id) == .running)

        await hook.arm()
        let replied = Flag()
        let request = Task {
            try await runtime.stopContainer(record.id)
            await replied.raise()
        }
        // The monitor recorded the exit and is paused inside canonical
        // persistence; the in-memory phase is exited while the durable one is
        // still running. No reply may be sent from this window.
        await hook.gate.wait()
        try await Task.sleep(for: .milliseconds(150))
        let stopped = try await runtime.container(record.id)
        #expect(stopped.phase == .exited)
        #expect(try await durablePhase(root, record.id) == .running)
        #expect(await !replied.raised)

        await hook.gate.resume()
        try await request.value
        #expect(await replied.raised)
        #expect(try await durablePhase(root, record.id) == .exited)
        let final = try await runtime.container(record.id)
        #expect(final.phase == .exited && final.exitCode == 137)
        await runtime.shutdown()
    }
}

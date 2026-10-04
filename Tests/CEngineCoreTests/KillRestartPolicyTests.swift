import CEngineCore
import Foundation
import Testing
@testable import CEngineRuntime

/// `docker kill` with SIGKILL or the container's stop signal is a manual stop:
/// moby's `killWithSignal` calls `ExitOnNext`, so the restart policy skips the
/// coming exit and resumes only after the next start. Other signals are plain
/// deliveries and leave the policy in force.
@Suite struct KillRestartPolicyTests {
    typealias Gate = EngineServiceReplacementTests.Gate

    /// Each start creates one exit gate for the newest execution; a completion
    /// monitor waits on the newest gate at the time it asks, exactly like a real
    /// backend observing the execution that is currently running. (A monitor
    /// that is cancelled before it ever asks must not leave a signalled gate
    /// behind for the next execution, so gates are never handed out by
    /// consumption order.) `kill` signals the newest gate (the process dies);
    /// the test signals it directly for a natural exit.
    actor Backend: ContainerBackend {
        private(set) var exits: [Gate] = []
        var startCount: Int { exits.count }
        func pullImage(_: String, platform _: String) async throws {}
        func prepare(_: ContainerRecord) async throws {}
        func start(_ container: ContainerRecord) async throws -> [PortBinding] {
            exits.append(Gate())
            return container.ports
        }
        func completion(_: ContainerRecord) async -> Int32? {
            guard let gate = exits.last else { return nil }
            await gate.wait()
            return 137
        }
        func kill(_: ContainerRecord, signal _: String) async throws { await exits.last?.signal() }
        func naturalExit() async { await exits.last?.signal() }
        func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { await exits.last?.signal(); return 137 }
        func wait(_: ContainerRecord) async throws -> Int32 { 137 }
        func delete(_: ContainerRecord) async throws {}
        func cleanupExecution(_: ContainerRecord) async throws {}
        func synchronizeVolumes(_: [VolumeRecord]) async throws {}
        func recover(_: ContainerRecord) async throws -> BackendContainerRecovery { .unavailable }
    }

    private func waitForStarts(_ count: Int, on backend: Backend) async throws {
        let deadline = ContinuousClock.now + .seconds(5)
        while await backend.startCount < count {
            guard ContinuousClock.now < deadline else { throw WatchdogExpired() }
            try await Task.sleep(for: .milliseconds(10))
        }
    }
    private struct WatchdogExpired: Error {}

    /// The backend's start count advances before the runtime publishes the
    /// restarted record (phase and restart count land in a later persistence),
    /// so observations of the record itself poll until they hold.
    private func waitForRecord(_ id: String, on runtime: EngineRuntime,
                               where predicate: (ContainerRecord) -> Bool) async throws -> ContainerRecord {
        let deadline = ContinuousClock.now + .seconds(5)
        while true {
            let record = try await runtime.container(id)
            if predicate(record) { return record }
            guard ContinuousClock.now < deadline else { return record }
            try await Task.sleep(for: .milliseconds(10))
        }
    }

    @Test func signalClassificationFollowsMoby() {
        for signal in ["SIGKILL", "KILL", "kill", "9", " sigkill "] {
            #expect(EngineRuntime.killCancelsRestartPolicy(signal, stopSignal: "SIGTERM"))
        }
        #expect(EngineRuntime.killCancelsRestartPolicy("SIGTERM", stopSignal: "SIGTERM"))
        #expect(EngineRuntime.killCancelsRestartPolicy("15", stopSignal: "TERM"))
        #expect(EngineRuntime.killCancelsRestartPolicy("QUIT", stopSignal: "SIGQUIT"))
        #expect(!EngineRuntime.killCancelsRestartPolicy("HUP", stopSignal: "SIGTERM"))
        #expect(!EngineRuntime.killCancelsRestartPolicy("SIGTERM", stopSignal: "SIGQUIT"))
        #expect(!EngineRuntime.killCancelsRestartPolicy("USR1", stopSignal: "SIGTERM"))
    }

    @Test(arguments: [("SIGKILL", true), ("SIGTERM", true), ("HUP", false)])
    func killCancelsRestartPolicyUntilNextStart(signal: String, cancels: Bool) async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = Backend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        var input = ContainerRecord(name: "killed", image: "fixture")
        input.restartPolicy = RestartPolicyRecord(name: "always")
        let record = try await runtime.createContainer(input)
        try await runtime.startContainer(record.id)
        try await waitForStarts(1, on: backend)

        try await runtime.killContainer(record.id, signal: signal)
        if cancels {
            // The exit is reconciled without a policy restart, and stays that way.
            try await Task.sleep(for: .milliseconds(300))
            let killed = try await runtime.container(record.id)
            #expect(killed.phase == .exited && killed.exitCode == 137 && killed.restartCount == 0)
            #expect(await backend.startCount == 1)
            // A new start resets the cancellation: the policy restarts the next natural exit.
            try await runtime.startContainer(record.id)
            try await waitForStarts(2, on: backend)
            await backend.naturalExit()
            try await waitForStarts(3, on: backend)
            let restarted = try await waitForRecord(record.id, on: runtime) { $0.phase == .running && $0.restartCount == 1 }
            let starts = await backend.startCount
            #expect(restarted.phase == .running && restarted.restartCount == 1,
                    "signal=\(signal) phase=\(restarted.phase) count=\(restarted.restartCount) exit=\(String(describing: restarted.exitCode)) starts=\(starts)")
        } else {
            // An ordinary signal is not a manual stop: the policy restarts the exit.
            try await waitForStarts(2, on: backend)
            let restarted = try await waitForRecord(record.id, on: runtime) { $0.phase == .running && $0.restartCount == 1 }
            let starts = await backend.startCount
            #expect(restarted.phase == .running && restarted.restartCount == 1,
                    "signal=\(signal) phase=\(restarted.phase) count=\(restarted.restartCount) exit=\(String(describing: restarted.exitCode)) starts=\(starts)")
        }
        await runtime.shutdown()
    }
}

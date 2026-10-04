import CEngineCore
@testable import CEngineRuntime
import Darwin
import Foundation
import Testing

/// A buffered, single-observer milestone: readiness is signalled by the backend,
/// not inferred from how quickly the full parallel suite schedules a polling task.
private struct ExecTestSignal: Sendable {
    private let stream: AsyncStream<Void>
    private let continuation: AsyncStream<Void>.Continuation

    init() {
        let signal = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
        stream = signal.stream
        continuation = signal.continuation
    }

    func signal() {
        continuation.yield(())
        continuation.finish()
    }

    func wait() async -> Bool {
        await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                for await _ in stream { return true }
                return false
            }
            // Safety watchdog only; normal progress is driven by the signal.
            // AsyncStream iteration and sleep both terminate on cancellation,
            // so the losing child cannot keep this task group suspended.
            group.addTask {
                try? await Task.sleep(for: .seconds(10))
                return false
            }
            defer { group.cancelAll() }
            return await group.next() ?? false
        }
    }
}

/// Models an exec whose metadata RPC cannot finish until the caller activates
/// the returned output stream. No VM or pipe-capacity timing is involved.
private actor ActivationGatedExecBackend: ContainerBackend {
    private var activated = false
    private var pidWaiters: [CheckedContinuation<Void, Never>] = []
    private var completionWaiters: [CheckedContinuation<Int32?, Never>] = []
    private var terminalCode: Int32?
    nonisolated let startReturned = ExecTestSignal()
    nonisolated let waitingForPID = ExecTestSignal()
    nonisolated let waitingForStart = ExecTestSignal()
    private var retired = false
    private var startWaiter: CheckedContinuation<Void, Never>?
    private var startReleased = false
    private var returnedDescriptorPeer: CInt?
    private var pidReturned = false
    private var pidReturnWaiters: [CheckedContinuation<Void, Never>] = []
    private var monitorFinished = false
    private var monitorFinishWaiters: [CheckedContinuation<Void, Never>] = []
    private let holdStart: Bool
    private let containStartFailure: Bool

    init(holdStart: Bool = false, containStartFailure: Bool = false) {
        self.holdStart = holdStart
        self.containStartFailure = containStartFailure
    }
    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {}
    func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 137 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func cleanupExecution(_: ContainerRecord) async throws {}
    func delete(_: ContainerRecord) async throws {}
    func prepareExec(_ exec: ExecRecord, container _: ContainerRecord) async throws -> ContainerIOBridge {
        ContainerIOBridge(tty: exec.configuration.tty)
    }
    func startExec(_: ExecRecord) async throws {
        if holdStart && !startReleased {
            await withCheckedContinuation {
                startWaiter = $0
                waitingForStart.signal()
            }
        }
        if containStartFailure {
            throw BackendExecStartContainedError(
                exitCode: 137, message: "contained start failure", containerTerminated: true
            )
        }
    }
    func startAttachedExec(_: ExecRecord) async throws -> CInt? {
        if holdStart && !startReleased {
            await withCheckedContinuation {
                startWaiter = $0
                waitingForStart.signal()
            }
        }
        var descriptors = [CInt](repeating: -1, count: 2)
        guard Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        if let returnedDescriptorPeer { Darwin.close(returnedDescriptorPeer) }
        returnedDescriptorPeer = descriptors[1]
        return descriptors[0]
    }
    func execPID(_: ExecRecord) async -> Int32 {
        if !activated {
            await withCheckedContinuation {
                pidWaiters.append($0)
                waitingForPID.signal()
            }
        }
        defer {
            pidReturned = true
            let waiters = pidReturnWaiters
            pidReturnWaiters.removeAll()
            waiters.forEach { $0.resume() }
        }
        return 73
    }
    func execCompletion(_: ExecRecord) async -> Int32? {
        if let terminalCode { return terminalCode }
        return await withCheckedContinuation { completionWaiters.append($0) }
    }
    func execStatus(_: ExecRecord) async -> Int32? { terminalCode }
    func retireExec(_: ExecRecord) async {
        retired = true
        if let returnedDescriptorPeer {
            Darwin.close(returnedDescriptorPeer)
            self.returnedDescriptorPeer = nil
        }
    }
    func markReturned() { startReturned.signal() }
    func hasRetired() -> Bool { retired }
    func descriptorIsClosed() -> Bool {
        guard let returnedDescriptorPeer else { return false }
        var descriptor = pollfd(fd: returnedDescriptorPeer, events: Int16(POLLHUP), revents: 0)
        let closed = Darwin.poll(&descriptor, 1, 0) == 1
            && descriptor.revents & Int16(POLLHUP) != 0
        if closed {
            Darwin.close(returnedDescriptorPeer)
            self.returnedDescriptorPeer = nil
        }
        return closed
    }
    func waitForPIDReturn() async {
        if !pidReturned { await withCheckedContinuation { pidReturnWaiters.append($0) } }
    }
    func markMonitorFinished() {
        monitorFinished = true
        let waiters = monitorFinishWaiters
        monitorFinishWaiters.removeAll()
        waiters.forEach { $0.resume() }
    }
    func waitForMonitorFinish() async {
        if !monitorFinished { await withCheckedContinuation { monitorFinishWaiters.append($0) } }
    }
    func releaseStart() {
        // Latch release as well, so a watchdog failure cannot release too early
        // and strand a start that has not reached the backend yet.
        startReleased = true
        startWaiter?.resume()
        startWaiter = nil
    }
    func activateStream() {
        activated = true
        let waiters = pidWaiters
        pidWaiters.removeAll()
        waiters.forEach { $0.resume() }
    }
    func finish() {
        terminalCode = 23
        let waiters = completionWaiters
        completionWaiters.removeAll()
        waiters.forEach { $0.resume(returning: 23) }
    }
}

@Suite struct AttachedExecStartupTests {
    private func eventually(_ predicate: () async throws -> Bool) async rethrows -> Bool {
        // Runtime publication has no backend readiness hook. Keep its bounded
        // observation budget consistent with the signal watchdog, not a 1s benchmark.
        let deadline = ContinuousClock.now + .seconds(10)
        while ContinuousClock.now < deadline {
            if Task.isCancelled { return false }
            if try await predicate() { return true }
            try? await Task.sleep(for: .milliseconds(1))
        }
        return try await predicate()
    }

    @Test func attachedExecReturnsBeforePIDMetadataForStreamActivation() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = ActivationGatedExecBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let container = try await runtime.createContainer(ContainerRecord(name: "activation-gate", image: "debian"))
        try await runtime.startContainer(container.id)
        let exec = try await runtime.createExec(container: container.id, configuration: .init(arguments: ["true"]))
        let start = Task {
            let descriptor = try await runtime.startAttachedExec(exec.id)
            await backend.markReturned()
            return descriptor
        }
        #expect(await backend.waitingForPID.wait())
        // Old code deterministically times out here: the only release of the
        // metadata RPC is below, standing in for HTTP-upgrade activation.
        // Keep this nonfatal so the negative run still reaches that release.
        #expect(await backend.startReturned.wait())
        #expect(try await runtime.container(container.id).phase == .running)
        do {
            _ = try await runtime.startAttachedExec(exec.id)
            Issue.record("a second start bypassed the exec reservation")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }
        await backend.activateStream() // Also releases the old-code negative run.
        let descriptor = try #require(try await start.value)
        defer { Darwin.close(descriptor) }
        #expect(try await eventually { try await runtime.exec(exec.id).pid == 73 })
        let running = try await runtime.inspectExec(exec.id)
        #expect(running.running)
        #expect(running.pid == 73)
        await backend.finish()
        #expect(try await eventually { try await runtime.exec(exec.id).exitCode == 23 })
        let completed = try await runtime.inspectExec(exec.id)
        #expect(!completed.running)
        #expect(completed.pid == 73)
        #expect(await eventually { await backend.hasRetired() })
    }

    @Test func removalDuringPIDRefreshDoesNotResurrectExec() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = ActivationGatedExecBackend()
        let runtime = try await EngineRuntime(
            root: root, backend: backend,
            afterAttachedExecMonitoring: { await backend.markMonitorFinished() }
        )
        let container = try await runtime.createContainer(ContainerRecord(name: "remove-pid-gate", image: "debian"))
        try await runtime.startContainer(container.id)
        let exec = try await runtime.createExec(container: container.id, configuration: .init(arguments: ["true"]))
        let descriptor = try #require(try await runtime.startAttachedExec(exec.id))
        defer { Darwin.close(descriptor) }
        #expect(await backend.waitingForPID.wait())
        try await runtime.removeContainer(container.id, force: true)
        await backend.activateStream()
        await backend.finish()
        // Observe both the backend return and runtime consumption: a backend
        // signal alone could race the stale refresh's post-await write.
        await backend.waitForPIDReturn()
        await backend.waitForMonitorFinish()
        await #expect(throws: EngineError.self) { _ = try await runtime.exec(exec.id) }
        #expect(Darwin.fcntl(descriptor, F_GETFD) >= 0)
    }

    @Test(arguments: [true, false])
    func startRejectsReplacementNamedRemovedOwnerID(attached: Bool) async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = ActivationGatedExecBackend(holdStart: true)
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let owner = try await runtime.createContainer(ContainerRecord(name: "original-owner", image: "debian"))
        try await runtime.startContainer(owner.id)
        let exec = try await runtime.createExec(container: owner.id, configuration: .init(arguments: ["true"]))
        let start = Task<CInt?, Error> {
            if attached { return try await runtime.startAttachedExec(exec.id) }
            try await runtime.startExec(exec.id)
            return nil
        }
        #expect(await backend.waitingForStart.wait())
        try await runtime.removeContainer(owner.id, force: true)
        let replacement = try await runtime.createContainer(ContainerRecord(name: owner.id, image: "debian"))
        try await runtime.startContainer(replacement.id)
        #expect(replacement.id != owner.id)
        #expect(replacement.instanceID != owner.instanceID)
        // Public lookup deliberately resolves the old ID as the new name.
        #expect(try await runtime.container(owner.id).id == replacement.id)
        await backend.releaseStart()
        await backend.activateStream()
        var publishedDescriptor: CInt?
        defer { if let publishedDescriptor { Darwin.close(publishedDescriptor) } }
        do {
            publishedDescriptor = try await start.value
            Issue.record("exec start was published for a replacement owner")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }
        if attached {
            #expect(publishedDescriptor == nil)
            #expect(await backend.descriptorIsClosed())
        }
        await #expect(throws: EngineError.self) { _ = try await runtime.exec(exec.id) }
        #expect(try await runtime.container(replacement.id).phase == .running)
        await backend.finish()
    }

    @Test func containedStartFailureDoesNotTerminalizeReplacementOwner() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = ActivationGatedExecBackend(holdStart: true, containStartFailure: true)
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let owner = try await runtime.createContainer(ContainerRecord(name: "contained-owner", image: "debian"))
        try await runtime.startContainer(owner.id)
        let exec = try await runtime.createExec(container: owner.id, configuration: .init(arguments: ["true"]))
        let start = Task { try await runtime.startExec(exec.id) }
        #expect(await backend.waitingForStart.wait())
        try await runtime.removeContainer(owner.id, force: true)
        let replacement = try await runtime.createContainer(ContainerRecord(name: owner.id, image: "debian"))
        try await runtime.startContainer(replacement.id)
        #expect(try await runtime.container(owner.id).id == replacement.id)
        await backend.releaseStart()
        do {
            try await start.value
            Issue.record("contained backend failure was not reported")
        } catch let error as BackendExecStartContainedError {
            #expect(error.containerTerminated)
        }
        await #expect(throws: EngineError.self) { _ = try await runtime.exec(exec.id) }
        #expect(try await runtime.container(replacement.id).phase == .running)
        #expect(try await runtime.container(replacement.id).exitCode == nil)
    }

    @Test func attachedStartPreservesRestartReservationAndRejectsRemovedOwner() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = ActivationGatedExecBackend(holdStart: true)
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let container = try await runtime.createContainer(ContainerRecord(name: "remove-start-gate", image: "debian"))
        try await runtime.startContainer(container.id)
        let exec = try await runtime.createExec(container: container.id, configuration: .init(arguments: ["true"]))
        let start = Task { try await runtime.startAttachedExec(exec.id) }
        #expect(await backend.waitingForStart.wait())
        do {
            try await runtime.restartContainer(container.id, timeoutSeconds: 0)
            Issue.record("restart bypassed the in-flight exec reservation")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }
        // Force removal already wins over an in-flight start: preserve that
        // policy and require the late descriptor to be rejected, not published.
        try await runtime.removeContainer(container.id, force: true)
        await backend.releaseStart()
        await backend.activateStream()
        do {
            if let descriptor = try await start.value { Darwin.close(descriptor) }
            Issue.record("an attached descriptor was published for a removed owner")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }
        #expect(await backend.descriptorIsClosed())
        await #expect(throws: EngineError.self) { _ = try await runtime.exec(exec.id) }
    }
}

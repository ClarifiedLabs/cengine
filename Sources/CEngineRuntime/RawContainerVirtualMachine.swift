#if os(macOS)
import CEngineCore
import Dispatch
import Foundation
@preconcurrency import Virtualization

@MainActor public final class RawContainerVirtualMachine: NSObject, @preconcurrency VZVirtualMachineDelegate {
    public let identifier: String
    public let trunk: RawPacketTrunk
    public private(set) var control: GuestControlConnection?
    public private(set) var stopError: Error?

    private let machine: VZVirtualMachine
    private let retainedAttachmentHandles: [FileHandle]
    private let maximumMemoryBytes: UInt64
    private var memoryPressureSource: (any DispatchSourceMemoryPressure)?
    private var memoryPressureState = MemoryBalloonPressureState()
    private lazy var timeSynchronizer = GuestTimeSynchronizer(
        synchronize: { [weak self] in
            guard let self else { throw CancellationError() }
            try await self.synchronizeTime()
        },
        failureHandler: { [weak self] error in
            self?.logTimeSynchronization(
                "periodic synchronization failed; retrying: \(error.localizedDescription)"
            )
        }
    )

    public init(configuration: RawVirtualMachineConfiguration) throws {
        identifier = configuration.id
        trunk = try RawPacketTrunk()
        let value = RawVirtualMachineConfiguration(
            id: configuration.id,
            kernel: configuration.kernel,
            initialRamdisk: configuration.initialRamdisk,
            rootDisk: configuration.rootDisk,
            rootDiskReadOnly: configuration.rootDiskReadOnly,
            additionalDisks: configuration.additionalDisks,
            cpus: configuration.cpus,
            memoryBytes: configuration.memoryBytes,
            networkFileHandle: trunk.virtualMachineFileHandle,
            macAddress: configuration.macAddress,
            bindShares: configuration.bindShares,
            retainedAttachmentHandles: configuration.retainedAttachmentHandles,
            kernelArguments: configuration.kernelArguments
        )
        let virtualizationConfiguration = try value.makeVirtualizationConfiguration()
        maximumMemoryBytes = virtualizationConfiguration.memorySize
        retainedAttachmentHandles = configuration.retainedAttachmentHandles
        machine = VZVirtualMachine(configuration: virtualizationConfiguration)
        super.init()
        machine.delegate = self
    }

    public func start() async throws {
        try await machine.start()
        let guest = try await GuestTimeSynchronizationTransaction.start {
            let guest = try await self.awaitGuestControl()
            try await self.timeSynchronizer.synchronizeNow()
            return guest
        } teardown: {
            await self.timeSynchronizer.stop()
            self.control = nil
            if self.machine.canStop {
                try await self.machine.stop()
            }
        }
        control = guest
        timeSynchronizer.startPeriodic()
        startMemoryPressureMonitoring()
    }

    private func awaitGuestControl() async throws -> GuestControlConnection {
        var lastError: Error?
        for attempt in 0..<100 {
            var connection: VZVirtioSocketConnection?
            do {
                let deadline = DispatchTime.now().uptimeNanoseconds &+ 100_000_000
                let value = try await connect(
                    toPort: GuestProtocol.controlPort, timeout: .milliseconds(100)
                )
                connection = value
                let guest = GuestControlConnection(
                    connection: SendableVirtioSocketConnection(value)
                )
                try await guest.ping(deadlineNanoseconds: deadline)
                return guest
            } catch {
                connection?.close()
                lastError = error
                try await Task.sleep(for: .milliseconds(min(25 * (attempt + 1), 250)))
            }
        }
        throw lastError ?? EngineError(.internalError, "guest control service did not become ready")
    }

    private func synchronizeTime() async throws {
        let deadline = DispatchTime.now().uptimeNanoseconds &+ 1_000_000_000
        let connection = try await connect(
            toPort: GuestProtocol.controlPort, timeout: .seconds(1)
        )
        defer { connection.close() }
        let guest = GuestControlConnection(
            connection: SendableVirtioSocketConnection(connection)
        )
        try await guest.synchronizeTime(deadlineNanoseconds: deadline)
    }

    public func startInfrastructure(servicePort: UInt32) async throws {
        try await machine.start()
        var lastError: Error?
        for attempt in 0..<100 {
            do {
                let connection = try await connect(toPort: servicePort, timeout: .milliseconds(100))
                connection.close()
                return
            } catch {
                lastError = error
                try await Task.sleep(for: .milliseconds(min(25 * (attempt + 1), 250)))
            }
        }
        try? await machine.stop()
        throw lastError ?? EngineError(.internalError, "infrastructure guest service did not become ready")
    }

    public func connect(toPort port: UInt32, timeout: Duration = .seconds(5)) async throws -> VZVirtioSocketConnection {
        guard let socket = machine.socketDevices.first as? VZVirtioSocketDevice else {
            throw EngineError(.internalError, "VM has no virtio socket device")
        }
        let connection = try await Self.awaitConnection(timeout: timeout) { completion in
            socket.__connect(toPort: port) { connection, error in
                completion(connection, error)
            }
        }
        return connection.connection
    }

    static func awaitConnection(
        timeout: Duration,
        start: (@escaping @MainActor (VZVirtioSocketConnection?, Error?) -> Void) -> Void
    ) async throws -> SendableVirtioSocketConnection {
        try await awaitBoundedResult(
            timeout: timeout,
            start: { completion in
                start { connection, error in
                    if let connection {
                        completion(.success(SendableVirtioSocketConnection(connection)))
                    } else {
                        completion(.failure(error ?? EngineError(
                            .internalError, "virtio socket connection failed"
                        )))
                    }
                }
            },
            disposeLateSuccess: { $0.connection.close() }
        )
    }

    static func awaitBoundedResult<Value: Sendable>(
        timeout: Duration,
        start: (@escaping @MainActor (Result<Value, Error>) -> Void) -> Void,
        disposeLateSuccess: @escaping @MainActor (Value) -> Void = { _ in }
    ) async throws -> Value {
        try await withCheckedThrowingContinuation { continuation in
            let attempt = BoundedAsyncAttempt(
                continuation: continuation,
                disposeLateSuccess: disposeLateSuccess
            )
            start { attempt.resolve($0) }
            Task { @MainActor in
                try? await Task.sleep(for: timeout)
                attempt.resolve(.failure(EngineError(.internalError, "virtio socket connection timed out")))
            }
        }
    }

    public func install(listener: VZVirtioSocketListener, port: UInt32) throws {
        guard let socket = machine.socketDevices.first as? VZVirtioSocketDevice else {
            throw EngineError(.internalError, "VM has no virtio socket device")
        }
        socket.setSocketListener(listener, forPort: port)
    }

    public func pause() async throws {
        guard machine.canPause else { throw EngineError(.conflict, "container VM cannot be paused") }
        await timeSynchronizer.stop()
        do {
            try await machine.pause()
        } catch {
            if machine.state == .running {
                timeSynchronizer.startPeriodic()
            }
            throw error
        }
    }

    public func resume() async throws {
        guard machine.canResume else { throw EngineError(.conflict, "container VM cannot be resumed") }
        try await machine.resume()
        try await GuestTimeSynchronizationTransaction.resume {
            try await self.timeSynchronizer.synchronizeNow()
        } repause: {
            guard self.machine.canPause else {
                throw EngineError(.conflict, "resumed container VM cannot be re-paused")
            }
            try await self.machine.pause()
        } contain: {
            try await self.forceStop()
        }
        timeSynchronizer.startPeriodic()
    }

    public func forceStop() async throws {
        await timeSynchronizer.stop()
        stopMemoryPressureMonitoring()
        control = nil
        guard machine.canStop else { return }
        try await machine.stop()
    }

    public func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        timeSynchronizer.cancel()
        stopMemoryPressureMonitoring()
        control = nil
    }

    public func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: any Error) {
        stopError = error
        timeSynchronizer.cancel()
        stopMemoryPressureMonitoring()
        control = nil
    }

    private func startMemoryPressureMonitoring() {
        guard memoryPressureSource == nil else { return }
        let source = DispatchSource.makeMemoryPressureSource(
            eventMask: [.normal, .warning, .critical],
            queue: .main
        )
        source.setEventHandler { [weak self, weak source] in
            guard let self, let event = source?.data else { return }
            Task { @MainActor in
                await self.handleMemoryPressure(event)
            }
        }
        memoryPressureSource = source
        source.resume()
    }

    private func stopMemoryPressureMonitoring() {
        memoryPressureSource?.cancel()
        memoryPressureSource = nil
        memoryPressureState = MemoryBalloonPressureState()
    }

    private func handleMemoryPressure(_ event: DispatchSource.MemoryPressureEvent) async {
        let constrained = event.contains(.warning) || event.contains(.critical)
        guard constrained || event.contains(.normal) else { return }
        let level = event.contains(.critical) ? "critical" : (event.contains(.warning) ? "warning" : "normal")
        let action = memoryPressureState.transition(toConstrained: constrained)
        guard action != .none else { return }
        guard let balloon = machine.memoryBalloonDevices.first as? VZVirtioTraditionalMemoryBalloonDevice else {
            logMemoryBalloon("pressure=\(level) ignored: VM has no memory balloon device")
            return
        }

        switch action {
        case .none:
            return
        case .restore:
            balloon.targetVirtualMachineMemorySize = maximumMemoryBytes
            logMemoryBalloon("pressure=normal target=\(maximumMemoryBytes) maximum=\(maximumMemoryBytes)")
        case let .reclaim(generation):
            guard machine.state == .running, let control else {
                logMemoryBalloon("pressure=\(level) reclaim skipped: guest is not running")
                return
            }
            do {
                struct Empty: Codable {}
                let status: GuestProtocol.MemoryStatus = try await control.request(
                    operation: "prepare-memory-reclaim",
                    payload: Empty(),
                    response: GuestProtocol.MemoryStatus.self
                )
                guard memoryPressureState.isCurrent(generation: generation, constrained: true) else { return }
                let maximum = maximumMemoryBytes
                let available = min(status.availableBytes, status.totalBytes)
                let target = MemoryBalloonPolicy.targetBytes(
                    maximumBytes: maximum,
                    availableBytes: available,
                    minimumBytes: VZVirtualMachineConfiguration.minimumAllowedMemorySize
                )
                balloon.targetVirtualMachineMemorySize = target
                logMemoryBalloon(
                    "pressure=\(level) total=\(status.totalBytes) available=\(available) reclaimed=\(maximum - target) target=\(target) maximum=\(maximum)"
                )
            } catch {
                guard memoryPressureState.isCurrent(generation: generation, constrained: true) else { return }
                logMemoryBalloon("pressure=\(level) reclaim failed open: \(error.localizedDescription)")
            }
        }
    }

    private func logMemoryBalloon(_ message: String) {
        FileHandle.standardError.write(Data("vm \(identifier) memory balloon: \(message)\n".utf8))
    }

    private func logTimeSynchronization(_ message: String) {
        FileHandle.standardError.write(
            Data("vm \(identifier) time synchronization: \(message)\n".utf8)
        )
    }
}

@MainActor private final class BoundedAsyncAttempt<Value: Sendable> {
    private var continuation: CheckedContinuation<Value, Error>?
    private let disposeLateSuccess: @MainActor (Value) -> Void

    init(
        continuation: CheckedContinuation<Value, Error>,
        disposeLateSuccess: @escaping @MainActor (Value) -> Void
    ) {
        self.continuation = continuation
        self.disposeLateSuccess = disposeLateSuccess
    }

    func resolve(_ result: Result<Value, Error>) {
        let pending = continuation
        continuation = nil
        if let pending {
            pending.resume(with: result)
        } else if case let .success(value) = result {
            disposeLateSuccess(value)
        }
    }
}
#endif

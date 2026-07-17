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
    private let maximumMemoryBytes: UInt64
    private var memoryPressureSource: (any DispatchSourceMemoryPressure)?
    private var memoryPressureState = MemoryBalloonPressureState()

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
            kernelArguments: configuration.kernelArguments
        )
        let virtualizationConfiguration = try value.makeVirtualizationConfiguration()
        maximumMemoryBytes = virtualizationConfiguration.memorySize
        machine = VZVirtualMachine(configuration: virtualizationConfiguration)
        super.init()
        machine.delegate = self
    }

    public func start() async throws {
        try await machine.start()
        var lastError: Error?
        for attempt in 0..<100 {
            do {
                let connection = try await connect(toPort: GuestProtocol.controlPort, timeout: .milliseconds(100))
                let guest = GuestControlConnection(connection: SendableVirtioSocketConnection(connection))
                try await guest.ping()
                control = guest
                startMemoryPressureMonitoring()
                return
            } catch {
                lastError = error
                try await Task.sleep(for: .milliseconds(min(25 * (attempt + 1), 250)))
            }
        }
        try? await machine.stop()
        throw lastError ?? EngineError(.internalError, "guest control service did not become ready")
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
        try await withCheckedThrowingContinuation { continuation in
            let attempt = VirtioSocketConnectionAttempt(continuation: continuation)
            start { connection, error in
                if let connection {
                    attempt.resolve(.success(SendableVirtioSocketConnection(connection)))
                } else {
                    attempt.resolve(.failure(error ?? EngineError(.internalError, "virtio socket connection failed")))
                }
            }
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
        try await machine.pause()
    }

    public func resume() async throws {
        guard machine.canResume else { throw EngineError(.conflict, "container VM cannot be resumed") }
        try await machine.resume()
    }

    public func forceStop() async throws {
        stopMemoryPressureMonitoring()
        control = nil
        guard machine.canStop else { return }
        try await machine.stop()
    }

    public func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        stopMemoryPressureMonitoring()
        control = nil
    }

    public func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: any Error) {
        stopError = error
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
}

@MainActor private final class VirtioSocketConnectionAttempt {
    private var continuation: CheckedContinuation<SendableVirtioSocketConnection, Error>?

    init(continuation: CheckedContinuation<SendableVirtioSocketConnection, Error>) {
        self.continuation = continuation
    }

    func resolve(_ result: Result<SendableVirtioSocketConnection, Error>) {
        let pending = continuation
        continuation = nil
        pending?.resume(with: result)
    }
}
#endif

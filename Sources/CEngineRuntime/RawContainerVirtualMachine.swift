#if os(macOS)
import CEngineCore
import Foundation
@preconcurrency import Virtualization

@MainActor public final class RawContainerVirtualMachine: NSObject, @preconcurrency VZVirtualMachineDelegate {
    public let identifier: String
    public let trunk: RawPacketTrunk
    public private(set) var control: GuestControlConnection?
    public private(set) var stopError: Error?

    private let machine: VZVirtualMachine

    public init(configuration: RawVirtualMachineConfiguration) throws {
        identifier = configuration.id
        trunk = try RawPacketTrunk()
        let value = RawVirtualMachineConfiguration(
            id: configuration.id,
            kernel: configuration.kernel,
            initialRamdisk: configuration.initialRamdisk,
            rootDisk: configuration.rootDisk,
            rootDiskReadOnly: configuration.rootDiskReadOnly,
            cpus: configuration.cpus,
            memoryBytes: configuration.memoryBytes,
            networkFileHandle: trunk.virtualMachineFileHandle,
            macAddress: configuration.macAddress,
            bindShares: configuration.bindShares,
            kernelArguments: configuration.kernelArguments
        )
        machine = VZVirtualMachine(configuration: try value.makeVirtualizationConfiguration())
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
        control = nil
        guard machine.canStop else { return }
        try await machine.stop()
    }

    public func guestDidStop(_ virtualMachine: VZVirtualMachine) {}

    public func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: any Error) {
        stopError = error
        control = nil
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

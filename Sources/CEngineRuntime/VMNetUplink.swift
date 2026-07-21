#if os(macOS)
import CEngineCore
import Darwin
import Foundation
@preconcurrency import XPC

final class VMNetUplink: @unchecked Sendable {
    private static let timeoutQueue = DispatchQueue(
        label: "com.cengine.vmnet-uplink-timeout",
        qos: .userInitiated
    )

    let fabricFileHandle: FileHandle

    private let networkID: String
    private let connection: xpc_connection_t
    private let events: VMNetUplinkEvents
    private let lock = NSLock()
    private var stopped = false

    static func start(
        network: VMShimClient.FabricNetwork,
        namespace: String
    ) async throws -> VMNetUplink {
        let request = PrivilegedVMNetRequest(
            namespace: namespace,
            id: network.id,
            vlan: network.vlan,
            subnet: network.subnet,
            gateway: network.gateway,
            ipv6Subnet: network.ipv6Subnet,
            internalNetwork: network.internalNetwork,
            dhcpEnabled: false,
            ports: network.ports.map {
                .init(
                    proto: $0.proto,
                    externalPort: $0.externalPort,
                    internalAddress: $0.internalAddress,
                    internalPort: $0.internalPort
                )
            }
        )
        let serviceName = PrivilegedPortProtocol.serviceName
        let teamIdentifier = Bundle.main.object(forInfoDictionaryKey: "CEngineTeamIdentifier") as? String ?? ""
        let transport = try await requestUplink(
            request,
            serviceName: serviceName,
            teamIdentifier: teamIdentifier
        )
        return VMNetUplink(
            networkID: request.resourceID,
            descriptor: transport.descriptor,
            connection: transport.connection,
            events: transport.events
        )
    }

    private init(
        networkID: String,
        descriptor: CInt,
        connection: xpc_connection_t,
        events: VMNetUplinkEvents
    ) {
        self.networkID = networkID
        self.connection = connection
        self.events = events
        fabricFileHandle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    }

    func setDisconnectHandler(_ handler: @escaping @Sendable () -> Void) {
        events.setDisconnectHandler(handler)
    }

    func stop() async {
        guard lock.withLock({
            if stopped { return false }
            stopped = true
            return true
        }) else { return }
        events.cancel()
        try? fabricFileHandle.close()

        let message = xpc_dictionary_create(nil, nil, 0)
        Self.configure(message)
        xpc_dictionary_set_string(message, "operation", "stop-vmnet")
        // The opaque resource ID includes the engine-root namespace and cannot
        // collide with an identically named Docker network in another daemon.
        networkID.withCString { xpc_dictionary_set_string(message, "network-id", $0) }
        await withCheckedContinuation { continuation in
            xpc_connection_send_message_with_reply(connection, message, nil) { _ in
                xpc_connection_cancel(self.connection)
                continuation.resume()
            }
        }
    }

    private static func requestUplink(
        _ request: PrivilegedVMNetRequest,
        serviceName: String,
        teamIdentifier: String
    ) async throws -> VMNetUplinkTransport {
        let encoded = try JSONEncoder().encode(request)
        return try await awaitUplinkReply(timeout: .seconds(5)) { reply in
            let connection = xpc_connection_create_mach_service(serviceName, nil, 0)
            let events = VMNetUplinkEvents()
            reply.attach(connection)
            let requirement = signingRequirement(
                identifier: PrivilegedPortProtocol.helperIdentifier,
                teamIdentifier: teamIdentifier
            )
            let status = requirement.withCString {
                xpc_connection_set_peer_code_signing_requirement(connection, $0)
            }
            guard status == 0 else {
                reply.finish(.failure(EngineError(
                    .internalError, "could not secure privileged networking helper connection (status \(status))"
                )))
                return
            }
            xpc_connection_set_event_handler(connection) { event in
                if xpc_get_type(event) == XPC_TYPE_ERROR { events.disconnect() }
            }
            xpc_connection_activate(connection)
            let message = xpc_dictionary_create(nil, nil, 0)
            configure(message)
            xpc_dictionary_set_string(message, "operation", "start-vmnet")
            encoded.withUnsafeBytes { bytes in
                xpc_dictionary_set_data(message, "request", bytes.baseAddress, bytes.count)
            }
            xpc_connection_send_message_with_reply(connection, message, nil) { response in
                guard xpc_get_type(response) == XPC_TYPE_DICTIONARY else {
                    reply.finish(.failure(EngineError(
                        .unsupported,
                        "privileged networking helper is unavailable; enable Networking in the cengine app"
                    )))
                    return
                }
                guard xpc_dictionary_get_bool(response, "ok") else {
                    let message = xpc_dictionary_get_string(response, "error").map(String.init(cString:))
                        ?? "privileged networking helper rejected vmnet startup"
                    reply.finish(.failure(EngineError(.internalError, message)))
                    return
                }
                let descriptor = xpc_dictionary_dup_fd(response, "packet-socket")
                guard descriptor >= 0 else {
                    reply.finish(.failure(EngineError(.internalError, "privileged networking helper returned no packet socket")))
                    return
                }
                var socketType: CInt = 0
                var length = socklen_t(MemoryLayout<CInt>.size)
                guard getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &socketType, &length) == 0,
                      socketType == CInt(SOCK_DGRAM) else {
                    close(descriptor)
                    reply.finish(.failure(EngineError(.internalError, "privileged networking helper returned an invalid packet socket")))
                    return
                }
                reply.finish(.success(.init(
                    descriptor: descriptor,
                    connection: connection,
                    events: events
                )))
            }
        }
    }

    static func awaitUplinkReply(
        timeout: Duration,
        completionHook: (@Sendable () -> Void)? = nil,
        connectionCancellation: @escaping @Sendable (xpc_connection_t) -> Void = {
            xpc_connection_cancel($0)
        },
        start: @escaping @Sendable (VMNetUplinkReply) -> Void
    ) async throws -> VMNetUplinkTransport {
        let reply = VMNetUplinkReply(
            completionHook: completionHook,
            connectionCancellation: connectionCancellation
        )
        return try await withTaskCancellationHandler {
            if Task.isCancelled {
                reply.finish(.failure(CancellationError()))
            }
            return try await withCheckedThrowingContinuation { continuation in
                let shouldStart = reply.install(
                    continuation: continuation,
                    timeout: timeout,
                    timeoutQueue: timeoutQueue
                )
                if shouldStart {
                    start(reply)
                }
            }
        } onCancel: {
            reply.finish(.failure(CancellationError()))
        }
    }

    private static func signingRequirement(identifier: String, teamIdentifier: String) -> String {
        guard !teamIdentifier.isEmpty else { return "identifier \"\(identifier)\"" }
        return "anchor apple generic and identifier \"\(identifier)\" and certificate leaf[subject.OU] = \"\(teamIdentifier)\""
    }

    private static func configure(_ message: xpc_object_t) {
        xpc_dictionary_set_int64(message, "version", PrivilegedPortProtocol.version)
        if let token = PrivilegedPortProtocol.authenticationToken() {
            token.withCString { xpc_dictionary_set_string(message, "authentication-token", $0) }
        }
    }

    static func tag(_ frame: Data, vlan: UInt16) -> Data {
        guard frame.count >= 14 else { return frame }
        var output = Data(frame.prefix(12))
        output.append(contentsOf: [0x81, 0x00, UInt8((vlan >> 8) & 0x0f), UInt8(vlan & 0xff)])
        output.append(frame.dropFirst(12))
        return output
    }

    static func untag(_ frame: Data, vlan: UInt16) -> Data? {
        guard frame.count >= 18, frame[12] == 0x81, frame[13] == 0x00 else { return nil }
        let value = (UInt16(frame[14] & 0x0f) << 8) | UInt16(frame[15])
        guard value == vlan else { return nil }
        var output = Data(frame.prefix(12))
        output.append(frame.dropFirst(16))
        return output
    }
}

struct VMNetUplinkTransport: @unchecked Sendable {
    let descriptor: CInt
    let connection: xpc_connection_t
    let events: VMNetUplinkEvents
}

final class VMNetUplinkEvents: @unchecked Sendable {
    private let lock = NSLock()
    private var disconnectHandler: (@Sendable () -> Void)?
    private var isDisconnected = false
    private var didDeliverDisconnect = false
    private var isCancelled = false

    func setDisconnectHandler(_ handler: @escaping @Sendable () -> Void) {
        let notify = lock.withLock { () -> Bool in
            guard !isCancelled, !didDeliverDisconnect else { return false }
            if isDisconnected {
                didDeliverDisconnect = true
                return true
            }
            disconnectHandler = handler
            return false
        }
        if notify { handler() }
    }

    func disconnect() {
        let handler = lock.withLock { () -> (@Sendable () -> Void)? in
            guard !isCancelled, !isDisconnected, !didDeliverDisconnect else { return nil }
            isDisconnected = true
            guard let disconnectHandler else { return nil }
            didDeliverDisconnect = true
            self.disconnectHandler = nil
            return disconnectHandler
        }
        handler?()
    }

    func cancel() {
        lock.withLock {
            isCancelled = true
            disconnectHandler = nil
        }
    }
}

final class VMNetUplinkReply: @unchecked Sendable {
    private let lock = NSLock()
    private let connectionCancellation: @Sendable (xpc_connection_t) -> Void
    private var completionHook: (@Sendable () -> Void)?
    private var continuation: CheckedContinuation<VMNetUplinkTransport, Error>?
    private var pendingResult: Result<VMNetUplinkTransport, Error>?
    private var connection: xpc_connection_t?
    private var cancelledConnection: xpc_connection_t?
    private var timeoutTimer: DispatchSourceTimer?
    private var isFinished = false

    init(
        completionHook: (@Sendable () -> Void)? = nil,
        connectionCancellation: @escaping @Sendable (xpc_connection_t) -> Void = {
            xpc_connection_cancel($0)
        }
    ) {
        self.completionHook = completionHook
        self.connectionCancellation = connectionCancellation
    }

    func install(
        continuation: CheckedContinuation<VMNetUplinkTransport, Error>,
        timeout: Duration,
        timeoutQueue: DispatchQueue
    ) -> Bool {
        lock.lock()
        if isFinished {
            let result = pendingResult
            pendingResult = nil
            lock.unlock()
            guard let result else {
                preconditionFailure("VMNet uplink reply installed more than once")
            }
            continuation.resume(with: result)
            return false
        }

        self.continuation = continuation
        let timer = DispatchSource.makeTimerSource(queue: timeoutQueue)
        let components = timeout.components
        let delay = max(
            0,
            Double(components.seconds) + Double(components.attoseconds) / 1_000_000_000_000_000_000
        )
        timer.schedule(deadline: .now() + delay)
        timer.setEventHandler {
            self.finish(.failure(EngineError(
                .unsupported,
                "timed out waiting for privileged networking helper; enable Networking in the cengine app"
            )))
        }
        timeoutTimer = timer
        timer.activate()
        lock.unlock()
        return true
    }

    func attach(_ connection: xpc_connection_t) {
        lock.lock()
        if isFinished {
            let shouldCancel = cancelledConnection !== connection
            if shouldCancel {
                cancelledConnection = connection
            }
            lock.unlock()
            if shouldCancel {
                connectionCancellation(connection)
            }
            return
        }
        self.connection = connection
        lock.unlock()
    }

    func finish(_ result: Result<VMNetUplinkTransport, Error>) {
        lock.lock()
        guard !isFinished else {
            lock.unlock()
            discard(result)
            return
        }
        isFinished = true
        let continuation = self.continuation
        self.continuation = nil
        if continuation == nil {
            pendingResult = result
        }
        let connection = self.connection
        self.connection = nil
        if case .failure = result {
            cancelledConnection = connection
        }
        let timeoutTimer = self.timeoutTimer
        self.timeoutTimer = nil
        let completionHook = self.completionHook
        self.completionHook = nil
        lock.unlock()

        timeoutTimer?.cancel()
        if case .failure = result, let connection {
            connectionCancellation(connection)
        }
        completionHook?()
        continuation?.resume(with: result)
    }

    private func discard(_ result: Result<VMNetUplinkTransport, Error>) {
        guard case let .success(transport) = result else { return }
        let shouldCancel = lock.withLock { () -> Bool in
            guard cancelledConnection === transport.connection else { return true }
            cancelledConnection = nil
            return false
        }
        transport.events.cancel()
        close(transport.descriptor)
        if shouldCancel {
            connectionCancellation(transport.connection)
        }
    }
}
#endif

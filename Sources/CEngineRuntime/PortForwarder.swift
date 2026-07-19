#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import NIOCore
import NIOPosix

typealias PortStreamConnector = @Sendable (PortBinding) async throws -> CInt

final class PortForwarder: @unchecked Sendable {
    struct Registration: Hashable, Sendable {
        fileprivate let id = UUID()
    }

    private struct RegistrationState {
        var channels: [ObjectIdentifier: Channel] = [:]
    }

    private let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private let privilegedPorts = PrivilegedPortClient()
    private let lock = NSLock()
    private var registrations: [String: [Registration: RegistrationState]] = [:]

    func start(
        containerID: String,
        registration: Registration = Registration(),
        bindings: [PortBinding],
        connect: @escaping PortStreamConnector
    ) async throws -> [PortBinding] {
        guard begin(containerID: containerID, registration: registration) else {
            throw EngineError(.conflict, "port forwarding registration is already active")
        }
        var resolved: [PortBinding] = []
        do {
            for binding in bindings {
                if binding.proto.lowercased() == "udp" {
                    let bootstrap = DatagramBootstrap(group: group)
                        .channelInitializer { channel in
                            channel.pipeline.addHandler(UDPInboundHandler(
                                binding: binding,
                                listener: channel,
                                connect: connect
                            ))
                        }
                    let channel: Channel
                    do {
                        channel = try await bootstrap
                            .bind(host: binding.hostIP.isEmpty ? "0.0.0.0" : binding.hostIP, port: Int(binding.hostPort)).get()
                    } catch let error as IOError {
                        channel = try await helperBoundChannel(binding: binding, transport: .udp, ioError: error) {
                            try await bootstrap.withBoundSocket($0).get()
                        }
                    }
                    guard track(
                        channel, containerID: containerID, registration: registration
                    ) else {
                        channel.close(promise: nil)
                        throw EngineError(.conflict, "port forwarding registration stopped while binding")
                    }
                    var value = binding
                    value.hostPort = UInt16(channel.localAddress?.port ?? Int(binding.hostPort))
                    resolved.append(value)
                    continue
                }
                guard binding.proto.lowercased() == "tcp" else { throw EngineError(.unsupported, "unsupported port protocol \(binding.proto)") }
                let bootstrap = ServerBootstrap(group: group)
                    .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
                    .childChannelOption(ChannelOptions.autoRead, value: false)
                    .childChannelInitializer { [weak self, group] inbound in
                        guard let self,
                              self.track(
                                inbound, containerID: containerID, registration: registration
                              ) else {
                            inbound.close(promise: nil)
                            return inbound.eventLoop.makeFailedFuture(
                                EngineError(.conflict, "port forwarding registration stopped")
                            )
                        }
                        let lifecycle = PortForwardChannelLifecycleHandler { [weak self, weak inbound] in
                            guard let self, let inbound else { return }
                            self.untrack(
                                inbound, containerID: containerID, registration: registration
                            )
                        }
                        return inbound.pipeline.addHandler(lifecycle).flatMap {
                            inbound.eventLoop.makeFutureWithTask {
                                let descriptor = try await connect(binding)
                                let outbound = try await ClientBootstrap(group: group)
                                    .channelOption(ChannelOptions.autoRead, value: false)
                                    .withConnectedSocket(descriptor).get()
                                do {
                                    guard self.track(
                                        outbound,
                                        containerID: containerID,
                                        registration: registration
                                    ) else {
                                        outbound.close(promise: nil)
                                        throw EngineError(
                                            .conflict, "port forwarding registration stopped"
                                        )
                                    }
                                    let outboundLifecycle = PortForwardChannelLifecycleHandler {
                                        [weak self, weak outbound] in
                                        guard let self, let outbound else { return }
                                        self.untrack(
                                            outbound,
                                            containerID: containerID,
                                            registration: registration
                                        )
                                    }
                                    try await outbound.pipeline.addHandler(outboundLifecycle).get()
                                    guard outbound.isActive,
                                          self.contains(
                                            outbound,
                                            containerID: containerID,
                                            registration: registration
                                          ) else {
                                        self.untrack(
                                            outbound,
                                            containerID: containerID,
                                            registration: registration
                                        )
                                        outbound.close(promise: nil)
                                        throw EngineError(
                                            .conflict, "port forwarding connection closed"
                                        )
                                    }
                                    _ = try await inbound.pipeline.addHandler(RelayHandler(peer: outbound)).and(
                                        outbound.pipeline.addHandler(RelayHandler(peer: inbound))
                                    ).get()
                                    guard self.contains(
                                            inbound,
                                            containerID: containerID,
                                            registration: registration
                                          ),
                                          self.contains(
                                            outbound,
                                            containerID: containerID,
                                            registration: registration
                                          ) else {
                                        inbound.close(promise: nil)
                                        outbound.close(promise: nil)
                                        throw EngineError(
                                            .conflict, "port forwarding registration stopped"
                                        )
                                    }
                                    try await inbound.setOption(ChannelOptions.autoRead, value: true).get()
                                    try await outbound.setOption(ChannelOptions.autoRead, value: true).get()
                                } catch {
                                    self.untrack(
                                        outbound,
                                        containerID: containerID,
                                        registration: registration
                                    )
                                    outbound.close(promise: nil)
                                    throw error
                                }
                            }
                        }.flatMapError { error in
                            inbound.close(promise: nil)
                            self.untrack(
                                inbound, containerID: containerID, registration: registration
                            )
                            return inbound.eventLoop.makeFailedFuture(error)
                        }
                    }
                let channel: Channel
                do {
                    channel = try await bootstrap.bind(
                        host: binding.hostIP.isEmpty ? "0.0.0.0" : binding.hostIP,
                        port: Int(binding.hostPort)
                    ).get()
                } catch let error as IOError {
                    channel = try await helperBoundChannel(binding: binding, transport: .tcp, ioError: error) {
                        try await bootstrap.withBoundSocket($0).get()
                    }
                }
                guard track(
                    channel, containerID: containerID, registration: registration
                ) else {
                    channel.close(promise: nil)
                    throw EngineError(.conflict, "port forwarding registration stopped while binding")
                }
                var value = binding
                value.hostPort = UInt16(channel.localAddress?.port ?? Int(binding.hostPort))
                resolved.append(value)
            }
            guard contains(containerID: containerID, registration: registration) else {
                throw EngineError(.conflict, "port forwarding registration stopped while starting")
            }
            return resolved
        } catch {
            stop(containerID: containerID, registration: registration)
            throw error
        }
    }

    private func begin(containerID: String, registration: Registration) -> Bool {
        lock.withLock {
            guard registrations[containerID]?[registration] == nil else { return false }
            registrations[containerID, default: [:]][registration] = RegistrationState()
            return true
        }
    }

    private func contains(containerID: String, registration: Registration) -> Bool {
        lock.withLock { registrations[containerID]?[registration] != nil }
    }

    private func contains(
        _ channel: Channel,
        containerID: String,
        registration: Registration
    ) -> Bool {
        lock.withLock {
            registrations[containerID]?[registration]?
                .channels[ObjectIdentifier(channel)] != nil
        }
    }

    private func track(
        _ channel: Channel,
        containerID: String,
        registration: Registration
    ) -> Bool {
        lock.withLock {
            guard registrations[containerID]?[registration] != nil else { return false }
            registrations[containerID]?[registration]?.channels[ObjectIdentifier(channel)] = channel
            return true
        }
    }

    private func untrack(
        _ channel: Channel,
        containerID: String,
        registration: Registration
    ) {
        _ = lock.withLock {
            registrations[containerID]?[registration]?.channels.removeValue(
                forKey: ObjectIdentifier(channel)
            )
        }
    }

    // Falls back to the privileged helper when a low-port bind was denied. NIO adopts
    // the helper's descriptor inside makeChannel and closes it on its own failure
    // paths, so the descriptor must never be closed here — the number may already
    // have been reused by another thread.
    func helperBoundChannel(
        binding: PortBinding, transport: PrivilegedPortRequest.Transport, ioError: IOError,
        bind: ((PrivilegedPortRequest) async throws -> CInt)? = nil,
        makeChannel: (CInt) async throws -> Channel
    ) async throws -> Channel {
        guard PrivilegedPortRequest.shouldUseHelper(
            errnoCode: ioError.errnoCode, address: binding.hostIP, port: binding.hostPort
        ) else { throw ioError }
        let request = try PrivilegedPortRequest(
            address: binding.hostIP, port: binding.hostPort, transport: transport
        )
        let descriptor = try await (bind ?? privilegedPorts.bind)(request)
        return try await makeChannel(descriptor)
    }

    func stop(containerID: String) {
        let values = lock.withLock {
            registrations.removeValue(forKey: containerID)?.values
                .flatMap { $0.channels.values } ?? []
        }
        values.forEach { $0.close(promise: nil) }
    }

    func stop(containerID: String, registration: Registration) {
        let values = lock.withLock {
            let values = registrations[containerID]?.removeValue(forKey: registration)
                .map { Array($0.channels.values) } ?? []
            if registrations[containerID]?.isEmpty == true {
                registrations.removeValue(forKey: containerID)
            }
            return values
        }
        values.forEach { $0.close(promise: nil) }
    }

    func stopAll() {
        let values = lock.withLock {
            let result = registrations.values.flatMap { $0.values }
                .flatMap { $0.channels.values }
            registrations.removeAll()
            return result
        }
        values.forEach { $0.close(promise: nil) }
    }
}

private final class PortForwardChannelLifecycleHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    private let inactive: @Sendable () -> Void

    init(inactive: @escaping @Sendable () -> Void) { self.inactive = inactive }

    func channelInactive(context: ChannelHandlerContext) {
        inactive()
        context.fireChannelInactive()
    }
}

private final class UDPInboundHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    private let binding: PortBinding
    private let listener: Channel
    private let connect: PortStreamConnector
    private var connections: [String: UDPStreamRelay] = [:]

    init(binding: PortBinding, listener: Channel, connect: @escaping PortStreamConnector) {
        self.binding = binding
        self.listener = listener
        self.connect = connect
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var datagram = unwrapInboundIn(data)
        let key = String(describing: datagram.remoteAddress)
        let payload = Data(datagram.data.readBytes(length: datagram.data.readableBytes) ?? [])
        let connection: UDPStreamRelay
        if let existing = connections[key] {
            connection = existing
        } else {
            let id = UUID()
            connection = UDPStreamRelay(
                id: id,
                binding: binding,
                client: datagram.remoteAddress,
                listener: listener,
                connect: connect,
                completion: { [self, listener] in
                    listener.eventLoop.execute {
                        guard self.connections[key]?.id == id else { return }
                        self.connections.removeValue(forKey: key)
                    }
                }
            )
            connections[key] = connection
        }
        connection.send(payload)
    }

    func channelInactive(context: ChannelHandlerContext) {
        connections.values.forEach { $0.stop() }
        connections.removeAll()
        context.fireChannelInactive()
    }
}

private final class UDPStreamRelay: @unchecked Sendable {
    let id: UUID

    private let binding: PortBinding
    private let client: SocketAddress
    private let listener: Channel
    private let connect: PortStreamConnector
    private let completion: @Sendable () -> Void
    private let queue: DispatchQueue
    private var file: FileHandle?
    private var pending: [Data] = []
    private var buffer = Data()
    private var closed = false

    init(
        id: UUID,
        binding: PortBinding,
        client: SocketAddress,
        listener: Channel,
        connect: @escaping PortStreamConnector,
        completion: @escaping @Sendable () -> Void
    ) {
        self.id = id
        self.binding = binding
        self.client = client
        self.listener = listener
        self.connect = connect
        self.completion = completion
        queue = DispatchQueue(label: "dev.cengine.udp-forwarder.\(id.uuidString)")
        Task { [weak self] in await self?.open() }
    }

    func send(_ payload: Data) {
        queue.async { [weak self] in self?.writeOrQueue(payload) }
    }

    func stop() {
        queue.async { [weak self] in self?.finish() }
    }

    private func open() async {
        do {
            let descriptor = try await connect(binding)
            queue.async { [weak self] in self?.activate(descriptor) }
        } catch {
            queue.async { [weak self] in self?.finish() }
        }
    }

    private func activate(_ descriptor: CInt) {
        guard !closed else { Darwin.close(descriptor); return }
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        self.file = file
        file.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            self?.queue.async { [weak self] in
                guard !data.isEmpty else { self?.finish(); return }
                self?.consume(data)
            }
        }
        let values = pending
        pending.removeAll(keepingCapacity: true)
        for payload in values { writeOrQueue(payload) }
    }

    private func writeOrQueue(_ payload: Data) {
        guard !closed else { return }
        guard let file else {
            if pending.count < 256 { pending.append(payload) }
            return
        }
        guard payload.count <= 65_535 else { return }
        var size = UInt32(payload.count).bigEndian
        do {
            try file.write(contentsOf: Data(bytes: &size, count: 4) + payload)
        } catch {
            finish()
        }
    }

    private func consume(_ data: Data) {
        buffer.append(data)
        while buffer.count >= 4 {
            let size = buffer.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            guard size <= 65_535 else { finish(); return }
            guard buffer.count >= Int(size) + 4 else { return }
            let payload = buffer.subdata(in: 4..<(Int(size) + 4))
            buffer.removeSubrange(0..<(Int(size) + 4))
            listener.eventLoop.execute { [listener, client] in
                var value = listener.allocator.buffer(capacity: payload.count)
                value.writeBytes(payload)
                listener.writeAndFlush(AddressedEnvelope(remoteAddress: client, data: value), promise: nil)
            }
        }
    }

    private func finish() {
        guard !closed else { return }
        closed = true
        file?.readabilityHandler = nil
        try? file?.close()
        file = nil
        pending.removeAll()
        buffer.removeAll()
        completion()
    }
}

private final class RelayHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    private let peer: Channel
    private var pendingWrite: EventLoopFuture<Void>?

    init(peer: Channel) { self.peer = peer }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let promise = peer.eventLoop.makePromise(of: Void.self)
        peer.writeAndFlush(unwrapInboundIn(data), promise: promise)
        pendingWrite = promise.futureResult
    }

    func channelInactive(context: ChannelHandlerContext) {
        if let pendingWrite {
            pendingWrite.whenComplete { [peer] _ in peer.close(promise: nil) }
        } else {
            peer.close(promise: nil)
        }
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        peer.close(promise: nil)
        context.close(promise: nil)
    }
}
#endif

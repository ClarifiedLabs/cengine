#if os(macOS)
import CEngineCore
import Foundation
import NIOCore
import NIOPosix
@preconcurrency import Network

final class PortForwarder: @unchecked Sendable {
    private let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private let lock = NSLock()
    private var listeners: [String: [Channel]] = [:]

    func start(containerID: String, guestIPv4Address: String, guestIPv6Address: String?,
               bindings: [PortBinding]) async throws -> [PortBinding] {
        var started: [Channel] = []
        var resolved: [PortBinding] = []
        do {
            for binding in bindings {
                let wantsIPv6 = binding.hostIP.contains(":")
                guard !wantsIPv6 || guestIPv6Address != nil else {
                    throw EngineError(.unsupported, "IPv6 port publishing requires an IPv6 container endpoint")
                }
                let guestAddress = wantsIPv6 ? guestIPv6Address! : guestIPv4Address
                if binding.proto.lowercased() == "udp" {
                    let guest = try SocketAddress(ipAddress: guestAddress, port: Int(binding.containerPort))
                    let channel = try await DatagramBootstrap(group: group)
                        .channelInitializer { channel in
                            channel.pipeline.addHandler(UDPInboundHandler(guest: guest, listener: channel))
                        }
                        .bind(host: binding.hostIP.isEmpty ? "0.0.0.0" : binding.hostIP, port: Int(binding.hostPort)).get()
                    started.append(channel)
                    var value = binding
                    value.hostPort = UInt16(channel.localAddress?.port ?? Int(binding.hostPort))
                    resolved.append(value)
                    continue
                }
                guard binding.proto.lowercased() == "tcp" else { throw EngineError(.unsupported, "unsupported port protocol \(binding.proto)") }
                let bootstrap = ServerBootstrap(group: group)
                    .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
                    .childChannelOption(ChannelOptions.autoRead, value: false)
                    .childChannelInitializer { [group] inbound in
                        ClientBootstrap(group: group)
                            .connect(host: guestAddress, port: Int(binding.containerPort))
                            .flatMap { outbound in
                                inbound.pipeline.addHandler(RelayHandler(peer: outbound)).and(
                                    outbound.pipeline.addHandler(RelayHandler(peer: inbound))
                                ).flatMap { _ in
                                    inbound.setOption(ChannelOptions.autoRead, value: true)
                                }
                            }
                    }
                let channel = try await bootstrap.bind(
                    host: binding.hostIP.isEmpty ? "0.0.0.0" : binding.hostIP,
                    port: Int(binding.hostPort)
                ).get()
                started.append(channel)
                var value = binding
                value.hostPort = UInt16(channel.localAddress?.port ?? Int(binding.hostPort))
                resolved.append(value)
            }
            lock.withLock { listeners[containerID, default: []].append(contentsOf: started) }
            return resolved
        } catch {
            started.forEach { $0.close(promise: nil) }
            throw error
        }
    }

    func stop(containerID: String) {
        let values = lock.withLock { listeners.removeValue(forKey: containerID) ?? [] }
        values.forEach { $0.close(promise: nil) }
    }

    func stopAll() {
        let values = lock.withLock {
            let result = listeners.values.flatMap { $0 }
            listeners.removeAll()
            return result
        }
        values.forEach { $0.close(promise: nil) }
    }
}

private final class UDPInboundHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    private let guest: SocketAddress; private let listener: Channel
    private let queue = DispatchQueue(label: "dev.cengine.udp-forwarder")
    private var connections: [String: NWConnection] = [:]
    init(guest: SocketAddress, listener: Channel) { self.guest = guest; self.listener = listener }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var datagram = unwrapInboundIn(data)
        let key = String(describing: datagram.remoteAddress)
        let payload = Data(datagram.data.readBytes(length: datagram.data.readableBytes) ?? [])
        if let connection = connections[key] {
            connection.send(content: payload, completion: .contentProcessed { _ in })
            return
        }
        guard let port = NWEndpoint.Port(rawValue: UInt16(guest.port ?? 0)) else { return }
        let connection = NWConnection(host: NWEndpoint.Host(guest.ipAddress ?? ""), port: port, using: .udp)
        connections[key] = connection
        let client = datagram.remoteAddress
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                connection.send(content: payload, completion: .contentProcessed { _ in })
                self.receive(on: connection, for: client)
            case .failed, .cancelled: self.connections.removeValue(forKey: key)
            default: break
            }
        }
        connection.start(queue: queue)
    }
    func channelInactive(context: ChannelHandlerContext) {
        connections.values.forEach { $0.cancel() }; connections.removeAll(); context.fireChannelInactive()
    }
    private func receive(on connection: NWConnection, for client: SocketAddress) {
        connection.receiveMessage { [weak self] content, _, _, error in
            guard let self else { return }
            if let content {
                self.listener.eventLoop.execute {
                    var buffer = self.listener.allocator.buffer(capacity: content.count); buffer.writeBytes(content)
                    self.listener.writeAndFlush(AddressedEnvelope(remoteAddress: client, data: buffer), promise: nil)
                }
            }
            if error == nil { self.receive(on: connection, for: client) }
        }
    }
}

private final class RelayHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    private let peer: Channel

    init(peer: Channel) { self.peer = peer }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        peer.writeAndFlush(unwrapInboundIn(data), promise: nil)
    }

    func channelInactive(context: ChannelHandlerContext) {
        peer.close(promise: nil)
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        peer.close(promise: nil)
        context.close(promise: nil)
    }
}
#endif

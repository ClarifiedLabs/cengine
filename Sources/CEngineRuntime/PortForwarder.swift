#if os(macOS)
import CEngineCore
import Foundation
import NIOCore
import NIOPosix

final class PortForwarder: @unchecked Sendable {
    private let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private let lock = NSLock()
    private var listeners: [String: [Channel]] = [:]

    func start(containerID: String, guestAddress: String, bindings: [PortBinding]) async throws {
        var started: [Channel] = []
        do {
            for binding in bindings {
                guard binding.proto.lowercased() == "tcp" else {
                    throw EngineError(.unsupported, "UDP port publishing is not supported yet")
                }
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
            }
            lock.withLock { listeners[containerID, default: []].append(contentsOf: started) }
        } catch {
            started.forEach { $0.close(promise: nil) }
            throw error
        }
    }

    func stop(containerID: String) {
        let values = lock.withLock { listeners.removeValue(forKey: containerID) ?? [] }
        values.forEach { $0.close(promise: nil) }
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

import CEngineCore
import Darwin
import Foundation
import NIOCore
import NIOPosix
import Testing
@testable import CEngineRuntime

private final class PortForwardResponseHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer

    private let promise: EventLoopPromise<String>
    private var completed = false

    init(promise: EventLoopPromise<String>) { self.promise = promise }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !completed else { return }
        var buffer = unwrapInboundIn(data)
        completed = true
        promise.succeed(buffer.readString(length: buffer.readableBytes) ?? "")
    }

    func channelInactive(context: ChannelHandlerContext) {
        if !completed {
            completed = true
            promise.fail(ChannelError.eof)
        }
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        if !completed {
            completed = true
            promise.fail(error)
        }
        context.close(promise: nil)
    }
}

private final class PortForwardDescriptorBox: @unchecked Sendable {
    private let lock = NSLock()
    private var descriptor: CInt = -1

    func store(_ value: CInt) { lock.withLock { descriptor = value } }
    func close() {
        let value = lock.withLock { () -> CInt in
            let result = descriptor
            descriptor = -1
            return result
        }
        if value >= 0 { Darwin.close(value) }
    }
}

@Suite struct PortForwarderHelperTests {
    private struct ChannelFactoryFailure: Error {}

    @Test func helperDescriptorIsNotClosedWhenChannelFactoryFails() async throws {
        let forwarder = PortForwarder()
        var pair: [CInt] = [-1, -1]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0)
        let descriptor = pair[0]
        defer { close(pair[0]); close(pair[1]) }
        let binding = PortBinding(hostIP: "127.0.0.1", hostPort: 80, containerPort: 8080, proto: "tcp")

        await #expect(throws: ChannelFactoryFailure.self) {
            _ = try await forwarder.helperBoundChannel(
                binding: binding, transport: .tcp,
                ioError: IOError(errnoCode: EACCES, reason: "bind"),
                bind: { _ in descriptor }
            ) { _ in throw ChannelFactoryFailure() }
        }
        // The channel factory (NIO) owns the descriptor once invoked and closes it on
        // its own failure paths; a second close here could kill an unrelated, reused fd.
        #expect(fcntl(descriptor, F_GETFD) != -1)
    }

    @Test func unrelatedBindErrorsRethrowWithoutContactingHelper() async throws {
        let forwarder = PortForwarder()
        let binding = PortBinding(hostIP: "127.0.0.1", hostPort: 80, containerPort: 8080, proto: "tcp")

        do {
            _ = try await forwarder.helperBoundChannel(
                binding: binding, transport: .udp,
                ioError: IOError(errnoCode: EADDRINUSE, reason: "bind"),
                bind: { _ in
                    Issue.record("helper must not be contacted for non-permission errors")
                    throw ChannelFactoryFailure()
                }
            ) { _ in throw ChannelFactoryFailure() }
            Issue.record("expected the original bind error to be rethrown")
        } catch let error as IOError {
            #expect(error.errnoCode == EADDRINUSE)
        }
    }

    @Test func tcpForwardingRelaysAnUpgradedStream() async throws {
        let forwarder = PortForwarder()
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let peer = PortForwardDescriptorBox()
        var client: Channel?
        do {
            let ports = try await forwarder.start(
                containerID: UUID().uuidString,
                bindings: [
                    .init(hostIP: "127.0.0.1", hostPort: 0, containerPort: 8080, proto: "tcp")
                ],
                connect: { _ in
                    var pair: [CInt] = [-1, -1]
                    guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else {
                        throw IOError(errnoCode: errno, reason: "socketpair")
                    }
                    let response = Data("ready".utf8)
                    _ = response.withUnsafeBytes { write(pair[1], $0.baseAddress, response.count) }
                    peer.store(pair[1])
                    return pair[0]
                }
            )

            let promise = group.next().makePromise(of: String.self)
            client = try await ClientBootstrap(group: group)
                .channelInitializer { channel in
                    channel.pipeline.addHandler(PortForwardResponseHandler(promise: promise))
                }
                .connect(host: "127.0.0.1", port: Int(ports[0].hostPort)).get()

            #expect(try await promise.futureResult.get() == "ready")
            try await client?.close().get()
            peer.close()
            forwarder.stopAll()
            try await group.shutdownGracefully()
        } catch {
            client?.close(promise: nil)
            peer.close()
            forwarder.stopAll()
            try? await group.shutdownGracefully()
            throw error
        }
    }
}

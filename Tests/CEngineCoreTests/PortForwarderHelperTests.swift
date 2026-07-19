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

    func store(_ value: CInt) {
        var enabled: CInt = 1
        _ = setsockopt(value, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout.size(ofValue: enabled)))
        lock.withLock { descriptor = value }
    }
    func isStored() -> Bool { lock.withLock { descriptor >= 0 } }
    func send(_ data: Data) {
        lock.withLock {
            guard descriptor >= 0 else { return }
            _ = data.withUnsafeBytes { write(descriptor, $0.baseAddress, data.count) }
        }
    }
    func reachedEOF() -> Bool {
        lock.withLock {
            guard descriptor >= 0 else { return false }
            var byte: UInt8 = 0
            return recv(descriptor, &byte, 1, MSG_DONTWAIT) == 0
        }
    }
    func close() {
        let value = lock.withLock { () -> CInt in
            let result = descriptor
            descriptor = -1
            return result
        }
        if value >= 0 { Darwin.close(value) }
    }
}

private final class PortForwardDataBox: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()

    func append(_ value: Data) { lock.withLock { data.append(value) } }
    func value() -> Data { lock.withLock { data } }
}

private final class PortForwardDataHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    private let received: PortForwardDataBox

    init(received: PortForwardDataBox) { self.received = received }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        received.append(Data(buffer.readBytes(length: buffer.readableBytes) ?? []))
    }
}

private actor PortForwardConnectGate {
    private var entered = false
    private var continuation: CheckedContinuation<Void, Never>?

    func block() async {
        entered = true
        await withCheckedContinuation { continuation = $0 }
    }
    func isBlocked() -> Bool { entered && continuation != nil }
    func release() {
        continuation?.resume()
        continuation = nil
    }
}

private func waitForPortForwardCondition(_ condition: () -> Bool) async {
    for _ in 0..<400 {
        if condition() { return }
        try? await Task.sleep(for: .milliseconds(5))
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

    @Test func stoppingRegistrationClosesEstablishedTCPRelay() async throws {
        let forwarder = PortForwarder()
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let containerID = UUID().uuidString
        let registration = PortForwarder.Registration()
        let peer = PortForwardDescriptorBox()
        var client: Channel?
        do {
            let ports = try await forwarder.start(
                containerID: containerID,
                registration: registration,
                bindings: [
                    .init(hostIP: "127.0.0.1", hostPort: 0, containerPort: 8080, proto: "tcp")
                ],
                connect: { _ in
                    var pair: [CInt] = [-1, -1]
                    guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else {
                        throw IOError(errnoCode: errno, reason: "socketpair")
                    }
                    peer.store(pair[1])
                    return pair[0]
                }
            )
            client = try await ClientBootstrap(group: group)
                .connect(host: "127.0.0.1", port: Int(ports[0].hostPort)).get()
            await waitForPortForwardCondition { peer.isStored() }
            #expect(peer.isStored())

            forwarder.stop(containerID: containerID, registration: registration)
            await waitForPortForwardCondition { client?.isActive != true }
            await waitForPortForwardCondition { peer.reachedEOF() }
            #expect(client?.isActive == false)
            #expect(peer.reachedEOF())
            client?.close(promise: nil)
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

    @Test func stoppingOldRegistrationDoesNotCloseReplacementTCPRelay() async throws {
        let forwarder = PortForwarder()
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let containerID = UUID().uuidString
        let oldRegistration = PortForwarder.Registration()
        let replacementRegistration = PortForwarder.Registration()
        let oldPeer = PortForwardDescriptorBox()
        let replacementPeer = PortForwardDescriptorBox()
        let replacementData = PortForwardDataBox()
        var oldClient: Channel?
        var replacementClient: Channel?
        do {
            let oldPorts = try await forwarder.start(
                containerID: containerID,
                registration: oldRegistration,
                bindings: [
                    .init(hostIP: "127.0.0.1", hostPort: 0, containerPort: 8080, proto: "tcp")
                ],
                connect: { _ in
                    var pair: [CInt] = [-1, -1]
                    guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else {
                        throw IOError(errnoCode: errno, reason: "socketpair")
                    }
                    oldPeer.store(pair[1])
                    return pair[0]
                }
            )
            let replacementPorts = try await forwarder.start(
                containerID: containerID,
                registration: replacementRegistration,
                bindings: [
                    .init(hostIP: "127.0.0.1", hostPort: 0, containerPort: 8080, proto: "tcp")
                ],
                connect: { _ in
                    var pair: [CInt] = [-1, -1]
                    guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else {
                        throw IOError(errnoCode: errno, reason: "socketpair")
                    }
                    replacementPeer.store(pair[1])
                    return pair[0]
                }
            )
            oldClient = try await ClientBootstrap(group: group)
                .connect(host: "127.0.0.1", port: Int(oldPorts[0].hostPort)).get()
            replacementClient = try await ClientBootstrap(group: group)
                .channelInitializer { channel in
                    channel.pipeline.addHandler(PortForwardDataHandler(received: replacementData))
                }
                .connect(host: "127.0.0.1", port: Int(replacementPorts[0].hostPort)).get()
            await waitForPortForwardCondition {
                oldPeer.isStored() && replacementPeer.isStored()
            }
            #expect(oldPeer.isStored())
            #expect(replacementPeer.isStored())

            forwarder.stop(containerID: containerID, registration: oldRegistration)
            await waitForPortForwardCondition { oldClient?.isActive != true }
            #expect(oldClient?.isActive == false)
            #expect(replacementClient?.isActive == true)

            replacementPeer.send(Data("replacement-alive".utf8))
            await waitForPortForwardCondition { !replacementData.value().isEmpty }
            #expect(replacementData.value() == Data("replacement-alive".utf8))
            #expect(replacementClient?.isActive == true)
            oldClient?.close(promise: nil)
            replacementClient?.close(promise: nil)
            oldPeer.close()
            replacementPeer.close()
            forwarder.stopAll()
            try await group.shutdownGracefully()
        } catch {
            oldClient?.close(promise: nil)
            replacementClient?.close(promise: nil)
            oldPeer.close()
            replacementPeer.close()
            forwarder.stopAll()
            try? await group.shutdownGracefully()
            throw error
        }
    }

    @Test func stoppingRegistrationDuringTCPConnectCannotLeakAcceptedChannels() async throws {
        let forwarder = PortForwarder()
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let containerID = UUID().uuidString
        let registration = PortForwarder.Registration()
        let peer = PortForwardDescriptorBox()
        let connectGate = PortForwardConnectGate()
        var client: Channel?
        do {
            let ports = try await forwarder.start(
                containerID: containerID,
                registration: registration,
                bindings: [
                    .init(hostIP: "127.0.0.1", hostPort: 0, containerPort: 8080, proto: "tcp")
                ],
                connect: { _ in
                    var pair: [CInt] = [-1, -1]
                    guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else {
                        throw IOError(errnoCode: errno, reason: "socketpair")
                    }
                    peer.store(pair[1])
                    await connectGate.block()
                    return pair[0]
                }
            )
            let connection = Task {
                try? await ClientBootstrap(group: group)
                    .connect(host: "127.0.0.1", port: Int(ports[0].hostPort)).get()
            }
            while !(await connectGate.isBlocked()) {
                try? await Task.sleep(for: .milliseconds(5))
            }

            forwarder.stop(containerID: containerID, registration: registration)
            await connectGate.release()
            client = await connection.value
            await waitForPortForwardCondition { client?.isActive != true }
            await waitForPortForwardCondition { peer.reachedEOF() }
            #expect(client?.isActive != true)
            #expect(peer.reachedEOF())

            client?.close(promise: nil)
            peer.close()
            forwarder.stopAll()
            try await group.shutdownGracefully()
        } catch {
            await connectGate.release()
            client?.close(promise: nil)
            peer.close()
            forwarder.stopAll()
            try? await group.shutdownGracefully()
            throw error
        }
    }
}

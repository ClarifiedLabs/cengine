import Foundation
import CEngineCore
import CEngineRuntime
import NIOCore
import NIOHTTP1
import NIOPosix

public final class DockerHTTPHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    public typealias InboundIn = HTTPServerRequestPart
    public typealias OutboundOut = HTTPServerResponsePart

    private let router: DockerRouter
    private var head: HTTPRequestHead?
    private var body = ByteBuffer()
    private let maximumBodyBytes: Int

    public init(router: DockerRouter, maximumBodyBytes: Int = 512 * 1024 * 1024) {
        self.router = router; self.maximumBodyBytes = maximumBodyBytes
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let value): head = value; body.clear()
        case .body(var chunk):
            guard body.readableBytes + chunk.readableBytes <= maximumBodyBytes else {
                Self.write(channel: context.channel, response: .init(status: .payloadTooLarge, body: Data(#"{"message":"request body too large"}"#.utf8)), keepAlive: false)
                return
            }
            body.writeBuffer(&chunk)
        case .end:
            guard let head else { return }
            let request = APIRequest(method: head.method, uri: head.uri, headers: head.headers, body: Data(body.readableBytesView))
            let keepAlive = head.isKeepAlive
            let channel = context.channel
            Task { [router] in
                let response = await router.route(request)
                channel.eventLoop.execute { Self.write(channel: channel, response: response, keepAlive: keepAlive) }
            }
        }
    }

    private static func write(channel: Channel, response: APIResponse, keepAlive: Bool) {
        var headers = response.headers
        headers.replaceOrAdd(name: "Content-Length", value: String(response.body.count))
        if keepAlive { headers.replaceOrAdd(name: "Connection", value: "keep-alive") }
        channel.write(HTTPServerResponsePart.head(.init(version: .http1_1, status: response.status, headers: headers)), promise: nil)
        if !response.body.isEmpty {
            var buffer = channel.allocator.buffer(capacity: response.body.count)
            buffer.writeBytes(response.body)
            channel.write(HTTPServerResponsePart.body(.byteBuffer(buffer)), promise: nil)
        }
        channel.writeAndFlush(HTTPServerResponsePart.end(nil)).whenComplete { _ in if !keepAlive { channel.close(promise: nil) } }
    }
}

public final class DockerServer: @unchecked Sendable {
    private let group: MultiThreadedEventLoopGroup
    private let socketPath: String
    private let router: DockerRouter
    private var channel: Channel?

    public init(socketPath: String, router: DockerRouter) {
        self.socketPath = socketPath; self.router = router
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: max(2, System.coreCount / 2))
    }

    public func start() async throws {
        if FileManager.default.fileExists(atPath: socketPath) { try FileManager.default.removeItem(atPath: socketPath) }
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 256)
            .childChannelOption(ChannelOptions.allowRemoteHalfClosure, value: true)
            .childChannelInitializer { [router] channel in
                let upgrader = DockerTCPUpgrader(router: router)
                let upgrade: NIOHTTPServerUpgradeSendableConfiguration = (
                    upgraders: [upgrader],
                    completionHandler: { _ in }
                )
                return channel.pipeline.configureHTTPServerPipeline(withServerUpgrade: upgrade).flatMap {
                    channel.pipeline.addHandler(DockerHTTPHandler(router: router), name: "docker-http")
                }
            }
        channel = try await bootstrap.bind(unixDomainSocketPath: socketPath).get()
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: socketPath)
    }

    public func wait() async throws { try await channel?.closeFuture.get() }
    public func shutdown() async throws { try await channel?.close().get(); try await group.shutdownGracefully() }
}

private final class DockerTCPUpgrader: HTTPServerProtocolUpgrader, @unchecked Sendable {
    let supportedProtocol = "tcp"
    let requiredUpgradeHeaders: [String] = []
    private let router: DockerRouter
    private let lock = NSLock()
    private struct Pending: Sendable { let io: ContainerIOBridge; let execID: String? }
    private var pending: [ObjectIdentifier: Pending] = [:]

    init(router: DockerRouter) { self.router = router }

    func buildUpgradeResponse(
        channel: Channel,
        upgradeRequest: HTTPRequestHead,
        initialResponseHeaders: HTTPHeaders
    ) -> EventLoopFuture<HTTPHeaders> {
        let promise = channel.eventLoop.makePromise(of: HTTPHeaders.self)
        guard upgradeRequest.method == .POST, let target = Self.upgradeTarget(from: upgradeRequest.uri) else {
            promise.fail(EngineError(.notFound, "attach endpoint not found"))
            return promise.futureResult
        }
        Task { [router] in
            do {
                let pending: Pending
                switch target {
                case .container(let id): pending = try await .init(io: router.containerIO(id), execID: nil)
                case .exec(let id): pending = try await .init(io: router.execIO(id), execID: id)
                }
                self.lock.withLock { self.pending[ObjectIdentifier(channel as AnyObject)] = pending }
                channel.eventLoop.execute {
                    var headers = initialResponseHeaders
                    headers.replaceOrAdd(name: "Content-Type", value: "application/vnd.docker.raw-stream")
                    promise.succeed(headers)
                }
            } catch {
                channel.eventLoop.execute { promise.fail(error) }
            }
        }
        return promise.futureResult
    }

    func upgrade(context: ChannelHandlerContext, upgradeRequest _: HTTPRequestHead) -> EventLoopFuture<Void> {
        let key = ObjectIdentifier(context.channel as AnyObject)
        guard let pending = lock.withLock({ pending.removeValue(forKey: key) }) else {
            return context.eventLoop.makeFailedFuture(EngineError(.internalError, "attach I/O was not prepared"))
        }
        let pipeline = context.pipeline
        return pipeline.removeHandler(name: "docker-http").flatMap {
            pipeline.addHandler(ContainerAttachHandler(io: pending.io))
        }.map {
            if let execID = pending.execID {
                Task {
                    do { try await self.router.startExec(execID) }
                    catch { pending.io.finishOutput() }
                }
            }
        }
    }

    private enum UpgradeTarget: Sendable { case container(String), exec(String) }
    private static func upgradeTarget(from uri: String) -> UpgradeTarget? {
        guard let components = URLComponents(string: uri) else { return nil }
        let path = components.path.replacingOccurrences(of: #"^/v[0-9.]+"#, with: "", options: .regularExpression)
        if path.hasPrefix("/containers/"), path.hasSuffix("/attach") {
            return .container(String(path.dropFirst("/containers/".count).dropLast("/attach".count)))
        }
        if path.hasPrefix("/exec/"), path.hasSuffix("/start") {
            return .exec(String(path.dropFirst("/exec/".count).dropLast("/start".count)))
        }
        return nil
    }
}

private final class ContainerAttachHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer
    private let io: ContainerIOBridge

    init(io: ContainerIOBridge) { self.io = io }

    func handlerAdded(context: ChannelHandlerContext) {
        let context = SendableContext(context)
        io.attach(
            output: { data in
                context.value.eventLoop.execute {
                    var buffer = context.value.channel.allocator.buffer(capacity: data.count)
                    buffer.writeBytes(data)
                    context.value.writeAndFlush(self.wrapOutboundOut(buffer), promise: nil)
                }
            },
            closed: {
                context.value.eventLoop.execute {
                    let buffer = context.value.channel.allocator.buffer(capacity: 0)
                    context.value.writeAndFlush(self.wrapOutboundOut(buffer)).flatMap { context.value.close() }.whenComplete { _ in }
                }
            }
        )
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        if let bytes = buffer.readBytes(length: buffer.readableBytes) { io.sendInput(Data(bytes)) }
    }

    func channelInactive(context: ChannelHandlerContext) {
        io.finishInput()
        io.detach()
        context.fireChannelInactive()
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let event = event as? ChannelEvent, event == .inputClosed {
            io.finishInput()
            return
        }
        context.fireUserInboundEventTriggered(event)
    }
}

private final class SendableContext: @unchecked Sendable {
    let value: ChannelHandlerContext
    init(_ value: ChannelHandlerContext) { self.value = value }
}

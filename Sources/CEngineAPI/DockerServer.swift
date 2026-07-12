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
    private var followIO: ContainerIOBridge?
    private var followSubscription: UUID?
    private var eventTask: Task<Void, Never>?
    private var statsTask: Task<Void, Never>?
    private var pullTask: Task<Void, Never>?
    private var waitTask: Task<Void, Never>?
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
            let target: DockerRequestTarget
            do { target = try DockerRequestTarget.parse(head.uri) }
            catch let error as EngineError {
                Self.write(channel: context.channel, response: dockerErrorResponse(error), keepAlive: head.isKeepAlive)
                return
            } catch {
                Self.write(channel: context.channel, response: .init(status: .badRequest), keepAlive: head.isKeepAlive)
                return
            }
            if Self.isImagePull(head, target: target) {
                startImagePull(request: .init(method: head.method, uri: head.uri, headers: head.headers, body: Data(body.readableBytesView)), channel: context.channel)
                return
            }
            if Self.isStreamingStats(target), let id = Self.statsContainerID(target) {
                startStats(identifier: id, version: target.version, channel: context.channel)
                return
            }
            if target.path == "/events" {
                startEvents(target: target, requestHeaders: head.headers, channel: context.channel)
                return
            }
            if Self.isFollowingLogs(target), let id = Self.logContainerID(target) {
                startFollowingLogs(identifier: id, target: target, channel: context.channel)
                return
            }
            if head.method == .POST, let id = Self.waitContainerID(target) {
                let condition = target.components.queryItems?.first(where: { $0.name == "condition" })?.value
                startContainerWait(identifier: id, condition: condition, channel: context.channel, keepAlive: head.isKeepAlive)
                return
            }
            let request = APIRequest(method: head.method, uri: head.uri, headers: head.headers, body: Data(body.readableBytesView))
            let keepAlive = head.isKeepAlive
            let channel = context.channel
            Task { [router] in
                let response = await router.route(request)
                channel.eventLoop.execute { Self.write(channel: channel, response: response, keepAlive: keepAlive) }
            }
        }
    }

    public func channelInactive(context: ChannelHandlerContext) {
        if let followSubscription { followIO?.detach(followSubscription) }
        eventTask?.cancel()
        statsTask?.cancel()
        pullTask?.cancel()
        waitTask?.cancel()
        context.fireChannelInactive()
    }

    private func startContainerWait(identifier: String, condition: String?, channel: Channel, keepAlive: Bool) {
        waitTask = Task { [router] in
            do {
                let subscription = try await router.containerWait(identifier, condition: condition)
                channel.eventLoop.execute {
                    var headers = HTTPHeaders()
                    headers.add(name: "Content-Type", value: "application/json")
                    headers.add(name: "Transfer-Encoding", value: "chunked")
                    if keepAlive { headers.add(name: "Connection", value: "keep-alive") }
                    channel.writeAndFlush(HTTPServerResponsePart.head(.init(version: .http1_1, status: .ok, headers: headers)), promise: nil)
                }
                for await code in subscription.stream {
                    guard !Task.isCancelled else { return }
                    let payload = try JSONEncoder().encode(ContainerWaitResponse(StatusCode: code, Error: nil))
                    channel.eventLoop.execute {
                        var buffer = channel.allocator.buffer(capacity: payload.count)
                        buffer.writeBytes(payload)
                        channel.write(HTTPServerResponsePart.body(.byteBuffer(buffer)), promise: nil)
                        channel.writeAndFlush(HTTPServerResponsePart.end(nil), promise: nil)
                    }
                    return
                }
            } catch let error as EngineError {
                channel.eventLoop.execute {
                    Self.write(channel: channel, response: dockerErrorResponse(error), keepAlive: keepAlive)
                }
            } catch {
                channel.eventLoop.execute {
                    Self.write(channel: channel, response: dockerErrorResponse(EngineError(.internalError, EngineError.message(for: error))), keepAlive: keepAlive)
                }
            }
        }
    }

    private static func waitContainerID(_ target: DockerRequestTarget) -> String? {
        let path = target.path
        guard path.hasPrefix("/containers/"), path.hasSuffix("/wait") else { return nil }
        return String(path.dropFirst("/containers/".count).dropLast("/wait".count))
    }

    private func startFollowingLogs(identifier id: String, target: DockerRequestTarget, channel: Channel) {
        let options = Self.logOptions(target)
        Task { [router] in
            do {
                let io = try await router.containerIO(id)
                channel.eventLoop.execute {
                    self.followIO = io
                    var headers = HTTPHeaders()
                    headers.add(name: "Content-Type", value: "application/vnd.docker.raw-stream")
                    headers.add(name: "Transfer-Encoding", value: "chunked")
                    channel.write(HTTPServerResponsePart.head(.init(version: .http1_1, status: .ok, headers: headers)), promise: nil)
                    let subscription = io.attachLogs(options: options, replayExisting: true, output: { data in
                        channel.eventLoop.execute {
                            var buffer = channel.allocator.buffer(capacity: data.count)
                            buffer.writeBytes(data)
                            channel.writeAndFlush(HTTPServerResponsePart.body(.byteBuffer(buffer)), promise: nil)
                        }
                    }, closed: {
                        channel.eventLoop.execute { channel.writeAndFlush(HTTPServerResponsePart.end(nil), promise: nil) }
                    })
                    self.followSubscription = subscription.id
                    if !subscription.initial.isEmpty {
                        let initial = subscription.initial
                        var buffer = channel.allocator.buffer(capacity: initial.count)
                        buffer.writeBytes(initial)
                        channel.writeAndFlush(HTTPServerResponsePart.body(.byteBuffer(buffer)), promise: nil)
                    } else { channel.flush() }
                    if let until = options.until {
                        let delay = max(until.timeIntervalSinceNow, 0)
                        self.eventTask = Task {
                            try? await Task.sleep(for: .seconds(delay))
                            channel.eventLoop.execute {
                                if let subscription = self.followSubscription { io.detach(subscription) }
                                channel.writeAndFlush(HTTPServerResponsePart.end(nil), promise: nil)
                            }
                        }
                    }
                }
            } catch {
                channel.eventLoop.execute {
                    Self.write(channel: channel, response: .init(status: .notFound, body: Data(#"{"message":"container logs unavailable"}"#.utf8)), keepAlive: false)
                }
            }
        }
    }

    private static func isFollowingLogs(_ target: DockerRequestTarget) -> Bool {
        guard target.path.hasSuffix("/logs") else { return false }
        return target.components.queryItems?.contains { $0.name == "follow" && ($0.value == "1" || $0.value == "true") } == true
    }

    private static func logContainerID(_ target: DockerRequestTarget) -> String? {
        let path = target.path
        guard path.hasPrefix("/containers/"), path.hasSuffix("/logs") else { return nil }
        return String(path.dropFirst("/containers/".count).dropLast("/logs".count))
    }

    private static func logOptions(_ target: DockerRequestTarget) -> DockerLogOptions {
        let query = Dictionary(uniqueKeysWithValues: (target.components.queryItems ?? []).map { ($0.name, $0.value ?? "") })
        return .init(
            stdout: query["stdout"].map { $0 == "1" || $0 == "true" } ?? true,
            stderr: query["stderr"].map { $0 == "1" || $0 == "true" } ?? true,
            since: query["since"].flatMap(parseDockerTimestamp),
            until: query["until"].flatMap(parseDockerTimestamp),
            timestamps: query["timestamps"].map { $0 == "1" || $0 == "true" } ?? false,
            tail: query["tail"].flatMap { $0 == "all" ? nil : Int($0) }
        )
    }

    private func startEvents(target: DockerRequestTarget, requestHeaders: HTTPHeaders, channel: Channel) {
        let filters = Self.eventFilters(target)
        let query = Dictionary(uniqueKeysWithValues: (target.components.queryItems ?? []).map { ($0.name, $0.value ?? "") })
        let since = query["since"].flatMap(parseDockerTimestamp)
        let until = query["until"].flatMap(parseDockerTimestamp)
        let jsonl = target.version >= .init(major: 1, minor: 53)
            && requestHeaders["Accept"].contains(where: { $0.split(separator: ",").contains { $0.trimmingCharacters(in: .whitespaces) == "application/jsonl" } })
        eventTask = Task { [router] in
            let stream = await router.events(since: since, until: until)
            do {
                var headers = HTTPHeaders()
                headers.add(name: "Content-Type", value: jsonl ? "application/jsonl" : "application/json")
                headers.add(name: "Transfer-Encoding", value: "chunked")
                try await channel.writeAndFlush(HTTPServerResponsePart.head(.init(
                    version: .http1_1, status: .ok, headers: headers
                ))).get()
                let encoder = JSONEncoder()
                for await event in stream {
                    guard !Task.isCancelled else { break }
                    guard Self.matches(event, filters: filters) else { continue }
                    guard var data = try? encoder.encode(DockerEventResponse(event, version: target.version)) else { continue }
                    data.append(0x0a)
                    var buffer = channel.allocator.buffer(capacity: data.count)
                    buffer.writeBytes(data)
                    try await channel.writeAndFlush(HTTPServerResponsePart.body(.byteBuffer(buffer))).get()
                }
                try await channel.writeAndFlush(HTTPServerResponsePart.end(nil)).get()
            } catch {}
        }
    }

    static func eventFilters(_ target: DockerRequestTarget) -> [String: [String]] {
        guard let raw = target.components.queryItems?.first(where: { $0.name == "filters" })?.value,
              let data = raw.replacingOccurrences(of: "+", with: " ").data(using: .utf8) else {
            return [:]
        }
        return (try? JSONDecoder().decode([String: [String]].self, from: data)) ?? [:]
    }

    private static func matches(_ event: RuntimeEvent, filters: [String: [String]]) -> Bool {
        filters.allSatisfy { key, values in
            guard !values.isEmpty else { return true }
            return values.contains { value in
                return switch key {
                case "type": event.type == value
                case "event": event.action == value
                case "container":
                    event.id == value || event.id.hasPrefix(value) || event.attributes["name"] == value
                case "label": matchesLabel(event, value: value)
                default: true
                }
            }
        }
    }

    private static func matchesLabel(_ event: RuntimeEvent, value: String) -> Bool {
        let fields = value.split(separator: "=", maxSplits: 1).map(String.init)
        guard let actual = event.attributes[fields[0]] else { return false }
        return fields.count == 1 || actual == fields[1]
    }

    private func startStats(identifier: String, version: DockerAPIVersion, channel: Channel) {
        statsTask = Task { [router] in
            channel.eventLoop.execute {
                var headers = HTTPHeaders(); headers.add(name: "Content-Type", value: "application/json")
                headers.add(name: "Transfer-Encoding", value: "chunked")
                channel.writeAndFlush(HTTPServerResponsePart.head(.init(version: .http1_1, status: .ok, headers: headers)), promise: nil)
            }
            let encoder = JSONEncoder()
            while !Task.isCancelled {
                do {
                    var encoded = try encoder.encode(await router.statistics(identifier, version: version)); encoded.append(0x0a)
                    let payload = encoded
                    channel.eventLoop.execute {
                        var buffer = channel.allocator.buffer(capacity: payload.count); buffer.writeBytes(payload)
                        channel.writeAndFlush(HTTPServerResponsePart.body(.byteBuffer(buffer)), promise: nil)
                    }
                    try await Task.sleep(for: .seconds(1))
                } catch { break }
            }
            channel.eventLoop.execute { channel.writeAndFlush(HTTPServerResponsePart.end(nil), promise: nil) }
        }
    }

    private static func isStreamingStats(_ target: DockerRequestTarget) -> Bool {
        guard target.path.hasSuffix("/stats") else { return false }
        return !((target.components.queryItems ?? []).contains {
            $0.name == "stream" && ($0.value == "0" || $0.value?.lowercased() == "false")
        })
    }

    private static func statsContainerID(_ target: DockerRequestTarget) -> String? {
        let path = target.path
        guard path.hasPrefix("/containers/"), path.hasSuffix("/stats") else { return nil }
        return String(path.dropFirst("/containers/".count).dropLast("/stats".count))
    }

    private func startImagePull(request: APIRequest, channel: Channel) {
        channel.write(HTTPServerResponsePart.head(.init(
            version: .http1_1, status: .ok,
            headers: ["Content-Type": "application/json", "Transfer-Encoding": "chunked"]
        )), promise: nil)
        channel.flush()
        pullTask = Task { [router] in
            do {
                let image = try await router.pullImage(request, progress: { progress in
                    let line = "{\"status\":\"Downloading\",\"progressDetail\":{\"current\":\(progress.completedBytes),\"total\":\(progress.totalBytes)}}\n"
                    Self.writeChunk(Data(line.utf8), channel: channel)
                })
                Self.writeChunk(Data("{\"status\":\"Pull complete\",\"id\":\"\(image.id)\"}\n".utf8), channel: channel)
            } catch {
                let message = error.localizedDescription
                let data = (try? JSONSerialization.data(withJSONObject: ["error": message, "errorDetail": ["message": message]])) ?? Data()
                Self.writeChunk(data + Data([0x0a]), channel: channel)
            }
            channel.eventLoop.execute { channel.writeAndFlush(HTTPServerResponsePart.end(nil), promise: nil) }
        }
    }

    private static func writeChunk(_ data: Data, channel: Channel) {
        channel.eventLoop.execute {
            var buffer = channel.allocator.buffer(capacity: data.count); buffer.writeBytes(data)
            channel.writeAndFlush(HTTPServerResponsePart.body(.byteBuffer(buffer)), promise: nil)
        }
    }

    private static func isImagePull(_ head: HTTPRequestHead, target: DockerRequestTarget) -> Bool {
        head.method == .POST && target.path == "/images/create"
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
    public func stop() async throws {
        if let channel, channel.isActive { try await channel.close().get() }
    }
    public func shutdown() async throws {
        try await stop()
        try await group.shutdownGracefully()
        try? FileManager.default.removeItem(atPath: socketPath)
    }
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
        guard let target = try? DockerRequestTarget.parse(uri) else { return nil }
        let path = target.path
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
    private var subscription: UUID?

    init(io: ContainerIOBridge) { self.io = io }

    func handlerAdded(context: ChannelHandlerContext) {
        let context = SendableContext(context)
        subscription = io.attach(
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
        if let subscription { io.detach(subscription) }
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

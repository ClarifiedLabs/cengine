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
        let query = Dictionary(grouping: target.components.queryItems ?? [], by: \.name)
            .compactMapValues { $0.first?.value ?? "" }
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
        let query = Dictionary(grouping: target.components.queryItems ?? [], by: \.name)
            .compactMapValues { $0.first?.value ?? "" }
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
        return (try? JSONDecoder().decode([String: DockerFilterValues].self, from: data).mapValues(\.active)) ?? [:]
    }

    static func matches(_ event: RuntimeEvent, filters: [String: [String]]) -> Bool {
        filters.allSatisfy { key, values in
            guard !values.isEmpty else { return true }
            return values.contains { value in
                return switch key {
                case "type": event.type == value
                case "event": event.action == value
                case "container":
                    event.id == value || event.id.hasPrefix(value) || event.attributes["name"] == value
                case "image":
                    matchesImage(event, value: value)
                case "label": matchesLabel(event, value: value)
                default: true
                }
            }
        }
    }

    private static func matchesImage(_ event: RuntimeEvent, value: String) -> Bool {
        let attribute = event.attributes[event.type == "image" ? "name" : "image"] ?? ""
        return [event.id, attribute].contains { reference in
            reference == value
                || familiarImageReference(reference) == value
                || familiarImageName(reference) == value
        }
    }

    private static func familiarImageReference(_ reference: String) -> String {
        if reference.hasPrefix("docker.io/library/") {
            return String(reference.dropFirst("docker.io/library/".count))
        }
        if reference.hasPrefix("docker.io/") {
            return String(reference.dropFirst("docker.io/".count))
        }
        return reference
    }

    private static func familiarImageName(_ reference: String) -> String {
        let familiar = familiarImageReference(reference)
        let withoutDigest = familiar.split(separator: "@", maxSplits: 1).first.map(String.init) ?? familiar
        let slash = withoutDigest.lastIndex(of: "/")
        guard let colon = withoutDigest.lastIndex(of: ":") else { return withoutDigest }
        if let slash, colon < slash { return withoutDigest }
        return String(withoutDigest[..<colon])
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
                configureDockerHTTPPipeline(channel: channel, router: router)
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

func configureDockerHTTPPipeline(channel: Channel, router: DockerRouter) -> EventLoopFuture<Void> {
    let responseEncoder = HTTPResponseEncoder()
    let requestDecoder = ByteToMessageHandler(HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes))
    let pipelineHandler = HTTPServerPipelineHandler()
    let headerValidator = NIOHTTPResponseHeadersValidator()
    let protocolErrorHandler = HTTPServerProtocolErrorHandler()
    let requestBodies = DockerUpgradeRequestBodyStore()
    let bodyCollector = DockerUpgradeRequestBodyCollector(store: requestBodies)
    let tcpUpgrader = DockerTCPUpgrader(router: router, requestBodies: requestBodies)
    let upgradeHandler = HTTPServerUpgradeHandler(
        upgraders: [tcpUpgrader],
        httpEncoder: responseEncoder,
        extraHTTPHandlers: [
            requestDecoder, pipelineHandler, headerValidator, protocolErrorHandler, bodyCollector,
        ],
        upgradeCompletionHandler: { _ in }
    )
    do {
        try channel.pipeline.syncOperations.addHandlers([
            responseEncoder, requestDecoder, pipelineHandler, headerValidator, protocolErrorHandler,
            bodyCollector, upgradeHandler,
        ])
        try channel.pipeline.syncOperations.addHandler(DockerHTTPHandler(router: router), name: "docker-http")
        return channel.eventLoop.makeSucceededFuture(())
    } catch {
        return channel.eventLoop.makeFailedFuture(error)
    }
}

final class DockerUpgradeRequestBodyStore: @unchecked Sendable {
    private struct Entry {
        let promise: EventLoopPromise<Data>
        var body = Data()
        var failure: EngineError?
    }

    private let lock = NSLock()
    private var entries: [ObjectIdentifier: Entry] = [:]

    func begin(for channel: Channel) {
        let key = ObjectIdentifier(channel as AnyObject)
        lock.withLock { entries[key] = Entry(promise: channel.eventLoop.makePromise(of: Data.self)) }
    }

    func append(_ bytes: ByteBufferView, for channel: Channel) {
        let key = ObjectIdentifier(channel as AnyObject)
        lock.withLock {
            guard entries[key] != nil else { return }
            if entries[key]!.body.count + bytes.count > 64 * 1_024 {
                entries[key]!.failure = EngineError(.badRequest, "upgrade request body is too large")
                return
            }
            entries[key]!.body.append(contentsOf: bytes)
        }
    }

    func finish(for channel: Channel) {
        let key = ObjectIdentifier(channel as AnyObject)
        guard let entry = lock.withLock({ entries.removeValue(forKey: key) }) else { return }
        if let failure = entry.failure {
            entry.promise.fail(failure)
        } else {
            entry.promise.succeed(entry.body)
        }
    }

    func body(for channel: Channel) -> EventLoopFuture<Data>? {
        let key = ObjectIdentifier(channel as AnyObject)
        return lock.withLock { entries[key]?.promise.futureResult }
    }

    func cancel(for channel: Channel) {
        let key = ObjectIdentifier(channel as AnyObject)
        guard let entry = lock.withLock({ entries.removeValue(forKey: key) }) else { return }
        entry.promise.fail(EngineError(.badRequest, "upgrade request body was interrupted"))
    }
}

final class DockerUpgradeRequestBodyCollector: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = HTTPServerRequestPart
    typealias InboundOut = HTTPServerRequestPart

    private let store: DockerUpgradeRequestBodyStore
    private var collecting = false

    init(store: DockerUpgradeRequestBodyStore) { self.store = store }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let part = unwrapInboundIn(data)
        switch part {
        case .head(let head):
            collecting = head.headers[canonicalForm: "upgrade"].contains { $0.lowercased() == "tcp" }
            if collecting { store.begin(for: context.channel) }
        case .body(let body):
            if collecting { store.append(body.readableBytesView, for: context.channel) }
        case .end:
            if collecting { store.finish(for: context.channel) }
            collecting = false
        }
        context.fireChannelRead(wrapInboundOut(part))
    }

    func channelInactive(context: ChannelHandlerContext) {
        if collecting { store.cancel(for: context.channel) }
        collecting = false
        context.fireChannelInactive()
    }
}

final class DockerTCPUpgrader: HTTPServerProtocolUpgrader, @unchecked Sendable {
    let supportedProtocol = "tcp"
    let requiredUpgradeHeaders: [String] = []
    private let router: DockerRouter
    private let requestBodies: DockerUpgradeRequestBodyStore
    private let lock = NSLock()
    private enum Pending: Sendable {
        case buffered(io: ContainerIOBridge, execID: String?)
        case stream(Channel)
    }
    private var pending: [ObjectIdentifier: Pending] = [:]

    init(router: DockerRouter, requestBodies: DockerUpgradeRequestBodyStore) {
        self.router = router
        self.requestBodies = requestBodies
    }

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
        guard let body = requestBodies.body(for: channel) else {
            promise.fail(EngineError(.badRequest, "upgrade request body is unavailable"))
            return promise.futureResult
        }
        Task { [router] in
            do {
                let requestBody = try await body.get()
                let pending: Pending
                switch target {
                case .container(let id):
                    pending = try await .buffered(io: router.containerIO(id), execID: nil)
                case .exec(let id):
                    try await router.validateAttachedExecStart(id, body: requestBody)
                    if let descriptor = try await router.startAttachedExec(id) {
                        let stream = try await ClientBootstrap(group: channel.eventLoop)
                            .channelOption(ChannelOptions.autoRead, value: false)
                            .channelOption(ChannelOptions.allowRemoteHalfClosure, value: true)
                            .withConnectedSocket(descriptor)
                            .get()
                        pending = .stream(stream)
                    } else {
                        pending = try await .buffered(io: router.execIO(id), execID: id)
                    }
                }
                let key = ObjectIdentifier(channel as AnyObject)
                self.lock.withLock { self.pending[key] = pending }
                channel.closeFuture.whenComplete { _ in
                    let abandoned = self.lock.withLock { self.pending.removeValue(forKey: key) }
                    if case .stream(let stream)? = abandoned { stream.close(promise: nil) }
                }
                channel.eventLoop.execute {
                    var headers = initialResponseHeaders
                    headers.replaceOrAdd(name: "Content-Type", value: "application/vnd.docker.raw-stream")
                    promise.succeed(headers)
                }
            } catch {
                let message = "docker stream upgrade failed for \(upgradeRequest.uri): \(EngineError.message(for: error))\n"
                try? FileHandle.standardError.write(contentsOf: Data(message.utf8))
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
        let channel = context.channel
        let pipeline = channel.pipeline
        let result = channel.setOption(ChannelOptions.autoRead, value: false).flatMap {
            pipeline.removeHandler(name: "docker-http")
        }.flatMap {
            switch pending {
            case .buffered(let io, let execID):
                return pipeline.addHandler(ContainerAttachHandler(io: io)).flatMap {
                    channel.setOption(ChannelOptions.autoRead, value: true)
                }.map {
                    if let execID {
                        Task {
                            do { try await self.router.startExec(execID) }
                            catch { io.finishOutput() }
                        }
                    }
                }
            case .stream(let stream):
                return pipeline.addHandler(StreamingRelayHandler(peer: stream)).and(
                    stream.pipeline.addHandler(StreamingRelayHandler(peer: channel))
                ).flatMap { _ in
                    channel.setOption(ChannelOptions.autoRead, value: true).and(
                        stream.setOption(ChannelOptions.autoRead, value: true)
                    )
                }.map { _ in }
            }
        }
        if case .stream(let stream) = pending {
            result.whenFailure { _ in stream.close(promise: nil) }
        }
        return result
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

private final class StreamingRelayHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    private let peer: Channel

    init(peer: Channel) { self.peer = peer }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        peer.write(unwrapInboundIn(data), promise: nil)
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        peer.flush()
        context.fireChannelReadComplete()
    }

    func channelWritabilityChanged(context: ChannelHandlerContext) {
        peer.setOption(ChannelOptions.autoRead, value: context.channel.isWritable).whenFailure { _ in
            self.peer.close(promise: nil)
        }
        context.fireChannelWritabilityChanged()
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let event = event as? ChannelEvent, event == .inputClosed {
            peer.flush()
            peer.close(mode: .output, promise: nil)
            return
        }
        context.fireUserInboundEventTriggered(event)
    }

    func channelInactive(context: ChannelHandlerContext) {
        peer.flush()
        peer.close(promise: nil)
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        peer.close(promise: nil)
        context.close(promise: nil)
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

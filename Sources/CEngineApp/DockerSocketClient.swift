import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix

final class DockerSocketClient: @unchecked Sendable {
    private let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private let socketPath: String

    init(socketPath: String) { self.socketPath = socketPath }

    deinit { try? group.syncShutdownGracefully() }

    func get(_ path: String) async throws -> Data {
        let promise = group.next().makePromise(of: Data.self)
        let channel = try await ClientBootstrap(group: group)
            .channelInitializer { channel in
                channel.pipeline.addHTTPClientHandlers().flatMap {
                    channel.pipeline.addHandler(DockerResponseHandler(promise: promise))
                }
            }
            .connect(unixDomainSocketPath: socketPath).get()
        var headers = HTTPHeaders()
        headers.add(name: "Host", value: "localhost")
        headers.add(name: "Connection", value: "close")
        try await channel.writeAndFlush(HTTPClientRequestPart.head(.init(
            version: .http1_1, method: .GET, uri: path, headers: headers
        ))).get()
        try await channel.writeAndFlush(HTTPClientRequestPart.end(nil)).get()
        return try await promise.futureResult.get()
    }
}

final class DockerResponseHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPClientResponsePart
    private let promise: EventLoopPromise<Data>
    private var status: HTTPResponseStatus?
    private var body = ByteBuffer()
    private var completed = false

    init(promise: EventLoopPromise<Data>) { self.promise = promise }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let head): status = head.status
        case .body(var value): body.writeBuffer(&value)
        case .end:
            guard !completed else { return }
            completed = true
            let data = Data(body.readableBytesView)
            if status?.code ?? 500 >= 400 {
                let message = (try? JSONDecoder().decode(DockerError.self, from: data).message)
                    ?? "Docker API returned HTTP \(status?.code ?? 500)"
                promise.fail(DashboardError(message))
            } else {
                promise.succeed(data)
            }
            context.close(promise: nil)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        if !completed {
            completed = true
            promise.fail(DashboardError("The engine closed the connection before completing the response"))
        }
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        guard !completed else { return }
        completed = true
        promise.fail(error)
        context.close(promise: nil)
    }

    private struct DockerError: Decodable { let message: String }
}

struct DashboardError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

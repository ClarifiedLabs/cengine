import CEngineAPI
import CEngineCore
import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix

enum CEngineControlClient {
    static func createResourceScope(
        socketPath: String,
        ownerPID: Int32,
        resources: ContainerResourceOverride
    ) async throws -> ContainerResourceScope {
        let body = try JSONEncoder().encode(ContainerResourceScopeCreateRequest(
            ownerPID: ownerPID,
            cpus: resources.cpus,
            memoryGiB: resources.memoryGiB
        ))
        let response = try await request(
            socketPath: socketPath,
            method: .POST,
            path: "/_cengine/v1/resource-scopes",
            body: body
        )
        return try JSONDecoder().decode(ContainerResourceScope.self, from: response)
    }

    static func removeResourceScope(socketPath: String, id: String) async {
        _ = try? await request(
            socketPath: socketPath,
            method: .DELETE,
            path: "/_cengine/v1/resource-scopes/\(id)"
        )
    }

    private static func request(
        socketPath: String,
        method: HTTPMethod,
        path: String,
        body: Data = Data()
    ) async throws -> Data {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        do {
            let promise = group.next().makePromise(of: Data.self)
            let channel = try await ClientBootstrap(group: group)
                .channelInitializer { channel in
                    channel.pipeline.addHTTPClientHandlers().flatMap {
                        channel.pipeline.addHandler(ControlResponseHandler(promise: promise))
                    }
                }
                .connect(unixDomainSocketPath: socketPath).get()
            var headers: HTTPHeaders = [
                "Host": "localhost",
                "Connection": "close",
                "Content-Length": String(body.count),
            ]
            if !body.isEmpty { headers.add(name: "Content-Type", value: "application/json") }
            try await channel.writeAndFlush(HTTPClientRequestPart.head(.init(
                version: .http1_1,
                method: method,
                uri: path,
                headers: headers
            ))).get()
            if !body.isEmpty {
                var buffer = channel.allocator.buffer(capacity: body.count)
                buffer.writeBytes(body)
                try await channel.writeAndFlush(HTTPClientRequestPart.body(.byteBuffer(buffer))).get()
            }
            try await channel.writeAndFlush(HTTPClientRequestPart.end(nil)).get()
            let response = try await promise.futureResult.get()
            try await channel.closeFuture.get()
            try await group.shutdownGracefully()
            return response
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }
}

private final class ControlResponseHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPClientResponsePart

    private let promise: EventLoopPromise<Data>
    private var status: HTTPResponseStatus?
    private var body = ByteBuffer()
    private var completed = false

    init(promise: EventLoopPromise<Data>) { self.promise = promise }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let head): status = head.status
        case .body(var chunk): body.writeBuffer(&chunk)
        case .end:
            guard !completed else { return }
            completed = true
            let data = Data(body.readableBytesView)
            let statusCode = status?.code ?? 500
            context.close().whenComplete { _ in
                if statusCode >= 400 {
                    let message = (try? JSONDecoder().decode(DockerErrorBody.self, from: data).message)
                        ?? "cengine API returned HTTP \(statusCode)"
                    self.promise.fail(EngineError(.internalError, message))
                } else {
                    self.promise.succeed(data)
                }
            }
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        if !completed {
            completed = true
            promise.fail(EngineError(.internalError, "cengine closed the resource-scope request early"))
        }
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        if !completed {
            completed = true
            context.close().whenComplete { _ in self.promise.fail(error) }
        } else {
            context.close(promise: nil)
        }
    }
}

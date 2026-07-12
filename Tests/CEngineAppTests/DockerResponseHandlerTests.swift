import Foundation
import NIOCore
import NIOEmbedded
import NIOHTTP1
import Testing
@testable import CEngineApp

@Suite struct DockerResponseHandlerTests {
    @Test func failsThePromiseWhenConnectionClosesBeforeResponseCompletes() async throws {
        let channel = EmbeddedChannel()
        let promise = channel.eventLoop.makePromise(of: Data.self)
        try channel.pipeline.syncOperations.addHandler(DockerResponseHandler(promise: promise))

        try channel.writeInbound(HTTPClientResponsePart.head(.init(version: .http1_1, status: .ok)))
        channel.pipeline.fireChannelInactive()

        await #expect(throws: DashboardError.self) {
            _ = try await promise.futureResult.get()
        }
    }

    @Test func failsThePromiseWhenConnectionClosesWithNoResponseAtAll() async throws {
        let channel = EmbeddedChannel()
        let promise = channel.eventLoop.makePromise(of: Data.self)
        try channel.pipeline.syncOperations.addHandler(DockerResponseHandler(promise: promise))

        channel.pipeline.fireChannelInactive()

        await #expect(throws: DashboardError.self) {
            _ = try await promise.futureResult.get()
        }
    }

    @Test func deliversTheBodyAndToleratesCloseAfterCompletion() async throws {
        let channel = EmbeddedChannel()
        let promise = channel.eventLoop.makePromise(of: Data.self)
        try channel.pipeline.syncOperations.addHandler(DockerResponseHandler(promise: promise))

        try channel.writeInbound(HTTPClientResponsePart.head(.init(version: .http1_1, status: .ok)))
        var buffer = channel.allocator.buffer(capacity: 16)
        buffer.writeString("{\"ok\":true}")
        try channel.writeInbound(HTTPClientResponsePart.body(buffer))
        try channel.writeInbound(HTTPClientResponsePart.end(nil))
        channel.pipeline.fireChannelInactive()

        let data = try await promise.futureResult.get()
        #expect(String(decoding: data, as: UTF8.self) == "{\"ok\":true}")
    }

    @Test func surfacesDockerErrorBodiesAsErrors() async throws {
        let channel = EmbeddedChannel()
        let promise = channel.eventLoop.makePromise(of: Data.self)
        try channel.pipeline.syncOperations.addHandler(DockerResponseHandler(promise: promise))

        try channel.writeInbound(HTTPClientResponsePart.head(.init(version: .http1_1, status: .internalServerError)))
        var buffer = channel.allocator.buffer(capacity: 64)
        buffer.writeString("{\"message\":\"no such container\"}")
        try channel.writeInbound(HTTPClientResponsePart.body(buffer))
        try channel.writeInbound(HTTPClientResponsePart.end(nil))

        do {
            _ = try await promise.futureResult.get()
            Issue.record("expected an error response to fail the promise")
        } catch let error as DashboardError {
            #expect(error.message == "no such container")
        }
    }
}

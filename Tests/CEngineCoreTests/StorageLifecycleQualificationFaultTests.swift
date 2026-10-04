#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

@Suite struct StorageLifecycleQualificationFaultTests {
    private typealias Wire = StorageLifecycleShimProtocol

    @Test func qualificationWireCasesAreClosedAndCompileOnly() throws {
        let ordinary = try Wire.encode(.init(sequence: 1, operation: .stop, reply: false))
        let text = String(decoding: ordinary, as: UTF8.self)
        for name in ["qualificationRevokeServiceProof", "qualificationCheckLiveVM"] {
            let bytes = Data(text.replacingOccurrences(of: "\"stop\"", with: "\"\(name)\"").utf8)
            #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
            let request = try Wire.decode(bytes)
            #expect(request.operation.rawValue == name)
            #expect(!request.operation.transfersDescriptor)
            #expect(request.operation.isRepeatable == (name == "qualificationCheckLiveVM"))
            #expect(try Wire.encode(request) == bytes)
            let reply = Wire.Frame(sequence: 1, operation: request.operation, reply: true)
            #expect(try Wire.decode(Wire.encode(reply)).reply)
            for field in ["receipt", "running", "configuration", "command", "greeting", "binding", "ready"] {
                let injected = Data(("{\"\(field)\":null," + String(decoding: bytes, as: UTF8.self).dropFirst()).utf8)
                #expect(throws: (any Error).self) { try Wire.decode(injected) }
            }
            #else
            // Ordinary builds must not even recognize qualification wire cases.
            #expect(throws: (any Error).self) { try Wire.decode(bytes) }
            #endif
        }
    }

    #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION && DEBUG
    @Test func productionConnectionRejectsFaultsBeforeIOWithoutClosingChannel() async throws {
        var fds: [Int32] = [-1, -1]
        try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        let local = FileHandle(fileDescriptor: fds[0], closeOnDealloc: true)
        let peer = FileHandle(fileDescriptor: fds[1], closeOnDealloc: true)
        let connection = try StorageLifecycleShimConnection.testing(borrowedFD: local.fileDescriptor)
        defer { connection.cancel() }
        for _ in 0..<2 {
            await #expect(throws: (any Error).self) { try await connection.qualificationRevokeServiceProof() }
            await #expect(throws: (any Error).self) { try await connection.qualificationCheckLiveVM() }
        }
        var byte: UInt8 = 0
        #expect(Darwin.recv(peer.fileDescriptor, &byte, 1, MSG_DONTWAIT) == -1)
        #expect(errno == EAGAIN || errno == EWOULDBLOCK) // Neither a request nor EOF.
    }
    #endif
}
#endif

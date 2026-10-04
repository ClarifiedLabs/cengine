#if os(macOS)
import CEngineCore
@testable import CEngineRuntime
import Darwin
import Foundation
import Testing

@Suite("Lifecycle child terminal diagnostics", .serialized)
struct StorageLifecycleChildFailureTests {
    private typealias Child = StorageLifecycleChildProcess

    private func terminal(_ code: String, id: UInt64 = 1) -> Data {
        Data("{\"error\":\"\(code)\",\"request_id\":\(id),\"version\":\"storage-child-lifecycle.v2\"}".utf8)
    }

    @Test(arguments: Child.TerminalCode.allCases)
    func fatalReplyFencesAndRetainsFirstOperation(_ code: StorageLifecycleChildProcess.TerminalCode) async throws {
        let channel = try AttachmentSocketPair()
        let child = try channel.adoptingChild()
        defer { child.close() }
        let raw = terminal(code.rawValue)
        let peer = PeerFixtureWorker {
            let request = try AttachmentWire.readFrame(channel.second)
            guard request.rights.isEmpty else { throw AttachmentTestFailure.invalidFrame }
            try AttachmentWire.sendFrame(raw, on: channel.second)
            var byte: UInt8 = 0
            return recv(channel.second, &byte, 1, 0) == 0
        }
        defer { precondition(peer.wait(milliseconds: 15_000), "terminal peer did not join") }
        let first = try await capture { try child.takeover() }
        #expect(first.operation == "takeover")
        #expect(first.cause == .rejected(code))
        let next = try await capture { _ = try child.controllerCSR() }
        #expect(next == first)
        #expect(try await peer.value())
    }

    @Test func malformedTerminalCannotMasqueradeAsTypedFailure() async throws {
        let valid = String(decoding: terminal("fatal-timeout"), as: UTF8.self)
        let replies = [
            valid.replacingOccurrences(of: "fatal-timeout", with: "fatal-unknown"),
            valid.replacingOccurrences(of: "\"request_id\":1", with: "\"request_id\":2"),
            valid.replacingOccurrences(of: "\"request_id\":1", with: "\"request_id\":1,\"request_id\":1"),
            valid.replacingOccurrences(of: "lifecycle.v2", with: "lifecycle.v1"),
            "{\"data\":\"\"," + valid.dropFirst(),
            valid + "\n",
            valid.replacingOccurrences(of: "fatal-timeout", with: "workload-unavailable")
        ]
        for reply in replies {
            let channel = try AttachmentSocketPair()
            let child = try channel.adoptingChild()
            defer { child.close() }
            let peer = PeerFixtureWorker {
                _ = try AttachmentWire.readFrame(channel.second)
                try AttachmentWire.sendFrame(Data(reply.utf8), on: channel.second)
                var byte: UInt8 = 0
                return recv(channel.second, &byte, 1, 0) == 0
            }
            defer { precondition(peer.wait(milliseconds: 15_000), "malformed peer did not join") }
            let failure = try await capture { try child.takeover() }
            #expect(failure.operation == "takeover")
            #expect(failure.cause == .invalidReply)
            #expect(try await peer.value())
        }
    }

    @Test func peerEOFNamesTheOriginalOperation() async throws {
        let channel = try AttachmentSocketPair()
        let child = try channel.adoptingChild()
        defer { child.close() }
        let peer = PeerFixtureWorker {
            _ = try AttachmentWire.readFrame(channel.second)
            shutdown(channel.second, SHUT_WR)
        }
        defer { precondition(peer.wait(milliseconds: 15_000), "EOF peer did not join") }
        let failure = try await capture { _ = try child.controllerCSR() }
        #expect(failure.operation == "controller-csr")
        #expect(failure.cause == .connectionClosed)
        #expect(try await capture { try child.takeover() } == failure)
        try await peer.value()
    }

    private func capture(_ body: @escaping @Sendable () throws -> Void) async throws -> Child.ExchangeFailure {
        do {
            try await attachmentThread(body)
            throw AttachmentTestFailure.invalidFrame
        } catch let failure as Child.ExchangeFailure {
            return failure
        }
    }
}
#endif

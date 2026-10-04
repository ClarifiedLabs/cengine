import CEngineCore
import Darwin
import Foundation
import Testing
@preconcurrency import XPC
@testable import StorageControllerRuntime

@Suite struct StorageLifecycleRootColdClientTests {
    private typealias W = StorageLifecycleColdRootProtocol
    private func request() throws -> W.Request {
        try .init(requestID: .init(UUID().uuidString.lowercased()), body: .complete(
            operationID: UUID().uuidString.lowercased(), signedOpenSHA256: String(repeating: "a", count: 64)))
    }
    @Test func nestedColdProofBudgetDoesNotWidenResumeOrUnknownOperations() throws {
        #expect(try StorageLifecycleRootClient.recoveryBudget(operation: W.xpcOperation) == 120)
        #expect(try StorageLifecycleRootClient.recoveryBudget(operation: StorageLifecycleResumeRootProtocol.xpcOperation) == 30)
        #expect(throws: (any Error).self) {
            try StorageLifecycleRootClient.recoveryBudget(operation: "unknown")
        }
    }

    @Test func coldEnvelopeRequiresThreeObservedDescriptors() throws {
        let request = try request()
        let fd = open(NSTemporaryDirectory(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        defer { close(fd) }
        let message = try StorageLifecycleRootClient.coldMessage(request, pathFD: fd, rootFD: fd, lockFD: fd)
        var keys = Set<String>()
        xpc_dictionary_apply(message) { key, _ in keys.insert(String(cString: key)); return true }
        #expect(keys == ["operation", "request", "path-lock", "store-root", "daemon-lock"])
        #expect(String(cString: xpc_dictionary_get_string(message, "operation")!) == W.xpcOperation)
        for key in ["path-lock", "store-root", "daemon-lock"] {
            let copy = xpc_dictionary_dup_fd(message, key)
            #expect(copy >= 0)
            if copy >= 0 { close(copy) }
        }
        var length = 0
        let bytes = try #require(xpc_dictionary_get_data(message, "request", &length))
        #expect(try W.decodeRequest(Data(bytes: bytes, count: length)) == request)
        for fds: (Int32, Int32, Int32) in [(-1, fd, fd), (fd, -1, fd), (fd, fd, -1)] {
            #expect(throws: (any Error).self) {
                try StorageLifecycleRootClient.coldMessage(request, pathFD: fds.0, rootFD: fds.1, lockFD: fds.2)
            }
        }
    }
    @Test func resumeUsesDistinctOperationAndExactCorrelationWithObservedDescriptors() throws {
        typealias R = StorageLifecycleResumeRootProtocol
        let request = try R.Request(requestID: .init(UUID().uuidString.lowercased()), body: .complete(
            operationID: UUID().uuidString.lowercased(), signedOpenSHA256: String(repeating: "a", count: 64)))
        let fd = open(NSTemporaryDirectory(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        defer { close(fd) }
        let message = try StorageLifecycleRootClient.resumeMessage(request, pathFD: fd, rootFD: fd, lockFD: fd)
        var keys = Set<String>()
        xpc_dictionary_apply(message) { key, _ in keys.insert(String(cString: key)); return true }
        #expect(keys == ["operation", "request", "path-lock", "store-root", "daemon-lock"])
        #expect(String(cString: xpc_dictionary_get_string(message, "operation")!) == R.xpcOperation)
        for key in ["path-lock", "store-root", "daemon-lock"] {
            let copy = xpc_dictionary_dup_fd(message, key)
            #expect(copy >= 0)
            if copy >= 0 { close(copy) }
        }
        for fds: (Int32, Int32, Int32) in [(-1, fd, fd), (fd, -1, fd), (fd, fd, -1)] {
            #expect(throws: (any Error).self) {
                try StorageLifecycleRootClient.resumeMessage(request, pathFD: fds.0, rootFD: fds.1, lockFD: fds.2)
            }
        }
        let denied = try R.Reply(for: request, body: .failure(.blocked))
        do {
            _ = try StorageLifecycleRootClient.decodeResumeResponse(R.encode(denied), for: request)
            Issue.record("helper denial accepted")
        } catch let failure as StorageLifecycleRootClient.Failure { #expect(failure.code == .blocked) }
        let other = try R.Request(requestID: .init(UUID().uuidString.lowercased()), body: request.body)
        #expect(throws: (any Error).self) { try StorageLifecycleRootClient.decodeResumeResponse(R.encode(denied), for: other) }
        let cold = try self.request(), coldReply = try W.Reply(for: cold, body: .failure(.blocked))
        #expect(throws: (any Error).self) { try StorageLifecycleRootClient.decodeResumeResponse(W.encode(coldReply), for: request) }
    }

    @Test func exactCorrelationPrecedesHelperError() throws {
        let request = try request(), denied = try W.Reply(for: request, body: .failure(.blocked))
        do {
            _ = try StorageLifecycleRootClient.decodeColdResponse(W.encode(denied), for: request)
            Issue.record("helper denial accepted")
        } catch let failure as StorageLifecycleRootClient.Failure { #expect(failure.code == .blocked) }
        let other = try self.request()
        #expect(throws: (any Error).self) { try StorageLifecycleRootClient.decodeColdResponse(W.encode(denied), for: other) }
        #expect(throws: (any Error).self) { try StorageLifecycleRootClient.decodeColdResponse(W.encode(denied) + Data([10]), for: request) }
    }
}

import CEngineCore
import Darwin
import Foundation
import Testing
@testable import LifecycleChildRuntime

extension LifecycleChildSocketTests {
    private var workloadUUID: String { "11111111-1111-4111-8111-111111111111" }
    private func volumeRequest(name: String) throws -> ManagedStorageControlProtocol.ControlRequest {
        .createVolume(try .init(operation: workloadUUID, store: workloadUUID, volume: workloadUUID, name: name))
    }
    private func workloadReply(_ data: Data, id: Int) -> String {
        "{\"data\":\"\(data.base64EncodedString())\",\"request_id\":\(id),\"version\":\"storage-child-lifecycle.v2\"}"
    }
    @Test(arguments: ["workload-unavailable", "workload-failed"])
    func correlatedWorkloadUnavailablePreservesChildAndSequence(_ code: String) throws {
        let pair = try sockets(); defer { pair.forEach { Darwin.close($0) } }
        let child = try Child.adoptingTestSocket(pair[0]); defer { child.close() }
        try frame(pair[1], "{\"error\":\"\(code)\",\"request_id\":1,\"version\":\"storage-child-lifecycle.v2\"}")
        do {
            _ = try child.workloadCommand(request: .query)
            Issue.record("missing unavailable error")
        } catch Child.Failure.serviceUnavailable { #expect(code == "workload-unavailable") }
        catch Child.Failure.workloadFailed { #expect(code == "workload-failed") }
        _ = try readFrame(pair[1])
        try frame(pair[1], workloadReply(Data([42]), id: 2))
        #expect(try child.controllerCSR() == Data([42]))
        #expect(String(decoding: try readFrame(pair[1]), as: UTF8.self).contains("\"request_id\":2"))
    }

    @Test(arguments: [
        #"{"error":"unknown","request_id":1,"version":"storage-child-lifecycle.v2"}"#,
        #"{"error":"workload-unavailable","request_id":2,"version":"storage-child-lifecycle.v2"}"#,
        #"{"error":"workload-unavailable","request_id":1,"version":"wrong"}"#,
        #"{"data":"","error":"workload-unavailable","request_id":1,"version":"storage-child-lifecycle.v2"}"#,
        #"{"error":"workload-unavailable","extra":0,"request_id":1,"version":"storage-child-lifecycle.v2"}"#,
        #"{"error":"workload-unavailable","request_id":1,"request_id":1,"version":"storage-child-lifecycle.v2"}"#
    ])
    func malformedUnavailablePermanentlyCloses(_ reply: String) throws {
        try malformedWorkloadFailureCloses(reply)
        try malformedWorkloadFailureCloses(reply.replacingOccurrences(of: "workload-unavailable", with: "workload-failed"))
    }
    private func malformedWorkloadFailureCloses(_ reply: String) throws {
        let pair = try sockets(); defer { pair.forEach { Darwin.close($0) } }
        let child = try Child.adoptingTestSocket(pair[0]); defer { child.close() }
        try frame(pair[1], reply)
        #expect(throws: (any Error).self) { try child.workloadCommand(request: .query) }
        _ = try readFrame(pair[1])
        #expect(throws: (any Error).self) { try child.controllerCSR() }
        var byte: UInt8 = 0
        #expect(recv(pair[1], &byte, 1, 0) == 0)
    }

    @Test(arguments: ["workload-unavailable", "workload-failed"])
    func unavailableNotPermittedForLifecycleCommands(_ code: String) throws {
        let pair = try sockets(); defer { pair.forEach { Darwin.close($0) } }
        let child = try Child.adoptingTestSocket(pair[0]); defer { child.close() }
        try frame(pair[1], "{\"error\":\"\(code)\",\"request_id\":1,\"version\":\"storage-child-lifecycle.v2\"}")
        #expect(throws: (any Error).self) { try child.controllerCSR() }
        _ = try readFrame(pair[1])
        var byte: UInt8 = 0
        #expect(recv(pair[1], &byte, 1, 0) == 0)
    }

    @Test func connectWorkloadFailurePreservesLifecycleAndSequence() throws {
        let pair = try sockets(), stream = try sockets()
        defer { (pair + stream).forEach { Darwin.close($0) } }
        let child = try Child.adoptingTestSocket(pair[0]); defer { child.close() }
        try frame(pair[1], #"{"error":"workload-failed","request_id":1,"version":"storage-child-lifecycle.v2"}"#)
        do { try child.connectWorkload(socket: stream[0]); Issue.record("missing workload failure") }
        catch Child.Failure.workloadFailed { }
        #expect(String(decoding: try readFrame(pair[1]), as: UTF8.self) == #"{"operation":"connect-workload","request_id":1,"version":"storage-child-lifecycle.v2"}"#)
        #expect(fcntl(stream[0], F_GETFD) >= 0)
        // The correlated failure is thrown outside the channel-closing catch.
        try frame(pair[1], workloadReply(Data([42]), id: 2))
        #expect(try child.controllerCSR() == Data([42]))
        #expect(String(decoding: try readFrame(pair[1]), as: UTF8.self).contains("\"request_id\":2"))
    }

    @Test(arguments: [
        #"{"error":"workload-unavailable","request_id":1,"version":"storage-child-lifecycle.v2"}"#,
        #"{"error":"unknown","request_id":1,"version":"storage-child-lifecycle.v2"}"#,
        #"{"error":"workload-failed","request_id":2,"version":"storage-child-lifecycle.v2"}"#,
        #"{"error":"workload-failed","request_id":1,"version":"wrong"}"#,
        #"{"data":"","error":"workload-failed","request_id":1,"version":"storage-child-lifecycle.v2"}"#,
        #"{"error":"workload-failed","extra":0,"request_id":1,"version":"storage-child-lifecycle.v2"}"#,
        #"{"error":"workload-failed","request_id":1,"request_id":1,"version":"storage-child-lifecycle.v2"}"#,
        #"{"error":"workload-failed","request_id":1.0,"version":"storage-child-lifecycle.v2"}"#,
        #"{ "error":"workload-failed","request_id":1,"version":"storage-child-lifecycle.v2"}"#,
        #"{"data":"AQ==","request_id":1,"version":"storage-child-lifecycle.v2"}"#
    ])
    func malformedConnectWorkloadFailureCloses(_ reply: String) throws {
        let pair = try sockets(), stream = try sockets()
        defer { (pair + stream).forEach { Darwin.close($0) } }
        let child = try Child.adoptingTestSocket(pair[0]); defer { child.close() }
        try frame(pair[1], reply)
        #expect(throws: (any Error).self) { try child.connectWorkload(socket: stream[0]) }
        _ = try readFrame(pair[1])
        #expect(throws: (any Error).self) { try child.controllerCSR() }
        var byte: UInt8 = 0
        #expect(recv(pair[1], &byte, 1, 0) == 0)
        #expect(fcntl(stream[0], F_GETFD) >= 0)
    }

    @Test(arguments: [UInt32(0), UInt32(65_537)])
    func connectWorkloadKeepsSmallReplyFrameLimit(_ size: UInt32) throws {
        let pair = try sockets(), stream = try sockets()
        defer { (pair + stream).forEach { Darwin.close($0) } }
        let child = try Child.adoptingTestSocket(pair[0]); defer { child.close() }
        var header = size.bigEndian
        try withUnsafeBytes(of: &header) { try write(pair[1], Data($0)) }
        #expect(throws: (any Error).self) { try child.connectWorkload(socket: stream[0]) }
        _ = try readFrame(pair[1])
        #expect(throws: (any Error).self) { try child.controllerCSR() }
        var byte: UInt8 = 0
        #expect(recv(pair[1], &byte, 1, 0) == 0)
    }

    @Test func everyTypedWorkloadCommandUsesClosedNestedJSONAndFreshIDs() throws {
        typealias Controller = ManagedStorageControlProtocol
        let id = workloadUUID, key = String(repeating: "a", count: 64)
        let binding = try Controller.Binding(store: id, volume: id, attachment: id, prepare: id,
            container: key, launch: id, key: key, role: .prepare, mode: .readWrite)
        let receipt = try Controller.Receipt(schema: 3, store: id, volume: id, attachment: id,
            prepare: id, launch: id, revision: UInt64.max)
        let reserve = try Controller.ReserveRequest(operation: id, prepare: id, attachments: [binding])
        let requests: [Controller.ControlRequest] = [
            .query,
            .reservePrepare(reserve),
            .registerAttachment(try .init(operation: id, binding: binding)),
            .retire(try .init(operation: id, store: id, volume: id, attachment: id, launch: id)),
            .completePrepare(try .init(operation: id, prepare: id, receipts: [receipt],
                attestation: .init(prepare: id, succeeded: true, cleanCopyUp: false))),
            .replacePrepare(try .init(operation: id, prepare: id, receipts: [receipt], successor: reserve)),
            try volumeRequest(name: "<volume>&/\"\\\n\u{2028}\u{2029}é"),
            .deleteVolume(try .init(operation: id, store: id, volume: id))
        ]
        let pair = try sockets(); defer { pair.forEach { Darwin.close($0) } }
        let child = try Child.adoptingTestSocket(pair[0], timeout: 5); defer { child.close() }
        let done = DispatchSemaphore(value: 0)
        let rawReply = Data("{\"error\":\"CONFLICT\",\"id\":23}".utf8)
        Thread.detachNewThread {
            defer { done.signal() }
            do {
                for (index, request) in requests.enumerated() {
                    let body = String(decoding: try request.durableBytes(), as: UTF8.self)
                    let expected = "{\"body\":\(body),\"operation\":\"workload-command\",\"request_id\":\(index + 1),\"version\":\"storage-child-lifecycle.v2\"}"
                    #expect(String(decoding: try readFrame(pair[1]), as: UTF8.self) == expected)
                    try frame(pair[1], workloadReply(rawReply, id: index + 1))
                }
                #expect(String(decoding: try readFrame(pair[1]), as: UTF8.self) == "{\"operation\":\"takeover\",\"request_id\":9,\"version\":\"storage-child-lifecycle.v2\"}")
                try frame(pair[1], workloadReply(Data(), id: 9))
            } catch { Issue.record(error) }
        }
        defer { done.wait() }
        for request in requests { #expect(try child.workloadCommand(request: request) == rawReply) }
        try child.takeover()
        #expect(child.processIdentity == nil)
    }

    @Test(arguments: [0, 1]) func workloadWholeRequestLimit(extra: Int) throws {
        let empty = String(decoding: try volumeRequest(name: "").durableBytes(), as: UTF8.self)
        let baseline = "{\"body\":\(empty),\"operation\":\"workload-command\",\"request_id\":1,\"version\":\"storage-child-lifecycle.v2\"}"
        let request = try volumeRequest(name: String(repeating: "x", count: 256 * 1024 - baseline.utf8.count + extra))
        // The ordinary v1 path still has its original 64 KiB ceiling.
        #expect(throws: (any Error).self) { try request.durableBytes() }
        let pair = try sockets(); defer { pair.forEach { Darwin.close($0) } }
        let child = try Child.adoptingTestSocket(pair[0], timeout: 5); defer { child.close() }
        if extra > 0 {
            #expect(throws: (any Error).self) { try child.workloadCommand(request: request) }
            var byte: UInt8 = 0
            #expect(recv(pair[1], &byte, 1, 0) == 0) // No oversized request header was sent.
            return
        }
        let done = DispatchSemaphore(value: 0)
        Thread.detachNewThread {
            defer { done.signal() }
            do {
                let bytes = try readFrame(pair[1], limit: 256 * 1024)
                #expect(bytes.count == 256 * 1024)
                let fields = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
                #expect(fields["body"] is [String: Any])
                try frame(pair[1], workloadReply(Data([42]), id: 1))
            } catch { Issue.record(error) }
        }
        defer { done.wait() }
        #expect(try child.workloadCommand(request: request) == Data([42]))
    }

    @Test func workloadRequestLimitIncludesGoEscaping() throws {
        let pair = try sockets(); defer { pair.forEach { Darwin.close($0) } }
        let child = try Child.adoptingTestSocket(pair[0]); defer { child.close() }
        let request = try volumeRequest(name: String(repeating: "<", count: 48_000))
        #expect(throws: (any Error).self) { try child.workloadCommand(request: request) }
        var byte: UInt8 = 0
        #expect(recv(pair[1], &byte, 1, 0) == 0)
    }

    @Test(arguments: [65_537, 4 * 1024 * 1024, 4 * 1024 * 1024 + 1])
    func workloadRawResponseLimit(count: Int) throws {
        let pair = try sockets(); defer { pair.forEach { Darwin.close($0) } }
        let child = try Child.adoptingTestSocket(pair[0], timeout: 5); defer { child.close() }
        let raw = Data(repeating: 255, count: count), done = DispatchSemaphore(value: 0)
        Thread.detachNewThread {
            defer { done.signal() }
            do {
                _ = try readFrame(pair[1])
                try frame(pair[1], workloadReply(raw, id: 1))
            } catch { Issue.record(error) }
        }
        defer { done.wait() }
        if count > 4 * 1024 * 1024 {
            #expect(throws: (any Error).self) { try child.workloadCommand(request: .query) }
            #expect(throws: (any Error).self) { try child.controllerCSR() }
        } else {
            #expect(try child.workloadCommand(request: .query) == raw)
        }
    }

    // One byte above floor(4 MiB * 4 / 3) + 1024; literal avoids macro type-check blowup.
    @Test(arguments: [UInt32(0), UInt32(5_593_430)])
    func workloadReplyFrameBounds(size: UInt32) throws {
        let pair = try sockets(); defer { pair.forEach { Darwin.close($0) } }
        let child = try Child.adoptingTestSocket(pair[0]); defer { child.close() }
        var size = size.bigEndian
        try withUnsafeBytes(of: &size) { try write(pair[1], Data($0)) }
        #expect(throws: (any Error).self) { try child.workloadCommand(request: .query) }
    }

    @Test func rejectedWorkloadInputsLeaveSequenceAndBorrowedDescriptorUntouched() throws {
        let pair = try sockets(); defer { pair.forEach { Darwin.close($0) } }
        let child = try Child.adoptingTestSocket(pair[0]); defer { child.close() }
        let file = open("/dev/null", O_RDONLY); defer { Darwin.close(file) }
        #expect(throws: (any Error).self) { try child.connectWorkload(socket: file) }
        #expect(fcntl(file, F_GETFD) >= 0)
        var byte: UInt8 = 0
        #expect(recv(pair[1], &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN)
        try frame(pair[1], workloadReply(Data([42]), id: 1))
        #expect(try child.workloadCommand(request: .query) == Data([42]))
        #expect(String(decoding: try readFrame(pair[1]), as: UTF8.self) == "{\"body\":{\"id\":0,\"query\":{}},\"operation\":\"workload-command\",\"request_id\":1,\"version\":\"storage-child-lifecycle.v2\"}")
    }

    @Test func workloadLastUInt64RequestNeverWraps() throws {
        let pair = try sockets(); defer { pair.forEach { Darwin.close($0) } }
        let child = try Child.adoptingTestSocket(pair[0], sequence: UInt64.max - 1); defer { child.close() }
        try frame(pair[1], "{\"data\":\"AQ==\",\"request_id\":18446744073709551615,\"version\":\"storage-child-lifecycle.v2\"}")
        #expect(try child.workloadCommand(request: .query) == Data([1]))
        #expect(String(decoding: try readFrame(pair[1]), as: UTF8.self) == "{\"body\":{\"id\":0,\"query\":{}},\"operation\":\"workload-command\",\"request_id\":18446744073709551615,\"version\":\"storage-child-lifecycle.v2\"}")
        #expect(throws: (any Error).self) { try child.workloadCommand(request: .query) }
        var byte: UInt8 = 0
        #expect(recv(pair[1], &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN)
    }
}

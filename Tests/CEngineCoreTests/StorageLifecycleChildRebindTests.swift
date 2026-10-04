#if os(macOS)
import CEngineCore
@testable import CEngineRuntime
import CryptoKit
import Darwin
import Foundation
import Testing

@Suite("Lifecycle child staged service rebind", .serialized)
struct StorageLifecycleChildRebindTests {
    private typealias Child = StorageLifecycleChildProcess
    private typealias L = StorageLifecycleProtocol
    private struct Inputs: Sendable {
        let change: L.ServiceChangeRequest
        let boot: Child.Boot
    }
    private func inputs() throws -> Inputs {
        struct Fixture: Decodable {
            struct Vector: Decodable { let name: String; let challenge: StorageLifecycleChildProtocol.Challenge }
            let vectors: [Vector]
        }
        struct CertificateFixture: Decodable {
            struct Binding: Decodable { let root_der: Data }
            let service_binding: Binding
        }
        let fixtures = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Fixtures/storage-bootstrap")
        let vector = try JSONDecoder().decode(Fixture.self,
            from: Data(contentsOf: fixtures.appendingPathComponent("lifecycle-child-service-v2.json")))
        let challenge = try #require(vector.vectors.first { $0.name == "service_change_result" }).challenge
        let trust = try #require(challenge.boot), change = try #require(challenge.changeRequest)
        let der = try JSONDecoder().decode(CertificateFixture.self,
            from: Data(contentsOf: fixtures.appendingPathComponent("child-startup-v2.json"))).service_binding.root_der
        // The socket peer exercises parent shape validation only. ROOT signature,
        // certificate URI/SPKI and actual CA-key non-reuse are the child's checks.
        let boot = try Child.Boot(certificateDER: der, identity: trust.identity, rootDER: der,
            serverSPKI: trust.serverSPKI, serviceEpoch: trust.serviceEpoch,
            signed: .init(grant: challenge.grant, signature: Data(repeating: 1, count: 64)))
        return Inputs(change: change, boot: boot)
    }
    private static func reply(_ data: Data = Data(), id: UInt64 = 1) -> Data {
        Data("{\"data\":\"\(data.base64EncodedString())\",\"request_id\":\(id),\"version\":\"storage-child-lifecycle.v2\"}".utf8)
    }

    @Test func canonicalStageBorrowsOneSocketAndAcceptsOnlyEmptyReply() async throws {
        let input = try inputs(), channel = try AttachmentSocketPair(), stream = try AttachmentSocketPair()
        let child = try channel.adoptingChild(sequence: .max - 1)
        defer { child.close() }
        let flags = fcntl(stream.first, F_GETFL), descriptorFlags = fcntl(stream.first, F_GETFD)
        // Start the native peer eagerly. An async-let initializer first needs a
        // cooperative thread and can otherwise start after the client times out.
        let observed = PeerFixtureWorker {
            let frame = try AttachmentWire.readFrame(channel.second)
            defer { frame.rights.forEach { Darwin.close($0) } }
            guard frame.rights.count == 1 else { throw AttachmentTestFailure.invalidFrame }
            try AttachmentWire.send(Data([42]), on: frame.rights[0])
            try AttachmentWire.sendFrame(Self.reply(id: .max), on: channel.second)
            return frame.data
        }
        defer { precondition(observed.wait(milliseconds: 15_000), "rebind peer did not join") }
        try await attachmentThread { try child.stageServiceRebind(socket: stream.first, change: input.change, boot: input.boot) }
        let bytes = try await observed.value()
        let bootJSON = String(decoding: try L.encode(input.boot), as: UTF8.self)
        let changeJSON = String(decoding: try L.encode(input.change), as: UTF8.self)
        let expected = "{\"body\":{\"boot\":\(bootJSON),\"change\":\(changeJSON)},\"operation\":\"stage-service-rebind\",\"request_id\":18446744073709551615,\"version\":\"storage-child-lifecycle.v2\"}"
        #expect(bytes == Data(expected.utf8))
        #expect(try AttachmentWire.readBytes(stream.second, count: 1).data == Data([42]))
        let statusFlags = O_ACCMODE | O_NONBLOCK | O_APPEND | O_ASYNC | O_SYNC | O_DSYNC
        #expect(fcntl(stream.first, F_GETFL) & statusFlags == flags & statusFlags)
        #expect(fcntl(stream.first, F_GETFD) == descriptorFlags)
        child.close()
        try AttachmentWire.send(Data([43]), on: stream.first)
        #expect(try AttachmentWire.readBytes(stream.second, count: 1).data == Data([43]))
        stream.closeFirst()
        var byte: UInt8 = 0
        #expect(recv(stream.second, &byte, 1, 0) == 0)
    }

    @Test func mismatchedGrantIdentityEpochAndTrustNeverSendOrConsumeSequence() async throws {
        let input = try inputs(), channel = try AttachmentSocketPair(), stream = try AttachmentSocketPair()
        let child = try channel.adoptingChild()
        defer { child.close() }
        let prior = input.change.predecessor, original = input.boot
        for field in 0..<6 {
            let identity = try L.Identity(store: original.identity.store,
                generation: original.identity.generation + (field == 1 ? 1 : 0), binding: original.identity.binding)
            let grant = try L.Grant(operation: prior.grant.operation, id: prior.grant.id, identity: identity,
                serial: prior.grant.serial - (field == 0 ? 1 : 0), expectedEpoch: prior.grant.expectedEpoch, newKey: prior.grant.newKey)
            var boot = try Child.Boot(certificateDER: original.certificateDER, identity: identity, rootDER: original.rootDER,
                serverSPKI: field == 3 ? prior.boot.serverSPKI : original.serverSPKI,
                serviceEpoch: field == 2 ? prior.boot.serviceEpoch : original.serviceEpoch,
                signed: .init(grant: grant, signature: original.signed.signature))
            var change = input.change
            if field == 4 {
                let trust = try StorageLifecycleBootTrust(identity: prior.boot.identity, serviceEpoch: prior.boot.serviceEpoch,
                    tlsRootSHA256: SHA256.hash(data: original.rootDER).map { String(format: "%02x", $0) }.joined(),
                    serverSPKI: prior.boot.serverSPKI, bootstrapKey: prior.boot.bootstrapKey)
                change = try .init(operationID: change.operationID,
                    predecessor: .init(grant: prior.grant, context: prior.context, openRevision: prior.openRevision, boot: trust))
            }
            if field == 5 {
                // Synthesized Boot decoding can bypass its constructor: validate at use.
                let encoded = String(decoding: try L.encode(boot), as: UTF8.self)
                boot = try JSONDecoder().decode(Child.Boot.self, from: Data(encoded.replacingOccurrences(
                    of: "\"root_der\":\"\(boot.rootDER.base64EncodedString())\"", with: "\"root_der\":\"AQ==\"").utf8))
            }
            let changedBoot = boot, changedRequest = change
            #expect(await attachmentThreadResult {
                try child.stageServiceRebind(socket: stream.first, change: changedRequest, boot: changedBoot)
            })
            var byte: UInt8 = 0
            #expect(recv(channel.second, &byte, 1, MSG_DONTWAIT) == -1)
            #expect(errno == EAGAIN)
        }
        #expect(await attachmentThreadResult { try child.stageServiceRebind(socket: -1, change: input.change, boot: input.boot) })
        let peer = PeerFixtureWorker {
            let frame = try AttachmentWire.readFrame(channel.second)
            defer { frame.rights.forEach { Darwin.close($0) } }
            guard frame.rights.isEmpty else { throw AttachmentTestFailure.invalidFrame }
            try AttachmentWire.sendFrame(Self.reply(Data([9])), on: channel.second)
            return frame.data
        }
        defer { precondition(peer.wait(milliseconds: 15_000), "rebind peer did not join") }
        #expect(try await attachmentThread { try child.controllerCSR() } == Data([9]))
        let bytes = try await peer.value()
        #expect(String(decoding: bytes, as: UTF8.self).contains("\"request_id\":1,"))
        #expect(fcntl(stream.first, F_GETFD) >= 0)
    }

    @Test func malformedAndTruncatedStageRepliesFenceBeforeWaitingCall() async throws {
        let input = try inputs()
        let valid = String(decoding: Self.reply(), as: UTF8.self)
        let replies = [Self.reply(Data([1])), Self.reply(id: 2), Data((valid + "\n").utf8),
            Data(("{\"unknown\":0," + valid.dropFirst()).utf8),
            Data(valid.replacingOccurrences(of: "\"request_id\":1", with: "\"request_id\":1,\"request_id\":1").utf8),
            Data(valid.replacingOccurrences(of: "lifecycle.v2", with: "lifecycle.v1").utf8), Self.reply()]
        for (index, reply) in replies.enumerated() {
            let channel = try AttachmentSocketPair(), stream = try AttachmentSocketPair()
            let child = try channel.adoptingChild()
            defer { child.close() }
            let received = DispatchSemaphore(value: 0), waiting = DispatchSemaphore(value: 0)
            let peer = PeerFixtureWorker {
                let frame = try AttachmentWire.readFrame(channel.second)
                defer { frame.rights.forEach { Darwin.close($0) }; received.signal() }
                guard frame.rights.count == 1 else { throw AttachmentTestFailure.invalidFrame }
                received.signal()
                guard waiting.wait(timeout: .now() + 3) == .success else { throw AttachmentTestFailure.timeout }
                let truncated = index == replies.count - 1
                try AttachmentWire.sendFrame(reply, on: channel.second, truncate: truncated)
                if truncated { shutdown(channel.second, SHUT_WR) }
                var byte: UInt8 = 0
                return recv(channel.second, &byte, 1, 0) == 0
            }
            defer { precondition(peer.wait(milliseconds: 15_000), "rebind peer did not join") }
            let next = PeerFixtureWorker {
                guard received.wait(timeout: .now() + 3) == .success else { throw AttachmentTestFailure.timeout }
                waiting.signal()
                do { _ = try child.controllerCSR(); return false } catch { return true }
            }
            defer { precondition(next.wait(milliseconds: 15_000), "waiting rebind caller did not join") }
            #expect(await attachmentThreadResult { try child.stageServiceRebind(socket: stream.first, change: input.change, boot: input.boot) })
            let nextFailed = try await next.value(), sawEOF = try await peer.value()
            #expect(nextFailed)
            #expect(sawEOF)
            #expect(fcntl(stream.first, F_GETFD) >= 0)
            stream.closeFirst()
            var byte: UInt8 = 0
            #expect(recv(stream.second, &byte, 1, 0) == 0)
        }
    }
}
#endif

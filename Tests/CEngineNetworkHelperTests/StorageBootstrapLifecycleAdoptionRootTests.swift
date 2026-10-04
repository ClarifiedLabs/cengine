import CEngineCore
import CryptoKit
import Darwin
import Foundation
import Testing
@preconcurrency import XPC
@testable import StorageBootstrapHelper

private typealias Root = StorageLifecycleAdoptionRootProtocol
private typealias Adapter = StorageBootstrapLifecycleAdoptionRootXPC
private typealias L = StorageLifecycleProtocol
private typealias H = StorageLifecycleHandoffRootProtocol

/// Dispatch-only fixture: no native authorization or installed helper is simulated.
private final class HandoffRouteJournal: StorageLifecycleAdoptionJournal {
    let root: Data
    init(root: Data) { self.root = root }
    func load() throws -> Data? { nil }
    func rootPublicKey() throws -> Data { root }
    func checkpoint(_ bytes: Data) throws {
        Issue.record("handoff dispatch unexpectedly wrote adoption state")
        throw BootstrapFailure(.unavailable)
    }
}

private struct HandoffRouteFixture {
    let origin: StorageLifecycleAdoptionProtocol.Origin
    let completed: H.Completed
    let authority: StorageBootstrapLifecycleAdoptionAuthority
    let peer = BootstrapAuditIdentity(token: audit_token_t())
    var identity: L.Identity { completed.service.grant.identity }
    var operationID: String { completed.operationID }
    var status: H.Status {
        get throws {
            try .init(currentService: completed.predecessorService, pending: completed.signedRequest.request.pending,
                operationID: operationID, completion: nil)
        }
    }
    init(generation: UInt64 = 1) throws {
        let root = Curve25519.Signing.PrivateKey()
        let volume = try StorageIdentity.FilesystemUUID(UUID().uuidString.lowercased())
        let binding = try StorageIdentity.StoreBinding(storeID: .init(UUID().uuidString.lowercased()),
            root: .init(volumeUUID: volume, inode: 2),
            backing: .init(identity: .init(volumeUUID: volume, inode: 3), size: 4096), expectedExt4UUID: volume)
        origin = try .init(binding: .init(binding), rootPublicKey: root.publicKey.rawRepresentation,
            shimLaunchUUID: UUID().uuidString.lowercased(), specSHA256: String(repeating: "e", count: 64))
        let identity = try L.Identity(binding: binding, generation: generation)
        let predecessor = try L.Grant(operation: .initialize, id: UUID().uuidString.lowercased(), identity: identity,
            serial: 1, expectedEpoch: 0, newKey: String(repeating: "a", count: 64))
        let pending = try L.Grant(operation: .takeover, id: UUID().uuidString.lowercased(), identity: identity,
            serial: 2, expectedEpoch: 1, newKey: String(repeating: "b", count: 64))
        let epoch = UUID().uuidString.lowercased()
        let boot = try StorageLifecycleBootTrust(identity: identity, serviceEpoch: epoch,
            tlsRootSHA256: String(repeating: "c", count: 64), serverSPKI: String(repeating: "d", count: 64),
            bootstrapKey: StorageIdentity.RootPublicKey(publicData: root.publicKey.rawRepresentation).fingerprint.rawValue)
        let service = try L.ServiceState(grant: predecessor,
            context: .init(serviceEpoch: epoch, controllerEpoch: 1, controllerKey: predecessor.newKey), openRevision: 1, boot: boot)
        let request = try StorageLifecycleHandoffProtocol.Request(operationID: UUID().uuidString.lowercased(),
            predecessor: predecessor, pending: pending, serviceEpoch: epoch, openRevision: 1)
        let nonce = Data(repeating: 7, count: 32)
        let result = try StorageLifecycleHandoffProtocol.Result(request: request, nonce: nonce, appliedGrant: predecessor,
            appliedServiceEpoch: epoch, appliedRevision: 1, fenceRevision: 3)
        let receipt = try L.Receipt(grant: predecessor, nonce: nonce, serviceEpoch: epoch, revision: 1)
        completed = try .init(signedRequest: .init(request: request, signature: root.signature(for: request.signingBytes)),
            result: result, predecessorService: service, predecessorReceipt: receipt, service: service, receipt: receipt)
        let transport = StorageBootstrapLifecycleAdoptionXPC(ownerUID: geteuid(), team: "ABCDEFGHIJ",
            expectedRootPublicKey: try .init(publicData: root.publicKey.rawRepresentation), worker: .init(),
            lookupOrigin: { _ in throw BootstrapFailure(.unauthorized) },
            verifyFreshOrigin: { _, _, _ in throw BootstrapFailure(.unauthorized) },
            verifyCandidate: { _, _, _ in throw BootstrapFailure(.unauthorized) })
        authority = try .init(journal: HandoffRouteJournal(root: root.publicKey.rawRepresentation), processes: transport)
    }
    func request(recover: Bool, identity: L.Identity? = nil, operationID: String? = nil,
                 requestID: StorageIdentity.RequestID? = nil) throws -> Root.Request {
        try .init(requestID: requestID ?? .init(UUID().uuidString.lowercased()),
            body: recover ? .recoverHandoff(identity ?? self.identity, operationID: operationID ?? self.operationID)
                          : .handoffStatus(identity ?? self.identity))
    }
}

@Suite struct StorageBootstrapLifecycleAdoptionRootTests {
    private func request() throws -> Root.Request {
        try .init(requestID: .init(UUID().uuidString.lowercased()), body: .status)
    }
    private func envelope(_ request: Root.Request, descriptor: Int32? = nil) throws -> xpc_object_t {
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(message, "operation", Root.xpcOperation)
        let data = try Root.encode(request)
        data.withUnsafeBytes { xpc_dictionary_set_data(message, "request", $0.baseAddress, $0.count) }
        let fd = descriptor.map { dup($0) } ?? open("/dev/null", O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else { throw BootstrapFailure(.unavailable) }
        defer { close(fd) }
        for key in Adapter.descriptorKeys { xpc_dictionary_set_fd(message, key, fd) }
        return message
    }

    @Test func statusRoutesInBothNamespacesWithAllThreeTypedDescriptors() throws {
        let request = try request(), message = try envelope(request)
        #expect(try Adapter.decodeRequest(message) == request)
        #expect(try StorageBootstrapLifecycleRouter.validateAdmission(message) == Root.xpcOperation)
        #expect(StorageBootstrapLifecycleRouter.recognizes(Root.xpcOperation))
        for key in Adapter.descriptorKeys {
            let missing = try envelope(request)
            xpc_dictionary_set_value(missing, key, nil)
            #expect(throws: (any Error).self) { try StorageBootstrapLifecycleRouter.validateAdmission(missing) }
            xpc_dictionary_set_int64(missing, key, 3)
            #expect(throws: (any Error).self) { try Adapter.decodeRequest(missing) }
        }
    }

    @Test(arguments: ["extra", "version", "role", "wrong-operation", "operation-type", "request-type", "empty", "oversize", "noncanonical"])
    func malformedEnvelopeFailsBeforeDescriptorUse(_ kind: String) throws {
        let request = try request(), message = try envelope(request)
        switch kind {
        case "extra", "version", "role": xpc_dictionary_set_string(message, kind, "forbidden")
        case "wrong-operation": xpc_dictionary_set_string(message, "operation", "storage-lifecycle-root")
        case "operation-type": xpc_dictionary_set_int64(message, "operation", 1)
        case "request-type": xpc_dictionary_set_string(message, "request", "status")
        default:
            let bytes: Data = kind == "empty" ? Data() : kind == "oversize" ? Data(repeating: 32, count: Root.maximumPayloadBytes + 1) : try Root.encode(request) + Data([32])
            bytes.withUnsafeBytes { xpc_dictionary_set_data(message, "request", $0.baseAddress, $0.count) }
        }
        var called = false
        #expect(throws: (any Error).self) {
            try Adapter.withDescriptors(message, request: request) { _, _, _ in called = true }
        }
        #expect(!called)
    }

    @Test func duplicatesAreClosedOnSuccessFailureAndRequestMismatch() throws {
        let request = try request()
        for index in 0..<128 {
            var descriptors = [Int32](repeating: -1, count: 2)
            try #require(pipe(&descriptors) == 0)
            defer { close(descriptors[0]) }
            let message: xpc_object_t
            do {
                defer { close(descriptors[1]) }
                message = try envelope(request, descriptor: descriptors[1])
            }
            try #require(fcntl(descriptors[0], F_SETFL, O_NONBLOCK) == 0)
            var borrowed: [Int32] = []
            do {
                try Adapter.withDescriptors(message, request: request) { a, b, c in
                    borrowed = [a, b, c]
                    #expect(borrowed.allSatisfy { fcntl($0, F_GETFD) & FD_CLOEXEC != 0 })
                    if index % 2 == 0 { throw BootstrapFailure(.unavailable) }
                }
            } catch let error as BootstrapFailure { #expect(error.code == .unavailable) }
            #expect(borrowed.count == 3)
            // Release XPC's own writers. EOF proves ALL borrowed writers closed,
            // regardless of process-wide descriptor-number reuse by parallel tests.
            for key in Adapter.descriptorKeys { xpc_dictionary_set_value(message, key, nil) }
            var byte: UInt8 = 0
            #expect(read(descriptors[0], &byte, 1) == 0)
        }
        var descriptors = [Int32](repeating: -1, count: 2)
        try #require(pipe(&descriptors) == 0)
        defer { close(descriptors[0]) }
        let message: xpc_object_t
        do {
            defer { close(descriptors[1]) }
            message = try envelope(request, descriptor: descriptors[1])
        }
        try #require(fcntl(descriptors[0], F_SETFL, O_NONBLOCK) == 0)
        let other = try self.request()
        #expect(throws: (any Error).self) {
            try Adapter.withDescriptors(message, request: other) { _, _, _ in Issue.record("mismatched request used FDs") }
        }
        for key in Adapter.descriptorKeys { xpc_dictionary_set_value(message, key, nil) }
        var byte: UInt8 = 0
        #expect(read(descriptors[0], &byte, 1) == 0)
    }

    @Test(arguments: [false, true], [UInt64(1), 9_007_199_254_740_993])
    func handoffRoutesExactScopedIdentityAndOperation(recover: Bool, generation: UInt64) throws {
        let f = try HandoffRouteFixture(generation: generation), request = try f.request(recover: recover)
        let message = try envelope(request)
        #expect(try StorageBootstrapLifecycleRouter.validateAdmission(message) == Root.xpcOperation)
        var statusCalls = 0, recoverCalls = 0
        let result = try Adapter.withDescriptors(message, request: request) { _, _, _ in
            try Adapter.dispatch(request, authority: f.authority, origin: f.origin, peer: f.peer,
                handoffStatus: { identity in
                    statusCalls += 1; #expect(identity == f.identity)
                    return try f.status
                }, recoverHandoff: { identity, id in
                    recoverCalls += 1; #expect(identity == f.identity && id == f.operationID)
                    return f.completed
                })
        }
        #expect(statusCalls == (recover ? 0 : 1) && recoverCalls == (recover ? 1 : 0))
        #expect(try result == (recover ? .handoffRecovered(f.completed) : .handoffStatus(f.status)))
        let reply = try Root.Reply(for: request, body: result)
        #expect(try Root.decodeReply(Root.encode(reply), for: request) == reply)
    }

    @Test(arguments: [false, true], ["store", "binding", "missing-handler"])
    func handoffRejectsForeignScopeBeforeCallbacks(recover: Bool, mismatch: String) throws {
        let f = try HandoffRouteFixture()
        let identity = try L.Identity(store: mismatch == "store" ? UUID().uuidString.lowercased() : f.identity.store,
            generation: f.identity.generation, binding: mismatch == "binding" ? String(repeating: "f", count: 64) : f.identity.binding)
        let request = try f.request(recover: recover, identity: identity)
        var calls = 0
        do {
            if mismatch == "missing-handler" {
                _ = try Adapter.dispatch(request, authority: f.authority, origin: f.origin, peer: f.peer)
            } else {
                _ = try Adapter.dispatch(request, authority: f.authority, origin: f.origin, peer: f.peer,
                    handoffStatus: { _ in calls += 1; return try f.status },
                    recoverHandoff: { _, _ in calls += 1; return f.completed })
            }
            Issue.record("handoff accepted a foreign scope or missing handler")
        } catch let error as BootstrapFailure { #expect(error.code == .unauthorized) }
        #expect(calls == 0)
    }

    @Test(arguments: [false, true])
    func handoffRejectsCrossRequestDescriptorAndReplyReuse(recover: Bool) throws {
        let f = try HandoffRouteFixture(), request = try f.request(recover: recover)
        let message = try envelope(request)
        let body: Root.ResultBody = try recover ? .handoffRecovered(f.completed) : .handoffStatus(f.status)
        let bytes = try Root.encode(Root.Reply(for: request, body: body))
        let otherIdentity = try L.Identity(store: f.identity.store, generation: f.identity.generation + 1, binding: f.identity.binding)
        var others = [try f.request(recover: recover),
            try f.request(recover: recover, identity: otherIdentity, requestID: request.requestID),
            try f.request(recover: !recover, requestID: request.requestID)]
        if recover {
            others.append(try f.request(recover: true, operationID: UUID().uuidString.lowercased(), requestID: request.requestID))
        }
        for other in others {
            var called = false
            #expect(throws: (any Error).self) {
                try Adapter.withDescriptors(message, request: other) { _, _, _ in called = true }
            }
            #expect(!called)
            #expect(throws: (any Error).self) { try Root.decodeReply(bytes, for: other) }
        }
        let foreign = try HandoffRouteFixture()
        #expect(throws: (any Error).self) {
            try Root.Reply(for: request, body: recover ? .handoffRecovered(foreign.completed) : .handoffStatus(foreign.status))
        }
    }

    @Test(arguments: [false, true])
    func handoffCallbackFailureIsNotConvertedToCompletion(recover: Bool) throws {
        let f = try HandoffRouteFixture(), request = try f.request(recover: recover)
        do {
            _ = try Adapter.dispatch(request, authority: f.authority, origin: f.origin, peer: f.peer,
                handoffStatus: { _ in throw BootstrapFailure(.unavailable) },
                recoverHandoff: { _, _ in throw BootstrapFailure(.unavailable) })
            Issue.record("handoff callback failure was swallowed")
        } catch let error as BootstrapFailure { #expect(error.code == .unavailable) }
    }

    /// Exercises the closed proof decoder used by receive, not native Mach authentication.
    @Test func handoffProofBindsCounterNonceDeadlineAndOrigin() throws {
        typealias S = StorageLifecycleHandoffShimProtocol
        let f = try HandoffRouteFixture()
        let challenge = try S.Challenge(origin: f.origin, signed: f.completed.signedRequest,
            expected: f.completed.predecessorService, counter: 1, nonce: f.completed.result.nonce, expiresUnixMS: 30_001)
        let reply = try S.Reply(challenge: challenge, result: f.completed.result, boot: f.completed.service.boot)
        let bytes = try S.encode(reply)
        #expect(try S.decodeReply(bytes, challenge: challenge) == reply)
        #expect(challenge.isFresh(at: 1) && challenge.isFresh(at: 30_000))
        #expect(!challenge.isFresh(at: 0) && !challenge.isFresh(at: 30_001))
        for field in ["counter", "nonce", "deadline", "origin"] {
            let origin = try StorageLifecycleAdoptionProtocol.Origin(binding: f.origin.binding, rootPublicKey: f.origin.rootPublicKey,
                shimLaunchUUID: field == "origin" ? UUID().uuidString.lowercased() : f.origin.shimLaunchUUID,
                specSHA256: f.origin.specSHA256)
            let other = try S.Challenge(origin: origin, signed: challenge.signed, expected: challenge.expected,
                counter: field == "counter" ? 2 : challenge.counter,
                nonce: field == "nonce" ? Data(repeating: 8, count: 32) : challenge.nonce,
                expiresUnixMS: field == "deadline" ? 30_002 : challenge.expiresUnixMS)
            #expect(try other.digest != challenge.digest)
            #expect(throws: (any Error).self) { try S.decodeReply(bytes, challenge: other) }
        }
        #expect(throws: (any Error).self) {
            try S.Challenge(origin: f.origin, signed: challenge.signed, expected: challenge.expected,
                counter: 0, nonce: challenge.nonce, expiresUnixMS: challenge.expiresUnixMS)
        }
    }

    @Test func overallDeadlineIsNotRenewedAndScopedCheckDoesNotEscape() throws {
        let worker = StorageBootstrapLifecycleChildWorker()
        let transport = StorageBootstrapLifecycleAdoptionXPC(ownerUID: geteuid(), team: "ABCDEFGHIJ",
            expectedRootPublicKey: try .init(publicData: Data(repeating: 7, count: 32)), worker: worker,
            lookupOrigin: { _ in nil }, verifyFreshOrigin: { _, _, _ in throw BootstrapFailure(.unauthorized) },
            verifyCandidate: { _, _, _ in throw BootstrapFailure(.unauthorized) })
        try worker.perform {
            var called = false, checks = 0
            #expect(throws: (any Error).self) {
                try transport.withRequest(deadline: .now(), check: { checks += 1 }) { called = true }
            }
            #expect(!called && checks == 0)
            let deadline = DispatchTime.now() + 0.02
            #expect(throws: (any Error).self) {
                try transport.withRequest(deadline: deadline, check: { checks += 1 }) {
                    called = true
                    Thread.sleep(forTimeInterval: 0.03)
                    try transport.checkRequest()
                }
            }
            #expect(called && checks == 1)
            #expect(throws: (any Error).self) { try transport.checkRequest() }
            try transport.withRequest(deadline: .now() + 1, check: { checks += 1 }) {}
            #expect(checks == 3)
        }
    }
}

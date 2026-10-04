import CEngineCore
import CryptoKit
import Foundation
import Testing

@Suite struct StorageLifecycleAdoptionRootProtocolTests {
    private typealias Wire = StorageLifecycleAdoptionRootProtocol
    private typealias A = StorageLifecycleAdoptionProtocol
    private typealias L = StorageLifecycleProtocol
    private typealias H = StorageLifecycleHandoffProtocol
    private typealias HR = StorageLifecycleHandoffRootProtocol

    private struct HandoffFixture: Decodable {
        let root_seed: Data
        let root_public_key: Data
        let request: H.Request
        let signature: Data
        let results: [Outcome]
        struct Outcome: Decodable {
            let name: String
            let result: H.Result
        }
    }
    private func handoff(applied: Bool, includePendingSigned: Bool = true) throws -> HR.Completed {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Fixtures/storage-bootstrap/lifecycle-handoff-v1.json")
        let fixture = try JSONDecoder().decode(HandoffFixture.self, from: Data(contentsOf: url))
        let r = fixture.request
        let prior = try #require(fixture.results.first { $0.name == "predecessor" }).result
        let result = try #require(fixture.results.first { $0.name == (applied ? "pending" : "predecessor") }).result
        let root = try Curve25519.Signing.PrivateKey(rawRepresentation: fixture.root_seed)
        let boot = try StorageLifecycleBootTrust(identity: r.predecessor.identity, serviceEpoch: r.serviceEpoch,
            tlsRootSHA256: String(repeating: "c", count: 64), serverSPKI: String(repeating: "d", count: 64),
            bootstrapKey: StorageIdentity.RootPublicKey(publicData: fixture.root_public_key).fingerprint.rawValue)
        func service(_ grant: L.Grant) throws -> L.ServiceState {
            try .init(grant: grant, context: .init(serviceEpoch: r.serviceEpoch,
                controllerEpoch: grant.expectedEpoch + 1, controllerKey: grant.newKey), openRevision: r.openRevision, boot: boot)
        }
        func receipt(_ value: H.Result) throws -> L.Receipt {
            try .init(grant: value.appliedGrant, nonce: value.nonce,
                serviceEpoch: value.appliedServiceEpoch, revision: value.appliedRevision)
        }
        let pendingSigned = try L.SignedGrant(grant: r.pending, signature: root.signature(for: r.pending.signingBytes))
        let signedRequest = try H.SignedRequest(request: r, signature: fixture.signature)
        #expect(root.publicKey.rawRepresentation == fixture.root_public_key)
        #expect(signedRequest.isValidSignature(using: try .init(publicData: fixture.root_public_key)))
        return try .init(signedRequest: signedRequest, result: result,
            predecessorService: service(r.predecessor), predecessorReceipt: receipt(prior),
            service: service(result.appliedGrant), receipt: receipt(result), pendingSigned: includePendingSigned ? pendingSigned : nil)
    }
    private func adoption() throws -> A.Request {
        let uuid = try StorageIdentity.FilesystemUUID("11111111-1111-4111-8111-111111111111")
        let binding = try StorageIdentity.StoreBinding(storeID: .init(uuid.rawValue), root: .init(volumeUUID: uuid, inode: 2),
            backing: .init(identity: .init(volumeUUID: uuid, inode: 3), size: 4096), expectedExt4UUID: uuid)
        return try .init(id: uuid.rawValue, origin: .init(binding: .init(binding), rootPublicKey: Data(repeating: 7, count: 32),
            shimLaunchUUID: uuid.rawValue, specSHA256: String(repeating: "a", count: 64)), expectedEpoch: 1,
            daemonAudit: Data(repeating: 1, count: 32), daemonUniqueID: 1,
            controllerAudit: Data(repeating: 2, count: 32), controllerUniqueID: 2)
    }
    @Test func coldBaseEpochIsRequiredOnWireAndAllowsInitialEpochAboveOne() throws {
        let a = try adoption(), request = try Wire.Request(requestID: .init(UUID().uuidString.lowercased()), body: .status)
        let status = try Wire.Status(origin: a.origin, shimAudit: Data(repeating: 3, count: 32), shimUniqueID: 3,
            baseEpoch: 8, committedEpoch: 8, allocatedEpoch: 8, pending: nil, latest: nil)
        let reply = try Wire.Reply(for: request, body: .status(status)), bytes = try Wire.encode(reply)
        #expect(try Wire.decodeReply(bytes, for: request) == reply)
        let text = String(decoding: bytes, as: UTF8.self)
        for bad in [text.replacingOccurrences(of: "\"baseEpoch\":8,", with: ""),
                    text.replacingOccurrences(of: "\"baseEpoch\":8", with: "\"baseEpoch\":0"),
                    text.replacingOccurrences(of: "\"baseEpoch\":8", with: "\"baseEpoch\":9")] {
            #expect(throws: (any Error).self) { try Wire.decodeReply(Data(bad.utf8), for: request) }
        }
        #expect(throws: (any Error).self) {
            try Wire.Status(origin: a.origin, shimAudit: Data(repeating: 3, count: 32), shimUniqueID: 3,
                baseEpoch: 2, committedEpoch: 2, allocatedEpoch: 2, pending: nil, latest: a)
        }
    }
    @Test func closedRequestsAndCorrelatedReplies() throws {
        let a = try adoption()
        let status = try Wire.Status(origin: a.origin, shimAudit: Data(repeating: 3, count: 32), shimUniqueID: 3, baseEpoch: 1, committedEpoch: 1, allocatedEpoch: 2, pending: a, latest: nil)
        let cases: [(Wire.Body, Wire.ResultBody)] = [(.status, .status(status)),
            (.prepare(a), .prepared(try a.fenceIdentity)), (.complete(a), .completed(try a.fenceIdentity))]
        for (body, result) in cases {
            let request = try Wire.Request(requestID: .init(UUID().uuidString.lowercased()), body: body)
            let bytes = try Wire.encode(request)
            #expect(try Wire.decodeRequest(bytes) == request)
            let reply = try Wire.Reply(for: request, body: result)
            #expect(try Wire.decodeReply(Wire.encode(reply), for: request) == reply)
            let wrongID = try Wire.Request(requestID: .init(UUID().uuidString.lowercased()), body: body)
            #expect(throws: (any Error).self) { try Wire.decodeReply(Wire.encode(reply), for: wrongID) }
            let text = String(decoding: bytes, as: UTF8.self)
            for bad in [text + "\n", text.replacingOccurrences(of: "\"version\":", with: "\"extra\":true,\"version\":"),
                        text.replacingOccurrences(of: Wire.version, with: "old.v0")] {
                #expect(throws: (any Error).self) { try Wire.decodeRequest(Data(bad.utf8)) }
            }
            let denied = try Wire.Reply(for: request, body: .failure(.unauthorized))
            #expect(try Wire.decodeReply(Wire.encode(denied), for: request) == denied)
        }
    }
    @Test func crossOperationFieldsAndRepliesAreRejected() throws {
        let a = try adoption(), id = try StorageIdentity.RequestID(UUID().uuidString.lowercased())
        let status = try Wire.Request(requestID: id, body: .status)
        let prepare = try Wire.Request(requestID: id, body: .prepare(a))
        let complete = try Wire.Request(requestID: id, body: .complete(a))
        let text = String(decoding: try Wire.encode(prepare), as: UTF8.self)
        #expect(throws: (any Error).self) {
            try Wire.decodeRequest(Data(text.replacingOccurrences(of: "\"operation\":\"prepare\"", with: "\"operation\":\"status\"").utf8))
        }
        #expect(throws: (any Error).self) { try Wire.Reply(for: status, body: .prepared(a.fenceIdentity)) }
        let reply = try Wire.Reply(for: prepare, body: .prepared(a.fenceIdentity))
        #expect(throws: (any Error).self) { try Wire.decodeReply(Wire.encode(reply), for: complete) }
        #expect(throws: (any Error).self) { try Wire.decodeRequest(Wire.encode(reply)) }
        let badFence = try A.FenceIdentity(id: UUID().uuidString.lowercased(), epoch: 2, nativeIdentitySHA256: a.nativeIdentitySHA256)
        #expect(throws: (any Error).self) { try Wire.Reply(for: prepare, body: .prepared(badFence)) }
    }
    @Test func serviceChangeCompletionIsClosedAndExactlyCorrelated() throws {
        let f = try AdoptionServiceChangeFixture(adoption: adoption())
        let request = try Wire.Request(requestID: .init(UUID().uuidString.lowercased()),
            body: .completeServiceChange(adoption: f.adoption, change: f.change))
        let bytes = try Wire.encode(request), text = String(decoding: bytes, as: UTF8.self)
        #expect(text.contains("\"operation\":\"completeServiceChange\""))
        #expect(try Wire.decodeRequest(bytes) == request)
        let reply = try Wire.Reply(for: request, body: .serviceChanged(f.confirmation, f.result()))
        let replyBytes = try Wire.encode(reply), replyText = String(decoding: replyBytes, as: UTF8.self)
        #expect(replyText.contains("\"confirmation\":"))
        #expect(replyText.contains("\"serviceResult\":"))
        #expect(try Wire.decodeReply(replyBytes, for: request) == reply)
        for bad in [text + "\n", text.replacingOccurrences(of: "\"change\":{", with: "\"change\":{\"extra\":0,"),
                    text.replacingOccurrences(of: "\"operation\":", with: "\"confirmation\":null,\"operation\":"),
                    text.replacingOccurrences(of: "completeServiceChange", with: "complete")] {
            #expect(throws: (any Error).self) { try Wire.decodeRequest(Data(bad.utf8)) }
        }
        for bad in [replyText + "\n", replyText.replacingOccurrences(of: "\"serviceResult\":", with: "\"result\":"),
                    replyText.replacingOccurrences(of: "\"operation\":", with: "\"change\":null,\"operation\":")] {
            #expect(throws: (any Error).self) { try Wire.decodeReply(Data(bad.utf8), for: request) }
        }
        let otherChange = try StorageLifecycleProtocol.ServiceChangeRequest(operationID: UUID().uuidString.lowercased(), predecessor: f.change.predecessor)
        let otherConfirmation = try StorageLifecycleProtocol.ServiceChangeConfirmation(request: otherChange, successor: f.confirmation.successor)
        #expect(throws: (any Error).self) { try Wire.Reply(for: request, body: .serviceChanged(otherConfirmation, f.result())) }
        #expect(throws: (any Error).self) { try Wire.Reply(for: request, body: .serviceChanged(f.confirmation, f.result(revision: 3))) }
        #expect(throws: (any Error).self) { try Wire.Reply(for: request, body: .service(f.confirmation.successor)) }
        let otherRequest = try Wire.Request(requestID: .init(UUID().uuidString.lowercased()), body: request.body)
        #expect(throws: (any Error).self) { try Wire.decodeReply(replyBytes, for: otherRequest) }
        for adoption in try f.unboundAdoptions() {
            #expect(throws: (any Error).self) {
                try Wire.Request(requestID: request.requestID, body: .completeServiceChange(adoption: adoption, change: f.change))
            }
        }
        let denied = try Wire.Reply(for: request, body: .failure(.unauthorized))
        #expect(try Wire.decodeReply(Wire.encode(denied), for: request) == denied)
        // Existing normal-service packets gain no new fields.
        let normal = try Wire.Request(requestID: request.requestID, body: .service(f.adoption, f.change.predecessor.grant))
        let normalText = String(decoding: try Wire.encode(normal), as: UTF8.self)
        #expect(!normalText.contains("\"change\":"))
        #expect(!normalText.contains("\"confirmation\":"))
        #expect(!normalText.contains("\"serviceResult\":"))
    }
    @Test func handoffRequestsAreClosedAndOperationSpecific() throws {
        let completed = try handoff(applied: false), r = completed.signedRequest.request
        let id = try StorageIdentity.RequestID(UUID().uuidString.lowercased())
        let cases: [(Wire.Body, String)] = [(.handoffStatus(r.predecessor.identity), "handoffStatus"),
            (.recoverHandoff(r.predecessor.identity, operationID: r.operationID), "recoverHandoff")]
        for (body, operation) in cases {
            let request = try Wire.Request(requestID: id, body: body)
            let bytes = try Wire.encode(request), text = String(decoding: bytes, as: UTF8.self)
            #expect(try Wire.decodeRequest(bytes) == request)
            #expect(text.contains("\"operation\":\"\(operation)\""))
            var malformed = [text + "\n", "{\"unknown\":true," + text.dropFirst(),
                text.replacingOccurrences(of: "\"identity\":{", with: "\"identity\":{\"unknown\":true,"),
                text.replacingOccurrences(of: "\"identity\":", with: "\"identity\":null,\"identity\":"),
                text.replacingOccurrences(of: "\"identity\":", with: "\"adoption\":"),
                text.replacingOccurrences(of: "\"operation\":", with: "\"handoffStatus\":null,\"operation\":"),
                text.replacingOccurrences(of: "\"operation\":", with: "\"handoffCompleted\":null,\"operation\":"),
                text.replacingOccurrences(of: "\"operation\":\"\(operation)\"", with: "\"operation\":\"status\""),
                text.replacingOccurrences(of: Wire.version, with: "old.v0")]
            if operation == "handoffStatus" {
                malformed.append(text.replacingOccurrences(of: "\"operation\":", with: "\"operationID\":\"\(r.operationID)\",\"operation\":"))
                malformed.append(text.replacingOccurrences(of: "\"operation\":\"handoffStatus\"", with: "\"operation\":\"recoverHandoff\""))
            } else {
                malformed.append(text.replacingOccurrences(of: "\"operation\":\"recoverHandoff\"", with: "\"operation\":\"handoffStatus\""))
                for replacement in ["", "\"operationID\":null,", "\"operationID\":\"bad\","] {
                    malformed.append(text.replacingOccurrences(of: "\"operationID\":\"\(r.operationID)\",", with: replacement))
                }
            }
            for bad in malformed {
                #expect(bad != text)
                #expect(throws: (any Error).self) { try Wire.decodeRequest(Data(bad.utf8)) }
            }
        }
        for badID in ["", "bad", r.operationID.uppercased(), "00000000-0000-0000-0000-000000000000"] {
            #expect(throws: (any Error).self) {
                try Wire.Request(requestID: id, body: .recoverHandoff(r.predecessor.identity, operationID: badID))
            }
        }
    }

    private func checkHandoffReply(_ request: Wire.Request, body: Wire.ResultBody, nested: [String]) throws {
        let reply = try Wire.Reply(for: request, body: body)
        let bytes = try Wire.encode(reply), text = String(decoding: bytes, as: UTF8.self)
        #expect(try Wire.decodeReply(bytes, for: request) == reply)
        #expect(throws: (any Error).self) { try Wire.decodeRequest(bytes) }
        #expect(throws: (any Error).self) { try Wire.decodeReply(Wire.encode(request), for: request) }
        let otherRequestID = try Wire.Request(requestID: .init(UUID().uuidString.lowercased()), body: request.body)
        #expect(throws: (any Error).self) { try Wire.decodeReply(bytes, for: otherRequestID) }
        var malformed = [text + "\n", "{\"unknown\":true," + text.dropFirst(),
            text.replacingOccurrences(of: "\"requestID\":", with: "\"requestID\":null,\"requestID\":"),
            text.replacingOccurrences(of: request.requestID.rawValue, with: otherRequestID.requestID.rawValue),
            text.replacingOccurrences(of: reply.requestSHA256, with: String(repeating: "0", count: 64)),
            text.replacingOccurrences(of: "\"operation\":\"\(reply.operation)\"", with: "\"operation\":\"status\""),
            text.replacingOccurrences(of: "\"operation\":", with: "\"identity\":null,\"operation\":"),
            text.replacingOccurrences(of: "\"operation\":", with: "\"operationID\":null,\"operation\":"),
            text.replacingOccurrences(of: "\"operation\":", with: "\"error\":\"unauthorized\",\"operation\":")]
        for field in nested {
            malformed.append(text.replacingOccurrences(of: "\"\(field)\":{", with: "\"\(field)\":{\"unknown\":true,"))
        }
        for bad in malformed {
            #expect(bad != text)
            #expect(throws: (any Error).self) { try Wire.decodeReply(Data(bad.utf8), for: request) }
        }
        let denied = try Wire.Reply(for: request, body: .failure(.unauthorized))
        #expect(try Wire.decodeReply(Wire.encode(denied), for: request) == denied)
        #expect(throws: (any Error).self) { try Wire.decodeReply(Wire.encode(denied), for: otherRequestID) }
    }

    @Test func handoffStatusPreservesRawPendingAfterLostIssueReply() throws {
        let completed = try handoff(applied: false), r = completed.signedRequest.request
        let request = try Wire.Request(requestID: .init(UUID().uuidString.lowercased()), body: .handoffStatus(r.predecessor.identity))
        for operationID in [nil, r.operationID] as [String?] {
            // No SignedGrant was received by HOST; ROOT still reports the original raw grant.
            let status = try HR.Status(currentService: completed.predecessorService, pending: r.pending,
                operationID: operationID, completion: nil)
            try checkHandoffReply(request, body: .handoffStatus(status), nested: ["handoffStatus", "currentService", "pending", "identity"])
            let reply = try Wire.decodeReply(Wire.encode(Wire.Reply(for: request, body: .handoffStatus(status))), for: request)
            guard case .handoffStatus(let decoded) = reply.body else { Issue.record("Expected handoff status"); return }
            #expect(decoded.pending == r.pending)
            #expect(decoded.operationID == operationID && decoded.completion == nil)
        }
        let idle = try HR.Status(currentService: completed.predecessorService, pending: nil, operationID: nil, completion: nil)
        try checkHandoffReply(request, body: .handoffStatus(idle), nested: ["handoffStatus", "currentService"])
    }

    @Test(arguments: [false, true], [false, true])
    func handoffRepliesCorrelateBothOutcomesAndPreservePendingSigned(applied: Bool, includePendingSigned: Bool) throws {
        let completed = try handoff(applied: applied, includePendingSigned: includePendingSigned)
        let r = completed.signedRequest.request, identity = r.predecessor.identity
        let id = try StorageIdentity.RequestID(UUID().uuidString.lowercased())
        let statusRequest = try Wire.Request(requestID: id, body: .handoffStatus(identity))
        let recoveryRequest = try Wire.Request(requestID: id, body: .recoverHandoff(identity, operationID: r.operationID))
        let status = try HR.Status(currentService: completed.service, pending: nil, operationID: r.operationID, completion: completed)
        var completedFields = ["signedRequest", "result", "predecessorService", "predecessorReceipt", "service", "receipt", "request", "identity"]
        if includePendingSigned { completedFields.append("pendingSigned") }
        let cases: [(Wire.Request, Wire.ResultBody, [String])] = [
            (statusRequest, .handoffStatus(status), ["handoffStatus", "completion"] + completedFields),
            (recoveryRequest, .handoffRecovered(completed), ["handoffCompleted"] + completedFields)]
        let otherIdentity = try L.Identity(store: identity.store, generation: identity.generation + 1, binding: identity.binding)
        let wrongStatus = try Wire.Request(requestID: id, body: .handoffStatus(otherIdentity))
        let wrongRecovery = try Wire.Request(requestID: id, body: .recoverHandoff(otherIdentity, operationID: r.operationID))
        let wrongOperationID = try Wire.Request(requestID: id, body: .recoverHandoff(identity, operationID: UUID().uuidString.lowercased()))
        for (request, body, nested) in cases {
            try checkHandoffReply(request, body: body, nested: nested)
            let bytes = try Wire.encode(Wire.Reply(for: request, body: body))
            let otherOperation = request == statusRequest ? recoveryRequest : statusRequest
            let wrongIdentity = request == statusRequest ? wrongStatus : wrongRecovery
            for other in [otherOperation, wrongIdentity] {
                #expect(throws: (any Error).self) { try Wire.Reply(for: other, body: body) }
                #expect(throws: (any Error).self) { try Wire.decodeReply(bytes, for: other) }
            }
            if let signed = completed.pendingSigned {
                let unrelated = try L.SignedGrant(grant: r.predecessor, signature: signed.signature)
                let text = String(decoding: bytes, as: UTF8.self)
                let bad = text.replacingOccurrences(of: String(decoding: try L.encode(signed), as: UTF8.self),
                    with: String(decoding: try L.encode(unrelated), as: UTF8.self))
                #expect(bad != text)
                #expect(throws: (any Error).self) { try Wire.decodeReply(Data(bad.utf8), for: request) }
            }
        }
        let recovered = try Wire.Reply(for: recoveryRequest, body: .handoffRecovered(completed))
        #expect(throws: (any Error).self) { try Wire.Reply(for: wrongOperationID, body: .handoffRecovered(completed)) }
        #expect(throws: (any Error).self) { try Wire.decodeReply(Wire.encode(recovered), for: wrongOperationID) }
        guard case .handoffRecovered(let decoded) = try Wire.decodeReply(Wire.encode(recovered), for: recoveryRequest).body else {
            Issue.record("Expected handoff completion"); return
        }
        #expect(decoded.result.appliedGrant == (applied ? r.pending : r.predecessor))
        #expect(decoded.receipt.revision == decoded.result.appliedRevision)
        #expect(decoded.receipt.revision < decoded.result.fenceRevision)
        #expect(decoded.signedRequest == completed.signedRequest)
        #expect(decoded.pendingSigned == completed.pendingSigned)
        if includePendingSigned {
            let signed = try #require(decoded.pendingSigned)
            #expect(signed.grant == r.pending)
        } else {
            #expect(decoded.pendingSigned == nil)
        }
    }

    @Test func statusRejectsUnboundAndImpossibleEpochs() throws {
        let a = try adoption()
        for (committed, allocated) in [(UInt64(0), UInt64(0)), (2, 1), (1, 2), (2, 2)] {
            #expect(throws: (any Error).self) {
                try Wire.Status(origin: a.origin, shimAudit: Data(repeating: 3, count: 32), shimUniqueID: 3, baseEpoch: 1, committedEpoch: committed, allocatedEpoch: allocated, pending: nil, latest: nil)
            }
        }
        #expect(throws: (any Error).self) {
            try Wire.Status(origin: a.origin, shimAudit: Data(repeating: 3, count: 32), shimUniqueID: 3, baseEpoch: 1, committedEpoch: 1, allocatedEpoch: 3, pending: a, latest: nil)
        }
        let value = try Wire.Status(origin: a.origin, shimAudit: Data(repeating: 3, count: 32), shimUniqueID: 3, baseEpoch: 1, committedEpoch: 2, allocatedEpoch: 2, pending: nil, latest: a)
        try value.validate()
    }
}

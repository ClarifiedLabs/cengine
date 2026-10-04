import CEngineCore
import CryptoKit
import Foundation
import Testing

@Suite("Lifecycle live service and bounded change wire")
struct StorageLifecycleServiceChangeProtocolTests {
    private typealias L = StorageLifecycleProtocol
    private typealias C = StorageLifecycleChildProtocol
    private typealias R = StorageLifecycleRootProtocol
    private struct Vectors: Decodable {
        let root_public_key: Data
        let vectors: [Vector]
        struct Vector: Decodable {
            let value: L.ServiceResult
            let canonical_json: String
            let signing_bytes: Data
            let signature: Data
        }
    }
    private func vectors() throws -> Vectors {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Fixtures/storage-bootstrap/lifecycle-service-result-v2.json")
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url))
    }
    private struct ChangeVectors: Decodable {
        let version: String
        let root_public_key: Data
        let vectors: [Vector]
        struct Vector: Decodable {
            let value: L.SignedServiceChange
            let canonical_json: String
            let signing_bytes: Data
            let signature: Data
        }
    }
    @Test func sharedGoSignedServiceChangeVectors() throws {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Fixtures/storage-bootstrap/lifecycle-service-change-v2.json")
        let fixture = try JSONDecoder().decode(ChangeVectors.self, from: Data(contentsOf: url))
        let root = try StorageIdentity.RootPublicKey(publicData: fixture.root_public_key)
        #expect(!fixture.vectors.isEmpty)
        for v in fixture.vectors {
            #expect(v.value.request.signingBytes == v.signing_bytes)
            #expect(v.value.signature == v.signature && v.value.isValidSignature(using: root))
            // canonical_json is Go declaration order (the signing order); the
            // Swift wire form is sorted-key canonical. Values must agree.
            #expect(try JSONDecoder().decode(L.SignedServiceChange.self, from: Data(v.canonical_json.utf8)) == v.value)
            let wire = try L.encode(v.value)
            #expect(try L.decode(L.SignedServiceChange.self, from: wire) == v.value)
            let other = try StorageIdentity.RootPublicKey(publicData: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)
            #expect(!v.value.isValidSignature(using: other))
            var tampered = v.signature; tampered[0] ^= 1
            #expect(try !L.SignedServiceChange(request: v.value.request, signature: tampered).isValidSignature(using: root))
            #expect(throws: (any Error).self) { try L.SignedServiceChange(request: v.value.request, signature: Data(v.signature.prefix(63))) }
            #expect(throws: (any Error).self) {
                try L.decode(L.SignedServiceChange.self, from: Data("{\"extra\":0,".utf8) + wire.dropFirst())
            }
        }
    }
    @Test func sharedGoServiceResultSigningAndClosedWire() throws {
        let fixture = try vectors()
        let key = try Curve25519.Signing.PublicKey(rawRepresentation: fixture.root_public_key)
        for v in fixture.vectors {
            #expect(v.value.signingBytes == v.signing_bytes)
            #expect(key.isValidSignature(v.signature, for: v.value.signingBytes))
            #expect(try L.decode(L.ServiceResult.self, from: Data(v.canonical_json.utf8)) == v.value)
            #expect(v.value.openRevision == UInt64.max)
            for text in [v.canonical_json + "\n", "{\"extra\":0," + v.canonical_json.dropFirst(),
                         v.canonical_json.replacingOccurrences(of: "\"controller_epoch\":", with: "\"controller_epoch\":0,\"controller_epoch\":")] {
                #expect(throws: (any Error).self) { try L.decode(L.ServiceResult.self, from: Data(text.utf8)) }
            }
            #expect(throws: (any Error).self) {
                try L.ServiceResult(identity: v.value.identity, grant: v.value.grant, nonce: v.value.nonce,
                    serviceEpoch: v.value.serviceEpoch, controllerEpoch: v.value.controllerEpoch - 1,
                    controllerKey: v.value.controllerKey, openRevision: 1)
            }
        }
    }

    private func states() throws -> (L.ServiceState, L.ServiceState, Curve25519.Signing.PrivateKey, C.Greeting) {
        let id = try vectors().vectors[0].value.identity
        let key = Curve25519.Signing.PrivateKey(), root = Curve25519.Signing.PrivateKey()
        let spki = try StorageIdentity.Ed25519SPKI(rawPublicKey: key.publicKey.rawRepresentation)
        let rootKey = try StorageIdentity.RootPublicKey(publicData: root.publicKey.rawRepresentation)
        let grant = try L.Grant(operation: .initialize, id: UUID().uuidString.lowercased(), identity: id,
                                serial: 1, expectedEpoch: 0, newKey: spki.fingerprint.rawValue)
        func state(_ revision: UInt64, _ pin: String) throws -> L.ServiceState {
            let epoch = UUID().uuidString.lowercased()
            return try .init(grant: grant, context: .init(serviceEpoch: epoch, controllerEpoch: 1, controllerKey: grant.newKey),
                openRevision: revision, boot: .init(identity: id, serviceEpoch: epoch,
                    tlsRootSHA256: String(repeating: pin, count: 64), serverSPKI: String(repeating: pin, count: 64),
                    bootstrapKey: rootKey.fingerprint.rawValue))
        }
        let greeting = try C.Greeting(channelID: UUID().uuidString.lowercased(), incarnationID: UUID().uuidString.lowercased(),
            daemonUniqueID: 10, controllerSPKI: spki.publicData, rootPublicKey: rootKey.publicData,
            store: id.store, binding: id.binding, expectedEpoch: 0)
        return try (state(1, "a"), state(2, "b"), key, greeting)
    }

    @Test func successorRequiresNewEpochPinsAndStrictOpenRevision() throws {
        let (before, after, _, _) = try states()
        let change = try L.ServiceChangeRequest(operationID: UUID().uuidString.lowercased(), predecessor: before)
        #expect(try L.decode(L.ServiceChangeRequest.self, from: L.encode(change)) == change)
        #expect(try L.ServiceChangeConfirmation(request: change, successor: after).successor == after)
        #expect(throws: (any Error).self) { try L.ServiceChangeConfirmation(request: change, successor: before) }
        for field in 0..<5 {
            let boot = try StorageLifecycleBootTrust(identity: after.grant.identity,
                serviceEpoch: field == 0 ? before.boot.serviceEpoch : after.boot.serviceEpoch,
                tlsRootSHA256: field == 1 ? before.boot.tlsRootSHA256 : after.boot.tlsRootSHA256,
                serverSPKI: field == 2 ? before.boot.serverSPKI : after.boot.serverSPKI,
                bootstrapKey: field == 3 ? String(repeating: "c", count: 64) : after.boot.bootstrapKey)
            let state = try L.ServiceState(grant: after.grant,
                context: .init(serviceEpoch: boot.serviceEpoch, controllerEpoch: 1, controllerKey: after.grant.newKey),
                openRevision: field == 4 ? before.openRevision : after.openRevision, boot: boot)
            #expect(throws: (any Error).self) { try L.ServiceChangeConfirmation(request: change, successor: state) }
        }
    }

    @Test func childServiceProofAndCommitAreDistinctClosedPurposes() throws {
        let (before, after, key, greeting) = try states()
        let change = try L.ServiceChangeRequest(operationID: UUID().uuidString.lowercased(), predecessor: before)
        let confirmation = try L.ServiceChangeConfirmation(request: change, successor: after)
        func challenge(_ purpose: C.Purpose, change: L.ServiceChangeRequest? = nil,
                       confirmation: L.ServiceChangeConfirmation? = nil) throws -> C.Challenge {
            try .init(greeting: greeting, grant: after.grant, childAudit: Data(repeating: 1, count: 32), childUniqueID: 11,
                daemonAudit: Data(repeating: 2, count: 32), counter: 1, nonce: Data(repeating: 3, count: 32), purpose: purpose,
                expiresUnixMS: 30_000, boot: after.boot, changeRequest: change, confirmation: confirmation)
        }
        let probe = try challenge(.serviceResult, change: change)
        let commit = try challenge(.serviceCommit, confirmation: confirmation)
        let result = try L.ServiceResult(identity: after.grant.identity, grant: after.grant, nonce: probe.nonce,
            serviceEpoch: after.context.serviceEpoch, controllerEpoch: 1, controllerKey: after.grant.newKey, openRevision: 2)
        for c in [probe, commit, try challenge(.serviceResult)] {
            #expect(try C.decodeChallenge(L.encode(c)) == c)
            let unsigned = try C.Reply(challengeSHA256: c.digest, receipt: nil, signature: Data(repeating: 0, count: 64), serviceResult: result)
            let signed = try C.Reply(challengeSHA256: c.digest, receipt: nil, signature: key.signature(for: unsigned.signingBytes), serviceResult: result)
            #expect(try C.decodeReply(L.encode(signed)) == signed)
            #expect(try signed.verifies(c))
            if c == probe { #expect(try !signed.verifies(commit)) }
        }
        #expect(throws: (any Error).self) { try challenge(.serviceCommit) }
        #expect(throws: (any Error).self) { try challenge(.serviceResult, confirmation: confirmation) }
        #expect(throws: (any Error).self) { try challenge(.serviceCommit, change: change, confirmation: confirmation) }
        #expect(throws: (any Error).self) { try challenge(.result, change: change) }
        #expect(throws: (any Error).self) {
            try C.Reply(challengeSHA256: probe.digest,
                receipt: .init(grant: after.grant, nonce: probe.nonce, serviceEpoch: after.boot.serviceEpoch, revision: 1),
                signature: Data(repeating: 0, count: 64), serviceResult: result)
        }
    }

    @Test func rootServiceOperationsCorrelateExactClosedRequests() throws {
        let (before, after, _, _) = try states()
        let change = try L.ServiceChangeRequest(operationID: UUID().uuidString.lowercased(), predecessor: before)
        let confirmation = try L.ServiceChangeConfirmation(request: change, successor: after)
        let result = try L.ServiceResult(identity: after.grant.identity, grant: after.grant, nonce: Data(repeating: 1, count: 32),
            serviceEpoch: after.context.serviceEpoch, controllerEpoch: 1, controllerKey: after.grant.newKey, openRevision: 2)
        let pairs: [(R.Body, R.ResultBody)] = [
            (.stageServiceChange(change: change), .serviceChangeStaged(try L.SignedServiceChange(request: change,
                signature: Curve25519.Signing.PrivateKey().signature(for: change.signingBytes)))),
            (.serviceBootTrust(identity: after.grant.identity, grantID: after.grant.id, serviceChangeID: change.operationID), .serviceBootTrust(after.boot, grantID: after.grant.id, serviceChangeID: change.operationID)),
            (.serviceResult(identity: after.grant.identity, grantID: after.grant.id), .serviceResult(result)),
            (.completeServiceChange(identity: after.grant.identity, operationID: change.operationID), .serviceChanged(confirmation, result))]
        let bootRequest = try R.Request(requestID: .init(UUID().uuidString.lowercased()), body: pairs[1].0)
        for wrong in [R.ResultBody.serviceBootTrust(after.boot, grantID: UUID().uuidString.lowercased(), serviceChangeID: change.operationID),
                      .serviceBootTrust(after.boot, grantID: after.grant.id, serviceChangeID: nil),
                      .serviceBootTrust(after.boot, grantID: after.grant.id, serviceChangeID: UUID().uuidString.lowercased())] {
            #expect(throws: (any Error).self) { try R.Reply(for: bootRequest, body: wrong) }
        }
        for (body, response) in pairs {
            let request = try R.Request(requestID: .init(UUID().uuidString.lowercased()), body: body)
            #expect(try R.decodeRequest(R.encode(request)) == request)
            let reply = try R.Reply(for: request, body: response)
            #expect(try R.decodeReply(R.encode(reply), for: request) == reply)
            let other = try R.Request(requestID: .init(UUID().uuidString.lowercased()), body: body)
            #expect(throws: (any Error).self) { try R.decodeReply(R.encode(reply), for: other) }
            let text = String(decoding: try R.encode(request), as: UTF8.self)
            #expect(throws: (any Error).self) { try R.decodeRequest(Data(("{\"confirmation\":null," + text.dropFirst()).utf8)) }
        }
    }
}

import CEngineCore
import CryptoKit
import Foundation
import Testing

@Suite("Lifecycle interrupted-live-takeover handoff wire")
struct StorageLifecycleHandoffProtocolTests {
    private typealias H = StorageLifecycleHandoffProtocol
    private typealias L = StorageLifecycleProtocol
    private struct Vector: Decodable {
        let version: String
        let root_seed: Data
        let root_public_key: Data
        let request: H.Request
        let signing_bytes: Data
        let signature: Data
        let results: [ResultVector]
    }
    private struct ResultVector: Decodable {
        let name: String
        let result: H.Result
        let signing_bytes: Data
    }
    private func vector() throws -> Vector {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Fixtures/storage-bootstrap/lifecycle-handoff-v1.json")
        return try JSONDecoder().decode(Vector.self, from: Data(contentsOf: url))
    }
    private func request(_ r: H.Request, operationID: String? = nil, predecessor: L.Grant? = nil,
                         pending: L.Grant? = nil, serviceEpoch: String? = nil, openRevision: UInt64? = nil) throws -> H.Request {
        try .init(operationID: operationID ?? r.operationID, predecessor: predecessor ?? r.predecessor,
            pending: pending ?? r.pending, serviceEpoch: serviceEpoch ?? r.serviceEpoch, openRevision: openRevision ?? r.openRevision)
    }
    private func grant(_ g: L.Grant, operation: L.Operation? = nil, id: String? = nil, identity: L.Identity? = nil,
                       serial: UInt64? = nil, epoch: UInt64? = nil, key: String? = nil) throws -> L.Grant {
        try .init(operation: operation ?? g.operation, id: id ?? g.id, identity: identity ?? g.identity,
            serial: serial ?? g.serial, expectedEpoch: epoch ?? g.expectedEpoch, newKey: key ?? g.newKey)
    }
    private func result(_ r: H.Result, nonce: Data? = nil, applied: L.Grant? = nil, serviceEpoch: String? = nil,
                        revision: UInt64? = nil, fence: UInt64? = nil) throws -> H.Result {
        try .init(request: r.request, nonce: nonce ?? r.nonce, appliedGrant: applied ?? r.appliedGrant,
            appliedServiceEpoch: serviceEpoch ?? r.appliedServiceEpoch, appliedRevision: revision ?? r.appliedRevision,
            fenceRevision: fence ?? r.fenceRevision)
    }

    @Test func goSigningVectorsPinOrderDomainsAndUInt64Precision() throws {
        let v = try vector(), root = try StorageIdentity.RootPublicKey(publicData: v.root_public_key)
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: v.root_seed)
        #expect(v.version == "lifecycle-handoff.v1")
        #expect(v.request.signingBytes == v.signing_bytes)
        // CryptoKit may randomize Ed25519 signatures; pin Go's deterministic
        // signature by verification, not by re-signing and comparing its bytes.
        #expect(key.publicKey.rawRepresentation == v.root_public_key)
        let signed = try H.SignedRequest(request: v.request, signature: v.signature)
        #expect(signed.isValidSignature(using: root))
        #expect(try H.decode(H.SignedRequest.self, from: H.encode(signed)) == signed)
        #expect(try H.decode(H.Request.self, from: H.encode(v.request)) == v.request)
        #expect(v.request.predecessor.identity.generation == 9_007_199_254_740_993)
        #expect(v.request.predecessor.serial == UInt64.max - 1 && v.request.pending.serial == UInt64.max)
        #expect(v.request.openRevision == UInt64.max - 3)
        #expect(v.results.map(\.name) == ["predecessor", "pending"])
        for item in v.results {
            #expect(item.result.signingBytes == item.signing_bytes)
            #expect(item.result.fenceRevision == UInt64.max)
            #expect(try H.decode(H.Result.self, from: H.encode(item.result)) == item.result)
        }
    }

    @Test func requestCrossFieldConstraintsAndOverflowAreValidated() throws {
        let r = try vector().request, p = r.predecessor, g = r.pending
        for id in [p.id, g.id, "", r.operationID.uppercased(), "00000000-0000-0000-0000-000000000000"] {
            #expect(throws: (any Error).self) { try request(r, operationID: id) }
        }
        for epoch in ["", r.operationID.uppercased(), "11111111-1111-1111-8111-111111111111"] {
            #expect(throws: (any Error).self) { try request(r, serviceEpoch: epoch) }
        }
        #expect(throws: (any Error).self) { try request(r, openRevision: 0) }
        for pending in [try grant(g, operation: .retire), try grant(g, operation: .initialize, epoch: 0),
                        try grant(g, id: p.id), try grant(g, serial: p.serial), try grant(g, serial: p.serial - 1),
                        try grant(g, epoch: 2), try grant(g, key: p.newKey),
                        try grant(g, identity: L.Identity(store: g.identity.store, generation: g.identity.generation + 1, binding: g.identity.binding))] {
            #expect(throws: (any Error).self) { try request(r, pending: pending) }
        }
        for predecessor in [try grant(p, operation: .retire, epoch: 1),
                            try grant(p, operation: .retire, epoch: UInt64.max),
                            try grant(p, operation: .takeover, epoch: UInt64.max - 1)] {
            #expect(throws: (any Error).self) { try request(r, predecessor: predecessor) }
        }
        // A prior takeover is legal; this is not restricted to genesis recovery.
        _ = try request(r, predecessor: grant(p, operation: .takeover, epoch: 5), pending: grant(g, epoch: 6))
        _ = try request(r, openRevision: UInt64.max)
    }

    @Test func resultRequiresExactOutcomeAndImmutableReceiptBoundaries() throws {
        let v = try vector(), prior = v.results[0].result, pending = v.results[1].result
        for r in [prior, pending] {
            for count in [0, 31, 33] {
                #expect(throws: (any Error).self) { try result(r, nonce: Data(repeating: 0, count: count)) }
            }
            for revision in [UInt64(0), r.fenceRevision] {
                #expect(throws: (any Error).self) { try result(r, revision: revision) }
            }
            for fence in [UInt64(0), r.request.openRevision, r.appliedRevision] {
                #expect(throws: (any Error).self) { try result(r, fence: fence) }
            }
            #expect(throws: (any Error).self) { try result(r, serviceEpoch: "bad") }
            #expect(throws: (any Error).self) { try result(r, applied: grant(r.appliedGrant, serial: 1)) }
        }
        #expect(throws: (any Error).self) { try result(pending, serviceEpoch: prior.appliedServiceEpoch) }
        #expect(throws: (any Error).self) { try result(pending, revision: pending.request.openRevision) }
        #expect(throws: (any Error).self) { try result(pending, revision: pending.request.openRevision - 1) }
        // The predecessor's applied epoch/revision need not equal the live open.
        #expect(prior.appliedServiceEpoch != prior.request.serviceEpoch)
        #expect(prior.appliedRevision < prior.request.openRevision)
        _ = try result(prior, serviceEpoch: prior.request.serviceEpoch, revision: prior.request.openRevision + 1)
    }

    @Test func signaturesRejectWrongRootTamperingAndOtherDomains() throws {
        let v = try vector(), root = try StorageIdentity.RootPublicKey(publicData: v.root_public_key)
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: v.root_seed)
        let other = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 42, count: 32))
        let signed = try H.SignedRequest(request: v.request, signature: v.signature)
        #expect(!signed.isValidSignature(using: try .init(publicData: other.publicKey.rawRepresentation)))
        #expect(try !H.SignedRequest(request: request(v.request, openRevision: 1), signature: v.signature).isValidSignature(using: root))
        for domain in ["lifecycle.v2", "lifecycle-cold-open.v1", "lifecycle-handoff-result.v1"] {
            let bytes = Data(String(decoding: v.signing_bytes, as: UTF8.self)
                .replacingOccurrences(of: "lifecycle-handoff.v1", with: domain).utf8)
            #expect(try !H.SignedRequest(request: v.request, signature: key.signature(for: bytes)).isValidSignature(using: root))
        }
        #expect(try !H.SignedRequest(request: v.request, signature: Data(repeating: 0, count: 64)).isValidSignature(using: root))
        for count in [0, 63, 65] {
            #expect(throws: (any Error).self) { try H.SignedRequest(request: v.request, signature: Data(repeating: 0, count: count)) }
        }
    }

    private func rejectMalformed<T: Codable>(_ value: T, nested: [String], scalar: String) throws {
        let body = String(decoding: try H.encode(value), as: UTF8.self)
        var bad = [body + "\n", " " + body, body + "{}", "{\"unknown\":true," + body.dropFirst(),
                   body.replacingOccurrences(of: "\"\(scalar)\":", with: "\"\(scalar)\":null,\"\(scalar)\":"),
                   body.replacingOccurrences(of: "9007199254740993", with: "9.007199254740993e15"),
                   body.replacingOccurrences(of: "9007199254740993", with: "9007199254740993.0"),
                   body.replacingOccurrences(of: "18446744073709551615", with: "18446744073709551616"),
                   body.replacingOccurrences(of: "\"open_revision\":18446744073709551612", with: "\"open_revision\":-1"),
                   body.replacingOccurrences(of: "operation_id", with: "operation_\\u0069d")]
        for field in nested {
            bad.append(body.replacingOccurrences(of: "\"\(field)\":{", with: "\"\(field)\":{\"unknown\":false,"))
            bad.append(body.replacingOccurrences(of: "\"\(field)\":{", with: "\"\(field)\":null,\"\(field)\":{"))
        }
        for text in bad {
            #expect(text != body)
            #expect(throws: (any Error).self) { try H.decode(T.self, from: Data(text.utf8)) }
        }
    }

    @Test func closedTransportRejectsAlternateSpellingsAtEveryDepth() throws {
        let v = try vector()
        try rejectMalformed(v.request, nested: ["predecessor", "pending", "identity"], scalar: "operation_id")
        try rejectMalformed(H.SignedRequest(request: v.request, signature: v.signature),
            nested: ["request", "predecessor", "pending", "identity"], scalar: "signature")
        for item in v.results {
            try rejectMalformed(item.result, nested: ["request", "predecessor", "pending", "identity", "applied_grant"], scalar: "nonce")
            let body = String(decoding: try H.encode(item.result), as: UTF8.self)
            for nonce in ["", "AA==", item.result.nonce.base64EncodedString().replacingOccurrences(of: "=", with: ""),
                          item.result.nonce.base64EncodedString().replacingOccurrences(of: "/", with: "\\/")] {
                let bad = body.replacingOccurrences(of: item.result.nonce.base64EncodedString(), with: nonce)
                #expect(bad != body)
                #expect(throws: (any Error).self) { try H.decode(H.Result.self, from: Data(bad.utf8)) }
            }
        }
        #expect(throws: L.ValidationError.payloadTooLarge) {
            try H.decode(H.Request.self, from: Data(repeating: 32, count: L.maximumPayloadBytes + 1))
        }
        #expect(throws: L.ValidationError.payloadTooLarge) { try H.encode(String(repeating: "x", count: L.maximumPayloadBytes)) }
    }

    @Test func codableAlsoRejectsMissingNullAndInvalidValues() throws {
        let v = try vector(), r = v.request
        let body = String(decoding: try H.encode(r), as: UTF8.self)
        for (old, new) in [
            ("\"operation_id\":\"\(r.operationID)\",", ""),
            ("\"operation_id\":\"\(r.operationID)\"", "\"operation_id\":null"),
            ("\"open_revision\":\(r.openRevision)", "\"open_revision\":0"),
            ("\"expected_epoch\":1", "\"expected_epoch\":0"),
            ("\"operation\":\"takeover\"", "\"operation\":\"retire\"")
        ] {
            let bad = body.replacingOccurrences(of: old, with: new)
            #expect(bad != body)
            #expect(throws: (any Error).self) { try JSONDecoder().decode(H.Request.self, from: Data(bad.utf8)) }
        }
        let signed = try H.SignedRequest(request: r, signature: v.signature)
        let signedJSON = String(decoding: try H.encode(signed), as: UTF8.self)
        #expect(throws: (any Error).self) {
            try JSONDecoder().decode(H.SignedRequest.self, from: Data(signedJSON.replacingOccurrences(of: v.signature.base64EncodedString(), with: "AA==").utf8))
        }
        let resultJSON = String(decoding: try H.encode(v.results[1].result), as: UTF8.self)
        #expect(throws: (any Error).self) {
            try JSONDecoder().decode(H.Result.self, from: Data(resultJSON.replacingOccurrences(of: "\"applied_revision\":18446744073709551613", with: "\"applied_revision\":0").utf8))
        }
    }
}

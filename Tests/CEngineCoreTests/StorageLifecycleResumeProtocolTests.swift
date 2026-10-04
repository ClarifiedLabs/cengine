import CEngineCore
import CryptoKit
import Foundation
import Testing

@Suite("Lifecycle fresh-resume authorization")
struct StorageLifecycleResumeProtocolTests {
    private typealias R = StorageLifecycleResumeProtocol
    private typealias L = StorageLifecycleProtocol
    private struct Vector: Decodable {
        let version: String
        let root_seed: Data
        let root_public_key: Data
        let request: R.Request
        let signing_bytes: Data
        let takeover_signing_bytes: Data
        let request_sha256: String
        let signature: Data
    }
    private func vector() throws -> Vector {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Fixtures/storage-bootstrap/lifecycle-resume-open-v1.json")
        return try JSONDecoder().decode(Vector.self, from: Data(contentsOf: url))
    }
    private func request(_ r: R.Request, original: L.Grant? = nil, takeover: L.SignedGrant? = nil,
                         now: UInt64? = nil, lifetime: UInt64? = nil) throws -> R.Request {
        try R.Request(operationID: r.operationID, original: original ?? r.original, takeover: takeover ?? r.takeover,
            launch: r.launch, nowUnixSeconds: now ?? r.nowUnixSeconds, lifetimeSeconds: lifetime ?? r.lifetimeSeconds)
    }

    @Test func goVectorPinsBothSignaturesExactSigningOrderAndUInt64s() throws {
        let v = try vector(), root = try StorageIdentity.RootPublicKey(publicData: v.root_public_key)
        let signed = try R.SignedOpen(request: v.request, signature: v.signature)
        #expect(v.version == "lifecycle-resume-open.v1")
        #expect(v.request.signingBytes == v.signing_bytes)
        #expect(v.request.takeover.grant.signingBytes == v.takeover_signing_bytes)
        #expect(v.request.digest == v.request_sha256)
        #expect(signed.isValidSignature(using: root))
        #expect(v.request.original.identity.generation == 9_007_199_254_740_993)
        #expect(v.request.original.serial == UInt64.max - 1 && v.request.takeover.grant.serial == UInt64.max)
        #expect(v.request.takeover.grant.expectedEpoch == 1 && v.request.original.expectedEpoch == 0)
        #expect(try R.decode(L.encode(signed)) == signed)
        #expect(MemoryLayout<R.SignedOpen>.size <= 2 * MemoryLayout<UnsafeRawPointer>.size)
    }

    @Test func closedTransportRejectsMixedNullDuplicateAndUnknownState() throws {
        let v = try vector(), signed = try R.SignedOpen(request: v.request, signature: v.signature)
        let body = String(decoding: try L.encode(signed), as: UTF8.self)
        var bad = [body + "\n", " " + body]
        for field in ["request", "original", "identity", "takeover", "grant", "launch"] {
            bad.append(body.replacingOccurrences(of: "\"\(field)\":{", with: "\"\(field)\":{\"unknown\":true,"))
            bad.append(body.replacingOccurrences(of: "\"\(field)\":{", with: "\"\(field)\":null,\"\(field)\":{"))
        }
        for (old, new) in [
            ("9007199254740993", "9.007199254740993e15"),
            ("9007199254740993", "9007199254740993.0"),
            ("18446744073709551615", "18446744073709551616"),
            ("\"expected_epoch\":1", "\"expected_epoch\":null"),
            ("\"original\":{", "\"predecessor\":{},\"original\":{")
        ] { bad.append(body.replacingOccurrences(of: old, with: new)) }
        for bytes in bad {
            #expect(bytes != body)
            #expect(throws: (any Error).self) { try R.decode(Data(bytes.utf8)) }
        }
    }

    @Test func initializeAndSuccessorCannotBeReusedOrSubstituted() throws {
        let r = try vector().request
        let body = String(decoding: try L.encode(r), as: UTF8.self)
        for (old, new) in [
            ("\"operation\":\"initialize\"", "\"operation\":\"takeover\""),
            ("\"operation\":\"takeover\"", "\"operation\":\"retire\""),
            ("\"expected_epoch\":1", "\"expected_epoch\":2"),
            ("\"expected_epoch\":0", "\"expected_epoch\":1"),
            ("\"serial\":18446744073709551615", "\"serial\":18446744073709551614"),
            ("\"new_key\":\"\(r.takeover.grant.newKey)\"", "\"new_key\":\"\(r.original.newKey)\""),
            ("\"operation_id\":\"\(r.operationID)\"", "\"operation_id\":\"\(r.original.id)\""),
            ("\"bytes\":9223372036854775807", "\"bytes\":0"),
            ("\"ext4_uuid\":\"\(r.launch.ext4UUID)\"", "\"ext4_uuid\":\"00000000-0000-0000-0000-000000000000\"")
        ] {
            let bad = body.replacingOccurrences(of: old, with: new)
            #expect(bad != body)
            #expect(throws: (any Error).self) { try JSONDecoder().decode(R.Request.self, from: Data(bad.utf8)) }
        }
        let other = try L.Identity(store: r.original.identity.store, generation: r.original.identity.generation + 1,
            binding: r.original.identity.binding)
        let original = try L.Grant(operation: .initialize, id: r.original.id, identity: other,
            serial: r.original.serial, expectedEpoch: 0, newKey: r.original.newKey)
        #expect(throws: (any Error).self) { try request(r, original: original) }
    }

    @Test func wrongInnerOuterSignaturesRootAliasesAndTamperingFail() throws {
        let v = try vector(), r = v.request
        let root = try StorageIdentity.RootPublicKey(publicData: v.root_public_key)
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: v.root_seed)
        let attacker = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 42, count: 32))
        for signature in [Data(repeating: 0, count: 64), try attacker.signature(for: r.signingBytes)] {
            #expect(try !R.SignedOpen(request: r, signature: signature).isValidSignature(using: root))
        }
        let inner = try L.SignedGrant(grant: r.takeover.grant, signature: Data(repeating: 0, count: 64))
        let badInner = try request(r, takeover: inner)
        #expect(try !R.SignedOpen(request: badInner, signature: key.signature(for: badInner.signingBytes)).isValidSignature(using: root))
        let tampered = try request(r, now: r.nowUnixSeconds + 1)
        #expect(try !R.SignedOpen(request: tampered, signature: v.signature).isValidSignature(using: root))
        // Even two valid ROOT signatures cannot assign the ROOT signing key to a controller.
        for aliasOriginal in [false, true] {
            let g = aliasOriginal ? r.original : r.takeover.grant
            let alias = try L.Grant(operation: g.operation, id: g.id, identity: g.identity, serial: g.serial,
                expectedEpoch: g.expectedEpoch, newKey: root.fingerprint.rawValue)
            let modified = aliasOriginal ? try request(r, original: alias) : try request(r,
                takeover: L.SignedGrant(grant: alias, signature: key.signature(for: alias.signingBytes)))
            let signed = try R.SignedOpen(request: modified, signature: key.signature(for: modified.signingBytes))
            #expect(!signed.isValidSignature(using: root))
        }
        for count in [0, 63, 65] {
            #expect(throws: (any Error).self) { try R.SignedOpen(request: r, signature: Data(repeating: 0, count: count)) }
        }
    }

    @Test func bootConfigurationRequiresExactResumeAndRejectsMixedActions() throws {
        typealias W = StorageLifecycleServiceBootProtocol
        let v = try vector(), signed = try R.SignedOpen(request: v.request, signature: v.signature)
        let r = v.request
        func configuration(_ action: W.Configuration.Action = .resumeOpenTakeover,
                           resume: R.SignedOpen? = signed, now: UInt64 = r.nowUnixSeconds) -> W.Configuration {
            .init(action: action, rootPublicKey: v.root_public_key, signed: r.takeover,
                nowUnixSeconds: now, lifetimeSeconds: r.lifetimeSeconds, resume: resume)
        }
        let binding = W.Binding(shimLaunchUUID: r.launch.shimLaunchUUID, guestBootNonce: "11111111-1111-4111-8111-111111111111",
            ext4UUID: r.launch.ext4UUID, bytes: r.launch.bytes)
        let frame = W.Frame(operation: .configure, binding: binding, configuration: configuration())
        let bytes = Data(try W.encode(frame).dropFirst(4))
        #expect(try W.decode(bytes) == frame)
        for invalid in [configuration(.initialize), configuration(.open), configuration(.coldOpenTakeover),
                        configuration(resume: nil), configuration(now: r.nowUnixSeconds + 1)] {
            #expect(throws: (any Error).self) { try invalid.validate() }
        }
        #expect(throws: (any Error).self) {
            try W.ReplacementRequest(predecessorWorkerUUID: "11111111-1111-4111-8111-111111111111", configuration: configuration()).validate()
        }
        let text = String(decoding: bytes, as: UTF8.self)
        for injection in ["\"cold\":null,", "\"reopen\":null,", "\"resume\":null,"] {
            let bad = text.replacingOccurrences(of: "\"resume\":{", with: injection + "\"resume\":{")
            #expect(throws: (any Error).self) { try W.decode(Data(bad.utf8)) }
        }
    }

    @Test func boundedTimesAndDistinctSigningDomain() throws {
        let v = try vector(), r = v.request
        for (now, lifetime): (UInt64, UInt64) in [(0, 1), (1, 0), (1, 86_401),
            (253_402_300_799, 1), (253_402_300_798, 2), (UInt64.max, 1), (1, UInt64.max)] {
            #expect(throws: (any Error).self) { try request(r, now: now, lifetime: lifetime) }
        }
        _ = try request(r, now: 253_402_300_798, lifetime: 1)
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: v.root_seed)
        let coldDomain = Data(String(decoding: r.signingBytes, as: UTF8.self)
            .replacingOccurrences(of: "lifecycle-resume-open.v1", with: "lifecycle-cold-open.v1").utf8)
        let signed = try R.SignedOpen(request: r, signature: key.signature(for: coldDomain))
        #expect(!signed.isValidSignature(using: try .init(publicData: v.root_public_key)))
    }
}

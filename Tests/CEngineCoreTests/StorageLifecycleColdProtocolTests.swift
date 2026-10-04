import CEngineCore
import CryptoKit
import Foundation
import Testing

@Suite("Dormant lifecycle cold-open signing and closed wire")
struct StorageLifecycleColdProtocolTests {
    private typealias C = StorageLifecycleColdProtocol
    private typealias L = StorageLifecycleProtocol
    private typealias W = StorageLifecycleServiceBootProtocol

    private struct Vector: Decodable {
        let version: String
        let root_seed: Data
        let root_public_key: Data
        let signing_bytes: Data
        let takeover_signing_bytes: Data
        let request_sha256: String
        let signature: Data
        let canonical_frame: String
    }
    private func vector() throws -> Vector {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Fixtures/storage-bootstrap/lifecycle-cold-open-v1.json")
        return try JSONDecoder().decode(Vector.self, from: Data(contentsOf: url))
    }
    private func configuration(_ v: Vector) throws -> W.Configuration {
        try #require(W.decode(Data(v.canonical_frame.utf8)).configuration)
    }
    private func request(_ r: C.Request, predecessor: C.Predecessor? = nil, takeover: L.SignedGrant? = nil,
                         now: UInt64? = nil, lifetime: UInt64? = nil) throws -> C.Request {
        try C.Request(operationID: r.operationID, predecessor: predecessor ?? r.predecessor,
            takeover: takeover ?? r.takeover, launch: r.launch,
            nowUnixSeconds: now ?? r.nowUnixSeconds, lifetimeSeconds: lifetime ?? r.lifetimeSeconds)
    }
    private func configuration(_ cfg: W.Configuration, cold: C.SignedOpen, root: Data? = nil,
                               signed: L.SignedGrant? = nil, now: UInt64? = nil, lifetime: UInt64? = nil) -> W.Configuration {
        W.Configuration(action: .coldOpenTakeover, rootPublicKey: root ?? cfg.rootPublicKey,
            signed: signed ?? cold.request.takeover, nowUnixSeconds: now ?? cold.request.nowUnixSeconds,
            lifetimeSeconds: lifetime ?? cold.request.lifetimeSeconds, cold: cold)
    }

    @Test func coldAuthorizationDoesNotInflateNestedBootFrames() {
        // The wire carries repeated configuration values. A large inline cold
        // request previously overflowed a Swift cooperative test-thread stack.
        #expect(MemoryLayout<C.SignedOpen>.size <= 2 * MemoryLayout<UnsafeRawPointer>.size)
    }

    @Test func exactGoSigningBytesDigestSignaturesAndCanonicalFrame() throws {
        let v = try vector(), cfg = try configuration(v), cold = try #require(cfg.cold)
        let root = try StorageIdentity.RootPublicKey(publicData: v.root_public_key)
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: v.root_seed)
        #expect(v.version == "lifecycle-cold-open.v1")
        #expect(key.publicKey.rawRepresentation == v.root_public_key && cfg.rootPublicKey == v.root_public_key)
        #expect(cold.request.signingBytes == v.signing_bytes)
        #expect(cold.request.digest == v.request_sha256)
        #expect(cold.request.takeover.grant.signingBytes == v.takeover_signing_bytes)
        // CryptoKit may randomize Ed25519 signatures. Pin the Go signature and
        // exact message bytes, but do not assume a fresh signer reproduces bytes.
        #expect(key.publicKey.isValidSignature(cold.request.takeover.signature, for: v.takeover_signing_bytes))
        #expect(key.publicKey.isValidSignature(v.signature, for: v.signing_bytes))
        #expect(cold.signature == v.signature && cold.isValidSignature(using: root))
        #expect(cold.request.takeover.isValidSignature(using: root))
        #expect(cfg.action == .coldOpenTakeover && cfg.signed == cold.request.takeover && cfg.reopen == nil)
        let r = cold.request, p = r.predecessor, launch = r.launch
        // Reconstruct with the public value APIs, rather than adding a fixture API.
        let predecessor = try C.Predecessor(currentGrant: p.currentGrant, serviceEpoch: p.serviceEpoch,
            controllerEpoch: p.controllerEpoch, controllerKey: p.controllerKey,
            openRevision: p.openRevision, bootstrapKey: p.bootstrapKey)
        let rebuiltLaunch = try C.Launch(shimLaunchUUID: launch.shimLaunchUUID, specSHA256: launch.specSHA256,
            initramfsSHA256: launch.initramfsSHA256, ext4UUID: launch.ext4UUID, bytes: launch.bytes)
        let rebuilt = try C.Request(operationID: r.operationID, predecessor: predecessor, takeover: r.takeover,
            launch: rebuiltLaunch, nowUnixSeconds: r.nowUnixSeconds, lifetimeSeconds: r.lifetimeSeconds)
        #expect(try C.SignedOpen(request: rebuilt, signature: v.signature) == cold)
        #expect(p.currentGrant.identity.generation == 9_007_199_254_740_993)
        #expect(p.currentGrant.expectedEpoch == 9_007_199_254_740_992)
        #expect(p.controllerEpoch == 9_007_199_254_740_993 && r.takeover.grant.expectedEpoch == p.controllerEpoch)
        #expect(p.currentGrant.serial == UInt64.max - 1 && r.takeover.grant.serial == UInt64.max)
        #expect(p.openRevision == UInt64.max && launch.bytes == UInt64(Int64.max))
        let frame = try W.decode(Data(v.canonical_frame.utf8)), encoded = try W.encode(frame)
        #expect(Data(encoded.dropFirst(4)) == Data(v.canonical_frame.utf8))
        #expect(encoded.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) } == UInt32(encoded.count - 4))
        #expect(try W.decode(encoded.dropFirst(4)) == frame)
    }

    @Test func closedFrameRejectsNullUnknownDuplicateAndNonIntegerWireForms() throws {
        let body = try vector().canonical_frame
        var mutations = [" " + body, body + "\n"]
        // Exercise every cold nesting boundary, not only the outer frame.
        for field in ["configuration", "cold", "request", "predecessor", "current_grant", "identity", "takeover", "grant", "launch"] {
            mutations.append(body.replacingOccurrences(of: "\"\(field)\":{", with: "\"\(field)\":{\"unknown\":true,"))
            mutations.append(body.replacingOccurrences(of: "\"\(field)\":{", with: "\"\(field)\":null,\"\(field)\":{"))
        }
        for (from, to) in [
            ("\"version\":", "\"unknown\":true,\"version\":"),
            ("\"cold\":{", "\"reopen\":null,\"cold\":{"),
            ("\"open_revision\":18446744073709551615", "\"open_revision\":18446744073709551615,\"open_revision\":18446744073709551615"),
            ("9007199254740993", "9.007199254740993e15"),
            ("9007199254740993", "9007199254740993.0"),
            ("9007199254740993", "\"9007199254740993\""),
            ("18446744073709551615", "18446744073709551616"),
            ("\"open_revision\":18446744073709551615", "\"open_revision\":-1"),
            ("\"open_revision\":18446744073709551615", "\"open_revision\":null"),
            ("\"bytes\":9223372036854775807", "\"bytes\":09223372036854775807")
        ] { mutations.append(body.replacingOccurrences(of: from, with: to)) }
        for bad in mutations {
            #expect(bad != body)
            #expect(throws: (any Error).self) { try W.decode(Data(bad.utf8)) }
        }
    }

    @Test func malformedColdFieldsFailBeforeSignatureVerification() throws {
        let cfg = try configuration(vector()), cold = try #require(cfg.cold), r = cold.request
        let body = String(decoding: try L.encode(r), as: UTF8.self)
        // Bare Request decoding deliberately isolates value validation from the
        // boot frame's cryptographic checks (which would reject any tampering).
        for (from, to) in [
            ("\"operation_id\":\"\(r.operationID)\"", "\"operation_id\":\"\(r.predecessor.currentGrant.id)\""),
            ("\"service_epoch\":\"\(r.predecessor.serviceEpoch)\"", "\"service_epoch\":\"bad\""),
            ("\"controller_epoch\":9007199254740993", "\"controller_epoch\":1"),
            ("\"controller_key\":\"\(r.predecessor.controllerKey)\"", "\"controller_key\":\"\(r.takeover.grant.newKey)\""),
            ("\"bootstrap_key\":\"\(r.predecessor.bootstrapKey)\"", "\"bootstrap_key\":\"\(r.predecessor.controllerKey)\""),
            ("\"open_revision\":18446744073709551615", "\"open_revision\":0"),
            ("\"expected_epoch\":9007199254740993", "\"expected_epoch\":1"),
            ("\"serial\":18446744073709551615", "\"serial\":18446744073709551614"),
            ("\"new_key\":\"\(r.takeover.grant.newKey)\"", "\"new_key\":\"\(r.predecessor.controllerKey)\""),
            ("\"new_key\":\"\(r.takeover.grant.newKey)\"", "\"new_key\":\"\(r.predecessor.bootstrapKey)\""),
            ("\"operation\":\"takeover\"", "\"operation\":\"retire\""),
            ("\"shim_launch_uuid\":\"\(r.launch.shimLaunchUUID)\"", "\"shim_launch_uuid\":\"bad\""),
            ("\"ext4_uuid\":\"\(r.launch.ext4UUID)\"", "\"ext4_uuid\":\"00000000-0000-0000-0000-000000000000\""),
            ("\"spec_sha256\":\"\(r.launch.specSHA256)\"", "\"spec_sha256\":\"bad\""),
            ("\"initramfs_sha256\":\"\(r.launch.initramfsSHA256)\"", "\"initramfs_sha256\":\"\(r.launch.initramfsSHA256.uppercased())\""),
            ("\"bytes\":9223372036854775807", "\"bytes\":0"),
            ("\"bytes\":9223372036854775807", "\"bytes\":9223372036854775808")
        ] {
            let bad = body.replacingOccurrences(of: from, with: to)
            #expect(bad != body)
            #expect(throws: (any Error).self) { try JSONDecoder().decode(C.Request.self, from: Data(bad.utf8)) }
        }
        for count in [0, 63, 65] {
            #expect(throws: (any Error).self) { try C.SignedOpen(request: r, signature: Data(repeating: 0, count: count)) }
        }
    }

    @Test func wrongInnerOuterSignaturesAndBootstrapFailIndependently() throws {
        let v = try vector(), cfg = try configuration(v), cold = try #require(cfg.cold), r = cold.request
        let root = try StorageIdentity.RootPublicKey(publicData: v.root_public_key)
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: v.root_seed)
        let attacker = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 42, count: 32))
        let attackerRoot = try StorageIdentity.RootPublicKey(publicData: attacker.publicKey.rawRepresentation)
        var flipped = cold.signature; flipped[0] ^= 1
        for signature in [Data(repeating: 0, count: 64), flipped, try attacker.signature(for: r.signingBytes)] {
            let bad = try C.SignedOpen(request: r, signature: signature)
            #expect(!bad.isValidSignature(using: root))
            #expect(throws: (any Error).self) { try configuration(cfg, cold: bad).validate() }
        }
        // A valid outer ROOT signature cannot authorize an invalid inner grant.
        for signature in [Data(repeating: 0, count: 64), try attacker.signature(for: r.takeover.grant.signingBytes)] {
            let inner = try L.SignedGrant(grant: r.takeover.grant, signature: signature)
            let badRequest = try request(r, takeover: inner)
            let bad = try C.SignedOpen(request: badRequest, signature: key.signature(for: badRequest.signingBytes))
            #expect(key.publicKey.isValidSignature(bad.signature, for: badRequest.signingBytes))
            #expect(!bad.isValidSignature(using: root))
            #expect(throws: (any Error).self) { try configuration(cfg, cold: bad).validate() }
        }
        let p = r.predecessor
        let wrongBootstrap = try C.Predecessor(currentGrant: p.currentGrant, serviceEpoch: p.serviceEpoch,
            controllerEpoch: p.controllerEpoch, controllerKey: p.controllerKey, openRevision: p.openRevision,
            bootstrapKey: attackerRoot.fingerprint.rawValue)
        let badRequest = try request(r, predecessor: wrongBootstrap)
        let wrongPin = try C.SignedOpen(request: badRequest, signature: key.signature(for: badRequest.signingBytes))
        let selfConsistentAttacker = try C.SignedOpen(request: badRequest, signature: attacker.signature(for: badRequest.signingBytes))
        #expect(!wrongPin.isValidSignature(using: root))
        #expect(!selfConsistentAttacker.isValidSignature(using: attackerRoot))
        #expect(!cold.isValidSignature(using: attackerRoot))
        for bad in [configuration(cfg, cold: wrongPin),
                    configuration(cfg, cold: selfConsistentAttacker, root: attackerRoot.publicData),
                    configuration(cfg, cold: cold, root: attackerRoot.publicData)] {
            #expect(throws: (any Error).self) { try bad.validate() }
        }
        let tampered = try C.SignedOpen(request: request(r, now: r.nowUnixSeconds + 1), signature: cold.signature)
        #expect(!tampered.isValidSignature(using: root))
        #expect(throws: (any Error).self) { try configuration(cfg, cold: tampered).validate() }
    }

    @Test func coldActionRequiresExactConfigurationAndCannotReplaceService() throws {
        let v = try vector(), cfg = try configuration(v), cold = try #require(cfg.cold)
        let badGrant = try L.SignedGrant(grant: cfg.signed.grant, signature: Data(repeating: 0, count: 64))
        let missing = W.Configuration(action: .coldOpenTakeover, rootPublicKey: cfg.rootPublicKey,
            signed: cfg.signed, nowUnixSeconds: cfg.nowUnixSeconds, lifetimeSeconds: cfg.lifetimeSeconds)
        for bad in [missing, configuration(cfg, cold: cold, now: cfg.nowUnixSeconds + 1),
                    configuration(cfg, cold: cold, lifetime: cfg.lifetimeSeconds + 1),
                    configuration(cfg, cold: cold, signed: badGrant)] {
            #expect(throws: (any Error).self) { try bad.validate() }
        }
        for action in ["initialize", "open", "cold-open", "unknown"] {
            let bad = v.canonical_frame.replacingOccurrences(of: "cold-open-takeover", with: action)
            #expect(throws: (any Error).self) { try W.decode(Data(bad.utf8)) }
        }
        #expect(throws: (any Error).self) {
            try W.ReplacementRequest(predecessorWorkerUUID: cold.request.predecessor.serviceEpoch, configuration: cfg).validate()
        }
        // Reuse an independently valid reopen value solely to test exclusivity.
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Fixtures/storage-bootstrap/lifecycle-service-boot-v2.json")
        let frames = try JSONDecoder().decode([String].self, from: Data(contentsOf: url))
        let reopen = try #require(W.decode(Data(frames[5].utf8)).configuration?.reopen)
        let mixed = W.Configuration(action: .coldOpenTakeover, rootPublicKey: cfg.rootPublicKey,
            signed: cfg.signed, nowUnixSeconds: cfg.nowUnixSeconds, lifetimeSeconds: cfg.lifetimeSeconds, reopen: reopen, cold: cold)
        #expect(throws: (any Error).self) { try mixed.validate() }
    }

    @Test func authorityTimeBoundAndIntentionallyTighterBootBound() throws {
        let v = try vector(), cfg = try configuration(v), cold = try #require(cfg.cold)
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: v.root_seed)
        #expect(StorageServiceTypes.maximumUnixSeconds == 253_402_214_399)
        for (now, lifetime, bootValid): (UInt64, UInt64, Bool) in [
            (253_402_214_399, 86_400, true), (253_402_214_400, 1, false), (253_402_300_798, 1, false)
        ] {
            let r = try request(cold.request, now: now, lifetime: lifetime)
            let signed = try C.SignedOpen(request: r, signature: key.signature(for: r.signingBytes))
            #expect(signed.isValidSignature(using: try .init(publicData: v.root_public_key)))
            let c = configuration(cfg, cold: signed)
            if bootValid { try c.validate() } else { #expect(throws: (any Error).self) { try c.validate() } }
        }
        for (now, lifetime): (UInt64, UInt64) in [
            (0, 1), (1_800_000_000, 0), (1_800_000_000, 86_401),
            (253_402_300_799, 1), (253_402_300_798, 2), (UInt64.max, 1), (1, UInt64.max)
        ] {
            #expect(throws: (any Error).self) { try request(cold.request, now: now, lifetime: lifetime) }
        }
    }
}

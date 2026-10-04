import CEngineCore
import CryptoKit
import Foundation
import Testing

@Suite("Inactive service provenance wire")
struct StorageLifecycleServiceProofProtocolTests {
    private typealias P = StorageLifecycleServiceProofProtocol
    private typealias L = StorageLifecycleProtocol
    private let uuid = "11111111-1111-4111-8111-111111111111"
    private let other = "22222222-2222-4222-8222-222222222222"

    private func binding() throws -> StorageIdentity.StoreBinding {
        try .init(storeID: .init(uuid), root: .init(volumeUUID: .init(uuid), inode: .max),
                  backing: .init(identity: .init(volumeUUID: .init(other), inode: .max - 1), size: 32 << 20),
                  expectedExt4UUID: .init(uuid))
    }
    private func greeting() throws -> P.Greeting {
        let full = try binding(), root = try StorageIdentity.RootPublicKey(publicData: Data(repeating: 1, count: 32))
        return try .init(channelID: uuid, daemonUniqueID: .max - 1, rootPublicKey: root.publicData,
            binding: .init(full), bootBinding: .init(shimLaunchUUID: uuid, guestBootNonce: other,
                ext4UUID: uuid, bytes: full.backing.size), initramfsSHA256: String(repeating: "a", count: 64),
            boot: .init(identity: .init(binding: full, generation: .max), serviceEpoch: other,
                tlsRootSHA256: String(repeating: "b", count: 64), serverSPKI: String(repeating: "c", count: 64),
                bootstrapKey: root.fingerprint.rawValue))
    }
    private func challenge(_ operation: L.Operation = .initialize) throws -> P.Challenge {
        let g = try greeting()
        return try .init(greeting: g, grant: .init(operation: operation, id: uuid, identity: g.boot.identity,
            serial: .max, expectedEpoch: operation == .initialize ? 0 : 1, newKey: String(repeating: "d", count: 64)),
            shimAudit: Data(repeating: 2, count: 32), shimUniqueID: .max,
            daemonAudit: Data(repeating: 3, count: 32), counter: .max,
            nonce: Data(repeating: 4, count: 32), expiresUnixMS: 60_000)
    }

    @Test func fullBindingRoundTripPreservesStableDigestAndEveryField() throws {
        let full = try binding(), dto = StorageLifecycleStoreBinding(full)
        let decoded = try L.decode(StorageLifecycleStoreBinding.self, from: L.encode(dto))
        #expect(try decoded.value() == full)
        #expect(try L.bindingDigest(decoded.value()) == L.bindingDigest(full))
        #expect(try L.Identity(binding: decoded.value(), generation: .max) == greeting().boot.identity)
        let json = String(decoding: try L.encode(dto), as: UTF8.self)
        #expect(json == "{\"backing\":{\"inode\":18446744073709551614,\"volume_uuid\":\"\(other)\"},\"bytes\":33554432,\"ext4_uuid\":\"\(uuid)\",\"root\":{\"inode\":18446744073709551615,\"volume_uuid\":\"\(uuid)\"},\"store\":\"\(uuid)\",\"version\":\"storage-host-binding.v2\"}")
        for (old, new) in [
            ("\"store\":\"\(uuid)\"", "\"store\":\"\(other)\""),
            ("\"ext4_uuid\":\"\(uuid)\"", "\"ext4_uuid\":\"\(other)\""),
            ("\"bytes\":33554432", "\"bytes\":33554433"),
            ("\"inode\":18446744073709551615", "\"inode\":18446744073709551613"),
            ("\"inode\":18446744073709551614", "\"inode\":18446744073709551613"),
            ("\"volume_uuid\":\"\(uuid)\"", "\"volume_uuid\":\"\(other)\""),
            ("\"volume_uuid\":\"\(other)\"", "\"volume_uuid\":\"\(uuid)\"")
        ] {
            try #require(json.contains(old))
            let changed = try L.decode(StorageLifecycleStoreBinding.self, from: Data(json.replacingOccurrences(of: old, with: new).utf8))
            #expect(try L.bindingDigest(changed.value()) != L.bindingDigest(full))
        }
        for (old, new) in [("\"bytes\":33554432", "\"bytes\":0"),
                           ("\"inode\":18446744073709551615", "\"inode\":0"),
                           ("\"bytes\":33554432", "\"bytes\":18446744073709551615")] {
            #expect(throws: (any Error).self) {
                try JSONDecoder().decode(StorageLifecycleStoreBinding.self, from: Data(json.replacingOccurrences(of: old, with: new).utf8))
            }
        }
    }

    @Test func canonicalUnsignedCorrelationAcceptsEveryLifecycleOperation() throws {
        let g = try greeting()
        #expect(try P.decodeGreeting(L.encode(g)) == g)
        for operation in [L.Operation.initialize, .takeover, .retire] {
            let c = try challenge(operation), reply = try P.Reply(challengeSHA256: c.digest, boot: g.boot)
            #expect(try P.decodeChallenge(L.encode(c)) == c)
            #expect(try P.decodeReply(L.encode(reply)) == reply)
            #expect(try reply.verifies(c))
            #expect(try c.digest == Data(SHA256.hash(data: Data("cengine.storage-service-proof.challenge.v2\0".utf8) + L.encode(c))))
            #expect(!c.isFresh(at: 29_999)); #expect(c.isFresh(at: 30_000))
            #expect(c.isFresh(at: 59_999)); #expect(!c.isFresh(at: 60_000)); #expect(!c.isFresh(at: .max))
            #expect(try !P.Reply(challengeSHA256: Data(count: 32), boot: g.boot).verifies(c))
            let changed = try StorageLifecycleBootTrust(identity: g.boot.identity, serviceEpoch: uuid,
                tlsRootSHA256: g.boot.tlsRootSHA256, serverSPKI: g.boot.serverSPKI, bootstrapKey: g.boot.bootstrapKey)
            #expect(try !P.Reply(challengeSHA256: c.digest, boot: changed).verifies(c))
        }
    }

    @Test func closedSchemaRejectsMalformedAndMismatchedNestedBindings() throws {
        let c = try challenge()
        let values: [(Data, (Data) throws -> Void)] = [
            (try L.encode(c.greeting), { _ = try P.decodeGreeting($0) }),
            (try L.encode(c), { _ = try P.decodeChallenge($0) }),
            (try L.encode(P.Reply(challengeSHA256: c.digest, boot: c.greeting.boot)), { _ = try P.decodeReply($0) })
        ]
        for (bytes, decode) in values {
            let text = String(decoding: bytes, as: UTF8.self)
            for invalid in [bytes + Data([10]), Data([32]) + bytes,
                Data(("{\"unknown\":0," + text.dropFirst()).utf8),
                Data(text.replacingOccurrences(of: "\"version\":", with: "\"version\":\"\(P.version)\",\"version\":").utf8),
                Data(text.replacingOccurrences(of: P.version, with: "storage-service-proof.v1").utf8)] {
                #expect(throws: (any Error).self) { try decode(invalid) }
            }
        }
        let text = String(decoding: try L.encode(c), as: UTF8.self)
        for (old, new) in [
            ("\"inode\":18446744073709551615", "\"inode\":18446744073709551613"),
            ("\"volume_uuid\":\"\(other)\"", "\"volume_uuid\":\"\(uuid)\""),
            ("\"bytes\":33554432", "\"bytes\":33554433"),
            ("\"ext4UUID\":\"\(uuid)\"", "\"ext4UUID\":\"\(other)\""),
            ("\"counter\":18446744073709551615", "\"counter\":0"),
            ("\"counter\":18446744073709551615", "\"counter\":18446744073709551616"),
            ("\"shim_unique_id\":18446744073709551615", "\"shim_unique_id\":18446744073709551614"),
            ("\"daemon_unique_id\":18446744073709551614", "\"daemon_unique_id\":0"),
            ("\"expires_unix_ms\":60000", "\"expires_unix_ms\":0"),
            ("\"boot_binding\":{", "\"boot_binding\":{\"extra\":false,"),
            ("\"root\":{", "\"root\":{\"extra\":false,"),
            ("\"guestBootNonce\":\"\(other)\"", "\"guestBootNonce\":\"invalid\""),
            ("\"initramfs_sha256\":\"" + String(repeating: "a", count: 64), "\"initramfs_sha256\":\"A" + String(repeating: "a", count: 63)),
            ("\"bootstrap_key\":\"\(c.greeting.boot.bootstrapKey)\"", "\"bootstrap_key\":\"" + String(repeating: "a", count: 64) + "\"")
        ] {
            try #require(text.contains(old))
            #expect(throws: (any Error).self) { try P.decodeChallenge(Data(text.replacingOccurrences(of: old, with: new).utf8)) }
        }
        for key in ["shim_audit", "daemon_audit", "nonce", "root_public_key"] {
            let object = try #require(JSONSerialization.jsonObject(with: L.encode(c)) as? [String: Any])
            var changed = object
            if key == "root_public_key" {
                var g = try #require(changed["greeting"] as? [String: Any]); g[key] = Data(count: 31).base64EncodedString(); changed["greeting"] = g
            } else { changed[key] = Data(count: 31).base64EncodedString() }
            let invalid = try JSONSerialization.data(withJSONObject: changed, options: [.sortedKeys, .withoutEscapingSlashes])
            #expect(throws: (any Error).self) { try P.decodeChallenge(invalid) }
        }
        #expect(throws: (any Error).self) { try P.Reply(challengeSHA256: Data(count: 31), boot: c.greeting.boot) }
        #expect(throws: (any Error).self) { try P.decodeGreeting(Data(count: L.maximumPayloadBytes + 1)) }
    }
}

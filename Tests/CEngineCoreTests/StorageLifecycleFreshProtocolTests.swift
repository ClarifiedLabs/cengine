import CEngineCore
import CryptoKit
import Foundation
import Testing

@Suite("Inactive fresh lifecycle wire")
struct StorageLifecycleFreshProtocolTests {
    private typealias P = StorageLifecycleFreshProtocol
    private typealias L = StorageLifecycleProtocol
    private let uuid = "11111111-1111-4111-8111-111111111111"

    private func greeting(device: UInt64 = 0) throws -> P.Greeting {
        try .init(channelID: uuid, daemonUniqueID: UInt64.max - 1, rootPublicKey: Data(repeating: 1, count: 32),
            store: uuid, shimLaunchUUID: uuid, guestBootNonce: uuid, operationUUID: uuid, ext4UUID: uuid,
            bytes: 32 << 20, initramfsSHA256: String(repeating: "a", count: 64),
            device: device, inode: UInt64.max, volumeUUID: uuid)
    }
    private func challenge() throws -> P.Challenge {
        try .init(greeting: greeting(), grant: .init(operation: .initialize, id: uuid,
            identity: .init(store: uuid, generation: UInt64.max, binding: String(repeating: "b", count: 64)),
            serial: UInt64.max, expectedEpoch: 0, newKey: String(repeating: "c", count: 64)),
            shimAudit: Data(repeating: 2, count: 32), shimUniqueID: UInt64.max,
            daemonAudit: Data(repeating: 3, count: 32), counter: UInt64.max,
            nonce: Data(repeating: 4, count: 32), expiresUnixMS: 60_000)
    }
    @Test func canonicalRoundTripAndUnsignedCorrelation() throws {
        let g = try greeting(), c = try challenge(), reply = try P.Reply(challengeSHA256: c.digest)
        #expect(try P.decodeGreeting(L.encode(g)) == g)
        #expect(try P.decodeChallenge(L.encode(c)) == c)
        #expect(try P.decodeReply(L.encode(reply)) == reply)
        #expect(try reply.verifies(c))
        #expect(try c.digest == Data(SHA256.hash(data: Data("cengine.storage-fresh-lifecycle.challenge.v2\0".utf8) + L.encode(c))))
        #expect(!c.isFresh(at: 29_999))
        #expect(c.isFresh(at: 30_000))
        #expect(c.isFresh(at: 59_999))
        #expect(!c.isFresh(at: 60_000))
        #expect(!c.isFresh(at: .max))
        #expect(throws: (any Error).self) { try P.Reply(challengeSHA256: Data(count: 31)) }
        #expect(try !P.Reply(challengeSHA256: Data(count: 32)).verifies(c))
    }
    @Test func matchesExactBackingAndExt4ButDoesNotInferRootIdentity() throws {
        let g = try greeting()
        let identity = try StorageIdentity.RootIdentity(volumeUUID: .init(uuid), inode: .max)
        let binding = StorageIdentity.StoreBinding(storeID: try .init(uuid), root: identity,
            backing: try .init(identity: identity, size: g.bytes), expectedExt4UUID: try .init(uuid))
        #expect(g.matches(binding: binding))
        let renumbered = try greeting(device: 42)
        #expect(renumbered != g)
        #expect(renumbered.matches(binding: binding))
        for changed in [
            StorageIdentity.StoreBinding(storeID: try .init(UUID().uuidString.lowercased()), root: identity, backing: binding.backing, expectedExt4UUID: binding.expectedExt4UUID),
            StorageIdentity.StoreBinding(storeID: binding.storeID, root: identity, backing: try .init(identity: identity, size: g.bytes + 1), expectedExt4UUID: binding.expectedExt4UUID),
            StorageIdentity.StoreBinding(storeID: binding.storeID, root: identity, backing: binding.backing, expectedExt4UUID: try .init(UUID().uuidString.lowercased())),
            StorageIdentity.StoreBinding(storeID: binding.storeID, root: identity, backing: try .init(identity: .init(volumeUUID: identity.volumeUUID, inode: .max - 1), size: g.bytes), expectedExt4UUID: binding.expectedExt4UUID)
        ] { #expect(!g.matches(binding: changed)) }
    }
    @Test func rejectsNoncanonicalClosedAndInvalidNestedWire() throws {
        let values: [(Data, (Data) throws -> Void)] = [
            (try L.encode(greeting()), { _ = try P.decodeGreeting($0) }),
            (try L.encode(challenge()), { _ = try P.decodeChallenge($0) }),
            (try L.encode(P.Reply(challengeSHA256: Data(count: 32))), { _ = try P.decodeReply($0) })
        ]
        for (bytes, decode) in values {
            let text = String(decoding: bytes, as: UTF8.self)
            for bad in [bytes + Data([10]), Data([32]) + bytes,
                        Data(("{\"unknown\":0," + text.dropFirst()).utf8),
                        Data(text.replacingOccurrences(of: "\"version\":", with: "\"version\":\"\(P.version)\",\"version\":").utf8),
                        Data(text.replacingOccurrences(of: P.version, with: "storage-fresh.v1").utf8)] {
                #expect(throws: (any Error).self) { try decode(bad) }
            }
        }
        let text = String(decoding: try L.encode(challenge()), as: UTF8.self)
        for (old, new) in [
            ("\"counter\":18446744073709551615", "\"counter\":0"),
            ("\"counter\":18446744073709551615", "\"counter\":18446744073709551616"),
            ("\"device\":0", "\"device\":-0"),
            ("\"bytes\":33554432", "\"bytes\":0"),
            ("\"inode\":18446744073709551615", "\"inode\":0"),
            ("\"expected_epoch\":0", "\"expected_epoch\":1"),
            ("\"operation\":\"initialize\"", "\"operation\":\"takeover\""),
            ("\"shim_unique_id\":18446744073709551615", "\"shim_unique_id\":18446744073709551614"),
            ("\"expires_unix_ms\":60000", "\"expires_unix_ms\":0"),
            ("\"greeting\":{", "\"greeting\":{\"extra\":false,")
        ] {
            try #require(text.contains(old))
            #expect(throws: (any Error).self) { try P.decodeChallenge(Data(text.replacingOccurrences(of: old, with: new).utf8)) }
        }
        let c = try challenge()
        for count in [0, 31, 33] {
            #expect(throws: (any Error).self) {
                try P.Challenge(greeting: c.greeting, grant: c.grant, shimAudit: Data(count: count),
                    shimUniqueID: c.shimUniqueID, daemonAudit: c.daemonAudit, counter: 1,
                    nonce: c.nonce, expiresUnixMS: c.expiresUnixMS)
            }
            #expect(throws: (any Error).self) {
                try P.Challenge(greeting: c.greeting, grant: c.grant, shimAudit: c.shimAudit,
                    shimUniqueID: c.shimUniqueID, daemonAudit: c.daemonAudit, counter: 1,
                    nonce: Data(count: count), expiresUnixMS: c.expiresUnixMS)
            }
        }
        #expect(throws: (any Error).self) { try P.decodeGreeting(Data(repeating: 32, count: L.maximumPayloadBytes + 1)) }
    }
}

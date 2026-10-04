import CEngineCore
import CryptoKit
import Foundation
import Testing

@Suite("Inactive lifecycle direct-child v2 wire")
struct StorageLifecycleChildProtocolTests {
    private typealias P = StorageLifecycleChildProtocol
    private typealias L = StorageLifecycleProtocol
    private struct Fixture: Decodable {
        let version: String
        let greeting: P.Greeting
        let challenge: P.Challenge
        let candidate_reply: P.Reply
        let result_challenge: P.Challenge
        let result_reply: P.Reply
        let greeting_canonical_json: String
        let challenge_canonical_json: String
        let candidate_reply_canonical_json: String
        let result_challenge_canonical_json: String
        let result_reply_canonical_json: String
        let challenge_sha256: Data
        let result_challenge_sha256: Data
        let candidate_signing_bytes: Data
        let result_signing_bytes: Data
    }
    private func fixture() throws -> Fixture {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Fixtures/storage-bootstrap/lifecycle-child-v2.json")
        return try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: url))
    }
    @Test func sharedGoWireAndSignatures() throws {
        let f = try fixture()
        #expect(f.version == P.version)
        #expect(try P.decodeGreeting(Data(f.greeting_canonical_json.utf8)) == f.greeting)
        #expect(try P.decodeChallenge(Data(f.challenge_canonical_json.utf8)) == f.challenge)
        #expect(try P.decodeChallenge(Data(f.result_challenge_canonical_json.utf8)) == f.result_challenge)
        #expect(try P.decodeReply(Data(f.candidate_reply_canonical_json.utf8)) == f.candidate_reply)
        #expect(try P.decodeReply(Data(f.result_reply_canonical_json.utf8)) == f.result_reply)
        #expect(try f.challenge.digest == f.challenge_sha256)
        #expect(try f.result_challenge.digest == f.result_challenge_sha256)
        #expect(f.candidate_reply.signingBytes == f.candidate_signing_bytes)
        #expect(f.result_reply.signingBytes == f.result_signing_bytes)
        #expect(try f.candidate_reply.verifies(f.challenge))
        #expect(try f.result_reply.verifies(f.result_challenge))
        #expect(try !f.candidate_reply.verifies(f.result_challenge))
        #expect(try !f.result_reply.verifies(f.challenge))
        #expect(f.candidate_reply.receipt == nil)
        #expect(!f.candidate_reply_canonical_json.contains("receipt"))
        #expect(f.result_reply.receipt?.nonce == f.result_challenge.nonce)
    }
    @Test func closedSchemaRejectsMalleableAndNestedInvalidMessages() throws {
        let f = try fixture()
        for text in [f.greeting_canonical_json, f.challenge_canonical_json, f.result_reply_canonical_json] {
            let bytes = Data(text.utf8)
            let decode: (Data) throws -> Void
            if text == f.greeting_canonical_json { decode = { _ = try P.decodeGreeting($0) } }
            else if text == f.challenge_canonical_json { decode = { _ = try P.decodeChallenge($0) } }
            else { decode = { _ = try P.decodeReply($0) } }
            for changed in [bytes + Data([10]), Data([32]) + bytes,
                            Data(("{\"unknown\":0," + text.dropFirst()).utf8),
                            Data(text.replacingOccurrences(of: "\"version\":\"\(P.version)\"", with: "\"version\":\"storage-child.v1\"").utf8),
                            Data(text.replacingOccurrences(of: "\"version\":", with: "\"version\":\"\(P.version)\",\"version\":").utf8)] {
                #expect(throws: (any Error).self) { try decode(changed) }
            }
        }
        for (old, new) in [("\"counter\":\(f.challenge.counter)", "\"counter\":0"),
                           ("\"counter\":\(f.challenge.counter)", "\"counter\":18446744073709551616"),
                           ("\"purpose\":\"candidate\"", "\"purpose\":\"confirm\""),
                           ("\"expected_epoch\":\(f.challenge.grant.expectedEpoch)", "\"expected_epoch\":-0") ] {
            // Assert fixture coverage rather than let a no-op replacement pass.
            try #require(f.challenge_canonical_json.contains(old))
            #expect(throws: (any Error).self) { try P.decodeChallenge(Data(f.challenge_canonical_json.replacingOccurrences(of: old, with: new).utf8)) }
        }
        let nullReceipt = "{\"receipt\":null," + f.candidate_reply_canonical_json.dropFirst()
        #expect(throws: (any Error).self) { try P.decodeReply(Data(nullReceipt.utf8)) }
        #expect(throws: (any Error).self) { try P.decodeGreeting(Data(repeating: 32, count: L.maximumPayloadBytes + 1)) }
    }
    @Test func freshnessAndRetirementEpochBoundary() throws {
        let f = try fixture(), c = f.challenge
        #expect(!c.isFresh(at: c.expiresUnixMS))
        #expect(!c.isFresh(at: UInt64.max))
        #expect(c.isFresh(at: c.expiresUnixMS - 1))
        #expect(c.isFresh(at: c.expiresUnixMS - P.lifetimeMS))
        #expect(!c.isFresh(at: c.expiresUnixMS - P.lifetimeMS - 1))
        let retirement = try L.Grant(operation: .retire, id: c.grant.id, identity: c.grant.identity,
            serial: c.grant.serial, expectedEpoch: .max, newKey: c.grant.newKey)
        #expect(try f.greeting.matches(retirement))
        let wrongEpoch = try L.Grant(operation: .retire, id: c.grant.id, identity: c.grant.identity,
            serial: c.grant.serial, expectedEpoch: .max - 1, newKey: c.grant.newKey)
        #expect(try !f.greeting.matches(wrongEpoch))
        #expect(throws: (any Error).self) {
            try P.Greeting(channelID: f.greeting.channelID, incarnationID: f.greeting.incarnationID,
                daemonUniqueID: f.greeting.daemonUniqueID, controllerSPKI: f.greeting.controllerSPKI,
                rootPublicKey: f.greeting.rootPublicKey, store: f.greeting.store,
                binding: f.greeting.binding, expectedEpoch: .max)
        }
    }
    @Test func cryptographicResultBindsEveryChallengeField() throws {
        let f = try fixture(), c = f.result_challenge
        let changed = try P.Challenge(greeting: c.greeting, grant: c.grant, childAudit: c.childAudit,
            childUniqueID: c.childUniqueID, daemonAudit: c.daemonAudit, counter: c.counter - 1,
            nonce: c.nonce, purpose: c.purpose, expiresUnixMS: c.expiresUnixMS, boot: c.boot)
        #expect(try !f.result_reply.verifies(changed))
        let key = try Curve25519.Signing.PublicKey(rawRepresentation: Data(c.greeting.controllerSPKI.suffix(32)))
        #expect(!key.isValidSignature(f.result_reply.signature, for: c.grant.signingBytes))
        #expect(!key.isValidSignature(f.result_reply.signature, for: try #require(f.result_reply.receipt).signingBytes))
    }
    @Test func resultRequiresRootBoundBootAndBindsEveryField() throws {
        let f = try fixture(), c = f.result_challenge
        let boot = try #require(c.boot)
        func challenge(_ value: StorageLifecycleBootTrust?, purpose: P.Purpose = .result) throws -> P.Challenge {
            try .init(greeting: c.greeting, grant: c.grant, childAudit: c.childAudit,
                      childUniqueID: c.childUniqueID, daemonAudit: c.daemonAudit, counter: c.counter,
                      nonce: c.nonce, purpose: purpose, expiresUnixMS: c.expiresUnixMS, boot: value)
        }
        #expect(f.challenge.boot == nil)
        #expect(throws: (any Error).self) { try challenge(nil) }
        #expect(throws: (any Error).self) { try challenge(boot, purpose: .candidate) }
        for field in 0..<7 {
            let identity = try L.Identity(store: field == 0 ? c.grant.id : boot.identity.store,
                generation: boot.identity.generation + (field == 1 ? 1 : 0),
                binding: field == 2 ? String(repeating: "e", count: 64) : boot.identity.binding)
            let changed = try StorageLifecycleBootTrust(identity: identity,
                serviceEpoch: field == 3 ? c.grant.id : boot.serviceEpoch,
                tlsRootSHA256: field == 4 ? String(repeating: "a", count: 64) : boot.tlsRootSHA256,
                serverSPKI: field == 5 ? String(repeating: "a", count: 64) : boot.serverSPKI,
                bootstrapKey: field == 6 ? String(repeating: "a", count: 64) : boot.bootstrapKey)
            if field < 3 || field == 6 {
                #expect(throws: (any Error).self) { try challenge(changed) }
            } else {
                #expect(try !f.result_reply.verifies(challenge(changed)))
            }
        }
        let encodedBoot = String(decoding: try L.encode(boot), as: UTF8.self)
        let missing = f.result_challenge_canonical_json.replacingOccurrences(of: "\"boot\":\(encodedBoot),", with: "")
        #expect(missing != f.result_challenge_canonical_json)
        #expect(throws: (any Error).self) { try P.decodeChallenge(Data(missing.utf8)) }
        let nullBoot = f.result_challenge_canonical_json.replacingOccurrences(of: encodedBoot, with: "null")
        #expect(throws: (any Error).self) { try P.decodeChallenge(Data(nullBoot.utf8)) }
        // Re-sign with the documented public RFC 8032 seed to isolate epoch
        // correlation from signature integrity. A valid signature is insufficient.
        let seed: [UInt8] = [0x4c,0xcd,0x08,0x9b,0x28,0xff,0x96,0xda,0x9d,0xb6,0xc3,0x46,0xec,0x11,0x4e,0x0f,
                            0x5b,0x8a,0x31,0x9f,0x35,0xab,0xa6,0x24,0xda,0x8c,0xf6,0xed,0x4f,0xb8,0xa6,0xfb]
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(seed))
        let receipt = try L.Receipt(grant: c.grant, nonce: c.nonce, serviceEpoch: c.grant.id, revision: 1)
        let unsigned = try P.Reply(challengeSHA256: c.digest, receipt: receipt, signature: Data(repeating: 0, count: 64))
        let signed = try P.Reply(challengeSHA256: c.digest, receipt: receipt, signature: key.signature(for: unsigned.signingBytes))
        #expect(try !signed.verifies(c))
    }

    @Test func bootTrustValidatesIdentifiersAndFingerprints() throws {
        let boot = try #require(fixture().result_challenge.boot)
        #expect(try L.decode(StorageLifecycleBootTrust.self, from: L.encode(boot)) == boot)
        for field in 0..<4 {
            #expect(throws: (any Error).self) {
                try StorageLifecycleBootTrust(identity: boot.identity,
                    serviceEpoch: field == 0 ? "invalid" : boot.serviceEpoch,
                    tlsRootSHA256: field == 1 ? String(repeating: "A", count: 64) : boot.tlsRootSHA256,
                    serverSPKI: field == 2 ? "bad" : boot.serverSPKI,
                    bootstrapKey: field == 3 ? "" : boot.bootstrapKey)
            }
        }
    }

}

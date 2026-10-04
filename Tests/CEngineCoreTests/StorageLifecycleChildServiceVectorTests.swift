import CEngineCore
import CryptoKit
import Foundation
import Testing

@Suite("Lifecycle child service proof Go vectors")
struct StorageLifecycleChildServiceVectorTests {
    private typealias P = StorageLifecycleChildProtocol
    private typealias L = StorageLifecycleProtocol
    private struct Fixture: Decodable {
        let version: String
        let vectors: [Vector]
    }
    private struct Vector: Decodable {
        let name: String
        let challenge: P.Challenge
        let reply: P.Reply
        let challenge_canonical_json: String
        let reply_canonical_json: String
        let challenge_sha256: Data
        let signing_bytes: Data
    }
    private func fixture() throws -> Fixture {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Fixtures/storage-bootstrap/lifecycle-child-service-v2.json")
        return try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: url))
    }
    @Test func exactCanonicalWireDigestSigningBytesAndSignatures() throws {
        let f = try fixture()
        #expect(f.version == P.version)
        #expect(f.vectors.map(\.name) == ["service_result", "service_change_result", "service_commit"])
        for v in f.vectors {
            let challengeBytes = Data(v.challenge_canonical_json.utf8), replyBytes = Data(v.reply_canonical_json.utf8)
            #expect(try P.decodeChallenge(challengeBytes) == v.challenge)
            #expect(try P.decodeReply(replyBytes) == v.reply)
            #expect(try L.encode(v.challenge) == challengeBytes)
            #expect(try L.encode(v.reply) == replyBytes)
            #expect(try v.challenge.digest == v.challenge_sha256)
            #expect(v.reply.challengeSHA256 == v.challenge_sha256)
            #expect(v.reply.signingBytes == v.signing_bytes)
            #expect(try v.reply.verifies(v.challenge))
            let key = try Curve25519.Signing.PublicKey(rawRepresentation: Data(v.challenge.greeting.controllerSPKI.suffix(32)))
            #expect(key.isValidSignature(v.reply.signature, for: v.signing_bytes))
            #expect(!key.isValidSignature(v.reply.signature, for: v.signing_bytes + Data([0])))
            #expect(v.reply.receipt == nil)
            #expect(v.challenge.childUniqueID == .max)
            #expect(v.challenge.expiresUnixMS == .max)
            #expect(v.challenge.grant.serial == .max)
            #expect(v.reply.serviceResult?.controllerEpoch == .max)
            #expect(v.challenge.grant.identity.generation == 9_007_199_254_740_993)
            #expect(v.challenge.isFresh(at: UInt64.max - 1))
            #expect(!v.challenge.isFresh(at: UInt64.max))
        }
    }
    @Test func purposeAndResultUnionsRemainClosed() throws {
        let vectors = try fixture().vectors
        let staged = vectors[1].challenge, commit = vectors[2].challenge
        #expect(vectors[0].challenge.purpose == .serviceResult)
        #expect(vectors[0].challenge.changeRequest == nil)
        #expect(staged.purpose == .serviceResult && staged.changeRequest != nil)
        #expect(commit.purpose == .serviceCommit && commit.confirmation != nil)
        func challenge(_ purpose: P.Purpose, boot: StorageLifecycleBootTrust?,
                       change: L.ServiceChangeRequest? = nil, confirmation: L.ServiceChangeConfirmation? = nil) throws -> P.Challenge {
            try .init(greeting: staged.greeting, grant: staged.grant, childAudit: staged.childAudit,
                childUniqueID: staged.childUniqueID, daemonAudit: staged.daemonAudit, counter: staged.counter,
                nonce: staged.nonce, purpose: purpose, expiresUnixMS: staged.expiresUnixMS,
                boot: boot, changeRequest: change, confirmation: confirmation)
        }
        for purpose in [P.Purpose.candidate, .result, .serviceCommit] {
            #expect(throws: (any Error).self) { try challenge(purpose, boot: staged.boot, change: staged.changeRequest) }
        }
        #expect(throws: (any Error).self) { try challenge(.serviceResult, boot: staged.boot, confirmation: commit.confirmation) }
        #expect(throws: (any Error).self) { try challenge(.serviceCommit, boot: staged.boot) }
        #expect(throws: (any Error).self) { try challenge(.serviceResult, boot: nil) }
        let result = try #require(vectors[1].reply.serviceResult)
        let receipt = try L.Receipt(grant: result.grant, nonce: result.nonce, serviceEpoch: result.serviceEpoch, revision: 1)
        #expect(throws: (any Error).self) {
            try P.Reply(challengeSHA256: vectors[1].reply.challengeSHA256, receipt: receipt,
                        signature: vectors[1].reply.signature, serviceResult: result)
        }
        let candidateOnly = try P.Reply(challengeSHA256: vectors[1].reply.challengeSHA256, receipt: nil,
                                       signature: vectors[1].reply.signature)
        #expect(try !candidateOnly.verifies(staged))
        #expect(try !vectors[1].reply.verifies(commit))
        for v in vectors {
            for text in [v.challenge_canonical_json, v.reply_canonical_json] {
                let isChallenge = text == v.challenge_canonical_json
                for malformed in [text + "\n", "{\"unknown\":0," + text.dropFirst(),
                    text.replacingOccurrences(of: "\"version\":", with: "\"version\":\"\(P.version)\",\"version\":")] {
                    #expect(throws: (any Error).self) {
                        if isChallenge { _ = try P.decodeChallenge(Data(malformed.utf8)) }
                        else { _ = try P.decodeReply(Data(malformed.utf8)) }
                    }
                }
            }
        }
    }
    @Test func oldCandidateVectorIsByteForByteUnchanged() throws {
        struct OldFixture: Decodable {
            let challenge: P.Challenge
            let candidate_reply: P.Reply
            let challenge_canonical_json: String
            let candidate_reply_canonical_json: String
            let challenge_sha256: Data
            let candidate_signing_bytes: Data
        }
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Fixtures/storage-bootstrap/lifecycle-child-v2.json")
        let f = try JSONDecoder().decode(OldFixture.self, from: Data(contentsOf: url))
        #expect(f.challenge.purpose == .candidate)
        #expect(f.challenge.changeRequest == nil && f.challenge.confirmation == nil)
        #expect(f.candidate_reply.serviceResult == nil)
        #expect(try L.encode(f.challenge) == Data(f.challenge_canonical_json.utf8))
        #expect(try L.encode(f.candidate_reply) == Data(f.candidate_reply_canonical_json.utf8))
        #expect(try P.decodeChallenge(Data(f.challenge_canonical_json.utf8)) == f.challenge)
        #expect(try P.decodeReply(Data(f.candidate_reply_canonical_json.utf8)) == f.candidate_reply)
        #expect(try f.challenge.digest == f.challenge_sha256)
        #expect(f.candidate_reply.signingBytes == f.candidate_signing_bytes)
        #expect(try f.candidate_reply.verifies(f.challenge))
    }
}

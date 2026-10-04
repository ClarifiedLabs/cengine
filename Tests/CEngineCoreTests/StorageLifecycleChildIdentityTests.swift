import CEngineCore
import Foundation
import Testing

@Suite struct StorageLifecycleChildIdentityTests {
    private typealias P = StorageLifecycleChildProtocol
    private struct Fixture: Decodable {
        let challenge: String
        let reply: String
        let digest: Data
        let signing_bytes: Data
    }
    @Test func goVectorAndClosedIdentityFamily() throws {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Fixtures/storage-bootstrap/lifecycle-child-identity-v1.json")
        let f = try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: url))
        let c = try P.decodeIdentityChallenge(Data(f.challenge.utf8))
        let r = try P.decodeIdentityReply(Data(f.reply.utf8))
        #expect(try c.digest == f.digest)
        #expect(r.signingBytes == f.signing_bytes)
        #expect(try r.verifies(c))
        #expect(c.childUniqueID == UInt64.max)
        #expect(c.isFresh(at: UInt64.max - 1))
        #expect(!c.isFresh(at: UInt64.max))
        #expect(try StorageLifecycleProtocol.encode(c) == Data(f.challenge.utf8))
        #expect(try StorageLifecycleProtocol.encode(r) == Data(f.reply.utf8))
        #expect(throws: (any Error).self) { try P.decodeChallenge(Data(f.challenge.utf8)) }
        #expect(throws: (any Error).self) { try P.decodeReply(Data(f.reply.utf8)) }
        for malformed in [f.challenge + "\n", "{\"grant\":null," + f.challenge.dropFirst(),
            f.challenge.replacingOccurrences(of: "\"version\":", with: "\"version\":\"wrong\",\"version\":"),
            f.challenge.replacingOccurrences(of: P.identityVersion, with: P.version)] {
            #expect(throws: (any Error).self) { try P.decodeIdentityChallenge(Data(malformed.utf8)) }
        }
        let changed = try P.IdentityChallenge(greeting: c.greeting, childAudit: c.childAudit,
            childUniqueID: c.childUniqueID, daemonAudit: c.daemonAudit, counter: c.counter,
            nonce: c.nonce, requestSHA256: Data(repeating: 7, count: 32), expiresUnixMS: c.expiresUnixMS)
        #expect(try !r.verifies(changed))
    }
}

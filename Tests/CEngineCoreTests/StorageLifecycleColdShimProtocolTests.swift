import CEngineCore
import Foundation
import Testing

@Suite struct StorageLifecycleColdShimProtocolTests {
    private typealias S = StorageLifecycleColdShimProtocol
    private typealias L = StorageLifecycleProtocol
    private func challenge(_ f: ColdContractFixture, counter: UInt64 = 1, nonce: Data = Data(repeating: 3, count: 32),
                           prepareSHA256: String? = nil, baseEpoch: UInt64? = nil) throws -> S.Challenge {
        try .init(greeting: f.prepare.mountedGreeting, prepareSHA256: prepareSHA256 ?? f.prepare.digest,
                  unsignedGrant: f.prepared.signedOpen.request.takeover.grant, signedOpenSHA256: f.prepared.signedOpenSHA256,
                  baseEpoch: baseEpoch ?? f.prepared.baseEpoch, shimAudit: Data(repeating: 1, count: 32), shimUniqueID: 20,
                  daemonAudit: Data(repeating: 2, count: 32), daemonUniqueID: 10, counter: counter, nonce: nonce, expiresUnixMS: 40_000)
    }
    @Test func mountChallengeAndTypedEnrollmentRoundTrip() throws {
        let f = try ColdContractFixture(), c = try challenge(f), g = f.prepare.mountedGreeting
        #expect(try S.decodeGreeting(S.encode(g)) == g)
        #expect(try S.decodeChallenge(S.encode(c)) == c)
        try c.validate(prepare: f.prepare, prepared: f.prepared)
        let reply = try S.Reply(challengeSHA256: c.digest)
        #expect(try S.decodeReply(S.encode(reply), for: c) == reply)
        #expect(c.isFresh(at: 10_000)); #expect(!c.isFresh(at: 9_999)); #expect(!c.isFresh(at: 40_000))
        #expect(!c.isFresh(at: UInt64.max))
        let seed = try S.ColdEnrollmentSeed(operationID: f.prepare.operationID, signedOpenSHA256: f.prepared.signedOpenSHA256,
                                           successorOrigin: f.prepared.successorOrigin, baseEpoch: f.prepared.baseEpoch)
        try seed.validate(prepared: f.prepared)
        #expect(try S.decodeEnrollmentSeed(S.encode(seed)) == seed)
        let ack = try S.ColdEnrollmentAcknowledgement(for: seed)
        #expect(try S.decodeEnrollmentAcknowledgement(S.encode(ack), for: seed) == ack)
        #expect(throws: (any Error).self) { try S.decodeReply(S.encode(ack), for: c) }
        #expect(throws: (any Error).self) { try S.decodeEnrollmentAcknowledgement(S.encode(reply), for: seed) }
        let other = try S.ColdEnrollmentSeed(operationID: seed.operationID, signedOpenSHA256: String(repeating: "0", count: 64),
                                            successorOrigin: seed.successorOrigin, baseEpoch: seed.baseEpoch)
        #expect(throws: (any Error).self) { try S.decodeEnrollmentAcknowledgement(S.encode(ack), for: other) }
        #expect(throws: (any Error).self) { try other.validate(prepared: f.prepared) }
    }
    @Test func exactChallengeJoinReplayAndNativeTupleShape() throws {
        let f = try ColdContractFixture(), c = try challenge(f)
        let reply = try S.Reply(challengeSHA256: c.digest)
        for changed in [try challenge(f, counter: 2), try challenge(f, nonce: Data(repeating: 4, count: 32))] {
            #expect(throws: (any Error).self) { try S.decodeReply(S.encode(reply), for: changed) }
        }
        for changed in [try challenge(f, prepareSHA256: String(repeating: "0", count: 64)), try challenge(f, baseEpoch: 2)] {
            #expect(throws: (any Error).self) { try changed.validate(prepare: f.prepare, prepared: f.prepared) }
        }
        #expect(throws: (any Error).self) { try challenge(f, counter: 0) }
        #expect(throws: (any Error).self) { try challenge(f, nonce: Data(repeating: 0, count: 31)) }
        let text = String(decoding: try S.encode(c), as: UTF8.self)
        for (old, new) in [("\"shimUniqueID\":20", "\"shimUniqueID\":10"),
                           ("\"daemonUniqueID\":10", "\"daemonUniqueID\":0"),
                           ("\"expiresUnixMS\":40000", "\"expiresUnixMS\":0"),
                           ("\"shimAudit\":\"\(c.shimAudit.base64EncodedString())\"", "\"shimAudit\":\"\(c.daemonAudit.base64EncodedString())\"")] {
            let bad = text.replacingOccurrences(of: old, with: new)
            #expect(bad != text)
            #expect(throws: (any Error).self) { try S.decodeChallenge(Data(bad.utf8)) }
        }
    }
    @Test func liveDeviceRenumberingPreservesOriginButNotGreeting() throws {
        let f = try ColdContractFixture(), g = f.prepare.mountedGreeting
        let observed = StorageLifecycleStoreBinding.LiveFileIdentity(
            .init(stableIdentity: try g.binding.backing.value(), device: 0))
        let changed = try S.Greeting(channelID: g.channelID, daemonUniqueID: g.daemonUniqueID,
            rootPublicKey: g.rootPublicKey, binding: g.binding, bootBinding: g.bootBinding,
            launch: g.launch, heldBackingIdentity: observed)
        #expect(changed != g)
        #expect(changed.heldBackingIdentity.device == 0)
        #expect(try changed.successorOrigin == g.successorOrigin)
        #expect(try S.decodeGreeting(S.encode(changed)) == changed)
        let text = String(decoding: try S.encode(changed), as: UTF8.self)
        for bad in [text.replacingOccurrences(of: S.version, with: "storage-lifecycle-cold-shim.v1"),
                    text.replacingOccurrences(of: "\"device\":0,", with: "")] {
            #expect(throws: (any Error).self) { try S.decodeGreeting(Data(bad.utf8)) }
        }
    }

    @Test func mountedGreetingMustJoinLaunchBackingAndActualBootNonce() throws {
        let f = try ColdContractFixture(), g = f.prepare.mountedGreeting
        var boot = g.bootBinding; boot.bytes += 1
        #expect(throws: (any Error).self) {
            try S.Greeting(channelID: g.channelID, daemonUniqueID: g.daemonUniqueID, rootPublicKey: g.rootPublicKey,
                           binding: g.binding, bootBinding: boot, launch: g.launch, heldBackingIdentity: g.heldBackingIdentity)
        }
        #expect(throws: (any Error).self) {
            try S.Greeting(channelID: g.channelID, daemonUniqueID: g.daemonUniqueID, rootPublicKey: g.rootPublicKey,
                           binding: g.binding, bootBinding: g.bootBinding, launch: g.launch, heldBackingIdentity: .init(.init(stableIdentity: g.binding.root.value(), device: 1)))
        }
        let text = String(decoding: try S.encode(g), as: UTF8.self)
        for bad in [text + "\n", text.replacingOccurrences(of: S.version, with: "old.v0"),
                    text.replacingOccurrences(of: "\"guestBootNonce\":\"\(g.bootBinding.guestBootNonce)\"", with: "\"guestBootNonce\":\"invalid\""),
                    text.replacingOccurrences(of: "\"bootBinding\":{", with: "\"bootBinding\":{\"exitBoolean\":true,"),
                    text.replacingOccurrences(of: "\"launch\":{", with: "\"launch\":null,\"launch\":{"),
                    text.replacingOccurrences(of: "\"heldBackingIdentity\":{", with: "\"heldBackingIdentity\":{\"fd\":3,")] {
            #expect(throws: (any Error).self) { try S.decodeGreeting(Data(bad.utf8)) }
        }
    }
}

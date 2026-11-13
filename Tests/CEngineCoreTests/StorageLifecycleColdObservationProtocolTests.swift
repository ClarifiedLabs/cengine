import CEngineCore
import CryptoKit
import Foundation
import Testing

@Suite("Observed cold history stays separate from service authority")
struct StorageLifecycleColdObservationProtocolTests {
    private typealias O = StorageLifecycleColdObservationProtocol
    private typealias C = StorageLifecycleColdProtocol
    private typealias R = StorageLifecycleColdRootProtocol
    private typealias S = StorageLifecycleColdShimProtocol
    private typealias L = StorageLifecycleProtocol
    private typealias W = StorageLifecycleServiceBootProtocol

    private func history(applied: Bool = false) throws -> (ColdContractFixture, O.History) {
        let f = try ColdContractFixture(), old = f.prepared.signedOpen.request, p = old.predecessor
        let launch = try C.Launch(shimLaunchUUID: "88888888-8888-4888-8888-888888888888", specSHA256: old.launch.specSHA256,
            initramfsSHA256: old.launch.initramfsSHA256, ext4UUID: old.launch.ext4UUID, bytes: old.launch.bytes)
        let g = f.prepare.mountedGreeting
        let greeting = try S.Greeting(channelID: g.channelID, daemonUniqueID: g.daemonUniqueID, rootPublicKey: g.rootPublicKey,
            binding: g.binding, bootBinding: .init(shimLaunchUUID: launch.shimLaunchUUID, guestBootNonce: g.bootBinding.guestBootNonce,
                ext4UUID: launch.ext4UUID, bytes: launch.bytes), launch: launch, heldBackingIdentity: g.heldBackingIdentity)
        let request = try O.Request(observationID: "99999999-9999-4999-8999-999999999999", subject: L.encode(f.prepared.signedOpen), observer: launch)
        let signed = try O.SignedRequest(request: request, signature: f.key.signature(for: request.signingBytes))
        let observe = try R.Observe(observationID: request.observationID, identity: old.takeover.grant.identity,
            operationID: old.operationID, signedOpenSHA256: f.prepared.signedOpenSHA256, observerGreeting: greeting)
        let predecessor = applied ? try C.Predecessor(currentGrant: old.takeover.grant,
            serviceEpoch: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", controllerEpoch: p.controllerEpoch + 1,
            controllerKey: old.takeover.grant.newKey, openRevision: p.openRevision + 1, bootstrapKey: p.bootstrapKey) : p
        let observation = try O.Observation(requestSHA256: request.digest, outcome: applied ? .applied : .unchanged, predecessor: predecessor)
        let anchor = try L.ServiceState(grant: p.currentGrant,
            context: .init(serviceEpoch: p.serviceEpoch, controllerEpoch: p.controllerEpoch, controllerKey: p.controllerKey),
            openRevision: p.openRevision, boot: .init(identity: p.currentGrant.identity, serviceEpoch: p.serviceEpoch,
                tlsRootSHA256: String(repeating: "1", count: 64), serverSPKI: String(repeating: "2", count: 64), bootstrapKey: p.bootstrapKey))
        return (f, try O.History(request: observe, authorization: signed, observation: observation, anchor: anchor,
            failedOrigin: f.prepared.successorOrigin, failedBaseEpoch: f.prepared.baseEpoch))
    }

    private func successor(_ f: ColdContractFixture, _ h: O.History) throws -> R.Prepared {
        let g = try L.Grant(operation: .takeover, id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", identity: h.request.identity,
            serial: 3, expectedEpoch: h.predecessor.controllerEpoch, newKey: String(repeating: "4", count: 64))
        let signed = try L.SignedGrant(grant: g, signature: f.key.signature(for: g.signingBytes))
        let r = try C.Request(operationID: g.id, predecessor: h.predecessor, takeover: signed, launch: h.request.observerGreeting.launch,
            nowUnixSeconds: 1_800_000_001, lifetimeSeconds: 60, observation: h.authorization)
        return try R.Prepared(signedOpen: .init(request: r, signature: f.key.signature(for: r.signingBytes)),
            successorOrigin: h.request.observerGreeting.successorOrigin, baseEpoch: h.failedBaseEpoch, observedHistory: h)
    }

    @Test func unchangedAndAppliedHistoryAndNewRealCompletionRoundTrip() throws {
        for applied in [false, true] {
            let (f, h) = try history(applied: applied)
            try h.validate(preparedFailed: f.prepared, anchor: h.anchor)
            #expect(try L.decode(O.History.self, from: L.encode(h)) == h)
            #expect(try h.anchor.grant != h.authorization.request.subjectOpen().request.takeover.grant)
            let request = try R.Request(requestID: .init(UUID().uuidString.lowercased()), body: .observe(h.request))
            #expect(try R.decodeRequest(R.encode(request)) == request)
            let reply = try R.Reply(for: request, body: .observed(h))
            #expect(try R.decodeReply(R.encode(reply), for: request) == reply)
            #expect(throws: (any Error).self) { try R.Reply(for: request, body: .completed(f.completed)) }
            let next = try successor(f, h), g = next.signedOpen.request.takeover.grant
            #expect(next.signedOpen.isValidSignature(using: try .init(publicData: f.key.publicKey.rawRepresentation)))
            #expect(try L.decode(R.Prepared.self, from: L.encode(next)) == next)
            for wrongEpoch in [h.failedBaseEpoch - 1, h.failedBaseEpoch + 1, UInt64.max] {
                #expect(throws: (any Error).self) {
                    try R.Prepared(signedOpen: next.signedOpen, successorOrigin: next.successorOrigin,
                        baseEpoch: wrongEpoch, observedHistory: h)
                }
            }
            let e = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
            let receipt = try L.Receipt(grant: g, nonce: Data(repeating: 1, count: 32), serviceEpoch: e, revision: h.predecessor.openRevision + 1)
            let state = try L.ServiceState(grant: g, context: .init(serviceEpoch: e, controllerEpoch: g.expectedEpoch + 1, controllerKey: g.newKey),
                openRevision: receipt.revision, boot: .init(identity: g.identity, serviceEpoch: e, tlsRootSHA256: String(repeating: "5", count: 64),
                    serverSPKI: String(repeating: "6", count: 64), bootstrapKey: h.predecessor.bootstrapKey))
            let completed = try R.Completed(operationID: g.id, signedOpenSHA256: next.signedOpenSHA256,
                successorOrigin: next.successorOrigin, baseEpoch: next.baseEpoch, receipt: receipt, successor: state, observedHistory: h)
            try completed.validate(prepared: next)
            #expect(try L.decode(R.Completed.self, from: L.encode(completed)) == completed)
            #expect(throws: (any Error).self) { try h.validate(preparedFailed: next, anchor: h.anchor) }
        }
    }

    @Test func coldRootMessagesStayCompactAndDecodeOnDispatchWorker() async throws {
        // Large inline payloads amplify across Debug RPC frames and overflow the
        // normal host-owner dispatch stack, even when the payload is not selected.
        let word = MemoryLayout<UnsafeRawPointer>.size
        #expect(MemoryLayout<R.Body>.size <= 2 * word)
        #expect(MemoryLayout<R.ResultBody>.size <= 2 * word)
        #expect(MemoryLayout<R.Request>.size <= 4 * word)
        #expect(MemoryLayout<R.Reply>.size <= 8 * word)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            DispatchQueue(label: "dev.cengine.test.cold-root-stack").async {
                continuation.resume(with: Result {
                    let (f, h) = try history(), p = f.prepare
                    let status = try R.Status(predecessor: p.expectedPredecessor, origin: p.expectedOrigin,
                        allocatedEpoch: p.expectedAllocatedEpoch, eligibility: .observationRequired)
                    let pairs: [(R.Body, R.ResultBody)] = [(.status(p.identity), .status(status)),
                        (.prepare(p), .prepared(f.prepared)),
                        (.complete(operationID: p.operationID, signedOpenSHA256: try f.prepared.signedOpenSHA256), .completed(f.completed)),
                        (.observe(h.request), .observed(h))]
                    for (body, result) in pairs {
                        let request = try R.Request(requestID: .init(UUID().uuidString.lowercased()), body: body)
                        #expect(try R.decodeRequest(R.encode(request)) == request)
                        let reply = try R.Reply(for: request, body: result)
                        #expect(try R.decodeReply(R.encode(reply), for: request) == reply)
                        let failure = try R.Reply(for: request, body: .failure(.unauthorized))
                        #expect(try R.decodeReply(R.encode(failure), for: request) == failure)
                    }
                })
            }
        }
    }

    @Test func signingOrderSignaturePinsAndCompactHeapValues() throws {
        let (f, h) = try history(), r = h.authorization.request, l = r.observer
        let json = "{\"observation_id\":\"\(r.observationID)\",\"subject\":\"\(r.subject.base64EncodedString())\",\"observer\":{\"shim_launch_uuid\":\"\(l.shimLaunchUUID)\",\"spec_sha256\":\"\(l.specSHA256)\",\"initramfs_sha256\":\"\(l.initramfsSHA256)\",\"ext4_uuid\":\"\(l.ext4UUID)\",\"bytes\":\(l.bytes)}}"
        #expect(r.signingBytes == Data(("cengine.storageauthority.lifecycle-cold-observe.v1\0" + json).utf8))
        #expect(r.digest == SHA256.hash(data: r.signingBytes).map { String(format: "%02x", $0) }.joined())
        let root = try StorageIdentity.RootPublicKey(publicData: f.key.publicKey.rawRepresentation)
        #expect(h.authorization.isValidSignature(using: root))
        let bad = try O.SignedRequest(request: r, signature: Data(repeating: 0, count: 64))
        #expect(!bad.isValidSignature(using: root))
        #expect(!h.authorization.isValidSignature(using: try .init(publicData: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)))
        #expect(MemoryLayout<O.SignedRequest>.size <= 2 * MemoryLayout<UnsafeRawPointer>.size)
        #expect(MemoryLayout<O.History>.size <= 2 * MemoryLayout<UnsafeRawPointer>.size)
        let next = try successor(f, h).signedOpen.request
        let badNestedRequest = try C.Request(operationID: next.operationID, predecessor: next.predecessor, takeover: next.takeover,
            launch: next.launch, nowUnixSeconds: next.nowUnixSeconds, lifetimeSeconds: next.lifetimeSeconds, observation: bad)
        let validOuterWithBadNested = try C.SignedOpen(request: badNestedRequest, signature: f.key.signature(for: badNestedRequest.signingBytes))
        #expect(!validOuterWithBadNested.isValidSignature(using: root))
        let suffix = ",\"observation\":{\"request\":\(json),\"signature\":\"\(h.authorization.signature.base64EncodedString())\"}}"
        #expect(String(decoding: next.signingBytes, as: UTF8.self).hasSuffix(suffix))
        for value in [try L.encode(f.prepared), try L.encode(f.completed), try L.encode(f.prepare), try L.encode(f.prepared.signedOpen.request)] {
            #expect(!String(decoding: value, as: UTF8.self).contains("observation"))
            #expect(!String(decoding: value, as: UTF8.self).contains("observedHistory"))
        }
    }

    @Test func portableObservationDigestVector() throws {
        struct Vector: Decodable { let canonical_frame: String }
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Fixtures/storage-bootstrap/lifecycle-cold-open-v1.json")
        let vector = try JSONDecoder().decode(Vector.self, from: Data(contentsOf: url))
        let old = try #require(W.decode(Data(vector.canonical_frame.utf8)).configuration?.cold), l = old.request.launch
        let observer = try C.Launch(shimLaunchUUID: "88888888-8888-4888-8888-888888888888", specSHA256: l.specSHA256,
            initramfsSHA256: l.initramfsSHA256, ext4UUID: l.ext4UUID, bytes: l.bytes)
        let request = try O.Request(observationID: "77777777-7777-4777-8777-777777777777", subject: L.encode(old), observer: observer)
        #expect(request.digest == "edfb34801241a1e4ef2c398ffeff21ad926fd708f923d945ac9590c843fa8550")
    }

    @Test func subjectIsBoundedCanonicalAndNonrecursiveBeforeTypedDecode() throws {
        let (_, h) = try history(), r = h.authorization.request
        let original = String(decoding: r.subject, as: UTF8.self)
        for subject in [Data(), Data(repeating: 32, count: O.maximumSubjectBytes + 1), Data((original + "\n").utf8),
                        Data(original.replacingOccurrences(of: "\"request\":{", with: "\"request\":{\"observation\":null,").utf8),
                        Data(original.replacingOccurrences(of: "\"request\":{", with: "\"request\":{\"observation\":{},").utf8)] {
            #expect(throws: (any Error).self) { try O.Request(observationID: r.observationID, subject: subject, observer: r.observer) }
        }
        let old = try r.subjectOpen()
        #expect(throws: (any Error).self) { try O.Request(observationID: r.observationID, subject: r.subject, observer: old.request.launch) }
        let forged = try C.SignedOpen(request: old.request, signature: Data(repeating: 0, count: 64))
        let request = try O.Request(observationID: r.observationID, subject: L.encode(forged), observer: r.observer)
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 7, count: 32))
        let authorization = try O.SignedRequest(request: request, signature: key.signature(for: request.signingBytes))
        #expect(!authorization.isValidSignature(using: try .init(publicData: key.publicKey.rawRepresentation)))
    }

    @Test func projectionsRejectFalseOutcomeDigestAndReusedAbandonedAuthority() throws {
        let (f, unchanged) = try history(), (_, applied) = try history(applied: true)
        for (outcome, p): (O.Observation.Outcome, C.Predecessor) in [(.unchanged, applied.predecessor), (.applied, unchanged.predecessor)] {
            let bad = try O.Observation(requestSHA256: unchanged.authorization.request.digest, outcome: outcome, predecessor: p)
            #expect(throws: (any Error).self) { try bad.validate(for: unchanged.authorization.request) }
        }
        let bad = try O.Observation(requestSHA256: String(repeating: "0", count: 64), outcome: .unchanged, predecessor: unchanged.predecessor)
        #expect(throws: (any Error).self) { try bad.validate(for: unchanged.authorization.request) }
        let old = f.prepared.signedOpen.request, h = unchanged
        #expect(throws: (any Error).self) {
            try C.Request(operationID: old.operationID, predecessor: old.predecessor, takeover: old.takeover,
                launch: h.authorization.request.observer, nowUnixSeconds: old.nowUnixSeconds, lifetimeSeconds: old.lifetimeSeconds,
                observation: h.authorization)
        }
        let next = try successor(f, h)
        #expect(throws: (any Error).self) {
            try R.Prepared(signedOpen: next.signedOpen, successorOrigin: next.successorOrigin, baseEpoch: next.baseEpoch)
        }
    }

    @Test func separateNativeChallengeAndBootFramesAreClosedAndCorrelated() throws {
        let (_, h) = try history(), g = h.request.observerGreeting
        let challenge = try S.ObservationChallenge(authorization: h.authorization, greeting: g,
            shimAudit: Data(repeating: 1, count: 32), shimUniqueID: 20,
            daemonAudit: Data(repeating: 2, count: 32), daemonUniqueID: g.daemonUniqueID,
            counter: 1, nonce: Data(repeating: 3, count: 32), expiresUnixMS: 40_000)
        #expect(challenge.isFresh(at: 10_000) && !challenge.isFresh(at: 9_999) && !challenge.isFresh(at: 40_000))
        #expect(try S.decodeObservationChallenge(S.encode(challenge)) == challenge)
        let reply = try S.ObservationReply(challengeSHA256: challenge.digest, observation: h.observation)
        #expect(try S.decodeObservationReply(S.encode(reply), for: challenge) == reply)
        let bad = try S.ObservationReply(challengeSHA256: Data(repeating: 0, count: 32), observation: h.observation)
        #expect(throws: (any Error).self) { try bad.validate(for: challenge) }
        let request = W.Frame(operation: .observeCold, binding: g.bootBinding, observationAuthorization: h.authorization,
            observationRootPublicKey: g.rootPublicKey)
        let response = W.Frame(operation: .coldObserved, binding: g.bootBinding, coldObservation: h.observation)
        for frame in [request, response] {
            #expect(try W.decode(Data(W.encode(frame).dropFirst(4))) == frame)
            var mixed = frame; mixed.ok = true
            #expect(throws: (any Error).self) { try W.encode(mixed) }
        }
        var wrong = request; wrong.operation = .configure
        #expect(throws: (any Error).self) { try W.encode(wrong) }
        wrong = request; wrong.binding = .init(shimLaunchUUID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            guestBootNonce: g.bootBinding.guestBootNonce, ext4UUID: g.launch.ext4UUID, bytes: g.launch.bytes)
        #expect(throws: (any Error).self) { try W.encode(wrong) }
        let bytes = try L.encode(request), text = String(decoding: bytes, as: UTF8.self)
        #expect(throws: (any Error).self) { try W.decode(Data(text.replacingOccurrences(of: "\"observation_authorization\":{", with: "\"observation_authorization\":{\"unknown\":true,").utf8)) }
    }
}

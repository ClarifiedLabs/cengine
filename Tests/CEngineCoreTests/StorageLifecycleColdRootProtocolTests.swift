import CEngineCore
import CryptoKit
import Foundation
import Testing

/// Shared only by the two dormant cold-contract test suites.
struct ColdContractFixture {
    typealias L = StorageLifecycleProtocol
    typealias C = StorageLifecycleColdProtocol
    typealias R = StorageLifecycleColdRootProtocol
    typealias S = StorageLifecycleColdShimProtocol
    let key: Curve25519.Signing.PrivateKey
    let prepare: R.Prepare
    let prepared: R.Prepared
    let completed: R.Completed
    init() throws {
        let root = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 7, count: 32))
        key = root
        let candidateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 8, count: 32))
        let uuid = try StorageIdentity.FilesystemUUID("11111111-1111-4111-8111-111111111111")
        let binding = StorageIdentity.StoreBinding(storeID: try .init(uuid.rawValue), root: try .init(volumeUUID: uuid, inode: 2),
            backing: try .init(identity: .init(volumeUUID: uuid, inode: 3), size: 4096), expectedExt4UUID: uuid)
        let identity = try L.Identity(binding: binding, generation: 1)
        let grant = try L.Grant(operation: .initialize, id: uuid.rawValue, identity: identity, serial: 1,
                                expectedEpoch: 0, newKey: String(repeating: "a", count: 64))
        let predecessor = try C.Predecessor(currentGrant: grant, serviceEpoch: uuid.rawValue, controllerEpoch: 1,
            controllerKey: grant.newKey, openRevision: 5, bootstrapKey: StorageIdentity.RootPublicKey(publicData: root.publicKey.rawRepresentation).fingerprint.rawValue)
        let origin = try StorageLifecycleAdoptionProtocol.Origin(binding: .init(binding), rootPublicKey: root.publicKey.rawRepresentation,
            shimLaunchUUID: uuid.rawValue, specSHA256: String(repeating: "b", count: 64))
        let launch = try C.Launch(shimLaunchUUID: "22222222-2222-4222-8222-222222222222", specSHA256: String(repeating: "c", count: 64),
            initramfsSHA256: String(repeating: "d", count: 64), ext4UUID: uuid.rawValue, bytes: 4096)
        let greeting = try S.Greeting(channelID: "33333333-3333-4333-8333-333333333333", daemonUniqueID: 10,
            rootPublicKey: root.publicKey.rawRepresentation, binding: .init(binding),
            bootBinding: .init(shimLaunchUUID: launch.shimLaunchUUID, guestBootNonce: "44444444-4444-4444-8444-444444444444",
                               ext4UUID: uuid.rawValue, bytes: 4096), launch: launch, heldBackingIdentity: .init(.init(stableIdentity: binding.backing.identity, device: 1)))
        let candidate = try StorageIdentity.Candidate(publicKey: .init(rawPublicKey: candidateKey.publicKey.rawRepresentation), childPIDHint: 123,
                                       incarnationID: .init("55555555-5555-4555-8555-555555555555"))
        prepare = try R.Prepare(operationID: "66666666-6666-4666-8666-666666666666", identity: identity,
            expectedPredecessor: predecessor, expectedOrigin: origin, expectedAllocatedEpoch: 9_007_199_254_740_993,
            candidate: candidate, mountedGreeting: greeting, nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 60)
        let takeover = try L.Grant(operation: .takeover, id: prepare.operationID, identity: identity, serial: 2,
                                   expectedEpoch: 1, newKey: candidate.publicKey.fingerprint.rawValue)
        let signed = try L.SignedGrant(grant: takeover, signature: root.signature(for: takeover.signingBytes))
        let request = try C.Request(operationID: takeover.id, predecessor: predecessor, takeover: signed, launch: launch,
                                   nowUnixSeconds: prepare.nowUnixSeconds, lifetimeSeconds: prepare.lifetimeSeconds)
        prepared = try R.Prepared(signedOpen: .init(request: request, signature: root.signature(for: request.signingBytes)),
                                  successorOrigin: greeting.successorOrigin, baseEpoch: prepare.expectedAllocatedEpoch + 1)
        let service = "77777777-7777-4777-8777-777777777777"
        let receipt = try L.Receipt(grant: takeover, nonce: Data(repeating: 1, count: 32), serviceEpoch: service, revision: 1)
        let successor = try L.ServiceState(grant: takeover, context: .init(serviceEpoch: service, controllerEpoch: 2, controllerKey: takeover.newKey),
            openRevision: 1, boot: .init(identity: identity, serviceEpoch: service, tlsRootSHA256: String(repeating: "e", count: 64),
                                        serverSPKI: String(repeating: "f", count: 64), bootstrapKey: predecessor.bootstrapKey))
        completed = try R.Completed(operationID: takeover.id, signedOpenSHA256: prepared.signedOpenSHA256,
                                    successorOrigin: prepared.successorOrigin, baseEpoch: prepared.baseEpoch, receipt: receipt, successor: successor)
    }
}

@Suite struct StorageLifecycleColdRootProtocolTests {
    private typealias R = StorageLifecycleColdRootProtocol
    private typealias L = StorageLifecycleProtocol
    private func deadHistory() throws -> (ColdContractFixture, R.ResolvedDead) {
        let f = try ColdContractFixture(), p = f.prepare.expectedPredecessor, live = f.completed
        let anchor = try L.ServiceState(grant: p.currentGrant,
            context: .init(serviceEpoch: p.serviceEpoch, controllerEpoch: p.controllerEpoch, controllerKey: p.controllerKey),
            openRevision: p.openRevision, boot: .init(identity: p.currentGrant.identity, serviceEpoch: p.serviceEpoch,
                tlsRootSHA256: String(repeating: "1", count: 64), serverSPKI: String(repeating: "2", count: 64),
                bootstrapKey: p.bootstrapKey))
        let receipt = try L.Receipt(grant: live.receipt.grant, nonce: live.receipt.nonce,
            serviceEpoch: live.receipt.serviceEpoch, revision: p.openRevision + 1)
        let successor = try L.ServiceState(grant: receipt.grant, context: live.successor.context,
            openRevision: receipt.revision, boot: live.successor.boot)
        let request = try R.ResolveDead(resolutionID: UUID().uuidString.lowercased(), identity: f.prepare.identity,
            operationID: f.prepare.operationID, signedOpenSHA256: f.prepared.signedOpenSHA256)
        return (f, try .init(request: request, anchor: anchor, receipt: receipt, successor: successor,
            successorOrigin: f.prepared.successorOrigin, baseEpoch: f.prepared.baseEpoch))
    }
    @Test func disjointDeadResolutionRoundTripsAndCannotMasqueradeAsCompletion() throws {
        let (f, dead) = try deadHistory()
        try dead.validate(prepared: f.prepared, anchor: dead.anchor)
        let request = try R.Request(requestID: .init(UUID().uuidString.lowercased()), body: .resolveDead(dead.request))
        #expect(try R.decodeRequest(R.encode(request)) == request)
        let reply = try R.Reply(for: request, body: .resolvedDead(dead))
        #expect(try R.decodeReply(R.encode(reply), for: request) == reply)
        #expect(throws: (any Error).self) { try R.Reply(for: request, body: .completed(f.completed)) }
        let completion = try R.Request(requestID: request.requestID,
            body: .complete(operationID: dead.request.operationID, signedOpenSHA256: dead.request.signedOpenSHA256))
        #expect(throws: (any Error).self) { try R.Reply(for: completion, body: .resolvedDead(dead)) }
        let changed = try R.ResolveDead(resolutionID: UUID().uuidString.lowercased(), identity: dead.request.identity,
            operationID: dead.request.operationID, signedOpenSHA256: dead.request.signedOpenSHA256)
        let other = try R.Request(requestID: request.requestID, body: .resolveDead(changed))
        #expect(throws: (any Error).self) { try R.decodeReply(R.encode(reply), for: other) }
        let text = String(decoding: try R.encode(request), as: UTF8.self)
        for extra in ["\"exitBoolean\":true,", "\"receipt\":{},", "\"candidate\":{},"] {
            let bytes = Data(text.replacingOccurrences(of: "\"resolveDead\":{", with: "\"resolveDead\":{\(extra)").utf8)
            #expect(throws: (any Error).self) { try R.decodeRequest(bytes) }
        }
        #expect(throws: (any Error).self) {
            try R.ResolveDead(resolutionID: dead.request.operationID, identity: dead.request.identity,
                operationID: dead.request.operationID, signedOpenSHA256: dead.request.signedOpenSHA256)
        }
    }
    @Test func ordinaryEnvelopesOmitRecoveryExtensionWithoutChangingExistingCanonicalBytes() throws {
        let f = try ColdContractFixture()
        for bytes in [try L.encode(f.prepared), try L.encode(f.completed)] {
            #expect(!String(decoding: bytes, as: UTF8.self).contains("recoveryBridge"))
        }
        #expect(try L.encode(JSONDecoder().decode(R.Prepared.self, from: L.encode(f.prepared))) == L.encode(f.prepared))
        #expect(try L.encode(JSONDecoder().decode(R.Completed.self, from: L.encode(f.completed))) == L.encode(f.completed))
        let (_, dead) = try deadHistory()
        #expect(throws: (any Error).self) {
            try R.Prepared(signedOpen: f.prepared.signedOpen, successorOrigin: f.prepared.successorOrigin,
                baseEpoch: f.prepared.baseEpoch, recoveryBridge: dead)
        }
        #expect(throws: (any Error).self) {
            try R.Completed(operationID: f.completed.operationID, signedOpenSHA256: f.completed.signedOpenSHA256,
                successorOrigin: f.completed.successorOrigin, baseEpoch: f.completed.baseEpoch,
                receipt: f.completed.receipt, successor: f.completed.successor, recoveryBridge: dead)
        }
    }
    @Test func exactCoupledExchangeAndFailuresRoundTrip() throws {
        let f = try ColdContractFixture(), p = f.prepare
        try f.prepared.validate(for: p); try f.completed.validate(prepared: f.prepared)
        for eligibility in [R.Eligibility.eligible, .live, .unavailable] {
            let status = try R.Status(predecessor: p.expectedPredecessor, origin: p.expectedOrigin,
                                      allocatedEpoch: p.expectedAllocatedEpoch, eligibility: eligibility)
            let pairs: [(R.Body, R.ResultBody)] = [(.status(p.identity), .status(status)), (.prepare(p), .prepared(f.prepared)),
                (.complete(operationID: p.operationID, signedOpenSHA256: try f.prepared.signedOpenSHA256), .completed(f.completed))]
            for (body, result) in pairs {
                let request = try R.Request(requestID: .init(UUID().uuidString.lowercased()), body: body)
                #expect(try R.decodeRequest(R.encode(request)) == request)
                for result in [result, .failure(.unauthorized)] {
                    let reply = try R.Reply(for: request, body: result)
                    #expect(try R.decodeReply(R.encode(reply), for: request) == reply)
                    let other = try R.Request(requestID: .init(UUID().uuidString.lowercased()), body: body)
                    #expect(throws: (any Error).self) { try R.decodeReply(R.encode(reply), for: other) }
                    #expect(throws: (any Error).self) { try R.decodeRequest(R.encode(reply)) }
                }
            }
        }
    }
    @Test func closedWireRejectsCallerAuthorityAndNestedAlternateForms() throws {
        let f = try ColdContractFixture()
        let request = try R.Request(requestID: .init(UUID().uuidString.lowercased()), body: .prepare(f.prepare))
        let text = String(decoding: try R.encode(request), as: UTF8.self)
        var bad = [text + "\n", text.replacingOccurrences(of: R.version, with: "old.v0"),
                   text.replacingOccurrences(of: "\"operation\":\"prepare\"", with: "\"operation\":\"status\""),
                   text.replacingOccurrences(of: "9007199254740993", with: "9.007199254740993e15")]
        for field in ["prepare", "expectedOrigin", "expectedPredecessor", "mountedGreeting", "candidate", "bootBinding", "heldBackingIdentity"] {
            bad.append(text.replacingOccurrences(of: "\"\(field)\":{", with: "\"\(field)\":{\"exitBoolean\":true,"))
            bad.append(text.replacingOccurrences(of: "\"\(field)\":{", with: "\"\(field)\":null,\"\(field)\":{"))
        }
        for value in bad {
            #expect(value != text)
            #expect(throws: (any Error).self) { try R.decodeRequest(Data(value.utf8)) }
        }
    }
    @Test func prepareAndCompletionJoinsCannotDrift() throws {
        let f = try ColdContractFixture(), p = f.prepare
        let wrongEpoch = try R.Prepared(signedOpen: f.prepared.signedOpen, successorOrigin: f.prepared.successorOrigin, baseEpoch: 2)
        #expect(throws: (any Error).self) { try wrongEpoch.validate(for: p) }
        let text = String(decoding: try L.encode(p), as: UTF8.self)
        for (old, new) in [("\"expectedAllocatedEpoch\":9007199254740993", "\"expectedAllocatedEpoch\":18446744073709551615"),
                           ("\"lifetimeSeconds\":60", "\"lifetimeSeconds\":0"),
                           ("\"nowUnixSeconds\":1800000000", "\"nowUnixSeconds\":0"),
                           ("\"operationID\":\"\(p.operationID)\"", "\"operationID\":\"\(p.expectedPredecessor.currentGrant.id)\"")] {
            #expect(throws: (any Error).self) { try JSONDecoder().decode(R.Prepare.self, from: Data(text.replacingOccurrences(of: old, with: new).utf8)) }
        }
        let request = try R.Request(requestID: .init(UUID().uuidString.lowercased()), body: .complete(operationID: p.operationID, signedOpenSHA256: String(repeating: "0", count: 64)))
        #expect(throws: (any Error).self) { try R.Reply(for: request, body: .completed(f.completed)) }
        let c = f.completed
        let wrong = try R.Completed(operationID: c.operationID, signedOpenSHA256: c.signedOpenSHA256,
                                     successorOrigin: c.successorOrigin, baseEpoch: 2, receipt: c.receipt, successor: c.successor)
        #expect(throws: (any Error).self) { try wrong.validate(prepared: f.prepared) }
        let receipt = try L.Receipt(grant: c.receipt.grant, nonce: c.receipt.nonce, serviceEpoch: c.receipt.serviceEpoch, revision: 2)
        #expect(throws: (any Error).self) {
            try R.Completed(operationID: c.operationID, signedOpenSHA256: c.signedOpenSHA256,
                            successorOrigin: c.successorOrigin, baseEpoch: c.baseEpoch, receipt: receipt, successor: c.successor)
        }
    }
    @Test func signedOpenDigestIncludesBothSignatures() throws {
        let f = try ColdContractFixture(), original = f.prepared.signedOpen, r = original.request
        let inner = try L.SignedGrant(grant: r.takeover.grant, signature: f.key.signature(for: r.takeover.grant.signingBytes))
        let changedRequest = try StorageLifecycleColdProtocol.Request(operationID: r.operationID, predecessor: r.predecessor,
            takeover: inner, launch: r.launch, nowUnixSeconds: r.nowUnixSeconds, lifetimeSeconds: r.lifetimeSeconds)
        let changed = try StorageLifecycleColdProtocol.SignedOpen(request: changedRequest, signature: f.key.signature(for: changedRequest.signingBytes))
        let prepared = try R.Prepared(signedOpen: changed, successorOrigin: f.prepared.successorOrigin, baseEpoch: f.prepared.baseEpoch)
        let expected = SHA256.hash(data: Data("cengine.storage-lifecycle-cold-root.signed-open.v1\0".utf8) + (try L.encode(changed)))
            .map { String(format: "%02x", $0) }.joined()
        #expect(try prepared.signedOpenSHA256 == expected)
        // No assumption that Ed25519 signing is deterministic on this platform.
        if changed != original { #expect(try prepared.signedOpenSHA256 != f.prepared.signedOpenSHA256) }
        #expect(MemoryLayout<StorageLifecycleColdProtocol.SignedOpen>.size <= 2 * MemoryLayout<UnsafeRawPointer>.size)
    }
}

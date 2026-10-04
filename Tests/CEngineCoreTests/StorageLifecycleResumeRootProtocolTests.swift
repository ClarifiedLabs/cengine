import CEngineCore
import CryptoKit
import Foundation
import Testing

/// Fresh-resume ROOT wire fixture. Distinct launch UUIDs, keys and epochs from
/// the cold fixture; the original initialize grant has no predecessor service epoch.
struct ResumeContractFixture {
    typealias L = StorageLifecycleProtocol
    typealias R = StorageLifecycleResumeRootProtocol
    typealias Resume = StorageLifecycleResumeProtocol
    typealias S = StorageLifecycleColdShimProtocol
    let key: Curve25519.Signing.PrivateKey
    let original: L.Grant
    /// Only resume-purpose greetings can form a fresh-resume prepare.
    let prepare: R.Prepare?
    let prepared: R.Prepared
    let completed: R.Completed
    let probeGreeting: S.Greeting
    init(purpose: S.Purpose = .resumeReadOnly, launchUUID: String = "22222222-2222-4222-8222-222222222222",
         candidateSeed: UInt8 = 8) throws {
        let root = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 7, count: 32))
        key = root
        let candidateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: candidateSeed, count: 32))
        let uuid = try StorageIdentity.FilesystemUUID("11111111-1111-4111-8111-111111111111")
        let binding = StorageIdentity.StoreBinding(storeID: try .init(uuid.rawValue), root: try .init(volumeUUID: uuid, inode: 2),
            backing: try .init(identity: .init(volumeUUID: uuid, inode: 3), size: 4096), expectedExt4UUID: uuid)
        let identity = try L.Identity(binding: binding, generation: 1)
        original = try L.Grant(operation: .initialize, id: uuid.rawValue, identity: identity, serial: 1,
                               expectedEpoch: 0, newKey: String(repeating: "a", count: 64))
        let launch = try StorageLifecycleColdProtocol.Launch(shimLaunchUUID: launchUUID, specSHA256: String(repeating: "c", count: 64),
            initramfsSHA256: String(repeating: "d", count: 64), ext4UUID: uuid.rawValue, bytes: 4096)
        probeGreeting = try S.Greeting(channelID: "33333333-3333-4333-8333-333333333333", daemonUniqueID: 10,
            rootPublicKey: root.publicKey.rawRepresentation, binding: .init(binding),
            bootBinding: .init(shimLaunchUUID: launch.shimLaunchUUID, guestBootNonce: "44444444-4444-4444-8444-444444444444",
                               ext4UUID: uuid.rawValue, bytes: 4096), launch: launch,
            heldBackingIdentity: .init(.init(stableIdentity: binding.backing.identity, device: 1)), purpose: purpose)
        let candidate = try StorageIdentity.Candidate(publicKey: .init(rawPublicKey: candidateKey.publicKey.rawRepresentation), childPIDHint: 123,
                                        incarnationID: .init("55555555-5555-4555-8555-555555555555"))
        let operationID = "66666666-6666-4666-8666-666666666666"
        let now = UInt64(1_800_000_000), lifetime = UInt64(60)
        prepare = purpose == .resumeReadOnly ? try R.Prepare(operationID: operationID, identity: identity,
            expectedOriginal: original, candidate: candidate, probeGreeting: probeGreeting,
            expectedOriginalShimLaunchUUID: "88888888-8888-4888-8888-888888888888",
            nowUnixSeconds: now, lifetimeSeconds: lifetime) : nil
        let takeover = try L.Grant(operation: .takeover, id: operationID, identity: identity, serial: 2,
                                   expectedEpoch: 1, newKey: candidate.publicKey.fingerprint.rawValue)
        let signed = try L.SignedGrant(grant: takeover, signature: root.signature(for: takeover.signingBytes))
        let request = try Resume.Request(operationID: takeover.id, original: original, takeover: signed, launch: launch,
                                         nowUnixSeconds: now, lifetimeSeconds: lifetime)
        prepared = try R.Prepared(signedOpen: .init(request: request, signature: root.signature(for: request.signingBytes)),
                                  successorOrigin: probeGreeting.successorOrigin, baseEpoch: 1)
        let service = "77777777-7777-4777-8777-777777777777"
        let receipt = try L.Receipt(grant: takeover, nonce: Data(repeating: 1, count: 32), serviceEpoch: service, revision: 1)
        let successor = try L.ServiceState(grant: takeover, context: .init(serviceEpoch: service, controllerEpoch: 2, controllerKey: takeover.newKey),
            openRevision: 1, boot: .init(identity: identity, serviceEpoch: service, tlsRootSHA256: String(repeating: "e", count: 64),
                                         serverSPKI: String(repeating: "f", count: 64),
                                         bootstrapKey: StorageIdentity.RootPublicKey(publicData: root.publicKey.rawRepresentation).fingerprint.rawValue))
        completed = try R.Completed(operationID: takeover.id, signedOpenSHA256: prepared.signedOpenSHA256,
                                    successorOrigin: prepared.successorOrigin, baseEpoch: 1, receipt: receipt, successor: successor)
    }
    func takeoverGrant() throws -> L.Grant { prepared.signedOpen.request.takeover.grant }
    func resumeRequest(original: L.Grant? = nil, takeover: L.SignedGrant? = nil,
                       now: UInt64? = nil, lifetime: UInt64? = nil) throws -> Resume.Request {
        let r = prepared.signedOpen.request
        return try Resume.Request(operationID: r.operationID, original: original ?? r.original, takeover: takeover ?? r.takeover,
            launch: r.launch, nowUnixSeconds: now ?? r.nowUnixSeconds, lifetimeSeconds: lifetime ?? r.lifetimeSeconds)
    }
}

@Suite struct StorageLifecycleResumeRootProtocolTests {
    private typealias R = StorageLifecycleResumeRootProtocol
    private typealias L = StorageLifecycleProtocol
    private typealias S = StorageLifecycleColdShimProtocol

    @Test func exactCoupledExchangeAndFailuresRoundTrip() throws {
        let f = try ResumeContractFixture(), p = f.prepare!
        try f.prepared.validate(for: p); try f.completed.validate(prepared: f.prepared)
        for eligibility in [R.Eligibility.eligible, .unavailable] {
            let status = try R.Status(original: f.original, binding: p.probeGreeting.binding, rootPublicKey: p.probeGreeting.rootPublicKey,
                                      originalShimLaunchUUID: p.expectedOriginalShimLaunchUUID, eligibility: eligibility)
            let pairs: [(R.Body, R.ResultBody)] = [(.lookup(p.probeGreeting.binding), .status(status)),
                (.status(p.identity), .status(status)), (.prepare(p), .prepared(f.prepared)),
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
    @Test func lookupIsClosedAndCorrelatesTheEntireBindingWithoutCallerGeneration() throws {
        let f = try ResumeContractFixture(), p = f.prepare!
        let request = try R.Request(requestID: .init(UUID().uuidString.lowercased()), body: .lookup(p.probeGreeting.binding))
        let bytes = try R.encode(request)
        let object = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        #expect(Set(object.keys) == ["version", "requestID", "operation", "binding"])
        let status = try R.Status(original: f.original, binding: p.probeGreeting.binding,
            rootPublicKey: p.probeGreeting.rootPublicKey, originalShimLaunchUUID: p.expectedOriginalShimLaunchUUID, eligibility: .eligible)
        let reply = try R.Reply(for: request, body: .status(status))
        let full = try p.probeGreeting.binding.value()
        let copiedBinding = StorageLifecycleStoreBinding(try StorageIdentity.StoreBinding(storeID: full.storeID, root: full.root,
            backing: .init(identity: .init(volumeUUID: full.backing.identity.volumeUUID, inode: full.backing.identity.inode + 1), size: full.backing.size), expectedExt4UUID: full.expectedExt4UUID))
        let other = try R.Request(requestID: request.requestID, body: .lookup(copiedBinding))
        #expect(throws: (any Error).self) { try R.Reply(for: other, body: .status(status)) }
        #expect(throws: (any Error).self) { try R.decodeReply(R.encode(reply), for: other) }
        #expect(throws: (any Error).self) { try R.Reply(for: request, body: .prepared(f.prepared)) }
        let identityRequest = try R.Request(requestID: request.requestID, body: .status(f.original.identity))
        #expect(throws: (any Error).self) { try R.decodeReply(R.encode(reply), for: identityRequest) }
        for mutation in 0..<5 {
            var bad = object
            switch mutation {
            case 0: bad.removeValue(forKey: "binding")
            case 1: bad["binding"] = NSNull()
            case 2: bad["identity"] = try JSONSerialization.jsonObject(with: L.encode(f.original.identity))
            case 3: bad["generation"] = 1
            default: bad["operation"] = "status"
            }
            let malformed = try JSONSerialization.data(withJSONObject: bad, options: [.sortedKeys, .withoutEscapingSlashes])
            #expect(throws: (any Error).self) { try R.decodeRequest(malformed) }
        }
        let text = String(decoding: bytes, as: UTF8.self)
        #expect(throws: (any Error).self) {
            try R.decodeRequest(Data(text.replacingOccurrences(of: "\"binding\":{", with: "\"binding\":null,\"binding\":{").utf8))
        }
    }
    @Test func statusRequiresDerivedBindingAndDistinctRootKey() throws {
        let f = try ResumeContractFixture()
        for eligibility in [R.Eligibility.eligible, .unavailable] {
            _ = try R.Status(original: f.original, binding: f.probeGreeting.binding, rootPublicKey: f.probeGreeting.rootPublicKey,
                             originalShimLaunchUUID: f.prepare!.expectedOriginalShimLaunchUUID, eligibility: eligibility)
        }
        let root = try StorageIdentity.RootPublicKey(publicData: f.probeGreeting.rootPublicKey)
        // The ROOT signing key may not alias the original initialize key.
        let aliased = try L.Grant(operation: .initialize, id: f.original.id, identity: f.original.identity, serial: f.original.serial,
                                  expectedEpoch: 0, newKey: root.fingerprint.rawValue)
        #expect(throws: (any Error).self) {
            try R.Status(original: aliased, binding: f.probeGreeting.binding, rootPublicKey: f.probeGreeting.rootPublicKey,
                         originalShimLaunchUUID: f.prepare!.expectedOriginalShimLaunchUUID, eligibility: .eligible)
        }
        // A takeover grant is not an original; a mismatched derived binding fails too.
        let takeover = try f.takeoverGrant()
        #expect(throws: (any Error).self) {
            try R.Status(original: takeover, binding: f.probeGreeting.binding, rootPublicKey: f.probeGreeting.rootPublicKey,
                         originalShimLaunchUUID: f.prepare!.expectedOriginalShimLaunchUUID, eligibility: .eligible)
        }
        // A binding that derives a different identity digest fails the join.
        let vol = try StorageIdentity.FilesystemUUID(f.probeGreeting.binding.ext4UUID)
        let storeID = try StorageIdentity.StoreID(f.probeGreeting.binding.store)
        let otherBinding = StorageLifecycleStoreBinding(try StorageIdentity.StoreBinding(storeID: storeID,
            root: .init(volumeUUID: vol, inode: 2),
            backing: .init(identity: .init(volumeUUID: vol, inode: 4), size: 4096), expectedExt4UUID: vol))
        #expect(throws: (any Error).self) {
            try R.Status(original: f.original, binding: otherBinding, rootPublicKey: f.probeGreeting.rootPublicKey,
                         originalShimLaunchUUID: f.prepare!.expectedOriginalShimLaunchUUID, eligibility: .eligible)
        }
    }
    @Test func prepareRejectsCrossPurposeReusedLaunchAndMixedOriginal() throws {
        let f = try ResumeContractFixture()
        // A cold-purpose greeting can never drive a fresh-resume prepare.
        let cold = try ResumeContractFixture(purpose: .cold)
        #expect(cold.probeGreeting.purpose == .cold)
        #expect(throws: (any Error).self) {
            try R.Prepare(operationID: f.prepare!.operationID, identity: f.prepare!.identity, expectedOriginal: f.original,
                candidate: f.prepare!.candidate, probeGreeting: cold.probeGreeting,
                expectedOriginalShimLaunchUUID: f.prepare!.expectedOriginalShimLaunchUUID,
                nowUnixSeconds: f.prepare!.nowUnixSeconds, lifetimeSeconds: f.prepare!.lifetimeSeconds)
        }
        // Reusing the original shim launch UUID is not a fresh launch.
        #expect(throws: (any Error).self) {
            try R.Prepare(operationID: f.prepare!.operationID, identity: f.prepare!.identity, expectedOriginal: f.original,
                candidate: f.prepare!.candidate, probeGreeting: f.probeGreeting,
                expectedOriginalShimLaunchUUID: f.probeGreeting.launch.shimLaunchUUID,
                nowUnixSeconds: f.prepare!.nowUnixSeconds, lifetimeSeconds: f.prepare!.lifetimeSeconds)
        }
        // Mixed original: takeover grant or drifted identity is rejected.
        let takeover = try f.takeoverGrant()
        #expect(throws: (any Error).self) {
            try R.Prepare(operationID: f.prepare!.operationID, identity: f.prepare!.identity, expectedOriginal: takeover,
                candidate: f.prepare!.candidate, probeGreeting: f.probeGreeting,
                expectedOriginalShimLaunchUUID: f.prepare!.expectedOriginalShimLaunchUUID,
                nowUnixSeconds: f.prepare!.nowUnixSeconds, lifetimeSeconds: f.prepare!.lifetimeSeconds)
        }
        let other = try L.Identity(store: f.original.identity.store, generation: 2, binding: f.original.identity.binding)
        #expect(throws: (any Error).self) {
            try R.Prepare(operationID: f.prepare!.operationID, identity: other, expectedOriginal: f.original,
                candidate: f.prepare!.candidate, probeGreeting: f.probeGreeting,
                expectedOriginalShimLaunchUUID: f.prepare!.expectedOriginalShimLaunchUUID,
                nowUnixSeconds: f.prepare!.nowUnixSeconds, lifetimeSeconds: f.prepare!.lifetimeSeconds)
        }
        // Candidate may not alias the original key or the ROOT key.
        let candidateFP = f.prepare!.candidate.publicKey.fingerprint.rawValue
        let originalAlias = try L.Grant(operation: .initialize, id: f.original.id, identity: f.original.identity,
                                        serial: 1, expectedEpoch: 0, newKey: candidateFP)
        #expect(throws: (any Error).self) {
            try R.Prepare(operationID: f.prepare!.operationID, identity: f.prepare!.identity, expectedOriginal: originalAlias,
                candidate: f.prepare!.candidate, probeGreeting: f.probeGreeting,
                expectedOriginalShimLaunchUUID: f.prepare!.expectedOriginalShimLaunchUUID,
                nowUnixSeconds: f.prepare!.nowUnixSeconds, lifetimeSeconds: f.prepare!.lifetimeSeconds)
        }
        let rootAlias = try StorageIdentity.Candidate(publicKey: .init(rawPublicKey: f.probeGreeting.rootPublicKey),
            childPIDHint: 123, incarnationID: .init("55555555-5555-4555-8555-555555555555"))
        #expect(throws: (any Error).self) {
            try R.Prepare(operationID: f.prepare!.operationID, identity: f.prepare!.identity, expectedOriginal: f.original,
                candidate: rootAlias, probeGreeting: f.probeGreeting,
                expectedOriginalShimLaunchUUID: f.prepare!.expectedOriginalShimLaunchUUID,
                nowUnixSeconds: f.prepare!.nowUnixSeconds, lifetimeSeconds: f.prepare!.lifetimeSeconds)
        }
        for (now, lifetime): (UInt64, UInt64) in [(0, 1), (1, 0), (1, 86_401)] {
            #expect(throws: (any Error).self) {
                try R.Prepare(operationID: f.prepare!.operationID, identity: f.prepare!.identity, expectedOriginal: f.original,
                    candidate: f.prepare!.candidate, probeGreeting: f.probeGreeting,
                    expectedOriginalShimLaunchUUID: f.prepare!.expectedOriginalShimLaunchUUID,
                    nowUnixSeconds: now, lifetimeSeconds: lifetime)
            }
        }
    }
    @Test func preparedValidatesExactPrepareAgreementAndSignatures() throws {
        let f = try ResumeContractFixture(), p = f.prepare!, root = try StorageIdentity.RootPublicKey(publicData: f.probeGreeting.rootPublicKey)
        let attacker = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 42, count: 32))
        // Outer signature not from the ROOT key fails even with a valid inner grant.
        let badOuter = try StorageLifecycleResumeProtocol.SignedOpen(request: f.prepared.signedOpen.request,
                                                                     signature: attacker.signature(for: f.prepared.signedOpen.request.signingBytes))
        #expect(throws: (any Error).self) { try R.Prepared(signedOpen: badOuter, successorOrigin: f.prepared.successorOrigin, baseEpoch: 1) }
        // ROOT key aliased into the takeover grant fails the signature identity guard.
        let g = try f.takeoverGrant()
        let alias = try L.Grant(operation: .takeover, id: g.id, identity: g.identity, serial: g.serial,
                                expectedEpoch: g.expectedEpoch, newKey: root.fingerprint.rawValue)
        let aliasRequest = try f.resumeRequest(takeover: L.SignedGrant(grant: alias, signature: f.key.signature(for: alias.signingBytes)))
        let aliasOpen = try StorageLifecycleResumeProtocol.SignedOpen(request: aliasRequest, signature: f.key.signature(for: aliasRequest.signingBytes))
        #expect(!aliasOpen.isValidSignature(using: root))
        #expect(throws: (any Error).self) { try R.Prepared(signedOpen: aliasOpen, successorOrigin: f.prepared.successorOrigin, baseEpoch: 1) }
        // Any drift from the exact prepare agreement fails the join.
        #expect(throws: (any Error).self) { try R.Prepared(signedOpen: f.prepared.signedOpen, successorOrigin: f.prepared.successorOrigin, baseEpoch: 2).validate(for: p) }
        let wrongNow = try f.resumeRequest(now: p.nowUnixSeconds + 1)
        let wrongNowOpen = try StorageLifecycleResumeProtocol.SignedOpen(request: wrongNow, signature: f.key.signature(for: wrongNow.signingBytes))
        #expect(throws: (any Error).self) { try R.Prepared(signedOpen: wrongNowOpen, successorOrigin: f.prepared.successorOrigin, baseEpoch: 1).validate(for: p) }
        let digest = SHA256.hash(data: Data("cengine.storage-lifecycle-resume-root.signed-open.v1\0".utf8) + (try L.encode(f.prepared.signedOpen)))
            .map { String(format: "%02x", $0) }.joined()
        #expect(try f.prepared.signedOpenSHA256 == digest)
        #expect(MemoryLayout<StorageLifecycleResumeProtocol.SignedOpen>.size <= 2 * MemoryLayout<UnsafeRawPointer>.size)
    }
    @Test func completedGenesisOnlyExactAgreement() throws {
        let f = try ResumeContractFixture(), c = f.completed
        try c.validate(prepared: f.prepared)
        // No fabricated predecessor epoch: base epoch is pinned to genesis 1.
        #expect(throws: (any Error).self) {
            try R.Completed(operationID: c.operationID, signedOpenSHA256: c.signedOpenSHA256, successorOrigin: c.successorOrigin,
                            baseEpoch: 2, receipt: c.receipt, successor: c.successor)
        }
        // Open revision is genesis-only (1 or 2): drifted revision 3 fails.
        let driftedSuccessor = try L.ServiceState(grant: c.successor.grant, context: c.successor.context,
            openRevision: 3, boot: c.successor.boot)
        let driftedReceipt = try L.Receipt(grant: c.receipt.grant, nonce: c.receipt.nonce,
                                           serviceEpoch: c.receipt.serviceEpoch, revision: 3)
        #expect(throws: (any Error).self) {
            try R.Completed(operationID: c.operationID, signedOpenSHA256: c.signedOpenSHA256, successorOrigin: c.successorOrigin,
                            baseEpoch: 1, receipt: driftedReceipt, successor: driftedSuccessor)
        }
        // Receipt/service/open revision must agree exactly.
        let wrongReceipt = try L.Receipt(grant: c.receipt.grant, nonce: c.receipt.nonce,
                                         serviceEpoch: c.receipt.serviceEpoch, revision: 2)
        #expect(throws: (any Error).self) {
            try R.Completed(operationID: c.operationID, signedOpenSHA256: c.signedOpenSHA256, successorOrigin: c.successorOrigin,
                            baseEpoch: 1, receipt: wrongReceipt, successor: c.successor)
        }
        let wrongDigest = String(repeating: "0", count: 64)
        let mismatched = try R.Completed(operationID: c.operationID, signedOpenSHA256: wrongDigest,
                                         successorOrigin: c.successorOrigin, baseEpoch: 1, receipt: c.receipt, successor: c.successor)
        #expect(throws: (any Error).self) { try mismatched.validate(prepared: f.prepared) }
    }
    @Test func prepareValidateForStatusCorrelatesProtectedWitness() throws {
        let f = try ResumeContractFixture(), p = f.prepare!
        func status(original: L.Grant? = nil, binding: StorageLifecycleStoreBinding? = nil,
                    rootPublicKey: Data? = nil, originalShimLaunchUUID: String? = nil,
                    eligibility: R.Eligibility = .eligible) throws -> R.Status {
            try R.Status(original: original ?? f.original, binding: binding ?? f.probeGreeting.binding,
                         rootPublicKey: rootPublicKey ?? p.probeGreeting.rootPublicKey,
                         originalShimLaunchUUID: originalShimLaunchUUID ?? p.expectedOriginalShimLaunchUUID,
                         eligibility: eligibility)
        }
        // Exact agreement with the ROOT-witnessed eligible status passes.
        try p.validate(for: status())
        // Unavailable witness evidence never authorizes a prepare.
        #expect(throws: (any Error).self) { try p.validate(for: status(eligibility: .unavailable)) }
        // A different ROOT key, original launch, original grant, or binding fails the join.
        let otherRoot = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 9, count: 32))
        #expect(throws: (any Error).self) { try p.validate(for: status(rootPublicKey: otherRoot.publicKey.rawRepresentation)) }
        #expect(throws: (any Error).self) {
            try p.validate(for: status(originalShimLaunchUUID: "99999999-9999-4999-8999-999999999999"))
        }
        let otherOriginal = try L.Grant(operation: .initialize, id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                                        identity: f.original.identity, serial: 1, expectedEpoch: 0,
                                        newKey: String(repeating: "b", count: 64))
        #expect(throws: (any Error).self) { try p.validate(for: status(original: otherOriginal)) }
        let vol = try StorageIdentity.FilesystemUUID(f.probeGreeting.binding.ext4UUID)
        let storeID = try StorageIdentity.StoreID(f.probeGreeting.binding.store)
        let otherBinding = StorageLifecycleStoreBinding(try StorageIdentity.StoreBinding(storeID: storeID,
            root: .init(volumeUUID: vol, inode: 2),
            backing: .init(identity: .init(volumeUUID: vol, inode: 4), size: 4096), expectedExt4UUID: vol))
        #expect(throws: (any Error).self) { try p.validate(for: status(binding: otherBinding)) }
    }
    @Test func closedWireRejectsMissingPurposeAndAlternateForms() throws {
        let f = try ResumeContractFixture()
        let request = try R.Request(requestID: .init(UUID().uuidString.lowercased()), body: .prepare(f.prepare!))
        let text = String(decoding: try R.encode(request), as: UTF8.self)
        var bad = [text + "\n", text.replacingOccurrences(of: R.version, with: "old.v0"),
                   text.replacingOccurrences(of: "\"operation\":\"prepare\"", with: "\"operation\":\"status\""),
                   text.replacingOccurrences(of: "1800000000", with: "1.8e9")]
        // A missing purpose on the closed shim wire is never invented at decode.
        bad.append(text.replacingOccurrences(of: "\"purpose\":\"resumeReadOnly\",", with: ""))
        for field in ["prepare", "expectedOriginal", "probeGreeting", "candidate", "bootBinding", "heldBackingIdentity"] {
            bad.append(text.replacingOccurrences(of: "\"\(field)\":{", with: "\"\(field)\":{\"exitBoolean\":true,"))
            bad.append(text.replacingOccurrences(of: "\"\(field)\":{", with: "\"\(field)\":null,\"\(field)\":{"))
        }
        for value in bad {
            #expect(value != text)
            #expect(throws: (any Error).self) { try R.decodeRequest(Data(value.utf8)) }
        }
        // ColdShim-side decode also rejects a greeting/seed stripped of purpose.
        let greetingText = String(decoding: try S.encode(f.probeGreeting), as: UTF8.self)
        let noPurpose = greetingText.replacingOccurrences(of: "\"purpose\":\"resumeReadOnly\",", with: "")
        #expect(noPurpose != greetingText)
        #expect(throws: (any Error).self) { try S.decodeGreeting(Data(noPurpose.utf8)) }
        let seed = try S.ColdEnrollmentSeed(operationID: f.prepare!.operationID, signedOpenSHA256: f.prepared.signedOpenSHA256,
                                            successorOrigin: f.prepared.successorOrigin, baseEpoch: 1, purpose: .resumeReadOnly)
        let seedText = String(decoding: try S.encode(seed), as: UTF8.self)
        #expect(throws: (any Error).self) {
            try S.decodeEnrollmentSeed(Data(seedText.replacingOccurrences(of: "\"purpose\":\"resumeReadOnly\",", with: "").utf8))
        }
    }
    @Test func resumeChallengeAndSeedJoinsRejectDrift() throws {
        let f = try ResumeContractFixture(), p = f.prepare!
        func challenge(prepareSHA256: String? = nil, unsignedGrant: L.Grant? = nil,
                       signedOpenSHA256: String? = nil, baseEpoch: UInt64 = 1) throws -> S.Challenge {
            try S.Challenge(greeting: p.probeGreeting, prepareSHA256: prepareSHA256 ?? p.digest,
                unsignedGrant: unsignedGrant ?? f.takeoverGrant(), signedOpenSHA256: signedOpenSHA256 ?? f.prepared.signedOpenSHA256,
                baseEpoch: baseEpoch, shimAudit: Data(repeating: 1, count: 32), shimUniqueID: 20,
                daemonAudit: Data(repeating: 2, count: 32), daemonUniqueID: 10, counter: 1,
                nonce: Data(repeating: 3, count: 32), expiresUnixMS: 40_000)
        }
        try challenge().validate(prepare: p, prepared: f.prepared)
        // Cross-purpose: a resume-purpose greeting can never satisfy the cold ROOT
        // join, even with the exact cold prepare digest and authorization.
        let coldF = try ColdContractFixture()
        let mounted = coldF.prepare.mountedGreeting
        let resumeGreeting = try S.Greeting(channelID: mounted.channelID, daemonUniqueID: mounted.daemonUniqueID,
            rootPublicKey: mounted.rootPublicKey, binding: mounted.binding, bootBinding: mounted.bootBinding,
            launch: mounted.launch, heldBackingIdentity: mounted.heldBackingIdentity, purpose: .resumeReadOnly)
        let coldChallenge = try S.Challenge(greeting: resumeGreeting, prepareSHA256: coldF.prepare.digest,
            unsignedGrant: coldF.prepared.signedOpen.request.takeover.grant, signedOpenSHA256: coldF.prepared.signedOpenSHA256,
            baseEpoch: 1, shimAudit: Data(repeating: 1, count: 32), shimUniqueID: 20,
            daemonAudit: Data(repeating: 2, count: 32), daemonUniqueID: mounted.daemonUniqueID, counter: 1,
            nonce: Data(repeating: 3, count: 32), expiresUnixMS: 40_000)
        #expect(resumeGreeting.purpose == .resumeReadOnly)
        #expect(throws: (any Error).self) { try coldChallenge.validate(prepare: coldF.prepare, prepared: coldF.prepared) }
        // Base epoch split: resume requires exactly genesis 1.
        #expect(throws: (any Error).self) { try challenge(baseEpoch: 2) }
        for changed in [try challenge(prepareSHA256: String(repeating: "0", count: 64)),
                        try challenge(signedOpenSHA256: String(repeating: "0", count: 64))] {
            #expect(throws: (any Error).self) { try changed.validate(prepare: p, prepared: f.prepared) }
        }
        let otherGrant = try L.Grant(operation: .takeover, id: p.operationID, identity: p.identity, serial: 3,
                                     expectedEpoch: 1, newKey: f.takeoverGrant().newKey)
        #expect(throws: (any Error).self) { try challenge(unsignedGrant: otherGrant).validate(prepare: p, prepared: f.prepared) }
        // Resume seed join and the cold-purpose split.
        let seed = try S.ColdEnrollmentSeed(operationID: p.operationID, signedOpenSHA256: f.prepared.signedOpenSHA256,
                                            successorOrigin: f.prepared.successorOrigin, baseEpoch: 1, purpose: .resumeReadOnly)
        try seed.validate(prepared: f.prepared)
        // A differently-launched cold-shaped prepared value cannot join the resume seed.
        let cold = try ResumeContractFixture(purpose: .cold, launchUUID: "99999999-9999-4999-8999-999999999999")
        #expect(throws: (any Error).self) { try seed.validate(prepared: cold.prepared) }
        // The cold seed requires a strictly-greater-than-genesis base epoch; the
        // value cannot even be constructed at genesis 1 with a cold purpose.
        #expect(throws: (any Error).self) {
            try S.ColdEnrollmentSeed(operationID: p.operationID, signedOpenSHA256: f.prepared.signedOpenSHA256,
                                     successorOrigin: f.prepared.successorOrigin, baseEpoch: 1, purpose: .cold)
        }
        #expect(throws: (any Error).self) {
            try S.ColdEnrollmentSeed(operationID: p.operationID, signedOpenSHA256: f.prepared.signedOpenSHA256,
                                     successorOrigin: f.prepared.successorOrigin, baseEpoch: 2, purpose: .resumeReadOnly)
        }
    }
}

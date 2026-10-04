import CEngineCore
import CryptoKit
import Foundation
import Testing

@Suite struct StorageLifecycleAdoptionProtocolTests {
    private typealias Wire = StorageLifecycleAdoptionProtocol
    private func request() throws -> Wire.Request {
        let uuid = try StorageIdentity.FilesystemUUID("11111111-1111-4111-8111-111111111111")
        let binding = try StorageIdentity.StoreBinding(storeID: .init(uuid.rawValue),
            root: .init(volumeUUID: uuid, inode: 2),
            backing: .init(identity: .init(volumeUUID: uuid, inode: 3), size: 4096), expectedExt4UUID: uuid)
        return try .init(id: uuid.rawValue,
            origin: .init(binding: .init(binding), rootPublicKey: Data(repeating: 7, count: 32),
                shimLaunchUUID: uuid.rawValue, specSHA256: String(repeating: "a", count: 64)), expectedEpoch: 1,
            daemonAudit: Data(repeating: 1, count: 32), daemonUniqueID: 1,
            controllerAudit: Data(repeating: 2, count: 32), controllerUniqueID: 2)
    }
    @Test func closedCanonicalRequestRejectsUnknownNestedKeysAndAlternateNumbers() throws {
        let value = try request(), bytes = try Wire.encode(value)
        #expect(try Wire.decodeRequest(bytes) == value)
        let text = String(decoding: bytes, as: UTF8.self)
        for invalid in [text.replacingOccurrences(of: "\"origin\":{", with: "\"origin\":{\"verified\":true,"),
                        text.replacingOccurrences(of: "\"expectedEpoch\":1", with: "\"expectedEpoch\":1.0"),
                        text + "\n"] {
            #expect(throws: (any Error).self) { try Wire.decodeRequest(Data(invalid.utf8)) }
        }
    }
    @Test func challengeDigestBindsNonceAndCompleteRequest() throws {
        let value = try request()
        let first = try Wire.Challenge(request: value, nonce: Data(repeating: 1, count: 32))
        let second = try Wire.Challenge(request: value, nonce: Data(repeating: 2, count: 32))
        #expect(try first.digest != second.digest)
        #expect(try Wire.decodeChallenge(Wire.encode(first)) == first)
        #expect(try Wire.decodeReply(Wire.encode(Wire.Reply(challengeSHA256: first.digest))).challengeSHA256 == first.digest)
        #expect(throws: (any Error).self) { try Wire.Challenge(request: value, nonce: Data()) }
    }
    @Test func supersessionIsRequiredNullOrClosedExactFenceAndBindsChallenge() throws {
        let original = try request()
        let text = String(decoding: try Wire.encode(original), as: UTF8.self)
        #expect(text.contains("\"superseded\":null"))
        #expect(throws: (any Error).self) {
            try Wire.decodeRequest(Data(text.replacingOccurrences(of: "\"superseded\":null,", with: "").utf8))
        }
        let replacement = try Wire.Request(id: UUID().uuidString.lowercased(), origin: original.origin,
            expectedEpoch: 2, daemonAudit: Data(repeating: 3, count: 32), daemonUniqueID: 3,
            controllerAudit: Data(repeating: 4, count: 32), controllerUniqueID: 4, superseded: original.fenceIdentity)
        #expect(try Wire.decodeRequest(Wire.encode(replacement)) == replacement)
        let without = try Wire.Request(id: replacement.id, origin: replacement.origin, expectedEpoch: 2,
            daemonAudit: replacement.daemonAudit, daemonUniqueID: 3,
            controllerAudit: replacement.controllerAudit, controllerUniqueID: 4)
        let nonce = Data(repeating: 8, count: 32)
        #expect(try Wire.Challenge(request: replacement, nonce: nonce).digest != Wire.Challenge(request: without, nonce: nonce).digest)
        let encoded = String(decoding: try Wire.encode(replacement), as: UTF8.self)
        for invalid in [encoded.replacingOccurrences(of: "\"superseded\":{", with: "\"superseded\":{\"extra\":1,"),
                        encoded.replacingOccurrences(of: "\"epoch\":2", with: "\"epoch\":3"),
                        encoded.replacingOccurrences(of: "\"epoch\":2", with: "\"epoch\":1")] {
            #expect(throws: (any Error).self) { try Wire.decodeRequest(Data(invalid.utf8)) }
        }
    }
    @Test func adoptedServiceProofBindsGrantNonceAndProtectedService() throws {
        typealias L = StorageLifecycleProtocol
        let adoption = try request()
        let identity = try L.Identity(binding: adoption.origin.binding.value(), generation: 1)
        let grant = try L.Grant(operation: .initialize, id: UUID().uuidString.lowercased(), identity: identity,
            serial: 1, expectedEpoch: 0, newKey: String(repeating: "a", count: 64))
        let boot = try StorageLifecycleBootTrust(identity: identity, serviceEpoch: UUID().uuidString.lowercased(),
            tlsRootSHA256: String(repeating: "b", count: 64), serverSPKI: String(repeating: "c", count: 64),
            bootstrapKey: StorageIdentity.RootPublicKey(publicData: adoption.origin.rootPublicKey).fingerprint.rawValue)
        let result = try L.ServiceResult(identity: identity, grant: grant, nonce: Data(repeating: 8, count: 32),
            serviceEpoch: boot.serviceEpoch, controllerEpoch: 1, controllerKey: grant.newKey, openRevision: 1)
        let state = try result.state(boot: boot)
        let challenge = try Wire.ServiceChallenge(adoption: adoption, grant: grant, expected: state,
            counter: 1, nonce: result.nonce, expiresUnixMS: 31_000)
        #expect(challenge.isFresh(at: 1_000))
        #expect(!challenge.isFresh(at: 999))
        #expect(!challenge.isFresh(at: 31_000))
        #expect(try Wire.decodeServiceChallenge(Wire.encode(challenge)) == challenge)
        let reply = try Wire.ServiceReply(challenge: challenge, result: result, boot: boot)
        #expect(try Wire.decodeServiceReply(Wire.encode(reply), challenge: challenge) == reply)
        let takeover = try L.Grant(operation: .takeover, id: UUID().uuidString.lowercased(), identity: identity,
            serial: 2, expectedEpoch: 1, newKey: String(repeating: "d", count: 64))
        #expect(throws: (any Error).self) {
            try Wire.ServiceChallenge(adoption: adoption, grant: takeover, expected: state,
                counter: 1, nonce: result.nonce, expiresUnixMS: 31_000)
        }
        // Reject the formerly accepted mixed grant even on the closed decoder path.
        let mixed = try Wire.encode(challenge)
        let grantText = String(decoding: try L.encode(grant), as: UTF8.self)
        let takeoverText = String(decoding: try L.encode(takeover), as: UTF8.self)
        let mixedText = String(decoding: mixed, as: UTF8.self)
            .replacingOccurrences(of: "\"grant\":\(grantText),\"nonce\"", with: "\"grant\":\(takeoverText),\"nonce\"")
        #expect(mixedText != String(decoding: mixed, as: UTF8.self))
        #expect(throws: (any Error).self) { try Wire.decodeServiceChallenge(Data(mixedText.utf8)) }
        let advanced = try L.ServiceResult(identity: identity, grant: takeover, nonce: result.nonce,
            serviceEpoch: boot.serviceEpoch, controllerEpoch: 2, controllerKey: takeover.newKey, openRevision: 1)
        let after = try Wire.ServiceChallenge(adoption: adoption, grant: takeover, expected: advanced.state(boot: boot),
            counter: 2, nonce: result.nonce, expiresUnixMS: 31_000)
        #expect(try Wire.decodeServiceReply(Wire.encode(Wire.ServiceReply(challenge: after, result: advanced, boot: boot)), challenge: after).result == advanced)
        #expect(throws: (any Error).self) { try Wire.ServiceReply(challenge: after, result: result, boot: boot) }
        #expect(throws: (any Error).self) { try Wire.ServiceReply(challenge: challenge, result: advanced, boot: boot) }
        let wrongBoot = try StorageLifecycleBootTrust(identity: identity, serviceEpoch: UUID().uuidString.lowercased(),
            tlsRootSHA256: boot.tlsRootSHA256, serverSPKI: boot.serverSPKI, bootstrapKey: boot.bootstrapKey)
        let wrongE = try L.ServiceResult(identity: identity, grant: takeover, nonce: result.nonce,
            serviceEpoch: wrongBoot.serviceEpoch, controllerEpoch: 2, controllerKey: takeover.newKey, openRevision: 1)
        #expect(throws: (any Error).self) { try Wire.ServiceReply(challenge: after, result: wrongE, boot: wrongBoot) }
        let replay = try Wire.ServiceChallenge(adoption: adoption, grant: grant, expected: state,
            counter: 2, nonce: Data(repeating: 9, count: 32), expiresUnixMS: 31_000)
        #expect(throws: (any Error).self) { try Wire.decodeServiceReply(Wire.encode(reply), challenge: replay) }
        let text = String(decoding: try Wire.encode(challenge), as: UTF8.self)
        #expect(throws: (any Error).self) { try Wire.decodeServiceChallenge(Data((text + "\n").utf8)) }
        typealias R = StorageLifecycleAdoptionRootProtocol
        let request = try R.Request(requestID: .init(UUID().uuidString.lowercased()), body: .service(adoption, grant))
        #expect(try R.decodeRequest(R.encode(request)) == request)
        let rootReply = try R.Reply(for: request, body: .service(state))
        #expect(try R.decodeReply(R.encode(rootReply), for: request) == rootReply)
    }
    @Test func adoptedServiceChangeProofBindsDiscoveryTargetAndCompletedState() throws {
        let f = try AdoptionServiceChangeFixture(adoption: request())
        for challenge in [try f.challenge(), try f.challenge(target: f.boot),
                          try f.challenge(target: f.boot, completed: f.confirmation)] {
            #expect(challenge.isFresh(at: 1_000))
            #expect(!challenge.isFresh(at: 999))
            #expect(!challenge.isFresh(at: 31_000))
            #expect(!challenge.isFresh(at: UInt64.max))
            #expect(try Wire.decodeServiceChangeChallenge(Wire.encode(challenge)) == challenge)
            #expect(try challenge.digest == Data(SHA256.hash(data:
                Data("cengine.storage-adopted-service-change.v1\0".utf8) + Wire.encode(challenge))))
            let reply = try Wire.ServiceChangeReply(challenge: challenge, result: f.result(), boot: f.boot)
            #expect(try Wire.decodeServiceChangeReply(Wire.encode(reply), challenge: challenge) == reply)
            for result in [try f.result(nonce: Data(repeating: 9, count: 32)), try f.result(revision: 1)] {
                #expect(throws: (any Error).self) { try Wire.ServiceChangeReply(challenge: challenge, result: result, boot: f.boot) }
            }
            let replay = try f.challenge(target: challenge.targetBoot, completed: challenge.completed, counter: 2)
            #expect(throws: (any Error).self) { try Wire.decodeServiceChangeReply(Wire.encode(reply), challenge: replay) }
            let bytes = try Wire.encode(reply)
            let bad = String(decoding: bytes, as: UTF8.self).replacingOccurrences(of: "\"boot\":{", with: "\"boot\":{\"extra\":0,")
            #expect(throws: (any Error).self) { try Wire.decodeServiceChangeReply(Data(bad.utf8), challenge: challenge) }
        }
        let discovery = try f.challenge(), pinned = try f.challenge(target: f.boot)
        let completed = try f.challenge(target: f.boot, completed: f.confirmation)
        #expect(try discovery.digest != pinned.digest)
        #expect(try pinned.digest != completed.digest)
        // A pinned but uncommitted proof can advance; a completed retry must be exact.
        _ = try Wire.ServiceChangeReply(challenge: pinned, result: f.result(revision: 3), boot: f.boot)
        #expect(throws: (any Error).self) {
            try Wire.ServiceChangeReply(challenge: completed, result: f.result(revision: 3), boot: f.boot)
        }
        let otherBoot = try StorageLifecycleBootTrust(identity: f.boot.identity, serviceEpoch: f.boot.serviceEpoch,
            tlsRootSHA256: String(repeating: "e", count: 64), serverSPKI: f.boot.serverSPKI, bootstrapKey: f.boot.bootstrapKey)
        _ = try Wire.ServiceChangeReply(challenge: discovery, result: f.result(), boot: otherBoot)
        #expect(throws: (any Error).self) { try Wire.ServiceChangeReply(challenge: pinned, result: f.result(), boot: otherBoot) }
        #expect(throws: (any Error).self) { try f.challenge(completed: f.confirmation) }
        #expect(throws: (any Error).self) { try f.challenge(target: otherBoot, completed: f.confirmation) }
        #expect(throws: (any Error).self) { try f.challenge(target: f.change.predecessor.boot) }
        let otherChange = try StorageLifecycleProtocol.ServiceChangeRequest(operationID: UUID().uuidString.lowercased(), predecessor: f.change.predecessor)
        let otherConfirmation = try StorageLifecycleProtocol.ServiceChangeConfirmation(request: otherChange, successor: f.confirmation.successor)
        #expect(throws: (any Error).self) { try f.challenge(target: f.boot, completed: otherConfirmation) }
    }
    @Test func adoptedServiceChangeChallengeRejectsUnboundAndNoncanonicalValues() throws {
        let f = try AdoptionServiceChangeFixture(adoption: request())
        let challenge = try f.challenge(), text = String(decoding: try Wire.encode(challenge), as: UTF8.self)
        #expect(text.contains("\"targetBoot\":null"))
        #expect(text.contains("\"completed\":null"))
        for bad in [text.replacingOccurrences(of: ",\"targetBoot\":null", with: ""),
                    text.replacingOccurrences(of: "\"completed\":null,", with: ""),
                    text.replacingOccurrences(of: "\"counter\":1", with: "\"counter\":0"),
                    text.replacingOccurrences(of: "\"counter\":1", with: "\"counter\":1.0"),
                    text.replacingOccurrences(of: "\"expiresUnixMS\":31000", with: "\"expiresUnixMS\":0"),
                    text.replacingOccurrences(of: "\"change\":{", with: "\"change\":{\"extra\":true,"),
                    text.replacingOccurrences(of: "\"nonce\":\"\(challenge.nonce.base64EncodedString())\"", with: "\"nonce\":\"\""),
                    text + "\n"] {
            #expect(bad != text)
            #expect(throws: (any Error).self) { try Wire.decodeServiceChangeChallenge(Data(bad.utf8)) }
        }
        for adoption in try f.unboundAdoptions() {
            #expect(throws: (any Error).self) {
                try Wire.ServiceChangeChallenge(adoption: adoption, change: f.change, targetBoot: nil, completed: nil,
                    counter: 1, nonce: challenge.nonce, expiresUnixMS: 31_000)
            }
        }
    }
    @Test func evenOrdinaryCodableCannotOverflowEpoch() throws {
        let bytes = try Wire.encode(request())
        let invalid = String(decoding: bytes, as: UTF8.self)
            .replacingOccurrences(of: "\"expectedEpoch\":1", with: "\"expectedEpoch\":18446744073709551615")
        let value = try JSONDecoder().decode(Wire.Request.self, from: Data(invalid.utf8))
        #expect(throws: (any Error).self) { try value.epoch }
        #expect(throws: (any Error).self) { try Wire.decodeRequest(Data(invalid.utf8)) }
    }
}

/// Shared by the adoption challenge and ROOT envelope regression tests.
struct AdoptionServiceChangeFixture {
    typealias A = StorageLifecycleAdoptionProtocol
    typealias L = StorageLifecycleProtocol
    let adoption: A.Request
    let change: L.ServiceChangeRequest
    let boot: StorageLifecycleBootTrust
    let confirmation: L.ServiceChangeConfirmation
    init(adoption: A.Request) throws {
        self.adoption = adoption
        let identity = try L.Identity(binding: adoption.origin.binding.value(), generation: 1)
        let grant = try L.Grant(operation: .initialize, id: UUID().uuidString.lowercased(), identity: identity,
            serial: 1, expectedEpoch: 0, newKey: String(repeating: "a", count: 64))
        let root = try StorageIdentity.RootPublicKey(publicData: adoption.origin.rootPublicKey).fingerprint.rawValue
        func state(_ revision: UInt64, _ pin: String) throws -> L.ServiceState {
            let epoch = UUID().uuidString.lowercased()
            return try .init(grant: grant, context: .init(serviceEpoch: epoch, controllerEpoch: 1, controllerKey: grant.newKey),
                openRevision: revision, boot: .init(identity: identity, serviceEpoch: epoch,
                    tlsRootSHA256: String(repeating: pin, count: 64), serverSPKI: String(repeating: pin, count: 64), bootstrapKey: root))
        }
        change = try .init(operationID: UUID().uuidString.lowercased(), predecessor: state(1, "b"))
        let successor = try state(2, "c")
        boot = successor.boot
        confirmation = try .init(request: change, successor: successor)
    }
    func result(nonce: Data = Data(repeating: 8, count: 32), revision: UInt64 = 2) throws -> L.ServiceResult {
        let grant = change.predecessor.grant
        return try .init(identity: grant.identity, grant: grant, nonce: nonce, serviceEpoch: boot.serviceEpoch,
            controllerEpoch: 1, controllerKey: grant.newKey, openRevision: revision)
    }
    func challenge(target: StorageLifecycleBootTrust? = nil, completed: L.ServiceChangeConfirmation? = nil,
                   counter: UInt64 = 1) throws -> A.ServiceChangeChallenge {
        try .init(adoption: adoption, change: change, targetBoot: target, completed: completed,
            counter: counter, nonce: Data(repeating: 8, count: 32), expiresUnixMS: 31_000)
    }
    func unboundAdoptions() throws -> [A.Request] {
        // Valid origins that disagree with the exact predecessor binding or ROOT key.
        let text = String(decoding: try A.encode(adoption), as: UTF8.self)
        return try [text.replacingOccurrences(of: "\"inode\":2", with: "\"inode\":4"),
                    text.replacingOccurrences(of: adoption.origin.rootPublicKey.base64EncodedString(),
                                              with: Data(repeating: 9, count: 32).base64EncodedString())]
            .map { try A.decodeRequest(Data($0.utf8)) }
    }
}

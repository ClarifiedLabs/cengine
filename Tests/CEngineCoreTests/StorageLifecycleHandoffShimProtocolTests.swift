import CEngineCore
import CryptoKit
import Foundation
import Testing

@Suite("Registered shim handoff closed proof")
struct StorageLifecycleHandoffShimProtocolTests {
    typealias H = StorageLifecycleHandoffProtocol
    typealias S = StorageLifecycleHandoffShimProtocol
    typealias L = StorageLifecycleProtocol
    typealias W = StorageLifecycleServiceBootProtocol

    private func challenge() throws -> S.Challenge {
        let root = Curve25519.Signing.PrivateKey()
        let uuid = try StorageIdentity.FilesystemUUID(UUID().uuidString.lowercased())
        let binding = try StorageIdentity.StoreBinding(storeID: .init(uuid.rawValue), root: .init(volumeUUID: uuid, inode: 2),
            backing: .init(identity: .init(volumeUUID: uuid, inode: 3), size: 4096), expectedExt4UUID: uuid)
        let identity = try L.Identity(binding: binding, generation: 1)
        let predecessor = try L.Grant(operation: .initialize, id: UUID().uuidString.lowercased(), identity: identity,
            serial: 1, expectedEpoch: 0, newKey: String(repeating: "a", count: 64))
        let pending = try L.Grant(operation: .takeover, id: UUID().uuidString.lowercased(), identity: identity,
            serial: 2, expectedEpoch: 1, newKey: String(repeating: "b", count: 64))
        let epoch = UUID().uuidString.lowercased()
        let boot = try StorageLifecycleBootTrust(identity: identity, serviceEpoch: epoch,
            tlsRootSHA256: String(repeating: "c", count: 64), serverSPKI: String(repeating: "d", count: 64),
            bootstrapKey: StorageIdentity.RootPublicKey(publicData: root.publicKey.rawRepresentation).fingerprint.rawValue)
        let expected = try L.ServiceState(grant: predecessor, context: .init(serviceEpoch: epoch, controllerEpoch: 1,
            controllerKey: predecessor.newKey), openRevision: 1, boot: boot)
        let request = try H.Request(operationID: UUID().uuidString.lowercased(), predecessor: predecessor,
            pending: pending, serviceEpoch: epoch, openRevision: 1)
        return try .init(origin: .init(binding: .init(binding), rootPublicKey: root.publicKey.rawRepresentation,
            shimLaunchUUID: uuid.rawValue, specSHA256: String(repeating: "e", count: 64)),
            signed: .init(request: request, signature: root.signature(for: request.signingBytes)), expected: expected,
            counter: 1, nonce: Data(repeating: 7, count: 32), expiresUnixMS: 30_001)
    }
    @Test(arguments: [false, true])
    func exactProofAndClosedGuestEnvelope(committed: Bool) throws {
        let c = try challenge(), r = c.signed.request
        let grant = committed ? r.pending : r.predecessor
        let result = try H.Result(request: r, nonce: c.nonce, appliedGrant: grant, appliedServiceEpoch: r.serviceEpoch,
            appliedRevision: committed ? 2 : 1, fenceRevision: 3)
        let reply = try S.Reply(challenge: c, result: result, boot: c.expected.boot)
        #expect(try S.decodeChallenge(S.encode(c)) == c)
        #expect(try S.decodeReply(S.encode(reply), challenge: c) == reply)
        #expect(c.isFresh(at: 1) && !c.isFresh(at: 0) && !c.isFresh(at: 30_001))
        let other = try S.Challenge(origin: c.origin, signed: c.signed, expected: c.expected,
            counter: 2, nonce: Data(repeating: 8, count: 32), expiresUnixMS: c.expiresUnixMS)
        #expect(throws: (any Error).self) { try S.decodeReply(S.encode(reply), challenge: other) }
        for bytes in [try S.encode(c), try S.encode(reply)] {
            let body = String(decoding: bytes, as: UTF8.self)
            for bad in [" " + body, "{\"extra\":true," + body.dropFirst(), body.replacingOccurrences(of: "\"nonce\":", with: "\"nonce\":null,\"nonce\":")] {
                #expect(throws: (any Error).self) {
                    if bytes == (try S.encode(c)) { _ = try S.decodeChallenge(Data(bad.utf8)) }
                    else { _ = try S.decodeReply(Data(bad.utf8), challenge: c) }
                }
            }
        }
        let binding = W.Binding(shimLaunchUUID: c.origin.shimLaunchUUID, guestBootNonce: UUID().uuidString.lowercased(),
            ext4UUID: c.origin.shimLaunchUUID, bytes: 4096)
        let ready = W.Ready(identity: grant.identity, serviceEpoch: r.serviceEpoch, workerUUID: UUID().uuidString.lowercased(),
            controllerEpoch: grant.expectedEpoch + 1, controllerKey: grant.newKey, revision: 3, openRevision: 1,
            bootstrapKey: c.expected.boot.bootstrapKey, tlsRootDER: Data([1]), serverDER: Data([2]), serverSPKI: c.expected.boot.serverSPKI)
        let command = W.Frame(operation: .command, binding: binding, sequence: 1, serviceEpoch: r.serviceEpoch,
            command: .fenceHandoff, workerUUID: ready.workerUUID, handoff: c.signed, nonce: c.nonce)
        let response = W.Frame(operation: .reply, binding: binding, sequence: 1, serviceEpoch: r.serviceEpoch,
            workerUUID: ready.workerUUID, handoffResult: .init(result: result, ready: ready))
        for frame in [command, response] {
            #expect(try W.decode(W.encode(frame).dropFirst(4)) == frame)
            var mixed = frame; mixed.ready = ready
            #expect(throws: (any Error).self) { try W.encode(mixed) }
            mixed = frame; mixed.signed = try .init(grant: grant, signature: Data(repeating: 0, count: 64))
            #expect(throws: (any Error).self) { try W.encode(mixed) }
            mixed = frame; mixed.serviceEpoch = UUID().uuidString.lowercased()
            #expect(throws: (any Error).self) { try W.encode(mixed) }
        }
        var query = command; query.command = .query
        #expect(throws: (any Error).self) { try W.encode(query) }
        var missing = command; missing.nonce = nil
        #expect(throws: (any Error).self) { try W.encode(missing) }
    }
}

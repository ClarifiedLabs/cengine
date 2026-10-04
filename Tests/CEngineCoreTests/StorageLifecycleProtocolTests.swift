import CEngineCore
import CryptoKit
import Foundation
import Testing

@Suite("Inactive storage lifecycle v2 wire")
struct StorageLifecycleProtocolTests {
    private typealias P = StorageLifecycleProtocol
    private let store = "bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb"
    private let id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    private let serviceEpoch = "cccccccc-cccc-4ccc-accc-cccccccccccc"
    private let key = String(repeating: "ab", count: 32)

    private struct Fixture: Decodable {
        let version: String
        let root_public_key: Data
        let binding_json: String
        let binding_digest: String
        let vectors: [Vector]
        let receipt: ReceiptVector
    }
    private struct Vector: Decodable {
        let grant: P.Grant
        let signing_bytes: Data
        let signature: Data
        let canonical_json: String
    }
    private struct ReceiptVector: Decodable {
        let value: P.Receipt
        let signing_bytes: Data
        let signature: Data
        let canonical_json: String
    }
    private func fixture() throws -> Fixture {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Fixtures/storage-bootstrap/lifecycle-v2.json")
        return try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: url))
    }
    private func binding() throws -> StorageIdentity.StoreBinding {
        try StorageIdentity.StoreBinding(storeID: StorageIdentity.StoreID(store),
            root: StorageIdentity.RootIdentity(volumeUUID: StorageIdentity.FilesystemUUID("cccccccc-cccc-1ccc-accc-cccccccccccc"),
                                 inode: .max),
            backing: StorageIdentity.BackingIdentity(identity: StorageIdentity.RootIdentity(
                volumeUUID: StorageIdentity.FilesystemUUID("dddddddd-dddd-1ddd-bddd-dddddddddddd"),
                inode: 9_007_199_254_740_995), size: 9_007_199_254_740_997),
            expectedExt4UUID: StorageIdentity.FilesystemUUID("eeeeeeee-eeee-1eee-8eee-eeeeeeeeeeee"))
    }
    private func identity() throws -> P.Identity {
        try P.Identity(binding: binding(), generation: 9_007_199_254_740_993)
    }
    private func grant(_ operation: P.Operation = .takeover, epoch: UInt64 = 1) throws -> P.Grant {
        try P.Grant(operation: operation, id: id, identity: identity(), serial: 1, expectedEpoch: epoch, newKey: key)
    }
    private func roundTrip<T: Codable & Equatable>(_ value: T) throws {
        #expect(try P.decode(T.self, from: P.encode(value)) == value)
    }

    @Test func sharedGoSignaturesAndExactDeclarationOrder() throws {
        let f = try fixture()
        #expect(f.version == P.version)
        #expect(f.vectors.map(\.grant.operation) == [.initialize, .takeover, .retire])
        let root = try StorageIdentity.RootPublicKey(publicData: f.root_public_key)
        let verifier = try Curve25519.Signing.PublicKey(rawRepresentation: f.root_public_key)
        for v in f.vectors {
            #expect(v.grant.signingBytes == v.signing_bytes)
            #expect(String(decoding: try P.encode(v.grant), as: UTF8.self) == v.canonical_json)
            #expect(try P.decode(P.Grant.self, from: Data(v.canonical_json.utf8)) == v.grant)
            let signed = try P.SignedGrant(grant: v.grant, signature: v.signature)
            #expect(signed.isValidSignature(using: root))
            try roundTrip(signed)
            var corrupt = v.signature
            corrupt[0] ^= 1
            #expect(!(try P.SignedGrant(grant: v.grant, signature: corrupt)).isValidSignature(using: root))
            let body = v.signing_bytes.dropFirst(Data("cengine.storageauthority.lifecycle.v2\0".utf8).count)
            for domain in ["cengine.storageauthority.takeover.v1\0", "cengine.storageauthority.lifecycle.v1\0",
                           "cengine.storageauthority.lifecycle-receipt.v2\0"] {
                #expect(!verifier.isValidSignature(v.signature, for: Data(domain.utf8) + body))
            }
            #expect(!verifier.isValidSignature(v.signature,
                for: Data("cengine.storageauthority.lifecycle.v2\0".utf8) + (try P.encode(v.grant))))
        }
        #expect(f.receipt.value.signingBytes == f.receipt.signing_bytes)
        #expect(verifier.isValidSignature(f.receipt.signature, for: f.receipt.value.signingBytes))
        #expect(String(decoding: try P.encode(f.receipt.value), as: UTF8.self) == f.receipt.canonical_json)
        try roundTrip(f.receipt.value)
        #expect(!verifier.isValidSignature(f.receipt.signature, for: f.receipt.value.grant.signingBytes))
        // Obsolete takeover JSON cannot be interpreted as a lifecycle grant.
        let legacy = "{\"id\":\"\(id)\",\"store\":\"\(store)\",\"expected_epoch\":1,\"new_key\":\"\(key)\"}"
        #expect(throws: (any Error).self) { try P.decode(P.Grant.self, from: Data(legacy.utf8)) }
    }

    @Test func bindingDigestPinsExactFixtureRepresentationAndEveryField() throws {
        let f = try fixture()
        let b = try binding()
        #expect(P.bindingDigest(b) == f.binding_digest)
        #expect(try identity().binding == f.binding_digest)
        #expect(try identity().store == b.storeID.rawValue)
        let digest = SHA256.hash(data: Data(("cengine.storageauthority.binding.v3\0" + f.binding_json).utf8))
            .map { String(format: "%02x", $0) }.joined()
        #expect(digest == f.binding_digest)
        let otherUUID = try StorageIdentity.FilesystemUUID(id)
        let roots = try [
            StorageIdentity.RootIdentity(volumeUUID: otherUUID, inode: b.root.inode),
            StorageIdentity.RootIdentity(volumeUUID: b.root.volumeUUID, inode: b.root.inode - 1)
        ]
        var variants = roots.map { StorageIdentity.StoreBinding(storeID: b.storeID, root: $0, backing: b.backing, expectedExt4UUID: b.expectedExt4UUID) }
        let backingRoots = try [
            StorageIdentity.RootIdentity(volumeUUID: otherUUID, inode: b.backing.identity.inode),
            StorageIdentity.RootIdentity(volumeUUID: b.backing.identity.volumeUUID, inode: b.backing.identity.inode + 1)
        ]
        for root in backingRoots {
            variants.append(try StorageIdentity.StoreBinding(storeID: b.storeID, root: b.root,
                backing: StorageIdentity.BackingIdentity(identity: root, size: b.backing.size), expectedExt4UUID: b.expectedExt4UUID))
        }
        variants.append(try StorageIdentity.StoreBinding(storeID: StorageIdentity.StoreID(id), root: b.root, backing: b.backing, expectedExt4UUID: b.expectedExt4UUID))
        variants.append(StorageIdentity.StoreBinding(storeID: b.storeID, root: b.root, backing: b.backing, expectedExt4UUID: otherUUID))
        variants.append(try StorageIdentity.StoreBinding(storeID: b.storeID, root: b.root,
            backing: StorageIdentity.BackingIdentity(identity: b.backing.identity, size: b.backing.size + 1), expectedExt4UUID: b.expectedExt4UUID))
        for changed in variants { #expect(P.bindingDigest(changed) != f.binding_digest) }
    }

    @Test func liveObservationsProjectToOneDurableBindingAndDigest() throws {
        let b = try binding()
        let original = StorageLifecycleStoreBinding(b)
        for device: UInt64 in [0, 1, 9_007_199_254_740_993, .max] {
            let root = StorageIdentity.DescriptorIdentity(stableIdentity: b.root, device: device)
            let backing = StorageIdentity.DescriptorIdentity(stableIdentity: b.backing.identity, device: device)
            let live = StorageLifecycleStoreBinding.LiveFileIdentity(backing)
            #expect(try live.value() == backing)
            #expect(try P.decode(StorageLifecycleStoreBinding.LiveFileIdentity.self, from: P.encode(live)) == live)
            #expect(live.stableIdentity == original.backing)
            let projected = try StorageIdentity.StoreBinding(storeID: b.storeID, root: root.stableIdentity,
                backing: .init(identity: live.stableIdentity.value(), size: b.backing.size), expectedExt4UUID: b.expectedExt4UUID)
            #expect(projected == b)
            #expect(StorageLifecycleStoreBinding(projected) == original)
            #expect(try P.encode(StorageLifecycleStoreBinding(projected)) == P.encode(original))
            #expect(P.bindingDigest(projected) == P.bindingDigest(b))
        }
        let a = StorageLifecycleStoreBinding.LiveFileIdentity(.init(stableIdentity: b.backing.identity, device: 0))
        let z = StorageLifecycleStoreBinding.LiveFileIdentity(.init(stableIdentity: b.backing.identity, device: .max))
        #expect(a != z)
        #expect(try P.encode(a) != P.encode(z))
        #expect(a.stableIdentity == z.stableIdentity)
    }

    @Test func bindingDTORejectsLegacyFieldsVersionsAndMissingStableIdentity() throws {
        let dto = StorageLifecycleStoreBinding(try binding())
        let text = String(decoding: try P.encode(dto), as: UTF8.self)
        #expect(!text.contains("device"))
        #expect(dto.version == "storage-host-binding.v2")
        #expect(try dto.value() == binding())
        for bad in [
            text.replacingOccurrences(of: "storage-host-binding.v2", with: "storage-host-binding.v1"),
            text.replacingOccurrences(of: ",\"version\":\"storage-host-binding.v2\"", with: ""),
            text.replacingOccurrences(of: "\"root\":{", with: "\"root\":{\"device\":0,"),
            text.replacingOccurrences(of: "\"backing\":{", with: "\"backing\":{\"device\":1,"),
            text.replacingOccurrences(of: "volume_uuid", with: "old_volume_uuid"),
            text.replacingOccurrences(of: "\"inode\":18446744073709551615", with: "\"inode\":0")
        ] {
            #expect(bad != text)
            #expect(throws: (any Error).self) { try P.decode(StorageLifecycleStoreBinding.self, from: Data(bad.utf8)) }
            #expect(throws: (any Error).self) { try JSONDecoder().decode(StorageLifecycleStoreBinding.self, from: Data(bad.utf8)) }
        }
        let fixture = try fixture()
        let oldDomain = SHA256.hash(data: Data(("cengine.storageauthority.binding.v2\0" + fixture.binding_json).utf8))
            .map { String(format: "%02x", $0) }.joined()
        #expect(oldDomain != P.bindingDigest(try binding()))
    }

    @Test func scopeRequiresStableHostIdentityVersion() throws {
        let request = StorageLifecycleScopeProtocol.Request(store: try .init(store))
        let bytes = try StorageLifecycleScopeProtocol.encode(request)
        #expect(request.version == "storage-lifecycle-scope.v2")
        #expect(try StorageLifecycleScopeProtocol.decode(bytes) == request)
        let old = String(decoding: bytes, as: UTF8.self).replacingOccurrences(of: "storage-lifecycle-scope.v2", with: "storage-lifecycle-scope.v1")
        #expect(throws: (any Error).self) { try StorageLifecycleScopeProtocol.decode(Data(old.utf8)) }
    }

    @Test func unsignedIntegerBoundariesAndOperationEpochRules() throws {
        for number: UInt64 in [1, 9_007_199_254_740_993, .max] {
            let identity = try P.Identity(store: store, generation: number, binding: key)
            try roundTrip(identity)
            for (operation, epoch): (P.Operation, UInt64) in [(.initialize, 0), (.takeover, 1), (.takeover, .max - 1), (.retire, 1), (.retire, .max)] {
                let value = try P.Grant(operation: operation, id: id, identity: identity, serial: number, expectedEpoch: epoch, newKey: key)
                try value.validate()
                try roundTrip(value)
                try roundTrip(P.Receipt(grant: value, nonce: Data(repeating: 255, count: 32), serviceEpoch: serviceEpoch, revision: number))
            }
        }
        for (operation, epoch): (P.Operation, UInt64) in [(.initialize, 1), (.initialize, .max), (.takeover, 0), (.takeover, .max), (.retire, 0)] {
            #expect(throws: P.ValidationError.invalidValue) { try grant(operation, epoch: epoch) }
        }
    }

    @Test func invalidConstructorsAndNestedDecoding() throws {
        for bad in ["", store.uppercased(), "bbbbbbbb-bbbb-1bbb-9bbb-bbbbbbbbbbbb", "bbbbbbbb-bbbb-4bbb-cbbb-bbbbbbbbbbbb", store + " "] {
            #expect(throws: (any Error).self) { try P.Identity(store: bad, generation: 1, binding: key) }
            #expect(throws: (any Error).self) { try P.Grant(operation: .initialize, id: bad, identity: identity(), serial: 1, expectedEpoch: 0, newKey: key) }
            #expect(throws: (any Error).self) { try P.Receipt(grant: grant(), nonce: Data(repeating: 0, count: 32), serviceEpoch: bad, revision: 1) }
        }
        for bad in ["", key.uppercased(), String(key.dropLast()), key + "a", String(repeating: "g", count: 64)] {
            #expect(throws: (any Error).self) { try P.Identity(store: store, generation: 1, binding: bad) }
            #expect(throws: (any Error).self) { try P.Grant(operation: .initialize, id: id, identity: identity(), serial: 1, expectedEpoch: 0, newKey: bad) }
        }
        #expect(throws: (any Error).self) { try P.Identity(store: store, generation: 0, binding: key) }
        #expect(throws: (any Error).self) { try P.Identity(binding: binding(), generation: 0) }
        #expect(throws: (any Error).self) { try P.Grant(operation: .initialize, id: id, identity: identity(), serial: 0, expectedEpoch: 0, newKey: key) }
        for count in [0, 31, 33] {
            #expect(throws: (any Error).self) { try P.Receipt(grant: grant(), nonce: Data(repeating: 0, count: count), serviceEpoch: serviceEpoch, revision: 1) }
        }
        #expect(throws: (any Error).self) { try P.Receipt(grant: grant(), nonce: Data(repeating: 0, count: 32), serviceEpoch: serviceEpoch, revision: 0) }
        for count in [0, 32, 63, 65] {
            #expect(throws: P.ValidationError.invalidSignature) { try P.SignedGrant(grant: grant(), signature: Data(repeating: 0, count: count)) }
        }
        let receipt = try P.Receipt(grant: grant(), nonce: Data(repeating: 0, count: 32), serviceEpoch: serviceEpoch, revision: 1)
        let text = String(decoding: try P.encode(receipt), as: UTF8.self)
        for (old, new) in [("\"generation\":9007199254740993", "\"generation\":0"),
                           ("\"serial\":1", "\"serial\":0"), ("\"expected_epoch\":1", "\"expected_epoch\":0"),
                           ("\"revision\":1", "\"revision\":0"), ("\"operation\":\"takeover\"", "\"operation\":\"open\"")] {
            // Even direct JSONDecoder cannot bypass nested constructor validation.
            #expect(throws: (any Error).self) { try JSONDecoder().decode(P.Receipt.self, from: Data(text.replacingOccurrences(of: old, with: new).utf8)) }
        }
    }

    @Test func closedCanonicalJSONRejectsMalleableMessages() throws {
        let receipt = try P.Receipt(grant: grant(), nonce: Data(repeating: 255, count: 32), serviceEpoch: serviceEpoch, revision: 1)
        let text = String(decoding: try P.encode(receipt), as: UTF8.self)
        #expect(text.contains(receipt.nonce.base64EncodedString())) // no escaped slashes
        var invalid = [text + "\n", " " + text, text + "{}", String(text.dropLast()) + ",\"unknown\":1}",
            text.replacingOccurrences(of: "\"serial\":1", with: "\"serial\":1,\"serial\":1"),
            text.replacingOccurrences(of: "\"generation\":9007199254740993", with: "\"generation\":9007199254740993,\"unknown\":1"),
            text.replacingOccurrences(of: "\"store\":", with: "\"\\u0073tore\":"),
            text.replacingOccurrences(of: "/", with: "\\/"),
            text.replacingOccurrences(of: receipt.nonce.base64EncodedString(), with: receipt.nonce.base64EncodedString().replacingOccurrences(of: "8=", with: "9=")),
            text.replacingOccurrences(of: receipt.nonce.base64EncodedString(), with: String(receipt.nonce.base64EncodedString().dropLast())),
            text.replacingOccurrences(of: "\"revision\":1", with: "\"revision\":1,\"revision\":1")]
        for number in ["1.0", "1e0", "01", "-1", "18446744073709551616", "null", "true", "\"1\""] {
            invalid.append(text.replacingOccurrences(of: "\"revision\":1", with: "\"revision\":\(number)"))
        }
        for bad in invalid {
            #expect(bad != text)
            #expect(throws: (any Error).self) { try P.decode(P.Receipt.self, from: Data(bad.utf8)) }
        }
        #expect(throws: P.ValidationError.payloadTooLarge) {
            try P.decode(P.Receipt.self, from: Data(repeating: 32, count: P.maximumPayloadBytes + 1))
        }
        #expect(throws: P.ValidationError.payloadTooLarge) { try P.encode(String(repeating: "x", count: P.maximumPayloadBytes)) }
        #expect(try P.encode(String(repeating: "x", count: P.maximumPayloadBytes - 2)).count == P.maximumPayloadBytes)
    }
}

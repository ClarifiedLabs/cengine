import CEngineCore
import CryptoKit
import Foundation
import Testing

@Suite struct StorageIdentityTests {
    private let storeText = "bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb"
    private let grantText = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    private let requestText = "cccccccc-cccc-4ccc-accc-cccccccccccc"
    private let incarnationText = "dddddddd-dddd-4ddd-bddd-dddddddddddd"

    @Test func validatesDistinctCanonicalIdentifiers() throws {
        #expect(try StorageIdentity.StoreID(storeText).rawValue == storeText)
        #expect(try StorageIdentity.GrantID(grantText).rawValue == grantText)
        #expect(try StorageIdentity.RequestID(requestText).rawValue == requestText)
        #expect(try StorageIdentity.IncarnationID(incarnationText).rawValue == incarnationText)
        let invalid = ["", storeText.uppercased(), storeText + " ", " " + storeText,
                       storeText.replacingOccurrences(of: "4bbb", with: "1bbb"),
                       storeText.replacingOccurrences(of: "9bbb", with: "cbbb"),
                       "00000000-0000-0000-0000-000000000000", "\"" + storeText, storeText + "\0",
                       storeText.replacingOccurrences(of: "b", with: "Ｂ")]
        for text in invalid {
            #expect(throws: StorageIdentity.ValidationError.self) { try StorageIdentity.StoreID(text) }
            #expect(throws: StorageIdentity.ValidationError.self) { try StorageIdentity.GrantID(text) }
            #expect(throws: StorageIdentity.ValidationError.self) { try StorageIdentity.RequestID(text) }
            #expect(throws: StorageIdentity.ValidationError.self) { try StorageIdentity.IncarnationID(text) }
        }
        #expect(throws: StorageIdentity.ValidationError.self) { try StorageIdentity.FilesystemUUID("00000000-0000-0000-0000-000000000000") }
        #expect(try StorageIdentity.FilesystemUUID("aaaaaaaa-aaaa-1aaa-8aaa-aaaaaaaaaaaa").rawValue.contains("1aaa"))
    }

    @Test func epochAndBindingBounds() throws {
        #expect(throws: StorageIdentity.ValidationError.invalidEpoch) { try StorageIdentity.ControllerEpoch(0) }
        #expect(try StorageIdentity.ControllerEpoch(1).successor().rawValue == 2)
        #expect(try StorageIdentity.ControllerEpoch(UInt64.max - 1).successor().rawValue == UInt64.max)
        #expect(throws: StorageIdentity.ValidationError.epochExhausted) { try StorageIdentity.ControllerEpoch(UInt64.max).successor() }
        let key = try candidate().publicKey
        let uuid = try StorageIdentity.FilesystemUUID(storeText)
        #expect(throws: StorageIdentity.ValidationError.invalidBinding) { try StorageIdentity.RootIdentity(volumeUUID: uuid, inode: 0) }
        let root = try StorageIdentity.RootIdentity(volumeUUID: uuid, inode: .max)
        #expect(try StorageIdentity.DescriptorIdentity(volumeUUID: uuid, device: 0, inode: 1).device == 0)
        #expect(StorageIdentity.DescriptorIdentity(stableIdentity: root, device: 1) != StorageIdentity.DescriptorIdentity(stableIdentity: root, device: 2))
        #expect(throws: StorageIdentity.ValidationError.invalidBinding) { try StorageIdentity.BackingIdentity(identity: root, size: 0) }
        #expect(throws: StorageIdentity.ValidationError.invalidBinding) { try StorageIdentity.BackingIdentity(identity: root, size: UInt64(Int64.max) + 1) }
        #expect(try StorageIdentity.BackingIdentity(identity: root, size: UInt64(Int64.max)).size == UInt64(Int64.max))
        for pid: Int32 in [0, -1, .min] {
            #expect(throws: StorageIdentity.ValidationError.invalidPID) { try StorageIdentity.Candidate(publicKey: key, childPIDHint: pid, incarnationID: StorageIdentity.IncarnationID(incarnationText)) }
        }
        #expect(try StorageIdentity.Candidate(publicKey: key, childPIDHint: .max, incarnationID: StorageIdentity.IncarnationID(incarnationText)).childPIDHint == .max)
    }

    @Test func rejectsNoncanonicalEd25519SPKIAndFingerprints() throws {
        let key = try candidate().publicKey
        #expect(key.publicData.count == 44)
        #expect(try StorageIdentity.Ed25519SPKI(rawPublicKey: key.rawPublicKey) == key)
        var badOID = key.publicData
        badOID[8] = 0x6e // X25519, not Ed25519.
        var badBits = key.publicData
        badBits[11] = 1
        let withNull = Data([0x30, 0x2c, 0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0, 0x03, 0x21, 0]) + key.rawPublicKey
        let longLength = Data([0x30, 0x81, 0x2a]) + key.publicData.dropFirst(2)
        for data in [Data(), key.rawPublicKey, key.publicData + Data([0]), Data(key.publicData.dropLast()), badOID, badBits, withNull, longLength] {
            #expect(throws: StorageIdentity.ValidationError.invalidPublicKey) { try StorageIdentity.Ed25519SPKI(publicData: data) }
        }
        for count in [0, 31, 33, 44, 64] {
            #expect(throws: StorageIdentity.ValidationError.invalidPublicKey) { try StorageIdentity.RootPublicKey(publicData: Data(repeating: 0, count: count)) }
            #expect(throws: StorageIdentity.ValidationError.invalidPublicKey) { try StorageIdentity.Ed25519SPKI(rawPublicKey: Data(repeating: 0, count: count)) }
        }
        for fp in ["", String(repeating: "a", count: 63), String(repeating: "a", count: 65), String(repeating: "A", count: 64), String(repeating: "g", count: 64), key.fingerprint.rawValue + "\n"] {
            #expect(throws: StorageIdentity.ValidationError.invalidFingerprint) { try StorageIdentity.SPKISHA256(fp) }
        }
        let rawHash = SHA256.hash(data: key.rawPublicKey).map { String(format: "%02x", $0) }.joined()
        #expect(rawHash != key.fingerprint.rawValue)
    }

    @Test func rootFingerprintUsesCanonicalSPKIAndRFC8032Verifier() throws {
        func hex(_ text: String) -> Data {
            let bytes = Array(text.utf8)
            return Data(stride(from: 0, to: bytes.count, by: 2).map {
                UInt8(String(decoding: bytes[$0..<$0 + 2], as: UTF8.self), radix: 16)!
            })
        }
        let publicKey = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        let signature = hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        let root = try StorageIdentity.RootPublicKey(publicData: publicKey)
        let spki = try StorageIdentity.Ed25519SPKI(rawPublicKey: publicKey)
        #expect(root.fingerprint == spki.fingerprint)
        let verifier = try Curve25519.Signing.PublicKey(rawRepresentation: root.publicData)
        #expect(verifier.isValidSignature(signature, for: Data()))
        #expect(!verifier.isValidSignature(signature, for: Data([0])))
    }

    private func candidate() throws -> StorageIdentity.Candidate {
        let key = try StorageIdentity.Ed25519SPKI(rawPublicKey: Data(repeating: 1, count: 32))
        return try StorageIdentity.Candidate(publicKey: key, childPIDHint: 42,
            incarnationID: StorageIdentity.IncarnationID(incarnationText))
    }
}

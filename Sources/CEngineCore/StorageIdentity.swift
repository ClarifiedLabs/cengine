import CryptoKit
import Foundation

/// Shared storage identity values and validation, independent of transport or authority.
/// These values are untrusted evidence, not authenticated principals or writer leases.
public enum StorageIdentity {
    public enum ValidationError: Error, Equatable, Sendable {
        case invalidIdentifier, invalidEpoch, epochExhausted, invalidFingerprint
        case invalidPublicKey, invalidSignature, invalidBinding, invalidPID
        case invalidMessage, payloadTooLarge, correlationMismatch
    }

    // Tags keep store, grant and incarnation IDs non-interchangeable. All match
    // Guest/internal/storageauthority/types.go validID, not Foundation's permissive UUID parser.
    public enum StoreTag: Sendable {}
    public enum GrantTag: Sendable {}
    public enum IncarnationTag: Sendable {}
    public enum RequestTag: Sendable {}
    public struct ID<Tag: Sendable>: Equatable, Hashable, Sendable {
        public let rawValue: String
        public init(_ value: String) throws {
            guard canonicalUUID(value), value.utf8[value.utf8.index(value.utf8.startIndex, offsetBy: 14)] == 52,
                  [56, 57, 97, 98].contains(Array(value.utf8)[19]) else {
                throw ValidationError.invalidIdentifier
            }
            rawValue = value
        }
    }
    public typealias StoreID = ID<StoreTag>
    public typealias GrantID = ID<GrantTag>
    public typealias IncarnationID = ID<IncarnationTag>
    public typealias RequestID = ID<RequestTag>

    /// Filesystem UUIDs are canonical lowercase, nonnil UUIDs, but need not be v4.
    public struct FilesystemUUID: Equatable, Hashable, Sendable {
        public let rawValue: String
        public init(_ value: String) throws {
            guard canonicalUUID(value), value != "00000000-0000-0000-0000-000000000000" else {
                throw ValidationError.invalidIdentifier
            }
            rawValue = value
        }
    }

    public struct ControllerEpoch: Equatable, Hashable, Sendable {
        public let rawValue: UInt64
        public init(_ value: UInt64) throws {
            guard value != 0 else { throw ValidationError.invalidEpoch }
            rawValue = value
        }
        public func successor() throws -> Self {
            guard rawValue < UInt64.max else { throw ValidationError.epochExhausted }
            return try Self(rawValue + 1)
        }
    }

    /// SHA-256 of canonical PKIX SubjectPublicKeyInfo DER, NOT the raw 32-byte key.
    /// Matches storageauthority.PublicKeyFingerprint (Go x509.MarshalPKIXPublicKey).
    public struct SPKISHA256: Equatable, Hashable, Sendable {
        public let rawValue: String
        public init(_ value: String) throws {
            guard value.utf8.count == 64, value.utf8.allSatisfy(isLowerHex) else {
                throw ValidationError.invalidFingerprint
            }
            rawValue = value
        }
        fileprivate init(der: Data) {
            rawValue = SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
        }
    }

    /// RFC 8410 Ed25519 only: absent parameters, 32-byte BIT STRING, no trailing DER.
    public struct Ed25519SPKI: Equatable, Sendable {
        fileprivate static let prefix = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])
        public let publicData: Data
        public init(publicData: Data) throws {
            guard publicData.count == 44, publicData.starts(with: Self.prefix) else {
                throw ValidationError.invalidPublicKey
            }
            self.publicData = publicData
        }
        public init(rawPublicKey: Data) throws {
            guard rawPublicKey.count == 32 else { throw ValidationError.invalidPublicKey }
            try self.init(publicData: Self.prefix + rawPublicKey)
        }
        public var rawPublicKey: Data { Data(publicData.suffix(32)) }
        public var fingerprint: SPKISHA256 { SPKISHA256(der: publicData) }
    }

    /// Public bootstrap verifier only. The ROOT signing key belongs exclusively to
    /// the future helper; this module has no signing or private-key API.
    public struct RootPublicKey: Equatable, Sendable {
        public let publicData: Data
        public init(publicData: Data) throws {
            guard publicData.count == 32 else { throw ValidationError.invalidPublicKey }
            self.publicData = publicData
        }
        public var fingerprint: SPKISHA256 {
            // Construction already checked the raw-key length.
            SPKISHA256(der: Ed25519SPKI.prefix + publicData)
        }
    }

    /// Durable host identity. Device numbers are live observations, not store identity.
    public struct RootIdentity: Equatable, Sendable {
        public let volumeUUID: FilesystemUUID
        public let inode: UInt64
        public init(volumeUUID: FilesystemUUID, inode: UInt64) throws {
            guard inode > 0 else { throw ValidationError.invalidBinding }
            self.volumeUUID = volumeUUID
            self.inode = inode
        }
    }

    /// Full live descriptor observation; never persist as a durable store identity.
    /// Device zero is valid opaque st_dev metadata.
    public struct DescriptorIdentity: Equatable, Sendable {
        public let stableIdentity: RootIdentity
        public let device: UInt64
        public init(stableIdentity: RootIdentity, device: UInt64) {
            self.stableIdentity = stableIdentity
            self.device = device
        }
        public init(volumeUUID: FilesystemUUID, device: UInt64, inode: UInt64) throws {
            self.init(stableIdentity: try .init(volumeUUID: volumeUUID, inode: inode), device: device)
        }
    }

    public struct BackingIdentity: Equatable, Sendable {
        public let identity: RootIdentity
        public let size: UInt64
        public init(identity: RootIdentity, size: UInt64) throws {
            guard size > 0, size <= UInt64(Int64.max) else { throw ValidationError.invalidBinding }
            self.identity = identity
            self.size = size
        }
    }

    /// Host store-root + raw backing-file evidence; not guest root inode numbers.
    /// expectedExt4UUID maps to the independently verified guest Store.DeviceID.
    /// Only first registration accepts this binding. It never authorizes adoption,
    /// formatting, root replacement or a disk-writer handoff.
    public struct StoreBinding: Equatable, Sendable {
        public let storeID: StoreID
        public let root: RootIdentity
        public let backing: BackingIdentity
        public let expectedExt4UUID: FilesystemUUID
        public init(storeID: StoreID, root: RootIdentity, backing: BackingIdentity, expectedExt4UUID: FilesystemUUID) {
            self.storeID = storeID
            self.root = root
            self.backing = backing
            self.expectedExt4UUID = expectedExt4UUID
        }
    }
    public typealias DiskBinding = StoreBinding

    public struct Controller: Equatable, Sendable {
        public let epoch: ControllerEpoch
        public let key: SPKISHA256
        public init(epoch: ControllerEpoch, key: SPKISHA256) {
            self.epoch = epoch
            self.key = key
        }
    }

    /// Candidate metadata, never proof of process identity or key possession.
    /// childPIDHint is a positive Int32 lookup hint for independent helper checks;
    /// incarnationID is a fresh UUIDv4 for that child launch, not a daemon PID.
    public struct Candidate: Equatable, Sendable {
        public let publicKey: Ed25519SPKI
        public let childPIDHint: Int32
        public let incarnationID: IncarnationID
        public init(publicKey: Ed25519SPKI, childPIDHint: Int32, incarnationID: IncarnationID) throws {
            guard childPIDHint > 0 else { throw ValidationError.invalidPID }
            self.publicKey = publicKey
            self.childPIDHint = childPIDHint
            self.incarnationID = incarnationID
        }
    }

    /// Stable public failures, never arbitrary internal messages or success fields.
    public enum ErrorCode: String, CaseIterable, Sendable {
        case invalidRequest, unauthorized, conflict, unknownStore, unknownGrant
        case blocked, epochExhausted, capacityExceeded, repairRequired, unavailable
    }

    private static func isLowerHex(_ byte: UInt8) -> Bool {
        (48...57).contains(byte) || (97...102).contains(byte)
    }
    private static func canonicalUUID(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard bytes.count == 36 else { return false }
        return bytes.enumerated().allSatisfy { index, byte in
            [8, 13, 18, 23].contains(index) ? byte == 45 : isLowerHex(byte)
        }
    }
}

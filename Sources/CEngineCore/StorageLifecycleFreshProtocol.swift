import CryptoKit
import Foundation

/// Direct-shim messages. These unsigned values are never proof by themselves:
/// both endpoints MUST independently authenticate the direct Mach sender.
public enum StorageLifecycleFreshProtocol {
    public static let version = "storage-fresh-lifecycle.v2"
    public static let lifetimeMS: UInt64 = 30_000
    public typealias Lifecycle = StorageLifecycleProtocol
    public typealias Bootstrap = StorageIdentity

    public struct Greeting: Codable, Equatable, Sendable {
        public let version: String
        public let channelID: String
        public let daemonUniqueID: UInt64
        public let rootPublicKey: Data
        public let store: String
        public let shimLaunchUUID: String
        public let guestBootNonce: String
        public let operationUUID: String
        public let ext4UUID: String
        public let bytes: UInt64
        public let initramfsSHA256: String
        public let device: UInt64
        public let inode: UInt64
        public let volumeUUID: String

        public init(channelID: String, daemonUniqueID: UInt64, rootPublicKey: Data, store: String,
                    shimLaunchUUID: String, guestBootNonce: String, operationUUID: String,
                    ext4UUID: String, bytes: UInt64, initramfsSHA256: String,
                    device: UInt64, inode: UInt64, volumeUUID: String) throws {
            version = StorageLifecycleFreshProtocol.version
            self.channelID = channelID; self.daemonUniqueID = daemonUniqueID
            self.rootPublicKey = rootPublicKey; self.store = store
            self.shimLaunchUUID = shimLaunchUUID; self.guestBootNonce = guestBootNonce
            self.operationUUID = operationUUID; self.ext4UUID = ext4UUID; self.bytes = bytes
            self.initramfsSHA256 = initramfsSHA256
            self.device = device; self.inode = inode; self.volumeUUID = volumeUUID
            try validate()
        }
        public func validate() throws {
            guard version == StorageLifecycleFreshProtocol.version, daemonUniqueID > 0,
                  bytes > 0, bytes <= UInt64(Int64.max), inode > 0 else { throw Lifecycle.ValidationError.invalidValue }
            _ = try StorageIdentity.IncarnationID(channelID)
            _ = try StorageIdentity.RootPublicKey(publicData: rootPublicKey)
            _ = try StorageIdentity.StoreID(store)
            for value in [shimLaunchUUID, guestBootNonce, operationUUID, ext4UUID, volumeUUID] {
                _ = try StorageIdentity.FilesystemUUID(value)
            }
            _ = try StorageIdentity.SPKISHA256(initramfsSHA256)
        }
        /// Stable backing correlation only; deliberately ignores the live device.
        /// Callers must independently compare native descriptor observations.
        /// StoreBinding has no boot/operation/image fields; this is neither boot
        /// evidence nor sender authentication.
        public func matches(binding: StorageIdentity.StoreBinding) -> Bool {
            guard (try? validate()) != nil else { return false }
            return store == binding.storeID.rawValue && bytes == binding.backing.size &&
                ext4UUID == binding.expectedExt4UUID.rawValue &&
                inode == binding.backing.identity.inode && volumeUUID == binding.backing.identity.volumeUUID.rawValue
        }
        private enum CodingKeys: String, CodingKey {
            case version, store, bytes, device, inode
            case channelID = "channel_id", daemonUniqueID = "daemon_unique_id", rootPublicKey = "root_public_key"
            case shimLaunchUUID = "shim_launch_uuid", guestBootNonce = "guest_boot_nonce", operationUUID = "operation_uuid"
            case ext4UUID = "ext4_uuid", initramfsSHA256 = "initramfs_sha256", volumeUUID = "volume_uuid"
        }
    }

    public struct Challenge: Codable, Equatable, Sendable {
        public let version: String
        public let greeting: Greeting
        public let grant: Lifecycle.Grant
        public let shimAudit: Data
        public let shimUniqueID: UInt64
        public let daemonAudit: Data
        public let counter: UInt64
        public let nonce: Data
        public let expiresUnixMS: UInt64

        public init(greeting: Greeting, grant: Lifecycle.Grant, shimAudit: Data, shimUniqueID: UInt64,
                    daemonAudit: Data, counter: UInt64, nonce: Data, expiresUnixMS: UInt64) throws {
            version = StorageLifecycleFreshProtocol.version
            self.greeting = greeting; self.grant = grant; self.shimAudit = shimAudit
            self.shimUniqueID = shimUniqueID; self.daemonAudit = daemonAudit
            self.counter = counter; self.nonce = nonce; self.expiresUnixMS = expiresUnixMS
            try validate()
        }
        public func validate() throws {
            try greeting.validate(); try grant.validate()
            guard version == StorageLifecycleFreshProtocol.version, grant.operation == .initialize,
                  grant.identity.store == greeting.store, shimAudit.count == 32, daemonAudit.count == 32,
                  shimUniqueID > 0, shimUniqueID != greeting.daemonUniqueID,
                  counter > 0, nonce.count == 32, expiresUnixMS > 0 else { throw Lifecycle.ValidationError.invalidValue }
        }
        public func isFresh(at unixMS: UInt64) -> Bool {
            expiresUnixMS > unixMS && expiresUnixMS - unixMS <= StorageLifecycleFreshProtocol.lifetimeMS
        }
        public var digest: Data {
            get throws {
                try validate()
                return Data(SHA256.hash(data: Data("cengine.storage-fresh-lifecycle.challenge.v2\0".utf8) + (try Lifecycle.encode(self))))
            }
        }
        private enum CodingKeys: String, CodingKey {
            case version, greeting, grant, counter, nonce
            case shimAudit = "shim_audit", shimUniqueID = "shim_unique_id"
            case daemonAudit = "daemon_audit", expiresUnixMS = "expires_unix_ms"
        }
    }

    public struct Reply: Codable, Equatable, Sendable {
        public let version: String
        public let challengeSHA256: Data
        public init(challengeSHA256: Data) throws {
            version = StorageLifecycleFreshProtocol.version
            self.challengeSHA256 = challengeSHA256
            try validate()
        }
        public func validate() throws {
            guard version == StorageLifecycleFreshProtocol.version, challengeSHA256.count == 32 else {
                throw Lifecycle.ValidationError.invalidValue
            }
        }
        /// Correlation only, not sender authentication or a signed receipt.
        public func verifies(_ challenge: Challenge) throws -> Bool {
            try validate()
            return challengeSHA256 == (try challenge.digest)
        }
        private enum CodingKeys: String, CodingKey {
            case version, challengeSHA256 = "challenge_sha256"
        }
    }

    public static func decodeGreeting(_ bytes: Data) throws -> Greeting {
        let value = try Lifecycle.decode(Greeting.self, from: bytes)
        try value.validate(); return value
    }
    public static func decodeChallenge(_ bytes: Data) throws -> Challenge {
        let value = try Lifecycle.decode(Challenge.self, from: bytes)
        try value.validate(); return value
    }
    public static func decodeReply(_ bytes: Data) throws -> Reply {
        let value = try Lifecycle.decode(Reply.self, from: bytes)
        try value.validate(); return value
    }
}

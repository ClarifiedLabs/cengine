import CryptoKit
import Foundation

/// Direct service-shim provenance messages. These unsigned values alone are
/// NOT authority: ROOT must authenticate the native sender and independently pin
/// its full binding before adopting returned private-boot TLS trust.
public enum StorageLifecycleServiceProofProtocol {
    public static let version = "storage-service-proof.v2"
    public static let lifetimeMS: UInt64 = 30_000
    public typealias Lifecycle = StorageLifecycleProtocol
    public typealias Bootstrap = StorageIdentity

    public struct Greeting: Codable, Equatable, Sendable {
        public let version: String
        public let channelID: String
        public let daemonUniqueID: UInt64
        public let rootPublicKey: Data
        public let binding: StorageLifecycleStoreBinding
        public let bootBinding: DiskInitializationProtocol.Binding
        public let initramfsSHA256: String
        public let boot: StorageLifecycleBootTrust

        public init(channelID: String, daemonUniqueID: UInt64, rootPublicKey: Data,
                    binding: StorageLifecycleStoreBinding, bootBinding: DiskInitializationProtocol.Binding,
                    initramfsSHA256: String, boot: StorageLifecycleBootTrust) throws {
            version = StorageLifecycleServiceProofProtocol.version
            self.channelID = channelID; self.daemonUniqueID = daemonUniqueID
            self.rootPublicKey = rootPublicKey; self.binding = binding; self.bootBinding = bootBinding
            self.initramfsSHA256 = initramfsSHA256; self.boot = boot
            try validate()
        }
        public func validate() throws {
            try boot.validate()
            let fullBinding = try binding.value()
            let root = try StorageIdentity.RootPublicKey(publicData: rootPublicKey)
            _ = try StorageIdentity.IncarnationID(channelID)
            for uuid in [bootBinding.shimLaunchUUID, bootBinding.guestBootNonce, bootBinding.ext4UUID] {
                _ = try StorageIdentity.FilesystemUUID(uuid)
            }
            _ = try StorageIdentity.SPKISHA256(initramfsSHA256)
            guard version == StorageLifecycleServiceProofProtocol.version, daemonUniqueID > 0,
                  try Lifecycle.Identity(binding: fullBinding, generation: boot.identity.generation) == boot.identity,
                  bootBinding.ext4UUID == binding.ext4UUID, bootBinding.bytes == binding.bytes,
                  boot.bootstrapKey == root.fingerprint.rawValue else { throw Lifecycle.ValidationError.invalidValue }
        }
        private enum CodingKeys: String, CodingKey {
            case version, binding, boot
            case channelID = "channel_id", daemonUniqueID = "daemon_unique_id", rootPublicKey = "root_public_key"
            case bootBinding = "boot_binding", initramfsSHA256 = "initramfs_sha256"
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
            version = StorageLifecycleServiceProofProtocol.version
            self.greeting = greeting; self.grant = grant; self.shimAudit = shimAudit
            self.shimUniqueID = shimUniqueID; self.daemonAudit = daemonAudit
            self.counter = counter; self.nonce = nonce; self.expiresUnixMS = expiresUnixMS
            try validate()
        }
        public func validate() throws {
            try greeting.validate(); try grant.validate()
            guard version == StorageLifecycleServiceProofProtocol.version, grant.identity == greeting.boot.identity,
                  shimAudit.count == 32, daemonAudit.count == 32, shimUniqueID > 0,
                  shimUniqueID != greeting.daemonUniqueID, counter > 0, nonce.count == 32,
                  expiresUnixMS > 0 else { throw Lifecycle.ValidationError.invalidValue }
        }
        public func isFresh(at unixMS: UInt64) -> Bool {
            expiresUnixMS > unixMS && expiresUnixMS - unixMS <= StorageLifecycleServiceProofProtocol.lifetimeMS
        }
        public var digest: Data {
            get throws {
                try validate()
                return Data(SHA256.hash(data: Data("cengine.storage-service-proof.challenge.v2\0".utf8) + (try Lifecycle.encode(self))))
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
        public let boot: StorageLifecycleBootTrust

        public init(challengeSHA256: Data, boot: StorageLifecycleBootTrust) throws {
            version = StorageLifecycleServiceProofProtocol.version
            self.challengeSHA256 = challengeSHA256; self.boot = boot
            try validate()
        }
        public func validate() throws {
            try boot.validate()
            guard version == StorageLifecycleServiceProofProtocol.version, challengeSHA256.count == 32 else {
                throw Lifecycle.ValidationError.invalidValue
            }
        }
        /// Correlation only, not native sender authentication or a lifecycle receipt.
        public func verifies(_ challenge: Challenge) throws -> Bool {
            try validate()
            return challengeSHA256 == (try challenge.digest) && boot == challenge.greeting.boot
        }
        private enum CodingKeys: String, CodingKey {
            case version, boot, challengeSHA256 = "challenge_sha256"
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

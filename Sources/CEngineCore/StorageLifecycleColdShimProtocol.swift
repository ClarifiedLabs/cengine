import CryptoKit
import Foundation

/// Dedicated persistent mount-only channel. These messages do not
/// authenticate senders, prove old-process exit, or authorize a cold boot. Native
/// owners must pin both process tuples and the actual held disk FD independently.
public enum StorageLifecycleColdShimProtocol {
    public typealias Lifecycle = StorageLifecycleProtocol
    public typealias Bootstrap = StorageIdentity
    public typealias Cold = StorageLifecycleColdProtocol
    public typealias Adoption = StorageLifecycleAdoptionProtocol
    public static let version = "storage-lifecycle-cold-shim.v2"
    public static let lifetimeMS: UInt64 = 30_000

    /// Shared closed-wire mount channel purpose. Cold recovery and fresh-resume
    /// reuse the same native channel framing but never each other's epochs.
    public enum Purpose: String, Codable, Sendable {
        case cold, resumeReadOnly
    }

    public struct Greeting: Codable, Equatable, Sendable {
        public let version: String
        public let channelID: String
        /// Required on the closed wire; the public init default only preserves
        /// existing cold callers. Decoding never invents a missing purpose.
        public let purpose: Purpose
        public let daemonUniqueID: UInt64
        public let rootPublicKey: Data
        public let binding: StorageLifecycleStoreBinding
        /// Actual port-4105 mount greeting nonce, never a daemon-generated substitute.
        public let bootBinding: DiskInitializationProtocol.Binding
        public let launch: Cold.Launch
        public let heldBackingIdentity: StorageLifecycleStoreBinding.LiveFileIdentity

        public init(channelID: String, daemonUniqueID: UInt64, rootPublicKey: Data,
                    binding: StorageLifecycleStoreBinding, bootBinding: DiskInitializationProtocol.Binding,
                    launch: Cold.Launch, heldBackingIdentity: StorageLifecycleStoreBinding.LiveFileIdentity,
                    purpose: Purpose = .cold) throws {
            version = StorageLifecycleColdShimProtocol.version
            self.channelID = channelID; self.daemonUniqueID = daemonUniqueID; self.rootPublicKey = rootPublicKey
            self.binding = binding; self.bootBinding = bootBinding; self.launch = launch
            self.heldBackingIdentity = heldBackingIdentity; self.purpose = purpose
            try validate()
        }
        public func validate() throws {
            _ = try StorageIdentity.IncarnationID(channelID); _ = try StorageIdentity.RootPublicKey(publicData: rootPublicKey)
            _ = try binding.value(); _ = try heldBackingIdentity.value(); try launch.validate()
            _ = try StorageIdentity.IncarnationID(bootBinding.guestBootNonce)
            guard version == StorageLifecycleColdShimProtocol.version,
                  daemonUniqueID > 0, heldBackingIdentity.stableIdentity == binding.backing,
                  bootBinding.shimLaunchUUID == launch.shimLaunchUUID,
                  bootBinding.ext4UUID == launch.ext4UUID, bootBinding.bytes == launch.bytes,
                  launch.ext4UUID == binding.ext4UUID, launch.bytes == binding.bytes else {
                throw Lifecycle.ValidationError.invalidValue
            }
        }
        public var successorOrigin: Adoption.Origin {
            get throws {
                try validate()
                return try .init(binding: binding, rootPublicKey: rootPublicKey,
                                 shimLaunchUUID: launch.shimLaunchUUID, specSHA256: launch.specSHA256)
            }
        }
    }

    public struct Challenge: Codable, Equatable, Sendable {
        public let version: String
        public let greeting: Greeting
        public let prepareSHA256: String
        public let unsignedGrant: Lifecycle.Grant
        public let signedOpenSHA256: String
        public let baseEpoch: UInt64
        public let shimAudit: Data
        public let shimUniqueID: UInt64
        public let daemonAudit: Data
        public let daemonUniqueID: UInt64
        public let counter: UInt64
        public let nonce: Data
        public let expiresUnixMS: UInt64
        public init(greeting: Greeting, prepareSHA256: String, unsignedGrant: Lifecycle.Grant,
                    signedOpenSHA256: String, baseEpoch: UInt64, shimAudit: Data, shimUniqueID: UInt64,
                    daemonAudit: Data, daemonUniqueID: UInt64, counter: UInt64, nonce: Data, expiresUnixMS: UInt64) throws {
            version = StorageLifecycleColdShimProtocol.version
            self.greeting = greeting; self.prepareSHA256 = prepareSHA256; self.unsignedGrant = unsignedGrant
            self.signedOpenSHA256 = signedOpenSHA256; self.baseEpoch = baseEpoch
            self.shimAudit = shimAudit; self.shimUniqueID = shimUniqueID
            self.daemonAudit = daemonAudit; self.daemonUniqueID = daemonUniqueID
            self.counter = counter; self.nonce = nonce; self.expiresUnixMS = expiresUnixMS
            try validate()
        }
        public func validate() throws {
            try greeting.validate(); try unsignedGrant.validate()
            _ = try StorageIdentity.SPKISHA256(prepareSHA256); _ = try StorageIdentity.SPKISHA256(signedOpenSHA256)
            let baseEpochValid: Bool
            switch greeting.purpose {
            case .cold: baseEpochValid = baseEpoch > 1
            case .resumeReadOnly: baseEpochValid = baseEpoch == 1
            }
            guard version == StorageLifecycleColdShimProtocol.version, unsignedGrant.operation == .takeover,
                  try unsignedGrant.identity == Lifecycle.Identity(binding: greeting.binding.value(), generation: unsignedGrant.identity.generation),
                  baseEpochValid, shimAudit.count == 32, daemonAudit.count == 32, shimAudit != daemonAudit,
                  shimUniqueID > 0, daemonUniqueID == greeting.daemonUniqueID, shimUniqueID != daemonUniqueID,
                  counter > 0, nonce.count == 32, expiresUnixMS > 0 else { throw Lifecycle.ValidationError.invalidValue }
        }
        /// Exact retained prepare/authorization join; still not native authentication.
        public func validate(prepare: StorageLifecycleColdRootProtocol.Prepare,
                             prepared: StorageLifecycleColdRootProtocol.Prepared) throws {
            try validate(); try prepared.validate(for: prepare)
            guard greeting.purpose == .cold,
                  greeting == prepare.mountedGreeting, prepareSHA256 == (try prepare.digest),
                  unsignedGrant == prepared.signedOpen.request.takeover.grant,
                  signedOpenSHA256 == (try prepared.signedOpenSHA256), baseEpoch == prepared.baseEpoch else {
                throw StorageIdentity.ValidationError.correlationMismatch
            }
        }
        /// Fresh-resume join: the probe greeting must be a resume channel and the
        /// challenge must carry the fixed genesis base epoch.
        public func validate(prepare: StorageLifecycleResumeRootProtocol.Prepare,
                             prepared: StorageLifecycleResumeRootProtocol.Prepared) throws {
            try validate(); try prepared.validate(for: prepare)
            guard greeting.purpose == .resumeReadOnly,
                  greeting == prepare.probeGreeting, prepareSHA256 == (try prepare.digest),
                  unsignedGrant == prepared.signedOpen.request.takeover.grant,
                  signedOpenSHA256 == (try prepared.signedOpenSHA256), baseEpoch == prepared.baseEpoch else {
                throw StorageIdentity.ValidationError.correlationMismatch
            }
        }
        public func isFresh(at unixMS: UInt64) -> Bool {
            expiresUnixMS > unixMS && expiresUnixMS - unixMS <= StorageLifecycleColdShimProtocol.lifetimeMS
        }
        public var digest: Data {
            get throws { try validate(); return try StorageLifecycleColdShimProtocol.digest(self, domain: "challenge") }
        }
    }

    /// The actual held disk FD accompanies this reply out of band on the same
    /// native channel. A pathname, descriptor number or claimed exit bit is not proof.
    public struct Reply: Codable, Equatable, Sendable {
        public let challengeSHA256: Data
        public init(challengeSHA256: Data) throws { self.challengeSHA256 = challengeSHA256; try validate() }
        public func validate() throws {
            guard challengeSHA256.count == 32 else { throw Lifecycle.ValidationError.invalidValue }
        }
        public func verifies(_ challenge: Challenge) throws -> Bool {
            try validate(); return challengeSHA256 == (try challenge.digest)
        }
    }

    /// Sent only on the retained native channel after protected ROOT completion.
    /// This is an enrollment correlation, not a service result or authority token.
    public struct ColdEnrollmentSeed: Codable, Equatable, Sendable {
        public let operationID: String
        public let signedOpenSHA256: String
        public let successorOrigin: Adoption.Origin
        public let baseEpoch: UInt64
        /// Required on the closed wire; the public init default only preserves
        /// existing cold callers. Decoding never invents a missing purpose.
        public let purpose: Purpose
        public init(operationID: String, signedOpenSHA256: String, successorOrigin: Adoption.Origin,
                    baseEpoch: UInt64, purpose: Purpose = .cold) throws {
            self.operationID = operationID; self.signedOpenSHA256 = signedOpenSHA256
            self.successorOrigin = successorOrigin; self.baseEpoch = baseEpoch; self.purpose = purpose
            try validate()
        }
        public func validate() throws {
            _ = try StorageIdentity.GrantID(operationID); _ = try StorageIdentity.SPKISHA256(signedOpenSHA256)
            try successorOrigin.validate()
            switch purpose {
            case .cold: guard baseEpoch > 1 else { throw Lifecycle.ValidationError.invalidValue }
            case .resumeReadOnly: guard baseEpoch == 1 else { throw Lifecycle.ValidationError.invalidValue }
            }
        }
        public func validate(prepared: StorageLifecycleColdRootProtocol.Prepared) throws {
            try validate(); try prepared.validate()
            guard purpose == .cold,
                  operationID == prepared.signedOpen.request.operationID,
                  signedOpenSHA256 == (try prepared.signedOpenSHA256), successorOrigin == prepared.successorOrigin,
                  baseEpoch == prepared.baseEpoch else { throw StorageIdentity.ValidationError.correlationMismatch }
        }
        /// Fresh-resume enrollment correlation on the retained native channel.
        public func validate(prepared: StorageLifecycleResumeRootProtocol.Prepared) throws {
            try validate(); try prepared.validate()
            guard purpose == .resumeReadOnly,
                  operationID == prepared.signedOpen.request.operationID,
                  signedOpenSHA256 == (try prepared.signedOpenSHA256), successorOrigin == prepared.successorOrigin,
                  baseEpoch == prepared.baseEpoch else { throw StorageIdentity.ValidationError.correlationMismatch }
        }
        public var digest: Data {
            get throws { try validate(); return try StorageLifecycleColdShimProtocol.digest(self, domain: "enrollment") }
        }
    }
    public struct ColdEnrollmentAcknowledgement: Codable, Equatable, Sendable {
        public let seedSHA256: Data
        public init(for seed: ColdEnrollmentSeed) throws { seedSHA256 = try seed.digest }
        public func validate(for seed: ColdEnrollmentSeed) throws {
            guard seedSHA256 == (try seed.digest) else { throw StorageIdentity.ValidationError.correlationMismatch }
        }
    }

    private static func digest<T: Encodable>(_ value: T, domain: String) throws -> Data {
        Data(SHA256.hash(data: Data("cengine.storage-lifecycle-cold-shim.\(domain).v2\0".utf8) + (try Lifecycle.encode(value))))
    }
    public static func encode<T: Encodable>(_ value: T) throws -> Data { try Lifecycle.encode(value) }
    public static func decodeGreeting(_ bytes: Data) throws -> Greeting {
        let value = try Lifecycle.decode(Greeting.self, from: bytes); try value.validate(); return value
    }
    public static func decodeChallenge(_ bytes: Data) throws -> Challenge {
        let value = try Lifecycle.decode(Challenge.self, from: bytes); try value.validate(); return value
    }
    public static func decodeReply(_ bytes: Data, for challenge: Challenge) throws -> Reply {
        let value = try Lifecycle.decode(Reply.self, from: bytes)
        guard try value.verifies(challenge) else { throw StorageIdentity.ValidationError.correlationMismatch }; return value
    }
    public static func decodeEnrollmentSeed(_ bytes: Data) throws -> ColdEnrollmentSeed {
        let value = try Lifecycle.decode(ColdEnrollmentSeed.self, from: bytes); try value.validate(); return value
    }
    public static func decodeEnrollmentAcknowledgement(_ bytes: Data, for seed: ColdEnrollmentSeed) throws -> ColdEnrollmentAcknowledgement {
        let value = try Lifecycle.decode(ColdEnrollmentAcknowledgement.self, from: bytes); try value.validate(for: seed); return value
    }
}

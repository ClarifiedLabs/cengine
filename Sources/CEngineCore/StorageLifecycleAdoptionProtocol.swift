import CryptoKit
import Foundation

/// Reattachment messages correlate a direct authenticated exchange; none
/// is an authorization, native process proof, disk lock proof, or signed receipt.
public enum StorageLifecycleAdoptionProtocol {
    public static let version = "storage-lifecycle-adoption.v4"
    private typealias Lifecycle = StorageLifecycleProtocol

    public struct Origin: Codable, Equatable, Sendable {
        public let binding: StorageLifecycleStoreBinding
        public let rootPublicKey: Data
        public let shimLaunchUUID: String
        public let specSHA256: String

        public init(binding: StorageLifecycleStoreBinding, rootPublicKey: Data,
                    shimLaunchUUID: String, specSHA256: String) throws {
            self.binding = binding; self.rootPublicKey = rootPublicKey
            self.shimLaunchUUID = shimLaunchUUID; self.specSHA256 = specSHA256
            try validate()
        }
        public func validate() throws {
            _ = try binding.value(); _ = try StorageIdentity.RootPublicKey(publicData: rootPublicKey)
            _ = try StorageIdentity.IncarnationID(shimLaunchUUID); _ = try StorageIdentity.SPKISHA256(specSHA256)
        }
    }

    /// Exact immediately abandoned allocation, not a committed session or authority.
    /// No recursive request/history: ROOT retains native evidence for this one fence.
    public struct FenceIdentity: Codable, Equatable, Sendable {
        public let id: String
        public let epoch: UInt64
        public let nativeIdentitySHA256: Data

        public init(id: String, epoch: UInt64, nativeIdentitySHA256: Data) throws {
            self.id = id; self.epoch = epoch; self.nativeIdentitySHA256 = nativeIdentitySHA256
            try validate()
        }
        public func validate() throws {
            _ = try StorageIdentity.RequestID(id)
            guard epoch > 1, nativeIdentitySHA256.count == 32 else { throw Lifecycle.ValidationError.invalidValue }
        }
    }

    /// expectedEpoch is ROOT's allocated high-water mark, NOT the committed epoch.
    /// A native shim must accept a strictly greater ROOT-authorized allocation for
    /// the exact origin (even if it missed intervening prepares), or an exact retry
    /// of its current fence. It must never accept the same epoch for another fence.
    public struct Request: Codable, Equatable, Sendable {
        public let version: String
        public let id: String
        public let origin: Origin
        public let expectedEpoch: UInt64
        public let daemonAudit: Data
        public let daemonUniqueID: UInt64
        public let controllerAudit: Data
        public let controllerUniqueID: UInt64
        public let superseded: FenceIdentity?

        public init(id: String, origin: Origin, expectedEpoch: UInt64, daemonAudit: Data,
                    daemonUniqueID: UInt64, controllerAudit: Data, controllerUniqueID: UInt64,
                    superseded: FenceIdentity? = nil) throws {
            version = StorageLifecycleAdoptionProtocol.version; self.id = id; self.origin = origin
            self.expectedEpoch = expectedEpoch; self.daemonAudit = daemonAudit
            self.daemonUniqueID = daemonUniqueID; self.controllerAudit = controllerAudit
            self.controllerUniqueID = controllerUniqueID; self.superseded = superseded
            try validate()
        }
        public func validate() throws {
            try origin.validate(); _ = try StorageIdentity.RequestID(id)
            if let superseded {
                try superseded.validate()
                guard superseded.epoch == expectedEpoch, superseded.id != id,
                      superseded.nativeIdentitySHA256 != nativeIdentitySHA256 else { throw Lifecycle.ValidationError.invalidValue }
            }
            guard version == StorageLifecycleAdoptionProtocol.version, expectedEpoch > 0,
                  expectedEpoch < UInt64.max, daemonAudit.count == 32, controllerAudit.count == 32,
                  daemonUniqueID > 0, controllerUniqueID > 0, daemonUniqueID != controllerUniqueID,
                  daemonAudit != controllerAudit else { throw Lifecycle.ValidationError.invalidValue }
        }
        public var epoch: UInt64 {
            get throws { try validate(); return expectedEpoch + 1 }
        }
        public var nativeIdentitySHA256: Data {
            StorageLifecycleAdoptionProtocol.nativeIdentitySHA256(daemonAudit: daemonAudit,
                daemonUniqueID: daemonUniqueID, controllerAudit: controllerAudit, controllerUniqueID: controllerUniqueID)
        }
        public var fenceIdentity: FenceIdentity {
            get throws { try .init(id: id, epoch: epoch, nativeIdentitySHA256: nativeIdentitySHA256) }
        }
        private enum CodingKeys: String, CodingKey {
            case version, id, origin, expectedEpoch, daemonAudit, daemonUniqueID, controllerAudit, controllerUniqueID, superseded
        }
        public func encode(to encoder: any Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(version, forKey: .version); try c.encode(id, forKey: .id)
            try c.encode(origin, forKey: .origin); try c.encode(expectedEpoch, forKey: .expectedEpoch)
            try c.encode(daemonAudit, forKey: .daemonAudit); try c.encode(daemonUniqueID, forKey: .daemonUniqueID)
            try c.encode(controllerAudit, forKey: .controllerAudit); try c.encode(controllerUniqueID, forKey: .controllerUniqueID)
            // Required null when absent. Canonical decode rejects omitted keys.
            try c.encode(superseded, forKey: .superseded)
        }
    }

    public struct Challenge: Codable, Equatable, Sendable {
        public let request: Request
        public let nonce: Data
        public init(request: Request, nonce: Data) throws {
            self.request = request; self.nonce = nonce; try validate()
        }
        public func validate() throws {
            try request.validate()
            guard nonce.count == 32 else { throw Lifecycle.ValidationError.invalidValue }
        }
        public var digest: Data {
            get throws {
                try validate()
                return Data(SHA256.hash(data: Data("cengine.storage-lifecycle-adoption.challenge.v4\0".utf8) + (try Lifecycle.encode(self))))
            }
        }
    }

    /// Sent only after durable ROOT commit; never interchangeable with a fence.
    public struct Commit: Codable, Equatable, Sendable {
        public let request: Request
        public init(request: Request) throws { self.request = request; try validate() }
        public func validate() throws { try request.validate() }
        public var digest: Data {
            get throws {
                try validate()
                return Data(SHA256.hash(data: Data("cengine.storage-lifecycle-adoption.commit.v4\0".utf8) + (try Lifecycle.encode(self))))
            }
        }
    }

    public struct Reply: Codable, Equatable, Sendable {
        public let challengeSHA256: Data
        public init(challengeSHA256: Data) throws {
            self.challengeSHA256 = challengeSHA256; try validate()
        }
        public func validate() throws {
            guard challengeSHA256.count == 32 else { throw Lifecycle.ValidationError.invalidValue }
        }
    }

    /// Dedicated native registered-shim proof. The expected service is supplied
    /// only by ROOT's protected lifecycle journal, never by daemon metadata.
    public struct ServiceChallenge: Codable, Equatable, Sendable {
        public let adoption: Request
        public let grant: StorageLifecycleProtocol.Grant
        public let expected: StorageLifecycleProtocol.ServiceState
        public let counter: UInt64
        public let nonce: Data
        public let expiresUnixMS: UInt64
        public init(adoption: Request, grant: StorageLifecycleProtocol.Grant,
                    expected: StorageLifecycleProtocol.ServiceState, counter: UInt64,
                    nonce: Data, expiresUnixMS: UInt64) throws {
            self.adoption = adoption; self.grant = grant; self.expected = expected
            self.counter = counter; self.nonce = nonce; self.expiresUnixMS = expiresUnixMS
            try validate()
        }
        public func validate() throws {
            try adoption.validate(); try grant.validate(); try expected.validate()
            guard grant == expected.grant,
                  try grant.identity == StorageLifecycleProtocol.Identity(binding: adoption.origin.binding.value(), generation: grant.identity.generation),
                  try expected.boot.bootstrapKey == StorageIdentity.RootPublicKey(publicData: adoption.origin.rootPublicKey).fingerprint.rawValue,
                  counter > 0, nonce.count == 32, expiresUnixMS > 0 else { throw Lifecycle.ValidationError.invalidValue }
        }
        public func isFresh(at now: UInt64) -> Bool {
            expiresUnixMS > now && expiresUnixMS - now <= 30_000
        }
        public var digest: Data {
            get throws {
                try validate()
                return Data(SHA256.hash(data: Data("cengine.storage-adopted-service.v1\0".utf8) + (try Lifecycle.encode(self))))
            }
        }
    }
    public struct ServiceReply: Codable, Equatable, Sendable {
        public let challengeSHA256: Data
        public let result: StorageLifecycleProtocol.ServiceResult
        public let boot: StorageLifecycleBootTrust
        public init(challenge: ServiceChallenge, result: StorageLifecycleProtocol.ServiceResult,
                    boot: StorageLifecycleBootTrust) throws {
            challengeSHA256 = try challenge.digest; self.result = result; self.boot = boot
            try validate(challenge)
        }
        public func validate(_ challenge: ServiceChallenge) throws {
            try result.validate(); try boot.validate()
            guard challengeSHA256 == (try challenge.digest), result.nonce == challenge.nonce,
                  try result.state(boot: boot) == challenge.expected else { throw Lifecycle.ValidationError.invalidValue }
        }
    }
    public static func decodeServiceChallenge(_ bytes: Data) throws -> ServiceChallenge {
        let value = try Lifecycle.decode(ServiceChallenge.self, from: bytes); try value.validate(); return value
    }
    public static func decodeServiceReply(_ bytes: Data, challenge: ServiceChallenge) throws -> ServiceReply {
        let value = try Lifecycle.decode(ServiceReply.self, from: bytes); try value.validate(challenge); return value
    }

    /// Direct registered-shim proof of an adopted service change. Optional target
    /// and completion are ROOT's protected observations, never daemon assertions.
    public struct ServiceChangeChallenge: Codable, Equatable, Sendable {
        public let adoption: Request
        public let change: StorageLifecycleProtocol.ServiceChangeRequest
        public let targetBoot: StorageLifecycleBootTrust?
        public let completed: StorageLifecycleProtocol.ServiceChangeConfirmation?
        public let counter: UInt64
        public let nonce: Data
        public let expiresUnixMS: UInt64

        public init(adoption: Request, change: StorageLifecycleProtocol.ServiceChangeRequest,
                    targetBoot: StorageLifecycleBootTrust?, completed: StorageLifecycleProtocol.ServiceChangeConfirmation?,
                    counter: UInt64, nonce: Data, expiresUnixMS: UInt64) throws {
            self.adoption = adoption; self.change = change; self.targetBoot = targetBoot
            self.completed = completed; self.counter = counter; self.nonce = nonce
            self.expiresUnixMS = expiresUnixMS
            try validate()
        }
        public func validate() throws {
            try adoption.validate(); try change.validate()
            let predecessor = change.predecessor
            guard try predecessor.grant.identity == Lifecycle.Identity(binding: adoption.origin.binding.value(), generation: predecessor.grant.identity.generation),
                  try predecessor.boot.bootstrapKey == StorageIdentity.RootPublicKey(publicData: adoption.origin.rootPublicKey).fingerprint.rawValue,
                  counter > 0, nonce.count == 32, expiresUnixMS > 0 else { throw Lifecycle.ValidationError.invalidValue }
            if let targetBoot { try change.validateSuccessorBoot(targetBoot) }
            if let completed {
                try completed.validate()
                guard completed.request == change, targetBoot == completed.successor.boot else { throw Lifecycle.ValidationError.invalidValue }
            }
        }
        public func isFresh(at now: UInt64) -> Bool {
            expiresUnixMS > now && expiresUnixMS - now <= 30_000
        }
        public var digest: Data {
            get throws {
                try validate()
                return Data(SHA256.hash(data: Data("cengine.storage-adopted-service-change.v1\0".utf8) + (try Lifecycle.encode(self))))
            }
        }
        private enum CodingKeys: String, CodingKey {
            case adoption, change, targetBoot, completed, counter, nonce, expiresUnixMS
        }
        public func encode(to encoder: any Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(adoption, forKey: .adoption); try c.encode(change, forKey: .change)
            // Required null when absent; the canonical decoder rejects omitted keys.
            try c.encode(targetBoot, forKey: .targetBoot); try c.encode(completed, forKey: .completed)
            try c.encode(counter, forKey: .counter); try c.encode(nonce, forKey: .nonce)
            try c.encode(expiresUnixMS, forKey: .expiresUnixMS)
        }
    }
    public struct ServiceChangeReply: Codable, Equatable, Sendable {
        public let challengeSHA256: Data
        public let result: StorageLifecycleProtocol.ServiceResult
        public let boot: StorageLifecycleBootTrust
        public init(challenge: ServiceChangeChallenge, result: StorageLifecycleProtocol.ServiceResult,
                    boot: StorageLifecycleBootTrust) throws {
            challengeSHA256 = try challenge.digest; self.result = result; self.boot = boot
            try validate(challenge)
        }
        public func validate(_ challenge: ServiceChangeChallenge) throws {
            try result.validate(); try boot.validate()
            guard challengeSHA256 == (try challenge.digest), result.nonce == challenge.nonce else { throw Lifecycle.ValidationError.invalidValue }
            let state = try result.state(boot: boot)
            _ = try Lifecycle.ServiceChangeConfirmation(request: challenge.change, successor: state)
            if let target = challenge.targetBoot {
                guard boot == target else { throw Lifecycle.ValidationError.invalidValue }
            }
            if let completed = challenge.completed {
                guard state == completed.successor else { throw Lifecycle.ValidationError.invalidValue }
            }
        }
    }
    public static func decodeServiceChangeChallenge(_ bytes: Data) throws -> ServiceChangeChallenge {
        let value = try Lifecycle.decode(ServiceChangeChallenge.self, from: bytes); try value.validate(); return value
    }
    public static func decodeServiceChangeReply(_ bytes: Data, challenge: ServiceChangeChallenge) throws -> ServiceChangeReply {
        let value = try Lifecycle.decode(ServiceChangeReply.self, from: bytes); try value.validate(challenge); return value
    }

    /// Audit identity + kernel unique ID identify each native owner; ROOT validates
    /// these against the full process record before authorizing a fence.
    public static func nativeIdentitySHA256(daemonAudit: Data, daemonUniqueID: UInt64,
                                            controllerAudit: Data, controllerUniqueID: UInt64) -> Data {
        let daemonID = withUnsafeBytes(of: daemonUniqueID.bigEndian) { Data($0) }
        let controllerID = withUnsafeBytes(of: controllerUniqueID.bigEndian) { Data($0) }
        return Data(SHA256.hash(data: Data("cengine.storage-lifecycle-adoption.owners.v4\0".utf8)
            + daemonAudit + daemonID + controllerAudit + controllerID))
    }

    public static func encode<T: Encodable>(_ value: T) throws -> Data { try Lifecycle.encode(value) }
    public static func decodeOrigin(_ bytes: Data) throws -> Origin {
        let value = try Lifecycle.decode(Origin.self, from: bytes); try value.validate(); return value
    }
    public static func decodeCommit(_ bytes: Data) throws -> Commit {
        let value = try Lifecycle.decode(Commit.self, from: bytes); try value.validate(); return value
    }
    public static func decodeRequest(_ bytes: Data) throws -> Request {
        let value = try Lifecycle.decode(Request.self, from: bytes); try value.validate(); return value
    }
    public static func decodeChallenge(_ bytes: Data) throws -> Challenge {
        let value = try Lifecycle.decode(Challenge.self, from: bytes); try value.validate(); return value
    }
    public static func decodeReply(_ bytes: Data) throws -> Reply {
        let value = try Lifecycle.decode(Reply.self, from: bytes); try value.validate(); return value
    }
}

import CryptoKit
import Foundation

/// Direct-child proof messages. These values are not capabilities.
/// The transport must independently authenticate both message senders and keep
/// the exact child channel open. Daemon receipts and persisted values are not evidence.
public enum StorageLifecycleChildProtocol {
    public static let version = "storage-child-lifecycle.v2"
    public static let lifetimeMS: UInt64 = 30_000
    public typealias Lifecycle = StorageLifecycleProtocol
    public typealias Bootstrap = StorageIdentity
    public enum Purpose: String, Codable, Sendable { case candidate, result, serviceResult, serviceCommit }

    /// Sent on the child's direct authenticated ROOT channel before Guest E exists.
    /// The fresh child chooses channelID; reconnecting cannot reset its proof counter.
    public struct Greeting: Codable, Equatable, Sendable {
        public let version: String
        public let channelID: String
        public let incarnationID: String
        public let daemonUniqueID: UInt64
        public let controllerSPKI: Data
        public let rootPublicKey: Data
        public let store: String
        public let binding: String
        public let expectedEpoch: UInt64

        public init(channelID: String, incarnationID: String, daemonUniqueID: UInt64,
                    controllerSPKI: Data, rootPublicKey: Data, store: String,
                    binding: String, expectedEpoch: UInt64) throws {
            version = StorageLifecycleChildProtocol.version
            self.channelID = channelID; self.incarnationID = incarnationID
            self.daemonUniqueID = daemonUniqueID; self.controllerSPKI = controllerSPKI
            self.rootPublicKey = rootPublicKey; self.store = store
            self.binding = binding; self.expectedEpoch = expectedEpoch
            try validate()
        }
        public func validate() throws {
            guard version == StorageLifecycleChildProtocol.version, daemonUniqueID > 0,
                  expectedEpoch < UInt64.max else { throw Lifecycle.ValidationError.invalidValue }
            _ = try StorageIdentity.IncarnationID(channelID)
            _ = try StorageIdentity.IncarnationID(incarnationID)
            _ = try StorageIdentity.StoreID(store)
            _ = try StorageIdentity.SPKISHA256(binding)
            let key = try StorageIdentity.Ed25519SPKI(publicData: controllerSPKI)
            let root = try StorageIdentity.RootPublicKey(publicData: rootPublicKey)
            guard key.fingerprint != root.fingerprint else { throw Lifecycle.ValidationError.invalidValue }
        }
        public func matches(_ grant: Lifecycle.Grant) throws -> Bool {
            try validate(); try grant.validate()
            let key = try StorageIdentity.Ed25519SPKI(publicData: controllerSPKI)
            return grant.identity.store == store && grant.identity.binding == binding &&
                grant.newKey == key.fingerprint.rawValue &&
                grant.expectedEpoch == (grant.operation == .retire ? expectedEpoch + 1 : expectedEpoch)
        }
        private enum CodingKeys: String, CodingKey {
            case version, store, binding
            case channelID = "channel_id", incarnationID = "incarnation_id"
            case daemonUniqueID = "daemon_unique_id", controllerSPKI = "controller_spki"
            case rootPublicKey = "root_public_key", expectedEpoch = "expected_epoch"
        }
    }

    /// Full ROOT grant, fresh ROOT nonce and ordered channel-local counter. The
    /// counter replaces v1's lifetime nonce set, not ROOT's persistent grant serial.
    public struct Challenge: Codable, Equatable, Sendable {
        public let version: String
        public let greeting: Greeting
        public let grant: Lifecycle.Grant
        public let childAudit: Data
        public let childUniqueID: UInt64
        public let daemonAudit: Data
        public let counter: UInt64
        public let nonce: Data
        public let purpose: Purpose
        public let boot: StorageLifecycleBootTrust?
        public let changeRequest: Lifecycle.ServiceChangeRequest?
        public let confirmation: Lifecycle.ServiceChangeConfirmation?
        public let expiresUnixMS: UInt64

        public init(greeting: Greeting, grant: Lifecycle.Grant, childAudit: Data,
                    childUniqueID: UInt64, daemonAudit: Data, counter: UInt64,
                    nonce: Data, purpose: Purpose, expiresUnixMS: UInt64,
                    boot: StorageLifecycleBootTrust? = nil,
                    changeRequest: Lifecycle.ServiceChangeRequest? = nil,
                    confirmation: Lifecycle.ServiceChangeConfirmation? = nil) throws {
            version = StorageLifecycleChildProtocol.version
            self.greeting = greeting; self.grant = grant; self.childAudit = childAudit
            self.childUniqueID = childUniqueID; self.daemonAudit = daemonAudit
            self.counter = counter; self.nonce = nonce; self.purpose = purpose
            self.expiresUnixMS = expiresUnixMS; self.boot = boot
            self.changeRequest = changeRequest; self.confirmation = confirmation
            try validate()
        }
        public func validate() throws {
            guard version == StorageLifecycleChildProtocol.version,
                  try greeting.matches(grant), childAudit.count == 32, daemonAudit.count == 32,
                  childUniqueID > 0, childUniqueID != greeting.daemonUniqueID,
                  counter > 0, nonce.count == 32, expiresUnixMS > 0 else {
                throw Lifecycle.ValidationError.invalidValue
            }
            switch purpose {
            case .candidate:
                guard boot == nil, changeRequest == nil, confirmation == nil else { throw Lifecycle.ValidationError.invalidValue }
            case .result, .serviceResult, .serviceCommit:
                guard let boot else { throw Lifecycle.ValidationError.invalidValue }
                try boot.validate()
                let root = try StorageIdentity.RootPublicKey(publicData: greeting.rootPublicKey)
                guard boot.identity == grant.identity, boot.bootstrapKey == root.fingerprint.rawValue else {
                    throw Lifecycle.ValidationError.invalidValue
                }
                switch purpose {
                case .result:
                    guard changeRequest == nil, confirmation == nil else { throw Lifecycle.ValidationError.invalidValue }
                case .serviceResult:
                    guard grant.operation != .retire, confirmation == nil else { throw Lifecycle.ValidationError.invalidValue }
                    if let changeRequest {
                        try changeRequest.validateSuccessorBoot(boot)
                        guard changeRequest.predecessor.grant == grant else { throw Lifecycle.ValidationError.invalidValue }
                    }
                case .serviceCommit:
                    guard changeRequest == nil, let confirmation else { throw Lifecycle.ValidationError.invalidValue }
                    try confirmation.validate()
                    guard confirmation.successor.grant == grant, confirmation.successor.boot == boot else {
                        throw Lifecycle.ValidationError.invalidValue
                    }
                case .candidate: throw Lifecycle.ValidationError.invalidValue
                }
            }
        }
        public func isFresh(at unixMS: UInt64) -> Bool {
            expiresUnixMS > unixMS && expiresUnixMS - unixMS <= StorageLifecycleChildProtocol.lifetimeMS
        }
        public var digest: Data {
            get throws {
                try validate()
                return Data(SHA256.hash(data: Data("cengine.storage-child-lifecycle.challenge.v2\0".utf8) + (try Lifecycle.encode(self))))
            }
        }
        private enum CodingKeys: String, CodingKey {
            case version, greeting, grant, counter, nonce, purpose, boot
            case childAudit = "child_audit", childUniqueID = "child_unique_id"
            case daemonAudit = "daemon_audit", expiresUnixMS = "expires_unix_ms"
            case changeRequest = "change_request", confirmation
        }
    }

    /// Signature binds a complete fresh challenge AND (only for result) the typed
    /// TLS result. Signing a Receipt alone is insufficient to authenticate a process.
    public struct Reply: Codable, Equatable, Sendable {
        public let version: String
        public let challengeSHA256: Data
        public let receipt: Lifecycle.Receipt?
        public let serviceResult: Lifecycle.ServiceResult?
        public let signature: Data

        public init(challengeSHA256: Data, receipt: Lifecycle.Receipt?, signature: Data,
                    serviceResult: Lifecycle.ServiceResult? = nil) throws {
            version = StorageLifecycleChildProtocol.version
            self.challengeSHA256 = challengeSHA256; self.receipt = receipt; self.signature = signature
            self.serviceResult = serviceResult
            try validate()
        }
        public func validate() throws {
            guard version == StorageLifecycleChildProtocol.version,
                  challengeSHA256.count == 32, signature.count == 64 else {
                throw Lifecycle.ValidationError.invalidValue
            }
            guard receipt == nil || serviceResult == nil else { throw Lifecycle.ValidationError.invalidValue }
            try receipt?.validate(); try serviceResult?.validate()
        }
        public var signingBytes: Data {
            Data("cengine.storage-child-lifecycle.reply.v2\0".utf8) + challengeSHA256 +
                (serviceResult.map { Data("service-result\0".utf8) + $0.signingBytes } ??
                 receipt.map { Data("result\0".utf8) + $0.signingBytes } ?? Data("candidate\0".utf8))
        }
        public func verifies(_ challenge: Challenge) throws -> Bool {
            try validate(); try challenge.validate()
            guard challengeSHA256 == (try challenge.digest) else { return false }
            switch challenge.purpose {
            case .candidate: guard receipt == nil, serviceResult == nil else { return false }
            case .result:
                guard serviceResult == nil, let receipt, receipt.grant == challenge.grant, receipt.nonce == challenge.nonce,
                      receipt.serviceEpoch == challenge.boot?.serviceEpoch else { return false }
            case .serviceResult, .serviceCommit:
                guard receipt == nil, let serviceResult, let boot = challenge.boot,
                      serviceResult.grant == challenge.grant, serviceResult.nonce == challenge.nonce,
                      serviceResult.serviceEpoch == boot.serviceEpoch else { return false }
                let state = try serviceResult.state(boot: boot)
                if let change = challenge.changeRequest {
                    _ = try Lifecycle.ServiceChangeConfirmation(request: change, successor: state)
                }
                if let confirmation = challenge.confirmation, confirmation.successor != state { return false }
            }
            let key = try Curve25519.Signing.PublicKey(rawRepresentation: Data(challenge.greeting.controllerSPKI.suffix(32)))
            return key.isValidSignature(signature, for: signingBytes)
        }
        private enum CodingKeys: String, CodingKey {
            case version, receipt, signature
            case challengeSHA256 = "challenge_sha256", serviceResult = "service_result"
        }
    }

    /// Pre-grant identity only: no grant, boot, receipt, or ownership transition.
    public static let identityVersion = "storage-child-identity.v1"
    public struct IdentityChallenge: Codable, Equatable, Sendable {
        public let version: String
        public let greeting: Greeting
        public let childAudit: Data
        public let childUniqueID: UInt64
        public let daemonAudit: Data
        public let counter: UInt64
        public let nonce: Data
        public let requestSHA256: Data
        public let expiresUnixMS: UInt64
        public init(greeting: Greeting, childAudit: Data, childUniqueID: UInt64,
                    daemonAudit: Data, counter: UInt64, nonce: Data, requestSHA256: Data,
                    expiresUnixMS: UInt64) throws {
            version = StorageLifecycleChildProtocol.identityVersion
            self.greeting = greeting; self.childAudit = childAudit; self.childUniqueID = childUniqueID
            self.daemonAudit = daemonAudit; self.counter = counter; self.nonce = nonce
            self.requestSHA256 = requestSHA256; self.expiresUnixMS = expiresUnixMS
            try validate()
        }
        public func validate() throws {
            try greeting.validate()
            guard version == StorageLifecycleChildProtocol.identityVersion,
                  childAudit.count == 32, daemonAudit.count == 32, childAudit != daemonAudit,
                  childUniqueID > 0, childUniqueID != greeting.daemonUniqueID,
                  counter > 0, nonce.count == 32, requestSHA256.count == 32, expiresUnixMS > 0 else {
                throw Lifecycle.ValidationError.invalidValue
            }
        }
        public func isFresh(at unixMS: UInt64) -> Bool {
            expiresUnixMS > unixMS && expiresUnixMS - unixMS <= StorageLifecycleChildProtocol.lifetimeMS
        }
        public var digest: Data {
            get throws {
                try validate()
                return Data(SHA256.hash(data: Data("cengine.storage-child-identity.challenge.v1\0".utf8) + (try Lifecycle.encode(self))))
            }
        }
        private enum CodingKeys: String, CodingKey {
            case version, greeting, counter, nonce
            case childAudit = "child_audit", childUniqueID = "child_unique_id"
            case daemonAudit = "daemon_audit", expiresUnixMS = "expires_unix_ms", requestSHA256 = "request_sha256"
        }
    }
    public struct IdentityReply: Codable, Equatable, Sendable {
        public let version: String
        public let challengeSHA256: Data
        public let signature: Data
        public init(challengeSHA256: Data, signature: Data) throws {
            version = StorageLifecycleChildProtocol.identityVersion
            self.challengeSHA256 = challengeSHA256; self.signature = signature
            try validate()
        }
        public func validate() throws {
            guard version == StorageLifecycleChildProtocol.identityVersion,
                  challengeSHA256.count == 32, signature.count == 64 else { throw Lifecycle.ValidationError.invalidValue }
        }
        public var signingBytes: Data {
            Data("cengine.storage-child-identity.reply.v1\0".utf8) + challengeSHA256
        }
        public func verifies(_ challenge: IdentityChallenge) throws -> Bool {
            try validate(); try challenge.validate()
            guard challengeSHA256 == (try challenge.digest) else { return false }
            let key = try Curve25519.Signing.PublicKey(rawRepresentation: Data(challenge.greeting.controllerSPKI.suffix(32)))
            return key.isValidSignature(signature, for: signingBytes)
        }
        private enum CodingKeys: String, CodingKey {
            case version, signature, challengeSHA256 = "challenge_sha256"
        }
    }
    public static func adoptionRequestDigest(_ request: StorageLifecycleAdoptionProtocol.Request) throws -> Data {
        try request.validate()
        return Data(SHA256.hash(data: Data("cengine.storage-child-identity.adoption-request.v1\0".utf8) + (try Lifecycle.encode(request))))
    }
    public static func decodeIdentityChallenge(_ bytes: Data) throws -> IdentityChallenge {
        let value = try Lifecycle.decode(IdentityChallenge.self, from: bytes)
        try value.validate(); return value
    }
    public static func decodeIdentityReply(_ bytes: Data) throws -> IdentityReply {
        let value = try Lifecycle.decode(IdentityReply.self, from: bytes)
        try value.validate(); return value
    }

    // Codable is DTO-only. Every trust seam must use these validated closed decoders.
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

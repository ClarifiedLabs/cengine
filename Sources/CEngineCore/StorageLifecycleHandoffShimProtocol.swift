import CryptoKit
import Foundation

/// Fresh registered-shim proof, deliberately independent of a newly adopted
/// child. Native ROOT/shim authentication and held-disk checks remain mandatory.
public enum StorageLifecycleHandoffShimProtocol {
    public typealias L = StorageLifecycleProtocol
    public typealias H = StorageLifecycleHandoffProtocol
    public static let operation = "storage-lifecycle-handoff"

    public struct Challenge: Codable, Equatable, Sendable {
        public let origin: StorageLifecycleAdoptionProtocol.Origin
        public let signed: H.SignedRequest
        public let expected: L.ServiceState
        public let counter: UInt64
        public let nonce: Data
        public let expiresUnixMS: UInt64
        public init(origin: StorageLifecycleAdoptionProtocol.Origin, signed: H.SignedRequest,
                    expected: L.ServiceState, counter: UInt64, nonce: Data, expiresUnixMS: UInt64) throws {
            self.origin = origin; self.signed = signed; self.expected = expected
            self.counter = counter; self.nonce = nonce; self.expiresUnixMS = expiresUnixMS
            try validate()
        }
        public func validate() throws {
            try origin.validate(); try signed.validate(); try expected.validate()
            let r = signed.request
            let root = try StorageIdentity.RootPublicKey(publicData: origin.rootPublicKey)
            guard signed.isValidSignature(using: root), r.predecessor == expected.grant,
                  r.serviceEpoch == expected.context.serviceEpoch, r.openRevision == expected.openRevision,
                  try r.predecessor.identity == L.Identity(binding: origin.binding.value(), generation: r.predecessor.identity.generation),
                  expected.boot.bootstrapKey == root.fingerprint.rawValue,
                  counter > 0, nonce.count == 32, expiresUnixMS > 0 else { throw L.ValidationError.invalidValue }
        }
        public func isFresh(at now: UInt64) -> Bool { expiresUnixMS > now && expiresUnixMS - now <= 30_000 }
        public var digest: Data {
            get throws {
                try validate()
                return Data(SHA256.hash(data: Data("cengine.storage-lifecycle-handoff-shim.v1\0".utf8) + (try L.encode(self))))
            }
        }
    }

    public struct Reply: Codable, Equatable, Sendable {
        public let challengeSHA256: Data
        public let result: H.Result
        public let boot: StorageLifecycleBootTrust
        public init(challenge: Challenge, result: H.Result, boot: StorageLifecycleBootTrust) throws {
            challengeSHA256 = try challenge.digest; self.result = result; self.boot = boot
            try validate(challenge)
        }
        public func validate(_ challenge: Challenge) throws {
            try challenge.validate(); try result.validate(); try boot.validate()
            guard challengeSHA256 == (try challenge.digest), result.request == challenge.signed.request,
                  result.nonce == challenge.nonce, boot == challenge.expected.boot else { throw L.ValidationError.invalidValue }
        }
    }
    public static func encode<T: Encodable>(_ value: T) throws -> Data { try L.encode(value) }
    public static func decodeChallenge(_ bytes: Data) throws -> Challenge {
        let value = try L.decode(Challenge.self, from: bytes); try value.validate(); return value
    }
    public static func decodeReply(_ bytes: Data, challenge: Challenge) throws -> Reply {
        let value = try L.decode(Reply.self, from: bytes); try value.validate(challenge); return value
    }
}

import CryptoKit
import Foundation

/// ROOT authorization for a previously witnessed, unused initialization only.
/// No predecessor service epoch is invented. The Guest must admit either the
/// closed empty layout or the exact original genesis registry before mutation.
/// This value is not proof of process exit, a safe mount, or a live successor.
public enum StorageLifecycleResumeProtocol {
    public typealias L = StorageLifecycleProtocol
    public typealias Launch = StorageLifecycleColdProtocol.Launch

    public struct Request: Codable, Equatable, Sendable {
        public let operationID: String
        public let original: L.Grant
        public let takeover: L.SignedGrant
        public let launch: Launch
        public let nowUnixSeconds: UInt64
        public let lifetimeSeconds: UInt64

        public init(operationID: String, original: L.Grant, takeover: L.SignedGrant, launch: Launch,
                    nowUnixSeconds: UInt64, lifetimeSeconds: UInt64) throws {
            self.operationID = operationID; self.original = original; self.takeover = takeover
            self.launch = launch; self.nowUnixSeconds = nowUnixSeconds; self.lifetimeSeconds = lifetimeSeconds
            try validate()
        }
        public func validate() throws {
            try original.validate(); try takeover.validate(); try launch.validate()
            let g = takeover.grant
            guard original.operation == .initialize, original.expectedEpoch == 0,
                  operationID == g.id, g.operation == .takeover, g.expectedEpoch == 1,
                  g.identity == original.identity, g.serial > original.serial,
                  g.id != original.id, g.newKey != original.newKey,
                  nowUnixSeconds > 0, nowUnixSeconds <= 253_402_300_799,
                  lifetimeSeconds > 0, lifetimeSeconds <= 86_400,
                  lifetimeSeconds <= 253_402_300_799 - nowUnixSeconds else {
                throw L.ValidationError.invalidValue
            }
        }
        enum CodingKeys: String, CodingKey {
            case operationID = "operation_id", original, takeover, launch
            case nowUnixSeconds = "now_unix_seconds", lifetimeSeconds = "lifetime_seconds"
        }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            try self.init(operationID: c.decode(String.self, forKey: .operationID),
                original: c.decode(L.Grant.self, forKey: .original), takeover: c.decode(L.SignedGrant.self, forKey: .takeover),
                launch: c.decode(Launch.self, forKey: .launch), nowUnixSeconds: c.decode(UInt64.self, forKey: .nowUnixSeconds),
                lifetimeSeconds: c.decode(UInt64.self, forKey: .lifetimeSeconds))
        }
        /// Exact Go declaration order, distinct from canonical sorted transport JSON.
        public var signingBytes: Data {
            let signed = "{\"grant\":\(takeover.grant.signingJSON),\"signature\":\"\(takeover.signature.base64EncodedString())\"}"
            let l = launch
            let launchJSON = "{\"shim_launch_uuid\":\"\(l.shimLaunchUUID)\",\"spec_sha256\":\"\(l.specSHA256)\",\"initramfs_sha256\":\"\(l.initramfsSHA256)\",\"ext4_uuid\":\"\(l.ext4UUID)\",\"bytes\":\(l.bytes)}"
            let json = "{\"operation_id\":\"\(operationID)\",\"original\":\(original.signingJSON),\"takeover\":\(signed),\"launch\":\(launchJSON),\"now_unix_seconds\":\(nowUnixSeconds),\"lifetime_seconds\":\(lifetimeSeconds)}"
            return Data(("cengine.storageauthority.lifecycle-resume-open.v1\0" + json).utf8)
        }
        public var digest: String { SHA256.hash(data: signingBytes).map { String(format: "%02x", $0) }.joined() }
    }

    public struct SignedOpen: Codable, Equatable, Sendable {
        // Keep nested boot frames bounded on Swift cooperative-thread stacks.
        private final class Value: Sendable {
            let request: Request
            let signature: Data
            init(request: Request, signature: Data) { self.request = request; self.signature = signature }
        }
        private let value: Value
        public var request: Request { value.request }
        public var signature: Data { value.signature }
        public init(request: Request, signature: Data) throws {
            value = Value(request: request, signature: signature)
            try validate()
        }
        public static func == (lhs: Self, rhs: Self) -> Bool {
            lhs.request == rhs.request && lhs.signature == rhs.signature
        }
        public func validate() throws {
            try request.validate()
            guard signature.count == 64 else { throw L.ValidationError.invalidSignature }
        }
        public func isValidSignature(using root: StorageIdentity.RootPublicKey) -> Bool {
            guard (try? validate()) != nil,
                  root.fingerprint.rawValue != request.original.newKey,
                  root.fingerprint.rawValue != request.takeover.grant.newKey,
                  request.takeover.isValidSignature(using: root),
                  let key = try? Curve25519.Signing.PublicKey(rawRepresentation: root.publicData) else { return false }
            return key.isValidSignature(signature, for: request.signingBytes)
        }
        enum CodingKeys: String, CodingKey { case request, signature }
        public func encode(to encoder: any Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(request, forKey: .request); try c.encode(signature, forKey: .signature)
        }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            try self.init(request: c.decode(Request.self, forKey: .request), signature: c.decode(Data.self, forKey: .signature))
        }
    }

    public static func decode(_ bytes: Data) throws -> SignedOpen {
        let value = try L.decode(SignedOpen.self, from: bytes)
        try value.validate(); return value
    }
}

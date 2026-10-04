import CryptoKit
import Foundation

/// Value-only authorization to fence an abandoned live takeover and observe its
/// outcome. This neither applies a takeover nor authorizes a cold open, and is not
/// hot recovery of an installed old pair. Codable validates values; encode/decode
/// enforce the closed canonical wire. No routing or peer authentication lives here.
public enum StorageLifecycleHandoffProtocol {
    public typealias L = StorageLifecycleProtocol

    public struct Request: Codable, Equatable, Sendable {
        public let operationID: String
        public let predecessor: L.Grant
        public let pending: L.Grant
        public let serviceEpoch: String
        public let openRevision: UInt64

        public init(operationID: String, predecessor: L.Grant, pending: L.Grant,
                    serviceEpoch: String, openRevision: UInt64) throws {
            self.operationID = operationID; self.predecessor = predecessor; self.pending = pending
            self.serviceEpoch = serviceEpoch; self.openRevision = openRevision
            try validate()
        }
        public func validate() throws {
            try predecessor.validate(); try pending.validate()
            _ = try StorageIdentity.GrantID(operationID)
            _ = try StorageIdentity.IncarnationID(serviceEpoch)
            guard operationID != predecessor.id, operationID != pending.id,
                  predecessor.operation != .retire, predecessor.expectedEpoch < UInt64.max,
                  pending.operation == .takeover, pending.identity == predecessor.identity,
                  pending.expectedEpoch == predecessor.expectedEpoch + 1, pending.serial > predecessor.serial,
                  pending.id != predecessor.id, pending.newKey != predecessor.newKey,
                  openRevision > 0 else { throw L.ValidationError.invalidValue }
        }
        private enum CodingKeys: String, CodingKey {
            case operationID = "operation_id", predecessor, pending
            case serviceEpoch = "service_epoch", openRevision = "open_revision"
        }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            try self.init(operationID: c.decode(String.self, forKey: .operationID),
                predecessor: c.decode(L.Grant.self, forKey: .predecessor), pending: c.decode(L.Grant.self, forKey: .pending),
                serviceEpoch: c.decode(String.self, forKey: .serviceEpoch), openRevision: c.decode(UInt64.self, forKey: .openRevision))
        }
        fileprivate var signingJSON: String {
            "{\"operation_id\":\"\(operationID)\",\"predecessor\":\(predecessor.signingJSON),\"pending\":\(pending.signingJSON),\"service_epoch\":\"\(serviceEpoch)\",\"open_revision\":\(openRevision)}"
        }
        /// Exact Go declaration order, not sorted transport JSON.
        public var signingBytes: Data {
            Data(("cengine.storageauthority.lifecycle-handoff.v1\0" + signingJSON).utf8)
        }
    }

    /// A verified ROOT signature is authorization only, not an authenticated peer
    /// or evidence that the pending grant applied or was fenced.
    public struct SignedRequest: Codable, Equatable, Sendable {
        public let request: Request
        public let signature: Data
        public init(request: Request, signature: Data) throws {
            self.request = request; self.signature = signature
            try validate()
        }
        public func validate() throws {
            try request.validate()
            guard signature.count == 64 else { throw L.ValidationError.invalidSignature }
        }
        public func isValidSignature(using root: StorageIdentity.RootPublicKey) -> Bool {
            guard let key = try? Curve25519.Signing.PublicKey(rawRepresentation: root.publicData) else { return false }
            return key.isValidSignature(signature, for: request.signingBytes)
        }
        private enum CodingKeys: String, CodingKey { case request, signature }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            try self.init(request: c.decode(Request.self, forKey: .request), signature: c.decode(Data.self, forKey: .signature))
        }
    }

    /// DTO only: requires a freshly authenticated private Guest channel and ROOT
    /// challenge correlation. A HOST-supplied value proves nothing.
    public struct Result: Codable, Equatable, Sendable {
        public let request: Request
        public let nonce: Data
        public let appliedGrant: L.Grant
        public let appliedServiceEpoch: String
        /// Immutable original grant receipt, not the mutable query/fence revision.
        public let appliedRevision: UInt64
        public let fenceRevision: UInt64

        public init(request: Request, nonce: Data, appliedGrant: L.Grant, appliedServiceEpoch: String,
                    appliedRevision: UInt64, fenceRevision: UInt64) throws {
            self.request = request; self.nonce = nonce; self.appliedGrant = appliedGrant
            self.appliedServiceEpoch = appliedServiceEpoch; self.appliedRevision = appliedRevision
            self.fenceRevision = fenceRevision
            try validate()
        }
        public func validate() throws {
            try request.validate()
            _ = try StorageIdentity.IncarnationID(appliedServiceEpoch)
            guard nonce.count == 32, appliedGrant == request.predecessor || appliedGrant == request.pending,
                  appliedRevision > 0, appliedRevision < fenceRevision, request.openRevision < fenceRevision,
                  appliedGrant != request.pending || (appliedServiceEpoch == request.serviceEpoch && appliedRevision > request.openRevision)
            else { throw L.ValidationError.invalidValue }
        }
        private enum CodingKeys: String, CodingKey {
            case request, nonce, appliedGrant = "applied_grant", appliedServiceEpoch = "applied_service_epoch"
            case appliedRevision = "applied_revision", fenceRevision = "fence_revision"
        }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            try self.init(request: c.decode(Request.self, forKey: .request), nonce: c.decode(Data.self, forKey: .nonce),
                appliedGrant: c.decode(L.Grant.self, forKey: .appliedGrant), appliedServiceEpoch: c.decode(String.self, forKey: .appliedServiceEpoch),
                appliedRevision: c.decode(UInt64.self, forKey: .appliedRevision), fenceRevision: c.decode(UInt64.self, forKey: .fenceRevision))
        }
        /// Exact Go declaration order, including canonical padded base64.
        public var signingBytes: Data {
            let json = "{\"request\":\(request.signingJSON),\"nonce\":\"\(nonce.base64EncodedString())\",\"applied_grant\":\(appliedGrant.signingJSON),\"applied_service_epoch\":\"\(appliedServiceEpoch)\",\"applied_revision\":\(appliedRevision),\"fence_revision\":\(fenceRevision)}"
            return Data(("cengine.storageauthority.lifecycle-handoff-result.v1\0" + json).utf8)
        }
    }

    /// Closed canonical transport uses sorted keys, unlike the signing wire.
    public static func encode<T: Encodable>(_ value: T) throws -> Data { try L.encode(value) }
    public static func decode<T: Decodable & Encodable>(_ type: T.Type, from data: Data) throws -> T {
        try L.decode(type, from: data)
    }
}

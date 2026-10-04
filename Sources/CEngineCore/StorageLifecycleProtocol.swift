import CryptoKit
import Foundation

/// Storage lifecycle values and wire encoding. Routing, guest state changes,
/// writer leases, reattachment and authentication belong to the callers.
/// Call encode/decode for the closed canonical wire; Codable alone validates values.
public enum StorageLifecycleProtocol {
    public static let version = "storage-lifecycle.v2"
    public static let maximumPayloadBytes = 64 * 1024
    public typealias Bootstrap = StorageIdentity

    public enum ValidationError: Error, Equatable, Sendable {
        case invalidValue, invalidSignature, invalidMessage, payloadTooLarge
    }

    public enum Operation: String, Codable, Sendable {
        case initialize, takeover, retire
    }

    public struct Identity: Codable, Equatable, Sendable {
        public let store: String
        public let generation: UInt64
        /// SHA-256 lowercase hex of the domain-separated, full host StoreBinding.
        public let binding: String

        public init(store: String, generation: UInt64, binding: String) throws {
            self.store = store; self.generation = generation; self.binding = binding
            try validate()
        }

        public init(binding: StorageIdentity.StoreBinding, generation: UInt64) throws {
            try self.init(store: binding.storeID.rawValue, generation: generation,
                          binding: StorageLifecycleProtocol.bindingDigest(binding))
        }

        public func validate() throws {
            guard (try? StorageIdentity.StoreID(store)) != nil, generation > 0,
                  (try? StorageIdentity.SPKISHA256(binding)) != nil else { throw ValidationError.invalidValue }
        }

        private enum CodingKeys: String, CodingKey { case store, generation, binding }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            try self.init(store: c.decode(String.self, forKey: .store),
                          generation: c.decode(UInt64.self, forKey: .generation),
                          binding: c.decode(String.self, forKey: .binding))
        }

        fileprivate var signingJSON: String {
            "{\"store\":\"\(store)\",\"generation\":\(generation),\"binding\":\"\(binding)\"}"
        }
    }

    public struct Grant: Codable, Equatable, Sendable {
        public let operation: Operation
        public let id: String
        public let identity: Identity
        public let serial: UInt64
        public let expectedEpoch: UInt64
        /// SHA-256 of Ed25519 SubjectPublicKeyInfo DER, including for retire.
        public let newKey: String

        public init(operation: Operation, id: String, identity: Identity, serial: UInt64,
                    expectedEpoch: UInt64, newKey: String) throws {
            self.operation = operation; self.id = id; self.identity = identity
            self.serial = serial; self.expectedEpoch = expectedEpoch; self.newKey = newKey
            try validate()
        }

        public func validate() throws {
            try identity.validate()
            guard (try? StorageIdentity.GrantID(id)) != nil, serial > 0,
                  (try? StorageIdentity.SPKISHA256(newKey)) != nil else { throw ValidationError.invalidValue }
            switch operation {
            case .initialize:
                guard expectedEpoch == 0 else { throw ValidationError.invalidValue }
            case .takeover:
                guard expectedEpoch > 0, expectedEpoch < UInt64.max else { throw ValidationError.invalidValue }
            case .retire:
                guard expectedEpoch > 0 else { throw ValidationError.invalidValue }
            }
        }

        private enum CodingKeys: String, CodingKey {
            case operation, id, identity, serial
            case expectedEpoch = "expected_epoch", newKey = "new_key"
        }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            try self.init(operation: c.decode(Operation.self, forKey: .operation),
                          id: c.decode(String.self, forKey: .id), identity: c.decode(Identity.self, forKey: .identity),
                          serial: c.decode(UInt64.self, forKey: .serial),
                          expectedEpoch: c.decode(UInt64.self, forKey: .expectedEpoch),
                          newKey: c.decode(String.self, forKey: .newKey))
        }

        /// Exact Go json.Marshal(LifecycleGrant) declaration order, NOT sorted keys.
        /// Constructor-validated strings are ASCII UUIDs/hex/fixed operation labels.
        public var signingBytes: Data {
            Data(("cengine.storageauthority.lifecycle.v2\0" + signingJSON).utf8)
        }
        var signingJSON: String {
            "{\"operation\":\"\(operation.rawValue)\",\"id\":\"\(id)\",\"identity\":\(identity.signingJSON),\"serial\":\(serial),\"expected_epoch\":\(expectedEpoch),\"new_key\":\"\(newKey)\"}"
        }
    }

    /// A shaped or cryptographically verified grant is not an authenticated peer,
    /// current grant, or proof of any lifecycle transition. No signing API is exposed.
    public struct SignedGrant: Codable, Equatable, Sendable {
        public let grant: Grant
        public let signature: Data
        public init(grant: Grant, signature: Data) throws {
            self.grant = grant; self.signature = signature
            try validate()
        }
        public func validate() throws {
            try grant.validate()
            guard signature.count == 64 else { throw ValidationError.invalidSignature }
        }
        public func isValidSignature(using root: StorageIdentity.RootPublicKey) -> Bool {
            guard let key = try? Curve25519.Signing.PublicKey(rawRepresentation: root.publicData) else { return false }
            return key.isValidSignature(signature, for: grant.signingBytes)
        }
        private enum CodingKeys: String, CodingKey { case grant, signature }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            try self.init(grant: c.decode(Grant.self, forKey: .grant), signature: c.decode(Data.self, forKey: .signature))
        }
    }

    /// Direct-child result DTO only, NOT an authentication capability or evidence
    /// of drain. An owner must independently authenticate/correlate the child result.
    public struct Receipt: Codable, Equatable, Sendable {
        public let grant: Grant
        public let nonce: Data
        public let serviceEpoch: String
        public let revision: UInt64
        public init(grant: Grant, nonce: Data, serviceEpoch: String, revision: UInt64) throws {
            self.grant = grant; self.nonce = nonce; self.serviceEpoch = serviceEpoch; self.revision = revision
            try validate()
        }
        public func validate() throws {
            try grant.validate()
            guard nonce.count == 32, (try? StorageIdentity.IncarnationID(serviceEpoch)) != nil,
                  revision > 0 else { throw ValidationError.invalidValue }
        }
        private enum CodingKeys: String, CodingKey {
            case grant, nonce, revision
            case serviceEpoch = "service_epoch"
        }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            try self.init(grant: c.decode(Grant.self, forKey: .grant), nonce: c.decode(Data.self, forKey: .nonce),
                          serviceEpoch: c.decode(String.self, forKey: .serviceEpoch),
                          revision: c.decode(UInt64.self, forKey: .revision))
        }
        /// Exact Go json.Marshal(LifecycleReceipt), including canonical padded base64.
        public var signingBytes: Data {
            Data(("cengine.storageauthority.lifecycle-receipt.v2\0" +
                "{\"grant\":\(grant.signingJSON),\"nonce\":\"\(nonce.base64EncodedString())\",\"service_epoch\":\"\(serviceEpoch)\",\"revision\":\(revision)}").utf8)
        }
    }

    // Live-service DTOs are separate from the immutable applied-grant Receipt.
    public struct ServiceResult: Codable, Equatable, Sendable {
        public let identity: Identity
        public let grant: Grant
        public let nonce: Data
        public let serviceEpoch: String
        public let controllerEpoch: UInt64
        public let controllerKey: String
        public let openRevision: UInt64
        public init(identity: Identity, grant: Grant, nonce: Data, serviceEpoch: String, controllerEpoch: UInt64, controllerKey: String, openRevision: UInt64) throws {
            self.identity = identity
            self.grant = grant
            self.nonce = nonce
            self.serviceEpoch = serviceEpoch
            self.controllerEpoch = controllerEpoch
            self.controllerKey = controllerKey
            self.openRevision = openRevision
            try validate()
        }
        public func validate() throws {
            try grant.validate()
            guard identity == grant.identity, grant.operation != .retire,
                  nonce.count == 32, (try? StorageIdentity.IncarnationID(serviceEpoch)) != nil,
                  controllerEpoch == grant.expectedEpoch + 1, controllerKey == grant.newKey,
                  openRevision > 0 else { throw ValidationError.invalidValue }
        }
        private enum CodingKeys: String, CodingKey {
            case identity
            case grant
            case nonce
            case serviceEpoch = "service_epoch"
            case controllerEpoch = "controller_epoch"
            case controllerKey = "controller_key"
            case openRevision = "open_revision"
        }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            try self.init(identity: c.decode(Identity.self, forKey: .identity),
                          grant: c.decode(Grant.self, forKey: .grant),
                          nonce: c.decode(Data.self, forKey: .nonce),
                          serviceEpoch: c.decode(String.self, forKey: .serviceEpoch),
                          controllerEpoch: c.decode(UInt64.self, forKey: .controllerEpoch),
                          controllerKey: c.decode(String.self, forKey: .controllerKey),
                          openRevision: c.decode(UInt64.self, forKey: .openRevision))
        }
        /// Exact Go LifecycleServiceResult declaration order and padded base64.
        public var signingBytes: Data {
            Data(("cengine.storageauthority.lifecycle-service-result.v2\0" +
                "{\"identity\":\(identity.signingJSON),\"grant\":\(grant.signingJSON),\"nonce\":\"\(nonce.base64EncodedString())\",\"service_epoch\":\"\(serviceEpoch)\",\"controller_epoch\":\(controllerEpoch),\"controller_key\":\"\(controllerKey)\",\"open_revision\":\(openRevision)}").utf8)
        }
        public func state(boot: StorageLifecycleBootTrust) throws -> ServiceState {
            try validate()
            return try .init(grant: grant, context: .init(serviceEpoch: serviceEpoch,
                controllerEpoch: controllerEpoch, controllerKey: controllerKey), openRevision: openRevision, boot: boot)
        }
    }

    public struct ServiceContext: Codable, Equatable, Sendable {
        public let serviceEpoch: String
        public let controllerEpoch: UInt64
        public let controllerKey: String
        public init(serviceEpoch: String, controllerEpoch: UInt64, controllerKey: String) throws {
            self.serviceEpoch = serviceEpoch
            self.controllerEpoch = controllerEpoch
            self.controllerKey = controllerKey
            try validate()
        }
        public func validate() throws {
            _ = try StorageIdentity.IncarnationID(serviceEpoch)
            _ = try StorageIdentity.SPKISHA256(controllerKey)
            guard controllerEpoch > 0 else { throw ValidationError.invalidValue }
        }
        private enum CodingKeys: String, CodingKey {
            case serviceEpoch = "service_epoch"
            case controllerEpoch = "controller_epoch"
            case controllerKey = "controller_key"
        }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            try self.init(serviceEpoch: c.decode(String.self, forKey: .serviceEpoch),
                          controllerEpoch: c.decode(UInt64.self, forKey: .controllerEpoch),
                          controllerKey: c.decode(String.self, forKey: .controllerKey))
        }
    }

    public struct ServiceState: Codable, Equatable, Sendable {
        public let grant: Grant
        public let context: ServiceContext
        public let openRevision: UInt64
        public let boot: StorageLifecycleBootTrust
        public init(grant: Grant, context: ServiceContext, openRevision: UInt64, boot: StorageLifecycleBootTrust) throws {
            self.grant = grant
            self.context = context
            self.openRevision = openRevision
            self.boot = boot
            try validate()
        }
        public func validate() throws {
            try grant.validate(); try context.validate(); try boot.validate()
            guard grant.operation != .retire, context.controllerEpoch == grant.expectedEpoch + 1,
                  context.controllerKey == grant.newKey, openRevision > 0,
                  boot.identity == grant.identity, boot.serviceEpoch == context.serviceEpoch,
                  boot.bootstrapKey != context.controllerKey else { throw ValidationError.invalidValue }
        }
        private enum CodingKeys: String, CodingKey {
            case grant
            case context
            case openRevision = "open_revision"
            case boot
        }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            try self.init(grant: c.decode(Grant.self, forKey: .grant),
                          context: c.decode(ServiceContext.self, forKey: .context),
                          openRevision: c.decode(UInt64.self, forKey: .openRevision),
                          boot: c.decode(StorageLifecycleBootTrust.self, forKey: .boot))
        }
    }

    public struct ServiceChangeRequest: Codable, Equatable, Sendable {
        public let operationID: String
        public let predecessor: ServiceState
        public init(operationID: String, predecessor: ServiceState) throws {
            self.operationID = operationID
            self.predecessor = predecessor
            try validate()
        }
        public func validate() throws {
            _ = try StorageIdentity.GrantID(operationID)
            try predecessor.validate()
        }
        private enum CodingKeys: String, CodingKey {
            case operationID = "operation_id"
            case predecessor
        }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            try self.init(operationID: c.decode(String.self, forKey: .operationID),
                          predecessor: c.decode(ServiceState.self, forKey: .predecessor))
        }
        /// Exact Go json.Marshal(LifecycleServiceChangeRequest) declaration order, NOT sorted keys.
        /// Constructor-validated strings are ASCII UUIDs/hex; integers are decimal UInt64.
        public var signingBytes: Data {
            let p = predecessor, c = p.context, b = p.boot
            let boot = "{\"identity\":\(b.identity.signingJSON),\"service_epoch\":\"\(b.serviceEpoch)\",\"tls_root_sha256\":\"\(b.tlsRootSHA256)\",\"server_spki\":\"\(b.serverSPKI)\",\"bootstrap_key\":\"\(b.bootstrapKey)\"}"
            let context = "{\"service_epoch\":\"\(c.serviceEpoch)\",\"controller_epoch\":\(c.controllerEpoch),\"controller_key\":\"\(c.controllerKey)\"}"
            let json = "{\"operation_id\":\"\(operationID)\",\"predecessor\":{\"grant\":\(p.grant.signingJSON),\"context\":\(context),\"open_revision\":\(p.openRevision),\"boot\":\(boot)}}"
            return Data(("cengine.storageauthority.lifecycle-service-change.v2\0" + json).utf8)
        }
        /// A same-C reopen requires a new E, CA and server key, not a partial TLS rotation.
        public func validateSuccessorBoot(_ boot: StorageLifecycleBootTrust) throws {
            try validate(); try boot.validate()
            let old = predecessor.boot
            guard boot.identity == old.identity, boot.bootstrapKey == old.bootstrapKey,
                  boot.serviceEpoch != old.serviceEpoch, boot.tlsRootSHA256 != old.tlsRootSHA256,
                  boot.serverSPKI != old.serverSPKI else { throw ValidationError.invalidValue }
        }
    }

    /// ROOT-signed service-change authorization. A valid signature proves only that
    /// the ROOT bootstrap key staged this exact request; it is not a successor proof.
    public struct SignedServiceChange: Codable, Equatable, Sendable {
        public let request: ServiceChangeRequest
        public let signature: Data
        public init(request: ServiceChangeRequest, signature: Data) throws {
            self.request = request; self.signature = signature
            try validate()
        }
        public func validate() throws {
            try request.validate()
            guard signature.count == 64 else { throw ValidationError.invalidSignature }
        }
        /// Also binds the verifier to the predecessor's pinned bootstrap key.
        public func isValidSignature(using root: StorageIdentity.RootPublicKey) -> Bool {
            guard (try? validate()) != nil, root.fingerprint.rawValue == request.predecessor.boot.bootstrapKey,
                  let key = try? Curve25519.Signing.PublicKey(rawRepresentation: root.publicData) else { return false }
            return key.isValidSignature(signature, for: request.signingBytes)
        }
        private enum CodingKeys: String, CodingKey { case request, signature }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            try self.init(request: c.decode(ServiceChangeRequest.self, forKey: .request), signature: c.decode(Data.self, forKey: .signature))
        }
    }

    public struct ServiceChangeConfirmation: Codable, Equatable, Sendable {
        public let request: ServiceChangeRequest
        public let successor: ServiceState
        public init(request: ServiceChangeRequest, successor: ServiceState) throws {
            self.request = request
            self.successor = successor
            try validate()
        }
        public func validate() throws {
            try request.validate(); try successor.validate()
            try request.validateSuccessorBoot(successor.boot)
            let prior = request.predecessor
            guard successor.grant == prior.grant,
                  successor.context.controllerEpoch == prior.context.controllerEpoch,
                  successor.context.controllerKey == prior.context.controllerKey,
                  successor.openRevision > prior.openRevision else { throw ValidationError.invalidValue }
        }
        private enum CodingKeys: String, CodingKey {
            case request
            case successor
        }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            try self.init(request: c.decode(ServiceChangeRequest.self, forKey: .request),
                          successor: c.decode(ServiceState.self, forKey: .successor))
        }
    }

    /// Sorted-key, compact JSON with unescaped slashes; no envelope is added.
    /// UInt64 values are never converted through Double/NSNumber.
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(value)
        guard bytes.count <= maximumPayloadBytes else { throw ValidationError.payloadTooLarge }
        return bytes
    }

    /// Exact re-encoding closes schemas and rejects unknown/duplicate keys, alternate
    /// numeric/base64 spellings, escapes, whitespace and trailing data, at every depth.
    public static func decode<T: Decodable & Encodable>(_ type: T.Type, from data: Data) throws -> T {
        guard data.count <= maximumPayloadBytes else { throw ValidationError.payloadTooLarge }
        let value = try JSONDecoder().decode(type, from: data)
        guard try encode(value) == data else { throw ValidationError.invalidMessage }
        return value
    }

    /// Hashes domain `cengine.storageauthority.binding.v3\0` plus stable host
    /// StoreBinding JSON (sorted keys, compact, ASCII, decimal UInt64):
    /// {backing:{identity:{inode,volume_uuid},size},expected_ext4_uuid,
    ///  root:{inode,volume_uuid},store_id}. Generation is separate; no path,
    /// live device observation or key is included. Old digests are not normalized.
    public static func bindingDigest(_ binding: StorageIdentity.StoreBinding) -> String {
        func rootJSON(_ root: StorageIdentity.RootIdentity) -> String {
            "{\"inode\":\(root.inode),\"volume_uuid\":\"\(root.volumeUUID.rawValue)\"}"
        }
        let json = "{\"backing\":{\"identity\":\(rootJSON(binding.backing.identity)),\"size\":\(binding.backing.size)},\"expected_ext4_uuid\":\"\(binding.expectedExt4UUID.rawValue)\",\"root\":\(rootJSON(binding.root)),\"store_id\":\"\(binding.storeID.rawValue)\"}"
        return SHA256.hash(data: Data(("cengine.storageauthority.binding.v3\0" + json).utf8))
            .map { String(format: "%02x", $0) }.joined()
    }
}

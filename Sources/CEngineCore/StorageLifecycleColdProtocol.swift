import CryptoKit
import Foundation

/// Value-only cold-start authorization. This does not prove process death, disk
/// ownership or a live successor. ROOT and the native shim must establish those.
public enum StorageLifecycleColdProtocol {
    public typealias L = StorageLifecycleProtocol

    public struct Predecessor: Codable, Equatable, Sendable {
        public let currentGrant: L.Grant
        public let serviceEpoch: String
        public let controllerEpoch: UInt64
        public let controllerKey: String
        public let openRevision: UInt64
        public let bootstrapKey: String
        public init(currentGrant: L.Grant, serviceEpoch: String, controllerEpoch: UInt64,
                    controllerKey: String, openRevision: UInt64, bootstrapKey: String) throws {
            self.currentGrant = currentGrant; self.serviceEpoch = serviceEpoch; self.controllerEpoch = controllerEpoch
            self.controllerKey = controllerKey; self.openRevision = openRevision; self.bootstrapKey = bootstrapKey
            try validate()
        }
        public func validate() throws {
            try currentGrant.validate()
            _ = try StorageIdentity.IncarnationID(serviceEpoch)
            _ = try StorageIdentity.SPKISHA256(bootstrapKey)
            guard currentGrant.operation != .retire, currentGrant.expectedEpoch < UInt64.max,
                  controllerEpoch == currentGrant.expectedEpoch + 1, controllerKey == currentGrant.newKey,
                  controllerKey != bootstrapKey, openRevision > 0 else { throw L.ValidationError.invalidValue }
        }
        enum CodingKeys: String, CodingKey {
            case currentGrant = "current_grant", serviceEpoch = "service_epoch", controllerEpoch = "controller_epoch"
            case controllerKey = "controller_key", openRevision = "open_revision", bootstrapKey = "bootstrap_key"
        }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            try self.init(currentGrant: c.decode(L.Grant.self, forKey: .currentGrant), serviceEpoch: c.decode(String.self, forKey: .serviceEpoch),
                controllerEpoch: c.decode(UInt64.self, forKey: .controllerEpoch), controllerKey: c.decode(String.self, forKey: .controllerKey),
                openRevision: c.decode(UInt64.self, forKey: .openRevision), bootstrapKey: c.decode(String.self, forKey: .bootstrapKey))
        }
        fileprivate var signingJSON: String {
            "{\"current_grant\":\(currentGrant.signingJSON),\"service_epoch\":\"\(serviceEpoch)\",\"controller_epoch\":\(controllerEpoch),\"controller_key\":\"\(controllerKey)\",\"open_revision\":\(openRevision),\"bootstrap_key\":\"\(bootstrapKey)\"}"
        }
    }

    public struct Launch: Codable, Equatable, Sendable {
        public let shimLaunchUUID: String
        /// Hash of RawDiskBootTransaction.adoptionSpecification, not launch-file bytes.
        public let specSHA256: String
        public let initramfsSHA256: String
        public let ext4UUID: String
        public let bytes: UInt64
        public init(shimLaunchUUID: String, specSHA256: String, initramfsSHA256: String, ext4UUID: String, bytes: UInt64) throws {
            self.shimLaunchUUID = shimLaunchUUID; self.specSHA256 = specSHA256; self.initramfsSHA256 = initramfsSHA256
            self.ext4UUID = ext4UUID; self.bytes = bytes
            try validate()
        }
        public func validate() throws {
            _ = try StorageIdentity.IncarnationID(shimLaunchUUID)
            _ = try StorageIdentity.SPKISHA256(specSHA256); _ = try StorageIdentity.SPKISHA256(initramfsSHA256)
            guard StorageServiceTypes.validUUID(ext4UUID), bytes > 0, bytes <= UInt64(Int64.max) else {
                throw L.ValidationError.invalidValue
            }
        }
        enum CodingKeys: String, CodingKey {
            case shimLaunchUUID = "shim_launch_uuid", specSHA256 = "spec_sha256", initramfsSHA256 = "initramfs_sha256"
            case ext4UUID = "ext4_uuid", bytes
        }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            try self.init(shimLaunchUUID: c.decode(String.self, forKey: .shimLaunchUUID), specSHA256: c.decode(String.self, forKey: .specSHA256),
                initramfsSHA256: c.decode(String.self, forKey: .initramfsSHA256), ext4UUID: c.decode(String.self, forKey: .ext4UUID),
                bytes: c.decode(UInt64.self, forKey: .bytes))
        }
        fileprivate var signingJSON: String {
            "{\"shim_launch_uuid\":\"\(shimLaunchUUID)\",\"spec_sha256\":\"\(specSHA256)\",\"initramfs_sha256\":\"\(initramfsSHA256)\",\"ext4_uuid\":\"\(ext4UUID)\",\"bytes\":\(bytes)}"
        }
    }

    public struct Request: Codable, Equatable, Sendable {
        public let operationID: String
        public let predecessor: Predecessor
        public let takeover: L.SignedGrant
        public let launch: Launch
        public let nowUnixSeconds: UInt64
        public let lifetimeSeconds: UInt64
        public init(operationID: String, predecessor: Predecessor, takeover: L.SignedGrant, launch: Launch,
                    nowUnixSeconds: UInt64, lifetimeSeconds: UInt64) throws {
            self.operationID = operationID; self.predecessor = predecessor; self.takeover = takeover; self.launch = launch
            self.nowUnixSeconds = nowUnixSeconds; self.lifetimeSeconds = lifetimeSeconds
            try validate()
        }
        public func validate() throws {
            try predecessor.validate(); try takeover.validate(); try launch.validate()
            let g = takeover.grant, p = predecessor
            guard operationID == g.id, g.operation == .takeover, g.identity == p.currentGrant.identity,
                  g.expectedEpoch == p.controllerEpoch, g.serial > p.currentGrant.serial, g.id != p.currentGrant.id,
                  g.newKey != p.controllerKey, g.newKey != p.bootstrapKey,
                  nowUnixSeconds > 0, nowUnixSeconds <= 253_402_300_799,
                  lifetimeSeconds > 0, lifetimeSeconds <= 86_400,
                  lifetimeSeconds <= 253_402_300_799 - nowUnixSeconds else { throw L.ValidationError.invalidValue }
        }
        enum CodingKeys: String, CodingKey {
            case operationID = "operation_id", predecessor, takeover, launch
            case nowUnixSeconds = "now_unix_seconds", lifetimeSeconds = "lifetime_seconds"
        }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            try self.init(operationID: c.decode(String.self, forKey: .operationID), predecessor: c.decode(Predecessor.self, forKey: .predecessor),
                takeover: c.decode(L.SignedGrant.self, forKey: .takeover), launch: c.decode(Launch.self, forKey: .launch),
                nowUnixSeconds: c.decode(UInt64.self, forKey: .nowUnixSeconds), lifetimeSeconds: c.decode(UInt64.self, forKey: .lifetimeSeconds))
        }
        /// Exact Go declaration order, not sorted transport JSON.
        public var signingBytes: Data {
            let signed = "{\"grant\":\(takeover.grant.signingJSON),\"signature\":\"\(takeover.signature.base64EncodedString())\"}"
            let json = "{\"operation_id\":\"\(operationID)\",\"predecessor\":\(predecessor.signingJSON),\"takeover\":\(signed),\"launch\":\(launch.signingJSON),\"now_unix_seconds\":\(nowUnixSeconds),\"lifetime_seconds\":\(lifetimeSeconds)}"
            return Data(("cengine.storageauthority.lifecycle-cold-open.v1\0" + json).utf8)
        }
        public var digest: String { SHA256.hash(data: signingBytes).map { String(format: "%02x", $0) }.joined() }
    }

    public struct SignedOpen: Codable, Equatable, Sendable {
        // Boot frames nest configurations in replacement replies. Keep this
        // immutable value heap-backed rather than multiplying its large inline
        // request through every frame/copy and exhausting cooperative stacks.
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
            guard (try? validate()) != nil, root.fingerprint.rawValue == request.predecessor.bootstrapKey,
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
}

import CryptoKit
import Foundation

/// Scoped daemon-to-root-helper RPC for resuming an unfinished initialization.
/// Its domain is separate from cold recovery. Every request requires an independently
/// bound scope and observed lock descriptors. Caller-supplied exit claims and service
/// results cannot authorize recovery: the root helper checks the witness and process
/// exit itself. Status is informational only.
public enum StorageLifecycleResumeRootProtocol {
    public typealias Lifecycle = StorageLifecycleProtocol
    public typealias Bootstrap = StorageIdentity
    public typealias Cold = StorageLifecycleColdProtocol
    public typealias Resume = StorageLifecycleResumeProtocol
    public typealias Adoption = StorageLifecycleAdoptionProtocol
    public typealias Shim = StorageLifecycleColdShimProtocol
    public static let version = "storage-lifecycle-resume-root.v1"
    public static let xpcOperation = "storage-lifecycle-resume-root"
    public static let maximumPayloadBytes = Lifecycle.maximumPayloadBytes

    public struct Prepare: Codable, Equatable, Sendable {
        /// Also the takeover grant ID. The helper alone allocates its serial.
        public let operationID: String
        public let identity: Lifecycle.Identity
        /// Exact original initialize grant; no predecessor service epoch is invented.
        public let expectedOriginal: Lifecycle.Grant
        public let candidate: StorageIdentity.Candidate
        /// Read-only resume probe greeting from the dedicated mount channel.
        /// The ROOT natively verifies this greeting independently; this DTO copy
        /// is only a correlation input, never proof.
        public let probeGreeting: Shim.Greeting
        /// The original shim launch this resume must not reuse.
        public let expectedOriginalShimLaunchUUID: String
        public let nowUnixSeconds: UInt64
        public let lifetimeSeconds: UInt64
        public init(operationID: String, identity: Lifecycle.Identity, expectedOriginal: Lifecycle.Grant,
                    candidate: StorageIdentity.Candidate, probeGreeting: Shim.Greeting,
                    expectedOriginalShimLaunchUUID: String, nowUnixSeconds: UInt64, lifetimeSeconds: UInt64) throws {
            self.operationID = operationID; self.identity = identity; self.expectedOriginal = expectedOriginal
            self.candidate = candidate; self.probeGreeting = probeGreeting
            self.expectedOriginalShimLaunchUUID = expectedOriginalShimLaunchUUID
            self.nowUnixSeconds = nowUnixSeconds; self.lifetimeSeconds = lifetimeSeconds; try validate()
        }
        public func validate() throws {
            _ = try StorageIdentity.GrantID(operationID)
            try identity.validate(); try expectedOriginal.validate()
            guard expectedOriginal.operation == .initialize, expectedOriginal.expectedEpoch == 0,
                  identity == expectedOriginal.identity else { throw Lifecycle.ValidationError.invalidValue }
            try probeGreeting.validate()
            let root = try StorageIdentity.RootPublicKey(publicData: probeGreeting.rootPublicKey)
            _ = try StorageIdentity.IncarnationID(expectedOriginalShimLaunchUUID)
            guard probeGreeting.purpose == .resumeReadOnly,
                  try identity == Lifecycle.Identity(binding: probeGreeting.binding.value(), generation: identity.generation),
                  probeGreeting.launch.shimLaunchUUID != expectedOriginalShimLaunchUUID,
                  candidate.publicKey.fingerprint.rawValue != expectedOriginal.newKey,
                  candidate.publicKey.fingerprint.rawValue != root.fingerprint.rawValue,
                  operationID != expectedOriginal.id,
                  nowUnixSeconds > 0, nowUnixSeconds <= StorageServiceTypes.maximumUnixSeconds,
                  lifetimeSeconds > 0, lifetimeSeconds <= StorageServiceTypes.maximumLifetimeSeconds,
                  lifetimeSeconds <= StorageServiceTypes.maximumUnixSeconds - nowUnixSeconds else {
                throw Lifecycle.ValidationError.invalidValue
            }
        }
        /// Correlates this prepare against the ROOT-witnessed status. The helper
        /// must construct `status` from protected native state and call this
        /// overload; the public status DTO is never proof by itself.
        public func validate(for status: Status) throws {
            try validate(); try status.validate()
            guard status.eligibility == .eligible,
                  expectedOriginal == status.original,
                  expectedOriginalShimLaunchUUID == status.originalShimLaunchUUID,
                  probeGreeting.rootPublicKey == status.rootPublicKey,
                  probeGreeting.binding == status.binding else {
                throw StorageIdentity.ValidationError.correlationMismatch
            }
        }
        public var digest: String {
            get throws { try validate(); return try hash(self, domain: "prepare") }
        }
        private enum CodingKeys: String, CodingKey {
            case operationID, identity, expectedOriginal, candidate, probeGreeting
            case expectedOriginalShimLaunchUUID, nowUnixSeconds, lifetimeSeconds
        }
        public func encode(to encoder: any Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(operationID, forKey: .operationID); try c.encode(identity, forKey: .identity)
            try c.encode(expectedOriginal, forKey: .expectedOriginal); try c.encode(Candidate(candidate), forKey: .candidate)
            try c.encode(probeGreeting, forKey: .probeGreeting)
            try c.encode(expectedOriginalShimLaunchUUID, forKey: .expectedOriginalShimLaunchUUID)
            try c.encode(nowUnixSeconds, forKey: .nowUnixSeconds); try c.encode(lifetimeSeconds, forKey: .lifetimeSeconds)
        }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            try self.init(operationID: c.decode(String.self, forKey: .operationID),
                identity: c.decode(Lifecycle.Identity.self, forKey: .identity),
                expectedOriginal: c.decode(Lifecycle.Grant.self, forKey: .expectedOriginal),
                candidate: c.decode(Candidate.self, forKey: .candidate).value(),
                probeGreeting: c.decode(Shim.Greeting.self, forKey: .probeGreeting),
                expectedOriginalShimLaunchUUID: c.decode(String.self, forKey: .expectedOriginalShimLaunchUUID),
                nowUnixSeconds: c.decode(UInt64.self, forKey: .nowUnixSeconds),
                lifetimeSeconds: c.decode(UInt64.self, forKey: .lifetimeSeconds))
        }
    }
    private struct Candidate: Codable {
        let spki: Data
        let pid: Int32
        let incarnation: String
        init(_ value: StorageIdentity.Candidate) {
            spki = value.publicKey.publicData; pid = value.childPIDHint; incarnation = value.incarnationID.rawValue
        }
        func value() throws -> StorageIdentity.Candidate {
            try .init(publicKey: .init(publicData: spki), childPIDHint: pid, incarnationID: .init(incarnation))
        }
    }

    public struct Prepared: Codable, Equatable, Sendable {
        /// Exact authorization, including inner and outer signatures; already heap-backed.
        public let signedOpen: Resume.SignedOpen
        public let successorOrigin: Adoption.Origin
        /// Fixed genesis base epoch for fresh resume; never a fabricated predecessor epoch.
        public let baseEpoch: UInt64
        public init(signedOpen: Resume.SignedOpen, successorOrigin: Adoption.Origin, baseEpoch: UInt64) throws {
            self.signedOpen = signedOpen; self.successorOrigin = successorOrigin; self.baseEpoch = baseEpoch
            try validate()
        }
        public func validate() throws {
            try signedOpen.validate(); try successorOrigin.validate()
            let r = signedOpen.request, root = try StorageIdentity.RootPublicKey(publicData: successorOrigin.rootPublicKey)
            guard signedOpen.isValidSignature(using: root), baseEpoch == 1,
                  try r.takeover.grant.identity == Lifecycle.Identity(binding: successorOrigin.binding.value(), generation: r.takeover.grant.identity.generation),
                  r.launch.shimLaunchUUID == successorOrigin.shimLaunchUUID, r.launch.specSHA256 == successorOrigin.specSHA256,
                  r.launch.ext4UUID == successorOrigin.binding.ext4UUID, r.launch.bytes == successorOrigin.binding.bytes else {
                throw Lifecycle.ValidationError.invalidValue
            }
        }
        public func validate(for prepare: Prepare) throws {
            try validate(); try prepare.validate()
            let r = signedOpen.request, g = r.takeover.grant
            guard r.operationID == prepare.operationID, r.original == prepare.expectedOriginal,
                  g.identity == prepare.identity, g.newKey == prepare.candidate.publicKey.fingerprint.rawValue,
                  r.launch == prepare.probeGreeting.launch, r.nowUnixSeconds == prepare.nowUnixSeconds,
                  r.lifetimeSeconds == prepare.lifetimeSeconds, successorOrigin == (try prepare.probeGreeting.successorOrigin),
                  baseEpoch == 1 else { throw StorageIdentity.ValidationError.correlationMismatch }
        }
        public var signedOpenSHA256: String {
            get throws { try signedOpen.validate(); return try hash(signedOpen, domain: "signed-open") }
        }
    }
    public struct Completed: Codable, Equatable, Sendable {
        public let operationID: String
        public let signedOpenSHA256: String
        public let successorOrigin: Adoption.Origin
        public let baseEpoch: UInt64
        public let receipt: Lifecycle.Receipt
        public let successor: Lifecycle.ServiceState
        public init(operationID: String, signedOpenSHA256: String, successorOrigin: Adoption.Origin, baseEpoch: UInt64,
                    receipt: Lifecycle.Receipt, successor: Lifecycle.ServiceState) throws {
            self.operationID = operationID; self.signedOpenSHA256 = signedOpenSHA256; self.successorOrigin = successorOrigin
            self.baseEpoch = baseEpoch; self.receipt = receipt; self.successor = successor; try validate()
        }
        public func validate() throws {
            _ = try StorageIdentity.GrantID(operationID); _ = try StorageIdentity.SPKISHA256(signedOpenSHA256)
            try successorOrigin.validate(); try receipt.validate(); try successor.validate()
            let root = try StorageIdentity.RootPublicKey(publicData: successorOrigin.rootPublicKey)
            guard baseEpoch == 1, receipt.grant.operation == .takeover, receipt.grant.expectedEpoch == 1,
                  receipt.grant.id == operationID, receipt.grant == successor.grant,
                  receipt.serviceEpoch == successor.context.serviceEpoch,
                  receipt.revision == successor.openRevision,
                  successor.context.controllerEpoch == 2,
                  successor.openRevision == 1 || successor.openRevision == 2,
                  try successor.grant.identity == Lifecycle.Identity(binding: successorOrigin.binding.value(), generation: successor.grant.identity.generation),
                  try successor.boot.bootstrapKey == root.fingerprint.rawValue else {
                throw Lifecycle.ValidationError.invalidValue
            }
        }
        public func validate(prepared: Prepared) throws {
            try validate(); try prepared.validate()
            guard signedOpenSHA256 == (try prepared.signedOpenSHA256),
                  receipt.grant == prepared.signedOpen.request.takeover.grant,
                  successorOrigin == prepared.successorOrigin, baseEpoch == prepared.baseEpoch else {
                throw StorageIdentity.ValidationError.correlationMismatch
            }
        }
    }

    public enum Eligibility: String, Codable, Sendable {
        /// Only positive unused-initialization witness evidence for the protected
        /// native process permits the helper to report this. The ROOT alone owns
        /// the actual witness and exit checks; this value is never inferred from
        /// socket loss or caller input.
        case eligible
        /// Missing/ambiguous native evidence, unsupported state, or unavailable checks.
        case unavailable
    }
    /// Public status DTO; informational only. The helper must construct it from
    /// protected native state and must call `Prepare.validate(for:)` before
    /// relying on it — a public status is never proof by itself.
    public struct Status: Codable, Equatable, Sendable {
        public let original: Lifecycle.Grant
        public let binding: StorageLifecycleStoreBinding
        public let rootPublicKey: Data
        public let originalShimLaunchUUID: String
        public let eligibility: Eligibility
        public init(original: Lifecycle.Grant, binding: StorageLifecycleStoreBinding, rootPublicKey: Data,
                    originalShimLaunchUUID: String, eligibility: Eligibility) throws {
            self.original = original; self.binding = binding; self.rootPublicKey = rootPublicKey
            self.originalShimLaunchUUID = originalShimLaunchUUID; self.eligibility = eligibility; try validate()
        }
        public func validate() throws {
            try original.validate()
            let root = try StorageIdentity.RootPublicKey(publicData: rootPublicKey)
            _ = try binding.value(); _ = try StorageIdentity.IncarnationID(originalShimLaunchUUID)
            guard original.operation == .initialize, original.expectedEpoch == 0,
                  try original.identity == Lifecycle.Identity(binding: binding.value(), generation: original.identity.generation),
                  root.fingerprint.rawValue != original.newKey else { throw Lifecycle.ValidationError.invalidValue }
        }
    }
    public enum Body: Equatable, Sendable {
        /// Informational recovery of the protected original identity after a lost
        /// provision reply. Requires the exact full binding and an observed scope.
        case lookup(StorageLifecycleStoreBinding)
        case status(Lifecycle.Identity)
        case prepare(Prepare)
        case complete(operationID: String, signedOpenSHA256: String)
    }
    public struct Request: Equatable, Sendable {
        public let requestID: StorageIdentity.RequestID
        public let body: Body
        public init(requestID: StorageIdentity.RequestID, body: Body) throws {
            self.requestID = requestID; self.body = body
            switch body {
            case .lookup(let binding): _ = try binding.value()
            case .status(let identity): try identity.validate()
            case .prepare(let prepare): try prepare.validate()
            case .complete(let id, let digest): _ = try StorageIdentity.GrantID(id); _ = try StorageIdentity.SPKISHA256(digest)
            }
        }
    }
    public enum ResultBody: Equatable, Sendable {
        case status(Status), prepared(Prepared), completed(Completed), failure(StorageIdentity.ErrorCode)
    }
    public struct Reply: Equatable, Sendable {
        public let requestID: StorageIdentity.RequestID
        public let operation: String
        public let requestSHA256: String
        public let body: ResultBody
        public init(for request: Request, body: ResultBody) throws {
            switch (request.body, body) {
            case (_, .failure): break
            case (.lookup(let binding), .status(let status)):
                try status.validate()
                guard status.binding == binding else { throw StorageIdentity.ValidationError.correlationMismatch }
            case (.status(let identity), .status(let status)):
                try status.validate()
                guard status.original.identity == identity else { throw StorageIdentity.ValidationError.correlationMismatch }
            case (.prepare(let prepare), .prepared(let prepared)): try prepared.validate(for: prepare)
            case (.complete(let id, let digest), .completed(let completed)):
                try completed.validate()
                guard completed.operationID == id, completed.signedOpenSHA256 == digest else { throw StorageIdentity.ValidationError.correlationMismatch }
            default: throw StorageIdentity.ValidationError.correlationMismatch
            }
            requestID = request.requestID; operation = packet(request).operation
            requestSHA256 = try hash(packet(request), domain: "request"); self.body = body
        }
    }
    private struct Packet: Codable {
        var version = StorageLifecycleResumeRootProtocol.version
        var requestID: String
        var operation: String
        var identity: Lifecycle.Identity?
        var binding: StorageLifecycleStoreBinding?
        var prepare: Prepare?
        var operationID: String?
        var signedOpenSHA256: String?
        var requestSHA256: String?
        var status: Status?
        var prepared: Prepared?
        var completed: Completed?
        var error: String?
    }
    private static func packet(_ request: Request) -> Packet {
        var p = Packet(requestID: request.requestID.rawValue, operation: "status")
        switch request.body {
        case .lookup(let binding): p.operation = "lookup"; p.binding = binding
        case .status(let identity): p.identity = identity
        case .prepare(let prepare): p.operation = "prepare"; p.prepare = prepare
        case .complete(let id, let digest): p.operation = "complete"; p.operationID = id; p.signedOpenSHA256 = digest
        }
        return p
    }
    private static func packet(_ reply: Reply) -> Packet {
        var p = Packet(requestID: reply.requestID.rawValue, operation: reply.operation, requestSHA256: reply.requestSHA256)
        switch reply.body {
        case .status(let value): p.status = value
        case .prepared(let value): p.prepared = value
        case .completed(let value): p.completed = value
        case .failure(let code): p.error = code.rawValue
        }
        return p
    }
    private static func hash<T: Encodable>(_ value: T, domain: String) throws -> String {
        SHA256.hash(data: Data("cengine.storage-lifecycle-resume-root.\(domain).v1\0".utf8) + (try Lifecycle.encode(value)))
            .map { String(format: "%02x", $0) }.joined()
    }
    private static func required<T>(_ value: T?) throws -> T {
        guard let value else { throw Lifecycle.ValidationError.invalidMessage }; return value
    }
    public static func encode(_ request: Request) throws -> Data { try Lifecycle.encode(packet(request)) }
    public static func encode(_ reply: Reply) throws -> Data { try Lifecycle.encode(packet(reply)) }
    public static func decodeRequest(_ bytes: Data) throws -> Request {
        let p = try Lifecycle.decode(Packet.self, from: bytes)
        let body: Body
        switch p.operation {
        case "lookup": body = .lookup(try required(p.binding))
        case "status": body = .status(try required(p.identity))
        case "prepare": body = .prepare(try required(p.prepare))
        case "complete": body = .complete(operationID: try required(p.operationID), signedOpenSHA256: try required(p.signedOpenSHA256))
        default: throw Lifecycle.ValidationError.invalidMessage
        }
        let value = try Request(requestID: .init(p.requestID), body: body)
        guard try encode(value) == bytes else { throw Lifecycle.ValidationError.invalidMessage }; return value
    }
    public static func decodeReply(_ bytes: Data, for request: Request) throws -> Reply {
        let p = try Lifecycle.decode(Packet.self, from: bytes)
        let body: ResultBody
        if let error = p.error {
            guard let code = StorageIdentity.ErrorCode(rawValue: error) else { throw Lifecycle.ValidationError.invalidMessage }; body = .failure(code)
        } else {
            switch request.body {
            case .lookup, .status: body = .status(try required(p.status))
            case .prepare: body = .prepared(try required(p.prepared))
            case .complete: body = .completed(try required(p.completed))
            }
        }
        let value = try Reply(for: request, body: body)
        guard try encode(value) == bytes else { throw StorageIdentity.ValidationError.correlationMismatch }; return value
    }
}

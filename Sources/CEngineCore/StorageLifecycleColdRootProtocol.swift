import CryptoKit
import Foundation

/// Scoped daemon-to-root-helper cold recovery RPC. Every request requires an
/// independently bound scope and observed lock descriptors. Caller-supplied exit
/// claims and service results cannot authorize recovery. Status is informational.
public enum StorageLifecycleColdRootProtocol {
    public typealias Lifecycle = StorageLifecycleProtocol
    public typealias Bootstrap = StorageIdentity
    public typealias Cold = StorageLifecycleColdProtocol
    public typealias Adoption = StorageLifecycleAdoptionProtocol
    public typealias Shim = StorageLifecycleColdShimProtocol
    public static let version = "storage-lifecycle-cold-root.v1"
    public static let xpcOperation = "storage-lifecycle-cold-root"
    public static let maximumPayloadBytes = Lifecycle.maximumPayloadBytes

    public struct Prepare: Codable, Equatable, Sendable {
        /// Also the takeover grant ID. The helper alone allocates its serial.
        public let operationID: String
        public let identity: Lifecycle.Identity
        public let expectedPredecessor: Cold.Predecessor
        public let expectedOrigin: Adoption.Origin
        public let expectedAllocatedEpoch: UInt64
        public let candidate: StorageIdentity.Candidate
        public let mountedGreeting: Shim.Greeting
        public let nowUnixSeconds: UInt64
        public let lifetimeSeconds: UInt64
        public init(operationID: String, identity: Lifecycle.Identity, expectedPredecessor: Cold.Predecessor,
                    expectedOrigin: Adoption.Origin, expectedAllocatedEpoch: UInt64, candidate: StorageIdentity.Candidate,
                    mountedGreeting: Shim.Greeting, nowUnixSeconds: UInt64, lifetimeSeconds: UInt64) throws {
            self.operationID = operationID; self.identity = identity; self.expectedPredecessor = expectedPredecessor
            self.expectedOrigin = expectedOrigin; self.expectedAllocatedEpoch = expectedAllocatedEpoch
            self.candidate = candidate; self.mountedGreeting = mountedGreeting
            self.nowUnixSeconds = nowUnixSeconds; self.lifetimeSeconds = lifetimeSeconds; try validate()
        }
        public func validate() throws {
            _ = try StorageIdentity.GrantID(operationID)
            try validateProtected(identity: identity, predecessor: expectedPredecessor, origin: expectedOrigin,
                                  allocatedEpoch: expectedAllocatedEpoch)
            try mountedGreeting.validate()
            guard expectedAllocatedEpoch < UInt64.max, expectedPredecessor.controllerEpoch < UInt64.max,
                  expectedPredecessor.currentGrant.serial < UInt64.max,
                  operationID != expectedPredecessor.currentGrant.id,
                  mountedGreeting.purpose == .cold,
                  mountedGreeting.binding == expectedOrigin.binding, mountedGreeting.rootPublicKey == expectedOrigin.rootPublicKey,
                  mountedGreeting.launch.shimLaunchUUID != expectedOrigin.shimLaunchUUID,
                  candidate.publicKey.fingerprint.rawValue != expectedPredecessor.controllerKey,
                  candidate.publicKey.fingerprint.rawValue != expectedPredecessor.bootstrapKey,
                  nowUnixSeconds > 0, nowUnixSeconds <= StorageServiceTypes.maximumUnixSeconds,
                  lifetimeSeconds > 0, lifetimeSeconds <= StorageServiceTypes.maximumLifetimeSeconds else {
                throw Lifecycle.ValidationError.invalidValue
            }
        }
        public var digest: String {
            get throws { try validate(); return try hash(self, domain: "prepare") }
        }
        private enum CodingKeys: String, CodingKey {
            case operationID, identity, expectedPredecessor, expectedOrigin, expectedAllocatedEpoch
            case candidate, mountedGreeting, nowUnixSeconds, lifetimeSeconds
        }
        public func encode(to encoder: any Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(operationID, forKey: .operationID); try c.encode(identity, forKey: .identity)
            try c.encode(expectedPredecessor, forKey: .expectedPredecessor); try c.encode(expectedOrigin, forKey: .expectedOrigin)
            try c.encode(expectedAllocatedEpoch, forKey: .expectedAllocatedEpoch); try c.encode(Candidate(candidate), forKey: .candidate)
            try c.encode(mountedGreeting, forKey: .mountedGreeting); try c.encode(nowUnixSeconds, forKey: .nowUnixSeconds)
            try c.encode(lifetimeSeconds, forKey: .lifetimeSeconds)
        }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            try self.init(operationID: c.decode(String.self, forKey: .operationID), identity: c.decode(Lifecycle.Identity.self, forKey: .identity),
                expectedPredecessor: c.decode(Cold.Predecessor.self, forKey: .expectedPredecessor),
                expectedOrigin: c.decode(Adoption.Origin.self, forKey: .expectedOrigin),
                expectedAllocatedEpoch: c.decode(UInt64.self, forKey: .expectedAllocatedEpoch),
                candidate: c.decode(Candidate.self, forKey: .candidate).value(), mountedGreeting: c.decode(Shim.Greeting.self, forKey: .mountedGreeting),
                nowUnixSeconds: c.decode(UInt64.self, forKey: .nowUnixSeconds), lifetimeSeconds: c.decode(UInt64.self, forKey: .lifetimeSeconds))
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

    /// Keyless reconciliation of an already committed cold result. ROOT, not
    /// this request, must establish positive native death of every participant.
    public struct ResolveDead: Codable, Equatable, Sendable {
        public let resolutionID: String
        public let identity: Lifecycle.Identity
        public let operationID: String
        public let signedOpenSHA256: String
        public init(resolutionID: String, identity: Lifecycle.Identity, operationID: String,
                    signedOpenSHA256: String) throws {
            self.resolutionID = resolutionID; self.identity = identity
            self.operationID = operationID; self.signedOpenSHA256 = signedOpenSHA256
            try validate()
        }
        public func validate() throws {
            _ = try StorageIdentity.GrantID(resolutionID); _ = try StorageIdentity.GrantID(operationID)
            _ = try StorageIdentity.SPKISHA256(signedOpenSHA256); try identity.validate()
            guard resolutionID != operationID else { throw Lifecycle.ValidationError.invalidValue }
        }
    }
    /// Protected historical disposition, NEVER live control or enrollment proof.
    /// It can bridge only one failed cold edge to a genuinely new cold operation.
    public struct ResolvedDead: Codable, Equatable, Sendable {
        public let request: ResolveDead
        public let anchor: Lifecycle.ServiceState
        public let receipt: Lifecycle.Receipt
        public let successor: Lifecycle.ServiceState
        public let successorOrigin: Adoption.Origin
        public let baseEpoch: UInt64
        public init(request: ResolveDead, anchor: Lifecycle.ServiceState, receipt: Lifecycle.Receipt,
                    successor: Lifecycle.ServiceState, successorOrigin: Adoption.Origin, baseEpoch: UInt64) throws {
            self.request = request; self.anchor = anchor; self.receipt = receipt
            self.successor = successor; self.successorOrigin = successorOrigin; self.baseEpoch = baseEpoch
            try validate()
        }
        public func validate() throws {
            try request.validate(); try anchor.validate(); try receipt.validate(); try successor.validate()
            try successorOrigin.validate()
            let root = try StorageIdentity.RootPublicKey(publicData: successorOrigin.rootPublicKey)
            guard baseEpoch > 1, anchor.grant.identity == request.identity,
                  receipt.grant.identity == request.identity, receipt.grant.operation == .takeover,
                  receipt.grant.id == request.operationID, receipt.grant == successor.grant,
                  receipt.serviceEpoch == successor.context.serviceEpoch,
                  receipt.revision == successor.openRevision,
                  receipt.grant.serial > anchor.grant.serial,
                  anchor.context.controllerEpoch < UInt64.max,
                  successor.context.controllerEpoch == anchor.context.controllerEpoch + 1,
                  successor.context.controllerKey != anchor.context.controllerKey,
                  successor.context.serviceEpoch != anchor.context.serviceEpoch,
                  successor.openRevision > anchor.openRevision,
                  successor.boot.tlsRootSHA256 != anchor.boot.tlsRootSHA256,
                  successor.boot.serverSPKI != anchor.boot.serverSPKI,
                  successor.boot.bootstrapKey == root.fingerprint.rawValue,
                  anchor.boot.bootstrapKey == root.fingerprint.rawValue,
                  try request.identity == Lifecycle.Identity(binding: successorOrigin.binding.value(),
                    generation: request.identity.generation) else { throw Lifecycle.ValidationError.invalidValue }
        }
        public func validate(prepared: Prepared, anchor expected: Lifecycle.ServiceState) throws {
            try validate(); try prepared.validate(); try expected.validate()
            guard prepared.recoveryBridge == nil, anchor == expected,
                  request.operationID == prepared.signedOpen.request.operationID,
                  request.signedOpenSHA256 == (try prepared.signedOpenSHA256),
                  receipt.grant == prepared.signedOpen.request.takeover.grant,
                  successorOrigin == prepared.successorOrigin, baseEpoch == prepared.baseEpoch,
                  prepared.signedOpen.request.predecessor == (try protectedPredecessor(anchor)) else {
                throw StorageIdentity.ValidationError.correlationMismatch
            }
        }
    }
    private static func protectedPredecessor(_ service: Lifecycle.ServiceState) throws -> Cold.Predecessor {
        try .init(currentGrant: service.grant, serviceEpoch: service.context.serviceEpoch,
            controllerEpoch: service.context.controllerEpoch, controllerKey: service.context.controllerKey,
            openRevision: service.openRevision, bootstrapKey: service.boot.bootstrapKey)
    }

    public struct Prepared: Codable, Equatable, Sendable {
        /// Exact authorization, including inner and outer signatures; already heap-backed.
        public let signedOpen: Cold.SignedOpen
        public let successorOrigin: Adoption.Origin
        /// Fresh enrollment allocation, strictly above the protected old high-water mark.
        public let baseEpoch: UInt64
        /// Omitted for ordinary cold operations: existing sole-v2 bytes stay canonical.
        public let recoveryBridge: ResolvedDead?
        public init(signedOpen: Cold.SignedOpen, successorOrigin: Adoption.Origin, baseEpoch: UInt64,
                    recoveryBridge: ResolvedDead? = nil) throws {
            self.signedOpen = signedOpen; self.successorOrigin = successorOrigin; self.baseEpoch = baseEpoch
            self.recoveryBridge = recoveryBridge; try validate()
        }
        public func validate() throws {
            try signedOpen.validate(); try successorOrigin.validate()
            let r = signedOpen.request, root = try StorageIdentity.RootPublicKey(publicData: successorOrigin.rootPublicKey)
            guard signedOpen.isValidSignature(using: root), baseEpoch > 1,
                  try r.takeover.grant.identity == Lifecycle.Identity(binding: successorOrigin.binding.value(), generation: r.takeover.grant.identity.generation),
                  r.launch.shimLaunchUUID == successorOrigin.shimLaunchUUID, r.launch.specSHA256 == successorOrigin.specSHA256,
                  r.launch.ext4UUID == successorOrigin.binding.ext4UUID, r.launch.bytes == successorOrigin.binding.bytes else {
                throw Lifecycle.ValidationError.invalidValue
            }
            if let recoveryBridge {
                try recoveryBridge.validate()
                guard r.predecessor == (try protectedPredecessor(recoveryBridge.successor)),
                      r.takeover.grant.identity == recoveryBridge.request.identity,
                      r.takeover.grant.serial > recoveryBridge.receipt.grant.serial,
                      r.takeover.grant.newKey != recoveryBridge.successor.context.controllerKey,
                      r.operationID != recoveryBridge.request.operationID,
                      r.operationID != recoveryBridge.request.resolutionID,
                      successorOrigin.rootPublicKey == recoveryBridge.successorOrigin.rootPublicKey,
                      successorOrigin.shimLaunchUUID != recoveryBridge.successorOrigin.shimLaunchUUID,
                      recoveryBridge.baseEpoch < UInt64.max, baseEpoch == recoveryBridge.baseEpoch + 1 else {
                    throw StorageIdentity.ValidationError.correlationMismatch
                }
            }
        }
        public func validate(for prepare: Prepare) throws {
            try validate(); try prepare.validate()
            let r = signedOpen.request, g = r.takeover.grant
            guard r.operationID == prepare.operationID, r.predecessor == prepare.expectedPredecessor,
                  g.identity == prepare.identity, g.newKey == prepare.candidate.publicKey.fingerprint.rawValue,
                  r.launch == prepare.mountedGreeting.launch, r.nowUnixSeconds == prepare.nowUnixSeconds,
                  r.lifetimeSeconds == prepare.lifetimeSeconds, successorOrigin == (try prepare.mountedGreeting.successorOrigin),
                  baseEpoch == prepare.expectedAllocatedEpoch + 1 else { throw StorageIdentity.ValidationError.correlationMismatch }
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
        public let recoveryBridge: ResolvedDead?
        public init(operationID: String, signedOpenSHA256: String, successorOrigin: Adoption.Origin, baseEpoch: UInt64,
                    receipt: Lifecycle.Receipt, successor: Lifecycle.ServiceState, recoveryBridge: ResolvedDead? = nil) throws {
            self.operationID = operationID; self.signedOpenSHA256 = signedOpenSHA256; self.successorOrigin = successorOrigin
            self.baseEpoch = baseEpoch; self.receipt = receipt; self.successor = successor
            self.recoveryBridge = recoveryBridge; try validate()
        }
        public func validate() throws {
            _ = try StorageIdentity.GrantID(operationID); _ = try StorageIdentity.SPKISHA256(signedOpenSHA256)
            try successorOrigin.validate(); try receipt.validate(); try successor.validate()
            guard baseEpoch > 1, receipt.grant.operation == .takeover, receipt.grant.id == operationID,
                  receipt.grant == successor.grant, receipt.serviceEpoch == successor.context.serviceEpoch,
                  receipt.revision == successor.openRevision,
                  try successor.grant.identity == Lifecycle.Identity(binding: successorOrigin.binding.value(), generation: successor.grant.identity.generation),
                  try successor.boot.bootstrapKey == StorageIdentity.RootPublicKey(publicData: successorOrigin.rootPublicKey).fingerprint.rawValue else {
                throw Lifecycle.ValidationError.invalidValue
            }
            if let recoveryBridge {
                try recoveryBridge.validate()
                guard receipt.grant.identity == recoveryBridge.request.identity,
                      receipt.grant.expectedEpoch == recoveryBridge.successor.context.controllerEpoch,
                      receipt.grant.serial > recoveryBridge.receipt.grant.serial,
                      receipt.grant.newKey != recoveryBridge.successor.context.controllerKey,
                      successor.context.serviceEpoch != recoveryBridge.successor.context.serviceEpoch,
                      successorOrigin.rootPublicKey == recoveryBridge.successorOrigin.rootPublicKey,
                      operationID != recoveryBridge.request.operationID,
                      operationID != recoveryBridge.request.resolutionID,
                      successorOrigin.shimLaunchUUID != recoveryBridge.successorOrigin.shimLaunchUUID,
                      recoveryBridge.baseEpoch < UInt64.max, baseEpoch == recoveryBridge.baseEpoch + 1 else {
                    throw StorageIdentity.ValidationError.correlationMismatch
                }
            }
        }
        public func validate(prepared: Prepared) throws {
            try validate(); try prepared.validate()
            guard recoveryBridge == prepared.recoveryBridge else { throw StorageIdentity.ValidationError.correlationMismatch }
            guard signedOpenSHA256 == (try prepared.signedOpenSHA256), receipt.grant == prepared.signedOpen.request.takeover.grant,
                  successorOrigin == prepared.successorOrigin, baseEpoch == prepared.baseEpoch,
                  successor.context.serviceEpoch != prepared.signedOpen.request.predecessor.serviceEpoch else {
                throw StorageIdentity.ValidationError.correlationMismatch
            }
        }
    }

    public enum Eligibility: String, Codable, Sendable {
        /// Only positive exit evidence for the protected old native process permits
        /// the helper to report this. Never inferred from socket loss or caller input.
        case eligible
        case live
        /// Missing/ambiguous native evidence, unsupported state, or unavailable checks.
        case unavailable
    }
    public struct Status: Codable, Equatable, Sendable {
        public let predecessor: Cold.Predecessor
        public let origin: Adoption.Origin
        public let allocatedEpoch: UInt64
        public let eligibility: Eligibility
        public init(predecessor: Cold.Predecessor, origin: Adoption.Origin, allocatedEpoch: UInt64, eligibility: Eligibility) throws {
            self.predecessor = predecessor; self.origin = origin; self.allocatedEpoch = allocatedEpoch
            self.eligibility = eligibility; try validate()
        }
        public func validate() throws {
            try validateProtected(identity: predecessor.currentGrant.identity, predecessor: predecessor, origin: origin, allocatedEpoch: allocatedEpoch)
        }
    }
    private static func validateProtected(identity: Lifecycle.Identity, predecessor: Cold.Predecessor,
                                          origin: Adoption.Origin, allocatedEpoch: UInt64) throws {
        try identity.validate(); try predecessor.validate(); try origin.validate()
        guard identity == predecessor.currentGrant.identity, allocatedEpoch > 0,
              try identity == Lifecycle.Identity(binding: origin.binding.value(), generation: identity.generation),
              try predecessor.bootstrapKey == StorageIdentity.RootPublicKey(publicData: origin.rootPublicKey).fingerprint.rawValue else {
            throw Lifecycle.ValidationError.invalidValue
        }
    }
    public enum Body: Equatable, Sendable {
        case status(Lifecycle.Identity)
        case prepare(Prepare)
        case complete(operationID: String, signedOpenSHA256: String)
        case resolveDead(ResolveDead)
    }
    public struct Request: Equatable, Sendable {
        public let requestID: StorageIdentity.RequestID
        public let body: Body
        public init(requestID: StorageIdentity.RequestID, body: Body) throws {
            self.requestID = requestID; self.body = body
            switch body {
            case .status(let identity): try identity.validate()
            case .prepare(let prepare): try prepare.validate()
            case .complete(let id, let digest): _ = try StorageIdentity.GrantID(id); _ = try StorageIdentity.SPKISHA256(digest)
            case .resolveDead(let value): try value.validate()
            }
        }
    }
    public enum ResultBody: Equatable, Sendable {
        case status(Status), prepared(Prepared), completed(Completed), resolvedDead(ResolvedDead), failure(StorageIdentity.ErrorCode)
    }
    public struct Reply: Equatable, Sendable {
        public let requestID: StorageIdentity.RequestID
        public let operation: String
        public let requestSHA256: String
        public let body: ResultBody
        public init(for request: Request, body: ResultBody) throws {
            switch (request.body, body) {
            case (_, .failure): break
            case (.status(let identity), .status(let status)):
                try status.validate()
                guard status.predecessor.currentGrant.identity == identity else { throw StorageIdentity.ValidationError.correlationMismatch }
            case (.prepare(let prepare), .prepared(let prepared)): try prepared.validate(for: prepare)
            case (.complete(let id, let digest), .completed(let completed)):
                try completed.validate()
                guard completed.operationID == id, completed.signedOpenSHA256 == digest else { throw StorageIdentity.ValidationError.correlationMismatch }
            case (.resolveDead(let requested), .resolvedDead(let resolved)):
                try resolved.validate()
                guard requested == resolved.request else { throw StorageIdentity.ValidationError.correlationMismatch }
            default: throw StorageIdentity.ValidationError.correlationMismatch
            }
            requestID = request.requestID; operation = packet(request).operation
            requestSHA256 = try hash(packet(request), domain: "request"); self.body = body
        }
    }
    private struct Packet: Codable {
        var version = StorageLifecycleColdRootProtocol.version
        var requestID: String
        var operation: String
        var identity: Lifecycle.Identity?
        var prepare: Prepare?
        var operationID: String?
        var signedOpenSHA256: String?
        var requestSHA256: String?
        var status: Status?
        var prepared: Prepared?
        var completed: Completed?
        var resolveDead: ResolveDead?
        var resolvedDead: ResolvedDead?
        var error: String?
    }
    private static func packet(_ request: Request) -> Packet {
        var p = Packet(requestID: request.requestID.rawValue, operation: "status")
        switch request.body {
        case .status(let identity): p.identity = identity
        case .prepare(let prepare): p.operation = "prepare"; p.prepare = prepare
        case .complete(let id, let digest): p.operation = "complete"; p.operationID = id; p.signedOpenSHA256 = digest
        case .resolveDead(let value): p.operation = "resolve-dead"; p.resolveDead = value
        }
        return p
    }
    private static func packet(_ reply: Reply) -> Packet {
        var p = Packet(requestID: reply.requestID.rawValue, operation: reply.operation, requestSHA256: reply.requestSHA256)
        switch reply.body {
        case .status(let value): p.status = value
        case .prepared(let value): p.prepared = value
        case .completed(let value): p.completed = value
        case .resolvedDead(let value): p.resolvedDead = value
        case .failure(let code): p.error = code.rawValue
        }
        return p
    }
    private static func hash<T: Encodable>(_ value: T, domain: String) throws -> String {
        SHA256.hash(data: Data("cengine.storage-lifecycle-cold-root.\(domain).v1\0".utf8) + (try Lifecycle.encode(value)))
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
        case "status": body = .status(try required(p.identity))
        case "prepare": body = .prepare(try required(p.prepare))
        case "complete": body = .complete(operationID: try required(p.operationID), signedOpenSHA256: try required(p.signedOpenSHA256))
        case "resolve-dead": body = .resolveDead(try required(p.resolveDead))
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
            case .status: body = .status(try required(p.status))
            case .prepare: body = .prepared(try required(p.prepared))
            case .complete: body = .completed(try required(p.completed))
            case .resolveDead: body = .resolvedDead(try required(p.resolvedDead))
            }
        }
        let value = try Reply(for: request, body: body)
        guard try encode(value) == bytes else { throw StorageIdentity.ValidationError.correlationMismatch }; return value
    }
}

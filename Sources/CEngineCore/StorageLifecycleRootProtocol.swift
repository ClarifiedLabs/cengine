import CryptoKit
import Foundation

/// Daemon-to-root-helper RPC. Values and unsigned receipts are not capabilities;
/// only a natively authenticated ROOT exchange establishes their provenance.
public enum StorageLifecycleRootProtocol {
    public typealias Bootstrap = StorageIdentity
    public typealias Lifecycle = StorageLifecycleProtocol
    public static let version = "storage-root-lifecycle.v2"
    public static let maximumPayloadBytes = Lifecycle.maximumPayloadBytes
    public static let xpcOperation = "storage-lifecycle-root"

    public enum Body: Equatable, Sendable {
        case rootPublicKey
        case stageServiceChange(change: Lifecycle.ServiceChangeRequest)
        case serviceBootTrust(identity: Lifecycle.Identity, grantID: String, serviceChangeID: String?)
        case serviceResult(identity: Lifecycle.Identity, grantID: String)
        case completeServiceChange(identity: Lifecycle.Identity, operationID: String)
        case provision(id: String, binding: StorageIdentity.StoreBinding, candidate: StorageIdentity.Candidate, initialDescriptors: Bool)
        case issue(operation: Lifecycle.Operation, id: String, identity: Lifecycle.Identity, expectedEpoch: UInt64, candidate: StorageIdentity.Candidate)
        case read(identity: Lifecycle.Identity, id: String)
        case complete(identity: Lifecycle.Identity, id: String)
        case reclaim(identity: Lifecycle.Identity, id: String)
        case status(identity: Lifecycle.Identity)
    }
    public struct Request: Equatable, Sendable {
        public let requestID: StorageIdentity.RequestID
        public let body: Body
        public init(requestID: StorageIdentity.RequestID, body: Body) throws {
            self.requestID = requestID; self.body = body
            switch body {
            case .provision(let id, _, _, _): _ = try StorageIdentity.GrantID(id)
            case .issue(let op, let id, let identity, let epoch, let candidate):
                guard op != .initialize else { throw Lifecycle.ValidationError.invalidMessage }
                _ = try Lifecycle.Grant(operation: op, id: id, identity: identity, serial: 1,
                    expectedEpoch: epoch, newKey: candidate.publicKey.fingerprint.rawValue)
            case .read(let identity, let id), .complete(let identity, let id), .reclaim(let identity, let id):
                try identity.validate(); _ = try StorageIdentity.GrantID(id)
            case .status(let identity): try identity.validate()
            case .stageServiceChange(let change): try change.validate()
            case .serviceBootTrust(let identity, let grantID, let serviceChangeID):
                try identity.validate(); _ = try StorageIdentity.GrantID(grantID)
                if let serviceChangeID { _ = try StorageIdentity.GrantID(serviceChangeID) }
            case .serviceResult(let identity, let id), .completeServiceChange(let identity, let id):
                try identity.validate(); _ = try StorageIdentity.GrantID(id)
            case .rootPublicKey: break
            }
        }
        public var requiresDescriptors: Bool {
            if case .provision(_, _, _, let initial) = body { return initial }; return false
        }
    }
    public enum ResultBody: Equatable, Sendable {
        /// Public verifier only: not controller authority or TLS trust.
        case rootPublicKey(StorageIdentity.RootPublicKey)
        case grant(Lifecycle.SignedGrant)
        /// ROOT's authenticated report, not a transferable unsigned proof.
        case completed(Lifecycle.Receipt)
        case reclaimed
        case status(StorageIdentity.Controller)
        /// ROOT-signed staged request; verify with the pinned root key before use.
        case serviceChangeStaged(Lifecycle.SignedServiceChange)
        case serviceBootTrust(StorageLifecycleBootTrust, grantID: String, serviceChangeID: String?)
        case serviceResult(Lifecycle.ServiceResult)
        case serviceChanged(Lifecycle.ServiceChangeConfirmation, Lifecycle.ServiceResult)
        case failure(StorageIdentity.ErrorCode)
    }
    public struct Reply: Equatable, Sendable {
        public let requestID: StorageIdentity.RequestID
        public let operation: String
        public let requestSHA256: String
        public let body: ResultBody
        public init(for request: Request, body: ResultBody) throws {
            guard Self.matches(body, request.body) else { throw StorageIdentity.ValidationError.correlationMismatch }
            requestID = request.requestID; operation = packet(request).operation
            requestSHA256 = try digest(request); self.body = body
        }
        private static func matches(_ body: ResultBody, _ request: Body) -> Bool {
            switch (body, request) {
            case (.failure, _), (.rootPublicKey, .rootPublicKey), (.reclaimed, .reclaim), (.status, .status): return true
            case (.grant(let signed), .provision(let id, let binding, let candidate, _)):
                let g = signed.grant
                return g.operation == .initialize && g.id == id && g.identity.store == binding.storeID.rawValue &&
                    g.identity.binding == Lifecycle.bindingDigest(binding) && g.newKey == candidate.publicKey.fingerprint.rawValue
            case (.grant(let signed), .issue(let op, let id, let identity, let epoch, let candidate)):
                let g = signed.grant
                return g.operation == op && g.id == id && g.identity == identity && g.expectedEpoch == epoch &&
                    g.newKey == candidate.publicKey.fingerprint.rawValue
            case (.grant(let signed), .read(let identity, let id)): return signed.grant.identity == identity && signed.grant.id == id
            case (.completed(let receipt), .complete(let identity, let id)): return receipt.grant.identity == identity && receipt.grant.id == id
            case (.serviceChangeStaged(let staged), .stageServiceChange(let change)): return staged.request == change
            case (.serviceBootTrust(let boot, let grantID, let changeID), .serviceBootTrust(let identity, let requestedGrant, let requestedChange)):
                return boot.identity == identity && grantID == requestedGrant && changeID == requestedChange
            case (.serviceResult(let result), .serviceResult(let identity, let id)):
                return result.identity == identity && result.grant.id == id
            case (.serviceChanged(let confirmation, let result), .completeServiceChange(let identity, let id)):
                return confirmation.request.operationID == id && confirmation.successor.grant.identity == identity &&
                    (try? result.state(boot: confirmation.successor.boot)) == confirmation.successor
            default: return false
            }
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
    /// Reconstructed per-operation before comparison; optional fields are NOT an
    /// open schema. Unknown, duplicate, missing, null and cross-operation fields fail.
    private struct Packet: Codable {
        var version = StorageLifecycleRootProtocol.version
        var requestID: String
        var operation: String
        var id: String?
        var binding: StorageLifecycleStoreBinding?
        var candidate: Candidate?
        var initialDescriptors: Bool?
        var grantOperation: Lifecycle.Operation?
        var identity: Lifecycle.Identity?
        var expectedEpoch: UInt64?
        var requestSHA256: String?
        var rootPublicKey: Data?
        var grant: Lifecycle.SignedGrant?
        var receipt: Lifecycle.Receipt?
        var epoch: UInt64?
        var key: String?
        var error: String?
        var change: Lifecycle.ServiceChangeRequest?
        var signedChange: Lifecycle.SignedServiceChange?
        var serviceChangeID: String?
        var boot: StorageLifecycleBootTrust?
        var serviceResult: Lifecycle.ServiceResult?
        var confirmation: Lifecycle.ServiceChangeConfirmation?
        private enum CodingKeys: String, CodingKey {
            case version, requestID, operation, id, binding, candidate, initialDescriptors, grantOperation, identity
            case expectedEpoch, requestSHA256, rootPublicKey, grant, receipt, epoch, key, error, change, boot, confirmation
            case serviceChangeID = "service_change_id", serviceResult = "service_result", signedChange = "signed_change"
        }
    }
    private static func packet(_ request: Request) -> Packet {
        var p = Packet(requestID: request.requestID.rawValue, operation: "")
        switch request.body {
        case .rootPublicKey: p.operation = "rootPublicKey"
        case .provision(let id, let binding, let candidate, let initial):
            p.operation = "provision"; p.id = id; p.binding = .init(binding); p.candidate = .init(candidate); p.initialDescriptors = initial
        case .issue(let op, let id, let identity, let epoch, let candidate):
            p.operation = "issue"; p.grantOperation = op; p.id = id; p.identity = identity; p.expectedEpoch = epoch; p.candidate = .init(candidate)
        case .read(let identity, let id): p.operation = "read"; p.identity = identity; p.id = id
        case .complete(let identity, let id): p.operation = "complete"; p.identity = identity; p.id = id
        case .reclaim(let identity, let id): p.operation = "reclaim"; p.identity = identity; p.id = id
        case .status(let identity): p.operation = "status"; p.identity = identity
        case .stageServiceChange(let change): p.operation = "stageServiceChange"; p.change = change
        case .serviceBootTrust(let identity, let id, let changeID):
            p.operation = "serviceBootTrust"; p.identity = identity; p.id = id; p.serviceChangeID = changeID
        case .serviceResult(let identity, let id): p.operation = "serviceResult"; p.identity = identity; p.id = id
        case .completeServiceChange(let identity, let id): p.operation = "completeServiceChange"; p.identity = identity; p.id = id
        }
        return p
    }
    private static func required<T>(_ value: T?) throws -> T {
        guard let value else { throw Lifecycle.ValidationError.invalidMessage }; return value
    }
    private static func digest(_ request: Request) throws -> String {
        SHA256.hash(data: try encode(request)).map { String(format: "%02x", $0) }.joined()
    }
    public static func encode(_ request: Request) throws -> Data { try Lifecycle.encode(packet(request)) }
    public static func decodeRequest(_ data: Data) throws -> Request {
        let p = try Lifecycle.decode(Packet.self, from: data)
        let body: Body
        switch p.operation {
        case "rootPublicKey": body = .rootPublicKey
        case "provision": body = try .provision(id: required(p.id), binding: required(p.binding).value(),
            candidate: required(p.candidate).value(), initialDescriptors: required(p.initialDescriptors))
        case "issue": body = try .issue(operation: required(p.grantOperation), id: required(p.id), identity: required(p.identity),
            expectedEpoch: required(p.expectedEpoch), candidate: required(p.candidate).value())
        case "read": body = try .read(identity: required(p.identity), id: required(p.id))
        case "complete": body = try .complete(identity: required(p.identity), id: required(p.id))
        case "reclaim": body = try .reclaim(identity: required(p.identity), id: required(p.id))
        case "status": body = try .status(identity: required(p.identity))
        case "stageServiceChange": body = try .stageServiceChange(change: required(p.change))
        case "serviceBootTrust": body = try .serviceBootTrust(identity: required(p.identity), grantID: required(p.id), serviceChangeID: p.serviceChangeID)
        case "serviceResult": body = try .serviceResult(identity: required(p.identity), grantID: required(p.id))
        case "completeServiceChange": body = try .completeServiceChange(identity: required(p.identity), operationID: required(p.id))
        default: throw Lifecycle.ValidationError.invalidMessage
        }
        let request = try Request(requestID: .init(p.requestID), body: body)
        guard try encode(request) == data else { throw Lifecycle.ValidationError.invalidMessage }
        return request
    }
    public static func encode(_ reply: Reply) throws -> Data {
        var p = Packet(requestID: reply.requestID.rawValue, operation: reply.operation)
        p.requestSHA256 = reply.requestSHA256
        switch reply.body {
        case .rootPublicKey(let key): p.rootPublicKey = key.publicData
        case .grant(let grant): p.grant = grant
        case .completed(let receipt): p.receipt = receipt
        case .reclaimed: break
        case .status(let controller): p.epoch = controller.epoch.rawValue; p.key = controller.key.rawValue
        case .failure(let code): p.error = code.rawValue
        case .serviceChangeStaged(let signed): p.signedChange = signed
        case .serviceBootTrust(let boot, let grantID, let changeID): p.boot = boot; p.id = grantID; p.serviceChangeID = changeID
        case .serviceResult(let result): p.serviceResult = result
        case .serviceChanged(let confirmation, let result): p.confirmation = confirmation; p.serviceResult = result
        }
        return try Lifecycle.encode(p)
    }
    /// Parsing and correlation only. Authenticate the actual native message FIRST.
    public static func decodeReply(_ data: Data, for request: Request) throws -> Reply {
        let p = try Lifecycle.decode(Packet.self, from: data)
        let body: ResultBody
        if let error = p.error { body = .failure(try required(StorageIdentity.ErrorCode(rawValue: error))) }
        else {
            switch request.body {
            case .rootPublicKey: body = try .rootPublicKey(.init(publicData: required(p.rootPublicKey)))
            case .provision, .issue, .read: body = try .grant(required(p.grant))
            case .complete: body = try .completed(required(p.receipt))
            case .stageServiceChange: body = try .serviceChangeStaged(required(p.signedChange))
            case .serviceBootTrust: body = try .serviceBootTrust(required(p.boot), grantID: required(p.id), serviceChangeID: p.serviceChangeID)
            case .serviceResult: body = try .serviceResult(required(p.serviceResult))
            case .completeServiceChange: body = try .serviceChanged(required(p.confirmation), required(p.serviceResult))
            case .reclaim: body = .reclaimed
            case .status: body = try .status(.init(epoch: .init(required(p.epoch)), key: .init(required(p.key))))
            }
        }
        let reply = try Reply(for: request, body: body)
        guard try encode(reply) == data else { throw StorageIdentity.ValidationError.correlationMismatch }
        return reply
    }
}

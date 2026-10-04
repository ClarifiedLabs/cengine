import CryptoKit
import Foundation

/// Scoped daemon/ROOT adoption RPC. Status and replies are metadata, not a native
/// shim session capability. All requests require the three observed lock FDs.
public enum StorageLifecycleAdoptionRootProtocol {
    public typealias Adoption = StorageLifecycleAdoptionProtocol
    public typealias Bootstrap = StorageIdentity
    public typealias Lifecycle = StorageLifecycleProtocol
    public static let version = "storage-adoption-root.v1"
    public static let xpcOperation = "storage-lifecycle-adoption-root"
    public static let maximumPayloadBytes = StorageLifecycleProtocol.maximumPayloadBytes

    public enum Body: Equatable, Sendable {
        case status
        case handoffStatus(Lifecycle.Identity)
        case recoverHandoff(Lifecycle.Identity, operationID: String)
        case prepare(Adoption.Request)
        case complete(Adoption.Request)
        case service(Adoption.Request, StorageLifecycleProtocol.Grant)
        case completeServiceChange(adoption: Adoption.Request, change: StorageLifecycleProtocol.ServiceChangeRequest)
    }
    public struct Request: Equatable, Sendable {
        public let requestID: StorageIdentity.RequestID
        public let body: Body
        public init(requestID: StorageIdentity.RequestID, body: Body) throws {
            self.requestID = requestID; self.body = body
            switch body {
            case .status: break
            case .handoffStatus(let identity): try identity.validate()
            case .recoverHandoff(let identity, let id):
                try identity.validate(); _ = try StorageIdentity.GrantID(id)
            case .completeServiceChange(let adoption, let change):
                try adoption.validate(); try change.validate()
                let predecessor = change.predecessor
                guard try predecessor.grant.identity == Lifecycle.Identity(binding: adoption.origin.binding.value(), generation: predecessor.grant.identity.generation),
                      try predecessor.boot.bootstrapKey == StorageIdentity.RootPublicKey(publicData: adoption.origin.rootPublicKey).fingerprint.rawValue else {
                    throw Lifecycle.ValidationError.invalidValue
                }
            case .service(let request, let grant): try request.validate(); try grant.validate()
            case .prepare(let request), .complete(let request): try request.validate()
            }
        }
    }
    /// Read-only protected-journal projection. A latest commit does not prove that
    /// the shim acknowledged it: retry complete with the exact original request.
    public struct Status: Codable, Equatable, Sendable {
        public let origin: Adoption.Origin
        public let shimAudit: Data
        public let shimUniqueID: UInt64
        public let baseEpoch: UInt64
        public let committedEpoch: UInt64
        public let allocatedEpoch: UInt64
        public let pending: Adoption.Request?
        public let latest: Adoption.Request?
        public init(origin: Adoption.Origin, shimAudit: Data, shimUniqueID: UInt64, baseEpoch: UInt64, committedEpoch: UInt64, allocatedEpoch: UInt64,
                    pending: Adoption.Request?, latest: Adoption.Request?) throws {
            self.origin = origin; self.shimAudit = shimAudit; self.shimUniqueID = shimUniqueID; self.committedEpoch = committedEpoch; self.allocatedEpoch = allocatedEpoch
            self.baseEpoch = baseEpoch; self.pending = pending; self.latest = latest
            try validate()
        }
        public func validate() throws {
            try origin.validate()
            guard shimAudit.count == 32, shimUniqueID > 0 else { throw Lifecycle.ValidationError.invalidMessage }
            guard baseEpoch > 0, committedEpoch >= baseEpoch, allocatedEpoch >= committedEpoch else { throw Lifecycle.ValidationError.invalidMessage }
            if let latest {
                try latest.validate()
                guard latest.origin == origin, latest.expectedEpoch >= baseEpoch, try latest.epoch == committedEpoch else { throw Lifecycle.ValidationError.invalidMessage }
            } else {
                guard committedEpoch == baseEpoch else { throw Lifecycle.ValidationError.invalidMessage }
            }
            if let pending {
                try pending.validate()
                guard pending.origin == origin, try pending.epoch == allocatedEpoch,
                      pending.expectedEpoch >= committedEpoch, pending.id != latest?.id,
                      pending.superseded != nil || pending.expectedEpoch == committedEpoch else {
                    throw Lifecycle.ValidationError.invalidMessage
                }
            } else {
                guard allocatedEpoch == committedEpoch else { throw Lifecycle.ValidationError.invalidMessage }
            }
        }
    }
    public enum ResultBody: Equatable, Sendable {
        case status(Status)
        case handoffStatus(StorageLifecycleHandoffRootProtocol.Status)
        case handoffRecovered(StorageLifecycleHandoffRootProtocol.Completed)
        case prepared(Adoption.FenceIdentity)
        case completed(Adoption.FenceIdentity)
        case service(StorageLifecycleProtocol.ServiceState)
        case serviceChanged(StorageLifecycleProtocol.ServiceChangeConfirmation, StorageLifecycleProtocol.ServiceResult)
        case failure(StorageIdentity.ErrorCode)
    }
    public struct Reply: Equatable, Sendable {
        public let requestID: StorageIdentity.RequestID
        public let operation: String
        public let requestSHA256: String
        public let body: ResultBody
        public init(for request: Request, body: ResultBody) throws {
            switch (request.body, body) {
            case (_, .failure): break
            case (.status, .status(let status)): try status.validate()
            case (.handoffStatus(let identity), .handoffStatus(let status)):
                try status.validate()
                guard status.currentService.grant.identity == identity else { throw StorageIdentity.ValidationError.correlationMismatch }
            case (.recoverHandoff(let identity, let id), .handoffRecovered(let completed)):
                try completed.validate()
                guard completed.operationID == id, completed.service.grant.identity == identity else { throw StorageIdentity.ValidationError.correlationMismatch }
            case (.completeServiceChange(_, let change), .serviceChanged(let confirmation, let result)):
                try confirmation.validate(); try result.validate()
                guard confirmation.request == change,
                      try result.state(boot: confirmation.successor.boot) == confirmation.successor else {
                    throw StorageIdentity.ValidationError.correlationMismatch
                }
            case (.service(_, let grant), .service(let result)):
                try result.validate()
                guard result.grant == grant else { throw StorageIdentity.ValidationError.correlationMismatch }
            case (.prepare(let request), .prepared(let fence)), (.complete(let request), .completed(let fence)):
                try fence.validate()
                guard try request.fenceIdentity == fence else { throw StorageIdentity.ValidationError.correlationMismatch }
            default: throw StorageIdentity.ValidationError.correlationMismatch
            }
            requestID = request.requestID; operation = packet(request).operation
            requestSHA256 = try digest(request); self.body = body
        }
    }
    private struct Packet: Codable {
        var version = StorageLifecycleAdoptionRootProtocol.version
        var requestID: String
        var operation: String
        var adoption: Adoption.Request?
        var identity: Lifecycle.Identity?
        var operationID: String?
        var handoffStatus: StorageLifecycleHandoffRootProtocol.Status?
        var handoffCompleted: StorageLifecycleHandoffRootProtocol.Completed?
        var grant: StorageLifecycleProtocol.Grant?
        var service: StorageLifecycleProtocol.ServiceState?
        var change: StorageLifecycleProtocol.ServiceChangeRequest?
        var confirmation: StorageLifecycleProtocol.ServiceChangeConfirmation?
        var serviceResult: StorageLifecycleProtocol.ServiceResult?
        var requestSHA256: String?
        var status: Status?
        var fence: Adoption.FenceIdentity?
        var error: String?
    }
    private static func packet(_ request: Request) -> Packet {
        var result = Packet(requestID: request.requestID.rawValue, operation: "status")
        switch request.body {
        case .status: break
        case .handoffStatus(let identity): result.operation = "handoffStatus"; result.identity = identity
        case .recoverHandoff(let identity, let id):
            result.operation = "recoverHandoff"; result.identity = identity; result.operationID = id
        case .prepare(let value): result.operation = "prepare"; result.adoption = value
        case .complete(let value): result.operation = "complete"; result.adoption = value
        case .service(let value, let grant): result.operation = "service"; result.adoption = value; result.grant = grant
        case .completeServiceChange(let adoption, let change):
            result.operation = "completeServiceChange"; result.adoption = adoption; result.change = change
        }
        return result
    }
    private static func packet(_ reply: Reply) -> Packet {
        var result = Packet(requestID: reply.requestID.rawValue, operation: reply.operation,
                            requestSHA256: reply.requestSHA256)
        switch reply.body {
        case .status(let status): result.status = status
        case .handoffStatus(let status): result.handoffStatus = status
        case .handoffRecovered(let completed): result.handoffCompleted = completed
        case .prepared(let fence), .completed(let fence): result.fence = fence
        case .service(let value): result.service = value
        case .serviceChanged(let confirmation, let serviceResult):
            result.confirmation = confirmation; result.serviceResult = serviceResult
        case .failure(let code): result.error = code.rawValue
        }
        return result
    }
    private static func required<T>(_ value: T?) throws -> T {
        guard let value else { throw Lifecycle.ValidationError.invalidMessage }; return value
    }
    private static func digest(_ request: Request) throws -> String {
        SHA256.hash(data: try encode(request)).map { String(format: "%02x", $0) }.joined()
    }
    public static func encode(_ request: Request) throws -> Data { try Lifecycle.encode(packet(request)) }
    public static func encode(_ reply: Reply) throws -> Data { try Lifecycle.encode(packet(reply)) }
    public static func decodeRequest(_ bytes: Data) throws -> Request {
        let p = try Lifecycle.decode(Packet.self, from: bytes)
        let body: Body
        switch p.operation {
        case "status": body = .status
        case "handoffStatus": body = .handoffStatus(try required(p.identity))
        case "recoverHandoff": body = .recoverHandoff(try required(p.identity), operationID: try required(p.operationID))
        case "prepare": body = .prepare(try required(p.adoption))
        case "complete": body = .complete(try required(p.adoption))
        case "service": body = .service(try required(p.adoption), try required(p.grant))
        case "completeServiceChange": body = .completeServiceChange(adoption: try required(p.adoption), change: try required(p.change))
        default: throw Lifecycle.ValidationError.invalidMessage
        }
        let request = try Request(requestID: .init(p.requestID), body: body)
        guard try encode(request) == bytes else { throw Lifecycle.ValidationError.invalidMessage }
        return request
    }
    public static func decodeReply(_ bytes: Data, for request: Request) throws -> Reply {
        let p = try Lifecycle.decode(Packet.self, from: bytes)
        let body: ResultBody
        if let error = p.error {
            guard let code = StorageIdentity.ErrorCode(rawValue: error) else { throw Lifecycle.ValidationError.invalidMessage }
            body = .failure(code)
        }
        else {
            switch request.body {
            case .status: body = .status(try required(p.status))
            case .handoffStatus: body = .handoffStatus(try required(p.handoffStatus))
            case .recoverHandoff: body = .handoffRecovered(try required(p.handoffCompleted))
            case .prepare: body = .prepared(try required(p.fence))
            case .complete: body = .completed(try required(p.fence))
            case .service: body = .service(try required(p.service))
            case .completeServiceChange: body = .serviceChanged(try required(p.confirmation), try required(p.serviceResult))
            }
        }
        let reply = try Reply(for: request, body: body)
        guard try encode(reply) == bytes else { throw StorageIdentity.ValidationError.correlationMismatch }
        return reply
    }
}

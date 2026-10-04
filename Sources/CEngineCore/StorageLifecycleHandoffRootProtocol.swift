import Foundation

/// Value-only ROOT projections. Status is not proof; Completed is evidence only
/// when returned by the independently authenticated, scope-bound ROOT channel.
public enum StorageLifecycleHandoffRootProtocol {
    public typealias L = StorageLifecycleProtocol
    public typealias H = StorageLifecycleHandoffProtocol

    public struct Completed: Codable, Equatable, Sendable {
        public let signedRequest: H.SignedRequest
        /// Immutable signature over the original abandoned grant, never a new recipient grant.
        public let pendingSigned: L.SignedGrant?
        public let result: H.Result
        public let predecessorService: L.ServiceState
        public let predecessorReceipt: L.Receipt
        public let service: L.ServiceState
        public let receipt: L.Receipt
        public var operationID: String { signedRequest.request.operationID }
        public init(signedRequest: H.SignedRequest, result: H.Result,
                    predecessorService: L.ServiceState, predecessorReceipt: L.Receipt,
                    service: L.ServiceState, receipt: L.Receipt, pendingSigned: L.SignedGrant? = nil) throws {
            self.signedRequest = signedRequest; self.result = result; self.pendingSigned = pendingSigned
            self.predecessorService = predecessorService; self.predecessorReceipt = predecessorReceipt
            self.service = service; self.receipt = receipt
            try validate()
        }
        public func validate() throws {
            try signedRequest.validate(); try result.validate()
            try predecessorService.validate(); try predecessorReceipt.validate()
            try service.validate(); try receipt.validate()
            let r = signedRequest.request
            if let pendingSigned {
                try pendingSigned.validate()
                guard pendingSigned.grant == r.pending else { throw L.ValidationError.invalidValue }
            }
            guard predecessorService.boot.bootstrapKey == service.boot.bootstrapKey,
                  result.request == r, predecessorService.grant == r.predecessor,
                  predecessorReceipt.grant == r.predecessor,
                  predecessorService.context.serviceEpoch == r.serviceEpoch,
                  predecessorService.openRevision == r.openRevision,
                  service.boot == predecessorService.boot, service.openRevision == r.openRevision,
                  service.grant == result.appliedGrant, receipt.grant == result.appliedGrant,
                  receipt.serviceEpoch == result.appliedServiceEpoch, receipt.revision == result.appliedRevision
            else { throw L.ValidationError.invalidValue }
            if result.appliedGrant == r.predecessor {
                guard service == predecessorService, receipt == predecessorReceipt else { throw L.ValidationError.invalidValue }
            } else {
                guard receipt.revision > predecessorReceipt.revision else { throw L.ValidationError.invalidValue }
            }
        }
    }

    public struct Status: Codable, Equatable, Sendable {
        public let currentService: L.ServiceState
        /// Raw protected grant, including when HOST lost the issue reply.
        public let pending: L.Grant?
        public let operationID: String?
        /// Historical durable disposition, not fresh live proof. Retry recover.
        public let completion: Completed?
        public init(currentService: L.ServiceState, pending: L.Grant?, operationID: String?, completion: Completed?) throws {
            self.currentService = currentService; self.pending = pending
            self.operationID = operationID; self.completion = completion; try validate()
        }
        public func validate() throws {
            try currentService.validate()
            if let operationID { _ = try StorageIdentity.GrantID(operationID) }
            if let pending {
                try pending.validate()
                guard pending.operation == .takeover, pending.identity == currentService.grant.identity,
                      pending.expectedEpoch == currentService.context.controllerEpoch,
                      pending.serial > currentService.grant.serial, pending.id != currentService.grant.id,
                      pending.newKey != currentService.grant.newKey else { throw L.ValidationError.invalidValue }
            }
            if let completion {
                try completion.validate()
                guard operationID == completion.operationID, currentService == completion.service else { throw L.ValidationError.invalidValue }
            } else if operationID != nil && pending == nil { throw L.ValidationError.invalidValue }
        }
    }
    public static func encode(_ value: Status) throws -> Data { try value.validate(); return try L.encode(value) }
    public static func encode(_ value: Completed) throws -> Data { try value.validate(); return try L.encode(value) }
    public static func decodeStatus(_ bytes: Data) throws -> Status {
        let value = try L.decode(Status.self, from: bytes); try value.validate(); return value
    }
    public static func decodeCompleted(_ bytes: Data) throws -> Completed {
        let value = try L.decode(Completed.self, from: bytes); try value.validate(); return value
    }
}

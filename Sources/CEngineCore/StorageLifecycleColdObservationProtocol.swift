import CryptoKit
import Foundation

/// Read-only lifecycle journal evidence. Neither an observation nor its protected
/// history is a receipt, service state, TLS trust, or native process-death proof.
public enum StorageLifecycleColdObservationProtocol {
    public typealias C = StorageLifecycleColdProtocol
    public typealias L = StorageLifecycleProtocol
    public typealias ColdRoot = StorageLifecycleColdRootProtocol
    public typealias Adoption = StorageLifecycleAdoptionProtocol
    public static let maximumSubjectBytes = 64 * 1024

    public struct Request: Codable, Equatable, Sendable {
        public let observationID: String
        public let subject: Data
        public let observer: C.Launch
        public init(observationID: String, subject: Data, observer: C.Launch) throws {
            self.observationID = observationID; self.subject = subject; self.observer = observer
            try validate()
        }
        public func subjectOpen() throws -> C.SignedOpen {
            guard !subject.isEmpty, subject.count <= maximumSubjectBytes else { throw L.ValidationError.payloadTooLarge }
            // Reject recursion BEFORE decoding a typed request. A recursive base64
            // subject must never grow the decoder/validation call stack.
            guard let object = try JSONSerialization.jsonObject(with: subject) as? [String: Any],
                  let request = object["request"] as? [String: Any], request["observation"] == nil else {
                throw L.ValidationError.invalidMessage
            }
            let value = try L.decode(C.SignedOpen.self, from: subject)
            guard value.request.observation == nil else { throw L.ValidationError.invalidValue }
            return value
        }
        public func validate() throws {
            _ = try StorageIdentity.IncarnationID(observationID); try observer.validate()
            let old = try subjectOpen().request
            guard observationID != old.operationID, observer.shimLaunchUUID != old.launch.shimLaunchUUID,
                  observer.ext4UUID == old.launch.ext4UUID, observer.bytes == old.launch.bytes else {
                throw L.ValidationError.invalidValue
            }
        }
        enum CodingKeys: String, CodingKey { case observationID = "observation_id", subject, observer }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            try self.init(observationID: c.decode(String.self, forKey: .observationID),
                subject: c.decode(Data.self, forKey: .subject), observer: c.decode(C.Launch.self, forKey: .observer))
        }
        var signingJSON: String {
            "{\"observation_id\":\"\(observationID)\",\"subject\":\"\(subject.base64EncodedString())\",\"observer\":\(observer.signingJSON)}"
        }
        public var signingBytes: Data { Data(("cengine.storageauthority.lifecycle-cold-observe.v1\0" + signingJSON).utf8) }
        public var digest: String { SHA256.hash(data: signingBytes).map { String(format: "%02x", $0) }.joined() }
    }
    public struct SignedRequest: Codable, Equatable, Sendable {
        private final class Value: Sendable {
            let request: Request
            let signature: Data
            init(request: Request, signature: Data) { self.request = request; self.signature = signature }
        }
        private let value: Value
        public var request: Request { value.request }
        public var signature: Data { value.signature }
        public init(request: Request, signature: Data) throws {
            value = Value(request: request, signature: signature); try validate()
        }
        public static func == (lhs: Self, rhs: Self) -> Bool { lhs.request == rhs.request && lhs.signature == rhs.signature }
        public func validate() throws {
            try request.validate()
            guard signature.count == 64 else { throw L.ValidationError.invalidSignature }
        }
        public func isValidSignature(using root: StorageIdentity.RootPublicKey) -> Bool {
            guard (try? validate()) != nil, let old = try? request.subjectOpen(),
                  root.fingerprint.rawValue == old.request.predecessor.bootstrapKey,
                  old.isValidSignature(using: root),
                  let key = try? Curve25519.Signing.PublicKey(rawRepresentation: root.publicData) else { return false }
            return key.isValidSignature(signature, for: request.signingBytes)
        }
        var signingJSON: String { "{\"request\":\(request.signingJSON),\"signature\":\"\(signature.base64EncodedString())\"}" }
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
    public struct Observation: Codable, Equatable, Sendable {
        public enum Outcome: String, Codable, Sendable { case unchanged, applied }
        public let requestSHA256: String
        public let outcome: Outcome
        public let predecessor: C.Predecessor
        public init(requestSHA256: String, outcome: Outcome, predecessor: C.Predecessor) throws {
            self.requestSHA256 = requestSHA256; self.outcome = outcome; self.predecessor = predecessor
            try validate()
        }
        public func validate() throws {
            _ = try StorageIdentity.SPKISHA256(requestSHA256); try predecessor.validate()
        }
        public func validate(for request: Request) throws {
            try validate(); try request.validate()
            let old = try request.subjectOpen().request, p = old.predecessor
            guard requestSHA256 == request.digest else { throw StorageIdentity.ValidationError.correlationMismatch }
            switch outcome {
            case .unchanged:
                guard predecessor == p else { throw L.ValidationError.invalidValue }
            case .applied:
                guard p.controllerEpoch < UInt64.max, predecessor.currentGrant == old.takeover.grant,
                      predecessor.controllerEpoch == p.controllerEpoch + 1,
                      predecessor.serviceEpoch != p.serviceEpoch, predecessor.openRevision > p.openRevision,
                      predecessor.bootstrapKey == p.bootstrapKey else { throw L.ValidationError.invalidValue }
            }
        }
        enum CodingKeys: String, CodingKey { case requestSHA256 = "request_sha256", outcome, predecessor }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            try self.init(requestSHA256: c.decode(String.self, forKey: .requestSHA256), outcome: c.decode(Outcome.self, forKey: .outcome),
                predecessor: c.decode(C.Predecessor.self, forKey: .predecessor))
        }
    }
    public struct History: Codable, Equatable, Sendable {
        private final class Value: Sendable {
            let request: ColdRoot.Observe
            let authorization: SignedRequest
            let observation: Observation
            let anchor: L.ServiceState
            let failedOrigin: Adoption.Origin
            let failedBaseEpoch: UInt64
            init(request: ColdRoot.Observe, authorization: SignedRequest, observation: Observation,
                 anchor: L.ServiceState, failedOrigin: Adoption.Origin, failedBaseEpoch: UInt64) {
                self.request = request; self.authorization = authorization; self.observation = observation
                self.anchor = anchor; self.failedOrigin = failedOrigin; self.failedBaseEpoch = failedBaseEpoch
            }
        }
        private let value: Value
        public var request: ColdRoot.Observe { value.request }
        public var authorization: SignedRequest { value.authorization }
        public var observation: Observation { value.observation }
        public var anchor: L.ServiceState { value.anchor }
        public var failedOrigin: Adoption.Origin { value.failedOrigin }
        public var failedBaseEpoch: UInt64 { value.failedBaseEpoch }
        public var predecessor: C.Predecessor { observation.predecessor }
        public init(request: ColdRoot.Observe, authorization: SignedRequest, observation: Observation,
                    anchor: L.ServiceState, failedOrigin: Adoption.Origin, failedBaseEpoch: UInt64) throws {
            value = Value(request: request, authorization: authorization, observation: observation,
                anchor: anchor, failedOrigin: failedOrigin, failedBaseEpoch: failedBaseEpoch)
            try validate()
        }
        public static func == (lhs: Self, rhs: Self) -> Bool {
            lhs.request == rhs.request && lhs.authorization == rhs.authorization && lhs.observation == rhs.observation &&
                lhs.anchor == rhs.anchor && lhs.failedOrigin == rhs.failedOrigin && lhs.failedBaseEpoch == rhs.failedBaseEpoch
        }
        public func validate() throws {
            try request.validate(); try authorization.validate(); try observation.validate(for: authorization.request)
            try anchor.validate(); try failedOrigin.validate()
            let subject = try authorization.request.subjectOpen(), r = subject.request
            let root = try StorageIdentity.RootPublicKey(publicData: failedOrigin.rootPublicKey)
            guard authorization.isValidSignature(using: root), failedBaseEpoch > 1,
                  request.observationID == authorization.request.observationID,
                  request.observerGreeting.launch == authorization.request.observer,
                  request.identity == r.takeover.grant.identity, request.operationID == r.operationID,
                  request.signedOpenSHA256 == (try ColdRoot.signedOpenDigest(subject)),
                  r.predecessor == (try ColdRoot.protectedPredecessor(anchor)),
                  failedOrigin.shimLaunchUUID == r.launch.shimLaunchUUID, failedOrigin.specSHA256 == r.launch.specSHA256,
                  failedOrigin.binding.ext4UUID == r.launch.ext4UUID, failedOrigin.binding.bytes == r.launch.bytes,
                  failedOrigin.binding == request.observerGreeting.binding,
                  failedOrigin.rootPublicKey == request.observerGreeting.rootPublicKey else { throw StorageIdentity.ValidationError.correlationMismatch }
        }
        public func validate(preparedFailed: ColdRoot.Prepared, anchor expected: L.ServiceState) throws {
            try validate(); try preparedFailed.validate(); try expected.validate()
            guard preparedFailed.recoveryBridge == nil, preparedFailed.observedHistory == nil,
                  anchor == expected, authorization.request.subject == (try L.encode(preparedFailed.signedOpen)),
                  failedOrigin == preparedFailed.successorOrigin, failedBaseEpoch == preparedFailed.baseEpoch else {
                throw StorageIdentity.ValidationError.correlationMismatch
            }
        }
        enum CodingKeys: String, CodingKey { case request, authorization, observation, anchor, failedOrigin, failedBaseEpoch }
        public func encode(to encoder: any Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(request, forKey: .request); try c.encode(authorization, forKey: .authorization)
            try c.encode(observation, forKey: .observation); try c.encode(anchor, forKey: .anchor)
            try c.encode(failedOrigin, forKey: .failedOrigin); try c.encode(failedBaseEpoch, forKey: .failedBaseEpoch)
        }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            try self.init(request: c.decode(ColdRoot.Observe.self, forKey: .request), authorization: c.decode(SignedRequest.self, forKey: .authorization),
                observation: c.decode(Observation.self, forKey: .observation), anchor: c.decode(L.ServiceState.self, forKey: .anchor),
                failedOrigin: c.decode(Adoption.Origin.self, forKey: .failedOrigin), failedBaseEpoch: c.decode(UInt64.self, forKey: .failedBaseEpoch))
        }
    }
}

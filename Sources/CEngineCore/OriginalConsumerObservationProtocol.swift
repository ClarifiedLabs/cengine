import Foundation

/// Closed shim carrier. Its bytes are observations, not storage authority.
public enum OriginalConsumerObservationProtocol {
    public static let version: UInt32 = 1
    public static let maximumPayload = 256 * 1024
    public enum Command: String, Codable, Sendable {
        case arm = "original-consumer-arm", begin = "original-consumer-begin"
        case probe = "original-consumer-probe", result = "original-consumer-result"
        case release = "original-consumer-release"
        case positive = "original-consumer-positive"
        case resume = "original-consumer-resume" // original PID1 revalidates its unbegun retained observer
    }
    public enum Case: String, Codable, Sendable, CaseIterable {
        case sameEExistingData = "same-e-existing-data", sameERetainedFD = "same-e-retained-fd"
        case sameEOldLeafReconnect = "same-e-old-leaf-reconnect"
        case crossEExistingData = "cross-e-existing-data", crossERetainedFD = "cross-e-retained-fd"
        case crossEOldLeafReconnect = "cross-e-old-leaf-reconnect"
        case wrongVolume = "issued-identity-wrong-volume", wrongKey = "issued-identity-wrong-key", wrongRole = "issued-identity-wrong-role"
        case wrongMode = "issued-identity-wrong-mode", wrongEpoch = "issued-identity-wrong-epoch"
        case crossMountRootGrant = "cross-mount-root-grant", retiredRootGrantReplay = "retired-root-grant-replay"
        case attachmentKeyReuse = "attachment-key-reuse", delayedRegistration = "delayed-registration"
        case replayedTakeover = "replayed-takeover", legacyConnection = "legacy-connection"
        case secondServiceExclusivity = "second-service-exclusivity"
        public var isRegistration: Bool { self == .attachmentKeyReuse || self == .delayedRegistration }
        public var isSameE: Bool { self == .sameEExistingData || self == .sameEOldLeafReconnect || self == .sameERetainedFD || isRegistration }
        public var isWritableFD: Bool { self == .sameERetainedFD || self == .crossERetainedFD }
        public var isRoot: Bool { self == .crossMountRootGrant || self == .retiredRootGrantReplay }
        public var isWrongHello: Bool {
            [.wrongVolume, .wrongKey, .wrongRole, .wrongMode, .wrongEpoch].contains(self)
        }
    }
    public struct Binding: Codable, Sendable, Equatable {
        public let version: UInt32
        public let profile: String
        public let requestID: String
        public let armDigest: String
        public let operationUUID: String
        public let caseName: Case
        public let generation: UInt64
        public let boot: WorkloadStorageProtocol.BootBinding
        public let scope: WorkloadStorageProtocol.Scope
        public let targetAttachment: String
        public let key: String
        public let certificateSHA256: String
        public init(requestID: String, armDigest: String, operationUUID: String, caseName: Case, generation: UInt64,
                    boot: WorkloadStorageProtocol.BootBinding, scope: WorkloadStorageProtocol.Scope,
                    targetAttachment: String, key: String, certificateSHA256: String) {
            version = OriginalConsumerObservationProtocol.version(for: caseName)
            profile = ManagedPrepareCompatibilityProtocol.fullProfile
            self.requestID = requestID; self.armDigest = armDigest; self.operationUUID = operationUUID; self.caseName = caseName
            self.generation = generation; self.boot = boot; self.scope = scope
            self.targetAttachment = targetAttachment; self.key = key; self.certificateSHA256 = certificateSHA256
        }
    }
    public struct Request: Codable, Sendable, Equatable {
        public let binding: Binding
        public let command: Command
        /// Exact closed guest payload. No caller-selected operation, port or deadline.
        public let payload: Data
        public init(binding: Binding, command: Command, payload: Data) {
            self.binding = binding; self.command = command; self.payload = payload
        }
    }
    /// Exact original PID1 payload; the shim-only generation and arm digest are
    /// deliberately not added to this closed guest schema.
    public struct GuestArm: Codable, Sendable, Equatable {
        public let version: UInt32
        public let profile: String
        public let requestID: String
        public let operationUUID: String
        public let caseName: Case
        public let binding: WorkloadStorageProtocol.BootBinding
        public let scope: WorkloadStorageProtocol.Scope
        public let targetAttachment: String
        public let leafSHA256: String
        public init(_ owner: Binding) {
            version = owner.version; profile = owner.profile; requestID = owner.requestID
            operationUUID = owner.operationUUID; caseName = owner.caseName; binding = owner.boot
            scope = owner.scope; targetAttachment = owner.targetAttachment; leafSHA256 = owner.certificateSHA256
        }
    }
    public struct Probe: Codable, Sendable, Equatable {
        public let arm: GuestArm
        public let scope: WorkloadStorageProtocol.Scope
        public let peer: WorkloadStorageProtocol.Peer
        public init(arm: GuestArm, scope: WorkloadStorageProtocol.Scope, peer: WorkloadStorageProtocol.Peer) {
            self.arm = arm; self.scope = scope; self.peer = peer
        }
    }
    public struct Prefix: Codable, Sendable, Equatable {
        public let arm: GuestArm
        public let serverPrefixBytes: UInt64
        public let serverPrefixSHA256: String
        public init(arm: GuestArm, serverPrefixBytes: UInt64, serverPrefixSHA256: String) {
            self.arm = arm; self.serverPrefixBytes = serverPrefixBytes; self.serverPrefixSHA256 = serverPrefixSHA256
        }
    }
    public enum Failure: Error { case invalid, unsupported }
    public static func hash(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    private static func version(for caseName: Case) -> UInt32 {
        // v3 requires a successful GETATTR on the same original client before
        // its joined-close negative. Legacy FSYNC-only evidence is insufficient.
        caseName.isRoot ? 6 : caseName == .sameERetainedFD ? 7 : caseName.isWritableFD ? 5 : (caseName.isSameE ? 4 : (caseName == .crossEExistingData ? 3 : (caseName.isWrongHello ? 2 : version)))
    }
    public static func validate(_ binding: Binding) throws {
        guard binding.version == version(for: binding.caseName), binding.profile == ManagedPrepareCompatibilityProtocol.fullProfile,
              DiskInitializationProtocol.validUUID(binding.requestID), hash(binding.armDigest),
              DiskInitializationProtocol.validUUID(binding.operationUUID),
              hash(binding.key), hash(binding.certificateSHA256),
              DiskInitializationProtocol.validUUID(binding.boot.shimLaunchUUID),
              DiskInitializationProtocol.validUUID(binding.boot.guestBootNonce),
              binding.scope.launch == binding.boot.shimLaunchUUID,
              !binding.scope.containerInstance.isEmpty, !binding.targetAttachment.isEmpty else { throw Failure.invalid }
    }
    public static func validate(_ request: Request) throws {
        try validate(request.binding)
        guard !request.payload.isEmpty, request.payload.count <= maximumPayload else { throw Failure.invalid }
        let expected = GuestArm(request.binding)
        switch request.command {
        case .arm, .begin, .release, .resume, .positive:
            guard try exact(GuestArm.self, request.payload) == expected else { throw Failure.invalid }
        case .probe:
            let probe = try exact(Probe.self, request.payload)
            guard probe.arm == expected else { throw Failure.invalid }
        case .result:
            guard !expected.caseName.isSameE, !expected.caseName.isRoot else { throw Failure.invalid }
            let prefix = try exact(Prefix.self, request.payload)
            guard prefix.arm == expected, (1...131072).contains(prefix.serverPrefixBytes),
                  hash(prefix.serverPrefixSHA256) else { throw Failure.invalid }
        }
    }
    /// The original owner's local operation is distinct from its TLS denial.
    /// These finite observations are not authority admission or drain receipts.
    public struct OriginalOperation: Codable, Sendable, Equatable {
        public var kind: String
        public var sequence: UInt64
        public var errorClass: String
    }
    /// Actual root GETATTR operands; absent on legacy guest versions 1–3.
    public struct RootRequest: Codable, Sendable, Equatable {
        public var node: UInt64
        public var requestSequence: UInt64
        public init(node: UInt64, requestSequence: UInt64) {
            self.node = node; self.requestSequence = requestSequence
        }
    }
    /// Guest-local file operands are observations, never authority admission receipts.
    public struct FileRequest: Codable, Sendable, Equatable {
        public var node: UInt64
        public var handle: UInt64
        public var requestSequence: UInt64
    }
    public struct CapabilityRequest: Codable, Sendable, Equatable {
        public var node: UInt64
        public var requestSequence: UInt64
    }
    public struct FileTrace: Codable, Sendable, Equatable {
        public var capability: CapabilityRequest?
        public var write: FileRequest?
        public var sync: FileRequest?
        public var writeOK: Bool
        public var syncOK: Bool
    }
    public struct Writable: Codable, Sendable, Equatable {
        public var identitySHA256: String
        public var written: Int
        public var writeError: String
        public var syncError: String
        public var completed: Bool
        public var trace: FileTrace?
    }
    /// Every field in the guest's actual OriginalConsumerEvidence DTO is
    /// required, including the empty originalOperation object on old-leaf runs.
    public struct Evidence: Codable, Sendable, Equatable {
        public var arm: GuestArm
        public var stage: String
        public var scope: WorkloadStorageProtocol.Scope
        public var keySHA256: String
        public var mountIdentitySHA256: String
        public var serverDERSHA256: String
        public var signCount: UInt64
        public var signInputSHA256: String
        public var bytesWrittenAfterSign: UInt64
        public var clientWrittenBytes: UInt64
        public var clientPrefixBytes: UInt64
        public var clientPrefixSHA256: String
        public var localError: String
        public var fdOperation: String
        public var fdSequence: UInt64
        public var originalOperation = OriginalOperation(kind: "", sequence: 0, errorClass: "")
        public var hello: ConsumerObservationProtocol.Original?
        public var rootRequest: RootRequest?
        /// Present only for version 5/7 writable-FD cases.
        public var writable: Writable?
        /// Present only for v6 dual-original-mount root observations.
        public var roots: Roots?
    }
    private struct Released: Codable { let arm: GuestArm; let stage: String }
    public struct CheckedReply: Sendable {
        public let data: Data
        public let evidence: Evidence?
    }

    public static func decodeRequest(_ bytes: Data) throws -> Request {
        try exact(Request.self, bytes)
    }
    static func exact<T: Codable>(_ type: T.Type, _ bytes: Data) throws -> T {
        guard !bytes.isEmpty, bytes.count <= maximumPayload else { throw Failure.invalid }
        // This wire has only ASCII hashes, UUIDs, finite names and base64. No
        // Unicode spelling of an ASCII field/value is a second accepted alias.
        guard bytes.range(of: Data([92, 117])) == nil else { throw Failure.invalid }
        var parser = WorkloadStorageProtocol.Parser(bytes: Array(bytes), maximumDepth: 12)
        let original = try parser.parse() // duplicate-aware, bounded token tree
        let value = try JSONDecoder().decode(type, from: bytes)
        var typed = WorkloadStorageProtocol.Parser(bytes: Array(try JSONEncoder().encode(value)), maximumDepth: 12)
        guard try original == typed.parse() else { throw Failure.invalid }
        return value
    }
    public static func validateReply(_ bytes: Data, request: Request) throws {
        _ = try checkedReply(bytes, request: request)
    }
    public static func checkedReply(_ bytes: Data, request: Request, previous: Evidence? = nil) throws -> CheckedReply {
        try validate(request)
        let arm = GuestArm(request.binding)
        if request.command == .release {
            let value = try exact(Released.self, bytes)
            guard value.arm == arm, value.stage == "released" else { throw Failure.invalid }
            return .init(data: try JSONEncoder().encode(value), evidence: nil)
        }
        let value = try exact(Evidence.self, bytes)
        if request.command == .resume {
            // Resume only an unbegun original GETATTR observation. No new lease,
            // timestamp, VM, credential or client may be inferred from these bytes.
            guard arm.caseName == .sameEExistingData, value.arm == arm,
                  value.keySHA256 == request.binding.key, hash(value.mountIdentitySHA256) else { throw Failure.invalid }
            try validateMountedPositive(value, arm: arm, stage: "armed-mounted-positive")
            if let previous { guard previous == value else { throw Failure.invalid } }
            return .init(data: try JSONEncoder().encode(value), evidence: value)
        }
        if request.command == .positive {
            guard arm.caseName == .sameEExistingData, let previous,
                  previous.arm == arm, previous.roots == nil, previous.keySHA256 == request.binding.key,
                  hash(previous.mountIdentitySHA256), let prior = previous.rootRequest,
                  let root = value.rootRequest, root.node == prior.node,
                  root.requestSequence > prior.requestSequence else { throw Failure.invalid }
            try validateMountedPositive(previous, arm: arm, stage: "begun")
            var expected = previous
            expected.stage = "original-data-positive"
            expected.rootRequest = root
            expected.originalOperation.sequence = 2
            guard value == expected else { throw Failure.invalid }
            return .init(data: try JSONEncoder().encode(value), evidence: value)
        }
        if arm.caseName.isRoot {
            let probe = request.command == .probe ? try exact(Probe.self, request.payload) : nil
            try validateRootEvidence(value, request: request, previous: previous, probe: probe)
            return .init(data: try JSONEncoder().encode(value), evidence: value)
        }
        guard value.roots == nil else { throw Failure.invalid }
        if arm.caseName == .crossEExistingData || arm.caseName.isSameE || arm.caseName.isWritableFD, request.command != .arm {
            guard previous != nil else { throw Failure.invalid }
        }
        guard arm.caseName.isWrongHello || arm.caseName == .sameEOldLeafReconnect || value.hello == nil else { throw Failure.invalid }
        guard (arm.caseName.isSameE && !arm.caseName.isWritableFD) || value.rootRequest == nil else { throw Failure.invalid }
        guard arm.caseName.isWritableFD || value.writable == nil else { throw Failure.invalid }
        guard value.arm == arm, value.keySHA256 == request.binding.key,
              hash(value.mountIdentitySHA256),
              value.fdOperation == (arm.caseName.isWritableFD ? "write-file-fsync" : "fsync-directory") else { throw Failure.invalid }
        if let previous {
            guard previous.arm == arm, value.mountIdentitySHA256 == previous.mountIdentitySHA256,
                  value.keySHA256 == previous.keySHA256,
                  value.writable?.identitySHA256 == previous.writable?.identitySHA256 else { throw Failure.invalid }
        }
        let noSignature = value.signCount == 0 && value.signInputSHA256.isEmpty
            && value.bytesWrittenAfterSign == 0 && value.clientWrittenBytes == 0
        let noPrefix = value.clientPrefixBytes == 0 && value.clientPrefixSHA256.isEmpty
        switch request.command {
        case .arm, .begin:
            try validateMountedPositive(value, arm: arm,
                stage: request.command == .arm ? "armed-mounted-positive" : "begun")
            if request.command == .begin, var expected = previous {
                guard expected.stage == "armed-mounted-positive" else { throw Failure.invalid }
                expected.stage = "begun"
                guard value == expected else { throw Failure.invalid }
            }
        case .probe:
            let probe = try exact(Probe.self, request.payload)
            try validateProbeScope(probe.scope, arm: arm)
            guard value.scope == probe.scope,
                  value.serverDERSHA256 == WorkloadStorageProtocol.specificationDigest(probe.peer.serverDER),
                  noPrefix, previous == nil || previous?.stage == "begun" else { throw Failure.invalid }
            if arm.caseName == .crossEExistingData || arm.caseName.isSameE || arm.caseName.isWritableFD {
                guard let previous else { throw Failure.invalid }
                try validateMountedPositive(previous, arm: arm, stage: "begun")
            }
            switch arm.caseName {
            case .sameEExistingData, .attachmentKeyReuse, .delayedRegistration:
                guard let root = value.rootRequest, let prior = previous?.rootRequest,
                      root.node == prior.node, root.requestSequence > prior.requestSequence,
                      value.stage == "original-data-attempt", noSignature, value.fdSequence == 1,
                      value.localError.isEmpty,
                      value.originalOperation == OriginalOperation(kind: "data-getattr-root", sequence: 2,
                          errorClass: "transport-failed") else { throw Failure.invalid }
            case .sameEOldLeafReconnect:
                guard value.rootRequest == previous?.rootRequest,
                      value.stage == "original-owner-signed-flight" else { throw Failure.invalid }
                try validateSignedFlight(value)
            case .sameERetainedFD:
                guard let previous else { throw Failure.invalid }
                try validateSameEWritable(value, positive: previous)
            case .crossEOldLeafReconnect, .crossEExistingData, .crossERetainedFD, .wrongVolume, .wrongKey, .wrongRole, .wrongMode, .wrongEpoch:
                guard value.stage == "original-owner-signed-flight" else { throw Failure.invalid }
                try validateSignedFlight(value)
            default: throw Failure.unsupported
            }
        case .result:
            let prefix = try exact(Prefix.self, request.payload)
            guard ([.crossEOldLeafReconnect, .crossEExistingData, .crossERetainedFD].contains(arm.caseName) || arm.caseName.isWrongHello),
                  value.stage == "original-owner-prefix-correlated",
                  value.clientPrefixBytes == prefix.serverPrefixBytes,
                  value.clientPrefixSHA256 == prefix.serverPrefixSHA256,
                  value.clientPrefixBytes <= value.clientWrittenBytes else { throw Failure.invalid }
            try validateProbeScope(value.scope, arm: arm)
            try validateSignedFlight(value)
            if var expected = previous {
                guard expected.stage == "original-owner-signed-flight" else { throw Failure.invalid }
                expected.stage = "original-owner-prefix-correlated"
                expected.clientPrefixBytes = prefix.serverPrefixBytes
                expected.clientPrefixSHA256 = prefix.serverPrefixSHA256
                guard value == expected else { throw Failure.invalid }
            }
        case .release, .resume, .positive: throw Failure.invalid
        }
        return .init(data: try JSONEncoder().encode(value), evidence: value)
    }
    private static func validateMountedPositive(_ value: Evidence, arm: GuestArm, stage: String) throws {
        let operation = arm.caseName.isWritableFD
            ? OriginalOperation(kind: "write-file-fsync", sequence: 1, errorClass: "ok")
            : (arm.caseName == .crossEExistingData || arm.caseName.isSameE
                ? OriginalOperation(kind: "data-getattr-root", sequence: 1, errorClass: "ok")
                : OriginalOperation(kind: "", sequence: 0, errorClass: ""))
        if arm.caseName.isWritableFD {
            guard let writable = value.writable, hash(writable.identitySHA256), writable.completed,
                  writable.written == 1, writable.writeError == "ok", writable.syncError == "ok",
                  let trace = writable.trace, let write = trace.write, let sync = trace.sync,
                  trace.capability == nil, trace.writeOK, trace.syncOK else { throw Failure.invalid }
            try validateFileOrder(write: write, sync: sync)
        } else { guard value.writable == nil else { throw Failure.invalid } }
        if arm.caseName.isSameE && !arm.caseName.isWritableFD {
            guard let root = value.rootRequest, root.node > 0, root.requestSequence > 0 else { throw Failure.invalid }
        } else { guard value.rootRequest == nil else { throw Failure.invalid } }
        guard value.stage == stage, value.scope == arm.scope, value.serverDERSHA256.isEmpty,
              value.signCount == 0, value.signInputSHA256.isEmpty,
              value.bytesWrittenAfterSign == 0, value.clientWrittenBytes == 0,
              value.clientPrefixBytes == 0, value.clientPrefixSHA256.isEmpty,
              value.localError.isEmpty,
              value.fdOperation == (arm.caseName.isWritableFD ? "write-file-fsync" : "fsync-directory"), value.fdSequence == 1,
              value.hello == nil, value.originalOperation == operation else { throw Failure.invalid }
    }
    private static func validateFileOrder(write: FileRequest, sync: FileRequest) throws {
        guard write.node > 0, write.handle > 0, write.requestSequence > 0,
              sync.node == write.node, sync.handle == write.handle,
              sync.requestSequence > write.requestSequence else { throw Failure.invalid }
    }
    private static func validateWritableNegative(_ value: Evidence, errorClass: String) throws {
        let errors = ["eio", "enotconn", "estale", "eacces"]
        guard let writable = value.writable, hash(writable.identitySHA256), writable.completed,
              writable.written == 0, errors.contains(writable.writeError), errors.contains(writable.syncError),
              value.fdSequence == 2,
              value.originalOperation == OriginalOperation(kind: "write-file-fsync", sequence: 2,
                  errorClass: errorClass) else { throw Failure.invalid }
    }
    private static func validateSameEWritable(_ value: Evidence, positive: Evidence) throws {
        guard value.stage == "original-file-attempt", value.rootRequest == nil, value.hello == nil,
              value.fdOperation == "write-file-fsync", value.localError.isEmpty,
              value.signCount == 0, value.signInputSHA256.isEmpty,
              value.bytesWrittenAfterSign == 0, value.clientWrittenBytes == 0,
              value.writable?.identitySHA256 == positive.writable?.identitySHA256,
              let prior = positive.writable?.trace?.sync,
              let trace = value.writable?.trace, let capability = trace.capability,
              capability.node == prior.node, capability.requestSequence > prior.requestSequence,
              trace.write == nil, trace.sync == nil, !trace.writeOK, !trace.syncOK else { throw Failure.invalid }
        try validateWritableNegative(value, errorClass: "transport-failed")
    }
    private static func validateSignedFlight(_ value: Evidence) throws {
        guard value.signCount == 1, hash(value.signInputSHA256), hash(value.serverDERSHA256),
              value.bytesWrittenAfterSign > 0, value.bytesWrittenAfterSign <= value.clientWrittenBytes,
              value.clientWrittenBytes <= 131072,
              ["eof", "tls-alert-or-transport"].contains(value.localError) else { throw Failure.invalid }
        guard (value.arm.caseName.isWrongHello || value.arm.caseName == .sameEOldLeafReconnect) == (value.hello != nil) else { throw Failure.invalid }
        switch value.arm.caseName {
        case .sameEOldLeafReconnect:
            guard value.fdSequence == 1,
                  value.originalOperation == OriginalOperation(kind: "data-original-hello", sequence: 2,
                      errorClass: "peer-closed-before-root"), let hello = value.hello,
                  hello.epoch == value.arm.scope.serviceEpoch,
                  hello.binding.store == value.arm.scope.store,
                  hello.binding.attachment == value.arm.targetAttachment,
                  hello.binding.container == value.arm.scope.container,
                  hello.binding.launch == value.arm.scope.launch,
                  hello.binding.key == value.keySHA256,
                  hello.binding.role == "runtime", hello.binding.prepare == nil,
                  StorageServiceTypes.validID(hello.binding.volume),
                  ["read-only", "read-write"].contains(hello.binding.mode) else { throw Failure.invalid }
        case .crossEOldLeafReconnect:
            guard value.fdSequence == 1,
                  value.originalOperation == OriginalOperation(kind: "", sequence: 0, errorClass: "") else { throw Failure.invalid }
        case .crossEExistingData:
            guard value.fdSequence == 1,
                  value.originalOperation == OriginalOperation(kind: "data-getattr-root", sequence: 2,
                      errorClass: "client-closed-joined") else { throw Failure.invalid }
        case .crossERetainedFD:
            try validateWritableNegative(value, errorClass: "mount-closed-joined")
            guard value.writable?.trace == nil else { throw Failure.invalid }
        case .wrongVolume, .wrongKey, .wrongRole, .wrongMode, .wrongEpoch:
            guard value.fdSequence == 1,
                  value.originalOperation == OriginalOperation(kind: "data-wrong-hello", sequence: 1,
                      errorClass: "peer-closed-before-root") else { throw Failure.invalid }
        default: throw Failure.unsupported
        }
    }
    /// Correlate an already checked guest probe with the current worker's observation.
    /// The owner must pin the arm/peer and retire/reconcile authority before probing.
    public static func validateSameE(_ value: Evidence, positive: Evidence,
                                    observed: ConsumerObservationProtocol.Status) throws {
        try ConsumerObservationProtocol.validate(observed)
        let query = observed.query, arm = value.arm
        guard arm.caseName.isSameE, arm.version == version(for: arm.caseName), observed.state == .observed,
              positive.arm == arm, value.scope == arm.scope, hash(value.mountIdentitySHA256),
              value.mountIdentitySHA256 == positive.mountIdentitySHA256,
              value.keySHA256 == positive.keySHA256,
              query.requestID == arm.requestID, query.operationUUID == arm.operationUUID,
              query.originalBootBinding == arm.binding, query.originalLeafSHA256 == arm.leafSHA256,
              query.original.epoch == arm.scope.serviceEpoch,
              query.original.binding.store == arm.scope.store,
              query.original.binding.attachment == arm.targetAttachment,
              query.original.binding.container == arm.scope.container,
              query.original.binding.launch == arm.scope.launch,
              query.original.binding.key == value.keySHA256,
              value.clientPrefixBytes == 0, value.clientPrefixSHA256.isEmpty else { throw Failure.invalid }
        try validateMountedPositive(positive, arm: arm, stage: "begun")
        if arm.caseName == .sameERetainedFD {
            try validateSameEWritable(value, positive: positive)
            guard query.caseName == .sameEFile, query.version == 8,
                  let capability = value.writable?.trace?.capability, let admission = observed.evidence?.admission,
                  admission.node == capability.node,
                  admission.requestSequence == capability.requestSequence else { throw Failure.invalid }
            return
        }
        guard value.writable == nil, let root = value.rootRequest, let prior = positive.rootRequest else { throw Failure.invalid }
        if arm.caseName == .sameEExistingData || arm.caseName.isRegistration {
            guard query.caseName == .sameE, query.version == 6,
                  value.stage == "original-data-attempt", value.hello == nil,
                  value.signCount == 0, value.signInputSHA256.isEmpty,
                  value.bytesWrittenAfterSign == 0, value.clientWrittenBytes == 0,
                  value.localError.isEmpty, value.fdSequence == 1,
                  value.originalOperation == OriginalOperation(kind: "data-getattr-root", sequence: 2,
                      errorClass: "transport-failed"),
                  root.node == prior.node, root.requestSequence > prior.requestSequence,
                  observed.evidence?.admission?.node == root.node,
                  observed.evidence?.admission?.requestSequence == root.requestSequence else { throw Failure.invalid }
        } else {
            guard query.caseName == .sameEReconnect, query.version == 5,
                  value.stage == "original-owner-signed-flight", root == prior,
                  value.hello == query.original else { throw Failure.invalid }
            try validateSignedFlight(value)
        }
    }
    private static func validateProbeScope(_ scope: WorkloadStorageProtocol.Scope, arm: GuestArm) throws {
        if arm.caseName.isSameE || arm.caseName.isWrongHello {
            guard scope == arm.scope else { throw Failure.invalid }
        } else {
            guard WorkloadStorageProtocol.validID(scope.serviceEpoch), scope.serviceEpoch != arm.scope.serviceEpoch,
                  scope.controllerEpoch > 0, hash(scope.controllerKey) else { throw Failure.invalid }
            var original = scope
            original.serviceEpoch = arm.scope.serviceEpoch
            original.controllerEpoch = arm.scope.controllerEpoch
            original.controllerKey = arm.scope.controllerKey
            guard original == arm.scope else { throw Failure.invalid }
        }
    }
}

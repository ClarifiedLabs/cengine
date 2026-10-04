import Foundation

/// Closed public observation DTOs, matching Guest/internal/consumercompat/types.go.
/// These are not authority receipts and never assert server-verified key possession.
public enum ConsumerObservationProtocol {
    public static let version: UInt32 = 3
    public static let profile = ManagedPrepareCompatibilityProtocol.fullProfile
    public enum Failure: Error { case invalid }
    public enum Case: String, Codable, Sendable {
        case sameE = "same-e-existing-data", crossE = "cross-e-old-leaf-reconnect"
        case wrongVolume = "issued-identity-wrong-volume", wrongKey = "issued-identity-wrong-key"
        case wrongRole = "issued-identity-wrong-role", wrongMode = "issued-identity-wrong-mode", wrongEpoch = "issued-identity-wrong-epoch"
        case sameEReconnect = "same-e-old-leaf-reconnect"
        case sameEFile = "same-e-retained-fd"
        public var isWrongHello: Bool { self != .sameE && self != .crossE && self != .sameEReconnect && self != .sameEFile }
    }
    public enum State: String, Codable, Sendable { case armed, claimed, observed, finalized, failed }
    public enum FailureCode: String, Codable, Sendable {
        case duplicate, mismatch, timeout, transportOrUnattributed = "transport-or-unattributed"
        case notExisting = "not-existing", notBlocked = "not-blocked", closed
    }
    public struct RuntimeBinding: Codable, Equatable, Sendable {
        public var store: String
        public var volume: String
        public var attachment: String
        public var container: String
        public var launch: String
        public var key: String
        public var prepare: String?
        public var role: String
        public var mode: String
        public init(store: String, volume: String, attachment: String, container: String, launch: String, key: String, role: String = "runtime", mode: String) {
            self.store = store; self.volume = volume; self.attachment = attachment; self.container = container
            self.launch = launch; self.key = key; self.role = role; self.mode = mode
        }
    }
    public struct Original: Codable, Equatable, Sendable {
        public var epoch: String
        public var binding: RuntimeBinding
        public init(epoch: String, binding: RuntimeBinding) { self.epoch = epoch; self.binding = binding }
    }
    public struct WorkerScope: Codable, Equatable, Sendable {
        public var storeUUID: String
        public var serviceEpoch: String
        public var workerUUID: String
        public init(storeUUID: String, serviceEpoch: String, workerUUID: String) {
            self.storeUUID = storeUUID; self.serviceEpoch = serviceEpoch; self.workerUUID = workerUUID
        }
    }
    public struct Arm: Codable, Equatable, Sendable {
        public var version: UInt32
        public var profile: String
        public var requestID: String
        public var armDigest: String
        public var operationUUID: String
        public var caseName: Case
        public var originalBootBinding: WorkloadStorageProtocol.BootBinding
        public var original: Original
        public var originalLeafSHA256: String
        public var workerScope: WorkerScope
        public init(requestID: String, armDigest: String, operationUUID: String, caseName: Case,
                    originalBootBinding: WorkloadStorageProtocol.BootBinding, original: Original,
                    originalLeafSHA256: String, workerScope: WorkerScope) {
            version = caseName == .sameEFile ? 8 : (caseName == .sameE ? 6 : (caseName == .sameEReconnect ? 5 : (caseName.isWrongHello ? 4 : ConsumerObservationProtocol.version))); profile = ConsumerObservationProtocol.profile
            self.requestID = requestID; self.armDigest = armDigest; self.operationUUID = operationUUID; self.caseName = caseName
            self.originalBootBinding = originalBootBinding; self.original = original
            self.originalLeafSHA256 = originalLeafSHA256; self.workerScope = workerScope
        }
    }
    public typealias Query = Arm
    public struct Admission: Codable, Equatable, Sendable {
        public var original: Original
        public var requestSequence: UInt64
        public var operation: String?
        public var node: UInt64?
        public var authKind: UInt8?
        public var noHandle: Bool?
        public var handle: UInt64?
        public var writeOneAtZero: Bool?
        public var capabilityName: String?
        public init(original: Original, requestSequence: UInt64, operation: String? = nil,
                    node: UInt64? = nil, authKind: UInt8? = nil, noHandle: Bool? = nil,
                    handle: UInt64? = nil, writeOneAtZero: Bool? = nil, capabilityName: String? = nil) {
            self.original = original; self.requestSequence = requestSequence
            self.operation = operation; self.node = node; self.authKind = authKind; self.noHandle = noHandle
            self.handle = handle; self.writeOneAtZero = writeOneAtZero; self.capabilityName = capabilityName
        }
    }
    public struct Evidence: Codable, Equatable, Sendable {
        public var stage: String
        public var errorClass: String
        public var storeUUID: String
        public var serviceEpoch: String
        public var rejectedLeafSHA256: String
        public var byteCount: UInt64?
        public var prefixSHA256: String?
        public var admission: Admission?
        public var hello: Original?
        public init(stage: String, errorClass: String, storeUUID: String, serviceEpoch: String, rejectedLeafSHA256: String,
                    byteCount: UInt64? = nil, prefixSHA256: String? = nil, admission: Admission? = nil) {
            self.stage = stage; self.errorClass = errorClass; self.storeUUID = storeUUID; self.serviceEpoch = serviceEpoch
            self.rejectedLeafSHA256 = rejectedLeafSHA256; self.byteCount = byteCount; self.prefixSHA256 = prefixSHA256; self.admission = admission
        }
    }
    public struct Status: Codable, Equatable, Sendable {
        public var query: Query
        public var state: State
        public var selectedCount: UInt32
        public var failure: FailureCode?
        public var evidence: Evidence?
        public init(query: Query, state: State, selectedCount: UInt32, failure: FailureCode? = nil, evidence: Evidence? = nil) {
            self.query = query; self.state = state; self.selectedCount = selectedCount; self.failure = failure; self.evidence = evidence
        }
    }
    public static func validate(_ arm: Arm) throws {
        let b = arm.original.binding, w = arm.workerScope
        let ids = [arm.requestID, arm.operationUUID, arm.originalBootBinding.shimLaunchUUID, arm.originalBootBinding.guestBootNonce,
                   arm.original.epoch, b.store, b.volume, b.attachment, b.launch, w.storeUUID, w.serviceEpoch, w.workerUUID]
        guard (arm.caseName == .sameE ? [UInt32(3), 6].contains(arm.version) : arm.caseName == .sameEFile ? [UInt32(7), 8].contains(arm.version) : arm.version == (arm.caseName == .sameEReconnect ? 5 : (arm.caseName.isWrongHello ? 4 : version))), arm.profile == profile, ids.allSatisfy(StorageServiceTypes.validID),
              [arm.armDigest, b.container, b.key, arm.originalLeafSHA256].allSatisfy(OriginalConsumerObservationProtocol.hash),
              arm.originalBootBinding.shimLaunchUUID == b.launch, b.role == "runtime", b.prepare == nil,
              ["read-only", "read-write"].contains(b.mode), w.storeUUID == b.store,
              (arm.caseName == .crossE ? arm.original.epoch != w.serviceEpoch : arm.original.epoch == w.serviceEpoch) else { throw Failure.invalid }
        if arm.caseName == .wrongMode { guard b.mode == "read-only" else { throw Failure.invalid } }
        if arm.caseName == .sameEFile { guard b.mode == "read-write" else { throw Failure.invalid } }
    }
    public static func validate(_ status: Status, arm: Arm? = nil) throws {
        try validate(status.query)
        guard arm == nil || status.query == arm, status.selectedCount <= 1 else { throw Failure.invalid }
        switch status.state {
        case .armed:
            guard status.selectedCount == 0, status.failure == nil, status.evidence == nil else { throw Failure.invalid }
        case .claimed:
            guard status.selectedCount == 1, status.failure == nil, status.evidence == nil else { throw Failure.invalid }
        case .failed:
            guard status.failure != nil, status.evidence == nil else { throw Failure.invalid }
        case .observed, .finalized:
            guard status.selectedCount == 1, status.failure == nil, let e = status.evidence,
                  e.storeUUID == status.query.workerScope.storeUUID, e.serviceEpoch == status.query.workerScope.serviceEpoch,
                  e.rejectedLeafSHA256 == status.query.originalLeafSHA256 else { throw Failure.invalid }
            switch status.query.caseName {
            case .crossE:
                guard e.stage == "tls-client-certificate", e.errorClass == "unknown-authority", let count = e.byteCount,
                      (1...131072).contains(count), let hash = e.prefixSHA256, OriginalConsumerObservationProtocol.hash(hash),
                      e.admission == nil, e.hello == nil else { throw Failure.invalid }
            case .sameE, .sameEFile:
                guard e.stage == "request-admit", e.errorClass == "blocked", e.byteCount == nil, e.prefixSHA256 == nil,
                      let admission = e.admission, admission.original == status.query.original,
                      admission.requestSequence > 0, e.hello == nil else { throw Failure.invalid }
                if status.query.version == 8 {
                    // Actual Linux killpriv prelude, not a manufactured WRITE.
                    guard admission.operation == "get_xattr", let node = admission.node, node > 0,
                          admission.authKind == 1, admission.noHandle == true,
                          admission.capabilityName == "security.capability",
                          admission.handle == nil, admission.writeOneAtZero == nil else { throw Failure.invalid }
                } else if status.query.version == 7 {
                    // storagewire.OpWrite; CallerAuth=1 and OpenGrantAuth=2.
                    guard admission.operation == "write", let node = admission.node, node > 0,
                          let handle = admission.handle, handle > 0, admission.writeOneAtZero == true,
                          admission.noHandle == nil, admission.capabilityName == nil,
                          admission.authKind == 1 || admission.authKind == 2 else { throw Failure.invalid }
                } else {
                    guard admission.handle == nil, admission.writeOneAtZero == nil, admission.capabilityName == nil else { throw Failure.invalid }
                    if status.query.version == 6 {
                        guard admission.operation == "get_attr", let node = admission.node, node > 0,
                              admission.authKind == 3, admission.noHandle == true else { throw Failure.invalid }
                    } else {
                        guard admission.operation == nil, admission.node == nil,
                              admission.authKind == nil, admission.noHandle == nil else { throw Failure.invalid }
                    }
                }
            case .sameEReconnect:
                guard e.stage == "authenticate-data", e.errorClass == "blocked", e.byteCount == nil,
                      e.prefixSHA256 == nil, e.admission == nil, e.hello == status.query.original else { throw Failure.invalid }
            case .wrongVolume, .wrongKey, .wrongRole, .wrongMode, .wrongEpoch:
                guard e.stage == "pki-verify-peer", e.errorClass == "unauthorized", let count = e.byteCount,
                      (1...131072).contains(count), let hash = e.prefixSHA256, OriginalConsumerObservationProtocol.hash(hash),
                      e.admission == nil, let hello = e.hello else { throw Failure.invalid }
                try validateWrongHello(hello, original: status.query.original, caseName: status.query.caseName)
            }
        }
    }
    /// Closed one-field mutation; provenance is supplied/rechecked by the live owner.
    public static func validateWrongHello(_ hello: Original, original: Original, caseName: Case) throws {
        var expected = original
        switch caseName {
        case .wrongVolume:
            guard StorageServiceTypes.validID(hello.binding.volume), hello.binding.volume != original.binding.volume else { throw Failure.invalid }
            expected.binding.volume = hello.binding.volume
        case .wrongKey:
            guard OriginalConsumerObservationProtocol.hash(hello.binding.key), hello.binding.key != original.binding.key else { throw Failure.invalid }
            expected.binding.key = hello.binding.key
        case .wrongRole:
            guard let prepare = hello.binding.prepare, StorageServiceTypes.validID(prepare) else { throw Failure.invalid }
            expected.binding.role = "prepare"; expected.binding.prepare = prepare
        case .wrongMode:
            guard original.binding.mode == "read-only" else { throw Failure.invalid }
            expected.binding.mode = "read-write"
        case .wrongEpoch:
            guard StorageServiceTypes.validID(hello.epoch), hello.epoch != original.epoch else { throw Failure.invalid }
            expected.epoch = hello.epoch
        default: throw Failure.invalid
        }
        guard expected == hello else { throw Failure.invalid }
    }
    /// Accept only the exact worker snapshot atomically sealed by Finalize.
    /// An ordinary Query's mutable observed state is never a terminal receipt.
    public static func validateFinalization(_ finalized: Status, observed: Status) throws {
        try validate(observed)
        try validate(finalized, arm: observed.query)
        guard observed.state == .observed, finalized.state == .finalized else { throw Failure.invalid }
        var expected = observed
        expected.state = .finalized
        guard finalized == expected else { throw Failure.invalid }
    }
    /// Token-preserving comparison rejects unknown/null/missing/duplicate fields,
    /// noninteger counters and Unicode field aliases before typed decoding escapes.
    static func exact<T: Codable>(_ type: T.Type, _ bytes: Data) throws -> T {
        guard !bytes.isEmpty, bytes.count <= StorageServiceTypes.maxFrame,
              bytes.range(of: Data([92, 117])) == nil else { throw Failure.invalid }
        var parser = WorkloadStorageProtocol.Parser(bytes: Array(bytes), maximumDepth: 12)
        let original = try parser.parse()
        let value = try JSONDecoder().decode(type, from: bytes)
        var typed = WorkloadStorageProtocol.Parser(bytes: Array(try JSONEncoder().encode(value)), maximumDepth: 12)
        guard try original == typed.parse() else { throw Failure.invalid }
        return value
    }
    public static func decodeStatus(_ bytes: Data) throws -> Status {
        let value = try exact(Status.self, bytes); try validate(value); return value
    }
}

import Foundation

/// Public storage service/control values shared by private wire generations.
/// Decoding these values does not authenticate peers or confer lifecycle authority.
public enum StorageServiceTypes {
    public enum ValidationError: Error, Equatable, Sendable { case invalidFrame }

    public static let maxFrame = 65_536
    public static let maximumDERSize = 16 * 1_024
    public static let maximumNotifications = 32
    /// Guest/internal/storagepki/pki.go: MaxValidity and bounded (UTC years 1970...9999).
    public static let maximumLifetimeSeconds: UInt64 = 86_400
    /// Reserve a full MaxValidity before the end of year 9999, matching Go storageboot.
    public static let maximumUnixSeconds: UInt64 = 253_402_214_399

    /// Public worker identity; only an authenticated, bound private session confers authority.
    public struct Scope: Codable, Equatable, Sendable {
        public var serviceEpoch: String
        public var workerUUID: String
        public init(serviceEpoch: String, workerUUID: String) {
            self.serviceEpoch = serviceEpoch; self.workerUUID = workerUUID
        }
    }

    /// The full request, not operationUUID alone, is the replacement idempotency identity.
    public struct ReplacementRequest: Codable, Equatable, Sendable {
        public var operationUUID: String
        public var predecessor: Scope
        public var nowUnixSeconds: UInt64
        public init(operationUUID: String, predecessor: Scope, nowUnixSeconds: UInt64) {
            self.operationUUID = operationUUID; self.predecessor = predecessor; self.nowUnixSeconds = nowUnixSeconds
        }
    }

    /// Observational only: this result never promotes worker identity or keys.
    public struct ServiceStatus: Codable, Equatable, Sendable {
        public enum Phase: String, Codable, Sendable {
            case ready, workerLost = "worker-lost", replacing, failed
        }
        public var scope: Scope
        public var phase: Phase
        public init(scope: Scope, phase: Phase) { self.scope = scope; self.phase = phase }
    }

    public struct Controller: Codable, Equatable, Sendable {
        public var epoch: UInt64
        public var key: String
        public init(epoch: UInt64, key: String) { self.epoch = epoch; self.key = key }
    }

    /// The exact public storageauthority.Binding tuple, not an authorization token.
    public struct AttachmentBinding: Codable, Equatable, Sendable {
        public enum Role: String, Codable, Sendable { case prepare, runtime }
        public enum Mode: String, Codable, Sendable { case readOnly = "read-only", readWrite = "read-write" }
        public var store: String
        public var volume: String
        public var attachment: String
        public var prepare: String?
        public var container: String
        public var launch: String
        public var key: String
        public var role: Role
        public var mode: Mode
        public init(store: String, volume: String, attachment: String, prepare: String? = nil,
                    container: String, launch: String, key: String, role: Role, mode: Mode) {
            self.store = store; self.volume = volume; self.attachment = attachment; self.prepare = prepare
            self.container = container; self.launch = launch; self.key = key; self.role = role; self.mode = mode
        }
    }

    /// Wire shape is storageauthority.DataHello: {epoch, binding}, with no wrapper.
    public struct Notification: Codable, Equatable, Sendable {
        public var epoch: String
        public var binding: AttachmentBinding
        public init(epoch: String, binding: AttachmentBinding) { self.epoch = epoch; self.binding = binding }
    }

    public struct IsolationRequest: Codable, Equatable, Sendable {
        public let requestID: String
        public let operationUUID: String
        public let armDigest: String
        public let challenge: String
        public init(requestID: String, operationUUID: String, armDigest: String, challenge: String) {
            self.requestID = requestID; self.operationUUID = operationUUID
            self.armDigest = armDigest; self.challenge = challenge
        }
    }
    public struct IsolationStatePair: Codable, Equatable, Sendable {
        public let before: IsolationProof
        public let after: IsolationProof
        public init(before: IsolationProof, after: IsolationProof) throws {
            guard before.caseName == "isolation-state", before.result == "registry-state", before == after else { throw ValidationError.invalidFrame }
            self.before = before; self.after = after
        }
    }
    public struct IsolationReceipt: Codable, Equatable, Sendable {
        public let before: IsolationProof
        public let observation: IsolationProof
        public let after: IsolationProof
        public init(before: IsolationProof, observation: IsolationProof, after: IsolationProof) throws {
            guard before.caseName == "isolation-state", after.caseName == "isolation-state",
                  before == after, observation.request == before.request,
                  observation.workerUUID == before.workerUUID, observation.store == before.store,
                  observation.serviceEpoch == before.serviceEpoch, observation.revision == before.revision,
                  observation.registrySHA256 == before.registrySHA256,
                  ["legacy-connection", "second-service-exclusivity"].contains(observation.caseName) else { throw ValidationError.invalidFrame }
            self.before = before; self.observation = observation; self.after = after
        }
    }
    public struct IsolationProof: Codable, Equatable, Sendable {
        public let request: IsolationRequest
        public let workerUUID: String
        public let caseName: String
        public let store: String
        public let serviceEpoch: String
        public let revision: UInt64
        public let registrySHA256: String
        public let result: String
    }

    /// Canonical nonzero lowercase UUID, including ext4 UUIDs that are not UUIDv4.
    public static func validUUID(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard bytes.count == 36, value != "00000000-0000-0000-0000-000000000000" else { return false }
        return bytes.enumerated().allSatisfy { index, byte in
            [8, 13, 18, 23].contains(index) ? byte == 45 : (48...57).contains(byte) || (97...102).contains(byte)
        }
    }

    /// UUIDv4, matching Guest/internal/storageauthority/types.go validID.
    public static func validID(_ value: String) -> Bool {
        guard validUUID(value) else { return false }
        let bytes = Array(value.utf8)
        return bytes[14] == 52 && [56, 57, 97, 98].contains(bytes[19])
    }

}

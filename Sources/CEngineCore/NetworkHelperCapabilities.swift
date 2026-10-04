import Foundation

/// Public compatibility metadata, never authentication, rollout permission, or
/// evidence that an authority/store is open. Native peer authentication comes first.
public enum NetworkHelperCapabilities {
    public enum Profile: String, Codable, Sendable {
        case ordinary
        case lifecycleQualification = "lifecycle-qualification"
    }

    /// Mandatory additive lifecycle extensions are not implied by the original
    /// lifecycle v2 contract and do not change the security revision.
    public enum StorageContract: String, Codable, Sendable, CaseIterable {
        case lifecycleV2 = "lifecycle-v2"
        case lifecycleV2AdoptedServiceChange = "lifecycle-v2-adopted-service-change-v1"
        case lifecycleV2StableHostIdentity = "lifecycle-v2-stable-host-identity-v1"
        /// Authenticated ROOT resolve-dead audit leaves C11 intact; only proven
        /// death permits fresh C12 -> C13 cold recovery. Alive/unknown blocks.
        case lifecycleV2ColdDeadResolution = "lifecycle-v2-cold-dead-resolution-v1"
        /// A completed but unenrolled cold owner can precede a new cold operation
        /// only after all retained native births positively exit; no synthetic ACK.
        case lifecycleV2ColdUnenrolledRecovery = "lifecycle-v2-cold-unenrolled-recovery-v1"
    }

    public enum Requirement: String, Sendable, CaseIterable {
        case lifecycleV2 = "lifecycle-v2"
        case lifecycleQualification = "lifecycle-qualification"
    }

    public struct Advertisement: Codable, Equatable, Sendable {
        public let schemaVersion: Int
        public let securityRevision: UInt64
        public let profile: Profile
        public let storageContracts: [StorageContract]

        public init(schemaVersion: Int = 1, securityRevision: UInt64 = 1,
                    profile: Profile, storageContracts: [StorageContract]) {
            self.schemaVersion = schemaVersion
            self.securityRevision = securityRevision
            self.profile = profile
            self.storageContracts = storageContracts
        }
    }

    public static let maximumBytes = 4096
    /// Compiled rejection floor: not configurable through requests or environment.
    public static let minimumSecurityRevision: UInt64 = 1
    public static let securityRevision: UInt64 = 1

    public enum ValidationError: Error, LocalizedError, Sendable {
        case malformed, incompatible

        public var errorDescription: String? {
            switch self {
            case .malformed:
                return "Privileged Helper returned malformed capabilities"
            case .incompatible:
                return "Privileged Helper capabilities are incompatible; update the Privileged Helper before starting VMs"
            }
        }
    }

    public static func encode(_ value: Advertisement) throws -> Data {
        try validateShape(value)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(value)
        guard bytes.count <= maximumBytes else { throw ValidationError.malformed }
        return bytes
    }

    /// Only this bounded canonical codec is a wire decoder. Plain Codable is for
    /// value composition, not admission of untrusted capability bytes. Exact byte
    /// equality rejects duplicate/unknown keys, noninteger numeric spellings,
    /// whitespace, alternate escapes, and trailing data without lossy NSNumber casts.
    public static func decode(_ bytes: Data) throws -> Advertisement {
        guard !bytes.isEmpty, bytes.count <= maximumBytes else { throw ValidationError.malformed }
        let value = try JSONDecoder().decode(Advertisement.self, from: bytes)
        guard try encode(value) == bytes else { throw ValidationError.malformed }
        return value
    }

    public static func validate(_ value: Advertisement, for requirement: Requirement) throws {
        try validateShape(value)
        let profile: Profile = requirement == .lifecycleQualification ? .lifecycleQualification : .ordinary
        let requiredContracts: Set<StorageContract> = [.lifecycleV2, .lifecycleV2AdoptedServiceChange, .lifecycleV2StableHostIdentity, .lifecycleV2ColdDeadResolution, .lifecycleV2ColdUnenrolledRecovery]
        guard value.profile == profile, requiredContracts.isSubset(of: Set(value.storageContracts)) else {
            throw ValidationError.incompatible
        }
    }

    private static func validateShape(_ value: Advertisement) throws {
        let contracts = Set(value.storageContracts)
        let lifecycleContracts: Set<StorageContract> = [.lifecycleV2, .lifecycleV2AdoptedServiceChange, .lifecycleV2StableHostIdentity, .lifecycleV2ColdDeadResolution, .lifecycleV2ColdUnenrolledRecovery]
        guard value.schemaVersion == 1,
              value.securityRevision >= minimumSecurityRevision,
              !value.storageContracts.isEmpty,
              contracts.count == value.storageContracts.count,
              !contracts.contains(.lifecycleV2AdoptedServiceChange) || contracts.contains(.lifecycleV2),
              !contracts.contains(.lifecycleV2StableHostIdentity) || contracts.contains(.lifecycleV2),
              !contracts.contains(.lifecycleV2ColdDeadResolution) || contracts.contains(.lifecycleV2),
              !contracts.contains(.lifecycleV2ColdUnenrolledRecovery) || contracts.contains(.lifecycleV2),
              value.profile != .lifecycleQualification ||
                (contracts.contains(.lifecycleV2) && contracts.isSubset(of: lifecycleContracts)) else {
            throw ValidationError.incompatible
        }
        // Future security revisions are accepted at or above the compiled floor;
        // neither revision equality nor a fingerprint substitutes for contracts.
    }
}

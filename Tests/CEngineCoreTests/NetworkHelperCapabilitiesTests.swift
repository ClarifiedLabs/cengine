import CEngineCore
import Foundation
import Testing

@Suite struct NetworkHelperCapabilitiesTests {
    private typealias C = NetworkHelperCapabilities
    private let ordinary = C.Advertisement(profile: .ordinary, storageContracts: [.lifecycleV2, .lifecycleV2AdoptedServiceChange, .lifecycleV2StableHostIdentity, .lifecycleV2ColdDeadResolution, .lifecycleV2ColdUnenrolledRecovery])
    private let canonical = "{\"profile\":\"ordinary\",\"schemaVersion\":1,\"securityRevision\":1,\"storageContracts\":[\"lifecycle-v2\",\"lifecycle-v2-adopted-service-change-v1\",\"lifecycle-v2-stable-host-identity-v1\",\"lifecycle-v2-cold-dead-resolution-v1\",\"lifecycle-v2-cold-unenrolled-recovery-v1\"]}"

    @Test func canonicalRoundTrip() throws {
        #expect(try C.encode(ordinary) == Data(canonical.utf8))
        #expect(try C.decode(Data(canonical.utf8)) == ordinary)
        for revision in [C.minimumSecurityRevision, 2, UInt64.max] {
            let value = C.Advertisement(securityRevision: revision, profile: .ordinary, storageContracts: [.lifecycleV2, .lifecycleV2AdoptedServiceChange, .lifecycleV2StableHostIdentity, .lifecycleV2ColdDeadResolution, .lifecycleV2ColdUnenrolledRecovery])
            #expect(try C.decode(C.encode(value)) == value)
            try C.validate(value, for: .lifecycleV2)
        }
    }

    @Test func exactProfilesAndIndependentContracts() throws {
        try C.validate(ordinary, for: .lifecycleV2)
        #expect(throws: (any Error).self) { try C.validate(ordinary, for: .lifecycleQualification) }
        let lifecycle = C.Advertisement(profile: .ordinary, storageContracts: [.lifecycleV2, .lifecycleV2AdoptedServiceChange, .lifecycleV2StableHostIdentity, .lifecycleV2ColdDeadResolution, .lifecycleV2ColdUnenrolledRecovery])
        try C.validate(lifecycle, for: .lifecycleV2)
        #expect(C.Requirement(rawValue: "bootstrap-v1") == nil)
        #expect(C.StorageContract(rawValue: "bootstrap-v1") == nil)
        let qualification = C.Advertisement(profile: .lifecycleQualification, storageContracts: [.lifecycleV2, .lifecycleV2AdoptedServiceChange, .lifecycleV2StableHostIdentity, .lifecycleV2ColdDeadResolution, .lifecycleV2ColdUnenrolledRecovery])
        try C.validate(qualification, for: .lifecycleQualification)
        #expect(try C.decode(C.encode(qualification)) == qualification)
        #expect(throws: (any Error).self) { try C.validate(qualification, for: .lifecycleV2) }
    }

    @Test func oldLifecycleDecodesButRequiresHelperUpdateBeforeVMs() throws {
        for (profile, requirement) in [(C.Profile.ordinary, C.Requirement.lifecycleV2),
                                       (.lifecycleQualification, .lifecycleQualification)] {
            let legacy = C.Advertisement(profile: profile, storageContracts: [.lifecycleV2, .lifecycleV2AdoptedServiceChange])
            let decoded = try C.decode(C.encode(legacy))
            #expect(decoded == legacy)
            do {
                try C.validate(decoded, for: requirement)
                Issue.record("old lifecycle contract satisfied current requirement")
            } catch {
                #expect(error.localizedDescription.contains("update the Privileged Helper before starting VMs"))
            }
        }
        let retired = canonical.replacingOccurrences(of: "lifecycle-v2-adopted-service-change-v1", with: "bootstrap-v1")
        #expect(throws: (any Error).self) { try C.decode(Data(retired.utf8)) }
    }

    @Test func interruptedColdExtensionIsMandatoryWithoutRevisionOrSelectorChurn() throws {
        #expect(C.StorageContract.lifecycleV2ColdDeadResolution.rawValue == "lifecycle-v2-cold-dead-resolution-v1")
        #expect(C.securityRevision == 1)
        #expect(C.minimumSecurityRevision == 1)
        #expect(C.Requirement.allCases.map(\.rawValue) == ["lifecycle-v2", "lifecycle-qualification"])
        for (profile, requirement) in [(C.Profile.ordinary, C.Requirement.lifecycleV2),
                                       (.lifecycleQualification, .lifecycleQualification)] {
            // A helper with every previous extension still cannot start recovery.
            for revision in [C.securityRevision, UInt64.max] {
                let legacy = C.Advertisement(securityRevision: revision, profile: profile,
                    storageContracts: [.lifecycleV2, .lifecycleV2AdoptedServiceChange, .lifecycleV2StableHostIdentity])
                let decoded = try C.decode(C.encode(legacy))
                #expect(decoded == legacy)
                #expect(throws: C.ValidationError.incompatible) { try C.validate(decoded, for: requirement) }
            }
            // Extensions stay additive DTOs, but admission requires each one.
            for missing in C.StorageContract.allCases where missing != .lifecycleV2 {
                let incomplete = C.Advertisement(profile: profile,
                    storageContracts: C.StorageContract.allCases.filter { $0 != missing })
                let decoded = try C.decode(C.encode(incomplete))
                #expect(throws: C.ValidationError.incompatible) { try C.validate(decoded, for: requirement) }
            }
        }
    }

    @Test func unenrolledColdRecoveryRequiresItsSemanticExtension() throws {
        #expect(C.StorageContract.lifecycleV2ColdUnenrolledRecovery.rawValue == "lifecycle-v2-cold-unenrolled-recovery-v1")
        for (profile, requirement) in [(C.Profile.ordinary, C.Requirement.lifecycleV2),
                                       (.lifecycleQualification, .lifecycleQualification)] {
            for revision in [C.securityRevision, UInt64.max] {
                let old = C.Advertisement(securityRevision: revision, profile: profile,
                    storageContracts: [.lifecycleV2, .lifecycleV2AdoptedServiceChange, .lifecycleV2StableHostIdentity, .lifecycleV2ColdDeadResolution])
                let decoded = try C.decode(C.encode(old))
                #expect(decoded == old)
                #expect(throws: C.ValidationError.incompatible) { try C.validate(decoded, for: requirement) }
            }
        }
    }

    @Test func qualificationContractsAreAnUnorderedClosedLifecycleSet() throws {
        let reversed = C.Advertisement(profile: .lifecycleQualification,
            storageContracts: [.lifecycleV2ColdUnenrolledRecovery, .lifecycleV2ColdDeadResolution, .lifecycleV2StableHostIdentity, .lifecycleV2AdoptedServiceChange, .lifecycleV2])
        #expect(try C.decode(C.encode(reversed)) == reversed)
        try C.validate(reversed, for: .lifecycleQualification)
    }

    @Test func invalidValuesCannotBeEncodedOrValidated() {
        let invalid = [
            C.Advertisement(schemaVersion: 0, profile: .ordinary, storageContracts: [.lifecycleV2]),
            C.Advertisement(schemaVersion: 2, profile: .ordinary, storageContracts: [.lifecycleV2]),
            C.Advertisement(securityRevision: 0, profile: .ordinary, storageContracts: [.lifecycleV2]),
            C.Advertisement(profile: .ordinary, storageContracts: []),
            C.Advertisement(profile: .ordinary, storageContracts: [.lifecycleV2StableHostIdentity]),
            C.Advertisement(profile: .ordinary, storageContracts: [.lifecycleV2ColdUnenrolledRecovery]),
            C.Advertisement(profile: .lifecycleQualification, storageContracts: [.lifecycleV2ColdUnenrolledRecovery]),
            C.Advertisement(profile: .ordinary, storageContracts: [.lifecycleV2ColdDeadResolution]),
            C.Advertisement(profile: .lifecycleQualification, storageContracts: [.lifecycleV2ColdDeadResolution]),
            C.Advertisement(profile: .ordinary, storageContracts: [.lifecycleV2, .lifecycleV2ColdDeadResolution, .lifecycleV2ColdDeadResolution]),
            C.Advertisement(profile: .ordinary, storageContracts: [.lifecycleV2, .lifecycleV2]),
            C.Advertisement(profile: .ordinary, storageContracts: [.lifecycleV2AdoptedServiceChange]),
            C.Advertisement(profile: .ordinary, storageContracts: [.lifecycleV2, .lifecycleV2AdoptedServiceChange, .lifecycleV2AdoptedServiceChange]),
            C.Advertisement(profile: .lifecycleQualification, storageContracts: [.lifecycleV2AdoptedServiceChange]),
            C.Advertisement(profile: .lifecycleQualification, storageContracts: [.lifecycleV2, .lifecycleV2AdoptedServiceChange, .lifecycleV2AdoptedServiceChange])
        ]
        for value in invalid {
            #expect(throws: (any Error).self) { try C.encode(value) }
            for requirement in C.Requirement.allCases {
                #expect(throws: (any Error).self) { try C.validate(value, for: requirement) }
            }
        }
    }

    @Test func closedCanonicalObjectRejectsAmbiguity() {
        let invalid = [
            "", "{}", "[]", "null", canonical + "\n", " " + canonical, canonical + canonical,
            canonical.replacingOccurrences(of: "\"profile\":\"ordinary\"", with: "\"profile\":\"ordinary\",\"profile\":\"ordinary\""),
            canonical.replacingOccurrences(of: "\"profile\":\"ordinary\"", with: "\"profile\":\"ordinary\",\"pro\\u0066ile\":\"ordinary\""),
            canonical.replacingOccurrences(of: "\"schemaVersion\":1", with: "\"schemaVersion\":1,\"schemaVersion\":1"),
            canonical.replacingOccurrences(of: "\"profile\":\"ordinary\",", with: ""),
            canonical.replacingOccurrences(of: "\"schemaVersion\":1,", with: ""),
            canonical.replacingOccurrences(of: "\"securityRevision\":1,", with: ""),
            canonical.replacingOccurrences(of: ",\"storageContracts\":[\"lifecycle-v2\",\"lifecycle-v2-adopted-service-change-v1\",\"lifecycle-v2-stable-host-identity-v1\",\"lifecycle-v2-cold-dead-resolution-v1\",\"lifecycle-v2-cold-unenrolled-recovery-v1\"]", with: ""),
            canonical.replacingOccurrences(of: "\"profile\"", with: "\"unknown\""),
            canonical.replacingOccurrences(of: "{", with: "{\"extra\":true,"),
            canonical.replacingOccurrences(of: "ordinary", with: "unknown"),
            canonical.replacingOccurrences(of: "lifecycle-v2-adopted-service-change-v1", with: "unknown"),
            canonical.replacingOccurrences(of: "lifecycle-v2-adopted-service-change-v1", with: "lifecycle-v2"),
            canonical.replacingOccurrences(of: "lifecycle-v2-adopted-service-change-v1", with: "bootstrap-v1")
        ]
        for text in invalid {
            #expect(throws: (any Error).self) { try C.decode(Data(text.utf8)) }
        }
        #expect(throws: (any Error).self) { try C.decode(Data(repeating: 32, count: C.maximumBytes + 1)) }
        #expect(throws: (any Error).self) { try C.decode(Data([0xff, 0xfe])) }
    }

    @Test func contractTypesAndDuplicatesAreExact() {
        for token in ["true", "false", "null", "1", "{}", "[]",
                      "\"lifecycle-v2-adopted-service-change-v1\",\"lifecycle-v2-adopted-service-change-v1\""] {
            let text = canonical.replacingOccurrences(of: "\"lifecycle-v2-adopted-service-change-v1\"", with: token)
            #expect(throws: (any Error).self) { try C.decode(Data(text.utf8)) }
        }
        for token in ["true", "null", "1", "{}", "\"lifecycle-v2\""] {
            let text = canonical.replacingOccurrences(
                of: "[\"lifecycle-v2\",\"lifecycle-v2-adopted-service-change-v1\",\"lifecycle-v2-stable-host-identity-v1\",\"lifecycle-v2-cold-dead-resolution-v1\",\"lifecycle-v2-cold-unenrolled-recovery-v1\"]", with: token)
            #expect(throws: (any Error).self) { try C.decode(Data(text.utf8)) }
        }
    }

    @Test func numericTypesAreExactAndBounded() {
        for key in ["schemaVersion", "securityRevision"] {
            for token in ["true", "false", "null", "\"1\"", "1.0", "1e0", "1E+0", "-1", "-0", "0", "01", "18446744073709551616", "99999999999999999999999999999999999", "[]", "{}"] {
                let text = canonical.replacingOccurrences(of: "\"\(key)\":1", with: "\"\(key)\":\(token)")
                #expect(throws: (any Error).self) { try C.decode(Data(text.utf8)) }
            }
        }
    }
}

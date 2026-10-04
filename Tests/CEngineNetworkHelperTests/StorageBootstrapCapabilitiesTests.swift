import CEngineCore
import Testing
@testable import StorageBootstrapHelper

@Suite struct StorageBootstrapCapabilitiesTests {
    private typealias C = NetworkHelperCapabilities

    @Test func ordinaryCompatibilityAdvertisesOnlyCurrentLifecycleContracts() throws {
        let value = try #require(StorageBootstrapCapabilities.advertisement(namespace: .compatibility, profile: .ordinary))
        #expect(value.profile == .ordinary)
        #expect(value.storageContracts == [.lifecycleV2, .lifecycleV2AdoptedServiceChange, .lifecycleV2StableHostIdentity, .lifecycleV2ColdDeadResolution, .lifecycleV2ColdUnenrolledRecovery])
        #expect(value.securityRevision == C.securityRevision)
        try C.validate(value, for: .lifecycleV2)
        #expect(throws: (any Error).self) { try C.validate(value, for: .lifecycleQualification) }
    }

    @Test func productionDoesNotAdvertiseBootstrap() throws {
        let value = try #require(StorageBootstrapCapabilities.advertisement(namespace: .production, profile: .ordinary))
        #expect(value.storageContracts == [.lifecycleV2, .lifecycleV2AdoptedServiceChange, .lifecycleV2StableHostIdentity, .lifecycleV2ColdDeadResolution, .lifecycleV2ColdUnenrolledRecovery])
        try C.validate(value, for: .lifecycleV2)
    }

    @Test func qualificationIsSeparateAndLifecycleOnly() throws {
        let value = try #require(StorageBootstrapCapabilities.advertisement(namespace: .compatibility, profile: .lifecycleQualification))
        #expect(value.profile == .lifecycleQualification)
        #expect(value.storageContracts == [.lifecycleV2, .lifecycleV2AdoptedServiceChange, .lifecycleV2StableHostIdentity, .lifecycleV2ColdDeadResolution, .lifecycleV2ColdUnenrolledRecovery])
        try C.validate(value, for: .lifecycleQualification)
        #expect(throws: (any Error).self) { try C.validate(value, for: .lifecycleV2) }
        #expect(StorageBootstrapCapabilities.advertisement(namespace: .production, profile: .lifecycleQualification) == nil)
    }

    @Test func missingIdentityOrRejectedProfileNeverDefaultsToOrdinary() {
        #expect(StorageBootstrapCapabilities.advertisement(namespace: nil, profile: .ordinary) == nil)
        #expect(StorageBootstrapCapabilities.advertisement(namespace: .compatibility, profile: nil) == nil)
        #expect(StorageBootstrapCapabilities.advertisement(namespace: .production, profile: nil) == nil)
        #expect(StorageBootstrapCapabilities.advertisement(namespace: nil, profile: nil) == nil)
    }

    @Test func unsignedTestHostOmitsManagedCapabilities() {
        // Pure routing fixtures above are not proofs; live admission still checks
        // the running helper signature and signed profile, without storage I/O.
        #expect(StorageBootstrapCapabilities.current() == nil)
    }
}

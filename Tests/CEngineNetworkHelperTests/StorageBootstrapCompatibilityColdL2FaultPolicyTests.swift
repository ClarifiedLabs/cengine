import CEngineCore
import Foundation
import Testing
@testable import StorageBootstrapHelper

@Suite struct StorageBootstrapCompatibilityColdL2FaultPolicyTests {
    typealias Policy = StorageBootstrapCompatibilityColdL2FaultPolicy

    @Test func onlyProtectedRecoveryBridgeBypassesCut() {
        #expect(Policy.shouldInject(hasRecoveryBridge: false))
        #expect(!Policy.shouldInject(hasRecoveryBridge: true))
        // The guard is not one-shot: unbridged pending-L2 retries remain cut.
        #expect(Policy.shouldInject(hasRecoveryBridge: false))
    }

    #if CENGINE_COMPAT_COLD_L2_FAULT
    @Test func nativeRejectionIsBlockedAndProtectedBridgeSkipsInjection() throws {
        // This test process is not the authenticated native helper. Identity or
        // metadata rejection must still fail closed with the same blocked code.
        do {
            try Policy.afterColdL2BeforeA1(hasRecoveryBridge: false)
            Issue.record("unbridged L2 fault returned success")
        } catch let failure as BootstrapFailure {
            #expect(failure.code == .blocked)
        }
        try Policy.afterColdL2BeforeA1(hasRecoveryBridge: true)
    }
    #endif

    @Test func exactOrdinaryCompatibilityMetadataOnly() throws {
        let valid: [String: Any] = ["CEngineCompatColdL2Fault": "after-cold-l2-before-a1-v1"]
        #expect(try Policy.validateFields(namespace: .compatibility, isQualification: false,
            plist: valid) == .afterColdL2BeforeA1)
        #expect(throws: BootstrapFailure.self) {
            try Policy.validateFields(namespace: .production, isQualification: false, plist: valid)
        }
        #expect(throws: BootstrapFailure.self) {
            try Policy.validateFields(namespace: .compatibility, isQualification: true, plist: valid)
        }
        #expect(throws: BootstrapFailure.self) {
            try Policy.validateFields(namespace: .compatibility, isQualification: false, plist: [:])
        }
        for value: Any in ["", "after-cold-l2-before-a1-v2", " after-cold-l2-before-a1-v1",
                           "after-cold-l2-before-a1-v1 ", "before-configure-v1", 1, true, NSNull(), ["after-cold-l2-before-a1-v1"]] {
            #expect(throws: BootstrapFailure.self) {
                try Policy.validateFields(namespace: .compatibility, isQualification: false,
                    plist: ["CEngineCompatColdL2Fault": value])
            }
        }
        for key in ["CEngineStorageLifecycleQualification", "CEngineStorageLifecycleSourcePin", "CEngineStorageLifecycleAssetsSHA256"] {
            var plist = valid
            plist[key] = ""
            #expect(try Policy.validateFields(namespace: .compatibility, isQualification: false,
                plist: plist) == .afterColdL2BeforeA1)
            for value: Any in ["lifecycle-v2-native-v1", String(repeating: "a", count: 64), " ", 1, false, NSNull(), [String]()] {
                plist[key] = value
                #expect(throws: BootstrapFailure.self) {
                    try Policy.validateFields(namespace: .compatibility, isQualification: false, plist: plist)
                }
            }
        }
    }
}

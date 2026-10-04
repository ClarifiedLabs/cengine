import Foundation
import Security
import Testing
@testable import CEngineCore

@Suite struct StorageLifecycleNativePolicyTests {
    typealias Policy = StorageLifecycleNativePolicy
    private let pin = String(repeating: "a", count: 64)
    private let assets = String(repeating: "b", count: 64)
    private var plist: [String: Any] {
        ["CEngineStorageLifecycleQualification": "lifecycle-v2-native-v1",
         "CEngineStorageLifecycleSourcePin": pin,
         "CEngineStorageLifecycleAssetsSHA256": assets]
    }

    @Test func productionRemainsTheClosedDefault() {
        let policy = Policy.production
        #expect(policy.namespace == .production)
        #expect(!policy.isQualification)
        #expect(policy.engineIdentifier == PrivilegedPortProtocol.defaultEngineIdentifier)
        #expect(policy.helperIdentifier == PrivilegedPortProtocol.defaultHelperIdentifier)
        #expect(policy.controllerIdentifier == "dev.cengine.storage-control")
        #expect(policy.serviceName == PrivilegedPortProtocol.defaultServiceName)
        #expect(!(policy as Any is any Encodable))
        #expect(!(policy as Any is any Decodable))
    }

    @Test func ordinaryPolicyRejectsFullPartialAndMalformedQualificationMetadata() throws {
        try Policy.validateOrdinaryFields(plist: [:])
        try Policy.validateOrdinaryFields(plist: plist.mapValues { _ in "" })
        #expect(throws: (any Error).self) { try Policy.validateOrdinaryFields(plist: plist) }
        for key in plist.keys {
            for value: Any in [plist[key]!, NSNull(), 1, false, " ", "lifecycle-v2-native-v1\n"] {
                #expect(throws: (any Error).self) { try Policy.validateOrdinaryFields(plist: [key: value]) }
            }
        }
    }

    @Test func qualificationRequiresExactProfileAndLowercaseSourcePin() throws {
        #expect(try Policy.validateQualificationFields(plist: plist) == pin)
        for key in plist.keys {
            var missing = plist; missing.removeValue(forKey: key)
            #expect(throws: (any Error).self) { try Policy.validateQualificationFields(plist: missing) }
            for value: Any in [NSNull(), 1, true, "", "production", "lifecycle-v2-native-v1\n"] {
                var bad = plist; bad[key] = value
                #expect(throws: (any Error).self) { try Policy.validateQualificationFields(plist: bad) }
            }
        }
        for invalid in [String(repeating: "A", count: 64), String(repeating: "g", count: 64),
                        String(repeating: "0", count: 63), String(repeating: "0", count: 65),
                        String(repeating: "é", count: 32), pin + "\n", " " + pin] {
            for key in ["CEngineStorageLifecycleSourcePin", "CEngineStorageLifecycleAssetsSHA256"] {
                var bad = plist; bad[key] = invalid
                #expect(throws: (any Error).self) { try Policy.validateQualificationFields(plist: bad) }
            }
        }
        var digits = plist; digits["CEngineStorageLifecycleSourcePin"] = String(repeating: "0123456789abcdef", count: 4)
        #expect(try Policy.validateQualificationFields(plist: digits).count == 64)
    }

    @Test func peerMustMatchTheFrozenSignedSourcePin() throws {
        #expect(try Policy.validateQualificationFields(plist: plist, expectedSourcePin: pin,
                                                       expectedAssetsSHA256: assets) == pin)
        #expect(throws: (any Error).self) {
            try Policy.validateQualificationFields(plist: plist, expectedSourcePin: pin,
                                                   expectedAssetsSHA256: String(repeating: "c", count: 64))
        }
        #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
        #expect(Policy.production.qualificationAssetsSHA256 == nil)
        #endif
        #expect(throws: (any Error).self) {
            try Policy.validateQualificationFields(plist: plist, expectedSourcePin: String(repeating: "b", count: 64))
        }
        // A valid metadata DTO still cannot construct any policy or native proof.
        #expect(Policy.production.namespace == .production)
    }

    @Test(arguments: [SignedStorageIdentity.Role.engine, .helper])
    func testProcessCannotAuthenticateAsNativePeer(role: SignedStorageIdentity.Role) throws {
        #expect(throws: (any Error).self) { try Policy.production.currentIdentity(role: role) }
        #expect(throws: (any Error).self) { try Policy.current(role: role) }
        var running: SecCode?
        #expect(SecCodeCopySelf([], &running) == errSecSuccess)
        let code = try #require(running)
        #expect(throws: (any Error).self) {
            try Policy.production.validatePeer(code, pid: getpid(), role: role, expectedTeam: "ABCDEFGHIJ")
        }
        #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
        #expect(throws: (any Error).self) { try Policy.qualification(role: role) }
        #endif
    }

    @Test func testProcessCannotSubstituteForController() throws {
        var running: SecCode?, code: SecStaticCode?
        #expect(SecCodeCopySelf([], &running) == errSecSuccess)
        #expect(SecCodeCopyStaticCode(try #require(running), [], &code) == errSecSuccess)
        let actual = try #require(code)
        #expect(throws: (any Error).self) {
            try Policy.production.validateControllerCode(actual, expectedTeam: "ABCDEFGHIJ")
        }
    }
}

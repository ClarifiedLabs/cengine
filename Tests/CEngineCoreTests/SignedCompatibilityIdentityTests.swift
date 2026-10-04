import Foundation
import Security
import Testing
@testable import CEngineCore

@Suite struct SignedCompatibilityIdentityTests {
    private func plist(_ role: SignedCompatibilityIdentity.Role) -> [String: Any] {
        ["CFBundleIdentifier": role == .engine ? "dev.cengine.engine.test-compat" : "dev.cengine.network-helper.test-compat",
         "CEngineTeamIdentifier": "ABCDEFGHIJ", "CEngineNetworkHelperServiceName": "dev.cengine.network-helper.test-compat",
         role == .engine ? "CEngineNetworkHelperIdentifier" : "CEngineNetworkHelperClientIdentifier":
            role == .engine ? "dev.cengine.network-helper.test-compat" : "dev.cengine.engine.test-compat"]
    }
    @Test func policyAcceptsOnlyExactRoleAndMatchingSecuredMetadata() throws {
        for role: SignedCompatibilityIdentity.Role in [.engine, .helper] {
            let metadata = plist(role)
            let identifier = try #require(metadata["CFBundleIdentifier"] as? String)
            try SignedCompatibilityIdentity.validateFields(role: role, team: "ABCDEFGHIJ", identifier: identifier, plist: metadata)
            for field in metadata.keys {
                for invalid: Any in [NSNull(), "", "production", 1, "ABCDEFGHIJ\" or always"] {
                    var altered = metadata; altered[field] = invalid
                    #expect(throws: (any Error).self) {
                        try SignedCompatibilityIdentity.validateFields(role: role, team: "ABCDEFGHIJ", identifier: identifier, plist: altered)
                    }
                }
                var missing = metadata; missing.removeValue(forKey: field)
                #expect(throws: (any Error).self) {
                    try SignedCompatibilityIdentity.validateFields(role: role, team: "ABCDEFGHIJ", identifier: identifier, plist: missing)
                }
            }
        }
    }
    @Test(arguments: ["", "ABCDEFGHI", "ABCDEFGHIJK", "abcdefghij", "ABCDEF123\"", "ABCDE1234\n"])
    func invalidActualTeamNeverEntersARequirement(team: String) {
        #expect(throws: (any Error).self) {
            try SignedCompatibilityIdentity.validateFields(role: .engine, team: team,
                identifier: "dev.cengine.engine.test-compat", plist: plist(.engine))
        }
    }
    @Test(arguments: ["dev.cengine.engine", "dev.cengine.app", "dev.cengine.storage-control.test-compat", "dev.cengine.network-helper.test-compat"])
    func productionOrDifferentActualRoleCannotEnableEngine(identifier: String) {
        var metadata = plist(.engine); metadata["CFBundleIdentifier"] = identifier
        #expect(throws: (any Error).self) {
            try SignedCompatibilityIdentity.validateFields(role: .engine, team: "ABCDEFGHIJ", identifier: identifier, plist: metadata)
        }
    }
    @Test func hardenedRuntimeAndNonpermissiveEntitlementsAreRequired() throws {
        let flags = kSecCodeInfoFlags as String, entitlements = kSecCodeInfoEntitlementsDict as String
        try SignedCompatibilityIdentity.validateFlags([flags: NSNumber(value: 0x10000)])
        try SignedCompatibilityIdentity.validateFlags([flags: NSNumber(value: 0x10000), entitlements: ["com.apple.security.virtualization": true]])
        for invalid in [0, 2, 0x10002] {
            #expect(throws: (any Error).self) { try SignedCompatibilityIdentity.validateFlags([flags: NSNumber(value: invalid)]) }
        }
        for forbidden in SignedStorageIdentity.forbiddenControllerEntitlements {
            #expect(throws: (any Error).self) {
                try SignedCompatibilityIdentity.validateFlags([flags: NSNumber(value: 0x10000), entitlements: [forbidden: false]])
            }
        }
        #expect(throws: (any Error).self) { try SignedCompatibilityIdentity.validateFlags([flags: NSNumber(value: 0x10000), entitlements: "not a dictionary"]) }
    }
    @Test func everyPeerRequirementIncludesDeveloperIDOnlyCertificateOIDs() throws {
        for identifier in ["dev.cengine.engine.test-compat", "dev.cengine.network-helper.test-compat", "dev.cengine.storage-control.test-compat"] {
            let text = try SignedCompatibilityIdentity.developerIDRequirement(identifiers: [identifier], team: "ABCDEFGHIJ")
            #expect(text.contains("certificate 1[field.1.2.840.113635.100.6.2.6] exists"))
            #expect(text.contains("certificate leaf[field.1.2.840.113635.100.6.1.13] exists"))
            var requirement: SecRequirement?
            #expect(SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess)
        }
        #expect(throws: (any Error).self) {
            try SignedCompatibilityIdentity.developerIDRequirement(identifiers: ["arbitrary\" or always"], team: "ABCDEFGHIJ")
        }
        var running: SecCode?
        #expect(SecCodeCopySelf([], &running) == errSecSuccess)
        if let running {
            #expect(throws: (any Error).self) {
                try SignedCompatibilityIdentity.validatePeer(running, pid: getpid(), role: .engine, expectedTeam: "ABCDEFGHIJ")
            }
        }
    }
    @Test func unsignedOrUnitTestSelfCannotMintEitherNativeProof() {
        // Real SecCodeCopySelf path; these tests are not signed activation binaries.
        #expect(throws: (any Error).self) { try SignedCompatibilityIdentity.current(role: .engine) }
        #expect(throws: (any Error).self) { try SignedCompatibilityIdentity.current(role: .helper) }
    }
}

import Foundation
import Security
import Testing
@testable import CEngineCore

@Suite struct SignedStorageIdentityTests {
    typealias Identity = SignedStorageIdentity

    private func plist(_ role: Identity.Role, _ namespace: Identity.Namespace) -> [String: Any] {
        ["CFBundleIdentifier": role == .engine ? namespace.engineIdentifier : namespace.helperIdentifier,
         "CEngineTeamIdentifier": "ABCDEFGHIJ",
         PrivilegedPortProtocol.serviceNameInfoKey: namespace.serviceName,
         role == .engine ? PrivilegedPortProtocol.helperIdentifierInfoKey : PrivilegedPortProtocol.clientIdentifierInfoKey:
            role == .engine ? namespace.helperIdentifier : namespace.engineIdentifier]
    }

    @Test(arguments: Identity.Namespace.allCases, [Identity.Role.engine, .helper])
    func securedMetadataIsExactForEachNamespace(namespace: Identity.Namespace, role: Identity.Role) throws {
        let metadata = plist(role, namespace)
        let identifier = try #require(metadata["CFBundleIdentifier"] as? String)
        try Identity.validateFields(role: role, namespace: namespace, team: "ABCDEFGHIJ", identifier: identifier, plist: metadata)
        #expect(try Identity.selectedNamespace(role: role, team: "ABCDEFGHIJ", identifier: identifier, plist: metadata) == namespace)
        for field in metadata.keys {
            for invalid: Any in [NSNull(), "", "production", 1, "ABCDEFGHIJ\" or always"] {
                var altered = metadata; altered[field] = invalid
                #expect(throws: (any Error).self) {
                    try Identity.validateFields(role: role, namespace: namespace, team: "ABCDEFGHIJ", identifier: identifier, plist: altered)
                }
                #expect(throws: (any Error).self) {
                    try Identity.selectedNamespace(role: role, team: "ABCDEFGHIJ", identifier: identifier, plist: altered)
                }
            }
            var missing = metadata; missing.removeValue(forKey: field)
            #expect(throws: (any Error).self) {
                try Identity.validateFields(role: role, namespace: namespace, team: "ABCDEFGHIJ", identifier: identifier, plist: missing)
            }
        }
        for team in ["", "ABCDEFGHI", "ABCDEFGHIJK", "abcdefghij", "ABCDEF123\"", "ABCDE1234\n"] {
            #expect(throws: (any Error).self) {
                try Identity.selectedNamespace(role: role, team: team, identifier: identifier, plist: metadata)
            }
        }
    }

    @Test(arguments: Identity.Namespace.allCases, [Identity.Role.engine, .helper])
    func otherNamespaceAndRoleCannotSubstitute(namespace: Identity.Namespace, role: Identity.Role) throws {
        let otherNamespace: Identity.Namespace = namespace == .production ? .compatibility : .production
        let metadata = plist(role, otherNamespace)
        let identifier = try #require(metadata["CFBundleIdentifier"] as? String)
        #expect(throws: (any Error).self) {
            try Identity.validateFields(role: role, namespace: namespace, team: "ABCDEFGHIJ", identifier: identifier, plist: metadata)
        }
        let proper = plist(role, namespace)
        for wrong in [namespace.controllerIdentifier, "dev.cengine.app",
                      role == .engine ? namespace.helperIdentifier : namespace.engineIdentifier] {
            var altered = proper; altered["CFBundleIdentifier"] = wrong
            #expect(throws: (any Error).self) {
                try Identity.selectedNamespace(role: role, team: "ABCDEFGHIJ", identifier: wrong, plist: altered)
            }
        }
        // Even with the correct actual role, mixing any secured peer/service field is refused.
        let actual = try #require(proper["CFBundleIdentifier"] as? String)
        for field in [PrivilegedPortProtocol.serviceNameInfoKey,
                      role == .engine ? PrivilegedPortProtocol.helperIdentifierInfoKey : PrivilegedPortProtocol.clientIdentifierInfoKey] {
            var altered = proper; altered[field] = metadata[field]
            #expect(throws: (any Error).self) {
                try Identity.selectedNamespace(role: role, team: "ABCDEFGHIJ", identifier: actual, plist: altered)
            }
        }
    }

    @Test func controllerCodeRequiresRuntimeAndNoInjectionEntitlements() {
        #expect(!Identity.acceptsControllerCodeSigning(flags: 0, entitlementKeys: []))
        #expect(Identity.acceptsControllerCodeSigning(flags: Identity.controllerRuntimeFlag, entitlementKeys: []))
        for entitlement in Identity.forbiddenControllerEntitlements {
            #expect(!Identity.acceptsControllerCodeSigning(flags: Identity.controllerRuntimeFlag, entitlementKeys: [entitlement]))
        }
    }

    @Test func hardenedSignatureRejectsAdHocAndRelaxedEntitlements() throws {
        let flags = kSecCodeInfoFlags as String
        let entitlements = kSecCodeInfoEntitlementsDict as String
        try Identity.validateFlags([flags: NSNumber(value: 0x10000)])
        for invalid: UInt32 in [0, 2, 0x10002] {
            #expect(throws: (any Error).self) { try Identity.validateFlags([flags: NSNumber(value: invalid)]) }
        }
        for key in ["com.apple.security.get-task-allow", "com.apple.security.cs.disable-library-validation",
                    "com.apple.security.cs.allow-dyld-environment-variables"] {
            #expect(throws: (any Error).self) {
                try Identity.validateFlags([flags: NSNumber(value: 0x10000), entitlements: [key: false]])
            }
        }
        #expect(throws: (any Error).self) { try Identity.validateFlags([:]) }
        #expect(throws: (any Error).self) {
            try Identity.validateFlags([flags: NSNumber(value: 0x10000), entitlements: "malformed"])
        }
    }

    @Test(arguments: [Identity.Role.engine, .helper])
    func exactProductionMetadataNeverUnlocksCompatibilityFaults(role: Identity.Role) throws {
        let metadata = plist(role, .production)
        let identifier = try #require(metadata["CFBundleIdentifier"] as? String)
        try Identity.validateFields(role: role, namespace: .production, team: "ABCDEFGHIJ", identifier: identifier, plist: metadata)
        #expect(throws: (any Error).self) {
            try SignedCompatibilityIdentity.validateFields(role: role, team: "ABCDEFGHIJ", identifier: identifier, plist: metadata)
        }
    }

    @Test(arguments: Identity.Namespace.allCases)
    func namespacePoliciesUseExactDeveloperIDRoles(namespace: Identity.Namespace) throws {
        #expect(namespace.serviceName == namespace.helperIdentifier)
        for identifier in [namespace.engineIdentifier, namespace.helperIdentifier, namespace.controllerIdentifier] {
            let text = try Identity.developerIDRequirement(identifiers: [identifier], team: "ABCDEFGHIJ")
            #expect(text.contains("identifier \"\(identifier)\""))
            #expect(text.contains("certificate 1[field.1.2.840.113635.100.6.2.6] exists"))
            #expect(text.contains("certificate leaf[field.1.2.840.113635.100.6.1.13] exists"))
            var requirement: SecRequirement?
            #expect(SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess)
        }
    }

    @Test(arguments: Identity.Namespace.allCases, [Identity.Role.engine, .helper])
    func testSelfCannotMintOrValidateAnyNativeRole(namespace: Identity.Namespace, role: Identity.Role) throws {
        #expect(throws: (any Error).self) { try Identity.current(role: role, namespace: namespace) }
        #expect(throws: (any Error).self) { try Identity.current(role: role) }
        var running: SecCode?
        #expect(SecCodeCopySelf([], &running) == errSecSuccess)
        let code = try #require(running)
        #expect(throws: (any Error).self) {
            try Identity.validatePeer(code, pid: getpid(), role: role, namespace: namespace, expectedTeam: "ABCDEFGHIJ")
        }
    }
}

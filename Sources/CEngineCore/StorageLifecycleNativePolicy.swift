import Foundation
import Security

/// Closed, nonserialized namespace policy for the native lifecycle path.
/// Signed qualification metadata narrows an authenticated identity; it is never
/// authentication, rollout authorization, or a compatibility fault capability.
public struct StorageLifecycleNativePolicy: Equatable, Sendable {
    public static let production = Self(namespace: .production, sourcePin: nil, assetsSHA256: nil, team: nil)
    public let namespace: SignedStorageIdentity.Namespace
    /// Namespace is not qualification authority. Only the explicit factory pins a profile.
    public var isQualification: Bool { sourcePin != nil }
    private let sourcePin: String?
    private let assetsSHA256: String?
    private let team: String?

    private init(namespace: SignedStorageIdentity.Namespace, sourcePin: String?, assetsSHA256: String?, team: String?) {
        self.namespace = namespace
        self.sourcePin = sourcePin; self.assetsSHA256 = assetsSHA256; self.team = team
    }

    /// Ordinary production/compatibility policy selected only by the running signature.
    /// Qualification profiles must use the separate, explicitly compiled factory.
    public static func current(role: SignedStorageIdentity.Role) throws -> Self {
        let identity = try SignedStorageIdentity.current(role: role)
        var running: SecCode?
        guard SecCodeCopySelf([], &running) == errSecSuccess, let running else { throw unavailable() }
        try validateOrdinaryFields(plist: signedPlist(running))
        return Self(namespace: identity.namespace, sourcePin: nil, assetsSHA256: nil, team: identity.teamIdentifier)
    }
    public var engineIdentifier: String { namespace.engineIdentifier }
    public var helperIdentifier: String { namespace.helperIdentifier }
    public var controllerIdentifier: String { namespace.controllerIdentifier }
    public var serviceName: String { namespace.serviceName }

    #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
    /// Public build receipt only; exposing it does not mint a native policy.
    public var qualificationSourcePin: String? { sourcePin }
    public var qualificationAssetsSHA256: String? { assetsSHA256 }
    /// No supplied namespace, plist, pin, environment, or decoded request can mint
    /// this policy. Both the running signature and its sealed plist are required.
    public static func qualification(role: SignedStorageIdentity.Role) throws -> Self {
        let identity = try SignedStorageIdentity.current(role: role, namespace: .compatibility)
        var running: SecCode?
        guard SecCodeCopySelf([], &running) == errSecSuccess, let running else { throw unavailable() }
        try SignedStorageIdentity.validatePeer(running, pid: getpid(), role: role,
            namespace: .compatibility, expectedTeam: identity.teamIdentifier)
        let plist = try signedPlist(running)
        let pin = try validateQualificationFields(plist: plist)
        return Self(namespace: .compatibility, sourcePin: pin, assetsSHA256: plist["CEngineStorageLifecycleAssetsSHA256"] as? String,
                    team: identity.teamIdentifier)
    }
    #endif

    /// Revalidates this process before native spawn or shim authentication.
    public func currentIdentity(role: SignedStorageIdentity.Role) throws -> SignedStorageIdentity {
        let identity = try SignedStorageIdentity.current(role: role, namespace: namespace)
        if let team { guard identity.teamIdentifier == team else { throw Self.unavailable() } }
        var running: SecCode?
        guard SecCodeCopySelf([], &running) == errSecSuccess, let running else { throw Self.unavailable() }
        try validateProfile(plist: Self.signedPlist(running))
        return identity
    }

    /// Caller supplies real audit-pinned code and retains kernel process-generation
    /// checks around this call. The qualification profile is read from signed code.
    public func validatePeer(_ running: SecCode, pid: Int32, role: SignedStorageIdentity.Role,
                             expectedTeam: String) throws {
        if let team { guard expectedTeam == team else { throw Self.unavailable() } }
        try SignedStorageIdentity.validatePeer(running, pid: pid, role: role,
            namespace: namespace, expectedTeam: expectedTeam)
        try validateProfile(plist: Self.signedPlist(running))
    }

    /// Static controller preflight/qualification only. The launch or audit owner
    /// MUST also validate the actual running code, csops, and process generation.
    /// Controllers have their own role, not an engine/helper SignedStorageIdentity.
    public func validateControllerCode(_ code: SecStaticCode, expectedTeam: String) throws {
        if let team { guard expectedTeam == team else { throw Self.unavailable() } }
        let text = try SignedStorageIdentity.developerIDRequirement(identifiers: [controllerIdentifier], team: expectedTeam)
        var requirement: SecRequirement?, information: CFDictionary?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess, let requirement,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let values = information as? [String: Any] else { throw Self.unavailable() }
        try SignedStorageIdentity.validateFlags(values)
        let metadata = values[kSecCodeInfoPList as String]
        guard metadata == nil || metadata is [String: Any] else { throw Self.unavailable() }
        try validateProfile(plist: metadata as? [String: Any] ?? [:])
    }

    private func validateProfile(plist: [String: Any]) throws {
        if let sourcePin {
            _ = try Self.validateQualificationFields(plist: plist, expectedSourcePin: sourcePin,
                                                     expectedAssetsSHA256: assetsSHA256)
        } else {
            try Self.validateOrdinaryFields(plist: plist)
        }
    }

    // Xcode's ordinary sealed plist has empty build-setting placeholders. Only
    // absent or empty strings are ordinary; malformed and partial profiles fail.
    static func validateOrdinaryFields(plist: [String: Any]) throws {
        for key in ["CEngineStorageLifecycleQualification", "CEngineStorageLifecycleSourcePin",
                    "CEngineStorageLifecycleAssetsSHA256"] {
            guard plist[key] == nil || plist[key] as? String == "" else { throw unavailable() }
        }
    }

    private static func signedPlist(_ running: SecCode) throws -> [String: Any] {
        var code: SecStaticCode?, information: CFDictionary?
        guard SecCodeCopyStaticCode(running, [], &code) == errSecSuccess, let code,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let values = information as? [String: Any],
              let plist = values[kSecCodeInfoPList as String] as? [String: Any] else { throw unavailable() }
        return plist
    }

    // Pure rejection seam: returns text only, never a policy or identity proof.
    static func validateQualificationFields(plist: [String: Any], expectedSourcePin: String? = nil,
                                            expectedAssetsSHA256: String? = nil) throws -> String {
        guard plist["CEngineStorageLifecycleQualification"] as? String == "lifecycle-v2-native-v1",
              let pin = plist["CEngineStorageLifecycleSourcePin"] as? String,
              pin.utf8.count == 64,
              pin.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              let assets = plist["CEngineStorageLifecycleAssetsSHA256"] as? String,
              assets.utf8.count == 64,
              assets.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              expectedSourcePin == nil || pin == expectedSourcePin,
              expectedAssetsSHA256 == nil || assets == expectedAssetsSHA256 else { throw unavailable() }
        return pin
    }
    private static func unavailable() -> EngineError {
        EngineError(.unsupported, "native storage lifecycle requires matching authenticated namespace and signed qualification profile")
    }
}

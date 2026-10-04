import Darwin
import Foundation
import Security

@_silgen_name("csops")
nonisolated private func storageCodeStatus(_ pid: Int32, _ operation: UInt32, _ buffer: UnsafeMutableRawPointer, _ size: Int) -> Int32

/// Nonserialized proof of a running Developer-ID-signed storage engine/helper.
/// A production proof is NOT rollout authorization or a compatibility fault capability.
public struct SignedStorageIdentity: Sendable {
    /// CS_RUNTIME (XNU cs_blobs.h). Code identity alone does not protect a
    /// same-UID nonexporting key holder against debugger/DYLD injection.
    public static let controllerRuntimeFlag: UInt32 = 0x0001_0000
    public static let forbiddenControllerEntitlements: Set<String> = [
        "com.apple.security.get-task-allow", "com.apple.security.cs.debugger",
        "com.apple.security.cs.disable-library-validation", "com.apple.security.cs.allow-unsigned-executable-memory",
        "com.apple.security.cs.allow-dyld-environment-variables", "com.apple.security.cs.allow-jit",
        "com.apple.security.cs.disable-executable-page-protection"
    ]
    public static func acceptsControllerCodeSigning(flags: UInt32, entitlementKeys: Set<String>) -> Bool {
        flags & controllerRuntimeFlag != 0 && forbiddenControllerEntitlements.isDisjoint(with: entitlementKeys)
    }

    public enum Role: Sendable { case engine, helper }
    public enum Namespace: CaseIterable, Sendable {
        case production, compatibility

        public var engineIdentifier: String {
            self == .compatibility ? PrivilegedPortProtocol.testCompatEngineIdentifier : PrivilegedPortProtocol.defaultEngineIdentifier
        }
        public var helperIdentifier: String {
            self == .compatibility ? PrivilegedPortProtocol.testCompatHelperIdentifier : PrivilegedPortProtocol.defaultHelperIdentifier
        }
        public var serviceName: String {
            self == .compatibility ? PrivilegedPortProtocol.testCompatServiceName : PrivilegedPortProtocol.defaultServiceName
        }
        public var controllerIdentifier: String {
            self == .compatibility ? "dev.cengine.storage-control.test-compat" : "dev.cengine.storage-control"
        }
    }

    public let teamIdentifier: String
    public let executable: URL
    public let namespace: Namespace
    private let role: Role

    private init(teamIdentifier: String, executable: URL, role: Role, namespace: Namespace) {
        self.teamIdentifier = teamIdentifier; self.executable = executable
        self.role = role; self.namespace = namespace
    }

    /// Selects exactly one namespace from the actual running signed identifier.
    /// No environment, request metadata, or alternate-helper retry participates.
    public static func current(role: Role) throws -> Self {
        try current(role: role, expectedNamespace: nil)
    }

    /// Namespace selects an exact rejection policy, never asserts the actual identity.
    /// All identity/team/peer/service metadata comes from the running code signature.
    public static func current(role: Role, namespace: Namespace) throws -> Self {
        try current(role: role, expectedNamespace: namespace)
    }

    private static func current(role: Role, expectedNamespace: Namespace?) throws -> Self {
        var running: SecCode?, code: SecStaticCode?, information: CFDictionary?
        guard SecCodeCopySelf([], &running) == errSecSuccess, let running,
              SecCodeCopyStaticCode(running, [], &code) == errSecSuccess, let code,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let values = information as? [String: Any],
              let team = values[kSecCodeInfoTeamIdentifier as String] as? String,
              let identifier = values[kSecCodeInfoIdentifier as String] as? String,
              let plist = values[kSecCodeInfoPList as String] as? [String: Any],
              let executable = values[kSecCodeInfoMainExecutable as String] as? URL,
              executable.isFileURL, executable.path.hasPrefix("/") else { throw unavailable() }
        let namespace = try selectedNamespace(role: role, team: team, identifier: identifier, plist: plist)
        guard expectedNamespace == nil || expectedNamespace == namespace else { throw unavailable() }
        try validateFlags(values)
        let requirement = try requirement(identifier: identifier, team: team)
        let flags = SecCSFlags(rawValue: kSecCSStrictValidate)
        var status: UInt32 = 0
        guard SecStaticCodeCheckValidity(code, flags, requirement) == errSecSuccess,
              SecCodeCheckValidity(running, flags, requirement) == errSecSuccess,
              storageCodeStatus(getpid(), 0, &status, MemoryLayout<UInt32>.size) == 0,
              status & controllerRuntimeFlag != 0 else { throw unavailable() }
        return Self(teamIdentifier: team, executable: executable, role: role, namespace: namespace)
    }

    /// Fixed sibling of the verified engine, in the same namespace and team.
    /// Launch independently rechecks the actual suspended child; preflight is not adoption.
    public func storageControllerExecutable() throws -> URL {
        guard role == .engine else { throw Self.unavailable() }
        let child = executable.deletingLastPathComponent().appending(path: "cengine-storage-controller")
        var code: SecStaticCode?, information: CFDictionary?
        guard SecStaticCodeCreateWithPath(child as CFURL, [], &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate),
                try Self.requirement(identifier: namespace.controllerIdentifier, team: teamIdentifier)) == errSecSuccess,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let values = information as? [String: Any] else { throw Self.unavailable() }
        try Self.validateFlags(values)
        return child
    }

    // Pure rejection policy for tests; no native proof can be constructed from these fields.
    static func selectedNamespace(role: Role, team: String, identifier: String, plist: [String: Any]) throws -> Namespace {
        guard let namespace = Namespace.allCases.first(where: {
            identifier == (role == .engine ? $0.engineIdentifier : $0.helperIdentifier)
        }) else { throw unavailable() }
        try validateFields(role: role, namespace: namespace, team: team, identifier: identifier, plist: plist)
        return namespace
    }

    static func validateFields(role: Role, namespace: Namespace, team: String, identifier: String, plist: [String: Any]) throws {
        guard team.utf8.count == 10,
              team.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) }),
              identifier == (role == .engine ? namespace.engineIdentifier : namespace.helperIdentifier),
              plist["CFBundleIdentifier"] as? String == identifier,
              plist["CEngineTeamIdentifier"] as? String == team,
              plist[PrivilegedPortProtocol.serviceNameInfoKey] as? String == namespace.serviceName else { throw unavailable() }
        let key = role == .engine ? PrivilegedPortProtocol.helperIdentifierInfoKey : PrivilegedPortProtocol.clientIdentifierInfoKey
        let peer = role == .engine ? namespace.helperIdentifier : namespace.engineIdentifier
        guard plist[key] as? String == peer else { throw unavailable() }
    }

    static func validateFlags(_ information: [String: Any]) throws {
        let entitlements = information[kSecCodeInfoEntitlementsDict as String]
        guard let flags = information[kSecCodeInfoFlags as String] as? NSNumber,
              flags.uint32Value & 0x2 == 0, // CS_ADHOC is never a storage identity.
              entitlements == nil || entitlements is [String: Any],
              acceptsControllerCodeSigning(flags: flags.uint32Value,
                entitlementKeys: Set((entitlements as? [String: Any] ?? [:]).keys)) else { throw unavailable() }
    }

    /// Policy text only, not an authenticated identity proof.
    public static func developerIDRequirement(identifiers: [String], team: String) throws -> String {
        let allowed = Set(Namespace.allCases.flatMap { [$0.engineIdentifier, $0.helperIdentifier, $0.controllerIdentifier] })
        guard team.utf8.count == 10, team.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) }),
              !identifiers.isEmpty, identifiers.count <= 2, Set(identifiers).count == identifiers.count,
              identifiers.allSatisfy(allowed.contains) else { throw unavailable() }
        let roles = identifiers.map { "identifier \"\($0)\"" }.joined(separator: " or ")
        return "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and (\(roles)) and certificate leaf[subject.OU] = \"\(team)\""
    }

    /// Additional checks on an immutable-audit-pinned engine/helper. The caller
    /// retains its PID-generation checks around validation; this mints no proof.
    public static func validatePeer(_ running: SecCode, pid: Int32, role: Role,
                                    namespace: Namespace, expectedTeam: String) throws {
        var code: SecStaticCode?, information: CFDictionary?
        guard pid > 0, SecCodeCopyStaticCode(running, [], &code) == errSecSuccess, let code,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let values = information as? [String: Any],
              let team = values[kSecCodeInfoTeamIdentifier as String] as? String, team == expectedTeam,
              let identifier = values[kSecCodeInfoIdentifier as String] as? String,
              let plist = values[kSecCodeInfoPList as String] as? [String: Any] else { throw unavailable() }
        try validateFields(role: role, namespace: namespace, team: team, identifier: identifier, plist: plist)
        try validateFlags(values)
        let policy = try requirement(identifier: identifier, team: team)
        var status: UInt32 = 0
        guard SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), policy) == errSecSuccess,
              SecCodeCheckValidity(running, SecCSFlags(rawValue: kSecCSStrictValidate), policy) == errSecSuccess,
              storageCodeStatus(pid, 0, &status, MemoryLayout<UInt32>.size) == 0,
              status & controllerRuntimeFlag != 0 else { throw unavailable() }
    }

    private static func requirement(identifier: String, team: String) throws -> SecRequirement {
        let text = try developerIDRequirement(identifiers: [identifier], team: team)
        var value: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &value) == errSecSuccess, let value else { throw unavailable() }
        return value
    }

    private static func unavailable() -> EngineError {
        EngineError(.unsupported, "managed storage requires a hardened Developer-ID-signed binary with matching embedded namespace, identity and paired controller")
    }
}

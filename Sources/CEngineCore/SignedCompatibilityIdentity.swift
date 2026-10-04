import Foundation
import Security

/// Compatibility-only capability, including all runtime fault-control gates.
/// Production storage identity must NEVER broaden this proof's acceptance policy.
public struct SignedCompatibilityIdentity: Sendable {
    public typealias Role = SignedStorageIdentity.Role
    private let identity: SignedStorageIdentity
    public var teamIdentifier: String { identity.teamIdentifier }
    public var executable: URL { identity.executable }

    private init(identity: SignedStorageIdentity) { self.identity = identity }

    public static func current(role: Role) throws -> Self {
        Self(identity: try SignedStorageIdentity.current(role: role, namespace: .compatibility))
    }

    public func storageControllerExecutable() throws -> URL {
        try identity.storageControllerExecutable()
    }

    // Pure compatibility rejection policy; cannot mint a native proof.
    static func validateFields(role: Role, team: String, identifier: String, plist: [String: Any]) throws {
        try SignedStorageIdentity.validateFields(role: role, namespace: .compatibility,
            team: team, identifier: identifier, plist: plist)
    }

    static func validateFlags(_ information: [String: Any]) throws {
        try SignedStorageIdentity.validateFlags(information)
    }

    public static func developerIDRequirement(identifiers: [String], team: String) throws -> String {
        try SignedStorageIdentity.developerIDRequirement(identifiers: identifiers, team: team)
    }

    public static func validatePeer(_ running: SecCode, pid: Int32, role: Role, expectedTeam: String) throws {
        try SignedStorageIdentity.validatePeer(running, pid: pid, role: role,
            namespace: .compatibility, expectedTeam: expectedTeam)
    }
}

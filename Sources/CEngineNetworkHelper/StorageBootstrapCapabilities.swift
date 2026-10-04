import CEngineHelperSupport
import Darwin
@preconcurrency import XPC

@_silgen_name("xpc_dictionary_get_audit_token")
private func networkingMessageAuditToken(_ message: xpc_object_t, _ token: UnsafeMutablePointer<audit_token_t>)

/// Status-only metadata. This path must not construct a ROOT router, enroll an
/// owner, or open/create any storage authority, journal, or scope.
enum StorageBootstrapCapabilities {
    static func current() -> NetworkHelperCapabilities.Advertisement? {
        // Both factories validate the actual helper signature and sealed profile.
        // A malformed/partial qualification profile cannot fall back to ordinary.
        if let policy = try? StorageLifecycleNativePolicy.current(role: .helper) {
            return advertisement(namespace: policy.namespace, profile: .ordinary)
        }
        #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
        if let policy = try? StorageLifecycleNativePolicy.qualification(role: .helper) {
            return advertisement(namespace: policy.namespace, profile: .lifecycleQualification)
        }
        #endif
        return nil
    }

    /// Pure routing seam only: supplied fields produce a public DTO, NOT native
    /// identity or authority. Production status uses only the factories above.
    static func advertisement(namespace: SignedStorageIdentity.Namespace?,
                              profile: NetworkHelperCapabilities.Profile?) -> NetworkHelperCapabilities.Advertisement? {
        guard let namespace, let profile else { return nil }
        let contracts: [NetworkHelperCapabilities.StorageContract]
        switch (namespace, profile) {
        case (.compatibility, .ordinary): contracts = [.lifecycleV2, .lifecycleV2AdoptedServiceChange, .lifecycleV2StableHostIdentity, .lifecycleV2ColdDeadResolution, .lifecycleV2ColdUnenrolledRecovery]
        case (.production, .ordinary): contracts = [.lifecycleV2, .lifecycleV2AdoptedServiceChange, .lifecycleV2StableHostIdentity, .lifecycleV2ColdDeadResolution, .lifecycleV2ColdUnenrolledRecovery]
        case (.compatibility, .lifecycleQualification): contracts = [.lifecycleV2, .lifecycleV2AdoptedServiceChange, .lifecycleV2StableHostIdentity, .lifecycleV2ColdDeadResolution, .lifecycleV2ColdUnenrolledRecovery]
        case (.production, .lifecycleQualification): return nil
        }
        return .init(securityRevision: NetworkHelperCapabilities.securityRevision,
                     profile: profile, storageContracts: contracts)
    }
}

/// Native profile selection is independent of owner enrollment and never opens
/// storage state. No environment, request, or unsigned identity fallback exists.
struct StorageBootstrapAdmission {
    let policy: StorageLifecycleNativePolicy
    let team: String

    static func current() throws -> Self {
        let policy: StorageLifecycleNativePolicy
        do { policy = try .current(role: .helper) }
        catch {
            #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
            policy = try .qualification(role: .helper)
            #else
            throw error
            #endif
        }
        return try .init(policy: policy, team: policy.currentIdentity(role: .helper).teamIdentifier)
    }

    func listenerRequirement() throws -> String {
        try Self.listenerRequirement(namespace: policy.namespace, team: team)
    }
    /// Text-only rejection seam, not a native policy or authentication proof.
    static func listenerRequirement(namespace: SignedStorageIdentity.Namespace, team: String) throws -> String {
        try SignedStorageIdentity.developerIDRequirement(
            identifiers: [namespace.engineIdentifier, namespace.controllerIdentifier], team: team)
    }

    static func requireNetworkingOperation(_ message: xpc_object_t) throws {
        guard xpc_get_type(message) == XPC_TYPE_DICTIONARY,
              let value = xpc_dictionary_get_value(message, "operation"), xpc_get_type(value) == XPC_TYPE_STRING,
              xpc_string_get_length(value) <= 64, let text = xpc_string_get_string_ptr(value),
              String(cString: text).utf8.count == xpc_string_get_length(value),
              ["status", "restart", "bind", "start-vmnet", "stop-vmnet"].contains(String(cString: text)) else {
            throw EngineError(.unsupported, "unsupported privileged networking helper operation")
        }
    }

    func authenticateNetworking(_ message: xpc_object_t) throws {
        var token = audit_token_t()
        networkingMessageAuditToken(message, &token)
        try authenticateNetworking(token: token)
    }
    /// An actual received immutable trailer is mandatory in production. This seam
    /// permits unsigned rejection tests without calling libxpc on a fake message.
    func authenticateNetworking(token: audit_token_t) throws {
        guard token.val.1 != 0 else { throw BootstrapFailure(.unauthorized) }
        let owner = policy.namespace == .compatibility
            ? try StorageLifecycleScopeNamespace.compatibility.configuredOwner() : token.val.1
        _ = try StorageBootstrapProcesses(ownerUID: owner, team: team, policy: policy)
            .daemon(audit: .init(token: token))
    }
}

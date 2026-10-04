import CEngineHelperSupport
import Foundation
#if CENGINE_COMPAT_COLD_L2_FAULT
import Security
#endif

/// Pure rejection/guard seams remain testable without compiling the native fault.
/// Neither metadata nor a caller-supplied value can authorize native injection.
enum StorageBootstrapCompatibilityColdL2FaultPolicy {
    enum Profile: String {
        case afterColdL2BeforeA1 = "after-cold-l2-before-a1-v1"
    }

    @discardableResult
    static func validateFields(namespace: SignedStorageIdentity.Namespace, isQualification: Bool,
                               plist: [String: Any]) throws -> Profile {
        guard namespace == .compatibility, !isQualification,
              let raw = plist["CEngineCompatColdL2Fault"] as? String,
              let profile = Profile(rawValue: raw) else { throw BootstrapFailure(.blocked) }
        for key in ["CEngineStorageLifecycleQualification", "CEngineStorageLifecycleSourcePin",
                    "CEngineStorageLifecycleAssetsSHA256"] {
            guard plist[key] == nil || plist[key] as? String == "" else { throw BootstrapFailure(.blocked) }
        }
        return profile
    }

    /// The authority derives this Boolean only from its protected Prepared state.
    /// A genuinely resolved-dead successor must not repeat the original L2 cut.
    static func shouldInject(hasRecoveryBridge: Bool) -> Bool {
        !hasRecoveryBridge
    }

    #if CENGINE_COMPAT_COLD_L2_FAULT
    static func afterColdL2BeforeA1(hasRecoveryBridge: Bool) throws {
        guard shouldInject(hasRecoveryBridge: hasRecoveryBridge) else { return }
        do { _ = try currentProfile() }
        catch { throw BootstrapFailure(.blocked) }
        // Immediate failure: no pause, ROOT log marker, external selector or proof.
        throw BootstrapFailure(.blocked)
    }

    private static func currentProfile() throws -> Profile {
        let policy = try StorageLifecycleNativePolicy.current(role: .helper)
        _ = try policy.currentIdentity(role: .helper)
        var running: SecCode?, code: SecStaticCode?, information: CFDictionary?
        guard SecCodeCopySelf([], &running) == errSecSuccess, let running,
              SecCodeCopyStaticCode(running, [], &code) == errSecSuccess, let code,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let values = information as? [String: Any],
              let plist = values[kSecCodeInfoPList as String] as? [String: Any] else { throw BootstrapFailure(.blocked) }
        return try validateFields(namespace: policy.namespace, isQualification: policy.isQualification, plist: plist)
    }
    #endif
}

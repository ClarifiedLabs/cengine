#if os(macOS)
import CEngineCore
import Foundation
#if CENGINE_COMPAT_LIFECYCLE_FAULT
import Security
#endif

/// A rejection-only metadata seam is testable in ordinary builds. The native
/// fault implementation and its caller exist only in the selected Runtime build.
enum StorageLifecycleCompatibilityFaultPolicy {
    enum Profile: String {
        case beforeConfigure = "before-configure-v1"
        case beforeColdConfigure = "before-cold-configure-v1"
        case afterReplacement = "after-replacement-before-completion-v1"
        case beforeTakeoverApply = "before-takeover-apply-v1"
        case afterTakeoverApply = "after-takeover-apply-v1"
        case afterFirstColdApply = "after-first-cold-apply-v1"
        case afterFirstColdCompletion = "after-first-cold-completion-v1"
    }
    static func applies(to action: StorageLifecycleServiceBootProtocol.Configuration.Action,
                        profile: Profile = .beforeConfigure, observed: Bool = false) -> Bool {
        switch profile {
        case .beforeConfigure: action == .initialize
        case .beforeColdConfigure: action == .coldOpenTakeover && !observed
        default: false
        }
    }

    /// The authenticated takeover from C1 commits C2. Later cold successors must recover normally.
    static func isFirstColdCompletion(expectedEpoch: UInt64) -> Bool {
        expectedEpoch == 1
    }

    static func isFirstColdApply(expectedEpoch: UInt64, observed: Bool) -> Bool {
        expectedEpoch == 1 && !observed
    }

    // Values alone cannot authorize a fault: the compiled caller below obtains
    // both the ordinary native policy and the sealed plist from this process.
    @discardableResult
    static func validateFields(namespace: SignedStorageIdentity.Namespace, isQualification: Bool,
                               plist: [String: Any]) throws -> Profile {
        guard namespace == .compatibility, !isQualification,
              let raw = plist["CEngineCompatLifecycleFault"] as? String,
              let profile = Profile(rawValue: raw) else { throw refused() }
        for key in ["CEngineStorageLifecycleQualification", "CEngineStorageLifecycleSourcePin",
                    "CEngineStorageLifecycleAssetsSHA256"] {
            guard plist[key] == nil || plist[key] as? String == "" else { throw refused() }
        }
        return profile
    }

    /// Bounded public regression evidence only. It is never read by the engine,
    /// ROOT or a controller and cannot complete or authorize a replacement.
    struct ReplacementObservation: Codable, Equatable {
        let observation: StorageLifecycleProtocol.ServiceChangeConfirmation
        let predecessorWorkerUUID: String
        let workerUUID: String
    }
    static func replacementObservation(_ observation: StorageLifecycleProtocol.ServiceChangeConfirmation,
                                       predecessorWorkerUUID: String, workerUUID: String) throws -> Data {
        try observation.validate()
        guard StorageServiceTypes.validID(predecessorWorkerUUID),
              StorageServiceTypes.validID(workerUUID), predecessorWorkerUUID != workerUUID else { throw refused() }
        return try StorageLifecycleProtocol.encode(ReplacementObservation(observation: observation,
            predecessorWorkerUUID: predecessorWorkerUUID, workerUUID: workerUUID))
    }

    /// Public grant and live identity only; no signature, certificate or key material.
    struct TakeoverObservation: Codable, Equatable {
        let grant: StorageLifecycleProtocol.Grant
        let serviceEpoch: String
        let workerUUID: String
        let openRevision: UInt64
    }
    static func takeoverObservation(grant: StorageLifecycleProtocol.Grant, serviceEpoch: String,
                                    workerUUID: String, openRevision: UInt64) throws -> Data {
        try grant.validate()
        guard grant.operation == .takeover, StorageServiceTypes.validID(serviceEpoch),
              StorageServiceTypes.validID(workerUUID), openRevision > 0 else { throw refused() }
        let bytes = try StorageLifecycleProtocol.encode(TakeoverObservation(grant: grant,
            serviceEpoch: serviceEpoch, workerUUID: workerUUID, openRevision: openRevision))
        guard bytes.count <= 8192 else { throw refused() }
        return bytes
    }

    #if CENGINE_COMPAT_LIFECYCLE_FAULT
    /// After actual Guest apply/reconciliation, before any ROOT completion.
    static func afterFirstColdApply(_ prepared: StorageLifecycleColdRootProtocol.Prepared) throws {
        guard try currentProfile() == .afterFirstColdApply,
              isFirstColdApply(expectedEpoch: prepared.signedOpen.request.takeover.grant.expectedEpoch,
                  observed: prepared.signedOpen.request.observation != nil) else { return }
        FileHandle.standardError.write(Data("cengine.compat.lifecycle.after-first-cold-apply-v1.injected\n".utf8))
        throw EngineError(.conflict, "controlled compatibility first-cold apply failure before ROOT completion")
    }

    /// Called only after checked ROOT completion and HOST completeCold persistence,
    /// before enrollment. No additional disk/state writes or runtime selectors.
    static func afterFirstColdCompletion(_ completion: StorageLifecycleColdRootProtocol.Completed) throws {
        guard try currentProfile() == .afterFirstColdCompletion,
              isFirstColdCompletion(expectedEpoch: completion.receipt.grant.expectedEpoch) else { return }
        FileHandle.standardError.write(Data("cengine.compat.lifecycle.after-first-cold-completion-v1.injected\n".utf8))
        throw EngineError(.conflict, "controlled compatibility first-cold completion failure before enrollment")
    }

    /// Only a successfully authenticated and persisted recovery on this owner
    /// suppresses the cut. No external selector or durable marker can bypass it.
    static func takeoverApply(_ point: Profile, recoveredHandoff: Bool,
                              grant: StorageLifecycleProtocol.Grant, serviceEpoch: String,
                              workerUUID: String, openRevision: UInt64) async throws {
        guard !recoveredHandoff else { return }
        guard point == .beforeTakeoverApply || point == .afterTakeoverApply else { throw refused() }
        guard try currentProfile() == point else { return }
        let bytes = try takeoverObservation(grant: grant, serviceEpoch: serviceEpoch,
            workerUUID: workerUUID, openRevision: openRevision)
        FileHandle.standardError.write(Data("cengine.compat.lifecycle.\(point.rawValue).paused ".utf8) + bytes + Data([10]))
        try await Task.sleep(for: .seconds(30))
        throw EngineError(.conflict, "controlled compatibility takeover pause expired")
    }

    /// Called only after the real bound Guest4106 hello and before any configure
    /// bytes. Throwing uses the coordinator's normal close and positive Guest exit
    /// cleanup; there is no runtime environment, file, wire or command selector.
    static func beforeConfigure(action: StorageLifecycleServiceBootProtocol.Configuration.Action, observed: Bool = false) throws {
        guard action == .initialize || action == .coldOpenTakeover else { return }
        let profile = try currentProfile()
        guard applies(to: action, profile: profile, observed: observed) else { return }
        FileHandle.standardError.write(Data("cengine.compat.lifecycle.\(profile.rawValue).injected\n".utf8))
        throw EngineError(.conflict, "controlled compatibility failure before configure")
    }

    /// Only the normal replacement path calls this, after actual successful native
    /// replacement and before child rebind/ROOT completion. The bounded pause gives
    /// the owned test time to kill its daemon; no environment/file/IPC can release
    /// it or turn a timeout into success. Recovery never calls this hook.
    static func afterReplacementBeforeCompletion(_ observation: StorageLifecycleProtocol.ServiceChangeConfirmation,
                                                 predecessorWorkerUUID: String, workerUUID: String) async throws {
        guard try currentProfile() == .afterReplacement else { return }
        let bytes = try replacementObservation(observation, predecessorWorkerUUID: predecessorWorkerUUID, workerUUID: workerUUID)
        FileHandle.standardError.write(Data("cengine.compat.lifecycle.after-replacement-before-completion-v1.paused ".utf8)
            + bytes + Data([10]))
        try await Task.sleep(for: .seconds(30))
        throw EngineError(.conflict, "controlled compatibility replacement pause expired")
    }

    private static func currentProfile() throws -> Profile {
        let policy = try StorageLifecycleNativePolicy.current(role: .engine)
        _ = try policy.currentIdentity(role: .engine)
        var running: SecCode?, code: SecStaticCode?, information: CFDictionary?
        guard SecCodeCopySelf([], &running) == errSecSuccess, let running,
              SecCodeCopyStaticCode(running, [], &code) == errSecSuccess, let code,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let values = information as? [String: Any],
              let plist = values[kSecCodeInfoPList as String] as? [String: Any] else { throw refused() }
        return try validateFields(namespace: policy.namespace, isQualification: policy.isQualification, plist: plist)
    }
    #endif

    private static func refused() -> EngineError {
        .init(.unsupported, "lifecycle fault requires the exact sealed ordinary signed compatibility selection")
    }
}
#endif

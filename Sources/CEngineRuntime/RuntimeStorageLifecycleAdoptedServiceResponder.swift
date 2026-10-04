#if os(macOS)
import CEngineCore
import Foundation

/// Nonexportable pairing of actual accepted daemon socket and original private IO.
/// Only the adoption shim constructs this after native committed-session admission.
final class StorageLifecycleAdoptedServiceResponder: @unchecked Sendable {
    private let session: StorageLifecycleAdoptionShim.CommittedSession
    private let boot: PrivateStorageLifecycleBootCoordinator.VerifiedBoot
    init(session: StorageLifecycleAdoptionShim.CommittedSession,
         trustedBoot: PrivateStorageLifecycleBootCoordinator.VerifiedBoot) {
        self.session = session; boot = trustedBoot
    }
    func withAdmission<T>(_ body: () throws -> T) throws -> T { try session.withAdmission(body) }
    func prove(_ challenge: StorageLifecycleAdoptionProtocol.ServiceChangeChallenge,
               deadline: DispatchTime) throws -> StorageLifecycleAdoptionProtocol.ServiceChangeReply {
        try challenge.validate()
        func check() throws {
            try session.validate()
            guard challenge.adoption == session.request,
                  challenge.adoption.origin.shimLaunchUUID == boot.binding.shimLaunchUUID,
                  challenge.adoption.origin.rootPublicKey == boot.rootPublicKey.publicData,
                  challenge.isFresh(at: UInt64(Date().timeIntervalSince1970 * 1000)),
                  DispatchTime.now() < deadline else { throw StorageLifecycleAdoptionShim.Failure.unauthorized }
            _ = try boot.validateHeldDisk()
        }
        try check()
        let now = DispatchTime.now()
        guard now < deadline else { throw StorageLifecycleAdoptionShim.Failure.unavailable }
        let remaining = Double(deadline.uptimeNanoseconds - now.uptimeNanoseconds) / 1_000_000_000
        let proof = try boot.adoptedServiceChangeProof(challenge, deadline: ProcessInfo.processInfo.systemUptime + remaining)
        try check()
        return proof
    }
    func prove(_ challenge: StorageLifecycleAdoptionProtocol.ServiceChallenge,
               deadline: DispatchTime) throws -> StorageLifecycleAdoptionProtocol.ServiceReply {
        try challenge.validate()
        func check() throws {
            try session.validate()
            guard challenge.adoption == session.request,
                  challenge.adoption.origin.shimLaunchUUID == boot.binding.shimLaunchUUID,
                  challenge.adoption.origin.rootPublicKey == boot.rootPublicKey.publicData,
                  challenge.isFresh(at: UInt64(Date().timeIntervalSince1970 * 1000)),
                  DispatchTime.now() < deadline else { throw StorageLifecycleAdoptionShim.Failure.unauthorized }
            _ = try boot.validateHeldDisk()
        }
        try check()
        let now = DispatchTime.now()
        guard now < deadline else { throw StorageLifecycleAdoptionShim.Failure.unavailable }
        let remaining = Double(deadline.uptimeNanoseconds - now.uptimeNanoseconds) / 1_000_000_000
        let proof = try boot.adoptedServiceProof(challenge, deadline: ProcessInfo.processInfo.systemUptime + remaining)
        try check()
        return proof
    }
}
#endif

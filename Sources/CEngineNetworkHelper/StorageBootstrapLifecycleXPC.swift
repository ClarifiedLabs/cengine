import CEngineHelperSupport
import Darwin
import Foundation
@preconcurrency import XPC

@_silgen_name("xpc_dictionary_get_audit_token")
private func lifecycleRootAudit(_ message: xpc_object_t, _ token: UnsafeMutablePointer<audit_token_t>)

/// Dispatches authenticated storage lifecycle RPCs to the root-helper authority.
/// Uses the same worker as child, disk-binding and service-proof enrollment.
final class StorageBootstrapLifecycleXPC: @unchecked Sendable {
    typealias Wire = StorageLifecycleRootProtocol
    private let worker: StorageBootstrapLifecycleChildWorker
    private let authority: StorageBootstrapLifecycleAuthority
    private let journal: any StorageLifecycleJournal
    private let root: StorageIdentity.RootPublicKey
    private let native: StorageBootstrapProcesses
    private let remember: (BootstrapProcess) throws -> Void
    private let callbacks = DispatchQueue(label: "dev.cengine.storage-lifecycle.root-replies")

    init(ownerUID: uid_t, team: String, journal: any StorageLifecycleJournal,
         processes: any StorageLifecycleProcessChecking, bindings: any StorageLifecycleFreshBindingChecking,
         worker: StorageBootstrapLifecycleChildWorker, remember: @escaping (BootstrapProcess) throws -> Void,
         policy: StorageLifecycleNativePolicy = .production) throws {
        guard ownerUID != 0 else { throw BootstrapFailure(.unauthorized) }
        _ = try SignedStorageIdentity.developerIDRequirement(identifiers: [policy.engineIdentifier], team: team)
        self.worker = worker; self.journal = journal; self.remember = remember
        native = StorageBootstrapProcesses(ownerUID: ownerUID, team: team, policy: policy)
        root = try journal.lifecycleRootPublicKey()
        authority = try StorageBootstrapLifecycleAuthority(journal: journal, processes: processes, bindings: bindings)
        guard try journal.lifecycleRootPublicKey() == root else { throw BootstrapFailure(.repairRequired) }
    }

    /// Scheduling seam for native greet closures too. Never wait on the caller's
    /// event/reply queue; callbacks are delivered outside the shared proof worker.
    func schedule(_ operation: @escaping @Sendable () throws -> Void,
                  completion: @escaping @Sendable (Result<Void, any Error>) -> Void) {
        worker.enqueue { [self] in
            let result = Result { try worker.requireCurrent(); try operation() }
            callbacks.async { completion(result) }
        }
    }

    /// Only genuinely received Mach dictionaries: the audit SPI requires a trailer.
    /// Malformed envelopes fail without FD duplication or an uncorrelated wire reply.
    func handle(_ message: xpc_object_t, reply: xpc_object_t,
                completion: @escaping @Sendable (Result<Void, any Error>) -> Void) {
        schedule({ [self] in
            let request = try Self.decodeRequest(message)
            var token = audit_token_t(); lifecycleRootAudit(message, &token)
            let audit = BootstrapAuditIdentity(token: token)
            let body: Wire.ResultBody
            do {
                let daemon = try native.daemon(audit: audit)
                let result = try Self.withDescriptors(message, request: request) { rootFD, backingFD in
                    try dispatch(request, daemon: daemon, rootFD: rootFD, backingFD: backingFD)
                }
                guard try native.daemon(audit: audit) == daemon else { throw BootstrapFailure(.unauthorized) }
                body = result
            } catch let failure as BootstrapFailure { body = .failure(failure.code) }
            catch { body = .failure(.unavailable) }
            let data = try Wire.encode(Wire.Reply(for: request, body: body))
            data.withUnsafeBytes { xpc_dictionary_set_data(reply, "reply", $0.baseAddress, $0.count) }
            xpc_dictionary_set_bool(reply, "ok", true)
        }, completion: completion)
    }

    /// Service-shim successor boots: ROOT's exact pending change, on the shared worker.
    func authorizeServiceBootUpdate(predecessor: StorageLifecycleBootTrust, successor: StorageLifecycleBootTrust) throws {
        try worker.requireCurrent()
        try authority.authorizeServiceBootUpdate(predecessor: predecessor, successor: successor)
    }

    func adoptedService(identity: Lifecycle.Identity, proving grant: Lifecycle.Grant? = nil) throws -> Lifecycle.ServiceState {
        try worker.requireCurrent()
        return try authority.adoptedService(identity: identity, proving: grant)
    }
    func completeAdoptedServiceChange(adoption: Adoption.Request, change: Lifecycle.ServiceChangeRequest,
        peer: BootstrapAuditIdentity, adoptionAuthority: StorageBootstrapLifecycleAdoptionAuthority,
        check: () throws -> Void,
        prove: (Lifecycle.ServiceChangeRequest, StorageLifecycleBootTrust?, Lifecycle.ServiceChangeConfirmation?, Data,
                StorageLifecycleShimOrigin) throws -> Adoption.ServiceChangeReply
    ) throws -> (Lifecycle.ServiceChangeConfirmation, Lifecycle.ServiceResult) {
        try worker.requireCurrent()
        return try authority.completeAdoptedServiceChange(adoption: adoption, change: change, peer: peer,
            adoptionAuthority: adoptionAuthority, check: check, prove: prove)
    }

    func currentOriginPrincipal(binding: StorageIdentity.StoreBinding) throws -> (Lifecycle.Grant, BootstrapPrincipal, StorageLifecycleBootTrust) {
        try worker.requireCurrent()
        return try authority.currentOriginPrincipal(binding: binding)
    }

    func freshEnrollmentBacking(origin: StorageLifecycleShimOrigin) throws -> StorageIdentity.DescriptorIdentity {
        try worker.requireCurrent(); return try authority.freshEnrollmentBacking(origin: origin)
    }

    func configureCold(adoption: StorageBootstrapLifecycleAdoptionAuthority, mounted: any StorageLifecycleColdChecking) throws {
        try worker.requireCurrent(); try authority.configureCold(adoption: adoption, mounted: mounted)
    }
    func configureHandoff(adoption: StorageBootstrapLifecycleAdoptionAuthority, checking: any StorageLifecycleHandoffChecking) throws {
        try worker.requireCurrent(); try authority.configureHandoff(adoption: adoption, checking: checking)
    }
    func guardHandoffPublication(store: String) throws {
        try worker.requireCurrent(); try authority.guardHandoffPublication(store: store)
    }
    func handoffStatus(identity: Lifecycle.Identity, daemon: BootstrapProcess) throws -> StorageLifecycleHandoffRootProtocol.Status {
        try worker.requireCurrent(); return try authority.handoffStatus(identity: identity, daemon: daemon)
    }
    func recoverHandoff(identity: Lifecycle.Identity, operationID: String, daemon: BootstrapProcess) throws -> StorageLifecycleHandoffRootProtocol.Completed {
        try worker.requireCurrent(); return try authority.recoverHandoff(identity: identity, operationID: operationID, daemon: daemon)
    }
    func configureResume(mounted: any StorageLifecycleResumeChecking) throws {
        try worker.requireCurrent(); try authority.configureResume(mounted: mounted)
    }
    func guardColdPublication(store: String) throws {
        try worker.requireCurrent(); try authority.guardColdPublication(store: store)
    }
    func coldOriginPrincipal(binding: StorageIdentity.StoreBinding) throws -> (StorageLifecycleShimOrigin, BootstrapPrincipal, UInt64, StorageLifecycleColdRootProtocol.Completed) {
        try worker.requireCurrent(); return try authority.coldOriginPrincipal(binding: binding)
    }
    @discardableResult
    func authorizeColdEnrollment(seed: StorageLifecycleColdShimProtocol.ColdEnrollmentSeed,
                                 origin: StorageLifecycleShimOrigin, nativePrincipal: BootstrapPrincipal) throws -> StorageIdentity.DescriptorIdentity {
        try worker.requireCurrent()
        return try authority.authorizeColdEnrollment(seed: seed, origin: origin, nativePrincipal: nativePrincipal)
    }
    func completeColdEnrollment(seed: StorageLifecycleColdShimProtocol.ColdEnrollmentSeed,
                                origin: StorageLifecycleShimOrigin, nativePrincipal: BootstrapPrincipal) throws {
        try worker.requireCurrent()
        try authority.completeColdEnrollment(seed: seed, origin: origin, nativePrincipal: nativePrincipal)
    }
    func dispatchCold(_ request: StorageLifecycleColdRootProtocol.Request, daemon: BootstrapProcess,
                      cold: StorageBootstrapLifecycleColdXPC) throws -> StorageLifecycleColdRootProtocol.ResultBody {
        try worker.requireCurrent()
        // Reconcile only at transition boundaries. Failed/poisoned authority
        // snapshots retain every lease, including a proof stranded before L1.
        try? cold.reconcileClaims { try authority.retainedColdClaimOperationIDs() }
        defer { try? cold.reconcileClaims { try authority.retainedColdClaimOperationIDs() } }
        switch request.body {
        case .status(let identity): return try .status(authority.statusCold(identity: identity))
        case .prepare(let prepare): return try .prepared(authority.prepareCold(prepare, daemon: daemon))
        case .resolveDead(let value):
            return try .resolvedDead(authority.resolveDeadCold(value, check: cold.checkRecoveryRequest))
        case .complete(let id, let digest):
            let completed = try authority.completeCold(operationID: id, signedOpenSHA256: digest, daemon: daemon)
            try cold.enroll(completed)
            return .completed(completed)
        }
    }
    func resumeOriginPrincipal(binding: StorageIdentity.StoreBinding) throws -> (StorageLifecycleShimOrigin, BootstrapPrincipal, UInt64, StorageLifecycleResumeRootProtocol.Completed) {
        try worker.requireCurrent(); return try authority.resumeOriginPrincipal(binding: binding)
    }
    @discardableResult
    func authorizeResumeEnrollment(seed: StorageLifecycleColdShimProtocol.ColdEnrollmentSeed,
                                   origin: StorageLifecycleShimOrigin, nativePrincipal: BootstrapPrincipal) throws -> StorageIdentity.DescriptorIdentity {
        try worker.requireCurrent()
        return try authority.authorizeResumeEnrollment(seed: seed, origin: origin, nativePrincipal: nativePrincipal)
    }
    func completeResumeEnrollment(seed: StorageLifecycleColdShimProtocol.ColdEnrollmentSeed,
                                  origin: StorageLifecycleShimOrigin, nativePrincipal: BootstrapPrincipal) throws {
        try worker.requireCurrent()
        try authority.completeResumeEnrollment(seed: seed, origin: origin, nativePrincipal: nativePrincipal)
    }
    func dispatchResume(_ request: StorageLifecycleResumeRootProtocol.Request, daemon: BootstrapProcess,
                        resume: StorageBootstrapLifecycleResumeXPC) throws -> StorageLifecycleResumeRootProtocol.ResultBody {
        try worker.requireCurrent()
        switch request.body {
        case .lookup(let binding): return try .status(authority.lookupResume(binding: binding))
        case .status(let identity): return try .status(authority.statusResume(identity: identity))
        case .prepare(let prepare): return try .prepared(authority.prepareResume(prepare, daemon: daemon))
        case .complete(let id, let digest):
            let completed = try authority.completeResume(operationID: id, signedOpenSHA256: digest, daemon: daemon)
            try resume.enroll(completed)
            return .completed(completed)
        }
    }

    /// Unsigned dispatch seam; production always enters through handle's native pin.
    func dispatch(_ request: Wire.Request, daemon: BootstrapProcess, rootFD: Int32 = -1,
                  backingFD: Int32 = -1) throws -> Wire.ResultBody {
        try worker.requireCurrent()
        guard request.requiresDescriptors == (rootFD >= 0 && backingFD >= 0),
              (rootFD >= 0) == (backingFD >= 0) else { throw BootstrapFailure(.invalidRequest) }
        switch request.body {
        case .rootPublicKey:
            guard try journal.lifecycleRootPublicKey() == root else { throw BootstrapFailure(.repairRequired) }
            try remember(daemon) // Enrollment hint only, independently re-pinned by each native transport.
            return .rootPublicKey(root)
        case .provision(let id, let binding, let candidate, _):
            return try .grant(authority.provision(id: id, binding: binding, candidate: candidate, daemon: daemon,
                rootFD: rootFD, backingFD: backingFD))
        case .issue(let operation, let id, let identity, let epoch, let candidate):
            return try .grant(authority.issue(operation: operation, id: id, identity: identity,
                expectedEpoch: epoch, candidate: candidate, daemon: daemon))
        case .read(let identity, let id): return try .grant(authority.read(identity: identity, id: id, daemon: daemon))
        case .complete(let identity, let id): return try .completed(authority.complete(identity: identity, id: id, daemon: daemon))
        case .reclaim(let identity, let id):
            try authority.reclaim(identity: identity, id: id, daemon: daemon); return .reclaimed
        case .status(let identity): return try .status(authority.status(identity: identity))
        case .stageServiceChange(let change): return try .serviceChangeStaged(authority.stageServiceChange(change: change, daemon: daemon))
        case .serviceBootTrust(let identity, let grantID, let changeID):
            return try .serviceBootTrust(authority.serviceBootTrust(identity: identity, grantID: grantID, serviceChangeID: changeID, daemon: daemon), grantID: grantID, serviceChangeID: changeID)
        case .serviceResult(let identity, let grantID): return try .serviceResult(authority.serviceResult(identity: identity, grantID: grantID, daemon: daemon))
        case .completeServiceChange(let identity, let operationID):
            let (confirmation, result) = try authority.completeServiceChange(identity: identity, operationID: operationID, daemon: daemon)
            return .serviceChanged(confirmation, result)
        }
    }

    static func decodeRequest(_ message: xpc_object_t) throws -> Wire.Request {
        guard xpc_get_type(message) == XPC_TYPE_DICTIONARY,
              let op = xpc_dictionary_get_value(message, "operation"), xpc_get_type(op) == XPC_TYPE_STRING,
              let operation = xpc_string_get_string_ptr(op), String(cString: operation) == Wire.xpcOperation else { throw BootstrapFailure(.invalidRequest) }
        var length = 0
        guard let bytes = xpc_dictionary_get_data(message, "request", &length), length > 0,
              length <= Wire.maximumPayloadBytes else { throw BootstrapFailure(.invalidRequest) }
        let request: Wire.Request
        do { request = try Wire.decodeRequest(Data(bytes: bytes, count: length)) }
        catch { throw BootstrapFailure(.invalidRequest) }
        var keys = Set<String>()
        xpc_dictionary_apply(message) { key, _ in keys.insert(String(cString: key)); return true }
        let base: Set<String> = ["operation", "request"]
        guard keys == (request.requiresDescriptors ? base.union(["store-root", "store-backing"]) : base) else {
            throw BootstrapFailure(.invalidRequest)
        }
        if request.requiresDescriptors {
            for key in ["store-root", "store-backing"] {
                guard let fd = xpc_dictionary_get_value(message, key), xpc_get_type(fd) == XPC_TYPE_FD else {
                    throw BootstrapFailure(.invalidRequest)
                }
            }
        }
        return request
    }
    /// Borrowed duplicates are closed on success, partial duplication and failure.
    /// Reparse before any dup so even this seam cannot bypass envelope validation.
    static func withDescriptors<T>(_ message: xpc_object_t, request: Wire.Request,
                                   _ body: (Int32, Int32) throws -> T) throws -> T {
        guard try decodeRequest(message) == request else { throw BootstrapFailure(.invalidRequest) }
        var rootFD: Int32 = -1, backingFD: Int32 = -1
        defer { if rootFD >= 0 { close(rootFD) }; if backingFD >= 0 { close(backingFD) } }
        if request.requiresDescriptors {
            rootFD = xpc_dictionary_dup_fd(message, "store-root")
            guard rootFD >= 0 else { throw BootstrapFailure(.unavailable) }
            backingFD = xpc_dictionary_dup_fd(message, "store-backing")
            guard backingFD >= 0 else { throw BootstrapFailure(.unavailable) }
        }
        return try body(rootFD, backingFD)
    }
}

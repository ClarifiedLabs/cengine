import CEngineHelperSupport
import Foundation
import Security

typealias Lifecycle = StorageLifecycleProtocol

/// Never interprets or compacts a retired v1 authority.
protocol StorageLifecycleJournal: AnyObject {
    func load() throws -> Data?
    func lifecycleRootPublicKey() throws -> StorageIdentity.RootPublicKey
    func checkpoint(_ state: Data) throws
    func signLifecycle(_ grant: StorageLifecycleProtocol.Grant) throws -> StorageLifecycleProtocol.SignedGrant
    func signColdOpen(_ request: StorageLifecycleColdProtocol.Request) throws -> StorageLifecycleColdProtocol.SignedOpen
    func signHandoff(_ request: StorageLifecycleHandoffProtocol.Request) throws -> StorageLifecycleHandoffProtocol.SignedRequest
    func signResumeOpen(_ request: StorageLifecycleResumeProtocol.Request) throws -> StorageLifecycleResumeProtocol.SignedOpen
    func signServiceChange(_ request: StorageLifecycleProtocol.ServiceChangeRequest) throws -> StorageLifecycleProtocol.SignedServiceChange
}

// Existing non-cold test/adapter journals fail closed until explicitly implemented.
extension StorageLifecycleJournal {
    func signHandoff(_ request: StorageLifecycleHandoffProtocol.Request) throws -> StorageLifecycleHandoffProtocol.SignedRequest {
        throw BootstrapFailure(.unavailable)
    }
    func signColdOpen(_ request: StorageLifecycleColdProtocol.Request) throws -> StorageLifecycleColdProtocol.SignedOpen {
        throw BootstrapFailure(.unavailable)
    }
    func signResumeOpen(_ request: StorageLifecycleResumeProtocol.Request) throws -> StorageLifecycleResumeProtocol.SignedOpen {
        throw BootstrapFailure(.unavailable)
    }
}

/// Native implementation must retain the authenticated mount-only channel, pin the
/// full daemon/controller/shim tuples and actual held backing FD, and execute a fresh
/// nonce/counter challenge. It receives NO signatures. Rechecks use the same channel,
/// including after Open; neither a persisted Greeting nor caller DTO is evidence.
protocol StorageLifecycleColdChecking {
    func mounted(request: StorageLifecycleColdRootProtocol.Prepare, unsignedGrant: Lifecycle.Grant,
                 signedOpenDigest: String, baseEpoch: UInt64, daemon: BootstrapProcess) throws -> StorageLifecycleShimOrigin
}

/// Mount-only proof for resuming initialization: the same channel framing as cold recovery
/// but domain-separated by the resumeReadOnly purpose and the fixed genesis base
/// epoch. The retained peer must present a resume-purpose greeting; the ROOT
/// challenge join is validated against the protected resume prepare/prepared.
protocol StorageLifecycleResumeChecking {
    func mounted(request: StorageLifecycleResumeRootProtocol.Prepare, unsignedGrant: Lifecycle.Grant,
                 signedOpenDigest: String, baseEpoch: UInt64, daemon: BootstrapProcess) throws -> StorageLifecycleShimOrigin
}

/// Only a direct, independently pinned nonexporting child can implement these proofs.
/// The root helper uses fresh direct challenges. receipt() must execute the child's
/// typed TLS LifecycleResult challenge, never accept a daemon-supplied Receipt.
protocol StorageLifecycleProcessChecking {
    func candidate(_ candidate: StorageIdentity.Candidate, daemon: BootstrapProcess,
                   grant: StorageLifecycleProtocol.Grant) throws -> BootstrapPrincipal
    func liveness(_ process: BootstrapProcess) -> BootstrapLiveness
    func validateRecipient(_ principal: BootstrapPrincipal, daemon: BootstrapProcess,
                           grant: StorageLifecycleProtocol.Grant) throws
    func serviceBootTrust(_ principal: BootstrapPrincipal, daemon: BootstrapProcess,
                          grant: Lifecycle.Grant) throws -> StorageLifecycleBootTrust
    func serviceResult(_ principal: BootstrapPrincipal, daemon: BootstrapProcess,
                       grant: Lifecycle.Grant, nonce: Data, boot: StorageLifecycleBootTrust,
                       changeRequest: Lifecycle.ServiceChangeRequest?,
                       confirmation: Lifecycle.ServiceChangeConfirmation?) throws -> Lifecycle.ServiceResult
    func receipt(_ principal: BootstrapPrincipal, daemon: BootstrapProcess,
                 grant: StorageLifecycleProtocol.Grant, nonce: Data) throws -> StorageLifecycleProtocol.Receipt
}

/// Internal native-only proof seam. Must pin the registered origin and caller,
/// independently authenticate expectedService.boot (not HOST DTO trust), and
/// authenticate the live Guest result with this fresh ROOT nonce. No adoption,
/// reparenting, new candidate or current controller credentials are required.
protocol StorageLifecycleHandoffChecking {
    func handoff(_ signed: StorageLifecycleHandoffProtocol.SignedRequest,
                 expectedService: Lifecycle.ServiceState, origin: StorageLifecycleShimOrigin,
                 daemon: BootstrapProcess, nonce: Data) throws -> StorageLifecycleHandoffProtocol.Result
}

/// Fresh direct native shim evidence of the actual private service boot's TLS
/// trust. A daemon-supplied Ready/CA/pin or persisted receipt cannot conform.
protocol StorageLifecycleServiceChecking {
    func boot(grant: Lifecycle.Grant, daemon: BootstrapProcess) throws -> StorageLifecycleBootTrust
}

/// Requires independently verified fresh provisioning, not just matching host inodes.
/// Existing v1 binding verification alone is deliberately not conformant. Must
/// return the authenticated format-completion origin formed from the actually
/// pinned shim/daemon, the exact greeting, the grant and the proven candidate
/// principal; ROOT persists it and never infers it from the caller or from the
/// binding/ext4 identity alone.
protocol StorageLifecycleFreshBindingChecking {
    func verifyFresh(_ binding: StorageIdentity.StoreBinding, grant: Lifecycle.Grant, daemon: BootstrapProcess,
                     principal: BootstrapPrincipal, rootFD: Int32, backingFD: Int32) throws -> StorageLifecycleFreshOrigin
}

/// Root-helper authority for initialization, recovery and controller transitions.
/// The XPC adapter serializes operations on the shared lifecycle worker. Completed
/// history is replaced only after direct confirmation; pending states remain even
/// when their recipients die.
final class StorageBootstrapLifecycleAuthority {
    static let maximumStores = 128
    // One resolved dead cold edge can coexist with its fresh successor through
    // L2. The old 48-KiB usable budget did not fit that bounded pair when the
    // predecessor also retained a completed adoption. History remains nonrecursive
    // and is removed at L3; 128 stores still fit the checkpoint's aggregate bound.
    private static let maximumStoreBytes = 96 * 1024
    private static let completionReservation = 16 * 1024
    private struct Intent: Codable, Equatable {
        let grant: Lifecycle.Grant
        let recipient: BootstrapPrincipal
    }
    private struct PendingService: Codable {
        let request: Lifecycle.ServiceChangeRequest
        let recipient: BootstrapPrincipal
        var targetBoot: StorageLifecycleBootTrust?
    }
    /// Immutable heap storage keeps nested DTOs off native/Swift Testing worker stacks.
    private final class ColdTransaction: Codable {
        let request: StorageLifecycleColdRootProtocol.Prepare
        let predecessorService: Lifecycle.ServiceState
        let predecessorReceipt: Lifecycle.Receipt
        let predecessorPrincipal: BootstrapPrincipal
        let oldAdoption: StorageLifecycleColdAdoptionSnapshot
        let newPrincipal: BootstrapPrincipal
        let newOrigin: StorageLifecycleShimOrigin
        let prepared: StorageLifecycleColdRootProtocol.Prepared
        let completion: StorageLifecycleColdRootProtocol.Completed?
        let enrollmentAcknowledged: Bool
        init(request: StorageLifecycleColdRootProtocol.Prepare, predecessorService: Lifecycle.ServiceState,
             predecessorReceipt: Lifecycle.Receipt, predecessorPrincipal: BootstrapPrincipal,
             oldAdoption: StorageLifecycleColdAdoptionSnapshot, newPrincipal: BootstrapPrincipal,
             newOrigin: StorageLifecycleShimOrigin, prepared: StorageLifecycleColdRootProtocol.Prepared,
             completion: StorageLifecycleColdRootProtocol.Completed? = nil, enrollmentAcknowledged: Bool = false) {
            self.request = request; self.predecessorService = predecessorService
            self.predecessorReceipt = predecessorReceipt; self.predecessorPrincipal = predecessorPrincipal
            self.oldAdoption = oldAdoption; self.newPrincipal = newPrincipal; self.newOrigin = newOrigin
            self.prepared = prepared; self.completion = completion
            self.enrollmentAcknowledged = enrollmentAcknowledged
        }
        func completing(_ result: StorageLifecycleColdRootProtocol.Completed, enrolled: Bool = false) -> ColdTransaction {
            .init(request: request, predecessorService: predecessorService, predecessorReceipt: predecessorReceipt,
                predecessorPrincipal: predecessorPrincipal, oldAdoption: oldAdoption, newPrincipal: newPrincipal,
                newOrigin: newOrigin, prepared: prepared, completion: result, enrollmentAcknowledged: enrolled)
        }
    }
    /// Disjoint historical recovery, never a completed/enrolled current owner.
    /// The intent precedes A1; publication retains the exact failed boot forever
    /// fenced except for a new, freshly proved cold successor.
    private final class ResolvedDeadCold: Codable {
        enum Phase: String, Codable { case intent, published }
        let request: StorageLifecycleColdRootProtocol.ResolveDead
        let failed: ColdTransaction
        let phase: Phase
        init(request: StorageLifecycleColdRootProtocol.ResolveDead, failed: ColdTransaction, phase: Phase) {
            self.request = request; self.failed = failed; self.phase = phase
        }
        func publishing() -> ResolvedDeadCold { .init(request: request, failed: failed, phase: .published) }
    }
    /// Durable fresh publication phase. The first initialize commit stores the
    /// exact origin but remains `.unverified`; only the successful exact
    /// post-commit proof commits `.verified` BEFORE any signature release.
    /// Cleared together with the origin by the first completed successor.
    enum FreshPhase: String, Codable {
        case unverified, verified
    }
    private final class HandoffTransaction: Codable {
        let signed: StorageLifecycleHandoffProtocol.SignedRequest
        let predecessor: Intent
        let pending: Intent
        let service: Lifecycle.ServiceState
        let receipt: Lifecycle.Receipt
        let adoption: StorageLifecycleColdAdoptionSnapshot
        let completion: StorageLifecycleHandoffRootProtocol.Completed?
        init(signed: StorageLifecycleHandoffProtocol.SignedRequest, predecessor: Intent, pending: Intent,
             service: Lifecycle.ServiceState, receipt: Lifecycle.Receipt, adoption: StorageLifecycleColdAdoptionSnapshot,
             completion: StorageLifecycleHandoffRootProtocol.Completed? = nil) {
            self.signed = signed; self.predecessor = predecessor; self.pending = pending
            self.service = service; self.receipt = receipt; self.adoption = adoption; self.completion = completion
        }
        func completing(_ value: StorageLifecycleHandoffRootProtocol.Completed) -> HandoffTransaction {
            .init(signed: signed, predecessor: predecessor, pending: pending, service: service, receipt: receipt,
                adoption: adoption, completion: value)
        }
    }
    private struct Store: Codable {
        // Canonical neutral binding DTO only; retired registration envelopes refuse.
        let binding: Data
        let identity: Lifecycle.Identity
        var current: Intent?
        var result: Lifecycle.Receipt?
        var pending: Intent?
        var sealed: Lifecycle.Receipt?
        var currentService: Lifecycle.ServiceState?
        var pendingService: PendingService?
        var latestServiceChange: Lifecycle.ServiceChangeConfirmation?
        var pendingCold: ColdTransaction?
        var latestCold: ColdTransaction?
        // Additive sole-v2 recovery extension. Omission means NO historical
        // resolution; preserve existing canonical bytes without rewriting on load.
        var resolvedDeadCold: ResolvedDeadCold?
        // Initialization-resume transaction, separate from cold recovery. Only an
        // unused protected fresh initialization (pending/current INIT C1, no
        // adopted store) may stage one; the fence clears only after the actual
        // new shim adoption-enrollment acknowledgement is durable.
        var pendingResume: ResumeTransaction?
        var latestResume: ResumeTransaction?
        var pendingHandoff: HandoffTransaction?
        var latestHandoff: HandoffTransaction?
        // Exact authenticated fresh format-completion origin; required nullable
        // field, never inferred from an old v2 snapshot or the binding alone.
        var freshOrigin: StorageLifecycleFreshOrigin?
        // Explicit durable publication phase; never inferred from success or
        // inferred into one by retries, completion or initialization replies.
        var freshPhase: FreshPhase?
        var coldFenced: Bool { resolvedDeadCold != nil || pendingCold != nil || latestCold?.enrollmentAcknowledged == false }
        var resumeFenced: Bool { pendingResume != nil || latestResume?.enrollmentAcknowledged == false }
        var fenced: Bool { coldFenced || resumeFenced || pendingHandoff != nil }
        init(binding: Data, identity: Lifecycle.Identity, pending: Intent,
             freshOrigin: StorageLifecycleFreshOrigin?, freshPhase: FreshPhase?) {
            self.binding = binding; self.identity = identity; self.pending = pending
            self.freshOrigin = freshOrigin; self.freshPhase = freshPhase
        }
        private enum CodingKeys: String, CodingKey {
            case binding, identity, current, result, pending, sealed
            case currentService, pendingService, latestServiceChange, pendingCold, latestCold
            case pendingResume, latestResume, freshOrigin, freshPhase, pendingHandoff, latestHandoff, resolvedDeadCold
        }
        init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            // Required nullable additive slots. Missing fields refuse without
            // rewriting installed state; never infer that an old pending is safe.
            pendingHandoff = try c.decode(HandoffTransaction?.self, forKey: .pendingHandoff)
            latestHandoff = try c.decode(HandoffTransaction?.self, forKey: .latestHandoff)
            binding = try c.decode(Data.self, forKey: .binding)
            identity = try c.decode(Lifecycle.Identity.self, forKey: .identity)
            current = try c.decodeIfPresent(Intent.self, forKey: .current)
            result = try c.decodeIfPresent(Lifecycle.Receipt.self, forKey: .result)
            pending = try c.decodeIfPresent(Intent.self, forKey: .pending)
            sealed = try c.decodeIfPresent(Lifecycle.Receipt.self, forKey: .sealed)
            pendingCold = try c.decode(ColdTransaction?.self, forKey: .pendingCold)
            latestCold = try c.decode(ColdTransaction?.self, forKey: .latestCold)
            resolvedDeadCold = try c.decodeIfPresent(ResolvedDeadCold.self, forKey: .resolvedDeadCold)
            // Required nullable fields: a missing resume slot is never inferred.
            pendingResume = try c.decode(ResumeTransaction?.self, forKey: .pendingResume)
            latestResume = try c.decode(ResumeTransaction?.self, forKey: .latestResume)
            // Required nullable fields: never infer these facts from an old v2 snapshot.
            currentService = try c.decode(Lifecycle.ServiceState?.self, forKey: .currentService)
            pendingService = try c.decode(PendingService?.self, forKey: .pendingService)
            latestServiceChange = try c.decode(Lifecycle.ServiceChangeConfirmation?.self, forKey: .latestServiceChange)
            freshOrigin = try c.decode(StorageLifecycleFreshOrigin?.self, forKey: .freshOrigin)
            freshPhase = try c.decode(FreshPhase?.self, forKey: .freshPhase)
        }
        func encode(to encoder: any Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(binding, forKey: .binding); try c.encode(identity, forKey: .identity)
            try c.encodeIfPresent(current, forKey: .current); try c.encodeIfPresent(result, forKey: .result)
            try c.encodeIfPresent(pending, forKey: .pending); try c.encodeIfPresent(sealed, forKey: .sealed)
            try c.encode(pendingHandoff, forKey: .pendingHandoff)
            try c.encode(latestHandoff, forKey: .latestHandoff)
            try c.encode(pendingCold, forKey: .pendingCold)
            try c.encode(latestCold, forKey: .latestCold)
            try c.encodeIfPresent(resolvedDeadCold, forKey: .resolvedDeadCold)
            try c.encode(pendingResume, forKey: .pendingResume)
            try c.encode(latestResume, forKey: .latestResume)
            try c.encode(currentService, forKey: .currentService)
            try c.encode(pendingService, forKey: .pendingService)
            try c.encode(latestServiceChange, forKey: .latestServiceChange)
            try c.encode(freshOrigin, forKey: .freshOrigin)
            try c.encode(freshPhase, forKey: .freshPhase)
        }
    }
    private struct Reclaimed: Codable {
        let intent: Intent
        let receipt: Lifecycle.Receipt
    }
    private struct State: Codable {
        let version: String
        let serviceFormat: String
        var generation: UInt64 = 0
        var serial: UInt64 = 0
        var stores: [String: Store] = [:]
        // One exact latest reclaim reply, not historical UUID membership.
        var reclaimed: Reclaimed?
    }
    private let journal: any StorageLifecycleJournal
    private let processes: any StorageLifecycleProcessChecking
    private let bindings: any StorageLifecycleFreshBindingChecking
    private let root: StorageIdentity.RootPublicKey
    private var state: State
    private var poisoned = false
    private var coldAdoption: StorageBootstrapLifecycleAdoptionAuthority?
    private var coldMounted: (any StorageLifecycleColdChecking)?
    private var handoffAdoption: StorageBootstrapLifecycleAdoptionAuthority?
    private var handoffChecking: (any StorageLifecycleHandoffChecking)?
    private var resumeMounted: (any StorageLifecycleResumeChecking)?

    /// Install before exposing ANY scope routes, on the same serialized scope worker.
    func configureCold(adoption: StorageBootstrapLifecycleAdoptionAuthority,
                       mounted: any StorageLifecycleColdChecking) throws {
        guard coldAdoption == nil else { throw BootstrapFailure(.conflict) }
        coldAdoption = adoption; coldMounted = mounted
        try healthy()
    }

    /// Fresh-resume uses the same protected adoption scope but never an adopted
    /// store record; install its distinct mount-only proof channel alongside cold.
    func configureResume(mounted: any StorageLifecycleResumeChecking) throws {
        guard coldAdoption != nil, resumeMounted == nil else { throw BootstrapFailure(.conflict) }
        resumeMounted = mounted
        try healthy()
    }

    /// Protected reachability for worker-local cold mount leases, not liveness.
    /// L1/L2 and latest L3 retain their exact peer until durable L4; published
    /// dead resolution needs history only, never the failed mounted channel.
    func retainedColdClaimOperationIDs() throws -> Set<String> {
        try healthy()
        return Set(state.stores.values.compactMap { store in
            if let pending = store.pendingCold { return pending.request.operationID }
            if let latest = store.latestCold, !latest.enrollmentAcknowledged { return latest.request.operationID }
            return nil
        })
    }

    /// Native adoption/enrollment router must call this before ordinary publication.
    func guardColdPublication(store id: String) throws {
        try healthy()
        guard state.stores[id]?.coldFenced != true, state.stores[id]?.resumeFenced != true else { throw BootstrapFailure(.blocked) }
    }

    init(journal: any StorageLifecycleJournal, processes: any StorageLifecycleProcessChecking,
         bindings: any StorageLifecycleFreshBindingChecking) throws {
        self.journal = journal; self.processes = processes; self.bindings = bindings
        do {
            root = try journal.lifecycleRootPublicKey()
            if let bytes = try journal.load() {
                guard bytes.count <= StorageBootstrapCheckpointJournal.maximumPayloadBytes else { throw BootstrapFailure(.repairRequired) }
                state = try JSONDecoder().decode(State.self, from: bytes)
                guard try Self.encodeState(state) == bytes else { throw BootstrapFailure(.repairRequired) }
            } else { state = State(version: Lifecycle.version, serviceFormat: "bounded-service.v2") }
            try validate(state)
        } catch { throw BootstrapFailure(.repairRequired) }
    }

    /// ROOT allocates G and serial before Guest initialization, retaining a provisioning
    /// fence until the direct child confirms the signed initialization result.
    func provision(id: String, binding: StorageIdentity.StoreBinding, candidate: StorageIdentity.Candidate,
                   daemon: BootstrapProcess, rootFD: Int32 = -1, backingFD: Int32 = -1) throws -> Lifecycle.SignedGrant {
        try healthy()
        let storeID = binding.storeID.rawValue
        if let store = state.stores[storeID] {
            guard !store.fenced else { throw BootstrapFailure(.blocked) }
            guard rootFD < 0, backingFD < 0, try decodedBinding(store) == binding,
                  let intent = store.pending ?? store.current, intent.grant.operation == .initialize,
                  intent.grant.id == id, intent.grant.newKey == candidate.publicKey.fingerprint.rawValue,
                  store.sealed == nil, store.pendingService == nil else { throw BootstrapFailure(.conflict) }
            // The durable origin is NOT publication evidence: only the explicit
            // verified phase releases a same-recipient retry. The pending fence
            // is never cleared, dropped or reinterpreted as success.
            guard store.freshPhase == .verified else { throw BootstrapFailure(.blocked) }
            let proven = try processes.candidate(candidate, daemon: daemon, grant: intent.grant)
            guard proven == intent.recipient else { throw BootstrapFailure(.unauthorized) }
            return try release(intent, daemon: daemon)
        }
        guard state.stores.count < Self.maximumStores else { throw BootstrapFailure(.capacityExceeded) }
        guard rootFD >= 0, backingFD >= 0 else { throw BootstrapFailure(.invalidRequest) }
        let generation = try increment(state.generation), serial = try increment(state.serial)
        let identity = try Lifecycle.Identity(binding: binding, generation: generation)
        let grant = try Lifecycle.Grant(operation: .initialize, id: id, identity: identity,
            serial: serial, expectedEpoch: 0, newKey: candidate.publicKey.fingerprint.rawValue)
        try excludeLiveKey(grant.newKey)
        for old in state.stores.values {
            let bound = try decodedBinding(old)
            guard bound.root != binding.root, bound.backing.identity != binding.backing.identity else {
                throw BootstrapFailure(.conflict)
            }
        }
        let principal = try processes.candidate(candidate, daemon: daemon, grant: grant)
        try validatePrincipal(principal, key: grant.newKey)
        let origin = try bindings.verifyFresh(binding, grant: grant, daemon: daemon,
            principal: principal, rootFD: rootFD, backingFD: backingFD)
        try origin.validate(binding: binding, root: root.publicData)
        let intent = Intent(grant: grant, recipient: principal)
        var next = state
        next.generation = generation; next.serial = serial
        next.stores[storeID] = Store(binding: try Self.encodeBinding(binding), identity: identity,
            pending: intent, freshOrigin: origin, freshPhase: .unverified)
        try commit(next)
        // A lost shim or changed disk/greeting during publication retains the
        // provisioning fence, but no new signature escapes this failed attempt:
        // the republished origin must be exactly identical to the durable one.
        let republished = try bindings.verifyFresh(binding, grant: grant, daemon: daemon,
            principal: principal, rootFD: rootFD, backingFD: backingFD)
        guard republished == origin else { throw BootstrapFailure(.conflict) }
        // Exact post-commit proof: durably commit the verified publication phase
        // BEFORE any signature release. A lost verified commit leaves the store
        // durably unverified; retries and completion stay blocked.
        guard var confirmedStore = state.stores[storeID] else { throw BootstrapFailure(.repairRequired) }
        confirmedStore.freshPhase = .verified
        var confirmed = state; confirmed.stores[storeID] = confirmedStore
        try commit(confirmed)
        return try release(intent, daemon: daemon)
    }

    func issue(operation: Lifecycle.Operation, id: String, identity: Lifecycle.Identity,
               expectedEpoch: UInt64, candidate: StorageIdentity.Candidate, daemon: BootstrapProcess) throws -> Lifecycle.SignedGrant {
        try healthy()
        guard operation != .initialize else { throw BootstrapFailure(.invalidRequest) }
        guard var store = state.stores[identity.store], store.identity == identity else { throw BootstrapFailure(.unknownStore) }
        guard !store.fenced else { throw BootstrapFailure(.blocked) }
        guard store.pendingService == nil else { throw BootstrapFailure(.blocked) }
        if let old = [store.pending, store.current].compactMap({ $0 }).first(where: { $0.grant.id == id }) {
            guard (store.pending?.grant.operation != .retire || store.pending == old),
                  old.grant.operation == operation, old.grant.expectedEpoch == expectedEpoch,
                  old.grant.newKey == candidate.publicKey.fingerprint.rawValue else { throw BootstrapFailure(.conflict) }
            let proven = try processes.candidate(candidate, daemon: daemon, grant: old.grant)
            guard old.recipient == proven else { throw BootstrapFailure(.unauthorized) }
            return try release(old, daemon: daemon)
        }
        guard !store.fenced, store.pending == nil, store.sealed == nil, let current = store.current,
              try controller(current.grant).epoch.rawValue == expectedEpoch else { throw BootstrapFailure(.blocked) }
        let grant = try Lifecycle.Grant(operation: operation, id: id, identity: identity, serial: increment(state.serial),
            expectedEpoch: expectedEpoch, newKey: candidate.publicKey.fingerprint.rawValue)
        let principal = try processes.candidate(candidate, daemon: daemon, grant: grant)
        try validatePrincipal(principal, key: grant.newKey)
        if operation == .takeover {
            try excludeLiveKey(grant.newKey)
            guard principal.incarnation != current.recipient.incarnation,
                  processes.liveness(current.recipient.daemon) == .exited,
                  processes.liveness(current.recipient.child) == .exited else { throw BootstrapFailure(.blocked) }
        } else {
            guard principal == current.recipient, grant.newKey == current.grant.newKey else { throw BootstrapFailure(.unauthorized) }
        }
        let intent = Intent(grant: grant, recipient: principal)
        store.pending = intent
        // A new intent supersedes the previous recovery reply in the same checkpoint.
        // Never project an old completion alongside a newer interrupted takeover.
        store.latestHandoff = nil
        var next = state; next.serial = grant.serial; next.stores[identity.store] = store
        try commit(next)
        return try release(intent, daemon: daemon)
    }

    /// Exact current/pending retries only. Never signs an old epoch from history.
    func read(identity: Lifecycle.Identity, id: String, daemon: BootstrapProcess) throws -> Lifecycle.SignedGrant {
        try healthy()
        let intent = try find(identity: identity, id: id)
        return try release(intent, daemon: daemon)
    }

    /// Receipt nonce is created here, never supplied by the requesting daemon. Both the
    /// initial and duplicate result require fresh direct proof; metadata is not proof.
    /// After a service reopen use serviceResult/completeServiceChange: this stable
    /// applied-result path deliberately never relaxes its original boot-E requirement.
    func complete(identity: Lifecycle.Identity, id: String, daemon: BootstrapProcess) throws -> Lifecycle.Receipt {
        try healthy()
        let intent = try find(identity: identity, id: id)
        let receipt = try prove(intent, daemon: daemon)
        guard var store = state.stores[identity.store] else { throw BootstrapFailure(.unknownStore) }
        guard !store.fenced else { throw BootstrapFailure(.blocked) }
        // Initialization completion never bypasses the durable fresh publication
        // phase; only the verified phase may promote the pending initialize.
        if intent.grant.operation == .initialize {
            guard store.freshPhase == .verified else { throw BootstrapFailure(.blocked) }
        }
        if let previous = intent.grant.operation == .retire ? store.sealed : store.result,
           previous.grant == intent.grant {
            guard sameResult(receipt, previous) else { throw BootstrapFailure(.conflict) }
        } else if store.pending == intent {
            if intent.grant.operation == .retire {
                store.sealed = receipt
                // Keep the current controller AND pending retirement until explicit
                // reclamation. No new grant may supersede this terminal fence.
            } else {
                let boot = try observedBoot(intent, daemon: daemon)
                let live = try proveService(intent, daemon: daemon, boot: boot)
                guard live.serviceEpoch == receipt.serviceEpoch, live.openRevision <= receipt.revision else {
                    throw BootstrapFailure(.conflict)
                }
                store.current = intent; store.result = receipt; store.pending = nil; store.latestCold = nil
                store.latestHandoff = nil
                if intent.grant.operation == .takeover {
                    // First completed successor: the fresh initialization anchor
                    // is historical and must never anchor a future resume.
                    store.freshOrigin = nil; store.freshPhase = nil
                }
                store.currentService = try live.state(boot: boot); store.latestServiceChange = nil
            }
            var next = state; next.stores[identity.store] = store
            try commit(next)
        }
        // Loss during persistence must not release a result. The already confirmed
        // durable state remains; a failed reply is never evidence of rollback.
        let repeated = try prove(intent, daemon: daemon)
        guard sameResult(repeated, receipt) else { throw BootstrapFailure(.conflict) }
        if intent.grant.operation != .retire {
            guard let confirmed = state.stores[identity.store]?.currentService else { throw BootstrapFailure(.repairRequired) }
            _ = try confirmedService(intent, daemon: daemon, expected: confirmed)
        }
        return repeated
    }

    /// Separate from sealing, disk deletion and VM exit. Only an already persisted
    /// terminal seal can release ROOT's alias/count reservation. A lost child reply
    /// leaves the sealed entry untouched. No timeout or dead-recipient cleanup exists.
    func reclaim(identity: Lifecycle.Identity, id: String, daemon: BootstrapProcess) throws {
        try healthy()
        if let old = state.reclaimed, old.intent.grant.identity == identity, old.intent.grant.id == id {
            let receipt = try prove(old.intent, daemon: daemon)
            guard sameResult(receipt, old.receipt) else { throw BootstrapFailure(.conflict) }
            return
        }
        guard let store = state.stores[identity.store], store.identity == identity,
              let intent = store.pending, intent.grant.id == id, intent.grant.operation == .retire,
              let seal = store.sealed, !store.fenced, store.pendingService == nil else { throw BootstrapFailure(.blocked) }
        let receipt = try prove(intent, daemon: daemon)
        guard receipt.serviceEpoch == seal.serviceEpoch, receipt.revision == seal.revision else { throw BootstrapFailure(.conflict) }
        var next = state
        next.reclaimed = Reclaimed(intent: intent, receipt: receipt)
        next.stores.removeValue(forKey: identity.store)
        try commit(next)
    }

    /// Internal native enrollment only; no RPC exports the retained principal.
    /// Initialization must already be durably completed, with no pending transition.
    func currentOriginPrincipal(binding: StorageIdentity.StoreBinding) throws -> (Lifecycle.Grant, BootstrapPrincipal, StorageLifecycleBootTrust) {
        try healthy()
        guard let store = state.stores[binding.storeID.rawValue], try decodedBinding(store) == binding,
              !store.fenced, store.pending == nil, store.pendingService == nil, store.sealed == nil,
              let current = store.current, current.grant.operation == .initialize,
              store.result?.grant == current.grant, let service = store.currentService else {
            throw BootstrapFailure(.blocked)
        }
        try processes.validateRecipient(current.recipient, daemon: current.recipient.daemon, grant: current.grant)
        return (current.grant, current.recipient, service.boot)
    }

    /// Native enrollment must retain the live device from the authenticated format
    /// transaction, not reconstruct it from the reboot-stable binding or caller.
    func freshEnrollmentBacking(origin: StorageLifecycleShimOrigin) throws -> StorageIdentity.DescriptorIdentity {
        let binding = try origin.wire.binding.value()
        let (grant, principal, _) = try currentOriginPrincipal(binding: binding)
        guard let fresh = state.stores[binding.storeID.rawValue]?.freshOrigin,
              fresh.grant == grant, fresh.principal == principal,
              fresh.shim == origin.shim, fresh.daemon == origin.originalDaemon,
              principal.child == origin.originalController,
              fresh.greeting.shimLaunchUUID == origin.wire.shimLaunchUUID,
              fresh.greeting.rootPublicKey == origin.wire.rootPublicKey else { throw BootstrapFailure(.unauthorized) }
        return try .init(volumeUUID: .init(fresh.greeting.volumeUUID),
            device: fresh.greeting.device, inode: fresh.greeting.inode)
    }

    func status(identity: Lifecycle.Identity) throws -> StorageIdentity.Controller {
        try healthy()
        guard let store = state.stores[identity.store], store.identity == identity else { throw BootstrapFailure(.unknownStore) }
        guard !store.fenced else { throw BootstrapFailure(.blocked) }
        guard !store.fenced, store.pending == nil, store.pendingService == nil, store.sealed == nil, let current = store.current else { throw BootstrapFailure(.blocked) }
        return try controller(current.grant)
    }

    /// Returns the request signed by the ROOT bootstrap key only after it is durably
    /// staged (or exactly retried), so a daemon cannot fabricate a Guest reopen.
    func stageServiceChange(change: Lifecycle.ServiceChangeRequest, daemon: BootstrapProcess) throws -> Lifecycle.SignedServiceChange {
        try healthy(); try change.validate()
        guard try journal.lifecycleRootPublicKey().fingerprint.rawValue == change.predecessor.boot.bootstrapKey else { throw BootstrapFailure(.conflict) }
        let identity = change.predecessor.grant.identity
        guard var store = state.stores[identity.store], store.identity == identity else { throw BootstrapFailure(.unknownStore) }
        guard !store.fenced else { throw BootstrapFailure(.blocked) }
        guard !store.fenced, store.pending == nil, store.sealed == nil, let current = store.current else { throw BootstrapFailure(.blocked) }
        try processes.validateRecipient(current.recipient, daemon: daemon, grant: current.grant)
        if let pending = store.pendingService {
            guard pending.request == change, pending.recipient == current.recipient else { throw BootstrapFailure(.conflict) }
            return try signedServiceChange(change)
        }
        if let latest = store.latestServiceChange, latest.request.operationID == change.operationID {
            guard latest.request == change, latest.successor == store.currentService else { throw BootstrapFailure(.conflict) }
            return try signedServiceChange(change)
        }
        guard store.currentService == change.predecessor else { throw BootstrapFailure(.conflict) }
        store.pendingService = PendingService(request: change, recipient: current.recipient)
        var next = state; next.stores[identity.store] = store
        try commit(next)
        try processes.validateRecipient(current.recipient, daemon: daemon, grant: current.grant)
        return try signedServiceChange(change)
    }

    private func signedServiceChange(_ change: Lifecycle.ServiceChangeRequest) throws -> Lifecycle.SignedServiceChange {
        let signed = try journal.signServiceChange(change)
        guard signed.request == change, signed.isValidSignature(using: try journal.lifecycleRootPublicKey()) else { throw BootstrapFailure(.repairRequired) }
        return signed
    }

    func serviceBootTrust(identity: Lifecycle.Identity, grantID: String, serviceChangeID: String?,
                          daemon: BootstrapProcess) throws -> StorageLifecycleBootTrust {
        try healthy()
        guard var store = state.stores[identity.store], store.identity == identity else { throw BootstrapFailure(.unknownStore) }
        guard !store.fenced else { throw BootstrapFailure(.blocked) }
        if var pending = store.pendingService {
            guard pending.request.operationID == serviceChangeID, let current = store.current,
                  current.grant.id == grantID, current.recipient == pending.recipient else { throw BootstrapFailure(.blocked) }
            let boot = try observedBoot(current, daemon: daemon)
            try pending.request.validateSuccessorBoot(boot)
            if let target = pending.targetBoot {
                guard target == boot else { throw BootstrapFailure(.conflict) }
            } else {
                pending.targetBoot = boot; store.pendingService = pending
                var next = state; next.stores[identity.store] = store; try commit(next)
            }
            guard try observedBoot(current, daemon: daemon) == boot else { throw BootstrapFailure(.conflict) }
            return boot
        }
        let intent = try find(identity: identity, id: grantID)
        guard intent.grant.operation != .retire, store.sealed == nil,
              store.pending == nil || store.pending == intent else { throw BootstrapFailure(.blocked) }
        if let serviceChangeID {
            guard store.pending == nil, store.latestServiceChange?.request.operationID == serviceChangeID else { throw BootstrapFailure(.conflict) }
        }
        let boot = try observedBoot(intent, daemon: daemon)
        if store.pending == nil {
            guard store.currentService?.boot == boot else { throw BootstrapFailure(.conflict) }
        }
        return boot
    }

    /// Read-only, non-persisting authorization for the SAME enrolled service-proof
    /// channel to re-greet with a successor boot. Requires the exact durably staged
    /// change whose predecessor boot is the channel's current boot; a frozen target
    /// must match exactly. Never resets counters, nonces or any other high-water mark.
    func authorizeServiceBootUpdate(predecessor: StorageLifecycleBootTrust,
                                    successor: StorageLifecycleBootTrust) throws {
        try healthy()
        let identity = predecessor.identity
        guard let store = state.stores[identity.store], store.identity == identity,
              !store.fenced, store.pending == nil, store.sealed == nil, let current = store.current,
              let pending = store.pendingService, pending.recipient == current.recipient,
              pending.request.predecessor == store.currentService,
              pending.request.predecessor.boot == predecessor,
              successor.bootstrapKey == root.fingerprint.rawValue else { throw BootstrapFailure(.blocked) }
        try pending.request.validateSuccessorBoot(successor)
        if let target = pending.targetBoot, target != successor { throw BootstrapFailure(.conflict) }
    }

    /// Protected service projection for a separately authenticated adopted owner.
    /// Does not call the departed controller or treat its old receipt as fresh proof.
    /// A pending takeover projects ONLY a rejection expectation: the same shim must
    /// independently Query the new C/key, and the child must still prove its receipt.
    func adoptedService(identity: Lifecycle.Identity, proving grant: Lifecycle.Grant? = nil) throws -> Lifecycle.ServiceState {
        try healthy()
        guard let store = state.stores[identity.store], store.identity == identity,
              !store.fenced, store.pendingService == nil, store.sealed == nil,
              let current = store.current, let service = store.currentService,
              current.grant == service.grant else { throw BootstrapFailure(.blocked) }
        if let pending = store.pending {
            guard let grant, pending.grant == grant, grant.operation == .takeover,
                  grant.expectedEpoch == service.context.controllerEpoch,
                  grant.newKey != service.context.controllerKey else { throw BootstrapFailure(.blocked) }
            try validatePrincipal(pending.recipient, key: grant.newKey)
            return try .init(grant: grant,
                context: .init(serviceEpoch: service.context.serviceEpoch,
                    controllerEpoch: increment(grant.expectedEpoch), controllerKey: grant.newKey),
                openRevision: service.openRevision, boot: service.boot)
        }
        guard grant == nil || grant == current.grant else { throw BootstrapFailure(.blocked) }
        return service
    }

    func serviceResult(identity: Lifecycle.Identity, grantID: String, daemon: BootstrapProcess) throws -> Lifecycle.ServiceResult {
        try healthy()
        guard let store = state.stores[identity.store], store.identity == identity else { throw BootstrapFailure(.unknownStore) }
        guard !store.fenced else { throw BootstrapFailure(.blocked) }
        guard !store.fenced, store.pending == nil, store.pendingService == nil, store.sealed == nil,
              let current = store.current, current.grant.id == grantID, let service = store.currentService else {
            throw BootstrapFailure(.blocked)
        }
        return try confirmedService(current, daemon: daemon, expected: service)
    }

    func completeServiceChange(identity: Lifecycle.Identity, operationID: String,
                               daemon: BootstrapProcess) throws -> (Lifecycle.ServiceChangeConfirmation, Lifecycle.ServiceResult) {
        try healthy()
        guard var store = state.stores[identity.store], store.identity == identity else { throw BootstrapFailure(.unknownStore) }
        guard !store.fenced else { throw BootstrapFailure(.blocked) }
        guard !store.fenced, store.pending == nil, store.sealed == nil, let current = store.current else { throw BootstrapFailure(.blocked) }
        let confirmation: Lifecycle.ServiceChangeConfirmation
        if let pending = store.pendingService {
            guard pending.request.operationID == operationID, pending.recipient == current.recipient,
                  let boot = pending.targetBoot else { throw BootstrapFailure(.blocked) }
            let result = try proveService(current, daemon: daemon, boot: boot, changeRequest: pending.request)
            confirmation = try .init(request: pending.request, successor: result.state(boot: boot))
            guard let applied = store.result, result.openRevision > applied.revision else { throw BootstrapFailure(.conflict) }
            store.currentService = confirmation.successor; store.latestCold = nil; store.pendingService = nil; store.latestServiceChange = confirmation
            var next = state; next.stores[identity.store] = store; try commit(next)
        } else {
            guard let latest = store.latestServiceChange, latest.request.operationID == operationID,
                  latest.successor == store.currentService else { throw BootstrapFailure(.conflict) }
            confirmation = latest
        }
        // Only ROOT's post-publication challenge may promote the child's staged TLS client.
        let result = try proveService(current, daemon: daemon, boot: confirmation.successor.boot, confirmation: confirmation)
        guard try result.state(boot: confirmation.successor.boot) == confirmation.successor else { throw BootstrapFailure(.conflict) }
        return (confirmation, result)
    }

    /// Recovery through the exact committed native adoption, never the departed
    /// grant recipient. ROOT alone freezes the target and publishes completion.
    func completeAdoptedServiceChange(adoption: Adoption.Request, change: Lifecycle.ServiceChangeRequest,
        peer: BootstrapAuditIdentity, adoptionAuthority: StorageBootstrapLifecycleAdoptionAuthority,
        check: () throws -> Void,
        prove: (Lifecycle.ServiceChangeRequest, StorageLifecycleBootTrust?, Lifecycle.ServiceChangeConfirmation?, Data,
                StorageLifecycleShimOrigin) throws -> Adoption.ServiceChangeReply
    ) throws -> (Lifecycle.ServiceChangeConfirmation, Lifecycle.ServiceResult) {
        try check(); try healthy(); try change.validate()
        let identity = change.predecessor.grant.identity
        let (origin, principal) = try adoptionAuthority.committed(adoption, peer: peer)
        guard origin.wire == adoption.origin, origin.wire.rootPublicKey == root.publicData,
              try identity == Lifecycle.Identity(binding: origin.wire.binding.value(), generation: identity.generation),
              let initial = state.stores[identity.store], initial.identity == identity,
              let current = initial.current, let applied = initial.result,
              current.grant == change.predecessor.grant, applied.grant == current.grant else {
            throw BootstrapFailure(.unauthorized)
        }
        // Re-resolve protected state and native admission at every I/O boundary.
        // The retained grant owner may differ from the original shim owner.
        func recheck() throws {
            try check(); try healthy()
            let (again, candidate) = try adoptionAuthority.committed(adoption, peer: peer)
            guard again == origin, candidate == principal,
                  let store = state.stores[identity.store], store.identity == identity,
                  store.current == current, store.result == applied,
                  !store.fenced, store.pending == nil, store.sealed == nil,
                  store.pendingCold == nil, store.pendingResume == nil else { throw BootstrapFailure(.blocked) }
            for process in [origin.originalDaemon, origin.originalController, current.recipient.daemon, current.recipient.child] {
                guard processes.liveness(process) == .exited else { throw BootstrapFailure(.blocked) }
            }
            if let pending = store.pendingService {
                guard pending.request == change, pending.recipient == current.recipient,
                      store.currentService == change.predecessor else { throw BootstrapFailure(.conflict) }
            } else {
                guard let latest = store.latestServiceChange, latest.request == change,
                      latest.successor == store.currentService else { throw BootstrapFailure(.conflict) }
            }
            try check()
        }
        func proof(target: StorageLifecycleBootTrust?, completed: Lifecycle.ServiceChangeConfirmation?) throws -> Adoption.ServiceChangeReply {
            try recheck()
            let nonce = try randomNonce()
            let outcome = Result { try prove(change, target, completed, nonce, origin) }
            try recheck()
            let reply = try outcome.get()
            try reply.result.validate(); try reply.boot.validate()
            guard reply.result.nonce == nonce, reply.result.grant == current.grant,
                  reply.boot.bootstrapKey == root.fingerprint.rawValue,
                  target == nil || target == reply.boot,
                  reply.result.openRevision > applied.revision else { throw BootstrapFailure(.conflict) }
            let confirmation = try Lifecycle.ServiceChangeConfirmation(request: change, successor: reply.result.state(boot: reply.boot))
            guard completed == nil || completed == confirmation else { throw BootstrapFailure(.conflict) }
            return reply
        }
        try recheck()
        var store = state.stores[identity.store]!
        let confirmation: Lifecycle.ServiceChangeConfirmation
        if var pending = store.pendingService {
            if pending.targetBoot == nil {
                let actual = try proof(target: nil, completed: nil)
                pending.targetBoot = actual.boot; store.pendingService = pending
                var next = state; next.stores[identity.store] = store
                try commit(next, check: recheck)
            }
            let actual = try proof(target: pending.targetBoot, completed: nil)
            confirmation = try .init(request: change, successor: actual.result.state(boot: actual.boot))
            store.currentService = confirmation.successor; store.latestServiceChange = confirmation
            store.pendingService = nil; store.latestCold = nil
            var next = state; next.stores[identity.store] = store
            try commit(next, check: recheck)
        } else {
            confirmation = store.latestServiceChange!
        }
        let actual = try proof(target: confirmation.successor.boot, completed: confirmation)
        return (confirmation, actual.result)
    }

    private func observedBoot(_ intent: Intent, daemon: BootstrapProcess) throws -> StorageLifecycleBootTrust {
        try processes.validateRecipient(intent.recipient, daemon: daemon, grant: intent.grant)
        let boot = try processes.serviceBootTrust(intent.recipient, daemon: daemon, grant: intent.grant)
        try boot.validate()
        guard boot.identity == intent.grant.identity, boot.bootstrapKey == root.fingerprint.rawValue else { throw BootstrapFailure(.unauthorized) }
        return boot
    }
    private func proveService(_ intent: Intent, daemon: BootstrapProcess, boot: StorageLifecycleBootTrust,
                              changeRequest: Lifecycle.ServiceChangeRequest? = nil,
                              confirmation: Lifecycle.ServiceChangeConfirmation? = nil) throws -> Lifecycle.ServiceResult {
        guard try observedBoot(intent, daemon: daemon) == boot else { throw BootstrapFailure(.conflict) }
        let nonce = try randomNonce()
        let result = try processes.serviceResult(intent.recipient, daemon: daemon, grant: intent.grant,
            nonce: nonce, boot: boot, changeRequest: changeRequest, confirmation: confirmation)
        try result.validate()
        guard result.grant == intent.grant, result.nonce == nonce, result.serviceEpoch == boot.serviceEpoch else { throw BootstrapFailure(.unauthorized) }
        _ = try result.state(boot: boot)
        return result
    }
    private func confirmedService(_ intent: Intent, daemon: BootstrapProcess,
                                  expected: Lifecycle.ServiceState) throws -> Lifecycle.ServiceResult {
        let result = try proveService(intent, daemon: daemon, boot: expected.boot)
        guard try result.state(boot: expected.boot) == expected else { throw BootstrapFailure(.conflict) }
        return result
    }
    private func randomNonce() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { throw BootstrapFailure(.unavailable) }
        return Data(bytes)
    }

    private func find(identity: Lifecycle.Identity, id: String) throws -> Intent {
        guard let store = state.stores[identity.store], store.identity == identity else { throw BootstrapFailure(.unknownStore) }
        guard !store.fenced else { throw BootstrapFailure(.blocked) }
        guard store.pendingService == nil else { throw BootstrapFailure(.blocked) }
        guard let intent = [store.pending, store.current].compactMap({ $0 }).first(where: { $0.grant.id == id }) else {
            throw BootstrapFailure(.unknownGrant)
        }
        // Read/signature and service-proof routes share the same publication gate
        // as provision retries. A failed post-commit fresh proof cannot be bypassed
        // by reading the durable pending initialize grant through another route.
        guard intent.grant.operation != .initialize || store.freshPhase == .verified else { throw BootstrapFailure(.blocked) }
        // A retirement is terminal, not permission to re-release the preceding owner.
        guard store.pending?.grant.operation != .retire || store.pending == intent else { throw BootstrapFailure(.blocked) }
        return intent
    }
    private func release(_ intent: Intent, daemon: BootstrapProcess) throws -> Lifecycle.SignedGrant {
        try processes.validateRecipient(intent.recipient, daemon: daemon, grant: intent.grant)
        do { return try journal.signLifecycle(intent.grant) }
        catch { poisoned = true; throw BootstrapFailure(.repairRequired) }
    }
    private func prove(_ intent: Intent, daemon: BootstrapProcess) throws -> Lifecycle.Receipt {
        try processes.validateRecipient(intent.recipient, daemon: daemon, grant: intent.grant)
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { throw BootstrapFailure(.unavailable) }
        let nonce = Data(bytes)
        let receipt = try processes.receipt(intent.recipient, daemon: daemon, grant: intent.grant, nonce: nonce)
        guard receipt.grant == intent.grant, receipt.nonce == nonce else { throw BootstrapFailure(.unauthorized) }
        // Re-parse at the trust seam: conformers cannot smuggle unchecked Codable data.
        _ = try Lifecycle.decode(Lifecycle.Receipt.self, from: Lifecycle.encode(receipt))
        return receipt
    }
    private func sameResult(_ lhs: Lifecycle.Receipt, _ rhs: Lifecycle.Receipt) -> Bool {
        lhs.grant == rhs.grant && lhs.serviceEpoch == rhs.serviceEpoch && lhs.revision == rhs.revision
    }
    private func healthy() throws {
        guard !poisoned else { throw BootstrapFailure(.repairRequired) }
        do {
            guard try journal.lifecycleRootPublicKey() == root else { throw BootstrapFailure(.repairRequired) }
            if let adoption = coldAdoption {
                for store in state.stores.values {
                    if let cold = store.pendingCold {
                        let rotated = try coldRotated(cold, adoption: adoption)
                        if rotated {
                            guard cold.completion != nil else { throw BootstrapFailure(.repairRequired) }
                        } else {
                            guard try adoption.coldSnapshot(store: store.identity.store) == cold.oldAdoption else {
                                throw BootstrapFailure(.repairRequired)
                            }
                        }
                    } else if let resolved = store.resolvedDeadCold {
                        guard resolved.phase == .published,
                              try coldRotated(resolved.failed, adoption: adoption) else {
                            throw BootstrapFailure(.repairRequired)
                        }
                    } else if let cold = store.latestCold {
                        if !cold.enrollmentAcknowledged {
                            guard try coldRotated(cold, adoption: adoption) else { throw BootstrapFailure(.repairRequired) }
                        }
                        guard try adoption.registeredOrigin(store: store.identity.store) == cold.newOrigin else {
                            throw BootstrapFailure(.repairRequired)
                        }
                    }
                    // Fresh-resume never adopts an existing store: while a resume is
                    // pending no adoption record may exist; after completion the
                    // initial enrollment machinery records the exact new origin and
                    // only the durable enrollment ACK clears the fence.
                    if store.pendingResume != nil {
                        guard try adoption.registeredOrigin(store: store.identity.store) == nil else {
                            throw BootstrapFailure(.repairRequired)
                        }
                    } else if let resume = store.latestResume {
                        let registered = try adoption.registeredOrigin(store: store.identity.store)
                        if resume.enrollmentAcknowledged {
                            guard registered == resume.newOrigin else { throw BootstrapFailure(.repairRequired) }
                        } else {
                            guard registered == nil || registered == resume.newOrigin else {
                                throw BootstrapFailure(.repairRequired)
                            }
                        }
                    }
                }
            }
        } catch { poisoned = true; throw BootstrapFailure(.repairRequired) }
    }
    private func increment(_ value: UInt64) throws -> UInt64 {
        guard value < UInt64.max else { throw BootstrapFailure(.epochExhausted) }
        return value + 1
    }
    private func controller(_ grant: Lifecycle.Grant) throws -> StorageIdentity.Controller {
        guard grant.operation != .retire else { throw BootstrapFailure(.repairRequired) }
        return try .init(epoch: .init(increment(grant.expectedEpoch)), key: .init(grant.newKey))
    }
    private func excludeLiveKey(_ key: String) throws {
        guard key != root.fingerprint.rawValue,
              !state.stores.values.contains(where: { store in
                  [store.current, store.pending].compactMap({ $0 }).contains { $0.grant.newKey == key }
                      || store.pendingCold?.prepared.signedOpen.request.takeover.grant.newKey == key
                      || store.resolvedDeadCold?.failed.prepared.signedOpen.request.takeover.grant.newKey == key
                      || store.pendingResume?.prepared.signedOpen.request.takeover.grant.newKey == key
              }) else { throw BootstrapFailure(.conflict) }
    }
    private static func encodeBinding(_ binding: StorageIdentity.StoreBinding) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(StorageLifecycleStoreBinding(binding))
    }
    private func decodedBinding(_ store: Store) throws -> StorageIdentity.StoreBinding {
        let binding = try JSONDecoder().decode(StorageLifecycleStoreBinding.self, from: store.binding).value()
        guard try Self.encodeBinding(binding) == store.binding else { throw BootstrapFailure(.repairRequired) }
        return binding
    }
    private func validatePrincipal(_ principal: BootstrapPrincipal, key: String) throws {
        _ = try StorageIdentity.IncarnationID(principal.incarnation)
        guard try StorageIdentity.Ed25519SPKI(publicData: principal.controllerSPKI).fingerprint.rawValue == key else { throw BootstrapFailure(.repairRequired) }
        for p in [principal.daemon, principal.child] {
            guard p.pid > 0, p.uniqueID > 0, p.auditToken.count == 32,
                  !p.boot.isEmpty, p.boot.utf8.count <= 128,
                  !p.signingIdentity.isEmpty, p.signingIdentity.utf8.count <= 512 else { throw BootstrapFailure(.repairRequired) }
        }
    }
    private func validate(_ next: State) throws {
        guard next.version == Lifecycle.version, next.serviceFormat == "bounded-service.v2", next.generation <= next.serial,
              next.stores.count <= Self.maximumStores else { throw BootstrapFailure(.repairRequired) }
        var roots: [StorageIdentity.RootIdentity] = [], backings: [StorageIdentity.RootIdentity] = []
        var generations = Set<UInt64>(), serials = Set<UInt64>(), keys = Set<String>()
        for (id, store) in next.stores {
            let binding = try decodedBinding(store)
            guard store.identity == (try Lifecycle.Identity(binding: binding, generation: store.identity.generation)),
                  id == store.identity.store, store.identity.generation <= next.generation,
                  generations.insert(store.identity.generation).inserted,
                  !roots.contains(binding.root), !backings.contains(binding.backing.identity),
                  try Lifecycle.encode(store).count <= Self.maximumStoreBytes - (store.sealed == nil ? Self.completionReservation : 0)
            else { throw BootstrapFailure(.repairRequired) }
            try validateHandoff(store, serial: next.serial)
            try validateResolvedDeadCold(store, serial: next.serial)
            try validateCold(store, serial: next.serial)
            if let resolved = store.resolvedDeadCold, resolved.phase == .published {
                let grant = resolved.failed.prepared.signedOpen.request.takeover.grant
                guard serials.insert(grant.serial).inserted, keys.insert(grant.newKey).inserted else {
                    throw BootstrapFailure(.repairRequired)
                }
            }
            if let cold = store.pendingCold {
                let grant = cold.prepared.signedOpen.request.takeover.grant
                guard serials.insert(grant.serial).inserted, keys.insert(grant.newKey).inserted else {
                    throw BootstrapFailure(.repairRequired)
                }
            }
            try validateResume(store, serial: next.serial)
            if let resume = store.pendingResume {
                let grant = resume.prepared.signedOpen.request.takeover.grant
                guard serials.insert(grant.serial).inserted, keys.insert(grant.newKey).inserted else {
                    throw BootstrapFailure(.repairRequired)
                }
            }
            roots.append(binding.root); backings.append(binding.backing.identity)
            // The exact fresh format-completion origin is mandatory protected
            // state while initialization is live: structurally valid, bound to
            // this binding/ROOT key and full identity, identical to the durable
            // initialize intent, and phase-consistent (never inferred).
            if let phase = store.freshPhase {
                guard let origin = store.freshOrigin,
                      let initializing = [store.pending, store.current]
                          .compactMap({ $0 }).first(where: { $0.grant.operation == .initialize })
                else { throw BootstrapFailure(.repairRequired) }
                try origin.validate(binding: binding, root: root.publicData)
                guard origin.grant == initializing.grant, origin.principal == initializing.recipient else {
                    throw BootstrapFailure(.repairRequired)
                }
                // A completed initialization must carry the explicit verified
                // publication phase; pending-only may remain durably unverified.
                if store.current?.grant.operation == .initialize {
                    guard phase == .verified else { throw BootstrapFailure(.repairRequired) }
                }
            } else {
                // After the first completed takeover/cold successor no
                // initialize intent may remain and no historical origin may be
                // re-attached as an immutable anchor.
                guard store.freshOrigin == nil,
                      store.current?.grant.operation != .initialize,
                      store.pending?.grant.operation != .initialize else { throw BootstrapFailure(.repairRequired) }
            }
            guard store.current != nil || store.pending?.grant.operation == .initialize else { throw BootstrapFailure(.repairRequired) }
            for intent in [store.current, store.pending].compactMap({ $0 }) {
                try validatePrincipal(intent.recipient, key: intent.grant.newKey)
                guard intent.grant.identity == store.identity, intent.grant.serial <= next.serial,
                      serials.insert(intent.grant.serial).inserted, intent.grant.newKey != root.fingerprint.rawValue else { throw BootstrapFailure(.repairRequired) }
            }
            if let current = store.current {
                _ = try controller(current.grant)
                guard store.result?.grant == current.grant, store.currentService?.grant == current.grant,
                      keys.insert(current.grant.newKey).inserted else { throw BootstrapFailure(.repairRequired) }
            } else if store.result != nil { throw BootstrapFailure(.repairRequired) }
            if let service = store.currentService {
                try service.validate()
                guard service.boot.bootstrapKey == root.fingerprint.rawValue,
                      service.grant == store.current?.grant else { throw BootstrapFailure(.repairRequired) }
                if store.latestServiceChange == nil {
                    guard service.context.serviceEpoch == store.result?.serviceEpoch,
                          service.openRevision <= (store.result?.revision ?? 0) else { throw BootstrapFailure(.repairRequired) }
                }
            } else if store.current != nil { throw BootstrapFailure(.repairRequired) }
            if let pending = store.pendingService {
                try pending.request.validate()
                guard store.pending == nil, store.sealed == nil,
                      pending.recipient == store.current?.recipient,
                      pending.request.predecessor == store.currentService else { throw BootstrapFailure(.repairRequired) }
                if let boot = pending.targetBoot { try pending.request.validateSuccessorBoot(boot) }
                guard pending.request.operationID != store.latestServiceChange?.request.operationID else { throw BootstrapFailure(.repairRequired) }
            }
            if let latest = store.latestServiceChange {
                try latest.validate()
                guard latest.successor == store.currentService, latest.successor.openRevision > (store.result?.revision ?? 0) else { throw BootstrapFailure(.repairRequired) }
            }
            if let pending = store.pending {
                if pending.grant.operation == .initialize {
                    guard store.current == nil, keys.insert(pending.grant.newKey).inserted else { throw BootstrapFailure(.repairRequired) }
                } else {
                    guard let current = store.current,
                          pending.grant.expectedEpoch == (try controller(current.grant).epoch.rawValue),
                          pending.grant.serial > current.grant.serial,
                          pending.grant.id != current.grant.id else { throw BootstrapFailure(.repairRequired) }
                    if pending.grant.operation == .retire {
                        guard pending.recipient == current.recipient else { throw BootstrapFailure(.repairRequired) }
                    } else {
                        guard keys.insert(pending.grant.newKey).inserted else { throw BootstrapFailure(.repairRequired) }
                    }
                }
            }
            if let seal = store.sealed {
                guard seal.grant.operation == .retire, seal.grant == store.pending?.grant else { throw BootstrapFailure(.repairRequired) }
            }
        }
        if let old = next.reclaimed {
            try validatePrincipal(old.intent.recipient, key: old.intent.grant.newKey)
            guard old.intent.grant == old.receipt.grant, old.intent.grant.operation == .retire,
                  old.intent.grant.identity.generation <= next.generation, old.intent.grant.serial <= next.serial,
                  !generations.contains(old.intent.grant.identity.generation), !serials.contains(old.intent.grant.serial) else { throw BootstrapFailure(.repairRequired) }
        }
    }
    private static func encodeState(_ state: State) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(state)
        guard bytes.count <= StorageBootstrapCheckpointJournal.maximumPayloadBytes else { throw BootstrapFailure(.capacityExceeded) }
        return bytes
    }
    private func commit(_ next: State, check: () throws -> Void = {}) throws {
        try validate(next)
        let encoded = try Self.encodeState(next)
        try check()
        do { try journal.checkpoint(encoded) }
        catch { poisoned = true; throw BootstrapFailure(.repairRequired) }
        state = next
        // A failed postflight never rolls back an already durable publication.
        try check()
    }
}

extension StorageBootstrapCheckpointJournal: StorageLifecycleJournal {
    func lifecycleRootPublicKey() throws -> StorageIdentity.RootPublicKey {
        try .init(publicData: readRootPublicKey())
    }
}

extension StorageBootstrapLifecycleAuthority {
    private func coldDependencies() throws -> (StorageBootstrapLifecycleAdoptionAuthority, any StorageLifecycleColdChecking) {
        guard let coldAdoption, let coldMounted else { throw BootstrapFailure(.unavailable) }
        return (coldAdoption, coldMounted)
    }
    private func coldPredecessor(_ service: Lifecycle.ServiceState) throws -> StorageLifecycleColdProtocol.Predecessor {
        try .init(currentGrant: service.grant, serviceEpoch: service.context.serviceEpoch,
            controllerEpoch: service.context.controllerEpoch, controllerKey: service.context.controllerKey,
            openRevision: service.openRevision, bootstrapKey: service.boot.bootstrapKey)
    }
    private func coldDeparted(_ cold: ColdTransaction) throws {
        for p in [cold.predecessorPrincipal.daemon, cold.predecessorPrincipal.child,
                  cold.oldAdoption.origin.shim, cold.oldAdoption.origin.originalDaemon,
                  cold.oldAdoption.origin.originalController, cold.oldAdoption.daemon, cold.oldAdoption.controller] {
            guard processes.liveness(p) == .exited else { throw BootstrapFailure(.blocked) }
        }
    }
    /// A completed L3 is already the committed service, unlike an interrupted L2.
    /// Its missing L4 must still fence ordinary access, but cannot strand a store
    /// after every exact old/new process birth has positively exited. Discovery
    /// and a genuinely new cold L1 may use that committed predecessor without
    /// inventing enrollment, replaying its boot, or clearing the publication fence.
    private func requireColdPredecessor(_ store: Store) throws {
        guard store.coldFenced else { return }
        guard store.pendingCold == nil, store.resolvedDeadCold == nil,
              store.pending == nil, store.pendingService == nil, store.sealed == nil,
              store.pendingResume == nil, !store.resumeFenced, store.pendingHandoff == nil,
              let cold = store.latestCold, cold.completion != nil, !cold.enrollmentAcknowledged else {
            throw BootstrapFailure(.blocked)
        }
        let (adoption, _) = try coldDependencies()
        guard try coldRotated(cold, adoption: adoption) else { throw BootstrapFailure(.blocked) }
        try coldDeparted(cold)
        for process in [cold.newPrincipal.daemon, cold.newPrincipal.child, cold.newOrigin.shim,
                        cold.newOrigin.originalDaemon, cold.newOrigin.originalController] {
            guard processes.liveness(process) == .exited else { throw BootstrapFailure(.blocked) }
        }
    }
    private func coldRotated(_ cold: ColdTransaction, adoption: StorageBootstrapLifecycleAdoptionAuthority) throws -> Bool {
        try adoption.matchesColdRotation(from: cold.oldAdoption, to: cold.newOrigin,
            operationID: cold.request.operationID, signedOpenSHA256: cold.prepared.signedOpenSHA256,
            baseEpoch: cold.prepared.baseEpoch)
    }
    private func resolvedDeadValue(_ resolved: ResolvedDeadCold) throws -> StorageLifecycleColdRootProtocol.ResolvedDead {
        guard let completion = resolved.failed.completion,
              resolved.failed.prepared.recoveryBridge == nil,
              completion.recoveryBridge == nil, !resolved.failed.enrollmentAcknowledged else {
            throw BootstrapFailure(.blocked)
        }
        return try .init(request: resolved.request, anchor: resolved.failed.predecessorService,
            receipt: completion.receipt, successor: completion.successor,
            successorOrigin: completion.successorOrigin, baseEpoch: completion.baseEpoch)
    }
    private func resolvedParticipantsDeparted(_ resolved: ResolvedDeadCold) throws {
        try coldDeparted(resolved.failed)
        let cold = resolved.failed
        for process in [cold.newPrincipal.daemon, cold.newPrincipal.child, cold.newOrigin.shim,
                        cold.newOrigin.originalDaemon, cold.newOrigin.originalController] {
            guard processes.liveness(process) == .exited else { throw BootstrapFailure(.blocked) }
        }
    }
    private func proveResolvedDead(_ resolved: ResolvedDeadCold, store: Store,
                                   check: () throws -> Void) throws {
        try check()
        guard store.pending == nil, store.pendingService == nil, store.sealed == nil,
              store.pendingResume == nil, !store.resumeFenced, store.pendingHandoff == nil,
              store.latestCold == nil else { throw BootstrapFailure(.blocked) }
        try resolvedParticipantsDeparted(resolved)
        let (adoption, _) = try coldDependencies()
        let rotated = try coldRotated(resolved.failed, adoption: adoption)
        if resolved.phase == .published {
            guard rotated else { throw BootstrapFailure(.conflict) }
        } else if !rotated {
            try adoption.verifyColdPredecessor(snapshot: resolved.failed.oldAdoption)
        }
        try check()
    }
    private func validateResolvedDeadCold(_ store: Store, serial: UInt64) throws {
        guard let resolved = store.resolvedDeadCold else { return }
        try resolved.request.validate()
        let cold = resolved.failed, value = try resolvedDeadValue(resolved)
        guard resolved.request.identity == store.identity,
              resolved.request.operationID == cold.request.operationID,
              resolved.request.resolutionID != store.current?.grant.id,
              resolved.request.signedOpenSHA256 == (try cold.prepared.signedOpenSHA256),
              store.latestCold == nil, store.pending == nil, store.pendingService == nil,
              store.sealed == nil, store.pendingResume == nil, !store.resumeFenced,
              store.pendingHandoff == nil else { throw BootstrapFailure(.repairRequired) }
        try value.validate(prepared: cold.prepared, anchor: cold.predecessorService)
        // Validate the original attempted edge against the STILL committed C11.
        // No dead principal/receipt is ever substituted into current/currentService.
        var original = store
        original.resolvedDeadCold = nil; original.pendingCold = cold; original.latestCold = nil
        try validateCold(original, serial: serial)
        switch resolved.phase {
        case .intent:
            guard let pending = store.pendingCold,
                  try Lifecycle.encode(pending) == Lifecycle.encode(cold) else { throw BootstrapFailure(.repairRequired) }
        case .published:
            if let pending = store.pendingCold {
                guard pending.request.operationID != cold.request.operationID,
                      pending.request.operationID != resolved.request.resolutionID,
                      pending.prepared.recoveryBridge == value else { throw BootstrapFailure(.repairRequired) }
            }
        }
    }
    /// A distinct keyless history lane, not completeCold and not candidate rebind.
    /// The native RPC supplies current scope/owner/lock checks at every write cut.
    func resolveDeadCold(_ request: StorageLifecycleColdRootProtocol.ResolveDead,
                         check: () throws -> Void = {}) throws -> StorageLifecycleColdRootProtocol.ResolvedDead {
        try check(); try healthy(); try request.validate()
        guard var store = state.stores[request.identity.store], store.identity == request.identity,
              store.latestCold == nil else { throw BootstrapFailure(.blocked) }
        let resolved: ResolvedDeadCold
        if let saved = store.resolvedDeadCold {
            guard saved.request == request else { throw BootstrapFailure(.conflict) }
            if saved.phase == .published {
                guard store.pendingCold == nil else { throw BootstrapFailure(.blocked) }
                try proveResolvedDead(saved, store: store, check: check)
                return try resolvedDeadValue(saved)
            }
            resolved = saved
        } else {
            guard let failed = store.pendingCold, failed.completion != nil,
                  failed.prepared.recoveryBridge == nil,
                  request.operationID == failed.request.operationID,
                  request.signedOpenSHA256 == (try failed.prepared.signedOpenSHA256) else {
                throw BootstrapFailure(.blocked)
            }
            resolved = .init(request: request, failed: failed, phase: .intent)
            try proveResolvedDead(resolved, store: store, check: check)
            store.resolvedDeadCold = resolved
            var next = state; next.stores[store.identity.store] = store
            try commit(next, check: { try check(); try self.resolvedParticipantsDeparted(resolved) }) // D1
        }
        try proveResolvedDead(resolved, store: store, check: check)
        let (adoption, _) = try coldDependencies(), failed = resolved.failed
        try adoption.rotateCold(from: failed.oldAdoption, to: failed.newOrigin,
            operationID: failed.request.operationID, signedOpenSHA256: request.signedOpenSHA256,
            baseEpoch: failed.prepared.baseEpoch) // Exact original A1, never enrollment.
        try check(); try resolvedParticipantsDeparted(resolved)
        guard try coldRotated(failed, adoption: adoption) else { throw BootstrapFailure(.repairRequired) }
        let published = resolved.publishing()
        store.pendingCold = nil; store.resolvedDeadCold = published
        var next = state; next.stores[store.identity.store] = store
        try commit(next, check: { try self.proveResolvedDead(published, store: store, check: check) }) // D2
        try proveResolvedDead(published, store: store, check: check)
        return try resolvedDeadValue(published)
    }
    private func coldMountedProof(_ cold: ColdTransaction, daemon: BootstrapProcess) throws {
        let (_, mounted) = try coldDependencies()
        let grant = cold.prepared.signedOpen.request.takeover.grant
        guard try processes.candidate(cold.request.candidate, daemon: daemon, grant: grant) == cold.newPrincipal,
              try mounted.mounted(request: cold.request, unsignedGrant: grant,
                signedOpenDigest: cold.prepared.signedOpenSHA256, baseEpoch: cold.prepared.baseEpoch,
                daemon: daemon) == cold.newOrigin else { throw BootstrapFailure(.unauthorized) }
        try processes.validateRecipient(cold.newPrincipal, daemon: daemon, grant: grant)
    }
    func statusCold(identity: Lifecycle.Identity) throws -> StorageLifecycleColdRootProtocol.Status {
        try healthy()
        let (adoption, _) = try coldDependencies()
        if let store = state.stores[identity.store], store.identity == identity,
           let resolved = store.resolvedDeadCold, resolved.phase == .published,
           store.pendingCold == nil {
            try proveResolvedDead(resolved, store: store, check: {})
            let value = try resolvedDeadValue(resolved)
            return try .init(predecessor: coldPredecessor(value.successor), origin: value.successorOrigin,
                allocatedEpoch: value.baseEpoch, eligibility: .eligible)
        }
        guard let store = state.stores[identity.store], store.identity == identity,
              store.pendingService == nil, store.sealed == nil,
              store.pending == nil || store.pending?.grant.operation == .takeover,
              let current = store.current, let service = store.currentService else { throw BootstrapFailure(.blocked) }
        try requireColdPredecessor(store)
        let status = try adoption.status(store: identity.store)
        guard let origin = try adoption.registeredOrigin(store: identity.store), origin.wire == status.origin,
              origin.wire.rootPublicKey == root.publicData,
              try origin.wire.binding.value() == decodedBinding(store) else { throw BootstrapFailure(.conflict) }
        let eligibility: StorageLifecycleColdRootProtocol.Eligibility
        let shimLife = processes.liveness(origin.shim)
        if shimLife == .alive {
            // Live adoption can resume pending/superseded adoption and takeover.
            // This protected service projection is an expectation, not live proof.
            eligibility = .live
        } else if shimLife != .exited || store.pending != nil {
            eligibility = .unavailable
        } else {
            // Cold-only restrictions must not prevent recovery of the registered
            // live shim. Dead/unknown other principals never imply a live shim.
            let snapshot = try adoption.coldSnapshot(store: identity.store)
            if [current.recipient.daemon, current.recipient.child].allSatisfy({ processes.liveness($0) == .exited }),
               (try? adoption.verifyColdPredecessor(snapshot: snapshot)) != nil {
                eligibility = .eligible
            } else { eligibility = .unavailable }
        }
        return try .init(predecessor: coldPredecessor(service), origin: status.origin,
            allocatedEpoch: status.allocatedEpoch, eligibility: eligibility)
    }

    func prepareCold(_ request: StorageLifecycleColdRootProtocol.Prepare,
                     daemon: BootstrapProcess) throws -> StorageLifecycleColdRootProtocol.Prepared {
        try healthy(); try request.validate()
        let (adoption, mounted) = try coldDependencies()
        guard var store = state.stores[request.identity.store], store.identity == request.identity else {
            throw BootstrapFailure(.unknownStore)
        }
        guard store.resolvedDeadCold?.phase != .intent else { throw BootstrapFailure(.blocked) }
        if let cold = store.pendingCold ?? store.latestCold, cold.request.operationID == request.operationID {
            guard cold.request == request else { throw BootstrapFailure(.conflict) }
            if store.pendingCold == nil {
                guard store.pending == nil, store.pendingService == nil, store.sealed == nil,
                      try coldRotated(cold, adoption: adoption) else { throw BootstrapFailure(.conflict) }
                _ = try proveCold(cold, daemon: daemon)
            } else {
                try coldDeparted(cold)
                if try !coldRotated(cold, adoption: adoption) { try adoption.verifyColdPredecessor(snapshot: cold.oldAdoption) }
                try coldMountedProof(cold, daemon: daemon)
            }
            return cold.prepared // Never reconstruct or re-sign either signature.
        }
        guard store.pendingCold == nil, store.pending == nil, store.pendingService == nil, store.sealed == nil,
              let current = store.current, let committedService = store.currentService,
              let committedReceipt = store.result else { throw BootstrapFailure(.blocked) }
        let service: Lifecycle.ServiceState, receipt: Lifecycle.Receipt, predecessor: BootstrapPrincipal
        let bridge: StorageLifecycleColdRootProtocol.ResolvedDead?
        if let resolved = store.resolvedDeadCold {
            guard resolved.phase == .published,
                  request.operationID != resolved.request.operationID,
                  request.operationID != resolved.request.resolutionID else { throw BootstrapFailure(.blocked) }
            try proveResolvedDead(resolved, store: store, check: {})
            let value = try resolvedDeadValue(resolved)
            service = value.successor; receipt = value.receipt; predecessor = resolved.failed.newPrincipal; bridge = value
        } else {
            try requireColdPredecessor(store)
            service = committedService; receipt = committedReceipt; predecessor = current.recipient; bridge = nil
        }
        guard try request.expectedPredecessor == coldPredecessor(service) else { throw BootstrapFailure(.conflict) }
        let snapshot = try adoption.coldSnapshot(store: request.identity.store)
        guard snapshot.origin.wire == request.expectedOrigin, snapshot.allocatedEpoch == request.expectedAllocatedEpoch,
              try snapshot.origin.wire.binding.value() == decodedBinding(store) else { throw BootstrapFailure(.conflict) }
        try adoption.verifyColdPredecessor(snapshot: snapshot)
        for p in [predecessor.daemon, predecessor.child] {
            guard processes.liveness(p) == .exited else { throw BootstrapFailure(.blocked) }
        }
        let grant = try Lifecycle.Grant(operation: .takeover, id: request.operationID, identity: request.identity,
            serial: increment(state.serial), expectedEpoch: service.context.controllerEpoch,
            newKey: request.candidate.publicKey.fingerprint.rawValue)
        try excludeLiveKey(grant.newKey)
        let principal = try processes.candidate(request.candidate, daemon: daemon, grant: grant)
        try validatePrincipal(principal, key: grant.newKey)
        guard principal.daemon == daemon, principal.incarnation != predecessor.incarnation,
              principal.incarnation != current.recipient.incarnation else {
            throw BootstrapFailure(.unauthorized)
        }
        // Signing is internal only. The mount seam sees the unsigned grant and hash.
        let inner = try journal.signLifecycle(grant)
        guard inner.grant == grant, inner.isValidSignature(using: root) else { throw BootstrapFailure(.repairRequired) }
        let open = try StorageLifecycleColdProtocol.Request(operationID: request.operationID,
            predecessor: request.expectedPredecessor, takeover: inner, launch: request.mountedGreeting.launch,
            nowUnixSeconds: request.nowUnixSeconds, lifetimeSeconds: request.lifetimeSeconds)
        let prepared = try StorageLifecycleColdRootProtocol.Prepared(signedOpen: journal.signColdOpen(open),
            successorOrigin: request.mountedGreeting.successorOrigin, baseEpoch: increment(snapshot.allocatedEpoch),
            recoveryBridge: bridge)
        try prepared.validate(for: request)
        guard prepared.signedOpen.request == open else { throw BootstrapFailure(.repairRequired) }
        let origin = try mounted.mounted(request: request, unsignedGrant: grant,
            signedOpenDigest: prepared.signedOpenSHA256, baseEpoch: prepared.baseEpoch, daemon: daemon)
        let cold = ColdTransaction(request: request, predecessorService: service, predecessorReceipt: receipt,
            predecessorPrincipal: predecessor, oldAdoption: snapshot, newPrincipal: principal,
            newOrigin: origin, prepared: prepared)
        store.pendingCold = cold; store.latestCold = nil
        var next = state; next.serial = grant.serial; next.stores[request.identity.store] = store
        try commit(next) // L1: exact signatures durable BEFORE any release.
        try adoption.verifyColdPredecessor(snapshot: snapshot); try coldDeparted(cold)
        try coldMountedProof(cold, daemon: daemon)
        return prepared
    }

    func completeCold(operationID: String, signedOpenSHA256: String,
                      daemon: BootstrapProcess) throws -> StorageLifecycleColdRootProtocol.Completed {
        try healthy()
        let (adoption, _) = try coldDependencies()
        let matches = state.stores.values.filter {
            ($0.pendingCold ?? $0.latestCold)?.request.operationID == operationID
        }
        guard matches.count == 1, var store = matches.first,
              var cold = store.pendingCold ?? store.latestCold,
              try cold.prepared.signedOpenSHA256 == signedOpenSHA256 else { throw BootstrapFailure(.conflict) }
        guard store.resolvedDeadCold?.phase != .intent else { throw BootstrapFailure(.blocked) }
        let rotated = try coldRotated(cold, adoption: adoption)
        if store.pendingCold == nil {
            guard store.pending == nil, store.pendingService == nil, store.sealed == nil,
                  rotated, cold.completion != nil else { throw BootstrapFailure(.conflict) }
            return try proveCold(cold, daemon: daemon)
        }
        try coldDeparted(cold)
        if !rotated { try adoption.verifyColdPredecessor(snapshot: cold.oldAdoption) }
        let proven = try proveCold(cold, daemon: daemon)
        if cold.completion == nil {
            guard !rotated else { throw BootstrapFailure(.repairRequired) }
            cold = cold.completing(proven); store.pendingCold = cold
            var next = state; next.stores[store.identity.store] = store; try commit(next) // L2
        }
        #if CENGINE_COMPAT_COLD_L2_FAULT
        // Also fences pending L2 retries. Only protected resolved-dead recovery
        // may bypass this cut; no request, environment or marker selects it.
        try StorageBootstrapCompatibilityColdL2FaultPolicy.afterColdL2BeforeA1(
            hasRecoveryBridge: cold.prepared.recoveryBridge != nil)
        #endif
        // Reprove after L2, before crossing the separate adoption checkpoint.
        _ = try proveCold(cold, daemon: daemon)
        try coldDeparted(cold)
        try adoption.rotateCold(from: cold.oldAdoption, to: cold.newOrigin, operationID: operationID,
            signedOpenSHA256: signedOpenSHA256, baseEpoch: cold.prepared.baseEpoch) // A1
        guard try coldRotated(cold, adoption: adoption) else { throw BootstrapFailure(.repairRequired) }
        let completion = try proveCold(cold, daemon: daemon)
        store.current = Intent(grant: completion.receipt.grant, recipient: cold.newPrincipal)
        store.result = cold.completion!.receipt; store.currentService = completion.successor
        store.latestServiceChange = nil; store.pendingCold = nil; store.latestCold = cold; store.latestHandoff = nil
        store.resolvedDeadCold = nil // Only actual new live C13 publication clears dead history.
        // Completed cold successor: the historical fresh anchor is cleared too.
        store.freshOrigin = nil; store.freshPhase = nil
        var next = state; next.stores[store.identity.store] = store; try commit(next) // L3
        return try proveCold(cold, daemon: daemon)
    }

    /// Distinct from initialization-only enrollment. Native adapter must enroll the
    /// exact retained origin/channel at baseEpoch; never create a fresh base-1 origin.
    func coldOriginPrincipal(binding: StorageIdentity.StoreBinding) throws -> (StorageLifecycleShimOrigin, BootstrapPrincipal, UInt64, StorageLifecycleColdRootProtocol.Completed) {
        try healthy()
        let (adoption, _) = try coldDependencies()
        guard let store = state.stores[binding.storeID.rawValue], try decodedBinding(store) == binding,
              store.pendingCold == nil, store.pending == nil, store.pendingService == nil, store.sealed == nil,
              let cold = store.latestCold, try coldRotated(cold, adoption: adoption) else { throw BootstrapFailure(.blocked) }
        let completion = try proveCold(cold, daemon: cold.newPrincipal.daemon)
        return (cold.newOrigin, cold.newPrincipal, cold.prepared.baseEpoch, completion)
    }
    /// Trusted native adapter only. Metadata authorizes only the exact L3 proof
    /// path, not ordinary publication; service.nativeOrigin still challenges the
    /// authenticated sender and its retained endpoint, and verifies the disk.
    @discardableResult
    func authorizeColdEnrollment(seed: StorageLifecycleColdShimProtocol.ColdEnrollmentSeed,
                                 origin: StorageLifecycleShimOrigin, nativePrincipal: BootstrapPrincipal) throws -> StorageIdentity.DescriptorIdentity {
        try healthy(); try seed.validate()
        let (adoption, _) = try coldDependencies()
        guard let store = state.stores[origin.wire.binding.store],
              store.pendingCold == nil, store.pending == nil, store.pendingService == nil, store.sealed == nil,
              let cold = store.latestCold, cold.completion != nil,
              cold.newOrigin == origin, cold.newPrincipal == nativePrincipal,
              seed.successorOrigin == origin.wire, seed.operationID == cold.request.operationID,
              try seed.signedOpenSHA256 == cold.prepared.signedOpenSHA256, seed.baseEpoch == cold.prepared.baseEpoch,
              try coldRotated(cold, adoption: adoption) else { throw BootstrapFailure(.blocked) }
        return try cold.request.mountedGreeting.heldBackingIdentity.value()
    }

    /// Called only AFTER authenticated native enrollment proof. A seed delivery
    /// ACK never calls this. Lost native replies reprove even an enrolled transaction.
    func completeColdEnrollment(seed: StorageLifecycleColdShimProtocol.ColdEnrollmentSeed,
                                origin: StorageLifecycleShimOrigin, nativePrincipal: BootstrapPrincipal) throws {
        try authorizeColdEnrollment(seed: seed, origin: origin, nativePrincipal: nativePrincipal)
        guard var store = state.stores[origin.wire.binding.store], let cold = store.latestCold,
              let completion = cold.completion else { throw BootstrapFailure(.blocked) }
        _ = try proveCold(cold, daemon: nativePrincipal.daemon)
        if !cold.enrollmentAcknowledged {
            store.latestCold = cold.completing(completion, enrolled: true)
            var next = state; next.stores[store.identity.store] = store
            try commit(next) // L4: durable enrollment before the typed native reply.
        }
    }

    private func proveCold(_ cold: ColdTransaction, daemon: BootstrapProcess) throws -> StorageLifecycleColdRootProtocol.Completed {
        try coldMountedProof(cold, daemon: daemon)
        let intent = Intent(grant: cold.prepared.signedOpen.request.takeover.grant, recipient: cold.newPrincipal)
        let receipt = try prove(intent, daemon: daemon)
        let boot = try observedBoot(intent, daemon: daemon)
        let live = try proveService(intent, daemon: daemon, boot: boot)
        let completion = try StorageLifecycleColdRootProtocol.Completed(operationID: cold.request.operationID,
            signedOpenSHA256: cold.prepared.signedOpenSHA256, successorOrigin: cold.newOrigin.wire,
            baseEpoch: cold.prepared.baseEpoch, receipt: receipt, successor: live.state(boot: boot),
            recoveryBridge: cold.prepared.recoveryBridge)
        try validateColdCompletion(completion, cold: cold)
        if let previous = cold.completion {
            guard sameResult(previous.receipt, completion.receipt), previous.successor == completion.successor else {
                throw BootstrapFailure(.conflict)
            }
        }
        try coldMountedProof(cold, daemon: daemon)
        return completion
    }
    private func validateColdCompletion(_ completion: StorageLifecycleColdRootProtocol.Completed, cold: ColdTransaction) throws {
        try completion.validate(prepared: cold.prepared)
        let boot = completion.successor.boot, old = cold.predecessorService
        guard boot.serviceEpoch != old.boot.serviceEpoch, boot.tlsRootSHA256 != old.boot.tlsRootSHA256,
              boot.serverSPKI != old.boot.serverSPKI,
              completion.receipt.revision > cold.predecessorReceipt.revision,
              completion.receipt.revision > old.openRevision else { throw BootstrapFailure(.conflict) }
    }
    private func validateCold(_ store: Store, serial: UInt64) throws {
        guard store.pendingCold == nil || store.latestCold == nil else { throw BootstrapFailure(.repairRequired) }
        guard let cold = store.pendingCold ?? store.latestCold else { return }
        try cold.prepared.validate(for: cold.request)
        try cold.predecessorService.validate(); try cold.predecessorReceipt.validate()
        let grant = cold.prepared.signedOpen.request.takeover.grant
        try validatePrincipal(cold.newPrincipal, key: grant.newKey)
        try validatePrincipal(cold.predecessorPrincipal, key: cold.predecessorService.grant.newKey)
        guard cold.request.identity == store.identity, grant.serial <= serial,
              cold.request.expectedPredecessor == (try coldPredecessor(cold.predecessorService)),
              cold.predecessorReceipt.grant == cold.predecessorService.grant,
              cold.oldAdoption.origin.wire == cold.request.expectedOrigin,
              cold.oldAdoption.allocatedEpoch == cold.request.expectedAllocatedEpoch,
              cold.newOrigin.wire == cold.prepared.successorOrigin,
              cold.request.mountedGreeting.daemonUniqueID == cold.newPrincipal.daemon.uniqueID,
              cold.newOrigin.originalDaemon == cold.newPrincipal.daemon,
              cold.newOrigin.originalController == cold.newPrincipal.child,
              cold.newOrigin.shim.boot == cold.newPrincipal.daemon.boot,
              cold.newOrigin.shim.boot == cold.newPrincipal.child.boot,
              cold.newOrigin.shim.uniqueID != cold.newPrincipal.daemon.uniqueID,
              cold.newOrigin.shim.uniqueID != cold.newPrincipal.child.uniqueID,
              cold.newOrigin.shim.pid != cold.newPrincipal.daemon.pid,
              cold.newOrigin.shim.pid != cold.newPrincipal.child.pid,
              cold.newOrigin.shim.boot != cold.oldAdoption.origin.shim.boot || cold.newOrigin.shim.uniqueID != cold.oldAdoption.origin.shim.uniqueID
        else { throw BootstrapFailure(.repairRequired) }
        if let completion = cold.completion { try validateColdCompletion(completion, cold: cold) }
        if store.pendingCold != nil {
            guard !cold.enrollmentAcknowledged else { throw BootstrapFailure(.repairRequired) }
            guard store.pending == nil, store.pendingService == nil, store.sealed == nil,
                  grant.serial > (store.current?.grant.serial ?? 0) else { throw BootstrapFailure(.repairRequired) }
            if let bridge = cold.prepared.recoveryBridge {
                guard let resolved = store.resolvedDeadCold, resolved.phase == .published,
                      bridge == (try resolvedDeadValue(resolved)),
                      cold.predecessorPrincipal == resolved.failed.newPrincipal,
                      cold.predecessorService == bridge.successor, cold.predecessorReceipt == bridge.receipt,
                      cold.oldAdoption.origin == resolved.failed.newOrigin,
                      cold.oldAdoption.allocatedEpoch == bridge.baseEpoch else { throw BootstrapFailure(.repairRequired) }
            } else {
                guard store.current?.recipient == cold.predecessorPrincipal,
                      store.currentService == cold.predecessorService, store.result == cold.predecessorReceipt else {
                    throw BootstrapFailure(.repairRequired)
                }
            }
        } else {
            if !cold.enrollmentAcknowledged {
                guard store.pending == nil, store.pendingService == nil, store.sealed == nil else { throw BootstrapFailure(.repairRequired) }
            }
            guard let completion = cold.completion, store.current?.grant == grant,
                  store.current?.recipient == cold.newPrincipal, store.result == completion.receipt,
                  store.currentService == completion.successor else { throw BootstrapFailure(.repairRequired) }
        }
    }
}

extension StorageBootstrapLifecycleAuthority {
    /// Immutable heap storage keeps nested DTOs off native/Swift Testing worker stacks.
    /// Unlike cold there is NO predecessor service, receipt or adoption snapshot:
    /// resume authorizes only a previously witnessed, UNUSED fresh initialization.
    final class ResumeTransaction: Codable {
        let request: StorageLifecycleResumeRootProtocol.Prepare
        let originalPrincipal: BootstrapPrincipal
        let newPrincipal: BootstrapPrincipal
        let newOrigin: StorageLifecycleShimOrigin
        let prepared: StorageLifecycleResumeRootProtocol.Prepared
        let completion: StorageLifecycleResumeRootProtocol.Completed?
        let enrollmentAcknowledged: Bool
        init(request: StorageLifecycleResumeRootProtocol.Prepare, originalPrincipal: BootstrapPrincipal,
             newPrincipal: BootstrapPrincipal, newOrigin: StorageLifecycleShimOrigin,
             prepared: StorageLifecycleResumeRootProtocol.Prepared,
             completion: StorageLifecycleResumeRootProtocol.Completed? = nil, enrollmentAcknowledged: Bool = false) {
            self.request = request; self.originalPrincipal = originalPrincipal
            self.newPrincipal = newPrincipal; self.newOrigin = newOrigin; self.prepared = prepared
            self.completion = completion; self.enrollmentAcknowledged = enrollmentAcknowledged
        }
        func completing(_ result: StorageLifecycleResumeRootProtocol.Completed, enrolled: Bool = false) -> ResumeTransaction {
            .init(request: request, originalPrincipal: originalPrincipal, newPrincipal: newPrincipal,
                newOrigin: newOrigin, prepared: prepared, completion: result, enrollmentAcknowledged: enrolled)
        }
    }

    private func resumeDependencies() throws -> (StorageBootstrapLifecycleAdoptionAuthority, any StorageLifecycleResumeChecking) {
        guard let coldAdoption, let resumeMounted else { throw BootstrapFailure(.unavailable) }
        return (coldAdoption, resumeMounted)
    }
    /// The exact original pending/current initialize intent together with its
    /// protected fresh origin. Anything else (takeover/retire pending, missing or
    /// missing anchor) is not resumable state. A durable unverified phase already
    /// contains the native FORMAT witness; only ordinary INIT release needs verified.
    private func resumeOriginal(_ store: Store) throws -> (Intent, StorageLifecycleFreshOrigin) {
        guard store.pendingService == nil, store.sealed == nil,
              let origin = store.freshOrigin, store.freshPhase != nil,
              let intent = [store.pending, store.current].compactMap({ $0 })
                  .first(where: { $0.grant.operation == .initialize && $0.grant == origin.grant }),
              intent.recipient == origin.principal else { throw BootstrapFailure(.blocked) }
        return (intent, origin)
    }
    /// Only positive native exit evidence for ALL original pinned tuples (shim,
    /// daemon, controller) permits progress; ambiguity never does.
    private func resumeDeparted(_ origin: StorageLifecycleFreshOrigin) throws {
        for p in [origin.shim, origin.daemon, origin.principal.child] {
            guard processes.liveness(p) == .exited else { throw BootstrapFailure(.blocked) }
        }
    }
    private func resumeMountedProof(_ resume: ResumeTransaction, daemon: BootstrapProcess) throws {
        let (_, mounted) = try resumeDependencies()
        let grant = resume.prepared.signedOpen.request.takeover.grant
        guard try processes.candidate(resume.request.candidate, daemon: daemon, grant: grant) == resume.newPrincipal,
              try mounted.mounted(request: resume.request, unsignedGrant: grant,
                signedOpenDigest: resume.prepared.signedOpenSHA256, baseEpoch: resume.prepared.baseEpoch,
                daemon: daemon) == resume.newOrigin else { throw BootstrapFailure(.unauthorized) }
        try processes.validateRecipient(resume.newPrincipal, daemon: daemon, grant: grant)
    }

    /// Exact-binding lookup only: the scope router has already pinned the caller
    /// and observed its locks. Never enumerate stores, allocate G, sign, or fall
    /// back to a partial binding when HOST lost the original provision reply.
    func lookupResume(binding: StorageLifecycleStoreBinding) throws -> StorageLifecycleResumeRootProtocol.Status {
        try healthy()
        let full = try binding.value()
        guard let store = state.stores[full.storeID.rawValue],
              try decodedBinding(store) == full else { throw BootstrapFailure(.blocked) }
        return try statusResume(identity: store.identity)
    }

    /// Informational projection built ONLY from protected native state. Eligible
    /// requires the protected witnessed fresh origin, the original pending/current
    /// INIT C1, NO adopted store record, and positive exit of every original
    /// pinned shim/daemon/controller. No caller exit bit can influence this.
    func statusResume(identity: Lifecycle.Identity) throws -> StorageLifecycleResumeRootProtocol.Status {
        try healthy()
        let (adoption, _) = try resumeDependencies()
        guard let store = state.stores[identity.store], store.identity == identity,
              !store.fenced, store.pendingService == nil, store.sealed == nil,
              let original = [store.pending, store.current].compactMap({ $0 })
                  .first(where: { $0.grant.operation == .initialize }) else { throw BootstrapFailure(.blocked) }
        guard let origin = store.freshOrigin, store.freshPhase != nil,
              origin.grant == original.grant, origin.principal == original.recipient else {
            throw BootstrapFailure(.blocked)
        }
        let binding = try decodedBinding(store)
        let eligibility: StorageLifecycleResumeRootProtocol.Eligibility
        if try adoption.registeredOrigin(store: identity.store) == nil,
           [origin.shim, origin.daemon, origin.principal.child].allSatisfy({ processes.liveness($0) == .exited }) {
            eligibility = .eligible
        } else { eligibility = .unavailable }
        return try .init(original: original.grant, binding: .init(binding), rootPublicKey: root.publicData,
            originalShimLaunchUUID: origin.greeting.shimLaunchUUID, eligibility: eligibility)
    }

    func prepareResume(_ request: StorageLifecycleResumeRootProtocol.Prepare,
                       daemon: BootstrapProcess) throws -> StorageLifecycleResumeRootProtocol.Prepared {
        try healthy(); try request.validate()
        let (adoption, mounted) = try resumeDependencies()
        guard var store = state.stores[request.identity.store], store.identity == request.identity else {
            throw BootstrapFailure(.unknownStore)
        }
        if let resume = store.pendingResume ?? store.latestResume, resume.request.operationID == request.operationID {
            guard resume.request == request else { throw BootstrapFailure(.conflict) }
            if store.pendingResume == nil {
                guard store.pending == nil, store.pendingService == nil, store.sealed == nil,
                      resume.completion != nil else { throw BootstrapFailure(.conflict) }
                _ = try proveResume(resume, daemon: daemon)
            } else {
                let (_, origin) = try resumeOriginal(store)
                try resumeDeparted(origin)
                try resumeMountedProof(resume, daemon: daemon)
            }
            return resume.prepared // Never reconstruct or re-sign either signature.
        }
        guard !store.fenced, store.pendingService == nil, store.sealed == nil else { throw BootstrapFailure(.blocked) }
        let (original, origin) = try resumeOriginal(store)
        // NO adopted existing store: resume is the initial adoption path only and
        // must never supersede, rotate or reconstruct a committed owner.
        guard try adoption.registeredOrigin(store: request.identity.store) == nil else { throw BootstrapFailure(.blocked) }
        // Admission: validate the caller prepare against the protected Status.
        try request.validate(for: statusResume(identity: request.identity))
        try resumeDeparted(origin)
        // Fixed genesis base epoch: expectedEpoch 1, never a fabricated predecessor.
        let grant = try Lifecycle.Grant(operation: .takeover, id: request.operationID, identity: request.identity,
            serial: increment(state.serial), expectedEpoch: 1,
            newKey: request.candidate.publicKey.fingerprint.rawValue)
        try excludeLiveKey(grant.newKey)
        let principal = try processes.candidate(request.candidate, daemon: daemon, grant: grant)
        try validatePrincipal(principal, key: grant.newKey)
        guard principal.daemon == daemon, principal.incarnation != original.recipient.incarnation else {
            throw BootstrapFailure(.unauthorized)
        }
        // Signing is internal only. The mount seam sees the unsigned grant and hash.
        let inner = try journal.signLifecycle(grant)
        guard inner.grant == grant, inner.isValidSignature(using: root) else { throw BootstrapFailure(.repairRequired) }
        let open = try StorageLifecycleResumeProtocol.Request(operationID: request.operationID,
            original: original.grant, takeover: inner, launch: request.probeGreeting.launch,
            nowUnixSeconds: request.nowUnixSeconds, lifetimeSeconds: request.lifetimeSeconds)
        let prepared = try StorageLifecycleResumeRootProtocol.Prepared(signedOpen: journal.signResumeOpen(open),
            successorOrigin: request.probeGreeting.successorOrigin, baseEpoch: 1)
        try prepared.validate(for: request)
        guard prepared.signedOpen.request == open else { throw BootstrapFailure(.repairRequired) }
        // Bind the actual native mounted readonly proof on the retained resume channel.
        let newOrigin = try mounted.mounted(request: request, unsignedGrant: grant,
            signedOpenDigest: prepared.signedOpenSHA256, baseEpoch: 1, daemon: daemon)
        let resume = ResumeTransaction(request: request, originalPrincipal: original.recipient,
            newPrincipal: principal, newOrigin: newOrigin, prepared: prepared)
        store.pendingResume = resume; store.latestResume = nil
        var next = state; next.serial = grant.serial; next.stores[request.identity.store] = store
        try commit(next) // R1: exact inner+outer signed bytes durable BEFORE any release.
        try resumeDeparted(origin); try resumeMountedProof(resume, daemon: daemon)
        return prepared
    }

    func completeResume(operationID: String, signedOpenSHA256: String,
                        daemon: BootstrapProcess) throws -> StorageLifecycleResumeRootProtocol.Completed {
        try healthy()
        let matches = state.stores.values.filter {
            ($0.pendingResume ?? $0.latestResume)?.request.operationID == operationID
        }
        guard matches.count == 1, var store = matches.first,
              var resume = store.pendingResume ?? store.latestResume,
              try resume.prepared.signedOpenSHA256 == signedOpenSHA256 else { throw BootstrapFailure(.conflict) }
        if store.pendingResume == nil {
            guard store.pending == nil, store.pendingService == nil, store.sealed == nil,
                  resume.completion != nil else { throw BootstrapFailure(.conflict) }
            return try proveResume(resume, daemon: daemon)
        }
        let (_, origin) = try resumeOriginal(store)
        try resumeDeparted(origin)
        let proven = try proveResume(resume, daemon: daemon)
        if resume.completion == nil {
            resume = resume.completing(proven); store.pendingResume = resume
            var next = state; next.stores[store.identity.store] = store; try commit(next) // R2
        }
        // Reprove after R2, before the successor publication.
        _ = try proveResume(resume, daemon: daemon)
        try resumeDeparted(origin)
        let completion = try proveResume(resume, daemon: daemon)
        store.pending = nil
        store.current = Intent(grant: completion.receipt.grant, recipient: resume.newPrincipal)
        store.result = resume.completion!.receipt; store.currentService = completion.successor
        store.latestServiceChange = nil; store.pendingResume = nil; store.latestResume = resume; store.latestHandoff = nil
        // Completed resume successor: the historical fresh anchor is cleared too.
        store.freshOrigin = nil; store.freshPhase = nil
        var next = state; next.stores[store.identity.store] = store
        try commit(next) // R3
        return try proveResume(resume, daemon: daemon)
    }

    /// Distinct from initialization and cold enrollment. The native adapter enrolls
    /// the exact retained resume origin at the fixed genesis base epoch through the
    /// INITIAL adoption machinery; it never rotates or fabricates a predecessor epoch.
    func resumeOriginPrincipal(binding: StorageIdentity.StoreBinding) throws -> (StorageLifecycleShimOrigin, BootstrapPrincipal, UInt64, StorageLifecycleResumeRootProtocol.Completed) {
        try healthy()
        guard let store = state.stores[binding.storeID.rawValue], try decodedBinding(store) == binding,
              store.pendingResume == nil, store.pending == nil, store.pendingService == nil, store.sealed == nil,
              let resume = store.latestResume, let completion = resume.completion else { throw BootstrapFailure(.blocked) }
        _ = try proveResume(resume, daemon: resume.newPrincipal.daemon)
        return (resume.newOrigin, resume.newPrincipal, resume.prepared.baseEpoch, completion)
    }
    /// Trusted native adapter only. The resume seed authorizes the exact retained
    /// origin; an existing adopted store (cold/live) never matches a resume seed.
    @discardableResult
    func authorizeResumeEnrollment(seed: StorageLifecycleColdShimProtocol.ColdEnrollmentSeed,
                                   origin: StorageLifecycleShimOrigin, nativePrincipal: BootstrapPrincipal) throws -> StorageIdentity.DescriptorIdentity {
        try healthy(); try seed.validate()
        guard seed.purpose == .resumeReadOnly else { throw BootstrapFailure(.conflict) }
        let (adoption, _) = try resumeDependencies()
        guard let store = state.stores[origin.wire.binding.store],
              store.pendingResume == nil, store.pending == nil, store.pendingService == nil, store.sealed == nil,
              let resume = store.latestResume, resume.completion != nil,
              resume.newOrigin == origin, resume.newPrincipal == nativePrincipal,
              seed.successorOrigin == origin.wire, seed.operationID == resume.request.operationID,
              try seed.signedOpenSHA256 == resume.prepared.signedOpenSHA256, seed.baseEpoch == resume.prepared.baseEpoch else {
            throw BootstrapFailure(.blocked)
        }
        let registered = try adoption.registeredOrigin(store: origin.wire.binding.store)
        guard registered == nil || registered == origin else { throw BootstrapFailure(.blocked) }
        return try resume.request.probeGreeting.heldBackingIdentity.value()
    }
    /// Called only AFTER the initial adoption machinery durably recorded the exact
    /// origin. A seed delivery ACK never calls this; lost replies reprove the
    /// enrolled transaction before the durable ACK checkpoint.
    func completeResumeEnrollment(seed: StorageLifecycleColdShimProtocol.ColdEnrollmentSeed,
                                  origin: StorageLifecycleShimOrigin, nativePrincipal: BootstrapPrincipal) throws {
        try authorizeResumeEnrollment(seed: seed, origin: origin, nativePrincipal: nativePrincipal)
        guard var store = state.stores[origin.wire.binding.store], let resume = store.latestResume,
              let completion = resume.completion else { throw BootstrapFailure(.blocked) }
        let (adoption, _) = try resumeDependencies()
        guard try adoption.registeredOrigin(store: origin.wire.binding.store) == origin else { throw BootstrapFailure(.blocked) }
        _ = try proveResume(resume, daemon: nativePrincipal.daemon)
        if !resume.enrollmentAcknowledged {
            store.latestResume = resume.completing(completion, enrolled: true)
            var next = state; next.stores[store.identity.store] = store
            try commit(next) // R4: durable enrollment before the typed native reply.
        }
    }

    private func proveResume(_ resume: ResumeTransaction, daemon: BootstrapProcess) throws -> StorageLifecycleResumeRootProtocol.Completed {
        try resumeMountedProof(resume, daemon: daemon)
        let intent = Intent(grant: resume.prepared.signedOpen.request.takeover.grant, recipient: resume.newPrincipal)
        let receipt = try prove(intent, daemon: daemon)
        let boot = try observedBoot(intent, daemon: daemon)
        let live = try proveService(intent, daemon: daemon, boot: boot)
        let completion = try StorageLifecycleResumeRootProtocol.Completed(operationID: resume.request.operationID,
            signedOpenSHA256: resume.prepared.signedOpenSHA256, successorOrigin: resume.newOrigin.wire,
            baseEpoch: resume.prepared.baseEpoch, receipt: receipt, successor: live.state(boot: boot))
        try completion.validate(prepared: resume.prepared)
        if let previous = resume.completion {
            guard sameResult(previous.receipt, completion.receipt), previous.successor == completion.successor else {
                throw BootstrapFailure(.conflict)
            }
        }
        try resumeMountedProof(resume, daemon: daemon)
        return completion
    }
    private func validateResume(_ store: Store, serial: UInt64) throws {
        guard store.pendingResume == nil || store.latestResume == nil else { throw BootstrapFailure(.repairRequired) }
        guard let resume = store.pendingResume ?? store.latestResume else { return }
        try resume.prepared.validate(for: resume.request)
        let grant = resume.prepared.signedOpen.request.takeover.grant
        let original = resume.request.expectedOriginal
        try validatePrincipal(resume.newPrincipal, key: grant.newKey)
        try validatePrincipal(resume.originalPrincipal, key: original.newKey)
        guard resume.request.identity == store.identity, grant.serial <= serial,
              original.operation == .initialize, original.expectedEpoch == 0,
              grant.operation == .takeover, grant.expectedEpoch == 1,
              resume.prepared.baseEpoch == 1,
              resume.newOrigin.wire == resume.prepared.successorOrigin,
              resume.request.probeGreeting.daemonUniqueID == resume.newPrincipal.daemon.uniqueID,
              resume.newOrigin.originalDaemon == resume.newPrincipal.daemon,
              resume.newOrigin.originalController == resume.newPrincipal.child,
              resume.newOrigin.shim.boot == resume.newPrincipal.daemon.boot,
              resume.newOrigin.shim.boot == resume.newPrincipal.child.boot,
              resume.newOrigin.shim.uniqueID != resume.newPrincipal.daemon.uniqueID,
              resume.newOrigin.shim.uniqueID != resume.newPrincipal.child.uniqueID,
              resume.newOrigin.shim.pid != resume.newPrincipal.daemon.pid,
              resume.newOrigin.shim.pid != resume.newPrincipal.child.pid
        else { throw BootstrapFailure(.repairRequired) }
        if let completion = resume.completion { try completion.validate(prepared: resume.prepared) }
        if store.pendingResume != nil {
            let intent = [store.pending, store.current].compactMap({ $0 })
                .first(where: { $0.grant == original })
            guard let intent, intent.recipient == resume.originalPrincipal else { throw BootstrapFailure(.repairRequired) }
            if store.current?.grant == original {
                guard store.result?.grant == original, store.currentService?.grant == original else {
                    throw BootstrapFailure(.repairRequired)
                }
            } else {
                guard store.current == nil, store.result == nil, store.currentService == nil else {
                    throw BootstrapFailure(.repairRequired)
                }
            }
            // The protected fresh anchor remains bound to the exact original while
            // the resume is pending; completion clears it like every successor.
            guard let anchor = store.freshOrigin, store.freshPhase != nil,
                  anchor.grant == original, anchor.principal == resume.originalPrincipal else {
                throw BootstrapFailure(.repairRequired)
            }
            guard !resume.enrollmentAcknowledged else { throw BootstrapFailure(.repairRequired) }
        } else {
            if !resume.enrollmentAcknowledged {
                guard store.pending == nil, store.pendingService == nil, store.sealed == nil else {
                    throw BootstrapFailure(.repairRequired)
                }
            }
            guard let completion = resume.completion, store.current?.grant == grant,
                  store.current?.recipient == resume.newPrincipal, store.result == completion.receipt,
                  store.currentService == completion.successor else { throw BootstrapFailure(.repairRequired) }
        }
    }
}

extension StorageBootstrapLifecycleAuthority {
    func configureHandoff(adoption: StorageBootstrapLifecycleAdoptionAuthority,
                          checking: any StorageLifecycleHandoffChecking) throws {
        guard handoffAdoption == nil else { throw BootstrapFailure(.conflict) }
        handoffAdoption = adoption; handoffChecking = checking
        try healthy()
    }

    /// Ordinary publication/adoption routes use this additional fence. The native
    /// proof-channel greeting must continue using guardColdPublication instead.
    func guardHandoffPublication(store id: String) throws {
        try healthy()
        guard state.stores[id]?.pendingHandoff == nil else { throw BootstrapFailure(.blocked) }
    }

    func handoffStatus(identity: Lifecycle.Identity, daemon: BootstrapProcess) throws -> StorageLifecycleHandoffRootProtocol.Status {
        try healthy(); try identity.validate()
        guard processes.liveness(daemon) == .alive,
              let store = state.stores[identity.store], store.identity == identity,
              !store.resumeFenced, store.pendingService == nil, store.sealed == nil,
              let service = store.currentService,
              store.pending == nil || store.pending?.grant.operation == .takeover else { throw BootstrapFailure(.blocked) }
        // Discovery precedes HOST's cold selection; this does not authorize handoff.
        try requireColdPredecessor(store)
        let latest = store.latestHandoff.flatMap { $0.completion?.service == service ? $0 : nil }
        let transaction = store.pendingHandoff ?? latest
        return try .init(currentService: service, pending: store.pending?.grant,
            operationID: transaction?.signed.request.operationID, completion: transaction?.completion)
    }

    func recoverHandoff(identity: Lifecycle.Identity, operationID: String,
                        daemon: BootstrapProcess) throws -> StorageLifecycleHandoffRootProtocol.Completed {
        try healthy(); try identity.validate(); _ = try StorageIdentity.GrantID(operationID)
        guard let adoption = handoffAdoption, let checking = handoffChecking else { throw BootstrapFailure(.unavailable) }
        guard var store = state.stores[identity.store], store.identity == identity,
              !store.coldFenced, !store.resumeFenced, store.pendingService == nil, store.sealed == nil else {
            throw BootstrapFailure(.blocked)
        }
        var transaction: HandoffTransaction
        if let old = store.pendingHandoff {
            guard old.signed.request.operationID == operationID else { throw BootstrapFailure(.conflict) }
            transaction = old
        } else if let old = store.latestHandoff, old.signed.request.operationID == operationID {
            guard store.currentService == old.completion?.service else { throw BootstrapFailure(.conflict) }
            transaction = old
        } else {
            guard let current = store.current, let pending = store.pending, pending.grant.operation == .takeover,
                  let service = store.currentService, let receipt = store.result else { throw BootstrapFailure(.blocked) }
            let snapshot = try adoption.handoffSnapshot(store: identity.store)
            guard snapshot.origin.wire.rootPublicKey == root.publicData,
                  try snapshot.origin.wire.binding.value() == decodedBinding(store) else { throw BootstrapFailure(.conflict) }
            for process in [current.recipient.daemon, current.recipient.child, pending.recipient.daemon, pending.recipient.child] {
                guard processes.liveness(process) == .exited else { throw BootstrapFailure(.blocked) }
            }
            guard processes.liveness(daemon) == .alive else { throw BootstrapFailure(.unauthorized) }
            let request = try StorageLifecycleHandoffProtocol.Request(operationID: operationID,
                predecessor: current.grant, pending: pending.grant,
                serviceEpoch: service.context.serviceEpoch, openRevision: service.openRevision)
            // Signing stays internal. Exact signed request is durable before the
            // native checker receives it or any signature can leave this method.
            let signed = try journal.signHandoff(request)
            guard signed.request == request, signed.isValidSignature(using: root) else { throw BootstrapFailure(.repairRequired) }
            transaction = HandoffTransaction(signed: signed, predecessor: current, pending: pending,
                service: service, receipt: receipt, adoption: snapshot)
            store.pendingHandoff = transaction; store.latestHandoff = nil
            var next = state; next.stores[identity.store] = store
            try commit(next)
        }
        func recheck() throws {
            try healthy()
            guard processes.liveness(daemon) == .alive,
                  try adoption.handoffSnapshot(store: identity.store) == transaction.adoption else { throw BootstrapFailure(.blocked) }
            for process in [transaction.predecessor.recipient.daemon, transaction.predecessor.recipient.child,
                            transaction.pending.recipient.daemon, transaction.pending.recipient.child] {
                guard processes.liveness(process) == .exited else { throw BootstrapFailure(.blocked) }
            }
        }
        func proof() throws -> StorageLifecycleHandoffRootProtocol.Completed {
            try recheck()
            let nonce = try randomNonce()
            let result = try checking.handoff(transaction.signed, expectedService: transaction.service,
                origin: transaction.adoption.origin, daemon: daemon, nonce: nonce)
            try recheck(); try result.validate()
            guard result.request == transaction.signed.request, result.nonce == nonce else { throw BootstrapFailure(.unauthorized) }
            let service: Lifecycle.ServiceState
            let receipt: Lifecycle.Receipt
            if result.appliedGrant == transaction.predecessor.grant {
                service = transaction.service; receipt = transaction.receipt
            } else {
                service = try .init(grant: transaction.pending.grant,
                    context: .init(serviceEpoch: transaction.service.context.serviceEpoch,
                        controllerEpoch: increment(transaction.pending.grant.expectedEpoch), controllerKey: transaction.pending.grant.newKey),
                    openRevision: transaction.service.openRevision, boot: transaction.service.boot)
                receipt = try .init(grant: result.appliedGrant, nonce: nonce,
                    serviceEpoch: result.appliedServiceEpoch, revision: result.appliedRevision)
            }
            let value = try StorageLifecycleHandoffRootProtocol.Completed(signedRequest: transaction.signed, result: result,
                predecessorService: transaction.service, predecessorReceipt: transaction.receipt, service: service, receipt: receipt,
                pendingSigned: journal.signLifecycle(transaction.pending.grant))
            if let old = transaction.completion {
                guard old.service == value.service, sameResult(old.receipt, value.receipt),
                      old.result.fenceRevision == result.fenceRevision else { throw BootstrapFailure(.conflict) }
            }
            return value
        }
        let observed = try proof()
        if store.pendingHandoff != nil {
            transaction = transaction.completing(observed)
            if observed.result.appliedGrant == transaction.pending.grant {
                store.current = transaction.pending; store.result = observed.receipt
                store.currentService = observed.service; store.latestServiceChange = nil
                store.latestCold = nil; store.latestResume = nil
                store.freshOrigin = nil; store.freshPhase = nil
            }
            // Predecessor outcome retains the exact original receipt/service.
            store.pending = nil; store.pendingHandoff = nil; store.latestHandoff = transaction
            var next = state; next.stores[identity.store] = store
            try commit(next, check: recheck)
        }
        // Durable disposition is not a live outcome proof. Lost replies ALWAYS
        // execute another fresh native proof; later takeovers never replay history.
        return try proof()
    }

    private func validateHandoff(_ store: Store, serial: UInt64) throws {
        guard store.pendingHandoff == nil || store.latestHandoff == nil else { throw BootstrapFailure(.repairRequired) }
        guard let t = store.pendingHandoff ?? store.latestHandoff else { return }
        try t.signed.validate(); try t.service.validate(); try t.receipt.validate()
        try validatePrincipal(t.predecessor.recipient, key: t.predecessor.grant.newKey)
        try validatePrincipal(t.pending.recipient, key: t.pending.grant.newKey)
        let r = t.signed.request
        guard t.signed.isValidSignature(using: root), r.predecessor == t.predecessor.grant,
              r.pending == t.pending.grant, r.pending.serial <= serial, r.pending.identity == store.identity,
              t.service.grant == r.predecessor, t.receipt.grant == r.predecessor,
              t.service.context.serviceEpoch == r.serviceEpoch, t.service.openRevision == r.openRevision,
              t.adoption.origin.wire.rootPublicKey == root.publicData,
              try t.adoption.origin.wire.binding.value() == decodedBinding(store) else { throw BootstrapFailure(.repairRequired) }
        if store.pendingHandoff != nil {
            guard t.completion == nil, store.current == t.predecessor, store.pending == t.pending,
                  store.currentService == t.service, store.result == t.receipt,
                  !store.coldFenced, !store.resumeFenced, store.pendingService == nil, store.sealed == nil else { throw BootstrapFailure(.repairRequired) }
        } else {
            guard let completion = t.completion else { throw BootstrapFailure(.repairRequired) }
            try completion.validate()
            guard completion.signedRequest == t.signed, completion.predecessorService == t.service,
                  completion.predecessorReceipt == t.receipt,
                  store.current == (completion.result.appliedGrant == t.pending.grant ? t.pending : t.predecessor),
                  store.result == completion.receipt,
                  store.latestServiceChange != nil || store.currentService == completion.service else {
                throw BootstrapFailure(.repairRequired)
            }
        }
    }
}

#if os(macOS)
import CEngineCore
import Darwin
import Foundation

/// Host-side storage lifecycle checkpoint containing public recovery metadata.
/// These records provide neither signing keys nor verified boot or recovery authority.
/// Recovery requires fresh child queries and direct root-helper confirmation.
/// A signature checks grant bytes, not recipient liveness, current authority,
/// completed draining or permission to dispose of a disk.
@MainActor final class ManagedStorageLifecycleCheckpoint {
    typealias Wire = StorageLifecycleProtocol
    typealias ColdRoot = StorageLifecycleColdRootProtocol
    enum Failure: Error { case invalid, blocked, unknownContext, staleIntents, capacity, repairRequired }
    static let directoryName = "managed-storage-owner"
    static let maximumContexts = HostStorageIntents.maximumIntents * 4 + 2
    static let maximumLinks = HostStorageIntents.maximumIntents + 1
    static let maximumBytes = HostStorageIntentCommit.maximumStateBytes
    // Aggregate bound: fixed-size scalar/context fields plus reciprocal intent
    // edges. A child has one predecessor, so edges do not grow quadratically.
    private static let maximumReferenceBytes = HostStorageIntents.maximumIntents * 2_048

    /// Public independently pinned recipient metadata, never proof of possession.
    struct Recipient: Codable, Equatable, Sendable {
        let publicKey: Data
        let incarnation: String
        let daemonUniqueID: UInt64
        let childUniqueID: UInt64
        let childPID: Int32
    }
    /// Original grant/recipient retry tuple. ROOT generates its own fresh challenge
    /// for each direct proof; the host neither chooses nor pins that nonce here.
    /// No expiry/abandon operation exists.
    struct GrantContext: Codable, Equatable, Sendable {
        let signed: Wire.SignedGrant
        let recipient: Recipient
        let requestID: String
        /// Initialization is granted before Guest creates E. Only initialize may
        /// omit this expectation; takeover/retire identify the selected live service.
        let serviceEpoch: String?
    }
    /// The returned nonce is retained as public audit metadata, not authentication.
    /// Fresh trusted ROOT/child exchanges must validate their own challenge before
    /// supplying these DTOs. A ROOT signature covers the grant, not this receipt.
    struct Completed: Codable, Equatable, Sendable {
        let original: GrantContext
        let directResult: Wire.Receipt
    }
    struct Context: Codable, Equatable, Hashable, Sendable {
        let serviceEpoch: String
        let controllerEpoch: UInt64
        let controllerKey: String
    }
    /// Rejection-only diagnostic projection of the owner's freshly checked native
    /// worker. Public/copyable metadata, never boot, replacement or recovery authority.
    struct ObservedWorker: Codable, Equatable, Sendable {
        let context: Context
        let workerUUID: String
    }
    struct Historical: Codable, Equatable, Sendable {
        let context: Context
        let controller: Completed
        // A folded public service-result baseline, NOT a replay chain or proof.
        // Retain this result even when its older predecessor no longer has users.
        var serviceResult: ServiceChange? = nil
    }
    /// Public same-C service-change link. Its digest is the replacementRecovery
    /// workerHistoryReference for this NEW contract, not a reinterpretation of v1.
    struct ServiceChange: Codable, Equatable, Sendable {
        let operationID: String
        let predecessor: Context
        let successor: Context
        let revision: UInt64
        @MainActor var reference: String { get throws { HostStorageIntents.hash(try ManagedStorageLifecycleCheckpoint.encode(self)) } }
    }
    /// Original durable retry tuple, persisted before ROOT staging or Guest IO.
    /// Configuration time is not refreshed on recovery; no expiry/abandon exists.
    /// predecessorWorkerUUID is copied from the owner's held native boot envelope,
    /// never generated as a correlation ID. Persisted bytes alone are not proof.
    struct PendingService: Codable, Equatable, Sendable {
        let request: Wire.ServiceChangeRequest
        let stageRequestID: String
        let completionRequestID: String
        /// Worker that executed the predecessor service epoch; frozen before IO.
        let predecessorWorkerUUID: String
        let nowUnixSeconds: UInt64
        let lifetimeSeconds: UInt64
    }
    /// Durable PRE-ISSUANCE takeover tuple, persisted before ROOT issue so a lost
    /// reply retries exactly this request/grant/candidate. One slot; folded into
    /// the staged signed grant. Public metadata only, never takeover authority.
    struct TakeoverRequest: Codable, Equatable, Sendable {
        let requestID: String
        let grantID: String
        let recipient: Recipient
        let expectedEpoch: UInt64
        let serviceEpoch: String
    }
    /// One bounded public retry tuple, frozen before ROOT prepare/complete. Native
    /// identities here are untrusted correlations, never process capabilities.
    struct AdoptionRetry: Codable, Equatable, Sendable {
        let status: StorageLifecycleAdoptionRootProtocol.Status
        let request: StorageLifecycleAdoptionProtocol.Request
        let prepareRequestID: String
        let completeRequestID: String
    }
    /// Bounded, exact ROOT recovery retry. Public metadata, never outcome proof.
    struct HandoffRetry: Codable, Equatable, Sendable {
        let operationID: String
        let statusRequestID: String
        let recoveryRequestID: String
        let predecessor: Wire.ServiceState
        let pending: Wire.Grant
    }
    /// Exact pre-issuance tuple; public metadata, never native-exit or boot proof.
    struct ColdRequest: Codable, Equatable, Sendable {
        let prepare: ColdRoot.Prepare
        let recipient: Recipient
        let prepareRequestID: String
        let completionRequestID: String
    }
    struct ColdResolutionRequest: Codable, Equatable, Sendable {
        let value: ColdRoot.ResolveDead
        let requestID: String
    }
    struct PendingCold: Codable, Equatable, Sendable {
        let request: ColdRequest
        var prepared: ColdRoot.Prepared?
        var bootAttempted: Bool
        var resolutionRequest: ColdResolutionRequest? = nil
    }
    /// Exact attempted boot retained as DEAD history, never current control.
    struct ResolvedDeadCold: Codable, Equatable, Sendable {
        let attempted: PendingCold
        let value: ColdRoot.ResolvedDead
        let anchor: Historical
        let anchorService: Wire.ServiceState
    }
    /// One folded cross-E edge, not a recursive cold history or fresh authority.
    struct CompletedCold: Codable, Equatable, Sendable {
        let request: ColdRequest
        let prepared: ColdRoot.Prepared
        let completion: ColdRoot.Completed
        let predecessor: Historical
        let predecessorService: Wire.ServiceState
        var deadPredecessor: ResolvedDeadCold? = nil
    }
    /// Unlike synthesized Optional coding, missing keys are rejected and nil is
    /// encoded explicitly. Old checkpoints cannot silently acquire cold fields.
    @propertyWrapper struct RequiredNullable<Value: Codable & Equatable & Sendable>: Codable, Equatable, Sendable {
        var wrappedValue: Value?
        init(wrappedValue: Value?) { self.wrappedValue = wrappedValue }
        init(from decoder: any Decoder) throws {
            wrappedValue = try decoder.singleValueContainer().decode(Value?.self)
        }
        func encode(to encoder: any Encoder) throws {
            var container = encoder.singleValueContainer()
            try container.encode(wrappedValue)
        }
    }
    struct IntentReference: Codable, Equatable, Sendable {
        let id: String
        let version: UInt64
        let original: Context
        let recovery: HostStorageIntents.ReplacementRecovery?
        let predecessor: String?
        let successor: String?
        let superseded: [String]
    }
    struct Metadata: Codable, Equatable, Sendable {
        let version: String
        let identity: Wire.Identity
        let rootPublicKey: Data
        let provenanceReference: String
        var revision: UInt64
        var current: Completed?
        var currentContext: Context?
        var currentService: Wire.ServiceState?
        var observedWorker: ObservedWorker? = nil
        var pendingService: PendingService?
        /// Exact ROOT-signed native replacement configuration; bounded to the
        /// pending/latest operation, never a worker-history authority chain.
        var serviceReplacement: StorageLifecycleServiceBootProtocol.ReplacementRequest? = nil
        /// Durable operation-lane fence: never fall back to configure after native IO.
        var nativeReplacementAttempted: Bool? = nil
        /// Exact consumed tuple for rebuilding the latest completed retry envelope.
        var latestServiceRequest: PendingService?
        var latestServiceConfirmation: Wire.ServiceChangeConfirmation?
        var pending: GrantContext?
        var pendingTakeover: TakeoverRequest? = nil
        var adoptionRetry: AdoptionRetry? = nil
        var handoffRetry: HandoffRetry? = nil
        @RequiredNullable var pendingCold: PendingCold? = nil
        @RequiredNullable var latestCold: CompletedCold? = nil
        // Omitted in existing sole-v2 bytes: absent means unresolved, not success.
        var resolvedDeadCold: ResolvedDeadCold? = nil
        var sealed: Wire.Receipt?
        var terminal: Wire.Receipt?
        var contexts: [Historical]
        var serviceLinks: [ServiceChange]
        var latestServiceChange: ServiceChange?
        var intentRevision: UInt64
        var references: [IntentReference]
    }
    enum Change {
        case stageHandoff(HandoffRetry)
        case recoverHandoff(StorageLifecycleHandoffRootProtocol.Completed)
        case stageColdResolution(ColdResolutionRequest)
        case resolveDeadCold(ColdRoot.ResolvedDead)
        case stageColdRequest(ColdRequest)
        case authorizeCold(ColdRoot.Prepared)
        case attemptColdBoot
        case completeCold(ColdRoot.Completed)
        case stageAdoption(AdoptionRetry)
        case stageReplacementAdoption(AdoptionRetry)
        case stageTakeoverRequest(TakeoverRequest)
        case stage(GrantContext)
        case complete(Wire.Receipt)
        case recordService(Wire.ServiceState)
        case recordObservedWorker(ObservedWorker)
        case stageService(PendingService)
        case authorizeServiceReplacement(StorageLifecycleServiceBootProtocol.ReplacementRequest)
        case attemptNativeReplacement
        case confirmService(Wire.ServiceChangeConfirmation)
        case seal(Wire.Receipt)
        /// ROOT's final public retirement result, not permission to delete a disk.
        case retire(Wire.Receipt)
    }

    /// Fresh baseline starts with a ROOT-signed initialize fence, not epoch-1 replay.
    static func baseline(identity: Wire.Identity, rootPublicKey: Data, provenanceReference: String,
                         initialize: GrantContext) throws -> Metadata {
        let result = Metadata(version: Wire.version, identity: identity, rootPublicKey: rootPublicKey,
            provenanceReference: provenanceReference, revision: 1, pending: initialize,
            contexts: [], serviceLinks: [], intentRevision: 0, references: [])
        guard initialize.signed.grant.operation == .initialize else { throw Failure.invalid }
        try validate(result)
        return result
    }

    /// Resume has no fabricated predecessor receipt or old controller key.
    static func requireUnusedInitialization(_ state: Metadata, original: Wire.Grant?) throws {
        try validate(state)
        let grant = state.pending?.signed.grant ?? state.current?.original.signed.grant
        guard let grant, grant.operation == .initialize, original == nil || original == grant,
              state.pendingTakeover == nil, state.pendingService == nil, state.pendingCold == nil,
              state.latestCold == nil, state.adoptionRetry == nil, state.sealed == nil, state.terminal == nil,
              state.references.isEmpty, state.serviceLinks.isEmpty, state.latestServiceChange == nil,
              state.contexts.count <= 1 else { throw Failure.blocked }
    }
    static func resumeBaseline(request: ManagedStorageInitialization.Request,
                               prepared: StorageLifecycleResumeRootProtocol.Prepared,
                               completion: StorageLifecycleResumeRootProtocol.Completed,
                               provenance: String, intentRevision: UInt64) throws -> Metadata {
        try prepared.validate(for: request.prepare); try completion.validate(prepared: prepared)
        let completed = Completed(original: GrantContext(signed: prepared.signedOpen.request.takeover,
            recipient: request.recipient, requestID: request.completionRequestID,
            serviceEpoch: completion.receipt.serviceEpoch), directResult: completion.receipt)
        let context = try controllerContext(completed)
        let result = Metadata(version: Wire.version, identity: request.prepare.identity,
            rootPublicKey: request.prepare.probeGreeting.rootPublicKey, provenanceReference: provenance,
            revision: 1, current: completed, currentContext: context, currentService: completion.successor,
            contexts: [Historical(context: context, controller: completed)], serviceLinks: [],
            intentRevision: intentRevision, references: [])
        try validate(result); return result
    }
    func finishInitialization(request: ManagedStorageInitialization.Request,
                              prepared: StorageLifecycleResumeRootProtocol.Prepared,
                              completion: StorageLifecycleResumeRootProtocol.Completed,
                              intents: HostStorageIntents.State) throws {
        try healthy(); try Self.requireUnusedInitialization(state, original: request.prepare.expectedOriginal)
        try ManagedStorageInitialization.requireEmpty(intents)
        var next = try Self.resumeBaseline(request: request, prepared: prepared, completion: completion,
            provenance: state.provenanceReference, intentRevision: intents.revision)
        guard next.identity == state.identity, next.rootPublicKey == state.rootPublicKey,
              state.revision < UInt64.max else { throw Failure.invalid }
        next.revision = state.revision + 1
        do {
            try commits.commit(prior: Self.encode(state), priorRevision: state.revision,
                next: Self.encode(next), nextRevision: next.revision)
            state = next
        } catch { poisoned = true; commits.poison(); throw error }
    }

    /// Pure metadata transition; not an authenticated admission or recovery API.
    /// The durable wrapper below additionally closes the caller's intent snapshot race.
    static func applying(_ change: Change, to prior: Metadata, intents: HostStorageIntents.State) throws -> Metadata {
        try validate(prior)
        var next = prior
        if prior.handoffRetry != nil {
            switch change {
            case .stageHandoff, .recoverHandoff: break
            default: throw Failure.blocked
            }
        }
        if prior.resolvedDeadCold != nil {
            switch change {
            case .resolveDeadCold, .stageColdRequest, .authorizeCold, .attemptColdBoot, .completeCold: break
            default: throw Failure.blocked
            }
        }
        if prior.pendingCold != nil {
            switch change {
            case .stageColdResolution, .resolveDeadCold, .stageColdRequest, .authorizeCold, .attemptColdBoot, .completeCold: break
            default: throw Failure.blocked
            }
        }
        if let terminal = prior.terminal {
            guard case .retire(let result) = change, try sameResult(result, terminal) else { throw Failure.blocked }
            // Terminal checkpoints are immutable, including their intent census.
            // Refuse changed evidence rather than silently ignoring or folding it.
            guard intents.revision == prior.intentRevision else { throw Failure.staleIntents }
            guard try census(intents, identity: prior.identity, provenance: prior.provenanceReference) == prior.references else {
                throw Failure.blocked
            }
            return prior
        } else {
            switch change {
            case .stageHandoff(let retry):
                try validate(retry, in: prior)
                guard prior.handoffRetry == nil || prior.handoffRetry == retry else { throw Failure.blocked }
                next.handoffRetry = retry
            case .recoverHandoff(let completion):
                guard let retry = prior.handoffRetry else { throw Failure.blocked }
                try validate(retry, in: prior); try completion.validate()
                let request = completion.signedRequest.request
                let root = try StorageIdentity.RootPublicKey(publicData: prior.rootPublicKey)
                guard completion.signedRequest.isValidSignature(using: root),
                      request.operationID == retry.operationID, request.pending == retry.pending,
                      completion.predecessorService == retry.predecessor,
                      let current = prior.current,
                      try sameResult(completion.predecessorReceipt, current.directResult) else { throw Failure.invalid }
                let original: GrantContext
                if let pending = prior.pending {
                    original = pending
                    if let signed = completion.pendingSigned {
                        guard signed.grant == pending.signed.grant, signed.isValidSignature(using: root) else { throw Failure.invalid }
                    }
                } else {
                    guard let issued = prior.pendingTakeover, let signed = completion.pendingSigned else { throw Failure.invalid }
                    original = GrantContext(signed: signed, recipient: issued.recipient,
                        requestID: issued.requestID, serviceEpoch: issued.serviceEpoch)
                }
                try validate(original, in: prior)
                guard original.signed.grant == retry.pending else { throw Failure.invalid }
                if completion.service.grant == retry.pending {
                    guard completion.receipt.revision > (prior.latestServiceChange?.revision ?? 0) else { throw Failure.invalid }
                    let completed = Completed(original: original, directResult: completion.receipt)
                    let live = try controllerContext(completed)
                    guard !prior.contexts.contains(where: { $0.context == live }) else { throw Failure.invalid }
                    next.current = completed; next.currentContext = live; next.currentService = completion.service
                    next.contexts.append(Historical(context: live, controller: completed))
                    next.latestServiceChange = nil; next.latestServiceRequest = nil; next.latestServiceConfirmation = nil
                    next.serviceReplacement = nil; next.nativeReplacementAttempted = nil
                } else {
                    guard completion.service == prior.currentService,
                          try sameResult(completion.receipt, current.directResult) else { throw Failure.invalid }
                }
                // Only the exact abandoned lane checked above is cleared, after
                // the owner supplies independently authenticated native ROOT proof.
                next.pending = nil; next.pendingTakeover = nil; next.adoptionRetry = nil; next.handoffRetry = nil
            case .stageColdResolution(let request):
                guard var pending = prior.pendingCold, pending.bootAttempted, let prepared = pending.prepared,
                      prior.resolvedDeadCold == nil, prior.pending == nil, prior.pendingTakeover == nil,
                      prior.pendingService == nil, prior.sealed == nil, prior.terminal == nil else { throw Failure.blocked }
                try validate(request, for: pending, in: prior)
                guard prepared.recoveryBridge == nil else { throw Failure.blocked }
                if let retained = pending.resolutionRequest {
                    guard retained == request else { throw Failure.blocked }
                } else {
                    pending.resolutionRequest = request; next.pendingCold = pending
                }
            case .resolveDeadCold(let value):
                if let retained = prior.resolvedDeadCold {
                    guard prior.pendingCold == nil, retained.value == value else { throw Failure.blocked }
                } else {
                    guard let pending = prior.pendingCold, pending.bootAttempted, let prepared = pending.prepared,
                          let request = pending.resolutionRequest, request.value == value.request,
                          let service = prior.currentService, let live = prior.currentContext,
                          let anchor = prior.contexts.first(where: { $0.context == live }) else { throw Failure.blocked }
                    try value.validate(prepared: prepared, anchor: service)
                    let resolved = ResolvedDeadCold(attempted: pending, value: value, anchor: anchor, anchorService: service)
                    try validate(resolved, in: prior)
                    let historical = try deadColdHistorical(resolved)
                    guard !prior.contexts.contains(where: { $0.context == historical.context }) else { throw Failure.invalid }
                    next.contexts.append(historical)
                    next.resolvedDeadCold = resolved; next.pendingCold = nil
                    // Deliberately NO update of current/currentContext/currentService.
                }
            case .stageColdRequest(let request):
                guard prior.pending == nil, prior.pendingTakeover == nil, prior.pendingService == nil,
                      prior.sealed == nil else { throw Failure.blocked }
                let service = try coldPredecessorService(in: prior)
                let current = try coldPredecessor(in: prior).controller
                // adoptionRetry is retained even after successful adoption; it is
                // not a pending-operation flag. Owner serializes IO, and ROOT must
                // independently establish cold eligibility before authorization.
                try validateColdRequest(request, predecessor: current, service: service, in: prior)
                if let pending = prior.pendingCold {
                    guard pending.request == request else { throw Failure.blocked }
                } else {
                    guard request.prepare.operationID != prior.latestCold?.request.prepare.operationID,
                          request.prepare.operationID != prior.resolvedDeadCold?.value.request.operationID,
                          request.prepare.operationID != prior.resolvedDeadCold?.value.request.resolutionID else { throw Failure.blocked }
                    next.pendingCold = PendingCold(request: request, prepared: nil, bootAttempted: false)
                }
            case .authorizeCold(let prepared):
                guard var pending = prior.pendingCold else { throw Failure.blocked }
                try prepared.validate(for: pending.request.prepare)
                guard prepared.recoveryBridge == prior.resolvedDeadCold?.value,
                      pending.resolutionRequest == nil else { throw Failure.blocked }
                if let existing = pending.prepared {
                    guard prepared == existing else { throw Failure.blocked }
                } else {
                    pending.prepared = prepared
                    next.pendingCold = pending
                }
            case .attemptColdBoot:
                guard var pending = prior.pendingCold, pending.prepared != nil,
                      pending.resolutionRequest == nil else { throw Failure.blocked }
                pending.bootAttempted = true
                next.pendingCold = pending
            case .completeCold(let completion):
                if let pending = prior.pendingCold {
                    guard pending.bootAttempted, let prepared = pending.prepared,
                          pending.resolutionRequest == nil else { throw Failure.blocked }
                    let service = try coldPredecessorService(in: prior)
                    let predecessor = try coldPredecessor(in: prior)
                    let cold = CompletedCold(request: pending.request, prepared: prepared, completion: completion,
                        predecessor: predecessor, predecessorService: service, deadPredecessor: prior.resolvedDeadCold)
                    try validate(cold, in: prior)
                    let completed = coldController(cold)
                    let live = try controllerContext(completed)
                    guard !prior.contexts.contains(where: { $0.context == live }) else { throw Failure.invalid }
                    next.current = completed; next.currentContext = live; next.currentService = completion.successor
                    next.contexts.append(Historical(context: live, controller: completed))
                    next.latestCold = cold; next.pendingCold = nil; next.resolvedDeadCold = nil
                    next.latestServiceChange = nil; next.latestServiceRequest = nil; next.latestServiceConfirmation = nil
                    next.serviceReplacement = nil; next.nativeReplacementAttempted = nil
                    next.adoptionRetry = nil
                } else {
                    guard prior.pending == nil, prior.pendingTakeover == nil, prior.pendingService == nil,
                          prior.sealed == nil, let latest = prior.latestCold,
                          completion == latest.completion, prior.current == coldController(latest),
                          prior.currentService == completion.successor else { throw Failure.blocked }
                }
            case .stageAdoption(let retry):
                guard prior.current != nil, prior.sealed == nil, prior.pendingService == nil else { throw Failure.blocked }
                // Replacement is metadata only. The owner must re-check native
                // equality and ROOT's live allocation before any external IO.
                next.adoptionRetry = retry
            case .stageReplacementAdoption(let retry):
                guard try replacementRecoveryRequest(prior) != nil else { throw Failure.blocked }
                next.adoptionRetry = retry
            case .stageTakeoverRequest(let request):
                guard prior.pending == nil, prior.pendingService == nil, prior.sealed == nil else { throw Failure.blocked }
                try validate(request, in: prior)
                if let existing = prior.pendingTakeover {
                    guard request == existing else { throw Failure.blocked }
                } else {
                    next.pendingTakeover = request
                }
            case .stage(let context):
                guard prior.pendingService == nil else { throw Failure.blocked }
                try validate(context, in: prior)
                if let request = prior.pendingTakeover {
                    // Only the exact durable pre-issuance tuple may be staged.
                    let grant = context.signed.grant
                    guard prior.pending == nil, grant.operation == .takeover, grant.id == request.grantID,
                          context.requestID == request.requestID, context.recipient == request.recipient,
                          grant.expectedEpoch == request.expectedEpoch,
                          context.serviceEpoch == request.serviceEpoch else { throw Failure.blocked }
                    next.pendingTakeover = nil
                }
                if let pending = prior.pending {
                    guard context == pending else { throw Failure.blocked }
                } else if context == prior.current?.original {
                    // Exact latest completed retry only; historical grants are not retries.
                } else {
                    guard prior.sealed == nil, let current = prior.current, let live = prior.currentContext,
                          context.signed.grant.id != current.original.signed.grant.id,
                          context.signed.grant.serial > current.original.signed.grant.serial,
                          context.signed.grant.expectedEpoch == live.controllerEpoch,
                          context.signed.grant.operation != .initialize else { throw Failure.blocked }
                    if context.signed.grant.operation == .retire {
                        guard context.recipient == current.original.recipient,
                              context.signed.grant.newKey == live.controllerKey,
                              context.serviceEpoch == live.serviceEpoch else { throw Failure.invalid }
                    } else {
                        guard context.signed.grant.newKey != live.controllerKey,
                              context.recipient.incarnation != current.original.recipient.incarnation else { throw Failure.invalid }
                    }
                    next.pending = context
                }
            case .complete(let receipt):
                guard prior.pendingService == nil else { throw Failure.blocked }
                if let pending = prior.pending {
                    guard pending.signed.grant.operation != .retire else { throw Failure.blocked }
                    try match(receipt, pending)
                    if let current = prior.current {
                        guard receipt.revision > current.directResult.revision,
                              receipt.revision > (prior.latestServiceChange?.revision ?? 0) else { throw Failure.invalid }
                    }
                    let completed = Completed(original: pending, directResult: receipt)
                    let context = try controllerContext(completed)
                    next.current = completed; next.currentContext = context; next.pending = nil
                    next.contexts.append(Historical(context: context, controller: completed))
                    next.latestServiceChange = nil; next.serviceReplacement = nil; next.nativeReplacementAttempted = nil
                    next.currentService = nil; next.latestServiceRequest = nil; next.latestServiceConfirmation = nil
                } else {
                    guard prior.sealed == nil, let current = prior.current,
                          try sameResult(receipt, current.directResult) else { throw Failure.blocked }
                }
            case .recordService(let service):
                guard prior.pending == nil, prior.pendingService == nil, prior.sealed == nil,
                      let current = prior.current else { throw Failure.blocked }
                try validate(service, in: prior)
                if let existing = prior.currentService {
                    guard service == existing else { throw Failure.blocked }
                } else {
                    // Recording a boot can establish a grant's baseline, never move E.
                    guard prior.latestServiceConfirmation == nil, prior.latestServiceChange == nil,
                          context(service.context) == (try controllerContext(current)),
                          service.openRevision <= current.directResult.revision else { throw Failure.invalid }
                    next.currentService = service
                }
            case .recordObservedWorker(let observation):
                guard prior.pending == nil, prior.pendingTakeover == nil, prior.pendingService == nil,
                      prior.sealed == nil else { throw Failure.blocked }
                try validate(observation, in: prior)
                next.observedWorker = observation
            case .stageService(let pending):
                guard prior.pending == nil, prior.pendingTakeover == nil, prior.sealed == nil,
                      prior.currentService != nil else { throw Failure.blocked }
                try validate(pending, in: prior)
                if let existing = prior.pendingService {
                    guard pending == existing else { throw Failure.blocked }
                } else {
                    next.pendingService = pending
                    next.serviceReplacement = nil; next.nativeReplacementAttempted = nil
                }
            case .attemptNativeReplacement:
                guard prior.pendingService != nil, prior.serviceReplacement != nil else { throw Failure.blocked }
                next.nativeReplacementAttempted = true
            case .authorizeServiceReplacement(let request):
                guard let pending = prior.pendingService else { throw Failure.blocked }
                try validateReplacement(request, pending: pending, in: prior)
                if let existing = prior.serviceReplacement {
                    guard existing == request else { throw Failure.blocked }
                }
                next.serviceReplacement = request
            case .confirmService(let confirmation):
                guard prior.pending == nil, prior.sealed == nil, let current = prior.current else { throw Failure.blocked }
                try confirmation.validate()
                if let pending = prior.pendingService {
                    guard confirmation.request == pending.request,
                          confirmation.request.predecessor == prior.currentService,
                          confirmation.successor.openRevision > current.directResult.revision else { throw Failure.invalid }
                    let link = serviceChange(confirmation)
                    guard !prior.contexts.contains(where: { $0.context == link.successor }) else { throw Failure.invalid }
                    next.currentService = confirmation.successor; next.currentContext = link.successor
                    next.pendingService = nil; next.latestServiceRequest = pending; next.latestServiceConfirmation = confirmation
                    next.contexts.append(Historical(context: link.successor, controller: current, serviceResult: link))
                    next.serviceLinks.append(link); next.latestServiceChange = link
                } else {
                    guard confirmation == prior.latestServiceConfirmation else { throw Failure.blocked }
                }
            case .seal(let receipt):
                guard prior.pendingService == nil, let pending = prior.pending,
                      pending.signed.grant.operation == .retire else { throw Failure.blocked }
                try match(receipt, pending)
                guard receipt.revision > (prior.current?.directResult.revision ?? 0),
                      receipt.revision > (prior.latestServiceChange?.revision ?? 0) else { throw Failure.invalid }
                if let seal = prior.sealed {
                    guard try sameResult(receipt, seal) else { throw Failure.invalid }
                } else {
                    next.sealed = receipt
                }
            case .retire(let receipt):
                guard prior.pendingService == nil, let seal = prior.sealed,
                      try sameResult(receipt, seal) else { throw Failure.blocked }
                next.terminal = receipt
            }
        }
        // A selected-service/controller change invalidates the old observation.
        // Pending operations may retain it as predecessor diagnostics only.
        if next.currentService != prior.currentService || next.currentContext != prior.currentContext {
            next.observedWorker = nil
        }
        // No compaction at load. Only a prepared metadata update with a complete
        // reference census may fold completed contexts. Pending is never folded.
        let references = try census(intents, identity: prior.identity, provenance: prior.provenanceReference)
        guard intents.revision >= prior.intentRevision else { throw Failure.staleIntents }
        next.intentRevision = intents.revision; next.references = references
        try retainReferencedContexts(&next)
        if next == prior { return prior }
        guard prior.revision < UInt64.max else { throw Failure.capacity }
        next.revision += 1
        try validate(next)
        // Reserve completion space before IO: grant receipt/context, or a full
        // service confirmation/consumed tuple plus its successor context/link,
        // and terminal result.
        guard try encode(next).count <= maximumBytes - reservation(next) else { throw Failure.capacity }
        return next
    }

    private static func validateColdRequest(_ request: ColdRequest, predecessor: Completed,
                                           service: Wire.ServiceState, in state: Metadata) throws {
        let prepare = request.prepare, recipient = request.recipient
        try prepare.validate(); try service.validate()
        try validate(predecessor.original, in: state); try match(predecessor.directResult, predecessor.original)
        try uuid(request.prepareRequestID); try uuid(request.completionRequestID); try uuid(recipient.incarnation)
        let key = try StorageIdentity.Ed25519SPKI(rawPublicKey: recipient.publicKey)
        let protected = prepare.expectedPredecessor
        guard request.prepareRequestID != request.completionRequestID,
              prepare.identity == state.identity, prepare.expectedOrigin.rootPublicKey == state.rootPublicKey,
              prepare.mountedGreeting.rootPublicKey == state.rootPublicKey,
              prepare.candidate.publicKey == key, prepare.candidate.childPIDHint == recipient.childPID,
              prepare.candidate.incarnationID.rawValue == recipient.incarnation,
              recipient.childPID > 0, recipient.daemonUniqueID > 0, recipient.childUniqueID > 0,
              recipient.daemonUniqueID != recipient.childUniqueID,
              recipient.daemonUniqueID == prepare.mountedGreeting.daemonUniqueID,
              recipient.incarnation != predecessor.original.recipient.incarnation,
              service.grant == predecessor.original.signed.grant,
              protected.currentGrant == service.grant, protected.serviceEpoch == service.context.serviceEpoch,
              protected.controllerEpoch == service.context.controllerEpoch,
              protected.controllerKey == service.context.controllerKey,
              protected.openRevision == service.openRevision, protected.bootstrapKey == service.boot.bootstrapKey else {
            throw Failure.invalid
        }
    }
    private static func validate(_ request: ColdResolutionRequest, for pending: PendingCold, in state: Metadata) throws {
        try request.value.validate(); try uuid(request.requestID)
        guard pending.bootAttempted, let prepared = pending.prepared, prepared.recoveryBridge == nil,
              request.value.identity == state.identity,
              request.value.operationID == pending.request.prepare.operationID,
              request.value.signedOpenSHA256 == (try prepared.signedOpenSHA256),
              request.value.resolutionID != state.current?.original.signed.grant.id,
              request.requestID != pending.request.prepareRequestID,
              request.requestID != pending.request.completionRequestID else { throw Failure.invalid }
    }
    private static func validate(_ resolved: ResolvedDeadCold, in state: Metadata) throws {
        let pending = resolved.attempted
        guard pending.bootAttempted, let prepared = pending.prepared, let request = pending.resolutionRequest,
              request.value == resolved.value.request else { throw Failure.invalid }
        try validate(request, for: pending, in: state)
        try validateColdRequest(pending.request, predecessor: resolved.anchor.controller,
            service: resolved.anchorService, in: state)
        try resolved.value.validate(prepared: prepared, anchor: resolved.anchorService)
        guard resolved.anchor.context == context(resolved.anchorService.context) else { throw Failure.invalid }
    }
    private static func deadColdHistorical(_ resolved: ResolvedDeadCold) throws -> Historical {
        guard let prepared = resolved.attempted.prepared else { throw Failure.invalid }
        let completed = Completed(original: GrantContext(signed: prepared.signedOpen.request.takeover,
            recipient: resolved.attempted.request.recipient,
            requestID: resolved.attempted.request.completionRequestID,
            serviceEpoch: resolved.value.receipt.serviceEpoch), directResult: resolved.value.receipt)
        return try Historical(context: controllerContext(completed), controller: completed)
    }
    /// Epoch/key selection ONLY. Dead history never replaces the committed owner.
    static func coldPredecessor(in state: Metadata) throws -> Historical {
        if let resolved = state.resolvedDeadCold { return try deadColdHistorical(resolved) }
        guard let live = state.currentContext, let record = state.contexts.first(where: { $0.context == live }) else {
            throw Failure.blocked
        }
        return record
    }
    static func coldPredecessorService(in state: Metadata) throws -> Wire.ServiceState {
        if let resolved = state.resolvedDeadCold { return resolved.value.successor }
        guard let service = state.currentService else { throw Failure.blocked }
        return service
    }
    private static func coldController(_ cold: CompletedCold) -> Completed {
        Completed(original: GrantContext(signed: cold.prepared.signedOpen.request.takeover,
            recipient: cold.request.recipient, requestID: cold.request.completionRequestID,
            serviceEpoch: cold.completion.receipt.serviceEpoch), directResult: cold.completion.receipt)
    }
    private static func validate(_ cold: CompletedCold, in state: Metadata) throws {
        try validateColdRequest(cold.request, predecessor: cold.predecessor.controller,
            service: cold.predecessorService, in: state)
        try cold.prepared.validate(for: cold.request.prepare)
        try cold.completion.validate(prepared: cold.prepared)
        if let resolved = cold.deadPredecessor {
            try validate(resolved, in: state)
            guard cold.prepared.recoveryBridge == resolved.value,
                  cold.predecessor == (try deadColdHistorical(resolved)),
                  cold.predecessorService == resolved.value.successor else { throw Failure.invalid }
        } else {
            guard cold.prepared.recoveryBridge == nil else { throw Failure.invalid }
        }
        let old = cold.predecessorService, new = cold.completion.successor
        guard cold.predecessor.context == context(old.context),
              new.context.controllerEpoch == old.context.controllerEpoch + 1,
              new.context.controllerKey == cold.prepared.signedOpen.request.takeover.grant.newKey,
              new.openRevision > old.openRevision,
              new.openRevision > cold.predecessor.controller.directResult.revision,
              new.openRevision > (cold.predecessor.serviceResult?.revision ?? 0),
              new.boot.tlsRootSHA256 != old.boot.tlsRootSHA256,
              new.boot.serverSPKI != old.boot.serverSPKI else { throw Failure.invalid }
        if let result = cold.predecessor.serviceResult {
            guard old.openRevision == result.revision else { throw Failure.invalid }
        } else {
            guard old.openRevision <= cold.predecessor.controller.directResult.revision else { throw Failure.invalid }
        }
        let completed = coldController(cold)
        try validate(completed.original, in: state); try match(completed.directResult, completed.original)
    }

    private static func validate(_ request: TakeoverRequest, in state: Metadata) throws {
        try uuid(request.requestID); try uuid(request.grantID); try uuid(request.recipient.incarnation)
        let key = try StorageIdentity.Ed25519SPKI(rawPublicKey: request.recipient.publicKey)
        let root = try StorageIdentity.RootPublicKey(publicData: state.rootPublicKey)
        guard state.pending == nil, state.pendingService == nil, state.sealed == nil, state.terminal == nil,
              let current = state.current, let live = state.currentContext,
              request.requestID != request.grantID, request.expectedEpoch == live.controllerEpoch,
              request.serviceEpoch == live.serviceEpoch, key.fingerprint != root.fingerprint,
              key.fingerprint.rawValue != live.controllerKey,
              request.recipient.incarnation != current.original.recipient.incarnation,
              request.recipient.childPID > 0, request.recipient.daemonUniqueID > 0, request.recipient.childUniqueID > 0,
              request.recipient.daemonUniqueID != request.recipient.childUniqueID else { throw Failure.invalid }
    }
    /// Complete census equality against the actual journal; public data, not authority.
    static func censusMatches(_ state: Metadata, intents: HostStorageIntents.State) throws -> Bool {
        try validate(state)
        guard intents.revision == state.intentRevision else { return false }
        let references = try census(intents, identity: state.identity, provenance: state.provenanceReference)
        return references == state.references
    }
    /// Read-only UNTRUSTED manifest lookup for classification/open. Never mutates.
    static func readManifest(in root: PersistentStateDirectory) throws -> Manifest {
        let directory = try root.openDirectory(named: directoryName)
        let bytes = try HostStorageIntentCommit.readPrivateFile(in: directory, named: "manifest.json", maximumBytes: maximumBytes)
        let manifest: Manifest = try canonical(bytes)
        guard manifest.version == manifestVersion else { throw Failure.invalid }
        return manifest
    }

    private static func validate(_ retry: HandoffRetry, in state: Metadata) throws {
        try uuid(retry.operationID); try uuid(retry.statusRequestID); try uuid(retry.recoveryRequestID)
        try retry.predecessor.validate(); try retry.pending.validate()
        guard retry.statusRequestID != retry.recoveryRequestID,
              state.pendingCold == nil, state.pendingService == nil,
              state.sealed == nil, state.terminal == nil,
              retry.predecessor == state.currentService, let current = state.current,
              retry.predecessor.grant == current.original.signed.grant else { throw Failure.invalid }
        _ = try StorageLifecycleHandoffProtocol.Request(operationID: retry.operationID,
            predecessor: retry.predecessor.grant, pending: retry.pending,
            serviceEpoch: retry.predecessor.context.serviceEpoch, openRevision: retry.predecessor.openRevision)
        let recipient: Recipient
        if let pending = state.pending {
            guard state.pendingTakeover == nil, pending.signed.grant == retry.pending,
                  pending.serviceEpoch == retry.predecessor.context.serviceEpoch else { throw Failure.invalid }
            recipient = pending.recipient
        } else {
            guard let request = state.pendingTakeover,
                  request.grantID == retry.pending.id, request.expectedEpoch == retry.pending.expectedEpoch,
                  request.serviceEpoch == retry.predecessor.context.serviceEpoch,
                  try StorageIdentity.Ed25519SPKI(rawPublicKey: request.recipient.publicKey).fingerprint.rawValue == retry.pending.newKey
            else { throw Failure.invalid }
            recipient = request.recipient
        }
        if let adoption = state.adoptionRetry {
            guard adoption.request.daemonUniqueID == recipient.daemonUniqueID,
                  adoption.request.controllerUniqueID == recipient.childUniqueID else { throw Failure.invalid }
        }
    }
    private static func reservation(_ state: Metadata) throws -> Int {
        if state.handoffRetry != nil {
            return try 32_768 + maximumReferenceBytes - encode(state.references).count
        }
        if state.pendingCold != nil || state.resolvedDeadCold != nil {
            // Reserve the exact signed authorization, completion and folded edge,
            // plus possible census growth before any external cold IO.
            return try 98_304 + maximumReferenceBytes - encode(state.references).count
        }
        guard state.pendingService != nil else { return 16_384 }
        // Confirmation may consume its 16 KiB result allowance and fold a newer
        // intent census. Reserve all possible census growth before external IO;
        // new references can only retain already-held contexts/links.
        return try 32_768 + maximumReferenceBytes - encode(state.references).count
    }
    private static func context(_ service: Wire.ServiceContext) -> Context {
        Context(serviceEpoch: service.serviceEpoch, controllerEpoch: service.controllerEpoch, controllerKey: service.controllerKey)
    }
    private static func serviceChange(_ confirmation: Wire.ServiceChangeConfirmation) -> ServiceChange {
        ServiceChange(operationID: confirmation.request.operationID, predecessor: context(confirmation.request.predecessor.context),
            successor: context(confirmation.successor.context), revision: confirmation.successor.openRevision)
    }
    private static func validate(_ service: Wire.ServiceState, in state: Metadata) throws {
        try service.validate()
        let root = try StorageIdentity.RootPublicKey(publicData: state.rootPublicKey)
        guard service.grant == state.current?.original.signed.grant, service.grant.identity == state.identity,
              service.boot.bootstrapKey == root.fingerprint.rawValue,
              context(service.context) == state.currentContext else { throw Failure.invalid }
    }
    private static func validate(_ observation: ObservedWorker, in state: Metadata) throws {
        try validate(observation.context); try uuid(observation.workerUUID)
        guard let service = state.currentService,
              observation.context == state.currentContext,
              observation.context == context(service.context) else { throw Failure.invalid }
    }
    /// Shared original-envelope validation. A consumed tuple's predecessor is
    /// historical, so this deliberately does not require the current service.
    private static func validateServiceRequest(_ request: PendingService, in state: Metadata) throws {
        try request.request.validate(); try uuid(request.stageRequestID); try uuid(request.completionRequestID)
        try uuid(request.predecessorWorkerUUID)
        guard request.stageRequestID != request.completionRequestID,
              request.request.predecessor.openRevision < UInt64.max,
              let current = state.current, current.directResult.revision < UInt64.max else { throw Failure.invalid }
        // This pre-issuance tuple precedes the separately persisted exact ROOT-
        // signed serviceReplacement. Validate unsigned configuration invariants too.
        let signed = current.original.signed
        try signed.validate()
        let root = try StorageIdentity.RootPublicKey(publicData: state.rootPublicKey)
        guard request.nowUnixSeconds > 0, request.nowUnixSeconds <= StorageServiceTypes.maximumUnixSeconds,
              request.lifetimeSeconds > 0, request.lifetimeSeconds <= 86_400, signed.grant.operation != .retire,
              signed.grant == request.request.predecessor.grant,
              root.fingerprint.rawValue == request.request.predecessor.boot.bootstrapKey else { throw Failure.invalid }
    }
    private static func validateReplacement(_ replacement: StorageLifecycleServiceBootProtocol.ReplacementRequest,
                                            pending: PendingService, in state: Metadata) throws {
        try replacement.validate()
        let configuration = replacement.configuration
        guard replacement.predecessorWorkerUUID == pending.predecessorWorkerUUID,
              configuration.reopen?.request == pending.request,
              configuration.signed == state.current?.original.signed,
              configuration.rootPublicKey == state.rootPublicKey,
              configuration.nowUnixSeconds == pending.nowUnixSeconds,
              configuration.lifetimeSeconds == pending.lifetimeSeconds else { throw Failure.invalid }
    }
    /// Selects a retry lane, never authority. Missing frozen authorization for a
    /// pending change is a hard refusal, not permission to try cold/fresh startup.
    static func replacementRecoveryRequest(_ state: Metadata) throws -> PendingService? {
        try validate(state)
        // Cold uncertainty/resolution owns the lane even if a previous confirmed
        // service replacement still retains its consumed native retry envelope.
        if state.pendingCold != nil || state.resolvedDeadCold != nil {
            guard state.pendingService == nil else { throw Failure.blocked }
            return nil
        }
        // A confirmed replacement may retain its native envelope until the next
        // takeover completes. Its abandoned takeover must use handoff recovery,
        // not replay the already-completed replacement with another candidate.
        if state.pendingService == nil, state.latestServiceConfirmation != nil,
           state.pendingTakeover != nil || state.pending?.signed.grant.operation == .takeover {
            return nil
        }
        guard state.pendingService != nil || state.nativeReplacementAttempted == true else { return nil }
        guard state.pending == nil, state.pendingTakeover == nil, state.pendingCold == nil,
              state.sealed == nil, state.terminal == nil,
              let request = state.pendingService ?? state.latestServiceRequest,
              let replacement = state.serviceReplacement else { throw Failure.blocked }
        try validateReplacement(replacement, pending: request, in: state)
        return request
    }

    private static func validate(_ pending: PendingService, in state: Metadata) throws {
        try validateServiceRequest(pending, in: state)
        guard pending.request.predecessor == state.currentService,
              pending.request.operationID != state.latestServiceConfirmation?.request.operationID else { throw Failure.invalid }
    }
    private static func context(_ intent: HostStorageIntents.Intent) -> Context {
        Context(serviceEpoch: intent.serviceEpoch, controllerEpoch: intent.controllerEpoch, controllerKey: intent.controllerKey)
    }
    private static func context(_ recovery: HostStorageIntents.ReplacementRecovery) -> Context {
        Context(serviceEpoch: recovery.serviceEpoch, controllerEpoch: recovery.controllerEpoch, controllerKey: recovery.controllerKey)
    }
    private static func census(_ state: HostStorageIntents.State, identity: Wire.Identity,
                               provenance: String) throws -> [IntentReference] {
        guard state.schema == 2, state.store == identity.store, state.revision > 0,
              state.intents.count <= HostStorageIntents.maximumIntents else { throw Failure.invalid }
        // Deliberately conservative: ALL slots, even terminal, count. Thus original,
        // predecessor, superseded and replacementRecovery contexts all survive.
        let references = try state.intents.map { id, intent -> IntentReference in
            guard id == intent.id, intent.store == identity.store else { throw Failure.invalid }
            return IntentReference(id: id, version: intent.version, original: context(intent), recovery: intent.replacementRecovery,
                predecessor: intent.predecessor, successor: intent.successor, superseded: intent.supersededSuccessors ?? [])
        }.sorted { $0.id < $1.id }
        try validateReferences(references, provenance: provenance)
        return references
    }
    private static func validateReferences(_ references: [IntentReference], provenance: String) throws {
        guard references.count <= HostStorageIntents.maximumIntents,
              references.map(\.id) == references.map(\.id).sorted(),
              Set(references.map(\.id)).count == references.count,
              try encode(references).count <= maximumReferenceBytes else { throw Failure.invalid }
        let byID = Dictionary(uniqueKeysWithValues: references.map { ($0.id, $0) })
        for ref in references {
            try uuid(ref.id); try validate(ref.original)
            guard ref.version > 0, ref.superseded.count <= HostStorageIntents.maximumIntents,
                  Set(ref.superseded).count == ref.superseded.count else { throw Failure.invalid }
            if let recovery = ref.recovery {
                try validate(context(recovery))
                guard recovery.provenanceReference == provenance, ref.predecessor != nil else { throw Failure.invalid }
                if let worker = recovery.workerHistoryReference { try digest(worker) }
            }
            if let predecessor = ref.predecessor {
                guard let old = byID[predecessor], old.successor == ref.id || old.superseded.contains(ref.id) else { throw Failure.unknownContext }
            }
            for child in ref.superseded + (ref.successor.map { [$0] } ?? []) {
                guard byID[child]?.predecessor == ref.id, child != ref.id else { throw Failure.unknownContext }
            }
            var seen: Set<String> = [ref.id], ancestor = ref.predecessor
            while let id = ancestor {
                guard seen.insert(id).inserted, let old = byID[id] else { throw Failure.invalid }
                ancestor = old.predecessor
            }
        }
    }
    private static func required(_ state: Metadata, includingColdAudit: Bool = true) throws -> (Set<Context>, Set<String>) {
        var contexts = Set(state.references.map(\.original)), links = Set<String>()
        if let current = state.currentContext { contexts.insert(current) }
        if includingColdAudit, let cold = state.latestCold {
            contexts.insert(cold.predecessor.context)
            contexts.insert(try controllerContext(coldController(cold)))
            if let resolved = cold.deadPredecessor { contexts.insert(resolved.anchor.context) }
        }
        if includingColdAudit, let resolved = state.resolvedDeadCold {
            contexts.insert(resolved.anchor.context)
            contexts.insert(try deadColdHistorical(resolved).context)
        }
        if let latest = state.latestServiceChange { links.insert(try latest.reference) }
        for ref in state.references {
            if let recovery = ref.recovery {
                contexts.insert(context(recovery))
                if let link = recovery.workerHistoryReference { links.insert(link) }
            }
        }
        for reference in links {
            guard let link = try state.serviceLinks.first(where: { try $0.reference == reference }) else { throw Failure.unknownContext }
            contexts.insert(link.predecessor); contexts.insert(link.successor)
        }
        // Merely knowing an E/C/key tuple is not sufficient to invent its evidence.
        guard contexts.isSubset(of: Set(state.contexts.map(\.context))) else { throw Failure.unknownContext }
        for ref in state.references {
            if let recovery = ref.recovery, let reference = recovery.workerHistoryReference {
                guard let link = try state.serviceLinks.first(where: { try $0.reference == reference }),
                      link.predecessor == context(recovery), link.successor == ref.original,
                      let predecessor = state.references.first(where: { $0.id == ref.predecessor }),
                      predecessor.original == link.predecessor else { throw Failure.unknownContext }
            }
        }
        return (contexts, links)
    }
    /// Exact metadata-retention closure, including cold audit endpoints; public data only.
    static func requiredContexts(_ state: Metadata) throws -> Set<Context> {
        try validate(state)
        return try required(state).0
    }
    /// Settlement needs the complete intent/link census, not cold-only audit history.
    /// Keep physical validation exact; excluding an audit-only context grants it no
    /// authority. A cold endpoint referenced by ANY intent/link remains required.
    static func recoveryContexts(_ state: Metadata) throws -> Set<Context> {
        try validate(state)
        return try required(state, includingColdAudit: false).0
    }
    private static func retainReferencedContexts(_ state: inout Metadata) throws {
        let (contexts, links) = try required(state)
        state.contexts = state.contexts.filter { contexts.contains($0.context) }
        state.serviceLinks = try state.serviceLinks.filter { try links.contains($0.reference) }
    }
    private static func controllerContext(_ completed: Completed) throws -> Context {
        let grant = completed.original.signed.grant
        guard grant.operation != .retire, grant.expectedEpoch < UInt64.max else { throw Failure.invalid }
        return Context(serviceEpoch: completed.directResult.serviceEpoch, controllerEpoch: grant.expectedEpoch + 1, controllerKey: grant.newKey)
    }
    private static func validate(_ context: Context) throws {
        try uuid(context.serviceEpoch); try digest(context.controllerKey)
        guard context.controllerEpoch > 0 else { throw Failure.invalid }
    }
    private static func validate(_ link: ServiceChange) throws {
        try uuid(link.operationID); try validate(link.predecessor); try validate(link.successor)
        guard link.revision > 0, link.predecessor.serviceEpoch != link.successor.serviceEpoch,
              link.predecessor.controllerEpoch == link.successor.controllerEpoch,
              link.predecessor.controllerKey == link.successor.controllerKey else { throw Failure.invalid }
    }
    private static func validate(_ context: GrantContext, in state: Metadata) throws {
        try context.signed.validate(); try uuid(context.requestID)
        if let service = context.serviceEpoch {
            try uuid(service)
        } else {
            guard context.signed.grant.operation == .initialize else { throw Failure.invalid }
        }
        try uuid(context.recipient.incarnation)
        let key = try StorageIdentity.Ed25519SPKI(rawPublicKey: context.recipient.publicKey)
        let root = try StorageIdentity.RootPublicKey(publicData: state.rootPublicKey)
        guard context.signed.isValidSignature(using: root), context.signed.grant.identity == state.identity,
              context.signed.grant.newKey == key.fingerprint.rawValue, key.fingerprint != root.fingerprint,
              context.recipient.childPID > 0,
              context.recipient.daemonUniqueID > 0, context.recipient.childUniqueID > 0,
              context.recipient.daemonUniqueID != context.recipient.childUniqueID else { throw Failure.invalid }
    }
    private static func match(_ receipt: Wire.Receipt, _ pending: GrantContext) throws {
        try receipt.validate()
        guard receipt.grant == pending.signed.grant,
              pending.serviceEpoch == nil || receipt.serviceEpoch == pending.serviceEpoch else { throw Failure.invalid }
    }
    /// ROOT may return a different freshly proven nonce for the same durable result.
    /// Keep the first recorded receipt instead of rewriting audit data on every retry.
    private static func sameResult(_ lhs: Wire.Receipt, _ rhs: Wire.Receipt) throws -> Bool {
        try lhs.validate(); try rhs.validate()
        return lhs.grant == rhs.grant && lhs.serviceEpoch == rhs.serviceEpoch && lhs.revision == rhs.revision
    }
    static func validate(_ state: Metadata) throws {
        try state.identity.validate(); try digest(state.provenanceReference)
        _ = try StorageIdentity.RootPublicKey(publicData: state.rootPublicKey)
        guard state.version == Wire.version, state.revision > 0,
              state.contexts.count <= maximumContexts, state.serviceLinks.count <= maximumLinks,
              (state.current == nil) == (state.currentContext == nil),
              (state.latestServiceRequest == nil) == (state.latestServiceConfirmation == nil),
              Set(state.contexts.map(\.context)).count == state.contexts.count else { throw Failure.invalid }
        try validateReferences(state.references, provenance: state.provenanceReference)
        guard state.references.isEmpty || state.intentRevision > 0 else { throw Failure.invalid }
        if let resolved = state.resolvedDeadCold {
            try validate(resolved, in: state)
            guard state.current == resolved.anchor.controller, state.currentContext == resolved.anchor.context,
                  state.currentService == resolved.anchorService,
                  state.pending == nil, state.pendingTakeover == nil, state.pendingService == nil,
                  state.handoffRetry == nil, state.sealed == nil, state.terminal == nil,
                  state.contexts.contains(resolved.anchor),
                  state.contexts.contains(try deadColdHistorical(resolved)) else { throw Failure.invalid }
        }
        if let pending = state.pendingCold {
            guard state.pending == nil, state.pendingTakeover == nil, state.pendingService == nil,
                  state.sealed == nil, state.terminal == nil,
                  pending.request.prepare.operationID != state.latestCold?.request.prepare.operationID else { throw Failure.invalid }
            let predecessor = try coldPredecessor(in: state), service = try coldPredecessorService(in: state)
            try validateColdRequest(pending.request, predecessor: predecessor.controller, service: service, in: state)
            if let prepared = pending.prepared {
                try prepared.validate(for: pending.request.prepare)
                guard prepared.recoveryBridge == state.resolvedDeadCold?.value else { throw Failure.invalid }
            } else if pending.bootAttempted { throw Failure.invalid }
            if let request = pending.resolutionRequest {
                guard state.resolvedDeadCold == nil else { throw Failure.invalid }
                try validate(request, for: pending, in: state)
            }
        }
        if let cold = state.latestCold {
            try validate(cold, in: state)
            let controller = coldController(cold), successor = try controllerContext(controller)
            guard state.contexts.contains(cold.predecessor),
                  state.contexts.contains(where: { $0.context == successor && $0.controller == controller }) else {
                throw Failure.invalid
            }
        }
        if let service = state.currentService {
            try validate(service, in: state)
            if state.latestServiceConfirmation == nil {
                guard service.context.serviceEpoch == state.current?.directResult.serviceEpoch,
                      service.openRevision <= (state.current?.directResult.revision ?? 0) else { throw Failure.invalid }
            }
        } else {
            guard state.pendingService == nil, state.latestServiceConfirmation == nil,
                  state.latestServiceChange == nil else { throw Failure.invalid }
        }
        if let observation = state.observedWorker { try validate(observation, in: state) }
        if let retry = state.handoffRetry { try validate(retry, in: state) }
        if let retry = state.adoptionRetry {
            try retry.status.validate(); try retry.request.validate()
            try uuid(retry.prepareRequestID); try uuid(retry.completeRequestID)
            guard retry.prepareRequestID != retry.completeRequestID,
                  retry.request.origin == retry.status.origin,
                  retry.request.origin.rootPublicKey == state.rootPublicKey,
                  try Wire.Identity(binding: retry.request.origin.binding.value(), generation: state.identity.generation) == state.identity,
                  retry.request.expectedEpoch == retry.status.allocatedEpoch,
                  retry.request.superseded == (try retry.status.pending?.fenceIdentity) else { throw Failure.invalid }
        }
        if state.nativeReplacementAttempted != nil {
            guard state.nativeReplacementAttempted == true, state.serviceReplacement != nil else { throw Failure.invalid }
        }
        if let replacement = state.serviceReplacement {
            guard let pending = state.pendingService ?? state.latestServiceRequest else { throw Failure.invalid }
            try validateReplacement(replacement, pending: pending, in: state)
        }
        if let request = state.pendingTakeover { try validate(request, in: state) }
        if let pending = state.pendingService {
            guard state.pending == nil, state.sealed == nil, state.terminal == nil else { throw Failure.invalid }
            try validate(pending, in: state)
        }
        if let confirmation = state.latestServiceConfirmation {
            try confirmation.validate()
            guard let request = state.latestServiceRequest, request.request == confirmation.request else { throw Failure.invalid }
            try validateServiceRequest(request, in: state)
            let predecessor = confirmation.request.predecessor
            guard confirmation.successor == state.currentService,
                  confirmation.successor.openRevision > (state.current?.directResult.revision ?? 0),
                  serviceChange(confirmation) == state.latestServiceChange,
                  let historical = state.contexts.first(where: { $0.context == context(predecessor.context) }),
                  historical.controller == state.current else { throw Failure.invalid }
            if let result = historical.serviceResult {
                guard predecessor.openRevision == result.revision else { throw Failure.invalid }
            } else {
                guard predecessor.openRevision <= historical.controller.directResult.revision else { throw Failure.invalid }
            }
        } else if state.latestServiceChange != nil { throw Failure.invalid }
        if let current = state.current, let live = state.currentContext {
            try validate(current.original, in: state); try match(current.directResult, current.original)
            let base = try controllerContext(current)
            guard base.controllerEpoch == live.controllerEpoch, base.controllerKey == live.controllerKey,
                  let historical = state.contexts.first(where: { $0.context == live }), historical.controller == current,
                  historical.serviceResult == state.latestServiceChange else { throw Failure.invalid }
        } else {
            guard state.pending?.signed.grant.operation == .initialize, state.contexts.isEmpty,
                  state.serviceLinks.isEmpty, state.latestServiceChange == nil else { throw Failure.invalid }
        }
        if let pending = state.pending {
            try validate(pending, in: state)
            if let current = state.current, let live = state.currentContext {
                let grant = pending.signed.grant
                guard grant.operation != .initialize, grant.serial > current.original.signed.grant.serial,
                      grant.id != current.original.signed.grant.id, grant.expectedEpoch == live.controllerEpoch else { throw Failure.invalid }
                if grant.operation == .retire {
                    guard pending.recipient == current.original.recipient, grant.newKey == live.controllerKey,
                          pending.serviceEpoch == live.serviceEpoch else { throw Failure.invalid }
                } else {
                    guard grant.newKey != live.controllerKey,
                          pending.recipient.incarnation != current.original.recipient.incarnation else { throw Failure.invalid }
                }
            }
        }
        for old in state.contexts {
            try validate(old.context); try validate(old.controller.original, in: state)
            try match(old.controller.directResult, old.controller.original)
            let base = try controllerContext(old.controller)
            if let service = old.serviceResult {
                try validate(service)
                guard service.successor == old.context, service.revision > old.controller.directResult.revision else { throw Failure.invalid }
            } else {
                guard old.context == base else { throw Failure.invalid }
            }
            guard old.context.controllerEpoch == base.controllerEpoch, old.context.controllerKey == base.controllerKey else { throw Failure.invalid }
            if let resolved = state.resolvedDeadCold, old == (try deadColdHistorical(resolved)) {
                // The one disjoint dead successor is intentionally ahead of C11;
                // it never replaces current or waives bounds for other history.
                guard old.context.controllerEpoch == resolved.anchor.context.controllerEpoch + 1,
                      old.controller.original.signed.grant == resolved.value.successor.grant else { throw Failure.invalid }
            } else {
                guard old.context.controllerEpoch <= (state.currentContext?.controllerEpoch ?? 0),
                      old.controller.original.signed.grant.serial <= (state.current?.original.signed.grant.serial ?? 0) else { throw Failure.invalid }
            }
        }
        var linkIDs = Set<String>()
        for link in state.serviceLinks {
            try validate(link)
            guard try linkIDs.insert(link.reference).inserted,
                  state.contexts.contains(where: { $0.context == link.predecessor }),
                  state.contexts.contains(where: { $0.context == link.successor }) else { throw Failure.invalid }
        }
        if let latest = state.latestServiceChange {
            guard state.serviceLinks.contains(latest), latest.successor == state.currentContext else { throw Failure.invalid }
        }
        if let seal = state.sealed {
            guard let pending = state.pending, pending.signed.grant.operation == .retire,
                  seal.revision > (state.current?.directResult.revision ?? 0),
                  seal.revision > (state.latestServiceChange?.revision ?? 0) else { throw Failure.invalid }
            try match(seal, pending)
        }
        if let terminal = state.terminal {
            guard let seal = state.sealed, try sameResult(terminal, seal) else { throw Failure.invalid }
        }
        // Exact, not superset: unreferenced historical contexts/links are never
        // retained, so extra (possibly forged) history is structurally invalid.
        let (contexts, links) = try required(state)
        guard Set(state.contexts.map(\.context)) == contexts,
              Set(try state.serviceLinks.map { try $0.reference }) == links else { throw Failure.invalid }
        guard try encode(state).count <= maximumBytes - reservation(state) else { throw Failure.capacity }
    }
    static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(value)
        guard !bytes.isEmpty, bytes.count <= maximumBytes else { throw Failure.capacity }
        return bytes
    }
    static func decode(_ bytes: Data) throws -> Metadata {
        let state: Metadata = try canonical(bytes)
        try validate(state)
        return state // Never compact, rewrite or construct authority at load.
    }
    private static func canonical<T: Codable>(_ bytes: Data) throws -> T {
        guard !bytes.isEmpty, bytes.count <= maximumBytes else { throw Failure.invalid }
        let result = try JSONDecoder().decode(T.self, from: bytes)
        guard try encode(result) == bytes else { throw Failure.invalid }
        return result
    }
    private static func uuid(_ value: String) throws { _ = try StorageIdentity.RequestID(value) }
    private static func digest(_ value: String) throws { _ = try StorageIdentity.SPKISHA256(value) }

    static let manifestVersion = "storage-host-owner.v3"
    struct Manifest: Codable, Equatable {
        let version: String
        let identity: Wire.Identity
        let rootPublicKey: Data
        let provenanceReference: String
        let root: PersistentFileIdentity
        let directory: PersistentFileIdentity
        let lease: PersistentFileIdentity
        let backing: PersistentFileIdentity
        let bytes: UInt64
        let ext4UUID: String
    }
    private let root: PersistentStateDirectory
    private let directory: PersistentStateDirectory
    private let lease: Int32
    private let backing: Int32
    private let manifest: Manifest
    private let manifestBytes: Data
    private let commits: HostStorageIntentCommit
    private var state: Metadata
    private var poisoned = false
    private var busy = false

    /// Descriptor-root only. mkdir(exclusive) refuses ANY old/partial v1 or v2
    /// owner, including an empty existing directory. No versioned sibling bypass.
    static func fresh(in root: PersistentStateDirectory, backingDescriptor: Int32, binding: StorageIdentity.StoreBinding,
                      rootPublicKey: Data, provenanceReference: String, initialize: GrantContext,
                      commitHook: HostStorageIntentCommit.Hook? = nil) throws -> ManagedStorageLifecycleCheckpoint {
        let initial = try baseline(identity: initialize.signed.grant.identity, rootPublicKey: rootPublicKey,
            provenanceReference: provenanceReference, initialize: initialize)
        return try create(in: root, backingDescriptor: backingDescriptor, binding: binding, initial: initial,
            rootPublicKey: rootPublicKey, provenanceReference: provenanceReference, commitHook: commitHook)
    }
    static func createResumed(in root: PersistentStateDirectory, backingDescriptor: Int32, binding: StorageIdentity.StoreBinding,
                              initial: Metadata) throws -> ManagedStorageLifecycleCheckpoint {
        try validate(initial)
        guard initial.current?.original.signed.grant.operation == .takeover,
              initial.currentContext?.controllerEpoch == 2, initial.references.isEmpty else { throw Failure.invalid }
        return try create(in: root, backingDescriptor: backingDescriptor, binding: binding, initial: initial,
            rootPublicKey: initial.rootPublicKey, provenanceReference: initial.provenanceReference, commitHook: nil)
    }
    private static func create(in root: PersistentStateDirectory, backingDescriptor: Int32, binding: StorageIdentity.StoreBinding,
                               initial: Metadata, rootPublicKey: Data, provenanceReference: String,
                               commitHook: HostStorageIntentCommit.Hook?) throws -> ManagedStorageLifecycleCheckpoint {
        guard initial.identity == (try Wire.Identity(binding: binding, generation: initial.identity.generation)) else { throw Failure.invalid }
        try privateDescriptor(root.descriptor, directory: true)
        // A fresh owner must precede creation of its intent journal; never adopt
        // old v1 operations merely because the owner directory is absent.
        guard try root.entryMetadata(named: "managed-storage") == nil else { throw Failure.invalid }
        let owned = try duplicateBacking(backingDescriptor)
        var transferred = false, lease: Int32 = -1
        defer { if !transferred { Darwin.close(owned); if lease >= 0 { Darwin.close(lease) } } }
        guard try rootIdentity(root.identity) == binding.root,
              try rootIdentity(PersistentFileIdentity.capture(descriptor: owned)) == binding.backing.identity else { throw Failure.invalid }
        var info = stat()
        guard fstat(owned, &info) == 0, UInt64(info.st_size) == binding.backing.size else { throw Failure.invalid }
        let directory = try root.createDirectory(named: directoryName)
        lease = try acquire(directory, create: true)
        let manifest = Manifest(version: manifestVersion, identity: initial.identity, rootPublicKey: rootPublicKey,
            provenanceReference: provenanceReference, root: root.identity, directory: directory.identity,
            lease: try PersistentFileIdentity.capture(descriptor: lease), backing: try PersistentFileIdentity.capture(descriptor: owned),
            bytes: binding.backing.size, ext4UUID: binding.expectedExt4UUID.rawValue)
        let bytes = try encode(manifest)
        let commits = HostStorageIntentCommit(directory: directory, manifest: bytes, hook: commitHook)
        do {
            try directory.writeExclusiveRegularFile(named: "manifest.json", data: bytes)
            try directory.writeExclusiveRegularFile(named: "state.json", data: encode(initial))
        } catch { commits.poison(); throw error }
        let owner = ManagedStorageLifecycleCheckpoint(root: root, directory: directory, lease: lease, backing: owned,
            manifest: manifest, manifestBytes: bytes, state: initial, commits: commits)
        transferred = true
        try owner.healthy()
        return owner
    }
    /// Format inspection only. Never acquires leases, repairs commits, or writes.
    static func inspect(in root: PersistentStateDirectory, backingDescriptor: Int32,
                        allowRootPermissionRepair: Bool = false) throws -> Manifest {
        let directory = try root.openDirectory(named: directoryName)
        guard Set(try directory.entryNames()) == ["lease", "manifest.json", "state.json"] else { throw Failure.repairRequired }
        let manifest = try readManifest(in: root)
        let state = try decode(HostStorageIntentCommit.readPrivateFile(in: directory, named: "state.json", maximumBytes: maximumBytes))
        guard manifest.root == root.identity, manifest.directory == directory.identity,
              manifest.lease == (try directory.regularFileIdentity(named: "lease", expectedSize: 0)),
              manifest.backing == (try PersistentFileIdentity.capture(descriptor: backingDescriptor)),
              state.identity == manifest.identity, state.rootPublicKey == manifest.rootPublicKey,
              state.provenanceReference == manifest.provenanceReference else { throw Failure.invalid }
        _ = try HostStorageIntentCommit.readPrivateFile(in: directory, named: "lease", maximumBytes: 0)
        if allowRootPermissionRepair {
            // Read-only classification before the locked startup chmod. This
            // admits only removable read/search bits, never writable or ACL roots;
            // actual open/adoption and every ongoing check still require privacy.
            var rootInfo = stat()
            guard fstat(root.descriptor, &rootInfo) == 0,
                  rootInfo.st_mode & S_IFMT == S_IFDIR, rootInfo.st_uid == geteuid(),
                  rootInfo.st_mode & 0o7777 & ~mode_t(0o055) == 0o700 else { throw Failure.invalid }
            try RawDiskJournalDirectory.requireNoACL(root.descriptor)
        } else {
            try privateDescriptor(root.descriptor, directory: true)
        }
        try privateDescriptor(directory.descriptor, directory: true)
        try privateDescriptor(backingDescriptor, directory: false)
        var info = stat()
        guard fstat(backingDescriptor, &info) == 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
        guard info.st_size > 0, UInt64(info.st_size) == manifest.bytes else { throw Failure.invalid }
        let binding = StorageIdentity.StoreBinding(storeID: try .init(manifest.identity.store), root: try rootIdentity(manifest.root),
            backing: try .init(identity: rootIdentity(manifest.backing), size: manifest.bytes), expectedExt4UUID: try .init(manifest.ext4UUID))
        guard try Wire.Identity(binding: binding, generation: manifest.identity.generation) == manifest.identity,
              try root.entryMetadata(named: directoryName)?.identity == directory.identity else { throw Failure.invalid }
        return manifest
    }

    static func open(in root: PersistentStateDirectory, backingDescriptor: Int32, identity: Wire.Identity,
                     rootPublicKey: Data, provenanceReference: String,
                     commitHook: HostStorageIntentCommit.Hook? = nil) throws -> ManagedStorageLifecycleCheckpoint {
        let directory = try root.openDirectory(named: directoryName)
        let lease = try acquire(directory, create: false)
        var transferred = false, owned: Int32 = -1
        defer { if !transferred { Darwin.close(lease); if owned >= 0 { Darwin.close(owned) } } }
        owned = try duplicateBacking(backingDescriptor)
        // Closed census: no marker/candidate recovery or load-time cleanup.
        guard Set(try directory.entryNames()) == ["lease", "manifest.json", "state.json"] else { throw Failure.repairRequired }
        let bytes = try HostStorageIntentCommit.readPrivateFile(in: directory, named: "manifest.json", maximumBytes: maximumBytes)
        let manifest: Manifest = try canonical(bytes)
        guard manifest.version == manifestVersion, manifest.identity == identity, manifest.rootPublicKey == rootPublicKey,
              manifest.provenanceReference == provenanceReference else { throw Failure.invalid }
        let state = try decode(HostStorageIntentCommit.readPrivateFile(in: directory, named: "state.json", maximumBytes: maximumBytes))
        guard state.identity == identity, state.rootPublicKey == rootPublicKey,
              state.provenanceReference == provenanceReference else { throw Failure.invalid }
        let owner = ManagedStorageLifecycleCheckpoint(root: root, directory: directory, lease: lease, backing: owned,
            manifest: manifest, manifestBytes: bytes, state: state,
            commits: HostStorageIntentCommit(directory: directory, manifest: bytes, hook: commitHook))
        transferred = true
        try owner.healthy()
        return owner
    }
    private init(root: PersistentStateDirectory, directory: PersistentStateDirectory, lease: Int32, backing: Int32,
                 manifest: Manifest, manifestBytes: Data, state: Metadata, commits: HostStorageIntentCommit) {
        self.root = root; self.directory = directory; self.lease = lease; self.backing = backing
        self.manifest = manifest; self.manifestBytes = manifestBytes; self.state = state; self.commits = commits
    }
    deinit { Darwin.close(lease); Darwin.close(backing) }
    func snapshot() throws -> Metadata { try healthy(); return state }

    /// Synchronous MainActor transaction. readIntents MUST read the actual journal
    /// (e.g. journal.snapshot), not return a cached copy. Equality checks the entire
    /// State, including revision, per-intent versions and all public recovery links.
    /// No await, authentication callback or authority-producing return value exists.
    func persist(_ change: Change, intents: HostStorageIntents.State,
                 readIntents: () throws -> HostStorageIntents.State) throws {
        guard !busy else { throw Failure.blocked }
        busy = true; defer { busy = false }
        try healthy()
        guard try readIntents() == intents else { throw Failure.staleIntents }
        let next = try Self.applying(change, to: state, intents: intents)
        guard try readIntents() == intents else { throw Failure.staleIntents }
        if next == state { return }
        do {
            try commits.commit(prior: Self.encode(state), priorRevision: state.revision,
                next: Self.encode(next), nextRevision: next.revision)
            state = next
        } catch { poisoned = true; commits.poison(); throw error }
    }
    private func healthy() throws {
        guard !poisoned, root.pathStillNamesThisDirectory(), directory.pathStillNamesThisDirectory(),
              manifest.root == root.identity, manifest.directory == directory.identity,
              manifest.lease == (try PersistentFileIdentity.capture(descriptor: lease)),
              manifest.lease == (try directory.regularFileIdentity(named: "lease", expectedSize: 0)),
              manifest.backing == (try PersistentFileIdentity.capture(descriptor: backing)),
              Set(try directory.entryNames()) == ["lease", "manifest.json", "state.json"] else { throw Failure.repairRequired }
        try Self.privateDescriptor(root.descriptor, directory: true)
        try Self.privateDescriptor(directory.descriptor, directory: true)
        try Self.privateDescriptor(lease, directory: false)
        try Self.privateDescriptor(backing, directory: false)
        var info = stat()
        guard fstat(backing, &info) == 0, info.st_size > 0, UInt64(info.st_size) == manifest.bytes else { throw Failure.repairRequired }
        let binding = StorageIdentity.StoreBinding(storeID: try .init(manifest.identity.store), root: try Self.rootIdentity(manifest.root),
            backing: try .init(identity: Self.rootIdentity(manifest.backing), size: manifest.bytes), expectedExt4UUID: try .init(manifest.ext4UUID))
        guard try Wire.Identity(binding: binding, generation: manifest.identity.generation) == manifest.identity,
              try HostStorageIntentCommit.readPrivateFile(in: directory, named: "manifest.json", maximumBytes: Self.maximumBytes) == manifestBytes,
              try HostStorageIntentCommit.readPrivateFile(in: directory, named: "state.json", maximumBytes: Self.maximumBytes) == Self.encode(state) else { throw Failure.repairRequired }
    }
    private static func rootIdentity(_ identity: PersistentFileIdentity) throws -> StorageIdentity.RootIdentity {
        guard let volume = identity.volumeUUID else { throw Failure.invalid }
        return try .init(volumeUUID: .init(volume.uuidString.lowercased()), inode: identity.inode)
    }
    private static func privateDescriptor(_ fd: Int32, directory: Bool) throws {
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG),
              info.st_uid == geteuid(), info.st_mode & 0o7077 == 0,
              directory || info.st_nlink == 1 else { throw Failure.invalid }
    }
    private static func duplicateBacking(_ fd: Int32) throws -> Int32 {
        let owned = fcntl(fd, F_DUPFD_CLOEXEC, 0)
        guard owned >= 0 else { throw Failure.invalid }
        do { try privateDescriptor(owned, directory: false); return owned }
        catch { Darwin.close(owned); throw error }
    }
    private static func acquire(_ directory: PersistentStateDirectory, create: Bool) throws -> Int32 {
        try privateDescriptor(directory.descriptor, directory: true)
        let fd = openat(directory.descriptor, "lease", O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | (create ? O_CREAT | O_EXCL : 0), 0o600)
        guard fd >= 0 else { throw Failure.repairRequired }
        do {
            try privateDescriptor(fd, directory: false)
            let identity = try PersistentFileIdentity.capture(descriptor: fd)
            guard flock(fd, LOCK_EX | LOCK_NB) == 0,
                  identity == (try directory.regularFileIdentity(named: "lease", expectedSize: 0)) else { throw Failure.blocked }
            if create { guard fsync(fd) == 0 else { throw Failure.repairRequired }; try directory.synchronize() }
            return fd
        } catch { Darwin.close(fd); throw error }
    }
}
#endif

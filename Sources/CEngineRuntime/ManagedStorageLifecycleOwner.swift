#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Synchronization

/// Process-local authority; no decoder, DTO initializer, or injectable transport.
/// Only the concrete native ROOT client below can mint this after authenticated
/// completion and an exact committed-status observation.
struct StorageLifecycleAdoptedConnectionAuthorization: Sendable {
    let status: StorageLifecycleAdoptionRootProtocol.Status
    let request: StorageLifecycleAdoptionProtocol.Request
    let policy: StorageLifecycleNativePolicy
    fileprivate init(status: StorageLifecycleAdoptionRootProtocol.Status,
                     request: StorageLifecycleAdoptionProtocol.Request, policy: StorageLifecycleNativePolicy) {
        self.status = status; self.request = request; self.policy = policy
    }
}

nonisolated extension StorageLifecycleRootClient {
    func completeAdoptionForConnection(_ envelope: StorageLifecycleAdoptionRootProtocol.Request,
                                      storeLock: CanonicalDataStoreLock, timeout: TimeInterval) throws
        -> (StorageLifecycleAdoptionRootProtocol.Reply, StorageLifecycleAdoptedConnectionAuthorization) {
        guard case .complete(let request) = envelope.body else { throw Failure(.invalidRequest) }
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        let reply = try adoptionRequest(envelope, storeLock: storeLock, timeout: timeout)
        guard case .completed(let fence) = reply.body, try fence == request.fenceIdentity else { throw Failure(.unauthorized) }
        let remaining = deadline - ProcessInfo.processInfo.systemUptime
        guard remaining > 0 else { throw Failure(.unavailable) }
        // Never use the caller's saved/public status to confer native authority.
        let observed = try adoptionRequest(.init(requestID: .init(UUID().uuidString.lowercased()), body: .status),
            storeLock: storeLock, timeout: remaining)
        guard case .status(let status) = observed.body,
              status.origin == request.origin, status.latest == request, status.pending == nil,
              try status.committedEpoch == request.epoch else { throw Failure(.unauthorized) }
        return (reply, .init(status: status, request: request, policy: policy))
    }
}

/// UNTRUSTED metadata and owned IO only. A future daemon/shim private IPC adapter
/// must implement this; Ready, an FD, and a successful command are NOT capabilities.
/// configure must start the native service-proof responder before returning. ROOT
/// independently challenges that responder and the native child's TLS result.
protocol ManagedStorageLifecycleServiceTransport: Sendable {
    func configure(_ configuration: StorageLifecycleServiceBootProtocol.Configuration) async throws -> ManagedStorageLifecycleServiceReady
    func command(_ frame: StorageLifecycleServiceBootProtocol.Frame) async throws -> StorageLifecycleServiceBootProtocol.Frame
    /// Absolute DispatchTime uptime deadline, including queued IPC. Expired
    /// admission must send no bytes; implementations may shorten their own bound.
    func command(_ frame: StorageLifecycleServiceBootProtocol.Frame, deadlineNanoseconds: UInt64?) async throws -> StorageLifecycleServiceBootProtocol.Frame
    /// Each successful call transfers a new, exclusively owned connected handle.
    func connectLifecycle() async throws -> FileHandle
    func connectWorkload() async throws -> FileHandle
    /// Connected public attachment-CSR stream for exactly one certificate issue.
    func connectAttachmentCSR() async throws -> FileHandle
    /// Nonblocking and thread-safe; interrupt pending IPC and close owned streams.
    /// All operations must also enforce bounded monotonic IO deadlines.
    nonisolated func cancel()
}

extension ManagedStorageLifecycleServiceTransport {
    func command(_ frame: StorageLifecycleServiceBootProtocol.Frame, deadlineNanoseconds: UInt64?) async throws -> StorageLifecycleServiceBootProtocol.Frame {
        try Task.checkCancellation()
        guard let deadlineNanoseconds else { return try await command(frame) }
        guard DispatchTime.now().uptimeNanoseconds < deadlineNanoseconds else { throw AsyncTimeout.TimeoutError() }
        return try await withThrowingTaskGroup(of: StorageLifecycleServiceBootProtocol.Frame.self) { group in
            group.addTask {
                try Task.checkCancellation()
                guard DispatchTime.now().uptimeNanoseconds < deadlineNanoseconds else { throw AsyncTimeout.TimeoutError() }
                return try await self.command(frame)
            }
            group.addTask {
                let now = DispatchTime.now().uptimeNanoseconds
                if now < deadlineNanoseconds { try await Task.sleep(nanoseconds: deadlineNanoseconds - now) }
                try Task.checkCancellation()
                self.cancel() // Interrupt actual IO, not just publication of its reply.
                throw AsyncTimeout.TimeoutError()
            }
            defer { group.cancelAll() }
            guard let reply = try await group.next() else { throw AsyncTimeout.TimeoutError() }
            guard DispatchTime.now().uptimeNanoseconds < deadlineNanoseconds else { throw AsyncTimeout.TimeoutError() }
            return reply
        }
    }
}

/// Public DTO, deliberately not PrivateStorageLifecycleBootCoordinator.VerifiedBoot.
struct ManagedStorageLifecycleServiceReady: Equatable, Sendable {
    let binding: StorageLifecycleServiceBootProtocol.Binding
    let ready: StorageLifecycleServiceBootProtocol.Ready
}

/// HOST lifecycle orchestration; production startup composition is still pending.
/// Fresh provisioning and same-controller service changes retain durable retry
/// tuples. Live restart requires ROOT shim adoption before controller takeover.
/// No disk deletion, VerifiedStorageServiceBoot or ControllerRecovery is exported.
/// Production composition is INCOMPLETE until daemon/shim private IPC exists; this
/// owner plus metadata transport tests must not be called native end-to-end.
@MainActor final class ManagedStorageLifecycleOwner {
    typealias L = StorageLifecycleProtocol
    typealias Root = StorageLifecycleRootProtocol
    typealias Boot = StorageLifecycleServiceBootProtocol
    typealias Checkpoint = ManagedStorageLifecycleCheckpoint
    typealias Adoption = StorageLifecycleAdoptionProtocol
    typealias AdoptionRoot = StorageLifecycleAdoptionRootProtocol
    typealias ResumeRoot = StorageLifecycleResumeRootProtocol
    private var initialization: ManagedStorageInitialization?
    private var initializationAdmitted = false
    private var pendingInitializationAdmission: (marker: ManagedStorageInitialization, evidence: [String: Data])?
    private var resumeStatus: ResumeRoot.Status?
    typealias ColdRoot = StorageLifecycleColdRootProtocol
    typealias ColdShim = StorageLifecycleColdShimProtocol
    enum Failure: Error { case blocked, invalid, incomplete, repairRequired, system(Int32) }

    struct Preparation: Sendable {
        let rootPublicKey: StorageIdentity.RootPublicKey
        let greeting: StorageLifecycleChildProtocol.Greeting
    }
    private let rootDirectory: PersistentStateDirectory
    private let backing: FileHandle
    private let binding: StorageIdentity.StoreBinding
    private let provenance: String
    private let worker: Worker
    private var preparation: Preparation?
    private var recipient: Checkpoint.Recipient?
    private var checkpoint: Checkpoint?
    private var intents: HostStorageIntents?
    private var service: (any ManagedStorageLifecycleServiceTransport)?
    private var boot: ManagedStorageLifecycleServiceReady?
    private var bootAttempted = false
    private var retirementAttempted = false
    /// One Guest-mutating attempt per durable service-change operation. Uncertainty
    /// may only be resolved through ROOT, never by configuring another successor.
    private var serviceChangeAttempted: String?
    private var workloadConnected = false
    /// A workload fence is irreversible for this boot, even while private IO joins.
    private var fencedWorkloadBoot: ManagedStorageLifecycleServiceReady?
    /// Set only by an exact authenticated private worker-loss reply, never EOF/Wait.
    private var authenticatedWorkerLoss: ManagedStorageLifecycleServiceReady?
    private var busy = false
    /// In-flight workload IO; excludes lifecycle mutations while nonzero.
    private var workloadCalls = 0
    /// Retire owns only the child WORKLOAD lane, never private 4106 PREPARE/status IO.
    private var workloadRetireActive = false
    /// Only the read-only notifications/serviceStatus exchanges own this flag.
    private var serviceCommandActive = false
    /// Separate from read-only replacement admission and from child workload IO.
    private let prepareStorageCommands = PrepareCommandLane()
    /// Failed observations also consume this worker; a later worker gets a fresh attempt.
    private var originalConsumerWorkers: Set<String> = []
    private var originalConsumerSessionID: UUID?
    @MainActor private final class PrepareCommandLane {
        private(set) var active = false
        private var closed = false
        private var waiters: [CheckedContinuation<Void, Error>] = []
        func acquire() async throws {
            try Task.checkCancellation()
            guard !closed else { throw Failure.blocked }
            if active {
                guard waiters.count < 8 else { throw Failure.blocked }
                try await withCheckedThrowingContinuation { waiters.append($0) }
            } else { active = true }
            do { try Task.checkCancellation() } catch { release(); throw error }
        }
        func tryPoll() -> Bool {
            guard !closed, !active, waiters.isEmpty else { return false }
            active = true; return true
        }
        func release() {
            if !waiters.isEmpty { waiters.removeFirst().resume() }
            else { active = false }
        }
        func close() {
            closed = true
            let pending = waiters; waiters.removeAll()
            for waiter in pending { waiter.resume(throwing: Failure.blocked) }
        }
    }
    private var workloadLifecycle: ManagedVolumeLifecycleCoordinator?
    private var replacementTask: Task<ServiceReplacementMaintenance, Error>?
    private var replacementRetryable = false
    private var replacementTimeoutBoundary: RetryableReplacementTimeout?
    private var replacementAdmitted = false
    private struct ReplacementAttemptExpired: Error {}
    /// Process-local retry boundary, not decoded metadata or service authority.
    /// Construction is confined to the owner after its native attempt has joined.
    struct RetryableReplacementTimeout: Error, Sendable {
        let id = UUID()
        let request: StorageServiceTypes.ReplacementRequest
        fileprivate init(request: StorageServiceTypes.ReplacementRequest) { self.request = request }
    }
    #if DEBUG
    var replacementAttemptTimeoutForTesting: TimeInterval = 30
    var replacementAdmissionTimingForTesting: IsolatedTestSeam.RecoveryTiming?
    #endif

    func validateServiceReplacementRetry(_ request: StorageServiceTypes.ReplacementRequest) throws -> RetryableReplacementTimeout {
        try validateServiceReplacement(request)
        guard replacementIdentity != nil, replacementRetryable,
              let boundary = replacementTimeoutBoundary, boundary.request == request else { throw Failure.blocked }
        return boundary
    }
    /// Only the owner can mint the adapter's maintenance permission.
    struct MaintenanceCapability { fileprivate let owner: UUID }

    private var replacementIdentity: (id: UUID, operation: String, scope: StorageServiceTypes.Scope, now: UInt64, lifetime: UInt64)?
    /// Sealed only after recoverWorkload validates ROOT, Query and census proofs.
    struct RecoveryAuthorization {
        let current: ManagedStorageControlClient.Context
        let history: [Checkpoint.Context]
        let workerHistoryReference: String?
        fileprivate init(current: ManagedStorageControlClient.Context, history: [Checkpoint.Context], workerHistoryReference: String?) {
            self.current = current; self.history = history; self.workerHistoryReference = workerHistoryReference
        }
    }
    struct ReplacementRecoveryAuthorization {
        let current: ManagedStorageControlClient.Context
        let predecessor: Checkpoint.Context
        let reference: String
        fileprivate init(current: ManagedStorageControlClient.Context, predecessor: Checkpoint.Context, reference: String) {
            self.current = current; self.predecessor = predecessor; self.reference = reference
        }
    }
    struct ServiceReplacementMaintenance {
        fileprivate let owner: UUID
        let request: Boot.ReplacementRequest
        let lifecycle: ManagedVolumeLifecycleCoordinator
        fileprivate let context: ManagedStorageControlClient.Context
        let serviceScope: StorageServiceTypes.Scope
    }
    private var sequence: UInt64 = 0
    // Never replace semantic IDs or alter either frozen envelope after IO starts.
    private let keyRequest: Root.Request
    private let incarnation: String
    private var provisionRequests: (probe: Root.Request, attach: Root.Request)?
    /// Last attempted envelope, including lost replies before any physical baseline.
    /// In-memory diagnostics only, never crash-recovery authority.
    private(set) var attemptedProvision: Root.Request?
    private var retireRequest: Root.Request?
    private var completionRequests: [String: Root.Request] = [:]
    private var reclaimRequest: Root.Request?
    private var provisioned: L.SignedGrant?
    private var checkpointCommitHook: HostStorageIntentCommit.Hook?
    /// Opened from an existing v2 pair; only authenticated takeover establishes liveness.
    private var existing = false
    /// One Guest-mutating takeover attempt; uncertainty resolves only via ROOT complete.
    private var takeoverAttempted = false
    private var takeoverReconciled = false
    private var recoveredHandoff = false
    /// Minted ONLY by recoverWorkload after completed takeover + fresh Query + census.
    private var recoveryPermission: (context: ManagedStorageControlClient.Context,
                                     recovery: ManagedStorageControllerRecovery)?
    /// Pre-takeover context proven by a fresh ROOT live service result in THIS
    /// owner's takeover. Never read from (forgeable) checkpoint history.
    private var takeoverPredecessor: Checkpoint.Context?
    private struct PublicTakeoverSelection {
        let request: ManagedPrepareCompatibilityQueue.PublicTakeoverCapture
        let publish: (Data, String) throws -> Void
    }
    private var publicTakeoverRecovery: PublicTakeoverSelection?
    private var nativeAudit: ProcessAudit?
    private var adoptionRetry: Checkpoint.AdoptionRetry?
    private var adoptionLock: CanonicalDataStoreLock?
    private var adoptedShim: AdoptedShim?
    private var coldStatus: ColdRoot.Status?
    /// Never reconstructed from HOST metadata. Only this owner's authenticated
    /// complete response may attest the immediate cross-E predecessor.
    private struct FreshColdCompletion {
        let predecessor: Checkpoint.Context
        let completion: ColdRoot.Completed
    }
    private var freshColdCompletion: FreshColdCompletion?
    private var replacementRecoveryRequest: Checkpoint.PendingService?
    /// Process-local only: minted by the new adopted ROOT proof, never HOST history.
    private var freshReplacementCompletion: L.ServiceChangeConfirmation?
    /// Public projections plus a separate native-only connection authorization.
    /// Isolated transport tests deliberately never receive that authorization.
    struct AdoptedShim: Sendable {
        let status: AdoptionRoot.Status
        let request: Adoption.Request
        let connectionAuthorization: StorageLifecycleAdoptedConnectionAuthorization?
    }
    private struct ProcessAudit: Sendable {
        let daemonAudit: Data
        let daemonUniqueID: UInt64
        let childAudit: Data
        let childUniqueID: UInt64
        func matches(_ request: Adoption.Request) -> Bool {
            request.daemonAudit == daemonAudit && request.daemonUniqueID == daemonUniqueID
                && request.controllerAudit == childAudit && request.controllerUniqueID == childUniqueID
        }
    }

    enum StoreFormat: Equatable, Sendable { case fresh, initialization, existingV2 }
    struct UnsupportedStoreFormat: Error, Equatable, CustomStringConvertible, LocalizedError {
        var description: String { "unsupported storage format; data preserved" }
        var errorDescription: String? { description }
    }
    /// Transient/IO failure while classifying (EIO, EACCES, EMFILE, ...). Retryable;
    /// says nothing about the store format.
    struct StoreUnavailable: Error, Equatable, CustomStringConvertible, LocalizedError {
        let code: Int32
        var description: String { "storage state temporarily unreadable (errno \(code)); data preserved" }
        var errorDescription: String? { description }
    }
    /// Read-only. Any partial, v1, unknown or undecodable owner state is refused
    /// without modifying bytes; there is no migration or cleanup path. IO errors
    /// other than structural absence/type mismatches propagate as StoreUnavailable.
    static func classify(root: PersistentStateDirectory, allowRootPermissionRepair: Bool = false) throws -> StoreFormat {
        do {
            // Reopen without following symlinks; a detached/replaced root is not
            // a fresh store. Do not use pathStillNamesThisDirectory: it hides IO errors.
            guard try PersistentStateDirectory.open(root.url).identity == root.identity else { throw UnsupportedStoreFormat() }
            guard try root.entryMetadata(named: "storage-intents") == nil else { throw UnsupportedStoreFormat() }
            let infrastructure = try root.openDirectoryIfPresent(named: "infrastructure")
            if let infrastructure {
                guard try infrastructure.entryMetadata(named: "volume-token-secret") == nil,
                      try root.entryMetadata(named: "infrastructure")?.identity == infrastructure.identity else {
                    throw UnsupportedStoreFormat()
                }
            }
            // The retired selector is never interpreted or rewritten. A store
            // created through an older selectable-storage startup is unsupported.
            guard try root.entryMetadata(named: "shared-storage-mode.json") == nil else {
                throw UnsupportedStoreFormat()
            }
            func classified(_ format: StoreFormat) throws -> StoreFormat {
                if format != .fresh {
                    guard let infrastructure else { throw UnsupportedStoreFormat() }
                    let disk = try infrastructure.openRegularFile(named: "volumes.ext4", access: .readOnly)
                    defer { try? disk.handle.close() }
                    let marker = try root.entryMetadata(named: ManagedStorageInitialization.directoryName) == nil
                        ? nil : ManagedStorageInitialization.open(in: root)
                    let manifest = try root.entryMetadata(named: Checkpoint.directoryName) == nil
                        ? nil : Checkpoint.inspect(in: root, backingDescriptor: disk.handle.fileDescriptor,
                            allowRootPermissionRepair: allowRootPermissionRepair)
                    let bytes: UInt64, ext4UUID: String, store: String, provenance: String
                    if let marker {
                        let binding = try marker.manifest.binding.value()
                        guard binding.backing.identity.inode == disk.identity.inode,
                              binding.backing.identity.volumeUUID.rawValue == disk.identity.volumeUUID?.uuidString.lowercased(),
                              try infrastructure.regularFileIdentity(named: "volumes.ext4", expectedIdentity: disk.identity,
                                expectedSize: binding.backing.size) == disk.identity else { throw UnsupportedStoreFormat() }
                        if let manifest {
                            guard manifest.identity == (try L.Identity(binding: binding, generation: manifest.identity.generation)),
                                  manifest.provenanceReference == marker.manifest.provenance else { throw UnsupportedStoreFormat() }
                        }
                        bytes = binding.backing.size; ext4UUID = binding.expectedExt4UUID.rawValue
                        store = binding.storeID.rawValue; provenance = marker.manifest.provenance
                    } else if let manifest {
                        bytes = manifest.bytes; ext4UUID = manifest.ext4UUID
                        store = manifest.identity.store; provenance = manifest.provenanceReference
                    } else { throw UnsupportedStoreFormat() }
                    if try format == .existingV2 || root.entryMetadata(named: "managed-storage") != nil {
                        _ = try HostStorageIntents.inspect(in: root, store: store, provenanceReference: provenance)
                    }
                    guard case .journal(let record) = try RawDiskInitialization.inspectReadOnly(
                        in: infrastructure, named: "volumes.ext4", expectedSize: bytes,
                        heldDiskDescriptor: disk.handle.fileDescriptor),
                        format != .existingV2 || record.state == .initialized,
                        record.ext4UUID == ext4UUID else { throw UnsupportedStoreFormat() }
                }
                guard try PersistentStateDirectory.open(root.url).identity == root.identity,
                      try root.entryMetadata(named: "infrastructure")?.identity == infrastructure?.identity else {
                    throw UnsupportedStoreFormat()
                }
                return format
            }
            if try root.entryMetadata(named: ManagedStorageInitialization.directoryName) != nil {
                let marker = try ManagedStorageInitialization.open(in: root)
                // The hint is public, not permission to bypass pair validation.
                if try marker.hasCompletedPair(in: root) { return try classified(.existingV2) }
                if try marker.value("admitted.json", as: Bool.self) == true {
                    // Normal fresh initialization has no resume completion. Its
                    // complete pair still enters only authenticated recovery.
                    guard try root.entryMetadata(named: Checkpoint.directoryName) != nil,
                          try root.entryMetadata(named: "managed-storage") != nil else { throw UnsupportedStoreFormat() }
                } else {
                    try ManagedStorageInitialization.inspectPair(in: root)
                    return try classified(.initialization)
                }
            }
            let owner = try root.entryMetadata(named: Checkpoint.directoryName)
            let journal = try root.entryMetadata(named: "managed-storage")
            if owner == nil && journal == nil {
                // Infrastructure may already contain a network namespace from
                // ordinary fresh backend setup. Only storage evidence blocks it.
                if let infrastructure {
                    guard try !infrastructure.entryNames().contains(where: {
                        $0 == "volumes.ext4" || $0.hasPrefix(".raw-init-")
                    }) else { throw UnsupportedStoreFormat() }
                }
                for name in ["volume-storage.json"] {
                    guard try root.entryMetadata(named: name) == nil else { throw UnsupportedStoreFormat() }
                }
                for name in ["containers", "deleted-containers", "volumes"] {
                    if let directory = try root.openDirectoryIfPresent(named: name) {
                        guard try directory.entryNames().isEmpty,
                              try root.entryMetadata(named: name)?.identity == directory.identity else {
                            throw UnsupportedStoreFormat()
                        }
                    }
                }
                return try classified(.fresh)
            }
            guard owner != nil, journal != nil else { throw UnsupportedStoreFormat() }
            return try classified(.existingV2)
        } catch let error as POSIXError where ![.ENOENT, .ENOTDIR, .ELOOP].contains(error.code) {
            throw StoreUnavailable(code: error.code.rawValue)
        } catch { throw UnsupportedStoreFormat() }
    }
    private static func openExisting(root: PersistentStateDirectory, backingDescriptor: Int32, binding: StorageIdentity.StoreBinding,
                                     commitHook: HostStorageIntentCommit.Hook?) throws -> (Checkpoint, HostStorageIntents, String) {
        guard try classify(root: root) == .existingV2 else { throw Failure.blocked }
        // UNTRUSTED manifest names the expected identity/key/provenance; takeover
        // re-checks the key against ROOT before any child launch or mutation.
        let manifest = try Checkpoint.readManifest(in: root)
        guard manifest.identity == (try L.Identity(binding: binding, generation: manifest.identity.generation)) else { throw Failure.invalid }
        _ = try StorageIdentity.SPKISHA256(manifest.provenanceReference)
        let checkpoint = try Checkpoint.open(in: root, backingDescriptor: backingDescriptor, identity: manifest.identity,
            rootPublicKey: manifest.rootPublicKey, provenanceReference: manifest.provenanceReference, commitHook: commitHook)
        let intents = try HostStorageIntents.open(in: root, store: manifest.identity.store,
            provenanceReference: manifest.provenanceReference)
        return (checkpoint, intents, manifest.provenanceReference)
    }

    private static func initializationAdmission(in root: PersistentStateDirectory) throws
        -> (marker: ManagedStorageInitialization, evidence: [String: Data])? {
        guard try root.entryMetadata(named: ManagedStorageInitialization.directoryName) != nil else { return nil }
        let marker = try ManagedStorageInitialization.open(in: root)
        guard try marker.value("admitted.json", as: Bool.self) != true else { return nil }
        guard try marker.hasCompletedPair(in: root) else { throw Failure.blocked }
        return (marker, try marker.markerEvidence(in: root))
    }

    #if DEBUG
    private var afterCheckpointFresh: (() throws -> Void)?
    private var afterWorkloadDecode: (() async throws -> Void)?
    private var beforeWorkloadConnectionPublication: (() async throws -> Void)?
    /// Isolated NON-NATIVE test seam only. No release constructor accepts a ROOT
    /// callback, signer, proof, receipt producer, or fabricated process identity.
    struct IsolatedTestSeam: Sendable {
        enum ChildAction: Sendable {
            case bind(L.SignedGrant), csr, connectBoot, connectWorkload, retire, takeover
            case publicTakeoverReplay(StorageLifecycleChildProcess.PublicTakeoverReplayRequest)
            case stageServiceRebind(L.ServiceChangeRequest, StorageLifecycleChildProcess.Boot)
            case workload(ManagedStorageControlProtocol.ControlRequest)
            case attachmentCertificate(StorageLifecycleChildProcess.AttachmentCertificateRequest)
        }
        /// One clock domain per recovery lane for deadlines, waits, and worker budgets.
        /// Only isolated DEBUG owners can replace the production monotonic clock.
        struct RecoveryTiming: Sendable {
            let now: @Sendable () -> TimeInterval
            let sleep: @Sendable (TimeInterval) async throws -> Void
        }
        /// Isolated policy test only; release owners always inspect actual signed code.
        var isolationCompatibilityIdentity: (@Sendable () throws -> Void)? = nil
        /// Uses the real pinned queue and phases, but only on an isolated owner.
        var publicTakeoverQueue: ManagedPrepareCompatibilityQueue? = nil
        var resumeTiming: RecoveryTiming? = nil
        var coldTiming: RecoveryTiming? = nil
        let preparation: Preparation
        let recipient: Checkpoint.Recipient
        let rootRequest: @Sendable (Root.Request, Int32, Int32) throws -> Root.Reply
        let childAction: @Sendable (ChildAction) throws -> Data
        var adoptionRequest: (@Sendable (AdoptionRoot.Request) throws -> AdoptionRoot.Reply)? = nil
        var resumeRequest: (@Sendable (ResumeRoot.Request) throws -> ResumeRoot.Reply)? = nil
        var childLaunch: (@Sendable () throws -> Void)? = nil
        var coldRequest: (@Sendable (ColdRoot.Request, TimeInterval) throws -> ColdRoot.Reply)? = nil
        var daemonAudit: Data? = nil
        var childAudit: Data? = nil
    }
    init(isolatedTest seam: IsolatedTestSeam, root: PersistentStateDirectory, backingDescriptor: Int32,
         binding: StorageIdentity.StoreBinding, provenanceReference: String,
         commitHook: HostStorageIntentCommit.Hook? = nil,
         afterCheckpointFresh: (() throws -> Void)? = nil,
         afterWorkloadDecode: (() async throws -> Void)? = nil,
         beforeWorkloadConnectionPublication: (() async throws -> Void)? = nil) throws {
        rootDirectory = root; self.binding = binding; provenance = provenanceReference
        backing = try Self.own(backingDescriptor)
        keyRequest = try Self.request(.rootPublicKey); incarnation = seam.preparation.greeting.incarnationID
        worker = Worker(isolatedTest: seam)
        preparation = seam.preparation; recipient = seam.recipient; checkpointCommitHook = commitHook
        self.afterCheckpointFresh = afterCheckpointFresh
        self.afterWorkloadDecode = afterWorkloadDecode
        self.beforeWorkloadConnectionPublication = beforeWorkloadConnectionPublication
        try requireFreshDirectories()
        _ = try StorageIdentity.SPKISHA256(provenanceReference)
    }
    /// Existing-store seam: preparation/recipient describe the NEW takeover child.
    init(isolatedTestExisting seam: IsolatedTestSeam, root: PersistentStateDirectory, backingDescriptor: Int32,
         binding: StorageIdentity.StoreBinding, commitHook: HostStorageIntentCommit.Hook? = nil,
         afterWorkloadDecode: (() async throws -> Void)? = nil) throws {
        self.afterWorkloadDecode = afterWorkloadDecode
        let opened = try Self.openExisting(root: root, backingDescriptor: backingDescriptor, binding: binding, commitHook: commitHook)
        rootDirectory = root; self.binding = binding; provenance = opened.2
        backing = try Self.own(backingDescriptor)
        keyRequest = try Self.request(.rootPublicKey); incarnation = seam.preparation.greeting.incarnationID
        worker = Worker(isolatedTest: seam)
        checkpoint = opened.0; intents = opened.1; existing = true; checkpointCommitHook = commitHook
        pendingInitializationAdmission = try Self.initializationAdmission(in: root)
    }
    init(isolatedTestInitialization seam: IsolatedTestSeam, root: PersistentStateDirectory,
         backingDescriptor: Int32, binding: StorageIdentity.StoreBinding,
         afterWorkloadDecode: (() async throws -> Void)? = nil) throws {
        self.afterWorkloadDecode = afterWorkloadDecode
        let marker = try ManagedStorageInitialization.open(in: root)
        guard try marker.manifest.binding.value() == binding else { throw Failure.invalid }
        try ManagedStorageInitialization.inspectPair(in: root)
        rootDirectory = root; self.binding = binding; provenance = marker.manifest.provenance
        backing = try Self.own(backingDescriptor); initialization = marker
        keyRequest = try Self.request(.rootPublicKey); incarnation = seam.preparation.greeting.incarnationID
        worker = Worker(isolatedTest: seam)
    }
    /// Isolated tests only: the same physical journal the coordinator owns.
    var isolatedTestIntents: HostStorageIntents? { intents }
    #endif

    /// The sole production constructor accepts only the real native ROOT client.
    /// It duplicates the held backing descriptor, never reopens a caller pathname.
    init(rootClient: StorageLifecycleRootClient, installedHelperTeam: String,
         root: PersistentStateDirectory, backingDescriptor: Int32,
         binding: StorageIdentity.StoreBinding, provenanceReference: String,
         policy: StorageLifecycleNativePolicy = .production) throws {
        guard rootClient.policy == policy else { throw Failure.invalid }
        rootDirectory = root; self.binding = binding; provenance = provenanceReference
        backing = try Self.own(backingDescriptor)
        keyRequest = try Self.request(.rootPublicKey); incarnation = Self.id()
        worker = Worker(root: rootClient, team: installedHelperTeam, policy: policy, store: binding.storeID, scopeRoot: root)
        try requireFreshDirectories()
        _ = try StorageIdentity.SPKISHA256(provenanceReference)
    }

    /// Production restart constructor for an existing v2 pair. Opens both
    /// journals read-only (lease only); no ROOT, child or Guest IO happens here.
    init(existingStoreRootClient rootClient: StorageLifecycleRootClient, installedHelperTeam: String,
         root: PersistentStateDirectory, backingDescriptor: Int32, binding: StorageIdentity.StoreBinding,
         policy: StorageLifecycleNativePolicy = .production) throws {
        guard rootClient.policy == policy else { throw Failure.invalid }
        let opened = try Self.openExisting(root: root, backingDescriptor: backingDescriptor, binding: binding, commitHook: nil)
        rootDirectory = root; self.binding = binding; provenance = opened.2
        backing = try Self.own(backingDescriptor)
        keyRequest = try Self.request(.rootPublicKey); incarnation = Self.id()
        worker = Worker(root: rootClient, team: installedHelperTeam, policy: policy, store: binding.storeID, scopeRoot: root)
        checkpoint = opened.0; intents = opened.1; existing = true
        pendingInitializationAdmission = try Self.initializationAdmission(in: root)
    }

    init(initializationRootClient rootClient: StorageLifecycleRootClient, installedHelperTeam: String,
         root: PersistentStateDirectory, backingDescriptor: Int32, binding: StorageIdentity.StoreBinding,
         policy: StorageLifecycleNativePolicy = .production) throws {
        guard rootClient.policy == policy else { throw Failure.invalid }
        let marker = try ManagedStorageInitialization.open(in: root)
        guard try marker.manifest.binding.value() == binding else { throw Failure.invalid }
        try ManagedStorageInitialization.inspectPair(in: root)
        rootDirectory = root; self.binding = binding; provenance = marker.manifest.provenance
        backing = try Self.own(backingDescriptor)
        keyRequest = try Self.request(.rootPublicKey); incarnation = Self.id()
        worker = Worker(root: rootClient, team: installedHelperTeam, policy: policy, store: binding.storeID, scopeRoot: root)
        initialization = marker
    }

    func prepareResume(storeLock: CanonicalDataStoreLock, timeout: TimeInterval = 30) async throws -> Preparation {
        try begin(); defer { busy = false }
        guard timeout.isFinite, timeout > 0, timeout <= 30, let initialization, preparation == nil,
              try initialization.value("request.json", as: ManagedStorageInitialization.Request.self) == nil else {
            // Never fabricate the dead recipient's private key or allocate a new
            // child for an already frozen operation. ROOT cannot reassign it.
            throw Failure.blocked
        }
        let deadline = worker.resumeNow() + timeout
        let request = try ResumeRoot.Request(requestID: .init(Self.id()), body: .lookup(.init(binding)))
        let reply = try await checkedResumeRequest(request, storeLock: storeLock, deadline: deadline)
        guard case .status(let status) = reply.body, status.eligibility == .eligible,
              try status.binding.value() == binding else { throw Failure.blocked }
        try ManagedStorageInitialization.inspectPair(in: rootDirectory, original: status.original)
        if try rootDirectory.entryMetadata(named: Checkpoint.directoryName) != nil {
            let manifest = try Checkpoint.readManifest(in: rootDirectory)
            guard manifest.identity == status.original.identity, manifest.rootPublicKey == status.rootPublicKey,
                  manifest.provenanceReference == provenance else { throw Failure.invalid }
            checkpoint = try Checkpoint.open(in: rootDirectory, backingDescriptor: backing.fileDescriptor,
                identity: manifest.identity, rootPublicKey: manifest.rootPublicKey, provenanceReference: provenance)
        }
        let keyReply = try await checkedRootRequest(keyRequest)
        guard case .rootPublicKey(let key) = keyReply.body, key.publicData == status.rootPublicKey else { throw Failure.invalid }
        let initialized = try await worker.launch(.init(binding: L.bindingDigest(binding), expectedEpoch: 1,
            incarnationID: incarnation, rootPublicKey: key.publicData, store: binding.storeID.rawValue))
        guard initialized.greeting.rootPublicKey == key.publicData, initialized.greeting.expectedEpoch == 1,
              initialized.greeting.incarnationID == incarnation, initialized.greeting.store == binding.storeID.rawValue,
              initialized.greeting.binding == L.bindingDigest(binding) else { throw Failure.invalid }
        recipient = initialized.recipient; nativeAudit = initialized.nativeAudit
        let result = Preparation(rootPublicKey: key, greeting: initialized.greeting)
        preparation = result; resumeStatus = status
        return result
    }

    private func checkedResumeRequest(_ request: ResumeRoot.Request, storeLock: CanonicalDataStoreLock,
                                      deadline: TimeInterval) async throws -> ResumeRoot.Reply {
        guard let initialization else { throw Failure.blocked }
        let retained = try initialization.evidence(in: rootDirectory)
        while worker.resumeNow() < deadline {
            guard try initialization.evidence(in: rootDirectory) == retained else { throw Failure.blocked }
            let result: Result<ResumeRoot.Reply, any Error>
            do { result = .success(try await worker.resumeRequest(request, storeLock: storeLock, deadline: deadline)) }
            catch { result = .failure(error) }
            guard try initialization.evidence(in: rootDirectory) == retained else { throw Failure.blocked }
            try worker.check(); try Task.checkCancellation()
            guard worker.resumeNow() < deadline else { throw StorageLifecycleRootClient.Failure(.unavailable) }
            let retry: Bool
            switch result {
            case .failure(let error):
                retry = (error as? StorageLifecycleRootClient.Failure)?.code == .unavailable
            case .success(let reply):
                // A clean guest stop can precede native process exit. Only ROOT
                // may establish eligibility; wait passively using the SAME lookup,
                // physical baseline and deadline. Never retry a binding mismatch.
                if case .lookup(let requestedBinding) = request.body, case .status(let status) = reply.body {
                    guard status.binding == requestedBinding, try status.binding.value() == binding else { throw Failure.blocked }
                    retry = status.eligibility == .unavailable
                } else { retry = false }
            }
            if retry {
                try await worker.resumeSleep(min(0.1, max(0, deadline - worker.resumeNow())))
                guard try initialization.evidence(in: rootDirectory) == retained else { throw Failure.blocked }
                continue
            }
            return try result.get()
        }
        throw StorageLifecycleRootClient.Failure(.unavailable)
    }

    /// Validate both physical journals and remember the actual daemon at ROOT,
    /// then initialize exactly one native child at controller C (not adoption E).
    /// No service proof, VM launch, or disk mutation is attempted here.
    func prepareTakeover(storeLock: CanonicalDataStoreLock? = nil) async throws -> Preparation {
        try begin(); defer { busy = false }
        guard existing, !takeoverAttempted else { throw Failure.blocked }
        if let storeLock, try physicalState().resolvedDeadCold == nil {
            try await recoverInterruptedHandoffLocked(storeLock: storeLock,
                deadline: ProcessInfo.processInfo.systemUptime + 30)
        }
        let state = try physicalState()
        guard state.sealed == nil, state.terminal == nil, state.pendingService == nil, state.pendingCold == nil,
              state.handoffRetry == nil, state.pending == nil, state.pendingTakeover == nil else { throw Failure.blocked }
        let current = try Checkpoint.coldPredecessor(in: state).context
        if let resolved = state.resolvedDeadCold {
            guard let status = coldStatus, status.eligibility == .eligible,
                  status.predecessor.currentGrant == resolved.value.successor.grant,
                  status.origin == resolved.value.successorOrigin,
                  status.allocatedEpoch == resolved.value.baseEpoch else { throw Failure.blocked }
        }
        let reply = try await checkedRootRequest(keyRequest)
        guard case .rootPublicKey(let key) = reply.body, key.publicData == state.rootPublicKey else { throw Failure.invalid }
        try await prepareChild(key: key, epoch: current.controllerEpoch)
        guard let preparation else { throw Failure.invalid }
        return preparation
    }

    /// Runs before statusCold: ROOT deliberately refuses the cold lane while a
    /// service change is pending. Preparation launches a fresh unbound candidate
    /// at C, never a grant, old-key CSR, rebind, configure, or reopen.
    func prepareReplacementRecovery() async throws -> Bool {
        try begin(); defer { busy = false }
        guard existing, !takeoverAttempted, !bootAttempted else { throw Failure.blocked }
        let state = try physicalState()
        guard let retained = try Checkpoint.replacementRecoveryRequest(state), let intents else { return false }
        let census = try intents.checkedSnapshot()
        let reply = try await checkedRootRequest(keyRequest)
        guard case .rootPublicKey(let key) = reply.body, key.publicData == state.rootPublicKey else { throw Failure.invalid }
        guard try intents.checkedSnapshot() == census else { throw Failure.blocked }
        try await prepareChild(key: key, epoch: retained.request.predecessor.context.controllerEpoch)
        guard try physicalState() == state, try intents.checkedSnapshot() == census else { throw Failure.blocked }
        replacementRecoveryRequest = retained
        return true
    }

    /// Replay the SAME signed native operation on the already ROOT-adopted origin.
    /// The native operation cache, not currentReady or HOST history, resolves the
    /// predecessor frame after the surviving worker has advanced to a new E.
    func recoverReplacement(using transport: any ManagedStorageLifecycleServiceTransport,
                            current ready: ManagedStorageLifecycleServiceReady,
                            timeout: TimeInterval = 30) async throws {
        guard timeout.isFinite, timeout > 0, timeout <= 30 else { throw Failure.invalid }
        try begin(); defer { busy = false }
        guard existing, !takeoverAttempted, let retained = replacementRecoveryRequest,
              let adoptedShim, let adoptionLock, let preparation, let intents else { throw Failure.blocked }
        if try physicalState().pendingService != nil { try persist(.attemptNativeReplacement) }
        let state = try physicalState()
        guard try Checkpoint.replacementRecoveryRequest(state) == retained,
              let request = state.serviceReplacement, state.adoptionRetry == adoptionRetry,
              ready.binding.shimLaunchUUID == adoptedShim.status.origin.shimLaunchUUID,
              ready.binding.ext4UUID == binding.expectedExt4UUID.rawValue,
              ready.binding.bytes == binding.backing.size else { throw Failure.blocked }
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        service = transport; sequence = 0; workloadConnected = false
        try await withTaskCancellationHandler {
            // Census plus physical journals are compared across every suspension,
            // including lost replies, cancellation and timeout paths.
            let census = try intents.checkedSnapshot()
            @MainActor func unchanged() throws {
                try worker.check(); try Task.checkCancellation()
                guard try physicalState() == state, try intents.checkedSnapshot() == census else { throw Failure.blocked }
                guard ProcessInfo.processInfo.systemUptime < deadline else { throw Failure.blocked }
            }
            var admitted = false
            let successor: ManagedStorageLifecycleServiceReady
            while true {
                try unchanged()
                guard sequence < UInt64.max else { throw Failure.blocked }
                sequence += 1
                let frame = Boot.Frame(operation: .command, binding: ready.binding, sequence: sequence,
                    serviceEpoch: retained.request.predecessor.context.serviceEpoch,
                    command: admitted ? .replacementStatus : .replaceService,
                    workerUUID: retained.predecessorWorkerUUID, replacementRequest: admitted ? nil : request)
                try frame.validate()
                let response: Boot.Frame
                do {
                    response = try await withThrowingTaskGroup(of: Boot.Frame.self) { group in
                        group.addTask { try await transport.command(frame) }
                        group.addTask {
                            try await Task.sleep(for: .seconds(max(0, deadline - ProcessInfo.processInfo.systemUptime)))
                            transport.cancel()
                            throw Failure.blocked
                        }
                        defer { group.cancelAll() }
                        guard let reply = try await group.next() else { throw Failure.blocked }
                        return reply
                    }
                } catch {
                    try unchanged()
                    try await Task.sleep(for: .seconds(min(0.1, max(0, deadline - ProcessInfo.processInfo.systemUptime))))
                    try unchanged(); continue
                }
                try unchanged(); try response.validate()
                guard response.operation == .reply, response.binding == frame.binding,
                      response.sequence == frame.sequence, response.serviceEpoch == frame.serviceEpoch,
                      response.workerUUID == frame.workerUUID, response.code == nil,
                      let status = response.replacement, status.request == request else { throw Failure.invalid }
                admitted = true
                if status.phase == .failed { throw Failure.blocked }
                if status.phase == .succeeded {
                    guard let actual = status.ready, actual.workerUUID != retained.predecessorWorkerUUID else { throw Failure.invalid }
                    successor = .init(binding: ready.binding, ready: actual)
                    break
                }
                try await Task.sleep(for: .seconds(min(0.1, max(0, deadline - ProcessInfo.processInfo.systemUptime))))
                try unchanged()
            }
            try Self.validate(successor, binding: ready.binding, grant: retained.request.predecessor.grant,
                root: preparation.rootPublicKey)
            let envelope = try AdoptionRoot.Request(requestID: .init(retained.completionRequestID),
                body: .completeServiceChange(adoption: adoptedShim.request, change: retained.request))
            let reply = try await checkedAdoptionRequest(envelope, storeLock: adoptionLock, deadline: deadline,
                retryUnavailable: true)
            try unchanged()
            guard case .serviceChanged(let confirmation, let result) = reply.body,
                  confirmation.request == retained.request,
                  try result.state(boot: confirmation.successor.boot) == confirmation.successor else { throw Failure.invalid }
            try Self.match(confirmation.successor, boot: successor)
            // A fresh result must match the actual native cache Ready, including
            // current C/revision; HOST's completed record alone never attests it.
            try persist(.confirmService(confirmation))
            boot = successor
            freshReplacementCompletion = confirmation
        } onCancel: { [worker] in worker.cancel(); transport.cancel() }
    }

    /// Resolve an abandoned live takeover before selecting the next child's C.
    /// Status is discovery only; even a durable ROOT completion must be freshly
    /// re-proven by recoverHandoff over the authenticated, locked native channel.
    func recoverInterruptedHandoff(storeLock: CanonicalDataStoreLock, timeout: TimeInterval = 30) async throws {
        guard timeout.isFinite, timeout > 0, timeout <= 30 else { throw Failure.invalid }
        try begin(); defer { busy = false }
        guard existing, !takeoverAttempted, !bootAttempted, preparation == nil,
              initialization == nil, pendingInitializationAdmission == nil else { throw Failure.blocked }
        try await recoverInterruptedHandoffLocked(storeLock: storeLock,
            deadline: ProcessInfo.processInfo.systemUptime + timeout)
    }

    private func recoverInterruptedHandoffLocked(storeLock: CanonicalDataStoreLock, deadline: TimeInterval) async throws {
        guard initialization == nil, pendingInitializationAdmission == nil else { throw Failure.blocked }
        let state = try physicalState()
        // Completed replacement envelopes are retained for exact retry; only a
        // pending service change competes with this live takeover recovery lane.
        guard state.pendingCold == nil, state.pendingService == nil,
              state.sealed == nil, state.terminal == nil,
              state.pending == nil || state.pending?.signed.grant.operation == .takeover,
              let service = state.currentService else { throw Failure.blocked }
        let statusID = state.handoffRetry?.statusRequestID ?? Self.id()
        let envelope = try AdoptionRoot.Request(requestID: .init(statusID), body: .handoffStatus(state.identity))
        let reply = try await checkedAdoptionRequest(envelope, storeLock: storeLock, deadline: deadline, retryUnavailable: true)
        guard case .handoffStatus(let status) = reply.body else { throw Failure.invalid }
        let retry: Checkpoint.HandoffRetry
        if let saved = state.handoffRetry {
            retry = saved
        } else if let pending = status.pending {
            guard status.currentService == service else { throw Failure.invalid }
            retry = .init(operationID: status.operationID ?? Self.id(), statusRequestID: statusID,
                recoveryRequestID: Self.id(), predecessor: service, pending: pending)
        } else if let completion = status.completion, state.pending != nil || state.pendingTakeover != nil {
            guard completion.predecessorService == service else { throw Failure.invalid }
            retry = .init(operationID: completion.operationID, statusRequestID: statusID,
                recoveryRequestID: Self.id(), predecessor: service, pending: completion.signedRequest.request.pending)
        } else {
            guard state.pending == nil, state.pendingTakeover == nil, status.currentService == service else { throw Failure.blocked }
            return
        }
        guard preparation == nil else { throw Failure.blocked }
        if let completion = status.completion {
            guard status.pending == nil, completion.operationID == retry.operationID, completion.predecessorService == retry.predecessor,
                  completion.signedRequest.request.pending == retry.pending else { throw Failure.invalid }
        } else {
            guard status.currentService == retry.predecessor, status.pending == retry.pending,
                  status.operationID == nil || status.operationID == retry.operationID else { throw Failure.invalid }
        }
        try persist(.stageHandoff(retry))
        let recovery = try AdoptionRoot.Request(requestID: .init(retry.recoveryRequestID),
            body: .recoverHandoff(state.identity, operationID: retry.operationID))
        let completed = try await checkedAdoptionRequest(recovery, storeLock: storeLock, deadline: deadline, retryUnavailable: true)
        guard case .handoffRecovered(let value) = completed.body else { throw Failure.invalid }
        try persist(.recoverHandoff(value))
        recoveredHandoff = true
    }

    /// ROOT alone classifies positive old-process exit; unavailable never means cold.
    func statusCold(storeLock: CanonicalDataStoreLock, timeout: TimeInterval = 30) async throws -> ColdRoot.Status {
        guard timeout.isFinite, timeout > 0, timeout <= 30 else { throw Failure.invalid }
        try begin(); defer { busy = false }
        guard existing, !bootAttempted, !takeoverAttempted else { throw Failure.blocked }
        let deadline = worker.coldNow() + timeout
        // A persisted attempted cold operation is never configured again. ROOT
        // may resolve only an exact committed L2 whose participants all exited.
        try await resolveInterruptedColdLocked(storeLock: storeLock, deadline: deadline)
        // Ordinary adoption remains fenced while dead-cold history is retained.
        if worker.requiresAdoption, try physicalState().resolvedDeadCold == nil {
            try await recoverInterruptedHandoffLocked(storeLock: storeLock, deadline: deadline)
        }
        let state = try physicalState()
        guard state.pendingCold == nil else {
            throw EngineError(.conflict, "cold recovery is pending or its boot outcome is uncertain; data and launch evidence preserved")
        }
        let request = try ColdRoot.Request(requestID: .init(Self.id()), body: .status(state.identity))
        let reply = try await checkedColdRequest(request, storeLock: storeLock,
            deadline: deadline)
        guard case .status(let status) = reply.body, status.origin.rootPublicKey == state.rootPublicKey,
              try status.origin.binding.value() == binding else { throw Failure.invalid }
        if let resolved = state.resolvedDeadCold {
            let service = resolved.value.successor
            guard status.eligibility == .eligible, status.origin == resolved.value.successorOrigin,
                  status.allocatedEpoch == resolved.value.baseEpoch,
                  status.predecessor.currentGrant == service.grant,
                  status.predecessor.serviceEpoch == service.context.serviceEpoch,
                  status.predecessor.controllerEpoch == service.context.controllerEpoch,
                  status.predecessor.controllerKey == service.context.controllerKey,
                  status.predecessor.openRevision == service.openRevision,
                  status.predecessor.bootstrapKey == service.boot.bootstrapKey else { throw Failure.invalid }
        }
        coldStatus = status
        return status
    }

    /// Keyless authenticated reconciliation only. Freeze correlation BEFORE IO;
    /// a lost reply retries exactly this request, never the attempted configure.
    private func resolveInterruptedColdLocked(storeLock: CanonicalDataStoreLock, deadline: TimeInterval) async throws {
        let state = try physicalState()
        guard let pending = state.pendingCold else { return }
        guard preparation == nil, recipient == nil, pending.bootAttempted,
              let prepared = pending.prepared, prepared.recoveryBridge == nil,
              state.resolvedDeadCold == nil else {
            throw EngineError(.conflict, "cold recovery remains uncertain; data and launch evidence preserved")
        }
        let retry: Checkpoint.ColdResolutionRequest
        if let retained = pending.resolutionRequest {
            retry = retained
        } else {
            retry = try .init(value: .init(resolutionID: Self.id(), identity: state.identity,
                operationID: pending.request.prepare.operationID, signedOpenSHA256: prepared.signedOpenSHA256),
                requestID: Self.id())
            try persist(.stageColdResolution(retry))
        }
        let envelope = try ColdRoot.Request(requestID: .init(retry.requestID), body: .resolveDead(retry.value))
        let reply = try await checkedColdRequest(envelope, storeLock: storeLock, deadline: deadline, retryUnavailable: true)
        guard case .resolvedDead(let value) = reply.body, value.request == retry.value,
              let anchor = state.currentService else { throw Failure.invalid }
        try value.validate(prepared: prepared, anchor: anchor)
        try persist(.resolveDeadCold(value))
        // This audit reply cannot populate freshColdCompletion or grant recovery.
    }

    /// One frozen mounted candidate, one configure. Durable uncertainty is never
    /// recovered by creating a different child, launch, time, or authorization.
    func bootCold(using transport: any ManagedStorageLifecycleServiceTransport, greeting: ColdShim.Greeting,
                  storeLock: CanonicalDataStoreLock, nowUnixSeconds: UInt64, lifetimeSeconds: UInt64,
                  timeout: TimeInterval = 120) async throws {
        // Cold completion includes repeated native proofs and separate durable
        // lifecycle/adoption commits. Budget the whole transaction like ordinary
        // ROOT proof requests, not just the guest's 30-second configure exchange.
        guard timeout.isFinite, timeout > 0, timeout <= 120 else { throw Failure.invalid }
        let deadline = worker.coldNow() + timeout
        try begin(); defer { busy = false }
        guard existing, !bootAttempted, !takeoverAttempted, let preparation, let recipient,
              let status = coldStatus, status.eligibility == .eligible else { throw Failure.blocked }
        let state = try physicalState()
        let predecessor = try Checkpoint.coldPredecessor(in: state).context
        guard status.predecessor.currentGrant == (try Checkpoint.coldPredecessorService(in: state)).grant,
              status.predecessor.serviceEpoch == predecessor.serviceEpoch,
              status.predecessor.controllerEpoch == predecessor.controllerEpoch,
              status.predecessor.controllerKey == predecessor.controllerKey,
              state.pendingCold?.bootAttempted != true,
              greeting.rootPublicKey == preparation.rootPublicKey.publicData,
              try greeting.binding.value() == binding else { throw Failure.blocked }
        let request: Checkpoint.ColdRequest
        if let retained = state.pendingCold {
            guard retained.request.recipient == recipient, retained.request.prepare.mountedGreeting == greeting,
                  retained.request.prepare.nowUnixSeconds == nowUnixSeconds,
                  retained.request.prepare.lifetimeSeconds == lifetimeSeconds else { throw Failure.blocked }
            request = retained.request
        } else {
            let candidate = try StorageIdentity.Candidate(publicKey: .init(rawPublicKey: recipient.publicKey),
                childPIDHint: recipient.childPID, incarnationID: .init(recipient.incarnation))
            request = try .init(prepare: .init(operationID: Self.id(), identity: state.identity,
                expectedPredecessor: status.predecessor, expectedOrigin: status.origin,
                expectedAllocatedEpoch: status.allocatedEpoch, candidate: candidate, mountedGreeting: greeting,
                nowUnixSeconds: nowUnixSeconds, lifetimeSeconds: lifetimeSeconds), recipient: recipient,
                prepareRequestID: Self.id(), completionRequestID: Self.id())
            try persist(.stageColdRequest(request))
        }
        let reply = try await checkedColdRequest(.init(requestID: .init(request.prepareRequestID), body: .prepare(request.prepare)),
            storeLock: storeLock, deadline: deadline, retryUnavailable: true)
        guard case .prepared(let prepared) = reply.body else { throw Failure.invalid }
        try prepared.validate(for: request.prepare)
        let signed = prepared.signedOpen.request.takeover
        guard try preparation.greeting.matches(signed.grant) else { throw Failure.invalid }
        try persist(.authorizeCold(prepared)) // Exact outer signature BEFORE bind/configure.
        let configuration = Boot.Configuration(action: .coldOpenTakeover, rootPublicKey: state.rootPublicKey,
            signed: signed, nowUnixSeconds: request.prepare.nowUnixSeconds,
            lifetimeSeconds: request.prepare.lifetimeSeconds, cold: prepared.signedOpen)
        try configuration.validate()
        let expected = Boot.Binding(shimLaunchUUID: greeting.bootBinding.shimLaunchUUID,
            guestBootNonce: greeting.bootBinding.guestBootNonce, ext4UUID: greeting.bootBinding.ext4UUID,
            bytes: greeting.bootBinding.bytes)
        try persist(.attemptColdBoot)
        bootAttempted = true; takeoverAttempted = true
        service = transport; sequence = 0; workloadConnected = false
        let commandDeadline = (DispatchTime.now() + max(0, deadline - worker.coldNow())).uptimeNanoseconds
        try await withTaskCancellationHandler {
            try await withThrowingTaskGroup(of: Void.self) { group in
                group.addTask { [self] in
                    try await finishColdBoot(using: transport, configuration: configuration, expected: expected,
                        prepared: prepared, request: request, predecessor: predecessor, preparation: preparation,
                        storeLock: storeLock, deadline: deadline, commandDeadline: commandDeadline)
                }
                group.addTask { [worker] in
                    try await Task.sleep(for: .seconds(max(0, deadline - worker.coldNow())))
                    // Cancel actual transport IO and fence subsequent child/ROOT work.
                    // Structured joining prevents a late task publishing after return.
                    worker.cancel(); transport.cancel()
                    throw StorageLifecycleRootClient.Failure(.unavailable)
                }
                defer { group.cancelAll() }
                _ = try await group.next()
            }
        } onCancel: { [worker] in worker.cancel(); transport.cancel() }
    }

    private func finishColdBoot(using transport: any ManagedStorageLifecycleServiceTransport,
                                configuration: Boot.Configuration, expected: Boot.Binding,
                                prepared: ColdRoot.Prepared, request: Checkpoint.ColdRequest,
                                predecessor: Checkpoint.Context, preparation: Preparation,
                                storeLock: CanonicalDataStoreLock, deadline: TimeInterval,
                                commandDeadline: UInt64) async throws {
        let signed = prepared.signedOpen.request.takeover
        try checkColdDeadline(deadline)
        try await worker.bind(signed)
        try checkColdDeadline(deadline)
        let ready = try await transport.configure(configuration)
        try checkColdDeadline(deadline)
        try Self.validate(ready, binding: expected, grant: signed.grant, root: preparation.rootPublicKey)
        guard ready.ready.serviceEpoch != predecessor.serviceEpoch else { throw Failure.invalid }
        boot = ready
        let csr = try await worker.csr()
        try checkColdDeadline(deadline)
        let issued = try await command(.issueController, csr: csr, deadlineNanoseconds: commandDeadline)
        try checkColdDeadline(deadline)
        guard let certificate = issued.certificate else { throw Failure.invalid }
        let childBoot = try StorageLifecycleChildProcess.Boot(certificateDER: certificate, identity: ready.ready.identity,
            rootDER: ready.ready.tlsRootDER, serverSPKI: ready.ready.serverSPKI,
            serviceEpoch: ready.ready.serviceEpoch, signed: signed)
        let stream = try await transport.connectLifecycle()
        defer { try? stream.close() }
        try checkColdDeadline(deadline)
        try await worker.connectBoot(stream, boot: childBoot)
        try checkColdDeadline(deadline)
        try await worker.takeover()
        try checkColdDeadline(deadline)
        let reconciled = try await command(.reconcileController, signed: signed,
            controller: .init(epoch: signed.grant.expectedEpoch + 1, key: signed.grant.newKey),
            deadlineNanoseconds: commandDeadline)
        try checkColdDeadline(deadline)
        guard let actual = reconciled.ready else { throw Failure.invalid }
        let successor = ManagedStorageLifecycleServiceReady(binding: reconciled.binding, ready: actual)
        try Self.validate(successor, binding: expected, grant: signed.grant, root: preparation.rootPublicKey)
        guard actual.serviceEpoch == ready.ready.serviceEpoch, actual.workerUUID == ready.ready.workerUUID,
              actual.openRevision == ready.ready.openRevision, actual.revision >= ready.ready.revision,
              actual.tlsRootDER == ready.ready.tlsRootDER, actual.serverDER == ready.ready.serverDER,
              actual.serverSPKI == ready.ready.serverSPKI else { throw Failure.invalid }
        boot = successor; takeoverReconciled = true
        let completed = try await checkedColdRequest(.init(requestID: .init(request.completionRequestID),
            body: .complete(operationID: request.prepare.operationID, signedOpenSHA256: prepared.signedOpenSHA256)),
            storeLock: storeLock, deadline: deadline, retryUnavailable: true)
        guard case .completed(let result) = completed.body else { throw Failure.invalid }
        try result.validate(prepared: prepared)
        try Self.match(result.successor, boot: successor)
        try checkColdDeadline(deadline)
        try persist(.completeCold(result))
        #if CENGINE_COMPAT_LIFECYCLE_FAULT
        try StorageLifecycleCompatibilityFaultPolicy.afterFirstColdCompletion(result)
        #endif
        try checkColdDeadline(deadline)
        freshColdCompletion = .init(predecessor: predecessor, completion: result)
    }

    func bootResume(using transport: any ManagedStorageLifecycleServiceTransport, greeting: ColdShim.Greeting,
                    storeLock: CanonicalDataStoreLock, nowUnixSeconds: UInt64, lifetimeSeconds: UInt64,
                    timeout: TimeInterval = 30) async throws {
        guard timeout.isFinite, timeout > 0, timeout <= 30 else { throw Failure.invalid }
        let deadline = worker.resumeNow() + timeout
        try begin(); defer { busy = false }
        guard let initialization, let status = resumeStatus, let preparation, let recipient,
              !bootAttempted, greeting.purpose == .resumeReadOnly,
              greeting.rootPublicKey == preparation.rootPublicKey.publicData,
              try greeting.binding.value() == binding,
              try initialization.value("attempt.json", as: Bool.self) == nil else { throw Failure.blocked }
        let request: ManagedStorageInitialization.Request
        if let retained = try initialization.value("request.json", as: ManagedStorageInitialization.Request.self) {
            guard retained.recipient == recipient, retained.prepare.probeGreeting == greeting,
                  retained.prepare.nowUnixSeconds == nowUnixSeconds, retained.prepare.lifetimeSeconds == lifetimeSeconds else { throw Failure.blocked }
            request = retained
        } else {
            request = try .init(prepare: .init(operationID: Self.id(), identity: status.original.identity,
                expectedOriginal: status.original,
                candidate: .init(publicKey: .init(rawPublicKey: recipient.publicKey), childPIDHint: recipient.childPID,
                    incarnationID: .init(recipient.incarnation)), probeGreeting: greeting,
                expectedOriginalShimLaunchUUID: status.originalShimLaunchUUID,
                nowUnixSeconds: nowUnixSeconds, lifetimeSeconds: lifetimeSeconds), recipient: recipient,
                prepareRequestID: Self.id(), completionRequestID: Self.id())
            try request.prepare.validate(for: status)
            try initialization.retain("request.json", request)
        }
        let reply = try await checkedResumeRequest(.init(requestID: .init(request.prepareRequestID), body: .prepare(request.prepare)),
            storeLock: storeLock, deadline: deadline)
        guard case .prepared(let prepared) = reply.body else { throw Failure.invalid }
        try prepared.validate(for: request.prepare)
        let signed = prepared.signedOpen.request.takeover
        guard try preparation.greeting.matches(signed.grant) else { throw Failure.invalid }
        try initialization.retain("prepared.json", prepared)
        let configuration = Boot.Configuration(action: .resumeOpenTakeover, rootPublicKey: preparation.rootPublicKey.publicData,
            signed: signed, nowUnixSeconds: request.prepare.nowUnixSeconds, lifetimeSeconds: request.prepare.lifetimeSeconds,
            resume: prepared.signedOpen)
        try configuration.validate()
        let expected = Boot.Binding(shimLaunchUUID: greeting.bootBinding.shimLaunchUUID,
            guestBootNonce: greeting.bootBinding.guestBootNonce, ext4UUID: greeting.bootBinding.ext4UUID, bytes: greeting.bootBinding.bytes)
        try initialization.retain("attempt.json", true)
        let evidence = try initialization.evidence(in: rootDirectory)
        bootAttempted = true; takeoverAttempted = true
        service = transport; sequence = 0; workloadConnected = false
        try await withTaskCancellationHandler {
            try await worker.bind(signed)
            let ready = try await transport.configure(configuration)
            try worker.check(); try Task.checkCancellation()
            guard try initialization.evidence(in: rootDirectory) == evidence else { throw Failure.blocked }
            try Self.validate(ready, binding: expected, grant: signed.grant, root: preparation.rootPublicKey)
            boot = ready
            let csr = try await worker.csr()
            let issued = try await command(.issueController, csr: csr)
            guard let certificate = issued.certificate else { throw Failure.invalid }
            let childBoot = try StorageLifecycleChildProcess.Boot(certificateDER: certificate, identity: ready.ready.identity,
                rootDER: ready.ready.tlsRootDER, serverSPKI: ready.ready.serverSPKI,
                serviceEpoch: ready.ready.serviceEpoch, signed: signed)
            let stream = try await transport.connectLifecycle()
            defer { try? stream.close() }
            try await worker.connectBoot(stream, boot: childBoot)
            try await worker.takeover()
            let reconciled = try await command(.reconcileController, signed: signed,
                controller: .init(epoch: signed.grant.expectedEpoch + 1, key: signed.grant.newKey))
            guard let actual = reconciled.ready else { throw Failure.invalid }
            let successor = ManagedStorageLifecycleServiceReady(binding: reconciled.binding, ready: actual)
            try Self.validate(successor, binding: expected, grant: signed.grant, root: preparation.rootPublicKey)
            guard actual.serviceEpoch == ready.ready.serviceEpoch, actual.workerUUID == ready.ready.workerUUID,
                  actual.openRevision == ready.ready.openRevision, actual.revision >= ready.ready.revision,
                  actual.tlsRootDER == ready.ready.tlsRootDER, actual.serverDER == ready.ready.serverDER,
                  actual.serverSPKI == ready.ready.serverSPKI else { throw Failure.invalid }
            boot = successor; takeoverReconciled = true
            guard try initialization.evidence(in: rootDirectory) == evidence else { throw Failure.blocked }
            let completed = try await checkedResumeRequest(.init(requestID: .init(request.completionRequestID),
                body: .complete(operationID: request.prepare.operationID, signedOpenSHA256: prepared.signedOpenSHA256)),
                storeLock: storeLock, deadline: deadline)
            guard case .completed(let result) = completed.body else { throw Failure.invalid }
            try result.validate(prepared: prepared)
            try Self.match(result.successor, boot: successor)
            try initialization.retain("completed.json", result)
            try ManagedStorageInitialization.inspectPair(in: rootDirectory, original: status.original)
            if checkpoint == nil {
                let baseline = try Checkpoint.resumeBaseline(request: request, prepared: prepared, completion: result,
                    provenance: provenance, intentRevision: 1)
                checkpoint = try Checkpoint.createResumed(in: rootDirectory, backingDescriptor: backing.fileDescriptor,
                    binding: binding, initial: baseline)
            }
            if try rootDirectory.entryMetadata(named: "managed-storage") == nil {
                intents = try HostStorageIntents.initialize(in: rootDirectory, store: binding.storeID.rawValue, provenanceReference: provenance)
            } else {
                intents = try HostStorageIntents.open(in: rootDirectory, store: binding.storeID.rawValue, provenanceReference: provenance)
            }
            guard let checkpoint, let intents else { throw Failure.incomplete }
            let census = try intents.checkedSnapshot()
            try ManagedStorageInitialization.requireEmpty(census)
            if try checkpoint.snapshot().current?.original.signed.grant.operation != .takeover {
                try checkpoint.finishInitialization(request: request, prepared: prepared, completion: result, intents: census)
            }
            try worker.check(); try Task.checkCancellation()
        } onCancel: { [worker] in worker.cancel(); transport.cancel() }
    }

    private func checkColdDeadline(_ deadline: TimeInterval) throws {
        try worker.check(); try Task.checkCancellation()
        guard worker.coldNow() < deadline else { throw StorageLifecycleRootClient.Failure(.unavailable) }
    }

    private func checkedColdRequest(_ request: ColdRoot.Request, storeLock: CanonicalDataStoreLock,
                                    deadline: TimeInterval, retryUnavailable: Bool = false) async throws -> ColdRoot.Reply {
        let before = try physicalState()
        while true {
            guard worker.coldNow() < deadline else { throw StorageLifecycleRootClient.Failure(.unavailable) }
            let result: Result<ColdRoot.Reply, any Error>
            do { result = .success(try await worker.coldRequest(request, storeLock: storeLock, deadline: deadline)) }
            catch { result = .failure(error) }
            guard try physicalState() == before else { throw Failure.blocked }
            try worker.check(); try Task.checkCancellation()
            guard worker.coldNow() < deadline else { throw StorageLifecycleRootClient.Failure(.unavailable) }
            if retryUnavailable, case .failure(let error) = result,
               (error as? StorageLifecycleRootClient.Failure)?.code == .unavailable {
                try await worker.coldSleep(min(0.1, max(0, deadline - worker.coldNow())))
                guard try physicalState() == before else { throw Failure.blocked }
                continue
            }
            return try result.get()
        }
    }

    private func prepareChild(key: StorageIdentity.RootPublicKey, epoch: UInt64) async throws {
        if let preparation {
            guard preparation.rootPublicKey == key, preparation.greeting.expectedEpoch == epoch else { throw Failure.invalid }
            return
        }
        let before = try physicalState()
        let initialization = try StorageLifecycleChildProcess.Initialization(binding: L.bindingDigest(binding),
            expectedEpoch: epoch, incarnationID: incarnation, rootPublicKey: key.publicData, store: binding.storeID.rawValue)
        let initialized = try await worker.launch(initialization)
        try worker.check(); try Task.checkCancellation()
        guard try physicalState() == before else { throw Failure.blocked }
        let greeting = initialized.greeting
        guard greeting.rootPublicKey == key.publicData, greeting.incarnationID == incarnation,
              greeting.store == binding.storeID.rawValue, greeting.binding == L.bindingDigest(binding),
              greeting.expectedEpoch == epoch else { throw Failure.invalid }
        preparation = .init(rootPublicKey: key, greeting: greeting)
        recipient = initialized.recipient; nativeAudit = initialized.nativeAudit
    }

    /// Complete ROOT's live shim adoption BEFORE startup calls connectAdopted.
    /// Lost replies retry the frozen tuple; ROOT independently proves predecessor
    /// death, including supersession of its latest pending allocation.
    func adoptSurvivingShim(storeLock: CanonicalDataStoreLock, timeout: TimeInterval = 30) async throws -> AdoptedShim {
        guard timeout.isFinite, timeout > 0, timeout <= 30 else { throw Failure.invalid }
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        try begin(); defer { busy = false }
        guard existing, !takeoverAttempted, let preparation, let nativeAudit, let recipient,
              nativeAudit.daemonUniqueID == recipient.daemonUniqueID,
              nativeAudit.childUniqueID == recipient.childUniqueID else { throw Failure.blocked }
        let state = try physicalState()
        guard state.sealed == nil, state.terminal == nil else { throw Failure.blocked }
        if let replacementRecoveryRequest {
            guard try Checkpoint.replacementRecoveryRequest(state) == replacementRecoveryRequest else { throw Failure.blocked }
        } else {
            guard state.pendingService == nil else { throw Failure.blocked }
        }
        let statusRequest = try AdoptionRoot.Request(requestID: .init(Self.id()), body: .status)
        let reply = try await checkedAdoptionRequest(statusRequest, storeLock: storeLock, deadline: deadline)
        guard case .status(let status) = reply.body,
              status.origin.rootPublicKey == preparation.rootPublicKey.publicData,
              try status.origin.binding.value() == binding else { throw Failure.invalid }
        let retry: Checkpoint.AdoptionRetry
        if let frozen = adoptionRetry {
            guard state.adoptionRetry == frozen else { throw Failure.blocked }
            retry = frozen
        } else if let saved = state.adoptionRetry, nativeAudit.matches(saved.request) {
            retry = saved
        } else {
            let request = try Adoption.Request(id: Self.id(), origin: status.origin, expectedEpoch: status.allocatedEpoch,
                daemonAudit: nativeAudit.daemonAudit, daemonUniqueID: nativeAudit.daemonUniqueID,
                controllerAudit: nativeAudit.childAudit, controllerUniqueID: nativeAudit.childUniqueID,
                superseded: status.pending?.fenceIdentity)
            retry = .init(status: status, request: request, prepareRequestID: Self.id(), completeRequestID: Self.id())
        }
        guard nativeAudit.matches(retry.request), retry.status.origin == status.origin,
              retry.status.shimAudit == status.shimAudit, retry.status.shimUniqueID == status.shimUniqueID else { throw Failure.invalid }
        // A saved HOST tuple is never evidence of ROOT acceptance. Match ROOT's
        // exact pending/latest tuple, or its pre-allocation high-water mark.
        let pendingFence = try status.pending?.fenceIdentity
        guard status.pending == retry.request || status.latest == retry.request
                || (status.allocatedEpoch == retry.request.expectedEpoch
                    && pendingFence == retry.request.superseded) else { throw Failure.blocked }
        try persist(replacementRecoveryRequest == nil ? .stageAdoption(retry) : .stageReplacementAdoption(retry))
        adoptionRetry = retry
        let prepared = try await checkedAdoptionRequest(.init(requestID: .init(retry.prepareRequestID),
            body: .prepare(retry.request)), storeLock: storeLock, deadline: deadline, retryUnavailable: true)
        guard case .prepared(let fence) = prepared.body, try fence == retry.request.fenceIdentity else { throw Failure.invalid }
        let completed = try await checkedAdoptionRequest(.init(requestID: .init(retry.completeRequestID),
            body: .complete(retry.request)), storeLock: storeLock, deadline: deadline, retryUnavailable: true)
        guard case .completed(let fence) = completed.body, try fence == retry.request.fenceIdentity else { throw Failure.invalid }
        let authorization = try worker.connectionAuthorization(for: retry.request, status: status)
        let result = AdoptedShim(status: status, request: retry.request, connectionAuthorization: authorization)
        adoptionLock = storeLock; adoptedShim = result
        return result
    }

    private func checkedAdoptionRequest(_ request: AdoptionRoot.Request, storeLock: CanonicalDataStoreLock,
                                        deadline: TimeInterval? = nil, retryUnavailable: Bool = false) async throws -> AdoptionRoot.Reply {
        let deadline = deadline ?? ProcessInfo.processInfo.systemUptime + 30
        let before = try physicalState()
        let census = try intents?.checkedSnapshot()
        while true {
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw StorageLifecycleRootClient.Failure(.unavailable) }
            let result: Result<AdoptionRoot.Reply, any Error>
            do { result = .success(try await worker.adoptionRequest(request, storeLock: storeLock, deadline: deadline)) }
            catch { result = .failure(error) }
            guard try physicalState() == before, try intents?.checkedSnapshot() == census else { throw Failure.blocked }
            try worker.check(); try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw StorageLifecycleRootClient.Failure(.unavailable) }
            // Only the already-durable adoption envelope may be retried while
            // the retained shim re-registers after ROOT restarts. Never allocate
            // a new request/epoch, retry authorization failures or workload IO.
            if retryUnavailable, case .failure(let error) = result,
               (error as? StorageLifecycleRootClient.Failure)?.code == .unavailable {
                let remaining = deadline - ProcessInfo.processInfo.systemUptime
                try await Task.sleep(for: .seconds(min(0.1, max(0, remaining))))
                guard try physicalState() == before, try intents?.checkedSnapshot() == census else { throw Failure.blocked }
                continue
            }
            return try result.get()
        }
    }

    /// Cold daemon-restart takeover of the caller-supplied existing service.
    /// `current` is UNTRUSTED shim metadata, accepted only when it equals the
    /// checkpointed service AND a fresh ROOT live result. ROOT itself refuses issue
    /// unless the predecessor daemon and child have positively exited. A prior
    /// daemon's durable pre-issuance tuple or pending grant is resumed exactly.
    /// NOTE: a pending grant whose dead recipient never completed cannot be
    /// abandoned (no ROOT abandon contract); it fails closed with bytes preserved.
    func takeover(using transport: any ManagedStorageLifecycleServiceTransport,
                  current ready: ManagedStorageLifecycleServiceReady,
                  compatibility: ManagedPrepareCompatibilityCoordinator? = nil) async throws {
        try begin(); defer { busy = false }
        guard existing, !takeoverAttempted, checkpoint != nil, intents != nil,
              !worker.requiresAdoption || adoptedShim != nil else { throw Failure.blocked }
        if let adoptedShim {
            guard ready.binding.shimLaunchUUID == adoptedShim.status.origin.shimLaunchUUID,
                  try physicalState().adoptionRetry == adoptionRetry else { throw Failure.invalid }
        }
        var state = try physicalState()
        guard state.sealed == nil, state.terminal == nil, state.pendingService == nil, state.current != nil,
              ready.binding.bytes == binding.backing.size,
              ready.binding.ext4UUID == binding.expectedExt4UUID.rawValue else { throw Failure.blocked }
        let keyReply = try await checkedRootRequest(keyRequest)
        guard case .rootPublicKey(let key) = keyReply.body, key.publicData == state.rootPublicKey else { throw Failure.invalid }
        if let stale = state.pendingTakeover, stale.recipient != recipient {
            let signed = try await issueTakeover(stale, identity: state.identity, key: key)
            try persist(.stage(.init(signed: signed, recipient: stale.recipient, requestID: stale.requestID,
                serviceEpoch: stale.serviceEpoch)))
            state = try physicalState()
        }
        if let stale = state.pending, stale.recipient != recipient {
            guard stale.signed.grant.operation == .takeover else { throw Failure.blocked }
            try persist(.complete(try await rootCompletion(stale)))
            state = try physicalState()
        }
        if state.pending == nil, state.currentService == nil, let current = state.current {
            let grant = current.original.signed.grant
            let proven = try await rootAdoptedService(grant)
            try Self.match(proven, boot: ready)
            try persist(.recordService(proven))
            state = try physicalState()
        }
        guard let liveService = state.currentService, let live = state.currentContext else { throw Failure.blocked }
        if state.pending == nil {
            guard try await rootAdoptedService(liveService.grant) == liveService else { throw Failure.invalid }
        }
        try Self.validate(ready, binding: ready.binding, grant: liveService.grant, root: key)
        try Self.match(liveService, boot: ready)
        // Only a context just proven live by ROOT may later be treated as attested.
        let verifiedPredecessor = state.pending == nil ? live : nil
        guard try physicalState() == state else { throw Failure.blocked }
        let publicReplay = try capturePublicTakeover(compatibility, state: state)
        let replayOld = publicReplay == nil ? nil : state.current?.original.signed
        try await prepareChild(key: key, epoch: live.controllerEpoch)
        guard let preparation, let recipient, preparation.rootPublicKey == key else { throw Failure.invalid }
        state = try physicalState()
        let pending: Checkpoint.GrantContext
        if let staged = state.pending {
            guard staged.recipient == recipient, staged.signed.grant.operation == .takeover else { throw Failure.blocked }
            pending = staged
        } else {
            let request: Checkpoint.TakeoverRequest
            if let retained = state.pendingTakeover {
                guard retained.recipient == recipient else { throw Failure.blocked }
                request = retained
            } else {
                request = .init(requestID: Self.id(), grantID: Self.id(), recipient: recipient,
                    expectedEpoch: live.controllerEpoch, serviceEpoch: live.serviceEpoch)
                try persist(.stageTakeoverRequest(request))
            }
            let signed = try await issueTakeover(request, identity: state.identity, key: key)
            guard try preparation.greeting.matches(signed.grant) else { throw Failure.invalid }
            let context = Checkpoint.GrantContext(signed: signed, recipient: recipient, requestID: request.requestID,
                serviceEpoch: request.serviceEpoch)
            try persist(.stage(context))
            pending = context
        }
        takeoverAttempted = true // Consume before the first Guest/child mutation.
        takeoverPredecessor = pending.signed.grant.expectedEpoch == verifiedPredecessor?.controllerEpoch ? verifiedPredecessor : nil
        service = transport; boot = ready; sequence = 0; workloadConnected = false
        let replayState = publicReplay == nil ? nil : try physicalState()
        let replayCensus = publicReplay == nil ? nil : try intents?.checkedSnapshot()
        func replayUnchanged() throws {
            guard publicReplay != nil else { return }
            try worker.check(); try Task.checkCancellation()
            guard busy, boot == ready, !workloadConnected, replacementIdentity == nil,
                  try physicalState() == replayState, try intents?.checkedSnapshot() == replayCensus else { throw Failure.blocked }
        }
        do {
            try await withTaskCancellationHandler {
                try replayUnchanged()
                try await worker.bind(pending.signed)
                try replayUnchanged()
                let csr = try await worker.csr()
                try replayUnchanged()
                let reply = try await command(.authorizeSuccessor, csr: csr, signed: pending.signed)
                try replayUnchanged()
                guard let certificate = reply.certificate else { throw Failure.invalid }
                let childBoot = try StorageLifecycleChildProcess.Boot(certificateDER: certificate, identity: ready.ready.identity,
                    rootDER: ready.ready.tlsRootDER, serverSPKI: ready.ready.serverSPKI,
                    serviceEpoch: ready.ready.serviceEpoch, signed: pending.signed)
                let stream = try await transport.connectLifecycle()
                defer { try? stream.close() }
                try replayUnchanged()
                try await worker.connectBoot(stream, boot: childBoot)
                try replayUnchanged()
                if let publicReplay, let replayOld {
                    guard verifiedPredecessor == live else { throw Failure.blocked }
                    try await performPublicTakeoverReplay(publicReplay, old: replayOld, pending: pending,
                        predecessor: liveService, revalidate: replayUnchanged)
                    try replayUnchanged()
                }
                #if CENGINE_COMPAT_LIFECYCLE_FAULT
                try await StorageLifecycleCompatibilityFaultPolicy.takeoverApply(.beforeTakeoverApply,
                    recoveredHandoff: recoveredHandoff, grant: pending.signed.grant,
                    serviceEpoch: ready.ready.serviceEpoch, workerUUID: ready.ready.workerUUID,
                    openRevision: ready.ready.openRevision)
                #endif
                try await worker.takeover()
                #if CENGINE_COMPAT_LIFECYCLE_FAULT
                try await StorageLifecycleCompatibilityFaultPolicy.takeoverApply(.afterTakeoverApply,
                    recoveredHandoff: recoveredHandoff, grant: pending.signed.grant,
                    serviceEpoch: ready.ready.serviceEpoch, workerUUID: ready.ready.workerUUID,
                    openRevision: ready.ready.openRevision)
                #endif
                try replayUnchanged()
                let grant = pending.signed.grant
                guard grant.expectedEpoch < UInt64.max else { throw Failure.invalid }
                let reconciled = try await command(.reconcileController, signed: pending.signed,
                    controller: .init(epoch: grant.expectedEpoch + 1, key: grant.newKey))
                try replayUnchanged()
                guard let actual = reconciled.ready else { throw Failure.invalid }
                let successor = ManagedStorageLifecycleServiceReady(binding: reconciled.binding, ready: actual)
                try Self.validate(successor, binding: ready.binding, grant: grant, root: key)
                guard actual.serviceEpoch == ready.ready.serviceEpoch, actual.workerUUID == ready.ready.workerUUID,
                      actual.openRevision == ready.ready.openRevision, actual.revision >= ready.ready.revision,
                      actual.tlsRootDER == ready.ready.tlsRootDER, actual.serverDER == ready.ready.serverDER,
                      actual.serverSPKI == ready.ready.serverSPKI else { throw Failure.invalid }
                boot = successor
                takeoverReconciled = true
                try worker.check(); try Task.checkCancellation()
                @MainActor func unchangedCensus() throws {
                    guard publicReplay != nil else { return }
                    guard try intents?.checkedSnapshot() == replayCensus else { throw Failure.blocked }
                }
                try await completeLocked(revalidateCensus: unchangedCensus)
                try unchangedCensus()
                if let publicReplay {
                    let completed = try physicalState()
                    guard completed.pending == nil, completed.pendingTakeover == nil,
                          let current = completed.current, current.original == pending,
                          current.original.signed.grant == completed.currentService?.grant else { throw Failure.blocked }
                    try publicReplay.publish(ManagedPrepareCompatibilityProtocol.canonicalData(
                        PublicTakeoverConfirmed(version: 2, completion: current)), "confirmed")
                    if publicReplay.request.original != nil { publicTakeoverRecovery = publicReplay }
                }
            } onCancel: { [worker] in worker.cancel(); transport.cancel() }
        } catch {
            if publicReplay != nil { workloadConnected = false; cancel() }
            throw error
        }
    }
    struct PublicTakeoverBegun: Codable, Equatable, Sendable {
        let version: UInt32
        let requestID: String
        let old: L.SignedGrant
        let pending: L.SignedGrant
        let incarnationID: String
    }
    struct PublicTakeoverConfirmed: Codable, Equatable, Sendable {
        let version: UInt32
        let completion: Checkpoint.Completed
    }
    private func capturePublicTakeover(_ compatibility: ManagedPrepareCompatibilityCoordinator?,
                                      state: Checkpoint.Metadata) throws -> PublicTakeoverSelection? {
        guard !worker.policy.isQualification else { return nil }
        guard let context = state.currentContext else { throw Failure.blocked }
        let selected: PublicTakeoverSelection?
        #if DEBUG
        if let queue = worker.testSeam?.publicTakeoverQueue {
            try requireSignedCompatibilityIdentity()
            if let claim = try queue.publicTakeoverCapture(store: state.identity.store,
                epoch: context.controllerEpoch, serviceEpoch: context.serviceEpoch) {
                selected = .init(request: claim.request, publish: { try queue.publicTakeoverPublish($0, phase: $1, claim: claim) })
            } else { selected = nil }
        } else {
            selected = try productionPublicTakeover(compatibility, context: context, store: state.identity.store)
        }
        #else
        selected = try productionPublicTakeover(compatibility, context: context, store: state.identity.store)
        #endif
        guard let selected else { return nil }
        guard !worker.policy.isQualification, state.pending == nil, state.pendingTakeover == nil,
              state.pendingService == nil, state.pendingCold == nil, state.sealed == nil, state.terminal == nil,
              initialization == nil, pendingInitializationAdmission == nil,
              state.current?.original.signed.grant.operation == .takeover, context.controllerEpoch >= 2,
              selected.request.store == state.identity.store, selected.request.epoch == context.controllerEpoch,
              selected.request.serviceEpoch == context.serviceEpoch else { throw Failure.blocked }
        return selected
    }
    private func productionPublicTakeover(_ compatibility: ManagedPrepareCompatibilityCoordinator?,
        context: Checkpoint.Context, store: String) throws -> PublicTakeoverSelection? {
        guard let compatibility, let claim = try compatibility.publicTakeoverCapture(store: store,
            epoch: context.controllerEpoch, serviceEpoch: context.serviceEpoch) else { return nil }
        return .init(request: claim.request, publish: { try compatibility.publicTakeoverPublish($0, phase: $1, claim: claim) })
    }
    static func validatePublicReplayCandidate(old: L.SignedGrant, pending: L.SignedGrant,
        state: Checkpoint.Metadata, preparation: Preparation) throws {
        let root = try StorageIdentity.RootPublicKey(publicData: state.rootPublicKey)
        let o = old.grant, p = pending.grant
        guard state.current?.original.signed == old, state.pending?.signed == pending,
              old.isValidSignature(using: root), pending.isValidSignature(using: root),
              preparation.rootPublicKey == root, try preparation.greeting.matches(p),
              o.operation == .takeover, p.operation == .takeover, p.expectedEpoch >= 2,
              o.expectedEpoch < UInt64.max, o.expectedEpoch + 1 == p.expectedEpoch,
              p.expectedEpoch < UInt64.max, o.identity == state.identity, p.identity == state.identity,
              o.id != p.id, o.serial < p.serial, o.newKey != p.newKey,
              state.currentContext?.controllerEpoch == p.expectedEpoch,
              state.currentContext?.controllerKey == o.newKey else { throw Failure.invalid }
    }
    private func performPublicTakeoverReplay(_ selected: PublicTakeoverSelection, old: L.SignedGrant,
        pending: Checkpoint.GrantContext, predecessor: L.ServiceState,
        revalidate: () throws -> Void) async throws {
        try requireSignedCompatibilityIdentity()
        guard let preparation, let boot, let service, busy, workloadCalls == 0,
              !workloadRetireActive, !serviceCommandActive, prepareStorageCommands.tryPoll() else { throw Failure.blocked }
        defer { prepareStorageCommands.release() }
        let state = try physicalState()
        try Self.validatePublicReplayCandidate(old: old, pending: pending.signed, state: state, preparation: preparation)
        guard state.currentService == predecessor, predecessor.grant == old.grant,
              state.pending == pending, pending.recipient == recipient else { throw Failure.blocked }
        try Self.match(predecessor, boot: boot)
        let deadline = DispatchTime.now().uptimeNanoseconds + 30_000_000_000
        func unchanged() throws {
            try revalidate()
            guard try physicalState() == state, self.boot == boot,
                  DispatchTime.now().uptimeNanoseconds < deadline else { throw Failure.blocked }
        }
        try unchanged()
        let begun = PublicTakeoverBegun(version: 2, requestID: selected.request.requestID,
            old: old, pending: pending.signed, incarnationID: preparation.greeting.incarnationID)
        try selected.publish(ManagedPrepareCompatibilityProtocol.canonicalData(begun), "begun")
        let isolation = selected.request.original.map {
            Boot.IsolationRequest(requestID: selected.request.requestID, operationUUID: $0.operationUUID,
                armDigest: $0.armDigest, challenge: Self.id())
        }
        func observation() async throws -> Boot.IsolationProof? {
            try unchanged()
            guard let isolation else { return nil }
            guard sequence < UInt64.max else { throw Failure.blocked }
            sequence += 1
            let frame = Boot.Frame(operation: .command, binding: boot.binding, sequence: sequence,
                serviceEpoch: boot.ready.serviceEpoch, command: .isolationState, workerUUID: boot.ready.workerUUID,
                isolationRequest: isolation)
            try frame.validate()
            let reply: Boot.Frame
            do { reply = try await service.command(frame, deadlineNanoseconds: deadline) }
            catch { try unchanged(); throw error }
            try unchanged(); try reply.validate()
            guard reply.operation == .reply, reply.binding == frame.binding, reply.sequence == frame.sequence,
                  reply.serviceEpoch == frame.serviceEpoch, reply.workerUUID == frame.workerUUID,
                  reply.code == nil, let proof = reply.isolationProof,
                  proof.request == isolation, proof.caseName == "isolation-state",
                  proof.store == selected.request.store, proof.serviceEpoch == selected.request.serviceEpoch,
                  proof.workerUUID == boot.ready.workerUUID else { throw Failure.invalid }
            return proof
        }
        let before = try await observation()
        try unchanged()
        let denied: StorageLifecycleChildProcess.PublicTakeoverReplayObservation
        do { denied = try await worker.publicTakeoverReplay(requestID: selected.request.requestID, old: old) }
        catch { try unchanged(); throw error }
        try unchanged()
        guard denied.version == 1, denied.requestID == begun.requestID, denied.old == old,
              denied.pending == pending.signed, denied.incarnationID == begun.incarnationID,
              denied.error == "UNAUTHORIZED" else { throw Failure.invalid }
        let after = try await observation()
        try unchanged()
        try selected.publish(ManagedPrepareCompatibilityProtocol.canonicalData(denied), "denied")
        if let before, let after {
            try selected.publish(ManagedPrepareCompatibilityProtocol.canonicalData(
                StorageServiceTypes.IsolationStatePair(before: before, after: after)), "attestation")
        }
        try unchanged()
    }

    private func issueTakeover(_ request: Checkpoint.TakeoverRequest, identity: L.Identity,
                               key: StorageIdentity.RootPublicKey) async throws -> L.SignedGrant {
        let candidate = try StorageIdentity.Candidate(publicKey: .init(rawPublicKey: request.recipient.publicKey),
            childPIDHint: request.recipient.childPID, incarnationID: .init(request.recipient.incarnation))
        let envelope = try Root.Request(requestID: .init(request.requestID), body: .issue(operation: .takeover,
            id: request.grantID, identity: identity, expectedEpoch: request.expectedEpoch, candidate: candidate))
        let reply = try await checkedRootRequest(envelope)
        // The signed grant carries only the candidate KEY; PID hint and incarnation
        // are bound through the exact envelope we sent, rebuilt from the durable tuple.
        let recipientKey = try StorageIdentity.Ed25519SPKI(rawPublicKey: request.recipient.publicKey).fingerprint.rawValue
        guard case .issue(.takeover, request.grantID, identity, request.expectedEpoch, let sent) = envelope.body,
              sent.publicKey.fingerprint.rawValue == recipientKey, sent.childPIDHint == request.recipient.childPID,
              sent.incarnationID == (try StorageIdentity.IncarnationID(request.recipient.incarnation)) else { throw Failure.invalid }
        guard case .grant(let signed) = reply.body, signed.isValidSignature(using: key),
              signed.grant.operation == .takeover, signed.grant.id == request.grantID, signed.grant.identity == identity,
              signed.grant.expectedEpoch == request.expectedEpoch,
              signed.grant.newKey == recipientKey else { throw Failure.invalid }
        return signed
    }
    /// After a completed takeover: fresh ROOT live proof + child connect, a fresh
    /// full-identity Query, and complete HOST census equality against the
    /// checkpoint. ONLY then is restricted recovery permission minted (historical
    /// contexts for settlement; certificates remain current-context only).
    func recoverWorkload() async throws {
        guard existing, recoveryPermission == nil, recipient != nil else { throw Failure.blocked }
        try await connectWorkload()
        let query = try await queryWorkload()
        try begin(); defer { busy = false }
        let context = try workloadContext()
        guard workloadConnected, let checkpoint, let intents, let recipient else { throw Failure.blocked }
        let state = try checkpoint.snapshot()
        guard state.pendingTakeover == nil, let current = state.current, let live = state.currentContext,
              current.original.signed.grant.operation == .takeover, current.original.recipient == recipient,
              try Checkpoint.censusMatches(state, intents: intents.checkedSnapshot()) else { throw Failure.blocked }
        var required = try Checkpoint.recoveryContexts(state)
        // The checkpoint separately validates ALL retained metadata, including
        // cold audit edges. Only census-required contexts seek recovery authority.
        var held = state.contexts.map(\.context).filter { required.contains($0) }
        var replacementPredecessor: Checkpoint.Context?
        if let fresh = freshReplacementCompletion {
            let old = fresh.request.predecessor.context, successor = fresh.successor.context
            let edge = Checkpoint.Context(serviceEpoch: successor.serviceEpoch,
                controllerEpoch: successor.controllerEpoch, controllerKey: successor.controllerKey)
            guard edge == takeoverPredecessor, edge.serviceEpoch == live.serviceEpoch,
                  edge.controllerEpoch == current.original.signed.grant.expectedEpoch,
                  edge.controllerEpoch < UInt64.max, edge.controllerEpoch + 1 == live.controllerEpoch,
                  edge.controllerKey != live.controllerKey else { throw Failure.blocked }
            let predecessor = Checkpoint.Context(serviceEpoch: old.serviceEpoch,
                controllerEpoch: old.controllerEpoch, controllerKey: old.controllerKey)
            if required.contains(predecessor) {
                replacementPredecessor = predecessor
                required.remove(predecessor); held.removeAll { $0 == predecessor }
            }
        }
        var coldHistory: Set<Checkpoint.Context> = []
        if let fresh = freshColdCompletion {
            guard fresh.completion == state.latestCold?.completion,
                  fresh.completion.receipt == current.directResult,
                  fresh.completion.successor == state.currentService,
                  fresh.predecessor == state.latestCold?.predecessor.context else { throw Failure.blocked }
            var proven: Set<Checkpoint.Context> = [fresh.predecessor]
            if let bridge = fresh.completion.recoveryBridge {
                guard let retained = state.latestCold?.deadPredecessor,
                      retained.value == bridge,
                      Checkpoint.Context(serviceEpoch: bridge.successor.context.serviceEpoch,
                          controllerEpoch: bridge.successor.context.controllerEpoch,
                          controllerKey: bridge.successor.context.controllerKey) == fresh.predecessor else {
                    throw Failure.blocked
                }
                // Only this owner's fresh normal C13 completion, live proof and
                // Query/census may cover the original C11 and dead C12 edge.
                proven.insert(retained.anchor.context)
            } else {
                guard state.latestCold?.deadPredecessor == nil else { throw Failure.blocked }
            }
            coldHistory = required.intersection(proven)
            required.subtract(coldHistory); held.removeAll { coldHistory.contains($0) }
        }
        var history = try Self.attestedHistory(required: required,
            held: held, current: live, takeover: current.original.signed.grant,
            query: query, context: context, predecessor: takeoverPredecessor)
        history.append(contentsOf: coldHistory.sorted {
            ($0.controllerEpoch, $0.serviceEpoch) < ($1.controllerEpoch, $1.serviceEpoch)
        })
        if let replacementPredecessor { history.append(replacementPredecessor) }
        let authorization = RecoveryAuthorization(current: context, history: history,
            workerHistoryReference: try state.latestServiceChange?.reference)
        let recovery = try ManagedStorageControllerRecovery.lifecycle(authorization)
        if let pending = pendingInitializationAdmission {
            guard query.volumes.isEmpty, query.volumeLifecycles.isEmpty, query.prepares.isEmpty, query.attachments.isEmpty,
                  try pending.marker.markerEvidence(in: rootDirectory) == pending.evidence else { throw Failure.blocked }
            try ManagedStorageInitialization.requireEmpty(intents.checkedSnapshot())
            // Only THIS owner's fresh ROOT proof, completed takeover and Query
            // may finish the HOST admission hint. Cached completion never does.
            try pending.marker.retain("admitted.json", true)
            pendingInitializationAdmission = nil
        }
        try worker.publish(())
        recoveryPermission = (context, recovery)
    }
    /// Test/diagnostic observation only; never a capability.
    var hasRecoveryPermission: Bool { recoveryPermission != nil }

    /// Historical checkpoint contexts rest on UNSIGNED receipts/links and are
    /// forgeable by a same-UID offline writer. Recovery receives ONLY the exact
    /// census-required set, and every non-current member must be attested:
    /// the fresh authenticated schema-4 Query attests the current E/C/key; the
    /// Guest accepted the ROOT-signed takeover from C-1 under that same E; and the
    /// C-1 key was proven live by ROOT in this owner's takeover. Older contexts
    /// are admitted ONLY when the same fresh Query attests them as the Guest-
    /// persisted reserving context of a retained prepare; any other fails closed.
    static func attestedHistory(required: Set<Checkpoint.Context>, held: [Checkpoint.Context],
                                current: Checkpoint.Context, takeover: L.Grant,
                                query: ManagedStorageControlClient.Snapshot,
                                context: ManagedStorageControlClient.Context,
                                predecessor: Checkpoint.Context?) throws -> [Checkpoint.Context] {
        guard Set(held) == required, held.count == required.count, required.contains(current),
              query.schema == 4, query.store.id == context.store,
              query.epoch == current.serviceEpoch, query.epoch == context.serviceEpoch,
              query.controller.epoch == current.controllerEpoch, query.controller.key == current.controllerKey,
              context.controllerEpoch == current.controllerEpoch, context.controllerKey == current.controllerKey,
              takeover.operation == .takeover, takeover.expectedEpoch < UInt64.max,
              takeover.expectedEpoch + 1 == current.controllerEpoch, takeover.newKey == current.controllerKey else {
            throw Failure.blocked
        }
        let attested = Set(query.prepares.values.compactMap { prepare in
            prepare.context.map { Checkpoint.Context(serviceEpoch: $0.serviceEpoch,
                controllerEpoch: $0.controllerEpoch, controllerKey: $0.controllerKey) }
        })
        let history = required.subtracting([current])
        for old in history where !attested.contains(old) {
            guard let predecessor, old == predecessor, predecessor.serviceEpoch == query.epoch,
                  predecessor.controllerEpoch == takeover.expectedEpoch,
                  predecessor.controllerKey != current.controllerKey else { throw Failure.blocked }
        }
        return history.sorted { ($0.controllerEpoch, $0.serviceEpoch) < ($1.controllerEpoch, $1.serviceEpoch) }
    }

    /// ROOT key lookup also remembers the actual audited daemon. Only then may
    /// the actual native child launch and open its independently audited ROOT IPC.
    /// Returned public inputs let the caller start the external fresh shim BEFORE
    /// provisionFresh. The HOST never accepts a Boolean claiming fresh provenance.
    func prepareFresh() async throws -> Preparation {
        try begin(); defer { busy = false }
        if let preparation { return preparation }
        try requireFreshDirectories()
        let reply = try await checkedRootRequest(keyRequest)
        guard case .rootPublicKey(let key) = reply.body else { throw Failure.invalid }
        let initialization = try StorageLifecycleChildProcess.Initialization(binding: L.bindingDigest(binding),
            expectedEpoch: 0, incarnationID: incarnation, rootPublicKey: key.publicData, store: binding.storeID.rawValue)
        let initialized = try await worker.launch(initialization)
        try worker.check(); try Task.checkCancellation()
        let greeting = initialized.greeting
        guard greeting.rootPublicKey == key.publicData, greeting.incarnationID == incarnation,
              greeting.store == binding.storeID.rawValue, greeting.binding == L.bindingDigest(binding),
              greeting.expectedEpoch == 0 else { throw Failure.invalid }
        recipient = initialized.recipient
        let result = Preparation(rootPublicKey: key, greeting: greeting)
        preparation = result
        return result
    }

    /// PRECONDITION: caller has already started the native fresh shim. ROOT itself
    /// verifies it; a missing/forged shim fails without Guest boot or disk cleanup.
    /// Checkpoint.fresh MUST precede HostStorageIntents.initialize (its fresh API).
    /// A failure between these creations is intentionally fail-closed: repair is
    /// required, not deletion/reinitialization. This fresh-only owner has no recovery
    /// capability and an incomplete pair is never ready to boot.
    /// Freeze both envelopes before IO: initialDescriptors is only a transport flag;
    /// requestID, grant ID, binding and candidate remain the same semantic request.
    /// First call probes without FDs and attaches once ONLY on correlated invalidRequest
    /// (ROOT has no initial intent). Every later call probes once, even after uncertain
    /// results; never resend FDs to an existing intent, loop, or replace IDs.
    func provisionFresh() async throws {
        try begin(); defer { busy = false }
        guard let preparation, let recipient else { throw Failure.blocked }
        if checkpoint != nil { guard intents != nil else { throw Failure.repairRequired }; return }
        try requireFreshDirectories()
        if provisionRequests == nil {
            let candidate = try StorageIdentity.Candidate(publicKey: .init(publicData: preparation.greeting.controllerSPKI),
                childPIDHint: recipient.childPID, incarnationID: .init(recipient.incarnation))
            let id = Self.id(), requestID = try StorageIdentity.RequestID(Self.id())
            let probe = try Root.Request(requestID: requestID,
                body: .provision(id: id, binding: binding, candidate: candidate, initialDescriptors: false))
            let attach = try Root.Request(requestID: requestID,
                body: .provision(id: id, binding: binding, candidate: candidate, initialDescriptors: true))
            provisionRequests = (probe, attach)
        }
        let requests = provisionRequests!, firstAttempt = attemptedProvision == nil
        attemptedProvision = requests.probe // Consume the first-call allowance before IO.
        var reply = try await checkedRootRequest(requests.probe, returnMissingInitial: firstAttempt)
        if case .failure(.invalidRequest) = reply.body {
            // Only the correlated ROOT failure body permits attach. Client/transport
            // decoding can also throw invalidRequest; that is uncertain, not missing.
            attemptedProvision = requests.attach
            reply = try await checkedRootRequest(requests.attach, rootFD: rootDirectory.descriptor, backingFD: backing.fileDescriptor)
        }
        guard case .grant(let signed) = reply.body,
              signed.isValidSignature(using: preparation.rootPublicKey),
              signed.grant.expectedEpoch == 0,
              try preparation.greeting.matches(signed.grant) else { throw Failure.invalid }
        if let provisioned {
            // Native ROOT may produce different valid signature bytes on release.
            guard provisioned.isValidSignature(using: preparation.rootPublicKey),
                  provisioned.grant == signed.grant else { throw Failure.invalid }
        }
        provisioned = signed
        try worker.check(); try Task.checkCancellation()
        let context = Checkpoint.GrantContext(signed: signed, recipient: recipient,
            requestID: requests.probe.requestID.rawValue, serviceEpoch: nil)
        checkpoint = try Checkpoint.fresh(in: rootDirectory, backingDescriptor: backing.fileDescriptor,
            binding: binding, rootPublicKey: preparation.rootPublicKey.publicData,
            provenanceReference: provenance, initialize: context, commitHook: checkpointCommitHook)
        #if DEBUG
        try afterCheckpointFresh?()
        #endif
        intents = try HostStorageIntents.initialize(in: rootDirectory, store: binding.storeID.rawValue, provenanceReference: provenance)
    }

    /// One Guest-mutating attempt. Any uncertain result keeps the initialize fence;
    /// do not retry configure, recreate directories, or silently boot another E.
    func bootFresh(using transport: any ManagedStorageLifecycleServiceTransport,
                   expectedBinding: Boot.Binding, nowUnixSeconds: UInt64, lifetimeSeconds: UInt64) async throws {
        try begin(); defer { busy = false }
        guard !bootAttempted, let preparation, let checkpoint, intents != nil,
              let pending = try checkpoint.snapshot().pending,
              pending.signed.grant.operation == .initialize else { throw Failure.blocked }
        guard expectedBinding.bytes == binding.backing.size,
              expectedBinding.ext4UUID == binding.expectedExt4UUID.rawValue else { throw Failure.invalid }
        let configuration = Boot.Configuration(action: .initialize, rootPublicKey: preparation.rootPublicKey.publicData,
            signed: pending.signed, nowUnixSeconds: nowUnixSeconds, lifetimeSeconds: lifetimeSeconds)
        try Boot.Frame(operation: .configure, binding: expectedBinding, configuration: configuration).validate()
        // Revalidate the actual journals synchronously before the first mutation.
        _ = try intents!.checkedSnapshot()
        bootAttempted = true; service = transport
        try await worker.bind(pending.signed)
        let response = try await withTaskCancellationHandler {
            try await transport.configure(configuration)
        } onCancel: { [worker] in worker.cancel(); transport.cancel() }
        try worker.check(); try Task.checkCancellation()
        try Self.validate(response, binding: expectedBinding, grant: pending.signed.grant, root: preparation.rootPublicKey)
        boot = response
        let csr = try await worker.csr()
        let reply = try await command(.issueController, csr: csr)
        guard let certificate = reply.certificate else { throw Failure.invalid }
        let childBoot = try StorageLifecycleChildProcess.Boot(certificateDER: certificate, identity: response.ready.identity,
            rootDER: response.ready.tlsRootDER, serverSPKI: response.ready.serverSPKI,
            serviceEpoch: response.ready.serviceEpoch, signed: pending.signed)
        let stream = try await withTaskCancellationHandler {
            try await transport.connectLifecycle()
        } onCancel: { [worker] in worker.cancel(); transport.cancel() }
        defer { try? stream.close() }
        try await worker.connectBoot(stream, boot: childBoot)
        try worker.check(); try Task.checkCancellation()
        // No result is accepted from Ready/command/stream. Complete performs the
        // real independent native service-shim + child TLS-result ROOT challenge.
        try await completeLocked()
    }

    /// Every call contacts ROOT anew, including exact completed retries. A stored
    /// receipt is public audit only, never a cached authority/liveness shortcut.
    func complete() async throws {
        try begin(); defer { busy = false }
        try await completeLocked()
    }
    private func completeLocked(revalidateCensus: () throws -> Void = {}) async throws {
        try revalidateCensus()
        guard let checkpoint else { throw Failure.blocked }
        let state = try checkpoint.snapshot()
        guard state.sealed == nil, state.pendingService == nil,
              let context = state.pending ?? state.current?.original,
              context.signed.grant.operation != .retire else { throw Failure.blocked }
        if state.pending == nil, state.latestServiceConfirmation != nil {
            // Applied-grant E is immutable. After a reopen, only the separate live
            // result may establish liveness; never rewrite the original receipt.
            _ = try await verifyServiceLocked()
            try revalidateCensus()
            return
        }
        if existing, context.recipient == recipient, context.signed.grant.operation == .takeover {
            guard takeoverReconciled else { throw Failure.blocked }
        }
        let result = try await rootCompletion(context)
        try revalidateCensus()
        if let boot { guard result.serviceEpoch == boot.ready.serviceEpoch else { throw Failure.invalid } }
        try persist(.complete(result))
        try revalidateCensus()
        let trust = try await rootBootTrust(grant: context.signed.grant, serviceChangeID: nil)
        try revalidateCensus()
        let live = try await rootServiceResult(context.signed.grant)
        try revalidateCensus()
        let service = try live.state(boot: trust)
        if let boot { try Self.match(service, boot: boot) }
        try persist(.recordService(service))
        try revalidateCensus()
    }

    /// Fresh-session retirement only. No externally supplied grant/proof/result.
    /// Existing/takeover metadata cannot create an owner through this API.
    func stageRetire() async throws {
        try begin(); defer { busy = false }
        guard let checkpoint, let preparation, let recipient else { throw Failure.blocked }
        let state = try checkpoint.snapshot()
        guard state.terminal == nil, state.sealed == nil, state.pendingService == nil,
              let current = state.current, let live = state.currentContext,
              state.pending == nil || state.pending?.signed.grant.operation == .retire else { throw Failure.blocked }
        if retireRequest == nil {
            let candidate = try StorageIdentity.Candidate(publicKey: .init(rawPublicKey: recipient.publicKey),
                childPIDHint: recipient.childPID, incarnationID: .init(recipient.incarnation))
            retireRequest = try Self.request(.issue(operation: .retire, id: Self.id(), identity: state.identity,
                expectedEpoch: live.controllerEpoch, candidate: candidate))
        }
        let request = retireRequest!
        let response = try await checkedRootRequest(request)
        guard case .grant(let signed) = response.body,
              signed.isValidSignature(using: preparation.rootPublicKey),
              recipient == current.original.recipient else { throw Failure.invalid }
        try persist(.stage(.init(signed: signed, recipient: recipient, requestID: request.requestID.rawValue, serviceEpoch: live.serviceEpoch)))
    }

    /// Persisted pending retirement precedes Guest authorization and child mutation.
    /// Failure never unseals, drops a grant ID, or purports to prove a drain.
    func seal() async throws {
        try begin(); defer { busy = false }
        guard let checkpoint, let pending = try checkpoint.snapshot().pending,
              pending.signed.grant.operation == .retire else { throw Failure.blocked }
        if try checkpoint.snapshot().sealed == nil && !retirementAttempted {
            // Consume before mutation. An uncertain attempt may only be resolved
            // by fresh ROOT completion, never by replaying unsigned transport IO.
            retirementAttempted = true
            try await worker.bind(pending.signed)
            let reply = try await command(.authorizeRetirement, signed: pending.signed)
            guard reply.ok == true else { throw Failure.invalid }
            try await worker.retire()
        }
        let result = try await rootCompletion(pending)
        try persist(.seal(result))
    }

    /// Terminal metadata requires actual natively authenticated ROOT reclaim
    /// success. This never deletes the disk and returns no deletion capability.
    func reclaim() async throws {
        try begin(); defer { busy = false }
        guard let checkpoint, let seal = try checkpoint.snapshot().sealed else { throw Failure.blocked }
        if reclaimRequest == nil { reclaimRequest = try Self.request(.reclaim(identity: seal.grant.identity, id: seal.grant.id)) }
        let result = try await checkedRootRequest(reclaimRequest!)
        guard case .reclaimed = result.body else { throw Failure.invalid }
        try persist(.retire(seal))
    }

    /// Persist HOST intent before ROOT staging and any service mutation. Exact
    /// retries keep the operation ID, RPC IDs and configuration time; a timeout
    /// never abandons the original request or manufactures a new predecessor.
    func stageServiceChange(operationID: String, nowUnixSeconds: UInt64, lifetimeSeconds: UInt64) async throws {
        guard replacementIdentity == nil else { throw Failure.blocked }
        try await stageServiceChangeLockedEntry(operationID: operationID, nowUnixSeconds: nowUnixSeconds, lifetimeSeconds: lifetimeSeconds)
    }
    private func stageServiceChangeLockedEntry(operationID: String, nowUnixSeconds: UInt64, lifetimeSeconds: UInt64) async throws {
        try begin(); defer { busy = false }
        guard let checkpoint else { throw Failure.blocked }
        let state = try checkpoint.snapshot()
        guard state.pending == nil, state.sealed == nil, state.terminal == nil,
              let current = state.currentService else { throw Failure.blocked }
        let pending: Checkpoint.PendingService
        if let retained = state.pendingService {
            guard retained.request.operationID == operationID, retained.nowUnixSeconds == nowUnixSeconds,
                  retained.lifetimeSeconds == lifetimeSeconds else { throw Failure.blocked }
            pending = retained
        } else {
            // Finished operations are completed through completeServiceChange(),
            // never re-staged with their now-obsolete predecessor.
            guard operationID != state.latestServiceRequest?.request.operationID else { throw Failure.blocked }
            guard let boot else { throw Failure.blocked }
            try Self.match(current, boot: boot)
            pending = try .init(request: .init(operationID: operationID, predecessor: current),
                stageRequestID: Self.id(), completionRequestID: Self.id(), predecessorWorkerUUID: boot.ready.workerUUID,
                nowUnixSeconds: nowUnixSeconds, lifetimeSeconds: lifetimeSeconds)
        }
        workloadConnected = false
        try persist(.stageService(pending))
        try await stageRootService(pending)
    }

    /// Native same-C replacement. The task and operation fence survive caller
    /// cancellation and all ambiguous results; only owner shutdown cancels it.
    func replaceService(operationID: String, predecessor: StorageServiceTypes.Scope,
                        nowUnixSeconds: UInt64, lifetimeSeconds: UInt64,
                        names: SharedVolumeInitializationCoordinator) async throws -> ServiceReplacementMaintenance {
        #if DEBUG
        let attemptTimeout = replacementAttemptTimeoutForTesting
        #else
        let attemptTimeout: TimeInterval = 30
        #endif
        guard attemptTimeout.isFinite, attemptTimeout > 0, attemptTimeout <= 30 else { throw Failure.invalid }
        if let retained = replacementIdentity {
            guard retained.operation == operationID, retained.scope == predecessor,
                  retained.now == nowUnixSeconds, retained.lifetime == lifetimeSeconds,
                  let replacementTask else { throw Failure.blocked }
            if !replacementRetryable { return try await replacementTask.value }
        }
        try begin(); defer { busy = false }
        let state = try physicalState()
        guard let boot, let old = workloadLifecycle, let intents,
              state.pending == nil, (state.pendingService == nil || replacementRetryable), state.pendingCold == nil,
              state.sealed == nil, state.terminal == nil,
              predecessor == .init(serviceEpoch: boot.ready.serviceEpoch, workerUUID: boot.ready.workerUUID) else {
            throw Failure.blocked
        }
        let identity = replacementIdentity?.id ?? UUID()
        replacementRetryable = false
        replacementTimeoutBoundary = nil
        replacementIdentity = (identity, operationID, predecessor, nowUnixSeconds, lifetimeSeconds)
        workloadConnected = false // Fence before either durable write or suspension.
        let task = Task { @MainActor in
            await old.invalidate()
            try intents.requireReconciliation()
            if try self.physicalState().serviceReplacement == nil {
                try await self.stageServiceChangeLockedEntry(operationID: operationID, nowUnixSeconds: nowUnixSeconds,
                    lifetimeSeconds: lifetimeSeconds)
            }
            try self.begin(); defer { self.busy = false }
            guard let pending = try self.physicalState().pendingService,
                  let request = try self.physicalState().serviceReplacement else { throw Failure.blocked }
            try self.persist(.attemptNativeReplacement)
            let ready: ManagedStorageLifecycleServiceReady
            do {
                ready = try await self.pollReplacement(request, pending: pending, predecessor: boot,
                    deadline: ProcessInfo.processInfo.systemUptime + attemptTimeout)
            } catch is ReplacementAttemptExpired {
                self.replacementRetryable = true
                let boundary = RetryableReplacementTimeout(request: .init(operationUUID: operationID,
                    predecessor: predecessor, nowUnixSeconds: nowUnixSeconds))
                self.replacementTimeoutBoundary = boundary
                throw boundary
            }
            guard let preparation = self.preparation, let service = self.service else { throw Failure.blocked }
            try Self.validate(ready, binding: boot.binding, grant: pending.request.predecessor.grant,
                root: preparation.rootPublicKey)
            guard ready.ready.workerUUID != pending.predecessorWorkerUUID else { throw Failure.invalid }
            #if CENGINE_COMPAT_LIFECYCLE_FAULT
            try await StorageLifecycleCompatibilityFaultPolicy.afterReplacementBeforeCompletion(
                .init(request: pending.request, successor: Self.serviceState(ready, grant: pending.request.predecessor.grant)),
                predecessorWorkerUUID: pending.predecessorWorkerUUID, workerUUID: ready.ready.workerUUID)
            #endif
            let trust = try await self.rootBootTrust(grant: pending.request.predecessor.grant, serviceChangeID: operationID)
            try pending.request.validateSuccessorBoot(trust)
            guard try Self.serviceState(ready, grant: pending.request.predecessor.grant).boot == trust else { throw Failure.invalid }
            try self.requireServiceChange(pending)
            self.boot = ready
            let csr = try await self.worker.csr()
            let issued = try await self.command(.issueController, csr: csr)
            guard let certificate = issued.certificate else { throw Failure.invalid }
            let childBoot = try StorageLifecycleChildProcess.Boot(certificateDER: certificate,
                identity: ready.ready.identity, rootDER: ready.ready.tlsRootDER, serverSPKI: ready.ready.serverSPKI,
                serviceEpoch: ready.ready.serviceEpoch, signed: request.configuration.signed)
            let stream = try await service.connectLifecycle()
            defer { try? stream.close() }
            try self.requireServiceChange(pending)
            try await self.worker.stageServiceRebind(stream, change: pending.request, boot: childBoot)
            try self.requireServiceChange(pending)
            try await self.completeServiceChangeLocked() // Fresh ROOT authentication, not Ready authority.
            _ = try await self.verifyServiceLocked()
            let workload = try await service.connectWorkload()
            defer { try? workload.close() }
            try await self.worker.connectWorkload(workload)
            let context = try self.workloadContext()
            let bytes = try await self.worker.workload(.query)
            guard case .snapshot(let query) = try ManagedStorageControlClient.decode(bytes, for: .query, context: context) else {
                throw Failure.invalid
            }
            try ManagedStorageControlClient.validate(query, context: context)
            let completed = try self.physicalState()
            guard try self.workloadContext() == context,
                  let confirmation = completed.latestServiceConfirmation,
                  confirmation.request == pending.request,
                  let link = completed.latestServiceChange,
                  try Checkpoint.censusMatches(completed, intents: intents.checkedSnapshot()) else { throw Failure.blocked }
            // Do not promote forgeable older checkpoint history. This minimal
            // contract admits only this freshly ROOT-authenticated immediate edge.
            let required = try Checkpoint.requiredContexts(completed)
            guard required.isSubset(of: [link.predecessor, link.successor]) else { throw Failure.blocked }
            let authorization = try ReplacementRecoveryAuthorization(current: context,
                predecessor: link.predecessor, reference: link.reference)
            let recovery = try ManagedStorageControllerRecovery.lifecycleReplacement(authorization)
            let control = ManagedStorageLifecycleWorkloadControl(owner: self, context: context,
                maintenance: MaintenanceCapability(owner: identity))
            let fresh = try ManagedVolumeLifecycleCoordinator(journal: intents, control: control, names: names, recovery: recovery)
            try self.worker.publish(())
            self.recoveryPermission = (context, recovery)
            self.workloadLifecycle = fresh; self.workloadConnected = true
            return ServiceReplacementMaintenance(owner: identity, request: request, lifecycle: fresh, context: context,
                serviceScope: .init(serviceEpoch: ready.ready.serviceEpoch, workerUUID: ready.ready.workerUUID))
        }
        replacementTask = task
        busy = false
        return try await task.value
    }

    private func pollReplacement(_ request: Boot.ReplacementRequest, pending: Checkpoint.PendingService,
                                 predecessor: ManagedStorageLifecycleServiceReady,
                                 deadline: TimeInterval) async throws -> ManagedStorageLifecycleServiceReady {
        guard let service else { throw Failure.blocked }
        func checkBudget() throws {
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw ReplacementAttemptExpired() }
        }
        func pause() async throws {
            try checkBudget()
            try await Task.sleep(for: .seconds(min(0.2, max(0, deadline - ProcessInfo.processInfo.systemUptime))))
        }
        while true {
            try checkBudget()
            try requireServiceChange(pending)
            guard try physicalState().serviceReplacement == request, sequence < UInt64.max else { throw Failure.blocked }
            sequence += 1
            let frame = Boot.Frame(operation: .command, binding: predecessor.binding, sequence: sequence,
                serviceEpoch: predecessor.ready.serviceEpoch, command: replacementAdmitted ? .replacementStatus : .replaceService,
                workerUUID: predecessor.ready.workerUUID, replacementRequest: replacementAdmitted ? nil : request)
            try frame.validate()
            let reply: Boot.Frame
            do { reply = try await service.command(frame) }
            catch {
                try requireServiceChange(pending)
                // Lost transport result is neither admission nor death. Replay the
                // identical signed operation; after admission, poll only its pair.
                try await pause(); continue
            }
            try requireServiceChange(pending); try reply.validate()
            guard reply.operation == .reply, reply.binding == frame.binding, reply.sequence == frame.sequence,
                  reply.serviceEpoch == frame.serviceEpoch, reply.workerUUID == frame.workerUUID,
                  reply.code == nil, let status = reply.replacement, status.request == request else { throw Failure.invalid }
            replacementAdmitted = true
            // Retain admission even when the reply consumed this attempt's budget.
            // Timeout is not worker death and never authorizes configure fallback.
            switch status.phase {
            case .pending: try await pause()
            case .failed: throw Failure.blocked // Terminal, even after the budget expires.
            case .succeeded:
                try checkBudget()
                guard let ready = status.ready else { throw Failure.invalid }
                return .init(binding: predecessor.binding, ready: ready)
            }
        }
    }

    private func requireMaintenance(_ session: ServiceReplacementMaintenance) throws {
        try worker.check(); try Task.checkCancellation()
        guard replacementIdentity?.id == session.owner, replacementTask != nil,
              workloadLifecycle === session.lifecycle, workloadConnected,
              try workloadContext() == session.context,
              try physicalState().serviceReplacement == session.request else { throw Failure.blocked }
    }
    /// Checked public projection only; the maintenance lease remains the authority.
    func maintenanceServiceProjection(_ session: ServiceReplacementMaintenance) throws -> ManagedStorageLifecycleServiceReady {
        try requireMaintenance(session)
        guard try workloadContext() == session.context, let boot else { throw Failure.blocked }
        return boot
    }
    func maintenanceSnapshot(_ session: ServiceReplacementMaintenance) throws -> ManagedStorageJournalSnapshot {
        try requireMaintenance(session)
        return try journalSnapshot()
    }
    func planReplacementVolumes(_ volumes: [VolumeRecord], session: ServiceReplacementMaintenance) throws {
        try requireMaintenance(session)
        guard !busy, workloadCalls == 0, !serviceCommandActive, let intents else { throw Failure.blocked }
        let additions = try ManagedStorageJournalPolicy.volumeAdditions(volumes, existing: intents.checkedSnapshot().volumes)
        if !additions.isEmpty { try session.lifecycle.planVolumes(additions) }
    }
    /// Inventory commit is mandatory, synchronous, and still behind the fence.
    /// The callback MUST be idempotent: it can commit durably and then throw.
    /// A thrown commit retains the session/task so an exact retry can finish it.
    func completeServiceReplacement(_ session: ServiceReplacementMaintenance,
                                    commitInventory: () throws -> Void) throws {
        try requireMaintenance(session)
        guard !busy, workloadCalls == 0, !serviceCommandActive, let intents,
              try !intents.checkedSnapshot().reconciliationRequired,
              let service = try physicalState().currentService else { throw Failure.blocked }
        busy = true; defer { busy = false } // Also excludes synchronous callback reentry.
        try commitInventory()
        try requireMaintenance(session)
        guard try !intents.checkedSnapshot().reconciliationRequired else { throw Failure.blocked }
        try persist(.recordService(service)) // Fold exact post-reconciliation physical census.
        replacementIdentity = nil; replacementTask = nil
    }

    /// The transport owner must first join/reap the previous disk writer. Transport
    /// metadata is not that proof: Guest also checks the exact grant/open anchor
    /// under its writer lock, and ROOT independently authenticates the new boot.
    /// This is one configure attempt, NOT a worker-restart/adoption implementation.
    func reopenService(using transport: any ManagedStorageLifecycleServiceTransport,
                       expectedBinding: Boot.Binding) async throws {
        guard replacementIdentity == nil else { throw Failure.blocked }
        try begin(); defer { busy = false }
        guard let checkpoint, let preparation else { throw Failure.blocked }
        let state = try checkpoint.snapshot()
        guard let pending = state.pendingService, let current = state.current,
              state.nativeReplacementAttempted != true,
              serviceChangeAttempted != pending.request.operationID,
              expectedBinding.bytes == binding.backing.size,
              expectedBinding.ext4UUID == binding.expectedExt4UUID.rawValue else { throw Failure.blocked }
        guard state.rootPublicKey == preparation.rootPublicKey.publicData else { throw Failure.invalid }
        try await withTaskCancellationHandler {
            // A lost staging reply is resolved with exactly the persisted request
            // BEFORE configure. No new operation or deadlines are selected here.
            // Guest accepts only ROOT's signature over this exact request.
            let signedChange = try await stageRootService(pending)
            let configuration = Boot.Configuration(action: .open, rootPublicKey: state.rootPublicKey,
                signed: current.original.signed, nowUnixSeconds: pending.nowUnixSeconds,
                lifetimeSeconds: pending.lifetimeSeconds, reopen: signedChange)
            try configuration.validate()
            try requireServiceChange(pending)
            workloadConnected = false
            serviceChangeAttempted = pending.request.operationID
            service = transport; sequence = 0
            let response = try await transport.configure(configuration)
            try requireServiceChange(pending)
            try Self.validate(response, binding: expectedBinding, grant: current.original.signed.grant,
                root: preparation.rootPublicKey)
            let trust = try await rootBootTrust(grant: current.original.signed.grant,
                serviceChangeID: pending.request.operationID)
            try pending.request.validateSuccessorBoot(trust)
            let claimed = try Self.serviceState(response, grant: current.original.signed.grant)
            guard claimed.boot == trust, claimed.openRevision > pending.request.predecessor.openRevision else { throw Failure.invalid }
            try requireServiceChange(pending)
            boot = response
            let csr = try await worker.csr()
            let reply = try await command(.issueController, csr: csr)
            guard let certificate = reply.certificate else { throw Failure.invalid }
            let childBoot = try StorageLifecycleChildProcess.Boot(certificateDER: certificate, identity: response.ready.identity,
                rootDER: response.ready.tlsRootDER, serverSPKI: response.ready.serverSPKI,
                serviceEpoch: response.ready.serviceEpoch, signed: current.original.signed)
            let stream = try await transport.connectLifecycle()
            defer { try? stream.close() }
            try requireServiceChange(pending)
            try await worker.stageServiceRebind(stream, change: pending.request, boot: childBoot)
            try requireServiceChange(pending)
            try await completeServiceChangeLocked()
        } onCancel: { [worker] in worker.cancel(); transport.cancel() }
    }

    /// Every call re-challenges ROOT, including a completed retry. The helper alone
    /// commits the child's staged TLS binding; the parent has no promotion operation.
    func completeServiceChange() async throws {
        guard replacementIdentity == nil else { throw Failure.blocked }
        try begin(); defer { busy = false }
        try await completeServiceChangeLocked()
    }
    private func completeServiceChangeLocked() async throws {
        guard let checkpoint, let boot else { throw Failure.blocked }
        let state = try checkpoint.snapshot()
        guard state.pending == nil, state.sealed == nil, state.terminal == nil,
              let retained = state.pendingService ?? state.latestServiceRequest else { throw Failure.blocked }
        let request = try Root.Request(requestID: .init(retained.completionRequestID),
            body: .completeServiceChange(identity: state.identity, operationID: retained.request.operationID))
        let reply = try await checkedRootRequest(request)
        guard case .serviceChanged(let confirmation, let result) = reply.body,
              confirmation.request == retained.request,
              try result.state(boot: confirmation.successor.boot) == confirmation.successor else { throw Failure.invalid }
        try Self.match(confirmation.successor, boot: boot)
        try persist(.confirmService(confirmation))
        // Workload remains disconnected until a fresh live proof and child connect.
    }
    @discardableResult
    private func stageRootService(_ pending: Checkpoint.PendingService) async throws -> L.SignedServiceChange {
        try requireServiceChange(pending)
        guard let preparation else { throw Failure.blocked }
        let request = try Root.Request(requestID: .init(pending.stageRequestID), body: .stageServiceChange(change: pending.request))
        let reply = try await checkedRootRequest(request)
        guard case .serviceChangeStaged(let staged) = reply.body, staged.request == pending.request,
              staged.isValidSignature(using: preparation.rootPublicKey) else { throw Failure.invalid }
        try requireServiceChange(pending)
        guard let current = try checkpoint?.snapshot().current else { throw Failure.blocked }
        let configuration = Boot.Configuration(action: .open, rootPublicKey: preparation.rootPublicKey.publicData,
            signed: current.original.signed, nowUnixSeconds: pending.nowUnixSeconds,
            lifetimeSeconds: pending.lifetimeSeconds, reopen: staged)
        if let retained = try checkpoint?.snapshot().serviceReplacement {
            // ROOT may re-sign a valid retry with different signature bytes. The
            // native operation must keep the FIRST exact signed envelope forever.
            guard retained.predecessorWorkerUUID == pending.predecessorWorkerUUID,
                  let original = retained.configuration.reopen, original.request == staged.request,
                  original.isValidSignature(using: preparation.rootPublicKey) else { throw Failure.invalid }
            return original
        }
        try persist(.authorizeServiceReplacement(.init(predecessorWorkerUUID: pending.predecessorWorkerUUID,
            configuration: configuration)))
        return staged
    }
    private func requireServiceChange(_ pending: Checkpoint.PendingService) throws {
        try worker.check(); try Task.checkCancellation()
        guard let checkpoint, let intents else { throw Failure.blocked }
        let state = try checkpoint.snapshot()
        _ = try intents.checkedSnapshot()
        guard state.pendingService == pending, state.currentService == pending.request.predecessor,
              state.pending == nil, state.sealed == nil, state.terminal == nil else { throw Failure.blocked }
    }

    /// Connect IO only after fresh ROOT live-service proof; does not mint an authorization
    /// from transport metadata. The child retains its independently audited trust.
    func connectWorkload() async throws {
        _ = try await connectWorkload(recordObservation: true)
    }

    private func connectWorkload(recordObservation: Bool) async throws -> L.ServiceState {
        guard replacementIdentity == nil, boot == nil || fencedWorkloadBoot != boot else { throw Failure.blocked }
        try begin(); defer { busy = false }
        guard let checkpoint, let service else { throw Failure.blocked }
        let state = try checkpoint.snapshot()
        guard state.current != nil, state.pending == nil, state.pendingService == nil,
              state.sealed == nil else { throw Failure.blocked }
        workloadConnected = false
        _ = try workloadContext()
        return try await withTaskCancellationHandler {
            let live = try await verifyServiceLocked(recordObservation: recordObservation)
            let stream = try await service.connectWorkload()
            defer { try? stream.close() }
            try await worker.connectWorkload(stream)
            _ = try workloadContext()
            #if DEBUG
            try await beforeWorkloadConnectionPublication?()
            #endif
            try worker.publish(())
            workloadConnected = true
            return live
        } onCancel: { [worker] in worker.cancel(); service.cancel() }
    }

    /// Read-only Query over the nonexporting child's v3 channel. Mutation admission
    /// belongs to the journal-backed workload coordinator, never this query seam.
    /// The entire call is joined on the dedicated worker; both physical HOST
    /// journals and the exact identity/E/C/key are checked before publication.
    /// A decoded Query is data, never a recovery capability.
    func queryWorkload() async throws -> ManagedStorageControlClient.Snapshot {
        guard replacementIdentity == nil else { throw Failure.blocked }
        try begin(); defer { busy = false }
        guard workloadConnected else { throw Failure.blocked }
        let context = try workloadContext()
        do {
            return try await withTaskCancellationHandler {
                let bytes = try await worker.workload(.query)
                guard case .snapshot(let reply) = try ManagedStorageControlClient.decode(bytes, for: .query, context: context) else {
                    throw Failure.invalid
                }
                #if DEBUG
                try await afterWorkloadDecode?()
                #endif
                guard try workloadContext() == context else { throw Failure.blocked }
                return try worker.publish(reply)
            } onCancel: { [worker] in worker.cancel() }
        } catch ManagedStorageControlClient.Failure.remote(let code) {
            // Same as workloadControl: changed HOST state fences before surfacing.
            guard workloadConnected, (try? workloadContext()) == context else {
                workloadConnected = false; cancel(); throw Failure.blocked
            }
            throw ManagedStorageControlClient.Failure.remote(code)
        } catch {
            // A corrupt/uncertain/stale reply cannot be retried on this generation.
            // Revocation and EOF are not drain, recovery or deletion authority.
            workloadConnected = false
            cancel()
            throw error
        }
    }

    /// One joined workload exchange for ManagedStorageLifecycleWorkloadControl.
    /// Durable operation recording is the coordinator's job and precedes this.
    func workloadControl(_ request: ManagedStorageControlProtocol.ControlRequest,
                         context expected: ManagedStorageControlClient.Context,
                         maintenance: MaintenanceCapability? = nil) async throws -> ManagedStorageControlClient.Reply {
        if let replacementIdentity {
            guard maintenance?.owner == replacementIdentity.id else { throw Failure.blocked }
        }
        try worker.check(); try Task.checkCancellation()
        guard !busy, !workloadRetireActive, workloadConnected, try workloadContext() == expected else { throw Failure.blocked }
        // Retire owns the child WORKLOAD lane through its one optional reconnect.
        // Private PREPARE/status IO must remain independent: Retire may be waiting
        // for its release. workloadCalls already excludes lifecycle mutation.
        let retiring: Bool
        if case .retire = request { retiring = true } else { retiring = false }
        if retiring {
            guard workloadCalls == 0 else { throw Failure.blocked }
            workloadRetireActive = true
        }
        workloadCalls += 1
        defer { workloadCalls -= 1; if retiring { workloadRetireActive = false } }
        let generation = boot
        let maintenanceOwner = replacementIdentity?.id
        var retried = false
        var preflightFailureHandled = false
        var failureState: Checkpoint.Metadata?
        do {
            let frozenState = try physicalState()
            failureState = frozenState
            return try await withTaskCancellationHandler {
                let bytes: Data
                do { bytes = try await worker.workload(request) }
                catch StorageLifecycleChildProcess.Failure.serviceUnavailable where retiring {
                    // EOF is not worker-death authority. Join private Wait and
                    // ask the retained service as a reconnect optimization only:
                    // a ready worker can still die before the child connects.
                    if maintenanceOwner == nil {
                        do {
                            let ready = try await retireWorkerReady(context: expected, state: frozenState,
                                generation: generation)
                            if !ready {
                                preflightFailureHandled = true
                                throw StorageLifecycleChildProcess.Failure.serviceUnavailable
                            }
                        } catch {
                            if !preflightFailureHandled {
                                freezeWorkload(); cancel(); preflightFailureHandled = true
                            }
                            throw StorageLifecycleChildProcess.Failure.serviceUnavailable
                        }
                    }
                    retried = true
                    try await reconnectRetireWorkload(context: expected, state: frozenState,
                        generation: generation, maintenanceOwner: maintenanceOwner, maintenance: maintenance)
                    // No loop: a second loss, refusal, cancellation or malformed
                    // response follows the ordinary permanent-fence path.
                    bytes = try await worker.workload(request)
                }
                if retiring {
                    guard boot == generation, replacementIdentity?.id == maintenanceOwner,
                          try physicalState() == frozenState else { throw Failure.blocked }
                }
                let reply = try ManagedStorageControlClient.decode(bytes, for: request, context: expected)
                #if DEBUG
                try await afterWorkloadDecode?()
                #endif
                guard workloadConnected, try workloadContext() == expected else { throw Failure.blocked }
                if retiring {
                    guard boot == generation, replacementIdentity?.id == maintenanceOwner,
                          try physicalState() == frozenState else { throw Failure.blocked }
                }
                return try worker.publish(reply)
            } onCancel: { [worker] in worker.cancel() }
        } catch ManagedStorageControlClient.Failure.remote(let code) {
            // First remote refusals retain the existing contract. Any second
            // attempt failure fences, even when it is a correlated remote refusal.
            guard !retried, workloadConnected, (try? workloadContext()) == expected else {
                workloadConnected = false; cancel(); throw Failure.blocked
            }
            throw ManagedStorageControlClient.Failure.remote(code)
        } catch {
            // Preflight already classified loss or fenced uncertainty. Do not
            // probe again or cancel the retained authenticated-loss owner.
            if preflightFailureHandled { throw error }
            // Fence old-E work immediately, but do not destroy an admitted private
            // exchange (notably PID1 Wait) before querying actual worker liveness.
            // The original workload error still propagates; loss grants no receipt.
            freezeWorkload()
            if error is CancellationError { cancel() }
            else if !(await retainOwnerAfterWorkerLoss(
                context: expected, generation: generation, state: failureState)) { cancel() }
            throw error
        }
    }

    private func freezeWorkload() {
        workloadConnected = false
        fencedWorkloadBoot = boot
    }

    /// This is production liveness discrimination, not a compatibility exception.
    /// No workload retry or lifecycle mutation occurs here. Join private PREPARE
    /// first, with one bounded budget, then ask the exact retained native service.
    private func retainOwnerAfterWorkerLoss(context: ManagedStorageControlClient.Context,
        generation: ManagedStorageLifecycleServiceReady?, state: Checkpoint.Metadata?) async -> Bool {
        do {
            guard let generation, let state, replacementIdentity == nil else { return false }
            let deadline = DispatchTime.now().uptimeNanoseconds + 30_000_000_000
            func unchanged() throws {
                try worker.check(); try Task.checkCancellation()
                guard boot == generation, replacementIdentity == nil,
                      try physicalState() == state, try workloadContext() == context,
                      DispatchTime.now().uptimeNanoseconds < deadline else { throw Failure.blocked }
            }
            try unchanged()
            while !prepareStorageCommands.tryPoll() {
                try await Task.sleep(nanoseconds: 5_000_000)
                try unchanged()
            }
            defer { prepareStorageCommands.release() }
            try unchanged()
            let reply = try await prepareStorageExchange(.serviceStatus,
                current: (context, generation), deadlineNanoseconds: deadline) { _ in }
            try unchanged()
            guard reply.code == .workerLost || reply.status?.phase == .workerLost else { return false }
            authenticatedWorkerLoss = generation
            return true
        } catch { return false }
    }

    /// A bounded private preflight only; release this lane before any ROOT or
    /// workload reconnect IO so PREPARE release remains independently admissible.
    private func retireWorkerReady(context: ManagedStorageControlClient.Context,
        state: Checkpoint.Metadata, generation: ManagedStorageLifecycleServiceReady?) async throws -> Bool {
        guard let generation else { throw Failure.blocked }
        let deadline = DispatchTime.now().uptimeNanoseconds + 30_000_000_000
        func unchanged() throws {
            try worker.check(); try Task.checkCancellation()
            guard !busy, workloadRetireActive, workloadCalls == 1, workloadConnected,
                  boot == generation, replacementIdentity == nil,
                  try physicalState() == state, try workloadContext() == context,
                  DispatchTime.now().uptimeNanoseconds < deadline else { throw Failure.blocked }
        }
        try unchanged()
        // Join both an admitted checkpoint Wait and any prior read-only envelope.
        // No actor suspension occurs between this admission and exchange's send.
        while serviceCommandActive || !prepareStorageCommands.tryPoll() {
            try await Task.sleep(nanoseconds: 5_000_000)
            try unchanged()
        }
        defer { prepareStorageCommands.release() }
        try unchanged()
        let reply = try await prepareStorageExchange(.serviceStatus,
            current: (context, generation), deadlineNanoseconds: deadline) { _ in }
        try unchanged()
        if reply.code == .workerLost || reply.status?.phase == .workerLost {
            freezeWorkload(); authenticatedWorkerLoss = generation
            return false
        }
        guard reply.code == nil, reply.status?.phase == .ready else { throw Failure.blocked }
        return true
    }

    /// Internal owned lane: never calls begin(), mints a grant, mutates a
    /// checkpoint, replaces the child or changes the frozen Retire operation.
    private func reconnectRetireWorkload(context: ManagedStorageControlClient.Context,
                                        state: Checkpoint.Metadata,
                                        generation: ManagedStorageLifecycleServiceReady?,
                                        maintenanceOwner: UUID?, maintenance: MaintenanceCapability?) async throws {
        guard let service else { throw Failure.blocked }
        func revalidate() throws {
            try worker.check(); try Task.checkCancellation()
            guard !busy, workloadRetireActive, workloadCalls == 1, workloadConnected,
                  boot == generation, replacementIdentity?.id == maintenanceOwner,
                  maintenanceOwner == nil || maintenance?.owner == maintenanceOwner,
                  try physicalState() == state, try workloadContext() == context else { throw Failure.blocked }
        }
        try revalidate()
        // Keep the authenticated private service transport alive while only the
        // WORKLOAD stream reconnects; the preflight command lane is already free.
        // Any failure below still fences the owner.
        try await withTaskCancellationHandler {
            // Do not repeat ROOT live proof for this same-generation reconnect:
            // worker death after preflight could make ROOT revoke the retained
            // child needed for replacement. The child proves fresh guest service
            // state and authenticates TLS against its frozen ROOT boot trust.
            let stream = try await service.connectWorkload()
            defer { try? stream.close() }
            try revalidate()
            // connectWorkload independently obtains the child's fresh ServiceResult
            // before authenticating the new stream with its retained E/C/key.
            try await worker.connectWorkload(stream)
            try revalidate()
            try worker.publish(())
            // Reconnect preserves an admitted generation; it must never revive
            // one fenced by an independent authenticated worker-loss reply.
        } onCancel: { [worker] in worker.cancel(); service.cancel() }
    }

    /// Coordinator bound to this owner's single HOST intents journal. Never mints
    /// ControllerRecovery: an existing owner requires recoverWorkload's permission.
    func makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator) throws -> ManagedVolumeLifecycleCoordinator {
        try worker.check(); try Task.checkCancellation()
        guard replacementIdentity == nil, !busy, workloadConnected, workloadLifecycle == nil, let intents,
              initialization == nil || initializationAdmitted else { throw Failure.blocked }
        let context = try workloadContext()
        var recovery: ManagedStorageControllerRecovery?
        if existing {
            guard let permission = recoveryPermission, permission.context == context else { throw Failure.blocked }
            recovery = permission.recovery
        }
        let control = ManagedStorageLifecycleWorkloadControl(owner: self, context: context)
        let coordinator = try ManagedVolumeLifecycleCoordinator(journal: intents, control: control, names: names, recovery: recovery)
        workloadLifecycle = coordinator
        return coordinator
    }

    func validateUnusedInitializationCensus() throws {
        guard let intents, let checkpoint else { throw Failure.blocked }
        let census = try intents.checkedSnapshot()
        try ManagedStorageInitialization.requireEmpty(census)
        guard try Checkpoint.censusMatches(checkpoint.snapshot(), intents: census) else { throw Failure.blocked }
    }

    func admitInitialization() async throws {
        guard let initialization, let intents, let checkpoint,
              try initialization.hasCompletedPair(in: rootDirectory) else { throw Failure.blocked }
        let (live, query) = try await initialization.preservingEvidence(in: rootDirectory) {
            // Keep the whole-journal byte guard intact. The fresh worker projection
            // is staged only after this exchange and the physical census succeed.
            let live = try await connectWorkload(recordObservation: false)
            return (live, try await queryWorkload())
        }
        guard query.volumes.isEmpty, query.volumeLifecycles.isEmpty, query.prepares.isEmpty,
              query.attachments.isEmpty else { throw Failure.blocked }
        let census = try intents.checkedSnapshot()
        try ManagedStorageInitialization.requireEmpty(census)
        guard try Checkpoint.censusMatches(checkpoint.snapshot(), intents: census) else { throw Failure.blocked }
        _ = try workloadContext()
        try recordVerifiedService(live)
        try initialization.retain("admitted.json", true)
        initializationAdmitted = true
    }

    /// Read-only journal projection. Deliberately NOT gated on the live connected
    /// generation: after a fence, callers plan/report unresolved intents from it.
    /// It is never admission, credential or recovery authority.
    func journalSnapshot() throws -> ManagedStorageJournalSnapshot {
        guard workloadLifecycle != nil, let intents else { throw Failure.blocked }
        _ = try physicalState()
        let state = try intents.snapshot()
        return .init(revision: state.revision, volumes: state.volumes.values.sorted { $0.id < $1.id },
            intents: state.intents.values.sorted { $0.id < $1.id }, reconciliationRequired: state.reconciliationRequired)
    }
    func token(for id: String) throws -> HostStorageIntents.Token {
        guard replacementIdentity == nil, workloadConnected, workloadLifecycle != nil, let intents else { throw Failure.blocked }
        _ = try workloadContext()
        return try intents.token(for: id)
    }
    /// Replays preserve operation IDs; omitted records never erase tombstones.
    func planVolumes(_ volumes: [VolumeRecord]) throws {
        guard replacementIdentity == nil, workloadConnected, let workloadLifecycle, let intents else { throw Failure.blocked }
        _ = try workloadContext()
        let additions = try ManagedStorageJournalPolicy.volumeAdditions(volumes, existing: intents.snapshot().volumes)
        if !additions.isEmpty { try workloadLifecycle.planVolumes(additions) }
    }

    /// Only current, undrained frozen journal bindings with a durable register
    /// operation receive a certificate. Every suspension revalidates.
    func attachmentCertificate(intent token: HostStorageIntents.Token, attachment: String, csr: Data) async throws -> Data {
        try worker.check(); try Task.checkCancellation()
        guard replacementIdentity == nil, !busy, !workloadRetireActive, workloadConnected, workloadLifecycle != nil, let intents, let service else { throw Failure.blocked }
        let context = try workloadContext()
        let identity = try snapshot().identity
        func eligible() throws -> HostStorageIntents.Intent {
            let intent = try intents.intent(token)
            guard workloadConnected, try workloadContext() == context, intent.store == context.store,
                  intent.serviceEpoch == context.serviceEpoch, intent.controllerEpoch == context.controllerEpoch,
                  intent.controllerKey == context.controllerKey,
                  let slot = intent.slots.first(where: { $0.attachment == attachment }), slot.receipt == nil,
                  try intents.snapshot().operations[slot.registerOperation] != nil else { throw Failure.blocked }
            try ManagedStorageJournalPolicy.requireCertificateEligible(intent, attachment: attachment)
            return intent
        }
        let intent = try eligible()
        let slot = intent.slots.first { $0.attachment == attachment }!
        let request = try StorageLifecycleChildProcess.AttachmentCertificateRequest(binding: slot.binding(store: intent.store,
            prepare: intent.prepare, container: intent.container, launch: intent.launch), serviceEpoch: intent.serviceEpoch,
            controllerEpoch: context.controllerEpoch, csr: csr, identity: identity)
        workloadCalls += 1; defer { workloadCalls -= 1 }
        return try await withTaskCancellationHandler {
            let stream = try await service.connectAttachmentCSR()
            defer { try? stream.close() }
            _ = try eligible()
            let der: Data?
            do {
                der = try await worker.attachmentCertificate(stream, request: request)
                // Closure, quarantine or retirement may win while issuance is in flight.
                _ = try eligible()
            } catch {
                // Uncertain issuance may have committed: fence this generation.
                workloadConnected = false
                cancel()
                throw error
            }
            guard let der else { throw Failure.blocked }
            return try worker.publish(der)
        } onCancel: { [worker] in worker.cancel(); service.cancel() }
    }

    /// Existing-store owners require cold-restart design before backend adoption.
    var isExistingStore: Bool { existing }

    /// Checked projection (NOT a capability) of the live, connected, unfenced
    /// workload generation. Never a VerifiedStorageServiceBoot.
    func workloadSession() throws -> (context: ManagedStorageControlClient.Context, service: ManagedStorageLifecycleServiceReady) {
        try worker.check(); try Task.checkCancellation()
        guard replacementIdentity == nil, !busy, workloadConnected, workloadLifecycle != nil, let boot else { throw Failure.blocked }
        let context = try workloadContext()
        return (context, boot)
    }

    /// A process-local observation lease. Construction stays with this owner, not
    /// decoded Ready metadata. Its exchange retains the actual private transport.
    @MainActor struct OriginalConsumerSession {
        let service: ManagedStorageLifecycleServiceReady
        let request: StorageServiceTypes.ReplacementRequest
        fileprivate let lifecycle: ManagedVolumeLifecycleCoordinator
        fileprivate let validate: @MainActor () throws -> Void
        fileprivate let send: @MainActor (Boot.Command, ConsumerObservationProtocol.Arm, @escaping @MainActor () throws -> Void) async throws -> ConsumerObservationProtocol.Status
        func check() throws { try validate() }
        func retireOriginalConsumer(_ binding: OriginalConsumerObservationProtocol.Binding,
            revalidate: @MainActor () throws -> Void) async throws -> ManagedVolumeLifecycleCoordinator.OriginalRetirement {
            try check(); try revalidate()
            do {
                let result = try await lifecycle.retireOriginalConsumer(binding, revalidate: {
                    try check(); try revalidate()
                })
                try check()
                return result
            } catch { try check(); throw error }
        }
        func observeOriginalRegistration(_ binding: OriginalConsumerObservationProtocol.Binding,
            revalidate: @MainActor (ManagedVolumeLifecycleCoordinator.OriginalRetirement?) throws -> Void,
            probe: @MainActor (ManagedVolumeLifecycleCoordinator.OriginalRetirement?) async throws -> Void) async throws -> ManagedVolumeLifecycleCoordinator.OriginalRegistrationAuthority {
            try check()
            do {
                let result = try await lifecycle.observeOriginalRegistration(binding, revalidate: { receipt in
                    try check(); try revalidate(receipt)
                }, probe: { receipt in
                    try check()
                    do { try await probe(receipt) } catch { try check(); throw error }
                    try check()
                })
                try check()
                return result
            } catch { try check(); throw error }
        }
        func withOriginalRootAuthority(_ binding: OriginalConsumerObservationProtocol.Binding,
            target: ConsumerObservationProtocol.Original,
            revalidate: @MainActor (ManagedVolumeLifecycleCoordinator.OriginalRetirement?) throws -> Void,
            probe: @MainActor (ManagedVolumeLifecycleCoordinator.OriginalRetirement?) async throws -> Void) async throws -> ManagedVolumeLifecycleCoordinator.OriginalRootAuthority {
            try check()
            do {
                let result = try await lifecycle.withOriginalRootAuthority(binding, target: target, revalidate: { receipt in
                    try check(); try revalidate(receipt)
                }, probe: { receipt in
                    try check()
                    do { try await probe(receipt) } catch { try check(); throw error }
                    try check()
                })
                try check()
                return result
            } catch { try check(); throw error }
        }
        func command(_ command: Boot.Command, arm: ConsumerObservationProtocol.Arm,
                     revalidate: @escaping @MainActor () throws -> Void) async throws -> ConsumerObservationProtocol.Status {
            try await send(command, arm, revalidate)
        }
    }

    /// Separate from PREPARE/workload admission: post-ROOT replacement maintenance
    /// is allowed only for the exact still-retained maintenance identity. No public
    /// takeover or isolation command is admitted by this lease.
    func withOriginalConsumerSession<T>(request: StorageServiceTypes.ReplacementRequest? = nil,
        maintenance: ServiceReplacementMaintenance? = nil, deadlineNanoseconds: UInt64,
        body: @MainActor (OriginalConsumerSession) async throws -> T) async throws -> T {
        try worker.check(); try Task.checkCancellation()
        guard !busy, workloadConnected, let boot, let service, let lifecycle = workloadLifecycle,
              originalConsumerSessionID == nil else { throw Failure.blocked }
        let context = try workloadContext()
        let selected: StorageServiceTypes.ReplacementRequest
        if let maintenance {
            try requireMaintenance(maintenance)
            guard request == nil, let identity = replacementIdentity,
                  maintenance.serviceScope == .init(serviceEpoch: boot.ready.serviceEpoch, workerUUID: boot.ready.workerUUID)
            else { throw Failure.blocked }
            selected = .init(operationUUID: identity.operation, predecessor: identity.scope, nowUnixSeconds: identity.now)
        } else {
            guard replacementIdentity == nil, let request else { throw Failure.blocked }
            try validateServiceReplacement(request)
            selected = request
        }
        guard DispatchTime.now().uptimeNanoseconds < deadlineNanoseconds else { throw AsyncTimeout.TimeoutError() }
        guard !originalConsumerWorkers.contains(boot.ready.workerUUID), prepareStorageCommands.tryPoll() else { throw Failure.blocked }
        let identity = UUID()
        originalConsumerSessionID = identity
        originalConsumerWorkers.insert(boot.ready.workerUUID)
        defer { originalConsumerSessionID = nil; prepareStorageCommands.release() }
        @MainActor func check() throws {
            try self.worker.check(); try Task.checkCancellation()
            guard self.originalConsumerSessionID == identity, !self.busy, self.workloadConnected,
                  self.boot == boot, self.workloadLifecycle === lifecycle,
                  try self.workloadContext() == context else { throw Failure.blocked }
            if let maintenance { try self.requireMaintenance(maintenance) }
            else {
                let state = try self.physicalState()
                guard self.replacementIdentity == nil, state.pendingService == nil, state.pendingCold == nil,
                      state.serviceReplacement?.configuration.reopen?.request.operationID != selected.operationUUID,
                      selected.predecessor == .init(serviceEpoch: boot.ready.serviceEpoch, workerUUID: boot.ready.workerUUID)
                else { throw Failure.blocked }
            }
            guard DispatchTime.now().uptimeNanoseconds < deadlineNanoseconds else { throw AsyncTimeout.TimeoutError() }
        }
        var selectedArm: ConsumerObservationProtocol.Arm?
        var finalized = false
        let session = OriginalConsumerSession(service: boot, request: selected, lifecycle: lifecycle, validate: check,
            send: { command, arm, revalidate in
                guard [.consumerObservationArm, .consumerObservationQuery, .consumerObservationFinalize].contains(command),
                      arm.operationUUID == selected.operationUUID,
                      arm.original.epoch == selected.predecessor.serviceEpoch,
                      arm.workerScope == .init(storeUUID: boot.ready.identity.store,
                        serviceEpoch: boot.ready.serviceEpoch, workerUUID: boot.ready.workerUUID),
                      (maintenance == nil ? arm.caseName != .crossE : arm.caseName == .crossE)
                else { throw Failure.invalid }
                @MainActor func fenced() throws { try check(); try revalidate() }
                try fenced()
                while self.serviceCommandActive {
                    let now = DispatchTime.now().uptimeNanoseconds
                    guard now < deadlineNanoseconds else { throw AsyncTimeout.TimeoutError() }
                    do { try await Task.sleep(nanoseconds: min(5_000_000, deadlineNanoseconds - now)) }
                    catch { try fenced(); throw error }
                    try fenced()
                }
                guard !finalized else { throw Failure.blocked }
                if command == .consumerObservationArm {
                    guard selectedArm == nil else { throw Failure.blocked }
                    selectedArm = arm // Freeze before IO, including lost replies.
                } else {
                    guard selectedArm == arm else { throw Failure.blocked }
                    if command == .consumerObservationFinalize { finalized = true }
                }
                guard self.sequence < UInt64.max else { throw Failure.blocked }
                self.sequence += 1
                let frame = Boot.Frame(operation: .command, binding: boot.binding, sequence: self.sequence,
                    serviceEpoch: boot.ready.serviceEpoch, command: command, workerUUID: boot.ready.workerUUID,
                    consumerObservationArm: command == .consumerObservationArm ? arm : nil,
                    consumerObservationQuery: command == .consumerObservationArm ? nil : arm)
                try frame.validate()
                let reply: Boot.Frame
                do {
                    reply = try await withTaskCancellationHandler {
                        try await service.command(frame, deadlineNanoseconds: deadlineNanoseconds)
                    } onCancel: { [worker = self.worker] in worker.cancel(); service.cancel() }
                } catch { try fenced(); throw error }
                try fenced(); try reply.validate()
                guard reply.operation == .reply, reply.binding == frame.binding, reply.sequence == frame.sequence,
                      reply.serviceEpoch == frame.serviceEpoch, reply.workerUUID == frame.workerUUID,
                      reply.code == nil, let status = reply.consumerObservationStatus else { throw Failure.invalid }
                try ConsumerObservationProtocol.validate(status, arm: arm)
                return status
            })
        try check()
        do {
            let result = try await body(session)
            try check()
            return result
        } catch { try check(); throw error }
    }

    /// The signed v2 current grant is the baseline; compacted v1 history is neither
    /// required nor synthesized. This projection never grants mount authority.
    func validatePublicTakeoverArm(_ request: ManagedPrepareCompatibilityQueue.PublicTakeoverArmCapture) throws {
        try validatePublicTakeoverArm(request, ownsProbe: false)
    }
    private func validatePublicTakeoverArm(_ request: ManagedPrepareCompatibilityQueue.PublicTakeoverArmCapture,
                                         ownsProbe: Bool) throws {
        try worker.check(); try Task.checkCancellation()
        guard (!busy || ownsProbe), workloadCalls == 0, !workloadRetireActive,
              replacementIdentity == nil, originalConsumerSessionID == nil,
              workloadConnected, workloadLifecycle != nil, let boot,
              initialization == nil || initializationAdmitted, pendingInitializationAdmission == nil,
              request.version == "original-takeover-arm.v1", request.epoch >= 2,
              request.positiveOnly == nil || request.positiveOnly == true,
              request.isolationCase == nil || (request.positiveOnly == true &&
                ["legacy-connection", "second-service-exclusivity"].contains(request.isolationCase!)),
              [request.requestID, request.operationUUID, request.store, request.serviceEpoch,
               request.containerInstance].allSatisfy(StorageServiceTypes.validID),
              OriginalConsumerObservationProtocol.hash(request.container) else { throw Failure.blocked }
        let state = try physicalState(), context = try workloadContext()
        guard state.pending == nil, state.pendingTakeover == nil, state.pendingService == nil,
              state.pendingCold == nil, state.sealed == nil, state.terminal == nil,
              state.adoptionRetry == nil || (state.adoptionRetry == adoptionRetry && adoptedShim != nil),
              let current = state.current, current.original.recipient == recipient,
              let live = state.currentService else { throw Failure.blocked }
        let signed = current.original.signed, grant = signed.grant
        guard grant.operation == .takeover, grant.expectedEpoch < UInt64.max,
              grant.expectedEpoch + 1 == context.controllerEpoch, grant.newKey == context.controllerKey,
              grant.identity == state.identity, live.grant == grant,
              signed.isValidSignature(using: try .init(publicData: state.rootPublicKey)),
              request.store == context.store, request.epoch == context.controllerEpoch,
              request.serviceEpoch == context.serviceEpoch else { throw Failure.blocked }
        try Self.match(live, boot: boot)
    }

    /// Actual schema-4 child Query through the normal tracked lifecycle lane.
    func publicTakeoverRegistry(_ request: ManagedPrepareCompatibilityQueue.PublicTakeoverArmCapture) async throws -> ManagedStorageControlClient.Snapshot {
        try validatePublicTakeoverArm(request)
        guard let lifecycle = workloadLifecycle, let intents else { throw Failure.blocked }
        let state = try physicalState(), census = try intents.checkedSnapshot(), generation = boot
        func unchanged() throws {
            try validatePublicTakeoverArm(request)
            guard workloadLifecycle === lifecycle, boot == generation,
                  try physicalState() == state, try intents.checkedSnapshot() == census else { throw Failure.blocked }
        }
        let value: ManagedStorageControlClient.Snapshot
        do { value = try await lifecycle.publicTakeoverRegistry() }
        catch { try unchanged(); throw error }
        try unchanged()
        guard value.schema == 4 else { throw Failure.invalid }
        try ManagedStorageControlClient.validate(value, context: workloadContext())
        return try worker.publish(value)
    }

    struct PublicTakeoverRegistryEvidence: Codable, Sendable {
        let version: UInt32
        let lifecycleIdentity: L.Identity
        let registry: ManagedStorageControlClient.Snapshot
    }
    func publicTakeoverRegistryEvidence(_ request: ManagedPrepareCompatibilityQueue.PublicTakeoverArmCapture) async throws -> Data {
        let context = try workloadContext()
        let registry = try await publicTakeoverRegistry(request)
        try validatePublicTakeoverArm(request)
        guard try workloadContext() == context, let identity = context.lifecycleIdentity else { throw Failure.blocked }
        return try ManagedPrepareCompatibilityProtocol.canonicalData(PublicTakeoverRegistryEvidence(
            version: 2, lifecycleIdentity: identity, registry: registry))
    }
    /// Called by Raw only after reconciliation installed genuine live-runtime
    /// permits. Serialized bindings cannot create a client or resume authority.
    func resumePublicTakeoverOriginal() async throws {
        guard let selected = publicTakeoverRecovery else { return }
        do {
            try requireSignedCompatibilityIdentity()
            guard let original = selected.request.original, let lifecycle = workloadLifecycle, let intents,
                  recoveryPermission != nil, !busy, workloadConnected, replacementIdentity == nil,
                  try !intents.checkedSnapshot().reconciliationRequired else { throw Failure.blocked }
            let context = try workloadContext(), state = try physicalState(), census = try intents.checkedSnapshot(), generation = boot
            guard recoveryPermission?.context == context, context.store == selected.request.store,
                  context.serviceEpoch == selected.request.serviceEpoch, selected.request.epoch < UInt64.max,
                  context.controllerEpoch == selected.request.epoch + 1,
                  state.current?.original.signed.grant.operation == .takeover,
                  state.current?.original.signed.grant.expectedEpoch == selected.request.epoch else { throw Failure.blocked }
            func unchanged() throws {
                try worker.check(); try Task.checkCancellation()
                guard workloadConnected, replacementIdentity == nil, workloadLifecycle === lifecycle, boot == generation,
                      try workloadContext() == context, try physicalState() == state,
                      try intents.checkedSnapshot() == census else { throw Failure.blocked }
            }
            try unchanged()
            let evidence = try await lifecycle.resumeOriginalConsumer(original)
            try unchanged()
            try selected.publish(ManagedPrepareCompatibilityProtocol.canonicalData(evidence.resumed), "resumed")
            try selected.publish(ManagedPrepareCompatibilityProtocol.canonicalData(evidence), "positive")
            let registry = try await lifecycle.publicTakeoverRegistry()
            try unchanged()
            guard registry.schema == 4, let identity = context.lifecycleIdentity else { throw Failure.invalid }
            try ManagedStorageControlClient.validate(registry, context: context)
            try selected.publish(ManagedPrepareCompatibilityProtocol.canonicalData(PublicTakeoverRegistryEvidence(
                version: 2, lifecycleIdentity: identity, registry: registry)), "registry")
            publicTakeoverRecovery = nil
        } catch {
            workloadConnected = false; cancel(); throw error
        }
    }

    private static func actualSignedCompatibilityIdentity() throws {
        _ = try SignedCompatibilityIdentity.current(role: .engine)
    }
    private func requireSignedCompatibilityIdentity() throws {
        #if DEBUG
        if let policy = worker.testSeam?.isolationCompatibilityIdentity { try policy() }
        else { try Self.actualSignedCompatibilityIdentity() }
        #else
        try Self.actualSignedCompatibilityIdentity()
        #endif
    }

    /// Read-only diagnostic: retain the private lane and immutable physical census
    /// through state -> actual selected probe -> state. No Ready/receipt promotion.
    func probeServiceIsolation(_ request: ManagedPrepareCompatibilityQueue.PublicTakeoverArmCapture,
        original: OriginalConsumerObservationProtocol.Binding,
        timeout: TimeInterval = 30) async throws -> StorageServiceTypes.IsolationReceipt {
        guard timeout.isFinite, timeout > 0, timeout <= 30 else { throw Failure.invalid }
        let deadline = DispatchTime.now().uptimeNanoseconds + UInt64(timeout * 1_000_000_000)
        let rootDeadline = ProcessInfo.processInfo.systemUptime + timeout
        try requireSignedCompatibilityIdentity()
        try validatePublicTakeoverArm(request)
        try OriginalConsumerObservationProtocol.validate(original)
        guard let name = request.isolationCase, let kind = Boot.Command(rawValue: name),
              kind == .legacyConnection || kind == .secondServiceExclusivity,
              original.caseName == .sameEExistingData,
              original.requestID == request.requestID, original.operationUUID == request.operationUUID,
              original.scope.store == request.store, original.scope.serviceEpoch == request.serviceEpoch,
              original.scope.controllerEpoch == request.epoch,
              original.scope.controllerKey == (try workloadContext()).controllerKey,
              original.scope.container == request.container, original.scope.containerInstance == request.containerInstance,
              let boot, let service, let intents, prepareStorageCommands.tryPoll() else { throw Failure.blocked }
        busy = true
        defer { busy = false; prepareStorageCommands.release() }
        let state = try physicalState(), census = try intents.checkedSnapshot(), context = try workloadContext()
        func unchanged() throws {
            try validatePublicTakeoverArm(request, ownsProbe: true)
            guard self.boot == boot, try workloadContext() == context,
                  try physicalState() == state, try intents.checkedSnapshot() == census else { throw Failure.blocked }
            guard DispatchTime.now().uptimeNanoseconds < deadline else { throw AsyncTimeout.TimeoutError() }
        }
        try unchanged()
        // Join an already-admitted notification without cancelling its independent
        // IO. New polls skip the owned PREPARE lane; timeout sends no probe bytes.
        while serviceCommandActive {
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else { throw AsyncTimeout.TimeoutError() }
            do { try await Task.sleep(nanoseconds: min(5_000_000, deadline - now)) }
            catch { try unchanged(); throw error }
            try unchanged()
        }
        do { _ = try await verifyServiceLocked(recordObservation: false, deadline: rootDeadline) }
        catch { try unchanged(); throw error }
        try unchanged()
        let selected = Boot.IsolationRequest(requestID: request.requestID, operationUUID: request.operationUUID,
            armDigest: original.armDigest, challenge: Self.id())
        func exchangeIsolation(_ command: Boot.Command) async throws -> Boot.IsolationProof {
            try unchanged()
            guard sequence < UInt64.max else { throw Failure.blocked }
            sequence += 1
            let frame = Boot.Frame(operation: .command, binding: boot.binding, sequence: sequence,
                serviceEpoch: boot.ready.serviceEpoch, command: command, workerUUID: boot.ready.workerUUID,
                isolationRequest: selected)
            try frame.validate()
            let reply: Boot.Frame
            do {
                // The independent read-only envelope has joined. Cancellation now
                // interrupts only this owned probe, never the prior notification.
                reply = try await withTaskCancellationHandler {
                    try await service.command(frame, deadlineNanoseconds: deadline)
                } onCancel: { [worker] in worker.cancel(); service.cancel() }
            } catch { try unchanged(); throw error }
            try unchanged(); try reply.validate()
            guard reply.operation == .reply, reply.binding == frame.binding, reply.sequence == frame.sequence,
                  reply.serviceEpoch == frame.serviceEpoch, reply.workerUUID == frame.workerUUID,
                  reply.code == nil, let proof = reply.isolationProof, proof.request == selected,
                  proof.caseName == command.rawValue, proof.store == request.store,
                  proof.serviceEpoch == request.serviceEpoch, proof.workerUUID == boot.ready.workerUUID else { throw Failure.invalid }
            return proof
        }
        let before = try await exchangeIsolation(.isolationState)
        try unchanged()
        let observation = try await exchangeIsolation(kind)
        try unchanged()
        let after = try await exchangeIsolation(.isolationState)
        try unchanged()
        return try worker.publish(StorageServiceTypes.IsolationReceipt(before: before, observation: observation, after: after))
    }

    /// Compatibility observations are not lifecycle authority. This lane never
    /// acquires the child workload/Retire/credential lock or read-only status flag.
    func armPrepareStorage(_ arm: ManagedPrepareCompatibilityProtocol.Arm) async throws -> (ManagedPrepareCompatibilityProtocol.StorageArm, ManagedPrepareCompatibilityProtocol.StorageStatus) {
        typealias C = ManagedPrepareCompatibilityProtocol
        let current = try prepareStorageSession(scope: arm.scope)
        let wrapped = C.StorageArm(arm: arm, workerUUID: current.service.ready.workerUUID)
        try C.validate(wrapped)
        try await prepareStorageCommands.acquire()
        defer { prepareStorageCommands.release() }
        let reply = try await prepareStorageExchange(.prepareCompatibilityArm, current: current) { $0.prepareCompatibilityArm = wrapped }
        guard reply.code == nil, let status = reply.prepareCompatibilityStatus, status.state == "armed" else { throw Failure.blocked }
        try C.validate(status, arm: wrapped)
        return (wrapped, status)
    }
    func observePrepareStorage(_ arm: ManagedPrepareCompatibilityProtocol.StorageArm,
        deadlineNanoseconds: UInt64? = nil) async throws -> ManagedPrepareCompatibilityProtocol.StorageStatus? {
        let current = try prepareStorageSession(scope: arm.arm.scope, workerUUID: arm.workerUUID)
        // Observations never queue behind read-only IO, even with an expired deadline.
        guard !serviceCommandActive, prepareStorageCommands.tryPoll() else { return nil }
        defer { prepareStorageCommands.release() }
        let query = try ManagedPrepareCompatibilityProtocol.query(arm)
        let reply = try await prepareStorageExchange(.prepareCompatibilityObserve, current: current,
            deadlineNanoseconds: deadlineNanoseconds) { $0.prepareCompatibilityQuery = query }
        guard reply.code == nil, let status = reply.prepareCompatibilityStatus else { throw Failure.blocked }
        try ManagedPrepareCompatibilityProtocol.validate(status, arm: arm)
        return status
    }
    func releasePrepareStorage(_ release: ManagedPrepareCompatibilityProtocol.StorageRelease,
        arm: ManagedPrepareCompatibilityProtocol.StorageArm) async throws -> ManagedPrepareCompatibilityProtocol.StorageStatus {
        let current = try prepareStorageSession(scope: arm.arm.scope, workerUUID: arm.workerUUID)
        guard release.query == (try ManagedPrepareCompatibilityProtocol.query(arm)) else { throw Failure.blocked }
        try await prepareStorageCommands.acquire()
        defer { prepareStorageCommands.release() }
        let reply = try await prepareStorageExchange(.prepareCompatibilityRelease, current: current) { $0.prepareCompatibilityRelease = release }
        guard reply.code == nil, let status = reply.prepareCompatibilityStatus,
              ["released", "finished"].contains(status.state) else { throw Failure.blocked }
        try ManagedPrepareCompatibilityProtocol.validate(status, arm: arm)
        return status
    }
    func exitPrepareStorageWorker(_ exit: ManagedPrepareCompatibilityProtocol.StorageRelease,
        arm: ManagedPrepareCompatibilityProtocol.StorageArm,
        checkpoint: ManagedPrepareCompatibilityProtocol.StorageStatus) async throws -> ManagedPrepareCompatibilityProtocol.StorageWorkerWait {
        typealias C = ManagedPrepareCompatibilityProtocol
        try C.validateStorageWorkerExit(exit, arm: arm, checkpoint: checkpoint)
        let current = try prepareStorageSession(scope: arm.arm.scope, workerUUID: arm.workerUUID)
        try await prepareStorageCommands.acquire()
        defer { prepareStorageCommands.release() }
        let reply = try await prepareStorageExchange(.prepareCompatibilityWorkerExit, current: current) { $0.prepareCompatibilityWorkerExit = exit }
        guard reply.code == nil, let wait = reply.prepareCompatibilityWorkerWait else { throw Failure.blocked }
        try C.validate(wait, arm: arm, checkpoint: checkpoint)
        return wait // Never promote Ready, worker loss, drain or recovery state.
    }
    func exitCheckpointWorker(_ exit: ManagedPrepareWorkerCheckpointProtocol.WorkerCheckpointExit) async throws -> ManagedPrepareWorkerCheckpointProtocol.WorkerCheckpointWait {
        typealias C = ManagedPrepareWorkerCheckpointProtocol
        try C.validate(exit)
        let current = try prepareStorageSession(scope: exit.arm.scope, workerUUID: exit.workerUUID)
        try await prepareStorageCommands.acquire()
        defer { prepareStorageCommands.release() }
        let reply = try await prepareStorageExchange(.prepareCompatibilityCheckpointExit, current: current) { $0.prepareCompatibilityCheckpointExit = exit }
        guard reply.code == nil, let wait = reply.prepareCompatibilityCheckpointWait else { throw Failure.blocked }
        try C.validate(wait, for: exit)
        return wait // Generic checkpoint evidence has no release-token semantics.
    }
    private typealias PrepareSession = (context: ManagedStorageControlClient.Context, service: ManagedStorageLifecycleServiceReady)
    private func prepareStorageSession(scope: WorkloadStorageProtocol.Scope, workerUUID: String? = nil) throws -> PrepareSession {
        try worker.check(); try Task.checkCancellation()
        guard replacementIdentity == nil, !busy, workloadLifecycle != nil, let boot,
              workerUUID == nil || workerUUID == boot.ready.workerUUID else { throw Failure.blocked }
        let context = try workloadContext()
        guard scope.store == context.store, scope.serviceEpoch == context.serviceEpoch,
              scope.controllerEpoch == context.controllerEpoch, scope.controllerKey == context.controllerKey else { throw Failure.blocked }
        return (context, boot)
    }
    private func prepareStorageExchange(_ command: Boot.Command, current: PrepareSession,
        deadlineNanoseconds: UInt64? = nil, payload: (inout Boot.Frame) -> Void) async throws -> Boot.Frame {
        func unchanged() throws {
            try worker.check(); try Task.checkCancellation()
            guard replacementIdentity == nil, !busy, boot == current.service,
                  try workloadContext() == current.context else { throw Failure.blocked }
            if let deadlineNanoseconds, DispatchTime.now().uptimeNanoseconds >= deadlineNanoseconds {
                throw AsyncTimeout.TimeoutError()
            }
        }
        try unchanged()
        // A previously admitted read-only envelope must finish first. New status
        // polls skip this lane, so private sequence allocation cannot overtake it.
        // This never waits on child Retire or credential IO.
        while serviceCommandActive {
            let now = DispatchTime.now().uptimeNanoseconds
            let delay: UInt64
            if let deadlineNanoseconds {
                guard now < deadlineNanoseconds else { throw AsyncTimeout.TimeoutError() }
                delay = min(5_000_000, deadlineNanoseconds - now)
            } else { delay = 5_000_000 }
            try await Task.sleep(nanoseconds: delay)
            try unchanged()
        }
        guard let service, sequence < UInt64.max else { throw Failure.blocked }
        sequence += 1
        var frame = Boot.Frame(operation: .command, binding: current.service.binding, sequence: sequence,
            serviceEpoch: current.service.ready.serviceEpoch, command: command, workerUUID: current.service.ready.workerUUID)
        payload(&frame); try frame.validate()
        let reply = try await withTaskCancellationHandler {
            try await service.command(frame, deadlineNanoseconds: deadlineNanoseconds)
        } onCancel: { [worker] in worker.cancel(); service.cancel() }
        try unchanged(); try reply.validate()
        guard reply.operation == .reply, reply.binding == frame.binding, reply.sequence == frame.sequence,
              reply.serviceEpoch == frame.serviceEpoch, reply.workerUUID == frame.workerUUID else { throw Failure.invalid }
        return reply
    }

    /// Retirement hints (never receipts) over v2 `.notifications`. The exact
    /// E/worker envelope is checked by exchange(); every binding must match a
    /// journal attachment. Worker loss or an uncertain reply fences the generation.
    func retirementNotifications() async throws -> [Boot.Notification] {
        try worker.check(); try Task.checkCancellation()
        guard !prepareStorageCommands.active else { return [] }
        guard replacementIdentity == nil, !busy, !serviceCommandActive, workloadLifecycle != nil,
              let intents, let boot, workloadConnected || authenticatedWorkerLoss == boot else { throw Failure.blocked }
        let context = try workloadContext()
        let state = try physicalState()
        serviceCommandActive = true; defer { serviceCommandActive = false }
        let reply: Boot.Frame
        do {
            reply = try await exchange(.notifications)
            guard self.boot == boot, try physicalState() == state,
                  try workloadContext() == context else { throw Failure.blocked }
        } catch {
            workloadConnected = false; cancel(); throw error
        }
        if let code = reply.code {
            guard reply.notifications == nil else { workloadConnected = false; cancel(); throw Failure.invalid }
            if code == .workerLost {
                freezeWorkload(); authenticatedWorkerLoss = boot
                throw ManagedStorageControlFailure.serviceUnavailable
            }
            if authenticatedWorkerLoss == boot { freezeWorkload(); cancel() }
            throw Failure.blocked
        }
        do {
            guard let notifications = reply.notifications else { throw Failure.invalid }
            guard workloadConnected, try workloadContext() == context else { throw Failure.blocked }
            let journal = Array(try intents.snapshot().intents.values)
            for notification in notifications {
                guard notification.epoch == boot.ready.serviceEpoch,
                      let owner = journal.first(where: { $0.slots.contains { $0.attachment == notification.binding.attachment } }),
                      let slot = owner.slots.first(where: { $0.attachment == notification.binding.attachment }) else { throw Failure.repairRequired }
                let expected = try slot.binding(store: owner.store, prepare: owner.prepare, container: owner.container, launch: owner.launch)
                guard try ControllerJSON.from(notification.binding) == ControllerJSON.from(expected) else { throw Failure.invalid }
            }
            return try worker.publish(notifications)
        } catch {
            workloadConnected = false; cancel(); throw error
        }
    }

    /// Validate a backend request against this v2 owner, without a v1 VerifiedBoot cast.
    /// A lost-worker hint may have disconnected workload IO; the held native boot
    /// and physical current-service state must still match the requested pair.
    func validateServiceReplacement(_ request: StorageServiceTypes.ReplacementRequest) throws {
        try validateServiceReplacement(request, allowingReadOnlyCommand: false)
    }

    /// Admission only: no staging, retries of failures, or cancellation of the
    /// owned transport. One absolute monotonic budget covers read-only overlap.
    func awaitServiceReplacementAdmission(_ request: StorageServiceTypes.ReplacementRequest) async throws {
        let timing: ReplacementAdmissionTiming
        #if DEBUG
        if let test = replacementAdmissionTimingForTesting {
            timing = .init(now: test.now, sleep: test.sleep)
        } else { timing = .live }
        #else
        timing = .live
        #endif
        let deadline = timing.now() + 5
        while serviceCommandActive {
            try validateServiceReplacement(request, allowingReadOnlyCommand: true)
            let remaining = deadline - timing.now()
            guard remaining > 0 else { throw Failure.blocked }
            try await timing.sleep(min(0.01, remaining))
            try worker.check(); try Task.checkCancellation()
            guard timing.now() < deadline else { throw Failure.blocked }
        }
        try validateServiceReplacement(request)
    }

    private struct ReplacementAdmissionTiming {
        let now: @Sendable () -> TimeInterval
        let sleep: @Sendable (TimeInterval) async throws -> Void
        static let live = Self(now: { ProcessInfo.processInfo.systemUptime },
            sleep: { try await Task.sleep(for: .seconds($0)) })
    }

    private func validateServiceReplacement(_ request: StorageServiceTypes.ReplacementRequest,
        allowingReadOnlyCommand: Bool) throws {
        try worker.check(); try Task.checkCancellation()
        // Active PREPARE is never read-only overlap: replacement must fail fast.
        guard !busy, workloadCalls == 0, !prepareStorageCommands.active, (!serviceCommandActive || allowingReadOnlyCommand), let boot, workloadLifecycle != nil,
              StorageServiceTypes.validID(request.operationUUID), request.nowUnixSeconds > 0,
              request.nowUnixSeconds <= StorageServiceTypes.maximumUnixSeconds else { throw Failure.blocked }
        let state = try physicalState()
        if let retained = replacementIdentity {
            guard retained.operation == request.operationUUID, retained.scope == request.predecessor,
                  retained.now == request.nowUnixSeconds else { throw Failure.blocked }
            return
        }
        guard state.pending == nil, state.pendingService == nil, state.pendingCold == nil,
              state.sealed == nil, state.terminal == nil, let current = state.currentService,
              request.operationUUID != state.latestServiceRequest?.request.operationID,
              request.predecessor == .init(serviceEpoch: boot.ready.serviceEpoch, workerUUID: boot.ready.workerUUID) else {
            throw Failure.blocked
        }
        try Self.match(current, boot: boot)
    }

    /// v2 `.serviceStatus`. Worker loss -> ManagedStorageControlFailure.serviceUnavailable
    /// (and fences the generation); every other non-ready result is blocked.
    func validateServiceAvailability(_ scope: StorageServiceTypes.Scope) async throws {
        try worker.check(); try Task.checkCancellation()
        guard replacementIdentity == nil, !busy, !serviceCommandActive, !prepareStorageCommands.active, let boot,
              workloadConnected || authenticatedWorkerLoss == boot,
              scope == .init(serviceEpoch: boot.ready.serviceEpoch, workerUUID: boot.ready.workerUUID) else { throw Failure.blocked }
        let context = try workloadContext()
        serviceCommandActive = true; defer { serviceCommandActive = false }
        let state = try physicalState()
        let reply: Boot.Frame
        do {
            reply = try await exchange(.serviceStatus)
            guard self.boot == boot, try physicalState() == state,
                  try workloadContext() == context else { throw Failure.blocked }
        } catch { freezeWorkload(); cancel(); throw error }
        if reply.code == .workerLost || reply.status?.phase == .workerLost {
            freezeWorkload(); authenticatedWorkerLoss = boot
            throw ManagedStorageControlFailure.serviceUnavailable
        }
        guard reply.code == nil, reply.status?.phase == .ready, workloadConnected else {
            freezeWorkload(); cancel(); throw Failure.blocked
        }
    }

    private func workloadContext() throws -> ManagedStorageControlClient.Context {
        try worker.check(); try Task.checkCancellation()
        guard let checkpoint, let intents, let boot else { throw Failure.blocked }
        let state = try checkpoint.snapshot()
        let intentState = try intents.checkedSnapshot()
        guard state.pending == nil, state.pendingService == nil, state.sealed == nil, state.terminal == nil,
              let liveService = state.currentService,
              let current = state.current, let context = state.currentContext,
              state.identity == boot.ready.identity, state.provenanceReference == provenance,
              intentState.store == state.identity.store, intents.manifest.provenanceReference == provenance,
              context.serviceEpoch == boot.ready.serviceEpoch,
              context.controllerEpoch == boot.ready.controllerEpoch,
              context.controllerKey == boot.ready.controllerKey,
              current.original.signed.grant.identity == state.identity else { throw Failure.blocked }
        try Self.match(liveService, boot: boot)
        return try .init(store: state.identity.store, serviceEpoch: context.serviceEpoch,
            controllerEpoch: context.controllerEpoch, controllerKey: context.controllerKey,
            provenanceReference: provenance, lifecycleIdentity: state.identity)
    }

    /// Public metadata only; health-checks the actual physical checkpoint.
    func snapshot() throws -> Checkpoint.Metadata {
        guard let checkpoint else { throw Failure.incomplete }; return try checkpoint.snapshot()
    }
    /// In-memory retry diagnostics only, not crash-recovery authority.
    var attemptedRetirement: Root.Request? { retireRequest }
    /// Cancellation permanently fences this owner, including late replies. There
    /// is no implicit restart/recovery of a potentially mutated fresh session.
    func cancel() { prepareStorageCommands.close(); replacementTask?.cancel(); worker.cancel(); service?.cancel() }
    func close() async { cancel(); await worker.close() }

    private func requireFreshDirectories() throws {
        guard try rootDirectory.entryMetadata(named: Checkpoint.directoryName) == nil,
              try rootDirectory.entryMetadata(named: "managed-storage") == nil else { throw Failure.blocked }
    }
    private func begin() throws {
        try worker.check(); try Task.checkCancellation()
        guard !busy, workloadCalls == 0, !serviceCommandActive, !prepareStorageCommands.active else { throw Failure.blocked }; busy = true
    }
    private func persist(_ change: Checkpoint.Change) throws {
        try worker.check(); try Task.checkCancellation()
        guard let checkpoint, let intents else { throw Failure.incomplete }
        let snapshot = try intents.checkedSnapshot()
        // No suspension or caller-provided/cached census inside this transaction.
        try checkpoint.persist(change, intents: snapshot, readIntents: { try intents.checkedSnapshot() })
    }
    /// Check actual HOST journals before and after every ROOT exchange once the
    /// pair exists, including transport/decoding failures and completed retries.
    /// ROOT may have committed despite a lost reply; changed HOST evidence never
    /// permits that reply to publish a locally usable generation.
    private func checkedRootRequest(_ request: Root.Request, rootFD: Int32 = -1, backingFD: Int32 = -1,
                                    returnMissingInitial: Bool = false, deadline: TimeInterval? = nil) async throws -> Root.Reply {
        let before = try checkpoint.map { initialization != nil && intents == nil ? try $0.snapshot() : try physicalState() }
        let result: Result<Root.Reply, any Error>
        do {
            result = .success(try await worker.request(request, rootFD: rootFD, backingFD: backingFD,
                returnMissingInitial: returnMissingInitial, deadline: deadline))
        } catch { result = .failure(error) }
        if let before {
            guard try (initialization != nil && intents == nil ? checkpoint?.snapshot() : physicalState()) == before else { throw Failure.blocked }
        }
        try worker.check(); try Task.checkCancellation()
        return try result.get()
    }
    private func physicalState() throws -> Checkpoint.Metadata {
        guard let checkpoint, let intents else { throw Failure.incomplete }
        let state = try checkpoint.snapshot()
        let census = try intents.checkedSnapshot()
        guard census.store == state.identity.store,
              intents.manifest.provenanceReference == state.provenanceReference,
              state.provenanceReference == provenance else { throw Failure.invalid }
        return state
    }
    private func rootBootTrust(grant: L.Grant, serviceChangeID: String?) async throws -> StorageLifecycleBootTrust {
        let request = try Self.request(.serviceBootTrust(identity: grant.identity, grantID: grant.id, serviceChangeID: serviceChangeID))
        let reply = try await checkedRootRequest(request)
        guard case .serviceBootTrust(let trust, let id, let changeID) = reply.body,
              id == grant.id, changeID == serviceChangeID else { throw Failure.invalid }
        return trust
    }
    /// ROOT's committed adoption session proves the entire protected live boot,
    /// without asking the dead predecessor grant recipient to prove anything.
    private func rootAdoptedService(_ grant: L.Grant, deadline: TimeInterval? = nil) async throws -> L.ServiceState {
        if let adoptedShim, let adoptionLock {
            guard try physicalState().adoptionRetry == adoptionRetry else { throw Failure.blocked }
            let request = try AdoptionRoot.Request(requestID: .init(Self.id()), body: .service(adoptedShim.request, grant))
            let reply = try await checkedAdoptionRequest(request, storeLock: adoptionLock, deadline: deadline)
            guard case .service(let result) = reply.body, result.grant == grant else { throw Failure.invalid }
            try result.validate()
            return result
        }
        // Only isolated non-adoption test seams may use the old recipient path.
        guard !worker.requiresAdoption else { throw Failure.blocked }
        let trust = try await rootBootTrust(grant: grant,
            serviceChangeID: physicalState().latestServiceRequest?.request.operationID)
        return try await rootServiceResult(grant).state(boot: trust)
    }
    private func rootServiceResult(_ grant: L.Grant, deadline: TimeInterval? = nil) async throws -> L.ServiceResult {
        let reply = try await checkedRootRequest(Self.request(.serviceResult(identity: grant.identity, grantID: grant.id)), deadline: deadline)
        guard case .serviceResult(let result) = reply.body, result.grant == grant else { throw Failure.invalid }
        return result
    }
    private func verifyServiceLocked(recordObservation: Bool = true, deadline: TimeInterval? = nil) async throws -> L.ServiceState {
        guard let checkpoint else { throw Failure.blocked }
        let state = try checkpoint.snapshot()
        guard state.pending == nil, state.pendingService == nil, state.sealed == nil, state.terminal == nil,
              let current = state.currentService else { throw Failure.blocked }
        let live: L.ServiceState
        if adoptedShim != nil {
            live = try await rootAdoptedService(current.grant, deadline: deadline)
        } else {
            live = try await rootServiceResult(current.grant, deadline: deadline).state(boot: current.boot)
        }
        guard live == current else { throw Failure.invalid }
        if let boot { try Self.match(current, boot: boot) }
        if recordObservation { try recordVerifiedService(live) }
        return current
    }
    /// Called only with fresh ROOT proof, never with a public checkpoint projection.
    /// Revalidate synchronously before persisting; initialization defers this until
    /// its unchanged-evidence guard and empty physical census have both passed.
    private func recordVerifiedService(_ current: L.ServiceState) throws {
        try worker.check(); try Task.checkCancellation()
        let state = try physicalState()
        guard state.currentService == current, state.pending == nil, state.pendingService == nil,
              state.sealed == nil, state.terminal == nil else { throw Failure.blocked }
        if let boot {
            try Self.match(current, boot: boot)
            guard let context = state.currentContext else { throw Failure.invalid }
            // Only the held actual Ready, matched to this fresh ROOT live result,
            // supplies worker identity. This public projection grants no authority.
            // persist reads the physical intent census; exact repeats do not write.
            try persist(.recordObservedWorker(.init(context: context, workerUUID: boot.ready.workerUUID)))
        } else {
            // Isolated metadata fixtures have no native worker to observe.
            try persist(.recordService(current))
        }
    }
    private static func serviceState(_ response: ManagedStorageLifecycleServiceReady, grant: L.Grant) throws -> L.ServiceState {
        let ready = response.ready
        return try .init(grant: grant, context: .init(serviceEpoch: ready.serviceEpoch,
            controllerEpoch: ready.controllerEpoch, controllerKey: ready.controllerKey), openRevision: ready.openRevision,
            boot: .init(identity: ready.identity, serviceEpoch: ready.serviceEpoch,
                tlsRootSHA256: HostStorageIntents.hash(ready.tlsRootDER), serverSPKI: ready.serverSPKI, bootstrapKey: ready.bootstrapKey))
    }
    private static func match(_ service: L.ServiceState, boot: ManagedStorageLifecycleServiceReady) throws {
        guard try serviceState(boot, grant: service.grant) == service else { throw Failure.invalid }
    }
    private func rootCompletion(_ context: Checkpoint.GrantContext) async throws -> L.Receipt {
        let grant = context.signed.grant
        if completionRequests[grant.id] == nil { completionRequests[grant.id] = try Self.request(.complete(identity: grant.identity, id: grant.id)) }
        let reply = try await checkedRootRequest(completionRequests[grant.id]!)
        guard case .completed(let result) = reply.body, result.grant == grant,
              context.serviceEpoch == nil || result.serviceEpoch == context.serviceEpoch else { throw Failure.invalid }
        try worker.check(); try Task.checkCancellation()
        return result
    }
    private func command(_ command: Boot.Command, csr: Data? = nil, signed: L.SignedGrant? = nil,
                         controller: Boot.Controller? = nil, deadlineNanoseconds: UInt64? = nil) async throws -> Boot.Frame {
        let reply = try await exchange(command, csr: csr, signed: signed, controller: controller,
            deadlineNanoseconds: deadlineNanoseconds)
        guard reply.code == nil else { throw Failure.invalid }
        return reply
    }
    /// Exact envelope exchange; a closed error code is returned to the caller.
    private func exchange(_ command: Boot.Command, csr: Data? = nil, signed: L.SignedGrant? = nil,
                          controller: Boot.Controller? = nil, deadlineNanoseconds: UInt64? = nil) async throws -> Boot.Frame {
        guard let service, let boot, sequence < UInt64.max else { throw Failure.blocked }
        sequence += 1
        let frame = Boot.Frame(operation: .command, binding: boot.binding, sequence: sequence,
            serviceEpoch: boot.ready.serviceEpoch, command: command, csr: csr, signed: signed, controller: controller,
            workerUUID: boot.ready.workerUUID)
        try frame.validate()
        let reply = try await withTaskCancellationHandler {
            if let deadlineNanoseconds {
                return try await service.command(frame, deadlineNanoseconds: deadlineNanoseconds)
            }
            return try await service.command(frame)
        } onCancel: { [worker] in worker.cancel(); service.cancel() }
        try worker.check(); try Task.checkCancellation(); try reply.validate()
        guard reply.operation == .reply, reply.binding == frame.binding,
              reply.sequence == frame.sequence, reply.serviceEpoch == frame.serviceEpoch,
              reply.workerUUID == frame.workerUUID else { throw Failure.invalid }
        return reply
    }
    static func validate(_ response: ManagedStorageLifecycleServiceReady, binding: Boot.Binding,
                         grant: L.Grant, root: StorageIdentity.RootPublicKey) throws {
        try Boot.Frame(operation: .ready, binding: response.binding, ready: response.ready).validate()
        let ready = response.ready
        guard response.binding == binding, ready.identity == grant.identity,
              grant.expectedEpoch < UInt64.max, ready.controllerEpoch == grant.expectedEpoch + 1,
              ready.controllerKey == grant.newKey, ready.bootstrapKey == root.fingerprint.rawValue else { throw Failure.invalid }
        // TLS inputs remain untrusted here. Native child validates certificates;
        // ROOT independently supplies actual service-shim trust for TLS results.
    }
    nonisolated private static func own(_ descriptor: Int32) throws -> FileHandle {
        let fd = fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
        guard fd >= 0 else { throw Failure.system(errno) }
        return FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    }
    nonisolated private static func id() -> String { UUID().uuidString.lowercased() }
    nonisolated private static func request(_ body: Root.Body) throws -> Root.Request { try .init(requestID: .init(id()), body: body) }

    /// Blocking native calls use a dedicated GCD worker, NEVER the cooperative
    /// executor or MainActor. Detached tasks only bridge asynchronous continuations.
    /// Cancellation fences admission and publication even if native IO finishes late.
    nonisolated private final class Worker: @unchecked Sendable {
        let root: StorageLifecycleRootClient?
        #if DEBUG
        let testSeam: IsolatedTestSeam?
        init(isolatedTest seam: IsolatedTestSeam) {
            root = nil; team = ""; policy = .production; testSeam = seam; store = nil; scopeRoot = nil
        }
        #endif
        let team: String
        let policy: StorageLifecycleNativePolicy
        let cancelled = Mutex(false)
        let queue = DispatchQueue(label: "dev.cengine.storage-lifecycle.host-owner")
        // Queue-owned. No PID supplied by a transport DTO is ever closed/signaled.
        var child: StorageLifecycleChildProcess?
        var launched = false
        let store: StorageIdentity.StoreID?
        let scopeRoot: PersistentStateDirectory?
        init(root: StorageLifecycleRootClient, team: String, policy: StorageLifecycleNativePolicy,
             store: StorageIdentity.StoreID, scopeRoot: PersistentStateDirectory) {
            self.root = root; self.team = team; self.policy = policy; self.store = store; self.scopeRoot = scopeRoot
            #if DEBUG
            testSeam = nil
            #endif
        }
        /// Ordinary ROOT resolves a store only through this daemon's scope bind.
        /// Idempotent per daemon/root, so re-sent before each ROOT request (also
        /// re-establishes it after helper restart). Qualification binds explicitly.
        func bindOrdinaryScope(_ root: StorageLifecycleRootClient, timeout: TimeInterval = 30) throws {
            guard !policy.isQualification else { return }
            guard let store, let scopeRoot else { throw Failure.invalid }
            try root.bindScope(store: store, rootFD: scopeRoot.descriptor, timeout: timeout)
        }
        func check() throws { if cancelled.withLock({ $0 }) { throw CancellationError() } }
        func cancel() { cancelled.withLock { $0 = true } }
        /// One publication/cancellation linearization point, including cancellation
        /// after native IO has joined but while the owner validates decoded bytes.
        func publish<T: Sendable>(_ value: T) throws -> T {
            try cancelled.withLock {
                guard !$0, !Task.isCancelled else { throw CancellationError() }
                return value
            }
        }
        func run<T: Sendable>(_ action: @escaping @Sendable () throws -> T) async throws -> T {
            try await withTaskCancellationHandler {
                try Task.checkCancellation()
                return try await Task.detached { [self] in
                    try await withCheckedThrowingContinuation { continuation in
                        queue.async { [self] in
                            continuation.resume(with: Result {
                                try check(); let result = try action(); try check(); return result
                            })
                        }
                    }
                }.value
            } onCancel: { self.cancel() }
        }
        func request(_ request: Root.Request, rootFD: Int32 = -1, backingFD: Int32 = -1,
                     returnMissingInitial: Bool = false, deadline: TimeInterval? = nil) async throws -> Root.Reply {
            try await run { [self] in
                let reply: Root.Reply
                #if DEBUG
                if let testSeam { reply = try testSeam.rootRequest(request, rootFD, backingFD) }
                else {
                    guard let root else { throw Failure.invalid }
                    try bindOrdinaryScope(root, timeout: deadline.map { try Self.remaining($0) } ?? 30)
                    reply = try root.request(request, rootFD: rootFD, backingFD: backingFD,
                        timeout: deadline.map { try Self.remaining($0) } ?? 120)
                }
                #else
                guard let root else { throw Failure.invalid }
                try bindOrdinaryScope(root, timeout: deadline.map { try Self.remaining($0) } ?? 30)
                reply = try root.request(request, rootFD: rootFD, backingFD: backingFD,
                    timeout: deadline.map { try Self.remaining($0) } ?? 120)
                #endif
                _ = try Root.decodeReply(Root.encode(reply), for: request)
                if case .failure(let code) = reply.body, !(returnMissingInitial && code == .invalidRequest) {
                    throw StorageLifecycleRootClient.Failure(code)
                }
                return reply
            }
        }
        var requiresAdoption: Bool {
            #if DEBUG
            if let testSeam { return testSeam.adoptionRequest != nil }
            #endif
            return true
        }
        // Assigned exclusively by the concrete ROOT client path. Synchronous
        // lookup adds no owner suspension after checkedAdoptionRequest validates.
        private let nativeAdoptionAuthorization = Mutex<StorageLifecycleAdoptedConnectionAuthorization?>(nil)
        func connectionAuthorization(for request: Adoption.Request, status: AdoptionRoot.Status) throws
            -> StorageLifecycleAdoptedConnectionAuthorization? {
            #if DEBUG
            if testSeam != nil { return nil }
            #endif
            return try nativeAdoptionAuthorization.withLock { value in
                guard let authorization = value,
                      authorization.request == request, authorization.status.origin == status.origin,
                      authorization.status.shimAudit == status.shimAudit,
                      authorization.status.shimUniqueID == status.shimUniqueID else { throw Failure.invalid }
                return authorization
            }
        }
        private func nativeAdoptionRequest(_ request: AdoptionRoot.Request, root: StorageLifecycleRootClient,
                                           storeLock: CanonicalDataStoreLock, deadline: TimeInterval) throws -> AdoptionRoot.Reply {
            if case .complete = request.body {
                nativeAdoptionAuthorization.withLock { $0 = nil }
                let (reply, authorization) = try root.completeAdoptionForConnection(request,
                    storeLock: storeLock, timeout: Self.remaining(deadline))
                nativeAdoptionAuthorization.withLock { $0 = authorization }
                return reply
            }
            return try root.adoptionRequest(request, storeLock: storeLock, timeout: Self.remaining(deadline))
        }
        func adoptionRequest(_ request: AdoptionRoot.Request, storeLock: CanonicalDataStoreLock,
                             deadline: TimeInterval) async throws -> AdoptionRoot.Reply {
            try await run { [self] in
                let reply: AdoptionRoot.Reply
                #if DEBUG
                if let seam = testSeam?.adoptionRequest { reply = try seam(request) }
                else {
                    guard let root else { throw Failure.invalid }
                    try bindOrdinaryScope(root, timeout: Self.remaining(deadline))
                    reply = try nativeAdoptionRequest(request, root: root, storeLock: storeLock, deadline: deadline)
                }
                #else
                guard let root else { throw Failure.invalid }
                try bindOrdinaryScope(root, timeout: Self.remaining(deadline))
                reply = try nativeAdoptionRequest(request, root: root, storeLock: storeLock, deadline: deadline)
                #endif
                _ = try AdoptionRoot.decodeReply(AdoptionRoot.encode(reply), for: request)
                if case .failure(let code) = reply.body { throw StorageLifecycleRootClient.Failure(code) }
                return reply
            }
        }
        func coldRequest(_ request: ColdRoot.Request, storeLock: CanonicalDataStoreLock,
                         deadline: TimeInterval) async throws -> ColdRoot.Reply {
            try await run { [self] in
                let reply: ColdRoot.Reply
                #if DEBUG
                if let seam = testSeam?.coldRequest {
                    reply = try seam(request, Self.remaining(deadline, now: coldNow(), maximum: 120))
                }
                else {
                    guard let root else { throw Failure.invalid }
                    try bindOrdinaryScope(root, timeout: Self.remaining(deadline))
                    reply = try root.coldRequest(request, storeLock: storeLock,
                        timeout: Self.remaining(deadline, maximum: 120))
                }
                #else
                guard let root else { throw Failure.invalid }
                try bindOrdinaryScope(root, timeout: Self.remaining(deadline))
                reply = try root.coldRequest(request, storeLock: storeLock,
                        timeout: Self.remaining(deadline, maximum: 120))
                #endif
                _ = try ColdRoot.decodeReply(ColdRoot.encode(reply), for: request)
                if case .failure(let code) = reply.body { throw StorageLifecycleRootClient.Failure(code) }
                return reply
            }
        }
        func coldNow() -> TimeInterval {
            #if DEBUG
            if let timing = testSeam?.coldTiming { return timing.now() }
            #endif
            return ProcessInfo.processInfo.systemUptime
        }
        func coldSleep(_ interval: TimeInterval) async throws {
            #if DEBUG
            if let timing = testSeam?.coldTiming { try await timing.sleep(interval); return }
            #endif
            try await Task.sleep(for: .seconds(interval))
        }
        func resumeNow() -> TimeInterval {
            #if DEBUG
            if let timing = testSeam?.resumeTiming { return timing.now() }
            #endif
            return ProcessInfo.processInfo.systemUptime
        }
        func resumeSleep(_ interval: TimeInterval) async throws {
            #if DEBUG
            if let timing = testSeam?.resumeTiming { try await timing.sleep(interval); return }
            #endif
            try await Task.sleep(for: .seconds(interval))
        }
        func resumeRequest(_ request: ResumeRoot.Request, storeLock: CanonicalDataStoreLock,
                         deadline: TimeInterval) async throws -> ResumeRoot.Reply {
            try await run { [self] in
                let reply: ResumeRoot.Reply
                #if DEBUG
                if let seam = testSeam?.resumeRequest {
                    _ = try Self.remaining(deadline, now: resumeNow())
                    reply = try seam(request)
                }
                else {
                    guard let root else { throw Failure.invalid }
                    try bindOrdinaryScope(root, timeout: Self.remaining(deadline, now: resumeNow()))
                    reply = try root.resumeRequest(request, storeLock: storeLock, timeout: Self.remaining(deadline, now: resumeNow()))
                }
                #else
                guard let root else { throw Failure.invalid }
                try bindOrdinaryScope(root, timeout: Self.remaining(deadline, now: resumeNow()))
                reply = try root.resumeRequest(request, storeLock: storeLock, timeout: Self.remaining(deadline, now: resumeNow()))
                #endif
                _ = try ResumeRoot.decodeReply(ResumeRoot.encode(reply), for: request)
                if case .failure(let code) = reply.body { throw StorageLifecycleRootClient.Failure(code) }
                return reply
            }
        }
        private static func remaining(_ deadline: TimeInterval,
                                      now: TimeInterval = ProcessInfo.processInfo.systemUptime,
                                      maximum: TimeInterval = 30) throws -> TimeInterval {
            let remaining = deadline - now
            guard remaining > 0 else { throw StorageLifecycleRootClient.Failure(.unavailable) }
            return min(maximum, remaining)
        }
        struct Initialized: Sendable {
            let greeting: StorageLifecycleChildProtocol.Greeting
            let recipient: Checkpoint.Recipient
            let nativeAudit: ProcessAudit?
        }
        func launch(_ initialization: StorageLifecycleChildProcess.Initialization) async throws -> Initialized {
            try await run { [self] in
                guard !launched else { throw Failure.blocked }; launched = true
                #if DEBUG
                if let testSeam {
                    try testSeam.childLaunch?()
                    let audit: ProcessAudit?
                    if let daemon = testSeam.daemonAudit, let child = testSeam.childAudit {
                        audit = .init(daemonAudit: daemon, daemonUniqueID: testSeam.recipient.daemonUniqueID,
                            childAudit: child, childUniqueID: testSeam.recipient.childUniqueID)
                    } else { audit = nil }
                    return Initialized(greeting: testSeam.preparation.greeting, recipient: testSeam.recipient, nativeAudit: audit)
                }
                #endif
                let process = try StorageLifecycleChildProcess.launch(installedHelperTeam: team, policy: policy)
                child = process
                guard let native = process.processIdentity else { throw Failure.invalid }
                let greeting = try process.initialize(initialization)
                let key = try StorageIdentity.Ed25519SPKI(publicData: greeting.controllerSPKI)
                return Initialized(greeting: greeting, recipient: .init(publicKey: key.rawPublicKey,
                    incarnation: greeting.incarnationID, daemonUniqueID: native.daemonUniqueID,
                    childUniqueID: native.childUniqueID, childPID: process.pid),
                    nativeAudit: .init(daemonAudit: native.daemonAudit, daemonUniqueID: native.daemonUniqueID,
                        childAudit: native.childAudit, childUniqueID: native.childUniqueID))
            }
        }
        func requireChild() throws -> StorageLifecycleChildProcess { guard let child else { throw Failure.blocked }; return child }
        func publicTakeoverReplay(requestID: String, old: L.SignedGrant) async throws -> StorageLifecycleChildProcess.PublicTakeoverReplayObservation {
            let request = try StorageLifecycleChildProcess.PublicTakeoverReplayRequest(requestID: requestID, old: old)
            return try await run { [self] in
                #if DEBUG
                if let testSeam {
                    return try .decode(testSeam.childAction(.publicTakeoverReplay(request)), request: request)
                }
                #endif
                // The child's existing exchange lock, framing and finite absolute
                // IO budget apply; no alternate socket or old-key restoration.
                return try requireChild().publicTakeoverReplay(requestID: requestID, old: old)
            }
        }
        func takeover() async throws {
            try await run { [self] in
                #if DEBUG
                if let testSeam { _ = try testSeam.childAction(.takeover); return }
                #endif
                try requireChild().takeover()
            }
        }
        func bind(_ signed: L.SignedGrant) async throws {
            try await run { [self] in
                #if DEBUG
                if let testSeam { _ = try testSeam.childAction(.bind(signed)); return }
                #endif
                let child = try requireChild()
                if signed.grant.operation == .retire { try child.bindRetire(signed) } else { try child.bindGrant(signed) }
            }
        }
        func csr() async throws -> Data {
            try await run { [self] in
                #if DEBUG
                if let testSeam { return try testSeam.childAction(.csr) }
                #endif
                return try requireChild().controllerCSR()
            }
        }
        func connectBoot(_ stream: FileHandle, boot: StorageLifecycleChildProcess.Boot) async throws {
            try await run { [self] in
                #if DEBUG
                if let testSeam { _ = try testSeam.childAction(.connectBoot); return }
                #endif
                try requireChild().connectBoot(socket: stream.fileDescriptor, boot: boot)
            }
        }
        func stageServiceRebind(_ stream: FileHandle, change: L.ServiceChangeRequest,
                                boot: StorageLifecycleChildProcess.Boot) async throws {
            try await run { [self] in
                #if DEBUG
                if let testSeam { _ = try testSeam.childAction(.stageServiceRebind(change, boot)); return }
                #endif
                try requireChild().stageServiceRebind(socket: stream.fileDescriptor, change: change, boot: boot)
            }
        }
        func connectWorkload(_ stream: FileHandle) async throws {
            try await run { [self] in
                #if DEBUG
                if let testSeam { _ = try testSeam.childAction(.connectWorkload); return }
                #endif
                try requireChild().connectWorkload(socket: stream.fileDescriptor)
            }
        }
        func workload(_ request: ManagedStorageControlProtocol.ControlRequest) async throws -> Data {
            try await run { [self] in
                #if DEBUG
                if let testSeam { return try testSeam.childAction(.workload(request)) }
                #endif
                return try requireChild().workloadCommand(request: request)
            }
        }
        /// nil is a closed child refusal (rejected/unavailable), never a retry hint.
        func attachmentCertificate(_ stream: FileHandle,
                                   request: StorageLifecycleChildProcess.AttachmentCertificateRequest) async throws -> Data? {
            try await run { [self] in
                #if DEBUG
                if let testSeam {
                    let data = try testSeam.childAction(.attachmentCertificate(request))
                    guard case .certificate(let certificate) = try ManagedStorageControlProtocol.AttachmentCertificateResult.decode(data) else { return nil }
                    return certificate.der
                }
                #endif
                guard case .certificate(let certificate) = try requireChild().attachmentCertificate(socket: stream.fileDescriptor,
                    request: request) else { return nil }
                return certificate.der
            }
        }
        func retire() async throws {
            try await run { [self] in
                #if DEBUG
                if let testSeam { _ = try testSeam.childAction(.retire); return }
                #endif
                try requireChild().retire()
            }
        }
        func close() async {
            await withCheckedContinuation { continuation in
                queue.async { [self] in child?.close(); child = nil; continuation.resume() }
            }
        }
        deinit {
            if let child { queue.async { child.close() } }
        }
    }
}
#endif

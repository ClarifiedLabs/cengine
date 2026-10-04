import CEngineCore
import Dispatch
import Foundation

/// Keep both failures without reopening admission or discarding quarantine.
struct OriginalConsumerContainmentFailure: Error, LocalizedError {
    let observation: Error
    let containment: Error
    var errorDescription: String? {
        "original consumer observation failed: \(observation.localizedDescription); containment also failed: \(containment.localizedDescription)"
    }
}

/// Diagnostic only: finite vocabulary, no error text, identifiers or authority.
/// The original error remains in memory so cleanup retains its exact failures.
struct OriginalConsumerFailureDiagnostic: Codable, Sendable, Equatable {
    enum Stage: String, Codable, Sendable, CaseIterable {
        case preflightIdentity = "preflight-identity", preflightFreeze = "preflight-freeze"
        case preflightJoin = "preflight-join", preflightBinding = "preflight-binding"
        case preflightCandidate = "preflight-candidate", preflightArm = "preflight-arm"
        case preflightArmReturn = "preflight-arm-return", preflightArmedPublication = "preflight-armed-publication"
        case preflightBaselineWait = "preflight-baseline-wait", preflightBaselineValidation = "preflight-baseline-validation"
        case preflightBaselineRecord = "preflight-baseline-record", preflightBaselinePublication = "preflight-baseline-publication"
        case adoptionReturn = "adoption-return"
        case observationSetup = "observation-setup", ownerFence = "owner-fence"
        case maintenanceSession = "maintenance-session", originalTuple = "original-tuple"
        case successorScope = "successor-scope", baselineValidation = "baseline-validation"
        case probeConstruction = "probe-construction", armValidation = "arm-validation"
        case currentBoot = "current-boot", successorValidation = "successor-validation"
        case observationClaim = "observation-claim", observationDeadline = "observation-deadline"
        case workerArm = "worker-arm", workerArmReply = "worker-arm-reply"
        case originalRetire = "original-retire", retireReturnValidation = "retire-return-validation"
        case originalProbe = "original-probe", sameECorrelation = "same-e-correlation"
        case workerQuery = "worker-query", workerQueryReply = "worker-query-reply"
        case workerPollDeadline = "worker-poll-deadline", workerPollSleep = "worker-poll-sleep"
        case observedValidation = "observed-validation", originalResult = "original-result"
        case workerFinalize = "worker-finalize", workerFinalizeReply = "worker-finalize-reply"
        case finalValidation = "final-validation"
        case release, containment, joinWork = "join-work"
        case inventorySnapshot = "inventory-snapshot", volumePlan = "volume-plan"
        case inventoryReconcile = "inventory-reconcile", settledValidation = "settled-validation"
        case completionCommit = "completion-commit", admissionReopen = "admission-reopen"
        case serviceBoot = "service-boot", freshObservation = "fresh-observation"
        case resultPublication = "result-publication", workReopen = "work-reopen"
    }
    enum Category: String, Codable, Sendable, CaseIterable {
        case cancelled, ownerRejected = "owner-rejected", protocolRejected = "protocol-rejected", other
    }
    let stage: Stage
    let category: Category

    init(stage: Stage, error: any Error) {
        self.stage = stage
        switch error {
        case is CancellationError: category = .cancelled
        case is ManagedStorageFailure, is ManagedStorageLifecycleOwner.Failure: category = .ownerRejected
        case is OriginalConsumerObservationProtocol.Failure, is ConsumerObservationProtocol.Failure:
            category = .protocolRejected
        default: category = .other
        }
    }

    @MainActor final class Cursor { var stage: Stage = .observationSetup }

    private struct Failure: Error {
        let diagnostic: OriginalConsumerFailureDiagnostic
        let underlying: any Error
    }

    /// Cleanup can nest operation + release + containment failures. Prefer the
    /// first diagnosed failure; never flatten/replace the cleanup error itself.
    static func find(in error: any Error) -> Self? { find(in: error, remaining: 4) }
    private static func find(in error: any Error, remaining: Int) -> Self? {
        guard remaining > 0 else { return nil }
        if let failure = error as? Failure { return failure.diagnostic }
        if let cleanup = error as? OriginalConsumerContainmentFailure {
            return find(in: cleanup.observation, remaining: remaining - 1)
                ?? find(in: cleanup.containment, remaining: remaining - 1)
        }
        return nil
    }

    /// Remove only our annotation; preserve existing typed error classification.
    static func underlying(_ error: any Error) -> any Error {
        (error as? Failure)?.underlying ?? error
    }

    static func annotate(_ error: any Error, at stage: Stage?) -> any Error {
        guard let stage else { return error }
        if find(in: error) != nil { return error }
        return Failure(diagnostic: Self(stage: stage, error: error), underlying: error)
    }

    static func step<T>(_ stage: Stage?, _ body: () throws -> T) throws -> T {
        do { return try body() } catch { throw annotate(error, at: stage) }
    }
    static func step<T>(_ stage: Stage?, _ body: () async throws -> T,
        isolation: isolated (any Actor)? = #isolation) async throws -> T {
        do { return try await body() } catch { throw annotate(error, at: stage) }
    }
}

/// Failure-only host breadcrumbs for an already retained, validated RTM103 owner.
/// No error wrapping, description, NSError bridging, or authority in this sink.
final class OriginalConsumerHostDiagnostic: @unchecked Sendable {
    enum Stage: String, Sendable, CaseIterable {
        case clientProbeBinding = "client-probe-binding"
        case shimGuestWorkerReturn = "shim-guest-worker-return"
        case shimGuestConnectDeadline = "shim-guest-connect-deadline"
        case clientCheckedReply = "client-checked-reply"
        case clientDeadlineBoot = "client-deadline-boot"
        case clientDeadlineCancellation = "client-deadline-cancellation"
        case clientDeadlineState = "client-deadline-state"
        case clientEncode = "client-encode"
        case clientEvidence = "client-evidence"
        case clientExchange = "client-exchange"
        case clientPeerAfter = "client-peer-after"
        case clientPeerBefore = "client-peer-before"
        case clientPostDeadline = "client-post-deadline"
        case clientPreDeadline = "client-pre-deadline"
        case clientRemoteFailure = "client-remote-failure"
        case clientReplyAcknowledgement = "client-reply-acknowledgement"
        case clientReplyBinding = "client-reply-binding"
        case clientReplyCancellation = "client-reply-cancellation"
        case clientReplyDeadline = "client-reply-deadline"
        case clientReplyPayload = "client-reply-payload"
        case clientRequestValidation = "client-request-validation"
        case clientSignedIdentity = "client-signed-identity"
        case clientSocketConnect = "client-socket-connect"
        case clientSocketDeadline = "client-socket-deadline"
        case clientSocketDecode = "client-socket-decode"
        case clientSocketDescriptor = "client-socket-descriptor"
        case clientSocketEncodeWrite = "client-socket-encode-write"
        case clientSocketReadDecode = "client-socket-read-decode"
        case clientSocketRegister = "client-socket-register"
        case clientSocketWrite = "client-socket-write"
        case clientTransportReturn = "client-transport-return"
        case clientTransportRun = "client-transport-run"
        case shimAdmission = "shim-admission"
        case shimAdoptFD = "shim-adopt-fd"
        case shimBinding = "shim-binding"
        case shimCheckedReply = "shim-checked-reply"
        case shimConnectCancellation = "shim-connect-cancellation"
        case shimConnectIdentity = "shim-connect-identity"
        case shimDispatch = "shim-dispatch"
        case shimDispatchAdmission = "shim-dispatch-admission"
        case shimDuplicateFD = "shim-duplicate-fd"
        case shimGuestConnect = "shim-guest-connect"
        case shimGuestDecode = "shim-guest-decode"
        case shimGuestEncode = "shim-guest-encode"
        case shimGuestIODeadline = "shim-guest-iodeadline"
        case shimGuestPayload = "shim-guest-payload"
        case shimGuestRead = "shim-guest-read"
        case shimGuestRemoteFailure = "shim-guest-remote-failure"
        case shimGuestReplyBinding = "shim-guest-reply-binding"
        case shimGuestReturnCancellation = "shim-guest-return-cancellation"
        case shimGuestReturnIdentity = "shim-guest-return-identity"
        case shimGuestRun = "shim-guest-run"
        case shimGuestWrite = "shim-guest-write"
        case shimLeaseAdmission = "shim-lease-admission"
        case shimLeaseDeadline = "shim-lease-deadline"
        case shimLeaseTransition = "shim-lease-transition"
        case shimReleaseTeardown = "shim-release-teardown"
        case shimReleaseStop = "shim-release-stop"
        case shimPreviousEvidence = "shim-previous-evidence"
        case shimReplyAck = "shim-reply-ack"
        case shimReplyAdmission = "shim-reply-admission"
        case shimReplyEncode = "shim-reply-encode"
        case shimReplyTransport = "shim-reply-transport"
        case shimReplyWrite = "shim-reply-write"
        case shimRequestDecode = "shim-request-decode"
        case shimRequestValidation = "shim-request-validation"
        case shimReserve = "shim-reserve"
        case shimReturnCancellation = "shim-return-cancellation"
        case shimReturnDeadline = "shim-return-deadline"
        case shimSignedIdentity = "shim-signed-identity"
        case shimStartExchange = "shim-start-exchange"
        case shimTaskReturn = "shim-task-return"
        case shimTransportSetup = "shim-transport-setup"
        case shimValidationDeadline = "shim-validation-deadline"
    }
    enum Category: String, Sendable, CaseIterable {
        case cancelled, deadline, protocolRejected = "protocol-rejected"
        case decoding, encoding, posix, other
    }
    let enabled: Bool
    private let lock = NSLock()
    private var current: Stage
    var stage: Stage {
        get { lock.withLock { current } }
        set { lock.withLock { current = newValue } }
    }
    init(enabled: Bool, stage: Stage) { self.enabled = enabled; current = stage }

    static func enabled(_ retained: OriginalConsumerObservationProtocol.Binding?) -> Bool {
        guard let retained,
              retained.profile == ManagedPrepareCompatibilityProtocol.fullProfile else { return false }
        do { try OriginalConsumerObservationProtocol.validate(retained); return true }
        catch { return false }
    }
    static func category(_ error: any Error) -> Category {
        switch error {
        case is CancellationError: return .cancelled
        case is AsyncTimeout.TimeoutError: return .deadline
        case is OriginalConsumerObservationProtocol.Failure: return .protocolRejected
        case is DecodingError: return .decoding
        case is EncodingError: return .encoding
        case is POSIXError: return .posix
        default: return .other
        }
    }
    /// Snapshot on the caller, but never perform IO (including injected IO) there.
    func report(_ error: any Error, sink: Sink = .standardError) {
        guard enabled else { return }
        sink.enqueue(stage: stage, category: Self.category(error))
    }

    /// Runtime metadata is already closed and contains no retained identity or error.
    static func report(_ diagnostic: OriginalConsumerFailureDiagnostic, sink: Sink = .standardError) {
        sink.enqueue(.runtime(diagnostic))
    }

    /// One drain worker, at most 32 pending entries plus one in-flight write.
    /// A blocked stderr drops new breadcrumbs, never stalls containment. No IO
    /// holds the lock, and no task or dispatch block is created per report.
    final class Sink: @unchecked Sendable {
        static let capacity = 32
        static let standardError = Sink { try FileHandle.standardError.write(contentsOf: $0) }
        fileprivate enum Entry: Sendable {
            case host(Stage, Category)
            case runtime(OriginalConsumerFailureDiagnostic)

            var line: String {
                let stage: String, category: String
                switch self {
                case .host(let point, let kind): stage = point.rawValue; category = kind.rawValue
                case .runtime(let diagnostic): stage = diagnostic.stage.rawValue; category = diagnostic.category.rawValue
                }
                return "cengine original-host-failure stage=\(stage) category=\(category)\n"
            }
        }
        private let lock = NSLock()
        private let worker = DispatchQueue(label: "cengine.original-host-diagnostic", qos: .utility)
        private let emit: @Sendable (Data) throws -> Void
        private var pending: [Entry] = []
        private var draining = false

        init(emit: @escaping @Sendable (Data) throws -> Void) { self.emit = emit }

        var pendingCount: Int { lock.withLock { pending.count } }

        fileprivate func enqueue(stage: Stage, category: Category) {
            enqueue(.host(stage, category))
        }

        fileprivate func enqueue(_ entry: Entry) {
            lock.withLock {
                guard pending.count < Self.capacity else { return }
                pending.append(entry)
                guard !draining else { return }
                draining = true
                worker.async { self.drain() }
            }
        }

        private func drain() {
            while let entry = lock.withLock({ () -> Entry? in
                guard !pending.isEmpty else { draining = false; return nil }
                return pending.removeFirst()
            }) {
                try? emit(Data(entry.line.utf8))
            }
        }
    }
}

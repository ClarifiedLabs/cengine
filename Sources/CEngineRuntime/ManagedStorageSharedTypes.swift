#if os(macOS)
import CEngineCore
import Foundation
import Darwin

/// Closed owner-adoption diagnostic. Never retain an underlying error or payload.
/// A nil stage preserves ordinary (non-replacement) certificate errors.
enum ManagedStorageWorkerAdoptionFailure: String, Error, Codable, Sendable, CaseIterable {
    case childRebind = "child-rebind"
    case certificateCSR = "certificate-csr"
    case certificateIssuance = "certificate-issuance"
    case certificateInstall = "certificate-install"
    case controlStream = "control-stream"
    case controlConnect = "control-connect"
    case controlContext = "control-context"
    case query
    case reconcile
    case localEvidenceCommit = "local-evidence-commit"
    case lifecycleRecovery = "lifecycle-recovery"

    @MainActor static func step<T>(_ stage: Self?, _ operation: () throws -> T) throws -> T {
        do { return try operation() }
        catch { if let stage { throw stage }; throw error }
    }

    @MainActor static func step<T>(_ stage: Self?, _ operation: @MainActor () async throws -> T) async throws -> T {
        do { return try await operation() }
        catch { if let stage { throw stage }; throw error }
    }
}

/// Closed failure projection only; never retains Error, errno, text or payload.
struct ManagedStorageChildRebindDiagnostic: Error, Codable, Sendable, Equatable {
    enum Category: String, Codable, Sendable, CaseIterable {
        case invalidConfiguration = "invalid-configuration"
        case protocolViolation = "protocol-violation"
        case unauthorized
        case serviceUnavailable = "service-unavailable"
        case timeout, system
        case ownerRejected = "owner-rejected"
        case cancelled, other
    }
    enum Point: String, Codable, Sendable, CaseIterable {
        case construction
        case preflightClosed = "preflight-closed"
        case preflightState = "preflight-state"
        case preflightBinding = "preflight-binding"
        case preflightKey = "preflight-key"
        case encoding
        case ipcWrite = "ipc-write"
        case ipcRead = "ipc-read"
        case invalidAcknowledgement = "invalid-acknowledgement"
        case ownerRevalidation = "owner-revalidation"
    }

    let point: Point
    let category: Category
    let firstClose: ManagedStorageCloseDiagnostic?

    init(point: Point, error: any Error,
         firstClose: ManagedStorageCloseDiagnostic? = nil) {
        self.firstClose = firstClose
        self.point = point
        switch error {
        case ManagedStorageControlFailure.invalidConfiguration: category = .invalidConfiguration
        case ManagedStorageControlFailure.protocolViolation: category = .protocolViolation
        case ManagedStorageControlFailure.unauthorized: category = .unauthorized
        case ManagedStorageControlFailure.serviceUnavailable: category = .serviceUnavailable
        case ManagedStorageControlFailure.system(let code): category = code == ETIMEDOUT ? .timeout : .system
        case is ManagedStorageFailure, is ManagedStorageLifecycleOwner.Failure: category = .ownerRejected
        case is CancellationError: category = .cancelled
        default: category = .other
        }
    }

    @MainActor static func revalidate(_ body: () throws -> Void) throws {
        do { try body() }
        catch { throw Self(point: .ownerRevalidation, error: error) }
    }
}

/// Managed-storage failures shared by the lifecycle owner, workload coordinator
/// and backend, independent of any transport.
enum ManagedStorageFailure: Error { case invalid, blocked, repairRequired, changedServiceEpoch, unavailable, daemonRestartRequired }

/// Read-only HOST intents journal projection.
struct ManagedStorageJournalSnapshot: Sendable {
    let revision: UInt64
    let volumes: [HostStorageIntents.Volume]
    let intents: [HostStorageIntents.Intent]
    let reconciliationRequired: Bool
}

struct ManagedStorageHistoricalContext: Equatable, Sendable {
    let serviceEpoch: String
    let controller: StorageIdentity.Controller
}

/// Recovery permission for earlier controller contexts. It permits settlement,
/// not certificate delivery/remount under old contexts. Minted only by the
/// restricted factories below; the memberwise initializer is file-private.
struct ManagedStorageControllerRecovery {
    fileprivate let current: ManagedStorageControlClient.Context
    fileprivate let previous: [ManagedStorageHistoricalContext]
    fileprivate let workerHistoryReference: String?
    fileprivate init(current: ManagedStorageControlClient.Context, previous: [ManagedStorageHistoricalContext], workerHistoryReference: String?) {
        self.current = current; self.previous = previous; self.workerHistoryReference = workerHistoryReference
    }

    /// Only the owner can seal the completed ROOT, Query and census proof chain.
    @MainActor static func lifecycle(_ authorization: ManagedStorageLifecycleOwner.RecoveryAuthorization) throws -> Self {
        try makeLifecycle(current: authorization.current, previous: authorization.history,
            workerHistoryReference: authorization.workerHistoryReference)
    }

    private static func makeLifecycle(current: ManagedStorageControlClient.Context,
                                      previous: [ManagedStorageLifecycleCheckpoint.Context],
                                      workerHistoryReference: String?) throws -> Self {
        Self(current: current, previous: try previous.map {
            ManagedStorageHistoricalContext(serviceEpoch: $0.serviceEpoch,
                controller: .init(epoch: try .init($0.controllerEpoch), key: try .init($0.controllerKey)))
        }, workerHistoryReference: workerHistoryReference)
    }

    /// Called only from the owner's retained native maintenance task after fresh
    /// ROOT completion, child rebind, full-identity Query and physical census.
    @MainActor static func lifecycleReplacement(_ authorization: ManagedStorageLifecycleOwner.ReplacementRecoveryAuthorization) throws -> Self {
        let current = authorization.current, predecessor = authorization.predecessor
        let workerHistoryReference = authorization.reference
        guard predecessor.serviceEpoch != current.serviceEpoch,
              predecessor.controllerEpoch == current.controllerEpoch,
              predecessor.controllerKey == current.controllerKey,
              current.lifecycleIdentity != nil else { throw ManagedStorageFailure.invalid }
        _ = try StorageIdentity.SPKISHA256(workerHistoryReference)
        return try makeLifecycle(current: current,
            previous: [predecessor],
            workerHistoryReference: workerHistoryReference)
    }

    func permits(_ intent: HostStorageIntents.Intent, context: ManagedStorageControlClient.Context) -> Bool {
        context == current && intent.store == current.store && previous.contains {
            $0.serviceEpoch == intent.serviceEpoch && $0.controller.epoch.rawValue == intent.controllerEpoch &&
                $0.controller.key.rawValue == intent.controllerKey
        }
    }
    func replacementEvidence(from old: HostStorageIntents.Intent, to next: HostStorageIntents.Intent) -> HostStorageIntents.ReplacementRecovery? {
        guard permits(old, context: current), next.store == current.store, next.serviceEpoch == current.serviceEpoch,
              next.controllerEpoch == current.controllerEpoch, next.controllerKey == current.controllerKey else { return nil }
        return .init(serviceEpoch: old.serviceEpoch, controllerEpoch: old.controllerEpoch,
            controllerKey: old.controllerKey, provenanceReference: current.provenanceReference,
            workerHistoryReference: old.controllerEpoch == current.controllerEpoch ? workerHistoryReference : nil)
    }
    func crossesServiceEpoch(_ intent: HostStorageIntents.Intent) -> Bool {
        permits(intent, context: current) && intent.serviceEpoch != current.serviceEpoch
    }
}

enum ManagedStorageJournalPolicy {
    /// Canonical V is mandatory. Replays preserve operation IDs; omitted records
    /// never erase tombstones or unresolved generations.
    static func volumeAdditions(_ records: [VolumeRecord], existing: [String: HostStorageIntents.Volume]) throws -> [HostStorageIntents.Volume] {
        var ids = Set<String>(), names = Set<String>(), additions: [HostStorageIntents.Volume] = []
        for record in records {
            guard let id = record.instanceID?.uuidString.lowercased(), ids.insert(id).inserted,
                  names.insert(record.name).inserted else { throw ManagedStorageFailure.invalid }
            _ = try StorageIdentity.StoreID(id)
            if let prior = existing[id] {
                guard prior.name == record.name, !prior.isDeleted else { throw ManagedStorageFailure.repairRequired }
            } else {
                guard !existing.values.contains(where: { $0.name == record.name && !$0.isDeleted }) else { throw ManagedStorageFailure.repairRequired }
                additions.append(.init(id: id, name: record.name, createOperation: UUID().uuidString.lowercased(),
                    deleteOperation: UUID().uuidString.lowercased()))
            }
        }
        return additions
    }

    /// Attachment certificate eligibility: an undrained slot in the admitted
    /// prepare phase, or a runtime slot after prepare completed and froze.
    static func requireCertificateEligible(_ intent: HostStorageIntents.Intent, attachment: String) throws {
        guard let slot = intent.slots.first(where: { $0.attachment == attachment }), slot.receipt == nil,
              (slot.role == "prepare" && intent.phase == .prepareAdmitted) ||
                (slot.role == "runtime" && intent.phase == .runtimeFrozen && intent.prepareCompleted) else {
            throw ManagedStorageFailure.blocked
        }
    }
}
#endif

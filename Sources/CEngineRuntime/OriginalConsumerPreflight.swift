#if os(macOS)
import CEngineCore
import Foundation

/// Selection only. Authority and all credential/boot values come from the live owner.
enum OriginalConsumerRuntimeCarrier {
    struct Request: Codable, Sendable, Equatable {
        let version: UInt32
        let profile: String
        let requestID: String
        let operationUUID: String
        let caseName: OriginalConsumerObservationProtocol.Case
        let container: String
        let containerInstance: String
        func validate() throws {
            try validateShape()
            guard [.sameEExistingData, .sameEOldLeafReconnect, .sameERetainedFD, .crossERetainedFD, .crossEOldLeafReconnect, .crossEExistingData, .wrongVolume, .wrongKey, .wrongRole, .wrongMode, .wrongEpoch, .crossMountRootGrant, .retiredRootGrantReplay, .attachmentKeyReuse, .delayedRegistration].contains(caseName)
            else { throw OriginalConsumerObservationProtocol.Failure.unsupported }
        }
        /// Unsigned queue parsing only. Both signed activation and the live
        /// runtime binding retain the separate closed supported-case check.
        func validateShape() throws {
            guard version == 1, profile == ManagedPrepareCompatibilityProtocol.fullProfile,
                  OriginalConsumerObservationProtocol.hash(container),
                  [requestID, operationUUID, containerInstance].allSatisfy(DiskInitializationProtocol.validUUID)
            else { throw OriginalConsumerObservationProtocol.Failure.invalid }
        }
    }
    struct Candidate: Codable, Sendable, Equatable {
        let request: Request
        let binding: OriginalConsumerObservationProtocol.Binding
        let ownerRequest: StorageServiceTypes.ReplacementRequest
    }
    /// Public scheduling acknowledgment, never a backing or authority capability.
    /// Production separately checks this exact reader's installed live identity.
    struct RootBaselineMount: Codable, Sendable, Equatable {
        let volume: String
        let readerAttachment: String
        let readerKey: String
        let contentSHA256: String
    }
    struct Baseline: Codable, Sendable, Equatable {
        let version: UInt32
        let binding: OriginalConsumerObservationProtocol.Binding
        let readerIntent: String
        let readerAttachment: String
        let readerKey: String
        let snapshotSHA256: String
        var rootPair: [RootBaselineMount]? = nil
        func validate() throws {
            try OriginalConsumerObservationProtocol.validate(binding)
            guard binding.caseName.isRoot || binding.caseName.isWritableFD,
                  DiskInitializationProtocol.validUUID(readerIntent),
                  DiskInitializationProtocol.validUUID(readerAttachment),
                  readerIntent != binding.scope.intent, readerAttachment != binding.targetAttachment,
                  OriginalConsumerObservationProtocol.hash(readerKey), readerKey != binding.key,
                  OriginalConsumerObservationProtocol.hash(snapshotSHA256) else {
                throw OriginalConsumerObservationProtocol.Failure.invalid
            }
            if binding.caseName.isRoot {
                guard version == 2, let rootPair, rootPair.count == 2,
                      rootPair[0].readerAttachment == readerAttachment, rootPair[0].readerKey == readerKey,
                      Set(rootPair.map(\.volume)).count == 2,
                      Set(rootPair.map(\.readerAttachment)).count == 2,
                      Set(rootPair.map(\.readerKey)).count == 2,
                      Set(rootPair.map(\.contentSHA256)).count == 2,
                      rootPair.allSatisfy({ DiskInitializationProtocol.validUUID($0.volume)
                        && DiskInitializationProtocol.validUUID($0.readerAttachment)
                        && $0.readerAttachment != binding.targetAttachment && $0.readerKey != binding.key
                        && OriginalConsumerObservationProtocol.hash($0.readerKey)
                        && OriginalConsumerObservationProtocol.hash($0.contentSHA256) })
                else { throw OriginalConsumerObservationProtocol.Failure.invalid }
            } else {
                guard version == 1, rootPair == nil else { throw OriginalConsumerObservationProtocol.Failure.invalid }
            }
        }
        func validateRootPositive(_ positive: OriginalConsumerObservationProtocol.Evidence) throws {
            try validate()
            guard binding.caseName.isRoot, positive.arm == .init(binding), let roots = positive.roots,
                  let rootPair else { throw OriginalConsumerObservationProtocol.Failure.invalid }
            for (baseline, original) in zip(rootPair, [roots.source, roots.target]) {
                guard baseline.volume == original.read.authority.binding.volume,
                      baseline.contentSHA256 == original.read.contentSHA256,
                      baseline.readerKey != original.read.authority.binding.key,
                      baseline.readerAttachment != original.read.authority.binding.attachment
                else { throw OriginalConsumerObservationProtocol.Failure.invalid }
            }
        }
    }
    struct Result: Codable, Sendable {
        let worker: ConsumerObservationProtocol.Status
        let original: OriginalConsumerObservationProtocol.Evidence
        let retirement: ManagedVolumeLifecycleCoordinator.OriginalRetirement?
        let positive: OriginalConsumerObservationProtocol.Evidence?
        let baseline: Baseline?
        let registration: Registration?
        init(_ evidence: OriginalConsumerReplacementEvidence) {
            worker = evidence.worker; original = evidence.original; retirement = evidence.retirement
            positive = evidence.positive; baseline = evidence.baseline; registration = evidence.registration
        }
    }
    /// Positive-only use of the existing sealed v4 Arm: it sends the actual
    /// installed client's root GETATTR and releases without Begin or retirement.
    struct FreshGetattr: Codable, Sendable, Equatable {
        let original: OriginalConsumerObservationProtocol.Binding
        let binding: OriginalConsumerObservationProtocol.Binding
        let service: StorageServiceTypes.Scope
        let serverDERSHA256: String
        let evidence: OriginalConsumerObservationProtocol.Evidence
        let released: Bool
        static func required(_ name: OriginalConsumerObservationProtocol.Case) -> Bool {
            [.sameEExistingData, .crossEExistingData, .sameEOldLeafReconnect, .attachmentKeyReuse, .delayedRegistration].contains(name)
        }
        func validate(original expected: OriginalConsumerObservationProtocol.Binding) throws {
            typealias O = OriginalConsumerObservationProtocol
            try O.validate(original); try O.validate(binding)
            guard original == expected, Self.required(original.caseName), released,
                  binding.caseName == .sameEExistingData,
                  binding.requestID == original.requestID, binding.operationUUID == original.operationUUID,
                  binding.armDigest == original.armDigest,
                  binding.scope.store == original.scope.store,
                  binding.scope.container == original.scope.container,
                  binding.scope.containerInstance == original.scope.containerInstance,
                  binding.scope.serviceEpoch != original.scope.serviceEpoch,
                  binding.scope.intent != original.scope.intent, binding.scope.launch != original.scope.launch,
                  binding.boot != original.boot, binding.generation != original.generation,
                  binding.targetAttachment != original.targetAttachment, binding.key != original.key,
                  binding.certificateSHA256 != original.certificateSHA256,
                  service.serviceEpoch == binding.scope.serviceEpoch,
                  DiskInitializationProtocol.validUUID(service.workerUUID), O.hash(serverDERSHA256)
            else { throw O.Failure.invalid }
            _ = try O.checkedReply(JSONEncoder().encode(evidence), request: .init(binding: binding, command: .arm,
                payload: JSONEncoder().encode(O.GuestArm(binding))))
        }
    }
    /// Positive-only sealed v6 Arm: both current original mounted clients perform
    /// real root GETATTR + READ, then release/worker join before publication.
    struct FreshRootRead: Codable, Sendable, Equatable {
        let original: OriginalConsumerObservationProtocol.Binding
        let binding: OriginalConsumerObservationProtocol.Binding
        let service: StorageServiceTypes.Scope
        let serverDERSHA256: String
        let evidence: OriginalConsumerObservationProtocol.Evidence
        let released: Bool
        func validate(previous: RootResult) throws {
            typealias O = OriginalConsumerObservationProtocol
            try O.validate(original); try O.validate(binding)
            guard original == previous.binding, original.caseName.isRoot, released,
                  binding.caseName == .crossMountRootGrant,
                  binding.requestID == original.requestID, binding.operationUUID == original.operationUUID,
                  binding.armDigest == original.armDigest, binding.scope.store == original.scope.store,
                  binding.scope.container == original.scope.container,
                  binding.scope.containerInstance == original.scope.containerInstance,
                  binding.scope.serviceEpoch != original.scope.serviceEpoch,
                  binding.scope.intent != original.scope.intent, binding.scope.launch != original.scope.launch,
                  binding.scope.prepare != original.scope.prepare,
                  binding.boot != original.boot, binding.generation != original.generation,
                  service.serviceEpoch == binding.scope.serviceEpoch,
                  service.workerUUID != previous.service.workerUUID,
                  DiskInitializationProtocol.validUUID(service.workerUUID), O.hash(serverDERSHA256),
                  let fresh = evidence.roots, let old = previous.positive.roots,
                  let baseline = previous.baseline.rootPair else { throw O.Failure.invalid }
            _ = try O.checkedReply(JSONEncoder().encode(evidence), request: .init(binding: binding, command: .arm,
                payload: JSONEncoder().encode(O.GuestArm(binding))))
            let freshPair = [fresh.source, fresh.target], oldPair = [old.source, old.target]
            guard Set(freshPair.map { $0.read.authority.binding.volume }) == Set(baseline.map(\.volume)) else { throw O.Failure.invalid }
            for item in freshPair {
                let authority = item.read.authority.binding
                guard let expected = baseline.first(where: { $0.volume == authority.volume }),
                      item.read.contentSHA256 == expected.contentSHA256,
                      oldPair.allSatisfy({ $0.read.authority.binding.attachment != authority.attachment
                        && $0.read.authority.binding.key != authority.key && $0.leafSHA256 != item.leafSHA256 })
                else { throw O.Failure.invalid }
            }
        }
    }
    struct Failed: Encodable, Sendable {
        let requestID: String
        let code = "original-consumer-failed"
        var diagnostic: OriginalConsumerFailureDiagnostic? = nil
    }
}

/// In-memory sequencing only; cannot construct a verified boot or observation.
/// Production validates its retained live boot before recording a baseline.
struct OriginalConsumerBaselineGate {
    private enum State { case armed, begun, released }
    let binding: OriginalConsumerObservationProtocol.Binding
    private var state = State.armed
    private(set) var baseline: OriginalConsumerRuntimeCarrier.Baseline?
    init(binding: OriginalConsumerObservationProtocol.Binding) { self.binding = binding }
    mutating func record(_ value: OriginalConsumerRuntimeCarrier.Baseline, stage: String) throws {
        try value.validate()
        guard state == .armed, baseline == nil, value.binding == binding,
              stage == "armed-mounted-positive" else { throw OriginalConsumerObservationProtocol.Failure.invalid }
        baseline = value
    }
    mutating func begin() throws {
        guard state == .armed, !(binding.caseName.isWritableFD || binding.caseName.isRoot) || baseline != nil
        else { throw OriginalConsumerObservationProtocol.Failure.invalid }
        state = .begun
    }
    mutating func release() { state = .released }
}

/// Scheduling identity only, never a boot/credential capability.
struct OriginalConsumerPreflightIdentity: Equatable, Sendable {
    let serviceGeneration: UUID
    let shimGeneration: UInt64
    let launch: String
    let instance: String
    static func requireMatch<Client: AnyObject>(_ original: Self, _ current: Self,
        captured: Client, currentClient: Client?) throws {
        guard original == current, captured === currentClient else { throw OriginalConsumerObservationProtocol.Failure.invalid }
    }
}

/// Closing admission never releases the loop lease. Lifecycle control must drain
/// naturally: cancelling its exchange would fence the live owner.
enum OriginalConsumerNotificationFreeze {
    enum Policy { case cancelLegacy, drainLifecycle }
    static func close(_ work: RawServiceWorkTracker, task: Task<Void, Never>?, policy: Policy) {
        work.close()
        if policy == .cancelLegacy { task?.cancel() }
    }
}

/// Scheduling only: current-worker observations must precede replacement;
/// cross-E observations consume the returned native maintenance capability.
/// Public takeover and service isolation remain explicitly unsupported here.
enum OriginalConsumerObservationDispatch: Equatable {
    case roots, sameE, wrongHello, replacement
    init(_ name: OriginalConsumerObservationProtocol.Case) throws {
        switch name {
        case .crossMountRootGrant, .retiredRootGrantReplay: self = .roots
        case .sameEExistingData, .sameEOldLeafReconnect, .sameERetainedFD,
             .attachmentKeyReuse, .delayedRegistration: self = .sameE
        case .wrongVolume, .wrongKey, .wrongRole, .wrongMode, .wrongEpoch: self = .wrongHello
        case .crossEExistingData, .crossEOldLeafReconnect, .crossERetainedFD: self = .replacement
        case .replayedTakeover, .legacyConnection, .secondServiceExclusivity:
            throw OriginalConsumerObservationProtocol.Failure.unsupported
        }
    }
}

/// A total pre-fault budget. Timeout never proves that a task was joined.
struct OriginalConsumerPreflightDeadline: Sendable {
    private let deadline = ContinuousClock.now.advanced(by: .seconds(10))
    func remaining() throws -> Duration {
        let remaining = ContinuousClock.now.duration(to: deadline)
        guard remaining > .zero else { throw EngineError(.conflict, "original consumer preflight did not quiesce") }
        return remaining
    }
}

/// Bounds only the observation's wait, never the authoritative replacement.
/// The retained task may still be polling/adopting after expiry. Neither expiry
/// nor its eventual result proves worker death, drain, or permission to reopen.
/// An unstructured waiter is intentional: a task group would join the suspended
/// owner before returning the timeout and prevent mandatory cleanup.
@MainActor final class OriginalConsumerAdoptionWait<Value: Sendable> {
    enum Failure: Error { case deadline, alreadyWaited }
    let task: Task<Value, Error>
    private(set) var completion: Task<Void, Never>?
    private var started = false
    private var continuation: CheckedContinuation<Value, Error>?
    private var timer: Task<Void, Never>?
    private(set) var expired = false

    init(operation: @escaping @MainActor @Sendable () async throws -> Value) {
        task = Task { @MainActor in try await operation() }
    }

    func wait(deadline: UInt64,
        now: @escaping @MainActor @Sendable () -> UInt64 = { DispatchTime.now().uptimeNanoseconds },
        sleepUntil: @escaping @MainActor @Sendable (UInt64) async -> Void = { deadline in
            let now = DispatchTime.now().uptimeNanoseconds
            if deadline > now { try? await Task.sleep(nanoseconds: deadline - now) }
        }) async throws -> Value {
        guard !started else { throw Failure.alreadyWaited }
        started = true
        guard now() < deadline else { expired = true; throw Failure.deadline }
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            completion = Task { @MainActor in
                let result = await self.task.result
                // Recheck absolute time even if the timer has not been scheduled.
                self.finish(result, expired: now() >= deadline)
            }
            timer = Task { @MainActor in
                await sleepUntil(deadline)
                guard !Task.isCancelled else { return }
                self.finish(.failure(Failure.deadline), expired: true)
            }
        }
    }

    private func finish(_ result: Result<Value, Error>, expired: Bool) {
        guard let continuation else { return } // late outcomes cannot unfence
        self.continuation = nil
        self.expired = expired
        timer?.cancel(); timer = nil // never cancel the authoritative task
        continuation.resume(with: expired ? .failure(Failure.deadline) : result)
    }
}

/// Ordering seam used by production: release failure cannot escape containment.
/// Retains both errors; successful release is never positive observation evidence.
enum OriginalConsumerCleanup {
    static func run<Value>(operation: () async throws -> Value,
        release: () async throws -> Void, contain: () async throws -> Void,
        isolation: isolated (any Actor)? = #isolation) async throws -> Value {
        let result: Result<Value, Error>
        do { result = .success(try await operation()) } catch { result = .failure(error) }
        var failure: Error?
        if case .failure(let error) = result { failure = error }
        do { try await release() } catch {
            if let original = failure { failure = OriginalConsumerContainmentFailure(observation: original, containment: error) }
            else { failure = error }
        }
        do { try await contain() } catch {
            if let original = failure { throw OriginalConsumerContainmentFailure(observation: original, containment: error) }
            throw error
        }
        if let failure { throw failure }
        return try result.get()
    }
}
#endif

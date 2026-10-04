#if os(macOS)
import CEngineCore
import CryptoKit
import Darwin
import Foundation
import Virtualization

/// Synchronous admission plus an asynchronous, bounded join. All mutable state
/// is lock-protected so Raw's actor and the managed MainActor share this primitive.
/// A revoked lease remains inventoried until its operation actually unwinds;
/// timeout/cancellation is never converted into proof of quiescence.
final class RawServiceWorkTracker: @unchecked Sendable {
    struct Lease: Hashable, Sendable {
        fileprivate let generation: UUID
        fileprivate let id = UUID()
    }
    private let lock = NSLock()
    private var generation = UUID()
    private var closed = false
    private var leases = Set<Lease>()
    private var waiters: [UUID: CheckedContinuation<Void, Error>] = [:]

    func begin() throws -> Lease {
        try lock.withLock {
            guard !closed else { throw EngineError(.conflict, "raw service work is fenced") }
            let lease = Lease(generation: generation)
            leases.insert(lease)
            return lease
        }
    }
    /// Destructive work is never dropped because admission closed. Its producer
    /// is fenced separately; even an already-entered callback remains joinable.
    func retainDestructiveWork() -> Lease {
        lock.withLock {
            let lease = Lease(generation: generation)
            leases.insert(lease)
            return lease
        }
    }
    func requireQuiescent() throws {
        try lock.withLock {
            guard closed, leases.isEmpty else { throw EngineError(.conflict, "destructive work is not joined") }
        }
    }
    func end(_ lease: Lease) {
        let ready: [CheckedContinuation<Void, Error>] = lock.withLock {
            guard leases.remove(lease) != nil, leases.isEmpty else { return [] }
            let ready = Array(waiters.values); waiters.removeAll()
            return ready
        }
        for waiter in ready { waiter.resume() }
    }
    func close() { lock.withLock { closed = true } }
    func reopen() throws {
        try lock.withLock {
            guard closed, leases.isEmpty else { throw EngineError(.conflict, "raw service work has not quiesced") }
            generation = UUID(); closed = false
        }
    }
    func require(_ lease: Lease) throws {
        try lock.withLock {
            guard !closed, generation == lease.generation, leases.contains(lease) else {
                throw EngineError(.conflict, "raw service callback belongs to a revoked generation")
            }
        }
    }
    func join(timeout: Duration = .seconds(30)) async throws {
        let id = UUID()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let installed = lock.withLock {
                guard closed else {
                    continuation.resume(throwing: EngineError(.conflict, "raw service admission is not closed")); return false
                }
                guard !leases.isEmpty else { continuation.resume(); return false }
                waiters[id] = continuation; return true
            }
            if installed {
                Task {
                    try? await Task.sleep(for: timeout)
                    let waiter = self.lock.withLock { self.waiters.removeValue(forKey: id) }
                    waiter?.resume(throwing: EngineError(.conflict, "raw service work did not quiesce; maintenance remains fenced"))
                }
            }
        }
    }
}

/// The production launch rollback seam never rediscovers a client by container
/// ID. Even a late success or rollback-incomplete error can clean only its capture.
enum RawTrackedShimLaunch {
    static func run<Client: Sendable>(
        launch: () async throws -> Client,
        failedClient: (Error) -> Client?,
        validate: (Client) async throws -> Void,
        cleanup: (Client) async throws -> Void,
        retain: (Client) async -> Void,
        isolation: isolated (any Actor)? = #isolation
    ) async throws -> Client {
        var captured: Client?
        do {
            let client = try await launch(); captured = client
            try await validate(client)
            return client
        } catch {
            let launchError = error
            if let client = captured ?? failedClient(error) {
                do { try await cleanup(client) }
                catch {
                    await retain(client)
                    throw BackendResourceRollbackIncompleteError(
                        "VM shim launch failed: \(EngineError.message(for: launchError)); exact launch cleanup failed: \(EngineError.message(for: error))")
                }
            }
            throw launchError
        }
    }

    static func ownsCompletion<Client: AnyObject>(captured: Client, current: Client?,
        generation: RawBackendExecutionFence.Token?, completion: RawBackendExecutionFence.Token?) -> Bool {
        current === captured && generation != nil && generation == completion
    }
}

enum RawServiceContainment {
    struct JoinFailure: Error, LocalizedError {
        let join: Error
        let containment: Error
        var errorDescription: String? {
            "native launch join failed: \(join.localizedDescription); known-owner containment also failed: \(containment.localizedDescription)"
        }
    }
    struct KnownOwnersFailure: Error, LocalizedError {
        let failures: [Error]
        var errorDescription: String? { failures.map(\.localizedDescription).joined(separator: "; ") }
    }

    /// Best effort over an exact captured owner population; never a complete
    /// census or permission to discard unresolved/unpublished launch ownership.
    static func containKnown<Owner: Sendable>(owners: [Owner], terminate: (Owner) async throws -> Void,
        isolation: isolated (any Actor)? = #isolation) async throws {
        var failures: [Error] = []
        for owner in owners {
            do { try await terminate(owner) } catch { failures.append(error) }
        }
        if !failures.isEmpty { throw KnownOwnersFailure(failures: failures) }
    }

    static func run(native: RawServiceWorkTracker, work: RawServiceWorkTracker,
        nativeTimeout: Duration = .seconds(30), containKnown: (() async throws -> Void)? = nil,
        contain: () async throws -> Void, joinManaged: () async throws -> Void,
        census: () async throws -> Set<String>, isolation: isolated (any Actor)? = #isolation) async throws -> Set<String> {
        do { try await native.join(timeout: nativeTimeout) }
        catch {
            let joinError = error
            // A missing launch join is not permission to leave already-published
            // VMs running. Keep the launch lease and generation fence untouched.
            do {
                if let containKnown { try await containKnown() }
                else { try await contain() }
            } catch { throw JoinFailure(join: joinError, containment: error) }
            throw joinError // never report a complete contained census
        }
        do { try await contain() }
        catch {
            let censusError = error
            // A malformed/unknown filesystem entry may reject the full census
            // before it reaches any known VM. Failed observation cleanup must
            // still attempt all captured native owners, without calling it complete.
            if let containKnown {
                do { try await containKnown() }
                catch { throw KnownOwnersFailure(failures: [censusError, error]) }
            }
            throw censusError
        }
        try await work.join()
        try await joinManaged()
        return try await census()
    }
}

struct RawBackendExecutionFence: Sendable {
    struct Token: Equatable, Sendable {
        fileprivate let value = UUID()
    }

    private var tokens: [String: Token] = [:]

    mutating func replace(_ identifier: String) -> Token {
        let token = Token()
        tokens[identifier] = token
        return token
    }

    mutating func currentOrInstall(_ identifier: String) -> Token {
        if let token = tokens[identifier] { return token }
        return replace(identifier)
    }

    func current(_ identifier: String) -> Token? { tokens[identifier] }

    func owns(_ identifier: String, token: Token) -> Bool {
        tokens[identifier] == token
    }

    mutating func remove(_ identifier: String) {
        tokens.removeValue(forKey: identifier)
    }
}

struct RawCompletionPublication<Value: Sendable>: Sendable {
    let value: Value
    let synchronizeFabric: Bool
}

/// Bounded ownership index for immutable completed-exec output. Active output
/// is never evicted. Once an exec is terminal Docker exposes only its inspect
/// metadata; the one-shot start stream has already completed, so oldest
/// completed output may be dropped while its closed bridge and ExecRecord stay.
struct RawCompletedExecSnapshotBudget: Sendable {
    struct Entry: Sendable {
        let containerID: String
        let containerInstanceID: UUID
        let bytes: Int
        let sequence: UInt64
    }

    let perExecBytes: Int
    let perContainerBytes: Int
    let globalBytes: Int
    let minimumSnapshotBytes: Int
    private(set) var entries: [String: Entry] = [:]
    private var nextSequence: UInt64 = 0

    init(
        perExecBytes: Int,
        perContainerBytes: Int,
        globalBytes: Int,
        minimumSnapshotBytes: Int = 64 * 1_024
    ) {
        self.perExecBytes = max(0, perExecBytes)
        self.perContainerBytes = max(0, perContainerBytes)
        self.globalBytes = max(0, globalBytes)
        self.minimumSnapshotBytes = max(0, minimumSnapshotBytes)
    }

    mutating func register(
        execID: String,
        containerID: String,
        containerInstanceID: UUID,
        bytes: Int
    ) -> [String] {
        entries[execID] = Entry(
            containerID: containerID,
            containerInstanceID: containerInstanceID,
            // Charge a fixed structural floor so an unbounded stream of
            // zero-output execs cannot retain unbounded bridge objects while
            // consuming zero budget.
            bytes: min(max(minimumSnapshotBytes, bytes), perExecBytes),
            sequence: nextSequence
        )
        nextSequence &+= 1
        var evicted: [String] = []
        evictWhileOverBudget(
            limit: perContainerBytes,
            candidates: { entry in
                entry.containerID == containerID
                    && entry.containerInstanceID == containerInstanceID
            },
            evicted: &evicted
        )
        evictWhileOverBudget(
            limit: globalBytes, candidates: { _ in true }, evicted: &evicted
        )
        return evicted
    }

    mutating func remove(execID: String) {
        entries.removeValue(forKey: execID)
    }

    mutating func remove(containerID: String, instanceID: UUID) -> [String] {
        let identifiers = entries.compactMap { identifier, entry in
            entry.containerID == containerID && entry.containerInstanceID == instanceID
                ? identifier : nil
        }
        for identifier in identifiers { entries.removeValue(forKey: identifier) }
        return identifiers
    }

    var retainedBytes: Int { entries.values.reduce(0) { $0 + $1.bytes } }

    func retainedBytes(containerID: String, instanceID: UUID) -> Int {
        entries.values.reduce(0) { result, entry in
            result + (entry.containerID == containerID
                && entry.containerInstanceID == instanceID ? entry.bytes : 0)
        }
    }

    private mutating func evictWhileOverBudget(
        limit: Int,
        candidates: (Entry) -> Bool,
        evicted: inout [String]
    ) {
        while entries.values.reduce(0, { result, entry in
            result + (candidates(entry) ? entry.bytes : 0)
        }) > limit,
        let oldest = entries.filter({ candidates($0.value) })
            .min(by: { $0.value.sequence < $1.value.sequence })?.key {
            entries.removeValue(forKey: oldest)
            evicted.append(oldest)
        }
    }
}

/// The production ordering boundary for raw workload completion. Generation
/// validation and every generation-owned mutation supplied by `publish` happen
/// before the first possible suspension at `synchronizeFabric`.
enum RawCompletionPublisher {
    static func run<Value: Sendable>(
        isolation _: isolated (any Actor) = #isolation,
        fence: RawBackendExecutionFence,
        identifier: String,
        generation: RawBackendExecutionFence.Token,
        publish: () throws -> RawCompletionPublication<Value>,
        synchronizeFabric: () async -> Void
    ) async throws -> Value? {
        guard fence.owns(identifier, token: generation) else { return nil }
        let publication = try publish()
        if publication.synchronizeFabric { await synchronizeFabric() }
        return publication.value
    }
}

/// Passive completion may outlive its execution or original-consumer preflight.
/// Validate after publication's last suspension, then retain admitted destructive
/// work through stop: preflight must either reject this stop or join it before Arm.
/// Explicit stop/kill and containment keep their separate admission policies.
enum RawCompletionStop {
    static func run<Value: Sendable>(
        isolation _: isolated (any Actor) = #isolation,
        work: RawServiceWorkTracker,
        complete: () async throws -> Value,
        ownsExecution: () -> Bool,
        stop: () async throws -> Void
    ) async throws -> Value {
        let published = try await complete()
        guard ownsExecution(), let lease = try? work.begin() else { return published }
        defer { work.end(lease) }
        try? await stop()
        return published
    }
}

enum RawCompletionDrainCoordinator {
    static func drain(
        container: () throws -> Void,
        execSessions: () throws -> Void
    ) throws {
        try container()
        try execSessions()
    }
}

/// Runs an internal exec operation with an unconditional retirement boundary.
/// Healthchecks do not have a persistent `ExecRecord` in `EngineRuntime`, so
/// their backend resources must be retired by the operation that owns them.
enum RawHealthcheckExecLifecycle {
    static func run<Value: Sendable>(
        isolation _: isolated (any Actor)? = #isolation,
        prepare: () async throws -> Void,
        execute: () async throws -> Value,
        retire: () async -> Void
    ) async throws -> Value {
        do {
            try await prepare()
            let value = try await execute()
            await retire()
            return value
        } catch {
            await retire()
            throw error
        }
    }
}

/// Exact guest-side retirement state machine. Transport closures are required
/// to use the supplied lifecycle deadline; keeping policy separate from the VM
/// transport makes uncertain-start containment regression-testable.
enum RawGuestExecRetirement {
    struct Status: Sendable, Equatable {
        let status: String
        let exitCode: Int32?

        init(_ status: String, exitCode: Int32? = nil) {
            self.status = status
            self.exitCode = exitCode
        }
    }

    static func run(
        deadlineNanoseconds: UInt64,
        status: () async throws -> String,
        signal: () async throws -> Void,
        wait: () async throws -> String,
        discard: () async throws -> Void
    ) async throws {
        _ = try await runReportingExitCode(
            deadlineNanoseconds: deadlineNanoseconds,
            status: { Status(try await status()) },
            signal: signal,
            wait: { Status(try await wait()) },
            discard: discard
        )
    }

    /// Returns the terminal exit observed while containing the exec. A
    /// created or already-discarded exec has no process exit and returns nil.
    static func runReportingExitCode(
        deadlineNanoseconds: UInt64,
        status: () async throws -> Status,
        signal: () async throws -> Void,
        wait: () async throws -> Status,
        discard: () async throws -> Void
    ) async throws -> Int32? {
        var terminalExitCode: Int32?
        while true {
            guard DispatchTime.now().uptimeNanoseconds < deadlineNanoseconds else {
                throw AsyncTimeout.TimeoutError()
            }
            let current = try await status()
            switch current.status {
            case "", "created", "exited":
                if current.status == "exited" {
                    terminalExitCode = current.exitCode ?? terminalExitCode
                }
                try await discard()
                return terminalExitCode
            case "running":
                try await signal()
                let terminal = try await wait()
                guard terminal.status == "exited" else {
                    throw EngineError(.internalError, "guest exec did not exit")
                }
                terminalExitCode = terminal.exitCode
            case "starting":
                try await Task.sleep(for: .milliseconds(20))
            case let value:
                throw EngineError(.internalError, "guest returned invalid exec status \(value)")
            }
        }
    }
}

/// Reconciles durable exec journals only after canonical shim selection. A nil
/// containment decision means guest-process ownership is unresolved: the
/// exact journal is quarantined without attempting filesystem cleanup.
enum RawRecoveredExecCoordinator {
    struct Result: Sendable, Equatable {
        var failures: [String: String] = [:]
        var guestContainmentRequired: Set<String> = []
    }

    static func run(
        execIDs: [String],
        guestContainmentAvailable: Bool?,
        contain: (String) async throws -> Void,
        cleanup: (String) throws -> Void
    ) async -> Result {
        var result = Result()
        for execID in execIDs {
            guard let guestContainmentAvailable else {
                result.failures[execID] = "guest exec ownership is unresolved"
                result.guestContainmentRequired.insert(execID)
                continue
            }
            do {
                if guestContainmentAvailable {
                    do {
                        try await contain(execID)
                    } catch {
                        result.guestContainmentRequired.insert(execID)
                        throw error
                    }
                }
                try cleanup(execID)
            } catch {
                result.failures[execID] = EngineError.message(for: error)
                if guestContainmentAvailable {
                    // A retry may conservatively repeat idempotent status and
                    // discard even when containment completed before local
                    // artifact cleanup failed.
                    result.guestContainmentRequired.insert(execID)
                }
            }
        }
        return result
    }
}

enum RawPreparedShimStateLookup {
    static func existingContainerDirectory(
        in containersDirectory: PersistentStateDirectory,
        containerID: String
    ) throws -> PersistentStateDirectory? {
        try containersDirectory.openDirectoryIfPresent(named: containerID)
    }
}

enum RawContainerInstanceCoordinator {
    static func requireNoConflictingFreshPreparation(
        of container: ContainerRecord,
        in freshPreparationInstances: [String: UUID]
    ) throws {
        guard let preparingInstance = freshPreparationInstances[container.id],
              preparingInstance != container.instanceID else { return }
        throw BackendResourceRollbackIncompleteError(
            "container \(container.id) has a different VM preparation in progress"
        )
    }
}

/// Single policy boundary for every operation that observes or mutates a
/// container execution. A selected canonical shim is insufficient while a
/// sibling generation still has unresolved ownership evidence.
enum RawExactContainerOwnershipGuard {
    static func require(
        _ container: ContainerRecord,
        knownInstanceID: UUID?,
        quarantinedGenerationCount: Int,
        cleanupPendingGenerationCount: Int
    ) throws {
        if let knownInstanceID, knownInstanceID != container.instanceID {
            throw BackendResourceRollbackIncompleteError(
                "container \(container.id) backend state belongs to a different instance"
            )
        }
        guard quarantinedGenerationCount == 0,
              cleanupPendingGenerationCount == 0 else {
            throw BackendResourceRollbackIncompleteError(
                "container \(container.id) has unresolved VM shim generation ownership"
            )
        }
    }
}

/// A network-record refresh carries metadata for every container, but only
/// running or paused records can cause guest execution mutations. Residual
/// generation evidence on an inactive record must continue to fence that
/// container's lifecycle without poisoning refreshes for unrelated containers.
enum RawNetworkRefreshOwnershipGuard {
    static func require(
        _ container: ContainerRecord,
        knownInstanceID: UUID?,
        quarantinedGenerationCount: Int,
        cleanupPendingGenerationCount: Int
    ) throws {
        let hasActiveExecution = container.phase == .running || container.phase == .paused
        try RawExactContainerOwnershipGuard.require(
            container,
            knownInstanceID: knownInstanceID,
            quarantinedGenerationCount:
                hasActiveExecution ? quarantinedGenerationCount : 0,
            cleanupPendingGenerationCount:
                hasActiveExecution ? cleanupPendingGenerationCount : 0
        )
    }

    static func require(
        _ containers: [ContainerRecord],
        knownContainers: [String: ContainerRecord],
        quarantinedGenerationCounts: [String: Int],
        cleanupPendingGenerationCounts: [String: Int]
    ) throws {
        for container in containers {
            try require(
                container,
                knownInstanceID: knownContainers[container.id]?.instanceID,
                quarantinedGenerationCount: quarantinedGenerationCounts[container.id] ?? 0,
                cleanupPendingGenerationCount: cleanupPendingGenerationCounts[container.id] ?? 0
            )
        }
    }
}

enum RawActiveContainerExecutionGuard {
    static func require(
        _ container: ContainerRecord,
        activeInstanceID: UUID?,
        hasCompletion: Bool
    ) throws {
        guard !hasCompletion,
              activeInstanceID == container.instanceID else {
            throw EngineError(
                .conflict, "Container \(container.id) is not running"
            )
        }
    }
}

struct RawExecCleanupKey: Hashable, Sendable {
    let containerID: String
    let containerInstanceID: UUID
    let execID: String
    let containerDirectoryIdentity: PersistentFileIdentity

    init(
        exec: ExecRecord,
        containerDirectoryIdentity: PersistentFileIdentity
    ) {
        containerID = exec.containerID
        containerInstanceID = exec.containerInstanceID
        execID = exec.id
        self.containerDirectoryIdentity = containerDirectoryIdentity
    }

    func owns(
        container: ContainerRecord,
        directoryIdentity: PersistentFileIdentity
    ) -> Bool {
        containerID == container.id
            && containerInstanceID == container.instanceID
            && containerDirectoryIdentity == directoryIdentity
    }
}

struct RawDeletedContainerReceipt: Codable, Equatable, Sendable {
    static let currentSchemaVersion = 1

    let schemaVersion: Int
    let containerID: String
    let instanceID: UUID
    let directoryIdentity: PersistentFileIdentity

    init(container: ContainerRecord, directoryIdentity: PersistentFileIdentity) {
        schemaVersion = Self.currentSchemaVersion
        containerID = container.id
        instanceID = container.instanceID
        self.directoryIdentity = directoryIdentity
    }
}

/// A preparation attempt lives outside the disposable container directory so
/// cleanup can still attribute an exact instance after preparation rolled its
/// state directory back or failed before creating one.
struct RawContainerPreparationAttempt: Codable, Equatable, Sendable {
    static let currentSchemaVersion = 1

    var schemaVersion: Int
    let containerID: String
    let instanceID: UUID
    let directoryIdentity: PersistentFileIdentity?
    let cleanupContained: Bool

    init(
        container: ContainerRecord,
        directoryIdentity: PersistentFileIdentity? = nil,
        cleanupContained: Bool = false
    ) {
        schemaVersion = Self.currentSchemaVersion
        containerID = container.id
        instanceID = container.instanceID
        self.directoryIdentity = directoryIdentity
        self.cleanupContained = cleanupContained
    }
}

/// Durable proof that this exact logical container entered raw preparation.
/// An unbound attempt proves an absent state directory is safe to treat as
/// cleaned; once bound, it also authorizes disposal of that exact partial
/// directory when preparation did not reach `PreparedShimState` publication.
enum RawContainerPreparationAttemptCoordinator {
    static func begin(
        _ container: ContainerRecord,
        in containers: PersistentStateDirectory,
        attempts: PersistentStateDirectory
    ) throws {
        let hasState = try containers.pendingDisposalIdentity(named: container.id) != nil
            || containers.openDirectoryIfPresent(named: container.id) != nil
        if let existing = try load(containerID: container.id, from: attempts), hasState {
            guard existing.instanceID == container.instanceID else {
                throw EngineError(.conflict, "container preparation attempt belongs to another instance")
            }
            return
        }
        try save(RawContainerPreparationAttempt(container: container), in: attempts)
    }

    static func bind(
        _ container: ContainerRecord,
        directoryIdentity: PersistentFileIdentity,
        in attempts: PersistentStateDirectory
    ) throws {
        guard let existing = try load(containerID: container.id, from: attempts),
              existing.instanceID == container.instanceID else {
            throw EngineError(.conflict, "container preparation attempt is unavailable")
        }
        if existing.directoryIdentity == directoryIdentity,
           !existing.cleanupContained { return }
        try save(
            RawContainerPreparationAttempt(
                container: container, directoryIdentity: directoryIdentity
            ),
            in: attempts
        )
    }

    static func recordContainedCleanup(
        _ container: ContainerRecord,
        directoryIdentity: PersistentFileIdentity,
        in attempts: PersistentStateDirectory
    ) throws {
        guard let existing = try load(containerID: container.id, from: attempts),
              existing.instanceID == container.instanceID,
              existing.directoryIdentity == directoryIdentity else {
            throw EngineError(.conflict, "contained cleanup does not match its preparation attempt")
        }
        try save(
            RawContainerPreparationAttempt(
                container: container,
                directoryIdentity: directoryIdentity,
                cleanupContained: true
            ),
            in: attempts
        )
    }

    static func requireUnboundPartialState(
        _ container: ContainerRecord,
        stateDirectory: PersistentStateDirectory,
        in attempts: PersistentStateDirectory
    ) throws {
        guard try stateDirectory.entryNames().isEmpty else {
            throw EngineError(.conflict, "unbound container preparation state is not empty")
        }
        guard let attempt = try load(containerID: container.id, from: attempts),
              attempt.instanceID == container.instanceID,
              attempt.directoryIdentity == nil else {
            throw EngineError(.conflict, "container cleanup is not an unbound preparation attempt")
        }
    }

    static func requireCleanAbsence(
        _ container: ContainerRecord,
        in containers: PersistentStateDirectory,
        attempts: PersistentStateDirectory
    ) throws {
        guard try containers.pendingDisposalIdentity(named: container.id) == nil,
              try containers.openDirectoryIfPresent(named: container.id) == nil else {
            throw EngineError(.conflict, "container preparation state disposal remains incomplete")
        }
        try require(container, in: attempts)
        guard try containers.pendingDisposalIdentity(named: container.id) == nil,
              try containers.openDirectoryIfPresent(named: container.id) == nil else {
            throw EngineError(.conflict, "container preparation state changed while confirming cleanup")
        }
    }

    static func require(
        _ container: ContainerRecord,
        directoryIdentity: PersistentFileIdentity? = nil,
        in attempts: PersistentStateDirectory
    ) throws {
        guard let attempt = try load(containerID: container.id, from: attempts),
              attempt.instanceID == container.instanceID else {
            throw EngineError(.conflict, "container cleanup cannot be attributed to a preparation attempt")
        }
        if let directoryIdentity {
            guard attempt.directoryIdentity == directoryIdentity else {
                throw EngineError(.conflict, "partial container state does not match its preparation attempt")
            }
        } else {
            guard attempt.directoryIdentity == nil || attempt.cleanupContained else {
                throw EngineError(.conflict, "bound container preparation cleanup is not contained")
            }
        }
    }

    static func remove(containerID: String, from attempts: PersistentStateDirectory) throws {
        try attempts.removeRegularFileIfPresent(named: attemptName(containerID))
    }

    private static func save(
        _ attempt: RawContainerPreparationAttempt,
        in attempts: PersistentStateDirectory
    ) throws {
        try attempts.replaceRegularFile(
            named: attemptName(attempt.containerID),
            data: try JSONEncoder().encode(attempt)
        )
    }

    private static func load(
        containerID: String,
        from attempts: PersistentStateDirectory
    ) throws -> RawContainerPreparationAttempt? {
        guard let data = try attempts.readRegularFile(
            named: attemptName(containerID), required: false
        ) else { return nil }
        let attempt = try JSONDecoder().decode(RawContainerPreparationAttempt.self, from: data)
        guard attempt.schemaVersion == RawContainerPreparationAttempt.currentSchemaVersion,
              attempt.containerID == containerID else {
            throw EngineError(.conflict, "invalid container preparation attempt")
        }
        return attempt
    }

    private static func attemptName(_ containerID: String) -> String {
        "\(containerID).preparation"
    }
}

/// A deletion receipt lives outside the disposable container directory. It is
/// written before disposal, allowing a removal retry (including after daemon
/// restart) to distinguish the exact instance that was already deleted from a
/// missing, substituted, or newly-created incarnation with the same public ID.
enum RawDeletedContainerCoordinator {
    static func record(
        _ container: ContainerRecord,
        directoryIdentity: PersistentFileIdentity,
        in receipts: PersistentStateDirectory
    ) throws {
        if let existing = try load(containerID: container.id, from: receipts) {
            guard existing.instanceID == container.instanceID,
                  existing.directoryIdentity == directoryIdentity else {
                throw EngineError(.conflict, "container deletion receipt belongs to another instance")
            }
            return
        }
        let receipt = RawDeletedContainerReceipt(
            container: container, directoryIdentity: directoryIdentity
        )
        try receipts.replaceRegularFile(
            named: receiptName(container.id), data: try JSONEncoder().encode(receipt)
        )
    }

    static func hasReceipt(
        containerID: String,
        in receipts: PersistentStateDirectory
    ) throws -> Bool {
        try load(containerID: containerID, from: receipts) != nil
    }

    static func requireCompletedDeletion(
        of container: ContainerRecord,
        in containers: PersistentStateDirectory,
        receipts: PersistentStateDirectory
    ) throws {
        guard try containers.pendingDisposalIdentity(named: container.id) == nil,
              try containers.openDirectoryIfPresent(named: container.id) == nil else {
            throw EngineError(.conflict, "container state disposal remains incomplete")
        }
        guard let receipt = try load(containerID: container.id, from: receipts),
              receipt.instanceID == container.instanceID else {
            throw EngineError(.conflict, "container deletion cannot be attributed to this instance")
        }
        guard try containers.pendingDisposalIdentity(named: container.id) == nil,
              try containers.openDirectoryIfPresent(named: container.id) == nil else {
            throw EngineError(.conflict, "container state changed while confirming deletion")
        }
    }

    static func requireRecordedDeletion(
        of container: ContainerRecord,
        directoryIdentity: PersistentFileIdentity,
        in receipts: PersistentStateDirectory
    ) throws {
        guard let receipt = try load(containerID: container.id, from: receipts),
              receipt.instanceID == container.instanceID,
              receipt.directoryIdentity == directoryIdentity else {
            throw EngineError(.conflict, "container deletion cannot be attributed to this state")
        }
    }

    static func clearForPreparation(
        of container: ContainerRecord,
        in containers: PersistentStateDirectory,
        receipts: PersistentStateDirectory
    ) throws {
        guard let receipt = try load(containerID: container.id, from: receipts) else { return }
        guard try containers.pendingDisposalIdentity(named: container.id) == nil,
              try containers.openDirectoryIfPresent(named: container.id) == nil else {
            throw EngineError(.conflict, "container deletion is incomplete")
        }
        // A new preparation (or restart of the same logical record) is the
        // publication boundary that consumes an older completed-deletion proof.
        _ = receipt
        try receipts.removeRegularFileIfPresent(named: receiptName(container.id))
    }

    static func removeReceipt(
        containerID: String, from receipts: PersistentStateDirectory
    ) throws {
        try receipts.removeRegularFileIfPresent(named: receiptName(containerID))
    }

    private static func load(
        containerID: String, from receipts: PersistentStateDirectory
    ) throws -> RawDeletedContainerReceipt? {
        guard let data = try receipts.readRegularFile(
            named: receiptName(containerID), required: false
        ) else { return nil }
        let receipt: RawDeletedContainerReceipt
        do {
            receipt = try JSONDecoder().decode(RawDeletedContainerReceipt.self, from: data)
        } catch {
            throw EngineError(.conflict, "invalid container deletion receipt")
        }
        guard receipt.schemaVersion == RawDeletedContainerReceipt.currentSchemaVersion,
              receipt.containerID == containerID else {
            throw EngineError(.conflict, "container deletion receipt identity mismatch")
        }
        return receipt
    }

    private static func receiptName(_ containerID: String) -> String {
        "\(containerID).json"
    }
}

struct RawFreshContainerDirectoryAcquisition {
    let directory: PersistentStateDirectory
    let wasCreated: Bool
}

/// The durable state acquisition boundary for a fresh writable root. A name
/// that already exists is never reported as newly created, even when it has no
/// prepared marker; callers must first prove that no shim generation owns it.
enum RawFreshContainerStateCoordinator {
    static func acquire(
        in containersDirectory: PersistentStateDirectory,
        containerID: String
    ) throws -> RawFreshContainerDirectoryAcquisition {
        try containersDirectory.reconcileDisposals()
        if let existing = try containersDirectory.openDirectoryIfPresent(
            named: containerID
        ) {
            return .init(directory: existing, wasCreated: false)
        }
        do {
            return .init(
                directory: try containersDirectory.createDirectory(named: containerID),
                wasCreated: true
            )
        } catch let error as POSIXError where error.code == .EEXIST {
            guard let existing = try containersDirectory.openDirectoryIfPresent(
                named: containerID
            ) else { throw error }
            return .init(directory: existing, wasCreated: false)
        }
    }

    static func recreateUnclaimed(
        in containersDirectory: PersistentStateDirectory,
        containerID: String,
        existing: PersistentStateDirectory,
        hook: PersistentDisposalHook? = nil
    ) throws -> PersistentStateDirectory {
        guard existing.pathStillNamesThisDirectory(),
              try containersDirectory.openDirectory(named: containerID).identity
                == existing.identity else {
            throw EngineError(
                .conflict,
                "container \(containerID) state changed before fresh preparation"
            )
        }
        try RawDiskJournalDirectory.requireSafeAutomaticRootDisposal(existing)
        try containersDirectory.disposeDirectory(
            named: containerID,
            expectedIdentity: existing.identity,
            hook: hook
        )
        guard try containersDirectory.openDirectoryIfPresent(named: containerID) == nil else {
            throw EngineError(
                .conflict,
                "container \(containerID) state reappeared during fresh preparation"
            )
        }
        let replacement = try containersDirectory.createDirectory(named: containerID)
        guard replacement.pathStillNamesThisDirectory(),
              try containersDirectory.openDirectory(named: containerID).identity
                == replacement.identity else {
            throw EngineError(
                .conflict,
                "container \(containerID) replacement state changed during creation"
            )
        }
        return replacement
    }
}

/// Descriptor-created files that are passed directly to Virtualization.framework
/// or shared with the guest. Identities are retained until the launch boundary
/// so a stale file, symlink, or intervening name replacement is rejected.
struct RawContainerPreparationArtifacts: Codable, Equatable, Sendable {
    static let directIOFileNames = ["stdout", "stderr", "stdin", "stdin.closed"]

    let directoryIdentity: PersistentFileIdentity
    let rootDiskIdentity: PersistentFileIdentity
    let rootDiskSize: UInt64
    let shimLogIdentity: PersistentFileIdentity
    let execArtifactJournalIdentity: PersistentFileIdentity
    let execArtifactCompactionIdentity: PersistentFileIdentity
    let ioDirectoryIdentity: PersistentFileIdentity
    let ioFileIdentities: [String: PersistentFileIdentity]
    let outputSpoolDirectoryIdentities: [String: PersistentFileIdentity]?
    let dockerLogIdentity: PersistentFileIdentity
    let dockerLogIndexIdentity: PersistentFileIdentity
    let dockerLogJournalDirectoryIdentity: PersistentFileIdentity?

    static func create(
        in directory: PersistentStateDirectory,
        rootDiskSize: UInt64
    ) throws -> RawContainerPreparationArtifacts {
        try RawDiskJournalDirectory.prepare(directory)
        guard case .created(let created) = try RawDiskInitialization.createNewDisk(
            in: directory, named: "root.ext4", size: rootDiskSize
        ) else { throw POSIXError(.EEXIST) }
        let rootDiskIdentity = try directory.regularFileIdentity(
            named: "root.ext4", expectedSize: rootDiskSize
        )
        guard rootDiskIdentity.inode == created.record.diskIdentity.inode,
              rootDiskIdentity.volumeUUID?.uuidString.lowercased() == created.record.diskIdentity.volumeUUID else {
            throw RawDiskInitialization.Failure.unsafePath
        }
        let shimLogIdentity = try directory.createSparseRegularFile(
            named: "shim.log", size: 0
        )
        let execArtifactJournalIdentity = try directory.createSparseRegularFile(
            named: "exec-artifacts.jsonl", size: 0
        )
        let execArtifactCompactionIdentity = try directory.createSparseRegularFile(
            named: "exec-artifacts.compact", size: 0
        )
        let ioDirectory = try directory.createDirectory(named: "io")
        var ioFileIdentities: [String: PersistentFileIdentity] = [:]
        for name in directIOFileNames {
            ioFileIdentities[name] = try ioDirectory.createSparseRegularFile(
                named: name, size: 0
            )
        }
        var outputSpoolDirectoryIdentities: [String: PersistentFileIdentity] = [:]
        for name in ["stdout.spool", "stderr.spool"] {
            outputSpoolDirectoryIdentities[name] = try ioDirectory.createDirectory(
                named: name
            ).identity
        }
        let dockerLogIdentity = try ioDirectory.createSparseRegularFile(
            named: "docker.log", size: 0
        )
        let dockerLogIndexIdentity = try ioDirectory.createSparseRegularFile(
            named: "docker.log.entries", size: 0
        )
        let dockerLogJournalDirectoryIdentity = try ioDirectory.createDirectory(
            named: "docker.log.journal"
        ).identity
        let artifacts = RawContainerPreparationArtifacts(
            directoryIdentity: directory.identity,
            rootDiskIdentity: rootDiskIdentity,
            rootDiskSize: rootDiskSize,
            shimLogIdentity: shimLogIdentity,
            execArtifactJournalIdentity: execArtifactJournalIdentity,
            execArtifactCompactionIdentity: execArtifactCompactionIdentity,
            ioDirectoryIdentity: ioDirectory.identity,
            ioFileIdentities: ioFileIdentities,
            outputSpoolDirectoryIdentities: outputSpoolDirectoryIdentities,
            dockerLogIdentity: dockerLogIdentity,
            dockerLogIndexIdentity: dockerLogIndexIdentity,
            dockerLogJournalDirectoryIdentity: dockerLogJournalDirectoryIdentity
        )
        try artifacts.validate(in: directory)
        return artifacts
    }

    static func validateExisting(in directory: PersistentStateDirectory) throws {
        _ = try directory.regularFileIdentity(named: "root.ext4")
        _ = try directory.regularFileIdentity(named: "shim.log")
        _ = try directory.regularFileIdentity(named: "exec-artifacts.jsonl")
        _ = try directory.regularFileIdentity(named: "exec-artifacts.compact")
        let ioDirectory = try directory.openDirectory(named: "io")
        guard let ioMetadata = try directory.entryMetadata(named: "io"),
              ioMetadata.identity == ioDirectory.identity,
              ioMetadata.type == S_IFDIR,
              ioDirectory.pathStillNamesThisDirectory() else {
            throw EngineError(.conflict, "container direct-I/O directory changed")
        }
        for name in directIOFileNames {
            _ = try ioDirectory.regularFileIdentity(named: name)
        }
        for name in ["stdout.spool", "stderr.spool"] {
            if let spool = try ioDirectory.openDirectoryIfPresent(named: name) {
                guard spool.pathStillNamesThisDirectory() else {
                    throw EngineError(.conflict, "container output spool directory changed")
                }
            }
        }
        _ = try ioDirectory.regularFileIdentity(named: "docker.log")
        _ = try ioDirectory.regularFileIdentity(named: "docker.log.entries")
        if let journal = try ioDirectory.openDirectoryIfPresent(
            named: "docker.log.journal"
        ) {
            guard journal.pathStillNamesThisDirectory() else {
                throw EngineError(.conflict, "container log journal directory changed")
            }
        }
        guard directory.pathStillNamesThisDirectory() else {
            throw EngineError(.conflict, "container state directory changed")
        }
    }

    func refreshed(
        in directory: PersistentStateDirectory
    ) throws -> RawContainerPreparationArtifacts {
        let rootDisk = try directory.regularFileIdentity(
            named: "root.ext4", expectedSize: rootDiskSize
        )
        let shimLog = try directory.regularFileIdentity(named: "shim.log")
        let execJournal = try directory.regularFileIdentity(
            named: "exec-artifacts.jsonl"
        )
        let execCompaction = try directory.regularFileIdentity(
            named: "exec-artifacts.compact"
        )
        let ioDirectory = try directory.openDirectory(named: "io")
        var ioFiles: [String: PersistentFileIdentity] = [:]
        for name in Self.directIOFileNames {
            ioFiles[name] = try ioDirectory.regularFileIdentity(named: name)
        }
        var spoolDirectories: [String: PersistentFileIdentity]?
        if outputSpoolDirectoryIdentities != nil {
            spoolDirectories = [:]
            for name in ["stdout.spool", "stderr.spool"] {
                spoolDirectories?[name] = try ioDirectory.openDirectory(named: name).identity
            }
        }
        let dockerLog = try ioDirectory.regularFileIdentity(named: "docker.log")
        let dockerLogIndex = try ioDirectory.regularFileIdentity(
            named: "docker.log.entries"
        )
        let dockerLogJournal: PersistentFileIdentity?
        if dockerLogJournalDirectoryIdentity != nil {
            dockerLogJournal = try ioDirectory.openDirectory(
                named: "docker.log.journal"
            ).identity
        } else {
            dockerLogJournal = nil
        }

        var expected = [
            directoryIdentity, rootDiskIdentity, shimLogIdentity,
            execArtifactJournalIdentity, execArtifactCompactionIdentity,
            ioDirectoryIdentity, dockerLogIdentity, dockerLogIndexIdentity,
        ]
        var observed = [
            directory.identity, rootDisk, shimLog, execJournal, execCompaction,
            ioDirectory.identity, dockerLog, dockerLogIndex,
        ]
        for name in Self.directIOFileNames {
            guard let old = ioFileIdentities[name], let current = ioFiles[name] else {
                throw EngineError(.internalError, "missing direct-I/O file identity")
            }
            expected.append(old)
            observed.append(current)
        }
        if let oldSpools = outputSpoolDirectoryIdentities,
           let currentSpools = spoolDirectories {
            for name in ["stdout.spool", "stderr.spool"] {
                guard let old = oldSpools[name], let current = currentSpools[name] else {
                    throw EngineError(.internalError, "missing output spool identity")
                }
                expected.append(old)
                observed.append(current)
            }
        }
        if let old = dockerLogJournalDirectoryIdentity,
           let current = dockerLogJournal {
            expected.append(old)
            observed.append(current)
        }
        guard PersistentFileIdentity.recoveryMatches(
            expected: expected, observed: observed
        ) else {
            throw EngineError(.conflict, "container preparation artifact identity changed")
        }

        let result = RawContainerPreparationArtifacts(
            directoryIdentity: directory.identity,
            rootDiskIdentity: rootDisk,
            rootDiskSize: rootDiskSize,
            shimLogIdentity: shimLog,
            execArtifactJournalIdentity: execJournal,
            execArtifactCompactionIdentity: execCompaction,
            ioDirectoryIdentity: ioDirectory.identity,
            ioFileIdentities: ioFiles,
            outputSpoolDirectoryIdentities: spoolDirectories,
            dockerLogIdentity: dockerLog,
            dockerLogIndexIdentity: dockerLogIndex,
            dockerLogJournalDirectoryIdentity: dockerLogJournal
        )
        try result.validate(in: directory)
        return result
    }

    func validate(in directory: PersistentStateDirectory) throws {
        guard directory.identity == directoryIdentity else {
            throw EngineError(.conflict, "container state directory identity changed")
        }
        _ = try directory.regularFileIdentity(
            named: "root.ext4",
            expectedIdentity: rootDiskIdentity,
            expectedSize: rootDiskSize
        )
        _ = try directory.regularFileIdentity(
            named: "shim.log", expectedIdentity: shimLogIdentity
        )
        _ = try directory.regularFileIdentity(
            named: "exec-artifacts.jsonl",
            expectedIdentity: execArtifactJournalIdentity
        )
        _ = try directory.regularFileIdentity(
            named: "exec-artifacts.compact",
            expectedIdentity: execArtifactCompactionIdentity
        )
        let ioDirectory = try directory.openDirectory(named: "io")
        guard ioDirectory.identity == ioDirectoryIdentity,
              let ioMetadata = try directory.entryMetadata(named: "io"),
              ioMetadata.identity == ioDirectoryIdentity,
              ioMetadata.type == S_IFDIR,
              ioDirectory.pathStillNamesThisDirectory() else {
            throw EngineError(.conflict, "container direct-I/O directory changed")
        }
        for name in Self.directIOFileNames {
            guard let expectedIdentity = ioFileIdentities[name] else {
                throw EngineError(.internalError, "missing direct-I/O file identity")
            }
            _ = try ioDirectory.regularFileIdentity(
                named: name,
                expectedIdentity: expectedIdentity
            )
        }
        if let spoolIdentities = outputSpoolDirectoryIdentities {
            for name in ["stdout.spool", "stderr.spool"] {
                guard let expected = spoolIdentities[name] else {
                    throw EngineError(.internalError, "missing output spool identity")
                }
                let spool = try ioDirectory.openDirectory(named: name)
                guard spool.identity == expected,
                      spool.pathStillNamesThisDirectory() else {
                    throw EngineError(.conflict, "container output spool directory changed")
                }
            }
        }
        _ = try ioDirectory.regularFileIdentity(
            named: "docker.log", expectedIdentity: dockerLogIdentity
        )
        _ = try ioDirectory.regularFileIdentity(
            named: "docker.log.entries", expectedIdentity: dockerLogIndexIdentity
        )
        if let expected = dockerLogJournalDirectoryIdentity {
            let journal = try ioDirectory.openDirectory(named: "docker.log.journal")
            guard journal.identity == expected,
                  journal.pathStillNamesThisDirectory() else {
                throw EngineError(.conflict, "container log journal directory changed")
            }
        }
        guard directory.pathStillNamesThisDirectory() else {
            throw EngineError(.conflict, "container state directory changed")
        }
    }
}

struct RawExecArtifactRecord: Codable, Equatable, Sendable {
    enum Phase: String, Codable, Sendable {
        case preparing
        case creating
        case staged
        case published
    }

    static let currentSchemaVersion = 2

    let schemaVersion: Int
    let containerID: String
    let execID: String
    let stagingDirectoryName: String
    var stagingDirectoryIdentity: PersistentFileIdentity?
    var phase: Phase
    var fileIdentities: [String: PersistentFileIdentity]

    init(
        containerID: String,
        execID: String,
        stagingDirectoryName: String,
        stagingDirectoryIdentity: PersistentFileIdentity? = nil,
        phase: Phase,
        fileIdentities: [String: PersistentFileIdentity] = [:]
    ) {
        schemaVersion = Self.currentSchemaVersion
        self.containerID = containerID
        self.execID = execID
        self.stagingDirectoryName = stagingDirectoryName
        self.stagingDirectoryIdentity = stagingDirectoryIdentity
        self.phase = phase
        self.fileIdentities = fileIdentities
    }

    /// Builds an already-published record for focused cleanup tests and
    /// recovery callers that have captured all canonical inode identities.
    init(
        containerID: String,
        execID: String,
        fileIdentities: [String: PersistentFileIdentity]
    ) {
        self.init(
            containerID: containerID,
            execID: execID,
            stagingDirectoryName: "",
            phase: .published,
            fileIdentities: fileIdentities
        )
    }

    static func expectedNames(execID: String) -> [String] {
        let prefix = "exec-\(execID)"
        return [
            "\(prefix)-stdout", "\(prefix)-stderr", "\(prefix)-stdin",
            "\(prefix)-stdin.closed", "\(prefix)-docker.log",
            "\(prefix)-docker.log.entries",
        ]
    }

    func validate() throws {
        let expectedNames = Set(Self.expectedNames(execID: execID))
        guard schemaVersion == Self.currentSchemaVersion,
              !containerID.isEmpty,
              !execID.isEmpty,
              containerID.utf8.count <= 128,
              execID.utf8.count <= 128 else {
            throw EngineError(.conflict, "invalid exec artifact identity record")
        }
        switch phase {
        case .preparing:
            guard stagingDirectoryName.hasPrefix(".cengine-exec-stage-"),
                  stagingDirectoryIdentity == nil,
                  fileIdentities.isEmpty else {
                throw EngineError(.conflict, "invalid preparing exec artifact record")
            }
        case .creating:
            guard stagingDirectoryName.hasPrefix(".cengine-exec-stage-"),
                  stagingDirectoryIdentity != nil,
                  fileIdentities.isEmpty else {
                throw EngineError(.conflict, "invalid creating exec artifact record")
            }
        case .staged:
            guard stagingDirectoryName.hasPrefix(".cengine-exec-stage-"),
                  stagingDirectoryIdentity != nil,
                  Set(fileIdentities.keys) == expectedNames,
                  Set(fileIdentities.values).count == expectedNames.count else {
                throw EngineError(.conflict, "invalid staged exec artifact record")
            }
        case .published:
            guard Set(fileIdentities.keys) == expectedNames,
                  Set(fileIdentities.values).count == expectedNames.count,
                  (stagingDirectoryName.isEmpty && stagingDirectoryIdentity == nil)
                    || (stagingDirectoryName.hasPrefix(".cengine-exec-stage-")
                        && stagingDirectoryIdentity != nil) else {
                throw EngineError(.conflict, "invalid published exec artifact record")
            }
        }
        guard !stagingDirectoryName.contains("/"),
              !stagingDirectoryName.contains("\0") else {
            throw EngineError(.conflict, "invalid exec artifact identity record")
        }
    }
}

private final class RawExecArtifactLockRegistry: @unchecked Sendable {
    struct Key: Hashable {
        let directory: PersistentFileIdentity
        let journal: PersistentFileIdentity
    }

    private final class WeakLock {
        weak var value: NSRecursiveLock?

        init(_ value: NSRecursiveLock) { self.value = value }
    }

    static let shared = RawExecArtifactLockRegistry()

    private let registryLock = NSLock()
    private var locks: [Key: WeakLock] = [:]

    func withLock<Value>(
        directoryIdentity: PersistentFileIdentity,
        journalIdentity: PersistentFileIdentity,
        _ operation: () throws -> Value
    ) rethrows -> Value {
        let key = Key(directory: directoryIdentity, journal: journalIdentity)
        let transactionLock = registryLock.withLock { () -> NSRecursiveLock in
            if let existing = locks[key]?.value { return existing }
            locks = locks.filter { $0.value.value != nil }
            let created = NSRecursiveLock()
            locks[key] = WeakLock(created)
            return created
        }
        return try transactionLock.withLock(operation)
    }
}

enum RawExecArtifactBoundary: Equatable, Sendable {
    case intentionSynchronized
    case stagingDirectoryCreated
    case stagingDirectorySynchronized
    case artifactStaged(String)
    case stagedOwnershipSynchronized
    case artifactExposed(String)
    case ioDirectorySynchronized
    case publicationSynchronized
}

enum RawExecJournalCompactionBoundary: Equatable, Sendable {
    case recoverySynchronized
    case journalTruncated
    case journalWritten
    case journalSynchronized
    case recoveryCleared
}

enum RawExecJournalMutationBoundary: Equatable, Sendable {
    case snapshotLoaded
    case frameWillWrite
}

typealias RawExecArtifactHook = (RawExecArtifactBoundary) throws -> Void
typealias RawExecJournalCompactionHook = (RawExecJournalCompactionBoundary) throws -> Void
typealias RawExecJournalMutationHook = (RawExecJournalMutationBoundary) throws -> Void

/// The journal inode is part of the prepared container artifacts. Exec files
/// are therefore recoverably attributable after a daemon restart without
/// trusting their mutable directory names at cleanup time.
enum RawExecArtifactJournal {
    private static let frameMagic = Data([0x43, 0x45, 0x45, 0x4a]) // CEEJ
    private static let frameHeaderSize = 20
    static let maximumFramePayloadSize = 64 * 1_024
    static let maximumJournalSize = 512 * 1_024
    static let maximumFrameCount = 320
    static let maximumActiveRecordCount = 64
    static let maximumAbandonedRecordCount = 16
    private static let compactionFrameThreshold = 48

    private enum Action: String, Codable, Sendable {
        case prepared
        case removed
        case abandoned
    }
    private struct Event: Codable, Sendable {
        let action: Action
        let record: RawExecArtifactRecord
    }

    private struct DecodedJournal {
        let events: [Event]
        let completeByteCount: Int
    }

    private struct ReplayState {
        var active: [String: RawExecArtifactRecord] = [:]
        var abandoned: [RawExecArtifactRecord] = []
    }

    static func withLock<Value>(
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts,
        _ operation: () throws -> Value
    ) rethrows -> Value {
        try RawExecArtifactLockRegistry.shared.withLock(
            directoryIdentity: containerDirectory.identity,
            journalIdentity: artifacts.execArtifactJournalIdentity,
            operation
        )
    }

    static func recordPrepared(
        _ record: RawExecArtifactRecord,
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts
    ) throws {
        try withLock(in: containerDirectory, artifacts: artifacts) {
            try record.validate()
            guard record.phase == .published else {
                throw EngineError(.conflict, "exec artifact publication is incomplete")
            }
            try appendLocked(
                Event(action: .prepared, record: record),
                in: containerDirectory,
                artifacts: artifacts
            )
        }
    }

    static func recordState(
        _ record: RawExecArtifactRecord,
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts,
        mutationHook: RawExecJournalMutationHook? = nil
    ) throws {
        try withLock(in: containerDirectory, artifacts: artifacts) {
            try record.validate()
            try appendLocked(
                Event(action: .prepared, record: record),
                in: containerDirectory,
                artifacts: artifacts,
                mutationHook: mutationHook
            )
        }
    }

    static func activeRecord(
        containerID: String,
        execID: String,
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts
    ) throws -> RawExecArtifactRecord? {
        try withLock(in: containerDirectory, artifacts: artifacts) {
            try replay(
                eventsLocked(
                    in: containerDirectory,
                    artifacts: artifacts,
                    expectedContainerID: containerID
                ).events,
                expectedContainerID: containerID
            ).active[execID]
        }
    }

    static func activeRecords(
        containerID: String,
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts
    ) throws -> [RawExecArtifactRecord] {
        try withLock(in: containerDirectory, artifacts: artifacts) {
            try replay(
                eventsLocked(
                    in: containerDirectory,
                    artifacts: artifacts,
                    expectedContainerID: containerID
                ).events,
                expectedContainerID: containerID
            ).active.values.sorted { $0.execID < $1.execID }
        }
    }

    static func recordRemoved(
        _ record: RawExecArtifactRecord,
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts,
        compactionHook: RawExecJournalCompactionHook? = nil
    ) throws {
        try withLock(in: containerDirectory, artifacts: artifacts) {
            try record.validate()
            try appendLocked(
                Event(action: .removed, record: record),
                in: containerDirectory,
                artifacts: artifacts,
                compactionHook: compactionHook
            )
        }
    }

    static func recordAbandoned(
        _ record: RawExecArtifactRecord,
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts,
        compactionHook: RawExecJournalCompactionHook? = nil
    ) throws {
        try withLock(in: containerDirectory, artifacts: artifacts) {
            try record.validate()
            guard record.phase == .preparing else {
                throw EngineError(
                    .conflict, "only a pre-identity exec staging intent can be abandoned"
                )
            }
            try appendLocked(
                Event(action: .abandoned, record: record),
                in: containerDirectory,
                artifacts: artifacts,
                compactionHook: compactionHook
            )
        }
    }

    static func abandonedRecords(
        containerID: String,
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts
    ) throws -> [RawExecArtifactRecord] {
        try withLock(in: containerDirectory, artifacts: artifacts) {
            try replay(
                eventsLocked(
                    in: containerDirectory,
                    artifacts: artifacts,
                    expectedContainerID: containerID
                ).events,
                expectedContainerID: containerID
            ).abandoned
        }
    }

    static func requirePreparationCapacity(
        containerID: String,
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts
    ) throws {
        try withLock(in: containerDirectory, artifacts: artifacts) {
            let state = try replay(
                eventsLocked(
                    in: containerDirectory,
                    artifacts: artifacts,
                    expectedContainerID: containerID
                ).events,
                expectedContainerID: containerID
            )
            guard state.abandoned.count < maximumAbandonedRecordCount else {
                throw BackendResourceRollbackIncompleteError(
                    "exec artifact quarantine reached its bounded limit of "
                        + "\(maximumAbandonedRecordCount)"
                )
            }
            guard state.active.count < maximumActiveRecordCount else {
                throw BackendResourceRollbackIncompleteError(
                    "exec artifact journal reached its active transaction limit of "
                        + "\(maximumActiveRecordCount)"
                )
            }
        }
    }

    static func forceCompaction(
        containerID: String,
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts,
        hook: RawExecJournalCompactionHook? = nil
    ) throws {
        try withLock(in: containerDirectory, artifacts: artifacts) {
            let decoded = try eventsLocked(
                in: containerDirectory,
                artifacts: artifacts,
                expectedContainerID: containerID
            )
            let state = try replay(
                decoded.events, expectedContainerID: containerID
            )
            try compactLocked(
                state: state,
                in: containerDirectory,
                artifacts: artifacts,
                hook: hook
            )
        }
    }

    static func byteCount(
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts
    ) throws -> Int {
        try withLock(in: containerDirectory, artifacts: artifacts) {
            try boundedData(from: open(
                in: containerDirectory, artifacts: artifacts, access: .readWrite
            )).count
        }
    }

    private static func appendLocked(
        _ event: Event,
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts,
        compactionHook: RawExecJournalCompactionHook? = nil,
        mutationHook: RawExecJournalMutationHook? = nil
    ) throws {
        try event.record.validate()
        let handle = try open(in: containerDirectory, artifacts: artifacts, access: .readWrite)
        var decoded = try eventsLocked(
            journalHandle: handle,
            in: containerDirectory,
            artifacts: artifacts,
            expectedContainerID: event.record.containerID
        )
        try mutationHook?(.snapshotLoaded)
        if decoded.events.count >= compactionFrameThreshold {
            let state = try replay(
                decoded.events, expectedContainerID: event.record.containerID
            )
            try compactLocked(
                state: state,
                journalHandle: handle,
                in: containerDirectory,
                artifacts: artifacts,
                hook: compactionHook
            )
            decoded = try eventsLocked(
                journalHandle: handle,
                in: containerDirectory,
                artifacts: artifacts,
                expectedContainerID: event.record.containerID
            )
        }
        let nextEvents = decoded.events + [event]
        _ = try replay(
            nextEvents,
            expectedContainerID: event.record.containerID
        )
        let existing = try boundedData(from: handle)
        if decoded.completeByteCount != existing.count {
            guard Darwin.ftruncate(
                handle.fileDescriptor, off_t(decoded.completeByteCount)
            ) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            try handle.synchronize()
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let payload = try encoder.encode(event)
        guard payload.count <= maximumFramePayloadSize else {
            throw EngineError(.internalError, "exec artifact journal event is too large")
        }
        let data = frame(payload)
        guard decoded.completeByteCount + data.count <= maximumJournalSize else {
            throw BackendResourceRollbackIncompleteError(
                "exec artifact journal reached its bounded size limit"
            )
        }
        try mutationHook?(.frameWillWrite)
        try handle.seek(toOffset: UInt64(decoded.completeByteCount))
        try handle.write(contentsOf: data)
        try handle.synchronize()

        if nextEvents.count >= compactionFrameThreshold,
           event.action != .prepared {
            let state = try replay(
                nextEvents, expectedContainerID: event.record.containerID
            )
            try compactLocked(
                state: state,
                journalHandle: handle,
                in: containerDirectory,
                artifacts: artifacts,
                hook: compactionHook
            )
        }
    }

    private static func eventsLocked(
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts,
        expectedContainerID: String? = nil
    ) throws -> DecodedJournal {
        try eventsLocked(
            journalHandle: open(
                in: containerDirectory, artifacts: artifacts, access: .readWrite
            ),
            in: containerDirectory,
            artifacts: artifacts,
            expectedContainerID: expectedContainerID
        )
    }

    private static func eventsLocked(
        journalHandle: FileHandle,
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts,
        expectedContainerID: String?
    ) throws -> DecodedJournal {
        let canonical = try boundedData(from: journalHandle)
        let recovery = try openCompaction(
            in: containerDirectory, artifacts: artifacts
        )
        let recoveryData = try boundedData(from: recovery)
        if !recoveryData.isEmpty {
            if let recovered = try? decode(recoveryData),
               recovered.completeByteCount == recoveryData.count,
               (try? validateRecovered(
                    recovered.events, expectedContainerID: expectedContainerID
               )) != nil {
                try rewrite(recoveryData, to: journalHandle)
                try rewrite(Data(), to: recovery)
                return recovered
            }
            do {
                let decoded = try decode(canonical)
                if let expectedContainerID {
                    _ = try replay(
                        decoded.events, expectedContainerID: expectedContainerID
                    )
                }
                try rewrite(Data(), to: recovery)
                return decoded
            } catch {
                throw EngineError(
                    .conflict,
                    "exec artifact journal and compaction recovery are both invalid"
                )
            }
        }
        let decoded = try decode(canonical)
        if let expectedContainerID {
            _ = try replay(decoded.events, expectedContainerID: expectedContainerID)
        }
        return decoded
    }

    private static func decode(_ data: Data) throws -> DecodedJournal {
        var result: [Event] = []
        var offset = 0
        while offset < data.count {
            guard result.count < maximumFrameCount else {
                throw EngineError(.conflict, "exec artifact journal has too many frames")
            }
            let remaining = data.count - offset
            if remaining < frameHeaderSize {
                let magicBytes = min(remaining, frameMagic.count)
                guard Data(data[offset..<(offset + magicBytes)])
                    == frameMagic.prefix(magicBytes) else {
                    throw EngineError(.conflict, "invalid exec artifact journal frame")
                }
                break
            }
            guard Data(data[offset..<(offset + frameMagic.count)]) == frameMagic else {
                throw EngineError(.conflict, "invalid exec artifact journal frame")
            }
            let length = decodeUInt64(data, at: offset + 4)
            let expectedChecksum = decodeUInt64(data, at: offset + 12)
            guard length <= UInt64(maximumFramePayloadSize),
                  length <= UInt64(Int.max) else {
                throw EngineError(.conflict, "invalid exec artifact journal frame length")
            }
            let payloadCount = Int(length)
            let (frameEnd, overflow) = offset.addingReportingOverflow(
                frameHeaderSize + payloadCount
            )
            guard !overflow else {
                throw EngineError(.conflict, "invalid exec artifact journal frame length")
            }
            guard frameEnd <= data.count else { break }
            let payload = Data(data[(offset + frameHeaderSize)..<frameEnd])
            guard checksum(payload) == expectedChecksum,
                  let event = try? JSONDecoder().decode(Event.self, from: payload) else {
                throw EngineError(.conflict, "invalid exec artifact journal checksum")
            }
            result.append(event)
            offset = frameEnd
        }
        // A crash may leave only the final frame incomplete. It cannot grant
        // deletion authority. Readers ignore it, while the next writer removes
        // and synchronizes it before appending a complete retry. Complete but
        // corrupt frames are rejected because ownership journals fail closed.
        return DecodedJournal(
            events: result,
            completeByteCount: offset
        )
    }

    static func eventCount(
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts
    ) throws -> Int {
        try withLock(in: containerDirectory, artifacts: artifacts) {
            try eventsLocked(
                in: containerDirectory, artifacts: artifacts
            ).events.count
        }
    }

    private static func replay(
        _ events: [Event],
        expectedContainerID: String
    ) throws -> ReplayState {
        var state = ReplayState()
        for event in events {
            try event.record.validate()
            guard event.record.containerID == expectedContainerID else {
                throw EngineError(.conflict, "exec artifact journal container identity mismatch")
            }
            switch event.action {
            case .prepared:
                if let previous = state.active[event.record.execID] {
                    guard previous == event.record
                            || validTransition(from: previous, to: event.record) else {
                        throw EngineError(.conflict, "invalid exec artifact journal transition")
                    }
                } else {
                    guard event.record.phase == .preparing
                            || (event.record.phase == .published
                                && event.record.stagingDirectoryName.isEmpty) else {
                        throw EngineError(.conflict, "invalid initial exec artifact journal state")
                    }
                }
                state.active[event.record.execID] = event.record
            case .removed, .abandoned:
                guard state.active[event.record.execID] == event.record else {
                    throw EngineError(.conflict, "invalid exec artifact removal event")
                }
                guard event.action != .abandoned
                        || event.record.phase == .preparing else {
                    throw EngineError(.conflict, "invalid exec artifact abandonment event")
                }
                state.active.removeValue(forKey: event.record.execID)
                if event.action == .abandoned {
                    state.abandoned.append(event.record)
                }
            }
            guard state.active.count <= maximumActiveRecordCount,
                  state.abandoned.count <= maximumAbandonedRecordCount else {
                throw BackendResourceRollbackIncompleteError(
                    "exec artifact journal exceeds its bounded transaction policy"
                )
            }
        }
        return state
    }

    private static func validateRecovered(
        _ events: [Event],
        expectedContainerID: String?
    ) throws {
        guard let containerID = expectedContainerID
                ?? events.first?.record.containerID else { return }
        _ = try replay(events, expectedContainerID: containerID)
    }

    private static func compactLocked(
        state: ReplayState,
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts,
        hook: RawExecJournalCompactionHook?
    ) throws {
        try compactLocked(
            state: state,
            journalHandle: open(
                in: containerDirectory, artifacts: artifacts, access: .readWrite
            ),
            in: containerDirectory,
            artifacts: artifacts,
            hook: hook
        )
    }

    private static func compactLocked(
        state: ReplayState,
        journalHandle: FileHandle,
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts,
        hook: RawExecJournalCompactionHook?
    ) throws {
        let compactEvents = canonicalEvents(for: state)
        guard compactEvents.count <= maximumFrameCount else {
            throw BackendResourceRollbackIncompleteError(
                "exec artifact compacted journal exceeds its frame limit"
            )
        }
        let compactData = try encoded(compactEvents)
        guard compactData.count <= maximumJournalSize else {
            throw BackendResourceRollbackIncompleteError(
                "exec artifact compacted journal exceeds its size limit"
            )
        }
        let recovery = try openCompaction(
            in: containerDirectory, artifacts: artifacts
        )
        try rewrite(compactData, to: recovery)
        try hook?(.recoverySynchronized)

        guard Darwin.ftruncate(journalHandle.fileDescriptor, 0) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try hook?(.journalTruncated)
        try journalHandle.seek(toOffset: 0)
        if !compactData.isEmpty {
            try journalHandle.write(contentsOf: compactData)
        }
        try hook?(.journalWritten)
        try journalHandle.synchronize()
        try hook?(.journalSynchronized)
        try rewrite(Data(), to: recovery)
        try hook?(.recoveryCleared)
    }

    private static func canonicalEvents(for state: ReplayState) -> [Event] {
        var result: [Event] = []
        for record in state.abandoned.sorted(by: {
            $0.stagingDirectoryName < $1.stagingDirectoryName
        }) {
            result.append(Event(action: .prepared, record: record))
            result.append(Event(action: .abandoned, record: record))
        }
        for record in state.active.values.sorted(by: { $0.execID < $1.execID }) {
            result.append(contentsOf: transitionEvents(to: record))
        }
        return result
    }

    private static func transitionEvents(
        to record: RawExecArtifactRecord
    ) -> [Event] {
        if record.phase == .published, record.stagingDirectoryName.isEmpty {
            return [Event(action: .prepared, record: record)]
        }
        let preparing = RawExecArtifactRecord(
            containerID: record.containerID,
            execID: record.execID,
            stagingDirectoryName: record.stagingDirectoryName,
            phase: .preparing
        )
        var records = [preparing]
        if record.phase != .preparing {
            let creating = RawExecArtifactRecord(
                containerID: record.containerID,
                execID: record.execID,
                stagingDirectoryName: record.stagingDirectoryName,
                stagingDirectoryIdentity: record.stagingDirectoryIdentity,
                phase: .creating
            )
            records.append(creating)
            if record.phase == .staged || record.phase == .published {
                let staged = RawExecArtifactRecord(
                    containerID: record.containerID,
                    execID: record.execID,
                    stagingDirectoryName: record.stagingDirectoryName,
                    stagingDirectoryIdentity: record.stagingDirectoryIdentity,
                    phase: .staged,
                    fileIdentities: record.fileIdentities
                )
                records.append(staged)
            }
            if record.phase == .published { records.append(record) }
        }
        return records.map { Event(action: .prepared, record: $0) }
    }

    private static func encoded(_ events: [Event]) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        var result = Data()
        for event in events {
            let payload = try encoder.encode(event)
            guard payload.count <= maximumFramePayloadSize else {
                throw BackendResourceRollbackIncompleteError(
                    "exec artifact journal event exceeds its payload limit"
                )
            }
            result.append(frame(payload))
        }
        return result
    }

    private static func frame(_ payload: Data) -> Data {
        var data = Data()
        data.append(frameMagic)
        appendUInt64(UInt64(payload.count), to: &data)
        appendUInt64(checksum(payload), to: &data)
        data.append(payload)
        return data
    }

    private static func boundedData(from handle: FileHandle) throws -> Data {
        let size = try handle.seekToEnd()
        guard size <= UInt64(maximumJournalSize), size <= UInt64(Int.max) else {
            throw BackendResourceRollbackIncompleteError(
                "exec artifact journal exceeds its bounded size limit"
            )
        }
        try handle.seek(toOffset: 0)
        let data = try handle.read(upToCount: Int(size)) ?? Data()
        guard data.count == Int(size) else {
            throw EngineError(.conflict, "exec artifact journal changed while reading")
        }
        return data
    }

    private static func rewrite(_ data: Data, to handle: FileHandle) throws {
        guard Darwin.ftruncate(handle.fileDescriptor, 0) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try handle.seek(toOffset: 0)
        if !data.isEmpty { try handle.write(contentsOf: data) }
        try handle.synchronize()
    }

    private static func validTransition(
        from previous: RawExecArtifactRecord,
        to next: RawExecArtifactRecord
    ) -> Bool {
        guard previous.containerID == next.containerID,
              previous.execID == next.execID,
              previous.stagingDirectoryName == next.stagingDirectoryName else { return false }
        switch (previous.phase, next.phase) {
        case (.preparing, .creating):
            return previous.stagingDirectoryIdentity == nil
                && next.stagingDirectoryIdentity != nil
                && previous.fileIdentities.isEmpty
                && next.fileIdentities.isEmpty
        case (.creating, .staged):
            return previous.stagingDirectoryIdentity == next.stagingDirectoryIdentity
                && previous.fileIdentities.isEmpty
        case (.staged, .published):
            return previous.stagingDirectoryIdentity == next.stagingDirectoryIdentity
                && previous.fileIdentities == next.fileIdentities
        default:
            return false
        }
    }

    private static func appendUInt64(_ value: UInt64, to data: inout Data) {
        var encoded = value.bigEndian
        withUnsafeBytes(of: &encoded) { data.append(contentsOf: $0) }
    }

    private static func decodeUInt64(_ data: Data, at offset: Int) -> UInt64 {
        data[offset..<(offset + 8)].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }

    private static func checksum(_ data: Data) -> UInt64 {
        data.reduce(UInt64(1_469_598_103_934_665_603)) {
            ($0 ^ UInt64($1)) &* 1_099_511_628_211
        }
    }

    private static func open(
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts,
        access: PersistentRegularFileAccess
    ) throws -> FileHandle {
        try containerDirectory.openRegularFile(
            named: "exec-artifacts.jsonl",
            expectedIdentity: artifacts.execArtifactJournalIdentity,
            access: access
        ).handle
    }

    private static func openCompaction(
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts
    ) throws -> FileHandle {
        try containerDirectory.openRegularFile(
            named: "exec-artifacts.compact",
            expectedIdentity: artifacts.execArtifactCompactionIdentity,
            access: .readWrite
        ).handle
    }
}

struct RawPreparedExecArtifacts {
    let record: RawExecArtifactRecord
    let stdout: FileHandle
    let stderr: FileHandle
    let stdin: FileHandle
    let stdinClosed: FileHandle
    let log: FileHandle
    let logIndex: FileHandle
}

/// Publishes exec I/O as a durable identity-bound transaction. All files are
/// first created in an exact staging-directory inode. The journal captures
/// every file identity before any canonical `exec-*` name is exposed, so
/// cleanup after a crash can distinguish owned inodes from replacements.
enum RawExecArtifactTransaction {
    static func prepare(
        containerID: String,
        execID: String,
        attachStdin: Bool,
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts,
        hook: RawExecArtifactHook? = nil,
        journalMutationHook: RawExecJournalMutationHook? = nil,
        cleanupOnFailure: Bool = true
    ) throws -> RawPreparedExecArtifacts {
        try RawExecArtifactJournal.withLock(
            in: containerDirectory, artifacts: artifacts
        ) {
            try prepareLocked(
                containerID: containerID,
                execID: execID,
                attachStdin: attachStdin,
                in: containerDirectory,
                artifacts: artifacts,
                hook: hook,
                journalMutationHook: journalMutationHook,
                cleanupOnFailure: cleanupOnFailure
            )
        }
    }

    private static func prepareLocked(
        containerID: String,
        execID: String,
        attachStdin: Bool,
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts,
        hook: RawExecArtifactHook? = nil,
        journalMutationHook: RawExecJournalMutationHook? = nil,
        cleanupOnFailure: Bool = true
    ) throws -> RawPreparedExecArtifacts {
        try artifacts.validate(in: containerDirectory)
        let ioDirectory = try containerDirectory.openDirectory(named: "io")
        guard ioDirectory.identity == artifacts.ioDirectoryIdentity else {
            throw EngineError(.conflict, "exec artifact I/O directory changed")
        }
        try RawExecArtifactJournal.requirePreparationCapacity(
            containerID: containerID,
            in: containerDirectory,
            artifacts: artifacts
        )
        guard try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: execID,
            in: containerDirectory,
            artifacts: artifacts
        ) == nil else {
            throw BackendResourceRollbackIncompleteError(
                "exec \(execID) has an unfinished artifact transaction"
            )
        }

        let nonce = String(
            UUID().uuidString.replacingOccurrences(of: "-", with: "")
                .lowercased().prefix(16)
        )
        var record = RawExecArtifactRecord(
            containerID: containerID,
            execID: execID,
            stagingDirectoryName: ".cengine-exec-stage-\(nonce)",
            phase: .preparing
        )
        try RawExecArtifactJournal.recordState(
            record,
            in: containerDirectory,
            artifacts: artifacts,
            mutationHook: journalMutationHook
        )

        do {
            try hook?(.intentionSynchronized)
            let staging = try ioDirectory.createDirectory(
                named: record.stagingDirectoryName
            )
            try hook?(.stagingDirectoryCreated)
            record.stagingDirectoryIdentity = staging.identity
            record.phase = .creating
            try RawExecArtifactJournal.recordState(
                record,
                in: containerDirectory,
                artifacts: artifacts,
                mutationHook: journalMutationHook
            )
            try hook?(.stagingDirectorySynchronized)

            var identities: [String: PersistentFileIdentity] = [:]
            for (index, name) in RawExecArtifactRecord.expectedNames(
                execID: execID
            ).enumerated() {
                identities[name] = try staging.createSparseRegularFile(
                    named: stagedName(index), size: 0
                )
                try hook?(.artifactStaged(name))
            }
            if !attachStdin {
                let inputClosedName = "exec-\(execID)-stdin.closed"
                guard let inputClosedIndex = RawExecArtifactRecord.expectedNames(
                    execID: execID
                ).firstIndex(of: inputClosedName),
                      let identity = identities[inputClosedName] else {
                    throw EngineError(.internalError, "missing staged exec input marker")
                }
                let inputClosed = try staging.openRegularFile(
                    named: stagedName(inputClosedIndex),
                    expectedIdentity: identity,
                    access: .readWrite
                ).handle
                try RawContainerDirectIOHandles.markInputClosed(inputClosed)
            }
            try staging.synchronize()
            record.fileIdentities = identities
            record.phase = .staged
            try RawExecArtifactJournal.recordState(
                record,
                in: containerDirectory,
                artifacts: artifacts,
                mutationHook: journalMutationHook
            )
            try hook?(.stagedOwnershipSynchronized)
            try requireCanonicalDirectories(
                containerDirectory: containerDirectory,
                ioDirectory: ioDirectory,
                artifacts: artifacts
            )

            for (index, name) in RawExecArtifactRecord.expectedNames(
                execID: execID
            ).enumerated() {
                guard let identity = identities[name],
                      let staged = try staging.entryMetadata(named: stagedName(index)),
                      staged.identity == identity,
                      staged.type == S_IFREG,
                      try ioDirectory.entryMetadata(named: name) == nil else {
                    throw EngineError(.conflict, "exec artifact changed before publication")
                }
                guard Darwin.renameatx_np(
                    staging.descriptor,
                    stagedName(index),
                    ioDirectory.descriptor,
                    name,
                    UInt32(RENAME_EXCL)
                ) == 0 else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
                try hook?(.artifactExposed(name))
                guard let exposed = try ioDirectory.entryMetadata(named: name),
                      exposed.identity == identity,
                      exposed.type == S_IFREG else {
                    throw EngineError(.conflict, "exec artifact changed during publication")
                }
                try requireCanonicalDirectories(
                    containerDirectory: containerDirectory,
                    ioDirectory: ioDirectory,
                    artifacts: artifacts
                )
            }
            guard try staging.entryNames().isEmpty,
                  let stagingMetadata = try ioDirectory.entryMetadata(
                    named: record.stagingDirectoryName
                  ),
                  stagingMetadata.identity == staging.identity,
                  stagingMetadata.type == S_IFDIR,
                  Darwin.unlinkat(
                    ioDirectory.descriptor,
                    record.stagingDirectoryName,
                    AT_REMOVEDIR
                  ) == 0 else {
                throw EngineError(.conflict, "exec artifact staging directory changed")
            }
            try ioDirectory.synchronize()
            try hook?(.ioDirectorySynchronized)
            try requireCanonicalDirectories(
                containerDirectory: containerDirectory,
                ioDirectory: ioDirectory,
                artifacts: artifacts
            )
            record.phase = .published
            try RawExecArtifactJournal.recordState(
                record,
                in: containerDirectory,
                artifacts: artifacts,
                mutationHook: journalMutationHook
            )
            try hook?(.publicationSynchronized)

            func open(_ name: String) throws -> FileHandle {
                guard let identity = record.fileIdentities[name] else {
                    throw EngineError(.internalError, "missing published exec artifact identity")
                }
                return try ioDirectory.openRegularFile(
                    named: name, expectedIdentity: identity, access: .readWrite
                ).handle
            }
            return try RawPreparedExecArtifacts(
                record: record,
                stdout: open("exec-\(execID)-stdout"),
                stderr: open("exec-\(execID)-stderr"),
                stdin: open("exec-\(execID)-stdin"),
                stdinClosed: open("exec-\(execID)-stdin.closed"),
                log: open("exec-\(execID)-docker.log"),
                logIndex: open("exec-\(execID)-docker.log.entries")
            )
        } catch {
            guard cleanupOnFailure else { throw error }
            do {
                try cleanup(
                    containerID: containerID,
                    execID: execID,
                    in: containerDirectory,
                    artifacts: artifacts
                )
            } catch let cleanupError {
                throw BackendResourceRollbackIncompleteError(
                    "exec \(execID) artifact preparation failed ("
                        + EngineError.message(for: error)
                        + ") and cleanup was incomplete ("
                        + EngineError.message(for: cleanupError) + ")"
                )
            }
            throw error
        }
    }

    static func cleanup(
        containerID: String,
        execID: String,
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts,
        hook: PersistentRuntimeArtifactHook? = nil,
        compactionHook: RawExecJournalCompactionHook? = nil
    ) throws {
        try RawExecArtifactJournal.withLock(
            in: containerDirectory, artifacts: artifacts
        ) {
            try cleanupLocked(
                containerID: containerID,
                execID: execID,
                in: containerDirectory,
                artifacts: artifacts,
                hook: hook,
                compactionHook: compactionHook
            )
        }
    }

    private static func cleanupLocked(
        containerID: String,
        execID: String,
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts,
        hook: PersistentRuntimeArtifactHook?,
        compactionHook: RawExecJournalCompactionHook?
    ) throws {
        try artifacts.validate(in: containerDirectory)
        guard let record = try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: execID,
            in: containerDirectory,
            artifacts: artifacts
        ) else { return }
        let ioDirectory = try containerDirectory.openDirectory(named: "io")
        guard ioDirectory.identity == artifacts.ioDirectoryIdentity else {
            throw EngineError(.conflict, "exec artifact I/O directory changed")
        }

        switch record.phase {
        case .preparing:
            if try ioDirectory.entryMetadata(
                named: record.stagingDirectoryName
            ) != nil {
                // mkdir may have landed before its inode identity frame. No
                // later observation can distinguish that inode from an ABA
                // replacement, so preserve the path and retire this attempt.
                // A retry uses a new random reservation and cannot be blocked
                // by the quarantined object.
                try requireCanonicalDirectories(
                    containerDirectory: containerDirectory,
                    ioDirectory: ioDirectory,
                    artifacts: artifacts
                )
                try RawExecArtifactJournal.recordAbandoned(
                    record,
                    in: containerDirectory,
                    artifacts: artifacts,
                    compactionHook: compactionHook
                )
                return
            }
        case .creating:
            guard let expectedIdentity = record.stagingDirectoryIdentity else {
                throw EngineError(.conflict, "exec artifact staging identity is missing")
            }
            if let staging = try ioDirectory.openDirectoryIfPresent(
                named: record.stagingDirectoryName
            ) {
                guard staging.identity == expectedIdentity else {
                    throw BackendResourceRollbackIncompleteError(
                        "exec artifact staging directory was replaced"
                    )
                }
                try ioDirectory.disposeDirectory(
                    named: record.stagingDirectoryName,
                    expectedIdentity: expectedIdentity
                )
            }
        case .staged, .published:
            try RawContainerDirectIOHandles.cleanupGuestClaims(
                Self.guestClaim(for: record),
                names: Array(
                    RawExecArtifactRecord.expectedNames(execID: record.execID).prefix(4)
                ),
                identities: record.fileIdentities,
                in: ioDirectory,
                removalHook: hook
            )
            try cleanupIdentifiedFiles(
                record,
                in: ioDirectory,
                hook: hook
            )
        }

        try requireCanonicalDirectories(
            containerDirectory: containerDirectory,
            ioDirectory: ioDirectory,
            artifacts: artifacts
        )
        try RawExecArtifactJournal.recordRemoved(
            record,
            in: containerDirectory,
            artifacts: artifacts,
            compactionHook: compactionHook
        )
    }

    static func cleanupAll(
        containerID: String,
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts
    ) throws {
        try RawExecArtifactJournal.withLock(
            in: containerDirectory, artifacts: artifacts
        ) {
            for record in try RawExecArtifactJournal.activeRecords(
                containerID: containerID,
                in: containerDirectory,
                artifacts: artifacts
            ) {
                try cleanupLocked(
                    containerID: containerID,
                    execID: record.execID,
                    in: containerDirectory,
                    artifacts: artifacts,
                    hook: nil,
                    compactionHook: nil
                )
            }
        }
    }

    private static func cleanupIdentifiedFiles(
        _ record: RawExecArtifactRecord,
        in ioDirectory: PersistentStateDirectory,
        hook: PersistentRuntimeArtifactHook?
    ) throws {
        let staging: PersistentStateDirectory?
        if record.stagingDirectoryName.isEmpty {
            staging = nil
        } else if let directory = try ioDirectory.openDirectoryIfPresent(
            named: record.stagingDirectoryName
        ) {
            guard directory.identity == record.stagingDirectoryIdentity else {
                throw BackendResourceRollbackIncompleteError(
                    "exec artifact staging directory was replaced"
                )
            }
            staging = directory
        } else {
            staging = nil
        }

        let names = RawExecArtifactRecord.expectedNames(execID: record.execID)
        for (index, name) in names.enumerated() {
            guard let identity = record.fileIdentities[name] else {
                throw EngineError(.conflict, "missing exec artifact identity")
            }
            let claim = removalClaimName(record: record, index: index)
            try requireOwnedOrAbsent(
                in: ioDirectory,
                names: [name, claim],
                identity: identity
            )
            if let staging {
                try requireOwnedOrAbsent(
                    in: staging,
                    names: [stagedName(index), claim],
                    identity: identity
                )
            }
        }

        for (index, name) in names.enumerated() {
            guard let identity = record.fileIdentities[name] else { continue }
            let claim = removalClaimName(record: record, index: index)
            _ = try ioDirectory.removeEntryIfMatching(
                named: name,
                identity: identity,
                type: S_IFREG,
                claimName: claim,
                hook: hook
            )
            if let staging {
                _ = try staging.removeEntryIfMatching(
                    named: stagedName(index),
                    identity: identity,
                    type: S_IFREG,
                    claimName: claim,
                    hook: hook
                )
            }
        }

        for (index, name) in names.enumerated() {
            let claim = removalClaimName(record: record, index: index)
            try requireAbsence(in: ioDirectory, names: [name, claim])
            if let staging {
                try requireAbsence(
                    in: staging,
                    names: [stagedName(index), claim]
                )
            }
        }

        if let staging {
            guard try staging.entryNames().isEmpty,
                  let stagingIdentity = record.stagingDirectoryIdentity else {
                throw EngineError(.conflict, "exec artifact staging directory is not empty")
            }
            try ioDirectory.disposeDirectory(
                named: record.stagingDirectoryName,
                expectedIdentity: stagingIdentity
            )
        }
        for (index, name) in names.enumerated() {
            try requireAbsence(
                in: ioDirectory,
                names: [name, removalClaimName(record: record, index: index)]
            )
        }
    }

    private static func requireOwnedOrAbsent(
        in directory: PersistentStateDirectory,
        names: [String],
        identity: PersistentFileIdentity
    ) throws {
        for name in names {
            guard let metadata = try directory.entryMetadata(named: name) else { continue }
            guard metadata.identity == identity, metadata.type == S_IFREG else {
                throw BackendResourceRollbackIncompleteError(
                    "exec artifact \(name) was replaced"
                )
            }
        }
    }

    private static func requireAbsence(
        in directory: PersistentStateDirectory,
        names: [String]
    ) throws {
        for name in names {
            if try directory.entryMetadata(named: name) != nil {
                throw BackendResourceRollbackIncompleteError(
                    "exec artifact \(name) remained after cleanup"
                )
            }
        }
    }

    private static func requireCanonicalDirectories(
        containerDirectory: PersistentStateDirectory,
        ioDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts
    ) throws {
        try artifacts.validate(in: containerDirectory)
        guard containerDirectory.pathStillNamesThisDirectory(),
              ioDirectory.pathStillNamesThisDirectory(),
              ioDirectory.identity == artifacts.ioDirectoryIdentity else {
            throw BackendResourceRollbackIncompleteError(
                "exec artifact publication directory changed"
            )
        }
    }

    private static func stagedName(_ index: Int) -> String { "a\(index)" }

    private static func removalClaimName(
        record: RawExecArtifactRecord,
        index: Int
    ) -> String {
        let token = record.stagingDirectoryName.isEmpty
            ? String(record.execID.prefix(16))
            : String(record.stagingDirectoryName.suffix(16))
        return ".cengine-remove-exec-\(token)-\(index)"
    }

    static func guestClaim(for record: RawExecArtifactRecord) -> String {
        let token = record.stagingDirectoryName.isEmpty
            ? String(record.execID.prefix(16))
            : String(record.stagingDirectoryName.suffix(16))
        return "exec-\(token)"
    }
}

enum RawIOSourceSessionResetBoundary: Equatable, Sendable {
    case directIOTruncated(String)
    case directIOSynchronized(String)
    case inputClosedSynchronized
    case epochWillAppend
    case epochAppended
}

typealias RawIOSourceSessionResetHook = (RawIOSourceSessionResetBoundary) throws -> Void

struct RawContainerDirectIOHandles {
    let directory: PersistentStateDirectory
    let stdout: FileHandle
    let stderr: FileHandle
    let stdin: FileHandle
    let stdinClosed: FileHandle
    let stdoutSpool: PersistentStateDirectory?
    let stderrSpool: PersistentStateDirectory?

    static func open(
        in containerDirectory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts
    ) throws -> RawContainerDirectIOHandles {
        try artifacts.validate(in: containerDirectory)
        let ioDirectory = try containerDirectory.openDirectory(named: "io")
        guard ioDirectory.identity == artifacts.ioDirectoryIdentity else {
            throw EngineError(.conflict, "container direct-I/O directory identity changed")
        }
        func open(_ name: String) throws -> FileHandle {
            guard let identity = artifacts.ioFileIdentities[name] else {
                throw EngineError(.internalError, "missing direct-I/O file identity")
            }
            let opened = try ioDirectory.openRegularFile(
                named: name,
                expectedIdentity: identity,
                access: .readWrite
            )
            return opened.handle
        }
        let handles = RawContainerDirectIOHandles(
            directory: ioDirectory,
            stdout: try open("stdout"),
            stderr: try open("stderr"),
            stdin: try open("stdin"),
            stdinClosed: try open("stdin.closed"),
            stdoutSpool: try openSpool(
                "stdout.spool", artifacts: artifacts, directory: ioDirectory
            ),
            stderrSpool: try openSpool(
                "stderr.spool", artifacts: artifacts, directory: ioDirectory
            )
        )
        try handles.validateNames(artifacts: artifacts)
        return handles
    }

    private static func openSpool(
        _ name: String,
        artifacts: RawContainerPreparationArtifacts,
        directory: PersistentStateDirectory
    ) throws -> PersistentStateDirectory? {
        guard let expected = artifacts.outputSpoolDirectoryIdentities?[name] else {
            return nil
        }
        let spool = try directory.openDirectory(named: name)
        guard spool.identity == expected else {
            throw EngineError(.conflict, "container output spool directory changed")
        }
        return spool
    }

    func validateNames(artifacts: RawContainerPreparationArtifacts) throws {
        guard directory.identity == artifacts.ioDirectoryIdentity,
              directory.pathStillNamesThisDirectory() else {
            throw EngineError(.conflict, "container direct-I/O directory changed")
        }
        for name in RawContainerPreparationArtifacts.directIOFileNames {
            guard let identity = artifacts.ioFileIdentities[name] else {
                throw EngineError(.internalError, "missing direct-I/O file identity")
            }
            _ = try directory.regularFileIdentity(
                named: name, expectedIdentity: identity
            )
        }
        if let expected = artifacts.outputSpoolDirectoryIdentities {
            for (name, identity) in expected {
                let spool = try directory.openDirectory(named: name)
                guard spool.identity == identity else {
                    throw EngineError(.conflict, "container output spool directory changed")
                }
            }
        }
        _ = try directory.regularFileIdentity(
            named: "docker.log", expectedIdentity: artifacts.dockerLogIdentity
        )
        _ = try directory.regularFileIdentity(
            named: "docker.log.entries", expectedIdentity: artifacts.dockerLogIndexIdentity
        )
    }

    func openDockerLogs(
        artifacts: RawContainerPreparationArtifacts
    ) throws -> (
        log: FileHandle,
        index: FileHandle,
        journalDirectory: PersistentStateDirectory
    ) {
        try validateNames(artifacts: artifacts)
        let log = try directory.openRegularFile(
            named: "docker.log",
            expectedIdentity: artifacts.dockerLogIdentity,
            access: .readWrite
        ).handle
        let index = try directory.openRegularFile(
            named: "docker.log.entries",
            expectedIdentity: artifacts.dockerLogIndexIdentity,
            access: .readWrite
        ).handle
        let journalDirectory = try directory.openOrCreateDirectory(
            named: "docker.log.journal"
        )
        if let expected = artifacts.dockerLogJournalDirectoryIdentity,
           journalDirectory.identity != expected {
            throw EngineError(.conflict, "container log journal directory changed")
        }
        try validateNames(artifacts: artifacts)
        return (log, index, journalDirectory)
    }

    func truncate(hook: RawIOSourceSessionResetHook? = nil) throws {
        for spool in [stdoutSpool, stderrSpool].compactMap({ $0 }) {
            try VMShimOutputSpooler.reset(spool)
        }
        let namedHandles = zip(
            RawContainerPreparationArtifacts.directIOFileNames,
            [stdout, stderr, stdin, stdinClosed]
        )
        for (name, handle) in namedHandles {
            guard Darwin.ftruncate(handle.fileDescriptor, 0) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            try handle.seek(toOffset: 0)
            try hook?(.directIOTruncated(name))
            try handle.synchronize()
            try hook?(.directIOSynchronized(name))
        }
    }

    func resetSourceSession(
        artifacts: RawContainerPreparationArtifacts,
        openStdin: Bool,
        bridge: ContainerIOBridge,
        hook: RawIOSourceSessionResetHook? = nil
    ) throws {
        try validateNames(artifacts: artifacts)
        try truncate(hook: hook)
        try validateNames(artifacts: artifacts)
        if !openStdin {
            try markInputClosed()
            try hook?(.inputClosedSynchronized)
        }
        try hook?(.epochWillAppend)
        try bridge.beginSourceSession()
        try hook?(.epochAppended)
    }

    func markInputClosed() throws {
        try Self.markInputClosed(stdinClosed)
    }

    static func markInputClosed(_ handle: FileHandle) throws {
        try handle.seek(toOffset: 0)
        try handle.write(contentsOf: Data([1]))
        guard Darwin.ftruncate(handle.fileDescriptor, 1) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try handle.synchronize()
    }

    func consumeGuestClaims(
        _ claim: String,
        artifacts: RawContainerPreparationArtifacts,
        beforeClaimRemoval: ((Int) throws -> Void)? = nil,
        removalHook: PersistentRuntimeArtifactHook? = nil
    ) throws {
        try validateNames(artifacts: artifacts)
        try Self.consumeGuestClaims(
            claim,
            names: RawContainerPreparationArtifacts.directIOFileNames,
            identities: artifacts.ioFileIdentities,
            in: directory,
            beforeClaimRemoval: beforeClaimRemoval,
            removalHook: removalHook
        )
        try validateNames(artifacts: artifacts)
    }

    static func consumeGuestClaims(
        _ claim: String,
        names: [String],
        identities: [String: PersistentFileIdentity],
        in directory: PersistentStateDirectory,
        beforeClaimRemoval: ((Int) throws -> Void)? = nil,
        removalHook: PersistentRuntimeArtifactHook? = nil
    ) throws {
        var isResumingRemoval = false
        for (index, name) in names.enumerated() {
            guard let identity = identities[name] else {
                throw EngineError(.internalError, "missing I/O file identity")
            }
            let original = guestClaimName(claim, index: index)
            let removal = guestClaimRemovalName(claim, index: index)
            let originalMetadata = try directory.entryMetadata(named: original)
            let removalMetadata = try directory.entryMetadata(named: removal)
            try requireMatchingClaim(
                originalMetadata, name: original, identity: identity
            )
            try requireMatchingClaim(
                removalMetadata, name: removal, identity: identity
            )
            isResumingRemoval = isResumingRemoval || removalMetadata != nil
        }
        if !isResumingRemoval {
            for (index, name) in names.enumerated() {
                guard try directory.entryMetadata(
                    named: guestClaimName(claim, index: index)
                ) != nil else {
                    throw EngineError(
                        .conflict, "guest I/O claim is missing before consumption"
                    )
                }
                guard identities[name] != nil else {
                    throw EngineError(.internalError, "missing I/O file identity")
                }
            }
        }
        for (index, name) in names.enumerated() {
            try beforeClaimRemoval?(index)
            guard let identity = identities[name] else { continue }
            try removeGuestClaim(
                claim,
                index: index,
                identity: identity,
                in: directory,
                errorMessage: "guest I/O claim changed before cleanup",
                removalHook: removalHook
            )
        }
    }

    static func cleanupGuestClaims(
        _ claim: String,
        names: [String],
        identities: [String: PersistentFileIdentity],
        in directory: PersistentStateDirectory,
        beforeClaimRemoval: ((Int) throws -> Void)? = nil,
        removalHook: PersistentRuntimeArtifactHook? = nil
    ) throws {
        for (index, name) in names.enumerated() {
            guard let identity = identities[name] else {
                throw EngineError(.internalError, "missing I/O file identity")
            }
            try requireMatchingClaim(
                try directory.entryMetadata(named: guestClaimName(claim, index: index)),
                name: guestClaimName(claim, index: index),
                identity: identity
            )
            try requireMatchingClaim(
                try directory.entryMetadata(
                    named: guestClaimRemovalName(claim, index: index)
                ),
                name: guestClaimRemovalName(claim, index: index),
                identity: identity
            )
        }
        for (index, name) in names.enumerated() {
            try beforeClaimRemoval?(index)
            guard let identity = identities[name] else { continue }
            try removeGuestClaim(
                claim,
                index: index,
                identity: identity,
                in: directory,
                errorMessage: "guest I/O claim changed before recovery",
                removalHook: removalHook
            )
        }
    }

    private static func removeGuestClaim(
        _ claim: String,
        index: Int,
        identity: PersistentFileIdentity,
        in directory: PersistentStateDirectory,
        errorMessage: String,
        removalHook: PersistentRuntimeArtifactHook?
    ) throws {
        let original = guestClaimName(claim, index: index)
        let removal = guestClaimRemovalName(claim, index: index)
        // Two passes handle the fail-closed case where both names reference
        // the owned inode: first retire the durable removal claim, then claim
        // and retire the original alias. Normal and replay paths both use the
        // same descriptor-owned rename/unlink helper.
        for _ in 0..<2 {
            let originalExists = try directory.entryMetadata(named: original) != nil
            let removalExists = try directory.entryMetadata(named: removal) != nil
            guard originalExists || removalExists else { return }
            guard try directory.removeEntryIfMatching(
                named: original,
                identity: identity,
                type: S_IFREG,
                claimName: removal,
                hook: removalHook
            ) else {
                throw EngineError(.conflict, errorMessage)
            }
        }
        guard try directory.entryMetadata(named: original) == nil,
              try directory.entryMetadata(named: removal) == nil else {
            throw EngineError(.conflict, errorMessage)
        }
    }

    private static func requireMatchingClaim(
        _ metadata: (identity: PersistentFileIdentity, type: mode_t)?,
        name: String,
        identity: PersistentFileIdentity
    ) throws {
        guard let metadata else { return }
        guard metadata.identity == identity, metadata.type == S_IFREG else {
            throw EngineError(.conflict, "guest I/O removal claim \(name) was replaced")
        }
    }

    static func guestClaimName(_ claim: String, index: Int) -> String {
        ".cengine-io-claim-\(claim)-\(index)"
    }

    static func guestClaimRemovalName(_ claim: String, index: Int) -> String {
        ".cengine-remove-io-claim-\(claim)-\(index)"
    }

    static func containerGuestClaim(instanceID: UUID, generation: UInt64) -> String {
        "container-\(instanceID.uuidString.lowercased())-\(generation)"
    }
}

enum RawDirectoryTransferBoundary: Equatable, Sendable {
    case entryOpened(String)
    case destinationCreated(String)
    case entryCopied(String)
}

typealias RawDirectoryTransferHook = (RawDirectoryTransferBoundary) throws -> Void

/// Copies an archive tree between descriptor-owned directories. Every lookup
/// is relative to a retained directory descriptor, final components are never
/// followed, and names are revalidated after use so a concurrent replacement
/// is rejected without redirecting reads or writes through its path.
enum RawDirectoryTransfer {
    static func copyContents(
        from source: PersistentStateDirectory,
        to destination: PersistentStateDirectory,
        validateRoots: () throws -> Void = {},
        hook: RawDirectoryTransferHook? = nil
    ) throws {
        try validateRoots()
        guard try destination.entryNames().isEmpty else {
            throw EngineError(.conflict, "copy destination is not empty")
        }
        let names = try source.entryNames()
        for name in names {
            try copyEntry(
                named: name,
                path: name,
                from: source,
                to: destination,
                validateRoots: validateRoots,
                hook: hook
            )
        }
        guard try source.entryNames() == names else {
            throw EngineError(.conflict, "copy source changed during transfer")
        }
        try validateRoots()
    }

    private static func copyEntry(
        named name: String,
        path: String,
        from source: PersistentStateDirectory,
        to destination: PersistentStateDirectory,
        validateRoots: () throws -> Void,
        hook: RawDirectoryTransferHook?
    ) throws {
        guard let original = try source.entryMetadata(named: name) else {
            throw EngineError(.conflict, "copy source entry disappeared")
        }
        switch original.type {
        case S_IFDIR:
            let sourceChild = try source.openDirectory(named: name)
            guard sourceChild.identity == original.identity else {
                throw EngineError(.conflict, "copy source directory changed")
            }
            let permissions = try permissions(of: sourceChild.descriptor)
            let destinationChild = try destination.createDirectory(
                named: name, permissions: mode_t(0o700)
            )
            try hook?(.entryOpened(path))
            try hook?(.destinationCreated(path))
            try validateRoots()
            let names = try sourceChild.entryNames()
            for childName in names {
                try copyEntry(
                    named: childName,
                    path: "\(path)/\(childName)",
                    from: sourceChild,
                    to: destinationChild,
                    validateRoots: validateRoots,
                    hook: hook
                )
            }
            guard try sourceChild.entryNames() == names,
                  try entryStillMatches(
                    in: source, named: name, identity: original.identity, type: S_IFDIR
                  ),
                  try entryStillMatches(
                    in: destination,
                    named: name,
                    identity: destinationChild.identity,
                    type: S_IFDIR
                  ) else {
                throw EngineError(.conflict, "copy directory changed during transfer")
            }
            guard Darwin.fchmod(destinationChild.descriptor, permissions) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            try destinationChild.synchronize()

        case S_IFREG:
            let input = try source.openRegularFile(
                named: name, expectedIdentity: original.identity, access: .readOnly
            )
            let permissions = try permissions(of: input.handle.fileDescriptor)
            let outputIdentity = try destination.createSparseRegularFile(
                named: name, size: 0, permissions: mode_t(0o600)
            )
            let output = try destination.openRegularFile(
                named: name, expectedIdentity: outputIdentity, access: .writeOnly
            )
            try hook?(.entryOpened(path))
            try hook?(.destinationCreated(path))
            try validateRoots()
            try copyRegularFile(from: input.handle, to: output.handle)
            guard Darwin.fchmod(output.handle.fileDescriptor, permissions) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            try output.handle.synchronize()
            guard try entryStillMatches(
                    in: source, named: name, identity: original.identity, type: S_IFREG
                  ),
                  try entryStillMatches(
                    in: destination,
                    named: name,
                    identity: outputIdentity,
                    type: S_IFREG
                  ) else {
                throw EngineError(.conflict, "copy regular file changed during transfer")
            }

        case S_IFLNK:
            let sourceDescriptor = Darwin.openat(
                source.descriptor, name, O_RDONLY | O_SYMLINK | O_CLOEXEC
            )
            guard sourceDescriptor >= 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            defer { Darwin.close(sourceDescriptor) }
            var sourceInformation = stat()
            guard Darwin.fstat(sourceDescriptor, &sourceInformation) == 0,
                  sourceInformation.st_mode & S_IFMT == S_IFLNK,
                  PersistentFileIdentity(
                      sourceInformation, volumeUUID: original.identity.volumeUUID
                  ) == original.identity else {
                throw EngineError(.conflict, "copy source symbolic link changed while opening")
            }
            try hook?(.entryOpened(path))
            try validateRoots()
            let target = try readSymbolicLink(descriptor: sourceDescriptor)
            guard target.withCString({ Darwin.symlinkat($0, destination.descriptor, name) }) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            let destinationDescriptor = Darwin.openat(
                destination.descriptor, name, O_RDONLY | O_SYMLINK | O_CLOEXEC
            )
            guard destinationDescriptor >= 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            defer { Darwin.close(destinationDescriptor) }
            var destinationInformation = stat()
            guard Darwin.fstat(destinationDescriptor, &destinationInformation) == 0,
                  destinationInformation.st_mode & S_IFMT == S_IFLNK else {
                throw EngineError(.conflict, "copy destination symbolic link is unsafe")
            }
            let destinationIdentity = try PersistentFileIdentity.capture(
                descriptor: destinationDescriptor
            )
            guard try readSymbolicLink(descriptor: destinationDescriptor) == target else {
                throw EngineError(.conflict, "copy destination symbolic link target changed")
            }
            try hook?(.destinationCreated(path))
            guard try entryStillMatches(
                    in: source, named: name, identity: original.identity, type: S_IFLNK
                  ),
                  try entryStillMatches(
                    in: destination,
                    named: name,
                    identity: destinationIdentity,
                    type: S_IFLNK
                  ),
                  try readSymbolicLink(descriptor: sourceDescriptor) == target,
                  try readSymbolicLink(descriptor: destinationDescriptor) == target else {
                throw EngineError(.conflict, "copy symbolic link changed during transfer")
            }

        default:
            throw EngineError(.badRequest, "unsupported archive entry \(path)")
        }
        try hook?(.entryCopied(path))
        try validateRoots()
    }

    private static func copyRegularFile(from source: FileHandle, to destination: FileHandle) throws {
        var buffer = [UInt8](repeating: 0, count: 128 * 1_024)
        while true {
            let count = buffer.withUnsafeMutableBytes {
                Darwin.read(source.fileDescriptor, $0.baseAddress, $0.count)
            }
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            var offset = 0
            while offset < count {
                let written = buffer.withUnsafeBytes {
                    Darwin.write(
                        destination.fileDescriptor,
                        $0.baseAddress?.advanced(by: offset),
                        count - offset
                    )
                }
                if written > 0 {
                    offset += written
                } else if written < 0, errno == EINTR {
                    continue
                } else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
            }
        }
        try destination.synchronize()
    }

    private static func permissions(of descriptor: CInt) throws -> mode_t {
        var information = stat()
        guard Darwin.fstat(descriptor, &information) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        return information.st_mode & mode_t(0o7777)
    }

    private static func readSymbolicLink(descriptor: CInt) throws -> String {
        var bytes = [UInt8](repeating: 0, count: Int(PATH_MAX) + 1)
        let count = bytes.withUnsafeMutableBytes {
            Darwin.freadlink(descriptor, $0.baseAddress, $0.count - 1)
        }
        guard count >= 0, count < bytes.count else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        return String(decoding: bytes.prefix(count), as: UTF8.self)
    }

    private static func entryStillMatches(
        in directory: PersistentStateDirectory,
        named name: String,
        identity: PersistentFileIdentity,
        type: mode_t
    ) throws -> Bool {
        guard let current = try directory.entryMetadata(named: name) else { return false }
        return current.identity == identity && current.type == type
    }
}

struct CompatibilityResourceUpdateFailureMarker: Codable, Equatable, Sendable {
    let containerID: String
    let failureAfterWrites: UInt32
}

enum CompatibilityResourceUpdateFailureClaim {
    private static let maximumMarkerSize = 4 * 1_024

    static func claim(
        at markerURL: URL,
        containerID: String,
        afterClaim: (() throws -> Void)? = nil
    ) throws -> UInt32? {
        let lockURL = markerURL.appendingPathExtension("lock")
        let descriptor = Darwin.open(
            lockURL.path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, mode_t(0o600)
        )
        guard descriptor >= 0 else {
            throw EngineError(
                .internalError,
                "could not open compatibility resource failure lock: \(posixErrorDescription())"
            )
        }
        defer { Darwin.close(descriptor) }

        while flock(descriptor, LOCK_EX) != 0 {
            guard errno == EINTR else {
                throw EngineError(
                    .internalError,
                    "could not lock compatibility resource failure marker: \(posixErrorDescription())"
                )
            }
        }
        defer { _ = flock(descriptor, LOCK_UN) }

        let claimedURL = markerURL.deletingLastPathComponent().appending(
            path: ".\(markerURL.lastPathComponent).claim.\(UUID().uuidString)"
        )
        guard Darwin.renamex_np(markerURL.path, claimedURL.path, UInt32(RENAME_EXCL)) == 0 else {
            if errno == ENOENT { return nil }
            throw EngineError(
                .internalError,
                "could not atomically claim compatibility resource failure marker: \(posixErrorDescription())"
            )
        }
        do {
            try afterClaim?()
        } catch {
            try? restoreClaimedMarker(claimedURL, to: markerURL)
            throw EngineError(
                .internalError,
                "compatibility resource failure claim hook failed: \(error.localizedDescription)"
            )
        }

        let markerData: Data
        do {
            guard let data = try readRegularMarker(at: claimedURL) else {
                throw EngineError(.internalError, "claimed marker disappeared")
            }
            markerData = data
        } catch {
            let restoreError: Error?
            do {
                try restoreClaimedMarker(claimedURL, to: markerURL)
                restoreError = nil
            } catch {
                restoreError = error
            }
            throw EngineError(
                .internalError,
                "invalid compatibility resource failure marker: \(error.localizedDescription)"
                    + (restoreError.map { "; marker restoration failed: \($0.localizedDescription)" } ?? "")
            )
        }
        let marker: CompatibilityResourceUpdateFailureMarker
        do {
            marker = try JSONDecoder().decode(
                CompatibilityResourceUpdateFailureMarker.self,
                from: markerData
            )
        } catch {
            let restoreError: Error?
            do {
                try restoreClaimedMarker(claimedURL, to: markerURL)
                restoreError = nil
            } catch {
                restoreError = error
            }
            throw EngineError(
                .internalError,
                "invalid compatibility resource failure marker: \(error.localizedDescription)"
                    + (restoreError.map { "; marker restoration failed: \($0.localizedDescription)" } ?? "")
            )
        }
        guard !marker.containerID.isEmpty, marker.failureAfterWrites > 0 else {
            let restoreError: Error?
            do {
                try restoreClaimedMarker(claimedURL, to: markerURL)
                restoreError = nil
            } catch {
                restoreError = error
            }
            throw EngineError(
                .internalError,
                "invalid compatibility resource failure marker: containerID and failureAfterWrites are required"
                    + (restoreError.map { "; marker restoration failed: \($0.localizedDescription)" } ?? "")
            )
        }
        guard marker.containerID == containerID else {
            try restoreClaimedMarker(claimedURL, to: markerURL)
            return nil
        }
        guard Darwin.unlink(claimedURL.path) == 0 else {
            throw EngineError(
                .internalError,
                "could not consume compatibility resource failure marker: \(posixErrorDescription())"
            )
        }
        return marker.failureAfterWrites
    }

    private static func restoreClaimedMarker(_ claimedURL: URL, to markerURL: URL) throws {
        guard Darwin.renamex_np(claimedURL.path, markerURL.path, UInt32(RENAME_EXCL)) == 0 else {
            throw EngineError(
                .internalError,
                errno == EEXIST
                    ? "a replacement compatibility resource failure marker already exists"
                    : "could not restore compatibility resource failure marker: \(posixErrorDescription())"
            )
        }
    }

    private static func readRegularMarker(at markerURL: URL) throws -> Data? {
        let markerDescriptor = Darwin.open(
            markerURL.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
        )
        guard markerDescriptor >= 0 else {
            if errno == ENOENT { return nil }
            throw EngineError(
                .internalError,
                "could not safely open marker: \(posixErrorDescription())"
            )
        }
        defer { Darwin.close(markerDescriptor) }

        var status = stat()
        guard Darwin.fstat(markerDescriptor, &status) == 0 else {
            throw EngineError(.internalError, "could not inspect marker: \(posixErrorDescription())")
        }
        guard status.st_mode & S_IFMT == S_IFREG else {
            throw EngineError(.internalError, "marker is not a regular file")
        }
        guard status.st_size >= 0, status.st_size <= off_t(maximumMarkerSize) else {
            throw EngineError(
                .internalError,
                "marker exceeds the \(maximumMarkerSize)-byte size limit"
            )
        }

        var bytes = [UInt8](repeating: 0, count: maximumMarkerSize + 1)
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeMutableBytes { buffer in
                Darwin.read(
                    markerDescriptor,
                    buffer.baseAddress!.advanced(by: offset),
                    buffer.count - offset
                )
            }
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw EngineError(.internalError, "could not read marker: \(posixErrorDescription())")
            }
            offset += count
        }
        guard offset <= maximumMarkerSize else {
            throw EngineError(
                .internalError,
                "marker exceeds the \(maximumMarkerSize)-byte size limit"
            )
        }
        return Data(bytes.prefix(offset))
    }

    private static func posixErrorDescription() -> String {
        String(cString: strerror(errno))
    }
}

public actor RawVirtualizationBackend: ContainerBackend {
    enum VolumeStorageMode: String, Codable, Sendable { case block, shared }

    /// The canonical stopped preparation. Unlike a launch record this is a
    /// selection, not process ownership: it is replaced only after a complete
    /// preparation/replacement succeeds. Every spawned process remains owned
    /// independently beneath `shim-generations/` until verified dead.
    struct PreparedShimState: Codable, Sendable {
        static let currentSchemaVersion = 3

        let schemaVersion: Int
        let directoryIdentity: PersistentFileIdentity
        let artifacts: RawContainerPreparationArtifacts
        let currentContainer: ContainerRecord
        let specification: VMShimProtocol.Specification

        init(
            directoryIdentity: PersistentFileIdentity,
            artifacts: RawContainerPreparationArtifacts,
            currentContainer: ContainerRecord,
            specification: VMShimProtocol.Specification
        ) {
            schemaVersion = Self.currentSchemaVersion
            self.directoryIdentity = directoryIdentity
            self.artifacts = artifacts
            self.currentContainer = currentContainer
            self.specification = specification
        }
    }

    struct ResolvedExecContext: Equatable, Sendable {
        let environment: [String]
        let workingDirectory: String
        let user: GuestProtocol.User
        let noNewPrivileges: Bool
        let privileged: Bool
    }

    public static let defaultRootDiskBytes: UInt64 = 64 * 1_024 * 1_024 * 1_024
    public static let defaultVolumeDiskBytes = VolumeRecord.defaultSizeBytes
    public static let defaultStorageDiskBytes = VolumeRecord.defaultSizeBytes
    static let managementServerAddress = "100.64.0.1"
    private static let forcedStopWaitSeconds: Int64 = 5
    static let completedExecSnapshotPerExecBytes = 8 * 1_024 * 1_024
    static let completedExecSnapshotPerContainerBytes = 64 * 1_024 * 1_024
    static let completedExecSnapshotGlobalBytes = 256 * 1_024 * 1_024

    private let root: URL
    private let runtimeNamespace: VMShimRuntimeNamespace
    private let containersStateDirectory: PersistentStateDirectory
    private let deletedContainersStateDirectory: PersistentStateDirectory
    private let kernel: URL
    private let containerInitialRamdisk: URL
    private let diskBootstrapMetadata: GuestAssetInstaller.DiskBootstrapMetadata
    private let automaticNetworkPool: AutomaticNetworkPool
    private let store: OCIContentStore
    private let infrastructure: VMShimClient
    private let managedStorage: RawManagedStorageBackend?
    private let prepareCompatibility: ManagedPrepareCompatibilityCoordinator?
    private var recoveredStorageContainers = false
    private var serviceMaintenance = false
    private var serviceReplacementInProgress = false
    private var storageLossObserver: (@Sendable () async -> Void)?
    private var serviceGeneration = UUID()
    private var attachmentRetirementTasks: [UUID: Task<Void, Never>] = [:]
    private let serviceWork = RawServiceWorkTracker()
    private let nativeLaunchWork = RawServiceWorkTracker()
    private let destructiveTerminationWork = RawServiceWorkTracker()
    private var originalConsumerObservation: (operation: String, handle: VMShimClient.OriginalConsumerObservation)?
    private var serviceReplacements: [String: (StorageServiceTypes.ReplacementRequest, Task<BackendServiceReplacementResult, Error>)] = [:]
    private var serviceReplacementRetries: [String: ManagedStorageLifecycleOwner.RetryableReplacementTimeout] = [:]
    private let portForwarder = PortForwarder()
    private var shims: [String: VMShimClient] = [:]
    /// Launch can cross `Process.run()` before readiness and then fail to prove
    /// cleanup. Retain those generation-specific clients until containment or
    /// delete verifies termination; the registered shim dictionary alone is
    /// insufficient because readiness is what normally publishes into it.
    private var cleanupPendingShims: [String: [VMShimClient]] = [:]
    /// Fences the pre-spawn interval, before a durable generation record can
    /// prove ownership to a reentrant prepare call for the same container ID.
    private var freshPreparationInstances: [String: UUID] = [:]
    /// Generations with credible ownership evidence that cannot be safely
    /// adopted or killed. Any entry fences the entire container directory.
    private var quarantinedShimGenerations:
        [String: [VMShimClient.QuarantinedPersistentGeneration]] = [:]
    private var completions: [String: Int32] = [:]
    private var completionTasks: [String: (generation: RawBackendExecutionFence.Token, task: Task<Int32, Never>)] = [:]
    private var executionFence = RawBackendExecutionFence()
    private var portForwardingRegistrations: [String: (
        generation: RawBackendExecutionFence.Token,
        registration: PortForwarder.Registration
    )] = [:]
    private var networks: [String: NetworkRecord] = [:]
    private var networkVLANs: [String: UInt16] = [:]
    private var appliedNetworks: [String: Set<String>] = [:]
    private var activeContainers: [String: ContainerRecord] = [:]
    private var knownContainers: [String: ContainerRecord] = [:]
    private var bridges: [String: ContainerIOBridge] = [:]
    private var logMonitors: [String: ContainerLogMonitor] = [:]
    private var execBridges: [String: ContainerIOBridge] = [:]
    private var execMonitors: [String: ContainerLogMonitor] = [:]
    private var execShims: [String: VMShimClient] = [:]
    /// Runtime cleanup failures are tracked per exec so a later successful
    /// retirement cannot erase ownership of an unrelated failed cleanup.
    private var execArtifactCleanupFailures: [RawExecCleanupKey: String] = [:]
    private var execArtifactCleanupPreserveBridges: [RawExecCleanupKey: Bool] = [:]
    /// Startup recovery cannot infer that an active journal is only local
    /// debris while a selected VM may still own its guest process. These exact
    /// exec IDs must repeat guest containment before filesystem cleanup.
    private var recoveredExecContainmentFailures: Set<RawExecCleanupKey> = []
    private struct ExecOwner: Sendable, Equatable {
        let containerID: String
        let containerInstanceID: UUID
        let containerDirectoryIdentity: PersistentFileIdentity
    }
    private var execOwners: [String: ExecOwner] = [:]
    private var completedExecSnapshotBudget = RawCompletedExecSnapshotBudget(
        perExecBytes: completedExecSnapshotPerExecBytes,
        perContainerBytes: completedExecSnapshotPerContainerBytes,
        globalBytes: completedExecSnapshotGlobalBytes
    )
    private var execRetirementDeadlines: [String: UInt64] = [:]
    private static let execRetirementTimeoutMilliseconds: UInt64 = 3_000
    private static let execStartRequestTimeoutMilliseconds: UInt64 = 3_000
    private static let execStartNeverRanExitCode: Int32 = 125
    private var preparedBindSources: [String: [Int: PreparedBindSource]] = [:]
    private var volumeStorageModes: [String: VolumeStorageMode] = [:]
    private let sharedVolumeInitialization: SharedVolumeInitializationCoordinator
    private var containerDirectoryIdentities: [String: PersistentFileIdentity] = [:]

    public init(
        root: URL,
        kernel: URL,
        containerInitialRamdisk: URL,
        storageInitialRamdisk: URL,
        automaticNetworkPool: AutomaticNetworkPool = .default,
        sharedStorage: SharedStorageConfiguration? = nil,
        compatibilityStoreLock: CanonicalDataStoreLock? = nil
    ) async throws {
        let sharedStorage = try sharedStorage ?? ManagedStorageStartup.lifecycleConfiguration()
        guard let compatibilityStoreLock else {
            throw EngineError(.conflict, "lifecycle storage requires the held canonical data-store lock")
        }
        let dataRoot = root.standardizedFileURL.resolvingSymlinksInPath().standardizedFileURL
        guard Self.storeLockGuardsDataRoot(compatibilityStoreLock.root, dataRoot: dataRoot) else {
            throw EngineError(.conflict, "lifecycle storage requires the held canonical data-store lock")
        }
        let volumeNames = SharedVolumeInitializationCoordinator()
        sharedVolumeInitialization = volumeNames
        self.root = dataRoot
        self.kernel = kernel
        self.containerInitialRamdisk = containerInitialRamdisk
        let diskBootstrapMetadata = try GuestAssetInstaller.diskBootstrapMetadata(
            kernel: kernel,
            containerInitialRamdisk: containerInitialRamdisk,
            storageInitialRamdisk: storageInitialRamdisk
        )
        self.diskBootstrapMetadata = diskBootstrapMetadata
        // Authenticate assets and reject old/ambiguous stores before the first write.
        try diskBootstrapMetadata.requireLifecycleStorageSupport(policy: sharedStorage.policy)
        let lifecycleRoot = try await ManagedLifecycleStartupRoot.prepareForStartup(storeLock: compatibilityStoreLock)
        let dataDirectory = lifecycleRoot.directory
        try lifecycleRoot.validate()
        try await ManagedLifecycleStartup.preflight(root: dataDirectory)
        if let profile = diskBootstrapMetadata.prepareCompatibilityProfile {
            prepareCompatibility = try ManagedPrepareCompatibilityCoordinator(storeLock: compatibilityStoreLock, profile: profile)
        } else { prepareCompatibility = nil }
        self.automaticNetworkPool = automaticNetworkPool
        try lifecycleRoot.validate()
        let runtimeNamespace = try await ManagedLifecycleStartup.acquireRuntimeNamespace(root: lifecycleRoot)
        self.runtimeNamespace = runtimeNamespace
        try lifecycleRoot.validate()
        let infrastructureRoot = dataRoot.appending(path: "infrastructure", directoryHint: .isDirectory)
        containersStateDirectory = try lifecycleRoot.openOrCreateDirectory(named: "containers")
        deletedContainersStateDirectory = try lifecycleRoot.openOrCreateDirectory(named: "deleted-containers")
        try lifecycleRoot.validate()
        let volumesDirectory = try dataDirectory.openOrCreateDirectory(named: "volumes", permissions: 0o700)
        try lifecycleRoot.validate()
        let infrastructureDirectory = try dataDirectory.openOrCreateDirectory(named: "infrastructure", permissions: 0o700)
        try lifecycleRoot.validate(infrastructure: infrastructureDirectory)
        try RawDiskJournalDirectory.prepare(volumesDirectory, repairPermissions: false)
        try lifecycleRoot.validate(infrastructure: infrastructureDirectory)
        try RawDiskJournalDirectory.prepare(infrastructureDirectory, repairPermissions: false)
        try lifecycleRoot.validate(infrastructure: infrastructureDirectory)
        store = try OCIContentStore(root: dataRoot.appending(path: "content"))
        try lifecycleRoot.validate(infrastructure: infrastructureDirectory)
        let networkData = try dataDirectory.readRegularFile(named: "networks.json", required: false)
        if let data = networkData,
           let state = try? JSONDecoder().decode([String: NetworkState].self, from: data) {
            networks = state.mapValues(\.record)
            networkVLANs = state.mapValues(\.vlan)
        }
        let volumeStorageData = try dataDirectory.readRegularFile(named: "volume-storage.json", required: false)
        if let data = volumeStorageData,
           let state = try? JSONDecoder().decode([String: VolumeStorageMode].self, from: data) {
            volumeStorageModes = state
        }

        let networkNamespace = try lifecycleRoot.networkNamespace(in: infrastructureDirectory)
        let disk = infrastructureRoot.appending(path: "volumes.ext4")
        // Disk provisioning belongs to the ordered lifecycle startup.
        let infrastructureSpec = VMShimProtocol.Specification(
            kind: .storage,
            containerID: "cengine-storage",
            generation: 1,
            token: Self.randomToken(),
            kernelPath: kernel.path,
            initialRamdiskPath: storageInitialRamdisk.path,
            rootDiskPath: disk.path,
            rootDiskIdentity: nil,
            rootDiskSize: Self.defaultStorageDiskBytes,
            cpus: 2,
            memoryBytes: 1 * 1_024 * 1_024 * 1_024,
            macAddress: "02:ce:00:00:00:01",
            socketPath: try runtimeNamespace.makeSocketPath(),
            logPath: infrastructureRoot.appending(path: "shim.log").path,
            kernelArguments: [
                "cengine.management_address=\(Self.managementServerAddress)/10",
                "cengine.management_vlan=\(VMShimProtocol.managementVLAN)",
            ],
            networkSocketPath: try runtimeNamespace.makeSocketPath(),
            networkNamespace: networkNamespace,
            vlans: [VMShimProtocol.managementVLAN],
            // Allocated only after positive death proof and the block FD lease.
            shimLaunchUUID: nil,
            diskBootstrapVersion: 1,
            expectedInitramfsSHA256: diskBootstrapMetadata.expectedInitramfsSHA256(for: .storage)
        )
        try lifecycleRoot.validate(infrastructure: infrastructureDirectory)
        let startup = await ManagedLifecycleProductionStartup(retainedRoot: lifecycleRoot,
            infrastructureDirectory: infrastructureDirectory,
            installedHelperTeam: sharedStorage.installedHelperTeam, policy: sharedStorage.policy,
            diskSize: Self.defaultStorageDiskBytes,
            names: volumeNames, provenanceReference: diskBootstrapMetadata.storageInitramfsSHA256,
            specification: infrastructureSpec, compatibility: prepareCompatibility)
        try lifecycleRoot.validate(infrastructure: infrastructureDirectory)
        let started = try await startup.start()
        try lifecycleRoot.validate(infrastructure: infrastructureDirectory)
        infrastructure = started.shim
        managedStorage = started.backend
    }

    private func recoverPersistedContainers() async throws {
        guard !recoveredStorageContainers else { return }
        for name in try containersStateDirectory.reconciledEntryNames() {
            let directory = try containersStateDirectory.openDirectory(named: name)
            containerDirectoryIdentities[name] = directory.identity
            let prepared = try Self.loadPreparedShimState(
                from: directory, expectedContainerID: name
            )
            if let prepared, let managedStorage,
               try await managedStorage.hasIntents(containerID: name),
               try RawDeletedContainerCoordinator.hasReceipt(containerID: name, in: deletedContainersStateDirectory) {
                try RawDeletedContainerCoordinator.requireRecordedDeletion(of: prepared.currentContainer,
                    directoryIdentity: directory.identity, in: deletedContainersStateDirectory)
                // Whole-state history is deliberately retained for the next exact
                // native census; it is not a recoverable/public container anymore.
                continue
            }
            if let prepared {
                knownContainers[prepared.currentContainer.id] = prepared.currentContainer
                let ioDirectory = try directory.openDirectory(named: "io")
                guard ioDirectory.identity == prepared.artifacts.ioDirectoryIdentity else {
                    throw EngineError(.conflict, "container direct-I/O directory changed")
                }
                try RawContainerDirectIOHandles.cleanupGuestClaims(
                    RawContainerDirectIOHandles.containerGuestClaim(
                        instanceID: prepared.currentContainer.instanceID,
                        generation: prepared.specification.generation
                    ),
                    names: RawContainerPreparationArtifacts.directIOFileNames,
                    identities: prepared.artifacts.ioFileIdentities,
                    in: ioDirectory
                )
            }
            let launches = try VMShimClient.persistedLaunches(
                in: directory,
                expectedContainerID: name,
                expectedInstanceID: prepared?.currentContainer.instanceID
            )
            quarantinedShimGenerations[name] = launches.quarantined.isEmpty
                ? nil : launches.quarantined
            guard let containerID = prepared?.currentContainer.id
                ?? launches.first?.record.container.id else { continue }
            var ready: [(
                client: VMShimClient,
                record: VMShimClient.PersistentLaunchRecord,
                status: VMShimProtocol.Status
            )] = []
            for launch in launches {
                if let status = try? await launch.client.status() {
                    ready.append((launch.client, launch.record, status))
                    continue
                }
                do {
                    guard launch.client.ownsPersistedContainer(
                        id: name, directoryIdentity: directory.identity
                    ) else {
                        throw EngineError(.conflict, "recovered VM shim ownership mismatch")
                    }
                    try await launch.client.terminate()
                    if managedStorage == nil { try launch.client.removePersistentLaunchArtifacts() }
                } catch {
                    cleanupPendingShims[containerID, default: []].append(launch.client)
                }
            }
            // Only a generation named by the durable canonical preparation is
            // publishable. A newer ready process may have crashed between
            // readiness and the selection write; it remains independently
            // owned, but must be contained rather than implicitly committed.
            let selected = ready.first { launch in
                guard let prepared else { return false }
                return Self.launchRecordMatchesPrepared(
                    launch.record, prepared: prepared
                )
            }
            if let selected {
                if selected.client.specification.workloadStorageMode == .managed {
                    guard selected.status.state == .running else {
                        throw EngineError(.conflict, "managed workload is not eligible for live adoption")
                    }
                    guard let managedStorage, let container = prepared?.currentContainer,
                          try await managedStorage.permitsLiveRecovery(container: container, shim: selected.client) else {
                        throw EngineError(.conflict, "managed workload has no sealed live adoption proof")
                    }
                }
                shims[containerID] = selected.client
                knownContainers[containerID] = prepared?.currentContainer
            }
            for launch in ready where launch.client !== selected?.client {
                do {
                    guard launch.client.ownsPersistedContainer(
                        id: name, directoryIdentity: directory.identity
                    ) else {
                        throw EngineError(.conflict, "recovered VM shim ownership mismatch")
                    }
                    try await launch.client.terminate()
                    if managedStorage == nil { try launch.client.removePersistentLaunchArtifacts() }
                } catch {
                    cleanupPendingShims[containerID, default: []].append(launch.client)
                }
            }
            guard let prepared else { continue }
            let activeExecIDs = try RawExecArtifactJournal.activeRecords(
                containerID: containerID,
                in: directory,
                artifacts: prepared.artifacts
            ).map(\.execID)
            guard !activeExecIDs.isEmpty else { continue }

            let unresolvedGenerationOwnership = !(launches.quarantined.isEmpty)
                || !(cleanupPendingShims[containerID] ?? []).isEmpty
            let guestContainmentAvailable: Bool?
            if unresolvedGenerationOwnership {
                guestContainmentAvailable = nil
            } else if let selected {
                switch selected.status.state {
                case .created, .starting, .running, .paused:
                    guestContainmentAvailable = true
                case .stopping, .stopped, .failed:
                    guestContainmentAvailable = false
                }
            } else {
                // Every persisted generation was either absent or terminated
                // successfully, proving there is no surviving guest process.
                guestContainmentAvailable = false
            }
            let recovery = await RawRecoveredExecCoordinator.run(
                execIDs: activeExecIDs,
                guestContainmentAvailable: guestContainmentAvailable,
                contain: { execID in
                    guard let selected else {
                        throw EngineError(.conflict, "selected VM shim disappeared")
                    }
                    _ = try await Self.containAndDiscardGuestExec(
                        shim: selected.client,
                        execID: execID,
                        deadlineNanoseconds: Self.execDeadline(
                            afterMilliseconds: Self.execRetirementTimeoutMilliseconds
                        )
                    )
                },
                cleanup: { execID in
                    try RawExecArtifactTransaction.cleanup(
                        containerID: containerID,
                        execID: execID,
                        in: directory,
                        artifacts: prepared.artifacts
                    )
                }
            )
            for (execID, message) in recovery.failures {
                let key = RawExecCleanupKey(
                    exec: ExecRecord(
                        id: execID,
                        containerID: containerID,
                        containerInstanceID: prepared.currentContainer.instanceID,
                        configuration: .init(arguments: ["true"])
                    ),
                    containerDirectoryIdentity: prepared.directoryIdentity
                )
                execArtifactCleanupFailures[key] = message
            }
            for execID in recovery.guestContainmentRequired {
                recoveredExecContainmentFailures.insert(RawExecCleanupKey(
                    exec: ExecRecord(
                        id: execID,
                        containerID: containerID,
                        containerInstanceID: prepared.currentContainer.instanceID,
                        configuration: .init(arguments: ["true"])
                    ),
                    containerDirectoryIdentity: prepared.directoryIdentity
                ))
            }
        }
        recoveredStorageContainers = true
    }

    public func reconcileStorage(volumes: [VolumeRecord], containers: [ContainerRecord]) async throws {
        if let managedStorage {
            try await managedStorage.reconcile(volumes: volumes, containers: containers)
            try await recoverPersistedContainers()
            await managedStorage.observeRetirements({ [weak self] containerID, launch in
                await self?.managedAttachmentRetired(containerID: containerID, launch: launch)
            }, serviceLost: { [weak self] in await self?.managedServiceLost() })
        }
    }

    public func observeManagedStorageLoss(_ observer: @escaping @Sendable () async -> Void) async {
        storageLossObserver = observer
        if serviceMaintenance { await observer() }
    }

    public func fenceManagedStorageService() async { fenceServiceWork(containers: []) }

    private func managedServiceLost() async {
        fenceServiceWork(containers: [])
        await storageLossObserver?()
    }

    /// Only the signed, FD-pinned production replacement claim can reach Arm.
    /// The original configured receipt is retained at successful runtime start.
    private func prepareOriginalConsumerObservation(_ claim: ManagedPrepareCompatibilityQueue.OriginalClaim,
        request: StorageServiceTypes.ReplacementRequest) async throws -> VMShimClient.OriginalConsumerObservation {
        // Preflight runs before the lifecycle owner's observation cursor exists.
        // Keep its finite stage through awaits so failures here reach both receipts
        // without changing admission, the original deadline, or cleanup ownership.
        var stage = OriginalConsumerFailureDiagnostic.Stage.preflightIdentity
        do {
            _ = try SignedCompatibilityIdentity.current(role: .engine)
            guard let managedStorage, let compatibility = prepareCompatibility,
                  compatibility.profile == ManagedPrepareCompatibilityProtocol.fullProfile,
                  originalConsumerObservation == nil,
                  let shim = shims[claim.request.container] else { throw OriginalConsumerObservationProtocol.Failure.invalid }
            let epoch = serviceGeneration
            let deadline = OriginalConsumerPreflightDeadline()
            let generation = shim.specification.generation
            guard let launch = shim.specification.shimLaunchUUID else {
                throw OriginalConsumerObservationProtocol.Failure.invalid
            }
            let captured = OriginalConsumerPreflightIdentity(serviceGeneration: epoch, shimGeneration: generation,
                launch: launch, instance: claim.request.containerInstance)
            func check() throws {
                _ = try deadline.remaining()
                guard let currentLaunch = shim.specification.shimLaunchUUID else {
                    throw OriginalConsumerObservationProtocol.Failure.invalid
                }
                let current = OriginalConsumerPreflightIdentity(serviceGeneration: serviceGeneration,
                    shimGeneration: shim.specification.generation, launch: currentLaunch,
                    instance: knownContainers[claim.request.container]?.instanceID.uuidString.lowercased() ?? "")
                try OriginalConsumerPreflightIdentity.requireMatch(captured, current,
                    captured: shim, currentClient: shims[claim.request.container])
            }
            stage = .preflightFreeze
            // Close ordinary admission BEFORE hopping to the notification actor.
            serviceWork.close(); nativeLaunchWork.close()
            let managedEpoch = try await managedStorage.freezeOriginalConsumerWork()
            try check()
            stage = .preflightJoin
            try await managedStorage.joinOriginalConsumerWork(managedEpoch, deadline: deadline)
            try check()
            // Whole notification callbacks have returned, including any callback
            // that entered its destructive lane after we requested cancellation.
            try await nativeLaunchWork.join(timeout: deadline.remaining()); try check()
            try await serviceWork.join(timeout: deadline.remaining()); try check()
            destructiveTerminationWork.close()
            try await destructiveTerminationWork.join(timeout: deadline.remaining()); try check()
            for task in attachmentRetirementTasks.values { await task.value; try check() }
            try destructiveTerminationWork.requireQuiescent()
            stage = .preflightBinding
            let binding = try await managedStorage.originalRuntimeBinding(claim.request, replacement: request, shim: shim)
            try check(); try destructiveTerminationWork.requireQuiescent()
            // Arm itself checks the actual installed RUNNING machine and mounted
            // positive through its bounded signed exchange, not an unbounded status RPC.
            stage = .preflightCandidate
            try compatibility.originalCandidate(.init(request: claim.request, binding: binding, ownerRequest: request), claim: claim)
            stage = .preflightArm
            let observation = try await managedStorage.armOriginalRuntime(binding,
                request: claim.request, replacement: request, shim: shim)
            // Store before any further throwing checks so every failed arm path releases.
            originalConsumerObservation = (request.operationUUID, observation)
            stage = .preflightArmReturn
            try check(); try destructiveTerminationWork.requireQuiescent()
            guard try await managedStorage.originalRuntimeBinding(claim.request, replacement: request, shim: shim) == binding
            else { throw OriginalConsumerObservationProtocol.Failure.invalid }
            try check(); try destructiveTerminationWork.requireQuiescent()
            stage = .preflightArmedPublication
            try compatibility.originalPublish(binding, phase: .armed, claim: claim)
            if binding.caseName.isWritableFD || binding.caseName.isRoot {
                // Stay inside the ORIGINAL preflight budget. Ordinary exec admission
                // remains closed: the independent reader was started before capture
                // and is triggered only over its already-owned bounded stream.
                while true {
                    stage = .preflightBaselineWait
                    try Task.checkCancellation(); try check()
                    if let baseline = try compatibility.originalBaseline(binding: binding, claim: claim) {
                        stage = .preflightBaselineValidation
                        try await managedStorage.validateOriginalBaseline(baseline)
                        try check(); try destructiveTerminationWork.requireQuiescent()
                        guard try await managedStorage.originalRuntimeBinding(claim.request, replacement: request, shim: shim) == binding
                        else { throw OriginalConsumerObservationProtocol.Failure.invalid }
                        try check()
                        stage = .preflightBaselineRecord
                        try await observation.recordBackingBaseline(baseline)
                        try check(); try destructiveTerminationWork.requireQuiescent()
                        stage = .preflightBaselinePublication
                        try compatibility.originalPublish(baseline, phase: .baselineAccepted, claim: claim)
                        break
                    }
                    try await Task.sleep(for: min(.milliseconds(10), deadline.remaining()))
                }
            }
            return observation
        } catch { throw OriginalConsumerFailureDiagnostic.annotate(error, at: stage) }
    }

    public func validateManagedStorageReplacement(_ request: StorageServiceTypes.ReplacementRequest) async throws {
        guard let managedStorage else { throw RawManagedStorageBackend.failure() }
        try await managedStorage.validateServiceReplacement(request)
    }

    public func validateManagedStorageAvailability(_ scope: StorageServiceTypes.Scope) async throws {
        let epoch = serviceGeneration
        try requireServiceGeneration(epoch)
        guard let managedStorage else { throw RawManagedStorageBackend.failure() }
        do { try await managedStorage.validateServiceAvailability(scope) }
        catch ManagedStorageControlFailure.serviceUnavailable {
            if serviceGeneration == epoch { await managedServiceLost() }
            throw ManagedStorageControlFailure.serviceUnavailable
        }
        try requireServiceGeneration(epoch)
    }

    public func replaceManagedStorageService(_ request: StorageServiceTypes.ReplacementRequest,
        volumes: [VolumeRecord], containers: [ContainerRecord]) async throws -> BackendServiceReplacementResult {
        let retrying: Bool
        if let (original, task) = serviceReplacements[request.operationUUID] {
            guard original == request else { throw RawManagedStorageBackend.failure("replacement request changed") }
            guard let retry = serviceReplacementRetries[request.operationUUID], retry.request == request else {
                return try await task.value
            }
            retrying = true
        } else { retrying = false }
        guard let managedStorage, retrying || !serviceReplacementInProgress else { throw RawManagedStorageBackend.failure() }
        if !retrying {
            try await managedStorage.validateServiceReplacement(request)
            guard !serviceReplacementInProgress else { throw RawManagedStorageBackend.failure() }
        }
        serviceReplacementRetries.removeValue(forKey: request.operationUUID)
        serviceReplacementInProgress = true
        // Retain the entire preflight + fault + release + containment operation.
        let task = Task {
            var claim: ManagedPrepareCompatibilityQueue.OriginalClaim?
            var replacementEntered = false
            do {
                claim = try self.prepareCompatibility?.originalCapture(request)
                let observation: VMShimClient.OriginalConsumerObservation?
                if let claim { observation = try await self.prepareOriginalConsumerObservation(claim, request: request) }
                else { observation = nil }
                self.fenceServiceWork(containers: containers)
                replacementEntered = true
                let result = try await managedStorage.replaceService(request, volumes: volumes, containers: containers,
                    observation: observation, originalClaim: claim, compatibility: self.prepareCompatibility) {
                    try await self.containServiceExecutions(containers: containers)
                }
                try await OriginalConsumerFailureDiagnostic.step(claim != nil ? .resultPublication : nil) {
                    if let claim, let compatibility = self.prepareCompatibility {
                        if claim.request.caseName.isRoot {
                            let evidence = try await managedStorage.rootEvidence(operationUUID: request.operationUUID)
                            try compatibility.originalPublish(evidence, phase: .result, claim: claim)
                        } else {
                            let evidence = try await managedStorage.originalEvidence(operationUUID: request.operationUUID)
                            try compatibility.originalPublish(OriginalConsumerRuntimeCarrier.Result(evidence), phase: .result, claim: claim)
                        }
                    }
                }
                self.originalConsumerObservation = nil
                try OriginalConsumerFailureDiagnostic.step(claim != nil ? .workReopen : nil) {
                    if claim != nil { try self.destructiveTerminationWork.reopen() }
                    try self.nativeLaunchWork.reopen()
                    try self.serviceWork.reopen()
                }
                self.serviceMaintenance = false; self.serviceReplacementInProgress = false
                await managedStorage.observeRetirements({ [weak self] containerID, launch in
                    await self?.managedAttachmentRetired(containerID: containerID, launch: launch)
                }, serviceLost: { [weak self] in await self?.managedServiceLost() })
                return result
            } catch {
                let failure = error
                if let claim, let compatibility = self.prepareCompatibility {
                    try? compatibility.originalPublish(OriginalConsumerRuntimeCarrier.Failed(requestID: claim.request.requestID,
                        diagnostic: OriginalConsumerFailureDiagnostic.find(in: failure)), phase: .failed, claim: claim)
                }
                // RawManaged owns post-entry cleanup; preflight has not killed a
                // worker, but must still release and run normal full containment.
                if !replacementEntered {
                    self.fenceServiceWork(containers: containers)
                    await managedStorage.fenceOriginalConsumerFailure()
                    return try await OriginalConsumerCleanup.run(operation: { throw failure }, release: {
                        if let observation = self.originalConsumerObservation { _ = try await observation.handle.release() }
                        self.originalConsumerObservation = nil
                    }, contain: { _ = try await self.containServiceExecutions(containers: containers, nativeTimeout: .zero) })
                }
                if let retry = failure as? ManagedStorageLifecycleOwner.RetryableReplacementTimeout,
                   retry.request == request {
                    self.serviceReplacementRetries[request.operationUUID] = retry
                }
                throw failure
            }
        }
        serviceReplacements[request.operationUUID] = (request, task)
        return try await task.value
    }

    private func fenceServiceWork(containers: [ContainerRecord]) {
        guard !serviceMaintenance else { return }
        serviceWork.close(); nativeLaunchWork.close()
        serviceMaintenance = true; serviceGeneration = UUID()
        let ids = Set(containers.map(\.id)).union(knownContainers.keys).union(shims.keys)
            .union(cleanupPendingShims.keys).union(freshPreparationInstances.keys).union(quarantinedShimGenerations.keys)
        for id in ids {
            _ = executionFence.replace(id)
            completionTasks.removeValue(forKey: id)?.task.cancel()
            activeContainers.removeValue(forKey: id)
            if let registration = portForwardingRegistrations.removeValue(forKey: id) {
                portForwarder.stop(containerID: id, registration: registration.registration)
            }
            try? logMonitors.removeValue(forKey: id)?.stop()
            try? bridges[id]?.finishInput(); bridges[id]?.finishOutput()
        }
        for (id, owner) in execOwners where ids.contains(owner.containerID) {
            try? execMonitors.removeValue(forKey: id)?.stop()
            try? execBridges[id]?.finishInput(); execBridges[id]?.finishOutput()
        }
    }

    private func containServiceExecutions(containers: [ContainerRecord],
        nativeTimeout: Duration = .seconds(30)) async throws -> Set<String> {
        // Also used on failed preflight/observation: worker death is not assumed.
        // Join the narrow native publisher before a full census. If that join
        // fails, still terminate exact known handles without retiring artifacts,
        // clearing unknown launch ownership, or claiming complete containment.
        try await RawServiceContainment.run(native: nativeLaunchWork, work: serviceWork,
            nativeTimeout: nativeTimeout, containKnown: { try await self.containKnownServiceExecutions() },
            contain: { _ = try await self.censusServiceExecutions(containers: containers, retireArtifacts: false) },
            joinManaged: { try await self.managedStorage?.joinServiceReplacementWork() },
            census: { try await self.censusServiceExecutions(containers: containers, retireArtifacts: true) })
    }

    private func containKnownServiceExecutions() async throws {
        // Do not discover/overwrite launch ownership while its publisher is still
        // unresolved. Each captured client retains its exact native identity;
        // even successful termination here leaves all ownership maps fenced.
        var seen = Set<String>()
        let owners = (Array(shims.values) + cleanupPendingShims.values.flatMap { $0 })
            .filter { seen.insert($0.persistentOwnershipKey).inserted }
        try await RawServiceContainment.containKnown(owners: owners) { shim in
            let lease = self.destructiveTerminationWork.retainDestructiveWork()
            defer { self.destructiveTerminationWork.end(lease) }
            try await shim.terminate()
        }
    }

    /// Fail closed on disposal claims, including roots renamed out of their ID.
    /// Never reconcile (delete) them or silently omit them from the native census.
    static func serviceExecutionCensus(in directory: PersistentStateDirectory) throws -> Set<String> {
        let names = try directory.entryNames()
        guard !names.contains(where: { $0.hasPrefix(".cengine-disposal-") || $0.hasPrefix(".cengine-remove-") }) else {
            throw EngineError(.conflict, "raw service census has unresolved disposal ownership")
        }
        guard names.allSatisfy({ $0.count == 64 && $0.allSatisfy(\.isHexDigit) }) else {
            throw EngineError(.conflict, "raw service census has unknown container entries")
        }
        return Set(names)
    }

    private func censusServiceExecutions(containers: [ContainerRecord], retireArtifacts: Bool) async throws -> Set<String> {
        let ids = try Self.serviceExecutionCensus(in: containersStateDirectory)
            .union(shims.keys).union(cleanupPendingShims.keys).union(quarantinedShimGenerations.keys)
        for id in ids.sorted() {
            try await terminateEveryShim(for: id,
                expectedInstanceID: containers.first(where: { $0.id == id })?.instanceID)
            if retireArtifacts {
                let directory = try containerStateDirectory(for: id)
                if let prepared = try Self.loadPreparedShimState(from: directory, expectedContainerID: id) {
                    for (execID, owner) in execOwners where owner.containerID == id {
                        guard owner.containerInstanceID == prepared.currentContainer.instanceID,
                              owner.containerDirectoryIdentity == directory.identity else { throw RawManagedStorageBackend.failure() }
                        try execMonitors.removeValue(forKey: execID)?.stop()
                        freezeExecBridge(execID: execID, preserveBridge: true)
                        execShims.removeValue(forKey: execID)
                        execRetirementDeadlines.removeValue(forKey: execID)
                    }
                    try Self.retireContainedExecArtifacts(containerID: id, in: directory, artifacts: prepared.artifacts)
                    clearExecArtifactCleanupFailures(for: prepared.currentContainer)
                }
            }
        }
        // This is the complete contained census, NOT newly-exited containers.
        // Engine filters its pre-maintenance running/paused records for events.
        return ids
    }

    static func retireContainedExecArtifacts(containerID: String, in directory: PersistentStateDirectory,
        artifacts: RawContainerPreparationArtifacts) throws {
        for record in try RawExecArtifactJournal.activeRecords(containerID: containerID, in: directory, artifacts: artifacts) {
            try RawExecArtifactTransaction.cleanup(containerID: containerID, execID: record.execID,
                in: directory, artifacts: artifacts)
        }
    }

    private func requireServiceGeneration(_ generation: UUID) throws {
        guard !serviceMaintenance, serviceGeneration == generation else { throw RawManagedStorageBackend.failure() }
    }

    public func synchronizeVolumes(_ volumes: [VolumeRecord]) async throws {
        try await managedStorage?.synchronize(volumes)
    }

    public func deleteVolume(_ volume: VolumeRecord) async throws {
        let workLease = try serviceWork.begin()
        defer { serviceWork.end(workLease) }
        if let managedStorage {
            let disk = try volumeDiskURL(name: volume.name)
            try await managedStorage.delete(volume)
            try serviceWork.require(workLease)
            try Self.removeVolumeDisk(at: disk)
            var modes = volumeStorageModes
            modes.removeValue(forKey: volume.name)
            try JSONEncoder().encode(modes).write(to: root.appending(path: "volume-storage.json"), options: .atomic)
            volumeStorageModes = modes
            return
        }
        try await deleteVolume(volume.name)
    }

    private func managedAttachmentRetired(containerID: String, launch: String) async {
        let id = UUID()
        let task = Task { await self.performManagedAttachmentRetired(containerID: containerID, launch: launch) }
        attachmentRetirementTasks[id] = task
        await task.value // Positive join, not cancellation or a generation flag.
        attachmentRetirementTasks.removeValue(forKey: id)
    }

    private func performManagedAttachmentRetired(containerID: String, launch: String) async {
        let epoch = serviceGeneration
        guard !serviceMaintenance, let shim = shims[containerID], shim.specification.shimLaunchUUID == launch else { return }
        // A notification is a containment hint, not a drain receipt. Retire uses
        // exact authority replies; no unrelated container generation is touched.
        _ = executionFence.replace(containerID)
        activeContainers.removeValue(forKey: containerID)
        if let registration = portForwardingRegistrations.removeValue(forKey: containerID) {
            portForwarder.stop(containerID: containerID, registration: registration.registration)
        }
        // Even unknown authority state requires positive VM containment. Failure
        // to obtain a drain receipt must not skip stopping this exact launch.
        do { try await managedStorage?.retire(containerID: containerID, launch: launch) } catch { }
        guard shims[containerID] === shim, shim.specification.shimLaunchUUID == launch else { return }
        if epoch != serviceGeneration || serviceMaintenance {
            // Maintenance cannot erase a callback that crossed retire's await.
            // Retain its exact launch and STILL join destructive containment.
            retainCleanupPendingShim(shim, for: containerID)
        }
        do { try await terminateShim(containerID, shim: shim) }
        catch {
            guard epoch == serviceGeneration, !serviceMaintenance else { return }
            retainCleanupPendingShim(shim, for: containerID)
        }
    }

    /// The store lock records the physical path (`realpath`, so `/private/var/…`),
    /// while the data root is Foundation's canonical form, which drops the
    /// `/private` prefix. Compare both in the data root's canonical form so a
    /// temporary-directory store is recognized as the lock's own store.
    static func storeLockGuardsDataRoot(_ lockRoot: URL, dataRoot: URL) -> Bool {
        lockRoot.standardizedFileURL.resolvingSymlinksInPath().standardizedFileURL == dataRoot.standardizedFileURL
    }

    static func canonicalDataRoot(_ requested: URL) throws -> URL {
        let standardized = requested.standardizedFileURL
        try FileManager.default.createDirectory(
            at: standardized, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
        )
        let canonical = standardized.resolvingSymlinksInPath().standardizedFileURL
        _ = try PersistentStateDirectory.open(canonical)
        return canonical
    }

    public func shutdown() async {
        // Shims own running VMs. Daemon shutdown intentionally only drops control connections.
        portForwarder.stopAll()
        portForwardingRegistrations.removeAll()
        for monitor in logMonitors.values { try? monitor.stop(finishOutput: false) }
        logMonitors.removeAll()
        for monitor in execMonitors.values { try? monitor.stop(finishOutput: false) }
        execMonitors.removeAll()
    }

    /// Explicit, non-destructive ownership reconciliation. It never adopts a
    /// foreign executable or deletes a quarantined entry; callers may retry
    /// after durable generation evidence is repaired, and normal lifecycle
    /// work remains fenced until then.
    func reconcileQuarantinedShimOwnership(
        for container: ContainerRecord
    ) throws -> [VMShimClient.QuarantinedPersistentGeneration] {
        let directory = try containerStateDirectory(for: container.id)
        let enumeration = try VMShimClient.persistedLaunches(
            in: directory,
            expectedContainerID: container.id,
            expectedInstanceID: container.instanceID
        )
        quarantinedShimGenerations[container.id] = enumeration.quarantined.isEmpty
            ? nil : enumeration.quarantined
        return enumeration.quarantined
    }

    public func pullImage(_ reference: String, platform: String) async throws {
        _ = try await pull(reference, platform: platform, credentials: nil) { _ in }
    }

    public func pullImage(_ reference: String, platform: String, credentials: RegistryCredentials?, progress: @escaping ImagePullProgressHandler) async throws {
        _ = try await pull(reference, platform: platform, credentials: credentials, progress: progress)
    }

    public func listImages() async throws -> [BackendImage]? { try await store.summaries() }

    public func deleteImage(reference: String) async throws {
        try await store.remove(reference: reference)
        _ = try await store.prune()
    }

    public func deleteImage(reference: String, platforms: [OCIPlatform]) async throws -> [String] {
        let removed = try await store.remove(reference: reference, platforms: platforms)
        _ = try await store.prune()
        return removed
    }

    public func tagImage(existing: String, new: String) async throws {
        guard let descriptor = await store.descriptor(for: existing) else { throw EngineError(.notFound, "image \(existing) not found") }
        try await store.tag(descriptor, as: new)
    }

    public func loadImages(fromOCILayout directory: URL) async throws -> [BackendImage] { try await store.importLayout(directory) }

    public func loadImages(fromOCILayout directory: URL, platforms: [OCIPlatform]) async throws -> [BackendImage] {
        try await store.importLayout(directory, platforms: platforms)
    }

    public func saveImages(references: [String], platform: String) async throws -> Data {
        try await store.exportLayout(references: references, platforms: [try OCIPlatform(platform)])
    }

    public func saveImages(references: [String], platforms: [OCIPlatform]) async throws -> Data {
        try await store.exportLayout(references: references, platforms: platforms)
    }

    public func saveImages(
        references: [String], platforms: [OCIPlatform], to destination: URL
    ) async throws {
        try await store.exportLayout(
            references: references, platforms: platforms, to: destination
        )
    }

    public func pushImage(reference: String, platform: String, credentials: RegistryCredentials?) async throws {
        try await store.push(reference: reference, platform: try OCIPlatform(platform), credentials: credentials)
    }

    public func pushImage(reference: String, platform: OCIPlatform?, credentials: RegistryCredentials?) async throws {
        try await store.push(reference: reference, platform: platform, credentials: credentials)
    }

    public func imageHistory(reference: String, platform: String) async throws -> [ImageHistoryEntry] {
        try await store.history(reference: reference, platform: try OCIPlatform(platform))
    }

    public func imageHistory(reference: String, platform: OCIPlatform?) async throws -> [ImageHistoryEntry] {
        try await store.history(reference: reference, platform: platform)
    }

    public func imageAttestations(reference: String, platform: OCIPlatform?, predicateTypes: [String], includeStatement: Bool) async throws -> [ImageAttestationRecord] {
        try await store.attestations(
            reference: reference,
            platform: platform,
            predicateTypes: predicateTypes,
            includeStatement: includeStatement
        )
    }

    public func prepare(_ container: ContainerRecord) async throws {
        let workLease = try serviceWork.begin()
        defer { serviceWork.end(workLease) }
        let epoch = serviceGeneration
        try requireServiceGeneration(epoch)
        try await managedStorage?.requireReconciled()
        try serviceWork.require(workLease)
        try requireExactContainerOwnership(container)
        // Publish the new cleanup proof before consuming an older deletion
        // receipt so a crash between the two operations never leaves a gap.
        try RawContainerPreparationAttemptCoordinator.begin(
            container,
            in: containersStateDirectory,
            attempts: deletedContainersStateDirectory
        )
        try RawDeletedContainerCoordinator.clearForPreparation(
            of: container,
            in: containersStateDirectory,
            receipts: deletedContainersStateDirectory
        )
        if shims[container.id] != nil {
            if knownContainers[container.id] == nil {
                try requireServiceGeneration(epoch)
        knownContainers[container.id] = container
            }
            return
        }
        if try await relaunchPreparedShim(container) != nil { return }
        try requireServiceGeneration(epoch)
        guard freshPreparationInstances[container.id] == nil else {
            throw BackendResourceRollbackIncompleteError(
                "container \(container.id) already has a fresh VM preparation in progress"
            )
        }
        freshPreparationInstances[container.id] = container.instanceID
        defer {
            if freshPreparationInstances[container.id] == container.instanceID {
                freshPreparationInstances.removeValue(forKey: container.id)
            }
        }
        let image = try await resolvedImage(container.image, platform: container.platform)
        try requireServiceGeneration(epoch)
        let stateDirectory = try freshContainerStateDirectory(for: container)
        let directory = stateDirectory.url
        let containerDirectoryIdentity = stateDirectory.identity
        try RawContainerPreparationAttemptCoordinator.bind(
            container,
            directoryIdentity: containerDirectoryIdentity,
            in: deletedContainersStateDirectory
        )
        let preparation: (
            artifacts: RawContainerPreparationArtifacts,
            bindSources: [Int: PreparedBindSource],
            specification: VMShimProtocol.Specification
        )
        do {
            let artifacts = try RawContainerPreparationArtifacts.create(
                in: stateDirectory, rootDiskSize: Self.defaultRootDiskBytes
            )
            try requireServiceGeneration(epoch)
        let bindSources = try HostBindSourceResolver(
                root: root.appending(path: "bind-sources")
            ).resolve(container.mounts)
            let specification = try containerShimSpecification(
                container,
                directory: directory,
                artifacts: artifacts,
                bindSources: bindSources,
                generation: try nextShimGeneration(in: directory),
                volumeDisks: []
            )
            try artifacts.validate(in: stateDirectory)
            preparation = (artifacts, bindSources, specification)
        } catch {
            try requireServiceGeneration(epoch)
            let preparationError = error
            do {
                try RawDiskJournalDirectory.requireSafeAutomaticRootDisposal(stateDirectory)
                try RawContainerPreparationAttemptCoordinator.recordContainedCleanup(
                    container,
                    directoryIdentity: containerDirectoryIdentity,
                    in: deletedContainersStateDirectory
                )
                try disposeContainerDirectory(
                    container.id, expectedIdentity: containerDirectoryIdentity
                )
            } catch {
            try requireServiceGeneration(epoch)
                throw BackendResourceRollbackIncompleteError(
                    "container VM preparation setup failed: "
                        + "\(EngineError.message(for: preparationError)); writable root cleanup failed: "
                        + EngineError.message(for: error)
                )
            }
            throw preparationError
        }
        preparedBindSources[container.id] = preparation.bindSources
        let shim: VMShimClient
        do {
            try preparation.artifacts.validate(in: stateDirectory)
            shim = try await launchTrackedShim(
                preparation.specification,
                container: container,
                expectedLogIdentity: preparation.artifacts.shimLogIdentity
            )
        } catch {
            try requireServiceGeneration(epoch)
            let launchError = error
            do {
                try await terminateEveryShim(for: container.id)
                try requireServiceGeneration(epoch)
                try RawDiskJournalDirectory.requireSafeAutomaticRootDisposal(stateDirectory)
                try RawContainerPreparationAttemptCoordinator.recordContainedCleanup(
                    container,
                    directoryIdentity: containerDirectoryIdentity,
                    in: deletedContainersStateDirectory
                )
                preparedBindSources.removeValue(forKey: container.id)
                try disposeContainerDirectory(
                    container.id, expectedIdentity: containerDirectoryIdentity
                )
            } catch {
            try requireServiceGeneration(epoch)
                throw BackendResourceRollbackIncompleteError(
                    "container VM preparation launch failed: \(EngineError.message(for: launchError)); "
                        + "partial shim cleanup failed: \(EngineError.message(for: error))"
                )
            }
            throw launchError
        }
        try requireServiceGeneration(epoch)
        retainCleanupPendingShim(shim, for: container.id)
        do {
            try preparation.artifacts.validate(in: stateDirectory)
            if shim.specification.workloadStorageMode == .managed { _ = try await shim.bootWorkloadStorage() }
            else { _ = try await shim.boot() }
            try requireServiceGeneration(epoch)
            try await shim.prepareRootFS(contentStorePath: root.appending(path: "content").path, layers: image.manifest.layers)
            try requireServiceGeneration(epoch)
            _ = try await shim.stop()
            try requireServiceGeneration(epoch)
            try persistPreparedShimState(
                container: container,
                specification: preparation.specification,
                artifacts: preparation.artifacts,
                expectedDirectoryIdentity: containerDirectoryIdentity
            )
            removeCleanupPendingShim(shim, for: container.id)
            try requireServiceGeneration(epoch)
            shims[container.id] = shim
            try requireServiceGeneration(epoch)
        knownContainers[container.id] = container
        } catch {
            try requireServiceGeneration(epoch)
            let preparationError = error
            try await PreparedShimFailureRecovery.perform(
                preparationError: preparationError,
                terminateEveryGeneration: {
                    try await self.terminateEveryShim(for: container.id)
                },
                discardWritableRoot: {
                    try self.requireServiceGeneration(epoch)
                    try RawDiskJournalDirectory.requireSafeAutomaticRootDisposal(stateDirectory)
                    try RawContainerPreparationAttemptCoordinator.recordContainedCleanup(
                        container,
                        directoryIdentity: containerDirectoryIdentity,
                        in: self.deletedContainersStateDirectory
                    )
                    preparedBindSources.removeValue(forKey: container.id)
                    try self.disposeContainerDirectory(
                        container.id, expectedIdentity: containerDirectoryIdentity
                    )
                }
            )
        }
    }

    public func start(_ container: ContainerRecord) async throws -> [PortBinding] {
        let workLease = try serviceWork.begin()
        defer { serviceWork.end(workLease) }
        try await managedStorage?.requireReconciled()
        try serviceWork.require(workLease)
        try requireExactContainerOwnership(container)
        guard knownContainers[container.id]?.instanceID == container.instanceID else {
            throw BackendResourceRollbackIncompleteError(
                "container \(container.id) VM preparation belongs to a different instance"
            )
        }
        if !(quarantinedShimGenerations[container.id] ?? []).isEmpty {
            throw BackendResourceRollbackIncompleteError(
                "container \(container.id) has unresolved VM shim generation ownership"
            )
        }
        guard let preparedShim = shims[container.id] else { throw EngineError(.notFound, "container VM shim is unavailable") }
        // Replace the workload generation before any suspension. A completion
        // waiter for the previous workload may already be queued to re-enter
        // this actor while image, shim, or guest setup is in progress.
        let generation = executionFence.replace(container.id)
        completionTasks.removeValue(forKey: container.id)?.task.cancel()
        completions.removeValue(forKey: container.id)
        activeContainers.removeValue(forKey: container.id)
        if let previous = portForwardingRegistrations.removeValue(forKey: container.id) {
            portForwarder.stop(containerID: container.id, registration: previous.registration)
        }
        let portRegistration = PortForwarder.Registration()
        let image = try await resolvedImage(container.image, platform: container.platform)
        try requireExecutionGeneration(container.id, generation: generation)
        let modes = try resolveVolumeStorageModes(for: container)
        let usesManagedStorage = managedStorage != nil && Self.volumeNames(in: container.mounts).contains { modes[$0] == .shared }
        if usesManagedStorage, let managedStorage {
            let launchUUID = UUID().uuidString.lowercased()
            let specification = try await workload(container, image: image, volumeModes: modes, ioClaim: "")
            let directory = try containerStateDirectory(for: container.id)
            do {
                return try await managedStorage.start(container: container, launchUUID: launchUUID, directory: directory,
                    workload: specification, compatibility: prepareCompatibility, launchShim: {
                        try await self.launchManagedShim(preparedShim, container: container, modes: modes,
                            generation: generation, launchUUID: launchUUID)
                    }, check: { shim in
                        try await self.requireManagedExecution(container, shim: shim, generation: generation)
                    }, consumeIOClaim: { shim, ioClaim in
                        try await self.consumeManagedIOClaim(container, shim: shim, generation: generation, ioClaim: ioClaim)
                    }, beforePublication: { shim in
                        try await self.publishStartedContainer(container, shim: shim,
                            generation: generation, portRegistration: portRegistration)
                    })
            } catch {
                portForwarder.stop(containerID: container.id, registration: portRegistration)
                if executionFence.owns(container.id, token: generation) {
                    if portForwardingRegistrations[container.id]?.generation == generation {
                        portForwardingRegistrations.removeValue(forKey: container.id)
                    }
                    activeContainers.removeValue(forKey: container.id)
                }
                throw error // EngineRuntime settles execution; the durable P/A fence remains.
            }
        }
        try requireExecutionGeneration(container.id, generation: generation)
        let shim = try await reconfigureVolumeDisks(
            preparedShim, container: container, modes: modes, generation: generation
        )
        try requireExecutionGeneration(container.id, generation: generation)
        _ = try ensureIO(container, replacingStoppedSession: true)
        let attachmentDirectory = try containerStateDirectory(for: container.id)
        guard let attachmentState = try Self.loadPreparedShimState(
                from: attachmentDirectory, expectedContainerID: container.id
              ), attachmentState.currentContainer.instanceID == container.instanceID,
              attachmentState.specification == shim.specification else {
            throw EngineError(
                .conflict,
                "container VM attachment does not match its durable preparation"
            )
        }
        try attachmentState.artifacts.validate(in: attachmentDirectory)
        _ = try await shim.boot()
        try requireExecutionGeneration(container.id, generation: generation)
        struct Prepared: Decodable, Sendable { let status: String }
        let ioClaim = RawContainerDirectIOHandles.containerGuestClaim(
            instanceID: container.instanceID,
            generation: attachmentState.specification.generation
        )
        let sharedNames = Self.volumeNames(in: container.mounts).filter { modes[$0] == .shared }
        let prepared = try await sharedVolumeInitialization.withInitialization(of: sharedNames) {
            // Waiting for another container's copyup permits actor reentrancy.
            // A replaced execution must not send PREPARE or mutate its IO claim.
            try requireExecutionGeneration(container.id, generation: generation)
            try requireExactContainerOwnership(container)
            guard shims[container.id] === shim else {
                throw BackendResourceRollbackIncompleteError(
                    "container VM changed while waiting to prepare shared volumes"
                )
            }
            // A host-generated timeout cannot prove that the separate storage VM
            // drained NFS work already received. Keep the coordinator lease until
            // this RPC completes or its transport actually unwinds; safe ambiguous
            // recovery requires a generation-fenced storage drain.
            return try await shim.guest(
                operation: "prepare",
                payload: try workload(
                    container, image: image, volumeModes: modes, ioClaim: ioClaim
                ),
                response: Prepared.self
            )
        }
        try requireExecutionGeneration(container.id, generation: generation)
        guard prepared.status == "prepared" else { throw EngineError(.internalError, "guest did not prepare workload") }
        let claimedIO = try RawContainerDirectIOHandles.open(
            in: attachmentDirectory, artifacts: attachmentState.artifacts
        )
        try claimedIO.consumeGuestClaims(ioClaim, artifacts: attachmentState.artifacts)
        struct Empty: Encodable {}
        struct Status: Decodable { let status: String; let pid: Int? }
        let response: Status = try await shim.guest(operation: "start", payload: Empty(), response: Status.self)
        try requireExecutionGeneration(container.id, generation: generation)
        guard response.status == "running" else { throw EngineError(.internalError, "workload did not start") }
        return try await publishStartedContainer(container, shim: shim, generation: generation, portRegistration: portRegistration)
    }

    private func requireManagedExecution(_ container: ContainerRecord, shim: VMShimClient?,
        generation: RawBackendExecutionFence.Token) throws {
        try requireExecutionGeneration(container.id, generation: generation)
        try requireExactContainerOwnership(container)
        if let shim, shims[container.id] !== shim { throw RawManagedStorageBackend.failure() }
    }

    private func launchManagedShim(_ prepared: VMShimClient, container: ContainerRecord,
        modes: [String: VolumeStorageMode], generation: RawBackendExecutionFence.Token, launchUUID: String) async throws -> VMShimClient {
        try requireManagedExecution(container, shim: nil, generation: generation)
        let shim = try await reconfigureVolumeDisks(prepared, container: container, modes: modes,
            generation: generation, futureLaunchUUID: launchUUID)
        try requireManagedExecution(container, shim: shim, generation: generation)
        _ = try ensureIO(container, replacingStoppedSession: true)
        return shim
    }

    private func consumeManagedIOClaim(_ container: ContainerRecord, shim: VMShimClient,
        generation: RawBackendExecutionFence.Token, ioClaim: String) throws {
        try requireManagedExecution(container, shim: shim, generation: generation)
        let directory = try containerStateDirectory(for: container.id)
        guard let state = try Self.loadPreparedShimState(from: directory, expectedContainerID: container.id),
              state.currentContainer.instanceID == container.instanceID, state.specification == shim.specification else {
            throw RawManagedStorageBackend.failure()
        }
        try state.artifacts.validate(in: directory)
        let handles = try RawContainerDirectIOHandles.open(in: directory, artifacts: state.artifacts)
        try handles.consumeGuestClaims(ioClaim, artifacts: state.artifacts)
    }

    private func publishStartedContainer(_ container: ContainerRecord, shim: VMShimClient,
        generation: RawBackendExecutionFence.Token, portRegistration: PortForwarder.Registration) async throws -> [PortBinding] {
        do {
            var active = container
            if !container.ports.isEmpty {
                let hasIPv4 = container.networks.contains { $0.ipv4Address != nil }
                guard hasIPv4 || container.networks.contains(where: { $0.ipv6Address != nil }) else {
                    throw EngineError(.conflict, "published ports require a container network endpoint")
                }
                active.ports = try await portForwarder.start(
                    containerID: container.id,
                    registration: portRegistration,
                    bindings: container.ports,
                    connect: { binding in
                        try await shim.startPortStream(
                            transport: binding.proto.lowercased(),
                            port: binding.containerPort,
                            ipv6: !hasIPv4
                        )
                    }
                )
                try requireExecutionGeneration(container.id, generation: generation)
                portForwardingRegistrations[container.id] = (generation, portRegistration)
            }
            activeContainers[container.id] = active
            try await synchronizeFabric()
            try requireExecutionGeneration(container.id, generation: generation)
            return active.ports
        } catch {
            // Listener registrations are generation-specific, so stale failed
            // starts can always release their own channels without touching a
            // replacement that reused the container ID.
            portForwarder.stop(containerID: container.id, registration: portRegistration)
            // A replacement generation owns all ID-keyed resources once the
            // fence changes. Only the generation that failed may tear them down.
            if executionFence.owns(container.id, token: generation) {
                if portForwardingRegistrations[container.id]?.generation == generation {
                    portForwardingRegistrations.removeValue(forKey: container.id)
                }
                activeContainers.removeValue(forKey: container.id)
                try? logMonitors.removeValue(forKey: container.id)?.stop()
                bridges.removeValue(forKey: container.id)?.finishOutput()
                _ = try? await shim.stop()
            }
            throw error
        }
    }

    public func stop(_ container: ContainerRecord, timeoutSeconds: Int) async throws -> Int32 {
        let workLease = try serviceWork.begin()
        defer { serviceWork.end(workLease) }
        try requireExactContainerOwnership(container)
        if let code = completions[container.id] { return code }
        guard let shim = shims[container.id] else { return completions[container.id] ?? container.exitCode ?? 0 }
        let generation = executionFence.currentOrInstall(container.id)
        let runtimeClose: RawManagedStorageBackend.RetirementHints.Close?
        if let launch = shim.specification.shimLaunchUUID {
            runtimeClose = await managedStorage?.beginRuntimeClose(container: container, launch: launch)
        } else {
            runtimeClose = nil
        }
        do {
            try requireExecutionGeneration(container.id, generation: generation)
            let code = try await stop(container, timeoutSeconds: timeoutSeconds, shim: shim, generation: generation)
            if let runtimeClose { await managedStorage?.endRuntimeClose(runtimeClose) }
            return code
        } catch {
            if let runtimeClose { await managedStorage?.endRuntimeClose(runtimeClose) }
            throw error
        }
    }

    private func stop(_ container: ContainerRecord, timeoutSeconds: Int, shim: VMShimClient,
                      generation: RawBackendExecutionFence.Token) async throws -> Int32 {
        struct Signal: Encodable { let signal: Int }
        struct Empty: Encodable {}
        struct Status: Decodable { let status: String; let exitCode: Int? }
        if container.phase == .paused {
            do {
                _ = try await AsyncTimeout.run(seconds: Self.forcedStopWaitSeconds) {
                    try await shim.resume()
                }
            } catch {
                try await terminateShim(container.id, shim: shim, expectedExecutionGeneration: generation)
                return try await recordCompletion(container, code: 137, generation: generation)
            }
        }
        _ = try? await AsyncTimeout.run(seconds: Self.forcedStopWaitSeconds) {
            try await shim.guest(
                operation: "signal",
                payload: Signal(signal: Self.signalNumber(container.stopSignal)),
                response: Status.self
            )
        }
        try requireExecutionGeneration(container.id, generation: generation)
        if let existing = completionTasks[container.id], existing.generation == generation {
            let code: Int32
            var terminated = false
            do {
                code = try await AsyncTimeout.run(seconds: Int64(max(0, timeoutSeconds))) {
                    await existing.task.value
                }
            } catch {
                _ = try? await AsyncTimeout.run(seconds: Self.forcedStopWaitSeconds) {
                    try await shim.guest(
                        operation: "signal", payload: Signal(signal: 9), response: Status.self
                    )
                }
                do {
                    code = try await AsyncTimeout.run(seconds: Self.forcedStopWaitSeconds) {
                        await existing.task.value
                    }
                } catch {
                    try await terminateShim(container.id, shim: shim, expectedExecutionGeneration: generation)
                    code = 137
                    terminated = true
                }
            }
            let published = try await recordCompletion(
                container, code: code, generation: generation
            )
            if !terminated {
                do {
                    _ = try await AsyncTimeout.run(seconds: Self.forcedStopWaitSeconds) {
                        try await shim.stop()
                    }
                } catch {
                    try await terminateShim(container.id, shim: shim, expectedExecutionGeneration: generation)
                }
            }
            return published
        }
        completionTasks.removeValue(forKey: container.id)?.task.cancel()
        let task = Task {
            let code: Int32
            do {
                code = try await AsyncTimeout.run(seconds: Int64(max(0, timeoutSeconds))) {
                    let value: Status = try await shim.guest(operation: "wait", payload: Empty(), response: Status.self)
                    return Int32(value.exitCode ?? 0)
                }
            } catch {
                _ = try? await AsyncTimeout.run(seconds: Self.forcedStopWaitSeconds) {
                    try await shim.guest(
                        operation: "signal", payload: Signal(signal: 9), response: Status.self
                    )
                }
                let value: Status? = try? await AsyncTimeout.run(seconds: Self.forcedStopWaitSeconds) {
                    try await shim.guest(operation: "wait", payload: Empty(), response: Status.self)
                }
                code = Int32(value?.exitCode ?? 137)
            }
            return code
        }
        completionTasks[container.id] = (generation, task)
        let code = await task.value
        do {
            _ = try await AsyncTimeout.run(seconds: Self.forcedStopWaitSeconds) {
                try await shim.stop()
            }
        } catch {
            try await terminateShim(container.id, shim: shim, expectedExecutionGeneration: generation)
        }
        return try await recordCompletion(container, code: code, generation: generation)
    }

    public func wait(_ container: ContainerRecord) async throws -> Int32 {
        try requireExactContainerOwnership(container)
        let epoch = serviceGeneration
        if let code = completions[container.id] { return code }
        guard let shim = shims[container.id] else { return container.exitCode ?? 0 }
        let generation = executionFence.currentOrInstall(container.id)
        struct Empty: Encodable {}; struct Status: Decodable { let exitCode: Int? }
        let task: Task<Int32, Never>
        if let existing = completionTasks[container.id], existing.generation == generation {
            task = existing.task
        } else {
            completionTasks.removeValue(forKey: container.id)?.task.cancel()
            task = Task {
                let value: Status? = try? await shim.guest(operation: "wait", payload: Empty(), response: Status.self)
                return value.map { Int32($0.exitCode ?? 0) } ?? container.exitCode ?? 137
            }
            completionTasks[container.id] = (generation, task)
        }
        return try await RawCompletionStop.run(
            work: destructiveTerminationWork,
            complete: {
                try await self.recordCompletion(container, code: task.value, generation: generation)
            },
            ownsExecution: {
                !self.serviceMaintenance && self.serviceGeneration == epoch
                    && self.executionFence.owns(container.id, token: generation)
                    && self.shims[container.id] === shim
                    && self.knownContainers[container.id]?.instanceID == container.instanceID
            },
            // Publish terminal backend state while guest control is still available.
            // The admitted lease remains held across the entire stop suspension.
            stop: { _ = try await shim.stop() }
        )
    }

    public func completion(_ container: ContainerRecord) async -> Int32? {
        guard (try? requireExactContainerOwnership(container)) != nil else { return nil }
        if let code = completions[container.id] { return code }
        return try? await wait(container)
    }

    public func recover(_ container: ContainerRecord) async throws -> BackendContainerRecovery {
        let workLease = try serviceWork.begin()
        defer { serviceWork.end(workLease) }
        try requireExactContainerOwnership(container)
        guard knownContainers[container.id]?.instanceID == container.instanceID else {
            throw BackendResourceRollbackIncompleteError(
                "container \(container.id) recovered VM belongs to a different instance"
            )
        }
        guard let shim = shims[container.id] else { return .unavailable }
        _ = executionFence.currentOrInstall(container.id)
        let status = try await shim.status()
        try serviceWork.require(workLease)
        switch status.state {
        case .running:
            struct Empty: Encodable {}
            struct WorkloadStatus: Decodable { let status: String; let exitCode: Int? }
            let workload: WorkloadStatus = try await shim.guest(
                operation: "status", payload: Empty(), response: WorkloadStatus.self
            )
            try serviceWork.require(workLease)
            guard workload.status == "running" else {
                let code = Int32(workload.exitCode ?? 0)
                completions[container.id] = code
                _ = try? await shim.stop()
                return .exited(code)
            }
            try await restoreLiveContainer(container)
            return .running
        case .paused:
            try await restoreLiveContainer(container)
            return .paused
        default:
            return .unavailable
        }
    }

    public func io(for container: ContainerRecord) async throws -> ContainerIOBridge {
        try requireExactContainerOwnership(container)
        return try ensureIO(container, replacingStoppedSession: true)
    }

    public func resize(
        _ container: ContainerRecord, width: UInt16, height: UInt16
    ) async throws {
        let workLease = try serviceWork.begin()
        defer { serviceWork.end(workLease) }
        try requireExactContainerOwnership(container)
        try requireActiveContainerExecution(container)
        guard let shim = shims[container.id] else {
            throw EngineError(.notFound, "container VM shim is unavailable")
        }
        struct Status: Decodable { let status: String }
        let status: Status = try await shim.guest(
            operation: "resize",
            payload: TerminalSize(height: height, width: width),
            response: Status.self
        )
        try serviceWork.require(workLease)
        guard status.status == "resized" else {
            throw EngineError(.internalError, "guest did not resize the container terminal")
        }
    }

    public func logs(for container: ContainerRecord) async throws -> Data {
        try requireExactContainerOwnership(container)
        return try ensureIO(container).logData()
    }

    public func logs(for container: ContainerRecord, options: DockerLogOptions) async throws -> Data {
        try requireExactContainerOwnership(container)
        return try ensureIO(container).logData(options: options)
    }

    public func deleteLogs(for container: ContainerRecord) async throws {
        try requireExactContainerOwnership(container)
        try Self.deleteContainerLogs(
            for: container,
            in: containersStateDirectory,
            receipts: deletedContainersStateDirectory,
            freshPreparationInstances: freshPreparationInstances,
            retainedIdentities: &containerDirectoryIdentities,
            logMonitors: &logMonitors,
            bridges: &bridges
        )
    }

    static func deleteContainerLogs(
        for container: ContainerRecord,
        in containers: PersistentStateDirectory,
        receipts: PersistentStateDirectory,
        freshPreparationInstances: [String: UUID],
        retainedIdentities: inout [String: PersistentFileIdentity],
        logMonitors: inout [String: ContainerLogMonitor],
        bridges: inout [String: ContainerIOBridge]
    ) throws {
        try RawContainerInstanceCoordinator.requireNoConflictingFreshPreparation(
            of: container, in: freshPreparationInstances
        )
        try completePendingContainerDeletion(
            of: container,
            in: containers,
            receipts: receipts,
            retainedIdentities: &retainedIdentities
        )
        guard let containerDirectory = try matchingContainerStateDirectory(
            for: container.id,
            in: containers,
            retainedIdentities: retainedIdentities
        ) else {
            if try RawDeletedContainerCoordinator.hasReceipt(
                containerID: container.id, in: receipts
            ) {
                try RawDeletedContainerCoordinator.requireCompletedDeletion(
                    of: container, in: containers, receipts: receipts
                )
            } else {
                try RawContainerPreparationAttemptCoordinator.requireCleanAbsence(
                    container, in: containers, attempts: receipts
                )
            }
            try? logMonitors.removeValue(forKey: container.id)?.stop()
            bridges.removeValue(forKey: container.id)?.finishOutput()
            return
        }
        guard let prepared = try exactPreparedShimState(
            for: container, in: containerDirectory
        ) else {
            throw EngineError(.notFound, "container VM preparation is unavailable")
        }
        retainedIdentities[container.id] = containerDirectory.identity
        try? logMonitors.removeValue(forKey: container.id)?.stop()
        bridges.removeValue(forKey: container.id)?.finishOutput()
        let handles = try RawContainerDirectIOHandles.open(
            in: containerDirectory, artifacts: prepared.artifacts
        )
        try handles.validateNames(artifacts: prepared.artifacts)
        try handles.truncate()
        try handles.validateNames(artifacts: prepared.artifacts)
        let logs = try handles.openDockerLogs(artifacts: prepared.artifacts)
        for handle in [logs.log, logs.index] {
            guard Darwin.ftruncate(handle.fileDescriptor, 0) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            try handle.seek(toOffset: 0)
            try handle.synchronize()
        }
        try handles.validateNames(artifacts: prepared.artifacts)
    }

    public func prepareExec(_ exec: ExecRecord, container: ContainerRecord) async throws -> ContainerIOBridge {
        let workLease = try serviceWork.begin()
        defer { serviceWork.end(workLease) }
        let epoch = serviceGeneration
        try requireServiceGeneration(epoch)
        try requireExactContainerOwnership(container)
        try requireActiveContainerExecution(container)
        guard exec.containerID == container.id,
              exec.containerInstanceID == container.instanceID else {
            throw EngineError(.conflict, "exec owner does not match container instance")
        }
        try await recoverFailedExecArtifactCleanup(for: container)
        try requireActiveContainerExecution(container)
        guard let shim = shims[container.id] else { throw EngineError(.notFound, "container VM shim is unavailable") }
        let image = try await resolvedImage(container.image, platform: container.platform)
        try requireServiceGeneration(epoch)
        let containerDirectory = try containerStateDirectory(for: container.id)
        guard let prepared = try Self.loadPreparedShimState(
            from: containerDirectory, expectedContainerID: container.id
        ), prepared.currentContainer.instanceID == container.instanceID else {
            throw EngineError(.conflict, "exec I/O does not match durable preparation")
        }
        let ioDirectory = try containerDirectory.openDirectory(named: "io")
        guard ioDirectory.identity == prepared.artifacts.ioDirectoryIdentity else {
            throw EngineError(.conflict, "exec I/O directory identity changed")
        }
        let prefix = "exec-\(exec.id)"
        let preparedExecArtifacts = try RawExecArtifactTransaction.prepare(
            containerID: container.id,
            execID: exec.id,
            attachStdin: exec.configuration.attachStdin,
            in: containerDirectory,
            artifacts: prepared.artifacts
        )
        let bridge = ContainerIOBridge(
            tty: exec.configuration.tty,
            logHandle: preparedExecArtifacts.log,
            logIndexHandle: preparedExecArtifacts.logIndex
        )
        let monitor = ContainerLogMonitor(
            stdout: preparedExecArtifacts.stdout,
            stderr: preparedExecArtifacts.stderr,
            input: preparedExecArtifacts.stdin,
            bridge: bridge,
            markInputClosed: {
                try RawContainerDirectIOHandles.markInputClosed(
                    preparedExecArtifacts.stdinClosed
                )
            }
        )
        monitor.start()
        execBridges[exec.id] = bridge
        execMonitors[exec.id] = monitor
        execShims[exec.id] = shim
        execOwners[exec.id] = ExecOwner(
            containerID: container.id,
            containerInstanceID: container.instanceID,
            containerDirectoryIdentity: prepared.directoryIdentity
        )
        struct Status: Decodable { let status: String }
        let configuration = exec.configuration
        let context = Self.resolveExecContext(
            configuration: configuration,
            containerEnvironment: container.environment,
            containerWorkingDirectory: container.workingDirectory,
            containerUser: container.user,
            containerPrivileged: container.privileged,
            containerNoNewPrivileges: container.noNewPrivileges,
            imageEnvironment: image.configuration.config?.environment ?? [],
            imageWorkingDirectory: image.configuration.config?.workingDirectory,
            imageUser: image.configuration.config?.user
        )
        let ioClaim = RawExecArtifactTransaction.guestClaim(
            for: preparedExecArtifacts.record
        )
        try requireActiveContainerExecution(container)
        let status: Status
        do {
            status = try await shim.guest(
                operation: "prepare-exec",
                payload: GuestProtocol.Exec(
                    id: exec.id, arguments: configuration.arguments, environment: context.environment,
                    workingDirectory: context.workingDirectory, user: context.user,
                    terminal: configuration.tty,
                    consoleSize: configuration.tty && !configuration.consoleSize.isZero
                        ? configuration.consoleSize : nil,
                    attachStdin: configuration.attachStdin,
                    attachStdout: configuration.attachStdout, attachStderr: configuration.attachStderr,
                    noNewPrivileges: context.noNewPrivileges,
                    privileged: context.privileged,
                    seccompDefault: Self.usesDefaultSeccomp(container),
                    capabilityAdd: container.capabilityAdd, capabilityDrop: container.capabilityDrop,
                    rlimits: try Self.rlimits(container.ulimits), ioClaim: ioClaim
                ),
                response: Status.self
            )
        } catch {
            try requireServiceGeneration(epoch)
            throw await normalizedExecPreparationError(
                error, container: container, shim: shim
            )
        }
        try requireServiceGeneration(epoch)
        guard status.status == "created" else {
            throw EngineError(.internalError, "guest did not prepare exec")
        }
        let ioNames = [
            "\(prefix)-stdout", "\(prefix)-stderr", "\(prefix)-stdin", "\(prefix)-stdin.closed",
        ]
        try RawContainerDirectIOHandles.consumeGuestClaims(
            ioClaim,
            names: ioNames,
            identities: preparedExecArtifacts.record.fileIdentities,
            in: ioDirectory
        )
        for name in ioNames {
            guard let identity = preparedExecArtifacts.record.fileIdentities[name] else {
                throw EngineError(.internalError, "missing exec I/O file identity")
            }
            _ = try ioDirectory.regularFileIdentity(named: name, expectedIdentity: identity)
        }
        return bridge
    }

    public func discardExec(_ exec: ExecRecord) async {
        await retireExec(exec, preserveBridge: false)
    }

    public func retireExec(_ exec: ExecRecord) async {
        await retireExec(exec, preserveBridge: true)
    }

    private func retireExec(_ exec: ExecRecord, preserveBridge: Bool) async {
        guard let workLease = try? serviceWork.begin() else { return }
        defer { serviceWork.end(workLease) }
        var cleanupKey: RawExecCleanupKey?
        do {
            cleanupKey = try exactExecCleanupKey(for: exec)
            guard let cleanupKey else { return }
            _ = try await retireExecOwnership(
                exec, cleanupKey: cleanupKey, preserveBridge: preserveBridge
            )
        } catch {
            guard let cleanupKey else { return }
            recordExecArtifactCleanupFailure(
                cleanupKey, error: error, preserveBridge: preserveBridge
            )
        }
    }

    private func retireExecOwnership(
        _ exec: ExecRecord,
        cleanupKey: RawExecCleanupKey,
        preserveBridge: Bool,
        guestAlreadyContained: Bool = false
    ) async throws -> Bool {
        // Durable exact-instance and directory proof is the first retirement
        // boundary. In-memory maps are keyed by reusable public exec IDs and
        // cannot authorize any mutation on their own.
        guard let durable = try Self.exactDurableExecPreparation(
            root: root, exec: exec
        ) else { return false }
        let observedKey = RawExecCleanupKey(
            exec: exec,
            containerDirectoryIdentity: durable.prepared.directoryIdentity
        )
        guard observedKey == cleanupKey else {
            throw BackendResourceRollbackIncompleteError(
                "exec \(exec.id) durable cleanup owner changed before retirement"
            )
        }
        let expectedOwner = ExecOwner(
            containerID: exec.containerID,
            containerInstanceID: exec.containerInstanceID,
            containerDirectoryIdentity: cleanupKey.containerDirectoryIdentity
        )
        let hasInMemoryResources = execMonitors[exec.id] != nil
            || execBridges[exec.id] != nil
            || execShims[exec.id] != nil
            || execRetirementDeadlines[exec.id] != nil
        if hasInMemoryResources {
            guard execOwners[exec.id] == expectedOwner else { return false }
        } else if let owner = execOwners[exec.id] {
            guard owner == expectedOwner else { return false }
        }
        if let monitor = execMonitors[exec.id] {
            try monitor.stop()
            execMonitors.removeValue(forKey: exec.id)
        } else {
            execBridges[exec.id]?.finishOutput()
        }
        // Durable output drain is the only prerequisite for snapshotting.
        // Guest discard and local artifact deletion are independent cleanup
        // steps and may remain retryable without retaining live descriptors or
        // escaping the aggregate completed-output budget.
        freezeExecBridge(execID: exec.id, preserveBridge: preserveBridge)
        let shim = execShims[exec.id]
        let deadline = execRetirementDeadlines.removeValue(forKey: exec.id)
            ?? Self.execDeadline(afterMilliseconds: Self.execRetirementTimeoutMilliseconds)
        try await Self.discardExecArtifacts(
            root: root,
            exec: exec,
            expectedContainerDirectoryIdentity: cleanupKey.containerDirectoryIdentity
        ) {
            guard !guestAlreadyContained, let shim else { return }
            _ = try await Self.containAndDiscardGuestExec(
                shim: shim, execID: exec.id, deadlineNanoseconds: deadline
            )
        }
        execShims.removeValue(forKey: exec.id)
        if !preserveBridge { execOwners.removeValue(forKey: exec.id) }
        clearExecArtifactCleanupFailure(cleanupKey)
        return true
    }

    private func exactExecCleanupKey(
        for exec: ExecRecord
    ) throws -> RawExecCleanupKey? {
        guard let durable = try Self.exactDurableExecPreparation(
            root: root, exec: exec
        ) else { return nil }
        return RawExecCleanupKey(
            exec: exec,
            containerDirectoryIdentity: durable.prepared.directoryIdentity
        )
    }

    private func freezeExecBridge(execID: String, preserveBridge: Bool) {
        guard let bridge = execBridges[execID] else { return }
        guard preserveBridge else {
            bridge.freezeCompleted(maximumBytes: Self.completedExecSnapshotPerExecBytes)
            execBridges.removeValue(forKey: execID)?.discardCompletedOutput()
            completedExecSnapshotBudget.remove(execID: execID)
            return
        }
        guard let owner = execOwners[execID] else { return }
        let evicted = Self.freezeCompletedExecOutput(bridge, execID: execID,
            containerID: owner.containerID, instanceID: owner.containerInstanceID,
            budget: &completedExecSnapshotBudget)
        for identifier in evicted {
            execBridges.removeValue(forKey: identifier)?.discardCompletedOutput()
        }
    }

    static func freezeCompletedExecOutput(_ bridge: ContainerIOBridge, execID: String,
        containerID: String, instanceID: UUID, budget: inout RawCompletedExecSnapshotBudget) -> [String] {
        bridge.freezeCompleted(maximumBytes: Self.completedExecSnapshotPerExecBytes)
        return budget.register(execID: execID, containerID: containerID,
            containerInstanceID: instanceID, bytes: bridge.retainedLogPayloadByteCount)
    }

    private func recoverFailedExecArtifactCleanup(for container: ContainerRecord) async throws {
        do {
            let containerDirectory = try containerStateDirectory(for: container.id)
            guard let prepared = try Self.loadPreparedShimState(
                from: containerDirectory, expectedContainerID: container.id
            ), prepared.currentContainer.instanceID == container.instanceID else {
                throw EngineError(.conflict, "exec artifact recovery has no matching durable preparation")
            }
            let cleanupKeys = execArtifactCleanupFailures.keys.filter {
                $0.owns(
                    container: container,
                    directoryIdentity: prepared.directoryIdentity
                )
            }.sorted { $0.execID < $1.execID }
            guard !cleanupKeys.isEmpty else { return }
            for cleanupKey in cleanupKeys {
                let execID = cleanupKey.execID
                if execShims[execID] != nil
                        || execMonitors[execID] != nil
                        || execBridges[execID] != nil
                        || execRetirementDeadlines[execID] != nil {
                    let preserve = execArtifactCleanupPreserveBridges[cleanupKey] ?? false
                    guard try await retireExecOwnership(
                        ExecRecord(
                            id: execID,
                            containerID: container.id,
                            containerInstanceID: container.instanceID,
                            configuration: .init(arguments: ["true"])
                        ),
                        cleanupKey: cleanupKey,
                        preserveBridge: preserve
                    ) else {
                        throw EngineError(
                            .conflict, "exec \(execID) in-memory owner was replaced"
                        )
                    }
                } else {
                    if recoveredExecContainmentFailures.contains(cleanupKey) {
                        guard let shim = shims[container.id] else {
                            throw EngineError(
                                .conflict,
                                "exec \(execID) guest ownership is still unresolved"
                            )
                        }
                        guard shim.ownsPersistedContainer(
                            id: container.id,
                            directoryIdentity: cleanupKey.containerDirectoryIdentity
                        ) else {
                            throw EngineError(
                                .conflict,
                                "exec \(execID) guest cleanup shim ownership changed"
                            )
                        }
                        _ = try await Self.containAndDiscardGuestExec(
                            shim: shim,
                            execID: execID,
                            deadlineNanoseconds: Self.execDeadline(
                                afterMilliseconds: Self.execRetirementTimeoutMilliseconds
                            )
                        )
                    }
                    try RawExecArtifactTransaction.cleanup(
                        containerID: container.id,
                        execID: execID,
                        in: containerDirectory,
                        artifacts: prepared.artifacts
                    )
                    clearExecArtifactCleanupFailure(cleanupKey)
                }
            }
        } catch {
            throw BackendResourceRollbackIncompleteError(
                "container \(container.id) has quarantined exec artifacts; cleanup retry failed ("
                    + EngineError.message(for: error) + ")"
            )
        }
    }

    private func recordExecArtifactCleanupFailure(
        _ cleanupKey: RawExecCleanupKey,
        error: Error,
        preserveBridge: Bool = false
    ) {
        execArtifactCleanupFailures[cleanupKey] = EngineError.message(for: error)
        execArtifactCleanupPreserveBridges[cleanupKey] = preserveBridge
    }

    private func recordExecArtifactCleanupFailure(
        for exec: ExecRecord,
        error: Error,
        preserveBridge: Bool = false
    ) {
        guard let cleanupKey = try? exactExecCleanupKey(for: exec) else { return }
        recordExecArtifactCleanupFailure(
            cleanupKey, error: error, preserveBridge: preserveBridge
        )
    }

    private func clearExecArtifactCleanupFailure(_ cleanupKey: RawExecCleanupKey) {
        recoveredExecContainmentFailures.remove(cleanupKey)
        execArtifactCleanupFailures.removeValue(forKey: cleanupKey)
        execArtifactCleanupPreserveBridges.removeValue(forKey: cleanupKey)
    }

    private func clearExecArtifactCleanupFailures(for container: ContainerRecord) {
        let keys = Set(execArtifactCleanupFailures.keys)
            .union(execArtifactCleanupPreserveBridges.keys)
            .union(recoveredExecContainmentFailures)
            .filter {
                $0.containerID == container.id
                    && $0.containerInstanceID == container.instanceID
            }
        for key in keys {
            clearExecArtifactCleanupFailure(key)
        }
    }

    static func discardExecArtifacts(
        root: URL,
        exec: ExecRecord,
        expectedContainerDirectoryIdentity: PersistentFileIdentity,
        guestDiscard: @Sendable () async throws -> Void
    ) async throws {
        guard let durable = try exactDurableExecPreparation(root: root, exec: exec) else {
            // A durable preparation for a different instance proves that this
            // old instance is no longer present beneath the reused public ID.
            // Retirement is therefore already complete for this exact owner.
            return
        }
        guard durable.prepared.directoryIdentity
                == expectedContainerDirectoryIdentity else {
            // The public IDs may now name the same logical container instance
            // beneath a substituted directory. Only the directory captured
            // when this exec was prepared authorizes retirement mutations.
            return
        }
        try await guestDiscard()
        guard let current = try loadPreparedShimState(
            from: durable.directory, expectedContainerID: exec.containerID
        ), current.currentContainer.instanceID == exec.containerInstanceID,
              current.directoryIdentity == expectedContainerDirectoryIdentity,
              durable.directory.identity == expectedContainerDirectoryIdentity,
              current.artifacts == durable.prepared.artifacts else {
            throw BackendResourceRollbackIncompleteError(
                "exec artifact cleanup durable owner changed after guest retirement"
            )
        }
        try RawExecArtifactTransaction.cleanup(
            containerID: exec.containerID,
            execID: exec.id,
            in: durable.directory,
            artifacts: current.artifacts
        )
    }

    private static func exactDurableExecPreparation(
        root: URL,
        exec: ExecRecord
    ) throws -> (directory: PersistentStateDirectory, prepared: PreparedShimState)? {
        let containers = try PersistentStateDirectory.open(
            root.appending(path: "containers", directoryHint: .isDirectory)
        )
        guard let directory = try containers.openDirectoryIfPresent(
            named: exec.containerID
        ) else { return nil }
        guard let prepared = try loadPreparedShimState(
            from: directory, expectedContainerID: exec.containerID
        ) else {
            throw EngineError(.conflict, "exec artifact cleanup has no durable preparation")
        }
        guard let namedDirectory = try containers.entryMetadata(named: exec.containerID),
              namedDirectory.identity == directory.identity,
              namedDirectory.type == S_IFDIR,
              prepared.directoryIdentity == directory.identity,
              prepared.artifacts.directoryIdentity == directory.identity,
              directory.pathStillNamesThisDirectory() else {
            throw BackendResourceRollbackIncompleteError(
                "exec artifact cleanup container directory identity changed"
            )
        }
        guard prepared.currentContainer.instanceID == exec.containerInstanceID else {
            return nil
        }
        return (directory, prepared)
    }

    private static func execDeadline(afterMilliseconds milliseconds: UInt64) -> UInt64 {
        let (delta, overflow) = milliseconds.multipliedReportingOverflow(by: 1_000_000)
        guard !overflow else { return UInt64.max }
        let (deadline, additionOverflow) = DispatchTime.now().uptimeNanoseconds
            .addingReportingOverflow(delta)
        return additionOverflow ? UInt64.max : deadline
    }

    /// Resolves the uncertain-result window after a start request. Only a
    /// created or terminal status may be discarded. Starting/running execs are
    /// first driven to a terminal state under the same absolute deadline.
    private static func containAndDiscardGuestExec(
        shim: VMShimClient,
        execID: String,
        deadlineNanoseconds: UInt64
    ) async throws -> Int32? {
        struct Request: Encodable { let id: String }
        struct Signal: Encodable { let id: String; let signal: Int }
        struct Status: Decodable { let status: String; let exitCode: Int? }
        let request = Request(id: execID)
        return try await RawGuestExecRetirement.runReportingExitCode(
            deadlineNanoseconds: deadlineNanoseconds,
            status: {
                let status: Status = try await shim.guest(
                    operation: "exec-status",
                    payload: request,
                    response: Status.self,
                    deadlineNanoseconds: deadlineNanoseconds
                )
                return .init(
                    status.status,
                    exitCode: status.exitCode.map { Int32(clamping: $0) }
                )
            },
            signal: {
                let _: Status = try await shim.guest(
                    operation: "signal-exec",
                    payload: Signal(id: execID, signal: 9),
                    response: Status.self,
                    deadlineNanoseconds: deadlineNanoseconds
                )
            },
            wait: {
                let terminal: Status = try await shim.guest(
                    operation: "wait-exec",
                    payload: request,
                    response: Status.self,
                    deadlineNanoseconds: deadlineNanoseconds
                )
                return .init(
                    terminal.status,
                    exitCode: terminal.exitCode.map { Int32(clamping: $0) }
                )
            },
            discard: {
                let discarded: Status = try await shim.guest(
                    operation: "discard-exec",
                    payload: request,
                    response: Status.self,
                    deadlineNanoseconds: deadlineNanoseconds
                )
                guard discarded.status == "discarded" else {
                    throw EngineError(.internalError, "guest did not discard exec \(execID)")
                }
            }
        )
    }

    public func startExec(_ exec: ExecRecord) async throws {
        try await startExec(exec, consoleSize: nil)
    }

    public func startExec(
        _ exec: ExecRecord, consoleSize: TerminalSize?
    ) async throws {
        let workLease = try serviceWork.begin()
        defer { serviceWork.end(workLease) }
        try requireExactExecOwnership(exec)
        guard let shim = execShims[exec.id] else {
            throw EngineError(.notFound, "exec is unavailable")
        }
        let deadline = Self.execDeadline(
            afterMilliseconds: Self.execStartRequestTimeoutMilliseconds
        )
        do {
            try await startExec(
                exec, consoleSize: consoleSize, deadlineNanoseconds: deadline
            )
        } catch {
            try serviceWork.require(workLease)
            let startError = error
            var exitCode = Self.execStartNeverRanExitCode
            var containerTerminated = false
            do {
                exitCode = try await Self.containAndDiscardGuestExec(
                    shim: shim,
                    execID: exec.id,
                    deadlineNanoseconds: deadline
                ) ?? Self.execStartNeverRanExitCode
            } catch {
                let containmentError = error
                do {
                    // An unresponsive guest cannot be allowed to hide a
                    // process behind a failed start response. Terminating the
                    // exact persisted shim generation contains every process
                    // in that VM; EngineRuntime then publishes the parent as
                    // exited as well as terminalizing this exec.
                    try await terminateShim(exec.containerID, shim: shim)
                    containerTerminated = true
                    exitCode = 137
                } catch {
                    recordExecArtifactCleanupFailure(
                        for: exec,
                        error: BackendResourceRollbackIncompleteError(
                            "exec start failed: \(EngineError.message(for: startError)); "
                                + "guest containment failed: \(EngineError.message(for: containmentError)); "
                                + "owning VM containment failed: \(EngineError.message(for: error))"
                        ),
                        preserveBridge: true
                    )
                    throw BackendExecStartQuarantinedError(
                        exitCode: Self.execStartNeverRanExitCode,
                        message: "exec \(exec.id) start result is quarantined because neither guest nor VM containment completed"
                    )
                }
            }

            do {
                if let cleanupKey = try exactExecCleanupKey(for: exec) {
                    _ = try await retireExecOwnership(
                        exec,
                        cleanupKey: cleanupKey,
                        preserveBridge: true,
                        guestAlreadyContained: true
                    )
                }
            } catch {
                recordExecArtifactCleanupFailure(
                    for: exec,
                    error: error,
                    preserveBridge: true
                )
            }
            throw BackendExecStartContainedError(
                exitCode: exitCode,
                message: EngineError.message(for: startError),
                containerTerminated: containerTerminated
            )
        }
    }

    private func startExec(
        _ exec: ExecRecord,
        consoleSize: TerminalSize? = nil,
        deadlineNanoseconds: UInt64?
    ) async throws {
        guard let shim = execShims[exec.id] else { throw EngineError(.notFound, "exec is unavailable") }
        struct Request: Encodable {
            let id: String
            let consoleSize: TerminalSize?
        }
        struct Status: Decodable { let status: String; let pid: Int? }
        let status: Status
        if let deadlineNanoseconds {
            status = try await shim.guest(
                operation: "start-exec",
                payload: Request(id: exec.id, consoleSize: consoleSize),
                response: Status.self,
                deadlineNanoseconds: deadlineNanoseconds
            )
        } else {
            status = try await shim.guest(
                operation: "start-exec",
                payload: Request(id: exec.id, consoleSize: consoleSize),
                response: Status.self
            )
        }
        guard status.status == "running" else { throw EngineError(.internalError, "exec did not start") }
    }

    public func startAttachedExec(_ exec: ExecRecord) async throws -> CInt? {
        try await startAttachedExec(exec, consoleSize: nil)
    }

    public func startAttachedExec(
        _ exec: ExecRecord, consoleSize: TerminalSize?
    ) async throws -> CInt? {
        let workLease = try serviceWork.begin()
        defer { serviceWork.end(workLease) }
        try requireExactExecOwnership(exec)
        guard let shim = execShims[exec.id] else { throw EngineError(.notFound, "exec is unavailable") }
        let descriptor = try await shim.startExecStream(id: exec.id, consoleSize: consoleSize)
        do { try serviceWork.require(workLease) }
        catch { Darwin.close(descriptor); throw error }
        return descriptor
    }

    public func execCompletion(_ exec: ExecRecord) async -> Int32? {
        let epoch = serviceGeneration
        guard (try? requireExactExecOwnership(exec)) != nil else { return nil }
        guard let shim = execShims[exec.id] else { return exec.exitCode }
        struct Request: Encodable { let id: String }; struct Status: Decodable { let status: String; let exitCode: Int? }
        guard let value: Status = try? await shim.guest(operation: "wait-exec", payload: Request(id: exec.id), response: Status.self), value.status == "exited" else { return nil }
        guard epoch == serviceGeneration, !serviceMaintenance, execShims[exec.id] === shim else { return nil }
        do {
            if let monitor = execMonitors[exec.id] {
                try monitor.stop()
                execMonitors.removeValue(forKey: exec.id)
            }
            return Int32(value.exitCode ?? 0)
        } catch {
            recordExecArtifactCleanupFailure(
                for: exec,
                error: error,
                preserveBridge: true
            )
            return nil
        }
    }

    public func execIO(_ exec: ExecRecord) async throws -> ContainerIOBridge {
        try requireExactExecOwnership(exec)
        guard let bridge = execBridges[exec.id] else {
            throw EngineError(.notFound, "exec I/O is unavailable")
        }
        return bridge
    }

    public func execPID(_ exec: ExecRecord) async -> Int32 {
        guard (try? requireExactExecOwnership(exec)) != nil else { return 0 }
        guard let shim = execShims[exec.id] else { return 0 }
        struct Request: Encodable { let id: String }
        struct Status: Decodable { let status: String; let pid: Int? }
        for _ in 0..<1_000 where !Task.isCancelled {
            guard let value: Status = try? await shim.guest(
                operation: "exec-status", payload: Request(id: exec.id), response: Status.self
            ) else { return 0 }
            if let pid = value.pid, pid > 0 { return Int32(pid) }
            guard value.status == "created" || value.status == "starting" else { return 0 }
            try? await Task.sleep(for: .milliseconds(10))
        }
        return 0
    }

    public func execStatus(_ exec: ExecRecord) async -> Int32? {
        let epoch = serviceGeneration
        guard (try? requireExactExecOwnership(exec)) != nil else { return nil }
        guard let shim = execShims[exec.id] else { return exec.exitCode }
        struct Request: Encodable { let id: String }; struct Status: Decodable { let status: String; let exitCode: Int? }
        guard let value: Status = try? await shim.guest(operation: "exec-status", payload: Request(id: exec.id), response: Status.self), value.status == "exited" else { return nil }
        guard epoch == serviceGeneration, !serviceMaintenance, execShims[exec.id] === shim else { return nil }
        do {
            if let monitor = execMonitors[exec.id] {
                try monitor.stop()
                execMonitors.removeValue(forKey: exec.id)
            }
            return Int32(value.exitCode ?? 0)
        } catch {
            recordExecArtifactCleanupFailure(
                for: exec,
                error: error,
                preserveBridge: true
            )
            return nil
        }
    }

    public func resizeExec(
        _ exec: ExecRecord, width: UInt16, height: UInt16
    ) async throws {
        let workLease = try serviceWork.begin()
        defer { serviceWork.end(workLease) }
        try requireExactExecOwnership(exec)
        guard let shim = execShims[exec.id] else {
            throw EngineError(.notFound, "exec is unavailable")
        }
        struct Request: Encodable {
            let id: String
            let height: UInt16
            let width: UInt16
        }
        struct Status: Decodable { let status: String }
        let status: Status = try await shim.guest(
            operation: "resize-exec",
            payload: Request(id: exec.id, height: height, width: width),
            response: Status.self
        )
        try serviceWork.require(workLease)
        guard status.status == "resized" else {
            throw EngineError(.internalError, "guest did not resize the exec terminal")
        }
    }

    public func runHealthcheck(_ container: ContainerRecord, arguments: [String], timeoutSeconds: Int64) async throws -> (exitCode: Int32, output: String) {
        let workLease = try serviceWork.begin()
        defer { serviceWork.end(workLease) }
        let record = ExecRecord(
            containerID: container.id,
            containerInstanceID: container.instanceID,
            configuration: .init(arguments: arguments)
        )
        return try await RawHealthcheckExecLifecycle.run(
            prepare: {
                _ = try await self.prepareExec(record, container: container)
                do {
                    try await self.startExec(
                        record,
                        deadlineNanoseconds: Self.execDeadline(
                            afterMilliseconds: Self.execRetirementTimeoutMilliseconds
                        )
                    )
                } catch {
                    self.execRetirementDeadlines[record.id] = Self.execDeadline(
                        afterMilliseconds: Self.execRetirementTimeoutMilliseconds
                    )
                    throw error
                }
            },
            execute: {
                guard let shim = self.execShims[record.id] else {
                    throw EngineError(.notFound, "healthcheck exec is unavailable")
                }
                struct Request: Encodable { let id: String }
                struct Signal: Encodable { let id: String; let signal: Int }
                struct Status: Decodable { let status: String; let exitCode: Int? }
                let code: Int32
                let waitMilliseconds = UInt64(max(1, timeoutSeconds)) * 1_000
                let waitDeadline = Self.execDeadline(afterMilliseconds: waitMilliseconds)
                do {
                    let value: Status = try await shim.guest(
                        operation: "wait-exec",
                        payload: Request(id: record.id),
                        response: Status.self,
                        deadlineNanoseconds: waitDeadline
                    )
                    code = Int32(value.exitCode ?? 0)
                } catch {
                    let recoveryDeadline = Self.execDeadline(
                        afterMilliseconds: Self.execRetirementTimeoutMilliseconds
                    )
                    self.execRetirementDeadlines[record.id] = recoveryDeadline
                    let _: Status = try await shim.guest(
                        operation: "signal-exec",
                        payload: Signal(id: record.id, signal: 9),
                        response: Status.self,
                        deadlineNanoseconds: recoveryDeadline
                    )
                    let value: Status = try await shim.guest(
                        operation: "wait-exec",
                        payload: Request(id: record.id),
                        response: Status.self,
                        deadlineNanoseconds: recoveryDeadline
                    )
                    code = Int32(value.exitCode ?? 137)
                }
                let monitor = self.execMonitors[record.id]
                try monitor?.stop()
                self.execMonitors.removeValue(forKey: record.id)
                let rawOutput = (try? monitor?.rawOutput()) ?? Data()
                return (code, String(decoding: rawOutput, as: UTF8.self))
            },
            retire: { await self.discardExec(record) }
        )
    }

    public func kill(_ container: ContainerRecord, signal: String) async throws {
        let workLease = try serviceWork.begin()
        defer { serviceWork.end(workLease) }
        try requireExactContainerOwnership(container)
        guard let shim = shims[container.id] else { throw EngineError(.notFound, "container VM shim is unavailable") }
        struct Signal: Encodable { let signal: Int }; struct Status: Decodable { let status: String }
        _ = try await shim.guest(operation: "signal", payload: Signal(signal: Self.signalNumber(signal)), response: Status.self)
        try serviceWork.require(workLease)
    }

    public func pause(_ container: ContainerRecord) async throws {
        let workLease = try serviceWork.begin()
        defer { serviceWork.end(workLease) }
        try requireExactContainerOwnership(container)
        guard let shim = shims[container.id] else { throw EngineError(.notFound, "container VM shim is unavailable") }
        _ = try await shim.pause()
        try serviceWork.require(workLease)
    }
    public func resume(_ container: ContainerRecord) async throws {
        let workLease = try serviceWork.begin()
        defer { serviceWork.end(workLease) }
        try requireExactContainerOwnership(container)
        guard let shim = shims[container.id] else { throw EngineError(.notFound, "container VM shim is unavailable") }
        _ = try await shim.resume()
        try serviceWork.require(workLease)
    }
    public func restart(_ container: ContainerRecord, timeoutSeconds: Int) async throws {
        let workLease = try serviceWork.begin()
        defer { serviceWork.end(workLease) }
        _ = try await stop(container, timeoutSeconds: timeoutSeconds)
        try serviceWork.require(workLease)
        if shims[container.id] == nil {
            guard try await relaunchPreparedShim(container) != nil else {
                throw EngineError(.notFound, "container VM preparation is unavailable")
            }
        }
        try serviceWork.require(workLease)
        _ = try await start(container)
    }

    public func updateResources(_ container: ContainerRecord) async throws {
        let workLease = try serviceWork.begin()
        defer { serviceWork.end(workLease) }
        let epoch = serviceGeneration
        try requireServiceGeneration(epoch)
        try requireExactContainerOwnership(container)
        guard container.phase != .paused else {
            throw EngineError(.conflict, "cannot update resources while container \(container.id) is paused")
        }
        if container.phase != .running {
            try await managedStorage?.retire(containerID: container.id, instanceID: container.instanceID)
            try requireServiceGeneration(epoch)
            guard let originalShim = shims[container.id] else {
                // A daemon can crash after terminating the old stopped shim but
                // before registering its candidate. The persisted preparation
                // and writable root remain authoritative; reconstruct the old
                // journal-selected capacity instead of treating absence as a
                // reason to delete the container directory.
                guard try await relaunchPreparedShim(container) != nil else {
                    throw EngineError(.notFound, "container VM preparation is unavailable")
                }
                try requireServiceGeneration(epoch)
        knownContainers[container.id] = container
                activeContainers.removeValue(forKey: container.id)
                return
            }
            try requireServiceGeneration(epoch)
        let containerDirectory = try containerStateDirectory(for: container.id)
            let originalPrepared = try Self.loadPreparedShimState(
                from: containerDirectory, expectedContainerID: container.id
            )
            let original = originalPrepared?.currentContainer
                ?? knownContainers[container.id] ?? container
            try await StoppedResourceReplacementTransaction.perform(
                terminateOriginal: {
                    try self.requireServiceGeneration(epoch)
                    try await self.terminateShim(container.id, shim: originalShim)
                },
                launchCandidate: {
                    try self.requireServiceGeneration(epoch)
                    guard try await self.relaunchPreparedShim(container) != nil else {
                        throw EngineError(.notFound, "container VM preparation is unavailable")
                    }
                },
                cleanupCandidate: {
                    try self.requireServiceGeneration(epoch)
                    try await self.terminateEveryShim(for: container.id)
                },
                restoreOriginal: {
                    try self.requireServiceGeneration(epoch)
                    try await self.terminateEveryShim(for: container.id)
                    try self.requireServiceGeneration(epoch)
                    guard try await self.relaunchPreparedShim(
                        original, preservingCapacityFrom: originalPrepared
                    ) != nil else {
                        throw EngineError(.notFound, "original container VM preparation is unavailable")
                    }
                    self.knownContainers[container.id] = original
                    self.activeContainers.removeValue(forKey: container.id)
                }
            )
            try requireServiceGeneration(epoch)
        knownContainers[container.id] = container
            activeContainers.removeValue(forKey: container.id)
            return
        }
        guard let shim = shims[container.id] else {
            throw EngineError(.notFound, "container VM shim is unavailable")
        }
        guard container.cpus <= shim.specification.cpus else {
            throw EngineError(
                .conflict,
                "requested CPU limit of \(container.cpus) exceeds running VM capacity of \(shim.specification.cpus); stop the container before increasing its VM capacity"
            )
        }
        let requiredMemoryBytes = try VirtualMachineMemory.capacity(forHardLimit: container.memoryBytes)
        guard requiredMemoryBytes <= shim.specification.memoryBytes else {
            throw EngineError(
                .conflict,
                "requested memory limit of \(container.memoryBytes) bytes exceeds running VM capacity of \(shim.specification.memoryBytes) bytes; stop the container before increasing its VM capacity"
            )
        }
        let directory = try containerStateDirectory(for: container.id)
        guard let prepared = try Self.loadPreparedShimState(
                from: directory, expectedContainerID: container.id
              ),
              prepared.specification == shim.specification,
              prepared.currentContainer.id == container.id,
              prepared.currentContainer.instanceID == container.instanceID else {
            throw EngineError(
                .conflict, "running VM shim does not match its durable preparation"
            )
        }
        let original = prepared.currentContainer
        do {
            try await LiveResourceCanonicalTransaction.perform(
                applyDesired: {
                    try self.requireServiceGeneration(epoch)
                    try await self.applyLiveResources(
                        container,
                        shim: shim,
                        compatibilityFailureAfterWrites:
                            try Self.compatibilityResourceFailureAfterWrites(
                                containerID: container.id
                            )
                    )
                },
                persistDesired: {
                    try self.requireServiceGeneration(epoch)
                    try self.persistPreparedShimState(
                        container: container,
                        specification: prepared.specification,
                        artifacts: prepared.artifacts,
                        expectedDirectoryIdentity: prepared.directoryIdentity
                    )
                },
                applyOriginal: {
                    try self.requireServiceGeneration(epoch)
                    try await self.applyLiveResources(
                        original, shim: shim, compatibilityFailureAfterWrites: nil
                    )
                },
                persistOriginal: {
                    try self.requireServiceGeneration(epoch)
                    try self.persistPreparedShimState(
                        container: original,
                        specification: prepared.specification,
                        artifacts: prepared.artifacts,
                        expectedDirectoryIdentity: prepared.directoryIdentity
                    )
                }
            )
        } catch {
            try requireServiceGeneration(epoch)
            knownContainers[container.id] = original
            activeContainers[container.id] = original
            throw error
        }
        try requireServiceGeneration(epoch)
        knownContainers[container.id] = container
        activeContainers[container.id] = container
    }

    private func applyLiveResources(
        _ container: ContainerRecord,
        shim: VMShimClient,
        compatibilityFailureAfterWrites: UInt32?
    ) async throws {
        let resources = GuestProtocol.Resources(
            memoryBytes: container.memoryBytes,
            cpuQuota: try DockerCPUResources.quota(cpuCount: container.cpus),
            cpuPeriod: 100_000,
            pids: container.pidsLimit,
            blockIOReadBps: Self.blockIOThrottles(container.blockIOReadBps),
            blockIOWriteBps: Self.blockIOThrottles(container.blockIOWriteBps),
            blockIOReadIOps: Self.blockIOThrottles(container.blockIOReadIOps),
            blockIOWriteIOps: Self.blockIOThrottles(container.blockIOWriteIOps),
            devices: Self.devices(container.devices),
            deviceCgroupRules: try Self.deviceCgroupRules(container.deviceCgroupRules)
        )
        let update = GuestProtocol.ResourceUpdate(
            resources: resources,
            compatibilityFailureAfterWrites: compatibilityFailureAfterWrites
        )
        struct Status: Decodable { let status: String }
        let response: Status = try await shim.guest(
            operation: "update-resources", payload: update, response: Status.self
        )
        guard response.status == "running" else {
            throw EngineError(.conflict, "workload is not running")
        }
    }

    public func cleanupExecution(_ container: ContainerRecord) async throws {
        try await cleanupContainer(container, removingState: false)
    }

    public func delete(_ container: ContainerRecord) async throws {
        try await cleanupContainer(container, removingState: true)
    }

    private func cleanupContainer(_ container: ContainerRecord, removingState: Bool) async throws {
        let workLease = try serviceWork.begin()
        defer { serviceWork.end(workLease) }
        let epoch = serviceGeneration
        try requireServiceGeneration(epoch)
        try await managedStorage?.requireReconciled()
        try requireServiceGeneration(epoch)
        if let known = knownContainers[container.id], known.instanceID != container.instanceID {
            throw BackendResourceRollbackIncompleteError(
                "container \(container.id) cleanup belongs to a different instance"
            )
        }
        try RawContainerInstanceCoordinator.requireNoConflictingFreshPreparation(
            of: container, in: freshPreparationInstances
        )
        do {
            if !removingState, let managedStorage {
                try await managedStorage.settleExecution(container: container, in: containerStateDirectory(for: container.id))
            } else {
                try await managedStorage?.retire(containerID: container.id, instanceID: container.instanceID)
            }
        } catch {
            try requireServiceGeneration(epoch)
            try await terminateEveryShim(for: container.id, expectedInstanceID: container.instanceID, expectedServiceGeneration: epoch)
            throw error // Preserve the failed P and writable root for explicit replacement.
        }
        try requireServiceGeneration(epoch)
        let retainsManagedHistory = try await managedStorage?.hasIntents(containerID: container.id) ?? false
        try requireServiceGeneration(epoch)
        if removingState && !retainsManagedHistory {
            try completePendingContainerDeletionIfNeeded(container)
        } else if try containersStateDirectory.pendingDisposalIdentity(named: container.id) != nil {
            // Only a durable removal intent may finish destructive disposal.
            throw BackendResourceRollbackIncompleteError(
                "container \(container.id) retains an unresolved state-directory removal"
            )
        }
        guard let stateDirectory = try Self.matchingContainerStateDirectory(
            for: container.id,
            in: containersStateDirectory,
            retainedIdentities: containerDirectoryIdentities
        ) else {
            if try RawDeletedContainerCoordinator.hasReceipt(
                containerID: container.id, in: deletedContainersStateDirectory
            ) {
                try RawDeletedContainerCoordinator.requireCompletedDeletion(
                    of: container,
                    in: containersStateDirectory,
                    receipts: deletedContainersStateDirectory
                )
            } else {
                try RawContainerPreparationAttemptCoordinator.requireCleanAbsence(
                    container,
                    in: containersStateDirectory,
                    attempts: deletedContainersStateDirectory
                )
            }
            portForwarder.stop(containerID: container.id)
            portForwardingRegistrations.removeValue(forKey: container.id)
            completionTasks.removeValue(forKey: container.id)?.task.cancel()
            completions.removeValue(forKey: container.id)
            executionFence.remove(container.id)
            activeContainers.removeValue(forKey: container.id)
            knownContainers.removeValue(forKey: container.id)
            preparedBindSources.removeValue(forKey: container.id)
            clearExecArtifactCleanupFailures(for: container)
            purgeExecResources(for: container)
            try? logMonitors.removeValue(forKey: container.id)?.stop()
            bridges.removeValue(forKey: container.id)?.finishOutput()
            return
        }
        if try Self.exactPreparedShimState(for: container, in: stateDirectory) == nil {
            do {
                try RawContainerPreparationAttemptCoordinator.require(
                    container,
                    directoryIdentity: stateDirectory.identity,
                    in: deletedContainersStateDirectory
                )
            } catch {
                try RawContainerPreparationAttemptCoordinator.requireUnboundPartialState(
                    container,
                    stateDirectory: stateDirectory,
                    in: deletedContainersStateDirectory
                )
            }
        }
        containerDirectoryIdentities[container.id] = stateDirectory.identity
        let directoryIdentity = try containersStateDirectory.pendingDisposalIdentity(
            named: container.id
        ) ?? stateDirectory.identity
        portForwarder.stop(containerID: container.id)
        portForwardingRegistrations.removeValue(forKey: container.id)
        try await terminateEveryShim(for: container.id, expectedInstanceID: container.instanceID, expectedServiceGeneration: epoch)
        try requireServiceGeneration(epoch)
        try await managedStorage?.refreshTerminalContainment(container: container, in: stateDirectory)
        try requireServiceGeneration(epoch)
        guard stateDirectory.pathStillNamesThisDirectory(),
              knownContainers[container.id].map({ $0.instanceID == container.instanceID }) ?? true else {
            throw BackendResourceRollbackIncompleteError(
                "container \(container.id) ownership changed during execution cleanup"
            )
        }
        completionTasks.removeValue(forKey: container.id)?.task.cancel()
        completions.removeValue(forKey: container.id)
        executionFence.remove(container.id)
        activeContainers.removeValue(forKey: container.id)
        knownContainers.removeValue(forKey: container.id)
        preparedBindSources.removeValue(forKey: container.id)
        purgeExecResources(for: container)
        try? logMonitors.removeValue(forKey: container.id)?.stop()
        bridges.removeValue(forKey: container.id)?.finishOutput()
        if removingState {
            try Self.finalizeContainerRemoval(container, directoryIdentity: directoryIdentity,
                in: containersStateDirectory, receipts: deletedContainersStateDirectory,
                retainedIdentities: &containerDirectoryIdentities, retainingManagedHistory: retainsManagedHistory)
        }
        // Execution rollback retains the exact root, initialization history,
        // prepared-shim record and IO files for a later mount-only generation.
        clearExecArtifactCleanupFailures(for: container)
    }

    public func cleanupOrphans(keeping containerIDs: Set<String>) async throws {
        let workLease = try serviceWork.begin()
        defer { serviceWork.end(workLease) }
        try await managedStorage?.requireReconciled()
        try serviceWork.require(workLease)
        try containersStateDirectory.reconcileDisposals()
        for name in Array(containerDirectoryIdentities.keys) {
            if try containersStateDirectory.openDirectoryIfPresent(named: name) == nil {
                containerDirectoryIdentities.removeValue(forKey: name)
            }
        }
        var persistedIDs = Set<String>()
        for name in try containersStateDirectory.entryNames() {
            let directory = try containersStateDirectory.openDirectory(named: name)
            if let expected = containerDirectoryIdentities[name],
               expected != directory.identity {
                throw BackendResourceRollbackIncompleteError(
                    "container \(name) state directory identity changed during orphan cleanup"
                )
            }
            containerDirectoryIdentities[name] = directory.identity
            persistedIDs.insert(name)
        }
        let orphanIDs = Set(shims.keys).union(cleanupPendingShims.keys)
            .union(quarantinedShimGenerations.keys).union(persistedIDs)
            .filter { !containerIDs.contains($0) }
        for id in orphanIDs {
            let directory = try containerStateDirectory(for: id)
            portForwarder.stop(containerID: id)
            portForwardingRegistrations.removeValue(forKey: id)
            do { try await managedStorage?.retire(containerID: id) }
            catch {
                try serviceWork.require(workLease)
                try await terminateEveryShim(for: id)
                throw error // Keep root and journals; VM death is not storage drain.
            }
            try serviceWork.require(workLease)
            try await terminateEveryShim(for: id)
            try serviceWork.require(workLease)
            completionTasks.removeValue(forKey: id)?.task.cancel()
            completions.removeValue(forKey: id)
            executionFence.remove(id)
            activeContainers.removeValue(forKey: id)
            knownContainers.removeValue(forKey: id)
            preparedBindSources.removeValue(forKey: id)
            try? logMonitors.removeValue(forKey: id)?.stop()
            bridges.removeValue(forKey: id)?.finishOutput()
            if try await managedStorage?.hasIntents(containerID: id) != true {
                try serviceWork.require(workLease)
                try RawDiskJournalDirectory.requireSafeAutomaticRootDisposal(directory)
                try disposeContainerDirectory(id, expectedIdentity: directory.identity)
            }
        }
        for name in try deletedContainersStateDirectory.entryNames() {
            if name.hasSuffix(".json") {
                let containerID = String(name.dropLast(5))
                if !containerIDs.contains(containerID),
                   try await managedStorage?.hasIntents(containerID: containerID) != true {
                    try serviceWork.require(workLease)
                    try RawDeletedContainerCoordinator.removeReceipt(
                        containerID: containerID, from: deletedContainersStateDirectory
                    )
                }
            } else if name.hasSuffix(".preparation") {
                let containerID = String(name.dropLast(".preparation".count))
                if !containerIDs.contains(containerID),
                   try await managedStorage?.hasIntents(containerID: containerID) != true {
                    try serviceWork.require(workLease)
                    try RawContainerPreparationAttemptCoordinator.remove(
                        containerID: containerID, from: deletedContainersStateDirectory
                    )
                }
            }
        }
    }

    public func deleteVolume(_ name: String) async throws {
        throw RawManagedStorageBackend.failure("managed volume deletion requires its immutable instance UUID")
    }

    public func restoreNetworks(_ values: [NetworkRecord]) async throws -> [NetworkRecord] {
        var restored: [NetworkRecord] = []
        for value in values {
            if let existing = networks[value.id] { restored.append(existing) }
            else { restored.append(try await createNetwork(value)) }
        }
        try await synchronizeFabric()
        return restored
    }

    public func createNetwork(_ network: NetworkRecord) async throws -> NetworkRecord {
        if let existing = networks[network.id] { return existing }
        let vlan = try allocateVLAN()
        var value = network
        if value.enableIPv4, value.subnet.isEmpty {
            let automaticNetwork = automaticNetworkPool.ipv4Network(vlan: vlan)
            value.subnet = automaticNetwork.subnet
            value.gateway = automaticNetwork.gateway
        }
        if !value.enableIPv4 { value.subnet = ""; value.gateway = "" }
        if value.enableIPv6, value.ipv6Subnet.isEmpty {
            let automaticNetwork = automaticNetworkPool.ipv6Network(vlan: vlan)
            value.ipv6Subnet = automaticNetwork.subnet
            value.ipv6Gateway = automaticNetwork.gateway
        }
        if !value.enableIPv6 { value.ipv6Subnet = ""; value.ipv6Gateway = "" }
        let transaction = RawNetworkStateTransaction(
            adding: value,
            vlan: vlan,
            networks: networks,
            networkVLANs: networkVLANs
        )
        transaction.apply(networks: &networks, networkVLANs: &networkVLANs)
        do {
            // Reserve and configure vmnet before making the new network durable.
            // If either stage fails, restore both dictionaries and the previous
            // fabric so a failed create cannot consume a VLAN or reappear after
            // daemon recovery.
            try await synchronizeFabric()
            try persistNetworks()
        } catch {
            transaction.rollback(networks: &networks, networkVLANs: &networkVLANs)
            try? await synchronizeFabric()
            try? persistNetworks()
            throw error
        }
        return value
    }

    public func deleteNetwork(_ network: NetworkRecord) async throws {
        networks.removeValue(forKey: network.id)
        networkVLANs.removeValue(forKey: network.id)
        try persistNetworks()
        try await synchronizeFabric()
    }

    public func updateNetworkRecords(_ containers: [ContainerRecord]) async throws {
        let workLease = try serviceWork.begin()
        defer { serviceWork.end(workLease) }
        guard !serviceMaintenance else { throw RawManagedStorageBackend.failure() }
        try RawNetworkRefreshOwnershipGuard.require(
            containers,
            knownContainers: knownContainers,
            quarantinedGenerationCounts: quarantinedShimGenerations.mapValues(\.count),
            cleanupPendingGenerationCounts: cleanupPendingShims.mapValues(\.count)
        )
        knownContainers = Dictionary(uniqueKeysWithValues: containers.map { ($0.id, $0) })
        activeContainers = Dictionary(uniqueKeysWithValues: containers.filter { $0.phase == .running || $0.phase == .paused }.map { ($0.id, $0) })
        for container in containers {
            try serviceWork.require(workLease)
            guard activeContainers[container.id] != nil, let shim = shims[container.id],
                  (try? await shim.status().state) == .running else { continue }
            try serviceWork.require(workLease)
            let desired = Set(container.networks.map(\.networkID))
            let existing = appliedNetworks[container.id] ?? []
            struct NetworkRequest: Encodable { let endpoint: GuestProtocol.NetworkEndpoint?; let name: String? }
            struct Status: Decodable { let status: String }
            _ = try await shim.configureNetwork(vlans: desired.compactMap { networkVLANs[$0] } + [VMShimProtocol.managementVLAN])
            try serviceWork.require(workLease)
            for id in existing.subtracting(desired) {
                _ = try? await shim.guest(operation: "disconnect-network", payload: NetworkRequest(endpoint: nil, name: id), response: Status.self)
                try serviceWork.require(workLease)
            }
            for endpoint in networkEndpoints(container) where !existing.contains(endpoint.networkID) {
                _ = try await shim.guest(operation: "connect-network", payload: NetworkRequest(endpoint: endpoint, name: nil), response: Status.self)
                try serviceWork.require(workLease)
            }
            appliedNetworks[container.id] = desired
        }
        try serviceWork.require(workLease)
        try await synchronizeFabric()
        try serviceWork.require(workLease)
    }

    public func endpointAddresses(for container: ContainerRecord) async -> [String: BackendEndpointAddress] {
        Dictionary(uniqueKeysWithValues: container.networks.map {
            ($0.networkID, BackendEndpointAddress(ipv4Address: $0.ipv4Address ?? "", ipv6Address: $0.ipv6Address ?? ""))
        })
    }

    public func statistics(_ container: ContainerRecord) async throws -> BackendStatistics {
        try requireExactContainerOwnership(container)
        guard let shim = shims[container.id] else { throw EngineError(.notFound, "container VM shim is unavailable") }
        struct Network: Decodable { let name: String; let rxBytes, rxPackets, rxErrors, txBytes, txPackets, txErrors: UInt64 }
        struct BlockIO: Decodable { let major, minor: Int; let readBytes, writeBytes: UInt64 }
        struct Value: Decodable {
            let cpuTotalNanoseconds, cpuUserNanoseconds, cpuSystemNanoseconds: UInt64
            let cpuPeriods, cpuThrottledPeriods, cpuThrottledNanoseconds: UInt64
            let memoryUsage, memoryPeak, memoryCache, pids, blockReadBytes, blockWriteBytes: UInt64
            let blockIO: [BlockIO]; let networks: [Network]
        }
        struct Empty: Encodable {}
        let value: Value = try await shim.guest(operation: "statistics", payload: Empty(), response: Value.self)
        return .init(
            cpuTotalNanoseconds: value.cpuTotalNanoseconds,
            cpuUserNanoseconds: value.cpuUserNanoseconds,
            cpuSystemNanoseconds: value.cpuSystemNanoseconds,
            memoryUsage: value.memoryUsage, memoryLimit: container.memoryBytes,
            memoryCache: value.memoryCache, pids: value.pids,
            blockReadBytes: value.blockReadBytes, blockWriteBytes: value.blockWriteBytes,
            networks: value.networks.map { .init(name: $0.name, rxBytes: $0.rxBytes, rxPackets: $0.rxPackets, rxErrors: $0.rxErrors, txBytes: $0.txBytes, txPackets: $0.txPackets, txErrors: $0.txErrors) },
            memoryPeak: value.memoryPeak,
            blockIO: value.blockIO.map { .init(
                major: $0.major, minor: $0.minor, readBytes: $0.readBytes, writeBytes: $0.writeBytes
            ) },
            cpuPeriods: value.cpuPeriods,
            cpuThrottledPeriods: value.cpuThrottledPeriods,
            cpuThrottledNanoseconds: value.cpuThrottledNanoseconds
        )
    }

    public func top(_ container: ContainerRecord, arguments: [String]) async throws -> (titles: [String], processes: [[String]]) {
        try requireExactContainerOwnership(container)
        guard let shim = shims[container.id] else { throw EngineError(.notFound, "container VM shim is unavailable") }
        struct ProcessValue: Decodable { let pid: Int; let user: String; let command: String }; struct Empty: Encodable {}
        let values: [ProcessValue] = try await shim.guest(operation: "top", payload: Empty(), response: [ProcessValue].self)
        return (["UID", "PID", "CMD"], values.map { [$0.user, String($0.pid), $0.command] })
    }

    public func copyIn(_ container: ContainerRecord, extractedDirectory: URL, destination: String, ownership: [ArchiveOwnership]) async throws {
        let workLease = try serviceWork.begin()
        defer { serviceWork.end(workLease) }
        try requireExactContainerOwnership(container)
        guard let shim = shims[container.id] else { throw EngineError(.notFound, "container VM shim is unavailable") }
        let containerDirectory = try containerStateDirectory(for: container.id)
        guard let prepared = try Self.loadPreparedShimState(
            from: containerDirectory, expectedContainerID: container.id
        ), Self.copyPreparationMatches(
            container, prepared: prepared, shimSpecification: shim.specification
        ) else {
            throw EngineError(.conflict, "container copy does not match durable preparation")
        }
        let ioDirectory = try containerDirectory.openDirectory(named: "io")
        guard ioDirectory.identity == prepared.artifacts.ioDirectoryIdentity else {
            throw EngineError(.conflict, "container copy I/O directory changed")
        }
        let transfer = UUID().uuidString
        let transferDirectory = try ioDirectory.createDirectory(named: transfer)
        defer {
            try? ioDirectory.disposeDirectory(
                named: transfer, expectedIdentity: transferDirectory.identity
            )
        }
        let extracted = try PersistentStateDirectory.open(extractedDirectory)
        try RawDirectoryTransfer.copyContents(from: extracted, to: transferDirectory) {
            guard extracted.pathStillNamesThisDirectory(),
                  transferDirectory.pathStillNamesThisDirectory(),
                  let current = try ioDirectory.entryMetadata(named: transfer),
                  current.identity == transferDirectory.identity,
                  current.type == S_IFDIR else {
                throw EngineError(.conflict, "container copy transfer directory changed")
            }
        }
        let generation = executionFence.currentOrInstall(container.id)
        try await Self.copyInToShim(shim, phase: container.phase, source: transfer,
            destination: destination, ownership: ownership, validate: {
                try await self.validateCopyIn(container, shim: shim, generation: generation,
                    prepared: prepared, directory: containerDirectory, transfer: transferDirectory)
            })
    }

    nonisolated static func copyInToShim(_ shim: VMShimClient, phase: ContainerPhase,
        source: String, destination: String, ownership: [ArchiveOwnership],
        validate: @Sendable () async throws -> Void) async throws {
        struct Owner: Encodable { let path: String; let user: UInt32; let group: UInt32 }
        struct Request: Encodable { let source: String; let destination: String; let ownership: [Owner] }
        struct Status: Decodable { let status: String }
        try await validate()
        switch phase {
        case .running:
            // Public boot is deliberately forbidden for managed workloads. Copy
            // uses only the already configured launch; status cannot grant boot
            // or mount authority and every exchange retains its native proof.
            let status = try await shim.status()
            try await validate()
            guard status.state == .running else {
                throw EngineError(.conflict, "archive copy requires a running VM guest")
            }
        case .created:
            guard shim.specification.workloadStorageMode == .none else {
                throw EngineError(.conflict, "archive copy requires an active managed storage workload")
            }
            _ = try await shim.boot()
            try await validate()
        case .paused, .exited, .dead:
            throw EngineError(.conflict, "archive copy requires a created or running container")
        }
        _ = try await shim.guest(operation: "copy-in", payload: Request(source: source,
            destination: destination, ownership: ownership.map {
                .init(path: $0.path, user: $0.user, group: $0.group)
            }), response: Status.self)
        try await validate()
        if phase == .created { _ = try? await shim.stop() }
    }

    private func validateCopyIn(_ container: ContainerRecord, shim: VMShimClient,
        generation: RawBackendExecutionFence.Token, prepared: PreparedShimState,
        directory: PersistentStateDirectory, transfer: PersistentStateDirectory) throws {
        try requireExactContainerOwnership(container)
        try requireExecutionGeneration(container.id, generation: generation)
        guard shims[container.id] === shim else {
            throw EngineError(.conflict, "container copy VM shim changed")
        }
        if container.phase == .running { try requireActiveContainerExecution(container) }
        try prepared.artifacts.validate(in: directory)
        guard transfer.pathStillNamesThisDirectory() else {
            throw EngineError(.conflict, "container copy transfer directory changed")
        }
    }

    public func copyOut(_ container: ContainerRecord, source: String, destinationDirectory: URL) async throws {
        let workLease = try serviceWork.begin()
        defer { serviceWork.end(workLease) }
        try requireExactContainerOwnership(container)
        guard let shim = shims[container.id] else { throw EngineError(.notFound, "container VM shim is unavailable") }
        let containerDirectory = try containerStateDirectory(for: container.id)
        guard let prepared = try Self.loadPreparedShimState(
            from: containerDirectory, expectedContainerID: container.id
        ), Self.copyPreparationMatches(
            container, prepared: prepared, shimSpecification: shim.specification
        ) else {
            throw EngineError(.conflict, "container copy does not match durable preparation")
        }
        let ioDirectory = try containerDirectory.openDirectory(named: "io")
        guard ioDirectory.identity == prepared.artifacts.ioDirectoryIdentity else {
            throw EngineError(.conflict, "container copy I/O directory changed")
        }
        let transfer = UUID().uuidString
        let transferDirectory = try ioDirectory.createDirectory(named: transfer)
        defer {
            try? ioDirectory.disposeDirectory(
                named: transfer, expectedIdentity: transferDirectory.identity
            )
        }
        try prepared.artifacts.validate(in: containerDirectory)
        struct Request: Encodable { let source: String; let destination: String }; struct Status: Decodable { let status: String }
        _ = try await shim.guest(operation: "copy-out", payload: Request(source: source, destination: transfer), response: Status.self)
        try serviceWork.require(workLease)
        try prepared.artifacts.validate(in: containerDirectory)
        let destination = try PersistentStateDirectory.open(destinationDirectory)
        try RawDirectoryTransfer.copyContents(from: transferDirectory, to: destination) {
            guard destination.pathStillNamesThisDirectory(),
                  transferDirectory.pathStillNamesThisDirectory(),
                  let current = try ioDirectory.entryMetadata(named: transfer),
                  current.identity == transferDirectory.identity,
                  current.type == S_IFDIR else {
                throw EngineError(.conflict, "container copy transfer directory changed")
            }
        }
    }

    private func resolvedImage(_ reference: String, platform: String) async throws -> OCIStoredImage {
        if let value = try? await store.image(reference: reference, platform: platform) { return value }
        return try await pull(reference, platform: platform, credentials: nil) { _ in }
    }

    private func recordCompletion(
        _ container: ContainerRecord,
        code: Int32,
        generation: RawBackendExecutionFence.Token
    ) async throws -> Int32 {
        if executionFence.owns(container.id, token: generation), let managedStorage {
            try await managedStorage.retire(containerID: container.id, instanceID: container.instanceID)
            try requireExecutionGeneration(container.id, generation: generation)
        }
        return try await RawCompletionPublisher.run(
            fence: executionFence,
            identifier: container.id,
            generation: generation,
            publish: {
                if let existing = completions[container.id] {
                    return RawCompletionPublication(
                        value: existing, synchronizeFabric: false
                    )
                }
                // Final output publication is the first completion boundary.
                // Every monitor remains owned in its dictionary until all
                // drains succeed, so a failure retries exact source offsets.
                let containerMonitor = logMonitors[container.id]
                try RawCompletionDrainCoordinator.drain(
                    container: { try containerMonitor?.stop() },
                    execSessions: {
                        if let shim = shims[container.id] {
                            try finishExecSessions(using: shim)
                        }
                    }
                )
                if let containerMonitor,
                   logMonitors[container.id] === containerMonitor {
                    logMonitors.removeValue(forKey: container.id)
                }
                if completionTasks[container.id]?.generation == generation {
                    completionTasks.removeValue(forKey: container.id)
                }
                completions[container.id] = code
                activeContainers.removeValue(forKey: container.id)
                if let forwarding = portForwardingRegistrations[container.id],
                   forwarding.generation == generation {
                    portForwardingRegistrations.removeValue(forKey: container.id)
                    portForwarder.stop(
                        containerID: container.id, registration: forwarding.registration
                    )
                }
                return RawCompletionPublication(value: code, synchronizeFabric: true)
            },
            synchronizeFabric: { try? await self.synchronizeFabric() }
        ) ?? code
    }

    private func requireExecutionGeneration(
        _ identifier: String,
        generation: RawBackendExecutionFence.Token
    ) throws {
        guard !serviceMaintenance, executionFence.owns(identifier, token: generation) else {
            throw EngineError(.conflict, "container \(identifier) execution was replaced while starting")
        }
    }

    /// Every operation that can observe or mutate a container execution must
    /// first prove that exactly one generation owns this container instance
    /// and writable root. A canonical shim is not sufficient while any sibling
    /// generation still has unresolved termination evidence.
    private func requireExactContainerOwnership(_ container: ContainerRecord) throws {
        guard !serviceMaintenance else { throw RawManagedStorageBackend.failure() }
        try RawExactContainerOwnershipGuard.require(
            container,
            knownInstanceID: knownContainers[container.id]?.instanceID,
            quarantinedGenerationCount:
                (quarantinedShimGenerations[container.id] ?? []).count,
            cleanupPendingGenerationCount:
                (cleanupPendingShims[container.id] ?? []).count
        )
    }

    private func requireActiveContainerExecution(
        _ container: ContainerRecord
    ) throws {
        guard !serviceMaintenance else { throw RawManagedStorageBackend.failure() }
        try RawActiveContainerExecutionGuard.require(
            container,
            activeInstanceID: activeContainers[container.id]?.instanceID,
            hasCompletion: completions[container.id] != nil
        )
    }

    private func normalizedExecPreparationError(
        _ error: Error,
        container: ContainerRecord,
        shim: VMShimClient
    ) async -> Error {
        if (try? requireActiveContainerExecution(container)) == nil {
            return EngineError(
                .conflict, "Container \(container.id) is not running"
            )
        }
        struct Empty: Encodable {}
        struct Status: Decodable { let status: String }
        if let status: Status = try? await shim.guest(
            operation: "status", payload: Empty(), response: Status.self
        ), status.status != "running" {
            return EngineError(
                .conflict, "Container \(container.id) is not running"
            )
        }
        if (try? requireActiveContainerExecution(container)) == nil {
            return EngineError(
                .conflict, "Container \(container.id) is not running"
            )
        }
        return error
    }

    private func requireExactExecOwnership(_ exec: ExecRecord) throws {
        guard let container = knownContainers[exec.containerID],
              container.instanceID == exec.containerInstanceID else {
            throw BackendResourceRollbackIncompleteError(
                "exec \(exec.id) backend state belongs to a different container instance"
            )
        }
        try requireExactContainerOwnership(container)
    }

    private func finishExecSessions(using shim: VMShimClient) throws {
        let identifiers = execShims.compactMap { identifier, value in
            value === shim ? identifier : nil
        }
        var stopped: [(String, ContainerLogMonitor)] = []
        for identifier in identifiers {
            if let monitor = execMonitors[identifier] {
                try monitor.stop()
                stopped.append((identifier, monitor))
            } else {
                execBridges[identifier]?.finishOutput()
            }
        }
        for (identifier, monitor) in stopped where execMonitors[identifier] === monitor {
            execMonitors.removeValue(forKey: identifier)
        }
    }

    private func purgeExecResources(for container: ContainerRecord) {
        let identifiers = execOwners.compactMap { identifier, owner in
            owner.containerID == container.id
                    && owner.containerInstanceID == container.instanceID
                ? identifier : nil
        }
        for identifier in identifiers {
            try? execMonitors.removeValue(forKey: identifier)?.stop()
            execBridges.removeValue(forKey: identifier)?.freezeCompleted()
            execShims.removeValue(forKey: identifier)
            execOwners.removeValue(forKey: identifier)
            completedExecSnapshotBudget.remove(execID: identifier)
            execRetirementDeadlines.removeValue(forKey: identifier)
        }
        _ = completedExecSnapshotBudget.remove(
            containerID: container.id, instanceID: container.instanceID
        )
    }

    private func terminateShim(_ containerID: String, shim: VMShimClient,
        expectedExecutionGeneration: RawBackendExecutionFence.Token? = nil) async throws {
        let destructiveLease = destructiveTerminationWork.retainDestructiveWork()
        defer { destructiveTerminationWork.end(destructiveLease) }
        let directory = try containerStateDirectory(for: containerID)
        guard shim.ownsPersistedContainer(
            id: containerID, directoryIdentity: directory.identity
        ) else {
            throw BackendResourceRollbackIncompleteError(
                "refusing to signal a VM shim without exact container-directory ownership"
            )
        }
        let epoch = serviceGeneration
        if RawTrackedShimLaunch.ownsCompletion(captured: shim, current: shims[containerID],
            generation: expectedExecutionGeneration ?? executionFence.current(containerID), completion: completionTasks[containerID]?.generation) {
            completionTasks.removeValue(forKey: containerID)?.task.cancel()
        }
        try finishExecSessions(using: shim)
        try await shim.terminate()
        guard epoch == serviceGeneration else { return }
        for identifier in execShims.compactMap({ identifier, value in
            value === shim ? identifier : nil
        }) {
            execShims.removeValue(forKey: identifier)
        }
        if managedStorage == nil { try shim.removePersistentLaunchArtifacts() }
        if shims[containerID] === shim { shims.removeValue(forKey: containerID) }
        removeCleanupPendingShim(shim, for: containerID)
    }

    private func launchTrackedShim(
        _ specification: VMShimProtocol.Specification,
        container: ContainerRecord,
        expectedLogIdentity: PersistentFileIdentity
    ) async throws -> VMShimClient {
        let epoch = serviceGeneration
        try requireServiceGeneration(epoch)
        let lease = try nativeLaunchWork.begin()
        defer { nativeLaunchWork.end(lease) }
        guard specification.containerID == container.id else {
            throw EngineError(.conflict, "VM shim launch container identity mismatch")
        }
        let directory = try containerStateDirectory(for: specification.containerID)
        return try await RawTrackedShimLaunch.run(launch: {
            try await VMShimClient.launchPersisted(specification: specification, container: container,
                containerDirectory: directory, expectedLogIdentity: expectedLogIdentity)
        }, failedClient: { ($0 as? VMShimLaunchRollbackIncompleteError)?.client }, validate: { client in
            try self.requireServiceGeneration(epoch)
            guard client.hasPersistentLaunchRecord,
                  client.ownsPersistedContainer(id: container.id, directoryIdentity: directory.identity) else {
                throw EngineError(.conflict, "VM shim generation ownership disappeared while launching")
            }
        }, cleanup: { client in
            try await client.terminate()
            if self.managedStorage == nil { try client.removePersistentLaunchArtifacts() }
        }, retain: { client in
            // A stale callback never adds ownership to the successor. On failure
            // the immutable launch record remains in the fenced final census.
            guard self.serviceGeneration == epoch, !self.serviceMaintenance else { return }
            self.retainCleanupPendingShim(client, for: container.id)
        })
    }

    private func retainCleanupPendingShim(_ shim: VMShimClient, for containerID: String) {
        guard !(cleanupPendingShims[containerID] ?? []).contains(where: {
            $0.persistentOwnershipKey == shim.persistentOwnershipKey
        }) else { return }
        cleanupPendingShims[containerID, default: []].append(shim)
    }

    private func removeCleanupPendingShim(_ shim: VMShimClient, for containerID: String) {
        guard var pending = cleanupPendingShims[containerID] else { return }
        pending.removeAll { $0.persistentOwnershipKey == shim.persistentOwnershipKey }
        cleanupPendingShims[containerID] = pending.isEmpty ? nil : pending
    }

    /// Terminate both the published shim and every launch generation that
    /// failed before publication. Failed clients remain registered so a later
    /// containment retry still owns the exact PID/socket identity. Callers may
    /// remove the writable root only after this returns successfully.
    private func terminateEveryShim(for containerID: String, expectedInstanceID: UUID? = nil,
        expectedServiceGeneration: UUID? = nil) async throws {
        let epoch = expectedServiceGeneration ?? serviceGeneration
        guard epoch == serviceGeneration else { throw RawManagedStorageBackend.failure() }
        let instanceID = expectedInstanceID ?? knownContainers[containerID]?.instanceID
        let containerDirectory: PersistentStateDirectory
        do {
            containerDirectory = try containerStateDirectory(for: containerID)
        } catch {
            throw BackendResourceRollbackIncompleteError(
                "cannot verify container \(containerID) state before shim cleanup: "
                    + EngineError.message(for: error)
            )
        }
        let registered = shims[containerID]
        let persisted = try VMShimClient.persistedLaunches(
            in: containerDirectory,
            expectedContainerID: containerID,
            expectedInstanceID: instanceID
        )
        quarantinedShimGenerations[containerID] = persisted.quarantined.isEmpty
            ? nil : persisted.quarantined
        let persistedClients = persisted.map(\.client)
        let pending = (cleanupPendingShims[containerID] ?? []) + persistedClients
        var seen = Set<String>()
        var failures: [String] = []
        var retained: [VMShimClient] = []

        if !persisted.quarantined.isEmpty {
            failures.append(
                "\(persisted.quarantined.count) quarantined shim generation(s) retain unresolved ownership"
            )
        }

        if let registered {
            seen.insert(registered.persistentOwnershipKey)
            do {
                try await terminateShim(containerID, shim: registered)
            } catch {
                retained.append(registered)
                failures.append("registered shim: \(EngineError.message(for: error))")
            }
        }
        for candidate in pending where seen.insert(candidate.persistentOwnershipKey).inserted {
            guard epoch == serviceGeneration else { throw RawManagedStorageBackend.failure() }
            guard candidate.ownsPersistedContainer(
                id: containerID, directoryIdentity: containerDirectory.identity
            ) else {
                retained.append(candidate)
                failures.append(
                    "refused shim generation \(candidate.specification.generation) with mismatched container ownership"
                )
                continue
            }
            do {
                try await candidate.terminate()
                if managedStorage == nil { try candidate.removePersistentLaunchArtifacts() }
            } catch {
                retained.append(candidate)
                failures.append(
                    "unpublished shim generation \(candidate.specification.generation): "
                        + EngineError.message(for: error)
                )
            }
        }
        guard epoch == serviceGeneration else { throw RawManagedStorageBackend.failure() }
        cleanupPendingShims[containerID] = retained.isEmpty ? nil : retained
        if failures.isEmpty {
            let remaining = try VMShimClient.persistedLaunches(
                in: containerDirectory,
                expectedContainerID: containerID,
                expectedInstanceID: instanceID
            )
            quarantinedShimGenerations[containerID] = remaining.quarantined.isEmpty
                ? nil : remaining.quarantined
            let unexpected = remaining.filter { managedStorage == nil || !seen.contains($0.client.persistentOwnershipKey) }
            if !unexpected.isEmpty || !remaining.quarantined.isEmpty {
                failures.append("new shim generations appeared while cleanup was in progress")
                for launch in unexpected {
                    retainCleanupPendingShim(launch.client, for: containerID)
                }
            }
        }
        guard failures.isEmpty else {
            throw BackendResourceRollbackIncompleteError(
                "VM shim cleanup for container \(containerID) was incomplete ("
                    + failures.joined(separator: "; ") + ")"
            )
        }
    }

    private func ensureIO(_ container: ContainerRecord, replacingStoppedSession: Bool = false,
                          preservingExistingFiles: Bool = false) throws -> ContainerIOBridge {
        if let existing = bridges[container.id] {
            if !replacingStoppedSession || logMonitors[container.id] != nil { return existing }
            existing.finishOutput()
            bridges.removeValue(forKey: container.id)
        }
        let containerDirectory = try containerStateDirectory(for: container.id)
        guard let prepared = try Self.loadPreparedShimState(
            from: containerDirectory, expectedContainerID: container.id
        ), prepared.currentContainer.instanceID == container.instanceID else {
            throw EngineError(
                .conflict,
                "container direct-I/O does not match its durable preparation"
            )
        }
        let handles = try RawContainerDirectIOHandles.open(
            in: containerDirectory, artifacts: prepared.artifacts
        )
        let logs = try handles.openDockerLogs(artifacts: prepared.artifacts)
        try handles.validateNames(artifacts: prepared.artifacts)
        let bridge = ContainerIOBridge(
            tty: container.tty,
            logHandle: logs.log,
            logIndexHandle: logs.index,
            journalDirectory: logs.journalDirectory
        )
        if !preservingExistingFiles {
            try handles.resetSourceSession(
                artifacts: prepared.artifacts,
                openStdin: container.openStdin,
                bridge: bridge
            )
        }
        let stdinClosed = handles.stdinClosed
        let monitor = ContainerLogMonitor(
            stdout: handles.stdout,
            stderr: handles.stderr,
            input: handles.stdin,
            bridge: bridge,
            stdoutSpoolDirectory: handles.stdoutSpool,
            stderrSpoolDirectory: handles.stderrSpool,
            spoolSegmentBytes: ContainerLogRetentionPolicy.default.segmentBytes,
            spoolMaximumSegments: ContainerLogRetentionPolicy.default.maximumSegments,
            markInputClosed: {
                try RawContainerDirectIOHandles.markInputClosed(stdinClosed)
            }
        )
        bridges[container.id] = bridge; logMonitors[container.id] = monitor
        monitor.start(atEnd: preservingExistingFiles)
        return bridge
    }

    private func restoreLiveContainer(_ container: ContainerRecord) async throws {
        preparedBindSources[container.id] = try HostBindSourceResolver(
            root: root.appending(path: "bind-sources")
        ).resolve(container.mounts)
        _ = try ensureIO(container, preservingExistingFiles: true)
        var active = container
        if !container.ports.isEmpty {
            guard let shim = shims[container.id] else {
                throw EngineError(.notFound, "container VM shim is unavailable")
            }
            let hasIPv4 = container.networks.contains { $0.ipv4Address != nil }
            guard hasIPv4 || container.networks.contains(where: { $0.ipv6Address != nil }) else {
                throw EngineError(.conflict, "published ports require a container network endpoint")
            }
            let generation = executionFence.currentOrInstall(container.id)
            let registration = PortForwarder.Registration()
            active.ports = try await portForwarder.start(
                containerID: container.id,
                registration: registration,
                bindings: container.ports,
                connect: { binding in
                    try await shim.startPortStream(
                        transport: binding.proto.lowercased(),
                        port: binding.containerPort,
                        ipv6: !hasIPv4
                    )
                }
            )
            guard executionFence.owns(container.id, token: generation) else {
                portForwarder.stop(containerID: container.id, registration: registration)
                try requireExecutionGeneration(container.id, generation: generation)
                return
            }
            if let previous = portForwardingRegistrations.updateValue(
                (generation, registration), forKey: container.id
            ) {
                portForwarder.stop(containerID: container.id, registration: previous.registration)
            }
        }
        knownContainers[container.id] = active
        activeContainers[container.id] = active
    }

    private func pull(_ reference: String, platform: String, credentials: RegistryCredentials?, progress: @escaping ImagePullProgressHandler) async throws -> OCIStoredImage {
        try await store.pull(reference: reference, platform: platform, credentials: credentials, progress: progress)
    }

    static func generationsDirectory(for containerDirectory: URL) -> URL {
        containerDirectory.appending(path: "shim-generations", directoryHint: .isDirectory)
    }

    private func freshContainerStateDirectory(
        for container: ContainerRecord
    ) throws -> PersistentStateDirectory {
        let acquisition = try RawFreshContainerStateCoordinator.acquire(
            in: containersStateDirectory, containerID: container.id
        )
        let directory = acquisition.directory
        if acquisition.wasCreated {
            guard containerDirectoryIdentities[container.id] == nil else {
                throw BackendResourceRollbackIncompleteError(
                    "container \(container.id) state disappeared while its identity was retained"
                )
            }
            containerDirectoryIdentities[container.id] = directory.identity
            return directory
        }

        if let expected = containerDirectoryIdentities[container.id],
           expected != directory.identity {
            throw BackendResourceRollbackIncompleteError(
                "container \(container.id) state directory identity changed"
            )
        }
        containerDirectoryIdentities[container.id] = directory.identity
        guard try Self.loadPreparedShimState(
            from: directory, expectedContainerID: container.id
        ) == nil else {
            throw BackendResourceRollbackIncompleteError(
                "container \(container.id) prepared state was not safely relaunched"
            )
        }
        guard shims[container.id] == nil,
              (cleanupPendingShims[container.id] ?? []).isEmpty else {
            throw BackendResourceRollbackIncompleteError(
                "container \(container.id) retains live VM shim ownership"
            )
        }
        let ownership = try VMShimClient.persistedLaunches(
            in: directory,
            expectedContainerID: container.id,
            expectedInstanceID: container.instanceID
        )
        quarantinedShimGenerations[container.id] = ownership.quarantined.isEmpty
            ? nil : ownership.quarantined
        guard ownership.isEmpty, ownership.quarantined.isEmpty else {
            throw BackendResourceRollbackIncompleteError(
                "container \(container.id) state retains unresolved VM shim ownership"
            )
        }

        do {
            let replacement = try RawFreshContainerStateCoordinator.recreateUnclaimed(
                in: containersStateDirectory,
                containerID: container.id,
                existing: directory
            )
            containerDirectoryIdentities[container.id] = replacement.identity
            return replacement
        } catch {
            throw BackendResourceRollbackIncompleteError(
                "container \(container.id) unclaimed state could not be safely replaced: "
                    + EngineError.message(for: error)
            )
        }
    }

    private func containerStateDirectory(
        for containerID: String,
        createIfMissing: Bool = false
    ) throws -> PersistentStateDirectory {
        let directory = createIfMissing
            ? try containersStateDirectory.openOrCreateDirectory(named: containerID)
            : try containersStateDirectory.openDirectory(named: containerID)
        if let expected = containerDirectoryIdentities[containerID],
           expected != directory.identity {
            throw EngineError(
                .conflict,
                "container \(containerID) state directory identity changed"
            )
        }
        containerDirectoryIdentities[containerID] = directory.identity
        return directory
    }

    private func existingContainerStateDirectory(
        for containerID: String
    ) throws -> PersistentStateDirectory? {
        try Self.existingContainerStateDirectory(
            for: containerID,
            in: containersStateDirectory,
            retainedIdentities: &containerDirectoryIdentities
        )
    }

    static func existingContainerStateDirectory(
        for containerID: String,
        in containers: PersistentStateDirectory,
        retainedIdentities: inout [String: PersistentFileIdentity]
    ) throws -> PersistentStateDirectory? {
        guard let directory = try matchingContainerStateDirectory(
            for: containerID,
            in: containers,
            retainedIdentities: retainedIdentities
        ) else { return nil }
        retainedIdentities[containerID] = directory.identity
        return directory
    }

    static func matchingContainerStateDirectory(
        for containerID: String,
        in containers: PersistentStateDirectory,
        retainedIdentities: [String: PersistentFileIdentity]
    ) throws -> PersistentStateDirectory? {
        guard let directory = try RawPreparedShimStateLookup.existingContainerDirectory(
            in: containers, containerID: containerID
        ) else { return nil }
        if let expected = retainedIdentities[containerID],
           expected != directory.identity {
            throw EngineError(
                .conflict,
                "container \(containerID) state directory identity changed"
            )
        }
        return directory
    }

    static func exactPreparedShimState(
        for container: ContainerRecord,
        in directory: PersistentStateDirectory
    ) throws -> PreparedShimState? {
        guard let prepared = try loadPreparedShimState(
            from: directory, expectedContainerID: container.id
        ) else { return nil }
        guard prepared.currentContainer.instanceID == container.instanceID else {
            throw BackendResourceRollbackIncompleteError(
                "refused container \(container.id) state owned by a different instance"
            )
        }
        return prepared
    }

    private func completePendingContainerDeletionIfNeeded(
        _ container: ContainerRecord
    ) throws {
        try Self.completePendingContainerDeletion(
            of: container,
            in: containersStateDirectory,
            receipts: deletedContainersStateDirectory,
            retainedIdentities: &containerDirectoryIdentities
        )
    }

    static func completePendingContainerDeletion(
        of container: ContainerRecord,
        in containers: PersistentStateDirectory,
        receipts: PersistentStateDirectory,
        retainedIdentities: inout [String: PersistentFileIdentity]
    ) throws {
        if let pendingIdentity = try containers.pendingDisposalIdentity(
            named: container.id
        ) {
            try RawDeletedContainerCoordinator.requireRecordedDeletion(
                of: container,
                directoryIdentity: pendingIdentity,
                in: receipts
            )
            try disposeContainerDirectory(
                container.id,
                expectedIdentity: pendingIdentity,
                in: containers,
                retainedIdentities: &retainedIdentities
            )
            return
        }
        try reconcileDurablyCompletedContainerDeletion(
            of: container,
            in: containers,
            receipts: receipts,
            retainedIdentities: &retainedIdentities
        )
    }

    static func reconcileDurablyCompletedContainerDeletion(
        of container: ContainerRecord,
        in containers: PersistentStateDirectory,
        receipts: PersistentStateDirectory,
        retainedIdentities: inout [String: PersistentFileIdentity]
    ) throws {
        guard let retainedIdentity = retainedIdentities[container.id],
              try containers.openDirectoryIfPresent(named: container.id) == nil else { return }
        try RawDeletedContainerCoordinator.requireRecordedDeletion(
            of: container,
            directoryIdentity: retainedIdentity,
            in: receipts
        )
        guard try containers.pendingDisposalIdentity(named: container.id) == nil,
              try containers.openDirectoryIfPresent(named: container.id) == nil,
              try containers.containsDisposalClaim(identity: retainedIdentity) == false else {
            throw BackendResourceRollbackIncompleteError(
                "container \(container.id) state directory disposal remains incomplete"
            )
        }
        guard try containers.pendingDisposalIdentity(named: container.id) == nil,
              try containers.openDirectoryIfPresent(named: container.id) == nil,
              try containers.containsDisposalClaim(identity: retainedIdentity) == false else {
            throw BackendResourceRollbackIncompleteError(
                "container \(container.id) state changed while confirming disposal"
            )
        }
        if retainedIdentities[container.id] == retainedIdentity {
            retainedIdentities.removeValue(forKey: container.id)
        }
    }

    private func disposeContainerDirectory(
        _ containerID: String,
        expectedIdentity: PersistentFileIdentity
    ) throws {
        try Self.disposeContainerDirectory(
            containerID,
            expectedIdentity: expectedIdentity,
            in: containersStateDirectory,
            retainedIdentities: &containerDirectoryIdentities
        )
    }

    /// Called only after storage retirement and positive native termination.
    /// The managed journal's historical census outlives public container removal.
    static func finalizeContainerRemoval(_ container: ContainerRecord,
        directoryIdentity: PersistentFileIdentity, in containers: PersistentStateDirectory,
        receipts: PersistentStateDirectory, retainedIdentities: inout [String: PersistentFileIdentity],
        retainingManagedHistory: Bool) throws {
        guard retainedIdentities[container.id] == directoryIdentity,
              try containers.openDirectory(named: container.id).identity == directoryIdentity else {
            throw EngineError(.conflict, "container removal evidence changed")
        }
        try RawDeletedContainerCoordinator.record(container, directoryIdentity: directoryIdentity, in: receipts)
        if !retainingManagedHistory {
            try disposeContainerDirectory(container.id, expectedIdentity: directoryIdentity,
                in: containers, retainedIdentities: &retainedIdentities)
        }
        // Otherwise preserve ALL root/journal/native-generation bytes together.
        // A decoded removal receipt is not a replacement for native death proof.
    }

    static func disposeContainerDirectory(
        _ containerID: String,
        expectedIdentity: PersistentFileIdentity,
        in containers: PersistentStateDirectory,
        retainedIdentities: inout [String: PersistentFileIdentity],
        hook: PersistentDisposalHook? = nil
    ) throws {
        let pendingIdentity = try? containers.pendingDisposalIdentity(
            named: containerID
        )
        let retainedIdentity = retainedIdentities[containerID]
        guard retainedIdentity == nil || retainedIdentity == expectedIdentity,
              retainedIdentity == expectedIdentity || pendingIdentity == expectedIdentity else {
            throw BackendResourceRollbackIncompleteError(
                "container \(containerID) state directory ownership changed before disposal"
            )
        }
        do {
            try containers.disposeDirectory(
                named: containerID, expectedIdentity: expectedIdentity, hook: hook
            )
            if retainedIdentities[containerID] == expectedIdentity {
                retainedIdentities.removeValue(forKey: containerID)
            }
        } catch {
            throw BackendResourceRollbackIncompleteError(
                "container \(containerID) state directory disposal was incomplete: "
                    + EngineError.message(for: error)
            )
        }
    }

    static func preparedShimStateURL(for containerDirectory: URL) -> URL {
        containerDirectory.appending(path: "prepared-shim.json")
    }

    static func containerRecordsMatch(
        _ lhs: ContainerRecord, _ rhs: ContainerRecord
    ) throws -> Bool {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let left = try encoder.encode(lhs)
        let right = try encoder.encode(rhs)
        return left == right
    }

    static func launchSpecificationMatchesPrepared(
        _ specification: VMShimProtocol.Specification,
        prepared: PreparedShimState
    ) -> Bool {
        specification == prepared.specification
    }

    static func copyPreparationMatches(
        _ container: ContainerRecord,
        prepared: PreparedShimState,
        shimSpecification: VMShimProtocol.Specification
    ) -> Bool {
        prepared.currentContainer.instanceID == container.instanceID
            && prepared.specification == shimSpecification
    }

    static func launchRecordMatchesPrepared(
        _ record: VMShimClient.PersistentLaunchRecord,
        prepared: PreparedShimState
    ) -> Bool {
        launchSpecificationMatchesPrepared(record.specification, prepared: prepared)
            && record.container.id == prepared.currentContainer.id
            && record.container.instanceID == prepared.currentContainer.instanceID
    }

    static func relaunchCapacitySpecification(
        for container: ContainerRecord,
        prepared: PreparedShimState,
        preserving preserved: PreparedShimState? = nil
    ) throws -> VMShimProtocol.Specification? {
        if let preserved {
            guard preserved.directoryIdentity == prepared.directoryIdentity,
                  preserved.artifacts == prepared.artifacts,
                  preserved.currentContainer.id == container.id,
                  preserved.currentContainer.instanceID == container.instanceID,
                  prepared.currentContainer.instanceID == container.instanceID,
                  preserved.specification.containerID == container.id else {
                throw EngineError(.conflict, "invalid preserved VM shim capacity")
            }
            return preserved.specification
        }
        return try containerRecordsMatch(container, prepared.currentContainer)
            ? prepared.specification : nil
    }

    static func loadPreparedShimState(from containerDirectory: URL) throws -> PreparedShimState? {
        let directory = try PersistentStateDirectory.open(containerDirectory)
        return try loadPreparedShimState(from: directory)
    }

    static func loadPreparedShimState(
        from directory: PersistentStateDirectory,
        expectedContainerID: String? = nil
    ) throws -> PreparedShimState? {
        guard let data = try directory.readRegularFile(
            named: "prepared-shim.json", required: false
        ) else { return nil }
        let url = preparedShimStateURL(for: directory.url)
        let state = try JSONDecoder().decode(
            PreparedShimState.self, from: data
        )
        let ioShares = state.specification.bindShares.filter { $0.tag == "cengine-io" }
        guard state.schemaVersion == PreparedShimState.currentSchemaVersion,
              state.artifacts.directoryIdentity == state.directoryIdentity,
              state.artifacts.rootDiskSize > 0,
              Set(state.artifacts.ioFileIdentities.keys)
                == Set(RawContainerPreparationArtifacts.directIOFileNames),
              state.currentContainer.id == state.specification.containerID,
              expectedContainerID == nil || state.currentContainer.id == expectedContainerID,
              state.specification.kind == .container,
              state.specification.rootDiskIdentity.map({ identity in
                  Self.launchIdentity(
                      .persistedIdentity(identity),
                      references: state.artifacts.rootDiskIdentity
                  )
              }) == true,
              state.specification.rootDiskSize == state.artifacts.rootDiskSize,
              ioShares.count == 1,
              ioShares[0].sourceIdentity.map({ identity in
                  Self.launchIdentity(
                      .persistedIdentity(identity),
                      references: state.artifacts.ioDirectoryIdentity
                  )
              }) == true,
              ioShares[0].readOnly == false,
              VMShimClient.launchPathsMatch(
                state.specification.rootDiskPath,
                directory.url.appending(path: "root.ext4").path
              ),
              VMShimClient.launchPathsMatch(
                ioShares[0].source,
                directory.url.appending(path: "io", directoryHint: .isDirectory).path
              ),
              VMShimClient.launchPathsMatch(
                state.specification.logPath,
                directory.url.appending(path: "shim.log").path
              ) else {
            throw EngineError(.internalError, "invalid prepared VM shim state at \(url.path)")
        }
        let artifacts = try state.artifacts.refreshed(in: directory)
        var specification = state.specification
        // Preserve an old same-boot launch specification long enough to adopt
        // its live generation. Only a legacy device mismatch proves that the
        // immutable launch contract was recorded before a remount.
        let refreshLaunchIdentity = state.directoryIdentity.volumeUUID == nil
            && state.directoryIdentity.device != directory.identity.device
        if refreshLaunchIdentity {
            specification.rootDiskIdentity = artifacts.rootDiskIdentity.shimIdentity
            guard let ioShareIndex = specification.bindShares.firstIndex(
                where: { $0.tag == "cengine-io" }
            ) else {
                throw EngineError(
                    .internalError, "invalid prepared VM shim state at \(url.path)"
                )
            }
            specification.bindShares[ioShareIndex].sourceIdentity =
                artifacts.ioDirectoryIdentity.shimIdentity
        }
        if refreshLaunchIdentity, var spool = specification.outputSpool {
            guard let directories = artifacts.outputSpoolDirectoryIdentities,
                  let stdout = artifacts.ioFileIdentities["stdout"],
                  let stderr = artifacts.ioFileIdentities["stderr"],
                  let stdoutSpool = directories["stdout.spool"],
                  let stderrSpool = directories["stderr.spool"] else {
                throw EngineError(
                    .internalError, "invalid prepared VM output spool state at \(url.path)"
                )
            }
            spool.directoryIdentity = artifacts.ioDirectoryIdentity.shimIdentity
            spool.stdoutIdentity = stdout.shimIdentity
            spool.stderrIdentity = stderr.shimIdentity
            spool.stdoutSpoolDirectoryIdentity = stdoutSpool.shimIdentity
            spool.stderrSpoolDirectoryIdentity = stderrSpool.shimIdentity
            specification.outputSpool = spool
        }
        let refreshed = PreparedShimState(
            directoryIdentity: directory.identity,
            artifacts: artifacts,
            currentContainer: state.currentContainer,
            specification: specification
        )
        if refreshLaunchIdentity && (
            state.directoryIdentity.volumeUUID == nil
                || state.specification != specification
        ) {
            try directory.replaceRegularFile(
                named: "prepared-shim.json",
                data: try JSONEncoder().encode(refreshed)
            )
        }
        guard directory.pathStillNamesThisDirectory() else {
            throw EngineError(.conflict, "prepared VM shim directory was replaced")
        }
        return refreshed
    }

    private static func launchIdentity(
        _ identity: PersistentFileIdentity,
        references artifact: PersistentFileIdentity
    ) -> Bool {
        if identity.volumeUUID != nil {
            return identity == artifact
        }
        return identity.inode == artifact.inode
    }

    private func persistPreparedShimState(
        container: ContainerRecord,
        specification: VMShimProtocol.Specification,
        artifacts: RawContainerPreparationArtifacts,
        expectedDirectoryIdentity: PersistentFileIdentity? = nil
    ) throws {
        let stateDirectory = try containerStateDirectory(for: container.id)
        guard expectedDirectoryIdentity == nil
                || expectedDirectoryIdentity == stateDirectory.identity,
              stateDirectory.pathStillNamesThisDirectory() else {
            throw EngineError(.conflict, "prepared VM shim directory was replaced")
        }
        guard artifacts.directoryIdentity == stateDirectory.identity else {
            throw EngineError(.conflict, "prepared VM artifact ownership changed")
        }
        try artifacts.validate(in: stateDirectory)
        try stateDirectory.replaceRegularFile(
            named: "prepared-shim.json",
            data: try JSONEncoder().encode(PreparedShimState(
                directoryIdentity: stateDirectory.identity,
                artifacts: artifacts,
                currentContainer: container,
                specification: specification
            ))
        )
        try artifacts.validate(in: stateDirectory)
        guard stateDirectory.pathStillNamesThisDirectory() else {
            throw EngineError(.conflict, "prepared VM shim directory was replaced")
        }
    }

    private func nextShimGeneration(in containerDirectory: URL) throws -> UInt64 {
        let directory = try containerStateDirectory(
            for: containerDirectory.lastPathComponent
        )
        var maximum = try Self.loadPreparedShimState(
            from: directory, expectedContainerID: containerDirectory.lastPathComponent
        )?
            .specification.generation ?? 0
        if let stateDirectory = try directory.openDirectoryIfPresent(
            named: "shim-generations"
        ) {
            for name in try stateDirectory.reconciledEntryNames() {
                guard let separator = name.firstIndex(of: "-") else { continue }
                maximum = max(maximum, UInt64(name[..<separator]) ?? 0)
            }
        }
        guard maximum < UInt64.max else {
            throw EngineError(.conflict, "VM shim generation counter is exhausted")
        }
        return maximum + 1
    }

    private func relaunchPreparedShim(
        _ container: ContainerRecord,
        preservingCapacityFrom preservedState: PreparedShimState? = nil
    ) async throws -> VMShimClient? {
        let epoch = serviceGeneration
        try requireServiceGeneration(epoch)
        guard let stateDirectory = try existingContainerStateDirectory(
            for: container.id
        ) else { return nil }
        let directory = stateDirectory.url
        guard let prepared = try Self.loadPreparedShimState(
            from: stateDirectory, expectedContainerID: container.id
        ) else { return nil }
        try prepared.artifacts.validate(in: stateDirectory)
        guard prepared.specification.kind == .container,
              prepared.currentContainer.id == container.id,
              prepared.currentContainer.instanceID == container.instanceID,
              prepared.specification.containerID == container.id else {
            throw EngineError(.conflict, "persisted VM shim does not belong to container \(container.id)")
        }
        let persistentLaunches = try VMShimClient.persistedLaunches(
            in: stateDirectory,
            expectedContainerID: container.id,
            expectedInstanceID: container.instanceID
        )
        quarantinedShimGenerations[container.id] = persistentLaunches.quarantined.isEmpty
            ? nil : persistentLaunches.quarantined
        guard persistentLaunches.quarantined.isEmpty else {
            throw BackendResourceRollbackIncompleteError(
                "container \(container.id) has unresolved VM shim generation ownership"
            )
        }
        if !(cleanupPendingShims[container.id] ?? []).isEmpty || !persistentLaunches.isEmpty {
            try await terminateEveryShim(for: container.id)
        }
        try requireServiceGeneration(epoch)
        let bindSources = try HostBindSourceResolver(
            root: root.appending(path: "bind-sources")
        ).resolve(container.mounts)
        let capacitySpecification = try Self.relaunchCapacitySpecification(
            for: container, prepared: prepared, preserving: preservedState
        )
        let volumeDisks = try refreshedVolumeDisks(
            (capacitySpecification ?? prepared.specification).volumeDisks
        )
        let specification = try containerShimSpecification(
            container,
            directory: directory,
            artifacts: prepared.artifacts,
            bindSources: bindSources,
            generation: try nextShimGeneration(in: directory),
            volumeDisks: volumeDisks,
            capacitySpecification: capacitySpecification
        )
        try prepared.artifacts.validate(in: stateDirectory)
        let shim = try await launchTrackedShim(
            specification,
            container: container,
            expectedLogIdentity: prepared.artifacts.shimLogIdentity
        )
        try requireServiceGeneration(epoch)
        retainCleanupPendingShim(shim, for: container.id)
        do {
            try requireServiceGeneration(epoch)
            try persistPreparedShimState(
                container: container,
                specification: specification,
                artifacts: prepared.artifacts,
                expectedDirectoryIdentity: prepared.directoryIdentity
            )
            preparedBindSources[container.id] = bindSources
            removeCleanupPendingShim(shim, for: container.id)
            try requireServiceGeneration(epoch)
            shims[container.id] = shim
            try requireServiceGeneration(epoch)
        knownContainers[container.id] = container
            activeContainers.removeValue(forKey: container.id)
            return shim
        } catch {
            try requireServiceGeneration(epoch)
            let persistenceError = error
            do {
                try await terminateEveryShim(for: container.id)
            } catch {
            try requireServiceGeneration(epoch)
                throw BackendResourceRollbackIncompleteError(
                    "prepared shim selection could not be persisted: "
                        + "\(EngineError.message(for: persistenceError)); cleanup failed: "
                        + EngineError.message(for: error)
                )
            }
            throw persistenceError
        }
    }

    private func containerShimSpecification(
        _ container: ContainerRecord,
        directory: URL,
        artifacts: RawContainerPreparationArtifacts,
        bindSources: [Int: PreparedBindSource],
        generation: UInt64,
        volumeDisks: [VMShimProtocol.VolumeDisk],
        capacitySpecification: VMShimProtocol.Specification? = nil
    ) throws -> VMShimProtocol.Specification {
        let ioDirectory = directory.appending(path: "io", directoryHint: .isDirectory)
        if let platform = try? OCIPlatform(container.platform),
           platform.architecture != "arm64",
           VZLinuxRosettaDirectoryShare.availability != .installed {
            throw EngineError(
                .unsupported,
                "running \(container.platform) containers requires Rosetta; "
                    + "install it with: softwareupdate --install-rosetta --agree-to-license"
            )
        }
        let memoryCapacity: UInt64
        if let capacitySpecification {
            memoryCapacity = capacitySpecification.memoryBytes
        } else {
            memoryCapacity = try VirtualMachineMemory.capacity(
                forHardLimit: container.memoryBytes
            )
        }
        let outputSpool: VMShimProtocol.OutputSpool?
        if let directories = artifacts.outputSpoolDirectoryIdentities {
            guard let stdout = artifacts.ioFileIdentities["stdout"],
                  let stderr = artifacts.ioFileIdentities["stderr"],
                  let stdoutSpool = directories["stdout.spool"],
                  let stderrSpool = directories["stderr.spool"] else {
                throw EngineError(.internalError, "container output spool preparation is incomplete")
            }
            let policy = ContainerLogRetentionPolicy.default
            outputSpool = .init(
                directoryPath: ioDirectory.path,
                directoryIdentity: artifacts.ioDirectoryIdentity.shimIdentity,
                stdoutIdentity: stdout.shimIdentity,
                stderrIdentity: stderr.shimIdentity,
                stdoutSpoolDirectoryIdentity: stdoutSpool.shimIdentity,
                stderrSpoolDirectoryIdentity: stderrSpool.shimIdentity,
                retainedBytes: policy.retainedBytes,
                segmentBytes: policy.segmentBytes,
                maximumSegments: policy.maximumSegments
            )
        } else {
            outputSpool = nil
        }
        return VMShimProtocol.Specification(
            containerID: container.id,
            generation: generation,
            token: Self.randomToken(),
            kernelPath: kernel.path,
            initialRamdiskPath: containerInitialRamdisk.path,
            rootDiskPath: directory.appending(path: "root.ext4").path,
            rootDiskIdentity: artifacts.rootDiskIdentity.shimIdentity,
            rootDiskSize: artifacts.rootDiskSize,
            volumeDisks: volumeDisks,
            cpus: capacitySpecification?.cpus ?? max(container.cpus, 1),
            memoryBytes: memoryCapacity,
            macAddress: Self.macAddress(container.id),
            bindShares: container.mounts.enumerated().compactMap { index, mount in
                guard mount.kind == .bind, let source = bindSources[index],
                      case .virtioFS(let share) = source else { return nil }
                return .init(
                    tag: "bind-\(index)",
                    source: share.shareRoot.path,
                    readOnly: mount.readOnly,
                    sourceIdentity: share.identity.shimIdentity
                )
            } + [.init(
                tag: "cengine-io",
                source: ioDirectory.path,
                readOnly: false,
                sourceIdentity: artifacts.ioDirectoryIdentity.shimIdentity
            )],
            socketRelays: bindSources.values.compactMap { source in
                guard case .socket(let socket) = source else { return nil }
                return .init(path: socket.path.path, port: socket.port)
            }.sorted { $0.port < $1.port },
            socketPath: try runtimeNamespace.makeSocketPath(),
            logPath: directory.appending(path: "shim.log").path,
            kernelArguments: [
                "cengine.management_address=\(Self.managementAddress(for: container.id))",
                "cengine.management_vlan=\(VMShimProtocol.managementVLAN)",
            ],
            networkSocketPath: infrastructure.specification.networkSocketPath,
            vlans: container.networks.compactMap { networkVLANs[$0.networkID] } + [VMShimProtocol.managementVLAN],
            rosetta: VZLinuxRosettaDirectoryShare.availability == .installed,
            outputSpool: outputSpool,
            shimLaunchUUID: UUID().uuidString.lowercased(),
            diskBootstrapVersion: 1,
            expectedInitramfsSHA256: diskBootstrapMetadata.expectedInitramfsSHA256(for: .container),
            workloadStorageMode: managedStorage != nil && Self.volumeNames(in: container.mounts).contains(where: { volumeStorageModes[$0] == .shared }) ? .managed : .none
        )
    }

    private func workload(
        _ container: ContainerRecord,
        image: OCIStoredImage,
        volumeModes: [String: VolumeStorageMode],
        ioClaim: String
    ) async throws -> GuestProtocol.Workload {
        let config = image.configuration.config
        let bindSources = preparedBindSources[container.id] ?? [:]
        let blockVolumes = Self.volumeNames(in: container.mounts).filter { volumeModes[$0] != .shared }
        let volumeDevices = try Dictionary(uniqueKeysWithValues: blockVolumes.enumerated().map {
            ($0.element, try Self.volumeDevicePath(index: $0.offset))
        })
        var managedIDs: [String: String] = [:]
        if let managedStorage {
            for name in Self.volumeNames(in: container.mounts) where volumeModes[name] == .shared {
                managedIDs[name] = try await managedStorage.volumeID(named: name)
            }
        }
        let mountOrder = Self.mountDestinationOrder(container.mounts.map(\.destination))
        let mounts = mountOrder.map { index -> GuestProtocol.Mount in
            let mount = container.mounts[index]
            if let source = bindSources[index], case .socket(let socket) = source {
                return GuestProtocol.Mount(
                    kind: "socket", source: mount.source, destination: mount.destination,
                    readOnly: mount.readOnly, socketPort: socket.port, socketMode: socket.mode,
                    socketUID: socket.uid, socketGID: socket.gid
                )
            }
            let bindSubpath: String? = {
                guard mount.kind == .bind else { return mount.subpath }
                guard let source = bindSources[index], case .virtioFS(let share) = source else { return mount.subpath }
                return [share.subpath, mount.subpath].compactMap { $0 }.joined(separator: "/").nilIfEmpty
            }()
            let options = mount.kind == .tmpfs
                ? [
                    "size=\(max(mount.tmpfsSizeBytes ?? 64 * 1_024 * 1_024, 0))",
                    String(format: "mode=%o", mount.tmpfsMode ?? 0o1777),
                ] + (mount.tmpfsOptions ?? []).map { $0[0] }
                : []
            return GuestProtocol.Mount(
                kind: mount.kind.rawValue,
                source: mount.kind == .bind ? "bind-\(index)" : (managedIDs[mount.source] ?? mount.source),
                device: mount.kind == .volume ? volumeDevices[mount.source] : nil,
                destination: mount.destination,
                readOnly: mount.readOnly,
                options: options,
                subpath: bindSubpath,
                noCopy: mount.noCopy,
                propagation: mount.propagation?.rawValue ?? "",
                nonRecursive: mount.nonRecursive,
                readOnlyNonRecursive: mount.readOnlyNonRecursive,
                readOnlyForceRecursive: mount.readOnlyForceRecursive
            )
        }
        return try Self.workloadSpecification(
            container: container, imageConfiguration: config,
            mounts: mounts, networks: networkEndpoints(container), hosts: networkHosts(container),
            volumeServer: managedStorage == nil && volumeModes.values.contains(.shared) ? Self.managementServerAddress : nil,
            ioClaim: ioClaim
        )
    }

    static func effectiveWorkloadSysctls(for container: ContainerRecord) -> [String: String] {
        var result = container.effectiveSysctls
        let domainname = container.effectiveDomainname
        guard !domainname.isEmpty else { return result }
        guard !result.keys.contains(where: {
            $0.replacingOccurrences(of: ".", with: "/") == "kernel/domainname"
        }) else { return result }
        result["kernel.domainname"] = domainname
        return result
    }

    static func workloadSpecification(
        container: ContainerRecord,
        imageConfiguration config: OCIImageConfiguration.Configuration?,
        mounts: [GuestProtocol.Mount],
        networks: [GuestProtocol.NetworkEndpoint],
        hosts: [String: String],
        volumeServer: String?,
        ioClaim: String = ""
    ) throws -> GuestProtocol.Workload {
        let arguments = (container.entrypoint ?? config?.entrypoint ?? []) + (container.command ?? config?.command ?? [])
        guard !arguments.isEmpty else { throw EngineError(.badRequest, "container has no command") }
        let maskedPaths = container.privileged
            ? []
            : container.maskedPaths ?? dockerDefaultMaskedPaths(cpus: container.cpus)
        let readonlyPaths = container.privileged
            ? []
            : container.readonlyPaths ?? dockerDefaultReadonlyPaths
        return GuestProtocol.Workload(
            id: container.id, rootDevice: "/dev/vda", arguments: arguments,
            environment: Self.mergeEnvironment(image: config?.environment ?? [], container: container.environment),
            workingDirectory: container.workingDirectory.isEmpty ? (config?.workingDirectory ?? "/") : container.workingDirectory,
            hostname: container.hostname, user: Self.user(container.user.isEmpty ? config?.user : container.user),
            terminal: container.tty,
            consoleSize: container.tty && !container.consoleSize.isZero
                ? container.consoleSize : nil,
            readOnlyRoot: container.readOnlyRootfs,
            maskedPaths: maskedPaths, readonlyPaths: readonlyPaths,
            stopSignal: container.stopSignal,
            volumeServer: volumeServer,
            mounts: mounts, networks: networks, hosts: hosts,
            resources: .init(
                memoryBytes: container.memoryBytes,
                cpuQuota: try DockerCPUResources.quota(cpuCount: container.cpus), cpuPeriod: 100_000, pids: container.pidsLimit,
                blockIOReadBps: Self.blockIOThrottles(container.blockIOReadBps),
                blockIOWriteBps: Self.blockIOThrottles(container.blockIOWriteBps),
                blockIOReadIOps: Self.blockIOThrottles(container.blockIOReadIOps),
                blockIOWriteIOps: Self.blockIOThrottles(container.blockIOWriteIOps),
                devices: Self.devices(container.devices),
                deviceCgroupRules: try Self.deviceCgroupRules(container.deviceCgroupRules)
            ),
            privileged: container.privileged,
            noNewPrivileges: container.noNewPrivileges ?? false,
            seccompDefault: Self.usesDefaultSeccomp(container),
            annotations: container.annotations,
            capabilityAdd: container.capabilityAdd, capabilityDrop: container.capabilityDrop,
            rlimits: try Self.rlimits(container.ulimits), ipcMode: container.ipcMode,
            shmSize: container.effectiveShmSizeBytes,
            sysctls: Self.effectiveWorkloadSysctls(for: container),
            ioClaim: ioClaim
        )
    }

    static func usesDefaultSeccomp(_ container: ContainerRecord) -> Bool {
        switch container.seccompProfile {
        case "builtin": true
        case "unconfined": false
        default: !container.privileged
        }
    }

    private static let dockerDefaultMaskedPaths = [
        "/proc/acpi", "/proc/asound", "/proc/interrupts", "/proc/kcore", "/proc/keys",
        "/proc/latency_stats", "/proc/sched_debug", "/proc/scsi", "/proc/timer_list",
        "/proc/timer_stats", "/sys/devices/virtual/powercap", "/sys/firmware",
    ]

    private static let dockerDefaultReadonlyPaths = [
        "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger",
    ]

    private static func dockerDefaultMaskedPaths(cpus: Int) -> [String] {
        dockerDefaultMaskedPaths + (0..<max(cpus, 1)).map {
            "/sys/devices/system/cpu/cpu\($0)/thermal_throttle"
        }
    }

    private static func rlimits(_ values: [UlimitRecord]) throws -> [GuestProtocol.Rlimit] {
        values.map {
            .init(
                type: $0.name,
                soft: UInt64(bitPattern: $0.soft),
                hard: UInt64(bitPattern: $0.hard)
            )
        }
    }

    private static func blockIOThrottles(
        _ values: [BlockIOThrottleDeviceRecord]?
    ) -> [GuestProtocol.BlockIOThrottle] {
        (values ?? []).map { .init(path: $0.path, rate: $0.rate) }
    }

    private static func devices(_ values: [DeviceMappingRecord]) -> [GuestProtocol.DeviceMapping] {
        values.map { .init(
            pathOnHost: $0.pathOnHost, pathInContainer: $0.pathInContainer,
            cgroupPermissions: $0.cgroupPermissions
        ) }
    }

    private static func deviceCgroupRules(
        _ values: [String]
    ) throws -> [GuestProtocol.DeviceCgroupRule] {
        try values.flatMap { value -> [GuestProtocol.DeviceCgroupRule] in
            let fields = value.split(separator: " ").map(String.init)
            let numbers = fields.count > 1 ? fields[1].split(separator: ":").map(String.init) : []
            guard fields.count == 3, numbers.count == 2 else {
                throw EngineError(.internalError, "container has an invalid persisted device cgroup rule")
            }
            func number(_ value: String) throws -> UInt32? {
                if value == "*" { return nil }
                guard let parsed = UInt32(value) else {
                    throw EngineError(
                        .internalError, "container has an invalid persisted device cgroup rule"
                    )
                }
                return parsed
            }
            let major = try number(numbers[0])
            let minor = try number(numbers[1])
            let types = fields[0] == "a" ? ["c", "b"] : [fields[0]]
            return types.map { .init(deviceType: $0, major: major, minor: minor, access: fields[2]) }
        }
    }

    private static func compatibilityResourceFailureAfterWrites(containerID: String) throws -> UInt32? {
        guard let path = ProcessInfo.processInfo.environment[
            "CENGINE_COMPAT_RESOURCE_UPDATE_FAILURE_FILE"
        ] else { return nil }
        return try CompatibilityResourceUpdateFailureClaim.claim(
            at: URL(fileURLWithPath: path), containerID: containerID
        )
    }

    private func refreshedVolumeDisks(
        _ disks: [VMShimProtocol.VolumeDisk]
    ) throws -> [VMShimProtocol.VolumeDisk] {
        let trustedVolumeUUID = try PersistentStateDirectory.open(root).identity.volumeUUID
        return try disks.map { disk in
            guard !disk.name.isEmpty, !disk.name.contains("/"),
                  let expected = disk.identity, let size = disk.size,
                  VMShimClient.launchPathsMatch(
                      disk.path, try volumeDiskURL(name: disk.name).path
                  ) else {
                throw EngineError(.conflict, "invalid persisted volume disk identity")
            }
            let url = URL(filePath: disk.path).standardizedFileURL
            let directory = try PersistentStateDirectory.open(
                url.deletingLastPathComponent()
            )
            try RawDiskJournalDirectory.prepare(directory)
            try RawVolumeDiskProvisioning.validateExisting(
                in: directory, named: url.lastPathComponent, size: size,
                legacy: url.lastPathComponent != "disk.ext4"
            )
            let observed = try directory.regularFileIdentity(
                named: url.lastPathComponent, expectedSize: size
            )
            guard PersistentFileIdentity.matches(
                expected: .persistedIdentity(expected),
                observed: observed,
                onTrustedVolume: trustedVolumeUUID
            ) else {
                throw EngineError(.conflict, "persisted volume disk identity changed")
            }
            var result = disk
            result.identity = observed.shimIdentity
            return result
        }
    }

    private func ensureVolumeDisks(names: [String]) throws -> [VMShimProtocol.VolumeDisk] {
        let volumes = try PersistentStateDirectory.open(
            root.appending(path: "volumes", directoryHint: .isDirectory)
        )
        return try names.map { name in
            try RawVolumeDiskProvisioning.prepare(
                in: volumes, name: name, size: Self.defaultVolumeDiskBytes
            )
        }
    }

    private func resolveVolumeStorageModes(for container: ContainerRecord) throws -> [String: VolumeStorageMode] {
        let names = Self.volumeNames(in: container.mounts)
        var referenceCounts: [String: Int] = [:]
        for known in knownContainers.values {
            for name in Self.volumeNames(in: known.mounts) {
                referenceCounts[name, default: 0] += 1
            }
        }
        if knownContainers[container.id] == nil {
            for name in names { referenceCounts[name, default: 0] += 1 }
        }
        let resolved = try Self.resolveVolumeStorageModes(
            names: names,
            referenceCounts: referenceCounts,
            existing: volumeStorageModes
        )
        if resolved != volumeStorageModes {
            volumeStorageModes = resolved
            try persistVolumeStorageModes()
        }
        return resolved
    }

    static func resolveVolumeStorageModes(
        names: [String],
        referenceCounts: [String: Int],
        existing: [String: VolumeStorageMode]
    ) throws -> [String: VolumeStorageMode] {
        var resolved = existing
        for name in names {
            if resolved[name] == .block, referenceCounts[name, default: 1] > 1 {
                throw EngineError(.conflict, "volume \(name) is block-backed and cannot be attached to multiple container VMs")
            }
            if resolved[name] == nil {
                resolved[name] = referenceCounts[name, default: 1] > 1 ? .shared : .block
            }
        }
        return resolved
    }

    private func reconfigureVolumeDisks(
        _ shim: VMShimClient,
        container: ContainerRecord,
        modes: [String: VolumeStorageMode],
        generation: RawBackendExecutionFence.Token,
        futureLaunchUUID: String? = nil
    ) async throws -> VMShimClient {
        let desiredNames = Self.volumeNames(in: container.mounts).filter { modes[$0] != .shared }
        let managed = managedStorage != nil && Self.volumeNames(in: container.mounts).contains { modes[$0] == .shared }
        // Managed sessions are one-shot and never reuse an earlier launch's keys.
        if !managed, shim.specification.workloadStorageMode == .none,
           shim.specification.volumeDisks.map(\.name) == desiredNames { return shim }
        let containerDirectory = try containerStateDirectory(for: container.id)
        guard let prepared = try Self.loadPreparedShimState(
                from: containerDirectory, expectedContainerID: container.id
              ),
              prepared.specification == shim.specification else {
            throw EngineError(
                .conflict, "volume reconfiguration does not match its durable preparation"
            )
        }
        if managed {
            // Failed-P replacement may already have positively terminated it.
            // Repeat exact owned termination, never infer death from no socket.
            try await shim.terminate()
        } else {
            let status = try await shim.status()
            try requireExecutionGeneration(container.id, generation: generation)
            guard status.state != .running && status.state != .paused else {
                throw EngineError(.conflict, "cannot change volume storage while the container VM is running")
            }
        }
        try await terminateShim(container.id, shim: shim, expectedExecutionGeneration: generation)
        try requireExecutionGeneration(container.id, generation: generation)
        var specification = shim.specification
        specification.generation = try nextShimGeneration(in: containerDirectory.url)
        specification.token = Self.randomToken()
        specification.shimLaunchUUID = futureLaunchUUID ?? UUID().uuidString.lowercased()
        specification.diskBootstrapVersion = 1
        specification.expectedInitramfsSHA256 = diskBootstrapMetadata.expectedInitramfsSHA256(for: .container)
        specification.socketPath = try runtimeNamespace.makeSocketPath()
        specification.workloadStorageMode = managed ? .managed : .none
        specification.volumeDisks = try ensureVolumeDisks(names: desiredNames)
        try prepared.artifacts.validate(in: containerDirectory)
        let replacement = try await launchTrackedShim(
            specification,
            container: container,
            expectedLogIdentity: prepared.artifacts.shimLogIdentity
        )
        guard executionFence.owns(container.id, token: generation) else {
            try await replacement.terminate()
            try requireExecutionGeneration(container.id, generation: generation)
            return replacement
        }
        retainCleanupPendingShim(replacement, for: container.id)
        do {
            try persistPreparedShimState(
                container: container,
                specification: specification,
                artifacts: prepared.artifacts,
                expectedDirectoryIdentity: prepared.directoryIdentity
            )
        } catch {
            let persistenceError = error
            do {
                try await terminateEveryShim(for: container.id)
            } catch {
                throw BackendResourceRollbackIncompleteError(
                    "volume-disk shim selection could not be persisted: "
                        + "\(EngineError.message(for: persistenceError)); cleanup failed: "
                        + EngineError.message(for: error)
                )
            }
            throw persistenceError
        }
        removeCleanupPendingShim(replacement, for: container.id)
        shims[container.id] = replacement
        knownContainers[container.id] = container
        return replacement
    }

    static func removeVolumeDisk(at url: URL) throws {
        try RawVolumeDiskProvisioning.remove(at: url)
    }

    private func volumeDiskURL(name: String) throws -> URL {
        try RawVolumeDiskProvisioning.diskURL(
            in: PersistentStateDirectory.open(root.appending(path: "volumes")), name: name
        )
    }

    private func persistVolumeStorageModes() throws {
        let data = try JSONEncoder().encode(volumeStorageModes)
        try data.write(to: root.appending(path: "volume-storage.json"), options: .atomic)
    }

    static func volumeNames(in mounts: [MountRecord]) -> [String] {
        var seen = Set<String>()
        return mounts.compactMap { mount in
            guard mount.kind == .volume, seen.insert(mount.source).inserted else { return nil }
            return mount.source
        }
    }

    static func mountDestinationOrder(_ destinations: [String]) -> [Int] {
        func depth(_ destination: String) -> Int {
            var result = 0
            for component in destination.split(separator: "/", omittingEmptySubsequences: true) {
                switch component {
                case ".": break
                case "..": result = max(result - 1, 0)
                default: result += 1
                }
            }
            return result
        }
        return destinations.indices.sorted { left, right in
            let leftDepth = depth(destinations[left])
            let rightDepth = depth(destinations[right])
            return leftDepth == rightDepth ? left < right : leftDepth < rightDepth
        }
    }

    static func volumeDevicePath(index: Int) throws -> String {
        guard (0..<25).contains(index), let suffix = UnicodeScalar(98 + index) else {
            throw EngineError(.badRequest, "a container may mount at most 25 volumes")
        }
        return "/dev/vd\(Character(suffix))"
    }

    private func networkEndpoints(_ container: ContainerRecord) -> [GuestProtocol.NetworkEndpoint] {
        // Docker gives a multi-homed container a single default gateway, chosen by
        // endpoint gateway priority (ties broken lexicographically by network
        // name). Selecting across every endpoint means a single-network container
        // always keeps its only network's gateway.
        let defaultGateways = EndpointGatewayPriority.defaultGatewayNetworks(
            among: container.networks.compactMap { endpoint in
                guard let network = networks[endpoint.networkID] else { return nil }
                return .init(
                    networkID: endpoint.networkID,
                    priority: endpoint.gatewayPriority ?? 0,
                    networkName: network.name,
                    providesIPv4: endpoint.ipv4Address?.isEmpty == false && !network.gateway.isEmpty,
                    providesIPv6: endpoint.ipv6Address?.isEmpty == false && !network.ipv6Gateway.isEmpty
                )
            }
        )
        return container.networks.enumerated().compactMap { index, endpoint in
            guard let network = networks[endpoint.networkID], let vlan = networkVLANs[endpoint.networkID] else { return nil }
            var addresses: [String] = []
            if let address = endpoint.ipv4Address, !address.isEmpty { addresses.append(Self.withPrefix(address, from: network.subnet)) }
            if let address = endpoint.ipv6Address, !address.isEmpty { addresses.append(Self.withPrefix(address, from: network.ipv6Subnet)) }
            var gateways: [String] = []
            // Select default routes independently. A higher-priority IPv6-only
            // endpoint must not suppress the IPv4 default route (and vice versa).
            if endpoint.networkID == defaultGateways.ipv4NetworkID { gateways.append(network.gateway) }
            if endpoint.networkID == defaultGateways.ipv6NetworkID { gateways.append(network.ipv6Gateway) }
            return .init(
                networkID: endpoint.networkID,
                vlan: vlan,
                name: "eth\(index)",
                macAddress: endpoint.macAddress ?? Self.endpointMacAddress(container: container.id, network: endpoint.networkID),
                addresses: addresses,
                gateways: gateways,
                dns: network.internalNetwork ? [] : [network.gateway, network.ipv6Gateway].filter { !$0.isEmpty },
                aliases: endpoint.aliases,
                sysctls: endpoint.interfaceSysctls
            )
        }
    }

    private func networkHosts(_ container: ContainerRecord) -> [String: String] {
        var result: [String: String] = [:]
        let networkIDs = Set(container.networks.map(\.networkID))
        for peer in knownContainers.values {
            for endpoint in peer.networks where networkIDs.contains(endpoint.networkID) {
                guard let address = Self.peerHostAddress(endpoint) else { continue }
                for name in Set(endpoint.aliases + [peer.name, peer.hostname]).filter({ !$0.isEmpty }) { result[name] = address }
            }
        }
        return result
    }

    static func peerHostAddress(_ endpoint: NetworkEndpointRecord) -> String? {
        if let address = endpoint.ipv4Address, !address.isEmpty { return address }
        if let address = endpoint.ipv6Address, !address.isEmpty { return address }
        return nil
    }

    static func automaticIPv4Network(vlan: UInt16) -> (subnet: String, gateway: String) {
        AutomaticNetworkPool.default.ipv4Network(vlan: vlan)
    }

    private func allocateVLAN() throws -> UInt16 {
        let used = Set(networkVLANs.values)
        guard let vlan = Self.nextAvailableVLAN(used: used) else { throw EngineError(.conflict, "all VLAN identifiers are allocated") }
        return vlan
    }

    static func nextAvailableVLAN(used: Set<UInt16>) -> UInt16? {
        (1..<VMShimProtocol.managementVLAN).first(where: { !used.contains($0) })
    }

    static func managementAddress(for containerID: String) -> String {
        let digest = Array(SHA256.hash(data: Data(containerID.utf8)))
        let second = 64 | Int(digest[0] & 0x3f)
        let third = Int(digest[1])
        var fourth = Int(digest[2])
        if second == 64, third == 0, fourth < 2 { fourth = 2 }
        return "100.\(second).\(third).\(fourth)/10"
    }

    private func persistNetworks() throws {
        let state = Dictionary(uniqueKeysWithValues: networks.compactMap { id, record in networkVLANs[id].map { (id, NetworkState(record: record, vlan: $0)) } })
        try JSONEncoder().encode(state).write(to: root.appending(path: "networks.json"), options: .atomic)
    }

    private func synchronizeFabric() async throws {
        let values = networks.compactMap { id, network -> VMShimClient.FabricNetwork? in
            guard let vlan = networkVLANs[id], !network.subnet.isEmpty || !network.ipv6Subnet.isEmpty else { return nil }
            return .init(id: id, vlan: vlan, subnet: network.subnet, gateway: network.gateway, ipv6Subnet: network.ipv6Subnet, internalNetwork: network.internalNetwork, isolated: network.fabricIsolated, ports: [])
        }
        _ = try await infrastructure.configureFabric(networks: values.sorted { $0.id < $1.id })
    }

    static func recoverOrLaunch(
        _ specification: VMShimProtocol.Specification,
        executableUUID: UUID? = RunningExecutableIdentity.uuid,
        probe: (VMShimClient) async throws -> VMShimProtocol.Status = {
            try await $0.status(timeoutMilliseconds: 2_000)
        },
        launch: (VMShimProtocol.Specification) async throws -> VMShimClient = {
            try await VMShimClient.launch(specification: $0)
        }
    ) async throws -> VMShimClient {
        try Task.checkCancellation()
        if let old = try RawStorageShimRecovery.publishedGeneration(for: specification) {
            let identity = old.record.process
            switch RawStorageShimRecovery.liveness(identity, observation: RawStorageShimRecovery.observe(identity.pid)) {
            case .dead:
                // launch revalidates every retained generation and acquires the
                // actual block FD lease before writing a fresh immutable intent.
                return try await launch(specification)
            case .unknown:
                throw EngineError(.conflict, "storage shim kernel identity is unavailable; explicit quiescence is required; preserve launch records")
            case .alive:
                let client = VMShimClient(specification: old.specification)
                let status: VMShimProtocol.Status
                do {
                    status = try await probe(client)
                } catch {
                    if error is CancellationError || Task.isCancelled { throw CancellationError() }
                    guard RawStorageShimRecovery.liveness(identity, observation: RawStorageShimRecovery.observe(identity.pid)) == .dead else {
                        throw EngineError(.conflict, "storage shim status unavailable and death unproven; explicit quiescence is required; preserve launch records")
                    }
                    return try await launch(specification)
                }
                let (seconds, overflow) = identity.startSeconds.multipliedReportingOverflow(by: 1_000_000)
                let (start, additionOverflow) = seconds.addingReportingOverflow(identity.startMicroseconds)
                guard !overflow, !additionOverflow,
                      status.shimLaunchUUID == old.specification.shimLaunchUUID,
                      status.containerID == old.specification.containerID,
                      status.generation == old.specification.generation,
                      status.processIdentifier == identity.pid, status.processStartTime == start,
                      RawStorageShimRecovery.liveness(identity, observation: RawStorageShimRecovery.observe(identity.pid)) == .alive else {
                    throw EngineError(.conflict, "storage shim launch identity changed")
                }
                try InfrastructureRecovery.validate(
                    status, specification: old.specification, executableUUID: executableUUID
                )
                guard old.specification.rootDiskIdentity == specification.rootDiskIdentity else {
                    throw EngineError(.conflict, "running infrastructure VM disk identity changed")
                }
                return client
            }
        }
        try Task.checkCancellation()
        return try await launch(specification)
    }

    private static let ephemeralRuntimeNamespace: Result<VMShimRuntimeNamespace, Error> = Result {
        try VMShimRuntimeNamespace.createEphemeral()
    }

    /// Focused shim tests construct specifications without a complete backend.
    /// Production allocations use the backend's persisted boot-session namespace.
    static func makeRuntimeSocketPath() throws -> String {
        try ephemeralRuntimeNamespace.get().makeSocketPath()
    }

    private static func randomToken() -> String {
        var generator = SystemRandomNumberGenerator()
        let data = (0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
        return data.map { String(format: "%02x", $0) }.joined()
    }

    private static func mergeEnvironment(image: [String], container: [String]) -> [String] {
        var order: [String] = []; var values: [String: String] = [:]
        for entry in image + container {
            let key = entry.split(separator: "=", maxSplits: 1).first.map(String.init) ?? entry
            if values[key] == nil { order.append(key) }
            values[key] = entry
        }
        return order.compactMap { values[$0] }
    }

    static func resolveExecContext(
        configuration: ExecConfiguration,
        containerEnvironment: [String],
        containerWorkingDirectory: String,
        containerUser: String,
        containerPrivileged: Bool,
        containerNoNewPrivileges: Bool?,
        imageEnvironment: [String],
        imageWorkingDirectory: String?,
        imageUser: String?
    ) -> ResolvedExecContext {
        let inheritedEnvironment = mergeEnvironment(
            image: imageEnvironment, container: containerEnvironment
        )
        return ResolvedExecContext(
            environment: mergeEnvironment(
                image: inheritedEnvironment, container: configuration.environment
            ),
            workingDirectory: configuration.workingDirectory.nilIfEmpty
                ?? containerWorkingDirectory.nilIfEmpty
                ?? imageWorkingDirectory?.nilIfEmpty
                ?? "/",
            user: user(
                configuration.user.nilIfEmpty
                    ?? containerUser.nilIfEmpty
                    ?? imageUser?.nilIfEmpty
            ),
            noNewPrivileges: containerNoNewPrivileges ?? false,
            privileged: containerPrivileged || configuration.privileged
        )
    }

    private static func user(_ value: String?) -> GuestProtocol.User {
        let raw = value ?? ""; if raw.isEmpty { return .init() }
        let parts = raw.split(separator: ":", omittingEmptySubsequences: false)
        guard let uid = UInt32(parts[0]) else { return .init(username: raw) }
        guard parts.count > 1, !parts[1].isEmpty else { return .init(uid: uid, gid: uid) }
        guard let gid = UInt32(parts[1]) else {
            return .init(uid: uid, gid: uid, username: raw)
        }
        return .init(uid: uid, gid: gid)
    }

    private static func signalNumber(_ value: String) -> Int {
        let normalized = value.uppercased().replacingOccurrences(of: "SIG", with: "")
        if let number = Int(normalized) { return number }
        return ["HUP": 1, "INT": 2, "QUIT": 3, "KILL": 9, "USR1": 10, "USR2": 12, "PIPE": 13, "ALRM": 14, "TERM": 15, "CHLD": 17, "CONT": 18, "STOP": 19, "TSTP": 20][normalized] ?? 15
    }

    private static func macAddress(_ id: String) -> String {
        EndpointMacAddress.generated(seed: id)
    }

    /// Deterministic MAC for a container's endpoint on a given network, shared
    /// with the Docker inspect surface so reported and applied MACs never diverge.
    static func endpointMacAddress(container: String, network: String) -> String {
        EndpointMacAddress.generated(seed: container + network)
    }

    private static func withPrefix(_ address: String, from subnet: String) -> String {
        if address.contains("/") { return address }
        return address + "/" + (subnet.split(separator: "/").dropFirst().first.map(String.init) ?? (address.contains(":") ? "64" : "24"))
    }

    private struct NetworkState: Codable { let record: NetworkRecord; let vlan: UInt16 }
}

/// Journal parents are private and ACL-free. Tightening a safe owned directory
/// is descriptor-relative; an unsafe directory is never repaired by pathname.
enum RawDiskJournalDirectory {
    static func prepare(_ directory: PersistentStateDirectory, repairPermissions: Bool = true) throws {
        var information = stat()
        guard Darwin.fstat(directory.descriptor, &information) == 0,
              information.st_mode & S_IFMT == S_IFDIR,
              information.st_uid == geteuid(), information.st_mode & 0o022 == 0,
              directory.pathStillNamesThisDirectory() else {
            throw RawDiskInitialization.Failure.unsafePath
        }
        try requireNoACL(directory.descriptor)
        if information.st_mode & 0o7777 != 0o700 {
            guard repairPermissions else { throw RawDiskInitialization.Failure.unsafePath }
            guard Darwin.fchmod(directory.descriptor, 0o700) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            try directory.synchronize()
        }
        guard Darwin.fstat(directory.descriptor, &information) == 0,
              information.st_uid == geteuid(), information.st_mode & 0o7777 == 0o700,
              directory.pathStillNamesThisDirectory() else {
            throw RawDiskInitialization.Failure.unsafePath
        }
        try requireNoACL(directory.descriptor)
    }

    static func requireNoACL(_ descriptor: CInt) throws {
        guard let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            if errno == ENOENT { return }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        guard acl_get_entry(acl, ACL_FIRST_ENTRY.rawValue, &entry) == -1,
              errno == EINVAL else { throw RawDiskInitialization.Failure.unsafePath }
    }

    static func requireSafeAutomaticRootDisposal(_ directory: PersistentStateDirectory) throws {
        // Inspection also creates a lock for legacy mount-only roots; the lock
        // alone is not initialization history. Every other artifact still is.
        guard try directory.entryNames().contains(where: {
            $0.hasPrefix(".raw-init-root.ext4.") && $0 != ".raw-init-root.ext4.lock"
        }) else { return }
        // Only fully acknowledged initialization can be discarded automatically.
        // Missing, CREATED, SPENT and malformed histories require explicit removal.
        if let disk = try? directory.openRegularFile(named: "root.ext4", access: .readOnly) {
            defer { try? disk.handle.close() }
            var information = stat()
            if Darwin.fstat(disk.handle.fileDescriptor, &information) == 0,
               information.st_size > 0,
               let inspection = try? RawDiskInitialization.inspectExisting(
                   in: directory, named: "root.ext4", expectedSize: UInt64(information.st_size)
               ), case .journal(let record) = inspection, record.state == .initialized { return }
        }
        throw BackendResourceRollbackIncompleteError(
            "writable root initialization is incomplete; preserving disk and journal evidence"
        )
    }
}

/// New direct volumes own a whole directory so deletion cannot leave an old
/// initialization authorization behind for a same-name replacement.
enum RawVolumeDiskProvisioning {
    static func diskURL(in volumes: PersistentStateDirectory, name: String) throws -> URL {
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/"), !name.utf8.contains(0) else {
            throw EngineError(.badRequest, "invalid volume name")
        }
        try RawDiskJournalDirectory.prepare(volumes)
        try requireNoDisposals(volumes)
        let digest = SHA256.hash(data: Data(name.utf8)).map { String(format: "%02x", $0) }.joined()
        let legacyName = "\(digest).ext4"
        let directoryName = "\(digest).disk"
        let legacy = try volumes.entryMetadata(named: legacyName)
        let current = try volumes.entryMetadata(named: directoryName)
        guard legacy == nil || current == nil else {
            throw EngineError(.conflict, "volume has both legacy and journaled disk layouts")
        }
        if legacy != nil { return volumes.url.appending(path: legacyName) }
        return volumes.url.appending(path: "\(directoryName)/disk.ext4")
    }

    static func prepare(
        in volumes: PersistentStateDirectory, name: String, size: UInt64
    ) throws -> VMShimProtocol.VolumeDisk {
        let disk = try diskURL(in: volumes, name: name)
        let legacy = disk.lastPathComponent != "disk.ext4"
        let directory: PersistentStateDirectory
        if legacy {
            directory = volumes
        } else {
            let directoryName = disk.deletingLastPathComponent().lastPathComponent
            if let existing = try volumes.openDirectoryIfPresent(named: directoryName) {
                directory = existing
                // An existing empty/partial directory is not a fresh allocation.
            } else {
                directory = try volumes.createDirectory(named: directoryName, permissions: 0o700)
                try RawDiskJournalDirectory.prepare(directory)
                guard case .created = try RawDiskInitialization.createNewDisk(
                    in: directory, named: "disk.ext4", size: size
                ) else { throw POSIXError(.EEXIST) }
            }
        }
        try RawDiskJournalDirectory.prepare(directory)
        try validateExisting(in: directory, named: disk.lastPathComponent, size: size, legacy: legacy)
        let identity = try directory.regularFileIdentity(named: disk.lastPathComponent, expectedSize: size)
        guard directory.pathStillNamesThisDirectory(),
              try diskURL(in: volumes, name: name) == disk else {
            throw EngineError(.conflict, "volume disk layout changed during preparation")
        }
        return .init(name: name, path: disk.path, identity: identity.shimIdentity, size: size)
    }

    static func validateExisting(
        in directory: PersistentStateDirectory, named name: String, size: UInt64, legacy: Bool
    ) throws {
        switch try RawDiskInitialization.inspectExisting(in: directory, named: name, expectedSize: size) {
        case .mountOnly: return
        case .journal(let record):
            guard !legacy, record.state != .spent else { throw RawDiskInitialization.Failure.alreadySpent }
        case .quarantined: throw RawDiskInitialization.Failure.quarantined
        }
    }

    static func requireNoDisposals(_ volumes: PersistentStateDirectory) throws {
        // Do not let generic disposal reconciliation erase a disk without its
        // actual writer lease. Any incomplete claim needs explicit recovery.
        guard try !volumes.entryNames().contains(where: {
            $0.hasPrefix(".cengine-disposal-") || $0.hasPrefix(".cengine-remove-")
        }) else {
            throw EngineError(.conflict, "volume disk disposal remains unresolved")
        }
    }

    static func remove(at disk: URL, hook: PersistentDisposalHook? = nil) throws {
        let parentURL = disk.deletingLastPathComponent()
        let journaled = disk.lastPathComponent == "disk.ext4" && parentURL.lastPathComponent.hasSuffix(".disk")
        let volumes = try PersistentStateDirectory.open(journaled ? parentURL.deletingLastPathComponent() : parentURL)
        try RawDiskJournalDirectory.prepare(volumes)
        try requireNoDisposals(volumes)
        let directory: PersistentStateDirectory
        if journaled {
            let legacyName = String(parentURL.lastPathComponent.dropLast(5)) + ".ext4"
            guard try volumes.entryMetadata(named: legacyName) == nil else {
                throw EngineError(.conflict, "volume has both legacy and journaled disk layouts")
            }
            guard let existing = try volumes.openDirectoryIfPresent(named: parentURL.lastPathComponent) else { return }
            directory = existing
            try RawDiskJournalDirectory.prepare(directory)
        } else {
            directory = volumes
            let newName = disk.deletingPathExtension().lastPathComponent + ".disk"
            guard try volumes.entryMetadata(named: newName) == nil else {
                throw EngineError(.conflict, "volume has both legacy and journaled disk layouts")
            }
            guard try directory.entryMetadata(named: disk.lastPathComponent) != nil else { return }
            guard try !directory.entryNames().contains(where: {
                $0.hasPrefix(".raw-init-\(disk.lastPathComponent).") && $0 != ".raw-init-\(disk.lastPathComponent).lock"
            }) else { throw RawDiskInitialization.Failure.quarantined }
        }
        let opened = try directory.openRegularFile(named: disk.lastPathComponent, access: .readWrite)
        defer { try? opened.handle.close() }
        let descriptor = opened.handle.fileDescriptor
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            throw EngineError(.conflict, "volume disk is still attached or locked")
        }
        defer { _ = flock(descriptor, LOCK_UN) }
        var information = stat()
        guard Darwin.fstat(descriptor, &information) == 0,
              information.st_uid == geteuid(), information.st_nlink == 1,
              directory.pathStillNamesThisDirectory(), volumes.pathStillNamesThisDirectory(),
              try directory.regularFileIdentity(named: disk.lastPathComponent) == opened.identity else {
            throw RawDiskInitialization.Failure.unsafePath
        }
        try RawDiskJournalDirectory.requireNoACL(descriptor)
        if journaled {
            try volumes.disposeDirectory(named: parentURL.lastPathComponent, expectedIdentity: directory.identity, hook: hook)
        } else {
            guard try directory.removeEntryIfMatching(
                named: disk.lastPathComponent, identity: opened.identity, type: S_IFREG,
                claimName: ".cengine-remove-\(UUID().uuidString.lowercased())"
            ) else { throw EngineError(.conflict, "volume disk changed before removal") }
        }
    }
}

/// Publishes initialization history only for an exact O_EXCL-created storage
/// disk. Existing disks are inspected, never truncated or granted fresh history.
enum RawStorageDiskProvisioning {
    static func prepare(
        in directory: PersistentStateDirectory,
        size: UInt64,
        afterMissingObservation: (() throws -> Void)? = nil
    ) throws -> PersistentFileIdentity {
        let name = "volumes.ext4"
        try RawDiskJournalDirectory.prepare(directory)
        var expectedIdentity = try directory.entryMetadata(named: name)?.identity
        if expectedIdentity == nil {
            try afterMissingObservation?()
            switch try RawDiskInitialization.createNewDisk(in: directory, named: name, size: size) {
            case .created(let created):
                let observed = try directory.regularFileIdentity(named: name, expectedSize: size)
                guard observed.inode == created.record.diskIdentity.inode,
                      observed.volumeUUID?.uuidString.lowercased() == created.record.diskIdentity.volumeUUID else {
                    throw RawDiskInitialization.Failure.unsafePath
                }
                expectedIdentity = observed
            case .alreadyExists:
                // Inspect the winner without manufacturing new authorization.
                expectedIdentity = try directory.entryMetadata(named: name)?.identity
            }
        }
        try RawVolumeDiskProvisioning.validateExisting(
            in: directory, named: name, size: size, legacy: false
        )
        let identity = try directory.regularFileIdentity(
            named: name, expectedIdentity: expectedIdentity, expectedSize: size
        )
        guard directory.pathStillNamesThisDirectory() else {
            throw EngineError(.conflict, "storage disk parent directory changed")
        }
        return identity
    }
}

struct RawNetworkStateTransaction {
    let network: NetworkRecord
    let vlan: UInt16
    let previousNetwork: NetworkRecord?
    let previousVLAN: UInt16?

    init(
        adding network: NetworkRecord,
        vlan: UInt16,
        networks: [String: NetworkRecord],
        networkVLANs: [String: UInt16]
    ) {
        self.network = network
        self.vlan = vlan
        previousNetwork = networks[network.id]
        previousVLAN = networkVLANs[network.id]
    }

    func apply(
        networks: inout [String: NetworkRecord],
        networkVLANs: inout [String: UInt16]
    ) {
        networks[network.id] = network
        networkVLANs[network.id] = vlan
    }

    func rollback(
        networks: inout [String: NetworkRecord],
        networkVLANs: inout [String: UInt16]
    ) {
        networks[network.id] = previousNetwork
        networkVLANs[network.id] = previousVLAN
    }
}

struct PreparedVirtioFSBind: Sendable, Equatable {
    let shareRoot: URL
    let subpath: String?
    let identity: PersistentFileIdentity
}

struct PreparedSocketBind: Sendable, Equatable {
    let path: URL
    let port: UInt32
    let mode: UInt32
    let uid: UInt32
    let gid: UInt32
}

enum PreparedBindSource: Sendable, Equatable {
    case virtioFS(PreparedVirtioFSBind)
    case socket(PreparedSocketBind)
}

struct HostBindSourceResolver: Sendable {
    let root: URL

    func resolve(_ mounts: [MountRecord]) throws -> [Int: PreparedBindSource] {
        var resolved: [Int: PreparedBindSource] = [:]
        for (index, mount) in mounts.enumerated() where mount.kind == .bind {
            let requested = URL(filePath: mount.source)
            if FileManager.default.fileExists(atPath: requested.path) {
                let canonical = requested.resolvingSymlinksInPath()
                var metadata = stat()
                if lstat(canonical.path, &metadata) == 0,
                   metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFSOCK) {
                    guard let offset = UInt32(exactly: index) else {
                        throw EngineError(.badRequest, "too many container mounts")
                    }
                    let (port, overflow) = GuestProtocol.socketProxyPortBase.addingReportingOverflow(offset)
                    guard !overflow else { throw EngineError(.badRequest, "too many container mounts") }
                    resolved[index] = .socket(.init(
                        path: canonical, port: port,
                        mode: UInt32(metadata.st_mode & mode_t(0o7777)),
                        uid: UInt32(metadata.st_uid), gid: UInt32(metadata.st_gid)
                    ))
                    continue
                }
                let isDirectory = metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR)
                guard isDirectory
                        || metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG) else {
                    throw EngineError(.badRequest, "unsupported bind source \(mount.source)")
                }
                let shareRoot = isDirectory
                    ? canonical : canonical.deletingLastPathComponent()
                resolved[index] = .virtioFS(.init(
                    shareRoot: shareRoot,
                    subpath: isDirectory ? nil : canonical.lastPathComponent,
                    identity: try PersistentStateDirectory.open(
                        shareRoot
                    ).identity
                ))
                continue
            }
            guard mount.createSourceIfMissing != false else {
                throw EngineError(.notFound, "bind source \(mount.source) does not exist")
            }
            do {
                try FileManager.default.createDirectory(at: requested, withIntermediateDirectories: true)
                resolved[index] = .virtioFS(.init(
                    shareRoot: requested,
                    subpath: nil,
                    identity: try PersistentStateDirectory.open(requested).identity
                ))
            } catch {
                guard Self.isHostNamespaceWriteRestriction(error) else { throw error }
                let digest = SHA256.hash(data: Data(requested.path.utf8)).map { String(format: "%02x", $0) }.joined()
                let managed = root.appending(path: digest, directoryHint: .isDirectory)
                try FileManager.default.createDirectory(at: managed, withIntermediateDirectories: true)
                resolved[index] = .virtioFS(.init(
                    shareRoot: managed,
                    subpath: nil,
                    identity: try PersistentStateDirectory.open(managed).identity
                ))
            }
        }
        return resolved
    }

    private static func isHostNamespaceWriteRestriction(_ error: Error) -> Bool {
        let value = error as NSError
        if value.domain == NSCocoaErrorDomain,
           value.code == CocoaError.fileWriteNoPermission.rawValue || value.code == CocoaError.fileWriteVolumeReadOnly.rawValue {
            return true
        }
        if value.domain == NSPOSIXErrorDomain,
           value.code == EACCES || value.code == EPERM || value.code == EROFS {
            return true
        }
        if let underlying = value.userInfo[NSUnderlyingErrorKey] as? Error {
            return isHostNamespaceWriteRestriction(underlying)
        }
        return false
    }
}

private extension String { var nilIfEmpty: String? { isEmpty ? nil : self } }
#endif

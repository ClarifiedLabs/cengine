#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Synchronization
@preconcurrency import Virtualization

/// One-shot, fail-closed stages. Completion after cancellation cannot resurrect
/// either proof responder or admit a second Guest initialization attempt.
@MainActor struct StorageLifecycleStartupState {
    enum Phase: Sendable { case created, diskStarting, diskReady, serviceStarting, ready, terminal }
    private(set) var phase: Phase = .created
    mutating func beginDisk() throws { try move(from: .created, to: .diskStarting) }
    mutating func diskReady() throws { try move(from: .diskStarting, to: .diskReady) }
    mutating func beginService() throws { try move(from: .diskReady, to: .serviceStarting) }
    mutating func serviceReady() throws { try move(from: .serviceStarting, to: .ready) }
    func requireReady() throws { guard phase == .ready else { throw failure() } }
    mutating func terminate() { phase = .terminal }
    private mutating func move(from: Phase, to: Phase) throws {
        guard phase == from else { throw failure() }
        phase = to
    }
    private func failure() -> EngineError { .init(.conflict, "lifecycle startup is closed or out of order") }
}

/// A bounded containment gate, NOT an authority capability. Register responders
/// before start(), so termination during off-main startup revokes them immediately.
final class StorageLifecycleShimRevocation: @unchecked Sendable {
    enum Slot: Hashable { case fresh, cold, service, adoption }
    private let lock = NSLock()
    private var closed = false
    private var callbacks: [Slot: @Sendable () -> Void] = [:]
    func hold(_ slot: Slot, close: @escaping @Sendable () -> Void) throws {
        let accepted = lock.withLock {
            guard !closed, callbacks[slot] == nil else { return false }
            callbacks[slot] = close
            return true
        }
        guard accepted else { close(); throw EngineError(.conflict, "lifecycle owner revoked") }
    }
    func close() {
        let pending = lock.withLock {
            closed = true
            let pending = Array(callbacks.values); callbacks.removeAll()
            return pending
        }
        for callback in pending { callback() }
    }
    deinit { close() }
    /// shutdown affects every duplicate, unlike closing one descriptor. It is
    /// containment, not proof of Guest drain, process exit or VM shutdown.
    static func revokeStream(_ descriptor: Int32) { _ = Darwin.shutdown(descriptor, SHUT_RDWR) }
}

/// Process-lifetime enrollment with replaceable, independently fenced controls.
/// Only a live committed native socket capability can install a new generation.
final class StorageLifecycleControlLifetime: @unchecked Sendable {
    enum Slot: Hashable { case transport, fresh, cold, service, stream(UInt32) }
    private let lock = NSRecursiveLock()
    private let fenceLock = NSRecursiveLock()
    private let operationLock = NSLock()
    struct Generation: Equatable, Sendable { fileprivate let id: UUID }
    enum DetachResult: Equatable { case stale, preserved, terminateUnenrolled }
    private let initialGeneration = Generation(id: UUID())
    private var adoptedGeneration: Generation?
    private var authorization: StorageLifecycleAdoptionProtocol.Request?
    private var generation: Generation { adoptedGeneration ?? initialGeneration }
    private var terminal = false
    private var drained = false
    private var draining = 0
    private var detached = false
    private var enrollmentPending = false
    private var enrolled = false
    private var callbacks: [Slot: @Sendable () -> Void] = [:]
    var isEnrolled: Bool { lock.withLock { enrolled } }
    var preservesOwner: Bool { lock.withLock { enrolled && detached } }
    // Initial-only shorthand: old startup callbacks can never act on a successor.
    func withAdmission<T>(_ body: () throws -> T) throws -> T {
        try withAdmission(initialGeneration, body)
    }
    func withAdmission<T>(_ expected: Generation, _ body: () throws -> T) throws -> T {
        try lock.withLock {
            guard !terminal, !detached, expected == generation else { throw StorageLifecycleShimProtocol.Failure.closed }
            return try body()
        }
    }
    func adopt(_ session: StorageLifecycleAdoptionShim.CommittedSession) throws -> Generation {
        try session.withAdmission { try installAdopted(session.request) }
    }
    private func installAdopted(_ request: StorageLifecycleAdoptionProtocol.Request) throws -> Generation {
        try lock.withLock {
            guard enrolled, !terminal, detached, drained, callbacks.isEmpty else {
                throw StorageLifecycleShimProtocol.Failure.closed
            }
            let next = Generation(id: UUID())
            adoptedGeneration = next; authorization = request; detached = false; drained = false
            return next
        }
    }
    #if DEBUG
    // Gate-model seam only. No production caller can mint a native session here.
    func testingAdopt(_ request: StorageLifecycleAdoptionProtocol.Request) throws -> Generation {
        try installAdopted(request)
    }
    #endif
    func fence(_ request: StorageLifecycleAdoptionProtocol.Request) throws {
        try fenceLock.withLock {
            let predecessor: Generation? = try lock.withLock {
                // Exact ROOT complete retries must not revoke their own attachment.
                if authorization == request { return nil }
                if let authorization, try request.epoch <= authorization.epoch {
                    throw StorageLifecycleShimProtocol.Failure.unauthorized
                }
                return generation
            }
            if let predecessor { _ = detach(predecessor) }
        }
    }
    func beginEnrollment() throws {
        try withAdmission {
            guard !enrollmentPending, !enrolled else { throw StorageLifecycleShimProtocol.Failure.closed }
            enrollmentPending = true
        }
    }
    // Value-only lifetime transition used by owner-model tests. Native ACKs use
    // publishEnrollment below to couple deadline acceptance with preservation.
    func enroll() throws {
        try withAdmission {
            guard enrollmentPending else { throw StorageLifecycleShimProtocol.Failure.closed }
            enrolled = true
        }
    }
    /// Called only AFTER native ROOT authentication and typed ACK validation.
    /// Acquire admission before the deadline gate: contention must not block the
    /// timeout waiter. Under both locks, publication is only fixed state mutation,
    /// never an arbitrary callback, native authentication, or I/O. Thus timeout
    /// containment either sees enrollment or wins before ACK acceptance entirely.
    func publishEnrollment(acknowledging gate: borrowing Mutex<StorageLifecycleAdoptionDeadline>) throws {
        try withAdmission {
            guard enrollmentPending else { throw StorageLifecycleShimProtocol.Failure.closed }
            try gate.withLock { timing in
                guard timing.acceptReply(at: .now()) else { throw StorageLifecycleShimProtocol.Failure.closed }
                enrolled = true
            }
        }
    }
    func reserveTokenStop() throws {
        try withAdmission {
            guard !enrollmentPending, !enrolled else { throw StorageLifecycleShimProtocol.Failure.unauthorized }
            detached = true
        }
        detach()
    }
    /// Reserve under admission, then release it BEFORE acquiring the fence lock
    /// for teardown. Never nest detach() inside withAdmission: the opposite lock
    /// order is used by off-main ROOT/EOF fences.
    func reservePrivateStop() throws { try reservePrivateStop(initialGeneration) }
    func reservePrivateStop(_ expected: Generation) throws { try withAdmission(expected) { detached = true; terminal = true } }
    func captureGeneration() throws -> Generation { try withAdmission { initialGeneration } }
    func withOperation<T>(_ expected: Generation, _ body: () throws -> T) throws -> T {
        try operationLock.withLock {
            try withAdmission(expected) {}
            return try body()
        }
    }
    func hold(_ slot: Slot, revoke: @escaping @Sendable () -> Void) throws {
        try hold(slot, generation: initialGeneration, revoke: revoke)
    }
    func hold(_ slot: Slot, generation expected: Generation, revoke: @escaping @Sendable () -> Void) throws {
        do {
            try fenceLock.withLock {
                let previous = try withAdmission(expected) { callbacks.updateValue(revoke, forKey: slot) }
                // Fence cannot acknowledge between replacing this slot and
                // revoking its predecessor; still never hold admission over IO.
                previous?()
            }
        } catch { revoke(); throw error }
    }
    @discardableResult func detach(revokeTransport: Bool = true) -> Bool {
        detach(initialGeneration, revokeTransport: revokeTransport) != .terminateUnenrolled
    }
    /// A stale callback is NOT an instruction to terminate the surviving owner.
    @discardableResult func detach(_ expected: Generation, revokeTransport: Bool = true) -> DetachResult {
        fenceLock.withLock {
            let pending: [@Sendable () -> Void]? = lock.withLock {
                guard expected == generation else { return nil }
                detached = true; drained = false; draining += 1
                let pending = callbacks.filter { revokeTransport || $0.key != .transport }.map(\.value)
                if revokeTransport { callbacks.removeAll() }
                else { callbacks = callbacks.filter { $0.key == .transport } }
                return pending
            }
            guard let pending else { return .stale }
            // Join bounded exchanges without cancelling/resetting the retained 4106.
            operationLock.withLock {}
            for callback in pending { callback() }
            return lock.withLock {
                draining -= 1; drained = draining == 0
                return enrolled ? .preserved : .terminateUnenrolled
            }
        }
    }
    func terminate(revokeTransport: Bool = true) {
        let current = lock.withLock { terminal = true; return generation }
        detach(current, revokeTransport: revokeTransport)
    }
}

/// Terminal VM notifications can arrive inside forceStop, before its private
/// response. Retain only that generation's reply channel until EOF/deadline.
struct StorageLifecycleStopReplyLifetime {
    private(set) var generation: StorageLifecycleControlLifetime.Generation?
    // Eligibility only: the host must still positively join stop and release its machine.
    private(set) var permitsProcessExit = false
    var preservesReply: Bool { generation != nil }
    mutating func begin(_ generation: StorageLifecycleControlLifetime.Generation) throws {
        guard self.generation == nil, !permitsProcessExit else { throw StorageLifecycleShimProtocol.Failure.closed }
        self.generation = generation
    }
    mutating func finish(_ expected: StorageLifecycleControlLifetime.Generation) -> Bool {
        guard generation == expected else { return false }
        generation = nil
        permitsProcessExit = true
        return true
    }
}

/// Bounded current-generation stream ownership. The lifecycle stream admits one
/// initial connection plus one per admitted service change; workload and CSR
/// streams replace (and the caller closes) the previous connection.
struct StorageLifecycleStreamOwnership<Connection> {
    enum Stream: UInt32, Sendable { case lifecycle = 4_117, workload = 4_107, attachmentCSR = 4_108 }
    private(set) var lifecycleAllowance = 1
    private(set) var connections: [Stream: Connection] = [:]
    mutating func admit(_ stream: Stream) throws {
        guard stream == .lifecycle else { return }
        guard lifecycleAllowance > 0 else { throw EngineError(.conflict, "lifecycle stream generation exhausted") }
        lifecycleAllowance -= 1
    }
    /// Returns the superseded connection, which the caller must revoke and close.
    mutating func install(_ connection: Connection, for stream: Stream) -> Connection? {
        connections.updateValue(connection, forKey: stream)
    }
    mutating func serviceChanged() { lifecycleAllowance = 1 }
    mutating func removeAll() -> [Connection] {
        defer { connections.removeAll(); lifecycleAllowance = 0 }
        return Array(connections.values)
    }
}

/// Freeze before abort: only zero actual VZ start attempts prove that no VM ever
/// owned the attachment. `.stopped`, cancellation or a thrown start do not prove it.
struct StorageLifecycleVMStartLifetime {
    private(set) var attemptCount = 0
    private(set) var frozenAttemptCount: Int?
    mutating func beginStart() throws {
        guard frozenAttemptCount == nil else { throw CancellationError() }
        attemptCount += 1
    }
    mutating func freezeForAbort() -> Bool {
        if frozenAttemptCount == nil { frozenAttemptCount = attemptCount }
        return frozenAttemptCount == 0
    }
}

/// Abort and the joined bootstrap worker share one close, including reentrant
/// teardown. Clear ownership before calling into VZ; never close a reused FD.
@MainActor final class StorageLifecycleBootstrapConnectionLifetime {
    private var closed = false
    private let revokeConnection: () -> Void
    private let closeConnection: () -> Void
    init(revoke: @escaping () -> Void, close: @escaping () -> Void) {
        revokeConnection = revoke; closeConnection = close
    }
    func close(revoking: Bool = false) {
        guard !closed else { return }
        closed = true
        if revoking { revokeConnection() }
        closeConnection()
    }
}

/// Same-machine notification latch, installed before start. Neither a VZ state
/// snapshot nor an error callback is evidence of orderly Guest POWER_OFF.
@MainActor final class StorageLifecycleGuestExit {
    private(set) var stoppedAt: TimeInterval?
    private(set) var failed = false
    func guestDidStop() { if stoppedAt == nil { stoppedAt = ProcessInfo.processInfo.systemUptime } }
    func didStopWithError() { failed = true }
}

/// Record establishment before coordinator construction. A timed-out VZ attempt
/// is also consumed: its already-accepted connection may arrive late.
struct StorageLifecycleBootPortOwnership {
    private(set) var consumed = false
    mutating func connectedOrUncertain() { consumed = true }
    mutating func claimEOFConnection() -> Bool {
        guard !consumed else { return false }
        consumed = true
        return true
    }
}

/// Owner-held, cancellation-independent cleanup. Every rollback joins this task;
/// fallback is irrevocable even if a positive callback arrives afterward.
@MainActor final class StorageLifecycleFreshAbort {
    private(set) var task: Task<Bool, Never>?
    private(set) var usedFallback = false
    private(set) var neverStarted = false
    static func permitsRelease(clean: Bool, forcedExit: Bool, neverStarted: Bool = false) -> Bool {
        clean || forcedExit || neverStarted
    }
    static func eligible(_ policy: RawDiskBootTransaction.Policy) -> Bool {
        policy == .journalDriven || policy == .resumeReadOnly
    }
    /// Only a failed, unenrolled initializer can retire its executable. This is
    /// eligibility, not stop evidence: the host must still join full teardown.
    func permitsProcessExit(control: StorageLifecycleControlLifetime, privateStopRequested: Bool) -> Bool {
        task != nil && !control.isEnrolled && !privateStopRequested
    }
    func begin(exit: StorageLifecycleGuestExit, neverStarted: Bool = false, timeout: TimeInterval = 10,
               now: @escaping @MainActor () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
               wait: @escaping @MainActor () async -> Void = { try? await Task.sleep(for: .milliseconds(10)) },
               close: @escaping @MainActor (TimeInterval) async -> Void,
               fallback: @escaping @MainActor () async -> Void) {
        guard task == nil else { return }
        self.neverStarted = neverStarted
        if neverStarted {
            // No Guest existed, so neither a clean-stop claim nor a grace wait
            // makes sense. The frozen zero-attempt proof permits release instead.
            task = Task { false }
            return
        }
        let deadline = now() + timeout
        // Unstructured Task does not inherit the caller's cancellation.
        task = Task { @MainActor [self] in
            await close(deadline)
            while !exit.failed {
                if let stopped = exit.stoppedAt, stopped <= deadline {
                    // Positive timely guestDidStop only: never fallback or no-VM proof.
                    FileHandle.standardError.write(Data("cengine.lifecycle.fresh-abort.guest-did-stop.clean\n".utf8))
                    return true
                }
                guard now() < deadline else { break }
                await wait()
            }
            usedFallback = true
            await fallback()
            return false
        }
    }
}

/// Owns the storage VM's boot and private service session inside the signed shim.
/// The shim server retains this owner and its authenticated control channel.
/// Returned Ready values and greetings are public metadata, not permission to
/// control the service or delete storage.
@MainActor final class RawStorageLifecycleShim {
    typealias Boot = StorageLifecycleServiceBootProtocol
    typealias Stream = StorageLifecycleStreamOwnership<SendableVirtioSocketConnection>.Stream

    nonisolated let policy: StorageLifecycleNativePolicy
    let machine: RawContainerVirtualMachine
    private let bootstrap: RawDiskBootTransaction
    private let binding: StorageIdentity.StoreBinding
    private let root: StorageIdentity.RootPublicKey
    private let parent: FileHandle
    private var state = StorageLifecycleStartupState()
    private let revocation = StorageLifecycleShimRevocation()
    nonisolated let controlLifetime = StorageLifecycleControlLifetime()
    private var disk: RawDiskBootTransaction.VerifiedStorageDiskBoot?
    private var cold: StorageLifecycleColdShim?
    private var fresh: StorageLifecycleFreshShim?
    private var service: StorageLifecycleServiceShim?
    private var adoption: StorageLifecycleAdoptionShim?
    private var adoptionStarting = false
    private var stopReply = StorageLifecycleStopReplyLifetime()
    private var privateStopRequested = false
    #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
    private var qualificationServiceProofRevoked = false
    #endif
    private var coordinator: PrivateStorageLifecycleBootCoordinator?
    private let freshAbort = StorageLifecycleFreshAbort()
    private var bootPort = StorageLifecycleBootPortOwnership()
    private var bootPortAttempt: Task<SendableVirtioSocketConnection, Error>?
    private var streams = StorageLifecycleStreamOwnership<SendableVirtioSocketConnection>()
    /// Host (VMShimServer) integration: one-shot service-ready and terminal hooks.
    var onReady: (@MainActor () -> Void)?
    var onTerminal: (@MainActor () -> Void)?

    convenience init(configuration: RawVirtualMachineConfiguration, bootstrap: RawDiskBootTransaction,
         binding: StorageIdentity.StoreBinding, root: StorageIdentity.RootPublicKey, parentBorrowedFD: Int32,
         policy: StorageLifecycleNativePolicy = .production) throws {
        try self.init(machine: try RawContainerVirtualMachine(configuration: configuration), bootstrap: bootstrap,
            binding: binding, root: root, parentBorrowedFD: parentBorrowedFD, policy: policy)
    }

    /// Hosts the SAME machine instance a VMShimServer already tracks.
    init(machine: RawContainerVirtualMachine, bootstrap: RawDiskBootTransaction,
         binding: StorageIdentity.StoreBinding, root: StorageIdentity.RootPublicKey, parentBorrowedFD: Int32,
         policy: StorageLifecycleNativePolicy = .production) throws {
        let descriptor = fcntl(parentBorrowedFD, F_DUPFD_CLOEXEC, 0)
        guard descriptor >= 0 else { throw Self.failure() }
        let parent = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        self.parent = parent; self.bootstrap = bootstrap; self.binding = binding; self.root = root; self.policy = policy
        self.machine = machine
        machine.storageLifecycleDidTerminate = { [weak self] in self?.terminate(vmDidTerminate: true) }
        machine.storageLifecycleJoinAbort = { [weak self] in
            guard let self, self.freshAbort.task != nil else { return false }
            try await self.stopForRollback()
            return true
        }
    }

    nonisolated static func diskMode(for action: Boot.Configuration.Action) -> RawContainerVirtualMachine.StorageLifecycleDiskMode {
        switch action {
        case .initialize: .initialize
        case .open, .coldOpenTakeover: .open
        case .resumeOpenTakeover: .resumeReadOnly
        }
    }
    private nonisolated static func failure() -> EngineError {
        .init(.conflict, "lifecycle shim refused; retain pending generation and disk leases")
    }

    /// Native parent authentication precedes VM start/disk mutation. The ROOT
    /// responder starts only after the actual 4105 initialize+sync+commit exchange.
    func prepareFreshDisk() async throws -> StorageLifecycleFreshProtocol.Greeting {
        try state.beginDisk()
        do {
            let parent = parent, policy = policy
            try await Self.worker {
                _ = try StorageLifecycleFreshShim.authenticatedParent(parentFD: parent.fileDescriptor, policy: policy)
            }
            try Task.checkCancellation()
            guard state.phase == .diskStarting else { throw Self.failure() }
            let disk = try await machine.startStorageLifecycleDisk(bootstrap: bootstrap, mode: .initialize)
            let capability = try disk.freshInitialization(), root = root, binding = binding, revocation = revocation,
                control = controlLifetime
            let responder = try await Self.worker {
                let responder = try StorageLifecycleFreshShim(capability: capability, storeID: binding.storeID,
                    pinnedRoot: root, parentBorrowedFD: parent.fileDescriptor, policy: policy)
                guard responder.greeting.matches(binding: binding) else { throw Self.failure() }
                try revocation.hold(.fresh) { responder.close() }
                try control.hold(.fresh) { responder.close() }
                try responder.start()
                return responder
            }
            do {
                try Task.checkCancellation()
                try state.diskReady()
                self.disk = disk; fresh = responder
                return responder.greeting
            } catch { responder.close(); throw error }
        } catch { containControlFailure(); throw error }
    }

    /// Mount only. No private service configuration or signature is sent here;
    /// ROOT must durably authorize this exact mounted launch before cold boot.
    func prepareColdDisk() async throws -> StorageLifecycleColdShimProtocol.Greeting {
        try await prepareRecoveryDisk(purpose: .cold)
    }

    func prepareResumeDisk() async throws -> StorageLifecycleColdShimProtocol.Greeting {
        try await prepareRecoveryDisk(purpose: .resumeReadOnly)
    }

    private func prepareRecoveryDisk(purpose: StorageLifecycleColdShimProtocol.Purpose) async throws -> StorageLifecycleColdShimProtocol.Greeting {
        try state.beginDisk()
        do {
            guard bootstrap.policy == (purpose == .cold ? .requireInitializedStorage : .resumeReadOnly) else { throw Self.failure() }
            let parent = parent, policy = policy
            try await Self.worker {
                _ = try StorageLifecycleColdShim.authenticatedParent(parentFD: parent.fileDescriptor, policy: policy)
            }
            try Task.checkCancellation()
            guard state.phase == .diskStarting else { throw Self.failure() }
            let disk = try await machine.startStorageLifecycleDisk(bootstrap: bootstrap, mode: purpose == .cold ? .open : .resumeReadOnly)
            let root = root, binding = binding, revocation = revocation, control = controlLifetime
            let responder = try await Self.worker {
                let responder = try StorageLifecycleColdShim(capability: disk, binding: binding,
                    pinnedRoot: root, parentBorrowedFD: parent.fileDescriptor, policy: policy, purpose: purpose)
                try revocation.hold(.cold) { responder.close() }
                try control.hold(.cold) { responder.close() }
                try responder.start()
                return responder
            }
            do {
                try Task.checkCancellation()
                try state.diskReady()
                self.disk = disk; cold = responder
                return responder.greeting
            } catch { responder.close(); throw error }
        } catch { containControlFailure(); throw error }
    }

    /// Local admission requires the claim from the independently authenticated
    /// ROOT mounted channel; the signed HOST configuration alone is insufficient.
    nonisolated static func validateLifecycleCold(_ configuration: Boot.Configuration,
        disk: RawDiskBootTransaction.VerifiedStorageDiskBoot,
        root: StorageIdentity.RootPublicKey, binding: StorageIdentity.StoreBinding) throws {
        guard configuration.rootPublicKey == root.publicData,
              configuration.signed.grant.identity == (try StorageLifecycleProtocol.Identity(
                binding: binding, generation: configuration.signed.grant.identity.generation)) else { throw failure() }
        let held = try disk.validateRecoveryDisk(purpose: configuration.action == .resumeOpenTakeover ? .resumeReadOnly : .cold)
        // validateRecoveryDisk retains exact live descriptor/device checks;
        // the durable binding deliberately contains no mount-instance device number.
        guard held.inode == binding.backing.identity.inode,
              held.volumeUUID?.uuidString.lowercased() == binding.backing.identity.volumeUUID.rawValue,
              disk.binding.bytes == binding.backing.size, disk.binding.ext4UUID == binding.expectedExt4UUID.rawValue else { throw failure() }
        try disk.validateColdConfiguration(configuration)
    }

    /// The grant must match the claim frozen by the independently authenticated
    /// ROOT fresh challenge. A different historical, even validly signed grant
    /// cannot configure the new Guest. `.open` starts the existing store directly
    /// (no fresh responder) and never mints a fresh-initialization capability.
    func boot(_ configuration: Boot.Configuration) async throws -> (Boot.Binding, Boot.Ready) {
        do {
            if configuration.action == .open { try await startExistingDisk(configuration) }
            try state.beginService()
            guard configuration.rootPublicKey == root.publicData, let disk else { throw Self.failure() }
            try configuration.validate()
            switch configuration.action {
            case .initialize: try disk.validateLifecycleInitialization(configuration.signed, root: root, binding: binding)
            case .open: try Self.validateLifecycleOpen(configuration, disk: disk, root: root, binding: binding)
            case .coldOpenTakeover, .resumeOpenTakeover:
                guard cold != nil else { throw Self.failure() }
                try Self.validateLifecycleCold(configuration, disk: disk, root: root, binding: binding)
            }
            let connection = try await connectBootPort()
            let held = SendableVirtioSocketConnection(connection)
            let coordinator: PrivateStorageLifecycleBootCoordinator
            do {
                coordinator = try PrivateStorageLifecycleBootCoordinator(verified: disk, configuration: configuration,
                    descriptor: connection.fileDescriptor, closeConnection: { held.connection.close() })
            } catch { connection.close(); throw error }
            self.coordinator = coordinator
            // PID1 owns DATA through this private session. It is not daemon control.
            let verified = try await Self.worker { try coordinator.bootstrap() }
            try Task.checkCancellation()
            guard state.phase == .serviceStarting else { throw Self.failure() }
            let binding = binding, parent = parent, revocation = revocation, policy = policy, control = controlLifetime
            let responder = try await Self.worker {
                let responder = try StorageLifecycleServiceShim(boot: verified, binding: binding,
                    parentBorrowedFD: parent.fileDescriptor, policy: policy)
                try revocation.hold(.service) { responder.close() }
                try control.hold(.service) { responder.close() }
                try responder.start()
                return responder
            }
            do {
                try Task.checkCancellation()
                try state.serviceReady()
                service = responder
                let ready = onReady; onReady = nil; ready?()
                // ROOT may still re-prove its provisioning fence on a lost reply;
                // retain the frozen fresh responder until this owner terminates.
                return (verified.binding, verified.ready)
            } catch { responder.close(); throw error }
        } catch { containControlFailure(); throw error }
    }

    /// Existing ext4 store: signatures (grant + ROOT reopen) are checked before
    /// VM start; there is no fresh claim, so freshInitialization is never used.
    private func startExistingDisk(_ configuration: Boot.Configuration) async throws {
        try state.beginDisk()
        try configuration.validate()
        guard configuration.action == .open, configuration.rootPublicKey == root.publicData else { throw Self.failure() }
        let parent = parent, policy = policy
        try await Self.worker {
            _ = try StorageLifecycleFreshShim.authenticatedParent(parentFD: parent.fileDescriptor, policy: policy)
        }
        try Task.checkCancellation()
        guard state.phase == .diskStarting else { throw Self.failure() }
        // Existing store: never consumes or requests fresh initialization.
        let disk = try await machine.startStorageLifecycleDisk(bootstrap: bootstrap,
            mode: Self.diskMode(for: configuration.action))
        try Self.validateLifecycleOpen(configuration, disk: disk, root: root, binding: binding)
        try Task.checkCancellation()
        try state.diskReady()
        self.disk = disk
    }
    nonisolated static func validateLifecycleOpen(_ configuration: Boot.Configuration,
                                                  disk: RawDiskBootTransaction.VerifiedStorageDiskBoot,
                                                  root: StorageIdentity.RootPublicKey, binding: StorageIdentity.StoreBinding) throws {
        try configuration.validate()
        let grant = configuration.signed.grant
        guard configuration.action == .open, disk.policy == .requireInitializedStorage,
              configuration.rootPublicKey == root.publicData,
              configuration.signed.isValidSignature(using: root), let reopen = configuration.reopen,
              reopen.isValidSignature(using: root), reopen.request.predecessor.grant == grant,
              reopen.request.predecessor.boot.identity == grant.identity,
              grant.identity == (try StorageLifecycleProtocol.Identity(binding: binding, generation: grant.identity.generation)) else {
            throw failure()
        }
        _ = try disk.validateHeldDisk()
    }

    func command(_ request: Boot.Frame, generation: StorageLifecycleControlLifetime.Generation) async throws -> Boot.Frame {
        try requireControlReady(generation)
        guard let coordinator else { throw Self.failure() }
        let control = controlLifetime
        let deadline = ProcessInfo.processInfo.systemUptime + 15
        do {
            let (reply, successor) = try await Self.worker {
                try control.withOperation(generation) { () -> (Boot.Frame, PrivateStorageLifecycleBootCoordinator.VerifiedBoot?) in
                    let before = try coordinator.currentBoot().ready.serviceEpoch
                    let reply = try coordinator.command(request, deadline: deadline)
                    let after = try coordinator.currentBoot()
                    return (reply, after.ready.serviceEpoch == before ? nil : after)
                }
            }
            try Task.checkCancellation()
            try requireControlReady(generation)
            if let successor {
                // Validated replacement: rotate the ROOT proof responder, then admit
                // exactly one lifecycle stream for the new generation.
                if let service {
                    try await Self.worker { try control.withOperation(generation) { try service.updateBoot(successor) } }
                }
                try requireControlReady(generation)
                try controlLifetime.withAdmission(generation) { streams.serviceChanged() }
            }
            return reply
        } catch { containControlFailure(generation); throw error }
    }

    /// Explicit trusted-owner command AFTER ROOT completion; never automatic boot
    /// activation or an Origin/FD supplied by IPC. The caller must implement a
    /// control-only fence without stopping VM/DATA. No wire-provided origin or
    /// capability can enable persistence.
    func enrollAdoption() async throws {
        try requireControlReady()
        guard !adoptionStarting, let coordinator else { throw Self.failure() }
        try controlLifetime.beginEnrollment()
        adoptionStarting = true
        defer { adoptionStarting = false }
        do {
            let responder: StorageLifecycleAdoptionShim
            if let adoption { responder = adoption }
            else {
                let binding = binding, parent = parent, policy = policy, revocation = revocation, control = controlLifetime
                let frozenSpec = try bootstrap.frozenAdoptionSpecification, cold = cold
                responder = try await Self.worker {
                    let boot = try coordinator.currentBoot()
                    let fence: @Sendable (StorageLifecycleAdoptionProtocol.Request) throws -> Void = { request in
                        try control.fence(request)
                        _ = try coordinator.currentBoot()
                    }
                    let responder: StorageLifecycleAdoptionShim
                    if boot.configuration.action == .coldOpenTakeover || boot.configuration.action == .resumeOpenTakeover {
                        guard let cold else { throw Self.failure() }
                        let joined = try cold.localEnrollmentSeed().join(boot)
                        responder = try StorageLifecycleAdoptionShim(coldBoot: joined, binding: binding,
                            frozenSpec: frozenSpec, parentBorrowedFD: parent.fileDescriptor, policy: policy,
                            controlLifetime: control, onFence: fence)
                    } else {
                        responder = try StorageLifecycleAdoptionShim(trustedBoot: boot, binding: binding,
                            frozenSpec: frozenSpec, parentBorrowedFD: parent.fileDescriptor, policy: policy,
                            controlLifetime: control, onFence: fence)
                    }
                    try revocation.hold(.adoption) { responder.close() }
                    return responder
                }
                // Retain process-lifetime fence state; failed pending never reopens.
                adoption = responder
            }
            try requireControlReady()
            try await Self.worker { try responder.start() }
            try Task.checkCancellation()
            try requireControlReady()
        } catch { containControlFailure(); throw error }
    }

    /// Only these actual VZ ports may be transferred to the nonexporting child.
    /// Keep the VZ objects alive until teardown; returned FDs are owned. A new
    /// stream revokes (shutdown, all duplicates) and closes its predecessor.
    func connect(_ stream: Stream, generation: StorageLifecycleControlLifetime.Generation) async throws -> FileHandle {
        try requireControlReady(generation)
        try controlLifetime.withAdmission(generation) { try streams.admit(stream) }
        do {
            let connection = try await machine.connect(toPort: stream.rawValue)
            do {
                try Task.checkCancellation()
                try requireControlReady(generation)
                let owned = fcntl(connection.fileDescriptor, F_DUPFD_CLOEXEC, 0)
                guard owned >= 0 else { throw Self.failure() }
                let handle = FileHandle(fileDescriptor: owned, closeOnDealloc: true)
                // Pin the descriptor independently of the returned handle. Closing
                // a daemon alias must not make the fence hit a reused FD.
                let pinned = fcntl(owned, F_DUPFD_CLOEXEC, 0)
                guard pinned >= 0 else { throw Self.failure() }
                let lease = FileHandle(fileDescriptor: pinned, closeOnDealloc: true)
                try controlLifetime.hold(.stream(stream.rawValue), generation: generation) {
                    StorageLifecycleShimRevocation.revokeStream(lease.fileDescriptor)
                }
                try controlLifetime.withAdmission(generation) {
                    if let previous = streams.install(SendableVirtioSocketConnection(connection), for: stream) {
                        StorageLifecycleShimRevocation.revokeStream(previous.connection.fileDescriptor)
                        previous.connection.close()
                    }
                }
                return handle
            } catch {
                StorageLifecycleShimRevocation.revokeStream(connection.fileDescriptor)
                connection.close(); throw error
            }
        } catch { containControlFailure(generation); throw error }
    }

    /// The accepted socket, not its path or a wire request, mints admission.
    func adoptControl(candidateFD: Int32) async throws -> (StorageLifecycleAdoptionShim.CommittedSession, StorageLifecycleControlLifetime.Generation) {
        try state.requireReady()
        guard let adoption, let coordinator else { throw Self.failure() }
        let control = controlLifetime
        let admitted = try await Self.worker {
            _ = try coordinator.currentBoot()
            let session = try adoption.committedSession(candidateFD: candidateFD)
            let generation = try control.adopt(session)
            do {
                try session.installServiceProof()
                return (session, generation)
            } catch { control.detach(generation); throw error }
        }
        do {
            try Task.checkCancellation()
            try requireControlReady(admitted.1)
            try control.withAdmission(admitted.1) {
                for old in streams.removeAll() { old.connection.close() }
                streams = StorageLifecycleStreamOwnership()
                // Original responders remain parent-pinned and were revoked by fence.
                service = nil
            }
            return admitted
        } catch { control.detach(admitted.1); throw error }
    }
    func currentReady(generation: StorageLifecycleControlLifetime.Generation) async throws -> (Boot.Binding, Boot.Ready) {
        try requireControlReady(generation)
        guard let coordinator else { throw Self.failure() }
        let control = controlLifetime
        let current = try await Self.worker {
            try control.withOperation(generation) { try coordinator.currentBoot() }
        }
        try requireControlReady(generation)
        return (current.binding, current.ready) // Metadata only, never a capability.
    }

    #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
    /// Deliberately preserve the VM, TLS, private boot/control, child streams and
    /// fresh responder. Losing this ROOT proof channel must not imply VM exit.
    func qualificationRevokeServiceProof() throws {
        try qualificationCheckLiveVM()
        guard !qualificationServiceProofRevoked, let service else { throw Self.failure() }
        qualificationServiceProofRevoked = true
        service.close()
        try qualificationCheckLiveVM()
    }
    /// May be called again after ROOT refuses completion. No mutation or bypass.
    func qualificationCheckLiveVM() throws {
        guard policy.isQualification else { throw Self.failure() }
        try requireControlReady()
        guard machine.qualificationIsRunning else { throw Self.failure() }
    }
    #endif

    /// Channel revocation is containment only. Explicit stop still has to prove
    /// VZ stopped; this owner and the machine retain disk handles if that fails.
    private func requireControlReady() throws {
        try controlLifetime.withAdmission { try state.requireReady() }
    }
    private func requireControlReady(_ generation: StorageLifecycleControlLifetime.Generation) throws {
        try controlLifetime.withAdmission(generation) { try state.requireReady() }
    }
    private func containControlFailure(_ generation: StorageLifecycleControlLifetime.Generation) {
        if controlLifetime.detach(generation) == .terminateUnenrolled { terminate() }
    }
    private func containControlFailure() {
        // A cancelled old task must not tear down an enrolled VM after its fence.
        // The decision and admission closure must be atomic with the ROOT reply
        // worker publishing enrollment. A snapshot read could race into teardown.
        if !controlLifetime.detach() { terminate() }
    }
    func terminate(preservingStopReply: Bool = false, vmDidTerminate: Bool = false) {
        let preserve = preservingStopReply || stopReply.preservesReply
        // ROOT ACK, not the daemon's later reply ACK, is the cutoff. detach is
        // atomic with ROOT publication; stale initial-generation callbacks preserve.
        if !preserve, !privateStopRequested, freshAbort.task == nil,
           StorageLifecycleFreshAbort.eligible(bootstrap.policy) {
            let retained = controlLifetime.detach()
            if retained && !vmDidTerminate { return }
            if !retained {
                let neverStarted = machine.beginFreshStorageAbort()
                freshAbort.begin(exit: machine.storageLifecycleExit, neverStarted: neverStarted, close: { [self] deadline in
                    await closeFreshStorageBoot(deadline: deadline)
                }, fallback: { [self] in
                    // A fallback is never a clean receipt, even after a late callback.
                    try? await machine.stopAfterFreshStorageAbort()
                })
            }
        }
        controlLifetime.terminate(revokeTransport: !preserve)
        state.terminate()
        // Adoption retains native socket authentication solely for this terminal
        // response. Closed coordinator/terminal control cannot prove service/attach.
        if !preserve { revocation.close(); adoption?.close() }
        fresh?.close(); cold?.close(); service?.close(); coordinator?.close()
        for stream in streams.removeAll() {
            StorageLifecycleShimRevocation.revokeStream(stream.connection.fileDescriptor)
            stream.connection.close()
        }
        onReady = nil
        if !preserve {
            let terminal = onTerminal; onTerminal = nil; terminal?()
        }
    }
    var shouldExitAfterFreshAbort: Bool {
        freshAbort.permitsProcessExit(control: controlLifetime, privateStopRequested: privateStopRequested)
    }
    var shouldExitAfterPrivateStop: Bool {
        privateStopRequested && stopReply.permitsProcessExit
    }

    /// VMShimServer must join the owner before generic teardown can touch VZ.
    func stopForRollback() async throws {
        if let task = freshAbort.task {
            let clean = await task.value
            guard StorageLifecycleFreshAbort.permitsRelease(clean: clean, forcedExit: machine.freshStorageForcedExit,
                                                            neverStarted: freshAbort.neverStarted) else {
                throw BackendResourceRollbackIncompleteError("fresh storage exit unproven; retaining disk leases")
            }
            return
        }
        try await machine.forceStop()
    }

    private func closeFreshStorageBoot(deadline: TimeInterval) async {
        coordinator?.close() // Exact existing 4106; no new wire command or ACPI.
        if let attempt = bootPortAttempt {
            if let connection = try? await attempt.value { connection.connection.close() }
        }
        guard !bootPort.consumed, machine.storageLifecycleExit.stoppedAt == nil,
              !machine.storageLifecycleExit.failed, machine.lifecycleBootstrapCompleted else { return }
        let remaining = deadline - ProcessInfo.processInfo.systemUptime
        guard remaining > 0 else { return }
        // Consume before awaiting or constructing a coordinator. This connection
        // sends zero bytes, solely EOF to PID1's existing boot-session cleanup.
        guard bootPort.claimEOFConnection() else { return }
        if let connection = try? await machine.connect(toPort: 4_106, timeout: .seconds(remaining)) {
            connection.close()
        }
    }

    func controlEnded(_ generation: StorageLifecycleControlLifetime.Generation) {
        if stopReply.finish(generation) { terminate() }
    }
    func stop() async throws { try await stop(generation: controlLifetime.captureGeneration()) }
    func stop(generation: StorageLifecycleControlLifetime.Generation) async throws {
        try controlLifetime.reservePrivateStop(generation)
        privateStopRequested = true // Reply EOF must not turn an explicit stop into startup abort.
        try stopReply.begin(generation)
        terminate(preservingStopReply: true)
        try await machine.forceStop()
    }
    private func connectBootPort() async throws -> VZVirtioSocketConnection {
        var lastError: (any Error)?
        for attempt in 0..<100 {
            try Task.checkCancellation()
            guard state.phase == .serviceStarting else { throw Self.failure() }
            guard !bootPort.consumed else { throw Self.failure() }
            let machine = machine
            let pending = Task { @MainActor in
                do {
                    let connection = try await machine.connectLifecycleBootPort(timeout: .milliseconds(100))
                    self.bootPort.connectedOrUncertain()
                    return SendableVirtioSocketConnection(connection)
                } catch {
                    // A timed-out VZ attempt may still accept in Guest. Its late
                    // connection is closed by awaitConnection; never open another.
                    if error is VirtioSocketConnectionTimeout { self.bootPort.connectedOrUncertain() }
                    throw error
                }
            }
            bootPortAttempt = pending
            do {
                let held = try await pending.value
                bootPort.connectedOrUncertain() // BEFORE coordinator construction, including its failures.
                bootPortAttempt = nil
                guard state.phase == .serviceStarting else { held.connection.close(); throw Self.failure() }
                return held.connection
            } catch {
                bootPortAttempt = nil
                if error is VirtioSocketConnectionTimeout { bootPort.connectedOrUncertain(); throw error }
                lastError = error
                try await Task.sleep(for: .milliseconds(min(25 * (attempt + 1), 250)))
            }
        }
        throw lastError ?? Self.failure()
    }
    // Blocking disk, Security, XPC and private-wire work never occupy MainActor
    // or Swift's cooperative executor. Every started operation is joined.
    private nonisolated static func worker<Value: Sendable>(_ operation: @escaping @Sendable () throws -> Value) async throws -> Value {
        try await withCheckedThrowingContinuation { continuation in
            Thread.detachNewThread {
                do { continuation.resume(returning: try operation()) }
                catch { continuation.resume(throwing: error) }
            }
        }
    }
}

/// Single-machine hosting seam for VMShimServer: the lifecycle owner must host
/// exactly the machine published in the server's VMShimMachineOwner, once.
@MainActor final class VMShimLifecycleHosting<Machine: AnyObject> {
    enum Phase: Sendable, Equatable { case idle, hosting, ready, terminal }
    private(set) var phase: Phase = .idle
    private weak var hosted: Machine?

    func host(_ machine: Machine, owner: VMShimMachineOwner<Machine>) throws {
        guard phase == .idle, owner.machine == nil else {
            throw EngineError(.conflict, "storage lifecycle hosting is one-shot per shim")
        }
        phase = .hosting; hosted = machine; owner.machine = machine
    }
    func ready(_ machine: Machine, owner: VMShimMachineOwner<Machine>) -> Bool {
        guard phase == .hosting, hosted === machine, owner.isCurrent(machine) else { return false }
        phase = .ready
        return true
    }
    /// True exactly once, for the hosted machine (or before any machine exists).
    func terminate(_ machine: Machine?) -> Bool {
        guard phase != .terminal, machine == nil || hosted === machine else { return false }
        phase = .terminal
        return true
    }
}
#endif

#if os(macOS)
import CEngineCore
import Dispatch
import Foundation
@preconcurrency import Virtualization

@MainActor public final class RawContainerVirtualMachine: NSObject, @preconcurrency VZVirtualMachineDelegate {
    public let identifier: String
    public let trunk: RawPacketTrunk
    public private(set) var control: GuestControlConnection?
    public private(set) var stopError: Error?

    private let machine: VZVirtualMachine
    #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
    /// Actual VZ state only; not a cached Ready, Guest proof or stop receipt.
    var qualificationIsRunning: Bool { machine.state == .running }
    #endif
    private let retainedAttachmentHandles: [FileHandle]
    private let maximumMemoryBytes: UInt64
    private var lifecycleDiskAttempted = false
    private var startLifetime = StorageLifecycleVMStartLifetime()
    let storageLifecycleExit = StorageLifecycleGuestExit()
    private var freshStorageAbortRequested = false
    private var lifecycleBootstrapConnection: StorageLifecycleBootstrapConnectionLifetime?
    private(set) var lifecycleBootstrapCompleted = false
    private(set) var freshStorageForcedExit = false
    var storageLifecycleDidTerminate: (@MainActor @Sendable () -> Void)?
    var storageLifecycleJoinAbort: (@MainActor () async throws -> Bool)?
    private var privateWorkloadStorage: PrivateWorkloadStorageCoordinator?
    let rootFSContentTransfers = RootFSContentTransfers()
    var workloadStorageDidTerminate: (@MainActor @Sendable () -> Void)?
    private var memoryPressureSource: (any DispatchSourceMemoryPressure)?
    private var memoryPressureState = MemoryBalloonPressureState()
    private lazy var timeSynchronizer = GuestTimeSynchronizer(
        synchronize: { [weak self] in
            guard let self else { throw CancellationError() }
            try await self.synchronizeTime()
        },
        failureHandler: { [weak self] error in
            self?.logTimeSynchronization(
                "periodic synchronization failed; retrying: \(error.localizedDescription)"
            )
        }
    )

    public init(configuration: RawVirtualMachineConfiguration) throws {
        identifier = configuration.id
        trunk = try RawPacketTrunk()
        let value = configuration.replacingNetworkFileHandle(trunk.virtualMachineFileHandle)
        let virtualizationConfiguration = try value.makeVirtualizationConfiguration()
        maximumMemoryBytes = virtualizationConfiguration.memorySize
        retainedAttachmentHandles = configuration.retainedAttachmentHandles
        machine = VZVirtualMachine(configuration: virtualizationConfiguration)
        super.init()
        machine.delegate = self
    }

    private func startMachine() async throws {
        // Count before VZ can run or suspend. A thrown start remains uncertain.
        try startLifetime.beginStart()
        try await machine.start()
    }

    func start(bootstrap: RawDiskBootTransaction) async throws {
        try await startMachine()
        try await initializeDisks(bootstrap)
        let guest = try await GuestTimeSynchronizationTransaction.start {
            let guest = try await self.awaitGuestControl()
            try await self.timeSynchronizer.synchronizeNow()
            return guest
        } teardown: {
            await self.timeSynchronizer.stop()
            self.control = nil
            if self.machine.canStop {
                try await self.machine.stop()
            }
        }
        control = guest
        timeSynchronizer.startPeriodic()
        startMemoryPressureMonitoring()
    }

    private func awaitGuestControl() async throws -> GuestControlConnection {
        var lastError: Error?
        for attempt in 0..<100 {
            var connection: VZVirtioSocketConnection?
            do {
                let deadline = DispatchTime.now().uptimeNanoseconds &+ 100_000_000
                let value = try await connect(
                    toPort: GuestProtocol.controlPort, timeout: .milliseconds(100)
                )
                connection = value
                let guest = GuestControlConnection(
                    connection: SendableVirtioSocketConnection(value)
                )
                try await guest.ping(deadlineNanoseconds: deadline)
                return guest
            } catch {
                connection?.close()
                lastError = error
                try await Task.sleep(for: .milliseconds(min(25 * (attempt + 1), 250)))
            }
        }
        throw lastError ?? EngineError(.internalError, "guest control service did not become ready")
    }

    private func synchronizeTime() async throws {
        let deadline = DispatchTime.now().uptimeNanoseconds &+ 1_000_000_000
        let connection = try await connect(
            toPort: GuestProtocol.controlPort, timeout: .seconds(1)
        )
        defer { connection.close() }
        let guest = GuestControlConnection(
            connection: SendableVirtioSocketConnection(connection)
        )
        try await guest.synchronizeTime(deadlineNanoseconds: deadline)
    }

    /// `.initialize`: fresh store; requires this boot's actual initialize+sync+commit.
    /// `.open`: existing ROOT-signed store; verified held disk WITHOUT ever
    /// requesting or minting the fresh-initialization capability.
    enum StorageLifecycleDiskMode: Sendable, Equatable {
        case initialize, open, resumeReadOnly

        var bootstrapPolicy: RawDiskBootTransaction.Policy {
            switch self {
            case .initialize: .journalDriven
            case .open: .requireInitializedStorage
            case .resumeReadOnly: .resumeReadOnly
            }
        }
    }

    /// Pure admission seam: `.open` never calls `fresh`.
    nonisolated static func admitLifecycleDisk<Disk>(_ disk: Disk, mode: StorageLifecycleDiskMode,
        fresh: (Disk) throws -> Void, held: (Disk) throws -> Void) throws {
        switch mode {
        case .initialize: try fresh(disk) // Never adopt a mounted existing disk.
        case .open, .resumeReadOnly: try held(disk)
        }
    }

    /// Split v2 startup: for `.initialize` ROOT allocates the generation after the
    /// real disk commit, before the private Guest authority is initialized.
    /// A failed attempt retains leases.
    func startStorageLifecycleDisk(bootstrap: RawDiskBootTransaction,
                                   mode: StorageLifecycleDiskMode) async throws -> RawDiskBootTransaction.VerifiedStorageDiskBoot {
        guard !lifecycleDiskAttempted, machine.state == .stopped else {
            throw EngineError(.conflict, "lifecycle disk boot is one-shot")
        }
        lifecycleDiskAttempted = true
        let policy = mode.bootstrapPolicy
        guard bootstrap.policy == policy else { throw EngineError(.conflict, "disk boot policy differs from frozen construction policy") }
        try Task.checkCancellation()
        try await startMachine()
        guard !freshStorageAbortRequested else { throw CancellationError() }
        try await initializeDisks(bootstrap, policy: policy)
        lifecycleBootstrapCompleted = true
        guard !freshStorageAbortRequested else { throw CancellationError() }
        try Task.checkCancellation()
        let verified = try bootstrap.verifiedStorageDiskBoot()
        try Self.admitLifecycleDisk(verified, mode: mode,
            fresh: { _ = try $0.freshInitialization() }, held: { _ = try $0.validateHeldDisk() })
        guard machine.state == .running else {
            throw EngineError(.conflict, "lifecycle VM stopped during disk initialization")
        }
        return verified
    }

    func startManagedWorkload(bootstrap: RawDiskBootTransaction, compatibilityProfile: String? = nil) async throws {
        try await startMachine()
        try await initializeDisks(bootstrap)
        let verified = try bootstrap.verifiedContainerBoot()
        var lastError: Error?
        for attempt in 0..<100 {
            try Task.checkCancellation()
            let connection: VZVirtioSocketConnection
            do {
                connection = try await connect(toPort: WorkloadStorageProtocol.port, timeout: .milliseconds(100))
            } catch {
                lastError = error
                try await Task.sleep(for: .milliseconds(min(25 * (attempt + 1), 250)))
                continue
            }
            let held = SendableVirtioSocketConnection(connection)
            let coordinator: PrivateWorkloadStorageCoordinator
            do {
                coordinator = try PrivateWorkloadStorageCoordinator(verified: verified,
                    descriptor: connection.fileDescriptor, compatibilityProfile: compatibilityProfile, closeConnection: { held.connection.close() },
                    onTerminal: { [weak self] in
                        Task { @MainActor in self?.workloadStorageDidTerminate?() }
                    })
            } catch { connection.close(); throw error }
            privateWorkloadStorage = coordinator
            _ = try await workloadStorageOperation(coordinator) { try $0.hello() }
            startMemoryPressureMonitoring()
            return // Configure follows image-layer streaming, never a second connection.
        }
        throw lastError ?? PrivateWorkloadStorageCoordinator.failure()
    }

    func validateOriginalConsumer(_ binding: OriginalConsumerObservationProtocol.Binding) throws {
        guard let privateWorkloadStorage else { throw PrivateWorkloadStorageCoordinator.failure() }
        try privateWorkloadStorage.validateOriginalConsumer(binding)
    }

    var prepareObserver: PrivatePrepareObservation? { privateWorkloadStorage?.prepareObserver }

    var workloadStorageIsTerminal: Bool { privateWorkloadStorage?.isTerminal ?? false }
    var permitsManagedRootPreparation: Bool { privateWorkloadStorage?.permitsRootPreparation ?? false }

    func workloadStorageReceipt() throws -> WorkloadStorageBootReceipt {
        guard let privateWorkloadStorage else { throw PrivateWorkloadStorageCoordinator.failure() }
        return try privateWorkloadStorage.currentReceipt()
    }

    func configureWorkloadStorage(_ configuration: WorkloadStorageConfiguration) async throws -> WorkloadStorageBootReceipt {
        guard let privateWorkloadStorage else { throw PrivateWorkloadStorageCoordinator.failure() }
        return try await workloadStorageOperation(privateWorkloadStorage) { try $0.configure(configuration) }
    }

    func workloadStorageCommand(_ command: WorkloadStorageProtocol.Frame) async throws -> WorkloadStorageProtocol.Frame {
        guard let privateWorkloadStorage else { throw PrivateWorkloadStorageCoordinator.failure() }
        return try await workloadStorageOperation(privateWorkloadStorage) { try $0.command(command) }
    }

    func prepareObservation(_ arm: ManagedPrepareCompatibilityProtocol.Arm) async throws -> WorkloadStorageProtocol.Frame {
        guard let coordinator = privateWorkloadStorage else { throw PrivateWorkloadStorageCoordinator.failure() }
        return try await withCheckedThrowingContinuation { continuation in
            Thread.detachNewThread {
                do { continuation.resume(returning: try coordinator.prepareObservation(arm)) }
                catch { continuation.resume(throwing: error) }
            }
        }
    }

    func observeRunningWorkloadStorage(expectedScope: WorkloadStorageProtocol.Scope,
        deadlineNanoseconds: UInt64) async throws -> WorkloadStorageProtocol.Frame {
        guard let privateWorkloadStorage else { throw PrivateWorkloadStorageCoordinator.failure() }
        // The continuation joins the owned synchronous operation, including its
        // deadline watchdog; socket expiry never leaves an unbounded guest call.
        return try await workloadStorageOperation(privateWorkloadStorage) {
            try $0.observeRunningWorkloadStorage(expectedScope: expectedScope, deadlineNanoseconds: deadlineNanoseconds)
        }
    }

    private func workloadStorageOperation<Value: Sendable>(_ coordinator: PrivateWorkloadStorageCoordinator,
        operation: @escaping @Sendable (PrivateWorkloadStorageCoordinator) throws -> Value) async throws -> Value {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                Thread.detachNewThread {
                    do { continuation.resume(returning: try operation(coordinator)) }
                    catch { continuation.resume(throwing: error) }
                }
            }
        } onCancel: { coordinator.cancel() }
    }

    private func initializeDisks(_ transaction: RawDiskBootTransaction,
                                 policy: RawDiskBootTransaction.Policy = .journalDriven) async throws {
        var lastError: Error?
        for attempt in 0..<100 {
            try Task.checkCancellation()
            let connection: VZVirtioSocketConnection
            do {
                connection = try await connect(toPort: DiskInitializationProtocol.port, timeout: .milliseconds(100))
            } catch {
                lastError = error
                try await Task.sleep(for: .milliseconds(min(25 * (attempt + 1), 250)))
                continue
            }
            // Only connection establishment is retried; a connected session is
            // consumed even if hello, manifest, acknowledgement or commit fails.
            let held = SendableVirtioSocketConnection(connection)
            let lifetime = StorageLifecycleBootstrapConnectionLifetime(
                revoke: { StorageLifecycleShimRevocation.revokeStream(held.connection.fileDescriptor) },
                close: { held.connection.close() })
            defer {
                lifetime.close()
                if lifecycleBootstrapConnection === lifetime { lifecycleBootstrapConnection = nil }
            }
            if lifecycleDiskAttempted {
                guard !freshStorageAbortRequested else { throw CancellationError() }
                lifecycleBootstrapConnection = lifetime
            }
            let worker = Task.detached {
                try transaction.run(descriptor: held.connection.fileDescriptor, policy: policy)
            }
            try await withTaskCancellationHandler {
                try await worker.value
                if lifecycleDiskAttempted { lifecycleBootstrapCompleted = true }
                try Task.checkCancellation()
            } onCancel: {
                worker.cancel()
            }
            return
        }
        throw lastError ?? EngineError(.internalError, "disk bootstrap service unavailable")
    }

    public func connect(toPort port: UInt32, timeout: Duration = .seconds(5)) async throws -> VZVirtioSocketConnection {
        try await connect(toPort: port, timeout: timeout,
                          timeoutError: EngineError(.internalError, "virtio socket connection timed out"))
    }

    /// Only lifecycle boot needs to distinguish an uncertain timed-out attempt
    /// from a refused connection. Keep the ordinary connect error contract intact.
    func connectLifecycleBootPort(timeout: Duration) async throws -> VZVirtioSocketConnection {
        try await connect(toPort: 4_106, timeout: timeout, timeoutError: VirtioSocketConnectionTimeout())
    }

    private func connect(toPort port: UInt32, timeout: Duration, timeoutError: any Error) async throws -> VZVirtioSocketConnection {
        guard let socket = machine.socketDevices.first as? VZVirtioSocketDevice else {
            throw EngineError(.internalError, "VM has no virtio socket device")
        }
        let connection = try await Self.awaitConnection(timeout: timeout, timeoutError: timeoutError) { completion in
            socket.__connect(toPort: port) { connection, error in
                completion(connection, error)
            }
        }
        return connection.connection
    }

    static func awaitConnection(
        timeout: Duration,
        timeoutError: any Error = EngineError(.internalError, "virtio socket connection timed out"),
        start: (@escaping @MainActor (VZVirtioSocketConnection?, Error?) -> Void) -> Void
    ) async throws -> SendableVirtioSocketConnection {
        try await awaitBoundedResult(
            timeout: timeout,
            timeoutError: timeoutError,
            start: { completion in
                start { connection, error in
                    if let connection {
                        completion(.success(SendableVirtioSocketConnection(connection)))
                    } else {
                        completion(.failure(error ?? EngineError(
                            .internalError, "virtio socket connection failed"
                        )))
                    }
                }
            },
            disposeLateSuccess: { $0.connection.close() }
        )
    }

    static func awaitBoundedResult<Value: Sendable>(
        timeout: Duration,
        timeoutError: any Error = EngineError(.internalError, "virtio socket connection timed out"),
        start: (@escaping @MainActor (Result<Value, Error>) -> Void) -> Void,
        disposeLateSuccess: @escaping @MainActor (Value) -> Void = { _ in }
    ) async throws -> Value {
        try await withCheckedThrowingContinuation { continuation in
            let attempt = BoundedAsyncAttempt(
                continuation: continuation,
                disposeLateSuccess: disposeLateSuccess
            )
            start { attempt.resolve($0) }
            Task { @MainActor in
                try? await Task.sleep(for: timeout)
                attempt.resolve(.failure(timeoutError))
            }
        }
    }

    public func install(listener: VZVirtioSocketListener, port: UInt32) throws {
        guard let socket = machine.socketDevices.first as? VZVirtioSocketDevice else {
            throw EngineError(.internalError, "VM has no virtio socket device")
        }
        socket.setSocketListener(listener, forPort: port)
    }

    public func pause() async throws {
        guard machine.canPause else { throw EngineError(.conflict, "container VM cannot be paused") }
        await timeSynchronizer.stop()
        do {
            try await machine.pause()
        } catch {
            if machine.state == .running {
                timeSynchronizer.startPeriodic()
            }
            throw error
        }
    }

    public func resume() async throws {
        guard machine.canResume else { throw EngineError(.conflict, "container VM cannot be resumed") }
        try await machine.resume()
        try await GuestTimeSynchronizationTransaction.resume {
            try await self.timeSynchronizer.synchronizeNow()
        } repause: {
            guard self.machine.canPause else {
                throw EngineError(.conflict, "resumed container VM cannot be re-paused")
            }
            try await self.machine.pause()
        } contain: {
            try await self.forceStop()
        }
        timeSynchronizer.startPeriodic()
    }

    func beginFreshStorageAbort() -> Bool {
        freshStorageAbortRequested = true
        let neverStarted = startLifetime.freezeForAbort()
        let held = lifecycleBootstrapConnection
        lifecycleBootstrapConnection = nil
        held?.close(revoking: true)
        return neverStarted
    }

    /// Successful stop completion is forced-exit evidence, never clean shutdown.
    /// A preexisting `.stopped` snapshot or didStopWithError alone cannot release leases.
    func stopAfterFreshStorageAbort() async throws {
        guard machine.canStop else {
            throw BackendResourceRollbackIncompleteError("fresh storage fallback exit unproven")
        }
        try await Self.awaitBoundedResult(timeout: .seconds(5), start: { complete in
            Task { @MainActor in
                do {
                    try await self.machine.stop()
                    // Positive VZ completion remains exit evidence even if the
                    // bounded waiter already timed out. It cannot change the
                    // cached clean-abort result or erase the fallback marker.
                    self.freshStorageForcedExit = true
                    complete(.success(()))
                } catch { complete(.failure(error)) }
            }
        })
    }

    public func forceStop() async throws {
        storageLifecycleDidTerminate?()
        if try await storageLifecycleJoinAbort?() == true { return }
        await rootFSContentTransfers.cancelAndJoin()
        privateWorkloadStorage?.close()
        await timeSynchronizer.stop()
        stopMemoryPressureMonitoring()
        control = nil
        if machine.state == .stopped { return }
        guard machine.canStop else {
            throw BackendResourceRollbackIncompleteError("VM stop not proven; retaining disk leases")
        }
        try await machine.stop()
        guard machine.state == .stopped else {
            throw BackendResourceRollbackIncompleteError("VM remains active; retaining disk leases")
        }
    }

    public func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        guard virtualMachine === machine else { return }
        storageLifecycleExit.guestDidStop()
        storageLifecycleDidTerminate?()
        rootFSContentTransfers.cancel()
        let unexpectedPrivateStop = privateWorkloadStorage?.isTerminal == false
        privateWorkloadStorage?.close()
        if unexpectedPrivateStop { workloadStorageDidTerminate?() }
        timeSynchronizer.cancel()
        stopMemoryPressureMonitoring()
        control = nil
    }

    public func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: any Error) {
        guard virtualMachine === machine else { return }
        storageLifecycleExit.didStopWithError()
        stopError = error
        storageLifecycleDidTerminate?()
        rootFSContentTransfers.cancel()
        let unexpectedPrivateStop = privateWorkloadStorage?.isTerminal == false
        privateWorkloadStorage?.close()
        if unexpectedPrivateStop { workloadStorageDidTerminate?() }
        timeSynchronizer.cancel()
        stopMemoryPressureMonitoring()
        control = nil
    }

    private func startMemoryPressureMonitoring() {
        guard memoryPressureSource == nil else { return }
        let source = DispatchSource.makeMemoryPressureSource(
            eventMask: [.normal, .warning, .critical],
            queue: .main
        )
        source.setEventHandler { [weak self, weak source] in
            guard let self, let event = source?.data else { return }
            Task { @MainActor in
                await self.handleMemoryPressure(event)
            }
        }
        memoryPressureSource = source
        source.resume()
    }

    private func stopMemoryPressureMonitoring() {
        memoryPressureSource?.cancel()
        memoryPressureSource = nil
        memoryPressureState = MemoryBalloonPressureState()
    }

    private func handleMemoryPressure(_ event: DispatchSource.MemoryPressureEvent) async {
        let constrained = event.contains(.warning) || event.contains(.critical)
        guard constrained || event.contains(.normal) else { return }
        let level = event.contains(.critical) ? "critical" : (event.contains(.warning) ? "warning" : "normal")
        let action = memoryPressureState.transition(toConstrained: constrained)
        guard action != .none else { return }
        guard let balloon = machine.memoryBalloonDevices.first as? VZVirtioTraditionalMemoryBalloonDevice else {
            logMemoryBalloon("pressure=\(level) ignored: VM has no memory balloon device")
            return
        }

        switch action {
        case .none:
            return
        case .restore:
            balloon.targetVirtualMachineMemorySize = maximumMemoryBytes
            logMemoryBalloon("pressure=normal target=\(maximumMemoryBytes) maximum=\(maximumMemoryBytes)")
        case let .reclaim(generation):
            guard machine.state == .running, let control else {
                logMemoryBalloon("pressure=\(level) reclaim skipped: guest is not running")
                return
            }
            do {
                struct Empty: Codable {}
                let status: GuestProtocol.MemoryStatus = try await control.request(
                    operation: "prepare-memory-reclaim",
                    payload: Empty(),
                    response: GuestProtocol.MemoryStatus.self
                )
                guard memoryPressureState.isCurrent(generation: generation, constrained: true) else { return }
                let maximum = maximumMemoryBytes
                let available = min(status.availableBytes, status.totalBytes)
                let target = MemoryBalloonPolicy.targetBytes(
                    maximumBytes: maximum,
                    availableBytes: available,
                    minimumBytes: VZVirtualMachineConfiguration.minimumAllowedMemorySize
                )
                balloon.targetVirtualMachineMemorySize = target
                logMemoryBalloon(
                    "pressure=\(level) total=\(status.totalBytes) available=\(available) reclaimed=\(maximum - target) target=\(target) maximum=\(maximum)"
                )
            } catch {
                guard memoryPressureState.isCurrent(generation: generation, constrained: true) else { return }
                logMemoryBalloon("pressure=\(level) reclaim failed open: \(error.localizedDescription)")
            }
        }
    }

    private func logMemoryBalloon(_ message: String) {
        FileHandle.standardError.write(Data("vm \(identifier) memory balloon: \(message)\n".utf8))
    }

    private func logTimeSynchronization(_ message: String) {
        FileHandle.standardError.write(
            Data("vm \(identifier) time synchronization: \(message)\n".utf8)
        )
    }
}

struct VirtioSocketConnectionTimeout: Error {}

@MainActor private final class BoundedAsyncAttempt<Value: Sendable> {
    private var continuation: CheckedContinuation<Value, Error>?
    private let disposeLateSuccess: @MainActor (Value) -> Void

    init(
        continuation: CheckedContinuation<Value, Error>,
        disposeLateSuccess: @escaping @MainActor (Value) -> Void
    ) {
        self.continuation = continuation
        self.disposeLateSuccess = disposeLateSuccess
    }

    func resolve(_ result: Result<Value, Error>) {
        let pending = continuation
        continuation = nil
        if let pending {
            pending.resume(with: result)
        } else if case let .success(value) = result {
            disposeLateSuccess(value)
        }
    }
}
#endif

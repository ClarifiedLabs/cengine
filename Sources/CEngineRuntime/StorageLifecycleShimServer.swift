#if os(macOS)
import CEngineCore
import Darwin
import Foundation

/// Native-authenticated transport for one retained Raw owner. EOF is fail-closed
/// until ROOT enrollment succeeds; afterward it detaches only old control.
/// No wire field can construct an owner or mint an adoption capability.
final class StorageLifecycleShimServer: @unchecked Sendable {
    typealias Wire = StorageLifecycleShimProtocol
    typealias Channel = StorageLifecycleShimChannel
    typealias Response = (Wire.Frame, FileHandle?)
    private let channel: Channel
    private let controlLifetime: StorageLifecycleControlLifetime?
    private let generation: StorageLifecycleControlLifetime.Generation?
    private let timeout: TimeInterval
    private let initialDeadline: DispatchTime?
    private let authenticate: @Sendable (Int32) throws -> Void
    private let operation: @MainActor @Sendable (Wire.Frame) async throws -> Response
    private let terminate: @MainActor @Sendable () -> Void
    private let controlEnded: @MainActor @Sendable () -> Void
    private let reader = DispatchQueue(label: "dev.cengine.lifecycle-shim.server-reader")
    private let writer = DispatchQueue(label: "dev.cengine.lifecycle-shim.server-writer")
    private let deadlines = DispatchQueue(label: "dev.cengine.lifecycle-shim.server-deadlines")
    private let lock = NSLock()
    private var closed = false, started = false, busy = false
    private var sequence: UInt64 = 0
    private var task: Task<Void, Never>?
    private var writing: DispatchGroup?
    private var authenticating: UUID?
    #if DEBUG
    enum Observation: Sendable {
        case idle
        case firstByte(DispatchTime)
        case admitted(UInt64, DispatchTime)
        case responding(UInt64, DispatchTime)
        case completed(UInt64)
        case cancelled(UInt64, Bool)
    }
    // Synchronous instrumentation only: observers must not block or reenter this
    // server (admission is observed under its lock). Never replaces clock or IO.
    private var observe: @Sendable (Observation) -> Void = { _ in }
    #endif

    /// Off-main native authentication MUST precede first channel IO, including
    /// receiving malformed requests. There is no unsigned production initializer.
    init(owner: RawStorageLifecycleShim, parentBorrowedFD: Int32, policy: StorageLifecycleNativePolicy = .production) throws {
        guard !Thread.isMainThread, owner.policy == policy else { throw Wire.Failure.unauthorized }
        let channel = try Channel(borrowedFD: parentBorrowedFD)
        do {
            let lease = try channel.lease()
            let (observed, team) = try StorageLifecycleFreshShim.authenticatedParent(parentFD: lease.fileDescriptor, policy: policy)
            self.channel = channel; timeout = Channel.budget; initialDeadline = nil
            controlLifetime = owner.controlLifetime
            let generation = try owner.controlLifetime.captureGeneration()
            self.generation = generation
            authenticate = { fd in
                let (current, currentTeam) = try StorageLifecycleFreshShim.authenticatedParent(parentFD: fd, policy: policy)
                guard current == observed, currentTeam == team else { throw Wire.Failure.unauthorized }
            }
            terminate = { owner.terminate() }
            controlEnded = { owner.controlEnded(generation) }
            operation = { request in
                try Self.validateProfile(for: request.operation, isQualification: policy.isQualification)
                try owner.controlLifetime.withAdmission(generation) {}
                var reply = Wire.Frame(sequence: request.sequence, operation: request.operation, reply: true)
                var descriptor: FileHandle?
                switch request.operation {
                case .prepare: reply.greeting = try await owner.prepareFreshDisk()
                case .prepareCold: reply.coldGreeting = try await owner.prepareColdDisk()
                case .prepareResume: reply.resumeGreeting = try await owner.prepareResumeDisk()
                case .configure:
                    guard let configuration = request.configuration else { throw Wire.Failure.invalid }
                    (reply.binding, reply.ready) = try await owner.boot(configuration)
                case .command:
                    guard let command = request.command else { throw Wire.Failure.invalid }
                    reply.command = try await owner.command(command, generation: generation)
                case .currentReady: (reply.binding, reply.ready) = try await owner.currentReady(generation: generation)
                case .connectLifecycle: descriptor = try await owner.connect(.lifecycle, generation: generation)
                case .connectWorkload: descriptor = try await owner.connect(.workload, generation: generation)
                case .connectAttachmentCSR: descriptor = try await owner.connect(.attachmentCSR, generation: generation)
                case .enrollAdoption:
                    try await owner.enrollAdoption()
                case .stop: try await owner.stop(generation: generation)
                #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
                case .qualificationRevokeServiceProof:
                    try owner.qualificationRevokeServiceProof()
                case .qualificationCheckLiveVM:
                    try owner.qualificationCheckLiveVM()
                #endif
                }
                return (reply, descriptor)
            }
        } catch { channel.close(); Task { @MainActor in owner.terminate() }; throw error }
    }
    /// Adopted path is separate from inherited parent authentication. The session
    /// was minted from this accepted FD and ROOT's exact committed fence.
    init(owner: RawStorageLifecycleShim, acceptedFD: Int32,
         session: StorageLifecycleAdoptionShim.CommittedSession,
         generation: StorageLifecycleControlLifetime.Generation, deadline: DispatchTime) throws {
        guard !Thread.isMainThread else { throw Wire.Failure.unauthorized }
        let channel = try Channel(borrowedFD: acceptedFD)
        do {
            try Channel.check(deadline)
            try session.withAdmission { try owner.controlLifetime.withAdmission(generation) {} }
            self.channel = channel; timeout = Channel.budget; initialDeadline = deadline
            controlLifetime = owner.controlLifetime; self.generation = generation
            authenticate = { _ in try session.validate() }
            terminate = {} // Candidate failure must never stop a surviving machine.
            controlEnded = { owner.controlEnded(generation) }
            operation = { request in
                try owner.controlLifetime.withAdmission(generation) {}
                var reply = Wire.Frame(sequence: request.sequence, operation: request.operation, reply: true)
                var descriptor: FileHandle?
                switch request.operation {
                case .currentReady: (reply.binding, reply.ready) = try await owner.currentReady(generation: generation)
                case .command:
                    guard let command = request.command else { throw Wire.Failure.invalid }
                    reply.command = try await owner.command(command, generation: generation)
                case .connectLifecycle: descriptor = try await owner.connect(.lifecycle, generation: generation)
                case .connectWorkload: descriptor = try await owner.connect(.workload, generation: generation)
                case .connectAttachmentCSR: descriptor = try await owner.connect(.attachmentCSR, generation: generation)
                case .stop: try await owner.stop(generation: generation)
                default: throw Wire.Failure.unauthorized
                }
                return (reply, descriptor)
            }
        } catch { channel.close(); owner.controlLifetime.detach(generation); throw error }
    }
    /// Profile admission is separate from namespace authentication. Ordinary
    /// production and compatibility peers have the same operation permissions.
    static func validateProfile(for operation: Wire.Operation, isQualification: Bool) throws {
        switch operation {
        case .enrollAdoption:
            guard !isQualification else { throw Wire.Failure.unauthorized }
        #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
        case .qualificationRevokeServiceProof, .qualificationCheckLiveVM:
            guard isQualification else { throw Wire.Failure.unauthorized }
        #endif
        default: break
        }
    }
    func start() throws {
        if let controlLifetime, let generation {
            try controlLifetime.hold(.transport, generation: generation) { [weak self] in self?.close() }
        }
        try lock.withLock {
            guard !closed, !started else { throw Wire.Failure.closed }
            started = true
        }
        let channel = channel, timeout = timeout, initialDeadline = initialDeadline
        // Fixed off-main reader remains active during VZ awaits. EOF cancels the
        // in-flight Task; only unenrolled owners are asynchronously terminated.
        reader.async { [weak self] in
            do {
                let lease = try channel.lease()
                var firstDeadline = initialDeadline
                while true {
                    #if DEBUG
                    self?.observe(.idle)
                    #endif
                    // Adoption keeps the accepted socket's initial deadline;
                    // no fresh budget or unbounded idle gap after its preface.
                    let deadline: DispatchTime
                    if let initial = firstDeadline { deadline = initial; firstDeadline = nil }
                    else {
                        try channel.waitForFirstByte(on: lease)
                        deadline = Channel.deadline(timeout)
                    }
                    #if DEBUG
                    self?.observe(.firstByte(deadline))
                    #endif
                    let packet = try Channel.receive(fd: lease.fileDescriptor, permitsDescriptor: false, deadline: deadline)
                    guard let server = self else { channel.close(); return }
                    let authenticationID = UUID()
                    server.lock.withLock { server.authenticating = authenticationID }
                    server.deadlines.asyncAfter(deadline: deadline) { [weak server] in
                        server?.close(authenticationID: authenticationID)
                    }
                    try server.authenticate(lease.fileDescriptor)
                    let request = try Wire.decode(packet.body)
                    try server.admit(request, deadline: deadline)
                    server.lock.withLock { server.authenticating = nil }
                }
            } catch { self?.close(); channel.close() }
        }
    }
    private func admit(_ request: Wire.Frame, deadline: DispatchTime) throws {
        // No pipelining during native work. A caller that has just received the
        // reply may race its writer's final bookkeeping; wait only for that write.
        if let writing = lock.withLock({ self.writing }) {
            guard writing.wait(timeout: deadline) == .success else { throw Wire.Failure.timeout }
        }
        try Channel.check(deadline)
        try lock.withLock {
            guard !closed, !busy, !request.reply, sequence < UInt64.max,
                  request.sequence == sequence + 1 else { throw Wire.Failure.invalid }
            busy = true; sequence = request.sequence
            task = Task { [weak self, operation] in
                do {
                    try Task.checkCancellation()
                    let result = try await operation(request)
                    try Task.checkCancellation()
                    self?.respond(result, request: request, deadline: deadline)
                } catch { self?.close() }
            }
            #if DEBUG
            observe(.admitted(request.sequence, deadline))
            #endif
        }
        deadlines.asyncAfter(deadline: deadline) { [weak self] in
            self?.close(operationSequence: request.sequence)
        }
    }
    private func respond(_ response: Response, request: Wire.Frame, deadline: DispatchTime) {
        #if DEBUG
        observe(.responding(request.sequence, deadline))
        #endif
        writer.async { [weak self] in
            guard let self else { return }
            do {
                try self.channel.check(); try Channel.check(deadline)
                let lease = try self.channel.lease()
                try self.authenticate(lease.fileDescriptor)
                if request.operation != .stop, let generation = self.generation {
                    try self.controlLifetime?.withAdmission(generation) {}
                }
                let (reply, descriptor) = response
                guard reply.reply, reply.sequence == request.sequence, reply.operation == request.operation,
                      (descriptor != nil) == request.operation.transfersDescriptor else { throw Wire.Failure.invalid }
                let bytes = try Wire.encode(reply)
                let writing = DispatchGroup(); writing.enter()
                defer { writing.leave() }
                try self.lock.withLock {
                    guard !self.closed else { throw Wire.Failure.closed }
                    self.writing = writing
                }
                try Channel.send(bytes, fd: lease.fileDescriptor, passing: descriptor?.fileDescriptor, deadline: deadline)
                self.lock.withLock {
                    // Keep the shim alive for the parent's post-reply authentication.
                    // stop() closes its channel only after that check. Remain busy
                    // until EOF (or this operation's original deadline), so no later
                    // request is admitted and an abandoned peer cannot keep us alive.
                    self.busy = request.operation == .stop
                    self.task = nil; self.writing = nil
                }
                #if DEBUG
                self.observe(.completed(request.sequence))
                #endif
            } catch { self.close() }
        }
    }
    /// Nonblocking containment. The caller retains Raw and all disk leases; this
    /// does not call stop, report drain, delete storage or synthesize a receipt.
    func close() { close(operationSequence: nil, authenticationID: nil) }
    private func close(operationSequence: UInt64? = nil, authenticationID: UUID? = nil) {
        let result: (Bool, Task<Void, Never>?) = lock.withLock {
            guard !closed else { return (false, nil) }
            if let operationSequence, !busy || sequence != operationSequence { return (false, nil) }
            if let authenticationID, authenticating != authenticationID { return (false, nil) }
            closed = true
            let pending = task; task = nil
            return (true, pending)
        }
        guard result.0 else { return }
        channel.close(); result.1?.cancel()
        // detach() joins private boot work, closes child streams and permanently denies
        // admission before any MainActor cleanup or ROOT fence reply can run.
        if controlLifetime == nil || generation.map({ controlLifetime?.detach($0) == .terminateUnenrolled }) == true {
            let terminate = terminate
            Task { @MainActor in terminate() }
        }
        let controlEnded = controlEnded
        Task { @MainActor in controlEnded() }
        #if DEBUG
        if let pending = result.1 { observe(.cancelled(lock.withLock { sequence }, pending.isCancelled)) }
        #endif
    }
    deinit { close() }
    #if DEBUG
    /// Private unit seam: validates framing/lifetime, never native authentication.
    init(testFD: Int32, timeout: TimeInterval = Channel.budget,
         controlLifetime: StorageLifecycleControlLifetime? = nil,
         observe: @escaping @Sendable (Observation) -> Void = { _ in },
         operation: @escaping @MainActor @Sendable (Wire.Frame) async throws -> Response,
         terminate: @escaping @MainActor @Sendable () -> Void = {}) throws {
        guard timeout > 0, timeout <= Channel.budget, timeout.isFinite else { throw Wire.Failure.invalid }
        channel = try Channel(borrowedFD: testFD); self.timeout = timeout; self.operation = operation; initialDeadline = nil
        self.terminate = terminate; controlEnded = {}; authenticate = { _ in }; self.observe = observe
        self.controlLifetime = controlLifetime
        self.generation = try controlLifetime?.captureGeneration()
    }
    /// Invoke the exact production operation-deadline callback, without waiting for its timer.
    func testingExpire(sequence: UInt64) { close(operationSequence: sequence) }
    func waitForWriterForTesting(deadline: DispatchTime) -> Bool {
        let joined = DispatchGroup(); joined.enter()
        writer.async { joined.leave() }
        return joined.wait(timeout: deadline) == .success
    }
    func waitForReaderForTesting(deadline: DispatchTime) -> Bool {
        let joined = DispatchGroup(); joined.enter()
        reader.async { joined.leave() }
        return joined.wait(timeout: deadline) == .success
    }
    #endif
}
#endif

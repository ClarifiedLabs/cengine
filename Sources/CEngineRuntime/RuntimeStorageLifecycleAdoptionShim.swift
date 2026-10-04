#if os(macOS)
import CEngineCore
import CryptoKit
import Darwin
import Foundation
import Security
import Synchronization
@preconcurrency import XPC

/// Value-only transition model, NOT an authentication seam or capability. The
/// responder owns its instance privately and authenticates every Mach message.
struct StorageLifecycleAdoptionFence {
    typealias Wire = StorageLifecycleAdoptionProtocol
    let origin: Wire.Origin
    let baseEpoch: UInt64
    private(set) var current: Wire.Request?
    private(set) var committed: Wire.Request?
    mutating func fence(_ request: Wire.Request) throws -> Bool {
        try request.validate()
        guard baseEpoch > 0, request.origin == origin, request.expectedEpoch >= baseEpoch else { throw StorageLifecycleAdoptionShim.Failure.unauthorized }
        if request == current { return false } // Includes already committed retries.
        guard try request.epoch > (current?.epoch ?? baseEpoch) else { throw StorageLifecycleAdoptionShim.Failure.unauthorized }
        current = request; committed = nil
        return true
    }
    mutating func commit(_ request: Wire.Request) throws {
        try request.validate()
        guard request == current else { throw StorageLifecycleAdoptionShim.Failure.unauthorized }
        committed = request
    }
}

/// Value-only scheduling policy, never an authentication or enrollment capability.
/// All transitions are serialized by the owning shim's lock. A running attempt
/// owns its slot until its registration authentication has actually settled.
struct StorageLifecycleAdoptionReconnectState {
    struct Retry: Equatable, Sendable {
        let generation: UUID
        let delay: TimeInterval
    }
    private(set) var enrolled = false
    private(set) var terminated = false
    private(set) var current: UUID?
    private(set) var running: UUID?
    private(set) var scheduled: Retry?
    private var backoff = 0
    private static let delays: [TimeInterval] = [0.25, 0.5, 1, 2, 5]

    mutating func begin() -> UUID? {
        guard !terminated, current == nil, running == nil, scheduled == nil else { return nil }
        let generation = UUID()
        current = generation; running = generation
        return generation
    }
    mutating func beginRetry(_ retry: Retry) -> UUID? {
        guard !terminated, scheduled == retry, current == nil, running == nil else { return nil }
        scheduled = nil; current = retry.generation; running = retry.generation
        return retry.generation
    }
    mutating func acknowledgeEnrollment(_ generation: UUID) {
        // A disconnect after native ACK authentication must not forget enrollment.
        guard !terminated, running == generation else { return }
        enrolled = true
    }
    mutating func disconnected(_ generation: UUID) -> Retry? {
        guard !terminated, current == generation else { return nil }
        current = nil
        return schedule()
    }
    mutating func finished(_ generation: UUID, succeeded: Bool) -> Retry? {
        guard running == generation else { return nil }
        running = nil
        if current == generation {
            if succeeded { backoff = 0 } else { current = nil }
        }
        return schedule()
    }
    mutating func terminate() {
        terminated = true; current = nil; scheduled = nil
        // Do not free running until the native authentication callback joins.
    }
    private mutating func schedule() -> Retry? {
        guard enrolled, !terminated, current == nil, running == nil, scheduled == nil else { return nil }
        let retry = Retry(generation: UUID(), delay: Self.delays[backoff])
        backoff = min(backoff + 1, Self.delays.count - 1)
        scheduled = retry
        return retry
    }
}

/// Pure timing/terminal policy, NOT proof of authentication or enrollment. The
/// owner serializes it with ACK side effects; native authentication stays outside.
struct StorageLifecycleAdoptionDeadline {
    let deadline: DispatchTime
    private(set) var result: Bool?
    private(set) var acceptedReplies = 0

    init(start: DispatchTime, initial: Bool, recovering: Bool = false) {
        // Cold/resume enrollment re-proves the completed transaction, including
        // multiple native child, mounted-disk and service challenges. Its whole
        // exchange cannot use the smaller fresh-enrollment budget after a reboot.
        // Keep one absolute deadline for enrollment + greeting, with room inside
        // the 110s daemon/shim channel budget. Reconnect still gets only 5s.
        deadline = start + (initial ? (recovering ? 90 : 30) : 5)
    }
    func permitsProgress(at now: DispatchTime) -> Bool {
        result == nil && now < deadline
    }
    mutating func acceptReply(at now: DispatchTime) -> Bool {
        guard permitsProgress(at: now) else { return false }
        acceptedReplies += 1
        return true
    }
    @discardableResult
    mutating func finish(at now: DispatchTime, succeeded: Bool) -> Bool {
        if result == nil { result = succeeded && now < deadline }
        return result == true
    }
}

/// Handles reattachment challenges using the storage shim's verified boot.
/// Decoded Origin/Ready values and host journals cannot replace that capability.
/// Fencing a control channel does not stop the VM or its data plane.
final class StorageLifecycleAdoptionShim: @unchecked Sendable {
    typealias Wire = StorageLifecycleAdoptionProtocol
    enum Failure: Error { case unauthorized, unavailable, invalidMessage }
    private final class Attempt: @unchecked Sendable {
        let gate: Mutex<StorageLifecycleAdoptionDeadline>
        let deadline: DispatchTime
        let done = DispatchSemaphore(value: 0)
        init(initial: Bool, recovering: Bool = false) {
            let timing = StorageLifecycleAdoptionDeadline(start: .now(), initial: initial, recovering: recovering)
            gate = Mutex(timing); deadline = timing.deadline
        }
    }
    private final class Channel: @unchecked Sendable {
        let connection: xpc_connection_t
        let generation: UUID
        let lock = NSLock()
        var closed = false
        var root: StorageLifecycleFreshShim.RootPeer? // Worker only.
        var serviceCounter: UInt64 = 0 // Same authenticated ROOT channel; never reset by UDS admission.
        init(_ connection: xpc_connection_t, generation: UUID) {
            self.connection = connection; self.generation = generation
        }
        func requireOpen() throws { try lock.withLock { if closed { throw Failure.unavailable } } }
        func close() {
            let cancel = lock.withLock { if closed { return false }; closed = true; return true }
            if cancel { xpc_connection_cancel(connection) }
        }
    }
    /// Nonserialized, live-gate-scoped proof. Native socket identity was checked at
    /// minting; consumers must revalidate immediately before control admission.
    final class CommittedSession: @unchecked Sendable {
        private weak var owner: StorageLifecycleAdoptionShim?
        let request: Wire.Request
        private let peer: FileHandle
        fileprivate init(owner: StorageLifecycleAdoptionShim, request: Wire.Request, peer: FileHandle) {
            self.owner = owner; self.request = request; self.peer = peer
        }
        func withAdmission<T>(_ body: () throws -> T) throws -> T {
            guard let owner else { throw Failure.unavailable }
            try owner.validateSession(request, descriptor: peer.fileDescriptor)
            return try owner.lock.withLock {
                guard !owner.transport.terminated, owner.state.committed == request else { throw Failure.unauthorized }
                return try body()
            }
        }
        func validate() throws {
            guard let owner else { throw Failure.unavailable }
            try owner.validateSession(request, descriptor: peer.fileDescriptor)
        }
        /// Install only AFTER the owner has reserved this socket's control
        /// generation. A rejected concurrent candidate must not replace proof.
        func installServiceProof() throws {
            guard let owner else { throw Failure.unavailable }
            let responder = StorageLifecycleAdoptedServiceResponder(session: self, trustedBoot: owner.trustedBoot)
            try withAdmission { owner.serviceResponder = responder }
        }
    }
    let origin: Wire.Origin
    private static let constructed = Mutex(false)
    private let team: String
    private let policy: StorageLifecycleNativePolicy
    private let backing: FileHandle
    private let worker = DispatchQueue(label: "dev.cengine.adoption-shim.worker")
    private let events = DispatchQueue(label: "dev.cengine.adoption-shim.events")
    private let retries = DispatchQueue(label: "dev.cengine.adoption-shim.retries")
    private let lock = NSLock()
    private var channel: Channel?
    private var transport = StorageLifecycleAdoptionReconnectState() // Lock only.
    private var retryWork: DispatchWorkItem? // At most one timer; lock only.
    private var state: StorageLifecycleAdoptionFence // lock only; survives ROOT reconnect.
    private let controlLifetime: StorageLifecycleControlLifetime
    private let onFence: @Sendable (Wire.Request) throws -> Void
    private let coldSeed: StorageLifecycleColdShimProtocol.ColdEnrollmentSeed?
    private let trustedBoot: PrivateStorageLifecycleBootCoordinator.VerifiedBoot
    private var serviceResponder: StorageLifecycleAdoptedServiceResponder?

    /// frozenSpec is the host-held launch specification, NOT caller-supplied IPC
    /// metadata. Launch UUID comes from the verified physical disk boot itself.
    convenience init(trustedBoot boot: PrivateStorageLifecycleBootCoordinator.VerifiedBoot,
         binding: StorageIdentity.StoreBinding, frozenSpec: Data, parentBorrowedFD: Int32,
         policy: StorageLifecycleNativePolicy = .production,
         controlLifetime: StorageLifecycleControlLifetime,
         onFence: @escaping @Sendable (Wire.Request) throws -> Void) throws {
        guard boot.configuration.action != .coldOpenTakeover, boot.configuration.action != .resumeOpenTakeover else { throw Failure.unauthorized }
        try self.init(boot: boot, cold: nil, binding: binding, frozenSpec: frozenSpec,
            parentBorrowedFD: parentBorrowedFD, policy: policy, controlLifetime: controlLifetime, onFence: onFence)
    }

    /// Cold enrollment accepts only a native local seed joined to actual 4106 completion.
    convenience init(coldBoot: StorageLifecycleColdShim.ColdVerifiedBoot,
         binding: StorageIdentity.StoreBinding, frozenSpec: Data, parentBorrowedFD: Int32,
         policy: StorageLifecycleNativePolicy = .production,
         controlLifetime: StorageLifecycleControlLifetime,
         onFence: @escaping @Sendable (Wire.Request) throws -> Void) throws {
        guard !Thread.isMainThread else { throw Failure.unavailable }
        try coldBoot.validate()
        try self.init(boot: coldBoot.boot, cold: coldBoot, binding: binding, frozenSpec: frozenSpec,
            parentBorrowedFD: parentBorrowedFD, policy: policy, controlLifetime: controlLifetime, onFence: onFence)
    }

    private init(boot: PrivateStorageLifecycleBootCoordinator.VerifiedBoot, cold: StorageLifecycleColdShim.ColdVerifiedBoot?,
         binding: StorageIdentity.StoreBinding, frozenSpec: Data, parentBorrowedFD: Int32,
         policy: StorageLifecycleNativePolicy,
         controlLifetime: StorageLifecycleControlLifetime,
         onFence: @escaping @Sendable (Wire.Request) throws -> Void) throws {
        guard !Thread.isMainThread, !frozenSpec.isEmpty else { throw Failure.unavailable }
        let (parent, team) = try StorageLifecycleFreshShim.authenticatedParent(parentFD: parentBorrowedFD, policy: policy)
        let held = try boot.validateHeldDisk()
        // The verified boot pins the exact current-mount descriptor independently.
        guard held.inode == binding.backing.identity.inode,
              held.volumeUUID?.uuidString.lowercased() == binding.backing.identity.volumeUUID.rawValue,
              boot.binding.bytes == binding.backing.size,
              boot.binding.ext4UUID == binding.expectedExt4UUID.rawValue,
              try StorageLifecycleProtocol.Identity(binding: binding, generation: boot.identity.generation) == boot.identity,
              try StorageLifecycleFreshShim.observe(parentFD: parentBorrowedFD) == parent else { throw Failure.unauthorized }
        let origin = try Wire.Origin(binding: .init(binding), rootPublicKey: boot.rootPublicKey.publicData,
            shimLaunchUUID: boot.binding.shimLaunchUUID,
            specSHA256: SHA256.hash(data: frozenSpec).map { String(format: "%02x", $0) }.joined())
        let seed = cold?.seed.value
        if let seed {
            try seed.validate()
            guard seed.successorOrigin == origin else { throw Failure.unauthorized }
        }
        let backing = try boot.duplicateHeldDisk()
        // One responder lifetime per shim process. Reconstructing from the same
        // verified boot must never reset high-water; reconnect reuses this object.
        try Self.constructed.withLock { claimed in
            guard !claimed else { throw Failure.unavailable }
            claimed = true
        }
        self.origin = origin; self.team = team; self.onFence = onFence; self.controlLifetime = controlLifetime
        self.policy = policy; self.backing = backing; self.trustedBoot = boot
        self.coldSeed = seed
        state = StorageLifecycleAdoptionFence(origin: origin, baseEpoch: seed?.baseEpoch ?? 1)
    }

    /// Initial enrollment remains synchronous. Thereafter ROOT reconnects on this
    /// SAME process-lifetime object, without resetting origin or fence high-water.
    func start() throws {
        guard !Thread.isMainThread else { throw Failure.unavailable }
        dispatchPrecondition(condition: .notOnQueue(events))
        dispatchPrecondition(condition: .notOnQueue(worker))
        dispatchPrecondition(condition: .notOnQueue(retries))
        // Include admission/queue delay, not just time spent waiting for XPC.
        let attempt = Attempt(initial: true, recovering: coldSeed != nil)
        let generation = try lock.withLock {
            guard let generation = transport.begin() else { throw Failure.unavailable }
            return generation
        }
        retries.async {
            defer { attempt.done.signal() }
            do { try self.connect(generation, attempt: attempt) }
            catch { attempt.gate.withLock { $0.finish(at: .now(), succeeded: false) } }
        }
        _ = attempt.done.wait(timeout: attempt.deadline)
        let succeeded = attempt.gate.withLock { $0.finish(at: .now(), succeeded: false) }
        guard succeeded else {
            let expired = lock.withLock {
                scheduleLocked(transport.disconnected(generation))
                return channel?.generation == generation ? channel : nil
            }
            expired?.close()
            // connect, not this waiter, owns running until native auth joins.
            throw Failure.unavailable
        }
    }
    private func connect(_ generation: UUID, attempt: Attempt) throws {
        var succeeded = false
        defer { lock.withLock { scheduleLocked(transport.finished(generation, succeeded: succeeded)) } }
        guard attempt.gate.withLock({ $0.permitsProgress(at: .now()) }) else { throw Failure.unavailable }
        let connection = xpc_connection_create_mach_service(policy.serviceName,
            events, UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED))
        let next = Channel(connection, generation: generation)
        do {
            try lock.withLock {
                guard !transport.terminated, transport.current == generation,
                      transport.running == generation else { throw Failure.unavailable }
                channel = next
            }
        } catch { next.close(); throw error }
        xpc_connection_set_event_handler(connection) { [weak self] message in
            guard let self else { next.close(); return }
            guard xpc_get_type(message) == XPC_TYPE_DICTIONARY else { self.transportClosed(next); return }
            let settled = Mutex(false), deadline = DispatchTime.now() + 5
            self.events.asyncAfter(deadline: deadline) {
                if !settled.withLock({ $0 }) { self.transportClosed(next) }
            }
            self.worker.async {
                defer { settled.withLock { $0 = true } }
                do { try self.respond(message, channel: next, deadline: deadline) }
                catch { self.transportClosed(next) }
            }
        }
        xpc_connection_resume(connection)
        do {
            // Enrollment must succeed before the greeting, on this same native
            // connection. ROOT selects the store using origin.binding and checks
            // the transferred live backing description, not metadata-derived FDs.
            if !lock.withLock({ transport.enrolled }) {
                try exchange(Self.registration(origin: origin, enrolling: backing.fileDescriptor, coldSeed: coldSeed), channel: next, attempt: attempt, enrolling: true)
            }
            // Once ROOT has acknowledged persistence, reconnect only proves the
            // registered shim. Never require the original daemon/controller alive.
            try exchange(Self.registration(origin: origin, enrolling: nil), channel: next, attempt: attempt)
            succeeded = attempt.gate.withLock { $0.finish(at: .now(), succeeded: true) }
            guard succeeded else { throw Failure.unavailable }
        } catch { transportClosed(next); throw error }
    }
    private func transportClosed(_ channel: Channel) {
        channel.close()
        lock.withLock { scheduleLocked(transport.disconnected(channel.generation)) }
    }
    /// Called only under lock. Timers retain the shim weakly; blocking exchange
    /// runs only on the dedicated serial retry queue, never events/worker/main.
    private func scheduleLocked(_ retry: StorageLifecycleAdoptionReconnectState.Retry?) {
        guard let retry else { return }
        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            let generation = self.lock.withLock {
                guard let generation = self.transport.beginRetry(retry) else { return nil as UUID? }
                self.retryWork = nil
                return generation
            }
            guard let generation else { return }
            try? self.connect(generation, attempt: Attempt(initial: false))
        }
        retryWork = work
        retries.asyncAfter(deadline: .now() + retry.delay, execute: work)
    }
    static func registration(origin: Wire.Origin, enrolling descriptor: Int32?,
                             coldSeed: StorageLifecycleColdShimProtocol.ColdEnrollmentSeed? = nil) throws -> xpc_object_t {
        try origin.validate()
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_int64(message, "version", PrivilegedPortProtocol.version)
        xpc_dictionary_set_string(message, "role", "storage-shim")
        xpc_dictionary_set_string(message, "operation", descriptor == nil
            ? "storage-lifecycle-adoption-shim" : "storage-lifecycle-adoption-enroll")
        let bytes = try Wire.encode(origin)
        bytes.withUnsafeBytes { xpc_dictionary_set_data(message, "request", $0.baseAddress, $0.count) }
        if let coldSeed {
            try coldSeed.validate()
            guard descriptor != nil, coldSeed.successorOrigin == origin else { throw Failure.unauthorized }
            xpc_dictionary_set_string(message, "operation", coldSeed.purpose == .cold
                ? "storage-lifecycle-cold-adoption-enroll" : "storage-lifecycle-resume-adoption-enroll")
            let encoded = try StorageLifecycleColdShimProtocol.encode(coldSeed)
            encoded.withUnsafeBytes { xpc_dictionary_set_data(message, coldSeed.purpose == .cold ? "cold-seed" : "resume-seed", $0.baseAddress, $0.count) }
        }
        if let descriptor { xpc_dictionary_set_fd(message, "backing-fd", descriptor) }
        return message
    }
    private func exchange(_ message: xpc_object_t, channel next: Channel,
                          attempt: Attempt, enrolling: Bool = false) throws {
        try next.requireOpen()
        let done = DispatchSemaphore(value: 0), accepted = Mutex(false)
        // Queue admission and encoding cannot renew the absolute budget.
        guard attempt.gate.withLock({ $0.permitsProgress(at: .now()) }) else { throw Failure.unavailable }
        // Never hold the waiter's gate across native submission. Cancellation
        // may race this send; accepting its reply still requires the live gate.
        xpc_connection_send_message_with_reply(next.connection, message, events) { [weak self] reply in
            guard let self else { next.close(); done.signal(); return }
            self.worker.async {
                defer { done.signal() }
                do {
                    // Security/native proofs may block: never hold the gate here.
                    try self.authenticate(reply, channel: next)
                    guard xpc_dictionary_get_bool(reply, "ok") else { throw Failure.invalidMessage }
                    if enrolling, let seed = self.coldSeed {
                        var count = 0
                        guard let raw = xpc_dictionary_get_data(reply, "reply", &count), count > 0,
                              count <= StorageLifecycleProtocol.maximumPayloadBytes else { throw Failure.invalidMessage }
                        _ = try StorageLifecycleColdShimProtocol.decodeEnrollmentAcknowledgement(Data(bytes: raw, count: count), for: seed)
                    }
                    // AFTER native authentication and typed ACK validation,
                    // accept enrollment and publish owner preservation together.
                    // A mere ACK reservation cannot survive timeout containment.
                    if enrolling {
                        try self.controlLifetime.publishEnrollment(acknowledging: attempt.gate)
                        self.lock.withLock { self.transport.acknowledgeEnrollment(next.generation) }
                    } else {
                        guard attempt.gate.withLock({ $0.acceptReply(at: .now()) }) else { throw Failure.unavailable }
                    }
                    accepted.withLock { $0 = true }
                } catch { self.transportClosed(next) }
            }
        }
        if done.wait(timeout: attempt.deadline) != .success {
            attempt.gate.withLock { $0.finish(at: .now(), succeeded: false) }
            transportClosed(next)
            // Cancellation cannot interrupt native Security authentication. Join
            // this callback before freeing the running slot: a hung auth may hold
            // one attempt, but must never accumulate retry workers behind it.
            done.wait()
            throw Failure.unavailable
        }
        guard accepted.withLock({ $0 }) else { transportClosed(next); throw Failure.unavailable }
        try next.requireOpen()
    }
    /// Lifetime termination revokes proofs; a transport disconnect alone does not.
    func close() {
        let channel = lock.withLock {
            transport.terminate()
            retryWork?.cancel(); retryWork = nil
            return self.channel
        }
        channel?.close()
    }
    deinit { close() }
    static func authenticateRoot(_ message: xpc_object_t, team: String,
                                 policy: StorageLifecycleNativePolicy = .production) throws -> StorageLifecycleFreshShim.RootPeer {
        try StorageLifecycleFreshShim.authenticateRoot(message, team: team, policy: policy)
    }
    private func authenticate(_ message: xpc_object_t, channel: Channel) throws {
        try channel.requireOpen()
        let peer = try Self.authenticateRoot(message, team: team, policy: policy)
        if let root = channel.root { guard peer == root else { throw Failure.unauthorized } }
        else { channel.root = peer }
        try lock.withLock { guard !transport.terminated, self.channel === channel else { throw Failure.unavailable } }
        try channel.requireOpen()
        // Deliberately no observe(oldParent). Native ROOT authorizes new epochs.
    }
    private func respond(_ message: xpc_object_t, channel: Channel, deadline: DispatchTime) throws {
        try authenticate(message, channel: channel)
        try lock.withLock { guard transport.enrolled else { throw Failure.unavailable } }
        guard let name = xpc_dictionary_get_string(message, "operation") else { throw Failure.invalidMessage }
        var size = 0
        guard let raw = xpc_dictionary_get_data(message, "request", &size), size > 0,
              size <= StorageLifecycleProtocol.maximumPayloadBytes else { throw Failure.invalidMessage }
        let bytes = Data(bytes: raw, count: size)
        let operation = String(cString: name)
        if operation == StorageLifecycleHandoffShimProtocol.operation {
            // Registered-shim recovery deliberately precedes new child/adoption:
            // no CommittedSession or adopted-service responder is required.
            typealias H = StorageLifecycleHandoffShimProtocol
            let challenge = try H.decodeChallenge(bytes)
            guard challenge.origin == origin, challenge.counter > channel.serviceCounter,
                  challenge.isFresh(at: UInt64(Date().timeIntervalSince1970 * 1000)),
                  DispatchTime.now() < deadline else { throw Failure.unauthorized }
            channel.serviceCounter = challenge.counter
            _ = try trustedBoot.validateHeldDisk()
            let now = DispatchTime.now()
            guard now < deadline else { throw Failure.unavailable }
            let remaining = Double(deadline.uptimeNanoseconds - now.uptimeNanoseconds) / 1_000_000_000
            let encoded: Data?
            do {
                encoded = try H.encode(trustedBoot.handoffProof(challenge,
                    deadline: ProcessInfo.processInfo.systemUptime + remaining))
            } catch PrivateStorageLifecycleBootCoordinator.HandoffFailure.busy {
                encoded = nil // Typed busy preserves this enrolled XPC channel.
            }
            try authenticate(message, channel: channel)
            _ = try trustedBoot.validateHeldDisk()
            guard DispatchTime.now() < deadline,
                  challenge.isFresh(at: UInt64(Date().timeIntervalSince1970 * 1000)),
                  let reply = xpc_dictionary_create_reply(message) else { throw Failure.unavailable }
            if let encoded {
                encoded.withUnsafeBytes { xpc_dictionary_set_data(reply, "reply", $0.baseAddress, $0.count) }
                xpc_dictionary_set_bool(reply, "ok", true)
            } else {
                xpc_dictionary_set_bool(reply, "ok", false)
                xpc_dictionary_set_string(reply, "code", "worker-busy")
            }
            xpc_connection_send_message(channel.connection, reply)
            return
        }
        if operation == "storage-lifecycle-adopted-service" || operation == "storage-lifecycle-adopted-service-change" {
            let service = try operation == "storage-lifecycle-adopted-service" ? Wire.decodeServiceChallenge(bytes) : nil
            let change = try operation == "storage-lifecycle-adopted-service-change" ? Wire.decodeServiceChangeChallenge(bytes) : nil
            guard let counter = service?.counter ?? change?.counter,
                  counter > channel.serviceCounter else { throw Failure.unauthorized }
            channel.serviceCounter = counter // Both purposes share one ROOT-channel ordering.
            let responder = try lock.withLock {
                guard !transport.terminated, let responder = serviceResponder else { throw Failure.unavailable }
                return responder
            }
            let encoded: Data
            if let service { encoded = try Wire.encode(responder.prove(service, deadline: deadline)) }
            else if let change { encoded = try Wire.encode(responder.prove(change, deadline: deadline)) }
            else { throw Failure.invalidMessage }
            try authenticate(message, channel: channel)
            try responder.withAdmission {
                guard DispatchTime.now() < deadline, let reply = xpc_dictionary_create_reply(message) else { throw Failure.unavailable }
                encoded.withUnsafeBytes { xpc_dictionary_set_data(reply, "reply", $0.baseAddress, $0.count) }
                xpc_dictionary_set_bool(reply, "ok", true)
                xpc_connection_send_message(channel.connection, reply)
            }
            return
        }
        let digest: Data
        switch String(cString: name) {
        case "storage-lifecycle-adoption-challenge":
            let challenge = try Wire.decodeChallenge(bytes)
            digest = try challenge.digest
            _ = try lock.withLock {
                guard !transport.terminated, DispatchTime.now() < deadline else { throw Failure.unavailable }
                try channel.requireOpen()
                return try state.fence(challenge.request)
            }
            // Callback must close OLD daemon control channels only, never VM/DATA.
            try onFence(challenge.request) // Exact retries must also prove the original drain succeeded.
        case "storage-lifecycle-adoption-commit":
            let commit = try Wire.decodeCommit(bytes)
            digest = try commit.digest
            try lock.withLock {
                guard !transport.terminated, DispatchTime.now() < deadline else { throw Failure.unavailable }
                try channel.requireOpen()
                try state.commit(commit.request)
            }
        default: throw Failure.invalidMessage
        }
        try authenticate(message, channel: channel)
        guard DispatchTime.now() < deadline, let reply = xpc_dictionary_create_reply(message) else { throw Failure.unavailable }
        let encoded = try Wire.encode(Wire.Reply(challengeSHA256: digest))
        xpc_dictionary_set_bool(reply, "ok", true)
        encoded.withUnsafeBytes { xpc_dictionary_set_data(reply, "reply", $0.baseAddress, $0.count) }
        xpc_connection_send_message(channel.connection, reply)
    }

    /// The future Unix admission router must supply its actual accepted socket,
    /// never a caller audit DTO. Duplicate pins its lifetime through proof use.
    func committedSession(candidateFD: Int32) throws -> CommittedSession {
        guard !Thread.isMainThread else { throw Failure.unavailable }
        let fd = fcntl(candidateFD, F_DUPFD_CLOEXEC, 0)
        guard fd >= 0 else { throw Failure.unauthorized }
        let peer = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        let request = try lock.withLock {
            guard !transport.terminated, let request = state.committed else { throw Failure.unauthorized }
            return request
        }
        try validateSession(request, descriptor: fd)
        return CommittedSession(owner: self, request: request, peer: peer)
    }
    private func validateSession(_ request: Wire.Request, descriptor: Int32) throws {
        guard !Thread.isMainThread else { throw Failure.unavailable }
        var token = audit_token_t(), size = socklen_t(MemoryLayout<audit_token_t>.size)
        var kind: Int32 = 0, kindSize = socklen_t(MemoryLayout<Int32>.size)
        var address = sockaddr_un(), addressSize = socklen_t(MemoryLayout<sockaddr_un>.size)
        guard getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &kind, &kindSize) == 0, kind == SOCK_STREAM,
              withUnsafeMutablePointer(to: &address, { pointer in
                  pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getpeername(descriptor, $0, &addressSize) }
              }) == 0, address.sun_family == AF_UNIX,
              getsockopt(descriptor, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &size) == 0,
              size == MemoryLayout<audit_token_t>.size, token.val.1 == geteuid(), token.val.3 == getuid() else {
            throw Failure.unauthorized
        }
        // A duplicate FD pins the description, not the remote socket's openness.
        // Reject EOF/errors without consuming queued control bytes.
        var byte: UInt8 = 0
        let peek = recv(descriptor, &byte, 1, MSG_PEEK | MSG_DONTWAIT)
        guard peek > 0 || (peek < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) else { throw Failure.unauthorized }
        let audit = withUnsafeBytes(of: token) { Data($0) }, pid = Int32(bitPattern: token.val.5)
        guard audit == request.daemonAudit,
              let identity = RuntimeProcessIdentity.processIdentity(pid: pid, pidVersion: token.val.7),
              identity.withUnsafeBytes({ $0.loadUnaligned(fromByteOffset: 16, as: UInt64.self) }) == request.daemonUniqueID else {
            throw Failure.unauthorized
        }
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: audit] as CFDictionary, [], &code) == errSecSuccess,
              let code else { throw Failure.unauthorized }
        try policy.validatePeer(code, pid: pid, role: .engine, expectedTeam: team)
        guard RuntimeProcessIdentity.processIdentity(pid: pid, pidVersion: token.val.7) == identity else { throw Failure.unauthorized }
        try lock.withLock { guard !transport.terminated, state.committed == request else { throw Failure.unauthorized } }
    }
}
#endif

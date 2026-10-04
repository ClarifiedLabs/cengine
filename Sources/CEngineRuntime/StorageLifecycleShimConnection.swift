#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Security

@_silgen_name("csops_audittoken")
nonisolated private func adoptedShimCodeStatus(_ pid: Int32, _ operation: UInt32,
    _ address: UnsafeMutableRawPointer, _ size: Int, _ token: UnsafeMutablePointer<audit_token_t>) -> Int32

/// Daemon connection to the storage shim. Fresh launches use the inherited channel
/// and actual child PID; reattachment uses the root helper's authorization and a
/// newly authenticated socket peer. Neither authenticates guest results: direct
/// service proof to the root helper is still required.
final class StorageLifecycleShimConnection: ManagedStorageLifecycleServiceTransport, @unchecked Sendable {
    private typealias Wire = StorageLifecycleShimProtocol
    private typealias Channel = StorageLifecycleShimChannel
    private typealias Boot = StorageLifecycleServiceBootProtocol
    private let channel: Channel
    private let authenticate: @Sendable (Int32) throws -> Void
    private let worker = DispatchQueue(label: "dev.cengine.lifecycle-shim.client")
    private let deadlines = DispatchQueue(label: "dev.cengine.lifecycle-shim.client-deadlines")
    private let lock = NSLock()
    private var closed = false
    private var pending: [UUID: @Sendable () -> Void] = [:]
    private var sequence: UInt64 = 0 // worker only
    private var attempted: Set<Wire.Operation> = [] // worker only
    private let timeout: TimeInterval
    #if DEBUG
    private var beforePublicationForTesting: (@Sendable (DispatchTime) -> Void)?
    private var beforeDeadlineForTesting: (@Sendable () -> Void)?
    #endif
    #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
    private let qualificationPolicy: StorageLifecycleNativePolicy
    private var qualificationRevocationAttempted = false // lock only
    #endif

    /// No arbitrary executable/team/namespace policy or metadata identity input.
    /// Call off-main: Security validation is synchronous and never dispatches VM work.
    init(parentBorrowedFD: Int32, expectedChildPID: Int32, policy: StorageLifecycleNativePolicy = .production) throws {
        guard !Thread.isMainThread else { throw Wire.Failure.unauthorized }
        let channel = try Channel(borrowedFD: parentBorrowedFD)
        do {
            let identity = try policy.currentIdentity(role: .engine)
            let observation = try Self.observe(childPID: expectedChildPID)
            try Self.validate(observation, childPID: expectedChildPID, team: identity.teamIdentifier, policy: policy)
            guard try Self.observe(childPID: expectedChildPID) == observation else { throw Wire.Failure.unauthorized }
            // The socketpair's peer token can name its creator rather than the
            // child. The explicit PID is supplied ONLY by the trusted spawn owner;
            // immutable child audit and direct-child unique IDs come from Mach/proc.
            self.channel = channel; timeout = Channel.budget
            #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
            qualificationPolicy = policy
            #endif
            authenticate = { _ in
                guard try Self.observe(childPID: expectedChildPID) == observation else { throw Wire.Failure.unauthorized }
                try Self.validate(observation, childPID: expectedChildPID, team: identity.teamIdentifier, policy: policy)
                guard try Self.observe(childPID: expectedChildPID) == observation else { throw Wire.Failure.unauthorized }
            }
        } catch { channel.close(); throw error }
    }
    /// Only authenticated native ROOT completion authorizes upgrade-safe auth.
    /// A socket path is merely a locator; no decoded status can select this path.
    static func connectAdopted(socketPath: String, authorization: StorageLifecycleAdoptedConnectionAuthorization) async throws -> StorageLifecycleShimConnection {
        let status = authorization.status
        let connection = try await Task.detached {
            try status.validate()
            let fd = try UnixSocket.connect(path: socketPath, timeoutMilliseconds: 5_000)
            defer { Darwin.close(fd) }
            return try StorageLifecycleShimConnection(adoptedBorrowedFD: fd, authorization: authorization)
        }.value
        do {
            // The preface only routes the socket. A reply proves that the server
            // installed and admitted this exact committed control generation.
            let ready = try await connection.currentReady()
            let binding = try status.origin.binding.value()
            guard ready.binding.shimLaunchUUID == status.origin.shimLaunchUUID,
                  ready.binding.ext4UUID == binding.expectedExt4UUID.rawValue,
                  ready.binding.bytes == binding.backing.size else { throw Wire.Failure.unauthorized }
            try Task.checkCancellation()
            return connection
        }
        catch { connection.cancel(); throw error }
    }

    /// Unlike inherited socketpairs, this must be a native connected UDS whose
    /// LOCAL_PEERTOKEN is the exact ROOT-registered shim, not a spawn-parent pin.
    init(adoptedBorrowedFD: Int32, status: StorageLifecycleAdoptionRootProtocol.Status,
         policy: StorageLifecycleNativePolicy = .production) throws {
        guard !Thread.isMainThread else { throw Wire.Failure.unauthorized }
        try status.validate()
        let channel = try Channel(borrowedFD: adoptedBorrowedFD)
        do {
            let lease = try channel.lease(), fd = lease.fileDescriptor
            let observed = try Self.observeAdopted(fd: fd, status: status)
            let identity = try policy.currentIdentity(role: .engine)
            let authenticate: @Sendable (Int32) throws -> Void = { fd in
                guard try Self.observeAdopted(fd: fd, status: status) == observed else { throw Wire.Failure.unauthorized }
                var code: SecCode?
                guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: status.shimAudit] as CFDictionary,
                    [], &code) == errSecSuccess, let code else { throw Wire.Failure.unauthorized }
                let token = status.shimAudit.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) }
                try policy.validatePeer(code, pid: Int32(bitPattern: token.val.5), role: .engine,
                    expectedTeam: identity.teamIdentifier)
                guard try Self.observeAdopted(fd: fd, status: status) == observed else { throw Wire.Failure.unauthorized }
            }
            try authenticate(fd)
            try Channel.sendRaw(Wire.adoptionPreface, fd: fd, deadline: Channel.deadline(5))
            try authenticate(fd)
            self.channel = channel; self.authenticate = authenticate; timeout = Channel.budget
            #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
            qualificationPolicy = policy
            #endif
        } catch { channel.close(); throw error }
    }
    /// ROOT already validated the enrolled, mapped code, including its frozen
    /// CDHash. Re-resolving SecCode's static path here would validate the NEW
    /// executable after atomic replacement, not this still-running old shim.
    private init(adoptedBorrowedFD: Int32, authorization: StorageLifecycleAdoptedConnectionAuthorization) throws {
        guard !Thread.isMainThread else { throw Wire.Failure.unauthorized }
        let status = authorization.status
        let channel = try Channel(borrowedFD: adoptedBorrowedFD)
        do {
            let lease = try channel.lease(), fd = lease.fileDescriptor
            let observed = try Self.observeAdopted(fd: fd, status: status)
            let authenticate: @Sendable (Int32) throws -> Void = { fd in
                guard try Self.observeAdopted(fd: fd, status: status) == observed else { throw Wire.Failure.unauthorized }
                var token = status.shimAudit.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) }
                var flags: UInt32 = 0
                guard adoptedShimCodeStatus(Int32(bitPattern: token.val.5), 0, &flags,
                    MemoryLayout<UInt32>.size, &token) == 0,
                    Self.validAdoptedCodeFlags(flags) else { throw Wire.Failure.unauthorized }
                guard try Self.observeAdopted(fd: fd, status: status) == observed else { throw Wire.Failure.unauthorized }
            }
            try authenticate(fd)
            try Channel.sendRaw(Wire.adoptionPreface, fd: fd, deadline: Channel.deadline(5))
            try authenticate(fd)
            self.channel = channel; self.authenticate = authenticate; timeout = Channel.budget
            #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
            qualificationPolicy = authorization.policy
            #endif
        } catch { channel.close(); throw error }
    }
    /// Pure rejection predicate, not an authentication or capability-minting seam.
    static func validAdoptedCodeFlags(_ flags: UInt32) -> Bool {
        // XNU cs_blobs.h: CS_VALID | CS_RUNTIME; reject CS_ADHOC | CS_DEBUGGED.
        let required: UInt32 = 0x0000_0001 | 0x0001_0000
        let forbidden: UInt32 = 0x0000_0002 | 0x1000_0000
        return flags & required == required && flags & forbidden == 0
    }
    private static func observeAdopted(fd: Int32, status: StorageLifecycleAdoptionRootProtocol.Status) throws -> Data {
        var token = audit_token_t(), size = socklen_t(MemoryLayout<audit_token_t>.size)
        var address = sockaddr_un(), addressSize = socklen_t(MemoryLayout<sockaddr_un>.size)
        guard getuid() == geteuid(),
              withUnsafeMutablePointer(to: &address, { pointer in
                  pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getpeername(fd, $0, &addressSize) }
              }) == 0, address.sun_family == AF_UNIX, address.sun_path.0 != 0,
              getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &size) == 0,
              size == MemoryLayout<audit_token_t>.size,
              token.val.1 == geteuid(), token.val.3 == getuid(),
              withUnsafeBytes(of: token, { Data($0) }) == status.shimAudit else { throw Wire.Failure.unauthorized }
        let pid = Int32(bitPattern: token.val.5)
        guard pid > 0, pid != getpid(),
              let process = RuntimeProcessIdentity.processIdentity(pid: pid, pidVersion: token.val.7),
              process.withUnsafeBytes({ $0.loadUnaligned(fromByteOffset: 16, as: UInt64.self) }) == status.shimUniqueID else {
            throw Wire.Failure.unauthorized
        }
        var byte: UInt8 = 0
        let peek = recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT)
        guard peek > 0 || (peek < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) else { throw Wire.Failure.unauthorized }
        return process
    }
    private struct Observation: Equatable, Sendable {
        let ownAudit: Data, childAudit: Data, own: Data, child: Data
    }
    private static func audit(_ task: mach_port_t) throws -> audit_token_t {
        var token = audit_token_t(), count: mach_msg_type_number_t = 8
        let result = withUnsafeMutablePointer(to: &token) {
            $0.withMemoryRebound(to: integer_t.self, capacity: 8) { task_info(task, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count) }
        }
        guard result == KERN_SUCCESS, count == 8 else { throw Wire.Failure.unauthorized }
        return token
    }
    private static func observe(childPID: Int32) throws -> Observation {
        guard childPID > 0, childPID != getpid(), getuid() == geteuid() else { throw Wire.Failure.unauthorized }
        var task: mach_port_t = 0
        guard task_name_for_pid(mach_task_self_, childPID, &task) == KERN_SUCCESS else { throw Wire.Failure.unauthorized }
        defer { mach_port_deallocate(mach_task_self_, task) }
        let ownAudit = try audit(mach_task_self_), childAudit = try audit(task)
        guard ownAudit.val.5 == UInt32(getpid()), childAudit.val.5 == UInt32(childPID),
              childAudit.val.1 == geteuid(), childAudit.val.3 == getuid(),
              let own = RuntimeProcessIdentity.processIdentity(pid: getpid(), pidVersion: ownAudit.val.7),
              let child = RuntimeProcessIdentity.processIdentity(pid: childPID, pidVersion: childAudit.val.7),
              child.withUnsafeBytes({ $0.loadUnaligned(fromByteOffset: 24, as: UInt64.self) }) ==
                own.withUnsafeBytes({ $0.loadUnaligned(fromByteOffset: 16, as: UInt64.self) }), child != own else { throw Wire.Failure.unauthorized }
        return Observation(ownAudit: withUnsafeBytes(of: ownAudit) { Data($0) },
            childAudit: withUnsafeBytes(of: childAudit) { Data($0) }, own: own, child: child)
    }
    private static func validate(_ observed: Observation, childPID: Int32, team: String, policy: StorageLifecycleNativePolicy) throws {
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: observed.childAudit] as CFDictionary,
            [], &code) == errSecSuccess, let code else { throw Wire.Failure.unauthorized }
        try policy.validatePeer(code, pid: childPID, role: .engine, expectedTeam: team)
    }
    func prepareFreshDisk() async throws -> StorageLifecycleFreshProtocol.Greeting {
        let reply = try await exchange(.prepare)
        guard let greeting = reply.frame.greeting else { cancel(); throw Wire.Failure.invalid }
        return greeting
    }
    func prepareColdDisk() async throws -> StorageLifecycleColdShimProtocol.Greeting {
        let reply = try await exchange(.prepareCold)
        guard let greeting = reply.frame.coldGreeting else { cancel(); throw Wire.Failure.invalid }
        return greeting
    }
    func prepareResumeDisk() async throws -> StorageLifecycleColdShimProtocol.Greeting {
        let reply = try await exchange(.prepareResume)
        guard let greeting = reply.frame.resumeGreeting else { cancel(); throw Wire.Failure.invalid }
        return greeting
    }
    func configure(_ configuration: StorageLifecycleServiceBootProtocol.Configuration) async throws -> ManagedStorageLifecycleServiceReady {
        let reply = try await exchange(.configure, configuration: configuration)
        guard let binding = reply.frame.binding, let ready = reply.frame.ready else { cancel(); throw Wire.Failure.invalid }
        return .init(binding: binding, ready: ready)
    }
    /// Metadata from the live shim, not a ROOT service-proof capability.
    func currentReady() async throws -> ManagedStorageLifecycleServiceReady {
        let reply = try await exchange(.currentReady)
        guard let binding = reply.frame.binding, let ready = reply.frame.ready else { cancel(); throw Wire.Failure.invalid }
        return .init(binding: binding, ready: ready)
    }
    func command(_ frame: StorageLifecycleServiceBootProtocol.Frame) async throws -> StorageLifecycleServiceBootProtocol.Frame {
        try await command(frame, deadlineNanoseconds: nil)
    }
    func command(_ frame: StorageLifecycleServiceBootProtocol.Frame, deadlineNanoseconds: UInt64?) async throws -> StorageLifecycleServiceBootProtocol.Frame {
        let reply = try await exchange(.command, command: frame, deadlineNanoseconds: deadlineNanoseconds)
        guard let result = reply.frame.command, result.binding == frame.binding,
              result.sequence == frame.sequence, result.serviceEpoch == frame.serviceEpoch else { cancel(); throw Wire.Failure.invalid }
        return result
    }
    #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
    /// No authority result: closes only the live shim's service-proof responder.
    /// Repeated local attempts fail without revoking the private parent channel.
    func qualificationRevokeServiceProof() async throws {
        guard qualificationPolicy.isQualification else { throw Wire.Failure.unauthorized }
        try lock.withLock {
            guard !closed, !qualificationRevocationAttempted else { throw Wire.Failure.invalid }
            qualificationRevocationAttempted = true
        }
        _ = try await exchange(.qualificationRevokeServiceProof)
    }
    /// Read-only VZ state observation, never a replacement for ROOT service proof.
    func qualificationCheckLiveVM() async throws {
        guard qualificationPolicy.isQualification else { throw Wire.Failure.unauthorized }
        _ = try await exchange(.qualificationCheckLiveVM)
    }
    #endif
    /// Trusted startup calls this only after bootFresh has completed ROOT proof.
    func enrollAdoption() async throws { _ = try await exchange(.enrollAdoption) }
    func connectLifecycle() async throws -> FileHandle { try await connect(.connectLifecycle) }
    func connectWorkload() async throws -> FileHandle { try await connect(.connectWorkload) }
    /// Dedicated 4108 stream; the shim replaces and closes any previous one.
    func connectAttachmentCSR() async throws -> FileHandle { try await connect(.connectAttachmentCSR) }
    private func connect(_ operation: Wire.Operation) async throws -> FileHandle {
        let reply = try await exchange(operation)
        guard let descriptor = reply.descriptor else { cancel(); throw Wire.Failure.invalid }
        return descriptor
    }
    /// Success means only the shim's actual Raw.stop returned successfully. It is
    /// not a process-exit capability, drain receipt or permission to delete a disk.
    func stop() async throws { _ = try await exchange(.stop); cancel() }
    func cancel() { cancel(requiringPending: nil) }
    private func cancel(requiringPending id: UUID?) {
        let callbacks: [@Sendable () -> Void]? = lock.withLock {
            if let id, pending[id] == nil { return nil }
            closed = true
            let callbacks = Array(pending.values); pending.removeAll()
            return callbacks
        }
        guard let callbacks else { return }
        channel.close()
        for callback in callbacks { callback() }
    }
    deinit { channel.close() }
    private struct Reply: Sendable { let frame: Wire.Frame; let descriptor: FileHandle? }
    private final class Completion: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<Reply, any Error>?
        init(_ continuation: CheckedContinuation<Reply, any Error>) { self.continuation = continuation }
        func finish(_ result: Result<Reply, any Error>) {
            let next = lock.withLock { let next = continuation; continuation = nil; return next }
            next?.resume(with: result)
        }
    }
    private func exchange(_ operation: Wire.Operation, configuration: Boot.Configuration? = nil, command: Boot.Frame? = nil,
                          deadlineNanoseconds: UInt64? = nil) async throws -> Reply {
        let localDeadline = Channel.deadline(timeout), id = UUID()
        // Check raw uptime first: DispatchTime(uptimeNanoseconds: 0) means now,
        // not an already-expired deadline. Reject before admission or any IO.
        if let deadlineNanoseconds, DispatchTime.now().uptimeNanoseconds >= deadlineNanoseconds {
            throw Wire.Failure.timeout
        }
        // One bound covers queueing, authentication, every send/receive and reply
        // publication. A caller may shorten, but never extend, the channel budget.
        let deadline = DispatchTime(uptimeNanoseconds: min(localDeadline.uptimeNanoseconds,
            deadlineNanoseconds ?? localDeadline.uptimeNanoseconds))
        let result: Reply = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let completion = Completion(continuation)
                let accepted = lock.withLock {
                    guard !closed else { return false }
                    pending[id] = { completion.finish(.failure(Wire.Failure.closed)) }; return true
                }
                guard accepted else { completion.finish(.failure(Wire.Failure.closed)); return }
                deadlines.asyncAfter(deadline: deadline) { [weak self] in
                    #if DEBUG
                    self?.beforeDeadlineForTesting?()
                    #endif
                    self?.cancel(requiringPending: id)
                }
                worker.async { [self] in
                    do {
                        try channel.check(); try Channel.check(deadline)
                        guard sequence < UInt64.max else { throw Wire.Failure.invalid }
                        if !operation.isRepeatable {
                            guard attempted.insert(operation).inserted else { throw Wire.Failure.invalid }
                        }
                        sequence += 1
                        let request = Wire.Frame(sequence: sequence, operation: operation, reply: false,
                            configuration: configuration, command: command)
                        let bytes = try Wire.encode(request)
                        let lease = try channel.lease(), fd = lease.fileDescriptor
                        try authenticate(fd); try channel.check(); try Channel.check(deadline)
                        try Channel.send(bytes, fd: fd, deadline: deadline)
                        try authenticate(fd); try channel.check(); try Channel.check(deadline)
                        let packet = try Channel.receive(fd: fd, permitsDescriptor: operation.transfersDescriptor, deadline: deadline)
                        try authenticate(fd); try channel.check(); try Channel.check(deadline)
                        let response = try Wire.decode(packet.body)
                        guard response.reply, response.sequence == request.sequence, response.operation == operation else { throw Wire.Failure.invalid }
                        try channel.check(); try Channel.check(deadline)
                        #if DEBUG
                        beforePublicationForTesting?(deadline)
                        #endif
                        try lock.withLock {
                            guard !closed, pending[id] != nil else { throw Wire.Failure.closed }
                            // Timer delivery can lag: expiry and publication must
                            // be decided together before retiring this request.
                            try Channel.check(deadline)
                            _ = pending.removeValue(forKey: id)
                            completion.finish(.success(Reply(frame: response, descriptor: packet.descriptor)))
                        }
                    } catch {
                        cancel(); completion.finish(.failure(error))
                    }
                }
            }
        } onCancel: { self.cancel() }
        try Task.checkCancellation()
        try channel.check()
        return result
    }
    #if DEBUG
    /// Unsigned framing seam only; cannot construct a native authenticated peer.
    static func testing(borrowedFD: Int32, timeout: TimeInterval = 0.2,
                        beforePublication: (@Sendable (DispatchTime) -> Void)? = nil,
                        beforeDeadline: (@Sendable () -> Void)? = nil) throws -> StorageLifecycleShimConnection {
        guard timeout > 0, timeout <= Channel.budget, timeout.isFinite else { throw Wire.Failure.invalid }
        let connection = try StorageLifecycleShimConnection(testFD: borrowedFD, timeout: timeout)
        connection.beforePublicationForTesting = beforePublication
        connection.beforeDeadlineForTesting = beforeDeadline
        return connection
    }
    private init(testFD: Int32, timeout: TimeInterval) throws {
        channel = try Channel(borrowedFD: testFD); self.timeout = timeout; authenticate = { _ in }
        #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
        qualificationPolicy = .production // Never mint signed qualification policy for unit tests.
        #endif
    }
    #endif
}
#endif

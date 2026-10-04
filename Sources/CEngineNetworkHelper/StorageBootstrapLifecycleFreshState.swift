import CEngineHelperSupport
import Foundation
import Security

/// Unsigned exchange seam only. Production MUST supply independently pinned Mach
/// senders and re-pin both native processes. Reply DTOs have no signature/authority.
final class StorageBootstrapLifecycleFreshEndpoint: @unchecked Sendable {
    typealias Wire = StorageLifecycleFreshProtocol
    struct Received: Sendable { let shim: BootstrapProcess; let bytes: Data }
    typealias Completion = @Sendable (Result<Received, any Error>) -> Void
    typealias Sender = (Wire.Challenge, @escaping Completion) throws -> Void
    private final class Pending: @unchecked Sendable {
        let challenge: Wire.Challenge
        let deadline: TimeInterval
        let signal = DispatchSemaphore(value: 0)
        var reply: Wire.Reply?
        init(_ challenge: Wire.Challenge, deadline: TimeInterval) {
            self.challenge = challenge; self.deadline = deadline
        }
    }
    let greeting: Wire.Greeting
    let daemon: BootstrapProcess
    let shim: BootstrapProcess
    let channel: StorageBootstrapChildChannel
    private let lock = NSLock()
    private let counter: StorageBootstrapLifecycleChildCounter
    private let worker: StorageBootstrapLifecycleChildWorker
    private let now: () -> UInt64
    private let uptime: () -> TimeInterval
    private let timeout: TimeInterval
    private let sender: Sender
    private let onRevoke: () -> Void
    private var revoked = false
    private var pending: Pending?
    private var claim: Lifecycle.Grant?

    init(greeting: Wire.Greeting, daemon: BootstrapProcess, shim: BootstrapProcess,
         channel: StorageBootstrapChildChannel, expectedRoot: StorageIdentity.RootPublicKey,
         counter: StorageBootstrapLifecycleChildCounter, worker: StorageBootstrapLifecycleChildWorker,
         timeout: TimeInterval = 5,
         now: @escaping () -> UInt64 = { UInt64(Date().timeIntervalSince1970 * 1000) },
         uptime: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
         onRevoke: @escaping () -> Void = {}, sender: @escaping Sender) throws {
        try greeting.validate()
        guard greeting.rootPublicKey == expectedRoot.publicData, greeting.daemonUniqueID == daemon.uniqueID,
              shim.uniqueID != daemon.uniqueID, shim.uniqueID > 0, shim.pid > 0, shim.boot == daemon.boot,
              shim.auditToken.count == 32, daemon.auditToken.count == 32, channel.isOpen,
              timeout.isFinite, timeout > 0, timeout <= Double(Wire.lifetimeMS) / 1000 else {
            throw BootstrapFailure(.unauthorized)
        }
        self.greeting = greeting; self.daemon = daemon; self.shim = shim; self.channel = channel
        self.counter = counter; self.worker = worker; self.timeout = timeout; self.now = now
        self.uptime = uptime; self.sender = sender; self.onRevoke = onRevoke
    }
    func revoke() {
        let cancel = lock.withLock {
            guard !revoked else { return false }
            revoked = true; channel.close(); pending?.signal.signal(); pending = nil
            return true
        }
        if cancel { onRevoke() }
    }
    private func fresh(_ item: Pending) -> Bool {
        !revoked && channel.isOpen && item.challenge.isFresh(at: now()) && item.deadline > uptime()
    }
    private func receive(_ result: Result<Received, any Error>, for item: Pending) {
        do {
            try lock.withLock {
                guard pending === item, item.reply == nil, fresh(item) else { throw BootstrapFailure(.unauthorized) }
            }
            let received = try result.get()
            guard received.shim == shim else { throw BootstrapFailure(.unauthorized) }
            let reply = try Wire.decodeReply(received.bytes)
            guard try reply.verifies(item.challenge) else { throw BootstrapFailure(.unauthorized) }
            try lock.withLock {
                guard pending === item, item.reply == nil, fresh(item) else { throw BootstrapFailure(.unauthorized) }
                item.reply = reply; item.signal.signal()
            }
        } catch { revoke() }
    }
    /// Freezes this live initialization to exactly one ROOT grant. The shim also
    /// freezes it in the shared boot capability, across all capability wrappers.
    func prove(binding: StorageIdentity.StoreBinding, grant: Lifecycle.Grant, daemon expected: BootstrapProcess,
               repin: () throws -> Void) throws {
        try worker.requireCurrent()
        do {
            guard expected == daemon, greeting.matches(binding: binding), grant.operation == .initialize,
                  grant.identity == (try Lifecycle.Identity(binding: binding, generation: grant.identity.generation)) else {
                throw BootstrapFailure(.unauthorized)
            }
            try repin()
            let item = try lock.withLock {
                guard !revoked, channel.isOpen, pending == nil, claim == nil || claim == grant else {
                    throw BootstrapFailure(.unauthorized)
                }
                claim = grant
                let wall = now()
                guard wall <= UInt64.max - Wire.lifetimeMS else { throw BootstrapFailure(.unavailable) }
                var nonce = Data(count: 32)
                guard nonce.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }) == errSecSuccess else {
                    throw BootstrapFailure(.unavailable)
                }
                let challenge = try Wire.Challenge(greeting: greeting, grant: grant, shimAudit: shim.auditToken,
                    shimUniqueID: shim.uniqueID, daemonAudit: daemon.auditToken, counter: counter.next(),
                    nonce: nonce, expiresUnixMS: wall + Wire.lifetimeMS)
                let value = Pending(challenge, deadline: uptime() + timeout)
                pending = value; return value
            }
            try sender(item.challenge) { [self] result in receive(result, for: item) }
            guard item.signal.wait(timeout: .now() + timeout) == .success else { throw BootstrapFailure(.unavailable) }
            try lock.withLock {
                guard pending === item, fresh(item), let reply = item.reply, try reply.verifies(item.challenge) else {
                    throw BootstrapFailure(.unauthorized)
                }
            }
            try repin()
            try lock.withLock {
                guard pending === item, fresh(item) else { throw BootstrapFailure(.unauthorized) }
                pending = nil
            }
        } catch { revoke(); throw error }
    }
}

import CEngineHelperSupport
import Foundation
import Security

/// Serializes each complete synchronous authority operation on one worker.
/// Never enter this worker while holding a gate also needed by a reply/disconnect callback.
final class StorageBootstrapLifecycleChildWorker: @unchecked Sendable {
    private let queue = DispatchQueue(label: "dev.cengine.storage-lifecycle.worker")
    private let key = DispatchSpecificKey<Bool>()
    init() { queue.setSpecific(key: key, value: true) }
    func requireCurrent() throws {
        guard !Thread.isMainThread, DispatchQueue.getSpecific(key: key) == true else {
            throw BootstrapFailure(.unavailable)
        }
    }
    /// Schedule directly: a global-pool wrapper blocked in queue.sync can starve
    /// independent reply/revocation work while other authority calls wait here.
    func enqueue(_ body: @escaping @Sendable () -> Void) { queue.async(execute: body) }
    func perform<T>(_ body: () throws -> T) throws -> T {
        guard !Thread.isMainThread else { throw BootstrapFailure(.unavailable) }
        if DispatchQueue.getSpecific(key: key) == true { return try body() }
        return try queue.sync(execute: body)
    }
}

/// Enrollment-window selection only, never native authentication. Existing peers
/// require the same full greeting and native process re-pinning at the call site.
enum StorageBootstrapLifecycleEnrollment {
    static func daemon(existing: BootstrapProcess?, uniqueID: UInt64,
                       remembered: BootstrapProcess?, deadline: TimeInterval?, now: TimeInterval) throws -> BootstrapProcess {
        if let existing {
            guard existing.uniqueID == uniqueID else { throw BootstrapFailure(.unauthorized) }
            return existing
        }
        guard let remembered, remembered.uniqueID == uniqueID, let deadline, deadline > now else {
            throw BootstrapFailure(.unauthorized)
        }
        return remembered
    }
}

/// Global to one transport, not an expiring nonce set. Reconnects cannot reset it.
final class StorageBootstrapLifecycleChildCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value: UInt64
    init(initialValue: UInt64 = 0) { value = initialValue }
    func next() throws -> UInt64 {
        try lock.withLock {
            guard value < UInt64.max else { throw BootstrapFailure(.epochExhausted) }
            value += 1
            return value
        }
    }
}

/// Unsigned exchange/state seam. Only the native adapter may turn this into process
/// evidence: the seam's injected sender and re-pin closures are NOT authentication.
final class StorageBootstrapLifecycleChildEndpoint: @unchecked Sendable {
    typealias Wire = StorageLifecycleChildProtocol
    struct Received: Sendable { let child: BootstrapProcess; let bytes: Data }
    typealias Completion = @Sendable (Result<Received, any Error>) -> Void
    typealias Sender = (Wire.Challenge, @escaping Completion) throws -> Void
    typealias IdentitySender = (Wire.IdentityChallenge, @escaping Completion) throws -> Void
    private final class Pending: @unchecked Sendable {
        let deadline: TimeInterval
        let expiresUnixMS: UInt64
        let verifies: (Data) throws -> Bool
        let signal = DispatchSemaphore(value: 0)
        var reply: Data?
        init(expiresUnixMS: UInt64, deadline: TimeInterval, verifies: @escaping (Data) throws -> Bool) {
            self.expiresUnixMS = expiresUnixMS; self.deadline = deadline; self.verifies = verifies
        }
    }
    let greeting: Wire.Greeting
    let principal: BootstrapPrincipal
    let connectionID: UUID
    let channel: StorageBootstrapChildChannel
    private let lock = NSLock()
    private let counter: StorageBootstrapLifecycleChildCounter
    private let worker: StorageBootstrapLifecycleChildWorker
    private let now: () -> UInt64
    private let uptime: () -> TimeInterval
    private let timeout: TimeInterval
    private let identitySender: IdentitySender
    private let sender: Sender
    private let onRevoke: () -> Void
    private var revoked = false
    private var pending: Pending?

    init(greeting: Wire.Greeting, daemon: BootstrapProcess, child: BootstrapProcess,
         connectionID: UUID, channel: StorageBootstrapChildChannel,
         expectedRoot: StorageIdentity.RootPublicKey, counter: StorageBootstrapLifecycleChildCounter,
         worker: StorageBootstrapLifecycleChildWorker, timeout: TimeInterval = 5,
         now: @escaping () -> UInt64 = { UInt64(Date().timeIntervalSince1970 * 1000) },
         uptime: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
         onRevoke: @escaping () -> Void = {},
         identitySender: @escaping IdentitySender = { _, _ in throw BootstrapFailure(.unavailable) },
         sender: @escaping Sender) throws {
        try greeting.validate()
        guard greeting.rootPublicKey == expectedRoot.publicData,
              greeting.daemonUniqueID == daemon.uniqueID, child.uniqueID != daemon.uniqueID,
              child.boot == daemon.boot, child.auditToken.count == 32, daemon.auditToken.count == 32,
              child.pid > 0, child.uniqueID > 0, channel.isOpen,
              timeout > 0, timeout <= Double(Wire.lifetimeMS) / 1000 else {
            throw BootstrapFailure(.unauthorized)
        }
        self.greeting = greeting
        principal = BootstrapPrincipal(daemon: daemon, child: child,
            incarnation: greeting.incarnationID, controllerSPKI: greeting.controllerSPKI)
        self.connectionID = connectionID; self.channel = channel
        self.counter = counter; self.worker = worker; self.timeout = timeout
        self.identitySender = identitySender
        self.now = now; self.uptime = uptime; self.sender = sender; self.onRevoke = onRevoke
    }
    /// Independent of the authority's operation gate and the worker; wakes waiters now.
    func revoke() {
        let cancel = lock.withLock {
            guard !revoked else { return false }
            revoked = true
            channel.close(); pending?.signal.signal(); pending = nil
            return true
        }
        // Cancel native outstanding reply handlers too; closed endpoints must not
        // retain arbitrarily many unanswered XPC exchanges after pruning.
        if cancel { onRevoke() }
    }
    private func fresh(_ item: Pending) -> Bool {
        let wall = now()
        return channel.isOpen && item.expiresUnixMS > wall && item.expiresUnixMS - wall <= Wire.lifetimeMS && item.deadline > uptime()
    }
    private func receive(_ result: Result<Received, any Error>, for item: Pending) {
        do {
            try lock.withLock {
                guard pending === item, item.reply == nil, fresh(item) else { throw BootstrapFailure(.unauthorized) }
            }
            let received = try result.get()
            guard received.child == principal.child else { throw BootstrapFailure(.unauthorized) }
            // Keep decoding/cryptography outside the cancellation lock.
            let reply = received.bytes
            guard try item.verifies(reply) else { throw BootstrapFailure(.unauthorized) }
            try lock.withLock {
                guard pending === item, item.reply == nil, fresh(item) else { throw BootstrapFailure(.unauthorized) }
                item.reply = reply
                item.signal.signal()
            }
        } catch { revoke() }
    }
    /// Every call creates and consumes a new challenge; no historical DTO is evidence.
    func prove(principal expected: BootstrapPrincipal, grant: Lifecycle.Grant, purpose: Wire.Purpose,
               nonce: Data? = nil, boot: StorageLifecycleBootTrust? = nil,
               changeRequest: Lifecycle.ServiceChangeRequest? = nil,
               confirmation: Lifecycle.ServiceChangeConfirmation? = nil, repin: () throws -> Void) throws -> Wire.Reply {
        try worker.requireCurrent()
        do {
            guard channel.isOpen, expected == principal, try greeting.matches(grant) else { throw BootstrapFailure(.unauthorized) }
            try repin()
            var challenge: Wire.Challenge!
            let item = try lock.withLock {
                guard channel.isOpen, pending == nil else { throw BootstrapFailure(.unavailable) }
                let wall = now()
                guard wall <= UInt64.max - Wire.lifetimeMS else { throw BootstrapFailure(.unavailable) }
                challenge = try Wire.Challenge(greeting: greeting, grant: grant,
                    childAudit: principal.child.auditToken, childUniqueID: principal.child.uniqueID,
                    daemonAudit: principal.daemon.auditToken, counter: counter.next(),
                    nonce: nonce ?? Self.randomNonce(), purpose: purpose, expiresUnixMS: wall + Wire.lifetimeMS, boot: boot,
                    changeRequest: changeRequest, confirmation: confirmation)
                let frozen = challenge!
                let value = Pending(expiresUnixMS: frozen.expiresUnixMS, deadline: uptime() + timeout) {
                    try Wire.decodeReply($0).verifies(frozen)
                }
                pending = value
                return value
            }
            try sender(challenge) { [self] result in receive(result, for: item) }
            // DispatchTime is monotonic, independent of wall-clock changes.
            guard item.signal.wait(timeout: .now() + timeout) == .success else { throw BootstrapFailure(.unavailable) }
            let reply = try lock.withLock {
                guard pending === item, fresh(item), let reply = item.reply else { throw BootstrapFailure(.unauthorized) }
                return reply
            }
            guard try item.verifies(reply) else { throw BootstrapFailure(.unauthorized) }
            try lock.withLock {
                guard pending === item, fresh(item) else { throw BootstrapFailure(.unauthorized) }
            }
            try repin()
            guard try item.verifies(reply) else { throw BootstrapFailure(.unauthorized) }
            return try lock.withLock {
                guard pending === item, fresh(item) else { throw BootstrapFailure(.unauthorized) }
                pending = nil
                return try Wire.decodeReply(reply)
            }
        } catch { revoke(); throw error }
    }
    /// Uses the same single outstanding slot, counter, revocation and native
    /// reply authentication as grant-bearing proofs, without inventing a grant.
    func proveIdentity(principal expected: BootstrapPrincipal, requestSHA256: Data,
                       deadline: DispatchTime = .distantFuture, repin: () throws -> Void) throws -> Wire.IdentityReply {
        try worker.requireCurrent()
        do {
            guard channel.isOpen, expected == principal else { throw BootstrapFailure(.unauthorized) }
            try repin()
            var challenge: Wire.IdentityChallenge!
            let item = try lock.withLock {
                guard channel.isOpen, pending == nil else { throw BootstrapFailure(.unavailable) }
                let wall = now()
                guard wall <= UInt64.max - Wire.lifetimeMS else { throw BootstrapFailure(.unavailable) }
                challenge = try Wire.IdentityChallenge(greeting: greeting, childAudit: principal.child.auditToken,
                    childUniqueID: principal.child.uniqueID, daemonAudit: principal.daemon.auditToken,
                    counter: counter.next(), nonce: Self.randomNonce(), requestSHA256: requestSHA256,
                    expiresUnixMS: wall + Wire.lifetimeMS)
                let frozen = challenge!
                let value = Pending(expiresUnixMS: frozen.expiresUnixMS, deadline: uptime() + timeout) {
                    try Wire.decodeIdentityReply($0).verifies(frozen)
                }
                pending = value
                return value
            }
            guard DispatchTime.now() < deadline else { throw BootstrapFailure(.unavailable) }
            try identitySender(challenge) { [self] result in receive(result, for: item) }
            guard item.signal.wait(timeout: min(.now() + timeout, deadline)) == .success,
                  DispatchTime.now() < deadline else { throw BootstrapFailure(.unavailable) }
            let reply = try lock.withLock {
                guard pending === item, fresh(item), let reply = item.reply else { throw BootstrapFailure(.unauthorized) }
                return reply
            }
            guard try item.verifies(reply) else { throw BootstrapFailure(.unauthorized) }
            try repin()
            guard try item.verifies(reply) else { throw BootstrapFailure(.unauthorized) }
            return try lock.withLock {
                guard pending === item, fresh(item) else { throw BootstrapFailure(.unauthorized) }
                pending = nil
                return try Wire.decodeIdentityReply(reply)
            }
        } catch { revoke(); throw error }
    }
    private static func randomNonce() throws -> Data {
        var bytes = Data(count: 32)
        guard bytes.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }) == errSecSuccess else {
            throw BootstrapFailure(.unavailable)
        }
        return bytes
    }
}

/// Counts LIVE endpoints, never expires a connected endpoint to admit another one.
/// Connection UUIDs distinguish callbacks after pruning; counters survive all pruning.
final class StorageBootstrapLifecycleChildState: @unchecked Sendable {
    static let maximumEndpoints = 128
    let counter = StorageBootstrapLifecycleChildCounter()
    private let lock = NSLock()
    private var endpoints: [Int32: StorageBootstrapLifecycleChildEndpoint] = [:]
    func insert(_ endpoint: StorageBootstrapLifecycleChildEndpoint) throws {
        try lock.withLock {
            endpoints = endpoints.filter { $0.value.channel.isOpen }
            guard endpoint.channel.isOpen,
                  !endpoints.values.contains(where: {
                      $0.connectionID == endpoint.connectionID || $0.greeting.channelID == endpoint.greeting.channelID ||
                      $0.principal.child.uniqueID == endpoint.principal.child.uniqueID
                  }), endpoints[endpoint.principal.child.pid] == nil else { throw BootstrapFailure(.unauthorized) }
            guard endpoints.count < Self.maximumEndpoints else { throw BootstrapFailure(.capacityExceeded) }
            endpoints[endpoint.principal.child.pid] = endpoint
        }
    }
    func endpoint(uniqueID: UInt64) throws -> StorageBootstrapLifecycleChildEndpoint {
        try lock.withLock {
            let matches = endpoints.values.filter { $0.channel.isOpen && $0.principal.child.uniqueID == uniqueID }
            guard matches.count == 1, let endpoint = matches.first else { throw BootstrapFailure(.unavailable) }
            return endpoint
        }
    }
    func endpoint(pid: Int32) throws -> StorageBootstrapLifecycleChildEndpoint {
        try lock.withLock {
            guard let endpoint = endpoints[pid], endpoint.channel.isOpen else { throw BootstrapFailure(.unavailable) }
            return endpoint
        }
    }
}


/// Selector consistency only, not native evidence. The adapter must supply an
/// origin read from protected ROOT state and independently pin both processes.
enum StorageBootstrapLifecycleAdoptionSelection {
    static func validate(request: StorageLifecycleAdoptionProtocol.Request,
                         origin: StorageLifecycleAdoptionProtocol.Origin?,
                         greeting: StorageLifecycleChildProtocol.Greeting,
                         principal: BootstrapPrincipal, daemon: BootstrapProcess,
                         root: StorageIdentity.RootPublicKey) throws {
        try request.validate(); try greeting.validate()
        guard let origin, origin == request.origin,
              principal.daemon == daemon, request.daemonUniqueID == daemon.uniqueID,
              request.daemonAudit == daemon.auditToken,
              request.controllerUniqueID == principal.child.uniqueID,
              request.controllerAudit == principal.child.auditToken,
              greeting.daemonUniqueID == daemon.uniqueID,
              greeting.incarnationID == principal.incarnation,
              greeting.controllerSPKI == principal.controllerSPKI,
              origin.rootPublicKey == root.publicData, greeting.rootPublicKey == root.publicData,
              greeting.store == origin.binding.store,
              greeting.binding == (try Lifecycle.bindingDigest(origin.binding.value())) else {
            throw BootstrapFailure(.unauthorized)
        }
    }
}

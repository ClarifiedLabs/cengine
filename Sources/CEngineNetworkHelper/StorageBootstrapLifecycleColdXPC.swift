import CEngineHelperSupport
import Darwin
import Foundation
import Security
@preconcurrency import XPC

@_silgen_name("xpc_dictionary_get_audit_token")
private func lifecycleColdAudit(_ message: xpc_object_t, _ token: UnsafeMutablePointer<audit_token_t>)

/// Worker-only bounded leases. Only a successful protected-authority snapshot
/// may retire a lease; transport loss and unavailable snapshots leave it intact.
struct StorageBootstrapLifecycleColdClaims<Value> {
    private var values: [String: Value] = [:]
    var count: Int { values.count }
    subscript(operationID: String) -> Value? {
        get { values[operationID] }
        set { values[operationID] = newValue }
    }
    func checkCapacity(for operationID: String) throws {
        guard values[operationID] != nil || values.count < 128 else { throw BootstrapFailure(.capacityExceeded) }
    }
    mutating func reconcile(reachable: () throws -> Set<String>) throws {
        let retained = try reachable()
        values = values.filter { retained.contains($0.key) }
    }
}

/// Dedicated retained mount-only channel. All authority calls run on the scope
/// worker; callbacks only authenticate replies and borrow descriptors for the proof.
/// A channel loss is never process death, nor permission to replace a claimed peer.
final class StorageBootstrapLifecycleColdXPC: StorageLifecycleColdChecking, @unchecked Sendable {
    typealias Wire = StorageLifecycleColdShimProtocol
    static let greetingOperation = "storage-lifecycle-cold-shim"
    private final class Pending: @unchecked Sendable {
        let signal = DispatchSemaphore(value: 0)
        let deadline = DispatchTime.now() + 5
        var result: Result<Void, any Error>?
    }
    private final class Peer: @unchecked Sendable {
        let connection: xpc_connection_t
        let greeting: Wire.Greeting
        let daemon: BootstrapProcess
        let shim: BootstrapProcess
        var open = true
        var pending: Pending?
        init(_ connection: xpc_connection_t, _ greeting: Wire.Greeting, _ daemon: BootstrapProcess, _ shim: BootstrapProcess) {
            self.connection = connection; self.greeting = greeting; self.daemon = daemon; self.shim = shim
        }
    }
    private struct Claim {
        let peer: Peer
        let request: StorageLifecycleColdRootProtocol.Prepare
        let grant: Lifecycle.Grant
        let digest: String
        let baseEpoch: UInt64
        let origin: StorageLifecycleShimOrigin
    }
    private let worker: StorageBootstrapLifecycleChildWorker
    private let processes: StorageBootstrapProcesses
    private let bindings: StorageBootstrapBindings
    private let root: StorageIdentity.RootPublicKey
    private let rootFD: Int32 // Borrowed from the enclosing scope, not a disk writer lease.
    private let candidate: (StorageIdentity.Candidate, BootstrapProcess, Lifecycle.Grant) throws -> BootstrapPrincipal
    private let counter = StorageBootstrapLifecycleChildCounter()
    private let lock = NSLock()
    private var peers: [ObjectIdentifier: Peer] = [:]
    private var daemons: [UInt64: (BootstrapProcess, TimeInterval)] = [:] // worker only
    private var claims = StorageBootstrapLifecycleColdClaims<Claim>() // worker only; never discard on disconnect
    private var requestCheck: (() throws -> Void)? // worker only
    func withRequest<T>(check: () throws -> Void, _ body: () throws -> T) throws -> T {
        try worker.requireCurrent()
        guard requestCheck == nil else { throw BootstrapFailure(.unavailable) }
        return try withoutActuallyEscaping(check) { scoped in
            requestCheck = scoped; defer { requestCheck = nil }
            try scoped(); let result = Result { try body() }; try scoped(); return try result.get()
        }
    }
    /// Keyless historical resolution still checks the actual scoped caller,
    /// observed canonical locks and deadline around every durable transition.
    func checkRecoveryRequest() throws {
        try worker.requireCurrent()
        guard let requestCheck else { throw BootstrapFailure(.unavailable) }
        try requestCheck()
    }
    private let callbacks = DispatchQueue(label: "dev.cengine.storage-lifecycle.cold-replies")
    init(ownerUID: uid_t, team: String, expectedRootPublicKey: StorageIdentity.RootPublicKey,
         rootFD: Int32, worker: StorageBootstrapLifecycleChildWorker, policy: StorageLifecycleNativePolicy = .production,
         candidate: @escaping (StorageIdentity.Candidate, BootstrapProcess, Lifecycle.Grant) throws -> BootstrapPrincipal) {
        processes = .init(ownerUID: ownerUID, team: team, policy: policy)
        bindings = .init(ownerUID: ownerUID); root = expectedRootPublicKey
        self.rootFD = rootFD; self.worker = worker; self.candidate = candidate
    }
    /// Router calls this only after authenticating and binding the physical scope.
    func remember(_ daemon: BootstrapProcess) throws {
        try worker.requireCurrent()
        guard try processes.daemon(audit: Self.audit(daemon)) == daemon else { throw BootstrapFailure(.unauthorized) }
        let now = ProcessInfo.processInfo.systemUptime
        daemons = daemons.filter { $0.value.1 > now }
        guard daemons[daemon.uniqueID] == nil || daemons[daemon.uniqueID]?.0 == daemon,
              daemons[daemon.uniqueID] != nil || daemons.count < 128 else { throw BootstrapFailure(.capacityExceeded) }
        daemons[daemon.uniqueID] = (daemon, now + 30)
    }
    func greet(_ message: xpc_object_t, reply: xpc_object_t, peer: xpc_connection_t) throws {
        try worker.requireCurrent()
        do {
            let greeting = try Self.decodeGreeting(message)
            guard greeting.rootPublicKey == root.publicData else { throw BootstrapFailure(.unauthorized) }
            let old = lock.withLock { peers[ObjectIdentifier(peer)] }
            let remembered = daemons[greeting.daemonUniqueID]
            let daemon = try StorageBootstrapLifecycleEnrollment.daemon(existing: old?.daemon,
                uniqueID: greeting.daemonUniqueID, remembered: remembered?.0, deadline: remembered?.1,
                now: ProcessInfo.processInfo.systemUptime)
            guard try processes.daemon(audit: Self.audit(daemon)) == daemon else { throw BootstrapFailure(.unauthorized) }
            var token = audit_token_t(); lifecycleColdAudit(message, &token)
            let shim = try processes.storageShim(audit: .init(token: token), daemon: daemon)
            try lock.withLock {
                if let old {
                    guard old.open, old.greeting == greeting, old.daemon == daemon, old.shim == shim else { throw BootstrapFailure(.unauthorized) }
                } else {
                    peers = peers.filter { $0.value.open }
                    guard peers.count < 128 else { throw BootstrapFailure(.capacityExceeded) }
                    guard !peers.values.contains(where: { $0.shim.uniqueID == shim.uniqueID ||
                        $0.greeting.channelID == greeting.channelID || $0.greeting.binding == greeting.binding }) else {
                        throw BootstrapFailure(.unauthorized)
                    }
                    peers[ObjectIdentifier(peer)] = Peer(peer, greeting, daemon, shim)
                }
            }
            xpc_dictionary_set_bool(reply, "ok", true)
        } catch { disconnected(peer); xpc_connection_cancel(peer); throw error }
    }
    func disconnected(_ connection: xpc_connection_t) {
        lock.withLock {
            guard let peer = peers[ObjectIdentifier(connection)] else { return }
            peer.open = false; peer.pending?.signal.signal()
        }
    }
    private func pin(_ peer: Peer) throws {
        guard lock.withLock({ peer.open }),
              try processes.daemon(audit: Self.audit(peer.daemon)) == peer.daemon,
              try processes.storageShim(audit: Self.audit(peer.shim), daemon: peer.daemon) == peer.shim else {
            throw BootstrapFailure(.unauthorized)
        }
    }
    func mounted(request: StorageLifecycleColdRootProtocol.Prepare, unsignedGrant: Lifecycle.Grant,
                 signedOpenDigest: String, baseEpoch: UInt64, daemon: BootstrapProcess) throws -> StorageLifecycleShimOrigin {
        try worker.requireCurrent(); try requestCheck?(); try request.validate()
        let peer = try lock.withLock {
            let matches = peers.values.filter { $0.open && $0.daemon == daemon && $0.greeting == request.mountedGreeting }
            guard matches.count == 1, let peer = matches.first else { throw BootstrapFailure(.unauthorized) }; return peer
        }
        let principal = try candidate(request.candidate, daemon, unsignedGrant)
        guard principal.daemon == daemon, principal.child != peer.shim else { throw BootstrapFailure(.unauthorized) }
        let origin = try StorageLifecycleShimOrigin(wire: peer.greeting.successorOrigin, shim: peer.shim,
            originalDaemon: daemon, originalController: principal.child)
        if let old = claims[request.operationID] {
            guard old.peer === peer, old.request == request, old.grant == unsignedGrant,
                  old.digest == signedOpenDigest, old.baseEpoch == baseEpoch, old.origin == origin else { throw BootstrapFailure(.conflict) }
        } else {
            try claims.checkCapacity(for: request.operationID)
        }
        var nonce = Data(count: 32)
        guard nonce.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }) == errSecSuccess else { throw BootstrapFailure(.unavailable) }
        let challenge = try Wire.Challenge(greeting: peer.greeting, prepareSHA256: request.digest,
            unsignedGrant: unsignedGrant, signedOpenSHA256: signedOpenDigest, baseEpoch: baseEpoch,
            shimAudit: peer.shim.auditToken, shimUniqueID: peer.shim.uniqueID, daemonAudit: daemon.auditToken,
            daemonUniqueID: daemon.uniqueID, counter: counter.next(), nonce: nonce,
            expiresUnixMS: UInt64(Date().timeIntervalSince1970 * 1000) + Wire.lifetimeMS)
        try exchange(peer, operation: "storage-lifecycle-cold-challenge", bytes: Wire.encode(challenge)) { [self] response in
            guard challenge.isFresh(at: UInt64(Date().timeIntervalSince1970 * 1000)) else { throw BootstrapFailure(.unavailable) }
            _ = try Wire.decodeReply(Self.payload(response, key: "reply"), for: challenge)
            try Self.withBacking(response) { fd in
                try self.bindings.verify(peer.greeting.binding.value(), rootFD: self.rootFD, backingFD: fd,
                    expectedBacking: peer.greeting.heldBackingIdentity.value())
            }
        }
        guard try candidate(request.candidate, daemon, unsignedGrant) == principal else { throw BootstrapFailure(.unauthorized) }
        try requestCheck?()
        claims[request.operationID] = Claim(peer: peer, request: request, grant: unsignedGrant,
            digest: signedOpenDigest, baseEpoch: baseEpoch, origin: origin)
        return origin
    }
    /// Called only outside an authority transition on the serialized worker:
    /// mounted() may retain a proof before L1 commits, so never reconcile there.
    func reconcileClaims(reachable: () throws -> Set<String>) throws {
        try worker.requireCurrent()
        try claims.reconcile(reachable: reachable)
    }
    /// L3 must already be durable. A lost acknowledgement retries the same seed
    /// after authority.completeCold freshly reproves this exact retained claim.
    func enroll(_ completed: StorageLifecycleColdRootProtocol.Completed) throws {
        try worker.requireCurrent(); try completed.validate()
        guard let claim = claims[completed.operationID], claim.digest == completed.signedOpenSHA256,
              claim.origin.wire == completed.successorOrigin, claim.baseEpoch == completed.baseEpoch else { throw BootstrapFailure(.unauthorized) }
        let seed = try Wire.ColdEnrollmentSeed(operationID: completed.operationID, signedOpenSHA256: completed.signedOpenSHA256,
            successorOrigin: completed.successorOrigin, baseEpoch: completed.baseEpoch)
        try exchange(claim.peer, operation: "storage-lifecycle-cold-enrollment", bytes: Wire.encode(seed)) { response in
            _ = try Wire.decodeEnrollmentAcknowledgement(Self.payload(response, key: "reply"), for: seed)
        }
    }
    private func exchange(_ peer: Peer, operation: String, bytes: Data,
                          verify: @escaping @Sendable (xpc_object_t) throws -> Void) throws {
        try requestCheck?(); try pin(peer)
        let pending = Pending()
        try lock.withLock {
            guard peer.open, peer.pending == nil else { throw BootstrapFailure(.unavailable) }; peer.pending = pending
        }
        defer { lock.withLock { if peer.pending === pending { peer.pending = nil } } }
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(message, "operation", operation)
        bytes.withUnsafeBytes { xpc_dictionary_set_data(message, "request", $0.baseAddress, $0.count) }
        xpc_connection_send_message_with_reply(peer.connection, message, callbacks) { [self] response in
            let result = Result {
                guard lock.withLock({ peer.open && peer.pending === pending && pending.result == nil && DispatchTime.now() < pending.deadline }),
                      xpc_get_type(response) == XPC_TYPE_DICTIONARY else { throw BootstrapFailure(.unavailable) }
                var token = audit_token_t(); lifecycleColdAudit(response, &token)
                guard try processes.storageShim(audit: .init(token: token), daemon: peer.daemon) == peer.shim else { throw BootstrapFailure(.unauthorized) }
                try verify(response); try pin(peer)
            }
            lock.withLock {
                guard peer.pending === pending, pending.result == nil, DispatchTime.now() < pending.deadline else { return }
                pending.result = result; pending.signal.signal()
            }
        }
        guard pending.signal.wait(timeout: pending.deadline) == .success else { throw BootstrapFailure(.unavailable) }
        try lock.withLock {
            guard peer.open, peer.pending === pending, let result = pending.result else { throw BootstrapFailure(.unavailable) }
            try result.get()
        }
        try pin(peer); try requestCheck?()
    }
    /// Descriptor ownership never escapes proof, including malformed/wrong-file replies.
    static func withBacking<T>(_ response: xpc_object_t, _ body: (Int32) throws -> T) throws -> T {
        guard let value = xpc_dictionary_get_value(response, "backing-fd"), xpc_get_type(value) == XPC_TYPE_FD else { throw BootstrapFailure(.invalidRequest) }
        let fd = xpc_dictionary_dup_fd(response, "backing-fd")
        guard fd >= 0 else { throw BootstrapFailure(.unavailable) }
        defer { close(fd) }
        guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { throw BootstrapFailure(.unavailable) }
        return try body(fd)
    }
    static func decodeGreeting(_ message: xpc_object_t) throws -> Wire.Greeting {
        guard xpc_get_type(message) == XPC_TYPE_DICTIONARY,
              let op = xpc_dictionary_get_string(message, "operation"), String(cString: op) == greetingOperation,
              let role = xpc_dictionary_get_string(message, "role"), String(cString: role) == "storage-shim" else { throw BootstrapFailure(.invalidRequest) }
        return try Wire.decodeGreeting(payload(message, key: "request"))
    }
    private static func payload(_ message: xpc_object_t, key: String) throws -> Data {
        var count = 0
        guard let bytes = xpc_dictionary_get_data(message, key, &count), count > 0, count <= Lifecycle.maximumPayloadBytes else { throw BootstrapFailure(.invalidRequest) }
        return Data(bytes: bytes, count: count)
    }
    private static func audit(_ process: BootstrapProcess) throws -> BootstrapAuditIdentity {
        guard process.auditToken.count == MemoryLayout<audit_token_t>.size else { throw BootstrapFailure(.unauthorized) }
        return .init(token: process.auditToken.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) })
    }
}

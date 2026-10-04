import CEngineHelperSupport
import CryptoKit
import Darwin
import Foundation
@preconcurrency import XPC

@_silgen_name("xpc_dictionary_get_audit_token")
private func qualificationAudit(_ message: xpc_object_t, _ token: UnsafeMutablePointer<audit_token_t>)

/// Descriptor-relative storage. The injected base/owner/sync are unprivileged test
/// seams only; live construction always uses fixedBase(), uid 0 and full durability.
enum StorageLifecycleQualificationFiles {
    static func validate(_ fd: Int32, owner: uid_t, directory: Bool, privateMode: Bool = true) throws {
        var s = stat()
        guard fstat(fd, &s) == 0, s.st_uid == owner,
              s.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG),
              s.st_mode & 0o7022 == 0,
              !privateMode || s.st_mode & 0o777 == (directory ? 0o700 : 0o600),
              directory || s.st_nlink == 1 else { throw BootstrapFailure(.repairRequired) }
        try StorageBootstrapSecureFilesystem.requireNoACL(fd)
    }
    static func sync(_ fd: Int32) throws {
        guard fcntl(fd, F_FULLFSYNC) == 0 else { throw BootstrapFailure(.repairRequired) }
    }
    static func directory(_ parent: Int32, _ name: String, owner: uid_t,
                          create: Bool, privateMode: Bool = true) throws -> (Int32, Bool) {
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/"), !name.contains("\0") else {
            throw BootstrapFailure(.invalidRequest)
        }
        var fresh = false
        if create {
            if mkdirat(parent, name, 0o700) == 0 { fresh = true }
            else if errno != EEXIST { throw BootstrapFailure(.repairRequired) }
        }
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw BootstrapFailure(.repairRequired) }
        do { try validate(fd, owner: owner, directory: true, privateMode: privateMode); return (fd, fresh) }
        catch { close(fd); throw error }
    }
    /// Both fixed namespaces require current markers; only empty directories initialize.
    static func fixedBase(_ namespace: StorageLifecycleScopeNamespace = .compatibility) throws -> Int32 {
        let fd = try fixedDirectory(namespace.components, privateLeaf: true)
        do { try StorageLifecycleProductionFormat.require(fd, owner: 0, namespace: namespace, sync: sync); return fd }
        catch { close(fd); throw error }
    }
    static func fixedDirectory(_ components: [String], privateLeaf: Bool, create: Bool = true) throws -> Int32 {
        var fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw BootstrapFailure(.unavailable) }
        do {
            try validate(fd, owner: 0, directory: true, privateMode: false)
            for (index, name) in components.enumerated() {
                // The installer intentionally uses 0755 for its shared support
                // ancestors. Only the lifecycle subtree must be private (0700).
                let (next, fresh) = try directory(fd, name, owner: 0, create: create && index >= 2,
                    privateMode: privateLeaf && index == components.count - 1)
                do { if fresh { try sync(next); try sync(fd) } }
                catch { close(next); throw error }
                close(fd); fd = next
            }
            return fd
        } catch { close(fd); throw error }
    }
    static func read(_ parent: Int32, _ name: String, owner: uid_t) throws -> Data? {
        let fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if fd < 0 { if errno == ENOENT { return nil }; throw BootstrapFailure(.repairRequired) }
        defer { close(fd) }
        try validate(fd, owner: owner, directory: false)
        var s = stat()
        guard fstat(fd, &s) == 0, s.st_size > 0, s.st_size <= 4096 else { throw BootstrapFailure(.repairRequired) }
        var data = Data(count: Int(s.st_size))
        let count = data.withUnsafeMutableBytes { pread(fd, $0.baseAddress, $0.count, 0) }
        guard count == data.count else { throw BootstrapFailure(.repairRequired) }
        return data
    }
    static func write(_ data: Data, parent: Int32, name: String, owner: uid_t,
                      sync: (Int32) throws -> Void) throws {
        let fd = openat(parent, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw BootstrapFailure(.repairRequired) }
        defer { close(fd) }
        try validate(fd, owner: owner, directory: false)
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let n = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                guard n > 0 else { throw BootstrapFailure(.repairRequired) }; offset += n
            }
        }
        try sync(fd); try sync(parent)
    }
}

struct StorageLifecycleQualificationBinding: Equatable, Sendable {
    let store: StorageIdentity.StoreID
    let root: StorageIdentity.RootIdentity
    let ownerUID: uid_t
    var rootHash: String {
        let text = "cengine.lifecycle.qualification.root.v2\0\(root.volumeUUID.rawValue)\0\(root.inode)"
        return SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }
    var metadata: Data {
        Data("cengine.lifecycle.qualification.scope.v2\n\(ownerUID)\n\(store.rawValue)\n\(root.volumeUUID.rawValue)\n\(root.inode)\n".utf8)
    }
    static func requireSameObservation(_ pinned: StorageIdentity.DescriptorIdentity, _ current: StorageIdentity.DescriptorIdentity) throws {
        guard pinned == current else { throw BootstrapFailure(.conflict) }
    }
    static func verified(store: String, rootFD: Int32, owner: uid_t) throws -> Self {
        let root = try StorageBootstrapBindings(ownerUID: owner).identity(rootFD, type: S_IFDIR, role: .root)
        var s = stat()
        guard fstat(rootFD, &s) == 0, s.st_mode & 0o777 == 0o700 else { throw BootstrapFailure(.unauthorized) }
        return try .init(store: .init(store), root: root, ownerUID: owner)
    }
}

/// Never evicts a live, dead, failed, or pending binding. Capacity exhaustion is
/// deliberately fail-closed for this bounded qualification process lifetime.
struct StorageLifecycleQualificationRegistry {
    static let maximum = 128
    private var entries: [UInt64: (BootstrapProcess, StorageLifecycleQualificationBinding)] = [:]
    mutating func bind(_ daemon: BootstrapProcess, to binding: StorageLifecycleQualificationBinding) throws {
        if let old = entries[daemon.uniqueID] {
            guard old.0 == daemon, old.1 == binding else { throw BootstrapFailure(.conflict) }
        } else {
            guard entries.count < Self.maximum else { throw BootstrapFailure(.capacityExceeded) }
            entries[daemon.uniqueID] = (daemon, binding)
        }
    }
    func binding(_ daemon: BootstrapProcess) throws -> StorageLifecycleQualificationBinding {
        guard let old = entries[daemon.uniqueID], old.0 == daemon else { throw BootstrapFailure(.unauthorized) }
        return old.1
    }
    func route(_ uniqueID: UInt64) throws -> StorageLifecycleQualificationBinding {
        guard let old = entries[uniqueID] else { throw BootstrapFailure(.unauthorized) }; return old.1
    }
}

/// Scope construction failure known to precede every durable write; never poisons.
struct StorageLifecycleTransientScopeFailure: Error {
    let failure: BootstrapFailure
}

/// Routing-queue-only cache. Physical roots, NOT store UUIDs, are authority keys.
struct StorageLifecycleQualificationScopes<Value> {
    private var scopes: [String: (StorageLifecycleQualificationBinding, Value)] = [:]
    private var failed: Set<String> = []
    func existing(_ binding: StorageLifecycleQualificationBinding) throws -> Value? {
        guard !failed.contains(binding.rootHash) else { throw BootstrapFailure(.repairRequired) }
        guard let old = scopes[binding.rootHash] else { return nil }
        // A mismatching request must not poison an already healthy authority.
        guard old.0 == binding else { throw BootstrapFailure(.conflict) }
        return old.1
    }
    mutating func resolve(_ binding: StorageLifecycleQualificationBinding, create: () throws -> Value) throws -> Value {
        if let old = try existing(binding) { return old }
        guard scopes.count + failed.count < StorageLifecycleQualificationRegistry.maximum else { throw BootstrapFailure(.capacityExceeded) }
        do {
            let value = try create(); scopes[binding.rootHash] = (binding, value); return value
        } catch let transient as StorageLifecycleTransientScopeFailure {
            // Raised only BEFORE any durable write (e.g. fd exhaustion): retryable.
            throw transient.failure
        } catch {
            // Construction may have partially written durable authority. Always refuse
            // this root thereafter, even for transient failures: retrying with a new
            // provisioning generation is NOT safe recovery from uncertain state.
            failed.insert(binding.rootHash); throw error
        }
    }
}

/// Pure admission seam; no identity/audit claims. Invalidation does NOT release a
/// queued/running operation: only its actual completion may return its slot. This
/// bounds routing closures AND global tasks waiting on the shared scope worker.
final class StorageLifecycleQualificationAdmission<Key: Hashable & Sendable>: @unchecked Sendable {
    static var maximumInFlight: Int { 16 }
    static var maximumPeers: Int { 128 }
    final class Ticket: @unchecked Sendable {
        fileprivate let peer: Key
        fileprivate var finishing = false
        fileprivate init(_ peer: Key) { self.peer = peer }
    }
    private struct Entry {
        var ticket: Ticket?
        var closed = false
    }
    private let lock = NSLock()
    private let pending = DispatchGroup()
    private var peers: [Key: Entry] = [:]
    private var inFlight = 0
    private var terminating = false
    var counts: (peers: Int, inFlight: Int) { lock.withLock { (peers.count, inFlight) } }
    func admit(_ peer: Key) throws -> Ticket {
        try lock.withLock {
            guard !terminating, peers[peer]?.closed != true else { throw BootstrapFailure(.unavailable) }
            guard inFlight < Self.maximumInFlight, peers[peer]?.ticket == nil,
                  peers[peer] != nil || peers.count < Self.maximumPeers else { throw BootstrapFailure(.capacityExceeded) }
            let ticket = Ticket(peer)
            peers[peer] = Entry(ticket: ticket); inFlight += 1
            pending.enter() // All checks precede entry and retention by the dispatcher.
            return ticket
        }
    }
    /// The nonblocking reply-send completion must not reenter admission. Send and
    /// release are atomic to admit(): an immediate follow-up after receiving the
    /// reply must not race with the previous request's still-busy ticket.
    func finish(_ ticket: Ticket, completion: () -> Void = {}) {
        lock.withLock {
            guard peers[ticket.peer]?.ticket === ticket, !ticket.finishing else { return }
            ticket.finishing = true
            defer {
                if peers[ticket.peer]?.closed == true { peers.removeValue(forKey: ticket.peer) }
                else { peers[ticket.peer]?.ticket = nil }
                inFlight -= 1; pending.leave()
            }
            completion()
        }
    }
    func disconnected(_ peer: Key) {
        lock.withLock {
            if peers[peer]?.ticket == nil { peers.removeValue(forKey: peer) }
            else { peers[peer]?.closed = true }
        }
    }
    func invalidate() {
        lock.withLock {
            terminating = true
            for peer in Array(peers.keys) {
                if peers[peer]?.ticket == nil { peers.removeValue(forKey: peer) }
                else { peers[peer]?.closed = true }
            }
        }
    }
    func wait() { pending.wait() }
}

final class StorageLifecycleQualificationDirectory {
    let binding: StorageLifecycleQualificationBinding
    let fd: Int32
    let journal: StorageBootstrapCheckpointJournal
    let wasCreated: Bool
    private let owner: uid_t
    private let sync: (Int32) throws -> Void
    init(baseFD: Int32, binding: StorageLifecycleQualificationBinding, owner: uid_t,
         sync: @escaping (Int32) throws -> Void = StorageLifecycleQualificationFiles.sync) throws {
        self.binding = binding; self.owner = owner; self.sync = sync
        try StorageLifecycleQualificationFiles.validate(baseFD, owner: owner, directory: true)
        let (directory, fresh) = try StorageLifecycleQualificationFiles.directory(baseFD, binding.rootHash, owner: owner, create: true)
        do {
            if fresh {
                try sync(directory); try sync(baseFD)
                try StorageLifecycleQualificationFiles.write(binding.metadata, parent: directory, name: "scope", owner: owner, sync: sync)
            }
            guard try StorageLifecycleQualificationFiles.read(directory, "scope", owner: owner) == binding.metadata else {
                throw BootstrapFailure(.repairRequired)
            }
            // Metadata is OUTSIDE the leaf: a fresh journal must see an empty directory.
            let (leaf, leafFresh) = try StorageLifecycleQualificationFiles.directory(directory, "journal", owner: owner, create: fresh)
            defer { close(leaf) }
            guard !fresh || leafFresh else { throw BootstrapFailure(.repairRequired) }
            if fresh { try sync(leaf); try sync(directory) }
            journal = try StorageBootstrapCheckpointJournal(directoryFD: leaf, fresh: fresh && leafFresh,
                ownerUID: owner, configuredOwnerUID: binding.ownerUID, sync: sync)
            fd = directory
            wasCreated = fresh && leafFresh
        } catch { close(directory); throw error }
        let recorded = try recordedBinding()
        if recorded == nil, try journal.load() != nil { throw BootstrapFailure(.repairRequired) }
    }
    deinit { close(fd) }

    /// Enrollment-only integration point; deliberately not called by normal startup.
    /// Existing scopes require explicit, verified no-state enrollment, never missing=fresh.
    func adoptionJournal(enrollIfNoState: Bool = false) throws -> StorageBootstrapLifecycleAdoptionJournal {
        guard owner == 0 else { throw BootstrapFailure(.unauthorized) }
        return try .init(scope: self, owner: 0, enrollIfNoState: enrollIfNoState,
                         sync: StorageLifecycleQualificationFiles.sync)
    }

    /// Internal unprivileged filesystem/fault seam. No request-selected production owner.
    func adoptionJournalForTesting(enrollIfNoState: Bool = false,
        sync: @escaping (Int32) throws -> Void = StorageLifecycleQualificationFiles.sync) throws -> StorageBootstrapLifecycleAdoptionJournal {
        try .init(scope: self, owner: owner, enrollIfNoState: enrollIfNoState, sync: sync)
    }

    func recordedBinding() throws -> StorageIdentity.StoreBinding? {
        guard try StorageLifecycleQualificationFiles.read(fd, "scope", owner: owner) == binding.metadata else {
            throw BootstrapFailure(.repairRequired)
        }
        guard let data = try StorageLifecycleQualificationFiles.read(fd, "binding", owner: owner) else { return nil }
        let dto = try StorageLifecycleProtocol.decode(StorageLifecycleStoreBinding.self, from: data)
        let value = try dto.value()
        guard value.storeID == binding.store, value.root == binding.root,
              try StorageLifecycleProtocol.encode(dto) == data else { throw BootstrapFailure(.repairRequired) }
        return value
    }
    func requireBinding(_ value: StorageIdentity.StoreBinding, establish: Bool) throws {
        guard value.root == binding.root, value.storeID == binding.store else { throw BootstrapFailure(.conflict) }
        if let old = try recordedBinding() { guard old == value else { throw BootstrapFailure(.conflict) } }
        else {
            // The HOST probes before transferring descriptors. Only a genuinely
            // absent initial binding returns this correlated attach allowance.
            guard try journal.load() == nil else { throw BootstrapFailure(.repairRequired) }
            guard establish else { throw BootstrapFailure(.invalidRequest) }
            try StorageLifecycleQualificationFiles.write(StorageLifecycleProtocol.encode(StorageLifecycleStoreBinding(value)),
                parent: fd, name: "binding", owner: owner, sync: sync)
        }
    }
    func requireIdentity(_ identity: StorageLifecycleProtocol.Identity) throws {
        guard let full = try recordedBinding(), identity.store == binding.store.rawValue,
              identity.binding == StorageLifecycleProtocol.bindingDigest(full) else { throw BootstrapFailure(.conflict) }
    }
    func validateResume(_ request: StorageLifecycleResumeRootProtocol.Request) throws {
        switch request.body {
        case .lookup(let binding): try requireBinding(binding.value(), establish: false)
        case .status(let identity): try requireIdentity(identity)
        case .prepare(let prepare):
            try requireIdentity(prepare.identity)
            try requireBinding(prepare.probeGreeting.binding.value(), establish: false)
        case .complete: break // Scope-local authority resolves the protected operation.
        }
    }
    func validate(_ request: StorageLifecycleRootProtocol.Request) throws {
        switch request.body {
        case .rootPublicKey: _ = try recordedBinding()
        case .provision(_, let value, _, let initial): try requireBinding(value, establish: initial)
        case .issue(_, _, let identity, _, _), .read(let identity, _), .complete(let identity, _),
             .reclaim(let identity, _), .status(let identity), .serviceBootTrust(let identity, _, _),
             .serviceResult(let identity, _), .completeServiceChange(let identity, _): try requireIdentity(identity)
        case .stageServiceChange(let change): try requireIdentity(change.predecessor.boot.identity)
        }
    }
}

#if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
typealias StorageBootstrapLifecycleQualification = StorageBootstrapLifecycleRouter
#endif

/// Namespace-parameterized v2 ROOT/child/fresh/service router. Ordinary signed
/// compatibility uses the installed test owner; the narrower qualification profile
/// remains compile-gated. Production is fixed-path and enrollment-owned.
final class StorageBootstrapLifecycleRouter: @unchecked Sendable {
    #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
    static let installed: StorageBootstrapLifecycleRouter? = try? qualification()
    private static func qualification() throws -> StorageBootstrapLifecycleRouter {
        let policy = try StorageLifecycleNativePolicy.qualification(role: .helper)
        let team = try policy.currentIdentity(role: .helper).teamIdentifier
        _ = try StorageLifecycleScopeNamespace.compatibility.configuredOwner()
        return try .init(namespace: .compatibility, policy: policy, team: team,
            owner: { try StorageLifecycleScopeNamespace.compatibility.configuredOwner() })
    }
    #endif
    /// Same-worker ROOT check for same-channel successor boots (both namespaces).
    static func wireSuccessorBoot(_ service: StorageBootstrapLifecycleServiceXPC,
                                  to authorize: @escaping (StorageLifecycleBootTrust, StorageLifecycleBootTrust) throws -> Void) {
        service.authorizeSuccessorBoot = authorize
    }
    private final class AdoptionReference { weak var value: StorageBootstrapLifecycleAdoptionAuthority? }
    private final class Scope: @unchecked Sendable {
        let directory: StorageLifecycleQualificationDirectory
        let rootFD: Int32
        let rootObservation: StorageIdentity.DescriptorIdentity
        let worker = StorageBootstrapLifecycleChildWorker()
        let cold: StorageBootstrapLifecycleColdXPC
        let resume: StorageBootstrapLifecycleResumeXPC
        let fresh: StorageBootstrapLifecycleFreshXPC
        let service: StorageBootstrapLifecycleServiceXPC
        let child: StorageBootstrapLifecycleChildXPC
        let rpc: StorageBootstrapLifecycleXPC
        let adoption: StorageBootstrapLifecycleAdoptionXPC
        let adoptionAuthority: StorageBootstrapLifecycleAdoptionAuthority
        init(binding: StorageLifecycleQualificationBinding, rootFD: Int32, owner: uid_t, team: String,
             policy: StorageLifecycleNativePolicy, namespace: StorageLifecycleScopeNamespace) throws {
            // Duplicate first: fd exhaustion here precedes every durable write.
            let duplicate = fcntl(rootFD, F_DUPFD_CLOEXEC, 0)
            guard duplicate >= 0 else { throw StorageLifecycleTransientScopeFailure(failure: BootstrapFailure(.unavailable)) }
            self.rootFD = duplicate
            do {
                rootObservation = try StorageBootstrapBindings(ownerUID: owner).observe(duplicate, type: S_IFDIR, role: .root)
                guard rootObservation.stableIdentity == binding.root else { throw BootstrapFailure(.conflict) }
                let base = try StorageLifecycleQualificationFiles.fixedBase(namespace); defer { close(base) }
                directory = try .init(baseFD: base, binding: binding, owner: 0)
                // Only this construction's genuinely fresh scope may enroll the
                // no-state leaf. Missing/partial existing enrollment never resets.
                let adoptionJournal = try directory.adoptionJournal(enrollIfNoState: directory.wasCreated)
                let key = try directory.journal.lifecycleRootPublicKey()
                fresh = .init(ownerUID: owner, team: team, expectedRootPublicKey: key, worker: worker, policy: policy)
                service = .init(ownerUID: owner, team: team, expectedRootPublicKey: key, worker: worker, policy: policy)
                let adoptionReference = AdoptionReference()
                child = .init(ownerUID: owner, team: team, expectedRootPublicKey: key, worker: worker, services: service, policy: policy,
                    lookupOrigin: { id in
                        guard let authority = adoptionReference.value else { throw BootstrapFailure(.unavailable) }
                        return try authority.registeredOrigin(store: id)
                    })
                let fresh = fresh, service = service, child = child
                cold = .init(ownerUID: owner, team: team, expectedRootPublicKey: key, rootFD: duplicate,
                    worker: worker, policy: policy, candidate: { candidate, daemon, grant in
                        try child.candidate(candidate, daemon: daemon, grant: grant)
                    })
                resume = StorageBootstrapLifecycleResumeXPC(ownerUID: owner, team: team, expectedRootPublicKey: key,
                    rootFD: duplicate, worker: worker, policy: policy, candidate: { candidate, daemon, grant in
                        try child.candidate(candidate, daemon: daemon, grant: grant)
                    })
                rpc = try .init(ownerUID: owner, team: team, journal: directory.journal, processes: child,
                    bindings: fresh, worker: worker, remember: { daemon in
                        try fresh.remember(daemon); try service.remember(daemon); try child.remember(daemon)
                    }, policy: policy)
                let rpc = rpc
                (adoption, adoptionAuthority) = try StorageBootstrapLifecycleAdoptionXPC.native(ownerUID: owner,
                    team: team, worker: worker, policy: policy, directory: directory,
                    rpc: rpc, service: service, child: child, journal: adoptionJournal)
                adoptionReference.value = adoptionAuthority
                let cold = cold, authority = adoptionAuthority
                try worker.perform { try rpc.configureCold(adoption: authority, mounted: cold) }
                let resumeTransport = resume
                try worker.perform { try rpc.configureResume(mounted: resumeTransport) }
                let handoffTransport = adoption
                try worker.perform { try rpc.configureHandoff(adoption: authority, checking: handoffTransport) }
                service.guardPublication = { [weak rpc] store in
                    guard let rpc else { throw BootstrapFailure(.unavailable) }
                    try rpc.guardColdPublication(store: store)
                }
                StorageBootstrapLifecycleRouter.wireSuccessorBoot(service) { [weak rpc] predecessor, successor in
                    guard let rpc else { throw BootstrapFailure(.unavailable) }
                    try rpc.authorizeServiceBootUpdate(predecessor: predecessor, successor: successor)
                }
            } catch { close(duplicate); throw error }
        }
        deinit { close(rootFD) }
        func validateRoot(receivedFD: Int32? = nil) throws {
            let b = directory.binding
            let verifier = StorageBootstrapBindings(ownerUID: b.ownerUID)
            try StorageLifecycleQualificationBinding.requireSameObservation(rootObservation, verifier.observe(rootFD, type: S_IFDIR, role: .root))
            if let receivedFD {
                try StorageLifecycleQualificationBinding.requireSameObservation(rootObservation, verifier.observe(receivedFD, type: S_IFDIR, role: .root))
            }
            guard try StorageLifecycleQualificationBinding.verified(store: b.store.rawValue, rootFD: rootFD, owner: b.ownerUID) == b else {
                throw BootstrapFailure(.conflict)
            }
        }
        func disconnected(_ peer: xpc_connection_t) {
            cold.disconnected(peer); resume.disconnected(peer); fresh.disconnected(peer); service.disconnected(peer); child.disconnected(peer); adoption.disconnected(peer)
        }
    }
    private final class Peer: @unchecked Sendable {
        let connection: xpc_connection_t
        var closed = false
        var scope: Scope?
        init(_ connection: xpc_connection_t) { self.connection = connection }
    }
    let policy: StorageLifecycleNativePolicy
    let team: String
    let namespace: StorageLifecycleScopeNamespace
    /// Re-read per scope bind: production owner is the root-owned enrollment.
    private let owner: () throws -> uid_t
    private let routing = DispatchQueue(label: "dev.cengine.lifecycle.qualification-routing")
    private let lock = NSLock()
    private let admission = StorageLifecycleQualificationAdmission<ObjectIdentifier>()
    private var terminating = false
    private var peers: [ObjectIdentifier: Peer] = [:]
    // routing queue only; bindings remain reserved even when construction fails.
    private var registry = StorageLifecycleQualificationRegistry()
    private var scopes = StorageLifecycleQualificationScopes<Scope>()
    init(namespace: StorageLifecycleScopeNamespace, policy: StorageLifecycleNativePolicy, team: String,
         owner: @escaping () throws -> uid_t) throws {
        guard geteuid() == 0, namespace == StorageLifecycleScopeNamespace(policy.namespace) else {
            throw BootstrapFailure(.unauthorized)
        }
        self.namespace = namespace; self.policy = policy; self.team = team; self.owner = owner
    }
    static func recognizes(_ operation: String) -> Bool {
        [scopeBindOperation, StorageLifecycleRootProtocol.xpcOperation, StorageLifecycleAdoptionRootProtocol.xpcOperation,
         StorageLifecycleColdRootProtocol.xpcOperation, StorageBootstrapLifecycleColdXPC.greetingOperation,
         StorageLifecycleResumeRootProtocol.xpcOperation, StorageBootstrapLifecycleResumeXPC.greetingOperation,
         StorageBootstrapLifecycleAdoptionXPC.coldEnrollmentOperation, StorageBootstrapLifecycleAdoptionXPC.resumeEnrollmentOperation,
         "storage-lifecycle-fresh-shim", "storage-lifecycle-service-shim", "storage-lifecycle-child",
         StorageBootstrapLifecycleAdoptionXPC.greetingOperation, StorageBootstrapLifecycleAdoptionXPC.enrollmentOperation].contains(operation)
    }
    /// Bound the envelope before copying payloads, retaining messages, or scheduling.
    /// Closed decoders below additionally require canonical bytes and valid DTOs.
    static func validateAdmission(_ message: xpc_object_t) throws -> String? {
        guard xpc_get_type(message) == XPC_TYPE_DICTIONARY,
              let op = xpc_dictionary_get_value(message, "operation"), xpc_get_type(op) == XPC_TYPE_STRING,
              xpc_string_get_length(op) <= 64, let text = xpc_string_get_string_ptr(op) else { throw BootstrapFailure(.invalidRequest) }
        let operation = String(cString: text)
        guard operation.utf8.count == xpc_string_get_length(op) else { throw BootstrapFailure(.invalidRequest) }
        guard recognizes(operation) else { return nil }
        if operation == StorageLifecycleColdRootProtocol.xpcOperation {
            _ = try StorageBootstrapLifecycleColdRootXPC.decodeRequest(message)
            return operation
        }
        if operation == StorageLifecycleResumeRootProtocol.xpcOperation {
            _ = try StorageBootstrapLifecycleResumeRootXPC.decodeRequest(message)
            return operation
        }
        let adoption = operation == StorageLifecycleAdoptionRootProtocol.xpcOperation
        if adoption {
            _ = try StorageBootstrapLifecycleAdoptionRootXPC.decodeRequest(message)
            return operation
        }
        let coldEnrollment = operation == StorageBootstrapLifecycleAdoptionXPC.coldEnrollmentOperation
        let resumeEnrollment = operation == StorageBootstrapLifecycleAdoptionXPC.resumeEnrollmentOperation
        let enrollment = operation == StorageBootstrapLifecycleAdoptionXPC.enrollmentOperation || coldEnrollment || resumeEnrollment
        guard xpc_dictionary_get_count(message) <= (coldEnrollment || resumeEnrollment ? 6 : enrollment ? 5 : 4) else { throw BootstrapFailure(.invalidRequest) }
        let bind = operation == scopeBindOperation
        let root = operation == StorageLifecycleRootProtocol.xpcOperation
        let allowed: Set<String> = bind ? ["operation", "request", "store-root"] :
            root ? ["operation", "request", "store-root", "store-backing"] :
            coldEnrollment ? ["version", "operation", "request", "role", "backing-fd", "cold-seed"] :
            resumeEnrollment ? ["version", "operation", "request", "role", "backing-fd", "resume-seed"] :
            enrollment ? ["version", "operation", "request", "role", "backing-fd"] : ["version", "operation", "request", "role"]
        var keys = Set<String>()
        let valid = xpc_dictionary_apply(message) { key, value in
            guard strnlen(key, 32) < 32 else { return false }
            let name = String(cString: key)
            guard allowed.contains(name) else { return false }
            keys.insert(name)
            switch name {
            // Native child and fresh/service shims carry the fixed helper envelope
            // version. ROOT/scope requests deliberately use their own versionless envelope.
            case "version": return xpc_get_type(value) == XPC_TYPE_INT64 && xpc_int64_get_value(value) == PrivilegedPortProtocol.version
            case "operation", "role": return xpc_get_type(value) == XPC_TYPE_STRING && xpc_string_get_length(value) <= 64
            case "request", "cold-seed", "resume-seed": return xpc_get_type(value) == XPC_TYPE_DATA && xpc_data_get_length(value) > 0 &&
                xpc_data_get_length(value) <= (bind ? scopeBindMaximumPayloadBytes : StorageLifecycleProtocol.maximumPayloadBytes)
            default: return xpc_get_type(value) == XPC_TYPE_FD
            }
        }
        guard valid, root || keys == allowed else { throw BootstrapFailure(.invalidRequest) }
        if !bind && !root {
            let role = operation == "storage-lifecycle-child" ? "controller-child" : "storage-shim"
            guard let value = xpc_dictionary_get_value(message, "role"),
                  xpc_string_get_length(value) == role.utf8.count,
                  let text = xpc_string_get_string_ptr(value), String(cString: text) == role else { throw BootstrapFailure(.invalidRequest) }
        }
        switch operation {
        case scopeBindOperation: _ = try decodeBind(message)
        case StorageLifecycleRootProtocol.xpcOperation: _ = try StorageBootstrapLifecycleXPC.decodeRequest(message)
        case "storage-lifecycle-child": _ = try StorageBootstrapLifecycleChildXPC.decodeGreeting(message)
        case StorageBootstrapLifecycleColdXPC.greetingOperation: _ = try StorageBootstrapLifecycleColdXPC.decodeGreeting(message)
        case StorageBootstrapLifecycleAdoptionXPC.coldEnrollmentOperation: _ = try StorageBootstrapLifecycleAdoptionXPC.decodeColdEnrollment(message)
        case StorageBootstrapLifecycleAdoptionXPC.resumeEnrollmentOperation: _ = try StorageBootstrapLifecycleAdoptionXPC.decodeResumeEnrollment(message)
        case StorageBootstrapLifecycleResumeXPC.greetingOperation: _ = try StorageBootstrapLifecycleResumeXPC.decodeGreeting(message)
        case "storage-lifecycle-fresh-shim": _ = try StorageBootstrapLifecycleFreshXPC.decodeGreeting(message)
        case StorageBootstrapLifecycleAdoptionXPC.greetingOperation: _ = try StorageBootstrapLifecycleAdoptionXPC.decodeGreeting(message)
        case StorageBootstrapLifecycleAdoptionXPC.enrollmentOperation: _ = try StorageBootstrapLifecycleAdoptionXPC.decodeEnrollment(message)
        default: _ = try StorageBootstrapLifecycleServiceXPC.decodeGreeting(message)
        }
        return operation
    }
    /// Namespace-neutral scope bind (CEngineCore StorageLifecycleScopeProtocol). The
    /// journal root comes from this router's compiled namespace, never the request.
    static let scopeBindOperation = StorageLifecycleScopeProtocol.xpcOperation
    static let scopeBindMaximumPayloadBytes = StorageLifecycleScopeProtocol.maximumPayloadBytes
    static func decodeBind(_ message: xpc_object_t) throws -> StorageLifecycleScopeProtocol.Request {
        var keys = Set<String>()
        guard xpc_get_type(message) == XPC_TYPE_DICTIONARY else { throw BootstrapFailure(.invalidRequest) }
        xpc_dictionary_apply(message) { key, _ in keys.insert(String(cString: key)); return true }
        var length = 0
        guard keys == ["operation", "request", "store-root"],
              let op = xpc_dictionary_get_string(message, "operation"), String(cString: op) == StorageLifecycleScopeProtocol.xpcOperation,
              let fd = xpc_dictionary_get_value(message, "store-root"), xpc_get_type(fd) == XPC_TYPE_FD,
              let bytes = xpc_dictionary_get_data(message, "request", &length), length > 0,
              length <= StorageLifecycleScopeProtocol.maximumPayloadBytes else { throw BootstrapFailure(.invalidRequest) }
        return try StorageLifecycleScopeProtocol.decode(Data(bytes: bytes, count: length))
    }
    private func daemon(_ message: xpc_object_t) throws -> BootstrapProcess {
        var token = audit_token_t(); qualificationAudit(message, &token)
        let owner = try owner()
        guard owner != 0 else { throw BootstrapFailure(.unauthorized) }
        return try StorageBootstrapProcesses(ownerUID: owner, team: team, policy: policy).daemon(audit: .init(token: token))
    }
    /// Pure budget-selection seam shared by both namespaces. Anchor before admission
    /// so routing/scope-worker queue time and native proofs consume one deadline.
    static func requestDeadline(operation: String, receivedAt: DispatchTime) -> DispatchTime {
        switch operation {
        case StorageLifecycleColdRootProtocol.xpcOperation:
            return receivedAt + StorageBootstrapLifecycleColdRootXPC.budget
        case StorageLifecycleResumeRootProtocol.xpcOperation:
            return receivedAt + StorageBootstrapLifecycleResumeRootXPC.budget
        default:
            return receivedAt + StorageBootstrapLifecycleAdoptionRootXPC.budget
        }
    }
    /// Returns true exactly when this adapter owns the one asynchronous reply.
    func dispatch(_ message: xpc_object_t, reply: xpc_object_t, peer: xpc_connection_t) throws -> Bool {
        let receivedAt = DispatchTime.now()
        let operation: String
        let record: Peer
        let ticket: StorageLifecycleQualificationAdmission<ObjectIdentifier>.Ticket
        do {
            guard let recognized = try Self.validateAdmission(message) else { return false }
            operation = recognized
            (record, ticket) = try lock.withLock {
                guard !terminating else { throw BootstrapFailure(.unavailable) }
                let key = ObjectIdentifier(peer)
                guard peers[key]?.closed != true else { throw BootstrapFailure(.unavailable) }
                let ticket = try admission.admit(key)
                let value = peers[key] ?? Peer(peer)
                peers[key] = value
                return (value, ticket)
            }
        } catch {
            disconnected(peer); xpc_connection_cancel(peer); throw error
        }
        let deadline = Self.requestDeadline(operation: operation, receivedAt: receivedAt)
        routing.async { [self] in
            let finish: @Sendable (Result<Void, any Error>) -> Void = { [self] result in
                admission.finish(ticket) {
                    if case .failure = result { xpc_dictionary_set_bool(reply, "ok", false) }
                    xpc_connection_send_message(peer, reply)
                }
            }
            do {
                guard !lock.withLock({ terminating || record.closed }) else { throw BootstrapFailure(.unavailable) }
                if operation == Self.scopeBindOperation {
                    // Both namespaces: `policy`/`namespace` fix the journal root
                    // (production: StorageLifecycleNativePolicy.production).
                    let installedOwnerUID = try owner()
                    let sender = try daemon(message)
                    let request = try Self.decodeBind(message)
                    let fd = xpc_dictionary_dup_fd(message, "store-root"); guard fd >= 0 else { throw BootstrapFailure(.invalidRequest) }
                    defer { close(fd) }
                    let binding = try StorageLifecycleQualificationBinding.verified(store: request.store, rootFD: fd, owner: installedOwnerUID)
                    try registry.bind(sender, to: binding)
                    let scope = try scopes.resolve(binding) {
                        try Scope(binding: binding, rootFD: fd, owner: installedOwnerUID, team: team, policy: policy, namespace: namespace)
                    }
                    try scope.validateRoot(receivedFD: fd)
                    guard try daemon(message) == sender else { throw BootstrapFailure(.unauthorized) }
                    try scope.worker.perform { try scope.cold.remember(sender); try scope.resume.remember(sender) }
                    xpc_dictionary_set_bool(reply, "ok", true); finish(.success(())); return
                }
                let binding: StorageLifecycleQualificationBinding
                let sender: BootstrapProcess?
                if operation == StorageLifecycleRootProtocol.xpcOperation || operation == StorageLifecycleAdoptionRootProtocol.xpcOperation || operation == StorageLifecycleColdRootProtocol.xpcOperation || operation == StorageLifecycleResumeRootProtocol.xpcOperation {
                    let pinned = try daemon(message); sender = pinned; binding = try registry.binding(pinned)
                } else if operation == StorageBootstrapLifecycleAdoptionXPC.greetingOperation ||
                            operation == StorageBootstrapLifecycleAdoptionXPC.enrollmentOperation ||
                            operation == StorageBootstrapLifecycleAdoptionXPC.coldEnrollmentOperation ||
                            operation == StorageBootstrapLifecycleAdoptionXPC.resumeEnrollmentOperation {
                    sender = nil
                    let origin = try operation == StorageBootstrapLifecycleAdoptionXPC.greetingOperation ?
                        StorageBootstrapLifecycleAdoptionXPC.decodeGreeting(message) :
                        operation == StorageBootstrapLifecycleAdoptionXPC.coldEnrollmentOperation ? StorageBootstrapLifecycleAdoptionXPC.decodeColdEnrollment(message).0 :
                        operation == StorageBootstrapLifecycleAdoptionXPC.resumeEnrollmentOperation ? StorageBootstrapLifecycleAdoptionXPC.decodeResumeEnrollment(message).0 :
                        StorageBootstrapLifecycleAdoptionXPC.decodeEnrollment(message)
                    let full = try origin.binding.value()
                    // Routing metadata only. No original/new parent requirement on
                    // reconnect: greet repins the protected registered native shim.
                    binding = StorageLifecycleQualificationBinding(store: full.storeID, root: full.root, ownerUID: try owner())
                } else {
                    sender = nil
                    // Only routing hints. greet() below independently pins the actual
                    // direct child/shim and daemon before accepting any enrollment.
                    let id: UInt64
                    switch operation {
                    case "storage-lifecycle-child": id = try StorageBootstrapLifecycleChildXPC.decodeGreeting(message).daemonUniqueID
                    case StorageBootstrapLifecycleColdXPC.greetingOperation: id = try StorageBootstrapLifecycleColdXPC.decodeGreeting(message).daemonUniqueID
                    case StorageBootstrapLifecycleResumeXPC.greetingOperation: id = try StorageBootstrapLifecycleResumeXPC.decodeGreeting(message).daemonUniqueID
                    case "storage-lifecycle-fresh-shim": id = try StorageBootstrapLifecycleFreshXPC.decodeGreeting(message).daemonUniqueID
                    default: id = try StorageBootstrapLifecycleServiceXPC.decodeGreeting(message).daemonUniqueID
                    }
                    binding = try registry.route(id)
                }
                guard let scope = try scopes.existing(binding) else { throw BootstrapFailure(.unauthorized) }
                try lock.withLock {
                    guard !terminating, !record.closed, record.scope == nil || record.scope === scope else { throw BootstrapFailure(.unauthorized) }
                    record.scope = scope
                }
                scope.rpc.schedule({ [self] in
                    guard !lock.withLock({ terminating || record.closed }) else { throw BootstrapFailure(.unavailable) }
                    try scope.validateRoot()
                    switch operation {
                    case StorageLifecycleRootProtocol.xpcOperation:
                        guard let sender, try daemon(message) == sender else { throw BootstrapFailure(.unauthorized) }
                        let request = try StorageBootstrapLifecycleXPC.decodeRequest(message)
                        let body: StorageLifecycleRootProtocol.ResultBody
                        do {
                            try scope.directory.validate(request)
                            body = try StorageBootstrapLifecycleXPC.withDescriptors(message, request: request) {
                                try scope.rpc.dispatch(request, daemon: sender, rootFD: $0, backingFD: $1)
                            }
                        } catch let failure as BootstrapFailure { body = .failure(failure.code) }
                        catch { body = .failure(.repairRequired) }
                        guard try daemon(message) == sender else { throw BootstrapFailure(.unauthorized) }
                        let data = try StorageLifecycleRootProtocol.encode(.init(for: request, body: body))
                        data.withUnsafeBytes { xpc_dictionary_set_data(reply, "reply", $0.baseAddress, $0.count) }
                        xpc_dictionary_set_bool(reply, "ok", true)
                    case StorageLifecycleColdRootProtocol.xpcOperation:
                        guard let sender, try daemon(message) == sender else { throw BootstrapFailure(.unauthorized) }
                        let request = try StorageBootstrapLifecycleColdRootXPC.decodeRequest(message)
                        let body: StorageLifecycleColdRootProtocol.ResultBody
                        do {
                            switch request.body {
                            case .status(let identity): try scope.directory.requireIdentity(identity)
                            case .prepare(let prepare):
                                try scope.directory.requireIdentity(prepare.identity)
                                try scope.directory.requireBinding(prepare.mountedGreeting.binding.value(), establish: false)
                            case .resolveDead(let value): try scope.directory.requireIdentity(value.identity)
                            case .complete: break // Scope-local authority resolves the protected operation.
                            }
                            body = try StorageBootstrapLifecycleColdRootXPC.withDescriptors(message, request: request) { pathFD, rootFD, lockFD in
                                try StorageBootstrapLifecycleAdoptionLease.withObservedLocks(owner: sender, expectedRoot: binding.root,
                                    pathFD: pathFD, rootFD: rootFD, fileFD: lockFD) { observed in
                                    try scope.adoption.withRequest(deadline: deadline, check: {
                                        guard !lock.withLock({ terminating || record.closed }), try daemon(message) == sender,
                                              try observed.validate().root == binding.root else { throw BootstrapFailure(.unauthorized) }
                                        try scope.validateRoot()
                                    }) {
                                        try scope.cold.withRequest(check: scope.adoption.checkRequest) {
                                            try scope.adoptionAuthority.withIOChecks(scope.adoption.checkRequest) {
                                                try scope.rpc.dispatchCold(request, daemon: sender, cold: scope.cold)
                                            }
                                        }
                                    }
                                }
                            }
                        } catch let failure as BootstrapFailure { body = .failure(failure.code) }
                        catch { body = .failure(.unavailable) }
                        guard try daemon(message) == sender else { throw BootstrapFailure(.unauthorized) }
                        let data = try StorageLifecycleColdRootProtocol.encode(.init(for: request, body: body))
                        data.withUnsafeBytes { xpc_dictionary_set_data(reply, "reply", $0.baseAddress, $0.count) }
                        xpc_dictionary_set_bool(reply, "ok", true)
                    case StorageLifecycleAdoptionRootProtocol.xpcOperation:
                        guard let sender, try daemon(message) == sender else { throw BootstrapFailure(.unauthorized) }
                        let request = try StorageBootstrapLifecycleAdoptionRootXPC.decodeRequest(message)
                        let body: StorageLifecycleAdoptionRootProtocol.ResultBody
                        do {
                            switch request.body {
                            case .handoffStatus(let identity):
                                // Read-only discovery rechecks the exact dead L3 predecessor
                                // inside handoffStatus, after native scope/lock validation.
                                try scope.directory.requireIdentity(identity)
                            case .recoverHandoff(let identity, _):
                                try scope.rpc.guardColdPublication(store: binding.store.rawValue)
                                try scope.directory.requireIdentity(identity)
                            default:
                                try scope.rpc.guardColdPublication(store: binding.store.rawValue)
                                try scope.rpc.guardHandoffPublication(store: binding.store.rawValue)
                            }
                            guard let origin = try scope.adoptionAuthority.registeredOrigin(store: binding.store.rawValue) else {
                                throw BootstrapFailure(.conflict)
                            }
                            var token = audit_token_t(); qualificationAudit(message, &token)
                            let audit = BootstrapAuditIdentity(token: token)
                            body = try StorageBootstrapLifecycleAdoptionRootXPC.withDescriptors(message, request: request) { pathFD, rootFD, lockFD in
                                try StorageBootstrapLifecycleAdoptionLease.withObservedLocks(owner: sender, expectedRoot: binding.root,
                                    pathFD: pathFD, rootFD: rootFD, fileFD: lockFD) { observed in
                                    try scope.adoption.withRequest(deadline: deadline, check: {
                                        guard !lock.withLock({ terminating || record.closed }),
                                              try daemon(message) == sender,
                                              try observed.validate().root == binding.root,
                                              try scope.adoptionAuthority.registeredOrigin(store: binding.store.rawValue) == origin else {
                                            throw BootstrapFailure(.unauthorized)
                                        }
                                        try scope.validateRoot()
                                        try scope.directory.requireBinding(origin.wire.binding.value(), establish: false)
                                    }) {
                                        try scope.adoptionAuthority.withIOChecks(scope.adoption.checkRequest) {
                                            try StorageBootstrapLifecycleAdoptionRootXPC.dispatch(request, authority: scope.adoptionAuthority,
                                                origin: origin.wire, peer: audit, service: { adoption, grant in
                                                    let (registered, principal) = try scope.adoptionAuthority.committed(adoption, peer: audit)
                                                    let expected = try scope.rpc.adoptedService(identity: grant.identity)
                                                    guard expected.grant == grant else { throw BootstrapFailure(.conflict) }
                                                    let proof = try scope.adoption.service(adoption, grant: grant, expected: expected, origin: registered)
                                                    guard try scope.adoptionAuthority.committed(adoption, peer: audit).1 == principal,
                                                          try scope.rpc.adoptedService(identity: grant.identity) == expected else { throw BootstrapFailure(.unauthorized) }
                                                    return try proof.result.state(boot: proof.boot)
                                                }, completeServiceChange: { adoption, change in
                                                    try scope.rpc.completeAdoptedServiceChange(adoption: adoption, change: change,
                                                        peer: audit, adoptionAuthority: scope.adoptionAuthority,
                                                        check: scope.adoption.checkRequest, prove: { change, target, completed, nonce, registered in
                                                            try scope.adoption.serviceChange(adoption, change: change,
                                                                targetBoot: target, completed: completed, nonce: nonce, origin: registered)
                                                        })
                                                }, handoffStatus: { identity in
                                                    try scope.rpc.handoffStatus(identity: identity, daemon: sender)
                                                }, recoverHandoff: { identity, id in
                                                    try scope.rpc.recoverHandoff(identity: identity, operationID: id, daemon: sender)
                                                })
                                        }
                                    }
                                }
                            }
                        } catch let failure as BootstrapFailure { body = .failure(failure.code) }
                        catch { body = .failure(.unavailable) }
                        guard try daemon(message) == sender else { throw BootstrapFailure(.unauthorized) }
                        let data = try StorageLifecycleAdoptionRootProtocol.encode(.init(for: request, body: body))
                        data.withUnsafeBytes { xpc_dictionary_set_data(reply, "reply", $0.baseAddress, $0.count) }
                        xpc_dictionary_set_bool(reply, "ok", true)
                    case StorageBootstrapLifecycleAdoptionXPC.resumeEnrollmentOperation:
                        try scope.adoption.enrollResume(message, reply: reply, rootFD: scope.rootFD, directory: scope.directory,
                            rpc: scope.rpc, service: scope.service, authority: scope.adoptionAuthority)
                    case StorageBootstrapLifecycleResumeXPC.greetingOperation:
                        let greeting = try StorageBootstrapLifecycleResumeXPC.decodeGreeting(message)
                        try scope.directory.requireBinding(greeting.binding.value(), establish: false)
                        try scope.resume.greet(message, reply: reply, peer: peer)
                    case StorageLifecycleResumeRootProtocol.xpcOperation:
                        guard let sender, try daemon(message) == sender else { throw BootstrapFailure(.unauthorized) }
                        let request = try StorageBootstrapLifecycleResumeRootXPC.decodeRequest(message)
                        let body: StorageLifecycleResumeRootProtocol.ResultBody
                        do {
                            try scope.directory.validateResume(request)
                            body = try StorageBootstrapLifecycleResumeRootXPC.withDescriptors(message, request: request) { pathFD, rootFD, lockFD in
                                try StorageBootstrapLifecycleAdoptionLease.withObservedLocks(owner: sender, expectedRoot: binding.root,
                                    pathFD: pathFD, rootFD: rootFD, fileFD: lockFD) { observed in
                                        try scope.adoption.withRequest(deadline: deadline, check: {
                                            guard !lock.withLock({ terminating || record.closed }), try daemon(message) == sender,
                                                  try observed.validate().root == binding.root else { throw BootstrapFailure(.unauthorized) }
                                            try scope.validateRoot()
                                        }) {
                                            try scope.resume.withRequest(check: scope.adoption.checkRequest) {
                                                try scope.adoptionAuthority.withIOChecks(scope.adoption.checkRequest) {
                                                    try scope.rpc.dispatchResume(request, daemon: sender, resume: scope.resume)
                                                }
                                            }
                                        }
                                    }
                            }
                        } catch let failure as BootstrapFailure { body = .failure(failure.code) }
                        catch { body = .failure(.unavailable) }
                        guard try daemon(message) == sender else { throw BootstrapFailure(.unauthorized) }
                        let data = try StorageLifecycleResumeRootProtocol.encode(.init(for: request, body: body))
                        data.withUnsafeBytes { xpc_dictionary_set_data(reply, "reply", $0.baseAddress, $0.count) }
                        xpc_dictionary_set_bool(reply, "ok", true)
                    case StorageBootstrapLifecycleAdoptionXPC.coldEnrollmentOperation:
                        try scope.adoption.enrollCold(message, reply: reply, rootFD: scope.rootFD, directory: scope.directory,
                            rpc: scope.rpc, service: scope.service, authority: scope.adoptionAuthority)
                    case StorageBootstrapLifecycleColdXPC.greetingOperation:
                        let greeting = try StorageBootstrapLifecycleColdXPC.decodeGreeting(message)
                        try scope.directory.requireBinding(greeting.binding.value(), establish: false)
                        try scope.cold.greet(message, reply: reply, peer: peer)
                    case StorageBootstrapLifecycleAdoptionXPC.enrollmentOperation:
                        try scope.rpc.guardColdPublication(store: binding.store.rawValue)
                        try scope.adoption.enroll(message, reply: reply, rootFD: scope.rootFD, directory: scope.directory,
                            rpc: scope.rpc, service: scope.service, authority: scope.adoptionAuthority)
                    case StorageBootstrapLifecycleAdoptionXPC.greetingOperation:
                        try scope.rpc.guardColdPublication(store: binding.store.rawValue)
                        let origin = try StorageBootstrapLifecycleAdoptionXPC.decodeGreeting(message)
                        try scope.directory.requireBinding(origin.binding.value(), establish: false)
                        try scope.adoption.greet(message, reply: reply, peer: peer)
                    case "storage-lifecycle-child":
                        let greeting = try StorageBootstrapLifecycleChildXPC.decodeGreeting(message)
                        guard greeting.store == binding.store.rawValue else { throw BootstrapFailure(.conflict) }
                        if let full = try scope.directory.recordedBinding() {
                            guard greeting.binding == StorageLifecycleProtocol.bindingDigest(full) else { throw BootstrapFailure(.conflict) }
                        }
                        try scope.child.greet(message, reply: reply, peer: peer)
                    case "storage-lifecycle-fresh-shim":
                        let greeting = try StorageBootstrapLifecycleFreshXPC.decodeGreeting(message)
                        guard greeting.store == binding.store.rawValue else { throw BootstrapFailure(.conflict) }
                        if let full = try scope.directory.recordedBinding() {
                            guard greeting.matches(binding: full) else { throw BootstrapFailure(.conflict) }
                        }
                        try scope.fresh.greet(message, reply: reply, peer: peer)
                    default:
                        let greeting = try StorageBootstrapLifecycleServiceXPC.decodeGreeting(message)
                        try scope.directory.requireBinding(greeting.binding.value(), establish: false)
                        try scope.service.greet(message, reply: reply, peer: peer)
                    }
                    if lock.withLock({ terminating || record.closed }) { scope.disconnected(peer); throw BootstrapFailure(.unavailable) }
                }, completion: finish)
            } catch { finish(.failure(error)) }
        }
        return true
    }
    /// Direct revocation is never queued behind a blocked proof and is not exit evidence.
    func disconnected(_ peer: xpc_connection_t) {
        let scope = lock.withLock { () -> Scope? in
            let key = ObjectIdentifier(peer)
            admission.disconnected(key)
            guard let record = peers.removeValue(forKey: key) else { return nil }
            record.closed = true; return record.scope
        }
        scope?.disconnected(peer)
    }
    func quiesce() {
        let active = lock.withLock { () -> [Peer] in
            terminating = true; admission.invalidate()
            let values = Array(peers.values); values.forEach { $0.closed = true }; return values
        }
        for record in active { record.scope?.disconnected(record.connection); xpc_connection_cancel(record.connection) }
        admission.wait()
    }
}

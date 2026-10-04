import CEngineHelperSupport
import CryptoKit
import Darwin
import Foundation
import Security

typealias Adoption = StorageLifecycleAdoptionProtocol

/// Metadata frozen by ROOT, never itself native authorization.
struct StorageLifecycleShimOrigin: Codable, Equatable {
    let wire: StorageLifecycleAdoptionProtocol.Origin
    let shim: BootstrapProcess
    let originalDaemon: BootstrapProcess
    let originalController: BootstrapProcess
}

/// Protected predecessor evidence, not a caller capability. Exact canonical store
/// bytes include latest request/principal and the previous bounded bridge.
struct StorageLifecycleColdAdoptionSnapshot: Codable, Equatable {
    let origin: StorageLifecycleShimOrigin
    let committedEpoch: UInt64
    let allocatedEpoch: UInt64
    let daemon: BootstrapProcess
    let controller: BootstrapProcess
    let protectedStore: Data
}

/// Dedicated scope-owned checkpoint ONLY. Must not share a lifecycle/v1 payload.
/// The protected adapter couples directory selection and ROOT key to the lifecycle
/// scope. No daemon lock descriptors are retained.
protocol StorageLifecycleAdoptionJournal: AnyObject {
    func load() throws -> Data?
    func rootPublicKey() throws -> Data
    func checkpoint(_ bytes: Data) throws
}

/// Internal dependency boundary, not an RPC or caller-supplied capability. The native
/// transport still requires trusted scope-router fresh/candidate verifier injection. Shared locks are not irrevocable
/// leases: adoption authority is ROOT's serialized origin/epoch, positive old-owner
/// death, and the independently fenced native shim session, not a lock DTO.
protocol StorageLifecycleAdoptionChecking {
    /// Must authenticate original daemon, its direct controller and direct shim;
    /// validate actual root/disk descriptors and live shim launch/spec claims.
    func freshOrigin(_ origin: StorageLifecycleShimOrigin, rootFD: Int32, backingFD: Int32) throws
    /// Must pin the actual connected peer as the new signed owner daemon, pin its
    /// direct controller, and observe canonical locks without retaining their FDs.
    /// Locks are rejection-only consistency evidence, never adoption or continuing
    /// VM-control authority. Future native calls must validate immediately before
    /// and after I/O against the fixed descriptor root identity; canonical paths
    /// only reject replacements, never select an authorization target. A postflight
    /// failure can follow side effects: uncertain completion retains durable pending
    /// intent; never undo/delete it or claim rollback.
    /// Incarnation/SPKI must be authenticated stable launch claims, never regenerated
    /// per call. Every process field must come from the pinned native process.
    func candidate(_ request: StorageLifecycleAdoptionProtocol.Request,
                   peer: BootstrapAuditIdentity) throws -> BootstrapPrincipal
    /// Resolve the full boot/uniqueID/start-time/audit-version identity, never PID
    /// alone: an unrelated process reusing its PID does not keep this owner alive.
    /// Only positive native exit evidence returns .exited; ambiguity is .unknown.
    func liveness(_ process: BootstrapProcess) -> BootstrapLiveness
    /// Must natively repin the exact frozen shim, without requiring a new parent.
    func registeredShim(_ origin: StorageLifecycleShimOrigin) throws
    /// Must directly challenge that same shim; return only after native sender
    /// authentication and exact nonce/digest acknowledgement of the durable fence.
    /// Native implementation MUST serialize ROOT exchanges and retain a process-
    /// lifetime shim high-water mark (not a writable host journal): accept strictly greater ROOT-authorized epochs for this exact
    /// origin, or the exact current fence retry; reject stale/equal-different fences.
    /// ROOT proves each superseded owner positively dead before allocating again.
    /// Intervening prepares may never have reached the shim, so it cannot require
    /// equality with expectedEpoch or a historical chain. A fence is only native
    /// pending/commit state, NEVER workload permission until the distinct commit phase.
    func fence(_ challenge: StorageLifecycleAdoptionProtocol.Challenge,
               origin: StorageLifecycleShimOrigin) throws
    /// Native commit acknowledgement AFTER durable ROOT commit. Failure retains
    /// the commit; an exact retry must not revoke its legitimate control channel.
    func commit(_ request: Adoption.Request, origin: StorageLifecycleShimOrigin) throws
}

/// Serialized reattachment authority. Retains one origin, current session, pending
/// adoption and latest commit per physical store, plus one abandoned native fence.
/// Allocated high-water advances durably at prepare; committed epoch/owners advance
/// only after native fence acknowledgement and fresh rechecks. Supersession never
/// authorizes workloads or rewrites the last committed owner evidence.
/// No recursive history, TTL cleanup or dead
/// shim fallback. Existing fresh direct-parent authorization is not weakened.
final class StorageBootstrapLifecycleAdoptionAuthority {
    static let maximumStores = 128
    private static let maximumBytes = 2 * 1024 * 1024
    private struct Intent: Codable, Equatable {
        let request: Adoption.Request
        let principal: BootstrapPrincipal
    }
    /// One bounded predecessor; deliberately contains no Request/history chain.
    private struct Abandoned: Codable {
        let fence: Adoption.FenceIdentity
        let principal: BootstrapPrincipal
    }
    private struct ColdBridge: Codable, Equatable {
        let operationID: String
        let signedOpenSHA256: String
        let snapshotSHA256: String
        let oldAllocatedEpoch: UInt64
        let origin: StorageLifecycleShimOrigin
        let baseEpoch: UInt64
    }
    private struct Store: Codable {
        let origin: StorageLifecycleShimOrigin
        let baseEpoch: UInt64
        var coldBridge: ColdBridge?
        var epoch: UInt64
        var allocatedEpoch: UInt64
        var abandoned: Abandoned?
        var daemon: BootstrapProcess
        var controller: BootstrapProcess
        var pending: Intent?
        var latest: Intent?
    }
    private struct State: Codable {
        let version: String
        let root: Data
        var stores: [String: Store]
    }
    private let journal: any StorageLifecycleAdoptionJournal
    private let processes: any StorageLifecycleAdoptionChecking
    private var state: State
    private var poisoned = false
    private var ioCheck: (() throws -> Void)?

    /// Native router-only scope; never retained beyond the observed-lock callback.
    func withIOChecks<T>(_ check: () throws -> Void, _ body: () throws -> T) throws -> T {
        guard ioCheck == nil else { throw BootstrapFailure(.unavailable) }
        return try withoutActuallyEscaping(check) { scoped in
            ioCheck = scoped
            defer { ioCheck = nil }
            return try body()
        }
    }

    init(journal: any StorageLifecycleAdoptionJournal, processes: any StorageLifecycleAdoptionChecking) throws {
        self.journal = journal; self.processes = processes
        do {
            let root = try journal.rootPublicKey()
            _ = try StorageIdentity.RootPublicKey(publicData: root)
            if let bytes = try journal.load() {
                guard bytes.count <= Self.maximumBytes else { throw BootstrapFailure(.repairRequired) }
                state = try JSONDecoder().decode(State.self, from: bytes)
                guard try Self.encode(state) == bytes else { throw BootstrapFailure(.repairRequired) }
            } else { state = State(version: Adoption.version, root: root, stores: [:]) }
            guard state.root == root else { throw BootstrapFailure(.repairRequired) }
            try validate(state)
        } catch { throw BootstrapFailure(.repairRequired) }
    }

    func recordOrigin(_ origin: StorageLifecycleShimOrigin, rootFD: Int32, backingFD: Int32) throws {
        try healthy(); try origin.wire.validate()
        guard origin.wire.rootPublicKey == state.root else { throw BootstrapFailure(.conflict) }
        let id = origin.wire.binding.store
        if let old = state.stores[id] {
            guard old.origin == origin else { throw BootstrapFailure(.conflict) }
            try processes.freshOrigin(origin, rootFD: rootFD, backingFD: backingFD)
            return
        }
        guard state.stores.count < Self.maximumStores else { throw BootstrapFailure(.capacityExceeded) }
        let binding = try origin.wire.binding.value()
        for existing in state.stores.values {
            let other = try existing.origin.wire.binding.value()
            guard binding.root != other.root, binding.backing.identity != other.backing.identity else {
                throw BootstrapFailure(.conflict)
            }
        }
        try processes.freshOrigin(origin, rootFD: rootFD, backingFD: backingFD)
        var next = state
        next.stores[id] = Store(origin: origin, baseEpoch: 1, epoch: 1, allocatedEpoch: 1, daemon: origin.originalDaemon,
                                controller: origin.originalController)
        try commit(next)
    }

    /// Durable prepare before any shim side effect; failures retain the exact intent.
    func prepare(_ request: Adoption.Request, peer: BootstrapAuditIdentity) throws {
        try healthy(); try request.validate()
        let id = request.origin.binding.store
        guard var store = state.stores[id], store.origin.wire == request.origin else { throw BootstrapFailure(.conflict) }
        let principal = try candidate(request, peer: peer, origin: store.origin)
        let intent = Intent(request: request, principal: principal)
        if let pending = store.pending {
            if pending == intent { try departed(store); return }
            guard request.expectedEpoch == store.allocatedEpoch,
                  try request.superseded == pending.request.fenceIdentity,
                  request.id != store.latest?.request.id else { throw BootstrapFailure(.conflict) }
            try departed(store)
            try departed(pending.principal)
            // Preserve the last committed owner and only the immediate abandoned
            // fence. A higher allocation covers arbitrarily many missed shim fences.
            store.abandoned = Abandoned(fence: try pending.request.fenceIdentity, principal: pending.principal)
            store.pending = intent; store.allocatedEpoch = try request.epoch
            var next = state; next.stores[id] = store
            try commit(next); return
        }
        if store.latest?.request.id == request.id {
            guard store.latest == intent else { throw BootstrapFailure(.conflict) }
            return
        }
        guard store.allocatedEpoch == request.expectedEpoch, request.superseded == nil else { throw BootstrapFailure(.conflict) }
        try departed(store)
        store.abandoned = nil
        store.pending = intent; store.allocatedEpoch = try request.epoch
        var next = state; next.stores[id] = store
        try commit(next)
    }

    /// Exact lost-reply retries perform fresh native proof, not a persisted DTO replay.
    func complete(_ request: Adoption.Request, peer: BootstrapAuditIdentity) throws -> UInt64 {
        try healthy(); try request.validate()
        let id = request.origin.binding.store
        guard var store = state.stores[id], store.origin.wire == request.origin else { throw BootstrapFailure(.conflict) }
        let principal = try candidate(request, peer: peer, origin: store.origin)
        let intent = Intent(request: request, principal: principal)
        guard store.pending == intent || (store.pending == nil && store.latest == intent) else { throw BootstrapFailure(.conflict) }
        if store.pending != nil { try departed(store) }
        var nonce = Data(count: 32)
        let status = nonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
        guard status == errSecSuccess else { throw BootstrapFailure(.unavailable) }
        try processes.fence(.init(request: request, nonce: nonce), origin: store.origin)
        // Recheck both endpoint identities after the native exchange and before commit.
        guard try candidate(request, peer: peer, origin: store.origin) == principal else { throw BootstrapFailure(.unauthorized) }
        if store.pending != nil {
            try departed(store)
            store.epoch = try request.epoch; store.daemon = principal.daemon; store.controller = principal.child
            store.latest = intent; store.pending = nil
            var next = state; next.stores[id] = store
            try commit(next)
        }
        try processes.commit(request, origin: store.origin)
        guard try candidate(request, peer: peer, origin: store.origin) == principal else {
            throw BootstrapFailure(.unauthorized)
        }
        return store.epoch
    }

    /// Read-only scope projection. In particular a latest durable commit does not
    /// claim that the native shim acknowledged it or mint a control capability.
    func status(store id: String) throws -> StorageLifecycleAdoptionRootProtocol.Status {
        try healthy()
        guard let store = state.stores[id] else { throw BootstrapFailure(.conflict) }
        return try .init(origin: store.origin.wire, shimAudit: store.origin.shim.auditToken, shimUniqueID: store.origin.shim.uniqueID, baseEpoch: store.baseEpoch, committedEpoch: store.epoch,
            allocatedEpoch: store.allocatedEpoch, pending: store.pending?.request, latest: store.latest?.request)
    }

    /// Exact latest committed owner only; pending/superseding fences fail closed.
    func committed(_ request: Adoption.Request, peer: BootstrapAuditIdentity) throws -> (StorageLifecycleShimOrigin, BootstrapPrincipal) {
        try healthy(); try request.validate()
        guard let store = state.stores[request.origin.binding.store], store.pending == nil,
              let latest = store.latest, latest.request == request,
              try candidate(request, peer: peer, origin: store.origin) == latest.principal else {
            throw BootstrapFailure(.unauthorized)
        }
        return (store.origin, latest.principal)
    }
    func committedRequest(store id: String, daemon: BootstrapProcess) throws -> Adoption.Request? {
        try healthy()
        guard let store = state.stores[id], store.pending == nil,
              let latest = store.latest, latest.principal.daemon == daemon else { return nil }
        return latest.request
    }

    /// Scope router lookup: protected persisted evidence, never caller authority.
    func registeredOrigin(store id: String) throws -> StorageLifecycleShimOrigin? {
        try healthy()
        return state.stores[id]?.origin
    }

    /// Read-only live-handoff anchor: all native owner/candidate tuples must be
    /// positively dead, including pending/latest/abandoned adoption candidates.
    /// The shim stays live and is repinned, never reparented or adopted here.
    func handoffSnapshot(store id: String) throws -> StorageLifecycleColdAdoptionSnapshot {
        try healthy(); try ioCheck?()
        guard let store = state.stores[id] else { throw BootstrapFailure(.blocked) }
        try processes.registeredShim(store.origin)
        try departed(store)
        for process in [store.origin.originalDaemon, store.origin.originalController] {
            guard processes.liveness(process) == .exited else { throw BootstrapFailure(.blocked) }
        }
        if let pending = store.pending { try departed(pending.principal) }
        if let latest = store.latest { try departed(latest.principal) }
        try ioCheck?()
        return try snapshot(store)
    }

    /// Initial cold policy rejects both pending and abandoned allocations. No
    /// implicit abandonment or liveness assumption about the successor is made.
    func coldSnapshot(store id: String) throws -> StorageLifecycleColdAdoptionSnapshot {
        try healthy()
        guard let store = state.stores[id] else { throw BootstrapFailure(.conflict) }
        guard store.pending == nil, store.abandoned == nil else { throw BootstrapFailure(.blocked) }
        return try snapshot(store)
    }

    func verifyColdPredecessor(snapshot expected: StorageLifecycleColdAdoptionSnapshot) throws {
        guard try coldSnapshot(store: expected.origin.wire.binding.store) == expected else {
            throw BootstrapFailure(.conflict)
        }
        for process in [expected.origin.shim, expected.origin.originalDaemon,
                        expected.origin.originalController, expected.daemon, expected.controller] {
            guard processes.liveness(process) == .exited else { throw BootstrapFailure(.blocked) }
        }
    }

    /// Trusted lifecycle coordinator proves the NEW origin and its boot/key. This
    /// method only proves the old protected state/death and durably rotates it.
    func rotateCold(from expected: StorageLifecycleColdAdoptionSnapshot, to origin: StorageLifecycleShimOrigin,
                    operationID: String, signedOpenSHA256: String, baseEpoch: UInt64) throws {
        try healthy()
        let bridge = try coldBridge(from: expected, to: origin, operationID: operationID,
                                    signedOpenSHA256: signedOpenSHA256, baseEpoch: baseEpoch)
        if try matchesColdRotation(from: expected, to: origin, operationID: operationID,
                                   signedOpenSHA256: signedOpenSHA256, baseEpoch: baseEpoch) { return }
        try verifyColdPredecessor(snapshot: expected)
        var next = state
        next.stores[origin.wire.binding.store] = Store(origin: origin, baseEpoch: baseEpoch,
            coldBridge: bridge, epoch: baseEpoch, allocatedEpoch: baseEpoch,
            daemon: origin.originalDaemon, controller: origin.originalController)
        try commit(next)
    }

    /// L2 recovery after the adoption checkpoint but before lifecycle L3. The
    /// bridge survives live adoption, but must NEVER authorize a stale L3 replay.
    func matchesColdRotation(from expected: StorageLifecycleColdAdoptionSnapshot, to origin: StorageLifecycleShimOrigin,
                             operationID: String, signedOpenSHA256: String, baseEpoch: UInt64) throws -> Bool {
        try healthy()
        let bridge = try coldBridge(from: expected, to: origin, operationID: operationID,
                                    signedOpenSHA256: signedOpenSHA256, baseEpoch: baseEpoch)
        guard let store = state.stores[origin.wire.binding.store] else { return false }
        return store.coldBridge == bridge && store.origin == origin && store.baseEpoch == baseEpoch
            && store.epoch == baseEpoch && store.allocatedEpoch == baseEpoch
            && store.pending == nil && store.latest == nil && store.abandoned == nil
            && store.daemon == origin.originalDaemon && store.controller == origin.originalController
    }

    private func snapshot(_ store: Store) throws -> StorageLifecycleColdAdoptionSnapshot {
        try .init(origin: store.origin, committedEpoch: store.epoch, allocatedEpoch: store.allocatedEpoch,
                  daemon: store.daemon, controller: store.controller, protectedStore: Self.encode(store))
    }
    private func coldBridge(from expected: StorageLifecycleColdAdoptionSnapshot, to origin: StorageLifecycleShimOrigin,
                            operationID: String, signedOpenSHA256: String, baseEpoch: UInt64) throws -> ColdBridge {
        _ = try StorageIdentity.RequestID(operationID); _ = try StorageIdentity.SPKISHA256(signedOpenSHA256)
        try origin.wire.validate()
        guard expected.protectedStore.count <= Self.maximumBytes else { throw BootstrapFailure(.conflict) }
        let old = try JSONDecoder().decode(Store.self, from: expected.protectedStore)
        guard try snapshot(old) == expected, old.pending == nil, old.abandoned == nil,
              expected.allocatedEpoch < UInt64.max, baseEpoch == expected.allocatedEpoch + 1,
              origin.wire.binding == expected.origin.wire.binding,
              origin.wire.rootPublicKey == expected.origin.wire.rootPublicKey,
              origin.wire.rootPublicKey == state.root,
              origin.wire.shimLaunchUUID != expected.origin.wire.shimLaunchUUID,
              origin.shim.boot != expected.origin.shim.boot || origin.shim.uniqueID != expected.origin.shim.uniqueID else {
            throw BootstrapFailure(.conflict)
        }
        try validate(State(version: Adoption.version, root: state.root,
                           stores: [old.origin.wire.binding.store: old]))
        return ColdBridge(operationID: operationID, signedOpenSHA256: signedOpenSHA256,
            snapshotSHA256: SHA256.hash(data: expected.protectedStore).map { String(format: "%02x", $0) }.joined(),
            oldAllocatedEpoch: expected.allocatedEpoch, origin: origin, baseEpoch: baseEpoch)
    }

    private func candidate(_ request: Adoption.Request, peer: BootstrapAuditIdentity,
                           origin: StorageLifecycleShimOrigin) throws -> BootstrapPrincipal {
        guard peer.data == request.daemonAudit else { throw BootstrapFailure(.unauthorized) }
        let principal = try processes.candidate(request, peer: peer)
        do { try validatePrincipal(principal, origin: origin) }
        catch { throw BootstrapFailure(.unauthorized) }
        guard principal.daemon.auditToken == request.daemonAudit,
              principal.daemon.uniqueID == request.daemonUniqueID,
              principal.child.auditToken == request.controllerAudit,
              principal.child.uniqueID == request.controllerUniqueID,
              principal.daemon.boot == origin.shim.boot, principal.child.boot == origin.shim.boot,
              principal.daemon.uniqueID != origin.shim.uniqueID,
              principal.child.uniqueID != origin.shim.uniqueID else { throw BootstrapFailure(.unauthorized) }
        try processes.registeredShim(origin)
        return principal
    }
    private func departed(_ store: Store) throws {
        guard processes.liveness(store.daemon) == .exited,
              processes.liveness(store.controller) == .exited else { throw BootstrapFailure(.blocked) }
        if let abandoned = store.abandoned { try departed(abandoned.principal) }
    }
    private func departed(_ principal: BootstrapPrincipal) throws {
        guard processes.liveness(principal.daemon) == .exited,
              processes.liveness(principal.child) == .exited else { throw BootstrapFailure(.blocked) }
    }
    private func healthy() throws {
        guard !poisoned else { throw BootstrapFailure(.repairRequired) }
        do {
            guard try journal.rootPublicKey() == state.root else { throw BootstrapFailure(.repairRequired) }
        } catch { poisoned = true; throw BootstrapFailure(.repairRequired) }
    }
    private func commit(_ next: State) throws {
        try validate(next)
        let bytes = try Self.encode(next)
        guard bytes.count <= Self.maximumBytes else { throw BootstrapFailure(.capacityExceeded) }
        try ioCheck?()
        do { try journal.checkpoint(bytes); state = next }
        catch { poisoned = true; throw BootstrapFailure(.repairRequired) }
        // Postflight failure preserves the durable state; it is not rollback.
        try ioCheck?()
    }
    private static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }
    private func validate(_ value: State) throws {
        guard value.version == Adoption.version, value.stores.count <= Self.maximumStores else { throw BootstrapFailure(.repairRequired) }
        var roots: [StorageIdentity.RootIdentity] = [], disks: [StorageIdentity.RootIdentity] = []
        for (id, store) in value.stores {
            try store.origin.wire.validate()
            for process in [store.origin.shim, store.origin.originalDaemon, store.origin.originalController,
                            store.daemon, store.controller] { try validateProcess(process) }
            guard store.origin.shim.boot == store.origin.originalDaemon.boot,
                  store.origin.shim.boot == store.origin.originalController.boot,
                  store.daemon.boot == store.origin.shim.boot, store.controller.boot == store.origin.shim.boot,
                  store.daemon.uniqueID != store.controller.uniqueID,
                  store.daemon.pid != store.controller.pid,
                  store.origin.originalDaemon.uniqueID != store.origin.originalController.uniqueID,
                  store.origin.originalDaemon.pid != store.origin.originalController.pid,
                  store.origin.shim.pid != store.origin.originalDaemon.pid,
                  store.origin.shim.pid != store.origin.originalController.pid else { throw BootstrapFailure(.repairRequired) }
            let binding = try store.origin.wire.binding.value()
            guard id == binding.storeID.rawValue, store.origin.wire.rootPublicKey == value.root,
                  !roots.contains(binding.root), !disks.contains(binding.backing.identity),
                  store.baseEpoch > 0, store.epoch >= store.baseEpoch,
                  store.origin.shim.uniqueID != store.origin.originalDaemon.uniqueID,
                  store.origin.shim.uniqueID != store.origin.originalController.uniqueID else { throw BootstrapFailure(.repairRequired) }
            if let bridge = store.coldBridge {
                _ = try StorageIdentity.RequestID(bridge.operationID)
                _ = try StorageIdentity.SPKISHA256(bridge.signedOpenSHA256)
                _ = try StorageIdentity.SPKISHA256(bridge.snapshotSHA256)
                guard bridge.oldAllocatedEpoch > 0, bridge.oldAllocatedEpoch < UInt64.max,
                      bridge.baseEpoch == bridge.oldAllocatedEpoch + 1,
                      bridge.baseEpoch == store.baseEpoch, bridge.origin == store.origin else {
                    throw BootstrapFailure(.repairRequired)
                }
            } else {
                guard store.baseEpoch == 1 else { throw BootstrapFailure(.repairRequired) }
            }
            // Size is mutable metadata, never part of physical alias identity.
            roots.append(binding.root); disks.append(binding.backing.identity)
            if let abandoned = store.abandoned {
                try abandoned.fence.validate(); try validatePrincipal(abandoned.principal, origin: store.origin)
                let principal = abandoned.principal
                guard abandoned.fence.nativeIdentitySHA256 == Adoption.nativeIdentitySHA256(
                    daemonAudit: principal.daemon.auditToken, daemonUniqueID: principal.daemon.uniqueID,
                    controllerAudit: principal.child.auditToken, controllerUniqueID: principal.child.uniqueID),
                    abandoned.fence.epoch > store.epoch || store.pending == nil else { throw BootstrapFailure(.repairRequired) }
            }
            guard (store.pending ?? store.latest)?.request.superseded == store.abandoned?.fence else {
                throw BootstrapFailure(.repairRequired)
            }
            if let latest = store.latest {
                try validate(latest, origin: store.origin)
                guard try latest.request.epoch == store.epoch, latest.request.expectedEpoch >= store.baseEpoch,
                      latest.principal.daemon == store.daemon,
                      latest.principal.child == store.controller else { throw BootstrapFailure(.repairRequired) }
            } else {
                guard store.epoch == store.baseEpoch, store.daemon == store.origin.originalDaemon,
                      store.controller == store.origin.originalController else { throw BootstrapFailure(.repairRequired) }
            }
            if let pending = store.pending {
                try validate(pending, origin: store.origin)
                guard try pending.request.epoch == store.allocatedEpoch,
                      pending.request.expectedEpoch >= store.epoch,
                      (pending.request.superseded != nil || pending.request.expectedEpoch == store.epoch),
                      pending.request.id != store.latest?.request.id else { throw BootstrapFailure(.repairRequired) }
            } else {
                guard store.allocatedEpoch == store.epoch else { throw BootstrapFailure(.repairRequired) }
            }
        }
    }
    private func validateProcess(_ process: BootstrapProcess) throws {
        guard process.pid > 0, process.uniqueID > 0, process.pidVersion > 0, process.startSeconds > 0,
              process.startMicroseconds < 1_000_000, process.auditToken.count == 32,
              !process.boot.isEmpty, process.boot.utf8.count <= 64,
              !process.signingIdentity.isEmpty, process.signingIdentity.utf8.count <= 256 else {
            throw BootstrapFailure(.repairRequired)
        }
        let audit = BootstrapAuditIdentity(token: process.auditToken.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) })
        guard audit.pid == process.pid, audit.pidVersion == process.pidVersion else { throw BootstrapFailure(.repairRequired) }
    }
    private func validatePrincipal(_ principal: BootstrapPrincipal, origin: StorageLifecycleShimOrigin) throws {
        _ = try StorageIdentity.IncarnationID(principal.incarnation)
        _ = try StorageIdentity.Ed25519SPKI(publicData: principal.controllerSPKI)
        try validateProcess(principal.daemon); try validateProcess(principal.child)
        guard principal.daemon.boot == origin.shim.boot, principal.child.boot == origin.shim.boot,
              principal.daemon.pid != principal.child.pid, principal.daemon.uniqueID != principal.child.uniqueID,
              principal.daemon.pid != origin.shim.pid, principal.child.pid != origin.shim.pid,
              principal.daemon.uniqueID != origin.shim.uniqueID, principal.child.uniqueID != origin.shim.uniqueID else {
            throw BootstrapFailure(.repairRequired)
        }
    }
    private func validate(_ intent: Intent, origin: StorageLifecycleShimOrigin) throws {
        try intent.request.validate()
        try validatePrincipal(intent.principal, origin: origin)
        guard intent.principal.daemon.boot == origin.shim.boot,
              intent.principal.child.boot == origin.shim.boot,
              intent.principal.daemon.uniqueID != origin.shim.uniqueID,
              intent.principal.child.uniqueID != origin.shim.uniqueID,
              intent.request.origin == origin.wire,
              intent.request.daemonAudit == intent.principal.daemon.auditToken,
              intent.request.daemonUniqueID == intent.principal.daemon.uniqueID,
              intent.request.controllerAudit == intent.principal.child.auditToken,
              intent.request.controllerUniqueID == intent.principal.child.uniqueID else { throw BootstrapFailure(.repairRequired) }
    }
}

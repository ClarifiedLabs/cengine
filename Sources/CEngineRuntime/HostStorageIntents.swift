#if os(macOS)
import CEngineCore
import CryptoKit
import Darwin
import Foundation

/// Owner-private write-ahead evidence. Releasing this object's file lease never
/// releases an attachment or PREPARE reservation or authorizes reattachment.
@MainActor final class HostStorageIntents {
    enum Failure: Error { case invalid, missing, locked, stale, blocked, capacity, poisoned, persistence }
    enum Boundary: Sendable { case beforeMarker, afterMarker, afterState, beforeUnmark, afterUnmark }
    typealias Hook = (Boundary) throws -> Void
    static let maximumIntents = 128
    static let maximumVolumes = 256
    static let maximumAttachments = 64
    static let maximumBytes = 1_048_576
    // Reserve enough bytes for every admitted attachment's eventual receipt and
    // every intent's quarantine/completion evidence. Tombstones are never evicted.
    static let completionBytesPerAttachment = 4096
    static let completionBytesPerIntent = 8192

    struct Manifest: Codable, Equatable, Sendable {
        let schema: UInt64
        let mode: String
        let store: String
        let provenanceReference: String
        let root: PersistentFileIdentity
        let directory: PersistentFileIdentity
        let lease: PersistentFileIdentity
    }
    struct Volume: Codable, Equatable, Sendable {
        let id: String
        let name: String
        let createOperation: String
        let deleteOperation: String
        var rootDevice: UInt64?
        var rootInode: UInt64?
        var createdRevision: UInt64?
        var deletedRevision: UInt64?
        var localDeletionRevision: UInt64? = nil
        var isDeleted: Bool { deletedRevision != nil || localDeletionRevision != nil }
    }
    struct Mount: Codable, Equatable, Sendable {
        let volume: String
        let destination: String
        let subpath: String
        let mode: String
    }
    struct Slot: Codable, Equatable, Sendable {
        let volume: String
        let attachment: String
        let role: String
        let mode: String
        let registerOperation: String
        let retireOperation: String
        var key: String?
        var receipt: DrainReceipt?
        func binding(store: String, prepare: String, container: String, launch: String) throws -> ManagedStorageControlProtocol.Binding {
            guard let key, let role = ManagedStorageControlProtocol.Role(rawValue: role),
                  let mode = ManagedStorageControlProtocol.Mode(rawValue: mode) else { throw Failure.invalid }
            return try .init(store: store, volume: volume, attachment: attachment,
                prepare: role == .prepare ? prepare : nil, container: container, launch: launch,
                key: key, role: role, mode: mode)
        }
    }
    struct DrainReceipt: Codable, Equatable, Sendable {
        let store: String
        let volume: String
        let attachment: String
        let prepare: String?
        let launch: String
        let revision: UInt64
        init(_ receipt: ManagedStorageControlProtocol.Receipt) {
            store = receipt.store; volume = receipt.volume; attachment = receipt.attachment
            prepare = receipt.prepare; launch = receipt.launch; revision = receipt.revision
        }
        func wire() throws -> ManagedStorageControlProtocol.Receipt {
            try .init(schema: 3, store: store, volume: volume, attachment: attachment, prepare: prepare, launch: launch, revision: revision)
        }
    }
    /// Returned only by the trusted private guest RPC. Not a storage drain proof.
    struct GuestCompletion: Codable, Equatable, Sendable {
        let prepare: String
        let containerInstance: String
        let launch: String
        let succeeded: Bool
        let cleanCopyUp: Bool
        let evidenceDigest: String
    }
    enum Phase: String, Codable, Sendable {
        case planned, prepareFrozen, prepareAdmitted, prepareSucceeded, prepareDrained
        case prepareCompleted, runtimeFrozen, running, quarantined, retired, replaced, unlaunched, abortedBeforeAdmission
    }
    /// Public historical link, not an authorization capability. Only a sealed
    /// owner recovery can append this link through planReplacement.
    struct ReplacementRecovery: Codable, Equatable, Sendable {
        let serviceEpoch: String
        let controllerEpoch: UInt64
        let controllerKey: String
        let provenanceReference: String
        var workerHistoryReference: String? = nil
    }
    enum LaunchBoundary: String, Codable, Sendable { case planned, attempted, cancelled }
    struct Intent: Codable, Equatable, Sendable {
        let id: String
        let store: String
        let container: String
        let containerInstance: String
        let launch: String
        let specificationDigest: String
        let serviceEpoch: String
        let controllerEpoch: UInt64
        let controllerKey: String
        let prepare: String
        let reserveOperation: String
        let completeOperation: String
        let replaceOperation: String
        let mounts: [Mount]
        var slots: [Slot]
        var version: UInt64
        var phase: Phase
        var prepareCompleted: Bool
        var guestCompletion: GuestCompletion?
        var cleanUnmount: Bool
        var quarantineReason: String?
        var predecessor: String? = nil
        var successor: String? = nil
        var replacementRecovery: ReplacementRecovery? = nil
        // Missing on historical records means unknown, never proof of no launch.
        var launchBoundary: LaunchBoundary? = nil
        var supersededSuccessors: [String]? = nil
        var isPreAdmissionTerminal: Bool { phase == .unlaunched || phase == .abortedBeforeAdmission }
        var isTerminal: Bool { phase == .retired || phase == .replaced || isPreAdmissionTerminal }
    }
    struct State: Codable, Equatable, Sendable {
        let schema: UInt64
        let store: String
        var revision: UInt64
        var volumes: [String: Volume]
        var intents: [String: Intent]
        // Exact canonical requests, including receipt/attestation arguments, are
        // retained even after success. A reused operation ID cannot change bytes.
        var operations: [String: Data]
        var operationDigests: [String: String]
        var reconciliationRequired: Bool
        var reconciliationEvidence: Data?
        // Public audit only; every reopen still requires fresh native/session proof.
        var liveAdoptionEvidence: Data? = nil
    }
    struct Token: Equatable, Sendable { let intent: String; let version: UInt64 }

    let manifest: Manifest
    private let root: PersistentStateDirectory
    private let directory: PersistentStateDirectory
    private var lease: CInt
    private var state: State
    private var poisoned = false
    private let hook: Hook?
    private let commits: HostStorageIntentCommit

    static func initialize(in root: PersistentStateDirectory, store: String, provenanceReference: String,
                           hook: Hook? = nil, commitHook: HostStorageIntentCommit.Hook? = nil) throws -> HostStorageIntents {
        try uuid(store); try digest(provenanceReference)
        let directory = try root.createDirectory(named: "managed-storage")
        let fd = try acquire(in: directory, create: true)
        do {
            let manifest = Manifest(schema: 1, mode: "managed", store: store, provenanceReference: provenanceReference,
                root: root.identity, directory: directory.identity, lease: try PersistentFileIdentity.capture(descriptor: fd))
            let state = State(schema: 2, store: store, revision: 1, volumes: [:], intents: [:],
                operations: [:], operationDigests: [:], reconciliationRequired: true)
            let manifestBytes = try encode(manifest)
            try directory.writeExclusiveRegularFile(named: "manifest.json", data: manifestBytes)
            try directory.writeExclusiveRegularFile(named: "state.json", data: encode(state))
            return HostStorageIntents(root: root, directory: directory, lease: fd, manifest: manifest,
                manifestBytes: manifestBytes, state: state, hook: hook, commitHook: commitHook)
        } catch { Darwin.close(fd); throw error }
    }
    /// Read-only format/physical inspection. Sound retained commit artifacts are
    /// accepted, but only open's later lease-owning recovery may remove them.
    static func inspect(in root: PersistentStateDirectory, store: String, provenanceReference: String) throws -> State {
        try uuid(store); try digest(provenanceReference)
        let directory = try root.openDirectory(named: "managed-storage")
        let manifestBytes = try HostStorageIntentCommit.readPrivateFile(in: directory, named: "manifest.json", maximumBytes: maximumBytes)
        let stateBytes = try HostStorageIntentCommit.readPrivateFile(in: directory, named: "state.json", maximumBytes: maximumBytes)
        let manifest: Manifest = try decode(manifestBytes)
        guard manifest.schema == 1, manifest.mode == "managed", manifest.store == store,
              manifest.provenanceReference == provenanceReference, manifest.root == root.identity,
              manifest.directory == directory.identity,
              manifest.lease == (try directory.regularFileIdentity(named: "lease", expectedSize: 0)) else { throw Failure.invalid }
        let state: State = try decode(stateBytes)
        try validate(state, store: store, provenance: provenanceReference)
        _ = try HostStorageIntentCommit(directory: directory, manifest: manifestBytes).inspect(state: stateBytes, revision: state.revision)
        guard try root.entryMetadata(named: "managed-storage")?.identity == directory.identity else { throw Failure.invalid }
        return state
    }

    static func open(in root: PersistentStateDirectory, store: String, provenanceReference: String,
                     hook: Hook? = nil, commitHook: HostStorageIntentCommit.Hook? = nil) throws -> HostStorageIntents {
        try uuid(store); try digest(provenanceReference)
        guard let directory = try root.openDirectoryIfPresent(named: "managed-storage") else { throw Failure.missing }
        let fd = try acquire(in: directory, create: false)
        var transferred = false
        defer { if !transferred { Darwin.close(fd) } }
        let manifestBytes = try HostStorageIntentCommit.readPrivateFile(in: directory, named: "manifest.json", maximumBytes: maximumBytes)
        let stateBytes = try HostStorageIntentCommit.readPrivateFile(in: directory, named: "state.json", maximumBytes: maximumBytes)
        let manifest: Manifest = try decode(manifestBytes)
        guard manifest.schema == 1, manifest.mode == "managed", manifest.store == store,
              manifest.provenanceReference == provenanceReference, manifest.root == root.identity,
              manifest.directory == directory.identity,
              manifest.lease == (try PersistentFileIdentity.capture(descriptor: fd)) else { throw Failure.invalid }
        let state: State = try decode(stateBytes)
        try validate(state, store: store, provenance: provenanceReference)
        let journal = HostStorageIntents(root: root, directory: directory, lease: fd, manifest: manifest,
            manifestBytes: manifestBytes, state: state, hook: hook, commitHook: commitHook)
        transferred = true // From here only journal.deinit owns the descriptor.
        // Expected store/provenance, physical identities and full state semantics
        // must all succeed before any certified transaction artifact is removed.
        try journal.healthy()
        let recovery = try journal.commits.inspect(state: stateBytes, revision: state.revision)
        try journal.commits.recover(recovery)
        // Every new owner must reconcile the full storage registry before new
        // authority or deletion, even if the last owner shut down cleanly.
        if !state.reconciliationRequired { try journal.commit { $0.reconciliationRequired = true } }
        return journal
    }
    private init(root: PersistentStateDirectory, directory: PersistentStateDirectory, lease: CInt,
                 manifest: Manifest, manifestBytes: Data, state: State, hook: Hook?, commitHook: HostStorageIntentCommit.Hook?) {
        self.root = root; self.directory = directory; self.lease = lease
        self.manifest = manifest; self.state = state; self.hook = hook
        commits = HostStorageIntentCommit(directory: directory, manifest: manifestBytes, hook: commitHook)
    }
    deinit { Darwin.close(lease) }

    func snapshot() throws -> State { try healthy(); return state }

    /// Read-only physical eligibility at lifecycle authority/IO boundaries. A
    /// cached State or an intact lease alone cannot excuse a replaced state file,
    /// changed manifest, unknown artifact or unfinished commit. Recovery remains
    /// the open path's job; never clean or adopt files while publishing a reply.
    func checkedSnapshot() throws -> State {
        try healthy()
        do {
            guard Set(try directory.entryNames()) == [HostStorageIntentCommit.leaseName,
                HostStorageIntentCommit.manifestName, HostStorageIntentCommit.stateName] else { throw Failure.poisoned }
            _ = try commits.inspect(state: Self.encode(state), revision: state.revision)
            return state
        } catch {
            poisoned = true // In-memory fence only; preserve all disk evidence.
            throw error
        }
    }
    func intent(_ token: Token) throws -> Intent {
        try healthy()
        guard let intent = state.intents[token.intent], intent.version == token.version else { throw Failure.stale }
        return intent
    }
    func token(for id: String) throws -> Token {
        try healthy(); guard let intent = state.intents[id] else { throw Failure.missing }
        return Token(intent: id, version: intent.version)
    }
    func planVolumes(_ volumes: [Volume]) throws {
        try healthy()
        guard !state.reconciliationRequired else { throw Failure.blocked }
        try commit { next in
            for volume in volumes {
                guard volume.rootDevice == nil, volume.rootInode == nil, volume.createdRevision == nil,
                      !volume.isDeleted, next.volumes[volume.id] == nil,
                      !next.volumes.values.contains(where: { $0.name == volume.name && !$0.isDeleted }) else { throw Failure.invalid }
                next.volumes[volume.id] = volume
            }
        }
    }
    func plan(_ intent: Intent) throws -> Token {
        try healthy()
        try admit(intent, replacing: nil)
        var planned = intent; planned.launchBoundary = .planned
        try commit { $0.intents[intent.id] = planned }
        return Token(intent: intent.id, version: 1)
    }
    /// Reserve the whole replacement set before offering any successor key.
    /// Historical bindings are immutable. A new context requires the owner's
    /// independently ROOT-confirmed recovery capability, never decoded metadata.
    func planReplacement(predecessor token: Token, successor: Intent,
                         recovery: ManagedStorageControllerRecovery? = nil) throws -> Token {
        let old = try intent(token)
        guard successor.replacementRecovery == nil else { throw Failure.invalid }
        var linked = successor
        if !Self.sameReplacementContext(old, successor) {
            guard let evidence = recovery?.replacementEvidence(from: old, to: successor),
                  evidence.provenanceReference == manifest.provenanceReference else { throw Failure.blocked }
            linked.replacementRecovery = evidence
        }
        let superseded = old.successor.flatMap { state.intents[$0] }
        guard old.successor == nil || (superseded?.isPreAdmissionTerminal == true && state.operations[old.replaceOperation] == nil),
              !old.prepareCompleted, old.phase != .replaced,
              old.version < UInt64.max, Self.drainedPrepare(old),
              old.slots.filter({ $0.role == "runtime" }).allSatisfy({ $0.key == nil }),
              Self.sameReplacementContext(old, linked) else { throw Failure.blocked }
        try admit(successor, replacing: old.id)
        var previous = old
        if let abandoned = old.successor {
            previous.supersededSuccessors = (old.supersededSuccessors ?? []) + [abandoned]
        }
        previous.successor = successor.id; previous.version += 1
        var next = linked; next.predecessor = old.id; next.launchBoundary = .planned
        try commit { $0.intents[old.id] = previous; $0.intents[next.id] = next }
        return Token(intent: next.id, version: next.version)
    }
    /// The caller confirms the exact successful replace reply. Both requests must
    /// already be durable; only the predecessor transitions to a terminal phase.
    func confirmReplacement(predecessor: Token, successor: Token) throws -> Token {
        let old = try intent(predecessor), next = try intent(successor)
        guard old.successor == next.id, next.predecessor == old.id,
              old.phase != .replaced, !old.prepareCompleted, old.version < UInt64.max else { throw Failure.invalid }
        _ = try replayRequest(operation: old.replaceOperation)
        _ = try replayRequest(operation: next.reserveOperation)
        var changed = old; changed.phase = .replaced; changed.version += 1
        try commit { $0.intents[old.id] = changed }
        return Token(intent: old.id, version: changed.version)
    }
    private func admit(_ intent: Intent, replacing predecessor: String?) throws {
        guard !state.reconciliationRequired, intent.phase == .planned, intent.version == 1,
              !intent.prepareCompleted, intent.guestCompletion == nil, !intent.cleanUnmount,
              intent.predecessor == nil, intent.successor == nil, intent.replacementRecovery == nil, intent.quarantineReason == nil, intent.launchBoundary == nil, intent.supersededSuccessors == nil,
              intent.slots.allSatisfy({ $0.key == nil && $0.receipt == nil }), state.intents[intent.id] == nil else { throw Failure.blocked }
        let identifiers = Self.freshIdentifiers(intent)
        guard identifiers.count == 6 + intent.slots.count * 3,
              identifiers.isDisjoint(with: state.volumes.values.flatMap { [$0.id, $0.createOperation, $0.deleteOperation] }),
              state.intents.values.allSatisfy({ identifiers.isDisjoint(with: Self.freshIdentifiers($0)) }) else { throw Failure.blocked }
        let volumes = Set(intent.mounts.map(\.volume))
        guard volumes.allSatisfy({ state.volumes[$0] != nil && state.volumes[$0]?.isDeleted == false }) else { throw Failure.blocked }
        for prior in state.intents.values where prior.id != predecessor && !prior.isTerminal && !(prior.phase == .running && prior.prepareCompleted) {
            guard volumes.isDisjoint(with: prior.mounts.map(\.volume)) else { throw Failure.blocked }
        }
    }
    private static func freshIdentifiers(_ intent: Intent) -> Set<String> {
        Set([intent.id, intent.launch, intent.prepare, intent.reserveOperation, intent.completeOperation, intent.replaceOperation]
            + intent.slots.flatMap { [$0.attachment, $0.registerOperation, $0.retireOperation] })
    }
    private static func sameReplacementContext(_ old: Intent, _ next: Intent) -> Bool {
        let sameIdentity = old.serviceEpoch == next.serviceEpoch && old.controllerEpoch == next.controllerEpoch && old.controllerKey == next.controllerKey
        let transition = next.replacementRecovery
        let rootTurnover = next.controllerEpoch > old.controllerEpoch && next.controllerKey != old.controllerKey
            && transition?.workerHistoryReference == nil
        let workerTurnover = next.controllerEpoch == old.controllerEpoch && next.controllerKey == old.controllerKey
            && next.serviceEpoch != old.serviceEpoch && transition?.workerHistoryReference != nil
        let recoveredIdentity = transition?.serviceEpoch == old.serviceEpoch && transition?.controllerEpoch == old.controllerEpoch
            && transition?.controllerKey == old.controllerKey && (rootTurnover || workerTurnover)
        return old.store == next.store && (sameIdentity ? transition == nil : recoveredIdentity)
            && old.container == next.container && old.containerInstance == next.containerInstance
            && old.specificationDigest == next.specificationDigest && old.mounts == next.mounts && slotScope(old) == slotScope(next)
    }
    private static func slotScope(_ intent: Intent) -> [String] {
        intent.slots.map { "\($0.volume):\($0.role):\($0.mode)" }.sorted()
    }
    private static func drainedPrepare(_ intent: Intent) -> Bool {
        let slots = intent.slots.filter { $0.role == "prepare" }
        return !slots.isEmpty && slots.allSatisfy { $0.key != nil && $0.receipt != nil }
    }
    /// Local CAS protects stale asynchronous replies; global state revisions are
    /// deliberately NOT compared across disjoint volume transactions.
    func update(_ token: Token, _ body: (inout Intent) throws -> Void) throws -> Token {
        try update(token, recordingFrozenKeys: nil, body)
    }
    /// Freeze admission requests in the SAME durable transaction as their keys:
    /// PREPARE's Reserve (and its predecessor's Replace), or every runtime Register.
    /// Recovery can then admit-and-drain keys whose first send was never reached.
    func freezeKeys(_ token: Token, role: ManagedStorageControlProtocol.Role, keys: [String: String]) throws -> Token {
        let old = try intent(token)
        let slots = old.slots.filter { $0.role == role.rawValue }
        guard Set(keys.keys) == Set(slots.map(\.attachment)), keys.count == slots.count,
              Set(keys.values).count == keys.count, slots.allSatisfy({ $0.key == nil }) else { throw Failure.invalid }
        for key in keys.values { try Self.digest(key) }
        return try update(token, recordingFrozenKeys: role) { next in
            for index in next.slots.indices where next.slots[index].role == role.rawValue {
                next.slots[index].key = keys[next.slots[index].attachment]
            }
            next.phase = role == .prepare ? .prepareFrozen : .runtimeFrozen
        }
    }
    private func update(_ token: Token, recordingFrozenKeys role: ManagedStorageControlProtocol.Role?,
                        _ body: (inout Intent) throws -> Void) throws -> Token {
        let old = try intent(token)
        guard old.version < UInt64.max else { throw Failure.capacity }
        var changed = old
        try body(&changed)
        guard changed.id == old.id, changed.store == old.store, changed.container == old.container,
              changed.containerInstance == old.containerInstance, changed.launch == old.launch,
              changed.specificationDigest == old.specificationDigest, changed.serviceEpoch == old.serviceEpoch,
              changed.controllerEpoch == old.controllerEpoch, changed.controllerKey == old.controllerKey, changed.prepare == old.prepare,
              changed.reserveOperation == old.reserveOperation, changed.completeOperation == old.completeOperation,
              changed.replaceOperation == old.replaceOperation, changed.mounts == old.mounts,
              changed.predecessor == old.predecessor, changed.successor == old.successor, changed.replacementRecovery == old.replacementRecovery,
              (changed.phase == .replaced) == (old.phase == .replaced),
              changed.launchBoundary == old.launchBoundary, changed.supersededSuccessors == old.supersededSuccessors,
              changed.slots.count == old.slots.count else { throw Failure.invalid }
        for (before, after) in zip(old.slots, changed.slots) {
            var expected = before; expected.key = after.key; expected.receipt = after.receipt
            guard expected == after, before.key == nil || before.key == after.key,
                  before.receipt == nil || before.receipt == after.receipt else { throw Failure.invalid }
        }
        guard !old.prepareCompleted || changed.prepareCompleted,
              old.guestCompletion == nil || old.guestCompletion == changed.guestCompletion,
              !old.cleanUnmount || changed.cleanUnmount else { throw Failure.invalid }
        changed.version = old.version + 1
        try commit { next in
            next.intents[old.id] = changed
            var operations: [String] = []
            if role == .prepare {
                operations.append(changed.reserveOperation)
                if let predecessor = changed.predecessor {
                    guard let previous = next.intents[predecessor] else { throw Failure.invalid }
                    operations.append(previous.replaceOperation)
                }
            } else if role == .runtime {
                operations = changed.slots.filter { $0.role == "runtime" }.map(\.registerOperation)
            }
            for operation in operations {
                // Reconstruct from the immutable plan and existing durable receipts,
                // never from caller-supplied request bytes or replacement authority.
                let bytes = try Self.request(for: operation, in: next).durableBytes()
                let digest = Self.hash(bytes)
                guard (next.operations[operation] == nil && next.operationDigests[operation] == nil)
                    || (next.operations[operation] == bytes && next.operationDigests[operation] == digest) else { throw Failure.invalid }
                next.operations[operation] = bytes
                next.operationDigests[operation] = digest
            }
        }
        return Token(intent: old.id, version: changed.version)
    }
    /// Committed before the only callback allowed to persist/launch the VM.
    func attemptLaunch(_ token: Token) throws -> Token {
        var next = try intent(token)
        guard next.launchBoundary == .planned, next.slots.allSatisfy({ $0.key == nil }),
              next.version < UInt64.max else { throw Failure.blocked }
        next.launchBoundary = .attempted; next.version += 1
        try commit { $0.intents[next.id] = next }
        return Token(intent: next.id, version: next.version)
    }
    struct NeverLaunched {
        fileprivate let intent: Intent
        fileprivate init(_ intent: Intent) { self.intent = intent }
        func matches(_ expected: Intent) -> Bool { intent == expected }
    }
    /// Cancels launch under the journal lease. Native census is still required
    /// before claiming execution cleanup. An attempted or historical launch blocks.
    func cancelUnlaunched(_ token: Token) throws -> NeverLaunched {
        var next = try intent(token)
        guard next.launchBoundary == .planned || next.launchBoundary == .cancelled,
              Self.hasNoAdmission(next, in: state) else { throw Failure.blocked }
        if next.launchBoundary != .cancelled {
            guard next.version < UInt64.max else { throw Failure.capacity }
            next.launchBoundary = .cancelled; next.version += 1
            try commit { $0.intents[next.id] = next }
        }
        return NeverLaunched(next)
    }
    static func hasNoAdmission(_ intent: Intent, in state: State) -> Bool {
        intent.successor == nil && intent.slots.allSatisfy { $0.key == nil && $0.receipt == nil }
            && state.operations[intent.reserveOperation] == nil && state.operations[intent.completeOperation] == nil
            && state.operations[intent.replaceOperation] == nil
            && intent.slots.allSatisfy { state.operations[$0.registerOperation] == nil && state.operations[$0.retireOperation] == nil }
            && !intent.prepareCompleted && intent.guestCompletion == nil && !intent.cleanUnmount
            && intent.predecessor.map { oldID in
                guard let old = state.intents[oldID] else { return false }
                return old.successor == intent.id ? state.operations[old.replaceOperation] == nil
                    : (old.supersededSuccessors ?? []).contains(intent.id)
            } != false
    }
    /// Only sealed native-containment + complete-registry evidence can close this
    /// fence. A launched-but-keyless VM is not mislabeled as never launched.
    func confirmNoAdmission(_ evidence: ManagedVolumeLifecycleCoordinator.NoAdmission) throws -> Token {
        let token = try token(for: evidence.intentID)
        let old = try intent(token)
        guard evidence.matches(old), Self.hasNoAdmission(old, in: state),
              old.launchBoundary == .cancelled || old.launchBoundary == .attempted else { throw Failure.blocked }
        if old.isPreAdmissionTerminal { return token }
        return try update(token) { $0.phase = old.launchBoundary == .cancelled ? .unlaunched : .abortedBeforeAdmission }
    }
    func quarantine(_ token: Token, reason: String) throws -> Token {
        try update(token) { $0.phase = .quarantined; $0.quarantineReason = String(reason.prefix(256)) }
    }
    func recordOperation(id: String, request: ManagedStorageControlProtocol.ControlRequest) throws {
        try healthy(); try Self.uuid(id)
        let bytes = try request.durableBytes()
        guard !bytes.isEmpty, bytes.count <= ManagedStorageControlProtocol.maximumPayloadBytes,
              bytes == (try Self.request(for: id, in: state).durableBytes()) else { throw Failure.invalid }
        let digest = Self.hash(bytes)
        if let previous = state.operations[id] {
            guard previous == bytes, state.operationDigests[id] == digest else { throw Failure.invalid }
            try healthy(); return
        }
        try commit { $0.operations[id] = bytes; $0.operationDigests[id] = digest }
    }
    func request(for operation: String) throws -> ManagedStorageControlProtocol.ControlRequest {
        try healthy()
        return try Self.request(for: operation, in: state)
    }
    func replayRequest(operation: String) throws -> ManagedStorageControlProtocol.ControlRequest {
        let request = try request(for: operation)
        guard let bytes = state.operations[operation], state.operationDigests[operation] == Self.hash(bytes),
              bytes == (try request.durableBytes()) else { throw Failure.invalid }
        return request
    }
    private static func reserve(_ intent: Intent) throws -> ManagedStorageControlProtocol.ReserveRequest {
        let slots = intent.slots.filter { $0.role == "prepare" }.sorted { $0.volume < $1.volume }
        guard !slots.isEmpty else { throw Failure.invalid }
        return try .init(operation: intent.reserveOperation, prepare: intent.prepare, attachments: slots.map {
            try $0.binding(store: intent.store, prepare: intent.prepare, container: intent.container, launch: intent.launch)
        })
    }
    private static func receipts(_ intent: Intent) throws -> [ManagedStorageControlProtocol.Receipt] {
        guard drainedPrepare(intent) else { throw Failure.blocked }
        return try intent.slots.filter { $0.role == "prepare" }.sorted { $0.attachment < $1.attachment }.map {
            guard let receipt = $0.receipt else { throw Failure.invalid }
            return try receipt.wire()
        }
    }
    /// Reconstruction, not decoding: durable bytes cannot introduce authority that
    /// is absent from the immutable plan and its monotonically retained evidence.
    private static func request(for operation: String, in state: State) throws -> ManagedStorageControlProtocol.ControlRequest {
        try uuid(operation)
        for volume in state.volumes.values {
            if operation == volume.createOperation {
                return .createVolume(try .init(operation: operation, store: state.store, volume: volume.id, name: volume.name))
            }
            if operation == volume.deleteOperation {
                return .deleteVolume(try .init(operation: operation, store: state.store, volume: volume.id))
            }
        }
        for intent in state.intents.values {
            if operation == intent.reserveOperation { return .reservePrepare(try reserve(intent)) }
            if operation == intent.completeOperation {
                guard let completion = intent.guestCompletion,
                      completion.succeeded, completion.cleanCopyUp, intent.cleanUnmount else { throw Failure.blocked }
                return .completePrepare(try .init(operation: operation, prepare: intent.prepare, receipts: receipts(intent),
                    attestation: .init(prepare: completion.prepare, succeeded: completion.succeeded, cleanCopyUp: completion.cleanCopyUp)))
            }
            if operation == intent.replaceOperation {
                guard let id = intent.successor, let next = state.intents[id], next.predecessor == intent.id,
                      !intent.prepareCompleted, sameReplacementContext(intent, next) else { throw Failure.blocked }
                return .replacePrepare(try .init(operation: operation, prepare: intent.prepare,
                    receipts: receipts(intent), successor: reserve(next)))
            }
            for slot in intent.slots {
                if operation == slot.registerOperation {
                    return .registerAttachment(try .init(operation: operation,
                        binding: slot.binding(store: intent.store, prepare: intent.prepare, container: intent.container, launch: intent.launch)))
                }
                if operation == slot.retireOperation {
                    guard slot.key != nil else { throw Failure.blocked }
                    return .retire(try .init(operation: operation, store: intent.store, volume: slot.volume,
                        attachment: slot.attachment, launch: intent.launch))
                }
            }
        }
        throw Failure.missing
    }
    func recordVolume(_ volume: Volume) throws {
        guard let old = state.volumes[volume.id], old.id == volume.id, old.name == volume.name,
              old.createOperation == volume.createOperation, old.deleteOperation == volume.deleteOperation,
              old.rootDevice == nil || old.rootDevice == volume.rootDevice,
              old.rootInode == nil || old.rootInode == volume.rootInode,
              old.createdRevision == nil || old.createdRevision == volume.createdRevision,
              old.localDeletionRevision == volume.localDeletionRevision,
              old.deletedRevision == nil || old.deletedRevision == volume.deletedRevision else { throw Failure.invalid }
        try commit { $0.volumes[volume.id] = volume }
    }
    /// This is not a storage receipt. No intent or durable control request may
    /// ever have referred to V, so there is no remote authority to abandon.
    func deleteUncreatedVolume(_ id: String) throws -> Volume {
        try healthy()
        guard var volume = state.volumes[id], volume.createdRevision == nil, volume.deletedRevision == nil,
              state.operations[volume.createOperation] == nil, state.operations[volume.deleteOperation] == nil,
              !state.intents.values.contains(where: { $0.mounts.contains { $0.volume == id } }) else { throw Failure.blocked }
        if volume.localDeletionRevision != nil { return volume }
        guard !state.reconciliationRequired else { throw Failure.blocked }
        guard state.revision < UInt64.max else { throw Failure.capacity }
        volume.localDeletionRevision = state.revision + 1
        try commit { $0.volumes[id] = volume }
        return volume
    }
    func requireReconciliation() throws { try commit { $0.reconciliationRequired = true } }
    /// Only the coordinator calls this after validating the complete query union.
    func reconciled() throws { try commit { $0.reconciliationRequired = false; $0.reconciliationEvidence = nil } }
    func recordLiveAdoptionEvidence(_ evidence: Data) throws {
        guard !state.reconciliationRequired, !evidence.isEmpty, evidence.count <= Self.maximumBytes / 16 else { throw Failure.blocked }
        do { try commit { $0.liveAdoptionEvidence = evidence } }
        catch Failure.capacity {
            // Optional audit must not consume capacity already promised to older
            // admissions. Keep the previous record unchanged. A capacity error
            // from any persistence hook poisons the journal and MUST propagate.
            try healthy()
        }
    }
    func retainReconciliationFence(_ evidence: Data) throws {
        guard evidence.count <= Self.maximumBytes / 4 else {
            try requireReconciliation(); throw Failure.capacity
        }
        try commit { $0.reconciliationRequired = true; $0.reconciliationEvidence = evidence }
    }
    func canDelete(volume: String) -> Bool {
        guard !poisoned, !state.reconciliationRequired, let known = state.volumes[volume],
              known.createdRevision != nil, !known.isDeleted else { return false }
        return !state.intents.values.contains { intent in
            !intent.isTerminal && intent.mounts.contains { $0.volume == volume }
        }
    }
    func canChangeMode(volume: String) -> Bool { false } // Storage mode cannot be changed in place.

    private func healthy() throws {
        guard !poisoned, root.pathStillNamesThisDirectory(), directory.pathStillNamesThisDirectory(),
              manifest.lease == (try directory.regularFileIdentity(named: "lease", expectedSize: 0)) else { throw Failure.poisoned }
    }
    private func commit(_ mutate: (inout State) throws -> Void) throws {
        try healthy()
        guard state.revision < UInt64.max else { throw Failure.capacity }
        var next = state; try mutate(&next); next.revision += 1
        try Self.validate(next, store: manifest.store, provenance: manifest.provenanceReference)
        let bytes = try Self.encode(next)
        // Admission reserves the final worst-case footprint, not current bytes
        // plus a constant. Saving a receipt therefore cannot consume its own
        // reserved capacity twice or steal a disjoint intent's completion space.
        let encodedReconciliationReservation = ((Self.maximumBytes / 4 + 2) / 3) * 4 + 512
        var projected = encodedReconciliationReservation + 8192 + next.volumes.count * 4096
            + ((next.liveAdoptionEvidence?.count ?? 0) + 2) / 3 * 4
        for intent in next.intents.values {
            var planned = intent
            planned.version = 1; planned.phase = .planned; planned.prepareCompleted = false
            planned.guestCompletion = nil; planned.cleanUnmount = false; planned.quarantineReason = nil
            for index in planned.slots.indices { planned.slots[index].key = nil; planned.slots[index].receipt = nil }
            projected += try Self.encode(planned).count + Self.completionBytesPerIntent + planned.slots.count * Self.completionBytesPerAttachment
        }
        guard projected <= Self.maximumBytes else { throw Failure.capacity }
        let prior = try Self.encode(state)
        var persistenceStarted = false
        do {
            try commits.commit(prior: prior, priorRevision: state.revision, next: bytes, nextRevision: next.revision) { [self] boundary in
                try hook?(boundary)
                // A beforeMarker hook failure precedes every persistence attempt.
                // Later returned errors remain sticky even after proof retirement.
                if case .beforeMarker = boundary { persistenceStarted = true }
            }
            state = next
        } catch {
            poisoned = true
            if persistenceStarted { commits.poison() }
            throw error
        }
    }
    private static func acquire(in directory: PersistentStateDirectory, create: Bool) throws -> CInt {
        var info = stat()
        guard fstat(directory.descriptor, &info) == 0, info.st_uid == geteuid(), info.st_mode & 0o077 == 0 else { throw Failure.invalid }
        let fd = openat(directory.descriptor, "lease", O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | (create ? O_CREAT | O_EXCL : 0), 0o600)
        guard fd >= 0 else { throw Failure.missing }
        do {
            guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_size == 0,
                  info.st_nlink == 1, info.st_uid == geteuid(), info.st_mode & 0o077 == 0 else { throw Failure.invalid }
            guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw Failure.locked }
            if create { guard fsync(fd) == 0 else { throw Failure.persistence }; try directory.synchronize() }
            return fd
        } catch { Darwin.close(fd); throw error }
    }
    private static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(value)
        guard data.count <= maximumBytes else { throw Failure.capacity }
        return data
    }
    private static func decode<T: Codable>(_ data: Data) throws -> T {
        guard !data.isEmpty, data.count <= maximumBytes else { throw Failure.invalid }
        let value = try JSONDecoder().decode(T.self, from: data)
        guard try encode(value) == data else { throw Failure.invalid }
        return value
    }
    nonisolated static func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    static func uuid(_ value: String) throws { _ = try StorageIdentity.RequestID(value) }
    static func digest(_ value: String) throws { _ = try StorageIdentity.SPKISHA256(value) }
    private static func validate(_ state: State, store: String, provenance: String) throws {
        guard state.schema == 2, state.store == store, state.revision > 0,
              state.volumes.count <= maximumVolumes, state.intents.count <= maximumIntents,
              (state.liveAdoptionEvidence?.count ?? 0) <= maximumBytes / 16,
              state.operations.count <= 8192, Set(state.operations.keys) == Set(state.operationDigests.keys) else { throw Failure.invalid }
        var names = Set<String>(), attachments = Set<String>(), prepares = Set<String>(), operationIDs = Set<String>(), keys = Set<String>()
        var identifiers = Set(state.volumes.values.flatMap { [$0.id, $0.createOperation, $0.deleteOperation] })
        func operation(_ id: String) throws { try uuid(id); guard operationIDs.insert(id).inserted else { throw Failure.invalid } }
        for (id, volume) in state.volumes {
            try uuid(id); guard id == volume.id, !volume.name.isEmpty, volume.name.utf8.count <= 255,
                  volume.name.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [45,46,95].contains($0) }),
                  (volume.isDeleted || names.insert(volume.name).inserted), (volume.rootDevice == nil) == (volume.rootInode == nil),
                  (volume.createdRevision == nil) == (volume.rootInode == nil),
                  volume.rootInode == nil || volume.rootInode! > 0,
                  volume.createdRevision == nil || volume.createdRevision! > 0,
                  volume.deletedRevision == nil || (volume.createdRevision != nil && volume.deletedRevision! >= volume.createdRevision!) else { throw Failure.invalid }
            if let revision = volume.localDeletionRevision {
                guard revision > 0, revision <= state.revision, volume.createdRevision == nil, volume.deletedRevision == nil,
                      state.operations[volume.createOperation] == nil, state.operations[volume.deleteOperation] == nil,
                      !state.intents.values.contains(where: { $0.mounts.contains { $0.volume == id } }) else { throw Failure.invalid }
            }
            try operation(volume.createOperation); try operation(volume.deleteOperation)
        }
        for (id, intent) in state.intents {
            try uuid(id); try uuid(intent.containerInstance); try uuid(intent.launch); try uuid(intent.prepare)
            try digest(intent.container); try digest(intent.specificationDigest)
            try uuid(intent.serviceEpoch); try digest(intent.controllerKey)
            let fresh = freshIdentifiers(intent)
            guard intent.controllerEpoch > 0, fresh.count == 6 + intent.slots.count * 3,
                  identifiers.isDisjoint(with: fresh) else { throw Failure.invalid }
            identifiers.formUnion(fresh)
            guard id == intent.id, intent.store == store, intent.version > 0, prepares.insert(intent.prepare).inserted,
                  !intent.mounts.isEmpty, intent.mounts.count <= maximumAttachments, intent.slots.count <= maximumAttachments,
                  intent.quarantineReason == nil || intent.quarantineReason!.utf8.count <= 1024 else { throw Failure.invalid }
            try operation(intent.reserveOperation); try operation(intent.completeOperation); try operation(intent.replaceOperation)
            let volumes = Set(intent.mounts.map(\.volume))
            for mount in intent.mounts {
                guard state.volumes[mount.volume] != nil, ["read-only", "read-write"].contains(mount.mode),
                      mount.destination.hasPrefix("/"), mount.destination.utf8.count <= 4096,
                      !mount.destination.contains("\0"), mount.subpath.utf8.count <= 4096,
                      !mount.subpath.hasPrefix("/"), !mount.subpath.split(separator: "/").contains(".."), !mount.subpath.contains("\0") else { throw Failure.invalid }
            }
            let prepareSlots = intent.slots.filter { $0.role == "prepare" }
            let runtimeSlots = intent.slots.filter { $0.role == "runtime" }
            let runtimeScope = Set(intent.mounts.map { $0.volume + ":" + $0.mode })
            guard prepareSlots.count == volumes.count, Set(prepareSlots.map(\.volume)) == volumes,
                  runtimeSlots.count == runtimeScope.count,
                  Set(runtimeSlots.map { $0.volume + ":" + $0.mode }) == runtimeScope else { throw Failure.invalid }
            for slot in intent.slots {
                try uuid(slot.attachment); try operation(slot.registerOperation); try operation(slot.retireOperation)
                guard attachments.insert(slot.attachment).inserted, volumes.contains(slot.volume),
                      ["prepare", "runtime"].contains(slot.role), ["read-only", "read-write"].contains(slot.mode) else { throw Failure.invalid }
                if let key = slot.key {
                    try digest(key)
                    guard key != intent.controllerKey, keys.insert(key).inserted else { throw Failure.invalid }
                }
                if let receipt = slot.receipt {
                    guard slot.key != nil, receipt.store == store, receipt.volume == slot.volume,
                          receipt.attachment == slot.attachment, receipt.launch == intent.launch,
                          receipt.prepare == (slot.role == "prepare" ? intent.prepare : nil),
                          receipt.revision > 0 else { throw Failure.invalid }
                }
            }
            if let completion = intent.guestCompletion {
                try digest(completion.evidenceDigest)
                guard completion.prepare == intent.prepare, completion.containerInstance == intent.containerInstance,
                      completion.launch == intent.launch, completion.succeeded, completion.cleanCopyUp else { throw Failure.invalid }
            }
            if intent.prepareCompleted {
                guard intent.guestCompletion != nil, intent.cleanUnmount,
                      prepareSlots.allSatisfy({ $0.receipt != nil }) else { throw Failure.invalid }
            }
            if intent.launchBoundary == .cancelled || intent.isPreAdmissionTerminal {
                guard hasNoAdmission(intent, in: state),
                      intent.phase != .unlaunched || intent.launchBoundary == .cancelled,
                      intent.phase != .abortedBeforeAdmission || intent.launchBoundary == .attempted else { throw Failure.invalid }
            }
            if intent.phase == .retired {
                guard intent.prepareCompleted, intent.slots.allSatisfy({ $0.key == nil || $0.receipt != nil }) else { throw Failure.invalid }
            }
            if let recovery = intent.replacementRecovery {
                try uuid(recovery.serviceEpoch); try digest(recovery.controllerKey); try digest(recovery.provenanceReference)
                if let reference = recovery.workerHistoryReference { try digest(reference) }
                guard intent.predecessor != nil, recovery.controllerEpoch > 0, recovery.provenanceReference == provenance else { throw Failure.invalid }
            }
            if let predecessor = intent.predecessor {
                try uuid(predecessor)
                guard let old = state.intents[predecessor],
                      old.successor == id || ((old.supersededSuccessors ?? []).contains(id) && intent.isPreAdmissionTerminal),
                      sameReplacementContext(old, intent) else { throw Failure.invalid }
            }
            if let successor = intent.successor {
                try uuid(successor)
                guard let next = state.intents[successor], next.predecessor == id,
                      intent.version > 1, sameReplacementContext(intent, next), !intent.prepareCompleted,
                      drainedPrepare(intent), intent.slots.filter({ $0.role == "runtime" }).allSatisfy({ $0.key == nil }) else { throw Failure.invalid }
            }
            if let superseded = intent.supersededSuccessors {
                guard !superseded.isEmpty, superseded.count <= maximumIntents,
                      Set(superseded).count == superseded.count, !superseded.contains(id),
                      intent.successor.map({ !superseded.contains($0) }) != false else { throw Failure.invalid }
                for child in superseded {
                    guard let next = state.intents[child], next.predecessor == id,
                          next.isPreAdmissionTerminal, sameReplacementContext(intent, next) else { throw Failure.invalid }
                }
            }
            var visited: Set<String> = [id], ancestor = intent.predecessor
            while let previous = ancestor {
                guard visited.insert(previous).inserted, let old = state.intents[previous] else { throw Failure.invalid }
                ancestor = old.predecessor
            }
            if intent.phase == .replaced {
                guard let successor = intent.successor, let next = state.intents[successor],
                      state.operations[intent.replaceOperation] != nil, state.operations[next.reserveOperation] != nil else { throw Failure.invalid }
            }
        }
        for (id, bytes) in state.operations {
            try uuid(id)
            guard operationIDs.contains(id), !bytes.isEmpty, bytes.count <= ManagedStorageControlProtocol.maximumPayloadBytes,
                  state.operationDigests[id] == hash(bytes),
                  bytes == (try request(for: id, in: state).durableBytes()) else { throw Failure.invalid }
        }
    }
}
#endif

import CEngineCore
import Darwin
import Foundation

/// Private compatibility marker, not an API or an alternate storage owner.
/// The caller keeps CanonicalDataStoreLock alive until runtime shutdown and join.
public actor ManagedStorageReplacementTrigger {
    private let root: URL
    private let runtime: EngineRuntime
    private var polling: Task<Void, Never>?
    private var pending: Task<Void, Never>?
    private var stopped = false

    private init(root: URL, runtime: EngineRuntime) {
        self.root = root; self.runtime = runtime
    }

    /// No injectable identity, operation closure, path selector or environment gate.
    public static func start(storeLock: CanonicalDataStoreLock,
                             runtime: EngineRuntime) throws -> ManagedStorageReplacementTrigger? {
        guard try permitsActivation() else { return nil }
        let trigger = ManagedStorageReplacementTrigger(root: storeLock.root, runtime: runtime)
        Task { await trigger.begin() }
        return trigger
    }

    static func permitsActivation() throws -> Bool {
        let policy = try StorageLifecycleNativePolicy.current(role: .engine)
        guard policy.namespace == .compatibility, !policy.isQualification else { return false }
        _ = try SignedCompatibilityIdentity.current(role: .engine)
        return true
    }

    private func begin() {
        guard !stopped, polling == nil else { return }
        polling = Task { await self.run() }
    }

    /// Stops new claims, not the retained replacement. Cancellation is not drain.
    /// Call runtime.shutdown() BEFORE join(), so owned VM containment can progress.
    public func stop() { stopped = true; polling?.cancel() }
    public func join() async { await polling?.value; await pending?.value }

    private func run() async {
        do {
            // Actor executor, never MainActor: all bounded filesystem work stays here.
            let queue = try ManagedStorageReplacementQueue(root: root)
            while !stopped {
                if let claim = try queue.claim() {
                    let task = Task { await self.replace(claim, queue: queue) }
                    pending = task
                    await task.value
                    pending = nil
                }
                if !stopped { try await Task.sleep(for: .milliseconds(200)) }
            }
        } catch {
            // Fail closed. Unsafe/capacity/I/O failures leave all artifacts in place.
            stopped = true
        }
    }

    private func replace(_ claim: ManagedStorageReplacementQueue.Claim,
                         queue: ManagedStorageReplacementQueue) async {
        do {
            let observation = try queue.ownerObservation()
            let proof = try await Self.validateOwner(observation, request: claim.request)
            guard !stopped else { throw ManagedStorageReplacementQueue.Failure.stopped }
            try queue.validateClaim(claim)
            try queue.publish(claim, phase: .pending, proof: proof)
            // Only this production API may fence, contain and replace. Public disk
            // evidence above is rejection-only; Engine/owner's sealed E is authority.
            let result = try await runtime.replaceManagedStorageService(
                operationUUID: claim.request.operationUUID, predecessor: claim.request.predecessor)
            guard result.request.operationUUID == claim.request.operationUUID,
                  result.request.predecessor == claim.request.predecessor else {
                throw ManagedStorageReplacementQueue.Failure.changed
            }
            try queue.publish(claim, phase: .succeeded, proof: proof, result: result)
        } catch {
            // Never serialize arbitrary error text (paths/keys/transport data).
            let underlying = OriginalConsumerFailureDiagnostic.underlying(error)
            try? queue.publish(claim, phase: .failed, code: "replacement-failed",
                               adoptionStage: underlying is ManagedStorageChildRebindDiagnostic ? .childRebind : underlying as? ManagedStorageWorkerAdoptionFailure,
                               childRebindDiagnostic: underlying as? ManagedStorageChildRebindDiagnostic,
                               originalConsumerDiagnostic: OriginalConsumerFailureDiagnostic.find(in: error))
        }
    }

    /// Pure rejection seam: a returned receipt proof is never replacement authority.
    @MainActor static func validateOwner(_ observation: ManagedStorageReplacementQueue.OwnerObservation,
        request: ManagedStorageReplacementQueue.Request) throws -> ManagedStorageReplacementQueue.Proof {
        _ = try ManagedStorageReplacementQueue.Request.decode(request.canonicalData)
        typealias Checkpoint = ManagedStorageLifecycleCheckpoint
        let state = try Checkpoint.decode(observation.data)
        guard let manifestData = observation.manifestData, let intentsData = observation.intentsData,
              let intentsManifestData = observation.intentsManifestData,
              let rootIdentity = observation.rootIdentity, let ownerIdentity = observation.ownerIdentity else {
            throw ManagedStorageReplacementQueue.Failure.changed
        }
        let manifest = try JSONDecoder().decode(Checkpoint.Manifest.self, from: manifestData)
        let intents = try JSONDecoder().decode(HostStorageIntents.State.self, from: intentsData)
        let intentsManifest = try JSONDecoder().decode(HostStorageIntents.Manifest.self, from: intentsManifestData)
        guard try Checkpoint.encode(manifest) == manifestData,
              try Checkpoint.encode(intents) == intentsData,
              try Checkpoint.encode(intentsManifest) == intentsManifestData,
              intentsManifest.schema == 1, intentsManifest.mode == "managed",
              intentsManifest.store == state.identity.store, intentsManifest.provenanceReference == state.provenanceReference,
              intentsManifest.root == observation.rootIdentity, intentsManifest.directory == observation.intentsIdentity,
              intentsManifest.lease == observation.intentsLeaseIdentity,
              manifest.version == Checkpoint.manifestVersion, manifest.identity == state.identity,
              manifest.rootPublicKey == state.rootPublicKey, manifest.provenanceReference == state.provenanceReference,
              manifest.root.volumeUUID != nil, manifest.directory.volumeUUID != nil, manifest.lease.volumeUUID != nil,
              rootIdentity.device == observation.rootDevice, rootIdentity.inode == observation.rootInode,
              ownerIdentity.device == observation.ownerDevice, ownerIdentity.inode == observation.ownerInode,
              manifest.lease == observation.leaseIdentity,
              manifest.root == observation.rootIdentity, manifest.directory == observation.ownerIdentity,
              !intents.reconciliationRequired,
              state.pending == nil, state.pendingTakeover == nil, state.pendingService == nil,
              state.pendingCold == nil, state.sealed == nil, state.terminal == nil,
              state.latestServiceRequest?.request.operationID != request.operationUUID,
              !state.serviceLinks.contains(where: { $0.operationID == request.operationUUID }),
              let service = state.currentService, let context = state.currentContext,
              let observedWorker = state.observedWorker, observedWorker.context == context,
              observedWorker.context.serviceEpoch == service.boot.serviceEpoch,
              request.store == state.identity.store, request.predecessor.serviceEpoch == service.boot.serviceEpoch,
              request.predecessor.workerUUID == observedWorker.workerUUID else {
            throw ManagedStorageReplacementQueue.Failure.changed
        }
        // Workload journal commits can advance between owner checkpoints. Validate
        // the complete fresh census with the existing pure transition: it rejects
        // rewinds and unknown/malformed reference contexts without writing files
        // or supplying authority. Keep all operation fences above on the original
        // checkpoint, before projection can fold any historical service links.
        _ = try Checkpoint.applying(.recordService(service), to: state, intents: intents)
        // observedWorker is rejection-only public metadata, not protected BootTrust.
        // Even matching/copyable metadata cannot authorize replacement: EngineRuntime
        // -> sealed owner's validateServiceReplacement independently compares the
        // complete (E, worker) pair to its held actual native boot before fencing.
        return .init(controllerEpoch: context.controllerEpoch, controllerKey: context.controllerKey,
                     rootPublicKey: state.rootPublicKey.base64EncodedString())
    }
}

/// Authority-free parser/FD queue. Tests may use this, but cannot create a watcher
/// or install an operation closure. Immutable artifacts are evidence, never authority.
final class ManagedStorageReplacementQueue {
    static let directoryName = "managed-storage-replacement"
    static let maximumRequests = 16
    static let maximumRequestBytes = 512
    // Mirrors the v2 checkpoint bound without moving filesystem IO to MainActor.
    static let maximumLifecycleOwnerBytes = 1_048_576
    enum Failure: Error { case unsafe, invalid, changed, full, io, stopped }
    enum Phase: String, Codable { case pending, succeeded, failed }

    struct Request: Codable, Equatable, Sendable {
        let operationUUID: String
        let store: String
        let predecessor: StorageServiceTypes.Scope

        var canonicalData: Data {
            Data("{\"operationUUID\":\"\(operationUUID)\",\"store\":\"\(store)\",\"predecessor\":{\"serviceEpoch\":\"\(predecessor.serviceEpoch)\",\"workerUUID\":\"\(predecessor.workerUUID)\"}}".utf8)
        }
        static func decode(_ data: Data) throws -> Self {
            guard data.count <= maximumRequestBytes else { throw Failure.invalid }
            let value = try JSONDecoder().decode(Self.self, from: data)
            guard [value.operationUUID, value.store, value.predecessor.serviceEpoch, value.predecessor.workerUUID]
                .allSatisfy(StorageServiceTypes.validID),
                  value.canonicalData == data else { throw Failure.invalid }
            return value
        }
    }

    struct Proof: Codable, Sendable {
        let controllerEpoch: UInt64
        let controllerKey: String
        let rootPublicKey: String
    }
    struct OwnerObservation: Sendable {
        let data: Data
        let rootDevice: UInt64
        let rootInode: UInt64
        let ownerDevice: UInt64
        let ownerInode: UInt64
        var manifestData: Data? = nil
        var intentsData: Data? = nil
        var leaseIdentity: PersistentFileIdentity? = nil
        var rootIdentity: PersistentFileIdentity? = nil
        var ownerIdentity: PersistentFileIdentity? = nil
        var intentsManifestData: Data? = nil
        var intentsIdentity: PersistentFileIdentity? = nil
        var intentsLeaseIdentity: PersistentFileIdentity? = nil
    }
    struct Claim: Sendable {
        let request: Request
        let counter: Int
        let data: Data
        let device: Int32
        let inode: UInt64
    }
    /// Public diagnostic schema v1. A succeeded receipt is NOT native drain proof.
    /// The fixture must independently inspect native lifetimes and owner history.
    struct Receipt: Codable {
        let schema: Int
        let counter: Int
        let phase: Phase
        let request: Request?
        let ownerRequest: StorageServiceTypes.ReplacementRequest?
        let successor: StorageServiceTypes.Scope?
        let containedContainerIDs: [String]?
        let proof: Proof?
        let code: String?
        let adoptionStage: ManagedStorageWorkerAdoptionFailure?
        var childRebindDiagnostic: ManagedStorageChildRebindDiagnostic? = nil
        var originalConsumerDiagnostic: OriginalConsumerFailureDiagnostic? = nil
    }

    private let root: URL
    private let rootFD: Int32
    private let directoryFD: Int32

    init(root: URL) throws {
        self.root = root
        rootFD = try Self.openRoot(root)
        do {
            if mkdirat(rootFD, Self.directoryName, 0o700) != 0, errno != EEXIST { throw Failure.io }
            let directory = try Self.openDirectory(rootFD, Self.directoryName)
            // The claim's directory entry must survive a crash too, not just its
            // contents. Never accept a marker until the parent is synchronized.
            guard fsync(rootFD) == 0 else { close(directory); throw Failure.io }
            directoryFD = directory
        } catch { close(rootFD); throw error }
    }
    deinit { close(directoryFD); close(rootFD) }

    static func validateSelection(_ request: Request, store: String, scope: StorageServiceTypes.Scope) throws {
        guard request.store == store, request.predecessor == scope else { throw Failure.changed }
    }

    func claim() throws -> Claim? {
        try validateDirectories()
        let names = try entryNames()
        var named = stat()
        if fstatat(directoryFD, "request.json", &named, AT_SYMLINK_NOFOLLOW) != 0 {
            guard errno == ENOENT else { throw Failure.io }; return nil
        }
        let count = names.filter { $0.hasSuffix(".request.json") }.count
        guard count < Self.maximumRequests else { throw Failure.full }
        let fd = openat(directoryFD, "request.json", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw Failure.unsafe }
        defer { close(fd) }
        let held = try Self.validateFile(fd, directory: directoryFD, name: "request.json")
        let data = try Self.read(fd, maximum: Self.maximumRequestBytes)
        let request = try? Request.decode(data)
        let name = request.map { "\($0.operationUUID).request.json" } ?? "rejected-\(UUID().uuidString.lowercased()).request.json"
        try Self.validateFile(fd, directory: directoryFD, name: "request.json")
        try validateDirectories()
        // EXCL is essential: a claimed UUID survives watcher AND daemon restart.
        if renameatx_np(directoryFD, "request.json", directoryFD, name, UInt32(RENAME_EXCL)) != 0 {
            guard errno == EEXIST else { throw Failure.io }
            let rejected = "rejected-\(UUID().uuidString.lowercased())"
            try preserveRejected(fd: fd, name: rejected, request: request, counter: count + 1, code: "operation-already-claimed")
            return nil
        }
        try Self.validateFile(fd, directory: directoryFD, name: name)
        guard try Self.read(fd, maximum: Self.maximumRequestBytes) == data, fsync(fd) == 0,
              fsync(directoryFD) == 0 else { throw Failure.changed }
        guard let request else {
            try writeReceipt(name: String(name.dropLast(".request.json".count)) + ".failed.json",
                receipt: .init(schema: 1, counter: count + 1, phase: .failed, request: nil, ownerRequest: nil,
                               successor: nil, containedContainerIDs: nil, proof: nil, code: "invalid-request", adoptionStage: nil))
            return nil
        }
        return Claim(request: request, counter: count + 1, data: data, device: held.st_dev, inode: held.st_ino)
    }

    private func preserveRejected(fd: Int32, name: String, request: Request?, counter: Int, code: String) throws {
        try Self.validateFile(fd, directory: directoryFD, name: "request.json")
        guard renameatx_np(directoryFD, "request.json", directoryFD, name + ".request.json", UInt32(RENAME_EXCL)) == 0 else { throw Failure.io }
        try Self.validateFile(fd, directory: directoryFD, name: name + ".request.json")
        guard fsync(fd) == 0, fsync(directoryFD) == 0 else { throw Failure.io }
        try writeReceipt(name: name + ".failed.json", receipt: .init(schema: 1, counter: counter, phase: .failed,
            request: request, ownerRequest: nil, successor: nil, containedContainerIDs: nil, proof: nil, code: code, adoptionStage: nil))
    }

    func validateClaim(_ claim: Claim) throws {
        try validateDirectories()
        let name = claim.request.operationUUID + ".request.json"
        let fd = openat(directoryFD, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw Failure.unsafe }; defer { close(fd) }
        let held = try Self.validateFile(fd, directory: directoryFD, name: name)
        guard held.st_dev == claim.device, held.st_ino == claim.inode,
              try Self.read(fd, maximum: Self.maximumRequestBytes) == claim.data else { throw Failure.changed }
    }

    func publish(_ claim: Claim, phase: Phase, proof: Proof? = nil,
                 result: BackendServiceReplacementResult? = nil, code: String? = nil,
                 adoptionStage: ManagedStorageWorkerAdoptionFailure? = nil,
                 childRebindDiagnostic: ManagedStorageChildRebindDiagnostic? = nil,
                 originalConsumerDiagnostic: OriginalConsumerFailureDiagnostic? = nil) throws {
        try validateDirectories()
        let ids = result?.containedContainerIDs.sorted()
        guard (ids?.count ?? 0) <= 4096, ids?.allSatisfy({ $0.utf8.count <= 128 }) ?? true else { throw Failure.full }
        try writeReceipt(name: claim.request.operationUUID + "." + phase.rawValue + ".json",
            receipt: .init(schema: 1, counter: claim.counter, phase: phase, request: claim.request,
                ownerRequest: result?.request, successor: result?.successor, containedContainerIDs: ids, proof: proof, code: code,
                adoptionStage: phase == .failed ? adoptionStage : nil,
                childRebindDiagnostic: phase == .failed && adoptionStage == .childRebind ? childRebindDiagnostic : nil,
                originalConsumerDiagnostic: phase == .failed ? originalConsumerDiagnostic : nil))
    }

    func ownerObservation() throws -> OwnerObservation {
        try validateDirectories()
        let owner = try Self.openDirectory(rootFD, "managed-storage-owner")
        defer { close(owner) }
        var uncertain = stat()
        guard fstatat(owner, "uncertain", &uncertain, AT_SYMLINK_NOFOLLOW) != 0, errno == ENOENT else { throw Failure.changed }
        let fd = openat(owner, "state.json", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw Failure.unsafe }; defer { close(fd) }
        try Self.validateFile(fd, directory: owner, name: "state.json")
        let data = try Self.read(fd, maximum: Self.maximumLifecycleOwnerBytes)
        var manifestData: Data?, intentsData: Data?, intentsManifestData: Data?
        var leaseIdentity: PersistentFileIdentity?, intentsIdentity: PersistentFileIdentity?, intentsLeaseIdentity: PersistentFileIdentity?
        do {
            // Refuse partial commits without repairing, taking a lease or minting an owner.
            guard Set(try entryNames(in: owner)) == ["lease", "manifest.json", "state.json"] else { throw Failure.changed }
            manifestData = try Self.readFile(owner, name: "manifest.json", maximum: Self.maximumLifecycleOwnerBytes)
            let lease = openat(owner, "lease", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            guard lease >= 0 else { throw Failure.unsafe }; defer { close(lease) }
            try Self.validateFile(lease, directory: owner, name: "lease")
            _ = try Self.read(lease, maximum: 0)
            leaseIdentity = try PersistentFileIdentity.capture(descriptor: lease)
            let intents = try Self.openDirectory(rootFD, "managed-storage")
            defer { close(intents) }
            guard Set(try entryNames(in: intents)) == ["lease", "manifest.json", "state.json"] else { throw Failure.changed }
            intentsIdentity = try PersistentFileIdentity.capture(descriptor: intents)
            intentsData = try Self.readFile(intents, name: "state.json", maximum: Self.maximumLifecycleOwnerBytes)
            intentsManifestData = try Self.readFile(intents, name: "manifest.json", maximum: Self.maximumLifecycleOwnerBytes)
            let intentsLease = openat(intents, "lease", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            guard intentsLease >= 0 else { throw Failure.unsafe }; defer { close(intentsLease) }
            try Self.validateFile(intentsLease, directory: intents, name: "lease")
            _ = try Self.read(intentsLease, maximum: 0)
            intentsLeaseIdentity = try PersistentFileIdentity.capture(descriptor: intentsLease)
            try Self.validateDirectory(intents, parent: rootFD, name: "managed-storage")
            guard Set(try entryNames(in: intents)) == ["lease", "manifest.json", "state.json"],
                  try Self.readFile(intents, name: "state.json", maximum: Self.maximumLifecycleOwnerBytes) == intentsData,
                  try Self.readFile(intents, name: "manifest.json", maximum: Self.maximumLifecycleOwnerBytes) == intentsManifestData,
                  try Self.readFile(owner, name: "manifest.json", maximum: Self.maximumLifecycleOwnerBytes) == manifestData else { throw Failure.changed }
            try Self.validateFile(intentsLease, directory: intents, name: "lease")
            try Self.validateFile(lease, directory: owner, name: "lease")
            guard Set(try entryNames(in: owner)) == ["lease", "manifest.json", "state.json"],
                  try Self.read(fd, maximum: Self.maximumLifecycleOwnerBytes) == data else { throw Failure.changed }
        }
        try Self.validateFile(fd, directory: owner, name: "state.json")
        try Self.validateDirectory(owner, parent: rootFD, name: "managed-storage-owner")
        var r = stat(), o = stat()
        guard fstat(rootFD, &r) == 0, fstat(owner, &o) == 0 else { throw Failure.io }
        try validateDirectories()
        return .init(data: data, rootDevice: UInt64(UInt32(bitPattern: r.st_dev)), rootInode: r.st_ino,
                     ownerDevice: UInt64(UInt32(bitPattern: o.st_dev)), ownerInode: o.st_ino,
                     manifestData: manifestData, intentsData: intentsData, leaseIdentity: leaseIdentity,
                     rootIdentity: try PersistentFileIdentity.capture(descriptor: rootFD),
                     ownerIdentity: try PersistentFileIdentity.capture(descriptor: owner),
                     intentsManifestData: intentsManifestData, intentsIdentity: intentsIdentity,
                     intentsLeaseIdentity: intentsLeaseIdentity)
    }

    private func writeReceipt(name: String, receipt: Receipt) throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(receipt)
        guard data.count <= 1_048_576 else { throw Failure.full }
        // A staging artifact is never removed on failure or reused after restart.
        let staging = name + ".writing"
        let fd = openat(directoryFD, staging, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
        guard fd >= 0 else { throw Failure.io }; defer { close(fd) }
        try Self.validateFile(fd, directory: directoryFD, name: staging)
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let written = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                guard written > 0 else { throw Failure.io }; offset += written
            }
        }
        guard fsync(fd) == 0 else { throw Failure.io }
        try Self.validateFile(fd, directory: directoryFD, name: staging)
        guard renameatx_np(directoryFD, staging, directoryFD, name, UInt32(RENAME_EXCL)) == 0,
              fsync(directoryFD) == 0 else { throw Failure.io }
        try Self.validateFile(fd, directory: directoryFD, name: name)
    }

    private func entryNames(in directory: Int32? = nil) throws -> [String] {
        let fd = openat(directory ?? directoryFD, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw Failure.io }
        guard let stream = fdopendir(fd) else { close(fd); throw Failure.io }
        defer { closedir(stream) }
        var names: [String] = []
        while true {
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw Failure.io }; break
            }
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) { String(cString: $0) }
            }
            if name == "." || name == ".." { continue }
            guard names.count < Self.maximumRequests * 5 + 1 else { throw Failure.full }
            names.append(name)
        }
        return names
    }

    private func validateDirectories() throws {
        let current = try Self.openRoot(root); defer { close(current) }
        var held = stat(), named = stat()
        guard fstat(rootFD, &held) == 0, fstat(current, &named) == 0,
              held.st_dev == named.st_dev, held.st_ino == named.st_ino else { throw Failure.changed }
        try Self.validateDirectory(directoryFD, parent: rootFD, name: Self.directoryName)
    }

    private static func openRoot(_ root: URL) throws -> Int32 {
        guard root.isFileURL, root.path.hasPrefix("/"), let resolved = realpath(root.path, nil) else { throw Failure.unsafe }
        defer { free(resolved) }
        guard String(cString: resolved) == root.path else { throw Failure.unsafe }
        var fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw Failure.io }
        do {
            for component in root.path.split(separator: "/") {
                let next = openat(fd, String(component), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
                guard next >= 0 else { throw Failure.unsafe }; close(fd); fd = next
            }
            var info = stat()
            guard fstat(fd, &info) == 0, info.st_uid == geteuid(), info.st_mode & 0o022 == 0 else { throw Failure.unsafe }
            return fd
        } catch { close(fd); throw error }
    }

    private static func openDirectory(_ parent: Int32, _ name: String) throws -> Int32 {
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw Failure.unsafe }
        do { try validateDirectory(fd, parent: parent, name: name); return fd }
        catch { close(fd); throw error }
    }

    private static func validateDirectory(_ fd: Int32, parent: Int32, name: String) throws {
        var held = stat(), named = stat()
        guard fstat(fd, &held) == 0, fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              held.st_mode & S_IFMT == S_IFDIR, held.st_uid == geteuid(), held.st_mode & 0o7777 == 0o700,
              held.st_dev == named.st_dev, held.st_ino == named.st_ino, held.st_mode == named.st_mode,
              held.st_uid == named.st_uid else { throw Failure.unsafe }
    }

    @discardableResult static func validateFile(_ fd: Int32, directory: Int32, name: String,
                                                expectedUID: uid_t = geteuid()) throws -> stat {
        var held = stat(), named = stat(), parent = stat()
        guard fstat(fd, &held) == 0, fstat(directory, &parent) == 0,
              fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              held.st_mode & S_IFMT == S_IFREG, held.st_uid == expectedUID,
              held.st_mode & 0o7777 == 0o600, held.st_nlink == 1,
              held.st_dev == parent.st_dev, held.st_dev == named.st_dev, held.st_ino == named.st_ino,
              held.st_mode == named.st_mode, held.st_uid == named.st_uid, named.st_nlink == 1 else { throw Failure.unsafe }
        return held
    }

    private static func readFile(_ directory: Int32, name: String, maximum: Int) throws -> Data {
        let fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw Failure.unsafe }; defer { close(fd) }
        try validateFile(fd, directory: directory, name: name)
        let data = try read(fd, maximum: maximum)
        try validateFile(fd, directory: directory, name: name)
        return data
    }

    private static func read(_ fd: Int32, maximum: Int) throws -> Data {
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_size >= 0, info.st_size <= maximum,
              lseek(fd, 0, SEEK_SET) == 0 else { throw Failure.invalid }
        var bytes = [UInt8](repeating: 0, count: Int(info.st_size) + 1)
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeMutableBytes {
                Darwin.read(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset)
            }
            guard count >= 0 else { throw Failure.io }
            if count == 0 { break }; offset += count
        }
        guard offset == info.st_size else { throw Failure.changed }
        return Data(bytes.prefix(offset))
    }
}

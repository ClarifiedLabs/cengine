import CEngineCore
import Darwin
import Foundation

/// Shared-storage configuration, resolved from the running signed engine.
public enum ManagedStorageStartup {
    #if os(macOS)
    public static func lifecycleConfiguration() throws -> RawVirtualizationBackend.SharedStorageConfiguration {
        let policy = try StorageLifecycleNativePolicy.current(role: .engine)
        let identity = try policy.currentIdentity(role: .engine)
        return .init(installedHelperTeam: identity.teamIdentifier, policy: policy)
    }
    #endif
}

#if os(macOS)
/// Managed-storage startup errors. All leave store bytes untouched.
enum ManagedLifecycleStartupError {
    static let existingStoreMessage = "storage recovery cannot confirm that the previous process exited or find a matching running VM; data preserved"
    static func existingStore() -> EngineError { EngineError(.unsupported, existingStoreMessage) }
}

/// The lifecycle startup root is the directory actually held by the daemon lock.
/// Every namespace mutation revalidates the lock; no path reopen can select a
/// different store between preflight and production startup.
struct ManagedLifecycleStartupRoot: Sendable {
    let directory: PersistentStateDirectory
    let storeLock: CanonicalDataStoreLock

    init(storeLock: CanonicalDataStoreLock) throws {
        directory = try PersistentStateDirectory.retaining(storeLock)
        self.storeLock = storeLock
        try validate()
    }

    /// One-time startup repair: remove only group/other read/search permissions
    /// from a locked, owned, ACL-free root. Never repair writable-by-others roots,
    /// child directories, or known unsupported storage. Subsequent validation is strict.
    /// The store lock serializes cooperating daemons, not arbitrary same-UID writers;
    /// this chmod is not proof of store integrity or permission to admit a backend.
    @MainActor static func prepareForStartup(storeLock: CanonicalDataStoreLock) throws -> Self {
        let directory = try PersistentStateDirectory.retaining(storeLock)
        var information = stat()
        guard Darwin.fstat(directory.descriptor, &information) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let mode = information.st_mode & 0o7777
        if mode != 0o700 {
            guard information.st_uid == geteuid(), mode & ~mode_t(0o055) == 0o700 else {
                throw EngineError(.unsupported, "Storage directory \(directory.url.path) has unsafe ownership or permissions; automatic repair requires an owned directory without group/other write access or special mode bits. Data was preserved.")
            }
            try RawDiskJournalDirectory.requireNoACL(directory.descriptor)
            // Preserve the no-migration contract: classify before changing even
            // directory metadata, and leave unsafe child directories untouched.
            _ = try ManagedStorageLifecycleOwner.classify(root: directory, allowRootPermissionRepair: true)
            for name in ["containers", "deleted-containers", "volumes", "infrastructure"] {
                if let child = try directory.openDirectoryIfPresent(named: name) {
                    try RawDiskJournalDirectory.prepare(child, repairPermissions: false)
                    guard try directory.entryMetadata(named: name)?.identity == child.identity else {
                        throw EngineError(.conflict, "Storage directory changed during startup; retry without resetting data.")
                    }
                }
            }
            try storeLock.validateRetainedOwnership()
            try RawDiskJournalDirectory.prepare(directory)
        }
        return try Self(storeLock: storeLock)
    }

    func validate(infrastructure: PersistentStateDirectory? = nil) throws {
        try storeLock.validateRetainedOwnership()
        // Lifecycle roots are private authorities, unlike generic metadata roots.
        // Only prepareForStartup may tighten a safe root; revalidation never repairs.
        try RawDiskJournalDirectory.prepare(directory, repairPermissions: false)
        if let infrastructure {
            try RawDiskJournalDirectory.prepare(infrastructure, repairPermissions: false)
            guard try directory.entryMetadata(named: "infrastructure")?.identity == infrastructure.identity,
                  infrastructure.pathStillNamesThisDirectory() else {
                throw EngineError(.conflict, "lifecycle infrastructure directory was replaced; data preserved")
            }
        }
    }

    func openOrCreateDirectory(named name: String) throws -> PersistentStateDirectory {
        try validate()
        return try directory.openOrCreateDirectory(named: name, permissions: 0o700)
    }

    func networkNamespace(in infrastructure: PersistentStateDirectory) throws -> String {
        try validate(infrastructure: infrastructure)
        if let data = try infrastructure.readRegularFile(named: "network-namespace", required: false),
           let value = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
           !value.isEmpty {
            return value
        }
        let value = Identifier.random()
        try validate(infrastructure: infrastructure)
        try infrastructure.replaceRegularFile(named: "network-namespace", data: Data("\(value)\n".utf8))
        return value
    }
}

/// Ordered managed-storage startup steps. Production and tests share `run`, so the
/// order (classify before disk/spawn; adoption before control; recovery before
/// backend admission) is enforced once.
@MainActor protocol ManagedLifecycleStartupSteps: AnyObject {
    func validateRetainedDirectories() throws
    func classify() throws -> ManagedStorageLifecycleOwner.StoreFormat
    /// Read-only live-writer build guard, before helper I/O or owner mutation.
    func validateExistingGeneration() async throws
    func openInitializationDisk() throws
    func prepareResume() async throws
    func launchResumeShim() async throws
    func prepareResumeDisk() async throws
    func bootResume() async throws
    func admitInitialization() async throws
    func provisionDisk() throws
    func openExistingDisk() throws
    func prepareReplacementRecovery() async throws -> Bool
    func recoverReplacement() async throws
    func coldStatus() async throws -> StorageLifecycleColdRootProtocol.Eligibility
    func prepareTakeover() async throws
    func freezeColdLaunch() throws
    func launchColdShim() async throws
    func prepareColdDisk() async throws
    func bootCold() async throws
    func adoptShim() async throws
    func reattachShim() async throws
    func takeover() async throws
    func recoverWorkload() async throws
    func bindScope() async throws
    func prepareOwner() async throws
    func launchShim() async throws
    func prepareFreshDisk() async throws
    func provisionFresh() async throws
    func bootFresh() async throws
    func enrollAdoption() async throws
    func connectWorkload() async throws
    func queryWorkload() async throws
    func adopt() async throws
    /// Containment after a failure past classification; never deletes bytes.
    func abandon() async
}

extension ManagedLifecycleStartupSteps {
    func validateRetainedDirectories() throws {}
    func openInitializationDisk() throws { throw ManagedStorageLifecycleOwner.Failure.blocked }
    func prepareResume() async throws { throw ManagedStorageLifecycleOwner.Failure.blocked }
    func launchResumeShim() async throws { throw ManagedStorageLifecycleOwner.Failure.blocked }
    func prepareResumeDisk() async throws { throw ManagedStorageLifecycleOwner.Failure.blocked }
    func bootResume() async throws { throw ManagedStorageLifecycleOwner.Failure.blocked }
    func admitInitialization() async throws { throw ManagedStorageLifecycleOwner.Failure.blocked }
    func prepareReplacementRecovery() async throws -> Bool { false }
    func recoverReplacement() async throws { throw ManagedStorageLifecycleOwner.Failure.blocked }
    func coldStatus() async throws -> StorageLifecycleColdRootProtocol.Eligibility { throw ManagedStorageLifecycleOwner.Failure.blocked }
    func freezeColdLaunch() throws { throw ManagedStorageLifecycleOwner.Failure.blocked }
    func launchColdShim() async throws { throw ManagedStorageLifecycleOwner.Failure.blocked }
    func prepareColdDisk() async throws { throw ManagedStorageLifecycleOwner.Failure.blocked }
    func bootCold() async throws { throw ManagedStorageLifecycleOwner.Failure.blocked }
}

@MainActor enum ManagedLifecycleStartup {
    /// Read-only classification and parent validation. Absent parents stay absent;
    /// no namespace, selector, or directory may be created until all checks pass.
    static func preflight(root: PersistentStateDirectory) throws {
        do { try RawDiskJournalDirectory.prepare(root, repairPermissions: false) }
        catch RawDiskInitialization.Failure.unsafePath {
            throw ManagedStorageLifecycleOwner.UnsupportedStoreFormat()
        }
        _ = try ManagedStorageLifecycleOwner.classify(root: root)
        for name in ["containers", "deleted-containers", "volumes", "infrastructure"] {
            if let directory = try root.openDirectoryIfPresent(named: name) {
                try RawDiskJournalDirectory.prepare(directory, repairPermissions: false)
                guard try root.entryMetadata(named: name)?.identity == directory.identity else {
                    throw RawDiskInitialization.Failure.unsafePath
                }
            }
        }
    }

    /// The production boundary before the first lifecycle startup mutation.
    static func acquireRuntimeNamespace(root: ManagedLifecycleStartupRoot) throws -> VMShimRuntimeNamespace {
        try root.validate()
        try preflight(root: root.directory)
        try root.validate()
        return try VMShimRuntimeNamespace.acquire(stateDirectory: root.directory)
    }

    /// Publication is only a locator: positively identify the live process before
    /// probing, then correlate its native-pinned status with the recorded birth
    /// and launch. This never launches, adopts, or contacts ROOT. Proven death
    /// merely leaves cold-start eligibility to the existing lifecycle authority.
    static func validateExistingGeneration(
        _ specification: VMShimProtocol.Specification,
        executableUUID: UUID? = RunningExecutableIdentity.uuid,
        observe: (Int32) -> RawStorageShimRecovery.Observation = RawStorageShimRecovery.observe,
        probe: (VMShimClient) async throws -> VMShimProtocol.Status = {
            try await $0.status(timeoutMilliseconds: 2_000)
        }
    ) async throws {
        try Task.checkCancellation()
        guard let old = try RawStorageShimRecovery.publishedGeneration(for: specification, observe: observe) else { return }
        let identity = old.record.process
        switch RawStorageShimRecovery.liveness(identity, observation: observe(identity.pid)) {
        case .dead:
            return
        case .unknown:
            throw EngineError(.conflict, "storage shim kernel identity is unavailable; explicit quiescence is required; preserve launch records")
        case .alive:
            let status: VMShimProtocol.Status
            do {
                status = try await probe(VMShimClient(specification: old.specification))
            } catch {
                if error is CancellationError || Task.isCancelled { throw CancellationError() }
                guard RawStorageShimRecovery.liveness(identity, observation: observe(identity.pid)) == .dead else {
                    throw EngineError(.conflict, "storage shim status unavailable and death unproven; explicit quiescence is required; preserve launch records")
                }
                return
            }
            let (seconds, overflow) = identity.startSeconds.multipliedReportingOverflow(by: 1_000_000)
            let (start, additionOverflow) = seconds.addingReportingOverflow(identity.startMicroseconds)
            guard !overflow, !additionOverflow,
                  status.shimLaunchUUID == old.specification.shimLaunchUUID,
                  status.containerID == old.specification.containerID,
                  status.generation == old.specification.generation,
                  status.processIdentifier == identity.pid, status.processStartTime == start,
                  RawStorageShimRecovery.liveness(identity, observation: observe(identity.pid)) == .alive else {
                throw EngineError(.conflict, "storage shim launch identity changed")
            }
            try InfrastructureRecovery.validate(status, specification: old.specification, executableUUID: executableUUID)
            guard old.specification.rootDiskIdentity == specification.rootDiskIdentity else {
                throw EngineError(.conflict, "running infrastructure VM disk identity changed")
            }
        }
    }

    static func run(_ steps: any ManagedLifecycleStartupSteps) async throws {
        try steps.validateRetainedDirectories()
        let format = try steps.classify()
        do {
            if format == .initialization {
                try steps.openInitializationDisk()
                try await steps.validateExistingGeneration()
                try steps.validateRetainedDirectories()
                try await steps.bindScope()
                try steps.validateRetainedDirectories()
                try await steps.prepareResume()
                try steps.validateRetainedDirectories()
                try await steps.launchResumeShim()
                try steps.validateRetainedDirectories()
                try await steps.prepareResumeDisk()
                try steps.validateRetainedDirectories()
                try await steps.bootResume()
                try steps.validateRetainedDirectories()
                try await steps.enrollAdoption()
                try steps.validateRetainedDirectories()
                try await steps.admitInitialization()
                try steps.validateRetainedDirectories()
                try await steps.adopt()
                try steps.validateRetainedDirectories()
                return
            }
            if format == .existingV2 {
                try steps.openExistingDisk()
                try await steps.validateExistingGeneration()
                try steps.validateRetainedDirectories()
                try await steps.bindScope()
                try steps.validateRetainedDirectories()
                if try await steps.prepareReplacementRecovery() {
                    try steps.validateRetainedDirectories()
                    try await steps.adoptShim()
                    try steps.validateRetainedDirectories()
                    try await steps.reattachShim()
                    try steps.validateRetainedDirectories()
                    try await steps.recoverReplacement()
                    try steps.validateRetainedDirectories()
                    try await steps.takeover()
                    try steps.validateRetainedDirectories()
                    try await steps.recoverWorkload()
                    try steps.validateRetainedDirectories()
                    try await steps.adopt()
                    try steps.validateRetainedDirectories()
                    return
                }
                try steps.validateRetainedDirectories()
                let status = try await steps.coldStatus()
                try steps.validateRetainedDirectories()
                guard status != .unavailable else { throw ManagedLifecycleStartupError.existingStore() }
                try await steps.prepareTakeover()
                try steps.validateRetainedDirectories()
                switch status {
                case .live:
                    try await steps.adoptShim()
                    try steps.validateRetainedDirectories()
                    try await steps.reattachShim()
                    try steps.validateRetainedDirectories()
                    try await steps.takeover()
                    try steps.validateRetainedDirectories()
                case .eligible:
                    try steps.freezeColdLaunch()
                    try steps.validateRetainedDirectories()
                    try await steps.launchColdShim()
                    try steps.validateRetainedDirectories()
                    try await steps.prepareColdDisk()
                    try steps.validateRetainedDirectories()
                    try await steps.bootCold()
                    try steps.validateRetainedDirectories()
                    try await steps.enrollAdoption()
                    try steps.validateRetainedDirectories()
                case .unavailable:
                    throw ManagedLifecycleStartupError.existingStore()
                }
                try await steps.recoverWorkload()
                try steps.validateRetainedDirectories()
                try await steps.adopt()
                try steps.validateRetainedDirectories()
                return
            }
            try steps.provisionDisk()
            try await steps.bindScope()
            try steps.validateRetainedDirectories()
            try await steps.prepareOwner()
            try steps.validateRetainedDirectories()
            try await steps.launchShim()
            try steps.validateRetainedDirectories()
            try await steps.prepareFreshDisk()
            try steps.validateRetainedDirectories()
            try await steps.provisionFresh()
            try steps.validateRetainedDirectories()
            try await steps.bootFresh()
            try steps.validateRetainedDirectories()
            try await steps.connectWorkload()
            try steps.validateRetainedDirectories()
            try await steps.queryWorkload()
            try steps.validateRetainedDirectories()
            try await steps.adopt()
            try steps.validateRetainedDirectories()
            try await steps.enrollAdoption()
            try steps.validateRetainedDirectories()
        } catch {
            await steps.abandon()
            throw error
        }
    }
}

/// Production startup and recovery for the infrastructure storage VM.
@MainActor final class ManagedLifecycleProductionStartup: ManagedLifecycleStartupSteps {
    private let retainedRoot: ManagedLifecycleStartupRoot
    private var dataDirectory: PersistentStateDirectory { retainedRoot.directory }
    private let infrastructureDirectory: PersistentStateDirectory
    private let storeLock: CanonicalDataStoreLock
    private let team: String
    private let policy: StorageLifecycleNativePolicy
    private let compatibility: ManagedPrepareCompatibilityCoordinator?
    private let diskSize: UInt64
    private let names: SharedVolumeInitializationCoordinator
    /// Exact storage initramfs digest from validated disk-bootstrap metadata.
    private let provenance: String
    /// Infrastructure spec (fabric, management address); disk identity filled at launch.
    private let specification: VMShimProtocol.Specification
    private var client: StorageLifecycleRootClient?
    private var binding: StorageIdentity.StoreBinding?
    private var backing: FileHandle?
    private var owner: ManagedStorageLifecycleOwner?
    private var preparation: ManagedStorageLifecycleOwner.Preparation?
    private var diskIdentity: PersistentFileIdentity?
    private var greeting: StorageLifecycleFreshProtocol.Greeting?
    private var initialization: ManagedStorageInitialization?
    private var resuming = false
    private var restarting = false
    private var coldEligibility: StorageLifecycleColdRootProtocol.Eligibility?
    private var coldLaunch: RawStorageShimRecovery.PreparedLaunch?
    private var coldGreeting: StorageLifecycleColdShimProtocol.Greeting?
    private var survivingGeneration: RawStorageShimRecovery.Generation?
    private var adoptedShim: ManagedStorageLifecycleOwner.AdoptedShim?
    private(set) var shim: VMShimClient?
    private(set) var connection: StorageLifecycleShimConnection?
    private(set) var backend: RawManagedStorageBackend?

    init(retainedRoot: ManagedLifecycleStartupRoot, infrastructureDirectory: PersistentStateDirectory,
         installedHelperTeam: String, policy: StorageLifecycleNativePolicy,
         diskSize: UInt64, names: SharedVolumeInitializationCoordinator, provenanceReference: String,
         specification: VMShimProtocol.Specification, compatibility: ManagedPrepareCompatibilityCoordinator? = nil) {
        self.compatibility = compatibility
        self.retainedRoot = retainedRoot; self.infrastructureDirectory = infrastructureDirectory
        storeLock = retainedRoot.storeLock; team = installedHelperTeam; self.policy = policy
        self.diskSize = diskSize; self.names = names; provenance = provenanceReference
        self.specification = specification
    }

    func start() async throws -> (shim: VMShimClient, backend: RawManagedStorageBackend) {
        try await ManagedLifecycleStartup.run(self)
        guard let shim, let backend else { throw RawManagedStorageBackend.failure() }
        return (shim, backend)
    }

    func validateRetainedDirectories() throws {
        try retainedRoot.validate(infrastructure: infrastructureDirectory)
    }

    func classify() throws -> ManagedStorageLifecycleOwner.StoreFormat {
        try validateRetainedDirectories()
        return try ManagedStorageLifecycleOwner.classify(root: dataDirectory)
    }

    func validateExistingGeneration() async throws {
        try validateRetainedDirectories()
        guard let diskIdentity else { throw RawManagedStorageBackend.failure() }
        var proposed = specification
        proposed.rootDiskIdentity = diskIdentity.shimIdentity
        try await ManagedLifecycleStartup.validateExistingGeneration(proposed)
    }

    /// Binding comes from the actual held root and the actual created disk record.
    func provisionDisk() throws {
        try validateRetainedDirectories()
        try RawDiskJournalDirectory.prepare(infrastructureDirectory, repairPermissions: false)
        let identity = try RawStorageDiskProvisioning.prepare(in: infrastructureDirectory, size: diskSize)
        guard case .journal(let record) = try RawDiskInitialization.inspectExisting(
            in: infrastructureDirectory, named: "volumes.ext4", expectedSize: diskSize), record.state == .created else {
            throw EngineError(.conflict, "lifecycle storage disk is not freshly created; data preserved")
        }
        let disk = try infrastructureDirectory.openRegularFile(named: "volumes.ext4", access: .readWrite)
        guard disk.identity == identity else { try? disk.handle.close(); throw RawManagedStorageBackend.failure() }
        backing = disk.handle
        diskIdentity = identity
        binding = try StorageIdentity.StoreBinding(storeID: .init(UUID().uuidString.lowercased()),
            root: Self.rootIdentity(dataDirectory.identity),
            backing: .init(identity: Self.rootIdentity(identity), size: record.expectedSize),
            expectedExt4UUID: .init(record.ext4UUID))
        // Persist correlation before launching the formatter or provisioning ROOT.
        initialization = try ManagedStorageInitialization.create(in: dataDirectory, binding: binding!, provenance: provenance)
    }

    func openInitializationDisk() throws {
        let marker = try ManagedStorageInitialization.open(in: dataDirectory)
        let binding = try marker.manifest.binding.value()
        guard binding.backing.size == diskSize, marker.manifest.provenance == provenance else { throw RawManagedStorageBackend.failure() }
        let disk = try infrastructureDirectory.openRegularFile(named: "volumes.ext4", access: .readWrite)
        backing = disk.handle
        guard try Self.rootIdentity(disk.identity) == binding.backing.identity,
              case .journal(let record) = try RawDiskInitialization.inspectExisting(in: infrastructureDirectory,
                named: "volumes.ext4", expectedSize: diskSize, heldDiskDescriptor: disk.handle.fileDescriptor, createLock: false),
              record.ext4UUID == binding.expectedExt4UUID.rawValue, record.state == .initialized else {
            throw RawManagedStorageBackend.failure("initialization disk lacks exact format evidence; data preserved")
        }
        initialization = marker; self.binding = binding; diskIdentity = disk.identity; resuming = true
    }
    func prepareResume() async throws {
        guard let client, let binding, let backing else { throw RawManagedStorageBackend.failure() }
        let owner = try ManagedStorageLifecycleOwner(initializationRootClient: client, installedHelperTeam: team,
            root: dataDirectory, backingDescriptor: backing.fileDescriptor, binding: binding, policy: policy)
        self.owner = owner
        preparation = try await owner.prepareResume(storeLock: storeLock)
        try validateRetainedDirectories()
        guard let diskIdentity else { throw RawManagedStorageBackend.failure() }
        var proposed = specification; proposed.rootDiskIdentity = diskIdentity.shimIdentity
        coldLaunch = try RawStorageShimRecovery.prepareLaunch(proposed)
    }
    func launchResumeShim() async throws {
        guard let coldLaunch, let preparation, let binding, shim == nil else { throw RawManagedStorageBackend.failure() }
        let launched = try await VMShimClient.launchLifecycleStorage(preparedLaunch: coldLaunch, diskMode: .resumeReadOnly,
            rootPublicKey: preparation.rootPublicKey, binding: binding, storeLock: storeLock)
        shim = launched.shim; connection = launched.connection
    }
    func prepareResumeDisk() async throws {
        guard let connection, let coldLaunch, let binding else { throw RawManagedStorageBackend.failure() }
        let greeting = try await connection.prepareResumeDisk()
        try greeting.validate()
        guard greeting.purpose == .resumeReadOnly, try greeting.binding.value() == binding,
              greeting.launch.shimLaunchUUID == coldLaunch.specification.shimLaunchUUID,
              try greeting.launch.specSHA256 == RawStorageShimRecovery.digest(RawDiskBootTransaction.adoptionSpecification(coldLaunch.specification)),
              greeting.launch.initramfsSHA256 == coldLaunch.specification.expectedInitramfsSHA256 else { throw RawManagedStorageBackend.failure() }
        coldGreeting = greeting
    }
    func bootResume() async throws {
        guard let owner, let connection, let coldGreeting else { throw RawManagedStorageBackend.failure() }
        try await owner.bootResume(using: connection, greeting: coldGreeting, storeLock: storeLock,
            nowUnixSeconds: UInt64(Date().timeIntervalSince1970), lifetimeSeconds: 3600)
    }
    func admitInitialization() async throws {
        guard let owner else { throw RawManagedStorageBackend.failure() }
        try await owner.admitInitialization()
    }

    /// Open the exact completed physical pair without creating or formatting it.
    /// ROOT status selects live adoption versus a separate mount-only cold launch;
    /// incomplete/ambiguous state remains untouched.
    func openExistingDisk() throws {
        restarting = true
        let manifest = try ManagedStorageLifecycleCheckpoint.readManifest(in: dataDirectory)
        guard manifest.root == dataDirectory.identity, manifest.bytes == diskSize else { throw RawManagedStorageBackend.failure() }
        let disk = try infrastructureDirectory.openRegularFile(named: "volumes.ext4", access: .readWrite)
        backing = disk.handle
        guard disk.identity == manifest.backing,
              case .journal(let record) = try RawDiskInitialization.inspectExisting(in: infrastructureDirectory,
                named: "volumes.ext4", expectedSize: manifest.bytes, heldDiskDescriptor: disk.handle.fileDescriptor, createLock: false),
              record.state == .initialized, record.ext4UUID == manifest.ext4UUID else {
            throw RawManagedStorageBackend.failure("incomplete lifecycle disk initialization; data preserved")
        }
        diskIdentity = disk.identity
        binding = try StorageIdentity.StoreBinding(storeID: .init(manifest.identity.store), root: Self.rootIdentity(dataDirectory.identity),
            backing: .init(identity: Self.rootIdentity(disk.identity), size: manifest.bytes), expectedExt4UUID: .init(manifest.ext4UUID))
    }
    func prepareReplacementRecovery() async throws -> Bool {
        guard let client, let binding, let backing else { throw RawManagedStorageBackend.failure() }
        let owner = try ManagedStorageLifecycleOwner(existingStoreRootClient: client, installedHelperTeam: team,
            root: dataDirectory, backingDescriptor: backing.fileDescriptor, binding: binding, policy: policy)
        self.owner = owner
        guard try await owner.prepareReplacementRecovery() else { return false }
        try validateRetainedDirectories()
        var proposed = specification
        proposed.rootDiskIdentity = diskIdentity?.shimIdentity
        guard let published = try RawStorageShimRecovery.publishedGeneration(for: proposed) else {
            throw ManagedLifecycleStartupError.existingStore()
        }
        survivingGeneration = published
        return true
    }
    func recoverReplacement() async throws {
        guard let owner, let connection else { throw RawManagedStorageBackend.failure() }
        try await owner.recoverReplacement(using: connection, current: connection.currentReady())
    }
    func coldStatus() async throws -> StorageLifecycleColdRootProtocol.Eligibility {
        guard let owner else { throw RawManagedStorageBackend.failure() }
        let status = try await owner.statusCold(storeLock: storeLock)
        try validateRetainedDirectories()
        coldEligibility = status.eligibility
        if status.eligibility == .live {
            var proposed = specification
            proposed.rootDiskIdentity = diskIdentity?.shimIdentity
            guard let published = try RawStorageShimRecovery.publishedGeneration(for: proposed) else {
                throw ManagedLifecycleStartupError.existingStore()
            }
            survivingGeneration = published
        }
        return status.eligibility
    }
    func prepareTakeover() async throws {
        guard let owner else { throw RawManagedStorageBackend.failure() }
        preparation = try await owner.prepareTakeover(storeLock: storeLock)
    }
    func freezeColdLaunch() throws {
        guard coldEligibility == .eligible, coldLaunch == nil, let diskIdentity else { throw RawManagedStorageBackend.failure() }
        var proposed = specification
        proposed.rootDiskIdentity = diskIdentity.shimIdentity
        coldLaunch = try RawStorageShimRecovery.prepareLaunch(proposed)
    }
    func launchColdShim() async throws {
        guard let coldLaunch, let preparation, let binding, shim == nil else { throw RawManagedStorageBackend.failure() }
        let launched = try await VMShimClient.launchLifecycleStorage(preparedLaunch: coldLaunch,
            rootPublicKey: preparation.rootPublicKey, binding: binding, storeLock: storeLock)
        shim = launched.shim; connection = launched.connection
    }
    func prepareColdDisk() async throws {
        guard let connection, let coldLaunch, let binding else { throw RawManagedStorageBackend.failure() }
        let greeting = try await connection.prepareColdDisk()
        try greeting.validate()
        guard try greeting.binding.value() == binding,
              greeting.launch.shimLaunchUUID == coldLaunch.specification.shimLaunchUUID,
              try greeting.launch.specSHA256 == RawStorageShimRecovery.digest(RawDiskBootTransaction.adoptionSpecification(coldLaunch.specification)),
              greeting.launch.initramfsSHA256 == coldLaunch.specification.expectedInitramfsSHA256 else { throw RawManagedStorageBackend.failure() }
        coldGreeting = greeting
    }
    func bootCold() async throws {
        guard let owner, let connection, let coldGreeting else { throw RawManagedStorageBackend.failure() }
        try await owner.bootCold(using: connection, greeting: coldGreeting, storeLock: storeLock,
            nowUnixSeconds: UInt64(Date().timeIntervalSince1970), lifetimeSeconds: 3600)
    }
    func adoptShim() async throws {
        guard let owner, let published = survivingGeneration else { throw RawManagedStorageBackend.failure() }
        let adopted = try await owner.adoptSurvivingShim(storeLock: storeLock)
        try Self.validateSurvivingGeneration(published, status: adopted.status)
        adoptedShim = adopted
    }
    /// Host publication is only a locator. ROOT's native shim pin and frozen spec
    /// hash must independently match; the UDS constructor re-pins the live peer.
    static func validateSurvivingGeneration(_ published: RawStorageShimRecovery.Generation,
                                           status: StorageLifecycleAdoptionRootProtocol.Status) throws {
        try status.validate()
        guard published.specification.kind == .storage,
              published.specification.shimLaunchUUID == status.origin.shimLaunchUUID,
              published.record.process.uniqueID == status.shimUniqueID,
              try RawStorageShimRecovery.digest(RawDiskBootTransaction.adoptionSpecification(published.specification)) == status.origin.specSHA256 else { throw RawManagedStorageBackend.failure() }
    }
    func reattachShim() async throws {
        guard let published = survivingGeneration, let authorization = adoptedShim?.connectionAuthorization else { throw RawManagedStorageBackend.failure() }
        let connection = try await StorageLifecycleShimConnection.connectAdopted(socketPath: published.specification.socketPath,
            authorization: authorization)
        self.connection = connection
        shim = VMShimClient(specification: published.specification, processIdentifier: published.record.process.pid)
    }
    func takeover() async throws {
        guard let owner, let connection else { throw RawManagedStorageBackend.failure() }
        try await owner.takeover(using: connection, current: connection.currentReady(),
            compatibility: policy.isQualification ? nil : compatibility)
    }
    func recoverWorkload() async throws {
        guard let owner else { throw RawManagedStorageBackend.failure() }
        try await owner.recoverWorkload()
    }

    func bindScope() async throws {
        guard let binding else { throw RawManagedStorageBackend.failure() }
        let client = try StorageLifecycleRootClient(installedHelperTeam: team, policy: policy)
        self.client = client
        let store = binding.storeID, root = dataDirectory
        // bindScope refuses the main thread; run it on a detached worker.
        try await Task.detached { try client.bindScope(store: store, rootFD: root.descriptor) }.value
    }

    func prepareOwner() async throws {
        guard let client, let binding, let backing else { throw RawManagedStorageBackend.failure() }
        let owner = try ManagedStorageLifecycleOwner(rootClient: client, installedHelperTeam: team,
            root: dataDirectory, backingDescriptor: backing.fileDescriptor, binding: binding,
            provenanceReference: provenance, policy: policy)
        self.owner = owner
        preparation = try await owner.prepareFresh()
    }

    func launchShim() async throws {
        guard let preparation, let binding, let diskIdentity else { throw RawManagedStorageBackend.failure() }
        var specification = specification
        specification.rootDiskIdentity = diskIdentity.shimIdentity
        let launched = try await VMShimClient.launchLifecycleStorage(specification: specification,
            rootPublicKey: preparation.rootPublicKey, binding: binding, storeLock: storeLock)
        shim = launched.shim; connection = launched.connection
    }

    func prepareFreshDisk() async throws {
        guard let connection, let binding else { throw RawManagedStorageBackend.failure() }
        let greeting = try await connection.prepareFreshDisk()
        guard greeting.matches(binding: binding) else { throw RawManagedStorageBackend.failure() }
        self.greeting = greeting
    }

    func provisionFresh() async throws {
        try validateRetainedDirectories()
        guard let owner else { throw RawManagedStorageBackend.failure() }
        try await owner.provisionFresh()
    }

    func bootFresh() async throws {
        guard let owner, let connection, let greeting else { throw RawManagedStorageBackend.failure() }
        let expected = StorageLifecycleServiceBootProtocol.Binding(shimLaunchUUID: greeting.shimLaunchUUID,
            guestBootNonce: greeting.guestBootNonce, ext4UUID: greeting.ext4UUID, bytes: greeting.bytes)
        try await owner.bootFresh(using: connection, expectedBinding: expected,
            nowUnixSeconds: UInt64(Date().timeIntervalSince1970), lifetimeSeconds: 3600)
    }

    func enrollAdoption() async throws {
        guard let connection else { throw RawManagedStorageBackend.failure() }
        if let initialization {
            try await initialization.preservingEvidence(in: dataDirectory) {
                try await connection.enrollAdoption()
            }
        } else {
            try await connection.enrollAdoption()
        }
        try validateRetainedDirectories()
        if !resuming, let initialization {
            guard let owner else { throw RawManagedStorageBackend.failure() }
            try owner.validateUnusedInitializationCensus()
            try initialization.retain("admitted.json", true)
        }
    }

    func connectWorkload() async throws {
        guard let owner else { throw RawManagedStorageBackend.failure() }
        try await owner.connectWorkload()
    }

    func queryWorkload() async throws {
        guard let owner else { throw RawManagedStorageBackend.failure() }
        _ = try await owner.queryWorkload()
    }

    /// The coordinator's reconcileStartup runs in RawManagedStorageBackend.reconcile,
    /// which gates every workload admission (requireReconciled).
    func adopt() async throws {
        guard let owner else { throw RawManagedStorageBackend.failure() }
        backend = try RawManagedStorageBackend.adoptConnectedOwner(root: dataDirectory, owner: owner, names: names)
    }

    func abandon() async {
        // Intentional abandonment uses authenticated private control while live.
        // Never fall back to a launch token or signals after an uncertain reply.
        if !restarting, let connection {
            // Cleanup has its own bounded exchange; caller cancellation must not
            // cancel private stop before it is sent. A closed peer stays closed.
            await Task.detached { try? await connection.stop() }.value
        }
        // A failed adoption/takeover detaches this candidate; never stop the
        // surviving storage VM or delete the pending operation/disk evidence.
        connection?.cancel()
        await owner?.close()
        backend = nil
        try? backing?.close()
    }

    private static func rootIdentity(_ value: PersistentFileIdentity) throws -> StorageIdentity.RootIdentity {
        guard let volume = value.volumeUUID else { throw RawManagedStorageBackend.failure() }
        return try .init(volumeUUID: .init(volume.uuidString.lowercased()), inode: value.inode)
    }
}
#endif

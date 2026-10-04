#if os(macOS)
import CEngineCore
import CryptoKit
import Darwin
import Foundation
import Synchronization

/// One private exchange for one VZ boot. Durable SPENT records, not transport
/// retries or filesystem inspection, decide whether initialization is allowed.
final class RawDiskBootTransaction: Sendable {
    enum Boundary: Equatable, Sendable {
        case afterPreflight, beforeConsume(Int), afterConsumed(Int)
        case beforeManifestWrite, manifestBytesWritten(Int), afterManifestWrite
        case afterAcknowledgementValidation, beforeComplete(Int), beforeCommit
    }
    typealias Hook = @Sendable (Boundary) throws -> Void

    /// Closed intent, frozen at construction before even a legacy lock can be
    /// created. The one-shot run cannot change it. Container/bootstrap callers retain
    /// their journal-driven behavior; lifecycle open can only mount INITIALIZED.
    enum Policy: Sendable, Equatable { case journalDriven, requireInitializedStorage, resumeReadOnly }

    let policy: Policy
    private let specification: VMShimProtocol.Specification
    /// Exact host-held launch specification, never supplied by an adoption request.
    var frozenAdoptionSpecification: Data {
        get throws { try Self.adoptionSpecification(specification) }
    }
    /// One canonical representation on enrollment and reconnection. Launch-file
    /// byte integrity is checked separately by RawStorageShimRecovery.
    static func adoptionSpecification(_ specification: VMShimProtocol.Specification) throws -> Data {
        try StorageLifecycleProtocol.encode(specification)
    }
    private let disks: [VMShimHeldDisk]
    private let hook: Hook?
    private let manifestWriteChunkSize: Int
    private let used = Mutex(false)
    private let verifiedBoot = Mutex<VerifiedStorageDiskBoot?>(nil)
    private let verifiedContainer = Mutex<VerifiedContainerBoot?>(nil)

    /// Whole committed container disk inventory, retained independently of the
    /// transaction. No serialized data can construct this capability.
    final class VerifiedContainerBoot: Sendable {
        let containerID: String
        let shimLaunchUUID: String
        let guestBootNonce: String
        let rootExt4UUID: String
        let rootBytes: UInt64
        let initramfsSHA256: String
        private let disks: [VMShimHeldDisk]

        fileprivate init(containerID: String, shimLaunchUUID: String, guestBootNonce: String,
                         rootExt4UUID: String, rootBytes: UInt64, initramfsSHA256: String,
                         disks: [VMShimHeldDisk]) {
            self.containerID = containerID; self.shimLaunchUUID = shimLaunchUUID
            self.guestBootNonce = guestBootNonce; self.rootExt4UUID = rootExt4UUID
            self.rootBytes = rootBytes; self.initramfsSHA256 = initramfsSHA256; self.disks = disks
        }

        func validateHeldDisks() throws -> [VMShimProtocol.FileIdentity] {
            try disks.map { try RawDiskBootTransaction.validateHeldDisk($0, bytes: $0.bytes) }
        }
    }

    func verifiedContainerBoot() throws -> VerifiedContainerBoot {
        guard let result = verifiedContainer.withLock({ $0 }) else { throw Self.failure() }
        _ = try result.validateHeldDisks()
        return result
    }

    /// Not Codable and not constructible outside this file. Only the completed
    /// 4105 exchange can mint this capability; decoded metadata is never authority.
    final class VerifiedStorageDiskBoot: Sendable {
        let binding: DiskInitializationProtocol.Binding
        let initramfsSHA256: String
        let specificationSHA256: String
        let policy: Policy
        private let coldState = Mutex(StorageLifecycleColdClaimState())
        private let disk: VMShimHeldDisk
        private let initializationOperation: String?
        // Owned by the BOOT, not a wrapper: minting another capability cannot
        // reset the first grant/generation/channel claim or the proof counter.
        private struct FreshClaim: Equatable, Sendable {
            let greeting: StorageLifecycleFreshProtocol.Greeting
            let grant: StorageLifecycleProtocol.Grant
            let shimAudit: Data
            let shimUniqueID: UInt64
            let daemonAudit: Data
        }
        private struct FreshState: Sendable {
            var claim: FreshClaim?
            var counter: UInt64 = 0
            var nonce: Data?
        }
        private let freshState = Mutex(FreshState())
        private let lifecycleServiceBootClaimed = Mutex(false)

        /// One private SERVICE boot attempt per verified raw boot, across all
        /// coordinator wrappers. Failure cannot reopen it. Independent of ROOT's
        /// repeatable fresh proofs and their frozen claim/monotonic counter.
        func claimLifecycleServiceBoot() throws {
            try lifecycleServiceBootClaimed.withLock { claimed in
                guard !claimed else { throw RawDiskBootTransaction.failure() }
                claimed = true
            }
        }

        fileprivate func reply(to challenge: StorageLifecycleFreshProtocol.Challenge) throws -> StorageLifecycleFreshProtocol.Reply {
            try challenge.validate()
            let greeting = challenge.greeting
            guard initializationOperation == greeting.operationUUID,
                  binding.shimLaunchUUID == greeting.shimLaunchUUID,
                  binding.guestBootNonce == greeting.guestBootNonce,
                  binding.ext4UUID == greeting.ext4UUID, binding.bytes == greeting.bytes,
                  initramfsSHA256 == greeting.initramfsSHA256,
                  challenge.isFresh(at: UInt64(Date().timeIntervalSince1970 * 1000)) else {
                throw RawDiskBootTransaction.failure()
            }
            let claim = FreshClaim(greeting: greeting, grant: challenge.grant, shimAudit: challenge.shimAudit,
                shimUniqueID: challenge.shimUniqueID, daemonAudit: challenge.daemonAudit)
            try freshState.withLock { state in
                guard state.claim == nil || state.claim == claim,
                      challenge.counter > state.counter, state.nonce != challenge.nonce else {
                    throw RawDiskBootTransaction.failure()
                }
                state.claim = claim; state.counter = challenge.counter; state.nonce = challenge.nonce
            }
            // Consume before any disk I/O, including failed identity checks. No
            // bounded lifetime nonce collection can accidentally reenable a boot.
            let identity = try validateHeldDisk()
            guard greeting.device == identity.device, greeting.inode == identity.inode,
                  greeting.volumeUUID == identity.volumeUUID?.uuidString.lowercased(),
                  challenge.isFresh(at: UInt64(Date().timeIntervalSince1970 * 1000)) else {
                throw RawDiskBootTransaction.failure()
            }
            return try .init(challengeSHA256: challenge.digest)
        }

        fileprivate init(binding: DiskInitializationProtocol.Binding, initramfsSHA256: String, specificationSHA256: String,
                         disk: VMShimHeldDisk, initializationOperation: String?, policy: Policy) {
            self.binding = binding
            self.initramfsSHA256 = initramfsSHA256
            self.specificationSHA256 = specificationSHA256
            self.disk = disk
            self.policy = policy
            self.initializationOperation = initializationOperation
        }

        /// Only this live transaction's actual initialize+sync+commit can yield
        /// fresh provisioning. Mounting an already initialized (or unjournaled)
        /// disk cannot promote its public UUID/metadata into this capability.
        func freshInitialization() throws -> FreshStorageInitialization {
            guard policy == .journalDriven, let operation = initializationOperation else { throw RawDiskBootTransaction.failure() }
            _ = try validateHeldDisk()
            return FreshStorageInitialization(boot: self, operationUUID: operation)
        }

        /// Only a completed, explicitly mount-only 4105 run can enter cold proof.
        func validateColdMount() throws -> VMShimProtocol.FileIdentity {
            try validateRecoveryDisk(purpose: .cold)
        }

        func validateResumeProbe() throws -> VMShimProtocol.FileIdentity {
            try validateRecoveryDisk(purpose: .resumeReadOnly)
        }

        func validateRecoveryDisk(purpose: StorageLifecycleColdShimProtocol.Purpose) throws -> VMShimProtocol.FileIdentity {
            let expectedPolicy: Policy = purpose == .cold ? .requireInitializedStorage : .resumeReadOnly
            guard policy == expectedPolicy, initializationOperation == nil else {
                throw RawDiskBootTransaction.failure()
            }
            let identity = try validateHeldDisk()
            guard case .journal(let record) = try RawDiskInitialization.inspectExisting(
                in: disk.parent, named: disk.name, expectedSize: binding.bytes,
                heldDiskDescriptor: disk.handle.fileDescriptor, createLock: false),
                record.state == .initialized, record.ext4UUID == binding.ext4UUID else {
                throw RawDiskBootTransaction.failure()
            }
            // Read the actual retained description, not a named replacement.
            var superblock = [UInt8](repeating: 0, count: 120)
            guard pread(disk.handle.fileDescriptor, &superblock, superblock.count, 1024) == superblock.count,
                  superblock[56] == 0x53, superblock[57] == 0xef,
                  let uuid = UUID(uuidString: binding.ext4UUID) else { throw RawDiskBootTransaction.failure() }
            var expected = uuid.uuid
            guard withUnsafeBytes(of: &expected, { Array($0) }) == Array(superblock[104..<120]) else {
                throw RawDiskBootTransaction.failure()
            }
            return try validateHeldDisk()
        }

        /// Unsigned local component. The native responder authenticates ROOT first.
        func coldReply(to challenge: StorageLifecycleColdShimProtocol.Challenge) throws -> StorageLifecycleColdShimProtocol.Reply {
            let g = challenge.greeting
            guard g.bootBinding == binding, g.launch.specSHA256 == specificationSHA256,
                  g.launch.initramfsSHA256 == initramfsSHA256 else { throw RawDiskBootTransaction.failure() }
            try coldState.withLock { try $0.accept(challenge, now: UInt64(Date().timeIntervalSince1970 * 1000)) }
            let held = try validateRecoveryDisk(purpose: g.purpose)
            guard held.device == g.heldBackingIdentity.device, held.inode == g.heldBackingIdentity.inode,
                  held.volumeUUID?.uuidString.lowercased() == g.heldBackingIdentity.volumeUUID,
                  challenge.isFresh(at: UInt64(Date().timeIntervalSince1970 * 1000)) else {
                throw RawDiskBootTransaction.failure()
            }
            return try .init(challengeSHA256: challenge.digest)
        }
        func validateColdSeed(_ seed: StorageLifecycleColdShimProtocol.ColdEnrollmentSeed) throws {
            try coldState.withLock { try $0.validate(seed) }
            _ = try validateRecoveryDisk(purpose: seed.purpose)
        }
        func validateColdConfiguration(_ configuration: StorageLifecycleServiceBootProtocol.Configuration) throws {
            try configuration.validate()
            if configuration.action == .resumeOpenTakeover {
                try validateResumeConfiguration(configuration)
                return
            }
            guard configuration.action == .coldOpenTakeover, let signed = configuration.cold else {
                throw RawDiskBootTransaction.failure()
            }
            try coldState.withLock { state in
                guard let claim = state.first, claim.greeting.purpose == .cold else { throw RawDiskBootTransaction.failure() }
                let prepared = try StorageLifecycleColdRootProtocol.Prepared(signedOpen: signed,
                    successorOrigin: claim.greeting.successorOrigin, baseEpoch: claim.baseEpoch)
                guard configuration.rootPublicKey == claim.greeting.rootPublicKey,
                      configuration.signed.grant == claim.unsignedGrant,
                      try prepared.signedOpenSHA256 == claim.signedOpenSHA256,
                      signed.request.launch == claim.greeting.launch else { throw RawDiskBootTransaction.failure() }
            }
            _ = try validateColdMount()
        }

        func validateResumeConfiguration(_ configuration: StorageLifecycleServiceBootProtocol.Configuration) throws {
            try configuration.validate()
            guard configuration.action == .resumeOpenTakeover, let signed = configuration.resume else {
                throw RawDiskBootTransaction.failure()
            }
            try coldState.withLock { state in
                guard let claim = state.first, claim.greeting.purpose == .resumeReadOnly else {
                    throw RawDiskBootTransaction.failure()
                }
                let prepared = try StorageLifecycleResumeRootProtocol.Prepared(signedOpen: signed,
                    successorOrigin: claim.greeting.successorOrigin, baseEpoch: claim.baseEpoch)
                guard configuration.rootPublicKey == claim.greeting.rootPublicKey,
                      configuration.signed.grant == claim.unsignedGrant,
                      try prepared.signedOpenSHA256 == claim.signedOpenSHA256,
                      signed.request.launch == claim.greeting.launch else { throw RawDiskBootTransaction.failure() }
            }
            _ = try validateResumeProbe()
        }

        /// Native fresh responder must already have frozen this EXACT ROOT claim.
        /// This local check cannot authenticate ROOT by itself; only its native
        /// responder calls reply(to:). No historical initialize grant may boot a
        /// new generation merely because the disk and signature still match.
        func validateLifecycleInitialization(_ signed: StorageLifecycleProtocol.SignedGrant,
                                             root: StorageIdentity.RootPublicKey,
                                             binding: StorageIdentity.StoreBinding) throws {
            guard signed.grant.operation == .initialize, signed.isValidSignature(using: root),
                  let claim = freshState.withLock({ $0.claim }), claim.grant == signed.grant,
                  claim.greeting.rootPublicKey == root.publicData, claim.greeting.matches(binding: binding),
                  signed.grant.identity == (try .init(binding: binding, generation: signed.grant.identity.generation)) else {
                throw RawDiskBootTransaction.failure()
            }
            _ = try validateHeldDisk()
        }

        func validateHeldDisk() throws -> VMShimProtocol.FileIdentity {
            try RawDiskBootTransaction.validateHeldDisk(disk, bytes: binding.bytes)
        }

        /// Duplicate the actual retained disk description; never reopen a DTO path.
        func duplicateHeldDisk() throws -> FileHandle {
            _ = try validateHeldDisk()
            let descriptor = fcntl(disk.handle.fileDescriptor, F_DUPFD_CLOEXEC, 0)
            guard descriptor >= 0 else { throw RawDiskBootTransaction.failure() }
            return FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        }
    }

    /// Inactive fresh-v2 prerequisite, local to the trusted shim. This capability
    /// is not Codable, a ROOT receipt, proof of VM exit, or permission to erase a
    /// disk. The future native adapter must independently pin the live shim/boot.
    final class FreshStorageInitialization: Sendable {
        let boot: VerifiedStorageDiskBoot
        let operationUUID: String
        fileprivate init(boot: VerifiedStorageDiskBoot, operationUUID: String) {
            self.boot = boot; self.operationUUID = operationUUID
        }
        func validateHeldDisk() throws -> VMShimProtocol.FileIdentity { try boot.validateHeldDisk() }

        func greeting(storeID: StorageIdentity.StoreID,
                      root: StorageIdentity.RootPublicKey,
                      channelID: String, daemonUniqueID: UInt64) throws -> StorageLifecycleFreshProtocol.Greeting {
            let identity = try validateHeldDisk()
            guard let volume = identity.volumeUUID else { throw RawDiskBootTransaction.failure() }
            return try .init(channelID: channelID, daemonUniqueID: daemonUniqueID, rootPublicKey: root.publicData,
                store: storeID.rawValue, shimLaunchUUID: boot.binding.shimLaunchUUID,
                guestBootNonce: boot.binding.guestBootNonce, operationUUID: operationUUID,
                ext4UUID: boot.binding.ext4UUID, bytes: boot.binding.bytes, initramfsSHA256: boot.initramfsSHA256,
                device: identity.device, inode: identity.inode, volumeUUID: volume.uuidString.lowercased())
        }

        /// INTERNAL unsigned component, not a native authentication boundary.
        /// Caller MUST authenticate and pin the direct native ROOT sender BEFORE
        /// invocation, and compare native own/parent audits plus the channel greeting.
        func reply(to challenge: StorageLifecycleFreshProtocol.Challenge) throws -> StorageLifecycleFreshProtocol.Reply {
            try boot.reply(to: challenge)
        }
    }

    private static func validateHeldDisk(_ disk: VMShimHeldDisk, bytes: UInt64) throws -> VMShimProtocol.FileIdentity {
        let descriptor = disk.handle.fileDescriptor
        let identity = try PersistentFileIdentity.capture(descriptor: descriptor)
        let expected = VMShimProtocol.FileIdentity(device: disk.identity.device, inode: disk.identity.inode,
                                                   volumeUUID: disk.identity.volumeUUID)
        var info = stat()
        guard Darwin.fstat(descriptor, &info) == 0,
              info.st_mode & S_IFMT == S_IFREG, info.st_size >= 0,
              UInt64(info.st_size) == bytes, info.st_nlink == 1,
              identity.device == expected.device, identity.inode == expected.inode,
              identity.volumeUUID == expected.volumeUUID,
              disk.parent.pathStillNamesThisDirectory(),
              try disk.parent.regularFileIdentity(named: disk.name) == identity,
              flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            throw RawDiskBootTransaction.failure()
        }
        return expected
    }

    func verifiedStorageDiskBoot() throws -> VerifiedStorageDiskBoot {
        guard let result = verifiedBoot.withLock({ $0 }) else { throw Self.failure() }
        _ = try result.validateHeldDisk()
        return result
    }

    // Internal fault seams exercise the real durability and socket boundaries.
    // Production uses an unbounded write and no hook; neither enables replay.
    init(specification: VMShimProtocol.Specification, disks: [VMShimHeldDisk],
         policy: Policy = .journalDriven, hook: Hook? = nil, manifestWriteChunkSize: Int = .max) throws {
        guard specification.diskBootstrapVersion == 1,
              let launch = specification.shimLaunchUUID,
              DiskInitializationProtocol.validUUID(launch),
              !specification.rootDiskReadOnly,
              !disks.isEmpty, disks.count <= 26,
              disks.count == specification.volumeDisks.count + 1,
              manifestWriteChunkSize > 0,
              specification.kind == .container || disks.count == 1 else { throw Self.failure() }
        self.specification = specification
        self.policy = policy
        self.disks = disks
        self.hook = hook
        self.manifestWriteChunkSize = manifestWriteChunkSize
        _ = try preflight(policy: policy)
    }

    private static func failure() -> EngineError {
        EngineError(.conflict, "disk bootstrap transaction refused")
    }

    private func preflight(policy: Policy = .journalDriven) throws -> [RawDiskInitialization.Inspection] {
        if policy != .journalDriven {
            guard specification.kind == .storage, disks.count == 1 else { throw Self.failure() }
        }
        var names = Set<String>()
        var identities = Set<String>()
        return try disks.enumerated().map { index, disk in
            let volume = index == 0 ? nil : specification.volumeDisks[index - 1]
            let path = volume?.path ?? specification.rootDiskPath
            let expectedIdentity = volume?.identity ?? (index == 0 ? specification.rootDiskIdentity : nil)
            let expectedBytes = volume?.size ?? (index == 0 ? specification.rootDiskSize : nil)
            let role = index == 0 ? (specification.kind == .container ? "container-root" : "storage-root") : "direct-volume"
            let captured = try PersistentFileIdentity.capture(descriptor: disk.handle.fileDescriptor)
            // Do not use PersistentFileIdentity ==: it intentionally ignores the
            // boot-local device number when a volume UUID is available.
            func exact(_ identity: PersistentFileIdentity) -> VMShimProtocol.FileIdentity {
                .init(device: identity.device, inode: identity.inode, volumeUUID: identity.volumeUUID)
            }
            guard disk.ordinal == index, disk.role == role, disk.volumeName == volume?.name,
                  disk.bytes > 0, disk.bytes <= UInt64(Int64.max), expectedBytes == disk.bytes,
                  expectedIdentity?.volumeUUID != nil, expectedIdentity == exact(disk.identity),
                  exact(captured) == exact(disk.identity),
                  URL(filePath: path).standardizedFileURL == disk.parent.url.appending(path: disk.name).standardizedFileURL,
                  identities.insert("\(captured.device):\(captured.inode):\(captured.volumeUUID!)").inserted else {
                throw Self.failure()
            }
            if let name = disk.volumeName {
                guard !name.isEmpty, name.utf8.count <= 255,
                      name.utf8.first.map({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) }) == true,
                      name.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [45, 46, 95].contains($0) }),
                      names.insert(name).inserted else { throw Self.failure() }
            }
            let state = try RawDiskInitialization.inspectExisting(
                in: disk.parent, named: disk.name, expectedSize: disk.bytes,
                heldDiskDescriptor: disk.handle.fileDescriptor,
                createLock: policy == .journalDriven
            )
            if policy != .journalDriven {
                guard case .journal(let record) = state, record.state == .initialized else {
                    throw Self.failure()
                }
            }
            switch state {
            case .quarantined: throw Self.failure()
            case .journal(let record):
                guard record.state != .spent else { throw Self.failure() }
                if record.state == .created {
                    guard disk.bytes >= 16 << 20, disk.bytes % 4096 == 0 else { throw Self.failure() }
                }
            case .mountOnly: break
            }
            return state
        }
    }

    /// Blocking socket/durability work runs off MainActor. Cancellation interrupts
    /// poll/read/write, and the caller settles this worker before stopping VZ.
    /// Dispatch workers supply a synchronized flag instead of Task-local state.
    func run(descriptor: Int32, policy requestedPolicy: Policy? = nil,
             isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled }) throws {
        guard used.withLock({ value in if value { return false }; value = true; return true }) else { throw Self.failure() }
        guard requestedPolicy == nil || requestedPolicy == policy else { throw Self.failure() }
        // The connected 4105 descriptor is borrowed exclusively until this
        // worker settles. Preserve its other flags and restore the caller's mode.
        // MSG_DONTWAIT alone can block Darwin send past cancellation.
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else { throw Self.failure() }
        defer { _ = fcntl(descriptor, F_SETFL, flags) }
        let transport = Transport(descriptor: descriptor, isCancelled: isCancelled)
        let hello = try transport.readReply(DiskInitializationProtocol.Hello.self, diskCount: disks.count)
        guard hello.kind == specification.kind.rawValue,
              DiskInitializationProtocol.validUUID(hello.guestBootNonce),
              hello.disks.count == disks.count else { throw Self.failure() }
        for (observed, held) in zip(hello.disks, disks) {
            guard observed.ordinal == held.ordinal, observed.blockIdentifier == held.blockIdentifier,
                  observed.bytes == held.bytes else { throw Self.failure() }
        }
        let states = try preflight(policy: policy)
        try hook?(.afterPreflight)
        let launch = specification.shimLaunchUUID!
        let binding = RawDiskInitialization.Binding(
            shimLaunchUUID: UUID(uuidString: launch)!, guestBootNonce: UUID(uuidString: hello.guestBootNonce)!
        )
        var entries: [DiskInitializationProtocol.ManifestDisk] = []
        for (disk, state) in zip(disks, states) {
            try transport.checkCancellation()
            var uuid: String?
            var operation: String?
            if case .journal(let record) = state {
                uuid = record.ext4UUID
                if record.state == .created {
                    try hook?(.beforeConsume(disk.ordinal))
                    try transport.checkCancellation()
                    guard let authorization = try RawDiskInitialization.begin(
                        in: disk.parent, named: disk.name, expectedSize: disk.bytes,
                        binding: binding, heldDiskDescriptor: disk.handle.fileDescriptor
                    ), authorization.record.ext4UUID == record.ext4UUID,
                       authorization.record.operationUUID == record.operationUUID else { throw Self.failure() }
                    operation = authorization.record.operationUUID
                    try hook?(.afterConsumed(disk.ordinal))
                }
            }
            entries.append(.init(ordinal: disk.ordinal, role: disk.role,
                                 action: policy == .resumeReadOnly ? "probe-read-only" : (operation == nil ? "mount-existing-ext4" : "initialize-ext4"),
                                 expectedBytes: disk.bytes, ext4UUID: uuid, operationUUID: operation,
                                 volumeName: disk.volumeName))
        }
        // Every CREATED authorization is consumed before this first write.
        try hook?(.beforeManifestWrite)
        try transport.write(DiskInitializationProtocol.encode(DiskInitializationProtocol.Manifest(
            kind: specification.kind.rawValue, shimLaunchUUID: launch,
            guestBootNonce: hello.guestBootNonce, disks: entries
        )), chunkSize: manifestWriteChunkSize) { count in
            try self.hook?(.manifestBytesWritten(count))
        }
        try hook?(.afterManifestWrite)
        let synced = try transport.readReply(DiskInitializationProtocol.Synced.self, diskCount: disks.count)
        guard synced.shimLaunchUUID == launch, synced.guestBootNonce == hello.guestBootNonce,
              synced.sync == (policy == .resumeReadOnly ? "read-only-no-replay" : "filesystem-and-block"), synced.disks.count == entries.count else { throw Self.failure() }
        // Validate the WHOLE reply before completing any journal.
        for (entry, result) in zip(entries, synced.disks) {
            guard result.ordinal == entry.ordinal, result.bytes == entry.expectedBytes,
                  DiskInitializationProtocol.validUUID(result.ext4UUID),
                  entry.ext4UUID == nil || entry.ext4UUID == result.ext4UUID,
                  entry.operationUUID == result.operationUUID else { throw Self.failure() }
        }
        try hook?(.afterAcknowledgementValidation)
        for (disk, result) in zip(disks, synced.disks) {
            guard let operation = result.operationUUID else { continue }
            try hook?(.beforeComplete(disk.ordinal))
            try transport.checkCancellation()
            try RawDiskInitialization.completeAfterVerifiedGuestSync(
                in: disk.parent, named: disk.name, expectedSize: result.bytes,
                operationUUID: UUID(uuidString: operation)!, ext4UUID: UUID(uuidString: result.ext4UUID)!,
                binding: binding, heldDiskDescriptor: disk.handle.fileDescriptor
            )
        }
        try hook?(.beforeCommit)
        try transport.write(DiskInitializationProtocol.encode(DiskInitializationProtocol.Commit(
            shimLaunchUUID: launch, guestBootNonce: hello.guestBootNonce
        )))
        // The result does not exist on a partial/failed commit. A production
        // storage shim has already hashed this exact pinned initramfs FD prestart.
        if let digest = specification.expectedInitramfsSHA256,
           digest.count == 64, digest.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) {
            let disk = synced.disks[0]
            if specification.kind == .storage {
                let result = VerifiedStorageDiskBoot(
                    binding: .init(shimLaunchUUID: launch, guestBootNonce: hello.guestBootNonce,
                                   ext4UUID: disk.ext4UUID, bytes: disk.bytes),
                    initramfsSHA256: digest,
                    specificationSHA256: SHA256.hash(data: try Self.adoptionSpecification(specification)).map { String(format: "%02x", $0) }.joined(),
                    disk: disks[0], initializationOperation: entries[0].operationUUID, policy: policy)
                _ = try result.validateHeldDisk()
                verifiedBoot.withLock { $0 = result }
            } else {
                let result = VerifiedContainerBoot(containerID: specification.containerID,
                    shimLaunchUUID: launch, guestBootNonce: hello.guestBootNonce,
                    rootExt4UUID: disk.ext4UUID, rootBytes: disk.bytes,
                    initramfsSHA256: digest, disks: disks)
                _ = try result.validateHeldDisks()
                verifiedContainer.withLock { $0 = result }
            }
        }
    }

    private struct Transport {
        let descriptor: Int32
        let isCancelled: @Sendable () -> Bool
        func checkCancellation() throws {
            if isCancelled() { throw CancellationError() }
        }
        func wait(_ events: Int16) throws {
            while true {
                try checkCancellation()
                var item = pollfd(fd: descriptor, events: events, revents: 0)
                let result = Darwin.poll(&item, 1, 100)
                if result < 0 && errno == EINTR { continue }
                guard result >= 0 else { throw Self.error() }
                if result == 0 { continue }
                guard item.revents & events != 0 else { throw Self.error() }
                return
            }
        }
        static func error() -> EngineError { EngineError(.internalError, "disk bootstrap transport failed") }
        func readExactly(_ count: Int) throws -> Data {
            var result = Data(count: count)
            var offset = 0
            while offset < count {
                try wait(Int16(POLLIN))
                let amount = result.withUnsafeMutableBytes {
                    Darwin.recv(descriptor, $0.baseAddress!.advanced(by: offset), count - offset, MSG_DONTWAIT)
                }
                if amount < 0 && [EINTR, EAGAIN].contains(errno) { continue }
                guard amount > 0 else { throw Self.error() }
                offset += amount
            }
            return result
        }
        func readFrame() throws -> Data {
            let prefix = try readExactly(4)
            let count = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            guard count > 0, count <= 65_536 else { throw Self.error() }
            return try readExactly(Int(count))
        }
        func readReply<T: Decodable>(_ type: T.Type, diskCount: Int) throws -> T {
            let body = try readFrame() // Transport errors and cancellation retain their original meaning.
            // The guest may refuse before hello or instead of synced. Only the
            // closed-schema decoder can authorize exposing its fixed code/ordinal.
            if let refusal = try? DiskInitializationProtocol.decode(DiskInitializationProtocol.ErrorFrame.self, from: body) {
                guard refusal.ordinal.map({ (0..<diskCount).contains($0) }) ?? true else {
                    throw EngineError(.internalError, "disk bootstrap guest sent an invalid reply")
                }
                let disk = refusal.ordinal.map { " (disk ordinal \($0))" } ?? ""
                throw EngineError(.conflict, "disk bootstrap guest refused: \(refusal.code)\(disk)")
            }
            do {
                return try DiskInitializationProtocol.decode(type, from: body)
            } catch DiskInitializationProtocol.ValidationError.invalidFrame {
                // Never echo an unvalidated frame or Foundation decoder detail.
                throw EngineError(.internalError, "disk bootstrap guest sent an invalid reply")
            }
        }
        func write(_ data: Data, chunkSize: Int = .max, progress: ((Int) throws -> Void)? = nil) throws {
            var noSignal: Int32 = 1
            guard setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size)) == 0 else { throw Self.error() }
            var offset = 0
            while offset < data.count {
                try wait(Int16(POLLOUT))
                let amount = data.withUnsafeBytes {
                    Darwin.send(descriptor, $0.baseAddress!.advanced(by: offset), min(chunkSize, data.count - offset), MSG_DONTWAIT)
                }
                if amount < 0 && [EINTR, EAGAIN].contains(errno) { continue }
                guard amount > 0 else { throw Self.error() }
                offset += amount
                try progress?(offset)
            }
        }
    }
}
#endif

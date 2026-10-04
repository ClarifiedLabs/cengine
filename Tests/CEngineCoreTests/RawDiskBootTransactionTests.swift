#if os(macOS)
import CEngineCore
import CryptoKit
import Darwin
import Foundation
import Synchronization
import Testing
@testable import CEngineRuntime
@preconcurrency import XPC

@_silgen_name("xpc_dictionary_get_audit_token")
private func freshTestMessageAudit(_ message: xpc_object_t, _ token: UnsafeMutablePointer<audit_token_t>)

// Each case owns blocking peer I/O plus durable disk syncs; keep fault fixtures
// serial so the full test run cannot starve their transport workers.
@Suite(.serialized) struct RawDiskBootTransactionTests {
    @Test @MainActor func adoptionValidatesCanonicalFrozenSpecNotLaunchFileEncoding() throws {
        let fixture = try BootFixture(kind: .storage)
        defer { fixture.remove() }
        var specification = fixture.specification
        let transaction = try RawDiskBootTransaction(specification: specification, disks: fixture.disks)
        let frozen = try transaction.frozenAdoptionSpecification
        // Launch publication intentionally uses ordinary JSONEncoder. ROOT
        // enrollment uses canonical JSON, including unescaped absolute paths.
        let launchBytes = try JSONEncoder().encode(specification)
        #expect(launchBytes != frozen)
        let decoded = try JSONDecoder().decode(VMShimProtocol.Specification.self, from: launchBytes)
        let launch = try #require(specification.shimLaunchUUID)
        let identity = fixture.disks[0].identity
        let uuid = try StorageIdentity.FilesystemUUID(fixture.originals[0].ext4UUID)
        let binding = try StorageIdentity.StoreBinding(storeID: .init(launch),
            root: .init(volumeUUID: uuid, inode: 2),
            backing: .init(identity: .init(volumeUUID: uuid, inode: 3), size: 32 << 20),
            expectedExt4UUID: uuid)
        let record = RawStorageShimRecovery.LaunchRecord(intent: .init(schemaVersion: 1,
            protocolVersion: VMShimProtocol.version, launchUUID: launch,
            specificationSHA256: RawStorageShimRecovery.digest(launchBytes),
            storeIdentity: identity, generationIdentity: identity),
            process: .init(pid: getpid(), startSeconds: 1, startMicroseconds: 0, bootUUID: launch, uniqueID: 42))
        func status(hash: String) throws -> StorageLifecycleAdoptionRootProtocol.Status {
            try .init(origin: .init(binding: .init(binding), rootPublicKey: Data(repeating: 7, count: 32),
                shimLaunchUUID: launch, specSHA256: hash), shimAudit: Data(repeating: 3, count: 32),
                shimUniqueID: 42, baseEpoch: 1, committedEpoch: 1, allocatedEpoch: 1, pending: nil, latest: nil)
        }
        let enrolled = try status(hash: RawStorageShimRecovery.digest(frozen))
        let published = RawStorageShimRecovery.Generation(specification: decoded, data: launchBytes, record: record)
        try ManagedLifecycleProductionStartup.validateSurvivingGeneration(published, status: enrolled)
        #expect(throws: (any Error).self) {
            try ManagedLifecycleProductionStartup.validateSurvivingGeneration(published,
                status: status(hash: RawStorageShimRecovery.digest(launchBytes)))
        }
        var changed = decoded
        changed.socketPath += ".changed"
        #expect(throws: (any Error).self) {
            try ManagedLifecycleProductionStartup.validateSurvivingGeneration(
                .init(specification: changed, data: launchBytes, record: record), status: enrolled)
        }
    }

    @Test func storageBootWorkerJoinsWatchdogCancellationBeforeCleanup() throws {
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let operation = DispatchSemaphore(value: 0)
        let cancelled = Mutex(false)
        let worker = StorageBootWorker(cancel: {
            operation.signal()
            entered.signal()
            // Hold an already-running watchdog after the operation can finish.
            precondition(release.wait(timeout: .now() + 15) == .success)
            cancelled.withLock { $0 = true }
        }, watchdogTimeout: .now()) {
            precondition(operation.wait(timeout: .now() + 15) == .success)
        }
        defer { release.signal(); worker.settle() }
        try #require(worker.waitForStart(entered))
        try #require(worker.finishedWithin(3))
        #expect(!cancelled.withLock { $0 })
        release.signal()
        worker.settle()
        #expect(cancelled.withLock { $0 })
    }

    @Test func partialDiskManifestWriteCanBeCancelledWithoutCommitting() async throws {
        let fixture = try BootFixture(directVolumeCount: 25)
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        try bootTestLimitSendBuffer(pair.host.fileDescriptor)
        let cancelled = Mutex(false)
        let manifestReady = DispatchSemaphore(value: 0)
        let transaction = try RawDiskBootTransaction(specification: fixture.specification, disks: fixture.disks, hook: {
            if $0 == .beforeManifestWrite { manifestReady.signal() }
        })
        let worker = StorageBootWorker(cancel: {
            cancelled.withLock { $0 = true }
            _ = shutdown(pair.host.fileDescriptor, SHUT_RDWR) // Watchdog cleanup only.
        }) {
            try transaction.run(descriptor: pair.host.fileDescriptor, isCancelled: { cancelled.withLock { $0 } })
        }
        defer { worker.settle() }
        try pair.send(fixture.hello())
        // The short socket bound measures a partial write, not 26 durable
        // journal consumptions competing with the rest of the test process.
        try #require(worker.waitForStart(manifestReady, seconds: 15))
        let prefix = try bootTestReadPrefix(pair.guest.fileDescriptor)
        #expect(prefix > 4_096)
        cancelled.withLock { $0 = true } // Leave peer alive and stop draining it.
        let bounded = worker.finishedWithin(3)
        #expect(bounded, "partial manifest send ignored cancellation")
        if !bounded { _ = shutdown(pair.host.fileDescriptor, SHUT_RDWR) }
        do { try await worker.result(); Issue.record("partial manifest committed") }
        catch { #expect(error is CancellationError) }
        #expect(fcntl(pair.host.fileDescriptor, F_GETFL) & O_NONBLOCK == 0)
        try fixture.expectStates(Array(repeating: .spent, count: fixture.disks.count))
        fixture.expectNewBootRefused()
        #expect(throws: (any Error).self) { _ = try transaction.verifiedContainerBoot() }
    }

    @Test func workerOwnsDescriptorAfterCallerClosesItsHandle() async throws {
        let fixture = try BootFixture()
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        let transaction = try RawDiskBootTransaction(specification: fixture.specification, disks: fixture.disks)
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.host.close()
        try pair.send(fixture.hello())
        let manifest = try pair.manifest()
        try pair.send(fixture.synced(manifest))
        _ = try pair.commit()
        try await worker.result().get()
        try fixture.expectStates([.initialized, .initialized])
    }

    @Test func wholeBatchIsConsumedBeforeFirstManifestByte() async throws {
        let fixture = try BootFixture()
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        let boundaries = Mutex<[RawDiskBootTransaction.Boundary]>([])
        let transaction = try RawDiskBootTransaction(specification: fixture.specification, disks: fixture.disks, hook: { boundary in
            boundaries.withLock { $0.append(boundary) }
            if boundary == .beforeManifestWrite {
                try fixture.expectStates([.spent, .spent])
                // This checks the socket, not merely the decoded manifest.
                try pair.expectNoBytesAvailable()
            }
        }, manifestWriteChunkSize: 7)
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.send(fixture.hello())
        let manifest = try pair.manifest()
        #expect(manifest.disks.map(\.action) == ["initialize-ext4", "initialize-ext4"])
        #expect(manifest.disks.map(\.ext4UUID) == fixture.originals.map { Optional($0.ext4UUID) })
        try pair.send(fixture.synced(manifest))
        let commit = try pair.commit()
        #expect(commit.shimLaunchUUID == fixture.specification.shimLaunchUUID)
        #expect(commit.guestBootNonce == fixture.nonce)
        try await worker.result().get()
        try fixture.expectStates([.initialized, .initialized])
        let observed = boundaries.withLock { $0 }
        #expect(Array(observed.prefix(6)) == [.afterPreflight, .beforeConsume(0), .afterConsumed(0),
                                            .beforeConsume(1), .afterConsumed(1), .beforeManifestWrite])
        #expect(observed[6] == .manifestBytesWritten(7))
        #expect(Array(observed.suffix(4)) == [.afterAcknowledgementValidation, .beforeComplete(0), .beforeComplete(1), .beforeCommit])
        #expect(throws: (any Error).self) { try transaction.run(descriptor: pair.host.fileDescriptor) }
    }

    @Test(arguments: ["version", "type", "kind", "nonce", "count", "ordinal", "block-identifier", "size", "zero-size"])
    func invalidHelloSendsNothingAndLeavesJournalsUnchanged(fault: String) async throws {
        let fixture = try BootFixture()
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        let before = try fixture.journalSnapshot()
        let transaction = try RawDiskBootTransaction(specification: fixture.specification, disks: fixture.disks, hook: { _ in
            Issue.record("invalid hello reached a transaction boundary")
        })
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        var hello = fixture.hello()
        switch fault {
        case "version": hello.version += 1
        case "type": hello.type = "synced"
        case "kind": hello.kind = "storage"; hello.disks.removeLast()
        case "nonce": hello.guestBootNonce = "00000000-0000-0000-0000-000000000000"
        case "count": hello.disks.removeLast()
        case "ordinal": hello.disks[1].ordinal = 0
        case "block-identifier": hello.disks[1].blockIdentifier = "volume1"
        case "size": hello.disks[1].bytes += 4096
        case "zero-size": hello.disks[1].bytes = 0
        default: Issue.record("unhandled fault")
        }
        try pair.sendUnchecked(hello)
        expectNonCancellationFailure(await worker.result())
        #expect(try pair.remainingBytes().isEmpty)
        #expect(try fixture.journalSnapshot() == before)
        try fixture.expectStates([.created, .created])
    }

    @Test(arguments: ["zero-length", "oversized", "overflow", "partial-prefix", "partial-body", "invalid-json"])
    func malformedHelloFrameSendsNothingAndLeavesJournalsUnchanged(fault: String) async throws {
        let fixture = try BootFixture()
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        let before = try fixture.journalSnapshot()
        let transaction = try RawDiskBootTransaction(specification: fixture.specification, disks: fixture.disks, hook: { _ in
            Issue.record("malformed frame reached a transaction boundary")
        })
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        let hello = try DiskInitializationProtocol.encode(fixture.hello())
        let bytes: Data
        switch fault {
        case "zero-length": bytes = Data([0, 0, 0, 0])
        case "oversized": bytes = Data([0, 1, 0, 1])
        case "overflow": bytes = Data([255, 255, 255, 255])
        case "partial-prefix": bytes = Data(hello.prefix(2))
        case "partial-body": bytes = Data(hello.dropLast())
        default: bytes = Data([0, 0, 0, 1, 123]) // A lone JSON opening brace.
        }
        try pair.guest.write(contentsOf: bytes)
        if fault == "partial-prefix" || fault == "partial-body" {
            #expect(shutdown(pair.guest.fileDescriptor, SHUT_WR) == 0)
        }
        let result = await worker.result()
        if fault == "invalid-json" { expectNonCancellationFailure(result) }
        else { expectTransportFailure(result) }
        #expect(try pair.remainingBytes().isEmpty)
        #expect(try fixture.journalSnapshot() == before)
        try fixture.expectStates([.created, .created])
    }

    @Test func unjournaledDisksMountWithoutCreatingInitializationAuthority() async throws {
        let fixture = try BootFixture()
        defer { fixture.remove() }
        // Simulate pre-existing, unjournaled disks. The host must not infer
        // permission to initialize from their contents, even when they are blank.
        for disk in fixture.disks {
            try FileManager.default.removeItem(at: fixture.root.appending(path: ".raw-init-\(disk.name).created.json"))
        }
        let before = try fixture.journalSnapshot()
        let pair = try BootSocketPair()
        defer { pair.close() }
        let transaction = try RawDiskBootTransaction(specification: fixture.specification, disks: fixture.disks, hook: {
            if case .beforeConsume = $0 { Issue.record("unjournaled disk was consumed") }
            if case .beforeComplete = $0 { Issue.record("unjournaled disk was completed") }
        })
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.send(fixture.hello())
        let manifest = try pair.manifest()
        #expect(manifest.disks.map(\.action) == ["mount-existing-ext4", "mount-existing-ext4"])
        #expect(manifest.disks.allSatisfy { $0.ext4UUID == nil && $0.operationUUID == nil })
        let synced = DiskInitializationProtocol.Synced(
            shimLaunchUUID: manifest.shimLaunchUUID, guestBootNonce: manifest.guestBootNonce,
            disks: manifest.disks.map { .init(ordinal: $0.ordinal, bytes: $0.expectedBytes,
                                              ext4UUID: UUID().uuidString.lowercased()) }
        )
        try pair.send(synced)
        let commit = try pair.commit()
        #expect(commit.shimLaunchUUID == fixture.specification.shimLaunchUUID)
        #expect(commit.guestBootNonce == fixture.nonce)
        try await worker.result().get()
        #expect(try fixture.journalSnapshot() == before)
        for disk in fixture.disks {
            #expect(try RawDiskInitialization.inspectExisting(in: disk.parent, named: disk.name,
                expectedSize: disk.bytes, heldDiskDescriptor: disk.handle.fileDescriptor) == .mountOnly)
        }
    }

    @Test(arguments: ["created", "spent", "unjournaled", "missing-metadata", "missing-lock", "missing-disk",
                      "pending", "malformed", "incomplete-initialized"], [false, true])
    func lifecycleOpenRefusesBeforeAnyMutationOrManifest(fault: String, resume: Bool) async throws {
        let fixture = try BootFixture(kind: .storage)
        defer { fixture.remove() }
        _ = try await fixture.storageProof()
        // Construct before changing metadata: the actual run must preflight the
        // selected open intent, not trust an earlier constructor inspection.
        let transaction = try RawDiskBootTransaction(specification: fixture.specification, disks: fixture.disks,
            policy: resume ? .resumeReadOnly : .requireInitializedStorage, hook: { _ in
            Issue.record("refused lifecycle open reached a mutation/manifest boundary")
        })
        let disk = fixture.disks[0]
        let prefix = ".raw-init-\(disk.name)"
        switch fault {
        case "created":
            try FileManager.default.removeItem(at: fixture.root.appending(path: prefix + ".initialized.json"))
            try FileManager.default.removeItem(at: fixture.root.appending(path: prefix + ".spent.json"))
        case "spent":
            try FileManager.default.removeItem(at: fixture.root.appending(path: prefix + ".initialized.json"))
        case "unjournaled":
            for suffix in [".created.json", ".spent.json", ".initialized.json"] {
                try FileManager.default.removeItem(at: fixture.root.appending(path: prefix + suffix))
            }
        case "missing-metadata":
            for name in try fixture.journalSnapshot().keys {
                try FileManager.default.removeItem(at: fixture.root.appending(path: name))
            }
        case "missing-lock":
            try FileManager.default.removeItem(at: fixture.root.appending(path: prefix + ".lock"))
        case "missing-disk":
            try FileManager.default.removeItem(at: fixture.root.appending(path: disk.name))
        case "pending":
            try Data("incomplete".utf8).write(to: fixture.root.appending(path: prefix + ".spent.json.pending"))
        case "malformed":
            try Data("{}".utf8).write(to: fixture.root.appending(path: prefix + ".created.json"))
        case "incomplete-initialized":
            try FileManager.default.removeItem(at: fixture.root.appending(path: prefix + ".spent.json"))
        default: Issue.record("unhandled fault")
        }
        let before = try fixture.fileSnapshot()
        let pair = try BootSocketPair()
        defer { pair.close() }
        let policy: RawDiskBootTransaction.Policy = resume ? .resumeReadOnly : .requireInitializedStorage
        let worker = try BootWorker(transaction, host: pair.host, policy: policy)
        defer { worker.cancel() }
        try pair.send(fixture.hello())
        expectNonCancellationFailure(await worker.result())
        #expect(try pair.remainingBytes().isEmpty) // Not even an initialize manifest prefix.
        #expect(try fixture.fileSnapshot() == before) // Disk bytes and every sidecar/name.
        #expect(throws: (any Error).self) { _ = try transaction.verifiedStorageDiskBoot() }
        // A refused one-shot open cannot be retried with the provisioning default.
        #expect(throws: (any Error).self) { try transaction.run(descriptor: pair.host.fileDescriptor) }
        #expect(try fixture.fileSnapshot() == before)
    }

    @Test(arguments: ["created", "spent", "missing-lock", "legacy-no-lock"], [false, true])
    func mountOnlyConstructionNeverCreatesMetadata(fault: String, resume: Bool) throws {
        let fixture = try BootFixture(kind: .storage)
        defer { fixture.remove() }
        let disk = fixture.disks[0], prefix = ".raw-init-\(fixture.disks[0].name)"
        if fault == "spent" {
            _ = try RawDiskInitialization.begin(in: disk.parent, named: disk.name, expectedSize: disk.bytes,
                binding: .init(shimLaunchUUID: UUID(), guestBootNonce: UUID()), heldDiskDescriptor: disk.handle.fileDescriptor)
        }
        if fault == "missing-lock" || fault == "legacy-no-lock" {
            try FileManager.default.removeItem(at: fixture.root.appending(path: prefix + ".lock"))
        }
        if fault == "legacy-no-lock" {
            try FileManager.default.removeItem(at: fixture.root.appending(path: prefix + ".created.json"))
        }
        let before = try fixture.fileSnapshot()
        #expect(throws: (any Error).self) {
            _ = try RawDiskBootTransaction(specification: fixture.specification, disks: fixture.disks,
                policy: resume ? .resumeReadOnly : .requireInitializedStorage)
        }
        #expect(try fixture.fileSnapshot() == before)
    }

    @Test func lifecycleOpenMountsInitializedStorageWithoutFreshCapability() async throws {
        let fixture = try BootFixture(kind: .storage)
        defer { fixture.remove() }
        let initialized = try await fixture.storageProof()
        _ = try initialized.freshInitialization() // The unchanged initialize path still works.
        #expect(throws: (any Error).self) { _ = try initialized.validateColdMount() }
        // Minimal ext4 identity header: production reads the real mounted disk.
        var superblock = [UInt8](repeating: 0, count: 120)
        superblock[56] = 0x53; superblock[57] = 0xef
        var uuid = try #require(UUID(uuidString: initialized.binding.ext4UUID)).uuid
        superblock.replaceSubrange(104..<120, with: withUnsafeBytes(of: &uuid) { Array($0) })
        try #require(pwrite(fixture.disks[0].handle.fileDescriptor, superblock, superblock.count, 1024) == superblock.count)
        let before = try fixture.fileSnapshot()
        var specification = fixture.specification
        specification.expectedInitramfsSHA256 = storageBootTestSHA256
        let transaction = try RawDiskBootTransaction(specification: specification, disks: fixture.disks,
            policy: .requireInitializedStorage, hook: {
            if case .beforeConsume = $0 { Issue.record("open consumed initialization authority") }
            if case .beforeComplete = $0 { Issue.record("open rewrote initialization journal") }
        })
        let pair = try BootSocketPair()
        defer { pair.close() }
        let worker = try BootWorker(transaction, host: pair.host,
            policy: RawContainerVirtualMachine.StorageLifecycleDiskMode.open.bootstrapPolicy)
        defer { worker.cancel() }
        try pair.send(fixture.hello())
        let manifest = try pair.manifest()
        #expect(manifest.disks.count == 1)
        #expect(manifest.disks[0].action == "mount-existing-ext4")
        #expect(manifest.disks[0].operationUUID == nil)
        #expect(manifest.disks[0].ext4UUID == initialized.binding.ext4UUID)
        #expect(throws: (any Error).self) { _ = try transaction.verifiedStorageDiskBoot() }
        try pair.send(fixture.synced(manifest))
        _ = try pair.commit()
        try await worker.result().get()
        let mounted = try transaction.verifiedStorageDiskBoot()
        #expect(mounted.policy == .requireInitializedStorage)
        _ = try mounted.validateColdMount()
        #expect(try mounted.validateHeldDisk() == specification.rootDiskIdentity)
        #expect(mounted.binding.ext4UUID == initialized.binding.ext4UUID)
        #expect(mounted.specificationSHA256 == RawStorageShimRecovery.digest(try transaction.frozenAdoptionSpecification))
        #expect(throws: (any Error).self) { _ = try mounted.freshInitialization() }
        #expect(try fixture.fileSnapshot() == before)
    }

    @Test(arguments: [false, true])
    func resumeProbeRequiresExactReadOnlyAcknowledgement(writableAcknowledgement: Bool) async throws {
        let fixture = try BootFixture(kind: .storage)
        defer { fixture.remove() }
        let initialized = try await fixture.storageProof()
        var superblock = [UInt8](repeating: 0, count: 120)
        superblock[56] = 0x53; superblock[57] = 0xef
        var uuid = try #require(UUID(uuidString: initialized.binding.ext4UUID)).uuid
        superblock.replaceSubrange(104..<120, with: withUnsafeBytes(of: &uuid) { Array($0) })
        try #require(pwrite(fixture.disks[0].handle.fileDescriptor, superblock, superblock.count, 1024) == superblock.count)
        let before = try fixture.fileSnapshot()
        var specification = fixture.specification
        specification.expectedInitramfsSHA256 = storageBootTestSHA256
        let transaction = try RawDiskBootTransaction(specification: specification, disks: fixture.disks,
            policy: .resumeReadOnly, hook: {
                if case .beforeConsume = $0 { Issue.record("resume consumed initialization authority") }
                if case .beforeComplete = $0 { Issue.record("resume rewrote initialization journal") }
            })
        let pair = try BootSocketPair()
        defer { pair.close() }
        let worker = try BootWorker(transaction, host: pair.host, policy: .resumeReadOnly)
        defer { worker.cancel() }
        try pair.send(fixture.hello())
        let manifest = try pair.manifest()
        #expect(manifest.disks.count == 1)
        #expect(manifest.disks[0].action == "probe-read-only")
        #expect(manifest.disks[0].operationUUID == nil)
        #expect(manifest.disks[0].ext4UUID == initialized.binding.ext4UUID)
        #expect(throws: (any Error).self) { _ = try transaction.verifiedStorageDiskBoot() }
        var synced = fixture.synced(manifest)
        synced.sync = writableAcknowledgement ? "filesystem-and-block" : "read-only-no-replay"
        try pair.send(synced)
        if writableAcknowledgement {
            expectNonCancellationFailure(await worker.result())
            #expect(try pair.remainingBytes().isEmpty)
            #expect(throws: (any Error).self) { _ = try transaction.verifiedStorageDiskBoot() }
        } else {
            _ = try pair.commit()
            try await worker.result().get()
            let probe = try transaction.verifiedStorageDiskBoot()
            _ = try probe.validateResumeProbe()
            #expect(probe.policy == .resumeReadOnly)
            #expect(throws: (any Error).self) { _ = try probe.freshInitialization() }
            #expect(throws: (any Error).self) { _ = try probe.validateColdMount() }
            try validateResumeClaim(probe, descriptor: pair.host.fileDescriptor)
        }
        #expect(try fixture.fileSnapshot() == before)
    }

    /// Exercises only the unsigned capability component. Production can invoke it
    /// only after the retained native channel independently authenticates ROOT.
    private func validateResumeClaim(_ probe: RawDiskBootTransaction.VerifiedStorageDiskBoot, descriptor: Int32) throws {
        typealias L = StorageLifecycleProtocol
        typealias R = StorageLifecycleResumeRootProtocol
        typealias S = StorageLifecycleColdShimProtocol
        let key = Curve25519.Signing.PrivateKey()
        let held = try probe.validateResumeProbe()
        let uuid = try StorageIdentity.FilesystemUUID(probe.binding.ext4UUID)
        let binding = StorageIdentity.StoreBinding(storeID: try .init(UUID().uuidString.lowercased()),
            root: try .init(volumeUUID: uuid, inode: 2),
            backing: try .init(identity: .init(volumeUUID: .init(held.volumeUUID!.uuidString.lowercased()),
                inode: held.inode), size: probe.binding.bytes), expectedExt4UUID: uuid)
        let identity = try L.Identity(binding: binding, generation: 1)
        let original = try L.Grant(operation: .initialize, id: UUID().uuidString.lowercased(), identity: identity,
            serial: 1, expectedEpoch: 0, newKey: String(repeating: "a", count: 64))
        let grant = try L.Grant(operation: .takeover, id: UUID().uuidString.lowercased(), identity: identity,
            serial: 2, expectedEpoch: 1, newKey: String(repeating: "b", count: 64))
        let signed = try L.SignedGrant(grant: grant, signature: key.signature(for: grant.signingBytes))
        let launch = try StorageLifecycleColdProtocol.Launch(shimLaunchUUID: probe.binding.shimLaunchUUID,
            specSHA256: probe.specificationSHA256, initramfsSHA256: probe.initramfsSHA256,
            ext4UUID: probe.binding.ext4UUID, bytes: probe.binding.bytes)
        let greeting = try S.Greeting(channelID: UUID().uuidString.lowercased(), daemonUniqueID: 10,
            rootPublicKey: key.publicKey.rawRepresentation, binding: .init(binding), bootBinding: probe.binding,
            launch: launch, heldBackingIdentity: .init(.init(stableIdentity: binding.backing.identity, device: held.device)), purpose: .resumeReadOnly)
        func configuration(now: UInt64) throws -> StorageLifecycleServiceBootProtocol.Configuration {
            let request = try StorageLifecycleResumeProtocol.Request(operationID: grant.id, original: original,
                takeover: signed, launch: launch, nowUnixSeconds: now, lifetimeSeconds: 60)
            return .init(action: .resumeOpenTakeover, rootPublicKey: key.publicKey.rawRepresentation, signed: signed,
                nowUnixSeconds: now, lifetimeSeconds: 60,
                resume: try .init(request: request, signature: key.signature(for: request.signingBytes)))
        }
        let now = UInt64(Date().timeIntervalSince1970), cfg = try configuration(now: now)
        let prepared = try R.Prepared(signedOpen: #require(cfg.resume), successorOrigin: greeting.successorOrigin, baseEpoch: 1)
        #expect(throws: (any Error).self) { try probe.validateResumeConfiguration(cfg) }
        #expect(throws: (any Error).self) {
            try PrivateStorageLifecycleBootCoordinator(verified: probe, configuration: cfg, descriptor: descriptor)
        }
        let challenge = try S.Challenge(greeting: greeting, prepareSHA256: String(repeating: "c", count: 64),
            unsignedGrant: grant, signedOpenSHA256: prepared.signedOpenSHA256, baseEpoch: 1,
            shimAudit: Data(repeating: 1, count: 32), shimUniqueID: 20,
            daemonAudit: Data(repeating: 2, count: 32), daemonUniqueID: 10, counter: 1,
            nonce: Data(repeating: 3, count: 32), expiresUnixMS: UInt64(Date().timeIntervalSince1970 * 1000) + 20_000)
        #expect(try probe.coldReply(to: challenge).verifies(challenge))
        try probe.validateResumeConfiguration(cfg)
        let coordinator = try PrivateStorageLifecycleBootCoordinator(verified: probe, configuration: cfg, descriptor: descriptor)
        coordinator.close()
        #expect(throws: (any Error).self) { try probe.validateResumeConfiguration(configuration(now: now + 1)) }
        let seed = try S.ColdEnrollmentSeed(operationID: grant.id, signedOpenSHA256: prepared.signedOpenSHA256,
            successorOrigin: greeting.successorOrigin, baseEpoch: 1, purpose: .resumeReadOnly)
        try probe.validateColdSeed(seed)
    }

    @Test func storageRootInitializesAndCommits() async throws {
        let fixture = try BootFixture(kind: .storage)
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        let transaction = try RawDiskBootTransaction(specification: fixture.specification, disks: fixture.disks, hook: {
            if $0 == .beforeManifestWrite { try fixture.expectStates([.spent]) }
            if $0 == .beforeCommit { try fixture.expectStates([.initialized]) }
        })
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.send(fixture.hello())
        let manifest = try pair.manifest()
        #expect(manifest.kind == "storage")
        #expect(manifest.disks.count == 1)
        let disk = try #require(manifest.disks.first)
        #expect(disk.role == "storage-root")
        #expect(disk.action == "initialize-ext4")
        #expect(disk.volumeName == nil)
        #expect(disk.ext4UUID == fixture.originals[0].ext4UUID)
        #expect(disk.operationUUID == fixture.originals[0].operationUUID)
        try pair.send(fixture.synced(manifest))
        let commit = try pair.commit()
        #expect(commit.shimLaunchUUID == fixture.specification.shimLaunchUUID)
        #expect(commit.guestBootNonce == fixture.nonce)
        try await worker.result().get()
        try fixture.expectStates([.initialized])
    }

    @Test(arguments: [0, 1])
    func consumptionFailureSendsZeroManifestBytes(ordinal: Int) async throws {
        let fixture = try BootFixture()
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        let transaction = try RawDiskBootTransaction(specification: fixture.specification, disks: fixture.disks, hook: { boundary in
            if boundary == .beforeConsume(ordinal) { throw BootFault.injected }
        })
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.send(fixture.hello())
        let result = await worker.result()
        expectInjected(result)
        #expect(try pair.remainingBytes().isEmpty)
        try fixture.expectStates(ordinal == 0 ? [.created, .created] : [.spent, .created])
        #expect(throws: (any Error).self) { try transaction.run(descriptor: pair.host.fileDescriptor) }
        if ordinal == 1 { fixture.expectNewBootRefused() }
    }

    @Test(arguments: [0, 1])
    func changedSidecarMakesRealConsumptionFailBeforeAnyManifestByte(ordinal: Int) async throws {
        let fixture = try BootFixture()
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        let disk = fixture.disks[ordinal]
        let lock = fixture.root.appending(path: ".raw-init-\(disk.name).lock")
        let backup = fixture.root.appending(path: "original-lock")
        let reachedConsumption = Mutex(false)
        let transaction = try RawDiskBootTransaction(specification: fixture.specification, disks: fixture.disks, hook: {
            if $0 == .beforeConsume(ordinal) {
                try FileManager.default.moveItem(at: lock, to: backup)
                guard FileManager.default.createFile(atPath: lock.path, contents: Data(), attributes: [.posixPermissions: 0o600]) else {
                    throw POSIXError(.EIO)
                }
                reachedConsumption.withLock { $0 = true }
                // Return normally: it is begin(), not the hook, that must fail.
            }
        })
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.send(fixture.hello())
        let result = await worker.result()
        guard case .failure(let error) = result else { Issue.record("changed lock was accepted"); return }
        #expect(error as? RawDiskInitialization.Failure == .quarantined)
        #expect(reachedConsumption.withLock { $0 })
        #expect(try pair.remainingBytes().isEmpty)
        try FileManager.default.removeItem(at: lock)
        try FileManager.default.moveItem(at: backup, to: lock)
        try fixture.expectStates(ordinal == 0 ? [.created, .created] : [.spent, .created])
        #expect(throws: (any Error).self) { try transaction.run(descriptor: pair.host.fileDescriptor) }
        if ordinal == 1 { fixture.expectNewBootRefused() }
    }

    @Test(arguments: [RawDiskBootTransaction.Boundary.afterPreflight, .afterConsumed(0), .afterConsumed(1), .beforeManifestWrite])
    func failureAtDurabilityBoundariesCannotPublishManifest(boundary: RawDiskBootTransaction.Boundary) async throws {
        let fixture = try BootFixture()
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        let transaction = try RawDiskBootTransaction(specification: fixture.specification, disks: fixture.disks, hook: {
            if $0 == boundary { throw BootFault.injected }
        })
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.send(fixture.hello())
        expectInjected(await worker.result())
        #expect(try pair.remainingBytes().isEmpty)
        let states: [RawDiskInitialization.State] = boundary == .afterPreflight ? [.created, .created]
            : boundary == .afterConsumed(0) ? [.spent, .created] : [.spent, .spent]
        try fixture.expectStates(states)
        #expect(throws: (any Error).self) { try transaction.run(descriptor: pair.host.fileDescriptor) }
        if boundary != .afterPreflight { fixture.expectNewBootRefused() }
    }

    @Test func partialManifestSendIsNotReplayed() async throws {
        let fixture = try BootFixture()
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        let transaction = try RawDiskBootTransaction(specification: fixture.specification, disks: fixture.disks, hook: {
            if case .manifestBytesWritten = $0 { throw BootFault.injected }
        }, manifestWriteChunkSize: 7)
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.send(fixture.hello())
        expectInjected(await worker.result())
        let bytes = try pair.remainingBytes()
        #expect(bytes.count == 7)
        #expect(bytes.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) } > 3)
        try fixture.expectStates([.spent, .spent])
        #expect(throws: (any Error).self) { try transaction.run(descriptor: pair.host.fileDescriptor) }
        #expect(try pair.remainingBytes().isEmpty)
        fixture.expectNewBootRefused()
    }

    @Test(arguments: ["lost", "partial-prefix", "partial-body"])
    func incompleteAcknowledgementFailsClosed(fault: String) async throws {
        let fixture = try BootFixture()
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        let transaction = try RawDiskBootTransaction(specification: fixture.specification, disks: fixture.disks)
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.send(fixture.hello())
        let manifest = try pair.manifest()
        let acknowledgement = try DiskInitializationProtocol.encode(fixture.synced(manifest))
        if fault != "lost" {
            try pair.guest.write(contentsOf: acknowledgement.prefix(fault == "partial-prefix" ? 2 : acknowledgement.count - 1))
        }
        // A write-side EOF explicitly terminates the truncated frame; a live
        // half-open peer plus watchdog cancellation is not a loss proof.
        #expect(shutdown(pair.guest.fileDescriptor, SHUT_WR) == 0)
        expectTransportFailure(await worker.result())
        #expect(try pair.remainingBytes().isEmpty)
        try fixture.expectStates([.spent, .spent])
        #expect(throws: (any Error).self) { try transaction.run(descriptor: pair.host.fileDescriptor) }
        fixture.expectNewBootRefused()
    }

    @Test(arguments: ["launch", "nonce", "operation", "missing-operation", "uuid", "size", "ordinal", "count", "sync"])
    func acknowledgementMismatchRejectsWholeBatch(fault: String) async throws {
        let fixture = try BootFixture()
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        let validated = Mutex(false)
        let transaction = try RawDiskBootTransaction(specification: fixture.specification, disks: fixture.disks, hook: {
            if $0 == .afterAcknowledgementValidation { validated.withLock { $0 = true } }
        })
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.send(fixture.hello())
        var acknowledgement = fixture.synced(try pair.manifest())
        switch fault {
        case "launch": acknowledgement.shimLaunchUUID = UUID().uuidString.lowercased()
        case "nonce": acknowledgement.guestBootNonce = UUID().uuidString.lowercased()
        case "operation": acknowledgement.disks[1].operationUUID = UUID().uuidString.lowercased()
        case "missing-operation": acknowledgement.disks[1].operationUUID = nil
        case "uuid": acknowledgement.disks[1].ext4UUID = UUID().uuidString.lowercased()
        case "size": acknowledgement.disks[1].bytes += 4096
        case "ordinal": acknowledgement.disks[1].ordinal = 0
        case "count": acknowledgement.disks.removeLast()
        case "sync": acknowledgement.sync = "filesystem-only"
        default: Issue.record("unhandled fault")
        }
        // Bypass the sender's strict schema to exercise host rejection too.
        try pair.sendUnchecked(acknowledgement)
        let result = await worker.result()
        expectNonCancellationFailure(result)
        #expect(!validated.withLock { $0 })
        #expect(try pair.remainingBytes().isEmpty)
        try fixture.expectStates([.spent, .spent])
        #expect(throws: (any Error).self) { try transaction.run(descriptor: pair.host.fileDescriptor) }
        fixture.expectNewBootRefused()
    }

    @Test(arguments: ["invalid-peer", "invalid-frame", "invalid-manifest", "disk-mismatch", "disk-operation", "sync", "commit"], [nil, 0, 1, 2] as [Int?])
    func guestRefusalReportsOnlyValidatedCodeAndLeavesBatchSpent(code: String, ordinal: Int?) async throws {
        // Match RTM-074's root + two direct volumes, including ordinal 2.
        let fixture = try BootFixture(directVolumeCount: 2)
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        let transaction = try RawDiskBootTransaction(specification: fixture.specification, disks: fixture.disks)
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.send(fixture.hello())
        _ = try pair.manifest()
        let before = try fixture.journalSnapshot()
        try pair.send(DiskInitializationProtocol.ErrorFrame(code: code, ordinal: ordinal))
        guard case .failure(let error) = await worker.result() else { Issue.record("guest refusal was accepted"); return }
        #expect((error as? EngineError)?.code == .conflict)
        #expect(EngineError.message(for: error) == "disk bootstrap guest refused: \(code)" + (ordinal.map { " (disk ordinal \($0))" } ?? ""))
        #expect(try pair.remainingBytes().isEmpty) // No commit after refusal.
        #expect(try fixture.journalSnapshot() == before)
        try fixture.expectStates([.spent, .spent, .spent])
        fixture.expectNewBootRefused()
    }

    @Test func guestRefusalBeforeHelloDoesNotConsumeAuthorization() async throws {
        let fixture = try BootFixture()
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        let before = try fixture.journalSnapshot()
        let transaction = try RawDiskBootTransaction(specification: fixture.specification, disks: fixture.disks)
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.send(DiskInitializationProtocol.ErrorFrame(code: "disk-mismatch"))
        guard case .failure(let error) = await worker.result() else { Issue.record("guest refusal was accepted"); return }
        #expect(EngineError.message(for: error) == "disk bootstrap guest refused: disk-mismatch")
        #expect(try pair.remainingBytes().isEmpty)
        #expect(try fixture.journalSnapshot() == before)
        try fixture.expectStates([.created, .created])
    }

    @Test(arguments: ["unknown-code", "unknown-field", "duplicate-code", "null-ordinal", "null-code", "trailing", "version", "type", "outside-inventory", "truncated"])
    func invalidGuestRefusalDoesNotExposeRawDataOrCompleteAnyDisk(fault: String) async throws {
        let fixture = try BootFixture()
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        let transaction = try RawDiskBootTransaction(specification: fixture.specification, disks: fixture.disks)
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.send(fixture.hello())
        _ = try pair.manifest()
        let before = try fixture.journalSnapshot()
        let valid = #"{"version":1,"type":"error","code":"disk-operation","ordinal":1}"#
        var body = valid
        switch fault {
        case "unknown-code": body = body.replacingOccurrences(of: "disk-operation", with: "secret-canary")
        case "unknown-field": body = String(body.dropLast()) + #", "secret-canary":"raw-detail"}"#
        case "duplicate-code": body = String(body.dropLast()) + #", "code":"secret-canary"}"#
        case "null-ordinal": body = body.replacingOccurrences(of: #""ordinal":1"#, with: #""ordinal":null"#)
        case "null-code": body = body.replacingOccurrences(of: #""disk-operation""#, with: "null")
        case "trailing": body += " secret-canary"
        case "version": body = body.replacingOccurrences(of: #""version":1"#, with: #""version":2"#)
        case "type": body = body.replacingOccurrences(of: #""type":"error""#, with: #""type":"secret-canary""#)
        case "outside-inventory": body = body.replacingOccurrences(of: #""ordinal":1"#, with: #""ordinal":2"#)
        case "truncated": break
        default: Issue.record("unhandled fault")
        }
        let payload = Data(body.utf8)
        var count = UInt32(payload.count).bigEndian
        try pair.guest.write(contentsOf: Data(bytes: &count, count: 4) + (fault == "truncated" ? Data(payload.dropLast()) : payload))
        if fault == "truncated" { #expect(shutdown(pair.guest.fileDescriptor, SHUT_WR) == 0) }
        guard case .failure(let error) = await worker.result() else { Issue.record("invalid refusal was accepted"); return }
        #expect(EngineError.message(for: error) == (fault == "truncated"
            ? "disk bootstrap transport failed" : "disk bootstrap guest sent an invalid reply"))
        #expect(!EngineError.message(for: error).contains("secret-canary"))
        #expect(try pair.remainingBytes().isEmpty)
        #expect(try fixture.journalSnapshot() == before)
        try fixture.expectStates([.spent, .spent])
        fixture.expectNewBootRefused()
    }

    @Test func repeatedMountOnlyGuestRefusalPreservesInitializedJournalsAndBytes() async throws {
        let fixture = try BootFixture()
        defer { fixture.remove() }
        let canary = Data("existing disk bytes must never be rewritten".utf8)
        try fixture.disks[1].handle.write(contentsOf: canary)
        var initialized: [String: Data]?
        for attempt in 0..<3 {
            let pair = try BootSocketPair()
            defer { pair.close() }
            var spec = fixture.specification
            spec.shimLaunchUUID = UUID().uuidString.lowercased()
            let transaction = try RawDiskBootTransaction(specification: spec, disks: fixture.disks)
            let worker = try BootWorker(transaction, host: pair.host)
            defer { worker.cancel() }
            try pair.send(fixture.hello(nonce: UUID().uuidString.lowercased()))
            let manifest = try pair.manifest()
            if attempt == 0 {
                try pair.send(fixture.synced(manifest))
                _ = try pair.commit()
                try await worker.result().get()
                initialized = try fixture.journalSnapshot()
            } else {
                #expect(manifest.disks.allSatisfy { $0.action == "mount-existing-ext4" && $0.operationUUID == nil })
                try pair.send(DiskInitializationProtocol.ErrorFrame(code: "disk-operation", ordinal: 1))
                guard case .failure(let error) = await worker.result() else { Issue.record("mount refusal was accepted"); return }
                #expect(EngineError.message(for: error) == "disk bootstrap guest refused: disk-operation (disk ordinal 1)")
                #expect(try pair.remainingBytes().isEmpty)
                #expect(try fixture.journalSnapshot() == initialized)
                try fixture.disks[1].handle.seek(toOffset: 0)
                #expect(try fixture.disks[1].handle.read(upToCount: canary.count) == canary)
            }
            try fixture.expectStates([.initialized, .initialized])
        }
    }

    @Test(arguments: [RawDiskBootTransaction.Boundary.afterManifestWrite, .afterAcknowledgementValidation, .beforeComplete(0), .beforeComplete(1)])
    func completionFailureNeverRollsBackEarlierDisks(boundary: RawDiskBootTransaction.Boundary) async throws {
        let fixture = try BootFixture()
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        let transaction = try RawDiskBootTransaction(specification: fixture.specification, disks: fixture.disks, hook: {
            if $0 == boundary { throw BootFault.injected }
        })
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        // Do not send an acknowledgement after the afterManifestWrite fault:
        // the host has already closed, so that write would race with EPIPE.
        try pair.send(fixture.hello())
        if boundary != .afterManifestWrite {
            let manifest = try pair.manifest()
            try pair.send(fixture.synced(manifest))
        } else {
            _ = try pair.manifest()
        }
        expectInjected(await worker.result())
        #expect(try pair.remainingBytes().isEmpty)
        try fixture.expectStates(boundary == .beforeComplete(1) ? [.initialized, .spent] : [.spent, .spent])
        #expect(throws: (any Error).self) { try transaction.run(descriptor: pair.host.fileDescriptor) }
        fixture.expectNewBootRefused()
    }

    @Test func lostCommitLeavesInitializedAndNewBootMountsWithoutNewUUIDs() async throws {
        let fixture = try BootFixture()
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        let beforeCommit = Mutex(false)
        let transaction = try RawDiskBootTransaction(specification: fixture.specification, disks: fixture.disks, hook: {
            if $0 == .beforeCommit {
                try fixture.expectStates([.initialized, .initialized])
                beforeCommit.withLock { $0 = true }
                // Close the HOST write direction only after durable completion.
                // The ensuing real send must fail; no peer race or timer needed.
                guard shutdown(pair.host.fileDescriptor, SHUT_WR) == 0 else { throw POSIXError(.EIO) }
            }
        })
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.send(fixture.hello())
        try pair.send(fixture.synced(try pair.manifest()))
        expectTransportFailure(await worker.result())
        #expect(beforeCommit.withLock { $0 })
        #expect(try pair.remainingBytes().isEmpty)
        try fixture.expectStates([.initialized, .initialized])
        #expect(throws: (any Error).self) { try transaction.run(descriptor: pair.host.fileDescriptor) }

        var nextSpecification = fixture.specification
        nextSpecification.shimLaunchUUID = UUID().uuidString.lowercased()
        let nextNonce = UUID().uuidString.lowercased()
        let nextPair = try BootSocketPair()
        defer { nextPair.close() }
        let next = try RawDiskBootTransaction(specification: nextSpecification, disks: fixture.disks, hook: {
            if case .beforeConsume = $0 { Issue.record("initialized disk was consumed again") }
            if case .beforeComplete = $0 { Issue.record("mount-only disk was completed again") }
        })
        let nextWorker = try BootWorker(next, host: nextPair.host)
        defer { nextWorker.cancel() }
        try nextPair.send(fixture.hello(nonce: nextNonce))
        let manifest = try nextPair.manifest()
        #expect(manifest.shimLaunchUUID == nextSpecification.shimLaunchUUID)
        #expect(manifest.guestBootNonce == nextNonce)
        #expect(manifest.disks.map(\.action) == ["mount-existing-ext4", "mount-existing-ext4"])
        #expect(manifest.disks.allSatisfy { $0.operationUUID == nil })
        #expect(manifest.disks.map(\.ext4UUID) == fixture.originals.map { Optional($0.ext4UUID) })
        try nextPair.send(fixture.synced(manifest))
        let commit = try nextPair.commit()
        #expect(commit.shimLaunchUUID == nextSpecification.shimLaunchUUID)
        #expect(commit.guestBootNonce == nextNonce)
        try await nextWorker.result().get()
        try fixture.expectStates([.initialized, .initialized])
        for disk in fixture.disks {
            let record = try fixture.record(disk)
            #expect(record.binding?.shimLaunchUUID == fixture.specification.shimLaunchUUID)
            #expect(record.binding?.guestBootNonce == fixture.nonce)
        }
    }

    @Test func cancellationStopsLiveAcknowledgementReaderPromptlyWithoutRetry() async throws {
        let fixture = try BootFixture()
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        let transaction = try RawDiskBootTransaction(specification: fixture.specification, disks: fixture.disks)
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.send(fixture.hello())
        _ = try pair.manifest()
        try pair.guest.write(contentsOf: Data([0, 0]))
        let clock = ContinuousClock()
        let started = clock.now
        worker.task.cancel() // Peer remains open; only task cancellation can stop read.
        let result = await worker.result()
        #expect(clock.now - started < .seconds(1))
        guard case .failure(let error) = result else { Issue.record("cancelled reader succeeded"); return }
        #expect(error is CancellationError)
        #expect(try pair.remainingBytes().isEmpty)
        try fixture.expectStates([.spent, .spent])
        #expect(throws: (any Error).self) { try transaction.run(descriptor: pair.host.fileDescriptor) }
        fixture.expectNewBootRefused()
    }

    @Test(arguments: ["count", "path", "size", "missing-size", "device", "inode", "volume-uuid", "missing-identity", "name", "root-path", "root-size", "root-identity", "read-only", "kind"])
    func immutableSpecificationMustMatchEntireHeldSet(field: String) throws {
        let fixture = try BootFixture()
        defer { fixture.remove() }
        var spec = fixture.specification
        switch field {
        case "count": spec.volumeDisks = []
        case "path": spec.volumeDisks[0].path = fixture.root.appending(path: "other.ext4").path
        case "size": spec.volumeDisks[0].size! += 4096
        case "missing-size": spec.volumeDisks[0].size = nil
        case "device": spec.volumeDisks[0].identity!.device += 1
        case "inode": spec.volumeDisks[0].identity!.inode += 1
        case "volume-uuid": spec.volumeDisks[0].identity!.volumeUUID = UUID()
        case "missing-identity": spec.volumeDisks[0].identity = nil
        case "name": spec.volumeDisks[0].name = "different-volume"
        case "root-path": spec.rootDiskPath = spec.volumeDisks[0].path
        case "root-size": spec.rootDiskSize! += 4096
        case "root-identity": spec.rootDiskIdentity = spec.volumeDisks[0].identity
        case "read-only": spec.rootDiskReadOnly = true
        case "kind": spec.kind = .storage
        default: Issue.record("unhandled field")
        }
        #expect(throws: (any Error).self) { _ = try RawDiskBootTransaction(specification: spec, disks: fixture.disks) }
        try fixture.expectStates([.created, .created])
    }

    @Test(arguments: ["ordinal", "role", "volume-name", "identity", "descriptor", "path"])
    func heldDiskFieldsCannotDisagreeWithSpecification(field: String) throws {
        let fixture = try BootFixture()
        defer { fixture.remove() }
        let disk = fixture.disks[1]
        let wrong = VMShimHeldDisk(ordinal: field == "ordinal" ? 0 : disk.ordinal,
                                  role: field == "role" ? "container-root" : disk.role,
                                  volumeName: field == "volume-name" ? nil : disk.volumeName,
                                  parent: disk.parent, name: field == "path" ? fixture.disks[0].name : disk.name,
                                  handle: field == "descriptor" ? fixture.disks[0].handle : disk.handle,
                                  identity: field == "identity" ? fixture.disks[0].identity : disk.identity, bytes: disk.bytes)
        #expect(throws: (any Error).self) {
            _ = try RawDiskBootTransaction(specification: fixture.specification, disks: [fixture.disks[0], wrong])
        }
        try fixture.expectStates([.created, .created])
    }

    @Test(arguments: ["held-path", "sidecar-lock", "sidecar-record"])
    func runRechecksWholeSetBeforeConsumptionAfterConstructor(fault: String) async throws {
        let fixture = try BootFixture()
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        let transaction = try RawDiskBootTransaction(specification: fixture.specification, disks: fixture.disks)
        let disk = fixture.disks[1]
        let path: URL
        switch fault {
        case "held-path": path = fixture.root.appending(path: disk.name)
        case "sidecar-lock": path = fixture.root.appending(path: ".raw-init-\(disk.name).lock")
        default: path = fixture.root.appending(path: ".raw-init-\(disk.name).created.json")
        }
        let backup = fixture.root.appending(path: "original-artifact")
        try FileManager.default.moveItem(at: path, to: backup)
        if fault == "sidecar-record" {
            // Keep canonical schema and diskName; change only the recorded inode.
            var record = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: backup)) as? [String: Any])
            var identity = try #require(record["diskIdentity"] as? [String: Any])
            identity["inode"] = fixture.disks[0].identity.inode
            record["diskIdentity"] = identity
            try JSONSerialization.data(withJSONObject: record, options: [.sortedKeys, .withoutEscapingSlashes]).write(to: path)
        } else {
            #expect(FileManager.default.createFile(atPath: path.path, contents: Data(), attributes: [.posixPermissions: 0o600]))
            if fault == "held-path" {
                let replacement = try FileHandle(forWritingTo: path)
                try replacement.truncate(atOffset: disk.bytes)
                try replacement.close()
            }
        }
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.send(fixture.hello())
        expectNonCancellationFailure(await worker.result())
        #expect(try pair.remainingBytes().isEmpty)
        #expect(try fixture.record(fixture.disks[0]).state == .created)
        for disk in fixture.disks {
            #expect(!FileManager.default.fileExists(atPath: fixture.root.appending(path: ".raw-init-\(disk.name).spent.json").path))
        }
        // Restore only the artifacts this test changed, then prove no transition.
        try FileManager.default.removeItem(at: path)
        try FileManager.default.moveItem(at: backup, to: path)
        try fixture.expectStates([.created, .created])
    }

    @Test func oldOrChangedAssetsAreRejectedBeforeVZConstruction() throws {
        let fixture = try BootFixture()
        defer { fixture.remove() }
        var spec = fixture.specification
        spec.diskBootstrapVersion = nil
        #expect(throws: (any Error).self) { _ = try VMShimServer.pinnedBootstrapInitramfs(spec) }
        spec.diskBootstrapVersion = 1
        spec.expectedInitramfsSHA256 = String(repeating: "0", count: 64)
        #expect(throws: (any Error).self) { _ = try VMShimServer.pinnedBootstrapInitramfs(spec) }
        let image = Data("bootstrap image".utf8)
        let path = fixture.root.appending(path: "initramfs")
        try image.write(to: path)
        spec.initialRamdiskPath = path.path
        spec.expectedInitramfsSHA256 = SHA256.hash(data: image).map { String(format: "%02x", $0) }.joined()
        let pinned = try VMShimServer.pinnedBootstrapInitramfs(spec)
        defer { try? pinned.close() }
        try FileManager.default.moveItem(at: path, to: fixture.root.appending(path: "old-initramfs"))
        try Data("wrong image".utf8).write(to: path)
        #expect(try pinned.readToEnd() == image)
    }

    @Test func containerProofRequiresCommitAndRetainsHeldDisks() async throws {
        var fixture: BootFixture? = try BootFixture(directVolumeCount: 2)
        let root = try #require(fixture?.root)
        defer { try? FileManager.default.removeItem(at: root) }
        let specification = try #require(fixture?.specification)
        let expectedUUID = try #require(fixture?.originals.first?.ext4UUID)
        let expectedNonce = try #require(fixture?.nonce)
        let descriptors = try #require(fixture?.disks.map { $0.handle.fileDescriptor })
        let released = DispatchSemaphore(value: 0)
        let proof = try await #require(fixture).containerProof(checkBeforeCommit: true, releaseSignal: released)
        fixture = nil
        // The hook's release sentinel proves the transaction itself is gone,
        // rather than merely dropping the caller's reference to it.
        #expect(await containerBootWasReleased(released))
        #expect(proof.containerID == specification.containerID)
        #expect(proof.shimLaunchUUID == specification.shimLaunchUUID)
        #expect(proof.guestBootNonce == expectedNonce)
        #expect(proof.rootExt4UUID == expectedUUID)
        #expect(proof.rootBytes == specification.rootDiskSize)
        #expect(proof.initramfsSHA256 == containerBootTestSHA256)
        let identities = try proof.validateHeldDisks()
        #expect(identities == [try #require(specification.rootDiskIdentity)] + specification.volumeDisks.compactMap(\.identity))
        for (descriptor, identity) in zip(descriptors, identities) {
            let actual = try PersistentFileIdentity.capture(descriptor: descriptor)
            #expect(actual.device == identity.device)
            #expect(actual.inode == identity.inode)
            #expect(actual.volumeUUID == identity.volumeUUID)
        }
    }

    @Test func containerProofUsesCurrentNonceAndStableRoot() async throws {
        let fixture = try BootFixture(directVolumeCount: 2)
        defer { fixture.remove() }
        let first = try await fixture.containerProof()
        let nextLaunch = UUID().uuidString.lowercased()
        let nextNonce = UUID().uuidString.lowercased()
        let next = try await fixture.containerProof(launch: nextLaunch, nonce: nextNonce)
        #expect(first.shimLaunchUUID == fixture.specification.shimLaunchUUID)
        #expect(first.guestBootNonce == fixture.nonce)
        #expect(next.shimLaunchUUID == nextLaunch)
        #expect(next.guestBootNonce == nextNonce)
        #expect(next.rootExt4UUID == first.rootExt4UUID)
        #expect(next.rootExt4UUID == fixture.originals[0].ext4UUID)
        #expect(next.rootBytes == first.rootBytes)
        #expect(next.containerID == first.containerID)
        #expect(try next.validateHeldDisks() == first.validateHeldDisks())
        // Durable initialization records retain the old boot binding; the new
        // capability must instead bind the current, mount-only exchange.
        #expect(try fixture.record(fixture.disks[0]).binding?.guestBootNonce == fixture.nonce)
        try fixture.expectStates([.initialized, .initialized, .initialized])
    }

    @Test(arguments: ["partial-prefix", "partial-body", "missing-disk", "later-direct-uuid"])
    func incompleteContainerAcknowledgementCannotMintProof(fault: String) async throws {
        let fixture = try BootFixture(directVolumeCount: 2)
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        var specification = fixture.specification
        specification.expectedInitramfsSHA256 = containerBootTestSHA256
        let transaction = try RawDiskBootTransaction(specification: specification, disks: fixture.disks)
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.send(fixture.hello())
        var synced = fixture.synced(try pair.manifest())
        #expect(throws: (any Error).self) { _ = try transaction.verifiedContainerBoot() }
        if fault.hasPrefix("partial-") {
            let bytes = try DiskInitializationProtocol.encode(synced)
            try pair.guest.write(contentsOf: bytes.prefix(fault == "partial-prefix" ? 2 : bytes.count - 1))
            #expect(shutdown(pair.guest.fileDescriptor, SHUT_WR) == 0)
            expectTransportFailure(await worker.result())
        } else {
            if fault == "missing-disk" { synced.disks.removeLast() }
            else { synced.disks[2].ext4UUID = UUID().uuidString.lowercased() }
            try pair.sendUnchecked(synced)
            expectNonCancellationFailure(await worker.result())
        }
        #expect(try pair.remainingBytes().isEmpty)
        #expect(throws: (any Error).self) { _ = try transaction.verifiedContainerBoot() }
        try fixture.expectStates([.spent, .spent, .spent])
    }

    @Test(arguments: ["root-completion", "later-direct-completion", "commit-write"])
    func failedContainerCompletionOrCommitCannotMintProof(fault: String) async throws {
        let fixture = try BootFixture(directVolumeCount: 2)
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        var specification = fixture.specification
        specification.expectedInitramfsSHA256 = containerBootTestSHA256
        let transaction = try RawDiskBootTransaction(specification: specification, disks: fixture.disks, hook: {
            if fault == "root-completion", $0 == .beforeComplete(0) { throw BootFault.injected }
            if fault == "later-direct-completion", $0 == .beforeComplete(2) { throw BootFault.injected }
            if fault == "commit-write", $0 == .beforeCommit {
                guard shutdown(pair.host.fileDescriptor, SHUT_WR) == 0 else { throw POSIXError(.EIO) }
            }
        })
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.send(fixture.hello())
        try pair.send(fixture.synced(try pair.manifest()))
        let result = await worker.result()
        if fault == "commit-write" { expectTransportFailure(result) }
        else { expectInjected(result) }
        #expect(try pair.remainingBytes().isEmpty)
        #expect(throws: (any Error).self) { _ = try transaction.verifiedContainerBoot() }
        try fixture.expectStates(fault == "root-completion" ? [.spent, .spent, .spent]
            : fault == "later-direct-completion" ? [.initialized, .initialized, .spent]
            : [.initialized, .initialized, .initialized])
    }

    @Test(arguments: ["storage", "missing-digest", "short-digest", "uppercase-digest", "nonhex-digest"])
    func completedExchangeWithoutContainerBindingCannotMintProof(fault: String) async throws {
        let fixture = try BootFixture(kind: fault == "storage" ? .storage : .container)
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        var specification = fixture.specification
        switch fault {
        case "storage": specification.expectedInitramfsSHA256 = containerBootTestSHA256
        case "missing-digest": specification.expectedInitramfsSHA256 = nil
        case "short-digest": specification.expectedInitramfsSHA256 = "abc"
        case "uppercase-digest": specification.expectedInitramfsSHA256 = String(repeating: "A", count: 64)
        default: specification.expectedInitramfsSHA256 = String(repeating: "g", count: 64)
        }
        let transaction = try RawDiskBootTransaction(specification: specification, disks: fixture.disks)
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.send(fixture.hello())
        try pair.send(fixture.synced(try pair.manifest()))
        _ = try pair.commit()
        try await worker.result().get()
        #expect(throws: (any Error).self) { _ = try transaction.verifiedContainerBoot() }
    }

    @Test(arguments: ["path-replacement", "size-change"], [false, true])
    func containerProofRejectsChangedLaterDirectDisk(fault: String, afterCommit: Bool) async throws {
        let fixture = try BootFixture(directVolumeCount: 2)
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        let disk = fixture.disks[2]
        let path = fixture.root.appending(path: disk.name)
        let backup = fixture.root.appending(path: "original-direct-disk")
        let changeDisk: @Sendable () throws -> Void = {
            if fault == "path-replacement" {
                try FileManager.default.moveItem(at: path, to: backup)
                guard FileManager.default.createFile(atPath: path.path, contents: Data(), attributes: [.posixPermissions: 0o600]) else {
                    throw POSIXError(.EIO)
                }
                let replacement = try FileHandle(forWritingTo: path)
                defer { try? replacement.close() }
                try replacement.truncate(atOffset: disk.bytes)
            } else {
                try disk.handle.truncate(atOffset: disk.bytes + 4096)
            }
        }
        var specification = fixture.specification
        specification.expectedInitramfsSHA256 = containerBootTestSHA256
        let transaction = try RawDiskBootTransaction(specification: specification, disks: fixture.disks, hook: {
            if !afterCommit, $0 == .beforeCommit { try changeDisk() }
        })
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.send(fixture.hello())
        try pair.send(fixture.synced(try pair.manifest()))
        _ = try pair.commit()
        let result = await worker.result()
        if afterCommit {
            try result.get()
            let proof = try transaction.verifiedContainerBoot()
            #expect(try proof.validateHeldDisks().count == 3)
            try changeDisk()
            #expect(throws: (any Error).self) { _ = try proof.validateHeldDisks() }
        } else {
            expectNonCancellationFailure(result)
        }
        #expect(throws: (any Error).self) { _ = try transaction.verifiedContainerBoot() }
        // The valid root and first direct disk cannot authorize the whole batch.
        #expect(try fixture.record(fixture.disks[0]).state == .initialized)
        #expect(try fixture.record(fixture.disks[1]).state == .initialized)
        if fault == "path-replacement" {
            try FileManager.default.removeItem(at: path)
            try FileManager.default.moveItem(at: backup, to: path)
        } else {
            try disk.handle.truncate(atOffset: disk.bytes)
        }
        try fixture.expectStates([.initialized, .initialized, .initialized])
        if !afterCommit {
            // Restoring the inventory cannot mint a capability for a failed run.
            #expect(throws: (any Error).self) { _ = try transaction.verifiedContainerBoot() }
        }
    }

    @Test func storageProofExistsOnlyAfterCommitAndRetainsTheHeldDisk() async throws {
        var fixture: BootFixture? = try BootFixture(kind: .storage)
        let root = try #require(fixture?.root)
        defer { try? FileManager.default.removeItem(at: root) }
        let expectedIdentity = try #require(fixture?.specification.rootDiskIdentity)
        let expectedUUID = try #require(fixture?.originals.first?.ext4UUID)
        let expectedNonce = try #require(fixture?.nonce)
        let proof = try await #require(fixture).storageProof(checkBeforeCommit: true)
        fixture = nil // Neither the fixture nor the transaction keeps the descriptor alive now.
        #expect(proof.binding.ext4UUID == expectedUUID)
        #expect(proof.binding.guestBootNonce == expectedNonce)
        #expect(proof.binding.bytes == 32 << 20)
        #expect(proof.initramfsSHA256 == storageBootTestSHA256)
        #expect(try proof.validateHeldDisk() == expectedIdentity)
    }

    @Test func freshStorageCapabilityRequiresThisBootToActuallyInitialize() async throws {
        let fixture = try BootFixture(kind: .storage)
        defer { fixture.remove() }
        let first = try await fixture.storageProof(checkBeforeCommit: true)
        let fresh = try first.freshInitialization()
        #expect(fresh.operationUUID == fixture.originals[0].operationUUID)
        #expect(fresh.boot === first)
        #expect(try fresh.validateHeldDisk() == fixture.specification.rootDiskIdentity)
        // The next verified boot mounts the exact initialized disk. Historical
        // CREATED/INITIALIZED sidecars cannot mint fresh provisioning again.
        let mounted = try await fixture.storageProof()
        #expect(mounted.binding.ext4UUID == first.binding.ext4UUID)
        #expect(throws: (any Error).self) { try mounted.freshInitialization() }
        try fixture.disks[0].handle.truncate(atOffset: fixture.disks[0].bytes + 4096)
        #expect(throws: (any Error).self) { try fresh.validateHeldDisk() }
        #expect(throws: (any Error).self) { try first.freshInitialization() }
    }

    @Test func freshClaimIsFrozenAcrossAllCapabilitiesAndConsumesBeforeDiskIO() async throws {
        typealias P = StorageLifecycleFreshProtocol
        typealias L = StorageLifecycleProtocol
        let fixture = try BootFixture(kind: .storage)
        defer { fixture.remove() }
        let boot = try await fixture.storageProof()
        let first = try boot.freshInitialization(), second = try boot.freshInitialization()
        let store = try StorageIdentity.StoreID(UUID().uuidString.lowercased())
        let root = try StorageIdentity.RootPublicKey(publicData: Data(repeating: 7, count: 32))
        let greeting = try first.greeting(storeID: store, root: root,
            channelID: UUID().uuidString.lowercased(), daemonUniqueID: 101)
        let grant = try L.Grant(operation: .initialize, id: UUID().uuidString.lowercased(),
            identity: .init(store: store.rawValue, generation: 1, binding: String(repeating: "a", count: 64)),
            serial: 1, expectedEpoch: 0, newKey: String(repeating: "b", count: 64))
        func challenge(_ counter: UInt64, greeting g: P.Greeting? = nil, grant value: L.Grant? = nil,
                       shimAudit: Data = Data(repeating: 1, count: 32),
                       daemonAudit: Data = Data(repeating: 2, count: 32)) throws -> P.Challenge {
            var nonce = counter.bigEndian
            let bytes = withUnsafeBytes(of: &nonce) { Data($0) } + Data(repeating: 0, count: 24)
            return try .init(greeting: g ?? greeting, grant: value ?? grant, shimAudit: shimAudit, shimUniqueID: 102,
                daemonAudit: daemonAudit, counter: counter, nonce: bytes,
                expiresUnixMS: UInt64(Date().timeIntervalSince1970 * 1000) + 29_000)
        }
        let original = try challenge(1)
        #expect(try first.reply(to: original).verifies(original))
        #expect(throws: (any Error).self) { try second.reply(to: original) }
        let reusedNonce = try P.Challenge(greeting: greeting, grant: grant, shimAudit: original.shimAudit,
            shimUniqueID: original.shimUniqueID, daemonAudit: original.daemonAudit, counter: 2,
            nonce: original.nonce, expiresUnixMS: original.expiresUnixMS)
        #expect(throws: (any Error).self) { try second.reply(to: reusedNonce) }
        for changed in [
            try L.Grant(operation: .initialize, id: grant.id, identity: .init(store: store.rawValue, generation: 2, binding: grant.identity.binding), serial: 1, expectedEpoch: 0, newKey: grant.newKey),
            try L.Grant(operation: .initialize, id: UUID().uuidString.lowercased(), identity: grant.identity, serial: 2, expectedEpoch: 0, newKey: grant.newKey)
        ] { #expect(throws: (any Error).self) { try second.reply(to: challenge(2, grant: changed)) } }
        for changed in [
            try second.greeting(storeID: store, root: root, channelID: UUID().uuidString.lowercased(), daemonUniqueID: 101),
            try second.greeting(storeID: store, root: root, channelID: greeting.channelID, daemonUniqueID: 103),
            try second.greeting(storeID: store, root: .init(publicData: Data(repeating: 8, count: 32)), channelID: greeting.channelID, daemonUniqueID: 101)
        ] { #expect(throws: (any Error).self) { try second.reply(to: challenge(2, greeting: changed)) } }
        #expect(throws: (any Error).self) { try second.reply(to: challenge(2, shimAudit: Data(repeating: 3, count: 32))) }
        #expect(throws: (any Error).self) { try second.reply(to: challenge(2, daemonAudit: Data(repeating: 3, count: 32))) }
        // Exact retry with fresh counter/nonce is allowed, without a 64/4096
        // lifetime quota and without regenerating a wrapper to erase history.
        for counter in UInt64(2)...4_098 {
            let c = try challenge(counter)
            #expect(try second.reply(to: c).verifies(c))
            // Each reply performs synchronous disk validation. Let other tests'
            // actor/transport continuations run only after this iteration completes.
            await Task.yield()
        }
        let afterMutation = try challenge(4_099)
        try fixture.disks[0].handle.truncate(atOffset: fixture.disks[0].bytes + 4096)
        #expect(throws: (any Error).self) { try first.reply(to: afterMutation) }
        try fixture.disks[0].handle.truncate(atOffset: fixture.disks[0].bytes)
        #expect(throws: (any Error).self) { try boot.freshInitialization().reply(to: afterMutation) }
        let retry = try challenge(4_100)
        #expect(try first.reply(to: retry).verifies(retry))
    }

    @Test func lifecycleInitializationRequiresExactFrozenFreshClaim() async throws {
        typealias L = StorageLifecycleProtocol
        let fixture = try BootFixture(kind: .storage)
        defer { fixture.remove() }
        let boot = try await fixture.storageProof(), fresh = try boot.freshInitialization()
        let key = Curve25519.Signing.PrivateKey(), root = try StorageIdentity.RootPublicKey(publicData: key.publicKey.rawRepresentation)
        let disk = try fresh.validateHeldDisk(), volume = try StorageIdentity.FilesystemUUID(#require(disk.volumeUUID).uuidString.lowercased())
        let binding = try StorageIdentity.StoreBinding(storeID: .init(UUID().uuidString.lowercased()),
            root: .init(volumeUUID: volume, inode: disk.inode + 1),
            backing: .init(identity: .init(volumeUUID: volume, inode: disk.inode), size: boot.binding.bytes),
            expectedExt4UUID: .init(boot.binding.ext4UUID))
        let grant = try L.Grant(operation: .initialize, id: UUID().uuidString.lowercased(),
            identity: .init(binding: binding, generation: 1), serial: 1, expectedEpoch: 0, newKey: String(repeating: "b", count: 64))
        func sign(_ grant: L.Grant) throws -> L.SignedGrant {
            try .init(grant: grant, signature: key.signature(for: grant.signingBytes))
        }
        let signed = try sign(grant)
        // A signature alone cannot substitute for the live ROOT fresh challenge.
        #expect(throws: (any Error).self) { try boot.validateLifecycleInitialization(signed, root: root, binding: binding) }
        let greeting = try fresh.greeting(storeID: binding.storeID, root: root,
            channelID: UUID().uuidString.lowercased(), daemonUniqueID: 101)
        let challenge = try StorageLifecycleFreshProtocol.Challenge(greeting: greeting, grant: grant,
            shimAudit: Data(repeating: 1, count: 32), shimUniqueID: 102, daemonAudit: Data(repeating: 2, count: 32),
            counter: 1, nonce: Data(repeating: 1, count: 32), expiresUnixMS: UInt64(Date().timeIntervalSince1970 * 1000) + 29_000)
        // Explicit unsigned component seam, not native ROOT authentication.
        _ = try fresh.reply(to: challenge)
        try boot.validateLifecycleInitialization(signed, root: root, binding: binding)
        for changed in [
            try L.Grant(operation: .initialize, id: grant.id, identity: .init(binding: binding, generation: 2), serial: 2, expectedEpoch: 0, newKey: grant.newKey),
            try L.Grant(operation: .initialize, id: UUID().uuidString.lowercased(), identity: grant.identity, serial: 2, expectedEpoch: 0, newKey: grant.newKey)
        ] {
            #expect(throws: (any Error).self) { try boot.validateLifecycleInitialization(sign(changed), root: root, binding: binding) }
        }
        let invalid = try L.SignedGrant(grant: grant, signature: Data(repeating: 0, count: 64))
        #expect(throws: (any Error).self) { try boot.validateLifecycleInitialization(invalid, root: root, binding: binding) }
        try fixture.disks[0].handle.truncate(atOffset: fixture.disks[0].bytes + 4096)
        #expect(throws: (any Error).self) { try boot.validateLifecycleInitialization(signed, root: root, binding: binding) }
    }

    @Test func lifecycleServiceClaimDoesNotConsumeFreshWrappersOrProofCounters() async throws {
        let fixture = try BootFixture(kind: .storage)
        defer { fixture.remove() }
        let boot = try await fixture.storageProof()
        let first = try boot.freshInitialization()
        try boot.claimLifecycleServiceBoot()
        let second = try boot.freshInitialization()
        #expect(first.boot === second.boot)
        #expect(throws: (any Error).self) { try second.boot.claimLifecycleServiceBoot() }
        let root = try StorageIdentity.RootPublicKey(publicData: Data(repeating: 7, count: 32))
        let store = try StorageIdentity.StoreID(UUID().uuidString.lowercased())
        let greeting = try first.greeting(storeID: store, root: root,
            channelID: UUID().uuidString.lowercased(), daemonUniqueID: 101)
        let grant = try StorageLifecycleProtocol.Grant(operation: .initialize, id: UUID().uuidString.lowercased(),
            identity: .init(store: store.rawValue, generation: 1, binding: String(repeating: "a", count: 64)),
            serial: 1, expectedEpoch: 0, newKey: String(repeating: "b", count: 64))
        for counter in UInt64(1)...3 {
            let challenge = try StorageLifecycleFreshProtocol.Challenge(greeting: greeting, grant: grant,
                shimAudit: Data(repeating: 1, count: 32), shimUniqueID: 102, daemonAudit: Data(repeating: 2, count: 32),
                counter: counter, nonce: Data(repeating: UInt8(counter), count: 32),
                expiresUnixMS: UInt64(Date().timeIntervalSince1970 * 1000) + 29_000)
            #expect(try boot.freshInitialization().reply(to: challenge).verifies(challenge))
            #expect(throws: (any Error).self) { try second.reply(to: challenge) }
        }
    }

    @Test func freshNativeShimRejectsLocallyFabricatedRootMessages() throws {
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_bool(message, "ok", true)
        xpc_dictionary_set_string(message, "operation", "storage-lifecycle-fresh-challenge")
        #expect(throws: (any Error).self) {
            try StorageLifecycleFreshShim.authenticateRoot(message, team: "ABCDEFGHIJ")
        }
    }

    @Test func freshNativeShimRejectsActualUnsignedMachReply() async throws {
        // No named service, helper install or elevation. Unlike a fabricated
        // dictionary, this traverses Mach and verifies the reply audit trailer.
        try await Task.detached {
            let queue = DispatchQueue(label: "dev.cengine.test.fresh-native-reply")
            let listener = xpc_connection_create(nil, queue)
            let peers = Mutex<[xpc_connection_t]>([])
            xpc_connection_set_event_handler(listener) { peer in
                guard xpc_get_type(peer) == XPC_TYPE_CONNECTION else { return }
                peers.withLock { $0.append(peer) }
                xpc_connection_set_event_handler(peer) { message in
                    guard xpc_get_type(message) == XPC_TYPE_DICTIONARY,
                          let reply = xpc_dictionary_create_reply(message) else { return }
                    xpc_dictionary_set_bool(reply, "ok", true)
                    xpc_connection_send_message(peer, reply)
                }
                xpc_connection_resume(peer)
            }
            xpc_connection_resume(listener)
            let endpoint = xpc_endpoint_create(listener)
            let client = xpc_connection_create_from_endpoint(endpoint)
            xpc_connection_set_event_handler(client) { _ in }
            xpc_connection_resume(client)
            defer {
                xpc_connection_cancel(client)
                xpc_connection_cancel(listener)
                peers.withLock { for peer in $0 { xpc_connection_cancel(peer) }; $0.removeAll() }
            }
            let received = DispatchSemaphore(value: 0)
            let request = xpc_dictionary_create(nil, nil, 0)
            xpc_dictionary_set_string(request, "operation", "storage-lifecycle-fresh-shim")
            xpc_connection_send_message_with_reply(client, request, queue) { reply in
                defer { received.signal() }
                guard xpc_get_type(reply) == XPC_TYPE_DICTIONARY else {
                    Issue.record("native XPC did not deliver a dictionary reply"); return
                }
                var token = audit_token_t()
                freshTestMessageAudit(reply, &token)
                #expect(token.val.5 == UInt32(getpid()))
                #expect(token.val.1 == geteuid())
                #expect(throws: (any Error).self) {
                    try StorageLifecycleFreshShim.authenticateRoot(reply, team: "ABCDEFGHIJ")
                }
            }
            func waitForReply() -> Bool { received.wait(timeout: .now() + 5) == .success }
            try #require(waitForReply())
        }.value
    }

    @Test func unjournaledStorageBootCannotMintFreshProvisioning() async throws {
        let fixture = try BootFixture(kind: .storage)
        defer { fixture.remove() }
        try FileManager.default.removeItem(at: fixture.root.appending(path: ".raw-init-disk0.ext4.created.json"))
        let pair = try BootSocketPair()
        defer { pair.close() }
        var specification = fixture.specification
        specification.expectedInitramfsSHA256 = storageBootTestSHA256
        let transaction = try RawDiskBootTransaction(specification: specification, disks: fixture.disks)
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.send(fixture.hello())
        let manifest = try pair.manifest()
        #expect(manifest.disks[0].action == "mount-existing-ext4")
        #expect(manifest.disks[0].operationUUID == nil)
        try pair.send(DiskInitializationProtocol.Synced(shimLaunchUUID: manifest.shimLaunchUUID,
            guestBootNonce: manifest.guestBootNonce, disks: [.init(ordinal: 0, bytes: fixture.disks[0].bytes,
                ext4UUID: fixture.originals[0].ext4UUID)]))
        _ = try pair.commit()
        try await worker.result().get()
        let boot = try transaction.verifiedStorageDiskBoot()
        #expect(throws: (any Error).self) { try boot.freshInitialization() }
    }

    @Test(arguments: ["acknowledgement", "completion", "commit-write", "late-disk-change"])
    func failedStorageCommitCannotMintProof(fault: String) async throws {
        let fixture = try BootFixture(kind: .storage)
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        var specification = fixture.specification
        specification.expectedInitramfsSHA256 = storageBootTestSHA256
        let transaction = try RawDiskBootTransaction(specification: specification, disks: fixture.disks, hook: {
            if fault == "completion", $0 == .beforeComplete(0) { throw BootFault.injected }
            if $0 == .beforeCommit {
                if fault == "commit-write" {
                    guard shutdown(pair.host.fileDescriptor, SHUT_WR) == 0 else { throw POSIXError(.EIO) }
                } else if fault == "late-disk-change" {
                    // Commit can be written, but the held-disk recheck must still refuse the capability.
                    try fixture.disks[0].handle.truncate(atOffset: fixture.disks[0].bytes + 4096)
                }
            }
        })
        #expect(throws: (any Error).self) { _ = try transaction.verifiedStorageDiskBoot() }
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.send(fixture.hello())
        var synced = fixture.synced(try pair.manifest())
        if fault == "acknowledgement" { synced.disks[0].ext4UUID = UUID().uuidString.lowercased() }
        try pair.send(synced)
        expectNonCancellationFailure(await worker.result())
        if fault == "late-disk-change" { _ = try pair.commit() }
        #expect(try pair.remainingBytes().isEmpty)
        #expect(throws: (any Error).self) { _ = try transaction.verifiedStorageDiskBoot() }
        #expect(throws: (any Error).self) { try transaction.run(descriptor: pair.host.fileDescriptor) }
    }

    @Test(arguments: ["container", "missing-digest", "short-digest", "uppercase-digest", "nonhex-digest"])
    func completedDiskExchangeWithoutStorageImageBindingCannotMintProof(fault: String) async throws {
        let fixture = try BootFixture(kind: fault == "container" ? .container : .storage)
        defer { fixture.remove() }
        let pair = try BootSocketPair()
        defer { pair.close() }
        var specification = fixture.specification
        switch fault {
        case "container": specification.expectedInitramfsSHA256 = storageBootTestSHA256
        case "missing-digest": specification.expectedInitramfsSHA256 = nil
        case "short-digest": specification.expectedInitramfsSHA256 = "abc"
        case "uppercase-digest": specification.expectedInitramfsSHA256 = String(repeating: "A", count: 64)
        default: specification.expectedInitramfsSHA256 = String(repeating: "g", count: 64)
        }
        let transaction = try RawDiskBootTransaction(specification: specification, disks: fixture.disks)
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.send(fixture.hello())
        try pair.send(fixture.synced(try pair.manifest()))
        _ = try pair.commit()
        try await worker.result().get()
        #expect(throws: (any Error).self) { _ = try transaction.verifiedStorageDiskBoot() }
    }

    @Test func storageBootstrapKernelArgumentsSelectExplicitModeWithoutChangingContainers() throws {
        let fixture = try BootFixture(kind: .storage)
        defer { fixture.remove() }
        var specification = fixture.specification
        specification.kernelArguments = ["console=hvc0", "quiet"]
        #expect(try VMShimServer.bootstrapKernelArguments(specification) == ["console=hvc0", "quiet", "cengine.storage_mode=lifecycle"])
        specification.kind = .container
        #expect(try VMShimServer.bootstrapKernelArguments(specification) == specification.kernelArguments)
    }

    @Test(arguments: ["cengine.storage_mode", "cengine.storage_mode=legacy", "cengine.storage_mode=managed",
                      "console=hvc0 cengine.storage_mode=managed", "quiet\tcengine.storage_mode=legacy\n"])
    func callerCannotInjectStorageBootstrapMode(argument: String) throws {
        let fixture = try BootFixture(kind: .storage)
        defer { fixture.remove() }
        var specification = fixture.specification
        specification.kernelArguments = [argument]
        #expect(throws: (any Error).self) { _ = try VMShimServer.bootstrapKernelArguments(specification) }
        specification.kind = .container
        #expect(throws: (any Error).self) { _ = try VMShimServer.bootstrapKernelArguments(specification) }
    }

    @Test(arguments: [UInt32(4105), 4106, 4107, 4108])
    func privateStoragePortsCannotBecomeGeneralRelays(port: UInt32) throws {
        let fixture = try BootFixture(kind: .storage)
        defer { fixture.remove() }
        var specification = fixture.specification
        specification.socketRelays = [.init(path: "/unused", port: port)]
        #expect(throws: (any Error).self) { _ = try VMShimServer.bootstrapKernelArguments(specification) }
        specification.kind = .container
        #expect(throws: (any Error).self) { _ = try VMShimServer.bootstrapKernelArguments(specification) }
        specification.socketRelays = [.init(path: "/unused", port: 4104)]
        #expect(try VMShimServer.bootstrapKernelArguments(specification) == specification.kernelArguments)
    }

    @Test(arguments: ["missing-file", "missing-version", "wrong-version", "missing-lifecycle", "wrong-lifecycle",
                      "missing-workload", "wrong-workload", "wrong-schema", "wrong-protocol", "wrong-digest", "supported"])
    func managedStorageRequiresCompanionAssetCapabilityBeforeVZ(fault: String) throws {
        let fixture = try BootFixture(kind: .storage)
        defer { fixture.remove() }
        let image = Data("managed bootstrap image".utf8)
        let imageURL = fixture.root.appending(path: "storage-initramfs")
        try image.write(to: imageURL)
        var specification = fixture.specification
        specification.kernelPath = fixture.root.appending(path: "vmlinux").path
        specification.initialRamdiskPath = imageURL.path
        let digest = SHA256.hash(data: image).map { String(format: "%02x", $0) }.joined()
        specification.expectedInitramfsSHA256 = digest
        if fault != "missing-file" {
            var metadata: [String: Any] = ["schemaVersion": 1, "protocolVersion": 1,
                "storageServiceBootVersion": 2, "storageLifecycleVersion": 2, "workloadStorageBootVersion": 1,
                "containerInitramfsSHA256": containerBootTestSHA256, "storageInitramfsSHA256": digest]
            switch fault {
            case "missing-version": metadata.removeValue(forKey: "storageServiceBootVersion")
            case "wrong-version": metadata["storageServiceBootVersion"] = 1
            case "missing-lifecycle": metadata.removeValue(forKey: "storageLifecycleVersion")
            case "wrong-lifecycle": metadata["storageLifecycleVersion"] = 1
            case "missing-workload": metadata.removeValue(forKey: "workloadStorageBootVersion")
            case "wrong-workload": metadata["workloadStorageBootVersion"] = 2
            case "wrong-schema": metadata["schemaVersion"] = 2
            case "wrong-protocol": metadata["protocolVersion"] = 2
            case "wrong-digest": metadata["storageInitramfsSHA256"] = String(repeating: "0", count: 64)
            default: break
            }
            try JSONSerialization.data(withJSONObject: metadata).write(to: fixture.root.appending(path: "disk-bootstrap.json"))
        }
        if fault == "supported" {
            let pinned = try VMShimServer.pinnedBootstrapInitramfs(specification)
            defer { try? pinned.close() }
            #expect(try pinned.readToEnd() == image)
        } else {
            #expect(throws: (any Error).self) { _ = try VMShimServer.pinnedBootstrapInitramfs(specification) }
        }
    }

    private func expectInjected(_ result: Result<Void, any Error>) {
        guard case .failure(let error) = result else { Issue.record("fault did not fail"); return }
        #expect(error as? BootFault == .injected)
    }
    private func expectNonCancellationFailure(_ result: Result<Void, any Error>) {
        guard case .failure(let error) = result else { Issue.record("fault did not fail"); return }
        #expect(!(error is CancellationError))
    }
    private func expectTransportFailure(_ result: Result<Void, any Error>) {
        guard case .failure(let error) = result else { Issue.record("transport did not fail"); return }
        #expect((error as? EngineError)?.message == "disk bootstrap transport failed")
    }
}

private let storageBootTestSHA256 = String(repeating: "a1", count: 32)
private let containerBootTestSHA256 = String(repeating: "b2", count: 32)

private func containerBootWasReleased(_ semaphore: DispatchSemaphore) async -> Bool {
    await withCheckedContinuation { continuation in
        Thread.detachNewThread {
            continuation.resume(returning: semaphore.wait(timeout: .now() + 15) == .success)
        }
    }
}

private final class ContainerBootReleaseSignal: Sendable {
    let released: DispatchSemaphore
    init(_ released: DispatchSemaphore) { self.released = released }
    deinit { released.signal() }
}

private extension BootFixture {
    func containerProof(launch: String? = nil, nonce: String? = nil, checkBeforeCommit: Bool = false,
                        releaseSignal: DispatchSemaphore? = nil) async throws -> RawDiskBootTransaction.VerifiedContainerBoot {
        let pair = try BootSocketPair()
        defer { pair.close() }
        var specification = self.specification
        specification.shimLaunchUUID = launch ?? specification.shimLaunchUUID
        specification.expectedInitramfsSHA256 = containerBootTestSHA256
        let owner = Mutex<RawDiskBootTransaction?>(nil)
        let checked = Mutex<[RawDiskBootTransaction.Boundary]>([])
        let lifetime = releaseSignal.map { ContainerBootReleaseSignal($0) }
        let transaction = try RawDiskBootTransaction(specification: specification, disks: disks, hook: { [lifetime] boundary in
            defer { withExtendedLifetime(lifetime) {} }
            if checkBeforeCommit {
                let current = try #require(owner.withLock { $0 })
                #expect(throws: (any Error).self) { _ = try current.verifiedContainerBoot() }
                checked.withLock { $0.append(boundary) }
            }
        })
        owner.withLock { $0 = transaction }
        defer { owner.withLock { $0 = nil } }
        #expect(throws: (any Error).self) { _ = try transaction.verifiedContainerBoot() }
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.send(hello(nonce: nonce))
        let manifest = try pair.manifest()
        #expect(manifest.kind == "container")
        try pair.send(synced(manifest))
        let commit = try pair.commit()
        #expect(commit.shimLaunchUUID == specification.shimLaunchUUID)
        #expect(commit.guestBootNonce == (nonce ?? self.nonce))
        try await worker.result().get()
        if checkBeforeCommit {
            #expect(checked.withLock { $0 }.contains(.afterAcknowledgementValidation))
            #expect(checked.withLock { $0 }.last == .beforeCommit)
        }
        let proof = try transaction.verifiedContainerBoot()
        #expect(try transaction.verifiedContainerBoot() === proof)
        return proof
    }

    func storageProof(checkBeforeCommit: Bool = false) async throws -> RawDiskBootTransaction.VerifiedStorageDiskBoot {
        let pair = try BootSocketPair()
        defer { pair.close() }
        var specification = self.specification
        specification.expectedInitramfsSHA256 = storageBootTestSHA256
        let owner = Mutex<RawDiskBootTransaction?>(nil)
        let checked = Mutex<[RawDiskBootTransaction.Boundary]>([])
        let transaction = try RawDiskBootTransaction(specification: specification, disks: disks, hook: { boundary in
            if checkBeforeCommit, boundary == .afterAcknowledgementValidation || boundary == .beforeCommit {
                let current = try #require(owner.withLock { $0 })
                #expect(throws: (any Error).self) { _ = try current.verifiedStorageDiskBoot() }
                checked.withLock { $0.append(boundary) }
            }
        })
        owner.withLock { $0 = transaction }
        defer { owner.withLock { $0 = nil } } // Break the hook's test-only reference cycle.
        #expect(throws: (any Error).self) { _ = try transaction.verifiedStorageDiskBoot() }
        let worker = try BootWorker(transaction, host: pair.host)
        defer { worker.cancel() }
        try pair.send(hello())
        let manifest = try pair.manifest()
        #expect(manifest.kind == "storage")
        try pair.send(synced(manifest))
        let commit = try pair.commit()
        #expect(commit.shimLaunchUUID == specification.shimLaunchUUID)
        #expect(commit.guestBootNonce == nonce)
        try await worker.result().get()
        if checkBeforeCommit {
            #expect(checked.withLock { $0 } == [.afterAcknowledgementValidation, .beforeCommit])
        }
        return try transaction.verifiedStorageDiskBoot()
    }
}

/// Disk-only fixture shared by lifecycle private-channel tests. No v1 coordinator
/// or serialized receipt can supply this actual committed 4105 disk proof.
struct StorageBootFixture: Sendable {
    private let disk: BootFixture
    let proof: RawDiskBootTransaction.VerifiedStorageDiskBoot
    let pair: BootSocketPair

    static func make() async throws -> Self {
        let disk = try BootFixture(kind: .storage)
        do {
            let proof = try await disk.storageProof()
            return Self(disk: disk, proof: proof, pair: try BootSocketPair())
        } catch { disk.remove(); throw error }
    }

    func close() { pair.close(); disk.remove() }
}

private final class StorageBootValue<Value: Sendable>: Sendable {
    let value = Mutex<Value?>(nil)
}

/// Submit blocking coordinator work before peer I/O, off the cooperative executor.
/// Cleanup joins both the operation and watchdog before any socket descriptor closes.
final class StorageBootWorker<Value: Sendable> {
    // This bounded test barrier waits only for a dedicated OS thread, never
    // for work scheduled on Swift's cooperative executor.
    func waitForStart(_ semaphore: DispatchSemaphore, seconds: Double = 1) -> Bool {
        semaphore.wait(timeout: .now() + seconds) == .success
    }

    private let state: BootWorkerState
    private let value: StorageBootValue<Value>
    private let finished: DispatchGroup
    private let watchdogFinished: DispatchGroup
    private let cancelIO: @Sendable () -> Void

    init(cancel: @escaping @Sendable () -> Void, watchdogTimeout: DispatchTime = .now() + 15,
         operation: @escaping @Sendable () throws -> Value) {
        let state = BootWorkerState()
        let value = StorageBootValue<Value>()
        let finished = DispatchGroup(), watchdogFinished = DispatchGroup()
        self.state = state; self.value = value; self.finished = finished
        self.watchdogFinished = watchdogFinished; self.cancelIO = cancel
        finished.enter()
        watchdogFinished.enter()
        Thread.detachNewThread {
            defer { watchdogFinished.leave() }
            guard finished.wait(timeout: watchdogTimeout) == .timedOut else { return }
            state.expire()
            if state.expired.withLock({ $0 }) { cancel() }
        }
        Thread.detachNewThread {
            let result = Result<Void, any Error> {
                let output = try operation()
                value.value.withLock { $0 = output }
            }
            finished.leave()
            state.finish(result)
        }
    }

    func result() async throws -> Value {
        let result = await state.result()
        #expect(!state.expired.withLock { $0 }, "safety watchdog fired; timeout is NOT transport-loss evidence")
        try result.get()
        return try #require(value.value.withLock { $0 })
    }

    func finishedWithin(_ seconds: Double) -> Bool {
        finished.wait(timeout: .now() + seconds) == .success
    }

    func settle() {
        if !finishedWithin(0) { cancelIO() }
        precondition(finishedWithin(15), "private storage worker failed to settle before descriptor cleanup")
        // Cancellation can already be executing when the operation completes.
        // Joining just the operation would let that callback hit a reused FD.
        precondition(watchdogFinished.wait(timeout: .now() + 15) == .success,
            "private storage watchdog failed to settle before descriptor cleanup")
    }
}

private func bootTestLimitSendBuffer(_ descriptor: Int32) throws {
    var size: Int32 = 1_024
    try #require(setsockopt(descriptor, SOL_SOCKET, SO_SNDBUF, &size,
                           socklen_t(MemoryLayout<Int32>.size)) == 0)
}

private func bootTestReadPrefix(_ descriptor: Int32) throws -> Int {
    var ready = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
    try #require(poll(&ready, 1, 3_000) > 0)
    var bytes = [UInt8](repeating: 0, count: 4)
    try #require(recv(descriptor, &bytes, bytes.count, MSG_DONTWAIT) == 4)
    return Int(bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) })
}

private enum BootFault: Error, Equatable { case injected }

private final class BootWorkerState: Sendable {
    private struct Completion {
        var result: Result<Void, any Error>?
        var continuation: CheckedContinuation<Result<Void, any Error>, Never>?
    }
    let cancelled = Mutex(false)
    let expired = Mutex(false)
    private let completion = Mutex(Completion())

    func expire() {
        completion.withLock {
            guard $0.result == nil else { return }
            expired.withLock { $0 = true }
            cancelled.withLock { $0 = true }
        }
    }

    func finish(_ result: Result<Void, any Error>) {
        let continuation = completion.withLock {
            $0.result = result
            let continuation = $0.continuation
            $0.continuation = nil
            return continuation
        }
        continuation?.resume(returning: result)
    }

    func result() async -> Result<Void, any Error> {
        await withCheckedContinuation { continuation in
            let result = completion.withLock {
                if $0.result == nil { $0.continuation = continuation }
                return $0.result
            }
            if let result { continuation.resume(returning: result) }
        }
    }
}

private struct BootWorker {
    let task: Task<Void, any Error>
    private let watchdog: DispatchWorkItem
    private let state: BootWorkerState
    private let settled: DispatchSemaphore

    init(_ transaction: RawDiskBootTransaction, host: FileHandle,
         policy: RawDiskBootTransaction.Policy = .journalDriven) throws {
        // Own a separate descriptor before enqueueing. Even failed test cleanup
        // must not leave a queued worker dereferencing a closed FileHandle.
        let descriptor = fcntl(host.fileDescriptor, F_DUPFD_CLOEXEC, 0)
        guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let settled = DispatchSemaphore(value: 0)
        self.settled = settled
        let state = BootWorkerState()
        self.state = state
        let watchdog = DispatchWorkItem { state.expire() }
        self.watchdog = watchdog
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 15, execute: watchdog)
        // Launch an OS thread before returning to synchronous peer I/O. Global
        // dispatch shares a pool with blocking tests and can starve this worker.
        Thread.detachNewThread {
            defer { Darwin.close(descriptor) }
            let result = Result {
                try transaction.run(descriptor: descriptor, policy: policy, isCancelled: {
                    state.cancelled.withLock { $0 }
                })
            }
            // Darwin rejects SHUT_RDWR with ENOTCONN after a peer write EOF,
            // without closing our write side. Explicit SHUT_WR still sends EOF.
            _ = shutdown(descriptor, SHUT_WR)
            settled.signal()
            state.finish(result)
        }
        task = Task.detached {
            try await withTaskCancellationHandler {
                try await state.result().get()
            } onCancel: {
                state.cancelled.withLock { $0 = true }
            }
        }
    }
    func result() async -> Result<Void, any Error> {
        let result = await task.result
        watchdog.cancel()
        #expect(!state.expired.withLock { $0 }, "safety watchdog fired; timeout is NOT evidence of transport loss")
        return result
    }
    func cancel() {
        watchdog.cancel()
        state.cancelled.withLock { $0 = true }
        task.cancel()
        // Settle the dispatch worker even when peer I/O throws, before closing
        // the pair and allowing descriptor numbers to be reused.
        #expect(settled.wait(timeout: .now() + 15) == .success)
    }
}

struct BootSocketPair: Sendable {
    let host: FileHandle
    let guest: FileHandle
    init() throws {
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { throw POSIXError(.EIO) }
        var timeout = timeval(tv_sec: 15, tv_usec: 0)
        var noSignal: Int32 = 1
        for fd in pair {
            _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
            _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
            _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
        }
        host = FileHandle(fileDescriptor: pair[0], closeOnDealloc: true)
        guest = FileHandle(fileDescriptor: pair[1], closeOnDealloc: true)
    }
    func close() { try? host.close(); try? guest.close() }
    func send<T: Encodable>(_ value: T) throws { try guest.write(contentsOf: DiskInitializationProtocol.encode(value)) }
    func sendUnchecked<T: Encodable>(_ value: T) throws {
        let body = try JSONEncoder().encode(value)
        var count = UInt32(body.count).bigEndian
        try guest.write(contentsOf: Data(bytes: &count, count: 4) + body)
    }
    func manifest() throws -> DiskInitializationProtocol.Manifest {
        try DiskInitializationProtocol.decode(DiskInitializationProtocol.Manifest.self, from: readFrame())
    }
    func commit() throws -> DiskInitializationProtocol.Commit {
        try DiskInitializationProtocol.decode(DiskInitializationProtocol.Commit.self, from: readFrame())
    }
    func expectNoBytesAvailable() throws {
        var byte: UInt8 = 0
        let amount = recv(guest.fileDescriptor, &byte, 1, MSG_PEEK | MSG_DONTWAIT)
        #expect(amount == -1 && errno == EAGAIN)
    }
    func remainingBytes() throws -> Data { try guest.readToEnd() ?? Data() }
    private func readFrame() throws -> Data {
        func read(_ count: Int) throws -> Data {
            var data = Data()
            while data.count < count {
                guard let part = try guest.read(upToCount: count - data.count), !part.isEmpty else { throw POSIXError(.EIO) }
                data.append(part)
            }
            return data
        }
        let count = try read(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard count > 0, count <= 65_536 else { throw POSIXError(.EIO) }
        return try read(Int(count))
    }
}

private struct BootFixture: Sendable {
    let root: URL
    let disks: [VMShimHeldDisk]
    let originals: [RawDiskInitialization.Record]
    let specification: VMShimProtocol.Specification
    let nonce = UUID().uuidString.lowercased()
    init(kind: VMShimProtocol.Specification.Kind = .container, directVolumeCount: Int = 1) throws {
        root = FileManager.default.temporaryDirectory.appending(path: "cengine-boot-transaction-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let directory = try PersistentStateDirectory.open(root)
        var held: [VMShimHeldDisk] = []
        var records: [RawDiskInitialization.Record] = []
        for ordinal in 0..<(kind == .storage ? 1 : directVolumeCount + 1) {
            let name = "disk\(ordinal).ext4"
            guard case .created(let created) = try RawDiskInitialization.createNewDisk(in: directory, named: name, size: 32 << 20) else {
                throw BootFault.injected
            }
            records.append(created.record)
            let opened = try directory.openRegularFile(named: name, access: .readWrite)
            guard flock(opened.handle.fileDescriptor, LOCK_EX | LOCK_NB) == 0 else { throw POSIXError(.EIO) }
            held.append(.init(ordinal: ordinal, role: ordinal == 0 ? (kind == .storage ? "storage-root" : "container-root") : "direct-volume",
                              volumeName: ordinal == 0 ? nil : (ordinal == 1 ? "volume" : "volume\(ordinal - 1)"), parent: directory, name: name,
                              handle: opened.handle, identity: opened.identity, bytes: 32 << 20))
        }
        disks = held
        originals = records
        func identity(_ disk: VMShimHeldDisk) -> VMShimProtocol.FileIdentity {
            .init(device: disk.identity.device, inode: disk.identity.inode, volumeUUID: disk.identity.volumeUUID)
        }
        specification = .init(kind: kind, containerID: "test", generation: 1, token: "unused", kernelPath: "/unused",
                              initialRamdiskPath: "/unused", rootDiskPath: root.appending(path: "disk0.ext4").path,
                              rootDiskIdentity: identity(held[0]), rootDiskSize: held[0].bytes,
                              volumeDisks: held.dropFirst().map { .init(name: $0.volumeName!, path: directory.url.appending(path: $0.name).path,
                                                                       identity: identity($0), size: $0.bytes) },
                              cpus: 1, memoryBytes: 1 << 30, macAddress: "02:00:00:00:00:01",
                              socketPath: "/unused", logPath: "/unused", shimLaunchUUID: UUID().uuidString.lowercased(),
                              diskBootstrapVersion: 1, expectedInitramfsSHA256: nil)
    }
    func hello(nonce: String? = nil) -> DiskInitializationProtocol.Hello {
        .init(kind: specification.kind.rawValue, guestBootNonce: nonce ?? self.nonce,
              disks: disks.map { .init(ordinal: $0.ordinal, blockIdentifier: $0.blockIdentifier, bytes: $0.bytes) })
    }
    func synced(_ manifest: DiskInitializationProtocol.Manifest) -> DiskInitializationProtocol.Synced {
        .init(shimLaunchUUID: manifest.shimLaunchUUID, guestBootNonce: manifest.guestBootNonce,
              disks: manifest.disks.map { .init(ordinal: $0.ordinal, bytes: $0.expectedBytes,
                                                ext4UUID: $0.ext4UUID!, operationUUID: $0.operationUUID) })
    }
    func record(_ disk: VMShimHeldDisk) throws -> RawDiskInitialization.Record {
        guard case .journal(let record) = try RawDiskInitialization.inspectExisting(
            in: disk.parent, named: disk.name, expectedSize: disk.bytes, heldDiskDescriptor: disk.handle.fileDescriptor
        ) else { throw BootFault.injected }
        return record
    }
    func expectStates(_ states: [RawDiskInitialization.State]) throws {
        #expect(states.count == disks.count)
        for (disk, state) in zip(disks, states) {
            let current = try record(disk)
            #expect(current.state == state)
            #expect(current.ext4UUID == originals[disk.ordinal].ext4UUID)
            #expect(current.operationUUID == originals[disk.ordinal].operationUUID)
        }
    }
    func fileSnapshot() throws -> [String: Data] {
        let names = try FileManager.default.contentsOfDirectory(atPath: root.path)
        return try Dictionary(uniqueKeysWithValues: names.map { ($0, try Data(contentsOf: root.appending(path: $0))) })
    }
    func journalSnapshot() throws -> [String: Data] {
        let names = try FileManager.default.contentsOfDirectory(atPath: root.path).filter { $0.hasPrefix(".raw-init-") }
        return try Dictionary(uniqueKeysWithValues: names.map { ($0, try Data(contentsOf: root.appending(path: $0))) })
    }
    func expectNewBootRefused() {
        #expect(throws: (any Error).self) { _ = try RawDiskBootTransaction(specification: specification, disks: disks) }
    }
    func remove() { try? FileManager.default.removeItem(at: root) }
}

@Suite("Lifecycle private boot mounted prerequisite")
struct LifecycleBootMountedPrerequisiteTests {
    @Test func mountedBootCannotInitializeLifecycle() async throws {
        let fixture = try BootFixture(kind: .storage)
        defer { fixture.remove() }
        _ = try await fixture.storageProof()
        let mounted = try await fixture.storageProof()
        let pair = try BootSocketPair()
        defer { pair.close() }
        let frames = try StorageLifecycleServiceBootProtocolTests.vectors()
        let cfg = try #require(frames[1].configuration)
        #expect(throws: (any Error).self) {
            try PrivateStorageLifecycleBootCoordinator(verified: mounted, configuration: cfg, descriptor: pair.host.fileDescriptor)
        }
        let open = StorageLifecycleServiceBootProtocol.Configuration(action: .open, rootPublicKey: cfg.rootPublicKey,
            signed: cfg.signed, nowUnixSeconds: cfg.nowUnixSeconds, lifetimeSeconds: cfg.lifetimeSeconds)
        #expect(throws: (any Error).self) {
            try PrivateStorageLifecycleBootCoordinator(verified: mounted, configuration: open, descriptor: pair.host.fileDescriptor)
        }
        let pairedOpen = try #require(frames[5].configuration)
        let coordinator = try PrivateStorageLifecycleBootCoordinator(verified: mounted, configuration: pairedOpen, descriptor: pair.host.fileDescriptor)
        coordinator.close()
    }
}
#endif

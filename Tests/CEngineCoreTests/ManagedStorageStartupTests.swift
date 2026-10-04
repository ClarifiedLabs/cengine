import Testing
@testable import CEngineRuntime

#if os(macOS)
import Foundation
import Darwin
@testable import CEngineCore

/// Read-only census: bytes, names, inode, permissions, owner and modification/change
/// times. Access time is deliberately excluded because reading may update it.
struct StoragePreflightSnapshot: Equatable {
    let entries: [String: Entry]
    struct Entry: Equatable {
        let metadata: [UInt64]
        let bytes: Data
    }
    init(_ url: URL) throws {
        var entries: [String: Entry] = [:]
        func visit(_ url: URL, _ name: String) throws {
            var info = stat()
            guard lstat(url.path, &info) == 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
            let type = info.st_mode & S_IFMT
            let bytes: Data
            if type == S_IFREG { bytes = try Data(contentsOf: url) }
            else if type == S_IFLNK { bytes = Data(try FileManager.default.destinationOfSymbolicLink(atPath: url.path).utf8) }
            else { bytes = Data() }
            entries[name] = Entry(metadata: [UInt64(info.st_dev), UInt64(info.st_ino), UInt64(info.st_mode),
                UInt64(info.st_uid), UInt64(info.st_gid), UInt64(info.st_size), UInt64(info.st_nlink),
                UInt64(info.st_mtimespec.tv_sec), UInt64(info.st_mtimespec.tv_nsec),
                UInt64(info.st_ctimespec.tv_sec), UInt64(info.st_ctimespec.tv_nsec)], bytes: bytes)
            if type == S_IFDIR {
                for child in try FileManager.default.contentsOfDirectory(atPath: url.path).sorted() {
                    try visit(url.appending(path: child), name + "/" + child)
                }
            }
        }
        try visit(url, ".")
        self.entries = entries
    }
}

@Suite struct ManagedLifecycleStartupTests {
    @Test func unsignedProcessCannotSelectAnyLifecycleNamespace() {
        #expect(throws: (any Error).self) { try ManagedStorageStartup.lifecycleConfiguration() }
    }

    @MainActor final class Recorder: ManagedLifecycleStartupSteps {
        var format: ManagedStorageLifecycleOwner.StoreFormat = .fresh
        var failAt: String?
        var replacementPending = false
        var eligibility: StorageLifecycleColdRootProtocol.Eligibility = .live
        var calls: [String] = []
        var generationPreflight: (() async throws -> Void)?
        private func step(_ name: String) throws {
            calls.append(name)
            if failAt == name { throw EngineError(.conflict, "injected \(name)") }
        }
        func classify() throws -> ManagedStorageLifecycleOwner.StoreFormat { try step("classify"); return format }
        func validateExistingGeneration() async throws {
            try step("generationPreflight")
            try await generationPreflight?()
        }
        func openInitializationDisk() throws { try step("resumeOpen") }
        func prepareResume() async throws { try step("resumePrepare") }
        func launchResumeShim() async throws { try step("resumeSpawn") }
        func prepareResumeDisk() async throws { try step("resumeDisk") }
        func bootResume() async throws { try step("resumeBoot") }
        func admitInitialization() async throws { try step("resumeAdmit") }
        func provisionDisk() throws { try step("disk") }
        func openExistingDisk() throws { try step("open") }
        func prepareReplacementRecovery() async throws -> Bool { try step("replacementCheck"); return replacementPending }
        func recoverReplacement() async throws { try step("replacementComplete") }
        func coldStatus() async throws -> StorageLifecycleColdRootProtocol.Eligibility { try step("coldStatus"); return eligibility }
        func prepareTakeover() async throws { try step("prepareTakeover") }
        func freezeColdLaunch() throws { try step("freeze") }
        func launchColdShim() async throws { try step("coldSpawn") }
        func prepareColdDisk() async throws { try step("coldDisk") }
        func bootCold() async throws { try step("coldBoot") }
        func adoptShim() async throws { try step("adoptShim") }
        func reattachShim() async throws { try step("reattach") }
        func takeover() async throws { try step("takeover") }
        func recoverWorkload() async throws { try step("recover") }
        func bindScope() async throws { try step("bind") }
        func prepareOwner() async throws { try step("prepare") }
        func launchShim() async throws { try step("spawn") }
        func prepareFreshDisk() async throws { try step("freshDisk") }
        func provisionFresh() async throws { try step("provision") }
        func bootFresh() async throws { try step("boot") }
        func enrollAdoption() async throws { try step("enroll") }
        func connectWorkload() async throws { try step("connect") }
        func queryWorkload() async throws { try step("query") }
        func adopt() async throws { try step("adopt") }
        func abandon() async { calls.append("abandon") }
    }

    @Test @MainActor func freshStartupRunsInOrderClassifyBeforeDiskAndSpawn() async throws {
        let recorder = Recorder()
        try await ManagedLifecycleStartup.run(recorder)
        #expect(recorder.calls == ["classify", "disk", "bind", "prepare", "spawn", "freshDisk",
                                   "provision", "boot", "connect", "query", "adopt", "enroll"])
    }
    @Test @MainActor func initializationResumesBeforeAdmitting() async throws {
        let recorder = Recorder(); recorder.format = .initialization
        try await ManagedLifecycleStartup.run(recorder)
        #expect(recorder.calls == ["classify", "resumeOpen", "generationPreflight", "bind", "resumePrepare", "resumeSpawn", "resumeDisk", "resumeBoot", "enroll", "resumeAdmit", "adopt"])
    }
    @Test(arguments: ["resumeOpen", "generationPreflight", "bind", "resumePrepare", "resumeSpawn", "resumeDisk", "resumeBoot", "enroll", "resumeAdmit"])
    @MainActor func initializationFailuresNeverFormatOrAdmit(stage: String) async {
        let recorder = Recorder(); recorder.format = .initialization; recorder.failAt = stage
        await #expect(throws: EngineError.self) { try await ManagedLifecycleStartup.run(recorder) }
        #expect(recorder.calls.suffix(2) == [stage, "abandon"])
        #expect(!recorder.calls.contains("disk") && !recorder.calls.contains("adopt"))
    }
    @Test @MainActor func existingV2AdoptsAndRecoversWithoutProvisioningOrSpawn() async throws {
        let recorder = Recorder(); recorder.format = .existingV2
        try await ManagedLifecycleStartup.run(recorder)
        #expect(recorder.calls == ["classify", "open", "generationPreflight", "bind", "replacementCheck", "coldStatus", "prepareTakeover", "adoptShim", "reattach", "takeover", "recover", "adopt"])
    }
    @Test @MainActor func replacementRecoveryPrecedesColdAndTakeover() async throws {
        let recorder = Recorder(); recorder.format = .existingV2; recorder.replacementPending = true
        try await ManagedLifecycleStartup.run(recorder)
        #expect(recorder.calls == ["classify", "open", "generationPreflight", "bind", "replacementCheck", "adoptShim", "reattach",
            "replacementComplete", "takeover", "recover", "adopt"])
    }
    @Test(arguments: ["replacementCheck", "adoptShim", "reattach", "replacementComplete", "takeover", "recover"])
    @MainActor func replacementFailureNeverFallsBack(stage: String) async {
        let recorder = Recorder(); recorder.format = .existingV2; recorder.replacementPending = true; recorder.failAt = stage
        await #expect(throws: EngineError.self) { try await ManagedLifecycleStartup.run(recorder) }
        #expect(recorder.calls.suffix(2) == [stage, "abandon"])
        for forbidden in ["coldStatus", "prepareTakeover", "freeze", "coldSpawn", "disk", "spawn", "boot", "adopt"] {
            #expect(!recorder.calls.contains(forbidden))
        }
    }
    @Test @MainActor func coldStartupUsesOneFrozenLaunchThenEnrollmentAndRecovery() async throws {
        let recorder = Recorder(); recorder.format = .existingV2; recorder.eligibility = .eligible
        try await ManagedLifecycleStartup.run(recorder)
        #expect(recorder.calls == ["classify", "open", "generationPreflight", "bind", "replacementCheck", "coldStatus", "prepareTakeover", "freeze",
            "coldSpawn", "coldDisk", "coldBoot", "enroll", "recover", "adopt"])
    }
    @Test @MainActor func unknownColdStatusRefusesWithoutLaunchingOrAdopting() async {
        let recorder = Recorder(); recorder.format = .existingV2; recorder.eligibility = .unavailable
        await #expect(throws: EngineError.self) { try await ManagedLifecycleStartup.run(recorder) }
        #expect(recorder.calls == ["classify", "open", "generationPreflight", "bind", "replacementCheck", "coldStatus", "abandon"])
    }
    @Test(arguments: ["freeze", "coldSpawn", "coldDisk", "coldBoot", "enroll", "recover"])
    @MainActor func coldFailuresNeverCreateFreshDiskOrAdmitBackend(stage: String) async {
        let recorder = Recorder(); recorder.format = .existingV2; recorder.eligibility = .eligible; recorder.failAt = stage
        await #expect(throws: EngineError.self) { try await ManagedLifecycleStartup.run(recorder) }
        #expect(recorder.calls.suffix(2) == [stage, "abandon"])
        for forbidden in ["disk", "spawn", "freshDisk", "provision", "boot", "adopt", "adoptShim", "reattach"] {
            #expect(!recorder.calls.contains(forbidden))
        }
    }
    @Test(arguments: ["open", "generationPreflight", "bind", "replacementCheck", "coldStatus", "prepareTakeover", "adoptShim", "reattach", "takeover", "recover"])
    @MainActor func existingFailureNeverFallsBackToFreshOrAdmitsBackend(stage: String) async {
        let recorder = Recorder(); recorder.format = .existingV2; recorder.failAt = stage
        await #expect(throws: EngineError.self) { try await ManagedLifecycleStartup.run(recorder) }
        #expect(recorder.calls.suffix(2) == [stage, "abandon"])
        for forbidden in ["disk", "spawn", "freshDisk", "provision", "boot", "adopt", "enroll"] {
            #expect(!recorder.calls.contains(forbidden))
        }
    }
    @Test @MainActor func unsupportedClassificationRefusesWithoutAnyStep() async {
        let recorder = Recorder(); recorder.failAt = "classify"
        await #expect(throws: EngineError.self) { try await ManagedLifecycleStartup.run(recorder) }
        #expect(recorder.calls == ["classify"])
    }
    @Test @MainActor func midStartupFailureContainsAndNeverAdopts() async {
        let recorder = Recorder(); recorder.failAt = "boot"
        await #expect(throws: EngineError.self) { try await ManagedLifecycleStartup.run(recorder) }
        #expect(recorder.calls.suffix(2) == ["boot", "abandon"])
        #expect(!recorder.calls.contains("adopt"))
    }

    @Test @MainActor func enrollmentIsLastAndFailureAbandons() async {
        let recorder = Recorder(); recorder.failAt = "enroll"
        await #expect(throws: EngineError.self) { try await ManagedLifecycleStartup.run(recorder) }
        #expect(recorder.calls.suffix(3) == ["adopt", "enroll", "abandon"])
        #expect(recorder.calls.contains("query"))
    }

    private func publishGeneration(_ fixture: StorageRecoveryFixture) throws -> RawStorageShimRecovery.PreparedLaunch {
        let launch = try RawStorageShimRecovery.prepareLaunch(fixture.specification)
        _ = try RawStorageShimRecovery.publishLaunch(specificationURL: launch.specificationURL,
            data: launch.data, diskHandle: launch.diskHandle)
        return launch
    }

    private func generationStatus(_ launch: RawStorageShimRecovery.PreparedLaunch, uuid: UUID?) throws -> VMShimProtocol.Status {
        let generation = try #require(try RawStorageShimRecovery.publishedGeneration(for: launch.specification))
        let identity = generation.record.process
        return .init(containerID: launch.specification.containerID, generation: launch.specification.generation,
            state: .running, processIdentifier: identity.pid,
            processStartTime: identity.startSeconds * 1_000_000 + identity.startMicroseconds,
            executableUUID: uuid, shimLaunchUUID: launch.specification.shimLaunchUUID)
    }

    @Test(arguments: ["same", "foreign", "missing-shim-build", "missing-engine-build"], [false, true])
    @MainActor func liveGenerationBuildCheckPrecedesAllHelperIO(mode: String, resuming: Bool) async throws {
        let fixture = try StorageRecoveryFixture(); defer { fixture.remove() }
        let launch = try publishGeneration(fixture); defer { withExtendedLifetime(launch) {} }
        let uuid = UUID()
        let reply = try generationStatus(launch, uuid: mode == "missing-shim-build" ? nil : (mode == "foreign" ? UUID() : uuid))
        let before = try StoragePreflightSnapshot(fixture.directory)
        let recorder = Recorder(); recorder.format = resuming ? .initialization : .existingV2
        var probes = 0
        recorder.generationPreflight = {
            try await ManagedLifecycleStartup.validateExistingGeneration(launch.specification,
                executableUUID: mode == "missing-engine-build" ? nil : uuid, probe: { client in
                    probes += 1
                    #expect(client.specification == launch.specification)
                    return reply
                })
        }
        if mode == "same" {
            try await ManagedLifecycleStartup.run(recorder)
            #expect(recorder.calls.contains("adopt"))
            #expect(recorder.calls.firstIndex(of: "generationPreflight")! < recorder.calls.firstIndex(of: "bind")!)
        } else {
            do {
                try await ManagedLifecycleStartup.run(recorder)
                Issue.record("a live foreign or unidentified build must refuse startup")
            } catch let error as EngineError {
                #expect(error.code == .conflict)
                #expect(error.message == "infrastructure VM belongs to a different or older cengine build; "
                    + "reopen the updated cengine app to finish the upgrade and restart its VMs")
            }
            #expect(recorder.calls == ["classify", resuming ? "resumeOpen" : "open", "generationPreflight", "abandon"])
        }
        #expect(probes == 1)
        #expect(try StoragePreflightSnapshot(fixture.directory) == before)
    }

    @Test(arguments: ["dead", "unknown", "unpublished"])
    @MainActor func generationPreflightNeverProbesWithoutPositiveIdentity(mode: String) async throws {
        let fixture = try StorageRecoveryFixture(); defer { fixture.remove() }
        let launch = mode == "unpublished" ? nil : try publishGeneration(fixture)
        defer { withExtendedLifetime(launch) {} }
        let before = try StoragePreflightSnapshot(fixture.directory)
        let recorder = Recorder(); recorder.format = .existingV2; recorder.eligibility = .eligible
        recorder.generationPreflight = {
            try await ManagedLifecycleStartup.validateExistingGeneration(fixture.specification,
                executableUUID: nil,
                observe: { _ in mode == "dead" ? .absent(bootUUID: UUID().uuidString.lowercased()) : .unknown },
                probe: { _ in Issue.record("unproven-live generation must not be probed"); throw EngineError(.conflict, "unexpected probe") })
        }
        if mode == "unknown" {
            await #expect(throws: EngineError.self) { try await ManagedLifecycleStartup.run(recorder) }
            #expect(recorder.calls == ["classify", "open", "generationPreflight", "abandon"])
        } else {
            try await ManagedLifecycleStartup.run(recorder)
            #expect(recorder.calls.contains("coldSpawn"))
            #expect(recorder.calls.contains("adopt"))
        }
        #expect(try StoragePreflightSnapshot(fixture.directory) == before)
    }

    @Test(arguments: ["launch", "birth", "pid", "container", "generation", "lost-identity"])
    @MainActor func generationStatusMustMatchPositiveLaunchBeforeHelperIO(mode: String) async throws {
        let fixture = try StorageRecoveryFixture(); defer { fixture.remove() }
        let launch = try publishGeneration(fixture); defer { withExtendedLifetime(launch) {} }
        let uuid = UUID()
        var reply = try generationStatus(launch, uuid: uuid)
        switch mode {
        case "launch": reply.shimLaunchUUID = UUID().uuidString.lowercased()
        case "birth": reply.processStartTime = 1
        case "pid": reply.processIdentifier += 1
        case "container": reply.containerID = "another-store"
        case "generation": reply.generation += 1
        default: break
        }
        let before = try StoragePreflightSnapshot(fixture.directory)
        let recorder = Recorder(); recorder.format = .existingV2
        var observations = 0
        recorder.generationPreflight = {
            try await ManagedLifecycleStartup.validateExistingGeneration(launch.specification, executableUUID: uuid,
                observe: { pid in
                    observations += 1
                    return mode == "lost-identity" && observations > 1 ? .unknown : RawStorageShimRecovery.observe(pid)
                }, probe: { _ in reply })
        }
        await #expect(throws: EngineError.self) { try await ManagedLifecycleStartup.run(recorder) }
        #expect(recorder.calls == ["classify", "open", "generationPreflight", "abandon"])
        #expect(try StoragePreflightSnapshot(fixture.directory) == before)
    }

    @Test(arguments: ["alive", "unknown", "dead", "cancelled"])
    @MainActor func unavailableGenerationStatusRequiresProvenDeathBeforeHelperIO(mode: String) async throws {
        let fixture = try StorageRecoveryFixture(); defer { fixture.remove() }
        let launch = try publishGeneration(fixture); defer { withExtendedLifetime(launch) {} }
        let before = try StoragePreflightSnapshot(fixture.directory)
        let recorder = Recorder(); recorder.format = .existingV2; recorder.eligibility = .eligible
        var observations = 0
        recorder.generationPreflight = {
            try await ManagedLifecycleStartup.validateExistingGeneration(launch.specification,
                observe: { pid in
                    observations += 1
                    if observations > 1 {
                        if mode == "dead" { return .absent(bootUUID: UUID().uuidString.lowercased()) }
                        if mode == "unknown" { return .unknown }
                    }
                    return RawStorageShimRecovery.observe(pid)
                }, probe: { _ in
                    if mode == "cancelled" { throw CancellationError() }
                    throw EngineError(.conflict, "injected status failure")
                })
        }
        if mode == "dead" {
            try await ManagedLifecycleStartup.run(recorder)
            #expect(recorder.calls.contains("coldSpawn"))
        } else {
            if mode == "cancelled" {
                await #expect(throws: CancellationError.self) { try await ManagedLifecycleStartup.run(recorder) }
            } else {
                await #expect(throws: EngineError.self) { try await ManagedLifecycleStartup.run(recorder) }
            }
            #expect(recorder.calls == ["classify", "open", "generationPreflight", "abandon"])
        }
        #expect(try StoragePreflightSnapshot(fixture.directory) == before)
    }

    private func temporaryRoot() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appending(path: "lifecycle-preflight-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return url
    }
    @Test @MainActor func preflightAcceptsEmptyRoot() throws {
        let url = try temporaryRoot(); defer { try? FileManager.default.removeItem(at: url) }
        try ManagedLifecycleStartup.preflight(root: PersistentStateDirectory.open(url))
    }
    @Test @MainActor func preflightRefusesPartialStoreAndPreservesBytes() throws {
        let url = try temporaryRoot(); defer { try? FileManager.default.removeItem(at: url) }
        let owner = url.appending(path: "managed-storage-owner", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: owner, withIntermediateDirectories: false)
        let marker = owner.appending(path: "evidence")
        try Data("keep".utf8).write(to: marker)
        let before = try FileManager.default.contentsOfDirectory(atPath: url.path).sorted()
        #expect(throws: ManagedStorageLifecycleOwner.UnsupportedStoreFormat.self) {
            try ManagedLifecycleStartup.preflight(root: PersistentStateDirectory.open(url))
        }
        #expect(try FileManager.default.contentsOfDirectory(atPath: url.path).sorted() == before)
        #expect(try Data(contentsOf: marker) == Data("keep".utf8))
    }
    @Test(arguments: ["infrastructure/volume-token-secret", "infrastructure/volumes.ext4",
        "infrastructure/.raw-init-volumes.ext4.created.json", "infrastructure/.raw-init-volumes.ext4.lock",
        "infrastructure/.raw-init-volumes.ext4.initialized.json.pending", "volume-storage.json",
        "storage-intents/evidence", "containers/old/root.ext4", "deleted-containers/old/receipt.json", "volumes/old.ext4",
        "managed-storage-owner/manifest.json", "managed-storage-initialization/manifest.json"])
    @MainActor func oldAndAmbiguousStoresRefuseWithoutByteOrMetadataChanges(path: String) throws {
        let url = try temporaryRoot(); defer { try? FileManager.default.removeItem(at: url) }
        let file = url.appending(path: path)
        try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("old-storage-evidence".utf8).write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o640], ofItemAtPath: file.path)
        let root = try PersistentStateDirectory.open(url), before = try StoragePreflightSnapshot(url)
        #expect(throws: ManagedStorageLifecycleOwner.UnsupportedStoreFormat.self) {
            try ManagedLifecycleStartup.preflight(root: root)
        }
        #expect(try StoragePreflightSnapshot(url) == before)
    }

    @Test(arguments: ["legacy", "managed", "unknown", "lifecycle"])
    @MainActor func selectorNeverSuppliesFormatProof(mode: String) throws {
        let url = try temporaryRoot(); defer { try? FileManager.default.removeItem(at: url) }
        let root = try PersistentStateDirectory.open(url)
        struct RetiredSelection: Encodable {
            let schema = 1
            let mode: String
            let root: PersistentFileIdentity
        }
        let selection = RetiredSelection(mode: mode, root: root.identity)
        try root.writeExclusiveRegularFile(named: "shared-storage-mode.json", data: JSONEncoder().encode(selection))
        let before = try StoragePreflightSnapshot(url)
        #expect(throws: ManagedStorageLifecycleOwner.UnsupportedStoreFormat.self) {
            try ManagedLifecycleStartup.preflight(root: root)
        }
        #expect(try StoragePreflightSnapshot(url) == before)
        let infrastructure = try root.createDirectory(named: "infrastructure")
        try infrastructure.writeExclusiveRegularFile(named: "volumes.ext4", data: Data("old".utf8))
        let old = try StoragePreflightSnapshot(url)
        #expect(throws: ManagedStorageLifecycleOwner.UnsupportedStoreFormat.self) { try ManagedLifecycleStartup.preflight(root: root) }
        #expect(try StoragePreflightSnapshot(url) == old)
    }

    @Test @MainActor func freshRuntimeDirectoriesAndNonstorageAssetsRemainFresh() throws {
        let url = try temporaryRoot(); defer { try? FileManager.default.removeItem(at: url) }
        let root = try PersistentStateDirectory.open(url)
        for name in ["containers", "deleted-containers", "volumes", "metadata", "assets"] { _ = try root.createDirectory(named: name) }
        let infrastructure = try root.createDirectory(named: "infrastructure")
        _ = try infrastructure.createDirectory(named: "network-namespace")
        try infrastructure.writeExclusiveRegularFile(named: "unrelated", data: Data("keep".utf8))
        try root.writeExclusiveRegularFile(named: "settings.json", data: Data("{}".utf8))
        let before = try StoragePreflightSnapshot(url)
        #expect(try ManagedStorageLifecycleOwner.classify(root: root) == .fresh)
        try ManagedLifecycleStartup.preflight(root: root)
        #expect(try StoragePreflightSnapshot(url) == before)
    }

    @Test(arguments: ["infrastructure", "containers", "deleted-containers", "volumes", "shared-storage-mode.json"])
    @MainActor func storageSymlinksAreRefusedWithoutFollowingOrChangingThem(name: String) throws {
        let url = try temporaryRoot(); defer { try? FileManager.default.removeItem(at: url) }
        let target = try temporaryRoot(); defer { try? FileManager.default.removeItem(at: target) }
        try Data("keep".utf8).write(to: target.appending(path: "evidence"))
        try FileManager.default.createSymbolicLink(at: url.appending(path: name), withDestinationURL: target)
        let before = try StoragePreflightSnapshot(url), outside = try StoragePreflightSnapshot(target)
        #expect(throws: ManagedStorageLifecycleOwner.UnsupportedStoreFormat.self) {
            try ManagedLifecycleStartup.preflight(root: PersistentStateDirectory.open(url))
        }
        #expect(try StoragePreflightSnapshot(url) == before)
        #expect(try StoragePreflightSnapshot(target) == outside)
    }

    @Test @MainActor func replacedRootIsNotClassifiedThroughDetachedDescriptor() throws {
        let url = try temporaryRoot(), moved = url.appendingPathExtension("moved")
        defer { try? FileManager.default.removeItem(at: url); try? FileManager.default.removeItem(at: moved) }
        let root = try PersistentStateDirectory.open(url)
        try FileManager.default.moveItem(at: url, to: moved)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
        let before = try StoragePreflightSnapshot(url), detached = try StoragePreflightSnapshot(moved)
        #expect(throws: ManagedStorageLifecycleOwner.UnsupportedStoreFormat.self) { try ManagedLifecycleStartup.preflight(root: root) }
        #expect(try StoragePreflightSnapshot(url) == before)
        #expect(try StoragePreflightSnapshot(moved) == detached)
    }

    @Test @MainActor func unreadableInfrastructureRemainsRetryableAndUnmodified() throws {
        let url = try temporaryRoot(); defer { try? FileManager.default.removeItem(at: url) }
        let root = try PersistentStateDirectory.open(url)
        let infrastructure = try root.createDirectory(named: "infrastructure")
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: infrastructure.url.path)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: infrastructure.url.path) }
        #expect(throws: ManagedStorageLifecycleOwner.StoreUnavailable.self) { try ManagedLifecycleStartup.preflight(root: root) }
        let attributes = try FileManager.default.attributesOfItem(atPath: infrastructure.url.path)
        #expect(attributes[.posixPermissions] as? Int == 0)
    }

    @Test func existingStoreMessageIsExplicit() {
        #expect(ManagedLifecycleStartupError.existingStore().localizedDescription.contains("storage recovery cannot confirm that the previous process exited or find a matching running VM; data preserved"))
    }

    private func metadata(_ extra: String) throws -> GuestAssetInstaller.DiskBootstrapMetadata {
        let hash = String(repeating: "a", count: 64)
        let json = #"{"schemaVersion":1,"protocolVersion":1,"storageServiceBootVersion":2,"workloadStorageBootVersion":1,"containerInitramfsSHA256":"\#(hash)","storageInitramfsSHA256":"\#(hash)"\#(extra)}"#
        return try JSONDecoder().decode(GuestAssetInstaller.DiskBootstrapMetadata.self, from: Data(json.utf8))
    }
    @Test func lifecycleAssetCapabilityIsExplicitAndNotQualification() throws {
        #expect(throws: EngineError.self) { try metadata("").requireLifecycleStorageSupport() }
        #expect(throws: EngineError.self) { try metadata(#","storageLifecycleVersion":1"#).requireLifecycleStorageSupport() }
        #expect(throws: EngineError.self) {
            try metadata(#","storageLifecycleVersion":2,"storageLifecycleQualification":"q"}"#.dropLast().description).requireLifecycleStorageSupport()
        }
        try metadata(#","storageLifecycleVersion":2"#).requireLifecycleStorageSupport()
    }
}
#endif

#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

// Darwin fork/pre-exec can briefly retain CLOEXEC descriptions from other tests.
// Immediate lock handovers run in child-created fixtures, without retries.
@Suite struct RawStorageShimRecoveryTests {
    private typealias Recovery = RawStorageShimRecovery
    private let boot = "11111111-1111-4111-8111-111111111111"

    @Test func positiveDeathRequiresCompleteKernelEvidence() {
        let old = process()
        #expect(Recovery.liveness(old, observation: .process(old)) == .alive)
        #expect(Recovery.liveness(old, observation: .absent(bootUUID: boot)) == .dead)
        #expect(Recovery.liveness(old, observation: .process(process(start: 200, unique: 20))) == .dead)
        #expect(Recovery.liveness(old, observation: .process(process(unique: 20))) == .unknown)
        #expect(Recovery.liveness(old, observation: .process(process(start: 200))) == .unknown)
        #expect(Recovery.liveness(old, observation: .unknown) == .unknown)
        #expect(Recovery.liveness(old, observation: .absent(bootUUID: "invalid")) == .unknown)
        let reboot = Recovery.ProcessIdentity(pid: getpid(), startSeconds: 100,
            startMicroseconds: 1, bootUUID: "22222222-2222-4222-8222-222222222222", uniqueID: 10)
        #expect(Recovery.liveness(old, observation: .process(reboot)) == .dead)
    }

    @Test func permissionShortReadsAndBootRacesAreNotExit() {
        #expect(Recovery.queryFailure(byteCount: 0, error: ESRCH, bootBefore: boot, bootAfter: boot) == .absent(bootUUID: boot))
        for code in [EPERM, EACCES, EINVAL, EIO, Int32(0)] {
            let observation = Recovery.queryFailure(byteCount: 0, error: code, bootBefore: boot, bootAfter: boot)
            #expect(observation == .bootOnly(bootUUID: boot))
            #expect(Recovery.liveness(process(), observation: observation) == .unknown)
        }
        let short = Recovery.queryFailure(byteCount: 12, error: ESRCH, bootBefore: boot, bootAfter: boot)
        #expect(short == .bootOnly(bootUUID: boot))
        #expect(Recovery.liveness(process(), observation: short) == .unknown)
        #expect(Recovery.queryFailure(byteCount: 0, error: ESRCH, bootBefore: boot, bootAfter: nil) == .unknown)
    }

    @Test func unreadableReusedPIDProvesOnlyPriorBootDeath() {
        let currentBoot = "22222222-2222-4222-8222-222222222222"
        for code in [EPERM, EACCES, EINVAL, EIO, Int32(0)] {
            for count: Int32 in [0, 12] {
                let observed = Recovery.queryFailure(byteCount: count, error: code,
                    bootBefore: currentBoot, bootAfter: currentBoot)
                #expect(Recovery.liveness(process(), observation: observed) == .dead)
                let current = Recovery.ProcessIdentity(pid: getpid(), startSeconds: 200,
                    startMicroseconds: 1, bootUUID: currentBoot, uniqueID: 20)
                #expect(Recovery.liveness(current, observation: observed) == .unknown)
            }
        }
        for (before, after): (String?, String?) in [(nil, currentBoot), (currentBoot, nil),
            (boot, currentBoot), ("invalid", "invalid")] {
            let observed = Recovery.queryFailure(byteCount: 0, error: EPERM,
                bootBefore: before, bootAfter: after)
            #expect(observed == .unknown)
            #expect(Recovery.liveness(process(), observation: observed) == .unknown)
        }
        #expect(Recovery.liveness(process(), observation: .bootOnly(bootUUID: "invalid")) == .unknown)
    }

    @Test func unreadablePriorBootHistoryDoesNotBlockCurrentLivePublication() async {
        await #expect(processExitsWith: .success) {
            try RawStorageShimRecoveryTests().checkUnreadablePriorBootHistory()
        }
    }

    private func checkUnreadablePriorBootHistory() throws {
        let fixture = try StorageRecoveryFixture()
        defer { fixture.remove() }
        let old = Recovery.ProcessIdentity(pid: 1, startSeconds: 100,
            startMicroseconds: 1, bootUUID: boot, uniqueID: 10)
        let history = try fixture.persistOldDeviceHistory(process: old)
        let currentBoot = "22222222-2222-4222-8222-222222222222"
        let inaccessible = Recovery.queryFailure(byteCount: 0, error: EPERM,
            bootBefore: currentBoot, bootAfter: currentBoot)
        let sameBoot = Recovery.queryFailure(byteCount: 0, error: EPERM,
            bootBefore: boot, bootAfter: boot)
        #expect(throws: (any Error).self) {
            _ = try Recovery.publishedGeneration(for: fixture.specification) { _ in sameBoot }
        }
        let fresh = try Recovery.prepareLaunch(fixture.specification) { _ in inaccessible }
        defer { withExtendedLifetime(fresh) {} }
        let current = Recovery.ProcessIdentity(pid: getpid(), startSeconds: 200,
            startMicroseconds: 1, bootUUID: currentBoot, uniqueID: 20)
        _ = try Recovery.publishLaunch(specificationURL: fresh.specificationURL,
            data: fresh.data, diskHandle: fresh.diskHandle) { .process(current) }
        let baseline = try fixture.historyBytes()
        // Revalidate all immutable histories after cold enrollment, as every
        // ordinary storage socket does before restoring workloads after reboot.
        let selected = try #require(try Recovery.publishedGeneration(for: fresh.specification) { pid in
            pid == old.pid ? inaccessible : .process(current)
        })
        #expect(selected.data == fresh.data && selected.record.process == current)
        #expect(try fixture.historyBytes() == baseline)
        #expect(baseline["storage-shim-generations/\(history.record.intent.launchUUID)/spec.json"] == history.data)
        // A stable boot never proves the current writer dead or authorizes its PID.
        #expect(throws: (any Error).self) {
            _ = try Recovery.prepareLaunch(fresh.specification) { _ in inaccessible }
        }
        #expect(try fixture.historyBytes() == baseline)
    }

    @Test func nativeSelfIdentityIsCompleteAndStable() throws {
        guard case let .process(first) = Recovery.observe(getpid()),
              case let .process(second) = Recovery.observe(getpid()) else {
            Issue.record("native self identity unavailable")
            return
        }
        #expect(first.valid)
        #expect(first == second)
        #expect(first.pid == getpid())
    }

    @Test func coldReopenRetainsRecordsAndAllocatesFreshLaunch() async {
        await #expect(processExitsWith: .success) {
            try RawStorageShimRecoveryTests().checkColdReopenRetainsRecordsAndAllocatesFreshLaunch()
        }
    }

    private func checkColdReopenRetainsRecordsAndAllocatesFreshLaunch() throws {
        let fixture = try StorageRecoveryFixture()
        defer { fixture.remove() }
        let first = try Recovery.prepareLaunch(fixture.specification)
        #expect(throws: (any Error).self) {
            _ = try Recovery.publishedGeneration(for: fixture.specification)
        }
        _ = try Recovery.publishLaunch(specificationURL: first.specificationURL, data: first.data, diskHandle: first.diskHandle) { .process(process()) }
        let firstRecordURL = first.specificationURL.deletingLastPathComponent().appending(path: "launch.json")
        let firstRecord = try Data(contentsOf: firstRecordURL)
        let reopened = try #require(try Recovery.publishedGeneration(for: fixture.specification))
        #expect(reopened.data == first.data)
        #expect(reopened.record.intent.specificationSHA256 == Recovery.digest(first.data))
        #expect(throws: (any Error).self) {
            _ = try Recovery.prepareLaunch(fixture.specification) { _ in .unknown }
        }
        #expect(throws: (any Error).self) {
            _ = try Recovery.prepareLaunch(fixture.specification) { _ in .process(process()) }
        }
        try first.diskHandle.close() // Simulate positive exit releasing the old writer.
        let second = try Recovery.prepareLaunch(fixture.specification) { _ in .absent(bootUUID: boot) }
        #expect(second.specification.shimLaunchUUID != first.specification.shimLaunchUUID)
        #expect(second.specification.generation == first.specification.generation + 1)
        #expect(try Data(contentsOf: firstRecordURL) == firstRecord)
        #expect(try Data(contentsOf: first.specificationURL) == first.data)
        _ = try Recovery.publishLaunch(specificationURL: second.specificationURL, data: second.data, diskHandle: second.diskHandle) { .process(process(start: 200, unique: 20)) }
        let latest = try #require(try Recovery.publishedGeneration(for: fixture.specification) { _ in .process(process(start: 200, unique: 20)) })
        #expect(latest.data == second.data)
        #expect(try Data(contentsOf: firstRecordURL) == firstRecord)
    }

    @Test func remountedHistoryRequiresPositiveDeathAndPreservesOriginalBytes() throws {
        let fixture = try StorageRecoveryFixture()
        defer { fixture.remove() }
        let historical = try fixture.persistOldDeviceHistory(process: process())
        let baseline = try fixture.historyBytes()
        for observation: Recovery.Observation in [.process(process()), .unknown,
            .absent(bootUUID: "invalid"), .process(process(unique: 20))] {
            #expect(throws: (any Error).self) {
                _ = try Recovery.publishedGeneration(for: fixture.specification) { _ in observation }
            }
            #expect(try fixture.historyBytes() == baseline)
        }
        for observation: Recovery.Observation in [.absent(bootUUID: boot), .process(process(start: 200, unique: 20))] {
            let recovered = try #require(try Recovery.publishedGeneration(for: fixture.specification) { _ in observation })
            #expect(recovered.specification == historical.specification)
            #expect(recovered.data == historical.data)
            #expect(recovered.record == historical.record)
            #expect(recovered.specification.rootDiskIdentity?.device != fixture.specification.rootDiskIdentity?.device)
            #expect(recovered.record.intent.specificationSHA256 == Recovery.digest(recovered.data))
            #expect(try fixture.historyBytes() == baseline)
        }
    }

    @Test func remountedHistoryRejectsIdentitySizeAndFormatMismatchRegardlessOfDeath() throws {
        let fixture = try StorageRecoveryFixture()
        defer { fixture.remove() }
        _ = try fixture.persistOldDeviceHistory(process: process())
        let baseline = try fixture.historyBytes()
        var mismatches: [VMShimProtocol.Specification] = []
        var changed = fixture.specification
        changed.rootDiskIdentity?.volumeUUID = UUID()
        mismatches.append(changed)
        changed = fixture.specification
        changed.rootDiskIdentity?.inode += 1
        mismatches.append(changed)
        changed = fixture.specification
        changed.rootDiskSize = 8_192
        mismatches.append(changed)
        changed = fixture.specification
        changed.rootDiskIdentity?.volumeUUID = nil
        mismatches.append(changed)
        changed = fixture.specification
        changed.rootDiskIdentity?.inode = 0
        mismatches.append(changed)
        changed = fixture.specification
        changed.rootDiskIdentity = nil
        mismatches.append(changed)
        changed = fixture.specification
        changed.diskBootstrapVersion = 2
        mismatches.append(changed)
        changed = fixture.specification
        changed.rootDiskPath += ".other"
        mismatches.append(changed)
        changed = fixture.specification
        changed.logPath += ".other"
        mismatches.append(changed)
        changed = fixture.specification
        changed.expectedInitramfsSHA256 = nil
        mismatches.append(changed)
        changed = fixture.specification
        changed.expectedInitramfsSHA256 = "invalid"
        mismatches.append(changed)
        for mismatch in mismatches {
            for observation: Recovery.Observation in [.absent(bootUUID: boot), .process(process()), .unknown] {
                #expect(throws: (any Error).self) {
                    _ = try Recovery.publishedGeneration(for: mismatch) { _ in observation }
                }
                #expect(try fixture.historyBytes() == baseline)
            }
        }
    }

    @Test func guestUpdateRequiresPositiveDeathAndPreservesHistory() throws {
        let fixture = try StorageRecoveryFixture()
        defer { fixture.remove() }
        let historical = try fixture.persistHistory(process: process())
        let baseline = try fixture.historyBytes()
        var updated = fixture.specification
        updated.expectedInitramfsSHA256 = String(repeating: "b", count: 64)
        for observation: Recovery.Observation in [.process(process()), .unknown] {
            #expect(throws: (any Error).self) {
                _ = try Recovery.publishedGeneration(for: updated) { _ in observation }
            }
        }
        let recovered = try #require(try Recovery.publishedGeneration(for: updated) { _ in .absent(bootUUID: boot) })
        #expect(recovered.data == historical.data)
        #expect(try fixture.historyBytes() == baseline)
    }

    @Test func historicalDirectoryIdentityStillRequiresVolumeAndInode() throws {
        let mutations: [(PersistentFileIdentity) -> PersistentFileIdentity] = [
            { .init(device: $0.device ^ 1, inode: $0.inode + 1, volumeUUID: $0.volumeUUID) },
            { .init(device: $0.device ^ 1, inode: $0.inode, volumeUUID: UUID()) },
            { .init(device: $0.device ^ 1, inode: $0.inode, volumeUUID: nil) },
            { .init(device: $0.device ^ 1, inode: 0, volumeUUID: $0.volumeUUID) }
        ]
        for mutation in mutations {
            for changeStore in [false, true] {
                let fixture = try StorageRecoveryFixture()
                defer { fixture.remove() }
                _ = try fixture.persistHistory(process: process(),
                    transformStoreIdentity: { changeStore ? mutation($0) : $0 },
                    transformGenerationIdentity: { changeStore ? $0 : mutation($0) })
                let baseline = try fixture.historyBytes()
                #expect(throws: (any Error).self) {
                    _ = try Recovery.publishedGeneration(for: fixture.specification) { _ in .absent(bootUUID: boot) }
                }
                #expect(try fixture.historyBytes() == baseline)
            }
        }
    }

    @Test func remountedLaunchStillRequiresExactLiveDeviceAndExclusiveHeldDisk() async {
        await #expect(processExitsWith: .success) {
            try RawStorageShimRecoveryTests().checkRemountedLaunchStillRequiresExactLiveDeviceAndExclusiveHeldDisk()
        }
    }

    private func checkRemountedLaunchStillRequiresExactLiveDeviceAndExclusiveHeldDisk() throws {
        let fixture = try StorageRecoveryFixture()
        defer { fixture.remove() }
        let historical = try fixture.persistOldDeviceHistory(process: process())
        let baseline = try fixture.historyBytes()
        let held = try FileHandle(forUpdating: URL(filePath: fixture.specification.rootDiskPath))
        try #require(flock(held.fileDescriptor, LOCK_EX | LOCK_NB) == 0)
        #expect(throws: (any Error).self) {
            _ = try Recovery.prepareLaunch(fixture.specification) { _ in .absent(bootUUID: boot) }
        }
        #expect(try fixture.historyBytes() == baseline)
        try held.close()
        // Historical device evidence must never become a fresh live FD identity.
        #expect(throws: (any Error).self) {
            _ = try Recovery.prepareLaunch(historical.specification) { _ in .absent(bootUUID: boot) }
        }
        #expect(try fixture.historyBytes() == baseline)
        var updated = fixture.specification
        updated.expectedInitramfsSHA256 = String(repeating: "b", count: 64)
        let fresh = try Recovery.prepareLaunch(updated) { _ in .absent(bootUUID: boot) }
        defer { withExtendedLifetime(fresh) {} }
        #expect(fresh.specification.expectedInitramfsSHA256 == updated.expectedInitramfsSHA256)
        #expect(fresh.specification.rootDiskIdentity == fixture.specification.rootDiskIdentity)
        #expect(fresh.specification.generation == historical.specification.generation + 1)
        #expect(fresh.specification.shimLaunchUUID != historical.specification.shimLaunchUUID)
        for (path, bytes) in baseline where path != "shim.json" {
            #expect(try Data(contentsOf: fixture.directory.appending(path: path)) == bytes)
        }
        _ = try Recovery.publishLaunch(specificationURL: fresh.specificationURL, data: fresh.data,
            diskHandle: fresh.diskHandle) { .process(process(start: 200, unique: 20)) }
        // Old-device histories remain death-gated even when no longer selected.
        for observation: Recovery.Observation in [.process(process()), .unknown] {
            #expect(throws: (any Error).self) {
                _ = try Recovery.publishedGeneration(for: updated) { _ in observation }
            }
        }
        let selected = try #require(try Recovery.publishedGeneration(for: updated) { _ in
            .process(process(start: 200, unique: 20))
        })
        #expect(selected.data == fresh.data)
    }

    @Test @MainActor func childPublicationRejectsChangedBytesAndReplay() throws {
        let fixture = try StorageRecoveryFixture()
        defer { fixture.remove() }
        let launch = try Recovery.prepareLaunch(fixture.specification)
        #expect(throws: (any Error).self) {
            _ = try Recovery.publishLaunch(specificationURL: launch.specificationURL, data: launch.data + Data(" ".utf8), diskHandle: launch.diskHandle) { .process(process()) }
        }
        let pinned = try VMShimServer.launchSpecification(specificationURL: launch.specificationURL,
            launchIntentURL: nil, expectedSpecificationSHA256: Recovery.digest(launch.data), inheritedStorageDisk: launch.diskHandle)
        #expect(pinned == launch.specification)
        #expect(throws: (any Error).self) {
            _ = try VMShimServer.launchSpecification(specificationURL: launch.specificationURL,
                launchIntentURL: nil, expectedSpecificationSHA256: Recovery.digest(launch.data), inheritedStorageDisk: launch.diskHandle)
        }
    }

    @Test func legacyAndMismatchedMetadataCannotBeAdopted() throws {
        let fixture = try StorageRecoveryFixture()
        defer { fixture.remove() }
        let current = fixture.directory.appending(path: "shim.json")
        try JSONEncoder().encode(fixture.specification).write(to: current)
        #expect(throws: (any Error).self) {
            _ = try Recovery.prepareLaunch(fixture.specification) { _ in .absent(bootUUID: boot) }
        }
        try FileManager.default.removeItem(at: current) // Explicit fixture reset, not recovery behavior.
        let launch = try Recovery.prepareLaunch(fixture.specification)
        _ = try Recovery.publishLaunch(specificationURL: launch.specificationURL, data: launch.data, diskHandle: launch.diskHandle) { .process(process()) }
        var mismatch = fixture.specification
        mismatch.rootDiskSize = 8_192
        #expect(throws: (any Error).self) { _ = try Recovery.publishedGeneration(for: mismatch) }
        try (launch.data + Data(" ".utf8)).write(to: current)
        #expect(throws: (any Error).self) { _ = try Recovery.publishedGeneration(for: fixture.specification) }
    }

    @Test func missingOldPublicationBlocksEvenWithSelectedNewGeneration() async {
        await #expect(processExitsWith: .success) {
            try RawStorageShimRecoveryTests().checkMissingOldPublicationBlocksEvenWithSelectedNewGeneration()
        }
    }

    private func checkMissingOldPublicationBlocksEvenWithSelectedNewGeneration() throws {
        let fixture = try StorageRecoveryFixture()
        defer { fixture.remove() }
        let first = try Recovery.prepareLaunch(fixture.specification)
        _ = try Recovery.publishLaunch(specificationURL: first.specificationURL, data: first.data, diskHandle: first.diskHandle) { .process(process()) }
        try first.diskHandle.close() // Simulate positive exit releasing the old writer.
        let second = try Recovery.prepareLaunch(fixture.specification) { _ in .absent(bootUUID: boot) }
        _ = try Recovery.publishLaunch(specificationURL: second.specificationURL, data: second.data, diskHandle: second.diskHandle) { .process(process(start: 200, unique: 20)) }
        try FileManager.default.removeItem(at: first.specificationURL.deletingLastPathComponent().appending(path: "launch.json"))
        #expect(throws: (any Error).self) {
            _ = try Recovery.publishedGeneration(for: fixture.specification) { _ in .absent(bootUUID: boot) }
        }
        #expect(try Data(contentsOf: second.specificationURL) == second.data)
    }

    @Test func actualDiskContentionBlocksBeforeFreshIntent() throws {
        let fixture = try StorageRecoveryFixture()
        defer { fixture.remove() }
        let first = try Recovery.prepareLaunch(fixture.specification)
        _ = try Recovery.publishLaunch(specificationURL: first.specificationURL, data: first.data, diskHandle: first.diskHandle) { .process(process()) }
        defer { withExtendedLifetime(first) {} }
        // Even a (mock) positive-death observation cannot override the actual
        // still-held writer lease retained by the prepared launch.
        #expect(throws: (any Error).self) {
            _ = try Recovery.prepareLaunch(fixture.specification) { _ in .absent(bootUUID: boot) }
        }
        let histories = try PersistentStateDirectory.open(fixture.directory.appending(path: Recovery.directoryName))
        #expect(try histories.entryNames() == [first.specification.shimLaunchUUID!])
        #expect(try Data(contentsOf: fixture.directory.appending(path: "shim.json")) == first.data)
    }

    @Test @MainActor func missingOrUnlockedTransferCannotPublish() async {
        await #expect(processExitsWith: .success) {
            try await RawStorageShimRecoveryTests().checkMissingOrUnlockedTransferCannotPublish()
        }
    }

    @MainActor private func checkMissingOrUnlockedTransferCannotPublish() throws {
        let fixture = try StorageRecoveryFixture()
        defer { fixture.remove() }
        let launch = try Recovery.prepareLaunch(fixture.specification)
        #expect(throws: (any Error).self) {
            _ = try VMShimServer.launchSpecification(specificationURL: launch.specificationURL,
                launchIntentURL: nil, expectedSpecificationSHA256: Recovery.digest(launch.data))
        }
        let independent = try FileHandle(forUpdating: URL(filePath: fixture.specification.rootDiskPath))
        defer { try? independent.close() }
        #expect(throws: (any Error).self) {
            _ = try Recovery.publishLaunch(specificationURL: launch.specificationURL,
                data: launch.data, diskHandle: independent)
        }
        try launch.diskHandle.close()
        #expect(throws: (any Error).self) {
            _ = try Recovery.publishLaunch(specificationURL: launch.specificationURL,
                data: launch.data, diskHandle: independent)
        }
        #expect(!FileManager.default.fileExists(atPath:
            launch.specificationURL.deletingLastPathComponent().appending(path: "launch.json").path))
    }

    @Test @MainActor func unjournaledSpecificationReadIsSizeBounded() throws {
        let fixture = try StorageRecoveryFixture()
        defer { fixture.remove() }
        let url = fixture.directory.appending(path: "oversized.json")
        let data = Data(repeating: 32, count: PersistentStateDirectory.maximumStateBytes + 1)
        try data.write(to: url)
        #expect(throws: (any Error).self) {
            _ = try VMShimServer.launchSpecification(specificationURL: url,
                launchIntentURL: nil, expectedSpecificationSHA256: Recovery.digest(data))
        }
    }

    @Test func childIdentityIsCapturedOnceBeforeReaping() throws {
        let fixture = try StorageRecoveryFixture()
        defer { fixture.remove() }
        var events: [String] = []
        #expect(throws: (any Error).self) {
            _ = try VMShimClient.storageProcessClient(specification: fixture.specification, pid: 123,
                identityProvider: { pid in
                    #expect(pid == 123)
                    events.append("identity")
                    return nil
                }, startReaper: { pid in
                    #expect(pid == 123)
                    events.append("reap")
                })
        }
        #expect(events == ["identity", "reap"])
        events.removeAll()
        let client = try VMShimClient.storageProcessClient(specification: fixture.specification, pid: 123,
            identityProvider: { pid in
                #expect(events.isEmpty)
                events.append("identity")
                return .init(processIdentifier: pid, startTime: 1)
            }, startReaper: { _ in events.append("reap") })
        #expect(client.specification == fixture.specification)
        #expect(events == ["identity", "reap"])
    }

    @Test func productionStorageSpawnUsesRealNullInputAndPreservesLaunchMetadata() throws {
        let fixture = try StorageRecoveryFixture()
        defer { fixture.remove() }
        let launch = try Recovery.prepareLaunch(fixture.specification)
        let intentURL = launch.specificationURL.deletingLastPathComponent().appending(path: "intent.json")
        let intent = try Data(contentsOf: intentURL)
        let executable = try buildStorageTransferHelper(in: fixture.directory)
        let logURL = fixture.directory.appending(path: "shim.log")
        try Data().write(to: logURL)
        let output = try FileHandle(forWritingTo: logURL)
        defer { try? output.close() }
        // Omit input exactly as the production storage launch does. Foundation's
        // nullDevice sink has no usable OS descriptor on macOS.
        let pid = try VMShimClient.spawnStorageProcess(executable: executable,
            arguments: [fixture.specification.rootDiskPath, String(fixture.specification.rootDiskIdentity!.inode), "null-input"],
            disk: launch.diskHandle, output: output)
        var reaped = false
        defer {
            if !reaped {
                kill(pid, SIGKILL)
                while waitpid(pid, nil, 0) < 0 && errno == EINTR {}
            }
        }
        let deadline = Date().addingTimeInterval(5)
        var status: Int32 = 0
        while Date() < deadline {
            if waitpid(pid, &status, WNOHANG) == pid { reaped = true; break }
            usleep(10_000)
        }
        try #require(reaped, "default-input storage child exit timed out")
        #expect(status == 0)
        #expect(try Data(contentsOf: logURL) == Data([82]))
        #expect(try Data(contentsOf: intentURL) == intent)
        #expect(try Data(contentsOf: launch.specificationURL) == launch.data)
        try expectStorageDiskLock(URL(filePath: fixture.specification.rootDiskPath), available: false)
    }

    @Test func invalidStorageInputReportsOperationWithoutLaunchData() throws {
        let fixture = try StorageRecoveryFixture()
        defer { fixture.remove() }
        let launch = try Recovery.prepareLaunch(fixture.specification)
        do {
            _ = try VMShimClient.spawnStorageProcess(executable: URL(filePath: "/unused"),
                arguments: ["secret-must-not-appear"], disk: launch.diskHandle,
                input: FileHandle.nullDevice, output: FileHandle.nullDevice)
            Issue.record("invalid storage input was accepted")
        } catch let error as EngineError {
            #expect(error.code == .internalError)
            #expect(error.message == "storage shim open stdin failed: Bad file descriptor")
            #expect(!error.message.contains("secret-must-not-appear"))
        }
    }

    @Test func actualProcessTransferRetainsLockUntilNativeChildExit() async {
        await #expect(processExitsWith: .success) {
            try RawStorageShimRecoveryTests().checkActualProcessTransferRetainsLockUntilNativeChildExit()
        }
    }

    private func checkActualProcessTransferRetainsLockUntilNativeChildExit() throws {
        let fixture = try StorageRecoveryFixture()
        defer { fixture.remove() }
        let launch = try Recovery.prepareLaunch(fixture.specification)
        let diskURL = URL(filePath: fixture.specification.rootDiskPath)
        try expectStorageDiskLock(diskURL, available: false) // Intent already published.
        let executable = try buildStorageTransferHelper(in: fixture.directory)
        let input = Pipe(), output = Pipe()
        let pid = try VMShimClient.spawnStorageProcess(executable: executable,
            arguments: [diskURL.path, String(fixture.specification.rootDiskIdentity!.inode)],
            disk: launch.diskHandle, input: input.fileHandleForReading, output: output.fileHandleForWriting)
        var reaped = false
        defer {
            if !reaped {
                kill(pid, SIGKILL)
                while waitpid(pid, nil, 0) < 0 && errno == EINTR {}
            }
        }
        try input.fileHandleForReading.close()
        try output.fileHandleForWriting.close()
        try expectStorageTransferReady(output.fileHandleForReading)
        // launchd kills the departed daemon's process group. Storage must own
        // a different group, just like the persistent workload shims.
        #expect(getpgid(pid) == pid)
        #expect(getpgid(pid) != getpgrp())
        let birth: Recovery.ProcessIdentity
        guard case let .process(identity) = Recovery.observe(pid) else {
            Issue.record("native child birth identity unavailable")
            return
        }
        birth = identity
        #expect(birth.valid)
        #expect(Recovery.liveness(birth, observation: Recovery.observe(pid)) == .alive)
        try expectStorageDiskLock(diskURL, available: false)
        try launch.diskHandle.close() // Parent gone; only inherited child FD owns the lease.
        try expectStorageDiskLock(diskURL, available: false)
        try input.fileHandleForWriting.write(contentsOf: Data([113]))
        let deadline = Date().addingTimeInterval(5)
        var status: Int32 = 0
        while Date() < deadline {
            if waitpid(pid, &status, WNOHANG) == pid { reaped = true; break }
            usleep(10_000)
        }
        try #require(reaped, "storage transfer child exit timed out")
        #expect(status == 0)
        #expect(Recovery.liveness(birth, observation: Recovery.observe(pid)) == .dead)
        try expectStorageDiskLock(diskURL, available: true)
    }

    private func process(start: UInt64 = 100, unique: UInt64 = 10) -> Recovery.ProcessIdentity {
        .init(pid: getpid(), startSeconds: start, startMicroseconds: 1, bootUUID: boot, uniqueID: unique)
    }
}

private func expectStorageDiskLock(_ url: URL, available: Bool) throws {
    let descriptor = open(url.path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw POSIXError(.EIO) }
    defer { close(descriptor) }
    let result = flock(descriptor, LOCK_EX | LOCK_NB)
    let code = errno
    #expect((result == 0) == available)
    if !available { #expect(code == EWOULDBLOCK) }
}

private func expectStorageTransferReady(_ handle: FileHandle) throws {
    var event = pollfd(fd: handle.fileDescriptor, events: Int16(POLLIN), revents: 0)
    guard poll(&event, 1, 5_000) > 0 else { throw POSIXError(.ETIMEDOUT) }
    try #require(handle.read(upToCount: 1) == Data([82]))
}

private func buildStorageTransferHelper(in directory: URL) throws -> URL {
    let source = directory.appending(path: "storage-transfer.c")
    let executable = directory.appending(path: "storage-transfer")
    try Data(#"""
    #include <sys/file.h>
    #include <sys/stat.h>
    #include <errno.h>
    #include <stdlib.h>
    #include <unistd.h>
    int main(int argc, char **argv) {
        alarm(10);
        struct stat disk;
        if ((argc != 3 && argc != 4) || fstat(3, &disk) != 0 || !S_ISREG(disk.st_mode)
            || disk.st_ino != strtoull(argv[2], 0, 10)) return 10;
        int probe = open(argv[1], O_RDWR | O_NOFOLLOW | O_CLOEXEC);
        if (probe < 0 || flock(probe, LOCK_SH | LOCK_NB) != -1 || errno != EWOULDBLOCK) return 11;
        if (flock(3, LOCK_EX | LOCK_NB) != 0 || fcntl(3, F_SETFD, FD_CLOEXEC) != 0) return 12;
        close(probe);
        if (write(1, "R", 1) != 1) return 13;
        char command;
        if (argc == 4) {
            struct stat input, output, error;
            if (fstat(0, &input) != 0 || !S_ISCHR(input.st_mode)
                || fstat(1, &output) != 0 || !S_ISREG(output.st_mode)
                || fstat(2, &error) != 0 || output.st_dev != error.st_dev
                || output.st_ino != error.st_ino) return 15;
            return read(0, &command, 1) == 0 ? 0 : 16;
        }
        if (read(0, &command, 1) != 1 || command != 'q') return 14;
        return 0; /* Kernel closes the inherited description; no explicit unlock. */
    }
    """#.utf8).write(to: source)
    let compiler = Process()
    compiler.executableURL = URL(filePath: "/usr/bin/clang")
    compiler.arguments = ["-Wall", "-Wextra", "-Werror", source.path, "-o", executable.path]
    try compiler.run()
    compiler.waitUntilExit()
    guard compiler.terminationStatus == 0 else { throw POSIXError(.ENOEXEC) }
    return executable
}

struct StorageRecoveryFixture {
    let directory: URL
    let specification: VMShimProtocol.Specification

    init() throws {
        directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let disk = directory.appending(path: "volumes.ext4")
        try Data(repeating: 0x5a, count: 4_096).write(to: disk)
        let parent = try PersistentStateDirectory.open(directory)
        specification = try .init(kind: .storage, containerID: "cengine-storage", generation: 1,
            token: "test", kernelPath: "/unused", initialRamdiskPath: "/unused",
            rootDiskPath: disk.path, rootDiskIdentity: parent.regularFileIdentity(named: "volumes.ext4").shimIdentity,
            rootDiskSize: 4_096, cpus: 1, memoryBytes: 512 * 1_024 * 1_024,
            macAddress: "02:ce:00:00:00:01", socketPath: directory.appending(path: "shim.sock").path,
            logPath: directory.appending(path: "shim.log").path,
            shimLaunchUUID: UUID().uuidString.lowercased(), diskBootstrapVersion: 1,
            expectedInitramfsSHA256: String(repeating: "a", count: 64))
    }

    /// Construct a prior-mount publication before freezing the test baseline.
    /// No runtime rewrite is used to make old immutable records appear current.
    func persistOldDeviceHistory(process: RawStorageShimRecovery.ProcessIdentity) throws -> RawStorageShimRecovery.Generation {
        let changed: (PersistentFileIdentity) -> PersistentFileIdentity = {
            .init(device: $0.device ^ 1, inode: $0.inode, volumeUUID: $0.volumeUUID)
        }
        return try persistHistory(process: process, changeBackingDevice: true,
            transformStoreIdentity: changed, transformGenerationIdentity: changed)
    }

    func persistHistory(process: RawStorageShimRecovery.ProcessIdentity,
                        changeBackingDevice: Bool = false,
                        transformStoreIdentity: (PersistentFileIdentity) -> PersistentFileIdentity = { $0 },
                        transformGenerationIdentity: (PersistentFileIdentity) -> PersistentFileIdentity = { $0 }) throws -> RawStorageShimRecovery.Generation {
        var old = specification
        if changeBackingDevice { old.rootDiskIdentity?.device ^= 1 }
        let store = try PersistentStateDirectory.open(directory)
        let histories = try store.openOrCreateDirectory(named: RawStorageShimRecovery.directoryName)
        let generation = try histories.createDirectory(named: old.shimLaunchUUID!)
        let data = try JSONEncoder().encode(old)
        let intent = RawStorageShimRecovery.Intent(schemaVersion: 1, protocolVersion: VMShimProtocol.version,
            launchUUID: old.shimLaunchUUID!, specificationSHA256: RawStorageShimRecovery.digest(data),
            storeIdentity: transformStoreIdentity(store.identity),
            generationIdentity: transformGenerationIdentity(generation.identity))
        let record = RawStorageShimRecovery.LaunchRecord(intent: intent, process: process)
        try generation.writeExclusiveRegularFile(named: "spec.json", data: data)
        try generation.writeExclusiveRegularFile(named: "intent.json", data: JSONEncoder().encode(intent))
        try generation.writeExclusiveRegularFile(named: "launch.json", data: JSONEncoder().encode(record))
        try store.replaceRegularFile(named: "shim.json", data: data)
        return .init(specification: old, data: data, record: record)
    }

    func historyBytes() throws -> [String: Data] {
        let histories = RawStorageShimRecovery.directoryName
        var paths = ["shim.json", "volumes.ext4"]
        for name in try FileManager.default.contentsOfDirectory(atPath: directory.appending(path: histories).path) {
            paths += ["spec.json", "intent.json", "launch.json"].map { "\(histories)/\(name)/\($0)" }
        }
        return try Dictionary(uniqueKeysWithValues: paths.map { ($0, try Data(contentsOf: directory.appending(path: $0))) })
    }

    func remove() { try? FileManager.default.removeItem(at: directory) }
}
#endif

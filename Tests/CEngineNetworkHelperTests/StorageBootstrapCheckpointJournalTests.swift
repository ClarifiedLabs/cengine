import CEngineCore
import Darwin
import Foundation
import Testing
@testable import StorageBootstrapHelper

private typealias CheckpointJournal = StorageBootstrapCheckpointJournal
private final class CheckpointDirectory {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let fd: Int32
    init() throws {
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        fd = Darwin.open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw POSIXError(.EIO) }
    }
    deinit { close(fd); try? FileManager.default.removeItem(at: url) }
    func file(_ name: String = "authority.journal") -> URL { url.appendingPathComponent(name) }
    func bytes(_ name: String = "authority.journal") throws -> Data { try Data(contentsOf: file(name)) }
    func names() throws -> Set<String> { Set(try FileManager.default.contentsOfDirectory(atPath: url.path)) }
    func open(fresh: Bool = false, owner: uid_t = 501,
              read: @escaping CheckpointJournal.Read = { pread($0, $1, $2, $3) },
              sync: @escaping (Int32) throws -> Void = { fd in
                  guard fsync(fd) == 0 else { throw POSIXError(.EIO) }
              }, fault: @escaping (CheckpointJournal.Phase) throws -> Void = { _ in }) throws -> CheckpointJournal {
        try CheckpointJournal(directoryFD: fd, fresh: fresh, ownerUID: geteuid(), configuredOwnerUID: owner,
            read: read, sync: sync, fault: fault)
    }
    func mutate(_ name: String, offset: Int) throws {
        let descriptor = openat(fd, name, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        defer { close(descriptor) }
        var byte: UInt8 = 0
        #expect(pread(descriptor, &byte, 1, off_t(offset)) == 1)
        byte ^= 0xff
        #expect(pwrite(descriptor, &byte, 1, off_t(offset)) == 1)
    }
}

@Suite struct StorageBootstrapCheckpointJournalTests {
    // Concurrent Darwin spawns can briefly retain CLOEXEC descriptions before exec.
    // Isolate immediate release/reopen checks from unrelated process launches.
    @Test func handoffSigningIsDomainSeparatedAndRetainsRootAcrossReopen() async {
        await #expect(processExitsWith: .success) {
            try StorageBootstrapCheckpointJournalTests().checkHandoffSigningIsDomainSeparatedAndRetainsRootAcrossReopen()
        }
    }

    private func checkHandoffSigningIsDomainSeparatedAndRetainsRootAcrossReopen() throws {
        let directory = try CheckpointDirectory()
        var journal: CheckpointJournal? = try directory.open(fresh: true)
        let identity = try StorageLifecycleProtocol.Identity(store: UUID().uuidString.lowercased(), generation: 1,
            binding: String(repeating: "a", count: 64))
        let predecessor = try StorageLifecycleProtocol.Grant(operation: .initialize, id: UUID().uuidString.lowercased(),
            identity: identity, serial: 1, expectedEpoch: 0, newKey: String(repeating: "b", count: 64))
        let pending = try StorageLifecycleProtocol.Grant(operation: .takeover, id: UUID().uuidString.lowercased(),
            identity: identity, serial: 2, expectedEpoch: 1, newKey: String(repeating: "c", count: 64))
        let request = try StorageLifecycleHandoffProtocol.Request(operationID: UUID().uuidString.lowercased(),
            predecessor: predecessor, pending: pending, serviceEpoch: UUID().uuidString.lowercased(), openRevision: 1)
        let signed = try journal!.signHandoff(request)
        let root = try journal!.lifecycleRootPublicKey()
        #expect(signed.isValidSignature(using: root))
        journal = nil; journal = try directory.open()
        let resigned = try journal!.signHandoff(request)
        #expect(resigned.request == signed.request && resigned.isValidSignature(using: root))
        // ROOT retains the exact signature in its transaction. A re-sign is not
        // required to reproduce CryptoKit's (potentially randomized) signature.
        let grantSignature = try journal!.signLifecycle(pending).signature
        #expect(try !StorageLifecycleHandoffProtocol.SignedRequest(request: request, signature: grantSignature).isValidSignature(using: root))
    }

    @Test func successReopensWithFixedRootOwnerAndReadOnlyPublicAccess() async {
        await #expect(processExitsWith: .success) {
            try StorageBootstrapCheckpointJournalTests().checkSuccessReopensWithFixedRootOwnerAndReadOnlyPublicAccess()
        }
    }

    private func checkSuccessReopensWithFixedRootOwnerAndReadOnlyPublicAccess() throws {
        let directory = try CheckpointDirectory()
        // Exercise the real default full-sync implementation once, not 4097 times.
        var journal: CheckpointJournal? = try .init(directoryFD: directory.fd, fresh: true,
            ownerUID: geteuid(), configuredOwnerUID: 501)
        let root = try journal!.readRootPublicKey()
        let lock = try directory.bytes("authority.lock")
        #expect(root.count == 32)
        #expect(try journal!.load() == nil)
        try journal!.checkpoint(Data("first".utf8))
        try journal!.checkpoint(Data("second".utf8))
        let before = try directory.bytes()
        #expect(try journal!.readRootPublicKey() == root)
        #expect(try journal!.load() == Data("second".utf8))
        #expect(try directory.bytes() == before)
        #expect(try directory.bytes("authority.lock") == lock)
        journal = nil
        #expect(throws: CheckpointJournal.Failure.repairRequired) { try directory.open(owner: 502) }
        journal = try directory.open()
        #expect(try journal!.readRootPublicKey() == root)
        #expect(try journal!.load() == Data("second".utf8))
        #expect(try directory.names() == ["authority.journal", "authority.lock"])
    }

    @Test func moreThan4096CheckpointsKeepTwoFilesAndTheLockAcrossReplacement() async {
        await #expect(processExitsWith: .success) {
            try StorageBootstrapCheckpointJournalTests().checkMoreThan4096CheckpointsKeepTwoFilesAndTheLockAcrossReplacement()
        }
    }

    private func checkMoreThan4096CheckpointsKeepTwoFilesAndTheLockAcrossReplacement() throws {
        let directory = try CheckpointDirectory()
        var journal: CheckpointJournal? = try directory.open(fresh: true, sync: { _ in })
        let root = try journal!.readRootPublicKey()
        var firstLock = stat(), lastLock = stat(), firstCurrent = stat(), lastCurrent = stat()
        #expect(fstatat(directory.fd, "authority.lock", &firstLock, AT_SYMLINK_NOFOLLOW) == 0)
        #expect(fstatat(directory.fd, "authority.journal", &firstCurrent, AT_SYMLINK_NOFOLLOW) == 0)
        try journal!.checkpoint(Data("replacement".utf8))
        #expect(fstatat(directory.fd, "authority.journal", &lastCurrent, AT_SYMLINK_NOFOLLOW) == 0)
        #expect(lastCurrent.st_ino != firstCurrent.st_ino)
        #expect(throws: CheckpointJournal.Failure.unavailable) { try directory.open() }
        for i in 0..<4097 { try journal!.checkpoint(Data("snapshot-\(i)".utf8)) }
        #expect(try directory.names() == ["authority.journal", "authority.lock"])
        #expect(try directory.bytes().count == 88 + Data("snapshot-4096".utf8).count)
        #expect(fstatat(directory.fd, "authority.lock", &lastLock, AT_SYMLINK_NOFOLLOW) == 0)
        #expect(firstLock.st_ino == lastLock.st_ino)
        #expect(throws: CheckpointJournal.Failure.unavailable) { try directory.open() }
        journal = nil
        let reopened = try directory.open()
        #expect(try reopened.readRootPublicKey() == root)
        #expect(try reopened.load() == Data("snapshot-4096".utf8))
    }

    @Test func finalStateByteBoundaryAndPeakPublicationAreBounded() throws {
        let directory = try CheckpointDirectory()
        var inspect = false, peakObserved = false
        let journal = try directory.open(fresh: true, sync: { _ in }, fault: { phase in
            if inspect && phase == .candidateWritten {
                let sizes = try directory.names().map {
                    (try FileManager.default.attributesOfItem(atPath: directory.file($0).path)[.size] as! NSNumber).intValue
                }
                #expect(sizes.reduce(0, +) == 2 * CheckpointJournal.maximumBytes + 76 + 8)
                #expect(try directory.names() == ["authority.lock", "authority.journal", "authority.next", "authority.checkpoint-in-progress"])
                peakObserved = true
            }
        })
        let state = Data(repeating: 0x61, count: CheckpointJournal.maximumPayloadBytes)
        #expect(throws: CheckpointJournal.Failure.capacityExceeded) { try journal.checkpoint(state + Data([0])) }
        #expect(try journal.load() == nil)
        try journal.checkpoint(state)
        inspect = true
        try journal.checkpoint(state)
        inspect = false
        #expect(peakObserved)
        #expect(try directory.bytes().count == 32 * 1024 * 1024)
        try journal.checkpoint(Data())
        #expect(try journal.load() == Data())
        #expect(try directory.bytes().count == 88)
    }

    @Test(arguments: CheckpointJournal.Phase.allCases.map { String(describing: $0) })
    func freshCutsLeaveArtifactsAndNeverReset(_ phaseName: String) async {
        await #expect(processExitsWith: .success) { [phaseName] in
            let phase = try #require(CheckpointJournal.Phase.allCases.first { String(describing: $0) == phaseName })
            try StorageBootstrapCheckpointJournalTests().checkFreshCutsLeaveArtifactsAndNeverReset(phase)
        }
    }

    private func checkFreshCutsLeaveArtifactsAndNeverReset(_ phase: StorageBootstrapCheckpointJournal.Phase) throws {
        let directory = try CheckpointDirectory()
        #expect(throws: (any Error).self) {
            try directory.open(fresh: true, fault: { if $0 == phase { throw POSIXError(.EIO) } })
        }
        let names = try directory.names()
        #expect(!names.isEmpty)
        #expect(throws: (any Error).self) { try directory.open() }
        #expect(throws: (any Error).self) { try directory.open(fresh: true) }
        #expect(try directory.names() == names)
    }

    @Test(arguments: CheckpointJournal.Phase.allCases.dropFirst(3).map { String(describing: $0) })
    func checkpointCutsPoisonAndRefuseBothOldAndNewWithoutRepair(_ phaseName: String) async {
        await #expect(processExitsWith: .success) { [phaseName] in
            let phase = try #require(CheckpointJournal.Phase.allCases.first { String(describing: $0) == phaseName })
            try StorageBootstrapCheckpointJournalTests().checkCheckpointCutsPoisonAndRefuseBothOldAndNewWithoutRepair(phase)
        }
    }

    private func checkCheckpointCutsPoisonAndRefuseBothOldAndNewWithoutRepair(_ phase: StorageBootstrapCheckpointJournal.Phase) throws {
        let directory = try CheckpointDirectory()
        var armed = false
        var journal: CheckpointJournal? = try directory.open(fresh: true, fault: {
            if armed && $0 == phase { throw POSIXError(.EIO) }
        })
        try journal!.checkpoint(Data("old".utf8))
        armed = true
        #expect(throws: CheckpointJournal.Failure.repairRequired) { try journal!.checkpoint(Data("new".utf8)) }
        armed = false
        #expect(throws: CheckpointJournal.Failure.repairRequired) { try journal!.load() }
        #expect(throws: CheckpointJournal.Failure.repairRequired) { try journal!.readRootPublicKey() }
        #expect(throws: CheckpointJournal.Failure.repairRequired) { try journal!.checkpoint(Data("retry".utf8)) }
        let names = try directory.names(), current = try directory.bytes()
        #expect(names.contains("authority.checkpoint-in-progress"))
        journal = nil
        #expect(throws: CheckpointJournal.Failure.repairRequired) { try directory.open() }
        #expect(throws: CheckpointJournal.Failure.repairRequired) { try directory.open(fresh: true) }
        #expect(try directory.names() == names)
        #expect(try directory.bytes() == current)
    }

    @Test(arguments: 1...5)
    func syncFailuresRetainRefusalArtifacts(_ barrier: Int) async {
        await #expect(processExitsWith: .success) { [barrier] in
            try StorageBootstrapCheckpointJournalTests().checkSyncFailuresRetainRefusalArtifacts(barrier)
        }
    }

    private func checkSyncFailuresRetainRefusalArtifacts(_ barrier: Int) throws {
        let directory = try CheckpointDirectory()
        var armed = false, count = 0
        var journal: CheckpointJournal? = try directory.open(fresh: true, sync: { fd in
            if armed { count += 1; if count == barrier { throw POSIXError(.EIO) } }
            guard fsync(fd) == 0 else { throw POSIXError(.EIO) }
        })
        armed = true
        #expect(throws: CheckpointJournal.Failure.repairRequired) { try journal!.checkpoint(Data("uncertain".utf8)) }
        journal = nil
        #expect(try directory.names().contains("authority.checkpoint-in-progress"))
        #expect(throws: CheckpointJournal.Failure.repairRequired) { try directory.open() }
    }

    @Test func missingOldFormatAndNonemptyFreshNeverReset() async {
        await #expect(processExitsWith: .success) {
            try StorageBootstrapCheckpointJournalTests().checkMissingOldFormatAndNonemptyFreshNeverReset()
        }
    }

    private func checkMissingOldFormatAndNonemptyFreshNeverReset() throws {
        let directory = try CheckpointDirectory()
        #expect(throws: (any Error).self) { try directory.open() }
        #expect(try directory.names().isEmpty)
        // Retired format fixture only: no old authority implementation is linked.
        let bytes = Data("CEBSJ002".utf8) + Data(repeating: 0, count: 72)
        try bytes.write(to: directory.file())
        #expect(chmod(directory.file().path, 0o600) == 0)
        #expect(throws: (any Error).self) { try directory.open() }
        #expect(throws: (any Error).self) { try directory.open(fresh: true) }
        #expect(try directory.bytes() == bytes)
        #expect(try directory.names() == ["authority.journal"])
        let other = try CheckpointDirectory()
        try Data("unrelated".utf8).write(to: other.file("unrelated"))
        #expect(throws: (any Error).self) { try other.open(fresh: true) }
        #expect(try other.names() == ["unrelated"])
        let missing = try CheckpointDirectory()
        var journal: CheckpointJournal? = try missing.open(fresh: true)
        #expect(journal != nil)
        journal = nil
        #expect(unlink(missing.file().path) == 0)
        #expect(throws: (any Error).self) { try missing.open() }
        #expect(throws: (any Error).self) { try missing.open(fresh: true) }
        #expect(try missing.names() == ["authority.lock"])
    }

    @Test(arguments: [0, 8, 12, 43, 44, 52, 56, 90])
    func authenticatedSnapshotMutationPoisonsAndReopenRefuses(_ offset: Int) async {
        await #expect(processExitsWith: .success) { [offset] in
            try StorageBootstrapCheckpointJournalTests().checkAuthenticatedSnapshotMutationPoisonsAndReopenRefuses(offset)
        }
    }

    private func checkAuthenticatedSnapshotMutationPoisonsAndReopenRefuses(_ offset: Int) throws {
        let directory = try CheckpointDirectory()
        var journal: CheckpointJournal? = try directory.open(fresh: true)
        try journal!.checkpoint(Data("snapshot bytes".utf8))
        try directory.mutate("authority.journal", offset: offset)
        let corrupted = try directory.bytes()
        #expect(throws: (any Error).self) { try journal!.load() }
        try directory.mutate("authority.journal", offset: offset)
        #expect(throws: (any Error).self) { try journal!.checkpoint(Data("no retry".utf8)) }
        #expect(throws: (any Error).self) { try journal!.readRootPublicKey() }
        try directory.mutate("authority.journal", offset: offset)
        journal = nil
        #expect(throws: (any Error).self) { try directory.open() }
        #expect(try directory.bytes() == corrupted)
    }

    @Test(arguments: ["authority.lock", "authority.journal"], ["replace", "fifo", "symlink", "hardlink", "mode", "corrupt"])
    func liveNamedFileFences(_ name: String, _ mutation: String) throws {
        let directory = try CheckpointDirectory()
        let journal = try directory.open(fresh: true)
        let original = directory.file(name), backup = directory.file("backup")
        switch mutation {
        case "replace":
            try directory.bytes(name).write(to: backup)
            #expect(chmod(backup.path, 0o600) == 0)
            #expect(rename(backup.path, original.path) == 0)
        case "fifo", "symlink":
            #expect(unlink(original.path) == 0)
            if mutation == "fifo" { #expect(mkfifo(original.path, 0o600) == 0) }
            else { #expect(symlink("/dev/null", original.path) == 0) }
        case "hardlink": #expect(link(original.path, backup.path) == 0)
        case "mode": #expect(chmod(original.path, 0o644) == 0)
        default: try directory.mutate(name, offset: 0)
        }
        #expect(throws: (any Error).self) { try journal.readRootPublicKey() }
        #expect(throws: (any Error).self) { try journal.load() }
        #expect(throws: (any Error).self) { try journal.checkpoint(Data()) }
    }

    @Test(arguments: ["authority.lock", "authority.journal"])
    func reopenFIFORefusesWithoutBlocking(_ name: String) async {
        await #expect(processExitsWith: .success) { [name] in
            try StorageBootstrapCheckpointJournalTests().checkReopenFIFORefusesWithoutBlocking(name)
        }
    }

    private func checkReopenFIFORefusesWithoutBlocking(_ name: String) throws {
        let directory = try CheckpointDirectory()
        var journal: CheckpointJournal? = try directory.open(fresh: true)
        #expect(journal != nil)
        journal = nil
        #expect(unlink(directory.file(name).path) == 0)
        #expect(mkfifo(directory.file(name).path, 0o600) == 0)
        #expect(throws: (any Error).self) { try directory.open() }
    }

    @Test func rootSubstitutionWithValidMACStillFailsStableLockAnchor() async {
        await #expect(processExitsWith: .success) {
            try StorageBootstrapCheckpointJournalTests().checkRootSubstitutionWithValidMACStillFailsStableLockAnchor()
        }
    }

    private func checkRootSubstitutionWithValidMACStillFailsStableLockAnchor() throws {
        let first = try CheckpointDirectory(), second = try CheckpointDirectory()
        var a: CheckpointJournal? = try first.open(fresh: true)
        var b: CheckpointJournal? = try second.open(fresh: true)
        #expect(try a!.readRootPublicKey() != b!.readRootPublicKey())
        a = nil; b = nil
        try second.bytes().write(to: first.file())
        #expect(chmod(first.file().path, 0o600) == 0)
        #expect(throws: (any Error).self) { try first.open() }
    }

    @Test func directoryModeAndOwnerFences() throws {
        let directory = try CheckpointDirectory()
        #expect(throws: (any Error).self) {
            try CheckpointJournal(directoryFD: directory.fd, fresh: true, ownerUID: geteuid() &+ 1, configuredOwnerUID: 501)
        }
        #expect(try directory.names().isEmpty)
        let journal = try directory.open(fresh: true)
        #expect(fchmod(directory.fd, 0o755) == 0)
        #expect(throws: (any Error).self) { try journal.load() }
        #expect(fchmod(directory.fd, 0o700) == 0)
        #expect(throws: (any Error).self) { try journal.checkpoint(Data()) }
    }

    // Run this one test in a separate process so _exit bypasses every catch/defer.
    @Test func processCrashProbe() throws {
        let environment = ProcessInfo.processInfo.environment
        guard let path = environment["CENGINE_CHECKPOINT_CRASH_DIRECTORY"],
              let phaseName = environment["CENGINE_CHECKPOINT_CRASH_PHASE"] else { return }
        let fd = Darwin.open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw POSIXError(.EIO) }
        defer { close(fd) }
        let journal = try CheckpointJournal(directoryFD: fd,
            fresh: environment["CENGINE_CHECKPOINT_CRASH_FRESH"] == "1", ownerUID: geteuid(), configuredOwnerUID: 501,
            sync: { guard fsync($0) == 0 else { throw POSIXError(.EIO) } },
            fault: { if String(describing: $0) == phaseName { _exit(73) } })
        try journal.checkpoint(Data("new".utf8))
        Issue.record("crash phase was not reached")
    }

    @Test func abruptProcessCutsNeverFallBackAfterPublication() throws {
        for fresh in [false, true] {
            let phases = fresh ? CheckpointJournal.Phase.allCases : Array(CheckpointJournal.Phase.allCases.dropFirst(3))
            for phase in phases {
                let directory = try CheckpointDirectory()
                if !fresh {
                    let journal = try directory.open(fresh: true)
                    try journal.checkpoint(Data("old".utf8))
                }
                let process = Process()
                process.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
                // SwiftPM may launch through swiftpm-testing-helper rather than the
                // bundle executable. Preserve its bundle/package arguments, changing
                // only the selected test (also works with the older direct runner).
                var arguments = Array(CommandLine.arguments.dropFirst())
                if let filter = arguments.firstIndex(of: "--filter"), filter + 1 < arguments.count {
                    arguments.removeSubrange(filter...(filter + 1))
                }
                arguments += ["--filter", "StorageBootstrapCheckpointJournalTests/processCrashProbe"]
                process.arguments = arguments
                var environment = ProcessInfo.processInfo.environment
                environment["CENGINE_CHECKPOINT_CRASH_DIRECTORY"] = directory.url.path
                environment["CENGINE_CHECKPOINT_CRASH_PHASE"] = String(describing: phase)
                environment["CENGINE_CHECKPOINT_CRASH_FRESH"] = fresh ? "1" : "0"
                process.environment = environment
                process.standardOutput = FileHandle.nullDevice
                process.standardError = FileHandle.nullDevice
                try process.run()
                process.waitUntilExit()
                try #require(process.terminationStatus == 73, "phase=\(phase), arguments=\(CommandLine.arguments)")
                #expect(process.terminationReason == .exit)
                let names = try directory.names()
                if phase == .markerRemoved || phase == .committed {
                    // The new name was already durably synced before marker removal.
                    // An actual crash here may commit it, but can NEVER revive old state.
                    let reopened = try directory.open()
                    #expect(try reopened.load() == (fresh ? nil : Data("new".utf8)))
                } else {
                    #expect(throws: (any Error).self) { try directory.open() }
                    #expect(throws: (any Error).self) { try directory.open(fresh: true) }
                }
                #expect(try directory.names() == names)
            }
        }
    }

    @Test(arguments: ["directory", "authority.lock", "authority.journal"])
    func extendedACLIsRejected(_ name: String) throws {
        let directory = try CheckpointDirectory()
        let journal = try directory.open(fresh: true)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/chmod")
        process.arguments = ["+a", "user:\(NSUserName()) allow read",
            name == "directory" ? directory.url.path : directory.file(name).path]
        try process.run()
        process.waitUntilExit()
        try #require(process.terminationStatus == 0)
        #expect(throws: (any Error).self) { try journal.load() }
        #expect(throws: (any Error).self) { try journal.readRootPublicKey() }
    }

    @Test(arguments: [false, true])
    func mutationAfterReadIsRejected(_ mutateLock: Bool) throws {
        let directory = try CheckpointDirectory()
        var armed = false, mutations = 0
        let journal = try directory.open(fresh: true, read: { fd, buffer, count, offset in
            let n = pread(fd, buffer, count, offset)
            var info = stat()
            _ = fstat(fd, &info)
            if armed && (info.st_size == 76) == mutateLock && n > 0 && offset + off_t(n) == info.st_size {
                armed = false; mutations += 1
                var times = [info.st_atimespec, timespec(tv_sec: info.st_mtimespec.tv_sec - 1, tv_nsec: 0)]
                #expect(futimens(fd, &times) == 0)
            }
            return n
        })
        armed = true
        #expect(throws: (any Error).self) { try journal.load() }
        #expect(mutations == 1)
        #expect(throws: (any Error).self) { try journal.checkpoint(Data()) }
    }

    @Test func boundedPartialReadsInterruptsAndOversizedFileRejection() async {
        await #expect(processExitsWith: .success) {
            try StorageBootstrapCheckpointJournalTests().checkBoundedPartialReadsInterruptsAndOversizedFileRejection()
        }
    }

    private func checkBoundedPartialReadsInterruptsAndOversizedFileRejection() throws {
        let directory = try CheckpointDirectory()
        var journal: CheckpointJournal? = try directory.open(fresh: true)
        let payload = Data(repeating: 0x61, count: 131_079)
        try journal!.checkpoint(payload)
        journal = nil
        var calls = 0, largest = 0, fail = false
        journal = try directory.open(read: { fd, buffer, count, offset in
            calls += 1; largest = max(largest, count)
            if fail { return 0 }
            if calls % 17 == 1 { errno = EINTR; return -1 }
            return pread(fd, buffer, min(count, 7003), offset)
        })
        #expect(try journal!.load() == payload)
        #expect(largest == 65_536)
        fail = true
        #expect(throws: (any Error).self) { try journal!.load() }
        fail = false
        #expect(throws: (any Error).self) { try journal!.readRootPublicKey() }
        journal = nil
        let fd = openat(directory.fd, "authority.journal", O_RDWR | O_NOFOLLOW)
        defer { close(fd) }
        #expect(ftruncate(fd, off_t(CheckpointJournal.maximumBytes + 1)) == 0)
        var oversizedReads = 0
        #expect(throws: (any Error).self) {
            try directory.open(read: { fd, buffer, count, offset in
                var info = stat(); _ = fstat(fd, &info)
                if info.st_size > CheckpointJournal.maximumBytes { oversizedReads += 1 }
                return pread(fd, buffer, count, offset)
            })
        }
        #expect(oversizedReads == 0)
    }
}

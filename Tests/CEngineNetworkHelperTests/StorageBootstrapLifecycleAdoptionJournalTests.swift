import CEngineCore
import Darwin
import Foundation
import Testing
@testable import StorageBootstrapHelper

final class AdoptionDiskFixture {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let fd: Int32
    let binding: StorageLifecycleQualificationBinding
    init() throws {
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        fd = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw POSIXError(.EIO) }
        binding = try .verified(store: UUID().uuidString.lowercased(), rootFD: fd, owner: geteuid())
    }
    deinit { close(fd); try? FileManager.default.removeItem(at: url) }
    var scopeURL: URL { url.appendingPathComponent(binding.rootHash) }
    var leafURL: URL { scopeURL.appendingPathComponent(StorageBootstrapLifecycleAdoptionJournal.leafName) }
    func scope() throws -> StorageLifecycleQualificationDirectory {
        try .init(baseFD: fd, binding: binding, owner: geteuid(), sync: Self.sync)
    }
    static func sync(_ fd: Int32) throws { guard fsync(fd) == 0 else { throw POSIXError(.EIO) } }
}

@Suite struct StorageBootstrapLifecycleAdoptionJournalTests {
    // Concurrent Darwin spawns can briefly retain CLOEXEC descriptions before exec.
    // Isolate immediate release/reopen checks from unrelated process launches.
    @Test func onlyGenuinelyNewScopeMarksEnrollmentEligible() async {
        await #expect(processExitsWith: .success) {
            try StorageBootstrapLifecycleAdoptionJournalTests().checkOnlyGenuinelyNewScopeMarksEnrollmentEligible()
        }
    }

    private func checkOnlyGenuinelyNewScopeMarksEnrollmentEligible() throws {
        let f = try AdoptionDiskFixture()
        var scope: StorageLifecycleQualificationDirectory? = try f.scope()
        #expect(scope!.wasCreated)
        scope = nil
        scope = try f.scope()
        #expect(!scope!.wasCreated)
        // Even an otherwise empty existing scope cannot be treated as fresh by
        // the native router when its enrollment receipt/leaf is missing.
        #expect(throws: (any Error).self) { try scope!.adoptionJournalForTesting() }
    }

    @Test func noStartupCreationExplicitEnrollmentAndExactParentRoot() async {
        await #expect(processExitsWith: .success) {
            try StorageBootstrapLifecycleAdoptionJournalTests().checkNoStartupCreationExplicitEnrollmentAndExactParentRoot()
        }
    }

    private func checkNoStartupCreationExplicitEnrollmentAndExactParentRoot() throws {
        let f = try AdoptionDiskFixture()
        var scope: StorageLifecycleQualificationDirectory? = try f.scope()
        #expect(!FileManager.default.fileExists(atPath: f.leafURL.path))
        #expect(throws: (any Error).self) { try scope!.adoptionJournalForTesting() }
        if geteuid() != 0 { #expect(throws: (any Error).self) { try scope!.adoptionJournal(enrollIfNoState: true) } }
        var adapter: StorageBootstrapLifecycleAdoptionJournal? = try scope!.adoptionJournalForTesting(enrollIfNoState: true)
        let root = try scope!.journal.readRootPublicKey()
        #expect(try adapter!.rootPublicKey() == root)
        #expect(try adapter!.load() == nil)
        let lock = try Data(contentsOf: f.leafURL.appendingPathComponent("authority.lock"))
        #expect(lock.subdata(in: 12..<44) != root) // The nested signing key is NOT ROOT.
        try adapter!.checkpoint(Data("state".utf8))
        #expect(try scope!.journal.load() == nil)
        scope = nil // Adapter retains the scope and parent lock/FDs.
        #expect(try adapter!.load() == Data("state".utf8))
        adapter = nil
        let reopened = try f.scope().adoptionJournalForTesting()
        #expect(try reopened.rootPublicKey() == root)
        #expect(try reopened.load() == Data("state".utf8))
    }

    @Test func exclusiveLockOnFreshAndReopenedAdapters() async {
        await #expect(processExitsWith: .success) {
            try StorageBootstrapLifecycleAdoptionJournalTests().checkExclusiveLockOnFreshAndReopenedAdapters()
        }
    }

    private func checkExclusiveLockOnFreshAndReopenedAdapters() throws {
        let f = try AdoptionDiskFixture(), scope = try f.scope()
        var adapter: StorageBootstrapLifecycleAdoptionJournal? = try scope.adoptionJournalForTesting(enrollIfNoState: true)
        #expect(throws: StorageBootstrapCheckpointJournal.Failure.unavailable) { try scope.adoptionJournalForTesting() }
        adapter = nil
        adapter = try scope.adoptionJournalForTesting()
        #expect(throws: StorageBootstrapCheckpointJournal.Failure.unavailable) { try scope.adoptionJournalForTesting() }
        #expect(try adapter!.load() == nil)
    }

    @Test func missingEnrolledLeafAndMissingInitializedJournalNeverReset() async {
        await #expect(processExitsWith: .success) {
            try StorageBootstrapLifecycleAdoptionJournalTests().checkMissingEnrolledLeafAndMissingInitializedJournalNeverReset()
        }
    }

    private func checkMissingEnrolledLeafAndMissingInitializedJournalNeverReset() throws {
        for missing in ["leaf", "authority.journal"] {
            let f = try AdoptionDiskFixture(), scope = try f.scope()
            _ = try scope.adoptionJournalForTesting(enrollIfNoState: true)
            try FileManager.default.removeItem(at: missing == "leaf" ? f.leafURL : f.leafURL.appendingPathComponent(missing))
            let before = try FileManager.default.contentsOfDirectory(atPath: f.scopeURL.path)
            #expect(throws: (any Error).self) { try scope.adoptionJournalForTesting() }
            #expect(throws: (any Error).self) { try scope.adoptionJournalForTesting(enrollIfNoState: true) }
            #expect(try FileManager.default.contentsOfDirectory(atPath: f.scopeURL.path) == before)
        }
    }

    @Test func existingLifecycleStateCannotEnroll() throws {
        let f = try AdoptionDiskFixture(), scope = try f.scope()
        try scope.journal.checkpoint(Data("existing lifecycle state".utf8))
        #expect(throws: (any Error).self) { try scope.adoptionJournalForTesting(enrollIfNoState: true) }
        #expect(!FileManager.default.fileExists(atPath: f.leafURL.path))
    }

    @Test func copiedCheckpointRejectsDifferentRootAndScope() throws {
        let a = try AdoptionDiskFixture(), b = try AdoptionDiskFixture()
        let first = try a.scope(), second = try b.scope()
        do {
            let adapter = try first.adoptionJournalForTesting(enrollIfNoState: true)
            try adapter.checkpoint(Data("copied".utf8))
        }
        _ = try second.adoptionJournalForTesting(enrollIfNoState: true)
        try FileManager.default.removeItem(at: b.leafURL)
        try FileManager.default.copyItem(at: a.leafURL, to: b.leafURL)
        #expect(throws: (any Error).self) { try second.adoptionJournalForTesting() }
        // Even with a copied receipt, exact scope metadata and parent ROOT differ.
        let receipt = "adoption-v3.enrolled"
        try FileManager.default.removeItem(at: b.scopeURL.appendingPathComponent(receipt))
        try FileManager.default.copyItem(at: a.scopeURL.appendingPathComponent(receipt), to: b.scopeURL.appendingPathComponent(receipt))
        #expect(throws: (any Error).self) { try second.adoptionJournalForTesting() }
    }

    @Test func sameScopeMetadataWithAnotherParentRootRejectsCopiedPayload() throws {
        let f = try AdoptionDiskFixture(), other = try AdoptionDiskFixture()
        var original: StorageLifecycleQualificationDirectory? = try f.scope()
        _ = try original!.adoptionJournalForTesting(enrollIfNoState: true)
        original = nil
        let replacement = try StorageLifecycleQualificationDirectory(baseFD: other.fd, binding: f.binding, owner: geteuid(), sync: AdoptionDiskFixture.sync)
        let target = other.url.appendingPathComponent(f.binding.rootHash)
        try FileManager.default.copyItem(at: f.leafURL, to: target.appendingPathComponent("adoption-v3"))
        try FileManager.default.copyItem(at: f.scopeURL.appendingPathComponent("adoption-v3.enrolled"), to: target.appendingPathComponent("adoption-v3.enrolled"))
        #expect(throws: (any Error).self) { try replacement.adoptionJournalForTesting() }
    }

    @Test func differentScopeWithCopiedParentRootStillRejectsWrapper() async {
        await #expect(processExitsWith: .success) {
            try StorageBootstrapLifecycleAdoptionJournalTests().checkDifferentScopeWithCopiedParentRootStillRejectsWrapper()
        }
    }

    private func checkDifferentScopeWithCopiedParentRootStillRejectsWrapper() throws {
        let a = try AdoptionDiskFixture(), b = try AdoptionDiskFixture()
        var first: StorageLifecycleQualificationDirectory? = try a.scope()
        _ = try first!.adoptionJournalForTesting(enrollIfNoState: true)
        first = nil
        var second: StorageLifecycleQualificationDirectory? = try b.scope()
        _ = try second!.adoptionJournalForTesting(enrollIfNoState: true)
        second = nil
        // Copy BOTH nested authority and parent key; only the scope metadata differs.
        for name in ["journal", "adoption-v3", "adoption-v3.enrolled"] {
            let target = b.scopeURL.appendingPathComponent(name)
            try FileManager.default.removeItem(at: target)
            try FileManager.default.copyItem(at: a.scopeURL.appendingPathComponent(name), to: target)
        }
        second = try b.scope()
        let firstRoot = try a.scope().journal.readRootPublicKey()
        #expect(try second!.journal.readRootPublicKey() == firstRoot)
        #expect(throws: (any Error).self) { try second!.adoptionJournalForTesting() }
    }

    @Test func interruptedEnrollmentReceiptNeverRetriesAsFresh() throws {
        let f = try AdoptionDiskFixture(), scope = try f.scope()
        #expect(throws: (any Error).self) {
            try scope.adoptionJournalForTesting(enrollIfNoState: true, sync: { _ in throw POSIXError(.EIO) })
        }
        let receipt = f.scopeURL.appendingPathComponent("adoption-v3.enrolled")
        let before = try Data(contentsOf: receipt)
        #expect(!FileManager.default.fileExists(atPath: f.leafURL.path))
        #expect(throws: (any Error).self) { try scope.adoptionJournalForTesting() }
        #expect(throws: (any Error).self) { try scope.adoptionJournalForTesting(enrollIfNoState: true) }
        #expect(try Data(contentsOf: receipt) == before)
    }

    @Test func parentValidationAfterPublicationRefusesAndPoisons() throws {
        let f = try AdoptionDiskFixture(), scope = try f.scope()
        var armed = false, calls = 0
        let metadata = f.scopeURL.appendingPathComponent("scope")
        let original = try Data(contentsOf: metadata)
        let adapter = try scope.adoptionJournalForTesting(enrollIfNoState: true, sync: { fd in
            try AdoptionDiskFixture.sync(fd)
            if armed {
                calls += 1
                if calls == 5 { try Data("changed during publication".utf8).write(to: metadata) }
            }
        })
        armed = true
        #expect(throws: (any Error).self) { try adapter.checkpoint(Data("published".utf8)) }
        try original.write(to: metadata)
        #expect(throws: (any Error).self) { try adapter.load() }
        #expect(throws: (any Error).self) { try adapter.rootPublicKey() }
    }

    @Test(arguments: ["unknown", "symlink", "mode", "marker", "emptyJournal"])
    func unsafeExistingLeafRefusesUnchanged(_ mutation: String) async {
        await #expect(processExitsWith: .success) { [mutation] in
            try StorageBootstrapLifecycleAdoptionJournalTests().checkUnsafeExistingLeafRefusesUnchanged(mutation)
        }
    }

    private func checkUnsafeExistingLeafRefusesUnchanged(_ mutation: String) throws {
        let f = try AdoptionDiskFixture(), scope = try f.scope()
        _ = try scope.adoptionJournalForTesting(enrollIfNoState: true)
        let file = f.leafURL.appendingPathComponent("authority.journal")
        switch mutation {
        case "unknown": try Data([1]).write(to: f.leafURL.appendingPathComponent("unknown"))
        case "symlink":
            try FileManager.default.removeItem(at: file)
            #expect(symlink("/dev/null", file.path) == 0)
        case "mode": #expect(chmod(file.path, 0o644) == 0)
        case "marker": try Data([1]).write(to: f.leafURL.appendingPathComponent("authority.checkpoint-in-progress"))
        default:
            // A valid native journal with no initialized adapter envelope is not fresh.
            try FileManager.default.removeItem(at: f.leafURL)
            #expect(mkdir(f.leafURL.path, 0o700) == 0)
            let fd = open(f.leafURL.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
            defer { close(fd) }
            _ = try StorageBootstrapCheckpointJournal(directoryFD: fd, fresh: true, ownerUID: geteuid(), configuredOwnerUID: f.binding.ownerUID, sync: AdoptionDiskFixture.sync)
        }
        let names = try FileManager.default.contentsOfDirectory(atPath: f.leafURL.path)
        #expect(throws: (any Error).self) { try scope.adoptionJournalForTesting() }
        #expect(try FileManager.default.contentsOfDirectory(atPath: f.leafURL.path) == names)
    }

    @Test func payloadBoundAndNativeJournalLimitUnchanged() throws {
        let f = try AdoptionDiskFixture(), scope = try f.scope()
        let adapter = try scope.adoptionJournalForTesting(enrollIfNoState: true, sync: AdoptionDiskFixture.sync)
        let bytes = Data(repeating: 42, count: 2 * 1024 * 1024)
        #expect(throws: (any Error).self) { try adapter.checkpoint(bytes + Data([0])) }
        try adapter.checkpoint(bytes)
        #expect(try adapter.load() == bytes)
        #expect(try Data(contentsOf: f.leafURL.appendingPathComponent("authority.journal")).count < bytes.count + 4096 + 88)
        #expect(StorageBootstrapCheckpointJournal.maximumBytes == 32 * 1024 * 1024)
    }

    @Test(arguments: 1...5)
    func failedSyncPoisonsAndPreservesMarker(_ barrier: Int) async {
        await #expect(processExitsWith: .success) { [barrier] in
            try StorageBootstrapLifecycleAdoptionJournalTests().checkFailedSyncPoisonsAndPreservesMarker(barrier)
        }
    }

    private func checkFailedSyncPoisonsAndPreservesMarker(_ barrier: Int) throws {
        let f = try AdoptionDiskFixture(), scope = try f.scope()
        var armed = false, calls = 0
        var adapter: StorageBootstrapLifecycleAdoptionJournal? = try scope.adoptionJournalForTesting(enrollIfNoState: true, sync: { fd in
            if armed { calls += 1; if calls == barrier { throw POSIXError(.EIO) } }
            try AdoptionDiskFixture.sync(fd)
        })
        armed = true
        #expect(throws: (any Error).self) { try adapter!.checkpoint(Data("uncertain".utf8)) }
        armed = false
        #expect(throws: (any Error).self) { try adapter!.load() }
        #expect(throws: (any Error).self) { try adapter!.rootPublicKey() }
        #expect(throws: (any Error).self) { try adapter!.checkpoint(Data()) }
        adapter = nil
        let marker = f.leafURL.appendingPathComponent("authority.checkpoint-in-progress")
        let before = try Data(contentsOf: marker)
        #expect(throws: (any Error).self) { try scope.adoptionJournalForTesting() }
        #expect(try Data(contentsOf: marker) == before)
    }

    @Test func liveMetadataFailurePoisonsEvenAfterRestoration() throws {
        let f = try AdoptionDiskFixture(), scope = try f.scope()
        let adapter = try scope.adoptionJournalForTesting(enrollIfNoState: true)
        let metadata = f.scopeURL.appendingPathComponent("scope"), before = try Data(contentsOf: metadata)
        try Data("bad".utf8).write(to: metadata)
        #expect(throws: (any Error).self) { try adapter.load() }
        try before.write(to: metadata)
        #expect(throws: (any Error).self) { try adapter.rootPublicKey() }
    }
}

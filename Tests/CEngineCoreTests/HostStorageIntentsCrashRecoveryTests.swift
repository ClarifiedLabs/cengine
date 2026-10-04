#if os(macOS)
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

@Suite(.serialized) @MainActor struct HostStorageIntentsCrashRecoveryTests {
    private typealias Commit = HostStorageIntentCommit
    private typealias State = HostStorageIntents.State

    nonisolated static let commitSteps = [
        "initialProofCreate", "initialProofWrite", "initialProofSync", "initialProofClose",
        "initialProofPublish", "initialProofDirectorySync",
        "candidateCreate", "candidateWrite", "candidateSync", "candidateClose",
        "readyProofCreate", "readyProofWrite", "readyProofSync", "readyProofClose",
        "readyProofPublish", "readyProofDirectorySync", "statePublish", "stateDirectorySync",
        "proofDeletionObserved", "proofDeletionClaimed", "proofDeletionRemoved", "proofDeletionDirectorySync",
    ]
    nonisolated static let cleanupSteps = [
        "stageDeletionObserved", "stageDeletionClaimed", "stageDeletionRemoved", "stageDeletionDirectorySync",
        "candidateDeletionObserved", "candidateDeletionClaimed", "candidateDeletionRemoved", "candidateDeletionDirectorySync",
        "proofDeletionObserved", "proofDeletionClaimed", "proofDeletionRemoved", "proofDeletionDirectorySync",
    ]

    @Test(arguments: commitSteps, [false, true])
    func abruptCommitPreservesExactlyPriorOrPublishedNext(step: String, after: Bool) async throws {
        let b = try baseline(); defer { b.fixture.remove() }
        let path = b.fixture.url.path, store = b.fixture.store, provenance = b.fixture.provenance, intent = b.intent
        // Only value captures cross the process boundary. No inherited owner or
        // fork-held lease is used; the child opens and owns the actual journal.
        await #expect(processExitsWith: .exitCode(74)) { [path = path as String, store = store as String, provenance = provenance as String, intent = intent as String, step, after] in
            try await HostStorageIntentsCrashRecoveryTests.crash(path: path, store: store, provenance: provenance, intent: intent,
                                 step: step, after: after, mutate: true)
        }
        let published = step == "statePublish" ? after : step == "stateDirectorySync" || step.hasPrefix("proofDeletion")
        let expected = published ? b.next : b.prior
        #expect(try stateBytes(b) == canonical(expected))
        try assertReopened(b, expected: expected)
    }

    @Test(arguments: cleanupSteps, [false, true])
    func recoveryCanCrashAgainAtFixedCleanupClaims(step: String, after: Bool) async throws {
        let b = try baseline(); defer { b.fixture.remove() }
        let path = b.fixture.url.path, store = b.fixture.store, provenance = b.fixture.provenance, intent = b.intent
        // Ready staging leaves stage + candidate + initial proof. A published
        // state leaves only the proof, reaching its cleanup with no scratch.
        let initial = step.hasPrefix("proof") ? "statePublish" : "readyProofClose"
        await #expect(processExitsWith: .exitCode(74)) { [path = path as String, store = store as String, provenance = provenance as String, intent = intent as String, initial = initial as String] in
            try await HostStorageIntentsCrashRecoveryTests.crash(path: path, store: store, provenance: provenance, intent: intent,
                                 step: initial, after: true, mutate: true)
        }
        await #expect(processExitsWith: .exitCode(74)) { [path = path as String, store = store as String, provenance = provenance as String, intent = intent as String, step, after] in
            try await HostStorageIntentsCrashRecoveryTests.crash(path: path, store: store, provenance: provenance, intent: intent,
                                 step: step, after: after, mutate: false)
        }
        let directory = try managed(b)
        let name = step.hasPrefix("stage") ? Commit.proofStageName : step.hasPrefix("candidate") ? Commit.candidateName : Commit.proofName
        let names = try directory.entryNames()
        if step.contains("Claimed") {
            #expect(names.contains(name + ".claim") && !names.contains(name))
        } else if step.contains("Removed") || step.contains("DirectorySync") {
            #expect(!names.contains(name) && !names.contains(name + ".claim"))
        }
        // A claim must be resumable, not renamed to a second random claim. Once
        // an entry is already gone, crash at the next still-reachable cleanup.
        let again: String
        if names.contains(name) || names.contains(name + ".claim") {
            again = String(step.prefix(while: { $0 != "D" })) + "DeletionRemoved"
        } else if names.contains(Commit.proofName) { again = "proofDeletionClaimed" }
        else { again = "inspection" } // Proof unlink was the last cleanup IO.
        await #expect(processExitsWith: .exitCode(74)) { [path = path as String, store = store as String, provenance = provenance as String, intent = intent as String, again = again as String] in
            try await HostStorageIntentsCrashRecoveryTests.crash(path: path, store: store, provenance: provenance, intent: intent,
                                 step: again, after: true, mutate: false)
        }
        try assertReopened(b, expected: initial == "statePublish" ? b.next : b.prior)
    }

    @Test(arguments: [false, true])
    func newOwnerReconciliationCommitIsItselfCrashRecoverable(after: Bool) async throws {
        let b = try baseline(fenced: false); defer { b.fixture.remove() }
        let path = b.fixture.url.path, store = b.fixture.store, provenance = b.fixture.provenance, intent = b.intent
        var fenced = b.prior; fenced.revision += 1; fenced.reconciliationRequired = true
        await #expect(processExitsWith: .exitCode(74)) { [path = path as String, store = store as String, provenance = provenance as String, intent = intent as String, after] in
            try await HostStorageIntentsCrashRecoveryTests.crash(path: path, store: store, provenance: provenance, intent: intent,
                                 step: "statePublish", after: after, mutate: false)
        }
        #expect(try stateBytes(b) == canonical(after ? fenced : b.prior))
        // Whether the first owner published or not, precisely one fence revision
        // survives; it must not mint keys, receipts, or replay operations.
        try assertReopened(b, expected: fenced)
    }

    private static func crash(path: String, store: String, provenance: String, intent: String,
                              step: String, after: Bool, mutate: Bool) throws {
        let root = try PersistentStateDirectory.open(URL(filePath: path))
        let journal = try HostStorageIntents.open(in: root, store: store, provenanceReference: provenance,
            commitHook: { observed, moment in
                if observed.rawValue == step, (moment == .after) == after { Darwin._exit(74) }
            })
        if mutate { try freeze(journal, intent: intent) }
        Issue.record("crash checkpoint was not reached: \(step)")
        // Normal return is intentionally not the expected exit code.
    }

    nonisolated static let refusals = [
        "wrongStore", "wrongProvenance", "manifestDigest", "rootIdentity", "directoryIdentity", "leaseIdentity",
        "malformedProof", "noncanonicalProof", "readyFalseNext", "revision", "hash", "semanticState",
        "unexpectedFile", "symlink", "fifo", "directory", "hardlink", "mode", "candidateWithoutProof",
        "uncertain", "genericTemporary", "doubledProof", "doubledStage", "doubledCandidate", "noncanonicalManifest",
    ]

    @Test(arguments: refusals)
    func invalidEvidenceNeverAuthorizesCleanupOrChangesOnSecondOpen(vector: String) throws {
        let b = try baseline(); defer { b.fixture.remove() }
        var directory = try managed(b)
        try seed(b, directory: directory)
        var store = b.fixture.store, provenance = b.fixture.provenance
        switch vector {
        case "wrongStore": store = HostIntentFixture.id()
        case "wrongProvenance": provenance = String(repeating: "f", count: 64)
        case "manifestDigest":
            try replaceProof(b, directory: directory, manifest: Data("different manifest".utf8))
        case "rootIdentity":
            let old = b.fixture.url.appendingPathExtension("old")
            defer { try? FileManager.default.removeItem(at: old) }
            try FileManager.default.moveItem(at: b.fixture.url, to: old)
            try FileManager.default.createDirectory(at: b.fixture.url, withIntermediateDirectories: false,
                                                    attributes: [.posixPermissions: 0o700])
            try FileManager.default.moveItem(at: old.appending(path: "managed-storage"),
                                            to: b.fixture.url.appending(path: "managed-storage"))
        case "directoryIdentity":
            let old = b.fixture.url.appending(path: "old-directory")
            try FileManager.default.moveItem(at: directory.url, to: old)
            directory = try b.fixture.root.createDirectory(named: "managed-storage")
            for name in try FileManager.default.contentsOfDirectory(atPath: old.path) {
                try FileManager.default.moveItem(at: old.appending(path: name), to: directory.url.appending(path: name))
            }
        case "leaseIdentity":
            try FileManager.default.moveItem(at: directory.url.appending(path: Commit.leaseName),
                                            to: b.fixture.url.appending(path: "old-lease"))
            try directory.writeExclusiveRegularFile(named: Commit.leaseName, data: Data())
        case "noncanonicalManifest":
            let bytes = try #require(try directory.readRegularFile(named: Commit.manifestName))
            try directory.replaceRegularFile(named: Commit.manifestName, data: bytes + Data("\n".utf8))
        case "malformedProof":
            try directory.replaceRegularFile(named: Commit.proofName, data: Data("{".utf8))
        case "noncanonicalProof":
            let bytes = try #require(try directory.readRegularFile(named: Commit.proofName))
            try directory.replaceRegularFile(named: Commit.proofName, data: bytes + Data("\n".utf8))
        case "readyFalseNext":
            try b.fixture.write(b.next)
            try FileManager.default.removeItem(at: directory.url.appending(path: Commit.candidateName))
            try replaceProof(b, directory: directory, ready: false)
        case "revision": try replaceProof(b, directory: directory, nextRevision: b.prior.revision + 2)
        case "hash": try replaceProof(b, directory: directory, prior: Data("not current state".utf8))
        case "semanticState":
            var invalid = b.prior
            let historical = try #require(invalid.intents.values.first { $0.phase == .retired })
            invalid.intents[historical.id]?.slots[0].key = nil // Receipt now has no corresponding key.
            try b.fixture.write(invalid)
            try replaceProof(b, directory: directory, prior: canonical(invalid))
        case "unexpectedFile", "uncertain", "genericTemporary":
            let name = vector == "uncertain" ? "uncertain" : vector == "genericTemporary" ? ".cengine-state-00000000-0000-4000-8000-000000000002" : "unexpected"
            try directory.writeExclusiveRegularFile(named: name, data: Data("do not delete".utf8))
        case "symlink", "fifo", "directory":
            let path = directory.url.appending(path: Commit.candidateName).path
            try #require(Darwin.unlink(path) == 0)
            if vector == "symlink" { try #require(Darwin.symlink("state.json", path) == 0) }
            else if vector == "fifo" { try #require(Darwin.mkfifo(path, 0o600) == 0) }
            else { try #require(Darwin.mkdir(path, 0o700) == 0) }
        case "hardlink":
            try #require(Darwin.link(directory.url.appending(path: Commit.candidateName).path,
                                    b.fixture.url.appending(path: "outside-link").path) == 0)
        case "mode": try #require(Darwin.chmod(directory.url.appending(path: Commit.proofName).path, 0o644) == 0)
        case "candidateWithoutProof":
            try FileManager.default.removeItem(at: directory.url.appending(path: Commit.proofName))
        case "doubledProof", "doubledStage", "doubledCandidate":
            let name = vector == "doubledProof" ? Commit.proofName : vector == "doubledStage" ? Commit.proofStageName : Commit.candidateName
            if vector == "doubledStage" { try directory.writeExclusiveRegularFile(named: name, data: Data("partial stage".utf8)) }
            let bytes = try #require(try directory.readRegularFile(named: name))
            try directory.writeExclusiveRegularFile(named: name + ".claim", data: bytes)
        default: Issue.record("unknown refusal vector")
        }
        try refusesTwice(b, store: store, provenance: provenance)
    }

    nonisolated static let errorSteps = [
        "commitPreflight", "candidateSync", "candidateClose", "readyProofPublish", "statePublish",
        "stateDirectorySync", "proofDeletionClaimed", "proofDeletionRemoved", "proofDeletionDirectorySync", "cleanupValidate",
    ]

    @Test(arguments: errorSteps, [false, true])
    func reportedIOErrorsPoisonMemoryAndPersistUncertainty(step: String, after: Bool) throws {
        for code in [POSIXErrorCode.EIO, .ENOSPC] {
            let b = try baseline(); defer { b.fixture.remove() }
            var armed = false, reached = false
            var owner: HostStorageIntents? = try HostStorageIntents.open(in: b.fixture.root, store: b.fixture.store,
                provenanceReference: b.fixture.provenance, commitHook: { observed, moment in
                    if armed, observed.rawValue == step, (moment == .after) == after {
                        reached = true; throw POSIXError(code)
                    }
                })
            weak var previous = owner
            armed = true
            #expect(throws: (any Error).self) { try Self.freeze(try #require(owner), intent: b.intent) }
            #expect(reached)
            #expect(throws: HostStorageIntents.Failure.poisoned) { try owner!.snapshot() }
            #expect(throws: HostStorageIntents.Failure.poisoned) { try owner!.replayRequest(operation: b.operation) }
            #expect(owner?.canDelete(volume: b.fixture.volumes[0].id) == false)
            #expect(try managed(b).readRegularFile(named: "uncertain") == Data([1]))
            owner = nil
            try #require(previous == nil)
            try refusesTwice(b)
        }
    }

    @Test(arguments: ["candidateSync", "candidateClose", "stateDirectorySync", "proofDeletionRemoved"], [EIO, ENOSPC])
    func deathAfterReturnedErrorBeforePoisonUsesOnlyIndependentStateProof(step: String, code: CInt) async throws {
        let b = try baseline(); defer { b.fixture.remove() }
        let path = b.fixture.url.path, store = b.fixture.store, provenance = b.fixture.provenance
        await #expect(processExitsWith: .exitCode(74)) { [path = path as String, store = store as String, provenance = provenance as String, step, code] in
            try await HostStorageIntentsCrashRecoveryTests.errorBeforePoison(path: path, store: store,
                provenance: provenance, step: step, code: code)
        }
        // A device cannot be assumed to record its own error before death. This
        // deliberately bypasses only the caller's best-effort poison write, not
        // any IO ordering or validation in the real commit helper.
        #expect(!(try managed(b).entryNames()).contains("uncertain"))
        var expected = b.prior
        if step == "stateDirectorySync" || step == "proofDeletionRemoved" {
            expected.revision += 1
            expected.reconciliationEvidence = Data("unacknowledged candidate".utf8)
        }
        #expect(try stateBytes(b) == canonical(expected))
        try assertReopened(b, expected: expected)
    }

    private static func errorBeforePoison(path: String, store: String, provenance: String,
                                         step: String, code: CInt) throws {
        let root = try PersistentStateDirectory.open(URL(filePath: path))
        let owner = try HostStorageIntents.open(in: root, store: store, provenanceReference: provenance)
        let directory = try PersistentStateDirectory.open(URL(filePath: path).appending(path: "managed-storage"))
        let manifest = try #require(try directory.readRegularFile(named: Commit.manifestName))
        let prior = try owner.snapshot()
        var next = prior; next.revision += 1
        next.reconciliationEvidence = Data("unacknowledged candidate".utf8)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var injected = false
        let helper = Commit(directory: directory, manifest: manifest, hook: { observed, moment in
            if observed.rawValue == step, moment == .before {
                injected = true
                throw POSIXError(try #require(POSIXErrorCode(rawValue: code)))
            }
        })
        try withExtendedLifetime(owner) {
            do {
                try helper.commit(prior: encoder.encode(prior), priorRevision: prior.revision,
                                  next: encoder.encode(next), nextRevision: next.revision)
                Issue.record("injected error was not reached")
            } catch let error as POSIXError where injected && error.code.rawValue == code {
                Darwin._exit(74) // The returned error is observed, but poison has not run.
            }
        }
    }

    @Test(arguments: ["recoveryDirectorySync", "stageDeletionClaimed", "candidateDeletionRemoved", "proofDeletionDirectorySync"], [false, true])
    func reportedRecoveryErrorsLeavePersistentFence(step: String, after: Bool) throws {
        for code in [POSIXErrorCode.EIO, .ENOSPC] {
            let b = try baseline(); defer { b.fixture.remove() }
            let directory = try managed(b)
            try seed(b, directory: directory)
            try directory.writeExclusiveRegularFile(named: Commit.proofStageName, data: Data("partial stage".utf8))
            var reached = false
            #expect(throws: (any Error).self) {
                _ = try HostStorageIntents.open(in: b.fixture.root, store: b.fixture.store,
                    provenanceReference: b.fixture.provenance, commitHook: { observed, moment in
                        if observed.rawValue == step, (moment == .after) == after {
                            reached = true; throw POSIXError(code)
                        }
                    })
            }
            #expect(reached)
            #expect(try directory.readRegularFile(named: "uncertain") == Data([1]))
            try refusesTwice(b)
        }
    }

    @Test func inspectionIsReadOnlyAndSealedToItsHelperAndExactCensus() throws {
        let b = try baseline(); defer { b.fixture.remove() }
        let owner = try b.fixture.open() // Keep a real exclusive owner throughout helper calls.
        let directory = try managed(b)
        try seed(b, directory: directory)
        let manifest = try #require(try directory.readRegularFile(named: Commit.manifestName))
        let helper = Commit(directory: directory, manifest: manifest)
        let foreign = Commit(directory: directory, manifest: manifest)
        let before = try census(b.fixture.url)
        let inspection = try helper.inspect(state: canonical(b.prior), revision: b.prior.revision)
        #expect(try census(b.fixture.url) == before)
        #expect(throws: (any Error).self) { try foreign.recover(inspection) }
        #expect(try census(b.fixture.url) == before)
        // Identical bytes with a different inode are still a stale inspection.
        try directory.replaceRegularFile(named: Commit.candidateName, data: canonical(b.next))
        let changed = try census(b.fixture.url)
        #expect(changed != before)
        #expect(throws: (any Error).self) { try helper.recover(inspection) }
        #expect(try census(b.fixture.url) == changed)
        #expect(try owner.snapshot() == b.prior)
        withExtendedLifetime(owner) {}
    }

    @Test func mutationAfterInspectionRefusesWithoutAutomaticCleanupOrPoison() throws {
        let b = try baseline(); defer { b.fixture.remove() }
        let directory = try managed(b)
        try seed(b, directory: directory)
        var changed: [String: Entry]?
        #expect(throws: (any Error).self) {
            _ = try HostStorageIntents.open(in: b.fixture.root, store: b.fixture.store,
                provenanceReference: b.fixture.provenance, commitHook: { step, moment in
                    if step == .inspection, moment == .after {
                        try directory.replaceRegularFile(named: Commit.candidateName, data: Data("raced candidate".utf8))
                        changed = try census(b.fixture.url)
                    }
                })
        }
        let expected = try #require(changed)
        #expect(try census(b.fixture.url) == expected)
        #expect(!(try directory.entryNames()).contains("uncertain"))
        try refusesTwice(b)
    }

    @Test(arguments: ["candidateDeletionObserved", "candidateDeletionClaimed"])
    func cleanupRaceNeverUnlinksAnUninspectedReplacement(step: String) throws {
        let b = try baseline(); defer { b.fixture.remove() }
        let directory = try managed(b)
        try seed(b, directory: directory)
        let name = step == "candidateDeletionClaimed" ? Commit.candidateClaimName : Commit.candidateName
        var replacement: Entry?
        #expect(throws: (any Error).self) {
            _ = try HostStorageIntents.open(in: b.fixture.root, store: b.fixture.store,
                provenanceReference: b.fixture.provenance, commitHook: { observed, moment in
                    if observed.rawValue == step, moment == .after {
                        try directory.replaceRegularFile(named: name, data: Data("not the inspected inode".utf8))
                        replacement = try census(b.fixture.url)["./managed-storage/" + name]
                    }
                })
        }
        let expected = try #require(replacement)
        #expect(try census(b.fixture.url)["./managed-storage/" + name] == expected)
        #expect(try directory.readRegularFile(named: "uncertain") == Data([1]))
        #expect(try stateBytes(b) == canonical(b.prior))
        try refusesTwice(b)
    }

    private struct Baseline {
        let fixture: HostIntentFixture
        let prior: State
        let next: State
        let intent: String
        let operation: String
    }

    /// All semantic history and both commit alternatives come from real public
    /// journal mutations. Only the final rewind uses the fixture's canonical writer.
    private func baseline(fenced: Bool = true) throws -> Baseline {
        let f = try HostIntentFixture()
        do {
            let prior: State, next: State, intent: String, operation: String
            weak var previous: HostStorageIntents?
            do {
                let journal = try f.initialize(); previous = journal
                try journal.reconciled(); try journal.planVolumes(f.volumes)
                for var volume in f.volumes {
                    volume.rootDevice = 1; volume.rootInode = 100; volume.createdRevision = 2
                    try journal.recordVolume(volume)
                }
                var old = try f.drain(journal, token: f.freeze(journal, token: journal.plan(f.intent()), runtime: true), runtime: true)
                old = try journal.update(old) {
                    $0.guestCompletion = .init(prepare: $0.prepare, containerInstance: $0.containerInstance, launch: $0.launch,
                        succeeded: true, cleanCopyUp: true, evidenceDigest: String(repeating: "e", count: 64))
                    $0.cleanUnmount = true
                }
                let history = try journal.intent(old)
                let operations = f.volumes.map(\.createOperation) + [history.reserveOperation, history.completeOperation]
                    + history.slots.flatMap { [$0.registerOperation, $0.retireOperation] }
                for id in operations { try journal.recordOperation(id: id, request: journal.request(for: id)) }
                _ = try journal.update(old) { $0.prepareCompleted = true; $0.phase = .retired }
                let tombstone = HostStorageIntents.Volume(id: HostIntentFixture.id(), name: "deleted-history",
                    createOperation: HostIntentFixture.id(), deleteOperation: HostIntentFixture.id())
                try journal.planVolumes([tombstone]); _ = try journal.deleteUncreatedVolume(tombstone.id)
                let active = try journal.plan(f.intent()); intent = active.intent; operation = history.completeOperation
                if fenced { try journal.retainReconciliationFence(Data("prior reconciliation evidence".utf8)) }
                prior = try journal.snapshot()
                try Self.freeze(journal, intent: intent)
                next = try journal.snapshot()
                #expect(prior.operations[operation] != nil)
                #expect(prior.intents[history.id]?.slots.allSatisfy { $0.key != nil && $0.receipt != nil } == true)
                #expect(prior.volumes[tombstone.id]?.localDeletionRevision != nil)
            }
            try #require(previous == nil)
            try f.write(prior)
            return Baseline(fixture: f, prior: prior, next: next, intent: intent, operation: operation)
        } catch { f.remove(); throw error }
    }

    private static func freeze(_ journal: HostStorageIntents, intent: String) throws {
        let token = try journal.token(for: intent), planned = try journal.intent(token)
        let keys = Dictionary(uniqueKeysWithValues: planned.slots.filter { $0.role == "prepare" }.map {
            ($0.attachment, HostStorageIntents.hash(Data($0.attachment.utf8)))
        })
        _ = try journal.freezeKeys(token, role: .prepare, keys: keys)
    }

    private func assertReopened(_ b: Baseline, expected: State) throws {
        for _ in 0..<2 {
            let root = try PersistentStateDirectory.open(b.fixture.url)
            let journal = try HostStorageIntents.open(in: root, store: b.fixture.store, provenanceReference: b.fixture.provenance)
            #expect(try journal.snapshot() == expected)
            #expect(try stateBytes(b) == canonical(expected))
            for (operation, bytes) in expected.operations {
                #expect(try journal.replayRequest(operation: operation).durableBytes() == bytes)
            }
            #expect(try managed(b).entryNames() == [Commit.leaseName, Commit.manifestName, Commit.stateName].sorted())
        }
    }

    private func managed(_ b: Baseline) throws -> PersistentStateDirectory {
        try PersistentStateDirectory.open(b.fixture.url.appending(path: "managed-storage"))
    }
    private func stateBytes(_ b: Baseline) throws -> Data {
        try #require(try managed(b).readRegularFile(named: Commit.stateName))
    }
    private func canonical<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }
    private func seed(_ b: Baseline, directory: PersistentStateDirectory) throws {
        try directory.writeExclusiveRegularFile(named: Commit.candidateName, data: canonical(b.next))
        try replaceProof(b, directory: directory)
    }
    private func replaceProof(_ b: Baseline, directory: PersistentStateDirectory, prior: Data? = nil,
                              nextRevision: UInt64? = nil, manifest: Data? = nil, ready: Bool = true) throws {
        let manifestBytes = try #require(try directory.readRegularFile(named: Commit.manifestName))
        let proof = Commit.Proof(version: 1, attempt: "00000000-0000-4000-8000-000000000001",
            manifestDigest: Commit.digest(manifest ?? manifestBytes), priorRevision: b.prior.revision,
            nextRevision: nextRevision ?? b.next.revision, priorSHA: Commit.digest(try prior ?? canonical(b.prior)),
            nextSHA: Commit.digest(try canonical(b.next)), ready: ready)
        try directory.replaceRegularFile(named: Commit.proofName, data: Commit.encodeProof(proof))
    }

    private func refusesTwice(_ b: Baseline, store: String? = nil, provenance: String? = nil) throws {
        let before = try census(b.fixture.url)
        var first: String?
        for _ in 0..<2 {
            var refusal: String?
            do {
                let root = try PersistentStateDirectory.open(b.fixture.url)
                _ = try HostStorageIntents.open(in: root, store: store ?? b.fixture.store,
                                                provenanceReference: provenance ?? b.fixture.provenance)
                Issue.record("unsafe journal unexpectedly reopened")
            } catch { refusal = String(reflecting: error) }
            #expect(refusal != nil)
            if let first { #expect(refusal == first) } else { first = refusal }
            #expect(try census(b.fixture.url) == before)
        }
    }

    private struct Entry: Equatable {
        let device: Int32
        let inode: UInt64
        let mode: UInt16
        let uid: UInt32
        let gid: UInt32
        let links: UInt16
        let flags: UInt32
        let size: Int64
        let modifiedSeconds: Int
        let modifiedNanos: Int
        let changedSeconds: Int
        let changedNanos: Int
        let bytes: Data?
    }

    /// Complete read-only evidence, including unexpected entries and physical
    /// identities. Never open a FIFO or follow a symlink to obtain its contents.
    private func census(_ root: URL) throws -> [String: Entry] {
        var result: [String: Entry] = [:]
        func visit(parent: CInt, component: String, name: String) throws {
            var info = stat()
            try #require(Darwin.fstatat(parent, component, &info, AT_SYMLINK_NOFOLLOW) == 0)
            let type = info.st_mode & S_IFMT
            var bytes: Data?
            if type == S_IFREG {
                let fd = Darwin.openat(parent, component, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
                try #require(fd >= 0)
                defer { _ = Darwin.close(fd) }
                var opened = stat()
                try #require(Darwin.fstat(fd, &opened) == 0 && opened.st_mode & S_IFMT == S_IFREG
                    && opened.st_ino == info.st_ino && opened.st_dev == info.st_dev)
                var data = Data(), buffer = [UInt8](repeating: 0, count: 4096)
                while true {
                    let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
                    if count < 0 && errno == EINTR { continue }
                    try #require(count >= 0)
                    if count == 0 { break }
                    data.append(contentsOf: buffer.prefix(count))
                }
                bytes = data
            } else if type == S_IFLNK {
                var buffer = [UInt8](repeating: 0, count: Int(PATH_MAX))
                let count = buffer.withUnsafeMutableBytes {
                    Darwin.readlinkat(parent, component, $0.baseAddress!.assumingMemoryBound(to: CChar.self), $0.count)
                }
                try #require(count >= 0); bytes = Data(buffer.prefix(count))
            }
            result[name] = Entry(device: info.st_dev, inode: info.st_ino, mode: info.st_mode,
                uid: info.st_uid, gid: info.st_gid, links: info.st_nlink, flags: info.st_flags, size: info.st_size,
                modifiedSeconds: info.st_mtimespec.tv_sec, modifiedNanos: info.st_mtimespec.tv_nsec,
                changedSeconds: info.st_ctimespec.tv_sec, changedNanos: info.st_ctimespec.tv_nsec, bytes: bytes)
            if type == S_IFDIR {
                let fd = Darwin.openat(parent, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
                try #require(fd >= 0)
                var transferred = false
                defer { if !transferred { _ = Darwin.close(fd) } }
                var opened = stat()
                try #require(Darwin.fstat(fd, &opened) == 0 && opened.st_ino == info.st_ino && opened.st_dev == info.st_dev)
                let openedStream = Darwin.fdopendir(fd)
                let stream = try #require(openedStream); transferred = true
                defer { _ = Darwin.closedir(stream) }
                var children: [String] = []
                while true {
                    errno = 0
                    guard let entry = Darwin.readdir(stream) else { try #require(errno == 0); break }
                    let child = withUnsafePointer(to: &entry.pointee.d_name) {
                        $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) { String(cString: $0) }
                    }
                    if child != "." && child != ".." { children.append(child) }
                }
                for child in children.sorted() { try visit(parent: fd, component: child, name: name + "/" + child) }
            }
        }
        let fd = Darwin.open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        try #require(fd >= 0)
        defer { _ = Darwin.close(fd) }
        try visit(parent: fd, component: ".", name: ".")
        return result
    }
}
#endif

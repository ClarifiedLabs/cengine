#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

// Darwin fork/pre-exec can briefly retain CLOEXEC descriptions from other tests.
// Isolate lock handovers so reopen checks reach persistence validation, not contention.
@Suite @MainActor struct HostStorageIntentsTests {
    @Test func launchBoundaryCannotBeRewrittenOrCancelledAfterAttempt() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        let journal = try f.initialize(); try journal.reconciled(); try journal.planVolumes(f.volumes)
        let token = try journal.plan(f.intent())
        #expect(try journal.intent(token).launchBoundary == .planned)
        #expect(throws: (any Error).self) { _ = try journal.update(token) { $0.launchBoundary = .cancelled } }
        let attempted = try journal.attemptLaunch(token)
        #expect(throws: (any Error).self) { _ = try journal.cancelUnlaunched(attempted) }
        #expect(throws: (any Error).self) { _ = try journal.attemptLaunch(attempted) }
    }
    @Test func historicalMissingLaunchBoundaryIsNotNoLaunchEvidence() async {
        await #expect(processExitsWith: .success) {
            try await HostStorageIntentsTests().checkHistoricalMissingLaunchBoundaryIsNotNoLaunchEvidence()
        }
    }

    private func checkHistoricalMissingLaunchBoundaryIsNotNoLaunchEvidence() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        let id: String
        var state: HostStorageIntents.State
        weak var previousOwner: HostStorageIntents?
        do {
            let journal = try f.initialize(); try journal.reconciled(); try journal.planVolumes(f.volumes)
            let token = try journal.plan(f.intent()); id = token.intent
            previousOwner = journal
            state = try journal.snapshot()
        }
        state.intents[id]?.launchBoundary = nil
        try f.write(state)
        try #require(previousOwner == nil)
        let journal = try f.open()
        #expect(throws: (any Error).self) { _ = try journal.cancelUnlaunched(journal.token(for: id)) }
    }

    @Test(arguments: [false, true])
    func recoveredReplacementHistoryKeepsOldBindingsAndExactWireAcrossReopen(workerOnly: Bool) async {
        await #expect(processExitsWith: .success) { [workerOnly] in
            try await HostStorageIntentsTests().checkRecoveredReplacementHistoryKeepsOldBindingsAndExactWireAcrossReopen(workerOnly: workerOnly)
        }
    }

    private func checkRecoveredReplacementHistoryKeepsOldBindingsAndExactWireAcrossReopen(workerOnly: Bool) throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        var state: HostStorageIntents.State
        let oldID: String, nextID: String, operation: String, bytes: Data
        weak var previousOwner: HostStorageIntents?
        do {
            let journal = try f.initialize()
            previousOwner = journal
            try journal.reconciled(); try journal.planVolumes(f.volumes)
            for var volume in f.volumes {
                volume.rootDevice = 1; volume.rootInode = 100; volume.createdRevision = 2
                try journal.recordVolume(volume)
            }
            let token = try f.drain(journal, token: f.freeze(journal, token: journal.plan(f.intent())))
            let old = try journal.intent(token)
            let successor = try journal.planReplacement(predecessor: token, successor: f.replacement(old))
            let planned = try journal.intent(successor)
            _ = try journal.freezeKeys(successor, role: .prepare, keys: f.offeredKeys(for: planned))
            state = try journal.snapshot(); oldID = old.id; nextID = planned.id; operation = old.replaceOperation
            bytes = try journal.replayRequest(operation: operation).durableBytes()
        }
        try #require(previousOwner == nil)
        let original = try #require(state.intents[oldID])
        // Serialized-public-history vector only: no fixture can manufacture the
        // live ControllerRecovery capability required to authorize this edge.
        var object = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(state)) as? [String: Any])
        var intents = try #require(object["intents"] as? [String: Any])
        var next = try #require(intents[nextID] as? [String: Any])
        next["serviceEpoch"] = HostIntentFixture.id()
        next["controllerEpoch"] = workerOnly ? original.controllerEpoch : original.controllerEpoch + 1
        next["controllerKey"] = workerOnly ? original.controllerKey : String(repeating: "f", count: 64)
        var recovery: [String: Any] = ["serviceEpoch": original.serviceEpoch, "controllerEpoch": original.controllerEpoch,
            "controllerKey": original.controllerKey, "provenanceReference": f.provenance]
        if workerOnly { recovery["workerHistoryReference"] = String(repeating: "e", count: 64) }
        next["replacementRecovery"] = recovery
        intents[nextID] = next; object["intents"] = intents
        let publicHistory = try JSONDecoder().decode(HostStorageIntents.State.self, from: JSONSerialization.data(withJSONObject: object))
        try f.write(publicHistory)
        do {
            let journal = try f.open()
            previousOwner = journal
            #expect(try journal.snapshot().intents[oldID] == original)
            #expect(try journal.replayRequest(operation: operation).durableBytes() == bytes)
        }
        try #require(previousOwner == nil)
        var forged = publicHistory
        forged.intents[nextID]?.replacementRecovery = .init(serviceEpoch: original.serviceEpoch,
            controllerEpoch: original.controllerEpoch, controllerKey: original.controllerKey, provenanceReference: String(repeating: "0", count: 64))
        try f.write(forged)
        #expect(throws: (any Error).self) { _ = try f.open() }
    }

    @Test func decodedDifferentServiceEpochCannotAuthorizeSameControllerReplacement() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        let journal = try f.initialize(); try journal.reconciled(); try journal.planVolumes(f.volumes)
        let token = try f.drain(journal, token: f.freeze(journal, token: journal.plan(f.intent())))
        let old = try journal.intent(token)
        var object = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(f.replacement(old))) as? [String: Any])
        object["serviceEpoch"] = HostIntentFixture.id()
        var successor = try JSONDecoder().decode(HostStorageIntents.Intent.self, from: JSONSerialization.data(withJSONObject: object))
        #expect(throws: (any Error).self) { try journal.planReplacement(predecessor: token, successor: successor) }
        successor.replacementRecovery = .init(serviceEpoch: old.serviceEpoch, controllerEpoch: old.controllerEpoch,
            controllerKey: old.controllerKey, provenanceReference: f.provenance, workerHistoryReference: String(repeating: "e", count: 64))
        #expect(throws: (any Error).self) { try journal.planReplacement(predecessor: token, successor: successor) }
        #expect(try journal.intent(token) == old)
    }

    @Test func localDeletionRequiresNoIntentOrControlHistoryAndSurvivesReopen() async {
        await #expect(processExitsWith: .success) {
            try await HostStorageIntentsTests().checkLocalDeletionRequiresNoIntentOrControlHistoryAndSurvivesReopen()
        }
    }

    private func checkLocalDeletionRequiresNoIntentOrControlHistoryAndSurvivesReopen() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        let volume = f.volumes[0]
        weak var previousOwner: HostStorageIntents?
        do {
            var journal: HostStorageIntents? = try f.initialize()
            previousOwner = journal
            try journal!.reconciled(); try journal!.planVolumes(f.volumes)
            let deleted = try journal!.deleteUncreatedVolume(volume.id)
            #expect(deleted.isDeleted && deleted.createdRevision == nil && deleted.deletedRevision == nil)
            #expect(try journal!.deleteUncreatedVolume(volume.id) == deleted)
            #expect(try journal!.snapshot().operations.isEmpty)
            #expect(!journal!.canDelete(volume: volume.id))
            #expect(throws: (any Error).self) { _ = try journal!.plan(f.intent()) }
            journal = nil // Reopening requires the previous lease owner to be gone.
        }
        try #require(previousOwner == nil)
        let journal = try f.open()
        #expect(try journal.snapshot().volumes[volume.id]?.localDeletionRevision != nil)
        #expect(try journal.deleteUncreatedVolume(volume.id).isDeleted)
    }
    @Test func uncreatedLocalDeletionCannotBypassReconciliationFence() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        let journal = try f.initialize()
        try journal.reconciled(); try journal.planVolumes(f.volumes)
        try journal.retainReconciliationFence(Data("unknown remote authority".utf8))
        #expect(throws: (any Error).self) { _ = try journal.deleteUncreatedVolume(f.volumes[0].id) }
        #expect(try journal.snapshot().volumes[f.volumes[0].id]?.isDeleted == false)
    }

    @Test func uncreatedVolumeWithAnyPlannedIntentOrCreateRequestCannotBeLocallyDeleted() throws {
        for operation in [false, true] {
            let f = try HostIntentFixture(); defer { f.remove() }
            let journal = try f.initialize()
            try journal.reconciled(); try journal.planVolumes(f.volumes)
            let volume = f.volumes[0]
            if operation { try journal.recordOperation(id: volume.createOperation, request: journal.request(for: volume.createOperation)) }
            else { _ = try journal.plan(f.intent()) }
            #expect(throws: (any Error).self) { _ = try journal.deleteUncreatedVolume(volume.id) }
            #expect(try journal.snapshot().volumes[volume.id]?.isDeleted == false)
        }
    }

    @Test func explicitInitializationAndExclusiveLease() async {
        await #expect(processExitsWith: .success) {
            try await HostStorageIntentsTests().checkExplicitInitializationAndExclusiveLease()
        }
    }

    private func checkExplicitInitializationAndExclusiveLease() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        #expect(throws: (any Error).self) { try HostStorageIntents.open(in: f.root, store: f.store, provenanceReference: f.provenance) }
        var journal: HostStorageIntents? = try f.initialize()
        #expect(throws: (any Error).self) { try f.initialize() }
        #expect(throws: (any Error).self) { try f.open() }
        #expect(journal?.canDelete(volume: HostIntentFixture.id()) == false)
        weak var previousOwner = journal
        journal = nil
        try #require(previousOwner == nil)
        let reopened = try f.open()
        #expect(try reopened.snapshot().revision == 1)
        #expect(try reopened.snapshot().reconciliationRequired)
    }
    @Test func missingExistingStateNeverReinitializes() async {
        await #expect(processExitsWith: .success) {
            try await HostStorageIntentsTests().checkMissingExistingStateNeverReinitializes()
        }
    }

    private func checkMissingExistingStateNeverReinitializes() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        var journal: HostStorageIntents? = try f.initialize()
        #expect(try journal?.snapshot().store == f.store)
        weak var previousOwner = journal
        journal = nil
        try #require(previousOwner == nil)
        try FileManager.default.removeItem(at: f.url.appending(path: "managed-storage/state.json"))
        #expect(throws: (any Error).self) { try f.open() }
        #expect(throws: (any Error).self) { try f.initialize() }
    }
    @Test func wholeSetPlanSurvivesLostQuarantinePersistence() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        var fail = false
        var journal: HostStorageIntents? = try f.initialize { boundary in
            if fail, case .beforeMarker = boundary { throw HostStorageIntents.Failure.persistence }
        }
        let j = try #require(journal)
        try j.reconciled(); try j.planVolumes(f.volumes)
        let planned = try j.plan(f.intent())
        fail = true
        #expect(throws: (any Error).self) { try j.quarantine(planned, reason: "lost reserve reply") }
        #expect(!j.canDelete(volume: f.volumes[0].id))
        #expect(throws: (any Error).self) { try j.snapshot() }
        // Direct file evidence: failure before marker cannot erase the prior plan.
        let bytes = try Data(contentsOf: f.url.appending(path: "managed-storage/state.json"))
        #expect(String(decoding: bytes, as: UTF8.self).contains(planned.intent))
        journal = nil
    }
    @Test func postRenameFailureIsPersistentPoison() async {
        await #expect(processExitsWith: .success) {
            try await HostStorageIntentsTests().checkPostRenameFailureIsPersistentPoison()
        }
    }

    private func checkPostRenameFailureIsPersistentPoison() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        var fail = false
        var journal: HostStorageIntents? = try f.initialize { boundary in
            if fail, case .afterState = boundary { throw HostStorageIntents.Failure.persistence }
        }
        try journal!.reconciled(); try journal!.planVolumes(f.volumes)
        let planned = try journal!.plan(f.intent())
        fail = true
        #expect(throws: (any Error).self) { try journal!.quarantine(planned, reason: "ambiguous send") }
        #expect(!journal!.canDelete(volume: f.volumes[0].id))
        weak var previousOwner = journal
        journal = nil
        try #require(previousOwner == nil)
        #expect(throws: (any Error).self) { try f.open() }
        #expect(FileManager.default.fileExists(atPath: f.url.appending(path: "managed-storage/uncertain").path))
    }
    @Test func restartKeepsPlannedPredecessorAndRejectsOverlap() async {
        await #expect(processExitsWith: .success) {
            try await HostStorageIntentsTests().checkRestartKeepsPlannedPredecessorAndRejectsOverlap()
        }
    }

    private func checkRestartKeepsPlannedPredecessorAndRejectsOverlap() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        var journal: HostStorageIntents? = try f.initialize()
        try journal!.reconciled(); try journal!.planVolumes(f.volumes)
        let token = try journal!.plan(f.intent())
        weak var previousOwner = journal
        journal = nil
        try #require(previousOwner == nil)
        let reopened = try f.open()
        #expect(try reopened.snapshot().reconciliationRequired)
        #expect(try reopened.token(for: token.intent) == token)
        try reopened.reconciled()
        #expect(throws: (any Error).self) { try reopened.plan(f.intent()) }
        #expect(!reopened.canDelete(volume: f.volumes[0].id))
        #expect(!reopened.canChangeMode(volume: HostIntentFixture.id()))
    }
    @Test func exactOperationAndStaleLocalVersion() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        let journal = try f.initialize(); try journal.reconciled(); try journal.planVolumes(f.volumes)
        let token = try journal.plan(f.intent())
        let volume = f.volumes[0]
        let request = ManagedStorageControlProtocol.ControlRequest.createVolume(try .init(operation: volume.createOperation, store: f.store, volume: volume.id, name: volume.name))
        try journal.recordOperation(id: volume.createOperation, request: request)
        let revision = try journal.snapshot().revision
        try journal.recordOperation(id: volume.createOperation, request: request)
        #expect(try journal.snapshot().revision == revision)
        #expect(throws: (any Error).self) {
            try journal.recordOperation(id: volume.createOperation, request: .createVolume(try .init(operation: volume.createOperation, store: f.store, volume: volume.id, name: "changed")))
        }
        let changed = try journal.quarantine(token, reason: "cancelled")
        #expect(changed.version == token.version + 1)
        #expect(throws: (any Error).self) { try journal.update(token) { $0.phase = .retired } }
        #expect(try journal.intent(changed).phase == .quarantined)
    }
    @Test func prepareFreezeAtomicallyPersistsWholeAdmissionSetAcrossReopen() async {
        await #expect(processExitsWith: .success) {
            try await HostStorageIntentsTests().checkPrepareFreezeAtomicallyPersistsWholeAdmissionSetAcrossReopen()
        }
    }

    private func checkPrepareFreezeAtomicallyPersistsWholeAdmissionSetAcrossReopen() throws {
        for replacing in [false, true] {
            let f = try HostIntentFixture(); defer { f.remove() }
            var journal: HostStorageIntents? = try f.initialize()
            try journal!.reconciled(); try journal!.planVolumes(f.volumes)
            var token = try journal!.plan(f.intent())
            if replacing {
                let initial = try journal!.intent(token)
                token = try journal!.freezeKeys(token, role: .prepare, keys: f.offeredKeys(for: initial))
                token = try f.drain(journal!, token: token)
                let predecessor = try journal!.intent(token)
                token = try journal!.planReplacement(predecessor: token, successor: f.replacement(predecessor))
            }
            let planned = try journal!.intent(token)
            let before = try journal!.snapshot()
            let predecessor = planned.predecessor.flatMap { before.intents[$0] }
            let keys = f.offeredKeys(for: planned)
            let requests = try f.freezeRequests(for: planned, keys: keys, predecessor: predecessor)
            #expect(requests.count == (replacing ? 2 : 1))
            for operation in requests.keys { #expect(before.operations[operation] == nil) }
            let frozenToken = try journal!.freezeKeys(token, role: .prepare, keys: keys)
            let frozen = try journal!.intent(frozenToken)
            let after = try journal!.snapshot()
            #expect(after.revision == before.revision + 1)
            #expect(frozenToken.version == token.version + 1)
            #expect(frozen.phase == .prepareFrozen)
            #expect(frozen.slots.filter { $0.role == "prepare" }.allSatisfy { $0.key == keys[$0.attachment] })
            #expect(frozen.slots.filter { $0.role == "runtime" }.allSatisfy { $0.key == nil })
            #expect(after.operations.count == before.operations.count + requests.count)
            for (operation, request) in requests {
                let bytes = try request.durableBytes()
                #expect(after.operations[operation] == bytes)
                #expect(after.operationDigests[operation] == HostStorageIntents.hash(bytes))
                #expect(try journal!.replayRequest(operation: operation).durableBytes() == bytes)
                // Coordinator's later recordOperation remains an idempotent no-op.
                try journal!.recordOperation(id: operation, request: request)
            }
            #expect(try journal!.snapshot() == after)
            if let predecessor { #expect(after.intents[predecessor.id] == predecessor) }
            weak var previousOwner = journal
            journal = nil
            try #require(previousOwner == nil)
            let reopened = try f.open()
            #expect(try reopened.intent(frozenToken) == frozen)
            for (operation, request) in requests {
                #expect(try reopened.replayRequest(operation: operation).durableBytes() == request.durableBytes())
            }
            if let predecessor { #expect(try reopened.snapshot().intents[predecessor.id] == predecessor) }
        }
    }
    @Test func prepareFreezePersistenceFaultNeverSeparatesKeysFromAdmissionRequests() async {
        await #expect(processExitsWith: .success) {
            try await HostStorageIntentsTests().checkPrepareFreezePersistenceFaultNeverSeparatesKeysFromAdmissionRequests()
        }
    }

    private func checkPrepareFreezePersistenceFaultNeverSeparatesKeysFromAdmissionRequests() throws {
        for replacing in [false, true] {
            for point in 0..<5 {
                let f = try HostIntentFixture(); defer { f.remove() }
                var fail = false
                var journal: HostStorageIntents? = try f.initialize { boundary in
                    let index: Int
                    switch boundary {
                    case .beforeMarker: index = 0
                    case .afterMarker: index = 1
                    case .afterState: index = 2
                    case .beforeUnmark: index = 3
                    case .afterUnmark: index = 4
                    }
                    if fail && index == point { throw HostStorageIntents.Failure.persistence }
                }
                try journal!.reconciled(); try journal!.planVolumes(f.volumes)
                var token = try journal!.plan(f.intent())
                if replacing {
                    let initial = try journal!.intent(token)
                    token = try journal!.freezeKeys(token, role: .prepare, keys: f.offeredKeys(for: initial))
                    token = try f.drain(journal!, token: token)
                    let predecessor = try journal!.intent(token)
                    token = try journal!.planReplacement(predecessor: token, successor: f.replacement(predecessor))
                }
                let planned = try journal!.intent(token)
                let before = try journal!.snapshot()
                let keys = f.offeredKeys(for: planned)
                let requests = try f.freezeRequests(for: planned, keys: keys,
                    predecessor: planned.predecessor.flatMap { before.intents[$0] })
                fail = true
                #expect(throws: (any Error).self) { try journal!.freezeKeys(token, role: .prepare, keys: keys) }
                #expect(throws: (any Error).self) { try journal!.snapshot() }
                let bytes = try Data(contentsOf: f.url.appending(path: "managed-storage/state.json"))
                let persisted = try JSONDecoder().decode(HostStorageIntents.State.self, from: bytes)
                if point < 2 {
                    #expect(persisted == before)
                } else {
                    #expect(persisted.revision == before.revision + 1)
                    let frozen = try #require(persisted.intents[planned.id])
                    #expect(frozen.phase == .prepareFrozen && frozen.version == token.version + 1)
                    #expect(frozen.slots.filter { $0.role == "prepare" }.allSatisfy { $0.key == keys[$0.attachment] })
                    #expect(persisted.operations.count == before.operations.count + requests.count)
                    for (operation, request) in requests {
                        let expected = try request.durableBytes()
                        #expect(persisted.operations[operation] == expected)
                        #expect(persisted.operationDigests[operation] == HostStorageIntents.hash(expected))
                    }
                    if let predecessor = planned.predecessor {
                        #expect(persisted.intents[predecessor] == before.intents[predecessor])
                    }
                }
                weak var previousOwner = journal
                journal = nil
                try #require(previousOwner == nil)
                if point == 0 {
                    let reopened = try f.open()
                    #expect(try reopened.intent(token) == planned)
                } else {
                    // Returned persistence errors are sticky even after the
                    // commit proof was removed; abrupt exit is tested separately.
                    #expect(throws: (any Error).self) { try f.open() }
                    #expect(FileManager.default.fileExists(atPath: f.url.appending(path: "managed-storage/uncertain").path))
                }
            }
        }
    }
    @Test func drainedAloneCannotCompleteFailedPrepare() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        let journal = try f.initialize(); try journal.reconciled(); try journal.planVolumes(f.volumes)
        let token = try journal.plan(f.intent())
        #expect(throws: (any Error).self) { try journal.update(token) { $0.prepareCompleted = true; $0.phase = .retired } }
        #expect(try journal.intent(token).phase == .planned)
    }
    @Test func tombstonesKeepIdentityButPermitFreshSameNameInstance() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        let journal = try f.initialize(); try journal.reconciled(); try journal.planVolumes(f.volumes)
        var volume = f.volumes[0]
        volume.rootDevice = 1; volume.rootInode = 10; volume.createdRevision = 2; volume.deletedRevision = 3
        try journal.recordVolume(volume)
        let fresh = HostStorageIntents.Volume(id: HostIntentFixture.id(), name: volume.name,
            createOperation: HostIntentFixture.id(), deleteOperation: HostIntentFixture.id())
        try journal.planVolumes([fresh])
        #expect(try journal.snapshot().volumes[volume.id]?.deletedRevision == 3)
        #expect(try journal.snapshot().volumes[fresh.id]?.deletedRevision == nil)
        #expect(!journal.canDelete(volume: volume.id))
        #expect(throws: (any Error).self) { try journal.plan(f.intent([volume])) }
    }
    @Test func saturatedAdmissionPreservesEncodedEvidenceCapacity() async throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        let journal = try f.initialize(); try journal.reconciled()
        var first: HostStorageIntents.Token?
        var reachedCapacity = false
        for index in 0..<64 {
            let volume = HostStorageIntents.Volume(id: HostIntentFixture.id(), name: "capacity-\(index)",
                createOperation: HostIntentFixture.id(), deleteOperation: HostIntentFixture.id())
            do {
                try journal.planVolumes([volume])
                // These are independent commits, not one atomic journal operation.
                await Task.yield()
                let token = try journal.plan(f.intent([volume]))
                if first == nil { first = token }
                await Task.yield()
            } catch HostStorageIntents.Failure.capacity { reachedCapacity = true; break }
        }
        #expect(reachedCapacity)
        let token = try #require(first)
        try journal.retainReconciliationFence(Data(repeating: 1, count: HostStorageIntents.maximumBytes / 4))
        #expect(try journal.snapshot().reconciliationEvidence?.count == HostStorageIntents.maximumBytes / 4)
        _ = try journal.quarantine(token, reason: "maximum evidence must not steal completion capacity")
    }
    @Test func failedReopenReleasesTransferredLease() async {
        await #expect(processExitsWith: .success) {
            try await HostStorageIntentsTests().checkFailedReopenReleasesTransferredLease()
        }
    }

    private func checkFailedReopenReleasesTransferredLease() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        var journal: HostStorageIntents? = try f.initialize()
        try journal!.reconciled()
        weak var previousOwner = journal
        journal = nil
        try #require(previousOwner == nil)
        #expect(throws: (any Error).self) {
            try f.open { boundary in
                if case .beforeMarker = boundary { throw HostStorageIntents.Failure.persistence }
            }
        }
        let reopened = try f.open()
        #expect(try reopened.snapshot().reconciliationRequired)
        #expect(throws: (any Error).self) { try f.open() }
    }
    @Test func leaseExcludesRealSubprocessOwner() async {
        await #expect(processExitsWith: .success) {
            try await HostStorageIntentsTests().checkLeaseExcludesRealSubprocessOwner()
        }
    }

    private func checkLeaseExcludesRealSubprocessOwner() async throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        var journal: HostStorageIntents? = try f.initialize()
        let firstProbe = try await f.pythonLease(hold: false)
        #expect(try await firstProbe.holder.finish().status == 73)
        weak var previousOwner = journal
        journal = nil
        try #require(previousOwner == nil)
        let holder = try await f.pythonLease(hold: true)
        do {
            #expect(holder.ready == Data("locked\n".utf8))
            #expect(throws: (any Error).self) { try f.open() }
            #expect(try await holder.holder.finish().status == 0)
        } catch {
            _ = try? await holder.holder.finish()
            throw error
        }
        journal = try f.open()
        #expect(try journal?.snapshot().store == f.store)
        let lastProbe = try await f.pythonLease(hold: false)
        #expect(try await lastProbe.holder.finish().status == 73)
    }
    @Test(arguments: [false, true])
    func subprocessLeaseJoinsAfterUnlockBeforeCompletion(cancelWhileJoining: Bool) async {
        await #expect(processExitsWith: .success) { [cancelWhileJoining] in
            try await HostStorageIntentsTests().checkSubprocessLeaseJoinsAfterUnlockBeforeCompletion(cancelWhileJoining: cancelWhileJoining)
        }
    }

    private func checkSubprocessLeaseJoinsAfterUnlockBeforeCompletion(cancelWhileJoining: Bool) async throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        var journal: HostStorageIntents? = try f.initialize()
        #expect(try journal?.snapshot().store == f.store)
        weak var previousOwner = journal
        journal = nil
        try #require(previousOwner == nil)
        let holder = try await f.pythonLease(hold: true, gateExit: true)
        #expect(holder.ready == Data("locked\n".utf8))
        let finish = Task { try await holder.holder.finish() }
        do {
            // Positive native event: Python unlocked, but cannot exit until we
            // allow its second stdin byte. The owner's last cancel check is past.
            let joining = try await holder.holder.waitUntilExitGate()
            #expect(joining.unlocked && joining.isRunning)
            journal = try f.open() // Reopening alone does not prove process exit.
            #expect(try journal?.snapshot().store == f.store)
            if cancelWhileJoining { finish.cancel() }
            #expect(holder.holder.finishIsPending)
            holder.holder.allowExit()
            do {
                _ = try await finish.value
                #expect(!cancelWhileJoining)
            } catch is CancellationError {
                #expect(cancelWhileJoining)
            }
            // The cancelled waiter must not overwrite the successful native
            // result. This uncancelled caller can inspect the actual joined child.
            let terminal = try await holder.holder.finish()
            #expect(terminal.status == 0 && terminal.exitedNormally && !terminal.isRunning)
        } catch {
            holder.holder.allowExit()
            _ = try? await finish.value
            _ = try? await holder.holder.finish()
            throw error
        }
    }
    @Test func reconstructionRejectsChangedArgumentsBeforeFirstRecord() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        let journal = try f.initialize(); try journal.reconciled(); try journal.planVolumes(f.volumes)
        let token = try f.freeze(journal, token: journal.plan(f.intent()))
        let intent = try journal.intent(token)
        #expect(throws: (any Error).self) { try journal.replayRequest(operation: intent.reserveOperation) }
        let reserve = try journal.request(for: intent.reserveOperation)
        guard case .reservePrepare(let body) = reserve else { Issue.record("expected reserve"); return }
        #expect(body.attachments.map(\.volume) == f.volumes.map(\.id).sorted())
        #expect(throws: (any Error).self) {
            try journal.recordOperation(id: intent.reserveOperation, request: .reservePrepare(try .init(
                operation: intent.reserveOperation, prepare: intent.prepare, attachments: Array(body.attachments.reversed()))))
        }
        let binding = try #require(body.attachments.first)
        let changed = try ManagedStorageControlProtocol.Binding(store: binding.store, volume: binding.volume,
            attachment: binding.attachment, prepare: binding.prepare, container: binding.container,
            launch: HostIntentFixture.id(), key: binding.key, role: binding.role, mode: binding.mode)
        #expect(throws: (any Error).self) {
            try journal.recordOperation(id: intent.reserveOperation, request: .reservePrepare(try .init(
                operation: intent.reserveOperation, prepare: intent.prepare, attachments: [changed] + Array(body.attachments.dropFirst()))))
        }
        let slot = try #require(intent.slots.first)
        #expect(throws: (any Error).self) {
            try journal.recordOperation(id: slot.registerOperation, request: .registerAttachment(try .init(operation: slot.registerOperation, binding: changed)))
        }
        #expect(throws: (any Error).self) {
            try journal.recordOperation(id: slot.retireOperation, request: .retire(try .init(operation: slot.retireOperation,
                store: f.store, volume: slot.volume, attachment: HostIntentFixture.id(), launch: intent.launch)))
        }
        let volume = f.volumes[0]
        #expect(throws: (any Error).self) {
            try journal.recordOperation(id: volume.createOperation, request: .createVolume(try .init(operation: volume.createOperation,
                store: f.store, volume: volume.id, name: "changed")))
        }
        #expect(throws: (any Error).self) {
            try journal.recordOperation(id: volume.deleteOperation, request: .deleteVolume(try .init(operation: volume.deleteOperation,
                store: f.store, volume: HostIntentFixture.id())))
        }
        #expect(try journal.snapshot().operations.isEmpty)
        try journal.recordOperation(id: intent.reserveOperation, request: reserve)
    }
    @Test func allTypedRequestsReplayAfterReopen() async {
        await #expect(processExitsWith: .success) {
            try await HostStorageIntentsTests().checkAllTypedRequestsReplayAfterReopen()
        }
    }

    private func checkAllTypedRequestsReplayAfterReopen() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        var journal: HostStorageIntents? = try f.initialize()
        try journal!.reconciled(); try journal!.planVolumes(f.volumes)
        var token = try journal!.plan(f.intent())
        token = try f.freeze(journal!, token: token, runtime: true)
        let frozen = try journal!.intent(token)
        #expect(throws: (any Error).self) { try journal!.request(for: frozen.completeOperation) }
        token = try f.drain(journal!, token: token, runtime: true)
        #expect(throws: (any Error).self) { try journal!.request(for: frozen.completeOperation) }
        token = try journal!.update(token) {
            $0.guestCompletion = .init(prepare: $0.prepare, containerInstance: $0.containerInstance, launch: $0.launch,
                succeeded: true, cleanCopyUp: true, evidenceDigest: String(repeating: "e", count: 64))
        }
        #expect(throws: (any Error).self) { try journal!.request(for: frozen.completeOperation) }
        token = try journal!.update(token) { $0.cleanUnmount = true }
        let intent = try journal!.intent(token)
        let operations = f.volumes.flatMap { [$0.createOperation, $0.deleteOperation] }
            + [intent.reserveOperation, intent.completeOperation]
            + intent.slots.flatMap { [$0.registerOperation, $0.retireOperation] }
        var bytes: [String: Data] = [:]
        for operation in operations {
            let request = try journal!.request(for: operation)
            bytes[operation] = try request.durableBytes()
            try journal!.recordOperation(id: operation, request: request)
        }
        guard case .completePrepare(let complete) = try journal!.request(for: intent.completeOperation) else {
            Issue.record("expected completion"); return
        }
        #expect(complete.receipts.map(\.attachment) == complete.receipts.map(\.attachment).sorted())
        #expect(throws: (any Error).self) {
            try journal!.recordOperation(id: intent.completeOperation, request: .completePrepare(try .init(
                operation: intent.completeOperation, prepare: intent.prepare, receipts: complete.receipts,
                attestation: .init(prepare: intent.prepare, succeeded: false, cleanCopyUp: true))))
        }
        _ = try journal!.update(token) { $0.prepareCompleted = true; $0.phase = .retired }
        weak var previousOwner = journal
        journal = nil
        try #require(previousOwner == nil)
        let reopened = try f.open()
        for operation in operations {
            #expect(try reopened.replayRequest(operation: operation).durableBytes() == bytes[operation])
        }
    }
    @Test func loadRejectsRehashedOperationWithChangedBinding() async {
        await #expect(processExitsWith: .success) {
            try await HostStorageIntentsTests().checkLoadRejectsRehashedOperationWithChangedBinding()
        }
    }

    private func checkLoadRejectsRehashedOperationWithChangedBinding() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        var journal: HostStorageIntents? = try f.initialize()
        try journal!.reconciled(); try journal!.planVolumes(f.volumes)
        let volume = f.volumes[0]
        try journal!.recordOperation(id: volume.createOperation, request: journal!.request(for: volume.createOperation))
        var state = try journal!.snapshot()
        weak var previousOwner = journal
        journal = nil
        try #require(previousOwner == nil)
        let changed = try ManagedStorageControlProtocol.ControlRequest.createVolume(.init(operation: volume.createOperation,
            store: f.store, volume: volume.id, name: "forged")).durableBytes()
        state.operations[volume.createOperation] = changed
        state.operationDigests[volume.createOperation] = HostStorageIntents.hash(changed)
        try f.write(state)
        #expect(throws: (any Error).self) { try f.open() }
    }
    @Test func replacementIsAtomicLinkedWholeSetAndExactlyReplayable() async {
        await #expect(processExitsWith: .success) {
            try await HostStorageIntentsTests().checkReplacementIsAtomicLinkedWholeSetAndExactlyReplayable()
        }
    }

    private func checkReplacementIsAtomicLinkedWholeSetAndExactlyReplayable() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        var journal: HostStorageIntents? = try f.initialize()
        try journal!.reconciled(); try journal!.planVolumes(f.volumes)
        for var volume in f.volumes {
            volume.rootDevice = 1; volume.rootInode = 10; volume.createdRevision = 2
            try journal!.recordVolume(volume)
        }
        var oldToken = try f.drain(journal!, token: f.freeze(journal!, token: journal!.plan(f.intent())))
        let old = try journal!.intent(oldToken)
        let nextToken = try journal!.planReplacement(predecessor: oldToken, successor: f.replacement(old))
        #expect(throws: (any Error).self) { try journal!.intent(oldToken) }
        oldToken = try journal!.token(for: old.id)
        #expect(oldToken.version == old.version + 1)
        #expect(try journal!.intent(oldToken).successor == nextToken.intent)
        #expect(try journal!.intent(nextToken).predecessor == old.id)
        #expect(throws: (any Error).self) { try journal!.update(oldToken) { $0.successor = nil } }
        #expect(throws: (any Error).self) { try journal!.update(nextToken) { $0.predecessor = nil } }
        #expect(throws: (any Error).self) { try journal!.update(oldToken) { $0.phase = .replaced } }
        #expect(throws: (any Error).self) { try journal!.request(for: old.replaceOperation) }
        #expect(throws: (any Error).self) { try journal!.planReplacement(predecessor: oldToken, successor: f.replacement(old)) }
        var successor = try f.freeze(journal!, token: nextToken)
        let next = try journal!.intent(successor)
        let replace = try journal!.request(for: old.replaceOperation)
        guard case .replacePrepare(let body) = replace else { Issue.record("expected replace"); return }
        #expect(body.receipts.map(\.attachment) == old.slots.filter { $0.role == "prepare" }.map(\.attachment).sorted())
        #expect(body.successor.attachments.map(\.volume) == f.volumes.map(\.id).sorted())
        #expect(throws: (any Error).self) {
            try journal!.recordOperation(id: old.replaceOperation, request: .replacePrepare(try .init(operation: old.replaceOperation,
                prepare: old.prepare, receipts: Array(body.receipts.dropLast()), successor: body.successor)))
        }
        try journal!.recordOperation(id: old.replaceOperation, request: replace)
        #expect(throws: (any Error).self) { try journal!.confirmReplacement(predecessor: oldToken, successor: successor) }
        try journal!.recordOperation(id: next.reserveOperation, request: journal!.request(for: next.reserveOperation))
        oldToken = try journal!.confirmReplacement(predecessor: oldToken, successor: successor)
        #expect(try journal!.intent(oldToken).phase == .replaced)
        #expect(try journal!.intent(oldToken).prepareCompleted == false)
        #expect(try journal!.intent(successor).phase == .prepareFrozen)
        #expect(throws: (any Error).self) { try journal!.update(oldToken) { $0.phase = .quarantined } }
        #expect(throws: (any Error).self) { try journal!.plan(f.intent()) }
        for volume in f.volumes { #expect(!journal!.canDelete(volume: volume.id)) }
        let bytes = try replace.durableBytes()
        weak var previousOwner = journal
        journal = nil
        try #require(previousOwner == nil)
        journal = try f.open()
        #expect(try journal!.replayRequest(operation: old.replaceOperation).durableBytes() == bytes)
        try journal!.reconciled()
        successor = try f.drain(journal!, token: successor)
        _ = try journal!.update(successor) {
            $0.guestCompletion = .init(prepare: $0.prepare, containerInstance: $0.containerInstance, launch: $0.launch,
                succeeded: true, cleanCopyUp: true, evidenceDigest: String(repeating: "e", count: 64))
            $0.cleanUnmount = true; $0.prepareCompleted = true; $0.phase = .retired
        }
        for volume in f.volumes { #expect(journal!.canDelete(volume: volume.id)) }
        _ = try journal!.plan(f.intent())
    }
    @Test func replacementRejectsChangedContextPartialSetAndNonfreshSuccessor() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        let journal = try f.initialize(); try journal.reconciled(); try journal.planVolumes(f.volumes)
        var token = try journal.plan(f.intent())
        var old = try journal.intent(token)
        #expect(throws: (any Error).self) { try journal.planReplacement(predecessor: token, successor: f.replacement(old)) }
        token = try f.freeze(journal, token: token)
        #expect(throws: (any Error).self) { try journal.planReplacement(predecessor: token, successor: f.replacement(old)) }
        token = try f.drain(journal, token: token)
        old = try journal.intent(token)
        let baseline = try journal.snapshot()
        let invalid = [f.replacement(old, serviceEpoch: HostIntentFixture.id()),
            f.replacement(old, controllerEpoch: 2), f.replacement(old, controllerKey: String(repeating: "e", count: 64)),
            f.replacement(old, specificationDigest: String(repeating: "f", count: 64)),
            f.replacement(old, selected: [f.volumes[0]]), f.replacement(old, launch: old.launch),
            f.replacement(old, changedMount: true)]
        for next in invalid {
            #expect(throws: (any Error).self) { try journal.planReplacement(predecessor: token, successor: next) }
            #expect(try journal.snapshot() == baseline)
        }
        var changedMode = f.replacement(old)
        let prepareIndex = try #require(changedMode.slots.firstIndex { $0.role == "prepare" })
        let prepare = changedMode.slots[prepareIndex]
        changedMode.slots[prepareIndex] = .init(volume: prepare.volume, attachment: prepare.attachment,
            role: prepare.role, mode: "read-only", registerOperation: prepare.registerOperation, retireOperation: prepare.retireOperation)
        #expect(throws: (any Error).self) { try journal.planReplacement(predecessor: token, successor: changedMode) }
        var duplicateRuntime = f.replacement(old)
        let runtimeSlot = try #require(duplicateRuntime.slots.first { $0.role == "runtime" })
        duplicateRuntime.slots.append(.init(volume: runtimeSlot.volume, attachment: HostIntentFixture.id(),
            role: runtimeSlot.role, mode: runtimeSlot.mode, registerOperation: HostIntentFixture.id(), retireOperation: HostIntentFixture.id()))
        #expect(throws: (any Error).self) { try journal.planReplacement(predecessor: token, successor: duplicateRuntime) }
        #expect(try journal.snapshot() == baseline)
        var next = f.replacement(old); next.version = 2
        #expect(throws: (any Error).self) { try journal.planReplacement(predecessor: token, successor: next) }
        next = f.replacement(old); next.slots[0].key = String(repeating: "e", count: 64)
        #expect(throws: (any Error).self) { try journal.planReplacement(predecessor: token, successor: next) }
        next = f.replacement(old); next.predecessor = old.id
        #expect(throws: (any Error).self) { try journal.plan(next) }
        let runtime = try #require(old.slots.firstIndex { $0.role == "runtime" })
        token = try journal.update(token) { $0.slots[runtime].key = String(repeating: "e", count: 64) }
        #expect(throws: (any Error).self) { try journal.planReplacement(predecessor: token, successor: f.replacement(old)) }
    }
    @Test func replacementSkipsOnlyItsOwnUnresolvedFence() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        let journal = try f.initialize(); try journal.reconciled(); try journal.planVolumes(f.volumes)
        var other = try f.drain(journal, token: f.freeze(journal, token: journal.plan(f.intent())))
        other = try journal.update(other) {
            $0.guestCompletion = .init(prepare: $0.prepare, containerInstance: $0.containerInstance, launch: $0.launch,
                succeeded: true, cleanCopyUp: true, evidenceDigest: String(repeating: "e", count: 64))
            $0.cleanUnmount = true; $0.prepareCompleted = true; $0.phase = .running
        }
        let completed = try journal.intent(other)
        #expect(throws: (any Error).self) { try journal.planReplacement(predecessor: other, successor: f.replacement(completed)) }
        let token = try f.drain(journal, token: f.freeze(journal, token: journal.plan(f.intent())))
        let old = try journal.intent(token)
        _ = try journal.quarantine(other, reason: "independent unresolved runtime")
        let baseline = try journal.snapshot()
        #expect(throws: (any Error).self) { try journal.planReplacement(predecessor: token, successor: f.replacement(old)) }
        #expect(try journal.snapshot() == baseline)
    }
    @Test func absentOptionalLinksRetainCanonicalCodec() async {
        await #expect(processExitsWith: .success) {
            try await HostStorageIntentsTests().checkAbsentOptionalLinksRetainCanonicalCodec()
        }
    }

    private func checkAbsentOptionalLinksRetainCanonicalCodec() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        var journal: HostStorageIntents? = try f.initialize()
        try journal!.reconciled(); try journal!.planVolumes(f.volumes)
        let token = try journal!.plan(f.intent())
        let bytes = try Data(contentsOf: f.url.appending(path: "managed-storage/state.json"))
        #expect(!String(decoding: bytes, as: UTF8.self).contains("\"predecessor\""))
        #expect(!String(decoding: bytes, as: UTF8.self).contains("\"successor\""))
        weak var previousOwner = journal
        journal = nil
        try #require(previousOwner == nil)
        let reopened = try f.open()
        #expect(try reopened.intent(token).predecessor == nil)
        #expect(try reopened.intent(token).successor == nil)
    }
    @Test func loadRejectsBrokenReplacementLinksAndReceipts() async {
        await #expect(processExitsWith: .success) {
            try await HostStorageIntentsTests().checkLoadRejectsBrokenReplacementLinksAndReceipts()
        }
    }

    private func checkLoadRejectsBrokenReplacementLinksAndReceipts() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        var journal: HostStorageIntents? = try f.initialize()
        try journal!.reconciled(); try journal!.planVolumes(f.volumes)
        let token = try f.drain(journal!, token: f.freeze(journal!, token: journal!.plan(f.intent())))
        let old = try journal!.intent(token)
        let next = try journal!.planReplacement(predecessor: token, successor: f.replacement(old))
        let valid = try journal!.snapshot()
        weak var previousOwner = journal
        journal = nil
        try #require(previousOwner == nil)
        var broken = valid; broken.intents[next.intent]?.predecessor = nil
        try f.write(broken)
        #expect(throws: (any Error).self) { try f.open() }
        broken = valid; broken.intents[old.id]?.slots[0].receipt = nil
        try f.write(broken)
        #expect(throws: (any Error).self) { try f.open() }
        try f.write(valid)
        let reopened = try f.open()
        #expect(try reopened.intent(next).predecessor == old.id)
    }
    @Test func changedBindingAndUnknownVolumesAreRejected() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        let journal = try f.initialize(); try journal.reconciled(); try journal.planVolumes(f.volumes)
        let token = try journal.plan(f.intent())
        let changed = try journal.update(token) { $0.slots[0].key = String(repeating: "a", count: 64) }
        #expect(throws: (any Error).self) { try journal.update(changed) { $0.slots[0].key = String(repeating: "b", count: 64) } }
        #expect(!journal.canDelete(volume: HostIntentFixture.id()))
    }
}

@MainActor struct HostIntentFixture {
    let url: URL
    let root: PersistentStateDirectory
    let store = id()
    let provenance = String(repeating: "a", count: 64)
    let volumes: [HostStorageIntents.Volume]
    static func id() -> String { UUID().uuidString.lowercased() }
    init() throws {
        url = FileManager.default.temporaryDirectory.appending(path: "cengine-host-intents-\(Self.id())")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        root = try PersistentStateDirectory.open(url)
        volumes = (0..<2).map { .init(id: Self.id(), name: "volume-\($0)", createOperation: Self.id(), deleteOperation: Self.id()) }
    }
    func initialize(hook: HostStorageIntents.Hook? = nil) throws -> HostStorageIntents {
        try .initialize(in: root, store: store, provenanceReference: provenance, hook: hook)
    }
    func open(hook: HostStorageIntents.Hook? = nil) throws -> HostStorageIntents {
        try .open(in: root, store: store, provenanceReference: provenance, hook: hook)
    }
    func write(_ state: HostStorageIntents.State) throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let directory = try #require(try root.openDirectoryIfPresent(named: "managed-storage"))
        try directory.replaceRegularFile(named: "state.json", data: encoder.encode(state))
    }
    func offeredKeys(for intent: HostStorageIntents.Intent) -> [String: String] {
        Dictionary(uniqueKeysWithValues: intent.slots.filter { $0.role == "prepare" }.map {
            ($0.attachment, HostStorageIntents.hash(Data($0.attachment.utf8)))
        })
    }
    func freezeRequests(for intent: HostStorageIntents.Intent, keys: [String: String],
                        predecessor: HostStorageIntents.Intent? = nil) throws -> [String: ManagedStorageControlProtocol.ControlRequest] {
        let bindings = try intent.slots.filter { $0.role == "prepare" }.sorted { $0.volume < $1.volume }.map { slot in
            var frozen = slot; frozen.key = keys[slot.attachment]
            return try frozen.binding(store: intent.store, prepare: intent.prepare, container: intent.container, launch: intent.launch)
        }
        let reserve = try ManagedStorageControlProtocol.ReserveRequest(operation: intent.reserveOperation,
            prepare: intent.prepare, attachments: bindings)
        var requests: [String: ManagedStorageControlProtocol.ControlRequest] = [intent.reserveOperation: .reservePrepare(reserve)]
        if let predecessor {
            let receipts = try predecessor.slots.filter { $0.role == "prepare" }.sorted { $0.attachment < $1.attachment }.map {
                try #require($0.receipt).wire()
            }
            requests[predecessor.replaceOperation] = .replacePrepare(try .init(operation: predecessor.replaceOperation,
                prepare: predecessor.prepare, receipts: receipts, successor: reserve))
        }
        return requests
    }
    /// Legacy fixture path intentionally omits admission operations.
    func freeze(_ journal: HostStorageIntents, token: HostStorageIntents.Token, runtime: Bool = false) throws -> HostStorageIntents.Token {
        try journal.update(token) { intent in
            for index in intent.slots.indices where runtime || intent.slots[index].role == "prepare" {
                intent.slots[index].key = HostStorageIntents.hash(Data(Self.id().utf8))
            }
            intent.phase = .prepareFrozen
        }
    }
    func drain(_ journal: HostStorageIntents, token: HostStorageIntents.Token, runtime: Bool = false) throws -> HostStorageIntents.Token {
        try journal.update(token) { intent in
            for index in intent.slots.indices where runtime || intent.slots[index].role == "prepare" {
                let slot = intent.slots[index]
                intent.slots[index].receipt = .init(try .init(schema: 3, store: intent.store, volume: slot.volume,
                    attachment: slot.attachment, prepare: slot.role == "prepare" ? intent.prepare : nil,
                    launch: intent.launch, revision: UInt64(index + 2)))
            }
            intent.phase = .prepareDrained
        }
    }
    func replacement(_ old: HostStorageIntents.Intent, serviceEpoch: String? = nil, controllerEpoch: UInt64? = nil,
                     controllerKey: String? = nil, specificationDigest: String? = nil,
                     selected: [HostStorageIntents.Volume]? = nil, launch: String? = nil,
                     changedMount: Bool = false) -> HostStorageIntents.Intent {
        let fresh = intent(selected)
        var mounts = fresh.mounts
        if changedMount, let first = mounts.first {
            mounts[0] = .init(volume: first.volume, destination: "/changed", subpath: first.subpath, mode: first.mode)
        }
        return .init(id: fresh.id, store: old.store, container: old.container, containerInstance: old.containerInstance,
            launch: launch ?? fresh.launch, specificationDigest: specificationDigest ?? old.specificationDigest,
            serviceEpoch: serviceEpoch ?? old.serviceEpoch, controllerEpoch: controllerEpoch ?? old.controllerEpoch,
            controllerKey: controllerKey ?? old.controllerKey, prepare: fresh.prepare, reserveOperation: fresh.reserveOperation,
            completeOperation: fresh.completeOperation, replaceOperation: fresh.replaceOperation, mounts: mounts, slots: fresh.slots,
            version: 1, phase: .planned, prepareCompleted: false, cleanUnmount: false)
    }
    fileprivate func pythonLease(hold: Bool, gateExit: Bool = false) async throws -> (holder: HostIntentLeaseProcess, ready: Data) {
        let holder = HostIntentLeaseProcess()
        let ready = try await holder.start(path: url.appending(path: "managed-storage/lease").path, hold: hold, gateExit: gateExit)
        return (holder, ready)
    }
    func remove() { try? FileManager.default.removeItem(at: url) }
    func intent(_ selected: [HostStorageIntents.Volume]? = nil) -> HostStorageIntents.Intent {
        let volumes = selected ?? self.volumes
        let slots: [HostStorageIntents.Slot] = volumes.flatMap { volume in
            ["prepare", "runtime"].map { role in
                .init(volume: volume.id, attachment: Self.id(), role: role, mode: "read-write", registerOperation: Self.id(), retireOperation: Self.id())
            }
        }
        return .init(id: Self.id(), store: store, container: String(repeating: "b", count: 64),
            containerInstance: Self.id(), launch: Self.id(), specificationDigest: String(repeating: "c", count: 64),
            serviceEpoch: Self.id(), controllerEpoch: 1, controllerKey: String(repeating: "d", count: 64),
            prepare: Self.id(), reserveOperation: Self.id(), completeOperation: Self.id(), replaceOperation: Self.id(),
            mounts: volumes.map { .init(volume: $0.id, destination: "/\($0.name)", subpath: "", mode: "read-write") },
            slots: slots, version: 1, phase: .planned, prepareCompleted: false, cleanUnmount: false)
    }
}

/// Only native threads touch Process and its pipes; the gated writer is joined
/// before ownership returns to the process owner. The condition protects shared
/// state and continuations; no Testing macros run off-task.
private final class HostIntentLeaseProcess: @unchecked Sendable {
    struct Terminal: Sendable {
        let status: Int32
        let exitedNormally: Bool
        let isRunning: Bool
    }
    struct ExitGateObservation: Sendable {
        let unlocked: Bool
        let isRunning: Bool
    }
    private let condition = NSCondition()
    private var releaseRequested = false
    private var cancelled = false
    private var result: Result<Terminal, any Error>?
    private var waiters: [CheckedContinuation<Terminal, any Error>] = []
    private var exitGate: Result<ExitGateObservation, any Error>?
    private var exitGateWaiters: [CheckedContinuation<ExitGateObservation, any Error>] = []
    private var exitAllowed = false
    private var exitGateInput: FileHandle?
    private var exitWriterFinished = false
    private var exitWriterError: (any Error)?

    func start(path: String, hold: Bool, gateExit: Bool = false) async throws -> Data {
        try await withTaskCancellationHandler {
            let ready: Data = try await withCheckedThrowingContinuation { continuation in
                Thread.detachNewThread { self.run(path: path, hold: hold, gateExit: gateExit, ready: continuation) }
            }
            do { try Task.checkCancellation() }
            catch {
                _ = try? await finish()
                throw error
            }
            return ready
        } onCancel: { self.cancel() }
    }

    func finish() async throws -> Terminal {
        let terminal: Terminal = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                condition.lock()
                releaseRequested = true
                let completed = result
                if completed == nil { waiters.append(continuation) }
                condition.broadcast()
                condition.unlock()
                if let completed { continuation.resume(with: completed) }
            }
        } onCancel: { self.cancel() }
        // Preserve native errors; only a successfully joined result is followed
        // by the individual caller's cancellation check.
        try Task.checkCancellation()
        return terminal
    }

    var finishIsPending: Bool {
        condition.lock(); defer { condition.unlock() }
        return result == nil && !waiters.isEmpty
    }

    func waitUntilExitGate() async throws -> ExitGateObservation {
        try await withCheckedThrowingContinuation { continuation in
            condition.lock()
            let observed = exitGate
            if observed == nil { exitGateWaiters.append(continuation) }
            condition.unlock()
            if let observed { continuation.resume(with: observed) }
        }
    }

    func allowExit() {
        condition.lock()
        exitAllowed = true
        condition.broadcast()
        condition.unlock()
    }

    private func publishExitGate(_ observation: Result<ExitGateObservation, any Error>) {
        condition.lock()
        guard exitGate == nil else { condition.unlock(); return }
        exitGate = observation
        let waiters = exitGateWaiters
        exitGateWaiters.removeAll()
        condition.unlock()
        for waiter in waiters { waiter.resume(with: observation) }
    }

    // Stdin ownership is handed from the native process owner to this native
    // writer, then joined back before final FD cleanup. No actor performs I/O.
    private func writeExitGate() {
        condition.lock()
        while !exitAllowed { condition.wait() }
        let input = exitGateInput!
        condition.unlock()
        var error: (any Error)?
        do { try input.write(contentsOf: Data([0x78])) }
        catch let failure { error = failure }
        try? input.close()
        condition.lock()
        exitGateInput = nil
        exitWriterError = error
        exitWriterFinished = true
        condition.broadcast()
        condition.unlock()
    }

    private func joinExitWriter() throws {
        condition.lock()
        while !exitWriterFinished { condition.wait() }
        let error = exitWriterError
        condition.unlock()
        if let error { throw error }
    }

    private func cancel() {
        condition.lock()
        cancelled = true
        condition.broadcast()
        condition.unlock()
    }

    private func checkCancellation() throws {
        condition.lock()
        let cancelled = self.cancelled
        condition.unlock()
        if cancelled { throw CancellationError() }
    }

    private func readReady(_ handle: FileHandle, byteCount: Int = 7) throws -> Data {
        var bytes = Data()
        while bytes.count < byteCount {
            try checkCancellation()
            var descriptor = pollfd(fd: handle.fileDescriptor, events: Int16(POLLIN), revents: 0)
            // Polling only wakes cancellation; it is not a readiness watchdog.
            let polled = Darwin.poll(&descriptor, 1, 50)
            if polled < 0 {
                if errno == EINTR { continue }
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            if polled == 0 { continue }
            var buffer = [UInt8](repeating: 0, count: byteCount - bytes.count)
            let count = buffer.withUnsafeMutableBytes { Darwin.read(handle.fileDescriptor, $0.baseAddress, $0.count) }
            if count < 0 {
                if errno == EINTR { continue }
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            if count == 0 { break }
            bytes.append(contentsOf: buffer.prefix(count))
        }
        return bytes
    }

    private func run(path: String, hold: Bool, gateExit: Bool, ready: CheckedContinuation<Data, any Error>) {
        let process = Process(), output = Pipe(), input = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = ["-c", """
        import fcntl, os, sys
        fd = os.open(sys.argv[1], os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            sys.exit(73)
        if sys.argv[2] == 'hold':
            print('locked', flush=True)
            sys.stdin.buffer.read(1)
        os.close(fd)
        if sys.argv[3] == 'gate':
            os.write(1, b'U')
            if sys.stdin.buffer.read(1) != b'x':
                sys.exit(74)
        """, path, hold ? "hold" : "probe", gateExit ? "gate" : "exit"]
        process.standardOutput = output; process.standardInput = input
        var launched = false
        var reportedReady = false
        var exitWriterStarted = false
        let completed: Result<Terminal, any Error>
        do {
            try checkCancellation()
            if gateExit {
                let noSignal = Darwin.fcntl(input.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1)
                if noSignal < 0 { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            }
            // Process uses posix_spawn; never fork the multithreaded test process.
            try process.run()
            launched = true
            // Foundation may already close its copies of the child-side ends.
            try? output.fileHandleForWriting.close()
            try? input.fileHandleForReading.close()
            let bytes = hold ? try readReady(output.fileHandleForReading) : Data()
            try checkCancellation()
            ready.resume(returning: bytes)
            reportedReady = true
            if hold {
                condition.lock()
                while !releaseRequested && !cancelled { condition.wait() }
                condition.unlock()
                try checkCancellation()
            }
            if gateExit {
                try input.fileHandleForWriting.write(contentsOf: Data([0x72]))
                let unlocked = try readReady(output.fileHandleForReading, byteCount: 1)
                condition.lock()
                exitGateInput = input.fileHandleForWriting
                condition.unlock()
                exitWriterStarted = true
                Thread.detachNewThread { self.writeExitGate() }
                publishExitGate(.success(.init(unlocked: unlocked == Data([0x55]), isRunning: process.isRunning)))
            } else {
                try input.fileHandleForWriting.close()
            }
            process.waitUntilExit()
            if exitWriterStarted { try joinExitWriter() }
            completed = .success(.init(status: process.terminationStatus,
                exitedNormally: process.terminationReason == .exit, isRunning: process.isRunning))
        } catch {
            if exitWriterStarted {
                allowExit()
                try? joinExitWriter()
            }
            if launched {
                // The fixed script only waits on stdin. EOF releases it without
                // signalling a PID that Foundation may already have reaped.
                try? input.fileHandleForWriting.close()
                process.waitUntilExit()
            }
            completed = .failure(error)
        }
        // Reap the child before final FD cleanup and before any join resumes.
        try? input.fileHandleForWriting.close()
        try? input.fileHandleForReading.close()
        try? output.fileHandleForReading.close()
        try? output.fileHandleForWriting.close()
        condition.lock()
        result = completed
        let waiters = self.waiters
        self.waiters.removeAll()
        condition.unlock()
        for waiter in waiters { waiter.resume(with: completed) }
        if case .failure(let error) = completed { publishExitGate(.failure(error)) }
        if !reportedReady {
            // Startup errors, including cancellation, return only after cleanup.
            if case .failure(let error) = completed { ready.resume(throwing: error) }
        }
    }
}
#endif

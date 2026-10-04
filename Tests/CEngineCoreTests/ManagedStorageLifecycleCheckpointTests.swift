#if os(macOS)
import CEngineCore
import CryptoKit
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

/// Metadata/unit coverage only: does not authenticate a native child, qualify
/// power-loss durability, prove a drain or activate fresh production storage.
@Suite(.serialized) @MainActor struct ManagedStorageLifecycleCheckpointTests {
    typealias Owner = ManagedStorageLifecycleCheckpoint
    typealias Wire = StorageLifecycleProtocol

    @Test func diagnosticDeviceRenumberingReopensWithoutChangingBindingOrState() throws {
        let disk = try Disk(); defer { disk.remove() }
        let f = try Fixture(binding: disk.binding)
        var owner: Owner? = try disk.fresh(f)
        let state = try owner!.snapshot()
        #expect(state.version == Wire.version)
        owner = nil
        let url = disk.url.appending(path: "managed-storage-owner/manifest.json")
        var fields = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        #expect(fields["version"] as? String == Owner.manifestVersion)
        for name in ["root", "directory", "lease", "backing"] {
            var identity = try #require(fields[name] as? [String: Any])
            identity["device"] = (identity["device"] as! NSNumber).uint64Value ^ 1
            fields[name] = identity
        }
        let changed = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes])
        try changed.write(to: url)
        let manifest = try Owner.inspect(in: disk.root, backingDescriptor: disk.backing)
        #expect(manifest.identity == f.identity)
        #expect(manifest.identity == (try Wire.Identity(binding: disk.binding, generation: 1)))
        #expect(manifest.root.device != disk.root.identity.device)
        owner = try disk.open(f)
        #expect(try owner!.snapshot() == state)
        #expect(try Data(contentsOf: url) == changed)
    }

    @Test(arguments: ["storage-lifecycle.v2", "storage-host-owner.v2"])
    func oldOwnerManifestRefusalPreservesBytes(version: String) throws {
        let disk = try Disk(); defer { disk.remove() }
        let f = try Fixture(binding: disk.binding)
        var owner: Owner? = try disk.fresh(f)
        _ = try owner!.snapshot()
        owner = nil
        let directory = try disk.root.openDirectory(named: Owner.directoryName)
        let url = disk.url.appending(path: "managed-storage-owner/manifest.json")
        var fields = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        fields["version"] = version
        let old = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes])
        try old.write(to: url)
        let names = try directory.entryNames()
        let stateURL = disk.url.appending(path: "managed-storage-owner/state.json")
        let state = try Data(contentsOf: stateURL)
        #expect(throws: (any Error).self) { try Owner.inspect(in: disk.root, backingDescriptor: disk.backing) }
        #expect(throws: (any Error).self) { try disk.open(f) }
        #expect(try Data(contentsOf: url) == old)
        #expect(try Data(contentsOf: stateURL) == state)
        #expect(try directory.entryNames() == names)
    }

    @Test(arguments: [false, true], [0, 1, 2, 3])
    func handoffFoldsOnlyActualOutcomeAndRetainsIntentHistory(applied: Bool, variant: Int) throws {
        let lostIssue = variant & 1 != 0, replaced = variant & 2 != 0
        let f = try Fixture()
        var state = try f.completed(), intents = f.intents()
        state = try Owner.applying(.recordService(f.service(state)), to: state, intents: intents)
        if replaced {
            let pending = try f.pendingService(state)
            state = try Owner.applying(.stageService(pending), to: state, intents: intents)
            let signed = try Wire.SignedServiceChange(request: pending.request,
                signature: f.root.signature(for: pending.request.signingBytes))
            let configuration = StorageLifecycleServiceBootProtocol.Configuration(action: .open,
                rootPublicKey: state.rootPublicKey, signed: state.current!.original.signed,
                nowUnixSeconds: pending.nowUnixSeconds, lifetimeSeconds: pending.lifetimeSeconds, reopen: signed)
            state = try Owner.applying(.authorizeServiceReplacement(.init(
                predecessorWorkerUUID: pending.predecessorWorkerUUID, configuration: configuration)), to: state, intents: intents)
            state = try Owner.applying(.attemptNativeReplacement, to: state, intents: intents)
            state = try Owner.applying(.confirmService(f.confirmation(pending, state: state)), to: state, intents: intents)
        }
        let before = state, service = state.currentService!, old = state.currentContext!
        let intent = f.intent(old); intents.intents[intent.id] = intent
        let pending = try f.grant(.takeover, epoch: 1, serial: 2, service: old.serviceEpoch)
        if lostIssue {
            state = try Owner.applying(.stageTakeoverRequest(.init(requestID: pending.requestID,
                grantID: pending.signed.grant.id, recipient: pending.recipient, expectedEpoch: 1, serviceEpoch: old.serviceEpoch)),
                to: state, intents: intents)
        } else { state = try Owner.applying(.stage(pending), to: state, intents: intents) }
        #expect(try Owner.replacementRecoveryRequest(state) == nil)
        let retry = Owner.HandoffRetry(operationID: id(), statusRequestID: id(), recoveryRequestID: id(),
            predecessor: service, pending: pending.signed.grant)
        state = try Owner.applying(.stageHandoff(retry), to: state, intents: intents)
        #expect(try Owner.decode(Owner.encode(state)) == state)
        #expect(try Owner.applying(.stageHandoff(retry), to: state, intents: intents) == state)
        for change: Owner.Change in [.stage(pending), .complete(before.current!.directResult),
                                    .stageService(try f.pendingService(before)), .recordService(service)] {
            #expect(throws: (any Error).self) { try Owner.applying(change, to: state, intents: intents) }
        }
        let request = try StorageLifecycleHandoffProtocol.Request(operationID: retry.operationID,
            predecessor: service.grant, pending: pending.signed.grant, serviceEpoch: old.serviceEpoch, openRevision: service.openRevision)
        let signed = try StorageLifecycleHandoffProtocol.SignedRequest(request: request, signature: f.root.signature(for: request.signingBytes))
        let receipt = try applied ? f.receipt(pending, revision: service.openRevision + 1) : before.current!.directResult
        let result = try StorageLifecycleHandoffProtocol.Result(request: request, nonce: Data(repeating: 4, count: 32),
            appliedGrant: receipt.grant, appliedServiceEpoch: receipt.serviceEpoch, appliedRevision: receipt.revision,
            fenceRevision: service.openRevision + 2)
        let actual = try applied ? Wire.ServiceState(grant: pending.signed.grant,
            context: .init(serviceEpoch: old.serviceEpoch, controllerEpoch: 2, controllerKey: pending.signed.grant.newKey),
            openRevision: service.openRevision, boot: service.boot) : service
        let completion = try StorageLifecycleHandoffRootProtocol.Completed(signedRequest: signed, result: result,
            predecessorService: service, predecessorReceipt: before.current!.directResult,
            service: actual, receipt: receipt, pendingSigned: pending.signed)
        let forged = try StorageLifecycleHandoffRootProtocol.Completed(
            signedRequest: .init(request: request, signature: Data(repeating: 0, count: 64)), result: result,
            predecessorService: service, predecessorReceipt: before.current!.directResult,
            service: actual, receipt: receipt, pendingSigned: pending.signed)
        #expect(throws: (any Error).self) { try Owner.applying(.recoverHandoff(forged), to: state, intents: intents) }
        var unknown = state; unknown.pending = nil; unknown.pendingTakeover = nil
        #expect(throws: (any Error).self) { try Owner.validate(unknown) }
        let done = try Owner.applying(.recoverHandoff(completion), to: state, intents: intents)
        #expect(done.currentContext?.controllerEpoch == (applied ? 2 : 1))
        #expect(done.currentService == actual && done.currentService?.boot == service.boot)
        #expect(done.pending == nil && done.pendingTakeover == nil && done.handoffRetry == nil)
        #expect(done.contexts.contains(where: { $0.context == old && $0.controller == before.current }))
        #expect(done.references.count == 1)
        #expect(try Owner.decode(Owner.encode(done)) == done)
        if applied {
            #expect(done.current?.original == pending)
            #expect(done.serviceReplacement == nil && done.nativeReplacementAttempted == nil)
        } else {
            #expect(done.current == before.current)
            #expect(done.serviceReplacement == before.serviceReplacement)
        }
    }

    @Test func completedTakeoversBeyond4096HaveBoundedBaselineAndExactRetries() async throws {
        let f = try Fixture()
        var state = try f.baseline()
        state = try Owner.applying(.complete(f.receipt(state.pending!, revision: 1)), to: state, intents: f.intents())
        let initial = state.current!.original
        var mainActorWasServiced = false
        let heartbeat = Task { @MainActor in mainActorWasServiced = true }
        defer { heartbeat.cancel() }
        for epoch in 1...4098 {
            let pending = try f.grant(.takeover, epoch: UInt64(epoch), serial: UInt64(epoch + 1))
            state = try Owner.applying(.stage(pending), to: state, intents: f.intents())
            let staged = state
            state = try Owner.applying(.stage(pending), to: state, intents: f.intents())
            #expect(state.pending == staged.pending)
            state = try Owner.applying(.complete(f.receipt(pending, revision: UInt64(epoch + 1))), to: state, intents: f.intents())
            #expect(state.contexts.count == 1)
            // Keep the stress campaign from starving unrelated MainActor deadline
            // tests. Each individual metadata transaction remains synchronous.
            await Task.yield()
        }
        #expect(mainActorWasServiced)
        await heartbeat.value
        #expect(state.currentContext?.controllerEpoch == 4099)
        #expect(try Owner.encode(state).count < 10_000)
        #expect(try Owner.decode(Owner.encode(state)) == state)
        let latest = state.current!.original
        #expect(try Owner.applying(.stage(latest), to: state, intents: f.intents()).pending == nil)
        #expect(throws: (any Error).self) { _ = try Owner.applying(.stage(initial), to: state, intents: f.intents()) }
    }

    @Test func allOriginalRecoveryPredecessorAndSupersededContextsSurviveHundredsOfChanges() async throws {
        let f = try Fixture()
        var state = try f.completed()
        state = try Owner.applying(.recordService(f.service(state)), to: state, intents: f.intents())
        let original = state.currentContext!
        state = try f.changeService(state, revision: 2, intents: f.intents())
        let link = state.latestServiceChange!
        var old = f.intent(original), superseded = f.intent(link.successor), successor = f.intent(link.successor)
        old.phase = .quarantined; old.successor = successor.id; old.supersededSuccessors = [superseded.id]
        superseded.phase = .abortedBeforeAdmission; superseded.predecessor = old.id
        successor.predecessor = old.id
        successor.replacementRecovery = .init(serviceEpoch: original.serviceEpoch, controllerEpoch: original.controllerEpoch,
            controllerKey: original.controllerKey, provenanceReference: f.provenance, workerHistoryReference: try link.reference)
        var intents = f.intents()
        intents.intents = [old.id: old, superseded.id: superseded, successor.id: successor]
        let frozen = intents
        for epoch in 1...200 {
            let pending = try f.grant(.takeover, epoch: UInt64(epoch), serial: UInt64(epoch + 1))
            state = try Owner.applying(.stage(pending), to: state, intents: intents)
            state = try Owner.applying(.complete(f.receipt(pending, revision: UInt64(epoch * 2 + 1))), to: state, intents: intents)
            state = try Owner.applying(.recordService(f.service(state)), to: state, intents: intents)
            state = try f.changeService(state, revision: UInt64(epoch * 2 + 2), intents: intents)
            #expect(state.contexts.count <= 4)
            #expect(state.serviceLinks.count == 2)
            await Task.yield()
        }
        #expect(intents == frozen)
        #expect(state.contexts.contains(where: { $0.context == original }))
        #expect(state.contexts.contains(where: { $0.context == link.successor }))
        #expect(state.references.first(where: { $0.id == old.id })?.superseded == [superseded.id])
        #expect(state.references.first(where: { $0.id == successor.id })?.recovery == successor.replacementRecovery)
        #expect(try Owner.decode(Owner.encode(state)) == state)
        // Unknown originals, dangling predecessor and unknown worker history all
        // refuse; none is silently discarded to fit a bounded checkpoint.
        var unknown = intents
        let alien = f.intent(.init(serviceEpoch: id(), controllerEpoch: 1, controllerKey: original.controllerKey))
        unknown.intents[alien.id] = alien
        #expect(throws: (any Error).self) { _ = try Owner.applying(.stage(state.current!.original), to: state, intents: unknown) }
        unknown = intents; unknown.intents.removeValue(forKey: superseded.id)
        #expect(throws: (any Error).self) { _ = try Owner.applying(.stage(state.current!.original), to: state, intents: unknown) }
        unknown = intents
        unknown.intents[successor.id]?.replacementRecovery = .init(serviceEpoch: original.serviceEpoch, controllerEpoch: 1,
            controllerKey: original.controllerKey, provenanceReference: f.provenance, workerHistoryReference: String(repeating: "f", count: 64))
        #expect(throws: (any Error).self) { _ = try Owner.applying(.stage(state.current!.original), to: state, intents: unknown) }
    }

    @Test func everyOneOf128IntentSlotsKeepsItsOriginalController() async throws {
        let f = try Fixture()
        var state = try f.completed(), intents = f.intents()
        for epoch in 1...128 {
            let intent = f.intent(state.currentContext!)
            intents.intents[intent.id] = intent; intents.revision += 1
            let pending = try f.grant(.takeover, epoch: UInt64(epoch), serial: UInt64(epoch + 1))
            state = try Owner.applying(.stage(pending), to: state, intents: intents)
            state = try Owner.applying(.complete(f.receipt(pending, revision: UInt64(epoch + 1))), to: state, intents: intents)
            await Task.yield()
        }
        #expect(state.references.count == 128)
        #expect(state.contexts.count == 129)
        for intent in intents.intents.values {
            #expect(state.contexts.contains(where: { $0.context.serviceEpoch == intent.serviceEpoch && $0.context.controllerEpoch == intent.controllerEpoch && $0.context.controllerKey == intent.controllerKey }))
        }
        #expect(try Owner.encode(state).count < Owner.maximumBytes)
        #expect(try Owner.decode(Owner.encode(state)) == state)
        let overflow = f.intent(state.currentContext!)
        intents.intents[overflow.id] = overflow; intents.revision += 1
        #expect(throws: (any Error).self) { _ = try Owner.applying(.stage(state.current!.original), to: state, intents: intents) }
    }

    @Test func malformedVersionCountersGenerationSignatureAndReceiptAreRejected() throws {
        let f = try Fixture()
        let state = try f.completed()
        let pending = try f.grant(.takeover, epoch: 1, serial: 2)
        func rejected(_ context: Owner.GrantContext) {
            #expect(throws: (any Error).self) { _ = try Owner.applying(.stage(context), to: state, intents: f.intents()) }
        }
        rejected(try f.grant(.takeover, epoch: 2, serial: 2))
        rejected(try f.grant(.takeover, epoch: 1, serial: 1))
        rejected(try f.grant(.takeover, epoch: 1, serial: 2,
            identity: Wire.Identity(store: f.identity.store, generation: 2, binding: f.identity.binding)))
        rejected(.init(signed: try .init(grant: pending.signed.grant, signature: Data(repeating: 0, count: 64)),
            recipient: pending.recipient, requestID: pending.requestID, serviceEpoch: pending.serviceEpoch))
        let staged = try Owner.applying(.stage(pending), to: state, intents: f.intents())
        #expect(throws: (any Error).self) {
            _ = try Wire.Receipt(grant: pending.signed.grant, nonce: Data(repeating: 0, count: 31), serviceEpoch: pending.serviceEpoch!, revision: 2)
        }
        let wrongService = try f.receipt(pending, revision: 2, service: id())
        #expect(throws: (any Error).self) { _ = try Owner.applying(.complete(wrongService), to: staged, intents: f.intents()) }
        #expect(throws: (any Error).self) { _ = try Owner.applying(.complete(f.receipt(pending, revision: 1)), to: staged, intents: f.intents()) }
        var overflowing = state; overflowing.revision = .max
        #expect(throws: (any Error).self) { _ = try Owner.applying(.stage(pending), to: overflowing, intents: f.intents()) }
        let bytes = try Owner.encode(state)
        let oldVersion = Data(String(decoding: bytes, as: UTF8.self).replacingOccurrences(of: Wire.version, with: "storage-lifecycle.v1").utf8)
        #expect(throws: (any Error).self) { _ = try Owner.decode(oldVersion) }
        #expect(throws: (any Error).self) { _ = try Owner.decode(bytes + Data([10])) }
        var zero = state; zero.revision = 0
        #expect(throws: (any Error).self) { _ = try Owner.decode(Owner.encode(zero)) }
        #expect(throws: (any Error).self) { _ = try Wire.Grant(operation: .takeover, id: id(), identity: f.identity, serial: 4, expectedEpoch: .max, newKey: pending.signed.grant.newKey) }
    }

    @Test func retirementRequiresMatchingSealAndRemainsTerminal() throws {
        let f = try Fixture()
        var state = try f.completed()
        let pending = try f.grant(.retire, epoch: 1, serial: 2, recipient: state.current!.original.recipient,
            service: state.currentContext!.serviceEpoch)
        state = try Owner.applying(.stage(pending), to: state, intents: f.intents())
        let result = try f.receipt(pending, revision: 2)
        #expect(throws: (any Error).self) { _ = try Owner.applying(.retire(result), to: state, intents: f.intents()) }
        state = try Owner.applying(.seal(result), to: state, intents: f.intents())
        let sealed = try Owner.decode(Owner.encode(state))
        #expect(sealed.pending == pending)
        let different = try f.grant(.retire, epoch: 1, serial: 3, recipient: pending.recipient, service: pending.serviceEpoch)
        #expect(throws: (any Error).self) { _ = try Owner.applying(.retire(f.receipt(different, revision: 2)), to: sealed, intents: f.intents()) }
        state = try Owner.applying(.retire(result), to: sealed, intents: f.intents())
        #expect(try Owner.decode(Owner.encode(state)).terminal == result)
        #expect(throws: (any Error).self) { _ = try Owner.applying(.stage(state.current!.original), to: state, intents: f.intents()) }
        #expect(throws: (any Error).self) { _ = try Owner.applying(.complete(state.current!.directResult), to: state, intents: f.intents()) }
    }

    @Test(arguments: [false, true])
    func preGuestInitializationAndCompletedRetriesAcceptFreshRootNonces(takeover: Bool) throws {
        let disk = try Disk(); defer { disk.remove() }
        let f = try Fixture(binding: disk.binding), intents = f.intents()
        var owner: Owner? = try disk.fresh(f)
        let initial = try owner!.snapshot().pending!
        #expect(initial.serviceEpoch == nil) // ROOT granted before Guest selected E.
        let observedService = id()
        let initialized = try f.receipt(initial, revision: 1, service: observedService)
        try owner!.persist(.complete(initialized), intents: intents, readIntents: { intents })
        #expect(try owner!.snapshot().currentContext?.serviceEpoch == observedService)
        #expect(try owner!.snapshot().current?.original.serviceEpoch == nil)
        if takeover {
            let pending = try f.grant(.takeover, epoch: 1, serial: 2)
            try owner!.persist(.stage(pending), intents: intents, readIntents: { intents })
            try owner!.persist(.complete(f.receipt(pending, revision: 2)), intents: intents, readIntents: { intents })
        }
        let before = try owner!.snapshot(), recorded = before.current!.directResult
        owner = nil
        owner = try disk.open(f, hook: { step, moment in
            if step == .statePublish, case .before = moment { throw Owner.Failure.repairRequired }
        })
        let fresh = try Wire.Receipt(grant: recorded.grant, nonce: Data(repeating: 8, count: 32),
            serviceEpoch: recorded.serviceEpoch, revision: recorded.revision)
        #expect(fresh.nonce != recorded.nonce)
        try owner!.persist(.complete(fresh), intents: intents, readIntents: { intents })
        for changed in [
            try Wire.Receipt(grant: fresh.grant, nonce: fresh.nonce, serviceEpoch: id(), revision: fresh.revision),
            try Wire.Receipt(grant: fresh.grant, nonce: fresh.nonce, serviceEpoch: fresh.serviceEpoch, revision: fresh.revision + 1),
        ] {
            #expect(throws: (any Error).self) { try owner!.persist(.complete(changed), intents: intents, readIntents: { intents }) }
        }
        #expect(try owner!.snapshot() == before) // Original audit nonce and revision retained; no write.
    }

    @Test(arguments: [false, true])
    func sealedAndTerminalRetriesAfterReopenKeepFirstReceipt(terminal: Bool) throws {
        let disk = try Disk(); defer { disk.remove() }
        let f = try Fixture(binding: disk.binding), intents = f.intents()
        var owner: Owner? = try disk.fresh(f)
        let initial = try owner!.snapshot().pending!
        try owner!.persist(.complete(f.receipt(initial, revision: 1)), intents: intents, readIntents: { intents })
        let current = try owner!.snapshot()
        let retiring = try f.grant(.retire, epoch: 1, serial: 2, recipient: initial.recipient,
            service: current.currentContext!.serviceEpoch)
        let seal = try f.receipt(retiring, revision: 2)
        try owner!.persist(.stage(retiring), intents: intents, readIntents: { intents })
        try owner!.persist(.seal(seal), intents: intents, readIntents: { intents })
        if terminal {
            // Final ROOT confirmation may itself carry a new challenge nonce.
            let final = try f.receipt(retiring, revision: 2, nonce: Data(repeating: 8, count: 32))
            try owner!.persist(.retire(final), intents: intents, readIntents: { intents })
        }
        let before = try owner!.snapshot()
        owner = nil
        owner = try disk.open(f, hook: { step, moment in
            if step == .statePublish, case .before = moment { throw Owner.Failure.repairRequired }
        })
        let retry = try f.receipt(retiring, revision: 2, nonce: Data(repeating: 9, count: 32))
        try owner!.persist(terminal ? .retire(retry) : .seal(retry), intents: intents, readIntents: { intents })
        let otherGrant = try f.grant(.retire, epoch: 1, serial: 3, recipient: initial.recipient, service: retiring.serviceEpoch)
        for changed in [
            try f.receipt(retiring, revision: 2, service: id(), nonce: retry.nonce),
            try f.receipt(retiring, revision: 3, nonce: retry.nonce),
            try f.receipt(retiring, revision: 1, nonce: retry.nonce),
            try f.receipt(otherGrant, revision: 2, nonce: retry.nonce),
        ] {
            #expect(throws: (any Error).self) {
                try owner!.persist(terminal ? .retire(changed) : .seal(changed), intents: intents, readIntents: { intents })
            }
        }
        #expect(try owner!.snapshot() == before)
        #expect(try owner!.snapshot().sealed == seal)
    }

    @Test func terminalRetryRequiresFrozenIntentCensus() throws {
        let f = try Fixture()
        var state = try f.completed(), intents = f.intents()
        intents.revision = 2
        let retiring = try f.grant(.retire, epoch: 1, serial: 2,
            recipient: state.current!.original.recipient, service: state.currentContext!.serviceEpoch)
        let result = try f.receipt(retiring, revision: 2)
        state = try Owner.applying(.stage(retiring), to: state, intents: intents)
        state = try Owner.applying(.seal(result), to: state, intents: intents)
        state = try Owner.applying(.retire(result), to: state, intents: intents)
        let frozen = state
        let retry = try f.receipt(retiring, revision: 2, nonce: Data(repeating: 9, count: 32))
        #expect(try Owner.applying(.retire(retry), to: frozen, intents: intents) == frozen)
        for revision in [UInt64(1), UInt64(3)] {
            var changed = intents; changed.revision = revision
            do {
                _ = try Owner.applying(.retire(retry), to: frozen, intents: changed)
                Issue.record("terminal retry accepted changed intent revision")
            } catch Owner.Failure.staleIntents {}
        }
        for context in [frozen.currentContext!, Owner.Context(serviceEpoch: id(), controllerEpoch: 1,
            controllerKey: frozen.currentContext!.controllerKey)] {
            var changed = intents
            let intent = f.intent(context)
            changed.intents[intent.id] = intent
            do {
                _ = try Owner.applying(.retire(retry), to: frozen, intents: changed)
                Issue.record("terminal retry accepted a new unresolved reference")
            } catch Owner.Failure.blocked {}
        }
        #expect(try Owner.applying(.retire(retry), to: frozen, intents: intents) == frozen)
    }

    @Test func durableTerminalRetryRefusesChangedCensusWithoutWrites() throws {
        let disk = try Disk(); defer { disk.remove() }
        let f = try Fixture(binding: disk.binding), intents = f.intents()
        var owner: Owner? = try disk.fresh(f)
        let initial = try owner!.snapshot().pending!
        try owner!.persist(.complete(f.receipt(initial, revision: 1)), intents: intents, readIntents: { intents })
        let current = try owner!.snapshot()
        let retiring = try f.grant(.retire, epoch: 1, serial: 2,
            recipient: initial.recipient, service: current.currentContext!.serviceEpoch)
        let result = try f.receipt(retiring, revision: 2)
        try owner!.persist(.stage(retiring), intents: intents, readIntents: { intents })
        try owner!.persist(.seal(result), intents: intents, readIntents: { intents })
        try owner!.persist(.retire(result), intents: intents, readIntents: { intents })
        let frozen = try owner!.snapshot()
        owner = nil
        var writes = 0
        owner = try disk.open(f, hook: { step, moment in
            if step == .initialProofCreate, case .before = moment { writes += 1 }
        })
        let retry = try f.receipt(retiring, revision: 2, nonce: Data(repeating: 9, count: 32))
        try owner!.persist(.retire(retry), intents: intents, readIntents: { intents })
        var changed = intents; changed.revision += 1
        do {
            try owner!.persist(.retire(retry), intents: changed, readIntents: { changed })
            Issue.record("durable terminal retry accepted changed intent revision")
        } catch Owner.Failure.staleIntents {}
        changed = intents
        let intent = f.intent(frozen.currentContext!) // Known context: not an unknown-context failure.
        changed.intents[intent.id] = intent
        do {
            try owner!.persist(.retire(retry), intents: changed, readIntents: { changed })
            Issue.record("durable terminal retry accepted changed references")
        } catch Owner.Failure.blocked {}
        #expect(writes == 0)
        #expect(try owner!.snapshot() == frozen)
        owner = nil
        owner = try disk.open(f)
        #expect(try owner!.snapshot() == frozen)
    }

    @Test(arguments: [Wire.Operation.takeover, .retire])
    func nonInitializationRequiresSelectedServiceEpoch(operation: Wire.Operation) throws {
        let f = try Fixture(), state = try f.completed()
        let context = try f.grant(operation, epoch: 1, serial: 2,
            recipient: operation == .retire ? state.current!.original.recipient : nil,
            service: state.currentContext!.serviceEpoch)
        let missing = Owner.GrantContext(signed: context.signed, recipient: context.recipient,
            requestID: context.requestID, serviceEpoch: nil)
        #expect(throws: (any Error).self) { _ = try Owner.applying(.stage(missing), to: state, intents: f.intents()) }
    }

    @Test func physicalPendingLostReplyReopensAnd64TransitionsStayBounded() async throws {
        let disk = try Disk(); defer { disk.remove() }
        let f = try Fixture(binding: disk.binding)
        var owner: Owner? = try disk.fresh(f)
        let intents = f.intents()
        let initial = try owner!.snapshot().pending!
        try owner!.persist(.complete(f.receipt(initial, revision: 1)), intents: intents, readIntents: { intents })
        let pending = try f.grant(.takeover, epoch: 1, serial: 2)
        try owner!.persist(.stage(pending), intents: intents, readIntents: { intents })
        owner = nil
        owner = try disk.open(f)
        #expect(try owner!.snapshot().pending == pending)
        let alien = try f.grant(.takeover, epoch: 1, serial: 3)
        #expect(throws: (any Error).self) { try owner!.persist(.stage(alien), intents: intents, readIntents: { intents }) }
        // A dead/lost recipient is not replaced or timed out. Only matching public
        // result metadata advances the pending tuple, with authentication still external.
        try owner!.persist(.complete(f.receipt(pending, revision: 2)), intents: intents, readIntents: { intents })
        for epoch in 2...65 {
            let next = try f.grant(.takeover, epoch: UInt64(epoch), serial: UInt64(epoch + 1))
            try owner!.persist(.stage(next), intents: intents, readIntents: { intents })
            try owner!.persist(.complete(f.receipt(next, revision: UInt64(epoch + 1))), intents: intents, readIntents: { intents })
            await Task.yield()
        }
        let before = try owner!.snapshot()
        #expect(before.contexts.count == 1)
        #expect(try Owner.encode(before).count < 10_000)
        owner = nil
        owner = try disk.open(f)
        #expect(try owner!.snapshot() == before)
        #expect(try disk.root.openDirectory(named: Owner.directoryName).entryNames() == ["lease", "manifest.json", "state.json"])
    }

    @Test func replacementRecoveryRequiresExactFrozenAuthorizationAndUncontestedLane() throws {
        let f = try Fixture(), intents = f.intents()
        var state = try f.completed()
        state = try Owner.applying(.recordService(f.service(state)), to: state, intents: intents)
        #expect(try Owner.replacementRecoveryRequest(state) == nil)
        let pending = try f.pendingService(state)
        state = try Owner.applying(.stageService(pending), to: state, intents: intents)
        #expect(throws: (any Error).self) { try Owner.replacementRecoveryRequest(state) }
        let signed = try Wire.SignedServiceChange(request: pending.request,
            signature: f.root.signature(for: pending.request.signingBytes))
        let configuration = StorageLifecycleServiceBootProtocol.Configuration(action: .open,
            rootPublicKey: state.rootPublicKey, signed: state.current!.original.signed,
            nowUnixSeconds: pending.nowUnixSeconds, lifetimeSeconds: pending.lifetimeSeconds, reopen: signed)
        let frozen = StorageLifecycleServiceBootProtocol.ReplacementRequest(
            predecessorWorkerUUID: pending.predecessorWorkerUUID, configuration: configuration)
        state = try Owner.applying(.authorizeServiceReplacement(frozen), to: state, intents: intents)
        #expect(try Owner.replacementRecoveryRequest(state) == pending)
        var wrong = state
        wrong.serviceReplacement = .init(predecessorWorkerUUID: id(), configuration: configuration)
        #expect(throws: (any Error).self) { try Owner.replacementRecoveryRequest(wrong) }
        state = try Owner.applying(.attemptNativeReplacement, to: state, intents: intents)
        state = try Owner.applying(.confirmService(f.confirmation(pending, state: state)), to: state, intents: intents)
        #expect(try Owner.replacementRecoveryRequest(state) == pending)
        // A later durable operation cannot accidentally reuse the consumed native
        // envelope, completion ID, or predecessor worker of the prior operation.
        let second = try f.pendingService(state)
        state = try Owner.applying(.stageService(second), to: state, intents: intents)
        #expect(state.serviceReplacement == nil && state.nativeReplacementAttempted == nil)
        #expect(throws: (any Error).self) { try Owner.replacementRecoveryRequest(state) }
        #expect(throws: (any Error).self) { try Owner.applying(.authorizeServiceReplacement(frozen), to: state, intents: intents) }
        let secondSigned = try Wire.SignedServiceChange(request: second.request,
            signature: f.root.signature(for: second.request.signingBytes))
        let secondConfiguration = StorageLifecycleServiceBootProtocol.Configuration(action: .open,
            rootPublicKey: state.rootPublicKey, signed: state.current!.original.signed,
            nowUnixSeconds: second.nowUnixSeconds, lifetimeSeconds: second.lifetimeSeconds, reopen: secondSigned)
        state = try Owner.applying(.authorizeServiceReplacement(.init(predecessorWorkerUUID: second.predecessorWorkerUUID,
            configuration: secondConfiguration)), to: state, intents: intents)
        state = try Owner.applying(.attemptNativeReplacement, to: state, intents: intents)
        #expect(try Owner.replacementRecoveryRequest(state) == second)
        state = try Owner.applying(.confirmService(f.confirmation(second, state: state)), to: state, intents: intents)
        #expect(try Owner.replacementRecoveryRequest(state) == second)
        #expect(throws: (any Error).self) { try Owner.applying(.confirmService(f.confirmation(pending, state: state)), to: state, intents: intents) }
        let takeover = try f.grant(.takeover, epoch: 1, serial: 2, service: state.currentContext!.serviceEpoch)
        state = try Owner.applying(.stage(takeover), to: state, intents: intents)
        #expect(try Owner.replacementRecoveryRequest(state) == nil)
    }

    @Test func serviceResultBaselineIsBoundedAndUnlinkedEpochTamperingRefuses() async throws {
        let f = try Fixture()
        var state = try f.completed()
        state = try Owner.applying(.recordService(f.service(state)), to: state, intents: f.intents())
        let applied = state.current!
        var oldest: Wire.ServiceChangeConfirmation?
        for revision in 2...201 {
            state = try f.changeService(state, revision: UInt64(revision), intents: f.intents())
            if oldest == nil { oldest = state.latestServiceConfirmation }
            #expect(state.current == applied) // Same-C reopen never rewrites the signed applied receipt.
            #expect(state.currentService == state.latestServiceConfirmation?.successor)
            #expect(state.latestServiceRequest?.request == state.latestServiceConfirmation?.request)
            #expect(state.pendingService == nil)
            #expect(state.contexts.count == 2)
            #expect(state.serviceLinks.count == 1)
            await Task.yield()
        }
        #expect(try Owner.decode(Owner.encode(state)) == state)
        #expect(try Owner.encode(state).count < 16_384)
        #expect(throws: (any Error).self) { _ = try Owner.applying(.confirmService(oldest!), to: state, intents: f.intents()) }
        #expect(throws: (any Error).self) { _ = try Owner.applying(.recordService(oldest!.successor), to: state, intents: f.intents()) }
        let replay = Owner.PendingService(request: oldest!.request, stageRequestID: id(), completionRequestID: id(),
            predecessorWorkerUUID: id(), nowUnixSeconds: 100, lifetimeSeconds: 60)
        #expect(throws: (any Error).self) { _ = try Owner.applying(.stageService(replay), to: state, intents: f.intents()) }
        var malformed = try f.completed()
        let invented = Owner.Context(serviceEpoch: id(), controllerEpoch: 1, controllerKey: malformed.currentContext!.controllerKey)
        malformed.currentContext = invented
        malformed.contexts = [.init(context: invented, controller: malformed.current!)]
        #expect(throws: (any Error).self) { _ = try Owner.decode(Owner.encode(malformed)) }
    }

    @Test func observedWorkerIsOptionalBoundedIdempotentAndClearedOnSelectionChanges() throws {
        let f = try Fixture(), intents = f.intents()
        var state = try f.completed()
        #expect(state.observedWorker == nil)
        #expect(try Owner.decode(Owner.encode(state)) == state) // Older metadata fixtures remain valid.
        let observation = Owner.ObservedWorker(context: state.currentContext!, workerUUID: id())
        #expect(throws: (any Error).self) {
            try Owner.applying(.recordObservedWorker(observation), to: state, intents: intents)
        }
        state = try Owner.applying(.recordService(f.service(state)), to: state, intents: intents)
        state = try Owner.applying(.recordObservedWorker(observation), to: state, intents: intents)
        #expect(try Owner.decode(Owner.encode(state)).observedWorker == observation)
        #expect(try Owner.applying(.recordObservedWorker(observation), to: state, intents: intents) == state)
        #expect(try Owner.encode(state).count < 16_384)
        let pending = try f.pendingService(state)
        let staged = try Owner.applying(.stageService(pending), to: state, intents: intents)
        #expect(staged.observedWorker == observation) // Frozen predecessor, not successor evidence.
        #expect(throws: (any Error).self) {
            try Owner.applying(.recordObservedWorker(observation), to: staged, intents: intents)
        }
        let replaced = try Owner.applying(.confirmService(f.confirmation(pending, state: staged)), to: staged, intents: intents)
        #expect(replaced.observedWorker == nil)
        #expect(throws: (any Error).self) {
            try Owner.applying(.recordObservedWorker(observation), to: replaced, intents: intents)
        }
        let takeover = try f.grant(.takeover, epoch: 1, serial: 2)
        let takingOver = try Owner.applying(.stage(takeover), to: state, intents: intents)
        #expect(throws: (any Error).self) {
            try Owner.applying(.recordObservedWorker(observation), to: takingOver, intents: intents)
        }
        let completed = try Owner.applying(.complete(f.receipt(takeover, revision: 2)), to: takingOver, intents: intents)
        #expect(completed.currentService == nil && completed.observedWorker == nil)
        var invalid = state
        invalid.observedWorker = .init(context: observation.context, workerUUID: "not-a-worker")
        #expect(throws: (any Error).self) { try Owner.decode(Owner.encode(invalid)) }
    }

    @Test func durableServicePendingAndLostConfirmationReopenWithExactRetries() throws {
        let disk = try Disk(); defer { disk.remove() }
        let f = try Fixture(binding: disk.binding), intents = f.intents()
        var owner: Owner? = try disk.fresh(f)
        let initial = try owner!.snapshot().pending!
        try owner!.persist(.complete(f.receipt(initial, revision: 1)), intents: intents, readIntents: { intents })
        let service = try f.service(owner!.snapshot())
        try owner!.persist(.recordService(service), intents: intents, readIntents: { intents })
        let applied = try owner!.snapshot().current!
        let pending = try f.pendingService(owner!.snapshot())
        try owner!.persist(.stageService(pending), intents: intents, readIntents: { intents })
        let staged = try owner!.snapshot()
        owner = nil
        var writes = 0
        owner = try disk.open(f, hook: { step, moment in
            if step == .statePublish, case .before = moment { writes += 1 }
        })
        #expect(try owner!.snapshot() == staged)
        try owner!.persist(.stageService(pending), intents: intents, readIntents: { intents })
        for changed in [
            Owner.PendingService(request: pending.request, stageRequestID: id(), completionRequestID: pending.completionRequestID,
                predecessorWorkerUUID: pending.predecessorWorkerUUID, nowUnixSeconds: pending.nowUnixSeconds,
                lifetimeSeconds: pending.lifetimeSeconds),
            Owner.PendingService(request: pending.request, stageRequestID: pending.stageRequestID, completionRequestID: id(),
                predecessorWorkerUUID: pending.predecessorWorkerUUID, nowUnixSeconds: pending.nowUnixSeconds,
                lifetimeSeconds: pending.lifetimeSeconds),
            Owner.PendingService(request: pending.request, stageRequestID: pending.stageRequestID,
                completionRequestID: pending.completionRequestID, predecessorWorkerUUID: id(),
                nowUnixSeconds: pending.nowUnixSeconds, lifetimeSeconds: pending.lifetimeSeconds),
            Owner.PendingService(request: pending.request, stageRequestID: pending.stageRequestID,
                completionRequestID: pending.completionRequestID, predecessorWorkerUUID: pending.predecessorWorkerUUID,
                nowUnixSeconds: pending.nowUnixSeconds + 1, lifetimeSeconds: pending.lifetimeSeconds),
            Owner.PendingService(request: pending.request, stageRequestID: pending.stageRequestID,
                completionRequestID: pending.completionRequestID, predecessorWorkerUUID: pending.predecessorWorkerUUID,
                nowUnixSeconds: pending.nowUnixSeconds, lifetimeSeconds: pending.lifetimeSeconds + 1),
            Owner.PendingService(request: try .init(operationID: id(), predecessor: service),
                stageRequestID: pending.stageRequestID, completionRequestID: pending.completionRequestID,
                predecessorWorkerUUID: pending.predecessorWorkerUUID, nowUnixSeconds: pending.nowUnixSeconds,
                lifetimeSeconds: pending.lifetimeSeconds),
        ] {
            #expect(throws: (any Error).self) { try owner!.persist(.stageService(changed), intents: intents, readIntents: { intents }) }
        }
        #expect(writes == 0)
        #expect(try owner!.snapshot() == staged)
        let confirmation = try f.confirmation(pending, state: staged)
        try owner!.persist(.confirmService(confirmation), intents: intents, readIntents: { intents })
        let completed = try owner!.snapshot()
        #expect(completed.current == applied)
        #expect(completed.currentService == confirmation.successor)
        #expect(completed.pendingService == nil)
        #expect(completed.latestServiceConfirmation == confirmation)
        #expect(completed.latestServiceRequest == pending)
        #expect(writes == 1)
        owner = nil
        owner = try disk.open(f, hook: { step, moment in
            if step == .statePublish, case .before = moment { throw Owner.Failure.repairRequired }
        })
        let recovered = try owner!.snapshot()
        #expect(recovered.latestServiceRequest == pending)
        #expect(recovered.latestServiceRequest?.stageRequestID == pending.stageRequestID)
        #expect(recovered.latestServiceRequest?.completionRequestID == pending.completionRequestID)
        #expect(recovered.latestServiceRequest?.nowUnixSeconds == pending.nowUnixSeconds)
        #expect(recovered.latestServiceRequest?.lifetimeSeconds == pending.lifetimeSeconds)
        #expect(recovered.latestServiceRequest?.request.predecessor != recovered.currentService)
        #expect(recovered.latestServiceRequest?.predecessorWorkerUUID == pending.predecessorWorkerUUID)
        try owner!.persist(.confirmService(confirmation), intents: intents, readIntents: { intents })
        try owner!.persist(.recordService(confirmation.successor), intents: intents, readIntents: { intents })
        let conflicting = try f.confirmation(pending, state: staged)
        #expect(throws: (any Error).self) { try owner!.persist(.confirmService(conflicting), intents: intents, readIntents: { intents }) }
        #expect(try owner!.snapshot() == completed)
        let nextPending = try f.pendingService(completed)
        let next = try Owner.applying(.stageService(nextPending), to: completed, intents: intents)
        #expect(throws: (any Error).self) { _ = try Owner.applying(.confirmService(confirmation), to: next, intents: intents) }
    }

    @Test func servicePendingFencesAllGrantAndStaleActions() throws {
        let f = try Fixture(), intents = f.intents()
        var state = try f.completed()
        state = try Owner.applying(.recordService(f.service(state)), to: state, intents: intents)
        let pending = try f.pendingService(state)
        let confirmation = try f.confirmation(pending, state: state)
        #expect(throws: (any Error).self) { _ = try Owner.applying(.confirmService(confirmation), to: state, intents: intents) }
        let takeover = try f.grant(.takeover, epoch: 1, serial: 2)
        let retirement = try f.grant(.retire, epoch: 1, serial: 2,
            recipient: state.current!.original.recipient, service: state.currentContext!.serviceEpoch)
        let grantPending = try Owner.applying(.stage(takeover), to: state, intents: intents)
        for action: Owner.Change in [.stageService(pending), .recordService(state.currentService!), .confirmService(confirmation)] {
            #expect(throws: (any Error).self) { _ = try Owner.applying(action, to: grantPending, intents: intents) }
        }
        state = try Owner.applying(.stageService(pending), to: state, intents: intents)
        for action: Owner.Change in [
            .stage(takeover), .stage(retirement), .stage(state.current!.original), .complete(state.current!.directResult),
            .recordService(state.currentService!), .seal(state.current!.directResult), .retire(state.current!.directResult),
        ] {
            #expect(throws: (any Error).self) { _ = try Owner.applying(action, to: state, intents: intents) }
        }
        state = try Owner.applying(.confirmService(confirmation), to: state, intents: intents)
        let afterService = state
        state = try Owner.applying(.complete(state.current!.directResult), to: state, intents: intents)
        #expect(state == afterService)
        state = try Owner.applying(.stage(takeover), to: state, intents: intents)
        state = try Owner.applying(.complete(f.receipt(takeover, revision: 3)), to: state, intents: intents)
        #expect(state.currentService == nil)
        #expect(state.latestServiceRequest == nil)
        #expect(state.latestServiceConfirmation == nil)
        #expect(state.latestServiceChange == nil)
        #expect(throws: (any Error).self) { _ = try Owner.applying(.stageService(pending), to: state, intents: intents) }
        #expect(throws: (any Error).self) { _ = try Owner.applying(.recordService(confirmation.successor), to: state, intents: intents) }
        state = try Owner.applying(.recordService(f.service(state, revision: 2)), to: state, intents: intents)
        #expect(state.currentService?.openRevision == 2) // Takeover applied revision need not be the open revision.
    }

    @Test func serviceBaselineCannotInventEpochAndPendingScalarsAreStrict() throws {
        let f = try Fixture(), intents = f.intents()
        var state = try f.completed()
        for service in [try f.service(state, epoch: id()), try f.service(state, revision: 2),
                        try f.service(state, bootstrapKey: String(repeating: "f", count: 64))] {
            #expect(throws: (any Error).self) { _ = try Owner.applying(.recordService(service), to: state, intents: intents) }
        }
        let service = try f.service(state)
        let beforeBaseline = Owner.PendingService(request: try .init(operationID: id(), predecessor: service),
            stageRequestID: id(), completionRequestID: id(), predecessorWorkerUUID: id(), nowUnixSeconds: 100, lifetimeSeconds: 60)
        #expect(throws: (any Error).self) { _ = try Owner.applying(.stageService(beforeBaseline), to: state, intents: intents) }
        state = try Owner.applying(.recordService(service), to: state, intents: intents)
        #expect(try Owner.applying(.recordService(service), to: state, intents: intents) == state)
        #expect(throws: (any Error).self) { _ = try Owner.applying(.recordService(f.service(state)), to: state, intents: intents) }
        let pending = try f.pendingService(state)
        for invalid in [
            Owner.PendingService(request: pending.request, stageRequestID: "bad", completionRequestID: pending.completionRequestID,
                predecessorWorkerUUID: pending.predecessorWorkerUUID, nowUnixSeconds: 100, lifetimeSeconds: 60),
            Owner.PendingService(request: pending.request, stageRequestID: pending.stageRequestID, completionRequestID: "bad",
                predecessorWorkerUUID: pending.predecessorWorkerUUID, nowUnixSeconds: 100, lifetimeSeconds: 60),
            Owner.PendingService(request: pending.request, stageRequestID: pending.stageRequestID,
                completionRequestID: pending.stageRequestID, predecessorWorkerUUID: pending.predecessorWorkerUUID,
                nowUnixSeconds: 100, lifetimeSeconds: 60),
            Owner.PendingService(request: pending.request, stageRequestID: pending.stageRequestID,
                completionRequestID: pending.completionRequestID, predecessorWorkerUUID: "bad",
                nowUnixSeconds: 100, lifetimeSeconds: 60),
            Owner.PendingService(request: pending.request, stageRequestID: pending.stageRequestID,
                completionRequestID: pending.completionRequestID, predecessorWorkerUUID: pending.predecessorWorkerUUID,
                nowUnixSeconds: 0, lifetimeSeconds: 60),
            Owner.PendingService(request: pending.request, stageRequestID: pending.stageRequestID,
                completionRequestID: pending.completionRequestID, predecessorWorkerUUID: pending.predecessorWorkerUUID,
                nowUnixSeconds: StorageServiceTypes.maximumUnixSeconds + 1, lifetimeSeconds: 60),
            Owner.PendingService(request: pending.request, stageRequestID: pending.stageRequestID,
                completionRequestID: pending.completionRequestID, predecessorWorkerUUID: pending.predecessorWorkerUUID,
                nowUnixSeconds: 100, lifetimeSeconds: 0),
            Owner.PendingService(request: pending.request, stageRequestID: pending.stageRequestID,
                completionRequestID: pending.completionRequestID, predecessorWorkerUUID: pending.predecessorWorkerUUID,
                nowUnixSeconds: 100, lifetimeSeconds: 86_401),
        ] {
            #expect(throws: (any Error).self) { _ = try Owner.applying(.stageService(invalid), to: state, intents: intents) }
            var malformed = state; malformed.pendingService = invalid
            #expect(throws: (any Error).self) { _ = try Owner.decode(Owner.encode(malformed)) }
        }
    }

    @Test func serviceCompletionRetainsMaximumNewIntentCensusWithinReservation() throws {
        let f = try Fixture()
        var intents = f.intents(), state = try f.completed()
        state = try Owner.applying(.recordService(f.service(state)), to: state, intents: intents)
        let pending = try f.pendingService(state)
        state = try Owner.applying(.stageService(pending), to: state, intents: intents)
        let stagedBytes = try Owner.encode(state).count
        for _ in 0..<HostStorageIntents.maximumIntents {
            let intent = f.intent(state.currentContext!)
            intents.intents[intent.id] = intent
        }
        intents.revision += 1
        state = try Owner.applying(.confirmService(f.confirmation(pending, state: state)), to: state, intents: intents)
        #expect(state.references.count == HostStorageIntents.maximumIntents)
        #expect(state.contexts.count == 2)
        #expect(try Owner.encode(state).count - stagedBytes < 16_384 + HostStorageIntents.maximumIntents * 2_048)
        #expect(try Owner.decode(Owner.encode(state)) == state)
    }

    @Test func serviceCheckpointRejectsMissingAndMixedPublicCorrelation() throws {
        let f = try Fixture(), intents = f.intents()
        var live = try f.completed()
        live = try Owner.applying(.recordService(f.service(live)), to: live, intents: intents)
        let pending = try f.pendingService(live)
        let staged = try Owner.applying(.stageService(pending), to: live, intents: intents)
        let confirmed = try Owner.applying(.confirmService(f.confirmation(pending, state: staged)), to: staged, intents: intents)
        var malformed = staged; malformed.currentService = nil
        #expect(throws: (any Error).self) { _ = try Owner.decode(Owner.encode(malformed)) }
        malformed = confirmed; malformed.latestServiceConfirmation = nil
        #expect(throws: (any Error).self) { _ = try Owner.decode(Owner.encode(malformed)) }
        malformed = confirmed; malformed.latestServiceRequest = nil
        #expect(throws: (any Error).self) { _ = try Owner.decode(Owner.encode(malformed)) }
        malformed = live; malformed.latestServiceRequest = pending
        #expect(throws: (any Error).self) { _ = try Owner.decode(Owner.encode(malformed)) }
        malformed = confirmed; malformed.latestServiceRequest = try f.pendingService(confirmed)
        #expect(throws: (any Error).self) { _ = try Owner.decode(Owner.encode(malformed)) }
        malformed = confirmed; malformed.currentService = live.currentService
        #expect(throws: (any Error).self) { _ = try Owner.decode(Owner.encode(malformed)) }
        malformed = confirmed; malformed.pendingService = pending
        #expect(throws: (any Error).self) { _ = try Owner.decode(Owner.encode(malformed)) }
        malformed = staged; malformed.pending = try f.grant(.takeover, epoch: 1, serial: 2)
        #expect(throws: (any Error).self) { _ = try Owner.decode(Owner.encode(malformed)) }
        for (path, value): ([String], Any) in [
            (["currentService", "boot", "identity", "generation"], 2),
            (["currentService", "boot", "identity", "binding"], String(repeating: "e", count: 64)),
            (["currentService", "boot", "service_epoch"], id()),
            (["currentService", "boot", "bootstrap_key"], String(repeating: "f", count: 64)),
            (["currentService", "boot", "tls_root_sha256"], String(repeating: "f", count: 64)),
            (["currentService", "boot", "server_spki"], String(repeating: "f", count: 64)),
            (["currentService", "open_revision"], 99),
            (["pendingService", "request", "predecessor", "open_revision"], 99),
        ] {
            let bytes = try replacingJSON(Owner.encode(staged), path: path, value: value)
            #expect(throws: (any Error).self) { _ = try Owner.decode(bytes) }
        }
        for (field, value): (String, Any) in [
            ("stageRequestID", "bad"), ("completionRequestID", "bad"),
            ("completionRequestID", pending.stageRequestID),
            ("predecessorWorkerUUID", "bad"),
            ("nowUnixSeconds", 0), ("nowUnixSeconds", StorageServiceTypes.maximumUnixSeconds + 1),
            ("lifetimeSeconds", 0), ("lifetimeSeconds", 86_401),
        ] {
            let bytes = try replacingJSON(Owner.encode(confirmed), path: ["latestServiceRequest", field], value: value)
            #expect(throws: (any Error).self) { _ = try Owner.decode(bytes) }
        }
        let missing = try removingJSON(Owner.encode(confirmed), path: ["latestServiceRequest", "predecessorWorkerUUID"])
        #expect(throws: (any Error).self) { _ = try Owner.decode(missing) }
        let missingPending = try removingJSON(Owner.encode(staged), path: ["pendingService", "predecessorWorkerUUID"])
        #expect(throws: (any Error).self) { _ = try Owner.decode(missingPending) }
        let twice = try f.changeService(confirmed, revision: 4, intents: intents)
        #expect(twice.latestServiceRequest != pending)
        #expect(twice.latestServiceRequest?.request == twice.latestServiceConfirmation?.request)
        let wrongPredecessorRevision = try replacingJSON(Owner.encode(twice),
            path: ["latestServiceConfirmation", "request", "predecessor", "open_revision"], value: 1)
        #expect(throws: (any Error).self) { _ = try Owner.decode(wrongPredecessorRevision) }
        for path in [["latestServiceConfirmation", "request", "predecessor", "boot", "bootstrap_key"],
                     ["latestServiceConfirmation", "successor", "boot", "tls_root_sha256"],
                     ["latestServiceConfirmation", "successor", "boot", "server_spki"]] {
            let bytes = try replacingJSON(Owner.encode(confirmed), path: path, value: String(repeating: "f", count: 64))
            #expect(throws: (any Error).self) { _ = try Owner.decode(bytes) }
        }
    }

    private func replacingJSON(_ bytes: Data, path: [String], value: Any) throws -> Data {
        func replace(_ object: [String: Any], _ keys: ArraySlice<String>) -> [String: Any] {
            var object = object
            let key = keys.first!
            if keys.count == 1 { object[key] = value }
            else { object[key] = replace(object[key] as! [String: Any], keys.dropFirst()) }
            return object
        }
        let object = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
        return try JSONSerialization.data(withJSONObject: replace(object, path[...]), options: [.sortedKeys, .withoutEscapingSlashes])
    }

    /// A strict non-optional field must be present in the wire copy, not defaulted.
    private func removingJSON(_ bytes: Data, path: [String]) throws -> Data {
        func remove(_ object: [String: Any], _ keys: ArraySlice<String>) -> [String: Any] {
            var object = object
            let key = keys.first!
            if keys.count == 1 { object.removeValue(forKey: key) }
            else { object[key] = remove(object[key] as! [String: Any], keys.dropFirst()) }
            return object
        }
        let object = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
        return try JSONSerialization.data(withJSONObject: remove(object, path[...]), options: [.sortedKeys, .withoutEscapingSlashes])
    }

    @Test func exactRetryDoesNotWriteAndFreshRefusesExistingIntentJournal() throws {
        let disk = try Disk(); defer { disk.remove() }
        let f = try Fixture(binding: disk.binding)
        var writes = 0
        let owner = try disk.fresh(f, hook: { step, moment in
            if step == .statePublish, case .before = moment { writes += 1 }
        })
        let initial = try owner.snapshot().pending!, intents = f.intents()
        try owner.persist(.complete(f.receipt(initial, revision: 1)), intents: intents, readIntents: { intents })
        let before = try owner.snapshot()
        try owner.persist(.stage(initial), intents: intents, readIntents: { intents })
        try owner.persist(.complete(before.current!.directResult), intents: intents, readIntents: { intents })
        #expect(writes == 1)
        #expect(try owner.snapshot() == before)
        let other = try Disk(); defer { other.remove() }
        _ = try other.root.createDirectory(named: "managed-storage")
        let otherFixture = try Fixture(binding: other.binding)
        #expect(throws: (any Error).self) { _ = try other.fresh(otherFixture) }
        #expect(try other.root.entryMetadata(named: Owner.directoryName) == nil)
    }

    @Test func staleIntentSnapshotRefusesBeforePublication() throws {
        let disk = try Disk(); defer { disk.remove() }
        let f = try Fixture(binding: disk.binding), owner = try disk.fresh(f)
        let before = try owner.snapshot(), intents = f.intents()
        var changed = intents; changed.revision += 1
        var reads = 0
        #expect(throws: (any Error).self) {
            try owner.persist(.complete(f.receipt(before.pending!, revision: 1)), intents: intents) {
                reads += 1; return reads == 1 ? intents : changed
            }
        }
        #expect(reads == 2)
        #expect(try owner.snapshot() == before)
    }

    @Test func freshRefusesExistingV1DirectoryAndOpenRefusesTampering() throws {
        let disk = try Disk(); defer { disk.remove() }
        let f = try Fixture(binding: disk.binding)
        let directory = try disk.root.createDirectory(named: Owner.directoryName)
        try directory.writeExclusiveRegularFile(named: "state.json", data: Data("{\"schema\":1}".utf8))
        #expect(throws: (any Error).self) { _ = try disk.fresh(f) }
        #expect(throws: (any Error).self) { _ = try disk.open(f) }
        #expect(try directory.entryNames() == ["state.json"])
    }

    @Test(arguments: [false, true]) func wrongGenerationAndSymlinkCannotOpen(symlink: Bool) throws {
        let disk = try Disk(); defer { disk.remove() }
        let f = try Fixture(binding: disk.binding)
        var owner: Owner? = try disk.fresh(f)
        #expect(owner != nil); owner = nil
        if symlink {
            let directory = try disk.root.openDirectory(named: Owner.directoryName)
            let path = directory.url.appending(path: "state.json").path
            try FileManager.default.moveItem(atPath: path, toPath: path + ".saved")
            try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: path + ".saved")
            #expect(throws: (any Error).self) { _ = try disk.open(f) }
        } else {
            let generation = try Wire.Identity(store: f.identity.store, generation: 2, binding: f.identity.binding)
            #expect(throws: (any Error).self) { _ = try Owner.open(in: disk.root, backingDescriptor: disk.backing,
                identity: generation, rootPublicKey: f.root.publicKey.rawRepresentation, provenanceReference: f.provenance) }
        }
    }

    @Test(arguments: [HostStorageIntentCommit.Step.initialProofDirectorySync, .statePublish, .proofDeletionDirectorySync])
    func failedPublicationPoisonsAndReopenNeverCleansMarkers(step: HostStorageIntentCommit.Step) throws {
        let disk = try Disk(); defer { disk.remove() }
        let f = try Fixture(binding: disk.binding)
        var owner: Owner? = try disk.fresh(f, hook: { actual, moment in
            if actual == step, case .after = moment { throw Owner.Failure.repairRequired }
        })
        let initial = try owner!.snapshot().pending!, intents = f.intents()
        #expect(throws: (any Error).self) { try owner!.persist(.complete(f.receipt(initial, revision: 1)), intents: intents, readIntents: { intents }) }
        #expect(throws: (any Error).self) { _ = try owner!.snapshot() }
        owner = nil
        let directory = try disk.root.openDirectory(named: Owner.directoryName), before = try directory.entryNames()
        #expect(before.contains("uncertain"))
        #expect(throws: (any Error).self) { _ = try disk.open(f) }
        #expect(try directory.entryNames() == before)
    }

    nonisolated private static func id() -> String { UUID().uuidString.lowercased() }
    private func id() -> String { Self.id() }

    private struct Fixture {
        let root = Curve25519.Signing.PrivateKey()
        let identity: Wire.Identity
        let provenance = String(repeating: "a", count: 64)
        init(binding: StorageIdentity.StoreBinding? = nil) throws {
            if let binding { identity = try .init(binding: binding, generation: 1) }
            else { identity = try .init(store: ManagedStorageLifecycleCheckpointTests.id(), generation: 1, binding: String(repeating: "b", count: 64)) }
        }
        @MainActor func grant(_ operation: Wire.Operation, epoch: UInt64, serial: UInt64,
                             identity: Wire.Identity? = nil, recipient: Owner.Recipient? = nil, service: String? = nil) throws -> Owner.GrantContext {
            let candidate = recipient ?? .init(publicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation,
                incarnation: ManagedStorageLifecycleCheckpointTests.id(), daemonUniqueID: serial * 2,
                childUniqueID: serial * 2 + 1, childPID: 42)
            let grant = try Wire.Grant(operation: operation, id: ManagedStorageLifecycleCheckpointTests.id(), identity: identity ?? self.identity,
                serial: serial, expectedEpoch: epoch, newKey: StorageIdentity.Ed25519SPKI(rawPublicKey: candidate.publicKey).fingerprint.rawValue)
            return try .init(signed: .init(grant: grant, signature: root.signature(for: grant.signingBytes)), recipient: candidate,
                requestID: ManagedStorageLifecycleCheckpointTests.id(),
                serviceEpoch: operation == .initialize ? service : service ?? ManagedStorageLifecycleCheckpointTests.id())
        }
        @MainActor func baseline() throws -> Owner.Metadata {
            try Owner.baseline(identity: identity, rootPublicKey: root.publicKey.rawRepresentation, provenanceReference: provenance,
                initialize: grant(.initialize, epoch: 0, serial: 1))
        }
        @MainActor func completed() throws -> Owner.Metadata {
            let state = try baseline()
            return try Owner.applying(.complete(receipt(state.pending!, revision: 1)), to: state, intents: intents())
        }
        @MainActor func service(_ state: Owner.Metadata, epoch: String? = nil, revision: UInt64? = nil,
                                bootstrapKey: String? = nil) throws -> Wire.ServiceState {
            let live = state.currentContext!, serviceEpoch = epoch ?? live.serviceEpoch
            return try .init(grant: state.current!.original.signed.grant,
                context: .init(serviceEpoch: serviceEpoch, controllerEpoch: live.controllerEpoch, controllerKey: live.controllerKey),
                openRevision: revision ?? state.current!.directResult.revision,
                boot: .init(identity: state.identity, serviceEpoch: serviceEpoch,
                    tlsRootSHA256: HostStorageIntents.hash(Data(ManagedStorageLifecycleCheckpointTests.id().utf8)),
                    serverSPKI: HostStorageIntents.hash(Data(ManagedStorageLifecycleCheckpointTests.id().utf8)),
                    bootstrapKey: bootstrapKey ?? StorageIdentity.RootPublicKey(publicData: root.publicKey.rawRepresentation).fingerprint.rawValue))
        }
        @MainActor func pendingService(_ state: Owner.Metadata) throws -> Owner.PendingService {
            try .init(request: .init(operationID: ManagedStorageLifecycleCheckpointTests.id(), predecessor: state.currentService!),
                stageRequestID: ManagedStorageLifecycleCheckpointTests.id(), completionRequestID: ManagedStorageLifecycleCheckpointTests.id(),
                predecessorWorkerUUID: ManagedStorageLifecycleCheckpointTests.id(), nowUnixSeconds: 100, lifetimeSeconds: 60)
        }
        @MainActor func confirmation(_ pending: Owner.PendingService, state: Owner.Metadata,
                                    revision: UInt64? = nil) throws -> Wire.ServiceChangeConfirmation {
            try .init(request: pending.request,
                successor: service(state, epoch: ManagedStorageLifecycleCheckpointTests.id(),
                    revision: revision ?? pending.request.predecessor.openRevision + 1))
        }
        @MainActor func changeService(_ state: Owner.Metadata, revision: UInt64,
                                     intents: HostStorageIntents.State) throws -> Owner.Metadata {
            let pending = try pendingService(state)
            let staged = try Owner.applying(.stageService(pending), to: state, intents: intents)
            return try Owner.applying(.confirmService(confirmation(pending, state: staged, revision: revision)), to: staged, intents: intents)
        }
        func receipt(_ pending: Owner.GrantContext, revision: UInt64, service: String? = nil,
                     nonce: Data = Data(repeating: 7, count: 32)) throws -> Wire.Receipt {
            try .init(grant: pending.signed.grant, nonce: nonce,
                serviceEpoch: service ?? pending.serviceEpoch ?? ManagedStorageLifecycleCheckpointTests.id(), revision: revision)
        }
        func intents() -> HostStorageIntents.State {
            .init(schema: 2, store: identity.store, revision: 1, volumes: [:], intents: [:], operations: [:], operationDigests: [:], reconciliationRequired: true)
        }
        func intent(_ context: Owner.Context) -> HostStorageIntents.Intent {
            .init(id: ManagedStorageLifecycleCheckpointTests.id(), store: identity.store, container: provenance,
                containerInstance: ManagedStorageLifecycleCheckpointTests.id(), launch: ManagedStorageLifecycleCheckpointTests.id(), specificationDigest: provenance,
                serviceEpoch: context.serviceEpoch, controllerEpoch: context.controllerEpoch, controllerKey: context.controllerKey,
                prepare: ManagedStorageLifecycleCheckpointTests.id(), reserveOperation: ManagedStorageLifecycleCheckpointTests.id(),
                completeOperation: ManagedStorageLifecycleCheckpointTests.id(), replaceOperation: ManagedStorageLifecycleCheckpointTests.id(),
                mounts: [], slots: [], version: 1, phase: .quarantined, prepareCompleted: false, cleanUnmount: false)
        }
    }
    @MainActor private final class Disk {
        let url: URL
        let root: PersistentStateDirectory
        let backing: Int32
        let binding: StorageIdentity.StoreBinding
        init() throws {
            url = FileManager.default.temporaryDirectory.appending(path: "cengine-lifecycle-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            root = try PersistentStateDirectory.open(url)
            _ = try root.createSparseRegularFile(named: "disk", size: 4096)
            backing = openat(root.descriptor, "disk", O_RDWR | O_CLOEXEC | O_NOFOLLOW)
            guard backing >= 0 else { throw Owner.Failure.invalid }
            let disk = try PersistentFileIdentity.capture(descriptor: backing)
            binding = StorageIdentity.StoreBinding(storeID: try .init(ManagedStorageLifecycleCheckpointTests.id()),
                root: try .init(volumeUUID: .init(root.identity.volumeUUID!.uuidString.lowercased()), inode: root.identity.inode),
                backing: try .init(identity: .init(volumeUUID: .init(disk.volumeUUID!.uuidString.lowercased()), inode: disk.inode), size: 4096),
                expectedExt4UUID: try .init(ManagedStorageLifecycleCheckpointTests.id()))
        }
        deinit { Darwin.close(backing) }
        func remove() { try? FileManager.default.removeItem(at: url) }
        func fresh(_ f: Fixture, hook: HostStorageIntentCommit.Hook? = nil) throws -> Owner {
            try Owner.fresh(in: root, backingDescriptor: backing, binding: binding, rootPublicKey: f.root.publicKey.rawRepresentation,
                provenanceReference: f.provenance, initialize: f.grant(.initialize, epoch: 0, serial: 1), commitHook: hook)
        }
        func open(_ f: Fixture, hook: HostStorageIntentCommit.Hook? = nil) throws -> Owner {
            try Owner.open(in: root, backingDescriptor: backing, identity: f.identity, rootPublicKey: f.root.publicKey.rawRepresentation,
                provenanceReference: f.provenance, commitHook: hook)
        }
    }
}
#endif

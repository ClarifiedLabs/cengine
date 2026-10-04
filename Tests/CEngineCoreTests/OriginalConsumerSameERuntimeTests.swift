#if os(macOS)
import CEngineCore
import Foundation
import Testing
@testable import CEngineRuntime

@MainActor @Suite struct OriginalConsumerSameERuntimeTests {
    typealias L = ManagedVolumeLifecycleCoordinator
    typealias C = ManagedStorageControlClient
    let store = "11111111-1111-4111-8111-111111111111"
    let epoch = "22222222-2222-4222-8222-222222222222"
    let volume = "33333333-3333-4333-8333-333333333333"
    let attachment = "44444444-4444-4444-8444-444444444444"
    let operation = "55555555-5555-4555-8555-555555555555"
    let key = String(repeating: "ab", count: 32)

    @Test(arguments: [OriginalConsumerObservationProtocol.Case.sameEExistingData, .sameEOldLeafReconnect])
    func checkedPositiveWithNoServerDigestCorrelatesOnlyToSealedProbePeer(_ name: OriginalConsumerObservationProtocol.Case) throws {
        typealias G = OriginalConsumerObservationProtocol
        let fixture = SameEConsumerObservationProtocolTests()
        let (binding, begun, negative, observed) = fixture.fixture(name)
        var armed = begun; armed.stage = "armed-mounted-positive"
        let arm = try #require(G.checkedReply(JSONEncoder().encode(armed),
            request: fixture.request(binding, .arm)).evidence)
        let positive = try #require(G.checkedReply(JSONEncoder().encode(begun),
            request: fixture.request(binding, .begin), previous: arm).evidence)
        let probeRequest = try fixture.request(binding, .probe)
        let probe = try JSONDecoder().decode(G.Probe.self, from: probeRequest.payload)
        let result = try #require(G.checkedReply(JSONEncoder().encode(negative),
            request: probeRequest, previous: positive).evidence)
        #expect(positive.serverDERSHA256.isEmpty)
        #expect(!result.serverDERSHA256.isEmpty)
        try ManagedStorageOriginalConsumerComparison.correlateSameE(observed, positive: positive, result: result,
            scope: binding.scope, peer: probe.peer)
        var changed = probe.peer; changed.serverDER = Data([9])
        #expect(throws: (any Error).self) {
            try ManagedStorageOriginalConsumerComparison.correlateSameE(observed, positive: positive, result: result,
                scope: binding.scope, peer: changed)
        }
        var missing = result; missing.serverDERSHA256 = ""
        #expect(throws: (any Error).self) {
            try ManagedStorageOriginalConsumerComparison.correlateSameE(observed, positive: positive, result: missing,
                scope: binding.scope, peer: probe.peer)
        }
    }

    @Test(arguments: [OriginalConsumerObservationProtocol.Case.sameEExistingData, .sameEOldLeafReconnect, .sameERetainedFD])
    func liveLifecycleRetiresThenQueriesBeforePublishingExactReceipt(_ name: OriginalConsumerObservationProtocol.Case) async throws {
        let f = try SameERetirementFixture(); defer { f.files.remove() }
        let running = try await f.start()
        let binding = try f.binding(running, name: name)
        let slot = try #require(running.slots.first { $0.attachment == binding.targetAttachment })
        let callbacks = f.control.events
        let proof = try await f.coordinator.retireOriginalConsumer(binding, revalidate: {})
        #expect(proof.operation == slot.retireOperation && proof.operation != binding.operationUUID)
        #expect(Array(f.control.events.dropFirst(callbacks.count)) == ["journal-" + slot.retireOperation,
            "retire-" + slot.attachment, "query"])
        let persisted = try f.persisted()
        var expected = running
        expected.version += 1
        expected.slots[try #require(expected.slots.firstIndex { $0.attachment == slot.attachment })].receipt = .init(proof.receipt)
        #expect(persisted.intents[running.id] == expected)
        #expect(proof.attachment.binding == (try slot.binding(store: running.store, prepare: running.prepare,
            container: running.container, launch: running.launch)))
        #expect(try f.journal.replayRequest(operation: slot.retireOperation).durableBytes() == persisted.operations[slot.retireOperation])
        #expect(!f.control.wasRevoked && !f.control.wasInvalidated)
        // Only Retire/Query ran: no mount, closePrepare, stop or publication callback.
        #expect(f.control.events.filter { $0.hasPrefix("guest-") } == callbacks.filter { $0.hasPrefix("guest-") })
    }

    @Test(arguments: ["scope", "context", "cancel-before", "owner-before", "owner-after-retire", "owner-after-query", "receipt", "receipt-launch", "query-receipt"])
    func lifecycleRejectsScopeOwnerCancellationAndUnreconciledReceipt(_ fault: String) async throws {
        let f = try SameERetirementFixture(); defer { f.files.remove() }
        let running = try await f.start()
        let binding = try f.binding(running, changedScope: fault == "scope")
        let before = f.control.events.count
        if fault == "context" { try f.control.changeContext() }
        f.control.setFault(fault)
        var checks = 0
        let operation = Task {
            if fault == "cancel-before" { withUnsafeCurrentTask { $0?.cancel() } }
            return try await f.coordinator.retireOriginalConsumer(binding) {
                checks += 1
                if (fault == "owner-before" && checks == 1) || (fault == "owner-after-retire" && checks == 2)
                    || (fault == "owner-after-query" && checks == 3) { throw L.Failure.staleExecution }
            }
        }
        await #expect(throws: (any Error).self) { try await operation.value }
        let state = try f.persisted()
        #expect(state.intents[running.id] == running)
        let events = Array(f.control.events.dropFirst(before))
        if ["scope", "context", "cancel-before", "owner-before"].contains(fault) { #expect(events.isEmpty) }
        if fault == "owner-after-retire" { #expect(!events.contains("query")) }
        if ["receipt", "receipt-launch", "query-receipt", "owner-after-query"].contains(fault) { #expect(events.last == "query") }
    }

    @Test(arguments: ["retire", "query"], [false, true])
    func revocationAndCancellationJoinSubmittedTransportWithoutPublishing(boundary: String, invalidate: Bool) async throws {
        let f = try SameERetirementFixture(); defer { f.files.remove() }
        let running = try await f.start(), binding = try f.binding(running)
        let gate = f.control.block(boundary)
        defer { gate.release.signal() }
        var returned = false
        let operation = Task {
            defer { returned = true }
            return try await f.coordinator.retireOriginalConsumer(binding, revalidate: {})
        }
        for await _ in gate.started.stream { break }
        if invalidate {
            let release = Task { @MainActor in
                #expect(f.control.wasRevoked)
                #expect(!returned && !f.control.wasInvalidated)
                gate.release.signal()
            }
            await f.coordinator.invalidate()
            await release.value
            await #expect(throws: L.Failure.staleExecution) { try await operation.value }
            #expect(f.control.wasInvalidated)
        } else {
            operation.cancel()
            let release = Task { @MainActor in
                #expect(!returned)
                gate.release.signal()
            }
            await #expect(throws: CancellationError.self) { try await operation.value }
            await release.value
        }
        #expect(returned && gate.completed)
        #expect(try f.persisted().intents[running.id] == running)
        if boundary == "retire" { #expect(!f.control.events.contains("query")) }
    }

    @Test func diagnosedCancellationStillJoinsActualRetirementLease() async throws {
        typealias D = OriginalConsumerFailureDiagnostic
        let f = try SameERetirementFixture(); defer { f.files.remove() }
        let running = try await f.start(), binding = try f.binding(running)
        let gate = f.control.block("retire"); defer { gate.release.signal() }
        var returned = false
        let task = Task {
            defer { returned = true }
            return try await D.step(.originalRetire) {
                try await f.coordinator.retireOriginalConsumer(binding, revalidate: {})
            }
        }
        for await _ in gate.started.stream { break }
        task.cancel()
        #expect(!returned && !gate.completed)
        gate.release.signal()
        do { _ = try await task.value; Issue.record("expected cancellation") }
        catch {
            #expect(D.underlying(error) is CancellationError)
            #expect(D.find(in: error) == D(stage: .originalRetire, error: CancellationError()))
        }
        #expect(returned && gate.completed)
        #expect(try f.persisted().intents[running.id] == running)
        #expect(!f.control.events.contains("query"))
    }

    @Test(arguments: [OriginalConsumerObservationProtocol.Case.crossMountRootGrant, .retiredRootGrantReplay])
    func rootAuthorityHoldsBothSlotsAcrossActualRetireAndProbe(_ name: OriginalConsumerObservationProtocol.Case) async throws {
        let f = try SameERetirementFixture(roots: true); defer { f.files.remove() }
        let running = try await f.start(), binding = try f.binding(running, name: name)
        let target = try f.rootTarget(running)
        let start = f.control.events.count
        var probed = false
        let proof = try await f.coordinator.withOriginalRootAuthority(binding, target: target,
            revalidate: { retirement in
                _ = try ManagedStorageOriginalConsumerComparison.originalConsumerTuple(binding,
                    intent: f.persisted().intents[running.id], retiredReceipt: retirement?.receipt)
            }, probe: { retirement in
                probed = true
                #expect((retirement != nil) == (name == .retiredRootGrantReplay))
                let current = try f.persisted().intents[running.id]
                #expect(current?.slots.first(where: { $0.attachment == target.binding.attachment })?.receipt == nil)
                await #expect(throws: (any Error).self) {
                    try await f.coordinator.withOriginalRootAuthority(binding, target: target,
                        revalidate: { _ in }, probe: { _ in })
                }
            })
        #expect(probed && proof.after == proof.atProbe)
        #expect(proof.before.attachments[target.binding.attachment] == proof.after.attachments[target.binding.attachment])
        #expect(proof.before.volumes == proof.after.volumes)
        let events = Array(f.control.events.dropFirst(start))
        if let retirement = proof.retirement {
            #expect(events == ["query", "journal-" + retirement.operation,
                "retire-" + binding.targetAttachment, "query", "query"])
        } else { #expect(events == ["query", "query"] && proof.before == proof.after) }
    }

    @Test(arguments: ["target", "shared-root", "target-drained", "probe-throws", "probe-cancel", "query-receipt", "stale-retire-revision", "post-probe-revision"])
    func rootAuthorityRejectsWrongPairAndFailedOrMutatingProbe(_ fault: String) async throws {
        let f = try SameERetirementFixture(roots: true); defer { f.files.remove() }
        let running = try await f.start(), binding = try f.binding(running, name: .retiredRootGrantReplay)
        var target = try f.rootTarget(running)
        if fault == "target" { target.binding.key = String(repeating: "0", count: 64) }
        f.control.setFault(fault)
        var probed = false
        let operation = Task {
            try await f.coordinator.withOriginalRootAuthority(binding, target: target,
                revalidate: { _ in }, probe: { _ in
                    probed = true
                    if fault == "probe-throws" { throw L.Failure.wrongEvidence }
                    if fault == "probe-cancel" { withUnsafeCurrentTask { $0?.cancel() } }
                    if fault == "post-probe-revision" { f.control.setFault("changed-revision") }
                })
        }
        await #expect(throws: (any Error).self) { try await operation.value }
        #expect(probed == ["probe-throws", "probe-cancel", "post-probe-revision"].contains(fault))
        let persisted = try #require(f.persisted().intents[running.id])
        let source = try #require(persisted.slots.first { $0.attachment == binding.targetAttachment })
        #expect((source.receipt != nil) == probed)
        #expect(persisted.slots.first { $0.attachment == target.binding.attachment }?.receipt == nil)
    }

    @Test(arguments: ["query", "retire"], [false, true])
    func rootCancellationAndRevocationJoinSubmittedControl(boundary: String, invalidate: Bool) async throws {
        let f = try SameERetirementFixture(roots: true); defer { f.files.remove() }
        let running = try await f.start(), binding = try f.binding(running, name: .retiredRootGrantReplay)
        let target = try f.rootTarget(running), gate = f.control.block(boundary)
        defer { gate.release.signal() }
        var returned = false, probed = false
        let task = Task {
            defer { returned = true }
            return try await f.coordinator.withOriginalRootAuthority(binding, target: target,
                revalidate: { _ in }, probe: { _ in probed = true })
        }
        for await _ in gate.started.stream { break }
        if invalidate {
            let release = Task { @MainActor in
                #expect(f.control.wasRevoked && !returned && !f.control.wasInvalidated)
                gate.release.signal()
            }
            await f.coordinator.invalidate(); await release.value
            await #expect(throws: L.Failure.staleExecution) { try await task.value }
        } else {
            task.cancel()
            let release = Task { @MainActor in
                #expect(!returned); gate.release.signal()
            }
            await #expect(throws: CancellationError.self) { try await task.value }
            await release.value
        }
        #expect(returned && gate.completed && !probed)
        #expect(try f.persisted().intents[running.id] == running)
    }

    @Test(arguments: [OriginalConsumerObservationProtocol.Case.attachmentKeyReuse, .delayedRegistration])
    func registrationControlRequiresRealRetirementAndUnchangedRegistry(_ name: OriginalConsumerObservationProtocol.Case) async throws {
        let f = try SameERetirementFixture(); defer { f.files.remove() }
        let running = try await f.start(), binding = try f.binding(running, name: name)
        let proof = try await f.coordinator.observeOriginalRegistration(binding, revalidate: { receipt in
            _ = try ManagedStorageOriginalConsumerComparison.originalConsumerTuple(binding,
                intent: f.persisted().intents[running.id], retiredReceipt: receipt?.receipt)
        })
        let retirement = try #require(proof.authority.retirement)
        let slot = try #require(running.slots.first { $0.attachment == binding.targetAttachment })
        #expect(proof.authority.after == proof.authority.atProbe)
        #expect(retirement.operation == slot.retireOperation)
        #expect(proof.attempted.key == binding.key && proof.attempted.volume == slot.volume)
        #expect(proof.denial == (name == .attachmentKeyReuse ? "CONFLICT" : "BLOCKED"))
        #expect((proof.attempted.attachment == slot.attachment) == (name == .delayedRegistration))
        #expect((proof.operation == slot.registerOperation) == (name == .delayedRegistration))
        #expect(try f.persisted().intents[running.id]?.slots.first(where: { $0.attachment == slot.attachment })?.receipt == .init(retirement.receipt))
        #expect(f.control.events.suffix(2) == ["denied-register", "query"])
    }

    @Test(arguments: ["wrong-code", "transport", "success", "changed-after-denial", "query-receipt", "stale-retire-revision", "cancel-before"])
    func registrationControlNeverConvertsFailureOrSuccessToDenial(_ fault: String) async throws {
        let f = try SameERetirementFixture(); defer { f.files.remove() }
        let running = try await f.start(), binding = try f.binding(running, name: .attachmentKeyReuse)
        f.control.setFault(fault)
        let task = Task {
            if fault == "cancel-before" { withUnsafeCurrentTask { $0?.cancel() } }
            return try await f.coordinator.observeOriginalRegistration(binding, revalidate: { _ in })
        }
        await #expect(throws: (any Error).self) { try await task.value }
    }

    @Test(arguments: [false, true])
    func registrationDenialStillJoinsOnCancellationOrRevocation(_ invalidate: Bool) async throws {
        let f = try SameERetirementFixture(); defer { f.files.remove() }
        let running = try await f.start(), binding = try f.binding(running, name: .delayedRegistration)
        let gate = f.control.block("denied-register"); defer { gate.release.signal() }
        var returned = false
        let task = Task {
            defer { returned = true }
            return try await f.coordinator.observeOriginalRegistration(binding, revalidate: { _ in })
        }
        for await _ in gate.started.stream { break }
        if invalidate {
            let release = Task { @MainActor in
                #expect(f.control.wasRevoked && !returned); gate.release.signal()
            }
            await f.coordinator.invalidate(); await release.value
            await #expect(throws: L.Failure.staleExecution) { try await task.value }
        } else {
            task.cancel()
            let release = Task { @MainActor in #expect(!returned); gate.release.signal() }
            await #expect(throws: CancellationError.self) { try await task.value }; await release.value
        }
        #expect(returned && gate.completed && f.control.events.last == "denied-register")
    }

    @Test(arguments: ["valid", "operation", "receipt", "phase", "binding", "epoch", "controller"])
    func independentlyQueriedRetirementMustMatchEveryOriginalField(_ fault: String) throws {
        let context = try C.Context(store: store, serviceEpoch: epoch, controllerEpoch: 1,
            controllerKey: key, provenanceReference: key)
        let binding = try ManagedStorageControlProtocol.Binding(store: store, volume: volume,
            attachment: attachment, container: key, launch: epoch, key: String(repeating: "cd", count: 32),
            role: .runtime, mode: .readOnly)
        let changed = try ManagedStorageControlProtocol.Binding(store: store, volume: volume,
            attachment: attachment, container: key, launch: operation, key: String(repeating: "cd", count: 32),
            role: .runtime, mode: .readOnly)
        let receipt = try ManagedStorageControlProtocol.Receipt(schema: 3, store: store, volume: volume,
            attachment: attachment, launch: binding.launch, revision: 4)
        let other = try ManagedStorageControlProtocol.Receipt(schema: 3, store: store, volume: volume,
            attachment: attachment, launch: binding.launch, revision: 3)
        let query = C.Snapshot(schema: 3, revision: 5,
            store: .init(id: store, deviceID: "owned", root: .init(device: 1, inode: 1), exports: .init(device: 1, inode: 2)),
            epoch: fault == "epoch" ? operation : epoch,
            controller: .init(epoch: fault == "controller" ? 2 : 1, key: key),
            volumes: [volume: .init(id: volume, name: "data", root: .init(device: 1, inode: 3))],
            volumeLifecycles: [volume: .init(phase: .ready, create: nil, delete: nil, createdRevision: nil, deletedRevision: nil)],
            attachments: [attachment: .init(binding: fault == "binding" ? changed : binding,
                phase: fault == "phase" ? .active : .drained,
                receipt: fault == "receipt" ? other : receipt, retirement: fault == "operation" ? epoch : operation)],
            prepares: [:])
        if fault == "valid" {
            let proof = try L.reconcileOriginalRetirement(operation: operation, binding: binding,
                receipt: receipt, query: query, context: context)
            #expect(proof.receipt == receipt)
            #expect(proof.attachment.binding == binding)
            #expect(proof.operation == operation)
            #expect(proof.queryRevision == 5)
        } else {
            #expect(throws: (any Error).self) {
                try L.reconcileOriginalRetirement(operation: operation, binding: binding,
                    receipt: receipt, query: query, context: context)
            }
        }
    }
}

/// Same production coordinator and persisted journal as the established lifecycle
/// harness; only synchronous authenticated-control IO and guest callbacks are fake.
@MainActor private struct SameERetirementFixture {
    let files: HostIntentFixture
    let journal: HostStorageIntents
    let plan: HostStorageIntents.Intent
    let control: SameERetirementControl
    let coordinator: ManagedVolumeLifecycleCoordinator
    init(roots: Bool = false) throws {
        files = try HostIntentFixture()
        journal = try files.initialize()
        try journal.reconciled(); try journal.planVolumes(files.volumes)
        plan = files.intent(roots ? files.volumes : [files.volumes[0]])
        control = try .init(plan: plan, provenance: files.provenance,
            journalURL: files.url.appending(path: "managed-storage/state.json"))
        coordinator = try .init(journal: journal, control: control, names: SharedVolumeInitializationCoordinator())
    }
    func start() async throws -> HostStorageIntents.Intent {
        let control = control
        let guest = ManagedVolumeLifecycleCoordinator.GuestActions(offerKeys: { intent, role in
            control.append("guest-offer-" + role.rawValue)
            return intent.slots.filter { $0.role == role.rawValue }.map {
                .init(attachment: $0.attachment, key: HostStorageIntents.hash(Data($0.attachment.utf8)))
            }
        }, credentialAndMount: { _, role in control.append("guest-mount-" + role.rawValue) }, prepare: { intent in
            control.append("guest-prepare")
            return .init(prepare: intent.prepare, containerInstance: intent.containerInstance, launch: intent.launch,
                succeeded: true, cleanCopyUp: true, evidenceDigest: String(repeating: "e", count: 64))
        }, closePrepare: { _ in control.append("guest-close-prepare"); return true },
            start: { _ in control.append("guest-start") }, beforePublication: { _ in control.append("guest-publication") })
        return try journal.intent(await coordinator.start(plan, guest: guest))
    }
    func rootTarget(_ intent: HostStorageIntents.Intent) throws -> ConsumerObservationProtocol.Original {
        let slots = intent.slots.filter { $0.role == "runtime" }.sorted { $0.attachment < $1.attachment }
        let slot = slots[1]
        return .init(epoch: intent.serviceEpoch, binding: .init(store: intent.store, volume: slot.volume,
            attachment: slot.attachment, container: intent.container, launch: intent.launch,
            key: try #require(slot.key), mode: slot.mode))
    }
    func persisted() throws -> HostStorageIntents.State {
        try JSONDecoder().decode(HostStorageIntents.State.self,
            from: Data(contentsOf: files.url.appending(path: "managed-storage/state.json")))
    }
    func binding(_ intent: HostStorageIntents.Intent, name: OriginalConsumerObservationProtocol.Case = .sameEExistingData,
                 changedScope: Bool = false) throws -> OriginalConsumerObservationProtocol.Binding {
        let slot = try #require(intent.slots.filter { $0.role == "runtime" }.sorted { $0.attachment < $1.attachment }.first)
        return .init(requestID: HostIntentFixture.id(), armDigest: String(repeating: "a", count: 64),
            operationUUID: HostIntentFixture.id(), caseName: name, generation: 7,
            boot: .init(shimLaunchUUID: intent.launch, guestBootNonce: HostIntentFixture.id()),
            scope: .init(intent: intent.id, store: intent.store, serviceEpoch: changedScope ? HostIntentFixture.id() : intent.serviceEpoch,
                controllerEpoch: intent.controllerEpoch, controllerKey: intent.controllerKey, container: intent.container,
                containerInstance: intent.containerInstance, launch: intent.launch, prepare: intent.prepare,
                specificationDigest: intent.specificationDigest), targetAttachment: slot.attachment,
            key: try #require(slot.key), certificateSHA256: String(repeating: "f", count: 64))
    }
}

private final class SameERetirementGate: @unchecked Sendable {
    let started = AsyncStream<Void>.makeStream()
    let release = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var done = false
    var completed: Bool { lock.withLock { done } }
    func finish() { lock.withLock { done = true } }
}

private final class SameERetirementControl: ManagedStorageControlling, @unchecked Sendable {
    typealias C = ManagedStorageControlClient
    typealias P = ManagedStorageControlProtocol
    private let lock = NSLock()
    private var current: C.Context
    var context: C.Context { lock.withLock { current } }
    private let plan: HostStorageIntents.Intent
    private let journalURL: URL
    private var log: [String] = []
    private var fault = ""
    private var gate: (String, SameERetirementGate)?
    private var retired: [String: P.Receipt] = [:]
    private var revoked = false
    private var invalidated = false
    var events: [String] { lock.withLock { log } }
    var wasRevoked: Bool { lock.withLock { revoked } }
    var wasInvalidated: Bool { lock.withLock { invalidated } }
    init(plan: HostStorageIntents.Intent, provenance: String, journalURL: URL) throws {
        self.plan = plan; self.journalURL = journalURL
        current = try .init(store: plan.store, serviceEpoch: plan.serviceEpoch, controllerEpoch: plan.controllerEpoch,
            controllerKey: plan.controllerKey, provenanceReference: provenance)
    }
    func append(_ event: String) { lock.withLock { log.append(event) } }
    func setFault(_ fault: String) { lock.withLock { self.fault = fault } }
    func changeContext() throws {
        try lock.withLock { current = try .init(store: current.store, serviceEpoch: current.serviceEpoch,
            controllerEpoch: current.controllerEpoch + 1, controllerKey: current.controllerKey,
            provenanceReference: current.provenanceReference) }
    }
    func block(_ boundary: String) -> SameERetirementGate {
        let selected = SameERetirementGate(); lock.withLock { gate = (boundary, selected) }; return selected
    }
    func revoke() { lock.withLock { revoked = true } }
    func invalidate() async { lock.withLock { invalidated = true } }
    func send(_ request: P.ControlRequest) throws -> C.Reply {
        let (reply, selected): (Result<C.Reply, Error>, SameERetirementGate?) = try lock.withLock {
            let state = try JSONDecoder().decode(HostStorageIntents.State.self, from: Data(contentsOf: journalURL))
            let intent = try #require(state.intents[plan.id])
            let operation: String?
            let boundary: String
            switch request {
            case .createVolume(let r): operation = r.operation; boundary = "create"
            case .reservePrepare(let r): operation = r.operation; boundary = "reserve"
            case .registerAttachment(let r): operation = r.operation; boundary = "register"
            case .completePrepare(let r): operation = r.operation; boundary = "complete"
            case .retire(let r): operation = r.operation; boundary = "retire"
            case .query: operation = nil; boundary = "query"
            default: throw C.Failure.invalidRequest
            }
            if case .registerAttachment(let r) = request,
               let original = intent.slots.first(where: { $0.role == "runtime" && $0.key == r.binding.key }),
               retired[original.attachment] != nil {
                log.append("denied-register")
                let selected = gate?.0 == "denied-register" ? gate?.1 : nil
                if selected != nil { gate = nil }
                if fault == "success" { return (.success(.ok), selected) }
                if fault == "transport" { return (.failure(C.Failure.poisoned), selected) }
                let code = fault == "wrong-code" ? "UNAUTHORIZED" : (r.binding.attachment == original.attachment ? "BLOCKED" : "CONFLICT")
                return (.failure(C.Failure.remote(code)), selected)
            }
            if let operation {
                let bytes = try request.durableBytes()
                guard state.operations[operation] == bytes,
                      state.operationDigests[operation] == HostStorageIntents.hash(bytes) else { throw C.Failure.invalidRequest }
                log.append("journal-" + operation)
            }
            let reply: C.Reply
            switch request {
            case .createVolume(let r):
                reply = .volumeReceipt(.init(schema: 3, operation: r.operation, store: current.store,
                    volume: .init(id: r.volume, name: r.name, root: .init(device: 1,
                        inode: 100 + UInt64(plan.slots.filter { $0.role == "runtime" }.map(\.volume).sorted().firstIndex(of: r.volume)!))), phase: .ready, revision: 2))
            case .retire(let r):
                let slot = try #require(intent.slots.first { $0.attachment == r.attachment })
                guard slot.receipt == nil else { throw C.Failure.invalidRequest }
                log.append("retire-" + r.attachment)
                let exact = try P.Receipt(schema: 3, store: current.store, volume: r.volume, attachment: r.attachment,
                    prepare: slot.role == "prepare" ? intent.prepare : nil, launch: intent.launch,
                    revision: slot.role == "prepare" || fault == "stale-retire-revision" ? 4 : 6)
                retired[r.attachment] = exact
                reply = .receipt(fault == "receipt" || fault == "receipt-launch" ? try .init(schema: 3,
                    store: current.store, volume: r.volume, attachment: r.attachment,
                    launch: fault == "receipt-launch" ? "66666666-6666-4666-8666-666666666666" : intent.launch,
                    revision: 3) : exact)
            case .query:
                log.append("query")
                var attachments: [String: C.Attachment] = [:]
                for slot in intent.slots {
                    let receipt = retired[slot.attachment]
                    if slot.role == "runtime", let recorded = slot.receipt {
                        guard receipt.map(HostStorageIntents.DrainReceipt.init) == recorded else { throw C.Failure.invalidRequest }
                    }
                    attachments[slot.attachment] = .init(binding: try slot.binding(store: intent.store,
                        prepare: intent.prepare, container: intent.container, launch: intent.launch),
                        phase: fault == "target-drained" && slot.attachment == intent.slots.filter({ $0.role == "runtime" }).map(\.attachment).sorted().last ? .drained : (receipt == nil ? .active : .drained),
                        receipt: fault == "query-receipt" && slot.role == "runtime" ? try .init(schema: 3,
                            store: current.store, volume: slot.volume, attachment: slot.attachment,
                            launch: intent.launch, revision: 3) : receipt,
                        retirement: receipt == nil ? nil : slot.retireOperation)
                }
                let volumes = state.volumes.values.filter { $0.createdRevision != nil }
                let prepareBindings = try intent.slots.filter { $0.role == "prepare" }.sorted { $0.volume < $1.volume }.map {
                    try $0.binding(store: intent.store, prepare: intent.prepare, container: intent.container, launch: intent.launch)
                }
                let hasRetiredRuntime = intent.slots.contains { $0.role == "runtime" && retired[$0.attachment] != nil }
                reply = .snapshot(.init(schema: 3, revision: fault == "changed-revision" || (fault == "changed-after-denial" && log.contains("denied-register")) ? 8 : (hasRetiredRuntime ? 7 : 5),
                    store: .init(id: current.store, deviceID: "device", root: .init(device: 1, inode: 1), exports: .init(device: 1, inode: 2)),
                    epoch: current.serviceEpoch, controller: .init(epoch: current.controllerEpoch, key: current.controllerKey),
                    volumes: Dictionary(uniqueKeysWithValues: volumes.map { ($0.id, .init(id: $0.id, name: $0.name, root: .init(device: 1, inode: fault == "shared-root" ? 100 : 100 + UInt64(plan.slots.filter { $0.role == "runtime" }.map(\.volume).sorted().firstIndex(of: $0.id)!)))) }),
                    volumeLifecycles: Dictionary(uniqueKeysWithValues: volumes.map { ($0.id, .init(phase: .ready,
                        create: $0.createOperation, delete: nil, createdRevision: $0.createdRevision, deletedRevision: nil)) }),
                    attachments: attachments, prepares: [intent.prepare: .init(id: intent.prepare, attachments: prepareBindings,
                        phase: .completed, successor: nil, attestation: try .init(prepare: intent.prepare, succeeded: true, cleanCopyUp: true))]))
            default: reply = .ok
            }
            let selected = gate?.0 == boundary ? gate?.1 : nil
            if selected != nil { gate = nil }
            return (.success(reply), selected)
        }
        if let selected {
            defer { selected.finish() }
            selected.started.continuation.yield(())
            guard selected.release.wait(timeout: .now() + 10) == .success else { throw C.Failure.remote("TIMEOUT") }
        }
        return try reply.get()
    }
}
#endif

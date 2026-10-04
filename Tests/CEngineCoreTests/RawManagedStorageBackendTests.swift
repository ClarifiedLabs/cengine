#if os(macOS)
import CEngineCore
import CryptoKit
import Foundation
import Testing
@testable import CEngineRuntime

@Suite @MainActor struct RawManagedStorageBackendTests {
    private typealias Backend = RawManagedStorageBackend
    private typealias Journal = HostStorageIntents
    private static let volumeA = "11111111-1111-4111-8111-111111111111"
    private static let volumeB = "22222222-2222-4222-8222-222222222222"
    private static let containerID = String(repeating: "b", count: 64)
    @Test func freshLifecyclePreflightIsIdempotentAndDoesNotCreateASelector() throws {
        let f = try RawManagedStorageDirectory(); defer { f.remove() }
        let before = try StoragePreflightSnapshot(f.url)
        for _ in 0..<2 {
            #expect(try ManagedStorageLifecycleOwner.classify(root: f.root) == .fresh)
            try ManagedLifecycleStartup.preflight(root: f.root)
            #expect(try StoragePreflightSnapshot(f.url) == before)
        }
        #expect(try f.root.entryNames().isEmpty)
    }

    // Retired on-disk bytes are fixtures, not a selectable runtime configuration.
    private struct RetiredSelection: Encodable {
        let schema: Int
        let mode: String
        let root: PersistentFileIdentity
    }

    @Test(arguments: [0, 1, 2], ["legacy", "managed"])
    func retiredSelectionIsRefusedWithoutChangingEvidence(schema: Int, mode: String) throws {
        let f = try RawManagedStorageDirectory(); defer { f.remove() }
        let bytes = try JSONEncoder().encode(RetiredSelection(schema: schema, mode: mode, root: f.root.identity))
        try f.root.writeExclusiveRegularFile(named: "shared-storage-mode.json", data: bytes)
        let before = try StoragePreflightSnapshot(f.url)
        for _ in 0..<2 {
            #expect(throws: ManagedStorageLifecycleOwner.UnsupportedStoreFormat.self) {
                try ManagedLifecycleStartup.preflight(root: f.root)
            }
            #expect(try StoragePreflightSnapshot(f.url) == before)
        }
    }

    @Test func copiedRetiredSelectionCannotAuthorizeAnotherRoot() throws {
        let first = try RawManagedStorageDirectory(); defer { first.remove() }
        let second = try RawManagedStorageDirectory(); defer { second.remove() }
        #expect(first.root.identity != second.root.identity)
        let bytes = try JSONEncoder().encode(RetiredSelection(schema: 1, mode: "managed", root: first.root.identity))
        try first.root.writeExclusiveRegularFile(named: "shared-storage-mode.json", data: bytes)
        try second.root.writeExclusiveRegularFile(named: "shared-storage-mode.json", data: bytes)
        let original = try StoragePreflightSnapshot(first.url), copied = try StoragePreflightSnapshot(second.url)
        #expect(throws: ManagedStorageLifecycleOwner.UnsupportedStoreFormat.self) {
            try ManagedLifecycleStartup.preflight(root: second.root)
        }
        #expect(try StoragePreflightSnapshot(first.url) == original)
        #expect(try StoragePreflightSnapshot(second.url) == copied)
    }

    @Test(arguments: ["infrastructure", "containers", "volumes", "managed-storage-owner", "managed-storage", "storage-intents"])
    func lifecyclePreflightRejectsExistingStorageWithoutChangingEvidence(name: String) throws {
        let f = try RawManagedStorageDirectory(); defer { f.remove() }
        let directory = try f.root.createDirectory(named: name)
        try directory.writeExclusiveRegularFile(named: name == "infrastructure" ? "volumes.ext4" : "existing",
            data: Data("existing storage evidence".utf8))
        let before = try StoragePreflightSnapshot(f.url)
        #expect(throws: ManagedStorageLifecycleOwner.UnsupportedStoreFormat.self) {
            try ManagedLifecycleStartup.preflight(root: f.root)
        }
        #expect(try StoragePreflightSnapshot(f.url) == before)
        #expect(try f.root.readRegularFile(named: "shared-storage-mode.json", required: false) == nil)
    }

    @Test func lifecyclePreflightAllowsEmptyRuntimeDirectoriesButRejectsVolumeSelection() throws {
        let f = try RawManagedStorageDirectory(); defer { f.remove() }
        for name in ["infrastructure", "containers", "volumes"] {
            _ = try f.root.createDirectory(named: name)
        }
        let empty = try StoragePreflightSnapshot(f.url)
        try ManagedLifecycleStartup.preflight(root: f.root)
        #expect(try StoragePreflightSnapshot(f.url) == empty)
        try f.root.writeExclusiveRegularFile(named: "volume-storage.json", data: Data("{}".utf8))
        let existing = try StoragePreflightSnapshot(f.url)
        #expect(throws: ManagedStorageLifecycleOwner.UnsupportedStoreFormat.self) {
            try ManagedLifecycleStartup.preflight(root: f.root)
        }
        #expect(try StoragePreflightSnapshot(f.url) == existing)
    }

    @Test(arguments: ["managed-storage-owner", "managed-storage", "storage-intents"])
    func lifecyclePreflightRejectsEmptyPartialManagedState(name: String) throws {
        let f = try RawManagedStorageDirectory(); defer { f.remove() }
        _ = try f.root.createDirectory(named: name)
        let before = try StoragePreflightSnapshot(f.url)
        #expect(throws: ManagedStorageLifecycleOwner.UnsupportedStoreFormat.self) {
            try ManagedLifecycleStartup.preflight(root: f.root)
        }
        #expect(try StoragePreflightSnapshot(f.url) == before)
    }

    @Test func workloadBytesAreExactSortedJSONAndDigestBindsTheWholeSpecification() throws {
        let workload = Self.workload()
        let bytes = try Backend.workloadBytes(workload)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        #expect(bytes == (try encoder.encode(workload)))
        #expect(try JSONDecoder().decode(GuestProtocol.Workload.self, from: bytes) == workload)
        let text = String(decoding: bytes, as: UTF8.self)
        #expect(text.contains("\"annotations\":{\"a-first\":\"/first\",\"z-last\":\"/last\"}"))
        #expect(text.contains("\"hosts\":{\"a-host\":\"192.0.2.1\",\"z-host\":\"192.0.2.2\"}"))
        #expect(text.contains("\"ioClaim\":\"\""))
        #expect(!text.contains("\\/"))
        #expect(!text.contains("managedAttachment"))
        #expect(!text.contains("volumeServer"))
        let plan = try Self.plan(workload)
        let digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        #expect(plan.specificationDigest == digest)
        var reordered = workload
        reordered.annotations = [:]
        reordered.annotations["a-first"] = "/first"
        reordered.annotations["z-last"] = "/last"
        #expect(try Backend.workloadBytes(reordered) == bytes)
        var changed = workload
        changed.arguments.append("different-command")
        #expect(try Self.plan(changed).specificationDigest != plan.specificationDigest)
        changed = workload
        changed.mounts[0].noCopy.toggle()
        #expect(try Self.plan(changed).specificationDigest != plan.specificationDigest)
    }

    @Test func workloadRejectsIOClaimAndLegacyVolumeServerRatherThanSerializingThem() throws {
        var claimed = Self.workload()
        claimed.ioClaim = "private-io-claim-must-not-be-persisted"
        #expect(throws: (any Error).self) { try Backend.workloadBytes(claimed) }
        #expect(throws: (any Error).self) { try Self.plan(claimed) }
        for server in ["", "192.0.2.10:2049"] {
            var legacy = Self.workload()
            legacy.volumeServer = server
            #expect(throws: (any Error).self) { try Backend.workloadBytes(legacy) }
            #expect(throws: (any Error).self) { try Self.plan(legacy) }
        }
    }

    @Test func workloadRejectsCallerSuppliedManagedAttachmentsOnEveryMountKind() throws {
        for index in Self.workload().mounts.indices {
            var workload = Self.workload()
            workload.mounts[index].managedAttachment = Self.id()
            #expect(throws: (any Error).self) { try Backend.workloadBytes(workload) }
            #expect(throws: (any Error).self) { try Self.plan(workload) }
        }
    }

    @Test func workloadRejectsOversizedPrivateFrame() throws {
        var workload = Self.workload()
        workload.arguments = [String(repeating: "x", count: WorkloadStorageProtocol.maximumWorkloadBytes)]
        #expect(throws: (any Error).self) { try Backend.workloadBytes(workload) }
        #expect(throws: (any Error).self) { try Self.plan(workload) }
    }

    @Test func planBindsContainerLaunchAndControllerWithoutInventingAuthority() throws {
        let container = ContainerRecord(id: Self.containerID, name: "docker-name", image: "test")
        let context = try Self.context()
        let launch = Self.id()
        let plan = try Backend.plan(container: container, launch: launch, context: context, workload: Self.workload())
        #expect(plan.container == container.id)
        #expect(plan.containerInstance == container.instanceID.uuidString.lowercased())
        #expect(plan.launch == launch)
        #expect(plan.store == context.store)
        #expect(plan.serviceEpoch == context.serviceEpoch)
        #expect(plan.controllerEpoch == context.controllerEpoch)
        #expect(plan.controllerKey == context.controllerKey)
        #expect(plan.phase == .planned && plan.version == 1)
        #expect(!plan.prepareCompleted && !plan.cleanUnmount)
        #expect(plan.guestCompletion == nil && plan.quarantineReason == nil)
        #expect(plan.predecessor == nil && plan.successor == nil)
        #expect(plan.slots.allSatisfy { $0.key == nil && $0.receipt == nil })
        let scope = Backend.scope(plan)
        #expect(scope == .init(intent: plan.id, store: context.store, serviceEpoch: context.serviceEpoch,
            controllerEpoch: context.controllerEpoch, controllerKey: context.controllerKey,
            container: container.id, containerInstance: container.instanceID.uuidString.lowercased(),
            launch: launch, prepare: plan.prepare, specificationDigest: plan.specificationDigest))
    }

    @Test func mixedMountsDeduplicatePrepareAndEachRuntimeModeWithoutLosingMounts() throws {
        let plan = try Self.plan(Self.workload())
        #expect(plan.mounts == [
            .init(volume: Self.volumeA, destination: "/readonly", subpath: "docs", mode: "read-only"),
            .init(volume: Self.volumeA, destination: "/data", subpath: "", mode: "read-write"),
            .init(volume: Self.volumeA, destination: "/readonly-again", subpath: "other", mode: "read-only"),
            .init(volume: Self.volumeA, destination: "/data-again", subpath: "", mode: "read-write"),
            .init(volume: Self.volumeB, destination: "/second", subpath: "", mode: "read-only")
        ])
        #expect(plan.slots.count == 5)
        #expect(Set(plan.slots.map { "\($0.volume):\($0.role):\($0.mode)" }) == [
            "\(Self.volumeA):prepare:read-write", "\(Self.volumeA):runtime:read-only",
            "\(Self.volumeA):runtime:read-write", "\(Self.volumeB):prepare:read-write",
            "\(Self.volumeB):runtime:read-only"
        ])
        #expect(plan.slots.filter { $0.role == "prepare" }.count == 2)
        let identifiers = Self.identifiers(plan)
        #expect(identifiers.count == 6 + 3 * plan.slots.count)
        #expect(Set(identifiers).count == identifiers.count)
        #expect(Set(identifiers).isDisjoint(with: [Self.volumeA, Self.volumeB, plan.store, plan.containerInstance]))
        for id in identifiers + plan.mounts.map(\.volume) {
            #expect(id.count == 36)
            #expect(UUID(uuidString: id)?.uuidString.lowercased() == id)
        }
    }

    @Test func repeatedPlanningNeverReusesPrepareAttachmentOrOperationIdentifiers() throws {
        let workload = Self.workload()
        let container = ContainerRecord(id: Self.containerID, name: "same-name", image: "test")
        let context = try Self.context()
        let launch = Self.id()
        let first = try Backend.plan(container: container, launch: launch, context: context, workload: workload)
        let second = try Backend.plan(container: container, launch: launch, context: context, workload: workload)
        #expect(first.mounts == second.mounts)
        #expect(first.specificationDigest == second.specificationDigest)
        #expect(first.containerInstance == second.containerInstance)
        #expect(first.launch == second.launch)
        let firstGenerated = Set(Self.identifiers(first).filter { $0 != launch })
        let secondGenerated = Set(Self.identifiers(second).filter { $0 != launch })
        #expect(firstGenerated.count == 5 + 3 * first.slots.count)
        #expect(secondGenerated.count == firstGenerated.count)
        #expect(firstGenerated.isDisjoint(with: secondGenerated))
    }

    @Test(arguments: ["docker-volume-name", String(repeating: "a", count: 64), "11111111-111", ""])
    func managedSourceMustBeAFullUUIDNotADockerName(source: String) throws {
        var workload = Self.workload()
        workload.mounts[0].source = source
        #expect(throws: (any Error).self) { try Self.plan(workload) }
    }

    @Test func planRequiresManagedMountsAndEnforcesAggregateSlotLimit() throws {
        var workload = Self.workload()
        workload.mounts = workload.mounts.filter { $0.kind != "volume" || $0.device != nil }
        #expect(throws: (any Error).self) { try Self.plan(workload) }
        workload.mounts = []
        #expect(throws: (any Error).self) { try Self.plan(workload) }
        workload.mounts = (0..<(WorkloadStorageProtocol.maximumSlots / 2)).map {
            .init(kind: "volume", source: Self.id(), destination: "/volume-\($0)", readOnly: false)
        }
        #expect(try Self.plan(workload).slots.count == WorkloadStorageProtocol.maximumSlots)
        workload.mounts.append(.init(kind: "volume", source: Self.id(), destination: "/overflow", readOnly: true))
        #expect(throws: (any Error).self) { try Self.plan(workload) }
    }

    @Test func wholeBackendPlanIsDurableBeforeAnyKeysAreFrozen() throws {
        let f = try RawManagedStorageDirectory(); defer { f.remove() }
        let context = try Self.context()
        let journal = try Journal.initialize(in: f.root, store: context.store, provenanceReference: context.provenanceReference)
        try journal.reconciled()
        try journal.planVolumes([Self.volumeA, Self.volumeB].enumerated().map { index, id in
            .init(id: id, name: "volume-\(index)", createOperation: Self.id(), deleteOperation: Self.id())
        })
        let plan = try Backend.plan(container: .init(id: Self.containerID, name: "test", image: "test"),
            launch: Self.id(), context: context, workload: Self.workload())
        let before = try journal.snapshot()
        let token = try journal.plan(plan)
        let after = try journal.snapshot()
        #expect(after.revision == before.revision + 1)
        var planned = plan
        planned.launchBoundary = .planned
        #expect(after.intents == [plan.id: planned])
        #expect(after.operations.isEmpty && after.operationDigests.isEmpty)
        let directory = try f.root.openDirectory(named: "managed-storage")
        let bytes = try #require(try directory.readRegularFile(named: "state.json"))
        #expect(try JSONDecoder().decode(Journal.State.self, from: bytes) == after)
        #expect(try journal.intent(token) == planned)
        #expect(plan.slots.allSatisfy { $0.key == nil && $0.receipt == nil })
        // Local journal coverage only: no shim, service, helper, or fake authenticated boot.
        let keys = Dictionary(uniqueKeysWithValues: plan.slots.filter { $0.role == "prepare" }.map {
            ($0.attachment, Journal.hash(Data($0.attachment.utf8)))
        })
        let frozen = try journal.freezeKeys(token, role: .prepare, keys: keys)
        let frozenPlan = try journal.intent(frozen)
        #expect(frozenPlan.phase == .prepareFrozen)
        #expect(frozenPlan.mounts == plan.mounts)
        #expect(frozenPlan.slots.count == plan.slots.count)
        #expect(frozenPlan.slots.filter { $0.role == "runtime" }.allSatisfy { $0.key == nil })
    }

    @Test func retirementHintsDistinguishExpectedPrepareClosureFromLiveRuntime() throws {
        var intent = try Self.plan(Self.workload())
        let prepare = try #require(intent.slots.first { $0.role == "prepare" })
        let runtime = try #require(intent.slots.first { $0.role == "runtime" })
        #expect(try Backend.retirementTarget(attachment: prepare.attachment, intents: [intent], closingPrepare: [])?.launch == intent.launch)
        #expect(try Backend.retirementTarget(attachment: prepare.attachment, intents: [intent], closingPrepare: [prepare.attachment]) == nil)
        #expect(try Backend.retirementTarget(attachment: runtime.attachment, intents: [intent], closingPrepare: [prepare.attachment])?.launch == intent.launch)
        intent.cleanUnmount = true
        #expect(try Backend.retirementTarget(attachment: prepare.attachment, intents: [intent], closingPrepare: []) == nil)
        #expect(try Backend.retirementTarget(attachment: runtime.attachment, intents: [intent], closingPrepare: [])?.container == intent.container)
        intent.phase = .retired
        #expect(try Backend.retirementTarget(attachment: runtime.attachment, intents: [intent], closingPrepare: []) == nil)
        #expect(throws: (any Error).self) {
            try Backend.retirementTarget(attachment: Self.id(), intents: [intent], closingPrepare: [])
        }
    }

    @Test func runtimeHintsRemainPendingUntilEveryExactCloseOwnerLeaves() throws {
        var intent = try Self.plan(Self.workload())
        for index in intent.slots.indices { intent.slots[index].key = String(repeating: "a", count: 64) }
        let runtime = try #require(intent.slots.first { $0.role == "runtime" })
        var hints = Backend.RetirementHints()
        let first = hints.begin(intents: [intent], container: intent.container, instance: intent.containerInstance, launch: intent.launch)
        let second = hints.begin(intents: [intent], container: intent.container, instance: intent.containerInstance, launch: intent.launch)
        try hints.enqueue(runtime.attachment)
        try hints.enqueue(runtime.attachment)
        #expect(try hints.next(intents: [intent], closingPrepare: []) == nil)
        hints.end(first)
        #expect(try hints.next(intents: [intent], closingPrepare: []) == nil)
        #expect(hints.pending == [runtime.attachment])
        // Failure/cancellation supplies no receipt: retaining the consumed hint
        // ensures the original exact launch is still sent to containment.
        hints.end(second)
        let target = try #require(try hints.next(intents: [intent], closingPrepare: []))
        #expect(target.container == intent.container && target.launch == intent.launch)
        #expect(hints.pending.isEmpty)
        // A late duplicate after successful retirement is settled from fresh
        // per-attachment evidence even if the overall intent is not terminal.
        let index = try #require(intent.slots.firstIndex { $0.attachment == runtime.attachment })
        intent.slots[index].receipt = Journal.DrainReceipt(try .init(schema: 3, store: intent.store,
            volume: runtime.volume, attachment: runtime.attachment, prepare: nil, launch: intent.launch, revision: 10))
        try hints.enqueue(runtime.attachment)
        #expect(try hints.next(intents: [intent], closingPrepare: []) == nil)
        #expect(hints.pending.isEmpty)
    }

    @Test(arguments: ["container", "instance", "launch"])
    func runtimeCloseCannotSuppressAnotherExecution(field: String) throws {
        var intent = try Self.plan(Self.workload())
        for index in intent.slots.indices { intent.slots[index].key = String(repeating: "a", count: 64) }
        let runtime = try #require(intent.slots.first { $0.role == "runtime" })
        var hints = Backend.RetirementHints()
        let close = hints.begin(intents: [intent], container: field == "container" ? String(repeating: "d", count: 64) : intent.container,
            instance: field == "instance" ? Self.id() : intent.containerInstance, launch: field == "launch" ? Self.id() : intent.launch)
        defer { hints.end(close) }
        try hints.enqueue(runtime.attachment)
        let target = try #require(try hints.next(intents: [intent], closingPrepare: []))
        #expect(target.container == intent.container && target.launch == intent.launch)
        // Raw's unchanged immutable-shim launch guard cannot aim this old hint
        // at a new launch merely because the container name/instance is reused.
        let replacementLaunch = Self.id()
        var fence = RawBackendExecutionFence()
        let replacement = fence.replace(intent.container)
        if target.launch == replacementLaunch { _ = fence.replace(target.container) }
        #expect(fence.owns(intent.container, token: replacement))
        try hints.enqueue(Self.id())
        #expect(throws: (any Error).self) { _ = try hints.next(intents: [intent], closingPrepare: []) }
        #expect(hints.pending.count == 1)
    }

    @Test func deletionAdmissionRejectsConcurrentStartsBeforeMutationAndRecovers() throws {
        let admission = Backend.Admission()
        let first = try admission.beginStart()
        let second = try admission.beginStart()
        #expect(throws: (any Error).self) { try admission.beginDeletion() }
        admission.endStart(first)
        #expect(throws: (any Error).self) { try admission.beginDeletion() }
        admission.endStart(second)
        let deletion = try admission.beginDeletion()
        #expect(throws: (any Error).self) { try admission.beginStart() }
        #expect(throws: (any Error).self) { try admission.beginDeletion() }
        admission.endDeletion(deletion)
        let third = try admission.beginStart()
        admission.endStart(third)
        let last = try admission.beginDeletion()
        admission.endDeletion(last)
    }

    @Test func admissionReplacementJoinsOldLeasesAndStaleReleaseCannotOpenSuccessor() async throws {
        let admission = Backend.Admission()
        let old = try admission.beginStart()
        admission.close()
        #expect(throws: (any Error).self) { try admission.beginStart() }
        #expect(throws: (any Error).self) { try admission.reopen() }
        await #expect(throws: (any Error).self) { try await admission.join(timeout: .milliseconds(1)) }
        admission.endStart(old)
        try await admission.join()
        try admission.reopen()
        let deletion = try admission.beginDeletion()
        admission.endStart(old)
        #expect(throws: (any Error).self) { try admission.beginStart() }
        admission.endDeletion(deletion)
        admission.close(); try await admission.join(); try admission.reopen()
        let successor = try admission.beginDeletion()
        admission.endDeletion(deletion)
        #expect(throws: (any Error).self) { try admission.beginStart() }
        admission.endDeletion(successor)
    }

    @Test func reconciliationProvesEveryHistoricalAndCurrentIntentBeforeAnyRecoveryRPC() async throws {
        let active = try Self.plan(Self.workload(), serviceEpoch: Self.id())
        var retired = try Self.plan(Self.workload(), serviceEpoch: Self.id())
        var replaced = try Self.plan(Self.workload(), serviceEpoch: Self.id())
        var unlaunched = try Self.plan(Self.workload())
        retired.phase = .retired
        replaced.phase = .replaced
        unlaunched.phase = .unlaunched; unlaunched.launchBoundary = .cancelled
        let intents = [retired, unlaunched, active, replaced]
        let ids = intents.map(\.id).sorted()
        var events: [String] = []
        // Values below are only scheduling markers, not constructible native
        // ReplacementPermit evidence or a fake authenticated owner/service.
        try await Backend.reconcileExecutions(intents, prepare: { intent in
            events.append("prove:" + intent.id); return intent.id
        }, register: { proofs in
            #expect(proofs == ids); events.append("register-all")
        }, settle: { intent in
            events.append("recover:" + intent.id)
        }, ready: { events.append("ready") })
        #expect(events == ids.map { "prove:" + $0 } + ["register-all", "recover:" + active.id, "ready"])
    }

    @Test func livePartitionPreservesCurrentRuntimeWhileContainingTerminalHistory() async throws {
        var current = try Self.plan(Self.workload())
        var historical = try Self.plan(Self.workload())
        current.phase = .running; current.prepareCompleted = true
        historical.phase = .retired; historical.prepareCompleted = true
        #expect(ManagedVolumeLifecycleCoordinator.permitsLivePartition(current, intents: [historical, current]))
        var events: [String] = []
        // Scheduling markers only: production obtains the preserved ID exclusively
        // from LiveRuntimePermit's native + original-private-session factory.
        try await Backend.reconcileExecutions([current, historical], preserving: [current.id], prepare: { intent in
            events.append("contain:" + intent.id); return intent.id
        }, register: { proofs in
            #expect(proofs == [historical.id]); events.append("register-all")
        }, settle: { intent in events.append("settle:" + intent.id) }, ready: { events.append("ready") })
        #expect(events == ["contain:" + historical.id, "register-all", "ready"])
        #expect(!events.contains("contain:" + current.id))
    }

    @Test(arguments: [Journal.Phase.planned, .prepareFrozen, .prepareAdmitted, .prepareSucceeded,
        .prepareDrained, .prepareCompleted, .runtimeFrozen, .running, .quarantined])
    private func unresolvedSiblingDisablesLivePartition(phase: Journal.Phase) throws {
        var current = try Self.plan(Self.workload())
        var sibling = try Self.plan(Self.workload(), serviceEpoch: Self.id())
        current.phase = .running; current.prepareCompleted = true; sibling.phase = phase
        #expect(!ManagedVolumeLifecycleCoordinator.permitsLivePartition(current, intents: [current, sibling]))
    }

    @Test func livePartitionCannotInventAnIDOrPreserveUnfinishedStartup() async throws {
        let intent = try Self.plan(Self.workload())
        for ids: Set<String> in [[intent.id], [Self.id()]] {
            var touched = false
            do {
                try await Backend.reconcileExecutions([intent], preserving: ids, prepare: { value in
                    touched = true; return value.id
                }, register: { _ in touched = true }, settle: { _ in touched = true }, ready: { touched = true })
                Issue.record("invalid preservation accepted")
            } catch {}
            #expect(!touched)
        }
    }

    @Test(arguments: ["containment", "registration", "settlement"])
    func reconciliationFailureCannotSkipToRecoveryOrReadiness(boundary: String) async throws {
        let intents = try [Self.plan(Self.workload()), Self.plan(Self.workload()), Self.plan(Self.workload())]
        let ids = intents.map(\.id).sorted()
        var events: [String] = []
        do {
            try await Backend.reconcileExecutions(intents, prepare: { intent in
                events.append("prove:" + intent.id)
                if boundary == "containment", intent.id == ids[1] { throw Backend.failure() }
                return intent.id
            }, register: { _ in
                events.append("register-all")
                if boundary == "registration" { throw Backend.failure() }
            }, settle: { intent in
                events.append("recover:" + intent.id)
                throw Backend.failure()
            }, ready: { events.append("ready") })
            Issue.record("failed reconciliation unexpectedly became ready")
        } catch {}
        let expected: [String]
        switch boundary {
        case "containment": expected = ids.prefix(2).map { "prove:" + $0 }
        case "registration": expected = ids.map { "prove:" + $0 } + ["register-all"]
        default: expected = ids.map { "prove:" + $0 } + ["register-all", "recover:" + ids[0]]
        }
        #expect(events == expected)
    }

    @Test func managedRemovalRetainsWholeNativeHistoryAcrossRepeatedAndReloadedPublication() throws {
        let fixture = try RawManagedStorageDirectory(); defer { fixture.remove() }
        let containers = try fixture.root.createDirectory(named: "containers")
        let receipts = try fixture.root.createDirectory(named: "deleted")
        let container = ContainerRecord(id: Self.containerID, name: "removed", image: "test")
        let directory = try containers.createDirectory(named: container.id)
        let files = ["root.ext4": Data("writable user bytes".utf8),
                     ".raw-init-root.ext4.created.json": Data("immutable journal".utf8),
                     "native-launch.json": Data("immutable native generation".utf8)]
        var identities: [String: PersistentFileIdentity] = [:]
        for (name, bytes) in files {
            try directory.writeExclusiveRegularFile(named: name, data: bytes)
            let opened = try directory.openRegularFile(named: name, access: .readOnly)
            identities[name] = opened.identity; try opened.handle.close()
        }
        var retained = [container.id: directory.identity]
        for _ in 0..<2 {
            // Same production finalization when canonical publication was lost.
            try RawVirtualizationBackend.finalizeContainerRemoval(container,
                directoryIdentity: directory.identity, in: containers, receipts: receipts,
                retainedIdentities: &retained, retainingManagedHistory: true)
        }
        let reopened = try PersistentStateDirectory.open(fixture.url)
        let reloadedContainers = try reopened.openDirectory(named: "containers")
        let reloaded = try reloadedContainers.openDirectory(named: container.id)
        let reloadedReceipts = try reopened.openDirectory(named: "deleted")
        try RawVirtualizationBackend.finalizeContainerRemoval(container,
            directoryIdentity: reloaded.identity, in: reloadedContainers, receipts: reloadedReceipts,
            retainedIdentities: &retained, retainingManagedHistory: true)
        try RawDeletedContainerCoordinator.requireRecordedDeletion(of: container,
            directoryIdentity: reloaded.identity, in: reloadedReceipts)
        #expect(reloaded.identity == directory.identity)
        #expect(try reloadedContainers.pendingDisposalIdentity(named: container.id) == nil)
        for (name, bytes) in files {
            #expect(try reloaded.readRegularFile(named: name) == bytes)
            let opened = try reloaded.openRegularFile(named: name, access: .readOnly)
            #expect(opened.identity == identities[name]); try opened.handle.close()
        }
        // Legacy/no-intent removal still disposes state through the existing path.
        let legacy = ContainerRecord(id: String(repeating: "c", count: 64), name: "legacy", image: "test")
        let legacyDirectory = try containers.createDirectory(named: legacy.id)
        retained[legacy.id] = legacyDirectory.identity
        try RawVirtualizationBackend.finalizeContainerRemoval(legacy,
            directoryIdentity: legacyDirectory.identity, in: containers, receipts: receipts,
            retainedIdentities: &retained, retainingManagedHistory: false)
        try RawDeletedContainerCoordinator.requireCompletedDeletion(of: legacy, in: containers, receipts: receipts)
    }

    @Test func duplicateIntentInventoryIsRejectedBeforeNativeContainment() async throws {
        let intent = try Self.plan(Self.workload())
        var called = false
        do {
            try await Backend.reconcileExecutions([intent, intent], prepare: { _ in called = true },
                register: { _ in called = true }, settle: { _ in called = true }, ready: { called = true })
            Issue.record("duplicate reconciliation intent accepted")
        } catch {}
        #expect(!called)
    }

    private static func id() -> String { UUID().uuidString.lowercased() }

    private static func context(serviceEpoch: String = "44444444-4444-4444-8444-444444444444") throws -> ManagedStorageControlClient.Context {
        try .init(store: "33333333-3333-4333-8333-333333333333",
            serviceEpoch: serviceEpoch, controllerEpoch: 7,
            controllerKey: String(repeating: "c", count: 64), provenanceReference: String(repeating: "d", count: 64))
    }

    private static func plan(_ workload: GuestProtocol.Workload,
        serviceEpoch: String = "44444444-4444-4444-8444-444444444444") throws -> Journal.Intent {
        try Backend.plan(container: .init(id: containerID, name: "test", image: "test"),
            launch: id(), context: context(serviceEpoch: serviceEpoch), workload: workload)
    }

    private static func identifiers(_ plan: Journal.Intent) -> [String] {
        [plan.id, plan.launch, plan.prepare, plan.reserveOperation, plan.completeOperation, plan.replaceOperation]
            + plan.slots.flatMap { [$0.attachment, $0.registerOperation, $0.retireOperation] }
    }

    private static func workload() -> GuestProtocol.Workload {
        .init(id: containerID, rootDevice: "/dev/vda", arguments: ["/bin/sh", "-c", "echo ready"],
            environment: ["PATH=/usr/bin:/bin"], workingDirectory: "/work", hostname: "test",
            user: .init(uid: 1000, gid: 1000), terminal: false, readOnlyRoot: false, stopSignal: "SIGTERM",
            mounts: [
                .init(kind: "volume", source: volumeA, destination: "/readonly", readOnly: true, subpath: "docs", noCopy: true),
                .init(kind: "volume", source: volumeA, destination: "/data", readOnly: false),
                .init(kind: "volume", source: volumeA, destination: "/readonly-again", readOnly: true, subpath: "other"),
                .init(kind: "volume", source: volumeA, destination: "/data-again", readOnly: false, noCopy: true),
                .init(kind: "volume", source: volumeB, destination: "/second", readOnly: true, noCopy: true),
                .init(kind: "bind", source: "/host/project", destination: "/project", readOnly: false),
                .init(kind: "tmpfs", source: "", destination: "/tmp", readOnly: false),
                .init(kind: "volume", source: "legacy-volume-name", device: "/dev/vdb", destination: "/legacy", readOnly: false)
            ], networks: [], hosts: ["z-host": "192.0.2.2", "a-host": "192.0.2.1"],
            resources: .init(memoryBytes: 128 * 1_024 * 1_024, cpuQuota: -1, cpuPeriod: 100_000, pids: 64),
            annotations: ["z-last": "/last", "a-first": "/first"])
    }
}

@MainActor private struct RawManagedStorageDirectory {
    let url: URL
    let root: PersistentStateDirectory

    init() throws {
        url = FileManager.default.temporaryDirectory.appending(path: "cengine-raw-managed-storage-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        root = try PersistentStateDirectory.open(url)
    }

    func remove() { try? FileManager.default.removeItem(at: url) }
}
#endif

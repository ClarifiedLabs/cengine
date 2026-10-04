import Foundation
import Testing
@testable import CEngineCore
#if os(macOS)
import Darwin
@testable import CEngineRuntime
#endif

@Suite struct OriginalConsumerSuccessorTests {
    typealias C = ConsumerObservationProtocol
    private typealias B = StorageLifecycleServiceBootProtocol
    private let id = "11111111-1111-4111-8111-111111111111"
    private let other = "22222222-2222-4222-8222-222222222222"
    private let hash = String(repeating: "ab", count: 32)
    private var arm: C.Arm {
        .init(requestID: id, armDigest: hash, operationUUID: other, caseName: .crossE,
            originalBootBinding: .init(shimLaunchUUID: id, guestBootNonce: other),
            original: .init(epoch: id, binding: .init(store: id, volume: other, attachment: other,
                container: hash, launch: id, key: hash, mode: "read-write")), originalLeafSHA256: hash,
            workerScope: .init(storeUUID: id, serviceEpoch: other, workerUUID: other))
    }
    private var binding: DiskInitializationProtocol.Binding { .init(shimLaunchUUID: id, guestBootNonce: other, ext4UUID: id, bytes: 4096) }
    private var observed: C.Status {
        .init(query: arm, state: .observed, selectedCount: 1,
            evidence: .init(stage: "tls-client-certificate", errorClass: "unknown-authority", storeUUID: id,
                serviceEpoch: other, rejectedLeafSHA256: hash, byteCount: 456, prefixSHA256: hash))
    }
    @Test(arguments: [C.Case.wrongVolume, .wrongKey, .wrongRole, .wrongMode, .wrongEpoch])
    func currentWorkerWrongHelloRequiresExactMutationAndFinalization(_ name: C.Case) throws {
        var query = arm; query.version = 4; query.caseName = name
        query.workerScope.serviceEpoch = query.original.epoch
        if name == .wrongMode { query.original.binding.mode = "read-only" }
        var hello = query.original
        switch name {
        case .wrongVolume: hello.binding.volume = id
        case .wrongKey: hello.binding.key = String(repeating: "cd", count: 32)
        case .wrongRole: hello.binding.role = "prepare"; hello.binding.prepare = other
        case .wrongMode: hello.binding.mode = "read-write"
        case .wrongEpoch: hello.epoch = other
        default: Issue.record("unexpected case")
        }
        try C.validate(query)
        var status = observed; status.query = query
        status.evidence?.stage = "pki-verify-peer"; status.evidence?.errorClass = "unauthorized"
        status.evidence?.serviceEpoch = query.original.epoch; status.evidence?.hello = hello
        #expect(try C.decodeStatus(JSONEncoder().encode(status)) == status)
        var final = status; final.state = .finalized
        try C.validateFinalization(final, observed: status)
        for fault in ["new-ca", "successor", "hello", "version", "field", "no-hello", "duplicate"] {
            var bad = final
            switch fault {
            case "new-ca": bad.evidence?.stage = "tls-client-certificate"; bad.evidence?.errorClass = "unknown-authority"
            case "successor": bad.query.workerScope.serviceEpoch = other
            case "hello": bad.evidence?.hello?.binding.key = String(repeating: "ef", count: 32)
            case "version": bad.query.version = 3
            case "field": bad.evidence?.hello?.binding.attachment = id
            case "no-hello": bad.evidence?.hello = nil
            default: bad.selectedCount = 2
            }
            #expect(throws: (any Error).self) { try C.validateFinalization(bad, observed: status) }
        }
        let command = B.Frame(operation: .command, binding: binding, sequence: 7, serviceEpoch: id, command: .consumerObservationArm, workerUUID: other, consumerObservationArm: query)
        #expect(try B.decode(Data(B.encode(command).dropFirst(4))) == command)
    }

    @Test func actualGoV3ShapeRoundTripsThroughBootCodec() throws {
        for kind in [B.Command.consumerObservationArm, .consumerObservationQuery, .consumerObservationFinalize] {
            let command = B.Frame(operation: .command, binding: binding, sequence: 7, serviceEpoch: other, command: kind, workerUUID: other, consumerObservationArm: kind == .consumerObservationArm ? arm : nil,
                consumerObservationQuery: kind != .consumerObservationArm ? arm : nil)
            #expect(try B.decode(Data(B.encode(command).dropFirst(4))) == command)
        }
        let reply = B.Frame(operation: .reply, binding: binding, sequence: 8, serviceEpoch: other, workerUUID: other, consumerObservationStatus: observed)
        #expect(try B.decode(Data(B.encode(reply).dropFirst(4))) == reply)
        let json = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(arm)) as? [String: Any])
        #expect(Set(json.keys) == ["version", "profile", "requestID", "armDigest", "operationUUID", "caseName", "originalBootBinding", "original", "originalLeafSHA256", "workerScope"])
        #expect(json["version"] as? Int == 3)
        #expect(json["profile"] as? String == "rtm096-full-nine-v3")
    }
    @Test(arguments: ["version", "profile", "store", "worker", "epoch", "leaf", "digest", "operation", "boot", "role", "mode", "volume", "key"])
    func workerStatusCannotRedirectAnyArmField(_ fault: String) throws {
        var bad = observed
        switch fault {
        case "version": bad.query.version = 1
        case "profile": bad.query.profile = "rtm095-early"
        case "store": bad.query.workerScope.storeUUID = other
        case "worker": bad.query.workerScope.workerUUID = id
        case "epoch": bad.query.workerScope.serviceEpoch = id
        case "leaf": bad.query.originalLeafSHA256 = String(repeating: "cd", count: 32)
        case "digest": bad.query.armDigest = String(repeating: "cd", count: 32)
        case "operation": bad.query.operationUUID = id
        case "boot": bad.query.originalBootBinding.guestBootNonce = id
        case "role": bad.query.original.binding.role = "prepare"
        case "mode": bad.query.original.binding.mode = "read-only"
        case "volume": bad.query.original.binding.volume = id
        default: bad.query.original.binding.key = String(repeating: "cd", count: 32)
        }
        #expect(throws: (any Error).self) { try C.validate(bad, arm: arm) }
    }
    @Test(arguments: ["duplicate", "alias", "unknown", "null", "missing", "fraction", "eof", "count", "zero", "wrong-stage", "key-claim", "admission"])
    func actualWorkerCodecRejectsAmbiguousOrUnattributedEvidence(_ fault: String) throws {
        let bytes = try JSONEncoder().encode(observed)
        var text = String(decoding: bytes, as: UTF8.self)
        switch fault {
        case "duplicate": text = "{\"selectedCount\":1," + text.dropFirst()
        case "alias": text = text.replacingOccurrences(of: "\"state\":", with: "\"\\u0073tate\":")
        case "unknown": text = "{\"privateKey\":\"secret\"," + text.dropFirst()
        case "null": text = "{\"failure\":null," + text.dropFirst()
        default:
            var status = observed
            switch fault {
            case "missing": status.evidence?.prefixSHA256 = nil
            case "fraction": text = text.replacingOccurrences(of: "\"selectedCount\":1", with: "\"selectedCount\":1.0")
            case "eof": status.evidence?.errorClass = "eof"
            case "count": status.selectedCount = 2
            case "zero": status.evidence?.byteCount = 0
            case "wrong-stage": status.evidence?.stage = "request-admit"
            case "key-claim": status.evidence?.errorClass = "verified-key-possession"
            default: status.evidence?.admission = .init(original: arm.original, requestSequence: 1)
            }
            if fault != "fraction" { text = String(decoding: try JSONEncoder().encode(status), as: UTF8.self) }
        }
        #expect(throws: (any Error).self) { try C.decodeStatus(Data(text.utf8)) }
    }
    @Test func terminalAcceptanceRequiresExactAtomicFinalization() throws {
        var sealed = observed
        sealed.state = .finalized
        let reply = B.Frame(operation: .reply, binding: binding, sequence: 9, serviceEpoch: other, workerUUID: other, consumerObservationStatus: sealed)
        let decoded = try B.decode(Data(B.encode(reply).dropFirst(4)))
        try C.validateFinalization(#require(decoded.consumerObservationStatus), observed: observed)
        #expect(throws: (any Error).self) { try C.validateFinalization(observed, observed: observed) }
        for fault in ["worker", "prefix", "duplicate", "failed"] {
            var changed = sealed
            switch fault {
            case "worker": changed.query.workerScope.workerUUID = id
            case "prefix": changed.evidence?.prefixSHA256 = String(repeating: "cd", count: 32)
            case "duplicate": changed.selectedCount = 2
            default: changed.state = .failed; changed.failure = .duplicate; changed.evidence = nil
            }
            #expect(throws: (any Error).self) { try C.validateFinalization(changed, observed: observed) }
        }
    }
    @Test func sameERequiresActualAuthenticatedAdmissionAndNoPrefix() throws {
        var query = arm; query.caseName = .sameE; query.workerScope.serviceEpoch = query.original.epoch
        var value = C.Status(query: query, state: .observed, selectedCount: 1,
            evidence: .init(stage: "request-admit", errorClass: "blocked", storeUUID: id, serviceEpoch: id,
                rejectedLeafSHA256: hash, admission: .init(original: query.original, requestSequence: 42)))
        #expect(try C.decodeStatus(JSONEncoder().encode(value)) == value)
        value.evidence?.admission?.requestSequence = 0
        #expect(throws: (any Error).self) { try C.decodeStatus(JSONEncoder().encode(value)) }
        value.evidence?.admission?.requestSequence = 42; value.evidence?.byteCount = 12
        #expect(throws: (any Error).self) { try C.decodeStatus(JSONEncoder().encode(value)) }
    }
    @Test func bootCodecRejectsWrongScopeAndMixedResults() throws {
        var command = B.Frame(operation: .command, binding: binding, sequence: 1, serviceEpoch: other, command: .consumerObservationArm, workerUUID: id, consumerObservationArm: arm)
        #expect(throws: (any Error).self) { try B.encode(command) }
        command.workerUUID = other; command.consumerObservationQuery = arm
        #expect(throws: (any Error).self) { try B.encode(command) }
        let reply = B.Frame(operation: .reply, binding: binding, sequence: 1, serviceEpoch: other, code: .command, workerUUID: other, consumerObservationStatus: observed)
        #expect(throws: (any Error).self) { try B.encode(reply) }
    }

    #if os(macOS)
    @Test func runtimeCarrierAdmitsExactlyFifteenCompletedSourceCases() throws {
        for name in OriginalConsumerObservationProtocol.Case.allCases {
            let request = OriginalConsumerRuntimeCarrier.Request(version: 1, profile: ManagedPrepareCompatibilityProtocol.fullProfile,
                requestID: id, operationUUID: other, caseName: name, container: hash, containerInstance: other)
            if [.sameEExistingData, .sameEOldLeafReconnect, .sameERetainedFD, .crossERetainedFD, .crossEOldLeafReconnect, .crossEExistingData, .wrongVolume, .wrongKey, .wrongRole, .wrongMode, .wrongEpoch, .crossMountRootGrant, .retiredRootGrantReplay, .attachmentKeyReuse, .delayedRegistration].contains(name) {
                try request.validate()
            } else {
                #expect(throws: (any Error).self) { try request.validate() }
            }
        }
    }
    @Test @MainActor func wrongHelloTargetsMustComeFromIssuedOwnerJournal() throws {
        let fixture = try HostIntentFixture(); defer { fixture.remove() }
        var intent = fixture.intent(); intent.phase = .running
        let runtime = try #require(intent.slots.firstIndex(where: { $0.role == "runtime" }))
        let prepare = try #require(intent.slots.firstIndex(where: { $0.role == "prepare" }))
        intent.slots[runtime].key = hash
        let issued = String(repeating: "cd", count: 32)
        intent.slots[prepare].key = issued
        let slot = intent.slots[runtime]
        let scope = WorkloadStorageProtocol.Scope(intent: intent.id, store: intent.store, serviceEpoch: intent.serviceEpoch,
            controllerEpoch: intent.controllerEpoch, controllerKey: intent.controllerKey, container: intent.container,
            containerInstance: intent.containerInstance, launch: intent.launch, prepare: intent.prepare, specificationDigest: intent.specificationDigest)
        func binding(_ name: OriginalConsumerObservationProtocol.Case) -> OriginalConsumerObservationProtocol.Binding {
            .init(requestID: id, armDigest: hash, operationUUID: other, caseName: name, generation: 1,
                boot: .init(shimLaunchUUID: intent.launch, guestBootNonce: other), scope: scope,
                targetAttachment: slot.attachment, key: hash, certificateSHA256: hash)
        }
        func snapshot() -> ManagedStorageJournalSnapshot {
            .init(revision: 1, volumes: [], intents: [intent], reconciliationRequired: false)
        }
        #expect(try ManagedStorageOriginalConsumerComparison.originalConsumerWrongHello(binding(.wrongKey), snapshot: snapshot()).binding.key == issued)
        let role = try ManagedStorageOriginalConsumerComparison.originalConsumerWrongHello(binding(.wrongRole), snapshot: snapshot())
        #expect(role.binding.role == "prepare" && role.binding.prepare == intent.prepare)
        let epoch = try ManagedStorageOriginalConsumerComparison.originalConsumerWrongHello(binding(.wrongEpoch), snapshot: snapshot())
        #expect(epoch.epoch != scope.serviceEpoch && StorageServiceTypes.validID(epoch.epoch))
        // A created-only volume / missing second issued mount is NOT authority.
        #expect(throws: (any Error).self) { try ManagedStorageOriginalConsumerComparison.originalConsumerWrongHello(binding(.wrongVolume), snapshot: snapshot()) }
        intent.slots[prepare].key = nil
        #expect(throws: (any Error).self) { try ManagedStorageOriginalConsumerComparison.originalConsumerWrongHello(binding(.wrongKey), snapshot: snapshot()) }
        #expect(throws: (any Error).self) { try ManagedStorageOriginalConsumerComparison.originalConsumerWrongHello(binding(.wrongRole), snapshot: snapshot()) }
    }

    @Test @MainActor func journalTupleUsesOriginalRuntimeSlotNotCallerVolumeOrGrant() throws {
        let fixture = try HostIntentFixture(); defer { fixture.remove() }
        var intent = fixture.intent(); intent.phase = .running
        let index = try #require(intent.slots.firstIndex(where: { $0.role == "runtime" }))
        intent.slots[index].key = hash
        let slot = intent.slots[index]
        let scope = WorkloadStorageProtocol.Scope(intent: intent.id, store: intent.store, serviceEpoch: intent.serviceEpoch,
            controllerEpoch: intent.controllerEpoch, controllerKey: intent.controllerKey, container: intent.container,
            containerInstance: intent.containerInstance, launch: intent.launch, prepare: intent.prepare, specificationDigest: intent.specificationDigest)
        func bound(_ scope: WorkloadStorageProtocol.Scope, key: String = String(repeating: "ab", count: 32)) -> OriginalConsumerObservationProtocol.Binding {
            .init(requestID: id, armDigest: hash, operationUUID: other, caseName: .crossEOldLeafReconnect, generation: 1,
                boot: .init(shimLaunchUUID: intent.launch, guestBootNonce: other), scope: scope,
                targetAttachment: slot.attachment, key: key, certificateSHA256: hash)
        }
        let tuple = try ManagedStorageOriginalConsumerComparison.originalConsumerTuple(bound(scope), intent: intent)
        #expect(tuple.binding.volume == slot.volume)
        #expect(tuple.binding.attachment == slot.attachment)
        #expect(tuple.binding.key == slot.key)
        for fault in ["container", "launch", "controller", "intent", "instance", "store", "digest"] {
            var wrong = scope
            switch fault {
            case "container": wrong.container = hash
            case "launch": wrong.launch = id
            case "controller": wrong.controllerEpoch += 1
            case "intent": wrong.intent = id
            case "instance": wrong.containerInstance = id
            case "store": wrong.store = id
            default: wrong.specificationDigest = hash
            }
            #expect(throws: (any Error).self) { try ManagedStorageOriginalConsumerComparison.originalConsumerTuple(bound(wrong), intent: intent) }
        }
        #expect(throws: (any Error).self) { try ManagedStorageOriginalConsumerComparison.originalConsumerTuple(bound(scope, key: String(repeating: "cd", count: 32)), intent: intent) }
    }
    #endif
}

#if os(macOS)
@Suite @MainActor struct OriginalConsumerBindingSelectionTests {
    typealias O = OriginalConsumerObservationProtocol
    typealias Credential = ManagedPrepareCompatibilityProtocol.Credential
    typealias Intent = HostStorageIntents.Intent

    private func prepared(_ f: HostIntentFixture, count: Int = 2, mode: String = "read-write") -> Intent {
        var intent = f.intent(Array(f.volumes.prefix(count)))
        intent.phase = .running; intent.prepareCompleted = true
        // PREPARE attachments sort before all runtime attachments, deliberately.
        intent.slots = intent.slots.enumerated().map { index, slot in
            let digit = slot.role == "prepare" ? "0" : String(index + 1)
            return .init(volume: slot.volume,
                attachment: digit + "1111111-1111-4111-8111-11111111111" + String(index),
                role: slot.role, mode: mode, registerOperation: slot.registerOperation,
                retireOperation: slot.retireOperation, key: String(repeating: String(index + 1), count: 64))
        }
        return intent
    }
    private func credentials(_ intent: Intent) -> [Credential] {
        intent.slots.filter { $0.role == "runtime" }.enumerated().map { index, slot in
            .init(attachment: slot.attachment, key: slot.key!, certificateSHA256: String(repeating: String(index + 7), count: 64))
        }
    }
    private func select(_ name: O.Case, _ intent: Intent, _ values: [Credential]) throws -> Credential {
        try RawManagedStorageBackend.selectOriginalRuntimeCredential(caseName: name,
            scope: RawManagedStorageBackend.scope(intent), credentials: values, intent: intent)
    }
    private func binding(_ name: O.Case, _ intent: Intent, _ credential: Credential) -> O.Binding {
        .init(requestID: intent.id, armDigest: String(repeating: "a", count: 64), operationUUID: intent.prepare,
            caseName: name, generation: 1, boot: .init(shimLaunchUUID: intent.launch, guestBootNonce: intent.id),
            scope: RawManagedStorageBackend.scope(intent), targetAttachment: credential.attachment,
            key: credential.key, certificateSHA256: credential.certificateSHA256)
    }
    private func snapshot(_ intent: Intent, _ f: HostIntentFixture) -> ManagedStorageJournalSnapshot {
        .init(revision: 1, volumes: f.volumes.map { volume in
            var created = volume; created.createdRevision = 1; return created
        }, intents: [intent], reconciliationRequired: false)
    }
    @Test(arguments: [O.Case.crossMountRootGrant, .retiredRootGrantReplay])
    func rootPairPinsBothActuallyInstalledLeavesAndTuples(_ name: O.Case) throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        let intent = prepared(f), values = credentials(intent)
        let selected = try select(name, intent, values.reversed())
        let owner = binding(name, intent, selected)
        var positive = try OriginalConsumerRootObservationTests().fixture(name).2
        positive.arm = .init(owner); positive.scope = owner.scope
        for (index, credential) in values.enumerated() {
            let slot = try #require(intent.slots.first { $0.attachment == credential.attachment })
            let authority = ConsumerObservationProtocol.Original(epoch: intent.serviceEpoch,
                binding: .init(store: intent.store, volume: slot.volume, attachment: slot.attachment,
                    container: intent.container, launch: intent.launch, key: credential.key, mode: slot.mode))
            if index == 0 {
                positive.roots?.source.leafSHA256 = credential.certificateSHA256
                positive.roots?.source.read.authority = authority
            } else {
                positive.roots?.target.leafSHA256 = credential.certificateSHA256
                positive.roots?.target.read.authority = authority
            }
        }
        try RawManagedStorageBackend.validateOriginalRootCredentials(owner, positive: positive,
            credentials: values, intent: intent, retirement: nil)
        for fault in ["source-leaf", "target-leaf", "target-key", "target-volume", "target-launch", "missing-credential"] {
            var bad = positive, credentials = values
            switch fault {
            case "source-leaf": bad.roots?.source.leafSHA256 = String(repeating: "0", count: 64)
            case "target-leaf": bad.roots?.target.leafSHA256 = owner.certificateSHA256
            case "target-key": bad.roots?.target.read.authority.binding.key = owner.key
            case "target-volume": bad.roots?.target.read.authority.binding.volume = intent.prepare
            case "target-launch": bad.roots?.target.read.authority.binding.launch = intent.prepare
            default: credentials.removeLast()
            }
            #expect(throws: (any Error).self) {
                try RawManagedStorageBackend.validateOriginalRootCredentials(owner, positive: bad,
                    credentials: credentials, intent: intent, retirement: nil)
            }
        }
    }
    @Test func exactMountedPairSelectsSmallestAttachmentAndGuestRuntimeAlternate() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        var intent = prepared(f); let values = credentials(intent)
        for reverse in [false, true] {
            let selected = try select(.wrongVolume, intent, reverse ? values.reversed() : values)
            #expect(selected == values[0])
            let hello = try ManagedStorageOriginalConsumerComparison.originalConsumerWrongHello(binding(.wrongVolume, intent, selected), snapshot: snapshot(intent, f))
            #expect(hello.binding.volume == intent.slots.first(where: { $0.attachment == values[1].attachment })?.volume)
            #expect(hello.binding.key == selected.key && hello.binding.attachment == selected.attachment)
            intent.slots.reverse()
        }
    }
    @Test(arguments: ["missing", "extra", "duplicate", "unknown-attachment", "key", "leaf", "same-key", "same-leaf", "missing-slot", "extra-slot", "duplicate-slot", "same-volume", "prepare-slot", "receipt", "not-running", "prepare-incomplete", "different-intent", "different-launch", "different-epoch"])
    func mountedSelectionFailsClosed(_ fault: String) throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        var intent = prepared(f), values = credentials(intent)
        var scope = RawManagedStorageBackend.scope(intent)
        let index = try #require(intent.slots.firstIndex(where: { $0.attachment == values[1].attachment }))
        switch fault {
        case "missing": values.removeLast()
        case "extra": values.append(values[0])
        case "duplicate": values[1] = values[0]
        case "unknown-attachment": values[1].attachment = intent.id
        case "key": values[1].key = String(repeating: "e", count: 64)
        case "leaf": values[1].certificateSHA256 = "unissued"
        case "same-key": values[1].key = values[0].key; intent.slots[index].key = values[0].key
        case "same-leaf": values[1].certificateSHA256 = values[0].certificateSHA256
        case "missing-slot": intent.slots.remove(at: index)
        case "duplicate-slot": intent.slots.append(intent.slots[index])
        case "extra-slot":
            let slot = intent.slots[index]
            intent.slots.append(.init(volume: intent.id, attachment: intent.prepare, role: "runtime", mode: slot.mode,
                registerOperation: slot.registerOperation, retireOperation: slot.retireOperation, key: String(repeating: "e", count: 64)))
        case "same-volume", "prepare-slot":
            let slot = intent.slots[index]
            intent.slots[index] = .init(volume: fault == "same-volume" ? intent.slots[1].volume : slot.volume,
                attachment: slot.attachment, role: fault == "prepare-slot" ? "prepare" : slot.role,
                mode: slot.mode, registerOperation: slot.registerOperation, retireOperation: slot.retireOperation, key: slot.key)
        case "receipt":
            let slot = intent.slots[index]
            intent.slots[index].receipt = .init(try .init(schema: 3, store: intent.store, volume: slot.volume,
                attachment: slot.attachment, prepare: nil, launch: intent.launch, revision: 1))
        case "not-running": intent.phase = .runtimeFrozen
        case "prepare-incomplete": intent.prepareCompleted = false
        case "different-intent": scope.intent = intent.prepare
        case "different-launch": scope.launch = intent.prepare
        default: scope.serviceEpoch = intent.prepare
        }
        #expect(throws: (any Error).self) {
            try RawManagedStorageBackend.selectOriginalRuntimeCredential(caseName: .wrongVolume, scope: scope, credentials: values, intent: intent)
        }
    }
    @Test func wrongModeRequiresActualSingleReadOnlyOriginalAndOtherCasesStaySingle() throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        let ro = prepared(f, count: 1, mode: "read-only"), values = credentials(ro)
        let selected = try select(.wrongMode, ro, values)
        let hello = try ManagedStorageOriginalConsumerComparison.originalConsumerWrongHello(binding(.wrongMode, ro, selected), snapshot: snapshot(ro, f))
        #expect(hello.binding.mode == "read-write")
        let rw = prepared(f, count: 1)
        #expect(throws: (any Error).self) { try select(.wrongMode, rw, credentials(rw)) }
        #expect(throws: (any Error).self) { try select(.wrongVolume, ro, values) }
        let pair = prepared(f)
        for name in [O.Case.crossEOldLeafReconnect, .crossEExistingData, .wrongKey, .wrongRole, .wrongEpoch] {
            #expect(try select(name, ro, values) == selected)
            #expect(throws: (any Error).self) { try select(name, pair, credentials(pair)) }
        }
        #expect(throws: (any Error).self) { try select(.wrongMode, pair, credentials(pair)) }
    }
    @Test(arguments: ["missing", "extra", "duplicate", "receipt", "key", "deleted", "different-target", "prepare-incomplete"])
    func ownerRejectsChangedMountedAlternative(_ fault: String) throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        var intent = prepared(f); let values = credentials(intent)
        let selected = try select(.wrongVolume, intent, values)
        var bound = binding(.wrongVolume, intent, selected)
        let index = try #require(intent.slots.firstIndex(where: { $0.attachment == values[1].attachment }))
        switch fault {
        case "missing": intent.slots.remove(at: index)
        case "extra", "duplicate": intent.slots.append(intent.slots[index])
        case "receipt":
            let slot = intent.slots[index]
            intent.slots[index].receipt = .init(try .init(schema: 3, store: intent.store, volume: slot.volume,
                attachment: slot.attachment, prepare: nil, launch: intent.launch, revision: 1))
        case "key": intent.slots[index].key = selected.key
        case "different-target": bound = binding(.wrongVolume, intent, values[1])
        case "prepare-incomplete": intent.prepareCompleted = false
        default: break
        }
        let current = snapshot(intent, f)
        let changed = ManagedStorageJournalSnapshot(revision: current.revision,
            volumes: fault == "deleted" ? [] : current.volumes, intents: current.intents, reconciliationRequired: false)
        #expect(throws: (any Error).self) { try ManagedStorageOriginalConsumerComparison.originalConsumerWrongHello(bound, snapshot: changed) }
    }
}

#if DEBUG
@Suite(.serialized) @MainActor struct OriginalConsumerSealedSuccessorTests {
    @Test func lifecycleSuccessorRejectsWrongOriginalScope() async throws {
        let f = try await ManagedStorageLifecycleOriginalConsumerTests.Fixture(); defer { f.disk.remove() }
        let old = try f.owner.workloadSession().service, request = f.request
        let maintenance = try await f.replace()
        let successor = try await f.owner.withOriginalConsumerSession(maintenance: maintenance,
            deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 5_000_000_000) { $0.service }
        let hash = String(repeating: "ab", count: 32), launch = consumerSuccessorID()
        let scope = WorkloadStorageProtocol.Scope(intent: consumerSuccessorID(), store: old.ready.identity.store,
            serviceEpoch: old.ready.serviceEpoch, controllerEpoch: old.ready.controllerEpoch,
            controllerKey: old.ready.controllerKey, container: hash, containerInstance: consumerSuccessorID(),
            launch: launch, prepare: consumerSuccessorID(), specificationDigest: hash)
        func binding(_ scope: WorkloadStorageProtocol.Scope, operation: String,
                     name: OriginalConsumerObservationProtocol.Case = .crossEOldLeafReconnect) -> OriginalConsumerObservationProtocol.Binding {
            .init(requestID: consumerSuccessorID(), armDigest: hash, operationUUID: operation, caseName: name, generation: 1,
                boot: .init(shimLaunchUUID: launch, guestBootNonce: consumerSuccessorID()), scope: scope,
                targetAttachment: consumerSuccessorID(), key: hash, certificateSHA256: hash)
        }
        for name in OriginalConsumerObservationProtocol.Case.allCases where name.isWrongHello {
            let original = binding(scope, operation: request.operationUUID, name: name)
            #expect(try ManagedStorageOriginalConsumerComparison.originalConsumerCurrentScope(original, current: .init(old.ready), request: request) == scope)
            #expect(throws: (any Error).self) {
                try ManagedStorageOriginalConsumerComparison.originalConsumerCurrentScope(original, current: .init(successor.ready), request: request)
            }
            #expect(throws: (any Error).self) {
                try ManagedStorageOriginalConsumerComparison.originalConsumerSuccessorScope(original, successor: .init(successor.ready), request: request)
            }
            var newScope = scope; newScope.serviceEpoch = successor.ready.serviceEpoch
            #expect(throws: (any Error).self) {
                try ManagedStorageOriginalConsumerComparison.originalConsumerCurrentScope(
                    binding(newScope, operation: request.operationUUID, name: name), current: .init(old.ready), request: request)
            }
            for fault in ["operation", "worker", "controller", "store"] {
                var wrong = scope, wrongRequest = request
                switch fault {
                case "operation": wrongRequest.operationUUID = consumerSuccessorID()
                case "worker": wrongRequest.predecessor.workerUUID = consumerSuccessorID()
                case "controller": wrong.controllerEpoch += 1
                default: wrong.store = consumerSuccessorID()
                }
                #expect(throws: (any Error).self) {
                    try ManagedStorageOriginalConsumerComparison.originalConsumerCurrentScope(
                        binding(wrong, operation: request.operationUUID, name: name), current: .init(old.ready), request: wrongRequest)
                }
            }
        }
        #expect(throws: (any Error).self) {
            try ManagedStorageOriginalConsumerComparison.originalConsumerCurrentScope(
                binding(scope, operation: request.operationUUID), current: .init(old.ready), request: request)
        }
        let result = try ManagedStorageOriginalConsumerComparison.originalConsumerSuccessorScope(binding(scope, operation: request.operationUUID),
            successor: .init(successor.ready), request: request)
        #expect(result.serviceEpoch == successor.ready.serviceEpoch)
        #expect(result.controllerEpoch == successor.ready.controllerEpoch)
        #expect(result.controllerKey == successor.ready.controllerKey)
        #expect(result.containerInstance == scope.containerInstance && result.launch == scope.launch)
        for name in [OriginalConsumerObservationProtocol.Case.crossEExistingData, .crossERetainedFD] {
            #expect(try ManagedStorageOriginalConsumerComparison.originalConsumerSuccessorScope(binding(scope, operation: request.operationUUID, name: name),
                successor: .init(successor.ready), request: request) == result)
        }
        for fault in ["store", "epoch", "launch", "operation", "case", "worker"] {
            var wrong = scope, wrongRequest = request
            switch fault {
            case "store": wrong.store = consumerSuccessorID()
            case "epoch": wrong.serviceEpoch = successor.ready.serviceEpoch
            case "launch": wrong.launch = consumerSuccessorID()
            case "worker": wrongRequest.predecessor.workerUUID = successor.ready.workerUUID
            default: break
            }
            let original = binding(wrong, operation: fault == "operation" ? consumerSuccessorID() : request.operationUUID,
                name: fault == "case" ? .sameERetainedFD : .crossEOldLeafReconnect)
            #expect(throws: (any Error).self) {
                try ManagedStorageOriginalConsumerComparison.originalConsumerSuccessorScope(original, successor: .init(successor.ready), request: wrongRequest)
            }
        }
        await f.owner.close()
    }
}

#endif

private func consumerSuccessorID() -> String { UUID().uuidString.lowercased() }
#endif

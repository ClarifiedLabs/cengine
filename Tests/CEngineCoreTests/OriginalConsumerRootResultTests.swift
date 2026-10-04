#if os(macOS)
import Darwin
import Foundation
import Testing
@testable import CEngineCore
@testable import CEngineRuntime

@MainActor @Suite struct OriginalConsumerRootResultTests {
    typealias O = OriginalConsumerObservationProtocol
    typealias C = ManagedStorageControlClient
    typealias R = OriginalConsumerRuntimeCarrier.RootResult
    typealias P = ManagedStorageControlProtocol

    func fixture(_ name: O.Case, schema: UInt64 = 3) throws -> R {
        let f = OriginalConsumerRootObservationTests()
        let (old, _, begun, attempted, status) = try f.fixture(name)
        var scope = old.scope; scope.controllerKey = String(repeating: "ef", count: 32)
        let binding = O.Binding(requestID: old.requestID, armDigest: old.armDigest, operationUUID: old.operationUUID,
            caseName: name, generation: old.generation, boot: old.boot, scope: scope,
            targetAttachment: old.targetAttachment, key: old.key, certificateSHA256: old.certificateSHA256)
        var positive = begun, original = attempted
        positive.arm = .init(binding); positive.scope = scope
        original.arm = .init(binding); original.scope = scope
        let roots = try #require(positive.roots)
        let items = try [roots.source, roots.target].map { value in
            let b = value.read.authority.binding
            return try P.Binding(store: b.store, volume: b.volume, attachment: b.attachment,
                container: b.container, launch: b.launch, key: b.key, role: .runtime, mode: .readOnly)
        }
        let before = C.Snapshot(schema: schema, revision: 5,
            store: .init(id: scope.store, deviceID: "owned", root: .init(device: 1, inode: 1), exports: .init(device: 1, inode: 2)),
            epoch: scope.serviceEpoch, controller: .init(epoch: scope.controllerEpoch, key: scope.controllerKey),
            volumes: Dictionary(uniqueKeysWithValues: items.enumerated().map { index, item in
                (item.volume, .init(id: item.volume, name: "root-\(index)", root: .init(device: 1, inode: UInt64(index + 3))))
            }), volumeLifecycles: Dictionary(uniqueKeysWithValues: items.map {
                ($0.volume, .init(phase: .ready, create: nil, delete: nil, createdRevision: nil, deletedRevision: nil))
            }), attachments: Dictionary(uniqueKeysWithValues: items.map {
                ($0.attachment, .init(binding: $0, phase: .active, receipt: nil, retirement: nil))
            }), prepares: [:])
        var atProbe = before
        var retirement: ManagedVolumeLifecycleCoordinator.OriginalRetirement?
        var worker: ConsumerObservationProtocol.Status?, finalized: ConsumerObservationProtocol.Status?
        if name == .retiredRootGrantReplay {
            let receipt = try P.Receipt(schema: 3, store: scope.store, volume: items[0].volume,
                attachment: items[0].attachment, launch: items[0].launch, revision: 6)
            let remote = C.Attachment(binding: items[0], phase: .drained, receipt: receipt, retirement: f.fourth)
            var attachments = before.attachments; attachments[items[0].attachment] = remote
            atProbe = .init(schema: schema, revision: 7, store: before.store, epoch: before.epoch, controller: before.controller,
                volumes: before.volumes, volumeLifecycles: before.volumeLifecycles, attachments: attachments, prepares: [:])
            retirement = .init(operation: f.fourth, receipt: receipt, queryRevision: 7,
                epoch: before.epoch, controller: before.controller, attachment: remote)
            worker = status; var final = status; final.state = .finalized; finalized = final
        }
        let request = try f.request(binding, .probe)
        let probe = try JSONDecoder().decode(O.Probe.self, from: request.payload)
        let pair = [roots.source, roots.target].enumerated().map { index, root in
            OriginalConsumerRuntimeCarrier.RootBaselineMount(volume: root.read.authority.binding.volume,
                readerAttachment: index == 0 ? f.id : f.fourth,
                readerKey: String(repeating: index == 0 ? "12" : "34", count: 32), contentSHA256: root.read.contentSHA256)
        }
        let baseline = OriginalConsumerRuntimeCarrier.Baseline(version: 2, binding: binding, readerIntent: f.third,
            readerAttachment: pair[0].readerAttachment, readerKey: pair[0].readerKey,
            snapshotSHA256: String(repeating: "56", count: 32), rootPair: pair)
        return R(binding: binding, service: status.query.workerScope, peer: probe.peer, baseline: baseline,
            positive: positive, original: original, authority: .init(before: before, atProbe: atProbe, after: atProbe,
                retirement: retirement), worker: worker, finalized: finalized)
    }

    @Test(arguments: [O.Case.crossMountRootGrant, .retiredRootGrantReplay])
    func rootBaselineIsRequiredBeforeBeginAndPinsBothPositiveVolumes(_ name: O.Case) throws {
        let value = try fixture(name)
        var gate = OriginalConsumerBaselineGate(binding: value.binding)
        #expect(throws: (any Error).self) { try gate.begin() }
        try value.baseline.validateRootPositive(value.positive)
        try gate.record(value.baseline, stage: "armed-mounted-positive")
        #expect(throws: (any Error).self) { try gate.record(value.baseline, stage: "armed-mounted-positive") }
        try gate.begin(); gate.release()
        #expect(throws: (any Error).self) { try gate.begin() }
        for fault in ["missing", "same-volume", "same-key", "source-content", "target-content", "reversed"] {
            var bad = value.baseline
            let pair = try #require(bad.rootPair)
            switch fault {
            case "missing": bad.rootPair = nil
            case "same-volume": bad.rootPair?[1] = .init(volume: pair[0].volume, readerAttachment: pair[1].readerAttachment,
                readerKey: pair[1].readerKey, contentSHA256: pair[1].contentSHA256)
            case "same-key": bad.rootPair?[1] = .init(volume: pair[1].volume, readerAttachment: pair[1].readerAttachment,
                readerKey: pair[0].readerKey, contentSHA256: pair[1].contentSHA256)
            case "reversed": bad.rootPair = pair.reversed()
            default:
                let index = fault == "source-content" ? 0 : 1
                bad.rootPair?[index] = .init(volume: pair[index].volume, readerAttachment: pair[index].readerAttachment,
                    readerKey: pair[index].readerKey, contentSHA256: String(repeating: "ff", count: 32))
            }
            #expect(throws: (any Error).self) { try bad.validateRootPositive(value.positive) }
        }
    }

    @Test(arguments: [O.Case.crossMountRootGrant, .retiredRootGrantReplay])
    func exactRegistryAndOriginalWireProofJoinWithoutInventingCrossMountDenial(_ name: O.Case) throws {
        let value = try fixture(name)
        try value.validate(original: value.binding, service: value.service)
        let decoded = try ManagedPrepareCompatibilityProtocol.decode(R.self,
            from: ManagedPrepareCompatibilityProtocol.canonicalData(value))
        #expect(decoded == value)
        try decoded.validate(original: value.binding, service: value.service)
        #expect((value.worker == nil) == (name == .crossMountRootGrant))
    }

    @Test(arguments: [O.Case.crossMountRootGrant, .retiredRootGrantReplay])
    func lifecycleRegistryRequiresPinnedIdentity(_ name: O.Case) throws {
        let value = try fixture(name, schema: 4)
        let identity = try StorageLifecycleProtocol.Identity(store: value.binding.scope.store,
            generation: 2, binding: String(repeating: "78", count: 32))
        try value.validate(original: value.binding, service: value.service, lifecycleIdentity: identity)
        let decoded = try ManagedPrepareCompatibilityProtocol.decode(R.self,
            from: ManagedPrepareCompatibilityProtocol.canonicalData(value))
        #expect(decoded == value)
        try decoded.validate(original: value.binding, service: value.service, lifecycleIdentity: identity)
        // Registry schema must not opt a legacy context into lifecycle validation.
        #expect(throws: C.Failure.protocolViolation) {
            try value.validate(original: value.binding, service: value.service)
        }
        let wrongStore = try StorageLifecycleProtocol.Identity(store: value.binding.scope.serviceEpoch,
            generation: identity.generation, binding: identity.binding)
        #expect(throws: C.Failure.invalidContext) {
            try value.validate(original: value.binding, service: value.service, lifecycleIdentity: wrongStore)
        }
        let legacy = try fixture(name)
        #expect(throws: C.Failure.protocolViolation) {
            try legacy.validate(original: legacy.binding, service: legacy.service, lifecycleIdentity: identity)
        }
    }

    // Shared by root and registration tests: exercise the real FD-pinned queue
    // publication boundary, not only the public result validators.
    func checkLifecycleQueue<T: Encodable>(_ result: T, binding b: O.Binding,
        service: ConsumerObservationProtocol.WorkerScope,
        baseline: OriginalConsumerRuntimeCarrier.Baseline? = nil, fault: String) throws {
        typealias Q = ManagedPrepareCompatibilityQueue
        typealias Carrier = ManagedPrepareCompatibilityProtocol
        let parent = FileManager.default.temporaryDirectory.appending(path: "original-result-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: parent) }
        let lock = try CanonicalDataStoreLock(root: parent.appending(path: "store"))
        let queue = try Q(storeLock: lock), directory = lock.root.appending(path: Q.directoryName)
        func put(_ bytes: Data, _ name: String) throws {
            let path = directory.appending(path: name)
            try bytes.write(to: path); #expect(chmod(path.path, 0o600) == 0)
        }
        let frame = try StorageLifecycleServiceBootProtocolTests.vectors()[2]
        let old = try #require(frame.ready)
        // Store generation deliberately differs from the workload shim generation.
        let identity = try StorageLifecycleProtocol.Identity(store: fault == "store" ? b.scope.serviceEpoch : b.scope.store,
            generation: b.generation + 17, binding: String(repeating: "78", count: 32))
        let ready = StorageLifecycleServiceBootProtocol.Ready(identity: identity,
            serviceEpoch: fault == "service" ? b.scope.store : b.scope.serviceEpoch,
            workerUUID: fault == "worker" ? UUID().uuidString.lowercased() : service.workerUUID,
            controllerEpoch: fault == "controller" ? b.scope.controllerEpoch + 1 : b.scope.controllerEpoch,
            controllerKey: fault == "key" ? String(repeating: "79", count: 32) : b.scope.controllerKey,
            revision: old.revision, openRevision: old.openRevision, bootstrapKey: old.bootstrapKey,
            tlsRootDER: old.tlsRootDER, serverDER: old.serverDER, serverSPKI: old.serverSPKI)
        let observation = try ManagedStorageLifecyclePeerObservation(binding: frame.binding, ready: ready,
            peer: .init(tlsRootDER: ready.tlsRootDER, serverDER: ready.serverDER,
                serverKey: ready.serverSPKI, dataAddress: "192.168.127.1"))
        if fault == "disk-only" {
            try put(observation.canonicalData(), observation.filename)
        } else if fault != "missing" {
            try queue.lifecyclePeerPublish(observation)
        }
        let request = OriginalConsumerRuntimeCarrier.Request(version: 1, profile: Carrier.fullProfile, requestID: b.requestID,
            operationUUID: b.operationUUID, caseName: b.caseName, container: b.scope.container, containerInstance: b.scope.containerInstance)
        let replacement = StorageServiceTypes.ReplacementRequest(operationUUID: b.operationUUID,
            predecessor: .init(serviceEpoch: b.scope.serviceEpoch, workerUUID: service.workerUUID), nowUnixSeconds: 1)
        try put(Carrier.canonicalData(request), "original-consumer.capture.json")
        let claim = try #require(try queue.originalCapture(replacement))
        try queue.originalCandidate(.init(request: request, binding: b, ownerRequest: replacement), claim: claim)
        try queue.originalPublish(b, phase: .armed, claim: claim)
        if let baseline {
            try put(Carrier.canonicalData(baseline), b.requestID + ".original-consumer.baseline.json")
            #expect(try queue.originalBaseline(binding: b, claim: claim) == baseline)
            try queue.originalPublish(baseline, phase: .baselineAccepted, claim: claim)
        }
        try queue.originalPublish(b, phase: .begun, claim: claim)
        if fault == "successor" {
            // Production retains the original workload peer, then publishes its
            // replacement before publishing this original-worker result.
            let successor = StorageLifecycleServiceBootProtocol.Ready(identity: identity,
                serviceEpoch: UUID().uuidString.lowercased(), workerUUID: UUID().uuidString.lowercased(),
                controllerEpoch: ready.controllerEpoch, controllerKey: ready.controllerKey,
                revision: ready.revision, openRevision: ready.openRevision, bootstrapKey: ready.bootstrapKey,
                tlsRootDER: ready.tlsRootDER, serverDER: ready.serverDER, serverSPKI: ready.serverSPKI)
            try queue.lifecyclePeerPublish(.init(binding: frame.binding, ready: successor, peer: observation.peer))
        }
        if fault == "tampered" {
            try put(observation.canonicalData() + Data([32]), observation.filename)
        }
        let path = directory.appending(path: b.requestID + ".original-consumer.result.json")
        if fault == "none" || fault == "successor" {
            try queue.originalPublish(result, phase: .result, claim: claim)
            #expect(try Data(contentsOf: path) == Carrier.canonicalData(result))
        } else {
            #expect(throws: (any Error).self) { try queue.originalPublish(result, phase: .result, claim: claim) }
            #expect(!FileManager.default.fileExists(atPath: path.path))
        }
    }

    @Test(arguments: [O.Case.crossMountRootGrant, .retiredRootGrantReplay],
        ["none", "successor", "missing", "disk-only", "store", "service", "worker", "controller", "key", "tampered"])
    func pinnedQueueUsesIndependentLifecycleIdentity(_ name: O.Case, _ fault: String) throws {
        let result = try fixture(name, schema: 4)
        try checkLifecycleQueue(result, binding: result.binding, service: result.service, baseline: result.baseline, fault: fault)
    }

    @Test(arguments: [O.Case.crossMountRootGrant, .retiredRootGrantReplay])
    func strictSchemaAndChangedRegistryOrWorkerCannotPublish(_ name: O.Case) throws {
        let value = try fixture(name)
        let bytes = try JSONEncoder().encode(value)
        let root = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        func check(_ object: [String: Any]) {
            #expect(throws: (any Error).self) {
                let decoded = try ManagedPrepareCompatibilityProtocol.decode(R.self,
                    from: JSONSerialization.data(withJSONObject: object))
                try decoded.validate(original: value.binding, service: value.service)
            }
        }
        for key in root.keys {
            var bad = root; bad.removeValue(forKey: key); check(bad)
            bad = root; bad[key] = NSNull(); check(bad)
        }
        var unknown = root; unknown["unknown"] = true; check(unknown)
        for fault in ["revision", "peer", "scope", "worker-id", "worker", "finalized", "retirement", "target", "content"] {
            var bad = root
            switch fault {
            case "peer": var peer = bad["peer"] as! [String: Any]; peer["serverDER"] = "CQ=="; bad["peer"] = peer
            case "worker-id": var service = bad["service"] as! [String: Any]; service["workerUUID"] = value.binding.scope.store; bad["service"] = service
            case "scope": var service = bad["service"] as! [String: Any]; service["serviceEpoch"] = value.binding.scope.store; bad["service"] = service
            case "worker", "finalized":
                if name == .retiredRootGrantReplay { bad.removeValue(forKey: fault) }
                else { bad[fault] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(fixture(.retiredRootGrantReplay).worker!)) }
            case "content":
                var evidence = bad["original"] as! [String: Any], roots = evidence["roots"] as! [String: Any]
                var replay = roots["replay"] as! [String: Any]; replay["contentSHA256"] = value.binding.key
                roots["replay"] = replay; evidence["roots"] = roots; bad["original"] = evidence
            default:
                var authority = bad["authority"] as! [String: Any]
                if fault == "retirement" {
                    if name == .retiredRootGrantReplay { authority.removeValue(forKey: "retirement") }
                    else { authority["retirement"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(fixture(.retiredRootGrantReplay).authority.retirement!)) }
                } else {
                    var after = authority["after"] as! [String: Any]
                    if fault == "revision" { after["revision"] = 99 }
                    else { after["attachments"] = [:] as [String: Any] }
                    authority["after"] = after
                }
                bad["authority"] = authority
            }
            check(bad)
        }
    }
}
#endif

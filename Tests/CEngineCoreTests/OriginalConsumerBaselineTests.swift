#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

/// Actual queue FDs + production sequencing/journal predicates. No verified boot,
/// signed activation, mounted VM or disk persistence is manufactured by these tests.
@Suite @MainActor struct OriginalConsumerBaselineTests {
    typealias O = OriginalConsumerObservationProtocol
    typealias Carrier = OriginalConsumerRuntimeCarrier
    typealias Q = ManagedPrepareCompatibilityQueue
    typealias Codec = ManagedPrepareCompatibilityProtocol
    private func id() -> String { UUID().uuidString.lowercased() }
    private let key = String(repeating: "ab", count: 32)
    private let readerKey = String(repeating: "cd", count: 32)
    private func changed<T: Codable>(_ value: T, _ edits: (inout [String: Any]) -> Void) throws -> T {
        var object = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as? [String: Any])
        edits(&object)
        return try JSONDecoder().decode(T.self, from: JSONSerialization.data(withJSONObject: object))
    }
    private func binding(_ name: O.Case = .sameERetainedFD) -> O.Binding {
        let launch = id()
        return .init(requestID: id(), armDigest: key, operationUUID: id(), caseName: name, generation: 7,
            boot: .init(shimLaunchUUID: launch, guestBootNonce: id()),
            scope: .init(intent: id(), store: id(), serviceEpoch: id(), controllerEpoch: 1, controllerKey: key,
                container: key, containerInstance: id(), launch: launch, prepare: id(), specificationDigest: key),
            targetAttachment: id(), key: key, certificateSHA256: key)
    }
    private func baseline(_ b: O.Binding) -> Carrier.Baseline {
        .init(version: 1, binding: b, readerIntent: id(), readerAttachment: id(), readerKey: readerKey, snapshotSHA256: key)
    }
    private func withQueue(_ b: O.Binding, _ body: (Q, Q.OriginalClaim, URL) throws -> Void) throws {
        let parent = URL(fileURLWithPath: "/private/tmp", isDirectory: true).appending(path: "rtm103-baseline-" + id())
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: parent) }
        let lock = try CanonicalDataStoreLock(root: parent.appending(path: "store"))
        let queue = try Q(storeLock: lock)
        let directory = lock.root.appending(path: Q.directoryName)
        let request = Carrier.Request(version: 1, profile: Codec.fullProfile, requestID: b.requestID,
            operationUUID: b.operationUUID, caseName: b.caseName, container: b.scope.container, containerInstance: b.scope.containerInstance)
        let replacement = StorageServiceTypes.ReplacementRequest(operationUUID: b.operationUUID,
            predecessor: .init(serviceEpoch: b.scope.serviceEpoch, workerUUID: id()), nowUnixSeconds: 1)
        try put(Codec.canonicalData(request), directory.appending(path: "original-consumer.capture.json"))
        let claim = try #require(try queue.originalCapture(replacement))
        try queue.originalCandidate(.init(request: request, binding: b, ownerRequest: replacement), claim: claim)
        try body(queue, claim, directory)
    }
    private func put(_ bytes: Data, _ path: URL) throws {
        try bytes.write(to: path)
        #expect(chmod(path.path, 0o600) == 0)
    }

    @Test(arguments: [O.Case.sameERetainedFD, .crossERetainedFD])
    func realQueueAndGateRequirePostArmBaselineBeforeBegin(_ name: O.Case) throws {
        let b = binding(name), value = baseline(b)
        try withQueue(b) { queue, claim, directory in
            var gate = OriginalConsumerBaselineGate(binding: b)
            #expect(throws: (any Error).self) { try gate.begin() }
            #expect(throws: (any Error).self) { try queue.originalBaseline(binding: b, claim: claim) }
            try queue.originalPublish(b, phase: .armed, claim: claim)
            #expect(try queue.originalBaseline(binding: b, claim: claim) == nil)
            #expect(throws: (any Error).self) { try queue.originalPublish(b, phase: .begun, claim: claim) }
            #expect(throws: (any Error).self) { try queue.originalPublish(value, phase: .baselineAccepted, claim: claim) }
            try put(Codec.canonicalData(value), directory.appending(path: b.requestID + ".original-consumer.baseline.json"))
            let read = try #require(try queue.originalBaseline(binding: b, claim: claim))
            #expect(read == value)
            try gate.record(read, stage: "armed-mounted-positive")
            try queue.originalPublish(read, phase: .baselineAccepted, claim: claim)
            try gate.begin()
            try queue.originalPublish(b, phase: .begun, claim: claim)
            #expect(throws: (any Error).self) { try gate.begin() }
            #expect(throws: (any Error).self) { try gate.record(read, stage: "armed-mounted-positive") }
            #expect(throws: (any Error).self) { try queue.originalBaseline(binding: b, claim: claim) }
            try queue.originalPublish(b, phase: .result, claim: claim)
            #expect(throws: (any Error).self) { try queue.originalPublish(b, phase: .result, claim: claim) }
        }
    }

    @Test(arguments: ["generation", "boot", "key", "intent", "operation", "request", "stage", "released", "duplicate"])
    func exactOriginalGenerationAndReleaseCannotBeBypassed(_ fault: String) throws {
        let b = binding(), value = baseline(b)
        var gate = OriginalConsumerBaselineGate(binding: b)
        var candidate = value
        if fault == "released" { gate.release() }
        else if fault == "duplicate" { try gate.record(value, stage: "armed-mounted-positive") }
        else if fault != "stage" {
            let wrong = try changed(b) { object in
                switch fault {
                case "generation": object["generation"] = b.generation + 1
                case "boot": object["boot"] = ["shimLaunchUUID": b.scope.launch, "guestBootNonce": id()]
                case "key": object["key"] = readerKey
                case "intent": var scope = object["scope"] as! [String: Any]; scope["intent"] = id(); object["scope"] = scope
                case "operation": object["operationUUID"] = id()
                default: object["requestID"] = id()
                }
            }
            candidate = .init(version: 1, binding: wrong, readerIntent: value.readerIntent,
                readerAttachment: value.readerAttachment, readerKey: value.readerKey, snapshotSHA256: value.snapshotSHA256)
        }
        #expect(throws: (any Error).self) { try gate.record(candidate, stage: fault == "stage" ? "begun" : "armed-mounted-positive") }
        if fault == "released" { #expect(throws: (any Error).self) { try gate.begin() } }
    }

    @Test(arguments: ["replace", "mutate", "symlink", "hardlink", "unknown", "null", "foreign", "oversize"])
    func pinnedBaselineRejectsFilesystemAndCodecChanges(_ fault: String) throws {
        let b = binding(), value = baseline(b)
        try withQueue(b) { queue, claim, directory in
            try queue.originalPublish(b, phase: .armed, claim: claim)
            let path = directory.appending(path: b.requestID + ".original-consumer.baseline.json")
            let bytes = try Codec.canonicalData(value)
            if fault == "symlink" {
                let target = directory.appending(path: "other.json"); try put(bytes, target)
                #expect(symlink(target.path, path.path) == 0)
            } else if fault == "hardlink" {
                let target = directory.appending(path: "other.json"); try put(bytes, target)
                #expect(link(target.path, path.path) == 0)
            } else if fault == "oversize" { try put(Data(repeating: 0x20, count: 65537), path) }
            else if ["unknown", "null", "foreign"].contains(fault) {
                var object = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
                if fault == "unknown" { object["privateKey"] = "forbidden" }
                if fault == "null" { object["snapshotSHA256"] = NSNull() }
                if fault == "foreign" { object["readerIntent"] = b.scope.intent }
                try put(JSONSerialization.data(withJSONObject: object), path)
            } else {
                try put(bytes, path)
                _ = try #require(try queue.originalBaseline(binding: b, claim: claim))
                if fault == "replace" { try FileManager.default.removeItem(at: path); try put(bytes, path) }
                else { try put(Data("{}".utf8), path) }
                #expect(throws: (any Error).self) { try queue.originalPublish(value, phase: .baselineAccepted, claim: claim) }
                return
            }
            #expect(throws: (any Error).self) { try queue.originalBaseline(binding: b, claim: claim) }
        }
    }

    @Test(arguments: ["valid", "epoch", "controller", "store", "volume", "mode", "key", "attachment", "container", "launch", "phase", "prepare", "reconcile", "original-retired", "reader-receipt"])
    func readerMustBeIndependentRunningSameVolumeCurrentAuthority(_ fault: String) throws {
        let f = try HostIntentFixture(); defer { f.remove() }
        var original = f.intent(Array(f.volumes.prefix(1)))
        original.phase = .running; original.prepareCompleted = true
        let index = try #require(original.slots.firstIndex { $0.role == "runtime" })
        original.slots[index].key = key
        var reader = try changed(f.intent(Array(f.volumes.prefix(1)))) { object in
            object["container"] = readerKey; object["serviceEpoch"] = original.serviceEpoch
        }
        reader.phase = .running; reader.prepareCompleted = true; reader.slots[index].key = readerKey
        let scope = WorkloadStorageProtocol.Scope(intent: original.id, store: original.store,
            serviceEpoch: original.serviceEpoch, controllerEpoch: original.controllerEpoch, controllerKey: original.controllerKey,
            container: original.container, containerInstance: original.containerInstance, launch: original.launch,
            prepare: original.prepare, specificationDigest: original.specificationDigest)
        let b = O.Binding(requestID: id(), armDigest: key, operationUUID: id(), caseName: .sameERetainedFD, generation: 7,
            boot: .init(shimLaunchUUID: original.launch, guestBootNonce: id()), scope: scope,
            targetAttachment: original.slots[index].attachment, key: key, certificateSHA256: key)
        let value = Carrier.Baseline(version: 1, binding: b, readerIntent: reader.id,
            readerAttachment: reader.slots[index].attachment, readerKey: readerKey, snapshotSHA256: key)
        reader = try changed(reader) { object in
            switch fault {
            case "epoch": object["serviceEpoch"] = id()
            case "controller": object["controllerEpoch"] = 2
            case "store": object["store"] = id()
            case "container": object["container"] = original.container
            case "launch": object["launch"] = original.launch
            case "phase": object["phase"] = "retired"
            case "prepare": object["prepareCompleted"] = false
            case "volume", "mode", "key", "attachment":
                var slots = object["slots"] as! [[String: Any]]
                slots[index][fault] = fault == "mode" ? "read-only" : fault == "key" ? key : id()
                object["slots"] = slots
            default: break
            }
        }
        if fault == "original-retired" { original.phase = .retired }
        if fault == "reader-receipt" {
            reader.slots[index].receipt = .init(try .init(schema: 3, store: reader.store,
                volume: reader.slots[index].volume, attachment: reader.slots[index].attachment,
                launch: reader.launch, revision: 2))
        }
        let snapshot = ManagedStorageJournalSnapshot(revision: 1, volumes: f.volumes, intents: [original, reader], reconciliationRequired: fault == "reconcile")
        if fault == "valid" { #expect(try RawManagedStorageBackend.originalBaselineReader(value, snapshot: snapshot) == reader) }
        else { #expect(throws: (any Error).self) { try RawManagedStorageBackend.originalBaselineReader(value, snapshot: snapshot) } }
    }

    @Test func releaseAndContainmentRunWhenBaselineReaderFails() async throws {
        enum Failed: Error { case reader }
        let b = binding(); var gate = OriginalConsumerBaselineGate(binding: b)
        var events: [String] = []
        await #expect(throws: Failed.self) {
            let _: Void = try await OriginalConsumerCleanup.run(operation: { throw Failed.reader }, release: {
                gate.release(); events.append("release")
            }, contain: { events.append("contain") })
        }
        #expect(events == ["release", "contain"])
        #expect(throws: (any Error).self) { try gate.record(baseline(b), stage: "armed-mounted-positive") }
        #expect(throws: (any Error).self) { try gate.begin() }
    }
}
#endif

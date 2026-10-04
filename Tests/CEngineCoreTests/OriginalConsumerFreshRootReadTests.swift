#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

@Suite @MainActor struct OriginalConsumerFreshRootReadTests {
    typealias O = OriginalConsumerObservationProtocol
    typealias F = OriginalConsumerRuntimeCarrier.FreshRootRead
    typealias R = OriginalConsumerRuntimeCarrier.RootResult
    typealias C = ManagedPrepareCompatibilityProtocol
    func id() -> String { UUID().uuidString.lowercased() }
    func fixture(_ name: O.Case, reversed: Bool = false) throws -> (R, F) {
        let previous = try OriginalConsumerRootResultTests().fixture(name), old = previous.binding
        var scope = old.scope
        scope.intent = id(); scope.launch = id(); scope.prepare = id(); scope.serviceEpoch = id()
        let key = String(repeating: "78", count: 32), leaf = String(repeating: "9a", count: 32)
        let binding = O.Binding(requestID: old.requestID, armDigest: old.armDigest, operationUUID: old.operationUUID,
            caseName: .crossMountRootGrant, generation: old.generation + 1,
            boot: .init(shimLaunchUUID: scope.launch, guestBootNonce: id()), scope: scope,
            targetAttachment: "00000000-0000-4000-8000-00000000000a", key: key, certificateSHA256: leaf)
        var evidence = previous.positive
        evidence.arm = .init(binding); evidence.scope = scope; evidence.keySHA256 = key; evidence.stage = "armed-mounted-positive"
        let prior = try #require(evidence.roots)
        var pair = reversed ? [prior.target, prior.source] : [prior.source, prior.target]
        for index in pair.indices {
            let old = pair[index].read.authority.binding
            pair[index].read.authority = .init(epoch: scope.serviceEpoch,
                binding: .init(store: scope.store, volume: old.volume,
                    attachment: index == 0 ? binding.targetAttachment : "00000000-0000-4000-8000-00000000000b",
                    container: scope.container, launch: scope.launch,
                    key: index == 0 ? key : String(repeating: "bc", count: 32), mode: old.mode))
            pair[index].leafSHA256 = index == 0 ? leaf : String(repeating: "de", count: 32)
        }
        var updated = prior
        updated.source = pair[0]; updated.target = pair[1]; updated.replay = nil
        evidence.roots = updated
        evidence.rootRequest = pair[0].rootRequest
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        evidence.mountIdentitySHA256 = WorkloadStorageProtocol.specificationDigest(try encoder.encode(
            ["Source": pair[0].identitySHA256, "Target": pair[1].identitySHA256]))
        return (previous, F(original: old, binding: binding, service: .init(serviceEpoch: scope.serviceEpoch, workerUUID: id()),
            serverDERSHA256: String(repeating: "12", count: 32), evidence: evidence, released: true))
    }
    @Test(arguments: [O.Case.crossMountRootGrant, .retiredRootGrantReplay], [false, true])
    func bothCasesMatchVolumesEvenWhenFreshAttachmentOrderChanges(_ name: O.Case, _ reversed: Bool) throws {
        let (previous, proof) = try fixture(name, reversed: reversed)
        try proof.validate(previous: previous)
        let decoded = try C.decode(F.self, from: C.canonicalData(proof))
        #expect(decoded == proof)
        try decoded.validate(previous: previous)
    }
    @Test(arguments: ["released", "worker", "epoch", "generation", "content", "volume", "leaf", "stat", "begun", "null", "unknown", "float"])
    func staleIdentityOrSnapshotCannotBecomeFreshWireRead(_ fault: String) throws {
        let (previous, proof) = try fixture(.retiredRootGrantReplay)
        var raw = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(proof)) as? [String: Any])
        var binding = raw["binding"] as! [String: Any], evidence = raw["evidence"] as! [String: Any]
        switch fault {
        case "released": raw["released"] = false
        case "worker": raw["service"] = ["workerUUID": previous.service.workerUUID, "serviceEpoch": proof.service.serviceEpoch]
        case "epoch": var scope = binding["scope"] as! [String: Any]; scope["serviceEpoch"] = previous.binding.scope.serviceEpoch; binding["scope"] = scope
        case "generation": binding["generation"] = previous.binding.generation
        case "stat": evidence["fdOperation"] = "fsync-directory"
        case "begun": evidence["stage"] = "begun"
        case "null": raw["released"] = NSNull()
        case "unknown": raw["unknown"] = true
        case "float": evidence["fdSequence"] = 1.0
        default:
            var roots = evidence["roots"] as! [String: Any], target = roots["target"] as! [String: Any]
            var read = target["read"] as! [String: Any]
            if fault == "content" { read["contentSHA256"] = String(repeating: "ff", count: 32) }
            if fault == "leaf" { target["leafSHA256"] = previous.positive.roots!.target.leafSHA256 }
            if fault == "volume" {
                var authority = read["authority"] as! [String: Any], b = authority["binding"] as! [String: Any]
                b["volume"] = id(); authority["binding"] = b; read["authority"] = authority
            }
            target["read"] = read; roots["target"] = target; evidence["roots"] = roots
        }
        raw["binding"] = binding; raw["evidence"] = evidence
        #expect(throws: (any Error).self) {
            var data = try JSONSerialization.data(withJSONObject: raw)
            if fault == "float" { data = Data(String(decoding: data, as: UTF8.self).replacingOccurrences(of: "\"fdSequence\":1", with: "\"fdSequence\":1.0").utf8) }
            let decoded = try C.decode(F.self, from: data)
            try decoded.validate(previous: previous)
        }
    }
    @Test func pinnedQueueRequiresResultBaselineAndOneFreshPublication() async throws {
        let (previous, proof) = try fixture(.retiredRootGrantReplay), b = previous.binding
        let parent = URL(fileURLWithPath: "/private/tmp", isDirectory: true).appending(path: "rtm103-fresh-root-" + id())
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: parent) }
        let lock = try CanonicalDataStoreLock(root: parent.appending(path: "store"))
        let queue = try ManagedPrepareCompatibilityQueue(storeLock: lock)
        let request = OriginalConsumerRuntimeCarrier.Request(version: 1, profile: C.fullProfile, requestID: b.requestID,
            operationUUID: b.operationUUID, caseName: b.caseName, container: b.scope.container, containerInstance: b.scope.containerInstance)
        let replacement = StorageServiceTypes.ReplacementRequest(operationUUID: b.operationUUID,
            predecessor: .init(serviceEpoch: b.scope.serviceEpoch, workerUUID: previous.service.workerUUID), nowUnixSeconds: 1)
        let directory = lock.root.appending(path: ManagedPrepareCompatibilityQueue.directoryName)
        func publish<T: Encodable>(_ value: T, _ name: String) throws {
            let path = directory.appending(path: name)
            try C.canonicalData(value).write(to: path); #expect(chmod(path.path, 0o600) == 0)
        }
        try publish(request, "original-consumer.capture.json")
        let claim = try #require(try queue.originalCapture(replacement))
        try queue.originalCandidate(.init(request: request, binding: b, ownerRequest: replacement), claim: claim)
        #expect(throws: (any Error).self) { try queue.originalPublish(proof, phase: .freshRootRead, claim: claim) }
        try queue.originalPublish(b, phase: .armed, claim: claim)
        try publish(previous.baseline, b.requestID + ".original-consumer.baseline.json")
        #expect(try queue.originalBaseline(binding: b, claim: claim) == previous.baseline)
        try queue.originalPublish(previous.baseline, phase: .baselineAccepted, claim: claim)
        try queue.originalPublish(b, phase: .begun, claim: claim)
        // Native publication runs on a bounded concurrency worker, not the
        // larger main-thread stack used by this suite's fixture construction.
        try await Task.detached {
            try queue.originalPublish(previous, phase: .result, claim: claim)
            try queue.originalPublish(proof, phase: .freshRootRead, claim: claim)
        }.value
        #expect(throws: (any Error).self) { try queue.originalPublish(proof, phase: .freshRootRead, claim: claim) }
    }
}
#endif

#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

@Suite @MainActor struct OriginalConsumerFreshGetattrTests {
    typealias O = OriginalConsumerObservationProtocol
    typealias F = OriginalConsumerRuntimeCarrier.FreshGetattr
    typealias C = ManagedPrepareCompatibilityProtocol
    private func id() -> String { UUID().uuidString.lowercased() }
    private let hash = String(repeating: "ab", count: 32)
    private func object<T: Encodable>(_ value: T) throws -> [String: Any] {
        try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as? [String: Any])
    }
    private func fixture(_ name: O.Case = .sameEExistingData) throws -> F {
        let launch = id()
        let original = O.Binding(requestID: id(), armDigest: hash, operationUUID: id(), caseName: name, generation: 1,
            boot: .init(shimLaunchUUID: launch, guestBootNonce: id()),
            scope: .init(intent: id(), store: id(), serviceEpoch: id(), controllerEpoch: 1, controllerKey: hash,
                container: hash, containerInstance: id(), launch: launch, prepare: id(), specificationDigest: hash),
            targetAttachment: id(), key: hash, certificateSHA256: hash)
        var scope = original.scope
        scope.intent = id(); scope.launch = id(); scope.prepare = id(); scope.serviceEpoch = id()
        let fresh = O.Binding(requestID: original.requestID, armDigest: original.armDigest, operationUUID: original.operationUUID,
            caseName: .sameEExistingData, generation: 2, boot: .init(shimLaunchUUID: scope.launch, guestBootNonce: id()), scope: scope,
            targetAttachment: id(), key: String(repeating: "cd", count: 32), certificateSHA256: String(repeating: "ef", count: 32))
        let data: [String: Any] = ["arm": try object(O.GuestArm(fresh)), "stage": "armed-mounted-positive", "scope": try object(scope),
            "keySHA256": fresh.key, "mountIdentitySHA256": hash, "serverDERSHA256": "", "signCount": 0, "signInputSHA256": "",
            "bytesWrittenAfterSign": 0, "clientWrittenBytes": 0, "clientPrefixBytes": 0, "clientPrefixSHA256": "", "localError": "",
            "fdOperation": "fsync-directory", "fdSequence": 1,
            "rootRequest": ["node": 99, "requestSequence": 7],
            "originalOperation": ["kind": "data-getattr-root", "sequence": 1, "errorClass": "ok"]]
        let evidence = try JSONDecoder().decode(O.Evidence.self, from: JSONSerialization.data(withJSONObject: data))
        return .init(original: original, binding: fresh, service: .init(serviceEpoch: scope.serviceEpoch, workerUUID: id()),
            serverDERSHA256: hash, evidence: evidence, released: true)
    }
    @Test(arguments: [O.Case.sameEExistingData, .crossEExistingData, .sameEOldLeafReconnect, .attachmentKeyReuse, .delayedRegistration])
    func exactSealedPositiveOnlyShape(_ name: O.Case) throws {
        let f = try fixture(name)
        try f.validate(original: f.original)
        #expect(try C.decode(F.self, from: C.canonicalData(f)) == f)
    }
    @Test(arguments: ["released", "key", "epoch", "instance", "generation", "operation", "digest", "worker", "node", "stat", "error", "begun", "unknown", "null", "fraction"])
    func staleOrSubstitutedWitnessRejected(_ fault: String) throws {
        let f = try fixture(); var raw = try object(f)
        var binding = raw["binding"] as! [String: Any], evidence = raw["evidence"] as! [String: Any]
        switch fault {
        case "released": raw["released"] = false
        case "key": binding["key"] = f.original.key
        case "generation": binding["generation"] = f.original.generation
        case "operation": binding["operationUUID"] = id()
        case "digest": binding["armDigest"] = String(repeating: "12", count: 32)
        case "instance", "epoch":
            var scope = binding["scope"] as! [String: Any]
            scope[fault == "epoch" ? "serviceEpoch" : "containerInstance"] = fault == "epoch" ? f.original.scope.serviceEpoch : id()
            binding["scope"] = scope
        case "worker": raw["service"] = ["serviceEpoch": f.binding.scope.serviceEpoch, "workerUUID": "not-id"]
        case "node": evidence["rootRequest"] = ["node": 0, "requestSequence": 7]
        case "stat", "error": evidence["originalOperation"] = ["kind": fault == "stat" ? "fsync-directory" : "data-getattr-root", "sequence": 1, "errorClass": fault == "error" ? "eio" : "ok"]
        case "begun": evidence["stage"] = "begun"
        case "unknown": raw["privateKey"] = "forbidden"
        case "null": raw["released"] = NSNull()
        default: evidence["fdSequence"] = 1.5
        }
        raw["binding"] = binding; raw["evidence"] = evidence
        #expect(throws: (any Error).self) {
            let decoded = try C.decode(F.self, from: JSONSerialization.data(withJSONObject: raw))
            try decoded.validate(original: f.original)
        }
    }
    @Test func pinnedQueueRequiresOriginalResultAndOneFreshPublication() throws {
        let f = try fixture(), b = f.original
        let parent = URL(fileURLWithPath: "/private/tmp", isDirectory: true).appending(path: "rtm103-fresh-" + id())
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: parent) }
        let lock = try CanonicalDataStoreLock(root: parent.appending(path: "store"))
        let queue = try ManagedPrepareCompatibilityQueue(storeLock: lock)
        let request = OriginalConsumerRuntimeCarrier.Request(version: 1, profile: C.fullProfile, requestID: b.requestID,
            operationUUID: b.operationUUID, caseName: b.caseName, container: b.scope.container, containerInstance: b.scope.containerInstance)
        let replacement = StorageServiceTypes.ReplacementRequest(operationUUID: b.operationUUID,
            predecessor: .init(serviceEpoch: b.scope.serviceEpoch, workerUUID: id()), nowUnixSeconds: 1)
        let path = lock.root.appending(path: ManagedPrepareCompatibilityQueue.directoryName).appending(path: "original-consumer.capture.json")
        try C.canonicalData(request).write(to: path); #expect(chmod(path.path, 0o600) == 0)
        let claim = try #require(try queue.originalCapture(replacement))
        try queue.originalCandidate(.init(request: request, binding: b, ownerRequest: replacement), claim: claim)
        #expect(throws: (any Error).self) { try queue.originalPublish(f, phase: .freshGetattr, claim: claim) }
        try queue.originalPublish(b, phase: .armed, claim: claim)
        try queue.originalPublish(b, phase: .begun, claim: claim)
        #expect(throws: (any Error).self) { try queue.originalPublish(f, phase: .freshGetattr, claim: claim) }
        try queue.originalPublish(b, phase: .result, claim: claim)
        try queue.originalPublish(f, phase: .freshGetattr, claim: claim)
        #expect(throws: (any Error).self) { try queue.originalPublish(f, phase: .freshGetattr, claim: claim) }
    }
}
#endif

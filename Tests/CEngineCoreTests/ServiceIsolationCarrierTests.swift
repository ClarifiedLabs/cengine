#if os(macOS)
import CEngineCore
import Foundation
import Testing
@testable import CEngineRuntime

@Suite @MainActor struct ServiceIsolationCarrierTests {
    @Test(arguments: ["legacy-connection", "second-service-exclusivity", "unknown", "mixed", "null", "extra", "result", "revision"])
    func closedProof(_ mode: String) throws {
        let id = UUID().uuidString.lowercased()
        let kind = mode == "second-service-exclusivity" ? mode : "legacy-connection"
        var proof: [String: Any] = ["request": ["requestID": id, "operationUUID": id, "challenge": id, "armDigest": String(repeating: "b", count: 64)], "workerUUID": id, "caseName": kind, "store": id, "serviceEpoch": id,
            "revision": 1, "registrySHA256": String(repeating: "a", count: 64),
            "result": kind == "legacy-connection" ? "legacy-tls-header-rejected" : "second-owner-locked"]
        if mode == "unknown" { proof["caseName"] = "unknown" }
        if mode == "extra" { proof["authorized"] = true }
        if mode == "result" { proof["result"] = "eof" }
        if mode == "revision" { proof["revision"] = 0 }
        var frame: [String: Any] = ["version": StorageLifecycleServiceBootProtocol.version, "operation": "reply", "sequence": 1,
            "service_epoch": id, "worker_uuid": id,
            "binding": ["shimLaunchUUID": id, "guestBootNonce": id, "ext4UUID": id, "bytes": 4096], "isolationProof": proof]
        if mode == "mixed" { frame["code"] = "command" }
        if mode == "null" { frame["isolationProof"] = NSNull() }
        let data = try JSONSerialization.data(withJSONObject: frame, options: [.sortedKeys, .withoutEscapingSlashes])
        if ["legacy-connection", "second-service-exclusivity"].contains(mode) {
            let reply = try StorageLifecycleServiceBootProtocol.decode(data)
            #expect(reply.isolationProof?.caseName == kind)
        } else {
            #expect(throws: (any Error).self) { try StorageLifecycleServiceBootProtocol.decode(data) }
        }
    }
    @Test(arguments: ["valid", "digest", "worker", "challenge", "arm", "revision"])
    func independentlyComparedReceipt(_ mode: String) throws {
        let id = UUID().uuidString.lowercased()
        let request: [String: Any] = ["requestID": id, "operationUUID": id, "challenge": id, "armDigest": String(repeating: "a", count: 64)]
        let state: [String: Any] = ["request": request, "workerUUID": id, "caseName": "isolation-state", "store": id, "serviceEpoch": id, "revision": 1, "registrySHA256": String(repeating: "b", count: 64), "result": "registry-state"]
        var probe = state; probe["caseName"] = "legacy-connection"; probe["result"] = "legacy-tls-header-rejected"
        if mode == "digest" { probe["registrySHA256"] = String(repeating: "c", count: 64) }
        if mode == "worker" { probe["workerUUID"] = UUID().uuidString.lowercased() }
        if mode == "revision" { probe["revision"] = 2 }
        if mode == "challenge" || mode == "arm" {
            var r = request; r[mode == "challenge" ? "challenge" : "armDigest"] = mode == "challenge" ? UUID().uuidString.lowercased() : String(repeating: "c", count: 64)
            probe["request"] = r
        }
        func decode(_ value: [String: Any]) throws -> StorageServiceTypes.IsolationProof {
            try JSONDecoder().decode(StorageServiceTypes.IsolationProof.self, from: JSONSerialization.data(withJSONObject: value))
        }
        let before = try decode(state), observation = try decode(probe)
        var afterFields = probe; afterFields["caseName"] = "isolation-state"; afterFields["result"] = "registry-state"
        let after = try decode(afterFields)
        if mode == "valid" { _ = try StorageServiceTypes.IsolationStatePair(before: before, after: after) }
        else { #expect(throws: (any Error).self) { try StorageServiceTypes.IsolationStatePair(before: before, after: after) } }
        if mode == "valid" { _ = try StorageServiceTypes.IsolationReceipt(before: before, observation: observation, after: before) }
        else { #expect(throws: (any Error).self) { try StorageServiceTypes.IsolationReceipt(before: before, observation: observation, after: before) } }
    }
    @Test(arguments: [false, true])
    func unrelatedCommandsRejectIsolationRequest(_ prepare: Bool) throws {
        typealias B = StorageLifecycleServiceBootProtocol
        let id = "11111111-1111-4111-8111-111111111111", other = "22222222-2222-4222-8222-222222222222"
        let hash = String(repeating: "ab", count: 32)
        var command = B.Frame(operation: .command, binding: .init(shimLaunchUUID: id, guestBootNonce: other, ext4UUID: id, bytes: 4096), sequence: 1,
            serviceEpoch: other, command: prepare ? .prepareCompatibilityObserve : .consumerObservationQuery, workerUUID: other)
        if prepare {
            command.prepareCompatibilityQuery = .init(requestID: id, armDigest: hash, workerUUID: other)
        } else {
            command.consumerObservationQuery = .init(requestID: id, armDigest: hash, operationUUID: other, caseName: .crossE,
                originalBootBinding: .init(shimLaunchUUID: id, guestBootNonce: other),
                original: .init(epoch: id, binding: .init(store: id, volume: other, attachment: other, container: hash, launch: id, key: hash, mode: "read-write")),
                originalLeafSHA256: hash, workerScope: .init(storeUUID: id, serviceEpoch: other, workerUUID: other))
        }
        _ = try B.encode(command)
        command.isolationRequest = .init(requestID: id, operationUUID: id, armDigest: hash, challenge: other)
        #expect(throws: (any Error).self) { try B.encode(command) }
    }
    @Test(arguments: ["legacy-connection", "second-service-exclusivity", "unknown", "unreleased"])
    func queueRequiresProbePositiveAndJoinedRelease(_ kind: String) throws {
        func id() -> String { UUID().uuidString.lowercased() }
        let parent = FileManager.default.temporaryDirectory.appending(path: "isolation-" + id())
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: parent) }
        let lock = try CanonicalDataStoreLock(root: parent.appending(path: "store"))
        let queue = try ManagedPrepareCompatibilityQueue(storeLock: lock)
        var request = ManagedPrepareCompatibilityQueue.PublicTakeoverArmCapture(version: "original-takeover-arm.v1", requestID: id(), operationUUID: id(), store: id(), epoch: 2, serviceEpoch: id(), container: String(repeating: "a", count: 64), containerInstance: id())
        request.positiveOnly = kind == "unreleased" ? nil : true
        request.isolationCase = kind == "unreleased" ? "legacy-connection" : kind
        let file = parent.appending(path: "store/managed-prepare-compatibility/public-takeover-arm.capture.json")
        try ManagedPrepareCompatibilityProtocol.canonicalData(request).write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        if ["unknown", "unreleased"].contains(kind) {
            #expect(throws: (any Error).self) { try queue.publicTakeoverArmCapture(container: request.container, instance: request.containerInstance) }
            return
        }
        let captured = try queue.publicTakeoverArmCapture(container: request.container, instance: request.containerInstance)
        let claim = try #require(captured)
        for phase in ["candidate", "armed", "registry", "isolation", "positive"] {
            #expect(throws: (any Error).self) { try queue.publicTakeoverArmPublish(Data("{}".utf8), phase: "released", claim: claim) }
            try queue.publicTakeoverArmPublish(Data("{}".utf8), phase: phase, claim: claim)
        }
        try queue.publicTakeoverArmPublish(Data("{}".utf8), phase: "released", claim: claim)
        #expect(throws: (any Error).self) { try queue.publicTakeoverArmPublish(Data("{}".utf8), phase: "released", claim: claim) }
    }
}
#endif

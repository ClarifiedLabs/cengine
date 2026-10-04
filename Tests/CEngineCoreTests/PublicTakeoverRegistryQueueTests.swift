#if os(macOS)
import CEngineCore
import Foundation
import Testing
@testable import CEngineRuntime

@Suite @MainActor struct PublicTakeoverRegistryQueueTests {
    @Test(arguments: ["original", "fresh", "false", "null", "alias"])
    func registryAndFreshReleaseAreOrdered(_ mode: String) throws {
        typealias Q = ManagedPrepareCompatibilityQueue
        func id() -> String { UUID().uuidString.lowercased() }
        let parent = FileManager.default.temporaryDirectory.appending(path: "registry-" + id())
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: parent) }
        let lock = try CanonicalDataStoreLock(root: parent.appending(path: "store"))
        let queue = try Q(storeLock: lock)
        var request = Q.PublicTakeoverArmCapture(version: "original-takeover-arm.v1", requestID: id(), operationUUID: id(),
            store: id(), epoch: 3, serviceEpoch: id(), container: String(repeating: "a", count: 64), containerInstance: id())
        if mode == "fresh" { request.positiveOnly = true }
        var fields = try #require(JSONSerialization.jsonObject(with: ManagedPrepareCompatibilityProtocol.canonicalData(request)) as? [String: Any])
        if mode == "false" { fields["positiveOnly"] = false }
        if mode == "null" { fields["positiveOnly"] = NSNull() }
        if mode == "alias" { fields["positiveOnly"] = 1 }
        let file = parent.appending(path: "store/managed-prepare-compatibility/public-takeover-arm.capture.json")
        try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes]).write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        if ["false", "null", "alias"].contains(mode) {
            #expect(throws: (any Error).self) { try queue.publicTakeoverArmCapture(container: request.container, instance: request.containerInstance) }
            return
        }
        let result = try queue.publicTakeoverArmCapture(container: request.container, instance: request.containerInstance)
        let claim = try #require(result)
        let bytes = Data("{}".utf8)
        for phase in ["candidate", "armed", "registry"] {
            #expect(throws: (any Error).self) { try queue.publicTakeoverArmPublish(bytes, phase: "released", claim: claim) }
            try queue.publicTakeoverArmPublish(bytes, phase: phase, claim: claim)
        }
        if mode == "fresh" { try queue.publicTakeoverArmPublish(bytes, phase: "released", claim: claim) }
        #expect(throws: (any Error).self) { try queue.publicTakeoverArmPublish(bytes, phase: "released", claim: claim) }
        #expect(throws: (any Error).self) { try queue.publicTakeoverArmPublish(bytes, phase: "registry", claim: claim) }
    }
}
#endif

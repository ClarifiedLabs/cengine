#if os(macOS)
import CEngineCore
import Foundation
import Testing
@testable import CEngineRuntime

@Suite @MainActor struct PublicTakeoverArmSchedulingTests {
    enum Fault: Error { case publication, release }
    @Test(arguments: ["success", "publication", "release", "cancel"])
    func joinsFailureWithoutBeginning(_ fault: String) async throws {
        var calls: [String] = []
        var resume: CheckedContinuation<Void, Never>?
        var finished = false
        let task = Task {
            defer { finished = true }
            try await PublicTakeoverArmScheduling.run(arm: {
                calls.append("arm"); return 42
            }, publish: { observation in
                #expect(observation == 42); calls.append("publish")
                if fault == "cancel" { throw CancellationError() }
                if fault != "success" { throw Fault.publication }
            }, release: { observation in
                #expect(observation == 42); calls.append("release")
                await withCheckedContinuation { resume = $0 }
                calls.append("joined")
                if fault == "release" { throw Fault.release }
            })
        }
        if fault != "success" {
            while resume == nil && !finished { await Task.yield() }
            #expect(!finished)
            #expect(calls == ["arm", "publish", "release"])
            resume?.resume()
        }
        let result = await task.result
        if fault == "success" {
            try result.get(); #expect(calls == ["arm", "publish"])
        } else {
            #expect(calls == ["arm", "publish", "release", "joined"])
            switch result {
            case .success: Issue.record("failed publication accepted")
            case .failure(let error):
                if fault == "release" { #expect(error is OriginalConsumerContainmentFailure) }
                if fault == "cancel" { #expect(error is CancellationError) }
            }
        }
    }

    @Test(arguments: ["valid", "first-epoch", "unknown", "null", "wrong-version", "changed-capture", "changed-candidate"])
    func pinnedQueueSelectsOnlyOneRealRunningPublication(_ fault: String) throws {
        typealias Q = ManagedPrepareCompatibilityQueue
        func id() -> String { UUID().uuidString.lowercased() }
        let root = FileManager.default.temporaryDirectory.appending(path: "takeover-arm-" + id())
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let lock = try CanonicalDataStoreLock(root: root.appending(path: "store"))
        let queue = try Q(storeLock: lock), other = try Q(storeLock: lock)
        let request = Q.PublicTakeoverArmCapture(version: "original-takeover-arm.v1", requestID: id(),
            operationUUID: id(), store: id(), epoch: 2, serviceEpoch: id(),
            container: String(repeating: "a", count: 64), containerInstance: id())
        let directory = root.appending(path: "store/managed-prepare-compatibility")
        let file = directory.appending(path: "public-takeover-arm.capture.json")
        var fields = try #require(JSONSerialization.jsonObject(with: ManagedPrepareCompatibilityProtocol.canonicalData(request)) as? [String: Any])
        if fault == "first-epoch" { fields["epoch"] = 1 }
        if fault == "unknown" { fields["signedGrant"] = "not-authority" }
        if fault == "null" { fields["containerInstance"] = NSNull() }
        if fault == "wrong-version" { fields["version"] = "original-takeover-public.v1" }
        try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes]).write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        if ["first-epoch", "unknown", "null", "wrong-version"].contains(fault) {
            #expect(throws: (any Error).self) { try queue.publicTakeoverArmCapture(container: request.container, instance: request.containerInstance) }
            return
        }
        #expect(try queue.publicTakeoverArmCapture(container: String(repeating: "b", count: 64), instance: id()) == nil)
        #expect(throws: (any Error).self) { try queue.publicTakeoverArmCapture(container: request.container, instance: id()) }
        let captured = try queue.publicTakeoverArmCapture(container: request.container, instance: request.containerInstance)
        let claim = try #require(captured)
        #expect(try queue.publicTakeoverArmCapture(container: request.container, instance: request.containerInstance) == nil)
        #expect(throws: (any Error).self) { try queue.publicTakeoverArmPublish(Data("{}".utf8), phase: "armed", claim: claim) }
        #expect(throws: (any Error).self) { try other.publicTakeoverArmPublish(Data("{}".utf8), phase: "candidate", claim: claim) }
        if fault == "changed-capture" {
            try Data("{}".utf8).write(to: directory.appending(path: request.requestID + ".public-takeover-arm.capture.json"))
            #expect(throws: (any Error).self) { try queue.publicTakeoverArmPublish(Data("{}".utf8), phase: "candidate", claim: claim) }
            return
        }
        try queue.publicTakeoverArmPublish(Data("{}".utf8), phase: "candidate", claim: claim)
        if fault == "changed-candidate" {
            try Data("{\"changed\":true}".utf8).write(to: directory.appending(path: request.requestID + ".public-takeover-arm.candidate.json"))
            #expect(throws: (any Error).self) { try queue.publicTakeoverArmPublish(Data("{}".utf8), phase: "armed", claim: claim) }
            return
        }
        try queue.publicTakeoverArmPublish(Data("{}".utf8), phase: "armed", claim: claim)
        #expect(throws: (any Error).self) { try queue.publicTakeoverArmPublish(Data("{}".utf8), phase: "armed", claim: claim) }
    }
}
#endif

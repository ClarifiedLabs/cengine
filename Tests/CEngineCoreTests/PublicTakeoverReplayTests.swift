#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

@Suite @MainActor struct PublicTakeoverReplayTests {
    typealias Q = ManagedPrepareCompatibilityQueue
    func id() -> String { UUID().uuidString.lowercased() }
    @Test func queuePinsCaptureAndOrderedOneShotArtifacts() throws {
        let parent = URL(filePath: "/private/tmp").appending(path: "public-replay-" + id())
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: parent) }
        let lock = try CanonicalDataStoreLock(root: parent.appending(path: "store"))
        let queue = try Q(storeLock: lock), store = id(), epoch = id()
        let capture = Q.PublicTakeoverCapture(version: "original-takeover-public.v1", requestID: id(), store: store, epoch: 2, serviceEpoch: epoch)
        let directory = parent.appending(path: "store/managed-prepare-compatibility")
        let file = directory.appending(path: "public-takeover.capture.json")
        try ManagedPrepareCompatibilityProtocol.canonicalData(capture).write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        #expect(throws: (any Error).self) { try queue.publicTakeoverCapture(store: id(), epoch: 2, serviceEpoch: epoch) }
        let captured = try queue.publicTakeoverCapture(store: store, epoch: 2, serviceEpoch: epoch)
        let claim = try #require(captured)
        #expect(try queue.publicTakeoverCapture(store: store, epoch: 2, serviceEpoch: epoch) == nil)
        #expect(throws: (any Error).self) { try queue.publicTakeoverPublish(Data("{}".utf8), phase: "denied", claim: claim) }
        for phase in ["begun", "denied", "confirmed"] { try queue.publicTakeoverPublish(Data("{}".utf8), phase: phase, claim: claim) }
        #expect(throws: (any Error).self) { try queue.publicTakeoverPublish(Data("{}".utf8), phase: "confirmed", claim: claim) }
    }
}
#endif

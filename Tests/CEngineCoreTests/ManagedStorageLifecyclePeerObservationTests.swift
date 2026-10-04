import CEngineCore
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

@Suite struct ManagedStorageLifecyclePeerObservationTests {
    private typealias Observation = ManagedStorageLifecyclePeerObservation
    private typealias Queue = ManagedPrepareCompatibilityQueue
    private typealias Carrier = ManagedPrepareCompatibilityProtocol

    private func observation(worker: String? = nil, epoch: UInt64? = nil, route: String = "192.168.127.1") throws -> Observation {
        let frame = try StorageLifecycleServiceBootProtocolTests.vectors()[2]
        let old = try #require(frame.ready)
        let ready = StorageLifecycleServiceBootProtocol.Ready(identity: old.identity,
            serviceEpoch: old.serviceEpoch, workerUUID: worker ?? old.workerUUID,
            controllerEpoch: epoch ?? old.controllerEpoch, controllerKey: old.controllerKey,
            revision: old.revision, openRevision: old.openRevision, bootstrapKey: old.bootstrapKey,
            tlsRootDER: old.tlsRootDER, serverDER: old.serverDER, serverSPKI: old.serverSPKI)
        return try .init(binding: frame.binding, ready: ready,
            peer: .init(tlsRootDER: ready.tlsRootDER, serverDER: ready.serverDER,
                serverKey: ready.serverSPKI, dataAddress: route))
    }
    private func fixture(_ body: (URL, CanonicalDataStoreLock, Queue) throws -> Void) throws {
        let parent = FileManager.default.temporaryDirectory.appending(path: "lifecycle-peer-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: parent) }
        let lock = try CanonicalDataStoreLock(root: parent.appending(path: "store"))
        let queue = try Queue(storeLock: lock)
        try body(lock.root.appending(path: Queue.directoryName), lock, queue)
    }

    @Test func publicDTOIsClosedAndPreservesFullActualReady() throws {
        let value = try observation(), bytes = try value.canonicalData()
        #expect(try Observation.decode(bytes) == value)
        let object = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        #expect(Set(object.keys) == ["version", "binding", "ready", "peer"])
        #expect(value.filename == "lifecycle-peer-" + value.ready.workerUUID + "-" + String(value.ready.controllerEpoch) + ".json")
        for location in ["top", "binding", "ready", "identity", "peer"] {
            var bad = object
            if location == "top" { bad["private_key"] = "forbidden" }
            else if location == "identity" {
                var ready = try #require(bad["ready"] as? [String: Any])
                var identity = try #require(ready["identity"] as? [String: Any])
                identity["private_key"] = "forbidden"; ready["identity"] = identity; bad["ready"] = ready
            } else {
                var nested = try #require(bad[location] as? [String: Any])
                nested["private_key"] = "forbidden"; bad[location] = nested
            }
            let encoded = try JSONSerialization.data(withJSONObject: bad, options: [.sortedKeys, .withoutEscapingSlashes])
            #expect(throws: (any Error).self) { try Observation.decode(encoded) }
        }
        #expect(throws: (any Error).self) { try Observation.decode(Data(" ".utf8) + bytes) }
        #expect(throws: (any Error).self) { try Observation.decode(Data(repeating: 32, count: 65537)) }
        let text = String(decoding: bytes, as: UTF8.self)
        #expect(throws: (any Error).self) {
            try Observation.decode(Data(text.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"version\":1").utf8))
        }
        #expect(throws: (any Error).self) {
            try Observation.decode(Data(text.replacingOccurrences(of: "\"version\":1", with: "\"version\":2").utf8))
        }
    }

    @Test func peerMustMatchReadyAndBindingMustBeValid() throws {
        let value = try observation()
        for field in ["root", "certificate", "key", "route"] {
            var peer = value.peer
            switch field {
            case "root": peer.tlsRootDER.append(0)
            case "certificate": peer.serverDER.append(0)
            case "key": peer.serverKey = String(repeating: "ab", count: 32)
            default: peer.dataAddress = "localhost"
            }
            #expect(throws: (any Error).self) { try Observation(binding: value.binding, ready: value.ready, peer: peer) }
        }
        var binding = value.binding; binding.bytes = 0
        #expect(throws: (any Error).self) { try Observation(binding: binding, ready: value.ready, peer: value.peer) }
    }

    @Test func duplicateIsIdempotentAcrossQueueRestartAndConflictNeverOverwrites() throws {
        try fixture { directory, lock, queue in
            let value = try observation(), path = directory.appending(path: value.filename)
            try queue.lifecyclePeerPublish(value)
            var before = stat(); #expect(lstat(path.path, &before) == 0)
            try queue.lifecyclePeerPublish(value)
            let reopened = try Queue(storeLock: lock)
            try reopened.lifecyclePeerPublish(value)
            #expect(throws: (any Error).self) { try reopened.lifecyclePeerPublish(observation(route: "192.168.127.2")) }
            var after = stat(); #expect(lstat(path.path, &after) == 0)
            #expect(before.st_ino == after.st_ino && after.st_nlink == 1 && after.st_mode & 0o7777 == 0o600)
            #expect(try Data(contentsOf: path) == value.canonicalData())
            #expect(throws: (any Error).self) {
                try ManagedPrepareCompatibilityCoordinator(storeLock: lock, profile: Carrier.fullProfile)
            }
        }
    }

    @Test func sameWorkerControllerEpochsAreDistinctImmutableEntries() throws {
        try fixture { directory, lock, queue in
            let first = try observation(epoch: 1), second = try observation(epoch: 2)
            #expect(first.ready.workerUUID == second.ready.workerUUID)
            #expect(first.filename != second.filename)
            try queue.lifecyclePeerPublish(first)
            try queue.lifecyclePeerPublish(second)
            let reopened = try Queue(storeLock: lock)
            for value in [first, second] {
                try reopened.lifecyclePeerPublish(value)
                #expect(throws: (any Error).self) {
                    try reopened.lifecyclePeerPublish(observation(epoch: value.ready.controllerEpoch, route: "192.168.127.2"))
                }
                #expect(try Data(contentsOf: directory.appending(path: value.filename)) == value.canonicalData())
            }
            #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).count == 2)
        }
    }

    @Test func filenameEpochIsCanonicalNonzeroUInt64() throws {
        #expect(throws: (any Error).self) { try observation(epoch: 0) }
        let value = try observation(epoch: UInt64.max)
        #expect(value.filename == "lifecycle-peer-" + value.ready.workerUUID + "-18446744073709551615.json")
    }

    @Test(arguments: ["replace", "modify", "mode", "hardlink", "symlink"])
    func everyRetainedTupleIsRevalidated(fault: String) throws {
        try fixture { directory, _, queue in
            let first = try observation(epoch: 1), second = try observation(epoch: 2)
            try queue.lifecyclePeerPublish(first)
            let path = directory.appending(path: first.filename), saved = path.appendingPathExtension("saved")
            switch fault {
            case "replace":
                try FileManager.default.moveItem(at: path, to: saved)
                try first.canonicalData().write(to: path); #expect(chmod(path.path, 0o600) == 0)
            case "modify":
                let fd = open(path.path, O_WRONLY); #expect(fd >= 0); defer { close(fd) }
                var byte: UInt8 = 32; #expect(pwrite(fd, &byte, 1, 0) == 1)
            case "mode": #expect(chmod(path.path, 0o644) == 0)
            case "hardlink": #expect(link(path.path, saved.path) == 0)
            default:
                try FileManager.default.moveItem(at: path, to: saved)
                #expect(symlink(saved.path, path.path) == 0)
            }
            #expect(throws: (any Error).self) { try queue.lifecyclePeerPublish(second) }
            #expect(!FileManager.default.fileExists(atPath: directory.appending(path: second.filename).path))
        }
    }

    @Test func queueRetains64TuplesAndBoundSurvivesRestart() throws {
        try fixture { directory, lock, queue in
            let first = try observation(epoch: 1)
            try queue.lifecyclePeerPublish(first)
            for epoch in UInt64(2)...64 { try queue.lifecyclePeerPublish(observation(epoch: epoch)) }
            try queue.lifecyclePeerPublish(first)
            let reopened = try Queue(storeLock: lock)
            try reopened.lifecyclePeerPublish(first)
            #expect(throws: (any Error).self) {
                try reopened.lifecyclePeerPublish(observation(epoch: 65))
            }
            #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).count == 64)
            #expect(try Data(contentsOf: directory.appending(path: first.filename)) == first.canonicalData())
        }
    }
}

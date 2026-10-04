#if os(macOS) && DEBUG
import CEngineCore
import Foundation
import Testing
@testable import CEngineRuntime

@Suite(.serialized) @MainActor struct ManagedStorageInitializationTests {
    typealias Base = ManagedStorageLifecycleOwnerTests
    typealias Marker = ManagedStorageInitialization
    @Test(arguments: ["storage-host-initialization.v1", "storage-host-binding.v1"])
    func oldInitializationFormatRefusesWithoutMutation(version: String) throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let marker = try Marker.create(in: disk.root, binding: disk.binding, provenance: String(repeating: "a", count: 64))
        #expect(marker.manifest.version == "storage-host-initialization.v2")
        let url = disk.url.appending(path: "managed-storage-initialization/manifest.json")
        let bytes = try Data(contentsOf: url)
        let current = version.hasPrefix("storage-host-binding") ? "storage-host-binding.v2" : "storage-host-initialization.v2"
        let old = Data(String(decoding: bytes, as: UTF8.self).replacingOccurrences(of: current, with: version).utf8)
        #expect(old != bytes)
        try old.write(to: url)
        let before = try ManagedStorageLifecycleRestartTests().bytes(disk.url)
        #expect(throws: (any Error).self) { try Marker.open(in: disk.root) }
        #expect(throws: ManagedStorageLifecycleOwner.UnsupportedStoreFormat.self) { try ManagedStorageLifecycleOwner.classify(root: disk.root) }
        #expect(try ManagedStorageLifecycleRestartTests().bytes(disk.url) == before)
    }

    @Test func completedClassificationIgnoresHistoricalDiagnosticDevices() async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let base = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        _ = try await ManagedStorageLifecycleResumeOwnerTests().completedStore(disk, base, lock)
        let marker = try Marker.open(in: disk.root)
        let binding = try marker.manifest.binding.value()
        let identity = try StorageLifecycleProtocol.Identity(binding: binding, generation: 1)
        let url = disk.url.appending(path: "managed-storage-owner/manifest.json")
        var fields = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        for name in ["root", "directory", "lease", "backing"] {
            var observed = try #require(fields[name] as? [String: Any])
            observed["device"] = (observed["device"] as! NSNumber).uint64Value ^ 1
            fields[name] = observed
        }
        try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes]).write(to: url)
        let before = try ManagedStorageLifecycleRestartTests().bytes(disk.url)
        #expect(try ManagedStorageLifecycleOwner.classify(root: disk.root) == .existingV2)
        #expect(try Marker.open(in: disk.root).manifest == marker.manifest)
        #expect(try ManagedStorageLifecycleCheckpoint.readManifest(in: disk.root).identity == identity)
        #expect(try ManagedStorageLifecycleRestartTests().bytes(disk.url) == before)
    }

    @Test func preformatMarkerRetainsRandomBindingAndRefusesUnknownPartial() throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let marker = try Marker.create(in: disk.root, binding: disk.binding, provenance: String(repeating: "a", count: 64))
        #expect(try Marker.open(in: disk.root).manifest == marker.manifest)
        #expect(try ManagedStorageLifecycleOwner.classify(root: disk.root) == .initialization)
        let bytes = try marker.evidence(in: disk.root)
        #expect(throws: (any Error).self) { try Marker.create(in: disk.root, binding: disk.binding, provenance: String(repeating: "a", count: 64)) }
        #expect(try marker.evidence(in: disk.root) == bytes)
        let partial = try disk.root.createDirectory(named: "managed-storage-owner")
        try partial.writeExclusiveRegularFile(named: "foreign", data: Data("preserve".utf8))
        #expect(throws: (any Error).self) { try ManagedStorageLifecycleOwner.classify(root: disk.root) }
        #expect(try partial.entryNames() == ["foreign"])
    }
    @Test func mixedRootAndForgedAdmittedCannotSelectFresh() throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let other = try Base.Disk(); defer { other.remove() }
        let marker = try Marker.create(in: disk.root, binding: disk.binding, provenance: String(repeating: "a", count: 64))
        let copied = try other.root.createDirectory(named: Marker.directoryName)
        try copied.writeExclusiveRegularFile(named: "manifest.json", data: ManagedStorageLifecycleCheckpoint.encode(marker.manifest))
        #expect(throws: (any Error).self) { try Marker.open(in: other.root) }
        try marker.retain("admitted.json", true)
        #expect(throws: (any Error).self) { try ManagedStorageLifecycleOwner.classify(root: disk.root) }
    }
    @Test func exactPhasesAreImmutableAndUnknownArtifactsPreserved() throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let marker = try Marker.create(in: disk.root, binding: disk.binding, provenance: String(repeating: "a", count: 64))
        try marker.retain("attempt.json", true)
        let before = try marker.evidence(in: disk.root)
        try marker.retain("attempt.json", true)
        #expect(throws: (any Error).self) { try marker.retain("attempt.json", false) }
        #expect(try marker.evidence(in: disk.root) == before)
        try marker.directory.writeExclusiveRegularFile(named: "commit-candidate", data: Data([1]))
        #expect(throws: (any Error).self) { try Marker.open(in: disk.root) }
        #expect(try marker.directory.entryNames().contains("commit-candidate"))
    }
    @Test(arguments: ["prepared-signature", "completion-digest", "request-recipient", "backing", "provenance", "service",
                      "intent-store", "intent-lease", "old-owner-format", "partial-pair", "commit-candidate"], [false, true])
    func completedClassificationRejectsForgedOrMixedPhysicalPairs(fault: String, admitted: Bool) async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let base = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        _ = try await ManagedStorageLifecycleResumeOwnerTests().completedStore(disk, base, lock)
        if admitted { try ManagedStorageInitialization.open(in: disk.root).retain("admitted.json", true) }
        func replace(_ name: String, _ field: String, _ value: Any) throws {
            let url = disk.url.appending(path: name)
            var object = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
            object[field] = value
            try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]).write(to: url)
        }
        switch fault {
        case "prepared-signature":
            let name = "managed-storage-initialization/prepared.json"
            let url = disk.url.appending(path: name)
            let object = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
            var signed = try #require(object["signedOpen"] as? [String: Any]); signed["signature"] = Data(repeating: 0, count: 64).base64EncodedString()
            try replace(name, "signedOpen", signed)
        case "completion-digest": try replace("managed-storage-initialization/completed.json", "signedOpenSHA256", String(repeating: "f", count: 64))
        case "request-recipient":
            let name = "managed-storage-initialization/request.json"
            let object = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: disk.url.appending(path: name))) as? [String: Any])
            var recipient = try #require(object["recipient"] as? [String: Any]); recipient["incarnation"] = Base.id()
            try replace(name, "recipient", recipient)
        case "backing":
            let name = "managed-storage-owner/manifest.json"
            let object = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: disk.url.appending(path: name))) as? [String: Any])
            var backing = try #require(object["backing"] as? [String: Any]); backing["inode"] = 1
            try replace(name, "backing", backing)
        case "old-owner-format": try replace("managed-storage-owner/manifest.json", "version", "storage-lifecycle.v2")
        case "provenance": try replace("managed-storage-owner/manifest.json", "provenanceReference", String(repeating: "b", count: 64))
        case "service":
            let name = "managed-storage-owner/state.json"
            var state = try ManagedStorageLifecycleCheckpoint.decode(Data(contentsOf: disk.url.appending(path: name)))
            state.currentService = nil // Valid checkpoint, but not the completed resume pair.
            try ManagedStorageLifecycleCheckpoint.encode(state).write(to: disk.url.appending(path: name))
        case "intent-store": try replace("managed-storage/manifest.json", "store", Base.id())
        case "intent-lease":
            let name = "managed-storage/manifest.json"
            let object = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: disk.url.appending(path: name))) as? [String: Any])
            var lease = try #require(object["lease"] as? [String: Any]); lease["inode"] = 1
            try replace(name, "lease", lease)
        case "partial-pair": try FileManager.default.removeItem(at: disk.url.appending(path: "managed-storage/state.json"))
        default: try Data([1]).write(to: disk.url.appending(path: "managed-storage/commit-candidate"))
        }
        let before = try ManagedStorageLifecycleRestartTests().bytes(disk.url)
        #expect(throws: ManagedStorageLifecycleOwner.UnsupportedStoreFormat.self) { try ManagedStorageLifecycleOwner.classify(root: disk.root) }
        #expect(try ManagedStorageLifecycleRestartTests().bytes(disk.url) == before)
    }

    @Test(arguments: [false, true], ["unknown", "observed-worker"])
    func enrollmentExchangeMutationIsCheckedEvenWhenAckIsLost(loseAck: Bool, target: String) async throws {
        let disk = try Base.Disk(); defer { disk.remove() }
        let base = try Base.Peer(disk.binding), lock = try CanonicalDataStoreLock(root: disk.url)
        _ = try await ManagedStorageLifecycleResumeOwnerTests().completedStore(disk, base, lock)
        let marker = try Marker.open(in: disk.root)
        let unknown = disk.url.appending(path: target == "unknown"
            ? "managed-storage-initialization/commit-candidate" : "managed-storage-owner/state.json")
        let changed: Data
        if target == "unknown" {
            changed = Data([8])
        } else {
            // Even a schema-valid known diagnostic field is part of the whole journal.
            var state = try ManagedStorageLifecycleCheckpoint.decode(Data(contentsOf: unknown))
            state.observedWorker = .init(context: try #require(state.currentContext), workerUUID: Base.id())
            state.revision += 1
            changed = try ManagedStorageLifecycleCheckpoint.encode(state)
        }
        // Production enrollAdoption uses this same guard around native ACK IO.
        await #expect(throws: (any Error).self) {
            try await marker.preservingEvidence(in: disk.root) {
                try changed.write(to: unknown)
                if loseAck { throw ManagedStorageLifecycleOwner.Failure.incomplete }
            }
        }
        #expect(try Data(contentsOf: unknown) == changed)
        #expect(try marker.value("admitted.json", as: Bool.self) == nil)
    }

}
#endif

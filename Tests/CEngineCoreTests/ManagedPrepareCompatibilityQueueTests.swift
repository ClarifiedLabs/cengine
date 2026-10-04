import CEngineCore
import Darwin
import Foundation
import Synchronization
import Testing
@testable import CEngineRuntime

/// Real host file descriptors/locks only. No signed activation, VM, or DATA authority.
@Suite struct ManagedPrepareCompatibilityQueueTests {
    private typealias Carrier = ManagedPrepareCompatibilityProtocol
    private typealias Queue = ManagedPrepareCompatibilityQueue
    private typealias Wire = WorkloadStorageProtocol
    private func id() -> String { UUID().uuidString.lowercased() }
    private let key = String(repeating: "ab", count: 32)

    private struct Selection {
        let capture: Carrier.Capture
        let candidate: Carrier.Candidate
        let arm: Carrier.Arm
    }
    private func selection(caseName: String = "first-child-published") -> Selection {
        let request = id(), instance = id(), volume = id(), launch = id(), attachment = id()
        let mounts: [Wire.MountBinding] = [.init(index: 0, volume: volume, destination: "/data", subpath: "", mode: .readWrite, noCopy: false)]
        let slots: [Wire.Slot] = [.init(volume: volume, attachment: attachment, role: .prepare, mode: .readWrite),
                                .init(volume: volume, attachment: id(), role: .runtime, mode: .readWrite)].sorted { $0.attachment < $1.attachment }
        let credentials: [Carrier.Credential] = [.init(attachment: attachment, key: key, certificateSHA256: key)]
        let binding = Wire.BootBinding(shimLaunchUUID: launch, guestBootNonce: id())
        let scope = Wire.Scope(intent: id(), store: id(), serviceEpoch: id(), controllerEpoch: 1, controllerKey: key,
            container: key, containerInstance: instance, launch: launch, prepare: id(), specificationDigest: key)
        return Selection(capture: .init(version: 1, requestID: request, container: key, containerInstance: instance,
            specificationDigest: key, mounts: mounts), candidate: .init(version: 1, profile: Carrier.profile, requestID: request,
            binding: binding, scope: scope, mounts: mounts, slots: slots, credentials: credentials),
            arm: .init(version: 1, profile: Carrier.profile, requestID: request, caseName: caseName,
                targetAttachment: attachment, binding: binding, scope: scope, mounts: mounts, slots: slots, credentials: credentials))
    }
    private func fixture(_ body: (URL, CanonicalDataStoreLock, Queue) throws -> Void) throws {
        let parent = FileManager.default.temporaryDirectory.appending(path: "prepare-queue-" + id())
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: parent) }
        let lock = try CanonicalDataStoreLock(root: parent.appending(path: "store"))
        let queue = try Queue(storeLock: lock)
        try body(lock.root.appending(path: Queue.directoryName), lock, queue)
    }
    private func put(_ bytes: Data, at path: URL) throws {
        try bytes.write(to: path)
        #expect(chmod(path.path, 0o600) == 0)
    }
    private func claim(_ selection: Selection, directory: URL, queue: Queue) throws -> Queue.Claim {
        try put(Carrier.canonicalData(selection.capture), at: directory.appending(path: "capture.json"))
        return try #require(try queue.capture(container: selection.capture.container, instance: selection.capture.containerInstance,
            digest: selection.capture.specificationDigest, mounts: selection.capture.mounts))
    }
    private func arm(_ selection: Selection, claim: Queue.Claim, directory: URL, queue: Queue) throws {
        try queue.candidate(selection.candidate, claim: claim)
        try put(Carrier.armData(selection.arm), at: directory.appending(path: selection.arm.requestID + ".arm.json"))
        #expect(try queue.arm(claim, candidate: selection.candidate) == selection.arm)
    }
    private func observation(_ arm: Carrier.Arm) throws -> Carrier.Observation {
        func identity(_ inode: UInt64, _ kind: UInt32) -> Carrier.ObjectIdentity {
            .init(inode: inode, generation: 1, fileType: kind, handle: String(format: "%02x00000001000000", inode))
        }
        return .init(version: 1, profile: Carrier.profile, requestID: arm.requestID, armDigest: try Carrier.digest(arm),
            stage: "first-child-published", count: 1, targetAttachment: arm.targetAttachment, copyIntent: id(),
            filesystemUUID: String(repeating: "ab", count: 16), manifestDigest: key, manifestSize: 512, sourceAtimes: .init(root: 0, a: 1, z: UInt64(Int64.max)),
            root: identity(2, 16384), transaction: identity(3, 16384), published: identity(4, 32768), staged: identity(5, 32768))
    }

    @Test func signedActivationCannotBeBypassedByQueueConstruction() throws {
        try fixture { _, lock, _ in
            #expect(throws: (any Error).self) { try ManagedPrepareCompatibilityCoordinator(storeLock: lock, profile: Carrier.profile) }
            #expect(throws: (any Error).self) { try ManagedPrepareCompatibilityCoordinator(storeLock: lock, profile: "other") }
        }
    }
    @Test func captureSelectsExactExistingInstanceWithoutClaimingUnrelatedStart() throws {
        try fixture { directory, _, queue in
            let value = selection(), path = directory.appending(path: "capture.json")
            let bytes = try Carrier.canonicalData(value.capture)
            try put(bytes, at: path)
            #expect(try queue.capture(container: String(repeating: "cd", count: 32), instance: id(), digest: key, mounts: []) == nil)
            #expect(try Data(contentsOf: path) == bytes)
            for mismatch in ["instance", "digest", "mounts"] {
                #expect(throws: (any Error).self) {
                    try queue.capture(container: value.capture.container, instance: mismatch == "instance" ? id() : value.capture.containerInstance,
                        digest: mismatch == "digest" ? String(repeating: "cd", count: 32) : key, mounts: mismatch == "mounts" ? [] : value.capture.mounts)
                }
            }
            #expect(try Data(contentsOf: path) == bytes)
            _ = try claim(value, directory: directory, queue: queue)
            #expect(!FileManager.default.fileExists(atPath: path.path))
        }
    }
    @Test(arguments: ["normal", "first-child-published"])
    func oneShotReceiptsAreCanonicalPinnedAndNeverReplaced(caseName: String) throws {
        try fixture { directory, _, queue in
            let value = selection(caseName: caseName), claimed = try claim(value, directory: directory, queue: queue)
            let event = try observation(value.arm)
            #expect(throws: (any Error).self) { try queue.armed(value.arm, claim: claimed) }
            #expect(throws: (any Error).self) { try queue.arm(claimed, candidate: value.candidate) }
            try queue.candidate(value.candidate, claim: claimed)
            #expect(try queue.arm(claimed, candidate: value.candidate) == nil)
            let candidatePath = directory.appending(path: value.arm.requestID + ".candidate.json")
            let candidateBytes = try Data(contentsOf: candidatePath)
            #expect(candidateBytes == (try Carrier.canonicalData(value.candidate)))
            #expect(throws: (any Error).self) { try queue.candidate(value.candidate, claim: claimed) }
            #expect(try Data(contentsOf: candidatePath) == candidateBytes)
            try put(Carrier.armData(value.arm), at: directory.appending(path: value.arm.requestID + ".arm.json"))
            #expect(try queue.arm(claimed, candidate: value.candidate) == value.arm)
            #expect(throws: (any Error).self) { try queue.arm(claimed, candidate: value.candidate) }
            #expect(throws: (any Error).self) { try queue.checkpoint(event, arm: value.arm, claim: claimed) }
            var wrong = value.arm; wrong.requestID = id()
            #expect(throws: (any Error).self) { try queue.armed(wrong, claim: claimed) }
            try queue.armed(value.arm, claim: claimed)
            #expect(throws: (any Error).self) { try queue.armed(value.arm, claim: claimed) }
            try queue.checkpoint(event, arm: value.arm, claim: claimed)
            let path = directory.appending(path: value.arm.requestID + ".checkpoint.json")
            let bytes = try Data(contentsOf: path)
            #expect(bytes == (try Carrier.canonicalData(event)))
            #expect(throws: (any Error).self) { try queue.checkpoint(event, arm: value.arm, claim: claimed) }
            #expect(try Data(contentsOf: path) == bytes)
            var info = stat(); #expect(lstat(path.path, &info) == 0)
            #expect(info.st_mode & 0o7777 == 0o600 && info.st_nlink == 1)
        }
    }
    @Test func restartNeverReadoptsOldCaptureArmOrClaim() throws {
        try fixture { directory, lock, queue in
            let value = selection(), claimed = try claim(value, directory: directory, queue: queue)
            try arm(value, claim: claimed, directory: directory, queue: queue)
            let reopened = try Queue(storeLock: lock)
            #expect(try reopened.capture(container: key, instance: value.capture.containerInstance, digest: key, mounts: value.capture.mounts) == nil)
            #expect(throws: (any Error).self) { try reopened.armed(value.arm, claim: claimed) }
            let capturePath = directory.appending(path: value.capture.requestID + ".capture.json")
            let bytes = try Data(contentsOf: capturePath)
            try put(bytes, at: directory.appending(path: "capture.json"))
            #expect(throws: (any Error).self) {
                try reopened.capture(container: key, instance: value.capture.containerInstance, digest: key, mounts: value.capture.mounts)
            }
            #expect(try Data(contentsOf: capturePath) == bytes)
            #expect(try Data(contentsOf: directory.appending(path: value.arm.requestID + ".arm.claimed.json")) == Carrier.armData(value.arm))
        }
    }
    @Test func sixteenthCaptureSurvivesRestartAndSeventeenthFailsClosed() throws {
        try fixture { directory, lock, queue in
            for _ in 0..<16 { _ = try claim(selection(), directory: directory, queue: queue) }
            let reopened = try Queue(storeLock: lock), value = selection()
            #expect(throws: (any Error).self) { try claim(value, directory: directory, queue: reopened) }
            let names = try FileManager.default.contentsOfDirectory(atPath: directory.path)
            #expect(names.filter { $0.hasSuffix(".capture.json") }.count == 16)
            #expect(try Data(contentsOf: directory.appending(path: "capture.json")) == Carrier.canonicalData(value.capture))
        }
    }
    @Test(arguments: ["replace", "modify", "mode", "hardlink", "symlink"])
    func retainedCaptureIsRechecked(fault: String) throws {
        try fixture { directory, _, queue in
            let value = selection(), claimed = try claim(value, directory: directory, queue: queue)
            let path = directory.appending(path: value.capture.requestID + ".capture.json")
            try damage(path, fault: fault)
            #expect(throws: (any Error).self) { try queue.candidate(value.candidate, claim: claimed) }
            #expect(!FileManager.default.fileExists(atPath: directory.appending(path: value.capture.requestID + ".candidate.json").path))
        }
    }
    @Test(arguments: ["candidate", "arm.claimed", "armed"])
    func everyPublishedStageRemainsFDPinned(stage: String) throws {
        try fixture { directory, _, queue in
            let value = selection(), claimed = try claim(value, directory: directory, queue: queue)
            if stage == "candidate" { try queue.candidate(value.candidate, claim: claimed) }
            else { try arm(value, claim: claimed, directory: directory, queue: queue) }
            if stage == "armed" { try queue.armed(value.arm, claim: claimed) }
            try damage(directory.appending(path: value.arm.requestID + "." + stage + ".json"), fault: "replace")
            if stage == "candidate" {
                try put(Carrier.armData(value.arm), at: directory.appending(path: value.arm.requestID + ".arm.json"))
                #expect(throws: (any Error).self) { try queue.arm(claimed, candidate: value.candidate) }
            } else if stage == "arm.claimed" {
                #expect(throws: (any Error).self) { try queue.armed(value.arm, claim: claimed) }
            } else {
                #expect(throws: (any Error).self) { try queue.checkpoint(observation(value.arm), arm: value.arm, claim: claimed) }
            }
        }
    }
    private func damage(_ path: URL, fault: String) throws {
        let saved = path.appendingPathExtension("saved"), bytes = try Data(contentsOf: path)
        switch fault {
        case "modify": try put(Data("{}".utf8), at: path)
        case "mode": #expect(chmod(path.path, 0o644) == 0)
        case "hardlink": #expect(link(path.path, saved.path) == 0)
        case "symlink":
            try FileManager.default.moveItem(at: path, to: saved)
            #expect(symlink(saved.path, path.path) == 0)
        default:
            try FileManager.default.moveItem(at: path, to: saved)
            try put(bytes, at: path)
        }
    }
    @Test(arguments: ["queue", "root", "lock"])
    func directoryAndLockReplacementNeverRedirectEvidence(target: String) throws {
        try fixture { directory, lock, queue in
            let value = selection(), claimed = try claim(value, directory: directory, queue: queue)
            let path = target == "queue" ? directory : target == "root" ? lock.root : lock.root.appending(path: ".daemon.lock")
            try FileManager.default.moveItem(at: path, to: path.appendingPathExtension("moved"))
            if target == "lock" { try put(Data(), at: path) }
            else { try FileManager.default.createDirectory(at: path, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]) }
            #expect(throws: (any Error).self) { try queue.candidate(value.candidate, claim: claimed) }
            #expect(!FileManager.default.fileExists(atPath: directory.appending(path: value.arm.requestID + ".candidate.json").path))
        }
    }
    @Test(arguments: ["symlink", "hardlink", "mode", "oversize", "fifo"])
    func submittedCaptureRejectsUnsafeEntriesWithoutFollowingOrBlocking(fault: String) throws {
        try fixture { directory, _, queue in
            let value = selection(), path = directory.appending(path: "capture.json")
            if fault == "fifo" { #expect(mkfifo(path.path, 0o600) == 0) }
            else {
                try put(Carrier.canonicalData(value.capture), at: path)
                if fault == "oversize" { try put(Data(repeating: 32, count: 65537), at: path) }
                else { try damage(path, fault: fault) }
            }
            #expect(throws: (any Error).self) {
                try queue.capture(container: key, instance: value.capture.containerInstance, digest: key, mounts: value.capture.mounts)
            }
        }
    }
    @Test func concurrentCapturesCannotClaimTwice() throws {
        try fixture { directory, _, queue in
            let value = selection()
            try put(Carrier.canonicalData(value.capture), at: directory.appending(path: "capture.json"))
            let counts = Mutex((claimed: 0, missing: 0)), group = DispatchGroup()
            defer {
                // A failed timing assertion must not remove files still used by
                // a contender. Joining is cleanup, not a second chance to pass.
                precondition(group.wait(timeout: .now() + 15) == .success, "capture workers did not join")
            }
            for _ in 0..<2 {
                group.enter()
                // Independent of the shared pool whose threads other fixtures
                // can occupy while this synchronous test waits for its result.
                Thread.detachNewThread {
                    defer { group.leave() }
                    do {
                        let result = try queue.capture(container: value.capture.container, instance: value.capture.containerInstance,
                            digest: value.capture.specificationDigest, mounts: value.capture.mounts)
                        counts.withLock { if result == nil { $0.missing += 1 } else { $0.claimed += 1 } }
                    } catch { Issue.record(error) }
                }
            }
            #expect(group.wait(timeout: .now() + 5) == .success)
            #expect(counts.withLock { $0.claimed == 1 && $0.missing == 1 })
        }
    }
}

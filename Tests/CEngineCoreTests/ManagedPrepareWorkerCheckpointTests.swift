#if os(macOS)
import CEngineCore
import Foundation
import Testing
@testable import CEngineRuntime

// Serialized: every test loads the same full-vectors fixture and drives the
// recursive frame validators; concurrent in-process execution overflows the
// test runner's per-test thread stack (each test passes in isolation).
@Suite(.serialized) struct ManagedPrepareWorkerCheckpointTests {
    typealias C = ManagedPrepareCompatibilityProtocol
    typealias Checkpoint = ManagedPrepareWorkerCheckpointProtocol
    typealias B = StorageLifecycleServiceBootProtocol

    private struct Vector: Decodable {
        var name: String
        var arm: C.Arm
        var observationCanonical: String
        var storageObservationCanonical: String?
    }
    private func vectors() throws -> [Vector] {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode([Vector].self, from: Data(contentsOf: root.appending(path: "Guest/internal/preparecompat/testdata/full-vectors.json")))
    }

    /// The real full-profile claim for one of the seven cuts, straight from its
    /// generated full-vectors row: physical Observation (NORMAL/A7),
    /// EarlyObservation (A1/A2/A3), or storage-owned StorageObservation (A6/A8).
    /// No synthetic physical fixture is ever produced for the early cuts.
    private func claim(_ stage: String) throws -> Checkpoint.WorkerCheckpointExit {
        let row = try #require(try vectors().first { $0.name == stage })
        switch stage {
        case "normal", "first-child-published":
            let observation = try C.decode(C.Observation.self, from: Data(row.observationCanonical.utf8))
            return Checkpoint.WorkerCheckpointExit(arm: row.arm, checkpoint: observation, workerUUID: row.arm.requestID)
        case "before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame":
            let observation = try C.decode(C.EarlyObservation.self, from: Data(row.observationCanonical.utf8))
            return Checkpoint.WorkerCheckpointExit(arm: row.arm, earlyCheckpoint: observation, workerUUID: row.arm.requestID)
        case "transaction-published-bind-reply-lost", "drain-durable-reply-lost":
            let observation = try C.decode(C.StorageObservation.self, from: Data(row.storageObservationCanonical!.utf8))
            return Checkpoint.WorkerCheckpointExit(arm: row.arm, storageCheckpoint: observation, workerUUID: observation.workerUUID)
        default: Issue.record("no fixture kind for \(stage)"); return Checkpoint.WorkerCheckpointExit(arm: row.arm, workerUUID: "")
        }
    }

    private func wait(_ exit: Checkpoint.WorkerCheckpointExit) -> Checkpoint.WorkerCheckpointWait {
        .init(arm: exit.arm, checkpoint: exit.checkpoint, earlyCheckpoint: exit.earlyCheckpoint,
              storageCheckpoint: exit.storageCheckpoint, workerUUID: exit.workerUUID,
              workerPID: 42, exitCode: 74, reaped: true)
    }

    private let cuts = ["normal", "before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame",
                        "first-child-published", "transaction-published-bind-reply-lost", "drain-durable-reply-lost"]

    @MainActor @Test(.timeLimit(.minutes(1)))
    func checkpointClaimRendezvousWaitsForLateParentAndExpiresWithoutProof() async throws {
        let expected = try claim("drain-durable-reply-lost")
        var polls = 0
        // Exercise late publication using the production budget: the full suite
        // can occupy MainActor for seconds between these three polls. Deadline
        // expiry is tested separately below, not by racing that shared executor.
        let actual = try await RawManagedStorageBackend.pollCheckpointWorkerExit(
            interval: .milliseconds(1), allowed: { true }, claim: {
                polls += 1
                return polls == 3 ? expected : nil
            })
        #expect(actual == expected)
        #expect(polls == 3)
        polls = 0
        let expired = try await RawManagedStorageBackend.pollCheckpointWorkerExit(
            budget: .zero, allowed: { true }, claim: { polls += 1; return expected })
        #expect(expired == nil)
        #expect(polls == 0)
        let disallowed = try await RawManagedStorageBackend.pollCheckpointWorkerExit(
            allowed: { false }, claim: { polls += 1; return expected })
        #expect(disallowed == nil)
        #expect(polls == 0)
        let absent = try await RawManagedStorageBackend.pollCheckpointWorkerExit(
            budget: .milliseconds(2), interval: .milliseconds(1), allowed: { true }, claim: { nil })
        #expect(absent == nil)
    }

    @Test func allSevenCutFixtureClaimsValidateAndRoundtrip() throws {
        for stage in cuts {
            let exit = try claim(stage)
            #expect(Checkpoint.checkpointExitCut(stage))
            try Checkpoint.validate(exit)
            let bytes = try C.canonicalData(exit)
            #expect(try Checkpoint.decodeWorkerCheckpointExit(from: bytes) == exit)
        }
        // A4/A5 admission cuts, the VM cases and IO cuts stay on their own paths.
        for stage in ["full-frame-before-admit", "admitted-queued", "vm-two-volume-drain-reply-gap",
                      "vm-private-bound", "vm-root-synced-before-cleanup", "vm-cleaning-transaction-removed"] {
            var exit = try claim("normal")
            exit.arm.caseName = stage // the stage gate rejects before any structural repair
            #expect(!Checkpoint.checkpointExitCut(stage))
            #expect(throws: (any Error).self) { try Checkpoint.validate(exit) }
        }
    }

    @Test func unionExactlyOneAndCarrierMatchesCut() throws {
        let physical = try claim("normal")
        let early = try claim("data-partial-frame")
        let storage = try claim("transaction-published-bind-reply-lost")
        // Zero or two carriers never validate, whatever the stage.
        var zero = physical
        zero.checkpoint = nil
        #expect(throws: (any Error).self) { try Checkpoint.validate(zero) }
        var dual = physical
        dual.earlyCheckpoint = early.earlyCheckpoint
        #expect(throws: (any Error).self) { try Checkpoint.validate(dual) }
        // The carrier kind must match the arm's case.
        var wrongKind = physical
        wrongKind.checkpoint = nil
        wrongKind.storageCheckpoint = storage.storageCheckpoint
        #expect(throws: (any Error).self) { try Checkpoint.validate(wrongKind) }
        var earlyWithPhysical = try claim("guest-accepted-before-prepare")
        earlyWithPhysical.checkpoint = physical.checkpoint
        #expect(throws: (any Error).self) { try Checkpoint.validate(earlyWithPhysical) }
    }

    @Test func physicalCheckpointBindsActualGuestObservationToArm() throws {
        let exit = try claim("normal")
        try Checkpoint.validate(exit)
        var bad = exit
        bad.checkpoint!.armDigest = String(repeating: "f", count: 64)
        #expect(throws: (any Error).self) { try Checkpoint.validate(bad) }
        bad = exit
        bad.checkpoint!.requestID = String(repeating: "a", count: 8) + bad.checkpoint!.requestID.dropFirst(8)
        #expect(throws: (any Error).self) { try Checkpoint.validate(bad) }
        bad = exit
        bad.checkpoint!.stage = "vm-root-synced-before-cleanup"
        #expect(throws: (any Error).self) { try Checkpoint.validate(bad) }
        bad = exit
        bad.checkpoint!.targetAttachment = String(repeating: "b", count: 8) + bad.checkpoint!.targetAttachment.dropFirst(8)
        #expect(throws: (any Error).self) { try Checkpoint.validate(bad) }
        bad = exit
        bad.checkpoint!.count = 2
        #expect(throws: (any Error).self) { try Checkpoint.validate(bad) }
        bad = exit
        bad.checkpoint!.root.fileType = 32768
        #expect(throws: (any Error).self) { try Checkpoint.validate(bad) }
        bad = exit
        bad.arm.targetAttachment = String(repeating: "c", count: 8) + bad.arm.targetAttachment.dropFirst(8)
        #expect(throws: (any Error).self) { try Checkpoint.validate(bad) }
    }

    @Test func earlyCheckpointBindsActualEarlyObservationToArm() throws {
        for stage in ["before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame"] {
            let exit = try claim(stage)
            #expect(exit.checkpoint == nil && exit.earlyCheckpoint != nil)
            try Checkpoint.validate(exit)
            var bad = exit
            bad.earlyCheckpoint!.stage = "normal"
            #expect(throws: (any Error).self) { try Checkpoint.validate(bad) }
            bad = exit
            bad.earlyCheckpoint!.armDigest = String(repeating: "f", count: 64)
            #expect(throws: (any Error).self) { try Checkpoint.validate(bad) }
            bad = exit
            bad.earlyCheckpoint!.requestSequence = 0
            #expect(throws: (any Error).self) { try Checkpoint.validate(bad) }
            bad = exit
            bad.earlyCheckpoint!.dataBytesWritten += 1
            #expect(throws: (any Error).self) { try Checkpoint.validate(bad) }
        }
    }

    @Test func storageCheckpointBindsActualBoundDrainObservationToArm() throws {
        for stage in ["transaction-published-bind-reply-lost", "drain-durable-reply-lost"] {
            let exit = try claim(stage)
            #expect(exit.storageCheckpoint != nil)
            try Checkpoint.validate(exit)
            var bad = exit
            bad.storageCheckpoint!.stage = "admitted-queued"
            #expect(throws: (any Error).self) { try Checkpoint.validate(bad) }
            bad = exit
            bad.storageCheckpoint!.armDigest = String(repeating: "f", count: 64)
            #expect(throws: (any Error).self) { try Checkpoint.validate(bad) }
            bad = exit
            bad.storageCheckpoint!.count = 2
            #expect(throws: (any Error).self) { try Checkpoint.validate(bad) }
            bad = exit
            bad.storageCheckpoint!.admission = .init(requestSequence: 1, admitted: true, releaseToken: String(repeating: "e", count: 64))
            #expect(throws: (any Error).self) { try Checkpoint.validate(bad) }
            bad = exit
            bad.workerUUID = UUID().uuidString.lowercased()
            #expect(throws: (any Error).self) { try Checkpoint.validate(bad) }
        }
    }

    @Test func waitEchoesExactClaimAndClosedCodec() throws {
        for stage in ["normal", "data-partial-frame", "drain-durable-reply-lost"] {
            let exit = try claim(stage)
            let value = wait(exit)
            try Checkpoint.validate(value)
            try Checkpoint.validate(value, for: exit)
            let bytes = try C.canonicalData(value)
            #expect(try Checkpoint.decodeWorkerCheckpointWait(from: bytes) == value)
            var bad = value
            bad.workerPID = 0
            #expect(throws: (any Error).self) { try Checkpoint.validate(bad) }
            bad = value; bad.workerPID = 1
            #expect(throws: (any Error).self) { try Checkpoint.validate(bad) }
            bad = value; bad.workerPID = UInt32(Int32.max) + 1 // 1 << 31
            #expect(throws: (any Error).self) { try Checkpoint.validate(bad) }
            bad = value; bad.workerPID = UInt32(Int32.max)
            try Checkpoint.validate(bad) // Int32.max is the inclusive bound
            bad = value; bad.exitCode = 0
            #expect(throws: (any Error).self) { try Checkpoint.validate(bad) }
            bad = value; bad.reaped = false
            #expect(throws: (any Error).self) { try Checkpoint.validate(bad) }
            // Always-mutating UUID tweak (dropLast()+"e" is a no-op when the
            // value already ends in "e", which would echo the exact claim).
            bad = value; bad.workerUUID = String(value.workerUUID.dropLast()) + (value.workerUUID.hasSuffix("e") ? "f" : "e")
            #expect(throws: (any Error).self) { try Checkpoint.validate(value, for: bad.claim) }
            bad = value; bad.arm.caseName = "admitted-queued"
            #expect(throws: (any Error).self) { try Checkpoint.validate(bad) }
            bad = value; bad.checkpoint = nil; bad.earlyCheckpoint = try claim("before-prepare-send").earlyCheckpoint
            #expect(throws: (any Error).self) { try Checkpoint.validate(value, for: bad.claim) }
            // The other storage cut's observation, never this claim's retained
            // one: for the drain-durable stage the same-row observation would
            // be the exact retained publication (bad == value), which the
            // top-of-loop validate(value) proves must succeed.
            bad = value; bad.storageCheckpoint = try claim("transaction-published-bind-reply-lost").storageCheckpoint
            #expect(throws: (any Error).self) { try Checkpoint.validate(bad) }
            bad = value; bad.workerUUID = "not-a-uuid"
            #expect(throws: (any Error).self) { try Checkpoint.validate(bad) }
            // Duplicate, unknown, null, fractional and missing JSON keys stay closed.
            let text = String(decoding: bytes, as: UTF8.self)
            for replacement in ["\"workerPID\":42,\"workerPID\":42", "\"workerPID\":42.0", "\"workerPID\":-42",
                                "\"workerPID\":18446744073709551616", "\"reaped\":true,\"extra\":1",
                                "\"reaped\":null", "\"reaped\":true,\"reaped\":true"] {
                let changed = text.replacingOccurrences(of: "\"workerPID\":42", with: replacement)
                #expect(changed != text)
                #expect(throws: (any Error).self) { try Checkpoint.decodeWorkerCheckpointWait(from: Data(changed.utf8)) }
            }
            for removal in ["\"exitCode\":74,", "\"reaped\":true,", "\"workerUUID\":\""] {
                let changed = text.replacingOccurrences(of: removal, with: "")
                #expect(changed != text)
                #expect(throws: (any Error).self) { try Checkpoint.decodeWorkerCheckpointWait(from: Data(changed.utf8)) }
            }
            for suffix in [" ", "{}"] {
                #expect(throws: (any Error).self) { try Checkpoint.decodeWorkerCheckpointWait(from: bytes + Data(suffix.utf8)) }
            }
            // The 64K maximum frame bound is enforced before parsing.
            #expect(throws: (any Error).self) { try Checkpoint.decodeWorkerCheckpointWait(from: bytes + Data(repeating: 32, count: 65_536)) }
            #expect(throws: (any Error).self) { try Checkpoint.decodeWorkerCheckpointExit(from: try C.canonicalData(exit) + Data(repeating: 32, count: 65_536)) }
        }
    }

    @Test func sameClaimRequiresCanonicalEquality() throws {
        let exit = try claim("normal")
        #expect(Checkpoint.sameClaim(exit, exit))
        var changed = exit
        changed.checkpoint!.manifestSize += 1
        #expect(!Checkpoint.sameClaim(exit, changed))
        changed = exit
        changed.workerUUID = UUID().uuidString.lowercased()
        #expect(!Checkpoint.sameClaim(exit, changed))
        #expect(Checkpoint.sameClaim(wait(exit).claim, exit))
    }

    @Test func bootCommandCarriesClaimAndReplyCarriesOnlyWait() throws {
        let exit = try claim("normal")
        let value = wait(exit)
        let binding = DiskInitializationProtocol.Binding(shimLaunchUUID: exit.arm.binding.shimLaunchUUID, guestBootNonce: exit.arm.binding.guestBootNonce,
                                ext4UUID: exit.arm.scope.store, bytes: 16 << 20)
        let scope = StorageServiceTypes.Scope(serviceEpoch: exit.arm.scope.serviceEpoch, workerUUID: exit.workerUUID)
        let command = B.Frame(operation: .command, binding: binding, sequence: 1, serviceEpoch: scope.serviceEpoch,
                                command: .prepareCompatibilityCheckpointExit, workerUUID: scope.workerUUID, prepareCompatibilityCheckpointExit: exit)
        #expect(try B.decode(Data(B.encode(command).dropFirst(4))) == command)
        let reply = B.Frame(operation: .reply, binding: binding, sequence: 1, serviceEpoch: scope.serviceEpoch, workerUUID: scope.workerUUID, prepareCompatibilityCheckpointWait: value)
        #expect(try B.decode(Data(B.encode(reply).dropFirst(4))) == reply)
        // The old A4/A5 strict release route is unchanged.
        let old = try WorkerExitVector.load()
        #expect(try B.decode(Data(B.encode(old.command).dropFirst(4))) == old.command)
        #expect(try B.decode(Data(B.encode(old.reply).dropFirst(4))) == old.reply)
    }

    @Test func bootRefusesMixedCheckpointFieldsOnOtherCommandsAndReplies() throws {
        let exit = try claim("normal")
        let value = wait(exit)
        let old = try WorkerExitVector.load()
        let binding = DiskInitializationProtocol.Binding(shimLaunchUUID: exit.arm.binding.shimLaunchUUID, guestBootNonce: exit.arm.binding.guestBootNonce,
                                ext4UUID: exit.arm.scope.store, bytes: 16 << 20)
        let scope = StorageServiceTypes.Scope(serviceEpoch: exit.arm.scope.serviceEpoch, workerUUID: exit.workerUUID)
        let command = B.Frame(operation: .command, binding: binding, sequence: 1, serviceEpoch: scope.serviceEpoch,
                                command: .prepareCompatibilityCheckpointExit, workerUUID: scope.workerUUID, prepareCompatibilityCheckpointExit: exit)
        var commands: [B.Frame] = []
        var bad = command; bad.command = .query; commands.append(bad)
        bad = command; bad.command = .consumerObservationArm; commands.append(bad)
        bad = command; bad.command = .consumerObservationQuery; commands.append(bad)
        bad = command; bad.command = .prepareCompatibilityWorkerExit; commands.append(bad)
        bad = command; bad.prepareCompatibilityWorkerExit = old.exit; commands.append(bad)
        bad = command; bad.prepareCompatibilityArm = old.arm; commands.append(bad)
        bad = command; bad.workerUUID = UUID().uuidString.lowercased(); commands.append(bad)
        bad = command; bad.serviceEpoch = UUID().uuidString.lowercased(); commands.append(bad)
        bad = command; bad.prepareCompatibilityCheckpointExit!.workerUUID = UUID().uuidString.lowercased(); commands.append(bad)
        for item in commands { #expect(throws: (any Error).self) { try B.encode(item) } }
        let reply = B.Frame(operation: .reply, binding: binding, sequence: 1, serviceEpoch: scope.serviceEpoch, workerUUID: scope.workerUUID, prepareCompatibilityCheckpointWait: value)
        var replies: [B.Frame] = []
        var rbad = reply; rbad.prepareCompatibilityStatus = old.status; replies.append(rbad)
        rbad = reply; rbad.prepareCompatibilityWorkerWait = old.wait; replies.append(rbad)
        rbad = reply; rbad.code = .command; replies.append(rbad)
        rbad = reply; rbad.ready = .init(identity: try .init(store: exit.arm.scope.store, generation: 1, binding: String(repeating: "a", count: 64)), serviceEpoch: exit.arm.scope.serviceEpoch,
                                         workerUUID: exit.workerUUID, controllerEpoch: 1, controllerKey: String(repeating: "a", count: 64),
                                         revision: 1, openRevision: 1, bootstrapKey: String(repeating: "a", count: 64), tlsRootDER: Data([1]), serverDER: Data([1]),
                                         serverSPKI: String(repeating: "a", count: 64)); replies.append(rbad)
        // The consumer reply path must also refuse the new wait field.
        let runtime = ConsumerObservationProtocol.RuntimeBinding(store: "s", volume: "v", attachment: "a", container: "c",
                                                                 launch: "l", key: "k", mode: "read-only")
        let arm = ConsumerObservationProtocol.Arm(requestID: "r", armDigest: "d", operationUUID: "o", caseName: .sameE,
                                                  originalBootBinding: .init(shimLaunchUUID: "b", guestBootNonce: "n"),
                                                  original: .init(epoch: "e", binding: runtime),
                                                  originalLeafSHA256: "x",
                                                  workerScope: .init(storeUUID: "s", serviceEpoch: "e", workerUUID: "w"))
        rbad = reply; rbad.consumerObservationStatus = .init(query: arm, state: .armed, selectedCount: 0); replies.append(rbad)
        for item in replies { #expect(throws: (any Error).self) { try B.encode(item) } }
    }
}
#endif

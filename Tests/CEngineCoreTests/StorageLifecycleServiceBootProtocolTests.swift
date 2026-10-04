import CEngineCore
import CryptoKit
import Foundation
import Testing

@Suite("Dormant lifecycle service boot closed wire")
struct StorageLifecycleServiceBootProtocolTests {
    typealias W = StorageLifecycleServiceBootProtocol
    nonisolated static func vectors() throws -> [W.Frame] {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Fixtures/storage-bootstrap/lifecycle-service-boot-v2.json")
        let bodies = try JSONDecoder().decode([String].self, from: Data(contentsOf: url))
        return try bodies.map { try W.decode(Data($0.utf8)) }
    }
    @Test func sharedGoCanonicalFramesAndUInt64() throws {
        let frames = try Self.vectors()
        #expect(frames.count == 18)
        for frame in frames { #expect(try W.decode(W.encode(frame).dropFirst(4)) == frame) }
        #expect(frames[1].configuration?.signed.grant.serial == UInt64.max)
        #expect(frames[1].configuration?.signed.grant.identity.generation == 9_007_199_254_740_993)
        #expect(frames[3].sequence == UInt64.max)
        let cfg = try #require(frames[1].configuration)
        #expect(try cfg.signed.isValidSignature(using: .init(publicData: cfg.rootPublicKey)))
        let open = try #require(frames[5].configuration)
        let signedReopen = try #require(open.reopen)
        #expect(signedReopen.isValidSignature(using: try .init(publicData: open.rootPublicKey)))
        let request = signedReopen.request
        #expect(open.action == .open && request.predecessor.grant == cfg.signed.grant)
        #expect(request.operationID == "99999999-9999-4999-8999-999999999999")
        #expect(request.operationID != request.predecessor.grant.id)
        #expect(request.predecessor.openRevision == frames[2].ready?.openRevision)
        #expect(frames[2].ready?.openRevision == 1 && frames[6].ready?.openRevision == 2)
        #expect(frames[2].ready?.serviceEpoch != frames[6].ready?.serviceEpoch)
    }
    @Test func malformedAndMixedVersionsFailClosed() throws {
        for frame in try Self.vectors() {
            let body = String(decoding: try W.encode(frame).dropFirst(4), as: UTF8.self)
            for bad in [" " + body, body.replacingOccurrences(of: "\"version\":", with: "\"unknown\":true,\"version\":"),
                        body.replacingOccurrences(of: "\"version\":", with: "\"csr\":null,\"version\":"),
                        body.replacingOccurrences(of: W.version, with: "storage-boot.v2"),
                        body.replacingOccurrences(of: "18446744073709551615", with: "1.8446744073709551615e19")] where bad != body {
                #expect(throws: (any Error).self) { try W.decode(Data(bad.utf8)) }
            }
        }
    }
    @Test func reopenAndReadinessFieldsAreClosedAndRequired() throws {
        let frames = try Self.vectors()
        for index in [1, 2, 5] {
            let body = try W.encode(frames[index]).dropFirst(4)
            let original = try #require(JSONSerialization.jsonObject(with: body) as? [String: Any])
            let nested = index == 2 ? "ready" : "configuration"
            let field = index == 2 ? "open_revision" : "reopen"
            for fault in ["missing", "null", "extra", "zero", "future"] {
                if index != 2 && ["zero", "future"].contains(fault) { continue }
                if index == 1 && fault == "missing" { continue }
                var object = original
                var fields = try #require(object[nested] as? [String: Any])
                switch fault {
                case "missing": fields.removeValue(forKey: field)
                case "null": fields[field] = NSNull()
                case "extra": fields["unknown"] = true
                case "zero": fields[field] = 0
                default: fields[field] = 2
                }
                object[nested] = fields
                let bad = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
                #expect(throws: (any Error).self) { try W.decode(bad) }
            }
        }
        let cfg = try #require(frames[5].configuration)
        let request = try #require(cfg.reopen)
        for action in [W.Configuration.Action.open, .initialize] {
            let bad = W.Configuration(action: action, rootPublicKey: cfg.rootPublicKey, signed: cfg.signed,
                nowUnixSeconds: cfg.nowUnixSeconds, lifetimeSeconds: cfg.lifetimeSeconds, reopen: action == .open ? nil : request)
            #expect(throws: (any Error).self) { try bad.validate() }
        }
        let fresh = try #require(frames[1].configuration)
        let wrongRoot = W.Configuration(action: .open, rootPublicKey: Data(repeating: 8, count: 32), signed: fresh.signed,
            nowUnixSeconds: cfg.nowUnixSeconds, lifetimeSeconds: cfg.lifetimeSeconds, reopen: request)
        #expect(throws: (any Error).self) { try wrongRoot.validate() }
        let g = fresh.signed.grant
        let wrongGrant = try W.L.Grant(operation: g.operation, id: UUID().uuidString.lowercased(), identity: g.identity,
            serial: g.serial, expectedEpoch: g.expectedEpoch, newKey: g.newKey)
        let mismatch = try W.Configuration(action: .open, rootPublicKey: cfg.rootPublicKey,
            signed: .init(grant: wrongGrant, signature: fresh.signed.signature), nowUnixSeconds: cfg.nowUnixSeconds,
            lifetimeSeconds: cfg.lifetimeSeconds, reopen: request)
        #expect(throws: (any Error).self) { try mismatch.validate() }
        try cfg.validate()
        func open(_ reopen: W.L.SignedServiceChange, root: Data? = nil) -> W.Configuration {
            W.Configuration(action: .open, rootPublicKey: root ?? cfg.rootPublicKey, signed: cfg.signed,
                nowUnixSeconds: cfg.nowUnixSeconds, lifetimeSeconds: cfg.lifetimeSeconds, reopen: reopen)
        }
        // Unsigned (zero), wrong-key, tampered-request and wrong-bootstrap-key reopens fail closed.
        let attacker = Curve25519.Signing.PrivateKey()
        let r = request.request, p = r.predecessor
        let tampered = try W.L.ServiceChangeRequest(operationID: UUID().uuidString.lowercased(), predecessor: p)
        let otherBoot = try StorageLifecycleBootTrust(identity: p.boot.identity, serviceEpoch: p.boot.serviceEpoch,
            tlsRootSHA256: p.boot.tlsRootSHA256, serverSPKI: p.boot.serverSPKI,
            bootstrapKey: try StorageIdentity.RootPublicKey(publicData: attacker.publicKey.rawRepresentation).fingerprint.rawValue)
        let wrongBoot = try W.L.ServiceChangeRequest(operationID: r.operationID,
            predecessor: .init(grant: p.grant, context: p.context, openRevision: p.openRevision, boot: otherBoot))
        for bad in [open(try .init(request: r, signature: Data(repeating: 0, count: 64))),
                    open(try .init(request: r, signature: attacker.signature(for: r.signingBytes))),
                    open(try .init(request: tampered, signature: request.signature)),
                    open(try .init(request: wrongBoot, signature: attacker.signature(for: wrongBoot.signingBytes)),
                         root: attacker.publicKey.rawRepresentation),
                    open(try .init(request: wrongBoot, signature: attacker.signature(for: wrongBoot.signingBytes)))] {
            #expect(throws: (any Error).self) { try bad.validate() }
        }
    }
    @Test func dependentFieldsAndLimits() throws {
        let frames = try Self.vectors()
        var command = frames[3]
        command.command = .authorizeSuccessor
        #expect(throws: (any Error).self) { try W.encode(command) }
        command = frames[3]; command.csr = Data([1])
        #expect(throws: (any Error).self) { try W.encode(command) }
        command = frames[3]; command.sequence = 0
        #expect(throws: (any Error).self) { try W.encode(command) }
        var reply = frames[4]; reply.ok = true
        #expect(throws: (any Error).self) { try W.encode(reply) }
        reply.ready = nil; reply.ok = false
        #expect(throws: (any Error).self) { try W.encode(reply) }
        reply.ok = nil; reply.certificate = Data(repeating: 1, count: 16_385)
        #expect(throws: (any Error).self) { try W.encode(reply) }
    }
    @Test func sameWorkerReplacementFramesAreClosed() throws {
        let frames = try Self.vectors()
        let replace = frames[9], request = try #require(replace.replacementRequest)
        #expect(replace.command == .replaceService && replace.workerUUID == frames[2].ready?.workerUUID)
        #expect(replace.workerUUID == request.predecessorWorkerUUID)
        #expect(replace.serviceEpoch == request.configuration.reopen?.request.predecessor.context.serviceEpoch)
        #expect(frames[8].status?.phase == .workerLost)
        #expect(frames[11].replacement?.phase == .pending)
        #expect(frames[12].replacement?.ready == frames[6].ready)
        #expect(frames[13].replacement?.code == .workerUnreaped)
        #expect(frames[15].command == .reconcileController && frames[15].signed != nil)
        for index in [3, 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17] {
            var frame = frames[index]; frame.workerUUID = nil
            #expect(throws: (any Error).self) { try W.encode(frame) }
            frame.workerUUID = "bad"
            #expect(throws: (any Error).self) { try W.encode(frame) }
        }
        let initialize = try #require(frames[1].configuration), ready = try #require(frames[6].ready)
        let status: (W.ReplacementStatus.Phase, W.Ready?, W.ReplacementCode?) -> W.Frame = { phase, ready, code in
            var frame = frames[11]
            frame.replacement = .init(request: request, phase: phase, ready: ready, code: code)
            return frame
        }
        var faults: [String: W.Frame] = [
            "pending with ready": status(.pending, ready, nil), "pending with code": status(.pending, nil, .replacementFailed),
            "succeeded without ready": status(.succeeded, nil, nil), "succeeded with code": status(.succeeded, ready, .workerUnreaped),
            "failed without code": status(.failed, nil, nil), "failed with ready": status(.failed, ready, .replacementFailed),
        ]
        var frame = frames[9]; frame.workerUUID = frames[6].ready?.workerUUID; faults["replace worker mismatch"] = frame
        frame = frames[9]; frame.serviceEpoch = frames[6].ready?.serviceEpoch; faults["replace epoch mismatch"] = frame
        frame = frames[9]; frame.replacementRequest = nil; faults["replace missing request"] = frame
        frame = frames[9]; frame.command = .query; faults["request on query"] = frame
        frame = frames[9]; frame.replacementRequest = .init(predecessorWorkerUUID: request.predecessorWorkerUUID, configuration: initialize)
        faults["request action initialize"] = frame
        frame = frames[9]; frame.replacementRequest = .init(predecessorWorkerUUID: "bad", configuration: request.configuration)
        faults["request invalid predecessor"] = frame
        frame = frames[15]; frame.signed = nil; faults["reconcile without signed"] = frame
        frame = frames[15]; frame.controller = nil; faults["reconcile without controller"] = frame
        frame = frames[8]; frame.ok = true; faults["status plus ok"] = frame
        frame = frames[8]; frame.replacement = frames[11].replacement; faults["status plus replacement"] = frame
        frame = frames[14]; frame.status = frames[8].status; faults["notifications with status"] = frame
        for (name, fault) in faults {
            #expect(throws: (any Error).self, "\(name)") { try W.encode(fault) }
        }
        let bodies = try frames.map { String(decoding: try W.encode($0).dropFirst(4), as: UTF8.self) }
        for (index, from, to) in [
            (8, "\"phase\":\"worker-lost\"", "\"phase\":\"lost\""),
            (8, "\"phase\":\"worker-lost\"", "\"phase\":\"worker-lost\",\"scope\":1"),
            (9, "\"predecessor_worker_uuid\":", "\"extra\":true,\"predecessor_worker_uuid\":"),
            (11, "\"phase\":\"pending\"", "\"phase\":\"pending\",\"ready\":null"),
            (13, "\"code\":\"worker-unreaped\"", "\"code\":\"service\""),
            (13, "\"code\":\"worker-unreaped\"", "\"code\":null"),
        ] {
            let bad = bodies[index].replacingOccurrences(of: from, with: to)
            #expect(bad != bodies[index])
            #expect(throws: (any Error).self) { try W.decode(Data(bad.utf8)) }
        }
    }
    @Test func notificationsReplyPayloadAndClosedCodes() throws {
        let frames = try Self.vectors()
        let reply = frames[16], entry = try #require(reply.notifications?.first)
        #expect(reply.notifications?.count == 1 && entry.epoch == frames[2].ready?.serviceEpoch)
        #expect(entry.binding.store == frames[2].ready?.identity.store && entry.binding.role == .runtime)
        #expect(frames[17].code == .workerBusy)
        for code in [W.Code.staleWorker, .workerBusy, .workerLost, .workerUnreaped, .replacementConflict, .configuration, .bindingMismatch,
                     .sequence, .command, .service, .invalidFrame] {
            var frame = frames[17]; frame.code = code
            #expect(try W.decode(W.encode(frame).dropFirst(4)) == frame)
        }
        var faults: [String: W.Frame] = [:]
        var frame = reply; frame.notifications = nil; faults["missing notifications"] = frame
        frame = reply; frame.notifications = Array(repeating: entry, count: W.maximumNotifications + 1); faults["oversize"] = frame
        frame = reply; frame.ok = true; faults["notifications plus ok"] = frame
        frame = reply; frame.code = .workerLost; faults["notifications plus code"] = frame
        frame = frames[14]; frame.notifications = []; faults["notifications on command"] = frame
        var bad = entry; bad.epoch = "bad"
        frame = reply; frame.notifications = [entry, bad]; faults["bad entry epoch"] = frame
        bad = entry; bad.binding.prepare = UUID().uuidString.lowercased()
        frame = reply; frame.notifications = [bad]; faults["runtime with prepare"] = frame
        bad = entry; bad.binding.role = .prepare
        frame = reply; frame.notifications = [bad]; faults["prepare without id"] = frame
        bad = entry; bad.binding.container = "zz"
        frame = reply; frame.notifications = [bad]; faults["bad container pin"] = frame
        for (name, fault) in faults {
            #expect(throws: (any Error).self, "\(name)") { try W.encode(fault) }
        }
        frame = reply; frame.notifications = Array(repeating: entry, count: W.maximumNotifications)
        #expect(try W.decode(W.encode(frame).dropFirst(4)) == frame)
        frame = reply; frame.notifications = []
        #expect(try W.decode(W.encode(frame).dropFirst(4)) == frame)
        let bodies = try [16, 17].map { String(decoding: try W.encode(frames[$0]).dropFirst(4), as: UTF8.self) }
        for (body, from, to) in [
            (bodies[0], "\"notifications\":[", "\"notifications\":[null,"),
            (bodies[0], "\"notifications\":[{", "\"notifications\":[{\"extra\":1,"),
            (bodies[0], "\"mode\":\"read-write\"", "\"mode\":\"read-write\",\"unknown\":true"),
            (bodies[0], "\"role\":\"runtime\"", "\"role\":\"owner\""),
            (bodies[1], "\"code\":\"worker-busy\"", "\"code\":\"worker-gone\""),
            (bodies[1], "\"code\":\"worker-busy\"", "\"code\":null"),
        ] {
            let mutated = body.replacingOccurrences(of: from, with: to)
            #expect(mutated != body)
            #expect(throws: (any Error).self) { try W.decode(Data(mutated.utf8)) }
        }
    }
    @Test func sharedGoWorkerUnreapedTopLevelReply() throws {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Fixtures/storage-bootstrap/lifecycle-worker-unreaped-v2.json")
        let body = Data(try Data(contentsOf: url).dropLast()) // Fixture ends with a newline.
        let frame = try W.decode(body)
        #expect(frame.operation == .reply && frame.code == .workerUnreaped)
        #expect(frame.sequence == UInt64.max)
        #expect(frame.replacement == nil && frame.ok == nil)
        #expect(Data(try W.encode(frame).dropFirst(4)) == body)
        let raw = String(decoding: body, as: UTF8.self)
        for replacement in ["\"code\":\"replacement-failed\"", "\"code\":\"worker-gone\"", "\"code\":null",
                            "\"code\":\"worker-unreaped\",\"ok\":true"] {
            let bad = raw.replacingOccurrences(of: "\"code\":\"worker-unreaped\"", with: replacement)
            #expect(throws: (any Error).self) { try W.decode(Data(bad.utf8)) }
        }
    }
    @Test func replyRejectsSuccessPlusErrorAndDuplicateKeys() throws {
        let frames = try Self.vectors()
        var reply = frames[4]
        reply.ready = nil; reply.ok = true; reply.code = .service
        #expect(throws: (any Error).self) { try W.encode(reply) }
        reply.code = nil
        let body = String(decoding: try W.encode(reply).dropFirst(4), as: UTF8.self)
        for bad in [body.replacingOccurrences(of: "\"ok\":true", with: "\"ok\":true,\"ok\":true"),
                    body.replacingOccurrences(of: "\"ok\":true", with: "\"code\":\"service\",\"ok\":true"),
                    body.replacingOccurrences(of: "\"binding\":{", with: "\"binding\":{\"bytes\":1,")] {
            #expect(throws: (any Error).self) { try W.decode(Data(bad.utf8)) }
        }
    }
}

extension StorageLifecycleServiceBootProtocolTests {
    private typealias C = ManagedPrepareCompatibilityProtocol
    private typealias P = ManagedPrepareWorkerCheckpointProtocol
    private struct PrepareVector: Decodable {
        var name: String
        var arm: C.Arm
        var observationCanonical: String
        var storageObservationCanonical: String?
        var storageArm: C.StorageArm?
        var storageStatus: C.StorageStatus?
    }
    private func prepareVectors() throws -> [PrepareVector] {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode([PrepareVector].self, from: Data(contentsOf:
            root.appendingPathComponent("Guest/internal/preparecompat/testdata/full-vectors.json")))
    }
    private func prepareFrames() throws -> [W.Frame] {
        let rows = try prepareVectors()
        let binding = try #require(Self.vectors().first?.binding)
        var frames: [W.Frame] = []
        for row in rows {
            if let arm = row.storageArm, let status = row.storageStatus {
                let base = W.Frame(operation: .command, binding: binding, sequence: 1,
                    serviceEpoch: arm.arm.scope.serviceEpoch, workerUUID: arm.workerUUID)
                var frame = base
                frame.command = .prepareCompatibilityArm; frame.prepareCompatibilityArm = arm
                frames.append(frame)
                frame = base; frame.command = .prepareCompatibilityObserve; frame.prepareCompatibilityQuery = status.query
                frames.append(frame)
                frame = base; frame.operation = .reply; frame.prepareCompatibilityStatus = status
                frames.append(frame)
                if let admission = status.observation?.admission {
                    let release = C.StorageRelease(query: status.query, stage: row.name, token: admission.releaseToken)
                    frame = base; frame.command = .prepareCompatibilityRelease; frame.prepareCompatibilityRelease = release
                    frames.append(frame)
                    frame = base; frame.command = .prepareCompatibilityWorkerExit; frame.prepareCompatibilityWorkerExit = release
                    frames.append(frame)
                    frame = base; frame.operation = .reply
                    frame.prepareCompatibilityWorkerWait = .init(query: status.query, stage: row.name, token: release.token,
                        requestSequence: admission.requestSequence, workerPID: 42, exitCode: 74, reaped: true)
                    frames.append(frame)
                }
            }
            guard P.checkpointExitCut(row.name) else { continue }
            var claim = P.WorkerCheckpointExit(arm: row.arm, workerUUID: row.arm.requestID)
            switch row.name {
            case "normal", "first-child-published":
                claim.checkpoint = try C.decode(C.Observation.self, from: Data(row.observationCanonical.utf8))
            case "before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame":
                claim.earlyCheckpoint = try C.decode(C.EarlyObservation.self, from: Data(row.observationCanonical.utf8))
            default:
                let raw = try #require(row.storageObservationCanonical)
                let observation = try C.decode(C.StorageObservation.self, from: Data(raw.utf8))
                claim.storageCheckpoint = observation; claim.workerUUID = observation.workerUUID
            }
            var frame = W.Frame(operation: .command, binding: binding, sequence: 1,
                serviceEpoch: claim.arm.scope.serviceEpoch, command: .prepareCompatibilityCheckpointExit,
                workerUUID: claim.workerUUID, prepareCompatibilityCheckpointExit: claim)
            frames.append(frame)
            frame.operation = .reply; frame.command = nil; frame.prepareCompatibilityCheckpointExit = nil
            frame.prepareCompatibilityCheckpointAck = claim
            frames.append(frame)
            frame.prepareCompatibilityCheckpointAck = nil
            frame.prepareCompatibilityCheckpointWait = .init(arm: claim.arm, checkpoint: claim.checkpoint,
                earlyCheckpoint: claim.earlyCheckpoint, storageCheckpoint: claim.storageCheckpoint,
                workerUUID: claim.workerUUID, workerPID: 42, exitCode: 74, reaped: true)
            frames.append(frame)
        }
        return frames
    }
    @Test func boundedFrameStoragePreservesCarrierValueSemantics() async throws {
        // Regression: inline nested carriers made Frame 8,761 bytes and exhausted
        // ordinary worker stacks in Frame.validatePrepareCompatibility().
        #expect(MemoryLayout<W.Frame>.size <= 512)
        print("Lifecycle Frame inline size: \(MemoryLayout<W.Frame>.size) bytes")
        let frames = try prepareFrames()
        try await Task.detached {
            for original in frames {
                let decoded = try W.decode(W.encode(original).dropFirst(4))
                #expect(decoded == original)
                var copy = original
                copy.prepareCompatibilityCheckpointExit?.arm.scope.prepare = "ffffffff-ffff-4fff-8fff-ffffffffffff"
                if original.prepareCompatibilityCheckpointExit != nil {
                    #expect(copy != original)
                    #expect(original == decoded)
                    #expect(throws: (any Error).self) { try W.encode(copy) }
                    copy.prepareCompatibilityCheckpointExit = nil
                    #expect(original == decoded)
                    #expect(copy != original)
                }
                // An additional carrier must not replace or conceal the first.
                copy = original
                copy.prepareCompatibilityQuery = .init(requestID: "ffffffff-ffff-4fff-8fff-ffffffffffff", armDigest: String(repeating: "a", count: 64), workerUUID: "ffffffff-ffff-4fff-8fff-ffffffffffff")
                #expect(copy != original)
                #expect(original == decoded)
                #expect(throws: (any Error).self) { try W.encode(copy) }
            }
        }.value
    }
    @Test func prepareCarrierRoundtripsAllCommandsAndCheckpointCuts() throws {
        let frames = try prepareFrames()
        #expect(Set(frames.compactMap { $0.command?.rawValue }) == [
            "prepare-compatibility-arm", "prepare-compatibility-observe", "prepare-compatibility-release",
            "prepare-compatibility-worker-exit", "prepare-compatibility-checkpoint-exit"])
        #expect(frames.filter { $0.prepareCompatibilityCheckpointExit != nil }.count == 7)
        var fields = Set<String>()
        for frame in frames {
            let body = try W.encode(frame).dropFirst(4)
            #expect(try W.decode(body) == frame)
            let object = try #require(JSONSerialization.jsonObject(with: body) as? [String: Any])
            fields.formUnion(object.keys.filter { $0.hasPrefix("prepareCompatibility") })
            #expect(object["scope"] == nil)
            #expect(object["service_epoch"] as? String == frame.serviceEpoch)
            #expect(object["worker_uuid"] as? String == frame.workerUUID)
        }
        #expect(fields == ["prepareCompatibilityArm", "prepareCompatibilityQuery", "prepareCompatibilityRelease",
            "prepareCompatibilityWorkerExit", "prepareCompatibilityCheckpointExit", "prepareCompatibilityStatus",
            "prepareCompatibilityWorkerWait", "prepareCompatibilityCheckpointAck", "prepareCompatibilityCheckpointWait"])
    }
    @Test func workerExitAllowsOnlyTheTwoHeldAdmissionStages() throws {
        let frames = try prepareFrames().filter { $0.prepareCompatibilityWorkerExit != nil }
        #expect(Set(frames.compactMap { $0.prepareCompatibilityWorkerExit?.stage }) == [
            "full-frame-before-admit", "admitted-queued"])
        for original in frames {
            let exit = try #require(original.prepareCompatibilityWorkerExit)
            try C.validateStorageWorkerExit(exit)
            #expect(try W.decode(W.encode(original).dropFirst(4)) == original)
            for stage in ["normal", "first-child-published", "storage-exit", "unknown", ""] {
                var invalid = exit; invalid.stage = stage
                #expect(throws: (any Error).self) { try C.validateStorageWorkerExit(invalid) }
                var frame = original; frame.prepareCompatibilityWorkerExit = invalid
                #expect(throws: (any Error).self) { try W.encode(frame) }
                #expect(throws: (any Error).self) { try W.decode(W.L.encode(frame)) }
            }
        }
    }
    @Test func prepareCarrierRejectsStaleIdentityAndMixedVersions() throws {
        let other = "ffffffff-ffff-4fff-8fff-ffffffffffff"
        for original in try prepareFrames() {
            var frame = original; frame.workerUUID = other
            #expect(throws: (any Error).self) { try W.encode(frame) }
            #expect(throws: (any Error).self) { try W.decode(W.L.encode(frame)) }
            let hasEpoch = original.prepareCompatibilityArm != nil || original.prepareCompatibilityCheckpointExit != nil ||
                original.prepareCompatibilityCheckpointAck != nil || original.prepareCompatibilityCheckpointWait != nil ||
                original.prepareCompatibilityStatus?.observation?.bound != nil
            if hasEpoch {
                frame = original; frame.serviceEpoch = other
                #expect(throws: (any Error).self) { try W.encode(frame) }
                #expect(throws: (any Error).self) { try W.decode(W.L.encode(frame)) }
            }
            frame = original; frame.version = "storage-boot.v2"
            #expect(throws: (any Error).self) { try W.encode(frame) }
            #expect(throws: (any Error).self) { try W.decode(W.L.encode(frame)) }
            frame = original; frame.operation = .hello
            #expect(throws: (any Error).self) { try W.encode(frame) }
            if original.operation == .command {
                frame = original; frame.command = .query
                #expect(throws: (any Error).self) { try W.encode(frame) }
            } else {
                frame = original; frame.ok = true
                #expect(throws: (any Error).self) { try W.encode(frame) }
            }
        }
    }
    @Test func prepareCarrierRawSchemaRejectsMalformedAndMixedPayloads() throws {
        for frame in try prepareFrames() {
            let bytes = try W.encode(frame).dropFirst(4)
            let original = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
            let key = try #require(original.keys.first { $0.hasPrefix("prepareCompatibility") })
            for fault in ["missing", "null", "unknown", "nested-null", "extra-result", "old-scope"] {
                var object = original
                switch fault {
                case "missing": object.removeValue(forKey: key)
                case "null": object[key] = NSNull()
                case "extra-result": object["ok"] = true
                case "old-scope":
                    object["scope"] = ["workerUUID": frame.workerUUID!, "serviceEpoch": frame.serviceEpoch!]
                    object.removeValue(forKey: "worker_uuid"); object.removeValue(forKey: "service_epoch")
                default:
                    var payload = try #require(object[key] as? [String: Any])
                    if fault == "unknown" { payload["unknown"] = true }
                    else { payload[payload.keys.sorted().first!] = NSNull() }
                    object[key] = payload
                }
                let bad = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
                #expect(throws: (any Error).self, "\(key): \(fault)") { try W.decode(bad) }
            }
            let body = String(decoding: bytes, as: UTF8.self)
            for bad in [body.replacingOccurrences(of: "\"\(key)\":{", with: "\"\(key)\":{},\"\(key)\":{"),
                        body.replacingOccurrences(of: "\"version\":3", with: "\"version\":2"),
                        body.replacingOccurrences(of: "\"version\":3", with: "\"version\":3.0"),
                        body.replacingOccurrences(of: "\"reaped\":true", with: "\"reaped\":false"),
                        body.replacingOccurrences(of: "\"workerPID\":42", with: "\"workerPID\":1"),
                        body.replacingOccurrences(of: "\"armDigest\":\"", with: "\"armDigest\":\"z"),
                        body.replacingOccurrences(of: "\"exitCode\":74", with: "\"exitCode\":0")] where bad != body {
                #expect(throws: (any Error).self) { try W.decode(Data(bad.utf8)) }
            }
        }
    }
    @Test func checkpointCarrierRejectsMalformedFullTupleAndCarrierUnion() throws {
        let frames = try prepareFrames()
        for original in frames where original.prepareCompatibilityCheckpointExit != nil {
            let claim = try #require(original.prepareCompatibilityCheckpointExit)
            var changed = claim; changed.arm.scope.prepare = "ffffffff-ffff-4fff-8fff-ffffffffffff"
            var frame = original; frame.prepareCompatibilityCheckpointExit = changed
            #expect(throws: (any Error).self) { try W.encode(frame) }
            changed = claim; changed.checkpoint = nil; changed.earlyCheckpoint = nil; changed.storageCheckpoint = nil
            frame.prepareCompatibilityCheckpointExit = changed
            #expect(throws: (any Error).self) { try W.encode(frame) }
            changed = claim
            if changed.earlyCheckpoint == nil {
                let checkpoints: [C.EarlyObservation] = frames.compactMap { $0.prepareCompatibilityCheckpointExit?.earlyCheckpoint }
                let first = checkpoints.first
                changed.earlyCheckpoint = try #require(first)
            } else {
                let checkpoints: [C.Observation] = frames.compactMap { $0.prepareCompatibilityCheckpointExit?.checkpoint }
                let first = checkpoints.first
                changed.checkpoint = try #require(first)
            }
            frame.prepareCompatibilityCheckpointExit = changed
            #expect(throws: (any Error).self) { try W.decode(W.L.encode(frame)) }
        }
    }
}


extension StorageLifecycleServiceBootProtocolTests {
    static func consumerArm(store: String, epoch: String, worker: String,
                            caseName: ConsumerObservationProtocol.Case = .sameE) -> ConsumerObservationProtocol.Arm {
        let launch = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        return .init(requestID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", armDigest: String(repeating: "c", count: 64),
            operationUUID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", caseName: caseName,
            originalBootBinding: .init(shimLaunchUUID: launch, guestBootNonce: launch),
            original: .init(epoch: caseName == .crossE ? launch : epoch,
                binding: .init(store: store, volume: launch, attachment: launch,
                    container: String(repeating: "e", count: 64), launch: launch, key: String(repeating: "f", count: 64),
                    mode: caseName == .wrongMode ? "read-only" : "read-write")),
            originalLeafSHA256: String(repeating: "a", count: 64),
            workerScope: .init(storeUUID: store, serviceEpoch: epoch, workerUUID: worker))
    }
    static func consumerStatus(_ arm: ConsumerObservationProtocol.Arm,
                               state: ConsumerObservationProtocol.State) -> ConsumerObservationProtocol.Status {
        .init(query: arm, state: state, selectedCount: state == .armed ? 0 : 1,
            evidence: [.observed, .finalized].contains(state) ? .init(stage: "request-admit", errorClass: "blocked",
                storeUUID: arm.workerScope.storeUUID, serviceEpoch: arm.workerScope.serviceEpoch,
                rejectedLeafSHA256: arm.originalLeafSHA256,
                admission: .init(original: arm.original, requestSequence: 1, operation: "get_attr", node: 1,
                    authKind: 3, noHandle: true)) : nil)
    }
    private func consumerFrames() throws -> [W.Frame] {
        let vectors = try Self.vectors(), ready = try #require(vectors[2].ready)
        var frames: [W.Frame] = []
        for caseName in [ConsumerObservationProtocol.Case.sameE, .crossE, .wrongVolume, .wrongKey,
                         .wrongRole, .wrongMode, .wrongEpoch, .sameEReconnect, .sameEFile] {
            let arm = Self.consumerArm(store: ready.identity.store, epoch: ready.serviceEpoch,
                worker: ready.workerUUID, caseName: caseName)
            for command in [W.Command.consumerObservationArm, .consumerObservationQuery, .consumerObservationFinalize] {
                frames.append(.init(operation: .command, binding: vectors[0].binding, sequence: 41,
                    serviceEpoch: ready.serviceEpoch, command: command, workerUUID: ready.workerUUID,
                    consumerObservationArm: command == .consumerObservationArm ? arm : nil,
                    consumerObservationQuery: command == .consumerObservationArm ? nil : arm))
            }
            frames.append(.init(operation: .reply, binding: vectors[0].binding, sequence: 41,
                serviceEpoch: ready.serviceEpoch, workerUUID: ready.workerUUID,
                consumerObservationStatus: .init(query: arm, state: .armed, selectedCount: 0)))
        }
        return frames
    }
    @Test func consumerCarriersRoundtripWithExactV1FieldSpelling() async throws {
        let frames = try consumerFrames()
        #expect(MemoryLayout<W.Frame>.size <= 512)
        try await Task.detached {
            for frame in frames {
                let bytes = try W.encode(frame).dropFirst(4)
                #expect(try W.decode(bytes) == frame)
                let object = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
                let field = frame.consumerObservationArm != nil ? "consumerObservationArm"
                    : frame.consumerObservationQuery != nil ? "consumerObservationQuery" : "consumerObservationStatus"
                #expect(object[field] != nil)
                #expect(object["service_epoch"] as? String == frame.serviceEpoch)
                #expect(object["worker_uuid"] as? String == frame.workerUUID)
                var copy = frame
                if copy.consumerObservationArm != nil { copy.consumerObservationArm?.requestID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" }
                if copy.consumerObservationQuery != nil { copy.consumerObservationQuery?.requestID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" }
                if copy.consumerObservationStatus != nil { copy.consumerObservationStatus?.query.requestID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" }
                #expect(copy != frame)
                #expect(try W.decode(bytes) == frame) // Immutable boxes must not alias copies.
            }
        }.value
    }
    @Test func consumerCarriersRejectEnvelopeMismatchAndMixedUnions() throws {
        // The shared vector's store is eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee.
        let other = "99999999-9999-4999-8999-999999999999"
        for original in try consumerFrames() {
            for fault in ["epoch", "worker", "operation", "command", "mixed-result", "mixed-query", "mixed-consumer", "missing-consumer", "profile", "version", "store"] {
                var frame = original
                switch fault {
                case "epoch": frame.serviceEpoch = other
                case "worker": frame.workerUUID = other
                case "operation": frame.operation = .hello
                case "command": frame.command = .query
                case "mixed-result": frame.ok = true
                case "mixed-consumer":
                    let arm = try #require(frame.consumerObservationArm ?? frame.consumerObservationQuery ?? frame.consumerObservationStatus?.query)
                    if frame.consumerObservationArm == nil { frame.consumerObservationArm = arm }
                    else { frame.consumerObservationQuery = arm }
                case "missing-consumer":
                    frame.consumerObservationArm = nil; frame.consumerObservationQuery = nil; frame.consumerObservationStatus = nil
                case "mixed-query":
                    frame.prepareCompatibilityQuery = .init(requestID: other, armDigest: String(repeating: "a", count: 64), workerUUID: other)
                default:
                    var arm = try #require(frame.consumerObservationArm ?? frame.consumerObservationQuery ?? frame.consumerObservationStatus?.query)
                    if fault == "profile" { arm.profile = "ordinary" }
                    if fault == "version" { arm.version = 0 }
                    if fault == "store" { arm.workerScope.storeUUID = other }
                    if frame.consumerObservationArm != nil { frame.consumerObservationArm = arm }
                    if frame.consumerObservationQuery != nil { frame.consumerObservationQuery = arm }
                    if frame.consumerObservationStatus != nil { frame.consumerObservationStatus?.query = arm }
                }
                try #require(frame != original, "\(fault) must change the valid fixture")
                #expect(throws: (any Error).self, "\(fault)") { try W.encode(frame) }
                #expect(throws: (any Error).self, "\(fault)") { try W.decode(W.L.encode(frame)) }
            }
        }
    }
    @Test func consumerCarrierSchemaRejectsNullUnknownMissingAndMixedFields() throws {
        for frame in try consumerFrames().prefix(4) {
            let bytes = try W.encode(frame).dropFirst(4)
            let original = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
            let key = try #require(original.keys.first { $0.hasPrefix("consumerObservation") })
            for fault in ["missing", "null", "unknown", "nested-null", "mixed", "alias"] {
                var object = original
                switch fault {
                case "missing": object.removeValue(forKey: key)
                case "null": object[key] = NSNull()
                case "mixed": object["ok"] = true
                case "alias": object["consumer_observation_arm"] = object.removeValue(forKey: key)
                default:
                    var payload = try #require(object[key] as? [String: Any])
                    if fault == "unknown" { payload["unknown"] = true }
                    else if key == "consumerObservationStatus" { payload["evidence"] = NSNull() }
                    else {
                        var original = try #require(payload["original"] as? [String: Any])
                        var binding = try #require(original["binding"] as? [String: Any])
                        binding["prepare"] = NSNull()
                        original["binding"] = binding; payload["original"] = original
                    }
                    object[key] = payload
                }
                let bad = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
                #expect(throws: (any Error).self, "\(key): \(fault)") { try W.decode(bad) }
            }
            let body = String(decoding: bytes, as: UTF8.self)
            let duplicate = body.replacingOccurrences(of: "\"\(key)\":{", with: "\"\(key)\":{},\"\(key)\":{")
            #expect(throws: (any Error).self) { try W.decode(Data(duplicate.utf8)) }
        }
    }
}

extension StorageLifecycleServiceBootProtocolTests {
    nonisolated static func isolationFrames(_ command: W.Command, revision: UInt64 = .max) throws -> (W.Frame, W.Frame) {
        let vectors = try vectors(), ready = try #require(vectors[2].ready)
        let claim = W.IsolationRequest(requestID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            operationUUID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", armDigest: String(repeating: "a", count: 64),
            challenge: "cccccccc-cccc-4ccc-8ccc-cccccccccccc")
        let result: String
        switch command {
        case .isolationState: result = "registry-state"
        case .legacyConnection: result = "legacy-tls-header-rejected"
        case .secondServiceExclusivity: result = "second-owner-locked"
        default: throw W.ValidationError.invalidFrame
        }
        // The reused v1 DTO intentionally has no public memberwise initializer.
        let requestJSON = String(decoding: try W.L.encode(claim), as: UTF8.self)
        let body = """
        {"caseName":"\(command.rawValue)","registrySHA256":"\(String(repeating: "b", count: 64))","request":\(requestJSON),"result":"\(result)","revision":\(revision),"serviceEpoch":"\(ready.serviceEpoch)","store":"\(ready.identity.store)","workerUUID":"\(ready.workerUUID)"}
        """
        let proof = try W.L.decode(W.IsolationProof.self, from: Data(body.utf8))
        let request = W.Frame(operation: .command, binding: vectors[0].binding, sequence: .max,
            serviceEpoch: ready.serviceEpoch, command: command, workerUUID: ready.workerUUID, isolationRequest: claim)
        let reply = W.Frame(operation: .reply, binding: request.binding, sequence: request.sequence,
            serviceEpoch: ready.serviceEpoch, workerUUID: ready.workerUUID, isolationProof: proof)
        return (request, reply)
    }

    @Test(arguments: [W.Command.isolationState, .legacyConnection, .secondServiceExclusivity])
    func isolationCarriersAreClosedAndBoxed(command: W.Command) throws {
        let (request, reply) = try Self.isolationFrames(command)
        #expect(MemoryLayout<W.Frame>.size <= 512)
        for original in [request, reply] {
            let bytes = try W.encode(original).dropFirst(4)
            #expect(try W.decode(bytes) == original)
            var copy = original
            copy.isolationRequest = request.isolationRequest
            copy.isolationProof = reply.isolationProof
            #expect(copy != original)
            #expect(try W.decode(bytes) == original)
            #expect(throws: (any Error).self) { try W.encode(copy) }
            #expect(throws: (any Error).self) { try W.decode(W.L.encode(copy)) }
            copy = original; copy.command = .query
            #expect(throws: (any Error).self) { try W.encode(copy) }
            copy = original; copy.ok = true
            #expect(throws: (any Error).self) { try W.encode(copy) }
            copy = original; copy.isolationRequest = nil; copy.isolationProof = nil
            #expect(throws: (any Error).self) { try W.encode(copy) }

            let object = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
            let key = original.operation == .command ? "isolationRequest" : "isolationProof"
            let nested = try #require(object[key] as? [String: Any])
            for field in nested.keys {
                for value in [NSNull(), "invalid"] as [Any] {
                    var bad = object, payload = nested; payload[field] = value; bad[key] = payload
                    let encoded = try JSONSerialization.data(withJSONObject: bad, options: [.sortedKeys, .withoutEscapingSlashes])
                    #expect(throws: (any Error).self) { try W.decode(encoded) }
                }
                var bad = object, payload = nested; payload.removeValue(forKey: field); bad[key] = payload
                #expect(throws: (any Error).self) {
                    try W.decode(JSONSerialization.data(withJSONObject: bad, options: [.sortedKeys, .withoutEscapingSlashes]))
                }
            }
            let body = String(decoding: bytes, as: UTF8.self)
            for bad in [
                body.replacingOccurrences(of: "\"\(key)\":{", with: "\"\(key)\":null,\"\(key)\":{"),
                body.replacingOccurrences(of: "\"\(key)\":{", with: "\"\(key)\":{\"unknown\":true,"),
                body.replacingOccurrences(of: "\"requestID\":", with: "\"requestID\":null,\"requestID\":"),
                body.replacingOccurrences(of: "\"requestID\":", with: "\"unknown\":true,\"requestID\":"),
                body.replacingOccurrences(of: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", with: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"),
                body.replacingOccurrences(of: String(repeating: "a", count: 64), with: String(repeating: "A", count: 64)),
                body.replacingOccurrences(of: "\"revision\":18446744073709551615", with: "\"revision\":0"),
                body.replacingOccurrences(of: "\"revision\":18446744073709551615", with: "\"revision\":18446744073709551616"),
                body.replacingOccurrences(of: "\"revision\":18446744073709551615", with: "\"revision\":1e2"),
            ] where bad != body {
                #expect(throws: (any Error).self) { try W.decode(Data(bad.utf8)) }
            }
        }
        #expect(reply.isolationProof?.revision == UInt64.max)
        for epoch in [true, false] {
            var bad = reply
            if epoch { bad.serviceEpoch = request.isolationRequest?.requestID }
            else { bad.workerUUID = request.isolationRequest?.requestID }
            #expect(throws: (any Error).self) { try W.encode(bad) }
        }
        let body = String(decoding: try W.encode(reply).dropFirst(4), as: UTF8.self)
        for result in ["registry-state", "legacy-tls-header-rejected", "second-owner-locked"] where result != reply.isolationProof?.result {
            let bad = body.replacingOccurrences(of: try #require(reply.isolationProof?.result), with: result)
            #expect(throws: (any Error).self) { try W.decode(Data(bad.utf8)) }
        }
    }
}

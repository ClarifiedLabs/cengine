import Foundation
import Testing
@testable import CEngineCore

@Suite struct SameEConsumerObservationProtocolTests {
    typealias G = OriginalConsumerObservationProtocol
    typealias C = ConsumerObservationProtocol
    let id = "11111111-1111-4111-8111-111111111111"
    let other = "22222222-2222-4222-8222-222222222222"
    let hash = String(repeating: "ab", count: 32)

    func fixture(_ name: G.Case) -> (G.Binding, G.Evidence, G.Evidence, C.Status) {
        let owner = G.Binding(requestID: id, armDigest: hash, operationUUID: other, caseName: name, generation: 7,
            boot: .init(shimLaunchUUID: id, guestBootNonce: other),
            scope: .init(intent: id, store: other, serviceEpoch: id, controllerEpoch: 1, controllerKey: hash,
                container: hash, containerInstance: other, launch: id, prepare: other, specificationDigest: hash),
            targetAttachment: other, key: hash, certificateSHA256: hash)
        var first = G.Evidence(arm: .init(owner), stage: "begun", scope: owner.scope,
            keySHA256: hash, mountIdentitySHA256: hash, serverDERSHA256: "", signCount: 0,
            signInputSHA256: "", bytesWrittenAfterSign: 0, clientWrittenBytes: 0,
            clientPrefixBytes: 0, clientPrefixSHA256: "", localError: "", fdOperation: "fsync-directory", fdSequence: 1,
            originalOperation: .init(kind: "data-getattr-root", sequence: 1, errorClass: "ok"),
            rootRequest: .init(node: 9, requestSequence: 4))
        if name == .sameERetainedFD {
            first.rootRequest = nil; first.fdOperation = "write-file-fsync"
            first.originalOperation = .init(kind: "write-file-fsync", sequence: 1, errorClass: "ok")
            first.writable = .init(identitySHA256: hash, written: 1, writeError: "ok", syncError: "ok", completed: true,
                trace: .init(write: .init(node: 9, handle: 10, requestSequence: 4),
                    sync: .init(node: 9, handle: 10, requestSequence: 5), writeOK: true, syncOK: true))
        }
        let arm = C.Arm(requestID: id, armDigest: hash, operationUUID: other,
            caseName: name == .sameERetainedFD ? .sameEFile : ((name == .sameEExistingData || name.isRegistration) ? .sameE : .sameEReconnect),
            originalBootBinding: owner.boot, original: .init(epoch: id,
                binding: .init(store: other, volume: id, attachment: other, container: hash, launch: id, key: hash,
                    mode: name == .sameERetainedFD ? "read-write" : "read-only")),
            originalLeafSHA256: hash, workerScope: .init(storeUUID: other, serviceEpoch: id, workerUUID: other))
        var probe = first
        probe.serverDERSHA256 = WorkloadStorageProtocol.specificationDigest(Data([1]))
        var evidence = C.Evidence(stage: "request-admit", errorClass: "blocked", storeUUID: other,
            serviceEpoch: id, rejectedLeafSHA256: hash)
        if (name == .sameEExistingData || name.isRegistration) {
            probe.stage = "original-data-attempt"
            probe.rootRequest = .init(node: 9, requestSequence: 7)
            probe.originalOperation = .init(kind: "data-getattr-root", sequence: 2, errorClass: "transport-failed")
            evidence.admission = .init(original: arm.original, requestSequence: 7, operation: "get_attr", node: 9, authKind: 3, noHandle: true)
        } else if name == .sameERetainedFD {
            probe.stage = "original-file-attempt"; probe.fdSequence = 2
            probe.originalOperation = .init(kind: "write-file-fsync", sequence: 2, errorClass: "transport-failed")
            probe.writable = .init(identitySHA256: hash, written: 0, writeError: "eio", syncError: "estale", completed: true,
                trace: .init(capability: .init(node: 9, requestSequence: 7), writeOK: false, syncOK: false))
            evidence.admission = .init(original: arm.original, requestSequence: 7, operation: "get_xattr", node: 9,
                authKind: 1, noHandle: true, capabilityName: "security.capability")
        } else {
            probe.stage = "original-owner-signed-flight"; probe.signCount = 1; probe.signInputSHA256 = hash
            probe.bytesWrittenAfterSign = 100; probe.clientWrittenBytes = 200; probe.localError = "eof"
            probe.hello = arm.original
            probe.originalOperation = .init(kind: "data-original-hello", sequence: 2, errorClass: "peer-closed-before-root")
            evidence.stage = "authenticate-data"; evidence.hello = arm.original
        }
        return (owner, first, probe, .init(query: arm, state: .observed, selectedCount: 1, evidence: evidence))
    }
    func request(_ owner: G.Binding, _ command: G.Command) throws -> G.Request {
        let payload: Data
        if command == .probe {
            payload = try JSONEncoder().encode(G.Probe(arm: .init(owner), scope: owner.scope,
                peer: .init(tlsRootDER: Data([2]), serverDER: Data([1]), serverKey: hash, dataAddress: "192.0.2.1:2049")))
        } else if command == .result {
            payload = try JSONEncoder().encode(G.Prefix(arm: .init(owner), serverPrefixBytes: 100, serverPrefixSHA256: hash))
        } else { payload = try JSONEncoder().encode(G.GuestArm(owner)) }
        return .init(binding: owner, command: command, payload: payload)
    }
    @Test(arguments: [G.Case.sameEExistingData, .sameEOldLeafReconnect, .attachmentKeyReuse, .delayedRegistration])
    func completeChainAndWorkerCorrelation(_ name: G.Case) throws {
        let (owner, begun, probe, observed) = fixture(name)
        #expect(owner.version == 4 && name.isSameE && G.Case.sameERetainedFD.isSameE)
        #expect(observed.query.version == ((name == .sameEExistingData || name.isRegistration) ? 6 : 5))
        var armed = begun; armed.stage = "armed-mounted-positive"
        _ = try G.checkedReply(JSONEncoder().encode(armed), request: request(owner, .arm))
        _ = try G.checkedReply(JSONEncoder().encode(begun), request: request(owner, .begin), previous: armed)
        _ = try G.checkedReply(JSONEncoder().encode(probe), request: request(owner, .probe), previous: begun)
        #expect(try C.decodeStatus(JSONEncoder().encode(observed)) == observed)
        try G.validateSameE(probe, positive: begun, observed: observed)
        var final = observed; final.state = .finalized
        try C.validateFinalization(final, observed: observed)
        #expect(throws: (any Error).self) { try G.validate(request(owner, .result)) }
        #expect(throws: (any Error).self) { try G.checkedReply(JSONEncoder().encode(probe), request: request(owner, .probe)) }
        for fault in ["node", "sequence", "operation", "prefix", "signature", "scope", "root-missing"] {
            var bad = probe
            switch fault {
            case "node": bad.rootRequest?.node = 11
            case "sequence": bad.rootRequest?.requestSequence = (name == .sameEExistingData || name.isRegistration) ? 4 : 7
            case "operation": bad.originalOperation.errorClass = "client-closed-joined"
            case "prefix": bad.clientPrefixBytes = 100; bad.clientPrefixSHA256 = hash
            case "signature": bad.signCount = (name == .sameEExistingData || name.isRegistration) ? 1 : 0
            case "scope": bad.scope.controllerEpoch += 1
            default: bad.rootRequest = nil
            }
            #expect(throws: (any Error).self) { try G.checkedReply(JSONEncoder().encode(bad), request: request(owner, .probe), previous: begun) }
        }
        var mismatch = observed
        if (name == .sameEExistingData || name.isRegistration) { mismatch.evidence?.admission?.requestSequence = 8 }
        else { mismatch.query.original.binding.volume = other; mismatch.evidence?.hello = mismatch.query.original }
        #expect(throws: (any Error).self) { try G.validateSameE(probe, positive: begun, observed: mismatch) }
    }
    func legacyWriteWorker() -> C.Status {
        var value = fixture(.sameERetainedFD).3
        value.query.version = 7
        value.evidence?.admission = .init(original: value.query.original, requestSequence: 7,
            operation: "write", node: 9, authKind: 2, handle: 10, writeOneAtZero: true)
        return value
    }
    @Test func writableChainJoinsActualCapabilityDenialAndFinalization() throws {
        let (owner, begun, probe, observed) = fixture(.sameERetainedFD)
        #expect(owner.version == 7 && observed.query.version == 8 && owner.caseName.isSameE)
        #expect(observed.query.caseName == .sameEFile && !observed.query.caseName.isWrongHello)
        var armed = begun; armed.stage = "armed-mounted-positive"
        _ = try G.checkedReply(JSONEncoder().encode(armed), request: request(owner, .arm))
        _ = try G.checkedReply(JSONEncoder().encode(begun), request: request(owner, .begin), previous: armed)
        _ = try G.checkedReply(JSONEncoder().encode(probe), request: request(owner, .probe), previous: begun)
        for auth: UInt8 in [1] {
            var actual = observed; actual.evidence?.admission?.authKind = auth
            #expect(try C.decodeStatus(JSONEncoder().encode(actual)) == actual)
            try G.validateSameE(probe, positive: begun, observed: actual)
            var final = actual; final.state = .finalized
            #expect(try C.decodeStatus(JSONEncoder().encode(final)) == final)
            try C.validateFinalization(final, observed: actual)
            final.evidence?.admission?.handle = 11
            #expect(throws: (any Error).self) { try C.validateFinalization(final, observed: actual) }
        }
        var withSync = probe
        withSync.writable?.trace?.sync = .init(node: 9, handle: 10, requestSequence: 8)
        #expect(throws: (any Error).self) { try G.validateSameE(withSync, positive: begun, observed: observed) }
        #expect(throws: (any Error).self) { try G.validate(request(owner, .result)) }
    }
    @Test func workerV7RejectsWrongWriteWitnessAndVersions() throws {
        let observed = legacyWriteWorker()
        for state in [C.State.observed, .finalized] {
            for fault in ["operation", "node", "handle", "zero-sequence", "auth", "missing-auth", "missing-handle",
                          "witness", "missing-witness", "no-handle", "mode", "epoch", "tuple", "leaf", "case"] {
                var bad = observed; bad.state = state
                switch fault {
                case "operation": bad.evidence?.admission?.operation = "fsync"
                case "node": bad.evidence?.admission?.node = 0
                case "handle": bad.evidence?.admission?.handle = 0
                case "zero-sequence": bad.evidence?.admission?.requestSequence = 0
                case "auth": bad.evidence?.admission?.authKind = 3
                case "missing-auth": bad.evidence?.admission?.authKind = nil
                case "missing-handle": bad.evidence?.admission?.handle = nil
                case "witness": bad.evidence?.admission?.writeOneAtZero = false
                case "missing-witness": bad.evidence?.admission?.writeOneAtZero = nil
                case "no-handle": bad.evidence?.admission?.noHandle = false
                case "mode": bad.query.original.binding.mode = "read-only"; bad.evidence?.admission?.original = bad.query.original
                case "epoch": bad.query.workerScope.serviceEpoch = other; bad.evidence?.serviceEpoch = other
                case "tuple": bad.evidence?.admission?.original.binding.attachment = id
                case "leaf": bad.evidence?.rejectedLeafSHA256 = String(repeating: "cd", count: 32)
                default: bad.query.caseName = .sameE
                }
                #expect(throws: (any Error).self) { try C.decodeStatus(JSONEncoder().encode(bad)) }
            }
        }
        for version: UInt32 in [0, 1, 2, 3, 4, 5, 6, 8] {
            var bad = observed; bad.query.version = version
            #expect(throws: (any Error).self) { try C.decodeStatus(JSONEncoder().encode(bad)) }
        }
    }
    @Test func writableCorrelationRejectsUnjoinedOperandsAndBaselineIdentity() throws {
        let (_, begun, probe, observed) = fixture(.sameERetainedFD)
        for fault in ["node", "handle", "sequence", "payload", "auth", "version", "tuple", "leaf", "boot", "request", "operation"] {
            var bad = observed
            switch fault {
            case "node": bad.evidence?.admission?.node = 11
            case "handle": bad.evidence?.admission?.handle = 11
            case "sequence": bad.evidence?.admission?.requestSequence = 8
            case "payload": bad.evidence?.admission?.writeOneAtZero = false
            case "auth": bad.evidence?.admission?.authKind = 3
            case "version": bad.query.version = 6
            case "tuple": bad.query.original.binding.attachment = id; bad.evidence?.admission?.original = bad.query.original
            case "leaf": bad.query.originalLeafSHA256 = String(repeating: "cd", count: 32); bad.evidence?.rejectedLeafSHA256 = bad.query.originalLeafSHA256
            case "boot": bad.query.originalBootBinding.guestBootNonce = id
            case "request": bad.query.requestID = other
            default: bad.query.operationUUID = id
            }
            #expect(throws: (any Error).self) { try G.validateSameE(probe, positive: begun, observed: bad) }
        }
        for fault in ["file-identity", "mount-identity", "key", "scope", "positive-node", "positive-sequence", "positive-write", "positive-sync",
                      "positive-root", "positive-incomplete", "negative-node", "negative-sequence", "negative-written", "negative-sync"] {
            var positive = begun, negative = probe
            switch fault {
            case "file-identity": positive.writable?.identitySHA256 = String(repeating: "cd", count: 32)
            case "mount-identity": positive.mountIdentitySHA256 = String(repeating: "cd", count: 32)
            case "key": positive.keySHA256 = String(repeating: "cd", count: 32)
            case "scope": positive.scope.controllerEpoch += 1
            case "positive-node": positive.writable?.trace?.write?.node = 11; positive.writable?.trace?.sync?.node = 11
            case "positive-sequence": positive.writable?.trace?.sync?.requestSequence = 7
            case "positive-write": positive.writable?.trace?.writeOK = false
            case "positive-sync": positive.writable?.trace?.sync = nil
            case "positive-root": positive.rootRequest = .init(node: 9, requestSequence: 4)
            case "positive-incomplete": positive.writable?.completed = false
            case "negative-node": negative.writable?.trace?.capability?.node = 11
            case "negative-sequence": negative.writable?.trace?.capability?.requestSequence = 8
            case "negative-written": negative.writable?.written = 1
            default: negative.writable?.trace?.sync = .init(node: 9, handle: 11, requestSequence: 8)
            }
            #expect(throws: (any Error).self) { try G.validateSameE(negative, positive: positive, observed: observed) }
        }
        var wrongScope = probe; wrongScope.scope.serviceEpoch = other
        #expect(throws: (any Error).self) { try G.validateSameE(wrongScope, positive: begun, observed: observed) }
    }
    @Test func workerFileAdmissionSchemaIsClosedAndLegacyCannotBorrowFields() throws {
        let observed = legacyWriteWorker()
        let object = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(observed)) as? [String: Any])
        let evidence = try #require(object["evidence"] as? [String: Any])
        let admission = try #require(evidence["admission"] as? [String: Any])
        #expect(Set(admission.keys) == ["original", "requestSequence", "operation", "node", "authKind", "handle", "writeOneAtZero"])
        for field in Array(admission.keys) + ["unknown"] {
            for null in [false, true] {
                var a = admission, e = evidence, bad = object
                if field == "unknown" { a[field] = 1 }
                else if null { a[field] = NSNull() }
                else { a.removeValue(forKey: field) }
                e["admission"] = a; bad["evidence"] = e
                #expect(throws: (any Error).self) { try C.decodeStatus(JSONSerialization.data(withJSONObject: bad)) }
            }
        }
        let text = String(decoding: try JSONEncoder().encode(observed), as: UTF8.self)
        for bad in [text.replacingOccurrences(of: "\"handle\":10", with: "\"handle\":10,\"handle\":10"),
                    text.replacingOccurrences(of: "\"handle\":10", with: "\"handle\":10.5"),
                    text.replacingOccurrences(of: "\"writeOneAtZero\":true", with: "\"writeOneAtZero\":1")] {
            #expect(throws: (any Error).self) { try C.decodeStatus(Data(bad.utf8)) }
        }
        for version: UInt32 in [3, 6] {
            var legacy = fixture(.sameEExistingData).3
            if version == 3 {
                legacy.query.version = 3
                legacy.evidence?.admission = .init(original: legacy.query.original, requestSequence: 7)
            }
            _ = try C.decodeStatus(JSONEncoder().encode(legacy))
            for field in ["handle", "writeOneAtZero"] {
                var bad = legacy
                if field == "handle" { bad.evidence?.admission?.handle = 0 }
                else { bad.evidence?.admission?.writeOneAtZero = false }
                #expect(throws: (any Error).self) { try C.decodeStatus(JSONEncoder().encode(bad)) }
            }
        }
    }
    @Test func workerV6RequiresActualOperandsAndV3RemainsExplicit() throws {
        let (_, _, _, observed) = fixture(.sameEExistingData)
        for fault in ["operation", "node", "auth", "handle", "missing", "version"] {
            var bad = observed
            switch fault {
            case "operation": bad.evidence?.admission?.operation = "fsync"
            case "node": bad.evidence?.admission?.node = 0
            case "auth": bad.evidence?.admission?.authKind = 1
            case "handle": bad.evidence?.admission?.noHandle = false
            case "missing": bad.evidence?.admission?.node = nil
            default: bad.query.version = 3
            }
            #expect(throws: (any Error).self) { try C.decodeStatus(JSONEncoder().encode(bad)) }
        }
        var legacy = observed; legacy.query.version = 3
        legacy.evidence?.admission = .init(original: legacy.query.original, requestSequence: 7)
        #expect(try C.decodeStatus(JSONEncoder().encode(legacy)) == legacy)
    }
    @Test(arguments: [G.Case.sameEExistingData, .sameEOldLeafReconnect, .attachmentKeyReuse, .delayedRegistration])
    func rootRequestAndWorkerDTOsAreClosed(_ name: G.Case) throws {
        let (owner, begun, probe, observed) = fixture(name)
        let text = String(decoding: try JSONEncoder().encode(probe), as: UTF8.self)
        for bad in [text.replacingOccurrences(of: "\"node\":9", with: "\"node\":9,\"node\":9"),
                    text.replacingOccurrences(of: "\"node\":9", with: "\"node\":null"),
                    text.replacingOccurrences(of: "\"node\":9", with: "\"node\":9,\"extra\":1"),
                    text.replacingOccurrences(of: "\"node\":9", with: "\"node\":0")] {
            #expect(throws: (any Error).self) { try G.checkedReply(Data(bad.utf8), request: request(owner, .probe), previous: begun) }
        }
        let worker = String(decoding: try JSONEncoder().encode(observed), as: UTF8.self)
        for prefix in ["\"extra\":1,", "\"failure\":null,", "\"selectedCount\":1,"] {
            #expect(throws: (any Error).self) { try C.decodeStatus(Data(("{" + prefix + worker.dropFirst()).utf8)) }
        }
    }
}

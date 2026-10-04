import Foundation
import Testing
@testable import CEngineCore

@Suite struct OriginalConsumerObservationReplyTests {
    typealias W = OriginalConsumerObservationProtocol
    private let id = "11111111-1111-4111-8111-111111111111"
    private let other = "22222222-2222-4222-8222-222222222222"
    private let hash = String(repeating: "ab", count: 32)
    private var binding: W.Binding {
        .init(requestID: id, armDigest: hash, operationUUID: other, caseName: .crossEOldLeafReconnect, generation: 7,
            boot: .init(shimLaunchUUID: id, guestBootNonce: other),
            scope: .init(intent: id, store: other, serviceEpoch: id, controllerEpoch: 1, controllerKey: hash,
                container: hash, containerInstance: other, launch: id, prepare: other, specificationDigest: hash),
            targetAttachment: other, key: hash, certificateSHA256: hash)
    }
    private var armed: W.Evidence {
        .init(arm: W.GuestArm(binding), stage: "armed-mounted-positive", scope: binding.scope,
            keySHA256: hash, mountIdentitySHA256: hash, serverDERSHA256: "", signCount: 0,
            signInputSHA256: "", bytesWrittenAfterSign: 0, clientWrittenBytes: 0,
            clientPrefixBytes: 0, clientPrefixSHA256: "", localError: "", fdOperation: "fsync-directory", fdSequence: 1)
    }
    private func request(_ command: W.Command, _ payload: Data? = nil) throws -> W.Request {
        .init(binding: binding, command: command, payload: try payload ?? JSONEncoder().encode(W.GuestArm(binding)))
    }
    @Test func exactArmAndBeginAreSanitizedAndCorrelated() throws {
        let first = armed
        let checked = try W.checkedReply(JSONEncoder().encode(first), request: request(.arm))
        #expect(checked.evidence == first)
        var begun = first; begun.stage = "begun"
        #expect(try W.checkedReply(JSONEncoder().encode(begun), request: request(.begin), previous: first).evidence == begun)
        begun.mountIdentitySHA256 = String(repeating: "cd", count: 32)
        #expect(throws: (any Error).self) {
            try W.checkedReply(JSONEncoder().encode(begun), request: request(.begin), previous: first)
        }
    }
    @Test func everyEvidenceFieldIsRequiredAndUnknownSecretFieldsAreRejected() throws {
        let bytes = try JSONEncoder().encode(armed)
        let object = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        for field in object.keys {
            var missing = object; missing.removeValue(forKey: field)
            #expect(throws: (any Error).self) {
                try W.validateReply(JSONSerialization.data(withJSONObject: missing), request: request(.arm))
            }
        }
        for field in ["privateKey", "ciphertext", "signature", "success"] {
            var secret = object; secret[field] = "not-exportable"
            #expect(throws: (any Error).self) {
                try W.validateReply(JSONSerialization.data(withJSONObject: secret), request: request(.arm))
            }
        }
    }
    @Test func duplicateAndUnicodeAliasFieldsAreRejected() throws {
        let text = String(decoding: try JSONEncoder().encode(armed), as: UTF8.self)
        let duplicate = text.dropLast() + ",\"stage\":\"armed-mounted-positive\"}"
        let alias = text.replacingOccurrences(of: "\"stage\":", with: "\"\\u0073tage\":")
        for invalid in [String(duplicate), alias, text.dropLast() + ",\"\\u0073tage\":\"armed-mounted-positive\"}"] {
            #expect(throws: (any Error).self) { try W.validateReply(Data(invalid.utf8), request: request(.arm)) }
        }
    }
    @Test func wrongStageAndContradictoryCountersDoNotPass() throws {
        var bad = armed; bad.stage = "original-owner-signed-flight"
        #expect(throws: (any Error).self) { try W.validateReply(JSONEncoder().encode(bad), request: request(.arm)) }
        bad = armed; bad.signCount = 1
        #expect(throws: (any Error).self) { try W.validateReply(JSONEncoder().encode(bad), request: request(.arm)) }
        bad = armed; bad.scope.containerInstance = id
        #expect(throws: (any Error).self) { try W.validateReply(JSONEncoder().encode(bad), request: request(.arm)) }
    }
    @Test func resultMustMatchExactPrefixAndPreviousFlight() throws {
        var flight = armed
        flight.stage = "original-owner-signed-flight"; flight.scope.serviceEpoch = other
        flight.serverDERSHA256 = hash; flight.signCount = 1; flight.signInputSHA256 = hash
        flight.bytesWrittenAfterSign = 200; flight.clientWrittenBytes = 400; flight.localError = "eof"
        let prefix = W.Prefix(arm: W.GuestArm(binding), serverPrefixBytes: 300, serverPrefixSHA256: hash)
        let query = try request(.result, JSONEncoder().encode(prefix))
        var result = flight; result.stage = "original-owner-prefix-correlated"
        result.clientPrefixBytes = 300; result.clientPrefixSHA256 = hash
        _ = try W.checkedReply(JSONEncoder().encode(result), request: query, previous: flight)
        result.clientPrefixBytes = 299
        #expect(throws: (any Error).self) { try W.checkedReply(JSONEncoder().encode(result), request: query, previous: flight) }
        result.clientPrefixBytes = 300; result.serverDERSHA256 = String(repeating: "cd", count: 32)
        #expect(throws: (any Error).self) { try W.checkedReply(JSONEncoder().encode(result), request: query, previous: flight) }
    }
    private func crossFlight(_ name: W.Case) -> (W.Binding, W.Evidence) {
        let owner = W.Binding(requestID: binding.requestID, armDigest: binding.armDigest,
            operationUUID: binding.operationUUID, caseName: name, generation: binding.generation,
            boot: binding.boot, scope: binding.scope, targetAttachment: binding.targetAttachment,
            key: binding.key, certificateSHA256: binding.certificateSHA256)
        var flight = armed
        flight.arm = W.GuestArm(owner); flight.stage = "original-owner-signed-flight"
        flight.scope.serviceEpoch = other
        flight.serverDERSHA256 = WorkloadStorageProtocol.specificationDigest(Data([1]))
        flight.signCount = 1; flight.signInputSHA256 = hash
        flight.bytesWrittenAfterSign = 200; flight.clientWrittenBytes = 400; flight.localError = "eof"
        if name == .crossEExistingData {
            flight.originalOperation = .init(kind: "data-getattr-root", sequence: 2, errorClass: "client-closed-joined")
        } else {
            flight.fdSequence = 2
            flight.fdOperation = "write-file-fsync"
            flight.originalOperation = .init(kind: "write-file-fsync", sequence: 2, errorClass: "mount-closed-joined")
            flight.writable = .init(identitySHA256: hash, written: 0, writeError: "eio", syncError: "enotconn", completed: true)
        }
        return (owner, flight)
    }
    private func crossPositive(_ owner: W.Binding, stage: String = "armed-mounted-positive") -> W.Evidence {
        var first = armed; first.arm = .init(owner); first.stage = stage
        if owner.caseName == .crossEExistingData {
            first.originalOperation = .init(kind: "data-getattr-root", sequence: 1, errorClass: "ok")
        } else if [.sameERetainedFD, .crossERetainedFD].contains(owner.caseName) {
            first.fdOperation = "write-file-fsync"
            first.originalOperation = .init(kind: "write-file-fsync", sequence: 1, errorClass: "ok")
            first.writable = .init(identitySHA256: hash, written: 1, writeError: "ok", syncError: "ok", completed: true,
                trace: .init(write: .init(node: 7, handle: 9, requestSequence: 11),
                    sync: .init(node: 7, handle: 9, requestSequence: 12), writeOK: true, syncOK: true))
        }
        return first
    }
    private func probeRequest(_ owner: W.Binding, flight: W.Evidence) throws -> W.Request {
        .init(binding: owner, command: .probe, payload: try JSONEncoder().encode(W.Probe(arm: .init(owner),
            scope: flight.scope, peer: .init(tlsRootDER: Data([2]), serverDER: Data([1]), serverKey: hash, dataAddress: "192.0.2.1:2049"))))
    }
    @Test(arguments: [W.Case.crossEExistingData, .crossERetainedFD])
    func crossERequiresOriginalOperationAndCorrelatedTLS(_ name: W.Case) throws {
        let (owner, flight) = crossFlight(name)
        var first = crossPositive(owner)
        #expect(owner.version == (name == .crossEExistingData ? 3 : 5))
        let armRequest = W.Request(binding: owner, command: .arm, payload: try JSONEncoder().encode(first.arm))
        _ = try W.checkedReply(JSONEncoder().encode(first), request: armRequest)
        var begun = first; begun.stage = "begun"
        _ = try W.checkedReply(JSONEncoder().encode(begun), request: .init(binding: owner, command: .begin,
            payload: JSONEncoder().encode(first.arm)), previous: first)
        _ = try W.checkedReply(JSONEncoder().encode(flight), request: probeRequest(owner, flight: flight), previous: begun)
        let query = W.Request(binding: owner, command: .result, payload: try JSONEncoder().encode(W.Prefix(
            arm: .init(owner), serverPrefixBytes: 300, serverPrefixSHA256: hash)))
        var result = flight; result.stage = "original-owner-prefix-correlated"
        result.clientPrefixBytes = 300; result.clientPrefixSHA256 = hash
        #expect(try W.checkedReply(JSONEncoder().encode(result), request: query, previous: flight).evidence == result)
        result.originalOperation.errorClass = name == .crossERetainedFD ? "estale" : "eof"
        #expect(throws: (any Error).self) { try W.checkedReply(JSONEncoder().encode(result), request: query, previous: flight) }
        first.originalOperation = flight.originalOperation
        #expect(throws: (any Error).self) { try W.checkedReply(JSONEncoder().encode(first), request: armRequest) }
    }
    @Test(arguments: [W.Case.crossEExistingData, .crossERetainedFD])
    func crossERejectsFakeOrCrossCaseNegatives(_ name: W.Case) throws {
        let (owner, flight) = crossFlight(name), otherName: W.Case = name == .crossEExistingData ? .crossERetainedFD : .crossEExistingData
        let query = try probeRequest(owner, flight: flight)
        for fault in ["missing-operation", "crosscase", "kind", "unjoined", "eof", "success", "sequence", "fd-sequence", "no-tls", "tls-error", "scope", "local-only", "binding"] {
            var bad = flight
            switch fault {
            case "missing-operation": bad.originalOperation = .init(kind: "", sequence: 0, errorClass: "")
            case "crosscase": bad.originalOperation = crossFlight(otherName).1.originalOperation
            case "kind": bad.originalOperation.kind = name == .crossEExistingData ? "fsync-directory" : "data-getattr-root"
            case "unjoined": bad.originalOperation.errorClass = "client-closed"
            case "eof": bad.originalOperation.errorClass = "eof"
            case "success": bad.originalOperation.errorClass = "success"
            case "sequence": bad.originalOperation.sequence = 0
            case "fd-sequence": bad.fdSequence = name == .crossERetainedFD ? 1 : 2
            case "no-tls": bad.signCount = 0; bad.signInputSHA256 = ""
            case "tls-error": bad.localError = "eio"
            case "scope": bad.scope.containerInstance = id
            case "local-only": bad.stage = "retained-fd-local-rejection"
            default: bad.arm = crossFlight(otherName).1.arm
            }
            #expect(throws: (any Error).self) { try W.checkedReply(JSONEncoder().encode(bad), request: query, previous: crossPositive(owner, stage: "begun")) }
        }
    }
    @Test(arguments: [W.Case.crossEExistingData, .crossERetainedFD])
    func crossEOriginalOperationSchemaIsClosed(_ name: W.Case) throws {
        let (owner, flight) = crossFlight(name), query = try probeRequest(owner, flight: flight)
        let object = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(flight)) as? [String: Any])
        let operation = try #require(object["originalOperation"] as? [String: Any])
        for field in ["kind", "sequence", "errorClass", "privateKey", "success"] {
            var badOperation = operation, bad = object
            if badOperation.removeValue(forKey: field) == nil { badOperation[field] = "forbidden" }
            bad["originalOperation"] = badOperation
            #expect(throws: (any Error).self) { try W.checkedReply(JSONSerialization.data(withJSONObject: bad), request: query, previous: crossPositive(owner, stage: "begun")) }
        }
        var missing = object; missing.removeValue(forKey: "originalOperation")
        #expect(throws: (any Error).self) { try W.checkedReply(JSONSerialization.data(withJSONObject: missing), request: query, previous: crossPositive(owner, stage: "begun")) }
        var null = object; null["originalOperation"] = NSNull()
        #expect(throws: (any Error).self) { try W.checkedReply(JSONSerialization.data(withJSONObject: null), request: query, previous: crossPositive(owner, stage: "begun")) }
        let text = String(decoding: try JSONEncoder().encode(flight), as: UTF8.self)
        for bad in [text.replacingOccurrences(of: "\"kind\":", with: "\"kind\":\"fake\",\"kind\":"),
                    text.replacingOccurrences(of: "\"kind\":", with: "\"\\u006bind\":")] {
            #expect(throws: (any Error).self) { try W.checkedReply(Data(bad.utf8), request: query, previous: crossPositive(owner, stage: "begun")) }
        }
    }
    private func crossEDataChain() throws -> [(request: W.Request, evidence: W.Evidence, previous: W.Evidence?)] {
        let (owner, flight) = crossFlight(.crossEExistingData)
        let first = crossPositive(owner), begun = crossPositive(owner, stage: "begun")
        let payload = try JSONEncoder().encode(W.GuestArm(owner))
        var result = flight; result.stage = "original-owner-prefix-correlated"
        result.clientPrefixBytes = 300; result.clientPrefixSHA256 = hash
        let prefix = W.Prefix(arm: .init(owner), serverPrefixBytes: 300, serverPrefixSHA256: hash)
        return [
            (.init(binding: owner, command: .arm, payload: payload), first, nil),
            (.init(binding: owner, command: .begin, payload: payload), begun, first),
            (try probeRequest(owner, flight: flight), flight, begun),
            (.init(binding: owner, command: .result, payload: try JSONEncoder().encode(prefix)), result, flight),
        ]
    }
    @Test func caseVersionsCannotBeDowngradedOrBorrowed() throws {
        for name in W.Case.allCases {
            let owner = crossFlight(name).0
            let expected: UInt32 = [.crossMountRootGrant, .retiredRootGrantReplay].contains(name) ? 6
                : name == .sameERetainedFD ? 7 : name == .crossERetainedFD ? 5
                : (name.isSameE ? 4 : (name == .crossEExistingData ? 3 : (name.isWrongHello ? 2 : 1)))
            #expect(owner.version == expected && W.GuestArm(owner).version == expected)
            try W.validate(owner)
            let object = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(owner)) as? [String: Any])
            for version in [UInt32(0), 1, 2, 3, 4, 5, 6, 7, 8] where version != expected {
                var changed = object; changed["version"] = version
                let decoded = try JSONDecoder().decode(W.Binding.self, from: JSONSerialization.data(withJSONObject: changed))
                #expect(throws: (any Error).self) { try W.validate(decoded) }
            }
        }
    }
    @Test func version3CompleteChainRequiresPositiveThenJoinedSameOperation() throws {
        let chain = try crossEDataChain()
        let armObject = try #require(JSONSerialization.jsonObject(with: chain[0].request.payload) as? [String: Any])
        #expect(Set(armObject.keys) == ["version", "profile", "requestID", "operationUUID", "caseName", "binding", "scope", "targetAttachment", "leafSHA256"])
        let probeObject = try #require(JSONSerialization.jsonObject(with: chain[2].request.payload) as? [String: Any])
        #expect(Set(probeObject.keys) == ["arm", "scope", "peer"])
        for step in chain {
            #expect(try W.checkedReply(JSONEncoder().encode(step.evidence), request: step.request, previous: step.previous).evidence == step.evidence)
            let positive = step.request.command == .arm || step.request.command == .begin
            #expect(step.evidence.fdOperation == "fsync-directory" && step.evidence.fdSequence == 1)
            #expect(step.evidence.originalOperation == .init(kind: "data-getattr-root", sequence: positive ? 1 : 2,
                errorClass: positive ? "ok" : "client-closed-joined"))
            for fault in ["empty", "old-sequence", "other-operation", "unjoined", "wrong-result", "missing", "version-downgrade"] {
                var bad = step.evidence
                switch fault {
                case "empty": bad.originalOperation = .init(kind: "", sequence: 0, errorClass: "")
                case "old-sequence": bad.originalOperation.sequence = positive ? 0 : 1
                case "other-operation": bad.originalOperation.kind = "fsync-directory"
                case "unjoined": bad.originalOperation.errorClass = "client-closed"
                case "wrong-result": bad.originalOperation.errorClass = positive ? "client-closed-joined" : "ok"
                default: break
                }
                var object = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(bad)) as? [String: Any])
                if fault == "missing" { object.removeValue(forKey: "originalOperation") }
                if fault == "version-downgrade" {
                    var arm = try #require(object["arm"] as? [String: Any]); arm["version"] = 1; object["arm"] = arm
                }
                #expect(throws: (any Error).self) {
                    try W.checkedReply(JSONSerialization.data(withJSONObject: object), request: step.request, previous: step.previous)
                }
            }
            if var previous = step.previous {
                #expect(throws: (any Error).self) { try W.checkedReply(JSONEncoder().encode(step.evidence), request: step.request) }
                previous.originalOperation = .init(kind: "", sequence: 0, errorClass: "")
                #expect(throws: (any Error).self) {
                    try W.checkedReply(JSONEncoder().encode(step.evidence), request: step.request, previous: previous)
                }
            }
        }
    }
    @Test func legacyFSYNCOnlyDataChainCannotSubstituteForVersion3() throws {
        for step in try crossEDataChain() {
            var bindingObject = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(step.request.binding)) as? [String: Any])
            bindingObject["version"] = 1
            let old = try JSONDecoder().decode(W.Binding.self, from: JSONSerialization.data(withJSONObject: bindingObject))
            var payload = try #require(JSONSerialization.jsonObject(with: step.request.payload) as? [String: Any])
            if step.request.command == .arm || step.request.command == .begin {
                payload["version"] = 1
            } else {
                var arm = try #require(payload["arm"] as? [String: Any]); arm["version"] = 1; payload["arm"] = arm
            }
            let oldRequest = W.Request(binding: old, command: step.request.command, payload: try JSONSerialization.data(withJSONObject: payload))
            var evidence = step.evidence; evidence.arm = .init(old)
            evidence.originalOperation = step.request.command == .arm || step.request.command == .begin
                ? .init(kind: "", sequence: 0, errorClass: "")
                : .init(kind: "data-getattr-root", sequence: 1, errorClass: "client-closed-joined")
            var previous = step.previous; previous?.arm = .init(old)
            #expect(throws: (any Error).self) { try W.validate(oldRequest) }
            #expect(throws: (any Error).self) {
                try W.checkedReply(JSONEncoder().encode(evidence), request: oldRequest, previous: previous)
            }
        }
    }
    @Test func oldLeafCannotBorrowOriginalDataOrFDEvidence() throws {
        var flight = armed; flight.stage = "original-owner-signed-flight"; flight.scope.serviceEpoch = other
        flight.serverDERSHA256 = WorkloadStorageProtocol.specificationDigest(Data([1]))
        flight.signCount = 1; flight.signInputSHA256 = hash; flight.bytesWrittenAfterSign = 200
        flight.clientWrittenBytes = 400; flight.localError = "eof"
        let query = try probeRequest(binding, flight: flight)
        _ = try W.checkedReply(JSONEncoder().encode(flight), request: query)
        for name in [W.Case.crossEExistingData, .crossERetainedFD] {
            flight.originalOperation = crossFlight(name).1.originalOperation
            #expect(throws: (any Error).self) { try W.checkedReply(JSONEncoder().encode(flight), request: query) }
            var first = armed; first.originalOperation = flight.originalOperation
            #expect(throws: (any Error).self) { try W.checkedReply(JSONEncoder().encode(first), request: request(.arm)) }
        }
    }
    @Test(arguments: [W.Case.wrongVolume, .wrongKey, .wrongRole, .wrongMode, .wrongEpoch])
    func wrongHelloStaysOnCurrentScopeAndResultCannotChangeFlight(_ name: W.Case) throws {
        let owner = W.Binding(requestID: binding.requestID, armDigest: binding.armDigest,
            operationUUID: binding.operationUUID, caseName: name, generation: binding.generation,
            boot: binding.boot, scope: binding.scope, targetAttachment: binding.targetAttachment,
            key: binding.key, certificateSHA256: binding.certificateSHA256)
        #expect(owner.version == 2)
        var first = armed; first.arm = .init(owner)
        var begun = first; begun.stage = "begun"
        _ = try W.checkedReply(JSONEncoder().encode(first), request: .init(binding: owner, command: .arm,
            payload: JSONEncoder().encode(first.arm)))
        _ = try W.checkedReply(JSONEncoder().encode(begun), request: .init(binding: owner, command: .begin,
            payload: JSONEncoder().encode(first.arm)), previous: first)
        var flight = begun; flight.stage = "original-owner-signed-flight"
        flight.serverDERSHA256 = WorkloadStorageProtocol.specificationDigest(Data([1]))
        flight.signCount = 1; flight.signInputSHA256 = hash; flight.bytesWrittenAfterSign = 200
        flight.clientWrittenBytes = 400; flight.localError = "eof"
        flight.originalOperation = .init(kind: "data-wrong-hello", sequence: 1, errorClass: "peer-closed-before-root")
        var hello = ConsumerObservationProtocol.Original(epoch: owner.scope.serviceEpoch,
            binding: .init(store: owner.scope.store, volume: id, attachment: owner.targetAttachment,
                container: owner.scope.container, launch: owner.scope.launch, key: hash, mode: "read-write"))
        switch name {
        case .wrongVolume: hello.binding.volume = other
        case .wrongKey: hello.binding.key = String(repeating: "cd", count: 32)
        case .wrongRole: hello.binding.role = "prepare"; hello.binding.prepare = owner.scope.prepare
        case .wrongMode: hello.binding.mode = "read-write"
        case .wrongEpoch: hello.epoch = other
        default: Issue.record("unexpected case")
        }
        flight.hello = hello
        let probe = try probeRequest(owner, flight: flight)
        let probeObject = try #require(JSONSerialization.jsonObject(with: probe.payload) as? [String: Any])
        #expect(Set(probeObject.keys) == ["arm", "scope", "peer"])
        _ = try W.checkedReply(JSONEncoder().encode(flight), request: probe, previous: begun)
        var injected = probeObject; injected["hello"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(hello))
        #expect(throws: (any Error).self) {
            try W.validate(.init(binding: owner, command: .probe, payload: JSONSerialization.data(withJSONObject: injected)))
        }
        var wrongScope = flight; wrongScope.scope.serviceEpoch = other
        #expect(throws: (any Error).self) {
            try W.checkedReply(JSONEncoder().encode(wrongScope), request: probeRequest(owner, flight: wrongScope), previous: begun)
        }
        var result = flight; result.stage = "original-owner-prefix-correlated"
        result.clientPrefixBytes = 300; result.clientPrefixSHA256 = hash
        let query = W.Request(binding: owner, command: .result, payload: try JSONEncoder().encode(W.Prefix(
            arm: .init(owner), serverPrefixBytes: 300, serverPrefixSHA256: hash)))
        _ = try W.checkedReply(JSONEncoder().encode(result), request: query, previous: flight)
        result.hello?.binding.key = String(repeating: "ef", count: 32)
        #expect(throws: (any Error).self) { try W.checkedReply(JSONEncoder().encode(result), request: query, previous: flight) }
        flight.hello = nil
        #expect(throws: (any Error).self) { try W.checkedReply(JSONEncoder().encode(flight), request: probe, previous: begun) }
    }

    private func writableChain(_ name: W.Case) throws -> [(request: W.Request, evidence: W.Evidence, previous: W.Evidence?)] {
        let (owner, cross) = crossFlight(name)
        let first = crossPositive(owner), begun = crossPositive(owner, stage: "begun")
        let payload = try JSONEncoder().encode(first.arm)
        var flight = cross
        if name == .sameERetainedFD {
            flight = begun; flight.stage = "original-file-attempt"
            flight.serverDERSHA256 = cross.serverDERSHA256; flight.fdSequence = 2
            flight.originalOperation = .init(kind: "write-file-fsync", sequence: 2, errorClass: "transport-failed")
            flight.writable = .init(identitySHA256: hash, written: 0, writeError: "eio", syncError: "estale", completed: true,
                trace: .init(capability: .init(node: 7, requestSequence: 13), writeOK: false, syncOK: false))
        }
        var chain: [(request: W.Request, evidence: W.Evidence, previous: W.Evidence?)] = [
            (.init(binding: owner, command: .arm, payload: payload), first, nil),
            (.init(binding: owner, command: .begin, payload: payload), begun, first),
            (try probeRequest(owner, flight: flight), flight, begun),
        ]
        if name == .crossERetainedFD {
            var result = flight; result.stage = "original-owner-prefix-correlated"
            result.clientPrefixBytes = 300; result.clientPrefixSHA256 = hash
            let prefix = W.Prefix(arm: .init(owner), serverPrefixBytes: 300, serverPrefixSHA256: hash)
            chain.append((.init(binding: owner, command: .result, payload: try JSONEncoder().encode(prefix)), result, flight))
        }
        return chain
    }
    @Test(arguments: [W.Case.sameERetainedFD, .crossERetainedFD])
    func versionedWritableChainIsStrictAndContinuous(_ name: W.Case) throws {
        for step in try writableChain(name) {
            #expect(step.evidence.arm.version == (name == .sameERetainedFD ? 7 : 5))
            #expect(try W.checkedReply(JSONEncoder().encode(step.evidence), request: step.request,
                previous: step.previous).evidence == step.evidence)
            let positive = step.request.command == .arm || step.request.command == .begin
            for fault in ["missing", "identity", "written", "write-error", "sync-error", "incomplete", "fd-operation",
                          "fd-sequence", "operation-kind", "operation-sequence", "operation-error", "root", "stage"] {
                var bad = step.evidence
                switch fault {
                case "missing": bad.writable = nil
                case "identity": bad.writable?.identitySHA256 = "invalid"
                case "written": bad.writable?.written = positive ? 0 : 1
                case "write-error": bad.writable?.writeError = positive ? "eio" : "ok"
                case "sync-error": bad.writable?.syncError = positive ? "eio" : "timeout"
                case "incomplete": bad.writable?.completed = false
                case "fd-operation": bad.fdOperation = "fsync-directory"
                case "fd-sequence": bad.fdSequence = positive ? 2 : 1
                case "operation-kind": bad.originalOperation.kind = "fsync-directory"
                case "operation-sequence": bad.originalOperation.sequence = positive ? 2 : 1
                case "operation-error": bad.originalOperation.errorClass = positive ? "transport-failed" : "eio"
                case "root": bad.rootRequest = .init(node: 7, requestSequence: 13)
                default: bad.stage = "retained-fd-local-rejection"
                }
                #expect(throws: (any Error).self) {
                    try W.checkedReply(JSONEncoder().encode(bad), request: step.request, previous: step.previous)
                }
            }
            if var prior = step.previous {
                #expect(throws: (any Error).self) { try W.checkedReply(JSONEncoder().encode(step.evidence), request: step.request) }
                prior.writable?.identitySHA256 = String(repeating: "cd", count: 32)
                #expect(throws: (any Error).self) {
                    try W.checkedReply(JSONEncoder().encode(step.evidence), request: step.request, previous: prior)
                }
                prior = try #require(step.previous); prior.stage = "released"
                #expect(throws: (any Error).self) {
                    try W.checkedReply(JSONEncoder().encode(step.evidence), request: step.request, previous: prior)
                }
            }
        }
    }
    @Test(arguments: [W.Case.sameERetainedFD, .crossERetainedFD])
    func writablePositiveRequiresRealOrderedOperands(_ name: W.Case) throws {
        let step = try writableChain(name)[0]
        for fault in ["trace", "write", "sync", "node", "handle", "sequence", "sync-node", "sync-handle", "sync-sequence", "write-ok", "sync-ok",
                      "signature", "prefix", "local-error"] {
            var bad = step.evidence
            switch fault {
            case "trace": bad.writable?.trace = nil
            case "write": bad.writable?.trace?.write = nil
            case "sync": bad.writable?.trace?.sync = nil
            case "node": bad.writable?.trace?.write?.node = 0
            case "handle": bad.writable?.trace?.write?.handle = 0
            case "sequence": bad.writable?.trace?.write?.requestSequence = 0
            case "sync-node": bad.writable?.trace?.sync?.node = 8
            case "sync-handle": bad.writable?.trace?.sync?.handle = 10
            case "sync-sequence": bad.writable?.trace?.sync?.requestSequence = 11
            case "write-ok": bad.writable?.trace?.writeOK = false
            case "sync-ok": bad.writable?.trace?.syncOK = false
            case "signature": bad.signCount = 1
            case "prefix": bad.clientPrefixBytes = 1
            default: bad.localError = "eio"
            }
            #expect(throws: (any Error).self) { try W.checkedReply(JSONEncoder().encode(bad), request: step.request) }
        }
    }
    @Test func sameEWritableTraceIsLocalOnlyAndCannotUseResult() throws {
        let step = try writableChain(.sameERetainedFD)[2]
        for error in ["eio", "enotconn", "estale", "eacces"] {
            var valid = step.evidence
            valid.writable?.writeError = error; valid.writable?.syncError = error
            _ = try W.checkedReply(JSONEncoder().encode(valid), request: step.request, previous: step.previous)
        }
        for fault in ["trace", "capability", "node", "write", "sequence", "write-ok", "sync-ok", "sync-node", "sync-handle", "sync-sequence",
                      "signature", "prefix", "local-error", "scope"] {
            var bad = step.evidence
            switch fault {
            case "trace": bad.writable?.trace = nil
            case "capability": bad.writable?.trace?.capability = nil
            case "node": bad.writable?.trace?.capability?.node = 8
            case "write": bad.writable?.trace?.write = .init(node: 7, handle: 9, requestSequence: 13)
            case "sequence": bad.writable?.trace?.capability?.requestSequence = 12
            case "write-ok": bad.writable?.trace?.writeOK = true
            case "sync-ok": bad.writable?.trace?.syncOK = true
            case "sync-node": bad.writable?.trace?.sync = .init(node: 8, handle: 9, requestSequence: 14)
            case "sync-handle": bad.writable?.trace?.sync = .init(node: 7, handle: 10, requestSequence: 14)
            case "sync-sequence": bad.writable?.trace?.sync = .init(node: 7, handle: 9, requestSequence: 13)
            case "signature": bad.signCount = 1
            case "prefix": bad.clientPrefixBytes = 1
            case "local-error": bad.localError = "eio"
            default: bad.scope.serviceEpoch = other
            }
            #expect(throws: (any Error).self) {
                try W.checkedReply(JSONEncoder().encode(bad), request: step.request, previous: step.previous)
            }
        }
        let prefix = W.Prefix(arm: step.evidence.arm, serverPrefixBytes: 300, serverPrefixSHA256: hash)
        #expect(throws: (any Error).self) {
            try W.validate(.init(binding: step.request.binding, command: .result, payload: JSONEncoder().encode(prefix)))
        }
        // Current-worker correlation still requires a separate sealed worker observation.
        #expect(W.Case.sameERetainedFD.isSameE)
    }
    @Test func crossEWritableCannotFabricateWireTraceAfterJoin() throws {
        let chain = try writableChain(.crossERetainedFD)
        for step in chain.suffix(2) {
            var bad = step.evidence
            bad.writable?.trace = .init(write: .init(node: 7, handle: 9, requestSequence: 13), writeOK: false, syncOK: false)
            #expect(throws: (any Error).self) {
                try W.checkedReply(JSONEncoder().encode(bad), request: step.request, previous: step.previous)
            }
            bad.writable?.trace = .init(writeOK: false, syncOK: false)
            #expect(throws: (any Error).self) {
                try W.checkedReply(JSONEncoder().encode(bad), request: step.request, previous: step.previous)
            }
        }
    }
    @Test func writableSchemaRejectsUnknownMissingNullAndLegacyFields() throws {
        let step = try writableChain(.sameERetainedFD)[0]
        let object = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(step.evidence)) as? [String: Any])
        let writable = try #require(object["writable"] as? [String: Any])
        let trace = try #require(writable["trace"] as? [String: Any])
        let write = try #require(trace["write"] as? [String: Any])
        #expect(Set(writable.keys) == ["identitySHA256", "written", "writeError", "syncError", "completed", "trace"])
        #expect(Set(trace.keys) == ["write", "sync", "writeOK", "syncOK"])
        #expect(Set(write.keys) == ["node", "handle", "requestSequence"])
        for depth in 0...3 {
            let nested = [object, writable, trace, write][depth]
            let keys = depth == 0 ? ["writable"] : Array(nested.keys)
            for field in keys + ["unknown"] {
                for null in [false, true] {
                    var changed = nested
                    if field == "unknown" { changed[field] = "forbidden" }
                    else if null { changed[field] = NSNull() }
                    else { changed.removeValue(forKey: field) }
                    var bad = object, w = writable, t = trace
                    switch depth {
                    case 0: bad = changed
                    case 1: bad["writable"] = changed
                    case 2: w["trace"] = changed; bad["writable"] = w
                    default: t["write"] = changed; w["trace"] = t; bad["writable"] = w
                    }
                    #expect(throws: (any Error).self) {
                        try W.checkedReply(JSONSerialization.data(withJSONObject: bad), request: step.request)
                    }
                }
            }
        }
        for name in [W.Case.crossEOldLeafReconnect, .wrongVolume, .crossEExistingData, .sameEExistingData] {
            let owner = crossFlight(name).0
            var legacy = crossPositive(owner)
            if name == .sameEExistingData {
                legacy.originalOperation = .init(kind: "data-getattr-root", sequence: 1, errorClass: "ok")
                legacy.rootRequest = .init(node: 7, requestSequence: 11)
            }
            let query = W.Request(binding: owner, command: .arm, payload: try JSONEncoder().encode(legacy.arm))
            let legacyObject = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(legacy)) as? [String: Any])
            #expect(legacyObject["writable"] == nil)
            _ = try W.checkedReply(JSONEncoder().encode(legacy), request: query)
            for injected in [writable as Any, NSNull()] {
                var bad = legacyObject; bad["writable"] = injected
                #expect(throws: (any Error).self) { try W.checkedReply(JSONSerialization.data(withJSONObject: bad), request: query) }
            }
        }
        for name in [W.Case.sameERetainedFD, .crossERetainedFD] {
            let old = try writableChain(name)[0]
            var legacy = old.evidence; legacy.writable = nil; legacy.fdOperation = "fsync-directory"
            legacy.originalOperation = .init(kind: "", sequence: 0, errorClass: "")
            #expect(throws: (any Error).self) { try W.checkedReply(JSONEncoder().encode(legacy), request: old.request) }
        }
    }

    @Test func releaseCannotCarryEvidenceOrSecrets() throws {
        let object: [String: Any] = ["arm": try JSONSerialization.jsonObject(with: JSONEncoder().encode(W.GuestArm(binding))), "stage": "released"]
        _ = try W.checkedReply(JSONSerialization.data(withJSONObject: object), request: request(.release))
        var bad = object; bad["ciphertext"] = "secret"
        #expect(throws: (any Error).self) { try W.checkedReply(JSONSerialization.data(withJSONObject: bad), request: request(.release)) }
    }
}

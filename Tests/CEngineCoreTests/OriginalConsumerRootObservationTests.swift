import Foundation
import Testing
@testable import CEngineCore

@Suite struct OriginalConsumerRootObservationTests {
    typealias G = OriginalConsumerObservationProtocol
    typealias C = ConsumerObservationProtocol
    let id = "11111111-1111-4111-8111-111111111111"
    let other = "22222222-2222-4222-8222-222222222222"
    let third = "33333333-3333-4333-8333-333333333333"
    let fourth = "44444444-4444-4444-8444-444444444444"
    let hash = String(repeating: "ab", count: 32)
    let different = String(repeating: "cd", count: 32)

    func fixture(_ name: G.Case) throws -> (G.Binding, G.Evidence, G.Evidence, G.Evidence, C.Status) {
        let owner = G.Binding(requestID: id, armDigest: hash, operationUUID: other, caseName: name, generation: 7,
            boot: .init(shimLaunchUUID: id, guestBootNonce: other),
            scope: .init(intent: id, store: other, serviceEpoch: id, controllerEpoch: 1, controllerKey: hash,
                container: hash, containerInstance: other, launch: id, prepare: other, specificationDigest: hash),
            targetAttachment: other, key: hash, certificateSHA256: hash)
        let source = C.Original(epoch: id, binding: .init(store: other, volume: id, attachment: other,
            container: hash, launch: id, key: hash, mode: "read-only"))
        let target = C.Original(epoch: id, binding: .init(store: other, volume: fourth, attachment: third,
            container: hash, launch: id, key: different, mode: "read-only"))
        let roots = G.Roots(source: .init(identitySHA256: hash, leafSHA256: hash,
            rootRequest: .init(node: 1, requestSequence: 1),
            read: .init(authority: source, rootNode: 1, node: 2, handle: 3, requestSequence: 5,
                size: 4096, ioFlags: 0x48800, contentSHA256: hash)),
            target: .init(identitySHA256: different, leafSHA256: different,
                rootRequest: .init(node: 1, requestSequence: 1),
                read: .init(authority: target, rootNode: 1, node: 2, handle: 3, requestSequence: 5,
                    size: 4096, ioFlags: 0x48800, contentSHA256: different)))
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let digest = WorkloadStorageProtocol.specificationDigest(try encoder.encode(["Source": hash, "Target": different]))
        let armed = G.Evidence(arm: .init(owner), stage: "armed-mounted-positive", scope: owner.scope,
            keySHA256: hash, mountIdentitySHA256: digest, serverDERSHA256: "", signCount: 0,
            signInputSHA256: "", bytesWrittenAfterSign: 0, clientWrittenBytes: 0,
            clientPrefixBytes: 0, clientPrefixSHA256: "", localError: "", fdOperation: "read-file-root-grant", fdSequence: 1,
            originalOperation: .init(kind: "read-file-root-grant", sequence: 1, errorClass: "ok"),
            rootRequest: roots.source.rootRequest, roots: roots)
        var begun = armed; begun.stage = "begun"
        var probe = begun; probe.stage = "original-root-scope-replay"; probe.fdSequence = 2
        probe.serverDERSHA256 = WorkloadStorageProtocol.specificationDigest(Data([1]))
        probe.rootRequest = .init(node: 1, requestSequence: 6)
        probe.originalOperation = .init(kind: "read-file-root-grant", sequence: 2,
            errorClass: name == .retiredRootGrantReplay ? "transport-failed" : "ok")
        probe.roots?.replay = .init(source: source, target: target, rootNode: 1, rootSequence: 6,
            node: 2, handle: 3, readSequence: 7, contentSHA256: different)
        let arm = C.Arm(requestID: id, armDigest: hash, operationUUID: other, caseName: .sameE,
            originalBootBinding: owner.boot, original: source, originalLeafSHA256: hash,
            workerScope: .init(storeUUID: other, serviceEpoch: id, workerUUID: third))
        let observed = C.Status(query: arm, state: .observed, selectedCount: 1,
            evidence: .init(stage: "request-admit", errorClass: "blocked", storeUUID: other, serviceEpoch: id,
                rejectedLeafSHA256: hash, admission: .init(original: source, requestSequence: 6,
                    operation: "get_attr", node: 1, authKind: 3, noHandle: true)))
        return (owner, armed, begun, probe, observed)
    }
    func request(_ owner: G.Binding, _ command: G.Command) throws -> G.Request {
        let payload: Data
        if command == .probe {
            payload = try JSONEncoder().encode(G.Probe(arm: .init(owner), scope: owner.scope,
                peer: .init(tlsRootDER: Data([2]), serverDER: Data([1]), serverKey: hash, dataAddress: "192.0.2.1:2049")))
        } else if command == .result {
            payload = try JSONEncoder().encode(G.Prefix(arm: .init(owner), serverPrefixBytes: 1, serverPrefixSHA256: hash))
        } else { payload = try JSONEncoder().encode(G.GuestArm(owner)) }
        return .init(binding: owner, command: command, payload: payload)
    }

    @Test(arguments: [G.Case.crossMountRootGrant, .retiredRootGrantReplay])
    func closedV6ChainKeepsLegitimateBCollisions(_ name: G.Case) throws {
        let (owner, armed, begun, probe, _) = try fixture(name)
        #expect(owner.version == 6 && owner.caseName.isRoot && !owner.caseName.isSameE)
        #expect(try G.checkedReply(JSONEncoder().encode(armed), request: request(owner, .arm)).evidence == armed)
        #expect(try G.checkedReply(JSONEncoder().encode(begun), request: request(owner, .begin), previous: armed).evidence == begun)
        #expect(try G.checkedReply(JSONEncoder().encode(probe), request: request(owner, .probe), previous: begun).evidence == probe)
        #expect(throws: (any Error).self) { try G.checkedReply(JSONEncoder().encode(begun), request: request(owner, .begin)) }
        #expect(throws: (any Error).self) { try G.checkedReply(JSONEncoder().encode(probe), request: request(owner, .probe)) }
        #expect(throws: (any Error).self) { try G.validate(request(owner, .result)) }
        let released = try JSONSerialization.data(withJSONObject: ["arm": JSONSerialization.jsonObject(with: JSONEncoder().encode(armed.arm)), "stage": "released"])
        #expect(try G.checkedReply(released, request: request(owner, .release)).evidence == nil)
    }

    @Test(arguments: [G.Case.crossMountRootGrant, .retiredRootGrantReplay])
    func scopeReplayAndFalseDenialNegatives(_ name: G.Case) throws {
        let (owner, _, begun, probe, _) = try fixture(name)
        let faults = ["source-content", "source-volume", "source-key", "target-volume", "target-key", "target-leaf", "target-identity", "target-attachment", "target-launch", "target-role", "target-prepare", "target-mode", "target-E", "source-root", "target-root", "node", "handle", "read-sequence", "root-sequence", "source-sequence", "read-flags", "write-flags", "size", "short-size", "mount", "scope", "signature", "prefix", "server", "stage", "operation", "fd", "roots", "replay", "positive-replay", "overflow", "foreign-binding"]
        for fault in faults {
            var bad = probe
            switch fault {
            case "source-content": bad.roots?.replay?.contentSHA256 = hash
            case "source-volume": bad.roots?.source.read.authority.binding.volume = third
            case "source-key": bad.roots?.source.read.authority.binding.key = different
            case "target-volume": bad.roots?.target.read.authority.binding.volume = id
            case "target-key": bad.roots?.target.read.authority.binding.key = hash
            case "target-leaf": bad.roots?.target.leafSHA256 = hash
            case "target-identity": bad.roots?.target.identitySHA256 = hash
            case "target-attachment": bad.roots?.target.read.authority.binding.attachment = other
            case "target-launch": bad.roots?.target.read.authority.binding.launch = other
            case "target-role": bad.roots?.target.read.authority.binding.role = "prepare"
            case "target-prepare": bad.roots?.target.read.authority.binding.prepare = other
            case "target-mode": bad.roots?.target.read.authority.binding.mode = "unknown"
            case "target-E": bad.roots?.target.read.authority.epoch = other
            case "source-root": bad.rootRequest?.node = 2
            case "target-root": bad.roots?.replay?.rootNode = 2
            case "node": bad.roots?.replay?.node = 1
            case "handle": bad.roots?.replay?.handle = 4
            case "read-sequence": bad.roots?.replay?.readSequence = 8
            case "root-sequence": bad.roots?.replay?.rootSequence = 7
            case "source-sequence": bad.rootRequest?.requestSequence = 5
            case "read-flags": bad.roots?.target.read.ioFlags = 0
            case "write-flags": bad.roots?.source.read.ioFlags |= 2; bad.roots?.target.read.ioFlags |= 2
            case "size": bad.roots?.target.read.size = 32
            case "short-size": bad.roots?.source.read.size = 31; bad.roots?.target.read.size = 31
            case "mount": bad.mountIdentitySHA256 = hash
            case "scope": bad.scope.controllerEpoch += 1
            case "signature": bad.signCount = 1
            case "prefix": bad.clientPrefixBytes = 1
            case "server": bad.serverDERSHA256 = hash
            case "stage": bad.stage = "original-data-attempt"
            case "operation": bad.originalOperation.errorClass = name == .retiredRootGrantReplay ? "ok" : "blocked"
            case "fd": bad.fdOperation = "fsync-directory"
            case "roots": bad.roots = nil
            case "replay": bad.roots?.replay = nil
            case "positive-replay": bad.roots?.replay = begun.roots?.replay
            case "overflow": bad.roots?.target.read.requestSequence = UInt64.max
            default: bad.arm = .init(try fixture(name == .retiredRootGrantReplay ? .crossMountRootGrant : .retiredRootGrantReplay).0)
            }
            #expect(throws: (any Error).self, Comment(rawValue: fault)) {
                try G.checkedReply(JSONEncoder().encode(bad), request: request(owner, .probe), previous: begun)
            }
        }
    }

    @Test func retiredProbeNeedsExactIndependentAdmitCorrelation() throws {
        let (owner, _, begun, probe, observed) = try fixture(.retiredRootGrantReplay)
        let query = try request(owner, .probe), worker = observed.query.workerScope
        try G.validateRetiredRootAdmission(probe, positive: begun, request: query, observed: observed, worker: worker)
        for fault in ["arm", "operation-id", "boot", "leaf", "worker", "volume", "mode", "node", "sequence", "auth", "operation", "handle", "state", "error", "stage", "missing"] {
            var bad = observed
            switch fault {
            case "arm": bad.query.armDigest = different
            case "operation-id": bad.query.operationUUID = third
            case "boot": bad.query.originalBootBinding.guestBootNonce = third
            case "leaf": bad.query.originalLeafSHA256 = different; bad.evidence?.rejectedLeafSHA256 = different
            case "worker": bad.query.workerScope.workerUUID = fourth
            case "volume": bad.query.original.binding.volume = third; bad.evidence?.admission?.original = bad.query.original
            case "mode": bad.query.original.binding.mode = "read-write"; bad.evidence?.admission?.original = bad.query.original
            case "node": bad.evidence?.admission?.node = 2
            case "sequence": bad.evidence?.admission?.requestSequence = 7
            case "auth": bad.evidence?.admission?.authKind = 1
            case "operation": bad.evidence?.admission?.operation = "read"
            case "handle": bad.evidence?.admission?.handle = 3
            case "state": bad.state = .finalized
            case "error": bad.evidence?.errorClass = "unauthorized"
            case "stage": bad.evidence?.stage = "authenticate-data"
            default: bad.evidence?.admission = nil
            }
            #expect(throws: (any Error).self, Comment(rawValue: fault)) {
                try G.validateRetiredRootAdmission(probe, positive: begun, request: query, observed: bad, worker: worker)
            }
        }
        let (cross, _, crossBegun, crossProbe, _) = try fixture(.crossMountRootGrant)
        #expect(throws: (any Error).self) {
            try G.validateRetiredRootAdmission(crossProbe, positive: crossBegun, request: request(cross, .probe), observed: observed, worker: worker)
        }
    }

    @Test func exhaustiveRequiredFieldsRejectMissingNullUnknownAndNumericAliases() throws {
        let (owner, armed, begun, probe, _) = try fixture(.retiredRootGrantReplay)
        for (value, command, prior) in [(armed, G.Command.arm, Optional<G.Evidence>.none), (probe, .probe, Optional(begun))] {
            let query = try request(owner, command)
            let object = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as? [String: Any])
            func walk(_ object: [String: Any], path: [String]) throws {
                func replace(_ value: Any, at keys: ArraySlice<String>, in current: [String: Any]) -> [String: Any] {
                    guard let first = keys.first else { return value as! [String: Any] }
                    var out = current
                    out[first] = replace(value, at: keys.dropFirst(), in: current[first] as! [String: Any])
                    return out
                }
                var unknown = object; unknown["unrecognized"] = true
                var variants = [unknown]
                for key in object.keys {
                    var missing = object; missing.removeValue(forKey: key); variants.append(missing)
                    var null = object; null[key] = NSNull(); variants.append(null)
                }
                for mutation in variants {
                    let bad = replace(mutation, at: path[...], in: objectRoot)
                    #expect(throws: (any Error).self) {
                        try G.checkedReply(JSONSerialization.data(withJSONObject: bad), request: query, previous: prior)
                    }
                }
                for (key, value) in object { if let nested = value as? [String: Any] { try walk(nested, path: path + [key]) } }
            }
            let objectRoot = object
            try walk(object, path: [])
            let text = String(decoding: try JSONEncoder().encode(value), as: UTF8.self)
            for needle in ["\"version\":6", "\"fdSequence\":\(value.fdSequence)", "\"size\":4096", "\"ioFlags\":296960"] {
                #expect(text.contains(needle))
                for suffix in [".0", "e0"] {
                    let bad = text.replacingOccurrences(of: needle, with: needle + suffix)
                    #expect(throws: (any Error).self) { try G.checkedReply(Data(bad.utf8), request: query, previous: prior) }
                }
            }
        }
    }
}

import CEngineCore
import CryptoKit
import Darwin
import Foundation
import Testing
@testable import LifecycleChildRuntime

extension LifecycleChildSocketTests {
    private func replayValues() throws -> (Child.PublicTakeoverReplayRequest, Child.PublicTakeoverReplayObservation) {
        typealias L = Child.Lifecycle
        let root = Curve25519.Signing.PrivateKey()
        let identity = try L.Identity(store: "11111111-1111-4111-8111-111111111111", generation: 9007199254740993, binding: String(repeating: "b", count: 64))
        let old = try L.Grant(operation: .takeover, id: "22222222-2222-4222-8222-222222222222", identity: identity, serial: 9007199254740993, expectedEpoch: 1, newKey: String(repeating: "c", count: 64))
        let pending = try L.Grant(operation: .takeover, id: "33333333-3333-4333-8333-333333333333", identity: identity, serial: old.serial + 1, expectedEpoch: 2, newKey: String(repeating: "d", count: 64))
        let signed = try L.SignedGrant(grant: old, signature: root.signature(for: old.signingBytes))
        let request = try Child.PublicTakeoverReplayRequest(requestID: identity.store, old: signed)
        let observation = Child.PublicTakeoverReplayObservation(version: 1, requestID: request.requestID, old: signed, pending: try .init(grant: pending, signature: root.signature(for: pending.signingBytes)), incarnationID: identity.store, error: "UNAUTHORIZED")
        return (request, observation)
    }
    @Test func publicReplayExactPrivateEnvelopeAndNormalTakeover() throws {
        let (request, observation) = try replayValues()
        let pair = try sockets(); defer { pair.forEach { Darwin.close($0) } }
        let child = try Child.adoptingTestSocket(pair[0]); defer { child.close() }
        let encoded = try Child.Lifecycle.encode(observation)
        try frame(pair[1], "{\"data\":\"\(encoded.base64EncodedString())\",\"request_id\":1,\"version\":\"storage-child-lifecycle.v2\"}")
        #expect(try child.publicTakeoverReplay(requestID: request.requestID, old: request.old) == observation)
        let body = String(decoding: try Child.Lifecycle.encode(request), as: UTF8.self)
        #expect(String(decoding: try readFrame(pair[1]), as: UTF8.self) == "{\"body\":\(body),\"operation\":\"public-takeover-replay\",\"request_id\":1,\"version\":\"storage-child-lifecycle.v2\"}")
        try frame(pair[1], "{\"data\":\"\",\"request_id\":2,\"version\":\"storage-child-lifecycle.v2\"}")
        try child.takeover()
        _ = try readFrame(pair[1])
    }
    @Test(arguments: ["unknown", "duplicate", "null", "fraction", "old", "request", "error", "epoch", "oversize"])
    func publicReplayMalformedObservationFencesChannel(_ kind: String) throws {
        let (request, observation) = try replayValues()
        var text = String(decoding: try Child.Lifecycle.encode(observation), as: UTF8.self)
        switch kind {
        case "unknown": text = text.replacingOccurrences(of: "{\"error\":", with: "{\"extra\":0,\"error\":")
        case "duplicate": text = text.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"version\":1")
        case "null": text = text.replacingOccurrences(of: "\"version\":1", with: "\"version\":null")
        case "fraction": text = text.replacingOccurrences(of: "\"version\":1", with: "\"version\":1.0")
        case "old": text = text.replacingOccurrences(of: "22222222-2222-4222-8222-222222222222", with: "44444444-4444-4444-8444-444444444444")
        case "request": text = text.replacingOccurrences(of: "\"requestID\":\"\(request.requestID)\"", with: "\"requestID\":\"44444444-4444-4444-8444-444444444444\"")
        case "error": text = text.replacingOccurrences(of: "UNAUTHORIZED", with: "CONFLICT")
        case "epoch": text = text.replacingOccurrences(of: "\"expected_epoch\":2", with: "\"expected_epoch\":3")
        default: text = String(repeating: " ", count: 4097)
        }
        let pair = try sockets(); defer { pair.forEach { Darwin.close($0) } }
        let child = try Child.adoptingTestSocket(pair[0]); defer { child.close() }
        try frame(pair[1], "{\"data\":\"\(Data(text.utf8).base64EncodedString())\",\"request_id\":1,\"version\":\"storage-child-lifecycle.v2\"}")
        #expect(throws: (any Error).self) { try child.publicTakeoverReplay(requestID: request.requestID, old: request.old) }
        _ = try readFrame(pair[1])
        #expect(throws: (any Error).self) { try child.takeover() }
    }
}

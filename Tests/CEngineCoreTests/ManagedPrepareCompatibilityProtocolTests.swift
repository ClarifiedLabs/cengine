import Foundation
import Testing
@testable import CEngineCore

@Suite("Managed PREPARE compatibility closed wire")
struct ManagedPrepareCompatibilityProtocolTests {
    private typealias Carrier = ManagedPrepareCompatibilityProtocol
    private typealias Wire = WorkloadStorageProtocol
    private let id = "11111111-1111-4111-8111-111111111111"
    private let second = "22222222-2222-4222-8222-222222222222"
    private let third = "33333333-3333-4333-8333-333333333333"
    private let key = String(repeating: "ab", count: 32)
    private var arm: Carrier.Arm {
        .init(version: 1, profile: Carrier.profile, requestID: id, caseName: "normal", targetAttachment: second,
            binding: .init(shimLaunchUUID: id, guestBootNonce: third),
            scope: .init(intent: id, store: second, serviceEpoch: third, controllerEpoch: 1, controllerKey: key,
                container: key, containerInstance: second, launch: id, prepare: third, specificationDigest: key),
            mounts: [.init(index: 0, volume: id, destination: "/data", subpath: "", mode: .readWrite, noCopy: false)],
            slots: [.init(volume: id, attachment: second, role: .prepare, mode: .readWrite),
                    .init(volume: id, attachment: third, role: .runtime, mode: .readWrite)],
            credentials: [.init(attachment: second, key: key, certificateSHA256: key)])
    }
    @Test func ordinaryHelloEncodingRemainsUnchanged() throws {
        let frame = Wire.Frame(operation: .hello, binding: arm.binding)
        let body = Data(try Wire.encode(frame).dropFirst(4))
        #expect(String(decoding: body, as: UTF8.self).contains("\"data\":{}"))
        #expect(!String(decoding: body, as: UTF8.self).contains("compatibility"))
        #expect(try Wire.decode(from: body) == frame)
    }
    @Test func profilePairIsClosed() throws {
        try Carrier.validateProfile(nil, sourceSHA256: nil)
        try Carrier.validateProfile(Carrier.profile, sourceSHA256: key)
        for pair: (String?, String?) in [(Carrier.profile, nil), (nil, key), ("other", key), (Carrier.profile, key.uppercased())] {
            #expect(throws: (any Error).self) { try Carrier.validateProfile(pair.0, sourceSHA256: pair.1) }
        }
    }
    @Test func canonicalEscapesAreExplicit() throws {
        let bytes = try Carrier.canonicalData(["z": "é/<>&\u{2028}\u{2029}\n\t\u{0001}\"\\", "a": "first"])
        #expect(String(decoding: bytes, as: UTF8.self) == #"{"a":"first","z":"é/<>&\u2028\u2029\n\t\u0001\"\\"}"#)
    }
    @Test func armAndPrivateWireRoundTrip() throws {
        let bytes = try Carrier.armData(arm)
        #expect(try Carrier.decode(Carrier.Arm.self, from: bytes) == arm)
        var reversed = arm; reversed.slots.reverse()
        #expect(try Carrier.digest(reversed) == Carrier.digest(arm))
        let command = Wire.Frame(operation: .command, binding: arm.binding, scope: arm.scope, sequence: 1,
            kind: .prepareCompatibilityArm, data: .init(compatibilityArm: arm))
        #expect(try Wire.decode(from: Data(Wire.encode(command).dropFirst(4))) == command)
    }
    @Test func rejectsOpenOrNoncanonicalQueueJSON() throws {
        let text = String(decoding: try Carrier.armData(arm), as: UTF8.self)
        for changed in [text + "\n", " " + text, String(text.dropLast()) + ",\"unknown\":1}",
                        text.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"version\":1"),
                        text.replacingOccurrences(of: "\"version\":1", with: "\"version\":null"),
                        text.replacingOccurrences(of: "\"version\":1", with: "\"version\":1e0")] {
            #expect(throws: (any Error).self) { try Carrier.decode(Carrier.Arm.self, from: Data(changed.utf8)) }
        }
    }
    @Test func rejectsIncompleteOrWrongCredentialsAndSlots() {
        var variants: [Carrier.Arm] = []
        var value = arm; value.credentials = []; variants.append(value)
        value = arm; value.credentials.append(value.credentials[0]); variants.append(value)
        value = arm; value.credentials[0].attachment = third; variants.append(value)
        value = arm; value.slots.removeLast(); variants.append(value)
        value = arm; value.mounts[0].noCopy = true; variants.append(value)
        value = arm; value.mounts[0].subpath = "child"; variants.append(value)
        value = arm; value.mounts[0].mode = .readOnly; variants.append(value)
        value = arm; value.targetAttachment = third; variants.append(value)
        value = arm; value.profile = "other"; variants.append(value)
        value = arm; value.binding.guestBootNonce = ""; variants.append(value)
        for value in variants { #expect(throws: (any Error).self) { try Carrier.validate(value) } }
    }
    @Test func exactCurrentCandidateRequired() throws {
        let value = arm
        let candidate = Carrier.Candidate(version: 1, profile: Carrier.profile, requestID: value.requestID,
            binding: value.binding, scope: value.scope, mounts: value.mounts, slots: value.slots, credentials: value.credentials)
        try Carrier.matches(value, candidate: candidate)
        var changed = value; changed.credentials[0].certificateSHA256 = String(repeating: "cd", count: 32)
        #expect(throws: (any Error).self) { try Carrier.matches(changed, candidate: candidate) }
        changed = value; changed.scope.controllerEpoch += 1
        #expect(throws: (any Error).self) { try Carrier.matches(changed, candidate: candidate) }
    }
    private func observation() throws -> Carrier.Observation {
        func identity(_ inode: UInt64, _ kind: UInt32) -> Carrier.ObjectIdentity {
            .init(inode: inode, generation: 1, fileType: kind, handle: String(format: "%02x00000001000000", inode))
        }
        return .init(version: 1, profile: Carrier.profile, requestID: arm.requestID, armDigest: try Carrier.digest(arm),
            stage: "first-child-published", count: 1, targetAttachment: arm.targetAttachment, copyIntent: third,
            filesystemUUID: String(repeating: "ab", count: 16), manifestDigest: key, manifestSize: 512,
            sourceAtimes: .init(root: 0, a: 1, z: UInt64(Int64.max)),
            root: identity(2, 16384), transaction: identity(3, 16384), published: identity(4, 32768), staged: identity(5, 32768))
    }
    @Test func sourceAtimesAreRequiredCanonicalBoundedEvidenceForNormal() throws {
        let observation = try observation()
        try Carrier.validate(observation, arm: arm)
        let bytes = try Carrier.canonicalData(observation)
        #expect(String(decoding: bytes, as: UTF8.self).contains(#""sourceAtimes":{"a":1,"root":0,"z":9223372036854775807}"#))
        #expect(try Carrier.decode(Carrier.Observation.self, from: bytes) == observation)
        let frame = Wire.Frame(operation: .prepareCheckpoint, binding: arm.binding, scope: arm.scope,
            data: .init(compatibilityObservation: observation))
        #expect(try Wire.decode(from: Data(Wire.encode(frame).dropFirst(4))) == frame)
    }
    @Test func sourceAtimesRejectMissingMalformedUnknownDuplicateAndOverflow() throws {
        let observation = try observation()
        let original = String(decoding: try Carrier.canonicalData(observation), as: UTF8.self)
        let frame = Wire.Frame(operation: .prepareCheckpoint, binding: arm.binding, scope: arm.scope,
            data: .init(compatibilityObservation: observation))
        let wire = String(decoding: try Data(Wire.encode(frame).dropFirst(4)), as: UTF8.self)
        let atimes = #"{"a":1,"root":0,"z":9223372036854775807}"#
        let invalid = ["null", "[]", "{}", #"{"a":1,"root":0}"#, #"{"a":1,"z":1}"#, #"{"root":0,"z":1}"#,
            #"{"a":1,"root":0,"unknown":0,"z":1}"#, #"{"a":1,"root":0,"root":0,"z":1}"#,
            #"{"a":-1,"root":0,"z":1}"#, #"{"a":true,"root":0,"z":1}"#, #"{"a":"1","root":0,"z":1}"#,
            #"{"a":1.0,"root":0,"z":1}"#, #"{"a":1e0,"root":0,"z":1}"#,
            #"{"a":9223372036854775808,"root":0,"z":1}"#,
            #"{"a":1,"root":9223372036854775808,"z":1}"#,
            #"{"a":1,"root":0,"z":18446744073709551615}"#]
        for value in invalid {
            #expect(throws: (any Error).self) { try Carrier.decode(Carrier.Observation.self, from: Data(original.replacingOccurrences(of: atimes, with: value).utf8)) }
            #expect(throws: (any Error).self) { try Wire.decode(from: Data(wire.replacingOccurrences(of: atimes, with: value).utf8)) }
        }
        let field = "\"sourceAtimes\":" + atimes + ","
        #expect(throws: (any Error).self) { try Carrier.decode(Carrier.Observation.self, from: Data(original.replacingOccurrences(of: field, with: "").utf8)) }
        #expect(throws: (any Error).self) { try Wire.decode(from: Data(wire.replacingOccurrences(of: field, with: "").utf8)) }
    }
    @Test(arguments: ["root", "a", "z"])
    func constructedSourceAtimeOverflowCannotBeEncoded(field: String) throws {
        var value = try observation()
        if field == "root" { value.sourceAtimes.root = UInt64(Int64.max) + 1 }
        if field == "a" { value.sourceAtimes.a = UInt64(Int64.max) + 1 }
        if field == "z" { value.sourceAtimes.z = UInt64(Int64.max) + 1 }
        #expect(throws: (any Error).self) { try Carrier.validate(value) }
        #expect(throws: (any Error).self) { try Carrier.canonicalData(value) }
    }
    @Test func sharedGoObservationCanonicalVectors() throws {
        struct Vector: Decodable { let name: String; let observation: Carrier.Observation; let canonical: String; let sha256: String }
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let path = root.appendingPathComponent("Guest/internal/preparecompat/testdata/observation-vectors.json")
        let vectors = try JSONDecoder().decode([Vector].self, from: Data(contentsOf: path))
        #expect(!vectors.isEmpty)
        for vector in vectors {
            try Carrier.validate(vector.observation)
            let bytes = try Carrier.canonicalData(vector.observation)
            #expect(bytes == Data(vector.canonical.utf8))
            #expect(try Carrier.decode(Carrier.Observation.self, from: bytes) == vector.observation)
            #expect(Wire.specificationDigest(bytes) == vector.sha256)
        }
    }
    @Test func sharedGoCanonicalVectors() throws {
        struct Vector: Decodable { let name: String; let arm: Carrier.Arm; let canonical: String; let sha256: String }
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let path = root.appendingPathComponent("Guest/internal/preparecompat/testdata/vectors.json")
        let vectors = try JSONDecoder().decode([Vector].self, from: Data(contentsOf: path))
        #expect(vectors.count >= 2)
        for vector in vectors {
            #expect(try Carrier.armData(vector.arm) == Data(vector.canonical.utf8))
            #expect(try Carrier.digest(vector.arm) == vector.sha256)
        }
    }
}

import Foundation
import Testing
@testable import CEngineCore

@Suite("Private workload storage wire")
struct WorkloadStorageProtocolTests {
    private typealias Wire = WorkloadStorageProtocol
    private let id = "11111111-1111-4111-8111-111111111111"
    private let second = "22222222-2222-4222-8222-222222222222"
    private let third = "33333333-3333-4333-8333-333333333333"
    private let key = String(repeating: "ab", count: 32)
    private var workload: Data { Data(#"{"ioClaim":""}"#.utf8) }
    private var binding: Wire.BootBinding { .init(shimLaunchUUID: id, guestBootNonce: second) }
    private var scope: Wire.Scope {
        .init(intent: id, store: second, serviceEpoch: third, controllerEpoch: 1,
              controllerKey: key, container: key, containerInstance: second, launch: id,
              prepare: third, specificationDigest: Wire.specificationDigest(workload))
    }
    private var mount: Wire.MountBinding {
        .init(index: 0, volume: id, destination: "/work", subpath: "", mode: .readWrite, noCopy: false)
    }
    private var slots: [Wire.Slot] {
        [.init(volume: id, attachment: second, role: .prepare, mode: .readWrite),
         .init(volume: id, attachment: third, role: .runtime, mode: .readWrite)]
    }
    private var configuration: Wire.Frame {
        .init(operation: .configure, binding: binding, scope: scope,
              data: .init(peer: .init(tlsRootDER: Data([1]), serverDER: Data([2]), serverKey: key,
                                      dataAddress: "192.0.2.1"), mounts: [mount], slots: slots))
    }
    private func body(_ frame: Wire.Frame) throws -> Data { Data(try Wire.encode(frame).dropFirst(4)) }
    private func roundTrip(_ frame: Wire.Frame) throws {
        let bytes = try Wire.encode(frame)
        let length = bytes.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        #expect(Int(length) == bytes.count - 4)
        #expect(try Wire.decode(from: Data(bytes.dropFirst(4))) == frame)
        #expect(throws: Wire.ValidationError.invalidFrame) { try Wire.decode(from: bytes) }
    }
    private func rejects(_ frame: Wire.Frame) {
        #expect(throws: Wire.ValidationError.invalidFrame) { try Wire.encode(frame) }
    }
    private func rejects(_ bytes: Data) {
        #expect(throws: Wire.ValidationError.invalidFrame) { try Wire.decode(from: bytes) }
    }

    @Test func sharedGoVectors() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let path = root.appendingPathComponent("Guest/internal/workloadstorage/testdata/vectors.json")
        struct Corpus: Decodable { var valid: [String]; var invalid: [String] }
        let vectors = try JSONDecoder().decode(Corpus.self, from: Data(contentsOf: path))
        #expect(vectors.valid.count >= 19)
        #expect(!vectors.invalid.isEmpty)
        for text in vectors.valid { try roundTrip(Wire.decode(from: Data(text.utf8))) }
        for text in vectors.invalid { rejects(Data(text.utf8)) }
    }

    @Test func helloAndScopeBinding() throws {
        let hello = Wire.Frame(operation: .hello, binding: binding)
        try roundTrip(hello)
        var bad = hello
        bad.scope = scope; rejects(bad)
        bad = hello; bad.sequence = 1; rejects(bad)
        bad = configuration; bad.scope = nil; rejects(bad)
        bad = configuration; bad.scope?.launch = second; rejects(bad)
        bad = configuration; bad.scope?.container = id; rejects(bad)
        bad = configuration; bad.scope?.controllerEpoch = 0; rejects(bad)
        bad = configuration; bad.binding.guestBootNonce = "11111111-1111-1111-8111-111111111111"; rejects(bad)
        bad = configuration; bad.scope?.specificationDigest = key.uppercased(); rejects(bad)
        bad = configuration; bad.sequence = 1; rejects(bad)
    }

    @Test func rejectsNonClosedJSON() throws {
        let text = String(decoding: try body(configuration), as: UTF8.self)
        for changed in [
            text + "{}", text + "null", String(text.dropLast()) + ",\"unknown\":1}",
            text.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"version\":1"),
            text.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"\\u0076ersion\":1"),
            text.replacingOccurrences(of: "\"controllerEpoch\":1", with: "\"controllerEpoch\":null"),
            text.replacingOccurrences(of: "\"controllerEpoch\":1", with: "\"controllerEpoch\":1e0"),
            text.replacingOccurrences(of: "\"index\":0", with: "\"index\":-0"),
            text.replacingOccurrences(of: "\"subpath\":\"\"", with: "\"subpath\":\"\\ud800\""),
            text.replacingOccurrences(of: "\"subpath\":\"\"", with: "\"subpath\":\"\",\"privateKey\":\"secret\""),
            text.replacingOccurrences(of: "AQ==", with: "AR=="),
            text.replacingOccurrences(of: "AQ==", with: "AQ"),
            text.replacingOccurrences(of: "\"noCopy\":false", with: "\"noCopy\":0")
        ] { rejects(Data(changed.utf8)) }
        rejects(Data(text.utf8) + Data([255]))
        rejects(Data(String(repeating: "[", count: 20).utf8))
        rejects(Data())
    }

    @Test func hierarchyHasOnePrepareAndExactRuntimeModes() throws {
        try roundTrip(configuration)
        var both = mount
        both.index = 1; both.mode = .readOnly
        var bothSlots = slots
        bothSlots.append(.init(volume: id, attachment: id, role: .runtime, mode: .readOnly))
        try Wire.validateConfiguration(mounts: [mount, both], slots: bothSlots)
        try Wire.validateConfiguration(mounts: [], slots: [])
        for (mounts, plan) in [([mount], Array(slots.dropFirst())), ([mount], slots + [slots[0]]),
                              ([mount, mount], slots), ([mount, both], slots), ([mount], bothSlots),
                              ([], slots)] {
            #expect(throws: Wire.ValidationError.invalidFrame) { try Wire.validateConfiguration(mounts: mounts, slots: plan) }
        }
        var bad = configuration
        bad.data.slots?[0].mode = .readOnly; rejects(bad)
        bad = configuration; bad.data.mounts?[0].index = 64; rejects(bad)
        bad = configuration; bad.data.mounts?[0].destination = "relative"; rejects(bad)
        bad = configuration; bad.data.mounts?[0].subpath = "\0"; rejects(bad)
        bad = configuration; bad.data.mounts = Array(repeating: mount, count: 65); rejects(bad)
        // 32 volumes each require two slots: the cap is total, not per role.
        var mounts: [Wire.MountBinding] = [], plan: [Wire.Slot] = []
        for index in 0..<33 {
            let volume = String(format: "%08x-1111-4111-8111-111111111111", index)
            mounts.append(.init(index: UInt32(index), volume: volume, destination: "/v\(index)", subpath: "", mode: .readWrite, noCopy: false))
            for (offset, role) in [Wire.Role.prepare, .runtime].enumerated() {
                let attachment = String(format: "%08x-2222-4222-8222-222222222222", index * 2 + offset)
                plan.append(.init(volume: volume, attachment: attachment, role: role, mode: .readWrite))
            }
        }
        try Wire.validateConfiguration(mounts: Array(mounts.prefix(32)), slots: Array(plan.prefix(64)))
        #expect(throws: Wire.ValidationError.invalidFrame) { try Wire.validateConfiguration(mounts: mounts, slots: plan) }
    }

    @Test func peerBoundsAndLiteralAddresses() throws {
        for address in ["127.0.0.1", "::1", "2001:db8::1", "::ffff:192.0.2.1"] {
            var frame = configuration; frame.data.peer?.dataAddress = address; try roundTrip(frame)
        }
        for address in ["localhost", "https://192.0.2.1", "192.0.2.1:2049", "[::1]", "fe80::1%en0", "127.0.0.1\0x", "127.001.0.1"] {
            var frame = configuration; frame.data.peer?.dataAddress = address; rejects(frame)
        }
        var frame = configuration
        frame.data.peer?.tlsRootDER = Data(repeating: 1, count: Wire.maximumDERBytes); try roundTrip(frame)
        frame.data.peer?.tlsRootDER.append(1); rejects(frame)
    }

    @Test func exactWorkloadDigestAndPayloadBounds() throws {
        var frame = Wire.Frame(operation: .command, binding: binding, scope: scope, sequence: 1, kind: .prepare,
                               data: .init(workloadJSON: workload, ioClaim: "separate-private-claim"))
        try roundTrip(frame)
        #expect(Wire.specificationDigest(Data("abc".utf8)) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        frame.data.ioClaim = "other-claim"; try roundTrip(frame)
        frame.data.workloadJSON?.append(32); rejects(frame)
        let maximum = Data(repeating: 32, count: Wire.maximumWorkloadBytes)
        frame.data.workloadJSON = maximum; frame.scope?.specificationDigest = Wire.specificationDigest(maximum)
        try roundTrip(frame) // Wire only: actual Workload schema belongs to sealed session integration.
        frame.data.workloadJSON?.append(32); rejects(frame)
        frame.data.workloadJSON = workload; frame.scope = scope
        frame.data.ioClaim = String(repeating: "x", count: 4097); rejects(frame)
        frame.data.ioClaim = "\0"; rejects(frame)
        frame.data.ioClaim = ""; frame.sequence = 0; rejects(frame)
        frame.sequence = UInt64.max; try roundTrip(frame)
    }

    @Test func replyUnionAndTerminalBounds() throws {
        var reply = Wire.Frame(operation: .reply, binding: binding, scope: scope, sequence: 1, kind: .start,
                               data: .init(status: "running", pid: 1))
        try roundTrip(reply)
        reply.data.pid = 0; rejects(reply)
        reply.data.pid = UInt32.max; rejects(reply)
        reply.data = .init(code: .internalError); try roundTrip(reply)
        reply.data.role = .runtime; rejects(reply)
        reply.kind = .status; reply.data = .init(phase: .running, mountedIDs: [id], terminalIDs: [id]); rejects(reply)
        reply.data.terminalIDs = [second]; try roundTrip(reply)
        reply.kind = .prepare
        reply.data = .init(prepare: third, containerInstance: second, launch: id, succeeded: true, cleanCopyUp: true, evidenceDigest: key)
        try roundTrip(reply)
        reply.data.launch = second; rejects(reply)
        var event = Wire.Frame(operation: .terminal, binding: binding, scope: scope, data: .init(attachmentIDs: [id], code: .terminal))
        try roundTrip(event)
        event.data.attachmentIDs = []; rejects(event)
        event.data.attachmentIDs = [id, id]; rejects(event)
        let unique = (0..<33).map { String(format: "%08x-1111-4111-8111-111111111111", $0) }
        event.data.attachmentIDs = Array(unique.prefix(32)); try roundTrip(event)
        event.data.attachmentIDs = unique; rejects(event)
    }

    @Test func swiftReaderRejectsOversizedPrefixBeforeBodyRead() throws {
        for count: UInt32 in [0, UInt32(Wire.maxFrame + 1), UInt32.max] {
            var calls = 0
            var big = count.bigEndian
            let prefix = Data(bytes: &big, count: 4)
            #expect(throws: Wire.ValidationError.invalidFrame) {
                try Wire.readFrame { requested in
                    calls += 1
                    #expect(requested == 4)
                    return prefix
                }
            }
            #expect(calls == 1)
        }
        let frame = Wire.Frame(operation: .hello, binding: binding)
        var bytes = try Wire.encode(frame)
        let decoded = try Wire.readFrame { requested in
            defer { bytes.removeFirst(requested) }
            return Data(bytes.prefix(requested))
        }
        #expect(decoded == frame && bytes.isEmpty)
    }

    @Test func binaryAndScalarBoundaries() throws {
        var frame = Wire.Frame(operation: .reply, binding: binding, scope: scope, sequence: 1, kind: .offerKeys,
                               data: .init(offers: [.init(attachment: id, key: key, csrDER: Data(repeating: 1, count: 4096))]))
        try roundTrip(frame)
        frame.data.offers?[0].csrDER.append(1); rejects(frame)
        frame.data.offers?[0].csrDER = Data([1])
        let duplicate = frame.data.offers![0]
        frame.data.offers?.append(duplicate); rejects(frame)
        frame.kind = .start; frame.data = .init(status: "running", pid: UInt32(Int32.max)); try roundTrip(frame)
        frame.operation = .command; frame.kind = .installCertificate
        frame.data = .init(attachment: id, certificateDER: Data(repeating: 1, count: 16384)); try roundTrip(frame)
        frame.data.certificateDER?.append(1); rejects(frame)
        frame.kind = .prepare
        let opaque = Data([255, 0, 10])
        frame.scope?.specificationDigest = Wire.specificationDigest(opaque)
        frame.data = .init(workloadJSON: opaque, ioClaim: String(repeating: "é", count: 2048)); try roundTrip(frame)
        var config = configuration
        config.data.mounts?[0].destination = "/" + String(repeating: "x", count: 4095)
        config.data.mounts?[0].subpath = String(repeating: "x", count: 4096); try roundTrip(config)
        config.data.mounts?[0].subpath.append("x"); rejects(config)
    }

    @Test func frameLimitCountsJSONNotPrefix() throws {
        let frame = Wire.Frame(operation: .hello, binding: binding)
        let original = try body(frame)
        let padded = original + Data(repeating: 32, count: Wire.maxFrame - original.count)
        #expect(try Wire.decode(from: padded) == frame)
        rejects(padded + Data([32]))
    }
}

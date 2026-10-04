#if os(macOS)
import CEngineCore
import Darwin
import Dispatch
import Foundation
import Testing
@testable import CEngineRuntime

@Suite struct ManagedStorageControlClientTests: Sendable {
    private typealias Client = ManagedStorageControlClient
    private let store = "11111111-1111-4111-8111-111111111111"
    private let epoch = "22222222-2222-4222-8222-222222222222"
    private let volume = "33333333-3333-4333-8333-333333333333"
    private let attachment = "44444444-4444-4444-8444-444444444444"
    private let prepare = "55555555-5555-4555-8555-555555555555"
    private let operation = "66666666-6666-4666-8666-666666666666"
    private let launch = "77777777-7777-4777-8777-777777777777"
    private let key = String(repeating: "a", count: 64)

    private func context(controllerEpoch: UInt64 = .max) throws -> Client.Context {
        try .init(store: store, serviceEpoch: epoch, controllerEpoch: controllerEpoch,
                  controllerKey: key, provenanceReference: key)
    }
    private func root(_ inode: UInt64) -> ControllerJSON {
        .object(["device": .number(.max), "inode": .number(inode)])
    }
    private func volumeTree() -> ControllerJSON {
        .object(["id": .string(volume), "name": .string("data"), "root": root(3)])
    }
    private func bindingTree() -> ControllerJSON {
        .object(["store": .string(store), "volume": .string(volume), "attachment": .string(attachment),
                 "prepare": .string(prepare), "container": .string(String(repeating: "b", count: 64)),
                 "launch": .string(launch), "key": .string(String(repeating: "c", count: 64)),
                 "role": .string("prepare"), "mode": .string("read-write")])
    }
    private func receiptTree() -> ControllerJSON {
        .object(["schema": .number(3), "store": .string(store), "volume": .string(volume),
                 "attachment": .string(attachment), "prepare": .string(prepare), "launch": .string(launch),
                 "revision": .number(.max)])
    }
    private func snapshotTree(completed: Bool = false) -> ControllerJSON {
        return .object(["schema": .number(3), "revision": .number(.max),
            "store": .object(["id": .string(store), "device_id": .string("ext4-device-identity"), "root": root(1), "exports": root(2)]),
            "epoch": .string(epoch), "controller": .object(["epoch": .number(.max), "key": .string(key)]),
            "volumes": .object([volume: volumeTree()]),
            "volume_lifecycles": .object([volume: .object(["phase": .string("READY")])]),
            "attachments": .object(completed ? [attachment: .object([
                "binding": bindingTree(), "phase": .string("DRAINED"), "receipt": receiptTree(), "retirement": .string(operation)
            ])] : [:]),
            "prepares": .object(completed ? [prepare: .object([
                "id": .string(prepare), "attachments": .array([bindingTree()]), "phase": .string("COMPLETED"),
                "attestation": .object(["prepare": .string(prepare), "succeeded": .bool(true), "clean_copy_up": .bool(true)])
            ])] : [:])])
    }
    private func response(_ field: String, _ tree: ControllerJSON, id: UInt64 = 1) throws -> Data {
        try ControllerJSON.object(["id": .number(id), field: tree]).bytes()
    }
    private func changed(_ tree: ControllerJSON, _ path: [String], _ value: ControllerJSON?) -> ControllerJSON {
        guard case .object(var fields) = tree, let first = path.first else { preconditionFailure("fixture path") }
        if path.count == 1 { fields[first] = value }
        else { fields[first] = changed(fields[first]!, Array(path.dropFirst()), value) }
        return .object(fields)
    }
    /// Schema-4 Query replies travel in the full lifecycle-identity envelope.
    private func lifecycleEnvelope(_ snapshot: ControllerJSON) -> ControllerJSON {
        .object(["id": .number(1), "snapshot": snapshot,
            "lifecycle_identity": .object(["store": .string(store), "generation": .number(.max), "binding": .string(key)])])
    }
    private func prepareContextTree(controllerEpoch: UInt64 = 1, key k: String = String(repeating: "d", count: 64)) -> ControllerJSON {
        .object(["service_epoch": .string(operation), "controller_epoch": .number(controllerEpoch), "controller_key": .string(k)])
    }

    @Test func schema4PrepareContextIsRequiredClosedAndBounded() throws {
        let v4 = changed(snapshotTree(completed: true), ["schema"], .number(4))
        let good = changed(v4, ["prepares", prepare, "context"], prepareContextTree())
        guard case .snapshot(let snapshot) = try Client.decode(lifecycleEnvelope(good).bytes(), for: .query, context: lifecycleContext()) else {
            Issue.record("not a snapshot"); return
        }
        #expect(snapshot.prepares[prepare]?.context == .init(serviceEpoch: operation, controllerEpoch: 1,
                                                              controllerKey: String(repeating: "d", count: 64)))
        let current = changed(v4, ["prepares", prepare, "context"], prepareContextTree(controllerEpoch: .max, key: key))
        _ = try Client.decode(lifecycleEnvelope(current).bytes(), for: .query, context: lifecycleContext())
        var bad: [ControllerJSON] = [
            v4, // schema 4 requires the attested owning context
            changed(good, ["prepares", prepare, "context"], .null),
            changed(good, ["prepares", prepare, "context"], .string(operation)),
            changed(good, ["prepares", prepare, "context", "unknown"], .bool(true)),
            changed(v4, ["prepares", prepare, "context"], prepareContextTree(controllerEpoch: 0)),
            changed(v4, ["prepares", prepare, "context"], prepareContextTree(key: "zz")),
            // Current controller epoch must carry the current key.
            changed(v4, ["prepares", prepare, "context"], prepareContextTree(controllerEpoch: .max)),
            changed(good, ["prepares", prepare, "context", "service_epoch"], .string("x"))
        ]
        for field in ["service_epoch", "controller_epoch", "controller_key"] {
            bad.append(changed(good, ["prepares", prepare, "context", field], nil))
            bad.append(changed(good, ["prepares", prepare, "context", field], .null))
        }
        for tree in bad {
            #expect(throws: Client.Failure.protocolViolation) {
                try Client.decode(self.lifecycleEnvelope(tree).bytes(), for: .query, context: self.lifecycleContext())
            }
        }
        // Schema 3 never carries a lifecycle context.
        try rejectsSnapshot(changed(snapshotTree(completed: true), ["prepares", prepare, "context"], prepareContextTree()))
    }

    private func rejectsSnapshot(_ tree: ControllerJSON) throws {
        let data = try response("snapshot", tree)
        #expect(throws: Client.Failure.protocolViolation) { try Client.decode(data, for: .query, context: context()) }
    }

    @Test func trustedContextRequiresCanonicalIdentities() throws {
        #expect(try context().controllerEpoch == UInt64.max)
        for id in ["", store.uppercased().replacingOccurrences(of: "1", with: "A"), "11111111-1111-1111-8111-111111111111", "11111111-1111-4111-7111-111111111111"] {
            #expect(throws: Client.Failure.invalidContext) {
                try Client.Context(store: id, serviceEpoch: epoch, controllerEpoch: 1, controllerKey: key, provenanceReference: "ready")
            }
            #expect(throws: Client.Failure.invalidContext) {
                try Client.Context(store: store, serviceEpoch: id, controllerEpoch: 1, controllerKey: key, provenanceReference: "ready")
            }
        }
        for fingerprint in ["", String(repeating: "A", count: 64), String(repeating: "a", count: 63)] {
            #expect(throws: Client.Failure.invalidContext) {
                try Client.Context(store: store, serviceEpoch: epoch, controllerEpoch: 1, controllerKey: fingerprint, provenanceReference: "ready")
            }
        }
        #expect(throws: Client.Failure.invalidContext) { try context(controllerEpoch: 0) }
        for reference in ["", "ready\n", String(repeating: "a", count: 4097)] {
            #expect(throws: Client.Failure.invalidContext) {
                try Client.Context(store: store, serviceEpoch: epoch, controllerEpoch: 1, controllerKey: key, provenanceReference: reference)
            }
        }
    }

    private func lifecycleContext() throws -> Client.Context {
        try .init(store: store, serviceEpoch: epoch, controllerEpoch: .max,
            controllerKey: key, provenanceReference: key,
            lifecycleIdentity: .init(store: store, generation: .max, binding: key))
    }

    private func lifecycleQuery() -> ControllerJSON {
        lifecycleEnvelope(changed(changed(snapshotTree(completed: true), ["schema"], .number(4)),
            ["prepares", prepare, "context"], prepareContextTree()))
    }

    @Test func lifecycleQueryRequiresExplicitFullIdentityAndSchemaFour() throws {
        let context = try lifecycleContext(), tree = lifecycleQuery()
        guard case .snapshot(let snapshot) = try Client.decode(tree.bytes(), for: .query, context: context) else {
            Issue.record("expected lifecycle snapshot"); return
        }
        #expect(snapshot.schema == 4)
        #expect(snapshot.revision == .max)
        // Snapshot format changed, not the independently versioned mutation receipts.
        #expect(snapshot.attachments[attachment]?.receipt?.schema == 3)
        let mutations: [([String], ControllerJSON?)] = [
            (["lifecycle_identity"], nil), (["lifecycle_identity"], .null),
            (["lifecycle_identity", "store"], .string(epoch)),
            (["lifecycle_identity", "generation"], .number(1)),
            (["lifecycle_identity", "generation"], .number(0)),
            (["lifecycle_identity", "binding"], .string(String(repeating: "b", count: 64))),
            (["lifecycle_identity", "unknown"], .bool(true)),
            (["snapshot", "schema"], .number(3)),
            (["snapshot", "epoch"], .string(store)),
            (["snapshot", "controller", "epoch"], .number(1)),
            (["snapshot", "controller", "key"], .string(String(repeating: "b", count: 64))),
            (["snapshot", "attachments", attachment, "receipt", "schema"], .number(4))
        ]
        for (path, value) in mutations {
            #expect(throws: Client.Failure.protocolViolation) {
                try Client.decode(changed(tree, path, value).bytes(), for: .query, context: context)
            }
        }
        #expect(throws: Client.Failure.protocolViolation) {
            try Client.decode(tree.bytes(), for: .query, context: self.context())
        }
        #expect(throws: Client.Failure.protocolViolation) {
            try Client.decode(response("snapshot", snapshotTree()), for: .query, context: context)
        }
        #expect(throws: Client.Failure.invalidContext) {
            try Client.Context(store: store, serviceEpoch: epoch, controllerEpoch: 1,
                controllerKey: key, provenanceReference: key,
                lifecycleIdentity: .init(store: epoch, generation: 1, binding: key))
        }
    }

    @Test func lifecycleMutationReceiptsRemainSchemaThreeAndRefuseQueryIdentityEnvelope() throws {
        let context = try lifecycleContext()
        let request = ManagedStorageControlProtocol.ControlRequest.retire(try .init(
            operation: operation, store: store, volume: volume, attachment: attachment, launch: launch))
        let bytes = try response("receipt", receiptTree())
        guard case .receipt(let receipt) = try Client.decode(bytes, for: request, context: context) else {
            Issue.record("expected receipt"); return
        }
        #expect(receipt.schema == 3)
        #expect(throws: Client.Failure.protocolViolation) {
            try Client.decode(response("receipt", changed(receiptTree(), ["schema"], .number(4))), for: request, context: context)
        }
        let envelope = ControllerJSON.object(["id": .number(1), "receipt": receiptTree(),
            "lifecycle_identity": try ControllerJSON.from(context.lifecycleIdentity!)])
        #expect(throws: Client.Failure.protocolViolation) {
            try Client.decode(envelope.bytes(), for: request, context: context)
        }
    }

    @Test func completeSnapshotPreservesMaximumIntegersAndActualGoShape() throws {
        let data = try response("snapshot", snapshotTree(completed: true), id: .max)
        guard case .snapshot(let snapshot) = try Client.decode(data, for: .query, context: context()) else {
            Issue.record("expected snapshot"); return
        }
        #expect(snapshot.revision == UInt64.max)
        #expect(snapshot.controller.epoch == UInt64.max)
        #expect(snapshot.store.root.device == UInt64.max)
        #expect(snapshot.attachments[attachment]?.receipt?.revision == UInt64.max)
        #expect(snapshot.prepares[prepare]?.attestation?.cleanCopyUp == true)
        #expect(try JSONDecoder().decode(Client.Snapshot.self, from: JSONEncoder().encode(snapshot)) == snapshot)
    }

    @Test func exactHeaderAndDictionaryTuplesAreRequired() throws {
        let base = snapshotTree(completed: true)
        let mutations: [([String], ControllerJSON?)] = [
            (["schema"], .number(1)), (["revision"], .number(0)), (["store", "id"], .string(epoch)),
            (["epoch"], .string(store)), (["controller", "epoch"], .number(1)), (["controller", "key"], .string(String(repeating: "b", count: 64))),
            (["store", "root", "inode"], .number(0)), (["store", "exports", "device"], .number(2)),
            (["volumes", volume, "id"], .string(store)), (["volumes", volume, "root", "device"], .number(2)),
            (["volumes", volume, "name"], .string("../data")), (["volume_lifecycles", volume], nil),
            (["attachments", attachment, "binding", "attachment"], .string(store)),
            (["attachments", attachment, "binding", "store"], .string(epoch)),
            (["attachments", attachment, "binding", "key"], .string(key)),
            (["attachments", attachment, "binding", "role"], .string("runtime")),
            (["attachments", attachment, "binding", "mode"], .string("writable")),
            (["attachments", attachment, "receipt", "volume"], .string(epoch)),
            (["attachments", attachment, "receipt", "prepare"], nil),
            (["attachments", attachment, "receipt", "revision"], .number(0)),
            (["prepares", prepare, "id"], .string(store))
        ]
        for (path, value) in mutations { try rejectsSnapshot(changed(base, path, value)) }
        try rejectsSnapshot(changed(base, ["operations"], .object(["not-a-uuid": .object(["kind": .string("reserve"), "digest": .string(key)])])))
    }

    @Test func everyNestedObjectIsClosedAndNullIsNotOmission() throws {
        let base = snapshotTree(completed: true)
        let paths: [[String]] = [[], ["store"], ["store", "root"], ["store", "exports"], ["controller"],
            ["volumes", volume], ["volumes", volume, "root"], ["volume_lifecycles", volume],
            ["attachments", attachment], ["attachments", attachment, "binding"], ["attachments", attachment, "receipt"],
            ["prepares", prepare], ["prepares", prepare, "attestation"]]
        for path in paths { try rejectsSnapshot(changed(base, path + ["unknown"], .bool(true))) }
        for path in [["attachments", attachment, "retirement"], ["attachments", attachment, "receipt"],
                     ["prepares", prepare, "successor"], ["prepares", prepare, "attestation"],
                     ["volume_lifecycles", volume, "create"]] {
            try rejectsSnapshot(changed(base, path, .null))
        }
        try rejectsSnapshot(changed(base, ["prepares", prepare, "attachments"], .array([changed(bindingTree(), ["unknown"], .number(1))])))
    }

    @Test func terminalEvidenceCannotBeReinterpretedAsLiveState() throws {
        let base = snapshotTree(completed: true)
        let mutations: [([String], ControllerJSON?)] = [
            (["attachments", attachment, "phase"], .string("ACTIVE")), (["attachments", attachment, "retirement"], nil),
            (["attachments", attachment, "receipt"], nil), (["attachments", attachment, "phase"], .string("UNKNOWN")),
            (["prepares", prepare, "phase"], .string("PENDING")), (["prepares", prepare, "phase"], .string("REPLACED")),
            (["prepares", prepare, "attestation", "prepare"], .string(store)),
            (["prepares", prepare, "attestation", "succeeded"], .bool(false)),
            (["prepares", prepare, "attestation", "clean_copy_up"], .bool(false)),
            (["prepares", prepare, "attachments"], .array([])),
            (["prepares", prepare, "successor"], .string(prepare)),
            (["volume_lifecycles", volume, "phase"], .string("DELETED")),
            (["volume_lifecycles", volume, "created_revision"], .number(0)),
            (["volume_lifecycles", volume, "deleted_revision"], .number(1))
        ]
        for (path, value) in mutations { try rejectsSnapshot(changed(base, path, value)) }
    }

    @Test func canonicalParserRejectsDuplicateKeysAndLossyNumbers() throws {
        let valid = String(decoding: try response("snapshot", snapshotTree()), as: UTF8.self)
        for text in [valid + " ", valid.replacingOccurrences(of: "\"id\":1,", with: "\"id\":1,\"id\":1,"),
                     valid.replacingOccurrences(of: "18446744073709551615", with: "18446744073709551616"),
                     valid.replacingOccurrences(of: "\"id\":1,", with: "\"id\":1.0,"),
                     valid.replacingOccurrences(of: "\"id\":1,", with: "\"id\":01,"),
                     "{\"snapshot\":{},\"id\":1}", "{\"id\":0,\"snapshot\":{}}"] {
            #expect(throws: Client.Failure.protocolViolation) { try Client.decode(Data(text.utf8), for: .query, context: context()) }
        }
    }

    @Test func receiptRepliesMustMatchOperationTuples() throws {
        let retire = ManagedStorageControlProtocol.ControlRequest.retire(try .init(operation: operation, store: store, volume: volume, attachment: attachment, launch: launch))
        guard case .receipt(let receipt) = try Client.decode(response("receipt", receiptTree()), for: retire, context: context()) else {
            Issue.record("expected receipt"); return
        }
        #expect(receipt.revision == UInt64.max)
        for field in ["store", "volume", "attachment", "launch"] {
            #expect(throws: Client.Failure.protocolViolation) {
                try Client.decode(response("receipt", changed(receiptTree(), [field], .string(epoch))), for: retire, context: context())
            }
        }
        let create = ManagedStorageControlProtocol.ControlRequest.createVolume(try .init(operation: operation, store: store, volume: volume, name: "data"))
        let body = ControllerJSON.object(["schema": .number(3), "operation": .string(operation), "store": .string(store),
            "volume": volumeTree(), "phase": .string("READY"), "revision": .number(.max)])
        guard case .volumeReceipt(let created) = try Client.decode(response("volume_receipt", body), for: create, context: context()) else {
            Issue.record("expected volume receipt"); return
        }
        #expect(created.volume.root.device == UInt64.max)
        for (path, value) in [(["operation"], ControllerJSON.string(epoch)), (["store"], .string(epoch)),
                              (["volume", "id"], .string(epoch)), (["volume", "name"], .string("other")),
                              (["phase"], .string("DELETED")), (["unknown"], .bool(true))] {
            #expect(throws: Client.Failure.protocolViolation) {
                try Client.decode(response("volume_receipt", changed(body, path, value)), for: create, context: context())
            }
        }
        let delete = ManagedStorageControlProtocol.ControlRequest.deleteVolume(try .init(operation: operation, store: store, volume: volume))
        guard case .volumeReceipt(let deleted) = try Client.decode(response("volume_receipt", changed(body, ["phase"], .string("DELETED"))), for: delete, context: context()) else {
            Issue.record("expected delete receipt"); return
        }
        #expect(deleted.phase == .deleted)
    }

    @Test func remoteErrorsAreTypedButInvalidUnionsFailClosed() throws {
        for code in ["INVALID", "UNAUTHORIZED", "CONFLICT", "UNKNOWN", "BLOCKED", "LIMIT", "BUSY", "CLOSED", "TIMEOUT", "REPAIR_REQUIRED", "INTERNAL"] {
            #expect(throws: Client.Failure.remote(code)) { try Client.decode(response("error", .string(code)), for: .query, context: context()) }
        }
        for text in ["{\"error\":\"OTHER\",\"id\":1}", "{\"error\":\"BUSY\",\"id\":1,\"ok\":{}}", "{\"id\":1,\"ok\":{}}"] {
            #expect(throws: Client.Failure.protocolViolation) { try Client.decode(Data(text.utf8), for: .query, context: context()) }
        }
        let reserve = ManagedStorageControlProtocol.ControlRequest.reservePrepare(try .init(operation: operation, prepare: prepare, attachments: []))
        guard case .ok = try Client.decode(response("ok", .object([:])), for: reserve, context: context()) else {
            Issue.record("expected ok"); return
        }
        #expect(throws: Client.Failure.protocolViolation) { try Client.decode(response("ok", .object(["extra": .bool(true)])), for: reserve, context: context()) }
    }

    @Test func crossStoreRequestsAreRejectedBeforeIO() throws {
        let foreign = ManagedStorageControlProtocol.ControlRequest.deleteVolume(try .init(operation: operation, store: epoch, volume: volume))
        #expect(throws: Client.Failure.invalidRequest) { try Client.decode(Data(), for: foreign, context: context()) }
    }

}
#endif

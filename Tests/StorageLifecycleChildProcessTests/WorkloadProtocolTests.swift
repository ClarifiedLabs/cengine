import Foundation
import Testing
@testable import LifecycleChildRuntime

@Suite struct WorkloadProtocolTests {
    typealias Control = ManagedStorageControlProtocol
    private let id = "11111111-1111-4111-8111-111111111111"

    @Test func retirementWireAndSchemaThreeReceiptRemainExact() throws {
        let request = Control.ControlRequest.retire(try .init(operation: id, store: id,
            volume: id, attachment: id, launch: id))
        let expected = "{\"id\":0,\"retire\":{\"attachment\":\"\(id)\",\"launch\":\"\(id)\",\"operation\":\"\(id)\",\"store\":\"\(id)\",\"volume\":\"\(id)\"}}"
        #expect(try request.durableBytes() == Data(expected.utf8))
        let receipt = try Control.Receipt(schema: 3, store: id, volume: id,
            attachment: id, launch: id, revision: UInt64.max)
        let body = "{\"attachment\":\"\(id)\",\"launch\":\"\(id)\",\"revision\":18446744073709551615,\"schema\":3,\"store\":\"\(id)\",\"volume\":\"\(id)\"}"
        #expect(try ControllerJSON.from(receipt).bytes() == Data(body.utf8))
        #expect(try JSONDecoder().decode(Control.Receipt.self, from: Data(body.utf8)) == receipt)
        let context = try ManagedStorageControlClient.Context(store: id, serviceEpoch: id,
            controllerEpoch: 1, controllerKey: String(repeating: "a", count: 64),
            provenanceReference: String(repeating: "b", count: 64))
        let decoded = try ManagedStorageControlClient.decode(Data("{\"id\":7,\"receipt\":\(body)}".utf8),
            for: request, context: context)
        guard case .receipt(let actual) = decoded else { Issue.record("missing receipt"); return }
        #expect(actual == receipt)
        // Actual outer request-ID correlation is exercised by WorkloadTests;
        // this value-only projection validates the complete receipt schema.
        #expect(throws: Control.Failure.invalidConfiguration) {
            try Control.Receipt(schema: 4, store: id, volume: id,
                attachment: id, launch: id, revision: 1)
        }
        #expect(throws: ManagedStorageControlClient.Failure.protocolViolation) {
            try ManagedStorageControlClient.decode(Data("{\"id\":7,\"receipt\":\(body.replacingOccurrences(of: "\"schema\":3", with: "\"schema\":4"))}".utf8),
                for: request, context: context)
        }
    }

    @Test func canonicalJSONRetainsGoEscapingAndIntegerPrecision() throws {
        let request = Control.ControlRequest.createVolume(try .init(operation: id,
            store: id, volume: id, name: "<>&/\u{2028}\u{2029}"))
        let expected = "{\"create_volume\":{\"name\":\"\\u003c\\u003e\\u0026/\\u2028\\u2029\",\"operation\":\"\(id)\",\"store\":\"\(id)\",\"volume\":\"\(id)\"},\"id\":0}"
        #expect(try request.durableBytes() == Data(expected.utf8))
        let bytes = Data("{\"revision\":18446744073709551615}".utf8)
        #expect(try ControllerJSON.parse(bytes, limit: 1024) == .object(["revision": .number(.max)]))
        for malformed in ["{\"id\":1,\"id\":2}", "{\"id\":01}", "{\"id\":18446744073709551616}"] {
            #expect(throws: Control.Failure.protocolViolation) {
                try ControllerJSON.parse(Data(malformed.utf8), limit: 1024)
            }
        }
    }
}

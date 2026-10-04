import Foundation
import Testing
@testable import CEngineRuntime
import CEngineCore

@Suite @MainActor struct OriginalConsumerObservationLeaseTests {
    @Test func armDoesNotDeferStop() throws {
        let lease = OriginalConsumerObservationLease()
        try lease.arm("one")
        #expect(lease.stop(.storageTerminal, now: 1) == nil)
        #expect(lease.closed && lease.pendingStop)
        #expect(throws: (any Error).self) { try lease.begin("one", now: 2) }
    }
    @Test func beginIsFixedAndCannotRenew() throws {
        let lease = OriginalConsumerObservationLease()
        try lease.arm("one"); try lease.begin("one", now: 100)
        #expect(lease.deadline == 10_000_000_100)
        #expect(throws: (any Error).self) { try lease.begin("one", now: 200) }
        #expect(lease.stop(.storageTerminal, now: 1_000) == 10_000_000_100)
        #expect(lease.stop(.storageTerminal, now: 2_000) == 10_000_000_100)
        #expect(lease.stop(.storageTerminal, now: 10_000_000_100) == nil)
        #expect(lease.closed && lease.pendingStop)
    }
    @Test func forcedStopNeverDefersAndReleaseCannotRearm() throws {
        let lease = OriginalConsumerObservationLease()
        try lease.arm("one"); try lease.begin("one", now: 1)
        #expect(lease.stop(.forced, now: 2) == nil)
        #expect(throws: (any Error).self) { try lease.require("one", now: 3) }
        try lease.release("one")
        #expect(throws: (any Error).self) { try lease.arm("two") }
        #expect(throws: (any Error).self) { try lease.release("two") }
    }
    @Test func cancellationAndWrongBindingCannotPass() throws {
        let lease = OriginalConsumerObservationLease()
        try lease.arm("one"); try lease.begin("one", now: 1)
        #expect(throws: (any Error).self) { try lease.require("two", now: 2) }
        lease.cancel()
        #expect(throws: (any Error).self) { try lease.require("one", now: 2) }
        #expect(lease.stop(.storageTerminal, now: 2) == nil)
    }
    @Test func guestPayloadHasExactOwnerBindingAndNoCallerDeadline() throws {
        typealias Wire = OriginalConsumerObservationProtocol
        let id = "11111111-1111-4111-8111-111111111111"
        let other = "22222222-2222-4222-8222-222222222222"
        let hash = String(repeating: "ab", count: 32)
        let binding = Wire.Binding(requestID: id, armDigest: hash, operationUUID: other,
            caseName: .crossEOldLeafReconnect, generation: 7,
            boot: .init(shimLaunchUUID: id, guestBootNonce: other),
            scope: .init(intent: id, store: other, serviceEpoch: other, controllerEpoch: 1,
                controllerKey: hash, container: hash, containerInstance: other, launch: id,
                prepare: other, specificationDigest: hash),
            targetAttachment: other, key: hash, certificateSHA256: hash)
        let payload = try JSONEncoder().encode(Wire.GuestArm(binding))
        let request = Wire.Request(binding: binding, command: .arm, payload: payload)
        try Wire.validate(request)
        var object = try #require(JSONSerialization.jsonObject(with: payload) as? [String: Any])
        object["deadlineNanoseconds"] = 99999999
        let extended = Wire.Request(binding: binding, command: .arm,
            payload: try JSONSerialization.data(withJSONObject: object))
        #expect(throws: (any Error).self) { try Wire.validate(extended) }
        object.removeValue(forKey: "deadlineNanoseconds")
        object["requestID"] = other
        let changed = Wire.Request(binding: binding, command: .arm,
            payload: try JSONSerialization.data(withJSONObject: object))
        #expect(throws: (any Error).self) { try Wire.validate(changed) }
        #expect(throws: (any Error).self) {
            try Wire.validateReply(Data("{\"success\":true}".utf8), request: request)
        }
    }

    @Test func fullInventoryRemainsClosedAndFinite() {
        #expect(OriginalConsumerObservationProtocol.Case.allCases.count == 18)
        #expect(OriginalConsumerObservationProtocol.Command(rawValue: "guest") == nil)
    }
}

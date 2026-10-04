import Foundation
import Testing
@testable import CEngineCore

@Suite struct SameECapabilityObservationTests {
    typealias C = ConsumerObservationProtocol
    typealias O = OriginalConsumerObservationProtocol

    @Test func capabilityProofHasClosedVersionedFields() throws {
        let observed = SameEConsumerObservationProtocolTests().fixture(.sameERetainedFD).3
        for state in [C.State.observed, .finalized] {
            var value = observed; value.state = state
            #expect(try C.decodeStatus(JSONEncoder().encode(value)) == value)
            for fault in ["name", "missing-name", "auth", "missing-auth", "no-handle", "handle", "write", "node", "sequence", "version"] {
                var bad = value
                switch fault {
                case "name": bad.evidence?.admission?.capabilityName = "user.capability"
                case "missing-name": bad.evidence?.admission?.capabilityName = nil
                case "auth": bad.evidence?.admission?.authKind = 2
                case "missing-auth": bad.evidence?.admission?.authKind = nil
                case "no-handle": bad.evidence?.admission?.noHandle = nil
                case "handle": bad.evidence?.admission?.handle = 0
                case "write": bad.evidence?.admission?.writeOneAtZero = false
                case "node": bad.evidence?.admission?.node = 0
                case "sequence": bad.evidence?.admission?.requestSequence = 0
                default: bad.query.version = 7
                }
                #expect(throws: (any Error).self) { try C.decodeStatus(JSONEncoder().encode(bad)) }
            }
        }
        let object = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(observed)) as? [String: Any])
        let evidence = try #require(object["evidence"] as? [String: Any])
        let admission = try #require(evidence["admission"] as? [String: Any])
        #expect(Set(admission.keys) == ["original", "requestSequence", "operation", "node", "authKind", "noHandle", "capabilityName"])
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
        var legacy = SameEConsumerObservationProtocolTests().legacyWriteWorker()
        legacy.evidence?.admission?.capabilityName = "security.capability"
        #expect(throws: (any Error).self) { try C.decodeStatus(JSONEncoder().encode(legacy)) }
    }
}

#if os(macOS)
import CEngineCore
import Foundation
import Testing
@testable import CEngineRuntime

@Suite struct OriginalConsumerRecoveredPositiveTests {
    @Test(arguments: ["valid", "cached-arm", "cached-begun", "sequence", "node", "mount", "key", "denial", "fsync", "extra", "null", "wrong-case", "no-prior"])
    func exactMatchingFIFOPositive(_ fault: String) throws {
        typealias O = OriginalConsumerObservationProtocol
        let id = UUID().uuidString.lowercased(), hash = String(repeating: "a", count: 64)
        let binding = O.Binding(requestID: id, armDigest: hash, operationUUID: id,
            caseName: fault == "wrong-case" ? .delayedRegistration : .sameEExistingData, generation: 1,
            boot: .init(shimLaunchUUID: id, guestBootNonce: id), scope: .init(intent: id, store: id,
                serviceEpoch: id, controllerEpoch: 2, controllerKey: hash, container: hash,
                containerInstance: id, launch: id, prepare: id, specificationDigest: hash),
            targetAttachment: id, key: hash, certificateSHA256: hash)
        var json: [String: Any] = ["arm": try JSONSerialization.jsonObject(with: JSONEncoder().encode(O.GuestArm(binding))),
            "stage": "begun", "scope": try JSONSerialization.jsonObject(with: JSONEncoder().encode(binding.scope)),
            "keySHA256": hash, "mountIdentitySHA256": hash, "serverDERSHA256": "", "signCount": 0, "signInputSHA256": "",
            "bytesWrittenAfterSign": 0, "clientWrittenBytes": 0, "clientPrefixBytes": 0, "clientPrefixSHA256": "", "localError": "",
            "fdOperation": "fsync-directory", "fdSequence": 1, "rootRequest": ["node": 99, "requestSequence": 7],
            "originalOperation": ["kind": "data-getattr-root", "sequence": 1, "errorClass": "ok"]]
        let previous = try JSONDecoder().decode(O.Evidence.self, from: JSONSerialization.data(withJSONObject: json))
        json["stage"] = "original-data-positive"
        json["rootRequest"] = ["node": 99, "requestSequence": 8]
        json["originalOperation"] = ["kind": "data-getattr-root", "sequence": 2, "errorClass": "ok"]
        switch fault {
        case "cached-arm": json["stage"] = "armed-mounted-positive"
        case "cached-begun": json["stage"] = "begun"
        case "sequence": json["rootRequest"] = ["node": 99, "requestSequence": 7]
        case "node": json["rootRequest"] = ["node": 1, "requestSequence": 8]
        case "mount": json["mountIdentitySHA256"] = String(repeating: "b", count: 64)
        case "key": json["keySHA256"] = String(repeating: "b", count: 64)
        case "denial": json["originalOperation"] = ["kind": "data-getattr-root", "sequence": 2, "errorClass": "transport-failed"]
        case "fsync": json["originalOperation"] = ["kind": "fsync-directory", "sequence": 2, "errorClass": "ok"]
        case "extra": json["snapshotProof"] = true
        case "null": json["rootRequest"] = NSNull()
        default: break
        }
        let request = O.Request(binding: binding, command: .positive, payload: try JSONEncoder().encode(O.GuestArm(binding)))
        let bytes = try JSONSerialization.data(withJSONObject: json)
        if fault == "valid" {
            let value = try O.checkedReply(bytes, request: request, previous: previous).evidence
            #expect(value?.rootRequest?.requestSequence == 8 && value?.originalOperation.errorClass == "ok")
        } else {
            #expect(throws: (any Error).self) { try O.checkedReply(bytes, request: request, previous: fault == "no-prior" ? nil : previous) }
        }
    }
}
#endif

#if os(macOS)
import CEngineCore
import Foundation
import Testing
@testable import CEngineRuntime

@Suite @MainActor struct OriginalConsumerResumeTests {
    @Test(arguments: ["valid", "binding", "machine", "active", "begun", "cancelled", "released", "terminal"])
    func resumeCannotRenewOrReplaceOwner(_ fault: String) throws {
        let lease = OriginalConsumerObservationLease(), machine = NSObject(), other = NSObject()
        try lease.arm("arm"); try lease.bindMachine(machine)
        switch fault {
        case "active": _ = try lease.reserveExchange()
        case "begun": try lease.begin("arm", now: 1)
        case "cancelled": lease.cancel()
        case "released": try lease.release("arm")
        case "terminal": _ = lease.stop(.storageTerminal, now: 1)
        default: break
        }
        if fault == "valid" {
            try lease.requireResumable("arm", machine: machine)
            try lease.requireResumable("arm", machine: machine)
            #expect(lease.deadline == nil && lease.exchangeID == nil && !lease.closed)
        } else {
            #expect(throws: (any Error).self) { try lease.requireResumable(fault == "binding" ? "other" : "arm", machine: fault == "machine" ? other : machine) }
        }
    }
    @Test(arguments: [false, true])
    func guestRoundTripDoesNotReviveStoppedLease(stopped: Bool) throws {
        let lease = OriginalConsumerObservationLease(), machine = NSObject()
        try lease.arm("arm"); try lease.bindMachine(machine)
        try lease.requireResumable("arm", machine: machine)
        let exchange = try lease.reserveExchange()
        #expect(throws: (any Error).self) { try lease.requireResumable("arm", machine: machine) }
        if stopped { _ = lease.stop(.forced, now: 1) }
        #expect(lease.finishExchange(exchange))
        if stopped {
            #expect(throws: (any Error).self) { try lease.requireResumable("arm", machine: machine) }
        } else {
            try lease.requireResumable("arm", machine: machine)
            #expect(lease.deadline == nil && !lease.closed)
        }
    }
    @Test(arguments: ["valid", "stage", "mount", "key", "signature", "operation", "root", "previous", "extra"])
    func retainedPositiveMustMatchExactOriginal(_ fault: String) throws {
        typealias O = OriginalConsumerObservationProtocol
        let id = UUID().uuidString.lowercased(), hash = String(repeating: "a", count: 64)
        let binding = O.Binding(requestID: id, armDigest: hash, operationUUID: id, caseName: .sameEExistingData, generation: 1,
            boot: .init(shimLaunchUUID: id, guestBootNonce: id), scope: .init(intent: id, store: id, serviceEpoch: id, controllerEpoch: 1,
                controllerKey: hash, container: hash, containerInstance: id, launch: id, prepare: id, specificationDigest: hash),
            targetAttachment: id, key: hash, certificateSHA256: hash)
        var json: [String: Any] = ["arm": try JSONSerialization.jsonObject(with: JSONEncoder().encode(O.GuestArm(binding))),
            "stage": "armed-mounted-positive", "scope": try JSONSerialization.jsonObject(with: JSONEncoder().encode(binding.scope)),
            "keySHA256": hash, "mountIdentitySHA256": hash, "serverDERSHA256": "", "signCount": 0, "signInputSHA256": "",
            "bytesWrittenAfterSign": 0, "clientWrittenBytes": 0, "clientPrefixBytes": 0, "clientPrefixSHA256": "", "localError": "",
            "fdOperation": "fsync-directory", "fdSequence": 1, "rootRequest": ["node": 1, "requestSequence": 7],
            "originalOperation": ["kind": "data-getattr-root", "sequence": 1, "errorClass": "ok"]]
        let original = try JSONDecoder().decode(O.Evidence.self, from: JSONSerialization.data(withJSONObject: json))
        switch fault {
        case "stage": json["stage"] = "begun"
        case "mount": json["mountIdentitySHA256"] = ""
        case "key": json["keySHA256"] = String(repeating: "b", count: 64)
        case "signature": json["signCount"] = 1
        case "operation": json["originalOperation"] = ["kind": "fsync-directory", "sequence": 1, "errorClass": "ok"]
        case "root": json["rootRequest"] = ["node": 0, "requestSequence": 7]
        case "previous": json["mountIdentitySHA256"] = String(repeating: "b", count: 64)
        case "extra": json["newClient"] = true
        default: break
        }
        let request = O.Request(binding: binding, command: .resume, payload: try JSONEncoder().encode(O.GuestArm(binding)))
        let bytes = try JSONSerialization.data(withJSONObject: json)
        if fault == "valid" { #expect(try O.checkedReply(bytes, request: request, previous: original).evidence == original) }
        else { #expect(throws: (any Error).self) { try O.checkedReply(bytes, request: request, previous: original) } }
    }
}
#endif

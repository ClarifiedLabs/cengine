import CEngineCore
import Foundation
import Testing

@Suite("Neutral storage service values")
struct StorageServiceTypesTests {
    private let id = "11111111-1111-4111-8111-111111111111"
    private let hash = String(repeating: "a", count: 64)

    @Test func diskBindingAndLifecycleAliasesPreserveValueSemantics() throws {
        let binding = DiskInitializationProtocol.Binding(shimLaunchUUID: id, guestBootNonce: id,
            ext4UUID: "11111111-1111-1111-1111-111111111111", bytes: UInt64(Int64.max))
        let lifecycleBinding: StorageLifecycleServiceBootProtocol.Binding = binding
        #expect(lifecycleBinding == binding)
        #expect(try JSONDecoder().decode(DiskInitializationProtocol.Binding.self,
            from: JSONEncoder().encode(binding)) == binding)
        let controller = StorageServiceTypes.Controller(epoch: UInt64.max, key: hash)
        let lifecycleController: StorageLifecycleServiceBootProtocol.Controller = controller
        #expect(lifecycleController == controller)
        var copy = controller
        copy.epoch = 1
        #expect(controller.epoch == UInt64.max)
        #expect(copy != controller)
    }

    @Test func boundsAndUUIDContractsAreUnchanged() {
        #expect(StorageServiceTypes.maxFrame == 65_536)
        #expect(StorageServiceTypes.maximumDERSize == 16_384)
        #expect(StorageServiceTypes.maximumNotifications == 32)
        #expect(StorageServiceTypes.maximumLifetimeSeconds == 86_400)
        #expect(StorageServiceTypes.maximumUnixSeconds == 253_402_214_399)
        #expect(StorageServiceTypes.validID(id))
        let filesystemUUID = "11111111-1111-1111-1111-111111111111"
        #expect(StorageServiceTypes.validUUID(filesystemUUID))
        #expect(!StorageServiceTypes.validID(filesystemUUID))
        for invalid in ["", "00000000-0000-0000-0000-000000000000", id + " ", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"] {
            #expect(!StorageServiceTypes.validUUID(invalid))
        }
    }

    @Test func isolationComparisonsRemainEvidenceOnly() throws {
        let request = StorageServiceTypes.IsolationRequest(requestID: id, operationUUID: id,
            armDigest: hash, challenge: id)
        func proof(_ name: String, result: String, revision: UInt64 = 1) throws -> StorageServiceTypes.IsolationProof {
            let fields: [String: Any] = ["request": try JSONSerialization.jsonObject(with: JSONEncoder().encode(request)),
                "workerUUID": id, "caseName": name, "store": id, "serviceEpoch": id,
                "revision": revision, "registrySHA256": hash, "result": result]
            return try JSONDecoder().decode(StorageServiceTypes.IsolationProof.self,
                from: JSONSerialization.data(withJSONObject: fields))
        }
        let before = try proof("isolation-state", result: "registry-state")
        let observation = try proof("legacy-connection", result: "legacy-tls-header-rejected")
        _ = try StorageServiceTypes.IsolationStatePair(before: before, after: before)
        let receipt = try StorageServiceTypes.IsolationReceipt(before: before, observation: observation, after: before)
        #expect(receipt.observation == observation)
        #expect(throws: StorageServiceTypes.ValidationError.invalidFrame) {
            try StorageServiceTypes.IsolationStatePair(before: before,
                after: proof("isolation-state", result: "registry-state", revision: 2))
        }
        #expect(throws: StorageServiceTypes.ValidationError.invalidFrame) {
            try StorageServiceTypes.IsolationReceipt(before: before,
                observation: proof("legacy-connection", result: "legacy-tls-header-rejected", revision: 2), after: before)
        }
        // Preserve the value/codec boundary: public Codable data alone is not proof
        // of valid IDs, a valid result, authenticated transport, or lifecycle authority.
        let invalid = StorageServiceTypes.Controller(epoch: 0, key: "not-a-key")
        #expect(try JSONDecoder().decode(StorageServiceTypes.Controller.self,
            from: JSONEncoder().encode(invalid)) == invalid)
    }
}

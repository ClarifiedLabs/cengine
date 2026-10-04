#if os(macOS)
import CEngineCore
import Foundation
@testable import CEngineRuntime
import Testing

@Suite struct StorageLifecycleCompatibilityFaultPolicyTests {
    typealias Policy = StorageLifecycleCompatibilityFaultPolicy

    @Test func firstColdCompletionOnlyAndSealedMetadata() throws {
        #expect(Policy.isFirstColdCompletion(expectedEpoch: 1)) // C2
        for epoch in [UInt64(0), 2, 3, .max] {
            #expect(!Policy.isFirstColdCompletion(expectedEpoch: epoch))
        }
        let valid: [String: Any] = ["CEngineCompatLifecycleFault": "after-first-cold-completion-v1"]
        #expect(try Policy.validateFields(namespace: .compatibility, isQualification: false,
            plist: valid) == .afterFirstColdCompletion)
        #expect(throws: (any Error).self) {
            try Policy.validateFields(namespace: .production, isQualification: false, plist: valid)
        }
        #expect(throws: (any Error).self) {
            try Policy.validateFields(namespace: .compatibility, isQualification: true, plist: valid)
        }
        for key in ["CEngineStorageLifecycleQualification", "CEngineStorageLifecycleSourcePin", "CEngineStorageLifecycleAssetsSHA256"] {
            var mixed = valid
            mixed[key] = "selected"
            #expect(throws: (any Error).self) {
                try Policy.validateFields(namespace: .compatibility, isQualification: false, plist: mixed)
            }
        }
    }

    @Test func freshOnly() {
        #expect(Policy.applies(to: .initialize))
        #expect(!Policy.applies(to: .resumeOpenTakeover))
        #expect(!Policy.applies(to: .coldOpenTakeover))
        #expect(!Policy.applies(to: .open))
    }

    @Test func replacementDiagnosticIsBoundedPublicObservation() throws {
        typealias L = StorageLifecycleProtocol
        struct Fixture: Decodable {
            struct Vector: Decodable { let value: L.SignedServiceChange }
            let vectors: [Vector]
        }
        let file = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Fixtures/storage-bootstrap/lifecycle-service-change-v2.json")
        let change = try #require(JSONDecoder().decode(Fixture.self, from: Data(contentsOf: file)).vectors.first).value.request
        let before = change.predecessor, epoch = UUID().uuidString.lowercased()
        let after = try L.ServiceState(grant: before.grant,
            context: .init(serviceEpoch: epoch, controllerEpoch: before.context.controllerEpoch, controllerKey: before.context.controllerKey),
            openRevision: before.openRevision + 1,
            boot: .init(identity: before.boot.identity, serviceEpoch: epoch,
                tlsRootSHA256: String(repeating: "c", count: 64), serverSPKI: String(repeating: "d", count: 64),
                bootstrapKey: before.boot.bootstrapKey))
        let observation = try L.ServiceChangeConfirmation(request: change, successor: after)
        let predecessor = UUID().uuidString.lowercased(), worker = UUID().uuidString.lowercased()
        let bytes = try Policy.replacementObservation(observation, predecessorWorkerUUID: predecessor, workerUUID: worker)
        let decoded = try L.decode(Policy.ReplacementObservation.self, from: bytes)
        #expect(decoded.observation == observation)
        #expect(decoded.predecessorWorkerUUID == predecessor && decoded.workerUUID == worker)
        #expect(bytes.count < 8192 && !bytes.contains(10))
        for bad in [predecessor, "", "invalid", worker.uppercased()] {
            #expect(throws: (any Error).self) {
                try Policy.replacementObservation(observation, predecessorWorkerUUID: predecessor, workerUUID: bad)
            }
        }
    }

    @Test func takeoverDiagnosticIsClosedPublicObservation() throws {
        typealias L = StorageLifecycleProtocol
        let identity = try L.Identity(store: UUID().uuidString.lowercased(), generation: 1,
            binding: String(repeating: "a", count: 64))
        let grant = try L.Grant(operation: .takeover, id: UUID().uuidString.lowercased(), identity: identity,
            serial: 2, expectedEpoch: 1, newKey: String(repeating: "b", count: 64))
        let epoch = UUID().uuidString.lowercased(), worker = UUID().uuidString.lowercased()
        let bytes = try Policy.takeoverObservation(grant: grant, serviceEpoch: epoch, workerUUID: worker, openRevision: 1)
        let value = try L.decode(Policy.TakeoverObservation.self, from: bytes)
        #expect(value.grant == grant && value.serviceEpoch == epoch && value.workerUUID == worker)
        #expect(value.openRevision == 1 && bytes.count <= 8192 && !bytes.contains(10))
        for bad in ["", "invalid", worker.uppercased()] {
            #expect(throws: (any Error).self) {
                try Policy.takeoverObservation(grant: grant, serviceEpoch: epoch, workerUUID: bad, openRevision: 1)
            }
        }
        #expect(throws: (any Error).self) {
            try Policy.takeoverObservation(grant: grant, serviceEpoch: epoch, workerUUID: worker, openRevision: 0)
        }
        for profile in [Policy.Profile.beforeTakeoverApply, .afterTakeoverApply] {
            #expect(try Policy.validateFields(namespace: .compatibility, isQualification: false,
                plist: ["CEngineCompatLifecycleFault": profile.rawValue]) == profile)
        }
    }

    @Test func exactOrdinaryMetadataOnly() throws {
        let valid: [String: Any] = ["CEngineCompatLifecycleFault": "before-configure-v1"]
        #expect(try Policy.validateFields(namespace: .compatibility, isQualification: false, plist: valid) == .beforeConfigure)
        #expect(try Policy.validateFields(namespace: .compatibility, isQualification: false,
            plist: ["CEngineCompatLifecycleFault": "after-replacement-before-completion-v1"]) == .afterReplacement)
        #expect(throws: (any Error).self) {
            try Policy.validateFields(namespace: .production, isQualification: false, plist: valid)
        }
        #expect(throws: (any Error).self) {
            try Policy.validateFields(namespace: .compatibility, isQualification: true, plist: valid)
        }
        for value: Any in ["", "before-configure-v2", " before-configure-v1", "before-takeover-apply-v2", "after-takeover-apply-v1 ",
                           "after-first-cold-completion-v2", "after-first-cold-completion-v1 ", 1, true] {
            #expect(throws: (any Error).self) {
                try Policy.validateFields(namespace: .compatibility, isQualification: false,
                    plist: ["CEngineCompatLifecycleFault": value])
            }
        }
        #expect(throws: (any Error).self) {
            try Policy.validateFields(namespace: .compatibility, isQualification: false, plist: [:])
        }
        for key in ["CEngineStorageLifecycleQualification", "CEngineStorageLifecycleSourcePin", "CEngineStorageLifecycleAssetsSHA256"] {
            var plist = valid
            plist[key] = ""
            try Policy.validateFields(namespace: .compatibility, isQualification: false, plist: plist)
            for value: Any in ["lifecycle-v2-native-v1", 1, false] {
                plist[key] = value
                #expect(throws: (any Error).self) {
                    try Policy.validateFields(namespace: .compatibility, isQualification: false, plist: plist)
                }
            }
        }
    }
}
#endif

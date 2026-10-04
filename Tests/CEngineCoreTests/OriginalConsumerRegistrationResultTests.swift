#if os(macOS)
import CEngineCore
import Foundation
import Testing
@testable import CEngineRuntime

@MainActor @Suite struct OriginalConsumerRegistrationResultTests {
    typealias O = OriginalConsumerObservationProtocol
    typealias C = ManagedStorageControlClient
    typealias P = ManagedStorageControlProtocol
    typealias R = OriginalConsumerRuntimeCarrier.Result

    // Foundation sortedKeys uses a different ordering from the carrier's lexical
    // canonical JSON. Preserve unknown/null fields so negative tests are real.
    func canonicalObject(_ value: Any) throws -> Data {
        func text(_ value: Any) throws -> String {
            if let object = value as? [String: Any] {
                return "{" + (try object.keys.sorted().map { key in
                    try text(key) + ":" + text(object[key]!)
                }).joined(separator: ",") + "}"
            }
            if let array = value as? [Any] { return "[" + (try array.map(text)).joined(separator: ",") + "]" }
            return String(decoding: try JSONSerialization.data(withJSONObject: value,
                options: [.fragmentsAllowed, .withoutEscapingSlashes]), as: UTF8.self)
        }
        return Data(try text(value).utf8)
    }

    func fixture(_ name: O.Case, schema: UInt64 = 3) throws -> (R, O.Binding, ConsumerObservationProtocol.WorkerScope) {
        let f = SameEConsumerObservationProtocolTests()
        let (old, first, last, status) = f.fixture(name)
        var scope = old.scope; scope.controllerKey = String(repeating: "ef", count: 32)
        let binding = O.Binding(requestID: old.requestID, armDigest: old.armDigest, operationUUID: old.operationUUID,
            caseName: name, generation: old.generation, boot: old.boot, scope: scope,
            targetAttachment: old.targetAttachment, key: old.key, certificateSHA256: old.certificateSHA256)
        var positive = first, original = last
        positive.arm = .init(binding); positive.scope = scope
        original.arm = .init(binding); original.scope = scope
        var final = status; final.state = .finalized
        let issued = status.query.original.binding
        let exact = try P.Binding(store: issued.store, volume: issued.volume, attachment: issued.attachment,
            container: issued.container, launch: issued.launch, key: issued.key, role: .runtime, mode: .readOnly)
        let operation = "33333333-3333-4333-8333-333333333333"
        let register = "44444444-4444-4444-8444-444444444444"
        let attemptedID = "55555555-5555-4555-8555-555555555555"
        let before = C.Snapshot(schema: schema, revision: 5,
            store: .init(id: scope.store, deviceID: "owned", root: .init(device: 1, inode: 1), exports: .init(device: 1, inode: 2)),
            epoch: scope.serviceEpoch, controller: .init(epoch: scope.controllerEpoch, key: scope.controllerKey),
            volumes: [exact.volume: .init(id: exact.volume, name: "original", root: .init(device: 1, inode: 3))],
            volumeLifecycles: [exact.volume: .init(phase: .ready, create: nil, delete: nil, createdRevision: nil, deletedRevision: nil)],
            attachments: [exact.attachment: .init(binding: exact, phase: .active, receipt: nil, retirement: nil)], prepares: [:])
        let receipt = try P.Receipt(schema: 3, store: exact.store, volume: exact.volume, attachment: exact.attachment, launch: exact.launch, revision: 6)
        let drained = C.Attachment(binding: exact, phase: .drained, receipt: receipt, retirement: operation)
        let after = C.Snapshot(schema: schema, revision: 7, store: before.store, epoch: before.epoch, controller: before.controller,
            volumes: before.volumes, volumeLifecycles: before.volumeLifecycles, attachments: [exact.attachment: drained], prepares: [:])
        let retired = ManagedVolumeLifecycleCoordinator.OriginalRetirement(operation: operation, receipt: receipt,
            queryRevision: 7, epoch: before.epoch, controller: before.controller, attachment: drained)
        let authority = ManagedVolumeLifecycleCoordinator.OriginalRootAuthority(before: before, atProbe: after, after: after, retirement: retired)
        let attempted = name == .delayedRegistration ? exact : try P.Binding(store: exact.store, volume: exact.volume,
            attachment: attemptedID, container: exact.container, launch: exact.launch, key: exact.key, role: exact.role, mode: exact.mode)
        let peer = try JSONDecoder().decode(O.Probe.self, from: f.request(binding, .probe).payload).peer
        func json<T: Encodable>(_ value: T) throws -> Any { try JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) }
        let registration: [String: Any] = ["binding": try json(binding), "operation": name == .delayedRegistration ? register : attemptedID,
            "originalRegisterOperation": register, "attempted": try json(attempted), "denial": name == .delayedRegistration ? "BLOCKED" : "CONFLICT",
            "authority": try json(authority), "service": try json(status.query.workerScope), "peer": try json(peer), "observed": try json(status)]
        let result: [String: Any] = ["worker": try json(final), "original": try json(original), "positive": try json(positive),
            "retirement": try json(retired), "registration": registration]
        let decoded = try ManagedPrepareCompatibilityProtocol.decode(R.self, from: canonicalObject(result))
        return (decoded, binding, status.query.workerScope)
    }

    @Test(arguments: [O.Case.attachmentKeyReuse, .delayedRegistration])
    func controlDenialJoinsOriginalPositiveRetirementAndRealAdmit(_ name: O.Case) throws {
        let (result, binding, service) = try fixture(name)
        try result.validateRegistration(binding: binding, service: service)
        #expect(OriginalConsumerRuntimeCarrier.FreshGetattr.required(name))
        let selection = OriginalConsumerRuntimeCarrier.Request(version: 1, profile: binding.profile,
            requestID: binding.requestID, operationUUID: binding.operationUUID, caseName: name,
            container: binding.scope.container, containerInstance: binding.scope.containerInstance)
        try selection.validate()
    }

    @Test(arguments: [O.Case.attachmentKeyReuse, .delayedRegistration])
    func lifecycleRegistryRequiresPinnedIdentity(_ name: O.Case) throws {
        let (result, binding, service) = try fixture(name, schema: 4)
        let identity = try StorageLifecycleProtocol.Identity(store: binding.scope.store,
            generation: 2, binding: String(repeating: "78", count: 32))
        try result.validateRegistration(binding: binding, service: service, lifecycleIdentity: identity)
        let decoded = try ManagedPrepareCompatibilityProtocol.decode(R.self,
            from: ManagedPrepareCompatibilityProtocol.canonicalData(result))
        try decoded.validateRegistration(binding: binding, service: service, lifecycleIdentity: identity)
        #expect(throws: C.Failure.protocolViolation) {
            try result.validateRegistration(binding: binding, service: service)
        }
        let wrongStore = try StorageLifecycleProtocol.Identity(store: binding.scope.serviceEpoch,
            generation: identity.generation, binding: identity.binding)
        #expect(throws: C.Failure.invalidContext) {
            try result.validateRegistration(binding: binding, service: service, lifecycleIdentity: wrongStore)
        }
        let (legacy, legacyBinding, legacyService) = try fixture(name)
        #expect(throws: C.Failure.protocolViolation) {
            try legacy.validateRegistration(binding: legacyBinding, service: legacyService, lifecycleIdentity: identity)
        }
    }

    @Test(arguments: [O.Case.attachmentKeyReuse, .delayedRegistration],
        ["none", "successor", "missing", "disk-only", "store", "service", "worker", "controller", "key", "tampered"])
    func pinnedQueueUsesIndependentLifecycleIdentity(_ name: O.Case, _ fault: String) throws {
        let (result, binding, service) = try fixture(name, schema: 4)
        try OriginalConsumerRootResultTests().checkLifecycleQueue(result, binding: binding, service: service, fault: fault)
    }

    @Test(arguments: [O.Case.attachmentKeyReuse, .delayedRegistration])
    func strictResultRejectsMissingProofAndSubstitutions(_ name: O.Case) throws {
        let (result, binding, service) = try fixture(name)
        let root = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(result)) as? [String: Any])
        func reject(_ value: [String: Any]) {
            #expect(throws: (any Error).self) {
                let decoded = try ManagedPrepareCompatibilityProtocol.decode(R.self, from: canonicalObject(value))
                try decoded.validateRegistration(binding: binding, service: service)
            }
        }
        for key in root.keys {
            var bad = root; bad.removeValue(forKey: key); reject(bad)
            bad = root; bad[key] = NSNull(); reject(bad)
        }
        var unknown = root; unknown["extra"] = true; reject(unknown)
        for fault in ["denial", "operation", "register", "attempted", "worker", "peer", "after", "positive", "finalization"] {
            var bad = root
            var proof = try #require(bad["registration"] as? [String: Any])
            switch fault {
            case "denial": proof["denial"] = "UNAUTHORIZED"
            case "operation": proof["operation"] = result.retirement?.operation
            case "register": proof["originalRegisterOperation"] = result.retirement?.operation
            case "attempted":
                var attempt = try #require(proof["attempted"] as? [String: Any]); attempt["key"] = String(repeating: "cd", count: 32); proof["attempted"] = attempt
            case "worker":
                var worker = try #require(proof["service"] as? [String: Any]); worker["workerUUID"] = binding.requestID; proof["service"] = worker
            case "peer":
                var peer = try #require(proof["peer"] as? [String: Any]); peer["serverDER"] = Data([9]).base64EncodedString(); proof["peer"] = peer
            case "after":
                var authority = try #require(proof["authority"] as? [String: Any]); authority["after"] = authority["before"]; proof["authority"] = authority
            case "positive": bad.removeValue(forKey: "positive")
            default: bad["worker"] = proof["observed"]
            }
            bad["registration"] = proof; reject(bad)
        }
    }
}
#endif

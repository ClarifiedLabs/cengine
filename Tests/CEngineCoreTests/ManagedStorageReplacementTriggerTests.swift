import CEngineCore
import CryptoKit
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

@Suite struct ManagedStorageReplacementTriggerTests {
    private typealias Queue = ManagedStorageReplacementQueue

    private func request() -> Queue.Request {
        .init(operationUUID: UUID().uuidString.lowercased(), store: UUID().uuidString.lowercased(),
              predecessor: .init(serviceEpoch: UUID().uuidString.lowercased(), workerUUID: UUID().uuidString.lowercased()))
    }
    private func fixture(_ body: (URL, Queue) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        // Match CanonicalDataStoreLock.root: Foundation's symlink resolver can
        // rewrite physical /private/var back to the /var symlink on macOS.
        let physicalPath = Darwin.realpath(root.path, nil)
        let resolved = try #require(physicalPath)
        defer { free(resolved) }
        let canonical = URL(filePath: String(cString: resolved), directoryHint: .isDirectory)
        try body(canonical, Queue(root: canonical))
    }
    private func marker(_ root: URL) -> URL {
        root.appending(path: Queue.directoryName).appending(path: "request.json")
    }
    private func put(_ bytes: Data, at path: URL) throws {
        try bytes.write(to: path)
        #expect(chmod(path.path, 0o600) == 0)
    }

    @Test func unsignedCannotActivate() throws {
        #expect(throws: (any Error).self) { try ManagedStorageReplacementTrigger.permitsActivation() }
    }

    @MainActor private func lifecycleFixture(intentRevision: UInt64 = 1) throws -> (Queue.OwnerObservation, Queue.Request) {
        typealias C = ManagedStorageLifecycleCheckpoint
        typealias L = StorageLifecycleProtocol
        let value = request(), root = Curve25519.Signing.PrivateKey(), child = Curve25519.Signing.PrivateKey()
        let identity = try L.Identity(store: value.store, generation: 1, binding: String(repeating: "b", count: 64))
        let grant = try L.Grant(operation: .initialize, id: UUID().uuidString.lowercased(), identity: identity,
            serial: 1, expectedEpoch: 0, newKey: StorageIdentity.Ed25519SPKI(rawPublicKey: child.publicKey.rawRepresentation).fingerprint.rawValue)
        let pending = try C.GrantContext(signed: .init(grant: grant, signature: root.signature(for: grant.signingBytes)),
            recipient: .init(publicKey: child.publicKey.rawRepresentation, incarnation: UUID().uuidString.lowercased(),
                daemonUniqueID: 2, childUniqueID: 3, childPID: 42), requestID: UUID().uuidString.lowercased(), serviceEpoch: nil)
        let intents = HostStorageIntents.State(schema: 2, store: value.store, revision: intentRevision,
            volumes: [:], intents: [:], operations: [:], operationDigests: [:], reconciliationRequired: false)
        var state = try C.baseline(identity: identity, rootPublicKey: root.publicKey.rawRepresentation,
            provenanceReference: String(repeating: "a", count: 64), initialize: pending)
        state = try C.applying(.complete(.init(grant: grant, nonce: Data(repeating: 7, count: 32),
            serviceEpoch: value.predecessor.serviceEpoch, revision: 1)), to: state, intents: intents)
        let context = try #require(state.currentContext)
        let service = try L.ServiceState(grant: grant,
            context: .init(serviceEpoch: context.serviceEpoch, controllerEpoch: context.controllerEpoch, controllerKey: context.controllerKey),
            openRevision: 1, boot: .init(identity: identity, serviceEpoch: context.serviceEpoch,
                tlsRootSHA256: String(repeating: "c", count: 64), serverSPKI: String(repeating: "d", count: 64),
                bootstrapKey: StorageIdentity.RootPublicKey(publicData: root.publicKey.rawRepresentation).fingerprint.rawValue))
        state = try C.applying(.recordService(service), to: state, intents: intents)
        state = try C.applying(.recordObservedWorker(.init(context: context, workerUUID: value.predecessor.workerUUID)),
            to: state, intents: intents)
        let rootID = PersistentFileIdentity(device: 1, inode: 2, volumeUUID: UUID())
        let ownerID = PersistentFileIdentity(device: 1, inode: 3, volumeUUID: rootID.volumeUUID)
        let lease = PersistentFileIdentity(device: 1, inode: 4, volumeUUID: rootID.volumeUUID)
        let manifest = C.Manifest(version: C.manifestVersion, identity: identity, rootPublicKey: state.rootPublicKey,
            provenanceReference: state.provenanceReference, root: rootID, directory: ownerID, lease: lease,
            backing: .init(device: 1, inode: 5, volumeUUID: rootID.volumeUUID), bytes: 4096, ext4UUID: UUID().uuidString.lowercased())
        let intentsID = PersistentFileIdentity(device: 1, inode: 6, volumeUUID: rootID.volumeUUID)
        let intentsLease = PersistentFileIdentity(device: 1, inode: 7, volumeUUID: rootID.volumeUUID)
        let intentsManifest = HostStorageIntents.Manifest(schema: 1, mode: "managed", store: value.store,
            provenanceReference: state.provenanceReference, root: rootID, directory: intentsID, lease: intentsLease)
        return (try .init(data: C.encode(state), rootDevice: 1, rootInode: 2, ownerDevice: 1, ownerInode: 3,
            manifestData: C.encode(manifest), intentsData: C.encode(intents), leaseIdentity: lease,
            rootIdentity: rootID, ownerIdentity: ownerID, intentsManifestData: C.encode(intentsManifest),
            intentsIdentity: intentsID, intentsLeaseIdentity: intentsLease), value)
    }

    @Test @MainActor func lifecycleMetadataIsCanonicalBoundedAndRejectionOnly() throws {
        typealias C = ManagedStorageLifecycleCheckpoint
        let (observation, value) = try lifecycleFixture()
        let proof = try ManagedStorageReplacementTrigger.validateOwner(observation, request: value)
        let state = try C.decode(observation.data)
        #expect(proof.controllerEpoch == state.currentContext?.controllerEpoch)
        #expect(proof.controllerKey == state.currentContext?.controllerKey)
        #expect(proof.rootPublicKey == state.rootPublicKey.base64EncodedString())
        #expect(Queue.maximumLifecycleOwnerBytes == C.maximumBytes)
        for changed in [Queue.Request(operationUUID: value.operationUUID, store: UUID().uuidString.lowercased(), predecessor: value.predecessor),
                        Queue.Request(operationUUID: value.operationUUID, store: value.store, predecessor: request().predecessor)] {
            #expect(throws: (any Error).self) { try ManagedStorageReplacementTrigger.validateOwner(observation, request: changed) }
        }
        var partial = observation; partial.manifestData = nil
        var copied = observation; copied.ownerIdentity = .init(device: 1, inode: 99)
        var copiedRoot = observation; copiedRoot.rootIdentity = .init(device: 1, inode: 98)
        var advanced = observation
        var intents = try JSONDecoder().decode(HostStorageIntents.State.self, from: #require(observation.intentsData))
        intents.revision += 1; advanced.intentsData = try C.encode(intents)
        // Revision equality with the last owner checkpoint is not an admission fence.
        _ = try ManagedStorageReplacementTrigger.validateOwner(advanced, request: value)
        var unreconciled = observation
        intents.reconciliationRequired = true; unreconciled.intentsData = try C.encode(intents)
        var copiedIntents = observation; copiedIntents.intentsIdentity = .init(device: 1, inode: 97)
        var copiedLease = observation; copiedLease.intentsLeaseIdentity = .init(device: 1, inode: 96)
        var partialIntents = observation; partialIntents.intentsManifestData = nil
        for bad in [partial, copied, copiedRoot, unreconciled, copiedIntents, copiedLease, partialIntents] {
            #expect(throws: (any Error).self) { try ManagedStorageReplacementTrigger.validateOwner(bad, request: value) }
        }
        var pending = state
        pending.pendingService = try .init(request: .init(operationID: UUID().uuidString.lowercased(), predecessor: #require(state.currentService)),
            stageRequestID: UUID().uuidString.lowercased(), completionRequestID: UUID().uuidString.lowercased(),
            predecessorWorkerUUID: value.predecessor.workerUUID, nowUnixSeconds: 100, lifetimeSeconds: 60)
        let wire = String(decoding: observation.data, as: UTF8.self)
        let badBytes = [observation.data + Data("\n".utf8), Data("{}".utf8),
            Data(wire.replacingOccurrences(of: "\"version\":", with: "\"unknown\":1,\"version\":").utf8),
            Data(wire.replacingOccurrences(of: state.current!.original.signed.signature.base64EncodedString(),
                with: Data(repeating: 0, count: 64).base64EncodedString()).utf8), try C.encode(pending)]
        for bytes in badBytes {
            let bad = Queue.OwnerObservation(data: bytes, rootDevice: 1, rootInode: 2, ownerDevice: 1, ownerInode: 3,
                manifestData: observation.manifestData, intentsData: observation.intentsData, leaseIdentity: observation.leaseIdentity,
                rootIdentity: observation.rootIdentity, ownerIdentity: observation.ownerIdentity,
                intentsManifestData: observation.intentsManifestData, intentsIdentity: observation.intentsIdentity,
                intentsLeaseIdentity: observation.intentsLeaseIdentity)
            #expect(throws: (any Error).self) { try ManagedStorageReplacementTrigger.validateOwner(bad, request: value) }
        }
    }

    @Test @MainActor func diagnosticDeviceChangesDoNotStrandReplacementProof() throws {
        let (observation, request) = try lifecycleFixture()
        let expected = try ManagedStorageReplacementTrigger.validateOwner(observation, request: request)
        func remap(_ value: PersistentFileIdentity?) throws -> PersistentFileIdentity {
            let identity = try #require(value)
            return .init(device: identity.device + 10, inode: identity.inode, volumeUUID: identity.volumeUUID)
        }
        func remounted(inconsistent: Bool = false) throws -> Queue.OwnerObservation {
            try .init(data: observation.data, rootDevice: observation.rootDevice + (inconsistent ? 11 : 10),
                rootInode: observation.rootInode, ownerDevice: observation.ownerDevice + 10,
                ownerInode: observation.ownerInode, manifestData: observation.manifestData,
                intentsData: observation.intentsData, leaseIdentity: remap(observation.leaseIdentity),
                rootIdentity: remap(observation.rootIdentity), ownerIdentity: remap(observation.ownerIdentity),
                intentsManifestData: observation.intentsManifestData, intentsIdentity: remap(observation.intentsIdentity),
                intentsLeaseIdentity: remap(observation.intentsLeaseIdentity))
        }
        let actual = try ManagedStorageReplacementTrigger.validateOwner(remounted(), request: request)
        #expect(actual.controllerEpoch == expected.controllerEpoch)
        #expect(actual.controllerKey == expected.controllerKey)
        #expect(actual.rootPublicKey == expected.rootPublicKey)
        // Current observations must remain internally exact, even though persisted
        // diagnostic devices no longer identify the durable owner.
        #expect(throws: (any Error).self) {
            try ManagedStorageReplacementTrigger.validateOwner(remounted(inconsistent: true), request: request)
        }
    }

    @MainActor private func workloadIntents(_ state: ManagedStorageLifecycleCheckpoint.Metadata,
        context: ManagedStorageLifecycleCheckpoint.Context) throws -> HostStorageIntents.State {
        let f = try HostIntentFixture(); defer { f.remove() }
        let journal = try HostStorageIntents.initialize(in: f.root, store: state.identity.store,
            provenanceReference: state.provenanceReference)
        try journal.reconciled()
        try journal.planVolumes(f.volumes)
        for volume in f.volumes {
            try journal.recordOperation(id: volume.createOperation, request: journal.request(for: volume.createOperation))
            let fresh = f.intent([volume])
            let intent = HostStorageIntents.Intent(id: fresh.id, store: state.identity.store,
                container: fresh.container, containerInstance: fresh.containerInstance, launch: fresh.launch,
                specificationDigest: fresh.specificationDigest, serviceEpoch: context.serviceEpoch,
                controllerEpoch: context.controllerEpoch, controllerKey: context.controllerKey,
                prepare: fresh.prepare, reserveOperation: fresh.reserveOperation, completeOperation: fresh.completeOperation,
                replaceOperation: fresh.replaceOperation, mounts: fresh.mounts, slots: fresh.slots,
                version: 1, phase: .planned, prepareCompleted: false, cleanUnmount: false)
            let token = try journal.plan(intent)
            _ = try journal.freezeKeys(token, role: .prepare, keys: f.offeredKeys(for: intent))
        }
        return try journal.checkedSnapshot()
    }

    @Test @MainActor func lifecycleAdvancedWorkloadCensusIsValidatedWithoutChangingCheckpoint() throws {
        typealias C = ManagedStorageLifecycleCheckpoint
        // Revision 2 represents the empty reconciled journal, before workload IO.
        var (observation, value) = try lifecycleFixture(intentRevision: 2)
        let original = observation.data, state = try C.decode(original)
        let context = try #require(state.currentContext)
        let intents = try workloadIntents(state, context: context)
        #expect(intents.revision > state.intentRevision)
        #expect(intents.volumes.count == 2 && intents.intents.count == 2 && intents.operations.count == 4)
        #expect(state.references.isEmpty)
        #expect(try !C.censusMatches(state, intents: intents))
        observation.intentsData = try C.encode(intents)
        let proof = try ManagedStorageReplacementTrigger.validateOwner(observation, request: value)
        #expect(proof.controllerEpoch == context.controllerEpoch && proof.controllerKey == context.controllerKey)
        #expect(observation.data == original)
        let projected = try C.applying(.recordService(#require(state.currentService)), to: state, intents: intents)
        #expect(projected.references.count == 2)
        #expect(try C.censusMatches(projected, intents: intents))
        #expect(projected.currentService == state.currentService && projected.observedWorker == state.observedWorker)

        var rewound = intents; rewound.revision = state.intentRevision - 1
        var malformed = intents
        let first = try #require(intents.intents.keys.sorted().first)
        malformed.intents[first]?.version = 0
        var incomplete = intents; incomplete.intents[first]?.predecessor = UUID().uuidString.lowercased()
        var unreconciled = intents; unreconciled.reconciliationRequired = true
        let unknown = try workloadIntents(state, context: .init(serviceEpoch: UUID().uuidString.lowercased(),
            controllerEpoch: context.controllerEpoch, controllerKey: context.controllerKey))
        for bad in [rewound, malformed, incomplete, unreconciled, unknown] {
            observation.intentsData = try C.encode(bad)
            #expect(throws: (any Error).self) {
                try ManagedStorageReplacementTrigger.validateOwner(observation, request: value)
            }
        }
        observation.intentsData = try C.encode(intents) + Data("\n".utf8)
        #expect(throws: (any Error).self) {
            try ManagedStorageReplacementTrigger.validateOwner(observation, request: value)
        }
    }

    @Test @MainActor func lifecycleWorkerProjectionRejectsMissingTamperedStaleAndCopiedMetadata() throws {
        typealias C = ManagedStorageLifecycleCheckpoint
        let (observation, value) = try lifecycleFixture()
        let state = try C.decode(observation.data)
        let worker = try #require(state.observedWorker)
        let wrongWorker = Queue.Request(operationUUID: value.operationUUID, store: value.store,
            predecessor: .init(serviceEpoch: value.predecessor.serviceEpoch, workerUUID: UUID().uuidString.lowercased()))
        #expect(throws: (any Error).self) {
            try ManagedStorageReplacementTrigger.validateOwner(observation, request: wrongWorker)
        }
        let (other, _) = try lifecycleFixture()
        let copiedWorker = try C.decode(other.data).observedWorker
        for projection in [nil, C.ObservedWorker(context: worker.context, workerUUID: wrongWorker.predecessor.workerUUID),
            C.ObservedWorker(context: .init(serviceEpoch: UUID().uuidString.lowercased(),
                controllerEpoch: worker.context.controllerEpoch, controllerKey: worker.context.controllerKey), workerUUID: worker.workerUUID),
            C.ObservedWorker(context: .init(serviceEpoch: worker.context.serviceEpoch,
                controllerEpoch: worker.context.controllerEpoch + 1, controllerKey: worker.context.controllerKey), workerUUID: worker.workerUUID),
            C.ObservedWorker(context: .init(serviceEpoch: worker.context.serviceEpoch,
                controllerEpoch: worker.context.controllerEpoch, controllerKey: String(repeating: "f", count: 64)), workerUUID: worker.workerUUID),
            copiedWorker] {
            var changed = state; changed.observedWorker = projection
            var bad = observation
            bad = try .init(data: C.encode(changed), rootDevice: bad.rootDevice, rootInode: bad.rootInode,
                ownerDevice: bad.ownerDevice, ownerInode: bad.ownerInode, manifestData: bad.manifestData,
                intentsData: bad.intentsData, leaseIdentity: bad.leaseIdentity, rootIdentity: bad.rootIdentity,
                ownerIdentity: bad.ownerIdentity, intentsManifestData: bad.intentsManifestData,
                intentsIdentity: bad.intentsIdentity, intentsLeaseIdentity: bad.intentsLeaseIdentity)
            #expect(throws: (any Error).self) {
                try ManagedStorageReplacementTrigger.validateOwner(bad, request: value)
            }
        }
    }

    @Test func lifecycleObservationUsesV2BoundAndRefusesPartialDirectories() throws {
        try fixture { root, queue in
            for name in ["managed-storage-owner", "managed-storage"] {
                let directory = root.appending(path: name)
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                    attributes: [.posixPermissions: 0o700])
                try put(Data(), at: directory.appending(path: "lease"))
                try put(Data("{}".utf8), at: directory.appending(path: "manifest.json"))
                try put(Data("{}".utf8), at: directory.appending(path: "state.json"))
            }
            let state = root.appending(path: "managed-storage-owner/state.json")
            let large = Data(repeating: 32, count: 262_145)
            try put(large, at: state)
            #expect(try queue.ownerObservation().data == large)
            for directory in ["managed-storage-owner", "managed-storage"] {
                let partial = root.appending(path: directory).appending(path: "intent-state-v1.tmp")
                try put(Data(), at: partial)
                #expect(throws: (any Error).self) { try queue.ownerObservation() }
                #expect(unlink(partial.path) == 0)
            }
            try put(Data(repeating: 32, count: Queue.maximumLifecycleOwnerBytes + 1), at: state)
            #expect(throws: (any Error).self) { try queue.ownerObservation() }
        }
    }

    @Test @MainActor func publicLifecycleProofCannotAuthorizeMetadataOnlyRuntime() async throws {
        let (observation, value) = try lifecycleFixture()
        _ = try ManagedStorageReplacementTrigger.validateOwner(observation, request: value)
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root)
        await #expect(throws: EngineError.self) {
            try await runtime.replaceManagedStorageService(operationUUID: value.operationUUID, predecessor: value.predecessor)
        }
        await runtime.shutdown()
    }

    @Test func closedCanonicalSchema() throws {
        let value = request(), data = value.canonicalData
        #expect(try Queue.Request.decode(data) == value)
        let wire = String(decoding: data, as: UTF8.self)
        let invalid = [wire + "\n", wire.replacingOccurrences(of: "{\"operationUUID\":", with: "{\"pid\":1,\"operationUUID\":"),
            wire.replacingOccurrences(of: "{\"serviceEpoch\":", with: "{\"path\":\"/tmp\",\"serviceEpoch\":"),
            wire.replacingOccurrences(of: "{\"serviceEpoch\":", with: "{\"workerUUID\":\"\(value.predecessor.workerUUID)\",\"serviceEpoch\":"),
            wire.replacingOccurrences(of: "{\"operationUUID\":", with: "{\"operationUUID\":\"\(value.operationUUID)\",\"operationUUID\":"),
            wire.replacingOccurrences(of: value.operationUUID, with: value.operationUUID.uppercased()),
            wire.replacingOccurrences(of: value.store, with: "not-a-uuid"),
            wire.replacingOccurrences(of: value.predecessor.serviceEpoch, with: "../scope")]
        for input in invalid { #expect(throws: (any Error).self) { try Queue.Request.decode(Data(input.utf8)) } }
        #expect(throws: (any Error).self) { try Queue.Request.decode(Data(repeating: 32, count: 513)) }
    }

    @Test func nonV4AndNilIDsNeverEnterQueue() throws {
        let value = request(), wire = String(decoding: value.canonicalData, as: UTF8.self)
        for id in [value.operationUUID, value.store, value.predecessor.serviceEpoch, value.predecessor.workerUUID] {
            for invalid in ["00000000-0000-0000-0000-000000000000", "12345678-1234-1234-8123-123456789abc",
                            "12345678-1234-4234-7123-123456789abc"] {
                #expect(throws: (any Error).self) {
                    try Queue.Request.decode(Data(wire.replacingOccurrences(of: id, with: invalid).utf8))
                }
            }
        }
    }

    @Test func storeAndScopeAreRejectionOnly() throws {
        let value = request()
        try Queue.validateSelection(value, store: value.store, scope: value.predecessor)
        #expect(throws: (any Error).self) { try Queue.validateSelection(value, store: UUID().uuidString.lowercased(), scope: value.predecessor) }
        #expect(throws: (any Error).self) {
            try Queue.validateSelection(value, store: value.store,
                scope: .init(serviceEpoch: value.predecessor.serviceEpoch, workerUUID: UUID().uuidString.lowercased()))
        }
    }

    @Test func canonicalRootRejectsSymlinkAliases() throws {
        try fixture { root, queue in
            let physicalPath = Darwin.realpath(root.path, nil)
            let resolved = try #require(physicalPath)
            defer { free(resolved) }
            #expect(root.path == String(cString: resolved))
            let alias = root.appending(path: "root-alias")
            #expect(symlink(root.path, alias.path) == 0)
            #expect(throws: (any Error).self) { try Queue(root: alias) }
            #expect(try queue.claim() == nil)
        }
    }

    @Test func claimIsExactDurableAndNeverReadopted() throws {
        try fixture { root, queue in
            let value = request(), path = marker(root)
            try put(value.canonicalData, at: path)
            let claim = try #require(try queue.claim())
            #expect(claim.request == value)
            #expect(!FileManager.default.fileExists(atPath: path.path))
            let artifact = path.deletingLastPathComponent().appending(path: value.operationUUID + ".request.json")
            #expect(try Data(contentsOf: artifact) == value.canonicalData)
            try queue.validateClaim(claim)
            try queue.publish(claim, phase: .failed, code: "replacement-failed")
            let failed = artifact.deletingLastPathComponent().appending(path: value.operationUUID + ".failed.json")
            let original = try Data(contentsOf: failed)
            #expect(throws: (any Error).self) { try queue.publish(claim, phase: .failed, code: "overwrite") }
            #expect(try Data(contentsOf: failed) == original)
            let reopened = try Queue(root: root)
            #expect(try reopened.claim() == nil)
            try put(value.canonicalData, at: path)
            #expect(try reopened.claim() == nil)
            #expect(try Data(contentsOf: artifact) == value.canonicalData)
            #expect(try Data(contentsOf: failed) == original)
            let names = try FileManager.default.contentsOfDirectory(atPath: artifact.deletingLastPathComponent().path)
            #expect(names.filter { $0.hasPrefix("rejected-") && $0.hasSuffix(".request.json") }.count == 1)
        }
    }

    private struct SecretBearingError: Error, LocalizedError, Equatable {
        let payload = "/private/secret-owner/controller.key token=do-not-serialize"
        var errorDescription: String? { payload }
    }

    @Test @MainActor func originalFailureDiagnosticsAreClosedAndFailureOnly() async throws {
        typealias D = OriginalConsumerFailureDiagnostic
        let samples: [(any Error, D.Category)] = [
            (SecretBearingError(), .other), (CancellationError(), .cancelled),
            (ManagedStorageFailure.blocked, .ownerRejected),
            (OriginalConsumerObservationProtocol.Failure.invalid, .protocolRejected),
            (ConsumerObservationProtocol.Failure.invalid, .protocolRejected)
        ]
        for stage in D.Stage.allCases {
            for (error, category) in samples {
                let value = D(stage: stage, error: error)
                #expect(value.category == category)
                let bytes = try JSONEncoder().encode(value)
                #expect(try JSONDecoder().decode(D.self, from: bytes) == value)
                let fields = try #require(try JSONSerialization.jsonObject(with: bytes) as? [String: String])
                #expect(fields == ["stage": stage.rawValue, "category": category.rawValue])
                #expect(bytes.count < 128)
                #expect(!String(decoding: bytes, as: UTF8.self).contains("secret"))
            }
            let tagged = D.annotate(SecretBearingError(), at: stage)
            let diagnostic = try #require(D.find(in: tagged))
            #expect(D.find(in: D.annotate(tagged, at: .release)) == diagnostic)
            let original = OriginalConsumerRuntimeCarrier.Failed(requestID: "existing-request", diagnostic: diagnostic)
            let fields = try #require(try JSONSerialization.jsonObject(with: JSONEncoder().encode(original)) as? [String: Any])
            #expect(Set(fields.keys) == Set(["requestID", "code", "diagnostic"]))
            #expect((fields["diagnostic"] as? [String: String])?["stage"] == stage.rawValue)
        }
        for json in ["{\"stage\":\"unknown\",\"category\":\"other\"}",
                     "{\"stage\":\"release\",\"category\":\"/secret/path\"}"] {
            #expect(throws: (any Error).self) { try JSONDecoder().decode(D.self, from: Data(json.utf8)) }
        }
        let diagnostic = D(stage: .originalProbe, error: SecretBearingError())
        for phase in [Queue.Phase.pending, .failed, .succeeded] {
            try fixture { root, queue in
                let value = request()
                try put(value.canonicalData, at: marker(root))
                let claim = try #require(try queue.claim())
                try queue.publish(claim, phase: phase, originalConsumerDiagnostic: diagnostic)
                let data = try Data(contentsOf: marker(root).deletingLastPathComponent()
                    .appending(path: value.operationUUID + "." + phase.rawValue + ".json"))
                let receipt = try JSONDecoder().decode(Queue.Receipt.self, from: data)
                #expect(receipt.originalConsumerDiagnostic == (phase == .failed ? diagnostic : nil))
                #expect(!String(decoding: data, as: UTF8.self).contains("secret"))
            }
        }
    }

    @Test @MainActor func diagnosticPreservesCleanupOrderingAndFirstFailure() async throws {
        typealias D = OriginalConsumerFailureDiagnostic
        for failedStage in [D.Stage.originalProbe, .release, .containment] {
            var calls: [D.Stage] = []
            do {
                let _: Int = try await OriginalConsumerCleanup.run(operation: {
                    try await D.step(.originalProbe) { () async throws -> Int in
                        calls.append(.originalProbe)
                        if failedStage == .originalProbe { throw SecretBearingError() }
                        return 42
                    }
                }, release: {
                    try D.step(.release) {
                        calls.append(.release)
                        if failedStage != .containment { throw SecretBearingError() }
                    }
                }, contain: {
                    try D.step(.containment) {
                        calls.append(.containment)
                        throw CancellationError()
                    }
                })
                Issue.record("expected injected failure")
            } catch {
                #expect(calls == [.originalProbe, .release, .containment])
                #expect(D.find(in: error)?.stage == failedStage)
                #expect(D.find(in: error)?.category == (failedStage == .containment ? .cancelled : .other))
                if failedStage != .containment { #expect(error is OriginalConsumerContainmentFailure) }
            }
        }
        #expect(try D.step(.finalValidation) { 42 } == 42)
        #expect(try await D.step(.originalProbe) { () async throws -> Int in 42 } == 42)
        #expect(D.find(in: SecretBearingError()) == nil)
    }

    private final class IdentityError: Error, @unchecked Sendable {}

    @Test @MainActor func noObservationPreservesExactErrorsAndOmitsDiagnostics() async throws {
        typealias D = OriginalConsumerFailureDiagnostic
        let original = IdentityError()
        for asynchronous in [false, true] {
            do {
                if asynchronous {
                    try await D.step(nil) { () async throws -> Void in throw original }
                } else {
                    try D.step(nil) { throw original }
                }
                Issue.record("expected original error")
            } catch {
                #expect((error as? IdentityError) === original)
                #expect(D.find(in: error) == nil)
                #expect((D.annotate(error, at: nil) as? IdentityError) === original)
                let failed = OriginalConsumerRuntimeCarrier.Failed(requestID: "ordinary")
                #expect(failed.diagnostic == nil)
                let fields = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(failed)) as? [String: Any])
                #expect(fields["diagnostic"] == nil)
                try fixture { root, queue in
                    let value = request(); try put(value.canonicalData, at: marker(root))
                    let claim = try #require(try queue.claim())
                    try queue.publish(claim, phase: .failed, code: "replacement-failed",
                        originalConsumerDiagnostic: D.find(in: error))
                    let data = try Data(contentsOf: marker(root).deletingLastPathComponent()
                        .appending(path: value.operationUUID + ".failed.json"))
                    let receipt = try JSONDecoder().decode(Queue.Receipt.self, from: data)
                    #expect(receipt.originalConsumerDiagnostic == nil)
                    #expect(receipt.adoptionStage == nil && receipt.childRebindDiagnostic == nil)
                    let wire = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
                    #expect(wire["originalConsumerDiagnostic"] == nil)
                }
            }
        }
    }

    @Test @MainActor func taggedErrorsPreserveTypedAdoptionReceipts() throws {
        typealias D = OriginalConsumerFailureDiagnostic
        let rebind = ManagedStorageChildRebindDiagnostic(point: .ipcRead, error: CancellationError())
        let errors: [any Error] = ManagedStorageWorkerAdoptionFailure.allCases.map { $0 as any Error } + [rebind]
        for original in errors {
            let tagged = D.annotate(original, at: .adoptionReturn)
            let error = D.underlying(tagged)
            let stage: ManagedStorageWorkerAdoptionFailure? = error is ManagedStorageChildRebindDiagnostic
                ? .childRebind : error as? ManagedStorageWorkerAdoptionFailure
            #expect(stage != nil)
            #expect(error as? ManagedStorageWorkerAdoptionFailure == original as? ManagedStorageWorkerAdoptionFailure)
            #expect(error as? ManagedStorageChildRebindDiagnostic == original as? ManagedStorageChildRebindDiagnostic)
            try fixture { root, queue in
                let value = request(); try put(value.canonicalData, at: marker(root))
                let claim = try #require(try queue.claim())
                try queue.publish(claim, phase: .failed, adoptionStage: stage,
                    childRebindDiagnostic: error as? ManagedStorageChildRebindDiagnostic,
                    originalConsumerDiagnostic: D.find(in: tagged))
                let data = try Data(contentsOf: marker(root).deletingLastPathComponent()
                    .appending(path: value.operationUUID + ".failed.json"))
                let receipt = try JSONDecoder().decode(Queue.Receipt.self, from: data)
                #expect(receipt.adoptionStage == stage)
                #expect(receipt.childRebindDiagnostic == original as? ManagedStorageChildRebindDiagnostic)
                #expect(receipt.originalConsumerDiagnostic?.stage == .adoptionReturn)
            }
        }
    }

    @Test @MainActor func adoptionStageSchemaIsClosedAndOrdinaryErrorsAreUnchanged() async throws {
        typealias Adoption = ManagedStorageWorkerAdoptionFailure
        #expect(Set(Adoption.allCases.map(\.rawValue)) == Set([
            "child-rebind", "certificate-csr", "certificate-issuance", "certificate-install",
            "control-stream", "control-connect", "control-context", "query", "reconcile",
            "local-evidence-commit", "lifecycle-recovery"
        ]))
        for input in ["\"unknown-stage\"", "{\"stage\":\"query\",\"error\":\"secret\"}"] {
            #expect(throws: (any Error).self) { try JSONDecoder().decode(Adoption.self, from: Data(input.utf8)) }
        }
        let original = SecretBearingError()
        do {
            try Adoption.step(nil) { throw original }
            Issue.record("ordinary synchronous error was swallowed")
        } catch { #expect(error as? SecretBearingError == original) }
        do {
            try await Adoption.step(nil) { () async throws -> Void in throw original }
            Issue.record("ordinary asynchronous certificate error was swallowed")
        } catch { #expect(error as? SecretBearingError == original) }
    }

    // Diagnostic helper/receipt coverage only: this does not inject faults into a
    // real owner, child, certificate exchange, control connection or ROOT reconcile.
    @Test(arguments: ManagedStorageWorkerAdoptionFailure.allCases)
    @MainActor func adoptionStepsDiscardUnderlyingErrors(stage: ManagedStorageWorkerAdoptionFailure) async throws {
        typealias Adoption = ManagedStorageWorkerAdoptionFailure
        #expect(try Adoption.step(stage) { 42 } == 42)
        #expect(try await Adoption.step(stage) { () async throws -> Int in 42 } == 42)
        for asynchronous in [false, true] {
            let wrapped: any Error
            do {
                if asynchronous {
                    try await Adoption.step(stage) { () async throws -> Void in throw SecretBearingError() }
                } else {
                    try Adoption.step(stage) { throw SecretBearingError() }
                }
                Issue.record("adoption error was swallowed")
                return
            } catch { wrapped = error }
            let closed = try #require(wrapped as? Adoption)
            #expect(closed == stage)
            #expect(try JSONEncoder().encode(closed) == Data("\"\(stage.rawValue)\"".utf8))
            try fixture { root, queue in
                let value = request()
                try put(value.canonicalData, at: marker(root))
                let claim = try #require(try queue.claim())
                try queue.publish(claim, phase: .failed, code: "replacement-failed", adoptionStage: closed)
                let data = try Data(contentsOf: marker(root).deletingLastPathComponent()
                    .appending(path: value.operationUUID + ".failed.json"))
                let receipt = try JSONDecoder().decode(Queue.Receipt.self, from: data)
                let fields = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
                #expect(receipt.adoptionStage == stage && receipt.code == "replacement-failed")
                #expect(Set(fields.keys) == Set(["schema", "counter", "phase", "request", "code", "adoptionStage"]))
                #expect(fields["adoptionStage"] as? String == stage.rawValue)
                let wire = String(decoding: data, as: UTF8.self)
                for secret in [SecretBearingError().payload, "SecretBearingError", "secret-owner", "do-not-serialize"] {
                    #expect(!wire.contains(secret))
                }
            }
        }
    }

    @Test func unknownErrorsHaveNoAdoptionStageOrPayload() throws {
        let errors: [any Error] = [SecretBearingError(), NSError(domain: "secret-owner", code: 19,
            userInfo: [NSLocalizedDescriptionKey: SecretBearingError().payload]), Queue.Failure.changed]
        for error in errors {
            try fixture { root, queue in
                let value = request()
                try put(value.canonicalData, at: marker(root))
                let claim = try #require(try queue.claim())
                // Match the trigger catch: arbitrary errors never enter the receipt writer.
                let stage = error as? ManagedStorageWorkerAdoptionFailure
                #expect(stage == nil)
                try queue.publish(claim, phase: .failed, code: "replacement-failed", adoptionStage: stage)
                let data = try Data(contentsOf: marker(root).deletingLastPathComponent()
                    .appending(path: value.operationUUID + ".failed.json"))
                let receipt = try JSONDecoder().decode(Queue.Receipt.self, from: data)
                let fields = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
                #expect(receipt.adoptionStage == nil && receipt.code == "replacement-failed")
                #expect(Set(fields.keys) == Set(["schema", "counter", "phase", "request", "code"]))
                #expect(!String(decoding: data, as: UTF8.self).contains("secret-owner"))
            }
        }
    }

    @Test @MainActor func childRebindDiagnosticIsClosedAndFailureOnly() throws {
        typealias D = ManagedStorageChildRebindDiagnostic
        let samples: [(any Error, D.Category)] = [
            (ManagedStorageControlFailure.invalidConfiguration, .invalidConfiguration),
            (ManagedStorageControlFailure.protocolViolation, .protocolViolation),
            (ManagedStorageControlFailure.unauthorized, .unauthorized),
            (ManagedStorageControlFailure.serviceUnavailable, .serviceUnavailable),
            (ManagedStorageControlFailure.system(ETIMEDOUT), .timeout),
            (ManagedStorageControlFailure.system(EIO), .system),
            (ManagedStorageFailure.blocked, .ownerRejected),
            (CancellationError(), .cancelled), (SecretBearingError(), .other),
            (NSError(domain: "secret-owner", code: 19, userInfo: [NSLocalizedDescriptionKey: SecretBearingError().payload]), .other)
        ]
        for (error, category) in samples {
            let diagnostic = D(point: .ipcRead, error: error)
            #expect(diagnostic.category == category)
            let data = try JSONEncoder().encode(diagnostic)
            #expect(try JSONDecoder().decode(D.self, from: data) == diagnostic)
            let fields = try #require(try JSONSerialization.jsonObject(with: data) as? [String: String])
            #expect(fields == ["point": "ipc-read", "category": category.rawValue])
        }
        for point in ManagedStorageChildRebindDiagnostic.Point.allCases {
            try fixture { root, queue in
                let value = request(); try put(value.canonicalData, at: marker(root))
                let claim = try #require(try queue.claim())
                let diagnostic = D(point: point, error: SecretBearingError())
                for phase in [Queue.Phase.pending, .succeeded, .failed] {
                    try queue.publish(claim, phase: phase, code: "replacement-failed",
                        adoptionStage: .childRebind, childRebindDiagnostic: diagnostic)
                    let data = try Data(contentsOf: marker(root).deletingLastPathComponent()
                        .appending(path: value.operationUUID + "." + phase.rawValue + ".json"))
                    let receipt = try JSONDecoder().decode(Queue.Receipt.self, from: data)
                    #expect(receipt.childRebindDiagnostic == (phase == .failed ? diagnostic : nil))
                    #expect(!String(decoding: data, as: UTF8.self).contains("secret-owner"))
                }
            }
        }
        for raw in [#"{"point":"unknown","category":"other"}"#, #"{"point":"ipc-read","category":"secret-error"}"#] {
            #expect(throws: (any Error).self) { try JSONDecoder().decode(D.self, from: Data(raw.utf8)) }
        }
        do { try D.revalidate { throw ManagedStorageFailure.changedServiceEpoch }; Issue.record("owner failure accepted") }
        catch { #expect(error as? D == D(point: .ownerRevalidation, error: ManagedStorageFailure.changedServiceEpoch)) }
    }

    @Test @MainActor func firstCloseReceiptIsClosedFailureOnlyAndSecretFree() throws {
        typealias C = ManagedStorageCloseDiagnostic
        typealias D = ManagedStorageChildRebindDiagnostic
        let samples: [(any Error, C.Category)] = [
            (ManagedStorageControlFailure.protocolViolation, .protocolViolation),
            (ManagedStorageControlFailure.system(EIO), .system),
            (ManagedStorageControlFailure.system(ETIMEDOUT), .timeout),
            (ManagedStorageFailure.blocked, .ownerRejected),
            (CancellationError(), .cancelled),
            (EngineError(.conflict, SecretBearingError().payload), .engineConflict),
            (EngineError(.internalError, SecretBearingError().payload), .engineInternal),
            (SecretBearingError(), .other)
        ]
        for (error, category) in samples {
            let first = C(site: .adapter, operation: .retire, phase: .reconnectStream, error: error)
            #expect(first.category == category)
            let diagnostic = D(point: .preflightClosed, error: ManagedStorageControlFailure.invalidConfiguration, firstClose: first)
            let encoded = try JSONEncoder().encode(diagnostic)
            #expect(try JSONDecoder().decode(D.self, from: encoded) == diagnostic)
            #expect(!String(decoding: encoded, as: UTF8.self).contains("secret"))
            try fixture { root, queue in
                let value = request(); try put(value.canonicalData, at: marker(root))
                let claim = try #require(try queue.claim())
                for phase in [Queue.Phase.pending, .succeeded, .failed] {
                    try queue.publish(claim, phase: phase, code: "replacement-failed", adoptionStage: .childRebind, childRebindDiagnostic: diagnostic)
                    let data = try Data(contentsOf: marker(root).deletingLastPathComponent().appending(path: value.operationUUID + "." + phase.rawValue + ".json"))
                    let receipt = try JSONDecoder().decode(Queue.Receipt.self, from: data)
                    #expect(receipt.childRebindDiagnostic?.firstClose == (phase == .failed ? first : nil))
                }
            }
        }
        for field in ["site", "operation", "phase", "category"] {
            let first = C(site: .adapter, operation: .retire, phase: .decode)
            var fields = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(first)) as? [String: String])
            fields[field] = "untrusted-secret"
            let data = try JSONSerialization.data(withJSONObject: fields)
            #expect(throws: (any Error).self) { try JSONDecoder().decode(C.self, from: data) }
        }
    }

    @Test func receiptsPreserveRealResultTimestampAndPublicProof() throws {
        try fixture { root, queue in
            let value = request()
            try put(value.canonicalData, at: marker(root))
            let claim = try #require(try queue.claim())
            let proof = Queue.Proof(controllerEpoch: 2, controllerKey: String(repeating: "a", count: 64),
                                    rootPublicKey: Data(repeating: 1, count: 32).base64EncodedString())
            let original = StorageServiceTypes.ReplacementRequest(operationUUID: value.operationUUID,
                predecessor: value.predecessor, nowUnixSeconds: 123456789)
            let successor = request().predecessor
            let result = BackendServiceReplacementResult(request: original, successor: successor,
                                                         containedContainerIDs: ["container-b", "container-a"])
            try queue.publish(claim, phase: .pending, proof: proof)
            try queue.publish(claim, phase: .succeeded, proof: proof, result: result)
            let directory = marker(root).deletingLastPathComponent()
            let receipt = try JSONDecoder().decode(Queue.Receipt.self,
                from: Data(contentsOf: directory.appending(path: value.operationUUID + ".succeeded.json")))
            #expect(receipt.phase == .succeeded)
            #expect(receipt.schema == 1 && receipt.counter == 1)
            #expect(receipt.request == value && receipt.ownerRequest == original)
            #expect(receipt.successor == successor)
            #expect(receipt.containedContainerIDs == ["container-a", "container-b"])
            #expect(receipt.proof?.controllerEpoch == 2)
            #expect(receipt.adoptionStage == nil && receipt.code == nil)
            for (phase, keys) in [
                ("pending", ["schema", "counter", "phase", "request", "proof"]),
                ("succeeded", ["schema", "counter", "phase", "request", "proof", "ownerRequest", "successor", "containedContainerIDs"])
            ] {
                let data = try Data(contentsOf: directory.appending(path: value.operationUUID + "." + phase + ".json"))
                let fields = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
                #expect(Set(fields.keys) == Set(keys))
                #expect(try JSONDecoder().decode(Queue.Receipt.self, from: data).adoptionStage == nil)
            }
        }
    }

    @Test func unfinishedClaimsAreNotAdoptedAfterReopen() throws {
        try fixture { root, queue in
            let value = request()
            try put(value.canonicalData, at: marker(root))
            _ = try #require(try queue.claim()) // Crash before publishing even pending.
            let reopened = try Queue(root: root)
            try put(value.canonicalData, at: marker(root))
            #expect(try reopened.claim() == nil)
        }
    }

    @Test func malformedRequestsRetainedAndCapacityNeverEvicted() throws {
        try fixture { root, queue in
            let bad = Data("{\"command\":\"replace\"}".utf8)
            for _ in 0..<Queue.maximumRequests {
                try put(bad, at: marker(root))
                #expect(try queue.claim() == nil)
            }
            let good = request().canonicalData
            try put(good, at: marker(root))
            #expect(throws: (any Error).self) { try queue.claim() }
            #expect(try Data(contentsOf: marker(root)) == good)
            let names = try FileManager.default.contentsOfDirectory(atPath: marker(root).deletingLastPathComponent().path)
            #expect(names.filter { $0.hasSuffix(".request.json") }.count == Queue.maximumRequests)
            #expect(names.filter { $0.hasSuffix(".failed.json") }.count == Queue.maximumRequests)
        }
    }

    @Test(arguments: [0o644, 0o400, 0o660, 0o1600])
    func unsafeModePreservesInput(mode: Int) throws {
        try fixture { root, queue in
            let value = request().canonicalData
            try put(value, at: marker(root)); #expect(chmod(marker(root).path, mode_t(mode)) == 0)
            #expect(throws: (any Error).self) { try queue.claim() }
            #expect(try Data(contentsOf: marker(root)) == value)
        }
    }

    @Test func symlinkHardlinkAndWrongUIDNeverClaim() throws {
        try fixture { root, queue in
            let target = root.appending(path: "target"), path = marker(root)
            try put(request().canonicalData, at: target)
            #expect(symlink(target.path, path.path) == 0)
            #expect(throws: (any Error).self) { try queue.claim() }
            #expect(unlink(path.path) == 0)
            #expect(link(target.path, path.path) == 0)
            #expect(throws: (any Error).self) { try queue.claim() }
            #expect(unlink(path.path) == 0)
            try put(request().canonicalData, at: path)
            let directory = open(path.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY)
            let fd = open(path.path, O_RDONLY)
            defer { close(fd); close(directory) }
            #expect(throws: (any Error).self) {
                try Queue.validateFile(fd, directory: directory, name: "request.json", expectedUID: geteuid() &+ 1)
            }
            // A descriptor must still match the live name, not merely safe metadata.
            #expect(unlink(path.path) == 0)
            try put(request().canonicalData, at: path)
            #expect(throws: (any Error).self) { try Queue.validateFile(fd, directory: directory, name: "request.json") }
        }
    }

    @Test func replacedClaimAndQueueDirectoryAreRejected() throws {
        try fixture { root, queue in
            let value = request()
            try put(value.canonicalData, at: marker(root))
            let claim = try #require(try queue.claim())
            let artifact = marker(root).deletingLastPathComponent().appending(path: value.operationUUID + ".request.json")
            try put(request().canonicalData, at: artifact)
            #expect(throws: (any Error).self) { try queue.validateClaim(claim) }
            let directory = marker(root).deletingLastPathComponent()
            try FileManager.default.moveItem(at: directory, to: root.appending(path: "old"))
            #expect(symlink(root.appending(path: "old").path, directory.path) == 0)
            #expect(throws: (any Error).self) { try queue.claim() }
        }
    }
}

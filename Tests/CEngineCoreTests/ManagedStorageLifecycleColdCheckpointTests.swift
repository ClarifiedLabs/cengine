#if os(macOS)
import CEngineCore
import CryptoKit
import Foundation
import Testing
@testable import CEngineRuntime

/// Public metadata only. These tests cannot establish native exit, fresh ROOT
/// authentication, child possession, or authorize cross-E workload recovery.
@Suite(.serialized) @MainActor struct ManagedStorageLifecycleColdCheckpointTests {
    typealias Owner = ManagedStorageLifecycleCheckpoint
    typealias Wire = StorageLifecycleProtocol
    typealias Cold = StorageLifecycleColdProtocol
    typealias Root = StorageLifecycleColdRootProtocol

    @Test func allFourStagesRoundTripExactTuplesAndSignatures() throws {
        let f = try Fixture(), initial = try f.initial(), request = try f.request(initial)
        let prepared = try f.prepared(request), completion = try f.completion(prepared, initial)
        var state = try Owner.applying(.stageColdRequest(request), to: initial, intents: f.intents)
        #expect(state.pendingCold?.prepared == nil)
        #expect(state.pendingCold?.bootAttempted == false)
        try roundTrip(state)
        #expect(try Owner.applying(.stageColdRequest(request), to: state, intents: f.intents) == state)
        #expect(throws: (any Error).self) { try Owner.applying(.attemptColdBoot, to: state, intents: f.intents) }
        #expect(throws: (any Error).self) { try Owner.applying(.completeCold(completion), to: state, intents: f.intents) }
        state = try Owner.applying(.authorizeCold(prepared), to: state, intents: f.intents)
        try roundTrip(state)
        #expect(state.pendingCold?.prepared?.signedOpen.signature == prepared.signedOpen.signature)
        #expect(state.pendingCold?.prepared?.signedOpen.request.takeover.signature == prepared.signedOpen.request.takeover.signature)
        #expect(try Owner.applying(.authorizeCold(prepared), to: state, intents: f.intents) == state)
        #expect(throws: (any Error).self) { try Owner.applying(.completeCold(completion), to: state, intents: f.intents) }
        state = try Owner.applying(.attemptColdBoot, to: state, intents: f.intents)
        try roundTrip(state)
        #expect(try Owner.applying(.attemptColdBoot, to: state, intents: f.intents) == state)
        state = try Owner.applying(.completeCold(completion), to: state, intents: f.intents)
        try roundTrip(state)
        #expect(state.pendingCold == nil)
        #expect(state.latestCold?.request == request)
        #expect(state.latestCold?.prepared == prepared)
        #expect(state.latestCold?.completion == completion)
        #expect(state.current?.original.signed == prepared.signedOpen.request.takeover)
        #expect(state.current?.original.recipient == request.recipient)
        #expect(state.current?.original.serviceEpoch == completion.receipt.serviceEpoch)
        #expect(state.current?.directResult == completion.receipt)
        #expect(state.currentService == completion.successor)
        #expect(state.currentContext?.controllerEpoch == initial.currentContext!.controllerEpoch + 1)
        #expect(try Owner.applying(.completeCold(completion), to: state, intents: f.intents) == state)
        #expect(throws: (any Error).self) { try Owner.applying(.stageColdRequest(request), to: state, intents: f.intents) }
    }

    @Test func requiredNullableFieldsAndInvalidStageCombinationsReject() throws {
        let f = try Fixture(), initial = try f.initial(), request = try f.request(initial)
        let bytes = try Owner.encode(initial)
        let json = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        #expect(json["pendingCold"] is NSNull)
        #expect(json["latestCold"] is NSNull)
        for field in ["pendingCold", "latestCold"] {
            var missing = json; missing.removeValue(forKey: field)
            let malformed = try JSONSerialization.data(withJSONObject: missing, options: [.sortedKeys, .withoutEscapingSlashes])
            #expect(throws: (any Error).self) { try Owner.decode(malformed) }
        }
        var state = try Owner.applying(.stageColdRequest(request), to: initial, intents: f.intents)
        state.pendingCold?.bootAttempted = true
        #expect(throws: (any Error).self) { try Owner.decode(Owner.encode(state)) }
        state.pendingCold?.bootAttempted = false
        state.pending = initial.current!.original
        #expect(throws: (any Error).self) { try Owner.decode(Owner.encode(state)) }
    }

    @Test func exactAuthorizationAndRequestCannotBeRefreshedOrResigned() throws {
        let f = try Fixture(), initial = try f.initial(), request = try f.request(initial)
        let prepared = try f.prepared(request)
        var state = try Owner.applying(.stageColdRequest(request), to: initial, intents: f.intents)
        for path in [["prepare", "nowUnixSeconds"], ["prepare", "lifetimeSeconds"], ["prepareRequestID"], ["completionRequestID"]] {
            let value: Any
            switch path.last {
            case "nowUnixSeconds": value = 101
            case "lifetimeSeconds": value = 61
            default: value = Self.id()
            }
            let changed = try JSONDecoder().decode(Owner.ColdRequest.self, from: replacing(Owner.encode(request), path: path, value: value))
            #expect(throws: (any Error).self) { try Owner.applying(.stageColdRequest(changed), to: state, intents: f.intents) }
        }
        state = try Owner.applying(.authorizeCold(prepared), to: state, intents: f.intents)
        // Valid ROOT signatures over another serial are still not this authorization.
        let other = try f.prepared(request, serial: prepared.signedOpen.request.takeover.grant.serial + 1)
        #expect(throws: (any Error).self) { try Owner.applying(.authorizeCold(other), to: state, intents: f.intents) }
        for path in [["pendingCold", "prepared", "signedOpen", "signature"],
                     ["pendingCold", "prepared", "signedOpen", "request", "takeover", "signature"]] {
            let bytes = try replacing(Owner.encode(state), path: path, value: Data(repeating: 0, count: 64).base64EncodedString())
            #expect(throws: (any Error).self) { try Owner.decode(bytes) }
        }
    }

    @Test func ordinaryGrantNeverGetsNilEpochWaiverAndEveryOrdinaryChangeIsFenced() throws {
        let f = try Fixture(), initial = try f.initial(), request = try f.request(initial)
        let prepared = try f.prepared(request), receipt = initial.current!.directResult
        let nilEpoch = Owner.GrantContext(signed: prepared.signedOpen.request.takeover, recipient: request.recipient,
            requestID: request.completionRequestID, serviceEpoch: nil)
        #expect(throws: (any Error).self) { try Owner.applying(.stage(nilEpoch), to: initial, intents: f.intents) }
        let service = try Wire.ServiceChangeRequest(operationID: Self.id(), predecessor: initial.currentService!)
        let pendingService = Owner.PendingService(request: service, stageRequestID: Self.id(), completionRequestID: Self.id(),
            predecessorWorkerUUID: Self.id(), nowUnixSeconds: 100, lifetimeSeconds: 60)
        let takeover = Owner.TakeoverRequest(requestID: Self.id(), grantID: Self.id(), recipient: request.recipient,
            expectedEpoch: initial.currentContext!.controllerEpoch, serviceEpoch: initial.currentContext!.serviceEpoch)
        let adoption = try f.adoption(request)
        let nextEpoch = Self.id(), grant = initial.current!.original.signed.grant
        let successor = try Wire.ServiceState(grant: grant,
            context: .init(serviceEpoch: nextEpoch, controllerEpoch: 1, controllerKey: grant.newKey), openRevision: 6,
            boot: .init(identity: grant.identity, serviceEpoch: nextEpoch, tlsRootSHA256: String(repeating: "d", count: 64),
                serverSPKI: String(repeating: "e", count: 64), bootstrapKey: initial.currentService!.boot.bootstrapKey))
        let confirmation = try Wire.ServiceChangeConfirmation(request: service, successor: successor)
        let ordinary = Owner.GrantContext(signed: nilEpoch.signed, recipient: nilEpoch.recipient,
            requestID: nilEpoch.requestID, serviceEpoch: initial.currentContext!.serviceEpoch)
        let changes: [Owner.Change] = [.stage(initial.current!.original), .complete(receipt), .recordService(initial.currentService!),
            .stageService(pendingService), .confirmService(confirmation), .stageTakeoverRequest(takeover),
            .stageAdoption(adoption), .seal(receipt), .retire(receipt)]
        var state = try Owner.applying(.stageColdRequest(request), to: initial, intents: f.intents)
        for stage in 0..<3 {
            for change in changes {
                #expect(throws: (any Error).self) { try Owner.applying(change, to: state, intents: f.intents) }
            }
            if stage == 0 { state = try Owner.applying(.authorizeCold(prepared), to: state, intents: f.intents) }
            if stage == 1 { state = try Owner.applying(.attemptColdBoot, to: state, intents: f.intents) }
        }
        for occupied in [try Owner.applying(.stageService(pendingService), to: initial, intents: f.intents),
                         try Owner.applying(.stage(ordinary), to: initial, intents: f.intents),
                         try Owner.applying(.stageTakeoverRequest(takeover), to: initial, intents: f.intents)] {
            #expect(throws: (any Error).self) { try Owner.applying(.stageColdRequest(request), to: occupied, intents: f.intents) }
        }
    }

    @Test func forgedCompletionOldAnchorsAndReusedServiceKeysReject() throws {
        let f = try Fixture(), initial = try f.initial(), request = try f.request(initial)
        let prepared = try f.prepared(request), completion = try f.completion(prepared, initial)
        #expect(throws: (any Error).self) { try Owner.applying(.completeCold(completion), to: initial, intents: f.intents) }
        let state = try f.attempted(initial, request, prepared)
        for bad in [try f.completion(prepared, initial, revision: initial.current!.directResult.revision),
                    try f.completion(prepared, initial, tls: initial.currentService!.boot.tlsRootSHA256),
                    try f.completion(prepared, initial, server: initial.currentService!.boot.serverSPKI),
                    try Root.Completed(operationID: completion.operationID, signedOpenSHA256: String(repeating: "f", count: 64),
                        successorOrigin: completion.successorOrigin, baseEpoch: completion.baseEpoch,
                        receipt: completion.receipt, successor: completion.successor)] {
            #expect(throws: (any Error).self) { try Owner.applying(.completeCold(bad), to: state, intents: f.intents) }
        }
        let done = try Owner.applying(.completeCold(completion), to: state, intents: f.intents)
        let tampered = try replacing(Owner.encode(done), path: ["latestCold", "completion", "signedOpenSHA256"], value: String(repeating: "f", count: 64))
        #expect(throws: (any Error).self) { try Owner.decode(tampered) }
        var stale = f.intents; stale.revision = 0
        #expect(throws: (any Error).self) { try Owner.applying(.completeCold(completion), to: state, intents: stale) }
    }

    @Test func immediatePredecessorSurvivesAndNextColdFoldsWithoutRecursiveHistory() throws {
        let f = try Fixture(), initial = try f.initial()
        var state = initial
        for _ in 0..<12 {
            let old = state, request = try f.request(state), prepared = try f.prepared(request)
            state = try Owner.applying(.completeCold(f.completion(prepared, old)),
                to: f.attempted(old, request, prepared), intents: f.intents)
            #expect(state.contexts.count == 2)
            #expect(state.contexts.contains(where: { $0.context == old.currentContext }))
            #expect(state.latestCold?.predecessor.controller == old.current)
            #expect(try Owner.requiredContexts(state).contains(old.currentContext!))
            #expect(try Owner.recoveryContexts(state) == [state.currentContext!])
            try roundTrip(state)
        }
        #expect(!state.contexts.contains(where: { $0.context == initial.currentContext }))
        #expect(try Owner.encode(state).count < 32_768)
        var pruned = state
        pruned.contexts.removeAll(where: { $0.context == state.latestCold!.predecessor.context })
        #expect(throws: (any Error).self) { try Owner.decode(Owner.encode(pruned)) }
        #expect(throws: (any Error).self) { try Owner.recoveryContexts(pruned) }
    }

    @Test(arguments: [HostStorageIntents.Phase.quarantined, .retired])
    func censusReferencesKeepOlderColdContextsAndRejectBrokenClosure(_ phase: HostStorageIntents.Phase) throws {
        let f = try Fixture(), initial = try f.initial()
        var state = initial, intents = f.intents
        let original = initial.currentContext!, digest = initial.provenanceReference
        let old = HostStorageIntents.Intent(id: Self.id(), store: initial.identity.store, container: digest,
            containerInstance: Self.id(), launch: Self.id(), specificationDigest: digest,
            serviceEpoch: original.serviceEpoch, controllerEpoch: original.controllerEpoch, controllerKey: original.controllerKey,
            prepare: Self.id(), reserveOperation: Self.id(), completeOperation: Self.id(), replaceOperation: Self.id(),
            mounts: [], slots: [], version: 1, phase: phase, prepareCompleted: false, cleanUnmount: false)
        intents.intents[old.id] = old
        for _ in 0..<3 {
            let request = try f.request(state), prepared = try f.prepared(request), completion = try f.completion(prepared, state)
            state = try Owner.applying(.stageColdRequest(request), to: state, intents: intents)
            state = try Owner.applying(.authorizeCold(prepared), to: state, intents: intents)
            state = try Owner.applying(.attemptColdBoot, to: state, intents: intents)
            state = try Owner.applying(.completeCold(completion), to: state, intents: intents)
            #expect(try Owner.recoveryContexts(state) == [original, state.currentContext!])
        }
        #expect(state.contexts.count == 3)
        #expect(state.contexts.contains(where: { $0.context == original }))
        try roundTrip(state)
        var broken = intents
        broken.intents[old.id]?.successor = Self.id()
        #expect(throws: (any Error).self) { try Owner.applying(.stage(state.current!.original), to: state, intents: broken) }
        intents.intents = [:]; intents.revision += 1
        state = try Owner.applying(.stage(state.current!.original), to: state, intents: intents)
        #expect(state.contexts.count == 2)
        #expect(!state.contexts.contains(where: { $0.context == original }))
        #expect(try Owner.recoveryContexts(state) == [state.currentContext!])
    }

    @Test func protectedPredecessorAndRecipientMustMatchCurrentMetadata() throws {
        let f = try Fixture(), initial = try f.initial(), request = try f.request(initial)
        for (path, value): ([String], Any) in [
            (["prepare", "expectedPredecessor", "open_revision"], 2),
            (["prepare", "expectedPredecessor", "service_epoch"], Self.id()),
            (["recipient", "incarnation"], initial.current!.original.recipient.incarnation),
            (["recipient", "daemonUniqueID"], 99),
            (["recipient", "childPID"], 99),
            (["recipient", "publicKey"], initial.current!.original.recipient.publicKey.base64EncodedString()),
        ] {
            let changed = try JSONDecoder().decode(Owner.ColdRequest.self, from: replacing(Owner.encode(request), path: path, value: value))
            #expect(throws: (any Error).self) { try Owner.applying(.stageColdRequest(changed), to: initial, intents: f.intents) }
        }
    }

    @Test func deadResolutionPreservesAttemptAndCurrentUntilGenuineNewColdCompletion() throws {
        let f = try Fixture(), initial = try f.initial(), request = try f.request(initial)
        let prepared = try f.prepared(request), completion = try f.completion(prepared, initial)
        var state = try f.attempted(initial, request, prepared)
        let retry = try Owner.ColdResolutionRequest(value: .init(resolutionID: Self.id(), identity: initial.identity,
            operationID: request.prepare.operationID, signedOpenSHA256: prepared.signedOpenSHA256), requestID: Self.id())
        state = try Owner.applying(.stageColdResolution(retry), to: state, intents: f.intents)
        let attempted = state.pendingCold
        try roundTrip(state)
        #expect(try Owner.applying(.stageColdResolution(retry), to: state, intents: f.intents) == state)
        #expect(throws: (any Error).self) { try Owner.applying(.attemptColdBoot, to: state, intents: f.intents) }
        #expect(throws: (any Error).self) { try Owner.applying(.completeCold(completion), to: state, intents: f.intents) }
        let value = try Root.ResolvedDead(request: retry.value, anchor: initial.currentService!, receipt: completion.receipt,
            successor: completion.successor, successorOrigin: completion.successorOrigin, baseEpoch: completion.baseEpoch)
        state = try Owner.applying(.resolveDeadCold(value), to: state, intents: f.intents)
        try roundTrip(state)
        #expect(state.current == initial.current && state.currentContext == initial.currentContext)
        #expect(state.currentService == initial.currentService && state.latestCold == nil)
        #expect(state.resolvedDeadCold?.attempted == attempted)
        #expect(state.pendingCold == nil)
        #expect(try Owner.coldPredecessorService(in: state) == completion.successor)
        #expect(try Owner.recoveryContexts(state) == [initial.currentContext!])
        #expect(try Owner.applying(.resolveDeadCold(value), to: state, intents: f.intents) == state)
        #expect(throws: (any Error).self) { try Owner.applying(.stage(initial.current!.original), to: state, intents: f.intents) }
        #expect(throws: (any Error).self) { try Owner.applying(.recordService(initial.currentService!), to: state, intents: f.intents) }
        #expect(try Owner.replacementRecoveryRequest(state) == nil)
        let newRequest = try f.request(state), newPrepared = try f.prepared(newRequest, bridge: value)
        let newCompletion = try f.completion(newPrepared, state)
        state = try f.attempted(state, newRequest, newPrepared)
        try roundTrip(state)
        #expect(state.current == initial.current)
        #expect(throws: (any Error).self) { try Owner.applying(.stageColdResolution(retry), to: state, intents: f.intents) }
        state = try Owner.applying(.completeCold(newCompletion), to: state, intents: f.intents)
        try roundTrip(state)
        #expect(state.currentContext?.controllerEpoch == 3)
        #expect(state.latestCold?.deadPredecessor?.attempted == attempted)
        #expect(state.latestCold?.completion.recoveryBridge == value)
        #expect(state.resolvedDeadCold == nil && state.pendingCold == nil)
        #expect(state.contexts.count == 3)
        var lostAudit = state
        lostAudit.latestCold?.deadPredecessor = nil
        #expect(throws: (any Error).self) { try Owner.decode(Owner.encode(lostAudit)) }
        var pruned = state
        pruned.contexts.removeAll { $0.context == initial.currentContext }
        #expect(throws: (any Error).self) { try Owner.decode(Owner.encode(pruned)) }
    }

    @Test func repeatedResolvedColdEdgesFoldUnreferencedAuditWithoutRecursiveGrowth() throws {
        let f = try Fixture()
        var state = try f.initial()
        for _ in 0..<12 {
            let anchor = state, request = try f.request(state), prepared = try f.prepared(request)
            let completion = try f.completion(prepared, state)
            state = try f.attempted(state, request, prepared)
            let retry = try Owner.ColdResolutionRequest(value: .init(resolutionID: Self.id(), identity: state.identity,
                operationID: request.prepare.operationID, signedOpenSHA256: prepared.signedOpenSHA256), requestID: Self.id())
            state = try Owner.applying(.stageColdResolution(retry), to: state, intents: f.intents)
            let resolved = try Root.ResolvedDead(request: retry.value, anchor: anchor.currentService!, receipt: completion.receipt,
                successor: completion.successor, successorOrigin: completion.successorOrigin, baseEpoch: completion.baseEpoch)
            state = try Owner.applying(.resolveDeadCold(resolved), to: state, intents: f.intents)
            #expect(state.current == anchor.current)
            #expect(state.contexts.count <= 4)
            let nextRequest = try f.request(state), nextPrepared = try f.prepared(nextRequest, bridge: resolved)
            let nextCompletion = try f.completion(nextPrepared, state)
            state = try f.attempted(state, nextRequest, nextPrepared)
            // This second attempted edge already has a bridge: never grow another.
            #expect(throws: (any Error).self) { try Owner.applying(.stageColdResolution(retry), to: state, intents: f.intents) }
            state = try Owner.applying(.completeCold(nextCompletion), to: state, intents: f.intents)
            #expect(state.contexts.count == 3)
            #expect(try Owner.recoveryContexts(state) == [state.currentContext!])
            #expect(try Owner.encode(state).count < 65_536)
            try roundTrip(state)
        }
    }

    private func roundTrip(_ state: Owner.Metadata) throws {
        let bytes = try Owner.encode(state)
        let decoded = try Owner.decode(bytes)
        #expect(decoded == state)
        #expect(try Owner.encode(decoded) == bytes)
    }
    private func replacing(_ bytes: Data, path: [String], value: Any) throws -> Data {
        func replace(_ object: Any, _ path: ArraySlice<String>) -> Any {
            var object = object as! [String: Any]
            let key = path.first!
            object[key] = path.count == 1 ? value : replace(object[key]!, path.dropFirst())
            return object
        }
        return try JSONSerialization.data(withJSONObject: replace(JSONSerialization.jsonObject(with: bytes), path[...]),
            options: [.sortedKeys, .withoutEscapingSlashes])
    }
    nonisolated private static func id() -> String { UUID().uuidString.lowercased() }

    @MainActor private struct Fixture {
        let contract: ColdContractFixture
        let root: Curve25519.Signing.PrivateKey
        var intents: HostStorageIntents.State {
            .init(schema: 2, store: contract.prepare.identity.store, revision: 1, volumes: [:], intents: [:], operations: [:],
                operationDigests: [:], reconciliationRequired: true)
        }
        init() throws { contract = try ColdContractFixture(); root = contract.key }
        func initial() throws -> Owner.Metadata {
            let key = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
            let recipient = Owner.Recipient(publicKey: key, incarnation: id(), daemonUniqueID: 10, childUniqueID: 11, childPID: 42)
            let grant = try Wire.Grant(operation: .initialize, id: id(), identity: contract.prepare.identity, serial: 1,
                expectedEpoch: 0, newKey: StorageIdentity.Ed25519SPKI(rawPublicKey: key).fingerprint.rawValue)
            let original = try Owner.GrantContext(signed: .init(grant: grant, signature: root.signature(for: grant.signingBytes)),
                recipient: recipient, requestID: id(), serviceEpoch: nil)
            var state = try Owner.baseline(identity: grant.identity, rootPublicKey: root.publicKey.rawRepresentation,
                provenanceReference: String(repeating: "a", count: 64), initialize: original)
            let epoch = id()
            state = try Owner.applying(.complete(.init(grant: grant, nonce: Data(repeating: 1, count: 32), serviceEpoch: epoch, revision: 5)),
                to: state, intents: intents)
            let service = try Wire.ServiceState(grant: grant, context: .init(serviceEpoch: epoch, controllerEpoch: 1, controllerKey: grant.newKey),
                openRevision: 3, boot: .init(identity: grant.identity, serviceEpoch: epoch, tlsRootSHA256: String(repeating: "b", count: 64),
                    serverSPKI: String(repeating: "c", count: 64), bootstrapKey: StorageIdentity.RootPublicKey(publicData: root.publicKey.rawRepresentation).fingerprint.rawValue))
            return try Owner.applying(.recordService(service), to: state, intents: intents)
        }
        func request(_ state: Owner.Metadata) throws -> Owner.ColdRequest {
            let service = try Owner.coldPredecessorService(in: state)
            let origin = state.resolvedDeadCold?.value.successorOrigin ?? state.latestCold?.completion.successorOrigin ?? contract.prepare.expectedOrigin
            let launch = try Cold.Launch(shimLaunchUUID: id(), specSHA256: String(repeating: "d", count: 64),
                initramfsSHA256: String(repeating: "e", count: 64), ext4UUID: origin.binding.ext4UUID, bytes: origin.binding.bytes)
            let greeting = try StorageLifecycleColdShimProtocol.Greeting(channelID: id(), daemonUniqueID: 20,
                rootPublicKey: root.publicKey.rawRepresentation, binding: origin.binding,
                bootBinding: .init(shimLaunchUUID: launch.shimLaunchUUID, guestBootNonce: id(), ext4UUID: launch.ext4UUID, bytes: launch.bytes),
                launch: launch, heldBackingIdentity: .init(.init(stableIdentity: origin.binding.backing.value(),
                    device: contract.prepare.mountedGreeting.heldBackingIdentity.device)))
            let recipient = Owner.Recipient(publicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation,
                incarnation: id(), daemonUniqueID: 20, childUniqueID: 21, childPID: 43)
            let predecessor = try Cold.Predecessor(currentGrant: service.grant, serviceEpoch: service.context.serviceEpoch,
                controllerEpoch: service.context.controllerEpoch, controllerKey: service.context.controllerKey,
                openRevision: service.openRevision, bootstrapKey: service.boot.bootstrapKey)
            let prepare = try Root.Prepare(operationID: id(), identity: state.identity, expectedPredecessor: predecessor,
                expectedOrigin: origin, expectedAllocatedEpoch: state.resolvedDeadCold?.value.baseEpoch ?? state.latestCold?.completion.baseEpoch ?? 1,
                candidate: .init(publicKey: .init(rawPublicKey: recipient.publicKey), childPIDHint: recipient.childPID, incarnationID: .init(recipient.incarnation)),
                mountedGreeting: greeting, nowUnixSeconds: 100, lifetimeSeconds: 60)
            return .init(prepare: prepare, recipient: recipient, prepareRequestID: id(), completionRequestID: id())
        }
        func prepared(_ request: Owner.ColdRequest, serial: UInt64? = nil, bridge: Root.ResolvedDead? = nil) throws -> Root.Prepared {
            let p = request.prepare
            let grant = try Wire.Grant(operation: .takeover, id: p.operationID, identity: p.identity,
                serial: serial ?? p.expectedPredecessor.currentGrant.serial + 1, expectedEpoch: p.expectedPredecessor.controllerEpoch,
                newKey: p.candidate.publicKey.fingerprint.rawValue)
            let signed = try Wire.SignedGrant(grant: grant, signature: root.signature(for: grant.signingBytes))
            let cold = try Cold.Request(operationID: p.operationID, predecessor: p.expectedPredecessor, takeover: signed,
                launch: p.mountedGreeting.launch, nowUnixSeconds: p.nowUnixSeconds, lifetimeSeconds: p.lifetimeSeconds)
            return try .init(signedOpen: .init(request: cold, signature: root.signature(for: cold.signingBytes)),
                successorOrigin: p.mountedGreeting.successorOrigin, baseEpoch: p.expectedAllocatedEpoch + 1, recoveryBridge: bridge)
        }
        func completion(_ prepared: Root.Prepared, _ state: Owner.Metadata, revision: UInt64? = nil,
                        tls: String? = nil, server: String? = nil) throws -> Root.Completed {
            let grant = prepared.signedOpen.request.takeover.grant, epoch = id()
            let predecessor = try Owner.coldPredecessor(in: state), oldService = try Owner.coldPredecessorService(in: state)
            let revision = revision ?? max(predecessor.controller.directResult.revision, oldService.openRevision) + 1
            let receipt = try Wire.Receipt(grant: grant, nonce: Data(repeating: 2, count: 32), serviceEpoch: epoch, revision: revision)
            let service = try Wire.ServiceState(grant: grant,
                context: .init(serviceEpoch: epoch, controllerEpoch: grant.expectedEpoch + 1, controllerKey: grant.newKey),
                openRevision: revision, boot: .init(identity: grant.identity, serviceEpoch: epoch,
                    tlsRootSHA256: tls ?? HostStorageIntents.hash(Data(id().utf8)), serverSPKI: server ?? HostStorageIntents.hash(Data(id().utf8)),
                    bootstrapKey: prepared.signedOpen.request.predecessor.bootstrapKey))
            return try .init(operationID: grant.id, signedOpenSHA256: prepared.signedOpenSHA256,
                successorOrigin: prepared.successorOrigin, baseEpoch: prepared.baseEpoch, receipt: receipt, successor: service,
                recoveryBridge: prepared.recoveryBridge)
        }
        func attempted(_ state: Owner.Metadata, _ request: Owner.ColdRequest, _ prepared: Root.Prepared) throws -> Owner.Metadata {
            let requested = try Owner.applying(.stageColdRequest(request), to: state, intents: intents)
            let authorized = try Owner.applying(.authorizeCold(prepared), to: requested, intents: intents)
            return try Owner.applying(.attemptColdBoot, to: authorized, intents: intents)
        }
        func adoption(_ request: Owner.ColdRequest) throws -> Owner.AdoptionRetry {
            let origin = request.prepare.expectedOrigin
            let status = try StorageLifecycleAdoptionRootProtocol.Status(origin: origin, shimAudit: Data(repeating: 3, count: 32),
                shimUniqueID: 30, baseEpoch: 1, committedEpoch: 1, allocatedEpoch: 1, pending: nil, latest: nil)
            let adoption = try StorageLifecycleAdoptionProtocol.Request(id: id(), origin: origin, expectedEpoch: 1,
                daemonAudit: Data(repeating: 1, count: 32), daemonUniqueID: 20,
                controllerAudit: Data(repeating: 2, count: 32), controllerUniqueID: 21)
            return .init(status: status, request: adoption, prepareRequestID: id(), completeRequestID: id())
        }
        private func id() -> String { ManagedStorageLifecycleColdCheckpointTests.id() }
    }
}
#endif

#if os(macOS)
import CEngineCore
import Foundation

extension OriginalConsumerRuntimeCarrier {
    /// Public projection of an authenticated control denial, never control authority.
    struct Registration: Codable, Sendable {
        let binding: OriginalConsumerObservationProtocol.Binding
        let operation: String
        let originalRegisterOperation: String
        let attempted: ManagedStorageControlProtocol.Binding
        let denial: String
        let authority: ManagedVolumeLifecycleCoordinator.OriginalRootAuthority
        let service: ConsumerObservationProtocol.WorkerScope
        let peer: WorkloadStorageProtocol.Peer
        let observed: ConsumerObservationProtocol.Status

        init(_ proof: ManagedVolumeLifecycleCoordinator.OriginalRegistrationAuthority,
             service: ConsumerObservationProtocol.WorkerScope, peer: WorkloadStorageProtocol.Peer,
             observed: ConsumerObservationProtocol.Status) {
            binding = proof.binding; operation = proof.operation; attempted = proof.attempted
            originalRegisterOperation = proof.originalRegisterOperation
            denial = proof.denial; authority = proof.authority
            self.service = service; self.peer = peer; self.observed = observed
        }
    }
}

extension OriginalConsumerRuntimeCarrier.Result {
    /// Called by the sealed owner before returning evidence and independently by
    /// the pinned queue before publishing after joined release and containment.
    func validateRegistration(binding expected: OriginalConsumerObservationProtocol.Binding,
                              service expectedService: ConsumerObservationProtocol.WorkerScope,
                              lifecycleIdentity: StorageLifecycleProtocol.Identity? = nil) throws {
        typealias O = OriginalConsumerObservationProtocol
        typealias C = ManagedStorageControlClient
        guard let proof = registration, let positive, let retirement, baseline == nil,
              expected.caseName.isRegistration, proof.binding == expected, proof.service == expectedService,
              proof.service.storeUUID == expected.scope.store, proof.service.serviceEpoch == expected.scope.serviceEpoch,
              DiskInitializationProtocol.validUUID(proof.service.workerUUID),
              DiskInitializationProtocol.validUUID(proof.operation),
              DiskInitializationProtocol.validUUID(proof.originalRegisterOperation),
              proof.originalRegisterOperation != retirement.operation,
              proof.operation != retirement.operation,
              proof.authority.retirement == retirement,
              !proof.peer.tlsRootDER.isEmpty, !proof.peer.serverDER.isEmpty, O.hash(proof.peer.serverKey)
        else { throw O.Failure.invalid }
        // Validate the genuine original client's successful operation and subsequent
        // attempted GETATTR against independently observed/finalized blocked Admit.
        var armed = positive; armed.stage = "armed-mounted-positive"
        _ = try O.checkedReply(JSONEncoder().encode(armed), request: .init(binding: expected, command: .arm,
            payload: JSONEncoder().encode(O.GuestArm(expected))))
        _ = try O.checkedReply(JSONEncoder().encode(positive), request: .init(binding: expected, command: .begin,
            payload: JSONEncoder().encode(O.GuestArm(expected))), previous: armed)
        _ = try O.checkedReply(JSONEncoder().encode(original), request: .init(binding: expected, command: .probe,
            payload: JSONEncoder().encode(O.Probe(arm: .init(expected), scope: expected.scope, peer: proof.peer))), previous: positive)
        try O.validateSameE(original, positive: positive, observed: proof.observed)
        guard proof.observed.query.workerScope == expectedService,
              proof.observed.query.armDigest == expected.armDigest else { throw O.Failure.invalid }
        try ConsumerObservationProtocol.validateFinalization(worker, observed: proof.observed)
        let context = try C.Context(store: expected.scope.store, serviceEpoch: expected.scope.serviceEpoch,
            controllerEpoch: expected.scope.controllerEpoch, controllerKey: expected.scope.controllerKey,
            provenanceReference: expected.armDigest, lifecycleIdentity: lifecycleIdentity)
        let authority = proof.authority
        for snapshot in [authority.before, authority.atProbe, authority.after] { try C.validate(snapshot, context: context) }
        let exact = retirement.attachment.binding
        let issued = proof.observed.query.original.binding
        guard exact.role == .runtime, exact.prepare == nil,
              exact.store == issued.store, exact.volume == issued.volume, exact.attachment == issued.attachment,
              exact.container == issued.container, exact.launch == issued.launch, exact.key == issued.key,
              exact.mode.rawValue == issued.mode,
              let active = authority.before.attachments[exact.attachment], active.binding == exact,
              active.phase == .active, active.receipt == nil, active.retirement == nil,
              authority.before.volumeLifecycles[exact.volume]?.phase == .ready,
              authority.after == authority.atProbe,
              retirement.receipt.revision > authority.before.revision,
              try ManagedVolumeLifecycleCoordinator.reconcileOriginalRetirement(operation: retirement.operation,
                binding: exact, receipt: retirement.receipt, query: authority.atProbe, context: context) == retirement
        else { throw O.Failure.invalid }
        var attachments = authority.before.attachments; attachments[exact.attachment] = retirement.attachment
        let before = authority.before, after = authority.atProbe
        guard after.attachments == attachments, after.schema == before.schema, after.store == before.store,
              after.epoch == before.epoch, after.controller == before.controller, after.volumes == before.volumes,
              after.volumeLifecycles == before.volumeLifecycles, after.prepares == before.prepares else { throw O.Failure.invalid }
        if expected.caseName == .delayedRegistration {
            guard proof.denial == "BLOCKED", proof.operation == proof.originalRegisterOperation,
                  proof.attempted == exact else { throw O.Failure.invalid }
        } else {
            let attempt = proof.attempted
            guard proof.denial == "CONFLICT", proof.operation != proof.originalRegisterOperation,
                  attempt.attachment != exact.attachment, before.attachments[attempt.attachment] == nil,
                  attempt == (try .init(store: exact.store, volume: exact.volume, attachment: attempt.attachment,
                    container: exact.container, launch: exact.launch, key: exact.key, role: exact.role, mode: exact.mode))
            else { throw O.Failure.invalid }
        }
    }
}
#endif

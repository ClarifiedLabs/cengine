#if os(macOS)
import CEngineCore
import Foundation

extension OriginalConsumerRuntimeCarrier {
    /// Closed public projection, never a constructor of the sealed owner handle.
    /// Registry evidence is not independent file-content/backing evidence.
    struct RootResult: Codable, Sendable, Equatable {
        var version: UInt32 = 1
        let binding: OriginalConsumerObservationProtocol.Binding
        let service: ConsumerObservationProtocol.WorkerScope
        let peer: WorkloadStorageProtocol.Peer
        let baseline: Baseline
        let positive: OriginalConsumerObservationProtocol.Evidence
        let original: OriginalConsumerObservationProtocol.Evidence
        let authority: ManagedVolumeLifecycleCoordinator.OriginalRootAuthority
        let worker: ConsumerObservationProtocol.Status?
        let finalized: ConsumerObservationProtocol.Status?

        func validate(original expected: OriginalConsumerObservationProtocol.Binding,
                      service expectedService: ConsumerObservationProtocol.WorkerScope,
                      lifecycleIdentity: StorageLifecycleProtocol.Identity? = nil) throws {
            typealias O = OriginalConsumerObservationProtocol
            typealias C = ManagedStorageControlClient
            guard version == 1, binding == expected, service == expectedService, binding.caseName.isRoot,
                  service.storeUUID == binding.scope.store, service.serviceEpoch == binding.scope.serviceEpoch,
                  DiskInitializationProtocol.validUUID(service.workerUUID),
                  !peer.tlsRootDER.isEmpty, !peer.serverDER.isEmpty, O.hash(peer.serverKey),
                  let roots = positive.roots else { throw O.Failure.invalid }
            guard baseline.binding == binding else { throw O.Failure.invalid }
            try baseline.validateRootPositive(positive)
            let request = O.Request(binding: binding, command: .probe,
                payload: try JSONEncoder().encode(O.Probe(arm: .init(binding), scope: binding.scope, peer: peer)))
            try O.validateRootReply(original, request: request, previous: positive)
            // Context here validates observations; it cannot mint control provenance.
            // Schema 4 requires the lifecycle owner's pinned identity. Snapshot has
            // no identity to infer, and the shim generation is not a store generation.
            let context = try C.Context(store: binding.scope.store, serviceEpoch: binding.scope.serviceEpoch,
                controllerEpoch: binding.scope.controllerEpoch, controllerKey: binding.scope.controllerKey,
                provenanceReference: binding.armDigest, lifecycleIdentity: lifecycleIdentity)
            for snapshot in [authority.before, authority.atProbe, authority.after] {
                try C.validate(snapshot, context: context)
            }
            guard authority.after == authority.atProbe else { throw O.Failure.invalid }
            func exact(_ value: ConsumerObservationProtocol.Original) throws -> ManagedStorageControlProtocol.Binding {
                let b = value.binding
                guard value.epoch == binding.scope.serviceEpoch,
                      let mode = ManagedStorageControlProtocol.Mode(rawValue: b.mode) else { throw O.Failure.invalid }
                return try .init(store: b.store, volume: b.volume, attachment: b.attachment,
                    container: b.container, launch: b.launch, key: b.key, role: .runtime, mode: mode)
            }
            let source = try exact(roots.source.read.authority), target = try exact(roots.target.read.authority)
            for item in [source, target] {
                guard let remote = authority.before.attachments[item.attachment], remote.binding == item,
                      remote.phase == .active, remote.receipt == nil, remote.retirement == nil,
                      authority.before.volumeLifecycles[item.volume]?.phase == .ready,
                      authority.before.volumes[item.volume] != nil else { throw O.Failure.invalid }
            }
            guard authority.before.volumes[source.volume]?.root != authority.before.volumes[target.volume]?.root
            else { throw O.Failure.invalid }
            if binding.caseName == .crossMountRootGrant {
                guard worker == nil, finalized == nil, authority.retirement == nil,
                      authority.before == authority.atProbe else { throw O.Failure.invalid }
            } else {
                guard let worker, let finalized, let retirement = authority.retirement else { throw O.Failure.invalid }
                try O.validateRetiredRootAdmission(original, positive: positive, request: request,
                    observed: worker, worker: service)
                try ConsumerObservationProtocol.validateFinalization(finalized, observed: worker)
                let reconciled = try ManagedVolumeLifecycleCoordinator.reconcileOriginalRetirement(
                    operation: retirement.operation, binding: source, receipt: retirement.receipt,
                    query: authority.atProbe, context: context)
                guard reconciled == retirement, retirement.receipt.revision > authority.before.revision
                else { throw O.Failure.invalid }
                var attachments = authority.before.attachments
                attachments[source.attachment] = retirement.attachment
                let before = authority.before, after = authority.atProbe
                guard after.attachments == attachments, after.schema == before.schema,
                      after.store == before.store, after.epoch == before.epoch, after.controller == before.controller,
                      after.volumes == before.volumes, after.volumeLifecycles == before.volumeLifecycles,
                      after.prepares == before.prepares else { throw O.Failure.invalid }
            }
        }
    }
}
#endif

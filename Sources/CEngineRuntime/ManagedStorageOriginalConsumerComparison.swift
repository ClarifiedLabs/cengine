#if os(macOS)
import CEngineCore
import Foundation

/// Comparison values only. These values cannot mint a verified boot or authority.
@MainActor enum ManagedStorageOriginalConsumerComparison {
    typealias Failure = ManagedStorageFailure
    struct Service {
        let storeUUID: String
        let serviceEpoch: String
        let workerUUID: String
        let controllerEpoch: UInt64
        let controllerKey: String
        init(_ ready: StorageLifecycleServiceBootProtocol.Ready) {
            storeUUID = ready.identity.store; serviceEpoch = ready.serviceEpoch; workerUUID = ready.workerUUID
            controllerEpoch = ready.controllerEpoch; controllerKey = ready.controllerKey
        }
    }
    static func correlateSameE(_ status: ConsumerObservationProtocol.Status,
        positive: OriginalConsumerObservationProtocol.Evidence,
        result: OriginalConsumerObservationProtocol.Evidence,
        scope: WorkloadStorageProtocol.Scope, peer: WorkloadStorageProtocol.Peer) throws {
        try OriginalConsumerObservationProtocol.validateSameE(result, positive: positive, observed: status)
        guard result.scope == scope, positive.scope == scope,
              result.serverDERSHA256 == WorkloadStorageProtocol.specificationDigest(peer.serverDER) else { throw Failure.invalid }
    }

    /// Wrong-Hello observes the exact predecessor before replacement. This
    /// comparison cannot turn a decoded boot into a current-worker capability.
    static func originalConsumerCurrentScope(_ binding: OriginalConsumerObservationProtocol.Binding,
        current: Service, request: StorageServiceTypes.ReplacementRequest) throws -> WorkloadStorageProtocol.Scope {
        try OriginalConsumerObservationProtocol.validate(binding)
        guard (binding.caseName.isWrongHello || binding.caseName.isSameE || binding.caseName.isRoot), binding.operationUUID == request.operationUUID,
              request.predecessor == .init(serviceEpoch: current.serviceEpoch, workerUUID: current.workerUUID),
              binding.scope.store == current.storeUUID,
              binding.scope.serviceEpoch == current.serviceEpoch,
              binding.scope.controllerEpoch == current.controllerEpoch,
              binding.scope.controllerKey == current.controllerKey else { throw Failure.invalid }
        return binding.scope
    }

    /// Pure comparison used by the real owner. It cannot mint maintenance or a
    /// verified boot; tests must obtain successor boots through authenticated IO.
    static func originalConsumerSuccessorScope(_ binding: OriginalConsumerObservationProtocol.Binding,
        successor: Service, request: StorageServiceTypes.ReplacementRequest) throws -> WorkloadStorageProtocol.Scope {
        try OriginalConsumerObservationProtocol.validate(binding)
        guard [.crossEOldLeafReconnect, .crossEExistingData, .crossERetainedFD].contains(binding.caseName),
              binding.operationUUID == request.operationUUID, binding.scope.serviceEpoch == request.predecessor.serviceEpoch,
              successor.storeUUID == binding.scope.store,
              successor.serviceEpoch != request.predecessor.serviceEpoch,
              successor.workerUUID != request.predecessor.workerUUID else { throw Failure.invalid }
        var scope = binding.scope
        scope.serviceEpoch = successor.serviceEpoch
        scope.controllerEpoch = successor.controllerEpoch; scope.controllerKey = successor.controllerKey
        return scope
    }

    static func originalConsumerTuple(_ binding: OriginalConsumerObservationProtocol.Binding,
        intent: HostStorageIntents.Intent?, retiredReceipt: ManagedStorageControlProtocol.Receipt? = nil) throws -> ConsumerObservationProtocol.Original {
        let scope = binding.scope
        guard let i = intent, i.id == scope.intent, i.store == scope.store, i.serviceEpoch == scope.serviceEpoch,
              i.controllerEpoch == scope.controllerEpoch, i.controllerKey == scope.controllerKey,
              i.container == scope.container, i.containerInstance == scope.containerInstance,
              i.launch == scope.launch, i.launch == binding.boot.shimLaunchUUID, i.prepare == scope.prepare,
              i.specificationDigest == scope.specificationDigest, i.phase == .running,
              i.slots.filter({ $0.attachment == binding.targetAttachment }).count == 1,
              let slot = i.slots.first(where: { $0.attachment == binding.targetAttachment }),
              slot.role == "runtime", slot.key == binding.key,
              slot.receipt == retiredReceipt.map(HostStorageIntents.DrainReceipt.init),
              let key = slot.key else { throw Failure.invalid }
        return .init(epoch: i.serviceEpoch, binding: .init(store: i.store, volume: slot.volume,
            attachment: slot.attachment, container: i.container, launch: i.launch, key: key, mode: slot.mode))
    }

    /// Public tuple values only; this cannot construct a probe capability. The
    /// live owner calls it before and after every suspension against its journal.
    static func originalConsumerWrongHello(_ binding: OriginalConsumerObservationProtocol.Binding,
        snapshot: ManagedStorageJournalSnapshot) throws -> ConsumerObservationProtocol.Original {
        guard binding.caseName.isWrongHello, !snapshot.reconciliationRequired,
              let intent = snapshot.intents.first(where: { $0.id == binding.scope.intent }) else { throw Failure.invalid }
        let original = try originalConsumerTuple(binding, intent: intent)
        var hello = original
        switch binding.caseName {
        case .wrongVolume:
            // The runtime carrier admits exactly this pair of actually mounted
            // credentials. Match Guest's sorted runtime alternative, never PREPARE.
            let runtime = intent.slots.filter { $0.role == "runtime" }.sorted { $0.attachment < $1.attachment }
            guard intent.prepareCompleted, runtime.count == 2,
                  Set(intent.slots.map(\.attachment)).count == intent.slots.count,
                  runtime[0].attachment == binding.targetAttachment,
                  runtime[0].volume != runtime[1].volume,
                  let alternateKey = runtime[1].key, alternateKey != binding.key,
                  runtime.allSatisfy({ slot in slot.receipt == nil && snapshot.volumes.contains(where: {
                      $0.id == slot.volume && !$0.isDeleted && $0.createdRevision != nil
                  }) }) else { throw Failure.blocked }
            hello.binding.volume = runtime[1].volume
        case .wrongKey:
            guard let key = intent.slots.sorted(by: { $0.attachment < $1.attachment }).compactMap(\.key).first(where: { $0 != original.binding.key }) else { throw Failure.blocked }
            hello.binding.key = key
        case .wrongRole:
            guard intent.slots.contains(where: { $0.role == "prepare" && $0.volume == original.binding.volume && $0.key != nil }) else { throw Failure.blocked }
            hello.binding.role = "prepare"; hello.binding.prepare = intent.prepare
        case .wrongMode:
            guard original.binding.mode == "read-only" else { throw Failure.invalid }
            hello.binding.mode = "read-write"
        case .wrongEpoch:
            hello.epoch = (original.epoch.first == "0" ? "1" : "0") + original.epoch.dropFirst()
        default: throw Failure.invalid
        }
        guard let name = ConsumerObservationProtocol.Case(rawValue: binding.caseName.rawValue) else { throw Failure.invalid }
        try ConsumerObservationProtocol.validateWrongHello(hello, original: original, caseName: name)
        return hello
    }

}
#endif

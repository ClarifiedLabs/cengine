import Foundation

extension OriginalConsumerObservationProtocol {
    /// Guest v6 observations. These DTOs do not confer authority, prove an
    /// unchanged backing store, or replace the sealed host retirement receipt.
    public struct RootRead: Codable, Sendable, Equatable {
        public var authority: ConsumerObservationProtocol.Original
        public var rootNode: UInt64
        public var node: UInt64
        public var handle: UInt64
        public var requestSequence: UInt64
        public var size: UInt32
        public var ioFlags: UInt32
        public var contentSHA256: String
    }
    public struct RootPositive: Codable, Sendable, Equatable {
        public var identitySHA256: String
        public var leafSHA256: String
        public var rootRequest: RootRequest
        public var read: RootRead
    }
    public struct RootReplay: Codable, Sendable, Equatable {
        public var source: ConsumerObservationProtocol.Original
        public var target: ConsumerObservationProtocol.Original
        public var rootNode: UInt64
        public var rootSequence: UInt64
        public var node: UInt64
        public var handle: UInt64
        public var readSequence: UInt64
        public var contentSHA256: String
    }
    public struct Roots: Codable, Sendable, Equatable {
        public var source: RootPositive
        public var target: RootPositive
        public var replay: RootReplay?
    }

    private static func validateRootHeader(_ value: Evidence, owner: Binding) throws {
        let arm = GuestArm(owner)
        guard owner.caseName.isRoot, owner.version == 6, owner.generation > 0,
              value.arm == arm, value.scope == arm.scope, value.keySHA256 == owner.key,
              value.hello == nil, value.writable == nil, value.fdOperation == "read-file-root-grant",
              value.localError.isEmpty, value.signCount == 0, value.signInputSHA256.isEmpty,
              value.bytesWrittenAfterSign == 0, value.clientWrittenBytes == 0,
              value.clientPrefixBytes == 0, value.clientPrefixSHA256.isEmpty,
              let roots = value.roots, value.rootRequest != nil else { throw Failure.invalid }
        try validateRootPair(roots, owner: owner)
        // Exact Go json.Marshal(struct{Source,Target string}) from the retained
        // pair. This binds both mounted identities, not a caller-selected hash.
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let pair = try encoder.encode(["Source": roots.source.identitySHA256, "Target": roots.target.identitySHA256])
        guard value.mountIdentitySHA256 == WorkloadStorageProtocol.specificationDigest(pair) else { throw Failure.invalid }
    }

    /// Revalidate an already decoded root projection without encoding/decoding
    /// the large evidence graph again on a bounded concurrency worker stack.
    /// Wire callers still use checkedReply's duplicate-aware exact decoder.
    public static func validateRootReply(_ value: Evidence, request: Request, previous: Evidence?) throws {
        try validate(request)
        guard request.binding.caseName.isRoot else { throw Failure.invalid }
        let probe = request.command == .probe ? try exact(Probe.self, request.payload) : nil
        try validateRootEvidence(value, request: request, previous: previous, probe: probe)
    }

    static func validateRootEvidence(_ value: Evidence, request: Request,
                                    previous: Evidence?, probe: Probe?) throws {
        let owner = request.binding, arm = GuestArm(owner)
        try validateRootHeader(value, owner: owner)
        guard let roots = value.roots, let root = value.rootRequest else { throw Failure.invalid }
        // Validate the prior phase directly rather than recursively copying this
        // large value graph onto a bounded Swift concurrency worker stack.
        switch request.command {
        case .arm:
            guard previous == nil else { throw Failure.invalid }
            try validateRootPositive(value, stage: "armed-mounted-positive")
        case .begin:
            guard var previous, previous.arm == arm else { throw Failure.invalid }
            try validateRootHeader(previous, owner: owner)
            try validateRootPositive(previous, stage: "armed-mounted-positive")
            previous.stage = "begun"
            guard value == previous else { throw Failure.invalid }
        case .probe:
            guard let previous, previous.arm == arm, let probe, probe.arm == arm,
                  probe.scope == arm.scope, value.stage == "original-root-scope-replay",
                  value.serverDERSHA256 == WorkloadStorageProtocol.specificationDigest(probe.peer.serverDER),
                  value.fdSequence == 2, previous.roots?.source == roots.source,
                  previous.roots?.target == roots.target,
                  previous.mountIdentitySHA256 == value.mountIdentitySHA256,
                  let replay = roots.replay else { throw Failure.invalid }
            try validateRootHeader(previous, owner: owner)
            try validateRootPositive(previous, stage: "begun")
            let source = roots.source.read, target = roots.target.read
            guard root.node == source.rootNode, root.requestSequence > source.requestSequence,
                  value.originalOperation == OriginalOperation(kind: "read-file-root-grant", sequence: 2,
                    errorClass: arm.caseName == .retiredRootGrantReplay ? "transport-failed" : "ok"),
                  replay.source == source.authority, replay.target == target.authority,
                  replay.rootNode == source.rootNode, replay.rootNode == target.rootNode,
                  replay.node == source.node, replay.node == target.node,
                  replay.handle == source.handle, replay.handle == target.handle,
                  target.requestSequence <= UInt64.max - 2,
                  replay.rootSequence == target.requestSequence + 1,
                  replay.readSequence == replay.rootSequence + 1,
                  replay.contentSHA256 == target.contentSHA256 else { throw Failure.invalid }
        case .result, .release, .resume, .positive: throw Failure.invalid
        }
    }

    private static func validateRootPositive(_ value: Evidence, stage: String) throws {
        guard let roots = value.roots, roots.replay == nil,
              value.rootRequest == roots.source.rootRequest, value.stage == stage,
              value.serverDERSHA256.isEmpty, value.fdSequence == 1,
              value.originalOperation == OriginalOperation(kind: "read-file-root-grant", sequence: 1,
                errorClass: "ok") else { throw Failure.invalid }
    }

    private static func validateRootPair(_ roots: Roots, owner: Binding) throws {
        let scope = owner.scope
        guard [scope.intent, scope.store, scope.serviceEpoch, scope.containerInstance, scope.launch, scope.prepare]
                .allSatisfy(DiskInitializationProtocol.validUUID),
              scope.controllerEpoch > 0, hash(scope.controllerKey), hash(scope.container), hash(scope.specificationDigest)
        else { throw Failure.invalid }
        for positive in [roots.source, roots.target] {
            let read = positive.read, hello = read.authority, binding = hello.binding
            // storagewire's normalized readonly flags; preserve the authentic
            // O_LARGEFILE/NOATIME/etc bits instead of asserting a synthetic zero.
            let readOnlyFlags: UInt32 = 0x800 | 0x8000 | 0x20000 | 0x40000 | 0x80000
            guard hash(positive.identitySHA256), hash(positive.leafSHA256), hash(read.contentSHA256),
                  positive.rootRequest.node > 0, positive.rootRequest.requestSequence > 0,
                  read.rootNode == positive.rootRequest.node, read.node > 0, read.handle > 0,
                  read.requestSequence > positive.rootRequest.requestSequence,
                  (32...4096).contains(read.size), read.ioFlags & ~readOnlyFlags == 0,
                  hello.epoch == scope.serviceEpoch, binding.store == scope.store,
                  binding.container == scope.container, binding.launch == scope.launch,
                  binding.role == "runtime", binding.prepare == nil,
                  ["read-only", "read-write"].contains(binding.mode), hash(binding.key),
                  DiskInitializationProtocol.validUUID(binding.volume),
                  DiskInitializationProtocol.validUUID(binding.attachment) else { throw Failure.invalid }
        }
        let source = roots.source, target = roots.target
        guard source.read.authority.binding.attachment == owner.targetAttachment,
              source.read.authority.binding.key == owner.key, source.leafSHA256 == owner.certificateSHA256,
              source.identitySHA256 != target.identitySHA256, source.leafSHA256 != target.leafSHA256,
              source.read.authority.binding.attachment < target.read.authority.binding.attachment,
              source.read.authority.binding.volume != target.read.authority.binding.volume,
              source.read.authority.binding.key != target.read.authority.binding.key,
              source.read.contentSHA256 != target.read.contentSHA256,
              source.read.size == target.read.size, source.read.ioFlags == target.read.ioFlags else { throw Failure.invalid }
    }

    /// Join v6 guest operands to the existing worker's exact GETATTR Admit
    /// recorder. Reusing this fixed-operation recorder is not a new authority or
    /// a substitute for Retire/query reconciliation. Host must retain that proof
    /// and validate both installed attachments/backing before enabling root2.
    public static func validateRetiredRootAdmission(_ value: Evidence, positive: Evidence,
        request: Request, observed: ConsumerObservationProtocol.Status,
        worker: ConsumerObservationProtocol.WorkerScope) throws {
        guard request.command == .probe, request.binding.caseName == .retiredRootGrantReplay else { throw Failure.invalid }
        try validateRootReply(value, request: request, previous: positive)
        try ConsumerObservationProtocol.validate(observed)
        let owner = request.binding, query = observed.query
        guard observed.state == .observed, query.version == 6, query.caseName == .sameE,
              query.requestID == owner.requestID, query.armDigest == owner.armDigest,
              query.operationUUID == owner.operationUUID, query.originalBootBinding == owner.boot,
              query.originalLeafSHA256 == owner.certificateSHA256,
              query.workerScope == worker, worker.storeUUID == owner.scope.store,
              worker.serviceEpoch == owner.scope.serviceEpoch,
              query.original == positive.roots?.source.read.authority,
              let admission = observed.evidence?.admission, let root = value.rootRequest,
              admission.node == root.node, admission.requestSequence == root.requestSequence
        else { throw Failure.invalid }
    }
}

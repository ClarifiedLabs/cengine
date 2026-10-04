import Foundation

/// Private storage service boot messages. Values are not authenticated capabilities.
/// Every peer must use encode/decode, not bare Codable, for the closed schema.
public enum StorageLifecycleServiceBootProtocol {
    public typealias L = StorageLifecycleProtocol
    public typealias Binding = DiskInitializationProtocol.Binding
    public typealias Controller = StorageServiceTypes.Controller
    public static let version = "storage-service-lifecycle.v2"
    public static let maxFrame = StorageServiceTypes.maxFrame
    public static let maximumDERSize = StorageServiceTypes.maximumDERSize
    /// Bound on a notifications reply (same bound as the v1 wire).
    public static let maximumNotifications = StorageServiceTypes.maximumNotifications
    /// Wire shape is storageauthority.DataHello {epoch, binding}; a neutral public value.
    public typealias Notification = StorageServiceTypes.Notification
    public typealias IsolationRequest = StorageServiceTypes.IsolationRequest
    public typealias IsolationProof = StorageServiceTypes.IsolationProof
    public enum ValidationError: Error, Sendable { case invalidFrame }
    public enum Operation: String, Codable, Sendable { case hello, configure, ready, command, reply, error }
    public enum Command: String, Codable, Sendable {
        case issueController = "issue-controller", authorizeSuccessor = "authorize-successor"
        case authorizeRetirement = "authorize-retirement", reconcileController = "reconcile-controller", query
        case serviceStatus = "service-status", replaceService = "replace-service"
        case fenceHandoff = "fence-handoff"
        /// Carries no body: keyed only by the envelope predecessor pair
        /// (worker_uuid + service_epoch) of the replace-service command.
        case replacementStatus = "replacement-status", notifications
        case isolationState = "isolation-state"
        case legacyConnection = "legacy-connection"
        case secondServiceExclusivity = "second-service-exclusivity"
        case consumerObservationArm = "consumer-observation-arm"
        case consumerObservationQuery = "consumer-observation-query"
        case consumerObservationFinalize = "consumer-observation-finalize"
        case prepareCompatibilityArm = "prepare-compatibility-arm"
        case prepareCompatibilityObserve = "prepare-compatibility-observe"
        case prepareCompatibilityRelease = "prepare-compatibility-release"
        case prepareCompatibilityWorkerExit = "prepare-compatibility-worker-exit"
        case prepareCompatibilityCheckpointExit = "prepare-compatibility-checkpoint-exit"
    }
    public enum Code: String, Codable, Sendable {
        case configuration, bindingMismatch = "binding-mismatch", sequence, command, service, invalidFrame = "invalid-frame"
        /// Supervisor-internal codes, representable on the closed wire.
        case staleWorker = "stale-worker", workerBusy = "worker-busy", workerLost = "worker-lost", workerUnreaped = "worker-unreaped", replacementConflict = "replacement-conflict"
    }

    public struct Configuration: Codable, Equatable, Sendable {
        public enum Action: String, Codable, Sendable { case initialize, open, coldOpenTakeover = "cold-open-takeover", resumeOpenTakeover = "resume-open-takeover" }
        public let action: Action
        public let rootPublicKey: Data
        public let signed: L.SignedGrant
        public let nowUnixSeconds: UInt64
        public let lifetimeSeconds: UInt64
        /// ROOT-signed; an unsigned daemon-fabricated reopen is rejected by validate().
        public let reopen: L.SignedServiceChange?
        public let cold: StorageLifecycleColdProtocol.SignedOpen?
        public let resume: StorageLifecycleResumeProtocol.SignedOpen?
        public init(action: Action, rootPublicKey: Data, signed: L.SignedGrant, nowUnixSeconds: UInt64, lifetimeSeconds: UInt64, reopen: L.SignedServiceChange? = nil, cold: StorageLifecycleColdProtocol.SignedOpen? = nil, resume: StorageLifecycleResumeProtocol.SignedOpen? = nil) {
            self.action = action; self.rootPublicKey = rootPublicKey; self.signed = signed
            self.nowUnixSeconds = nowUnixSeconds; self.lifetimeSeconds = lifetimeSeconds; self.reopen = reopen; self.cold = cold; self.resume = resume
        }
        enum CodingKeys: String, CodingKey {
            case action, signed, reopen, cold, resume, rootPublicKey = "root_public_key", nowUnixSeconds = "now_unix_seconds", lifetimeSeconds = "lifetime_seconds"
        }
        public func validate() throws {
            try signed.validate()
            guard rootPublicKey.count == 32, nowUnixSeconds > 0,
                  nowUnixSeconds <= StorageServiceTypes.maximumUnixSeconds,
                  lifetimeSeconds > 0, lifetimeSeconds <= 86_400,
                  signed.grant.operation != .retire,
                  action != .initialize || signed.grant.operation == .initialize else { throw ValidationError.invalidFrame }
            // Mirror Go lifecycleConstruct: the grant must be signed by this root,
            // so a self-consistent attacker root/bootstrap pair cannot validate.
            guard signed.isValidSignature(using: try L.Bootstrap.RootPublicKey(publicData: rootPublicKey)) else {
                throw ValidationError.invalidFrame
            }
            switch action {
            case .initialize:
                guard reopen == nil, cold == nil, resume == nil else { throw ValidationError.invalidFrame }
            case .open:
                guard let reopen, cold == nil, resume == nil else { throw ValidationError.invalidFrame }
                try reopen.validate()
                let root = try L.Bootstrap.RootPublicKey(publicData: rootPublicKey)
                guard signed.grant == reopen.request.predecessor.grant,
                      reopen.isValidSignature(using: root) else { throw ValidationError.invalidFrame }
            case .coldOpenTakeover:
                guard let cold, reopen == nil, resume == nil else { throw ValidationError.invalidFrame }
                try cold.validate()
                let root = try L.Bootstrap.RootPublicKey(publicData: rootPublicKey)
                guard signed == cold.request.takeover, nowUnixSeconds == cold.request.nowUnixSeconds,
                      lifetimeSeconds == cold.request.lifetimeSeconds,
                      cold.isValidSignature(using: root) else { throw ValidationError.invalidFrame }
            case .resumeOpenTakeover:
                guard let resume, reopen == nil, cold == nil else { throw ValidationError.invalidFrame }
                try resume.validate()
                let root = try L.Bootstrap.RootPublicKey(publicData: rootPublicKey)
                guard signed == resume.request.takeover, nowUnixSeconds == resume.request.nowUnixSeconds,
                      lifetimeSeconds == resume.request.lifetimeSeconds,
                      resume.isValidSignature(using: root) else { throw ValidationError.invalidFrame }
            }
        }
    }
    /// Same-worker replacement request: the successor boot that takes over a lost worker.
    public struct ReplacementRequest: Codable, Equatable, Sendable {
        public let predecessorWorkerUUID: String
        /// Open-only; carries grant/root/now/lifetime/reopen so nothing is duplicated.
        public let configuration: Configuration
        public init(predecessorWorkerUUID: String, configuration: Configuration) {
            self.predecessorWorkerUUID = predecessorWorkerUUID; self.configuration = configuration
        }
        enum CodingKeys: String, CodingKey {
            case configuration, predecessorWorkerUUID = "predecessor_worker_uuid"
        }
        public func validate() throws {
            guard StorageServiceTypes.validID(predecessorWorkerUUID),
                  configuration.action == .open else { throw ValidationError.invalidFrame }
            try configuration.validate()
        }
    }
    /// Envelope-bound service state; no scope is carried here.
    public struct ServiceStatus: Codable, Equatable, Sendable {
        public enum Phase: String, Codable, Sendable {
            case ready, workerLost = "worker-lost", replacing, failed
        }
        public let phase: Phase
        public init(phase: Phase) { self.phase = phase }
        enum CodingKeys: String, CodingKey { case phase }
        /// Phase is closed by decoding; validate exists for uniform nested checks.
        public func validate() throws {}
    }
    public enum ReplacementCode: String, Codable, Sendable {
        case replacementFailed = "replacement-failed", workerUnreaped = "worker-unreaped"
    }
    public struct ReplacementStatus: Codable, Equatable, Sendable {
        public enum Phase: String, Codable, Sendable { case pending, succeeded, failed }
        public let request: ReplacementRequest
        public let phase: Phase
        public let ready: Ready?
        public let code: ReplacementCode?
        public init(request: ReplacementRequest, phase: Phase, ready: Ready? = nil, code: ReplacementCode? = nil) {
            self.request = request; self.phase = phase; self.ready = ready; self.code = code
        }
        enum CodingKeys: String, CodingKey { case request, phase, ready, code }
        public func validate() throws {
            try request.validate()
            switch phase {
            case .pending:
                guard ready == nil, code == nil else { throw ValidationError.invalidFrame }
            case .succeeded:
                guard ready != nil, code == nil else { throw ValidationError.invalidFrame }
                try ready?.validate()
            case .failed:
                guard ready == nil, code != nil else { throw ValidationError.invalidFrame }
            }
        }
    }
    public struct Ready: Codable, Equatable, Sendable {
        public let identity: L.Identity
        public let serviceEpoch: String
        public let workerUUID: String
        public let controllerEpoch: UInt64
        public let controllerKey: String
        public let revision: UInt64
        public let openRevision: UInt64
        public let bootstrapKey: String
        public let tlsRootDER: Data
        public let serverDER: Data
        public let serverSPKI: String
        public init(identity: L.Identity, serviceEpoch: String, workerUUID: String, controllerEpoch: UInt64,
                    controllerKey: String, revision: UInt64, openRevision: UInt64, bootstrapKey: String, tlsRootDER: Data, serverDER: Data, serverSPKI: String) {
            self.identity = identity; self.serviceEpoch = serviceEpoch; self.workerUUID = workerUUID
            self.controllerEpoch = controllerEpoch; self.controllerKey = controllerKey; self.revision = revision; self.openRevision = openRevision
            self.bootstrapKey = bootstrapKey; self.tlsRootDER = tlsRootDER; self.serverDER = serverDER; self.serverSPKI = serverSPKI
        }
        enum CodingKeys: String, CodingKey {
            case openRevision = "open_revision"
            case identity, revision, serviceEpoch = "service_epoch", workerUUID = "worker_uuid"
            case controllerEpoch = "controller_epoch", controllerKey = "controller_key", bootstrapKey = "bootstrap_key"
            case tlsRootDER = "tls_root_der", serverDER = "server_der", serverSPKI = "server_spki"
        }
        public func validate() throws {
            try identity.validate()
            guard StorageServiceTypes.validID(serviceEpoch), StorageServiceTypes.validID(workerUUID),
                  controllerEpoch > 0, revision > 0, openRevision > 0, openRevision <= revision else { throw ValidationError.invalidFrame }
            for key in [controllerKey, bootstrapKey, serverSPKI] { _ = try L.Bootstrap.SPKISHA256(key) }
            try der(tlsRootDER); try der(serverDER)
        }
    }
    /// A fence receipt and actual live state, never ordinary query authority.
    public struct HandoffReply: Codable, Equatable, Sendable {
        public let result: StorageLifecycleHandoffProtocol.Result
        public let ready: Ready
        public init(result: StorageLifecycleHandoffProtocol.Result, ready: Ready) {
            self.result = result; self.ready = ready
        }
        public func validate() throws {
            try result.validate(); try ready.validate()
            let grant = result.appliedGrant
            guard ready.identity == grant.identity, ready.serviceEpoch == result.request.serviceEpoch,
                  ready.openRevision == result.request.openRevision, grant.expectedEpoch < UInt64.max,
                  ready.controllerEpoch == grant.expectedEpoch + 1, ready.controllerKey == grant.newKey,
                  ready.revision >= result.fenceRevision else { throw ValidationError.invalidFrame }
        }
    }
    /// Keep nested carrier values off caller stacks. Each assignment replaces an
    /// immutable box, so copies remain independent without unchecked Sendable or
    /// mutable shared storage. Nil allocates nothing; equality remains structural.
    /// Fields stay independent so invalid unions are rejected, never normalized.
    private struct Carrier<Value: Equatable & Sendable>: Equatable, Sendable {
        private final class Storage: Sendable {
            let value: Value
            init(_ value: Value) { self.value = value }
        }
        private var storage: Storage?
        var value: Value? {
            get { storage?.value }
            set { storage = newValue.map(Storage.init) }
        }
        init(_ value: Value? = nil) {
            storage = value.map(Storage.init)
        }
        static func == (lhs: Self, rhs: Self) -> Bool {
            lhs.storage?.value == rhs.storage?.value
        }
    }
    /// One envelope, with dependent fields checked by validate(). Null is never omission.
    public struct Frame: Codable, Equatable, Sendable {
        public var version = StorageLifecycleServiceBootProtocol.version
        public var operation: Operation
        public var binding: Binding
        private var _configuration = Carrier<Configuration>()
        public var configuration: Configuration? {
            get { _configuration.value }
            set { _configuration.value = newValue }
        }
        private var _ready = Carrier<Ready>()
        public var ready: Ready? {
            get { _ready.value }
            set { _ready.value = newValue }
        }
        public var sequence: UInt64?
        public var serviceEpoch: String?
        public var command: Command?
        public var csr: Data?
        private var _signed = Carrier<L.SignedGrant>()
        public var signed: L.SignedGrant? {
            get { _signed.value }
            set { _signed.value = newValue }
        }
        private var _controller = Carrier<Controller>()
        public var controller: Controller? {
            get { _controller.value }
            set { _controller.value = newValue }
        }
        private var _handoff = Carrier<StorageLifecycleHandoffProtocol.SignedRequest>()
        public var handoff: StorageLifecycleHandoffProtocol.SignedRequest? {
            get { _handoff.value }
            set { _handoff.value = newValue }
        }
        public var nonce: Data?
        private var _handoffResult = Carrier<HandoffReply>()
        public var handoffResult: HandoffReply? {
            get { _handoffResult.value }
            set { _handoffResult.value = newValue }
        }
        public var certificate: Data?
        public var ok: Bool?
        public var code: Code?
        public var workerUUID: String?
        private var _replacementRequest = Carrier<ReplacementRequest>()
        public var replacementRequest: ReplacementRequest? {
            get { _replacementRequest.value }
            set { _replacementRequest.value = newValue }
        }
        private var _status = Carrier<ServiceStatus>()
        public var status: ServiceStatus? {
            get { _status.value }
            set { _status.value = newValue }
        }
        private var _replacement = Carrier<ReplacementStatus>()
        public var replacement: ReplacementStatus? {
            get { _replacement.value }
            set { _replacement.value = newValue }
        }
        /// Sole result of a notifications reply; bounded by maximumNotifications.
        public var notifications: [Notification]?
        /// Isolation evidence only; never readiness, a grant, or trust.
        private var _isolationRequest = Carrier<IsolationRequest>()
        public var isolationRequest: IsolationRequest? {
            get { _isolationRequest.value }
            set { _isolationRequest.value = newValue }
        }
        private var _isolationProof = Carrier<IsolationProof>()
        public var isolationProof: IsolationProof? {
            get { _isolationProof.value }
            set { _isolationProof.value = newValue }
        }
        /// Observation evidence only; never readiness or lifecycle authority.
        private var _consumerObservationArm = Carrier<ConsumerObservationProtocol.Arm>()
        public var consumerObservationArm: ConsumerObservationProtocol.Arm? {
            get { _consumerObservationArm.value }
            set { _consumerObservationArm.value = newValue }
        }
        private var _consumerObservationQuery = Carrier<ConsumerObservationProtocol.Query>()
        public var consumerObservationQuery: ConsumerObservationProtocol.Query? {
            get { _consumerObservationQuery.value }
            set { _consumerObservationQuery.value = newValue }
        }
        private var _consumerObservationStatus = Carrier<ConsumerObservationProtocol.Status>()
        public var consumerObservationStatus: ConsumerObservationProtocol.Status? {
            get { _consumerObservationStatus.value }
            set { _consumerObservationStatus.value = newValue }
        }
        /// Compatibility evidence only; these carriers confer no lifecycle authority.
        private var _prepareCompatibilityArm = Carrier<ManagedPrepareCompatibilityProtocol.StorageArm>()
        public var prepareCompatibilityArm: ManagedPrepareCompatibilityProtocol.StorageArm? {
            get { _prepareCompatibilityArm.value }
            set { _prepareCompatibilityArm.value = newValue }
        }
        private var _prepareCompatibilityQuery = Carrier<ManagedPrepareCompatibilityProtocol.StorageQuery>()
        public var prepareCompatibilityQuery: ManagedPrepareCompatibilityProtocol.StorageQuery? {
            get { _prepareCompatibilityQuery.value }
            set { _prepareCompatibilityQuery.value = newValue }
        }
        private var _prepareCompatibilityRelease = Carrier<ManagedPrepareCompatibilityProtocol.StorageRelease>()
        public var prepareCompatibilityRelease: ManagedPrepareCompatibilityProtocol.StorageRelease? {
            get { _prepareCompatibilityRelease.value }
            set { _prepareCompatibilityRelease.value = newValue }
        }
        private var _prepareCompatibilityWorkerExit = Carrier<ManagedPrepareCompatibilityProtocol.StorageRelease>()
        public var prepareCompatibilityWorkerExit: ManagedPrepareCompatibilityProtocol.StorageRelease? {
            get { _prepareCompatibilityWorkerExit.value }
            set { _prepareCompatibilityWorkerExit.value = newValue }
        }
        private var _prepareCompatibilityCheckpointExit = Carrier<ManagedPrepareWorkerCheckpointProtocol.WorkerCheckpointExit>()
        public var prepareCompatibilityCheckpointExit: ManagedPrepareWorkerCheckpointProtocol.WorkerCheckpointExit? {
            get { _prepareCompatibilityCheckpointExit.value }
            set { _prepareCompatibilityCheckpointExit.value = newValue }
        }
        private var _prepareCompatibilityStatus = Carrier<ManagedPrepareCompatibilityProtocol.StorageStatus>()
        public var prepareCompatibilityStatus: ManagedPrepareCompatibilityProtocol.StorageStatus? {
            get { _prepareCompatibilityStatus.value }
            set { _prepareCompatibilityStatus.value = newValue }
        }
        private var _prepareCompatibilityWorkerWait = Carrier<ManagedPrepareCompatibilityProtocol.StorageWorkerWait>()
        public var prepareCompatibilityWorkerWait: ManagedPrepareCompatibilityProtocol.StorageWorkerWait? {
            get { _prepareCompatibilityWorkerWait.value }
            set { _prepareCompatibilityWorkerWait.value = newValue }
        }
        private var _prepareCompatibilityCheckpointAck = Carrier<ManagedPrepareWorkerCheckpointProtocol.WorkerCheckpointExit>()
        public var prepareCompatibilityCheckpointAck: ManagedPrepareWorkerCheckpointProtocol.WorkerCheckpointExit? {
            get { _prepareCompatibilityCheckpointAck.value }
            set { _prepareCompatibilityCheckpointAck.value = newValue }
        }
        private var _prepareCompatibilityCheckpointWait = Carrier<ManagedPrepareWorkerCheckpointProtocol.WorkerCheckpointWait>()
        public var prepareCompatibilityCheckpointWait: ManagedPrepareWorkerCheckpointProtocol.WorkerCheckpointWait? {
            get { _prepareCompatibilityCheckpointWait.value }
            set { _prepareCompatibilityCheckpointWait.value = newValue }
        }
        public init(operation: Operation, binding: Binding, configuration: Configuration? = nil, ready: Ready? = nil,
                    sequence: UInt64? = nil, serviceEpoch: String? = nil, command: Command? = nil, csr: Data? = nil,
                    signed: L.SignedGrant? = nil, controller: Controller? = nil, certificate: Data? = nil, ok: Bool? = nil, code: Code? = nil,
                    workerUUID: String? = nil, replacementRequest: ReplacementRequest? = nil, status: ServiceStatus? = nil, replacement: ReplacementStatus? = nil,
                    notifications: [Notification]? = nil,
                    handoff: StorageLifecycleHandoffProtocol.SignedRequest? = nil, nonce: Data? = nil, handoffResult: HandoffReply? = nil,
                    isolationRequest: IsolationRequest? = nil, isolationProof: IsolationProof? = nil,
                    consumerObservationArm: ConsumerObservationProtocol.Arm? = nil,
                    consumerObservationQuery: ConsumerObservationProtocol.Query? = nil,
                    consumerObservationStatus: ConsumerObservationProtocol.Status? = nil,

                    prepareCompatibilityArm: ManagedPrepareCompatibilityProtocol.StorageArm? = nil,
                    prepareCompatibilityQuery: ManagedPrepareCompatibilityProtocol.StorageQuery? = nil,
                    prepareCompatibilityRelease: ManagedPrepareCompatibilityProtocol.StorageRelease? = nil,
                    prepareCompatibilityWorkerExit: ManagedPrepareCompatibilityProtocol.StorageRelease? = nil,
                    prepareCompatibilityCheckpointExit: ManagedPrepareWorkerCheckpointProtocol.WorkerCheckpointExit? = nil,
                    prepareCompatibilityStatus: ManagedPrepareCompatibilityProtocol.StorageStatus? = nil,
                    prepareCompatibilityWorkerWait: ManagedPrepareCompatibilityProtocol.StorageWorkerWait? = nil,
                    prepareCompatibilityCheckpointAck: ManagedPrepareWorkerCheckpointProtocol.WorkerCheckpointExit? = nil,
                    prepareCompatibilityCheckpointWait: ManagedPrepareWorkerCheckpointProtocol.WorkerCheckpointWait? = nil) {
            self.operation = operation; self.binding = binding; self.configuration = configuration; self.ready = ready
            self.sequence = sequence; self.serviceEpoch = serviceEpoch; self.command = command; self.csr = csr
            self.signed = signed; self.controller = controller; self.certificate = certificate; self.ok = ok; self.code = code
            self.workerUUID = workerUUID; self.replacementRequest = replacementRequest; self.status = status; self.replacement = replacement
            self.notifications = notifications
            self.handoff = handoff; self.nonce = nonce; self.handoffResult = handoffResult
            self.isolationRequest = isolationRequest; self.isolationProof = isolationProof
            self.consumerObservationArm = consumerObservationArm
            self.consumerObservationQuery = consumerObservationQuery
            self.consumerObservationStatus = consumerObservationStatus
            self.prepareCompatibilityArm = prepareCompatibilityArm
            self.prepareCompatibilityQuery = prepareCompatibilityQuery
            self.prepareCompatibilityRelease = prepareCompatibilityRelease
            self.prepareCompatibilityWorkerExit = prepareCompatibilityWorkerExit
            self.prepareCompatibilityCheckpointExit = prepareCompatibilityCheckpointExit
            self.prepareCompatibilityStatus = prepareCompatibilityStatus
            self.prepareCompatibilityWorkerWait = prepareCompatibilityWorkerWait
            self.prepareCompatibilityCheckpointAck = prepareCompatibilityCheckpointAck
            self.prepareCompatibilityCheckpointWait = prepareCompatibilityCheckpointWait
        }
        enum CodingKeys: String, CodingKey {
            case version, operation, binding, configuration, ready, sequence, command, csr, signed, controller, certificate, ok, code
            case handoff, nonce, handoffResult = "handoff_result"
            case serviceEpoch = "service_epoch"
            case workerUUID = "worker_uuid", replacementRequest = "replacement_request", status, replacement, notifications
            // Preserve the v1 carrier spelling; envelope identity keys stay snake_case.
            case isolationRequest, isolationProof
            case consumerObservationArm
            case consumerObservationQuery
            case consumerObservationStatus
            case prepareCompatibilityArm
            case prepareCompatibilityQuery
            case prepareCompatibilityRelease
            case prepareCompatibilityWorkerExit
            case prepareCompatibilityCheckpointExit
            case prepareCompatibilityStatus
            case prepareCompatibilityWorkerWait
            case prepareCompatibilityCheckpointAck
            case prepareCompatibilityCheckpointWait
        }
        // Decode/encode one field at a time: synthesized Codable materializes all
        // large nested compatibility carriers together on cooperative thread stacks.
        public init(from decoder: any Decoder) throws {
            let fields = try decoder.container(keyedBy: CodingKeys.self)
            self.version = try fields.decode(String.self, forKey: .version)
            self.operation = try fields.decode(Operation.self, forKey: .operation)
            self.binding = try fields.decode(Binding.self, forKey: .binding)
            self.configuration = try fields.decodeIfPresent(Configuration.self, forKey: .configuration)
            self.ready = try fields.decodeIfPresent(Ready.self, forKey: .ready)
            self.sequence = try fields.decodeIfPresent(UInt64.self, forKey: .sequence)
            self.serviceEpoch = try fields.decodeIfPresent(String.self, forKey: .serviceEpoch)
            self.command = try fields.decodeIfPresent(Command.self, forKey: .command)
            self.csr = try fields.decodeIfPresent(Data.self, forKey: .csr)
            self.signed = try fields.decodeIfPresent(L.SignedGrant.self, forKey: .signed)
            self.controller = try fields.decodeIfPresent(Controller.self, forKey: .controller)
            self.handoff = try fields.decodeIfPresent(StorageLifecycleHandoffProtocol.SignedRequest.self, forKey: .handoff)
            self.nonce = try fields.decodeIfPresent(Data.self, forKey: .nonce)
            self.handoffResult = try fields.decodeIfPresent(HandoffReply.self, forKey: .handoffResult)
            self.certificate = try fields.decodeIfPresent(Data.self, forKey: .certificate)
            self.ok = try fields.decodeIfPresent(Bool.self, forKey: .ok)
            self.code = try fields.decodeIfPresent(Code.self, forKey: .code)
            self.workerUUID = try fields.decodeIfPresent(String.self, forKey: .workerUUID)
            self.replacementRequest = try fields.decodeIfPresent(ReplacementRequest.self, forKey: .replacementRequest)
            self.status = try fields.decodeIfPresent(ServiceStatus.self, forKey: .status)
            self.replacement = try fields.decodeIfPresent(ReplacementStatus.self, forKey: .replacement)
            self.notifications = try fields.decodeIfPresent([Notification].self, forKey: .notifications)
            self.isolationRequest = try fields.decodeIfPresent(IsolationRequest.self, forKey: .isolationRequest)
            self.isolationProof = try fields.decodeIfPresent(IsolationProof.self, forKey: .isolationProof)
            self.consumerObservationArm = try fields.decodeIfPresent(ConsumerObservationProtocol.Arm.self, forKey: .consumerObservationArm)
            self.consumerObservationQuery = try fields.decodeIfPresent(ConsumerObservationProtocol.Query.self, forKey: .consumerObservationQuery)
            self.consumerObservationStatus = try fields.decodeIfPresent(ConsumerObservationProtocol.Status.self, forKey: .consumerObservationStatus)
            self.prepareCompatibilityArm = try fields.decodeIfPresent(ManagedPrepareCompatibilityProtocol.StorageArm.self, forKey: .prepareCompatibilityArm)
            self.prepareCompatibilityQuery = try fields.decodeIfPresent(ManagedPrepareCompatibilityProtocol.StorageQuery.self, forKey: .prepareCompatibilityQuery)
            self.prepareCompatibilityRelease = try fields.decodeIfPresent(ManagedPrepareCompatibilityProtocol.StorageRelease.self, forKey: .prepareCompatibilityRelease)
            self.prepareCompatibilityWorkerExit = try fields.decodeIfPresent(ManagedPrepareCompatibilityProtocol.StorageRelease.self, forKey: .prepareCompatibilityWorkerExit)
            self.prepareCompatibilityCheckpointExit = try fields.decodeIfPresent(ManagedPrepareWorkerCheckpointProtocol.WorkerCheckpointExit.self, forKey: .prepareCompatibilityCheckpointExit)
            self.prepareCompatibilityStatus = try fields.decodeIfPresent(ManagedPrepareCompatibilityProtocol.StorageStatus.self, forKey: .prepareCompatibilityStatus)
            self.prepareCompatibilityWorkerWait = try fields.decodeIfPresent(ManagedPrepareCompatibilityProtocol.StorageWorkerWait.self, forKey: .prepareCompatibilityWorkerWait)
            self.prepareCompatibilityCheckpointAck = try fields.decodeIfPresent(ManagedPrepareWorkerCheckpointProtocol.WorkerCheckpointExit.self, forKey: .prepareCompatibilityCheckpointAck)
            self.prepareCompatibilityCheckpointWait = try fields.decodeIfPresent(ManagedPrepareWorkerCheckpointProtocol.WorkerCheckpointWait.self, forKey: .prepareCompatibilityCheckpointWait)
        }
        public func encode(to encoder: any Encoder) throws {
            var fields = encoder.container(keyedBy: CodingKeys.self)
            try fields.encode(version, forKey: .version)
            try fields.encode(operation, forKey: .operation)
            try fields.encode(binding, forKey: .binding)
            try fields.encodeIfPresent(configuration, forKey: .configuration)
            try fields.encodeIfPresent(ready, forKey: .ready)
            try fields.encodeIfPresent(sequence, forKey: .sequence)
            try fields.encodeIfPresent(serviceEpoch, forKey: .serviceEpoch)
            try fields.encodeIfPresent(command, forKey: .command)
            try fields.encodeIfPresent(csr, forKey: .csr)
            try fields.encodeIfPresent(signed, forKey: .signed)
            try fields.encodeIfPresent(controller, forKey: .controller)
            try fields.encodeIfPresent(handoff, forKey: .handoff)
            try fields.encodeIfPresent(nonce, forKey: .nonce)
            try fields.encodeIfPresent(handoffResult, forKey: .handoffResult)
            try fields.encodeIfPresent(certificate, forKey: .certificate)
            try fields.encodeIfPresent(ok, forKey: .ok)
            try fields.encodeIfPresent(code, forKey: .code)
            try fields.encodeIfPresent(workerUUID, forKey: .workerUUID)
            try fields.encodeIfPresent(replacementRequest, forKey: .replacementRequest)
            try fields.encodeIfPresent(status, forKey: .status)
            try fields.encodeIfPresent(replacement, forKey: .replacement)
            try fields.encodeIfPresent(notifications, forKey: .notifications)
            try fields.encodeIfPresent(isolationRequest, forKey: .isolationRequest)
            try fields.encodeIfPresent(isolationProof, forKey: .isolationProof)
            try fields.encodeIfPresent(consumerObservationArm, forKey: .consumerObservationArm)
            try fields.encodeIfPresent(consumerObservationQuery, forKey: .consumerObservationQuery)
            try fields.encodeIfPresent(consumerObservationStatus, forKey: .consumerObservationStatus)
            try fields.encodeIfPresent(prepareCompatibilityArm, forKey: .prepareCompatibilityArm)
            try fields.encodeIfPresent(prepareCompatibilityQuery, forKey: .prepareCompatibilityQuery)
            try fields.encodeIfPresent(prepareCompatibilityRelease, forKey: .prepareCompatibilityRelease)
            try fields.encodeIfPresent(prepareCompatibilityWorkerExit, forKey: .prepareCompatibilityWorkerExit)
            try fields.encodeIfPresent(prepareCompatibilityCheckpointExit, forKey: .prepareCompatibilityCheckpointExit)
            try fields.encodeIfPresent(prepareCompatibilityStatus, forKey: .prepareCompatibilityStatus)
            try fields.encodeIfPresent(prepareCompatibilityWorkerWait, forKey: .prepareCompatibilityWorkerWait)
            try fields.encodeIfPresent(prepareCompatibilityCheckpointAck, forKey: .prepareCompatibilityCheckpointAck)
            try fields.encodeIfPresent(prepareCompatibilityCheckpointWait, forKey: .prepareCompatibilityCheckpointWait)
        }
        public func validate() throws {
            guard version == StorageLifecycleServiceBootProtocol.version,
                  StorageServiceTypes.validID(binding.shimLaunchUUID), StorageServiceTypes.validID(binding.guestBootNonce),
                  StorageServiceTypes.validUUID(binding.ext4UUID), binding.bytes > 0, binding.bytes <= UInt64(Int64.max) else { throw ValidationError.invalidFrame }
            let present: Set<String> = Set([
                configuration == nil ? nil : "configuration", ready == nil ? nil : "ready", sequence == nil ? nil : "sequence",
                serviceEpoch == nil ? nil : "service_epoch", command == nil ? nil : "command", csr == nil ? nil : "csr",
                signed == nil ? nil : "signed", controller == nil ? nil : "controller", certificate == nil ? nil : "certificate",
                ok == nil ? nil : "ok", code == nil ? nil : "code",
                workerUUID == nil ? nil : "worker_uuid", replacementRequest == nil ? nil : "replacement_request",
                status == nil ? nil : "status", replacement == nil ? nil : "replacement",
                notifications == nil ? nil : "notifications",
                handoff == nil ? nil : "handoff", nonce == nil ? nil : "nonce", handoffResult == nil ? nil : "handoff_result",
                isolationRequest == nil ? nil : "isolationRequest",
                isolationProof == nil ? nil : "isolationProof",
                consumerObservationArm == nil ? nil : "consumerObservationArm",
                consumerObservationQuery == nil ? nil : "consumerObservationQuery",
                consumerObservationStatus == nil ? nil : "consumerObservationStatus",
                prepareCompatibilityArm == nil ? nil : "prepareCompatibilityArm",
                prepareCompatibilityQuery == nil ? nil : "prepareCompatibilityQuery",
                prepareCompatibilityRelease == nil ? nil : "prepareCompatibilityRelease",
                prepareCompatibilityWorkerExit == nil ? nil : "prepareCompatibilityWorkerExit",
                prepareCompatibilityCheckpointExit == nil ? nil : "prepareCompatibilityCheckpointExit",
                prepareCompatibilityStatus == nil ? nil : "prepareCompatibilityStatus",
                prepareCompatibilityWorkerWait == nil ? nil : "prepareCompatibilityWorkerWait",
                prepareCompatibilityCheckpointAck == nil ? nil : "prepareCompatibilityCheckpointAck",
                prepareCompatibilityCheckpointWait == nil ? nil : "prepareCompatibilityCheckpointWait"].compactMap { $0 })
            var expected: Set<String> = []
            switch operation {
            case .hello: break
            case .configure: expected = ["configuration"]; try configuration?.validate()
            case .ready: expected = ["ready"]; try ready?.validate()
            case .error: expected = ["code"]
            case .command:
                expected = ["sequence", "service_epoch", "worker_uuid", "command"]
                switch command {
                case .issueController: expected.insert("csr")
                case .authorizeSuccessor:
                    expected.formUnion(["csr", "signed"])
                    guard signed?.grant.operation == .takeover else { throw ValidationError.invalidFrame }
                case .authorizeRetirement:
                    expected.insert("signed")
                    guard signed?.grant.operation == .retire else { throw ValidationError.invalidFrame }
                case .fenceHandoff:
                    expected.formUnion(["handoff", "nonce"])
                    guard let handoff, nonce?.count == 32, handoff.request.serviceEpoch == serviceEpoch else { throw ValidationError.invalidFrame }
                    try handoff.validate()
                case .reconcileController:
                    expected.formUnion(["controller", "signed"])
                    guard controller != nil, signed != nil else { throw ValidationError.invalidFrame }
                case .replaceService:
                    expected.insert("replacement_request")
                    guard let replacementRequest,
                          let context = replacementRequest.configuration.reopen?.request.predecessor.context,
                          workerUUID == replacementRequest.predecessorWorkerUUID,
                          serviceEpoch == context.serviceEpoch else { throw ValidationError.invalidFrame }
                case .isolationState, .legacyConnection, .secondServiceExclusivity: expected.insert("isolationRequest")
                case .consumerObservationArm: expected.insert("consumerObservationArm")
                case .consumerObservationQuery, .consumerObservationFinalize: expected.insert("consumerObservationQuery")
                case .prepareCompatibilityArm: expected.insert("prepareCompatibilityArm")
                case .prepareCompatibilityObserve: expected.insert("prepareCompatibilityQuery")
                case .prepareCompatibilityRelease: expected.insert("prepareCompatibilityRelease")
                case .prepareCompatibilityWorkerExit: expected.insert("prepareCompatibilityWorkerExit")
                case .prepareCompatibilityCheckpointExit: expected.insert("prepareCompatibilityCheckpointExit")
                case .query, .serviceStatus, .replacementStatus, .notifications: break
                case nil: throw ValidationError.invalidFrame
                }
            case .reply:
                expected = ["sequence", "service_epoch", "worker_uuid"]
                let results = present.intersection(["handoff_result", "certificate", "ready", "ok", "code", "status", "replacement", "notifications", "isolationProof",
                    "consumerObservationStatus", "prepareCompatibilityStatus", "prepareCompatibilityWorkerWait",
                    "prepareCompatibilityCheckpointAck", "prepareCompatibilityCheckpointWait"])
                guard results.count == 1 else { throw ValidationError.invalidFrame }
                expected.formUnion(results); try ready?.validate(); try status?.validate(); try replacement?.validate()
            }
            guard present == expected else { throw ValidationError.invalidFrame }
            if let sequence { guard sequence > 0 else { throw ValidationError.invalidFrame } }
            if let serviceEpoch { guard StorageServiceTypes.validID(serviceEpoch) else { throw ValidationError.invalidFrame } }
            if let workerUUID { guard StorageServiceTypes.validID(workerUUID) else { throw ValidationError.invalidFrame } }
            if let handoffResult {
                try handoffResult.validate()
                guard handoffResult.ready.serviceEpoch == serviceEpoch,
                      handoffResult.ready.workerUUID == workerUUID else { throw ValidationError.invalidFrame }
            }
            try validateIsolation()
            try validateConsumerObservation()
            try validatePrepareCompatibility()
            try replacementRequest?.validate()
            try status?.validate()
            try replacement?.validate()
            if let notifications {
                guard notifications.count <= StorageLifecycleServiceBootProtocol.maximumNotifications else { throw ValidationError.invalidFrame }
                for notification in notifications { try validateNotification(notification) }
            }
            if let csr { try der(csr) }; if let certificate { try der(certificate) }
            try signed?.validate()
            if let controller {
                guard controller.epoch > 0 else { throw ValidationError.invalidFrame }
                _ = try L.Bootstrap.SPKISHA256(controller.key)
            }
            if let ok { guard ok else { throw ValidationError.invalidFrame } }
        }
        private func validateIsolation() throws {
            func request(_ request: IsolationRequest) throws {
                guard [request.requestID, request.operationUUID, request.challenge].allSatisfy(StorageServiceTypes.validID) else {
                    throw ValidationError.invalidFrame
                }
                _ = try L.Bootstrap.SPKISHA256(request.armDigest)
            }
            if let isolationRequest { try request(isolationRequest) }
            if let proof = isolationProof {
                try request(proof.request)
                guard [proof.workerUUID, proof.store, proof.serviceEpoch].allSatisfy(StorageServiceTypes.validID),
                      proof.workerUUID == workerUUID, proof.serviceEpoch == serviceEpoch,
                      proof.revision > 0 else { throw ValidationError.invalidFrame }
                _ = try L.Bootstrap.SPKISHA256(proof.registrySHA256)
                switch (proof.caseName, proof.result) {
                case ("isolation-state", "registry-state"),
                     ("legacy-connection", "legacy-tls-header-rejected"),
                     ("second-service-exclusivity", "second-owner-locked"): break
                default: throw ValidationError.invalidFrame
                }
            }
        }
        private func validateConsumerObservation() throws {
            typealias C = ConsumerObservationProtocol
            func scope(_ arm: C.Arm) throws {
                try C.validate(arm)
                guard arm.workerScope.serviceEpoch == serviceEpoch,
                      arm.workerScope.workerUUID == workerUUID else { throw ValidationError.invalidFrame }
            }
            if let arm = consumerObservationArm { try scope(arm) }
            if let query = consumerObservationQuery { try scope(query) }
            if let status = consumerObservationStatus {
                try C.validate(status)
                try scope(status.query)
            }
        }
        /// Validate the existing evidence schemas, then bind every available worker/
        /// epoch identity to this v2 envelope. Query-only carriers intentionally have
        /// no epoch: matching their retained arm/digest is the session owner's job.
        private func validatePrepareCompatibility() throws {
            typealias C = ManagedPrepareCompatibilityProtocol
            typealias P = ManagedPrepareWorkerCheckpointProtocol
            func worker(_ worker: String, epoch: String? = nil) throws {
                guard workerUUID == worker, epoch == nil || serviceEpoch == epoch else { throw ValidationError.invalidFrame }
            }
            if let arm = prepareCompatibilityArm {
                try C.validate(arm)
                try worker(arm.workerUUID, epoch: arm.arm.scope.serviceEpoch)
            }
            if let query = prepareCompatibilityQuery {
                try C.validate(query)
                try worker(query.workerUUID)
            }
            if let release = prepareCompatibilityRelease {
                try C.validate(release)
                try worker(release.query.workerUUID)
            }
            if let exit = prepareCompatibilityWorkerExit {
                try C.validateStorageWorkerExit(exit)
                try worker(exit.query.workerUUID)
            }
            if let exit = prepareCompatibilityCheckpointExit {
                try P.validate(exit)
                try worker(exit.workerUUID, epoch: exit.arm.scope.serviceEpoch)
            }
            if let status = prepareCompatibilityStatus {
                try C.validate(status)
                try worker(status.query.workerUUID, epoch: status.observation?.bound?.intent.epoch)
            }
            if let wait = prepareCompatibilityWorkerWait {
                try C.validate(wait)
                try worker(wait.query.workerUUID)
            }
            if let ack = prepareCompatibilityCheckpointAck {
                try P.validate(ack)
                try worker(ack.workerUUID, epoch: ack.arm.scope.serviceEpoch)
            }
            if let wait = prepareCompatibilityCheckpointWait {
                try P.validate(wait)
                try worker(wait.workerUUID, epoch: wait.arm.scope.serviceEpoch)
            }
        }
    }
    /// Mirrors Go validNotification: ids, pins and the role/prepare pairing.
    private static func validateNotification(_ n: Notification) throws {
        let b = n.binding
        guard [n.epoch, b.store, b.volume, b.attachment, b.launch].allSatisfy(StorageServiceTypes.validID) else {
            throw ValidationError.invalidFrame
        }
        _ = try L.Bootstrap.SPKISHA256(b.container); _ = try L.Bootstrap.SPKISHA256(b.key)
        switch b.role {
        case .prepare: guard let prepare = b.prepare, StorageServiceTypes.validID(prepare) else { throw ValidationError.invalidFrame }
        case .runtime: guard b.prepare == nil else { throw ValidationError.invalidFrame }
        }
    }
    private static func der(_ bytes: Data) throws {
        guard !bytes.isEmpty, bytes.count <= maximumDERSize else { throw ValidationError.invalidFrame }
    }
    /// Four-byte big-endian length followed by exact sorted-key JSON (UInt64 preserved).
    public static func encode(_ frame: Frame) throws -> Data {
        try frame.validate()
        let body = try L.encode(frame)
        var size = UInt32(body.count).bigEndian
        return Data(bytes: &size, count: 4) + body
    }
    /// Accepts the raw canonical body, not the length prefix.
    public static func decode(_ body: Data) throws -> Frame {
        let frame = try L.decode(Frame.self, from: body)
        try frame.validate()
        return frame
    }
}

#if os(macOS)
import CEngineCore
import Foundation

nonisolated protocol ManagedStorageControlling: Sendable {
    var context: ManagedStorageControlClient.Context { get }
    func send(_ request: ManagedStorageControlProtocol.ControlRequest) throws -> ManagedStorageControlClient.Reply
    func revoke()
    func invalidate() async
}

extension ManagedStorageControlling {
    // Authority-free test adapters need no transport generation. The lifecycle
    // still owns and joins every submitted call, including these adapters.
    func revoke() {}
    func invalidate() async {}
}

/// Value-only workload replies and fail-closed validation shared by lifecycle owners.
/// This namespace owns no transport, keys, or controller lifetime.
nonisolated enum ManagedStorageControlClient {
    enum Failure: Error, Equatable, Sendable {
        case invalidContext, invalidRequest, remote(String), protocolViolation, poisoned, revoked
    }

    /// The future private-VZ bootstrap owner must establish provenance before
    /// constructing this context. A well-shaped tuple alone is not authority.
    struct Context: Equatable, Sendable {
        let store: String
        let serviceEpoch: String
        let controllerEpoch: UInt64
        let controllerKey: String
        let provenanceReference: String
        /// Explicitly pinned by the lifecycle owner, never inferred from a reply.
        let lifecycleIdentity: StorageLifecycleProtocol.Identity?

        init(store: String, serviceEpoch: String, controllerEpoch: UInt64,
             controllerKey: String, provenanceReference: String,
             lifecycleIdentity: StorageLifecycleProtocol.Identity? = nil) throws {
            guard ManagedStorageControlClient.validID(store), ManagedStorageControlClient.validID(serviceEpoch),
                  controllerEpoch > 0, ManagedStorageControlClient.validKey(controllerKey),
                  ManagedStorageControlClient.validKey(provenanceReference) else {
                throw Failure.invalidContext
            }
            if let lifecycleIdentity {
                guard (try? lifecycleIdentity.validate()) != nil, lifecycleIdentity.store == store else {
                    throw Failure.invalidContext
                }
            }
            self.lifecycleIdentity = lifecycleIdentity
            self.store = store
            self.serviceEpoch = serviceEpoch
            self.controllerEpoch = controllerEpoch
            self.controllerKey = controllerKey
            self.provenanceReference = provenanceReference
        }
    }

    enum Reply: Sendable {
        case ok
        case receipt(ManagedStorageControlProtocol.Receipt)
        case volumeReceipt(VolumeReceipt)
        case snapshot(Snapshot)
    }

    struct RootIdentity: Codable, Hashable, Sendable {
        let device: UInt64
        let inode: UInt64
    }
    struct Store: Codable, Equatable, Sendable {
        let id: String
        let deviceID: String
        let root: RootIdentity
        let exports: RootIdentity
        enum CodingKeys: String, CodingKey { case id, deviceID = "device_id", root, exports }
    }
    struct Volume: Codable, Equatable, Sendable {
        let id: String
        let name: String
        let root: RootIdentity
    }
    struct Controller: Codable, Equatable, Sendable {
        let epoch: UInt64
        let key: String
    }
    enum VolumePhase: String, Codable, Sendable {
        case creating = "CREATING", ready = "READY", deleting = "DELETING", deleted = "DELETED"
    }
    enum AttachmentPhase: String, Codable, Sendable {
        case reserved = "RESERVED", active = "ACTIVE", retiring = "RETIRING", drained = "DRAINED"
    }
    enum PreparePhase: String, Codable, Sendable {
        case pending = "PENDING", completed = "COMPLETED", replaced = "REPLACED"
    }
    struct VolumeLifecycle: Codable, Equatable, Sendable {
        let phase: VolumePhase
        let create: String?
        let delete: String?
        let createdRevision: UInt64?
        let deletedRevision: UInt64?
        enum CodingKeys: String, CodingKey {
            case phase, create, delete, createdRevision = "created_revision", deletedRevision = "deleted_revision"
        }
    }
    struct VolumeReceipt: Codable, Equatable, Sendable {
        let schema: UInt64
        let operation: String
        let store: String
        let volume: Volume
        let phase: VolumePhase
        let revision: UInt64
    }
    struct Attachment: Codable, Equatable, Sendable {
        let binding: ManagedStorageControlProtocol.Binding
        let phase: AttachmentPhase
        let receipt: ManagedStorageControlProtocol.Receipt?
        let retirement: String?
    }
    struct Prepare: Codable, Equatable, Sendable {
        let id: String
        let attachments: [ManagedStorageControlProtocol.Binding]
        let phase: PreparePhase
        let successor: String?
        let attestation: ManagedStorageControlProtocol.Attestation?
        /// Schema 4 only: the Guest-persisted service epoch + controller that
        /// reserved this prepare (authenticated historical-context attestation).
        var context: PrepareContext? = nil
    }
    struct PrepareContext: Codable, Hashable, Sendable {
        let serviceEpoch: String
        let controllerEpoch: UInt64
        let controllerKey: String
        enum CodingKeys: String, CodingKey {
            case serviceEpoch = "service_epoch", controllerEpoch = "controller_epoch", controllerKey = "controller_key"
        }
    }
    struct Snapshot: Codable, Equatable, Sendable {
        let schema: UInt64
        let revision: UInt64
        let store: Store
        let epoch: String
        let controller: Controller
        let volumes: [String: Volume]
        let volumeLifecycles: [String: VolumeLifecycle]
        let attachments: [String: Attachment]
        let prepares: [String: Prepare]
        enum CodingKeys: String, CodingKey {
            case schema, revision, store, epoch, controller, volumes, attachments, prepares
            case volumeLifecycles = "volume_lifecycles"
        }
    }

    /// Internal vector seam. Transport correlation is checked by the actual child;
    /// this layer validates the complete closed schema and immutable authority tuple.
    static func decode(_ data: Data, for request: ManagedStorageControlProtocol.ControlRequest, context: Context) throws -> Reply {
        try validateRequest(request, context: context)
        do {
            let tree = try ControllerJSON.parse(data, limit: ManagedStorageControlProtocol.maximumReplyBytes)
            let fields = try object(tree)
            guard case .number(let id) = fields["id"], id > 0 else { throw Failure.protocolViolation }
            if let error = fields["error"] {
                try keys(fields, required: ["id", "error"])
                guard case .string(let code) = error,
                      ["INVALID", "UNAUTHORIZED", "CONFLICT", "UNKNOWN", "BLOCKED", "LIMIT", "BUSY", "CLOSED", "TIMEOUT", "REPAIR_REQUIRED", "INTERNAL"].contains(code) else {
                    throw Failure.protocolViolation
                }
                throw Failure.remote(code)
            }
            switch request {
            case .query:
                if let identity = context.lifecycleIdentity {
                    try keys(fields, required: ["id", "snapshot", "lifecycle_identity"])
                    let wireIdentity = try required(fields, "lifecycle_identity")
                    _ = try object(wireIdentity, required: ["store", "generation", "binding"])
                    guard try JSONDecoder().decode(StorageLifecycleProtocol.Identity.self, from: wireIdentity.bytes()) == identity else {
                        throw Failure.protocolViolation
                    }
                } else {
                    try keys(fields, required: ["id", "snapshot"])
                }
                let body = try required(fields, "snapshot")
                try snapshotShape(body)
                let snapshot = try JSONDecoder().decode(Snapshot.self, from: body.bytes())
                try validate(snapshot, context: context)
                return .snapshot(snapshot)
            case .retire(let request):
                try keys(fields, required: ["id", "receipt"])
                let body = try required(fields, "receipt")
                try receiptShape(body)
                let receipt = try JSONDecoder().decode(ManagedStorageControlProtocol.Receipt.self, from: body.bytes())
                try validate(receipt, store: context.store)
                guard receipt.volume == request.volume, receipt.attachment == request.attachment,
                      receipt.launch == request.launch else { throw Failure.protocolViolation }
                return .receipt(receipt)
            case .createVolume, .deleteVolume:
                try keys(fields, required: ["id", "volume_receipt"])
                let body = try required(fields, "volume_receipt")
                let fields = try object(body, required: ["schema", "operation", "store", "volume", "phase", "revision"])
                try volumeShape(required(fields, "volume"))
                let receipt = try JSONDecoder().decode(VolumeReceipt.self, from: body.bytes())
                guard receipt.schema == 3, receipt.revision > 0, receipt.store == context.store,
                      validID(receipt.operation), validVolume(receipt.volume) else { throw Failure.protocolViolation }
                switch request {
                case .createVolume(let request):
                    guard receipt.operation == request.operation, receipt.volume.id == request.volume,
                          receipt.volume.name == request.name, receipt.phase == .ready else { throw Failure.protocolViolation }
                case .deleteVolume(let request):
                    guard receipt.operation == request.operation, receipt.volume.id == request.volume,
                          receipt.phase == .deleted else { throw Failure.protocolViolation }
                default: throw Failure.protocolViolation
                }
                return .volumeReceipt(receipt)
            default:
                try keys(fields, required: ["id", "ok"])
                _ = try object(required(fields, "ok"), required: [])
                return .ok
            }
        } catch Failure.remote(let code) {
            throw Failure.remote(code)
        } catch {
            throw Failure.protocolViolation
        }
    }

    private static func validateRequest(_ request: ManagedStorageControlProtocol.ControlRequest, context: Context) throws {
        let stores: [String]
        switch request {
        case .query: stores = []
        case .reservePrepare(let request): stores = request.attachments.map(\.store)
        case .registerAttachment(let request): stores = [request.binding.store]
        case .retire(let request): stores = [request.store]
        case .createVolume(let request): stores = [request.store]
        case .deleteVolume(let request): stores = [request.store]
        case .completePrepare(let request): stores = request.receipts.map(\.store)
        case .replacePrepare(let request): stores = request.receipts.map(\.store) + request.successor.attachments.map(\.store)
        }
        guard stores.allSatisfy({ $0 == context.store }) else { throw Failure.invalidRequest }
    }

    private static func validID(_ value: String) -> Bool {
        (try? StorageIdentity.RequestID(value)) != nil
    }
    private static func validKey(_ value: String) -> Bool {
        (try? StorageIdentity.SPKISHA256(value)) != nil
    }
    private static func validVolume(_ volume: Volume, creating: Bool = false) -> Bool {
        validID(volume.id) && !volume.name.isEmpty && volume.name.utf8.count <= 255 &&
            volume.name != "." && volume.name != ".." && !volume.name.contains("/") && !volume.name.contains("\0") &&
            (creating ? volume.root == RootIdentity(device: 0, inode: 0) : volume.root.inode > 0)
    }
    private static func validate(_ receipt: ManagedStorageControlProtocol.Receipt, store: String) throws {
        guard receipt.schema == 3, receipt.revision > 0, receipt.store == store,
              validID(receipt.volume), validID(receipt.attachment), validID(receipt.launch),
              receipt.prepare.map(validID) ?? true else {
            throw Failure.protocolViolation
        }
    }
    private static func validate(_ binding: ManagedStorageControlProtocol.Binding, store: String) throws {
        guard binding.store == store, validID(binding.volume), validID(binding.attachment), validID(binding.launch),
              validKey(binding.container), validKey(binding.key),
              (binding.role == .prepare ? binding.prepare.map(validID) == true : binding.prepare == nil) else {
            throw Failure.protocolViolation
        }
    }

    /// Visible registry invariants from storageauthority/validate.go and
    /// volume_lifecycle_unix.go. Hidden bootstrap/grant/key history stays in Go.
    static func validate(_ snapshot: Snapshot, context: Context) throws {
        let s = snapshot
        guard s.schema == (context.lifecycleIdentity == nil ? 3 : 4), s.revision > 0, s.store.id == context.store, s.epoch == context.serviceEpoch,
              s.controller.epoch == context.controllerEpoch, s.controller.key == context.controllerKey,
              !s.store.deviceID.isEmpty, s.store.deviceID.utf8.count <= 256,
              s.store.root.inode > 0, s.store.exports.inode > 0, s.store.exports.device == s.store.root.device,
              Set(s.volumes.keys) == Set(s.volumeLifecycles.keys) else { throw Failure.protocolViolation }
        var names = Set<String>(), roots = Set<RootIdentity>()
        for (id, volume) in s.volumes {
            guard let life = s.volumeLifecycles[id], id == volume.id,
                  validVolume(volume, creating: life.phase == .creating) else { throw Failure.protocolViolation }
            let created = life.createdRevision ?? 0, deleted = life.deletedRevision ?? 0
            guard created <= s.revision, deleted <= s.revision,
                  life.createdRevision != 0, life.deletedRevision != 0 else { throw Failure.protocolViolation }
            if let operation = life.create {
                guard validID(operation) else { throw Failure.protocolViolation }
            } else if created != 0 { throw Failure.protocolViolation }
            if life.phase == .creating {
                guard life.create != nil, created == 0 else { throw Failure.protocolViolation }
            } else {
                guard volume.root.device == s.store.root.device, life.create == nil || created > 0 else { throw Failure.protocolViolation }
            }
            if life.phase == .deleting || life.phase == .deleted {
                guard let operation = life.delete, validID(operation),
                      (life.phase == .deleted) == (deleted > 0), deleted == 0 || deleted > created else { throw Failure.protocolViolation }
            } else if life.delete != nil || deleted != 0 { throw Failure.protocolViolation }
            if life.phase != .deleted {
                guard names.insert(volume.name).inserted,
                      life.phase == .creating || roots.insert(volume.root).inserted else { throw Failure.protocolViolation }
            }
        }
        var keys = Set([context.controllerKey])
        for (id, attachment) in s.attachments {
            let b = attachment.binding
            try validate(b, store: context.store)
            guard id == b.attachment, s.volumes[b.volume] != nil, keys.insert(b.key).inserted,
                  s.volumeLifecycles[b.volume]?.phase == .ready || attachment.phase == .drained else { throw Failure.protocolViolation }
            if let retirement = attachment.retirement {
                guard validID(retirement), attachment.phase == .retiring || attachment.phase == .drained else { throw Failure.protocolViolation }
            } else if attachment.phase == .drained { throw Failure.protocolViolation }
            if attachment.phase == .drained {
                guard let receipt = attachment.receipt else { throw Failure.protocolViolation }
                try validate(receipt, store: context.store)
                guard receipt.volume == b.volume, receipt.attachment == id, receipt.prepare == b.prepare,
                      receipt.launch == b.launch, receipt.revision <= s.revision else { throw Failure.protocolViolation }
            } else if attachment.receipt != nil { throw Failure.protocolViolation }
            if b.role == .prepare {
                guard let prepare = b.prepare, s.prepares[prepare]?.attachments.contains(b) == true else { throw Failure.protocolViolation }
            } else if attachment.phase == .reserved { throw Failure.protocolViolation }
        }
        var pending = Set<String>()
        for (id, prepare) in s.prepares {
            if let c = prepare.context {
                guard s.schema == 4, validID(c.serviceEpoch), validKey(c.controllerKey),
                      c.controllerEpoch > 0, c.controllerEpoch <= s.controller.epoch,
                      c.controllerEpoch < s.controller.epoch || c.controllerKey == s.controller.key else { throw Failure.protocolViolation }
            } else if s.schema == 4 { throw Failure.protocolViolation }
            guard validID(id), id == prepare.id, !prepare.attachments.isEmpty,
                  prepare.attachments.map(\.volume) == prepare.attachments.map(\.volume).sorted() else { throw Failure.protocolViolation }
            var volumes = Set<String>()
            for binding in prepare.attachments {
                guard let attachment = s.attachments[binding.attachment], binding.role == .prepare,
                      binding.prepare == id, attachment.binding == binding, volumes.insert(binding.volume).inserted else { throw Failure.protocolViolation }
                if prepare.phase == .pending {
                    guard s.volumeLifecycles[binding.volume]?.phase == .ready, pending.insert(binding.volume).inserted else { throw Failure.protocolViolation }
                } else if attachment.phase != .drained { throw Failure.protocolViolation }
            }
            switch prepare.phase {
            case .pending:
                guard prepare.successor == nil, prepare.attestation == nil else { throw Failure.protocolViolation }
            case .completed:
                guard prepare.successor == nil, let attestation = prepare.attestation,
                      attestation.prepare == id, attestation.succeeded, attestation.cleanCopyUp else { throw Failure.protocolViolation }
            case .replaced:
                guard let successorID = prepare.successor, successorID != id,
                      let successor = s.prepares[successorID], prepare.attestation == nil,
                      successor.attachments.map(\.volume) == prepare.attachments.map(\.volume) else { throw Failure.protocolViolation }
            }
        }
    }

    // JSONDecoder ignores unknown members. Validate every object in the canonical
    // tree first, including omitted-vs-null optional fields and dictionary entries.
    private static func object(_ tree: ControllerJSON, required: Set<String>? = nil, optional: Set<String> = []) throws -> [String: ControllerJSON] {
        guard case .object(let fields) = tree else { throw Failure.protocolViolation }
        if let required { try keys(fields, required: required, optional: optional) }
        return fields
    }
    private static func keys(_ fields: [String: ControllerJSON], required: Set<String>, optional: Set<String> = []) throws {
        let actual = Set(fields.keys)
        guard required.isSubset(of: actual), actual.isSubset(of: required.union(optional)),
              !fields.values.contains(.null) else { throw Failure.protocolViolation }
    }
    private static func required(_ fields: [String: ControllerJSON], _ key: String) throws -> ControllerJSON {
        guard let value = fields[key] else { throw Failure.protocolViolation }; return value
    }
    private static func rootShape(_ tree: ControllerJSON) throws {
        _ = try object(tree, required: ["device", "inode"])
    }
    private static func volumeShape(_ tree: ControllerJSON) throws {
        let fields = try object(tree, required: ["id", "name", "root"])
        try rootShape(required(fields, "root"))
    }
    private static func bindingShape(_ tree: ControllerJSON) throws {
        _ = try object(tree, required: ["store", "volume", "attachment", "container", "launch", "key", "role", "mode"], optional: ["prepare"])
    }
    private static func receiptShape(_ tree: ControllerJSON) throws {
        _ = try object(tree, required: ["schema", "store", "volume", "attachment", "launch", "revision"], optional: ["prepare"])
    }
    private static func snapshotShape(_ tree: ControllerJSON) throws {
        let fields = try object(tree, required: ["schema", "revision", "store", "epoch", "controller", "volumes", "volume_lifecycles", "attachments", "prepares"])
        let store = try object(required(fields, "store"), required: ["id", "device_id", "root", "exports"])
        try rootShape(required(store, "root")); try rootShape(required(store, "exports"))
        _ = try object(required(fields, "controller"), required: ["epoch", "key"])
        for (_, value) in try object(required(fields, "volumes")) { try volumeShape(value) }
        for (_, value) in try object(required(fields, "volume_lifecycles")) {
            _ = try object(value, required: ["phase"], optional: ["create", "delete", "created_revision", "deleted_revision"])
        }
        for (_, value) in try object(required(fields, "attachments")) {
            let attachment = try object(value, required: ["binding", "phase"], optional: ["receipt", "retirement"])
            try bindingShape(required(attachment, "binding"))
            if let receipt = attachment["receipt"] { try receiptShape(receipt) }
        }
        for (_, value) in try object(required(fields, "prepares")) {
            let prepare = try object(value, required: ["id", "attachments", "phase"], optional: ["successor", "attestation", "context"])
            if let context = prepare["context"] {
                _ = try object(context, required: ["service_epoch", "controller_epoch", "controller_key"])
            }
            guard case .array(let bindings) = prepare["attachments"] else { throw Failure.protocolViolation }
            for binding in bindings { try bindingShape(binding) }
            if let attestation = prepare["attestation"] {
                _ = try object(attestation, required: ["prepare", "succeeded", "clean_copy_up"])
            }
        }
    }
}
#endif

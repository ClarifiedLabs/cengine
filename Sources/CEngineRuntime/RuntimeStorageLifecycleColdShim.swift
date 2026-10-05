#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Synchronization
@preconcurrency import XPC

/// Value-only replay model. Owning disk capability retains this across wrappers;
/// only the native ROOT responder may supply an authenticated claim.
struct StorageLifecycleColdClaimState: Sendable {
    typealias Wire = StorageLifecycleColdShimProtocol
    private(set) var first: Wire.Challenge?
    private var latest: Wire.Challenge?
    static let maximumChallenges = 4_096
    private var nonces = Set<Data>()
    mutating func accept(_ challenge: Wire.Challenge, now: UInt64) throws {
        try challenge.validate()
        guard challenge.isFresh(at: now) else { throw StorageLifecycleColdShim.Failure.unauthorized }
        if let first {
            guard first.greeting == challenge.greeting, first.prepareSHA256 == challenge.prepareSHA256,
                  first.unsignedGrant == challenge.unsignedGrant, first.signedOpenSHA256 == challenge.signedOpenSHA256,
                  first.baseEpoch == challenge.baseEpoch, first.shimAudit == challenge.shimAudit,
                  first.daemonAudit == challenge.daemonAudit, first.shimUniqueID == challenge.shimUniqueID,
                  first.daemonUniqueID == challenge.daemonUniqueID else { throw StorageLifecycleColdShim.Failure.unauthorized }
        }
        if latest == challenge { return } // Exact latest retry, still unexpired.
        guard (nonces.count < Self.maximumChallenges),
              challenge.counter > (latest?.counter ?? 0), !nonces.contains(challenge.nonce) else {
            throw StorageLifecycleColdShim.Failure.unauthorized
        }
        if first == nil { first = challenge }
        latest = challenge; nonces.insert(challenge.nonce)
    }
    func validate(_ seed: Wire.ColdEnrollmentSeed) throws {
        try seed.validate()
        guard let first, seed.purpose == first.greeting.purpose, seed.operationID == first.unsignedGrant.id,
              seed.signedOpenSHA256 == first.signedOpenSHA256, seed.baseEpoch == first.baseEpoch,
              try seed.successorOrigin == first.greeting.successorOrigin else { throw StorageLifecycleColdShim.Failure.unauthorized }
    }
}

/// Native mounted responder. Construction requires actual mount-only
/// 4105 completion and an independently authenticated signed parent socket.
final class StorageLifecycleColdShim: @unchecked Sendable {
    typealias Wire = StorageLifecycleColdShimProtocol
    typealias Processes = StorageLifecycleFreshShim.Processes
    typealias RootPeer = StorageLifecycleFreshShim.RootPeer
    enum Failure: Error { case unauthorized, unavailable, invalidMessage }
    private final class Gate: @unchecked Sendable {
        let lock = NSLock()
        let ready = DispatchSemaphore(value: 0)
        var closed = false
        var started = false
        var acknowledged = false
        var connection: xpc_connection_t?
        func close() {
            let peer: xpc_connection_t? = lock.withLock {
                closed = true
                let peer = connection; connection = nil
                return peer
            }
            if let peer { xpc_connection_cancel(peer) }
            ready.signal()
        }
        func whileOpen(_ body: () throws -> Void) throws {
            try lock.withLock {
                guard !closed else { throw Failure.unavailable }
                try body()
            }
        }
        func acknowledge() throws {
            try whileOpen { acknowledged = true }
            ready.signal()
        }
    }
    private let capability: RawDiskBootTransaction.VerifiedStorageDiskBoot
    private let parent: FileHandle
    private let processes: Processes
    private let team: String
    private let policy: StorageLifecycleNativePolicy
    let greeting: Wire.Greeting
    private let gate = Gate()
    private let worker = DispatchQueue(label: "dev.cengine.storage-cold-shim.worker")
    private let events = DispatchQueue(label: "dev.cengine.storage-cold-shim.events")
    private var rootPeer: RootPeer? // Worker only; first native sender pins the channel.

    private static let constructed = Mutex(false)
    private let enrollment = Mutex<LocalEnrollmentSeed?>(nil)

    init(capability: RawDiskBootTransaction.VerifiedStorageDiskBoot,
         binding: StorageIdentity.StoreBinding,
         pinnedRoot: StorageIdentity.RootPublicKey,
         parentBorrowedFD: Int32, policy: StorageLifecycleNativePolicy = .production,
         purpose: Wire.Purpose = .cold) throws {
        guard !Thread.isMainThread else { throw Failure.unavailable }
        let descriptor = fcntl(parentBorrowedFD, F_DUPFD_CLOEXEC, 0)
        guard descriptor >= 0 else { throw Failure.unauthorized }
        let parent = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        let (observed, team) = try Self.authenticatedParent(parentFD: descriptor, policy: policy)
        self.capability = capability; self.parent = parent; processes = observed
        self.team = team; self.policy = policy
        let held = try capability.validateRecoveryDisk(purpose: purpose), dto = StorageLifecycleStoreBinding(binding)
        guard let volume = held.volumeUUID,
              held.inode == dto.backing.inode,
              volume.uuidString.lowercased() == dto.backing.volumeUUID else { throw Failure.unauthorized }
        let observation = try StorageIdentity.DescriptorIdentity(
            volumeUUID: .init(volume.uuidString.lowercased()), device: held.device, inode: held.inode)
        greeting = try .init(channelID: UUID().uuidString.lowercased(), daemonUniqueID: observed.daemonUniqueID,
            rootPublicKey: pinnedRoot.publicData, binding: dto, bootBinding: capability.binding,
            launch: .init(shimLaunchUUID: capability.binding.shimLaunchUUID, specSHA256: capability.specificationSHA256,
                initramfsSHA256: capability.initramfsSHA256, ext4UUID: capability.binding.ext4UUID, bytes: capability.binding.bytes),
            heldBackingIdentity: .init(observation), purpose: purpose)
        try Self.constructed.withLock { claimed in
            guard !claimed else { throw Failure.unavailable }
            claimed = true
        }
    }

    static func authenticatedParent(parentFD: Int32, policy: StorageLifecycleNativePolicy = .production) throws -> (Processes, String) {
        try StorageLifecycleFreshShim.authenticatedParent(parentFD: parentFD, policy: policy)
    }
    static func authenticateRoot(_ message: xpc_object_t, team: String,
                                 policy: StorageLifecycleNativePolicy = .production) throws -> RootPeer {
        try StorageLifecycleFreshShim.authenticateRoot(message, team: team, policy: policy)
    }
    static func observe(parentFD: Int32) throws -> Processes { try StorageLifecycleFreshShim.observe(parentFD: parentFD) }

    /// One channel only. A close, failed acknowledgement or timeout is terminal;
    /// re-instantiating cannot reset the underlying boot's first-claim freeze.
    func start() throws {
        guard !Thread.isMainThread else { throw Failure.unavailable }
        let gate = self.gate
        let connection = xpc_connection_create_mach_service(policy.serviceName,
            events, UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED))
        do {
            try gate.whileOpen {
                guard !gate.started else { throw Failure.unavailable }
                gate.started = true; gate.connection = connection
            }
        } catch { xpc_connection_cancel(connection); throw error }
        xpc_connection_set_event_handler(connection) { [weak self] message in
            guard xpc_get_type(message) == XPC_TYPE_DICTIONARY, let self else { gate.close(); return }
            let settled = Mutex(false)
            self.events.asyncAfter(deadline: .now() + 5) {
                if !settled.withLock({ $0 }) { gate.close() }
            }
            self.worker.async {
                defer { settled.withLock { $0 = true } }
                do { try self.respond(message, connection: connection) }
                catch { gate.close() }
            }
        }
        xpc_connection_resume(connection)
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_int64(message, "version", PrivilegedPortProtocol.version)
        xpc_dictionary_set_string(message, "role", "storage-shim")
        xpc_dictionary_set_string(message, "operation", greeting.purpose == .cold
            ? "storage-lifecycle-cold-shim" : "storage-lifecycle-resume-shim")
        do {
            let bytes = try StorageLifecycleProtocol.encode(greeting)
            bytes.withUnsafeBytes { xpc_dictionary_set_data(message, "request", $0.baseAddress, $0.count) }
            try gate.whileOpen {
                xpc_connection_send_message_with_reply(connection, message, events) { [weak self] reply in
                    guard let self else { gate.close(); return }
                    self.worker.async {
                        do {
                            try self.authenticate(reply)
                            guard xpc_dictionary_get_bool(reply, "ok") else { throw Failure.invalidMessage }
                            try gate.acknowledge()
                        } catch { gate.close() }
                    }
                }
            }
            guard gate.ready.wait(timeout: .now() + 5) == .success,
                  gate.lock.withLock({ gate.acknowledged && !gate.closed }) else { throw Failure.unavailable }
        } catch { close(); throw error }
    }
    func close() { gate.close() }
    deinit { gate.close() }

    private func authenticate(_ message: xpc_object_t) throws {
        try gate.whileOpen {}
        let peer = try Self.authenticateRoot(message, team: team, policy: policy)
        if let rootPeer { guard rootPeer == peer else { throw Failure.unauthorized } }
        else { rootPeer = peer }
        guard try Self.observe(parentFD: parent.fileDescriptor) == processes else { throw Failure.unauthorized }
        try gate.whileOpen {}
    }
    private func respond(_ message: xpc_object_t, connection: xpc_connection_t) throws {
        // MUST precede decoding or invoking the unsigned capability component.
        try authenticate(message)
        guard let operation = xpc_dictionary_get_string(message, "operation") else { throw Failure.invalidMessage }
        var count = 0
        guard let bytes = xpc_dictionary_get_data(message, "request", &count), count > 0,
              count <= StorageLifecycleProtocol.maximumPayloadBytes else { throw Failure.invalidMessage }
        let payload = Data(bytes: bytes, count: count)
        let encoded: Data
        var proofChallenge: Wire.Challenge?
        var backing: FileHandle?
        switch String(cString: operation) {
        case "storage-lifecycle-cold-challenge", "storage-lifecycle-resume-challenge":
            guard String(cString: operation) == (greeting.purpose == .cold
                ? "storage-lifecycle-cold-challenge" : "storage-lifecycle-resume-challenge") else { throw Failure.unauthorized }
            let challenge = try Wire.decodeChallenge(payload)
            guard challenge.greeting == greeting, challenge.shimAudit == processes.shimAudit,
                  challenge.daemonAudit == processes.daemonAudit, challenge.shimUniqueID == processes.shimUniqueID,
                  challenge.daemonUniqueID == processes.daemonUniqueID else {
                throw Failure.unauthorized
            }
            proofChallenge = challenge
            encoded = try Wire.encode(capability.coldReply(to: challenge))
            backing = try capability.duplicateHeldDisk()
            guard challenge.isFresh(at: UInt64(Date().timeIntervalSince1970 * 1000)) else { throw Failure.invalidMessage }
        case "storage-lifecycle-cold-enrollment", "storage-lifecycle-resume-enrollment":
            guard String(cString: operation) == (greeting.purpose == .cold
                ? "storage-lifecycle-cold-enrollment" : "storage-lifecycle-resume-enrollment") else { throw Failure.unauthorized }
            let seed = try Wire.decodeEnrollmentSeed(payload)
            try capability.validateColdSeed(seed)
            try authenticate(message)
            try enrollment.withLock { stored in
                if let stored { guard stored.value == seed else { throw Failure.unauthorized } }
                else { stored = LocalEnrollmentSeed(value: seed, disk: capability) }
            }
            encoded = try Wire.encode(Wire.ColdEnrollmentAcknowledgement(for: seed))
        default: throw Failure.invalidMessage
        }
        try authenticate(message)
        if let proofChallenge {
            guard proofChallenge.isFresh(at: UInt64(Date().timeIntervalSince1970 * 1000)) else { throw Failure.invalidMessage }
        }
        guard let reply = xpc_dictionary_create_reply(message) else { throw Failure.invalidMessage }
        xpc_dictionary_set_bool(reply, "ok", true)
        encoded.withUnsafeBytes { xpc_dictionary_set_data(reply, "reply", $0.baseAddress, $0.count) }
        // XPC owns the transferred duplicate. No borrowed descriptor number goes on wire.
        if let backing { xpc_dictionary_set_fd(reply, "backing-fd", backing.fileDescriptor) }
        try gate.whileOpen { xpc_connection_send_message(connection, reply) }
    }

    func localEnrollmentSeed() throws -> LocalEnrollmentSeed {
        try gate.whileOpen {}
        guard let seed = enrollment.withLock({ $0 }) else { throw Failure.unavailable }
        try capability.validateColdSeed(seed.value)
        return seed
    }

    /// Not Codable; no initializer accepts decoded metadata outside this file.
    final class LocalEnrollmentSeed: Sendable {
        let value: Wire.ColdEnrollmentSeed
        private let disk: RawDiskBootTransaction.VerifiedStorageDiskBoot
        fileprivate init(value: Wire.ColdEnrollmentSeed, disk: RawDiskBootTransaction.VerifiedStorageDiskBoot) {
            self.value = value; self.disk = disk
        }
        func join(_ boot: PrivateStorageLifecycleBootCoordinator.VerifiedBoot) throws -> ColdVerifiedBoot {
            try disk.validateColdSeed(value)
            try disk.validateColdConfiguration(boot.configuration)
            guard boot.binding == disk.binding, boot.initramfsSHA256 == disk.initramfsSHA256,
                  boot.rootPublicKey.publicData == value.successorOrigin.rootPublicKey,
                  try boot.validateHeldDisk() == disk.validateRecoveryDisk(purpose: value.purpose) else { throw Failure.unauthorized }
            switch value.purpose {
            case .cold:
                guard let signed = boot.configuration.cold else { throw Failure.unauthorized }
                let prepared = try StorageLifecycleColdRootProtocol.Prepared(signedOpen: signed,
                    successorOrigin: value.successorOrigin, baseEpoch: value.baseEpoch)
                try value.validate(prepared: prepared)
            case .resumeReadOnly:
                guard let signed = boot.configuration.resume else { throw Failure.unauthorized }
                let prepared = try StorageLifecycleResumeRootProtocol.Prepared(signedOpen: signed,
                    successorOrigin: value.successorOrigin, baseEpoch: value.baseEpoch)
                try value.validate(prepared: prepared)
            }
            return ColdVerifiedBoot(boot: boot, seed: self)
        }
    }
    final class ColdVerifiedBoot: Sendable {
        let boot: PrivateStorageLifecycleBootCoordinator.VerifiedBoot
        let seed: LocalEnrollmentSeed
        fileprivate init(boot: PrivateStorageLifecycleBootCoordinator.VerifiedBoot, seed: LocalEnrollmentSeed) {
            self.boot = boot; self.seed = seed
        }
        func validate() throws { _ = try seed.join(boot) }
    }
}
#endif

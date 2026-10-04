#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Security
import Synchronization
@preconcurrency import XPC

/// Answers the root helper's service-proof challenges from the storage shim.
/// Only the private coordinator's live capability supplies boot trust; neither a
/// daemon-provided Ready nor a signed DTO can stand in for that capability.
final class StorageLifecycleServiceShim: @unchecked Sendable {
    typealias Wire = StorageLifecycleServiceProofProtocol
    typealias L = StorageLifecycleProtocol
    enum Failure: Error { case unauthorized, unavailable, invalidMessage }

    /// Revocation is independent of the worker. Never hold this lock across
    /// Security, filesystem I/O, XPC calls, or waits.
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
        func whileOpen(_ body: () throws -> Void = {}) throws {
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

    /// Current boot capability and greeting. Replaced together by updateBoot; the
    /// prior boot trust is revoked immediately (no historical endpoints).
    private struct Current { let boot: PrivateStorageLifecycleBootCoordinator.VerifiedBoot; let greeting: Wire.Greeting }
    private let current: Mutex<Current>
    private var boot: PrivateStorageLifecycleBootCoordinator.VerifiedBoot { current.withLock { $0.boot } }
    var greeting: Wire.Greeting { current.withLock { $0.greeting } }
    private let binding: StorageIdentity.StoreBinding
    private let parent: FileHandle
    private let processes: StorageLifecycleFreshShim.Processes
    private let team: String
    private let policy: StorageLifecycleNativePolicy
    private let gate = Gate()
    private let worker = DispatchQueue(label: "dev.cengine.storage-service-shim.worker")
    private let events = DispatchQueue(label: "dev.cengine.storage-service-shim.events")
    // Worker-only state: one native ROOT, one greeting, one strictly increasing counter.
    private var rootPeer: StorageLifecycleFreshShim.RootPeer?
    private var counter: UInt64 = 0
    private var nonce: Data?

    init(boot: PrivateStorageLifecycleBootCoordinator.VerifiedBoot,
         binding: StorageIdentity.StoreBinding, parentBorrowedFD: Int32,
         policy: StorageLifecycleNativePolicy = .production) throws {
        guard !Thread.isMainThread else { throw Failure.unavailable }
        let identity = try policy.currentIdentity(role: .engine)
        let descriptor = fcntl(parentBorrowedFD, F_DUPFD_CLOEXEC, 0)
        guard descriptor >= 0 else { throw Failure.unauthorized }
        let parent = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        let observed = try StorageLifecycleFreshShim.observe(parentFD: descriptor)
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: observed.daemonAudit] as CFDictionary,
            [], &code) == errSecSuccess, let code else { throw Failure.unauthorized }
        try policy.validatePeer(code, pid: getppid(), role: .engine, expectedTeam: identity.teamIdentifier)
        try Self.validateBacking(boot: boot, binding: binding)
        let trust = try boot.trust(for: boot.configuration.signed.grant)
        let greeting = try Wire.Greeting(channelID: UUID().uuidString.lowercased(),
            daemonUniqueID: observed.daemonUniqueID, rootPublicKey: boot.rootPublicKey.publicData,
            binding: .init(binding), bootBinding: boot.binding, initramfsSHA256: boot.initramfsSHA256, boot: trust)
        guard try StorageLifecycleFreshShim.observe(parentFD: descriptor) == observed else { throw Failure.unauthorized }
        current = Mutex(Current(boot: boot, greeting: greeting)); self.binding = binding; self.parent = parent
        processes = observed; team = identity.teamIdentifier; self.policy = policy
    }

    private static func validateBacking(boot: PrivateStorageLifecycleBootCoordinator.VerifiedBoot,
                                        binding: StorageIdentity.StoreBinding) throws {
        let held = try boot.validateHeldDisk()
        // The verified boot pins the exact current-mount descriptor independently.
        guard held.inode == binding.backing.identity.inode,
              held.volumeUUID?.uuidString.lowercased() == binding.backing.identity.volumeUUID.rawValue,
              boot.binding.bytes == binding.backing.size,
              boot.binding.ext4UUID == binding.expectedExt4UUID.rawValue,
              try L.Identity(binding: binding, generation: boot.identity.generation) == boot.identity else {
            throw Failure.unauthorized
        }
    }

    /// One channel only. Cancellation and five-second monotonic deadlines remain
    /// effective even when native authentication or disk checks block the worker.
    func start() throws {
        guard !Thread.isMainThread else { throw Failure.unavailable }
        let connection = xpc_connection_create_mach_service(policy.serviceName,
            events, UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED))
        do {
            try gate.whileOpen {
                guard !gate.started else { throw Failure.unavailable }
                gate.started = true; gate.connection = connection
            }
        } catch { xpc_connection_cancel(connection); throw error }
        let gate = self.gate
        xpc_connection_set_event_handler(connection) { [weak self] message in
            guard xpc_get_type(message) == XPC_TYPE_DICTIONARY, let self else { gate.close(); return }
            let settled = Mutex(false)
            let deadline = DispatchTime.now() + 5
            self.events.asyncAfter(deadline: deadline) {
                if !settled.withLock({ $0 }) { gate.close() }
            }
            self.worker.async {
                defer { settled.withLock { $0 = true } }
                do { try self.respond(message, connection: connection, deadline: deadline) }
                catch { gate.close() }
            }
        }
        xpc_connection_resume(connection)
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_int64(message, "version", PrivilegedPortProtocol.version)
        xpc_dictionary_set_string(message, "role", "storage-shim")
        xpc_dictionary_set_string(message, "operation", "storage-lifecycle-service-shim")
        do {
            let bytes = try L.encode(greeting)
            bytes.withUnsafeBytes { xpc_dictionary_set_data(message, "request", $0.baseAddress, $0.count) }
            try gate.whileOpen()
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
            guard gate.ready.wait(timeout: .now() + 5) == .success,
                  gate.lock.withLock({ gate.acknowledged && !gate.closed }) else { throw Failure.unavailable }
        } catch { close(); throw error }
    }
    func close() { gate.close() }
    deinit { gate.close() }

    /// Same-C worker replacement: re-greet ROOT on the SAME enrolled channel with
    /// the successor boot trust. Channel ID, daemon, ROOT key, store binding, boot
    /// binding and initramfs pin stay fixed; only service epoch/TLS root/server SPKI
    /// change. Counter/nonce high-water marks are kept. Any failure closes the channel.
    func updateBoot(_ verified: PrivateStorageLifecycleBootCoordinator.VerifiedBoot) throws {
        guard !Thread.isMainThread else { throw Failure.unavailable }
        do {
            try gate.whileOpen { guard gate.started, gate.acknowledged else { throw Failure.unavailable } }
            try Self.validateBacking(boot: verified, binding: binding)
            let trust = try verified.trust(for: verified.configuration.signed.grant)
            let next: Wire.Greeting = try worker.sync {
                try authenticateProcesses()
                let old = greeting
                let candidate = try Wire.Greeting(channelID: old.channelID, daemonUniqueID: old.daemonUniqueID,
                    rootPublicKey: verified.rootPublicKey.publicData, binding: old.binding,
                    bootBinding: verified.binding, initramfsSHA256: verified.initramfsSHA256, boot: trust)
                guard try Self.isSuccessor(candidate, of: old) else { throw Failure.unauthorized }
                // Revoke the old boot trust before ROOT can challenge the new one.
                current.withLock { $0 = Current(boot: verified, greeting: candidate) }
                return candidate
            }
            try send(next)
        } catch { close(); throw error }
    }

    /// Exact duplicate, or same channel/daemon/ROOT/store/boot binding/initramfs
    /// with a genuinely new service epoch, TLS root and server SPKI.
    static func isSuccessor(_ next: Wire.Greeting, of old: Wire.Greeting) throws -> Bool {
        try next.validate()
        if next == old { return true }
        return next.channelID == old.channelID && next.daemonUniqueID == old.daemonUniqueID &&
            next.rootPublicKey == old.rootPublicKey && next.binding == old.binding &&
            next.bootBinding == old.bootBinding && next.initramfsSHA256 == old.initramfsSHA256 &&
            next.boot.identity == old.boot.identity && next.boot.bootstrapKey == old.boot.bootstrapKey &&
            next.boot.serviceEpoch != old.boot.serviceEpoch && next.boot.tlsRootSHA256 != old.boot.tlsRootSHA256 &&
            next.boot.serverSPKI != old.boot.serverSPKI
    }

    private func authenticateProcesses() throws {
        guard try StorageLifecycleFreshShim.observe(parentFD: parent.fileDescriptor) == processes else { throw Failure.unauthorized }
    }

    private func send(_ greeting: Wire.Greeting) throws {
        let connection: xpc_connection_t = try gate.lock.withLock {
            guard !gate.closed, let connection = gate.connection else { throw Failure.unavailable }
            return connection
        }
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_int64(message, "version", PrivilegedPortProtocol.version)
        xpc_dictionary_set_string(message, "role", "storage-shim")
        xpc_dictionary_set_string(message, "operation", "storage-lifecycle-service-shim")
        let bytes = try L.encode(greeting)
        bytes.withUnsafeBytes { xpc_dictionary_set_data(message, "request", $0.baseAddress, $0.count) }
        let done = DispatchSemaphore(value: 0), accepted = Mutex(false), gate = self.gate
        xpc_connection_send_message_with_reply(connection, message, events) { [weak self] reply in
            guard let self else { gate.close(); done.signal(); return }
            self.worker.async {
                defer { done.signal() }
                do {
                    try self.authenticate(reply)
                    guard xpc_dictionary_get_bool(reply, "ok"), self.greeting == greeting else { throw Failure.invalidMessage }
                    accepted.withLock { $0 = true }
                } catch { gate.close() }
            }
        }
        guard done.wait(timeout: .now() + 5) == .success, accepted.withLock({ $0 }) else { throw Failure.unavailable }
        try gate.whileOpen()
    }

    /// Shared production helper policy; the token comes only from the actual
    /// received Mach message. Also exposed internally for anonymous-XPC rejection tests.
    static func authenticateRoot(_ message: xpc_object_t, team: String, policy: StorageLifecycleNativePolicy = .production) throws -> StorageLifecycleFreshShim.RootPeer {
        try StorageLifecycleFreshShim.authenticateRoot(message, team: team, policy: policy)
    }

    private func authenticate(_ message: xpc_object_t) throws {
        try gate.whileOpen()
        let peer = try Self.authenticateRoot(message, team: team, policy: policy)
        if let rootPeer { guard rootPeer == peer else { throw Failure.unauthorized } }
        else { rootPeer = peer }
        guard try StorageLifecycleFreshShim.observe(parentFD: parent.fileDescriptor) == processes else { throw Failure.unauthorized }
        try gate.whileOpen()
    }

    private func respond(_ message: xpc_object_t, connection: xpc_connection_t, deadline: DispatchTime) throws {
        // Native ROOT authentication MUST precede even decoding the unsigned DTO.
        try authenticate(message)
        guard DispatchTime.now() < deadline,
              let operation = xpc_dictionary_get_string(message, "operation"),
              String(cString: operation) == "storage-lifecycle-service-challenge" else { throw Failure.invalidMessage }
        var count = 0
        guard let bytes = xpc_dictionary_get_data(message, "request", &count), count > 0,
              count <= L.maximumPayloadBytes else { throw Failure.invalidMessage }
        let challenge = try Wire.decodeChallenge(Data(bytes: bytes, count: count))
        guard challenge.greeting == greeting, challenge.shimAudit == processes.shimAudit,
              challenge.daemonAudit == processes.daemonAudit, challenge.shimUniqueID == processes.shimUniqueID,
              challenge.counter > counter, challenge.nonce != nonce,
              challenge.isFresh(at: UInt64(Date().timeIntervalSince1970 * 1000)) else { throw Failure.unauthorized }
        // Consume before ANY boot-capability/disk validation, including failures.
        counter = challenge.counter; nonce = challenge.nonce
        try Self.validateBacking(boot: boot, binding: binding)
        // Grant epochs/operations may change under this real ROOT, but the full
        // (store, generation, binding) identity and service epoch stay fixed.
        let trust = try boot.trust(for: challenge.grant)
        guard trust == greeting.boot else { throw Failure.unauthorized }
        let response = try Wire.Reply(challengeSHA256: challenge.digest, boot: trust)
        try authenticate(message) // Pin native ROOT/own/parent identities after disk I/O.
        guard challenge.isFresh(at: UInt64(Date().timeIntervalSince1970 * 1000)),
              let reply = xpc_dictionary_create_reply(message) else { throw Failure.invalidMessage }
        let encoded = try L.encode(response)
        xpc_dictionary_set_bool(reply, "ok", true)
        encoded.withUnsafeBytes { xpc_dictionary_set_data(reply, "reply", $0.baseAddress, $0.count) }
        try gate.whileOpen()
        guard DispatchTime.now() < deadline else { throw Failure.unavailable }
        // Cancellation uses this same connection; no I/O is done under the gate.
        xpc_connection_send_message(connection, reply)
    }
}
#endif

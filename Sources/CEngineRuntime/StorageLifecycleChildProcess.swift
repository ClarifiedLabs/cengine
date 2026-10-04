#if os(macOS)
import CEngineCore
import CryptoKit
import Darwin
import Foundation
import Security

@_silgen_name("csops")
nonisolated private func lifecycleControllerCodeStatus(_ pid: Int32, _ operation: UInt32, _ buffer: UnsafeMutableRawPointer, _ size: Int) -> Int32

/// Launches and authenticates the storage controller child and owns its private channel.
/// Controller keys stay in the child; root-helper enrollment and key lookup belong
/// to the caller.
nonisolated public final class StorageLifecycleChildProcess: @unchecked Sendable {
    public enum Failure: Error { case invalidConfiguration, unauthorized, system(Int32), protocolViolation, connectionClosed, serviceUnavailable, workloadFailed }
    /// Closed diagnostic vocabulary; not evidence of mutation outcome or retry safety.
    public enum TerminalCode: String, Sendable, CaseIterable {
        case session = "fatal-session", protocolViolation = "fatal-protocol", timeout = "fatal-timeout"
        case canceled = "fatal-canceled", eof = "fatal-eof", truncated = "fatal-truncated"
        case transport = "fatal-transport", tls = "fatal-tls", internalFailure = "fatal-internal"
        case remoteInvalid = "fatal-remote-INVALID", remoteUnauthorized = "fatal-remote-UNAUTHORIZED"
        case remoteConflict = "fatal-remote-CONFLICT", remoteUnknown = "fatal-remote-UNKNOWN"
        case remoteBlocked = "fatal-remote-BLOCKED", remoteLimit = "fatal-remote-LIMIT", remoteBusy = "fatal-remote-BUSY"
        case remoteClosed = "fatal-remote-CLOSED", remoteTimeout = "fatal-remote-TIMEOUT"
        case remoteRepairRequired = "fatal-remote-REPAIR_REQUIRED", remoteInternal = "fatal-remote-INTERNAL"
    }
    public struct ExchangeFailure: Error, Equatable, Sendable, CustomStringConvertible {
        public enum Cause: Equatable, Sendable {
            case rejected(TerminalCode), connectionClosed, system(Int32), invalidReply
        }
        public let operation: String
        public let cause: Cause
        public var description: String { "storage controller \(operation) failed: \(cause)" }
    }
    public typealias Greeting = StorageLifecycleChildProtocol.Greeting
    public typealias Lifecycle = StorageLifecycleProtocol
    private static let maximumPayloadBytes = 64 * 1024
    private static let maximumWorkloadRequestBytes = 256 * 1024
    private static let maximumWorkloadResponseBytes = 4 * 1024 * 1024
    private static let maximumWorkloadReplyBytes = maximumWorkloadResponseBytes * 4 / 3 + 1024
    private let descriptor: Int32
    public let pid: Int32
    private let lock = NSLock()
    private var closed = false
    private var firstExchangeFailure: ExchangeFailure?
    private var reaped = false
    private var initialized = false
    private var retainedGreeting: Greeting?
    private var sequence: UInt64 = 0
    private var ioDeadline = ProcessInfo.processInfo.systemUptime + 5
    private var exchangeTimeout: TimeInterval = 5
    /// Minted only by launch after actual process observation, never by DTO decoding.
    public private(set) var processIdentity: NativeProcessIdentity?
    private init(descriptor: Int32, pid: Int32) { self.descriptor = descriptor; self.pid = pid }

    public struct NativeProcessIdentity: Sendable {
        public let childAudit: Data
        public let childUniqueID: UInt64
        public let daemonAudit: Data
        public let daemonUniqueID: UInt64
        fileprivate init(_ hello: ProcessHello) {
            childAudit = hello.childAudit; childUniqueID = hello.childUniqueID
            daemonAudit = hello.daemonAudit; daemonUniqueID = hello.daemonUniqueID
        }
    }
    fileprivate struct ProcessHello: Codable {
        let childAudit: Data
        let childUniqueID: UInt64
        let daemonAudit: Data
        let daemonUniqueID: UInt64
        let version: String
        enum CodingKeys: String, CodingKey {
            case childAudit = "child_audit", childUniqueID = "child_unique_id"
            case daemonAudit = "daemon_audit", daemonUniqueID = "daemon_unique_id", version
        }
    }
    public struct Initialization: Codable, Sendable {
        public let binding: String
        public let expectedEpoch: UInt64
        public let incarnationID: String
        public let rootPublicKey: Data
        public let store: String
        public let version: String
        public init(binding: String, expectedEpoch: UInt64, incarnationID: String, rootPublicKey: Data, store: String) throws {
            self.binding = binding; self.expectedEpoch = expectedEpoch; self.incarnationID = incarnationID
            self.rootPublicKey = rootPublicKey; self.store = store; version = StorageLifecycleChildProtocol.version
            try validate()
        }
        func validate() throws {
            guard version == StorageLifecycleChildProtocol.version, expectedEpoch < UInt64.max else { throw Failure.invalidConfiguration }
            _ = try StorageIdentity.SPKISHA256(binding)
            _ = try StorageIdentity.IncarnationID(incarnationID)
            _ = try StorageIdentity.RootPublicKey(publicData: rootPublicKey)
            _ = try StorageIdentity.StoreID(store)
        }
        enum CodingKeys: String, CodingKey {
            case binding, store, version, expectedEpoch = "expected_epoch", incarnationID = "incarnation_id", rootPublicKey = "root_public_key"
        }
    }
    /// TLS inputs, not boot provenance. Only the child's native ROOT challenge can
    /// authorize matching result proof. No endpoint or private key can be supplied.
    public struct Boot: Codable, Sendable {
        public let certificateDER: Data
        public let identity: Lifecycle.Identity
        public let rootDER: Data
        public let serverSPKI: String
        public let serviceEpoch: String
        public let signed: Lifecycle.SignedGrant
        public init(certificateDER: Data, identity: Lifecycle.Identity, rootDER: Data, serverSPKI: String,
                    serviceEpoch: String, signed: Lifecycle.SignedGrant) throws {
            self.certificateDER = certificateDER; self.identity = identity; self.rootDER = rootDER
            self.serverSPKI = serverSPKI; self.serviceEpoch = serviceEpoch; self.signed = signed
            try validate()
        }
        func validate() throws {
            try identity.validate(); try signed.validate()
            _ = try StorageIdentity.SPKISHA256(serverSPKI)
            _ = try StorageIdentity.IncarnationID(serviceEpoch)
            guard signed.grant.identity == identity, signed.grant.operation != .retire,
                  !certificateDER.isEmpty, certificateDER.count <= 16 * 1024,
                  !rootDER.isEmpty, rootDER.count <= 16 * 1024,
                  SecCertificateCreateWithData(nil, certificateDER as CFData) != nil,
                  SecCertificateCreateWithData(nil, rootDER as CFData) != nil else { throw Failure.invalidConfiguration }
        }
        enum CodingKeys: String, CodingKey {
            case identity, signed, certificateDER = "certificate_der", rootDER = "root_der"
            case serverSPKI = "server_spki", serviceEpoch = "service_epoch"
        }
    }
    /// Public CSR and persisted attachment only. The child independently checks
    /// current ownership, the exact certificate URI and pins using frozen boot trust.
    public struct AttachmentCertificateRequest: Encodable, Sendable {
        public let binding: ManagedStorageControlProtocol.Binding
        public let serviceEpoch: String
        public let controllerEpoch: UInt64
        public let csr: Data
        public let identity: Lifecycle.Identity
        public init(binding: ManagedStorageControlProtocol.Binding, serviceEpoch: String,
                    controllerEpoch: UInt64, csr: Data, identity: Lifecycle.Identity) throws {
            try identity.validate()
            _ = try StorageIdentity.IncarnationID(serviceEpoch)
            // Binding is Codable; reconstruct to validate even a decoded value.
            _ = try ManagedStorageControlProtocol.Binding(store: binding.store, volume: binding.volume,
                attachment: binding.attachment, prepare: binding.prepare, container: binding.container,
                launch: binding.launch, key: binding.key, role: binding.role, mode: binding.mode)
            guard identity.store == binding.store, controllerEpoch > 0,
                  (binding.role == .prepare) == (binding.prepare != nil),
                  !csr.isEmpty, csr.count <= 16 * 1024 else { throw Failure.invalidConfiguration }
            self.binding = binding; self.serviceEpoch = serviceEpoch
            self.controllerEpoch = controllerEpoch; self.csr = csr; self.identity = identity
        }
        private struct Attachment: Encodable {
            let binding: ManagedStorageControlProtocol.Binding
            let epoch: String
        }
        private enum CodingKeys: String, CodingKey {
            case attachment, csr, identity, controllerEpoch = "controller_epoch"
        }
        public func encode(to encoder: any Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(Attachment(binding: binding, epoch: serviceEpoch), forKey: .attachment)
            try container.encode(controllerEpoch, forKey: .controllerEpoch)
            try container.encode(csr, forKey: .csr)
            try container.encode(identity, forKey: .identity)
        }
    }
    public struct AttachmentCertificate: Sendable {
        public let der: Data
        fileprivate init(_ der: Data) throws {
            guard der.count >= 2, der.count <= 16 * 1024 else { throw Failure.protocolViolation }
            // Require one complete, definite-length DER SEQUENCE, not a parsed
            // prefix with trailing data or a nonminimal outer length encoding.
            let bytes = [UInt8](der)
            guard bytes[0] == 0x30 else { throw Failure.protocolViolation }
            var header = 2, length = Int(bytes[1])
            if length >= 128 {
                let width = length & 0x7f
                guard (1...2).contains(width), bytes.count >= 2 + width, bytes[2] != 0 else { throw Failure.protocolViolation }
                header += width; length = 0
                for byte in bytes[2..<header] { length = length * 256 + Int(byte) }
                guard length >= 128 else { throw Failure.protocolViolation }
            }
            guard header + length == bytes.count,
                  SecCertificateCreateWithData(nil, der as CFData) != nil else { throw Failure.protocolViolation }
            self.der = der
        }
    }
    public enum AttachmentCertificateFailure: String, Sendable { case rejected, unavailable }
    public enum AttachmentCertificateResult: Sendable {
        case certificate(AttachmentCertificate)
        case failure(AttachmentCertificateFailure)
        private struct Wire: Codable {
            let certificate: Data?
            let error: String?
        }
        fileprivate static func decode(_ data: Data) throws -> Self {
            // Bounds include padded base64 and the exact one-field JSON wrapper.
            guard !data.isEmpty, data.count <= 4 * ((16 * 1024 + 2) / 3) + 18 else { throw Failure.protocolViolation }
            let wire = try Lifecycle.decode(Wire.self, from: data)
            switch (wire.certificate, wire.error) {
            case (let der?, nil): return .certificate(try AttachmentCertificate(der))
            case (nil, let text?):
                guard let failure = AttachmentCertificateFailure(rawValue: text) else { throw Failure.protocolViolation }
                return .failure(failure)
            default: throw Failure.protocolViolation
            }
        }
    }

    /// Bounded public signed-grant diagnostic, not a lifecycle authorization.
    public struct PublicTakeoverReplayRequest: Codable, Equatable, Sendable {
        public let version: UInt32
        public let requestID: String
        public let old: Lifecycle.SignedGrant
        public init(requestID: String, old: Lifecycle.SignedGrant) throws {
            version = 1; self.requestID = requestID; self.old = old
            try validate()
        }
        public func validate() throws {
            _ = try StorageIdentity.GrantID(requestID)
            try old.validate()
            guard version == 1, old.grant.operation == .takeover else { throw Failure.invalidConfiguration }
        }
    }
    public struct PublicTakeoverReplayObservation: Codable, Equatable, Sendable {
        public let version: UInt32
        public let requestID: String
        public let old: Lifecycle.SignedGrant
        public let pending: Lifecycle.SignedGrant
        public let incarnationID: String
        public let error: String

        public static func decode(_ data: Data, request: PublicTakeoverReplayRequest) throws -> Self {
            try request.validate()
            guard !data.isEmpty, data.count <= 4096 else { throw Failure.protocolViolation }
            let value = try Lifecycle.decode(Self.self, from: data)
            try value.old.validate(); try value.pending.validate()
            _ = try StorageIdentity.IncarnationID(value.incarnationID)
            let o = value.old.grant, p = value.pending.grant
            guard value.version == 1, value.requestID == request.requestID, value.old == request.old,
                  value.error == "UNAUTHORIZED", o.operation == .takeover, p.operation == .takeover,
                  o.identity == p.identity, o.expectedEpoch + 1 == p.expectedEpoch,
                  o.id != p.id, o.serial < p.serial, o.newKey != p.newKey else { throw Failure.protocolViolation }
            return value
        }
    }

    /// OLD must come from the host-validated current.original.signed checkpoint.
    /// The caller must additionally correlate pending with its bound candidate.
    public func publicTakeoverReplay(requestID: String, old: Lifecycle.SignedGrant) throws -> PublicTakeoverReplayObservation {
        let request = try PublicTakeoverReplayRequest(requestID: requestID, old: old)
        let reply = try exchange("public-takeover-replay", body: request, replyKind: .publicTakeoverReplay(request))
        guard let observation = reply.publicTakeoverReplay else { throw Failure.protocolViolation }
        return observation
    }

    public static func launch(installedHelperTeam: String, policy: StorageLifecycleNativePolicy = .production) throws -> StorageLifecycleChildProcess {
        let identity = try policy.currentIdentity(role: .engine)
        guard identity.teamIdentifier == installedHelperTeam else { throw Failure.unauthorized }
        let executable = try identity.storageControllerExecutable()
        guard executable.isFileURL, installedHelperTeam.utf8.count == 10,
              installedHelperTeam.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) }) else {
            throw Failure.invalidConfiguration
        }
        // This is preflight only. ROOT independently authenticates each message's
        // immutable audit token and executable identity after launch.
        let identifier = policy.controllerIdentifier
        var code: SecStaticCode?, requirement: SecRequirement?
        let expression = try SignedStorageIdentity.developerIDRequirement(identifiers: [identifier], team: installedHelperTeam)
        guard SecStaticCodeCreateWithPath(executable as CFURL, [], &code) == errSecSuccess, let code,
              SecRequirementCreateWithString(expression as CFString, [], &requirement) == errSecSuccess, let requirement,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else {
            throw Failure.unauthorized
        }
        try requireHardenedCode(code)
        try policy.validateControllerCode(code, expectedTeam: installedHelperTeam)
        var sockets: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0 else { throw Failure.system(errno) }
        var transferred = false
        defer { if !transferred { Darwin.close(sockets[0]) }; Darwin.close(sockets[1]) }
        guard fcntl(sockets[0], F_SETFD, FD_CLOEXEC) == 0,
              fcntl(sockets[1], F_SETFD, FD_CLOEXEC) == 0 else { throw Failure.system(errno) }
        // Only the parent's private child channel is deadline-driven. Do not
        // alter connected streams later borrowed for SCM_RIGHTS transfer.
        let channelFlags = fcntl(sockets[0], F_GETFL)
        guard channelFlags >= 0, fcntl(sockets[0], F_SETFL, channelFlags | O_NONBLOCK) == 0 else { throw Failure.system(errno) }
        var timeout = timeval(tv_sec: 10, tv_usec: 0)
        var noSignal: Int32 = 1
        guard setsockopt(sockets[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
              setsockopt(sockets[0], SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
              setsockopt(sockets[0], SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size)) == 0 else { throw Failure.system(errno) }
        var childFD = fcntl(sockets[1], F_DUPFD_CLOEXEC, 10)
        guard childFD >= 0 else { throw Failure.system(errno) }
        defer { Darwin.close(childFD) }
        let nullFD = open("/dev/null", O_RDWR | O_CLOEXEC)
        guard nullFD >= 0 else { throw Failure.system(errno) }
        defer { Darwin.close(nullFD) }
        var actions: posix_spawn_file_actions_t?, attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw Failure.system(errno) }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attributes) == 0 else { throw Failure.system(errno) }
        defer { posix_spawnattr_destroy(&attributes) }
        for (from, to) in [(childFD, Int32(3)), (nullFD, Int32(0)), (nullFD, Int32(1)), (nullFD, Int32(2))] {
            let result = posix_spawn_file_actions_adddup2(&actions, from, to)
            guard result == 0 else { throw Failure.system(result) }
        }
        // Start suspended: the path can be replaced after static preflight. Verify
        // the actual spawned executable before it executes or receives capabilities.
        let flags = posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_START_SUSPENDED))
        guard flags == 0 else { throw Failure.system(flags) }
        let strings: [String] = [executable.path, "--lifecycle-v2"]
        let arguments = strings.map { $0.withCString { strdup($0) } }
        guard arguments.allSatisfy({ $0 != nil }) else { throw Failure.system(ENOMEM) }
        defer { for argument in arguments { free(argument) } }
        var argv = arguments + [nil]
        var environment: [UnsafeMutablePointer<CChar>?] = [nil]
        var pid: pid_t = 0
        let result = posix_spawn(&pid, executable.path, &actions, &attributes, &argv, &environment)
        guard result == 0 else { throw Failure.system(result) }
        Darwin.close(childFD); childFD = -1
        Darwin.close(sockets[1]); sockets[1] = -1
        let process = StorageLifecycleChildProcess(descriptor: sockets[0], pid: pid)
        transferred = true
        do {
            var running: SecCode?
            guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary,
                                                [], &running) == errSecSuccess, let running,
                  SecCodeCheckValidity(running, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else {
                throw Failure.unauthorized
            }
            var runningStatic: SecStaticCode?
            guard SecCodeCopyStaticCode(running, [], &runningStatic) == errSecSuccess, let runningStatic else { throw Failure.unauthorized }
            try requireHardenedCode(runningStatic)
            try policy.validateControllerCode(runningStatic, expectedTeam: installedHelperTeam)
            var status: UInt32 = 0
            guard lifecycleControllerCodeStatus(pid, 0, &status, MemoryLayout<UInt32>.size) == 0,
                  status & SignedStorageIdentity.controllerRuntimeFlag != 0 else { throw Failure.unauthorized }
            guard kill(pid, SIGCONT) == 0 else { throw Failure.system(errno) }
            process.ioDeadline = ProcessInfo.processInfo.systemUptime + 5
            let hello: ProcessHello = try process.receive()
            process.processIdentity = try observe(hello, childPID: pid)
            return process
        } catch {
            process.close()
            throw error
        }
    }

    private static func requireHardenedCode(_ code: SecStaticCode) throws {
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let dictionary = information as? [String: Any], let flags = dictionary[kSecCodeInfoFlags as String] as? NSNumber else { throw Failure.unauthorized }
        let entitlements = dictionary[kSecCodeInfoEntitlementsDict as String]
        guard entitlements == nil || entitlements is [String: Any],
              SignedStorageIdentity.acceptsControllerCodeSigning(flags: flags.uint32Value,
                entitlementKeys: Set((entitlements as? [String: Any] ?? [:]).keys)) else { throw Failure.unauthorized }
    }

    private static func observe(_ hello: ProcessHello, childPID: Int32) throws -> NativeProcessIdentity {
        guard hello.version == StorageLifecycleChildProtocol.version,
              hello.childAudit.count == 32, hello.daemonAudit.count == 32,
              hello.childUniqueID != hello.daemonUniqueID else { throw Failure.unauthorized }
        var own = audit_token_t(), count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
        let result = withUnsafeMutablePointer(to: &own) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count) }
        }
        guard result == KERN_SUCCESS, count == 8,
              withUnsafeBytes(of: own, { Data($0) }) == hello.daemonAudit else { throw Failure.unauthorized }
        let child = hello.childAudit.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) }
        guard child.val.5 == UInt32(childPID), child.val.1 == geteuid(), child.val.3 == getuid(),
              let parent = processTuple(getpid()), let observed = processTuple(childPID),
              parent.id == hello.daemonUniqueID, parent.version == own.val.7,
              observed.id == hello.childUniqueID, observed.parent == parent.id, observed.version == child.val.7 else { throw Failure.unauthorized }
        return NativeProcessIdentity(hello)
    }
    private static func processTuple(_ pid: Int32) -> (id: UInt64, parent: UInt64, version: UInt32)? {
        var bytes = [UInt8](repeating: 0, count: 56)
        guard proc_pidinfo(pid, 17, 0, &bytes, 56) == 56 else { return nil }
        return bytes.withUnsafeBytes { ($0.loadUnaligned(fromByteOffset: 16, as: UInt64.self),
            $0.loadUnaligned(fromByteOffset: 24, as: UInt64.self), $0.loadUnaligned(fromByteOffset: 32, as: UInt32.self)) }
    }

    /// Call only after the external helper enrollment has pinned processIdentity.
    /// This is the sole initialization; the child opens its own native ROOT channel.
    public func initialize(_ initialization: Initialization) throws -> Greeting {
        try initialization.validate()
        return try lock.withLock {
            guard !closed, !initialized, let processIdentity else { throw Failure.protocolViolation }
            initialized = true
            ioDeadline = ProcessInfo.processInfo.systemUptime + exchangeTimeout
            do {
                try sendFrame(Lifecycle.encode(initialization))
                let greeting = try StorageLifecycleChildProtocol.decodeGreeting(receiveFrame())
                guard greeting.daemonUniqueID == processIdentity.daemonUniqueID,
                      greeting.incarnationID == initialization.incarnationID,
                      greeting.rootPublicKey == initialization.rootPublicKey,
                      greeting.store == initialization.store, greeting.binding == initialization.binding,
                      greeting.expectedEpoch == initialization.expectedEpoch else { throw Failure.protocolViolation }
                retainedGreeting = greeting
                return greeting
            } catch {
                closeLocked(); throw error
            }
        }
    }

    public func controllerCSR() throws -> Data { try exchange("controller-csr", body: Optional<String>.none, replyKind: .csr).data }
    public func bindGrant(_ signed: Lifecycle.SignedGrant) throws {
        try signed.validate()
        guard signed.grant.operation != .retire else { throw Failure.invalidConfiguration }
        _ = try exchange("bind-grant", body: signed)
    }
    public func bindRetire(_ signed: Lifecycle.SignedGrant) throws {
        try signed.validate()
        guard signed.grant.operation == .retire else { throw Failure.invalidConfiguration }
        _ = try exchange("bind-retire", body: signed)
    }
    /// Borrows the caller's stream only long enough to duplicate it. The owned
    /// duplicate is closed on every path; exactly one right is sent, on the header.
    public func connectBoot(socket: Int32, boot: Boot) throws {
        try boot.validate()
        let owned = try Self.duplicateConnectedSocket(socket)
        defer { Darwin.close(owned) }
        _ = try exchange("connect-boot", body: boot, passing: owned)
    }
    /// Stages one replacement stream and TLS inputs, never commits new trust.
    /// Only the child's authenticated ROOT service proof can authorize the rebind.
    public func stageServiceRebind(socket: Int32, change: Lifecycle.ServiceChangeRequest, boot: Boot) throws {
        try change.validate(); try boot.validate()
        guard boot.signed.grant == change.predecessor.grant,
              boot.identity == change.predecessor.grant.identity else { throw Failure.invalidConfiguration }
        let trust = try StorageLifecycleBootTrust(identity: boot.identity, serviceEpoch: boot.serviceEpoch,
            tlsRootSHA256: SHA256.hash(data: boot.rootDER).map { String(format: "%02x", $0) }.joined(),
            serverSPKI: boot.serverSPKI, bootstrapKey: change.predecessor.boot.bootstrapKey)
        try change.validateSuccessorBoot(trust)
        // This is shape validation only. The child derives its own pinned ROOT
        // bootstrap key and compares the old/new actual CA public keys itself.
        let owned = try Self.duplicateConnectedSocket(socket)
        defer { Darwin.close(owned) }
        _ = try exchange("stage-service-rebind", body: ServiceRebindRequest(boot: boot, change: change), passing: owned)
    }
    private struct ServiceRebindRequest: Encodable {
        let boot: Boot
        let change: Lifecycle.ServiceChangeRequest
    }

    /// Borrows one connected stream. The child retains its audited boot trust;
    /// the caller supplies neither TLS identity nor an authorization assertion.
    public func connectWorkload(socket: Int32) throws {
        let owned = try Self.duplicateConnectedSocket(socket)
        defer { Darwin.close(owned) }
        _ = try exchange("connect-workload", body: Optional<String>.none, passing: owned)
    }
    public func workloadCommand(request: ManagedStorageControlProtocol.ControlRequest) throws -> Data {
        // Lifecycle takeover remains its own ROOT-authorized operation.
        return try exchange("workload-command", body: WorkloadRequest(request: request), replyKind: .workload).data
    }
    /// Borrows exactly one connected socket; owns and closes its duplicate on
    /// every path. No caller TLS identity, private key or authority is accepted.
    public func attachmentCertificate(socket: Int32, request: AttachmentCertificateRequest) throws -> AttachmentCertificateResult {
        let owned = try Self.duplicateConnectedSocket(socket)
        defer { Darwin.close(owned) }
        let reply = try exchange("attachment-certificate", body: request, passing: owned, replyKind: .attachmentCertificate)
        guard let certificate = reply.attachmentCertificate else { throw Failure.protocolViolation }
        return certificate
    }
    public func takeover() throws { _ = try exchange("takeover", body: Optional<String>.none) }
    public func retire() throws { _ = try exchange("retire", body: Optional<String>.none) }

    private struct Request<Body: Encodable>: Encodable {
        let body: Body?
        let operation: String
        let requestID: UInt64
        let version = StorageLifecycleChildProtocol.version
        enum CodingKeys: String, CodingKey { case body, operation, version, requestID = "request_id" }
    }
    /// The closed storagecontrol.Request union, not an encoded blob or a generic
    /// JSON capability. The child assigns the actual TLS request sequence.
    private struct WorkloadRequest: Encodable {
        let request: ManagedStorageControlProtocol.ControlRequest
        private struct Empty: Encodable {}
        private enum CodingKeys: String, CodingKey {
            case id, query, retire
            case reservePrepare = "reserve_prepare", registerAttachment = "register_attachment"
            case completePrepare = "complete_prepare", replacePrepare = "replace_prepare"
            case createVolume = "create_volume", deleteVolume = "delete_volume"
        }
        func encode(to encoder: any Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(UInt64(0), forKey: .id)
            switch request {
            case .query: try container.encode(Empty(), forKey: .query)
            case .reservePrepare(let body): try container.encode(body, forKey: .reservePrepare)
            case .registerAttachment(let body): try container.encode(body, forKey: .registerAttachment)
            case .retire(let body): try container.encode(body, forKey: .retire)
            case .completePrepare(let body): try container.encode(body, forKey: .completePrepare)
            case .replacePrepare(let body): try container.encode(body, forKey: .replacePrepare)
            case .createVolume(let body): try container.encode(body, forKey: .createVolume)
            case .deleteVolume(let body): try container.encode(body, forKey: .deleteVolume)
            }
        }
    }
    private enum ReplyKind: Equatable {
        case empty, csr, workload, attachmentCertificate
        case publicTakeoverReplay(PublicTakeoverReplayRequest)
    }
    private struct ExchangeReply {
        let data: Data
        let attachmentCertificate: AttachmentCertificateResult?
        let publicTakeoverReplay: PublicTakeoverReplayObservation?
    }
    private struct ErrorReply: Codable {
        let error: String
        let requestID: UInt64
        let version: String
        enum CodingKeys: String, CodingKey { case error, version, requestID = "request_id" }
    }
    private struct Reply: Codable {
        let data: Data
        let requestID: UInt64
        let version: String
        enum CodingKeys: String, CodingKey { case data, version, requestID = "request_id" }
    }
    private func exchange<Body: Encodable>(_ operation: String, body: Body?, passing fd: Int32 = -1, replyKind: ReplyKind = .empty) throws -> ExchangeReply {
        let deadline = ProcessInfo.processInfo.systemUptime + exchangeTimeout
        while !lock.try() {
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw Failure.system(ETIMEDOUT) }
            Thread.sleep(forTimeInterval: 0.001)
        }
        defer { lock.unlock() }
        if let firstExchangeFailure { throw firstExchangeFailure }
        guard !closed, initialized, sequence < UInt64.max else {
            throw Failure.protocolViolation
        }
        var result: ExchangeReply?
        var workloadFailure: Failure?
        do {
            let next = sequence + 1
            let request = Request(body: body, operation: operation, requestID: next)
            let workload = replyKind == .workload
            let bytes = try workload ? Self.workloadBytes(request, limit: Self.maximumWorkloadRequestBytes) : Lifecycle.encode(request)
            ioDeadline = deadline
            sequence = next
            try sendFrame(bytes, passing: fd, limit: workload ? Self.maximumWorkloadRequestBytes : Self.maximumPayloadBytes)
            let reply: Reply?
            let limit = workload ? Self.maximumWorkloadReplyBytes : Self.maximumPayloadBytes
            let raw = try receiveFrame(limit: limit)
            if let terminal = try? JSONDecoder().decode(ErrorReply.self, from: raw),
               let code = TerminalCode(rawValue: terminal.error) {
                guard terminal.version == StorageLifecycleChildProtocol.version, terminal.requestID == next,
                      try Self.workloadBytes(terminal, limit: limit) == raw else { throw Failure.protocolViolation }
                throw ExchangeFailure(operation: operation, cause: .rejected(code))
            }
            if workload || operation == "connect-workload" {
                if let unavailable = try? JSONDecoder().decode(ErrorReply.self, from: raw) {
                    let permitted = unavailable.error == "workload-failed" ||
                        (operation == "workload-command" && unavailable.error == "workload-unavailable")
                    guard permitted,
                          unavailable.version == StorageLifecycleChildProtocol.version, unavailable.requestID == next,
                          try Self.workloadBytes(unavailable, limit: limit) == raw else {
                        throw Failure.protocolViolation
                    }
                    workloadFailure = unavailable.error == "workload-unavailable" ? .serviceUnavailable : .workloadFailed
                    reply = nil
                } else {
                    let decoded = try JSONDecoder().decode(Reply.self, from: raw)
                    // Re-encoding closes duplicate/unknown keys and noncanonical spellings.
                    guard try Self.workloadBytes(decoded, limit: limit) == raw else { throw Failure.protocolViolation }
                    reply = decoded
                }
            } else {
                reply = try Lifecycle.decode(Reply.self, from: raw)
            }
            if let reply {
                guard reply.version == StorageLifecycleChildProtocol.version, reply.requestID == next else { throw Failure.protocolViolation }
                var certificate: AttachmentCertificateResult?
                var replay: PublicTakeoverReplayObservation?
                switch replyKind {
                case .empty: guard reply.data.isEmpty else { throw Failure.protocolViolation }
                case .csr: guard !reply.data.isEmpty, reply.data.count <= 16 * 1024 else { throw Failure.protocolViolation }
                case .workload: guard !reply.data.isEmpty, reply.data.count <= Self.maximumWorkloadResponseBytes else { throw Failure.protocolViolation }
                case .publicTakeoverReplay(let request):
                    replay = try PublicTakeoverReplayObservation.decode(reply.data, request: request)
                    if let greeting = retainedGreeting {
                        guard replay?.incarnationID == greeting.incarnationID else { throw Failure.protocolViolation }
                    }
                case .attachmentCertificate:
                    // Decode and validate under the exchange lock so a malformed
                    // result fences the channel before any waiting call can send.
                    certificate = try AttachmentCertificateResult.decode(reply.data)
                }
                result = ExchangeReply(data: reply.data, attachmentCertificate: certificate, publicTakeoverReplay: replay)
            }
        } catch {
            let failure: ExchangeFailure
            if let diagnosed = error as? ExchangeFailure {
                failure = diagnosed
            } else {
                let cause: ExchangeFailure.Cause
                switch error {
                case Failure.connectionClosed: cause = .connectionClosed
                case Failure.system(let code): cause = .system(code)
                default: cause = .invalidReply
                }
                failure = ExchangeFailure(operation: operation, cause: cause)
            }
            firstExchangeFailure = failure
            closeLocked()
            throw failure
        }
        // Correlated workload failures preserve only the lifecycle channel. The
        // non-boundary failure never enters the owner's Retire reconnect path.
        if let workloadFailure { throw workloadFailure }
        guard let result else { throw Failure.protocolViolation }
        return result
    }
    /// Workload frames have their own bounded closed serializer. Never route
    /// oversized data through the lifecycle protocol's 64 KiB codec or v1 codec.
    private static func workloadBytes<T: Encodable>(_ value: T, limit: Int) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let encoded = try encoder.encode(value)
        guard !encoded.isEmpty, encoded.count <= limit else { throw Failure.protocolViolation }
        let text = String(decoding: encoded, as: UTF8.self)
            .replacingOccurrences(of: "<", with: "\\u003c").replacingOccurrences(of: ">", with: "\\u003e")
            .replacingOccurrences(of: "&", with: "\\u0026").replacingOccurrences(of: "\u{2028}", with: "\\u2028")
            .replacingOccurrences(of: "\u{2029}", with: "\\u2029")
        let bytes = Data(text.utf8)
        guard bytes.count <= limit else { throw Failure.protocolViolation }
        return bytes
    }
    /// EOF revokes the private owner. Termination is limited to our exact unreaped
    /// child; ECHILD is never permission to signal a potentially recycled PID.
    public func close() { lock.withLock { closeLocked() } }
    private func closeLocked() {
        if !closed { closed = true; shutdown(descriptor, SHUT_RDWR); Darwin.close(descriptor) }
        guard pid > 0, !reaped else { return }
        var status: Int32 = 0
        var result: pid_t
        repeat { result = waitpid(pid, &status, WNOHANG) } while result < 0 && errno == EINTR
        if result == 0 {
            _ = kill(pid, SIGKILL)
            let deadline = ProcessInfo.processInfo.systemUptime + 1
            repeat {
                result = waitpid(pid, &status, WNOHANG)
                if result == pid || (result < 0 && errno != EINTR) { break }
                Thread.sleep(forTimeInterval: 0.001)
            } while ProcessInfo.processInfo.systemUptime < deadline
        }
        if result == pid || (result < 0 && errno == ECHILD) { reaped = true }
    }
    deinit { close() }

    // Internal socket-only test seam. Never mints NativeProcessIdentity or owns a PID.
    static func adoptingTestSocket(_ socket: Int32, timeout: TimeInterval = 0.2, sequence: UInt64 = 0) throws -> StorageLifecycleChildProcess {
        guard timeout > 0, timeout <= 5, timeout.isFinite else { throw Failure.invalidConfiguration }
        let owned = try duplicateConnectedSocket(socket)
        var one: Int32 = 1
        guard setsockopt(owned, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            Darwin.close(owned); throw Failure.system(errno)
        }
        let process = StorageLifecycleChildProcess(descriptor: owned, pid: -1)
        process.exchangeTimeout = timeout; process.sequence = sequence; process.initialized = true
        return process
    }
    static func duplicateConnectedSocket(_ descriptor: Int32) throws -> Int32 {
        let owned = fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
        guard owned >= 0 else { throw Failure.system(errno) }
        var type: Int32 = 0, size = socklen_t(MemoryLayout<Int32>.size)
        var peer = sockaddr_storage(), peerSize = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let connected = withUnsafeMutablePointer(to: &peer) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getpeername(owned, $0, &peerSize) == 0 }
        }
        guard getsockopt(owned, SOL_SOCKET, SO_TYPE, &type, &size) == 0, type == SOCK_STREAM, connected else {
            Darwin.close(owned); throw Failure.invalidConfiguration
        }
        return owned
    }
    private func waitReady(_ events: Int32) throws {
        while true {
            let remaining = ioDeadline - ProcessInfo.processInfo.systemUptime
            guard remaining > 0 else { throw Failure.system(ETIMEDOUT) }
            var item = pollfd(fd: descriptor, events: Int16(events), revents: 0)
            let result = poll(&item, 1, Int32(min(5_000, max(1, remaining * 1000))))
            if result < 0 && errno == EINTR { continue }
            guard result > 0 else { throw Failure.system(result == 0 ? ETIMEDOUT : errno) }
            guard item.revents & Int16(events) != 0 else {
                if item.revents & Int16(POLLHUP | POLLERR) != 0 { throw Failure.connectionClosed }
                throw Failure.protocolViolation
            }
            return
        }
    }
    private func sendFrame(_ bytes: Data, passing fd: Int32 = -1, limit: Int = maximumPayloadBytes) throws {
        guard !bytes.isEmpty, bytes.count <= limit else { throw Failure.protocolViolation }
        var header = UInt32(bytes.count).bigEndian
        try waitReady(POLLOUT)
        let result = withUnsafeMutableBytes(of: &header) { raw in
            var iov = iovec(iov_base: raw.baseAddress, iov_len: 4)
            return withUnsafeMutablePointer(to: &iov) { pointer in
                var message = msghdr(); message.msg_iov = pointer; message.msg_iovlen = 1
                var control = [UInt32](repeating: 0, count: 4)
                return control.withUnsafeMutableBytes { ancillary in
                    if fd >= 0 {
                        ancillary.storeBytes(of: cmsghdr(cmsg_len: 16, cmsg_level: SOL_SOCKET, cmsg_type: SCM_RIGHTS), as: cmsghdr.self)
                        ancillary.storeBytes(of: fd, toByteOffset: 12, as: Int32.self)
                        message.msg_control = ancillary.baseAddress; message.msg_controllen = 16
                    }
                    var result: Int
                    repeat { result = Darwin.sendmsg(descriptor, &message, MSG_DONTWAIT) } while result < 0 && errno == EINTR
                    return result
                }
            }
        }
        // Never retry a partial rights-bearing header.
        guard result == 4 else { throw Failure.protocolViolation }
        var offset = 0
        while offset < bytes.count {
            try waitReady(POLLOUT)
            let n = bytes.withUnsafeBytes { Darwin.send(descriptor, $0.baseAddress!.advanced(by: offset), bytes.count - offset, MSG_DONTWAIT) }
            if n < 0 && [EINTR, EAGAIN].contains(errno) { continue }
            guard n > 0 else { throw Failure.protocolViolation }
            offset += n
        }
    }
    private func receiveFrame(limit: Int = maximumPayloadBytes) throws -> Data {
        let header = try receiveBytes(4)
        let count = header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).bigEndian }
        guard count > 0, count <= limit else { throw Failure.protocolViolation }
        return try receiveBytes(Int(count))
    }
    private func receive<T: Codable>() throws -> T { try Lifecycle.decode(T.self, from: receiveFrame()) }
    private func receiveBytes(_ count: Int) throws -> Data {
        var data = Data(count: count), offset = 0
        while offset < count {
            try waitReady(POLLIN)
            var ancillary = [UInt32](repeating: 0, count: 256)
            var flags: Int32 = 0, controlCount = 0
            let n = data.withUnsafeMutableBytes { raw in
                var iov = iovec(iov_base: raw.baseAddress!.advanced(by: offset), iov_len: count - offset)
                return withUnsafeMutablePointer(to: &iov) { pointer in
                    ancillary.withUnsafeMutableBytes { control in
                        var message = msghdr(); message.msg_iov = pointer; message.msg_iovlen = 1
                        message.msg_control = control.baseAddress; message.msg_controllen = socklen_t(control.count)
                        let result = Darwin.recvmsg(descriptor, &message, MSG_DONTWAIT)
                        flags = message.msg_flags; controlCount = Int(message.msg_controllen)
                        return result
                    }
                }
            }
            if n < 0 && [EINTR, EAGAIN].contains(errno) { continue }
            // No descriptor may arrive from the child, including on body fragments.
            // Close every delivered right before rejecting ancillary/truncated data.
            if n >= 0 && controlCount > 0 {
                ancillary.withUnsafeBytes { raw in
                    var cursor = 0
                    while cursor + 12 <= controlCount {
                        let header = raw.loadUnaligned(fromByteOffset: cursor, as: cmsghdr.self)
                        let length = Int(header.cmsg_len)
                        guard length >= 12, cursor + length <= controlCount else { break }
                        if header.cmsg_level == SOL_SOCKET && header.cmsg_type == SCM_RIGHTS {
                            for i in stride(from: cursor + 12, to: cursor + length - 3, by: 4) {
                                Darwin.close(raw.loadUnaligned(fromByteOffset: i, as: Int32.self))
                            }
                        }
                        cursor += (length + 3) & ~3
                    }
                }
            }
            guard controlCount == 0, flags & (MSG_CTRUNC | MSG_TRUNC) == 0 else { throw Failure.protocolViolation }
            if n == 0 { throw Failure.connectionClosed }
            guard n > 0 else { throw Failure.system(errno) }
            offset += n
        }
        return data
    }
}
#endif

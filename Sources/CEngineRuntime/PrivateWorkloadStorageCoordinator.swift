#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Synchronization

/// Public configuration only; never persisted into a VM launch specification.
public struct WorkloadStorageConfiguration: Codable, Equatable, Sendable {
    public let scope: WorkloadStorageProtocol.Scope
    public let peer: WorkloadStorageProtocol.Peer
    public let mounts: [WorkloadStorageProtocol.MountBinding]
    public let slots: [WorkloadStorageProtocol.Slot]

    public init(scope: WorkloadStorageProtocol.Scope, peer: WorkloadStorageProtocol.Peer,
                mounts: [WorkloadStorageProtocol.MountBinding], slots: [WorkloadStorageProtocol.Slot]) {
        self.scope = scope; self.peer = peer; self.mounts = mounts; self.slots = slots
    }

    func frame(binding: WorkloadStorageProtocol.BootBinding) -> WorkloadStorageProtocol.Frame {
        .init(operation: .configure, binding: binding, scope: scope,
              data: .init(peer: peer, mounts: mounts, slots: slots))
    }
}

/// Serialized evidence is not a capability. Only an authenticated VMShimClient
/// exchange may promote this receipt into a caller-visible verified boot value.
struct WorkloadStorageBootReceipt: Codable, Sendable {
    let hello: WorkloadStorageProtocol.Frame
    let configured: WorkloadStorageProtocol.Frame?
    let diskIdentities: [VMShimProtocol.FileIdentity]
    let rootExt4UUID: String
    let rootBytes: UInt64
    let initramfsSHA256: String
}

/// One retained private connection per container boot. A dedicated reader notices
/// terminal events and EOF even when no daemon is attached or command is pending.
/// No reader callback performs FUSE teardown or claims a registry drain receipt.
final class PrivateWorkloadStorageCoordinator: @unchecked Sendable {
    typealias Wire = WorkloadStorageProtocol
    // Only this closed local vocabulary may leave the private channel.
    enum Stage: String, Sendable {
        case validateHeldDisks = "validate-held-disks", connectInit = "connect-init"
        case helloGuard = "hello-guard", receiptGuard = "receipt-guard"
        case configureGuard = "configure-guard", configureEncode = "configure-encode"
        case writeConfigure = "write-configure", commandGuard = "command-guard"
        case commandPhase = "command-phase", commandEncode = "command-encode", writeCommand = "write-command"
        case readFrame = "read-frame", readLength = "read-length", readEOF = "read-eof", readDecode = "read-decode"
        case readBinding = "read-binding", readExpectation = "read-expectation"
        case terminalBinding = "terminal-binding", guestTerminal = "guest-terminal", replyValidate = "reply-validate"
        case shimResponseDecode = "shim-response-decode", shimResponseBinding = "shim-response-binding"
        case statusGuard = "status-guard", statusDeadline = "status-deadline"
    }
    // Internal synchronization seam: no payload or authority crosses this hook.
    enum DiagnosticBoundary: Sendable { case readerCancellationPublished, writerObservedCancellation }
    private struct Diagnostic: Error {
        let stage: Stage
        var guestCode: Wire.Code? = nil
    }
    private struct Expected {
        let operation: Wire.Operation
        let sequence: UInt64?
        let kind: Wire.Kind?
    }

    private let verified: RawDiskBootTransaction.VerifiedContainerBoot
    private let descriptor: Int32
    private let closeConnection: @Sendable () -> Void
    private let onTerminal: @Sendable () -> Void
    private let diagnosticHook: @Sendable (DiagnosticBoundary) -> Void
    private let serial = NSLock()
    private let condition = NSCondition()
    private let cancelled = Mutex(false)
    private let callerCancelled = Mutex(false)
    private let readerFinished = DispatchGroup()
    // All following fields are protected by condition, including read-only snapshots.
    private var readerStarted = false
    private var closed = false
    private var terminal = false
    private var terminalDiagnostic: Diagnostic?
    private var helloFrame: Wire.Frame?
    private var configuredFrame: Wire.Frame?
    private var configurationAttempted = false
    private var scope: Wire.Scope?
    private var slots: [Wire.Slot] = []
    private var mounts: [Wire.MountBinding] = []
    private let compatibilityProfile: String?
    private var compatibilityOffers: [String: Wire.Offer] = [:]
    private var compatibilityCredentials: [ManagedPrepareCompatibilityProtocol.Credential] = []
    private var compatibilityArm: ManagedPrepareCompatibilityProtocol.Arm?
    private var compatibilityAttempted = false
    private var compatibilityCheckpoint: Wire.Frame?
    let prepareObserver = PrivatePrepareObservation()
    private var phase: Wire.Phase = .configured
    private var offeredRole: Wire.Role?
    private var installed = Set<String>()
    private var preparedSuccessfully = false
    private var prepareClosedCleanly = false
    private var expected: Expected? = .init(operation: .hello, sequence: nil, kind: nil)
    private var response: Wire.Frame?
    private var sequence: UInt64 = 0
    private var terminalEvents: [Wire.Frame] = []

    var binding: Wire.BootBinding {
        .init(shimLaunchUUID: verified.shimLaunchUUID, guestBootNonce: verified.guestBootNonce)
    }

    init(verified: RawDiskBootTransaction.VerifiedContainerBoot, descriptor: Int32,
         compatibilityProfile: String? = nil,
         closeConnection: @escaping @Sendable () -> Void = {},
         onTerminal: @escaping @Sendable () -> Void = {},
         diagnosticHook: @escaping @Sendable (DiagnosticBoundary) -> Void = { _ in }) throws {
        do { _ = try verified.validateHeldDisks() }
        catch { throw Self.failure(stage: .validateHeldDisks) }
        let owned = fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
        guard owned >= 0 else { throw Self.failure(stage: .connectInit) }
        // Darwin's MSG_DONTWAIT alone can still block a stream send. The private
        // connection is exclusively driven here; poll must own every IO wait.
        let flags = fcntl(owned, F_GETFL)
        guard flags >= 0, fcntl(owned, F_SETFL, flags | O_NONBLOCK) == 0 else {
            Darwin.close(owned)
            throw Self.failure(stage: .connectInit)
        }
        var enabled: Int32 = 1
        guard setsockopt(owned, SOL_SOCKET, SO_NOSIGPIPE, &enabled,
                         socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            Darwin.close(owned)
            throw Self.failure(stage: .connectInit)
        }
        self.compatibilityProfile = compatibilityProfile
        self.verified = verified; self.descriptor = owned
        self.closeConnection = closeConnection; self.onTerminal = onTerminal
        self.diagnosticHook = diagnosticHook
    }

    deinit { close() }

    static func failure(stage: Stage? = nil, kind: Wire.Kind? = nil, role: Wire.Role? = nil,
                        guestCode: Wire.Code? = nil) -> EngineError {
        var diagnostic = ""
        if let stage {
            diagnostic = " [phase=\(stage.rawValue)"
            if let kind { diagnostic += " operation=\(kind.rawValue)" }
            if let role { diagnostic += " role=\(role.rawValue)" }
            if let guestCode { diagnostic += " guest-code=\(guestCode.rawValue)" }
            diagnostic += "]"
        }
        return EngineError(.conflict, "private workload storage channel refused; preserve generation evidence\(diagnostic)")
    }

    /// Authenticate the shim first, then reconstruct only closed enum values.
    /// The exact round-trip rejects extra fields, text, reordered fields and wrappers.
    static func forwardedFailure(_ remote: GuestProtocol.Failure) -> EngineError {
        guard remote.code == "shim_error" else { return failure() }
        let base = failure(), nsError = base as NSError
        let prefix = base.message + " [", suffix = "] [\(nsError.domain) \(nsError.code)]"
        let bootError = EngineError(.internalError, "") as NSError
        let bootPrefix = "boot step 'start virtual machine' failed: "
        let bootSuffix = " [\(bootError.domain) \(bootError.code)]"
        let isBootWrapped = remote.message.hasPrefix(bootPrefix) && remote.message.hasSuffix(bootSuffix)
        let message = isBootWrapped
            ? String(remote.message.dropFirst(bootPrefix.count).dropLast(bootSuffix.count)) : remote.message
        guard message.hasPrefix(prefix), message.hasSuffix(suffix) else { return base }
        let fields = message.dropFirst(prefix.count).dropLast(suffix.count).split(separator: " ")
        var values: [String: String] = [:]
        for field in fields {
            let pair = field.split(separator: "=", omittingEmptySubsequences: false)
            guard pair.count == 2, values.updateValue(String(pair[1]), forKey: String(pair[0])) == nil else { return base }
        }
        guard let stage = values["phase"].flatMap(Stage.init(rawValue:)) else { return base }
        let local = failure(stage: stage, kind: values["operation"].flatMap(Wire.Kind.init(rawValue:)),
            role: values["role"].flatMap(Wire.Role.init(rawValue:)),
            guestCode: values["guest-code"].flatMap(Wire.Code.init(rawValue:)))
        let wrapped = "\(local.message) [\(nsError.domain) \(nsError.code)]"
        guard remote.message == (isBootWrapped ? bootPrefix + wrapped + bootSuffix : wrapped),
              values["guest-code"] == nil || stage == .guestTerminal else { return base }
        return local
    }

    var isTerminal: Bool { condition.withLock { terminal } }
    var permitsRootPreparation: Bool {
        condition.withLock { !terminal && !configurationAttempted && helloFrame != nil }
    }

    func hello() throws -> WorkloadStorageBootReceipt {
        try serial.withLock {
            try condition.withLock {
                guard !readerStarted, !terminal, !closed else { throw Self.failure(stage: .helloGuard) }
                readerStarted = true
                readerFinished.enter()
                Thread.detachNewThread { [self] in
                    defer { readerFinished.leave() }
                    readLoop()
                }
            }
            do {
                let hello = try awaitResponse()
                guard hello.data.compatibilityProfile == compatibilityProfile else { throw Self.failure(stage: .helloGuard) }
                condition.withLock { helloFrame = hello }
                return try currentReceipt()
            } catch { fail(); throw sanitized(error, stage: .readFrame) }
        }
    }

    func currentReceipt() throws -> WorkloadStorageBootReceipt {
        let frames = try condition.withLock {
            guard !terminal, !closed, let helloFrame else { throw Self.failure(stage: .receiptGuard) }
            return (helloFrame, configuredFrame)
        }
        return WorkloadStorageBootReceipt(hello: frames.0, configured: frames.1,
            diskIdentities: try verified.validateHeldDisks(), rootExt4UUID: verified.rootExt4UUID,
            rootBytes: verified.rootBytes, initramfsSHA256: verified.initramfsSHA256)
    }

    func configure(_ configuration: WorkloadStorageConfiguration) throws -> WorkloadStorageBootReceipt {
        try serial.withLock {
            let frame = configuration.frame(binding: binding)
            let encoded: Data
            do { encoded = try Wire.encode(frame) }
            catch { throw Self.failure(stage: .configureEncode) }
            guard configuration.scope.container == verified.containerID else { throw Self.failure(stage: .configureGuard) }
            try condition.withLock {
                guard !terminal, !configurationAttempted, helloFrame != nil,
                      expected == nil, response == nil else { throw Self.failure(stage: .configureGuard) }
                configurationAttempted = true // Never reopen after a partial send or lost reply.
                scope = configuration.scope
                slots = configuration.slots
                mounts = configuration.mounts
                expected = .init(operation: .configured, sequence: nil, kind: nil)
            }
            var stage = Stage.validateHeldDisks
            do {
                _ = try verified.validateHeldDisks()
                stage = .writeConfigure
                try write(encoded)
                stage = .readFrame
                let configured = try awaitResponse()
                condition.withLock { configuredFrame = configured }
                return try currentReceipt()
            } catch { fail(); throw sanitized(error, stage: stage) }
        }
    }

    /// One bounded observation of the retained C1 session; never a new hello,
    /// configure, or boot. The watchdog starts BEFORE serial acquisition so a
    /// pending command cannot leave recovery work running after socket expiry.
    func observeRunningWorkloadStorage(expectedScope: Wire.Scope, deadlineNanoseconds: UInt64) throws -> Wire.Frame {
        func validateScope() throws {
            try condition.withLock {
                guard !terminal, !closed, phase == .running,
                      let configuredFrame, configuredFrame.binding == binding,
                      configuredFrame.scope == expectedScope, scope == expectedScope else {
                    throw Self.failure(stage: .statusGuard, kind: .status)
                }
            }
        }
        // Bad callers cannot cancel a different scope's pending command.
        try validateScope()
        let now = DispatchTime.now().uptimeNanoseconds
        let deadline = min(deadlineNanoseconds, now + VMShimManagedTransport.maximumNanoseconds)
        let completed = DispatchSemaphore(value: 0), watchdogFinished = DispatchGroup()
        watchdogFinished.enter()
        Thread.detachNewThread { [self] in
            defer { watchdogFinished.leave() }
            if completed.wait(timeout: DispatchTime(uptimeNanoseconds: deadline)) == .timedOut {
                fail(diagnostic: .init(stage: .statusDeadline))
            }
        }
        let result = Result {
            try serial.withLock {
                try checkStatusDeadline(deadline)
                try validateScope()
                let command = Wire.Frame(operation: .command, binding: binding, scope: expectedScope,
                    sequence: 1, kind: .status)
                let reply = try commandLocked(command)
                try condition.withLock {
                    guard reply.data.code == nil, reply.data.phase == .running,
                          let mounted = reply.data.mountedIDs, Set(mounted) == slotIDs(.runtime),
                          reply.data.terminalIDs == [] else {
                        throw Self.failure(stage: .statusGuard, kind: .status)
                    }
                }
                // Recheck the held descriptors after the guest observation too.
                do { _ = try verified.validateHeldDisks() }
                catch { fail(); throw Self.failure(stage: .validateHeldDisks, kind: .status) }
                return reply
            }
        }
        completed.signal()
        watchdogFinished.wait()
        try checkStatusDeadline(deadline)
        let reply = try result.get()
        try validateScope()
        return reply
    }

    private func checkStatusDeadline(_ deadline: UInt64) throws {
        guard DispatchTime.now().uptimeNanoseconds < deadline else {
            fail(diagnostic: .init(stage: .statusDeadline))
            throw Self.failure(stage: .statusDeadline, kind: .status)
        }
    }

    /// Independent condition wait: never serial, never a cancellation handler.
    /// Failed observation cannot cancel or release the pending PREPARE owner.
    /// Normal may already be prepared when this independent caller is scheduled;
    /// return the retained event, never admit a late first event after its reply.
    func prepareObservation(_ arm: ManagedPrepareCompatibilityProtocol.Arm) throws -> Wire.Frame {
        try prepareObserver.observe(arm)
    }

    func command(_ requested: Wire.Frame) throws -> Wire.Frame {
        do { return try serial.withLock { try commandLocked(requested) } }
        catch {
            if requested.kind == .prepareCompatibilityArm { fail() }
            throw error
        }
    }

    /// Caller owns serial for the entire request/reply, including phase checks.
    private func commandLocked(_ requested: Wire.Frame) throws -> Wire.Frame {
        var command = requested
        try condition.withLock {
            if terminal, let diagnostic = terminalDiagnostic {
                throw Self.failure(stage: diagnostic.stage, kind: requested.kind, role: requested.data.role,
                    guestCode: diagnostic.guestCode)
            }
            guard !terminal, configuredFrame != nil, requested.operation == .command,
                  requested.binding == binding, requested.scope == scope,
                  let kind = requested.kind, expected == nil, response == nil,
                  sequence < UInt64.max else {
                throw Self.failure(stage: .commandGuard, kind: requested.kind, role: requested.data.role)
            }
            do { try validateCommandLocked(requested) }
            catch {
                throw Self.failure(stage: .commandPhase, kind: requested.kind, role: requested.data.role)
            }
            sequence += 1
            command.sequence = sequence // Daemon-supplied sequences never own the private channel.
            expected = .init(operation: .reply, sequence: sequence, kind: kind)
        }
        var stage = Stage.validateHeldDisks
        do {
            _ = try verified.validateHeldDisks()
            stage = .commandEncode
            let encoded = try Wire.encode(command)
            stage = .writeCommand
            // A1 is after real mounted-phase checks, sequence assignment, disk
            // validation and encoding, but before the first PREPARE frame byte.
            let cut = try condition.withLock { () throws -> Bool in
                guard !terminal else { throw Self.failure() }
                guard command.kind == .prepare, let arm = compatibilityArm,
                      [ManagedPrepareCompatibilityProtocol.earlyProfile, ManagedPrepareCompatibilityProtocol.fullProfile].contains(arm.profile),
                      arm.caseName == "before-prepare-send" else { return false }
                guard phase == .prepareMounted, compatibilityCheckpoint == nil,
                      let requestSequence = command.sequence else { throw Self.failure() }
                let observation = ManagedPrepareCompatibilityProtocol.EarlyObservation(version: arm.version,
                    profile: arm.profile, requestID: arm.requestID,
                    armDigest: try ManagedPrepareCompatibilityProtocol.digest(arm), stage: arm.caseName,
                    count: 1, targetAttachment: arm.targetAttachment, requestSequence: requestSequence,
                    prepareCommandsSent: 0, prepareCommandsAccepted: 0, dataBytesWritten: 0)
                let frame = Wire.Frame(operation: .prepareEarlyCheckpoint, binding: binding, scope: scope,
                    data: .init(compatibilityEarlyObservation: observation))
                try ManagedPrepareCompatibilityProtocol.validateObservation(frame, arm: arm)
                try prepareObserver.publish(frame)
                compatibilityCheckpoint = frame
                return true
            }
            if cut {
                // Independent evidence is visible before EOF/terminal; no observer
                // claim or queue publication is required to release this channel.
                _ = Darwin.shutdown(descriptor, SHUT_RDWR)
                throw Self.failure()
            }
            try write(encoded)
            stage = .readFrame
            let reply = try awaitResponse()
            stage = .replyValidate
            try condition.withLock { try applyReplyLocked(reply, command: command) }
            return reply
        } catch {
            fail()
            throw sanitized(error, stage: stage, kind: command.kind, role: command.data.role)
        }
    }

    /// Positive installed-runtime identity, checked under the session's owner lock.
    /// PREPARE identity is deliberately ineligible for this observation lease.
    func validateOriginalConsumer(_ binding: OriginalConsumerObservationProtocol.Binding) throws {
        try condition.withLock {
            try OriginalConsumerObservationProtocol.validate(binding)
            guard !terminal, !closed, compatibilityProfile == ManagedPrepareCompatibilityProtocol.fullProfile,
                  binding.boot == self.binding, binding.scope == scope,
                  [.runtimeMounted, .running].contains(phase), offeredRole == .runtime,
                  installed.contains(binding.targetAttachment),
                  slots.contains(where: { $0.attachment == binding.targetAttachment && $0.role == .runtime }),
                  compatibilityCredentials.contains(.init(attachment: binding.targetAttachment,
                      key: binding.key, certificateSHA256: binding.certificateSHA256)) else { throw Self.failure() }
        }
    }

    private func slotIDs(_ role: Wire.Role) -> Set<String> {
        Set(slots.filter { $0.role == role }.map(\.attachment))
    }

    private func validateCommandLocked(_ command: Wire.Frame) throws {
        switch command.kind {
        case .prepareCompatibilityArm:
            guard let compatibilityProfile,
                  let version = ManagedPrepareCompatibilityProtocol.profileVersion(compatibilityProfile), !compatibilityAttempted,
                  phase == .certificatesInstalled, offeredRole == .prepare, installed == slotIDs(.prepare),
                  let arm = command.data.compatibilityArm, let scope else { throw Self.failure() }
            compatibilityAttempted = true
            try ManagedPrepareCompatibilityProtocol.matches(arm, candidate: .init(version: version,
                profile: compatibilityProfile, requestID: arm.requestID, binding: binding, scope: scope,
                mounts: mounts, slots: slots, credentials: compatibilityCredentials))
        case .offerKeys:
            guard (phase == .configured && command.data.role == .prepare)
                || (phase == .prepareClosed && preparedSuccessfully && prepareClosedCleanly
                    && command.data.role == .runtime) else { throw Self.failure() }
        case .installCertificate:
            guard phase == .keysOffered || phase == .certificatesInstalled,
                  let role = offeredRole, let attachment = command.data.attachment,
                  slotIDs(role).contains(attachment), !installed.contains(attachment) else { throw Self.failure() }
        case .mountPhase:
            guard let role = offeredRole, command.data.role == role,
                  phase == .certificatesInstalled, installed == slotIDs(role) else { throw Self.failure() }
        case .prepare:
            guard phase == .prepareMounted else { throw Self.failure() }
        case .closePhase:
            guard (command.data.role == .prepare && [.prepareMounted, .prepared].contains(phase))
                || (command.data.role == .runtime && [.runtimeMounted, .running].contains(phase)) else { throw Self.failure() }
        case .start:
            guard phase == .runtimeMounted, preparedSuccessfully, prepareClosedCleanly else { throw Self.failure() }
        case .status, .abort: break
        case nil: throw Self.failure()
        }
    }

    private func applyReplyLocked(_ reply: Wire.Frame, command: Wire.Frame) throws {
        guard !terminal else { throw Self.failure() }
        if reply.data.code != nil { return }
        let all = Set(slots.map(\.attachment))
        switch command.kind {
        case .prepareCompatibilityArm:
            guard let arm = command.data.compatibilityArm,
                  reply.data.compatibilityDigest == (try ManagedPrepareCompatibilityProtocol.digest(arm)) else { throw Self.failure() }
            compatibilityArm = arm
            try prepareObserver.install(arm)
        case .offerKeys:
            guard let role = command.data.role, let offers = reply.data.offers,
                  Set(offers.map(\.attachment)) == slotIDs(role) else { throw Self.failure() }
            compatibilityOffers = Dictionary(uniqueKeysWithValues: offers.map { ($0.attachment, $0) })
            compatibilityCredentials.removeAll()
            offeredRole = role
            installed.removeAll()
            phase = offers.isEmpty ? .certificatesInstalled : .keysOffered
        case .installCertificate:
            guard let role = offeredRole, let attachment = reply.data.attachment,
                  attachment == command.data.attachment else { throw Self.failure() }
            if role == .prepare || compatibilityProfile == ManagedPrepareCompatibilityProtocol.fullProfile {
                guard let offer = compatibilityOffers[attachment], let der = command.data.certificateDER else { throw Self.failure() }
                compatibilityCredentials.append(.init(attachment: attachment, key: offer.key,
                    certificateSHA256: Wire.specificationDigest(der)))
            }
            installed.insert(attachment)
            if installed == slotIDs(role) { phase = .certificatesInstalled }
        case .mountPhase:
            guard let role = command.data.role, let ids = reply.data.attachmentIDs,
                  Set(ids) == slotIDs(role) else { throw Self.failure() }
            phase = role == .prepare ? .prepareMounted : .runtimeMounted
        case .prepare:
            let succeeded = reply.data.succeeded == true && reply.data.cleanCopyUp == true
            if succeeded, let arm = compatibilityArm {
                // Guest joins the normal checkpoint write before replying. A7
                // cannot report successful PREPARE while its real owner is held.
                guard Self.allowsSuccessfulPrepare(arm, checkpoint: compatibilityCheckpoint) else { throw Self.failure() }
            }
            preparedSuccessfully = succeeded
            phase = .prepared
        case .closePhase:
            guard let role = command.data.role, reply.data.role == role,
                  let ids = reply.data.attachmentIDs, Set(ids) == slotIDs(role) else { throw Self.failure() }
            if role == .prepare {
                prepareClosedCleanly = reply.data.clean == true
                phase = .prepareClosed
            } else { phase = .aborted }
        case .start: phase = .running
        case .status:
            guard let mounted = reply.data.mountedIDs, let ended = reply.data.terminalIDs,
                  Set(mounted).isSubset(of: all), Set(ended).isSubset(of: all) else { throw Self.failure() }
        case .abort:
            guard let ended = reply.data.terminalIDs, Set(ended).isSubset(of: all) else { throw Self.failure() }
            phase = .aborted
        case nil: throw Self.failure()
        }
    }

    /// Retirement IO must reach the real authority retirement operation. No other
    /// IO cut may turn a successful PREPARE into permission to activate runtime.
    static func allowsSuccessfulPrepare(_ arm: ManagedPrepareCompatibilityProtocol.Arm,
        checkpoint: Wire.Frame?) -> Bool {
        ManagedPrepareCompatibilityProtocol.allowsIORetirePrepare(arm)
            || (ManagedPrepareCompatibilityProtocol.allowsPrepareSuccess(arm) && checkpoint != nil)
    }

    func events() -> [Wire.Frame] { condition.withLock { terminalEvents } }

    /// Wakes pending commands without waiting for guest filesystem work.
    func cancel() {
        callerCancelled.withLock { $0 = true }
        fail()
    }

    func close() {
        callerCancelled.withLock { $0 = true }
        fail(notify: false)
        serial.withLock {
            let shouldClose = condition.withLock {
                if closed { return false }
                closed = true
                return true
            }
            guard shouldClose else { return }
            _ = Darwin.shutdown(descriptor, SHUT_RDWR)
            readerFinished.wait()
            Darwin.close(descriptor)
            closeConnection()
        }
    }

    private func sanitized(_ error: any Error, stage: Stage, kind: Wire.Kind? = nil, role: Wire.Role? = nil) -> any Error {
        // A reader failure interrupts writes and schedules cleanup. Preserve its
        // first closed cause rather than misclassifying that interruption as caller cancellation.
        let diagnostic = (error as? Diagnostic) ?? condition.withLock { terminalDiagnostic }
        if diagnostic == nil, error is CancellationError { return error }
        return Self.failure(stage: diagnostic?.stage ?? stage, kind: kind, role: role, guestCode: diagnostic?.guestCode)
    }

    private func fail(notify: Bool = true, diagnostic: Diagnostic? = nil) {
        let first = condition.withLock {
            let first = !terminal
            if first { terminalDiagnostic = diagnostic }
            terminal = true
            prepareObserver.finish()
            response = nil
            // Publish the cause before interrupting a partial writer. Otherwise
            // its cancellation catch could commit a nil cause ahead of this reader.
            cancelled.withLock { $0 = true }
            if first, diagnostic != nil { diagnosticHook(.readerCancellationPublished) }
            condition.broadcast()
            return first
        }
        if first && notify { onTerminal() }
    }

    private func awaitResponse() throws -> Wire.Frame {
        condition.lock()
        defer { condition.unlock() }
        while response == nil && !terminal { condition.wait() }
        guard !terminal, let result = response else {
            if let terminalDiagnostic { throw terminalDiagnostic }
            if callerCancelled.withLock({ $0 }) { throw CancellationError() }
            throw Diagnostic(stage: .readFrame)
        }
        response = nil
        return result
    }

    private func readLoop() {
        var stage = Stage.readFrame
        do {
            while true {
                stage = .readFrame
                let body = try readFrame()
                stage = .readDecode
                let frame = try Wire.decode(from: body)
                stage = .readBinding
                guard frame.binding == binding else { throw Self.failure() }
                let isEvent = try condition.withLock {
                    guard !terminal else { throw CancellationError() }
                    if frame.operation == .prepareCheckpoint || frame.operation == .prepareEarlyCheckpoint {
                        guard let arm = compatibilityArm, frame.scope == scope,
                              compatibilityCheckpoint == nil, phase == .prepareMounted,
                              expected?.operation == .reply, expected?.kind == .prepare, response == nil else { throw Self.failure() }
                        // Authenticate IO evidence at this private receive boundary.
                        if let observation = frame.data.compatibilityIOObservation {
                            try ManagedPrepareCompatibilityProtocol.validate(observation, arm: arm)
                        }
                        try ManagedPrepareCompatibilityProtocol.validateObservation(frame, arm: arm)
                        if let observation = frame.data.compatibilityEarlyObservation {
                            // A1 is host-local only. A2 is this private PREPARE;
                            // A3 names the guest's independently assigned DATA sequence.
                            guard ["guest-accepted-before-prepare", "data-partial-frame"].contains(arm.caseName),
                                  arm.caseName != "guest-accepted-before-prepare" || observation.requestSequence == expected?.sequence else { throw Self.failure() }
                        }
                        try prepareObserver.publish(frame)
                        compatibilityCheckpoint = frame
                        condition.broadcast()
                        return false
                    }
                    if frame.operation == .terminal {
                        stage = .terminalBinding
                        guard let scope, frame.scope == scope, let ids = frame.data.attachmentIDs,
                              Set(ids).isSubset(of: Set(slots.map(\.attachment))),
                              terminalEvents.count < Wire.maximumEvents else { throw Self.failure() }
                        terminalEvents.append(frame)
                        return true
                    }
                    stage = .readExpectation
                    guard let expected, frame.operation == expected.operation,
                          frame.sequence == expected.sequence, frame.kind == expected.kind,
                          frame.scope == (expected.operation == .hello ? nil : scope),
                          response == nil else { throw Self.failure() }
                    self.expected = nil
                    response = frame
                    condition.broadcast()
                    return false
                }
                if isEvent { fail(diagnostic: .init(stage: .guestTerminal, guestCode: frame.data.code)); return }
            }
        } catch { fail(diagnostic: (error as? Diagnostic) ?? .init(stage: stage)) }
    }

    private func wait(_ events: Int16) throws {
        while true {
            if cancelled.withLock({ $0 }) {
                if events == Int16(POLLOUT) { diagnosticHook(.writerObservedCancellation) }
                throw CancellationError()
            }
            var item = pollfd(fd: descriptor, events: events, revents: 0)
            let result = Darwin.poll(&item, 1, 100)
            if result < 0 && errno == EINTR { continue }
            guard result >= 0 else { throw Self.failure() }
            if result == 0 { continue }
            guard item.revents & events != 0 else { throw Self.failure() }
            return
        }
    }

    private func readExactly(_ count: Int) throws -> Data {
        var data = Data(count: count), offset = 0
        while offset < count {
            try wait(Int16(POLLIN))
            let amount = data.withUnsafeMutableBytes {
                Darwin.recv(descriptor, $0.baseAddress!.advanced(by: offset), count - offset, MSG_DONTWAIT)
            }
            if amount < 0 && [EINTR, EAGAIN].contains(errno) { continue }
            guard amount > 0 else { throw Diagnostic(stage: amount == 0 ? .readEOF : .readFrame) }
            offset += amount
        }
        return data
    }

    private func readFrame() throws -> Data {
        let prefix = try readExactly(4)
        let count: Int
        do { count = try Wire.frameBodyLength(from: prefix) }
        catch { throw Diagnostic(stage: .readLength) }
        return try readExactly(count)
    }

    private func write(_ data: Data) throws {
        var offset = 0
        while offset < data.count {
            try wait(Int16(POLLOUT))
            let amount = data.withUnsafeBytes {
                Darwin.send(descriptor, $0.baseAddress!.advanced(by: offset), data.count - offset, MSG_DONTWAIT)
            }
            if amount < 0 && [EINTR, EAGAIN].contains(errno) { continue }
            guard amount > 0 else { throw Self.failure() }
            offset += amount
        }
    }
}

/// Evidence-only lifetime, independent of serial commands, VM leases and channel
/// close. Retaining this object cannot keep a VM or its disk authority alive.
final class PrivatePrepareObservation: @unchecked Sendable {
    private let condition = NSCondition()
    private var arm: ManagedPrepareCompatibilityProtocol.Arm?
    private var frame: WorkloadStorageProtocol.Frame?
    private var ended = false
    private var claimed = false

    func install(_ arm: ManagedPrepareCompatibilityProtocol.Arm) throws {
        try condition.withLock {
            guard self.arm == nil, !ended else { throw PrivateWorkloadStorageCoordinator.failure() }
            self.arm = arm
        }
    }
    func publish(_ frame: WorkloadStorageProtocol.Frame) throws {
        try condition.withLock {
            guard let arm, self.frame == nil, !ended else { throw PrivateWorkloadStorageCoordinator.failure() }
            // Retained/test-shim publication is a separate receive boundary.
            if let observation = frame.data.compatibilityIOObservation {
                try ManagedPrepareCompatibilityProtocol.validate(observation, arm: arm)
            }
            try ManagedPrepareCompatibilityProtocol.validateObservation(frame, arm: arm)
            self.frame = frame
            condition.broadcast()
        }
    }
    /// Evidence-only exception to the shim's terminal admission fence. Keep it
    /// after a claim too: the server checks admission again after awaiting the
    /// observation. This never permits commands, physical success, or a first
    /// publication after terminal; observe still validates the exact arm/claim.
    func permitsTerminalOperation(_ operation: VMShimProtocol.Operation) -> Bool {
        condition.withLock {
            operation == .workloadStoragePrepareObservation
                && (frame?.operation == .prepareEarlyCheckpoint
                    || frame?.data.compatibilityIOObservation != nil)
        }
    }

    func finish() { condition.withLock { ended = true; condition.broadcast() } }
    func observe(_ arm: ManagedPrepareCompatibilityProtocol.Arm) throws -> WorkloadStorageProtocol.Frame {
        condition.lock()
        defer { condition.unlock() }
        // Only already-published early/IO evidence survives terminal admission.
        // This exception never admits physical success or a late first event.
        guard self.arm == arm, !claimed,
              !ended || frame?.operation == .prepareEarlyCheckpoint
                  || frame?.data.compatibilityIOObservation != nil else { throw PrivateWorkloadStorageCoordinator.failure() }
        claimed = true
        while frame == nil && !ended { condition.wait() }
        guard let frame else { throw PrivateWorkloadStorageCoordinator.failure() }
        return frame
    }
    func observation(_ arm: ManagedPrepareCompatibilityProtocol.Arm) async throws -> WorkloadStorageProtocol.Frame {
        try await withCheckedThrowingContinuation { continuation in
            Thread.detachNewThread { [self] in
                do { continuation.resume(returning: try observe(arm)) }
                catch { continuation.resume(throwing: error) }
            }
        }
    }
}
#endif

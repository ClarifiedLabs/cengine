#if os(macOS)
import CEngineCore
import CryptoKit
import Darwin
import Foundation
import Security
import Synchronization

/// Coordinates private service boot over the storage VM's connected stream.
/// A file descriptor is not proof of VM origin: the shim must also supply the
/// verified disk boot capability.
final class PrivateStorageLifecycleBootCoordinator: @unchecked Sendable {
    typealias Wire = StorageLifecycleServiceBootProtocol
    typealias L = StorageLifecycleProtocol
    enum HandoffFailure: Error { case busy }
    /// Current service generation. Only bootstrap and a validated replacement
    /// `succeeded` mint it; reconcile-controller may advance only its signed grant.
    fileprivate struct Current: Sendable {
        var ready: Wire.Ready
        var configuration: Wire.Configuration
        var signed: L.SignedGrant
    }
    final class VerifiedBoot: Sendable {
        let binding: Wire.Binding
        let ready: Wire.Ready
        let rootPublicKey: StorageIdentity.RootPublicKey
        let configuration: Wire.Configuration
        /// Current ROOT-signed controller grant (advanced only by validated reconcile).
        let signed: L.SignedGrant
        var identity: L.Identity { ready.identity }
        var initramfsSHA256: String { owner.verified.initramfsSHA256 }
        func validateHeldDisk() throws -> VMShimProtocol.FileIdentity {
            _ = try owner.currentBoot()
            return try owner.verified.validateHeldDisk()
        }
        func duplicateHeldDisk() throws -> FileHandle {
            _ = try owner.currentBoot()
            return try owner.verified.duplicateHeldDisk()
        }
        /// Fresh query on this capability's SAME private coordinator.
        func adoptedServiceProof(_ challenge: StorageLifecycleAdoptionProtocol.ServiceChallenge,
                                 deadline: TimeInterval) throws -> StorageLifecycleAdoptionProtocol.ServiceReply {
            let observed = try freshServiceObservation(for: challenge.expected.grant, nonce: challenge.nonce, deadline: deadline)
            return try .init(challenge: challenge, result: observed.0, boot: observed.1)
        }
        /// Uses the original, nonserializable boot capability and its SAME private
        /// channel; ROOT's handoff signature is not an ordinary signed grant.
        func handoffProof(_ challenge: StorageLifecycleHandoffShimProtocol.Challenge,
                          deadline: TimeInterval) throws -> StorageLifecycleHandoffShimProtocol.Reply {
            try challenge.validate()
            guard challenge.origin.shimLaunchUUID == binding.shimLaunchUUID,
                  challenge.origin.specSHA256 == owner.verified.specificationSHA256,
                  challenge.origin.rootPublicKey == rootPublicKey.publicData,
                  challenge.expected.grant.identity == identity else { throw failure() }
            _ = try validateHeldDisk()
            let current = try owner.currentBoot()
            let request = Wire.Frame(operation: .command, binding: binding, sequence: 1,
                serviceEpoch: challenge.signed.request.serviceEpoch, command: .fenceHandoff,
                workerUUID: current.ready.workerUUID, handoff: challenge.signed, nonce: challenge.nonce)
            for attempt in 0..<8 {
                guard ProcessInfo.processInfo.systemUptime < deadline,
                      challenge.isFresh(at: UInt64(Date().timeIntervalSince1970 * 1000)) else { throw HandoffFailure.busy }
                let reply = try owner.command(request, deadline: deadline, adoptedServiceChange: nil, handoffChallenge: challenge)
                if reply.code == .workerBusy {
                    if attempt == 7 { throw HandoffFailure.busy }
                    usleep(25_000)
                    continue
                }
                guard reply.code == nil, let result = reply.handoffResult else { throw failure() }
                _ = try validateHeldDisk()
                guard ProcessInfo.processInfo.systemUptime < deadline,
                      challenge.isFresh(at: UInt64(Date().timeIntervalSince1970 * 1000)) else { throw HandoffFailure.busy }
                return try .init(challenge: challenge, result: result.result,
                    boot: PrivateStorageLifecycleBootCoordinator.trust(result.ready))
            }
            throw HandoffFailure.busy
        }
        /// Recovery proof for the actual completed native replacement, not a
        /// host-supplied reopen or an arbitrary current Ready projection.
        func adoptedServiceChangeProof(_ challenge: StorageLifecycleAdoptionProtocol.ServiceChangeChallenge,
                                       deadline: TimeInterval) throws -> StorageLifecycleAdoptionProtocol.ServiceChangeReply {
            try challenge.validate()
            let current = try owner.currentBoot()
            guard current.binding == binding, current.identity == identity else { throw failure() }
            let reply = try owner.command(.init(operation: .command, binding: binding, sequence: 1,
                serviceEpoch: current.ready.serviceEpoch, command: .query, workerUUID: current.ready.workerUUID),
                deadline: deadline, adoptedServiceChange: challenge)
            guard let ready = reply.ready else { throw failure() }
            _ = try validateHeldDisk()
            let result = try L.ServiceResult(identity: ready.identity, grant: challenge.change.predecessor.grant,
                nonce: challenge.nonce, serviceEpoch: ready.serviceEpoch, controllerEpoch: ready.controllerEpoch,
                controllerKey: ready.controllerKey, openRevision: ready.openRevision)
            return try .init(challenge: challenge, result: result,
                boot: PrivateStorageLifecycleBootCoordinator.trust(ready))
        }
        func freshServiceObservation(for grant: L.Grant, nonce: Data, deadline: TimeInterval) throws
            -> (L.ServiceResult, StorageLifecycleBootTrust) {
            try grant.validate()
            guard grant.identity == identity, nonce.count == 32 else { throw failure() }
            let current = try owner.currentBoot()
            guard current.binding == binding, current.identity == identity else { throw failure() }
            _ = try validateHeldDisk()
            let reply = try owner.command(.init(operation: .command, binding: binding, sequence: 1,
                serviceEpoch: current.ready.serviceEpoch, command: .query, workerUUID: current.ready.workerUUID), deadline: deadline)
            guard let ready = reply.ready else { throw failure() }
            _ = try validateHeldDisk()
            let result = try L.ServiceResult(identity: ready.identity, grant: grant,
                nonce: nonce, serviceEpoch: ready.serviceEpoch, controllerEpoch: ready.controllerEpoch,
                controllerKey: ready.controllerKey, openRevision: ready.openRevision)
            return try (result, PrivateStorageLifecycleBootCoordinator.trust(ready))
        }
        private let owner: PrivateStorageLifecycleBootCoordinator
        fileprivate init(owner: PrivateStorageLifecycleBootCoordinator, current: Current) throws {
            self.owner = owner; self.binding = owner.verified.binding; self.ready = current.ready
            self.configuration = current.configuration; self.signed = current.signed
            self.rootPublicKey = try .init(publicData: configuration.rootPublicKey)
        }
        /// Only a completed live exchange yields this capability. The returned DTO
        /// remains value-only; neither Codable nor Ready can mint VerifiedBoot.
        func trust(for grant: L.Grant) throws -> StorageLifecycleBootTrust {
            try grant.validate()
            let current = try owner.currentBoot()
            guard current.identity == identity, grant.identity == identity,
                  current.ready.serviceEpoch == ready.serviceEpoch else { throw failure() }
            return try PrivateStorageLifecycleBootCoordinator.trust(ready)
        }
    }
    fileprivate static func trust(_ ready: Wire.Ready) throws -> StorageLifecycleBootTrust {
        try StorageLifecycleBootTrust(identity: ready.identity, serviceEpoch: ready.serviceEpoch,
            tlsRootSHA256: digest(ready.tlsRootDER), serverSPKI: ready.serverSPKI, bootstrapKey: ready.bootstrapKey)
    }
    private let verified: RawDiskBootTransaction.VerifiedStorageDiskBoot
    private let configuration: Wire.Configuration
    private let descriptor: Int32
    private let closeConnection: @Sendable () -> Void
    private let gate = NSLock()
    private let cancelled = Mutex(false)
    private let state = Mutex<Current?>(nil)
    // Gate-only replacement retry state: one pending, one latest terminal.
    private var pendingReplacement: Wire.ReplacementRequest?
    // Exact ordinary ROOT signature retained before forwarding authorization.
    // A handoff authorizes fencing only and can never replace this signature.
    private var pendingSigned: L.SignedGrant?
    // Gate-only, one fully written fence. Preserve its original sequence/nonce
    // and incremental framing; never turn a stale receipt into a fresh proof.
    private final class OutstandingHandoff {
        let request: Wire.Frame
        let challenge: StorageLifecycleHandoffShimProtocol.Challenge?
        var bytes = Data()
        init(request: Wire.Frame, challenge: StorageLifecycleHandoffShimProtocol.Challenge?) {
            self.request = request; self.challenge = challenge
        }
    }
    private var outstandingHandoff: OutstandingHandoff?
    // A correlated busy consumes the frame, not the authority's possible fence.
    // Keep one exact ROOT-signed tuple until an actual result is fully validated.
    private var logicalHandoff: StorageLifecycleHandoffProtocol.SignedRequest?
    private var terminalReplacement: (request: Wire.ReplacementRequest, reply: Wire.Frame)?
    private var attempted = false
    private var closed = false
    private var sequence: UInt64 = 0

    init(verified: RawDiskBootTransaction.VerifiedStorageDiskBoot, configuration: Wire.Configuration,
         descriptor: Int32, closeConnection: @escaping @Sendable () -> Void = {}) throws {
        try configuration.validate()
        _ = try verified.validateHeldDisk()
        if configuration.action == .initialize { _ = try verified.freshInitialization() }
        try Self.validateColdLaunch(configuration, verified: verified)
        let root = try StorageIdentity.RootPublicKey(publicData: configuration.rootPublicKey)
        guard configuration.signed.isValidSignature(using: root) else { throw Self.failure() }
        let owned = fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
        guard owned >= 0 else { throw Self.failure() }
        var yes: Int32 = 1
        let flags = fcntl(owned, F_GETFL)
        guard flags >= 0, fcntl(owned, F_SETFL, flags | O_NONBLOCK) == 0,
              setsockopt(owned, SOL_SOCKET, SO_NOSIGPIPE, &yes, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            Darwin.close(owned); throw Self.failure()
        }
        self.verified = verified; self.configuration = configuration; self.descriptor = owned; self.closeConnection = closeConnection
    }
    deinit { close() }
    private static func failure() -> EngineError {
        EngineError(.conflict, "private lifecycle bootstrap refused; preserve storage generation evidence")
    }
    private static func digest(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }

    func bootstrap() throws -> VerifiedBoot {
        try gate.withLock {
            guard !closed, !attempted else { throw Self.failure() }; attempted = true
            do {
                try verified.claimLifecycleServiceBoot() // Consume before any disk or stream I/O.
                _ = try verified.validateHeldDisk()
                if configuration.action == .initialize { _ = try verified.freshInitialization() }
                try Self.validateColdLaunch(configuration, verified: verified)
                let io = transport()
                let hello = try read(io)
                guard hello.operation == .hello else { throw Self.failure() }
                #if CENGINE_COMPAT_LIFECYCLE_FAULT
                try StorageLifecycleCompatibilityFaultPolicy.beforeConfigure(action: configuration.action)
                #endif
                try io.write(Wire.encode(.init(operation: .configure, binding: verified.binding, configuration: configuration)))
                let response = try read(io)
                guard response.operation == .ready, let ready = response.ready else { throw Self.failure() }
                let grant = configuration.signed.grant
                let root = try StorageIdentity.RootPublicKey(publicData: configuration.rootPublicKey)
                guard ready.identity == grant.identity, ready.controllerEpoch == grant.expectedEpoch + 1,
                      ready.controllerKey == grant.newKey, ready.bootstrapKey == root.fingerprint.rawValue else { throw Self.failure() }
                try Self.validateCertificates(ready)
                if configuration.action == .open {
                    // Existing store: the ROOT-signed reopen names the predecessor;
                    // this boot must be a fresh E/CA/server key above its anchor.
                    guard let reopen = configuration.reopen,
                          ready.openRevision > reopen.request.predecessor.openRevision else { throw Self.failure() }
                    try reopen.request.validateSuccessorBoot(Self.trust(ready))
                }
                if let cold = configuration.cold {
                    guard ready.serviceEpoch != cold.request.predecessor.serviceEpoch,
                          ready.openRevision > cold.request.predecessor.openRevision else { throw Self.failure() }
                }
                _ = try verified.validateHeldDisk()
                let current = Current(ready: ready, configuration: configuration, signed: configuration.signed)
                return try cancelled.withLock { stopped in
                    guard !stopped else { throw CancellationError() }
                    state.withLock { $0 = current }
                    return try VerifiedBoot(owner: self, current: current)
                }
            } catch { cancel(); terminateLocked(); throw error }
        }
    }
    private static func validateColdLaunch(_ configuration: Wire.Configuration,
                                          verified: RawDiskBootTransaction.VerifiedStorageDiskBoot) throws {
        if configuration.action == .resumeOpenTakeover {
            // Unlike metadata, this check requires the frozen native ROOT claim.
            try verified.validateResumeConfiguration(configuration)
        }
        guard let launch = configuration.cold?.request.launch ?? configuration.resume?.request.launch else { return }
        let binding = verified.binding
        guard launch.shimLaunchUUID == binding.shimLaunchUUID, launch.ext4UUID == binding.ext4UUID,
              launch.bytes == binding.bytes, launch.initramfsSHA256 == verified.initramfsSHA256,
              launch.specSHA256 == verified.specificationSHA256 else { throw failure() }
    }
    func currentBoot() throws -> VerifiedBoot {
        guard !cancelled.withLock({ $0 }), let current = state.withLock({ $0 }) else { throw Self.failure() }
        _ = try verified.validateHeldDisk()
        return try VerifiedBoot(owner: self, current: current)
    }
    func command(_ requested: Wire.Frame, deadline: TimeInterval = ProcessInfo.processInfo.systemUptime + 15) throws -> Wire.Frame {
        try command(requested, deadline: deadline, adoptedServiceChange: nil)
    }
    private func command(_ requested: Wire.Frame, deadline: TimeInterval,
                         adoptedServiceChange: StorageLifecycleAdoptionProtocol.ServiceChangeChallenge?,
                         handoffChallenge: StorageLifecycleHandoffShimProtocol.Challenge? = nil) throws -> Wire.Frame {
        try requested.validate()
        let initial = try currentBoot()
        guard requested.operation == .command, requested.binding == initial.binding,
              let command = requested.command else { throw Self.failure() }
        // Replacement commands address the predecessor pair, which may already be
        // superseded on an exact retry; every other command addresses the current pair.
        let replacement = command == .replaceService || command == .replacementStatus
        if !replacement {
            guard requested.serviceEpoch == initial.ready.serviceEpoch,
                  requested.workerUUID == initial.ready.workerUUID else { throw Self.failure() }
        }
        // The full-profile carriers are evidence, not authority. Their closed
        // validators enforce v3/full; the sealed Guest admits the activated
        // profile, just as on v1. Do not accept a caller-supplied profile switch.
        if let arm = requested.prepareCompatibilityArm?.arm ?? requested.prepareCompatibilityCheckpointExit?.arm {
            guard arm.scope.store == initial.identity.store,
                  arm.scope.serviceEpoch == initial.ready.serviceEpoch else { throw Self.failure() }
        }
        if let arm = requested.consumerObservationArm ?? requested.consumerObservationQuery {
            guard arm.workerScope.storeUUID == initial.identity.store,
                  arm.workerScope.serviceEpoch == initial.ready.serviceEpoch,
                  arm.workerScope.workerUUID == initial.ready.workerUUID else { throw Self.failure() }
        }
        if let signed = requested.signed {
            guard signed.grant.identity == initial.identity, signed.isValidSignature(using: initial.rootPublicKey) else { throw Self.failure() }
        }
        while !gate.try() {
            if cancelled.withLock({ $0 }) { throw CancellationError() }
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw Self.failure() }
            usleep(1_000)
        }
        defer { gate.unlock() }
        guard ProcessInfo.processInfo.systemUptime < deadline else { throw Self.failure() }
        if let logicalHandoff {
            guard command == .fenceHandoff, requested.handoff == logicalHandoff else { throw HandoffFailure.busy }
        }
        if let outstanding = outstandingHandoff {
            guard command == .fenceHandoff else { throw HandoffFailure.busy }
            guard requested.handoff == outstanding.request.handoff,
                  requested.binding == outstanding.request.binding,
                  requested.serviceEpoch == outstanding.request.serviceEpoch,
                  requested.workerUUID == outstanding.request.workerUUID else { throw Self.failure() }
            // A repeated outer challenge cannot mint a fresh proof. Keep the
            // exact outstanding receipt intact for a genuinely new nonce.
            guard requested.nonce != outstanding.request.nonce else { throw HandoffFailure.busy }
        }
        if let adoptedServiceChange {
            // The same gate protects terminal evidence, current configuration and
            // the entire fresh query; replacement/reconcile cannot interleave.
            try validateAdoptedServiceChangeLocked(adoptedServiceChange)
        }
        if command == .fenceHandoff {
            let current = try currentBoot()
            guard pendingReplacement == nil, let handoff = requested.handoff,
                  handoff.isValidSignature(using: current.rootPublicKey),
                  handoff.request.predecessor.identity == current.identity,
                  handoff.request.openRevision == current.ready.openRevision,
                  handoff.request.predecessor == current.signed.grant || handoff.request.pending == current.signed.grant,
                  pendingSigned == nil || pendingSigned?.grant == handoff.request.pending else { throw Self.failure() }
            if let handoffChallenge {
                guard handoffChallenge.signed == handoff, handoffChallenge.nonce == requested.nonce,
                      handoffChallenge.isFresh(at: UInt64(Date().timeIntervalSince1970 * 1000)),
                      try handoffChallenge.expected.boot == Self.trust(current.ready) else { throw Self.failure() }
            }
        }
        if command == .fenceHandoff {
            return try handoffCommandLocked(requested, challenge: handoffChallenge, deadline: deadline)
        }
        if command == .authorizeSuccessor {
            let current = try currentBoot()
            guard pendingReplacement == nil, let signed = requested.signed,
                  signed.grant.expectedEpoch == current.ready.controllerEpoch,
                  pendingSigned == nil || pendingSigned == signed else { throw Self.failure() }
            pendingSigned = signed
        }
        // Local replacement routing performs no stream IO and never consumes a
        // raw disk boot claim.
        if replacement, let local = try routeReplacementLocked(requested) { return local }
        do {
            let current = try currentBoot()
            guard !closed, current.ready.serviceEpoch == requested.serviceEpoch,
                  current.ready.workerUUID == requested.workerUUID, sequence < UInt64.max else { throw Self.failure() }
            sequence += 1
            var request = requested; request.sequence = sequence
            let io = transport(deadline: deadline)
            try io.write(Wire.encode(request))
            let reply = try read(io)
            guard reply.operation == .reply, reply.sequence == sequence, reply.serviceEpoch == request.serviceEpoch,
                  reply.workerUUID == request.workerUUID else { throw Self.failure() }
            _ = try currentBoot()
            let validatedReply = try cancelled.withLock { stopped in
                guard !stopped else { throw CancellationError() }
                if reply.code != nil { return reply }
                switch request.command {
            case .isolationState, .legacyConnection, .secondServiceExclusivity:
                try Self.validateIsolationReply(reply, for: request, current: current.ready)
            case .consumerObservationArm, .consumerObservationQuery, .consumerObservationFinalize:
                try Self.validateConsumerObservationReply(reply, for: request)
            case .prepareCompatibilityArm, .prepareCompatibilityObserve, .prepareCompatibilityRelease,
                 .prepareCompatibilityWorkerExit, .prepareCompatibilityCheckpointExit:
                try Self.validatePrepareReply(reply, for: request)
            case .issueController, .authorizeSuccessor:
                guard let certificate = reply.certificate, let csr = request.csr else { throw Self.failure() }
                let epoch: UInt64
                let key: String
                if request.command == .authorizeSuccessor {
                    guard let grant = request.signed?.grant,
                          grant.expectedEpoch == current.ready.controllerEpoch,
                          grant.expectedEpoch < UInt64.max else { throw Self.failure() }
                    epoch = grant.expectedEpoch + 1; key = grant.newKey
                } else {
                    epoch = current.ready.controllerEpoch; key = current.ready.controllerKey
                }
                try Self.validateControllerCertificate(certificate, csr: csr, ready: current.ready, epoch: epoch, key: key)
            case .authorizeRetirement: guard reply.ok == true else { throw Self.failure() }
            case .fenceHandoff: throw Self.failure() // Dedicated bounded receive path above.
            case .query, .reconcileController:
                guard let r = reply.ready, r.identity == current.identity, r.serviceEpoch == current.ready.serviceEpoch,
                      r.workerUUID == current.ready.workerUUID, r.bootstrapKey == current.ready.bootstrapKey,
                      r.tlsRootDER == current.ready.tlsRootDER, r.serverDER == current.ready.serverDER,
                      r.serverSPKI == current.ready.serverSPKI, r.revision >= current.ready.revision else { throw Self.failure() }
                let expected = request.controller ?? .init(epoch: current.ready.controllerEpoch, key: current.ready.controllerKey)
                guard r.controllerEpoch == expected.epoch, r.controllerKey == expected.key else { throw Self.failure() }
                if let adoptedServiceChange {
                    guard r.openRevision == current.ready.openRevision,
                          adoptedServiceChange.isFresh(at: UInt64(Date().timeIntervalSince1970 * 1000)) else { throw Self.failure() }
                }
                var next = Current(ready: r, configuration: current.configuration, signed: current.signed)
                if request.command == .reconcileController {
                    // The signed grant (signature checked pre-IO) must name exactly
                    // the reconciled controller, like ServiceState's C invariant.
                    guard let signed = request.signed, signed.grant.operation != .retire,
                          signed.grant.expectedEpoch < UInt64.max,
                          signed.grant.expectedEpoch + 1 == r.controllerEpoch,
                          signed.grant.newKey == r.controllerKey else { throw Self.failure() }
                    next.signed = signed
                    pendingSigned = nil
                }
                state.withLock { $0 = next }
            case .serviceStatus: guard reply.status != nil else { throw Self.failure() }
            case .notifications: guard reply.notifications != nil else { throw Self.failure() }
            case .replaceService, .replacementStatus:
                guard let status = reply.replacement,
                      let expected = request.replacementRequest ?? pendingReplacement,
                      status.request == expected else { throw Self.failure() }
                switch status.phase {
                case .pending: pendingReplacement = expected
                case .failed: pendingReplacement = nil; terminalReplacement = (expected, reply)
                case .succeeded:
                    guard let r = status.ready else { throw Self.failure() }
                    let successor = try Self.validateSuccessor(r, request: expected, current: current)
                    pendingReplacement = nil; terminalReplacement = (expected, reply); pendingSigned = nil
                    state.withLock { $0 = successor } // Atomic successor mint.
                }
            case nil: throw Self.failure()
            }
                return reply
            }
            // The Guest counter belongs to this surviving 4106 session, not to
            // any daemon or ROOT query caller. Validate it above, then restore
            // the caller's correlation counter without changing identity pins.
            var correlated = validatedReply
            correlated.sequence = requested.sequence
            return correlated
        } catch {
            // Uncertain framing poisons authority permanently, but closing 4106
            // kills PID1's worker. Retain the session until explicit owner stop.
            cancel(); throw error
        }
    }
    /// Gate held. Only a fully written fence can survive a receive deadline.
    /// Drain the original envelope before assigning a new sequence or nonce.
    private func handoffCommandLocked(_ requested: Wire.Frame,
                                      challenge: StorageLifecycleHandoffShimProtocol.Challenge?,
                                      deadline: TimeInterval) throws -> Wire.Frame {
        do {
            if let outstanding = outstandingHandoff {
                _ = try receiveHandoffLocked(outstanding, deadline: deadline)
            }
            guard ProcessInfo.processInfo.systemUptime < deadline,
                  challenge?.isFresh(at: UInt64(Date().timeIntervalSince1970 * 1000)) != false else {
                throw HandoffFailure.busy
            }
            // Draining can reconcile C/key, but cannot change the fence's
            // identity/E/worker/TLS pins. Re-read current state before sending.
            let current = try currentBoot()
            guard !closed, sequence < UInt64.max,
                  requested.serviceEpoch == current.ready.serviceEpoch,
                  requested.workerUUID == current.ready.workerUUID else { throw Self.failure() }
            sequence += 1
            var request = requested; request.sequence = sequence
            // Freeze before forwarding, independently of the unread-frame state.
            logicalHandoff = request.handoff
            // A write failure has unknown send outcome and is never recoverable.
            try transport(deadline: deadline).write(Wire.encode(request))
            let outstanding = OutstandingHandoff(request: request, challenge: challenge)
            outstandingHandoff = outstanding
            var reply = try receiveHandoffLocked(outstanding, deadline: deadline)
            // Full validation/reconciliation happens even when the caller's proof
            // expired. Only a subsequent fresh private exchange may publish proof.
            guard ProcessInfo.processInfo.systemUptime < deadline,
                  challenge?.isFresh(at: UInt64(Date().timeIntervalSince1970 * 1000)) != false else {
                throw HandoffFailure.busy
            }
            reply.sequence = requested.sequence
            return reply
        } catch HandoffFailure.busy {
            throw HandoffFailure.busy
        } catch {
            cancel(); throw error // No EOF, malformed frame or unknown send recovery.
        }
    }
    private func receiveHandoffLocked(_ outstanding: OutstandingHandoff, deadline: TimeInterval) throws -> Wire.Frame {
        let bytes: Data
        do {
            bytes = try transport(deadline: deadline).readFrame(retaining: &outstanding.bytes)
        } catch Transport.Deadline.expired {
            throw HandoffFailure.busy
        }
        let request = outstanding.request
        let reply = try Wire.decode(bytes)
        guard reply.binding == verified.binding, reply.operation == .reply,
              reply.sequence == request.sequence, reply.serviceEpoch == request.serviceEpoch,
              reply.workerUUID == request.workerUUID else { throw Self.failure() }
        let current = try currentBoot()
        try cancelled.withLock { stopped in
            guard !stopped else { throw CancellationError() }
            if reply.code == nil {
                guard let proof = reply.handoffResult, let handoff = request.handoff,
                      handoff.isValidSignature(using: current.rootPublicKey),
                      handoff.request.predecessor == current.signed.grant || handoff.request.pending == current.signed.grant,
                      current.signed.isValidSignature(using: current.rootPublicKey),
                      pendingSigned?.isValidSignature(using: current.rootPublicKey) != false else { throw Self.failure() }
                let signed = try Self.validateHandoffReply(proof, for: request, current: current.ready,
                    signed: current.signed, successor: pendingSigned)
                if let challenge = outstanding.challenge {
                    _ = try StorageLifecycleHandoffShimProtocol.Reply(challenge: challenge,
                        result: proof.result, boot: Self.trust(proof.ready))
                }
                state.withLock { $0 = Current(ready: proof.ready, configuration: current.configuration, signed: signed) }
                pendingSigned = nil
                logicalHandoff = nil
            } else {
                guard reply.code == .workerBusy else { throw Self.failure() }
            }
            outstandingHandoff = nil
        }
        return reply
    }
    /// Closed same-worker reconciliation. Ordinary query remains exact-C/key;
    /// only an authenticated fence result can choose a retained signed grant.
    static func validateHandoffReply(_ proof: Wire.HandoffReply, for request: Wire.Frame,
                                    current: Wire.Ready, signed: L.SignedGrant,
                                    successor: L.SignedGrant?) throws -> L.SignedGrant {
        try request.validate(); try proof.validate()
        let next = proof.ready
        guard request.command == .fenceHandoff, proof.result.request == request.handoff?.request,
              proof.result.nonce == request.nonce, next.identity == current.identity,
              next.workerUUID == current.workerUUID, next.serviceEpoch == current.serviceEpoch,
              next.openRevision == current.openRevision, next.bootstrapKey == current.bootstrapKey,
              next.tlsRootDER == current.tlsRootDER, next.serverDER == current.serverDER,
              next.serverSPKI == current.serverSPKI, next.revision >= current.revision else { throw failure() }
        if signed.grant == proof.result.appliedGrant { return signed }
        guard let successor, successor.grant == proof.result.appliedGrant else { throw failure() }
        return successor
    }
    /// Observation only: full signed-runtime admission belongs to HostOwner and
    /// the sealed Guest, never an environment-selected profile here. This check
    /// cannot mint or advance Ready, a controller grant, or TLS trust.
    static func validateIsolationReply(_ reply: Wire.Frame, for request: Wire.Frame, current: Wire.Ready) throws {
        try request.validate()
        try reply.validate()
        try current.validate()
        guard request.operation == .command, reply.operation == .reply,
              reply.binding == request.binding, reply.sequence == request.sequence,
              request.serviceEpoch == current.serviceEpoch, request.workerUUID == current.workerUUID,
              reply.serviceEpoch == request.serviceEpoch, reply.workerUUID == request.workerUUID,
              let proof = reply.isolationProof, proof.request == request.isolationRequest,
              proof.store == current.identity.store, proof.revision >= current.revision,
              proof.caseName == request.command?.rawValue else { throw failure() }
        switch request.command {
        case .isolationState, .legacyConnection, .secondServiceExclusivity: break
        default: throw failure()
        }
        // Wire validation enforces the exact case/result pair and proof E/worker.
    }

    /// Correlated evidence from the same private exchange, never a Ready update.
    /// The actual worker retains full-profile admission and finalization ownership.
    static func validateConsumerObservationReply(_ reply: Wire.Frame, for request: Wire.Frame) throws {
        try request.validate()
        try reply.validate()
        guard request.operation == .command, reply.operation == .reply,
              reply.binding == request.binding, reply.sequence == request.sequence,
              reply.serviceEpoch == request.serviceEpoch, reply.workerUUID == request.workerUUID,
              let arm = request.consumerObservationArm ?? request.consumerObservationQuery,
              let status = reply.consumerObservationStatus else { throw failure() }
        try ConsumerObservationProtocol.validate(status, arm: arm)
        switch request.command {
        case .consumerObservationArm:
            guard status.state == .armed else { throw failure() }
        case .consumerObservationQuery: break
        case .consumerObservationFinalize:
            guard status.state == .finalized else { throw failure() }
        default: throw failure()
        }
    }

    /// Same private 4106 exchange only. An internal worker ACK is not PID1's
    /// completed Wait and must never escape as a successful exit observation.
    /// This validation does not mint Ready, a grant, or replacement authority.
    static func validatePrepareReply(_ reply: Wire.Frame, for request: Wire.Frame) throws {
        typealias C = ManagedPrepareCompatibilityProtocol
        typealias P = ManagedPrepareWorkerCheckpointProtocol
        try request.validate()
        try reply.validate()
        guard request.operation == .command, reply.operation == .reply,
              reply.binding == request.binding, reply.sequence == request.sequence,
              reply.serviceEpoch == request.serviceEpoch,
              reply.workerUUID == request.workerUUID else { throw failure() }
        switch request.command {
        case .prepareCompatibilityArm, .prepareCompatibilityObserve, .prepareCompatibilityRelease:
            guard let status = reply.prepareCompatibilityStatus else { throw failure() }
            let query = try request.prepareCompatibilityArm.map { try C.query($0) }
                ?? request.prepareCompatibilityQuery ?? request.prepareCompatibilityRelease?.query
            guard status.query == query else { throw failure() }
            if let arm = request.prepareCompatibilityArm {
                try C.validate(status, arm: arm)
                guard status.state == "armed" else { throw failure() }
            }
        case .prepareCompatibilityWorkerExit:
            guard let exit = request.prepareCompatibilityWorkerExit,
                  let wait = reply.prepareCompatibilityWorkerWait,
                  wait.query == exit.query, wait.stage == exit.stage,
                  wait.token == exit.token else { throw failure() }
            try C.validate(wait) // PID > 1, reaped, exit 74; not a synthetic ACK.
        case .prepareCompatibilityCheckpointExit:
            guard let exit = request.prepareCompatibilityCheckpointExit,
                  let wait = reply.prepareCompatibilityCheckpointWait else { throw failure() }
            try P.validate(wait, for: exit) // Exact full claim and actual Wait projection.
        default: throw failure()
        }
    }

    /// Gate held. Only a native succeeded terminal reply can establish the
    /// operation binding. Keep this evidence/configuration intact across adoption.
    private func validateAdoptedServiceChangeLocked(_ challenge: StorageLifecycleAdoptionProtocol.ServiceChangeChallenge) throws {
        try challenge.validate()
        let current = try currentBoot()
        guard challenge.isFresh(at: UInt64(Date().timeIntervalSince1970 * 1000)),
              challenge.adoption.origin.shimLaunchUUID == current.binding.shimLaunchUUID,
              challenge.adoption.origin.rootPublicKey == current.rootPublicKey.publicData,
              pendingReplacement == nil, let terminal = terminalReplacement,
              let status = terminal.reply.replacement, status.phase == .succeeded,
              status.request == terminal.request, let succeeded = status.ready,
              let reopen = terminal.request.configuration.reopen,
              reopen.request == challenge.change,
              terminal.request.configuration == current.configuration,
              current.configuration.signed == current.signed,
              current.signed.grant == challenge.change.predecessor.grant,
              succeeded.identity == current.identity,
              succeeded.serviceEpoch == current.ready.serviceEpoch,
              succeeded.workerUUID == current.ready.workerUUID,
              succeeded.controllerEpoch == current.ready.controllerEpoch,
              succeeded.controllerKey == current.ready.controllerKey,
              succeeded.openRevision == current.ready.openRevision,
              succeeded.bootstrapKey == current.ready.bootstrapKey,
              succeeded.tlsRootDER == current.ready.tlsRootDER,
              succeeded.serverDER == current.ready.serverDER,
              succeeded.serverSPKI == current.ready.serverSPKI else { throw Self.failure() }
        // Core validates exact target/completed constraints and same identity,
        // ROOT/grant/C/key, new E/TLS and advancing open revision. The native
        // terminal above additionally proves the actual worker replacement.
        let result = try L.ServiceResult(identity: succeeded.identity, grant: current.signed.grant,
            nonce: challenge.nonce, serviceEpoch: succeeded.serviceEpoch, controllerEpoch: succeeded.controllerEpoch,
            controllerKey: succeeded.controllerKey, openRevision: succeeded.openRevision)
        _ = try StorageLifecycleAdoptionProtocol.ServiceChangeReply(challenge: challenge,
            result: result, boot: Self.trust(succeeded))
    }

    /// Gate held. Returns a local reply (exact retry or conflict) without IO,
    /// nil to forward, or throws before IO for a stale/unowned request.
    private func routeReplacementLocked(_ request: Wire.Frame) throws -> Wire.Frame? {
        let current = try currentBoot()
        func local(_ base: Wire.Frame) -> Wire.Frame {
            var reply = base; reply.sequence = request.sequence; return reply
        }
        if let terminal = terminalReplacement, terminal.reply.serviceEpoch == request.serviceEpoch,
           terminal.reply.workerUUID == request.workerUUID,
           request.command == .replacementStatus || request.replacementRequest == terminal.request,
           pendingReplacement == nil {
            return local(terminal.reply) // Lost-reply exact retry.
        }
        guard request.serviceEpoch == current.ready.serviceEpoch,
              request.workerUUID == current.ready.workerUUID else { throw Self.failure() }
        guard request.command == .replaceService else {
            guard pendingReplacement != nil else { throw Self.failure() }
            return nil
        }
        guard let replacement = request.replacementRequest else { throw Self.failure() }
        if let pending = pendingReplacement {
            guard pending == replacement else {
                return local(.init(operation: .reply, binding: request.binding, serviceEpoch: request.serviceEpoch,
                                   code: .replacementConflict, workerUUID: request.workerUUID))
            }
            return nil
        }
        let c = replacement.configuration
        guard replacement.predecessorWorkerUUID == current.ready.workerUUID, c.action == .open,
              c.rootPublicKey == current.configuration.rootPublicKey, c.signed == current.signed,
              let reopen = c.reopen else { throw Self.failure() }
        let p = reopen.request.predecessor
        guard p.grant == current.signed.grant, p.context.serviceEpoch == current.ready.serviceEpoch,
              p.context.controllerEpoch == current.ready.controllerEpoch,
              p.context.controllerKey == current.ready.controllerKey,
              p.openRevision == current.ready.openRevision, try p.boot == Self.trust(current.ready) else { throw Self.failure() }
        return nil
    }
    /// Same identity/root/grant/C/key; new worker, E, TLS root and server key;
    /// revision and openRevision above the predecessor's current revision.
    private static func validateSuccessor(_ r: Wire.Ready, request: Wire.ReplacementRequest, current: VerifiedBoot) throws -> Current {
        let old = current.ready, grant = current.signed.grant
        guard let reopen = request.configuration.reopen, request.configuration.signed == current.signed,
              request.configuration.rootPublicKey == current.configuration.rootPublicKey,
              r.identity == old.identity, r.identity == grant.identity, r.bootstrapKey == old.bootstrapKey,
              r.controllerEpoch == old.controllerEpoch, r.controllerKey == old.controllerKey,
              grant.expectedEpoch < UInt64.max, r.controllerEpoch == grant.expectedEpoch + 1, r.controllerKey == grant.newKey,
              r.workerUUID != old.workerUUID, r.serviceEpoch != old.serviceEpoch,
              r.tlsRootDER != old.tlsRootDER, r.serverSPKI != old.serverSPKI, r.serverDER != old.serverDER,
              r.revision > old.revision, r.openRevision > old.revision,
              r.openRevision > reopen.request.predecessor.openRevision else { throw failure() }
        try validateCertificates(r)
        try reopen.request.validateSuccessorBoot(trust(r))
        return Current(ready: r, configuration: request.configuration, signed: current.signed)
    }
    func cancel() { cancelled.withLock { $0 = true } }
    func close() {
        cancel() // Outside the gate: bounded polling interrupts the active operation.
        gate.withLock { terminateLocked() }
    }
    private func terminateLocked() {
        guard !closed else { return }; closed = true
        _ = Darwin.shutdown(descriptor, SHUT_RDWR); Darwin.close(descriptor); closeConnection()
    }
    private func read(_ io: Transport) throws -> Wire.Frame {
        let f = try Wire.decode(io.readFrame())
        guard f.binding == verified.binding, f.operation != .error else { throw Self.failure() }
        return f
    }
    private func transport(deadline: TimeInterval? = nil) -> Transport {
        Transport(descriptor: descriptor, deadline: deadline ?? ProcessInfo.processInfo.systemUptime + 15,
                  isCancelled: { [self] in cancelled.withLock { $0 } })
    }
    private struct Transport {
        enum Deadline: Error { case expired }
        let descriptor: Int32
        let deadline: TimeInterval
        let isCancelled: @Sendable () -> Bool
        func wait(_ events: Int16) throws {
            while true {
                if isCancelled() { throw CancellationError() }
                guard ProcessInfo.processInfo.systemUptime < deadline else { throw Deadline.expired }
                let remaining = deadline - ProcessInfo.processInfo.systemUptime
                guard remaining > 0 else { throw Deadline.expired }
                var item = pollfd(fd: descriptor, events: events, revents: 0)
                let result = Darwin.poll(&item, 1, Int32(min(100, max(1, remaining * 1_000))))
                if result < 0 && errno == EINTR { continue }
                guard result >= 0 else { throw PrivateStorageLifecycleBootCoordinator.failure() }
                if result == 0 { continue }
                guard item.revents & events != 0 else { throw PrivateStorageLifecycleBootCoordinator.failure() }
                guard ProcessInfo.processInfo.systemUptime < deadline else { throw Deadline.expired }
                return
            }
        }
        func readFrame() throws -> Data {
            var bytes = Data()
            return try readFrame(retaining: &bytes)
        }
        // Bounded header + body, retained across handoff receive deadlines only.
        // recv never consumes bytes from the next frame.
        func readFrame(retaining bytes: inout Data) throws -> Data {
            var target = 4
            while true {
                if bytes.count >= 4 {
                    let count = bytes.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
                    guard count > 0, count <= 65_536 else { throw PrivateStorageLifecycleBootCoordinator.failure() }
                    target = 4 + Int(count)
                }
                if bytes.count == target, target > 4 { return Data(bytes.dropFirst(4)) }
                try wait(Int16(POLLIN))
                var chunk = Data(count: target - bytes.count)
                let amount = chunk.withUnsafeMutableBytes {
                    Darwin.recv(descriptor, $0.baseAddress!, $0.count, MSG_DONTWAIT)
                }
                if amount < 0 && [EINTR, EAGAIN].contains(errno) { continue }
                guard amount > 0 else { throw PrivateStorageLifecycleBootCoordinator.failure() }
                bytes.append(chunk.prefix(amount))
            }
        }
        func write(_ data: Data) throws {
            var offset = 0
            while offset < data.count {
                try wait(Int16(POLLOUT))
                let amount = data.withUnsafeBytes {
                    Darwin.send(descriptor, $0.baseAddress!.advanced(by: offset), data.count - offset, MSG_DONTWAIT)
                }
                if amount < 0 && [EINTR, EAGAIN].contains(errno) { continue }
                guard amount > 0 else { throw PrivateStorageLifecycleBootCoordinator.failure() }
                offset += amount
            }
        }
    }
    /// This is an Ed25519-only certificate pin/signature check, not a general
    /// X.509 policy engine. The lifecycle TLS client still verifies role and time.
    private static func validateCertificates(_ ready: Wire.Ready) throws {
        let root = try Certificate(ready.tlsRootDER), leaf = try Certificate(ready.serverDER)
        let key = try Curve25519.Signing.PublicKey(rawRepresentation: root.key)
        guard key.isValidSignature(root.signature, for: root.tbs), key.isValidSignature(leaf.signature, for: leaf.tbs),
              digest(leaf.spki) == ready.serverSPKI else { throw failure() }
    }
    /// Public certificates are not capabilities. This early correlation check
    /// deliberately does not replace storagepki's typed child/TLS verification
    /// (validity, EKU, CA constraints, role policy and possession of the private key).
    /// Compare canonical signed CSR/SAN bytes, as storagepki/csr.go does, rather
    /// than introducing a permissive URI or X.509 identity parser here.
    private static func validateControllerCertificate(_ bytes: Data, csr: Data, ready: Wire.Ready,
                                                      epoch: UInt64, key: String) throws {
        let san = DER.wrap(0x30, DER.wrap(0x86, Data("spiffe://cengine.storage/store/\(ready.identity.store)/controller/\(epoch)".utf8)))
        var outer = DER(bytes: Array(csr)); let request = try outer.take(0x30)
        guard outer.empty else { throw failure() }
        var fields = DER(bytes: request.body)
        let info = try fields.take(0x30)
        guard try fields.take(0x30).full == ed25519Algorithm else { throw failure() }
        let signature = try fields.take(0x03)
        guard fields.empty, signature.body.count == 65, signature.body.first == 0 else { throw failure() }
        var body = DER(bytes: info.body)
        guard try body.take(0x02).full == [2, 1, 0], try body.take(0x30).body.isEmpty else { throw failure() }
        let spki = try StorageIdentity.Ed25519SPKI(publicData: Data(body.take(0x30).full))
        let sanExtension = DER.wrap(0x30, Data([6, 3, 0x55, 0x1d, 0x11]) + DER.wrap(0x04, san))
        let attribute = DER.wrap(0x30, Data([6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 0x0e])
            + DER.wrap(0x31, DER.wrap(0x30, sanExtension)))
        let expected = DER.wrap(0x30, Data([2, 1, 0, 0x30, 0]) + spki.publicData + DER.wrap(0xa0, attribute))
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: spki.rawPublicKey)
        guard Data(info.full) == expected, spki.fingerprint.rawValue == key,
              publicKey.isValidSignature(Data(signature.body.dropFirst()), for: expected) else { throw failure() }
        let root = try Certificate(ready.tlsRootDER), leaf = try Certificate(bytes)
        let issuer = try Curve25519.Signing.PublicKey(rawRepresentation: root.key)
        guard issuer.isValidSignature(leaf.signature, for: leaf.tbs), leaf.spki == spki.publicData,
              leaf.san == san else { throw failure() }
    }
    private static let ed25519Algorithm: [UInt8] = [0x30, 5, 6, 3, 0x2b, 0x65, 0x70]
    private struct Certificate {
        let key: Data, spki: Data, tbs: Data, signature: Data
        let san: Data?
        init(_ bytes: Data) throws {
            guard !bytes.isEmpty, bytes.count <= Wire.maximumDERSize,
                  SecCertificateCreateWithData(nil, bytes as CFData) != nil else { throw failure() }
            var outer = DER(bytes: Array(bytes)); let certificate = try outer.take(0x30)
            guard outer.empty else { throw failure() }
            var fields = DER(bytes: certificate.body)
            let tbs = try fields.take(0x30)
            let algorithm = try fields.take(0x30)
            let signature = try fields.take(0x03)
            guard fields.empty, algorithm.full == ed25519Algorithm,
                  signature.body.count == 65, signature.body.first == 0 else { throw failure() }
            var body = DER(bytes: tbs.body)
            guard try body.take(0xa0).body == [2, 1, 2] else { throw failure() }
            _ = try body.take(0x02)
            guard try body.take(0x30).full == algorithm.full else { throw failure() }
            _ = try body.take(0x30); _ = try body.take(0x30); _ = try body.take(0x30)
            let spki = try body.take(0x30)
            let publicKey = try StorageIdentity.Ed25519SPKI(publicData: Data(spki.full))
            var extensions = DER(bytes: try body.take(0xa3).body)
            guard body.empty else { throw failure() }
            var values = DER(bytes: try extensions.take(0x30).body)
            guard extensions.empty else { throw failure() }
            var seen = Set<Data>(), san: Data?
            while !values.empty {
                var value = DER(bytes: try values.take(0x30).body)
                let oid = Data(try value.take(0x06).body)
                guard seen.insert(oid).inserted else { throw failure() }
                guard !value.empty else { throw failure() }
                if value.bytes[value.index] == 0x01 {
                    guard try value.take(0x01).body == [0xff] else { throw failure() }
                }
                let contents = Data(try value.take(0x04).body)
                guard value.empty else { throw failure() }
                if oid == Data([0x55, 0x1d, 0x11]) { san = contents }
            }
            self.key = publicKey.rawPublicKey; self.spki = publicKey.publicData; self.san = san
            self.tbs = Data(tbs.full); self.signature = Data(signature.body.dropFirst())
        }
    }
    private struct DER {
        let bytes: [UInt8]
        var index = 0
        var empty: Bool { index == bytes.count }
        static func wrap(_ tag: UInt8, _ body: Data) -> Data {
            let n = body.count
            let length: [UInt8] = n < 128 ? [UInt8(n)] : n < 256 ? [0x81, UInt8(n)] : [0x82, UInt8(n >> 8), UInt8(n & 255)]
            return Data([tag] + length) + body
        }
        mutating func take(_ tag: UInt8) throws -> (full: [UInt8], body: [UInt8]) {
            let start = index
            guard index + 2 <= bytes.count, bytes[index] == tag else { throw failure() }
            index += 1; let initial = Int(bytes[index]); index += 1
            var length = initial
            if initial >= 128 {
                let count = initial & 127
                guard count > 0, count <= 2, index + count <= bytes.count, bytes[index] != 0 else { throw failure() }
                length = 0
                for _ in 0..<count { length = length * 256 + Int(bytes[index]); index += 1 }
                guard length >= 128 else { throw failure() }
            }
            guard length <= bytes.count - index else { throw failure() }
            let body = Array(bytes[index..<index + length]); index += length
            return (Array(bytes[start..<index]), body)
        }
    }
}
#endif

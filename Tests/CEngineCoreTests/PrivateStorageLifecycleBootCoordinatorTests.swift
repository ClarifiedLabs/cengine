#if os(macOS)
import CEngineCore
@testable import CEngineRuntime
import Foundation
import Testing

@Suite("Lifecycle private boot component")
struct PrivateStorageLifecycleBootCoordinatorTests {
    typealias W = StorageLifecycleServiceBootProtocol
    // The shared fixture supplies only an actual committed disk proof and sockets;
    // lifecycle authority comes exclusively from the private exchange below.
    @Test(arguments: ["none", "launch", "spec", "initramfs", "ext4", "bytes", "epoch", "openRevision", "controller", "key"])
    func coldBootBindsActualLaunchAndSuccessor(fault: String) async throws {
        typealias C = StorageLifecycleColdProtocol
        let fixture = try await StorageBootFixture.make()
        defer { fixture.close() }
        let material = try LifecycleCertificateFixture(), old = material.ready
        let initial = material.configuration, binding = fixture.proof.binding
        let grant = try StorageLifecycleProtocol.Grant(operation: .takeover, id: UUID().uuidString.lowercased(),
            identity: old.identity, serial: 2, expectedEpoch: 1, newKey: LifecycleCertificateFixture.fingerprint(material.successor))
        let signed = try StorageLifecycleProtocol.SignedGrant(grant: grant, signature: material.bootstrap.signature(for: grant.signingBytes))
        let launch = try C.Launch(shimLaunchUUID: fault == "launch" ? UUID().uuidString.lowercased() : binding.shimLaunchUUID,
            specSHA256: fault == "spec" ? String(repeating: "c", count: 64) : fixture.proof.specificationSHA256,
            initramfsSHA256: fault == "initramfs" ? String(repeating: "c", count: 64) : fixture.proof.initramfsSHA256,
            ext4UUID: fault == "ext4" ? UUID().uuidString.lowercased() : binding.ext4UUID,
            bytes: fault == "bytes" ? binding.bytes + 1 : binding.bytes)
        let request = try C.Request(operationID: grant.id, predecessor: .init(currentGrant: initial.signed.grant,
            serviceEpoch: old.serviceEpoch, controllerEpoch: 1, controllerKey: old.controllerKey,
            openRevision: old.openRevision, bootstrapKey: old.bootstrapKey), takeover: signed, launch: launch,
            nowUnixSeconds: initial.nowUnixSeconds, lifetimeSeconds: initial.lifetimeSeconds)
        let cfg = try W.Configuration(action: .coldOpenTakeover, rootPublicKey: initial.rootPublicKey, signed: signed,
            nowUnixSeconds: initial.nowUnixSeconds, lifetimeSeconds: initial.lifetimeSeconds,
            cold: .init(request: request, signature: material.bootstrap.signature(for: request.signingBytes)))
        if ["launch", "spec", "initramfs", "ext4", "bytes"].contains(fault) {
            #expect(throws: (any Error).self) {
                try PrivateStorageLifecycleBootCoordinator(verified: fixture.proof, configuration: cfg,
                    descriptor: fixture.pair.host.fileDescriptor)
            }
            return
        }
        let ready = try material.readyLike(old, serviceEpoch: fault == "epoch" ? old.serviceEpoch : UUID().uuidString.lowercased(),
            root: .init(), server: .init(), controllerEpoch: fault == "controller" ? 1 : 2,
            controllerKey: fault == "key" ? old.controllerKey : grant.newKey, revision: 2,
            openRevision: fault == "openRevision" ? 1 : 2)
        let coordinator = try PrivateStorageLifecycleBootCoordinator(verified: fixture.proof, configuration: cfg,
            descriptor: fixture.pair.host.fileDescriptor)
        defer { coordinator.close() }
        let worker = StorageBootWorker(cancel: { coordinator.cancel() }) { try coordinator.bootstrap() }
        defer { worker.settle() }
        try fixture.pair.guest.write(contentsOf: W.encode(.init(operation: .hello, binding: binding)))
        #expect(try read(fixture.pair.guest).configuration == cfg)
        try fixture.pair.guest.write(contentsOf: W.encode(.init(operation: .ready, binding: binding, ready: ready)))
        if fault == "none" {
            let boot = try await worker.result()
            #expect(boot.signed == signed && boot.ready == ready)
        } else {
            do { _ = try await worker.result(); Issue.record("invalid cold successor minted boot") } catch { }
            #expect(throws: (any Error).self) { try coordinator.currentBoot() }
        }
    }

    @Test func realExchangeCapabilityAndClose() async throws {
        let fixture = try await StorageBootFixture.make()
        defer { fixture.close() }
        let vectors = try StorageLifecycleServiceBootProtocolTests.vectors()
        let cfg = try #require(vectors[1].configuration), ready = try #require(vectors[2].ready)
        let coordinator = try PrivateStorageLifecycleBootCoordinator(verified: fixture.proof, configuration: cfg,
                                                                    descriptor: fixture.pair.host.fileDescriptor)
        defer { coordinator.close() }
        #expect(throws: (any Error).self) { try coordinator.currentBoot() }
        let worker = StorageBootWorker(cancel: { coordinator.cancel() }) { try coordinator.bootstrap() }
        defer { worker.settle() }
        try fixture.pair.guest.write(contentsOf: W.encode(.init(operation: .hello, binding: fixture.proof.binding)))
        let configured = try read(fixture.pair.guest)
        #expect(configured.configuration == cfg)
        try fixture.pair.guest.write(contentsOf: W.encode(.init(operation: .ready, binding: fixture.proof.binding, ready: ready)))
        let boot = try await worker.result()
        #expect(boot.identity == cfg.signed.grant.identity)
        #expect(try boot.trust(for: cfg.signed.grant).serverSPKI == ready.serverSPKI)
        let request = W.Frame(operation: .command, binding: boot.binding, sequence: 1, serviceEpoch: ready.serviceEpoch, command: .query,
            workerUUID: ready.workerUUID)
        let query = StorageBootWorker(cancel: { coordinator.cancel() }) { try coordinator.command(request) }
        defer { query.settle() }
        let sent = try read(fixture.pair.guest)
        #expect(sent.sequence == 1)
        try fixture.pair.guest.write(contentsOf: W.encode(.init(operation: .reply, binding: boot.binding, ready: ready, sequence: sent.sequence, serviceEpoch: ready.serviceEpoch,
            workerUUID: ready.workerUUID)))
        #expect(try await query.result().ready == ready)
        // Proof must perform another sequence-bound private query, not read Ready.
        let nonce = Data(repeating: 9, count: 32)
        let proof = StorageBootWorker(cancel: { coordinator.cancel() }) {
            try boot.freshServiceObservation(for: cfg.signed.grant, nonce: nonce,
                deadline: ProcessInfo.processInfo.systemUptime + 5)
        }
        defer { proof.settle() }
        let fresh = try read(fixture.pair.guest)
        #expect(fresh.command == .query && fresh.sequence == 2)
        try fixture.pair.guest.write(contentsOf: W.encode(.init(operation: .reply, binding: boot.binding,
            ready: ready, sequence: fresh.sequence, serviceEpoch: ready.serviceEpoch, workerUUID: ready.workerUUID)))
        let observed = try await proof.result()
        #expect(observed.0.nonce == nonce && observed.0.openRevision == ready.openRevision)
        #expect(try observed.1 == boot.trust(for: cfg.signed.grant))
        coordinator.close()
        #expect(throws: (any Error).self) { try boot.trust(for: cfg.signed.grant) }
        #expect(throws: (any Error).self) { try coordinator.currentBoot() }
    }
    @Test(arguments: [false, true], [false, true])
    func callerSequencesRemainSeparateFromSurvivingGuestSession(errorReply: Bool, wrongGuestSequence: Bool) async throws {
        let fixture = try await StorageBootFixture.make()
        defer { fixture.close() }
        let material = try LifecycleCertificateFixture()
        let (coordinator, boot) = try await booted(fixture, material)
        defer { coordinator.close() }
        // A caller's counter need not match the persistent 4106 session: ROOT
        // queries also consume it, and an adopted daemon starts its own at one.
        for (index, callerSequence) in [UInt64(41), 1].enumerated() {
            let request = W.Frame(operation: .command, binding: boot.binding, sequence: callerSequence,
                serviceEpoch: boot.ready.serviceEpoch, command: .query, workerUUID: boot.ready.workerUUID)
            let worker = StorageBootWorker(cancel: { coordinator.cancel() }) { try coordinator.command(request) }
            defer { worker.settle() }
            let sent = try read(fixture.pair.guest)
            let guestSequence = try #require(sent.sequence)
            #expect(guestSequence == UInt64(index + 1))
            try fixture.pair.guest.write(contentsOf: W.encode(.init(operation: .reply, binding: boot.binding,
                ready: errorReply ? nil : boot.ready,
                sequence: wrongGuestSequence ? guestSequence + 1 : guestSequence,
                serviceEpoch: boot.ready.serviceEpoch, code: errorReply ? .replacementConflict : nil,
                workerUUID: boot.ready.workerUUID)))
            if wrongGuestSequence {
                await #expect(throws: (any Error).self) { try await worker.result() }
                #expect(throws: (any Error).self) { try coordinator.currentBoot() }
                return
            }
            let reply = try await worker.result()
            #expect(reply.sequence == callerSequence)
            #expect(reply.binding == request.binding && reply.serviceEpoch == request.serviceEpoch)
            #expect(reply.workerUUID == request.workerUUID)
            #expect(reply.ready == (errorReply ? nil : boot.ready))
            #expect(reply.code == (errorReply ? .replacementConflict : nil))
            _ = try coordinator.currentBoot()
        }
    }

    @Test(arguments: ["binding", "pins", "signature", "cancel"])
    func failClosed(fault: String) async throws {
        let fixture = try await StorageBootFixture.make()
        defer { fixture.close() }
        let vectors = try StorageLifecycleServiceBootProtocolTests.vectors()
        var cfg = try #require(vectors[1].configuration)
        if fault == "signature" {
            cfg = .init(action: cfg.action, rootPublicKey: cfg.rootPublicKey,
                signed: try .init(grant: cfg.signed.grant, signature: Data(repeating: 0, count: 64)),
                nowUnixSeconds: cfg.nowUnixSeconds, lifetimeSeconds: cfg.lifetimeSeconds)
            #expect(throws: (any Error).self) {
                try PrivateStorageLifecycleBootCoordinator(verified: fixture.proof, configuration: cfg, descriptor: fixture.pair.host.fileDescriptor)
            }
            return
        }
        let coordinator = try PrivateStorageLifecycleBootCoordinator(verified: fixture.proof, configuration: cfg, descriptor: fixture.pair.host.fileDescriptor)
        defer { coordinator.close() }
        let worker = StorageBootWorker(cancel: { coordinator.cancel() }) { try coordinator.bootstrap() }
        defer { worker.settle() }
        if fault == "cancel" { coordinator.close() } else {
            var binding = fixture.proof.binding
            if fault == "binding" { binding.guestBootNonce = UUID().uuidString.lowercased() }
            try fixture.pair.guest.write(contentsOf: W.encode(.init(operation: .hello, binding: binding)))
            if fault == "pins" {
                _ = try read(fixture.pair.guest)
                let r = try #require(vectors[2].ready)
                let bad = W.Ready(identity: r.identity, serviceEpoch: r.serviceEpoch, workerUUID: r.workerUUID,
                    controllerEpoch: r.controllerEpoch, controllerKey: r.controllerKey, revision: r.revision, openRevision: r.openRevision,
                    bootstrapKey: r.bootstrapKey, tlsRootDER: r.tlsRootDER, serverDER: r.serverDER, serverSPKI: String(repeating: "0", count: 64))
                try fixture.pair.guest.write(contentsOf: W.encode(.init(operation: .ready, binding: binding, ready: bad)))
            }
        }
        do { _ = try await worker.result(); Issue.record("failed exchange minted capability") } catch { }
        #expect(throws: (any Error).self) { try coordinator.currentBoot() }
    }
    private func read(_ handle: FileHandle) throws -> W.Frame {
        func exact(_ n: Int) throws -> Data {
            var data = Data()
            while data.count < n {
                guard let next = try handle.read(upToCount: n - data.count), !next.isEmpty else { throw W.ValidationError.invalidFrame }
                data.append(next)
            }
            return data
        }
        let count = try exact(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard count > 0, count <= W.maxFrame else { throw W.ValidationError.invalidFrame }
        return try W.decode(exact(Int(count)))
    }
}
#endif

#if os(macOS)
import CryptoKit
import Darwin

extension PrivateStorageLifecycleBootCoordinatorTests {
    @Test(arguments: [W.Configuration.Action.initialize, .open], [false, true])
    func onlyOneCoordinatorMayAttemptServiceBoot(action: W.Configuration.Action, complete: Bool) async throws {
        let fixture = try await StorageBootFixture.make()
        defer { fixture.close() }
        let vectors = try StorageLifecycleServiceBootProtocolTests.vectors()
        let cfg = try #require(vectors[action == .initialize ? 1 : 5].configuration)
        let secondPair = try BootSocketPair()
        defer { secondPair.close() }
        // Both constructors succeed. Neither claims the boot, even for initialize.
        let first = try PrivateStorageLifecycleBootCoordinator(verified: fixture.proof, configuration: cfg,
            descriptor: fixture.pair.host.fileDescriptor)
        let second = try PrivateStorageLifecycleBootCoordinator(verified: fixture.proof, configuration: cfg,
            descriptor: secondPair.host.fileDescriptor)
        defer { first.close(); second.close() }
        let worker = StorageBootWorker(cancel: { first.cancel() }) { try first.bootstrap() }
        defer { worker.settle() }
        if complete {
            try fixture.pair.guest.write(contentsOf: W.encode(.init(operation: .hello, binding: fixture.proof.binding)))
            _ = try read(fixture.pair.guest)
            try fixture.pair.guest.write(contentsOf: W.encode(.init(operation: .ready, binding: fixture.proof.binding,
                ready: vectors[action == .initialize ? 2 : 6].ready)))
            _ = try await worker.result()
        } else {
            // An idle first-byte read is cancelled without peer shutdown.
            first.cancel()
            #expect(worker.finishedWithin(3))
            do { _ = try await worker.result(); Issue.record("cancelled boot succeeded") } catch { }
        }
        let retry = StorageBootWorker(cancel: { second.cancel() }) { try second.bootstrap() }
        defer { retry.settle() }
        // No greeting: rejection must happen before even a first-byte read.
        #expect(retry.finishedWithin(3), "second coordinator performed stream I/O")
        do { _ = try await retry.result(); Issue.record("raw boot replayed configure") } catch { }
        var byte: UInt8 = 0
        #expect(recv(secondPair.guest.fileDescriptor, &byte, 1, MSG_DONTWAIT) <= 0)
        _ = try fixture.proof.freshInitialization() // Service claim is not fresh-proof consumption.
    }

    @Test(arguments: [W.Command.issueController, .authorizeSuccessor],
          ["valid", "garbage", "wrong-ca", "wrong-key", "wrong-uri", "extra-san", "signature", "trailing", "csr-signature", "csr-uri", "csr-hidden-attribute"])
    func controllerCertificateRepliesAreCorrelated(command: W.Command, fault: String) async throws {
        let fixture = try await StorageBootFixture.make()
        defer { fixture.close() }
        let material = try LifecycleCertificateFixture()
        let coordinator = try PrivateStorageLifecycleBootCoordinator(verified: fixture.proof, configuration: material.configuration,
            descriptor: fixture.pair.host.fileDescriptor)
        defer { coordinator.close() }
        let bootWorker = StorageBootWorker(cancel: { coordinator.cancel() }) { try coordinator.bootstrap() }
        defer { bootWorker.settle() }
        try fixture.pair.guest.write(contentsOf: W.encode(.init(operation: .hello, binding: fixture.proof.binding)))
        _ = try read(fixture.pair.guest)
        try fixture.pair.guest.write(contentsOf: W.encode(.init(operation: .ready, binding: fixture.proof.binding, ready: material.ready)))
        let boot = try await bootWorker.result()
        let key = command == .issueController ? material.controller : material.successor
        let epoch: UInt64 = command == .issueController ? 1 : 2
        let uri = "spiffe://cengine.storage/store/\(boot.identity.store)/controller/\(epoch)"
        var csr = try material.csr(key: key, uri: fault == "csr-uri" ? uri + "0" : uri,
                                   hiddenAttribute: fault == "csr-hidden-attribute")
        if fault == "csr-signature" { csr[csr.count - 1] ^= 1 }
        let grant = try StorageLifecycleProtocol.Grant(operation: .takeover, id: UUID().uuidString.lowercased(),
            identity: boot.identity, serial: 2, expectedEpoch: 1, newKey: LifecycleCertificateFixture.fingerprint(key))
        let signed = try StorageLifecycleProtocol.SignedGrant(grant: grant, signature: material.bootstrap.signature(for: grant.signingBytes))
        let request = W.Frame(operation: .command, binding: boot.binding, sequence: 1, serviceEpoch: boot.ready.serviceEpoch,
            command: command, csr: csr, signed: command == .authorizeSuccessor ? signed : nil, workerUUID: boot.ready.workerUUID)
        var certificate = try material.certificate(key: fault == "wrong-key" ? material.server : key,
            issuer: fault == "wrong-ca" ? material.bootstrap : material.root,
            uri: fault == "wrong-uri" ? uri + "0" : uri, extraSAN: fault == "extra-san")
        if fault == "garbage" { certificate = Data([1, 2, 3]) }
        if fault == "signature" { certificate[certificate.count - 1] ^= 1 }
        if fault == "trailing" { certificate.append(0) }
        let worker = StorageBootWorker(cancel: { coordinator.cancel() }) { try coordinator.command(request) }
        defer { worker.settle() }
        let sent = try read(fixture.pair.guest)
        try fixture.pair.guest.write(contentsOf: W.encode(.init(operation: .reply, binding: boot.binding,
            sequence: sent.sequence, serviceEpoch: boot.ready.serviceEpoch, certificate: certificate, workerUUID: boot.ready.workerUUID)))
        if fault == "valid" {
            #expect(try await worker.result().certificate == certificate)
            _ = try coordinator.currentBoot()
        } else {
            do { _ = try await worker.result(); Issue.record("invalid certificate/CSR accepted: \(fault)") } catch { }
            #expect(throws: (any Error).self) { try coordinator.currentBoot() }
        }
    }
}

extension PrivateStorageLifecycleBootCoordinatorTests {
    private func booted(_ fixture: StorageBootFixture, _ material: LifecycleCertificateFixture) async throws
        -> (PrivateStorageLifecycleBootCoordinator, PrivateStorageLifecycleBootCoordinator.VerifiedBoot) {
        let coordinator = try PrivateStorageLifecycleBootCoordinator(verified: fixture.proof, configuration: material.configuration,
            descriptor: fixture.pair.host.fileDescriptor)
        let worker = StorageBootWorker(cancel: { coordinator.cancel() }) { try coordinator.bootstrap() }
        defer { worker.settle() }
        try fixture.pair.guest.write(contentsOf: W.encode(.init(operation: .hello, binding: fixture.proof.binding)))
        _ = try read(fixture.pair.guest)
        try fixture.pair.guest.write(contentsOf: W.encode(.init(operation: .ready, binding: fixture.proof.binding, ready: material.ready)))
        return (coordinator, try await worker.result())
    }
    private static func waited(_ semaphore: DispatchSemaphore, seconds: Double) -> Bool {
        semaphore.wait(timeout: .now() + seconds) == .success
    }
    @Test func daemonFenceJoinsOriginalPrivateExchangeWithoutGuestEOF() async throws {
        let fixture = try await StorageBootFixture.make()
        defer { fixture.close() }
        let material = try LifecycleCertificateFixture()
        let (coordinator, boot) = try await booted(fixture, material)
        defer { coordinator.close() }
        let control = StorageLifecycleControlLifetime()
        try control.beginEnrollment(); try control.enroll()
        let generation = try control.captureGeneration()
        let request = W.Frame(operation: .command, binding: boot.binding, sequence: 1,
            serviceEpoch: boot.ready.serviceEpoch, command: .query, workerUUID: boot.ready.workerUUID)
        let query = StorageBootWorker(cancel: {}) {
            try control.withOperation(generation) { try coordinator.command(request) }
        }
        defer { query.settle() }
        let sent = try read(fixture.pair.guest) // Real 4106 framing: query is in flight.
        let started = DispatchSemaphore(value: 0), fenced = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            started.signal(); control.detach(); fenced.signal()
        }
        #expect(await Task.detached { Self.waited(started, seconds: 2) }.value)
        #expect(await Task.detached { !Self.waited(fenced, seconds: 0.05) }.value)
        try fixture.pair.guest.write(contentsOf: W.encode(.init(operation: .reply, binding: boot.binding,
            ready: boot.ready, sequence: sent.sequence, serviceEpoch: boot.ready.serviceEpoch,
            workerUUID: boot.ready.workerUUID)))
        #expect(try await query.result().ready == boot.ready)
        #expect(await Task.detached { Self.waited(fenced, seconds: 2) }.value)
        #expect(throws: (any Error).self) { try control.withOperation(generation) { Issue.record("stale operation") } }
        #expect(throws: (any Error).self) { try control.withAdmission { Issue.record("late publication") } }
        #expect(try coordinator.currentBoot().ready == boot.ready)
        var byte: UInt8 = 0
        #expect(recv(fixture.pair.guest.fileDescriptor, &byte, 1, MSG_DONTWAIT) == -1)
        #expect(errno == EAGAIN) // Not EOF: PID1 lifecycleSession still owns its worker.
        // A token from this lifetime cannot enter a future control generation.
        let next = StorageLifecycleControlLifetime()
        #expect(throws: (any Error).self) { try next.withOperation(generation) {} }
    }

    @Test func uncertainPrivateReplyPoisonsAuthorityWithoutClosingGuestSession() async throws {
        let fixture = try await StorageBootFixture.make()
        defer { fixture.close() }
        let material = try LifecycleCertificateFixture()
        let (coordinator, boot) = try await booted(fixture, material)
        defer { coordinator.close() }
        let request = W.Frame(operation: .command, binding: boot.binding, sequence: 1,
            serviceEpoch: boot.ready.serviceEpoch, command: .query, workerUUID: boot.ready.workerUUID)
        let query = StorageBootWorker(cancel: {}) { try coordinator.command(request) }
        defer { query.settle() }
        let sent = try read(fixture.pair.guest)
        try fixture.pair.guest.write(contentsOf: W.encode(.init(operation: .reply, binding: boot.binding,
            ready: boot.ready, sequence: try #require(sent.sequence) + 1, serviceEpoch: boot.ready.serviceEpoch,
            workerUUID: boot.ready.workerUUID)))
        await #expect(throws: (any Error).self) { try await query.result() }
        #expect(throws: (any Error).self) { try coordinator.currentBoot() }
        #expect(throws: (any Error).self) { try coordinator.command(request) }
        #expect(throws: (any Error).self) { try coordinator.bootstrap() }
        var byte: UInt8 = 0
        #expect(recv(fixture.pair.guest.fileDescriptor, &byte, 1, MSG_DONTWAIT) == -1)
        #expect(errno == EAGAIN)
    }

    private func exchange(_ fixture: StorageBootFixture, _ coordinator: PrivateStorageLifecycleBootCoordinator, _ request: W.Frame,
                          reply: @escaping (W.Frame) throws -> W.Frame) async throws -> W.Frame {
        let worker = StorageBootWorker(cancel: { coordinator.cancel() }) { try coordinator.command(request) }
        defer { worker.settle() }
        let sent = try read(fixture.pair.guest)
        #expect(sent.command == request.command && sent.replacementRequest == request.replacementRequest)
        try fixture.pair.guest.write(contentsOf: W.encode(reply(sent)))
        return try await worker.result()
    }
    /// Answered without stream IO: the Guest sees no bytes.
    private func local(_ fixture: StorageBootFixture, _ coordinator: PrivateStorageLifecycleBootCoordinator, _ request: W.Frame) throws -> W.Frame {
        let reply = try coordinator.command(request)
        var byte: UInt8 = 0
        #expect(recv(fixture.pair.guest.fileDescriptor, &byte, 1, MSG_DONTWAIT) < 0)
        return reply
    }
    private func replacementReply(_ sent: W.Frame, _ status: W.ReplacementStatus) -> W.Frame {
        .init(operation: .reply, binding: sent.binding, sequence: sent.sequence, serviceEpoch: sent.serviceEpoch,
              workerUUID: sent.workerUUID, replacement: status)
    }

    @Test(arguments: ["valid", "same-epoch", "same-worker", "same-tls", "revision", "controller", "other-request"])
    func replacementPendingRetryAndSuccessorValidation(fault: String) async throws {
        let fixture = try await StorageBootFixture.make()
        defer { fixture.close() }
        let material = try LifecycleCertificateFixture()
        let (coordinator, boot) = try await booted(fixture, material)
        defer { coordinator.close() }
        let old = boot.ready, request = try material.replacement(predecessor: old)
        func frame(_ command: W.Command, _ sequence: UInt64, _ replacement: W.ReplacementRequest? = nil) -> W.Frame {
            .init(operation: .command, binding: boot.binding, sequence: sequence, serviceEpoch: old.serviceEpoch, command: command,
                  workerUUID: old.workerUUID, replacementRequest: replacement)
        }
        // Status before any admitted replacement is refused before IO.
        #expect(throws: (any Error).self) { _ = try local(fixture, coordinator, frame(.replacementStatus, 1)) }
        let pending = try await exchange(fixture, coordinator, frame(.replaceService, 1, request)) {
            replacementReply($0, .init(request: request, phase: .pending))
        }
        #expect(pending.replacement?.phase == .pending)
        // A different replacement while one is pending: local conflict, no IO.
        let other = try material.replacement(predecessor: old)
        #expect(try local(fixture, coordinator, frame(.replaceService, 2, other)).code == .replacementConflict)
        // Lost-reply retry of the exact pending request is forwarded.
        _ = try await exchange(fixture, coordinator, frame(.replaceService, 3, request)) {
            replacementReply($0, .init(request: request, phase: .pending))
        }
        let successor = try material.readyLike(old,
            serviceEpoch: fault == "same-epoch" ? old.serviceEpoch : UUID().uuidString.lowercased(),
            workerUUID: fault == "same-worker" ? old.workerUUID : UUID().uuidString.lowercased(),
            root: fault == "same-tls" ? nil : .init(), server: fault == "same-tls" ? nil : .init(),
            controllerEpoch: fault == "controller" ? 2 : nil,
            revision: fault == "revision" ? 1 : 2, openRevision: fault == "revision" ? 1 : 2)
        let replied = fault == "other-request" ? other : request
        let result: W.Frame
        do {
            result = try await exchange(fixture, coordinator, frame(.replacementStatus, 4)) {
                replacementReply($0, .init(request: replied, phase: .succeeded, ready: successor))
            }
        } catch {
            #expect(fault != "valid", "valid successor refused")
            #expect(throws: (any Error).self) { try coordinator.currentBoot() }
            return
        }
        #expect(fault == "valid", "invalid successor accepted: \(fault)")
        #expect(result.replacement?.ready == successor)
        // Atomic successor mint; no second raw disk boot claim was consumed.
        let current = try coordinator.currentBoot()
        #expect(current.ready == successor && current.configuration == request.configuration)
        #expect(current.signed == material.configuration.signed)
        #expect(throws: (any Error).self) { try boot.trust(for: material.configuration.signed.grant) }
        _ = try current.trust(for: material.configuration.signed.grant)
        // Exact retries on the predecessor pair replay the terminal reply locally.
        let retried = try local(fixture, coordinator, frame(.replaceService, 5, request))
        #expect(retried.replacement == result.replacement && retried.sequence == 5)
        #expect(try local(fixture, coordinator, frame(.replacementStatus, 6)).replacement?.phase == .succeeded)
        #expect(throws: (any Error).self) { _ = try local(fixture, coordinator, frame(.replaceService, 7, other)) }
        #expect(throws: (any Error).self) { _ = try local(fixture, coordinator, frame(.query, 7)) }
        let query = W.Frame(operation: .command, binding: boot.binding, sequence: 7, serviceEpoch: successor.serviceEpoch,
                            command: .query, workerUUID: successor.workerUUID)
        #expect(try await exchange(fixture, coordinator, query) {
            .init(operation: .reply, binding: $0.binding, ready: successor, sequence: $0.sequence,
                  serviceEpoch: $0.serviceEpoch, workerUUID: $0.workerUUID)
        }.ready == successor)
    }

    @Test(arguments: [true, false])
    func reconcileControllerAdvancesTrackedSignedGrant(matching: Bool) async throws {
        let fixture = try await StorageBootFixture.make()
        defer { fixture.close() }
        let material = try LifecycleCertificateFixture()
        let (coordinator, boot) = try await booted(fixture, material)
        defer { coordinator.close() }
        let key = try LifecycleCertificateFixture.fingerprint(material.successor)
        let grant = try StorageLifecycleProtocol.Grant(operation: .takeover, id: UUID().uuidString.lowercased(), identity: boot.identity,
            serial: 2, expectedEpoch: 1, newKey: matching ? key : LifecycleCertificateFixture.fingerprint(material.server))
        let signed = try StorageLifecycleProtocol.SignedGrant(grant: grant, signature: material.bootstrap.signature(for: grant.signingBytes))
        let request = W.Frame(operation: .command, binding: boot.binding, sequence: 1, serviceEpoch: boot.ready.serviceEpoch,
            command: .reconcileController, signed: signed, controller: .init(epoch: 2, key: key), workerUUID: boot.ready.workerUUID)
        let reconciled = try material.readyLike(boot.ready, controllerEpoch: 2, controllerKey: key, revision: 2, openRevision: 1)
        do {
            _ = try await exchange(fixture, coordinator, request) {
                .init(operation: .reply, binding: $0.binding, ready: reconciled, sequence: $0.sequence,
                      serviceEpoch: $0.serviceEpoch, workerUUID: $0.workerUUID)
            }
            #expect(matching)
            let current = try coordinator.currentBoot()
            #expect(current.signed == signed && current.ready == reconciled)
        } catch {
            #expect(!matching)
            #expect(throws: (any Error).self) { try coordinator.currentBoot() }
        }
    }
}

extension PrivateStorageLifecycleBootCoordinatorTests {
    typealias Prepare = ManagedPrepareCompatibilityProtocol
    typealias Checkpoint = ManagedPrepareWorkerCheckpointProtocol

    @Test(arguments: [W.Command.prepareCompatibilityArm, .prepareCompatibilityObserve,
                      .prepareCompatibilityRelease, .prepareCompatibilityWorkerExit])
    func fullPrepareCommandsUseSamePrivateSession(command: W.Command) async throws {
        let vector = try WorkerExitVector.load()
        let fixture = try await StorageBootFixture.make()
        defer { fixture.close() }
        let material = try LifecycleCertificateFixture(store: vector.arm.arm.scope.store,
            serviceEpoch: vector.arm.arm.scope.serviceEpoch, workerUUID: vector.arm.workerUUID)
        let (coordinator, boot) = try await booted(fixture, material)
        defer { coordinator.close() }
        let request = W.Frame(operation: .command, binding: boot.binding, sequence: 41,
            serviceEpoch: boot.ready.serviceEpoch, command: command, workerUUID: boot.ready.workerUUID,
            prepareCompatibilityArm: command == .prepareCompatibilityArm ? vector.arm : nil,
            prepareCompatibilityQuery: command == .prepareCompatibilityObserve ? vector.status.query : nil,
            prepareCompatibilityRelease: command == .prepareCompatibilityRelease ? vector.exit : nil,
            prepareCompatibilityWorkerExit: command == .prepareCompatibilityWorkerExit ? vector.exit : nil)
        let status = command == .prepareCompatibilityArm
            ? Prepare.StorageStatus(query: vector.status.query, state: "armed") : vector.status
        let result = try await exchange(fixture, coordinator, request) {
            .init(operation: .reply, binding: $0.binding, sequence: $0.sequence,
                  serviceEpoch: $0.serviceEpoch, workerUUID: $0.workerUUID,
                  prepareCompatibilityStatus: command == .prepareCompatibilityWorkerExit ? nil : status,
                  prepareCompatibilityWorkerWait: command == .prepareCompatibilityWorkerExit ? vector.wait : nil)
        }
        #expect(result.sequence == 41)
        #expect(result.ready == nil && result.signed == nil && result.replacement == nil)
        #expect(try coordinator.currentBoot().ready == boot.ready)
        #expect(try coordinator.currentBoot().signed == boot.signed)
    }

    private func checkpointClaim() throws -> Checkpoint.WorkerCheckpointExit {
        struct Row: Decodable {
            var name: String
            var arm: Prepare.Arm
            var observationCanonical: String
        }
        let path = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appending(path: "Guest/internal/preparecompat/testdata/full-vectors.json")
        let row = try #require(JSONDecoder().decode([Row].self, from: Data(contentsOf: path)).first { $0.name == "normal" })
        return try .init(arm: row.arm,
            checkpoint: Prepare.decode(Prepare.Observation.self, from: Data(row.observationCanonical.utf8)),
            workerUUID: row.arm.requestID)
    }

    @Test(arguments: ["valid", "ack", "stale-claim", "wrong-result", "worker", "epoch", "exit", "unreaped", "worker-unreaped-code", "mixed-code"])
    func checkpointExitRequiresExactSupervisorWait(fault: String) async throws {
        let claim = try checkpointClaim()
        let fixture = try await StorageBootFixture.make()
        defer { fixture.close() }
        let material = try LifecycleCertificateFixture(store: claim.arm.scope.store,
            serviceEpoch: claim.arm.scope.serviceEpoch, workerUUID: claim.workerUUID)
        let (coordinator, boot) = try await booted(fixture, material)
        defer { coordinator.close() }
        let request = W.Frame(operation: .command, binding: boot.binding, sequence: 51,
            serviceEpoch: boot.ready.serviceEpoch, command: .prepareCompatibilityCheckpointExit,
            workerUUID: boot.ready.workerUUID, prepareCompatibilityCheckpointExit: claim)
        let worker = StorageBootWorker(cancel: { coordinator.cancel() }) { try coordinator.command(request) }
        defer { worker.settle() }
        let sent = try read(fixture.pair.guest)
        var returned = claim
        if fault == "stale-claim" {
            returned.arm.requestID = UUID().uuidString.lowercased()
            returned.checkpoint!.requestID = returned.arm.requestID
            returned.checkpoint!.armDigest = try Prepare.digest(returned.arm)
        }
        if fault == "worker" { returned.workerUUID = UUID().uuidString.lowercased() }
        let wait = Checkpoint.WorkerCheckpointWait(arm: returned.arm, checkpoint: returned.checkpoint,
            workerUUID: returned.workerUUID, workerPID: 42, exitCode: fault == "exit" ? 0 : 74,
            reaped: fault != "unreaped")
        let reply = W.Frame(operation: .reply, binding: boot.binding,
            sequence: sent.sequence, serviceEpoch: fault == "epoch" ? UUID().uuidString.lowercased() : boot.ready.serviceEpoch,
            ok: fault == "wrong-result" ? true : nil,
            code: ["worker-unreaped-code", "mixed-code"].contains(fault) ? .workerUnreaped : nil,
            workerUUID: boot.ready.workerUUID,
            prepareCompatibilityCheckpointAck: fault == "ack" ? claim : nil,
            prepareCompatibilityCheckpointWait: ["ack", "wrong-result", "worker-unreaped-code"].contains(fault) ? nil : wait)
        // Deliberately bypass encode validation to exercise the actual ingress
        // boundary for bad Wait/envelope fields, not merely the DTO validator.
        let body = try StorageLifecycleProtocol.encode(reply)
        var count = UInt32(body.count).bigEndian
        try fixture.pair.guest.write(contentsOf: Data(bytes: &count, count: 4) + body)
        if fault == "worker-unreaped-code" {
            let result = try await worker.result()
            #expect(result.sequence == 51 && result.code == .workerUnreaped)
            #expect(result.prepareCompatibilityCheckpointWait == nil && result.ready == nil)
            #expect(try coordinator.currentBoot().ready == boot.ready)
        } else if fault == "valid" {
            let result = try await worker.result()
            #expect(result.sequence == 51 && result.prepareCompatibilityCheckpointWait == wait)
            #expect(result.ready == nil && result.signed == nil && result.replacement == nil)
            #expect(try coordinator.currentBoot().ready == boot.ready)
            #expect(try coordinator.currentBoot().signed == boot.signed)
        } else {
            await #expect(throws: (any Error).self) { try await worker.result() }
            #expect(throws: (any Error).self) { try coordinator.currentBoot() }
        }
    }

    @Test(arguments: [W.Command.prepareCompatibilityArm, .prepareCompatibilityObserve, .prepareCompatibilityRelease])
    func prepareStatusRejectsStaleQuery(command: W.Command) throws {
        let vector = try WorkerExitVector.load()
        let request = W.Frame(operation: .command, binding: vector.binding, sequence: 1,
            serviceEpoch: vector.arm.arm.scope.serviceEpoch, command: command,
            workerUUID: vector.arm.workerUUID,
            prepareCompatibilityArm: command == .prepareCompatibilityArm ? vector.arm : nil,
            prepareCompatibilityQuery: command == .prepareCompatibilityObserve ? vector.status.query : nil,
            prepareCompatibilityRelease: command == .prepareCompatibilityRelease ? vector.exit : nil)
        var query = vector.status.query
        query.requestID = UUID().uuidString.lowercased()
        let reply = W.Frame(operation: .reply, binding: request.binding, sequence: 1,
            serviceEpoch: request.serviceEpoch, workerUUID: request.workerUUID,
            prepareCompatibilityStatus: .init(query: query, state: "armed"))
        try reply.validate()
        #expect(throws: (any Error).self) {
            try PrivateStorageLifecycleBootCoordinator.validatePrepareReply(reply, for: request)
        }
    }

    @Test(arguments: ["query", "token", "stage", "result", "sequence"])
    func workerExitRejectsDifferentValidEvidence(fault: String) throws {
        let vector = try WorkerExitVector.load()
        let request = W.Frame(operation: .command, binding: vector.binding, sequence: 1,
            serviceEpoch: vector.arm.arm.scope.serviceEpoch, command: .prepareCompatibilityWorkerExit,
            workerUUID: vector.arm.workerUUID, prepareCompatibilityWorkerExit: vector.exit)
        var wait = vector.wait
        if fault == "query" { wait.query.requestID = UUID().uuidString.lowercased() }
        if fault == "token" { wait.token = String(repeating: "f", count: 64) }
        if fault == "stage" { wait.stage = "full-frame-before-admit" }
        let reply = W.Frame(operation: .reply, binding: request.binding,
            sequence: fault == "sequence" ? 2 : 1, serviceEpoch: request.serviceEpoch,
            ok: fault == "result" ? true : nil, workerUUID: request.workerUUID,
            prepareCompatibilityWorkerWait: fault == "result" ? nil : wait)
        try reply.validate() // Valid union/shape is not sufficient correlation.
        #expect(throws: (any Error).self) {
            try PrivateStorageLifecycleBootCoordinator.validatePrepareReply(reply, for: request)
        }
    }
}

extension PrivateStorageLifecycleBootCoordinatorTests {
    @Test(arguments: ["valid", "no-target", "expired", "wrong-operation", "wrong-target", "completed", "completed-mismatch",
                      "pending", "failed", "no-terminal", "controller", "key", "stale-query",
                      "query-open-revision", "query-controller", "query-key", "session-loss"])
    func adoptedServiceChangeRequiresRetainedNativeTerminalAndFreshQuery(fault: String) async throws {
        typealias A = StorageLifecycleAdoptionProtocol
        typealias L = StorageLifecycleProtocol
        let fixture = try await StorageBootFixture.make()
        defer { fixture.close() }
        let uuid = try StorageIdentity.FilesystemUUID(UUID().uuidString.lowercased())
        let binding = try StorageIdentity.StoreBinding(storeID: .init(uuid.rawValue), root: .init(volumeUUID: uuid, inode: 2),
            backing: .init(identity: .init(volumeUUID: uuid, inode: 3), size: 4096), expectedExt4UUID: uuid)
        let material = try LifecycleCertificateFixture(identity: .init(binding: binding, generation: 1))
        let (coordinator, originalBoot) = try await booted(fixture, material)
        defer { coordinator.close() }
        let old = originalBoot.ready, replacement = try material.replacement(predecessor: old)
        let change = try #require(replacement.configuration.reopen).request
        let successor = try material.readyLike(old, serviceEpoch: UUID().uuidString.lowercased(),
            workerUUID: UUID().uuidString.lowercased(), root: .init(), server: .init(), revision: 2, openRevision: 2)
        if fault != "no-terminal" {
            let request = W.Frame(operation: .command, binding: originalBoot.binding, sequence: 41,
                serviceEpoch: old.serviceEpoch, command: .replaceService, workerUUID: old.workerUUID,
                replacementRequest: replacement)
            _ = try await exchange(fixture, coordinator, request) {
                replacementReply($0, .init(request: replacement,
                    phase: fault == "pending" ? .pending : fault == "failed" ? .failed : .succeeded,
                    ready: ["pending", "failed"].contains(fault) ? nil : successor,
                    code: fault == "failed" ? .replacementFailed : nil))
            }
        }
        if ["controller", "key"].contains(fault) {
            let key = fault == "key" ? try LifecycleCertificateFixture.fingerprint(material.successor) : old.controllerKey
            let grant = try L.Grant(operation: .takeover, id: UUID().uuidString.lowercased(), identity: old.identity,
                serial: 2, expectedEpoch: 1, newKey: key)
            let signed = try L.SignedGrant(grant: grant, signature: material.bootstrap.signature(for: grant.signingBytes))
            let request = W.Frame(operation: .command, binding: originalBoot.binding, sequence: 42,
                serviceEpoch: successor.serviceEpoch, command: .reconcileController, signed: signed,
                controller: .init(epoch: 2, key: key), workerUUID: successor.workerUUID)
            let reconciled = try material.readyLike(successor, controllerEpoch: 2, controllerKey: key, revision: 3, openRevision: 2)
            _ = try await exchange(fixture, coordinator, request) {
                .init(operation: .reply, binding: $0.binding, ready: reconciled, sequence: $0.sequence,
                    serviceEpoch: $0.serviceEpoch, workerUUID: $0.workerUUID)
            }
        }
        let adoption = try A.Request(id: UUID().uuidString.lowercased(), origin: .init(binding: .init(binding),
            rootPublicKey: material.configuration.rootPublicKey, shimLaunchUUID: originalBoot.binding.shimLaunchUUID,
            specSHA256: fixture.proof.specificationSHA256), expectedEpoch: 1,
            daemonAudit: Data(repeating: 1, count: 32), daemonUniqueID: 1,
            controllerAudit: Data(repeating: 2, count: 32), controllerUniqueID: 2)
        let boot = try StorageLifecycleBootTrust(identity: successor.identity, serviceEpoch: successor.serviceEpoch,
            tlsRootSHA256: LifecycleCertificateFixture.hex(successor.tlsRootDER), serverSPKI: successor.serverSPKI,
            bootstrapKey: successor.bootstrapKey)
        let target = try fault == "wrong-target" ? StorageLifecycleBootTrust(identity: boot.identity,
            serviceEpoch: UUID().uuidString.lowercased(), tlsRootSHA256: String(repeating: "d", count: 64),
            serverSPKI: String(repeating: "e", count: 64), bootstrapKey: boot.bootstrapKey) : boot
        let state = try L.ServiceState(grant: material.configuration.signed.grant,
            context: .init(serviceEpoch: successor.serviceEpoch, controllerEpoch: successor.controllerEpoch,
                controllerKey: successor.controllerKey), openRevision: fault == "completed-mismatch" ? 3 : 2, boot: boot)
        let challengedChange = try fault == "wrong-operation"
            ? L.ServiceChangeRequest(operationID: UUID().uuidString.lowercased(), predecessor: change.predecessor) : change
        let challenge = try A.ServiceChangeChallenge(adoption: adoption, change: challengedChange,
            targetBoot: fault == "no-target" ? nil : target,
            completed: ["completed", "completed-mismatch"].contains(fault) ? .init(request: change, successor: state) : nil,
            counter: 1, nonce: Data(repeating: 8, count: 32), expiresUnixMS: UInt64(Date().timeIntervalSince1970 * 1000) + (fault == "expired" ? 0 : 20_000))
        if ["expired", "wrong-operation", "wrong-target", "completed-mismatch", "pending", "failed", "no-terminal", "controller", "key"].contains(fault) {
            #expect(throws: (any Error).self) {
                try originalBoot.adoptedServiceChangeProof(challenge, deadline: ProcessInfo.processInfo.systemUptime + 3)
            }
            var byte: UInt8 = 0
            #expect(recv(fixture.pair.guest.fileDescriptor, &byte, 1, MSG_DONTWAIT) < 0)
            _ = try coordinator.currentBoot() // A refused proof does not destroy retained evidence.
            return
        }
        // Original pre-replacement capability is retained by adoption. Only the
        // SAME coordinator's terminal evidence and fresh query authorize proof.
        let worker = StorageBootWorker(cancel: { coordinator.cancel() }) {
            try originalBoot.adoptedServiceChangeProof(challenge, deadline: ProcessInfo.processInfo.systemUptime + 5)
        }
        defer { worker.settle() }
        let sent = try read(fixture.pair.guest)
        #expect(sent.command == .query && sent.sequence == 2)
        #expect(sent.serviceEpoch == successor.serviceEpoch && sent.workerUUID == successor.workerUUID)
        if fault == "session-loss" {
            _ = shutdown(fixture.pair.guest.fileDescriptor, SHUT_RDWR)
        } else {
            let observed = try material.readyLike(successor,
                controllerEpoch: fault == "query-controller" ? 2 : nil,
                controllerKey: fault == "query-key" ? String(repeating: "f", count: 64) : nil,
                revision: 2, openRevision: fault == "query-open-revision" ? 1 : 2)
            try fixture.pair.guest.write(contentsOf: W.encode(.init(operation: .reply, binding: sent.binding,
                ready: observed, sequence: fault == "stale-query" ? 1 : sent.sequence,
                serviceEpoch: sent.serviceEpoch, workerUUID: sent.workerUUID)))
        }
        if !["valid", "no-target", "completed"].contains(fault) {
            await #expect(throws: (any Error).self) { try await worker.result() }
            #expect(throws: (any Error).self) { try coordinator.currentBoot() }
            return
        }
        let proof = try await worker.result()
        #expect(proof.boot == boot && proof.result.nonce == challenge.nonce)
        #expect(try A.decodeServiceChangeReply(A.encode(proof), challenge: challenge) == proof)
        #expect(try coordinator.currentBoot().configuration == replacement.configuration)
        for crossOperation in [false, true] {
            let other = try A.ServiceChangeChallenge(adoption: adoption,
                change: crossOperation ? .init(operationID: UUID().uuidString.lowercased(), predecessor: change.predecessor) : change,
                targetBoot: boot, completed: nil, counter: 2,
                nonce: crossOperation ? challenge.nonce : Data(repeating: 9, count: 32), expiresUnixMS: challenge.expiresUnixMS)
            #expect(throws: (any Error).self) { try A.decodeServiceChangeReply(A.encode(proof), challenge: other) }
        }
        let service = try A.ServiceChallenge(adoption: adoption, grant: state.grant, expected: state,
            counter: 1, nonce: challenge.nonce, expiresUnixMS: challenge.expiresUnixMS)
        #expect(throws: (any Error).self) { try A.decodeServiceReply(A.encode(proof), challenge: service) }
    }
}

/// Public test DER only. Canonical requestInfo/extensionRequest matches
/// Guest/internal/storagepki/csr.go; no runtime test signing API is exposed.
private struct LifecycleCertificateFixture {
    typealias Key = Curve25519.Signing.PrivateKey
    let bootstrap = Key(), root = Key(), server = Key(), controller = Key(), successor = Key()
    let configuration: StorageLifecycleServiceBootProtocol.Configuration
    let ready: StorageLifecycleServiceBootProtocol.Ready
    private static let algorithm = Data([0x30, 5, 6, 3, 0x2b, 0x65, 0x70])
    private static func der(_ tag: UInt8, _ body: Data) -> Data {
        let n = body.count
        let length: [UInt8] = n < 128 ? [UInt8(n)] : n < 256 ? [0x81, UInt8(n)] : [0x82, UInt8(n >> 8), UInt8(n & 255)]
        return Data([tag] + length) + body
    }
    private static func spki(_ key: Key) throws -> Data {
        try StorageIdentity.Ed25519SPKI(rawPublicKey: key.publicKey.rawRepresentation).publicData
    }
    static func fingerprint(_ key: Key) throws -> String {
        try StorageIdentity.Ed25519SPKI(publicData: spki(key)).fingerprint.rawValue
    }
    private static func san(_ uri: String, extra: Bool = false) -> Data {
        der(0x30, der(0x86, Data(uri.utf8)) + (extra ? der(0x86, Data((uri + "0").utf8)) : Data()))
    }
    private static func sanExtension(_ uri: String, extra: Bool = false) -> Data {
        der(0x30, Data([6, 3, 0x55, 0x1d, 0x11]) + der(4, san(uri, extra: extra)))
    }
    func csr(key: Key, uri: String, hiddenAttribute: Bool = false) throws -> Data {
        let attribute = Self.der(0x30, Data([6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 0x0e])
            + Self.der(0x31, Self.der(0x30, Self.sanExtension(uri))))
        let info = try Self.der(0x30, Data([2, 1, 0, 0x30, 0]) + Self.spki(key)
            + Self.der(0xa0, attribute + (hiddenAttribute ? attribute : Data())))
        return try Self.der(0x30, info + Self.algorithm + Self.der(3, Data([0]) + key.signature(for: info)))
    }
    func certificate(key: Key, issuer: Key, uri: String, extraSAN: Bool = false) throws -> Data {
        try Self.certificate(key: key, issuer: issuer, uri: uri, extraSAN: extraSAN)
    }
    private static func certificate(key: Key, issuer: Key, uri: String, extraSAN: Bool = false, ca: Bool = false) throws -> Data {
        let name = der(0x30, der(0x31, der(0x30, Data([6, 3, 0x55, 4, 3]) + der(0x0c, Data("test TLS CA".utf8)))))
        let validity = der(0x30, der(0x17, Data("270115080000Z".utf8)) + der(0x17, Data("270115090000Z".utf8)))
        let constraints = der(0x30, Data([6, 3, 0x55, 0x1d, 0x13, 1, 1, 0xff])
            + der(4, der(0x30, ca ? Data([1, 1, 0xff, 2, 1, 0]) : Data())))
        let usage = Data([0x30, 0x0e, 6, 3, 0x55, 0x1d, 0x0f, 1, 1, 0xff, 4, 4, 3, 2, ca ? 2 : 7, ca ? 4 : 0x80])
        let eku = Data([0x30, 0x13, 6, 3, 0x55, 0x1d, 0x25, 4, 0x0c, 0x30, 0x0a, 6, 8, 0x2b, 6, 1, 5, 5, 7, 3, 2])
        let extensions = der(0xa3, der(0x30, constraints + usage + (ca ? Data() : eku + sanExtension(uri, extra: extraSAN))))
        let tbs = try der(0x30, Data([0xa0, 3, 2, 1, 2, 2, 1, 1]) + algorithm + name + validity
            + (ca ? name : Data([0x30, 0])) + spki(key) + extensions)
        return try der(0x30, tbs + algorithm + der(3, Data([0]) + issuer.signature(for: tbs)))
    }
    typealias Wire = StorageLifecycleServiceBootProtocol
    static func hex(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
    func readyLike(_ r: Wire.Ready, serviceEpoch: String? = nil, workerUUID: String? = nil, root newRoot: Key? = nil, server newServer: Key? = nil,
                   controllerEpoch: UInt64? = nil, controllerKey: String? = nil, revision: UInt64, openRevision: UInt64) throws -> Wire.Ready {
        let epoch = serviceEpoch ?? r.serviceEpoch
        let tlsRoot = try newRoot.map { try Self.certificate(key: $0, issuer: $0, uri: "", ca: true) } ?? r.tlsRootDER
        let serverDER = try newServer.map { try Self.certificate(key: $0, issuer: newRoot ?? root,
            uri: "spiffe://cengine.storage/store/\(r.identity.store)/server/\(epoch)") } ?? r.serverDER
        return try .init(identity: r.identity, serviceEpoch: epoch, workerUUID: workerUUID ?? r.workerUUID,
            controllerEpoch: controllerEpoch ?? r.controllerEpoch, controllerKey: controllerKey ?? r.controllerKey,
            revision: revision, openRevision: openRevision, bootstrapKey: r.bootstrapKey, tlsRootDER: tlsRoot,
            serverDER: serverDER, serverSPKI: try newServer.map { try Self.fingerprint($0) } ?? r.serverSPKI)
    }
    /// ROOT-signed open reopen naming `predecessor` as the current service state.
    func replacement(predecessor r: Wire.Ready, operationID: String = UUID().uuidString.lowercased()) throws -> Wire.ReplacementRequest {
        let trust = try StorageLifecycleBootTrust(identity: r.identity, serviceEpoch: r.serviceEpoch,
            tlsRootSHA256: Self.hex(r.tlsRootDER), serverSPKI: r.serverSPKI, bootstrapKey: r.bootstrapKey)
        let state = try StorageLifecycleProtocol.ServiceState(grant: configuration.signed.grant,
            context: .init(serviceEpoch: r.serviceEpoch, controllerEpoch: r.controllerEpoch, controllerKey: r.controllerKey),
            openRevision: r.openRevision, boot: trust)
        let request = try StorageLifecycleProtocol.ServiceChangeRequest(operationID: operationID, predecessor: state)
        let reopen = try StorageLifecycleProtocol.SignedServiceChange(request: request, signature: bootstrap.signature(for: request.signingBytes))
        return .init(predecessorWorkerUUID: r.workerUUID, configuration: .init(action: .open, rootPublicKey: configuration.rootPublicKey,
            signed: configuration.signed, nowUnixSeconds: configuration.nowUnixSeconds, lifetimeSeconds: configuration.lifetimeSeconds, reopen: reopen))
    }
    init(store: String = UUID().uuidString.lowercased(), serviceEpoch: String = UUID().uuidString.lowercased(),
         workerUUID: String = UUID().uuidString.lowercased(), identity suppliedIdentity: StorageLifecycleProtocol.Identity? = nil) throws {
        let identity = try suppliedIdentity ?? StorageLifecycleProtocol.Identity(store: store, generation: 1, binding: String(repeating: "a", count: 64))
        let grant = try StorageLifecycleProtocol.Grant(operation: .initialize, id: UUID().uuidString.lowercased(), identity: identity,
            serial: 1, expectedEpoch: 0, newKey: Self.fingerprint(controller))
        configuration = try .init(action: .initialize, rootPublicKey: bootstrap.publicKey.rawRepresentation,
            signed: .init(grant: grant, signature: bootstrap.signature(for: grant.signingBytes)), nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        ready = try .init(identity: identity, serviceEpoch: serviceEpoch, workerUUID: workerUUID,
            controllerEpoch: 1, controllerKey: Self.fingerprint(controller), revision: 1, openRevision: 1, bootstrapKey: Self.fingerprint(bootstrap),
            tlsRootDER: Self.certificate(key: root, issuer: root, uri: "", ca: true),
            serverDER: Self.certificate(key: server, issuer: root, uri: "spiffe://cengine.storage/store/\(identity.store)/server/\(serviceEpoch)"),
            serverSPKI: Self.fingerprint(server))
    }
}
#endif


#if os(macOS)
extension PrivateStorageLifecycleBootCoordinatorTests {
    @Test(arguments: [W.Command.consumerObservationArm, .consumerObservationQuery, .consumerObservationFinalize],
          ["valid", "query", "state", "sequence", "binding", "epoch", "worker", "wrong-result", "code", "mixed-code"])
    func consumerObservationUsesCorrelatedPrivateSession(command: W.Command, fault: String) async throws {
        let fixture = try await StorageBootFixture.make()
        defer { fixture.close() }
        let material = try LifecycleCertificateFixture()
        let (coordinator, boot) = try await booted(fixture, material)
        defer { coordinator.close() }
        let arm = StorageLifecycleServiceBootProtocolTests.consumerArm(store: boot.identity.store,
            epoch: boot.ready.serviceEpoch, worker: boot.ready.workerUUID)
        let request = W.Frame(operation: .command, binding: boot.binding, sequence: 41,
            serviceEpoch: boot.ready.serviceEpoch, command: command, workerUUID: boot.ready.workerUUID,
            consumerObservationArm: command == .consumerObservationArm ? arm : nil,
            consumerObservationQuery: command == .consumerObservationArm ? nil : arm)
        let worker = StorageBootWorker(cancel: { coordinator.cancel() }) { try coordinator.command(request) }
        defer { worker.settle() }
        let sent = try read(fixture.pair.guest)
        #expect(sent.sequence == 1 && sent.command == command)
        #expect(sent.consumerObservationArm == request.consumerObservationArm)
        #expect(sent.consumerObservationQuery == request.consumerObservationQuery)
        let state: ConsumerObservationProtocol.State = command == .consumerObservationArm ? .armed
            : command == .consumerObservationFinalize ? .finalized : .observed
        var status = StorageLifecycleServiceBootProtocolTests.consumerStatus(arm,
            state: fault == "state" ? .claimed : state)
        if fault == "query" { status.query.requestID = UUID().uuidString.lowercased() }
        var binding = sent.binding
        if fault == "binding" { binding.guestBootNonce = UUID().uuidString.lowercased() }
        let reply = W.Frame(operation: .reply, binding: binding,
            sequence: fault == "sequence" ? 2 : sent.sequence,
            serviceEpoch: fault == "epoch" ? UUID().uuidString.lowercased() : sent.serviceEpoch,
            ok: fault == "wrong-result" ? true : nil,
            code: ["code", "mixed-code"].contains(fault) ? .command : nil,
            workerUUID: fault == "worker" ? UUID().uuidString.lowercased() : sent.workerUUID,
            consumerObservationStatus: ["wrong-result", "code"].contains(fault) ? nil : status)
        // Exercise ingress validation, including deliberately malformed unions.
        let body = try StorageLifecycleProtocol.encode(reply)
        var count = UInt32(body.count).bigEndian
        try fixture.pair.guest.write(contentsOf: Data(bytes: &count, count: 4) + body)
        if fault == "valid" || fault == "code" || (fault == "state" && command == .consumerObservationQuery) {
            let result = try await worker.result()
            #expect(result.sequence == 41)
            #expect(result.consumerObservationStatus == (fault == "code" ? nil : status))
            #expect(result.code == (fault == "code" ? .command : nil))
            #expect(result.ready == nil && result.signed == nil && result.replacement == nil)
            let current = try coordinator.currentBoot()
            #expect(current.ready == boot.ready && current.signed == boot.signed && current.configuration == boot.configuration)
        } else {
            await #expect(throws: (any Error).self) { try await worker.result() }
            #expect(throws: (any Error).self) { try coordinator.currentBoot() }
        }
    }
    @Test(arguments: [W.Command.consumerObservationArm, .consumerObservationQuery, .consumerObservationFinalize])
    func consumerObservationRejectsOtherStoreBeforeIO(command: W.Command) async throws {
        let fixture = try await StorageBootFixture.make()
        defer { fixture.close() }
        let material = try LifecycleCertificateFixture()
        let (coordinator, boot) = try await booted(fixture, material)
        defer { coordinator.close() }
        let arm = StorageLifecycleServiceBootProtocolTests.consumerArm(store: UUID().uuidString.lowercased(),
            epoch: boot.ready.serviceEpoch, worker: boot.ready.workerUUID)
        let request = W.Frame(operation: .command, binding: boot.binding, sequence: 41,
            serviceEpoch: boot.ready.serviceEpoch, command: command, workerUUID: boot.ready.workerUUID,
            consumerObservationArm: command == .consumerObservationArm ? arm : nil,
            consumerObservationQuery: command == .consumerObservationArm ? nil : arm)
        try request.validate() // Store correlation requires the live private capability.
        #expect(throws: (any Error).self) { try coordinator.command(request) }
        var byte: UInt8 = 0
        #expect(recv(fixture.pair.guest.fileDescriptor, &byte, 1, MSG_DONTWAIT) == -1)
        #expect(errno == EAGAIN)
        #expect(try coordinator.currentBoot().ready == boot.ready)
    }
}
#endif

#if os(macOS)
extension PrivateStorageLifecycleBootCoordinatorTests {
    @Test(arguments: [W.Command.isolationState, .legacyConnection, .secondServiceExclusivity],
          ["valid", "requestID", "operationUUID", "armDigest", "challenge", "binding", "sequence", "epoch", "worker", "store", "revision", "case"])
    func isolationReplyCorrelation(command: W.Command, fault: String) throws {
        var (request, reply) = try StorageLifecycleServiceBootProtocolTests.isolationFrames(command)
        let ready = try #require(StorageLifecycleServiceBootProtocolTests.vectors()[2].ready)
        let other = "ffffffff-ffff-4fff-8fff-ffffffffffff"
        switch fault {
        case "binding": reply.binding.guestBootNonce = other
        case "sequence": reply.sequence = 1
        case "epoch": request.serviceEpoch = other
        case "worker": request.workerUUID = other
        case "case": request.command = command == .isolationState ? .legacyConnection : .isolationState
        case "requestID", "operationUUID", "armDigest", "challenge", "store", "revision":
            let proof = try #require(reply.isolationProof)
            var object = try #require(JSONSerialization.jsonObject(with: W.L.encode(proof)) as? [String: Any])
            if fault == "store" { object["store"] = other }
            else if fault == "revision" { object["revision"] = 0 }
            else {
                var claim = try #require(object["request"] as? [String: Any])
                claim[fault] = fault == "armDigest" ? String(repeating: "f", count: 64) : other
                object["request"] = claim
            }
            reply.isolationProof = try JSONDecoder().decode(W.IsolationProof.self, from: JSONSerialization.data(withJSONObject: object))
        default: break
        }
        if fault == "valid" {
            try PrivateStorageLifecycleBootCoordinator.validateIsolationReply(reply, for: request, current: ready)
        } else {
            #expect(throws: (any Error).self) {
                try PrivateStorageLifecycleBootCoordinator.validateIsolationReply(reply, for: request, current: ready)
            }
        }
    }

    @Test(arguments: [false, true])
    func isolationExchangeNeverAdvancesReady(staleRevision: Bool) async throws {
        let fixture = try await StorageBootFixture.make()
        defer { fixture.close() }
        let material = try LifecycleCertificateFixture()
        let (coordinator, boot) = try await booted(fixture, material)
        defer { coordinator.close() }
        // Establish a revision floor above one, independently of the observation.
        let ready = try material.readyLike(boot.ready, revision: 2, openRevision: boot.ready.openRevision)
        let query = W.Frame(operation: .command, binding: boot.binding, sequence: 7,
            serviceEpoch: ready.serviceEpoch, command: .query, workerUUID: ready.workerUUID)
        _ = try await exchange(fixture, coordinator, query) {
            .init(operation: .reply, binding: $0.binding, ready: ready, sequence: $0.sequence,
                serviceEpoch: $0.serviceEpoch, workerUUID: $0.workerUUID)
        }
        let before = try coordinator.currentBoot(), trust = try before.trust(for: before.signed.grant)
        for command in [W.Command.isolationState, .legacyConnection, .secondServiceExclusivity] {
            let (template, response) = try StorageLifecycleServiceBootProtocolTests.isolationFrames(command,
                revision: staleRevision ? 1 : .max)
            var request = template
            request.binding = boot.binding; request.serviceEpoch = ready.serviceEpoch; request.workerUUID = ready.workerUUID
            var object = try #require(JSONSerialization.jsonObject(with: W.L.encode(response.isolationProof)) as? [String: Any])
            object["store"] = ready.identity.store; object["serviceEpoch"] = ready.serviceEpoch; object["workerUUID"] = ready.workerUUID
            let proof = try JSONDecoder().decode(W.IsolationProof.self, from: JSONSerialization.data(withJSONObject: object))
            do {
                let reply = try await exchange(fixture, coordinator, request) {
                    .init(operation: .reply, binding: $0.binding, sequence: $0.sequence,
                        serviceEpoch: $0.serviceEpoch, workerUUID: $0.workerUUID, isolationProof: proof)
                }
                #expect(!staleRevision)
                #expect(reply.isolationProof == proof && reply.sequence == request.sequence)
                let after = try coordinator.currentBoot()
                #expect(after.ready == before.ready && after.signed == before.signed && after.configuration == before.configuration)
                #expect(try after.trust(for: after.signed.grant) == trust)
            } catch {
                #expect(staleRevision)
                #expect(throws: (any Error).self) { try coordinator.currentBoot() }
                return
            }
        }
    }
}
#endif

#if os(macOS)
extension PrivateStorageLifecycleBootCoordinatorTests {
    @Test(arguments: ["unapplied", "committed", "busy", "busy-direct", "busy-exhausted", "command", "drop", "nonce", "tls", "expired", "late", "missing-signed", "replacement",
                      "timeout", "partial-header", "partial-body", "drain-sequence", "drain-nonce", "drain-binding",
                      "drain-tls", "drain-frame", "drain-eof", "drain-command", "drain-busy", "drain-busy-sequence", "drain-busy-binding", "changed-fence", "bad-signature"])
    func registeredHandoffUsesOriginalCapabilityAndExactSignedCache(fault: String) async throws {
        typealias H = StorageLifecycleHandoffProtocol
        typealias S = StorageLifecycleHandoffShimProtocol
        typealias L = StorageLifecycleProtocol
        let fixture = try await StorageBootFixture.make()
        defer { fixture.close() }
        let uuid = try StorageIdentity.FilesystemUUID(UUID().uuidString.lowercased())
        let binding = try StorageIdentity.StoreBinding(storeID: .init(uuid.rawValue), root: .init(volumeUUID: uuid, inode: 2),
            backing: .init(identity: .init(volumeUUID: uuid, inode: 3), size: 4096), expectedExt4UUID: uuid)
        let material = try LifecycleCertificateFixture(identity: .init(binding: binding, generation: 1))
        let (coordinator, original) = try await booted(fixture, material)
        defer { coordinator.close() }
        let old = original.ready
        let pending = try L.Grant(operation: .takeover, id: UUID().uuidString.lowercased(), identity: old.identity,
            serial: 2, expectedEpoch: 1, newKey: LifecycleCertificateFixture.fingerprint(material.successor))
        let signed = try L.SignedGrant(grant: pending, signature: material.bootstrap.signature(for: pending.signingBytes))
        let uri = "spiffe://cengine.storage/store/\(old.identity.store)/controller/2"
        if fault != "missing-signed" {
            let authorize = try W.Frame(operation: .command, binding: original.binding, sequence: 1,
                serviceEpoch: old.serviceEpoch, command: .authorizeSuccessor,
                csr: material.csr(key: material.successor, uri: uri), signed: signed, workerUUID: old.workerUUID)
            let certificate = try material.certificate(key: material.successor, issuer: material.root, uri: uri)
            _ = try await exchange(fixture, coordinator, authorize) {
                .init(operation: .reply, binding: $0.binding, sequence: $0.sequence, serviceEpoch: $0.serviceEpoch,
                    certificate: certificate, workerUUID: $0.workerUUID)
            }
        }
        let request = try H.Request(operationID: UUID().uuidString.lowercased(), predecessor: original.signed.grant,
            pending: pending, serviceEpoch: old.serviceEpoch, openRevision: old.openRevision)
        let handoff = try H.SignedRequest(request: request, signature: material.bootstrap.signature(for: request.signingBytes))
        let origin = try StorageLifecycleAdoptionProtocol.Origin(binding: .init(binding), rootPublicKey: original.rootPublicKey.publicData,
            shimLaunchUUID: original.binding.shimLaunchUUID, specSHA256: fixture.proof.specificationSHA256)
        let expected = try L.ServiceState(grant: original.signed.grant,
            context: .init(serviceEpoch: old.serviceEpoch, controllerEpoch: old.controllerEpoch, controllerKey: old.controllerKey),
            openRevision: old.openRevision, boot: original.trust(for: original.signed.grant))
        let receiveTimeout = ["timeout", "partial-header", "partial-body", "drain-sequence", "drain-nonce", "drain-binding",
                              "drain-tls", "drain-frame", "drain-eof", "drain-command", "drain-busy", "drain-busy-sequence", "drain-busy-binding", "changed-fence", "bad-signature"].contains(fault)
        let now = UInt64(Date().timeIntervalSince1970 * 1000)
        let challenge = try S.Challenge(origin: origin, signed: handoff, expected: expected, counter: 1,
            nonce: Data(repeating: 8, count: 32), expiresUnixMS: now + (fault == "expired" ? 0 : fault == "late" ? 300 : 20_000))
        if fault == "replacement" {
            let replacement = try material.replacement(predecessor: old)
            let command = W.Frame(operation: .command, binding: original.binding, sequence: 1,
                serviceEpoch: old.serviceEpoch, command: .replaceService, workerUUID: old.workerUUID, replacementRequest: replacement)
            _ = try await exchange(fixture, coordinator, command) {
                replacementReply($0, .init(request: replacement, phase: .pending))
            }
        }
        if ["expired", "replacement"].contains(fault) {
            #expect(throws: (any Error).self) { try original.handoffProof(challenge, deadline: ProcessInfo.processInfo.systemUptime + 2) }
            #expect(try coordinator.currentBoot().ready == old)
            return
        }
        let committed = fault != "unapplied"
        let applied = committed ? pending : original.signed.grant
        let actual = try material.readyLike(old, root: fault == "tls" ? .init() : nil,
            controllerEpoch: applied.expectedEpoch + 1, controllerKey: applied.newKey, revision: 3, openRevision: 1)
        let result = try H.Result(request: request, nonce: fault == "nonce" ? Data(repeating: 9, count: 32) : challenge.nonce,
            appliedGrant: applied, appliedServiceEpoch: old.serviceEpoch, appliedRevision: committed ? 2 : 1, fenceRevision: 3)
        func expectLogicalFence() throws {
            let query = W.Frame(operation: .command, binding: original.binding, sequence: 42,
                serviceEpoch: old.serviceEpoch, command: .query, workerUUID: old.workerUUID)
            #expect(throws: PrivateStorageLifecycleBootCoordinator.HandoffFailure.busy) { try coordinator.command(query) }
            let replacement = W.Frame(operation: .command, binding: original.binding, sequence: 43,
                serviceEpoch: old.serviceEpoch, command: .replaceService, workerUUID: old.workerUUID,
                replacementRequest: try material.replacement(predecessor: old))
            #expect(throws: PrivateStorageLifecycleBootCoordinator.HandoffFailure.busy) { try coordinator.command(replacement) }
            let changed = try H.Request(operationID: UUID().uuidString.lowercased(), predecessor: request.predecessor,
                pending: pending, serviceEpoch: old.serviceEpoch, openRevision: old.openRevision)
            for other in [try H.SignedRequest(request: changed, signature: material.bootstrap.signature(for: changed.signingBytes)),
                          try H.SignedRequest(request: request, signature: Data(repeating: 0, count: 64))] {
                let refused = W.Frame(operation: .command, binding: original.binding, sequence: 44,
                    serviceEpoch: old.serviceEpoch, command: .fenceHandoff, workerUUID: old.workerUUID,
                    handoff: other, nonce: Data(repeating: 9, count: 32))
                #expect(throws: PrivateStorageLifecycleBootCoordinator.HandoffFailure.busy) { try coordinator.command(refused) }
            }
            var byte: UInt8 = 0
            #expect(recv(fixture.pair.guest.fileDescriptor, &byte, 1, MSG_DONTWAIT) == -1)
            #expect(errno == EAGAIN)
            #expect(try coordinator.currentBoot().ready == old)
        }
        if fault == "busy-direct" {
            let direct = W.Frame(operation: .command, binding: original.binding, sequence: 1,
                serviceEpoch: old.serviceEpoch, command: .fenceHandoff, workerUUID: old.workerUUID,
                handoff: handoff, nonce: Data(repeating: 7, count: 32))
            let busy = try await exchange(fixture, coordinator, direct) {
                .init(operation: .reply, binding: $0.binding, sequence: $0.sequence,
                    serviceEpoch: $0.serviceEpoch, code: .workerBusy, workerUUID: $0.workerUUID)
            }
            #expect(busy.code == .workerBusy)
            try expectLogicalFence()
        }
        let worker = StorageBootWorker(cancel: { coordinator.cancel() }) {
            try original.handoffProof(challenge, deadline: ProcessInfo.processInfo.systemUptime + (receiveTimeout ? 0.3 : 2))
        }
        defer { worker.settle() }
        if receiveTimeout {
            let sent = try read(fixture.pair.guest)
            #expect(sent.command == .fenceHandoff && sent.nonce == challenge.nonce)
            var originalReply = W.Frame(operation: .reply, binding: sent.binding, sequence: sent.sequence,
                serviceEpoch: sent.serviceEpoch, workerUUID: sent.workerUUID,
                handoffResult: .init(result: result, ready: actual))
            if ["drain-command", "drain-busy", "drain-busy-sequence", "drain-busy-binding"].contains(fault) {
                originalReply.handoffResult = nil
                originalReply.code = fault == "drain-command" ? .command : .workerBusy
            }
            if fault == "drain-busy-sequence" { originalReply.sequence = try #require(sent.sequence) + 1 }
            if fault == "drain-busy-binding" { originalReply.binding.guestBootNonce = UUID().uuidString.lowercased() }
            if fault == "drain-sequence" { originalReply.sequence = try #require(sent.sequence) + 1 }
            if fault == "drain-binding" { originalReply.binding.guestBootNonce = UUID().uuidString.lowercased() }
            if fault == "drain-nonce" {
                originalReply.handoffResult = .init(result: try H.Result(request: request,
                    nonce: Data(repeating: 9, count: 32), appliedGrant: applied, appliedServiceEpoch: old.serviceEpoch,
                    appliedRevision: 2, fenceRevision: 3), ready: actual)
            }
            if fault == "drain-tls" {
                originalReply.handoffResult = .init(result: result,
                    ready: try material.readyLike(actual, root: .init(), revision: 3, openRevision: 1))
            }
            let encoded = try W.encode(originalReply)
            let prefix = fault == "partial-header" ? 2 : fault == "partial-body" ? 12 : 0
            if prefix > 0 { try fixture.pair.guest.write(contentsOf: encoded.prefix(prefix)) }
            await #expect(throws: PrivateStorageLifecycleBootCoordinator.HandoffFailure.busy) { try await worker.result() }
            #expect(try coordinator.currentBoot().ready == old)
            #expect(throws: PrivateStorageLifecycleBootCoordinator.HandoffFailure.busy) {
                try original.handoffProof(challenge, deadline: ProcessInfo.processInfo.systemUptime + 2)
            }
            // The stream remains open, but no query/replacement may race the
            // uncertain fence, and no second request is written before draining.
            let query = W.Frame(operation: .command, binding: original.binding, sequence: 42,
                serviceEpoch: old.serviceEpoch, command: .query, workerUUID: old.workerUUID)
            #expect(throws: PrivateStorageLifecycleBootCoordinator.HandoffFailure.busy) { try coordinator.command(query) }
            let replacement = W.Frame(operation: .command, binding: original.binding, sequence: 43,
                serviceEpoch: old.serviceEpoch, command: .replaceService, workerUUID: old.workerUUID,
                replacementRequest: try material.replacement(predecessor: old))
            #expect(throws: PrivateStorageLifecycleBootCoordinator.HandoffFailure.busy) { try coordinator.command(replacement) }
            if fault == "changed-fence" || fault == "bad-signature" {
                let changed = try H.Request(operationID: UUID().uuidString.lowercased(), predecessor: original.signed.grant,
                    pending: pending, serviceEpoch: old.serviceEpoch, openRevision: old.openRevision)
                let other = try H.SignedRequest(request: fault == "changed-fence" ? changed : request,
                    signature: fault == "changed-fence" ? material.bootstrap.signature(for: changed.signingBytes) : Data(repeating: 0, count: 64))
                let refused = W.Frame(operation: .command, binding: original.binding, sequence: 44,
                    serviceEpoch: old.serviceEpoch, command: .fenceHandoff, workerUUID: old.workerUUID,
                    handoff: other, nonce: Data(repeating: 9, count: 32))
                #expect(throws: (any Error).self) { try coordinator.command(refused) }
                #expect(try coordinator.currentBoot().ready == old)
            }
            var byte: UInt8 = 0
            #expect(recv(fixture.pair.guest.fileDescriptor, &byte, 1, MSG_DONTWAIT) == -1)
            #expect(errno == EAGAIN)
            let fresh = try S.Challenge(origin: origin, signed: handoff, expected: expected, counter: 2,
                nonce: Data(repeating: 9, count: 32), expiresUnixMS: UInt64(Date().timeIntervalSince1970 * 1000) + 20_000)
            if fault == "timeout" {
                let stillPending = StorageBootWorker(cancel: { coordinator.cancel() }) {
                    try original.handoffProof(fresh, deadline: ProcessInfo.processInfo.systemUptime + 0.1)
                }
                defer { stillPending.settle() }
                await #expect(throws: PrivateStorageLifecycleBootCoordinator.HandoffFailure.busy) { try await stillPending.result() }
                #expect(try coordinator.currentBoot().ready == old)
                #expect(recv(fixture.pair.guest.fileDescriptor, &byte, 1, MSG_DONTWAIT) == -1)
                #expect(errno == EAGAIN)
            }
            let recovery = StorageBootWorker(cancel: { coordinator.cancel() }) {
                try original.handoffProof(fresh, deadline: ProcessInfo.processInfo.systemUptime + 2)
            }
            defer { recovery.settle() }
            // If a new command is emitted while the old reply is withheld, fail.
            #expect(!recovery.finishedWithin(0.05))
            #expect(recv(fixture.pair.guest.fileDescriptor, &byte, 1, MSG_DONTWAIT) == -1)
            #expect(errno == EAGAIN)
            if fault == "drain-eof" {
                _ = shutdown(fixture.pair.guest.fileDescriptor, SHUT_RDWR)
            } else if fault == "drain-frame" {
                try fixture.pair.guest.write(contentsOf: Data([0, 0, 0, 1, 123]))
            } else {
                try fixture.pair.guest.write(contentsOf: encoded.dropFirst(prefix))
            }
            if fault.hasPrefix("drain-") && fault != "drain-busy" {
                await #expect(throws: (any Error).self) { try await recovery.result() }
                #expect(throws: (any Error).self) { try coordinator.currentBoot() }
                return
            }
            let next = try read(fixture.pair.guest)
            #expect(next.sequence == sent.sequence.map { $0 + 1 })
            #expect(next.handoff == sent.handoff && next.nonce == fresh.nonce && next.nonce != sent.nonce)
            #expect(try coordinator.currentBoot().ready == (fault == "drain-busy" ? old : actual))
            #expect(try coordinator.currentBoot().signed == (fault == "drain-busy" ? original.signed : signed))
            let freshResult = try H.Result(request: request, nonce: fresh.nonce, appliedGrant: applied,
                appliedServiceEpoch: old.serviceEpoch, appliedRevision: 2, fenceRevision: 3)
            try fixture.pair.guest.write(contentsOf: W.encode(.init(operation: .reply, binding: next.binding,
                sequence: next.sequence, serviceEpoch: next.serviceEpoch, workerUUID: next.workerUUID,
                handoffResult: .init(result: freshResult, ready: actual))))
            let proof = try await recovery.result()
            #expect(proof.result == freshResult)
            #expect(throws: (any Error).self) { try proof.validate(challenge) }
            return
        }
        let attempts = fault == "busy-exhausted" ? 8 : fault == "busy" ? 3 : 1
        for index in 0..<attempts {
            let sent = try read(fixture.pair.guest)
            #expect(sent.command == .fenceHandoff && sent.handoff == handoff && sent.nonce == challenge.nonce)
            if fault == "drop" { _ = shutdown(fixture.pair.guest.fileDescriptor, SHUT_RDWR); break }
            if fault == "late" { try await Task.sleep(for: .milliseconds(400)) }
            let busy = fault == "busy-exhausted" || (fault == "busy" && index < 2)
            try fixture.pair.guest.write(contentsOf: W.encode(.init(operation: .reply, binding: sent.binding,
                sequence: sent.sequence, serviceEpoch: sent.serviceEpoch,
                code: busy ? .workerBusy : fault == "command" ? .command : nil, workerUUID: sent.workerUUID,
                handoffResult: busy || fault == "command" ? nil : .init(result: result, ready: actual))))
        }
        if fault == "late" || fault == "busy-exhausted" {
            await #expect(throws: PrivateStorageLifecycleBootCoordinator.HandoffFailure.busy) { try await worker.result() }
            if fault == "busy-exhausted" {
                try expectLogicalFence()
            } else {
                #expect(try coordinator.currentBoot().ready == actual)
                #expect(try coordinator.currentBoot().signed == signed)
                // An expired but fully validated proof reconciles and clears the
                // logical fence without publishing the expired outer proof.
                let query = W.Frame(operation: .command, binding: original.binding, sequence: 45,
                    serviceEpoch: old.serviceEpoch, command: .query, workerUUID: old.workerUUID)
                _ = try await exchange(fixture, coordinator, query) {
                    .init(operation: .reply, binding: $0.binding, ready: actual, sequence: $0.sequence,
                        serviceEpoch: $0.serviceEpoch, workerUUID: $0.workerUUID)
                }
            }
            let fresh = try S.Challenge(origin: origin, signed: handoff, expected: expected, counter: 2,
                nonce: Data(repeating: 9, count: 32), expiresUnixMS: UInt64(Date().timeIntervalSince1970 * 1000) + 20_000)
            let retry = StorageBootWorker(cancel: { coordinator.cancel() }) {
                try original.handoffProof(fresh, deadline: ProcessInfo.processInfo.systemUptime + 2)
            }
            defer { retry.settle() }
            let sent = try read(fixture.pair.guest)
            #expect(sent.nonce == fresh.nonce && sent.handoff == handoff)
            let freshResult = try H.Result(request: request, nonce: fresh.nonce, appliedGrant: applied,
                appliedServiceEpoch: old.serviceEpoch, appliedRevision: 2, fenceRevision: 3)
            try fixture.pair.guest.write(contentsOf: W.encode(.init(operation: .reply, binding: sent.binding,
                sequence: sent.sequence, serviceEpoch: sent.serviceEpoch, workerUUID: sent.workerUUID,
                handoffResult: .init(result: freshResult, ready: actual))))
            let proof = try await retry.result()
            #expect(proof.result == freshResult)
            #expect(throws: (any Error).self) { try proof.validate(challenge) }
            let query = W.Frame(operation: .command, binding: original.binding, sequence: 46,
                serviceEpoch: old.serviceEpoch, command: .query, workerUUID: old.workerUUID)
            let observed = try await exchange(fixture, coordinator, query) {
                .init(operation: .reply, binding: $0.binding, ready: actual, sequence: $0.sequence,
                    serviceEpoch: $0.serviceEpoch, workerUUID: $0.workerUUID)
            }
            #expect(observed.ready == actual)
            return
        }
        if ["command", "drop", "nonce", "tls", "missing-signed"].contains(fault) {
            await #expect(throws: (any Error).self) { try await worker.result() }
            #expect(throws: (any Error).self) { try coordinator.currentBoot() }
            return
        }
        let proof = try await worker.result()
        #expect(proof.result == result && proof.boot == expected.boot)
        let current = try coordinator.currentBoot()
        #expect(current.ready == actual && current.signed == (committed ? signed : original.signed))
        #expect(current.configuration == original.configuration)
        // A dropped outer reply can be retried on the same original capability,
        // even though the cache has already advanced. No fabricated signature.
        let retry = StorageBootWorker(cancel: { coordinator.cancel() }) {
            try original.handoffProof(challenge, deadline: ProcessInfo.processInfo.systemUptime + 2)
        }
        defer { retry.settle() }
        let sent = try read(fixture.pair.guest)
        try fixture.pair.guest.write(contentsOf: W.encode(.init(operation: .reply, binding: sent.binding,
            sequence: sent.sequence, serviceEpoch: sent.serviceEpoch, workerUUID: sent.workerUUID,
            handoffResult: .init(result: result, ready: actual))))
        #expect(try await retry.result() == proof)
        // Ordinary query must still reject a controller change (not reconcile it).
        let wrong = try material.readyLike(actual, controllerEpoch: actual.controllerEpoch + 1,
            controllerKey: String(repeating: "f", count: 64), revision: 4, openRevision: 1)
        let query = W.Frame(operation: .command, binding: original.binding, sequence: 1,
            serviceEpoch: old.serviceEpoch, command: .query, workerUUID: old.workerUUID)
        await #expect(throws: (any Error).self) {
            try await exchange(fixture, coordinator, query) {
                .init(operation: .reply, binding: $0.binding, ready: wrong, sequence: $0.sequence,
                    serviceEpoch: $0.serviceEpoch, workerUUID: $0.workerUUID)
            }
        }
    }
}
#endif

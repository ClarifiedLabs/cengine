#if os(macOS)
import CEngineCore
import CryptoKit
import Darwin
import Foundation
import Synchronization
import Testing
@testable import CEngineRuntime

// Real 4105 and 4109 socket traffic; no projected coordinator or forged boot proof.
// Serialize disk syncs and dedicated transport workers to avoid executor starvation.
@Suite(.serialized) struct PrivateWorkloadStorageCoordinatorTests {
    private typealias Wire = WorkloadStorageProtocol

    @Test func helloRequiresCommittedDiskBootProof() throws {
        let fixture = try WorkloadBootFixture()
        defer { fixture.remove() }
        let pair = try WorkloadSocketPair()
        defer { pair.close() }
        let checked = Mutex(false)
        // A valid hello can already be queued, but cannot create boot authority.
        try pair.send(.init(operation: .hello, binding: fixture.binding))
        let proof = try fixture.committedProof { transaction in
            #expect(throws: (any Error).self) {
                _ = try PrivateWorkloadStorageCoordinator(verified: transaction.verifiedContainerBoot(),
                    descriptor: pair.host.fileDescriptor)
            }
            checked.withLock { $0 = true }
            pair.expectNoBytes()
        }
        #expect(checked.withLock { $0 })
        let coordinator = try PrivateWorkloadStorageCoordinator(verified: proof, descriptor: pair.host.fileDescriptor)
        defer { coordinator.close() }
        let worker = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.hello() }
        defer { worker.settle() }
        let receipt = try worker.result()
        #expect(receipt.hello.binding == fixture.binding)
        #expect(receipt.configured == nil)
        #expect(receipt.diskIdentities == [try #require(fixture.specification.rootDiskIdentity)])
        #expect(receipt.rootExt4UUID == fixture.rootUUID)
        #expect(receipt.rootBytes == fixture.specification.rootDiskSize)
        #expect(receipt.initramfsSHA256 == fixture.specification.expectedInitramfsSHA256)
    }

    @Test func helloAndConfigureAreOnceOnlyAndShimOwnsCommandSequence() throws {
        let session = try WorkloadSession()
        defer { session.close() }
        let coordinator = session.coordinator
        #expect(!coordinator.permitsRootPreparation)
        #expect(throws: (any Error).self) { _ = try coordinator.currentReceipt() }
        #expect(throws: (any Error).self) { _ = try coordinator.configure(session.configuration) }
        #expect(throws: (any Error).self) { _ = try coordinator.command(session.command()) }
        session.pair.expectNoBytes()
        try session.hello()
        #expect(coordinator.permitsRootPreparation)
        #expect(throws: (any Error).self) { _ = try coordinator.hello() }
        #expect(!coordinator.isTerminal)
        let configure = WorkloadWorker(cancel: { coordinator.cancel() }) {
            try coordinator.configure(session.configuration)
        }
        defer { configure.settle() }
        let request = try session.pair.receive()
        #expect(request.operation == .configure)
        #expect(request.binding == session.binding)
        #expect(request.scope == session.configuration.scope)
        #expect(request.data.mounts == session.configuration.mounts)
        #expect(request.data.slots == session.configuration.slots)
        #expect(!coordinator.permitsRootPreparation)
        try session.pair.send(session.configured())
        #expect(try configure.result().configured == session.configured())
        #expect(throws: (any Error).self) { _ = try coordinator.configure(session.configuration) }
        session.pair.expectNoBytes()
        for supplied in [UInt64.max, 1] {
            var requested = session.command()
            requested.sequence = supplied
            let command = requested
            let worker = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.command(command) }
            defer { worker.settle() }
            let observed = try session.pair.receive()
            #expect(observed.sequence == (supplied == UInt64.max ? 1 : 2))
            let reply = session.reply(to: observed)
            try session.pair.send(reply)
            #expect(try worker.result() == reply)
        }
        #expect(!coordinator.isTerminal)
        #expect(try coordinator.currentReceipt().configured == session.configured())
    }

    @Test(arguments: ["launch", "nonce", "scope", "sequence"])
    func invalidHelloFailsClosed(fault: String) throws {
        let session = try WorkloadSession()
        defer { session.close() }
        var hello = Wire.Frame(operation: .hello, binding: session.binding)
        switch fault {
        case "launch": hello.binding.shimLaunchUUID = workloadUUID()
        case "nonce": hello.binding.guestBootNonce = workloadUUID()
        case "scope": hello.scope = session.configuration.scope
        default: hello.sequence = 1
        }
        let coordinator = session.coordinator
        let worker = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.hello() }
        defer { worker.settle() }
        try session.pair.sendUnchecked(hello)
        expectFailure(try worker.outcome())
        #expect(coordinator.isTerminal)
        #expect(!coordinator.permitsRootPreparation)
        #expect(throws: (any Error).self) { _ = try coordinator.currentReceipt() }
        session.pair.expectNoBytes()
    }

    @Test(arguments: ["launch", "nonce", "scope", "operation", "sequence", "kind"])
    func configuredReplyMustMatchPinnedSession(fault: String) throws {
        let session = try WorkloadSession()
        defer { session.close() }
        try session.hello()
        let coordinator = session.coordinator
        let worker = WorkloadWorker(cancel: { coordinator.cancel() }) {
            try coordinator.configure(session.configuration)
        }
        defer { worker.settle() }
        _ = try session.pair.receive()
        var reply = session.configured()
        switch fault {
        case "launch":
            let launch = workloadUUID()
            reply.binding.shimLaunchUUID = launch
            reply.scope?.launch = launch
        case "nonce": reply.binding.guestBootNonce = workloadUUID()
        case "scope": reply.scope?.intent = workloadUUID()
        case "operation": reply = .init(operation: .hello, binding: session.binding)
        case "sequence": reply.sequence = 1
        default: reply.kind = .status
        }
        try session.pair.sendUnchecked(reply)
        expectFailure(try worker.outcome())
        #expect(coordinator.isTerminal)
        #expect(!coordinator.permitsRootPreparation)
        #expect(throws: (any Error).self) { _ = try coordinator.currentReceipt() }
        #expect(throws: (any Error).self) { _ = try coordinator.configure(session.configuration) }
        session.pair.expectNoBytes()
    }

    @Test(arguments: ["launch", "nonce", "scope", "future-sequence", "replay", "kind"])
    func commandReplyBindingScopeSequenceAndKindAreNotInterchangeable(fault: String) throws {
        let session = try WorkloadSession()
        defer { session.close() }
        try session.start()
        let coordinator = session.coordinator
        // Complete sequence 1 so the replay case uses an actually observed reply.
        let first = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.command(session.command()) }
        defer { first.settle() }
        let previous = session.reply(to: try session.pair.receive())
        try session.pair.send(previous)
        _ = try first.result()
        let worker = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.command(session.command()) }
        defer { worker.settle() }
        let request = try session.pair.receive()
        #expect(request.sequence == 2)
        var reply = session.reply(to: request)
        switch fault {
        case "launch":
            let launch = workloadUUID()
            reply.binding.shimLaunchUUID = launch
            reply.scope?.launch = launch
        case "nonce": reply.binding.guestBootNonce = workloadUUID()
        case "scope": reply.scope?.containerInstance = workloadUUID()
        case "future-sequence": reply.sequence = 3
        case "replay": reply = previous
        default:
            reply.kind = .start
            reply.data = .init(code: .phase)
        }
        // These are valid individual wire frames; only the live coordinator can
        // reject their binding, expectation, or historical sequence mismatch.
        try session.pair.send(reply)
        expectFailure(try worker.outcome())
        #expect(coordinator.isTerminal)
        #expect(throws: (any Error).self) { _ = try coordinator.currentReceipt() }
    }

    @Test(arguments: ["binding", "scope"])
    func wrongDaemonCommandCannotConsumeSequenceOrWriteBytes(fault: String) throws {
        let session = try WorkloadSession()
        defer { session.close() }
        try session.start()
        var command = session.command()
        if fault == "binding" { command.binding.guestBootNonce = workloadUUID() }
        else { command.scope?.intent = workloadUUID() }
        #expect(throws: (any Error).self) { _ = try session.coordinator.command(command) }
        session.pair.expectNoBytes()
        #expect(!session.coordinator.isTerminal)
        let coordinator = session.coordinator
        let worker = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.command(session.command()) }
        defer { worker.settle() }
        let observed = try session.pair.receive()
        #expect(observed.sequence == 1)
        try session.pair.send(session.reply(to: observed))
        _ = try worker.result()
    }

    @Test(arguments: ["terminal", "EOF", "unsolicited-reply"])
    func idleReaderNoticesLossWithoutACommandOrReceiptPoll(fault: String) throws {
        let session = try WorkloadSession()
        defer { session.close() }
        try session.start()
        let event = Wire.Frame(operation: .terminal, binding: session.binding, scope: session.configuration.scope,
            data: .init(attachmentIDs: [session.configuration.slots[0].attachment], code: .terminal))
        switch fault {
        case "terminal": try session.pair.send(event)
        case "EOF": try session.pair.endWrites()
        default: try session.pair.send(session.reply(to: session.command()))
        }
        // Notification, rather than another API operation, proves the idle reader
        // observed the loss. A timeout/cancellation is never accepted as evidence.
        #expect(session.terminalSignal.wait(timeout: .now() + 3) == .success)
        #expect(session.coordinator.isTerminal)
        #expect(session.coordinator.events() == (fault == "terminal" ? [event] : []))
        #expect(throws: (any Error).self) { _ = try session.coordinator.currentReceipt() }
        #expect(!session.coordinator.permitsRootPreparation)
        session.coordinator.close()
        session.coordinator.close()
        #expect(session.callbacks.counts.withLock { $0.terminal } == 1)
        #expect(session.callbacks.counts.withLock { $0.closed } == 1)
    }

    @Test func closeCancelsBlockedCommandAndJoinsWithoutGuestFilesystemReply() throws {
        let session = try WorkloadSession()
        defer { session.close() }
        try session.start()
        let coordinator = session.coordinator
        let command = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.command(session.command()) }
        defer { command.settle() }
        _ = try session.pair.receive()
        // Keep the peer alive and the reader stuck inside an incomplete body.
        // No terminal/drain/FUSE completion message is sent by the guest.
        try session.pair.sendBytes(Data([0, 0, 0, 100, 123]))
        #expect(!command.finishedWithin(0))
        let started = ContinuousClock.now
        let closing = WorkloadWorker(cancel: { coordinator.cancel(); session.pair.interrupt() }) { coordinator.close() }
        defer { closing.settle() }
        try closing.result()
        #expect(ContinuousClock.now - started < .seconds(1))
        let result = try command.outcome()
        guard case .failure(let error) = result else { Issue.record("blocked command succeeded after close"); return }
        #expect(error is CancellationError)
        #expect(coordinator.isTerminal)
        #expect(coordinator.events().isEmpty)
        #expect(throws: (any Error).self) { _ = try coordinator.currentReceipt() }
        #expect(session.callbacks.counts.withLock { $0.terminal } == 0)
        #expect(session.callbacks.counts.withLock { $0.closed } == 1)
        // Original host FD was closed at construction: EOF proves owned socket
        // release, and closeConnection runs only after the reader has joined.
        #expect(try session.pair.readExactly(1).isEmpty)
        coordinator.close()
        #expect(session.callbacks.counts.withLock { $0.closed } == 1)
    }

    @Test func mainActorSnapshotsRemainResponsiveWhileCommandIsBlocked() async throws {
        let session = try WorkloadSession()
        defer { session.close() }
        try session.start()
        let coordinator = session.coordinator
        let worker = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.command(session.command()) }
        defer { worker.settle() }
        _ = try session.pair.receive()
        let snapshot = await MainActor.run {
            // Measure snapshot work, not unrelated MainActor queue contention
            // from the concurrently running suite. The command remains blocked.
            let started = ContinuousClock.now
            let value = (Thread.isMainThread, coordinator.isTerminal, coordinator.permitsRootPreparation, coordinator.events())
            #expect(ContinuousClock.now - started < .seconds(1))
            return value
        }
        #expect(snapshot.0)
        #expect(!snapshot.1 && !snapshot.2 && snapshot.3.isEmpty)
        #expect(!worker.finishedWithin(0))
        coordinator.close()
        expectFailure(try worker.outcome())
    }

    @Test func oneMiBBodyIsAcceptedWithFourAdditionalPrefixBytes() throws {
        let session = try WorkloadSession()
        defer { session.close() }
        #expect(Wire.maxFrame == 1_024 * 1_024)
        var body = try JSONEncoder().encode(Wire.Frame(operation: .hello, binding: session.binding))
        body.append(Data(repeating: 32, count: Wire.maxFrame - body.count))
        let coordinator = session.coordinator
        let worker = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.hello() }
        defer { worker.settle() }
        try session.pair.sendBody(body)
        #expect(try worker.result().hello.binding == session.binding)
        #expect(coordinator.permitsRootPreparation)
        #expect(!coordinator.isTerminal)
    }

    @Test(arguments: [UInt32(0), UInt32(1_024 * 1_024 + 1), UInt32.max])
    func invalidLengthIsRejectedWithoutWaitingForABody(length: UInt32) throws {
        let session = try WorkloadSession()
        defer { session.close() }
        let coordinator = session.coordinator
        let worker = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.hello() }
        defer { worker.settle() }
        var prefix = length.bigEndian
        try session.pair.sendBytes(Data(bytes: &prefix, count: 4))
        // Peer stays open. Header rejection, not EOF or the watchdog, must wake hello.
        #expect(worker.finishedWithin(3))
        expectFailure(try worker.outcome())
        #expect(coordinator.isTerminal)
        #expect(throws: (any Error).self) { _ = try coordinator.currentReceipt() }
    }

    @Test func managedModeFencesGenericOperationsAndPinsKernelSelector() throws {
        let fixture = try WorkloadBootFixture()
        defer { fixture.remove() }
        var specification = fixture.specification
        for operation in ["prepare", "start", "prepare-rootfs"] {
            #expect(throws: (any Error).self) {
                try VMShimServer.validateGenericWorkloadOperation(operation, specification: specification)
            }
        }
        for operation in ["status", "stop", "exec", "resize"] {
            try VMShimServer.validateGenericWorkloadOperation(operation, specification: specification)
        }
        #expect(try VMShimServer.bootstrapKernelArguments(specification) == ["cengine.workload_storage_mode=managed"])
        specification.workloadStorageMode = .none
        for operation in ["prepare", "start", "prepare-rootfs"] {
            try VMShimServer.validateGenericWorkloadOperation(operation, specification: specification)
        }
        #expect(try VMShimServer.bootstrapKernelArguments(specification).isEmpty)
        for argument in ["cengine.workload_storage_mode=legacy", "quiet cengine.workload_storage_mode=managed", "cengine.workload_storage_mode"] {
            specification.kernelArguments = [argument]
            #expect(throws: (any Error).self) { _ = try VMShimServer.bootstrapKernelArguments(specification) }
        }
        specification.kernelArguments = []
        specification.workloadStorageMode = .managed
        specification.kind = .storage
        #expect(throws: (any Error).self) { _ = try VMShimServer.bootstrapKernelArguments(specification) }
    }

    @Test(arguments: ["missing", "old-version", "wrong-digest", "valid"])
    func managedRootAssetRequiresExplicitWorkloadCapability(fault: String) throws {
        let fixture = try WorkloadBootFixture()
        defer { fixture.remove() }
        let image = Data("workload storage test initramfs".utf8)
        let path = fixture.root.appending(path: "initramfs")
        try image.write(to: path)
        let digest = SHA256.hash(data: image).map { String(format: "%02x", $0) }.joined()
        var specification = fixture.specification
        specification.kernelPath = fixture.root.appending(path: "kernel").path
        specification.initialRamdiskPath = path.path
        specification.expectedInitramfsSHA256 = digest
        if fault != "missing" {
            let metadata: [String: Any] = ["schemaVersion": 1, "protocolVersion": 1,
                "workloadStorageBootVersion": fault == "old-version" ? 0 : 1,
                "containerInitramfsSHA256": fault == "wrong-digest" ? String(repeating: "0", count: 64) : digest]
            try JSONSerialization.data(withJSONObject: metadata).write(to: fixture.root.appending(path: "disk-bootstrap.json"))
        }
        if fault == "valid" {
            let pinned = try VMShimServer.pinnedBootstrapInitramfs(specification)
            defer { try? pinned.close() }
            #expect(try pinned.readToEnd() == image)
        } else {
            #expect(throws: (any Error).self) { _ = try VMShimServer.pinnedBootstrapInitramfs(specification) }
        }
    }

    @Test(arguments: ["success", "failed-prepare", "dirty-copy-up", "dirty-close"])
    func runtimeRequiresSuccessfulPrepareAndCleanClose(fault: String) throws {
        let session = try WorkloadSession()
        defer { session.close() }
        try session.start()
        let prepareID = session.configuration.slots[0].attachment
        let runtimeID = session.configuration.slots[1].attachment
        // A direct runtime offer/start cannot skip preparation, even with valid wire data.
        for kind in [Wire.Kind.offerKeys, .start] {
            var command = session.command()
            command.kind = kind
            command.data = kind == .offerKeys ? .init(role: .runtime) : .init()
            #expect(throws: (any Error).self) { _ = try session.coordinator.command(command) }
        }
        session.pair.expectNoBytes()
        try session.exchange(.offerKeys, data: .init(role: .prepare),
            reply: .init(offers: [.init(attachment: prepareID, key: String(repeating: "e", count: 64), csrDER: Data([1]))]))
        try session.exchange(.installCertificate, data: .init(attachment: prepareID, certificateDER: Data([2])),
            reply: .init(attachment: prepareID))
        try session.exchange(.mountPhase, data: .init(role: .prepare), reply: .init(attachmentIDs: [prepareID]))
        let scope = session.configuration.scope
        try session.exchange(.prepare, data: .init(workloadJSON: Data("{}".utf8), ioClaim: "separate-private-claim"),
            reply: .init(prepare: scope.prepare, containerInstance: scope.containerInstance, launch: scope.launch,
                succeeded: fault != "failed-prepare", cleanCopyUp: fault != "dirty-copy-up", evidenceDigest: String(repeating: "f", count: 64)))
        try session.exchange(.closePhase, data: .init(role: .prepare),
            reply: .init(role: .prepare, attachmentIDs: [prepareID], clean: fault != "dirty-close"))
        if fault != "success" {
            var command = session.command()
            command.kind = .offerKeys
            command.data = .init(role: .runtime)
            #expect(throws: (any Error).self) { _ = try session.coordinator.command(command) }
            session.pair.expectNoBytes()
            #expect(!session.coordinator.isTerminal)
            return
        }
        try session.exchange(.offerKeys, data: .init(role: .runtime),
            reply: .init(offers: [.init(attachment: runtimeID, key: String(repeating: "e", count: 64), csrDER: Data([1]))]))
        try session.exchange(.installCertificate, data: .init(attachment: runtimeID, certificateDER: Data([2])),
            reply: .init(attachment: runtimeID))
        try session.exchange(.mountPhase, data: .init(role: .runtime), reply: .init(attachmentIDs: [runtimeID]))
        try session.exchange(.start, data: .init(), reply: .init(status: "running", pid: 42))
        try session.exchange(.status, data: .init(), reply: .init(phase: .running, mountedIDs: [runtimeID], terminalIDs: []))
        #expect(!session.coordinator.isTerminal)
    }

    @Test(arguments: [Wire.Kind.installCertificate, .mountPhase, .prepare])
    func authenticatedGuestRefusalPreservesOnlyClosedOperationAndCode(kind: WorkloadStorageProtocol.Kind) throws {
        let session = try WorkloadSession()
        defer { session.close() }
        try session.start()
        let attachment = session.configuration.slots[0].attachment
        try session.exchange(.offerKeys, data: .init(role: .prepare),
            reply: .init(offers: [.init(attachment: attachment, key: String(repeating: "e", count: 64), csrDER: Data([1]))]))
        if kind != .installCertificate {
            try session.exchange(.installCertificate, data: .init(attachment: attachment, certificateDER: Data([2])),
                reply: .init(attachment: attachment))
        }
        if kind == .prepare {
            try session.exchange(.mountPhase, data: .init(role: .prepare), reply: .init(attachmentIDs: [attachment]))
        }
        let data: Wire.Payload
        let code: Wire.Code
        switch kind {
        case .installCertificate: data = .init(attachment: attachment, certificateDER: Data([2])); code = .certificate
        case .mountPhase: data = .init(role: .prepare); code = .mount
        default: data = .init(workloadJSON: Data("{}".utf8), ioClaim: "private-test-claim"); code = .prepare
        }
        var command = session.command()
        command.kind = kind; command.data = data
        let requested = command, coordinator = session.coordinator
        let worker = WorkloadWorker(cancel: { coordinator.cancel() }) {
            let reply = try coordinator.command(requested)
            return try RawManagedStorageBackend.workloadCommandPayload(reply, kind: kind, role: data.role)
        }
        defer { worker.settle() }
        let received = try session.pair.receive()
        try session.pair.send(.init(operation: .reply, binding: session.binding, scope: session.configuration.scope,
            sequence: received.sequence, kind: kind, data: .init(code: code)))
        guard case .failure(let error) = try worker.outcome() else { Issue.record("guest refusal was accepted"); return }
        let role = kind == .mountPhase ? " role=prepare" : ""
        #expect(error.localizedDescription == "private workload storage operation refused [operation=\(kind.rawValue)\(role) guest=\(code.rawValue)]")
        #expect(!coordinator.isTerminal) // Classification changes no channel/retirement policy.
    }

    @Test func authenticatedSuccessPayloadIsUnchangedByClassification() throws {
        let session = try WorkloadSession()
        defer { session.close() }
        try session.start()
        let coordinator = session.coordinator
        let worker = WorkloadWorker(cancel: { coordinator.cancel() }) {
            let reply = try coordinator.command(session.command())
            return try RawManagedStorageBackend.workloadCommandPayload(reply, kind: .status, role: nil)
        }
        defer { worker.settle() }
        let reply = session.reply(to: try session.pair.receive())
        try session.pair.send(reply)
        #expect(try worker.result() == reply.data)
        #expect(!coordinator.isTerminal)
    }

    @Test(arguments: ["unknown-code", "raw-field", "binding"])
    func unverifiedGuestErrorCannotReachClosedDiagnostic(fault: String) throws {
        let session = try WorkloadSession()
        defer { session.close() }
        try session.start()
        let coordinator = session.coordinator
        let worker = WorkloadWorker(cancel: { coordinator.cancel() }) {
            let reply = try coordinator.command(session.command())
            return try RawManagedStorageBackend.workloadCommandPayload(reply, kind: .status, role: nil)
        }
        defer { worker.settle() }
        let request = try session.pair.receive()
        var reply = Wire.Frame(operation: .reply, binding: session.binding, scope: session.configuration.scope,
            sequence: request.sequence, kind: .status, data: .init(code: .mount))
        if fault == "binding" { reply.binding.guestBootNonce = workloadUUID() }
        var object = try #require(try JSONSerialization.jsonObject(with: JSONEncoder().encode(reply)) as? [String: Any])
        if fault == "unknown-code" { object["data"] = ["code": "raw-private-guest-error"] }
        if fault == "raw-field" { object["data"] = ["code": "mount", "message": "raw-private-guest-error"] }
        try session.pair.sendBody(JSONSerialization.data(withJSONObject: object))
        guard case .failure(let error) = try worker.outcome() else { Issue.record("unverified guest error accepted"); return }
        #expect(error.localizedDescription == PrivateWorkloadStorageCoordinator.failure(
            stage: fault == "binding" ? .readBinding : .readDecode, kind: .status).localizedDescription)
        #expect(!error.localizedDescription.contains("raw-private-guest-error"))
        #expect(coordinator.isTerminal)
    }

    @Test(arguments: ["eof", "length", "decode", "binding", "expectation", "terminal", "terminal-binding", "apply"])
    func commandDiagnosticsDistinguishPrivateResponseBoundaries(fault: String) throws {
        let session = try WorkloadSession()
        defer { session.close() }
        try session.start()
        let coordinator = session.coordinator
        let worker = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.command(session.command()) }
        defer { worker.settle() }
        let request = try session.pair.receive()
        var reply = session.reply(to: request)
        let stage: PrivateWorkloadStorageCoordinator.Stage
        switch fault {
        case "eof": stage = .readEOF; try session.pair.endWrites()
        case "length": stage = .readLength; try session.pair.sendBytes(Data([0, 0, 0, 0]))
        case "decode": stage = .readDecode; try session.pair.sendBody(Data("raw-private-guest-error".utf8))
        case "binding":
            stage = .readBinding; reply.binding.guestBootNonce = workloadUUID(); try session.pair.send(reply)
        case "expectation":
            stage = .readExpectation; reply.sequence = request.sequence! + 1; try session.pair.send(reply)
        case "terminal", "terminal-binding":
            stage = fault == "terminal" ? .guestTerminal : .terminalBinding
            let ids = [fault == "terminal" ? session.configuration.slots[0].attachment : workloadUUID()]
            try session.pair.send(.init(operation: .terminal, binding: session.binding, scope: session.configuration.scope,
                data: .init(attachmentIDs: ids, code: .mount)))
        default:
            stage = .replyValidate; reply.data.mountedIDs = [workloadUUID()]; try session.pair.send(reply)
        }
        guard case .failure(let error) = try worker.outcome() else { Issue.record("invalid response accepted"); return }
        let expected = PrivateWorkloadStorageCoordinator.failure(stage: stage, kind: .status,
            guestCode: fault == "terminal" ? .mount : nil)
        #expect(error.localizedDescription == expected.localizedDescription)
        #expect(!error.localizedDescription.contains("raw-private-guest-error"))
        #expect(coordinator.isTerminal)
        #expect(coordinator.events().count == (fault == "terminal" ? 1 : 0))
        #expect(session.callbacks.counts.withLock { $0.terminal } == 1)
    }

    @Test(arguments: [false, true])
    func readerFailureInterruptingPartialWriteKeepsItsClosedCause(callerFirst: Bool) throws {
        let published = DispatchSemaphore(value: 0), interrupted = DispatchSemaphore(value: 0)
        let releasePublication = DispatchSemaphore(value: 0)
        let session = try WorkloadSession(sendBuffer: 1_024, diagnosticHook: { boundary in
            switch boundary {
            case .readerCancellationPublished:
                published.signal()
                #expect(releasePublication.wait(timeout: .now() + 5) == .success)
            case .writerObservedCancellation: interrupted.signal()
            }
        })
        defer { session.close() }
        try session.start()
        let attachment = session.configuration.slots[0].attachment
        try session.exchange(.offerKeys, data: .init(role: .prepare),
            reply: .init(offers: [.init(attachment: attachment, key: String(repeating: "e", count: 64), csrDER: Data([1]))]))
        var command = session.command()
        command.kind = .installCertificate
        command.data = .init(attachment: attachment, certificateDER: Data(repeating: 1, count: Wire.maximumDERBytes))
        let encoded = try Wire.encode(command) // Prove the fixture passes the real closed wire validator.
        let requested = command, coordinator = session.coordinator
        let worker = WorkloadWorker(cancel: { coordinator.cancel(); session.pair.interrupt() }) {
            try coordinator.command(requested)
        }
        defer { releasePublication.signal(); worker.settle() }
        // Consume only the prefix. The oversized body cannot fit the small send
        // buffer, so the reader's terminal event interrupts an unfinished write.
        let prefix = try session.pair.readExactly(4)
        #expect(prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) } == UInt32(encoded.count - 4))
        #expect(!worker.finishedWithin(0))
        if callerFirst { coordinator.cancel() }
        try session.pair.send(.init(operation: .terminal, binding: session.binding, scope: session.configuration.scope,
            data: .init(attachmentIDs: [attachment], code: .mount)))
        if !callerFirst {
            try #require(published.wait(timeout: .now() + 3) == .success)
            try #require(interrupted.wait(timeout: .now() + 3) == .success)
            // The reader holds the condition lock after publishing interruption.
            // The writer has observed it but cannot publish an untyped first failure.
            #expect(!worker.finishedWithin(0))
            releasePublication.signal()
        }
        guard case .failure(let error) = try worker.outcome() else { Issue.record("interrupted write succeeded"); return }
        if callerFirst { #expect(error is CancellationError) }
        else {
            #expect(error.localizedDescription == PrivateWorkloadStorageCoordinator.failure(stage: .guestTerminal,
                kind: .installCertificate, guestCode: .mount).message)
            #expect(!(error is CancellationError))
        }
    }

    @Test func idleTerminalDiagnosticSurvivesUntilNextCommandWithoutExposingUnboundCode() throws {
        let session = try WorkloadSession()
        defer { session.close() }
        try session.start()
        try session.pair.send(.init(operation: .terminal, binding: session.binding, scope: session.configuration.scope,
            data: .init(attachmentIDs: [session.configuration.slots[0].attachment], code: .mount)))
        try #require(session.terminalSignal.wait(timeout: .now() + 3) == .success)
        session.coordinator.cancel() // Teardown after reader failure must not replace its first cause.
        do {
            _ = try session.coordinator.command(session.command())
            Issue.record("terminal channel accepted command")
        } catch {
            #expect(error.localizedDescription == PrivateWorkloadStorageCoordinator.failure(
                stage: .guestTerminal, kind: .status, guestCode: .mount).localizedDescription)
        }
        session.pair.expectNoBytes()
    }

    @Test func shimErrorForwardingReconstructsOnlyExactClosedDiagnostics() throws {
        let local = PrivateWorkloadStorageCoordinator.failure(stage: .guestTerminal, kind: .mountPhase,
            role: .prepare, guestCode: .mount)
        let nsError = local as NSError
        let text = "\(local.message) [\(nsError.domain) \(nsError.code)]"
        let reply = VMShimProtocol.Envelope(token: "unused", operation: .workloadStorageCommand,
            error: .init(code: "shim_error", message: text))
        let decoded = try VMShimProtocol.decode(VMShimProtocol.encode(reply))
        let forwarded = PrivateWorkloadStorageCoordinator.forwardedFailure(try #require(decoded.error))
        #expect(forwarded.code == local.code)
        #expect(forwarded.message == local.message)
        let boot = EngineError(.internalError, "boot step 'start virtual machine' failed: \(text)")
        let bootNSError = boot as NSError
        let bootText = "\(boot.message) [\(bootNSError.domain) \(bootNSError.code)]"
        #expect(PrivateWorkloadStorageCoordinator.forwardedFailure(.init(code: "shim_error", message: bootText)).message == local.message)
        for invalid in [text + " raw-private-token", "raw-private-token " + text,
            text.replacingOccurrences(of: "phase=guest-terminal", with: "phase=unknown"),
            text.replacingOccurrences(of: "guest-code=mount", with: "guest-code=raw-private-token"),
            text.replacingOccurrences(of: "operation=mount-phase", with: "operation=raw-private-token"),
            text.replacingOccurrences(of: "role=prepare", with: "role=unknown"),
            text.replacingOccurrences(of: "phase=guest-terminal", with: "phase=read-binding"),
            text.replacingOccurrences(of: "role=prepare", with: "role=prepare role=prepare"),
            text.replacingOccurrences(of: "role=prepare", with: "role=prepare raw=private-token")] {
            let error = PrivateWorkloadStorageCoordinator.forwardedFailure(.init(code: "shim_error", message: invalid))
            #expect(error.message == PrivateWorkloadStorageCoordinator.failure().message)
        }
        #expect(PrivateWorkloadStorageCoordinator.forwardedFailure(.init(code: "raw-private-token", message: text)).message
            == PrivateWorkloadStorageCoordinator.failure().message)
    }

    @Test func recoveryStatusUsesOriginalConfiguredScopeAndDoesNotReopenPreparation() throws {
        let session = try WorkloadSession()
        defer { session.close() }
        try session.startRunning()
        let coordinator = session.coordinator
        let worker = WorkloadWorker(cancel: { coordinator.cancel() }) {
            try coordinator.observeRunningWorkloadStorage(expectedScope: session.configuration.scope,
                deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 3_000_000_000)
        }
        defer { worker.settle() }
        let request = try session.pair.receive()
        #expect(request.operation == .command && request.kind == .status)
        #expect(request.scope == session.configuration.scope) // C1, not the restarted host's C2.
        #expect(request.binding == session.binding)
        #expect(request.sequence == 10)
        let reply = session.runningReply(to: request)
        try session.pair.send(reply)
        #expect(try worker.result() == reply)
        #expect(reply.data.terminalIDs == []) // Clean prepare close is not a terminal event.
        #expect(!coordinator.isTerminal && !coordinator.permitsRootPreparation)
        #expect(try coordinator.currentReceipt().configured == session.configured())
        #expect(throws: (any Error).self) { _ = try coordinator.configure(session.configuration) }
        session.pair.expectNoBytes()
    }

    @Test(arguments: ["controller-epoch", "controller-key", "intent", "instance", "launch", "prepare"])
    func recoveryStatusRejectsChangedOriginalScopeWithoutTouchingPendingCommand(field: String) throws {
        let session = try WorkloadSession()
        defer { session.close() }
        try session.startRunning()
        let coordinator = session.coordinator
        let pending = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.command(session.command()) }
        defer { pending.settle() }
        let request = try session.pair.receive()
        var scope = session.configuration.scope
        switch field {
        case "controller-epoch": scope.controllerEpoch += 1
        case "controller-key": scope.controllerKey = String(repeating: "f", count: 64)
        case "intent": scope.intent = workloadUUID()
        case "instance": scope.containerInstance = workloadUUID()
        case "launch": scope.launch = workloadUUID()
        default: scope.prepare = workloadUUID()
        }
        #expect(throws: (any Error).self) {
            _ = try coordinator.observeRunningWorkloadStorage(expectedScope: scope, deadlineNanoseconds: 0)
        }
        #expect(!coordinator.isTerminal && !pending.finishedWithin(0))
        session.pair.expectNoBytes()
        try session.pair.send(session.runningReply(to: request))
        _ = try pending.result()
        #expect(try coordinator.currentReceipt().configured == session.configured())
    }

    @Test func recoveryStatusRejectsNonrunningLocalPhaseWithoutSendingOrConfiguring() throws {
        let session = try WorkloadSession()
        defer { session.close() }
        try session.start()
        #expect(throws: (any Error).self) {
            _ = try session.coordinator.observeRunningWorkloadStorage(expectedScope: session.configuration.scope,
                deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 3_000_000_000)
        }
        session.pair.expectNoBytes()
        #expect(!session.coordinator.isTerminal && !session.coordinator.permitsRootPreparation)
        #expect(throws: (any Error).self) { _ = try session.coordinator.configure(session.configuration) }
    }

    @Test(arguments: [Wire.Phase.configured, .prepareClosed, .runtimeMounted, .aborted, .terminal])
    func recoveryStatusCannotPromoteNonrunningGuestPhase(phase: WorkloadStorageProtocol.Phase) throws {
        let session = try WorkloadSession()
        defer { session.close() }
        try session.startRunning()
        let coordinator = session.coordinator
        let worker = WorkloadWorker(cancel: { coordinator.cancel() }) {
            try coordinator.observeRunningWorkloadStorage(expectedScope: session.configuration.scope,
                deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 3_000_000_000)
        }
        defer { worker.settle() }
        var reply = session.runningReply(to: try session.pair.receive())
        reply.data.phase = phase
        try session.pair.send(reply)
        expectFailure(try worker.outcome())
        #expect(!coordinator.isTerminal && !coordinator.permitsRootPreparation)
        #expect(throws: (any Error).self) { _ = try coordinator.configure(session.configuration) }
        session.pair.expectNoBytes()
    }

    @Test(arguments: ["missing-runtime", "prepare-mounted", "runtime-terminal", "prepare-terminal"])
    func recoveryStatusRequiresOnlyLiveRuntimeAttachments(fault: String) throws {
        let session = try WorkloadSession()
        defer { session.close() }
        try session.startRunning()
        let coordinator = session.coordinator
        let worker = WorkloadWorker(cancel: { coordinator.cancel() }) {
            try coordinator.observeRunningWorkloadStorage(expectedScope: session.configuration.scope,
                deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 3_000_000_000)
        }
        defer { worker.settle() }
        var reply = session.runningReply(to: try session.pair.receive())
        switch fault {
        case "missing-runtime": reply.data.mountedIDs = []
        case "prepare-mounted": reply.data.mountedIDs = [session.configuration.slots[0].attachment]
        case "runtime-terminal":
            reply.data.mountedIDs = []; reply.data.terminalIDs = [session.configuration.slots[1].attachment]
        default: reply.data.terminalIDs = [session.configuration.slots[0].attachment]
        }
        try session.pair.send(reply)
        expectFailure(try worker.outcome())
        #expect(!coordinator.isTerminal && !coordinator.permitsRootPreparation)
        #expect(throws: (any Error).self) { _ = try coordinator.configure(session.configuration) }
        session.pair.expectNoBytes()
    }

    @Test func recoveryStatusSerializesBehindPendingCommandWithoutRenewingScope() throws {
        let session = try WorkloadSession()
        defer { session.close() }
        try session.startRunning()
        let coordinator = session.coordinator
        let pending = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.command(session.command()) }
        defer { pending.settle() }
        let first = try session.pair.receive()
        let status = WorkloadWorker(cancel: { coordinator.cancel() }) {
            try coordinator.observeRunningWorkloadStorage(expectedScope: session.configuration.scope,
                deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 3_000_000_000)
        }
        defer { status.settle() }
        #expect(!status.finishedWithin(0.05))
        session.pair.expectNoBytes()
        try session.pair.send(session.runningReply(to: first))
        _ = try pending.result()
        let second = try session.pair.receive()
        #expect(second.kind == .status && second.sequence == first.sequence! + 1)
        let reply = session.runningReply(to: second)
        try session.pair.send(reply)
        #expect(try status.result() == reply)
        #expect(!coordinator.isTerminal)
    }

    @Test(arguments: [false, true])
    func recoveryDeadlineIncludesSerialWaitAndPartialReplyAndJoins(pendingCommand: Bool) throws {
        let session = try WorkloadSession()
        defer { session.close() }
        try session.startRunning()
        let coordinator = session.coordinator
        let pending: WorkloadWorker<Wire.Frame>?
        if pendingCommand {
            pending = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.command(session.command()) }
            _ = try session.pair.receive()
        } else { pending = nil }
        defer { pending?.settle() }
        let started = ContinuousClock.now
        let deadline = DispatchTime.now().uptimeNanoseconds + 200_000_000
        let status = WorkloadWorker(cancel: { coordinator.cancel() }) {
            try coordinator.observeRunningWorkloadStorage(expectedScope: session.configuration.scope,
                deadlineNanoseconds: deadline)
        }
        defer { status.settle() }
        if !pendingCommand { _ = try session.pair.receive() }
        // Keep the guest alive with an incomplete reply. No EOF, drain, or fake
        // prepare terminal receipt may supply success or unblock the operation.
        try session.pair.sendBytes(Data([0, 0, 0, 100, 123]))
        expectFailure(try status.outcome())
        #expect(ContinuousClock.now - started < .seconds(2))
        if let pending {
            #expect(pending.finishedWithin(1))
            expectFailure(try pending.outcome())
        }
        #expect(coordinator.isTerminal && !coordinator.permitsRootPreparation)
        #expect(coordinator.events().isEmpty)
        #expect(session.callbacks.counts.withLock { $0.terminal } == 1)
        #expect(throws: (any Error).self) { _ = try coordinator.currentReceipt() }
        #expect(throws: (any Error).self) { _ = try coordinator.configure(session.configuration) }
        #expect(throws: (any Error).self) { _ = try coordinator.command(session.command()) }
        session.pair.expectNoBytes() // A timed-out queued status never writes later.
    }

    @Test func recoveryStatusRevalidatesHeldDisksAfterGuestReply() throws {
        let session = try WorkloadSession()
        defer { session.close() }
        try session.startRunning()
        let coordinator = session.coordinator
        let status = WorkloadWorker(cancel: { coordinator.cancel() }) {
            try coordinator.observeRunningWorkloadStorage(expectedScope: session.configuration.scope,
                deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 3_000_000_000)
        }
        defer { status.settle() }
        let request = try session.pair.receive()
        let disk = try FileHandle(forWritingTo: session.fixture.root.appending(path: "root.ext4"))
        defer { try? disk.close() }
        try disk.truncate(atOffset: 4_096)
        try session.pair.send(session.runningReply(to: request))
        expectFailure(try status.outcome())
        #expect(coordinator.isTerminal)
    }

    private func expectFailure<Value>(_ result: Result<Value, any Error>) {
        guard case .failure = result else { Issue.record("invalid private exchange succeeded"); return }
    }
}

private func workloadUUID() -> String { UUID().uuidString.lowercased() }

private enum WorkloadTestFailure: Error { case timeout, transport, fixture }

/// Dedicated OS threads, not shared-dispatch work or blocking cooperative Tasks.
/// Every owner defers settle before closing FDs; a watchdog is only a safety net.
private final class WorkloadWorker<Value: Sendable>: @unchecked Sendable {
    private struct State {
        var result: Result<Value, any Error>?
        var expired = false
    }
    private final class SharedState: Sendable {
        let value = Mutex(State())
    }
    private let state: SharedState
    private let finished: DispatchGroup
    private let watchdogFinished: DispatchGroup
    private let cancel: @Sendable () -> Void

    init(cancel: @escaping @Sendable () -> Void, operation: @escaping @Sendable () throws -> Value) {
        self.cancel = cancel
        let state = SharedState(), finished = DispatchGroup(), watchdogFinished = DispatchGroup()
        self.state = state; self.finished = finished; self.watchdogFinished = watchdogFinished
        finished.enter()
        watchdogFinished.enter()
        Thread.detachNewThread {
            defer { watchdogFinished.leave() }
            guard finished.wait(timeout: .now() + 15) == .timedOut else { return }
            let shouldCancel = state.value.withLock {
                guard $0.result == nil else { return false }
                $0.expired = true
                return true
            }
            if shouldCancel { cancel() }
        }
        Thread.detachNewThread {
            let result = Result { try operation() }
            state.value.withLock { $0.result = result }
            finished.leave()
        }
    }

    func finishedWithin(_ seconds: Double) -> Bool { finished.wait(timeout: .now() + seconds) == .success }

    func outcome() throws -> Result<Value, any Error> {
        guard finishedWithin(15) else { cancel(); throw WorkloadTestFailure.timeout }
        #expect(!state.value.withLock { $0.expired }, "watchdog cancellation is not evidence of transport rejection")
        return try #require(state.value.withLock { $0.result })
    }

    func result() throws -> Value { try outcome().get() }

    func settle() {
        if !finishedWithin(0) { cancel() }
        // Join the watchdog too: an already-running cancellation closure must
        // never touch descriptor numbers after test cleanup has reused them.
        precondition(finishedWithin(15), "private workload worker did not settle before descriptor cleanup")
        precondition(watchdogFinished.wait(timeout: .now() + 15) == .success,
            "private workload watchdog did not settle before descriptor cleanup")
    }
}

private final class WorkloadSocketPair: @unchecked Sendable {
    let host: FileHandle
    let guest: FileHandle

    init() throws {
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { throw WorkloadTestFailure.transport }
        host = FileHandle(fileDescriptor: pair[0], closeOnDealloc: true)
        guest = FileHandle(fileDescriptor: pair[1], closeOnDealloc: true)
        var enabled: Int32 = 1
        for descriptor in pair {
            guard setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled,
                socklen_t(MemoryLayout<Int32>.size)) == 0 else { throw WorkloadTestFailure.transport }
        }
    }

    func close() { try? host.close(); try? guest.close() }
    func interrupt() { _ = shutdown(guest.fileDescriptor, SHUT_RDWR) }
    func endWrites() throws {
        guard shutdown(guest.fileDescriptor, SHUT_WR) == 0 else { throw WorkloadTestFailure.transport }
    }
    func send(_ frame: WorkloadStorageProtocol.Frame) throws { try sendBytes(WorkloadStorageProtocol.encode(frame)) }
    func sendUnchecked<T: Encodable>(_ value: T) throws { try sendBody(JSONEncoder().encode(value)) }
    func sendBody(_ body: Data) throws {
        var count = UInt32(body.count).bigEndian
        try sendBytes(Data(bytes: &count, count: 4) + body)
    }
    func sendBytes(_ data: Data) throws {
        let deadline = ContinuousClock.now + .seconds(10)
        var offset = 0
        while offset < data.count {
            try wait(Int16(POLLOUT), deadline: deadline)
            let count = data.withUnsafeBytes {
                Darwin.send(guest.fileDescriptor, $0.baseAddress!.advanced(by: offset), data.count - offset, MSG_DONTWAIT)
            }
            if count < 0 && [EINTR, EAGAIN].contains(errno) { continue }
            guard count > 0 else { throw WorkloadTestFailure.transport }
            offset += count
        }
    }
    func readExactly(_ count: Int) throws -> Data {
        let deadline = ContinuousClock.now + .seconds(10)
        var data = Data(count: count), offset = 0
        while offset < count {
            try wait(Int16(POLLIN), deadline: deadline)
            let amount = data.withUnsafeMutableBytes {
                recv(guest.fileDescriptor, $0.baseAddress!.advanced(by: offset), count - offset, MSG_DONTWAIT)
            }
            if amount < 0 && [EINTR, EAGAIN].contains(errno) { continue }
            if amount == 0 && offset == 0 { return Data() }
            guard amount > 0 else { throw WorkloadTestFailure.transport }
            offset += amount
        }
        return data
    }
    func readBody() throws -> Data {
        let prefix = try readExactly(4)
        guard prefix.count == 4 else { throw WorkloadTestFailure.transport }
        let count = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard count > 0, count <= UInt32(WorkloadStorageProtocol.maxFrame) else { throw WorkloadTestFailure.transport }
        let body = try readExactly(Int(count))
        guard body.count == Int(count) else { throw WorkloadTestFailure.transport }
        return body
    }
    func receive() throws -> WorkloadStorageProtocol.Frame { try WorkloadStorageProtocol.decode(from: readBody()) }
    func expectNoBytes() {
        var byte: UInt8 = 0
        let amount = recv(guest.fileDescriptor, &byte, 1, MSG_PEEK | MSG_DONTWAIT)
        #expect(amount == -1 && errno == EAGAIN)
    }
    private func wait(_ events: Int16, deadline: ContinuousClock.Instant) throws {
        while ContinuousClock.now < deadline {
            var item = pollfd(fd: guest.fileDescriptor, events: events, revents: 0)
            let result = poll(&item, 1, 100)
            if result < 0 && errno == EINTR { continue }
            guard result >= 0 else { throw WorkloadTestFailure.transport }
            if result == 0 { continue }
            guard item.revents & events != 0 else { throw WorkloadTestFailure.transport }
            return
        }
        throw WorkloadTestFailure.timeout
    }
}

private struct WorkloadBootFixture: Sendable {
    let root: URL
    let disk: VMShimHeldDisk
    let specification: VMShimProtocol.Specification
    let rootUUID: String
    let nonce = workloadUUID()

    init() throws {
        root = FileManager.default.temporaryDirectory.appending(path: "cengine-private-workload-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let directory = try PersistentStateDirectory.open(root)
        guard case .created(let created) = try RawDiskInitialization.createNewDisk(in: directory, named: "root.ext4", size: 16 << 20) else {
            throw WorkloadTestFailure.fixture
        }
        rootUUID = created.record.ext4UUID
        let opened = try directory.openRegularFile(named: "root.ext4", access: .readWrite)
        guard flock(opened.handle.fileDescriptor, LOCK_EX | LOCK_NB) == 0 else { throw WorkloadTestFailure.fixture }
        disk = .init(ordinal: 0, role: "container-root", volumeName: nil, parent: directory, name: "root.ext4",
            handle: opened.handle, identity: opened.identity, bytes: 16 << 20)
        specification = .init(containerID: String(repeating: "a", count: 64), generation: 1, token: "unused",
            kernelPath: "/unused", initialRamdiskPath: "/unused", rootDiskPath: root.appending(path: "root.ext4").path,
            rootDiskIdentity: .init(device: opened.identity.device, inode: opened.identity.inode, volumeUUID: opened.identity.volumeUUID),
            rootDiskSize: disk.bytes, cpus: 1, memoryBytes: 1 << 30, macAddress: "02:00:00:00:00:01",
            socketPath: "/unused", logPath: "/unused", shimLaunchUUID: workloadUUID(), diskBootstrapVersion: 1,
            expectedInitramfsSHA256: String(repeating: "b", count: 64), workloadStorageMode: .managed)
    }

    var binding: WorkloadStorageProtocol.BootBinding {
        .init(shimLaunchUUID: specification.shimLaunchUUID!, guestBootNonce: nonce)
    }

    func committedProof(beforeCommit: (@Sendable (RawDiskBootTransaction) throws -> Void)? = nil) throws -> RawDiskBootTransaction.VerifiedContainerBoot {
        let pair = try WorkloadSocketPair()
        defer { pair.close() }
        let owner = Mutex<RawDiskBootTransaction?>(nil)
        let transaction = try RawDiskBootTransaction(specification: specification, disks: [disk], hook: { boundary in
            if boundary == .beforeCommit {
                let current = try #require(owner.withLock { $0 })
                #expect(throws: (any Error).self) { _ = try current.verifiedContainerBoot() }
                try beforeCommit?(current)
            }
        })
        owner.withLock { $0 = transaction }
        defer { owner.withLock { $0 = nil } }
        #expect(throws: (any Error).self) { _ = try transaction.verifiedContainerBoot() }
        let cancelled = Mutex(false)
        let worker = WorkloadWorker(cancel: { cancelled.withLock { $0 = true }; pair.interrupt() }) {
            try transaction.run(descriptor: pair.host.fileDescriptor, isCancelled: { cancelled.withLock { $0 } })
        }
        defer { worker.settle() }
        let hello = DiskInitializationProtocol.Hello(kind: "container", guestBootNonce: nonce,
            disks: [.init(ordinal: 0, blockIdentifier: disk.blockIdentifier, bytes: disk.bytes)])
        try pair.sendBytes(DiskInitializationProtocol.encode(hello))
        let manifest = try DiskInitializationProtocol.decode(DiskInitializationProtocol.Manifest.self, from: pair.readBody())
        #expect(manifest.shimLaunchUUID == specification.shimLaunchUUID)
        #expect(manifest.guestBootNonce == nonce)
        let synced = DiskInitializationProtocol.Synced(shimLaunchUUID: manifest.shimLaunchUUID, guestBootNonce: manifest.guestBootNonce,
            disks: manifest.disks.map { .init(ordinal: $0.ordinal, bytes: $0.expectedBytes, ext4UUID: $0.ext4UUID!, operationUUID: $0.operationUUID) })
        try pair.sendBytes(DiskInitializationProtocol.encode(synced))
        let commit = try DiskInitializationProtocol.decode(DiskInitializationProtocol.Commit.self, from: pair.readBody())
        #expect(commit.shimLaunchUUID == manifest.shimLaunchUUID)
        #expect(commit.guestBootNonce == nonce)
        try worker.result()
        return try transaction.verifiedContainerBoot()
    }

    func remove() { try? FileManager.default.removeItem(at: root) }
}

private final class WorkloadCallbackState: Sendable {
    let counts = Mutex((terminal: 0, closed: 0))
}

private final class WorkloadSession: @unchecked Sendable {
    let fixture: WorkloadBootFixture
    let pair: WorkloadSocketPair
    let coordinator: PrivateWorkloadStorageCoordinator
    let configuration: WorkloadStorageConfiguration
    let terminalSignal: DispatchSemaphore
    let callbacks: WorkloadCallbackState
    var binding: WorkloadStorageProtocol.BootBinding { fixture.binding }

    init(sendBuffer: Int32? = nil,
         diagnosticHook: @escaping @Sendable (PrivateWorkloadStorageCoordinator.DiagnosticBoundary) -> Void = { _ in }) throws {
        let fixture = try WorkloadBootFixture()
        var initialized = false
        defer { if !initialized { fixture.remove() } }
        let pair = try WorkloadSocketPair()
        defer { if !initialized { pair.close() } }
        if var sendBuffer {
            try #require(setsockopt(pair.host.fileDescriptor, SOL_SOCKET, SO_SNDBUF, &sendBuffer,
                socklen_t(MemoryLayout<Int32>.size)) == 0)
        }
        let proof = try fixture.committedProof()
        let signal = DispatchSemaphore(value: 0), counts = WorkloadCallbackState()
        let coordinator = try PrivateWorkloadStorageCoordinator(verified: proof, descriptor: pair.host.fileDescriptor,
            closeConnection: { counts.counts.withLock { $0.closed += 1 } },
            onTerminal: { counts.counts.withLock { $0.terminal += 1 }; signal.signal() }, diagnosticHook: diagnosticHook)
        defer { if !initialized { coordinator.close() } }
        // The real coordinator must retain an independent owned descriptor.
        try pair.host.close()
        let volume = workloadUUID()
        let configuration = WorkloadStorageConfiguration(scope: .init(intent: workloadUUID(), store: workloadUUID(), serviceEpoch: workloadUUID(),
            controllerEpoch: 1, controllerKey: String(repeating: "c", count: 64), container: proof.containerID,
            containerInstance: workloadUUID(), launch: proof.shimLaunchUUID, prepare: workloadUUID(),
            specificationDigest: WorkloadStorageProtocol.specificationDigest(Data("{}".utf8))),
            peer: .init(tlsRootDER: Data([1]), serverDER: Data([2]), serverKey: String(repeating: "d", count: 64), dataAddress: "192.0.2.1"),
            mounts: [.init(index: 0, volume: volume, destination: "/data", subpath: "", mode: .readWrite, noCopy: false)],
            slots: [.init(volume: volume, attachment: workloadUUID(), role: .prepare, mode: .readWrite),
                    .init(volume: volume, attachment: workloadUUID(), role: .runtime, mode: .readWrite)])
        self.fixture = fixture; self.pair = pair; self.coordinator = coordinator
        self.configuration = configuration; self.terminalSignal = signal; self.callbacks = counts
        initialized = true
    }

    func hello() throws {
        let coordinator = coordinator
        let worker = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.hello() }
        defer { worker.settle() }
        try pair.send(.init(operation: .hello, binding: binding))
        _ = try worker.result()
    }
    func start() throws {
        try hello()
        let coordinator = coordinator, configuration = configuration
        let worker = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.configure(configuration) }
        defer { worker.settle() }
        let request = try pair.receive()
        #expect(request.operation == .configure)
        #expect(request.scope == configuration.scope)
        try pair.send(configured())
        _ = try worker.result()
    }
    func startRunning() throws {
        try start()
        let prepareID = configuration.slots[0].attachment, runtimeID = configuration.slots[1].attachment
        try exchange(.offerKeys, data: .init(role: .prepare),
            reply: .init(offers: [.init(attachment: prepareID, key: String(repeating: "e", count: 64), csrDER: Data([1]))]))
        try exchange(.installCertificate, data: .init(attachment: prepareID, certificateDER: Data([2])),
            reply: .init(attachment: prepareID))
        try exchange(.mountPhase, data: .init(role: .prepare), reply: .init(attachmentIDs: [prepareID]))
        let scope = configuration.scope
        try exchange(.prepare, data: .init(workloadJSON: Data("{}".utf8), ioClaim: "separate-private-claim"),
            reply: .init(prepare: scope.prepare, containerInstance: scope.containerInstance, launch: scope.launch,
                succeeded: true, cleanCopyUp: true, evidenceDigest: String(repeating: "f", count: 64)))
        try exchange(.closePhase, data: .init(role: .prepare), reply: .init(role: .prepare, attachmentIDs: [prepareID], clean: true))
        try exchange(.offerKeys, data: .init(role: .runtime),
            reply: .init(offers: [.init(attachment: runtimeID, key: String(repeating: "e", count: 64), csrDER: Data([1]))]))
        try exchange(.installCertificate, data: .init(attachment: runtimeID, certificateDER: Data([2])),
            reply: .init(attachment: runtimeID))
        try exchange(.mountPhase, data: .init(role: .runtime), reply: .init(attachmentIDs: [runtimeID]))
        try exchange(.start, data: .init(), reply: .init(status: "running", pid: 42))
    }
    func runningReply(to command: WorkloadStorageProtocol.Frame) -> WorkloadStorageProtocol.Frame {
        .init(operation: .reply, binding: binding, scope: configuration.scope, sequence: command.sequence, kind: .status,
            data: .init(phase: .running, mountedIDs: [configuration.slots[1].attachment], terminalIDs: []))
    }
    func configured() -> WorkloadStorageProtocol.Frame {
        .init(operation: .configured, binding: binding, scope: configuration.scope)
    }
    func command() -> WorkloadStorageProtocol.Frame {
        .init(operation: .command, binding: binding, scope: configuration.scope, sequence: 1, kind: .status)
    }
    func reply(to command: WorkloadStorageProtocol.Frame) -> WorkloadStorageProtocol.Frame {
        .init(operation: .reply, binding: binding, scope: configuration.scope, sequence: command.sequence, kind: .status,
            data: .init(phase: .configured, mountedIDs: [], terminalIDs: []))
    }
    func exchange(_ kind: WorkloadStorageProtocol.Kind, data: WorkloadStorageProtocol.Payload,
                  reply: WorkloadStorageProtocol.Payload) throws {
        let coordinator = coordinator
        var command = command()
        command.kind = kind
        command.data = data
        let requested = command
        let worker = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.command(requested) }
        defer { worker.settle() }
        let received = try pair.receive()
        #expect(received.kind == kind)
        #expect(received.data == data)
        try pair.send(.init(operation: .reply, binding: binding, scope: configuration.scope,
            sequence: received.sequence, kind: kind, data: reply))
        #expect(try worker.result().data == reply)
    }
    func close() { coordinator.close(); pair.close(); fixture.remove() }
}
#endif

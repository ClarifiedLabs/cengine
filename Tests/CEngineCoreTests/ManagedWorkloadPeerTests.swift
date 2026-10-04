#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Synchronization
import Testing
@testable import CEngineRuntime

@Suite struct ManagedWorkloadPeerTests {
    private typealias Recovery = RawStorageShimRecovery

    @Test func runningManagedArchiveUsesExistingAuthenticatedGuestWithoutBootOrStop() async throws {
        let fixture = try WorkloadPeerFixture()
        defer { fixture.remove() }
        let exchange = try await archivePeerExchange(fixture, phase: .running)
        try exchange.result.get()
        #expect(exchange.requests.map(\.operation) == [.status, .guest])
        let request = try #require(exchange.requests.last?.payload)
        let call = try JSONDecoder().decode(VMShimClient.GuestCall.self, from: request)
        #expect(call.operation == "copy-in")
        let payload = try #require(JSONSerialization.jsonObject(with: call.payload) as? [String: Any])
        #expect(payload["source"] as? String == "owned-transfer")
        #expect(payload["destination"] as? String == "/")
        let owners = try #require(payload["ownership"] as? [[String: Any]])
        #expect(owners.count == 1)
        #expect(owners[0]["path"] as? String == "mount-proof")
        #expect(owners[0]["user"] as? Int == 123)
        #expect(owners[0]["group"] as? Int == 456)
    }

    @Test(arguments: [ContainerPhase.created, .running])
    func directBlockArchiveBootsAndStopsOnlyCreatedWorkload(phase: ContainerPhase) async throws {
        let fixture = try WorkloadPeerFixture(mode: .none)
        defer { fixture.remove() }
        let exchange = try await archivePeerExchange(fixture, phase: phase)
        try exchange.result.get()
        #expect(exchange.requests.map(\.operation) == (phase == .created
            ? [.boot, .guest, .stop] : [.status, .guest]))
    }

    @Test func delayedArchiveResumptionGetsIndependentAcceptBudget() async throws {
        let fixture = try WorkloadPeerFixture()
        defer { fixture.remove() }
        let ready = DispatchSemaphore(value: 0)
        let gate = ArchiveDelayGate(ready: ready)
        let exchange = try await archivePeerExchange(fixture, phase: .running, nextRequestReady: ready,
            validate: { try await gate.validate() })
        try exchange.result.get()
        #expect(exchange.requests.map(\.operation) == [.status, .guest])
        #expect(await gate.calls == 3)
    }

    @Test func delayedWorkloadStartupRetainsAuthenticatedAcknowledgement() async throws {
        let fixture = try WorkloadPeerFixture()
        defer { fixture.remove() }
        let exchange = try await workloadPeerExchange(fixture.client, delayedStartup: true)
        #expect(try exchange.result.get() == workloadPeerStatus(fixture.specification))
        #expect(exchange.capture.request?.token == fixture.specification.token)
        #expect(exchange.capture.acknowledged)
    }

    @Test func runningManagedArchiveFailureDoesNotStopOrReconfigureWorkload() async throws {
        let fixture = try WorkloadPeerFixture()
        defer { fixture.remove() }
        let exchange = try await archivePeerExchange(fixture, phase: .running, copyFailure: true)
        #expect(throws: EngineError.self) { try exchange.result.get() }
        #expect(exchange.requests.map(\.operation) == [.status, .guest])
    }

    @Test(arguments: [ContainerPhase.created, .paused, .exited, .dead])
    func inactiveManagedArchiveCannotBootConfigureCopyOrStop(phase: ContainerPhase) async throws {
        let fixture = try WorkloadPeerFixture()
        defer { fixture.remove() }
        let listener = try UnixSocket.listen(path: fixture.specification.socketPath)
        defer { Darwin.close(listener) }
        let watchdog = Task {
            do { try await Task.sleep(for: .seconds(5)); fixture.client.invalidateRequests() } catch {}
        }
        defer { watchdog.cancel() }
        await #expect(throws: EngineError.self) {
            try await RawVirtualizationBackend.copyInToShim(fixture.client, phase: phase,
                source: "owned-transfer", destination: "/", ownership: [], validate: {})
        }
        var ready = pollfd(fd: listener, events: Int16(POLLIN), revents: 0)
        #expect(Darwin.poll(&ready, 1, 0) == 0)
    }

    @Test(arguments: [VMShimProtocol.State.created, .starting, .paused, .stopping, .stopped, .failed])
    func runningArchiveCannotReviveNonrunningManagedVM(state: VMShimProtocol.State) async throws {
        let fixture = try WorkloadPeerFixture()
        defer { fixture.remove() }
        let exchange = try await archivePeerExchange(fixture, phase: .running, state: state)
        #expect(throws: EngineError.self) { try exchange.result.get() }
        #expect(exchange.requests.map(\.operation) == [.status])
    }

    @Test func archiveRevalidatesExecutionAfterStatusBeforeSendingMutation() async throws {
        let fixture = try WorkloadPeerFixture()
        defer { fixture.remove() }
        let gate = ArchiveValidationGate()
        let exchange = try await archivePeerExchange(fixture, phase: .running,
            stopAfterStatus: true, validate: { try await gate.validate() })
        #expect(throws: ArchiveValidationGate.Failure.self) { try exchange.result.get() }
        #expect(exchange.requests.map(\.operation) == [.status])
        #expect(await gate.calls == 2)
    }

    @Test(arguments: [false, true])
    func exactPublishedNativeWorkloadPeerReceivesToken(upgrade: Bool) async throws {
        let fixture = try WorkloadPeerFixture()
        defer { fixture.remove() }
        #expect(fixture.record.kernelIdentity == fixture.native)
        #expect(fixture.client.persistentGenerationDirectory?.identity == fixture.files.directoryIdentity)
        #expect(fixture.client.persistentLaunchIntentURL == fixture.files.intentURL)
        let exchange = try await workloadPeerExchange(fixture.client, upgrade: upgrade)
        #expect(try exchange.result.get() == workloadPeerStatus(fixture.specification))
        #expect(exchange.capture.peerPID == getpid())
        #expect(exchange.capture.request?.token == fixture.specification.token)
        #expect(exchange.capture.request?.operation == (upgrade ? .startPortStream : .status))
        #expect(exchange.capture.acknowledged == !upgrade)
        let request = try #require(exchange.capture.request)
        // JSONEncoder key order is not stable across encodes. Decoding the
        // exact captured frame still rejects trailing acknowledgement bytes.
        #expect(try VMShimProtocol.decode(exchange.capture.bytes) == request)
    }

    @Test func productionWorkloadReplyRetainsNativePeerUntilAcknowledged() async throws {
        let observation = try await peerFixtureOnThread { try Self.checkProductionWorkloadReply() }
        #expect(observation.requestMatched)
        #expect(observation.replyMatched)
        #expect(!observation.writerFinishedBeforeAcknowledgement)
        try observation.writerResult.get()
        try observation.proof.get()
    }

    private struct ProductionWorkloadReplyObservation: Sendable {
        let requestMatched: Bool
        let replyMatched: Bool
        let writerFinishedBeforeAcknowledgement: Bool
        let proof: Result<Void, any Error>
        let writerResult: Result<Void, any Error>
    }

    private static func checkProductionWorkloadReply() throws -> ProductionWorkloadReplyObservation {
        let fixture = try WorkloadPeerFixture()
        defer { fixture.remove() }
        let listener = try UnixSocket.listen(path: fixture.specification.socketPath)
        defer { Darwin.close(listener) }
        let client = VMShimManagedTransport()
        defer { client.close() }
        try client.connect(path: fixture.specification.socketPath)
        let peer = try UnixSocket.accept(listener)
        let server = VMShimManagedTransport()
        defer { server.close() }
        do { try server.adopt(peer) } catch { Darwin.close(peer); throw error }
        let descriptor = try client.ownedDescriptor()
        try fixture.client.validateManagedStoragePeer(descriptor)
        let request = VMShimProtocol.Envelope(token: fixture.specification.token, operation: .status)
        try client.write(VMShimProtocol.encode(request))
        let receivedRequest = try VMShimProtocol.decode(server.readFrame())
        let frame = try VMShimProtocol.encode(.init(id: request.id, token: request.token, operation: request.operation,
            payload: JSONEncoder().encode(workloadPeerStatus(fixture.specification))))
        let deadline = VMShimServer.replyAcknowledgementDeadline(fixture.specification,
            acceptedDeadline: 0, requestDeadline: nil)
        let writer = PeerFixtureWorker {
            defer { server.close() }
            if deadline != nil { try VMShimServer.writeManagedReply(frame, using: server) }
            else { try server.write(frame) }
        }
        defer {
            server.cancel()
            precondition(writer.wait(milliseconds: 15_000), "reply worker did not join before fixture cleanup")
        }
        let receivedFrame = try client.readFrame()
        let writerFinishedBeforeAcknowledgement = writer.wait(milliseconds: 100)
        let proof = Result { try fixture.client.validateManagedStoragePeer(descriptor) }
        if case .success = proof { try client.write(Data([VMShimServer.managedReplyAcknowledgement])) }
        else { client.close() }
        return try .init(requestMatched: receivedRequest == request, replyMatched: receivedFrame == frame,
            writerFinishedBeforeAcknowledgement: writerFinishedBeforeAcknowledgement,
            proof: proof, writerResult: writer.result())
    }

    @Test func replyDeadlineDoesNotTimeLimitWorkloadLifetimeOrRenewCallerBudget() throws {
        let fixture = try WorkloadPeerFixture()
        defer { fixture.remove() }
        let now: UInt64 = 60_000_000_000 // Well after the connection's old admission time.
        let expiredAcceptance: UInt64 = 1
        let limit = now + VMShimManagedTransport.maximumNanoseconds
        #expect(VMShimServer.replyAcknowledgementDeadline(fixture.specification,
            acceptedDeadline: expiredAcceptance, requestDeadline: nil, nowNanoseconds: now) == limit)
        for deadline in [UInt64(0), now - 1, now + 1, UInt64.max] {
            #expect(VMShimServer.replyAcknowledgementDeadline(fixture.specification,
                acceptedDeadline: expiredAcceptance, requestDeadline: deadline, nowNanoseconds: now) == min(deadline, limit))
        }
        var legacy = fixture.specification
        legacy.workloadStorageMode = .none
        #expect(VMShimServer.replyAcknowledgementDeadline(legacy,
            acceptedDeadline: expiredAcceptance, requestDeadline: nil, nowNanoseconds: now) == nil)
        var storage = legacy
        storage.kind = .storage
        #expect(VMShimServer.replyAcknowledgementDeadline(storage,
            acceptedDeadline: expiredAcceptance, requestDeadline: nil, nowNanoseconds: now) == expiredAcceptance)
    }

    @Test func unauthenticatedManagedRepliesCannotReserveAnAcknowledgementWindow() throws {
        let fixture = try WorkloadPeerFixture()
        defer { fixture.remove() }
        var storage = fixture.specification
        storage.kind = .storage
        for specification in [fixture.specification, storage] {
            #expect(VMShimServer.replyAcknowledgementDeadline(specification,
                acceptedDeadline: UInt64.max, requestDeadline: nil,
                requestAuthenticated: false) == nil)
        }
    }

    @Test func workloadWaitKeepsUnboundedOperationAndAcknowledgesOnlyItsReply() async throws {
        let fixture = try WorkloadPeerFixture()
        defer { fixture.remove() }
        let exchange = try await workloadPeerExchange(fixture.client, guestWait: true)
        #expect(try exchange.result.get() == workloadPeerStatus(fixture.specification))
        let request = try #require(exchange.capture.request)
        #expect(request.operation == .guest)
        #expect(request.deadlineNanoseconds == nil)
        let call = try JSONDecoder().decode(VMShimClient.GuestCall.self, from: #require(request.payload))
        #expect(call.operation == "wait")
        #expect(call.deadlineNanoseconds == nil)
        #expect(exchange.capture.acknowledged)
    }

    @Test(arguments: [false, true])
    func workloadErrorRepliesAreAcknowledgedIncludingFailedUpgrades(upgrade: Bool) async throws {
        let fixture = try WorkloadPeerFixture()
        defer { fixture.remove() }
        let exchange = try await workloadPeerExchange(fixture.client, upgrade: upgrade, replyFailure: true)
        if case .success = exchange.result { Issue.record("workload error reply succeeded") }
        #expect(exchange.capture.request != nil)
        #expect(exchange.capture.acknowledged)
    }

    @Test(arguments: ["direct", "boot-wrapper", "raw-text"])
    func authenticatedWorkloadBootForwardsOnlyClosedPrivateDiagnostic(shape: String) async throws {
        let fixture = try WorkloadPeerFixture()
        defer { fixture.remove() }
        let local = PrivateWorkloadStorageCoordinator.failure(stage: .readEOF)
        let nsError = local as NSError
        var text = "\(local.message) [\(nsError.domain) \(nsError.code)]"
        if shape == "boot-wrapper" {
            let boot = EngineError(.internalError, "boot step 'start virtual machine' failed: \(text)")
            let nsBoot = boot as NSError
            text = "\(boot.message) [\(nsBoot.domain) \(nsBoot.code)]"
        } else if shape == "raw-text" { text += " private-test-token" }
        let exchange = try await workloadPeerExchange(fixture.client, replyFailure: true,
            workloadBoot: true, replyMessage: text)
        guard case .failure(let error) = exchange.result else { Issue.record("private boot error succeeded"); return }
        #expect(error.localizedDescription == (shape == "raw-text"
            ? PrivateWorkloadStorageCoordinator.failure().message : local.message))
        #expect(!error.localizedDescription.contains("private-test-token"))
        #expect(exchange.capture.request?.operation == .workloadStorageBoot)
        #expect(exchange.capture.acknowledged)
    }

    @Test func recoveryObservationIsOneAuthenticatedStatusOnlyExchange() async throws {
        let fixture = try WorkloadPeerFixture(containerID: String(repeating: "a", count: 64))
        defer { fixture.remove() }
        let reply = workloadRecoveryReply(fixture.specification)
        let scope = try #require(reply.scope)
        let exchange = try await workloadPeerExchange(fixture.client, workloadStatusScope: scope,
            workloadStatusReply: Data(try WorkloadStorageProtocol.encode(reply).dropFirst(4)),
            deadlineNanoseconds: nil)
        try exchange.result.get()
        #expect(exchange.workloadStatus == reply)
        #expect(exchange.capture.acknowledged)
        let request = try #require(exchange.capture.request)
        #expect(request.operation == .workloadStorageStatus)
        #expect(request.deadlineNanoseconds == exchange.callerDeadline)
        #expect(exchange.callerDeadline != nil)
        let payload = try #require(request.payload)
        #expect(try JSONDecoder().decode(WorkloadStorageProtocol.Scope.self, from: payload) == scope)
        let object = try #require(JSONSerialization.jsonObject(with: payload) as? [String: Any])
        #expect(object["binding"] == nil && object["configuration"] == nil && object["operation"] == nil)
        #expect(exchange.workloadStatus?.data.terminalIDs == [])
    }

    @Test(arguments: ["launch", "scope", "operation", "kind", "phase", "code", "raw-field"])
    func recoveryObservationRejectsUnboundOrNonrunningStatusReply(fault: String) async throws {
        let fixture = try WorkloadPeerFixture(containerID: String(repeating: "a", count: 64))
        defer { fixture.remove() }
        var reply = workloadRecoveryReply(fixture.specification)
        let scope = try #require(reply.scope)
        switch fault {
        case "launch":
            let launch = UUID().uuidString.lowercased()
            reply.binding.shimLaunchUUID = launch; reply.scope?.launch = launch
        case "scope": reply.scope?.controllerEpoch += 1
        case "operation": reply.operation = .command; reply.data = .init()
        case "kind": reply.kind = .abort; reply.data = .init(terminalIDs: [])
        case "phase": reply.data.phase = .aborted
        case "code": reply.data = .init(code: .phase)
        default: break
        }
        var body = Data(try WorkloadStorageProtocol.encode(reply).dropFirst(4))
        if fault == "raw-field" {
            var object = try #require(JSONSerialization.jsonObject(with: body) as? [String: Any])
            object["private-raw-field"] = "never-promote"
            body = try JSONSerialization.data(withJSONObject: object)
        }
        let exchange = try await workloadPeerExchange(fixture.client, workloadStatusScope: scope,
            workloadStatusReply: body, deadlineNanoseconds: nil)
        #expect(throws: (any Error).self) { try exchange.result.get() }
        #expect(exchange.workloadStatus == nil)
        #expect(exchange.capture.request?.operation == .workloadStorageStatus)
    }

    @Test func recoveryObservationRevalidatesExactPeerAfterReply() async throws {
        let fixture = try WorkloadPeerFixture(containerID: String(repeating: "a", count: 64))
        defer { fixture.remove() }
        let reply = workloadRecoveryReply(fixture.specification)
        let exchange = try await workloadPeerExchange(fixture.client, workloadStatusScope: #require(reply.scope),
            workloadStatusReply: Data(try WorkloadStorageProtocol.encode(reply).dropFirst(4)),
            deadlineNanoseconds: nil, beforeReply: {
                var object = try fixture.recordObject()
                object.removeValue(forKey: "kernelIdentity")
                try JSONSerialization.data(withJSONObject: object).write(to: fixture.files.recordURL)
            })
        #expect(throws: (any Error).self) { try exchange.result.get() }
        #expect(exchange.workloadStatus == nil && !exchange.capture.acknowledged)
    }

    @Test(arguments: [false, true])
    func cancelledRecoveryObservationCannotReturnAnOtherwiseValidReply(delayedStartup: Bool) async throws {
        let fixture = try WorkloadPeerFixture(containerID: String(repeating: "a", count: 64))
        defer { fixture.remove() }
        let listener = try UnixSocket.listen(path: fixture.specification.socketPath)
        defer { Darwin.close(listener) }
        let reply = workloadRecoveryReply(fixture.specification), scope = try #require(reply.scope)
        let payload = Data(try WorkloadStorageProtocol.encode(reply).dropFirst(4))
        let accepting = DispatchSemaphore(value: 0)
        let cancelledAt = Mutex<ContinuousClock.Instant?>(nil)
        let completedAt = Mutex<ContinuousClock.Instant?>(nil)
        let observation = Task {
            defer { completedAt.withLock { $0 = .now } }
            if delayedStartup { try await delayPeerFixtureClient(until: accepting) }
            return try await fixture.client.observeRunningWorkloadStorage(expectedScope: scope,
                deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + PeerFixtureBudget.functionalNanoseconds)
        }
        let watchdog = PeerFixtureWatchdog { observation.cancel(); fixture.client.invalidateRequests() }
        defer { watchdog.finish() }
        let server = PeerFixtureWorker {
            try serveWorkloadPeer(listener, specification: fixture.specification, replyPayload: payload,
                beforeWrite: {
                    cancelledAt.withLock { $0 = .now }
                    observation.cancel()
                }, accepting: { accepting.signal() })
        }
        let result: Result<WorkloadStorageProtocol.Frame, any Error>
        do { result = .success(try await observation.value) }
        catch { result = .failure(error) }
        // Join both workers even on failure, before releasing listener/files.
        let capture = try await server.value(preserving: result)
        if case .success = result { Issue.record("cancelled recovery returned a valid reply") }
        let trigger = try #require(cancelledAt.withLock { $0 })
        let completion = try #require(completedAt.withLock { $0 })
        #expect(completion >= trigger)
        #expect(completion - trigger < .seconds(3))
        #expect(capture.request?.operation == .workloadStorageStatus)
        #expect(!capture.acknowledged)
    }

    @Test func expiredRecoveryObservationCannotSendOrBoot() async throws {
        let fixture = try WorkloadPeerFixture(containerID: String(repeating: "a", count: 64))
        defer { fixture.remove() }
        let listener = try UnixSocket.listen(path: fixture.specification.socketPath)
        defer { Darwin.close(listener) }
        let scope = try #require(workloadRecoveryReply(fixture.specification).scope)
        await #expect(throws: EngineError.self) {
            _ = try await fixture.client.observeRunningWorkloadStorage(expectedScope: scope, deadlineNanoseconds: 0)
        }
        var ready = pollfd(fd: listener, events: Int16(POLLIN), revents: 0)
        #expect(Darwin.poll(&ready, 1, 0) == 0)
    }

    @Test func publicHandleWithoutGenerationEvidenceCannotAuthenticate() async throws {
        let fixture = try WorkloadPeerFixture()
        defer { fixture.remove() }
        try await expectWorkloadPeerRejection(VMShimClient(
            specification: fixture.specification, processIdentifier: getpid()
        ))
    }

    @Test(arguments: ["missingKernel", "zeroUniqueID", "invalidBoot", "start", "uniqueID", "bothBirthFields", "otherBoot", "otherPID"], [false, true])
    func nativeIdentityMustBeCompleteAndExactlyAlive(field: String, upgrade: Bool) async throws {
        let fixture = try WorkloadPeerFixture()
        defer { fixture.remove() }
        let actual = fixture.native
        let start = actual.startSeconds + (["start", "bothBirthFields"].contains(field) ? 1 : 0)
        let unique = actual.uniqueID + (["uniqueID", "bothBirthFields"].contains(field) ? 1 : 0)
        let recorded = Recovery.ProcessIdentity(
            pid: field == "otherPID" ? getppid() : actual.pid,
            startSeconds: start, startMicroseconds: actual.startMicroseconds,
            bootUUID: field == "invalidBoot" ? "" : field == "otherBoot" ? UUID().uuidString.lowercased() : actual.bootUUID,
            uniqueID: field == "zeroUniqueID" ? 0 : unique
        )
        if ["start", "uniqueID"].contains(field) {
            #expect(Recovery.liveness(recorded, observation: Recovery.observe(getpid())) == .unknown)
        }
        if field == "bothBirthFields" {
            #expect(Recovery.liveness(recorded, observation: Recovery.observe(getpid())) == .dead)
        }
        var object = try fixture.recordObject()
        if field == "missingKernel" {
            object.removeValue(forKey: "kernelIdentity")
        } else {
            object["kernelIdentity"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(recorded))
            // Keep the historical PID/start fields consistent, so rejection
            // tests positive native birth proof, not merely scalar disagreement.
            object["processIdentifier"] = recorded.pid
            object["processStartTime"] = recorded.startSeconds * 1_000_000 + recorded.startMicroseconds
        }
        try JSONSerialization.data(withJSONObject: object).write(to: fixture.files.recordURL)
        // Missing/unknown native evidence remains readable for containment and
        // cleanup. Enumeration is not managed socket adoption authority.
        let recovered = try fixture.recover()
        #expect(recovered.hasPersistentLaunchRecord)
        let retained = try Data(contentsOf: fixture.files.recordURL)
        try await expectWorkloadPeerRejection(recovered, upgrade: upgrade)
        #expect(try Data(contentsOf: fixture.files.recordURL) == retained)
    }

    @Test(arguments: ["intent.json", "spec.json", "launch.json"])
    func missingImmutableEvidenceClosesBeforeAnyToken(name: String) async throws {
        let fixture = try WorkloadPeerFixture()
        defer { fixture.remove() }
        try FileManager.default.removeItem(at: fixture.files.directory.appending(path: name))
        try await expectWorkloadPeerRejection(fixture.client)
    }

    @Test(arguments: ["token", "generation", "cpus", "launchUUID", "nilLaunchUUID", "mode"])
    func changedImmutableSpecificationCannotAuthorizeExistingHandle(field: String) async throws {
        let fixture = try WorkloadPeerFixture()
        defer { fixture.remove() }
        var changed = fixture.specification
        switch field {
        case "token": changed.token = "different-token"
        case "generation": changed.generation += 1
        case "cpus": changed.cpus += 1
        case "launchUUID": changed.shimLaunchUUID = UUID().uuidString.lowercased()
        case "nilLaunchUUID": changed.shimLaunchUUID = nil
        default: changed.workloadStorageMode = .none
        }
        try fixture.replaceSpecification(changed)
        try await expectWorkloadPeerRejection(fixture.client)
    }

    @Test func nilLaunchUUIDRemainsCleanupOnlyEvenWithNativeEvidence() async throws {
        let fixture = try WorkloadPeerFixture()
        defer { fixture.remove() }
        var legacy = fixture.specification
        legacy.shimLaunchUUID = nil
        try fixture.replaceSpecification(legacy)
        let recovered = try fixture.recover()
        #expect(recovered.specification.shimLaunchUUID == nil)
        try await expectWorkloadPeerRejection(recovered)
    }

    @Test func replacedGenerationDirectoryCannotAuthenticateRetainedHandle() async throws {
        let fixture = try WorkloadPeerFixture()
        defer { fixture.remove() }
        let moved = fixture.files.directory.appendingPathExtension("old")
        try FileManager.default.moveItem(at: fixture.files.directory, to: moved)
        try FileManager.default.copyItem(at: moved, to: fixture.files.directory)
        try await expectWorkloadPeerRejection(fixture.client)
    }

    @Test(arguments: [false, true])
    func changedNativeRecordAfterReplyIsRejected(upgrade: Bool) async throws {
        let fixture = try WorkloadPeerFixture()
        defer { fixture.remove() }
        let exchange = try await workloadPeerExchange(fixture.client, upgrade: upgrade, beforeReply: {
            var object = try fixture.recordObject()
            object.removeValue(forKey: "kernelIdentity")
            try JSONSerialization.data(withJSONObject: object).write(to: fixture.files.recordURL)
        })
        if case .success = exchange.result { Issue.record("post-reply evidence change was accepted") }
        #expect(exchange.capture.request?.token == fixture.specification.token)
        #expect(!exchange.capture.acknowledged)
    }

    @Test func publicationCannotUpgradeLegacyEvidenceOrPublishInventedBirth() throws {
        let fixture = try WorkloadPeerFixture()
        defer { fixture.remove() }
        var object = try fixture.recordObject()
        object.removeValue(forKey: "kernelIdentity")
        try JSONSerialization.data(withJSONObject: object).write(to: fixture.files.recordURL)
        let retained = try Data(contentsOf: fixture.files.recordURL)
        #expect(throws: (any Error).self) { try fixture.publish() }
        #expect(try Data(contentsOf: fixture.files.recordURL) == retained)
        let fake = VMShimClient.ProcessIdentity(processIdentifier: getpid(), startTime: 1)
        #expect(throws: (any Error).self) {
            try VMShimClient.publishPersistentLaunchIdentity(
                intentURL: fixture.files.intentURL, expectedIdentity: fake,
                identityProvider: { _ in fake },
                inspectionProvider: { _ in fixture.inspection(fake) }
            )
        }
        #expect(try Data(contentsOf: fixture.files.recordURL) == retained)
    }

    @Test func closedBeforeAcceptStillReportsZeroByteEOF() throws {
        let fixture = try WorkloadPeerFixture()
        defer { fixture.remove() }
        let listener = try UnixSocket.listen(path: fixture.specification.socketPath)
        defer { Darwin.close(listener) }
        let connection = try UnixSocket.connect(path: fixture.specification.socketPath)
        Darwin.close(connection)
        let capture = try serveWorkloadPeer(listener, specification: fixture.specification)
        #expect(capture.bytes.isEmpty)
        #expect(capture.request == nil)
        #expect(capture.peerPID == nil)
    }
}

private struct WorkloadPeerFixture: @unchecked Sendable {
    let directory: URL
    let specification: VMShimProtocol.Specification
    let files: VMShimClient.PersistentSpawnFiles
    let native: RawStorageShimRecovery.ProcessIdentity
    let record: VMShimClient.PersistentLaunchRecord
    let client: VMShimClient
    let disk: FileHandle
    private let executable: URL

    init(mode: VMShimProtocol.Specification.WorkloadStorageMode = .managed, containerID: String = "workload-peer") throws {
        directory = URL(filePath: "/tmp/ce-wpeer-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        do {
            let diskURL = directory.appending(path: "root.ext4")
            try Data(repeating: 0x5a, count: 4_096).write(to: diskURL)
            disk = try FileHandle(forUpdating: diskURL)
            guard flock(disk.fileDescriptor, LOCK_EX | LOCK_NB) == 0 else { throw POSIXError(.EIO) }
            let owner = try PersistentStateDirectory.open(directory)
            let container = ContainerRecord(id: containerID, name: "workload-peer", image: "alpine")
            executable = (Bundle.main.executableURL ?? URL(filePath: CommandLine.arguments[0])).resolvingSymlinksInPath()
            specification = try VMShimProtocol.Specification(
                containerID: container.id, generation: 1, token: "private-managed-workload-peer-token",
                kernelPath: "/unused", initialRamdiskPath: "/unused", rootDiskPath: diskURL.path,
                rootDiskIdentity: owner.regularFileIdentity(named: "root.ext4").shimIdentity,
                rootDiskSize: 4_096, cpus: 1, memoryBytes: 268_435_456,
                macAddress: "02:ce:00:00:00:01", socketPath: directory.appending(path: "shim.sock").path,
                logPath: directory.appending(path: "shim.log").path,
                shimLaunchUUID: UUID().uuidString.lowercased(), workloadStorageMode: mode
            )
            files = try VMShimClient.preparePersistentSpawn(specification: specification,
                container: container, containerDirectory: owner, executable: executable)
            guard case let .process(identity) = RawStorageShimRecovery.observe(getpid()) else {
                throw POSIXError(.EIO)
            }
            native = identity
            let process = VMShimClient.ProcessIdentity(processIdentifier: identity.pid,
                startTime: identity.startSeconds * 1_000_000 + identity.startMicroseconds)
            let inspection = VMShimClient.ProcessInspection(identityBefore: process,
                executablePath: executable.resolvingSymlinksInPath().path,
                arguments: [executable.path, "vm-shim", "--spec", files.specificationURL.path,
                    "--launch-intent", files.intentURL.path], identityAfter: process)
            // Only argv inspection is synthetic: publication itself queries the
            // real native PID/start/boot/unique ID, with real exclusive records.
            record = try VMShimClient.publishPersistentLaunchIdentity(intentURL: files.intentURL,
                expectedIdentity: process, inspectionProvider: { _ in inspection })
            let launches = try VMShimClient.persistedLaunches(in: owner, expectedContainerID: container.id,
                expectedExecutable: executable, processIdentifiersProvider: { .complete([]) })
            guard let recovered = launches.first?.client else {
                throw PeerFixtureFailure.prerequisite("missing published workload client")
            }
            client = recovered
        } catch {
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
    }

    func inspection(_ identity: VMShimClient.ProcessIdentity) -> VMShimClient.ProcessInspection {
        .init(identityBefore: identity, executablePath: executable.resolvingSymlinksInPath().path,
            arguments: [executable.path, "vm-shim", "--spec", files.specificationURL.path,
                "--launch-intent", files.intentURL.path], identityAfter: identity)
    }

    @discardableResult func publish() throws -> VMShimClient.PersistentLaunchRecord {
        let identity = VMShimClient.ProcessIdentity(processIdentifier: native.pid,
            startTime: native.startSeconds * 1_000_000 + native.startMicroseconds)
        return try VMShimClient.publishPersistentLaunchIdentity(intentURL: files.intentURL,
            expectedIdentity: identity, inspectionProvider: { _ in inspection(identity) })
    }

    func recover() throws -> VMShimClient {
        let launches = try VMShimClient.persistedLaunches(in: files.containerDirectory,
            expectedContainerID: specification.containerID, expectedExecutable: executable,
            processIdentifiersProvider: { .complete([]) })
        guard let client = launches.first?.client else {
            throw PeerFixtureFailure.prerequisite("missing recovered workload client")
        }
        return client
    }

    func recordObject() throws -> [String: Any] {
        guard let object = try JSONSerialization.jsonObject(with: Data(contentsOf: files.recordURL)) as? [String: Any] else {
            throw PeerFixtureFailure.prerequisite("workload launch record is not an object")
        }
        return object
    }

    func replaceSpecification(_ replacement: VMShimProtocol.Specification) throws {
        let value = try JSONSerialization.jsonObject(with: JSONEncoder().encode(replacement))
        for url in [files.intentURL, files.recordURL] {
            guard var object = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any] else {
                throw PeerFixtureFailure.prerequisite("workload publication is not an object")
            }
            object["specification"] = value
            try JSONSerialization.data(withJSONObject: object).write(to: url)
        }
        try JSONEncoder().encode(replacement).write(to: files.specificationURL)
    }

    func remove() {
        try? disk.close()
        try? FileManager.default.removeItem(at: directory)
    }
}

private actor ArchiveDelayGate {
    private let ready: DispatchSemaphore
    private(set) var calls = 0
    init(ready: DispatchSemaphore) { self.ready = ready }
    func validate() async throws {
        calls += 1
        if calls == 2 { try await delayPeerFixtureClient(until: ready) }
    }
}

private actor ArchiveValidationGate {
    enum Failure: Error { case replaced }
    private(set) var calls = 0
    func validate() throws {
        calls += 1
        if calls == 2 { throw Failure.replaced }
    }
}

private struct ArchivePeerExchange: Sendable {
    let result: Result<Void, any Error>
    let requests: [VMShimProtocol.Envelope]
}

private func archivePeerExchange(_ fixture: WorkloadPeerFixture, phase: ContainerPhase,
    state: VMShimProtocol.State = .running, stopAfterStatus: Bool = false, copyFailure: Bool = false,
    nextRequestReady: DispatchSemaphore? = nil, validate: @escaping @Sendable () async throws -> Void = {}) async throws -> ArchivePeerExchange {
    let listener = try UnixSocket.listen(path: fixture.specification.socketPath)
    defer { Darwin.close(listener) }
    let budget = PeerFixtureBudget()
    let server = PeerFixtureWorker {
        // accept/read/ack and the next accept must not occupy the executor
        // needed by copyInToShim to resume and send its next request.
        try serveArchivePeer(listener, fixture: fixture,
            phase: phase, state: state, stopAfterStatus: stopAfterStatus, copyFailure: copyFailure, budget: budget,
            nextRequestReady: nextRequestReady)
    }
    let watchdog = PeerFixtureWatchdog { fixture.client.invalidateRequests() }
    defer { watchdog.finish() }
    let result: Result<Void, any Error>
    do {
        try await RawVirtualizationBackend.copyInToShim(fixture.client, phase: phase,
            source: "owned-transfer", destination: "/",
            ownership: [.init(path: "mount-proof", user: 123, group: 456)], validate: validate)
        result = .success(())
    } catch { result = .failure(error) }
    let requests = try await server.value(preserving: result)
    for request in requests { #expect(request.token == fixture.specification.token) }
    // Keep accepting evidence until the client settles, including any forbidden
    // request attempted after it consumes the final expected reply.
    var ready = pollfd(fd: listener, events: Int16(POLLIN), revents: 0)
    #expect(Darwin.poll(&ready, 1, 0) == 0)
    return .init(result: result, requests: requests)
}

private func serveArchivePeer(_ listener: CInt, fixture: WorkloadPeerFixture, phase: ContainerPhase,
    state: VMShimProtocol.State, stopAfterStatus: Bool, copyFailure: Bool, budget: PeerFixtureBudget,
    nextRequestReady: DispatchSemaphore?) throws -> [VMShimProtocol.Envelope] {
        var requests: [VMShimProtocol.Envelope] = []
        for index in 0..<4 {
            let acceptDeadline = budget.deadline(after: PeerFixtureBudget.startupNanoseconds)
            if index == 1 { nextRequestReady?.signal() }
            try waitForWorkloadPeerIO(listener, events: Int16(POLLIN),
                deadline: acceptDeadline, phase: "archive accept[\(index)]")
            let peer = try UnixSocket.accept(listener)
            let scope = VMShimManagedTransport(deadlineNanoseconds:
                budget.deadline(after: PeerFixtureBudget.ioNanoseconds))
            do { try scope.adopt(peer) } catch { Darwin.close(peer); throw error }
            defer { scope.close() }
            let request = try peerFixturePhase("archive request[\(index)]") { try VMShimProtocol.decode(scope.readFrame()) }
            requests.append(request)
            var status = workloadPeerStatus(fixture.specification)
            status.state = request.operation == .stop ? .stopped : state
            let managed = fixture.specification.workloadStorageMode == .managed
            let failure: GuestProtocol.Failure?
            if request.operation == .boot && managed {
                failure = .init(code: "shim_error", message: "managed storage requires its private boot configuration")
            } else if request.operation == .guest && copyFailure {
                failure = .init(code: "shim_error", message: "copy denied")
            } else { failure = nil }
            let payload = request.operation == .guest
                ? Data(#"{"status":"ok"}"#.utf8) : try JSONEncoder().encode(status)
            let reply = try VMShimProtocol.encode(.init(id: request.id, token: request.token,
                operation: request.operation, payload: failure == nil ? payload : nil, error: failure))
            try peerFixturePhase("archive reply/ack[\(index)]") {
                if managed { try VMShimServer.writeManagedReply(reply, using: scope) }
                else { try scope.write(reply) }
            }
            if failure != nil || state != .running || stopAfterStatus || request.operation == .stop
                || (request.operation == .guest && phase == .running) { return requests }
        }
        throw POSIXError(.ELOOP)
}

private struct WorkloadPeerCapture: Sendable {
    let peerPID: pid_t?
    let bytes: Data
    let request: VMShimProtocol.Envelope?
    var acknowledged = false
}

private struct WorkloadPeerExchange: Sendable {
    let result: Result<VMShimProtocol.Status, any Error>
    let capture: WorkloadPeerCapture
    let workloadStatus: WorkloadStorageProtocol.Frame?
    let callerDeadline: UInt64?
}

private func workloadRecoveryReply(_ specification: VMShimProtocol.Specification) -> WorkloadStorageProtocol.Frame {
    func id() -> String { UUID().uuidString.lowercased() }
    let binding = WorkloadStorageProtocol.BootBinding(shimLaunchUUID: specification.shimLaunchUUID!, guestBootNonce: id())
    let scope = WorkloadStorageProtocol.Scope(intent: id(), store: id(), serviceEpoch: id(),
        controllerEpoch: 1, controllerKey: String(repeating: "c", count: 64), container: specification.containerID,
        containerInstance: id(), launch: binding.shimLaunchUUID, prepare: id(), specificationDigest: String(repeating: "d", count: 64))
    return .init(operation: .reply, binding: binding, scope: scope, sequence: 10, kind: .status,
        data: .init(phase: .running, mountedIDs: [id()], terminalIDs: []))
}

private func workloadPeerStatus(_ specification: VMShimProtocol.Specification) -> VMShimProtocol.Status {
    .init(containerID: specification.containerID, generation: specification.generation,
        state: .created, processIdentifier: getpid(), shimLaunchUUID: specification.shimLaunchUUID)
}

private func expectWorkloadPeerRejection(_ client: VMShimClient, upgrade: Bool = false) async throws {
    let exchange = try await workloadPeerExchange(client, upgrade: upgrade)
    switch exchange.result {
    case .success: Issue.record("unproven managed workload peer was accepted")
    case let .failure(error): #expect(!EngineError.message(for: error).contains(client.specification.token))
    }
    // Actual accepted-socket EOF, never timeout or a failed accept, proves that
    // rejection happened before even a frame prefix (and therefore any token).
    #expect(exchange.capture.peerPID == nil || exchange.capture.peerPID == getpid())
    #expect(exchange.capture.bytes.isEmpty)
    #expect(exchange.capture.request == nil)
}

private func workloadPeerExchange(
    _ client: VMShimClient, upgrade: Bool = false, replyFailure: Bool = false, guestWait: Bool = false,
    workloadBoot: Bool = false, replyMessage: String = "closed test failure",
    workloadStatusScope: WorkloadStorageProtocol.Scope? = nil, workloadStatusReply: Data? = nil,
    deadlineNanoseconds: UInt64? = nil, delayedStartup: Bool = false, beforeReply: (@Sendable () throws -> Void)? = nil
) async throws -> WorkloadPeerExchange {
    // A successful upgrade closes only after the async client resumes. Keep
    // that continuation off the shared pool without extending the EOF budget.
    try await withTaskExecutorPreference(ManagedPeerFixtureExecutor()) {
        try await workloadPeerExchangeOnExecutor(client, upgrade: upgrade, replyFailure: replyFailure,
            guestWait: guestWait, workloadBoot: workloadBoot, replyMessage: replyMessage,
            workloadStatusScope: workloadStatusScope, workloadStatusReply: workloadStatusReply,
            deadlineNanoseconds: deadlineNanoseconds, delayedStartup: delayedStartup, beforeReply: beforeReply)
    }
}

private func workloadPeerExchangeOnExecutor(
    _ client: VMShimClient, upgrade: Bool, replyFailure: Bool, guestWait: Bool,
    workloadBoot: Bool, replyMessage: String,
    workloadStatusScope: WorkloadStorageProtocol.Scope?, workloadStatusReply: Data?,
    deadlineNanoseconds: UInt64?, delayedStartup: Bool, beforeReply: (@Sendable () throws -> Void)?
) async throws -> WorkloadPeerExchange {
    let listener = try UnixSocket.listen(path: client.specification.socketPath)
    let flags = fcntl(listener, F_GETFL)
    guard flags >= 0, fcntl(listener, F_SETFL, flags | O_NONBLOCK) == 0 else {
        Darwin.close(listener)
        throw POSIXError(.EIO)
    }
    let budget = PeerFixtureBudget()
    let accepting = DispatchSemaphore(value: 0)
    let server = PeerFixtureWorker {
        defer { Darwin.close(listener) }
        return try serveWorkloadPeer(listener,
            specification: client.specification, replyFailure: replyFailure, replyMessage: replyMessage,
            replyPayload: workloadStatusReply, beforeReply: beforeReply,
            budget: budget, accepting: { accepting.signal() })
    }
    let watchdog = PeerFixtureWatchdog { client.invalidateRequests() }
    defer { watchdog.finish() }
    let result: Result<VMShimProtocol.Status, any Error>
    var observed: WorkloadStorageProtocol.Frame?
    var callerDeadline: UInt64?
    do {
        if delayedStartup { try await delayPeerFixtureClient(until: accepting) }
        if let workloadStatusScope {
            let deadlineNanoseconds = deadlineNanoseconds ?? budget.deadline(after: PeerFixtureBudget.functionalNanoseconds)
            callerDeadline = deadlineNanoseconds
            observed = try await client.observeRunningWorkloadStorage(expectedScope: workloadStatusScope,
                deadlineNanoseconds: deadlineNanoseconds)
            result = .success(workloadPeerStatus(client.specification))
        } else if upgrade {
            let stream = try await client.startPortStream(transport: "tcp", port: 80, ipv6: false)
            Darwin.close(stream)
            result = .success(workloadPeerStatus(client.specification))
        } else if workloadBoot {
            _ = try await client.bootWorkloadStorage()
            result = .success(workloadPeerStatus(client.specification))
        } else if guestWait {
            result = .success(try await client.guest(operation: "wait", payload: [String: String](), response: VMShimProtocol.Status.self))
        } else {
            result = .success(try await client.status())
        }
    } catch { result = .failure(error) }
    return try await WorkloadPeerExchange(result: result, capture: server.value(preserving: result),
        workloadStatus: observed, callerDeadline: callerDeadline)
}

private func serveWorkloadPeer(
    _ listener: CInt, specification: VMShimProtocol.Specification, replyFailure: Bool = false,
    replyMessage: String = "closed test failure", replyPayload: Data? = nil,
    beforeReply: (@Sendable () throws -> Void)? = nil,
    beforeWrite: (@Sendable () throws -> Void)? = nil,
    budget: PeerFixtureBudget = .init(), accepting: @Sendable () -> Void = {}
) throws -> WorkloadPeerCapture {
    let acceptDeadline = budget.deadline(after: PeerFixtureBudget.startupNanoseconds)
    accepting()
    try waitForWorkloadPeerIO(listener, events: Int16(POLLIN), deadline: acceptDeadline, phase: "workload accept")
    // Production accept reapplies SO_NOSIGPIPE, which fails with EINVAL after
    // a pre-token rejection closes before accept. Assert inherited protection.
    let peer = Darwin.accept(listener, nil, nil)
    guard peer >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    defer { Darwin.close(peer) }
    let deadline = budget.deadline(after: PeerFixtureBudget.ioNanoseconds)
    var protected: CInt = 0
    var optionSize = socklen_t(MemoryLayout<CInt>.size)
    guard getsockopt(peer, SOL_SOCKET, SO_NOSIGPIPE, &protected, &optionSize) == 0,
          protected == 1 else { throw POSIXError(.EIO) }
    var pid: pid_t = 0
    var size = socklen_t(MemoryLayout<pid_t>.size)
    let identityResult = getsockopt(peer, SOL_LOCAL, LOCAL_PEERPID, &pid, &size)
    let identityError = errno
    let peerPID: pid_t?
    if identityResult == 0, size == MemoryLayout<pid_t>.size {
        peerPID = pid
    } else if identityResult < 0, identityError == ENOTCONN {
        peerPID = nil
    } else { throw POSIXError(.EIO) }
    var bytes = Data()
    var request: VMShimProtocol.Envelope?
    var frameSize: Int?
    var buffer = [UInt8](repeating: 0, count: 4_096)
    while true {
        try waitForWorkloadPeerIO(peer, events: Int16(POLLIN), deadline: deadline)
        let count = buffer.withUnsafeMutableBytes { Darwin.recv(peer, $0.baseAddress, $0.count, MSG_DONTWAIT) }
        if count == 0 { return .init(peerPID: peerPID, bytes: bytes, request: request) }
        if count < 0 {
            if errno == EINTR || errno == EAGAIN { continue }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        bytes.append(contentsOf: buffer.prefix(count))
        guard bytes.count <= 64 * 1_024 else { throw POSIXError(.EMSGSIZE) }
        if frameSize == nil, bytes.count >= 4 {
            let length = bytes.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            guard length > 0, length <= 64 * 1_024 - 4 else { throw POSIXError(.EMSGSIZE) }
            frameSize = 4 + Int(length)
        }
        if request == nil, let frameSize, bytes.count >= frameSize {
            let decoded = try VMShimProtocol.decode(Data(bytes.prefix(frameSize)))
            request = decoded
            try beforeReply?()
            let reply = VMShimProtocol.Envelope(id: decoded.id, token: decoded.token,
                operation: decoded.operation,
                payload: replyFailure ? nil : try (replyPayload ?? JSONEncoder().encode(workloadPeerStatus(specification))),
                error: replyFailure ? .init(code: "shim_error", message: replyMessage) : nil)
            let frame = try VMShimProtocol.encode(reply)
            if decoded.operation != .startPortStream || replyFailure {
                let scope = VMShimManagedTransport(deadlineNanoseconds:
                    min(budget.overall, VMShimServer.replyAcknowledgementDeadline(specification,
                        acceptedDeadline: 0, requestDeadline: decoded.deadlineNanoseconds) ?? budget.overall))
                let duplicate = fcntl(peer, F_DUPFD_CLOEXEC, 0)
                guard duplicate >= 0 else { throw POSIXError(.EIO) }
                do { try scope.adopt(duplicate) } catch { Darwin.close(duplicate); throw error }
                defer { scope.close() }
                do {
                    try beforeWrite?()
                    try VMShimServer.writeManagedReply(frame, using: scope)
                    return .init(peerPID: peerPID, bytes: bytes, request: request, acknowledged: true)
                } catch {
                    // A failed post-reply proof closes without acknowledging.
                    if beforeReply != nil || beforeWrite != nil {
                        return .init(peerPID: peerPID, bytes: bytes, request: request)
                    }
                    throw PeerFixtureFailure.phase("workload reply/ack", error)
                }
            }
            var offset = 0
            while offset < frame.count {
                try waitForWorkloadPeerIO(peer, events: Int16(POLLOUT), deadline: deadline, phase: "workload upgrade write")
                let sent = frame.withUnsafeBytes {
                    Darwin.send(peer, $0.baseAddress!.advanced(by: offset), $0.count - offset, MSG_DONTWAIT)
                }
                if sent > 0 { offset += sent; continue }
                if sent < 0, errno == EINTR || errno == EAGAIN { continue }
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            // Successful upgrade models an owned relay, not a one-shot reply.
            // The client must close it without sending an acknowledgement byte.
        }
    }
}

private func waitForWorkloadPeerIO(_ descriptor: CInt, events: Int16, deadline: UInt64, phase: String = "workload request/EOF") throws {
    while true {
        let now = DispatchTime.now().uptimeNanoseconds
        guard now < deadline else { throw PeerFixtureFailure.phase(phase, POSIXError(.ETIMEDOUT)) }
        var event = pollfd(fd: descriptor, events: events, revents: 0)
        let result = Darwin.poll(&event, 1, CInt(max(1, (deadline - now) / 1_000_000)))
        if result > 0 {
            guard event.revents & Int16(POLLNVAL) == 0 else { throw POSIXError(.EBADF) }
            return
        }
        if result < 0, errno != EINTR { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    }
}
#endif

#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

@Suite struct VMShimProcessObservationTests {
    private typealias Client = VMShimClient
    private let owner = Client.ProcessIdentity(processIdentifier: 4_321, startTime: 100_000_001)

    @Test func nativeQueryDistinguishesAbsenceFromUnreadableIdentity() {
        let size = CInt(MemoryLayout<proc_bsdinfo>.size)
        for count in [CInt(0), -1] {
            #expect(Client.observeProcess(owner.processIdentifier) { _, _ in
                (count, ESRCH)
            } == .absent)
            for error in [EPERM, EACCES, EINVAL, EIO, CInt(0)] {
                #expect(Client.observeProcess(owner.processIdentifier) { _, _ in
                    (count, error)
                } == .unknown)
            }
        }
        // Even stale ESRCH must not turn a short successful read into absence.
        for count in [CInt(1), size - 1, size + 1] {
            #expect(Client.observeProcess(owner.processIdentifier) { _, _ in
                (count, ESRCH)
            } == .unknown)
        }
        #expect(Client.observeProcess(owner.processIdentifier) { pid, information in
            information.pbi_pid = UInt32(pid)
            information.pbi_start_tvsec = 100
            information.pbi_start_tvusec = 1
            return (size, 0)
        } == .process(owner))
        #expect(Client.observeProcess(owner.processIdentifier) { pid, information in
            information.pbi_pid = UInt32(pid + 1)
            information.pbi_start_tvsec = 100
            return (size, 0)
        } == .unknown)
        #expect(Client.observeProcess(owner.processIdentifier) { pid, information in
            information.pbi_pid = UInt32(pid)
            information.pbi_start_tvsec = 100
            information.pbi_start_tvusec = 1_000_000
            return (size, 0)
        } == .unknown)
    }

    @Test func nativeSelfObservationIsStable() throws {
        let first = Client.observeProcess(getpid())
        guard case let .process(identity) = first else {
            Issue.record("native self process identity unavailable")
            return
        }
        #expect(identity.processIdentifier == getpid())
        #expect(identity.startTime > 0)
        #expect(Client.observeProcess(getpid()) == first)
        #expect(try !Client.hasExited(identity, observation: first))
        #expect(try !Client.waitForExit(identity, timeoutMilliseconds: 0))
    }

    @Test func fallbackBirthIsDeathOnlyAndValidatesNativeShape() throws {
        let size = MemoryLayout<kinfo_proc>.size
        for scenario in ["reused", "same", "error", "empty", "short", "long", "wrong-pid", "zero", "negative", "negative-usec", "large-usec", "overflow"] {
            let observed = Client.observeProcessExit(owner.processIdentifier, primary: { _ in .unknown }) { pid, info, bytes in
                info.kp_proc.p_pid = scenario == "wrong-pid" ? pid + 1 : pid
                info.kp_proc.p_un.__p_starttime.tv_sec = scenario == "same" ? 100 : 101
                info.kp_proc.p_un.__p_starttime.tv_usec = 1
                switch scenario {
                case "error": return -1
                case "empty": bytes = 0
                case "short": bytes = size - 1
                case "long": bytes = size + 1
                case "zero": info.kp_proc.p_un.__p_starttime.tv_sec = 0
                case "negative": info.kp_proc.p_un.__p_starttime.tv_sec = -1
                case "negative-usec": info.kp_proc.p_un.__p_starttime.tv_usec = -1
                case "large-usec": info.kp_proc.p_un.__p_starttime.tv_usec = 1_000_000
                case "overflow": info.kp_proc.p_un.__p_starttime.tv_sec = Int.max
                default: break
                }
                return 0
            }
            if scenario == "reused" {
                #expect(observed == .birthOnly(.init(processIdentifier: owner.processIdentifier, startTime: 101_000_001)))
                #expect(try Client.hasExited(owner, observation: observed))
            } else {
                #expect(observed == (scenario == "same" ? .birthOnly(owner) : .unknown))
                #expect(throws: EngineError.self) { _ = try Client.hasExited(owner, observation: observed) }
            }
        }
        for primary: Client.ProcessObservation in [.absent, .process(owner)] {
            #expect(Client.observeProcessExit(owner.processIdentifier, primary: { _ in primary }, query: { _, _, _ in
                Issue.record("known primary must not use fallback"); return -1
            }) == primary)
        }
        #expect(Client.observeProcessExit(1, primary: { _ in Issue.record("invalid PID"); return .absent }) == .unknown)
        #expect(throws: EngineError.self) {
            _ = try Client.hasExited(owner, observation: .birthOnly(.init(processIdentifier: owner.processIdentifier + 1, startTime: 1)))
        }
    }

    @Test func nativeFallbackMatchesBirthButCannotAuthorizeSignals() async throws {
        let own = try #require({ () -> Client.ProcessIdentity? in
            guard case .process(let identity) = Client.observeProcess(getpid()) else { return nil }
            return identity
        }())
        let observed = Client.observeProcessExit(getpid(), primary: { _ in .unknown })
        #expect(observed == .birthOnly(own))
        let fixture = try ObservationFixture(owner: own)
        defer { fixture.remove() }
        let evidence = try fixture.evidence()
        await #expect(throws: EngineError.self) {
            try await fixture.client.terminate(observe: { _ in observed },
                requestShutdown: { Issue.record("birth-only must not authorize shutdown") },
                forceTerminate: { _ in Issue.record("birth-only must not authorize a signal") })
        }
        #expect(try fixture.evidence() == evidence)
        let stale = try ObservationFixture(owner: .init(processIdentifier: own.processIdentifier, startTime: own.startTime - 1))
        defer { stale.remove() }
        try await stale.client.terminate(observe: { _ in observed },
            requestShutdown: { Issue.record("reused PID must not receive shutdown") },
            forceTerminate: { _ in Issue.record("reused PID must not receive signal") })
        stale.expectRuntimeArtifactsRemoved()
        #expect(Client.observeProcess(getpid()) == .process(own))
    }

    @Test func exitWaitRequiresPositiveAbsenceOrSamePIDReuse() throws {
        let reused = Client.ProcessIdentity(processIdentifier: owner.processIdentifier, startTime: owner.startTime + 1)
        #expect(try !Client.waitForExit(owner, timeoutMilliseconds: 0) { _ in .process(owner) })
        #expect(try Client.waitForExit(owner, timeoutMilliseconds: 0) { _ in .absent })
        #expect(try Client.waitForExit(owner, timeoutMilliseconds: 0) { _ in .process(reused) })
        #expect(try Client.waitForExit(owner, timeoutMilliseconds: 0) { _ in .birthOnly(reused) })
        #expect(throws: EngineError.self) {
            _ = try Client.waitForExit(owner, timeoutMilliseconds: 0) { _ in .birthOnly(owner) }
        }
        #expect(throws: EngineError.self) {
            _ = try Client.waitForExit(owner, timeoutMilliseconds: 0) { _ in .unknown }
        }
        #expect(throws: EngineError.self) {
            _ = try Client.hasExited(owner, observation: .process(.init(
                processIdentifier: owner.processIdentifier + 1, startTime: owner.startTime + 1
            )))
        }
    }

    @Test(arguments: ["initial", "graceful-wait", "pre-signal", "post-signal"])
    func unknownNeverCertifiesTerminationOrRemovesArtifacts(boundary: String) async throws {
        let fixture = try ObservationFixture(owner: owner)
        defer { fixture.remove() }
        let evidence = try fixture.evidence()
        var observations: [Client.ProcessObservation]
        switch boundary {
        case "initial": observations = [.unknown]
        case "post-signal": observations = [.process(owner), .process(owner), .unknown]
        default: observations = [.process(owner), .unknown]
        }
        var shutdowns = 0
        var signals = 0
        await #expect(throws: EngineError.self) {
            try await fixture.client.terminate(
                gracePeriodMilliseconds: 0, forceWaitMilliseconds: 0,
                observe: { pid in
                    #expect(pid == owner.processIdentifier)
                    return observations.isEmpty ? .unknown : observations.removeFirst()
                },
                requestShutdown: {
                    shutdowns += 1
                    if boundary != "graceful-wait" { throw ObservationFailure.shutdown }
                },
                forceTerminate: { _ in signals += 1 }
            )
        }
        #expect(observations.isEmpty)
        #expect(shutdowns == (boundary == "initial" ? 0 : 1))
        #expect(signals == (boundary == "post-signal" ? 1 : 0))
        #expect(try fixture.evidence() == evidence)
        #expect(fixture.client.hasPersistentLaunchRecord)

        // A later positive observation may finish the same production cleanup;
        // the failed attempt did not discard the only generation-specific handle.
        try await fixture.client.terminate(
            observe: { _ in .absent },
            requestShutdown: { Issue.record("dead shim must not receive shutdown") },
            forceTerminate: { _ in Issue.record("dead shim must not receive a signal") }
        )
        fixture.expectRuntimeArtifactsRemoved()
    }

    @Test(arguments: ["absent", "reused", "pre-signal-reused", "graceful", "forced", "legacy"])
    func positiveDeathRunsProductionArtifactCleanup(boundary: String) async throws {
        let fixture = try ObservationFixture(owner: owner, legacy: boundary == "legacy")
        defer { fixture.remove() }
        var observations: [Client.ProcessObservation]
        switch boundary {
        case "reused": observations = [.process(.init(
            processIdentifier: owner.processIdentifier, startTime: owner.startTime + 1
        ))]
        case "pre-signal-reused": observations = [.process(owner), .process(.init(
            processIdentifier: owner.processIdentifier, startTime: owner.startTime + 1
        ))]
        case "graceful": observations = [.process(owner), .absent]
        case "forced": observations = [.process(owner), .process(owner), .absent]
        default: observations = [.absent]
        }
        var signals = 0
        try await fixture.client.terminate(
            gracePeriodMilliseconds: 0, forceWaitMilliseconds: 0,
            observe: { _ in observations.isEmpty ? .unknown : observations.removeFirst() },
            requestShutdown: {
                if boundary == "forced" || boundary == "pre-signal-reused" {
                    throw ObservationFailure.shutdown
                }
                #expect(boundary == "graceful")
            },
            forceTerminate: { pid in
                #expect(pid == owner.processIdentifier)
                signals += 1
            }
        )
        #expect(observations.isEmpty)
        #expect(signals == (boundary == "forced" ? 1 : 0))
        fixture.expectRuntimeArtifactsRemoved()
        #expect(fixture.client.hasPersistentLaunchRecord)
        if boundary == "legacy" {
            #expect(fixture.client.specification.shimLaunchUUID == nil)
            #expect(throws: EngineError.self) {
                try fixture.client.validateStatus(.init(
                    containerID: fixture.client.specification.containerID,
                    generation: fixture.client.specification.generation,
                    state: .stopped, processIdentifier: owner.processIdentifier
                ))
            }
        }
    }

    @Test func missingIdentityCannotBecomeContainmentThroughShutdownReply() async throws {
        let fixture = try ObservationFixture(owner: owner)
        defer { fixture.remove() }
        // The published status is deliberately unreadable: a missing identity
        // must fail closed, not accept a successful shutdown reply as death.
        let client = Client(specification: fixture.client.specification)
        let evidence = try fixture.evidence()
        await #expect(throws: EngineError.self) {
            try await client.terminate(
                observe: { _ in Issue.record("no identity to observe"); return .absent },
                requestShutdown: { Issue.record("unidentified shutdown is not containment") },
                forceTerminate: { _ in Issue.record("no identity to signal") }
            )
        }
        #expect(try fixture.evidence() == evidence)
    }
}

private enum ObservationFailure: Error { case shutdown }

/// Metadata and local listener fixtures only: no child process, VM, helper,
/// disk attachment, or real signal is involved in these production-path tests.
private struct ObservationFixture {
    let root: URL
    let client: VMShimClient
    let files: VMShimClient.PersistentSpawnFiles
    let runtimePaths: [String]
    let listeners: [CInt]

    init(owner: VMShimClient.ProcessIdentity, legacy: Bool = false) throws {
        root = URL(filePath: "/tmp/ce-obs-\(UUID().uuidString)")
        let containerURL = root.appending(path: "container")
        let runtimeURL = root.appending(path: "runtime")
        try FileManager.default.createDirectory(at: containerURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: runtimeURL, withIntermediateDirectories: true)
        let container = ContainerRecord(id: "observation", name: "observation", image: "alpine")
        let executable = URL(filePath: "/usr/bin/true")
        var specification = VMShimProtocol.Specification(
            containerID: container.id, generation: 1, token: "observation-token",
            kernelPath: "/unused-kernel", initialRamdiskPath: "/unused-initramfs",
            rootDiskPath: containerURL.appending(path: "unused-root.ext4").path,
            cpus: 1, memoryBytes: 268_435_456, macAddress: "02:ce:00:00:00:01",
            socketPath: runtimeURL.appending(path: "shim.sock").path,
            logPath: containerURL.appending(path: "shim.log").path,
            shimLaunchUUID: UUID().uuidString.lowercased()
        )
        files = try VMShimClient.preparePersistentSpawn(
            specification: specification, container: container,
            containerDirectory: PersistentStateDirectory.open(containerURL), executable: executable
        )
        var intent = try JSONDecoder().decode(VMShimClient.PersistentLaunchIntent.self,
            from: Data(contentsOf: files.intentURL))
        if legacy {
            specification.shimLaunchUUID = nil
            intent = VMShimClient.PersistentLaunchIntent(
                nonce: intent.nonce, createdAt: intent.createdAt,
                specificationPath: intent.specificationPath, executablePath: intent.executablePath,
                containerDirectoryIdentity: intent.containerDirectoryIdentity,
                generationsDirectoryIdentity: intent.generationsDirectoryIdentity,
                generationDirectoryIdentity: intent.generationDirectoryIdentity,
                specification: specification, container: container
            )
            try JSONEncoder().encode(specification).write(to: files.specificationURL)
            try JSONEncoder().encode(intent).write(to: files.intentURL)
        }
        let record = VMShimClient.PersistentLaunchRecord(
            nonce: intent.nonce, createdAt: intent.createdAt,
            specificationPath: intent.specificationPath, executablePath: intent.executablePath,
            containerDirectoryIdentity: intent.containerDirectoryIdentity,
            generationsDirectoryIdentity: intent.generationsDirectoryIdentity,
            generationDirectoryIdentity: intent.generationDirectoryIdentity,
            specification: specification, processIdentifier: owner.processIdentifier,
            processStartTime: owner.startTime, container: container
        )
        try JSONEncoder().encode(record).write(to: files.recordURL)
        let socketPaths = VMShimServer.ownedSocketPaths(specification)
        let statusPath = specification.socketPath + ".status"
        let publication = try VMShimClient.preparePersistentRuntimeArtifacts(
            intentURL: files.intentURL, socketPaths: socketPaths, statusPath: statusPath
        )
        listeners = try socketPaths.map {
            try UnixSocket.listen(path: publication.stagedPath(for: $0))
        }
        try Data("unreadable status must not override launch identity".utf8).write(
            to: URL(filePath: publication.stagedPath(for: statusPath))
        )
        _ = try VMShimClient.publishPersistentRuntimeArtifacts(publication)
        runtimePaths = socketPaths + [statusPath]
        let launches = try VMShimClient.persistedLaunches(
            in: files.containerDirectory, expectedContainerID: container.id,
            expectedExecutable: executable, processIdentifiersProvider: { .complete([]) }
        )
        client = try #require(launches.first?.client)
    }

    func evidence() throws -> [String: Data] {
        var result: [String: Data] = [:]
        for url in [files.intentURL, files.specificationURL, files.recordURL,
                    files.directory.appending(path: "runtime-artifacts.json"),
                    URL(filePath: client.specification.socketPath + ".status")] {
            result[url.path] = try Data(contentsOf: url)
        }
        for path in runtimePaths {
            #expect(FileManager.default.fileExists(atPath: path))
        }
        return result
    }

    func expectRuntimeArtifactsRemoved() {
        for path in runtimePaths {
            #expect(!FileManager.default.fileExists(atPath: path))
        }
    }

    func remove() {
        for listener in listeners { Darwin.close(listener) }
        try? FileManager.default.removeItem(at: root)
    }
}
#endif

import Foundation
import Testing
@testable import CEngineCore
#if os(macOS)
import Darwin
@testable import CEngineRuntime

// Native peer tests compile and launch processes; serialize to avoid startup
// timeouts from many competing compiler/linker jobs in the same test runner.
@Suite(.serialized) struct VMShimTeardownTests {
    @Test func uninstallTerminatesContainerAndInfrastructureShimsBeforeZap() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerDirectory = root.appending(path: "containers/owned-container")
        let infrastructureDirectory = root.appending(path: "infrastructure")
        try FileManager.default.createDirectory(
            at: containerDirectory, withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: infrastructureDirectory, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let executable = try buildIdleShimExecutable(in: root)
        let rootDisk = containerDirectory.appending(path: "root.ext4")
        let rootDiskContents = Data("preserved container data".utf8)
        try rootDiskContents.write(to: rootDisk)
        let container = ContainerRecord(
            id: "owned-container", name: "owned-container", image: "alpine"
        )
        let containerSpecification = VMShimProtocol.Specification(
            containerID: container.id,
            generation: 3,
            token: "container-token",
            kernelPath: "/kernel",
            initialRamdiskPath: "/initramfs",
            rootDiskPath: rootDisk.path,
            cpus: 1,
            memoryBytes: 268_435_456,
            macAddress: "02:ce:00:00:00:03",
            socketPath: try RawVirtualizationBackend.makeRuntimeSocketPath(),
            logPath: containerDirectory.appending(path: "shim.log").path
        )
        let spawn = try VMShimClient.preparePersistentSpawn(
            specification: containerSpecification,
            container: container,
            generationsDirectory: RawVirtualizationBackend.generationsDirectory(
                for: containerDirectory
            ),
            executable: executable
        )
        let containerProcess = Process()
        containerProcess.executableURL = executable
        containerProcess.arguments = [
            "vm-shim", "--spec", spawn.specificationURL.path,
            "--launch-intent", spawn.intentURL.path,
        ]
        try containerProcess.run()
        Thread.detachNewThread { containerProcess.waitUntilExit() }
        defer { if containerProcess.isRunning { containerProcess.terminate() } }

        let infrastructureSpecification = VMShimProtocol.Specification(
            kind: .storage,
            containerID: "cengine-storage",
            generation: 1,
            token: "infrastructure-token",
            kernelPath: "/kernel",
            initialRamdiskPath: "/storage-initramfs",
            rootDiskPath: infrastructureDirectory.appending(path: "volumes.ext4").path,
            cpus: 2,
            memoryBytes: 1_073_741_824,
            macAddress: "02:ce:00:00:00:01",
            socketPath: try RawVirtualizationBackend.makeRuntimeSocketPath(),
            logPath: infrastructureDirectory.appending(path: "shim.log").path
        )
        try JSONEncoder().encode(infrastructureSpecification).write(
            to: infrastructureDirectory.appending(path: "shim.json")
        )
        defer {
            try? FileManager.default.removeItem(
                atPath: infrastructureSpecification.socketPath
            )
            try? FileManager.default.removeItem(
                atPath: infrastructureSpecification.socketPath + ".status"
            )
        }
        let listener = try UnixSocket.listen(path: infrastructureSpecification.socketPath)
        defer { Darwin.close(listener) }
        Thread.detachNewThread {
            guard let peer = try? UnixSocket.accept(listener) else { return }
            defer { Darwin.close(peer) }
            let file = FileHandle(fileDescriptor: peer, closeOnDealloc: false)
            let prefix = file.readData(ofLength: 4)
            guard prefix.count == 4 else { return }
            let size = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            let body = file.readData(ofLength: Int(size))
            guard let request = try? VMShimProtocol.decode(prefix + body),
                  request.token == infrastructureSpecification.token,
                  request.operation == .shutdown else { return }
            let status = VMShimProtocol.Status(
                containerID: infrastructureSpecification.containerID,
                generation: infrastructureSpecification.generation,
                state: .stopped,
                processIdentifier: getpid()
            )
            let response = VMShimProtocol.Envelope(
                id: request.id,
                token: infrastructureSpecification.token,
                operation: request.operation,
                payload: try! JSONEncoder().encode(status)
            )
            try? file.write(contentsOf: VMShimProtocol.encode(response))
        }

        let stopped = try await VMShimTeardown.terminateAll(
            in: root,
            expectedExecutable: executable,
            gracePeriodMilliseconds: 1_000,
            forceWaitMilliseconds: 1_000
        )

        #expect(stopped == 2)
        #expect(VMShimClient.processStartTime(for: containerProcess.processIdentifier) == nil)
        #expect(try Data(contentsOf: rootDisk) == rootDiskContents)
        #expect(FileManager.default.fileExists(atPath: spawn.intentURL.path))
    }

    @Test(arguments: [false, true])
    func infrastructureStatusCannotCauseForeignProcessTermination(
        requireCompleteShutdown: Bool
    ) async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let infrastructureDirectory = root.appending(path: "infrastructure")
        try FileManager.default.createDirectory(
            at: infrastructureDirectory, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let foreignProcess = Process()
        foreignProcess.executableURL = URL(filePath: "/bin/sleep")
        foreignProcess.arguments = ["30"]
        try foreignProcess.run()
        Thread.detachNewThread { foreignProcess.waitUntilExit() }
        defer { if foreignProcess.isRunning { foreignProcess.terminate() } }
        let startTime = try #require(
            VMShimClient.processStartTime(for: foreignProcess.processIdentifier)
        )
        let specification = VMShimProtocol.Specification(
            kind: .storage,
            containerID: "cengine-storage",
            generation: 1,
            token: "infrastructure-token",
            kernelPath: "/kernel",
            initialRamdiskPath: "/storage-initramfs",
            rootDiskPath: infrastructureDirectory.appending(path: "volumes.ext4").path,
            cpus: 2,
            memoryBytes: 1_073_741_824,
            macAddress: "02:ce:00:00:00:01",
            socketPath: try RawVirtualizationBackend.makeRuntimeSocketPath(),
            logPath: infrastructureDirectory.appending(path: "shim.log").path
        )
        try JSONEncoder().encode(specification).write(
            to: infrastructureDirectory.appending(path: "shim.json")
        )
        defer {
            try? FileManager.default.removeItem(atPath: specification.socketPath)
            try? FileManager.default.removeItem(atPath: specification.socketPath + ".status")
        }
        try JSONEncoder().encode(VMShimProtocol.Status(
            containerID: specification.containerID,
            generation: specification.generation,
            state: .running,
            processIdentifier: foreignProcess.processIdentifier,
            processStartTime: startTime
        )).write(to: URL(filePath: specification.socketPath + ".status"))

        do {
            _ = try await VMShimTeardown.terminateAll(
                in: root,
                gracePeriodMilliseconds: 10,
                forceWaitMilliseconds: 10,
                requireCompleteShutdown: requireCompleteShutdown
            )
            Issue.record("teardown unexpectedly accepted an unreachable infrastructure shim")
        } catch {
            // The warning is expected; the untrusted PID must remain untouched.
        }
        #expect(VMShimClient.processStartTime(for: foreignProcess.processIdentifier) == startTime)
    }

    @Test(arguments: [false, true])
    func quarantinedGenerationDoesNotBlockOwnedShimTermination(
        requireCompleteShutdown: Bool
    ) async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerDirectory = root.appending(path: "containers/owned-container")
        try FileManager.default.createDirectory(
            at: containerDirectory, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let executable = try buildIdleShimExecutable(in: root)
        let container = ContainerRecord(
            id: "owned-container", name: "owned-container", image: "alpine"
        )
        func specification(generation: UInt64) throws -> VMShimProtocol.Specification {
            VMShimProtocol.Specification(
                containerID: container.id,
                generation: generation,
                token: "container-token-\(generation)",
                kernelPath: "/kernel",
                initialRamdiskPath: "/initramfs",
                rootDiskPath: containerDirectory.appending(path: "root.ext4").path,
                cpus: 1,
                memoryBytes: 268_435_456,
                macAddress: "02:ce:00:00:00:03",
                socketPath: try RawVirtualizationBackend.makeRuntimeSocketPath(),
                logPath: containerDirectory.appending(path: "shim.log").path
            )
        }
        let generations = RawVirtualizationBackend.generationsDirectory(
            for: containerDirectory
        )
        let live = try VMShimClient.preparePersistentSpawn(
            specification: specification(generation: 3),
            container: container,
            generationsDirectory: generations,
            executable: executable
        )
        let process = Process()
        process.executableURL = executable
        process.arguments = [
            "vm-shim", "--spec", live.specificationURL.path,
            "--launch-intent", live.intentURL.path,
        ]
        try process.run()
        Thread.detachNewThread { process.waitUntilExit() }
        defer { if process.isRunning { process.terminate() } }

        let malformed = try VMShimClient.preparePersistentSpawn(
            specification: specification(generation: 4),
            container: container,
            generationsDirectory: generations,
            executable: executable
        )
        try Data("not-json".utf8).write(to: malformed.recordURL)

        await #expect(throws: EngineError.self) {
            _ = try await VMShimTeardown.terminateAll(
                in: root,
                expectedExecutable: executable,
                gracePeriodMilliseconds: 0,
                forceWaitMilliseconds: 1_000,
                requireCompleteShutdown: requireCompleteShutdown
            )
        }
        #expect(VMShimClient.processStartTime(for: process.processIdentifier) == nil)
        #expect(FileManager.default.fileExists(atPath: malformed.directory.path))
    }

    @Test(arguments: [false, true])
    func infrastructureAcknowledgementRequiresExitOnlyForStrictTeardown(
        requireCompleteShutdown: Bool
    ) async throws {
        let fixture = try AdministrativeShutdownFixture(listen: false)
        defer { fixture.close() }
        let peer = try NativeAdministrativeShutdownPeer(fixture: fixture, stayAlive: true)
        defer { peer.close() }
        do {
            let stopped = try await VMShimTeardown.terminateAll(
                in: fixture.root,
                expectedExecutable: peer.executable,
                gracePeriodMilliseconds: 1_000,
                requireCompleteShutdown: requireCompleteShutdown
            )
            #expect(!requireCompleteShutdown)
            #expect(stopped == 1)
        } catch {
            #expect(requireCompleteShutdown)
            #expect(EngineError.message(for: error).contains("did not exit after administrative shutdown"))
        }
        #expect(FileManager.default.fileExists(atPath: peer.acknowledgementPath))
        #expect(VMShimClient.processStartTime(for: peer.process.processIdentifier) == peer.startTime)
    }

    @Test func strictTeardownAcceptsExactLegacyInfrastructurePeerExit() async throws {
        let fixture = try AdministrativeShutdownFixture(listen: false)
        defer { fixture.close() }
        let peer = try NativeAdministrativeShutdownPeer(fixture: fixture, stayAlive: false)
        defer { peer.close() }
        // The native peer omits executableUUID, as a legacy shim would.
        let stopped = try await VMShimTeardown.terminateAll(
            in: fixture.root,
            expectedExecutable: peer.executable,
            gracePeriodMilliseconds: 2_000,
            requireCompleteShutdown: true
        )
        #expect(stopped == 1)
        #expect(FileManager.default.fileExists(atPath: peer.acknowledgementPath))
        #expect(VMShimClient.processStartTime(for: peer.process.processIdentifier) == nil)
    }

    @Test func strictTeardownReservesExitGraceAfterSlowShutdownReply() async throws {
        let fixture = try AdministrativeShutdownFixture(listen: false)
        defer { fixture.close() }
        let peer = try NativeAdministrativeShutdownPeer(
            fixture: fixture, stayAlive: false,
            replyDelayMilliseconds: 1_000, exitDelayMilliseconds: 1_000
        )
        defer { peer.close() }
        let stopped = try await VMShimTeardown.terminateAll(
            in: fixture.root, expectedExecutable: peer.executable,
            gracePeriodMilliseconds: 1_500, forceWaitMilliseconds: 2_000,
            requireCompleteShutdown: true
        )
        #expect(stopped == 1)
        #expect(VMShimClient.processStartTime(for: peer.process.processIdentifier) == nil)
    }

    @Test(arguments: [false, true])
    func strictTeardownAcceptsPersistedExitWithUnreachableInfrastructure(staleSocket: Bool) async throws {
        let fixture = try AdministrativeShutdownFixture(listen: false)
        defer { fixture.close() }
        let peer = try NativeAdministrativeShutdownPeer(fixture: fixture, stayAlive: true)
        defer { peer.close() }
        var status = fixture.status
        status.state = .running // A stale running status must not fence an upgrade.
        status.processIdentifier = peer.process.processIdentifier
        status.processStartTime = peer.startTime
        let statusURL = URL(filePath: fixture.specification.socketPath + ".status")
        let statusData = try JSONEncoder().encode(status)
        try statusData.write(to: statusURL)
        let specificationURL = VMShimClient.specificationURL(for: fixture.specification)
        let specificationData = try Data(contentsOf: specificationURL)
        peer.close()
        #expect(await shutdownFixtureCompletes(peer.exited))
        #expect(VMShimClient.processStartTime(for: peer.process.processIdentifier) == nil)
        if !staleSocket {
            try FileManager.default.removeItem(atPath: fixture.specification.socketPath)
        }

        // Best-effort uninstall retains its existing warning behavior.
        await #expect(throws: EngineError.self) {
            _ = try await VMShimTeardown.terminateAll(
                in: fixture.root, expectedExecutable: peer.executable,
                gracePeriodMilliseconds: 100
            )
        }
        let stopped = try await VMShimTeardown.terminateAll(
            in: fixture.root, expectedExecutable: peer.executable,
            gracePeriodMilliseconds: 100, requireCompleteShutdown: true
        )
        #expect(stopped == 1)
        #expect(try Data(contentsOf: statusURL) == statusData)
        #expect(try Data(contentsOf: specificationURL) == specificationData)
        #expect(FileManager.default.fileExists(atPath: fixture.specification.socketPath) == staleSocket)
    }

    @Test(arguments: ["missing", "malformed", "unreadable", "missing-start-time", "container", "generation"])
    func strictTeardownRejectsUnverifiedPersistedInfrastructureExit(evidence: String) async throws {
        let fixture = try AdministrativeShutdownFixture(listen: false)
        defer { fixture.close() }
        let listener = try UnixSocket.listen(path: fixture.specification.socketPath)
        Darwin.close(listener) // Leave an unreachable socket, not a responding peer.
        let statusURL = URL(filePath: fixture.specification.socketPath + ".status")
        var status = fixture.status
        switch evidence {
        case "missing": break
        case "malformed": try Data("not-json".utf8).write(to: statusURL)
        case "unreadable":
            try FileManager.default.createDirectory(at: statusURL, withIntermediateDirectories: false)
        default:
            if evidence == "missing-start-time" { status.processStartTime = nil }
            if evidence == "container" { status.containerID = "foreign-container" }
            if evidence == "generation" { status.generation += 1 }
            try JSONEncoder().encode(status).write(to: statusURL)
        }
        await #expect(throws: EngineError.self) {
            _ = try await VMShimTeardown.terminateAll(
                in: fixture.root, gracePeriodMilliseconds: 100, requireCompleteShutdown: true
            )
        }
        #expect(VMShimClient.processStartTime(for: getpid()) == fixture.status.processStartTime)
    }

    @Test(arguments: ["pid", "token", "token-without-artifacts"])
    func strictTeardownResponseMismatchRequiresIndependentExit(mismatch: String) async throws {
        let fixture = try AdministrativeShutdownFixture(listen: false)
        defer { fixture.close() }
        let peer = try NativeAdministrativeShutdownPeer(
            fixture: fixture, stayAlive: true, responseMismatch: mismatch
        )
        defer { peer.close() }
        var status = fixture.status
        status.processIdentifier = peer.process.processIdentifier
        status.processStartTime = peer.startTime
        try JSONEncoder().encode(status).write(
            to: URL(filePath: fixture.specification.socketPath + ".status")
        )
        do {
            _ = try await VMShimTeardown.terminateAll(
                in: fixture.root, expectedExecutable: peer.executable,
                gracePeriodMilliseconds: 1_000, requireCompleteShutdown: true
            )
            Issue.record("strict teardown accepted a live peer after a response mismatch")
        } catch {
            let message = EngineError.message(for: error)
            #expect(message.contains("does not match its socket peer")
                || message.contains("authentication mismatch"))
        }
        #expect(FileManager.default.fileExists(atPath: peer.acknowledgementPath))
        #expect(VMShimClient.processStartTime(for: peer.process.processIdentifier) == peer.startTime)
        if mismatch == "token-without-artifacts" {
            #expect(!FileManager.default.fileExists(atPath: fixture.specification.socketPath))
            #expect(!FileManager.default.fileExists(atPath: fixture.specification.socketPath + ".status"))
        }

        peer.close()
        #expect(await shutdownFixtureCompletes(peer.exited))
        // Restore independently captured ownership evidence if the peer removed it.
        try JSONEncoder().encode(status).write(
            to: URL(filePath: fixture.specification.socketPath + ".status")
        )
        let stopped = try await VMShimTeardown.terminateAll(
            in: fixture.root, expectedExecutable: peer.executable,
            gracePeriodMilliseconds: 100, requireCompleteShutdown: true
        )
        #expect(stopped == 1)
    }

    @Test func strictTeardownRejectsNativePeerWithForeignSpecArgumentBeforeSending() async throws {
        let fixture = try AdministrativeShutdownFixture(listen: false)
        defer { fixture.close() }
        let peer = try NativeAdministrativeShutdownPeer(
            fixture: fixture, stayAlive: false, foreignSpecificationArgument: true
        )
        defer { peer.close() }
        do {
            _ = try await VMShimTeardown.terminateAll(
                in: fixture.root, expectedExecutable: peer.executable,
                gracePeriodMilliseconds: 1_000, requireCompleteShutdown: true
            )
            Issue.record("strict teardown accepted a foreign spec argument")
        } catch {
            #expect(EngineError.message(for: error).contains("does not match the infrastructure launch"))
        }
        #expect(await shutdownFixtureCompletes(peer.exited))
        #expect(FileManager.default.fileExists(atPath: peer.noRequestPath))
        #expect(!FileManager.default.fileExists(atPath: peer.acknowledgementPath))
    }

    @Test(arguments: ["pid", "start-time", "missing-start-time", "container", "generation", "token", "operation"])
    func strictShutdownRejectsMismatchedPeerResponse(field: String) async throws {
        let fixture = try AdministrativeShutdownFixture()
        defer { fixture.close() }
        let completed = fixture.respondOnce { response in
            var status = try JSONDecoder().decode(
                VMShimProtocol.Status.self, from: #require(response.payload)
            )
            switch field {
            case "pid": status.processIdentifier = 1
            case "start-time": status.processStartTime = 0
            case "missing-start-time": status.processStartTime = nil
            case "container": status.containerID = "foreign-container"
            case "generation": status.generation += 1
            case "token": response.token = "foreign-token"
            case "operation": response.operation = .status
            default: Issue.record("unknown mismatch field")
            }
            response.payload = try JSONEncoder().encode(status)
        }
        do {
            try await VMShimClient(specification: fixture.specification)
                .requestAdministrativeShutdown(
                    timeoutMilliseconds: 1_000, waitForExit: true,
                    expectedExecutable: fixture.transportExecutable,
                    inspectionProvider: fixture.transportInspection
                )
            Issue.record("strict shutdown accepted mismatched peer response")
        } catch {
            let message = EngineError.message(for: error)
            #expect(message.contains("does not match its socket peer")
                || message.contains("authentication mismatch"))
        }
        #expect(await shutdownFixtureCompletes(completed))
        #expect(VMShimClient.processStartTime(for: getpid()) == fixture.status.processStartTime)
    }

    @Test(arguments: [false, true])
    func quarantinePreventsInfrastructureRequestOnlyForStrictTeardown(
        requireCompleteShutdown: Bool
    ) async throws {
        let fixture = try AdministrativeShutdownFixture()
        defer { fixture.close() }
        let generation = fixture.root.appending(path: "containers/unresolved/shim-generations/bad")
        try FileManager.default.createDirectory(at: generation, withIntermediateDirectories: true)
        try Data("not-json".utf8).write(to: generation.appending(path: "launch.json"))
        let completed = requireCompleteShutdown ? nil : fixture.respondOnce()

        do {
            _ = try await VMShimTeardown.terminateAll(
                in: fixture.root,
                gracePeriodMilliseconds: 1_000,
                requireCompleteShutdown: requireCompleteShutdown
            )
            Issue.record("teardown ignored quarantined generation")
        } catch {
            #expect(EngineError.message(for: error).contains("incomplete generation retains ownership evidence"))
        }
        if let completed {
            #expect(await shutdownFixtureCompletes(completed))
        } else {
            var pending = pollfd(fd: fixture.listener, events: Int16(POLLIN), revents: 0)
            #expect(Darwin.poll(&pending, 1, 0) == 0)
        }
        #expect(FileManager.default.fileExists(atPath: generation.path))
    }

    @Test func failedContainerOwnershipPreventsStrictInfrastructureRequest() async throws {
        let fixture = try AdministrativeShutdownFixture()
        defer { fixture.close() }
        let containers = fixture.root.appending(path: "containers")
        try FileManager.default.createDirectory(at: containers, withIntermediateDirectories: true)
        try Data().write(to: containers.appending(path: "not-a-directory"))
        await #expect(throws: (any Error).self) {
            _ = try await VMShimTeardown.terminateAll(
                in: fixture.root, requireCompleteShutdown: true
            )
        }
        var pending = pollfd(fd: fixture.listener, events: Int16(POLLIN), revents: 0)
        #expect(Darwin.poll(&pending, 1, 0) == 0)
    }

    @Test(arguments: ["foreign", "unreadable", "changed-identity"])
    func strictShutdownDoesNotSendCredentialsToUnverifiedPeer(reason: String) async throws {
        let fixture = try AdministrativeShutdownFixture()
        defer { fixture.close() }
        // This peer can reflect every response field. It must receive zero
        // bytes: learning the token from a request cannot prove ownership.
        let completed = fixture.respondOnce(expectRequest: false)
        let inspectionProvider: (@Sendable (CInt) -> VMShimClient.ProcessInspection?)?
        switch reason {
        case "unreadable": inspectionProvider = { _ in nil }
        case "changed-identity":
            inspectionProvider = { pid in
                guard let inspection = fixture.transportInspection(pid) else { return nil }
                return .init(
                    identityBefore: inspection.identityBefore,
                    executablePath: inspection.executablePath,
                    arguments: inspection.arguments,
                    identityAfter: .init(processIdentifier: pid, startTime: 0)
                )
            }
        default: inspectionProvider = nil // Inspect the actual, foreign test runner.
        }
        do {
            try await VMShimClient(specification: fixture.specification)
                .requestAdministrativeShutdown(
                    timeoutMilliseconds: 1_000, waitForExit: true,
                    expectedExecutable: fixture.transportExecutable,
                    inspectionProvider: inspectionProvider
                )
            Issue.record("strict shutdown trusted an unverified process")
        } catch {
            #expect(EngineError.message(for: error).contains("does not match the infrastructure launch"))
        }
        #expect(await shutdownFixtureCompletes(completed))
        #expect(VMShimClient.processStartTime(for: getpid()) == fixture.status.processStartTime)
    }

    @Test(arguments: [
        "exact", "var-alias", "executable", "argv0", "command", "flag", "spec",
        "extra-argument", "missing-argument", "before", "after", "peer", "kind",
        "container", "nonlexical-spec",
    ])
    func administrativeInspectionRequiresExactStorageLaunch(field: String) {
        var specification = VMShimProtocol.Specification(
            kind: .storage, containerID: "cengine-storage", generation: 1, token: "token",
            kernelPath: "/kernel", initialRamdiskPath: "/initramfs",
            rootDiskPath: "/var/engine/infrastructure/volumes.ext4", cpus: 1,
            memoryBytes: 268_435_456, macAddress: "02:ce:00:00:00:01",
            socketPath: "/var/engine/shim.sock", logPath: "/var/engine/infrastructure/shim.log"
        )
        let identity = VMShimClient.ProcessIdentity(processIdentifier: 42, startTime: 100)
        let changed = VMShimClient.ProcessIdentity(processIdentifier: 42, startTime: 101)
        var before = identity
        var after = identity
        var peer = identity
        var executable = "/var/app/cengine"
        var arguments = [executable, "vm-shim", "--spec", "/var/engine/infrastructure/shim.json"]
        switch field {
        case "var-alias":
            executable = "/private" + executable
            arguments[0] = executable
            arguments[3] = "/private" + arguments[3]
        case "executable": executable = "/foreign/cengine"
        case "argv0": arguments[0] = "/foreign/cengine"
        case "command": arguments[1] = "daemon"
        case "flag": arguments[2] = "--foreign"
        case "spec": arguments[3] = "/var/other/infrastructure/shim.json"
        case "extra-argument": arguments.append("--extra")
        case "missing-argument": arguments.removeLast()
        case "before": before = changed
        case "after": after = changed
        case "peer": peer = changed
        case "kind": specification.kind = .container
        case "container": specification.containerID = "foreign"
        case "nonlexical-spec": arguments[3] = "/var/engine/other/../infrastructure/shim.json"
        default: break
        }
        let inspection = VMShimClient.ProcessInspection(
            identityBefore: before, executablePath: executable,
            arguments: arguments, identityAfter: after
        )
        #expect(VMShimClient.administrativeInspectionMatches(
            inspection, peerIdentity: peer, specification: specification,
            expectedExecutable: URL(filePath: "/var/app/cengine")
        ) == (field == "exact" || field == "var-alias"))
    }

    @Test func administrativeExitVerificationAcceptsAbsenceAndPIDReuse() throws {
        let original = VMShimClient.ProcessIdentity(processIdentifier: 42, startTime: 100)
        var observations = 0
        try VMShimClient.waitForAdministrativeExit(
            original, deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 1_000_000_000
        ) { _ in
            observations += 1
            return observations == 1 ? original : nil
        }
        #expect(observations == 2)
        try VMShimClient.waitForAdministrativeExit(original, deadlineNanoseconds: 0) { pid in
            #expect(pid == original.processIdentifier)
            return nil
        }
        try VMShimClient.waitForAdministrativeExit(original, deadlineNanoseconds: 0) { pid in
            .init(processIdentifier: pid, startTime: 101)
        }
    }

    @Test func administrativeExitVerificationRetriesTransientInspectionFailure() throws {
        let original = VMShimClient.ProcessIdentity(processIdentifier: 42, startTime: 100)
        var observations = 0
        try VMShimClient.waitForAdministrativeExit(
            original, deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 1_000_000_000
        ) { _ in
            observations += 1
            if observations == 1 { throw POSIXError(.ESRCH) }
            return observations == 2 ? original : nil
        }
        #expect(observations == 3)
    }

    @Test func administrativeExitVerificationRejectsLiveOrUnreadableIdentity() {
        let original = VMShimClient.ProcessIdentity(processIdentifier: 42, startTime: 100)
        #expect(throws: EngineError.self) {
            try VMShimClient.waitForAdministrativeExit(original, deadlineNanoseconds: 0) { _ in
                original
            }
        }
        #expect(throws: POSIXError.self) {
            try VMShimClient.waitForAdministrativeExit(original, deadlineNanoseconds: 0) { _ in
                throw POSIXError(.EACCES)
            }
        }
    }

    @Test func statusProbeHasBoundedReadDeadline() async throws {
        let fixture = try AdministrativeShutdownFixture()
        defer { fixture.close() }
        // The listener accepts connections into its backlog but sends no reply.
        await #expect(throws: AsyncTimeout.TimeoutError.self) {
            _ = try await VMShimClient(specification: fixture.specification)
                .status(timeoutMilliseconds: 50)
        }
    }
}

private func shutdownFixtureReadExactly(_ file: FileHandle, count: Int) throws -> Data {
    var data = Data()
    while data.count < count {
        guard let next = try file.read(upToCount: count - data.count), !next.isEmpty else {
            throw EngineError(.internalError, "shutdown fixture request was truncated")
        }
        data.append(next)
    }
    return data
}

private func shutdownFixtureBlockingWait(_ semaphore: DispatchSemaphore) -> Bool {
    semaphore.wait(timeout: .now() + 3) == .success
}

private func shutdownFixtureCompletes(_ semaphore: DispatchSemaphore) async -> Bool {
    await Task.detached { shutdownFixtureBlockingWait(semaphore) }.value
}

private struct AdministrativeShutdownFixture: Sendable {
    let root: URL
    let specification: VMShimProtocol.Specification
    let status: VMShimProtocol.Status
    let listener: CInt

    init(listen: Bool = true) throws {
        root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let infrastructure = root.appending(path: "infrastructure")
        try FileManager.default.createDirectory(at: infrastructure, withIntermediateDirectories: true)
        specification = VMShimProtocol.Specification(
            kind: .storage,
            containerID: "cengine-storage",
            generation: 1,
            token: "infrastructure-token",
            kernelPath: "/kernel",
            initialRamdiskPath: "/storage-initramfs",
            rootDiskPath: infrastructure.appending(path: "volumes.ext4").path,
            cpus: 1,
            memoryBytes: 268_435_456,
            macAddress: "02:ce:00:00:00:01",
            socketPath: try RawVirtualizationBackend.makeRuntimeSocketPath(),
            logPath: infrastructure.appending(path: "shim.log").path
        )
        try JSONEncoder().encode(specification).write(to: infrastructure.appending(path: "shim.json"))
        status = VMShimProtocol.Status(
            containerID: specification.containerID,
            generation: specification.generation,
            state: .stopped,
            processIdentifier: getpid(),
            processStartTime: try #require(VMShimClient.processStartTime(for: getpid()))
        )
        if listen {
            listener = try UnixSocket.listen(path: specification.socketPath)
        } else {
            listener = -1
        }
    }

    // Deliberately fictional launch evidence, injected only into the internal
    // transport method. Teardown integration tests always inspect a native peer.
    var transportExecutable: URL { root.appending(path: "transport-only-cengine") }

    var transportInspection: @Sendable (CInt) -> VMShimClient.ProcessInspection? {
        { [self] pid in
            guard let startTime = status.processStartTime else { return nil }
            let identity = VMShimClient.ProcessIdentity(processIdentifier: pid, startTime: startTime)
            return .init(
                identityBefore: identity, executablePath: transportExecutable.path,
                arguments: [
                    transportExecutable.path, "vm-shim", "--spec",
                    VMShimClient.specificationURL(for: specification).path,
                ],
                identityAfter: identity
            )
        }
    }

    func respondOnce(
        expectRequest: Bool = true,
        modify: @escaping @Sendable (inout VMShimProtocol.Envelope) throws -> Void = { _ in }
    ) -> DispatchSemaphore {
        let completed = DispatchSemaphore(value: 0)
        Thread.detachNewThread { [listener, specification, status] in
            defer { completed.signal() }
            do {
                var pending = pollfd(fd: listener, events: Int16(POLLIN), revents: 0)
                guard Darwin.poll(&pending, 1, 2_000) > 0 else {
                    Issue.record("infrastructure shutdown request was not received")
                    return
                }
                // An unverified client can close before accept. Darwin rejects
                // setsockopt on that disconnected socket, so do not configure it.
                let peer = expectRequest ? try UnixSocket.accept(listener) : Darwin.accept(listener, nil, nil)
                guard peer >= 0 else { throw POSIXError(.EIO) }
                defer { Darwin.close(peer) }
                let file = FileHandle(fileDescriptor: peer, closeOnDealloc: false)
                if !expectRequest {
                    var readable = pollfd(fd: peer, events: Int16(POLLIN), revents: 0)
                    guard Darwin.poll(&readable, 1, 2_000) > 0 else { throw POSIXError(.ETIMEDOUT) }
                    let prefix = try file.read(upToCount: 4) ?? Data()
                    #expect(prefix.isEmpty)
                    return
                }
                var timeout = timeval(tv_sec: 2, tv_usec: 0)
                guard setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0 else {
                    throw POSIXError(.EIO)
                }
                let prefix = try shutdownFixtureReadExactly(file, count: 4)
                let size = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
                guard size > 0, size <= VMShimProtocol.maximumFrameSize else {
                    throw EngineError(.internalError, "invalid shutdown fixture frame size")
                }
                let body = try shutdownFixtureReadExactly(file, count: Int(size))
                let request = try VMShimProtocol.decode(prefix + body)
                #expect(request.operation == .shutdown)
                #expect(request.token == specification.token)
                var response = VMShimProtocol.Envelope(
                    id: request.id, token: request.token, operation: request.operation,
                    payload: try JSONEncoder().encode(status)
                )
                try modify(&response)
                try file.write(contentsOf: VMShimProtocol.encode(response))
            } catch {
                Issue.record("infrastructure shutdown fixture failed: \(error)")
            }
        }
        return completed
    }

    func close() {
        if listener >= 0 { Darwin.close(listener) }
        try? FileManager.default.removeItem(atPath: specification.socketPath)
        try? FileManager.default.removeItem(atPath: specification.socketPath + ".status")
        try? FileManager.default.removeItem(at: root)
    }
}

/// A separate native process is required to exercise real LOCAL_PEERPID and
/// proc_pidpath/KERN_PROCARGS2 evidence. A listener in the test runner is foreign.
private struct NativeAdministrativeShutdownPeer {
    let process: Process
    let executable: URL
    let startTime: UInt64
    let acknowledgementPath: String
    let noRequestPath: String
    let exited: DispatchSemaphore

    init(
        fixture: AdministrativeShutdownFixture,
        stayAlive: Bool,
        foreignSpecificationArgument: Bool = false,
        responseMismatch: String? = nil,
        replyDelayMilliseconds: Int = 0,
        exitDelayMilliseconds: Int = 0
    ) throws {
        let executable = try buildAdministrativeShutdownExecutable(in: fixture.root)
        var specificationURL = VMShimClient.specificationURL(for: fixture.specification)
        if foreignSpecificationArgument {
            let foreign = specificationURL.deletingLastPathComponent().appending(path: "foreign-shim.json")
            try FileManager.default.copyItem(at: specificationURL, to: foreign)
            specificationURL = foreign
        }
        let child = Process()
        child.executableURL = executable
        child.arguments = ["vm-shim", "--spec", specificationURL.path]
        var environment = ProcessInfo.processInfo.environment
        environment["CENGINE_TEST_SHIM_STAY_ALIVE"] = stayAlive ? "1" : "0"
        environment["CENGINE_TEST_SHIM_RESPONSE_MISMATCH"] = responseMismatch
        environment["CENGINE_TEST_SHIM_REPLY_DELAY_MS"] = String(replyDelayMilliseconds)
        environment["CENGINE_TEST_SHIM_EXIT_DELAY_MS"] = String(exitDelayMilliseconds)
        child.environment = environment
        child.standardInput = FileHandle.nullDevice
        child.standardOutput = FileHandle.nullDevice
        child.standardError = FileHandle.nullDevice
        let exited = DispatchSemaphore(value: 0)
        try child.run()
        Thread.detachNewThread {
            child.waitUntilExit()
            exited.signal()
        }
        do {
            // Many tests compile/spawn native peers concurrently under Xcode.
            let deadline = DispatchTime.now().uptimeNanoseconds + 5_000_000_000
            while !FileManager.default.fileExists(atPath: specificationURL.path + ".ready") {
                guard child.isRunning, DispatchTime.now().uptimeNanoseconds < deadline else {
                    throw EngineError(.internalError, "native shutdown peer did not become ready")
                }
                usleep(10_000)
            }
            startTime = try #require(VMShimClient.processStartTime(for: child.processIdentifier))
        } catch {
            if child.isRunning { child.terminate() }
            throw error
        }
        self.executable = executable
        process = child
        acknowledgementPath = specificationURL.path + ".ack"
        noRequestPath = specificationURL.path + ".no-request"
        self.exited = exited
    }

    func close() {
        // Test cleanup targets our directly spawned process, never status data.
        if process.isRunning { process.terminate() }
    }
}

private func buildAdministrativeShutdownExecutable(in directory: URL) throws -> URL {
    let source = directory.appending(path: "administrative-shim.m")
    let executable = directory.appending(path: "administrative-shim")
    let program = #"""
    #import <Foundation/Foundation.h>
    #include <arpa/inet.h>
    #include <errno.h>
    #include <libproc.h>
    #include <signal.h>
    #include <stdlib.h>
    #include <string.h>
    #include <sys/socket.h>
    #include <sys/un.h>
    #include <unistd.h>

    static int readAll(int fd, void *buffer, size_t count) {
        char *bytes = buffer;
        while (count) {
            ssize_t n = read(fd, bytes, count);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) return 0;
            bytes += n; count -= n;
        }
        return 1;
    }
    static int writeAll(int fd, const void *buffer, size_t count) {
        const char *bytes = buffer;
        while (count) {
            ssize_t n = write(fd, bytes, count);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) return 0;
            bytes += n; count -= n;
        }
        return 1;
    }
    int main(int argc, char **argv) {
        @autoreleasepool {
            alarm(10); // Bound every socket operation and the stay-alive mode.
            signal(SIGPIPE, SIG_IGN);
            if (argc != 4 || strcmp(argv[1], "vm-shim") || strcmp(argv[2], "--spec")) return 2;
            NSString *specPath = [NSString stringWithUTF8String:argv[3]];
            NSData *specData = [NSData dataWithContentsOfFile:specPath];
            if (!specData) return 3;
            NSDictionary *spec = [NSJSONSerialization JSONObjectWithData:specData options:0 error:NULL];
            if (![spec[@"kind"] isEqual:@"storage"]) return 4;
            const char *socketPath = [spec[@"socketPath"] fileSystemRepresentation];
            struct sockaddr_un address = {0};
            address.sun_family = AF_UNIX;
            address.sun_len = sizeof(address);
            if (!socketPath || strlcpy(address.sun_path, socketPath, sizeof(address.sun_path)) >= sizeof(address.sun_path)) return 5;
            int listener = socket(AF_UNIX, SOCK_STREAM, 0);
            if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) || listen(listener, 1)) return 6;
            if (![[NSData data] writeToFile:[specPath stringByAppendingString:@".ready"] atomically:YES]) return 7;
            int peer = accept(listener, NULL, NULL);
            uint32_t length = 0;
            if (peer < 0) return 8;
            ssize_t first = read(peer, &length, 1);
            if (first == 0) {
                return [[NSData data] writeToFile:[specPath stringByAppendingString:@".no-request"] atomically:YES] ? 0 : 8;
            }
            if (first != 1 || !readAll(peer, ((char *)&length) + 1, sizeof(length) - 1)) return 8;
            length = ntohl(length);
            if (!length || length > 16 * 1024 * 1024) return 9;
            NSMutableData *body = [NSMutableData dataWithLength:length];
            if (!readAll(peer, body.mutableBytes, length)) return 10;
            NSDictionary *request = [NSJSONSerialization JSONObjectWithData:body options:0 error:NULL];
            if (![request[@"operation"] isEqual:@"shutdown"] || ![request[@"token"] isEqual:spec[@"token"]]) return 11;
            struct proc_bsdinfo info = {0};
            if (proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info)) return 12;
            const char *mismatch = getenv("CENGINE_TEST_SHIM_RESPONSE_MISMATCH") ?: "";
            NSDictionary *status = @{
                @"containerID": spec[@"containerID"], @"generation": spec[@"generation"],
                @"state": @"stopped", @"processIdentifier": @(!strcmp(mismatch, "pid") ? 1 : getpid()),
                @"processStartTime": @(info.pbi_start_tvsec * 1000000ULL + info.pbi_start_tvusec)
            };
            NSData *payload = [NSJSONSerialization dataWithJSONObject:status options:0 error:NULL];
            NSMutableDictionary *response = [request mutableCopy];
            response[@"payload"] = [payload base64EncodedStringWithOptions:0];
            if (!strncmp(mismatch, "token", 5)) response[@"token"] = @"foreign-token";
            NSData *reply = [NSJSONSerialization dataWithJSONObject:response options:0 error:NULL];
            length = htonl((uint32_t)reply.length);
            if (![[NSData data] writeToFile:[specPath stringByAppendingString:@".ack"] atomically:YES]) return 13;
            if (!strcmp(mismatch, "token-without-artifacts")) {
                unlink(socketPath);
                NSString *statusPath = [spec[@"socketPath"] stringByAppendingString:@".status"];
                unlink(statusPath.fileSystemRepresentation);
            }
            usleep((useconds_t)atoi(getenv("CENGINE_TEST_SHIM_REPLY_DELAY_MS") ?: "0") * 1000);
            if (!writeAll(peer, &length, sizeof(length)) || !writeAll(peer, reply.bytes, reply.length)) return 14;
            close(peer); close(listener);
            usleep((useconds_t)atoi(getenv("CENGINE_TEST_SHIM_EXIT_DELAY_MS") ?: "0") * 1000);
            if (!strcmp(getenv("CENGINE_TEST_SHIM_STAY_ALIVE") ?: "0", "1")) {
                for (;;) pause();
            }
            return 0;
        }
    }
    """#
    try Data(program.utf8).write(to: source)
    let compiler = Process()
    compiler.executableURL = URL(filePath: "/usr/bin/clang")
    compiler.arguments = [source.path, "-framework", "Foundation", "-o", executable.path]
    compiler.standardInput = FileHandle.nullDevice
    compiler.standardOutput = FileHandle.nullDevice
    compiler.standardError = FileHandle.nullDevice
    let completed = DispatchSemaphore(value: 0)
    compiler.terminationHandler = { _ in completed.signal() }
    try compiler.run()
    guard completed.wait(timeout: .now() + 15) == .success else {
        if compiler.isRunning { compiler.terminate() }
        throw EngineError(.internalError, "timed out building native shutdown peer")
    }
    guard compiler.terminationStatus == 0 else {
        throw EngineError(.internalError, "could not build native shutdown peer")
    }
    return executable
}

private func buildIdleShimExecutable(in directory: URL) throws -> URL {
    let source = directory.appending(path: "uninstall-idle-shim.c")
    let executable = directory.appending(path: "uninstall-idle-shim")
    try Data("#include <unistd.h>\nint main(void) { for (;;) pause(); }\n".utf8)
        .write(to: source)
    let compiler = Process()
    compiler.executableURL = URL(filePath: "/usr/bin/clang")
    compiler.arguments = [source.path, "-o", executable.path]
    compiler.standardInput = FileHandle.nullDevice
    compiler.standardOutput = FileHandle.nullDevice
    compiler.standardError = FileHandle.nullDevice
    try compiler.run()
    compiler.waitUntilExit()
    guard compiler.terminationStatus == 0 else {
        throw EngineError(.internalError, "could not build uninstall shim test helper")
    }
    return executable
}
#endif

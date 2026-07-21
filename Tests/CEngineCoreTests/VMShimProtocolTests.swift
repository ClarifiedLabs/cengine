import Foundation
import Testing
@testable import CEngineCore
#if os(macOS)
import Darwin
@testable import CEngineRuntime

private final class ShimDescriptorBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: CInt?

    func store(_ descriptor: CInt) { lock.withLock { value = descriptor } }
    func load() -> CInt? { lock.withLock { value } }
}

private final class LockedUptimeBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: UInt64?

    func storeNow() {
        lock.withLock { value = DispatchTime.now().uptimeNanoseconds }
    }

    func load() -> UInt64? { lock.withLock { value } }
}

private final class RuntimeArtifactFault: @unchecked Sendable {
    enum Failure: Error { case injected }
    private let lock = NSLock()
    private let target: PersistentRuntimeArtifactBoundary
    private var fired = false

    init(_ target: PersistentRuntimeArtifactBoundary) { self.target = target }

    func fail(_ boundary: PersistentRuntimeArtifactBoundary) throws {
        let shouldFail = lock.withLock {
            guard !fired, boundary == target else { return false }
            fired = true
            return true
        }
        if shouldFail { throw Failure.injected }
    }
}

private final class RuntimeArtifactReplacementHook: @unchecked Sendable {
    private let lock = NSLock()
    private let socketPath: String
    private let statusPath: String
    private let statusData: Data
    private let listenerBox: ShimDescriptorBox
    private var replaced = Set<String>()

    init(
        socketPath: String,
        statusPath: String,
        statusData: Data,
        listenerBox: ShimDescriptorBox
    ) {
        self.socketPath = socketPath
        self.statusPath = statusPath
        self.statusData = statusData
        self.listenerBox = listenerBox
    }

    func replace(_ boundary: PersistentRuntimeArtifactBoundary) throws {
        guard case .deletionObserved(let name) = boundary else { return }
        try lock.withLock {
            guard replaced.insert(name).inserted else { return }
            if name == URL(filePath: socketPath).lastPathComponent {
                try FileManager.default.removeItem(atPath: socketPath)
                listenerBox.store(try UnixSocket.listen(path: socketPath))
            } else if name == URL(filePath: statusPath).lastPathComponent {
                try FileManager.default.removeItem(atPath: statusPath)
                try statusData.write(to: URL(filePath: statusPath))
            }
        }
    }
}

private func blockingSemaphoreWait(_ semaphore: DispatchSemaphore) -> Bool {
    semaphore.wait(timeout: .now() + 2) == .success
}

private func semaphoreArrives(_ semaphore: DispatchSemaphore) async -> Bool {
    await Task.detached { blockingSemaphoreWait(semaphore) }.value
}

private func descriptorIsReadable(_ descriptor: CInt, timeoutMilliseconds: CInt) -> Bool {
    var descriptor = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
    return Darwin.poll(&descriptor, 1, timeoutMilliseconds) > 0
}

private func buildArgumentPreservingIdleExecutable(in directory: URL) throws -> URL {
    let source = directory.appending(path: "idle-shim.c")
    let executable = directory.appending(path: "idle-shim")
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
        throw EngineError(.internalError, "could not build persistent shim test helper")
    }
    return executable
}

private actor OperationRecorder {
    private var entries: [String] = []
    func record(_ value: String) { entries.append(value) }
    func values() -> [String] { entries }
    func reset() { entries.removeAll() }
}

private final class LockedOperationRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var entries: [String] = []

    func record(_ value: String) { lock.withLock { entries.append(value) } }
    func values() -> [String] { lock.withLock { entries } }
}

private final class PreparationRecoveryState: @unchecked Sendable {
    enum Failure: Error { case preparation, termination }

    private let lock = NSLock()
    private var attempts = 0
    private var capacityOwned = true
    private var rootPresent = true

    func terminateEveryGeneration() throws {
        try lock.withLock {
            attempts += 1
            if attempts == 1 { throw Failure.termination }
            capacityOwned = false
        }
    }

    func discardWritableRoot() throws {
        lock.withLock {
            precondition(!capacityOwned)
            rootPresent = false
        }
    }

    func snapshot() -> (attempts: Int, capacityOwned: Bool, rootPresent: Bool) {
        lock.withLock { (attempts, capacityOwned, rootPresent) }
    }
}

private final class RecoveredPreparationBox: @unchecked Sendable {
    private let lock = NSLock()
    private var container: ContainerRecord?
    private var specification: VMShimProtocol.Specification?

    func restore(
        container: ContainerRecord,
        specification: VMShimProtocol.Specification
    ) {
        lock.withLock {
            self.container = container
            self.specification = specification
        }
    }

    func snapshot() -> (ContainerRecord?, VMShimProtocol.Specification?) {
        lock.withLock { (container, specification) }
    }
}

private func makePreparedState(
    in directory: PersistentStateDirectory,
    containerID: String,
    rootDiskSize: UInt64 = 4_096,
    generation: UInt64 = 1
) throws -> RawVirtualizationBackend.PreparedShimState {
    let artifacts = try RawContainerPreparationArtifacts.create(
        in: directory, rootDiskSize: rootDiskSize
    )
    let container = ContainerRecord(
        id: containerID, name: containerID, image: "alpine"
    )
    let specification = VMShimProtocol.Specification(
        containerID: containerID,
        generation: generation,
        token: "prepared-artifact-token",
        kernelPath: "/kernel",
        initialRamdiskPath: "/initramfs",
        rootDiskPath: directory.url.appending(path: "root.ext4").path,
        rootDiskIdentity: .init(
            device: artifacts.rootDiskIdentity.device,
            inode: artifacts.rootDiskIdentity.inode
        ),
        rootDiskSize: artifacts.rootDiskSize,
        cpus: 2,
        memoryBytes: 512 * 1_024 * 1_024,
        macAddress: "02:ce:00:00:00:01",
        bindShares: [.init(
            tag: "cengine-io",
            source: directory.url.appending(path: "io", directoryHint: .isDirectory).path,
            readOnly: false,
            sourceIdentity: .init(
                device: artifacts.ioDirectoryIdentity.device,
                inode: artifacts.ioDirectoryIdentity.inode
            )
        )],
        socketPath: "/tmp/cengine-prepared-artifact.sock",
        logPath: directory.url.appending(path: "shim.log").path
    )
    let state = RawVirtualizationBackend.PreparedShimState(
        directoryIdentity: directory.identity,
        artifacts: artifacts,
        currentContainer: container,
        specification: specification
    )
    try directory.replaceRegularFile(
        named: "prepared-shim.json", data: try JSONEncoder().encode(state)
    )
    return state
}

private func makeExecArtifactRecord(
    in containerDirectory: PersistentStateDirectory,
    containerID: String,
    execID: String
) throws -> RawExecArtifactRecord {
    let ioDirectory = try containerDirectory.openDirectory(named: "io")
    var identities: [String: PersistentFileIdentity] = [:]
    for name in RawExecArtifactRecord.expectedNames(execID: execID) {
        identities[name] = try ioDirectory.createSparseRegularFile(named: name, size: 0)
    }
    return RawExecArtifactRecord(
        containerID: containerID, execID: execID, fileIdentities: identities
    )
}

private func linkGuestIOClaims(
    _ claim: String,
    names: [String],
    in directory: PersistentStateDirectory
) throws {
    for (index, name) in names.enumerated() {
        try FileManager.default.linkItem(
            at: directory.url.appending(path: name),
            to: directory.url.appending(
                path: RawContainerDirectIOHandles.guestClaimName(
                    claim, index: index
                )
            )
        )
    }
}

private func readExecArtifactJournal(
    in containerDirectory: PersistentStateDirectory,
    artifacts: RawContainerPreparationArtifacts
) throws -> Data {
    let handle = try containerDirectory.openRegularFile(
        named: "exec-artifacts.jsonl",
        expectedIdentity: artifacts.execArtifactJournalIdentity,
        access: .readOnly
    ).handle
    try handle.seek(toOffset: 0)
    return try handle.readToEnd() ?? Data()
}

private func replaceExecArtifactJournal(
    with data: Data,
    in containerDirectory: PersistentStateDirectory,
    artifacts: RawContainerPreparationArtifacts
) throws {
    let handle = try containerDirectory.openRegularFile(
        named: "exec-artifacts.jsonl",
        expectedIdentity: artifacts.execArtifactJournalIdentity,
        access: .readWrite
    ).handle
    guard Darwin.ftruncate(handle.fileDescriptor, 0) == 0 else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    try handle.seek(toOffset: 0)
    try handle.write(contentsOf: data)
    try handle.synchronize()
}

private func readExecArtifactCompaction(
    in containerDirectory: PersistentStateDirectory,
    artifacts: RawContainerPreparationArtifacts
) throws -> Data {
    let handle = try containerDirectory.openRegularFile(
        named: "exec-artifacts.compact",
        expectedIdentity: artifacts.execArtifactCompactionIdentity,
        access: .readOnly
    ).handle
    try handle.seek(toOffset: 0)
    return try handle.readToEnd() ?? Data()
}

private func replaceExecArtifactCompaction(
    with data: Data,
    in containerDirectory: PersistentStateDirectory,
    artifacts: RawContainerPreparationArtifacts
) throws {
    let handle = try containerDirectory.openRegularFile(
        named: "exec-artifacts.compact",
        expectedIdentity: artifacts.execArtifactCompactionIdentity,
        access: .readWrite
    ).handle
    guard Darwin.ftruncate(handle.fileDescriptor, 0) == 0 else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    try handle.seek(toOffset: 0)
    try handle.write(contentsOf: data)
    try handle.synchronize()
}

private final class OneShotExecJournalPause: @unchecked Sendable {
    private let lock = NSLock()
    private var paused = false
    let entered = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)

    func pauseIfFirst(_ boundary: RawExecJournalMutationBoundary) {
        guard boundary == .snapshotLoaded else { return }
        let shouldPause = lock.withLock { () -> Bool in
            guard !paused else { return false }
            paused = true
            return true
        }
        if shouldPause {
            entered.signal()
            release.wait()
        }
    }
}

private final class ConcurrentExecJournalFailures: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String] = []

    func append(_ error: Error) {
        lock.withLock { values.append(EngineError.message(for: error)) }
    }

    var all: [String] { lock.withLock { values } }
}

private final class ExecJournalGuestGate: @unchecked Sendable {
    let entered = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)

    func enterAndWait() {
        entered.signal()
        release.wait()
    }
}
#endif

@Suite(.serialized) struct VMShimProtocolTests {
    @Test func envelopeRoundTrips() throws {
        let envelope = VMShimProtocol.Envelope(token: "secret", operation: .status)

        #expect(try VMShimProtocol.decode(VMShimProtocol.encode(envelope)) == envelope)
    }

    @Test func envelopeRequiresAuthenticationToken() throws {
        let frame = try VMShimProtocol.encode(.init(token: "", operation: .status))

        #expect(throws: EngineError.self) { try VMShimProtocol.decode(frame) }
    }

    @Test func shimSpecificationPersistsVolumeDisks() throws {
        let specification = VMShimProtocol.Specification(
            containerID: "volume-container",
            generation: 1,
            token: "secret",
            kernelPath: "/kernel",
            initialRamdiskPath: "/initramfs",
            rootDiskPath: "/root.ext4",
            volumeDisks: [.init(name: "data", path: "/data.ext4")],
            cpus: 1,
            memoryBytes: 268_435_456,
            macAddress: "02:ce:00:00:00:04",
            socketRelays: [.init(path: "/tmp/docker.sock", port: GuestProtocol.socketProxyPortBase)],
            socketPath: "/tmp/control.sock",
            logPath: "/tmp/shim.log",
            networkNamespace: "engine-root-namespace"
        )

        let data = try JSONEncoder().encode(specification)
        let decoded = try JSONDecoder().decode(VMShimProtocol.Specification.self, from: data)
        #expect(decoded == specification)
        #expect(decoded.networkNamespace == "engine-root-namespace")
    }

    @Test func managementVLANIsReservedFromDockerNetworks() {
        #expect(VMShimProtocol.managementVLAN == 4_094)
        #if os(macOS)
        #expect(RawVirtualizationBackend.nextAvailableVLAN(used: Set(1..<VMShimProtocol.managementVLAN)) == nil)
        #expect(RawVirtualizationBackend.nextAvailableVLAN(used: []) == 1)
        #endif
    }

    #if os(macOS)
    @Test func compatibilityResourceFailureClaimIsTargetedAndOneShot() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let markerURL = root.appending(path: "resource-update-failure")

        func publish(containerID: String, failureAfterWrites: UInt32) throws {
            let marker = CompatibilityResourceUpdateFailureMarker(
                containerID: containerID, failureAfterWrites: failureAfterWrites
            )
            try JSONEncoder().encode(marker).write(to: markerURL, options: .atomic)
        }

        try publish(containerID: "target", failureAfterWrites: 4)
        #expect(try CompatibilityResourceUpdateFailureClaim.claim(
            at: markerURL, containerID: "other"
        ) == nil)
        #expect(FileManager.default.fileExists(atPath: markerURL.path))
        #expect(try CompatibilityResourceUpdateFailureClaim.claim(
            at: markerURL, containerID: "target"
        ) == 4)
        #expect(!FileManager.default.fileExists(atPath: markerURL.path))
        #expect(try CompatibilityResourceUpdateFailureClaim.claim(
            at: markerURL, containerID: "target"
        ) == nil)

        try publish(containerID: "target", failureAfterWrites: 7)
        let claims = await withTaskGroup(of: UInt32?.self, returning: [UInt32?].self) { group in
            for _ in 0..<2 {
                group.addTask {
                    try? CompatibilityResourceUpdateFailureClaim.claim(
                        at: markerURL, containerID: "target"
                    )
                }
            }
            var values: [UInt32?] = []
            for await value in group { values.append(value) }
            return values
        }
        #expect(claims.compactMap { $0 } == [7])
        #expect(!FileManager.default.fileExists(atPath: markerURL.path))
    }

    @Test func compatibilityResourceFailureClaimRejectsUnsafeMarkerFiles() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let symlinkTarget = root.appending(path: "target.json")
        try JSONEncoder().encode(CompatibilityResourceUpdateFailureMarker(
            containerID: "target", failureAfterWrites: 1
        )).write(to: symlinkTarget)
        let symlink = root.appending(path: "symlink-marker")
        try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: symlinkTarget)
        #expect(throws: EngineError.self) {
            try CompatibilityResourceUpdateFailureClaim.claim(at: symlink, containerID: "target")
        }
        #expect(FileManager.default.fileExists(atPath: symlinkTarget.path))

        let fifo = root.appending(path: "fifo-marker")
        #expect(Darwin.mkfifo(fifo.path, mode_t(0o600)) == 0)
        #expect(throws: EngineError.self) {
            try CompatibilityResourceUpdateFailureClaim.claim(at: fifo, containerID: "target")
        }

        let oversized = root.appending(path: "oversized-marker")
        try Data(repeating: 0x20, count: 4 * 1_024 + 1).write(to: oversized)
        #expect(throws: EngineError.self) {
            try CompatibilityResourceUpdateFailureClaim.claim(at: oversized, containerID: "target")
        }
        #expect(FileManager.default.fileExists(atPath: oversized.path))
    }

    @Test func compatibilityResourceFailureClaimConsumesOnlyTheClaimedDirectoryEntry() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let markerURL = root.appending(path: "resource-update-failure")

        func publish(containerID: String, failureAfterWrites: UInt32) throws {
            try JSONEncoder().encode(CompatibilityResourceUpdateFailureMarker(
                containerID: containerID,
                failureAfterWrites: failureAfterWrites
            )).write(to: markerURL, options: .atomic)
        }

        try publish(containerID: "target", failureAfterWrites: 3)
        #expect(try CompatibilityResourceUpdateFailureClaim.claim(
            at: markerURL,
            containerID: "target",
            afterClaim: { try publish(containerID: "target", failureAfterWrites: 9) }
        ) == 3)
        #expect(try CompatibilityResourceUpdateFailureClaim.claim(
            at: markerURL,
            containerID: "target"
        ) == 9)

        try publish(containerID: "other", failureAfterWrites: 5)
        #expect(throws: EngineError.self) {
            try CompatibilityResourceUpdateFailureClaim.claim(
                at: markerURL,
                containerID: "target",
                afterClaim: { try publish(containerID: "target", failureAfterWrites: 11) }
            )
        }
        #expect(try CompatibilityResourceUpdateFailureClaim.claim(
            at: markerURL,
            containerID: "target"
        ) == 11)
        let strandedClaims = try FileManager.default.contentsOfDirectory(atPath: root.path)
            .filter { $0.contains(".claim.") }
        #expect(strandedClaims.count == 1)
    }

    @Test func stoppedResourceReplacementRestoresOriginalAndAggregatesReverseFailures() async throws {
        enum Failure: Error { case candidate, cleanup, restore }
        let recorder = OperationRecorder()

        await #expect(throws: Failure.self) {
            try await StoppedResourceReplacementTransaction.perform(
                terminateOriginal: { await recorder.record("terminate") },
                launchCandidate: { await recorder.record("candidate"); throw Failure.candidate },
                cleanupCandidate: { await recorder.record("cleanup") },
                restoreOriginal: { await recorder.record("restore") }
            )
        }
        #expect(await recorder.values() == ["terminate", "candidate", "cleanup", "restore"])

        await recorder.reset()
        await #expect(throws: Failure.self) {
            try await StoppedResourceReplacementTransaction.perform(
                terminateOriginal: {
                    await recorder.record("terminate")
                    throw Failure.cleanup
                },
                launchCandidate: { await recorder.record("candidate") },
                cleanupCandidate: { await recorder.record("cleanup") },
                restoreOriginal: { await recorder.record("restore") }
            )
        }
        #expect(await recorder.values() == ["terminate", "cleanup", "restore"])

        await recorder.reset()
        do {
            try await StoppedResourceReplacementTransaction.perform(
                terminateOriginal: {
                    await recorder.record("terminate")
                    throw Failure.cleanup
                },
                launchCandidate: { await recorder.record("candidate") },
                cleanupCandidate: {
                    await recorder.record("cleanup")
                    throw Failure.cleanup
                },
                restoreOriginal: {
                    await recorder.record("restore")
                    throw Failure.restore
                }
            )
            Issue.record("expected rollback-incomplete termination failure")
        } catch let error as BackendResourceRollbackIncompleteError {
            #expect(error.message.contains("original shim termination failed"))
            #expect(error.message.contains("cleanup after original shim termination failed"))
            #expect(error.message.contains("restoration after termination failure failed"))
        }
        #expect(await recorder.values() == ["terminate", "cleanup", "restore"])

        await recorder.reset()
        await #expect(throws: EngineError.self) {
            try await StoppedResourceReplacementTransaction.perform(
                terminateOriginal: { await recorder.record("terminate") },
                launchCandidate: {
                    await recorder.record("candidate")
                    throw BackendResourceRollbackIncompleteError("partial candidate process survived")
                },
                cleanupCandidate: { await recorder.record("cleanup") },
                restoreOriginal: { await recorder.record("restore") }
            )
        }
        #expect(await recorder.values() == ["terminate", "candidate", "cleanup", "restore"])

        await recorder.reset()
        do {
            try await StoppedResourceReplacementTransaction.perform(
                terminateOriginal: { await recorder.record("terminate") },
                launchCandidate: { await recorder.record("candidate"); throw Failure.candidate },
                cleanupCandidate: { await recorder.record("cleanup"); throw Failure.cleanup },
                restoreOriginal: { await recorder.record("restore"); throw Failure.restore }
            )
            Issue.record("expected rollback-incomplete failure")
        } catch let error as BackendResourceRollbackIncompleteError {
            #expect(error.message.contains("candidate launch failed"))
            #expect(error.message.contains("candidate cleanup failed"))
            #expect(error.message.contains("original shim restoration failed"))
        }
        #expect(await recorder.values() == ["terminate", "candidate", "cleanup", "restore"])
    }

    @Test func liveResourceCanonicalFailureRestoresGuestAndDurableState() async throws {
        enum Failure: Error { case publication, guestRestore, canonicalRestore }
        let recorder = LockedOperationRecorder()

        await #expect(throws: Failure.self) {
            try await LiveResourceCanonicalTransaction.perform(
                applyDesired: { recorder.record("guest-desired") },
                persistDesired: {
                    recorder.record("canonical-desired")
                    throw Failure.publication
                },
                applyOriginal: { recorder.record("guest-original") },
                persistOriginal: { recorder.record("canonical-original") }
            )
        }
        #expect(recorder.values() == [
            "guest-desired", "canonical-desired", "guest-original", "canonical-original",
        ])

        let incomplete = LockedOperationRecorder()
        do {
            try await LiveResourceCanonicalTransaction.perform(
                applyDesired: { incomplete.record("guest-desired") },
                persistDesired: {
                    incomplete.record("canonical-desired")
                    throw Failure.publication
                },
                applyOriginal: {
                    incomplete.record("guest-original")
                    throw Failure.guestRestore
                },
                persistOriginal: {
                    incomplete.record("canonical-original")
                    throw Failure.canonicalRestore
                }
            )
            Issue.record("expected rollback-incomplete live resource failure")
        } catch let error as BackendResourceRollbackIncompleteError {
            #expect(error.message.contains("guest restoration failed"))
            #expect(error.message.contains("canonical restoration failed"))
        }
        #expect(incomplete.values() == [
            "guest-desired", "canonical-desired", "guest-original", "canonical-original",
        ])
    }

    @Test func interruptedShimLaunchRetainsTheOnlyCleanupHandle() async throws {
        enum Failure: Error { case injectedCleanup }
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let executable = root.appending(path: "blocked-shim")
        try Data("#!/bin/sh\nexec /bin/sleep 30\n".utf8).write(to: executable)
        #expect(Darwin.chmod(executable.path, mode_t(0o700)) == 0)
        let socketPath = try RawVirtualizationBackend.makeRuntimeSocketPath()
        let specification = VMShimProtocol.Specification(
            containerID: "partial-launch",
            generation: 23,
            token: "test-token",
            kernelPath: "/kernel",
            initialRamdiskPath: "/initramfs",
            rootDiskPath: root.appending(path: "root.ext4").path,
            cpus: 1,
            memoryBytes: 268_435_456,
            macAddress: "02:ce:00:00:00:23",
            socketPath: socketPath,
            logPath: root.appending(path: "shim.log").path
        )
        let launch = Task {
            try await VMShimClient.launch(
                specification: specification,
                executable: executable,
                cleanupPartialProcess: { _ in throw Failure.injectedCleanup }
            )
        }
        try await Task.sleep(for: .milliseconds(100))
        launch.cancel()

        let failure: VMShimLaunchRollbackIncompleteError
        do {
            _ = try await launch.value
            Issue.record("expected interrupted launch cleanup failure")
            return
        } catch let error as VMShimLaunchRollbackIncompleteError {
            failure = error
        }
        let processIdentifier = try #require(failure.client.ownedProcessIdentifier)
        #expect(VMShimClient.processStartTime(for: processIdentifier) != nil)
        #expect(failure.message.contains("partial shim cleanup failed"))

        try await failure.client.terminate(
            gracePeriodMilliseconds: 0, forceWaitMilliseconds: 1_000
        )
        #expect(VMShimClient.processStartTime(for: processIdentifier) == nil)
        #expect(!FileManager.default.fileExists(atPath: socketPath))
        #expect(!FileManager.default.fileExists(atPath: socketPath + ".status"))
        try FileManager.default.removeItem(at: VMShimClient.specificationURL(for: specification))
        #expect(!FileManager.default.fileExists(
            atPath: VMShimClient.specificationURL(for: specification).path
        ))
    }

    @Test func persistentLaunchOwnershipRequiresExactExecutableAndPairedArguments() {
        let identity = VMShimClient.ProcessIdentity(
            processIdentifier: 4_321, startTime: 99
        )
        let executable = "/usr/local/bin/cengine"
        let specification = URL(filePath: "/private/var/run/generation/spec.json")
        let intent = URL(filePath: "/private/var/run/generation/intent.json")
        func inspection(_ arguments: [String], executablePath: String = executable)
            -> VMShimClient.ProcessInspection {
            .init(
                identityBefore: identity,
                executablePath: executablePath,
                arguments: arguments,
                identityAfter: identity
            )
        }
        let valid = [
            executable, "vm-shim", "--spec", "/var/run/generation/spec.json",
            "--launch-intent", "/var/run/generation/intent.json",
        ]
        #expect(VMShimClient.launchInspectionMatches(
            inspection(valid),
            intentURL: intent,
            specificationURL: specification,
            executablePath: executable
        ))
        let invalidArguments = [
            Array(valid.dropLast()) + ["/unrelated/intent.json"],
            [
                executable, "vm-shim", "--spec", specification.path,
                "--spec", intent.path,
            ],
            [
                executable, "vm-shim", specification.path, "--spec",
                "--launch-intent", intent.path,
            ],
            valid + ["--extra", intent.path],
        ]
        for arguments in invalidArguments {
            #expect(!VMShimClient.launchInspectionMatches(
                inspection(arguments),
                intentURL: intent,
                specificationURL: specification,
                executablePath: executable
            ))
        }
        #expect(!VMShimClient.launchInspectionMatches(
            inspection(valid, executablePath: "/usr/bin/unrelated"),
            intentURL: intent,
            specificationURL: specification,
            executablePath: executable
        ))
        var wrongArgvZero = valid
        wrongArgvZero[0] = "/usr/bin/unrelated"
        #expect(!VMShimClient.launchInspectionMatches(
            inspection(wrongArgvZero),
            intentURL: intent,
            specificationURL: specification,
            executablePath: executable
        ))
    }

    @Test func persistentLaunchPathsAndArgumentTuplesAreLexicallyExact() {
        #expect(VMShimClient.launchPathsMatch(
            "/private/var/run/cengine/spec.json", "/var/run/cengine/spec.json"
        ))
        #expect(!VMShimClient.launchPathsMatch("relative/spec.json", "/relative/spec.json"))
        #expect(!VMShimClient.launchPathsMatch("/tmp/./spec.json", "/tmp/spec.json"))
        #expect(!VMShimClient.launchPathsMatch("/tmp/a/../spec.json", "/tmp/spec.json"))
        #expect(!VMShimClient.launchPathsMatch("/tmp//spec.json", "/tmp/spec.json"))
        #expect(!VMShimClient.launchPathsMatch("/tmp/%73pec.json", "/tmp/spec.json"))
        #expect(!VMShimClient.launchPathsMatch("/private/variable/a", "/variable/a"))
        #expect(!VMShimClient.launchPathsMatch("/tmp/é", "/tmp/e\u{301}"))

        let identity = VMShimClient.ProcessIdentity(
            processIdentifier: 7_777, startTime: 18
        )
        let executable = "/usr/local/bin/cengine"
        let specification = URL(filePath: "/var/run/cengine/spec.json")
        let intent = URL(filePath: "/var/run/cengine/intent.json")
        let reordered = VMShimClient.ProcessInspection(
            identityBefore: identity,
            executablePath: executable,
            arguments: [
                executable, "vm-shim", "--launch-intent", intent.path,
                "--spec", specification.path,
            ],
            identityAfter: identity
        )
        #expect(!VMShimClient.launchInspectionMatches(
            reordered,
            intentURL: intent,
            specificationURL: specification,
            executablePath: executable
        ))
    }

    @Test func kernProcArgumentsHonorArgcAndPreserveEmptyEntries() {
        func encoded(
            _ arguments: [String], reportedCount: CInt? = nil,
            executable: String = "/usr/local/bin/cengine",
            environment: [String] = ["PATH=/usr/bin"],
            pointerSize: Int = 8
        ) -> [UInt8] {
            var count = reportedCount ?? CInt(arguments.count)
            var bytes: [UInt8] = []
            withUnsafeBytes(of: &count) { bytes.append(contentsOf: $0) }
            bytes.append(contentsOf: executable.utf8)
            bytes.append(0)
            let padding = (pointerSize - ((executable.utf8.count + 1) % pointerSize))
                % pointerSize
            bytes.append(contentsOf: repeatElement(0, count: padding))
            for argument in arguments {
                bytes.append(contentsOf: argument.utf8)
                bytes.append(0)
            }
            for value in environment {
                bytes.append(contentsOf: value.utf8)
                bytes.append(0)
            }
            bytes.append(contentsOf: repeatElement(0, count: 8))
            return bytes
        }

        let arguments = ["/usr/local/bin/cengine", "vm-shim", "", "tail", ""]
        #expect(VMShimClient.parseProcessArguments(encoded(arguments), pointerSize: 8) == arguments)
        let leadingEmpty = ["", "vm-shim", "--launch-intent", "/i", "--spec", "/s"]
        #expect(VMShimClient.parseProcessArguments(
            encoded(leadingEmpty, executable: "/x"), pointerSize: 8
        ) == leadingEmpty)
        #expect(VMShimClient.parseProcessArguments(
            encoded([], environment: []), pointerSize: 8
        ) == [])
        #expect(VMShimClient.parseProcessArguments(
            encoded(arguments, executable: "/123456", environment: [], pointerSize: 4),
            pointerSize: 4
        ) == arguments)
        #expect(VMShimClient.parseProcessArguments(
            encoded(arguments, reportedCount: CInt(arguments.count + 1)), pointerSize: 8
        ) != arguments)
        #expect(VMShimClient.parseProcessArguments(
            encoded(arguments, environment: ["malformed-environment"]), pointerSize: 8
        ) == nil)
        var malformedPadding = encoded(arguments, executable: "/x")
        malformedPadding[MemoryLayout<CInt>.size + 3] = 0x41
        #expect(VMShimClient.parseProcessArguments(malformedPadding, pointerSize: 8) == nil)
        #expect(VMShimClient.parseProcessArguments(
            Array(encoded(arguments).dropLast(16)), pointerSize: 8
        ) == nil)
    }

    @Test func processEnumerationGrowsWhenTheKernelFillsTheBuffer() {
        let expected = (1...40).map(CInt.init)
        var requestedCapacities: [Int] = []
        let scan = VMShimClient.enumerateProcessIdentifiers { buffer, capacity in
            requestedCapacities.append(capacity)
            guard let buffer else { return 2 }
            let count = min(capacity, expected.count)
            for index in 0..<count { buffer[index] = expected[index] }
            return Int32(count)
        }

        #expect(scan == .complete(expected))
        #expect(requestedCapacities == [0, 34, 68])
        #expect(VMShimClient.enumerateProcessIdentifiers { _, _ in -1 } == .failed)
    }

    @Test func incompleteProcessScansQuarantineUnpublishedLaunchIntent() throws {
        func verify(
            _ scan: VMShimClient.ProcessIdentifierScan,
            name: String
        ) throws {
            let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
            let containerURL = root.appending(path: "containers/\(name)")
            let generationsURL = containerURL.appending(path: "shim-generations")
            try FileManager.default.createDirectory(
                at: containerURL, withIntermediateDirectories: true
            )
            defer { try? FileManager.default.removeItem(at: root) }
            let container = ContainerRecord(id: name, name: name, image: "alpine")
            let specification = VMShimProtocol.Specification(
                containerID: name, generation: 1, token: "scan-token",
                kernelPath: "/kernel", initialRamdiskPath: "/initramfs",
                rootDiskPath: containerURL.appending(path: "root.ext4").path,
                cpus: 1, memoryBytes: 268_435_456,
                macAddress: "02:ce:00:00:00:41",
                socketPath: "/tmp/\(name).sock",
                logPath: containerURL.appending(path: "shim.log").path
            )
            let files = try VMShimClient.preparePersistentSpawn(
                specification: specification,
                container: container,
                generationsDirectory: generationsURL,
                executable: URL(filePath: "/usr/bin/yes")
            )

            let launches = try VMShimClient.persistedLaunches(
                in: PersistentStateDirectory.open(containerURL),
                expectedContainerID: name,
                expectedExecutable: URL(filePath: "/usr/bin/yes"),
                processIdentifiersProvider: { scan }
            )
            #expect(launches.isEmpty)
            #expect(launches.quarantined.count == 1)
            #expect(launches.quarantined.first?.reason.contains("process enumeration") == true)
            #expect(FileManager.default.fileExists(atPath: files.directory.path))
        }

        try verify(.incomplete([]), name: "truncated-scan")
        try verify(.failed, name: "failed-scan")
    }

    @Test func persistentLaunchPublicationRejectsPIDReuseAtEveryObservationBoundary() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerDirectory = root.appending(path: "containers/identity-boundary")
        let generations = RawVirtualizationBackend.generationsDirectory(for: containerDirectory)
        try FileManager.default.createDirectory(at: containerDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let container = ContainerRecord(
            id: "identity-boundary", name: "identity-boundary", image: "alpine"
        )
        let executable = URL(filePath: "/usr/bin/yes")
        func makeSpecification(_ generation: UInt64) throws -> VMShimProtocol.Specification {
            VMShimProtocol.Specification(
                containerID: container.id,
                generation: generation,
                token: "identity-\(generation)",
                kernelPath: "/kernel",
                initialRamdiskPath: "/initramfs",
                rootDiskPath: containerDirectory.appending(path: "root.ext4").path,
                cpus: 1,
                memoryBytes: 268_435_456,
                macAddress: "02:ce:00:00:00:31",
                socketPath: try RawVirtualizationBackend.makeRuntimeSocketPath(),
                logPath: containerDirectory.appending(path: "shim.log").path
            )
        }
        let expected = VMShimClient.ProcessIdentity(
            processIdentifier: 4_321, startTime: 10
        )
        let reused = VMShimClient.ProcessIdentity(
            processIdentifier: 4_321, startTime: 11
        )

        let beforeWrite = try VMShimClient.preparePersistentSpawn(
            specification: makeSpecification(31),
            container: container,
            generationsDirectory: generations,
            executable: executable
        )
        let inspection = VMShimClient.ProcessInspection(
            identityBefore: expected,
            executablePath: executable.path,
            arguments: [
                executable.path, "vm-shim", "--spec", beforeWrite.specificationURL.path,
                "--launch-intent", beforeWrite.intentURL.path,
            ],
            identityAfter: expected
        )
        var beforeWriteObservations = 0
        #expect(throws: EngineError.self) {
            try VMShimClient.publishPersistentLaunchIdentity(
                intentURL: beforeWrite.intentURL,
                expectedIdentity: expected,
                identityProvider: { _ in
                    beforeWriteObservations += 1
                    return beforeWriteObservations == 1 ? expected : reused
                },
                inspectionProvider: { _ in inspection }
            )
        }
        #expect(!FileManager.default.fileExists(atPath: beforeWrite.recordURL.path))

        let afterWrite = try VMShimClient.preparePersistentSpawn(
            specification: makeSpecification(32),
            container: container,
            generationsDirectory: generations,
            executable: executable
        )
        let afterInspection = VMShimClient.ProcessInspection(
            identityBefore: expected,
            executablePath: executable.path,
            arguments: [
                executable.path, "vm-shim", "--spec", afterWrite.specificationURL.path,
                "--launch-intent", afterWrite.intentURL.path,
            ],
            identityAfter: expected
        )
        var afterWriteObservations = 0
        #expect(throws: EngineError.self) {
            try VMShimClient.publishPersistentLaunchIdentity(
                intentURL: afterWrite.intentURL,
                expectedIdentity: expected,
                identityProvider: { _ in
                    afterWriteObservations += 1
                    return afterWriteObservations <= 2 ? expected : reused
                },
                inspectionProvider: { _ in afterInspection }
            )
        }
        let durable = try JSONDecoder().decode(
            VMShimClient.PersistentLaunchRecord.self,
            from: Data(contentsOf: afterWrite.recordURL)
        )
        #expect(durable.processIdentifier == expected.processIdentifier)
        #expect(durable.processStartTime == expected.startTime)
    }

    @Test func persistedShimRecoveryClosesCrashImmediatelyAfterProcessRun() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerDirectory = root.appending(path: "containers/crash-window")
        let generations = RawVirtualizationBackend.generationsDirectory(for: containerDirectory)
        try FileManager.default.createDirectory(at: containerDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let rootDisk = containerDirectory.appending(path: "root.ext4")
        try Data("writable-root".utf8).write(to: rootDisk)
        let executable = try buildArgumentPreservingIdleExecutable(in: root)

        var container = ContainerRecord(
            id: "crash-window", name: "crash-window", image: "alpine"
        )
        container.cpus = 2
        container.memoryBytes = 384 * 1_024 * 1_024
        let specification = VMShimProtocol.Specification(
            containerID: container.id,
            generation: 41,
            token: "pre-spawn-intent-token",
            kernelPath: "/kernel",
            initialRamdiskPath: "/initramfs",
            rootDiskPath: rootDisk.path,
            cpus: 2,
            memoryBytes: 512 * 1_024 * 1_024,
            macAddress: "02:ce:00:00:00:41",
            socketPath: try RawVirtualizationBackend.makeRuntimeSocketPath(),
            logPath: containerDirectory.appending(path: "shim.log").path
        )
        let files = try VMShimClient.preparePersistentSpawn(
            specification: specification,
            container: container,
            generationsDirectory: generations,
            executable: executable
        )
        #expect(!FileManager.default.fileExists(atPath: files.recordURL.path))

        // This deliberately bypasses the parent's post-Process.run publisher,
        // reproducing the exact crash window. Recovery must adopt from the
        // unique pre-spawn intent argument rather than lose ownership.
        let process = Process()
        process.executableURL = executable
        process.arguments = [
            "vm-shim", "--spec", files.specificationURL.path,
            "--launch-intent", files.intentURL.path,
        ]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        Thread.detachNewThread { process.waitUntilExit() }

        let launchedStartTime = try #require(
            VMShimClient.processStartTime(for: process.processIdentifier)
        )
        let launchedIdentity = VMShimClient.ProcessIdentity(
            processIdentifier: process.processIdentifier,
            startTime: launchedStartTime
        )
        let launchedInspection = try #require(VMShimClient.inspectProcess(
            process.processIdentifier,
            identityProvider: { _ in launchedIdentity }
        ))
        #expect(VMShimClient.launchInspectionMatches(
            launchedInspection,
            intentURL: files.intentURL,
            specificationURL: files.specificationURL,
            executablePath: executable.resolvingSymlinksInPath().path
        ), "observed executable=\(launchedInspection.executablePath) argv=\(launchedInspection.arguments)")

        let recovered = try VMShimClient.persistedLaunches(
            in: generations,
            expectedContainerID: container.id,
            expectedExecutable: executable
        )
        let launch = try #require(recovered.first)
        #expect(recovered.count == 1)
        #expect(launch.record.processIdentifier == process.processIdentifier)
        #expect(launch.record.container.cpus == container.cpus)
        #expect(FileManager.default.fileExists(atPath: files.recordURL.path))

        try await launch.client.terminate(
            gracePeriodMilliseconds: 0, forceWaitMilliseconds: 1_000
        )
        try launch.client.removePersistentLaunchArtifacts()
        #expect(VMShimClient.processStartTime(for: process.processIdentifier) == nil)
        #expect(try Data(contentsOf: rootDisk) == Data("writable-root".utf8))
        #expect((try? FileManager.default.contentsOfDirectory(atPath: generations.path))?.isEmpty != false)
    }

    @Test func persistedShimIdentityDoesNotSignalAReusedPID() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerDirectory = root.appending(path: "containers/pid-reuse")
        let generations = RawVirtualizationBackend.generationsDirectory(for: containerDirectory)
        try FileManager.default.createDirectory(at: containerDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let rootDisk = containerDirectory.appending(path: "root.ext4")
        let container = ContainerRecord(id: "pid-reuse", name: "pid-reuse", image: "alpine")
        let specification = VMShimProtocol.Specification(
            containerID: container.id,
            generation: 7,
            token: "stale-generation-token",
            kernelPath: "/kernel",
            initialRamdiskPath: "/initramfs",
            rootDiskPath: rootDisk.path,
            cpus: 1,
            memoryBytes: 268_435_456,
            macAddress: "02:ce:00:00:00:07",
            socketPath: try RawVirtualizationBackend.makeRuntimeSocketPath(),
            logPath: containerDirectory.appending(path: "shim.log").path
        )
        let files = try VMShimClient.preparePersistentSpawn(
            specification: specification,
            container: container,
            generationsDirectory: generations,
            executable: URL(filePath: "/usr/bin/yes")
        )
        let intent = try JSONDecoder().decode(
            VMShimClient.PersistentLaunchIntent.self,
            from: Data(contentsOf: files.intentURL)
        )
        let unrelated = Process()
        unrelated.executableURL = URL(filePath: "/bin/sleep")
        unrelated.arguments = ["30"]
        try unrelated.run()
        defer { if unrelated.isRunning { unrelated.terminate() } }
        Thread.detachNewThread { unrelated.waitUntilExit() }
        let actualStart = try #require(
            VMShimClient.processStartTime(for: unrelated.processIdentifier)
        )
        let stale = VMShimClient.PersistentLaunchRecord(
            nonce: intent.nonce,
            createdAt: intent.createdAt,
            specificationPath: files.specificationURL.path,
            executablePath: intent.executablePath,
            containerDirectoryIdentity: intent.containerDirectoryIdentity,
            generationsDirectoryIdentity: intent.generationsDirectoryIdentity,
            generationDirectoryIdentity: files.directoryIdentity,
            specification: specification,
            processIdentifier: unrelated.processIdentifier,
            processStartTime: actualStart &+ 1,
            container: container
        )
        try JSONEncoder().encode(stale).write(to: files.recordURL)
        let statusURL = URL(filePath: specification.socketPath + ".status")
        let publication = try VMShimClient.preparePersistentRuntimeArtifacts(
            intentURL: files.intentURL,
            socketPaths: [specification.socketPath],
            statusPath: statusURL.path
        )
        let originalListener = try UnixSocket.listen(
            path: publication.stagedPath(for: specification.socketPath)
        )
        try Data("owned-status".utf8).write(
            to: URL(filePath: publication.stagedPath(for: statusURL.path))
        )
        _ = try VMShimClient.publishPersistentRuntimeArtifacts(publication)
        Darwin.close(originalListener)
        let reboundListener = try UnixSocket.listen(path: specification.socketPath)
        defer { Darwin.close(reboundListener) }
        let reboundStatus = Data("rebound-status".utf8)
        try reboundStatus.write(to: statusURL, options: .atomic)

        let recovered = try VMShimClient.persistedLaunches(
            in: generations,
            expectedContainerID: container.id,
            expectedExecutable: URL(filePath: "/usr/bin/yes")
        )
        let client = try #require(recovered.first?.client)
        await #expect(throws: PersistentRuntimeArtifactOwnershipUnresolvedError.self) {
            try await client.terminate(
                gracePeriodMilliseconds: 0, forceWaitMilliseconds: 50
            )
        }
        #expect(throws: PersistentRuntimeArtifactOwnershipUnresolvedError.self) {
            try client.removePersistentLaunchArtifacts()
        }

        #expect(unrelated.isRunning)
        #expect(VMShimClient.processStartTime(for: unrelated.processIdentifier) == actualStart)
        #expect(FileManager.default.fileExists(atPath: specification.socketPath))
        #expect(try Data(contentsOf: statusURL) == reboundStatus)
        #expect(FileManager.default.fileExists(atPath: files.intentURL.path))
        let reboundConnection = try UnixSocket.connect(path: specification.socketPath)
        Darwin.close(reboundConnection)
    }

    @Test func persistentStateReadsRejectLinksPipesOversizeAndPathReplacement() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let stateURL = root.appending(path: "state")
        try FileManager.default.createDirectory(at: stateURL, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let state = try PersistentStateDirectory.open(stateURL)

        let target = root.appending(path: "target")
        try Data("target".utf8).write(to: target)
        try FileManager.default.createSymbolicLink(
            at: stateURL.appending(path: "linked"), withDestinationURL: target
        )
        #expect(throws: POSIXError.self) {
            try state.readRegularFile(named: "linked")
        }

        let fifo = stateURL.appending(path: "pipe")
        #expect(Darwin.mkfifo(fifo.path, mode_t(0o600)) == 0)
        #expect(throws: EngineError.self) {
            try state.readRegularFile(named: "pipe")
        }

        try Data(
            repeating: 0x41,
            count: PersistentStateDirectory.maximumStateBytes + 1
        ).write(to: stateURL.appending(path: "oversized"))
        #expect(throws: EngineError.self) {
            try state.readRegularFile(named: "oversized")
        }

        try Data("held-directory".utf8).write(to: stateURL.appending(path: "stable"))
        let moved = root.appending(path: "moved-state")
        try FileManager.default.moveItem(at: stateURL, to: moved)
        try FileManager.default.createDirectory(at: stateURL, withIntermediateDirectories: false)
        try Data("replacement".utf8).write(to: stateURL.appending(path: "stable"))
        #expect(try state.readRegularFile(named: "stable") == Data("held-directory".utf8))
        #expect(!state.pathStillNamesThisDirectory())

        let directoryLink = root.appending(path: "directory-link")
        try FileManager.default.createSymbolicLink(at: directoryLink, withDestinationURL: moved)
        #expect(throws: POSIXError.self) {
            try PersistentStateDirectory.open(directoryLink)
        }
    }

    @Test func missingContainerStateIsTreatedAsAFreshPrepare() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containersURL = root.appending(path: "containers")
        try FileManager.default.createDirectory(
            at: containersURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let containers = try PersistentStateDirectory.open(containersURL)

        let acquisition = try RawFreshContainerStateCoordinator.acquire(
            in: containers, containerID: "new-container"
        )
        #expect(acquisition.wasCreated)
        #expect(acquisition.directory.pathStillNamesThisDirectory())

        let artifacts = try RawContainerPreparationArtifacts.create(
            in: acquisition.directory, rootDiskSize: 4_096
        )
        try artifacts.validate(in: acquisition.directory)
        #expect(
            try acquisition.directory.regularFileIdentity(named: "root.ext4")
                == artifacts.rootDiskIdentity
        )
    }

    @Test func existingUnpreparedWritableRootIsDisposedInsteadOfAdopted() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containersURL = root.appending(path: "containers")
        let containerURL = containersURL.appending(path: "stale")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        let staleData = Data("stale-writable-root".utf8)
        try staleData.write(to: containerURL.appending(path: "root.ext4"))
        defer { try? FileManager.default.removeItem(at: root) }
        let containers = try PersistentStateDirectory.open(containersURL)

        let acquisition = try RawFreshContainerStateCoordinator.acquire(
            in: containers, containerID: "stale"
        )
        #expect(!acquisition.wasCreated)
        let staleDirectoryIdentity = acquisition.directory.identity
        let staleRootIdentity = try acquisition.directory.regularFileIdentity(
            named: "root.ext4"
        )
        let heldStaleRoot = Darwin.open(
            containerURL.appending(path: "root.ext4").path,
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC
        )
        #expect(heldStaleRoot >= 0)
        defer { if heldStaleRoot >= 0 { Darwin.close(heldStaleRoot) } }

        // Production reaches this boundary only after its persisted/live shim
        // ownership scan proves the markerless directory is unclaimed.
        let replacement = try RawFreshContainerStateCoordinator.recreateUnclaimed(
            in: containers,
            containerID: "stale",
            existing: acquisition.directory
        )
        #expect(replacement.identity != staleDirectoryIdentity)
        let artifacts = try RawContainerPreparationArtifacts.create(
            in: replacement, rootDiskSize: 4_096
        )
        #expect(artifacts.rootDiskIdentity != staleRootIdentity)
        #expect(
            try Data(contentsOf: containerURL.appending(path: "root.ext4"))
                == Data(repeating: 0, count: 4_096)
        )
    }

    @Test func freshWritableRootCreationRejectsSymlinkWithoutFollowingIt() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containersURL = root.appending(path: "containers")
        try FileManager.default.createDirectory(
            at: containersURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let sentinel = root.appending(path: "outside-root")
        let sentinelData = Data("must-not-be-truncated".utf8)
        try sentinelData.write(to: sentinel)
        let containers = try PersistentStateDirectory.open(containersURL)
        let acquisition = try RawFreshContainerStateCoordinator.acquire(
            in: containers, containerID: "symlink"
        )
        try FileManager.default.createSymbolicLink(
            at: acquisition.directory.url.appending(path: "root.ext4"),
            withDestinationURL: sentinel
        )

        #expect(throws: POSIXError.self) {
            try RawContainerPreparationArtifacts.create(
                in: acquisition.directory, rootDiskSize: 4_096
            )
        }
        #expect(try Data(contentsOf: sentinel) == sentinelData)
        #expect(
            try acquisition.directory.entryMetadata(named: "root.ext4")?.type
                == S_IFLNK
        )
    }

    @Test func freshStateReplacementRecoversInterruptedDisposalBeforeReuse() throws {
        enum SimulatedCrash: Error { case injected }
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containersURL = root.appending(path: "containers")
        let containerURL = containersURL.appending(path: "interrupted")
        try FileManager.default.createDirectory(
            at: containerURL.appending(path: "nested"),
            withIntermediateDirectories: true
        )
        try Data("stale".utf8).write(
            to: containerURL.appending(path: "nested/sentinel")
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let containers = try PersistentStateDirectory.open(containersURL)
        let existing = try containers.openDirectory(named: "interrupted")
        var injected = false

        #expect(throws: SimulatedCrash.self) {
            try RawFreshContainerStateCoordinator.recreateUnclaimed(
                in: containers,
                containerID: "interrupted",
                existing: existing,
                hook: { boundary in
                    guard boundary == .rootClaimed, !injected else { return }
                    injected = true
                    throw SimulatedCrash.injected
                }
            )
        }
        #expect(injected)
        let restarted = try PersistentStateDirectory.open(containersURL)
        #expect(
            try restarted.pendingDisposalIdentity(named: "interrupted")
                == existing.identity
        )

        let recovered = try RawFreshContainerStateCoordinator.acquire(
            in: restarted, containerID: "interrupted"
        )
        #expect(recovered.wasCreated)
        #expect(recovered.directory.identity != existing.identity)
        #expect(!FileManager.default.fileExists(
            atPath: containerURL.appending(path: "nested/sentinel").path
        ))
        _ = try RawContainerPreparationArtifacts.create(
            in: recovered.directory, rootDiskSize: 4_096
        )
    }

    @Test func descriptorOwnedDisposalNeverDeletesAncestorReplacementsOrRenamedPeers() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containers = root.appending(path: "containers")
        let originalA = containers.appending(path: "a")
        try FileManager.default.createDirectory(at: originalA, withIntermediateDirectories: true)
        try Data("owned-a".utf8).write(to: originalA.appending(path: "sentinel"))
        defer { try? FileManager.default.removeItem(at: root) }

        let heldContainers = try PersistentStateDirectory.open(containers)
        let identityA = try heldContainers.openDirectory(named: "a").identity
        let relocated = root.appending(path: "relocated-containers")
        try FileManager.default.moveItem(at: containers, to: relocated)
        let replacementA = containers.appending(path: "a")
        try FileManager.default.createDirectory(at: replacementA, withIntermediateDirectories: true)
        try Data("replacement-a".utf8).write(
            to: replacementA.appending(path: "sentinel")
        )

        try heldContainers.disposeDirectory(named: "a", expectedIdentity: identityA)
        #expect(try Data(contentsOf: replacementA.appending(path: "sentinel"))
            == Data("replacement-a".utf8))
        #expect(!FileManager.default.fileExists(
            atPath: relocated.appending(path: "a").path
        ))

        let symlinkOwned = relocated.appending(path: "symlink-owned")
        try FileManager.default.createDirectory(
            at: symlinkOwned, withIntermediateDirectories: false
        )
        try Data("held".utf8).write(to: symlinkOwned.appending(path: "sentinel"))
        let symlinkOwnedIdentity = try heldContainers.openDirectory(
            named: "symlink-owned"
        ).identity
        try FileManager.default.removeItem(at: containers)
        let decoy = root.appending(path: "decoy-containers")
        let decoyOwned = decoy.appending(path: "symlink-owned")
        try FileManager.default.createDirectory(at: decoyOwned, withIntermediateDirectories: true)
        try Data("decoy".utf8).write(to: decoyOwned.appending(path: "sentinel"))
        try FileManager.default.createSymbolicLink(at: containers, withDestinationURL: decoy)

        try heldContainers.disposeDirectory(
            named: "symlink-owned", expectedIdentity: symlinkOwnedIdentity
        )
        #expect(try Data(contentsOf: decoyOwned.appending(path: "sentinel"))
            == Data("decoy".utf8))

        let renamedA = relocated.appending(path: "renamed-a")
        try FileManager.default.createDirectory(
            at: renamedA, withIntermediateDirectories: false
        )
        try Data("renamed-owner".utf8).write(to: renamedA.appending(path: "sentinel"))
        let renamedIdentity = try heldContainers.openDirectory(named: "renamed-a").identity
        let peerB = relocated.appending(path: "b")
        try FileManager.default.moveItem(at: renamedA, to: peerB)
        try FileManager.default.createDirectory(
            at: renamedA, withIntermediateDirectories: false
        )
        try Data("new-a".utf8).write(to: renamedA.appending(path: "sentinel"))

        #expect(throws: EngineError.self) {
            try heldContainers.disposeDirectory(
                named: "renamed-a", expectedIdentity: renamedIdentity
            )
        }
        #expect(try Data(contentsOf: peerB.appending(path: "sentinel"))
            == Data("renamed-owner".utf8))
        #expect(try Data(contentsOf: renamedA.appending(path: "sentinel"))
            == Data("new-a".utf8))
    }

    @Test func persistentDirectoryEnumerationAlwaysStartsAtTheBeginning() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try Data("a".utf8).write(to: root.appending(path: "alpha"))
        try Data("b".utf8).write(to: root.appending(path: "beta"))
        let directory = try PersistentStateDirectory.open(root)

        #expect(try directory.entryNames() == ["alpha", "beta"])
        #expect(try directory.entryNames() == ["alpha", "beta"])
        #expect(try directory.reconciledEntryNames() == ["alpha", "beta"])
        #expect(try directory.reconciledEntryNames() == ["alpha", "beta"])
    }

    @Test func disposalJournalRecoversEveryDurabilityBoundary() throws {
        enum SimulatedCrash: Error { case injected }
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let parent = try PersistentStateDirectory.open(root)

        for boundary in PersistentDisposalBoundary.allCases {
            let targetName = "target-\(boundary.rawValue)"
            let target = root.appending(path: targetName)
            try FileManager.default.createDirectory(
                at: target.appending(path: "nested"), withIntermediateDirectories: true
            )
            try Data("owned".utf8).write(
                to: target.appending(path: "nested/sentinel")
            )
            let identity = try parent.openDirectory(named: targetName).identity
            var injected = false
            do {
                try parent.disposeDirectory(
                    named: targetName,
                    expectedIdentity: identity,
                    hook: { observed in
                        guard observed == boundary, !injected else { return }
                        injected = true
                        throw SimulatedCrash.injected
                    }
                )
            } catch SimulatedCrash.injected {}
            #expect(injected, "boundary was not exercised: \(boundary.rawValue)")

            let restarted = try PersistentStateDirectory.open(root)
            try restarted.reconcileDisposals()
            #expect(!FileManager.default.fileExists(atPath: target.path))
            #expect(try restarted.pendingDisposalIdentity(named: targetName) == nil)
            #expect(try restarted.reconciledEntryNames().isEmpty)
            #expect(try restarted.reconciledEntryNames().isEmpty)
        }
    }

    @Test func recursiveDisposalRejectsSwapsAndNeverFollowsSpecialEntries() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let target = root.appending(path: "target")
        let child = target.appending(path: "child")
        let decoy = root.appending(path: "decoy")
        try FileManager.default.createDirectory(at: child, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: decoy, withIntermediateDirectories: false)
        try Data("owned".utf8).write(to: child.appending(path: "sentinel"))
        try Data("decoy".utf8).write(to: decoy.appending(path: "sentinel"))
        defer { try? FileManager.default.removeItem(at: root) }
        let parent = try PersistentStateDirectory.open(root)
        let identity = try parent.openDirectory(named: "target").identity
        var swapped = false

        #expect(throws: EngineError.self) {
            try parent.disposeDirectory(
                named: "target", expectedIdentity: identity,
                hook: { boundary in
                    guard boundary == .childClaimed, !swapped else { return }
                    let rootClaimName = try #require(parent.entryNames().first {
                        $0.hasPrefix(".cengine-disposal-claim-")
                    })
                    let rootClaim = try parent.openDirectory(named: rootClaimName)
                    let childClaimName = try #require(rootClaim.entryNames().first {
                        $0.hasPrefix(".cengine-entry-claim-")
                    })
                    guard Darwin.renameat(
                        rootClaim.descriptor, childClaimName, parent.descriptor, "escaped"
                    ) == 0,
                    Darwin.renameat(
                        parent.descriptor, "decoy", rootClaim.descriptor, childClaimName
                    ) == 0 else {
                        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                    }
                    swapped = true
                }
            )
        }
        #expect(swapped)
        #expect(try Data(contentsOf: root.appending(path: "target/child/sentinel"))
            == Data("decoy".utf8))
        #expect(try Data(contentsOf: root.appending(path: "escaped/sentinel"))
            == Data("owned".utf8))
        #expect(try parent.pendingDisposalIdentity(named: "target") == nil)

        let preclaimTarget = root.appending(path: "preclaim")
        try FileManager.default.createDirectory(
            at: preclaimTarget, withIntermediateDirectories: false
        )
        try Data("preclaim-owned".utf8).write(
            to: preclaimTarget.appending(path: "sentinel")
        )
        let preclaimIdentity = try parent.openDirectory(named: "preclaim").identity
        var replacedBeforeClaim = false
        #expect(throws: EngineError.self) {
            try parent.disposeDirectory(
                named: "preclaim", expectedIdentity: preclaimIdentity,
                hook: { boundary in
                    guard boundary == .journalDirectorySynchronized,
                          !replacedBeforeClaim else { return }
                    guard Darwin.renameat(
                        parent.descriptor, "preclaim", parent.descriptor, "preclaim-escaped"
                    ) == 0,
                    Darwin.mkdirat(parent.descriptor, "preclaim", 0o700) == 0 else {
                        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                    }
                    try Data("preclaim-decoy".utf8).write(
                        to: preclaimTarget.appending(path: "sentinel")
                    )
                    replacedBeforeClaim = true
                }
            )
        }
        #expect(replacedBeforeClaim)
        #expect(try Data(contentsOf: root.appending(path: "preclaim/sentinel"))
            == Data("preclaim-decoy".utf8))
        #expect(try Data(contentsOf: root.appending(path: "preclaim-escaped/sentinel"))
            == Data("preclaim-owned".utf8))
        #expect(try parent.pendingDisposalIdentity(named: "preclaim") == nil)

        let rootSwapTarget = root.appending(path: "root-swap")
        let rootSwapDecoy = root.appending(path: "root-decoy")
        try FileManager.default.createDirectory(
            at: rootSwapTarget, withIntermediateDirectories: false
        )
        try FileManager.default.createDirectory(
            at: rootSwapDecoy, withIntermediateDirectories: false
        )
        try Data("owned-root".utf8).write(
            to: rootSwapTarget.appending(path: "sentinel")
        )
        try Data("decoy-root".utf8).write(
            to: rootSwapDecoy.appending(path: "sentinel")
        )
        let rootSwapIdentity = try parent.openDirectory(named: "root-swap").identity
        var rootSwapped = false
        #expect(throws: EngineError.self) {
            try parent.disposeDirectory(
                named: "root-swap", expectedIdentity: rootSwapIdentity,
                hook: { boundary in
                    guard boundary == .rootClaimed, !rootSwapped else { return }
                    let claim = try #require(parent.entryNames().first {
                        $0.hasPrefix(".cengine-disposal-claim-")
                    })
                    guard Darwin.renameat(
                        parent.descriptor, claim, parent.descriptor, "escaped-root"
                    ) == 0,
                    Darwin.renameat(
                        parent.descriptor, "root-decoy", parent.descriptor, claim
                    ) == 0 else {
                        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                    }
                    rootSwapped = true
                }
            )
        }
        #expect(rootSwapped)
        #expect(try Data(contentsOf: root.appending(path: "root-swap/sentinel"))
            == Data("decoy-root".utf8))
        #expect(try Data(contentsOf: root.appending(path: "escaped-root/sentinel"))
            == Data("owned-root".utf8))
        #expect(try parent.pendingDisposalIdentity(named: "root-swap") == nil)

        let safeTarget = root.appending(path: "special")
        let outside = root.appending(path: "outside")
        try FileManager.default.createDirectory(at: safeTarget, withIntermediateDirectories: false)
        try Data("outside".utf8).write(to: outside)
        try FileManager.default.createSymbolicLink(
            at: safeTarget.appending(path: "cycle"),
            withDestinationURL: safeTarget
        )
        try FileManager.default.createSymbolicLink(
            at: safeTarget.appending(path: "outside-link"),
            withDestinationURL: outside
        )
        #expect(Darwin.mkfifo(safeTarget.appending(path: "fifo").path, 0o600) == 0)
        let safeIdentity = try parent.openDirectory(named: "special").identity
        try parent.disposeDirectory(named: "special", expectedIdentity: safeIdentity)
        #expect(try Data(contentsOf: outside) == Data("outside".utf8))
    }

    @Test func persistedLaunchEnumerationReconcilesAClaimedGenerationFirst() throws {
        enum SimulatedCrash: Error { case claimed }
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerURL = root.appending(path: "container")
        let generationsURL = containerURL.appending(path: "shim-generations")
        let generationURL = generationsURL.appending(path: "generation")
        try FileManager.default.createDirectory(
            at: generationURL, withIntermediateDirectories: true
        )
        try Data("partial".utf8).write(to: generationURL.appending(path: "intent.json"))
        defer { try? FileManager.default.removeItem(at: root) }
        let generations = try PersistentStateDirectory.open(generationsURL)
        let identity = try generations.openDirectory(named: "generation").identity
        do {
            try generations.disposeDirectory(
                named: "generation", expectedIdentity: identity,
                hook: { boundary in
                    if boundary == .rootClaimed { throw SimulatedCrash.claimed }
                }
            )
        } catch SimulatedCrash.claimed {}

        let launches = try VMShimClient.persistedLaunches(
            in: PersistentStateDirectory.open(containerURL),
            expectedContainerID: "container",
            processIdentifiersProvider: { .complete([]) }
        )
        #expect(launches.isEmpty)
        #expect(try generations.reconciledEntryNames().isEmpty)
        #expect(try generations.reconciledEntryNames().isEmpty)
    }

    @Test func persistedLaunchRecoveryRetiresIncompletePreSpawnGenerations() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerURL = root.appending(path: "containers/partial")
        let generationsURL = containerURL.appending(path: "shim-generations")
        try FileManager.default.createDirectory(
            at: generationsURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let sibling = root.appending(path: "containers/sibling")
        try FileManager.default.createDirectory(at: sibling, withIntermediateDirectories: true)
        try Data("unrelated".utf8).write(to: sibling.appending(path: "sentinel"))

        func malformed(_ name: String, entry: String? = nil, data: Data = Data()) throws {
            let directory = generationsURL.appending(path: name)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
            if let entry { try data.write(to: directory.appending(path: entry)) }
        }
        try malformed("mkdir-only")
        try malformed("spec-only", entry: "spec.json", data: Data("{}".utf8))
        try malformed("zero-intent", entry: "intent.json")
        try malformed("truncated-intent", entry: "intent.json", data: Data("{".utf8))
        try malformed(
            "oversized-intent",
            entry: "intent.json",
            data: Data(repeating: 0x61, count: PersistentStateDirectory.maximumStateBytes + 1)
        )
        let intentLink = generationsURL.appending(path: "symlink-intent")
        try FileManager.default.createDirectory(at: intentLink, withIntermediateDirectories: false)
        try FileManager.default.createSymbolicLink(
            at: intentLink.appending(path: "intent.json"),
            withDestinationURL: sibling.appending(path: "sentinel")
        )

        let container = ContainerRecord(id: "partial", name: "partial", image: "alpine")
        func specification(_ generation: UInt64) -> VMShimProtocol.Specification {
            .init(
                containerID: container.id, generation: generation, token: "token-\(generation)",
                kernelPath: "/kernel", initialRamdiskPath: "/initramfs",
                rootDiskPath: containerURL.appending(path: "root.ext4").path,
                cpus: 1, memoryBytes: 268_435_456,
                macAddress: String(format: "02:ce:00:00:00:%02llx", generation),
                socketPath: "/tmp/partial-\(generation).sock",
                logPath: containerURL.appending(path: "shim.log").path
            )
        }
        func prepared(_ generation: UInt64) throws -> VMShimClient.PersistentSpawnFiles {
            try VMShimClient.preparePersistentSpawn(
                specification: specification(generation),
                container: container,
                generationsDirectory: generationsURL,
                executable: URL(filePath: "/usr/bin/yes")
            )
        }
        let missingSpec = try prepared(20)
        try FileManager.default.removeItem(at: missingSpec.specificationURL)
        let zeroSpec = try prepared(21)
        try Data().write(to: zeroSpec.specificationURL)
        let truncatedSpec = try prepared(22)
        try Data("{".utf8).write(to: truncatedSpec.specificationURL)
        let oversizedSpec = try prepared(23)
        try Data(
            repeating: 0x61, count: PersistentStateDirectory.maximumStateBytes + 1
        ).write(to: oversizedSpec.specificationURL)
        let symlinkSpec = try prepared(24)
        try FileManager.default.removeItem(at: symlinkSpec.specificationURL)
        try FileManager.default.createSymbolicLink(
            at: symlinkSpec.specificationURL,
            withDestinationURL: sibling.appending(path: "sentinel")
        )

        for _ in 0..<2 {
            let launches = try VMShimClient.persistedLaunches(
                in: PersistentStateDirectory.open(containerURL),
                expectedContainerID: container.id,
                expectedExecutable: URL(filePath: "/usr/bin/yes"),
                processIdentifiersProvider: { .complete([]) }
            )
            #expect(launches.isEmpty)
            #expect(launches.quarantined.count == 5)
        }
        #expect(Set(try PersistentStateDirectory.open(generationsURL).reconciledEntryNames()) == Set([
            missingSpec.directory.lastPathComponent,
            zeroSpec.directory.lastPathComponent,
            truncatedSpec.directory.lastPathComponent,
            oversizedSpec.directory.lastPathComponent,
            symlinkSpec.directory.lastPathComponent,
        ]))
        #expect(try Data(contentsOf: sibling.appending(path: "sentinel")) == Data("unrelated".utf8))
    }

    @Test func invalidIntentGenerationWithAForeignExecutableExactTupleIsQuarantined() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerURL = root.appending(path: "containers/owned-partial")
        let generationsURL = containerURL.appending(path: "shim-generations")
        try FileManager.default.createDirectory(at: containerURL, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let container = ContainerRecord(
            id: "owned-partial", name: "owned-partial", image: "alpine"
        )
        let specification = VMShimProtocol.Specification(
            containerID: container.id, generation: 31, token: "owned-partial-token",
            kernelPath: "/kernel", initialRamdiskPath: "/initramfs",
            rootDiskPath: containerURL.appending(path: "root.ext4").path,
            cpus: 1, memoryBytes: 268_435_456,
            macAddress: "02:ce:00:00:00:31", socketPath: "/tmp/owned-partial.sock",
            logPath: containerURL.appending(path: "shim.log").path
        )
        let files = try VMShimClient.preparePersistentSpawn(
            specification: specification,
            container: container,
            generationsDirectory: generationsURL,
            executable: URL(filePath: "/usr/bin/yes")
        )
        try Data("{".utf8).write(to: files.specificationURL)
        try Data("{".utf8).write(to: files.intentURL)
        let identity = VMShimClient.ProcessIdentity(processIdentifier: 4_321, startTime: 77)
        let inspection = VMShimClient.ProcessInspection(
            identityBefore: identity,
            executablePath: "/usr/bin/false",
            arguments: [
                "/usr/bin/false", "vm-shim", "--spec", files.specificationURL.path,
                "--launch-intent", files.intentURL.path,
            ],
            identityAfter: identity
        )

        let launches = try VMShimClient.persistedLaunches(
            in: PersistentStateDirectory.open(containerURL),
            expectedContainerID: container.id,
            expectedExecutable: URL(filePath: "/usr/bin/yes"),
            processIdentifiersProvider: { .complete([identity.processIdentifier]) },
            inspectionProvider: { $0 == identity.processIdentifier ? inspection : nil }
        )
        #expect(launches.isEmpty)
        #expect(launches.quarantined.count == 1)
        #expect(launches.quarantined.first?.ownerIdentities == [identity])
        #expect(FileManager.default.fileExists(atPath: files.directory.path))
    }

    @Test func malformedLaunchEvidenceIsQuarantinedWithoutBlockingSiblingCleanup() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerURL = root.appending(path: "containers/malformed-launch")
        let generationsURL = containerURL.appending(path: "shim-generations")
        try FileManager.default.createDirectory(at: containerURL, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let container = ContainerRecord(
            id: "malformed-launch", name: "malformed-launch", image: "alpine"
        )
        let specification = VMShimProtocol.Specification(
            containerID: container.id, generation: 32, token: "malformed-launch-token",
            kernelPath: "/kernel", initialRamdiskPath: "/initramfs",
            rootDiskPath: containerURL.appending(path: "root.ext4").path,
            cpus: 1, memoryBytes: 268_435_456,
            macAddress: "02:ce:00:00:00:32", socketPath: "/tmp/malformed-launch.sock",
            logPath: containerURL.appending(path: "shim.log").path
        )
        let files = try VMShimClient.preparePersistentSpawn(
            specification: specification,
            container: container,
            generationsDirectory: generationsURL,
            executable: URL(filePath: "/usr/bin/yes")
        )
        try Data("{".utf8).write(to: files.recordURL)
        let debris = generationsURL.appending(path: "mkdir-only")
        try FileManager.default.createDirectory(at: debris, withIntermediateDirectories: false)

        for _ in 0..<2 {
            let launches = try VMShimClient.persistedLaunches(
                in: PersistentStateDirectory.open(containerURL),
                expectedContainerID: container.id,
                expectedExecutable: URL(filePath: "/usr/bin/yes"),
                processIdentifiersProvider: { .complete([]) }
            )
            #expect(launches.isEmpty)
            #expect(launches.quarantined.count == 1)
        }
        #expect(FileManager.default.fileExists(atPath: files.directory.path))
        #expect(!FileManager.default.fileExists(atPath: debris.path))
    }

    @Test func recursiveDisposalPolicyRejectsMountAndIdentityCycles() {
        let rootIdentity = PersistentFileIdentity(device: 1, inode: 10)
        let childIdentity = PersistentFileIdentity(device: 1, inode: 11)
        let rootFilesystem = PersistentFilesystemIdentity(
            device: 1, fileSystemIdentifier: [1, 2, 3]
        )
        #expect(PersistentStateDirectory.mayTraverse(
            identity: childIdentity,
            filesystem: rootFilesystem,
            rootFilesystem: rootFilesystem,
            visited: [rootIdentity]
        ))
        #expect(!PersistentStateDirectory.mayTraverse(
            identity: rootIdentity,
            filesystem: rootFilesystem,
            rootFilesystem: rootFilesystem,
            visited: [rootIdentity]
        ))
        #expect(!PersistentStateDirectory.mayTraverse(
            identity: childIdentity,
            filesystem: .init(device: 2, fileSystemIdentifier: [9]),
            rootFilesystem: rootFilesystem,
            visited: [rootIdentity]
        ))
        #expect(!PersistentStateDirectory.mayTraverse(
            identity: childIdentity,
            filesystem: .init(
                device: 1, fileSystemIdentifier: [1, 2, 3], mountPoint: [47, 109, 110, 116]
            ),
            rootFilesystem: rootFilesystem,
            visited: [rootIdentity]
        ))
    }

    @Test func foreignGenerationIsQuarantinedWhileHealthySiblingRecovers() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerDirectory = root.appending(path: "containers/a")
        try FileManager.default.createDirectory(at: containerDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let container = ContainerRecord(id: "a", name: "a", image: "alpine")
        let specification = VMShimProtocol.Specification(
            containerID: "a", generation: 1, token: "token",
            kernelPath: "/kernel", initialRamdiskPath: "/initramfs",
            rootDiskPath: containerDirectory.appending(path: "root.ext4").path,
            cpus: 1, memoryBytes: 268_435_456,
            macAddress: "02:ce:00:00:00:01", socketPath: "/tmp/a.sock",
            logPath: containerDirectory.appending(path: "shim.log").path
        )
        let foreign = try VMShimClient.preparePersistentSpawn(
            specification: specification,
            container: container,
            containerDirectory: try PersistentStateDirectory.open(containerDirectory),
            executable: URL(filePath: "/usr/bin/yes")
        )
        var healthySpecification = specification
        healthySpecification.containerID = "b"
        healthySpecification.generation = 2
        healthySpecification.token = "healthy-token"
        healthySpecification.socketPath = "/tmp/b.sock"
        let healthyContainer = ContainerRecord(id: "b", name: "b", image: "alpine")
        let healthy = try VMShimClient.preparePersistentSpawn(
            specification: healthySpecification,
            container: healthyContainer,
            containerDirectory: try PersistentStateDirectory.open(containerDirectory),
            executable: URL(filePath: "/usr/bin/yes")
        )
        let owner = VMShimClient.ProcessIdentity(processIdentifier: 4_322, startTime: 88)
        let inspection = VMShimClient.ProcessInspection(
            identityBefore: owner,
            executablePath: "/usr/bin/yes",
            arguments: [
                "/usr/bin/yes", "vm-shim", "--spec", healthy.specificationURL.path,
                "--launch-intent", healthy.intentURL.path,
            ],
            identityAfter: owner
        )

        for _ in 0..<2 {
            let launches = try VMShimClient.persistedLaunches(
                in: PersistentStateDirectory.open(containerDirectory),
                expectedContainerID: "b",
                expectedExecutable: URL(filePath: "/usr/bin/yes"),
                processIdentifiersProvider: { .complete([owner.processIdentifier]) },
                identityProvider: { $0 == owner.processIdentifier ? owner : nil },
                inspectionProvider: { $0 == owner.processIdentifier ? inspection : nil }
            )
            #expect(launches.count == 1)
            #expect(launches.first?.record.container.id == "b")
            #expect(launches.quarantined.count == 1)
        }
        #expect(FileManager.default.fileExists(atPath: foreign.directory.path))
        #expect(FileManager.default.fileExists(atPath: healthy.recordURL.path))
    }

    @Test @MainActor
    func persistedShimUsesPublishedSpecificationAfterPathReplacement() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerDirectory = root.appending(path: "containers/published")
        try FileManager.default.createDirectory(at: containerDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let container = ContainerRecord(
            id: "published", name: "published", image: "alpine"
        )
        let original = VMShimProtocol.Specification(
            containerID: container.id, generation: 3, token: "original-token",
            kernelPath: "/kernel", initialRamdiskPath: "/initramfs",
            rootDiskPath: containerDirectory.appending(path: "root.ext4").path,
            cpus: 1, memoryBytes: 268_435_456,
            macAddress: "02:ce:00:00:00:03", socketPath: "/tmp/original.sock",
            logPath: containerDirectory.appending(path: "shim.log").path
        )
        let files = try VMShimClient.preparePersistentSpawn(
            specification: original,
            container: container,
            containerDirectory: try PersistentStateDirectory.open(containerDirectory),
            executable: URL(filePath: "/usr/bin/yes")
        )
        let intent = try JSONDecoder().decode(
            VMShimClient.PersistentLaunchIntent.self,
            from: Data(contentsOf: files.intentURL)
        )
        let record = VMShimClient.PersistentLaunchRecord(
            nonce: intent.nonce,
            createdAt: intent.createdAt,
            specificationPath: intent.specificationPath,
            executablePath: intent.executablePath,
            containerDirectoryIdentity: intent.containerDirectoryIdentity,
            generationsDirectoryIdentity: intent.generationsDirectoryIdentity,
            generationDirectoryIdentity: intent.generationDirectoryIdentity,
            specification: original,
            processIdentifier: 4_321,
            processStartTime: 44,
            container: container
        )
        var replacement = original
        replacement.token = "replacement-token"
        replacement.socketPath = "/tmp/replacement.sock"

        let selected = try VMShimServer.launchSpecification(
            specificationURL: files.specificationURL,
            launchIntentURL: files.intentURL,
            publish: { _ in
                try JSONEncoder().encode(replacement).write(
                    to: files.specificationURL, options: .atomic
                )
                return record
            }
        )
        #expect(selected == original)
        #expect(selected != replacement)
    }

    @Test func persistentRuntimeArtifactCleanupIsGenerationAndIdentityBound() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerURL = root.appending(path: "containers/artifacts")
        let runtimeURL = URL(filePath: "/tmp/ce-artifacts-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: containerURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: runtimeURL, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: root)
            try? FileManager.default.removeItem(at: runtimeURL)
        }
        let container = ContainerRecord(id: "artifacts", name: "artifacts", image: "alpine")

        func prepare(
            generation: UInt64, socketName: String
        ) throws -> (VMShimProtocol.Specification, VMShimClient.PersistentSpawnFiles) {
            let specification = VMShimProtocol.Specification(
                containerID: container.id, generation: generation, token: "token-\(generation)",
                kernelPath: "/kernel", initialRamdiskPath: "/initramfs",
                rootDiskPath: containerURL.appending(path: "root.ext4").path,
                cpus: 1, memoryBytes: 268_435_456,
                macAddress: String(format: "02:ce:00:00:00:%02llx", generation),
                socketPath: runtimeURL.appending(path: socketName).path,
                logPath: containerURL.appending(path: "shim.log").path
            )
            let files = try VMShimClient.preparePersistentSpawn(
                specification: specification,
                container: container,
                containerDirectory: PersistentStateDirectory.open(containerURL),
                executable: URL(filePath: "/usr/bin/yes")
            )
            let intent = try JSONDecoder().decode(
                VMShimClient.PersistentLaunchIntent.self,
                from: Data(contentsOf: files.intentURL)
            )
            let launch = VMShimClient.PersistentLaunchRecord(
                nonce: intent.nonce,
                createdAt: intent.createdAt,
                specificationPath: intent.specificationPath,
                executablePath: intent.executablePath,
                containerDirectoryIdentity: intent.containerDirectoryIdentity,
                generationsDirectoryIdentity: intent.generationsDirectoryIdentity,
                generationDirectoryIdentity: intent.generationDirectoryIdentity,
                specification: specification,
                processIdentifier: 4_321,
                processStartTime: generation,
                container: container
            )
            try JSONEncoder().encode(launch).write(to: files.recordURL)
            return (specification, files)
        }

        func publish(
            _ specification: VMShimProtocol.Specification,
            files: VMShimClient.PersistentSpawnFiles,
            status: Data
        ) throws -> Int32 {
            let publication = try VMShimClient.preparePersistentRuntimeArtifacts(
                intentURL: files.intentURL,
                socketPaths: [specification.socketPath],
                statusPath: specification.socketPath + ".status"
            )
            let listener = try UnixSocket.listen(
                path: publication.stagedPath(for: specification.socketPath)
            )
            try status.write(to: URL(filePath: publication.stagedPath(
                for: specification.socketPath + ".status"
            )))
            _ = try VMShimClient.publishPersistentRuntimeArtifacts(publication)
            return listener
        }

        let (ownedSpecification, ownedFiles) = try prepare(
            generation: 41, socketName: "owned.sock"
        )
        let ownedListener = try publish(
            ownedSpecification, files: ownedFiles, status: Data("owned-status".utf8)
        )
        defer { Darwin.close(ownedListener) }
        let ownedStatus = URL(filePath: ownedSpecification.socketPath + ".status")
        try VMShimClient.cleanupPersistentRuntimeArtifacts(intentURL: ownedFiles.intentURL)
        #expect(!FileManager.default.fileExists(atPath: ownedSpecification.socketPath))
        #expect(!FileManager.default.fileExists(atPath: ownedStatus.path))
        try VMShimClient.cleanupPersistentRuntimeArtifacts(intentURL: ownedFiles.intentURL)

        let (reboundSpecification, reboundFiles) = try prepare(
            generation: 42, socketName: "rebound.sock"
        )
        let reboundStatus = URL(filePath: reboundSpecification.socketPath + ".status")
        let originalListener = try publish(
            reboundSpecification,
            files: reboundFiles,
            status: Data("original-status".utf8)
        )
        Darwin.close(originalListener)
        let replacementListener = try UnixSocket.listen(path: reboundSpecification.socketPath)
        defer { Darwin.close(replacementListener) }
        let replacementStatus = Data("replacement-status".utf8)
        try replacementStatus.write(to: reboundStatus, options: .atomic)

        #expect(throws: PersistentRuntimeArtifactOwnershipUnresolvedError.self) {
            try VMShimClient.cleanupPersistentRuntimeArtifacts(
                intentURL: reboundFiles.intentURL
            )
        }
        #expect(throws: PersistentRuntimeArtifactOwnershipUnresolvedError.self) {
            try VMShimClient.cleanupPersistentRuntimeArtifacts(
                intentURL: reboundFiles.intentURL
            )
        }
        #expect(FileManager.default.fileExists(atPath: reboundSpecification.socketPath))
        #expect(try Data(contentsOf: reboundStatus) == replacementStatus)
        let connection = try UnixSocket.connect(path: reboundSpecification.socketPath)
        Darwin.close(connection)

        let (unpublishedSpecification, unpublishedFiles) = try prepare(
            generation: 43, socketName: "unpublished.sock"
        )
        let unpublishedListener = try UnixSocket.listen(path: unpublishedSpecification.socketPath)
        defer { Darwin.close(unpublishedListener) }
        let unpublishedStatus = URL(filePath: unpublishedSpecification.socketPath + ".status")
        try Data("unpublished-status".utf8).write(to: unpublishedStatus)
        #expect(throws: PersistentRuntimeArtifactOwnershipUnresolvedError.self) {
            try VMShimClient.cleanupPersistentRuntimeArtifacts(
                intentURL: unpublishedFiles.intentURL
            )
        }
        #expect(FileManager.default.fileExists(atPath: unpublishedSpecification.socketPath))
        #expect(FileManager.default.fileExists(atPath: unpublishedStatus.path))

        let (racingSpecification, racingFiles) = try prepare(
            generation: 44, socketName: "racing.sock"
        )
        let racingStatus = racingSpecification.socketPath + ".status"
        let racingListener = try publish(
            racingSpecification,
            files: racingFiles,
            status: Data("racing-original".utf8)
        )
        Darwin.close(racingListener)
        let replacementBox = ShimDescriptorBox()
        let racingReplacementStatus = Data("racing-replacement".utf8)
        let replacementHook = RuntimeArtifactReplacementHook(
            socketPath: racingSpecification.socketPath,
            statusPath: racingStatus,
            statusData: racingReplacementStatus,
            listenerBox: replacementBox
        )
        #expect(throws: PersistentRuntimeArtifactOwnershipUnresolvedError.self) {
            try VMShimClient.cleanupPersistentRuntimeArtifacts(
                intentURL: racingFiles.intentURL,
                hook: { try replacementHook.replace($0) }
            )
        }
        #expect(throws: PersistentRuntimeArtifactOwnershipUnresolvedError.self) {
            try VMShimClient.cleanupPersistentRuntimeArtifacts(
                intentURL: racingFiles.intentURL
            )
        }
        let racingReplacementListener = try #require(replacementBox.load())
        defer { Darwin.close(racingReplacementListener) }
        // Cleanup stops at the first unresolved socket replacement, so it
        // never reaches or mutates the still-owned status artifact.
        #expect(try Data(contentsOf: URL(filePath: racingStatus))
            == Data("racing-original".utf8))
        let racingConnection = try UnixSocket.connect(path: racingSpecification.socketPath)
        Darwin.close(racingConnection)

        let preparationFaults: [PersistentRuntimeArtifactBoundary] = [
            .creationJournalSynchronized,
            .stagingDirectorySynchronized,
        ]
        for (offset, boundary) in preparationFaults.enumerated() {
            let (faultSpecification, faultFiles) = try prepare(
                generation: UInt64(50 + offset),
                socketName: "prepare-fault-\(offset).sock"
            )
            let fault = RuntimeArtifactFault(boundary)
            #expect(throws: RuntimeArtifactFault.Failure.self) {
                _ = try VMShimClient.preparePersistentRuntimeArtifacts(
                    intentURL: faultFiles.intentURL,
                    socketPaths: [faultSpecification.socketPath],
                    statusPath: faultSpecification.socketPath + ".status",
                    hook: { try fault.fail($0) }
                )
            }
            try VMShimClient.cleanupPersistentRuntimeArtifacts(
                intentURL: faultFiles.intentURL
            )
            #expect(!FileManager.default.fileExists(atPath: faultSpecification.socketPath))
            #expect(!FileManager.default.fileExists(
                atPath: faultSpecification.socketPath + ".status"
            ))
        }

        let publicationFaults: [(String, String) -> PersistentRuntimeArtifactBoundary] = [
            { (name: String, _: String) in PersistentRuntimeArtifactBoundary.stagedOwnershipSynchronized },
            { (name: String, _: String) in .artifactExposed(name) },
            { (_: String, status: String) in .artifactExposed(status) },
            { (_: String, _: String) in .runtimeDirectorySynchronized },
            { (_: String, _: String) in .publicationSynchronized },
        ]
        for item in publicationFaults.enumerated() {
            let offset = item.offset
            let boundaryFactory = item.element
            let (faultSpecification, faultFiles) = try prepare(
                generation: UInt64(60 + offset),
                socketName: "publish-fault-\(offset).sock"
            )
            let publication = try VMShimClient.preparePersistentRuntimeArtifacts(
                intentURL: faultFiles.intentURL,
                socketPaths: [faultSpecification.socketPath],
                statusPath: faultSpecification.socketPath + ".status"
            )
            let stagedListener = try UnixSocket.listen(
                path: publication.stagedPath(for: faultSpecification.socketPath)
            )
            defer { Darwin.close(stagedListener) }
            try Data("fault-status".utf8).write(to: URL(filePath: publication.stagedPath(
                for: faultSpecification.socketPath + ".status"
            )))
            let socketName = URL(filePath: faultSpecification.socketPath).lastPathComponent
            let statusName = URL(
                filePath: faultSpecification.socketPath + ".status"
            ).lastPathComponent
            let fault = RuntimeArtifactFault(boundaryFactory(socketName, statusName))
            #expect(throws: RuntimeArtifactFault.Failure.self) {
                _ = try VMShimClient.publishPersistentRuntimeArtifacts(
                    publication, hook: { try fault.fail($0) }
                )
            }
            try VMShimClient.cleanupPersistentRuntimeArtifacts(intentURL: faultFiles.intentURL)
            try VMShimClient.cleanupPersistentRuntimeArtifacts(intentURL: faultFiles.intentURL)
            #expect(!FileManager.default.fileExists(atPath: faultSpecification.socketPath))
            #expect(!FileManager.default.fileExists(
                atPath: faultSpecification.socketPath + ".status"
            ))
            #expect(!FileManager.default.fileExists(atPath: publication.stagingDirectoryPath))
        }
        #expect(try FileManager.default.contentsOfDirectory(atPath: runtimeURL.path)
            .allSatisfy { !$0.hasPrefix(".c-") && !$0.hasPrefix(".cengine-artifact-") })
    }

    @Test func persistentRuntimePublicationFencesEveryGenerationAndRuntimeAncestor() throws {
        enum RelocatedChain: CaseIterable, Equatable { case generation, runtime }

        for relocatedChain in RelocatedChain.allCases {
            for boundaryIndex in 0..<3 {
                let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
                let stateAncestor = root.appending(path: "state-tree")
                let containerURL = stateAncestor.appending(path: "parent/containers/artifact-chain")
                let runtimeAncestor = URL(
                    filePath: "/tmp/ce-ar-"
                        + String(UUID().uuidString.replacingOccurrences(
                            of: "-", with: ""
                        ).prefix(8)),
                    directoryHint: .isDirectory
                )
                let runtimeURL = runtimeAncestor.appending(path: "r")
                try FileManager.default.createDirectory(
                    at: containerURL, withIntermediateDirectories: true
                )
                try FileManager.default.createDirectory(
                    at: runtimeURL, withIntermediateDirectories: true
                )
                defer {
                    try? FileManager.default.removeItem(at: root)
                    try? FileManager.default.removeItem(at: runtimeAncestor)
                }

                let container = ContainerRecord(
                    id: "artifact-chain", name: "artifact-chain", image: "alpine"
                )
                let socketPath = runtimeURL.appending(path: "shim.sock").path
                let statusPath = socketPath + ".status"
                let specification = VMShimProtocol.Specification(
                    containerID: container.id,
                    generation: UInt64(100 + boundaryIndex),
                    token: "artifact-chain-token-\(boundaryIndex)",
                    kernelPath: "/kernel",
                    initialRamdiskPath: "/initramfs",
                    rootDiskPath: containerURL.appending(path: "root.ext4").path,
                    cpus: 1,
                    memoryBytes: 268_435_456,
                    macAddress: "02:ce:00:00:01:0\(boundaryIndex)",
                    socketPath: socketPath,
                    logPath: containerURL.appending(path: "shim.log").path
                )
                let files = try VMShimClient.preparePersistentSpawn(
                    specification: specification,
                    container: container,
                    containerDirectory: PersistentStateDirectory.open(containerURL),
                    executable: URL(filePath: "/usr/bin/yes")
                )
                let intent = try JSONDecoder().decode(
                    VMShimClient.PersistentLaunchIntent.self,
                    from: Data(contentsOf: files.intentURL)
                )
                let launch = VMShimClient.PersistentLaunchRecord(
                    nonce: intent.nonce,
                    createdAt: intent.createdAt,
                    specificationPath: intent.specificationPath,
                    executablePath: intent.executablePath,
                    containerDirectoryIdentity: intent.containerDirectoryIdentity,
                    generationsDirectoryIdentity: intent.generationsDirectoryIdentity,
                    generationDirectoryIdentity: intent.generationDirectoryIdentity,
                    specification: specification,
                    processIdentifier: 4_321,
                    processStartTime: UInt64(100 + boundaryIndex),
                    container: container
                )
                try JSONEncoder().encode(launch).write(to: files.recordURL)

                let publication = try VMShimClient.preparePersistentRuntimeArtifacts(
                    intentURL: files.intentURL,
                    socketPaths: [socketPath],
                    statusPath: statusPath
                )
                let listener = try UnixSocket.listen(
                    path: publication.stagedPath(for: socketPath)
                )
                defer { Darwin.close(listener) }
                try Data("artifact-chain-status".utf8).write(
                    to: URL(filePath: publication.stagedPath(for: statusPath))
                )

                let socketName = URL(filePath: socketPath).lastPathComponent
                let targetBoundary: PersistentRuntimeArtifactBoundary = switch boundaryIndex {
                case 0: .artifactExposed(socketName)
                case 1: .runtimeDirectorySynchronized
                default: .publicationSynchronized
                }
                let originalAncestor = relocatedChain == .generation
                    ? stateAncestor : runtimeAncestor
                let detachedAncestor = root.appending(
                    path: "detached-\(relocatedChain)-\(boundaryIndex)"
                )
                let replacementMarker = originalAncestor.appending(path: "replacement-marker")
                var relocated = false

                #expect(throws: PersistentRuntimeArtifactOwnershipUnresolvedError.self) {
                    _ = try VMShimClient.publishPersistentRuntimeArtifacts(
                        publication,
                        hook: { boundary in
                            guard boundary == targetBoundary, !relocated else { return }
                            relocated = true
                            try FileManager.default.moveItem(
                                at: originalAncestor, to: detachedAncestor
                            )
                            try FileManager.default.createDirectory(
                                at: originalAncestor, withIntermediateDirectories: true
                            )
                            try Data("replacement".utf8).write(to: replacementMarker)
                        }
                    )
                }
                #expect(relocated)
                #expect(try Data(contentsOf: replacementMarker) == Data("replacement".utf8))

                let retainedJournal: URL
                if relocatedChain == .generation {
                    retainedJournal = detachedAncestor
                        .appending(path: "parent/containers/artifact-chain/shim-generations")
                        .appending(path: files.intentURL.deletingLastPathComponent().lastPathComponent)
                        .appending(path: "runtime-artifacts.json")
                } else {
                    retainedJournal = files.intentURL.deletingLastPathComponent()
                        .appending(path: "runtime-artifacts.json")
                }
                #expect(FileManager.default.fileExists(atPath: retainedJournal.path))
                #expect(throws: PersistentRuntimeArtifactOwnershipUnresolvedError.self) {
                    try VMShimClient.cleanupPersistentRuntimeArtifacts(intentURL: files.intentURL)
                }
                #expect(FileManager.default.fileExists(atPath: retainedJournal.path))
                #expect(try Data(contentsOf: replacementMarker) == Data("replacement".utf8))

                try FileManager.default.removeItem(at: originalAncestor)
                try FileManager.default.moveItem(at: detachedAncestor, to: originalAncestor)
                try VMShimClient.cleanupPersistentRuntimeArtifacts(intentURL: files.intentURL)
                try VMShimClient.cleanupPersistentRuntimeArtifacts(intentURL: files.intentURL)
                // Static artifact cleanup leaves the ownership journal for the
                // generation disposer. Only the owned socket/status/staging
                // inodes are retired here.
                let canonicalJournal = files.intentURL.deletingLastPathComponent()
                    .appending(path: "runtime-artifacts.json")
                #expect(FileManager.default.fileExists(atPath: canonicalJournal.path))
                #expect(!FileManager.default.fileExists(atPath: socketPath))
                #expect(!FileManager.default.fileExists(atPath: statusPath))
                #expect(try FileManager.default.contentsOfDirectory(atPath: runtimeURL.path)
                    .allSatisfy {
                        !$0.hasPrefix(".c-") && !$0.hasPrefix(".cengine-artifact-")
                    })
            }
        }
    }

    @Test func persistedGenerationQuarantinesAnyLaunchRecordMismatch() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerDirectory = root.appending(path: "containers/record-mismatch")
        let generations = RawVirtualizationBackend.generationsDirectory(for: containerDirectory)
        try FileManager.default.createDirectory(at: containerDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        var container = ContainerRecord(
            id: "record-mismatch", name: "record-mismatch", image: "alpine"
        )
        let specification = VMShimProtocol.Specification(
            containerID: container.id,
            generation: 71,
            token: "record-mismatch-token",
            kernelPath: "/kernel",
            initialRamdiskPath: "/initramfs",
            rootDiskPath: containerDirectory.appending(path: "root.ext4").path,
            cpus: 2,
            memoryBytes: 512 * 1_024 * 1_024,
            macAddress: "02:ce:00:00:00:71",
            socketPath: try RawVirtualizationBackend.makeRuntimeSocketPath(),
            logPath: containerDirectory.appending(path: "shim.log").path
        )
        let files = try VMShimClient.preparePersistentSpawn(
            specification: specification,
            container: container,
            generationsDirectory: generations,
            executable: URL(filePath: "/usr/bin/yes")
        )
        let intent = try JSONDecoder().decode(
            VMShimClient.PersistentLaunchIntent.self,
            from: Data(contentsOf: files.intentURL)
        )
        container.cpus = 9
        let mismatched = VMShimClient.PersistentLaunchRecord(
            nonce: intent.nonce,
            createdAt: intent.createdAt,
            specificationPath: intent.specificationPath,
            executablePath: intent.executablePath,
            containerDirectoryIdentity: intent.containerDirectoryIdentity,
            generationsDirectoryIdentity: intent.generationsDirectoryIdentity,
            generationDirectoryIdentity: intent.generationDirectoryIdentity,
            specification: specification,
            processIdentifier: 4_321,
            processStartTime: 123,
            container: container
        )
        try JSONEncoder().encode(mismatched).write(to: files.recordURL)

        let first = try VMShimClient.persistedLaunches(
            in: generations,
            expectedContainerID: container.id,
            expectedExecutable: URL(filePath: "/usr/bin/yes")
        )
        #expect(first.isEmpty)
        #expect(first.quarantined.count == 1)
        #expect(FileManager.default.fileExists(atPath: files.directory.path))
        let second = try VMShimClient.persistedLaunches(
            in: generations,
            expectedContainerID: container.id,
            expectedExecutable: URL(filePath: "/usr/bin/yes")
        )
        #expect(second.isEmpty)
        #expect(second.quarantined.count == 1)
        #expect(FileManager.default.fileExists(atPath: files.directory.path))
    }

    @Test func persistedGenerationNeverAdoptsAReusedContainerIDInstance() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerDirectory = root.appending(path: "containers/reused-instance")
        try FileManager.default.createDirectory(
            at: containerDirectory, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let original = ContainerRecord(
            id: "reused-instance", name: "same-name", image: "alpine"
        )
        let specification = VMShimProtocol.Specification(
            containerID: original.id, generation: 91, token: "original-instance",
            kernelPath: "/kernel", initialRamdiskPath: "/initramfs",
            rootDiskPath: containerDirectory.appending(path: "root.ext4").path,
            cpus: 1, memoryBytes: 268_435_456,
            macAddress: "02:ce:00:00:00:91", socketPath: "/tmp/reused-instance.sock",
            logPath: containerDirectory.appending(path: "shim.log").path
        )
        let files = try VMShimClient.preparePersistentSpawn(
            specification: specification,
            container: original,
            containerDirectory: try PersistentStateDirectory.open(containerDirectory),
            executable: URL(filePath: "/usr/bin/yes")
        )

        let enumeration = try VMShimClient.persistedLaunches(
            in: try PersistentStateDirectory.open(containerDirectory),
            expectedContainerID: original.id,
            expectedInstanceID: UUID(),
            expectedExecutable: URL(filePath: "/usr/bin/yes"),
            processIdentifiersProvider: { .complete([]) }
        )
        #expect(enumeration.isEmpty)
        #expect(enumeration.quarantined.count == 1)
        #expect(FileManager.default.fileExists(atPath: files.directory.path))
    }

    @Test func preparationFailureRetainsRootAndCapacityUntilTerminationRetrySucceeds() async throws {
        let state = PreparationRecoveryState()
        do {
            try await PreparedShimFailureRecovery.perform(
                preparationError: PreparationRecoveryState.Failure.preparation,
                terminateEveryGeneration: { try state.terminateEveryGeneration() },
                discardWritableRoot: { try state.discardWritableRoot() }
            )
        } catch let error as BackendResourceRollbackIncompleteError {
            #expect(error.message.contains("writable root was retained"))
        }
        var snapshot = state.snapshot()
        #expect(snapshot.attempts == 1)
        #expect(snapshot.capacityOwned)
        #expect(snapshot.rootPresent)

        await #expect(throws: PreparationRecoveryState.Failure.self) {
            try await PreparedShimFailureRecovery.perform(
                preparationError: PreparationRecoveryState.Failure.preparation,
                terminateEveryGeneration: { try state.terminateEveryGeneration() },
                discardWritableRoot: { try state.discardWritableRoot() }
            )
        }
        snapshot = state.snapshot()
        #expect(snapshot.attempts == 2)
        #expect(!snapshot.capacityOwned)
        #expect(!snapshot.rootPresent)
    }

    @Test func preparationCompensationSurfacesDirectoryIdentityDeletionFailure() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containersURL = root.appending(path: "containers")
        let containerURL = containersURL.appending(path: "owned")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        try Data("root".utf8).write(to: containerURL.appending(path: "root.ext4"))
        defer { try? FileManager.default.removeItem(at: root) }
        let containers = try PersistentStateDirectory.open(containersURL)
        let actual = try containers.openDirectory(named: "owned").identity
        let wrong = PersistentFileIdentity(device: actual.device, inode: actual.inode &+ 1)

        do {
            try await PreparedShimFailureRecovery.perform(
                preparationError: EngineError(.internalError, "preparation failed"),
                terminateEveryGeneration: {},
                discardWritableRoot: {
                    try containers.disposeDirectory(
                        named: "owned", expectedIdentity: wrong
                    )
                }
            )
        } catch let error as BackendResourceRollbackIncompleteError {
            #expect(error.message.contains("writable root could not be discarded"))
        }
        #expect(try Data(contentsOf: containerURL.appending(path: "root.ext4"))
            == Data("root".utf8))
    }

    @Test func preparedStdoutSymlinkIsRejectedWithoutTouchingItsTarget() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerURL = root.appending(path: "containers/symlink-before-start")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = try PersistentStateDirectory.open(containerURL)
        _ = try makePreparedState(
            in: directory, containerID: "symlink-before-start"
        )
        let ioURL = containerURL.appending(path: "io")
        let stdout = ioURL.appending(path: "stdout")
        let heldStdout = ioURL.appending(path: "held-stdout")
        let sentinel = root.appending(path: "stdout-sentinel")
        let sentinelData = Data("must-not-change".utf8)
        try sentinelData.write(to: sentinel)
        try FileManager.default.moveItem(at: stdout, to: heldStdout)
        try FileManager.default.createSymbolicLink(
            at: stdout, withDestinationURL: sentinel
        )

        #expect(throws: POSIXError.self) {
            try RawVirtualizationBackend.loadPreparedShimState(from: containerURL)
        }
        #expect(try Data(contentsOf: sentinel) == sentinelData)
        #expect(try Data(contentsOf: heldStdout).isEmpty)
    }

    @Test func persistedShimLogSymlinkIsRejectedWithoutTouchingItsTarget() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerURL = root.appending(path: "containers/shim-log-symlink")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = try PersistentStateDirectory.open(containerURL)
        let state = try makePreparedState(
            in: directory, containerID: "shim-log-symlink"
        )
        let logURL = containerURL.appending(path: "shim.log")
        let retainedURL = containerURL.appending(path: "retained-shim.log")
        let sentinelURL = root.appending(path: "sentinel")
        let sentinel = Data("must-not-change".utf8)
        try sentinel.write(to: sentinelURL)
        try FileManager.default.moveItem(at: logURL, to: retainedURL)
        try FileManager.default.createSymbolicLink(
            at: logURL, withDestinationURL: sentinelURL
        )

        #expect(throws: POSIXError.self) {
            _ = try VMShimClient.preparePersistentSpawn(
                specification: state.specification,
                container: state.currentContainer,
                containerDirectory: directory,
                expectedLogIdentity: state.artifacts.shimLogIdentity,
                executable: URL(filePath: "/usr/bin/true")
            )
        }
        #expect(try Data(contentsOf: sentinelURL) == sentinel)
        #expect(try Data(contentsOf: retainedURL).isEmpty)
    }

    @Test func persistedShimLogIdentitySupportsLegitimateRelaunchPreparation() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerURL = root.appending(path: "containers/shim-log-relaunch")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = try PersistentStateDirectory.open(containerURL)
        let state = try makePreparedState(
            in: directory, containerID: "shim-log-relaunch"
        )

        let first = try VMShimClient.preparePersistentSpawn(
            specification: state.specification,
            container: state.currentContainer,
            containerDirectory: directory,
            expectedLogIdentity: state.artifacts.shimLogIdentity,
            executable: URL(filePath: "/usr/bin/true")
        )
        var nextSpecification = state.specification
        nextSpecification.generation += 1
        nextSpecification.token = "next-log-generation"
        let second = try VMShimClient.preparePersistentSpawn(
            specification: nextSpecification,
            container: state.currentContainer,
            containerDirectory: directory,
            expectedLogIdentity: state.artifacts.shimLogIdentity,
            executable: URL(filePath: "/usr/bin/true")
        )

        #expect(first.logIdentity == state.artifacts.shimLogIdentity)
        #expect(second.logIdentity == state.artifacts.shimLogIdentity)
        try state.artifacts.validate(in: directory)
    }

    @Test func preparedStateRejectsEveryReplacementArtifactInode() throws {
        for artifactName in [
            "root.ext4", "shim.log", "exec-artifacts.jsonl", "exec-artifacts.compact",
            "stdout", "stderr", "stdin", "stdin.closed", "docker.log",
            "docker.log.entries",
        ] {
            let root = FileManager.default.temporaryDirectory.appending(
                path: UUID().uuidString
            )
            let containerID = "replaced-\(artifactName.replacingOccurrences(of: ".", with: "-"))"
            let containerURL = root.appending(path: "containers/\(containerID)")
            try FileManager.default.createDirectory(
                at: containerURL, withIntermediateDirectories: true
            )
            defer { try? FileManager.default.removeItem(at: root) }
            let directory = try PersistentStateDirectory.open(containerURL)
            _ = try makePreparedState(in: directory, containerID: containerID)
            let parentURL = [
                "root.ext4", "shim.log", "exec-artifacts.jsonl", "exec-artifacts.compact",
            ]
                .contains(artifactName) ? containerURL : containerURL.appending(path: "io")
            let originalURL = parentURL.appending(path: artifactName)
            let retainedURL = parentURL.appending(path: "held-\(artifactName)")
            let originalData = try Data(contentsOf: originalURL)
            let heldDescriptor = Darwin.open(
                originalURL.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC
            )
            #expect(heldDescriptor >= 0)
            defer { if heldDescriptor >= 0 { Darwin.close(heldDescriptor) } }
            try FileManager.default.moveItem(at: originalURL, to: retainedURL)
            let replacementData = artifactName == "root.ext4"
                ? Data(repeating: 0x52, count: 4_096)
                : Data("replacement".utf8)
            try replacementData.write(to: originalURL)

            #expect(throws: EngineError.self) {
                try RawVirtualizationBackend.loadPreparedShimState(from: containerURL)
            }
            #expect(try Data(contentsOf: retainedURL) == originalData)
            #expect(try Data(contentsOf: originalURL) == replacementData)
        }
    }

    @Test func preparedStateRejectsWrongRootDiskSize() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerURL = root.appending(path: "containers/wrong-root-size")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = try PersistentStateDirectory.open(containerURL)
        let state = try makePreparedState(
            in: directory, containerID: "wrong-root-size"
        )
        let rootHandle = try directory.openRegularFile(
            named: "root.ext4",
            expectedIdentity: state.artifacts.rootDiskIdentity,
            access: .readWrite
        ).handle
        #expect(Darwin.ftruncate(rootHandle.fileDescriptor, 2_048) == 0)

        #expect(throws: EngineError.self) {
            try RawVirtualizationBackend.loadPreparedShimState(from: containerURL)
        }
        var information = stat()
        #expect(Darwin.fstat(rootHandle.fileDescriptor, &information) == 0)
        #expect(information.st_size == 2_048)
    }

    @Test func preparedStateAllowsCanonicalFilesToGrowBeforeDeleteRetry() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerURL = root.appending(path: "containers/grown-io")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = try PersistentStateDirectory.open(containerURL)
        let state = try makePreparedState(in: directory, containerID: "grown-io")
        let ioDirectory = try directory.openDirectory(named: "io")

        for name in ["stdout", "stderr", "stdin", "stdin.closed"] {
            let identity = try #require(state.artifacts.ioFileIdentities[name])
            let handle = try ioDirectory.openRegularFile(
                named: name, expectedIdentity: identity, access: .readWrite
            ).handle
            try handle.write(contentsOf: Data("canonical-\(name)-data".utf8))
            try handle.synchronize()
        }
        let shimLog = try directory.openRegularFile(
            named: "shim.log",
            expectedIdentity: state.artifacts.shimLogIdentity,
            access: .readWrite
        ).handle
        try shimLog.write(contentsOf: Data("canonical-shim-log-data".utf8))
        try shimLog.synchronize()
        for (name, identity) in [
            ("docker.log", state.artifacts.dockerLogIdentity),
            ("docker.log.entries", state.artifacts.dockerLogIndexIdentity),
        ] {
            let handle = try ioDirectory.openRegularFile(
                named: name, expectedIdentity: identity, access: .readWrite
            ).handle
            try handle.write(contentsOf: Data("canonical-\(name)-data".utf8))
            try handle.synchronize()
        }

        let loadedState = try RawVirtualizationBackend.loadPreparedShimState(
            from: containerURL
        )
        let loaded = try #require(loadedState)
        #expect(loaded.artifacts == state.artifacts)
        try loaded.artifacts.validate(in: directory)

        let containers = try PersistentStateDirectory.open(
            root.appending(path: "containers")
        )
        let receiptsURL = root.appending(path: "deleted-containers")
        try FileManager.default.createDirectory(
            at: receiptsURL, withIntermediateDirectories: true
        )
        let receipts = try PersistentStateDirectory.open(receiptsURL)
        try RawDeletedContainerCoordinator.record(
            state.currentContainer,
            directoryIdentity: directory.identity,
            in: receipts
        )
        try containers.disposeDirectory(
            named: state.currentContainer.id,
            expectedIdentity: directory.identity
        )
        // Exercise the same durable proof used by a retry of Raw.delete and
        // the later Raw.deleteLogs step in auto-remove cleanup.
        try RawDeletedContainerCoordinator.requireCompletedDeletion(
            of: state.currentContainer, in: containers, receipts: receipts
        )
        try RawDeletedContainerCoordinator.requireCompletedDeletion(
            of: state.currentContainer, in: containers, receipts: receipts
        )
    }

    @Test func schemaThreeBindsSpecificationToCanonicalArtifacts() throws {
        typealias SpecificationMutation = (inout VMShimProtocol.Specification) -> Void
        let mutations: [(String, SpecificationMutation)] = [
            ("missing-root-identity", { $0.rootDiskIdentity = nil }),
            ("wrong-root-identity", {
                $0.rootDiskIdentity = .init(
                    device: $0.rootDiskIdentity?.device ?? 0,
                    inode: ($0.rootDiskIdentity?.inode ?? 0) &+ 1
                )
            }),
            ("missing-root-size", { $0.rootDiskSize = nil }),
            ("wrong-root-size", { $0.rootDiskSize = ($0.rootDiskSize ?? 0) &+ 1 }),
            ("missing-io-share", {
                $0.bindShares.removeAll { $0.tag == "cengine-io" }
            }),
            ("duplicate-io-share", {
                if let share = $0.bindShares.first(where: { $0.tag == "cengine-io" }) {
                    $0.bindShares.append(share)
                }
            }),
            ("wrong-io-path", {
                if let index = $0.bindShares.firstIndex(where: { $0.tag == "cengine-io" }) {
                    $0.bindShares[index].source += "-replacement"
                }
            }),
            ("missing-io-identity", {
                if let index = $0.bindShares.firstIndex(where: { $0.tag == "cengine-io" }) {
                    $0.bindShares[index].sourceIdentity = nil
                }
            }),
            ("wrong-io-identity", {
                if let index = $0.bindShares.firstIndex(where: { $0.tag == "cengine-io" }) {
                    let identity = $0.bindShares[index].sourceIdentity
                    $0.bindShares[index].sourceIdentity = .init(
                        device: identity?.device ?? 0,
                        inode: (identity?.inode ?? 0) &+ 1
                    )
                }
            }),
            ("read-only-io-share", {
                if let index = $0.bindShares.firstIndex(where: { $0.tag == "cengine-io" }) {
                    $0.bindShares[index].readOnly = true
                }
            }),
            ("wrong-shim-log-path", { $0.logPath += "-replacement" }),
        ]

        for (name, mutate) in mutations {
            let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
            let containerURL = root.appending(path: "containers/\(name)")
            try FileManager.default.createDirectory(
                at: containerURL, withIntermediateDirectories: true
            )
            defer { try? FileManager.default.removeItem(at: root) }
            let directory = try PersistentStateDirectory.open(containerURL)
            let original = try makePreparedState(in: directory, containerID: name)
            var specification = original.specification
            mutate(&specification)
            let replacement = RawVirtualizationBackend.PreparedShimState(
                directoryIdentity: original.directoryIdentity,
                artifacts: original.artifacts,
                currentContainer: original.currentContainer,
                specification: specification
            )
            try directory.replaceRegularFile(
                named: "prepared-shim.json", data: try JSONEncoder().encode(replacement)
            )

            #expect(throws: EngineError.self) {
                try RawVirtualizationBackend.loadPreparedShimState(from: containerURL)
            }
        }
    }

    @Test func exactContainerOwnershipGuardFencesEveryExecutionPathUntilSiblingEvidenceClears() throws {
        let container = ContainerRecord(
            id: "ownership-fence", name: "ownership-fence", image: "alpine"
        )
        let operations = [
            "prepare", "recover", "start", "stop", "wait", "completion", "io",
            "logs", "delete-logs", "prepare-exec", "start-exec", "attach-exec",
            "exec-completion", "exec-status", "exec-pid", "kill", "pause", "resume",
            "update-resources", "update-networks", "statistics", "top", "copy-in",
            "copy-out",
        ]

        for operation in operations {
            var reachedExecution = false
            #expect(throws: BackendResourceRollbackIncompleteError.self) {
                try RawExactContainerOwnershipGuard.require(
                    container,
                    knownInstanceID: container.instanceID,
                    quarantinedGenerationCount: 1,
                    cleanupPendingGenerationCount: 0
                )
                reachedExecution = true
            }
            #expect(!reachedExecution, "\(operation) crossed a quarantined generation fence")

            #expect(throws: BackendResourceRollbackIncompleteError.self) {
                try RawExactContainerOwnershipGuard.require(
                    container,
                    knownInstanceID: container.instanceID,
                    quarantinedGenerationCount: 0,
                    cleanupPendingGenerationCount: 1
                )
            }
        }

        // A retry after exact sibling termination has removed both kinds of
        // evidence may proceed through the same centralized boundary.
        try RawExactContainerOwnershipGuard.require(
            container,
            knownInstanceID: container.instanceID,
            quarantinedGenerationCount: 0,
            cleanupPendingGenerationCount: 0
        )

        let replacement = ContainerRecord(
            id: container.id, name: container.name, image: container.image
        )
        #expect(throws: BackendResourceRollbackIncompleteError.self) {
            try RawExactContainerOwnershipGuard.require(
                replacement,
                knownInstanceID: container.instanceID,
                quarantinedGenerationCount: 0,
                cleanupPendingGenerationCount: 0
            )
        }

    }

    @Test func containerGuestClaimsAreDurableDeterministicAndRecoveredWithoutAccumulation() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerID = "container-claim-recovery"
        let containerURL = root.appending(path: "containers/\(containerID)")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let containerDirectory = try PersistentStateDirectory.open(containerURL)
        let prepared = try makePreparedState(
            in: containerDirectory, containerID: containerID, generation: 37
        )
        let claim = RawContainerDirectIOHandles.containerGuestClaim(
            instanceID: prepared.currentContainer.instanceID,
            generation: prepared.specification.generation
        )
        #expect(claim == "container-\(prepared.currentContainer.instanceID.uuidString.lowercased())-37")

        let names = RawContainerPreparationArtifacts.directIOFileNames
        let io = try containerDirectory.openDirectory(named: "io")
        try linkGuestIOClaims(claim, names: names, in: io)

        // Simulate daemon death after the guest linked the exact inodes but
        // before the host consumed the prepare response.
        let recoveredContainer = try PersistentStateDirectory.open(containerURL)
        let recoveredIO = try recoveredContainer.openDirectory(named: "io")
        try RawContainerDirectIOHandles.cleanupGuestClaims(
            claim,
            names: names,
            identities: prepared.artifacts.ioFileIdentities,
            in: recoveredIO
        )
        for (index, name) in names.enumerated() {
            #expect(try recoveredIO.entryMetadata(named: name) != nil)
            #expect(try recoveredIO.entryMetadata(
                named: RawContainerDirectIOHandles.guestClaimName(claim, index: index)
            ) == nil)
        }

        // The same durable generation retries with the same claim and can be
        // consumed normally without leaving aliases behind.
        try linkGuestIOClaims(claim, names: names, in: recoveredIO)
        try RawContainerDirectIOHandles.consumeGuestClaims(
            claim,
            names: names,
            identities: prepared.artifacts.ioFileIdentities,
            in: recoveredIO
        )
        #expect(try recoveredIO.entryNames().allSatisfy {
            !$0.hasPrefix(".cengine-io-claim-")
        })
    }

    @Test func execGuestClaimCrashRecoveryUsesJournalNonceAndReleasesAllArtifacts() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerID = "exec-claim-recovery"
        let execID = "crashed-exec"
        let containerURL = root.appending(path: "containers/\(containerID)")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let containerDirectory = try PersistentStateDirectory.open(containerURL)
        let prepared = try makePreparedState(in: containerDirectory, containerID: containerID)
        let io = try containerDirectory.openDirectory(named: "io")
        let ioNames = Array(RawExecArtifactRecord.expectedNames(execID: execID).prefix(4))

        var transaction: RawPreparedExecArtifacts? = try RawExecArtifactTransaction.prepare(
            containerID: containerID,
            execID: execID,
            attachStdin: true,
            in: containerDirectory,
            artifacts: prepared.artifacts
        )
        let record = try #require(transaction?.record)
        let firstClaim = RawExecArtifactTransaction.guestClaim(for: record)
        #expect(firstClaim == "exec-\(record.stagingDirectoryName.suffix(16))")
        #expect(RawExecArtifactTransaction.guestClaim(for: record) == firstClaim)
        try transaction?.stdout.write(contentsOf: Data("unconsumed-output".utf8))
        try transaction?.stdout.synchronize()
        transaction = nil
        try linkGuestIOClaims(firstClaim, names: ioNames, in: io)

        let recoveredContainer = try PersistentStateDirectory.open(containerURL)
        try RawExecArtifactTransaction.cleanup(
            containerID: containerID,
            execID: execID,
            in: recoveredContainer,
            artifacts: prepared.artifacts
        )
        #expect(try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: execID,
            in: recoveredContainer,
            artifacts: prepared.artifacts
        ) == nil)
        let recoveredIO = try recoveredContainer.openDirectory(named: "io")
        #expect(try recoveredIO.entryNames().allSatisfy {
            !$0.contains(execID) && !$0.contains(firstClaim)
        })

        let retry = try RawExecArtifactTransaction.prepare(
            containerID: containerID,
            execID: execID,
            attachStdin: true,
            in: recoveredContainer,
            artifacts: prepared.artifacts
        )
        let retryClaim = RawExecArtifactTransaction.guestClaim(for: retry.record)
        #expect(retryClaim != firstClaim)
        try linkGuestIOClaims(retryClaim, names: ioNames, in: recoveredIO)
        try RawContainerDirectIOHandles.consumeGuestClaims(
            retryClaim,
            names: ioNames,
            identities: retry.record.fileIdentities,
            in: recoveredIO
        )
        try RawExecArtifactTransaction.cleanup(
            containerID: containerID,
            execID: execID,
            in: recoveredContainer,
            artifacts: prepared.artifacts
        )
        #expect(try recoveredIO.entryNames().allSatisfy {
            !$0.contains(execID) && !$0.hasPrefix(".cengine-io-claim-exec-")
        })
    }

    @Test func guestIOClaimRecoveryPreservesForeignAndBoundaryABAReplacements() throws {
        for kind in ["container", "exec"] {
            let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: root) }
            let directory = try PersistentStateDirectory.open(root)
            let names = [
                "\(kind)-stdout", "\(kind)-stderr", "\(kind)-stdin",
                "\(kind)-stdin.closed",
            ]
            var identities: [String: PersistentFileIdentity] = [:]
            for name in names {
                identities[name] = try directory.createSparseRegularFile(named: name, size: 0)
            }
            let claim = "\(kind)-durable-token"
            try linkGuestIOClaims(claim, names: names, in: directory)
            let claimName = RawContainerDirectIOHandles.guestClaimName(claim, index: 0)
            let claimURL = root.appending(path: claimName)
            let retainedURL = root.appending(path: "retained-\(kind)-claim")
            let replacement = Data("foreign-\(kind)-claim".utf8)

            try FileManager.default.moveItem(at: claimURL, to: retainedURL)
            try replacement.write(to: claimURL)
            #expect(throws: EngineError.self) {
                try RawContainerDirectIOHandles.cleanupGuestClaims(
                    claim, names: names, identities: identities, in: directory
                )
            }
            #expect(try Data(contentsOf: claimURL) == replacement)
            #expect(FileManager.default.fileExists(atPath: retainedURL.path))

            try FileManager.default.moveItem(
                at: claimURL, to: root.appending(path: "foreign-\(kind)-retained")
            )
            try FileManager.default.moveItem(at: retainedURL, to: claimURL)
            #expect(throws: EngineError.self) {
                try RawContainerDirectIOHandles.cleanupGuestClaims(
                    claim,
                    names: names,
                    identities: identities,
                    in: directory,
                    beforeClaimRemoval: { index in
                        guard index == 0 else { return }
                        try FileManager.default.moveItem(at: claimURL, to: retainedURL)
                        try replacement.write(to: claimURL)
                    }
                )
            }
            #expect(try Data(contentsOf: claimURL) == replacement)
            #expect(FileManager.default.fileExists(atPath: retainedURL.path))
        }
    }

    @Test func execGuestClaimMismatchDoesNotRetireItsOwnershipJournal() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerID = "exec-claim-mismatch"
        let execID = "foreign-alias"
        let containerURL = root.appending(path: "containers/\(containerID)")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let containerDirectory = try PersistentStateDirectory.open(containerURL)
        let prepared = try makePreparedState(in: containerDirectory, containerID: containerID)
        let io = try containerDirectory.openDirectory(named: "io")
        let transaction = try RawExecArtifactTransaction.prepare(
            containerID: containerID,
            execID: execID,
            attachStdin: true,
            in: containerDirectory,
            artifacts: prepared.artifacts
        )
        let claim = RawExecArtifactTransaction.guestClaim(for: transaction.record)
        let names = Array(RawExecArtifactRecord.expectedNames(execID: execID).prefix(4))
        try linkGuestIOClaims(claim, names: names, in: io)
        let claimName = RawContainerDirectIOHandles.guestClaimName(claim, index: 0)
        let claimURL = io.url.appending(path: claimName)
        let retainedURL = io.url.appending(path: "retained-owned-claim")
        let foreign = Data("foreign-must-remain".utf8)
        try FileManager.default.moveItem(at: claimURL, to: retainedURL)
        try foreign.write(to: claimURL)

        #expect(throws: EngineError.self) {
            try RawExecArtifactTransaction.cleanup(
                containerID: containerID,
                execID: execID,
                in: containerDirectory,
                artifacts: prepared.artifacts
            )
        }
        #expect(try Data(contentsOf: claimURL) == foreign)
        #expect(try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: execID,
            in: containerDirectory,
            artifacts: prepared.artifacts
        ) == transaction.record)

        try FileManager.default.moveItem(
            at: claimURL, to: io.url.appending(path: "foreign-retained")
        )
        try FileManager.default.moveItem(at: retainedURL, to: claimURL)
        let boundaryRetainedURL = io.url.appending(path: "boundary-owned-claim")
        #expect(throws: EngineError.self) {
            try RawContainerDirectIOHandles.cleanupGuestClaims(
                claim,
                names: names,
                identities: transaction.record.fileIdentities,
                in: io,
                beforeClaimRemoval: { index in
                    guard index == 0 else { return }
                    try FileManager.default.moveItem(
                        at: claimURL, to: boundaryRetainedURL
                    )
                    try foreign.write(to: claimURL)
                }
            )
        }
        #expect(try Data(contentsOf: claimURL) == foreign)
        #expect(try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: execID,
            in: containerDirectory,
            artifacts: prepared.artifacts
        ) == transaction.record)
        try FileManager.default.moveItem(
            at: claimURL, to: io.url.appending(path: "boundary-foreign-retained")
        )
        try FileManager.default.moveItem(at: boundaryRetainedURL, to: claimURL)
        try RawExecArtifactTransaction.cleanup(
            containerID: containerID,
            execID: execID,
            in: containerDirectory,
            artifacts: prepared.artifacts
        )
    }

    @Test func guestIOClaimRemovalResumesDurableRenameForConsumeAndRecovery() throws {
        struct InjectedCrash: Error {}

        let claims = [
            RawContainerDirectIOHandles.containerGuestClaim(
                instanceID: UUID(), generation: 71
            ),
            "exec-0123456789abcdef",
        ]
        #expect(Set(claims.enumerated().map {
            RawContainerDirectIOHandles.guestClaimRemovalName(
                $0.element, index: $0.offset
            )
        }).count == claims.count)

        for cleanupOnly in [false, true] {
            for claim in claims {
                let root = FileManager.default.temporaryDirectory.appending(
                    path: UUID().uuidString
                )
                try FileManager.default.createDirectory(
                    at: root, withIntermediateDirectories: true
                )
                defer { try? FileManager.default.removeItem(at: root) }
                let directory = try PersistentStateDirectory.open(root)
                let names = ["stdout", "stderr", "stdin", "stdin.closed"]
                var identities: [String: PersistentFileIdentity] = [:]
                for name in names {
                    identities[name] = try directory.createSparseRegularFile(
                        named: name, size: 0
                    )
                }
                try linkGuestIOClaims(claim, names: names, in: directory)

                let siblingClaim = "\(claim)-sibling"
                try linkGuestIOClaims(siblingClaim, names: names, in: directory)
                let firstGuestName = RawContainerDirectIOHandles.guestClaimName(
                    claim, index: 0
                )
                let firstRemovalName = RawContainerDirectIOHandles.guestClaimRemovalName(
                    claim, index: 0
                )
                let crash: PersistentRuntimeArtifactHook = { boundary in
                    guard boundary == .deletionClaimed(firstGuestName) else { return }
                    throw InjectedCrash()
                }

                #expect(throws: InjectedCrash.self) {
                    if cleanupOnly {
                        try RawContainerDirectIOHandles.cleanupGuestClaims(
                            claim,
                            names: names,
                            identities: identities,
                            in: directory,
                            removalHook: crash
                        )
                    } else {
                        try RawContainerDirectIOHandles.consumeGuestClaims(
                            claim,
                            names: names,
                            identities: identities,
                            in: directory,
                            removalHook: crash
                        )
                    }
                }
                #expect(try directory.entryMetadata(named: firstGuestName) == nil)
                #expect(try directory.entryMetadata(named: firstRemovalName)?.identity
                    == identities[names[0]])

                if cleanupOnly {
                    try RawContainerDirectIOHandles.cleanupGuestClaims(
                        claim, names: names, identities: identities, in: directory
                    )
                } else {
                    try RawContainerDirectIOHandles.consumeGuestClaims(
                        claim, names: names, identities: identities, in: directory
                    )
                }
                for (index, name) in names.enumerated() {
                    #expect(try directory.entryMetadata(named: name)?.identity
                        == identities[name])
                    #expect(try directory.entryMetadata(
                        named: RawContainerDirectIOHandles.guestClaimName(
                            claim, index: index
                        )
                    ) == nil)
                    #expect(try directory.entryMetadata(
                        named: RawContainerDirectIOHandles.guestClaimRemovalName(
                            claim, index: index
                        )
                    ) == nil)
                    #expect(try directory.entryMetadata(
                        named: RawContainerDirectIOHandles.guestClaimName(
                            siblingClaim, index: index
                        )
                    )?.identity == identities[name])
                }
            }
        }
    }

    @Test func execGuestClaimRemovalCrashAndABAKeepJournalUntilExactReplay() throws {
        struct InjectedCrash: Error {}

        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerID = "exec-removal-replay"
        let execID = "exec-removal-replay"
        let containerURL = root.appending(path: "containers/\(containerID)")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let containerDirectory = try PersistentStateDirectory.open(containerURL)
        let prepared = try makePreparedState(in: containerDirectory, containerID: containerID)
        let io = try containerDirectory.openDirectory(named: "io")
        var transaction: RawPreparedExecArtifacts? = try RawExecArtifactTransaction.prepare(
            containerID: containerID,
            execID: execID,
            attachStdin: true,
            in: containerDirectory,
            artifacts: prepared.artifacts
        )
        let record = try #require(transaction?.record)
        let claim = RawExecArtifactTransaction.guestClaim(for: record)
        let names = Array(RawExecArtifactRecord.expectedNames(execID: execID).prefix(4))
        transaction = nil
        try linkGuestIOClaims(claim, names: names, in: io)

        let guestName = RawContainerDirectIOHandles.guestClaimName(claim, index: 0)
        let removalName = RawContainerDirectIOHandles.guestClaimRemovalName(claim, index: 0)
        #expect(throws: InjectedCrash.self) {
            try RawExecArtifactTransaction.cleanup(
                containerID: containerID,
                execID: execID,
                in: containerDirectory,
                artifacts: prepared.artifacts,
                hook: { boundary in
                    guard boundary == .deletionClaimed(guestName) else { return }
                    throw InjectedCrash()
                }
            )
        }
        #expect(try io.entryMetadata(named: guestName) == nil)
        #expect(try io.entryMetadata(named: removalName)?.identity
            == record.fileIdentities[names[0]])
        #expect(try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: execID,
            in: containerDirectory,
            artifacts: prepared.artifacts
        ) == record)

        let removalURL = io.url.appending(path: removalName)
        let retainedOwnedURL = io.url.appending(path: "retained-owned-removal")
        let foreign = Data("foreign-removal-must-remain".utf8)
        try FileManager.default.moveItem(at: removalURL, to: retainedOwnedURL)
        try foreign.write(to: removalURL)
        #expect(throws: EngineError.self) {
            try RawExecArtifactTransaction.cleanup(
                containerID: containerID,
                execID: execID,
                in: containerDirectory,
                artifacts: prepared.artifacts
            )
        }
        #expect(try Data(contentsOf: removalURL) == foreign)
        #expect(try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: execID,
            in: containerDirectory,
            artifacts: prepared.artifacts
        ) == record)

        try FileManager.default.moveItem(
            at: removalURL, to: io.url.appending(path: "retained-foreign-removal")
        )
        try FileManager.default.moveItem(at: retainedOwnedURL, to: removalURL)
        let boundaryOwnedURL = io.url.appending(path: "boundary-owned-removal")
        #expect(throws: EngineError.self) {
            try RawExecArtifactTransaction.cleanup(
                containerID: containerID,
                execID: execID,
                in: containerDirectory,
                artifacts: prepared.artifacts,
                hook: { boundary in
                    guard boundary == .deletionClaimed(guestName) else { return }
                    try FileManager.default.moveItem(
                        at: removalURL, to: boundaryOwnedURL
                    )
                    try foreign.write(to: removalURL)
                }
            )
        }
        #expect(try Data(contentsOf: io.url.appending(path: guestName)) == foreign)
        #expect(FileManager.default.fileExists(atPath: boundaryOwnedURL.path))
        #expect(try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: execID,
            in: containerDirectory,
            artifacts: prepared.artifacts
        ) == record)

        try FileManager.default.moveItem(
            at: io.url.appending(path: guestName),
            to: io.url.appending(path: "boundary-foreign-removal")
        )
        try FileManager.default.moveItem(at: boundaryOwnedURL, to: removalURL)
        try RawExecArtifactTransaction.cleanup(
            containerID: containerID,
            execID: execID,
            in: containerDirectory,
            artifacts: prepared.artifacts
        )
        #expect(try io.entryMetadata(named: guestName) == nil)
        #expect(try io.entryMetadata(named: removalName) == nil)
        #expect(try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: execID,
            in: containerDirectory,
            artifacts: prepared.artifacts
        ) == nil)
    }

    @Test func guestIOClaimCleanupRejectsBoundaryReplacementWithoutDeletingIt() throws {
        for prefix in ["", "exec-test-"] {
            let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: root) }
            let directory = try PersistentStateDirectory.open(root)
            let names = [
                "\(prefix)stdout", "\(prefix)stderr", "\(prefix)stdin", "\(prefix)stdin.closed",
            ]
            var identities: [String: PersistentFileIdentity] = [:]
            for (index, name) in names.enumerated() {
                identities[name] = try directory.createSparseRegularFile(named: name, size: 0)
                try FileManager.default.linkItem(
                    at: root.appending(path: name),
                    to: root.appending(path: RawContainerDirectIOHandles.guestClaimName(
                        "claim", index: index
                    ))
                )
            }
            let claimName = RawContainerDirectIOHandles.guestClaimName("claim", index: 0)
            let claimURL = root.appending(path: claimName)
            let retainedClaimURL = root.appending(path: "retained-claim")
            let replacementURL = root.appending(path: "replacement")
            let replacementData = Data("replacement-must-remain".utf8)
            try replacementData.write(to: replacementURL)

            #expect(throws: EngineError.self) {
                try RawContainerDirectIOHandles.consumeGuestClaims(
                    "claim", names: names, identities: identities, in: directory,
                    beforeClaimRemoval: { index in
                        guard index == 0 else { return }
                        try FileManager.default.moveItem(at: claimURL, to: retainedClaimURL)
                        try FileManager.default.moveItem(at: replacementURL, to: claimURL)
                    }
                )
            }
            #expect(try Data(contentsOf: claimURL) == replacementData)
            #expect(FileManager.default.fileExists(atPath: retainedClaimURL.path))
        }
    }

    @Test func inputClosedPublicationUsesRetainedMarkerInode() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = try PersistentStateDirectory.open(root)
        let identity = try directory.createSparseRegularFile(named: "stdin.closed", size: 0)
        let marker = try directory.openRegularFile(
            named: "stdin.closed", expectedIdentity: identity, access: .readWrite
        ).handle
        let markerURL = root.appending(path: "stdin.closed")
        let retainedURL = root.appending(path: "retained-stdin.closed")
        try FileManager.default.moveItem(at: markerURL, to: retainedURL)
        try Data("replacement".utf8).write(to: markerURL)

        try RawContainerDirectIOHandles.markInputClosed(marker)

        #expect(try Data(contentsOf: retainedURL) == Data([1]))
        #expect(try Data(contentsOf: markerURL) == Data("replacement".utf8))
    }

    @Test func directIOResetSynchronizesCanonicalFilesBeforeEpochAndRecoversRetry() throws {
        struct SimulatedCrash: Error {}

        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = try PersistentStateDirectory.open(root)
        let artifacts = try RawContainerPreparationArtifacts.create(
            in: directory, rootDiskSize: 4_096
        )
        let handles = try RawContainerDirectIOHandles.open(
            in: directory, artifacts: artifacts
        )
        let historical = Data("historical-session".utf8)
        try handles.stdout.write(contentsOf: historical)
        try handles.stdout.synchronize()
        let initialLogs = try handles.openDockerLogs(artifacts: artifacts)
        let initialBridge = ContainerIOBridge(
            tty: true, logHandle: initialLogs.log, logIndexHandle: initialLogs.index
        )
        try initialBridge.beginSourceSession()
        try initialBridge.writer(.stdout).write(historical)

        var boundaries: [RawIOSourceSessionResetBoundary] = []
        #expect(throws: SimulatedCrash.self) {
            try handles.resetSourceSession(
                artifacts: artifacts,
                openStdin: false,
                bridge: initialBridge,
                hook: { boundary in
                    boundaries.append(boundary)
                    if boundary == .epochWillAppend { throw SimulatedCrash() }
                }
            )
        }

        let epochBoundary = try #require(boundaries.firstIndex(of: .epochWillAppend))
        let synchronizedNames = boundaries.compactMap { boundary -> String? in
            guard case .directIOSynchronized(let name) = boundary else { return nil }
            return name
        }
        #expect(synchronizedNames == RawContainerPreparationArtifacts.directIOFileNames)
        for name in RawContainerPreparationArtifacts.directIOFileNames {
            let syncBoundary = try #require(
                boundaries.firstIndex(of: .directIOSynchronized(name))
            )
            #expect(syncBoundary < epochBoundary)
        }
        let inputClosedBoundary = try #require(
            boundaries.firstIndex(of: .inputClosedSynchronized)
        )
        #expect(inputClosedBoundary < epochBoundary)
        #expect(!boundaries.contains(.epochAppended))
        var stdoutMetadata = stat()
        #expect(Darwin.fstat(handles.stdout.fileDescriptor, &stdoutMetadata) == 0)
        #expect(stdoutMetadata.st_size == 0)
        var inputClosedMetadata = stat()
        #expect(Darwin.fstat(handles.stdinClosed.fileDescriptor, &inputClosedMetadata) == 0)
        #expect(inputClosedMetadata.st_size == 1)

        let crashRecoveryLogs = try handles.openDockerLogs(artifacts: artifacts)
        let crashRecoveryBridge = ContainerIOBridge(
            tty: true,
            logHandle: crashRecoveryLogs.log,
            logIndexHandle: crashRecoveryLogs.index
        )
        let preRetryOffsets = try #require(crashRecoveryBridge.durableSourceByteOffsets())
        #expect(preRetryOffsets[.stdout] == UInt64(historical.count))

        boundaries.removeAll()
        try handles.resetSourceSession(
            artifacts: artifacts,
            openStdin: false,
            bridge: crashRecoveryBridge,
            hook: { boundaries.append($0) }
        )
        #expect(boundaries.last == .epochAppended)
        let retriedLogs = try handles.openDockerLogs(artifacts: artifacts)
        let retriedBridge = ContainerIOBridge(
            tty: true, logHandle: retriedLogs.log, logIndexHandle: retriedLogs.index
        )
        let postRetryOffsets = try #require(retriedBridge.durableSourceByteOffsets())
        #expect(postRetryOffsets[.stdout] == 0)

        let current = Data("current-session".utf8)
        try retriedBridge.writer(.stdout).write(current)
        let finalLogs = try handles.openDockerLogs(artifacts: artifacts)
        let finalBridge = ContainerIOBridge(
            tty: true, logHandle: finalLogs.log, logIndexHandle: finalLogs.index
        )
        let finalOffsets = try #require(finalBridge.durableSourceByteOffsets())
        #expect(finalOffsets[.stdout] == UInt64(current.count))
        #expect(try finalBridge.logData() == historical + current)
    }

    @Test func directoryTransferRejectsRenamedDestinationWithoutWritingReplacement() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let sourceURL = root.appending(path: "source")
        let parentURL = root.appending(path: "io")
        let outsideURL = root.appending(path: "outside")
        try FileManager.default.createDirectory(
            at: sourceURL, withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(at: parentURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: outsideURL, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try Data("retained".utf8).write(to: sourceURL.appending(path: "payload"))
        let source = try PersistentStateDirectory.open(sourceURL)
        let parent = try PersistentStateDirectory.open(parentURL)
        let destination = try parent.createDirectory(named: "transfer")
        let detachedURL = parentURL.appending(path: "detached")
        var replaced = false

        #expect(throws: EngineError.self) {
            try RawDirectoryTransfer.copyContents(
                from: source,
                to: destination,
                validateRoots: {
                    guard let current = try parent.entryMetadata(named: "transfer"),
                          current.identity == destination.identity,
                          current.type == S_IFDIR else {
                        throw EngineError(.conflict, "transfer changed")
                    }
                },
                hook: { boundary in
                    guard boundary == .entryOpened("payload"), !replaced else { return }
                    replaced = true
                    try FileManager.default.moveItem(at: destination.url, to: detachedURL)
                    try FileManager.default.createSymbolicLink(
                        at: destination.url, withDestinationURL: outsideURL
                    )
                }
            )
        }
        #expect(!FileManager.default.fileExists(
            atPath: outsideURL.appending(path: "payload").path
        ))
    }

    @Test func directoryTransferRejectsSubstitutedSourceWithoutReadingReplacement() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let parentURL = root.appending(path: "io")
        let destinationURL = root.appending(path: "destination")
        try FileManager.default.createDirectory(at: parentURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(
            at: destinationURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let parent = try PersistentStateDirectory.open(parentURL)
        let source = try parent.createDirectory(named: "transfer")
        _ = try source.createSparseRegularFile(named: "payload", size: 0)
        let sourceFile = try source.openRegularFile(
            named: "payload", access: .writeOnly
        ).handle
        try sourceFile.write(contentsOf: Data("retained".utf8))
        try sourceFile.synchronize()
        let destination = try PersistentStateDirectory.open(destinationURL)
        let detachedURL = parentURL.appending(path: "detached")
        var replaced = false

        #expect(throws: EngineError.self) {
            try RawDirectoryTransfer.copyContents(
                from: source,
                to: destination,
                validateRoots: {
                    guard let current = try parent.entryMetadata(named: "transfer"),
                          current.identity == source.identity,
                          current.type == S_IFDIR else {
                        throw EngineError(.conflict, "transfer changed")
                    }
                },
                hook: { boundary in
                    guard boundary == .entryOpened("payload"), !replaced else { return }
                    replaced = true
                    try FileManager.default.moveItem(at: source.url, to: detachedURL)
                    try FileManager.default.createDirectory(
                        at: source.url, withIntermediateDirectories: false
                    )
                    try Data("substitute".utf8).write(
                        to: source.url.appending(path: "payload")
                    )
                }
            )
        }
        let copied = try Data(contentsOf: destinationURL.appending(path: "payload"))
        #expect(copied.isEmpty)
        #expect(try Data(contentsOf: source.url.appending(path: "payload"))
            == Data("substitute".utf8))
    }

    @Test func directoryTransferPreservesSymlinkWithoutFollowingIt() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let sourceURL = root.appending(path: "source")
        let destinationURL = root.appending(path: "destination")
        let sentinelURL = root.appending(path: "sentinel")
        try FileManager.default.createDirectory(
            at: sourceURL, withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: destinationURL, withIntermediateDirectories: true
        )
        try Data("sentinel".utf8).write(to: sentinelURL)
        try FileManager.default.createSymbolicLink(
            at: sourceURL.appending(path: "link"), withDestinationURL: sentinelURL
        )
        defer { try? FileManager.default.removeItem(at: root) }

        try RawDirectoryTransfer.copyContents(
            from: PersistentStateDirectory.open(sourceURL),
            to: PersistentStateDirectory.open(destinationURL)
        )
        var information = stat()
        #expect(Darwin.lstat(
            destinationURL.appending(path: "link").path, &information
        ) == 0)
        #expect(information.st_mode & S_IFMT == S_IFLNK)
        #expect(try FileManager.default.destinationOfSymbolicLink(
            atPath: destinationURL.appending(path: "link").path
        ) == sentinelURL.path)
        #expect(try Data(contentsOf: sentinelURL) == Data("sentinel".utf8))
    }

    @Test func directoryTransferPinsSourceSymlinkAcrossTargetABA() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let sourceURL = root.appending(path: "source")
        let destinationURL = root.appending(path: "destination")
        for directory in [sourceURL, destinationURL] {
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true
            )
        }
        defer { try? FileManager.default.removeItem(at: root) }
        let linkURL = sourceURL.appending(path: "link")
        let retainedURL = sourceURL.appending(path: "retained")
        try FileManager.default.createSymbolicLink(
            atPath: linkURL.path, withDestinationPath: "safe-target"
        )
        var replaced = false

        try RawDirectoryTransfer.copyContents(
            from: PersistentStateDirectory.open(sourceURL),
            to: PersistentStateDirectory.open(destinationURL),
            hook: { boundary in
                guard boundary == .entryOpened("link"), !replaced else { return }
                replaced = true
                try FileManager.default.moveItem(at: linkURL, to: retainedURL)
                try FileManager.default.createSymbolicLink(
                    atPath: linkURL.path, withDestinationPath: "attacker-target"
                )
                try FileManager.default.removeItem(at: linkURL)
                try FileManager.default.moveItem(at: retainedURL, to: linkURL)
            }
        )

        #expect(try FileManager.default.destinationOfSymbolicLink(
            atPath: destinationURL.appending(path: "link").path
        ) == "safe-target")
    }

    @Test func directoryTransferRejectsCreatedFileReplacementWithoutWritingIt() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let sourceURL = root.appending(path: "source")
        let destinationURL = root.appending(path: "destination")
        for directory in [sourceURL, destinationURL] {
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true
            )
        }
        defer { try? FileManager.default.removeItem(at: root) }
        try Data("safe".utf8).write(to: sourceURL.appending(path: "payload"))
        let targetURL = destinationURL.appending(path: "payload")
        let retainedURL = destinationURL.appending(path: "retained")
        let replacement = Data("replacement-must-remain".utf8)
        var replaced = false

        #expect(throws: EngineError.self) {
            try RawDirectoryTransfer.copyContents(
                from: PersistentStateDirectory.open(sourceURL),
                to: PersistentStateDirectory.open(destinationURL),
                hook: { boundary in
                    guard boundary == .destinationCreated("payload"), !replaced else { return }
                    replaced = true
                    try FileManager.default.moveItem(at: targetURL, to: retainedURL)
                    try replacement.write(to: targetURL)
                }
            )
        }
        #expect(try Data(contentsOf: targetURL) == replacement)
        #expect(try Data(contentsOf: retainedURL) == Data("safe".utf8))
    }

    @Test func directoryTransferRejectsCreatedSymlinkReplacement() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let sourceURL = root.appending(path: "source")
        let destinationURL = root.appending(path: "destination")
        for directory in [sourceURL, destinationURL] {
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true
            )
        }
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createSymbolicLink(
            atPath: sourceURL.appending(path: "link").path,
            withDestinationPath: "safe-target"
        )
        let targetURL = destinationURL.appending(path: "link")
        let retainedURL = destinationURL.appending(path: "retained")
        var replaced = false

        #expect(throws: EngineError.self) {
            try RawDirectoryTransfer.copyContents(
                from: PersistentStateDirectory.open(sourceURL),
                to: PersistentStateDirectory.open(destinationURL),
                hook: { boundary in
                    guard boundary == .destinationCreated("link"), !replaced else { return }
                    replaced = true
                    try FileManager.default.moveItem(at: targetURL, to: retainedURL)
                    try FileManager.default.createSymbolicLink(
                        atPath: targetURL.path, withDestinationPath: "attacker-target"
                    )
                }
            )
        }
        #expect(try FileManager.default.destinationOfSymbolicLink(
            atPath: targetURL.path
        ) == "attacker-target")
        #expect(try FileManager.default.destinationOfSymbolicLink(
            atPath: retainedURL.path
        ) == "safe-target")
    }

    @Test func directoryTransferPreservesModesAcrossCopyInAndCopyOutStaging() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let sourceURL = root.appending(path: "source")
        let transferURL = root.appending(path: "transfer")
        let destinationURL = root.appending(path: "destination")
        for directory in [sourceURL, transferURL, destinationURL] {
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true
            )
        }
        defer { try? FileManager.default.removeItem(at: root) }
        let nestedURL = sourceURL.appending(path: "nested")
        try FileManager.default.createDirectory(
            at: nestedURL, withIntermediateDirectories: false
        )
        let payloadURL = nestedURL.appending(path: "payload")
        try Data("mode".utf8).write(to: payloadURL)
        #expect(Darwin.chmod(nestedURL.path, 0o710) == 0)
        #expect(Darwin.chmod(payloadURL.path, 0o751) == 0)

        try RawDirectoryTransfer.copyContents(
            from: PersistentStateDirectory.open(sourceURL),
            to: PersistentStateDirectory.open(transferURL)
        )
        try RawDirectoryTransfer.copyContents(
            from: PersistentStateDirectory.open(transferURL),
            to: PersistentStateDirectory.open(destinationURL)
        )

        for base in [transferURL, destinationURL] {
            var directoryInformation = stat()
            var fileInformation = stat()
            #expect(Darwin.lstat(base.appending(path: "nested").path, &directoryInformation) == 0)
            #expect(Darwin.lstat(
                base.appending(path: "nested/payload").path, &fileInformation
            ) == 0)
            #expect(directoryInformation.st_mode & mode_t(0o7777) == mode_t(0o710))
            #expect(fileInformation.st_mode & mode_t(0o7777) == mode_t(0o751))
        }
    }

    @Test func shimAttachmentDescriptorsKeepOriginalRootAndShareAfterPathReplacement() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let diskURL = root.appending(path: "root.ext4")
        let volumeURL = root.appending(path: "volume.ext4")
        let shareURL = root.appending(path: "io")
        try FileManager.default.createDirectory(at: shareURL, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try Data("original-disk".utf8).write(to: diskURL)
        try Data("original-volume".utf8).write(to: volumeURL)
        try Data("original-share".utf8).write(to: shareURL.appending(path: "marker"))
        let rootDirectory = try PersistentStateDirectory.open(root)
        let diskIdentity = try rootDirectory.regularFileIdentity(named: "root.ext4")
        let volumeIdentity = try rootDirectory.regularFileIdentity(named: "volume.ext4")
        let shareIdentity = try PersistentStateDirectory.open(shareURL).identity
        let specification = VMShimProtocol.Specification(
            containerID: "descriptor-attachments",
            generation: 1,
            token: "descriptor-token",
            kernelPath: "/kernel",
            initialRamdiskPath: "/initramfs",
            rootDiskPath: diskURL.path,
            rootDiskIdentity: .init(
                device: diskIdentity.device, inode: diskIdentity.inode
            ),
            rootDiskSize: UInt64(Data("original-disk".utf8).count),
            volumeDisks: [.init(
                name: "data",
                path: volumeURL.path,
                identity: .init(
                    device: volumeIdentity.device, inode: volumeIdentity.inode
                ),
                size: UInt64(Data("original-volume".utf8).count)
            )],
            cpus: 1,
            memoryBytes: 512 * 1_024 * 1_024,
            macAddress: "02:ce:00:00:00:01",
            bindShares: [.init(
                tag: "cengine-io",
                source: shareURL.path,
                readOnly: false,
                sourceIdentity: .init(
                    device: shareIdentity.device, inode: shareIdentity.inode
                )
            )],
            socketPath: "/tmp/descriptor.sock",
            logPath: root.appending(path: "shim.log").path
        )
        let attachments = try VMShimAttachmentResolver.resolve(specification)
        let retainedDiskURL = root.appending(path: "retained-root.ext4")
        let retainedVolumeURL = root.appending(path: "retained-volume.ext4")
        let retainedShareURL = root.appending(path: "retained-io")
        try FileManager.default.moveItem(at: diskURL, to: retainedDiskURL)
        try Data("replacement-disk".utf8).write(to: diskURL)
        try FileManager.default.moveItem(at: volumeURL, to: retainedVolumeURL)
        try Data("replacement-volume".utf8).write(to: volumeURL)
        try FileManager.default.moveItem(at: shareURL, to: retainedShareURL)
        try FileManager.default.createDirectory(
            at: shareURL, withIntermediateDirectories: false
        )
        try Data("replacement-share".utf8).write(to: shareURL.appending(path: "marker"))

        #expect(attachments.rootDisk.path.hasPrefix("/dev/fd/"))
        #expect(try Data(contentsOf: attachments.rootDisk) == Data("original-disk".utf8))
        let volume = try #require(attachments.additionalDisks.first)
        #expect(volume.source.path.hasPrefix("/dev/fd/"))
        #expect(try Data(contentsOf: volume.source) == Data("original-volume".utf8))
        let share = try #require(attachments.bindShares.first)
        #expect(share.source.path.hasPrefix("/.vol/"))
        #expect(try Data(contentsOf: share.source.appending(path: "marker"))
            == Data("original-share".utf8))
        let shareHandle = try #require(attachments.retainedHandles.last)
        let markerDescriptor = Darwin.openat(
            shareHandle.fileDescriptor,
            "marker",
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC
        )
        #expect(markerDescriptor >= 0)
        if markerDescriptor >= 0 {
            let marker = FileHandle(fileDescriptor: markerDescriptor, closeOnDealloc: true)
            #expect(try marker.readToEnd() == Data("original-share".utf8))
        }
    }

    @Test func shimAttachmentResolverRejectsRootAndBindSwapAtOpenBoundary() throws {
        for swappedBoundary in [
            VMShimAttachmentBoundary.rootDiskOpened,
            .bindShareOpened("cengine-io"),
        ] {
            let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
            let diskURL = root.appending(path: "root.ext4")
            let shareURL = root.appending(path: "io")
            try FileManager.default.createDirectory(
                at: shareURL, withIntermediateDirectories: true
            )
            defer { try? FileManager.default.removeItem(at: root) }
            try Data("original".utf8).write(to: diskURL)
            let rootDirectory = try PersistentStateDirectory.open(root)
            let diskIdentity = try rootDirectory.regularFileIdentity(named: "root.ext4")
            let shareIdentity = try PersistentStateDirectory.open(shareURL).identity
            let specification = VMShimProtocol.Specification(
                containerID: "swap-attachments",
                generation: 1,
                token: "swap-token",
                kernelPath: "/kernel",
                initialRamdiskPath: "/initramfs",
                rootDiskPath: diskURL.path,
                rootDiskIdentity: .init(
                    device: diskIdentity.device, inode: diskIdentity.inode
                ),
                rootDiskSize: UInt64(Data("original".utf8).count),
                cpus: 1,
                memoryBytes: 512 * 1_024 * 1_024,
                macAddress: "02:ce:00:00:00:01",
                bindShares: [.init(
                    tag: "cengine-io",
                    source: shareURL.path,
                    readOnly: false,
                    sourceIdentity: .init(
                        device: shareIdentity.device, inode: shareIdentity.inode
                    )
                )],
                socketPath: "/tmp/swap.sock",
                logPath: root.appending(path: "shim.log").path
            )

            #expect(throws: EngineError.self) {
                _ = try VMShimAttachmentResolver.resolve(specification) { boundary in
                    guard boundary == swappedBoundary else { return }
                    switch boundary {
                    case .rootDiskOpened:
                        try FileManager.default.moveItem(
                            at: diskURL, to: root.appending(path: "retained-root.ext4")
                        )
                        try Data("replacement".utf8).write(to: diskURL)
                    case .bindShareOpened:
                        try FileManager.default.moveItem(
                            at: shareURL, to: root.appending(path: "retained-io")
                        )
                        try FileManager.default.createDirectory(
                            at: shareURL, withIntermediateDirectories: false
                        )
                    case .volumeDiskOpened:
                        return
                    }
                }
            }
        }
    }

    @Test func shimAttachmentResolverRejectsSameInodeRootSizeChange() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let diskURL = root.appending(path: "root.ext4")
        try Data(repeating: 0, count: 4_096).write(to: diskURL)
        let directory = try PersistentStateDirectory.open(root)
        let identity = try directory.regularFileIdentity(
            named: "root.ext4", expectedSize: 4_096
        )
        let writer = try FileHandle(forUpdating: diskURL)
        let specification = VMShimProtocol.Specification(
            containerID: "root-size-swap",
            generation: 1,
            token: "root-size-token",
            kernelPath: "/kernel",
            initialRamdiskPath: "/initramfs",
            rootDiskPath: diskURL.path,
            rootDiskIdentity: .init(device: identity.device, inode: identity.inode),
            rootDiskSize: 4_096,
            cpus: 1,
            memoryBytes: 512 * 1_024 * 1_024,
            macAddress: "02:ce:00:00:00:01",
            socketPath: "/tmp/root-size.sock",
            logPath: root.appending(path: "shim.log").path
        )

        #expect(throws: EngineError.self) {
            _ = try VMShimAttachmentResolver.resolve(specification) { boundary in
                guard boundary == .rootDiskOpened else { return }
                #expect(Darwin.ftruncate(writer.fileDescriptor, 2_048) == 0)
            }
        }
    }

    @Test func storageShimAttachmentRequiresAndRetainsExactRootDisk() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let diskURL = root.appending(path: "volumes.ext4")
        let retainedURL = root.appending(path: "retained-volumes.ext4")
        let replacement = Data(repeating: 0x52, count: 4_096)
        try Data(repeating: 0x4f, count: 4_096).write(to: diskURL)
        let directory = try PersistentStateDirectory.open(root)
        let identity = try directory.regularFileIdentity(
            named: "volumes.ext4", expectedSize: 4_096
        )
        func specification(identity included: Bool = true) -> VMShimProtocol.Specification {
            VMShimProtocol.Specification(
                kind: .storage,
                containerID: "storage-root",
                generation: 1,
                token: "storage-token",
                kernelPath: "/kernel",
                initialRamdiskPath: "/initramfs",
                rootDiskPath: diskURL.path,
                rootDiskIdentity: included
                    ? .init(device: identity.device, inode: identity.inode) : nil,
                rootDiskSize: included ? 4_096 : nil,
                cpus: 1,
                memoryBytes: 512 * 1_024 * 1_024,
                macAddress: "02:ce:00:00:00:01",
                socketPath: "/tmp/storage-root.sock",
                logPath: root.appending(path: "shim.log").path
            )
        }

        #expect(throws: EngineError.self) {
            _ = try VMShimAttachmentResolver.resolve(specification(identity: false))
        }
        #expect(throws: EngineError.self) {
            _ = try VMShimAttachmentResolver.resolve(specification()) { boundary in
                guard boundary == .rootDiskOpened else { return }
                try FileManager.default.moveItem(at: diskURL, to: retainedURL)
                try replacement.write(to: diskURL)
            }
        }
        #expect(try Data(contentsOf: diskURL) == replacement)
        #expect(try Data(contentsOf: retainedURL) == Data(repeating: 0x4f, count: 4_096))
    }

    @Test func shimAttachmentResolverRejectsVolumeSymlinkSwapWithoutTouchingTarget() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let rootDiskURL = root.appending(path: "root.ext4")
        let volumeURL = root.appending(path: "volume.ext4")
        let sentinelURL = root.appending(path: "sentinel")
        try Data(repeating: 0, count: 4_096).write(to: rootDiskURL)
        try Data(repeating: 1, count: 8_192).write(to: volumeURL)
        let sentinel = Data("must-not-change".utf8)
        try sentinel.write(to: sentinelURL)
        let directory = try PersistentStateDirectory.open(root)
        let rootIdentity = try directory.regularFileIdentity(
            named: "root.ext4", expectedSize: 4_096
        )
        let volumeIdentity = try directory.regularFileIdentity(
            named: "volume.ext4", expectedSize: 8_192
        )
        let specification = VMShimProtocol.Specification(
            containerID: "volume-swap",
            generation: 1,
            token: "volume-token",
            kernelPath: "/kernel",
            initialRamdiskPath: "/initramfs",
            rootDiskPath: rootDiskURL.path,
            rootDiskIdentity: .init(
                device: rootIdentity.device, inode: rootIdentity.inode
            ),
            rootDiskSize: 4_096,
            volumeDisks: [.init(
                name: "data",
                path: volumeURL.path,
                identity: .init(
                    device: volumeIdentity.device, inode: volumeIdentity.inode
                ),
                size: 8_192
            )],
            cpus: 1,
            memoryBytes: 512 * 1_024 * 1_024,
            macAddress: "02:ce:00:00:00:01",
            socketPath: "/tmp/volume-swap.sock",
            logPath: root.appending(path: "shim.log").path
        )

        #expect(throws: EngineError.self) {
            _ = try VMShimAttachmentResolver.resolve(specification) { boundary in
                guard boundary == .volumeDiskOpened("data") else { return }
                try FileManager.default.moveItem(
                    at: volumeURL, to: root.appending(path: "retained-volume.ext4")
                )
                try FileManager.default.createSymbolicLink(
                    at: volumeURL, withDestinationURL: sentinelURL
                )
            }
        }
        #expect(try Data(contentsOf: sentinelURL) == sentinel)
    }

    @Test func completedRawDeletionSupportsDeleteAndDeleteLogsRetryOnlyForExactInstance() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containersURL = root.appending(path: "containers")
        let receiptsURL = root.appending(path: "deleted-containers")
        try FileManager.default.createDirectory(
            at: containersURL, withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: receiptsURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let containers = try PersistentStateDirectory.open(containersURL)
        let receipts = try PersistentStateDirectory.open(receiptsURL)
        let container = ContainerRecord(
            id: "deleted-retry", name: "deleted-retry", image: "alpine"
        )
        let directory = try containers.createDirectory(named: container.id)
        try RawDeletedContainerCoordinator.record(
            container, directoryIdentity: directory.identity, in: receipts
        )
        try containers.disposeDirectory(
            named: container.id, expectedIdentity: directory.identity
        )

        // The first call models a retry of Raw.delete; the second models the
        // following Raw.deleteLogs after a later removal stage failed.
        try RawDeletedContainerCoordinator.requireCompletedDeletion(
            of: container, in: containers, receipts: receipts
        )
        try RawDeletedContainerCoordinator.requireCompletedDeletion(
            of: container, in: containers, receipts: receipts
        )

        let wrongInstance = ContainerRecord(
            id: container.id,
            instanceID: UUID(),
            name: container.name,
            image: container.image
        )
        #expect(throws: EngineError.self) {
            try RawDeletedContainerCoordinator.requireCompletedDeletion(
                of: wrongInstance, in: containers, receipts: receipts
            )
        }
        _ = try containers.createDirectory(named: container.id)
        #expect(throws: EngineError.self) {
            try RawDeletedContainerCoordinator.requireCompletedDeletion(
                of: container, in: containers, receipts: receipts
            )
        }
    }

    @Test func rawDeleteRejectsStaleInstanceDuringFreshPreparationWindow() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containersURL = root.appending(path: "containers")
        try FileManager.default.createDirectory(
            at: containersURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let containers = try PersistentStateDirectory.open(containersURL)
        let replacement = ContainerRecord(
            id: "prepublication-replacement",
            name: "prepublication-replacement",
            image: "alpine"
        )
        let stale = ContainerRecord(
            id: replacement.id,
            instanceID: UUID(),
            name: replacement.name,
            image: replacement.image
        )
        let directory = try containers.createDirectory(named: replacement.id)
        try Data("replacement-owned".utf8).write(
            to: directory.url.appending(path: "sentinel")
        )
        var terminationAttempted = false
        var disposalAttempted = false

        #expect(throws: BackendResourceRollbackIncompleteError.self) {
            try RawContainerInstanceCoordinator.requireNoConflictingFreshPreparation(
                of: stale,
                in: [replacement.id: replacement.instanceID]
            )
            terminationAttempted = true
            disposalAttempted = true
            try containers.disposeDirectory(
                named: replacement.id, expectedIdentity: directory.identity
            )
        }
        #expect(!terminationAttempted)
        #expect(!disposalAttempted)
        #expect(directory.pathStillNamesThisDirectory())
        #expect(
            try Data(contentsOf: directory.url.appending(path: "sentinel"))
                == Data("replacement-owned".utf8)
        )

        try RawContainerInstanceCoordinator.requireNoConflictingFreshPreparation(
            of: replacement,
            in: [replacement.id: replacement.instanceID]
        )
    }

    @Test func staleRawDeleteLogsPreservesReplacementMonitorBridgeAndOutput() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containersURL = root.appending(path: "containers")
        let receiptsURL = root.appending(path: "deleted-containers")
        try FileManager.default.createDirectory(
            at: containersURL, withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: receiptsURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let containers = try PersistentStateDirectory.open(containersURL)
        let receipts = try PersistentStateDirectory.open(receiptsURL)
        let replacementDirectory = try containers.createDirectory(named: "logs-replacement")
        let replacement = try makePreparedState(
            in: replacementDirectory, containerID: "logs-replacement"
        )
        let stale = ContainerRecord(
            id: replacement.currentContainer.id,
            instanceID: UUID(),
            name: replacement.currentContainer.name,
            image: replacement.currentContainer.image
        )
        let ioDirectory = try replacementDirectory.openDirectory(named: "io")
        let stdout = try ioDirectory.openRegularFile(
            named: "stdout",
            expectedIdentity: replacement.artifacts.ioFileIdentities["stdout"],
            access: .readWrite
        ).handle
        let canonicalOutput = Data("replacement-output".utf8)
        try stdout.write(contentsOf: canonicalOutput)
        try stdout.synchronize()

        let bridge = ContainerIOBridge(tty: true)
        let monitor = ContainerLogMonitor(
            stdout: FileHandle.nullDevice,
            stderr: FileHandle.nullDevice,
            input: FileHandle.nullDevice,
            bridge: bridge
        )
        var retainedIdentities: [String: PersistentFileIdentity] = [:]
        var logMonitors = [replacement.currentContainer.id: monitor]
        var bridges = [replacement.currentContainer.id: bridge]

        #expect(throws: BackendResourceRollbackIncompleteError.self) {
            try RawVirtualizationBackend.deleteContainerLogs(
                for: stale,
                in: containers,
                receipts: receipts,
                freshPreparationInstances: [:],
                retainedIdentities: &retainedIdentities,
                logMonitors: &logMonitors,
                bridges: &bridges
            )
        }
        #expect(logMonitors[replacement.currentContainer.id].map { $0 === monitor } == true)
        #expect(bridges[replacement.currentContainer.id].map { $0 === bridge } == true)
        #expect(retainedIdentities.isEmpty)
        let persistedOutput = try ioDirectory.openRegularFile(
            named: "stdout",
            expectedIdentity: replacement.artifacts.ioFileIdentities["stdout"],
            access: .readOnly
        ).handle
        #expect(try persistedOutput.readToEnd() == canonicalOutput)

        let outputArrived = DispatchSemaphore(value: 0)
        let outputClosed = DispatchSemaphore(value: 0)
        let bridgeProbe = Data("bridge-still-open".utf8)
        _ = bridge.attach(
            replayBuffered: false,
            output: { data in
                if data == bridgeProbe { outputArrived.signal() }
            },
            closed: { outputClosed.signal() }
        )
        try bridge.writer(.stdout).write(bridgeProbe)
        #expect(blockingSemaphoreWait(outputArrived))
        #expect(outputClosed.wait(timeout: .now() + .milliseconds(25)) == .timedOut)

        let deleted = ContainerRecord(
            id: "completed-log-deletion",
            name: "completed-log-deletion",
            image: "alpine"
        )
        let deletedDirectory = try containers.createDirectory(named: deleted.id)
        try RawDeletedContainerCoordinator.record(
            deleted, directoryIdentity: deletedDirectory.identity, in: receipts
        )
        try containers.disposeDirectory(
            named: deleted.id, expectedIdentity: deletedDirectory.identity
        )
        let wrongCompletedInstance = ContainerRecord(
            id: deleted.id,
            instanceID: UUID(),
            name: deleted.name,
            image: deleted.image
        )
        let completedBridge = ContainerIOBridge(tty: true)
        let completedMonitor = ContainerLogMonitor(
            stdout: FileHandle.nullDevice,
            stderr: FileHandle.nullDevice,
            input: FileHandle.nullDevice,
            bridge: completedBridge
        )
        var completedRetained: [String: PersistentFileIdentity] = [:]
        var completedMonitors = [deleted.id: completedMonitor]
        var completedBridges = [deleted.id: completedBridge]
        #expect(throws: EngineError.self) {
            try RawVirtualizationBackend.deleteContainerLogs(
                for: wrongCompletedInstance,
                in: containers,
                receipts: receipts,
                freshPreparationInstances: [:],
                retainedIdentities: &completedRetained,
                logMonitors: &completedMonitors,
                bridges: &completedBridges
            )
        }
        #expect(completedMonitors[deleted.id].map { $0 === completedMonitor } == true)
        #expect(completedBridges[deleted.id].map { $0 === completedBridge } == true)

        try RawVirtualizationBackend.deleteContainerLogs(
            for: deleted,
            in: containers,
            receipts: receipts,
            freshPreparationInstances: [:],
            retainedIdentities: &completedRetained,
            logMonitors: &completedMonitors,
            bridges: &completedBridges
        )
        #expect(completedMonitors[deleted.id] == nil)
        #expect(completedBridges[deleted.id] == nil)
    }

    @Test func rawDeletionRetryFinishesRootClaimBeforePublishingSuccessOrReuse() throws {
        enum SimulatedCrash: Error { case injected }

        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containersURL = root.appending(path: "containers")
        let receiptsURL = root.appending(path: "deleted-containers")
        try FileManager.default.createDirectory(
            at: containersURL, withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: receiptsURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let containers = try PersistentStateDirectory.open(containersURL)
        let receipts = try PersistentStateDirectory.open(receiptsURL)
        let container = ContainerRecord(
            id: "claimed-deletion-retry",
            name: "claimed-deletion-retry",
            image: "alpine"
        )
        let directory = try containers.createDirectory(named: container.id)
        try FileManager.default.createDirectory(
            at: directory.url.appending(path: "nested"),
            withIntermediateDirectories: false
        )
        try Data("owned".utf8).write(
            to: directory.url.appending(path: "nested/sentinel")
        )
        try RawDeletedContainerCoordinator.record(
            container, directoryIdentity: directory.identity, in: receipts
        )
        var retainedIdentities = [container.id: directory.identity]
        var injected = false

        #expect(throws: BackendResourceRollbackIncompleteError.self) {
            try RawVirtualizationBackend.disposeContainerDirectory(
                container.id,
                expectedIdentity: directory.identity,
                in: containers,
                retainedIdentities: &retainedIdentities,
                hook: { boundary in
                    guard boundary == .rootClaimed, !injected else { return }
                    injected = true
                    throw SimulatedCrash.injected
                }
            )
        }
        #expect(injected)
        #expect(try containers.openDirectoryIfPresent(named: container.id) == nil)
        #expect(try containers.pendingDisposalIdentity(named: container.id) == directory.identity)
        #expect(retainedIdentities[container.id] == directory.identity)
        let interruptedNames = try containers.entryNames()
        #expect(interruptedNames.contains {
            $0.hasPrefix(".cengine-disposal-") && $0.hasSuffix(".json")
        })
        #expect(interruptedNames.contains { $0.hasPrefix(".cengine-disposal-claim-") })
        #expect(throws: EngineError.self) {
            try RawDeletedContainerCoordinator.requireCompletedDeletion(
                of: container, in: containers, receipts: receipts
            )
        }
        #expect(throws: EngineError.self) {
            try RawDeletedContainerCoordinator.clearForPreparation(
                of: container, in: containers, receipts: receipts
            )
        }

        let wrongInstance = ContainerRecord(
            id: container.id,
            instanceID: UUID(),
            name: container.name,
            image: container.image
        )
        #expect(throws: EngineError.self) {
            try RawVirtualizationBackend.completePendingContainerDeletion(
                of: wrongInstance,
                in: containers,
                receipts: receipts,
                retainedIdentities: &retainedIdentities
            )
        }
        #expect(try containers.pendingDisposalIdentity(named: container.id) == directory.identity)
        #expect(retainedIdentities[container.id] == directory.identity)

        // This is the exact helper shared by Raw.delete and Raw.deleteLogs when
        // the public container name disappeared before disposal completed.
        try RawVirtualizationBackend.completePendingContainerDeletion(
            of: container,
            in: containers,
            receipts: receipts,
            retainedIdentities: &retainedIdentities
        )
        #expect(try containers.pendingDisposalIdentity(named: container.id) == nil)
        #expect(try containers.entryNames().isEmpty)
        #expect(retainedIdentities[container.id] == nil)
        try RawDeletedContainerCoordinator.requireCompletedDeletion(
            of: container, in: containers, receipts: receipts
        )
        try RawDeletedContainerCoordinator.requireCompletedDeletion(
            of: container, in: containers, receipts: receipts
        )

        try RawDeletedContainerCoordinator.clearForPreparation(
            of: container, in: containers, receipts: receipts
        )
        let replacement = try RawFreshContainerStateCoordinator.acquire(
            in: containers, containerID: container.id
        )
        #expect(replacement.wasCreated)
        #expect(replacement.directory.identity != directory.identity)
        #expect(replacement.directory.pathStillNamesThisDirectory())
    }

    @Test func rawDeletionRetryClearsIdentityAfterDurableJournalRemoval() throws {
        enum SimulatedCrash: Error { case injected }

        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containersURL = root.appending(path: "containers")
        let receiptsURL = root.appending(path: "deleted-containers")
        try FileManager.default.createDirectory(
            at: containersURL, withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: receiptsURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let containers = try PersistentStateDirectory.open(containersURL)
        let receipts = try PersistentStateDirectory.open(receiptsURL)
        let container = ContainerRecord(
            id: "journal-retirement-retry",
            name: "journal-retirement-retry",
            image: "alpine"
        )
        let directory = try containers.createDirectory(named: container.id)
        try RawDeletedContainerCoordinator.record(
            container, directoryIdentity: directory.identity, in: receipts
        )
        var retainedIdentities = [container.id: directory.identity]
        var injected = false

        #expect(throws: BackendResourceRollbackIncompleteError.self) {
            try RawVirtualizationBackend.disposeContainerDirectory(
                container.id,
                expectedIdentity: directory.identity,
                in: containers,
                retainedIdentities: &retainedIdentities,
                hook: { boundary in
                    guard boundary == .journalRemovalSynchronized, !injected else { return }
                    injected = true
                    throw SimulatedCrash.injected
                }
            )
        }
        #expect(injected)
        #expect(try containers.openDirectoryIfPresent(named: container.id) == nil)
        #expect(try containers.pendingDisposalIdentity(named: container.id) == nil)
        #expect(try containers.containsDisposalClaim(identity: directory.identity) == false)
        #expect(retainedIdentities[container.id] == directory.identity)
        #expect(try containers.entryNames().contains { $0.hasSuffix(".claimed") })

        try RawVirtualizationBackend.completePendingContainerDeletion(
            of: container,
            in: containers,
            receipts: receipts,
            retainedIdentities: &retainedIdentities
        )
        #expect(retainedIdentities[container.id] == nil)
        try RawDeletedContainerCoordinator.requireCompletedDeletion(
            of: container, in: containers, receipts: receipts
        )
        try RawDeletedContainerCoordinator.clearForPreparation(
            of: container, in: containers, receipts: receipts
        )
        let replacement = try RawFreshContainerStateCoordinator.acquire(
            in: containers, containerID: container.id
        )
        #expect(replacement.wasCreated)
        #expect(replacement.directory.identity != directory.identity)
        #expect(try containers.entryNames() == [container.id])
    }

    @Test func copyOutPreparationRequiresExactInstanceAndShimSpecification() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerURL = root.appending(path: "containers/copy-guard")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let state = try makePreparedState(
            in: PersistentStateDirectory.open(containerURL), containerID: "copy-guard"
        )
        #expect(RawVirtualizationBackend.copyPreparationMatches(
            state.currentContainer,
            prepared: state,
            shimSpecification: state.specification
        ))

        let wrongInstance = ContainerRecord(
            id: state.currentContainer.id,
            instanceID: UUID(),
            name: state.currentContainer.name,
            image: state.currentContainer.image
        )
        #expect(!RawVirtualizationBackend.copyPreparationMatches(
            wrongInstance,
            prepared: state,
            shimSpecification: state.specification
        ))
        var wrongSpecification = state.specification
        wrongSpecification.token = "replacement-copy-shim"
        #expect(!RawVirtualizationBackend.copyPreparationMatches(
            state.currentContainer,
            prepared: state,
            shimSpecification: wrongSpecification
        ))
    }

    @Test func resourceRelaunchKeepsCanonicalArtifactIdentities() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerURL = root.appending(path: "containers/resource-identities")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = try PersistentStateDirectory.open(containerURL)
        let original = try makePreparedState(
            in: directory, containerID: "resource-identities", generation: 7
        )
        var updatedContainer = original.currentContainer
        updatedContainer.cpus = 3
        updatedContainer.memoryBytes = 700 * 1_024 * 1_024
        var replacementSpecification = original.specification
        replacementSpecification.generation = 8
        replacementSpecification.token = "resource-relaunch-token"
        let replacement = RawVirtualizationBackend.PreparedShimState(
            directoryIdentity: original.directoryIdentity,
            artifacts: original.artifacts,
            currentContainer: updatedContainer,
            specification: replacementSpecification
        )
        try directory.replaceRegularFile(
            named: "prepared-shim.json",
            data: try JSONEncoder().encode(replacement)
        )

        let loadedState = try RawVirtualizationBackend.loadPreparedShimState(
            from: containerURL
        )
        let loaded = try #require(loadedState)
        #expect(loaded.artifacts == original.artifacts)
        try loaded.artifacts.validate(in: directory)
        #expect(try RawVirtualizationBackend.relaunchCapacitySpecification(
            for: updatedContainer,
            prepared: loaded,
            preserving: original
        ) == original.specification)
    }

    @Test func recoveredStoppedReplacementRestoresExactOldResourcesAndCapacity() async throws {
        enum Failure: Error { case candidate }
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerDirectory = root.appending(path: "containers/recovered-old")
        try FileManager.default.createDirectory(at: containerDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let rootDisk = containerDirectory.appending(path: "root.ext4")
        var old = ContainerRecord(
            id: "recovered-old", name: "recovered-old", image: "alpine"
        )
        old.phase = .exited
        // These are post-live guest limits; the durable VM capacity remains
        // independently larger and must survive a failed stopped replacement.
        old.cpus = 1
        old.memoryBytes = 320 * 1_024 * 1_024
        old.pidsLimit = 19
        old.blockIOReadBps = [.init(path: "/dev/vda", rate: 1_234_567)]
        old.blockIOWriteIOps = [.init(path: "/dev/vda", rate: 321)]
        let persistentDirectory = try PersistentStateDirectory.open(
            containerDirectory
        )
        let artifacts = try RawContainerPreparationArtifacts.create(
            in: persistentDirectory, rootDiskSize: 4_096
        )
        let oldSpecification = VMShimProtocol.Specification(
            containerID: old.id,
            generation: 13,
            token: "old-resource-token",
            kernelPath: "/kernel",
            initialRamdiskPath: "/initramfs",
            rootDiskPath: rootDisk.path,
            rootDiskIdentity: .init(
                device: artifacts.rootDiskIdentity.device,
                inode: artifacts.rootDiskIdentity.inode
            ),
            rootDiskSize: artifacts.rootDiskSize,
            cpus: 4,
            memoryBytes: 512 * 1_024 * 1_024,
            macAddress: "02:ce:00:00:00:13",
            bindShares: [.init(
                tag: "cengine-io",
                source: containerDirectory.appending(path: "io").path,
                readOnly: false,
                sourceIdentity: .init(
                    device: artifacts.ioDirectoryIdentity.device,
                    inode: artifacts.ioDirectoryIdentity.inode
                )
            )],
            socketPath: try RawVirtualizationBackend.makeRuntimeSocketPath(),
            logPath: containerDirectory.appending(path: "shim.log").path
        )
        try JSONEncoder().encode(
            RawVirtualizationBackend.PreparedShimState(
                directoryIdentity: persistentDirectory.identity,
                artifacts: artifacts,
                currentContainer: old,
                specification: oldSpecification
            )
        ).write(to: RawVirtualizationBackend.preparedShimStateURL(for: containerDirectory))
        let recoveredState = try RawVirtualizationBackend.loadPreparedShimState(
            from: containerDirectory
        )
        let recovered = try #require(recoveredState)
        var desired = recovered.currentContainer
        desired.cpus = 5
        desired.memoryBytes = 900 * 1_024 * 1_024
        desired.pidsLimit = 77
        desired.blockIOReadBps = [.init(path: "/dev/vda", rate: 9_999_999)]
        #expect(try RawVirtualizationBackend.relaunchCapacitySpecification(
            for: recovered.currentContainer, prepared: recovered
        ) == oldSpecification)
        #expect(try RawVirtualizationBackend.relaunchCapacitySpecification(
            for: desired, prepared: recovered
        ) == nil)
        #expect(try RawVirtualizationBackend.relaunchCapacitySpecification(
            for: recovered.currentContainer,
            prepared: recovered,
            preserving: recovered
        ) == oldSpecification)
        let restored = RecoveredPreparationBox()

        await #expect(throws: Failure.self) {
            try await StoppedResourceReplacementTransaction.perform(
                terminateOriginal: {},
                launchCandidate: { throw Failure.candidate },
                cleanupCandidate: {},
                restoreOriginal: {
                    restored.restore(
                        container: recovered.currentContainer,
                        specification: recovered.specification
                    )
                }
            )
        }
        let (startedContainer, startedSpecification) = restored.snapshot()
        #expect(startedContainer?.cpus == old.cpus)
        #expect(startedContainer?.memoryBytes == old.memoryBytes)
        #expect(startedContainer?.pidsLimit == old.pidsLimit)
        #expect(startedContainer?.blockIOReadBps?.first?.rate == old.blockIOReadBps?.first?.rate)
        #expect(startedContainer?.blockIOWriteIOps?.first?.rate == old.blockIOWriteIOps?.first?.rate)
        #expect(startedSpecification?.cpus == oldSpecification.cpus)
        #expect(startedSpecification?.memoryBytes == oldSpecification.memoryBytes)
        #expect(startedContainer?.cpus != desired.cpus)
        #expect(startedContainer?.memoryBytes != desired.memoryBytes)
    }

    @Test func preparedStateKeepsPostLiveResourcesAndRequiresAnExactLaunch() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerDirectory = root.appending(path: "containers/canonical-exact")
        try FileManager.default.createDirectory(at: containerDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = try PersistentStateDirectory.open(containerDirectory)
        var current = ContainerRecord(
            id: "canonical-exact", name: "canonical-exact", image: "alpine"
        )
        current.cpus = 1
        current.memoryBytes = 300 * 1_024 * 1_024
        current.pidsLimit = 47
        let artifacts = try RawContainerPreparationArtifacts.create(
            in: directory, rootDiskSize: 4_096
        )
        func specification(
            generation: UInt64 = 80,
            cpus: Int = 4,
            memoryBytes: UInt64 = 1_024 * 1_024 * 1_024,
            rootDiskPath: String? = nil
        ) -> VMShimProtocol.Specification {
            VMShimProtocol.Specification(
                containerID: current.id,
                generation: generation,
                token: "canonical-token",
                kernelPath: "/kernel",
                initialRamdiskPath: "/initramfs",
                rootDiskPath: rootDiskPath
                    ?? containerDirectory.appending(path: "root.ext4").path,
                rootDiskIdentity: .init(
                    device: artifacts.rootDiskIdentity.device,
                    inode: artifacts.rootDiskIdentity.inode
                ),
                rootDiskSize: artifacts.rootDiskSize,
                cpus: cpus,
                memoryBytes: memoryBytes,
                macAddress: "02:ce:00:00:00:80",
                bindShares: [.init(
                    tag: "cengine-io",
                    source: containerDirectory.appending(path: "io").path,
                    readOnly: false,
                    sourceIdentity: .init(
                        device: artifacts.ioDirectoryIdentity.device,
                        inode: artifacts.ioDirectoryIdentity.inode
                    )
                )],
                socketPath: "/private/var/run/cengine-canonical.sock",
                logPath: containerDirectory.appending(path: "shim.log").path
            )
        }
        let capacity = specification()
        let state = RawVirtualizationBackend.PreparedShimState(
            directoryIdentity: directory.identity,
            artifacts: artifacts,
            currentContainer: current,
            specification: capacity
        )
        try directory.replaceRegularFile(
            named: "prepared-shim.json", data: try JSONEncoder().encode(state)
        )
        let loaded = try RawVirtualizationBackend.loadPreparedShimState(
            from: containerDirectory
        )
        let recovered = try #require(loaded)
        #expect(recovered.currentContainer.cpus == current.cpus)
        #expect(recovered.currentContainer.memoryBytes == current.memoryBytes)
        #expect(recovered.currentContainer.pidsLimit == current.pidsLimit)
        #expect(recovered.specification.cpus == 4)
        #expect(recovered.specification.memoryBytes == 1_024 * 1_024 * 1_024)
        #expect(RawVirtualizationBackend.launchSpecificationMatchesPrepared(
            capacity, prepared: recovered
        ))
        #expect(!RawVirtualizationBackend.launchSpecificationMatchesPrepared(
            specification(generation: 81), prepared: recovered
        ))
        #expect(!RawVirtualizationBackend.launchSpecificationMatchesPrepared(
            specification(cpus: 5), prepared: recovered
        ))
        #expect(!RawVirtualizationBackend.launchSpecificationMatchesPrepared(
            specification(memoryBytes: 2 * 1_024 * 1_024 * 1_024), prepared: recovered
        ))
        #expect(!RawVirtualizationBackend.launchSpecificationMatchesPrepared(
            specification(rootDiskPath: root.appending(path: "other.ext4").path),
            prepared: recovered
        ))

        var wrongContainer = current
        wrongContainer.id = "other-container"
        try directory.replaceRegularFile(
            named: "prepared-shim.json",
            data: try JSONEncoder().encode(RawVirtualizationBackend.PreparedShimState(
                directoryIdentity: directory.identity,
                artifacts: artifacts,
                currentContainer: wrongContainer,
                specification: capacity
            ))
        )
        #expect(throws: EngineError.self) {
            try RawVirtualizationBackend.loadPreparedShimState(from: containerDirectory)
        }

        try directory.replaceRegularFile(
            named: "prepared-shim.json",
            data: try JSONEncoder().encode(RawVirtualizationBackend.PreparedShimState(
                directoryIdentity: .init(device: directory.identity.device,
                                         inode: directory.identity.inode &+ 1),
                artifacts: artifacts,
                currentContainer: current,
                specification: capacity
            ))
        )
        #expect(throws: EngineError.self) {
            try RawVirtualizationBackend.loadPreparedShimState(from: containerDirectory)
        }
    }

    @Test func execContextInheritsImageThenContainerDefaults() {
        let context = RawVirtualizationBackend.resolveExecContext(
            configuration: .init(arguments: ["env"]),
            containerEnvironment: ["SHARED=container", "CONTAINER=1"],
            containerWorkingDirectory: "",
            containerUser: "",
            containerPrivileged: false,
            imageEnvironment: ["IMAGE=1", "SHARED=image"],
            imageWorkingDirectory: "/image-work",
            imageUser: "image-user"
        )

        #expect(context.environment == ["IMAGE=1", "SHARED=container", "CONTAINER=1"])
        #expect(context.workingDirectory == "/image-work")
        #expect(context.user == .init(username: "image-user"))
        #expect(context.noNewPrivileges)
        #expect(!context.privileged)
    }

    @Test func execContextExplicitValuesOverrideContainerAndImage() {
        let context = RawVirtualizationBackend.resolveExecContext(
            configuration: .init(
                arguments: ["env"], environment: ["SHARED=exec", "EXEC=1"],
                workingDirectory: "/exec-work", user: "2000:3000", privileged: true
            ),
            containerEnvironment: ["SHARED=container", "CONTAINER=1"],
            containerWorkingDirectory: "/container-work",
            containerUser: "1000:1000",
            containerPrivileged: false,
            imageEnvironment: ["IMAGE=1", "SHARED=image"],
            imageWorkingDirectory: "/image-work",
            imageUser: "image-user"
        )

        #expect(context.environment == [
            "IMAGE=1", "SHARED=exec", "CONTAINER=1", "EXEC=1",
        ])
        #expect(context.workingDirectory == "/exec-work")
        #expect(context.user == .init(uid: 2_000, gid: 3_000))
        #expect(!context.noNewPrivileges)
        #expect(context.privileged)
    }

    @Test func defaultExecInheritsContainerPrivilege() {
        let context = RawVirtualizationBackend.resolveExecContext(
            configuration: .init(arguments: ["id"]),
            containerEnvironment: [],
            containerWorkingDirectory: "",
            containerUser: "",
            containerPrivileged: true,
            imageEnvironment: [],
            imageWorkingDirectory: nil,
            imageUser: nil
        )

        #expect(context.privileged)
        #expect(!context.noNewPrivileges)
    }

    @Test func healthcheckExecLifecycleRetiresMoreThanJournalActiveLimit() async throws {
        enum SimulatedHealthcheckFailure: Error { case wait, timeout, prepare }

        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerID = "healthcheck-retirement-container"
        let containerURL = root.appending(path: "containers/\(containerID)")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let containerDirectory = try PersistentStateDirectory.open(containerURL)
        let prepared = try makePreparedState(
            in: containerDirectory, containerID: containerID
        )
        let cleanupFailures = ConcurrentExecJournalFailures()

        func retire(_ execID: String) async {
            do {
                try RawExecArtifactTransaction.cleanup(
                    containerID: containerID,
                    execID: execID,
                    in: containerDirectory,
                    artifacts: prepared.artifacts
                )
            } catch {
                cleanupFailures.append(error)
            }
        }

        for index in 0..<70 {
            let execID = "health-success-\(index)"
            let result = try await RawHealthcheckExecLifecycle.run(
                prepare: {
                    _ = try RawExecArtifactTransaction.prepare(
                        containerID: containerID,
                        execID: execID,
                        attachStdin: false,
                        in: containerDirectory,
                        artifacts: prepared.artifacts
                    )
                },
                execute: { (Int32(0), "ok") },
                retire: { await retire(execID) }
            )
            #expect(result.0 == 0)
            #expect(result.1 == "ok")
        }

        for (execID, failure) in [
            ("health-wait-failure", SimulatedHealthcheckFailure.wait),
            ("health-timeout", SimulatedHealthcheckFailure.timeout),
        ] {
            await #expect(throws: SimulatedHealthcheckFailure.self) {
                try await RawHealthcheckExecLifecycle.run(
                    prepare: {
                        _ = try RawExecArtifactTransaction.prepare(
                            containerID: containerID,
                            execID: execID,
                            attachStdin: false,
                            in: containerDirectory,
                            artifacts: prepared.artifacts
                        )
                    },
                    execute: { throw failure },
                    retire: { await retire(execID) }
                )
            }
        }

        let failedPrepareID = "health-prepare-failure"
        await #expect(throws: SimulatedHealthcheckFailure.self) {
            try await RawHealthcheckExecLifecycle.run(
                prepare: {
                    _ = try RawExecArtifactTransaction.prepare(
                        containerID: containerID,
                        execID: failedPrepareID,
                        attachStdin: false,
                        in: containerDirectory,
                        artifacts: prepared.artifacts
                    )
                    throw SimulatedHealthcheckFailure.prepare
                },
                execute: {},
                retire: { await retire(failedPrepareID) }
            )
        }

        #expect(cleanupFailures.all.isEmpty)
        #expect(try RawExecArtifactJournal.activeRecords(
            containerID: containerID,
            in: containerDirectory,
            artifacts: prepared.artifacts
        ).isEmpty)
    }

    @Test func uncertainGuestExecStartIsKilledWaitedAndDiscarded() async throws {
        var statuses = ["running", "exited"]
        var events: [String] = []
        try await RawGuestExecRetirement.run(
            deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 1_000_000_000,
            status: {
                events.append("status")
                return statuses.removeFirst()
            },
            signal: { events.append("signal") },
            wait: {
                events.append("wait")
                return "exited"
            },
            discard: { events.append("discard") }
        )

        #expect(events == ["status", "signal", "wait", "status", "discard"])
    }

    @Test func guestExecRetirementDiscardsMoreThanStatusLimit() async throws {
        var discarded = 0
        for _ in 0..<70 {
            try await RawGuestExecRetirement.run(
                deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 1_000_000_000,
                status: { "exited" },
                signal: {},
                wait: { "exited" },
                discard: { discarded += 1 }
            )
        }
        #expect(discarded == 70)
    }

    @Test func guestExecRetirementPropagatesUnresponsiveSignalAndDiscard() async {
        for terminalStatus in ["running", "exited"] {
            var discarded = false
            await #expect(throws: AsyncTimeout.TimeoutError.self) {
                try await RawGuestExecRetirement.run(
                    deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds
                        + 1_000_000_000,
                    status: { terminalStatus },
                    signal: { throw AsyncTimeout.TimeoutError() },
                    wait: { "exited" },
                    discard: {
                        discarded = true
                        throw AsyncTimeout.TimeoutError()
                    }
                )
            }
            #expect(discarded == (terminalStatus == "exited"))
        }
    }

    @Test func guestExecRetirementHonorsItsTotalLifecycleDeadline() async {
        let clock = ContinuousClock()
        let started = clock.now
        await #expect(throws: AsyncTimeout.TimeoutError.self) {
            try await RawGuestExecRetirement.run(
                deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds,
                status: { Issue.record("status called after deadline"); return "created" },
                signal: {},
                wait: { "exited" },
                discard: { Issue.record("discard called after deadline") }
            )
        }
        #expect(clock.now - started < .seconds(1))
    }

    @Test func recoveredExecCleanupWaitsForContainmentAndRetainsFailuresForRetry() async {
        var events: [String] = []
        let successful = await RawRecoveredExecCoordinator.run(
            execIDs: ["long-detached"],
            guestContainmentAvailable: true,
            contain: { identifier in events.append("contain:\(identifier)") },
            cleanup: { identifier in events.append("cleanup:\(identifier)") }
        )
        #expect(events == ["contain:long-detached", "cleanup:long-detached"])
        #expect(successful.failures.isEmpty)
        #expect(successful.guestContainmentRequired.isEmpty)

        events.removeAll()
        let failed = await RawRecoveredExecCoordinator.run(
            execIDs: ["wedged-detached"],
            guestContainmentAvailable: true,
            contain: { identifier in
                events.append("contain:\(identifier)")
                throw AsyncTimeout.TimeoutError()
            },
            cleanup: { identifier in events.append("cleanup:\(identifier)") }
        )
        #expect(events == ["contain:wedged-detached"])
        #expect(failed.failures["wedged-detached"] != nil)
        #expect(failed.guestContainmentRequired == ["wedged-detached"])

        events.removeAll()
        let unresolved = await RawRecoveredExecCoordinator.run(
            execIDs: ["unresolved-generation"],
            guestContainmentAvailable: nil,
            contain: { identifier in events.append("contain:\(identifier)") },
            cleanup: { identifier in events.append("cleanup:\(identifier)") }
        )
        #expect(events.isEmpty)
        #expect(unresolved.failures["unresolved-generation"] != nil)
        #expect(unresolved.guestContainmentRequired == ["unresolved-generation"])

        events.removeAll()
        let retried = await RawRecoveredExecCoordinator.run(
            execIDs: Array(failed.failures.keys),
            guestContainmentAvailable: true,
            contain: { identifier in events.append("contain:\(identifier)") },
            cleanup: { identifier in events.append("cleanup:\(identifier)") }
        )
        #expect(events == ["contain:wedged-detached", "cleanup:wedged-detached"])
        #expect(retried.failures.isEmpty)
    }

    @Test func execArtifactCleanupFailureRetainsOwnershipUntilRetry() throws {
        struct InjectedCleanupFailure: Error {}

        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerID = "exec-cleanup-retry-container"
        let execID = "exec-cleanup-retry"
        let containerURL = root.appending(path: "containers/\(containerID)")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let containerDirectory = try PersistentStateDirectory.open(containerURL)
        let prepared = try makePreparedState(
            in: containerDirectory, containerID: containerID
        )
        _ = try RawExecArtifactTransaction.prepare(
            containerID: containerID,
            execID: execID,
            attachStdin: false,
            in: containerDirectory,
            artifacts: prepared.artifacts
        )
        var injected = false

        #expect(throws: InjectedCleanupFailure.self) {
            try RawExecArtifactTransaction.cleanup(
                containerID: containerID,
                execID: execID,
                in: containerDirectory,
                artifacts: prepared.artifacts,
                hook: { boundary in
                    guard case .deletionClaimed = boundary, !injected else { return }
                    injected = true
                    throw InjectedCleanupFailure()
                }
            )
        }
        #expect(injected)
        #expect(try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: execID,
            in: containerDirectory,
            artifacts: prepared.artifacts
        ) != nil)

        try RawExecArtifactTransaction.cleanup(
            containerID: containerID,
            execID: execID,
            in: containerDirectory,
            artifacts: prepared.artifacts
        )
        #expect(try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: execID,
            in: containerDirectory,
            artifacts: prepared.artifacts
        ) == nil)
        let ioDirectory = try containerDirectory.openDirectory(named: "io")
        #expect(try ioDirectory.entryNames().allSatisfy {
            !$0.hasPrefix("exec-\(execID)-")
                && !$0.hasPrefix(".cengine-remove-exec-")
        })
    }

    @Test func execArtifactJournalRepairsTornPreparedAppendBeforeRetry() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerID = "torn-prepared-container"
        let execID = "torn-prepared-exec"
        let containerURL = root.appending(path: "containers/\(containerID)")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let containerDirectory = try PersistentStateDirectory.open(containerURL)
        let prepared = try makePreparedState(
            in: containerDirectory, containerID: containerID
        )
        let record = try makeExecArtifactRecord(
            in: containerDirectory, containerID: containerID, execID: execID
        )
        try RawExecArtifactJournal.recordPrepared(
            record, in: containerDirectory, artifacts: prepared.artifacts
        )
        let completeEvent = try readExecArtifactJournal(
            in: containerDirectory, artifacts: prepared.artifacts
        )
        let tornEvent = Data(completeEvent.prefix(max(1, completeEvent.count / 2)))
        #expect(tornEvent.count < completeEvent.count)
        try replaceExecArtifactJournal(
            with: tornEvent,
            in: containerDirectory,
            artifacts: prepared.artifacts
        )

        let beforeRetry = try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: execID,
            in: containerDirectory,
            artifacts: prepared.artifacts
        )
        #expect(beforeRetry == nil)
        try RawExecArtifactJournal.recordPrepared(
            record, in: containerDirectory, artifacts: prepared.artifacts
        )

        let reloadedDirectory = try PersistentStateDirectory.open(containerURL)
        let recovered = try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: execID,
            in: reloadedDirectory,
            artifacts: prepared.artifacts
        )
        #expect(recovered == record)
        let repairedData = try readExecArtifactJournal(
            in: reloadedDirectory, artifacts: prepared.artifacts
        )
        #expect(!repairedData.isEmpty)
        #expect(try RawExecArtifactJournal.eventCount(
            in: reloadedDirectory, artifacts: prepared.artifacts
        ) == 1)
    }

    @Test func execArtifactJournalRepairsTornRemovedAppendBeforeRetry() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerID = "torn-removed-container"
        let execID = "torn-removed-exec"
        let containerURL = root.appending(path: "containers/\(containerID)")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let containerDirectory = try PersistentStateDirectory.open(containerURL)
        let prepared = try makePreparedState(
            in: containerDirectory, containerID: containerID
        )
        let record = try makeExecArtifactRecord(
            in: containerDirectory, containerID: containerID, execID: execID
        )
        try RawExecArtifactJournal.recordPrepared(
            record, in: containerDirectory, artifacts: prepared.artifacts
        )
        let preparedEvent = try readExecArtifactJournal(
            in: containerDirectory, artifacts: prepared.artifacts
        )
        try RawExecArtifactJournal.recordRemoved(
            record, in: containerDirectory, artifacts: prepared.artifacts
        )
        let completeJournal = try readExecArtifactJournal(
            in: containerDirectory, artifacts: prepared.artifacts
        )
        let removedEvent = completeJournal.dropFirst(preparedEvent.count)
        let tornRemovedEvent = Data(removedEvent.prefix(max(1, removedEvent.count / 2)))
        #expect(tornRemovedEvent.count < removedEvent.count)
        try replaceExecArtifactJournal(
            with: preparedEvent + tornRemovedEvent,
            in: containerDirectory,
            artifacts: prepared.artifacts
        )

        let beforeRetry = try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: execID,
            in: containerDirectory,
            artifacts: prepared.artifacts
        )
        #expect(beforeRetry == record)
        try RawExecArtifactJournal.recordRemoved(
            record, in: containerDirectory, artifacts: prepared.artifacts
        )

        let reloadedDirectory = try PersistentStateDirectory.open(containerURL)
        let recovered = try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: execID,
            in: reloadedDirectory,
            artifacts: prepared.artifacts
        )
        #expect(recovered == nil)
        let repairedData = try readExecArtifactJournal(
            in: reloadedDirectory, artifacts: prepared.artifacts
        )
        #expect(!repairedData.isEmpty)
        #expect(try RawExecArtifactJournal.eventCount(
            in: reloadedDirectory, artifacts: prepared.artifacts
        ) == 2)
    }

    @Test func execArtifactTransactionRecoversEveryDurableBoundaryAfterReload() throws {
        struct InjectedCrash: Error {}

        let artifactNames = RawExecArtifactRecord.expectedNames(execID: "boundary-exec")
        let boundaries: [RawExecArtifactBoundary] = [
            .intentionSynchronized,
            .stagingDirectoryCreated,
            .stagingDirectorySynchronized,
        ] + artifactNames.map { .artifactStaged($0) } + [
            .stagedOwnershipSynchronized,
        ] + artifactNames.map { .artifactExposed($0) } + [
            .ioDirectorySynchronized,
            .publicationSynchronized,
        ]

        for (offset, boundary) in boundaries.enumerated() {
            let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
            let containerID = "exec-boundary-\(offset)"
            let execID = "boundary-exec"
            let containerURL = root.appending(path: "containers/\(containerID)")
            try FileManager.default.createDirectory(
                at: containerURL, withIntermediateDirectories: true
            )
            defer { try? FileManager.default.removeItem(at: root) }
            let containerDirectory = try PersistentStateDirectory.open(containerURL)
            let prepared = try makePreparedState(
                in: containerDirectory, containerID: containerID
            )
            var injected = false

            #expect(throws: InjectedCrash.self) {
                _ = try RawExecArtifactTransaction.prepare(
                    containerID: containerID,
                    execID: execID,
                    attachStdin: false,
                    in: containerDirectory,
                    artifacts: prepared.artifacts,
                    hook: { observed in
                        guard observed == boundary, !injected else { return }
                        injected = true
                        throw InjectedCrash()
                    },
                    cleanupOnFailure: false
                )
            }
            #expect(injected)

            // Reopen all descriptor-owned state to model daemon reload before
            // recovery. The durable phase decides whether cleanup removes an
            // exact staging subtree or exact staged/canonical file identities.
            let reloaded = try PersistentStateDirectory.open(containerURL)
            try RawExecArtifactTransaction.cleanupAll(
                containerID: containerID,
                in: reloaded,
                artifacts: prepared.artifacts
            )
            #expect(try RawExecArtifactJournal.activeRecord(
                containerID: containerID,
                execID: execID,
                in: reloaded,
                artifacts: prepared.artifacts
            ) == nil)
            let recoveredIO = try reloaded.openDirectory(named: "io")
            let recoveredNames = try recoveredIO.entryNames()
            #expect(artifactNames.allSatisfy { !recoveredNames.contains($0) })
            let quarantinedStages = recoveredNames.filter {
                $0.hasPrefix(".cengine-exec-stage-")
            }
            #expect(quarantinedStages.count
                == (boundary == .stagingDirectoryCreated ? 1 : 0))
            #expect(recoveredNames.allSatisfy {
                !$0.hasPrefix(".cengine-remove-exec-")
            })
            #expect(try RawExecArtifactJournal.abandonedRecords(
                containerID: containerID,
                in: reloaded,
                artifacts: prepared.artifacts
            ).count == (boundary == .stagingDirectoryCreated ? 1 : 0))

            let retry = try RawExecArtifactTransaction.prepare(
                containerID: containerID,
                execID: execID,
                attachStdin: false,
                in: reloaded,
                artifacts: prepared.artifacts
            )
            #expect(retry.record.phase == .published)
            for name in artifactNames {
                #expect(try recoveredIO.regularFileIdentity(
                    named: name,
                    expectedIdentity: retry.record.fileIdentities[name]
                ) == retry.record.fileIdentities[name])
            }
            try RawExecArtifactTransaction.cleanup(
                containerID: containerID,
                execID: execID,
                in: reloaded,
                artifacts: prepared.artifacts
            )
            #expect(try RawExecArtifactJournal.activeRecord(
                containerID: containerID,
                execID: execID,
                in: reloaded,
                artifacts: prepared.artifacts
            ) == nil)
        }
    }

    @Test func execArtifactTransactionNeverDeletesCanonicalReplacement() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerID = "exec-replacement-container"
        let execID = "exec-replacement"
        let containerURL = root.appending(path: "containers/\(containerID)")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let containerDirectory = try PersistentStateDirectory.open(containerURL)
        let prepared = try makePreparedState(
            in: containerDirectory, containerID: containerID
        )
        let publication = try RawExecArtifactTransaction.prepare(
            containerID: containerID,
            execID: execID,
            attachStdin: true,
            in: containerDirectory,
            artifacts: prepared.artifacts
        )
        let ioDirectory = try containerDirectory.openDirectory(named: "io")
        let replacedName = "exec-\(execID)-stdout"
        let originalURL = ioDirectory.url.appending(path: replacedName)
        let retainedURL = ioDirectory.url.appending(path: "retained-original")
        try FileManager.default.moveItem(at: originalURL, to: retainedURL)
        let replacement = Data("foreign-replacement".utf8)
        try replacement.write(to: originalURL)

        #expect(throws: BackendResourceRollbackIncompleteError.self) {
            try RawExecArtifactTransaction.cleanup(
                containerID: containerID,
                execID: execID,
                in: containerDirectory,
                artifacts: prepared.artifacts
            )
        }
        #expect(try Data(contentsOf: originalURL) == replacement)
        #expect(try ioDirectory.regularFileIdentity(named: "retained-original")
            == publication.record.fileIdentities[replacedName])
        #expect(try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: execID,
            in: containerDirectory,
            artifacts: prepared.artifacts
        ) == publication.record)

        try FileManager.default.removeItem(at: originalURL)
        try FileManager.default.moveItem(at: retainedURL, to: originalURL)
        try RawExecArtifactTransaction.cleanup(
            containerID: containerID,
            execID: execID,
            in: containerDirectory,
            artifacts: prepared.artifacts
        )
        #expect(try ioDirectory.entryMetadata(named: replacedName) == nil)
    }

    @Test func execArtifactTransactionNeverDeletesPreIdentityStagingReplacement() throws {
        struct InjectedCrash: Error {}

        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerID = "exec-stage-replacement-container"
        let execID = "exec-stage-replacement"
        let containerURL = root.appending(path: "containers/\(containerID)")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let containerDirectory = try PersistentStateDirectory.open(containerURL)
        let prepared = try makePreparedState(
            in: containerDirectory, containerID: containerID
        )
        let ioDirectory = try containerDirectory.openDirectory(named: "io")
        var stagingName: String?

        #expect(throws: InjectedCrash.self) {
            _ = try RawExecArtifactTransaction.prepare(
                containerID: containerID,
                execID: execID,
                attachStdin: true,
                in: containerDirectory,
                artifacts: prepared.artifacts,
                hook: { boundary in
                    guard boundary == .stagingDirectoryCreated else { return }
                    stagingName = try #require(ioDirectory.entryNames().first {
                        $0.hasPrefix(".cengine-exec-stage-")
                    })
                    let original = ioDirectory.url.appending(path: stagingName!)
                    let retained = ioDirectory.url.appending(path: "retained-stage")
                    try FileManager.default.moveItem(at: original, to: retained)
                    try FileManager.default.createDirectory(
                        at: original, withIntermediateDirectories: false
                    )
                    try Data("foreign".utf8).write(
                        to: original.appending(path: "foreign-marker")
                    )
                    throw InjectedCrash()
                },
                cleanupOnFailure: false
            )
        }

        let reloaded = try PersistentStateDirectory.open(containerURL)
        let reloadedIO = try reloaded.openDirectory(named: "io")
        let name = try #require(stagingName)
        try RawExecArtifactTransaction.cleanup(
            containerID: containerID,
            execID: execID,
            in: reloaded,
            artifacts: prepared.artifacts
        )
        #expect(try Data(contentsOf: reloadedIO.url
            .appending(path: name).appending(path: "foreign-marker"))
            == Data("foreign".utf8))
        #expect(try reloadedIO.openDirectory(named: "retained-stage")
            .entryNames().isEmpty)
        #expect(try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: execID,
            in: reloaded,
            artifacts: prepared.artifacts
        ) == nil)
        let abandoned = try RawExecArtifactJournal.abandonedRecords(
            containerID: containerID,
            in: reloaded,
            artifacts: prepared.artifacts
        )
        #expect(abandoned.count == 1)
        #expect(abandoned.first?.stagingDirectoryName == name)

        let retry = try RawExecArtifactTransaction.prepare(
            containerID: containerID,
            execID: execID,
            attachStdin: true,
            in: reloaded,
            artifacts: prepared.artifacts
        )
        #expect(retry.record.phase == .published)
        try RawExecArtifactTransaction.cleanup(
            containerID: containerID,
            execID: execID,
            in: reloaded,
            artifacts: prepared.artifacts
        )
        #expect(try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: execID,
            in: reloaded,
            artifacts: prepared.artifacts
        ) == nil)
    }

    @Test func execArtifactJournalCompactsClosedHistoryAndPreservesActiveState() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerID = "exec-compaction-container"
        let containerURL = root.appending(path: "containers/\(containerID)")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = try PersistentStateDirectory.open(containerURL)
        let prepared = try makePreparedState(in: directory, containerID: containerID)
        let retained = try RawExecArtifactTransaction.prepare(
            containerID: containerID,
            execID: "retained-active",
            attachStdin: true,
            in: directory,
            artifacts: prepared.artifacts
        )

        for index in 0..<100 {
            let execID = "closed-\(index)"
            _ = try RawExecArtifactTransaction.prepare(
                containerID: containerID,
                execID: execID,
                attachStdin: true,
                in: directory,
                artifacts: prepared.artifacts
            )
            try RawExecArtifactTransaction.cleanup(
                containerID: containerID,
                execID: execID,
                in: directory,
                artifacts: prepared.artifacts
            )
        }

        #expect(try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: "retained-active",
            in: directory,
            artifacts: prepared.artifacts
        ) == retained.record)
        #expect(try RawExecArtifactJournal.activeRecords(
            containerID: containerID,
            in: directory,
            artifacts: prepared.artifacts
        ).count == 1)
        #expect(try RawExecArtifactJournal.eventCount(
            in: directory, artifacts: prepared.artifacts
        ) < 64)
        #expect(try RawExecArtifactJournal.byteCount(
            in: directory, artifacts: prepared.artifacts
        ) < RawExecArtifactJournal.maximumJournalSize)

        try RawExecArtifactTransaction.cleanup(
            containerID: containerID,
            execID: "retained-active",
            in: directory,
            artifacts: prepared.artifacts
        )
    }

    @Test func execArtifactJournalRecoversEveryCompactionBoundary() throws {
        struct InjectedCrash: Error {}
        let boundaries: [RawExecJournalCompactionBoundary] = [
            .recoverySynchronized,
            .journalTruncated,
            .journalWritten,
            .journalSynchronized,
            .recoveryCleared,
        ]

        for (index, boundary) in boundaries.enumerated() {
            let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
            let containerID = "exec-compact-boundary-\(index)"
            let containerURL = root.appending(path: "containers/\(containerID)")
            try FileManager.default.createDirectory(
                at: containerURL, withIntermediateDirectories: true
            )
            defer { try? FileManager.default.removeItem(at: root) }
            let directory = try PersistentStateDirectory.open(containerURL)
            let prepared = try makePreparedState(in: directory, containerID: containerID)
            let active = try RawExecArtifactTransaction.prepare(
                containerID: containerID,
                execID: "active",
                attachStdin: true,
                in: directory,
                artifacts: prepared.artifacts
            )
            _ = try RawExecArtifactTransaction.prepare(
                containerID: containerID,
                execID: "closed",
                attachStdin: true,
                in: directory,
                artifacts: prepared.artifacts
            )
            try RawExecArtifactTransaction.cleanup(
                containerID: containerID,
                execID: "closed",
                in: directory,
                artifacts: prepared.artifacts
            )
            var injected = false

            #expect(throws: InjectedCrash.self) {
                try RawExecArtifactJournal.forceCompaction(
                    containerID: containerID,
                    in: directory,
                    artifacts: prepared.artifacts,
                    hook: { observed in
                        guard observed == boundary, !injected else { return }
                        injected = true
                        throw InjectedCrash()
                    }
                )
            }
            #expect(injected)

            let reloaded = try PersistentStateDirectory.open(containerURL)
            #expect(try RawExecArtifactJournal.activeRecord(
                containerID: containerID,
                execID: "active",
                in: reloaded,
                artifacts: prepared.artifacts
            ) == active.record)
            #expect(try RawExecArtifactJournal.activeRecord(
                containerID: containerID,
                execID: "closed",
                in: reloaded,
                artifacts: prepared.artifacts
            ) == nil)
            #expect(try readExecArtifactCompaction(
                in: reloaded, artifacts: prepared.artifacts
            ).isEmpty)
            try RawExecArtifactTransaction.cleanup(
                containerID: containerID,
                execID: "active",
                in: reloaded,
                artifacts: prepared.artifacts
            )
        }
    }

    @Test func execArtifactJournalIgnoresTornCompactionWhenCanonicalIsValid() throws {
        struct InjectedCrash: Error {}
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerID = "exec-torn-compaction-container"
        let containerURL = root.appending(path: "containers/\(containerID)")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = try PersistentStateDirectory.open(containerURL)
        let prepared = try makePreparedState(in: directory, containerID: containerID)
        let active = try RawExecArtifactTransaction.prepare(
            containerID: containerID,
            execID: "active",
            attachStdin: true,
            in: directory,
            artifacts: prepared.artifacts
        )
        #expect(throws: InjectedCrash.self) {
            try RawExecArtifactJournal.forceCompaction(
                containerID: containerID,
                in: directory,
                artifacts: prepared.artifacts,
                hook: { boundary in
                    guard boundary == .recoverySynchronized else { return }
                    throw InjectedCrash()
                }
            )
        }
        let completeRecovery = try readExecArtifactCompaction(
            in: directory, artifacts: prepared.artifacts
        )
        #expect(!completeRecovery.isEmpty)
        try replaceExecArtifactCompaction(
            with: Data(completeRecovery.prefix(max(1, completeRecovery.count / 2))),
            in: directory,
            artifacts: prepared.artifacts
        )

        #expect(try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: "active",
            in: directory,
            artifacts: prepared.artifacts
        ) == active.record)
        #expect(try readExecArtifactCompaction(
            in: directory, artifacts: prepared.artifacts
        ).isEmpty)
        try RawExecArtifactTransaction.cleanup(
            containerID: containerID,
            execID: "active",
            in: directory,
            artifacts: prepared.artifacts
        )
    }

    @Test func execArtifactJournalEnforcesSizeAndFrameCaps() throws {
        do {
            let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
            let containerID = "exec-size-cap-container"
            let containerURL = root.appending(path: "containers/\(containerID)")
            try FileManager.default.createDirectory(
                at: containerURL, withIntermediateDirectories: true
            )
            defer { try? FileManager.default.removeItem(at: root) }
            let directory = try PersistentStateDirectory.open(containerURL)
            let prepared = try makePreparedState(in: directory, containerID: containerID)
            try replaceExecArtifactJournal(
                with: Data(count: RawExecArtifactJournal.maximumJournalSize + 1),
                in: directory,
                artifacts: prepared.artifacts
            )
            #expect(throws: BackendResourceRollbackIncompleteError.self) {
                _ = try RawExecArtifactJournal.activeRecords(
                    containerID: containerID,
                    in: directory,
                    artifacts: prepared.artifacts
                )
            }
        }

        do {
            let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
            let containerID = "exec-frame-cap-container"
            let containerURL = root.appending(path: "containers/\(containerID)")
            try FileManager.default.createDirectory(
                at: containerURL, withIntermediateDirectories: true
            )
            defer { try? FileManager.default.removeItem(at: root) }
            let directory = try PersistentStateDirectory.open(containerURL)
            let prepared = try makePreparedState(in: directory, containerID: containerID)
            let record = try makeExecArtifactRecord(
                in: directory, containerID: containerID, execID: "frame-cap"
            )
            try RawExecArtifactJournal.recordPrepared(
                record, in: directory, artifacts: prepared.artifacts
            )
            let frame = try readExecArtifactJournal(
                in: directory, artifacts: prepared.artifacts
            )
            var repeated = Data()
            for _ in 0...RawExecArtifactJournal.maximumFrameCount {
                repeated.append(frame)
            }
            #expect(repeated.count < RawExecArtifactJournal.maximumJournalSize)
            try replaceExecArtifactJournal(
                with: repeated,
                in: directory,
                artifacts: prepared.artifacts
            )
            #expect(throws: EngineError.self) {
                _ = try RawExecArtifactJournal.activeRecords(
                    containerID: containerID,
                    in: directory,
                    artifacts: prepared.artifacts
                )
            }
        }
    }

    @Test func execArtifactAbandonmentIsBoundedAndFailClosed() throws {
        struct InjectedCrash: Error {}
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerID = "exec-abandon-cap-container"
        let containerURL = root.appending(path: "containers/\(containerID)")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = try PersistentStateDirectory.open(containerURL)
        let prepared = try makePreparedState(in: directory, containerID: containerID)

        for index in 0..<RawExecArtifactJournal.maximumAbandonedRecordCount {
            let execID = "abandoned-\(index)"
            #expect(throws: InjectedCrash.self) {
                _ = try RawExecArtifactTransaction.prepare(
                    containerID: containerID,
                    execID: execID,
                    attachStdin: true,
                    in: directory,
                    artifacts: prepared.artifacts,
                    hook: { boundary in
                        guard boundary == .stagingDirectoryCreated else { return }
                        throw InjectedCrash()
                    },
                    cleanupOnFailure: false
                )
            }
            try RawExecArtifactTransaction.cleanup(
                containerID: containerID,
                execID: execID,
                in: directory,
                artifacts: prepared.artifacts
            )
        }
        let io = try directory.openDirectory(named: "io")
        let quarantined = try io.entryNames().filter {
            $0.hasPrefix(".cengine-exec-stage-")
        }
        #expect(quarantined.count == RawExecArtifactJournal.maximumAbandonedRecordCount)
        #expect(try RawExecArtifactJournal.abandonedRecords(
            containerID: containerID,
            in: directory,
            artifacts: prepared.artifacts
        ).count == RawExecArtifactJournal.maximumAbandonedRecordCount)

        #expect(throws: BackendResourceRollbackIncompleteError.self) {
            _ = try RawExecArtifactTransaction.prepare(
                containerID: containerID,
                execID: "over-cap",
                attachStdin: true,
                in: directory,
                artifacts: prepared.artifacts
            )
        }
        #expect(try io.entryNames().filter {
            $0.hasPrefix(".cengine-exec-stage-")
        }.count == RawExecArtifactJournal.maximumAbandonedRecordCount)
    }

    @Test func execArtifactTransactionsSerializeConcurrentJournalSnapshots() throws {
        struct InjectedFailure: Error {}
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerID = "exec-concurrent-container"
        let containerURL = root.appending(path: "containers/\(containerID)")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = try PersistentStateDirectory.open(containerURL)
        let prepared = try makePreparedState(in: directory, containerID: containerID)
        let pause = OneShotExecJournalPause()
        let failures = ConcurrentExecJournalFailures()
        let group = DispatchGroup()
        let queue = DispatchQueue(
            label: "exec-journal-concurrency", attributes: .concurrent
        )

        group.enter()
        queue.async {
            defer { group.leave() }
            do {
                _ = try RawExecArtifactTransaction.prepare(
                    containerID: containerID,
                    execID: "first",
                    attachStdin: true,
                    in: directory,
                    artifacts: prepared.artifacts,
                    journalMutationHook: pause.pauseIfFirst
                )
                try RawExecArtifactTransaction.cleanup(
                    containerID: containerID,
                    execID: "first",
                    in: directory,
                    artifacts: prepared.artifacts
                )
            } catch { failures.append(error) }
        }
        #expect(pause.entered.wait(timeout: .now() + 2) == .success)

        let secondStarted = DispatchSemaphore(value: 0)
        group.enter()
        queue.async {
            defer { group.leave() }
            secondStarted.signal()
            do {
                _ = try RawExecArtifactTransaction.prepare(
                    containerID: containerID,
                    execID: "second",
                    attachStdin: true,
                    in: directory,
                    artifacts: prepared.artifacts
                )
                try RawExecArtifactTransaction.cleanup(
                    containerID: containerID,
                    execID: "second",
                    in: directory,
                    artifacts: prepared.artifacts
                )
            } catch { failures.append(error) }
        }
        #expect(secondStarted.wait(timeout: .now() + 2) == .success)
        pause.release.signal()
        #expect(group.wait(timeout: .now() + 10) == .success)
        #expect(failures.all.isEmpty)
        #expect(try RawExecArtifactJournal.activeRecords(
            containerID: containerID,
            in: directory,
            artifacts: prepared.artifacts
        ).isEmpty)

        #expect(throws: InjectedFailure.self) {
            _ = try RawExecArtifactTransaction.prepare(
                containerID: containerID,
                execID: "failed",
                attachStdin: true,
                in: directory,
                artifacts: prepared.artifacts,
                hook: { boundary in
                    guard case .artifactStaged = boundary else { return }
                    throw InjectedFailure()
                }
            )
        }

        _ = try RawExecArtifactTransaction.prepare(
            containerID: containerID,
            execID: "failed",
            attachStdin: true,
            in: directory,
            artifacts: prepared.artifacts
        )
        try RawExecArtifactTransaction.cleanup(
            containerID: containerID,
            execID: "failed",
            in: directory,
            artifacts: prepared.artifacts
        )
    }

    @Test func execArtifactDiscardAwaitReacquiresSerializedJournalState() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerID = "exec-discard-await-container"
        let containerURL = root.appending(path: "containers/\(containerID)")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = try PersistentStateDirectory.open(containerURL)
        let prepared = try makePreparedState(in: directory, containerID: containerID)
        let discarded = ExecRecord(
            id: "discarded", containerID: containerID,
            containerInstanceID: prepared.currentContainer.instanceID,
            configuration: .init(arguments: ["true"])
        )
        _ = try RawExecArtifactTransaction.prepare(
            containerID: containerID,
            execID: discarded.id,
            attachStdin: true,
            in: directory,
            artifacts: prepared.artifacts
        )

        let guestGate = ExecJournalGuestGate()
        let completed = DispatchSemaphore(value: 0)
        let failures = ConcurrentExecJournalFailures()
        Task.detached {
            defer { completed.signal() }
            do {
                try await RawVirtualizationBackend.discardExecArtifacts(
                    root: root,
                    exec: discarded,
                    expectedContainerDirectoryIdentity: prepared.directoryIdentity
                ) {
                    guestGate.enterAndWait()
                }
            } catch { failures.append(error) }
        }
        #expect(guestGate.entered.wait(timeout: .now() + 2) == .success)

        _ = try RawExecArtifactTransaction.prepare(
            containerID: containerID,
            execID: "overlap",
            attachStdin: true,
            in: directory,
            artifacts: prepared.artifacts
        )
        try RawExecArtifactTransaction.cleanup(
            containerID: containerID,
            execID: "overlap",
            in: directory,
            artifacts: prepared.artifacts
        )
        guestGate.release.signal()
        #expect(completed.wait(timeout: .now() + 10) == .success)
        #expect(failures.all.isEmpty)
        #expect(try RawExecArtifactJournal.activeRecords(
            containerID: containerID,
            in: directory,
            artifacts: prepared.artifacts
        ).isEmpty)
    }

    @Test func execArtifactJournalRejectsCompleteChecksumCorruption() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerID = "exec-checksum-container"
        let execID = "exec-checksum"
        let containerURL = root.appending(path: "containers/\(containerID)")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let containerDirectory = try PersistentStateDirectory.open(containerURL)
        let prepared = try makePreparedState(
            in: containerDirectory, containerID: containerID
        )
        let record = try makeExecArtifactRecord(
            in: containerDirectory, containerID: containerID, execID: execID
        )
        try RawExecArtifactJournal.recordPrepared(
            record, in: containerDirectory, artifacts: prepared.artifacts
        )
        var corrupted = try readExecArtifactJournal(
            in: containerDirectory, artifacts: prepared.artifacts
        )
        let finalIndex = corrupted.index(before: corrupted.endIndex)
        corrupted[finalIndex] ^= 0xff
        try replaceExecArtifactJournal(
            with: corrupted,
            in: containerDirectory,
            artifacts: prepared.artifacts
        )

        #expect(throws: EngineError.self) {
            _ = try RawExecArtifactJournal.activeRecord(
                containerID: containerID,
                execID: execID,
                in: containerDirectory,
                artifacts: prepared.artifacts
            )
        }
    }

    @Test func failedGuestExecDiscardRetainsPreparedHostArtifactsUntilRetry() async throws {
        struct GuestUnavailable: Error {}

        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerID = "prepared-container"
        let containerURL = root.appending(path: "containers/\(containerID)")
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let containerDirectory = try PersistentStateDirectory.open(containerURL)
        let prepared = try makePreparedState(
            in: containerDirectory, containerID: containerID
        )
        let exec = ExecRecord(
            id: "prepared-exec",
            containerID: containerID,
            containerInstanceID: prepared.currentContainer.instanceID,
            configuration: .init(arguments: ["true"])
        )
        let ioDirectory = try containerDirectory.openDirectory(named: "io")
        let artifactNames = RawExecArtifactRecord.expectedNames(execID: exec.id)
        var identities: [String: PersistentFileIdentity] = [:]
        for name in artifactNames {
            identities[name] = try ioDirectory.createSparseRegularFile(named: name, size: 0)
        }
        try RawExecArtifactJournal.recordPrepared(
            .init(
                containerID: exec.containerID,
                execID: exec.id,
                fileIdentities: identities
            ),
            in: containerDirectory,
            artifacts: prepared.artifacts
        )

        await #expect(throws: GuestUnavailable.self) {
            try await RawVirtualizationBackend.discardExecArtifacts(
                root: root,
                exec: exec,
                expectedContainerDirectoryIdentity: prepared.directoryIdentity
            ) {
                throw GuestUnavailable()
            }
        }

        for name in artifactNames {
            #expect(try ioDirectory.entryMetadata(named: name) != nil)
        }
        try await RawVirtualizationBackend.discardExecArtifacts(
            root: root,
            exec: exec,
            expectedContainerDirectoryIdentity: prepared.directoryIdentity
        ) {}
        for name in artifactNames {
            #expect(try ioDirectory.entryMetadata(named: name) == nil)
        }
    }

    @Test func execArtifactCleanupNeverDeletesPostPreparationReplacements() async throws {
        for replacedName in RawExecArtifactRecord.expectedNames(execID: "swapped-exec") {
            let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
            let containerID = "prepared-container"
            let containerURL = root.appending(path: "containers/\(containerID)")
            try FileManager.default.createDirectory(
                at: containerURL, withIntermediateDirectories: true
            )
            defer { try? FileManager.default.removeItem(at: root) }
            let containerDirectory = try PersistentStateDirectory.open(containerURL)
            let prepared = try makePreparedState(
                in: containerDirectory, containerID: containerID
            )
            let exec = ExecRecord(
                id: "swapped-exec",
                containerID: containerID,
                containerInstanceID: prepared.currentContainer.instanceID,
                configuration: .init(arguments: ["true"])
            )
            let ioDirectory = try containerDirectory.openDirectory(named: "io")
            let names = RawExecArtifactRecord.expectedNames(execID: exec.id)
            var identities: [String: PersistentFileIdentity] = [:]
            for name in names {
                identities[name] = try ioDirectory.createSparseRegularFile(named: name, size: 0)
            }
            try RawExecArtifactJournal.recordPrepared(
                .init(
                    containerID: exec.containerID,
                    execID: exec.id,
                    fileIdentities: identities
                ),
                in: containerDirectory,
                artifacts: prepared.artifacts
            )
            let originalURL = ioDirectory.url.appending(path: replacedName)
            let retainedURL = ioDirectory.url.appending(path: "retained-\(replacedName)")
            let replacement = Data("replacement-must-remain".utf8)
            try FileManager.default.moveItem(at: originalURL, to: retainedURL)
            try replacement.write(to: originalURL)

            await #expect(throws: BackendResourceRollbackIncompleteError.self) {
                try await RawVirtualizationBackend.discardExecArtifacts(
                    root: root,
                    exec: exec,
                    expectedContainerDirectoryIdentity: prepared.directoryIdentity
                ) {}
            }
            #expect(try Data(contentsOf: originalURL) == replacement)
            #expect(FileManager.default.fileExists(atPath: retainedURL.path))
            let active = try RawExecArtifactJournal.activeRecord(
                containerID: exec.containerID,
                execID: exec.id,
                in: containerDirectory,
                artifacts: prepared.artifacts
            )
            #expect(active != nil)
        }
    }

    @Test func staleExecDiscardAfterPublicIDReuseDoesNotTouchReplacement() async throws {
        struct GuestUnavailable: Error {}

        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerID = "reused-container-id"
        let execID = "reused-exec-id"
        let containerURL = root.appending(path: "containers/\(containerID)")
        let retainedContainerURL = root.appending(
            path: "containers/retained-\(containerID)"
        )
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let originalDirectory = try PersistentStateDirectory.open(containerURL)
        let original = try makePreparedState(
            in: originalDirectory, containerID: containerID
        )
        let stale = ExecRecord(
            id: execID,
            containerID: containerID,
            containerInstanceID: original.currentContainer.instanceID,
            configuration: .init(arguments: ["true"])
        )
        let originalTransaction = try RawExecArtifactTransaction.prepare(
            containerID: containerID,
            execID: execID,
            attachStdin: true,
            in: originalDirectory,
            artifacts: original.artifacts
        )

        await #expect(throws: GuestUnavailable.self) {
            try await RawVirtualizationBackend.discardExecArtifacts(
                root: root,
                exec: stale,
                expectedContainerDirectoryIdentity: original.directoryIdentity
            ) {
                throw GuestUnavailable()
            }
        }
        #expect(try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: execID,
            in: originalDirectory,
            artifacts: original.artifacts
        ) == originalTransaction.record)

        try FileManager.default.moveItem(
            at: containerURL, to: retainedContainerURL
        )
        try FileManager.default.createDirectory(
            at: containerURL, withIntermediateDirectories: false
        )
        let containerDirectory = try PersistentStateDirectory.open(containerURL)
        let replacement = try makePreparedState(
            in: containerDirectory, containerID: containerID
        )
        let transaction = try RawExecArtifactTransaction.prepare(
            containerID: containerID,
            execID: execID,
            attachStdin: true,
            in: containerDirectory,
            artifacts: replacement.artifacts
        )
        let replacementRecord = transaction.record
        let io = try containerDirectory.openDirectory(named: "io")
        let replacementNames = RawExecArtifactRecord.expectedNames(execID: execID)
        let guestCalls = LockedOperationRecorder()
        let exact = ExecRecord(
            id: execID,
            containerID: containerID,
            containerInstanceID: replacement.currentContainer.instanceID,
            configuration: .init(arguments: ["true"])
        )
        let staleCleanupKey = RawExecCleanupKey(
            exec: stale,
            containerDirectoryIdentity: original.directoryIdentity
        )
        let replacementCleanupKey = RawExecCleanupKey(
            exec: exact,
            containerDirectoryIdentity: replacement.directoryIdentity
        )
        #expect(staleCleanupKey != replacementCleanupKey)
        var cleanupFailures = [staleCleanupKey: "old cleanup failed"]
        #expect(cleanupFailures.keys.filter {
            $0.owns(
                container: replacement.currentContainer,
                directoryIdentity: replacement.directoryIdentity
            )
        }.isEmpty)

        try await RawVirtualizationBackend.discardExecArtifacts(
            root: root,
            exec: stale,
            expectedContainerDirectoryIdentity: original.directoryIdentity
        ) {
            guestCalls.record("stale")
        }
        #expect(guestCalls.values().isEmpty)
        #expect(try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: execID,
            in: containerDirectory,
            artifacts: replacement.artifacts
        ) == replacementRecord)
        for name in replacementNames {
            #expect(try io.entryMetadata(named: name)?.identity
                == replacementRecord.fileIdentities[name])
        }

        let retainedDirectory = try PersistentStateDirectory.open(retainedContainerURL)
        #expect(try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: execID,
            in: retainedDirectory,
            artifacts: original.artifacts
        ) == originalTransaction.record)
        let retainedIO = try retainedDirectory.openDirectory(named: "io")
        for name in replacementNames {
            #expect(try retainedIO.entryMetadata(named: name)?.identity
                == originalTransaction.record.fileIdentities[name])
        }

        cleanupFailures[replacementCleanupKey] = "replacement cleanup failed"
        let replacementFailures = cleanupFailures.keys.filter {
            $0.owns(
                container: replacement.currentContainer,
                directoryIdentity: replacement.directoryIdentity
            )
        }
        #expect(replacementFailures == [replacementCleanupKey])

        try await RawVirtualizationBackend.discardExecArtifacts(
            root: root,
            exec: exact,
            expectedContainerDirectoryIdentity: replacement.directoryIdentity
        ) {
            guestCalls.record("exact")
        }
        #expect(guestCalls.values() == ["exact"])
        #expect(try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: execID,
            in: containerDirectory,
            artifacts: replacement.artifacts
        ) == nil)
        for name in replacementNames {
            #expect(try io.entryMetadata(named: name) == nil)
        }
        #expect(try RawExecArtifactJournal.activeRecord(
            containerID: containerID,
            execID: execID,
            in: retainedDirectory,
            artifacts: original.artifacts
        ) == originalTransaction.record)
        for name in replacementNames {
            #expect(try retainedIO.entryMetadata(named: name)?.identity
                == originalTransaction.record.fileIdentities[name])
        }
    }

    @Test func blockVolumesUseTheReportedSparseCapacity() {
        #expect(VolumeRecord.defaultSizeBytes == 512 * 1_024 * 1_024 * 1_024)
        #expect(RawVirtualizationBackend.defaultVolumeDiskBytes == VolumeRecord.defaultSizeBytes)
        #expect(RawVirtualizationBackend.defaultStorageDiskBytes == VolumeRecord.defaultSizeBytes)
    }

    @Test func containerAnnotationsReachGuestWorkloadSpecification() throws {
        var container = ContainerRecord(
            id: "annotated-container", name: "annotated", image: "alpine:latest",
            processArguments: ["true"]
        )
        container.annotations = ["io.example.owner": "runtime"]

        let workload = try RawVirtualizationBackend.workloadSpecification(
            container: container, imageConfiguration: nil, mounts: [], networks: [],
            hosts: [:], volumeServer: nil
        )

        #expect(workload.annotations == container.annotations)
    }

    @Test func containerUlimitsReachGuestWorkloadSpecification() throws {
        var container = ContainerRecord(
            id: "limited-container", name: "limited", image: "alpine:latest",
            processArguments: ["true"]
        )
        container.ulimits = [
            .init(name: "nofile", soft: 1_024, hard: 2_048),
            .init(name: "core", soft: -1, hard: -1),
        ]

        let workload = try RawVirtualizationBackend.workloadSpecification(
            container: container, imageConfiguration: nil, mounts: [], networks: [],
            hosts: [:], volumeServer: nil
        )

        #expect(workload.rlimits == [
            .init(type: "nofile", soft: 1_024, hard: 2_048),
            .init(type: "core", soft: UInt64.max, hard: UInt64.max),
        ])
    }

    @Test func containerIPCModeReachesGuestWorkloadSpecification() throws {
        var container = ContainerRecord(
            id: "ipc-none-container", name: "ipc-none", image: "alpine:latest",
            processArguments: ["true"]
        )
        container.ipcMode = "none"

        let workload = try RawVirtualizationBackend.workloadSpecification(
            container: container, imageConfiguration: nil, mounts: [], networks: [],
            hosts: [:], volumeServer: nil
        )

        #expect(workload.ipcMode == "none")
    }

    @Test func containerPathPoliciesReachGuestWorkloadSpecification() throws {
        var container = ContainerRecord(
            id: "path-policy-container", name: "path-policy", image: "alpine:latest",
            processArguments: ["true"]
        )
        container.maskedPaths = ["/proc/kcore", "/sys/firmware"]
        container.readonlyPaths = ["/proc/sys"]

        let workload = try RawVirtualizationBackend.workloadSpecification(
            container: container, imageConfiguration: nil, mounts: [], networks: [],
            hosts: [:], volumeServer: nil
        )

        #expect(workload.maskedPaths == container.maskedPaths)
        #expect(workload.readonlyPaths == container.readonlyPaths)
    }

    @Test func containerPathPolicyDefaultsOverridesAndPrivilegedModeMatchDocker() throws {
        var container = ContainerRecord(
            id: "default-path-policy-container", name: "default-path-policy",
            image: "alpine:latest", processArguments: ["true"]
        )
        container.cpus = 2

        func workload() throws -> GuestProtocol.Workload {
            try RawVirtualizationBackend.workloadSpecification(
                container: container, imageConfiguration: nil, mounts: [], networks: [],
                hosts: [:], volumeServer: nil
            )
        }

        #expect(try workload().maskedPaths == [
            "/proc/acpi", "/proc/asound", "/proc/interrupts", "/proc/kcore", "/proc/keys",
            "/proc/latency_stats", "/proc/sched_debug", "/proc/scsi", "/proc/timer_list",
            "/proc/timer_stats", "/sys/devices/virtual/powercap", "/sys/firmware",
            "/sys/devices/system/cpu/cpu0/thermal_throttle",
            "/sys/devices/system/cpu/cpu1/thermal_throttle",
        ])
        #expect(try workload().readonlyPaths == [
            "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger",
        ])

        container.maskedPaths = []
        container.readonlyPaths = []
        #expect(try workload().maskedPaths.isEmpty)
        #expect(try workload().readonlyPaths.isEmpty)

        container.maskedPaths = ["/etc/passwd"]
        container.readonlyPaths = ["/tmp"]
        container.privileged = true
        #expect(try workload().maskedPaths.isEmpty)
        #expect(try workload().readonlyPaths.isEmpty)
    }

    @Test func multiContainerVolumesUseSharedStorageBeforeVMsStart() throws {
        let modes = try RawVirtualizationBackend.resolveVolumeStorageModes(
            names: ["compose-data", "buildkit-state"],
            referenceCounts: ["compose-data": 2, "buildkit-state": 1],
            existing: [:]
        )

        #expect(modes["compose-data"] == .shared)
        #expect(modes["buildkit-state"] == .block)
        #expect(throws: EngineError.self) {
            try RawVirtualizationBackend.resolveVolumeStorageModes(
                names: ["buildkit-state"],
                referenceCounts: ["buildkit-state": 2],
                existing: ["buildkit-state": .block]
            )
        }
    }
    #endif

    #if os(macOS)
    @Test func managementAddressesStayInsideIsolatedSubnetAndAvoidServer() {
        let address = RawVirtualizationBackend.managementAddress(for: "container-id")
        #expect(address.hasPrefix("100."))
        #expect(address.hasSuffix("/10"))
        #expect(address != "100.64.0.1/10")
    }
    #endif

    #if os(macOS)
    @Test func runtimeSocketsRemainBelowDarwinPathLimitForLongDataRoots() throws {
        let socket = try RawVirtualizationBackend.makeRuntimeSocketPath()
        let longRoot = "/tmp/" + String(repeating: "nested-data-root/", count: 20)
        let specification = VMShimProtocol.Specification(
            containerID: "long-root",
            generation: 1,
            token: "secret",
            kernelPath: "/kernel",
            initialRamdiskPath: "/initramfs",
            rootDiskPath: "\(longRoot)/root.ext4",
            cpus: 1,
            memoryBytes: 268_435_456,
            macAddress: "02:ce:00:00:00:02",
            socketPath: socket,
            logPath: "\(longRoot)/shim.log"
        )

        #expect(socket.utf8.count < 104)
        #expect(socket.hasPrefix("/tmp/cengine-\(getuid())/"))
        #expect(
            VMShimClient.specificationURL(for: specification).path
                == URL(filePath: longRoot).appending(path: "shim.json").path
        )
    }

    @Test func rawKernelCommandLineKeepsVirtioPCIEnabled() {
        let commandLine = RawVirtualMachineConfiguration.kernelCommandLine(
            id: "test-container",
            kernelArguments: []
        )
        let arguments = commandLine.split(separator: " ")

        #expect(arguments.contains("console=hvc0"))
        #expect(arguments.contains("cengine.id=test-container"))
        #expect(!arguments.contains("pci=off"))
    }

    @Test func dockerVolumesMapAfterTheRootVirtioBlockDevice() throws {
        #expect(try RawVirtualizationBackend.volumeDevicePath(index: 0) == "/dev/vdb")
        #expect(try RawVirtualizationBackend.volumeDevicePath(index: 24) == "/dev/vdz")
        #expect(throws: EngineError.self) { try RawVirtualizationBackend.volumeDevicePath(index: 25) }
    }

    @MainActor @Test func containerShutdownDoesNotOwnInfrastructureTransportSockets() {
        func specification(kind: VMShimProtocol.Specification.Kind) -> VMShimProtocol.Specification {
            VMShimProtocol.Specification(
                kind: kind,
                containerID: "socket-owner",
                generation: 1,
                token: "secret",
                kernelPath: "/kernel",
                initialRamdiskPath: "/initramfs",
                rootDiskPath: "/root.ext4",
                cpus: 1,
                memoryBytes: 268_435_456,
                macAddress: "02:ce:00:00:00:03",
                socketPath: "/tmp/control.sock",
                logPath: "/tmp/shim.log",
                fileSystemSocketPath: "/tmp/filesystem.sock",
                networkSocketPath: "/tmp/network.sock"
            )
        }

        #expect(VMShimServer.ownedSocketPaths(specification(kind: .container)) == ["/tmp/control.sock"])
        #expect(Set(VMShimServer.ownedSocketPaths(specification(kind: .storage))) == [
            "/tmp/control.sock", "/tmp/filesystem.sock", "/tmp/network.sock",
        ])
    }

    @MainActor @Test func virtioSocketAttemptsHaveABoundedDeadline() async {
        await #expect(throws: EngineError.self) {
            try await RawContainerVirtualMachine.awaitConnection(timeout: .milliseconds(1)) { _ in }
        }
    }

    @MainActor @Test func lateVirtioSocketSuccessIsDisposedAfterAttemptTimeout() async {
        var resolver: (@MainActor (Result<Int, Error>) -> Void)?
        var disposed: [Int] = []

        await #expect(throws: EngineError.self) {
            try await RawContainerVirtualMachine.awaitBoundedResult(
                timeout: .milliseconds(1),
                start: { resolver = $0 },
                disposeLateSuccess: { disposed.append($0) }
            )
        }
        resolver?(.success(42))
        #expect(disposed == [42])
    }

    @Test func guestConnectUsesOnlyTheAbsoluteDeadlineRemainder() throws {
        let now: UInt64 = 40_000_000_000
        #expect(try VMShimServer.guestConnectTimeout(
            deadlineNanoseconds: now + 3_000_000_000,
            nowNanoseconds: now
        ) == .seconds(3))
        #expect(try VMShimServer.guestConnectTimeout(
            deadlineNanoseconds: nil, nowNanoseconds: now
        ) == .seconds(5))
        #expect(throws: AsyncTimeout.TimeoutError.self) {
            try VMShimServer.guestConnectTimeout(
                deadlineNanoseconds: now, nowNanoseconds: now
            )
        }
    }

    @Test func timeoutCancelsTheLosingOperation() async {
        let (cancellations, continuation) = AsyncStream<Void>.makeStream()
        await #expect(throws: AsyncTimeout.TimeoutError.self) {
            try await AsyncTimeout.run(for: .milliseconds(10)) {
                do {
                    try await Task.sleep(for: .seconds(30))
                    return true
                } catch {
                    continuation.yield()
                    continuation.finish()
                    throw error
                }
            }
        }
        var iterator = cancellations.makeAsyncIterator()
        #expect(await iterator.next() != nil)
    }

    @Test func callerCancellationPromptlyEscapesANoncooperativeTimedOperation() async {
        let (startStream, startContinuation) = AsyncStream<Void>.makeStream()
        let (releaseStream, releaseContinuation) = AsyncStream<Void>.makeStream()
        let (observationStream, observationContinuation) = AsyncStream<Bool>.makeStream()
        let task = Task {
            try await AsyncTimeout.run(for: .seconds(30)) {
                startContinuation.yield()
                var releaseIterator = releaseStream.makeAsyncIterator()
                _ = await releaseIterator.next() // Deliberately ignores cancellation.
                observationContinuation.yield(Task.isCancelled)
                observationContinuation.finish()
                return true
            }
        }
        var startIterator = startStream.makeAsyncIterator()
        _ = await startIterator.next()

        let clock = ContinuousClock()
        let cancelledAt = clock.now
        task.cancel()
        do {
            _ = try await task.value
            Issue.record("cancelled timeout unexpectedly returned a value")
        } catch is CancellationError {
            // Expected: caller cancellation wins independently of the child.
        } catch {
            Issue.record("cancelled timeout threw \(error) instead of CancellationError")
        }
        #expect(clock.now - cancelledAt < .seconds(1))

        releaseContinuation.yield()
        releaseContinuation.finish()
        var observationIterator = observationStream.makeAsyncIterator()
        #expect(await observationIterator.next() == true)
    }

    @Test func descriptorInvalidationCannotShutdownAReusedUnrelatedSocket() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let socketPath = try RawVirtualizationBackend.makeRuntimeSocketPath()
        let listener = try UnixSocket.listen(path: socketPath)
        defer { Darwin.close(listener) }
        let requestReceived = DispatchSemaphore(value: 0)
        let sendResponse = DispatchSemaphore(value: 0)
        let invalidationEntered = DispatchSemaphore(value: 0)
        let releaseInvalidation = DispatchSemaphore(value: 0)
        let descriptorReleaseAttempted = DispatchSemaphore(value: 0)
        let invalidationFinished = DispatchSemaphore(value: 0)
        let invalidatedDescriptor = ShimDescriptorBox()
        let specification = VMShimProtocol.Specification(
            containerID: "descriptor-owner",
            generation: 11,
            token: "test-token",
            kernelPath: "/kernel",
            initialRamdiskPath: "/initramfs",
            rootDiskPath: "/root.ext4",
            cpus: 1,
            memoryBytes: 268_435_456,
            macAddress: "02:ce:00:00:00:11",
            socketPath: socketPath,
            logPath: root.appending(path: "shim.log").path
        )

        Thread.detachNewThread {
            guard let peer = try? UnixSocket.accept(listener) else { return }
            defer { Darwin.close(peer) }
            let file = FileHandle(fileDescriptor: peer, closeOnDealloc: false)
            let prefix = file.readData(ofLength: 4)
            guard prefix.count == 4 else { return }
            let size = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            let body = file.readData(ofLength: Int(size))
            guard let request = try? VMShimProtocol.decode(prefix + body) else { return }
            requestReceived.signal()
            sendResponse.wait()
            let payload = try! JSONEncoder().encode(true)
            let response = VMShimProtocol.Envelope(
                id: request.id,
                token: specification.token,
                operation: request.operation,
                payload: payload
            )
            try? file.write(contentsOf: VMShimProtocol.encode(response))
        }

        let client = VMShimClient(
            specification: specification,
            descriptorInvalidationHook: { descriptor in
                invalidatedDescriptor.store(descriptor)
                invalidationEntered.signal()
                releaseInvalidation.wait()
            },
            descriptorReleaseHook: { _ in descriptorReleaseAttempted.signal() }
        )
        let request = Task {
            try await client.guest(operation: "descriptor-test", payload: false, response: Bool.self)
        }
        #expect(await semaphoreArrives(requestReceived))
        DispatchQueue.global().async {
            client.invalidateRequests()
            invalidationFinished.signal()
        }
        #expect(await semaphoreArrives(invalidationEntered))
        sendResponse.signal()
        #expect(await semaphoreArrives(descriptorReleaseAttempted))

        var unrelated = [CInt](repeating: -1, count: 2)
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &unrelated) == 0)
        defer { unrelated.forEach { Darwin.close($0) } }
        let original = try #require(invalidatedDescriptor.load())
        #expect(!unrelated.contains(original))

        releaseInvalidation.signal()
        #expect(await semaphoreArrives(invalidationFinished))
        #expect(try await request.value)
        var sent: UInt8 = 0x5a
        var received: UInt8 = 0
        #expect(Darwin.write(unrelated[0], &sent, 1) == 1)
        #expect(Darwin.read(unrelated[1], &received, 1) == 1)
        #expect(received == sent)
    }

    @Test func deadlineAwareGuestRequestClosesItsTimedOutDescriptor() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let socketPath = try RawVirtualizationBackend.makeRuntimeSocketPath()
        let listener = try UnixSocket.listen(path: socketPath)
        defer { Darwin.close(listener) }
        let requestReceived = DispatchSemaphore(value: 0)
        let peerObservedClosure = DispatchSemaphore(value: 0)
        let descriptorReleased = DispatchSemaphore(value: 0)
        let requestReceivedAt = LockedUptimeBox()
        let descriptorReleasedAt = LockedUptimeBox()

        Thread.detachNewThread {
            guard let peer = try? UnixSocket.accept(listener) else { return }
            defer { Darwin.close(peer) }
            let file = FileHandle(fileDescriptor: peer, closeOnDealloc: false)
            let prefix = file.readData(ofLength: 4)
            guard prefix.count == 4 else { return }
            let size = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            guard file.readData(ofLength: Int(size)).count == Int(size) else { return }
            requestReceivedAt.storeNow()
            requestReceived.signal()
            var byte: UInt8 = 0
            while Darwin.read(peer, &byte, 1) > 0 {}
            peerObservedClosure.signal()
        }

        let specification = VMShimProtocol.Specification(
            containerID: "deadline-guest",
            generation: 19,
            token: "test-token",
            kernelPath: "/kernel",
            initialRamdiskPath: "/initramfs",
            rootDiskPath: "/root.ext4",
            cpus: 1,
            memoryBytes: 268_435_456,
            macAddress: "02:ce:00:00:00:19",
            socketPath: socketPath,
            logPath: root.appending(path: "shim.log").path
        )
        let client = VMShimClient(
            specification: specification,
            descriptorInvalidationHook: { _ in },
            descriptorReleaseHook: { _ in
                descriptorReleasedAt.storeNow()
                descriptorReleased.signal()
            }
        )
        await #expect(throws: AsyncTimeout.TimeoutError.self) {
            try await client.guest(
                operation: "wait-exec",
                payload: ["id": "blocked"],
                response: Bool.self,
                deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 100_000_000
            )
        }
        #expect(await semaphoreArrives(requestReceived))
        #expect(await semaphoreArrives(descriptorReleased))
        #expect(await semaphoreArrives(peerObservedClosure))
        let receivedAt = try #require(requestReceivedAt.load())
        let releasedAt = try #require(descriptorReleasedAt.load())
        #expect(releasedAt >= receivedAt)
        #expect(releasedAt - receivedAt < 1_000_000_000)
    }

    @Test func unresponsiveShimTerminationAbortsItsSocketAndMeetsTheDeadline() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let socketPath = try RawVirtualizationBackend.makeRuntimeSocketPath()
        let listener = try UnixSocket.listen(path: socketPath)
        defer { Darwin.close(listener) }

        Thread.detachNewThread {
            guard let peer = try? UnixSocket.accept(listener) else { return }
            defer { Darwin.close(peer) }
            var buffer = [UInt8](repeating: 0, count: 4_096)
            while Darwin.read(peer, &buffer, buffer.count) > 0 {}
        }

        let process = Process()
        process.executableURL = URL(filePath: "/bin/sleep")
        process.arguments = ["30"]
        try process.run()
        defer { if process.isRunning { process.terminate() } }
        Thread.detachNewThread {
            process.waitUntilExit()
        }

        let specification = VMShimProtocol.Specification(
            containerID: "wedged-shim",
            generation: 7,
            token: "test-token",
            kernelPath: "/kernel",
            initialRamdiskPath: "/initramfs",
            rootDiskPath: "/root.ext4",
            cpus: 1,
            memoryBytes: 268_435_456,
            macAddress: "02:ce:00:00:00:07",
            socketPath: socketPath,
            logPath: root.appending(path: "shim.log").path
        )
        let status = VMShimProtocol.Status(
            containerID: specification.containerID,
            generation: specification.generation,
            state: .paused,
            processIdentifier: process.processIdentifier,
            processStartTime: try #require(
                VMShimClient.processStartTime(for: process.processIdentifier)
            )
        )
        try JSONEncoder().encode(status).write(
            to: URL(filePath: socketPath + ".status"), options: .atomic
        )

        let client = VMShimClient(specification: specification)
        let clock = ContinuousClock()
        let started = clock.now
        try await client.terminate(gracePeriodMilliseconds: 100, forceWaitMilliseconds: 1_000)

        #expect(clock.now - started < .seconds(2))
        let observationDeadline = clock.now.advanced(by: .milliseconds(250))
        while process.isRunning, clock.now < observationDeadline {
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(!process.isRunning)
    }

    @Test func execStreamRelayWaitsForHTTPUpgradeActivation() throws {
        var clientPair = [CInt](repeating: -1, count: 2)
        var guestPair = [CInt](repeating: -1, count: 2)
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &clientPair) == 0)
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &guestPair) == 0)
        defer { (clientPair + guestPair).forEach { Darwin.close($0) } }

        let clientRelayDescriptor = clientPair[1]
        let guestRelayDescriptor = guestPair[1]
        let clientRelay = FileHandle(fileDescriptor: clientRelayDescriptor, closeOnDealloc: false)
        let guestRelay = FileHandle(fileDescriptor: guestRelayDescriptor, closeOnDealloc: false)
        let relay = BidirectionalDescriptorRelay(
            left: clientRelay,
            right: guestRelay,
            close: {
                _ = Darwin.shutdown(clientRelayDescriptor, SHUT_RDWR)
                _ = Darwin.shutdown(guestRelayDescriptor, SHUT_RDWR)
            },
            completion: {}
        )
        relay.start(afterActivationByte: VMShimProtocol.execStreamActivationByte)
        defer { relay.cancel() }

        let output = Array("framed-output".utf8)
        #expect(output.withUnsafeBytes { Darwin.write(guestPair[0], $0.baseAddress, $0.count) } == output.count)
        #expect(!descriptorIsReadable(clientPair[0], timeoutMilliseconds: 50))

        var activation = VMShimProtocol.execStreamActivationByte
        #expect(Darwin.write(clientPair[0], &activation, 1) == 1)
        #expect(descriptorIsReadable(clientPair[0], timeoutMilliseconds: 1_000))
        var receivedOutput = [UInt8](repeating: 0, count: output.count)
        #expect(Darwin.read(clientPair[0], &receivedOutput, receivedOutput.count) == output.count)
        #expect(receivedOutput == output)

        let input = Array("stdin".utf8)
        #expect(input.withUnsafeBytes { Darwin.write(clientPair[0], $0.baseAddress, $0.count) } == input.count)
        #expect(descriptorIsReadable(guestPair[0], timeoutMilliseconds: 1_000))
        var receivedInput = [UInt8](repeating: 0, count: input.count)
        #expect(Darwin.read(guestPair[0], &receivedInput, receivedInput.count) == input.count)
        #expect(receivedInput == input)
    }

    @Test func staleShimStatusCannotKillAReusedProcessIdentifier() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let socketPath = try RawVirtualizationBackend.makeRuntimeSocketPath()
        let listener = try UnixSocket.listen(path: socketPath)
        defer { Darwin.close(listener) }
        Thread.detachNewThread {
            guard let peer = try? UnixSocket.accept(listener) else { return }
            defer { Darwin.close(peer) }
            var buffer = [UInt8](repeating: 0, count: 4_096)
            while Darwin.read(peer, &buffer, buffer.count) > 0 {}
        }

        let unrelated = Process()
        unrelated.executableURL = URL(filePath: "/bin/sleep")
        unrelated.arguments = ["30"]
        try unrelated.run()
        defer { if unrelated.isRunning { unrelated.terminate() } }
        Thread.detachNewThread { unrelated.waitUntilExit() }
        let actualStart = try #require(
            VMShimClient.processStartTime(for: unrelated.processIdentifier)
        )
        let specification = VMShimProtocol.Specification(
            containerID: "stale-shim",
            generation: 17,
            token: "test-token",
            kernelPath: "/kernel",
            initialRamdiskPath: "/initramfs",
            rootDiskPath: "/root.ext4",
            cpus: 1,
            memoryBytes: 268_435_456,
            macAddress: "02:ce:00:00:00:17",
            socketPath: socketPath,
            logPath: root.appending(path: "shim.log").path
        )
        let stale = VMShimProtocol.Status(
            containerID: specification.containerID,
            generation: specification.generation,
            state: .paused,
            processIdentifier: unrelated.processIdentifier,
            processStartTime: actualStart &+ 1
        )
        let staleStatusData = try JSONEncoder().encode(stale)
        try staleStatusData.write(
            to: URL(filePath: socketPath + ".status"), options: .atomic
        )

        let client = VMShimClient(specification: specification)
        await #expect(throws: EngineError.self) {
            try await client.terminate(gracePeriodMilliseconds: 50, forceWaitMilliseconds: 50)
        }
        #expect(unrelated.isRunning)
        #expect(VMShimClient.processStartTime(for: unrelated.processIdentifier) == actualStart)
        #expect(FileManager.default.fileExists(atPath: socketPath))
        #expect(try Data(contentsOf: URL(filePath: socketPath + ".status")) == staleStatusData)
        let reboundConnection = try UnixSocket.connect(path: socketPath)
        Darwin.close(reboundConnection)
    }
    #endif
}

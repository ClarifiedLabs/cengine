import CryptoKit
import Darwin
import Dispatch
import Foundation
import Testing
@testable import CEngineCore
@testable import CEngineRuntime

private final class DataBox: @unchecked Sendable {
    private let lock = NSLock()
    private var storage = Data()
    func append(_ data: Data) { lock.withLock { storage.append(data) } }
    var value: Data { lock.withLock { storage } }
}

private final class FailingOutputPersistence: @unchecked Sendable {
    private struct StreamState {
        var attempts = 0
        var data = Data()
    }

    private enum InjectedFailure: Error { case firstAttempt }
    private let lock = NSLock()
    private var stdout = StreamState()
    private var stderr = StreamState()

    func write(_ data: Data, stream: ContainerIOBridge.OutputStream) throws {
        try lock.withLock {
            switch stream {
            case .stdout:
                stdout.attempts += 1
                guard stdout.attempts > 1 else { throw InjectedFailure.firstAttempt }
                stdout.data.append(data)
            case .stderr:
                stderr.attempts += 1
                guard stderr.attempts > 1 else { throw InjectedFailure.firstAttempt }
                stderr.data.append(data)
            }
        }
    }

    func attempts(for stream: ContainerIOBridge.OutputStream) -> Int {
        lock.withLock { stream == .stdout ? stdout.attempts : stderr.attempts }
    }

    func data(for stream: ContainerIOBridge.OutputStream) -> Data {
        lock.withLock { stream == .stdout ? stdout.data : stderr.data }
    }
}

private final class ChunkFailurePersistence: @unchecked Sendable {
    private enum InjectedFailure: Error { case selectedChunk }

    private let lock = NSLock()
    private let bridge: ContainerIOBridge
    private let failureObserved = DispatchSemaphore(value: 0)
    private var stdoutAttempts: [Data] = []
    private var failed = false

    init(bridge: ContainerIOBridge) { self.bridge = bridge }

    func write(_ data: Data, stream: ContainerIOBridge.OutputStream) throws {
        if stream == .stdout {
            let shouldFail = lock.withLock {
                stdoutAttempts.append(data)
                guard stdoutAttempts.count == 2, !failed else { return false }
                failed = true
                return true
            }
            if shouldFail {
                failureObserved.signal()
                throw InjectedFailure.selectedChunk
            }
        }
        try bridge.writer(stream).write(data)
    }

    func waitForFailure() -> Bool {
        failureObserved.wait(timeout: .now() + .seconds(2)) == .success
    }

    var attempts: [Data] { lock.withLock { stdoutAttempts } }
}

private final class GrowingOutputPersistence: @unchecked Sendable {
    private let lock = NSLock()
    private let bridge: ContainerIOBridge
    private let source: FileHandle
    private let growth: Data
    private var didGrow = false
    private var stdoutChunks: [Data] = []

    init(bridge: ContainerIOBridge, source: FileHandle, growth: Data) {
        self.bridge = bridge
        self.source = source
        self.growth = growth
    }

    func write(_ data: Data, stream: ContainerIOBridge.OutputStream) throws {
        let shouldGrow = lock.withLock {
            if stream == .stdout { stdoutChunks.append(data) }
            guard stream == .stdout, !didGrow else { return false }
            didGrow = true
            return true
        }
        if shouldGrow {
            try source.seekToEnd()
            try source.write(contentsOf: growth)
            try source.synchronize()
        }
        try bridge.writer(stream).write(data)
    }

    var chunks: [Data] { lock.withLock { stdoutChunks } }
}

private final class InputPublicationProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var events: [String] = []
    private var synchronizedData = Data()

    func recordSynchronization(_ data: Data) {
        lock.withLock {
            synchronizedData = data
            events.append("synchronize")
        }
    }

    func recordMarkerAttempt() {
        lock.withLock { events.append("marker") }
    }

    var observedEvents: [String] { lock.withLock { events } }
    var dataAtSynchronization: Data { lock.withLock { synchronizedData } }
}

private final class DrainRendezvous: @unchecked Sendable {
    private let lock = NSLock()
    private let peerArrived = DispatchSemaphore(value: 0)
    private var arrivals = 0

    func wait() {
        let arrival = lock.withLock { arrivals += 1; return arrivals }
        if arrival == 1 {
            _ = peerArrived.wait(timeout: .now() + .milliseconds(250))
        } else if arrival == 2 {
            peerArrived.signal()
        }
    }
}

private final class AtomicStoreParentRelocator: @unchecked Sendable {
    enum Replacement: Equatable { case directory, symbolicLink }

    private let lock = NSLock()
    private let parent: URL
    private let detached: URL
    private let replacement: Replacement
    private var fired = false

    init(
        parent: URL,
        detached: URL,
        replacement: Replacement = .directory
    ) {
        self.parent = parent
        self.detached = detached
        self.replacement = replacement
    }

    func relocate(at boundary: AtomicStoreSaveBoundary) throws {
        guard boundary == .replacementCompleted else { return }
        try lock.withLock {
            guard !fired else { return }
            fired = true
            try FileManager.default.moveItem(at: parent, to: detached)
            switch replacement {
            case .directory:
                try FileManager.default.createDirectory(
                    at: parent, withIntermediateDirectories: false
                )
            case .symbolicLink:
                try FileManager.default.createSymbolicLink(
                    at: parent, withDestinationURL: detached
                )
            }
        }
    }
}

private final class AtomicStoreTargetSwapper: @unchecked Sendable {
    private let lock = NSLock()
    private let target: URL
    private let replacement: URL
    private let detached: URL
    private var fired = false

    init(target: URL, replacement: URL, detached: URL) {
        self.target = target
        self.replacement = replacement
        self.detached = detached
    }

    func swap() throws {
        try lock.withLock {
            guard !fired else { return }
            fired = true
            try FileManager.default.moveItem(at: target, to: detached)
            try FileManager.default.moveItem(at: replacement, to: target)
        }
    }
}

@Suite struct CoreTests {
    @Test func versionReadsBundleMetadataAndFallsBack() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let bundleURL = root.appending(path: "VersionFixture.bundle", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: bundleURL, withIntermediateDirectories: true)
        let info: [String: Any] = [
            "CFBundleIdentifier": "dev.cengine.version-fixture",
            "CFBundleName": "VersionFixture",
            "CFBundlePackageType": "BNDL",
            "CFBundleShortVersionString": "2.3.4",
            "CEngineGitCommit": "abcdef0",
            "CEngineBuildTime": "2026-07-10T22:08:24Z",
        ]
        let data = try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
        try data.write(to: bundleURL.appending(path: "Info.plist"))
        let bundle = try #require(Bundle(url: bundleURL))

        #expect(CEngineVersion.shortVersion(bundle: bundle) == "2.3.4")
        #expect(CEngineVersion.gitCommit(bundle: bundle) == "abcdef0")
        #expect(CEngineVersion.buildTime(bundle: bundle) == "2026-07-10T22:08:24Z")
        #expect(CEngineVersion.shortVersion(bundle: Bundle()) == "0.0.1")
        #expect(CEngineVersion.gitCommit(bundle: Bundle()) == "unknown")
        #expect(CEngineVersion.buildTime(bundle: Bundle()) == "")
    }

    @Test func incompleteGuestAssetsAreNotAcceptedAsInstalled() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let kernel = root.appending(path: "vmlinux")
        try Data("not a kernel".utf8).write(to: kernel)
        #expect(!GuestAssetInstaller.isInstalled(paths: EnginePaths(home: root)))
    }

    @Test func staleGuestAssetsAreReinstalledFromSource() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appending(path: "source", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        for name in GuestAssetInstaller.names {
            try Data("new \(name)".utf8).write(to: source.appending(path: name))
        }
        let paths = EnginePaths(home: root.appending(path: "home", directoryHint: .isDirectory))
        #expect(GuestAssetInstaller.needsInstall(paths: paths, source: source))

        let assets = paths.kernel.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: assets, withIntermediateDirectories: true)
        for name in GuestAssetInstaller.names {
            try Data("stale \(name)".utf8).write(to: assets.appending(path: name))
        }
        #expect(GuestAssetInstaller.isInstalled(paths: paths))
        #expect(GuestAssetInstaller.needsInstall(paths: paths, source: source))

        try GuestAssetInstaller.install(paths: paths, source: source)
        #expect(!GuestAssetInstaller.needsInstall(paths: paths, source: source))
        #expect(try Data(contentsOf: paths.kernel) == Data("new vmlinux".utf8))
    }

    @Test func guestAssetStalenessUsesSourceManifestWhenPresent() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appending(path: "source", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        var manifest = ""
        for name in GuestAssetInstaller.names {
            let data = Data("asset \(name)".utf8)
            try data.write(to: source.appending(path: name))
            let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            manifest += "\(digest)  \(name)\n"
        }
        try Data(manifest.utf8).write(to: source.appending(path: "SHA256SUMS"))

        let paths = EnginePaths(home: root.appending(path: "home", directoryHint: .isDirectory))
        try GuestAssetInstaller.install(paths: paths, source: source)
        #expect(!GuestAssetInstaller.needsInstall(paths: paths, source: source))

        try Data("tampered".utf8).write(to: paths.containerInitialRamdisk)
        #expect(GuestAssetInstaller.needsInstall(paths: paths, source: source))
    }

    @Test func identifiersAreDockerCompatible() {
        let id = Identifier.random()
        #expect(id.count == 64)
        #expect(id.allSatisfy { $0.isHexDigit })
        #expect(Identifier.validateName("web-1.example"))
        #expect(!Identifier.validateName("bad/name"))
    }

    @Test func dockerImageReferencesAreNormalized() {
        #expect(ImageReference.normalized("debian") == "docker.io/library/debian:latest")
        #expect(ImageReference.normalized("example/debian") == "docker.io/example/debian:latest")
        #expect(ImageReference.normalized("registry.example/debian:bookworm") == "registry.example/debian:bookworm")
    }

    @Test func bindSourceFallsBackToManagedStorageForUnwritableHostNamespace() throws {
        let temporary = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let managed = temporary.appending(path: "managed")
        defer { try? FileManager.default.removeItem(at: temporary) }

        let requested = URL(filePath: "/lib/cengine-bind-source-\(UUID().uuidString)")
        let mount = MountRecord(kind: .bind, source: requested.path, destination: "/data", createSourceIfMissing: true)
        let source = try #require(HostBindSourceResolver(root: managed).resolve([mount])[0])
        guard case .virtioFS(let share) = source else {
            Issue.record("managed bind source was not prepared as a VirtioFS share")
            return
        }
        #expect(share.shareRoot.path.hasPrefix(managed.path + "/"))
        #expect(share.subpath == nil)
        #expect(FileManager.default.fileExists(atPath: share.shareRoot.path))
    }

    @Test func unixSocketBindUsesVsockRelayInsteadOfVirtioFS() throws {
        let temporary = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let socket = temporary.appending(path: "docker.sock")
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temporary) }
        let descriptor = try UnixSocket.listen(path: socket.path)
        defer { close(descriptor) }

        let mount = MountRecord(kind: .bind, source: socket.path, destination: "/var/run/docker.sock")
        let source = try #require(HostBindSourceResolver(root: temporary).resolve([mount])[0])
        guard case .socket(let relay) = source else {
            Issue.record("Unix socket bind source was prepared as VirtioFS")
            return
        }
        #expect(relay.path == socket)
        #expect(relay.port == GuestProtocol.socketProxyPortBase)
        #expect(relay.mode == 0o600)
        #expect(relay.uid == UInt32(getuid()))
        #expect(relay.gid == UInt32(getgid()))
    }

    @Test func directorySymlinkBindUsesCanonicalVirtioFSRoot() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let actual = root.appending(path: "actual", directoryHint: .isDirectory)
        let alias = root.appending(path: "alias", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: actual, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: actual)
        defer { try? FileManager.default.removeItem(at: root) }

        let mount = MountRecord(
            kind: .bind, source: alias.path, destination: "/data"
        )
        let source = try #require(HostBindSourceResolver(root: root).resolve([mount])[0])
        guard case .virtioFS(let share) = source else {
            Issue.record("directory symlink bind was not prepared as VirtioFS")
            return
        }
        let canonical = actual.resolvingSymlinksInPath()
        let canonicalIdentity = try PersistentStateDirectory.open(canonical).identity
        #expect(share.shareRoot.path == canonical.path)
        #expect(share.subpath == nil)
        #expect(share.identity == canonicalIdentity)
    }

    @Test func fileBindUnderSymlinkedParentUsesCanonicalRootAndLeaf() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let actual = root.appending(path: "actual", directoryHint: .isDirectory)
        let alias = root.appending(path: "alias", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: actual, withIntermediateDirectories: true)
        try Data("payload".utf8).write(to: actual.appending(path: "payload"))
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: actual)
        defer { try? FileManager.default.removeItem(at: root) }

        let mount = MountRecord(
            kind: .bind,
            source: alias.appending(path: "payload").path,
            destination: "/payload"
        )
        let source = try #require(HostBindSourceResolver(root: root).resolve([mount])[0])
        guard case .virtioFS(let share) = source else {
            Issue.record("file bind under symlinked parent was not prepared as VirtioFS")
            return
        }
        let canonical = actual.resolvingSymlinksInPath()
        let canonicalIdentity = try PersistentStateDirectory.open(canonical).identity
        #expect(share.shareRoot == canonical)
        #expect(share.subpath == "payload")
        #expect(share.identity == canonicalIdentity)
    }

    @Test func symlinkedDataRootInitializesAndPreparesThroughCanonicalDirectory() async throws {
        let parent = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let actual = parent.appending(path: "actual", directoryHint: .isDirectory)
        let alias = parent.appending(path: "alias", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: actual, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: actual)
        defer { try? FileManager.default.removeItem(at: parent) }

        let canonical = actual.resolvingSymlinksInPath().standardizedFileURL
        #expect(try RawVirtualizationBackend.canonicalDataRoot(alias) == canonical)
        let runtime = try await EngineRuntime(root: alias, backend: MetadataOnlyBackend())
        let container = try await runtime.createContainer(
            ContainerRecord(name: "symlink-root", image: "example")
        )

        let storedContainer = try await runtime.container(container.id)
        #expect(storedContainer.id == container.id)
        #expect(FileManager.default.fileExists(
            atPath: canonical.appending(path: "engine.json").path
        ))
        await runtime.shutdown()
    }

    @Test func unixSocketsSuppressSIGPIPEForListenersClientsAndAcceptedPeers() throws {
        let temporary = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let socket = temporary.appending(path: "transport.sock")
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temporary) }

        let listener = try UnixSocket.listen(path: socket.path)
        defer { close(listener) }
        let client = try UnixSocket.connect(path: socket.path)
        defer { close(client) }
        let peer = try UnixSocket.accept(listener)
        defer { close(peer) }

        for descriptor in [listener, client, peer] {
            var enabled: CInt = 0
            var length = socklen_t(MemoryLayout<CInt>.size)
            #expect(getsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, &length) == 0)
            #expect(enabled == 1)
        }
    }

    @Test func portForwarderResolvesEphemeralHostPort() async throws {
        let forwarder = PortForwarder()
        defer { forwarder.stopAll() }
        let ports = try await forwarder.start(
            containerID: UUID().uuidString,
            bindings: [.init(hostIP: "127.0.0.1", hostPort: 0, containerPort: 9)],
            connect: { _ in throw EngineError(.internalError, "unexpected connection") }
        )
        #expect(ports.count == 1)
        #expect(ports.first?.hostPort != 0)
    }

    @Test func containerIOFramesNonTTYOutput() throws {
        let bridge = ContainerIOBridge(tty: false)
        let received = DataBox()
        bridge.attach(output: { data in received.append(data) }, closed: {})
        try bridge.writer(.stdout).write(Data("ok".utf8))
        #expect(Array(received.value) == [1, 0, 0, 0, 0, 0, 0, 2, 111, 107])
    }

    @Test func containerIOBroadcastsToIndependentAttachments() throws {
        let bridge = ContainerIOBridge(tty: true)
        let first = DataBox()
        let second = DataBox()
        let firstID = bridge.attach(output: { first.append($0) }, closed: {})
        _ = bridge.attach(output: { second.append($0) }, closed: {})
        try bridge.writer(.stdout).write(Data("both".utf8))
        #expect(first.value == Data("both".utf8))
        #expect(second.value == Data("both".utf8))
        bridge.detach(firstID)
        try bridge.writer(.stdout).write(Data("-second".utf8))
        #expect(first.value == Data("both".utf8))
        #expect(second.value == Data("both-second".utf8))
    }

    @Test func containerIOFinishesInputAfterBufferedData() async throws {
        let bridge = ContainerIOBridge(tty: true)
        bridge.sendInput(Data("stdin".utf8))
        try bridge.finishInput()

        var received: [Data] = []
        for await data in bridge.stream() { received.append(data) }
        #expect(received == [Data("stdin".utf8)])
    }

    @Test func containerLogMonitorSynchronizesInputBeforePublishingEOF() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let stdoutURL = root.appending(path: "stdout")
        let stderrURL = root.appending(path: "stderr")
        let inputURL = root.appending(path: "stdin")
        for path in [stdoutURL, stderrURL, inputURL] { try Data().write(to: path) }
        let input = try FileHandle(forUpdating: inputURL)
        let bridge = ContainerIOBridge(tty: true)
        let probe = InputPublicationProbe()
        let monitor = ContainerLogMonitor(
            stdout: try FileHandle(forUpdating: stdoutURL),
            stderr: try FileHandle(forUpdating: stderrURL),
            input: input,
            bridge: bridge,
            markInputClosed: { probe.recordMarkerAttempt() },
            synchronizeInput: {
                try input.synchronize()
                probe.recordSynchronization(try Data(contentsOf: inputURL))
            }
        )
        monitor.start()
        let payload = Data("durable-before-eof".utf8)
        bridge.sendInput(payload)

        try bridge.finishInput()
        try monitor.stop(finishOutput: false)

        #expect(probe.observedEvents == ["synchronize", "marker"])
        #expect(probe.dataAtSynchronization == payload)
        #expect(try Data(contentsOf: inputURL) == payload)
    }

    @Test func containerLogMonitorPropagatesMarkerCreationFailure() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let stdoutURL = root.appending(path: "stdout")
        let stderrURL = root.appending(path: "stderr")
        let inputURL = root.appending(path: "stdin")
        let markerURL = root.appending(path: "missing/stdin.closed")
        for path in [stdoutURL, stderrURL, inputURL] { try Data().write(to: path) }
        let bridge = ContainerIOBridge(tty: true)
        let probe = InputPublicationProbe()
        let monitor = ContainerLogMonitor(
            stdout: try FileHandle(forUpdating: stdoutURL),
            stderr: try FileHandle(forUpdating: stderrURL),
            input: try FileHandle(forUpdating: inputURL),
            bridge: bridge,
            markInputClosed: {
                probe.recordMarkerAttempt()
                let descriptor = Darwin.open(
                    markerURL.path,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                    mode_t(0o600)
                )
                guard descriptor >= 0 else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
                Darwin.close(descriptor)
            }
        )
        monitor.start()
        let payload = Data("input-before-marker-failure".utf8)
        bridge.sendInput(payload)

        #expect(throws: POSIXError.self) { try bridge.finishInput() }
        // The terminal failure is retained: callers cannot observe a later
        // false success, and the failed marker is not retried out of order.
        #expect(throws: POSIXError.self) { try bridge.finishInput() }
        try monitor.stop(finishOutput: false)

        #expect(probe.observedEvents == ["marker"])
        #expect(try Data(contentsOf: inputURL) == payload)
        #expect(!FileManager.default.fileExists(atPath: markerURL.path))
    }

    @Test func containerIOPersistsFramedLogs() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let log = root.appending(path: "container.log")
        let bridge = ContainerIOBridge(tty: false, logURL: log)
        try bridge.writer(.stderr).write(Data("failure\n".utf8))
        #expect(Array(try bridge.logData().prefix(8)) == [2, 0, 0, 0, 0, 0, 0, 8])
        #expect(String(decoding: try bridge.logData().dropFirst(8), as: UTF8.self) == "failure\n")
    }

    @Test func containerIOBridgeKeepsVerifiedLogHandleAfterPathSwap() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let log = root.appending(path: "docker.log")
        let index = log.appendingPathExtension("entries")
        let heldLog = root.appending(path: "held-docker.log")
        let heldIndex = root.appending(path: "held-docker.log.entries")
        let sentinel = root.appending(path: "sentinel")
        let sentinelData = Data("do-not-write".utf8)
        try sentinelData.write(to: sentinel)
        let bridge = ContainerIOBridge(tty: true, logURL: log)
        try bridge.writer(.stdout).write(Data("before-".utf8))
        let firstIndexSize = try #require(
            FileManager.default.attributesOfItem(atPath: index.path)[.size] as? NSNumber
        ).uint64Value

        try FileManager.default.moveItem(at: log, to: heldLog)
        try FileManager.default.moveItem(at: index, to: heldIndex)
        try FileManager.default.createSymbolicLink(
            at: log, withDestinationURL: sentinel
        )
        try FileManager.default.createSymbolicLink(
            at: index, withDestinationURL: sentinel
        )
        try bridge.writer(.stdout).write(Data("after".utf8))

        #expect(try bridge.logData() == Data("before-after".utf8))
        #expect(try Data(contentsOf: heldLog) == Data("before-after".utf8))
        #expect(try #require(
            FileManager.default.attributesOfItem(atPath: heldIndex.path)[.size] as? NSNumber
        ).uint64Value > firstIndexSize)
        #expect(try Data(contentsOf: sentinel) == sentinelData)
        var indexInformation = stat()
        #expect(Darwin.lstat(index.path, &indexInformation) == 0)
        #expect(indexInformation.st_mode & S_IFMT == S_IFLNK)
    }

    @Test func containerIOBridgeReportsAnUnsafeInitialLogPath() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let log = root.appending(path: "docker.log")
        let sentinel = root.appending(path: "sentinel")
        let sentinelData = Data("do-not-write".utf8)
        try sentinelData.write(to: sentinel)
        try FileManager.default.createSymbolicLink(
            at: log, withDestinationURL: sentinel
        )
        let bridge = ContainerIOBridge(tty: true, logURL: log)

        #expect(throws: POSIXError.self) {
            try bridge.writer(.stdout).write(Data("unsafe".utf8))
        }
        #expect(try Data(contentsOf: sentinel) == sentinelData)
    }

    @Test func completedExecBridgesReleaseDescriptorsAndBoundRetainedOutput() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        var completed: [ContainerIOBridge] = []

        for index in 0..<70 {
            let bridge = ContainerIOBridge(
                tty: true, logURL: root.appending(path: "exec-\(index).log")
            )
            let payload = Data("prefix-output-\(index)".utf8)
            try bridge.writer(.stdout).write(payload)
            #expect(bridge.retainedPersistentDescriptorCount == 2)

            bridge.freezeCompleted(maximumBytes: 8)
            completed.append(bridge)

            #expect(bridge.retainedPersistentDescriptorCount == 0)
            #expect(bridge.retainedLogPayloadByteCount <= 8)
            #expect(bridge.retainedBufferedByteCount == 0)
            #expect(try bridge.logData() == Data(payload.suffix(8)))
            #expect(throws: EngineError.self) {
                try bridge.writer(.stdout).write(Data("late".utf8))
            }
        }

        #expect(completed.count == 70)
        #expect(completed.allSatisfy { $0.retainedPersistentDescriptorCount == 0 })
    }

    @Test func completedExecSnapshotBudgetBoundsAggregateAndPurgesExactInstance() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let oldInstance = UUID()
        let replacementInstance = UUID()
        var budget = RawCompletedExecSnapshotBudget(
            perExecBytes: 16, perContainerBytes: 128, globalBytes: 192
        )
        var bridges: [String: ContainerIOBridge] = [:]

        for index in 0..<80 {
            let identifier = "snapshot-(index)"
            let instance = index < 60 ? oldInstance : replacementInstance
            let bridge = ContainerIOBridge(
                tty: true, logURL: root.appending(path: "\(identifier).log")
            )
            try bridge.writer(.stdout).write(Data(repeating: UInt8(index), count: 16))
            bridge.freezeCompleted(maximumBytes: 16)
            bridges[identifier] = bridge
            let evicted = budget.register(
                execID: identifier,
                containerID: "reused-container",
                containerInstanceID: instance,
                bytes: bridge.retainedLogPayloadByteCount
            )
            for evictedID in evicted { bridges[evictedID]?.discardCompletedOutput() }

            #expect(budget.retainedBytes <= 192)
            #expect(budget.retainedBytes(
                containerID: "reused-container", instanceID: instance
            ) <= 128)
            #expect(bridges.values.reduce(0) {
                $0 + $1.retainedLogPayloadByteCount
            } == budget.retainedBytes)
        }

        #expect(bridges.values.allSatisfy { $0.retainedPersistentDescriptorCount == 0 })
        let replacementBytes = budget.retainedBytes(
            containerID: "reused-container", instanceID: replacementInstance
        )
        #expect(replacementBytes > 0)
        let purged = budget.remove(
            containerID: "reused-container", instanceID: oldInstance
        )
        for identifier in purged { bridges[identifier]?.discardCompletedOutput() }
        #expect(budget.retainedBytes(
            containerID: "reused-container", instanceID: oldInstance
        ) == 0)
        #expect(budget.retainedBytes(
            containerID: "reused-container", instanceID: replacementInstance
        ) == replacementBytes)
        #expect(budget.entries.values.allSatisfy {
            $0.containerInstanceID == replacementInstance
        })

        var emptyBudget = RawCompletedExecSnapshotBudget(
            perExecBytes: 16, perContainerBytes: 32, globalBytes: 64,
            minimumSnapshotBytes: 4
        )
        for index in 0..<100 {
            _ = emptyBudget.register(
                execID: "empty-\(index)", containerID: "empty-owner",
                containerInstanceID: oldInstance, bytes: 0
            )
        }
        #expect(emptyBudget.entries.count == 8)
        #expect(emptyBudget.retainedBytes == 32)
    }

    @Test func containerLogMonitorDoesNotDuplicateConcurrentDrains() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let stdout = root.appending(path: "stdout")
        let stderr = root.appending(path: "stderr")
        let stdin = root.appending(path: "stdin")
        let payload = Data("once".utf8)
        try payload.write(to: stdout)
        try Data().write(to: stderr)
        try Data().write(to: stdin)
        let bridge = ContainerIOBridge(tty: true, logURL: root.appending(path: "docker.log"))
        let rendezvous = DrainRendezvous()
        let monitor = try ContainerLogMonitor(
            stdoutURL: stdout,
            stderrURL: stderr,
            inputURL: stdin,
            bridge: bridge
        )
        let queue = DispatchQueue(label: "dev.cengine.tests.log-drain", attributes: .concurrent)
        let start = DispatchSemaphore(value: 0)
        let ready = DispatchGroup()
        let completed = DispatchGroup()
        let workers = 2

        for _ in 0..<workers {
            ready.enter()
            completed.enter()
            queue.async {
                ready.leave()
                start.wait()
                try? monitor.drain(stdout, stream: .stdout, didReadOffset: rendezvous.wait)
                completed.leave()
            }
        }
        ready.wait()
        for _ in 0..<workers { start.signal() }
        completed.wait()

        #expect(try bridge.logData() == payload)
    }

    @Test func containerLogMonitorRetriesFailedPersistenceWithoutSkippingOutput() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let stdoutURL = root.appending(path: "stdout")
        let stderrURL = root.appending(path: "stderr")
        let inputURL = root.appending(path: "stdin")
        let stdoutPayload = Data("stdout-once".utf8)
        let stderrPayload = Data("stderr-once".utf8)
        try stdoutPayload.write(to: stdoutURL)
        try stderrPayload.write(to: stderrURL)
        try Data().write(to: inputURL)
        let bridge = ContainerIOBridge(tty: true)
        let persistence = FailingOutputPersistence()
        func monitor() throws -> ContainerLogMonitor {
            ContainerLogMonitor(
                stdout: try FileHandle(forUpdating: stdoutURL),
                stderr: try FileHandle(forUpdating: stderrURL),
                input: try FileHandle(forUpdating: inputURL),
                bridge: bridge,
                persistOutput: persistence.write
            )
        }
        let original = try monitor()

        #expect(throws: (any Error).self) { try original.drain(stream: .stdout) }
        #expect(throws: (any Error).self) { try original.drain(stream: .stderr) }
        #expect(persistence.attempts(for: .stdout) == 1)
        #expect(persistence.attempts(for: .stderr) == 1)
        #expect(persistence.data(for: .stdout).isEmpty)
        #expect(persistence.data(for: .stderr).isEmpty)

        // Session teardown performs a final drain. Both old offsets must still
        // point at zero, so the exact source bytes are retried and committed.
        try original.stop(finishOutput: false)
        #expect(persistence.attempts(for: .stdout) == 2)
        #expect(persistence.attempts(for: .stderr) == 2)
        #expect(persistence.data(for: .stdout) == stdoutPayload)
        #expect(persistence.data(for: .stderr) == stderrPayload)

        try original.drain(stream: .stdout)
        try original.drain(stream: .stderr)
        #expect(persistence.attempts(for: .stdout) == 2)
        #expect(persistence.attempts(for: .stderr) == 2)

        // A stopped-session replacement starts at the committed source end and
        // must not publish either recovered chunk a second time.
        let replacement = try monitor()
        replacement.start(atEnd: true)
        try replacement.stop(finishOutput: false)
        #expect(persistence.attempts(for: .stdout) == 2)
        #expect(persistence.attempts(for: .stderr) == 2)
        #expect(persistence.data(for: .stdout) == stdoutPayload)
        #expect(persistence.data(for: .stderr) == stderrPayload)
    }

    @Test func containerCompletionWaitsForContainerAndExecFinalDrainRetries() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        func makeMonitor(
            name: String,
            stdoutPayload: Data,
            stderrPayload: Data,
            persistence: FailingOutputPersistence
        ) throws -> ContainerLogMonitor {
            let directory = root.appending(path: name)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let stdout = directory.appending(path: "stdout")
            let stderr = directory.appending(path: "stderr")
            let input = directory.appending(path: "stdin")
            try stdoutPayload.write(to: stdout)
            try stderrPayload.write(to: stderr)
            try Data().write(to: input)
            return ContainerLogMonitor(
                stdout: try FileHandle(forUpdating: stdout),
                stderr: try FileHandle(forUpdating: stderr),
                input: try FileHandle(forUpdating: input),
                bridge: ContainerIOBridge(tty: true),
                persistOutput: persistence.write
            )
        }

        let containerPersistence = FailingOutputPersistence()
        let execPersistence = FailingOutputPersistence()
        let containerStdout = Data("container-stdout".utf8)
        let containerStderr = Data("container-stderr".utf8)
        let execStdout = Data("exec-stdout".utf8)
        let execStderr = Data("exec-stderr".utf8)
        let containerMonitor = try makeMonitor(
            name: "container", stdoutPayload: containerStdout,
            stderrPayload: containerStderr, persistence: containerPersistence
        )
        let execMonitor = try makeMonitor(
            name: "exec", stdoutPayload: execStdout,
            stderrPayload: execStderr, persistence: execPersistence
        )

        var terminalPublished = false
        for attempt in 0..<5 {
            do {
                try RawCompletionDrainCoordinator.drain(
                    container: { try containerMonitor.stop(finishOutput: false) },
                    execSessions: { try execMonitor.stop(finishOutput: false) }
                )
                terminalPublished = true
            } catch {
                #expect(attempt < 4)
            }
            if attempt < 4 { #expect(!terminalPublished) }
        }

        #expect(terminalPublished)
        for stream in [ContainerIOBridge.OutputStream.stdout, .stderr] {
            #expect(containerPersistence.attempts(for: stream) == 2)
            #expect(execPersistence.attempts(for: stream) == 2)
        }
        #expect(containerPersistence.data(for: .stdout) == containerStdout)
        #expect(containerPersistence.data(for: .stderr) == containerStderr)
        #expect(execPersistence.data(for: .stdout) == execStdout)
        #expect(execPersistence.data(for: .stderr) == execStderr)
    }

    @Test func recoveredMonitorChunksBacklogAndRetriesOnlyFailedChunk() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let stdoutURL = root.appending(path: "stdout")
        let stderrURL = root.appending(path: "stderr")
        let inputURL = root.appending(path: "stdin")
        let logURL = root.appending(path: "docker.log")
        for path in [stdoutURL, stderrURL, inputURL] { try Data().write(to: path) }
        let prefix = Data("HEAD".utf8)
        let backlog = Data("ABCDEFGHIJ".utf8)
        let sourceWriter = try FileHandle(forUpdating: stdoutURL)

        let firstBridge = ContainerIOBridge(tty: true, logURL: logURL)
        let firstMonitor = ContainerLogMonitor(
            stdout: try FileHandle(forUpdating: stdoutURL),
            stderr: try FileHandle(forUpdating: stderrURL),
            input: try FileHandle(forUpdating: inputURL),
            bridge: firstBridge,
            maximumOutputChunkSize: 4
        )
        try sourceWriter.write(contentsOf: prefix)
        try sourceWriter.synchronize()
        try firstMonitor.drain(stream: .stdout)
        try firstMonitor.stop(finishOutput: false)

        // Model output accumulated while the daemon monitor was absent. The
        // recovered journal offset skips HEAD and begins at the backlog.
        try sourceWriter.seekToEnd()
        try sourceWriter.write(contentsOf: backlog)
        try sourceWriter.synchronize()
        let recoveredBridge = ContainerIOBridge(tty: true, logURL: logURL)
        let persistence = ChunkFailurePersistence(bridge: recoveredBridge)
        let recoveredMonitor = ContainerLogMonitor(
            stdout: try FileHandle(forUpdating: stdoutURL),
            stderr: try FileHandle(forUpdating: stderrURL),
            input: try FileHandle(forUpdating: inputURL),
            bridge: recoveredBridge,
            persistOutput: persistence.write,
            maximumOutputChunkSize: 4
        )
        recoveredMonitor.start(atEnd: true)
        #expect(persistence.waitForFailure())
        // The poll that observed the injected failure retained the second
        // chunk's offset. The final drain retries it, then commits the tail.
        try recoveredMonitor.stop(finishOutput: false)

        #expect(persistence.attempts == [
            Data("ABCD".utf8),
            Data("EFGH".utf8),
            Data("EFGH".utf8),
            Data("IJ".utf8),
        ])
        #expect(try recoveredBridge.logData() == prefix + backlog)
        let offsets = try #require(recoveredBridge.durableSourceByteOffsets())
        #expect(offsets[.stdout] == UInt64((prefix + backlog).count))

        // A fresh journal reader reconstructs every bounded entry exactly once.
        let restartedBridge = ContainerIOBridge(tty: true, logURL: logURL)
        #expect(try restartedBridge.logData() == prefix + backlog)
    }

    @Test func containerLogMonitorDrainsGrowthAtChunkBoundaryExactlyOnce() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let stdoutURL = root.appending(path: "stdout")
        let stderrURL = root.appending(path: "stderr")
        let inputURL = root.appending(path: "stdin")
        let initial = Data("first".utf8)
        let growth = Data("later".utf8)
        try initial.write(to: stdoutURL)
        try Data().write(to: stderrURL)
        try Data().write(to: inputURL)
        let bridge = ContainerIOBridge(
            tty: true, logURL: root.appending(path: "docker.log")
        )
        let persistence = GrowingOutputPersistence(
            bridge: bridge,
            source: try FileHandle(forUpdating: stdoutURL),
            growth: growth
        )
        let monitor = ContainerLogMonitor(
            stdout: try FileHandle(forUpdating: stdoutURL),
            stderr: try FileHandle(forUpdating: stderrURL),
            input: try FileHandle(forUpdating: inputURL),
            bridge: bridge,
            persistOutput: persistence.write,
            maximumOutputChunkSize: initial.count
        )

        try monitor.drain(stream: .stdout)
        try monitor.drain(stream: .stdout)

        #expect(persistence.chunks == [initial, growth])
        #expect(try bridge.logData() == initial + growth)
    }

    @Test func containerLogMonitorKeepsOriginalFilesAfterPathSwap() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        for name in ["stdout", "stderr", "stdin"] {
            try Data().write(to: root.appending(path: name))
        }
        let directory = try PersistentStateDirectory.open(root)
        let stdoutIdentity = try directory.regularFileIdentity(named: "stdout")
        let stderrIdentity = try directory.regularFileIdentity(named: "stderr")
        let stdinIdentity = try directory.regularFileIdentity(named: "stdin")
        let stdout = try directory.openRegularFile(
            named: "stdout", expectedIdentity: stdoutIdentity, access: .readWrite
        ).handle
        let stdoutWriter = try directory.openRegularFile(
            named: "stdout", expectedIdentity: stdoutIdentity, access: .writeOnly
        ).handle
        let stderr = try directory.openRegularFile(
            named: "stderr", expectedIdentity: stderrIdentity, access: .readWrite
        ).handle
        let stdin = try directory.openRegularFile(
            named: "stdin", expectedIdentity: stdinIdentity, access: .readWrite
        ).handle
        let stdinReader = try directory.openRegularFile(
            named: "stdin", expectedIdentity: stdinIdentity, access: .readOnly
        ).handle
        let bridge = ContainerIOBridge(tty: true)
        let received = DataBox()
        _ = bridge.attach(output: { received.append($0) }, closed: {})
        let monitor = ContainerLogMonitor(
            stdout: stdout, stderr: stderr, input: stdin, bridge: bridge
        )
        monitor.start()

        let outputSentinel = root.appending(path: "output-sentinel")
        let inputSentinel = root.appending(path: "input-sentinel")
        let outputSentinelData = Data("output-untouched".utf8)
        let inputSentinelData = Data("input-untouched".utf8)
        try outputSentinelData.write(to: outputSentinel)
        try inputSentinelData.write(to: inputSentinel)
        try FileManager.default.moveItem(
            at: root.appending(path: "stdout"),
            to: root.appending(path: "held-stdout")
        )
        try FileManager.default.moveItem(
            at: root.appending(path: "stdin"),
            to: root.appending(path: "held-stdin")
        )
        try FileManager.default.createSymbolicLink(
            at: root.appending(path: "stdout"), withDestinationURL: outputSentinel
        )
        try FileManager.default.createSymbolicLink(
            at: root.appending(path: "stdin"), withDestinationURL: inputSentinel
        )

        let output = Data("held-output".utf8)
        try stdoutWriter.seekToEnd()
        try stdoutWriter.write(contentsOf: output)
        try monitor.drain(stream: .stdout)
        let input = Data("held-input".utf8)
        bridge.sendInput(input)
        try bridge.finishInput()
        for _ in 0..<100 {
            try stdinReader.seek(toOffset: 0)
            if try stdinReader.readToEnd() == input { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        try stdinReader.seek(toOffset: 0)
        let writtenInput = try stdinReader.readToEnd() ?? Data()
        try monitor.stop()

        #expect(received.value == output)
        #expect(writtenInput == input)
        #expect(try Data(contentsOf: outputSentinel) == outputSentinelData)
        #expect(try Data(contentsOf: inputSentinel) == inputSentinelData)
    }

    @Test func containerAndExecMonitorCancellationDoesNotCloseRecoveredInput() async throws {
        for prefix in ["", "exec-123-"] {
            let root = FileManager.default.temporaryDirectory.appending(
                path: UUID().uuidString
            )
            defer { try? FileManager.default.removeItem(at: root) }
            try FileManager.default.createDirectory(
                at: root, withIntermediateDirectories: true
            )
            let stdout = root.appending(path: "\(prefix)stdout")
            let stderr = root.appending(path: "\(prefix)stderr")
            let input = root.appending(path: "\(prefix)stdin")
            let closed = root.appending(path: "\(prefix)stdin.closed")
            for path in [stdout, stderr, input] { try Data().write(to: path) }

            func monitor(for bridge: ContainerIOBridge) throws -> ContainerLogMonitor {
                ContainerLogMonitor(
                    stdout: try FileHandle(forUpdating: stdout),
                    stderr: try FileHandle(forUpdating: stderr),
                    input: try FileHandle(forUpdating: input),
                    bridge: bridge,
                    markInputClosed: {
                        let descriptor = Darwin.open(
                            closed.path,
                            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                            mode_t(0o600)
                        )
                        if descriptor >= 0 { Darwin.close(descriptor) }
                    }
                )
            }

            let originalBridge = ContainerIOBridge(tty: true)
            let originalMonitor = try monitor(for: originalBridge)
            originalMonitor.start()
            originalBridge.sendInput(Data("before-".utf8))
            for _ in 0..<100 {
                if try Data(contentsOf: input) == Data("before-".utf8) { break }
                try await Task.sleep(for: .milliseconds(5))
            }
            try originalMonitor.stop(finishOutput: false)
            try await Task.sleep(for: .milliseconds(50))
            #expect(!FileManager.default.fileExists(atPath: closed.path))

            let recoveredBridge = ContainerIOBridge(tty: true)
            let recoveredMonitor = try monitor(for: recoveredBridge)
            recoveredMonitor.start(atEnd: true)
            recoveredBridge.sendInput(Data("after".utf8))
            try recoveredBridge.finishInput()
            // Explicit EOF must synchronously drain prior input and publish the
            // marker before an immediately following backend shutdown cancels
            // the monitor task.
            #expect(try Data(contentsOf: input) == Data("before-after".utf8))
            #expect(FileManager.default.fileExists(atPath: closed.path))
            try recoveredMonitor.stop(finishOutput: false)

            #expect(try Data(contentsOf: input) == Data("before-after".utf8))
            #expect(FileManager.default.fileExists(atPath: closed.path))
        }
    }

    @Test func recoveredMonitorJournalsDaemonDowntimeOutputExactlyOnce() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let stdoutURL = root.appending(path: "stdout")
        let stderrURL = root.appending(path: "stderr")
        let inputURL = root.appending(path: "stdin")
        for path in [stdoutURL, stderrURL, inputURL] { try Data().write(to: path) }
        let logURL = root.appending(path: "docker.log")
        let stdoutWriter = try FileHandle(forUpdating: stdoutURL)

        let firstBridge = ContainerIOBridge(tty: true, logURL: logURL)
        let firstMonitor = ContainerLogMonitor(
            stdout: try FileHandle(forUpdating: stdoutURL),
            stderr: try FileHandle(forUpdating: stderrURL),
            input: try FileHandle(forUpdating: inputURL),
            bridge: firstBridge
        )
        try stdoutWriter.write(contentsOf: Data("before-".utf8))
        try firstMonitor.drain(stream: .stdout)
        try firstMonitor.stop(finishOutput: false)

        // The VM shim keeps its canonical stdout handle while the daemon and
        // its monitor are absent.
        try stdoutWriter.seekToEnd()
        try stdoutWriter.write(contentsOf: Data("downtime".utf8))
        try stdoutWriter.synchronize()

        let recoveredBridge = ContainerIOBridge(tty: true, logURL: logURL)
        let recoveredMonitor = ContainerLogMonitor(
            stdout: try FileHandle(forUpdating: stdoutURL),
            stderr: try FileHandle(forUpdating: stderrURL),
            input: try FileHandle(forUpdating: inputURL),
            bridge: recoveredBridge
        )
        recoveredMonitor.start(atEnd: true)
        try recoveredMonitor.drain(stream: .stdout)
        try recoveredMonitor.stop(finishOutput: false)

        #expect(try recoveredBridge.logData() == Data("before-downtime".utf8))
        let offsets = try #require(recoveredBridge.durableSourceByteOffsets())
        #expect(offsets[.stdout] == UInt64(Data("before-downtime".utf8).count))
    }

    @Test func recoveredMonitorUsesOnlyCurrentSourceSessionOffset() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let stdoutURL = root.appending(path: "stdout")
        let stderrURL = root.appending(path: "stderr")
        let inputURL = root.appending(path: "stdin")
        for path in [stdoutURL, stderrURL, inputURL] { try Data().write(to: path) }
        let logURL = root.appending(path: "docker.log")
        let historical = Data(repeating: 0x48, count: 100)
        let current = Data("session-two".utf8)
        let downtime = Data("-downtime".utf8)

        do {
            let bridge = ContainerIOBridge(tty: true, logURL: logURL)
            try bridge.beginSourceSession()
            try historical.write(to: stdoutURL)
            let monitor = try ContainerLogMonitor(
                stdoutURL: stdoutURL,
                stderrURL: stderrURL,
                inputURL: inputURL,
                bridge: bridge
            )
            try monitor.drain(stream: .stdout)
            try monitor.stop(finishOutput: false)
        }

        let sourceWriter = try FileHandle(forUpdating: stdoutURL)
        try sourceWriter.truncate(atOffset: 0)
        do {
            let bridge = ContainerIOBridge(tty: true, logURL: logURL)
            try bridge.beginSourceSession()
            try sourceWriter.write(contentsOf: current)
            try sourceWriter.synchronize()
            let monitor = try ContainerLogMonitor(
                stdoutURL: stdoutURL,
                stderrURL: stderrURL,
                inputURL: inputURL,
                bridge: bridge
            )
            try monitor.drain(stream: .stdout)
            try monitor.stop(finishOutput: false)
        }

        try sourceWriter.seekToEnd()
        try sourceWriter.write(contentsOf: downtime)
        try sourceWriter.synchronize()
        let recovered = ContainerIOBridge(tty: true, logURL: logURL)
        let recoveredMonitor = try ContainerLogMonitor(
            stdoutURL: stdoutURL,
            stderrURL: stderrURL,
            inputURL: inputURL,
            bridge: recovered
        )
        recoveredMonitor.start(atEnd: true)
        try recoveredMonitor.drain(stream: .stdout)
        try recoveredMonitor.stop(finishOutput: false)

        #expect(try recovered.logData() == historical + current + downtime)
        let offsets = try #require(recovered.durableSourceByteOffsets())
        #expect(offsets[.stdout] == UInt64((current + downtime).count))
    }

    @Test func containerIOFiltersLogStreamsTailAndTimestamps() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let bridge = ContainerIOBridge(tty: false, logURL: root.appending(path: "container.log"))
        try bridge.writer(.stdout).write(Data("first\nsecond\n".utf8))
        try bridge.writer(.stderr).write(Data("failure\n".utf8))

        let stdout = try bridge.logData(options: .init(stdout: true, stderr: false, tail: 1))
        #expect(String(decoding: stdout.dropFirst(8), as: UTF8.self) == "second\n")
        let stderr = try bridge.logData(options: .init(stdout: false, stderr: true, timestamps: true))
        let rendered = String(decoding: stderr.dropFirst(8), as: UTF8.self)
        #expect(rendered.contains("T")); #expect(rendered.hasSuffix(" failure\n"))
        #expect(try bridge.logData(options: .init(since: Date().addingTimeInterval(60))).isEmpty)
    }

    @Test func containerIOJournalRecoversValidPrefixBeforeFutureWrites() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let log = root.appending(path: "docker.log")
        let index = log.appendingPathExtension("entries")
        var firstLogSize: UInt64 = 0
        var firstIndexSize: UInt64 = 0
        do {
            let bridge = ContainerIOBridge(tty: false, logURL: log)
            try bridge.writer(.stdout).write(Data("first\n".utf8))
            firstLogSize = try #require(
                FileManager.default.attributesOfItem(atPath: log.path)[.size] as? NSNumber
            ).uint64Value
            firstIndexSize = try #require(
                FileManager.default.attributesOfItem(atPath: index.path)[.size] as? NSNumber
            ).uint64Value
            try bridge.writer(.stderr).write(Data("partial\n".utf8))
        }

        let indexHandle = try FileHandle(forUpdating: index)
        try indexHandle.truncate(atOffset: firstIndexSize + 7)
        try indexHandle.synchronize()
        try indexHandle.close()
        let logHandle = try FileHandle(forUpdating: log)
        try logHandle.truncate(atOffset: firstLogSize)
        try logHandle.synchronize()
        try logHandle.close()

        do {
            let recovered = ContainerIOBridge(tty: false, logURL: log)
            let stdout = try recovered.logData(options: .init(
                stdout: true, stderr: false
            ))
            #expect(String(decoding: stdout, as: UTF8.self).contains("first\n"))
            #expect(!String(decoding: stdout, as: UTF8.self).contains("partial\n"))
            try recovered.writer(.stderr).write(Data("future\n".utf8))
        }

        let restarted = ContainerIOBridge(tty: false, logURL: log)
        let all = try restarted.logData(options: .init())
        let rendered = String(decoding: all, as: UTF8.self)
        #expect(rendered.contains("first\n"))
        #expect(rendered.contains("future\n"))
        #expect(!rendered.contains("partial\n"))
        #expect(try #require(
            FileManager.default.attributesOfItem(atPath: index.path)[.size] as? NSNumber
        ).uint64Value > firstIndexSize)
    }

    @Test func containerIOJournalRepairsRawMirrorAfterCommittedIndexCrash() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let log = root.appending(path: "docker.log")
        var firstLogSize: UInt64 = 0
        do {
            let bridge = ContainerIOBridge(tty: false, logURL: log)
            try bridge.writer(.stdout).write(Data("committed-one\n".utf8))
            firstLogSize = try #require(
                FileManager.default.attributesOfItem(atPath: log.path)[.size] as? NSNumber
            ).uint64Value
            try bridge.writer(.stderr).write(Data("committed-two\n".utf8))
        }

        // Model a crash after the journal frame was synchronized but before
        // the corresponding raw Docker-log mirror append completed.
        let logHandle = try FileHandle(forUpdating: log)
        try logHandle.truncate(atOffset: firstLogSize)
        try logHandle.synchronize()
        try logHandle.close()

        do {
            let recovered = ContainerIOBridge(tty: false, logURL: log)
            let beforeAppend = String(
                decoding: try recovered.logData(options: .init()), as: UTF8.self
            )
            #expect(beforeAppend.contains("committed-one\n"))
            #expect(beforeAppend.contains("committed-two\n"))
            try recovered.writer(.stdout).write(Data("after-recovery\n".utf8))
        }

        let restarted = ContainerIOBridge(tty: false, logURL: log)
        let filtered = String(
            decoding: try restarted.logData(options: .init()), as: UTF8.self
        )
        let raw = String(decoding: try restarted.logData(), as: UTF8.self)
        for line in ["committed-one\n", "committed-two\n", "after-recovery\n"] {
            #expect(filtered.contains(line))
            #expect(raw.contains(line))
        }
    }

    @Test func atomicStoreRoundTrips() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = AtomicStore<[ContainerRecord]>(url: root.appending(path: "state.json"))
        let record = ContainerRecord(name: "web", image: "alpine:latest")
        try await store.save([record])
        let loaded = try await store.load(default: [])
        #expect(loaded.count == 1)
        #expect(loaded[0].id == record.id)
        #expect(loaded[0].instanceID == record.instanceID)
        #expect(loaded[0].name == "web")
    }

    @Test func atomicStoreReportsPostRenameFailuresAsAmbiguousAndKeepsValidState() async throws {
        enum Injected: Error { case boundary }
        struct State: Codable, Equatable, Sendable { let value: Int }

        for boundary in [
            AtomicStoreSaveBoundary.replacementCompleted,
            .directorySynchronized,
        ] {
            let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
            defer { try? FileManager.default.removeItem(at: root) }
            let url = root.appending(path: "state.json")
            try await AtomicStore<State>(url: url).save(.init(value: 1))
            let faulted = AtomicStore<State>(
                url: url,
                saveBoundaryHook: { observed in
                    if observed == boundary { throw Injected.boundary }
                }
            )

            do {
                try await faulted.save(.init(value: 2))
                Issue.record("expected an ambiguous post-rename persistence failure")
            } catch let error as AtomicStorePersistenceAmbiguousError {
                #expect(error.path == url.path)
            } catch {
                Issue.record("unexpected persistence error: \(error)")
            }

            let restarted = AtomicStore<State>(url: url)
            #expect(try await restarted.load(default: .init(value: 0)) == .init(value: 2))
            try await restarted.save(.init(value: 3))
            #expect(try await restarted.load(default: .init(value: 0)) == .init(value: 3))
            let names = try FileManager.default.contentsOfDirectory(atPath: root.path)
            #expect(names == ["state.json"])
        }
    }

    @Test func atomicStoreRejectsSuccessWhenItsParentIsReplacedAfterRename() async throws {
        struct State: Codable, Equatable, Sendable { let value: Int }
        let base = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let root = base.appending(path: "state")
        let detached = base.appending(path: "detached")
        defer { try? FileManager.default.removeItem(at: base) }
        let url = root.appending(path: "engine.json")
        try await AtomicStore<State>(url: url).save(.init(value: 1))
        let relocator = AtomicStoreParentRelocator(parent: root, detached: detached)
        let store = AtomicStore<State>(
            url: url, saveBoundaryHook: { try relocator.relocate(at: $0) }
        )

        await #expect(throws: AtomicStorePersistenceAmbiguousError.self) {
            try await store.save(.init(value: 2))
        }
        #expect(!FileManager.default.fileExists(atPath: url.path))
        #expect(try await AtomicStore<State>(
            url: detached.appending(path: "engine.json")
        ).load(default: .init(value: 0)) == .init(value: 2))
        #expect(try FileManager.default.contentsOfDirectory(atPath: detached.path)
            == ["engine.json"])

        try await AtomicStore<State>(url: url).save(.init(value: 3))
        #expect(try await AtomicStore<State>(url: url).load(
            default: .init(value: 0)
        ) == .init(value: 3))
    }

    @Test func atomicStoreRejectsRelocationAnywhereInItsFrozenAncestorChain() async throws {
        struct State: Codable, Equatable, Sendable { let value: Int }

        for level in 0..<3 {
            for replacement in [
                AtomicStoreParentRelocator.Replacement.directory,
                .symbolicLink,
            ] {
                let base = FileManager.default.temporaryDirectory.appending(
                    path: UUID().uuidString
                )
                defer { try? FileManager.default.removeItem(at: base) }
                let top = base.appending(path: "top")
                let middle = top.appending(path: "middle")
                let parent = middle.appending(path: "state")
                let ancestors = [parent, middle, top]
                let selected = ancestors[level]
                let detached = base.appending(path: "detached-\(level)")
                let url = parent.appending(path: "engine.json")
                try await AtomicStore<State>(url: url).save(.init(value: 1))
                let relocator = AtomicStoreParentRelocator(
                    parent: selected,
                    detached: detached,
                    replacement: replacement
                )
                let store = AtomicStore<State>(
                    url: url,
                    saveBoundaryHook: { try relocator.relocate(at: $0) }
                )

                await #expect(throws: AtomicStorePersistenceAmbiguousError.self) {
                    try await store.save(.init(value: 2))
                }
                let detachedParent: URL
                switch level {
                case 2: detachedParent = detached.appending(path: "middle/state")
                case 1: detachedParent = detached.appending(path: "state")
                default: detachedParent = detached
                }
                let detachedState = detachedParent.appending(path: "engine.json")
                #expect(try await AtomicStore<State>(url: detachedState).loadRequired()
                    == .init(value: 2))
                var information = stat()
                #expect(Darwin.lstat(selected.path, &information) == 0)
                if replacement == .symbolicLink {
                    #expect(information.st_mode & S_IFMT == S_IFLNK)
                } else {
                    #expect(information.st_mode & S_IFMT == S_IFDIR)
                }
            }
        }
    }

    @Test func atomicStoreLoadRejectsAReplacedTargetAfterReadingItsDescriptor() async throws {
        struct State: Codable, Equatable, Sendable { let value: Int }
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appending(path: "state.json")
        let replacement = root.appending(path: "replacement.json")
        let detached = root.appending(path: "detached.json")
        try await AtomicStore<State>(url: target).save(.init(value: 1))
        try await AtomicStore<State>(url: replacement).save(.init(value: 2))
        let swapper = AtomicStoreTargetSwapper(
            target: target, replacement: replacement, detached: detached
        )
        let raced = AtomicStore<State>(
            url: target,
            loadBoundaryHook: { boundary in
                guard boundary == .dataRead else { return }
                try swapper.swap()
            }
        )

        await #expect(throws: AtomicStoreCanonicalStateUnavailableError.self) {
            _ = try await raced.loadRequired()
        }
        #expect(try await AtomicStore<State>(url: target).loadRequired()
            == State(value: 2))
        #expect(try await AtomicStore<State>(url: detached).loadRequired()
            == State(value: 1))
    }

    @Test func atomicStoreSaveRejectsSuccessWhenPublishedTargetIsSwapped() async throws {
        struct State: Codable, Equatable, Sendable { let value: Int }
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appending(path: "state.json")
        let replacement = root.appending(path: "replacement.json")
        let detached = root.appending(path: "detached.json")
        try await AtomicStore<State>(url: target).save(.init(value: 1))
        try await AtomicStore<State>(url: replacement).save(.init(value: 99))
        let swapper = AtomicStoreTargetSwapper(
            target: target, replacement: replacement, detached: detached
        )
        let raced = AtomicStore<State>(
            url: target,
            saveBoundaryHook: { boundary in
                guard boundary == .replacementCompleted else { return }
                try swapper.swap()
            }
        )

        await #expect(throws: AtomicStorePersistenceAmbiguousError.self) {
            try await raced.save(.init(value: 2))
        }
        #expect(try await AtomicStore<State>(url: target).loadRequired()
            == State(value: 99))
        #expect(try await AtomicStore<State>(url: detached).loadRequired()
            == State(value: 2))
    }

    @Test func atomicStoreReportsMissingRequiredFieldsWithTheirPath() async throws {
        struct RequiredState: Codable, Sendable { let name: String }

        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let url = root.appending(path: "state.json")
        try Data(#"{"schemaVersion":1,"value":{}}"#.utf8).write(to: url)
        let store = AtomicStore<RequiredState>(url: url)

        do {
            _ = try await store.load(default: RequiredState(name: "fallback"))
            Issue.record("expected incompatible state to fail")
        } catch let error as EngineError {
            #expect(error.message.contains(url.path))
            #expect(error.message.contains("missing required field 'name' at value"))
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }

    @Test func defaultPathsAreUserScoped() {
        let home = URL(filePath: "/tmp/example-home", directoryHint: .isDirectory)
        let paths = EnginePaths(home: home)
        #expect(paths.socket.path == "/tmp/example-home/.cengine/run/docker.sock")
        #expect(paths.lock.path == "/tmp/example-home/.cengine/run/docker.sock.lock")
        #expect(paths.serviceState.path == "/tmp/example-home/.cengine/run/service-state.json")
        #expect(paths.data.path.contains("Application Support/cengine"))
        #expect(paths.activeContextMarker.path == "/tmp/example-home/Library/Application Support/cengine/active-docker-context")
    }
}

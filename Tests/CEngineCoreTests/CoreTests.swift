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

    @Test func containerIOFinishesInputAfterBufferedData() async {
        let bridge = ContainerIOBridge(tty: true)
        bridge.sendInput(Data("stdin".utf8))
        bridge.finishInput()

        var received: [Data] = []
        for await data in bridge.stream() { received.append(data) }
        #expect(received == [Data("stdin".utf8)])
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
        let monitor = ContainerLogMonitor(stdoutURL: stdout, stderrURL: stderr, inputURL: stdin, bridge: bridge)
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
                monitor.drain(stdout, stream: .stdout, didReadOffset: rendezvous.wait)
                completed.leave()
            }
        }
        ready.wait()
        for _ in 0..<workers { start.signal() }
        completed.wait()

        #expect(try bridge.logData() == payload)
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

    @Test func atomicStoreRoundTrips() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = AtomicStore<[ContainerRecord]>(url: root.appending(path: "state.json"))
        let record = ContainerRecord(name: "web", image: "alpine:latest")
        try await store.save([record])
        let loaded = try await store.load(default: [])
        #expect(loaded.count == 1)
        #expect(loaded[0].id == record.id)
        #expect(loaded[0].name == "web")
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
    }
}

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
        #expect(source.shareRoot.path.hasPrefix(managed.path + "/"))
        #expect(source.subpath == nil)
        #expect(FileManager.default.fileExists(atPath: source.shareRoot.path))
    }

    @Test func portForwarderResolvesEphemeralHostPort() async throws {
        let forwarder = PortForwarder()
        defer { forwarder.stopAll() }
        let ports = try await forwarder.start(
            containerID: UUID().uuidString,
            guestIPv4Address: "127.0.0.1",
            guestIPv6Address: nil,
            bindings: [.init(hostIP: "127.0.0.1", hostPort: 0, containerPort: 9)]
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

    @Test func defaultPathsAreUserScoped() {
        let home = URL(filePath: "/tmp/example-home", directoryHint: .isDirectory)
        let paths = EnginePaths(home: home)
        #expect(paths.socket.path == "/tmp/example-home/.cengine/run/docker.sock")
        #expect(paths.lock.path == "/tmp/example-home/.cengine/run/docker.sock.lock")
        #expect(paths.serviceState.path == "/tmp/example-home/.cengine/run/service-state.json")
        #expect(paths.data.path.contains("Application Support/cengine"))
    }
}

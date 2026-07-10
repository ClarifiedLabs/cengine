import Foundation
import Testing
@testable import CEngineCore
import CEngineRuntime

private final class DataBox: @unchecked Sendable {
    private let lock = NSLock()
    private var storage = Data()
    func append(_ data: Data) { lock.withLock { storage.append(data) } }
    var value: Data { lock.withLock { storage } }
}

@Suite struct CoreTests {
    @Test func kataKernelUsesPublishedZstdAsset() {
        #expect(KernelInstaller.archiveURL.lastPathComponent == "kata-static-3.28.0-arm64.tar.zst")
        #expect(KernelInstaller.archiveSHA256.count == 64)
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

    @Test func containerIOFramesNonTTYOutput() throws {
        let bridge = ContainerIOBridge(tty: false)
        let received = DataBox()
        bridge.attach(output: { data in received.append(data) }, closed: {})
        try bridge.writer(.stdout).write(Data("ok".utf8))
        #expect(Array(received.value) == [1, 0, 0, 0, 0, 0, 0, 2, 111, 107])
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
        #expect(paths.data.path.contains("Application Support/cengine"))
    }
}

import CEngineAPI
import CEngineCore
import CEngineRuntime
import Foundation
import NIOHTTP1
import Testing

private actor CompletionBackend: ContainerBackend {
    private var continuations: [String: CheckedContinuation<Int32?, Never>] = [:]
    private let log: Data
    private let completionEnabled: Bool
    private var execBridges: [String: ContainerIOBridge] = [:]

    init(log: Data = Data(), completionEnabled: Bool = true) {
        self.log = log
        self.completionEnabled = completionEnabled
    }
    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {}
    func start(_: ContainerRecord) async throws {}
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_: ContainerRecord) async throws {}
    func completion(_ container: ContainerRecord) async -> Int32? {
        guard completionEnabled else { return nil }
        return await withCheckedContinuation { continuations[container.id] = $0 }
    }
    func logs(for _: ContainerRecord) async throws -> Data { log }
    func finish(_ id: String, code: Int32) { continuations.removeValue(forKey: id)?.resume(returning: code) }
    func prepareExec(_ exec: ExecRecord, container _: ContainerRecord) async throws -> ContainerIOBridge {
        let bridge = ContainerIOBridge(tty: exec.configuration.tty)
        execBridges[exec.id] = bridge
        return bridge
    }
    func startExec(_ exec: ExecRecord) async throws {
        try execBridges[exec.id]?.writer(.stdout).write(Data("exec-ok\n".utf8))
        execBridges[exec.id]?.finishOutput()
    }
    func execCompletion(_: ExecRecord) async -> Int32? { 0 }
    func execIO(_ exec: ExecRecord) async throws -> ContainerIOBridge { try #require(execBridges[exec.id]) }
    func execPID(_: ExecRecord) async -> Int32 { 42 }
    func execStatus(_: ExecRecord) async -> Int32? { 0 }
    func pause(_: ContainerRecord) async throws {}
    func resume(_: ContainerRecord) async throws {}
    func loadImages(fromOCILayout _: URL) async throws -> [BackendImage] {
        [BackendImage(
            id: "sha256:0123456789abcdef",
            reference: "docker.io/example/imported:latest",
            size: 123,
            architecture: "arm64",
            os: "linux"
        )]
    }
}

private actor BlockingStartBackend: ContainerBackend {
    private var continuation: CheckedContinuation<Void, Never>?
    private var entered = false
    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {}
    func start(_: ContainerRecord) async throws {
        entered = true
        await withCheckedContinuation { continuation = $0 }
    }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 137 }
    func wait(_: ContainerRecord) async throws -> Int32 { 137 }
    func delete(_: ContainerRecord) async throws {}
    func hasEnteredStart() -> Bool { entered }
    func releaseStart() { continuation?.resume(); continuation = nil }
}

private actor ImageStoreBackend: ContainerBackend {
    private var references = ["docker.io/library/existing:latest"]
    private var deleted: [String] = []
    func pullImage(_ reference: String, platform _: String) async throws { references.append(reference) }
    func prepare(_: ContainerRecord) async throws {}
    func start(_: ContainerRecord) async throws {}
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_: ContainerRecord) async throws {}
    func listImages() async throws -> [BackendImage]? {
        references.map {
            BackendImage(id: "sha256:" + $0.data(using: .utf8)!.base64EncodedString(), reference: $0,
                         size: 456, architecture: "arm64", os: "linux")
        }
    }
    func deleteImage(reference: String) async throws {
        references.removeAll { $0 == reference }
        deleted.append(reference)
    }
    func deletedReferences() -> [String] { deleted }
}

@Suite struct DockerRouterTests {
    private func fixture() async throws -> (DockerRouter, URL) {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        return (DockerRouter(runtime: try await EngineRuntime(root: root), root: root), root)
    }

    @Test func pingAndVersionNegotiation() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let ping = await router.route(.init(method: .GET, uri: "/_ping", headers: [:], body: Data()))
        #expect(ping.status == .ok)
        #expect(String(decoding: ping.body, as: UTF8.self) == "OK")
        #expect(ping.headers["Api-Version"].first == "1.44")

        let version = await router.route(.init(method: .GET, uri: "/v1.44/version", headers: [:], body: Data()))
        #expect(version.status == .ok)
        let json = try #require(JSONSerialization.jsonObject(with: version.body) as? [String: Any])
        #expect(json["ApiVersion"] as? String == "1.44")
    }

    @Test func createStartInspectAndRemoveContainer() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let body = Data(#"{"Image":"alpine:latest","Cmd":["echo","hello"],"Labels":{"com.example":"test"}}"#.utf8)
        let create = await router.route(.init(method: .POST, uri: "/v1.44/containers/create?name=web", headers: [:], body: body))
        #expect(create.status == .created)
        let created = try #require(JSONSerialization.jsonObject(with: create.body) as? [String: Any])
        let id = try #require(created["Id"] as? String)

        let start = await router.route(.init(method: .POST, uri: "/v1.44/containers/\(id)/start", headers: [:], body: Data()))
        #expect(start.status == .noContent)
        let inspect = await router.route(.init(method: .GET, uri: "/v1.44/containers/web/json", headers: [:], body: Data()))
        #expect(inspect.status == .ok)
        let inspected = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        let state = try #require(inspected["State"] as? [String: Any])
        #expect(state["Running"] as? Bool == true)

        let kill = await router.route(.init(method: .POST, uri: "/v1.44/containers/web/kill?signal=TERM", body: Data()))
        #expect(kill.status == .noContent)

        let conflict = await router.route(.init(method: .DELETE, uri: "/v1.44/containers/web", headers: [:], body: Data()))
        #expect(conflict.status == .conflict)
        let removed = await router.route(.init(method: .DELETE, uri: "/v1.44/containers/web?force=1", headers: [:], body: Data()))
        #expect(removed.status == .noContent)
    }

    @Test func networkAndVolumeResponsesUseDockerSchema() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let networkCreate = await router.route(.init(method: .POST, uri: "/v1.44/networks/create", body: Data(#"{"Name":"frontend","Labels":{"app":"demo"}}"#.utf8)))
        #expect(networkCreate.status == .created)
        let networkInspect = await router.route(.init(method: .GET, uri: "/v1.44/networks/frontend", body: Data()))
        let network = try #require(JSONSerialization.jsonObject(with: networkInspect.body) as? [String: Any])
        #expect(network["Name"] as? String == "frontend")
        #expect(network["Driver"] as? String == "bridge")
        #expect(network["IPAM"] is [String: Any])

        let volumeCreate = await router.route(.init(method: .POST, uri: "/v1.44/volumes/create", body: Data(#"{"Name":"dbdata","Labels":{"app":"demo"}}"#.utf8)))
        #expect(volumeCreate.status == .created)
        let createdVolume = try #require(JSONSerialization.jsonObject(with: volumeCreate.body) as? [String: Any])
        #expect(createdVolume["Name"] as? String == "dbdata")
        #expect(createdVolume["Driver"] as? String == "local")
        let volumeInspect = await router.route(.init(method: .GET, uri: "/v1.44/volumes/dbdata", body: Data()))
        #expect(volumeInspect.status == .ok)
    }

    @Test func composeNetworkingAndNetworkLifecyclePersistEndpoints() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let networkCreate = await router.route(.init(
            method: .POST, uri: "/v1.44/networks/create", body: Data(#"{"Name":"project_default"}"#.utf8)
        ))
        #expect(networkCreate.status == .created)
        let create = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=web",
            body: Data(#"{"Image":"debian","NetworkingConfig":{"EndpointsConfig":{"project_default":{"Aliases":["web","api"],"IPAMConfig":{"IPv4Address":"172.30.0.20"}}}}}"#.utf8)
        ))
        #expect(create.status == .created)
        let inspected = await router.route(.init(method: .GET, uri: "/v1.44/containers/web/json"))
        #expect(inspected.status == .ok)

        let second = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=worker", body: Data(#"{"Image":"debian"}"#.utf8)
        ))
        #expect(second.status == .created)
        let connect = await router.route(.init(
            method: .POST, uri: "/v1.44/networks/project_default/connect",
            body: Data(#"{"Container":"worker","EndpointConfig":{"Aliases":["jobs"]}}"#.utf8)
        ))
        #expect(connect.status == .ok)
        let disconnect = await router.route(.init(
            method: .POST, uri: "/v1.44/networks/project_default/disconnect",
            body: Data(#"{"Container":"worker"}"#.utf8)
        ))
        #expect(disconnect.status == .ok)
        let pruneWhileUsed = await router.route(.init(method: .POST, uri: "/v1.44/networks/prune", body: Data(#"{"filters":{}}"#.utf8)))
        let pruneJSON = try #require(JSONSerialization.jsonObject(with: pruneWhileUsed.body) as? [String: Any])
        #expect((pruneJSON["NetworksDeleted"] as? [String])?.isEmpty == true)
    }

    @Test func emptyHostnamePreservesDockerStyleDefault() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let create = await router.route(.init(
            method: .POST,
            uri: "/v1.44/containers/create?name=default-hostname",
            body: Data(#"{"Image":"debian","Hostname":""}"#.utf8)
        ))
        let created = try #require(JSONSerialization.jsonObject(with: create.body) as? [String: Any])
        let id = try #require(created["Id"] as? String)
        let inspect = await router.route(.init(method: .GET, uri: "/v1.44/containers/\(id)/json", body: Data()))
        let inspected = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        let config = try #require(inspected["Config"] as? [String: Any])
        #expect(config["Hostname"] as? String == String(id.prefix(12)))

        let explicit = await router.route(.init(
            method: .POST,
            uri: "/v1.44/containers/create?name=explicit-hostname",
            body: Data(#"{"Image":"debian","Hostname":"web.internal"}"#.utf8)
        ))
        let explicitBody = try #require(JSONSerialization.jsonObject(with: explicit.body) as? [String: Any])
        let explicitID = try #require(explicitBody["Id"] as? String)
        let explicitInspect = await router.route(.init(method: .GET, uri: "/v1.44/containers/\(explicitID)/json", body: Data()))
        let explicitJSON = try #require(JSONSerialization.jsonObject(with: explicitInspect.body) as? [String: Any])
        let explicitConfig = try #require(explicitJSON["Config"] as? [String: Any])
        #expect(explicitConfig["Hostname"] as? String == "web.internal")
    }

    @Test func directBuildExplainsBuildxRequirement() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let response = await router.route(.init(method: .POST, uri: "/v1.44/build", headers: [:], body: Data()))
        #expect(response.status == .notImplemented)
        #expect(String(decoding: response.body, as: UTF8.self).contains("buildx"))
    }

    @Test func waitReturnsDockerExitStatus() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let create = await router.route(.init(method: .POST, uri: "/v1.44/containers/create?name=waiter", body: Data(#"{"Image":"debian","Cmd":["true"]}"#.utf8)))
        let body = try #require(JSONSerialization.jsonObject(with: create.body) as? [String: Any])
        let id = try #require(body["Id"] as? String)
        _ = await router.route(.init(method: .POST, uri: "/v1.44/containers/\(id)/start", body: Data()))
        let resize = await router.route(.init(method: .POST, uri: "/v1.44/containers/\(id)/resize?w=120&h=40", body: Data()))
        #expect(resize.status == .ok)
        let wait = await router.route(.init(method: .POST, uri: "/v1.44/containers/\(id)/wait", body: Data()))
        #expect(wait.status == .ok)
        let result = try #require(JSONSerialization.jsonObject(with: wait.body) as? [String: Any])
        #expect(result["StatusCode"] as? Int == 0)
    }

    @Test func pullInspectAndDeleteImage() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let pull = await router.route(.init(method: .POST, uri: "/v1.44/images/create?fromImage=alpine&tag=latest", body: Data()))
        #expect(pull.status == .ok)

        let list = await router.route(.init(method: .GET, uri: "/v1.44/images/json", body: Data()))
        let images = try #require(JSONSerialization.jsonObject(with: list.body) as? [[String: Any]])
        #expect(images.count == 1)
        #expect((images[0]["RepoTags"] as? [String]) == ["docker.io/library/alpine:latest"])

        let inspect = await router.route(.init(method: .GET, uri: "/v1.44/images/docker.io/library/alpine:latest/json", body: Data()))
        #expect(inspect.status == .ok)
        let remove = await router.route(.init(method: .DELETE, uri: "/v1.44/images/docker.io/library/alpine:latest", body: Data()))
        #expect(remove.status == .ok)
    }

    @Test func imageMetadataSynchronizesWithBackendAndDeleteReachesStore() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = ImageStoreBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        #expect(await runtime.listImages().map(\.references) == [["docker.io/library/existing:latest"]])

        let pulled = try await runtime.pullImage("docker.io/library/new:latest")
        #expect(pulled.id.hasPrefix("sha256:"))
        #expect(pulled.size == 456)
        try await runtime.removeImage("docker.io/library/new:latest", force: false)
        #expect(await backend.deletedReferences() == ["docker.io/library/new:latest"])
        #expect(await runtime.listImages().map(\.references) == [["docker.io/library/existing:latest"]])
    }

    @Test func loadImportsDockerArchiveAndMakesImageVisible() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let layout = root.appending(path: "layout")
        try FileManager.default.createDirectory(at: layout, withIntermediateDirectories: true)
        try Data(#"{"imageLayoutVersion":"1.0.0"}"#.utf8).write(to: layout.appending(path: "oci-layout"))
        let archive = root.appending(path: "image.tar")
        let tar = Process()
        tar.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
        tar.arguments = ["-cf", archive.path, "-C", layout.path, "."]
        try tar.run()
        tar.waitUntilExit()
        #expect(tar.terminationStatus == 0)

        let runtime = try await EngineRuntime(root: root, backend: CompletionBackend())
        let router = DockerRouter(runtime: runtime, root: root)
        let response = await router.route(.init(
            method: .POST,
            uri: "/v1.44/images/load",
            body: try Data(contentsOf: archive)
        ))
        #expect(response.status == .ok)
        #expect(String(decoding: response.body, as: UTF8.self).contains("docker.io/example/imported:latest"))

        let inspect = await router.route(.init(
            method: .GET,
            uri: "/v1.44/images/docker.io/example/imported:latest/json",
            body: Data()
        ))
        #expect(inspect.status == .ok)
        let image = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        #expect(image["Architecture"] as? String == "arm64")
        #expect(image["Os"] as? String == "linux")
    }

    @Test func detachedExitIsReconciledAndLogsAreServed() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let payload = Data([1, 0, 0, 0, 0, 0, 0, 3, 111, 107, 10])
        let backend = CompletionBackend(log: payload)
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let router = DockerRouter(runtime: runtime, root: root)
        let record = try await runtime.createContainer(ContainerRecord(name: "detached", image: "debian"))
        try await runtime.startContainer(record.id)

        for _ in 0..<100 {
            await backend.finish(record.id, code: 23)
            if try await runtime.container(record.id).phase == .exited { break }
            try await Task.sleep(for: .milliseconds(1))
        }
        let completed = try await runtime.container(record.id)
        #expect(completed.phase == .exited)
        #expect(completed.exitCode == 23)

        let logs = await router.route(.init(method: .GET, uri: "/v1.44/containers/\(record.id)/logs?stdout=1", body: Data()))
        #expect(logs.status == .ok)
        #expect(logs.body == payload)
    }

    @Test func execCreateStartAndInspectLifecycle() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = CompletionBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let router = DockerRouter(runtime: runtime, root: root)
        let container = try await runtime.createContainer(ContainerRecord(name: "exec-host", image: "debian"))
        try await runtime.startContainer(container.id)

        let create = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/\(container.id)/exec",
            body: Data(#"{"AttachStdout":true,"AttachStderr":true,"Cmd":["echo","ok"]}"#.utf8)
        ))
        #expect(create.status == .created)
        let created = try #require(JSONSerialization.jsonObject(with: create.body) as? [String: Any])
        let execID = try #require(created["Id"] as? String)
        let start = await router.route(.init(method: .POST, uri: "/v1.44/exec/\(execID)/start", body: Data(#"{"Detach":true,"Tty":false}"#.utf8)))
        #expect(start.status == .ok)
        for _ in 0..<20 {
            if try await runtime.exec(execID).exitCode != nil { break }
            await Task.yield()
        }
        let inspect = await router.route(.init(method: .GET, uri: "/v1.44/exec/\(execID)/json", body: Data()))
        let value = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        #expect(value["Running"] as? Bool == false)
        #expect(value["ExitCode"] as? Int == 0)
        #expect(value["ContainerID"] as? String == container.id)
    }

    @Test func concurrentRemovalWhileStartingReturnsConflictInsteadOfCrashing() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingStartBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let record = try await runtime.createContainer(ContainerRecord(name: "start-race", image: "debian"))
        let start = Task { try await runtime.startContainer(record.id) }
        while !(await backend.hasEnteredStart()) { await Task.yield() }
        try await runtime.removeContainer(record.id, force: true)
        await backend.releaseStart()
        do {
            try await start.value
            Issue.record("start should fail when the container is concurrently removed")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }
    }

    @Test func pauseUnpauseAndRestartUpdateContainerState() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root, backend: CompletionBackend(completionEnabled: false))
        let router = DockerRouter(runtime: runtime, root: root)
        let record = try await runtime.createContainer(ContainerRecord(name: "controls", image: "debian"))
        try await runtime.startContainer(record.id)

        #expect((await router.route(.init(method: .POST, uri: "/v1.44/containers/controls/pause"))).status == .noContent)
        #expect(try await runtime.container(record.id).phase == .paused)
        #expect((await router.route(.init(method: .POST, uri: "/v1.44/containers/controls/unpause"))).status == .noContent)
        #expect(try await runtime.container(record.id).phase == .running)
        #expect((await router.route(.init(method: .POST, uri: "/v1.44/containers/controls/restart?t=0"))).status == .noContent)
        let restarted = try await runtime.container(record.id)
        #expect(restarted.phase == .running)
        #expect(restarted.restartCount == 1)
    }
}

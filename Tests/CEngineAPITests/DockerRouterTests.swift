import CEngineAPI
import CEngineCore
import CEngineRuntime
import Foundation
import NIOHTTP1
import Testing

private actor CompletionBackend: ContainerBackend {
    private var continuations: [String: CheckedContinuation<Int32?, Never>] = [:]
    private let log: Data

    init(log: Data = Data()) { self.log = log }
    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {}
    func start(_: ContainerRecord) async throws {}
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_: ContainerRecord) async throws {}
    func completion(_ container: ContainerRecord) async -> Int32? {
        await withCheckedContinuation { continuations[container.id] = $0 }
    }
    func logs(for _: ContainerRecord) async throws -> Data { log }
    func finish(_ id: String, code: Int32) { continuations.removeValue(forKey: id)?.resume(returning: code) }
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
}

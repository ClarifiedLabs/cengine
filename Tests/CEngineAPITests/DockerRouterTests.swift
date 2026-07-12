@testable import CEngineAPI
import CEngineCore
@testable import CEngineRuntime
import ContainerizationExtras
import Foundation
import NIOHTTP1
import Testing

private func ethernetFrame(etherType: UInt16, payload: [UInt8]) -> [UInt8] {
    [UInt8](repeating: 0, count: 12) + [UInt8(etherType >> 8), UInt8(etherType & 0xff)] + payload
}

private func ipv4Frame(source: [UInt8], destination: [UInt8]) -> [UInt8] {
    var header = [UInt8](repeating: 0, count: 20)
    header[0] = 0x45
    header.replaceSubrange(12..<16, with: source)
    header.replaceSubrange(16..<20, with: destination)
    return ethernetFrame(etherType: 0x0800, payload: header)
}

private func arpFrame(source: [UInt8], target: [UInt8]) -> [UInt8] {
    var payload = [UInt8](repeating: 0, count: 28)
    payload[1] = 1; payload[2] = 0x08; payload[4] = 6; payload[5] = 4; payload[7] = 1
    payload.replaceSubrange(14..<18, with: source)
    payload.replaceSubrange(24..<28, with: target)
    return ethernetFrame(etherType: 0x0806, payload: payload)
}

private func ipv6Frame(source: [UInt8], destination: [UInt8], nextHeader: UInt8 = 58, type: UInt8 = 135) -> [UInt8] {
    var header = [UInt8](repeating: 0, count: 40)
    header[0] = 0x60; header[6] = nextHeader
    header.replaceSubrange(8..<24, with: source)
    header.replaceSubrange(24..<40, with: destination)
    return ethernetFrame(etherType: 0x86dd, payload: header + [type])
}

private func versionMetadataBundle() throws -> (Bundle, URL) {
    let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
    let bundleURL = root.appending(path: "VersionFixture.bundle", directoryHint: .isDirectory)
    try FileManager.default.createDirectory(at: bundleURL, withIntermediateDirectories: true)
    let info: [String: Any] = [
        "CFBundleIdentifier": "dev.cengine.api-version-fixture",
        "CFBundleName": "VersionFixture",
        "CFBundlePackageType": "BNDL",
        "CFBundleShortVersionString": "2.3.4",
        "CEngineGitCommit": "abcdef0",
        "CEngineBuildTime": "2026-02-02T17:16:40Z",
    ]
    let data = try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
    try data.write(to: bundleURL.appending(path: "Info.plist"))
    return (try #require(Bundle(url: bundleURL)), root)
}

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
    func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_: ContainerRecord) async throws {}
    func completion(_ container: ContainerRecord) async -> Int32? {
        guard completionEnabled else { return nil }
        return await withCheckedContinuation { continuations[container.id] = $0 }
    }
    func logs(for _: ContainerRecord) async throws -> Data { log }
    func finish(_ id: String, code: Int32) { continuations.removeValue(forKey: id)?.resume(returning: code) }
    func isWaitingForCompletion(_ id: String) -> Bool { continuations[id] != nil }
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
    func statistics(_: ContainerRecord) async throws -> BackendStatistics {
        .init(cpuTotalNanoseconds: 1_000, cpuUserNanoseconds: 700, cpuSystemNanoseconds: 300,
              memoryUsage: 1_024, memoryLimit: 4_096, memoryCache: 128, pids: 2,
              blockReadBytes: 10, blockWriteBytes: 20, networks: [])
    }
    func top(_: ContainerRecord, arguments _: [String]) async throws -> (titles: [String], processes: [[String]]) {
        (["PID", "CMD"], [["1", "sleep 10"]])
    }
    func runHealthcheck(_: ContainerRecord, arguments _: [String], timeoutSeconds _: Int64) async throws -> (exitCode: Int32, output: String) {
        (0, "ok")
    }
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

private actor NetworkRecordingBackend: ContainerBackend {
    private var requests: [String: NetworkRecord] = [:]

    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {}
    func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_: ContainerRecord) async throws {}

    func createNetwork(_ network: NetworkRecord) async throws -> NetworkRecord {
        requests[network.name] = network
        var result = network
        if result.subnet.isEmpty { result.subnet = "192.168.250.0/24"; result.gateway = "192.168.250.1" }
        if result.ipv6Subnet.isEmpty { result.ipv6Subnet = "fd00:ce::/64"; result.ipv6Gateway = "fd00:ce::1" }
        return result
    }

    func request(named name: String) -> NetworkRecord? { requests[name] }
}

private actor BlockingStartBackend: ContainerBackend {
    private var continuation: CheckedContinuation<Void, Never>?
    private var entered = false
    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {}
    func start(_ container: ContainerRecord) async throws -> [PortBinding] {
        entered = true
        await withCheckedContinuation { continuation = $0 }
        return container.ports
    }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 137 }
    func wait(_: ContainerRecord) async throws -> Int32 { 137 }
    func delete(_: ContainerRecord) async throws {}
    func hasEnteredStart() -> Bool { entered }
    func releaseStart() { continuation?.resume(); continuation = nil }
}

private actor ConcurrentDeleteBackend: ContainerBackend {
    private var arrivals = 0
    private var waiters: [CheckedContinuation<Void, Never>] = []
    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {}
    func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_: ContainerRecord) async throws {
        arrivals += 1
        if arrivals == 2 {
            let pending = waiters
            waiters.removeAll()
            pending.forEach { $0.resume() }
            return
        }
        await withCheckedContinuation { waiters.append($0) }
    }
}

private actor ImageStoreBackend: ContainerBackend {
    private var references = ["docker.io/library/existing:latest"]
    private var deleted: [String] = []
    func pullImage(_ reference: String, platform _: String) async throws { references.append(reference) }
    func prepare(_: ContainerRecord) async throws {}
    func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
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

private actor RestartBackend: ContainerBackend {
    private var exitCode: Int32?
    private var starts = 0
    init(exitCode: Int32? = nil) { self.exitCode = exitCode }
    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {}
    func start(_ container: ContainerRecord) async throws -> [PortBinding] { starts += 1; return container.ports }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_: ContainerRecord) async throws {}
    func completion(_: ContainerRecord) async -> Int32? { defer { exitCode = nil }; return exitCode }
    func startCount() -> Int { starts }
}

private actor AuthImageBackend: ContainerBackend {
    private var credentials: RegistryCredentials?
    private var pulled = false
    func pullImage(_: String, platform _: String) async throws {}
    func pullImage(_ reference: String, platform _: String, credentials: RegistryCredentials?, progress: @escaping ImagePullProgressHandler) async throws {
        self.credentials = credentials; pulled = true
        await progress(.init(completedItems: 1, totalItems: 2, completedBytes: 50, totalBytes: 100))
    }
    func prepare(_: ContainerRecord) async throws {}
    func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_: ContainerRecord) async throws {}
    func listImages() async throws -> [BackendImage]? {
        pulled ? [.init(id: "sha256:authenticated", reference: "registry.example/team/app:latest", size: 42,
                         architecture: "arm64", os: "linux")] : []
    }
    func imageHistory(reference _: String, platform _: String) async throws -> [ImageHistoryEntry] {
        [.init(created: 123, createdBy: "RUN true", comment: "test", emptyLayer: false)]
    }
    func username() -> String? { credentials?.username }
}

@Suite struct DockerRouterTests {
    private func fixture() async throws -> (DockerRouter, URL) {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        return (DockerRouter(runtime: try await EngineRuntime(root: root), root: root), root)
    }

    @Test func eventFiltersDecodeFormEncodedDockerJSON() throws {
        let target = try DockerRequestTarget.parse(
            "/v1.55/events?filters=%7B%22type%22%3A+%5B%22container%22%5D%2C+%22container%22%3A+%5B%22sample%22%5D%2C+%22label%22%3A+%5B%22app%3Ddemo%22%5D%7D"
        )
        #expect(DockerHTTPHandler.eventFilters(target) == [
            "type": ["container"], "container": ["sample"], "label": ["app=demo"],
        ])
    }

    @Test func pingAndVersionNegotiation() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let ping = await router.route(.init(method: .GET, uri: "/_ping", headers: [:], body: Data()))
        #expect(ping.status == .ok)
        #expect(String(decoding: ping.body, as: UTF8.self) == "OK")
        #expect(ping.headers["Api-Version"].first == "1.55")

        let version = await router.route(.init(method: .GET, uri: "/v1.44/version", headers: [:], body: Data()))
        #expect(version.status == .ok)
        let json = try #require(JSONSerialization.jsonObject(with: version.body) as? [String: Any])
        #expect(json["ApiVersion"] as? String == "1.55")
        #expect(json["MinAPIVersion"] as? String == "1.44")

        for minor in 44...55 {
            #expect((await router.route(.init(method: .GET, uri: "/v1.\(minor)/info"))).status == .ok)
        }
    }

    @Test func rejectsRequestsOutsideNegotiatedAPIRange() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }

        for uri in ["/v1.43/info", "/v1.56/info", "/v1.x/info", "/info"] {
            let response = await router.route(.init(method: .GET, uri: uri))
            #expect(response.status == .badRequest)
            let json = try #require(JSONSerialization.jsonObject(with: response.body) as? [String: String])
            #expect(json["message"]?.isEmpty == false)
        }

        #expect((await router.route(.init(method: .GET, uri: "/version"))).status == .ok)
        #expect((await router.route(.init(method: .GET, uri: "/_ping"))).status == .ok)
    }

    @Test func versionIncludesBuildMetadataInEngineDetails() throws {
        let (bundle, root) = try versionMetadataBundle()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = try JSONEncoder().encode(DockerVersionResponse(bundle: bundle))
        let json = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(json["GitCommit"] as? String == "abcdef0")
        #expect(json["BuildTime"] as? String == "2026-02-02T17:16:40Z")
        #expect(json["ApiVersion"] as? String == "1.55")
        #expect(json["MinAPIVersion"] as? String == "1.44")
        let components = try #require(json["Components"] as? [[String: Any]])
        let engine = try #require(components.first)
        let details = try #require(engine["Details"] as? [String: String])
        #expect(details["GitCommit"] == "abcdef0")
        #expect(details["BuildTime"] == "Mon Feb  2 17:16:40 2026")
        #expect(details["ApiVersion"] == "1.55")
        #expect(details["MinAPIVersion"] == "1.44")
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
        let excluded = await router.route(.init(
            method: .GET,
            uri: "/v1.44/containers/json?all=1&filters=%7B%22label%22:%5B%22com.example=other%22%5D%7D"
        ))
        let excludedContainers = try #require(JSONSerialization.jsonObject(with: excluded.body) as? [[String: Any]])
        #expect(excludedContainers.isEmpty)

        let kill = await router.route(.init(method: .POST, uri: "/v1.44/containers/web/kill?signal=TERM", body: Data()))
        #expect(kill.status == .noContent)

        let conflict = await router.route(.init(method: .DELETE, uri: "/v1.44/containers/web", headers: [:], body: Data()))
        #expect(conflict.status == .conflict)
        let removed = await router.route(.init(method: .DELETE, uri: "/v1.44/containers/web?force=1", headers: [:], body: Data()))
        #expect(removed.status == .noContent)
    }

    @Test func killReconcilesSigkillBeforeReturning() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root, backend: CompletionBackend(completionEnabled: false))
        let router = DockerRouter(runtime: runtime, root: root)
        let create = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=killed",
            body: Data(#"{"Image":"alpine","Cmd":["top"]}"#.utf8)
        ))
        let body = try #require(JSONSerialization.jsonObject(with: create.body) as? [String: Any])
        let id = try #require(body["Id"] as? String)
        _ = await router.route(.init(method: .POST, uri: "/v1.44/containers/\(id)/start"))
        let kill = await router.route(.init(method: .POST, uri: "/v1.44/containers/\(id)/kill?signal=SIGKILL"))
        #expect(kill.status == .noContent)
        let inspect = await router.route(.init(method: .GET, uri: "/v1.44/containers/\(id)/json"))
        let inspected = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        let state = try #require(inspected["State"] as? [String: Any])
        #expect(state["Status"] as? String == "exited")
        #expect(state["Running"] as? Bool == false)
    }

    @Test func inspectReportsNormalizedMountsAndBlankHostPorts() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let response = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=shape",
            body: Data(#"{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"volume","Source":"data","Target":"/data","ReadOnly":true}],"PortBindings":{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":""}]}}}"#.utf8)
        ))
        let created = try #require(JSONSerialization.jsonObject(with: response.body) as? [String: Any])
        let id = try #require(created["Id"] as? String)
        let inspect = await router.route(.init(method: .GET, uri: "/v1.44/containers/\(id)/json"))
        let object = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        let mounts = try #require(object["Mounts"] as? [[String: Any]])
        #expect(mounts.first?["Destination"] as? String == "/data")
        #expect(mounts.first?["RW"] as? Bool == false)
        let host = try #require(object["HostConfig"] as? [String: Any])
        #expect((host["Binds"] as? [String]) == ["data:/data:ro"])
        #expect(host["NetworkMode"] as? String == "default")
        let logConfig = try #require(host["LogConfig"] as? [String: Any])
        #expect(logConfig["Type"] as? String == "json-file")
        let bindings = try #require(host["PortBindings"] as? [String: [[String: String]]])
        #expect(bindings["8080/tcp"]?.first?["HostPort"] == "0")
    }

    @Test func createUsesCPUQuotaWhenNanoCPUsAreAbsent() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let response = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=quota-limited",
            body: Data(#"{"Image":"alpine","HostConfig":{"Memory":4294967296,"CpuPeriod":100000,"CpuQuota":400000}}"#.utf8)
        ))
        let created = try #require(JSONSerialization.jsonObject(with: response.body) as? [String: Any])
        let id = try #require(created["Id"] as? String)
        let inspect = await router.route(.init(method: .GET, uri: "/v1.44/containers/\(id)/json"))
        let object = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        let host = try #require(object["HostConfig"] as? [String: Any])

        #expect(host["Memory"] as? Int == 4 * 1_024 * 1_024 * 1_024)
        #expect(host["NanoCpus"] as? Int == 4_000_000_000)
    }

    @Test func createUsesConfiguredContainerDefaultsUnlessResourcesAreExplicit() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        try ContainerSettings(cpus: 2, memoryGiB: 3).save(
            to: root.appending(path: ContainerSettings.fileName)
        )

        let defaultCreate = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=configured-defaults",
            body: Data(#"{"Image":"alpine"}"#.utf8)
        ))
        let defaultBody = try #require(JSONSerialization.jsonObject(with: defaultCreate.body) as? [String: Any])
        let defaultID = try #require(defaultBody["Id"] as? String)
        let defaultInspect = await router.route(.init(method: .GET, uri: "/v1.44/containers/\(defaultID)/json"))
        let defaultObject = try #require(JSONSerialization.jsonObject(with: defaultInspect.body) as? [String: Any])
        let defaultHost = try #require(defaultObject["HostConfig"] as? [String: Any])
        #expect(defaultHost["Memory"] as? Int == 3 * 1_024 * 1_024 * 1_024)
        #expect(defaultHost["NanoCpus"] as? Int == 2_000_000_000)

        let explicitCreate = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=explicit-resources",
            body: Data(#"{"Image":"alpine","HostConfig":{"Memory":1073741824,"NanoCpus":1000000000}}"#.utf8)
        ))
        let explicitBody = try #require(JSONSerialization.jsonObject(with: explicitCreate.body) as? [String: Any])
        let explicitID = try #require(explicitBody["Id"] as? String)
        let explicitInspect = await router.route(.init(method: .GET, uri: "/v1.44/containers/\(explicitID)/json"))
        let explicitObject = try #require(JSONSerialization.jsonObject(with: explicitInspect.body) as? [String: Any])
        let explicitHost = try #require(explicitObject["HostConfig"] as? [String: Any])
        #expect(explicitHost["Memory"] as? Int == 1_073_741_824)
        #expect(explicitHost["NanoCpus"] as? Int == 1_000_000_000)
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
        #expect(network["EnableIPv6"] as? Bool == true)
        let ipam = try #require(network["IPAM"] as? [String: Any])
        let configs = try #require(ipam["Config"] as? [[String: Any]])
        #expect(configs.count == 2)
        #expect((configs[1]["Subnet"] as? String)?.contains(":") == true)

        let volumeCreate = await router.route(.init(method: .POST, uri: "/v1.44/volumes/create", body: Data(#"{"Name":"dbdata","Labels":{"app":"demo"}}"#.utf8)))
        #expect(volumeCreate.status == .created)
        let createdVolume = try #require(JSONSerialization.jsonObject(with: volumeCreate.body) as? [String: Any])
        #expect(createdVolume["Name"] as? String == "dbdata")
        #expect(createdVolume["Driver"] as? String == "local")
        let volumeInspect = await router.route(.init(method: .GET, uri: "/v1.44/volumes/dbdata", body: Data()))
        #expect(volumeInspect.status == .ok)
    }

    @Test func runningContainersRejectNetworkAttachmentChanges() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        #expect((await router.route(.init(
            method: .POST, uri: "/v1.44/networks/create", body: Data(#"{"Name":"late"}"#.utf8)
        ))).status == .created)
        let create = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=live", body: Data(#"{"Image":"debian"}"#.utf8)
        ))
        let created = try #require(JSONSerialization.jsonObject(with: create.body) as? [String: Any])
        let id = try #require(created["Id"] as? String)
        #expect((await router.route(.init(method: .POST, uri: "/v1.44/containers/\(id)/start"))).status == .noContent)
        let connect = await router.route(.init(
            method: .POST, uri: "/v1.44/networks/late/connect",
            body: Data("{\"Container\":\"\(id)\"}".utf8)
        ))
        #expect(connect.status == .conflict)
    }

    @Test func networkConnectTreatsDockerEmptyAddressesAsUnspecified() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        #expect((await router.route(.init(
            method: .POST, uri: "/v1.44/networks/create", body: Data(#"{"Name":"extra"}"#.utf8)
        ))).status == .created)
        let create = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=stopped", body: Data(#"{"Image":"debian"}"#.utf8)
        ))
        let created = try #require(JSONSerialization.jsonObject(with: create.body) as? [String: Any])
        let id = try #require(created["Id"] as? String)
        let connect = await router.route(.init(
            method: .POST, uri: "/v1.44/networks/extra/connect",
            body: Data("{\"Container\":\"\(id)\",\"EndpointConfig\":{\"IPAMConfig\":{\"IPv4Address\":\"\",\"IPv6Address\":\"\"},\"IPAddress\":\"\",\"GlobalIPv6Address\":\"\"}}".utf8)
        ))
        #expect(connect.status == .ok)
    }

    @Test func composeEmptyNetworkDriverUsesDefaultBridge() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let create = await router.route(.init(
            method: .POST, uri: "/v1.55/networks/create",
            body: Data(#"{"Name":"compose-default","Driver":""}"#.utf8)
        ))
        #expect(create.status == .created)
        let inspect = await router.route(.init(
            method: .GET, uri: "/v1.55/networks/compose-default"
        ))
        let json = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        #expect(json["Driver"] as? String == "bridge")
    }

    @Test func networkPoolsExpandAndInterleaveConfiguredPrivateRanges() throws {
        #expect(try AppleContainerBackend.expand(pool: "192.168.240.0/23") == [
            "192.168.240.0/24", "192.168.241.0/24",
        ])
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try Data(#"{"network":{"ipv4Pools":["192.168.250.0/23","172.29.8.0/23","10.240.8.0/23"]}}"#.utf8)
            .write(to: root.appending(path: "config.json"))
        #expect(try AppleContainerBackend.loadSubnetCandidates(root: root) == [
            "192.168.250.0/24", "172.29.8.0/24", "10.240.8.0/24",
            "192.168.251.0/24", "172.29.9.0/24", "10.240.9.0/24",
        ])
    }

    @Test func networkAllocationModesAreTrackedPerAddressFamily() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = NetworkRecordingBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)

        _ = try await runtime.createNetwork(name: "automatic")
        _ = try await runtime.createNetwork(name: "ipv4", subnet: "172.30.0.0/24")
        _ = try await runtime.createNetwork(name: "ipv6", ipv6Subnet: "fc00:f853:ccd:e793::/64")
        _ = try await runtime.createNetwork(
            name: "dual", subnet: "172.31.0.0/24", ipv6Subnet: "fd00:1234::/64"
        )

        let automatic = try #require(await backend.request(named: "automatic"))
        #expect(automatic.ipv4AllocationMode == .automatic)
        #expect(automatic.ipv6AllocationMode == .automatic)
        let ipv4 = try #require(await backend.request(named: "ipv4"))
        #expect(ipv4.ipv4AllocationMode == .explicit)
        #expect(ipv4.ipv6AllocationMode == .automatic)
        let ipv6 = try #require(await backend.request(named: "ipv6"))
        #expect(ipv6.ipv4AllocationMode == .automatic)
        #expect(ipv6.ipv6AllocationMode == .explicit)
        let dual = try #require(await backend.request(named: "dual"))
        #expect(dual.ipv4AllocationMode == .explicit)
        #expect(dual.ipv6AllocationMode == .explicit)
    }

    @Test func isolatedGatewayOptionsRoundTripAndRequireInternalNetwork() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = NetworkRecordingBackend()
        let router = DockerRouter(runtime: try await EngineRuntime(root: root, backend: backend), root: root)
        let invalid = await router.route(.init(
            method: .POST, uri: "/v1.55/networks/create",
            body: Data(#"{"Name":"invalid-isolated","Options":{"com.docker.network.bridge.gateway_mode_ipv4":"isolated"}}"#.utf8)
        ))
        #expect(invalid.status == .badRequest)

        let create = await router.route(.init(
            method: .POST, uri: "/v1.55/networks/create",
            body: Data(#"{"Name":"isolated","Internal":true,"Options":{"com.docker.network.bridge.gateway_mode_ipv4":"isolated","com.docker.network.bridge.gateway_mode_ipv6":"isolated"}}"#.utf8)
        ))
        #expect(create.status == .created)
        let request = try #require(await backend.request(named: "isolated"))
        #expect(request.internalNetwork)
        #expect(request.ipv4GatewayMode == .isolated)
        #expect(request.ipv6GatewayMode == .isolated)

        let inspect = await router.route(.init(method: .GET, uri: "/v1.55/networks/isolated"))
        let json = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        let options = try #require(json["Options"] as? [String: String])
        #expect(options[NetworkRecord.gatewayModeIPv4Option] == "isolated")
        #expect(options[NetworkRecord.gatewayModeIPv6Option] == "isolated")
    }

    @Test func networkNonePersistsWithoutAnImplicitDefaultInterface() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        var router = DockerRouter(runtime: try await EngineRuntime(root: root), root: root)
        let create = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=no-network",
            body: Data(#"{"Image":"alpine","HostConfig":{"NetworkMode":"none"}}"#.utf8)
        ))
        #expect(create.status == .created)
        router = DockerRouter(runtime: try await EngineRuntime(root: root), root: root)
        let inspect = await router.route(.init(method: .GET, uri: "/v1.55/containers/no-network/json"))
        let json = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        let host = try #require(json["HostConfig"] as? [String: Any])
        let settings = try #require(json["NetworkSettings"] as? [String: Any])
        #expect(host["NetworkMode"] as? String == "none")
        #expect((settings["Networks"] as? [String: Any])?.isEmpty == true)
    }

    @Test func networkNoneRejectsOtherNetworksAndPublishedPorts() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let endpointConflict = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=endpoint-conflict",
            body: Data(#"{"Image":"alpine","HostConfig":{"NetworkMode":"none"},"NetworkingConfig":{"EndpointsConfig":{"default":{}}}}"#.utf8)
        ))
        #expect(endpointConflict.status == .badRequest)
        let portConflict = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=port-conflict",
            body: Data(#"{"Image":"alpine","HostConfig":{"NetworkMode":"none","PortBindings":{"80/tcp":[{"HostPort":"8080"}]}}}"#.utf8)
        ))
        #expect(portConflict.status == .badRequest)
    }

    @Test func isolatedGatewayPacketFilterCannotBeBypassedWithAGuestRoute() throws {
        let filter = IsolatedGatewayPacketFilter(
            subnet: try CIDRv4("192.168.224.0/24"), prefixV6: nil,
            isolateIPv4: true, isolateIPv6: false
        )
        let peer = ipv4Frame(source: [192, 168, 224, 2], destination: [192, 168, 224, 3])
        #expect(filter.allows(peer, direction: .guestToNetwork))
        #expect(filter.allows(peer, direction: .networkToGuest))
        #expect(!filter.allows(
            ipv4Frame(source: [192, 168, 224, 2], destination: [192, 168, 224, 1]),
            direction: .guestToNetwork
        ))
        #expect(!filter.allows(
            ipv4Frame(source: [192, 168, 224, 2], destination: [8, 8, 8, 8]),
            direction: .guestToNetwork
        ))
        #expect(!filter.allows(
            arpFrame(source: [192, 168, 224, 2], target: [192, 168, 224, 1]),
            direction: .guestToNetwork
        ))
        #expect(filter.allows(
            arpFrame(source: [192, 168, 224, 2], target: [192, 168, 224, 3]),
            direction: .guestToNetwork
        ))
    }

    @Test func isolatedGatewayPacketFilterAppliesModesPerAddressFamily() throws {
        let local2 = [UInt8](repeating: 0, count: 15) + [2]
        let local3 = [UInt8](repeating: 0, count: 15) + [3]
        let external = [UInt8](repeating: 0x20, count: 16)
        let filter = IsolatedGatewayPacketFilter(
            subnet: try CIDRv4("192.168.224.0/24"), prefixV6: try CIDRv6("::/64"),
            isolateIPv4: true, isolateIPv6: false
        )
        #expect(!filter.allows(
            ipv4Frame(source: [192, 168, 224, 2], destination: [8, 8, 8, 8]),
            direction: .guestToNetwork
        ))
        #expect(filter.allows(ipv6Frame(source: local2, destination: local3), direction: .guestToNetwork))
        #expect(filter.allows(ipv6Frame(source: local2, destination: external), direction: .guestToNetwork))
    }

    @Test func isolatedGatewayPacketFilterAllowsDiscoveryButNotHostMulticastServices() throws {
        let local = [0xfd] + [UInt8](repeating: 0, count: 14) + [2]
        let multicast = [0xff, 0x02] + [UInt8](repeating: 0, count: 13) + [1]
        let filter = IsolatedGatewayPacketFilter(
            subnet: try CIDRv4("192.168.224.0/24"), prefixV6: try CIDRv6("fd00::/64"),
            isolateIPv4: false, isolateIPv6: true
        )
        #expect(filter.allows(
            ipv6Frame(source: local, destination: multicast), direction: .guestToNetwork
        ))
        #expect(!filter.allows(
            ipv6Frame(source: local, destination: multicast, nextHeader: 17), direction: .guestToNetwork
        ))
    }

    @Test func kindIPv6OnlyNetworkRequestAllocatesIPv4AndAllowsOnlyStaticIPv6() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = NetworkRecordingBackend()
        let router = DockerRouter(runtime: try await EngineRuntime(root: root, backend: backend), root: root)
        let create = await router.route(.init(
            method: .POST, uri: "/v1.55/networks/create",
            body: Data(#"{"Name":"kind","Driver":"bridge","EnableIPv6":true,"IPAM":{"Config":[{"Subnet":"fc00:f853:ccd:e793::/64"}]},"Options":{"com.docker.network.bridge.enable_ip_masquerade":"true"}}"#.utf8)
        ))
        #expect(create.status == .created)
        let request = try #require(await backend.request(named: "kind"))
        #expect(request.subnet.isEmpty)
        #expect(request.ipv4AllocationMode == .automatic)
        #expect(request.ipv6Subnet == "fc00:f853:ccd:e793::/64")
        #expect(request.ipv6AllocationMode == .explicit)
        #expect(request.options?[NetworkRecord.enableIPMasqueradeOption] == "true")

        let staticIPv6 = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=static-v6",
            body: Data(#"{"Image":"debian","NetworkingConfig":{"EndpointsConfig":{"kind":{"IPAMConfig":{"IPv6Address":"fc00:f853:ccd:e793::2"}}}}}"#.utf8)
        ))
        #expect(staticIPv6.status == .created)
        let staticIPv4 = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=static-v4",
            body: Data(#"{"Image":"debian","NetworkingConfig":{"EndpointsConfig":{"kind":{"IPAMConfig":{"IPv4Address":"192.168.250.20"}}}}}"#.utf8)
        ))
        #expect(staticIPv4.status == .badRequest)
    }

    @Test func uniqueLocalIPv6ValidationAcceptsTheFullRFC4193Range() throws {
        #expect(AppleContainerBackend.isUniqueLocal(prefix: try CIDRv6("fc00::/64")))
        #expect(AppleContainerBackend.isUniqueLocal(prefix: try CIDRv6("fdff:ffff:ffff:ffff::/64")))
        #expect(!AppleContainerBackend.isUniqueLocal(prefix: try CIDRv6("fbff:ffff::/64")))
        #expect(!AppleContainerBackend.isUniqueLocal(prefix: try CIDRv6("fe00::/64")))
        #expect(!AppleContainerBackend.isUniqueLocal(prefix: try CIDRv6("fc00::/48")))
    }

    @Test func responseShapesFollowRequestedAPIVersion() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }

        _ = await router.route(.init(method: .POST, uri: "/v1.55/networks/create", body: Data(#"{"Name":"versioned"}"#.utf8)))
        let create = await router.route(.init(
            method: .POST,
            uri: "/v1.55/containers/create?name=shape-version",
            body: Data(#"{"Image":"alpine","NetworkingConfig":{"EndpointsConfig":{"versioned":{"Aliases":["web"]}}}}"#.utf8)
        ))
        let created = try #require(JSONSerialization.jsonObject(with: create.body) as? [String: Any])
        let id = try #require(created["Id"] as? String)

        let oldInspect = await router.route(.init(method: .GET, uri: "/v1.44/containers/\(id)/json"))
        let oldJSON = try #require(JSONSerialization.jsonObject(with: oldInspect.body) as? [String: Any])
        let oldSettings = try #require(oldJSON["NetworkSettings"] as? [String: Any])
        let oldNetworks = try #require(oldSettings["Networks"] as? [String: Any])
        let oldEndpoint = try #require(oldNetworks["versioned"] as? [String: Any])
        let oldAliases = try #require(oldEndpoint["Aliases"] as? [String])
        #expect(oldAliases.contains("web"))
        #expect(oldAliases.contains(String(id.prefix(12))))
        #expect(oldSettings["Bridge"] != nil)

        let newInspect = await router.route(.init(method: .GET, uri: "/v1.55/containers/\(id)/json"))
        let newJSON = try #require(JSONSerialization.jsonObject(with: newInspect.body) as? [String: Any])
        let newSettings = try #require(newJSON["NetworkSettings"] as? [String: Any])
        let newNetworks = try #require(newSettings["Networks"] as? [String: Any])
        let newEndpoint = try #require(newNetworks["versioned"] as? [String: Any])
        #expect(newEndpoint["Aliases"] as? [String] == ["web"])
        #expect(newSettings["Bridge"] == nil)
        #expect(newSettings["HairpinMode"] == nil)

        let oldList = await router.route(.init(method: .GET, uri: "/v1.44/containers/json?all=1"))
        let oldSummary = try #require((JSONSerialization.jsonObject(with: oldList.body) as? [[String: Any]])?.first)
        #expect(oldSummary["Health"] == nil)
        let newList = await router.route(.init(method: .GET, uri: "/v1.55/containers/json?all=1"))
        let newSummary = try #require((JSONSerialization.jsonObject(with: newList.body) as? [[String: Any]])?.first)
        #expect((newSummary["Health"] as? [String: Any])?["Status"] as? String == "none")

        let image = ImageRecord(
            id: "sha256:test", references: [
                "docker.io/library/example:test", "docker.io/library/example@sha256:digest",
            ], createdAt: Date(), size: 1,
            architecture: "arm64", os: "linux"
        )
        let oldImage = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(
            ImageInspectResponse(image, version: .init(major: 1, minor: 51))
        )) as? [String: Any])
        let newImage = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(
            ImageInspectResponse(image, version: .init(major: 1, minor: 52))
        )) as? [String: Any])
        #expect((oldImage["Config"] as? [String: Any])?["Env"] != nil)
        #expect((newImage["Config"] as? [String: Any])?["Env"] == nil)
        #expect(newImage["RepoTags"] as? [String] == ["example:test"])
        #expect(newImage["RepoDigests"] as? [String] == ["example@sha256:digest"])

        let summary = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(
            ImageSummaryResponse(image, containers: 2)
        )) as? [String: Any])
        #expect(summary["ParentId"] as? String == "")
        #expect(summary["Containers"] as? Int == 2)
        #expect(summary["VirtualSize"] == nil)

        let event = RuntimeEvent(type: "container", action: "start", id: id, attributes: [:])
        let oldEvent = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(
            DockerEventResponse(event, version: .init(major: 1, minor: 51))
        )) as? [String: Any])
        let newEvent = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(
            DockerEventResponse(event, version: .init(major: 1, minor: 52))
        )) as? [String: Any])
        #expect(oldEvent["status"] as? String == "start")
        #expect(oldEvent["id"] as? String == id)
        #expect(newEvent["status"] == nil)
        #expect(newEvent["id"] == nil)
    }

    @Test func defaultNetworkIsAlwaysPresentAndCannotBeRemoved() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let inspect = await router.route(.init(method: .GET, uri: "/v1.44/networks/default"))
        #expect(inspect.status == .ok)
        let remove = await router.route(.init(method: .DELETE, uri: "/v1.44/networks/default"))
        #expect(remove.status == .conflict)
        let prune = await router.route(.init(method: .POST, uri: "/v1.44/networks/prune"))
        #expect(prune.status == .ok)
        let after = await router.route(.init(method: .GET, uri: "/v1.44/networks/default"))
        #expect(after.status == .ok)
    }

    @Test func composeNetworkingAndNetworkLifecyclePersistEndpoints() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let networkCreate = await router.route(.init(
            method: .POST, uri: "/v1.44/networks/create",
            body: Data(#"{"Name":"project_default","IPAM":{"Config":[{"Subnet":"172.30.0.0/24"}]}}"#.utf8)
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

    @Test func containerCreateAcceptsNullNetworkEndpointSettings() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        _ = await router.route(.init(
            method: .POST, uri: "/v1.44/networks/create",
            body: Data(#"{"Name":"selected"}"#.utf8)
        ))
        let create = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=null-endpoint",
            body: Data(#"{"Image":"debian","NetworkingConfig":{"selected":null}}"#.utf8)
        ))
        #expect(create.status == .created)
        let inspect = await router.route(.init(
            method: .GET, uri: "/v1.44/containers/null-endpoint/json"
        ))
        let object = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        let settings = try #require(object["NetworkSettings"] as? [String: Any])
        let networks = try #require(settings["Networks"] as? [String: Any])
        #expect(networks["selected"] != nil)
    }

    @Test func malformedContainerCreateBodyReturnsBadRequest() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let response = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create", body: Data(#"{"Image":42}"#.utf8)
        ))
        #expect(response.status == .badRequest)
    }

    @Test func containerRenamePersistsAndRejectsConflicts() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        _ = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=first",
            body: Data(#"{"Image":"debian"}"#.utf8)
        ))
        _ = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=second",
            body: Data(#"{"Image":"debian"}"#.utf8)
        ))
        let renamed = await router.route(.init(method: .POST, uri: "/v1.44/containers/first/rename?name=renamed"))
        #expect(renamed.status == .noContent)
        #expect((await router.route(.init(method: .GET, uri: "/v1.44/containers/renamed/json"))).status == .ok)
        let conflict = await router.route(.init(method: .POST, uri: "/v1.44/containers/second/rename?name=renamed"))
        #expect(conflict.status == .conflict)
    }

    @Test func composeResourceListsHonorProjectLabelFilters() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        for (name, project) in [("first", "alpha"), ("second", "beta")] {
            _ = await router.route(.init(
                method: .POST, uri: "/v1.44/networks/create",
                body: Data("{\"Name\":\"\(name)\",\"Labels\":{\"com.docker.compose.project\":\"\(project)\"}}".utf8)
            ))
            _ = await router.route(.init(
                method: .POST, uri: "/v1.44/volumes/create",
                body: Data("{\"Name\":\"\(name)\",\"Labels\":{\"com.docker.compose.project\":\"\(project)\"}}".utf8)
            ))
        }
        let filters = "%7B%22label%22:%5B%22com.docker.compose.project=alpha%22%5D%7D"
        let networks = await router.route(.init(method: .GET, uri: "/v1.44/networks?filters=\(filters)"))
        let networkJSON = try #require(JSONSerialization.jsonObject(with: networks.body) as? [[String: Any]])
        #expect(networkJSON.map { $0["Name"] as? String } == ["first"])
        let volumes = await router.route(.init(method: .GET, uri: "/v1.44/volumes?filters=\(filters)"))
        let volumeJSON = try #require(JSONSerialization.jsonObject(with: volumes.body) as? [String: Any])
        let items = try #require(volumeJSON["Volumes"] as? [[String: Any]])
        #expect(items.map { $0["Name"] as? String } == ["first"])
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

    @Test func containerCreatePreservesRequestedPlatform() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root, backend: CompletionBackend(completionEnabled: false))
        let router = DockerRouter(runtime: runtime, root: root)
        let response = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=amd64&platform=linux%2Famd64",
            body: Data(#"{"Image":"debian"}"#.utf8)
        ))
        #expect(response.status == .created)
        #expect(try await runtime.container("amd64").platform == "linux/amd64")
    }

    @Test func directBuildExplainsBuildxRequirement() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let response = await router.route(.init(method: .POST, uri: "/v1.44/build", headers: [:], body: Data()))
        #expect(response.status == .notImplemented)
        #expect(String(decoding: response.body, as: UTF8.self).contains("buildx"))
    }

    @Test func waitReturnsDockerExitStatus() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = CompletionBackend()
        let router = DockerRouter(runtime: try await EngineRuntime(root: root, backend: backend), root: root)
        let create = await router.route(.init(method: .POST, uri: "/v1.44/containers/create?name=waiter", body: Data(#"{"Image":"debian","Cmd":["true"]}"#.utf8)))
        let body = try #require(JSONSerialization.jsonObject(with: create.body) as? [String: Any])
        let id = try #require(body["Id"] as? String)
        _ = await router.route(.init(method: .POST, uri: "/v1.44/containers/\(id)/start", body: Data()))
        let resize = await router.route(.init(method: .POST, uri: "/v1.44/containers/\(id)/resize?w=120&h=40", body: Data()))
        #expect(resize.status == .ok)
        let waiting = Task {
            await router.route(.init(method: .POST, uri: "/v1.44/containers/\(id)/wait", body: Data()))
        }
        for _ in 0..<100 where !(await backend.isWaitingForCompletion(id)) {
            try await Task.sleep(for: .milliseconds(10))
        }
        await backend.finish(id, code: 0)
        let wait = await waiting.value
        #expect(wait.status == .ok)
        let result = try #require(JSONSerialization.jsonObject(with: wait.body) as? [String: Any])
        #expect(result["StatusCode"] as? Int == 0)
    }

    @Test func waitNextExitBlocksUntilCreatedContainerRunsAndExits() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = CompletionBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let router = DockerRouter(runtime: runtime, root: root)
        let create = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=next-exit",
            body: Data(#"{"Image":"alpine","Cmd":["true"]}"#.utf8)
        ))
        let body = try #require(JSONSerialization.jsonObject(with: create.body) as? [String: Any])
        let id = try #require(body["Id"] as? String)
        let subscription = try await router.containerWait(id, condition: "next-exit")
        let wait = Task {
            for await code in subscription.stream { return code }
            return -1
        }
        _ = await router.route(.init(method: .POST, uri: "/v1.44/containers/\(id)/start"))
        for _ in 0..<100 where !(await backend.isWaitingForCompletion(id)) {
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(await backend.isWaitingForCompletion(id))
        await backend.finish(id, code: 23)
        #expect(await wait.value == 23)
    }

    @Test func kindContainerCreateOptionsRoundTrip() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        _ = await router.route(.init(
            method: .POST, uri: "/v1.44/networks/create",
            body: Data(#"{"Name":"kind"}"#.utf8)
        ))
        let create = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=kind-control-plane",
            body: Data(#"{"Image":"kindest/node:v1.36.1","Volumes":{"/var":{}},"HostConfig":{"NetworkMode":"kind","Binds":["/lib/modules:/lib/modules:ro"]}}"#.utf8)
        ))
        #expect(create.status == .created)
        let inspect = await router.route(.init(method: .GET, uri: "/v1.55/containers/kind-control-plane/json"))
        let json = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        let host = try #require(json["HostConfig"] as? [String: Any])
        #expect(host["NetworkMode"] as? String == "kind")
        let mounts = try #require(json["Mounts"] as? [[String: Any]])
        #expect(mounts.contains { $0["Type"] as? String == "volume" && $0["Destination"] as? String == "/var" })
        #expect(mounts.contains { $0["Type"] as? String == "bind" && $0["Source"] as? String == "/lib/modules" })
        let networkSettings = try #require(json["NetworkSettings"] as? [String: Any])
        let networks = try #require(networkSettings["Networks"] as? [String: Any])
        #expect(networks["kind"] != nil)

        let stored = try Data(contentsOf: root.appending(path: "engine.json"))
        let serialized = String(decoding: stored, as: UTF8.self)
        #expect(serialized.contains(#""createSourceIfMissing":true"#))

        let info = await router.route(.init(method: .GET, uri: "/v1.55/info"))
        let infoJSON = try #require(JSONSerialization.jsonObject(with: info.body) as? [String: Any])
        #expect(infoJSON["CgroupVersion"] as? String == "2")
    }

    @Test func pullInspectAndDeleteImage() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let pull = await router.route(.init(method: .POST, uri: "/v1.44/images/create?fromImage=alpine&tag=latest", body: Data()))
        #expect(pull.status == .ok)

        let list = await router.route(.init(method: .GET, uri: "/v1.44/images/json", body: Data()))
        let images = try #require(JSONSerialization.jsonObject(with: list.body) as? [[String: Any]])
        #expect(images.count == 1)
        #expect((images[0]["RepoTags"] as? [String]) == ["alpine:latest"])

        let inspect = await router.route(.init(method: .GET, uri: "/v1.44/images/docker.io/library/alpine:latest/json", body: Data()))
        #expect(inspect.status == .ok)
        let shortInspect = await router.route(.init(method: .GET, uri: "/v1.44/images/alpine:latest/json", body: Data()))
        #expect(shortInspect.status == .ok)
        let shortJSON = try #require(JSONSerialization.jsonObject(with: shortInspect.body) as? [String: Any])
        #expect(shortJSON["Config"] is [String: Any])
        let remove = await router.route(.init(method: .DELETE, uri: "/v1.44/images/docker.io/library/alpine:latest", body: Data()))
        #expect(remove.status == .ok)
    }

    @Test func pullImageByDigestUsesDigestSeparator() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = ImageStoreBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let router = DockerRouter(runtime: runtime, root: root)
        let digest = "sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"

        let response = await router.route(.init(
            method: .POST,
            uri: "/v1.44/images/create?fromImage=kindest%2Fnode&tag=\(digest)"
        ))

        #expect(response.status == .ok)
        #expect(try await runtime.image("docker.io/kindest/node@\(digest)").references == [
            "docker.io/kindest/node@\(digest)"
        ])
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

    @Test func concurrentContainerRemovalsDoNotUseStaleIndices() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root, backend: ConcurrentDeleteBackend())
        let first = try await runtime.createContainer(ContainerRecord(name: "remove-first", image: "debian"))
        let second = try await runtime.createContainer(ContainerRecord(name: "remove-second", image: "debian"))
        async let removeFirst: Void = runtime.removeContainer(first.id, force: false)
        async let removeSecond: Void = runtime.removeContainer(second.id, force: false)
        _ = try await (removeFirst, removeSecond)
        #expect(await runtime.listContainers(all: true).isEmpty)
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

    @Test func runtimePublishesDockerLifecycleEvents() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root)
        let stream = await runtime.events()
        var iterator = stream.makeAsyncIterator()
        let record = try await runtime.createContainer(ContainerRecord(name: "eventful", image: "debian"))
        let event = await iterator.next()
        #expect(event?.action == "create")
        #expect(event?.id == record.id)
        #expect(event?.attributes["name"] == "eventful")
    }

    @Test func runtimeReplaysBoundedEventHistory() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root)
        let record = try await runtime.createContainer(ContainerRecord(name: "historical", image: "debian"))
        let stream = await runtime.events(since: Date().addingTimeInterval(-60), until: Date())
        var iterator = stream.makeAsyncIterator()
        #expect(await iterator.next()?.id == record.id)
        #expect(await iterator.next() == nil)
    }

    @Test func systemDiskUsageAndMountOptionsUseDockerSchemas() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        _ = await router.route(.init(
            method: .POST, uri: "/v1.55/volumes/create",
            body: Data(#"{"Name":"schema-volume"}"#.utf8)
        ))
        let create = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=mount-schema",
            body: Data(#"{"Image":"debian","HostConfig":{"Mounts":[{"Type":"volume","Source":"schema-volume","Target":"/data","VolumeOptions":{"NoCopy":true,"Subpath":"nested"}},{"Type":"tmpfs","Target":"/run/cache","TmpfsOptions":{"SizeBytes":1048576,"Mode":448}}]}}"#.utf8)
        ))
        #expect(create.status == .created)
        let inspect = await router.route(.init(method: .GET, uri: "/v1.55/containers/mount-schema/json"))
        let inspectJSON = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        let host = try #require(inspectJSON["HostConfig"] as? [String: Any])
        let mounts = try #require(host["Mounts"] as? [[String: Any]])
        #expect((mounts[0]["VolumeOptions"] as? [String: Any])?["Subpath"] as? String == "nested")
        #expect((mounts[1]["TmpfsOptions"] as? [String: Any])?["SizeBytes"] as? Int == 1_048_576)

        let usage = await router.route(.init(method: .GET, uri: "/v1.55/system/df?verbose=true"))
        #expect(usage.status == .ok)
        let usageJSON = try #require(JSONSerialization.jsonObject(with: usage.body) as? [String: Any])
        #expect((usageJSON["Containers"] as? [[String: Any]])?.count == 1)
        #expect((usageJSON["Volumes"] as? [[String: Any]])?.count == 1)
        #expect((usageJSON["BuildCache"] as? [[String: Any]])?.isEmpty == true)
    }

    @Test func statsTopUpdateAndPruneUseDockerSchemas() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root, backend: CompletionBackend(completionEnabled: false))
        let router = DockerRouter(runtime: runtime, root: root)
        let record = try await runtime.createContainer(ContainerRecord(name: "observed", image: "debian"))
        try await runtime.startContainer(record.id)
        let stats = await router.route(.init(method: .GET, uri: "/v1.44/containers/observed/stats?stream=false"))
        #expect(stats.status == .ok)
        let statsJSON = try #require(JSONSerialization.jsonObject(with: stats.body) as? [String: Any])
        #expect((statsJSON["memory_stats"] as? [String: Any])?["usage"] as? Int == 1_024)
        let top = await router.route(.init(method: .GET, uri: "/v1.44/containers/observed/top?ps_args=-ef"))
        let topJSON = try #require(JSONSerialization.jsonObject(with: top.body) as? [String: Any])
        #expect(topJSON["Titles"] as? [String] == ["PID", "CMD"])
        let update = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/observed/update",
            body: Data(#"{"Memory":8192,"NanoCpus":2000000000,"RestartPolicy":{"Name":"always"}}"#.utf8)
        ))
        #expect(update.status == .ok)
        let updated = try await runtime.container(record.id)
        #expect(updated.memoryBytes == 8_192)
        #expect(updated.cpus == 2)
        #expect(updated.restartPolicy.name == "always")

        try await runtime.stopContainer(record.id, timeoutSeconds: 0)
        let prune = await router.route(.init(method: .POST, uri: "/v1.44/containers/prune", body: Data(#"{"filters":{}}"#.utf8)))
        #expect(prune.status == .ok)
        let pruneJSON = try #require(JSONSerialization.jsonObject(with: prune.body) as? [String: Any])
        #expect((pruneJSON["ContainersDeleted"] as? [String])?.contains(record.id) == true)
    }

    @Test func healthcheckTransitionsContainerToHealthy() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root, backend: CompletionBackend(completionEnabled: false))
        let router = DockerRouter(runtime: runtime, root: root)
        let create = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=healthy",
            body: Data(#"{"Image":"debian","Healthcheck":{"Test":["CMD","true"],"Interval":100000000,"Timeout":1000000000,"Retries":2}}"#.utf8)
        ))
        let created = try #require(JSONSerialization.jsonObject(with: create.body) as? [String: Any])
        let id = try #require(created["Id"] as? String)
        try await runtime.startContainer(id)
        for _ in 0..<50 {
            if try await runtime.container(id).healthStatus == "healthy" { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(try await runtime.container(id).healthStatus == "healthy")
        let inspect = await router.route(.init(method: .GET, uri: "/v1.44/containers/healthy/json"))
        let json = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        let state = try #require(json["State"] as? [String: Any])
        #expect((state["Health"] as? [String: Any])?["Status"] as? String == "healthy")
    }

    @Test func anonymousVolumeIsCreatedAndRemovedWithContainer() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let create = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=anonymous-volume",
            body: Data(#"{"Image":"debian","Mounts":[{"Type":"volume","Target":"/data"}]}"#.utf8)
        ))
        #expect(create.status == .created)
        let volumes = await router.route(.init(method: .GET, uri: "/v1.44/volumes"))
        let envelope = try #require(JSONSerialization.jsonObject(with: volumes.body) as? [String: Any])
        #expect((envelope["Volumes"] as? [[String: Any]])?.count == 1)
        let remove = await router.route(.init(method: .DELETE, uri: "/v1.44/containers/anonymous-volume?v=1"))
        #expect(remove.status == .noContent)
        let after = await router.route(.init(method: .GET, uri: "/v1.44/volumes"))
        let afterEnvelope = try #require(JSONSerialization.jsonObject(with: after.body) as? [String: Any])
        #expect((afterEnvelope["Volumes"] as? [[String: Any]])?.isEmpty == true)
    }

    @Test func restartPolicyHandlesProcessAndDaemonFailure() async throws {
        let processRoot = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: processRoot) }
        let processBackend = RestartBackend(exitCode: 9)
        let runtime = try await EngineRuntime(root: processRoot, backend: processBackend)
        var record = ContainerRecord(name: "process-restart", image: "debian")
        record.restartPolicy = .init(name: "on-failure", maximumRetryCount: 1)
        record = try await runtime.createContainer(record)
        try await runtime.startContainer(record.id)
        for _ in 0..<100 {
            if try await runtime.container(record.id).restartCount == 1 { break }
            await Task.yield()
        }
        #expect(try await runtime.container(record.id).phase == .running)
        #expect(try await runtime.container(record.id).restartCount == 1)
        #expect(await processBackend.startCount() == 2)

        let daemonRoot = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: daemonRoot) }
        let firstBackend = RestartBackend()
        let first = try await EngineRuntime(root: daemonRoot, backend: firstBackend)
        var daemonRecord = ContainerRecord(name: "daemon-restart", image: "debian")
        daemonRecord.restartPolicy = .init(name: "always")
        daemonRecord = try await first.createContainer(daemonRecord)
        try await first.startContainer(daemonRecord.id)
        let recoveredBackend = RestartBackend()
        let recovered = try await EngineRuntime(root: daemonRoot, backend: recoveredBackend)
        #expect(try await recovered.container(daemonRecord.id).phase == .running)
        #expect(try await recovered.container(daemonRecord.id).restartCount == 1)
        #expect(await recoveredBackend.startCount() == 1)
    }

    @Test func registryAuthProgressAndImageHistoryAreForwarded() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = AuthImageBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let router = DockerRouter(runtime: runtime, root: root)
        let auth = Data(#"{"username":"alice","password":"secret"}"#.utf8).base64EncodedString()
        let pull = await router.route(.init(
            method: .POST, uri: "/v1.44/images/create?fromImage=registry.example%2Fteam%2Fapp&tag=latest",
            headers: ["X-Registry-Auth": auth]
        ))
        #expect(pull.status == .ok)
        #expect(await backend.username() == "alice")
        let output = String(decoding: pull.body, as: UTF8.self)
        #expect(output.contains(#""current":50"#))
        #expect(output.contains(#""total":100"#))
        let history = await router.route(.init(
            method: .GET, uri: "/v1.44/images/registry.example%2Fteam%2Fapp:latest/history"
        ))
        #expect(history.status == .ok)
        let entries = try #require(JSONSerialization.jsonObject(with: history.body) as? [[String: Any]])
        #expect(entries.first?["CreatedBy"] as? String == "RUN true")
    }
}

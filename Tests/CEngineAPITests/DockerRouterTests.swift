@testable import CEngineAPI
import CEngineCore
@testable import CEngineRuntime
import Foundation
import NIOHTTP1
import Testing
import Virtualization

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
        [
            BackendImage(
                id: "sha256:0123456789abcdef",
                reference: "docker.io/example/imported:latest",
                size: 123,
                architecture: "arm64",
                os: "linux"
            ),
            BackendImage(
                id: "sha256:0123456789abcdef",
                reference: "docker.io/library/imported-descriptor:latest",
                size: 123,
                architecture: "arm64",
                os: "linux"
            ),
        ]
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

private actor BlockingPrepareBackend: ContainerBackend {
    private var continuations: [CheckedContinuation<Void, Never>] = []
    private var prepares = 0

    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {
        prepares += 1
        await withCheckedContinuation { continuations.append($0) }
    }
    func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_: ContainerRecord) async throws {}
    func prepareCount() -> Int { prepares }
    func releasePreparations() {
        let pending = continuations
        continuations.removeAll()
        pending.forEach { $0.resume() }
    }
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
    func prepare(_ container: ContainerRecord) async throws {
        let reference = ImageReference.normalized(container.image)
        if !references.contains(reference) { references.append(reference) }
    }
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

private func multiPlatformBackendImage() -> BackendImage {
    let root = OCIDescriptor(
        mediaType: "application/vnd.oci.image.index.v1+json",
        digest: "sha256:" + String(repeating: "1", count: 64),
        size: 600
    )
    let arm = OCIDescriptor(
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        digest: "sha256:" + String(repeating: "2", count: 64),
        size: 200,
        platform: .init(architecture: "arm64", os: "linux")
    )
    let amd = OCIDescriptor(
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        digest: "sha256:" + String(repeating: "3", count: 64),
        size: 220,
        platform: .init(architecture: "amd64", os: "linux")
    )
    let attestation = OCIDescriptor(
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        digest: "sha256:" + String(repeating: "4", count: 64),
        size: 100,
        platform: .init(architecture: "unknown", os: "unknown"),
        artifactType: "application/vnd.docker.attestation.manifest.v1+json"
    )
    let armImageID = "sha256:" + String(repeating: "a", count: 64)
    let amdImageID = "sha256:" + String(repeating: "b", count: 64)
    return BackendImage(
        id: armImageID,
        reference: "docker.io/library/example:multi",
        createdAt: Date(timeIntervalSince1970: 1_700_000_000),
        size: 420,
        architecture: "arm64",
        os: "linux",
        targetDescriptor: root,
        manifests: [
            .init(
                descriptor: arm,
                imageID: armImageID,
                available: true,
                kind: .image,
                platform: arm.platform,
                createdAt: Date(timeIntervalSince1970: 1_700_000_001),
                contentSize: 200,
                configuration: .init(environment: ["ARCH=arm64"], rootFSDiffIDs: ["sha256:arm-layer"])
            ),
            .init(
                descriptor: amd,
                imageID: amdImageID,
                available: true,
                kind: .image,
                platform: amd.platform,
                createdAt: Date(timeIntervalSince1970: 1_700_000_002),
                contentSize: 220,
                configuration: .init(environment: ["ARCH=amd64"], rootFSDiffIDs: ["sha256:amd-layer"])
            ),
            .init(
                descriptor: attestation,
                available: true,
                kind: .attestation,
                platform: attestation.platform,
                contentSize: 100,
                attestationFor: arm.digest
            ),
        ],
        preferredManifestDigest: arm.digest,
        identity: .init(pullRepositories: ["docker.io/library/example"])
    )
}

private actor MultiPlatformImageBackend: ContainerBackend {
    private var savedPlatforms: [OCIPlatform] = []
    private var loadedPlatforms: [OCIPlatform] = []
    private var deletedPlatforms: [OCIPlatform] = []
    private var pushedPlatform: OCIPlatform?
    private var attestationPlatform: OCIPlatform?
    private var attestationTypes: [String] = []
    private var includedStatement = false

    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {}
    func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_: ContainerRecord) async throws {}
    func listImages() async throws -> [BackendImage]? { [multiPlatformBackendImage()] }
    func deleteImage(reference _: String) async throws {}
    func deleteImage(reference _: String, platforms: [OCIPlatform]) async throws -> [String] {
        deletedPlatforms = platforms
        let image = multiPlatformBackendImage()
        return platforms.compactMap { platform in
            image.manifests.first { $0.kind == .image && $0.platform?.matches(platform) == true }?.descriptor.digest
        }
    }
    func loadImages(fromOCILayout _: URL, platforms: [OCIPlatform]) async throws -> [BackendImage] {
        loadedPlatforms = platforms
        return [multiPlatformBackendImage()]
    }
    func saveImages(references _: [String], platforms: [OCIPlatform]) async throws -> Data {
        savedPlatforms = platforms
        return Data("archive".utf8)
    }
    func pushImage(reference _: String, platform: OCIPlatform?, credentials _: RegistryCredentials?) async throws {
        pushedPlatform = platform
    }
    func imageHistory(reference _: String, platform _: OCIPlatform?) async throws -> [ImageHistoryEntry] { [] }
    func imageAttestations(reference _: String, platform: OCIPlatform?, predicateTypes: [String], includeStatement: Bool) async throws -> [ImageAttestationRecord] {
        attestationPlatform = platform
        attestationTypes = predicateTypes
        includedStatement = includeStatement
        return [.init(
            descriptor: OCIDescriptor(
                mediaType: "application/vnd.in-toto+json",
                digest: "sha256:" + String(repeating: "5", count: 64),
                size: 20
            ),
            predicateType: "https://spdx.dev/Document",
            statement: includeStatement ? Data(#"{"predicateType":"https://spdx.dev/Document"}"#.utf8) : nil
        )]
    }

    func selections() -> (
        saved: [OCIPlatform], loaded: [OCIPlatform], deleted: [OCIPlatform], pushed: OCIPlatform?,
        attestation: OCIPlatform?, types: [String], statement: Bool
    ) {
        (savedPlatforms, loadedPlatforms, deletedPlatforms, pushedPlatform,
         attestationPlatform, attestationTypes, includedStatement)
    }
}

private actor RestartBackend: ContainerBackend {
    private var exitCode: Int32?
    private var starts = 0
    private var prepares = 0
    private var deletes = 0
    private var preparedContainers = Set<String>()
    private var resourceUpdates: [ContainerRecord] = []
    init(exitCode: Int32? = nil) { self.exitCode = exitCode }
    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_ container: ContainerRecord) async throws {
        if preparedContainers.insert(container.id).inserted { prepares += 1 }
    }
    func start(_ container: ContainerRecord) async throws -> [PortBinding] {
        guard preparedContainers.contains(container.id) else {
            throw EngineError(.notFound, "container VM shim is unavailable")
        }
        starts += 1
        return container.ports
    }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_ container: ContainerRecord) async throws {
        preparedContainers.remove(container.id)
        deletes += 1
    }
    func completion(_: ContainerRecord) async -> Int32? { defer { exitCode = nil }; return exitCode }
    func updateResources(_ container: ContainerRecord) async throws { resourceUpdates.append(container) }
    func startCount() -> Int { starts }
    func prepareCount() -> Int { prepares }
    func deleteCount() -> Int { deletes }
    func lastResourceUpdate() -> ContainerRecord? { resourceUpdates.last }
}

private actor LifecycleRaceBackend: ContainerBackend {
    private var completionContinuation: CheckedContinuation<Int32?, Never>?
    private var stopContinuation: CheckedContinuation<Void, Never>?
    private var stopIsBlocked = false
    private var starts = 0
    private var prepares = 0
    private var deletes = 0

    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws { prepares += 1 }
    func start(_ container: ContainerRecord) async throws -> [PortBinding] {
        starts += 1
        return container.ports
    }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 {
        completionContinuation?.resume(returning: 0)
        completionContinuation = nil
        stopIsBlocked = true
        await withCheckedContinuation { stopContinuation = $0 }
        stopIsBlocked = false
        return 0
    }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_: ContainerRecord) async throws { deletes += 1 }
    func completion(_: ContainerRecord) async -> Int32? {
        await withCheckedContinuation { completionContinuation = $0 }
    }
    func isWaitingForCompletion() -> Bool { completionContinuation != nil }
    func isStopBlocked() -> Bool { stopIsBlocked }
    func releaseStop() { stopContinuation?.resume(); stopContinuation = nil }
    func counts() -> (prepares: Int, starts: Int, deletes: Int) { (prepares, starts, deletes) }
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

    private func fixture(snapshot: EngineSnapshot) async throws -> (DockerRouter, URL) {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let store = AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json"))
        try await store.save(snapshot)
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

    @Test func imageEventFiltersMatchDockerImageSelectors() {
        let event = RuntimeEvent(
            type: "image",
            action: "pull",
            id: "alpine:latest",
            attributes: ["name": "alpine"]
        )
        #expect(DockerHTTPHandler.matches(event, filters: [
            "type": ["image"], "event": ["pull"], "image": ["alpine:latest"],
        ]))
        #expect(!DockerHTTPHandler.matches(event, filters: ["image": ["busybox:latest"]]))
    }

    @Test func containerEventImageFiltersMatchActorImageWithAndWithoutTag() {
        let event = RuntimeEvent(
            type: "container",
            action: "start",
            id: "container-id",
            attributes: ["name": "sample", "image": "docker.io/library/alpine:latest"]
        )
        #expect(DockerHTTPHandler.matches(event, filters: ["image": ["alpine:latest"]]))
        #expect(DockerHTTPHandler.matches(event, filters: ["image": ["alpine"]]))
        #expect(DockerHTTPHandler.matches(event, filters: ["image": ["docker.io/library/alpine:latest"]]))
        #expect(!DockerHTTPHandler.matches(event, filters: ["image": ["alpine:edge"]]))
        #expect(!DockerHTTPHandler.matches(event, filters: ["image": ["busybox"]]))
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

    @Test func infoCountsImagesAndVersionsOptionalEngineDetails() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        _ = await router.route(.init(
            method: .POST,
            uri: "/v1.55/images/create?fromImage=alpine&tag=latest"
        ))
        let info = await router.route(.init(method: .GET, uri: "/v1.55/info"))
        let current = try #require(JSONSerialization.jsonObject(with: info.body) as? [String: Any])
        #expect(current["Images"] as? Int == 1)
        #expect((current["DiscoveredDevices"] as? [[String: Any]])?.isEmpty == true)
        #expect(current["Containerd"] == nil)
        #expect(current["FirewallBackend"] == nil)
        #expect(current["NRI"] == nil)

        let containerd = DockerInfoResponse.ContainerdInfo(
            Address: "/run/containerd.sock",
            Namespaces: .init(Containers: "moby", Plugins: "plugins.moby")
        )
        let firewall = DockerInfoResponse.FirewallInfo(Driver: "nftables", Info: [])
        let devices = [DockerInfoResponse.DeviceInfo(Source: "cdi", ID: "vendor.example/device=one")]
        let nri = DockerInfoResponse.NRIInfo(Info: [["Enabled", "true"]])
        func encoded(_ minor: Int) throws -> [String: Any] {
            let response = DockerInfoResponse(
                Containers: 0, ContainersRunning: 0, ContainersPaused: 0, ContainersStopped: 0,
                Images: 0, DockerRootDir: root.path, version: .init(major: 1, minor: minor),
                containerd: containerd, firewallBackend: firewall, discoveredDevices: devices, nri: nri
            )
            return try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(response)) as? [String: Any])
        }
        #expect(try encoded(45)["Containerd"] == nil)
        #expect(try encoded(46)["Containerd"] != nil)
        #expect(try encoded(48)["FirewallBackend"] == nil)
        #expect(try encoded(49)["FirewallBackend"] != nil)
        #expect(try encoded(49)["DiscoveredDevices"] == nil)
        #expect(try encoded(50)["DiscoveredDevices"] != nil)
        #expect(try encoded(52)["NRI"] == nil)
        #expect(try encoded(53)["NRI"] != nil)
    }

    @Test func containerAnnotationsPersistAndListFromAPI146() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        var runtime: EngineRuntime? = try await EngineRuntime(root: root)
        var router: DockerRouter? = DockerRouter(runtime: try #require(runtime), root: root)
        let create = try await #require(router).route(.init(
            method: .POST,
            uri: "/v1.44/containers/create?name=annotated",
            body: Data(#"{"Image":"alpine","HostConfig":{"Annotations":{"io.example.owner":"api"}}}"#.utf8)
        ))
        #expect(create.status == .created)

        let legacyList = try await #require(router).route(.init(method: .GET, uri: "/v1.45/containers/json?all=true"))
        let legacy = try #require((JSONSerialization.jsonObject(with: legacyList.body) as? [[String: Any]])?.first)
        #expect((legacy["HostConfig"] as? [String: Any])?["Annotations"] == nil)

        let currentList = try await #require(router).route(.init(method: .GET, uri: "/v1.46/containers/json?all=true"))
        let current = try #require((JSONSerialization.jsonObject(with: currentList.body) as? [[String: Any]])?.first)
        #expect((current["HostConfig"] as? [String: Any])?["Annotations"] as? [String: String] == [
            "io.example.owner": "api",
        ])

        router = nil
        runtime = nil
        let restoredRuntime = try await EngineRuntime(root: root)
        let restoredRouter = DockerRouter(runtime: restoredRuntime, root: root)
        let inspect = await restoredRouter.route(.init(method: .GET, uri: "/v1.55/containers/annotated/json"))
        let inspected = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        #expect((inspected["HostConfig"] as? [String: Any])?["Annotations"] as? [String: String] == [
            "io.example.owner": "api",
        ])
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

    @Test func scopedCreateResourcesOverrideOnlySpecifiedFields() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try ContainerSettings(cpus: 3, memoryGiB: 3).save(
            to: root.appending(path: ContainerSettings.fileName)
        )
        let runtime = try await EngineRuntime(root: root)
        let cpuRouter = DockerRouter(
            runtime: runtime,
            root: root,
            containerResourceOverride: .init(cpus: 2)
        )

        let explicit = await cpuRouter.route(.init(
            method: .POST,
            uri: "/v1.44/containers/create?name=scoped-explicit",
            body: Data(#"{"Image":"alpine","HostConfig":{"Memory":1073741824,"NanoCpus":1000000000}}"#.utf8)
        ))
        let explicitBody = try #require(JSONSerialization.jsonObject(with: explicit.body) as? [String: Any])
        let explicitID = try #require(explicitBody["Id"] as? String)
        let explicitInspect = await cpuRouter.route(.init(method: .GET, uri: "/v1.44/containers/\(explicitID)/json"))
        let explicitObject = try #require(JSONSerialization.jsonObject(with: explicitInspect.body) as? [String: Any])
        let explicitHost = try #require(explicitObject["HostConfig"] as? [String: Any])
        #expect(explicitHost["Memory"] as? Int == 1_073_741_824)
        #expect(explicitHost["NanoCpus"] as? Int == 2_000_000_000)

        let memoryRouter = DockerRouter(
            runtime: runtime,
            root: root,
            containerResourceOverride: .init(memoryGiB: 2)
        )
        let defaults = await memoryRouter.route(.init(
            method: .POST,
            uri: "/v1.44/containers/create?name=scoped-default",
            body: Data(#"{"Image":"alpine"}"#.utf8)
        ))
        let defaultsBody = try #require(JSONSerialization.jsonObject(with: defaults.body) as? [String: Any])
        let defaultsID = try #require(defaultsBody["Id"] as? String)
        let defaultsInspect = await memoryRouter.route(.init(method: .GET, uri: "/v1.44/containers/\(defaultsID)/json"))
        let defaultsObject = try #require(JSONSerialization.jsonObject(with: defaultsInspect.body) as? [String: Any])
        let defaultsHost = try #require(defaultsObject["HostConfig"] as? [String: Any])
        #expect(defaultsHost["Memory"] as? Int == 2_147_483_648)
        #expect(defaultsHost["NanoCpus"] as? Int == 3_000_000_000)
    }

    @Test func resourceScopeSocketFollowsOwnerProcessLifetime() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let sockets = URL(filePath: "/tmp/cengine-scope-test-\(UUID().uuidString)", directoryHint: .isDirectory)
        defer {
            try? FileManager.default.removeItem(at: root)
            try? FileManager.default.removeItem(at: sockets)
        }
        let runtime = try await EngineRuntime(root: root)
        let manager = ContainerResourceScopeManager(runtime: runtime, root: root, socketDirectory: sockets)
        let owner = Process()
        owner.executableURL = URL(filePath: "/bin/sleep")
        owner.arguments = ["30"]
        try owner.run()

        do {
            let scope = try await manager.create(
                ownerPID: owner.processIdentifier,
                resources: .init(cpus: 1, memoryGiB: 1)
            )
            let path = String(scope.dockerHost.dropFirst("unix://".count))
            #expect(FileManager.default.fileExists(atPath: path))

            owner.terminate()
            owner.waitUntilExit()
            for _ in 0..<100 where FileManager.default.fileExists(atPath: path) {
                try await Task.sleep(for: .milliseconds(10))
            }
            #expect(!FileManager.default.fileExists(atPath: path))
            try await manager.shutdown()
        } catch {
            if owner.isRunning { owner.terminate() }
            try? await manager.shutdown()
            throw error
        }
    }

    @Test func resourceScopeControlEndpointCreatesAndDeletesSocket() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let sockets = URL(filePath: "/tmp/cengine-scope-api-test-\(UUID().uuidString)", directoryHint: .isDirectory)
        defer {
            try? FileManager.default.removeItem(at: root)
            try? FileManager.default.removeItem(at: sockets)
        }
        let runtime = try await EngineRuntime(root: root)
        let manager = ContainerResourceScopeManager(runtime: runtime, root: root, socketDirectory: sockets)
        let router = DockerRouter(runtime: runtime, root: root, resourceScopeManager: manager)

        do {
            let invalid = await router.route(.init(
                method: .POST,
                uri: "/_cengine/v1/resource-scopes",
                body: try JSONEncoder().encode(ContainerResourceScopeCreateRequest(ownerPID: getpid()))
            ))
            #expect(invalid.status == .badRequest)

            let created = await router.route(.init(
                method: .POST,
                uri: "/_cengine/v1/resource-scopes",
                body: try JSONEncoder().encode(ContainerResourceScopeCreateRequest(
                    ownerPID: getpid(), cpus: 1, memoryGiB: 1
                ))
            ))
            #expect(created.status == .created)
            let scope = try JSONDecoder().decode(ContainerResourceScope.self, from: created.body)
            let path = String(scope.dockerHost.dropFirst("unix://".count))
            #expect(FileManager.default.fileExists(atPath: path))

            let deleted = await router.route(.init(
                method: .DELETE,
                uri: "/_cengine/v1/resource-scopes/\(scope.id)"
            ))
            #expect(deleted.status == .noContent)
            #expect(!FileManager.default.fileExists(atPath: path))
            try await manager.shutdown()
        } catch {
            try? await manager.shutdown()
            throw error
        }
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

        let volumeCreate = await router.route(.init(method: .POST, uri: "/v1.44/volumes/create", body: Data(#"{"Name":"dbdata","Driver":"local","Labels":{"app":"demo"}}"#.utf8)))
        #expect(volumeCreate.status == .created)
        let createdVolume = try #require(JSONSerialization.jsonObject(with: volumeCreate.body) as? [String: Any])
        #expect(createdVolume["Name"] as? String == "dbdata")
        #expect(createdVolume["Driver"] as? String == "local")
        let volumeInspect = await router.route(.init(method: .GET, uri: "/v1.44/volumes/dbdata", body: Data()))
        #expect(volumeInspect.status == .ok)
        let unsupported = await router.route(.init(
            method: .POST,
            uri: "/v1.44/volumes/create",
            body: Data(#"{"Name":"remote","Driver":"third-party"}"#.utf8)
        ))
        #expect(unsupported.status == .notImplemented)
    }

    @Test func containerCreateRejectsUnsupportedVolumeDriversFromDockerFields() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let bodies = [
            #"{"Image":"alpine","Volumes":{"/legacy":{}},"HostConfig":{"VolumeDriver":"third-party"}}"#,
            #"{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"volume","Target":"/data","VolumeOptions":{"DriverConfig":{"Name":"third-party","Options":{"remote":"true"}}}}]}}"#,
        ]
        for body in bodies {
            let response = await router.route(.init(
                method: .POST,
                uri: "/v1.55/containers/create",
                body: Data(body.utf8)
            ))
            #expect(response.status == .notImplemented)
        }
        let volumes = await router.route(.init(method: .GET, uri: "/v1.55/volumes"))
        let volumeList = try #require(JSONSerialization.jsonObject(with: volumes.body) as? [String: Any])
        #expect((volumeList["Volumes"] as? [[String: Any]])?.isEmpty == true)
    }

    @Test func imagePruneDefaultsToUnusedDanglingAndCanExplicitlyWiden() async throws {
        let tagged = ImageRecord(
            id: "sha256:tagged", references: ["docker.io/library/keep:latest"], createdAt: Date(),
            size: 20, architecture: "arm64", os: "linux"
        )
        let dangling = ImageRecord(
            id: "sha256:dangling", references: [], createdAt: Date(), size: 10,
            architecture: "arm64", os: "linux"
        )
        let usedDangling = ImageRecord(
            id: "sha256:used", references: [], createdAt: Date(), size: 30,
            architecture: "arm64", os: "linux"
        )
        var container = ContainerRecord(name: "uses-dangling", image: usedDangling.id)
        container.imageID = usedDangling.id
        let (router, root) = try await fixture(snapshot: .init(
            containers: [container], images: [tagged, dangling, usedDangling]
        ))
        defer { try? FileManager.default.removeItem(at: root) }

        let defaultPrune = await router.route(.init(method: .POST, uri: "/v1.55/images/prune"))
        #expect(defaultPrune.status == .ok)
        let defaultJSON = try #require(JSONSerialization.jsonObject(with: defaultPrune.body) as? [String: Any])
        let defaultDeleted = try #require(defaultJSON["ImagesDeleted"] as? [[String: String]])
        #expect(defaultDeleted.map { $0["Deleted"] }.contains(dangling.id))
        #expect(!defaultDeleted.map { $0["Deleted"] }.contains(tagged.id))
        #expect(!defaultDeleted.map { $0["Deleted"] }.contains(usedDangling.id))

        let widePrune = await router.route(.init(
            method: .POST,
            uri: "/v1.55/images/prune?filters=%7B%22dangling%22:%7B%22false%22:true%7D%7D"
        ))
        #expect(widePrune.status == .ok)
        let wideJSON = try #require(JSONSerialization.jsonObject(with: widePrune.body) as? [String: Any])
        let wideDeleted = try #require(wideJSON["ImagesDeleted"] as? [[String: String]])
        #expect(wideDeleted.map { $0["Deleted"] }.contains(tagged.id))
        #expect(!wideDeleted.map { $0["Deleted"] }.contains(usedDangling.id))
    }

    @Test func volumePruneDefaultsToUnusedAnonymousAndCanExplicitlyWiden() async throws {
        let named = VolumeRecord(name: "keep-named", sizeBytes: 1, anonymous: false)
        let anonymous = VolumeRecord(name: "remove-anonymous", sizeBytes: 1, anonymous: true)
        let usedAnonymous = VolumeRecord(name: "keep-used", sizeBytes: 1, anonymous: true)
        var container = ContainerRecord(name: "uses-volume", image: "alpine")
        container.mounts = [.init(kind: .volume, source: usedAnonymous.name, destination: "/data")]
        let (router, root) = try await fixture(snapshot: .init(
            containers: [container], volumes: [named, anonymous, usedAnonymous]
        ))
        defer { try? FileManager.default.removeItem(at: root) }

        let defaultPrune = await router.route(.init(method: .POST, uri: "/v1.44/volumes/prune"))
        #expect(defaultPrune.status == .ok)
        let defaultJSON = try #require(JSONSerialization.jsonObject(with: defaultPrune.body) as? [String: Any])
        #expect(defaultJSON["VolumesDeleted"] as? [String] == [anonymous.name])

        let widePrune = await router.route(.init(
            method: .POST,
            uri: "/v1.44/volumes/prune?filters=%7B%22all%22:%5B%22true%22%5D%7D"
        ))
        #expect(widePrune.status == .ok)
        let wideJSON = try #require(JSONSerialization.jsonObject(with: widePrune.body) as? [String: Any])
        #expect(wideJSON["VolumesDeleted"] as? [String] == [named.name])
    }

    @Test func imageAndVolumePruneRejectUnsupportedActiveFilters() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        _ = await router.route(.init(
            method: .POST,
            uri: "/v1.55/images/create?fromImage=alpine&tag=latest"
        ))
        _ = await router.route(.init(
            method: .POST,
            uri: "/v1.55/volumes/create",
            body: Data(#"{"Name":"keep-me","Labels":{"retain":"true"}}"#.utf8)
        ))

        let imagePrune = await router.route(.init(
            method: .POST,
            uri: "/v1.55/images/prune?filters=%7B%22label%22:%5B%22retain=true%22%5D%7D"
        ))
        let volumePrune = await router.route(.init(
            method: .POST,
            uri: "/v1.55/volumes/prune?filters=%7B%22label%22:%5B%22retain=true%22%5D%7D"
        ))
        #expect(imagePrune.status == .notImplemented)
        #expect(volumePrune.status == .notImplemented)

        let inactiveImageFilter = await router.route(.init(
            method: .POST,
            uri: "/v1.55/images/prune?filters=%7B%22label%22:%5B%5D%7D"
        ))
        let inactiveVolumeFilter = await router.route(.init(
            method: .POST,
            uri: "/v1.55/volumes/prune?filters=%7B%22label%22:%7B%22retain=true%22:false%7D%7D"
        ))
        #expect(inactiveImageFilter.status == .ok)
        #expect(inactiveVolumeFilter.status == .ok)

        let images = await router.route(.init(method: .GET, uri: "/v1.55/images/json"))
        let volumes = await router.route(.init(method: .GET, uri: "/v1.55/volumes"))
        #expect((try #require(JSONSerialization.jsonObject(with: images.body) as? [[String: Any]])).count == 1)
        let volumeList = try #require(JSONSerialization.jsonObject(with: volumes.body) as? [String: Any])
        #expect((volumeList["Volumes"] as? [[String: Any]])?.contains { $0["Name"] as? String == "keep-me" } == true)
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

    @Test func explicitEndpointMacIsAcceptedNormalizedAndReturnedByInspect() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        _ = await router.route(.init(
            method: .POST, uri: "/v1.55/networks/create", body: Data(#"{"Name":"macnet"}"#.utf8)
        ))
        let create = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=explicit-mac",
            body: Data(#"{"Image":"debian","NetworkingConfig":{"EndpointsConfig":{"macnet":{"MacAddress":"02:42:AC:11:00:02"}}}}"#.utf8)
        ))
        #expect(create.status == .created)
        let inspect = await router.route(.init(method: .GET, uri: "/v1.55/containers/explicit-mac/json"))
        let object = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        let settings = try #require(object["NetworkSettings"] as? [String: Any])
        let networks = try #require(settings["Networks"] as? [String: Any])
        let endpoint = try #require(networks["macnet"] as? [String: Any])
        #expect(endpoint["MacAddress"] as? String == "02:42:ac:11:00:02")
    }

    @Test func connectEndpointMacIsAcceptedAndReturnedByInspect() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        _ = await router.route(.init(
            method: .POST, uri: "/v1.55/networks/create", body: Data(#"{"Name":"macnet"}"#.utf8)
        ))
        let create = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=connect-mac", body: Data(#"{"Image":"debian"}"#.utf8)
        ))
        #expect(create.status == .created)
        let connect = await router.route(.init(
            method: .POST, uri: "/v1.55/networks/macnet/connect",
            body: Data(#"{"Container":"connect-mac","EndpointConfig":{"MacAddress":"02:42:ac:11:00:09"}}"#.utf8)
        ))
        #expect(connect.status == .ok)
        let inspect = await router.route(.init(method: .GET, uri: "/v1.55/containers/connect-mac/json"))
        let object = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        let settings = try #require(object["NetworkSettings"] as? [String: Any])
        let networks = try #require(settings["Networks"] as? [String: Any])
        let endpoint = try #require(networks["macnet"] as? [String: Any])
        #expect(endpoint["MacAddress"] as? String == "02:42:ac:11:00:09")
    }

    @Test func endpointWithoutExplicitMacReportsDeterministicGeneratedMac() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let create = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=auto-mac", body: Data(#"{"Image":"debian"}"#.utf8)
        ))
        #expect(create.status == .created)
        let inspect = await router.route(.init(method: .GET, uri: "/v1.55/containers/auto-mac/json"))
        let object = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        let settings = try #require(object["NetworkSettings"] as? [String: Any])
        let networks = try #require(settings["Networks"] as? [String: Any])
        let endpoint = try #require(networks["default"] as? [String: Any])
        let mac = try #require(endpoint["MacAddress"] as? String)
        #expect(!mac.isEmpty)
        #expect(mac.hasPrefix("02:ce:"))
        // Inspecting again yields the same generated MAC.
        let again = await router.route(.init(method: .GET, uri: "/v1.55/containers/auto-mac/json"))
        let againObject = try #require(JSONSerialization.jsonObject(with: again.body) as? [String: Any])
        let againNetworks = try #require((againObject["NetworkSettings"] as? [String: Any])?["Networks"] as? [String: Any])
        let againEndpoint = try #require(againNetworks["default"] as? [String: Any])
        #expect(againEndpoint["MacAddress"] as? String == mac)
    }

    @Test func invalidAndDuplicateEndpointMacsAreRejected() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        _ = await router.route(.init(
            method: .POST, uri: "/v1.55/networks/create", body: Data(#"{"Name":"macnet"}"#.utf8)
        ))
        let malformed = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=bad-mac",
            body: Data(#"{"Image":"debian","NetworkingConfig":{"EndpointsConfig":{"macnet":{"MacAddress":"nope"}}}}"#.utf8)
        ))
        #expect(malformed.status == .badRequest)
        let multicast = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=multicast-mac",
            body: Data(#"{"Image":"debian","NetworkingConfig":{"EndpointsConfig":{"macnet":{"MacAddress":"03:42:ac:11:00:02"}}}}"#.utf8)
        ))
        #expect(multicast.status == .badRequest)

        let first = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=dup-first",
            body: Data(#"{"Image":"debian","NetworkingConfig":{"EndpointsConfig":{"macnet":{"MacAddress":"02:42:ac:11:00:02"}}}}"#.utf8)
        ))
        #expect(first.status == .created)
        let duplicate = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=dup-second",
            body: Data(#"{"Image":"debian","NetworkingConfig":{"EndpointsConfig":{"macnet":{"MacAddress":"02:42:AC:11:00:02"}}}}"#.utf8)
        ))
        #expect(duplicate.status == .conflict)
    }

    @Test func explicitGatewayPriorityIsAcceptedAndReturnedByInspect() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        _ = await router.route(.init(
            method: .POST, uri: "/v1.55/networks/create", body: Data(#"{"Name":"prionet"}"#.utf8)
        ))
        let create = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=priority",
            body: Data(#"{"Image":"debian","NetworkingConfig":{"EndpointsConfig":{"prionet":{"GwPriority":75}}}}"#.utf8)
        ))
        #expect(create.status == .created)
        let inspect = await router.route(.init(method: .GET, uri: "/v1.55/containers/priority/json"))
        let object = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        let settings = try #require(object["NetworkSettings"] as? [String: Any])
        let networks = try #require(settings["Networks"] as? [String: Any])
        let endpoint = try #require(networks["prionet"] as? [String: Any])
        #expect(endpoint["GwPriority"] as? Int == 75)

        let legacyInspect = await router.route(.init(method: .GET, uri: "/v1.47/containers/priority/json"))
        let legacyObject = try #require(JSONSerialization.jsonObject(with: legacyInspect.body) as? [String: Any])
        let legacyNetworks = try #require((legacyObject["NetworkSettings"] as? [String: Any])?["Networks"] as? [String: Any])
        let legacyEndpoint = try #require(legacyNetworks["prionet"] as? [String: Any])
        #expect(legacyEndpoint["GwPriority"] == nil)
    }

    @Test func endpointWithoutExplicitGatewayPriorityReportsZero() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let create = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=default-priority", body: Data(#"{"Image":"debian"}"#.utf8)
        ))
        #expect(create.status == .created)
        let inspect = await router.route(.init(method: .GET, uri: "/v1.55/containers/default-priority/json"))
        let object = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        let networks = try #require((object["NetworkSettings"] as? [String: Any])?["Networks"] as? [String: Any])
        let endpoint = try #require(networks["default"] as? [String: Any])
        #expect(endpoint["GwPriority"] as? Int == 0)
    }

    @Test func connectGatewayPriorityIsAcceptedAndReturnedByInspect() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        _ = await router.route(.init(
            method: .POST, uri: "/v1.55/networks/create", body: Data(#"{"Name":"prionet"}"#.utf8)
        ))
        let create = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=connect-priority", body: Data(#"{"Image":"debian"}"#.utf8)
        ))
        #expect(create.status == .created)
        let connect = await router.route(.init(
            method: .POST, uri: "/v1.55/networks/prionet/connect",
            body: Data(#"{"Container":"connect-priority","EndpointConfig":{"GwPriority":-5}}"#.utf8)
        ))
        #expect(connect.status == .ok)
        let inspect = await router.route(.init(method: .GET, uri: "/v1.55/containers/connect-priority/json"))
        let object = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        let networks = try #require((object["NetworkSettings"] as? [String: Any])?["Networks"] as? [String: Any])
        let endpoint = try #require(networks["prionet"] as? [String: Any])
        #expect(endpoint["GwPriority"] as? Int == -5)
    }

    @Test func publishingSCTPPortIsRejected() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let create = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=sctp",
            body: Data(#"{"Image":"debian","HostConfig":{"PortBindings":{"132/sctp":[{"HostPort":"8080"}]}}}"#.utf8)
        ))
        #expect(create.status == .badRequest)
    }

    @Test func duplicateContainerNameWithSCTPPortStillReturnsConflict() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let first = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=same-name", body: Data(#"{"Image":"debian"}"#.utf8)
        ))
        #expect(first.status == .created)
        let duplicate = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=same-name",
            body: Data(#"{"Image":"debian","HostConfig":{"PortBindings":{"132/sctp":[{"HostPort":"8080"}]}}}"#.utf8)
        ))
        #expect(duplicate.status == .conflict)
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

    @Test func multiPlatformImageMetadataIsVersionedAndPlatformSelectable() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = MultiPlatformImageBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let router = DockerRouter(runtime: runtime, root: root)

        let legacy = await router.route(.init(
            method: .GET,
            uri: "/v1.46/images/json?manifests=true&identity=true"
        ))
        let legacyImage = try #require((JSONSerialization.jsonObject(with: legacy.body) as? [[String: Any]])?.first)
        #expect(legacyImage["Descriptor"] == nil)
        #expect(legacyImage["Manifests"] == nil)

        let manifestsOnly = await router.route(.init(
            method: .GET,
            uri: "/v1.47/images/json?manifests=true"
        ))
        let v147 = try #require((JSONSerialization.jsonObject(with: manifestsOnly.body) as? [[String: Any]])?.first)
        #expect(v147["Descriptor"] == nil)
        #expect((v147["Manifests"] as? [[String: Any]])?.count == 3)

        let identity = await router.route(.init(
            method: .GET,
            uri: "/v1.54/images/json?identity=true"
        ))
        let current = try #require((JSONSerialization.jsonObject(with: identity.body) as? [[String: Any]])?.first)
        #expect((current["Descriptor"] as? [String: Any])?["digest"] as? String
            == multiPlatformBackendImage().targetDescriptor?.digest)
        let manifests = try #require(current["Manifests"] as? [[String: Any]])
        let arm = try #require(manifests.first { ($0["ImageData"] as? [String: Any])?["Platform"] as? [String: String] == [
            "architecture": "arm64", "os": "linux",
        ] })
        let imageData = try #require(arm["ImageData"] as? [String: Any])
        let pull = try #require(((imageData["Identity"] as? [String: Any])?["Pull"] as? [[String: Any]])?.first)
        #expect(pull["Repository"] as? String == "docker.io/library/example")

        let platform = #"{"os":"linux","architecture":"amd64"}"#
            .addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        let inspect = await router.route(.init(
            method: .GET,
            uri: "/v1.55/images/example:multi/json?platform=\(platform)"
        ))
        #expect(inspect.status == .ok)
        let inspected = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        #expect(inspected["Architecture"] as? String == "amd64")
        #expect((inspected["Config"] as? [String: Any])?["Env"] as? [String] == ["ARCH=amd64"])
        #expect((inspected["RootFS"] as? [String: Any])?["Layers"] as? [String] == ["sha256:amd-layer"])
        #expect(((inspected["Identity"] as? [String: Any])?["Pull"] as? [[String: Any]])?.count == 1)

        let conflict = await router.route(.init(
            method: .GET,
            uri: "/v1.55/images/example:multi/json?manifests=true&platform=\(platform)"
        ))
        #expect(conflict.status == .badRequest)

        let create = await router.route(.init(
            method: .POST,
            uri: "/v1.55/containers/create?name=amd-container&platform=linux%2Famd64",
            body: Data(#"{"Image":"example:multi"}"#.utf8)
        ))
        #expect(create.status == .created)
        let containers = await router.route(.init(method: .GET, uri: "/v1.55/containers/json?all=true"))
        let container = try #require((JSONSerialization.jsonObject(with: containers.body) as? [[String: Any]])?.first)
        #expect(container["ImageID"] as? String == "sha256:" + String(repeating: "b", count: 64))
        #expect((container["ImageManifestDescriptor"] as? [String: Any])?["digest"] as? String
            == "sha256:" + String(repeating: "3", count: 64))
    }

    @Test func repeatedPlatformSelectorsDriveImageOperationsAndAttestations() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = MultiPlatformImageBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let router = DockerRouter(runtime: runtime, root: root)
        func encoded(_ architecture: String) -> String {
            #"{"os":"linux","architecture":"\#(architecture)"}"#
                .addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        }
        let arm = encoded("arm64")
        let amd = encoded("amd64")

        let save = await router.route(.init(
            method: .GET,
            uri: "/v1.52/images/example:multi/get?platform=\(arm)&platform=\(amd)"
        ))
        #expect(save.status == .ok)
        #expect(save.body == Data("archive".utf8))

        let archive = OCIArchive.tar(entries: [("placeholder", Data())])
        let load = await router.route(.init(
            method: .POST,
            uri: "/v1.52/images/load?platform=\(amd)&platform=\(arm)",
            body: archive
        ))
        #expect(load.status == .ok)

        let requiresForce = await router.route(.init(
            method: .DELETE,
            uri: "/v1.55/images/example:multi?platforms=\(arm)"
        ))
        #expect(requiresForce.status == .conflict)
        let remove = await router.route(.init(
            method: .DELETE,
            uri: "/v1.55/images/example:multi?force=true&platforms=\(arm)&platforms=\(amd)"
        ))
        #expect(remove.status == .ok)
        let removals = try #require(JSONSerialization.jsonObject(with: remove.body) as? [[String: Any]])
        #expect(removals.count == 2)

        let push = await router.route(.init(
            method: .POST,
            uri: "/v1.55/images/example:multi/push?platform=\(amd)"
        ))
        #expect(push.status == .ok)

        let attestations = await router.route(.init(
            method: .GET,
            uri: "/v1.55/images/example:multi/attestations?platform=\(arm)&type=https%3A%2F%2Fspdx.dev%2FDocument&type=https%3A%2F%2Fslsa.dev%2Fprovenance%2Fv1&statement=true"
        ))
        #expect(attestations.status == .ok)
        let statements = try #require(JSONSerialization.jsonObject(with: attestations.body) as? [[String: Any]])
        #expect((statements.first?["Statement"] as? [String: Any])?["predicateType"] as? String
            == "https://spdx.dev/Document")

        let selections = await backend.selections()
        #expect(selections.saved.map(\.architecture) == ["arm64", "amd64"])
        #expect(selections.loaded.map(\.architecture) == ["amd64", "arm64"])
        #expect(selections.deleted.map(\.architecture) == ["arm64", "amd64"])
        #expect(selections.pushed?.architecture == "amd64")
        #expect(selections.attestation?.architecture == "arm64")
        #expect(selections.types == ["https://spdx.dev/Document", "https://slsa.dev/provenance/v1"])
        #expect(selections.statement)
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

    @Test func imagePulledWhileCreatingContainerAppearsInImageList() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = ImageStoreBackend()
        let router = DockerRouter(
            runtime: try await EngineRuntime(root: root, backend: backend),
            root: root
        )

        let create = await router.route(.init(
            method: .POST,
            uri: "/v1.44/containers/create?name=implicit-pull",
            body: Data(#"{"Image":"debian"}"#.utf8)
        ))
        #expect(create.status == .created)

        let list = await router.route(.init(method: .GET, uri: "/v1.44/images/json"))
        let images = try #require(JSONSerialization.jsonObject(with: list.body) as? [[String: Any]])
        #expect(images.contains { ($0["RepoTags"] as? [String])?.contains("debian:latest") == true })
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
        #expect(Set(image["RepoTags"] as? [String] ?? []) == [
            "example/imported:latest", "imported-descriptor:latest",
        ])

        let events = await runtime.events(since: Date().addingTimeInterval(-60), until: Date())
        var iterator = events.makeAsyncIterator()
        let load = await iterator.next()
        #expect(load?.type == "image")
        #expect(load?.action == "load")
        #expect(load?.id == "sha256:0123456789abcdef")
        #expect(load?.attributes["name"] == load?.id)
    }

    @Test func startingAStoppedContainerPreservesItsPreparedBackend() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = RestartBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let record = try await runtime.createContainer(ContainerRecord(name: "start-stopped", image: "debian"))

        try await runtime.startContainer(record.id)
        try await runtime.stopContainer(record.id, timeoutSeconds: 0)
        try await runtime.startContainer(record.id)

        #expect(await backend.prepareCount() == 1)
        #expect(await backend.deleteCount() == 0)
        #expect(await backend.startCount() == 2)
        #expect(try await runtime.container(record.id).phase == .running)
    }

    @Test func startingAnExitedContainerRestoresItsMissingBackendPreparation() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let firstBackend = RestartBackend()
        let first = try await EngineRuntime(root: root, backend: firstBackend)
        let record = try await first.createContainer(ContainerRecord(name: "missing-shim", image: "debian"))
        try await first.startContainer(record.id)
        try await first.stopContainer(record.id, timeoutSeconds: 0)

        let recoveredBackend = RestartBackend()
        let recovered = try await EngineRuntime(root: root, backend: recoveredBackend)
        try await recovered.startContainer(record.id)

        #expect(await recoveredBackend.prepareCount() == 1)
        #expect(await recoveredBackend.deleteCount() == 0)
        #expect(await recoveredBackend.startCount() == 1)
        #expect(try await recovered.container(record.id).phase == .running)
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

    @Test func containerListDoesNotPublishAContainerDuringItsStartTransition() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingStartBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let record = try await runtime.createContainer(ContainerRecord(name: "starting", image: "debian"))
        let start = Task { try await runtime.startContainer(record.id) }
        while !(await backend.hasEnteredStart()) { await Task.yield() }

        #expect(await runtime.listContainers(all: true).isEmpty)

        await backend.releaseStart()
        try await start.value
        let listed = await runtime.listContainers(all: true)
        #expect(listed.map(\.id) == [record.id])
        #expect(listed.first?.phase == .running)
    }

    @Test func concurrentCreatesReserveContainerNamesBeforeBackendPreparation() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingPrepareBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let first = Task {
            try await runtime.createContainer(ContainerRecord(name: "shared-name", image: "debian"))
        }
        while await backend.prepareCount() == 0 { await Task.yield() }
        let second = Task {
            try await runtime.createContainer(ContainerRecord(name: "shared-name", image: "debian"))
        }
        try await Task.sleep(for: .milliseconds(25))
        await backend.releasePreparations()

        var successes = 0
        var conflicts = 0
        for result in [await first.result, await second.result] {
            switch result {
            case .success:
                successes += 1
            case .failure(let error as EngineError) where error.code == .conflict:
                conflicts += 1
                #expect(error.message.contains("is already in use by container"))
            case .failure(let error):
                Issue.record("unexpected create error: \(error)")
            }
        }
        #expect(successes == 1)
        #expect(conflicts == 1)
        #expect(await backend.prepareCount() == 1)
        #expect(await runtime.listContainers(all: true).count == 1)
    }

    @Test func concurrentCreatesReserveEndpointAddressesBeforeBackendPreparation() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingPrepareBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let first = Task {
            try await runtime.createContainer(ContainerRecord(name: "first-endpoint", image: "debian"))
        }
        while await backend.prepareCount() < 1 { await Task.yield() }
        let second = Task {
            try await runtime.createContainer(ContainerRecord(name: "second-endpoint", image: "debian"))
        }
        while await backend.prepareCount() < 2 { await Task.yield() }
        await backend.releasePreparations()

        let created = try await (first.value, second.value)
        let endpoints = [created.0, created.1].compactMap { $0.networks.first?.ipv4Address }
        #expect(Set(endpoints) == ["192.168.64.2", "192.168.64.3"])
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

    @Test func runtimePublishesAndReplaysDockerImagePullEvents() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root)
        let stream = await runtime.events()
        var iterator = stream.makeAsyncIterator()
        _ = try await runtime.pullImage("docker.io/library/alpine:latest")
        let event = await iterator.next()
        #expect(event?.type == "image")
        #expect(event?.action == "pull")
        #expect(event?.id == "alpine:latest")
        #expect(event?.attributes["name"] == "alpine")

        let history = await runtime.events(since: Date().addingTimeInterval(-60), until: Date())
        var historical = history.makeAsyncIterator()
        #expect(await historical.next()?.action == "pull")
        #expect(await historical.next() == nil)
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

    @Test func restartPolicyUpdateDoesNotRecreateRunningContainer() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = RestartBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let router = DockerRouter(runtime: runtime, root: root)
        let record = try await runtime.createContainer(ContainerRecord(name: "policy-only", image: "debian"))
        try await runtime.startContainer(record.id)
        let before = try await runtime.container(record.id)
        let startedAt = try #require(before.startedAt)
        let startCount = await backend.startCount()
        let prepareCount = await backend.prepareCount()
        let deleteCount = await backend.deleteCount()

        let response = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/policy-only/update",
            body: Data(#"{"RestartPolicy":{"Name":"unless-stopped"}}"#.utf8)
        ))

        #expect(response.status == .ok)
        let updated = try await runtime.container(record.id)
        #expect(updated.phase == .running)
        #expect(updated.startedAt == startedAt)
        #expect(updated.restartPolicy.name == "unless-stopped")
        #expect(await backend.startCount() == startCount)
        #expect(await backend.prepareCount() == prepareCount)
        #expect(await backend.deleteCount() == deleteCount)
    }

    @Test func resourceUpdateDoesNotRecreateRunningContainer() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = RestartBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let router = DockerRouter(runtime: runtime, root: root)
        let record = try await runtime.createContainer(ContainerRecord(name: "live-resources", image: "debian"))
        try await runtime.startContainer(record.id)
        let before = try await runtime.container(record.id)
        let startedAt = try #require(before.startedAt)
        let startCount = await backend.startCount()
        let prepareCount = await backend.prepareCount()
        let deleteCount = await backend.deleteCount()

        let response = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/live-resources/update",
            body: Data(#"{"Memory":536870912,"NanoCpus":0,"CpuQuota":200000,"CpuPeriod":100000}"#.utf8)
        ))

        #expect(response.status == .ok)
        let updated = try await runtime.container(record.id)
        #expect(updated.phase == .running)
        #expect(updated.startedAt == startedAt)
        #expect(updated.memoryBytes == 512 * 1_024 * 1_024)
        #expect(updated.cpus == 2)
        #expect(await backend.lastResourceUpdate()?.memoryBytes == updated.memoryBytes)
        #expect(await backend.lastResourceUpdate()?.cpus == updated.cpus)
        #expect(await backend.startCount() == startCount)
        #expect(await backend.prepareCount() == prepareCount)
        #expect(await backend.deleteCount() == deleteCount)
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

    @Test func explicitStopSuppressesPolicyRestartWhenCompletionWinsRace() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = LifecycleRaceBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        var record = ContainerRecord(name: "intentional-stop", image: "debian")
        record.restartPolicy = .init(name: "unless-stopped")
        record = try await runtime.createContainer(record)
        let containerID = record.id
        try await runtime.startContainer(containerID)
        while !(await backend.isWaitingForCompletion()) { await Task.yield() }
        let baselineCounts = await backend.counts()

        let stop = Task { try await runtime.stopContainer(containerID) }
        while !(await backend.isStopBlocked()) { await Task.yield() }
        while try await runtime.container(containerID).phase != .exited { await Task.yield() }

        let countsDuringStop = await backend.counts()
        #expect(countsDuringStop.prepares == baselineCounts.prepares)
        #expect(countsDuringStop.starts == baselineCounts.starts)
        #expect(countsDuringStop.deletes == baselineCounts.deletes)
        #expect(try await runtime.container(containerID).restartCount == 0)

        await backend.releaseStop()
        try await stop.value
        #expect(try await runtime.container(containerID).phase == .exited)
        #expect(await backend.counts().starts == baselineCounts.starts)
    }

    @Test func daemonRestartHonorsManualStopRestartPolicySemantics() async throws {
        let alwaysRoot = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: alwaysRoot) }
        let alwaysBackend = RestartBackend()
        let firstAlways = try await EngineRuntime(root: alwaysRoot, backend: alwaysBackend)
        var alwaysRecord = ContainerRecord(name: "stopped-always", image: "debian")
        alwaysRecord.restartPolicy = .init(name: "always")
        alwaysRecord = try await firstAlways.createContainer(alwaysRecord)
        try await firstAlways.startContainer(alwaysRecord.id)
        try await firstAlways.stopContainer(alwaysRecord.id)
        #expect(try await firstAlways.container(alwaysRecord.id).phase == .exited)

        let restartedBackend = RestartBackend()
        let restarted = try await EngineRuntime(root: alwaysRoot, backend: restartedBackend)
        #expect(try await restarted.container(alwaysRecord.id).phase == .running)
        #expect(try await restarted.container(alwaysRecord.id).restartCount == 1)
        #expect(await restartedBackend.startCount() == 1)

        let unlessRoot = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: unlessRoot) }
        let unlessBackend = RestartBackend()
        let firstUnless = try await EngineRuntime(root: unlessRoot, backend: unlessBackend)
        var unlessRecord = ContainerRecord(name: "stopped-unless", image: "debian")
        unlessRecord.restartPolicy = .init(name: "unless-stopped")
        unlessRecord = try await firstUnless.createContainer(unlessRecord)
        try await firstUnless.startContainer(unlessRecord.id)
        try await firstUnless.stopContainer(unlessRecord.id)

        let stoppedBackend = RestartBackend()
        let stopped = try await EngineRuntime(root: unlessRoot, backend: stoppedBackend)
        #expect(try await stopped.container(unlessRecord.id).phase == .exited)
        #expect(try await stopped.container(unlessRecord.id).restartCount == 0)
        #expect(await stoppedBackend.startCount() == 0)
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

    @Test @MainActor func rawVMConsoleUsesReadableInputHandle() throws {
        let attachment = try RawVirtualMachineConfiguration.makeConsoleAttachment()
        withExtendedLifetime(attachment) {}
    }
}

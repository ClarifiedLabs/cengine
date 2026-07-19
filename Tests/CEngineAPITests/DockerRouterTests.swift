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

private func upgradedExecStart(socketPath: String, execID: String, body: String) throws -> String {
    let process = Process()
    let output = Pipe()
    let errors = Pipe()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
    process.arguments = [
        "--silent", "--show-error", "--include", "--max-time", "5",
        "--unix-socket", socketPath,
        "--request", "POST",
        "--header", "Connection: Upgrade",
        "--header", "Upgrade: tcp",
        "--header", "Content-Type: application/json",
        "--data-binary", body,
        "http://localhost/v1.44/exec/\(execID)/start",
    ]
    process.standardOutput = output
    process.standardError = errors
    try process.run()
    process.waitUntilExit()
    return String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        + String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
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
        if result.enableIPv4, result.subnet.isEmpty { result.subnet = "192.168.250.0/24"; result.gateway = "192.168.250.1" }
        if result.enableIPv6, result.ipv6Subnet.isEmpty { result.ipv6Subnet = "fd00:ce::/64"; result.ipv6Gateway = "fd00:ce::1" }
        return result
    }

    func request(named name: String) -> NetworkRecord? { requests[name] }
}

private actor BlockingStartBackend: ContainerBackend {
    private var continuation: CheckedContinuation<Void, Never>?
    private var entered = false
    private var starts = 0
    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {}
    func start(_ container: ContainerRecord) async throws -> [PortBinding] {
        entered = true
        starts += 1
        await withCheckedContinuation { continuation = $0 }
        return container.ports
    }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 137 }
    func wait(_: ContainerRecord) async throws -> Int32 { 137 }
    func delete(_: ContainerRecord) async throws {}
    func hasEnteredStart() -> Bool { entered }
    func startCount() -> Int { starts }
    func releaseStart() { continuation?.resume(); continuation = nil }
}

private actor BlockingEndpointAddressBackend: ContainerBackend {
    private var lookupContinuation: CheckedContinuation<Void, Never>?
    private var healthcheckContinuation: CheckedContinuation<Void, Never>?
    private var blockNextLookup = false
    private var lookupBlocked = false
    private var blockedHealthcheckCall: Int?
    private var blockedHealthcheckExitCode: Int32 = 0
    private var healthcheckBlocked = false
    private var healthchecks = 0
    private var lookups = 0
    private var starts = 0
    private var kills = 0

    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {}
    func start(_ container: ContainerRecord) async throws -> [PortBinding] {
        starts += 1
        return container.ports
    }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 137 }
    func wait(_: ContainerRecord) async throws -> Int32 { 137 }
    func delete(_: ContainerRecord) async throws {}
    func kill(_: ContainerRecord, signal _: String) async throws { kills += 1 }
    func endpointAddresses(for container: ContainerRecord) async -> [String: BackendEndpointAddress] {
        lookups += 1
        let address = "192.168.64.\(200 + lookups)"
        if blockNextLookup {
            blockNextLookup = false
            lookupBlocked = true
            await withCheckedContinuation { lookupContinuation = $0 }
            lookupBlocked = false
        }
        return Dictionary(uniqueKeysWithValues: container.networks.map {
            ($0.networkID, BackendEndpointAddress(ipv4Address: address, ipv6Address: ""))
        })
    }
    func runHealthcheck(
        _: ContainerRecord,
        arguments _: [String],
        timeoutSeconds _: Int64
    ) async throws -> (exitCode: Int32, output: String) {
        healthchecks += 1
        guard blockedHealthcheckCall == healthchecks else { return (0, "healthy") }
        let exitCode = blockedHealthcheckExitCode
        blockedHealthcheckCall = nil
        healthcheckBlocked = true
        await withCheckedContinuation { healthcheckContinuation = $0 }
        healthcheckBlocked = false
        return (exitCode, "blocked")
    }

    func blockNextEndpointLookup() { blockNextLookup = true }
    func isEndpointLookupBlocked() -> Bool { lookupBlocked }
    func releaseEndpointLookup() {
        lookupContinuation?.resume()
        lookupContinuation = nil
    }
    func blockHealthcheck(call: Int, exitCode: Int32) {
        blockedHealthcheckCall = call
        blockedHealthcheckExitCode = exitCode
    }
    func isHealthcheckBlocked() -> Bool { healthcheckBlocked }
    func releaseHealthcheck() {
        healthcheckContinuation?.resume()
        healthcheckContinuation = nil
    }
    func counts() -> (starts: Int, kills: Int) { (starts, kills) }
}

private actor BlockingPauseResumeBackend: ContainerBackend {
    private var pauseContinuation: CheckedContinuation<Void, Never>?
    private var resumeContinuation: CheckedContinuation<Void, Never>?
    private var pauseBlocked = false
    private var resumeBlocked = false

    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {}
    func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_: ContainerRecord) async throws {}
    func pause(_: ContainerRecord) async throws {
        pauseBlocked = true
        await withCheckedContinuation { pauseContinuation = $0 }
        pauseBlocked = false
    }
    func resume(_: ContainerRecord) async throws {
        resumeBlocked = true
        await withCheckedContinuation { resumeContinuation = $0 }
        resumeBlocked = false
    }
    func isPauseBlocked() -> Bool { pauseBlocked }
    func isResumeBlocked() -> Bool { resumeBlocked }
    func releasePause() { pauseContinuation?.resume(); pauseContinuation = nil }
    func releaseResume() { resumeContinuation?.resume(); resumeContinuation = nil }
}

private actor PauseExitRaceBackend: ContainerBackend {
    private var completionContinuation: CheckedContinuation<Int32?, Never>?
    private var pauseContinuation: CheckedContinuation<Void, Never>?
    private var pauseBlocked = false

    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {}
    func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_: ContainerRecord) async throws {}
    func completion(_: ContainerRecord) async -> Int32? {
        await withCheckedContinuation { completionContinuation = $0 }
    }
    func pause(_: ContainerRecord) async throws {
        pauseBlocked = true
        await withCheckedContinuation { pauseContinuation = $0 }
        pauseBlocked = false
    }
    func isWaitingForCompletion() -> Bool { completionContinuation != nil }
    func isPauseBlocked() -> Bool { pauseBlocked }
    func finish(code: Int32) {
        completionContinuation?.resume(returning: code)
        completionContinuation = nil
    }
    func releasePause() { pauseContinuation?.resume(); pauseContinuation = nil }
}

private actor BlockingNetworkUpdateBackend: ContainerBackend {
    private var continuation: CheckedContinuation<Void, Never>?
    private var blockNextUpdate = false
    private var updateBlocked = false

    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {}
    func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_: ContainerRecord) async throws {}
    func updateNetworkRecords(_: [ContainerRecord]) async throws {
        guard blockNextUpdate else { return }
        blockNextUpdate = false
        updateBlocked = true
        await withCheckedContinuation { continuation = $0 }
        updateBlocked = false
    }
    func blockNextNetworkUpdate() { blockNextUpdate = true }
    func isNetworkUpdateBlocked() -> Bool { updateBlocked }
    func releaseNetworkUpdate() { continuation?.resume(); continuation = nil }
}

private actor BlockingExecStartBackend: ContainerBackend {
    enum Mode { case detached, attached }

    private var mode: Mode?
    private var continuation: CheckedContinuation<Void, Never>?
    private var detachedStarts = 0
    private var attachedStarts = 0

    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {}
    func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_: ContainerRecord) async throws {}
    func prepareExec(_ exec: ExecRecord, container _: ContainerRecord) async throws -> ContainerIOBridge {
        ContainerIOBridge(tty: exec.configuration.tty)
    }
    func startExec(_: ExecRecord) async throws {
        mode = .detached
        detachedStarts += 1
        await withCheckedContinuation { continuation = $0 }
    }
    func startAttachedExec(_: ExecRecord) async throws -> CInt? {
        mode = .attached
        attachedStarts += 1
        await withCheckedContinuation { continuation = $0 }
        return nil
    }
    func execPID(_: ExecRecord) async -> Int32 { 42 }
    func entered(_ expected: Mode) -> Bool { mode == expected }
    func counts() -> (detached: Int, attached: Int) { (detachedStarts, attachedStarts) }
    func release() { continuation?.resume(); continuation = nil }
}

private actor BlockingRestartExecGateBackend: ContainerBackend {
    private var restartContinuation: CheckedContinuation<Void, Never>?
    private var replacementReady = false
    private var preparedExecs = 0
    private var detachedStarts = 0
    private var attachedStarts = 0

    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {}
    func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_: ContainerRecord) async throws {}
    func restart(_: ContainerRecord, timeoutSeconds _: Int) async throws {
        // Model RawVirtualizationBackend after it has installed the replacement
        // shim but before EngineRuntime has reconciled the old exec generation.
        replacementReady = true
        await withCheckedContinuation { restartContinuation = $0 }
    }
    func prepareExec(_ exec: ExecRecord, container _: ContainerRecord) async throws -> ContainerIOBridge {
        preparedExecs += 1
        return ContainerIOBridge(tty: exec.configuration.tty)
    }
    func startExec(_: ExecRecord) async throws { detachedStarts += 1 }
    func startAttachedExec(_: ExecRecord) async throws -> CInt? {
        attachedStarts += 1
        return nil
    }
    func isReplacementReady() -> Bool { replacementReady }
    func counts() -> (prepared: Int, detached: Int, attached: Int) {
        (preparedExecs, detachedStarts, attachedStarts)
    }
    func releaseRestart() {
        restartContinuation?.resume()
        restartContinuation = nil
    }
}

private actor BlockingStaleExecPreparationBackend: ContainerBackend {
    private var completionContinuation: CheckedContinuation<Int32?, Never>?
    private var prepareContinuation: CheckedContinuation<Void, Never>?
    private var completionCalls = 0
    private var prepareBlocked = false
    private var preparedExecID: String?
    private var discardedExecIDs: Set<String> = []
    private var starts = 0

    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {}
    func start(_ container: ContainerRecord) async throws -> [PortBinding] {
        starts += 1
        return container.ports
    }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_: ContainerRecord) async throws {}
    func completion(_: ContainerRecord) async -> Int32? {
        completionCalls += 1
        guard completionCalls == 1 else { return nil }
        return await withCheckedContinuation { completionContinuation = $0 }
    }
    func prepareExec(_ exec: ExecRecord, container _: ContainerRecord) async throws -> ContainerIOBridge {
        preparedExecID = exec.id
        prepareBlocked = true
        await withCheckedContinuation { prepareContinuation = $0 }
        prepareBlocked = false
        return ContainerIOBridge(tty: exec.configuration.tty)
    }
    func discardExec(_ exec: ExecRecord) async { discardedExecIDs.insert(exec.id) }
    func isWaitingForCompletion() -> Bool { completionContinuation != nil }
    func isPrepareBlocked() -> Bool { prepareBlocked }
    func preparedID() -> String? { preparedExecID }
    func wasDiscarded(_ identifier: String) -> Bool { discardedExecIDs.contains(identifier) }
    func startCount() -> Int { starts }
    func finishContainer(code: Int32) {
        completionContinuation?.resume(returning: code)
        completionContinuation = nil
    }
    func releasePrepare() {
        prepareContinuation?.resume()
        prepareContinuation = nil
    }
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

private actor BlockingContainerDeleteBackend: ContainerBackend {
    enum Failure: Error { case injected }

    private let failBlockedDelete: Bool
    private var blockedContainerID: String?
    private var continuation: CheckedContinuation<Void, Never>?
    private var hasBlocked = false

    init(failBlockedDelete: Bool = false) { self.failBlockedDelete = failBlockedDelete }

    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {}
    func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_ container: ContainerRecord) async throws {
        guard !hasBlocked else { return }
        hasBlocked = true
        blockedContainerID = container.id
        await withCheckedContinuation { continuation = $0 }
        if failBlockedDelete { throw Failure.injected }
    }

    func blockedID() -> String? { blockedContainerID }
    func releaseDelete() { continuation?.resume(); continuation = nil }
}

private actor BlockingPruneDeleteBackend: ContainerBackend {
    private var continuation: CheckedContinuation<Void, Never>?
    private var deleteEntered = false

    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {}
    func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_: ContainerRecord) async throws {
        deleteEntered = true
        await withCheckedContinuation { continuation = $0 }
    }
    func hasEnteredDelete() -> Bool { deleteEntered }
    func releaseDelete() { continuation?.resume(); continuation = nil }
}

private actor BlockingResourceUpdateBackend: ContainerBackend {
    private var continuation: CheckedContinuation<Void, Never>?
    private var updateEntered = false

    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {}
    func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_: ContainerRecord) async throws {}
    func updateResources(_: ContainerRecord) async throws {
        updateEntered = true
        await withCheckedContinuation { continuation = $0 }
    }
    func hasEnteredUpdate() -> Bool { updateEntered }
    func releaseUpdate() { continuation?.resume(); continuation = nil }
}

private actor UpdateExitRaceBackend: ContainerBackend {
    private var completionContinuation: CheckedContinuation<Int32?, Never>?
    private var updateContinuation: CheckedContinuation<Void, Never>?
    private var updateBlocked = false
    private var starts = 0
    private var prepares = 0
    private var deletes = 0

    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws { prepares += 1 }
    func start(_ container: ContainerRecord) async throws -> [PortBinding] {
        starts += 1
        return container.ports
    }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_: ContainerRecord) async throws { deletes += 1 }
    func completion(_: ContainerRecord) async -> Int32? {
        await withCheckedContinuation { completionContinuation = $0 }
    }
    func updateResources(_: ContainerRecord) async throws {
        updateBlocked = true
        await withCheckedContinuation { updateContinuation = $0 }
        updateBlocked = false
    }
    func isWaitingForCompletion() -> Bool { completionContinuation != nil }
    func isUpdateBlocked() -> Bool { updateBlocked }
    func finish(code: Int32) {
        completionContinuation?.resume(returning: code)
        completionContinuation = nil
    }
    func releaseUpdate() {
        updateContinuation?.resume()
        updateContinuation = nil
    }
    func counts() -> (prepares: Int, starts: Int, deletes: Int) { (prepares, starts, deletes) }
}

private actor BlockingReconciliationBackend: ContainerBackend {
    private var completionContinuations: [String: CheckedContinuation<Int32?, Never>] = [:]
    private var deleteContinuation: CheckedContinuation<Void, Never>?
    private var deleteBlocked = false
    private var prepares = 0
    private var starts = 0
    private var deletes = 0

    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws { prepares += 1 }
    func start(_ container: ContainerRecord) async throws -> [PortBinding] {
        starts += 1
        return container.ports
    }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 137 }
    func wait(_: ContainerRecord) async throws -> Int32 { 137 }
    func delete(_ container: ContainerRecord) async throws {
        deletes += 1
        guard container.phase == .exited else { return }
        deleteBlocked = true
        await withCheckedContinuation { deleteContinuation = $0 }
        deleteBlocked = false
    }
    func completion(_ container: ContainerRecord) async -> Int32? {
        await withCheckedContinuation { completionContinuations[container.id] = $0 }
    }
    func isWaitingForCompletion(_ identifier: String) -> Bool {
        completionContinuations[identifier] != nil
    }
    func finish(_ identifier: String, code: Int32) {
        completionContinuations.removeValue(forKey: identifier)?.resume(returning: code)
    }
    func hasBlockedReconciliationDelete() -> Bool { deleteBlocked }
    func releaseReconciliationDelete() {
        deleteContinuation?.resume()
        deleteContinuation = nil
    }
    func counts() -> (prepares: Int, starts: Int, deletes: Int) { (prepares, starts, deletes) }
}

private actor AttachedExecLifecycleBackend: ContainerBackend {
    private var execCompletionContinuation: CheckedContinuation<Int32?, Never>?
    private var terminal = false

    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {}
    func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_: ContainerRecord) async throws {}
    func prepareExec(_ exec: ExecRecord, container _: ContainerRecord) async throws -> ContainerIOBridge {
        ContainerIOBridge(tty: exec.configuration.tty)
    }
    func startAttachedExec(_: ExecRecord) async throws -> CInt? { 123 }
    func execCompletion(_: ExecRecord) async -> Int32? {
        await withCheckedContinuation { execCompletionContinuation = $0 }
    }
    func execPID(_: ExecRecord) async -> Int32 { terminal ? 0 : 73 }
    func isWaitingForExecCompletion() -> Bool { execCompletionContinuation != nil }
    func finishExec(code: Int32) {
        terminal = true
        execCompletionContinuation?.resume(returning: code)
        execCompletionContinuation = nil
    }
}

private actor FailedAttachedExecBackend: ContainerBackend {
    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {}
    func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_: ContainerRecord) async throws {}
    func prepareExec(_ exec: ExecRecord, container _: ContainerRecord) async throws -> ContainerIOBridge {
        ContainerIOBridge(tty: exec.configuration.tty)
    }
    func startAttachedExec(_: ExecRecord) async throws -> CInt? { 123 }
    func execCompletion(_: ExecRecord) async -> Int32? { 126 }
    func execPID(_: ExecRecord) async -> Int32 { 0 }
    func execStatus(_: ExecRecord) async -> Int32? { 126 }
}

private actor ParentTeardownExecBackend: ContainerBackend {
    private var containerCompletions: [CheckedContinuation<Int32?, Never>] = []
    private var execCompletions: [String: CheckedContinuation<Int32?, Never>] = [:]

    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {}
    func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 137 }
    func wait(_: ContainerRecord) async throws -> Int32 { 137 }
    func delete(_: ContainerRecord) async throws {}
    func completion(_: ContainerRecord) async -> Int32? {
        await withCheckedContinuation { containerCompletions.append($0) }
    }
    func prepareExec(_ exec: ExecRecord, container _: ContainerRecord) async throws -> ContainerIOBridge {
        ContainerIOBridge(tty: exec.configuration.tty)
    }
    func startExec(_: ExecRecord) async throws {}
    func startAttachedExec(_: ExecRecord) async throws -> CInt? { 123 }
    func execCompletion(_ exec: ExecRecord) async -> Int32? {
        await withCheckedContinuation { execCompletions[exec.id] = $0 }
    }
    func execPID(_: ExecRecord) async -> Int32 { 81 }
    func execStatus(_: ExecRecord) async -> Int32? { nil }
    func isWaitingForContainerCompletion() -> Bool { !containerCompletions.isEmpty }
    func waitingContainerCount() -> Int { containerCompletions.count }
    func waitingExecCount() -> Int { execCompletions.count }
    func finishContainer(code: Int32) {
        if !containerCompletions.isEmpty {
            containerCompletions.removeFirst().resume(returning: code)
        }
        let pending = execCompletions.values
        execCompletions.removeAll()
        pending.forEach { $0.resume(returning: nil) }
    }
    func releaseContainerCompletions() {
        let pending = containerCompletions
        containerCompletions.removeAll()
        pending.forEach { $0.resume(returning: nil) }
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

private actor ArmedStateSaveFailure {
    enum Failure: Error { case injected }

    private var armed = false

    func arm() { armed = true }
    func failWhenArmed() throws {
        guard armed else { return }
        armed = false
        throw Failure.injected
    }
}

/// Models a backend whose restart first stops the old execution and can then
/// fail while installing the replacement. It also exposes enough state to
/// prove EngineRuntime does not leave an orphan execution or health monitor.
private actor RestartFailurePathBackend: ContainerBackend {
    enum Failure: Error { case restartAfterStop }

    private var preparedContainers = Set<String>()
    private var runningContainers = Set<String>()
    private var runningExecs = Set<String>()
    private var failNextRestart = false
    private var starts = 0
    private var stops = 0
    private var deletes = 0
    private var restarts = 0
    private var healthchecks = 0
    private var blockHealthcheck = false
    private var healthcheckBlocked = false
    private var healthcheckContinuation: CheckedContinuation<Void, Never>?
    private var completionContinuations: [String: CheckedContinuation<Int32?, Never>] = [:]

    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_ container: ContainerRecord) async throws {
        preparedContainers.insert(container.id)
    }
    func start(_ container: ContainerRecord) async throws -> [PortBinding] {
        guard preparedContainers.contains(container.id) else {
            throw EngineError(.notFound, "container preparation is unavailable")
        }
        starts += 1
        runningContainers.insert(container.id)
        return container.ports
    }
    func stop(_ container: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 {
        stops += 1
        runningContainers.remove(container.id)
        completionContinuations.removeValue(forKey: container.id)?.resume(returning: nil)
        return 127
    }
    func wait(_: ContainerRecord) async throws -> Int32 { 127 }
    func delete(_ container: ContainerRecord) async throws {
        deletes += 1
        runningContainers.remove(container.id)
        preparedContainers.remove(container.id)
        completionContinuations.removeValue(forKey: container.id)?.resume(returning: nil)
    }
    func restart(_ container: ContainerRecord, timeoutSeconds _: Int) async throws {
        restarts += 1
        stops += 1
        runningContainers.remove(container.id)
        completionContinuations.removeValue(forKey: container.id)?.resume(returning: nil)
        if failNextRestart {
            failNextRestart = false
            throw Failure.restartAfterStop
        }
        guard preparedContainers.contains(container.id) else {
            throw EngineError(.notFound, "container preparation is unavailable")
        }
        starts += 1
        runningContainers.insert(container.id)
    }
    func completion(_ container: ContainerRecord) async -> Int32? {
        await withCheckedContinuation { completionContinuations[container.id] = $0 }
    }
    func prepareExec(_ exec: ExecRecord, container _: ContainerRecord) async throws -> ContainerIOBridge {
        ContainerIOBridge(tty: exec.configuration.tty)
    }
    func startExec(_ exec: ExecRecord) async throws { runningExecs.insert(exec.id) }
    func execCompletion(_: ExecRecord) async -> Int32? { nil }
    func execPID(_: ExecRecord) async -> Int32 { 41 }
    func execStatus(_ exec: ExecRecord) async -> Int32? {
        runningExecs.remove(exec.id)
        return nil
    }
    func runHealthcheck(
        _: ContainerRecord,
        arguments _: [String],
        timeoutSeconds _: Int64
    ) async throws -> (exitCode: Int32, output: String) {
        healthchecks += 1
        guard blockHealthcheck else { return (0, "healthy") }
        blockHealthcheck = false
        healthcheckBlocked = true
        await withCheckedContinuation { healthcheckContinuation = $0 }
        healthcheckBlocked = false
        return (0, "healthy")
    }

    func failRestartAfterStop() { failNextRestart = true }
    func blockNextHealthcheck() { blockHealthcheck = true }
    func isHealthcheckBlocked() -> Bool { healthcheckBlocked }
    func releaseHealthcheck() {
        healthcheckContinuation?.resume()
        healthcheckContinuation = nil
    }
    func isRunning(_ identifier: String) -> Bool { runningContainers.contains(identifier) }
    func isPrepared(_ identifier: String) -> Bool { preparedContainers.contains(identifier) }
    func isWaitingForCompletion(_ identifier: String) -> Bool {
        completionContinuations[identifier] != nil
    }
    func healthcheckCount() -> Int { healthchecks }
    func counts() -> (starts: Int, stops: Int, deletes: Int, restarts: Int) {
        (starts, stops, deletes, restarts)
    }
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

private actor PartialStartFailureBackend: ContainerBackend {
    enum Failure: Error { case duringPrepare, afterLaunch }

    private var preparedContainers = Set<String>()
    private var runningContainers = Set<String>()
    private var shouldFailPrepare = false
    private var shouldFailStart: Bool
    private var starts = 0
    private var stops = 0
    private var deletes = 0
    private var completionRegistrations = 0
    private var healthchecks = 0

    init(failStartAfterLaunch: Bool = true) {
        shouldFailStart = failStartAfterLaunch
    }

    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_ container: ContainerRecord) async throws {
        if shouldFailPrepare {
            shouldFailPrepare = false
            throw Failure.duringPrepare
        }
        preparedContainers.insert(container.id)
    }
    func start(_ container: ContainerRecord) async throws -> [PortBinding] {
        starts += 1
        runningContainers.insert(container.id)
        if shouldFailStart {
            shouldFailStart = false
            throw Failure.afterLaunch
        }
        return container.ports
    }
    func stop(_ container: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 {
        stops += 1
        runningContainers.remove(container.id)
        return 127
    }
    func wait(_: ContainerRecord) async throws -> Int32 { 127 }
    func delete(_ container: ContainerRecord) async throws {
        deletes += 1
        runningContainers.remove(container.id)
        preparedContainers.remove(container.id)
    }
    func completion(_: ContainerRecord) async -> Int32? {
        completionRegistrations += 1
        return nil
    }
    func runHealthcheck(
        _: ContainerRecord,
        arguments _: [String],
        timeoutSeconds _: Int64
    ) async throws -> (exitCode: Int32, output: String) {
        healthchecks += 1
        return (0, "healthy")
    }

    func isRunning(_ identifier: String) -> Bool { runningContainers.contains(identifier) }
    func isPrepared(_ identifier: String) -> Bool { preparedContainers.contains(identifier) }
    func failNextPrepare() { shouldFailPrepare = true }
    func counts() -> (starts: Int, stops: Int, deletes: Int, completions: Int, healthchecks: Int) {
        (starts, stops, deletes, completionRegistrations, healthchecks)
    }
}

/// Leaves an execution live when start/restart fails, then rejects compensation
/// attempts. This models a daemon crash boundary where the durable
/// record must drive cleanup after reload instead of hiding the execution as a
/// safe created/exited container.
private actor QuarantinedExecutionBackend: ContainerBackend {
    enum Failure: Error { case partialStart, partialRestart, cleanupStop, cleanupDelete }

    private var preparedContainers = Set<String>()
    private var runningContainers = Set<String>()
    private var failNextStart = false
    private var failNextRestart = false
    private var rejectCleanup = false
    private var rejectNextStopOnly = false
    private var starts = 0
    private var restarts = 0
    private var stops = 0
    private var deletes = 0

    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_ container: ContainerRecord) async throws {
        preparedContainers.insert(container.id)
    }
    func start(_ container: ContainerRecord) async throws -> [PortBinding] {
        starts += 1
        runningContainers.insert(container.id)
        if failNextStart {
            failNextStart = false
            throw Failure.partialStart
        }
        return container.ports
    }
    func stop(_ container: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 {
        stops += 1
        if rejectNextStopOnly {
            rejectNextStopOnly = false
            throw Failure.cleanupStop
        }
        if rejectCleanup { throw Failure.cleanupStop }
        runningContainers.remove(container.id)
        return 127
    }
    func wait(_: ContainerRecord) async throws -> Int32 { 127 }
    func delete(_ container: ContainerRecord) async throws {
        deletes += 1
        if rejectCleanup { throw Failure.cleanupDelete }
        runningContainers.remove(container.id)
        preparedContainers.remove(container.id)
    }
    func restart(_ container: ContainerRecord, timeoutSeconds _: Int) async throws {
        restarts += 1
        // The replacement crossed its launch boundary before the backend
        // reports failure, so cleanup must account for a live generation.
        runningContainers.insert(container.id)
        if failNextRestart {
            failNextRestart = false
            throw Failure.partialRestart
        }
    }
    func completion(_: ContainerRecord) async -> Int32? { nil }

    func failStartAndCleanup() {
        failNextStart = true
        rejectCleanup = true
    }
    func failRestartAndCleanup() {
        failNextRestart = true
        rejectCleanup = true
    }
    func failStartAndStopOnly() {
        failNextStart = true
        rejectNextStopOnly = true
    }
    func allowCleanup() { rejectCleanup = false }
    func isRunning(_ identifier: String) -> Bool { runningContainers.contains(identifier) }
    func counts() -> (starts: Int, restarts: Int, stops: Int, deletes: Int) {
        (starts, restarts, stops, deletes)
    }
}

private actor CompletionMonitorEntryGate {
    private var entries = 0
    private var firstEntryContinuation: CheckedContinuation<Void, Never>?

    func enter() async {
        entries += 1
        guard entries == 1 else { return }
        await withCheckedContinuation { firstEntryContinuation = $0 }
    }

    func firstEntryIsBlocked() -> Bool { firstEntryContinuation != nil }
    func releaseFirstEntry() {
        firstEntryContinuation?.resume()
        firstEntryContinuation = nil
    }
}

private actor GenerationCompletionBackend: ContainerBackend {
    private var completionContinuation: CheckedContinuation<Int32?, Never>?
    private var completionRegistrations = 0

    func pullImage(_: String, platform _: String) async throws {}
    func prepare(_: ContainerRecord) async throws {}
    func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
    func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    func delete(_: ContainerRecord) async throws {
        completionContinuation?.resume(returning: nil)
        completionContinuation = nil
    }
    func restart(_: ContainerRecord, timeoutSeconds _: Int) async throws {}
    func completion(_: ContainerRecord) async -> Int32? {
        completionRegistrations += 1
        return await withCheckedContinuation { completionContinuation = $0 }
    }

    func registrationCount() -> Int { completionRegistrations }
    func complete(code: Int32) {
        completionContinuation?.resume(returning: code)
        completionContinuation = nil
    }
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

    @Test func eventFiltersDecodeBooleanMapsAndIgnoreFalseEntries() throws {
        let target = try DockerRequestTarget.parse(
            "/v1.55/events?filters=%7B%22type%22:%7B%22container%22:true,%22image%22:false%7D,%22event%22:%7B%22start%22:true,%22die%22:false%7D%7D"
        )

        #expect(DockerHTTPHandler.eventFilters(target) == [
            "type": ["container"], "event": ["start"],
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
        #expect(mounts.first?["Propagation"] as? String == "")
        let host = try #require(object["HostConfig"] as? [String: Any])
        #expect((host["Binds"] as? [String]) == ["data:/data:ro"])
        #expect(host["NetworkMode"] as? String == "default")
        let logConfig = try #require(host["LogConfig"] as? [String: Any])
        #expect(logConfig["Type"] as? String == "json-file")
        let bindings = try #require(host["PortBindings"] as? [String: [[String: String]]])
        #expect(bindings["8080/tcp"]?.first?["HostPort"] == "0")
    }

    @Test func privateBindPropagationRoundTripsAndUnrealizableModesAreRejected() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let response = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=propagated-bind",
            body: Data(#"{"Image":"alpine","HostConfig":{"Binds":["/tmp:/legacy:rprivate"],"Mounts":[{"Type":"bind","Source":"/tmp","Target":"/typed","ReadOnly":true,"BindOptions":{"Propagation":"private"}}]}}"#.utf8)
        ))
        #expect(response.status == .created)
        let created = try #require(JSONSerialization.jsonObject(with: response.body) as? [String: Any])
        let id = try #require(created["Id"] as? String)
        let inspect = await router.route(.init(method: .GET, uri: "/v1.44/containers/\(id)/json"))
        let object = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        let mounts = try #require(object["Mounts"] as? [[String: Any]])
        #expect(mounts.first { $0["Destination"] as? String == "/legacy" }?["Propagation"] as? String == "rprivate")
        #expect(mounts.first { $0["Destination"] as? String == "/typed" }?["Propagation"] as? String == "private")
        let host = try #require(object["HostConfig"] as? [String: Any])
        let binds = try #require(host["Binds"] as? [String])
        #expect(binds.contains("/tmp:/legacy"))
        #expect(binds.contains("/tmp:/typed:ro,private"))

        for (index, propagation) in ["shared", "rshared", "slave", "rslave"].enumerated() {
            let unsupported = await router.route(.init(
                method: .POST, uri: "/v1.44/containers/create?name=unsupported-propagation-\(index)",
                body: Data("{\"Image\":\"alpine\",\"HostConfig\":{\"Binds\":[\"/tmp:/data:\(propagation)\"]}}".utf8)
            ))
            #expect(unsupported.status == .notImplemented)
        }

        let invalid = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=invalid-propagation",
            body: Data(#"{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"bind","Source":"/tmp","Target":"/data","BindOptions":{"Propagation":"sideways"}}]}}"#.utf8)
        ))
        #expect(invalid.status == .badRequest)

        let mismatched = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=mismatched-options",
            body: Data(#"{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"volume","Source":"data","Target":"/data","BindOptions":{"Propagation":"rshared"}}]}}"#.utf8)
        ))
        #expect(mismatched.status == .badRequest)
    }

    @Test func capabilityChangesRoundTripAndUnsupportedSecurityFieldsAreRejected() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let response = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=capabilities",
            body: Data(#"{"Image":"alpine","HostConfig":{"CapAdd":["net_admin","CAP_CHOWN"],"CapDrop":["net_raw","CHOWN"]}}"#.utf8)
        ))
        #expect(response.status == .created)
        let created = try #require(JSONSerialization.jsonObject(with: response.body) as? [String: Any])
        let id = try #require(created["Id"] as? String)
        let inspect = await router.route(.init(method: .GET, uri: "/v1.44/containers/\(id)/json"))
        let object = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        let host = try #require(object["HostConfig"] as? [String: Any])
        #expect(host["CapAdd"] as? [String] == ["CAP_NET_ADMIN", "CAP_CHOWN"])
        #expect(host["CapDrop"] as? [String] == ["CAP_NET_RAW", "CAP_CHOWN"])

        let invalid = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=invalid-capability",
            body: Data(#"{"Image":"alpine","HostConfig":{"CapAdd":["CAP_SIDEWAYS"]}}"#.utf8)
        ))
        #expect(invalid.status == .badRequest)

        let unsupportedFields = [
            #""SecurityOpt":["no-new-privileges"]"#,
            #""Ulimits":[{"Name":"nofile","Soft":1024,"Hard":1024}]"#,
            #""Devices":[{"PathOnHost":"/dev/null","PathInContainer":"/dev/test","CgroupPermissions":"rwm"}]"#,
            #""DeviceCgroupRules":["c 1:3 rwm"]"#,
            #""Sysctls":{"net.ipv4.ip_forward":"1"}"#,
            #""MaskedPaths":["/proc/kcore"]"#,
            #""ReadonlyPaths":["/proc/sys"]"#,
        ]
        for (index, field) in unsupportedFields.enumerated() {
            let body = "{\"Image\":\"alpine\",\"HostConfig\":{\(field)}}"
            let rejected = await router.route(.init(
                method: .POST, uri: "/v1.44/containers/create?name=unsupported-security-\(index)",
                body: Data(body.utf8)
            ))
            #expect(rejected.status == .notImplemented)
        }
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

    @Test func pidsLimitRoundTripsAndRejectsInvalidValues() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let response = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=pids-limited",
            body: Data(#"{"Image":"alpine","HostConfig":{"PidsLimit":32}}"#.utf8)
        ))
        #expect(response.status == .created)
        let created = try #require(JSONSerialization.jsonObject(with: response.body) as? [String: Any])
        let id = try #require(created["Id"] as? String)
        let inspect = await router.route(.init(method: .GET, uri: "/v1.44/containers/\(id)/json"))
        let object = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        let host = try #require(object["HostConfig"] as? [String: Any])
        #expect(host["PidsLimit"] as? Int == 32)
        let snapshot = try await AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json"))
            .load(default: .init())
        #expect(try #require(snapshot.containers.first { $0.id == id }).pidsLimit == 32)

        let invalid = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=invalid-pids",
            body: Data(#"{"Image":"alpine","HostConfig":{"PidsLimit":-2}}"#.utf8)
        ))
        #expect(invalid.status == .badRequest)
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
        #expect(network["EnableIPv6"] as? Bool == false)
        #expect(network["EnableIPv4"] == nil)
        let ipam = try #require(network["IPAM"] as? [String: Any])
        let configs = try #require(ipam["Config"] as? [[String: Any]])
        #expect(configs.count == 1)
        #expect((configs[0]["Subnet"] as? String)?.contains(":") == false)

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

    @Test func containerCreateRejectsUnsupportedVolumeDriversAndOptionsWithoutSideEffects() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let bodies = [
            #"{"Image":"alpine","Volumes":{"/legacy":{}},"HostConfig":{"VolumeDriver":"third-party"}}"#,
            #"{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"volume","Target":"/data","VolumeOptions":{"DriverConfig":{"Name":"third-party","Options":{"remote":"true"}}}}]}}"#,
            #"{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"volume","Target":"/data","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"tmpfs"}}}}]}}"#,
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
        let containers = await router.route(.init(method: .GET, uri: "/v1.55/containers/json?all=1"))
        #expect((try JSONSerialization.jsonObject(with: containers.body) as? [[String: Any]])?.isEmpty == true)
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

    @Test func networkAddressFamiliesAreAppliedInspectedAndRecovered() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())
        let router = DockerRouter(runtime: runtime, root: root)
        let create = await router.route(.init(
            method: .POST, uri: "/v1.55/networks/create",
            body: Data(#"{"Name":"v6only","EnableIPv4":false,"EnableIPv6":true,"IPAM":{"Config":[{"Subnet":"fd00:1234::/120","Gateway":"fd00:1234::1"}]}}"#.utf8)
        ))
        #expect(create.status == .created)
        let container = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=v6-client",
            body: Data(#"{"Image":"alpine","NetworkingConfig":{"EndpointsConfig":{"v6only":{}}}}"#.utf8)
        ))
        #expect(container.status == .created)

        let inspect = await router.route(.init(method: .GET, uri: "/v1.55/networks/v6only"))
        let network = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        #expect(network["EnableIPv4"] as? Bool == false)
        #expect(network["EnableIPv6"] as? Bool == true)
        let configs = try #require((network["IPAM"] as? [String: Any])?["Config"] as? [[String: Any]])
        #expect(configs.count == 1)
        #expect(configs[0]["Subnet"] as? String == "fd00:1234::/120")

        let containerInspect = await router.route(.init(method: .GET, uri: "/v1.55/containers/v6-client/json"))
        let containerObject = try #require(JSONSerialization.jsonObject(with: containerInspect.body) as? [String: Any])
        let endpoint = try #require(
            ((containerObject["NetworkSettings"] as? [String: Any])?["Networks"] as? [String: Any])?["v6only"] as? [String: Any]
        )
        #expect(endpoint["IPAddress"] as? String == "")
        #expect((endpoint["GlobalIPv6Address"] as? String)?.hasPrefix("fd00:1234::") == true)

        let restarted = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())
        let recovered = try await restarted.network("v6only")
        #expect(recovered.enableIPv4 == false)
        #expect(recovered.enableIPv6 == true)
        #expect(try await restarted.container("v6-client").networks.first?.ipv4Address == nil)

        let invalidV4 = await router.route(.init(
            method: .POST, uri: "/v1.55/networks/create",
            body: Data(#"{"Name":"bad-v4","EnableIPv4":false,"IPAM":{"Config":[{"Subnet":"10.44.0.0/24"}]}}"#.utf8)
        ))
        #expect(invalidV4.status == .badRequest)
        let invalidV6 = await router.route(.init(
            method: .POST, uri: "/v1.55/networks/create",
            body: Data(#"{"Name":"bad-v6","IPAM":{"Config":[{"Subnet":"fd00:44::/64"}]}}"#.utf8)
        ))
        #expect(invalidV6.status == .badRequest)
    }

    @Test func networkIPAMAndFamilyLimitationsAreRejectedExplicitly() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }

        let unsupportedBodies = [
            #"{"Name":"aux","IPAM":{"Config":[{"Subnet":"10.60.0.0/24","AuxiliaryAddresses":{"reserved":"10.60.0.10"}}]}}"#,
            #"{"Name":"multi-v4","IPAM":{"Config":[{"Subnet":"10.61.0.0/24"},{"Subnet":"10.62.0.0/24"}]}}"#,
            #"{"Name":"custom-v6-gateway","EnableIPv6":true,"IPAM":{"Config":[{"Subnet":"fd00:63::/64","Gateway":"fd00:63::fe"}]}}"#,
            #"{"Name":"asymmetric","Internal":true,"EnableIPv6":true,"Options":{"com.docker.network.bridge.gateway_mode_ipv4":"isolated"}}"#,
        ]
        for body in unsupportedBodies {
            let response = await router.route(.init(
                method: .POST,
                uri: "/v1.55/networks/create",
                body: Data(body.utf8)
            ))
            #expect(response.status == .notImplemented)
        }

        let disabled = await router.route(.init(
            method: .POST,
            uri: "/v1.55/networks/create",
            body: Data(#"{"Name":"disabled","EnableIPv4":false,"EnableIPv6":false}"#.utf8)
        ))
        #expect(disabled.status == .badRequest)

        // API versions before v1.48 did not define EnableIPv4, so a field sent
        // by a newer client must not disable legacy IPv4 behavior.
        let legacy = await router.route(.init(
            method: .POST,
            uri: "/v1.47/networks/create",
            body: Data(#"{"Name":"legacy-ipv4","EnableIPv4":false}"#.utf8)
        ))
        #expect(legacy.status == .created)
        let inspect = await router.route(.init(method: .GET, uri: "/v1.55/networks/legacy-ipv4"))
        let object = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        #expect(object["EnableIPv4"] as? Bool == true)
    }

    @Test func endpointSysctlsApplyAcrossRequestVersionsRoundTripPersistAndRejectInvalidOptions() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())
        let router = DockerRouter(runtime: runtime, root: root)
        _ = await router.route(.init(
            method: .POST, uri: "/v1.55/networks/create", body: Data(#"{"Name":"sysctl-net"}"#.utf8)
        ))
        let create = await router.route(.init(
            method: .POST, uri: "/v1.45/containers/create?name=sysctl-client",
            body: Data(#"{"Image":"alpine","NetworkingConfig":{"EndpointsConfig":{"sysctl-net":{"DriverOpts":{"com.docker.network.endpoint.sysctls":"net.ipv4.conf.IFNAME.forwarding=1,net.ipv6.conf.ifname.accept_ra=0"}}}}}"#.utf8)
        ))
        #expect(create.status == .created)
        let inspect = await router.route(.init(method: .GET, uri: "/v1.55/containers/sysctl-client/json"))
        let object = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        let endpoint = try #require(
            (((object["NetworkSettings"] as? [String: Any])?["Networks"] as? [String: Any])?["sysctl-net"] as? [String: Any])
        )
        let options = try #require(endpoint["DriverOpts"] as? [String: String])
        #expect(options[NetworkEndpointRecord.sysctlsDriverOption] == "net.ipv4.conf.IFNAME.forwarding=1,net.ipv6.conf.ifname.accept_ra=0")

        let oldInspect = await router.route(.init(
            method: .GET, uri: "/v1.45/containers/sysctl-client/json"
        ))
        let oldObject = try #require(JSONSerialization.jsonObject(with: oldInspect.body) as? [String: Any])
        let oldEndpoint = try #require(
            (((oldObject["NetworkSettings"] as? [String: Any])?["Networks"] as? [String: Any])?["sysctl-net"] as? [String: Any])
        )
        #expect(oldEndpoint["DriverOpts"] == nil)

        let introducedInspect = await router.route(.init(
            method: .GET, uri: "/v1.46/containers/sysctl-client/json"
        ))
        let introducedObject = try #require(
            JSONSerialization.jsonObject(with: introducedInspect.body) as? [String: Any]
        )
        let introducedEndpoint = try #require(
            (((introducedObject["NetworkSettings"] as? [String: Any])?["Networks"] as? [String: Any])?["sysctl-net"] as? [String: Any])
        )
        #expect(introducedEndpoint["DriverOpts"] as? [String: String] == options)

        let connectClient = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=connected-sysctl-client",
            body: Data(#"{"Image":"alpine"}"#.utf8)
        ))
        #expect(connectClient.status == .created)
        let connectedSetting = "net.ipv4.conf.IFNAME.forwarding=0"
        let connect = await router.route(.init(
            method: .POST, uri: "/v1.45/networks/sysctl-net/connect",
            body: Data(#"{"Container":"connected-sysctl-client","EndpointConfig":{"DriverOpts":{"com.docker.network.endpoint.sysctls":"net.ipv4.conf.IFNAME.forwarding=0"}}}"#.utf8)
        ))
        #expect(connect.status == .ok)

        let oldConnectedInspect = await router.route(.init(
            method: .GET, uri: "/v1.45/containers/connected-sysctl-client/json"
        ))
        let oldConnectedObject = try #require(
            JSONSerialization.jsonObject(with: oldConnectedInspect.body) as? [String: Any]
        )
        let oldConnectedEndpoint = try #require(
            (((oldConnectedObject["NetworkSettings"] as? [String: Any])?["Networks"] as? [String: Any])?["sysctl-net"] as? [String: Any])
        )
        #expect(oldConnectedEndpoint["DriverOpts"] == nil)

        let connectedInspect = await router.route(.init(
            method: .GET, uri: "/v1.46/containers/connected-sysctl-client/json"
        ))
        let connectedObject = try #require(
            JSONSerialization.jsonObject(with: connectedInspect.body) as? [String: Any]
        )
        let connectedEndpoint = try #require(
            (((connectedObject["NetworkSettings"] as? [String: Any])?["Networks"] as? [String: Any])?["sysctl-net"] as? [String: Any])
        )
        #expect(
            (connectedEndpoint["DriverOpts"] as? [String: String])?[NetworkEndpointRecord.sysctlsDriverOption]
                == connectedSetting
        )
        let connectedRecord = try await runtime.container("connected-sysctl-client")
        #expect(
            connectedRecord.networks.first(where: { $0.networkID != "cengine-default-network" })?.interfaceSysctls
                == [connectedSetting]
        )

        let restarted = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())
        let recovered = try await restarted.container("sysctl-client")
        #expect(recovered.networks.first?.interfaceSysctls == [
            "net.ipv4.conf.IFNAME.forwarding=1", "net.ipv6.conf.ifname.accept_ra=0",
        ])

        let malformed = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=bad-sysctl",
            body: Data(#"{"Image":"alpine","NetworkingConfig":{"EndpointsConfig":{"sysctl-net":{"DriverOpts":{"com.docker.network.endpoint.sysctls":"net.ipv4.conf.eth0.forwarding=1"}}}}}"#.utf8)
        ))
        #expect(malformed.status == .badRequest)
        let unsupported = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=bad-option",
            body: Data(#"{"Image":"alpine","NetworkingConfig":{"EndpointsConfig":{"sysctl-net":{"DriverOpts":{"example.unsupported":"1"}}}}}"#.utf8)
        ))
        #expect(unsupported.status == .notImplemented)
    }

    @Test func networkIPAMStatusTracksAllocationsAndIsVersioned() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let create = await router.route(.init(
            method: .POST, uri: "/v1.55/networks/create",
            body: Data(#"{"Name":"status-net","IPAM":{"Config":[{"Subnet":"10.55.0.2/29","Gateway":"10.55.0.1"}]}}"#.utf8)
        ))
        #expect(create.status == .created)
        _ = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=status-client",
            body: Data(#"{"Image":"alpine","NetworkingConfig":{"EndpointsConfig":{"status-net":{}}}}"#.utf8)
        ))

        let modern = await router.route(.init(method: .GET, uri: "/v1.52/networks/status-net"))
        let modernObject = try #require(JSONSerialization.jsonObject(with: modern.body) as? [String: Any])
        let subnet = try #require(
            (((modernObject["Status"] as? [String: Any])?["IPAM"] as? [String: Any])?["Subnets"] as? [String: Any])?["10.55.0.0/29"] as? [String: Any]
        )
        #expect(subnet["IPsInUse"] as? Int == 4)
        #expect(subnet["DynamicIPsAvailable"] as? Int == 4)

        let list = await router.route(.init(method: .GET, uri: "/v1.52/networks"))
        let listedNetworks = try #require(JSONSerialization.jsonObject(with: list.body) as? [[String: Any]])
        #expect(listedNetworks.first(where: { $0["Name"] as? String == "status-net" })?["Status"] == nil)

        let legacy = await router.route(.init(method: .GET, uri: "/v1.51/networks/status-net"))
        let legacyObject = try #require(JSONSerialization.jsonObject(with: legacy.body) as? [String: Any])
        #expect(legacyObject["Status"] == nil)

        let slash31Create = await router.route(.init(
            method: .POST, uri: "/v1.55/networks/create",
            body: Data(#"{"Name":"slash31","IPAM":{"Config":[{"Subnet":"10.55.1.2/31"}]}}"#.utf8)
        ))
        #expect(slash31Create.status == .created)
        let slash31Container = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=slash31-client",
            body: Data(#"{"Image":"alpine","NetworkingConfig":{"EndpointsConfig":{"slash31":{}}}}"#.utf8)
        ))
        #expect(slash31Container.status == .created)
        let slash31Inspect = await router.route(.init(method: .GET, uri: "/v1.52/networks/slash31"))
        let slash31Object = try #require(JSONSerialization.jsonObject(with: slash31Inspect.body) as? [String: Any])
        let slash31Config = try #require(
            ((slash31Object["IPAM"] as? [String: Any])?["Config"] as? [[String: Any]])?.first
        )
        #expect(slash31Config["Gateway"] as? String == "10.55.1.3")
        let slash31Status = try #require(
            (((slash31Object["Status"] as? [String: Any])?["IPAM"] as? [String: Any])?["Subnets"] as? [String: Any])?["10.55.1.2/31"] as? [String: Any]
        )
        #expect(slash31Status["IPsInUse"] as? Int == 2)
        #expect(slash31Status["DynamicIPsAvailable"] as? Int == 0)
        let containerInspect = await router.route(.init(
            method: .GET, uri: "/v1.55/containers/slash31-client/json"
        ))
        let containerObject = try #require(JSONSerialization.jsonObject(with: containerInspect.body) as? [String: Any])
        let slash31Endpoint = try #require(
            ((containerObject["NetworkSettings"] as? [String: Any])?["Networks"] as? [String: Any])?["slash31"] as? [String: Any]
        )
        #expect(slash31Endpoint["IPAddress"] as? String == "10.55.1.2")
    }

    @Test func omittedExplicitIPv6GatewayIsDerivedForInspectStatusAndAllocation() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let create = await router.route(.init(
            method: .POST, uri: "/v1.55/networks/create",
            body: Data(#"{"Name":"implicit-v6-gateway","EnableIPv4":false,"EnableIPv6":true,"IPAM":{"Config":[{"Subnet":"fd00:55::10/124"}]}}"#.utf8)
        ))
        #expect(create.status == .created)
        let container = await router.route(.init(
            method: .POST, uri: "/v1.55/containers/create?name=implicit-v6-client",
            body: Data(#"{"Image":"alpine","NetworkingConfig":{"EndpointsConfig":{"implicit-v6-gateway":{}}}}"#.utf8)
        ))
        #expect(container.status == .created)

        let inspect = await router.route(.init(method: .GET, uri: "/v1.52/networks/implicit-v6-gateway"))
        let network = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        let config = try #require(((network["IPAM"] as? [String: Any])?["Config"] as? [[String: Any]])?.first)
        #expect(config["Gateway"] as? String == "fd00:55::11")
        let status = try #require(
            (((network["Status"] as? [String: Any])?["IPAM"] as? [String: Any])?["Subnets"] as? [String: Any])?["fd00:55::10/124"] as? [String: Any]
        )
        #expect(status["IPsInUse"] as? Int == 3)
        #expect(status["DynamicIPsAvailable"] as? Int == 13)

        let containerInspect = await router.route(.init(
            method: .GET, uri: "/v1.55/containers/implicit-v6-client/json"
        ))
        let containerObject = try #require(JSONSerialization.jsonObject(with: containerInspect.body) as? [String: Any])
        let endpoint = try #require(
            ((containerObject["NetworkSettings"] as? [String: Any])?["Networks"] as? [String: Any])?["implicit-v6-gateway"] as? [String: Any]
        )
        #expect(endpoint["IPv6Gateway"] as? String == "fd00:55::11")
        #expect(endpoint["GlobalIPv6Address"] as? String == "fd00:55::12")
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

    @Test func engineRuntimeRejectsInvalidNetworkAddressingBeforeCallingBackend() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = NetworkRecordingBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let invalidRequests: [(String, String?, String?, String?, String?)] = [
            ("bogus-cidr", "bogus/24", nil, nil, nil),
            ("wrong-v4-subnet-family", "fd00:41::/64", nil, nil, nil),
            ("wrong-v6-subnet-family", nil, nil, "10.41.0.0/24", nil),
            ("wrong-v4-gateway-family", "10.41.0.0/24", "fd00:41::1", nil, nil),
            ("wrong-v6-gateway-family", nil, nil, "fd00:41::/64", "10.41.0.1"),
            ("outside-v4", "10.41.0.0/24", "10.42.0.1", nil, nil),
            ("reserved-v4-network", "10.41.0.0/24", "10.41.0.0", nil, nil),
            ("reserved-v4-broadcast", "10.41.0.0/24", "10.41.0.255", nil, nil),
            ("outside-v6", nil, nil, "fd00:41::/64", "fd00:42::1"),
            ("reserved-v6-network", nil, nil, "fd00:41::/64", "fd00:41::"),
            ("invalid-v6-prefix", nil, nil, "fd00:41::/129", nil),
        ]

        for (name, subnet, gateway, ipv6Subnet, ipv6Gateway) in invalidRequests {
            do {
                _ = try await runtime.createNetwork(
                    name: name, subnet: subnet, gateway: gateway,
                    ipv6Subnet: ipv6Subnet, ipv6Gateway: ipv6Gateway
                )
                Issue.record("invalid network addressing was accepted for \(name)")
            } catch let error as EngineError {
                #expect(error.code == .badRequest)
            }
            #expect(await backend.request(named: name) == nil)
        }
    }

    @Test func engineRuntimeCanonicalizesSubnetsAndImplicitGatewaysBeforeCallingBackend() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = NetworkRecordingBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)

        let network = try await runtime.createNetwork(
            name: "canonical-network",
            subnet: "10.44.0.30/28",
            ipv6Subnet: "FD00:0044:0000:0000:0000:0000:0000:001E/124"
        )

        let request = try #require(await backend.request(named: network.name))
        #expect(request.subnet == "10.44.0.16/28")
        #expect(request.gateway == "10.44.0.17")
        #expect(request.ipv6Subnet == "fd00:44::10/124")
        #expect(request.ipv6Gateway == "fd00:44::11")
        #expect(network.subnet == request.subnet)
        #expect(network.gateway == request.gateway)
        #expect(network.ipv6Subnet == request.ipv6Subnet)
        #expect(network.ipv6Gateway == request.ipv6Gateway)
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

        let ipv6Only = await router.route(.init(
            method: .POST, uri: "/v1.55/networks/create",
            body: Data(#"{"Name":"isolated-v6","Internal":true,"EnableIPv4":false,"EnableIPv6":true,"Options":{"com.docker.network.bridge.gateway_mode_ipv6":"isolated"}}"#.utf8)
        ))
        #expect(ipv6Only.status == .created)
        let ipv6OnlyRequest = try #require(await backend.request(named: "isolated-v6"))
        #expect(ipv6OnlyRequest.fabricIsolated)

        let asymmetric = await router.route(.init(
            method: .POST, uri: "/v1.55/networks/create",
            body: Data(#"{"Name":"asymmetric-isolation","Internal":true,"EnableIPv6":true,"Options":{"com.docker.network.bridge.gateway_mode_ipv4":"isolated"}}"#.utf8)
        ))
        #expect(asymmetric.status == .notImplemented)
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

    @Test func networkPruneFiltersLimitDeletionScope() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        for (name, project) in [("prune-alpha", "alpha"), ("prune-beta", "beta")] {
            let response = await router.route(.init(
                method: .POST, uri: "/v1.55/networks/create",
                body: Data(#"{"Name":"\#(name)","Labels":{"project":"\#(project)"}}"#.utf8)
            ))
            #expect(response.status == .created)
        }
        let emptyLabelFilters = "%7B%22label%22:%5B%22%22%5D%7D"
        let invalid = await router.route(.init(
            method: .POST,
            uri: "/v1.55/networks/prune?filters=\(emptyLabelFilters)"
        ))
        #expect(invalid.status == .badRequest)
        #expect((await router.route(.init(method: .GET, uri: "/v1.55/networks/prune-alpha"))).status == .ok)
        #expect((await router.route(.init(method: .GET, uri: "/v1.55/networks/prune-beta"))).status == .ok)

        let filters = "%7B%22label%22:%5B%22project=alpha%22%5D%7D"
        let prune = await router.route(.init(method: .POST, uri: "/v1.55/networks/prune?filters=\(filters)"))
        let object = try #require(JSONSerialization.jsonObject(with: prune.body) as? [String: Any])
        #expect(object["NetworksDeleted"] as? [String] == ["prune-alpha"])
        #expect((await router.route(.init(method: .GET, uri: "/v1.55/networks/prune-alpha"))).status == .notFound)
        #expect((await router.route(.init(method: .GET, uri: "/v1.55/networks/prune-beta"))).status == .ok)
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

        let detachKeys = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/\(container.id)/exec",
            body: Data(#"{"DetachKeys":"ctrl-x,x","Cmd":["true"]}"#.utf8)
        ))
        #expect(detachKeys.status == .notImplemented)

        let create = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/\(container.id)/exec",
            body: Data(#"{"AttachStdout":true,"AttachStderr":true,"Cmd":["echo","ok"]}"#.utf8)
        ))
        #expect(create.status == .created)
        let created = try #require(JSONSerialization.jsonObject(with: create.body) as? [String: Any])
        let execID = try #require(created["Id"] as? String)
        let mismatchedTTY = await router.route(.init(
            method: .POST, uri: "/v1.44/exec/\(execID)/start",
            body: Data(#"{"Detach":true,"Tty":true}"#.utf8)
        ))
        #expect(mismatchedTTY.status == .badRequest)
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

    @Test func concurrentDetachedExecStartsLaunchOnlyOnce() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingExecStartBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let container = try await runtime.createContainer(ContainerRecord(name: "detached-exec-race", image: "debian"))
        try await runtime.startContainer(container.id)
        let exec = try await runtime.createExec(
            container: container.id,
            configuration: .init(arguments: ["true"])
        )

        let first = Task { try await runtime.startExec(exec.id) }
        while !(await backend.entered(.detached)) { await Task.yield() }
        do {
            try await runtime.startExec(exec.id)
            Issue.record("a concurrent detached start launched the same exec twice")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }
        await backend.release()
        try await first.value

        let counts = await backend.counts()
        #expect(counts.detached == 1)
        #expect(counts.attached == 0)
    }

    @Test func concurrentAttachedExecStartsLaunchOnlyOnce() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingExecStartBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let container = try await runtime.createContainer(ContainerRecord(name: "attached-exec-race", image: "debian"))
        try await runtime.startContainer(container.id)
        let exec = try await runtime.createExec(
            container: container.id,
            configuration: .init(arguments: ["true"])
        )

        let first = Task { try await runtime.startAttachedExec(exec.id) }
        while !(await backend.entered(.attached)) { await Task.yield() }
        do {
            _ = try await runtime.startAttachedExec(exec.id)
            Issue.record("a concurrent attached start launched the same exec twice")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }
        await backend.release()
        #expect(try await first.value == nil)

        let counts = await backend.counts()
        #expect(counts.detached == 0)
        #expect(counts.attached == 1)
    }

    @Test func attachedExecPublishesPIDAndReconcilesCompletion() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = AttachedExecLifecycleBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let container = try await runtime.createContainer(
            ContainerRecord(name: "attached-exec-lifecycle", image: "debian")
        )
        try await runtime.startContainer(container.id)
        let exec = try await runtime.createExec(
            container: container.id,
            configuration: .init(arguments: ["sh", "-c", "exit 23"])
        )

        #expect(try await runtime.startAttachedExec(exec.id) == 123)
        let running = try await runtime.inspectExec(exec.id)
        #expect(running.running)
        #expect(running.pid == 73)
        while !(await backend.isWaitingForExecCompletion()) { await Task.yield() }

        await backend.finishExec(code: 23)
        for _ in 0..<100 {
            if try await runtime.inspectExec(exec.id).exitCode != nil { break }
            await Task.yield()
        }
        let completed = try await runtime.inspectExec(exec.id)
        #expect(!completed.running)
        #expect(completed.exitCode == 23)
        #expect(completed.pid == 73)
    }

    @Test func attachedExecLaunchFailureReconcilesTheHostRecord() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root, backend: FailedAttachedExecBackend())
        let container = try await runtime.createContainer(
            ContainerRecord(name: "attached-launch-failure", image: "debian")
        )
        try await runtime.startContainer(container.id)
        let exec = try await runtime.createExec(
            container: container.id,
            configuration: .init(arguments: ["missing-command"], attachStdout: true)
        )

        #expect(try await runtime.startAttachedExec(exec.id) == 123)
        for _ in 0..<100 {
            if try await runtime.inspectExec(exec.id).exitCode != nil { break }
            await Task.yield()
        }
        let completed = try await runtime.inspectExec(exec.id)
        #expect(completed.running == false)
        #expect(completed.exitCode == 126)
    }

    @Test func parentCompletionTerminalizesAttachedAndDetachedExecsWhenGuestStatusDisappears() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = ParentTeardownExecBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let container = try await runtime.createContainer(
            ContainerRecord(name: "parent-exec-teardown", image: "debian")
        )
        try await runtime.startContainer(container.id)
        while !(await backend.isWaitingForContainerCompletion()) { await Task.yield() }

        let detached = try await runtime.createExec(
            container: container.id, configuration: .init(arguments: ["sleep", "30"])
        )
        let attached = try await runtime.createExec(
            container: container.id, configuration: .init(arguments: ["sleep", "30"])
        )
        try await runtime.startExec(detached.id)
        #expect(try await runtime.startAttachedExec(attached.id) == 123)
        while (await backend.waitingExecCount()) != 2 { await Task.yield() }

        await backend.finishContainer(code: 0)
        for _ in 0..<100 {
            if try await runtime.inspectExec(detached.id).exitCode != nil,
               try await runtime.inspectExec(attached.id).exitCode != nil { break }
            await Task.yield()
        }
        let detachedCompleted = try await runtime.inspectExec(detached.id)
        let attachedCompleted = try await runtime.inspectExec(attached.id)
        #expect(!detachedCompleted.running)
        #expect(detachedCompleted.exitCode == 137)
        #expect(detachedCompleted.pid == 81)
        #expect(!attachedCompleted.running)
        #expect(attachedCompleted.exitCode == 137)
        #expect(attachedCompleted.pid == 81)

        try await runtime.removeContainer(container.id, force: false)
        #expect(try await runtime.inspectExec(detached.id).exitCode == 137)
        #expect(try await runtime.inspectExec(attached.id).exitCode == 137)
    }

    @Test func parentRestartTerminalizesOldAttachedAndDetachedExecsBeforePublishingNewGeneration() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = ParentTeardownExecBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let container = try await runtime.createContainer(
            ContainerRecord(name: "parent-exec-restart", image: "debian")
        )
        try await runtime.startContainer(container.id)
        while !(await backend.isWaitingForContainerCompletion()) { await Task.yield() }
        let firstStartedAt = try #require(try await runtime.container(container.id).startedAt)

        let detached = try await runtime.createExec(
            container: container.id, configuration: .init(arguments: ["sleep", "30"])
        )
        let attached = try await runtime.createExec(
            container: container.id, configuration: .init(arguments: ["sleep", "30"])
        )
        try await runtime.startExec(detached.id)
        #expect(try await runtime.startAttachedExec(attached.id) == 123)
        while (await backend.waitingExecCount()) != 2 { await Task.yield() }

        try await runtime.restartContainer(container.id, timeoutSeconds: 0)

        // The old completion continuations are deliberately still suspended.
        // Restart itself must close the old exec generation.
        for identifier in [detached.id, attached.id] {
            let completed = try await runtime.inspectExec(identifier)
            #expect(!completed.running)
            #expect(completed.exitCode == 137)
            #expect(completed.pid == 81)
        }
        let restarted = try await runtime.container(container.id)
        #expect(restarted.phase == .running)
        #expect(restarted.restartCount == 1)
        #expect(restarted.startedAt != firstStartedAt)

        while (await backend.waitingContainerCount()) != 2 { await Task.yield() }
        await backend.finishContainer(code: 0)
        for _ in 0..<100 { await Task.yield() }
        #expect(try await runtime.container(container.id).phase == .running)
        await backend.releaseContainerCompletions()
    }

    @Test func explicitRestartRejectsExecBindingUntilOldGenerationIsReconciled() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingRestartExecGateBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let container = try await runtime.createContainer(
            ContainerRecord(name: "restart-exec-gate", image: "debian")
        )
        try await runtime.startContainer(container.id)
        let detached = try await runtime.createExec(
            container: container.id, configuration: .init(arguments: ["true"])
        )
        let attached = try await runtime.createExec(
            container: container.id, configuration: .init(arguments: ["true"])
        )

        let restart = Task { try await runtime.restartContainer(container.id, timeoutSeconds: 0) }
        while !(await backend.isReplacementReady()) { await Task.yield() }

        await #expect(throws: EngineError.self) {
            try await runtime.createExec(
                container: container.id, configuration: .init(arguments: ["new-generation"])
            )
        }
        await #expect(throws: EngineError.self) { try await runtime.startExec(detached.id) }
        await #expect(throws: EngineError.self) { _ = try await runtime.startAttachedExec(attached.id) }
        let blockedCounts = await backend.counts()
        #expect(blockedCounts.prepared == 2)
        #expect(blockedCounts.detached == 0)
        #expect(blockedCounts.attached == 0)

        await backend.releaseRestart()
        try await restart.value
        #expect(try await runtime.container(container.id).restartCount == 1)
        #expect(try await runtime.inspectExec(detached.id).exitCode == 137)
        #expect(try await runtime.inspectExec(attached.id).exitCode == 137)
    }

    @Test func staleExecPreparationCannotCrossParentExitAndExplicitRestart() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingStaleExecPreparationBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let container = try await runtime.createContainer(
            ContainerRecord(name: "stale-exec-generation", image: "debian")
        )
        try await runtime.startContainer(container.id)
        while !(await backend.isWaitingForCompletion()) { await Task.yield() }
        let firstStartedAt = try #require(try await runtime.container(container.id).startedAt)

        let create = Task {
            try await runtime.createExec(
                container: container.id, configuration: .init(arguments: ["true"])
            )
        }
        while !(await backend.isPrepareBlocked()) { await Task.yield() }
        let preparedID = try #require(await backend.preparedID())

        await backend.finishContainer(code: 23)
        for _ in 0..<100 {
            if try await runtime.container(container.id).phase == .exited { break }
            await Task.yield()
        }
        #expect(try await runtime.container(container.id).phase == .exited)
        do {
            try await runtime.restartContainer(container.id, timeoutSeconds: 0)
            Issue.record("restart crossed an active exec preparation after parent exit")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }
        #expect(await backend.startCount() == 1)

        await backend.releasePrepare()
        do {
            _ = try await create.value
            Issue.record("stale exec preparation was published after its parent exited")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }
        #expect(await backend.wasDiscarded(preparedID))
        await #expect(throws: EngineError.self) { try await runtime.exec(preparedID) }

        try await runtime.restartContainer(container.id, timeoutSeconds: 0)
        let restarted = try await runtime.container(container.id)
        #expect(restarted.phase == .running)
        #expect(restarted.startedAt != firstStartedAt)
        #expect(restarted.exitCode == nil)
        #expect(restarted.restartCount == 0)
        #expect(await backend.startCount() == 2)
    }

    @Test func attachedUpgradeValidatesExecStartBodyBeforeHijacking() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let socket = root.appending(path: "engine.sock").path
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root, backend: CompletionBackend(completionEnabled: false))
        let router = DockerRouter(runtime: runtime, root: root)
        let container = try await runtime.createContainer(ContainerRecord(name: "upgrade-validation", image: "debian"))
        try await runtime.startContainer(container.id)
        let exec = try await runtime.createExec(
            container: container.id,
            configuration: .init(arguments: ["true"], tty: false)
        )
        let server = DockerServer(socketPath: socket, router: router)
        try await server.start()
        defer { Task { try? await server.shutdown() } }

        let detached = try upgradedExecStart(
            socketPath: socket, execID: exec.id, body: #"{"Detach":true,"Tty":false}"#
        )
        #expect(detached.contains("400 Bad Request"), "curl output: \(detached)")
        let mismatchedTTY = try upgradedExecStart(
            socketPath: socket, execID: exec.id, body: #"{"Detach":false,"Tty":true}"#
        )
        #expect(mismatchedTTY.contains("400 Bad Request"), "curl output: \(mismatchedTTY)")
        #expect(try await runtime.exec(exec.id).running == false)
        #expect(try await runtime.exec(exec.id).exitCode == nil)
    }

    @Test func scopedSocketValidatesExecUpgradeBodyBeforeHijacking() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let sockets = URL(
            filePath: "/tmp/cengine-scope-upgrade-test-\(UUID().uuidString)",
            directoryHint: .isDirectory
        )
        defer {
            try? FileManager.default.removeItem(at: root)
            try? FileManager.default.removeItem(at: sockets)
        }
        let runtime = try await EngineRuntime(
            root: root, backend: CompletionBackend(completionEnabled: false)
        )
        let manager = ContainerResourceScopeManager(
            runtime: runtime, root: root, socketDirectory: sockets
        )
        do {
            let container = try await runtime.createContainer(
                ContainerRecord(name: "scoped-upgrade-validation", image: "debian")
            )
            try await runtime.startContainer(container.id)
            let exec = try await runtime.createExec(
                container: container.id,
                configuration: .init(arguments: ["true"], tty: false)
            )
            let scope = try await manager.create(
                ownerPID: getpid(), resources: .init(cpus: 1, memoryGiB: 1)
            )
            let socket = String(scope.dockerHost.dropFirst("unix://".count))

            let detached = try upgradedExecStart(
                socketPath: socket, execID: exec.id, body: #"{"Detach":true,"Tty":false}"#
            )
            #expect(detached.contains("400 Bad Request"), "curl output: \(detached)")
            let mismatchedTTY = try upgradedExecStart(
                socketPath: socket, execID: exec.id, body: #"{"Detach":false,"Tty":true}"#
            )
            #expect(mismatchedTTY.contains("400 Bad Request"), "curl output: \(mismatchedTTY)")
            #expect(try await runtime.exec(exec.id).running == false)
            #expect(try await runtime.exec(exec.id).exitCode == nil)
            try await manager.shutdown()
        } catch {
            try? await manager.shutdown()
            throw error
        }
    }

    @Test func startingContainerExcludesStopRemovalAndNetworkAttachmentChanges() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingStartBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let record = try await runtime.createContainer(ContainerRecord(name: "start-race", image: "debian"))
        let defaultNetwork = try #require(record.networks.first?.networkID)
        let extraNetwork = try await runtime.createNetwork(name: "start-race-extra")
        let start = Task { try await runtime.startContainer(record.id) }
        while !(await backend.hasEnteredStart()) { await Task.yield() }

        for operation in [
            { try await runtime.stopContainer(record.id) },
            { try await runtime.removeContainer(record.id, force: true) },
            { try await runtime.connectNetwork(extraNetwork.id, container: record.id) },
            { try await runtime.disconnectNetwork(defaultNetwork, container: record.id, force: false) },
        ] {
            do {
                try await operation()
                Issue.record("container lifecycle operation bypassed an in-progress start")
            } catch let error as EngineError {
                #expect(error.code == .conflict)
            }
        }

        await backend.releaseStart()
        try await start.value
        #expect(try await runtime.container(record.id).phase == .running)
        try await runtime.stopContainer(record.id)
        #expect(try await runtime.container(record.id).phase == .exited)
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

    @Test func concurrentContainerStartsLaunchOnlyOnce() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingStartBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let record = try await runtime.createContainer(ContainerRecord(name: "concurrent-start", image: "debian"))
        let first = Task { try await runtime.startContainer(record.id) }
        while !(await backend.hasEnteredStart()) { await Task.yield() }

        do {
            try await runtime.startContainer(record.id)
            Issue.record("a concurrent start launched the same container twice")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }

        await backend.releaseStart()
        try await first.value
        #expect(await backend.startCount() == 1)
        #expect(try await runtime.container(record.id).phase == .running)
    }

    @Test func stopAndNetworkMutationConflictWithAnInFlightStart() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingStartBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let extra = try await runtime.createNetwork(
            name: "start-race-network", subnet: "192.168.210.0/24", gateway: "192.168.210.1"
        )
        let record = try await runtime.createContainer(
            ContainerRecord(name: "start-stop-network-race", image: "debian")
        )
        let defaultNetwork = try #require(record.networks.first?.networkID)
        let start = Task { try await runtime.startContainer(record.id) }
        while !(await backend.hasEnteredStart()) { await Task.yield() }

        for operation in [
            { try await runtime.stopContainer(record.id) },
            { try await runtime.connectNetwork(extra.id, container: record.id) },
            { try await runtime.disconnectNetwork(defaultNetwork, container: record.id, force: false) },
        ] {
            do {
                try await operation()
                Issue.record("an operation reported success while the container was still starting")
            } catch let error as EngineError {
                #expect(error.code == .conflict)
            }
        }

        await backend.releaseStart()
        try await start.value
        #expect(try await runtime.container(record.id).phase == .running)
        #expect(try await runtime.container(record.id).networks.map(\.networkID) == [defaultNetwork])
    }

    @Test func resourceUpdateConflictsWithAnInFlightContainerStart() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingStartBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let record = try await runtime.createContainer(
            ContainerRecord(name: "start-update-race", image: "debian")
        )
        let start = Task { try await runtime.startContainer(record.id) }
        while !(await backend.hasEnteredStart()) { await Task.yield() }

        do {
            _ = try await runtime.updateContainer(
                record.id, memoryBytes: 8_192, nanoCPUs: nil,
                pidsLimit: nil, restartPolicy: nil
            )
            Issue.record("resource update overlapped an in-flight container start")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }

        await backend.releaseStart()
        try await start.value
        #expect(try await runtime.container(record.id).phase == .running)
        #expect(try await runtime.container(record.id).memoryBytes != 8_192)
    }

    @Test func startReResolvesItsContainerAfterEndpointAddressLookup() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingEndpointAddressBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let earlier = try await runtime.createContainer(
            ContainerRecord(name: "start-index-earlier", image: "debian")
        )
        let target = try await runtime.createContainer(
            ContainerRecord(name: "start-index-target", image: "debian")
        )
        let trailing = try await runtime.createContainer(
            ContainerRecord(name: "start-index-trailing", image: "debian")
        )

        await backend.blockNextEndpointLookup()
        let start = Task { try await runtime.startContainer(target.id) }
        while !(await backend.isEndpointLookupBlocked()) { await Task.yield() }
        try await runtime.removeContainer(earlier.id, force: false)
        await backend.releaseEndpointLookup()
        try await start.value

        let started = try await runtime.container(target.id)
        let sentinel = try await runtime.container(trailing.id)
        #expect(started.phase == .running)
        #expect(started.networks.first?.ipv4Address == "192.168.64.201")
        #expect(sentinel.id == trailing.id)
        #expect(sentinel.phase == .created)
        #expect(sentinel.networks.first?.ipv4Address != "192.168.64.201")
    }

    @Test func restartReResolvesItsContainerAfterEndpointAddressLookup() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingEndpointAddressBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let earlier = try await runtime.createContainer(
            ContainerRecord(name: "restart-index-earlier", image: "debian")
        )
        let target = try await runtime.createContainer(
            ContainerRecord(name: "restart-index-target", image: "debian")
        )
        let trailing = try await runtime.createContainer(
            ContainerRecord(name: "restart-index-trailing", image: "debian")
        )
        try await runtime.startContainer(target.id)

        await backend.blockNextEndpointLookup()
        let restart = Task { try await runtime.restartContainer(target.id, timeoutSeconds: 0) }
        while !(await backend.isEndpointLookupBlocked()) { await Task.yield() }
        try await runtime.removeContainer(earlier.id, force: false)
        await backend.releaseEndpointLookup()
        try await restart.value

        let restarted = try await runtime.container(target.id)
        let sentinel = try await runtime.container(trailing.id)
        #expect(restarted.phase == .running)
        #expect(restarted.restartCount == 1)
        #expect(restarted.networks.first?.ipv4Address == "192.168.64.202")
        #expect(sentinel.id == trailing.id)
        #expect(sentinel.phase == .created)
        #expect(sentinel.networks.first?.ipv4Address != "192.168.64.202")
    }

    @Test func restartPreservesHealthAndRejectsAStaleHealthcheckAcrossItsGeneration() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingEndpointAddressBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        var input = ContainerRecord(name: "restart-health-generation", image: "debian")
        input.healthcheck = .init(
            test: ["CMD", "true"], intervalNanoseconds: 1_000_000,
            timeoutNanoseconds: 1_000_000_000, retries: 1, startPeriodNanoseconds: 0
        )
        input.healthStatus = "starting"
        input.healthFailingStreak = 0
        await backend.blockHealthcheck(call: 2, exitCode: 1)
        let target = try await runtime.createContainer(input)
        try await runtime.startContainer(target.id)

        for _ in 0..<1_000 {
            if try await runtime.container(target.id).healthStatus == "healthy" { break }
            try await Task.sleep(for: .milliseconds(1))
        }
        #expect(try await runtime.container(target.id).healthStatus == "healthy")
        while !(await backend.isHealthcheckBlocked()) { await Task.yield() }
        let originalStartedAt = try #require(try await runtime.container(target.id).startedAt)

        await backend.blockNextEndpointLookup()
        let restart = Task { try await runtime.restartContainer(target.id, timeoutSeconds: 0) }
        while !(await backend.isEndpointLookupBlocked()) { await Task.yield() }

        // Checked continuations do not observe task cancellation themselves.
        // Releasing this failed result proves the canceled old-generation
        // monitor is fenced before it can mutate the still-published record.
        await backend.releaseHealthcheck()
        for _ in 0..<100 { await Task.yield() }
        let duringRestart = try await runtime.container(target.id)
        #expect(duringRestart.startedAt == originalStartedAt)
        #expect(duringRestart.healthStatus == "healthy")
        #expect(duringRestart.healthFailingStreak == 0)

        await backend.releaseEndpointLookup()
        try await restart.value
        let restarted = try await runtime.container(target.id)
        #expect(restarted.phase == .running)
        #expect(restarted.startedAt != originalStartedAt)
        #expect(restarted.restartCount == 1)
        #expect(restarted.healthStatus == "healthy")
        #expect(restarted.healthFailingStreak == 0)
    }

    @Test func canceledCompletionMonitorCannotRegisterAgainstRestartedGeneration() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = GenerationCompletionBackend()
        let entryGate = CompletionMonitorEntryGate()
        let runtime = try await EngineRuntime(
            root: root,
            backend: backend,
            beforeCompletionMonitoring: { await entryGate.enter() }
        )
        let record = try await runtime.createContainer(
            ContainerRecord(name: "completion-monitor-generation", image: "debian")
        )
        try await runtime.startContainer(record.id)
        while !(await entryGate.firstEntryIsBlocked()) { await Task.yield() }
        let originalStartedAt = try #require(try await runtime.container(record.id).startedAt)

        // The first generation's task is suspended before entering
        // monitorContainer. Restart cancels it and publishes a replacement whose
        // monitor passes the gate and owns the backend completion waiter.
        try await runtime.restartContainer(record.id, timeoutSeconds: 0)
        while await backend.registrationCount() != 1 { await Task.yield() }
        let restarted = try await runtime.container(record.id)
        #expect(restarted.phase == .running)
        #expect(restarted.startedAt != originalStartedAt)

        // Releasing a checked continuation does not clear task cancellation. A
        // stale monitor that reads the replacement record before checking that
        // flag would register a second completion and displace its waiter.
        await entryGate.releaseFirstEntry()
        for _ in 0..<100 { await Task.yield() }
        #expect(await backend.registrationCount() == 1)

        await backend.complete(code: 23)
        for _ in 0..<1_000 {
            if try await runtime.container(record.id).phase == .exited { break }
            await Task.yield()
        }
        let completed = try await runtime.container(record.id)
        #expect(completed.phase == .exited)
        #expect(completed.exitCode == 23)
        #expect(completed.startedAt == restarted.startedAt)
    }

    @Test func restartFailureAfterStoppingOldExecutionCleansAndTerminalizesItsGeneration() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = RestartFailurePathBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        var input = ContainerRecord(name: "restart-failure-cleanup", image: "debian")
        input.healthcheck = .init(
            test: ["CMD", "true"], intervalNanoseconds: 1_000_000,
            timeoutNanoseconds: 1_000_000_000, retries: 1, startPeriodNanoseconds: 0
        )
        let record = try await runtime.createContainer(input)
        await backend.blockNextHealthcheck()
        try await runtime.startContainer(record.id)
        while !(await backend.isHealthcheckBlocked()) { await Task.yield() }
        while !(await backend.isWaitingForCompletion(record.id)) { await Task.yield() }

        let exec = try await runtime.createExec(
            container: record.id, configuration: .init(arguments: ["sleep", "30"])
        )
        try await runtime.startExec(exec.id)
        let wait = try await runtime.subscribeContainerWait(record.id, condition: "next-exit")
        var waitIterator = wait.stream.makeAsyncIterator()

        await backend.failRestartAfterStop()
        await #expect(throws: RestartFailurePathBackend.Failure.self) {
            try await runtime.restartContainer(record.id, timeoutSeconds: 0)
        }

        let failed = try await runtime.container(record.id)
        #expect(failed.phase == .exited)
        #expect(failed.exitCode == 127)
        #expect(failed.restartCount == 0)
        #expect(!(await backend.isRunning(record.id)))
        #expect(!(await backend.isPrepared(record.id)))
        #expect(!(await backend.isWaitingForCompletion(record.id)))
        #expect(try await runtime.inspectExec(exec.id).exitCode == 137)
        #expect(await waitIterator.next() == 127)
        let durable = try await AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json"))
            .load(default: EngineSnapshot())
        #expect(durable.containers.first(where: { $0.id == record.id })?.phase == .exited)

        // The checked continuation itself is not cancellation-aware. Releasing
        // it proves the canceled health task cannot schedule another check.
        #expect(await backend.healthcheckCount() == 1)
        await backend.releaseHealthcheck()
        try await Task.sleep(for: .milliseconds(150))
        #expect(await backend.healthcheckCount() == 1)

        let history = await runtime.events(since: Date().addingTimeInterval(-60), until: Date())
        var historyIterator = history.makeAsyncIterator()
        var actions: [String] = []
        while let event = await historyIterator.next() {
            if event.id == record.id { actions.append(event.action) }
        }
        #expect(!actions.contains("restart"))

        // The failure released both the lifecycle intent and the starting marker.
        try await runtime.startContainer(record.id)
        #expect(try await runtime.container(record.id).phase == .running)
        #expect(await backend.isRunning(record.id))
    }

    @Test func failedRestartAppliesPolicyAndAutoRemoveAfterReleasingItsClaim() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = RestartFailurePathBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)

        var policyInput = ContainerRecord(name: "restart-failure-policy", image: "debian")
        policyInput.restartPolicy = .init(name: "always")
        let policy = try await runtime.createContainer(policyInput)
        try await runtime.startContainer(policy.id)
        await backend.failRestartAfterStop()
        await #expect(throws: RestartFailurePathBackend.Failure.self) {
            try await runtime.restartContainer(policy.id, timeoutSeconds: 0)
        }
        let recovered = try await runtime.container(policy.id)
        #expect(recovered.phase == .running)
        #expect(recovered.restartCount == 1)
        #expect(await backend.isRunning(policy.id))

        var removeInput = ContainerRecord(name: "restart-failure-remove", image: "debian")
        removeInput.autoRemove = true
        let removed = try await runtime.createContainer(removeInput)
        try await runtime.startContainer(removed.id)
        await backend.failRestartAfterStop()
        await #expect(throws: RestartFailurePathBackend.Failure.self) {
            try await runtime.restartContainer(removed.id, timeoutSeconds: 0)
        }
        await #expect(throws: EngineError.self) { try await runtime.container(removed.id) }
        #expect(!(await backend.isRunning(removed.id)))
        #expect(!(await backend.isPrepared(removed.id)))
    }

    @Test func startPersistenceFailureRollsBackBackendAndDurableState() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = RestartFailurePathBackend()
        let saveFailure = ArmedStateSaveFailure()
        let runtime = try await EngineRuntime(
            root: root,
            backend: backend,
            beforePersistence: { try await saveFailure.failWhenArmed() }
        )
        let record = try await runtime.createContainer(
            ContainerRecord(name: "start-save-failure", image: "debian")
        )

        await saveFailure.arm()
        await #expect(throws: ArmedStateSaveFailure.Failure.self) {
            try await runtime.startContainer(record.id)
        }

        #expect(try await runtime.container(record.id).phase == .created)
        #expect(!(await backend.isRunning(record.id)))
        #expect(!(await backend.isPrepared(record.id)))
        let durable = try await AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json"))
            .load(default: EngineSnapshot())
        #expect(durable.containers.first(where: { $0.id == record.id })?.phase == .created)

        let history = await runtime.events(since: Date().addingTimeInterval(-60), until: Date())
        var historyIterator = history.makeAsyncIterator()
        var actions: [String] = []
        while let event = await historyIterator.next() {
            if event.id == record.id { actions.append(event.action) }
        }
        #expect(!actions.contains("start"))

        try await runtime.startContainer(record.id)
        #expect(try await runtime.container(record.id).phase == .running)
        #expect(await backend.isRunning(record.id))
    }

    @Test func partialBackendStartFailureIsCompensatedAndRetryableAfterReload() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = PartialStartFailureBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        var input = ContainerRecord(name: "partial-start-failure", image: "debian")
        input.healthcheck = .init(
            test: ["CMD", "true"], intervalNanoseconds: 1_000_000,
            timeoutNanoseconds: 1_000_000_000, retries: 1, startPeriodNanoseconds: 0
        )
        let record = try await runtime.createContainer(input)

        await #expect(throws: PartialStartFailureBackend.Failure.self) {
            try await runtime.startContainer(record.id)
        }

        #expect(try await runtime.container(record.id).phase == .created)
        #expect(!(await backend.isRunning(record.id)))
        #expect(!(await backend.isPrepared(record.id)))
        let failedCounts = await backend.counts()
        #expect(failedCounts.starts == 1)
        #expect(failedCounts.stops == 1)
        #expect(failedCounts.deletes == 1)
        #expect(failedCounts.completions == 0)
        #expect(failedCounts.healthchecks == 0)
        let durable = try await AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json"))
            .load(default: EngineSnapshot())
        #expect(durable.containers.first(where: { $0.id == record.id })?.phase == .created)

        let history = await runtime.events(since: Date().addingTimeInterval(-60), until: Date())
        var historyIterator = history.makeAsyncIterator()
        var actions: [String] = []
        while let event = await historyIterator.next() {
            if event.id == record.id { actions.append(event.action) }
        }
        #expect(!actions.contains("start"))

        await runtime.shutdown()
        let reloaded = try await EngineRuntime(root: root, backend: backend)
        #expect(try await reloaded.container(record.id).phase == .created)
        try await reloaded.startContainer(record.id)
        #expect(try await reloaded.container(record.id).phase == .running)
        #expect(await backend.isRunning(record.id))
        #expect(await backend.counts().starts == 2)
        await reloaded.shutdown()
    }

    @Test func failedStartCleanupStaysQuarantinedUntilReloadVerifiesTeardown() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = QuarantinedExecutionBackend()
        let saveFailure = ArmedStateSaveFailure()
        let runtime = try await EngineRuntime(
            root: root,
            backend: backend,
            beforePersistence: { try await saveFailure.failWhenArmed() }
        )
        let record = try await runtime.createContainer(
            ContainerRecord(name: "start-cleanup-quarantine", image: "debian")
        )
        // The first quarantine save fails, then the retry after cleanup failure
        // must make `.dead` durable rather than leaving `.created` on disk.
        await saveFailure.arm()
        await backend.failStartAndCleanup()

        await #expect(throws: EngineError.self) {
            try await runtime.startContainer(record.id)
        }

        #expect(try await runtime.container(record.id).phase == .dead)
        #expect(await backend.isRunning(record.id))
        let durableFailure = try await AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json"))
            .load(default: EngineSnapshot())
        #expect(durableFailure.containers.first(where: { $0.id == record.id })?.phase == .dead)
        let failedCounts = await backend.counts()
        #expect(failedCounts.starts == 1)
        #expect(failedCounts.stops == 1)
        #expect(failedCounts.deletes == 1)

        // A same-daemon retry cannot cross the quarantine while definitive
        // backend deletion is still failing.
        await #expect(throws: QuarantinedExecutionBackend.Failure.self) {
            try await runtime.startContainer(record.id)
        }
        #expect(try await runtime.container(record.id).phase == .dead)
        #expect(await backend.isRunning(record.id))

        await runtime.shutdown()
        await #expect(throws: EngineError.self) {
            _ = try await EngineRuntime(root: root, backend: backend)
        }
        #expect(await backend.isRunning(record.id))
        let beforeRecovery = await backend.counts()
        await backend.allowCleanup()
        let reloaded = try await EngineRuntime(root: root, backend: backend)
        #expect(!(await backend.isRunning(record.id)))
        #expect(try await reloaded.container(record.id).phase == .created)
        let recoveredCounts = await backend.counts()
        #expect(recoveredCounts.stops == beforeRecovery.stops + 1)
        #expect(recoveredCounts.deletes == beforeRecovery.deletes + 1)

        try await reloaded.startContainer(record.id)
        #expect(await backend.isRunning(record.id))
        #expect(try await reloaded.container(record.id).phase == .running)
        await reloaded.shutdown()
    }

    @Test func successfulDeleteVerifiesFailedStartCleanupAfterStopFailure() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = QuarantinedExecutionBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let record = try await runtime.createContainer(
            ContainerRecord(name: "delete-verifies-cleanup", image: "debian")
        )
        await backend.failStartAndStopOnly()

        await #expect(throws: QuarantinedExecutionBackend.Failure.self) {
            try await runtime.startContainer(record.id)
        }

        #expect(try await runtime.container(record.id).phase == .created)
        #expect(!(await backend.isRunning(record.id)))
        let counts = await backend.counts()
        #expect(counts.stops == 1)
        #expect(counts.deletes == 1)
        await runtime.shutdown()
    }

    @Test func failedRestartCleanupStaysQuarantinedUntilReloadVerifiesTeardown() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = QuarantinedExecutionBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let record = try await runtime.createContainer(
            ContainerRecord(name: "restart-cleanup-quarantine", image: "debian")
        )
        try await runtime.startContainer(record.id)
        await backend.failRestartAndCleanup()

        await #expect(throws: EngineError.self) {
            try await runtime.restartContainer(record.id, timeoutSeconds: 0)
        }

        #expect(try await runtime.container(record.id).phase == .dead)
        #expect(await backend.isRunning(record.id))
        let durableFailure = try await AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json"))
            .load(default: EngineSnapshot())
        #expect(durableFailure.containers.first(where: { $0.id == record.id })?.phase == .dead)

        await runtime.shutdown()
        await backend.allowCleanup()
        let reloaded = try await EngineRuntime(root: root, backend: backend)
        #expect(!(await backend.isRunning(record.id)))
        let recovered = try await reloaded.container(record.id)
        #expect(recovered.phase == .exited)
        #expect(recovered.exitCode == 127)

        try await reloaded.startContainer(record.id)
        #expect(await backend.isRunning(record.id))
        #expect(try await reloaded.container(record.id).phase == .running)
        #expect(await backend.counts().starts == 2)
        await reloaded.shutdown()
    }

    @Test func preparationFailureRetainsPreparedBackendForSafeRetry() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = PartialStartFailureBackend(failStartAfterLaunch: false)
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let record = try await runtime.createContainer(
            ContainerRecord(name: "prepare-retry-boundary", image: "debian")
        )
        await backend.failNextPrepare()

        await #expect(throws: PartialStartFailureBackend.Failure.self) {
            try await runtime.startContainer(record.id)
        }

        let failedCounts = await backend.counts()
        #expect(failedCounts.starts == 0)
        #expect(failedCounts.stops == 0)
        #expect(failedCounts.deletes == 0)
        #expect(await backend.isPrepared(record.id))
        #expect(try await runtime.container(record.id).phase == .created)

        try await runtime.startContainer(record.id)
        #expect(await backend.counts().starts == 1)
        #expect(await backend.isRunning(record.id))
        #expect(try await runtime.container(record.id).phase == .running)
        await runtime.shutdown()
    }

    @Test func restartPersistenceFailureCleansReplacementAndAllowsRetry() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = RestartFailurePathBackend()
        let saveFailure = ArmedStateSaveFailure()
        let runtime = try await EngineRuntime(
            root: root,
            backend: backend,
            beforePersistence: { try await saveFailure.failWhenArmed() }
        )
        let record = try await runtime.createContainer(
            ContainerRecord(name: "restart-save-failure", image: "debian")
        )
        try await runtime.startContainer(record.id)
        while !(await backend.isWaitingForCompletion(record.id)) { await Task.yield() }

        await saveFailure.arm()
        await #expect(throws: ArmedStateSaveFailure.Failure.self) {
            try await runtime.restartContainer(record.id, timeoutSeconds: 0)
        }

        let failed = try await runtime.container(record.id)
        #expect(failed.phase == .exited)
        #expect(failed.exitCode == 127)
        #expect(failed.restartCount == 0)
        #expect(!(await backend.isRunning(record.id)))
        #expect(!(await backend.isPrepared(record.id)))
        #expect(!(await backend.isWaitingForCompletion(record.id)))
        let durable = try await AtomicStore<EngineSnapshot>(url: root.appending(path: "engine.json"))
            .load(default: EngineSnapshot())
        #expect(durable.containers.first(where: { $0.id == record.id })?.phase == .exited)

        let history = await runtime.events(since: Date().addingTimeInterval(-60), until: Date())
        var historyIterator = history.makeAsyncIterator()
        var actions: [String] = []
        while let event = await historyIterator.next() {
            if event.id == record.id { actions.append(event.action) }
        }
        #expect(!actions.contains("restart"))
        #expect(actions.filter { $0 == "start" }.count == 1)

        try await runtime.restartContainer(record.id, timeoutSeconds: 0)
        #expect(try await runtime.container(record.id).phase == .running)
        #expect(await backend.isRunning(record.id))
    }

    @Test func killConflictsForTheEntireRestartCommit() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingEndpointAddressBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        var restartPolicyRecord = ContainerRecord(name: "restart-kill-policy", image: "debian")
        restartPolicyRecord.restartPolicy = .init(name: "always")
        var autoRemoveRecord = ContainerRecord(name: "restart-kill-remove", image: "debian")
        autoRemoveRecord.autoRemove = true

        for input in [restartPolicyRecord, autoRemoveRecord] {
            let record = try await runtime.createContainer(input)
            try await runtime.startContainer(record.id)
            let originalStartedAt = try #require(try await runtime.container(record.id).startedAt)
            await backend.blockNextEndpointLookup()
            let restart = Task { try await runtime.restartContainer(record.id, timeoutSeconds: 0) }
            while !(await backend.isEndpointLookupBlocked()) { await Task.yield() }

            do {
                try await runtime.killContainer(record.id, signal: "KILL")
                Issue.record("kill terminalized a container before its restart commit completed")
            } catch let error as EngineError {
                #expect(error.code == .conflict)
            }
            #expect(await backend.counts().kills == 0)
            let pending = try await runtime.container(record.id)
            #expect(pending.phase == .running)
            #expect(pending.startedAt == originalStartedAt)
            #expect(pending.restartCount == 0)

            await backend.releaseEndpointLookup()
            try await restart.value
            let restarted = try await runtime.container(record.id)
            #expect(restarted.phase == .running)
            #expect(restarted.startedAt != originalStartedAt)
            #expect(restarted.restartCount == 1)
        }
        #expect(await backend.counts().starts == 4)
        #expect((await runtime.listContainers(all: true)).count == 2)
    }

    @Test func killCannotTerminalizeAContainerDuringItsStartCommit() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingEndpointAddressBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        var restartPolicyRecord = ContainerRecord(name: "start-kill-restart", image: "debian")
        restartPolicyRecord.restartPolicy = .init(name: "always")
        var autoRemoveRecord = ContainerRecord(name: "start-kill-remove", image: "debian")
        autoRemoveRecord.autoRemove = true

        for input in [restartPolicyRecord, autoRemoveRecord] {
            let record = try await runtime.createContainer(input)
            await backend.blockNextEndpointLookup()
            let start = Task { try await runtime.startContainer(record.id) }
            while !(await backend.isEndpointLookupBlocked()) { await Task.yield() }

            do {
                try await runtime.killContainer(record.id, signal: "KILL")
                Issue.record("kill terminalized a container before its start commit completed")
            } catch let error as EngineError {
                #expect(error.code == .conflict)
            }
            #expect(await backend.counts().kills == 0)

            await backend.releaseEndpointLookup()
            try await start.value
            let started = try await runtime.container(record.id)
            #expect(started.phase == .running)
            #expect(started.restartCount == 0)
        }
        #expect(await backend.counts().starts == 2)
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

    @Test func containerPruneClaimsEveryCandidateBeforeDeletingAnyBackendState() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingContainerDeleteBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let first = try await runtime.createContainer(ContainerRecord(name: "prune-first", image: "debian"))
        let second = try await runtime.createContainer(ContainerRecord(name: "prune-second", image: "debian"))
        let prune = Task { try await runtime.pruneContainers() }
        while await backend.blockedID() == nil { await Task.yield() }

        do {
            try await runtime.startContainer(second.id)
            Issue.record("container start bypassed an in-progress prune")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }

        await backend.releaseDelete()
        #expect(Set(try await prune.value) == [first.id, second.id])
        #expect(await runtime.listContainers(all: true).isEmpty)
    }

    @Test func failedContainerPruneReleasesClaimsAndRetainsMetadata() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingContainerDeleteBackend(failBlockedDelete: true)
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let first = try await runtime.createContainer(ContainerRecord(name: "failed-prune-first", image: "debian"))
        let second = try await runtime.createContainer(ContainerRecord(name: "failed-prune-second", image: "debian"))
        let prune = Task { try await runtime.pruneContainers() }
        while await backend.blockedID() == nil { await Task.yield() }

        await backend.releaseDelete()
        await #expect(throws: BlockingContainerDeleteBackend.Failure.self) { try await prune.value }
        #expect(Set(await runtime.listContainers(all: true).map(\.id)) == [first.id, second.id])

        try await runtime.startContainer(second.id)
        #expect(try await runtime.container(second.id).phase == .running)
    }

    @Test func pruneReservesEachContainerAgainstConcurrentStart() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingPruneDeleteBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let record = try await runtime.createContainer(ContainerRecord(name: "prune-start-race", image: "debian"))
        let prune = Task { try await runtime.pruneContainers(ids: [record.id]) }
        while !(await backend.hasEnteredDelete()) { await Task.yield() }

        do {
            try await runtime.startContainer(record.id)
            Issue.record("container started while prune held its removal reservation")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }

        await backend.releaseDelete()
        #expect(try await prune.value == [record.id])
        #expect(await runtime.listContainers(all: true).isEmpty)
    }

    @Test func resourceUpdateReResolvesByIDAndConflictsWithConcurrentRemoval() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingResourceUpdateBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let first = try await runtime.createContainer(ContainerRecord(name: "update-index-first", image: "debian"))
        let target = try await runtime.createContainer(ContainerRecord(name: "update-index-target", image: "debian"))
        let update = Task {
            try await runtime.updateContainer(
                target.id, memoryBytes: 8_192, nanoCPUs: nil, pidsLimit: nil, restartPolicy: nil
            )
        }
        while !(await backend.hasEnteredUpdate()) { await Task.yield() }

        try await runtime.removeContainer(first.id, force: false)
        do {
            try await runtime.removeContainer(target.id, force: false)
            Issue.record("container removal overlapped an in-flight resource update")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }

        await backend.releaseUpdate()
        let updated = try await update.value
        #expect(updated.id == target.id)
        #expect(updated.memoryBytes == 8_192)
        #expect(try await runtime.container(target.id).memoryBytes == 8_192)
    }

    @Test func networkMutationsReResolveByIDAndReserveTheirContainer() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingNetworkUpdateBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let first = try await runtime.createContainer(
            ContainerRecord(name: "network-index-first", image: "debian")
        )
        let second = try await runtime.createContainer(
            ContainerRecord(name: "network-index-second", image: "debian")
        )
        let target = try await runtime.createContainer(
            ContainerRecord(name: "network-index-target", image: "debian")
        )
        let extra = try await runtime.createNetwork(
            name: "network-index-extra", subnet: "192.168.211.0/24", gateway: "192.168.211.1"
        )

        await backend.blockNextNetworkUpdate()
        let connect = Task { try await runtime.connectNetwork(extra.id, container: target.id) }
        while !(await backend.isNetworkUpdateBlocked()) { await Task.yield() }
        do {
            try await runtime.startContainer(target.id)
            Issue.record("container start overlapped an in-flight network connection")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }
        try await runtime.removeContainer(first.id, force: false)
        await backend.releaseNetworkUpdate()
        try await connect.value
        #expect(try await runtime.container(target.id).networks.contains { $0.networkID == extra.id })

        await backend.blockNextNetworkUpdate()
        let disconnect = Task {
            try await runtime.disconnectNetwork(extra.id, container: target.id, force: false)
        }
        while !(await backend.isNetworkUpdateBlocked()) { await Task.yield() }
        do {
            try await runtime.removeContainer(target.id, force: false)
            Issue.record("container removal overlapped an in-flight network disconnection")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }
        try await runtime.removeContainer(second.id, force: false)
        await backend.releaseNetworkUpdate()
        try await disconnect.value
        #expect(try await runtime.container(target.id).networks.allSatisfy { $0.networkID != extra.id })
    }

    @Test func automaticRestartReservesContainerAgainstPruneAndUpdate() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingReconciliationBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        var record = ContainerRecord(name: "reconcile-restart-race", image: "debian")
        record.restartPolicy = .init(name: "always")
        record = try await runtime.createContainer(record)
        try await runtime.startContainer(record.id)
        while !(await backend.isWaitingForCompletion(record.id)) { await Task.yield() }

        await backend.finish(record.id, code: 17)
        while !(await backend.hasBlockedReconciliationDelete()) { await Task.yield() }

        #expect(try await runtime.pruneContainers(ids: [record.id]).isEmpty)
        do {
            _ = try await runtime.updateContainer(
                record.id, memoryBytes: 8_192, nanoCPUs: nil,
                pidsLimit: nil, restartPolicy: nil
            )
            Issue.record("resource update overlapped an automatic restart")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }
        do {
            try await runtime.renameContainer(record.id, name: "restart-race-renamed-too-early")
            Issue.record("rename overlapped an automatic restart")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }

        await backend.releaseReconciliationDelete()
        for _ in 0..<100 {
            if try await runtime.container(record.id).phase == .running,
               try await runtime.container(record.id).restartCount == 1 { break }
            await Task.yield()
        }
        let restarted = try await runtime.container(record.id)
        #expect(restarted.phase == .running)
        #expect(restarted.restartCount == 1)
        var renamed = false
        for _ in 0..<1_000 {
            do {
                try await runtime.renameContainer(record.id, name: "restart-race-renamed")
                renamed = true
                break
            } catch let error as EngineError where error.code == .conflict {
                await Task.yield()
            }
        }
        #expect(renamed)
        #expect(try await runtime.container(record.id).name == "restart-race-renamed")
        let counts = await backend.counts()
        #expect(counts.prepares == 3)
        #expect(counts.starts == 2)
        #expect(counts.deletes == 1)
    }

    @Test func automaticRestartReservesContainerAgainstNetworkMutation() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingReconciliationBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let extra = try await runtime.createNetwork(
            name: "restart-race-network", subnet: "192.168.212.0/24", gateway: "192.168.212.1"
        )
        var record = ContainerRecord(name: "restart-network-race", image: "debian")
        record.restartPolicy = .init(name: "always")
        record = try await runtime.createContainer(record)
        let defaultNetwork = try #require(record.networks.first?.networkID)
        try await runtime.startContainer(record.id)
        while !(await backend.isWaitingForCompletion(record.id)) { await Task.yield() }

        await backend.finish(record.id, code: 17)
        while !(await backend.hasBlockedReconciliationDelete()) { await Task.yield() }
        do {
            try await runtime.connectNetwork(extra.id, container: record.id)
            Issue.record("network connection overlapped automatic restart")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }
        do {
            try await runtime.disconnectNetwork(defaultNetwork, container: record.id, force: false)
            Issue.record("network disconnection overlapped automatic restart")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }

        await backend.releaseReconciliationDelete()
        for _ in 0..<100 {
            if try await runtime.container(record.id).phase == .running { break }
            await Task.yield()
        }
        let restarted = try await runtime.container(record.id)
        #expect(restarted.phase == .running)
        #expect(restarted.networks.map(\.networkID) == [defaultNetwork])
    }

    @Test func automaticRemovalReservesContainerAgainstConcurrentLifecycleWork() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingReconciliationBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        var record = ContainerRecord(name: "reconcile-remove-race", image: "debian")
        record.autoRemove = true
        record = try await runtime.createContainer(record)
        try await runtime.startContainer(record.id)
        while !(await backend.isWaitingForCompletion(record.id)) { await Task.yield() }

        await backend.finish(record.id, code: 0)
        while !(await backend.hasBlockedReconciliationDelete()) { await Task.yield() }

        #expect(try await runtime.pruneContainers(ids: [record.id]).isEmpty)
        do {
            _ = try await runtime.updateContainer(
                record.id, memoryBytes: 8_192, nanoCPUs: nil,
                pidsLimit: nil, restartPolicy: nil
            )
            Issue.record("resource update overlapped automatic removal")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }
        do {
            try await runtime.removeContainer(record.id, force: false)
            Issue.record("explicit removal overlapped automatic removal")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }

        await backend.releaseReconciliationDelete()
        for _ in 0..<100 {
            if (try? await runtime.container(record.id)) == nil { break }
            await Task.yield()
        }
        do {
            _ = try await runtime.container(record.id)
            Issue.record("auto-remove reconciliation did not remove its container")
        } catch let error as EngineError {
            #expect(error.code == .notFound)
        }
        #expect(await backend.counts().deletes == 1)
    }

    @Test func exitDuringUpdateIsReconciledThroughRestartPolicy() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = UpdateExitRaceBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        var record = ContainerRecord(name: "update-exit-restart", image: "debian")
        record.restartPolicy = .init(name: "always")
        record = try await runtime.createContainer(record)
        let containerID = record.id
        try await runtime.startContainer(containerID)
        while !(await backend.isWaitingForCompletion()) { await Task.yield() }

        let update = Task {
            try await runtime.updateContainer(
                containerID, memoryBytes: 8_192, nanoCPUs: nil, pidsLimit: nil, restartPolicy: nil
            )
        }
        while !(await backend.isUpdateBlocked()) { await Task.yield() }
        await backend.finish(code: 17)
        while try await runtime.container(containerID).phase != .exited { await Task.yield() }
        #expect(await backend.counts().starts == 1)

        await backend.releaseUpdate()
        _ = try await update.value
        let restarted = try await runtime.container(containerID)
        #expect(restarted.phase == .running)
        #expect(restarted.restartCount == 1)
        #expect(restarted.memoryBytes == 8_192)
        #expect(await backend.counts().starts == 2)
    }

    @Test func autoRemoveExitDuringUpdateIsReconciledAfterUpdate() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = UpdateExitRaceBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        var record = ContainerRecord(name: "update-exit-remove", image: "debian")
        record.autoRemove = true
        record = try await runtime.createContainer(record)
        let containerID = record.id
        try await runtime.startContainer(containerID)
        while !(await backend.isWaitingForCompletion()) { await Task.yield() }

        let update = Task {
            try await runtime.updateContainer(
                containerID, memoryBytes: 8_192, nanoCPUs: nil, pidsLimit: nil, restartPolicy: nil
            )
        }
        while !(await backend.isUpdateBlocked()) { await Task.yield() }
        await backend.finish(code: 0)
        while try await runtime.container(containerID).phase != .exited { await Task.yield() }

        await backend.releaseUpdate()
        _ = try await update.value
        do {
            _ = try await runtime.container(containerID)
            Issue.record("auto-remove container survived an exit during update")
        } catch let error as EngineError {
            #expect(error.code == .notFound)
        }
        #expect(await backend.counts().deletes == 1)
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

    @Test func pauseAndResumeReResolveByIDAndReserveTheirContainer() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = BlockingPauseResumeBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let first = try await runtime.createContainer(
            ContainerRecord(name: "pause-index-first", image: "debian")
        )
        let second = try await runtime.createContainer(
            ContainerRecord(name: "pause-index-second", image: "debian")
        )
        let target = try await runtime.createContainer(
            ContainerRecord(name: "pause-index-target", image: "debian")
        )
        try await runtime.startContainer(target.id)

        let pause = Task { try await runtime.pauseContainer(target.id) }
        while !(await backend.isPauseBlocked()) { await Task.yield() }
        do {
            try await runtime.stopContainer(target.id)
            Issue.record("container stop overlapped an in-flight pause")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }
        try await runtime.removeContainer(first.id, force: false)
        await backend.releasePause()
        try await pause.value
        #expect(try await runtime.container(target.id).phase == .paused)

        let resume = Task { try await runtime.resumeContainer(target.id) }
        while !(await backend.isResumeBlocked()) { await Task.yield() }
        do {
            try await runtime.removeContainer(target.id, force: true)
            Issue.record("container removal overlapped an in-flight resume")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }
        try await runtime.removeContainer(second.id, force: false)
        await backend.releaseResume()
        try await resume.value
        #expect(try await runtime.container(target.id).phase == .running)
    }

    @Test func containerExitDuringPauseCannotBeOverwrittenByThePauseCommit() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let backend = PauseExitRaceBackend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let record = try await runtime.createContainer(
            ContainerRecord(name: "pause-exit-race", image: "debian")
        )
        try await runtime.startContainer(record.id)
        while !(await backend.isWaitingForCompletion()) { await Task.yield() }

        let pause = Task { try await runtime.pauseContainer(record.id) }
        while !(await backend.isPauseBlocked()) { await Task.yield() }
        await backend.finish(code: 19)
        while try await runtime.container(record.id).phase != .exited { await Task.yield() }
        await backend.releasePause()
        do {
            try await pause.value
            Issue.record("pause overwrote a terminal container execution")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }
        let completed = try await runtime.container(record.id)
        #expect(completed.phase == .exited)
        #expect(completed.exitCode == 19)
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

    @Test func containerPruneFiltersLimitDeletionAndRejectUnknownKeys() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root, backend: CompletionBackend(completionEnabled: false))
        let router = DockerRouter(runtime: runtime, root: root)

        var selected = ContainerRecord(name: "selected", image: "debian")
        selected.labels = ["prune": "yes", "tier": "frontend"]
        selected.createdAt = Date(timeIntervalSince1970: 100)
        selected = try await runtime.createContainer(selected)
        var wrongLabel = ContainerRecord(name: "wrong-label", image: "debian")
        wrongLabel.labels = ["prune": "no", "tier": "frontend"]
        wrongLabel.createdAt = Date(timeIntervalSince1970: 100)
        wrongLabel = try await runtime.createContainer(wrongLabel)
        var tooNew = ContainerRecord(name: "too-new", image: "debian")
        tooNew.labels = ["prune": "yes", "tier": "backend"]
        tooNew.createdAt = Date(timeIntervalSince1970: 200)
        tooNew = try await runtime.createContainer(tooNew)

        let unsupported = await router.route(.init(
            method: .POST,
            uri: "/v1.44/containers/prune?filters=%7B%22name%22%3A%5B%22selected%22%5D%7D"
        ))
        #expect(unsupported.status == .badRequest)
        #expect(await runtime.listContainers(all: true).count == 3)

        let falseMap = #"{"label":{"missing=value":false}}"#
            .addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        let falseValuedFilter = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/prune?filters=\(falseMap)"
        ))
        #expect(falseValuedFilter.status == .ok)
        #expect(await runtime.listContainers(all: true).count == 3)

        let multipleUntil = #"{"until":["150","250"]}"#
            .addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        let ambiguousUntil = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/prune?filters=\(multipleUntil)"
        ))
        #expect(ambiguousUntil.status == .badRequest)
        #expect(await runtime.listContainers(all: true).count == 3)

        let conjunctive = #"{"label":["prune=yes","tier=frontend"],"until":["150"]}"#
            .addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        let filtered = await router.route(.init(
            method: .POST,
            uri: "/v1.44/containers/prune?filters=\(conjunctive)"
        ))
        #expect(filtered.status == .ok)
        let payload = try #require(JSONSerialization.jsonObject(with: filtered.body) as? [String: Any])
        #expect(payload["ContainersDeleted"] as? [String] == [selected.id])
        let remaining = await runtime.listContainers(all: true)
        #expect(Set(remaining.map(\.id)) == Set([wrongLabel.id, tooNew.id]))
    }

    @Test func createPreservesAttachStdinAndRejectsUnsupportedHealthStartInterval() async throws {
        let (router, root) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let create = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=stdin-config",
            body: Data(#"{"Image":"debian","AttachStdin":true,"OpenStdin":true}"#.utf8)
        ))
        #expect(create.status == .created)
        let inspect = await router.route(.init(method: .GET, uri: "/v1.44/containers/stdin-config/json"))
        let payload = try #require(JSONSerialization.jsonObject(with: inspect.body) as? [String: Any])
        let config = try #require(payload["Config"] as? [String: Any])
        #expect(config["AttachStdin"] as? Bool == true)
        #expect(config["OpenStdin"] as? Bool == true)

        let health = await router.route(.init(
            method: .POST, uri: "/v1.44/containers/create?name=start-interval",
            body: Data(#"{"Image":"debian","Healthcheck":{"Test":["CMD","true"],"StartInterval":1000000000}}"#.utf8)
        ))
        #expect(health.status == .notImplemented)
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
            body: Data(#"{"Memory":536870912,"NanoCpus":0,"CpuQuota":200000,"CpuPeriod":100000,"PidsLimit":64}"#.utf8)
        ))

        #expect(response.status == .ok)
        let updated = try await runtime.container(record.id)
        #expect(updated.phase == .running)
        #expect(updated.startedAt == startedAt)
        #expect(updated.memoryBytes == 512 * 1_024 * 1_024)
        #expect(updated.cpus == 2)
        #expect(updated.pidsLimit == 64)
        #expect(await backend.lastResourceUpdate()?.memoryBytes == updated.memoryBytes)
        #expect(await backend.lastResourceUpdate()?.cpus == updated.cpus)
        #expect(await backend.lastResourceUpdate()?.pidsLimit == 64)
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

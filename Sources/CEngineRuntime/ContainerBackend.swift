import CEngineCore
import Foundation

public struct ArchiveOwnership: Sendable {
    public let path: String
    public let user: UInt32
    public let group: UInt32

    public init(path: String, user: UInt32, group: UInt32) {
        self.path = path; self.user = user; self.group = group
    }
}

public struct BackendEndpointAddress: Sendable {
    public let ipv4Address: String
    public let ipv6Address: String

    public init(ipv4Address: String, ipv6Address: String) {
        self.ipv4Address = ipv4Address; self.ipv6Address = ipv6Address
    }
}

public enum BackendContainerRecovery: Sendable, Equatable {
    case running
    case paused
    case exited(Int32)
    case unavailable
}

/// The guest could not completely restore its prior cgroup state after a
/// failed live update. The workload must not remain running until the backend
/// execution has been stopped or recreated from durable resources.
public struct BackendResourceRollbackIncompleteError: Error, LocalizedError, Sendable, Equatable {
    public let message: String

    public init(_ message: String) { self.message = message }

    public var errorDescription: String? { message }
}

/// A detached exec start crossed the guest execution boundary, but the reply
/// was not authoritative. The backend contained the exact guest exec (or its
/// owning VM), selected a deterministic terminal result, and retired its
/// backend resources before surfacing the original start failure.
public struct BackendExecStartContainedError: Error, LocalizedError, Sendable, Equatable {
    public let exitCode: Int32
    public let message: String
    /// True when containment required terminating the owning VM because the
    /// guest control channel could not prove exec-local containment.
    public let containerTerminated: Bool

    public init(exitCode: Int32, message: String, containerTerminated: Bool = false) {
        self.exitCode = exitCode
        self.message = message
        self.containerTerminated = containerTerminated
    }

    public var errorDescription: String? { message }
}

/// The backend could not prove containment after an uncertain exec start.
/// Durable ownership is retained and fenced for retry, while EngineRuntime
/// must still make the host exec terminal so the start cannot be repeated.
public struct BackendExecStartQuarantinedError: Error, LocalizedError, Sendable, Equatable {
    public let exitCode: Int32
    public let message: String

    public init(exitCode: Int32, message: String) {
        self.exitCode = exitCode
        self.message = message
    }

    public var errorDescription: String? { message }
}

/// Cleanup boundary after a shim became ready but container preparation did
/// not complete. The writable root is discarded only after every generation
/// has been proven dead; a termination failure remains retryable ownership,
/// rather than an ordinary preparation error that could lose containment.
enum PreparedShimFailureRecovery {
    nonisolated(nonsending) static func perform(
        preparationError: Error,
        terminateEveryGeneration: () async throws -> Void,
        discardWritableRoot: () throws -> Void
    ) async throws -> Never {
        do {
            try await terminateEveryGeneration()
        } catch {
            throw BackendResourceRollbackIncompleteError(
                "container VM preparation failed: \(EngineError.message(for: preparationError)); "
                    + "shim cleanup failed and the writable root was retained: "
                    + EngineError.message(for: error)
            )
        }
        do {
            try discardWritableRoot()
        } catch {
            throw BackendResourceRollbackIncompleteError(
                "container VM preparation failed: \(EngineError.message(for: preparationError)); "
                    + "the contained writable root could not be discarded: "
                    + EngineError.message(for: error)
            )
        }
        throw preparationError
    }
}

/// Runs the destructive portion of a stopped-container resource replacement.
/// A failed candidate launch must attempt both partial-candidate cleanup and
/// original-shim restoration; failure of either reverse step is a structured
/// rollback-incomplete result that the runtime will contain.
enum StoppedResourceReplacementTransaction {
    nonisolated(nonsending) static func perform(
        terminateOriginal: () async throws -> Void,
        launchCandidate: () async throws -> Void,
        cleanupCandidate: () async throws -> Void,
        restoreOriginal: () async throws -> Void
    ) async throws {
        do {
            try await terminateOriginal()
        } catch {
            let terminationError = error
            var cleanupFailure: String?
            do {
                try await cleanupCandidate()
            } catch {
                cleanupFailure = EngineError.message(for: error)
            }
            do {
                try await restoreOriginal()
            } catch {
                throw BackendResourceRollbackIncompleteError(
                    [
                        "original shim termination failed: \(EngineError.message(for: terminationError))",
                        cleanupFailure.map {
                            "cleanup after original shim termination failed: \($0)"
                        },
                        "original shim restoration after termination failure failed: \(EngineError.message(for: error))",
                    ].compactMap { $0 }.joined(separator: "; ")
                )
            }
            // The destructive step failed, but both deterministic cleanup and
            // old-shim restoration proved that the original preparation is
            // again authoritative. The ordinary error lets EngineRuntime clear
            // the durable journal through its normal rollback path.
            if terminationError is BackendResourceRollbackIncompleteError || cleanupFailure != nil {
                throw EngineError(
                    .internalError,
                    "original shim termination failed but its preparation was restored: "
                        + EngineError.message(for: terminationError)
                )
            }
            throw terminationError
        }
        do {
            try await launchCandidate()
        } catch {
            let forwardError = error
            var cleanupFailure: String?
            do {
                try await cleanupCandidate()
            } catch {
                cleanupFailure = EngineError.message(for: error)
            }
            do {
                try await restoreOriginal()
            } catch {
                throw BackendResourceRollbackIncompleteError(
                    [
                        "candidate launch failed: \(EngineError.message(for: forwardError))",
                        cleanupFailure.map { "candidate cleanup failed: \($0)" },
                        "original shim restoration failed: \(EngineError.message(for: error))",
                    ].compactMap { $0 }.joined(separator: "; ")
                )
            }
            // `restoreOriginal` is the final proof boundary and includes a
            // second cleanup attempt in the raw backend. Once it succeeds an
            // earlier partial-launch cleanup failure is no longer unresolved.
            if forwardError is BackendResourceRollbackIncompleteError || cleanupFailure != nil {
                throw EngineError(
                    .internalError,
                    "candidate launch failed but the original preparation was restored: "
                        + EngineError.message(for: forwardError)
                )
            }
            throw forwardError
        }
    }
}

/// Commits a live guest resource change and its durable canonical record as
/// one recoverable transaction. A canonical write can fail after rename, so
/// both the guest and the old canonical record are restored on every durable
/// publication failure.
enum LiveResourceCanonicalTransaction {
    nonisolated(nonsending) static func perform(
        applyDesired: () async throws -> Void,
        persistDesired: () throws -> Void,
        applyOriginal: () async throws -> Void,
        persistOriginal: () throws -> Void
    ) async throws {
        try await applyDesired()
        do {
            try persistDesired()
        } catch {
            let publicationError = error
            var compensationFailures: [String] = []
            do { try await applyOriginal() }
            catch {
                compensationFailures.append(
                    "guest restoration failed: \(EngineError.message(for: error))"
                )
            }
            do { try persistOriginal() }
            catch {
                compensationFailures.append(
                    "canonical restoration failed: \(EngineError.message(for: error))"
                )
            }
            if !compensationFailures.isEmpty {
                throw BackendResourceRollbackIncompleteError(
                    ([
                        "canonical live-resource publication failed: "
                            + EngineError.message(for: publicationError),
                    ] + compensationFailures).joined(separator: "; ")
                )
            }
            throw publicationError
        }
    }
}

public protocol ContainerBackend: Sendable {
    func shutdown() async
    func pullImage(_ reference: String, platform: String) async throws
    func prepare(_ container: ContainerRecord) async throws
    func start(_ container: ContainerRecord) async throws -> [PortBinding]
    func stop(_ container: ContainerRecord, timeoutSeconds: Int) async throws -> Int32
    func wait(_ container: ContainerRecord) async throws -> Int32
    func delete(_ container: ContainerRecord) async throws
    func deleteLogs(for container: ContainerRecord) async throws
    func io(for container: ContainerRecord) async throws -> ContainerIOBridge
    func resize(_ container: ContainerRecord, width: UInt16, height: UInt16) async throws
    func completion(_ container: ContainerRecord) async -> Int32?
    func logs(for container: ContainerRecord) async throws -> Data
    func logs(for container: ContainerRecord, options: DockerLogOptions) async throws -> Data
    func kill(_ container: ContainerRecord, signal: String) async throws
    func prepareExec(_ exec: ExecRecord, container: ContainerRecord) async throws -> ContainerIOBridge
    func discardExec(_ exec: ExecRecord) async
    func retireExec(_ exec: ExecRecord) async
    func startExec(_ exec: ExecRecord) async throws
    func startAttachedExec(_ exec: ExecRecord) async throws -> CInt?
    func execCompletion(_ exec: ExecRecord) async -> Int32?
    func execIO(_ exec: ExecRecord) async throws -> ContainerIOBridge
    func execPID(_ exec: ExecRecord) async -> Int32
    func execStatus(_ exec: ExecRecord) async -> Int32?
    func resizeExec(_ exec: ExecRecord, width: UInt16, height: UInt16) async throws
    func copyIn(_ container: ContainerRecord, extractedDirectory: URL, destination: String,
                ownership: [ArchiveOwnership]) async throws
    func copyOut(_ container: ContainerRecord, source: String, destinationDirectory: URL) async throws
    func loadImages(fromOCILayout directory: URL) async throws -> [BackendImage]
    func loadImages(fromOCILayout directory: URL, platforms: [OCIPlatform]) async throws -> [BackendImage]
    func listImages() async throws -> [BackendImage]?
    func deleteImage(reference: String) async throws
    func deleteImage(reference: String, platforms: [OCIPlatform]) async throws -> [String]
    func tagImage(existing: String, new: String) async throws
    func pushImage(reference: String, platform: String, credentials: RegistryCredentials?) async throws
    func pushImage(reference: String, platform: OCIPlatform?, credentials: RegistryCredentials?) async throws
    func saveImages(references: [String], platform: String) async throws -> Data
    func saveImages(references: [String], platforms: [OCIPlatform]) async throws -> Data
    func pause(_ container: ContainerRecord) async throws
    func resume(_ container: ContainerRecord) async throws
    /// Restart implementations may stop the old execution before throwing.
    /// They must tolerate EngineRuntime following any failure with idempotent
    /// `stop` and `delete` calls to remove a partial replacement.
    func restart(_ container: ContainerRecord, timeoutSeconds: Int) async throws
    func updateResources(_ container: ContainerRecord) async throws
    func endpointAddresses(for container: ContainerRecord) async -> [String: BackendEndpointAddress]
    func statistics(_ container: ContainerRecord) async throws -> BackendStatistics
    func top(_ container: ContainerRecord, arguments: [String]) async throws -> (titles: [String], processes: [[String]])
    func runHealthcheck(_ container: ContainerRecord, arguments: [String], timeoutSeconds: Int64) async throws -> (exitCode: Int32, output: String)
    func deleteVolume(_ name: String) async throws
    func cleanupOrphans(keeping containerIDs: Set<String>) async throws
    func recover(_ container: ContainerRecord) async throws -> BackendContainerRecovery
    func pullImage(_ reference: String, platform: String, credentials: RegistryCredentials?, progress: @escaping ImagePullProgressHandler) async throws
    func imageHistory(reference: String, platform: String) async throws -> [ImageHistoryEntry]
    func imageHistory(reference: String, platform: OCIPlatform?) async throws -> [ImageHistoryEntry]
    func imageAttestations(reference: String, platform: OCIPlatform?, predicateTypes: [String], includeStatement: Bool) async throws -> [ImageAttestationRecord]
    func updateNetworkRecords(_ containers: [ContainerRecord]) async throws
    func restoreNetworks(_ networks: [NetworkRecord]) async throws -> [NetworkRecord]
    func createNetwork(_ network: NetworkRecord) async throws -> NetworkRecord
    func deleteNetwork(_ network: NetworkRecord) async throws
}

public extension ContainerBackend {
    func shutdown() async {}
    func deleteLogs(for _: ContainerRecord) async throws {}
    func logs(for container: ContainerRecord, options _: DockerLogOptions) async throws -> Data { try await logs(for: container) }
    func io(for _: ContainerRecord) async throws -> ContainerIOBridge {
        throw EngineError(.unsupported, "container I/O is unavailable for this backend")
    }
    func resize(_: ContainerRecord, width _: UInt16, height _: UInt16) async throws {}
    func completion(_: ContainerRecord) async -> Int32? { nil }
    func logs(for _: ContainerRecord) async throws -> Data { Data() }
    func kill(_: ContainerRecord, signal _: String) async throws {}
    func prepareExec(_: ExecRecord, container _: ContainerRecord) async throws -> ContainerIOBridge {
        throw EngineError(.unsupported, "exec is unavailable for this backend")
    }
    func discardExec(_: ExecRecord) async {}
    func retireExec(_ exec: ExecRecord) async { await discardExec(exec) }
    func startExec(_: ExecRecord) async throws { throw EngineError(.unsupported, "exec is unavailable for this backend") }
    func startAttachedExec(_: ExecRecord) async throws -> CInt? { nil }
    func execCompletion(_: ExecRecord) async -> Int32? { nil }
    func execIO(_: ExecRecord) async throws -> ContainerIOBridge { throw EngineError(.notFound, "exec I/O is unavailable") }
    func execPID(_: ExecRecord) async -> Int32 { 0 }
    func execStatus(_: ExecRecord) async -> Int32? { nil }
    func resizeExec(_: ExecRecord, width _: UInt16, height _: UInt16) async throws {}
    func copyIn(_: ContainerRecord, extractedDirectory _: URL, destination _: String,
                ownership _: [ArchiveOwnership]) async throws {
        throw EngineError(.unsupported, "archive copy is unavailable for this backend")
    }
    func copyOut(_: ContainerRecord, source _: String, destinationDirectory _: URL) async throws {
        throw EngineError(.unsupported, "archive copy is unavailable for this backend")
    }
    func loadImages(fromOCILayout _: URL) async throws -> [BackendImage] {
        throw EngineError(.unsupported, "image import is unavailable for this backend")
    }
    func loadImages(fromOCILayout directory: URL, platforms: [OCIPlatform]) async throws -> [BackendImage] {
        guard platforms.isEmpty else {
            throw EngineError(.unsupported, "selective image import is unavailable for this backend")
        }
        return try await loadImages(fromOCILayout: directory)
    }
    func listImages() async throws -> [BackendImage]? { nil }
    func deleteImage(reference _: String) async throws {}
    func deleteImage(reference: String, platforms: [OCIPlatform]) async throws -> [String] {
        guard platforms.isEmpty else {
            throw EngineError(.unsupported, "selective image removal is unavailable for this backend")
        }
        try await deleteImage(reference: reference)
        return []
    }
    func tagImage(existing _: String, new _: String) async throws {
        throw EngineError(.unsupported, "image tagging is unavailable for this backend")
    }
    func pushImage(reference _: String, platform _: String, credentials _: RegistryCredentials?) async throws {
        throw EngineError(.unsupported, "image push is unavailable for this backend")
    }
    func pushImage(reference: String, platform: OCIPlatform?, credentials: RegistryCredentials?) async throws {
        try await pushImage(reference: reference, platform: platform?.description ?? "linux/arm64", credentials: credentials)
    }
    func saveImages(references _: [String], platform _: String) async throws -> Data {
        throw EngineError(.unsupported, "image export is unavailable for this backend")
    }
    func saveImages(references: [String], platforms: [OCIPlatform]) async throws -> Data {
        try await saveImages(references: references, platform: platforms.first?.description ?? "linux/arm64")
    }
    func pause(_: ContainerRecord) async throws { throw EngineError(.unsupported, "pause is unavailable for this backend") }
    func resume(_: ContainerRecord) async throws { throw EngineError(.unsupported, "unpause is unavailable for this backend") }
    func restart(_ container: ContainerRecord, timeoutSeconds: Int) async throws {
        _ = try await stop(container, timeoutSeconds: timeoutSeconds)
        try await delete(container)
        try await prepare(container)
        _ = try await start(container)
    }
    func updateResources(_: ContainerRecord) async throws {}
    func endpointAddresses(for _: ContainerRecord) async -> [String: BackendEndpointAddress] { [:] }
    func statistics(_: ContainerRecord) async throws -> BackendStatistics {
        throw EngineError(.unsupported, "container statistics are unavailable for this backend")
    }
    func top(_: ContainerRecord, arguments _: [String]) async throws -> (titles: [String], processes: [[String]]) {
        throw EngineError(.unsupported, "container process listing is unavailable for this backend")
    }
    func runHealthcheck(_: ContainerRecord, arguments _: [String], timeoutSeconds _: Int64) async throws -> (exitCode: Int32, output: String) {
        throw EngineError(.unsupported, "health checks are unavailable for this backend")
    }
    func deleteVolume(_: String) async throws {}
    func cleanupOrphans(keeping _: Set<String>) async throws {}
    func recover(_: ContainerRecord) async throws -> BackendContainerRecovery { .unavailable }
    func pullImage(_ reference: String, platform: String, credentials _: RegistryCredentials?, progress: @escaping ImagePullProgressHandler) async throws {
        try await pullImage(reference, platform: platform)
        await progress(.init(completedItems: 1, totalItems: 1))
    }
    func imageHistory(reference _: String, platform _: String) async throws -> [ImageHistoryEntry] { [] }
    func imageHistory(reference: String, platform: OCIPlatform?) async throws -> [ImageHistoryEntry] {
        try await imageHistory(reference: reference, platform: platform?.description ?? "linux/arm64")
    }
    func imageAttestations(reference _: String, platform _: OCIPlatform?, predicateTypes _: [String], includeStatement _: Bool) async throws -> [ImageAttestationRecord] {
        throw EngineError(.unsupported, "image attestations are unavailable for this backend")
    }
    func updateNetworkRecords(_: [ContainerRecord]) async throws {}
    func restoreNetworks(_ networks: [NetworkRecord]) async throws -> [NetworkRecord] { networks }
    func createNetwork(_ network: NetworkRecord) async throws -> NetworkRecord {
        var value = network
        if value.enableIPv4, value.subnet.isEmpty { value.subnet = "192.168.64.0/24"; value.gateway = "192.168.64.1" }
        if !value.enableIPv4 { value.subnet = ""; value.gateway = "" }
        if value.enableIPv6, value.ipv6Subnet.isEmpty { value.ipv6Subnet = "fd00:ce::/64"; value.ipv6Gateway = "fd00:ce::1" }
        if !value.enableIPv6 { value.ipv6Subnet = ""; value.ipv6Gateway = "" }
        return value
    }
    func deleteNetwork(_: NetworkRecord) async throws {}
}

public struct MetadataOnlyBackend: ContainerBackend {
    public init() {}
    public func pullImage(_: String, platform _: String) async throws {}
    public func prepare(_: ContainerRecord) async throws {}
    public func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
    public func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    public func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    public func delete(_: ContainerRecord) async throws {}
}

import CEngineCore
import Foundation

public protocol ContainerBackend: Sendable {
    func pullImage(_ reference: String, platform: String) async throws
    func prepare(_ container: ContainerRecord) async throws
    func start(_ container: ContainerRecord) async throws -> [PortBinding]
    func stop(_ container: ContainerRecord, timeoutSeconds: Int) async throws -> Int32
    func wait(_ container: ContainerRecord) async throws -> Int32
    func delete(_ container: ContainerRecord) async throws
    func io(for container: ContainerRecord) async throws -> ContainerIOBridge
    func resize(_ container: ContainerRecord, width: UInt16, height: UInt16) async throws
    func completion(_ container: ContainerRecord) async -> Int32?
    func logs(for container: ContainerRecord) async throws -> Data
    func kill(_ container: ContainerRecord, signal: String) async throws
    func prepareExec(_ exec: ExecRecord, container: ContainerRecord) async throws -> ContainerIOBridge
    func startExec(_ exec: ExecRecord) async throws
    func execCompletion(_ exec: ExecRecord) async -> Int32?
    func execIO(_ exec: ExecRecord) async throws -> ContainerIOBridge
    func execPID(_ exec: ExecRecord) async -> Int32
    func execStatus(_ exec: ExecRecord) async -> Int32?
    func resizeExec(_ exec: ExecRecord, width: UInt16, height: UInt16) async throws
    func copyIn(_ container: ContainerRecord, extractedDirectory: URL, destination: String) async throws
    func copyOut(_ container: ContainerRecord, source: String, destinationDirectory: URL) async throws
    func loadImages(fromOCILayout directory: URL) async throws -> [BackendImage]
    func listImages() async throws -> [BackendImage]?
    func deleteImage(reference: String) async throws
    func pause(_ container: ContainerRecord) async throws
    func resume(_ container: ContainerRecord) async throws
    func restart(_ container: ContainerRecord, timeoutSeconds: Int) async throws
    func ipv4Address(for container: ContainerRecord) async -> String?
    func statistics(_ container: ContainerRecord) async throws -> BackendStatistics
    func top(_ container: ContainerRecord, arguments: [String]) async throws -> (titles: [String], processes: [[String]])
    func runHealthcheck(_ container: ContainerRecord, arguments: [String], timeoutSeconds: Int64) async throws -> (exitCode: Int32, output: String)
    func deleteVolume(_ name: String) async throws
    func cleanupOrphans(keeping containerIDs: Set<String>) async throws
    func pullImage(_ reference: String, platform: String, credentials: RegistryCredentials?, progress: @escaping ImagePullProgressHandler) async throws
    func imageHistory(reference: String, platform: String) async throws -> [ImageHistoryEntry]
    func updateNetworkRecords(_ containers: [ContainerRecord]) async throws
}

public extension ContainerBackend {
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
    func startExec(_: ExecRecord) async throws { throw EngineError(.unsupported, "exec is unavailable for this backend") }
    func execCompletion(_: ExecRecord) async -> Int32? { nil }
    func execIO(_: ExecRecord) async throws -> ContainerIOBridge { throw EngineError(.notFound, "exec I/O is unavailable") }
    func execPID(_: ExecRecord) async -> Int32 { 0 }
    func execStatus(_: ExecRecord) async -> Int32? { nil }
    func resizeExec(_: ExecRecord, width _: UInt16, height _: UInt16) async throws {}
    func copyIn(_: ContainerRecord, extractedDirectory _: URL, destination _: String) async throws {
        throw EngineError(.unsupported, "archive copy is unavailable for this backend")
    }
    func copyOut(_: ContainerRecord, source _: String, destinationDirectory _: URL) async throws {
        throw EngineError(.unsupported, "archive copy is unavailable for this backend")
    }
    func loadImages(fromOCILayout _: URL) async throws -> [BackendImage] {
        throw EngineError(.unsupported, "image import is unavailable for this backend")
    }
    func listImages() async throws -> [BackendImage]? { nil }
    func deleteImage(reference _: String) async throws {}
    func pause(_: ContainerRecord) async throws { throw EngineError(.unsupported, "pause is unavailable for this backend") }
    func resume(_: ContainerRecord) async throws { throw EngineError(.unsupported, "unpause is unavailable for this backend") }
    func restart(_ container: ContainerRecord, timeoutSeconds: Int) async throws {
        _ = try await stop(container, timeoutSeconds: timeoutSeconds)
        try await delete(container)
        try await prepare(container)
        _ = try await start(container)
    }
    func ipv4Address(for _: ContainerRecord) async -> String? { nil }
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
    func pullImage(_ reference: String, platform: String, credentials _: RegistryCredentials?, progress: @escaping ImagePullProgressHandler) async throws {
        try await pullImage(reference, platform: platform)
        await progress(.init(completedItems: 1, totalItems: 1))
    }
    func imageHistory(reference _: String, platform _: String) async throws -> [ImageHistoryEntry] { [] }
    func updateNetworkRecords(_: [ContainerRecord]) async throws {}
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

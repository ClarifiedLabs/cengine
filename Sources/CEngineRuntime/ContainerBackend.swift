import CEngineCore
import Foundation

public protocol ContainerBackend: Sendable {
    func pullImage(_ reference: String, platform: String) async throws
    func prepare(_ container: ContainerRecord) async throws
    func start(_ container: ContainerRecord) async throws
    func stop(_ container: ContainerRecord, timeoutSeconds: Int) async throws -> Int32
    func wait(_ container: ContainerRecord) async throws -> Int32
    func delete(_ container: ContainerRecord) async throws
    func io(for container: ContainerRecord) async throws -> ContainerIOBridge
    func resize(_ container: ContainerRecord, width: UInt16, height: UInt16) async throws
    func completion(_ container: ContainerRecord) async -> Int32?
    func logs(for container: ContainerRecord) async throws -> Data
}

public extension ContainerBackend {
    func io(for _: ContainerRecord) async throws -> ContainerIOBridge {
        throw EngineError(.unsupported, "container I/O is unavailable for this backend")
    }
    func resize(_: ContainerRecord, width _: UInt16, height _: UInt16) async throws {}
    func completion(_: ContainerRecord) async -> Int32? { nil }
    func logs(for _: ContainerRecord) async throws -> Data { Data() }
}

public struct MetadataOnlyBackend: ContainerBackend {
    public init() {}
    public func pullImage(_: String, platform _: String) async throws {}
    public func prepare(_: ContainerRecord) async throws {}
    public func start(_: ContainerRecord) async throws {}
    public func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
    public func wait(_: ContainerRecord) async throws -> Int32 { 0 }
    public func delete(_: ContainerRecord) async throws {}
}

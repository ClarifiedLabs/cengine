#if os(macOS)
import CEngineCore
import Darwin
import Foundation

public final class VMShimClient: @unchecked Sendable {
    public struct FabricPort: Codable, Hashable, Sendable { public var proto: String; public var externalPort: UInt16; public var internalAddress: String; public var internalPort: UInt16 }
    public struct FabricNetwork: Codable, Hashable, Sendable { public var id: String; public var vlan: UInt16; public var subnet: String; public var ipv6Subnet: String; public var internalNetwork: Bool; public var isolated: Bool; public var ports: [FabricPort] }
    public struct GuestCall: Codable, Sendable { public var operation: String; public var payload: Data }
    public struct RootFSRequest: Codable, Sendable { public var contentStorePath: String; public var layers: [OCIDescriptor] }

    public let specification: VMShimProtocol.Specification

    public init(specification: VMShimProtocol.Specification) { self.specification = specification }

    public static func launch(specification: VMShimProtocol.Specification, executable: URL = Bundle.main.executableURL ?? URL(filePath: CommandLine.arguments[0])) async throws -> VMShimClient {
        let specURL = specificationURL(for: specification)
        try FileManager.default.createDirectory(at: specURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(specification)
        try data.write(to: specURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: specURL.path)
        let process = Process()
        process.executableURL = executable
        process.arguments = ["vm-shim", "--spec", specURL.path]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = try logHandle(specification.logPath)
        process.standardError = process.standardOutput
        try process.run()
        let client = VMShimClient(specification: specification)
        for _ in 0..<200 {
            if (try? await client.status()) != nil { return client }
            try await Task.sleep(for: .milliseconds(25))
        }
        throw EngineError(.internalError, "VM shim did not become ready at \(specification.socketPath)")
    }

    static func specificationURL(for specification: VMShimProtocol.Specification) -> URL {
        URL(filePath: specification.logPath).deletingLastPathComponent().appending(path: "shim.json")
    }

    public func status() async throws -> VMShimProtocol.Status { try await request(.status, response: VMShimProtocol.Status.self) }
    public func boot() async throws -> VMShimProtocol.Status { try await request(.boot, response: VMShimProtocol.Status.self) }
    public func pause() async throws -> VMShimProtocol.Status { try await request(.pause, response: VMShimProtocol.Status.self) }
    public func resume() async throws -> VMShimProtocol.Status { try await request(.resume, response: VMShimProtocol.Status.self) }
    public func stop() async throws -> VMShimProtocol.Status { try await request(.stop, response: VMShimProtocol.Status.self) }
    public func shutdown() async throws -> VMShimProtocol.Status { try await request(.shutdown, response: VMShimProtocol.Status.self) }

    public func guest<Payload: Encodable, Response: Decodable>(operation: String, payload: Payload, response: Response.Type) async throws -> Response {
        let call = GuestCall(operation: operation, payload: try JSONEncoder().encode(payload))
        return try await request(.guest, payload: call, response: response)
    }

    public func prepareRootFS(contentStorePath: String, layers: [OCIDescriptor]) async throws {
        struct Empty: Decodable {}
        _ = try await request(.prepareRootFS, payload: RootFSRequest(contentStorePath: contentStorePath, layers: layers), response: Empty.self)
    }

    public func configureNetwork(vlans: [UInt16]) async throws -> VMShimProtocol.Status {
        struct Configuration: Encodable { let vlans: [UInt16] }
        return try await request(.configureNetwork, payload: Configuration(vlans: vlans), response: VMShimProtocol.Status.self)
    }

    public func configureFabric(networks: [FabricNetwork]) async throws -> VMShimProtocol.Status {
        struct Configuration: Encodable { let networks: [FabricNetwork] }
        return try await request(.configureFabric, payload: Configuration(networks: networks), response: VMShimProtocol.Status.self)
    }

    private func request<Response: Decodable>(_ operation: VMShimProtocol.Operation, response: Response.Type) async throws -> Response {
        try await request(operation, payloadData: nil, response: response)
    }

    private func request<Payload: Encodable, Response: Decodable>(_ operation: VMShimProtocol.Operation, payload: Payload, response: Response.Type) async throws -> Response {
        try await request(operation, payloadData: try JSONEncoder().encode(payload), response: response)
    }

    private func request<Response: Decodable>(_ operation: VMShimProtocol.Operation, payloadData: Data?, response: Response.Type) async throws -> Response {
        let payload = try await Task.detached { [self] in try requestData(operation, payloadData: payloadData) }.value
        return try JSONDecoder().decode(response, from: payload)
    }

    private func requestData(_ operation: VMShimProtocol.Operation, payloadData: Data?) throws -> Data {
        let envelope = VMShimProtocol.Envelope(token: specification.token, operation: operation, payload: payloadData)
        let descriptor = try UnixSocket.connect(path: specification.socketPath)
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        try file.write(contentsOf: VMShimProtocol.encode(envelope))
        let reply = try VMShimProtocol.decode(try readFrame(file))
        guard reply.id == envelope.id else { throw EngineError(.internalError, "VM shim response id mismatch") }
        if let failure = reply.error { throw EngineError(.internalError, "VM shim \(failure.code): \(failure.message)") }
        guard let payload = reply.payload else { throw EngineError(.internalError, "VM shim response has no payload") }
        return payload
    }

    private func readFrame(_ file: FileHandle) throws -> Data {
        let prefix = try readExactly(file, count: 4)
        let size = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard size > 0, size <= VMShimProtocol.maximumFrameSize else { throw EngineError(.badRequest, "invalid VM shim frame") }
        return prefix + (try readExactly(file, count: Int(size)))
    }

    private func readExactly(_ file: FileHandle, count: Int) throws -> Data {
        var data = Data()
        while data.count < count {
            guard let next = try file.read(upToCount: count - data.count), !next.isEmpty else { throw EngineError(.internalError, "VM shim closed connection") }
            data.append(next)
        }
        return data
    }

    private static func logHandle(_ path: String) throws -> FileHandle {
        FileManager.default.createFile(atPath: path, contents: nil)
        let handle = try FileHandle(forWritingTo: URL(filePath: path))
        try handle.seekToEnd()
        return handle
    }
}
#endif

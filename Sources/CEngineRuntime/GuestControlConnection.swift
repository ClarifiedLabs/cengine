#if os(macOS)
import CEngineCore
import Foundation
import Virtualization

public actor GuestControlConnection {
    private let connection: SendableVirtioSocketConnection
    private let file: FileHandle

    init(connection: SendableVirtioSocketConnection) {
        self.connection = connection
        file = FileHandle(fileDescriptor: connection.connection.fileDescriptor, closeOnDealloc: false)
    }

    public func request<Payload: Encodable, Response: Decodable>(
        operation: String,
        payload: Payload,
        response: Response.Type
    ) throws -> Response {
        let data = try requestRaw(operation: operation, payload: JSONEncoder().encode(payload))
        return try JSONDecoder().decode(response, from: data)
    }

    public func requestRaw(operation: String, payload: Data) throws -> Data {
        let envelope = GuestProtocol.Envelope(operation: operation, payload: payload)
        try file.write(contentsOf: GuestProtocol.encode(envelope))
        let reply = try GuestProtocol.decode(readFrame())
        guard reply.id == envelope.id else {
            throw EngineError(.internalError, "guest response id does not match request")
        }
        if let failure = reply.error {
            throw EngineError(.internalError, "guest \(failure.code): \(failure.message)")
        }
        guard let data = reply.payload else {
            throw EngineError(.internalError, "guest response has no payload")
        }
        return data
    }

    public func ping() throws {
        struct Empty: Codable {}
        struct Status: Decodable { let status: String }
        let status: Status = try request(operation: "ping", payload: Empty(), response: Status.self)
        guard status.status == "ready" else {
            throw EngineError(.internalError, "guest returned unexpected status \(status.status)")
        }
    }

    private func readFrame() throws -> Data {
        let prefix = try readExactly(4)
        let size = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard size > 0, size <= GuestProtocol.maximumControlFrameSize else {
            throw EngineError(.badRequest, "invalid guest control frame size \(size)")
        }
        return prefix + (try readExactly(Int(size)))
    }

    private func readExactly(_ count: Int) throws -> Data {
        var result = Data()
        while result.count < count {
            guard let data = try file.read(upToCount: count - result.count), !data.isEmpty else {
                throw EngineError(.internalError, "guest control connection closed")
            }
            result.append(data)
        }
        return result
    }
}
#endif

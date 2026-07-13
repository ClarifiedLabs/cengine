#if os(macOS)
import CEngineCore
import Darwin
import Foundation

actor StorageAdministrativeClient {
    private struct Message: Codable {
        var version: Int = 2
        var type: String
        var request: Request?
        var reply: Reply?
    }
    private struct Request: Codable {
        var id: UInt64
        var op: String
        var volume: String?
        var token: String?
    }
    private struct Reply: Codable { var id: UInt64; var errno: Int? }

    private let socketPath: String
    private let tokenIssuer: VolumeAccessToken

    init(socketPath: String, tokenIssuer: VolumeAccessToken) {
        self.socketPath = socketPath
        self.tokenIssuer = tokenIssuer
    }

    func deleteVolume(_ volume: String) throws {
        let descriptor = try UnixSocket.connect(path: socketPath)
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        try send(.init(type: "request", request: .init(id: 1, op: "handshake", volume: volume, token: tokenIssuer.token(for: volume))), to: file)
        try expect(id: 1, from: file)
        try send(.init(type: "request", request: .init(id: 2, op: "delete-volume")), to: file)
        try expect(id: 2, from: file)
    }

    private func send(_ message: Message, to file: FileHandle) throws {
        let body = try JSONEncoder().encode(message)
        var size = UInt32(body.count).bigEndian
        try file.write(contentsOf: Data(bytes: &size, count: 4) + body)
    }

    private func expect(id: UInt64, from file: FileHandle) throws {
        while true {
            let message = try JSONDecoder().decode(Message.self, from: readBody(file))
            guard message.type == "response", let reply = message.reply else { continue }
            guard reply.id == id else { throw EngineError(.internalError, "storage response id mismatch") }
            if let value = reply.errno, value != 0 {
                if value == EBUSY { throw EngineError(.conflict, "volume is in use") }
                throw EngineError(.internalError, "storage appliance returned errno \(value)")
            }
            return
        }
    }

    private func readBody(_ file: FileHandle) throws -> Data {
        let prefix = try readExactly(file, count: 4)
        let size = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard size > 0, size <= 64 * 1_024 * 1_024 else { throw EngineError(.badRequest, "invalid storage frame") }
        return try readExactly(file, count: Int(size))
    }

    private func readExactly(_ file: FileHandle, count: Int) throws -> Data {
        var data = Data()
        while data.count < count {
            guard let part = try file.read(upToCount: count - data.count), !part.isEmpty else { throw EngineError(.internalError, "storage appliance closed connection") }
            data.append(part)
        }
        return data
    }
}
#endif

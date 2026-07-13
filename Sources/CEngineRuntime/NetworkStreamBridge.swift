#if os(macOS)
import CEngineCore
import Foundation

struct NetworkRegistration: Codable, Sendable {
    let endpointID: String
    let vlans: [UInt16]
}

final class NetworkStreamBridge: @unchecked Sendable {
    private let datagrams: FileHandle
    private let stream: FileHandle
    private let completion: @Sendable () -> Void
    private let writeLock = NSLock()
    private let readLock = NSLock()
    private var buffer = Data()
    private var closed = false

    init(datagrams: FileHandle, stream: FileHandle, registration: NetworkRegistration? = nil, completion: @escaping @Sendable () -> Void = {}) throws {
        self.datagrams = datagrams
        self.stream = stream
        self.completion = completion
        if let registration { try writeFrame(JSONEncoder().encode(registration)) }
    }

    func start() {
        datagrams.readabilityHandler = { [weak self] handle in
            guard let self else { return }
            let packet = handle.availableData
            guard !packet.isEmpty else { self.finish(); return }
            do { try self.writeFrame(packet) } catch { self.finish() }
        }
        stream.readabilityHandler = { [weak self] handle in
            guard let self else { return }
            let data = handle.availableData
            guard !data.isEmpty else { self.finish(); return }
            self.consume(data)
        }
    }

    func finish() {
        writeLock.lock()
        guard !closed else { writeLock.unlock(); return }
        closed = true
        datagrams.readabilityHandler = nil
        stream.readabilityHandler = nil
        try? stream.close()
        writeLock.unlock()
        completion()
    }

    private func writeFrame(_ data: Data) throws {
        guard data.count <= 65_535 else { throw EngineError(.badRequest, "Ethernet frame is too large") }
        var size = UInt32(data.count).bigEndian
        writeLock.lock(); defer { writeLock.unlock() }
        guard !closed else { throw EngineError(.conflict, "network bridge is closed") }
        try stream.write(contentsOf: Data(bytes: &size, count: 4) + data)
    }

    private func consume(_ data: Data) {
        readLock.lock(); defer { readLock.unlock() }
        buffer.append(data)
        while buffer.count >= 4 {
            let size = buffer.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            guard size > 0, size <= 65_535 else { buffer.removeAll(); finish(); return }
            guard buffer.count >= Int(size) + 4 else { return }
            let packet = buffer.subdata(in: 4..<(Int(size) + 4))
            buffer.removeSubrange(0..<(Int(size) + 4))
            do { try datagrams.write(contentsOf: packet) } catch { finish(); return }
        }
    }

    static func readRegistration(_ descriptor: Int32) throws -> (NetworkRegistration, FileHandle) {
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        let prefix = try readExactly(file, count: 4)
        let size = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard size > 0, size <= 65_535 else { throw EngineError(.badRequest, "invalid network registration") }
        return (try JSONDecoder().decode(NetworkRegistration.self, from: readExactly(file, count: Int(size))), file)
    }

    private static func readExactly(_ file: FileHandle, count: Int) throws -> Data {
        var data = Data()
        while data.count < count {
            guard let part = try file.read(upToCount: count - data.count), !part.isEmpty else { throw EngineError(.badRequest, "network registration is truncated") }
            data.append(part)
        }
        return data
    }
}
#endif

#if os(macOS)
import CEngineCore
import Darwin
import Foundation

enum UnixSocket {
    static func listen(path: String) throws -> Int32 {
        guard path.utf8.count < MemoryLayout<sockaddr_un>.size - 2 else {
            throw EngineError(.badRequest, "Unix socket path is too long: \(path)")
        }
        try? FileManager.default.removeItem(atPath: path)
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw systemError("create Unix socket") }
        do {
            try withAddress(path) { address, length in
                guard Darwin.bind(descriptor, address, length) == 0 else { throw systemError("bind Unix socket") }
            }
            guard chmod(path, S_IRUSR | S_IWUSR) == 0 else { throw systemError("protect Unix socket") }
            guard Darwin.listen(descriptor, 128) == 0 else { throw systemError("listen on Unix socket") }
            return descriptor
        } catch {
            close(descriptor)
            throw error
        }
    }

    static func connect(path: String) throws -> Int32 {
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw systemError("create Unix socket") }
        do {
            try withAddress(path) { address, length in
                guard Darwin.connect(descriptor, address, length) == 0 else { throw systemError("connect Unix socket") }
            }
            return descriptor
        } catch {
            close(descriptor)
            throw error
        }
    }

    static func accept(_ descriptor: Int32) throws -> Int32 {
        let client = Darwin.accept(descriptor, nil, nil)
        guard client >= 0 else { throw systemError("accept Unix socket") }
        return client
    }

    private static func withAddress<T>(_ path: String, body: (UnsafePointer<sockaddr>, socklen_t) throws -> T) throws -> T {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8) + [0]
        let pathOffset = MemoryLayout<UInt8>.size + MemoryLayout<sa_family_t>.size
        let length = pathOffset + bytes.count
        address.sun_len = UInt8(length)
        return try withUnsafeMutableBytes(of: &address) { raw in
            for (index, byte) in bytes.enumerated() {
                raw[pathOffset + index] = byte
            }
            return try raw.baseAddress!.assumingMemoryBound(to: sockaddr.self).withMemoryRebound(to: sockaddr.self, capacity: 1) {
                try body($0, socklen_t(length))
            }
        }
    }

    private static func systemError(_ operation: String) -> EngineError {
        EngineError(.internalError, "\(operation) failed: \(String(cString: strerror(errno)))")
    }
}
#endif

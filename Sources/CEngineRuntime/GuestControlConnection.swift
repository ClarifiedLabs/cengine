#if os(macOS)
import CEngineCore
import Darwin
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

    public func requestRaw(
        operation: String,
        payload: Data,
        deadlineNanoseconds: UInt64? = nil
    ) throws -> Data {
        let envelope = GuestProtocol.Envelope(operation: operation, payload: payload)
        let frame: Data
        if let deadlineNanoseconds {
            let descriptor = connection.connection.fileDescriptor
            let flags = Darwin.fcntl(descriptor, F_GETFL)
            guard flags >= 0,
                  Darwin.fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
                throw EngineError(
                    .internalError, "could not configure guest control request deadline"
                )
            }
            try Self.writeExactly(
                GuestProtocol.encode(envelope),
                to: descriptor,
                deadlineNanoseconds: deadlineNanoseconds
            )
            frame = try Self.readFrame(
                from: descriptor, deadlineNanoseconds: deadlineNanoseconds
            )
        } else {
            try file.write(contentsOf: GuestProtocol.encode(envelope))
            frame = try readFrame()
        }
        let reply = try GuestProtocol.decode(frame)
        guard reply.id == envelope.id else {
            throw EngineError(.internalError, "guest response id does not match request")
        }
        if let failure = reply.error {
            if failure.code == GuestProtocol.resourceRollbackIncompleteErrorCode {
                throw BackendResourceRollbackIncompleteError(failure.message)
            }
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

    private static func remainingMilliseconds(until deadline: UInt64) -> Int32 {
        let now = DispatchTime.now().uptimeNanoseconds
        guard deadline > now else { return 0 }
        let roundedUp = (deadline - now + 999_999) / 1_000_000
        return Int32(min(roundedUp, UInt64(Int32.max)))
    }

    private static func wait(
        for events: Int16, descriptor: CInt, deadlineNanoseconds: UInt64
    ) throws {
        var event = pollfd(fd: descriptor, events: events, revents: 0)
        while true {
            let timeout = remainingMilliseconds(until: deadlineNanoseconds)
            guard timeout > 0 else { throw AsyncTimeout.TimeoutError() }
            let result = Darwin.poll(&event, 1, timeout)
            if result > 0 { return }
            if result == 0 { throw AsyncTimeout.TimeoutError() }
            if errno != EINTR {
                throw EngineError(
                    .internalError,
                    "guest control socket poll failed: \(String(cString: strerror(errno)))"
                )
            }
        }
    }

    private static func writeExactly(
        _ data: Data, to descriptor: CInt, deadlineNanoseconds: UInt64
    ) throws {
        try data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var offset = 0
            while offset < raw.count {
                try wait(
                    for: Int16(POLLOUT), descriptor: descriptor,
                    deadlineNanoseconds: deadlineNanoseconds
                )
                let count = Darwin.write(
                    descriptor, base.advanced(by: offset), raw.count - offset
                )
                if count > 0 { offset += count; continue }
                if count < 0, errno == EINTR || errno == EAGAIN { continue }
                throw EngineError(.internalError, "guest control socket write failed")
            }
        }
    }

    private static func readExactly(
        from descriptor: CInt, count: Int, deadlineNanoseconds: UInt64
    ) throws -> Data {
        var data = Data(count: count)
        try data.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            var offset = 0
            while offset < count {
                try wait(
                    for: Int16(POLLIN), descriptor: descriptor,
                    deadlineNanoseconds: deadlineNanoseconds
                )
                let received = Darwin.read(
                    descriptor, base.advanced(by: offset), count - offset
                )
                if received > 0 { offset += received; continue }
                if received < 0, errno == EINTR || errno == EAGAIN { continue }
                throw EngineError(.internalError, "guest control connection closed")
            }
        }
        return data
    }

    private static func readFrame(
        from descriptor: CInt, deadlineNanoseconds: UInt64
    ) throws -> Data {
        let prefix = try readExactly(
            from: descriptor, count: 4, deadlineNanoseconds: deadlineNanoseconds
        )
        let size = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard size > 0, size <= GuestProtocol.maximumControlFrameSize else {
            throw EngineError(.badRequest, "invalid guest control frame size \(size)")
        }
        return prefix + (try readExactly(
            from: descriptor, count: Int(size), deadlineNanoseconds: deadlineNanoseconds
        ))
    }
}
#endif

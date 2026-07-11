import Containerization
import Foundation

public struct DockerLogOptions: Sendable {
    public var stdout: Bool; public var stderr: Bool; public var since: Date?; public var until: Date?
    public var timestamps: Bool; public var tail: Int?
    public init(stdout: Bool = true, stderr: Bool = true, since: Date? = nil, until: Date? = nil,
                timestamps: Bool = false, tail: Int? = nil) {
        self.stdout = stdout; self.stderr = stderr; self.since = since; self.until = until
        self.timestamps = timestamps; self.tail = tail
    }
}

public final class ContainerIOBridge: ReaderStream, @unchecked Sendable {
    public enum OutputStream: UInt8, Sendable { case stdout = 1, stderr = 2 }

    private let lock = NSLock()
    private let inputStream: AsyncStream<Data>
    private let inputContinuation: AsyncStream<Data>.Continuation
    private struct Subscriber: Sendable {
        let output: @Sendable (Data, OutputStream, Date) -> Void
        let closed: @Sendable () -> Void
    }
    private struct LogEntry: Codable, Sendable { let date: Date; let stream: UInt8; let payload: Data }
    private var subscribers: [UUID: Subscriber] = [:]
    private var buffered: [Data] = []
    private var finished = false
    private let tty: Bool
    private let logURL: URL?
    private let logIndexURL: URL?
    private var logEntries: [LogEntry] = []

    public init(tty: Bool, logURL: URL? = nil) {
        self.tty = tty
        self.logURL = logURL
        self.logIndexURL = logURL.map { $0.appendingPathExtension("entries") }
        (inputStream, inputContinuation) = AsyncStream.makeStream(of: Data.self)
        if let logURL {
            try? FileManager.default.createDirectory(at: logURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            if !FileManager.default.fileExists(atPath: logURL.path) {
                FileManager.default.createFile(atPath: logURL.path, contents: nil)
            }
            if let logIndexURL, let data = try? Data(contentsOf: logIndexURL),
               let entries = try? JSONDecoder().decode([LogEntry].self, from: data) { logEntries = entries }
        }
    }

    public func stream() -> AsyncStream<Data> { inputStream }
    public func sendInput(_ data: Data) { inputContinuation.yield(data) }
    public func finishInput() { inputContinuation.finish() }

    public func writer(_ stream: OutputStream) -> any Writer { OutputWriter(bridge: self, stream: stream) }

    @discardableResult
    public func attach(
        replayBuffered: Bool = true,
        output: @escaping @Sendable (Data) -> Void,
        closed: @escaping @Sendable () -> Void
    ) -> UUID {
        let id = UUID()
        lock.lock()
        subscribers[id] = .init(output: { data, _, _ in output(data) }, closed: closed)
        let pending = replayBuffered ? buffered : []
        buffered.removeAll(keepingCapacity: false)
        let alreadyFinished = finished
        lock.unlock()
        pending.forEach(output)
        if alreadyFinished { closed() }
        return id
    }

    public func detach(_ id: UUID) {
        lock.withLock { _ = subscribers.removeValue(forKey: id) }
    }

    public func finishOutput() {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        let close = subscribers.values.map(\.closed)
        lock.unlock()
        close.forEach { $0() }
    }

    public func logData() throws -> Data {
        guard let logURL else { return Data() }
        return try lock.withLock { try Data(contentsOf: logURL) }
    }

    public func logData(options: DockerLogOptions) throws -> Data {
        try lock.withLock {
            guard !logEntries.isEmpty else {
                guard let logURL else { return Data() }
                return try Data(contentsOf: logURL)
            }
            return Self.render(logEntries, tty: tty, options: options)
        }
    }

    public func attachLogs(
        options: DockerLogOptions,
        replayExisting: Bool = false,
        output: @escaping @Sendable (Data) -> Void,
        closed: @escaping @Sendable () -> Void
    ) -> (id: UUID, initial: Data) {
        let id = UUID()
        lock.lock()
        let initial = replayExisting ? Self.render(logEntries, tty: tty, options: options) : Data()
        let liveOptions: DockerLogOptions = { var value = options; value.tail = nil; return value }()
        subscribers[id] = .init(output: { data, stream, date in
            guard Self.includes(stream: stream, date: date, options: liveOptions) else { return }
            let entry = LogEntry(date: date, stream: stream.rawValue, payload: Self.payload(from: data, tty: self.tty))
            output(Self.render([entry], tty: self.tty, options: liveOptions))
        }, closed: closed)
        let alreadyFinished = finished
        lock.unlock()
        if alreadyFinished { closed() }
        return (id, initial)
    }

    fileprivate func write(_ data: Data, stream: OutputStream) {
        let framed: Data
        if tty {
            framed = data
        } else {
            var header = Data([stream.rawValue, 0, 0, 0])
            let count = UInt32(data.count).bigEndian
            withUnsafeBytes(of: count) { header.append(contentsOf: $0) }
            header.append(data)
            framed = header
        }
        let date = Date()
        lock.lock()
        if let logURL, let handle = try? FileHandle(forWritingTo: logURL) {
            do {
                try handle.seekToEnd()
                try handle.write(contentsOf: framed)
                try handle.close()
            } catch {
                try? handle.close()
            }
        }
        logEntries.append(.init(date: date, stream: stream.rawValue, payload: data))
        if let logIndexURL, let encoded = try? JSONEncoder().encode(logEntries) {
            try? encoded.write(to: logIndexURL, options: .atomic)
        }
        let handlers = subscribers.values.map(\.output)
        if handlers.isEmpty { buffered.append(framed) }
        lock.unlock()
        handlers.forEach { $0(framed, stream, date) }
    }


    private static func includes(stream: OutputStream, date: Date, options: DockerLogOptions) -> Bool {
        guard (stream == .stdout ? options.stdout : options.stderr) else { return false }
        if let since = options.since, date < since { return false }
        if let until = options.until, date > until { return false }
        return true
    }

    private static func payload(from framed: Data, tty: Bool) -> Data {
        guard !tty, framed.count >= 8 else { return framed }
        return framed.dropFirst(8)
    }

    private static func render(_ entries: [LogEntry], tty: Bool, options: DockerLogOptions) -> Data {
        var lines: [(LogEntry, Data)] = []
        for entry in entries {
            guard let stream = OutputStream(rawValue: entry.stream), includes(stream: stream, date: entry.date, options: options) else { continue }
            var start = entry.payload.startIndex
            for index in entry.payload.indices where entry.payload[index] == 0x0a {
                let end = entry.payload.index(after: index)
                lines.append((entry, Data(entry.payload[start..<end]))); start = end
            }
            if start < entry.payload.endIndex { lines.append((entry, Data(entry.payload[start...]))) }
        }
        if let tail = options.tail, tail >= 0 { lines = Array(lines.suffix(tail)) }
        let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        var result = Data()
        for (entry, rawLine) in lines {
            var payload = Data()
            if options.timestamps { payload.append(Data("\(formatter.string(from: entry.date)) ".utf8)) }
            payload.append(rawLine)
            if tty { result.append(payload); continue }
            var header = Data([entry.stream, 0, 0, 0]); var count = UInt32(payload.count).bigEndian
            withUnsafeBytes(of: &count) { header.append(contentsOf: $0) }
            result.append(header); result.append(payload)
        }
        return result
    }
}

private final class OutputWriter: Writer, @unchecked Sendable {
    private let bridge: ContainerIOBridge
    private let stream: ContainerIOBridge.OutputStream
    init(bridge: ContainerIOBridge, stream: ContainerIOBridge.OutputStream) { self.bridge = bridge; self.stream = stream }
    func write(_ data: Data) throws { bridge.write(data, stream: stream) }
    func close() throws {}
}

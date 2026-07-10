import Containerization
import Foundation

public final class ContainerIOBridge: ReaderStream, @unchecked Sendable {
    public enum OutputStream: UInt8, Sendable { case stdout = 1, stderr = 2 }

    private let lock = NSLock()
    private let inputStream: AsyncStream<Data>
    private let inputContinuation: AsyncStream<Data>.Continuation
    private struct Subscriber: Sendable {
        let output: @Sendable (Data) -> Void
        let closed: @Sendable () -> Void
    }
    private var subscribers: [UUID: Subscriber] = [:]
    private var buffered: [Data] = []
    private var finished = false
    private let tty: Bool
    private let logURL: URL?

    public init(tty: Bool, logURL: URL? = nil) {
        self.tty = tty
        self.logURL = logURL
        (inputStream, inputContinuation) = AsyncStream.makeStream(of: Data.self)
        if let logURL {
            try? FileManager.default.createDirectory(at: logURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            FileManager.default.createFile(atPath: logURL.path, contents: nil)
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
        subscribers[id] = .init(output: output, closed: closed)
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
        let handlers = subscribers.values.map(\.output)
        if handlers.isEmpty { buffered.append(framed) }
        lock.unlock()
        handlers.forEach { $0(framed) }
    }
}

private final class OutputWriter: Writer, @unchecked Sendable {
    private let bridge: ContainerIOBridge
    private let stream: ContainerIOBridge.OutputStream
    init(bridge: ContainerIOBridge, stream: ContainerIOBridge.OutputStream) { self.bridge = bridge; self.stream = stream }
    func write(_ data: Data) throws { bridge.write(data, stream: stream) }
    func close() throws {}
}

import CEngineCore
import Darwin
import Foundation

final class ContainerLogMonitor: @unchecked Sendable {
    private static let defaultMaximumOutputChunkSize = 1 * 1_024 * 1_024

    private final class InputCompletion: @unchecked Sendable {
        private let condition = NSCondition()
        private var result: Result<Void, Error>?

        func complete(_ result: Result<Void, Error>) {
            condition.lock()
            self.result = result
            condition.broadcast()
            condition.unlock()
        }

        func wait() throws {
            condition.lock()
            while result == nil { condition.wait() }
            let result = result!
            condition.unlock()
            try result.get()
        }
    }

    private final class InputClosureGate: @unchecked Sendable {
        private let lock = NSLock()
        private var cancellationRequested = false
        private var inputFinished = false

        func cancel() {
            lock.withLock { cancellationRequested = true }
        }

        func finishNaturally(_ markInputClosed: () throws -> Void) throws -> Bool {
            try lock.withLock {
                guard !cancellationRequested, !inputFinished else { return false }
                try markInputClosed()
                inputFinished = true
                return true
            }
        }
    }

    private let stdout: FileHandle
    private let stderr: FileHandle
    private let input: FileHandle
    private let markInputClosed: @Sendable () throws -> Void
    private let synchronizeInput: @Sendable () throws -> Void
    private let bridge: ContainerIOBridge
    private let persistOutput: @Sendable (
        Data, ContainerIOBridge.OutputStream
    ) throws -> Void
    private let maximumOutputChunkSize: Int
    private let lock = NSLock()
    private var offsets: [ContainerIOBridge.OutputStream: UInt64] = [:]
    private var task: Task<Void, Never>?
    private var inputTask: Task<Void, Never>?
    private var inputClosureGate: InputClosureGate?
    private var inputFinishRegistration: UUID?

    init(
        stdout: FileHandle,
        stderr: FileHandle,
        input: FileHandle,
        bridge: ContainerIOBridge,
        markInputClosed: @escaping @Sendable () throws -> Void = {},
        synchronizeInput: (@Sendable () throws -> Void)? = nil,
        persistOutput: (@Sendable (
            Data, ContainerIOBridge.OutputStream
        ) throws -> Void)? = nil,
        maximumOutputChunkSize: Int = defaultMaximumOutputChunkSize
    ) {
        self.stdout = stdout
        self.stderr = stderr
        self.input = input
        self.bridge = bridge
        self.markInputClosed = markInputClosed
        self.synchronizeInput = synchronizeInput ?? { try input.synchronize() }
        self.persistOutput = persistOutput ?? { data, stream in
            try bridge.writer(stream).write(data)
        }
        self.maximumOutputChunkSize = max(1, maximumOutputChunkSize)
    }

    convenience init(directory: URL, bridge: ContainerIOBridge) throws {
        try self.init(
            stdoutURL: directory.appending(path: "stdout"),
            stderrURL: directory.appending(path: "stderr"),
            inputURL: directory.appending(path: "stdin"),
            bridge: bridge
        )
    }

    convenience init(
        stdoutURL: URL,
        stderrURL: URL,
        inputURL: URL,
        bridge: ContainerIOBridge
    ) throws {
        self.init(
            stdout: try Self.openRegularFile(at: stdoutURL),
            stderr: try Self.openRegularFile(at: stderrURL),
            input: try Self.openRegularFile(at: inputURL),
            bridge: bridge
        )
    }

    func start(atEnd: Bool = false) {
        guard task == nil else { return }
        if atEnd {
            if let durable = bridge.durableSourceByteOffsets() {
                offsets[.stdout] = min(
                    durable[.stdout] ?? 0, Self.size(of: stdout)
                )
                offsets[.stderr] = min(
                    durable[.stderr] ?? 0, Self.size(of: stderr)
                )
            } else {
                offsets[.stdout] = Self.size(of: stdout)
                offsets[.stderr] = Self.size(of: stderr)
            }
        }
        task = Task.detached { [weak self] in
            while !Task.isCancelled {
                try? self?.drain(stream: .stdout)
                try? self?.drain(stream: .stderr)
                try? await Task.sleep(for: .milliseconds(25))
            }
        }
        let inputClosureGate = InputClosureGate()
        let inputCompletion = InputCompletion()
        self.inputClosureGate = inputClosureGate
        inputTask = Task.detached {
            [bridge, input, markInputClosed, synchronizeInput,
             inputClosureGate, inputCompletion] in
            do {
                for await data in bridge.stream() {
                    guard !Task.isCancelled else { throw CancellationError() }
                    try input.seekToEnd()
                    try input.write(contentsOf: data)
                }
                guard !Task.isCancelled else { throw CancellationError() }
                try synchronizeInput()
                guard try inputClosureGate.finishNaturally(markInputClosed) else {
                    throw CancellationError()
                }
                inputCompletion.complete(.success(()))
            } catch {
                inputCompletion.complete(.failure(error))
            }
        }
        inputFinishRegistration = bridge.registerInputFinishHandler {
            try inputCompletion.wait()
        }
    }

    func stop(finishOutput: Bool = true) throws {
        task?.cancel()
        if let inputFinishRegistration {
            bridge.unregisterInputFinishHandler(inputFinishRegistration)
        }
        inputClosureGate?.cancel()
        inputTask?.cancel()
        task = nil
        inputTask = nil
        inputClosureGate = nil
        inputFinishRegistration = nil
        try drain(stream: .stdout)
        try drain(stream: .stderr)
        if finishOutput { bridge.finishOutput() }
    }

    func rawOutput() throws -> Data {
        try lock.withLock {
            try Self.readAll(from: stdout) + Self.readAll(from: stderr)
        }
    }

    /// The URL parameter remains only as a source-compatible test hook. Reads
    /// always use the verified handle captured at initialization.
    func drain(
        _ ignoredURL: URL? = nil,
        stream: ContainerIOBridge.OutputStream,
        didReadOffset: @Sendable () -> Void = {}
    ) throws {
        let handle = stream == .stdout ? stdout : stderr
        lock.lock()
        defer { lock.unlock() }
        var committedOffset = offsets[stream] ?? 0
        didReadOffset()
        try handle.seek(toOffset: committedOffset)
        while let data = try handle.read(upToCount: maximumOutputChunkSize),
              !data.isEmpty {
            let (nextOffset, overflow) = committedOffset.addingReportingOverflow(
                UInt64(data.count)
            )
            guard !overflow else {
                throw EngineError(.internalError, "container output offset overflow")
            }
            try persistOutput(data, stream)
            // The source cursor is a commit position, not a read position.
            // Each bounded chunk advances independently only after its
            // journal/raw publication succeeds. A failure therefore retries
            // the identical chunk without replaying earlier committed data.
            committedOffset = nextOffset
            offsets[stream] = committedOffset
        }
    }

    private static func openRegularFile(at url: URL) throws -> FileHandle {
        let descriptor = Darwin.open(
            url.path, O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
        )
        guard descriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        var information = stat()
        guard Darwin.fstat(descriptor, &information) == 0,
              information.st_mode & S_IFMT == S_IFREG else {
            Darwin.close(descriptor)
            throw EngineError(.conflict, "container I/O path is not a regular file")
        }
        return FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    }

    private static func size(of handle: FileHandle) -> UInt64 {
        var information = stat()
        guard Darwin.fstat(handle.fileDescriptor, &information) == 0,
              information.st_size >= 0 else { return 0 }
        return UInt64(information.st_size)
    }

    private static func readAll(from handle: FileHandle) throws -> Data {
        try handle.seek(toOffset: 0)
        return try handle.readToEnd() ?? Data()
    }
}

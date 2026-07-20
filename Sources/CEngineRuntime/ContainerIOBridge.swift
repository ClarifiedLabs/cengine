import CEngineCore
import Darwin
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

public protocol CEngineWriter: Sendable {
    func write(_ data: Data) throws
    func close() throws
}

public final class ContainerIOBridge: @unchecked Sendable {
    public enum OutputStream: UInt8, Sendable { case stdout = 1, stderr = 2 }

    private static let journalMagic = Data([0x43, 0x45, 0x4c, 0x4a]) // CELJ
    private static let journalHeaderSize = 20
    private static let maximumJournalPayloadSize = 256 * 1_024 * 1_024
    static let defaultCompletedSnapshotByteLimit = 8 * 1_024 * 1_024

    private let lock = NSLock()
    private let inputLock = NSLock()
    private let inputStream: AsyncStream<Data>
    private let inputContinuation: AsyncStream<Data>.Continuation
    private struct Subscriber: Sendable {
        let output: @Sendable (Data, OutputStream, Date) -> Void
        let closed: @Sendable () -> Void
    }
    private struct LogEntry: Codable, Sendable {
        let date: Date
        let stream: UInt8
        let payload: Data
        let startsSourceSession: Bool?

        init(
            date: Date,
            stream: UInt8,
            payload: Data,
            startsSourceSession: Bool? = nil
        ) {
            self.date = date
            self.stream = stream
            self.payload = payload
            self.startsSourceSession = startsSourceSession
        }
    }
    private var subscribers: [UUID: Subscriber] = [:]
    private var buffered: [Data] = []
    private var finished = false
    private var frozen = false
    private let tty: Bool
    private var logHandle: FileHandle?
    private var logIndexHandle: FileHandle?
    private var logEntries: [LogEntry] = []
    private var logPersistenceError: Error?
    private var inputFinished = false
    private var inputFinishResult: Result<Void, Error>?
    private var inputMonitorWasRegistered = false
    private var inputFinishHandler: (
        id: UUID, handler: @Sendable () throws -> Void
    )?

    public convenience init(tty: Bool, logURL: URL? = nil) {
        var logHandle: FileHandle?
        var logIndexHandle: FileHandle?
        var openingError: Error?
        if let logURL {
            do {
                try FileManager.default.createDirectory(
                    at: logURL.deletingLastPathComponent(),
                    withIntermediateDirectories: true
                )
                logHandle = try Self.openOrCreateRegularFile(at: logURL)
                logIndexHandle = try Self.openOrCreateRegularFile(
                    at: logURL.appendingPathExtension("entries")
                )
            } catch {
                openingError = error
            }
        }
        self.init(
            tty: tty,
            logHandle: logHandle,
            logIndexHandle: logIndexHandle,
            initialPersistenceError: openingError
        )
    }

    init(
        tty: Bool,
        logHandle: FileHandle?,
        logIndexHandle: FileHandle?,
        initialPersistenceError: Error? = nil
    ) {
        self.tty = tty
        self.logHandle = logHandle
        self.logIndexHandle = logIndexHandle
        (inputStream, inputContinuation) = AsyncStream.makeStream(of: Data.self)
        logPersistenceError = initialPersistenceError
        do {
            logEntries = try Self.recoverLogEntries(
                tty: tty,
                logHandle: logHandle,
                logIndexHandle: logIndexHandle
            )
        } catch {
            // Keep raw reads available, but never append an entry behind an
            // index state whose valid boundary could not be established.
            if logPersistenceError == nil { logPersistenceError = error }
        }
    }

    public func stream() -> AsyncStream<Data> { inputStream }
    public func sendInput(_ data: Data) {
        inputLock.withLock {
            guard !inputFinished else { return }
            inputContinuation.yield(data)
        }
    }

    public func finishInput() throws {
        try inputLock.withLock {
            if let inputFinishResult { return try inputFinishResult.get() }
            guard !inputFinished else { return }
            inputFinished = true
            inputContinuation.finish()
            // The registered monitor waits until every previously yielded byte
            // is written and the durable EOF marker is published. Holding this
            // lock makes finish-vs-stop ordering explicit: whichever operation
            // acquires it first owns the close decision.
            guard let inputFinishHandler else {
                if inputMonitorWasRegistered {
                    let error = EngineError(
                        .conflict,
                        "container input monitor stopped before EOF publication"
                    )
                    inputFinishResult = .failure(error)
                    throw error
                }
                inputFinishResult = .success(())
                return
            }
            self.inputFinishHandler = nil
            do {
                try inputFinishHandler.handler()
                inputFinishResult = .success(())
            } catch {
                inputFinishResult = .failure(error)
                throw error
            }
        }
    }

    func registerInputFinishHandler(
        _ handler: @escaping @Sendable () throws -> Void
    ) -> UUID {
        inputLock.withLock {
            let id = UUID()
            inputMonitorWasRegistered = true
            if inputFinished {
                do {
                    try handler()
                    inputFinishResult = .success(())
                } catch {
                    inputFinishResult = .failure(error)
                }
            } else {
                inputFinishHandler = (id, handler)
            }
            return id
        }
    }

    func unregisterInputFinishHandler(_ id: UUID) {
        inputLock.withLock {
            guard inputFinishHandler?.id == id else { return }
            inputFinishHandler = nil
        }
    }

    public func writer(_ stream: OutputStream) -> any CEngineWriter { OutputWriter(bridge: self, stream: stream) }

    @discardableResult
    public func attach(
        replayBuffered: Bool = true,
        output: @escaping @Sendable (Data) -> Void,
        closed: @escaping @Sendable () -> Void
    ) -> UUID {
        let id = UUID()
        lock.lock()
        let pending: [Data]
        if replayBuffered, frozen {
            let replay = Self.rawLogData(logEntries, tty: tty)
            pending = replay.isEmpty ? [] : [replay]
        } else {
            pending = replayBuffered ? buffered : []
            buffered.removeAll(keepingCapacity: false)
        }
        let alreadyFinished = finished
        if !alreadyFinished {
            subscribers[id] = .init(output: { data, _, _ in output(data) }, closed: closed)
        }
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
        subscribers.removeAll(keepingCapacity: false)
        lock.unlock()
        close.forEach { $0() }
    }

    /// Converts a completed live bridge into an immutable, bounded in-memory
    /// snapshot. Exact output is made durable before callers invoke this; the
    /// snapshot intentionally retains only a suffix for later inspect/attach
    /// while releasing both persistent descriptors and subscriber closures.
    func freezeCompleted(
        maximumBytes: Int = defaultCompletedSnapshotByteLimit,
        maximumEntries: Int = 1_024
    ) {
        finishOutput()
        inputLock.withLock {
            if !inputFinished {
                inputFinished = true
                inputContinuation.finish()
            }
            inputFinishHandler = nil
        }
        let handles: [FileHandle] = lock.withLock {
            guard !frozen else { return [] }
            let limit = max(0, maximumBytes)
            let entryLimit = max(0, maximumEntries)
            var remaining = limit
            var retained: [LogEntry] = []
            for entry in logEntries.reversed() {
                guard OutputStream(rawValue: entry.stream) != nil,
                      remaining > 0, retained.count < entryLimit else {
                    continue
                }
                if entry.payload.count <= remaining {
                    retained.append(entry)
                    remaining -= entry.payload.count
                } else {
                    retained.append(.init(
                        date: entry.date,
                        stream: entry.stream,
                        payload: Data(entry.payload.suffix(remaining))
                    ))
                    remaining = 0
                }
            }
            logEntries = Array(retained.reversed())
            // Completed output has one immutable representation. Framing is
            // derived on demand for the single legal Docker start/attach
            // response instead of retaining a second full-sized byte copy.
            buffered.removeAll(keepingCapacity: false)
            logPersistenceError = nil
            frozen = true
            let result = [logHandle, logIndexHandle].compactMap { $0 }
            logHandle = nil
            logIndexHandle = nil
            return result
        }
        for handle in handles { try? handle.close() }
    }

    var retainedPersistentDescriptorCount: Int {
        lock.withLock { (logHandle == nil ? 0 : 1) + (logIndexHandle == nil ? 0 : 1) }
    }

    var retainedLogPayloadByteCount: Int {
        lock.withLock { logEntries.reduce(0) { $0 + $1.payload.count } }
    }

    var retainedBufferedByteCount: Int {
        lock.withLock { buffered.reduce(0) { $0 + $1.count } }
    }

    /// Releases an already-completed output snapshot without reviving any
    /// descriptors or callbacks. Docker exec inspect metadata lives in
    /// EngineRuntime and remains available after this bounded-cache eviction.
    func discardCompletedOutput() {
        lock.withLock {
            guard frozen else { return }
            logEntries.removeAll(keepingCapacity: false)
            buffered.removeAll(keepingCapacity: false)
        }
    }

    public func logData() throws -> Data {
        try lock.withLock {
            if !logEntries.isEmpty {
                return Self.rawLogData(logEntries, tty: tty)
            }
            guard let logHandle else { return Data() }
            return try Self.readAll(from: logHandle)
        }
    }

    public func logData(options: DockerLogOptions) throws -> Data {
        try lock.withLock {
            guard !logEntries.isEmpty else {
                guard let logHandle else { return Data() }
                return try Self.readAll(from: logHandle)
            }
            return Self.render(logEntries, tty: tty, options: options)
        }
    }

    /// Byte counts already committed from each canonical VM output stream.
    /// The journal, not the raw mirror, is the durable publication boundary.
    /// Recovery uses these offsets to ingest bytes written while the daemon
    /// monitor was stopped without replaying previously journaled output.
    func durableSourceByteOffsets() -> [OutputStream: UInt64]? {
        lock.withLock {
            guard logIndexHandle != nil else { return nil }
            var result: [OutputStream: UInt64] = [.stdout: 0, .stderr: 0]
            for entry in logEntries {
                if entry.startsSourceSession == true {
                    result = [.stdout: 0, .stderr: 0]
                    continue
                }
                guard let stream = OutputStream(rawValue: entry.stream) else { continue }
                result[stream, default: 0] &+= UInt64(entry.payload.count)
            }
            return result
        }
    }

    /// Publishes a durable boundary after the canonical stdout/stderr files
    /// have been truncated for a new process session. Historical Docker logs
    /// remain readable, while recovery cursors count only this source epoch.
    func beginSourceSession() throws {
        try lock.withLock {
            if let logPersistenceError { throw logPersistenceError }
            let marker = LogEntry(
                date: Date(), stream: 0, payload: Data(), startsSourceSession: true
            )
            do {
                if let logIndexHandle {
                    try Self.appendJournalEntry(marker, to: logIndexHandle)
                }
                logEntries.append(marker)
            } catch {
                logPersistenceError = error
                throw error
            }
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
        let alreadyFinished = finished
        if !alreadyFinished {
            subscribers[id] = .init(output: { data, stream, date in
                guard Self.includes(stream: stream, date: date, options: liveOptions) else { return }
                let entry = LogEntry(date: date, stream: stream.rawValue, payload: Self.payload(from: data, tty: self.tty))
                output(Self.render([entry], tty: self.tty, options: liveOptions))
            }, closed: closed)
        }
        lock.unlock()
        if alreadyFinished { closed() }
        return (id, initial)
    }

    fileprivate func write(_ data: Data, stream: OutputStream) throws {
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
        let entry = LogEntry(date: date, stream: stream.rawValue, payload: data)
        let handlers = try lock.withLock {
            guard !frozen else {
                throw EngineError(.conflict, "completed exec output is immutable")
            }
            if let logPersistenceError { throw logPersistenceError }
            do {
                if let logIndexHandle {
                    // The self-contained journal is authoritative. Publish and
                    // synchronize it before updating the raw Docker-log mirror.
                    try Self.appendJournalEntry(entry, to: logIndexHandle)
                    logEntries.append(entry)
                    if let logHandle {
                        try Self.appendAndSynchronize(framed, to: logHandle)
                    }
                } else {
                    if let logHandle {
                        try Self.appendAndSynchronize(framed, to: logHandle)
                    }
                    logEntries.append(entry)
                }
            } catch {
                logPersistenceError = error
                throw error
            }
            let handlers = subscribers.values.map(\.output)
            if handlers.isEmpty { buffered.append(framed) }
            return handlers
        }
        handlers.forEach { $0(framed, stream, date) }
    }

    private struct JournalRecovery {
        let entries: [LogEntry]
        let validByteCount: Int
        let recognized: Bool
    }

    /// Recover the longest completely framed journal prefix. A partial final
    /// frame is a normal crash boundary and is removed durably before future
    /// appends. The raw log is only a mirror; if the journal reached disk first,
    /// it can deterministically reconstruct that mirror after restart.
    private static func recoverLogEntries(
        tty: Bool,
        logHandle: FileHandle?,
        logIndexHandle: FileHandle?
    ) throws -> [LogEntry] {
        var entries: [LogEntry] = []
        if let logIndexHandle {
            let data = try readAll(from: logIndexHandle)
            if !data.isEmpty {
                let recovery = decodeJournal(data)
                if recovery.recognized {
                    entries = recovery.entries
                    if recovery.validByteCount != data.count {
                        try truncateAndSynchronize(
                            logIndexHandle, to: recovery.validByteCount
                        )
                    }
                } else if let legacy = try? JSONDecoder().decode(
                    [LogEntry].self, from: data
                ) {
                    entries = legacy
                    try rewriteJournal(entries, in: logIndexHandle)
                } else {
                    try truncateAndSynchronize(logIndexHandle, to: 0)
                }
            }
        }

        if let logHandle {
            let raw = try readAll(from: logHandle)
            let committedRaw = rawLogData(entries, tty: tty)
            if raw.starts(with: committedRaw), raw.count > committedRaw.count {
                let suffix = Data(raw.dropFirst(committedRaw.count))
                let recovered = recoverRawEntries(
                    suffix, tty: tty, date: modificationDate(of: logHandle)
                )
                if !recovered.isEmpty {
                    if let logIndexHandle {
                        for entry in recovered {
                            try appendJournalEntry(entry, to: logIndexHandle)
                        }
                    }
                    entries.append(contentsOf: recovered)
                }
            }

            let repairedRaw = rawLogData(entries, tty: tty)
            if raw != repairedRaw, !entries.isEmpty {
                try rewriteAndSynchronize(repairedRaw, in: logHandle)
            }
        }
        return entries
    }

    private static func decodeJournal(_ data: Data) -> JournalRecovery {
        var entries: [LogEntry] = []
        var offset = 0
        var recognized = false
        while offset < data.count {
            let remaining = data.count - offset
            if remaining < journalHeaderSize {
                let availableMagic = min(remaining, journalMagic.count)
                if availableMagic > 0,
                   Data(data[offset..<(offset + availableMagic)])
                    == journalMagic.prefix(availableMagic) {
                    recognized = true
                }
                break
            }
            guard Data(data[offset..<(offset + journalMagic.count)]) == journalMagic else {
                break
            }
            recognized = true
            let length = decodeUInt64(data, at: offset + 4)
            let checksum = decodeUInt64(data, at: offset + 12)
            guard length <= UInt64(maximumJournalPayloadSize),
                  length <= UInt64(Int.max) else { break }
            let payloadCount = Int(length)
            let (frameEnd, overflow) = offset.addingReportingOverflow(
                journalHeaderSize + payloadCount
            )
            guard !overflow, frameEnd <= data.count else { break }
            let payload = Data(data[(offset + journalHeaderSize)..<frameEnd])
            guard journalChecksum(payload) == checksum,
                  let entry = try? JSONDecoder().decode(LogEntry.self, from: payload),
                  entry.startsSourceSession == true
                    || OutputStream(rawValue: entry.stream) != nil else { break }
            entries.append(entry)
            offset = frameEnd
        }
        return JournalRecovery(
            entries: entries, validByteCount: offset, recognized: recognized
        )
    }

    private static func appendJournalEntry(
        _ entry: LogEntry, to handle: FileHandle
    ) throws {
        let payload = try JSONEncoder().encode(entry)
        guard payload.count <= maximumJournalPayloadSize else {
            throw EngineError(.internalError, "container log entry is too large to index")
        }
        var frame = Data()
        frame.append(journalMagic)
        appendUInt64(UInt64(payload.count), to: &frame)
        appendUInt64(journalChecksum(payload), to: &frame)
        frame.append(payload)
        try appendAndSynchronize(frame, to: handle)
    }

    private static func rewriteJournal(
        _ entries: [LogEntry], in handle: FileHandle
    ) throws {
        try truncateAndSynchronize(handle, to: 0)
        for entry in entries {
            try appendJournalEntry(entry, to: handle)
        }
    }

    private static func recoverRawEntries(
        _ data: Data, tty: Bool, date: Date
    ) -> [LogEntry] {
        guard !data.isEmpty else { return [] }
        if tty {
            return [.init(date: date, stream: OutputStream.stdout.rawValue, payload: data)]
        }
        var entries: [LogEntry] = []
        var offset = 0
        while data.count - offset >= 8 {
            guard let stream = OutputStream(rawValue: data[offset]),
                  data[offset + 1] == 0,
                  data[offset + 2] == 0,
                  data[offset + 3] == 0 else { break }
            let payloadCount = Int(decodeUInt32(data, at: offset + 4))
            let (frameEnd, overflow) = offset.addingReportingOverflow(8 + payloadCount)
            guard !overflow, frameEnd <= data.count else { break }
            entries.append(.init(
                date: date,
                stream: stream.rawValue,
                payload: Data(data[(offset + 8)..<frameEnd])
            ))
            offset = frameEnd
        }
        return entries
    }

    private static func rawLogData(_ entries: [LogEntry], tty: Bool) -> Data {
        var result = Data()
        for entry in entries {
            guard OutputStream(rawValue: entry.stream) != nil else { continue }
            if tty {
                result.append(entry.payload)
            } else {
                var header = Data([entry.stream, 0, 0, 0])
                var count = UInt32(entry.payload.count).bigEndian
                withUnsafeBytes(of: &count) { header.append(contentsOf: $0) }
                result.append(header)
                result.append(entry.payload)
            }
        }
        return result
    }

    private static func appendAndSynchronize(
        _ data: Data, to handle: FileHandle
    ) throws {
        try handle.seekToEnd()
        try handle.write(contentsOf: data)
        try handle.synchronize()
    }

    private static func rewriteAndSynchronize(
        _ data: Data, in handle: FileHandle
    ) throws {
        guard Darwin.ftruncate(handle.fileDescriptor, 0) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try handle.seek(toOffset: 0)
        try handle.write(contentsOf: data)
        try handle.synchronize()
        try handle.seekToEnd()
    }

    private static func truncateAndSynchronize(
        _ handle: FileHandle, to byteCount: Int
    ) throws {
        guard Darwin.ftruncate(handle.fileDescriptor, off_t(byteCount)) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try handle.synchronize()
        try handle.seekToEnd()
    }

    private static func appendUInt64(_ value: UInt64, to data: inout Data) {
        var encoded = value.bigEndian
        withUnsafeBytes(of: &encoded) { data.append(contentsOf: $0) }
    }

    private static func decodeUInt64(_ data: Data, at offset: Int) -> UInt64 {
        data[offset..<(offset + 8)].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }

    private static func decodeUInt32(_ data: Data, at offset: Int) -> UInt32 {
        data[offset..<(offset + 4)].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    }

    private static func journalChecksum(_ data: Data) -> UInt64 {
        data.reduce(UInt64(1_469_598_103_934_665_603)) {
            ($0 ^ UInt64($1)) &* 1_099_511_628_211
        }
    }

    private static func modificationDate(of handle: FileHandle) -> Date {
        var information = stat()
        guard Darwin.fstat(handle.fileDescriptor, &information) == 0 else { return Date() }
        return Date(
            timeIntervalSince1970: TimeInterval(information.st_mtimespec.tv_sec)
                + TimeInterval(information.st_mtimespec.tv_nsec) / 1_000_000_000
        )
    }

    private static func openOrCreateRegularFile(at url: URL) throws -> FileHandle {
        let descriptor = Darwin.open(
            url.path,
            O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
            mode_t(0o600)
        )
        guard descriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        var information = stat()
        guard Darwin.fstat(descriptor, &information) == 0,
              information.st_mode & S_IFMT == S_IFREG else {
            Darwin.close(descriptor)
            throw EngineError(.conflict, "container log path is not a regular file")
        }
        return FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    }

    private static func readAll(from handle: FileHandle) throws -> Data {
        try handle.seek(toOffset: 0)
        let data = try handle.readToEnd() ?? Data()
        try handle.seekToEnd()
        return data
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

private final class OutputWriter: CEngineWriter, @unchecked Sendable {
    private let bridge: ContainerIOBridge
    private let stream: ContainerIOBridge.OutputStream
    init(bridge: ContainerIOBridge, stream: ContainerIOBridge.OutputStream) { self.bridge = bridge; self.stream = stream }
    func write(_ data: Data) throws { try bridge.write(data, stream: stream) }
    func close() throws {}
}

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
    static let defaultCompletedSnapshotByteLimit = 8 * 1_024 * 1_024

    private let lock = NSLock()
    private let inputLock = NSLock()
    private let inputStream: AsyncStream<Data>
    private let inputContinuation: AsyncStream<Data>.Continuation
    private struct Subscriber: Sendable {
        let output: @Sendable (Data, OutputStream, Date) -> Void
        let closed: @Sendable () -> Void
    }
    private struct SourceOffsets: Codable, Sendable {
        let stdout: UInt64
        let stderr: UInt64
    }

    private struct LogEntry: Codable, Sendable {
        let date: Date
        let stream: UInt8
        let payload: Data
        let startsSourceSession: Bool?
        let sourceOffsets: SourceOffsets?

        init(
            date: Date,
            stream: UInt8,
            payload: Data,
            startsSourceSession: Bool? = nil,
            sourceOffsets: SourceOffsets? = nil
        ) {
            self.date = date
            self.stream = stream
            self.payload = payload
            self.startsSourceSession = startsSourceSession
            self.sourceOffsets = sourceOffsets
        }
    }
    private var subscribers: [UUID: Subscriber] = [:]
    private var buffered: [Data] = []
    private var finished = false
    private var frozen = false
    private let tty: Bool
    private var logHandle: FileHandle?
    /// The fixed index handle is retained only long enough to migrate legacy
    /// single-file journals. New records live in immutable generation segments.
    private var logIndexHandle: FileHandle?
    private let journalDirectory: PersistentStateDirectory?
    private var journalSegments: [JournalSegmentState] = []
    private var activeJournalHandle: FileHandle?
    private var logEntries: [LogEntry] = []
    private var sourceByteOffsets: [OutputStream: UInt64] = [.stdout: 0, .stderr: 0]
    private let retentionPolicy: ContainerLogRetentionPolicy
    private var logPersistenceError: Error?
    private var inputFinished = false
    private var inputFinishResult: Result<Void, Error>?
    private var inputMonitorWasRegistered = false
    private var inputFinishHandler: (
        id: UUID, handler: @Sendable () throws -> Void
    )?

    public convenience init(
        tty: Bool,
        logURL: URL? = nil,
        retentionPolicy: ContainerLogRetentionPolicy = .default
    ) {
        var logHandle: FileHandle?
        var logIndexHandle: FileHandle?
        var journalDirectory: PersistentStateDirectory?
        var openingError: Error?
        if let logURL {
            do {
                let parentURL = logURL.deletingLastPathComponent()
                try FileManager.default.createDirectory(
                    at: parentURL, withIntermediateDirectories: true
                )
                logHandle = try Self.openOrCreateRegularFile(at: logURL)
                logIndexHandle = try Self.openOrCreateRegularFile(
                    at: logURL.appendingPathExtension("entries")
                )
                let parent = try PersistentStateDirectory.open(parentURL)
                journalDirectory = try parent.openOrCreateDirectory(
                    named: logURL.lastPathComponent + ".journal"
                )
            } catch {
                openingError = error
            }
        }
        self.init(
            tty: tty,
            logHandle: logHandle,
            logIndexHandle: logIndexHandle,
            journalDirectory: journalDirectory,
            initialPersistenceError: openingError,
            retentionPolicy: retentionPolicy
        )
    }

    init(
        tty: Bool,
        logHandle: FileHandle?,
        logIndexHandle: FileHandle?,
        journalDirectory: PersistentStateDirectory? = nil,
        initialPersistenceError: Error? = nil,
        retentionPolicy: ContainerLogRetentionPolicy = .default
    ) {
        self.tty = tty
        self.logHandle = logHandle
        self.logIndexHandle = logIndexHandle
        self.journalDirectory = journalDirectory
        self.retentionPolicy = retentionPolicy
        (inputStream, inputContinuation) = AsyncStream.makeStream(of: Data.self)
        logPersistenceError = initialPersistenceError
        do {
            if let journalDirectory {
                let recovery = try Self.recoverSegmentedJournal(
                    tty: tty,
                    logHandle: logHandle,
                    legacyIndexHandle: logIndexHandle,
                    directory: journalDirectory,
                    policy: retentionPolicy
                )
                logEntries = recovery.entries
                journalSegments = recovery.segments
                activeJournalHandle = recovery.activeHandle
                try? logIndexHandle?.close()
                self.logIndexHandle = nil
            } else {
                logEntries = try Self.recoverLogEntries(
                    tty: tty,
                    logHandle: logHandle,
                    logIndexHandle: logIndexHandle,
                    policy: retentionPolicy
                )
            }
            sourceByteOffsets = try Self.recoveredSourceByteOffsets(logEntries)
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
            let result = [logHandle, logIndexHandle, activeJournalHandle].compactMap { $0 }
            logHandle = nil
            logIndexHandle = nil
            activeJournalHandle = nil
            return result
        }
        for handle in handles { try? handle.close() }
    }

    var retainedPersistentDescriptorCount: Int {
        lock.withLock {
            (logHandle == nil ? 0 : 1)
                + (logIndexHandle == nil ? 0 : 1)
                + (activeJournalHandle == nil ? 0 : 1)
        }
    }

    var retainedLogPayloadByteCount: Int {
        lock.withLock { logEntries.reduce(0) { result, entry in result + entry.payload.count } }
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
            let maximumBytes = try CheckedArithmetic.add(
                retentionPolicy.retainedBytes,
                try CheckedArithmetic.multiply(retentionPolicy.maximumRetainedRecords, 8)
            )
            return try Self.readAll(from: logHandle, maximumBytes: maximumBytes)
        }
    }

    public func logData(options: DockerLogOptions) throws -> Data {
        try lock.withLock {
            guard !logEntries.isEmpty else {
                guard let logHandle else { return Data() }
                let maximumBytes = try CheckedArithmetic.add(
                    retentionPolicy.retainedBytes,
                    try CheckedArithmetic.multiply(retentionPolicy.maximumRetainedRecords, 8)
                )
                return try Self.readAll(from: logHandle, maximumBytes: maximumBytes)
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
            guard logIndexHandle != nil || activeJournalHandle != nil else { return nil }
            return sourceByteOffsets
        }
    }

    /// Advances across a source-spool retention gap without manufacturing zero
    /// bytes from the punched source inode. The checkpoint is journal-durable
    /// before the monitor begins consuming the first retained segment.
    func advanceDurableSourceByteOffset(
        stream: OutputStream,
        to offset: UInt64
    ) throws {
        try lock.withLock {
            let current = sourceByteOffsets[stream] ?? 0
            guard offset > current else { return }
            if let logPersistenceError { throw logPersistenceError }
            guard logIndexHandle != nil || activeJournalHandle != nil else {
                throw EngineError(.internalError, "container log source checkpoint is unavailable")
            }
            do {
                try compactIfNeededForIncomingPayload(0)
                var next = sourceByteOffsets
                next[stream] = offset
                let marker = LogEntry(
                    date: Date(),
                    stream: 0,
                    payload: Data(),
                    sourceOffsets: .init(
                        stdout: next[.stdout] ?? 0,
                        stderr: next[.stderr] ?? 0
                    )
                )
                try appendPersistentJournalEntry(marker)
                logEntries.append(marker)
                sourceByteOffsets = next
            } catch {
                logPersistenceError = error
                throw error
            }
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
                if logIndexHandle != nil || activeJournalHandle != nil {
                    try appendPersistentJournalEntry(marker)
                }
                logEntries.append(marker)
                sourceByteOffsets = [.stdout: 0, .stderr: 0]
                try compactIfNeededForIncomingPayload(0)
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
        guard data.count <= retentionPolicy.maximumRecordBytes,
              let frameLength = UInt32(exactly: data.count) else {
            throw EngineError(.internalError, "container log record exceeds the retention policy")
        }
        let framed: Data
        if tty {
            framed = data
        } else {
            var header = Data([stream.rawValue, 0, 0, 0])
            var count = frameLength.bigEndian
            withUnsafeBytes(of: &count) { header.append(contentsOf: $0) }
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
                try compactIfNeededForIncomingPayload(data.count)
                let oldOffset = sourceByteOffsets[stream] ?? 0
                let nextOffset = try CheckedArithmetic.add(oldOffset, UInt64(data.count))
                if logIndexHandle != nil || activeJournalHandle != nil {
                    // The self-contained journal is authoritative. Publish and
                    // synchronize it before updating the raw Docker-log mirror.
                    try appendPersistentJournalEntry(entry)
                    logEntries.append(entry)
                    sourceByteOffsets[stream] = nextOffset
                    if let logHandle {
                        try Self.appendAndSynchronize(framed, to: logHandle)
                    }
                } else {
                    if let logHandle {
                        try Self.appendAndSynchronize(framed, to: logHandle)
                    }
                    logEntries.append(entry)
                    sourceByteOffsets[stream] = nextOffset
                }
            } catch {
                logPersistenceError = error
                throw error
            }
            let handlers = subscribers.values.map(\.output)
            if handlers.isEmpty {
                buffered.append(framed)
                while buffered.count > retentionPolicy.followerQueueRecords
                    || buffered.reduce(0, { $0 + $1.count }) > retentionPolicy.followerQueueBytes {
                    buffered.removeFirst()
                }
            }
            return handlers
        }
        handlers.forEach { $0(framed, stream, date) }
    }

    private func compactIfNeededForIncomingPayload(_ incomingBytes: Int) throws {
        let retainedBytes = try logEntries.reduce(0) {
            try CheckedArithmetic.add($0, $1.payload.count)
        }
        let journalLimit = try CheckedArithmetic.add(
            try CheckedArithmetic.add(
                try CheckedArithmetic.multiply(retentionPolicy.retainedBytes, 2),
                try CheckedArithmetic.multiply(retentionPolicy.maximumRecordBytes, 2)
            ),
            try CheckedArithmetic.multiply(retentionPolicy.maximumRetainedRecords, 256)
        )
        let rawLimit = try CheckedArithmetic.add(
            retentionPolicy.retainedBytes,
            try CheckedArithmetic.multiply(retentionPolicy.maximumRetainedRecords, 8)
        )
        let allowedExisting = retentionPolicy.retainedBytes - incomingBytes
        let shouldCompact = retainedBytes > allowedExisting
            || logEntries.count >= retentionPolicy.maximumRetainedRecords
            || journalPhysicalSize().map { $0 >= journalLimit } == true
            || Self.fileSize(logHandle).map { $0 >= rawLimit } == true
        guard shouldCompact else { return }

        var remainingBytes = allowedExisting
        var remainingRecords = max(0, retentionPolicy.maximumRetainedRecords - 1)
        var retained: [LogEntry] = []
        for entry in logEntries.reversed() {
            guard OutputStream(rawValue: entry.stream) != nil,
                  remainingBytes > 0, remainingRecords > 0 else { continue }
            if entry.payload.count <= remainingBytes {
                retained.append(entry)
                remainingBytes -= entry.payload.count
            } else {
                retained.append(.init(
                    date: entry.date,
                    stream: entry.stream,
                    payload: Data(entry.payload.suffix(remainingBytes))
                ))
                remainingBytes = 0
            }
            remainingRecords -= 1
        }
        retained.reverse()
        retained.append(.init(
            date: Date(),
            stream: 0,
            payload: Data(),
            sourceOffsets: .init(
                stdout: sourceByteOffsets[.stdout] ?? 0,
                stderr: sourceByteOffsets[.stderr] ?? 0
            )
        ))
        if journalDirectory != nil {
            try replaceSegmentedJournal(with: retained)
        } else if let logIndexHandle {
            try Self.rewriteJournal(
                retained, in: logIndexHandle, policy: retentionPolicy
            )
        }
        if let logHandle {
            try Self.rewriteAndSynchronize(Self.rawLogData(retained, tty: tty), in: logHandle)
        }
        logEntries = retained
    }

    private struct JournalSegmentReference: Codable, Equatable, Sendable {
        let name: String
        let identity: PersistentFileIdentity
    }

    private struct JournalManifest: Codable, Sendable {
        static let currentSchemaVersion = 1

        let schemaVersion: Int
        let segments: [JournalSegmentReference]

        init(segments: [JournalSegmentReference]) {
            schemaVersion = Self.currentSchemaVersion
            self.segments = segments
        }
    }

    private struct JournalSegmentState {
        let name: String
        let identity: PersistentFileIdentity
        var payloadBytes: Int
        var recordCount: Int
        var encodedBytes: Int

        var reference: JournalSegmentReference {
            .init(name: name, identity: identity)
        }
    }

    private struct SegmentedJournalRecovery {
        let entries: [LogEntry]
        let segments: [JournalSegmentState]
        let activeHandle: FileHandle
    }

    private func appendPersistentJournalEntry(_ entry: LogEntry) throws {
        if let directory = journalDirectory {
            let frame = try Self.journalFrame(entry, policy: retentionPolicy)
            guard var active = journalSegments.last,
                  let activeJournalHandle else {
                throw EngineError(.internalError, "container log journal has no active segment")
            }
            let payloadWouldOverflow = active.recordCount > 0
                && active.payloadBytes > retentionPolicy.segmentBytes - entry.payload.count
            let encodedLimit = try Self.journalSegmentEncodedLimit(retentionPolicy)
            let encodedWouldOverflow = active.recordCount > 0
                && active.encodedBytes > encodedLimit - frame.count
            if payloadWouldOverflow || encodedWouldOverflow {
                try rotateSegmentedJournal(in: directory)
                guard let rotated = journalSegments.last,
                      let rotatedHandle = self.activeJournalHandle else {
                    throw EngineError(.internalError, "container log journal rotation failed")
                }
                active = rotated
                try Self.appendAndSynchronize(frame, to: rotatedHandle)
            } else {
                try Self.appendAndSynchronize(frame, to: activeJournalHandle)
            }
            active.payloadBytes = try CheckedArithmetic.add(
                active.payloadBytes, entry.payload.count
            )
            active.recordCount = try CheckedArithmetic.add(active.recordCount, 1)
            active.encodedBytes = try CheckedArithmetic.add(active.encodedBytes, frame.count)
            journalSegments[journalSegments.count - 1] = active
            return
        }
        guard let logIndexHandle else {
            throw EngineError(.internalError, "container log journal is unavailable")
        }
        try Self.appendJournalEntry(entry, to: logIndexHandle, policy: retentionPolicy)
    }

    private func rotateSegmentedJournal(
        in directory: PersistentStateDirectory
    ) throws {
        if journalSegments.count >= retentionPolicy.maximumSegments {
            try replaceSegmentedJournal(with: logEntries)
        }
        guard journalSegments.count < retentionPolicy.maximumSegments else {
            throw EngineError(.internalError, "container log journal segment limit exhausted")
        }
        let created = try Self.createJournalSegment(in: directory)
        do {
            let references = journalSegments.map(\.reference) + [created.state.reference]
            try Self.publishJournalManifest(references, in: directory)
        } catch {
            try? created.handle.close()
            try? directory.removeRegularFileIfPresent(named: created.state.name)
            throw error
        }
        try? activeJournalHandle?.close()
        activeJournalHandle = created.handle
        journalSegments.append(created.state)
    }

    private func replaceSegmentedJournal(with entries: [LogEntry]) throws {
        guard let directory = journalDirectory else {
            throw EngineError(.internalError, "container log journal directory is unavailable")
        }
        let previous = journalSegments
        let replacement = try Self.publishJournalGeneration(
            entries, in: directory, policy: retentionPolicy
        )
        try? activeJournalHandle?.close()
        journalSegments = replacement.segments
        activeJournalHandle = replacement.activeHandle
        let retainedNames = Set(replacement.segments.map(\.name))
        for segment in previous where !retainedNames.contains(segment.name) {
            guard let current = try directory.entryMetadata(named: segment.name),
                  current.type == S_IFREG,
                  current.identity == segment.identity else {
                if try directory.entryMetadata(named: segment.name) != nil {
                    throw EngineError(.conflict, "container log segment changed before retirement")
                }
                continue
            }
            try directory.removeRegularFileIfPresent(named: segment.name)
        }
    }

    private func journalPhysicalSize() -> Int? {
        if journalDirectory != nil {
            return try? journalSegments.reduce(0) {
                try CheckedArithmetic.add($0, $1.encodedBytes)
            }
        }
        return Self.fileSize(logIndexHandle)
    }

    private static func recoverSegmentedJournal(
        tty: Bool,
        logHandle: FileHandle?,
        legacyIndexHandle: FileHandle?,
        directory: PersistentStateDirectory,
        policy: ContainerLogRetentionPolicy
    ) throws -> SegmentedJournalRecovery {
        let manifestData = try directory.readRegularFile(
            named: "manifest.json", maximumBytes: 64 * 1_024, required: false
        )
        guard let manifestData else {
            let legacyEntries = try recoverLogEntries(
                tty: tty,
                logHandle: logHandle,
                logIndexHandle: legacyIndexHandle,
                policy: policy
            )
            let replacement = try publishJournalGeneration(
                legacyEntries, in: directory, policy: policy
            )
            if let legacyIndexHandle {
                try truncateAndSynchronize(legacyIndexHandle, to: 0)
            }
            try removeOrphanedJournalFiles(
                in: directory,
                retaining: Set(replacement.segments.map(\.name))
            )
            return replacement
        }

        let manifest: JournalManifest
        do {
            manifest = try JSONDecoder().decode(JournalManifest.self, from: manifestData)
        } catch {
            throw EngineError(.conflict, "container log journal manifest is invalid")
        }
        guard manifest.schemaVersion == JournalManifest.currentSchemaVersion,
              !manifest.segments.isEmpty,
              manifest.segments.count <= policy.maximumSegments,
              Set(manifest.segments.map(\.name)).count == manifest.segments.count,
              manifest.segments.allSatisfy({ validJournalSegmentName($0.name) }) else {
            throw EngineError(.conflict, "container log journal manifest is invalid")
        }

        let segmentLimit = try journalSegmentEncodedLimit(policy)
        var entries: [LogEntry] = []
        var states: [JournalSegmentState] = []
        var activeHandle: FileHandle?
        do {
            for (index, reference) in manifest.segments.enumerated() {
                let opened = try directory.openRegularFile(
                    named: reference.name,
                    expectedIdentity: reference.identity,
                    access: .readWrite
                )
                let handle = opened.handle
                let data = try readAll(from: handle, maximumBytes: segmentLimit)
                let recovery = decodeJournal(data, policy: policy)
                guard data.isEmpty || recovery.recognized else {
                    try? handle.close()
                    throw EngineError(.conflict, "container log journal segment is invalid")
                }
                if recovery.validByteCount != data.count {
                    try truncateAndSynchronize(handle, to: recovery.validByteCount)
                }
                let payloadBytes = try recovery.entries.reduce(0) {
                    try CheckedArithmetic.add($0, $1.payload.count)
                }
                states.append(.init(
                    name: reference.name,
                    identity: reference.identity,
                    payloadBytes: payloadBytes,
                    recordCount: recovery.entries.count,
                    encodedBytes: recovery.validByteCount
                ))
                entries.append(contentsOf: recovery.entries)
                if index == manifest.segments.count - 1 {
                    activeHandle = handle
                } else {
                    try handle.close()
                }
            }
        } catch {
            try? activeHandle?.close()
            throw error
        }
        guard let recoveredActiveHandle = activeHandle else {
            throw EngineError(.internalError, "container log journal has no active segment")
        }
        var selectedActiveHandle = recoveredActiveHandle

        let payloadBytes = try entries.reduce(0) {
            try CheckedArithmetic.add($0, $1.payload.count)
        }
        if payloadBytes > policy.retainedBytes
            || entries.count > policy.maximumRetainedRecords {
            let offsets = try recoveredSourceByteOffsets(entries)
            let retained = retainedSuffix(
                entries, policy: policy, sourceOffsets: offsets
            )
            try selectedActiveHandle.close()
            let replacement = try publishJournalGeneration(
                retained, in: directory, policy: policy
            )
            for state in states
                where !replacement.segments.contains(where: { $0.name == state.name }) {
                if let current = try directory.entryMetadata(named: state.name),
                   current.identity == state.identity, current.type == S_IFREG {
                    try directory.removeRegularFileIfPresent(named: state.name)
                }
            }
            entries = retained
            states = replacement.segments
            selectedActiveHandle = replacement.activeHandle
        }

        if let logHandle {
            let rawLimit = try CheckedArithmetic.add(
                policy.retainedBytes,
                try CheckedArithmetic.multiply(policy.maximumRetainedRecords, 8)
            )
            let raw = try readAll(from: logHandle, maximumBytes: rawLimit)
            let repaired = rawLogData(entries, tty: tty)
            if raw != repaired { try rewriteAndSynchronize(repaired, in: logHandle) }
        }
        try removeOrphanedJournalFiles(
            in: directory, retaining: Set(states.map(\.name))
        )
        return .init(
            entries: entries, segments: states, activeHandle: selectedActiveHandle
        )
    }

    private static func publishJournalGeneration(
        _ entries: [LogEntry],
        in directory: PersistentStateDirectory,
        policy: ContainerLogRetentionPolicy
    ) throws -> SegmentedJournalRecovery {
        var groups: [[LogEntry]] = [[]]
        var groupPayloadBytes = 0
        for entry in entries {
            if !groups[groups.count - 1].isEmpty,
               groupPayloadBytes > policy.segmentBytes - entry.payload.count {
                groups.append([])
                groupPayloadBytes = 0
            }
            groups[groups.count - 1].append(entry)
            groupPayloadBytes = try CheckedArithmetic.add(
                groupPayloadBytes, entry.payload.count
            )
        }
        guard groups.count <= policy.maximumSegments else {
            throw EngineError(.internalError, "container log journal requires too many segments")
        }

        var created: [(state: JournalSegmentState, handle: FileHandle)] = []
        do {
            for group in groups {
                var segment = try createJournalSegment(in: directory)
                var encoded = Data()
                var payloadBytes = 0
                for entry in group {
                    let frame = try journalFrame(entry, policy: policy)
                    encoded.append(frame)
                    payloadBytes = try CheckedArithmetic.add(
                        payloadBytes, entry.payload.count
                    )
                }
                if !encoded.isEmpty {
                    try appendAndSynchronize(encoded, to: segment.handle)
                }
                segment.state.payloadBytes = payloadBytes
                segment.state.recordCount = group.count
                segment.state.encodedBytes = encoded.count
                created.append(segment)
            }
            try publishJournalManifest(created.map { $0.state.reference }, in: directory)
        } catch {
            for segment in created {
                try? segment.handle.close()
                try? directory.removeRegularFileIfPresent(named: segment.state.name)
            }
            throw error
        }
        for segment in created.dropLast() { try segment.handle.close() }
        guard let active = created.last else {
            throw EngineError(.internalError, "container log journal generation is empty")
        }
        return .init(
            entries: entries,
            segments: created.map(\.state),
            activeHandle: active.handle
        )
    }

    private static func createJournalSegment(
        in directory: PersistentStateDirectory
    ) throws -> (state: JournalSegmentState, handle: FileHandle) {
        let name = "segment-\(UUID().uuidString.lowercased()).celj"
        let identity = try directory.createSparseRegularFile(named: name, size: 0)
        do {
            let handle = try directory.openRegularFile(
                named: name, expectedIdentity: identity, access: .readWrite
            ).handle
            return (
                .init(
                    name: name, identity: identity, payloadBytes: 0,
                    recordCount: 0, encodedBytes: 0
                ),
                handle
            )
        } catch {
            try? directory.removeRegularFileIfPresent(named: name)
            throw error
        }
    }

    private static func publishJournalManifest(
        _ references: [JournalSegmentReference],
        in directory: PersistentStateDirectory
    ) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(JournalManifest(segments: references))
        guard data.count <= 64 * 1_024 else {
            throw EngineError(.internalError, "container log journal manifest is too large")
        }
        try directory.replaceRegularFile(named: "manifest.json", data: data)
    }

    private static func removeOrphanedJournalFiles(
        in directory: PersistentStateDirectory,
        retaining names: Set<String>
    ) throws {
        for name in try directory.entryNames() {
            let isSegment = validJournalSegmentName(name)
            let isTemporaryManifest = name.hasPrefix(".cengine-state-")
            guard (isSegment && !names.contains(name)) || isTemporaryManifest else {
                continue
            }
            guard let metadata = try directory.entryMetadata(named: name),
                  metadata.type == S_IFREG else {
                throw EngineError(.conflict, "container log journal contains an unsafe orphan")
            }
            try directory.removeRegularFileIfPresent(named: name)
        }
    }

    private static func validJournalSegmentName(_ name: String) -> Bool {
        guard name.hasPrefix("segment-"), name.hasSuffix(".celj") else { return false }
        let start = name.index(name.startIndex, offsetBy: 8)
        let end = name.index(name.endIndex, offsetBy: -5)
        return UUID(uuidString: String(name[start..<end])) != nil
    }

    private static func journalSegmentEncodedLimit(
        _ policy: ContainerLogRetentionPolicy
    ) throws -> Int {
        try CheckedArithmetic.add(
            try CheckedArithmetic.add(
                try CheckedArithmetic.multiply(policy.segmentBytes, 2),
                try CheckedArithmetic.multiply(policy.maximumRecordBytes, 2)
            ),
            try CheckedArithmetic.multiply(policy.maximumRetainedRecords, 256)
        )
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
        logIndexHandle: FileHandle?,
        policy: ContainerLogRetentionPolicy
    ) throws -> [LogEntry] {
        let journalLimit = try CheckedArithmetic.add(
            try CheckedArithmetic.add(
                try CheckedArithmetic.multiply(policy.retainedBytes, 2),
                try CheckedArithmetic.multiply(policy.maximumRecordBytes, 2)
            ),
            try CheckedArithmetic.multiply(policy.maximumRetainedRecords, 256)
        )
        let rawLimit = try CheckedArithmetic.add(
            policy.retainedBytes,
            try CheckedArithmetic.multiply(policy.maximumRetainedRecords, 8)
        )
        if fileSize(logIndexHandle).map({ $0 > journalLimit }) == true
            || fileSize(logHandle).map({ $0 > rawLimit }) == true {
            if let logIndexHandle { try truncateAndSynchronize(logIndexHandle, to: 0) }
            if let logHandle { try truncateAndSynchronize(logHandle, to: 0) }
            return []
        }

        var entries: [LogEntry] = []
        if let logIndexHandle {
            let data = try readAll(from: logIndexHandle, maximumBytes: journalLimit)
            if !data.isEmpty {
                let recovery = decodeJournal(data, policy: policy)
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
                    try rewriteJournal(entries, in: logIndexHandle, policy: policy)
                } else {
                    try truncateAndSynchronize(logIndexHandle, to: 0)
                }
            }
        }

        if let logHandle {
            let raw = try readAll(from: logHandle, maximumBytes: rawLimit)
            let committedRaw = rawLogData(entries, tty: tty)
            if raw.starts(with: committedRaw), raw.count > committedRaw.count {
                let suffix = Data(raw.dropFirst(committedRaw.count))
                let recovered = recoverRawEntries(
                    suffix, tty: tty, date: modificationDate(of: logHandle), policy: policy
                )
                if !recovered.isEmpty {
                    if let logIndexHandle {
                        for entry in recovered {
                            try appendJournalEntry(
                                entry, to: logIndexHandle, policy: policy
                            )
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
        let payloadBytes = try entries.reduce(0) {
            try CheckedArithmetic.add($0, $1.payload.count)
        }
        if payloadBytes > policy.retainedBytes
            || entries.count > policy.maximumRetainedRecords {
            let offsets = try recoveredSourceByteOffsets(entries)
            entries = retainedSuffix(entries, policy: policy, sourceOffsets: offsets)
            if let logIndexHandle {
                try rewriteJournal(entries, in: logIndexHandle, policy: policy)
            }
            if let logHandle {
                try rewriteAndSynchronize(rawLogData(entries, tty: tty), in: logHandle)
            }
        }
        return entries
    }

    private static func decodeJournal(
        _ data: Data,
        policy: ContainerLogRetentionPolicy
    ) -> JournalRecovery {
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
            let maximumEncodedRecordBytes = UInt64(policy.maximumRecordBytes) * 2 + 64 * 1_024
            guard length <= maximumEncodedRecordBytes,
                  length <= UInt64(Int.max) else { break }
            let payloadCount = Int(length)
            let (frameEnd, overflow) = offset.addingReportingOverflow(
                journalHeaderSize + payloadCount
            )
            guard !overflow, frameEnd <= data.count else { break }
            let payload = Data(data[(offset + journalHeaderSize)..<frameEnd])
            guard journalChecksum(payload) == checksum,
                  let entry = try? JSONDecoder().decode(LogEntry.self, from: payload),
                  entry.payload.count <= policy.maximumRecordBytes,
                  entry.startsSourceSession == true || entry.sourceOffsets != nil
                    || OutputStream(rawValue: entry.stream) != nil else { break }
            entries.append(entry)
            offset = frameEnd
        }
        return JournalRecovery(
            entries: entries, validByteCount: offset, recognized: recognized
        )
    }

    private static func appendJournalEntry(
        _ entry: LogEntry,
        to handle: FileHandle,
        policy: ContainerLogRetentionPolicy
    ) throws {
        try appendAndSynchronize(
            try journalFrame(entry, policy: policy), to: handle
        )
    }

    private static func journalFrame(
        _ entry: LogEntry,
        policy: ContainerLogRetentionPolicy
    ) throws -> Data {
        guard entry.payload.count <= policy.maximumRecordBytes else {
            throw EngineError(.internalError, "container log entry is too large to index")
        }
        let payload = try JSONEncoder().encode(entry)
        let maximumEncodedRecordBytes = try CheckedArithmetic.add(
            try CheckedArithmetic.multiply(policy.maximumRecordBytes, 2),
            64 * 1_024
        )
        guard payload.count <= maximumEncodedRecordBytes else {
            throw EngineError(.internalError, "encoded container log entry is too large to index")
        }
        var frame = Data()
        frame.append(journalMagic)
        appendUInt64(UInt64(payload.count), to: &frame)
        appendUInt64(journalChecksum(payload), to: &frame)
        frame.append(payload)
        return frame
    }

    private static func rewriteJournal(
        _ entries: [LogEntry],
        in handle: FileHandle,
        policy: ContainerLogRetentionPolicy
    ) throws {
        try truncateAndSynchronize(handle, to: 0)
        for entry in entries {
            try appendJournalEntry(entry, to: handle, policy: policy)
        }
    }

    private static func recoverRawEntries(
        _ data: Data,
        tty: Bool,
        date: Date,
        policy: ContainerLogRetentionPolicy
    ) -> [LogEntry] {
        guard !data.isEmpty else { return [] }
        if tty {
            return stride(from: 0, to: data.count, by: policy.maximumRecordBytes).map { offset in
                .init(
                    date: date,
                    stream: OutputStream.stdout.rawValue,
                    payload: Data(data[offset..<min(data.count, offset + policy.maximumRecordBytes)])
                )
            }
        }
        var entries: [LogEntry] = []
        var offset = 0
        while data.count - offset >= 8 {
            guard let stream = OutputStream(rawValue: data[offset]),
                  data[offset + 1] == 0,
                  data[offset + 2] == 0,
                  data[offset + 3] == 0 else { break }
            let payloadCount = Int(decodeUInt32(data, at: offset + 4))
            guard payloadCount <= policy.maximumRecordBytes else { break }
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
                guard let payloadCount = UInt32(exactly: entry.payload.count) else { continue }
                var header = Data([entry.stream, 0, 0, 0])
                var count = payloadCount.bigEndian
                withUnsafeBytes(of: &count) { header.append(contentsOf: $0) }
                result.append(header)
                result.append(entry.payload)
            }
        }
        return result
    }

    private static func recoveredSourceByteOffsets(
        _ entries: [LogEntry]
    ) throws -> [OutputStream: UInt64] {
        var result: [OutputStream: UInt64] = [.stdout: 0, .stderr: 0]
        for entry in entries {
            if entry.startsSourceSession == true {
                result = [.stdout: 0, .stderr: 0]
                continue
            }
            if let offsets = entry.sourceOffsets {
                result = [.stdout: offsets.stdout, .stderr: offsets.stderr]
                continue
            }
            guard let stream = OutputStream(rawValue: entry.stream) else { continue }
            result[stream] = try CheckedArithmetic.add(
                result[stream] ?? 0, UInt64(entry.payload.count)
            )
        }
        return result
    }

    private static func retainedSuffix(
        _ entries: [LogEntry],
        policy: ContainerLogRetentionPolicy,
        sourceOffsets: [OutputStream: UInt64]
    ) -> [LogEntry] {
        var remainingBytes = policy.retainedBytes
        var remainingRecords = max(0, policy.maximumRetainedRecords - 1)
        var retained: [LogEntry] = []
        for entry in entries.reversed() {
            guard OutputStream(rawValue: entry.stream) != nil,
                  remainingBytes > 0, remainingRecords > 0 else { continue }
            if entry.payload.count <= remainingBytes {
                retained.append(entry)
                remainingBytes -= entry.payload.count
            } else {
                retained.append(.init(
                    date: entry.date,
                    stream: entry.stream,
                    payload: Data(entry.payload.suffix(remainingBytes))
                ))
                remainingBytes = 0
            }
            remainingRecords -= 1
        }
        retained.reverse()
        retained.append(.init(
            date: Date(),
            stream: 0,
            payload: Data(),
            sourceOffsets: .init(
                stdout: sourceOffsets[.stdout] ?? 0,
                stderr: sourceOffsets[.stderr] ?? 0
            )
        ))
        return retained
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

    private static func fileSize(_ handle: FileHandle?) -> Int? {
        guard let handle else { return nil }
        var information = stat()
        guard Darwin.fstat(handle.fileDescriptor, &information) == 0,
              information.st_size >= 0,
              let size = Int(exactly: information.st_size) else { return nil }
        return size
    }

    private static func readAll(
        from handle: FileHandle,
        maximumBytes: Int
    ) throws -> Data {
        guard maximumBytes >= 0 else {
            throw EngineError(.internalError, "invalid container log read limit")
        }
        try handle.seek(toOffset: 0)
        var data = Data()
        data.reserveCapacity(min(maximumBytes, 64 * 1_024))
        while data.count <= maximumBytes {
            let requested = min(64 * 1_024, maximumBytes + 1 - data.count)
            guard requested > 0,
                  let chunk = try handle.read(upToCount: requested),
                  !chunk.isEmpty else { break }
            data.append(chunk)
        }
        try handle.seekToEnd()
        guard data.count <= maximumBytes else {
            throw EngineError(.internalError, "container log exceeds its persisted size limit")
        }
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

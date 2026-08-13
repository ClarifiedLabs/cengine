import CEngineCore
import Darwin
import Foundation

private func lockOutputSpoolDirectory(_ directory: PersistentStateDirectory) throws {
    while flock(directory.descriptor, LOCK_EX) != 0 {
        guard errno == EINTR else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }
}

private func unlockOutputSpoolDirectory(_ directory: PersistentStateDirectory) {
    _ = flock(directory.descriptor, LOCK_UN)
}

/// Shim-owned, descriptor-confined source output. The guest keeps its pinned
/// O_APPEND descriptors for the lifetime of a process; the shim copies each
/// byte into bounded durable segments and only then deallocates the copied
/// range from the source inode. This bounds daemon-downtime output without
/// renaming or truncating a file behind an active guest writer.
final class VMShimOutputSpooler: @unchecked Sendable {
    private struct Cursor: Codable {
        static let currentSchemaVersion = 1
        let schemaVersion: Int
        let sourceOffset: UInt64

        init(sourceOffset: UInt64) {
            schemaVersion = Self.currentSchemaVersion
            self.sourceOffset = sourceOffset
        }
    }

    fileprivate struct Segment {
        let name: String
        let identity: PersistentFileIdentity
        let start: UInt64
        let end: UInt64
        let active: Bool
    }

    fileprivate final class StreamWriter: @unchecked Sendable {
        let source: FileHandle
        let directory: PersistentStateDirectory
        let segmentBytes: Int
        let retainedBytes: Int
        let maximumSegments: Int
        let punchBlockBytes: UInt64
        var sourceOffset: UInt64
        var sourcePunchOffset: UInt64
        var activeStart: UInt64
        var activeName: String
        var activeIdentity: PersistentFileIdentity
        var activeHandle: FileHandle
        var activeBytes: Int

        init(
            source: FileHandle,
            directory: PersistentStateDirectory,
            segmentBytes: Int,
            retainedBytes: Int,
            maximumSegments: Int
        ) throws {
            guard segmentBytes > 0,
                  retainedBytes >= segmentBytes,
                  maximumSegments >= 2 else {
                throw EngineError(.badRequest, "invalid container output spool policy")
            }
            self.source = source
            self.directory = directory
            self.segmentBytes = segmentBytes
            self.retainedBytes = retainedBytes
            self.maximumSegments = maximumSegments
            punchBlockBytes = try Self.filesystemBlockSize(source)
            sourcePunchOffset = 0
            try lockOutputSpoolDirectory(directory)
            defer { unlockOutputSpoolDirectory(directory) }
            try Self.removeTemporaryState(in: directory)
            let segments = try Self.segments(
                in: directory,
                segmentBytes: segmentBytes,
                maximumSegments: maximumSegments
            )
            let activeSegments = segments.filter(\.active)
            guard activeSegments.count <= 1 else {
                throw EngineError(.conflict, "container output spool has multiple active segments")
            }
            let persistedCursor: UInt64
            if let data = try directory.readRegularFile(
                named: "cursor.json", maximumBytes: 4 * 1_024, required: false
            ) {
                let cursor = try JSONDecoder().decode(Cursor.self, from: data)
                guard cursor.schemaVersion == Cursor.currentSchemaVersion else {
                    throw EngineError(.conflict, "container output spool cursor is invalid")
                }
                persistedCursor = cursor.sourceOffset
            } else {
                persistedCursor = 0
            }
            let segmentEnd = segments.map(\.end).max() ?? 0
            guard persistedCursor <= segmentEnd || persistedCursor == 0 else {
                throw EngineError(.conflict, "container output spool cursor exceeds durable data")
            }
            sourceOffset = max(persistedCursor, segmentEnd)
            if try Self.fileSize(source) < sourceOffset {
                try Self.reset(directory)
                sourceOffset = 0
            }
            if let active = activeSegments.first,
               active.end == sourceOffset {
                activeStart = active.start
                activeName = active.name
                activeIdentity = active.identity
                activeBytes = Int(active.end - active.start)
                activeHandle = try directory.openRegularFile(
                    named: active.name,
                    expectedIdentity: active.identity,
                    access: .readWrite
                ).handle
            } else {
                let created = try Self.createActiveSegment(
                    at: sourceOffset, in: directory
                )
                activeStart = sourceOffset
                activeName = created.name
                activeIdentity = created.identity
                activeHandle = created.handle
                activeBytes = 0
            }
            try persistCursor()
            try enforceRetention()
            try punchSource(through: sourceOffset)
        }

        func drain() throws {
            try lockOutputSpoolDirectory(directory)
            defer { unlockOutputSpoolDirectory(directory) }
            if try Self.fileSize(source) < sourceOffset {
                try resetForNewSourceSession()
            }
            try source.seek(toOffset: sourceOffset)
            while let data = try source.read(upToCount: 1 * 1_024 * 1_024),
                  !data.isEmpty {
                try append(data)
                try persistCursor()
                try enforceRetention()
                try punchSource(through: sourceOffset)
            }
        }

        private func append(_ data: Data) throws {
            var offset = data.startIndex
            while offset < data.endIndex {
                if activeBytes == segmentBytes { try rotate() }
                let count = min(segmentBytes - activeBytes, data.endIndex - offset)
                let piece = Data(data[offset..<(offset + count)])
                try activeHandle.seekToEnd()
                try activeHandle.write(contentsOf: piece)
                try activeHandle.synchronize()
                activeBytes += count
                sourceOffset = try CheckedArithmetic.add(sourceOffset, UInt64(count))
                offset += count
                if activeBytes == segmentBytes { try rotate() }
            }
        }

        private func rotate() throws {
            guard activeBytes > 0 else { return }
            try activeHandle.synchronize()
            try activeHandle.close()
            let closedName = Self.closedName(start: activeStart, end: sourceOffset)
            guard Darwin.renameat(
                directory.descriptor, activeName,
                directory.descriptor, closedName
            ) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            try directory.synchronize()
            let created = try Self.createActiveSegment(at: sourceOffset, in: directory)
            activeStart = sourceOffset
            activeName = created.name
            activeIdentity = created.identity
            activeHandle = created.handle
            activeBytes = 0
            try enforceRetention()
        }

        private func resetForNewSourceSession() throws {
            try activeHandle.close()
            try Self.reset(directory)
            sourceOffset = 0
            sourcePunchOffset = 0
            let created = try Self.createActiveSegment(at: 0, in: directory)
            activeStart = 0
            activeName = created.name
            activeIdentity = created.identity
            activeHandle = created.handle
            activeBytes = 0
            try persistCursor()
        }

        private func persistCursor() throws {
            try directory.replaceRegularFile(
                named: "cursor.json",
                data: try JSONEncoder().encode(Cursor(sourceOffset: sourceOffset))
            )
        }

        private func punchSource(through copiedEnd: UInt64) throws {
            // Darwin requires both F_PUNCHHOLE arguments to be filesystem-block
            // aligned. Keep at most one copied partial block allocated until a
            // later append completes it; the durable cursor makes re-punching
            // the aligned prefix after a restart safe.
            let alignedEnd = copiedEnd - (copiedEnd % punchBlockBytes)
            guard alignedEnd > sourcePunchOffset else { return }
            let length = alignedEnd - sourcePunchOffset
            guard sourcePunchOffset <= UInt64(Int64.max),
                  length <= UInt64(Int64.max) else {
                throw EngineError(.internalError, "container output punch range overflow")
            }
            var punch = fpunchhole_t(
                fp_flags: 0,
                reserved: 0,
                fp_offset: off_t(sourcePunchOffset),
                fp_length: off_t(length)
            )
            guard Darwin.fcntl(source.fileDescriptor, F_PUNCHHOLE, &punch) != -1 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            try source.synchronize()
            sourcePunchOffset = alignedEnd
        }

        private func enforceRetention() throws {
            var closed = try Self.segments(
                in: directory,
                segmentBytes: segmentBytes,
                maximumSegments: maximumSegments
            ).filter { !$0.active }.sorted { $0.start < $1.start }
            var total = activeBytes
            for segment in closed {
                total = try CheckedArithmetic.add(
                    total, Int(segment.end - segment.start)
                )
            }
            while let oldest = closed.first,
                  total > retainedBytes || closed.count + 1 > maximumSegments {
                guard let current = try directory.entryMetadata(named: oldest.name),
                      current.identity == oldest.identity,
                      current.type == S_IFREG else {
                    throw EngineError(.conflict, "container output spool segment changed")
                }
                try directory.removeRegularFileIfPresent(named: oldest.name)
                total -= Int(oldest.end - oldest.start)
                closed.removeFirst()
            }
        }

        private static func filesystemBlockSize(_ file: FileHandle) throws -> UInt64 {
            var information = statfs()
            guard Darwin.fstatfs(file.fileDescriptor, &information) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            guard information.f_bsize > 0 else {
                throw EngineError(.internalError, "container output filesystem block size is invalid")
            }
            return UInt64(information.f_bsize)
        }

        private static func createActiveSegment(
            at offset: UInt64,
            in directory: PersistentStateDirectory
        ) throws -> (
            name: String,
            identity: PersistentFileIdentity,
            handle: FileHandle
        ) {
            let name = activeName(start: offset)
            let identity = try directory.createSparseRegularFile(named: name, size: 0)
            do {
                let handle = try directory.openRegularFile(
                    named: name, expectedIdentity: identity, access: .readWrite
                ).handle
                return (name, identity, handle)
            } catch {
                try? directory.removeRegularFileIfPresent(named: name)
                throw error
            }
        }

        static func reset(_ directory: PersistentStateDirectory) throws {
            try lockOutputSpoolDirectory(directory)
            defer { unlockOutputSpoolDirectory(directory) }
            for name in try directory.entryNames() {
                guard isOwnedName(name) else {
                    throw EngineError(.conflict, "container output spool contains an unsafe entry")
                }
                try directory.removeRegularFileIfPresent(named: name)
            }
            try directory.synchronize()
        }

        private static func removeTemporaryState(
            in directory: PersistentStateDirectory
        ) throws {
            for name in try directory.entryNames()
                where name.hasPrefix(".cengine-state-")
                    || name.hasPrefix(".cengine-remove-") {
                try directory.removeRegularFileIfPresent(named: name)
            }
        }

        static func segments(
            in directory: PersistentStateDirectory,
            segmentBytes: Int,
            maximumSegments: Int
        ) throws -> [Segment] {
            var result: [Segment] = []
            for name in try directory.entryNames() {
                guard let parsed = parse(name) else {
                    if name == "cursor.json"
                        || name.hasPrefix(".cengine-state-")
                        || name.hasPrefix(".cengine-remove-") {
                        continue
                    }
                    throw EngineError(.conflict, "container output spool contains an unsafe entry")
                }
                guard let metadata = try directory.entryMetadata(named: name),
                      metadata.type == S_IFREG else {
                    throw EngineError(.conflict, "container output spool segment is unsafe")
                }
                let opened = try directory.openRegularFile(
                    named: name,
                    expectedIdentity: metadata.identity,
                    access: .readOnly
                )
                defer { try? opened.handle.close() }
                let size = try fileSize(opened.handle)
                guard size <= UInt64(segmentBytes),
                      parsed.start <= UInt64.max - size else {
                    throw EngineError(.conflict, "container output spool segment is oversized")
                }
                let observedEnd = parsed.active ? parsed.start + size : parsed.end
                guard parsed.active || parsed.end - parsed.start == size else {
                    throw EngineError(.conflict, "container output spool segment length changed")
                }
                result.append(.init(
                    name: name,
                    identity: metadata.identity,
                    start: parsed.start,
                    end: observedEnd,
                    active: parsed.active
                ))
            }
            let segmentLimit = try CheckedArithmetic.add(maximumSegments, 1)
            guard result.count <= segmentLimit else {
                throw EngineError(.conflict, "container output spool has too many segments")
            }
            let sorted = result.sorted { lhs, rhs in
                lhs.start == rhs.start ? !lhs.active && rhs.active : lhs.start < rhs.start
            }
            for pair in zip(sorted, sorted.dropFirst())
                where pair.0.end != pair.1.start {
                throw EngineError(.conflict, "container output spool segments are discontinuous")
            }
            return sorted
        }

        private static func parse(
            _ name: String
        ) -> (start: UInt64, end: UInt64, active: Bool)? {
            if name.hasPrefix("active-"), name.hasSuffix(".data"),
               let start = UInt64(name.dropFirst(7).dropLast(5)) {
                return (start, start, true)
            }
            guard name.hasPrefix("segment-"), name.hasSuffix(".data") else {
                return nil
            }
            let fields = name.dropFirst(8).dropLast(5).split(separator: "-")
            guard fields.count == 2,
                  let start = UInt64(fields[0]),
                  let end = UInt64(fields[1]),
                  start < end else { return nil }
            return (start, end, false)
        }

        private static func activeName(start: UInt64) -> String {
            String(format: "active-%020llu.data", start)
        }

        private static func closedName(start: UInt64, end: UInt64) -> String {
            String(format: "segment-%020llu-%020llu.data", start, end)
        }

        private static func isOwnedName(_ name: String) -> Bool {
            name == "cursor.json"
                || name.hasPrefix(".cengine-state-")
                || name.hasPrefix(".cengine-remove-")
                || parse(name) != nil
        }

        static func fileSize(_ handle: FileHandle) throws -> UInt64 {
            var information = stat()
            guard Darwin.fstat(handle.fileDescriptor, &information) == 0,
                  information.st_size >= 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            return UInt64(information.st_size)
        }
    }

    private let writers: [StreamWriter]
    private let lock = NSLock()
    private var task: Task<Void, Never>?

    init(
        stdout: FileHandle,
        stderr: FileHandle,
        stdoutDirectory: PersistentStateDirectory,
        stderrDirectory: PersistentStateDirectory,
        retainedBytes: Int,
        segmentBytes: Int,
        maximumSegments: Int
    ) throws {
        writers = try [
            StreamWriter(
                source: stdout, directory: stdoutDirectory,
                segmentBytes: segmentBytes,
                retainedBytes: retainedBytes,
                maximumSegments: maximumSegments
            ),
            StreamWriter(
                source: stderr, directory: stderrDirectory,
                segmentBytes: segmentBytes,
                retainedBytes: retainedBytes,
                maximumSegments: maximumSegments
            ),
        ]
    }

    func start(
        onFailure: @escaping @Sendable (Error) -> Void
    ) {
        lock.withLock {
            guard task == nil else { return }
            task = Task.detached { [weak self] in
                guard let self else { return }
                do {
                    while !Task.isCancelled {
                        for writer in self.writers { try writer.drain() }
                        try await Task.sleep(for: .milliseconds(25))
                    }
                } catch is CancellationError {
                    return
                } catch {
                    onFailure(error)
                }
            }
        }
    }

    func stop() async throws {
        let running = lock.withLock { () -> Task<Void, Never>? in
            let running = task
            task?.cancel()
            task = nil
            return running
        }
        await running?.value
        for writer in writers { try writer.drain() }
    }

    static func reset(_ directory: PersistentStateDirectory) throws {
        try StreamWriter.reset(directory)
    }
}

private final class ContainerOutputSpoolReader: @unchecked Sendable {
    private let directory: PersistentStateDirectory
    private let segmentBytes: Int
    private let maximumSegments: Int

    init(
        directory: PersistentStateDirectory,
        segmentBytes: Int,
        maximumSegments: Int
    ) {
        self.directory = directory
        self.segmentBytes = segmentBytes
        self.maximumSegments = maximumSegments
    }

    func drain(
        stream: ContainerIOBridge.OutputStream,
        committedOffset: inout UInt64,
        maximumChunkSize: Int,
        bridge: ContainerIOBridge,
        persist: (Data, ContainerIOBridge.OutputStream) throws -> Void
    ) throws {
        try lockOutputSpoolDirectory(directory)
        defer { unlockOutputSpoolDirectory(directory) }
        let segments = try VMShimOutputSpooler.StreamWriter.segments(
            in: directory,
            segmentBytes: segmentBytes,
            maximumSegments: maximumSegments
        )
        for segment in segments {
            if segment.end <= committedOffset {
                if !segment.active { try remove(segment) }
                continue
            }
            if segment.start > committedOffset {
                try bridge.advanceDurableSourceByteOffset(
                    stream: stream, to: segment.start
                )
                committedOffset = segment.start
            }
            let opened = try directory.openRegularFile(
                named: segment.name,
                expectedIdentity: segment.identity,
                access: .readOnly
            )
            defer { try? opened.handle.close() }
            let relative = committedOffset - segment.start
            try opened.handle.seek(toOffset: relative)
            var remaining = segment.end - committedOffset
            while remaining > 0 {
                let count = min(maximumChunkSize, Int(remaining))
                guard let data = try opened.handle.read(upToCount: count),
                      !data.isEmpty else { break }
                try persist(data, stream)
                committedOffset = try CheckedArithmetic.add(
                    committedOffset, UInt64(data.count)
                )
                remaining -= UInt64(data.count)
            }
            if !segment.active, committedOffset >= segment.end {
                try remove(segment)
            }
        }
    }

    private func remove(_ segment: VMShimOutputSpooler.Segment) throws {
        guard let current = try directory.entryMetadata(named: segment.name) else {
            return
        }
        guard current.identity == segment.identity, current.type == S_IFREG else {
            throw EngineError(.conflict, "container output spool segment changed before acknowledgement")
        }
        try directory.removeRegularFileIfPresent(named: segment.name)
    }
}

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
    private let stdoutSpool: ContainerOutputSpoolReader?
    private let stderrSpool: ContainerOutputSpoolReader?
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
        stdoutSpoolDirectory: PersistentStateDirectory? = nil,
        stderrSpoolDirectory: PersistentStateDirectory? = nil,
        spoolSegmentBytes: Int = ContainerLogRetentionPolicy.default.segmentBytes,
        spoolMaximumSegments: Int = ContainerLogRetentionPolicy.default.maximumSegments,
        markInputClosed: @escaping @Sendable () throws -> Void = {},
        synchronizeInput: (@Sendable () throws -> Void)? = nil,
        persistOutput: (@Sendable (
            Data, ContainerIOBridge.OutputStream
        ) throws -> Void)? = nil,
        maximumOutputChunkSize: Int = defaultMaximumOutputChunkSize
    ) {
        self.stdout = stdout
        self.stderr = stderr
        stdoutSpool = stdoutSpoolDirectory.map {
            ContainerOutputSpoolReader(
                directory: $0,
                segmentBytes: spoolSegmentBytes,
                maximumSegments: spoolMaximumSegments
            )
        }
        stderrSpool = stderrSpoolDirectory.map {
            ContainerOutputSpoolReader(
                directory: $0,
                segmentBytes: spoolSegmentBytes,
                maximumSegments: spoolMaximumSegments
            )
        }
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
        let stdoutTarget = Self.size(of: stdout)
        let stderrTarget = Self.size(of: stderr)
        let deadline = DispatchTime.now() + .seconds(5)
        repeat {
            try drain(stream: .stdout)
            try drain(stream: .stderr)
            let caughtUp = lock.withLock {
                (stdoutSpool == nil || (offsets[.stdout] ?? 0) >= stdoutTarget)
                    && (stderrSpool == nil || (offsets[.stderr] ?? 0) >= stderrTarget)
            }
            if caughtUp { break }
            guard DispatchTime.now() < deadline else {
                throw EngineError(
                    .serviceUnavailable,
                    "container output spool did not reach the source boundary"
                )
            }
            usleep(25_000)
        } while true
        if finishOutput { bridge.finishOutput() }
    }

    func rawOutput(
        maximumBytes: Int = ContainerIOBridge.defaultCompletedSnapshotByteLimit
    ) throws -> Data {
        try lock.withLock {
            let bounded = max(0, maximumBytes)
            let stdoutLimit = bounded / 2 + bounded % 2
            let stderrLimit = bounded / 2
            return try Self.readSuffix(from: stdout, maximumBytes: stdoutLimit)
                + Self.readSuffix(from: stderr, maximumBytes: stderrLimit)
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
        let spool = stream == .stdout ? stdoutSpool : stderrSpool
        lock.lock()
        defer { lock.unlock() }
        var committedOffset = offsets[stream] ?? 0
        defer { offsets[stream] = committedOffset }
        didReadOffset()
        if let spool {
            try spool.drain(
                stream: stream,
                committedOffset: &committedOffset,
                maximumChunkSize: maximumOutputChunkSize,
                bridge: bridge,
                persist: persistOutput
            )
            return
        }
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

    private static func readSuffix(
        from handle: FileHandle,
        maximumBytes: Int
    ) throws -> Data {
        guard maximumBytes > 0 else { return Data() }
        let size = size(of: handle)
        let count = min(size, UInt64(maximumBytes))
        try handle.seek(toOffset: size - count)
        var result = Data()
        result.reserveCapacity(Int(count))
        while result.count < Int(count) {
            guard let chunk = try handle.read(
                upToCount: min(64 * 1_024, Int(count) - result.count)
            ), !chunk.isEmpty else { break }
            result.append(chunk)
        }
        return result
    }
}

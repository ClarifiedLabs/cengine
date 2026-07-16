import Darwin
import Dispatch
import Foundation

/// Writes the daemon's standard output/error to an append-only log file. The
/// SMAppService launchd plist cannot express a per-user StandardOutPath, so the
/// managed service redirects its own streams on startup.
public enum DaemonLog {
    /// Opens the log file for appending, creating it and its directory if needed.
    public static func open(at url: URL) throws -> FileHandle {
        let fm = FileManager.default
        try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        if !fm.fileExists(atPath: url.path) {
            fm.createFile(atPath: url.path, contents: nil)
        }
        let handle = try FileHandle(forWritingTo: url)
        try handle.seekToEnd()
        return handle
    }

    /// Redirects stdout and stderr to the log file at `url`, prefixing each line
    /// with a UTC ISO 8601 timestamp. The returned closure drains pending output
    /// and should be called immediately before the process exits.
    @discardableResult
    public static func redirectStandardStreams(to url: URL) throws -> @Sendable () -> Void {
        let output = try open(at: url)
        var descriptors: [Int32] = [0, 0]
        guard Darwin.pipe(&descriptors) == 0 else {
            let code = POSIXErrorCode(rawValue: errno) ?? .EIO
            try? output.close()
            throw POSIXError(code)
        }
        let input = FileHandle(fileDescriptor: descriptors[0], closeOnDealloc: true)
        let redirected = FileHandle(fileDescriptor: descriptors[1], closeOnDealloc: true)
        dup2(redirected.fileDescriptor, STDOUT_FILENO)
        dup2(redirected.fileDescriptor, STDERR_FILENO)
        try? redirected.close()
        setvbuf(stdout, nil, _IOLBF, 0)

        let redirection = DaemonLogRedirection()
        Thread.detachNewThread {
            TimestampedLogWriter(input: input, output: output).run()
            redirection.writerDidFinish()
        }
        return { redirection.finish() }
    }
}

struct TimestampedLineBuffer {
    private var startsLine = true

    mutating func append(_ data: Data, timestamp: () -> String) -> Data {
        var result = Data()
        var start = data.startIndex
        while start < data.endIndex {
            if startsLine { result.append(contentsOf: "\(timestamp()) ".utf8) }
            if let newline = data[start...].firstIndex(of: UInt8(ascii: "\n")) {
                result.append(data[start...newline])
                start = data.index(after: newline)
                startsLine = true
            } else {
                result.append(data[start...])
                startsLine = false
                break
            }
        }
        return result
    }
}

private final class DaemonLogRedirection: @unchecked Sendable {
    private let completion = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var isFinished = false

    func finish() {
        let shouldFinish = lock.withLock {
            guard !isFinished else { return false }
            isFinished = true
            return true
        }
        guard shouldFinish else { return }
        fflush(stdout)
        fflush(stderr)
        Darwin.close(STDOUT_FILENO)
        Darwin.close(STDERR_FILENO)
        completion.wait()
    }

    func writerDidFinish() {
        completion.signal()
    }
}

private final class TimestampedLogWriter: @unchecked Sendable {
    private let input: FileHandle
    private let output: FileHandle

    init(input: FileHandle, output: FileHandle) {
        self.input = input
        self.output = output
    }

    func run() {
        defer {
            try? input.close()
            try? output.close()
        }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        var lines = TimestampedLineBuffer()
        var canWrite = true

        while true {
            let next: Data?
            do {
                next = try input.read(upToCount: 16 * 1024)
            } catch {
                break
            }
            guard let data = next, !data.isEmpty else { break }
            let timestamped = lines.append(data) { formatter.string(from: Date()) }
            if canWrite, !timestamped.isEmpty {
                do {
                    try output.write(contentsOf: timestamped)
                } catch {
                    // Keep draining the pipe so a full or unavailable log file
                    // cannot block the daemon's stdout and stderr writers.
                    canWrite = false
                }
            }
        }
    }
}

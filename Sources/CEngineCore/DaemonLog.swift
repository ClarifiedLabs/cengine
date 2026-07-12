import Darwin
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

    /// Redirects stdout and stderr to the log file at `url`.
    public static func redirectStandardStreams(to url: URL) throws {
        let handle = try open(at: url)
        dup2(handle.fileDescriptor, STDOUT_FILENO)
        dup2(handle.fileDescriptor, STDERR_FILENO)
        try handle.close()
        setvbuf(stdout, nil, _IOLBF, 0)
    }
}

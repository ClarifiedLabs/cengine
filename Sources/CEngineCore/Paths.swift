import Foundation

public struct EnginePaths: Sendable {
    public let home: URL
    public let data: URL
    public let runtime: URL
    public let socket: URL
    public let logs: URL
    public let kernel: URL

    public init(home: URL = FileManager.default.homeDirectoryForCurrentUser) {
        self.home = home
        self.data = home.appending(path: "Library/Application Support/cengine", directoryHint: .isDirectory)
        self.runtime = home.appending(path: ".cengine/run", directoryHint: .isDirectory)
        self.socket = runtime.appending(path: "docker.sock", directoryHint: .notDirectory)
        self.logs = home.appending(path: "Library/Logs/cengine", directoryHint: .isDirectory)
        self.kernel = data.appending(path: "assets/vmlinux", directoryHint: .notDirectory)
    }

    public func createDirectories() throws {
        let fm = FileManager.default
        try fm.createDirectory(at: data, withIntermediateDirectories: true)
        try fm.createDirectory(at: runtime, withIntermediateDirectories: true)
        try fm.createDirectory(at: logs, withIntermediateDirectories: true)
    }
}

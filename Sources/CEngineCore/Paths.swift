import Foundation

public struct EnginePaths: Sendable {
    public let home: URL
    public let data: URL
    public let runtime: URL
    public let socket: URL
    public let lock: URL
    public let serviceState: URL
    public let builderSettings: URL
    public let containerSettings: URL
    public let activeContextMarker: URL
    public let logs: URL
    public let kernel: URL
    public let containerInitialRamdisk: URL
    public let storageInitialRamdisk: URL

    public init(home: URL = FileManager.default.homeDirectoryForCurrentUser) {
        self.home = home
        self.data = home.appending(path: "Library/Application Support/cengine", directoryHint: .isDirectory)
        self.runtime = home.appending(path: ".cengine/run", directoryHint: .isDirectory)
        self.socket = runtime.appending(path: "docker.sock", directoryHint: .notDirectory)
        self.lock = runtime.appending(path: "docker.sock.lock", directoryHint: .notDirectory)
        self.serviceState = runtime.appending(path: "service-state.json", directoryHint: .notDirectory)
        self.builderSettings = data.appending(path: "builder-settings.json", directoryHint: .notDirectory)
        self.containerSettings = data.appending(path: ContainerSettings.fileName, directoryHint: .notDirectory)
        self.activeContextMarker = data.appending(path: "active-docker-context", directoryHint: .notDirectory)
        self.logs = home.appending(path: "Library/Logs/cengine", directoryHint: .isDirectory)
        self.kernel = data.appending(path: "assets/vmlinux", directoryHint: .notDirectory)
        self.containerInitialRamdisk = data.appending(path: "assets/container-initramfs.cpio.gz", directoryHint: .notDirectory)
        self.storageInitialRamdisk = data.appending(path: "assets/storage-initramfs.cpio.gz", directoryHint: .notDirectory)
    }

    public func createDirectories() throws {
        let fm = FileManager.default
        try fm.createDirectory(at: data, withIntermediateDirectories: true)
        try fm.createDirectory(at: runtime, withIntermediateDirectories: true)
        try fm.createDirectory(at: logs, withIntermediateDirectories: true)
    }
}

import CEngineCore
import Foundation

public struct ExecConfiguration: Sendable {
    public var arguments: [String]
    public var environment: [String]
    public var workingDirectory: String
    public var user: String
    public var tty: Bool
    public var consoleSize: TerminalSize
    public var attachStdin: Bool
    public var attachStdout: Bool
    public var attachStderr: Bool
    public var privileged: Bool

    public init(
        arguments: [String], environment: [String] = [], workingDirectory: String = "", user: String = "",
        tty: Bool = false, consoleSize: TerminalSize = .zero,
        attachStdin: Bool = false, attachStdout: Bool = true,
        attachStderr: Bool = true, privileged: Bool = false
    ) {
        self.arguments = arguments; self.environment = environment; self.workingDirectory = workingDirectory
        self.user = user; self.tty = tty; self.consoleSize = consoleSize
        self.attachStdin = attachStdin; self.attachStdout = attachStdout
        self.attachStderr = attachStderr; self.privileged = privileged
    }
}

public struct ExecRecord: Sendable {
    public let id: String
    public let containerID: String
    public let containerInstanceID: UUID
    public let configuration: ExecConfiguration
    public let createdAt: Date
    public var running: Bool
    public var exitCode: Int32?
    public var pid: Int32

    public init(
        id: String = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased(),
        containerID: String,
        containerInstanceID: UUID,
        configuration: ExecConfiguration
    ) {
        self.id = id; self.containerID = containerID
        self.containerInstanceID = containerInstanceID
        self.configuration = configuration; self.createdAt = Date()
        self.running = false; self.pid = 0
    }
}

import Foundation

public enum EngineServicePhase: String, Codable, Sendable {
    case starting
    case running
    case failed
    case stopped
}

public struct EngineServiceState: Codable, Sendable {
    public let phase: EngineServicePhase
    public let message: String?
    public let updatedAt: Date

    public init(phase: EngineServicePhase, message: String?, updatedAt: Date = Date()) {
        self.phase = phase
        self.message = message
        self.updatedAt = updatedAt
    }

    public static func load(from url: URL) throws -> EngineServiceState {
        try JSONDecoder().decode(EngineServiceState.self, from: Data(contentsOf: url))
    }
}

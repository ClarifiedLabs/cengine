import Foundation

public struct EngineError: Error, LocalizedError, Sendable {
    public enum Code: Sendable {
        case badRequest
        case unauthorized
        case notFound
        case conflict
        case unsupported
        case internalError
    }

    public let code: Code
    public let message: String

    public init(_ code: Code, _ message: String) {
        self.code = code
        self.message = message
    }

    public var errorDescription: String? { message }

    /// A human-readable message for an arbitrary error: prefers a LocalizedError's
    /// own description, falling back to the full Swift representation for bare
    /// errors whose localizedDescription is an uninformative NSError bridge.
    public static func message(for error: Error) -> String {
        (error as? LocalizedError)?.errorDescription ?? String(describing: error)
    }
}

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
}

import CEngineCore
import Foundation
import NIOHTTP1

public struct DockerAPIVersion: Comparable, CustomStringConvertible, Sendable {
    public static let minimum = DockerAPIVersion(major: 1, minor: 44)
    public static let maximum = DockerAPIVersion(major: 1, minor: 55)

    public let major: Int
    public let minor: Int

    public init(major: Int, minor: Int) {
        self.major = major
        self.minor = minor
    }

    public var description: String { "\(major).\(minor)" }

    public static func < (lhs: Self, rhs: Self) -> Bool {
        (lhs.major, lhs.minor) < (rhs.major, rhs.minor)
    }
}

struct DockerRequestTarget: Sendable {
    let version: DockerAPIVersion
    let components: URLComponents
    let path: String

    static func parse(_ uri: String) throws -> Self {
        guard var components = URLComponents(string: uri) else {
            throw EngineError(.badRequest, "invalid request URI")
        }
        let originalPath = components.path
        let segments = originalPath.split(separator: "/", omittingEmptySubsequences: true)

        if originalPath == "/_ping" || originalPath == "/version" {
            return Self(version: .maximum, components: components, path: originalPath)
        }

        if let first = segments.first, first.hasPrefix("v") {
            let raw = first.dropFirst()
            let fields = raw.split(separator: ".", omittingEmptySubsequences: false)
            guard fields.count == 2, let major = Int(fields[0]), let minor = Int(fields[1]),
                  String(major) == fields[0], String(minor) == fields[1] else {
                throw EngineError(.badRequest, "invalid API version \(raw)")
            }
            let version = DockerAPIVersion(major: major, minor: minor)
            guard version >= .minimum else {
                throw EngineError(
                    .badRequest,
                    "client version \(version) is too old. Minimum supported API version is \(DockerAPIVersion.minimum)"
                )
            }
            guard version <= .maximum else {
                throw EngineError(
                    .badRequest,
                    "client version \(version) is too new. Maximum supported API version is \(DockerAPIVersion.maximum)"
                )
            }
            let prefix = "/\(first)"
            let path = String(originalPath.dropFirst(prefix.count))
            components.path = path.isEmpty ? "/" : path
            return Self(version: version, components: components, path: components.path)
        }

        throw EngineError(.badRequest, "API version is required; supported versions are v\(DockerAPIVersion.minimum) through v\(DockerAPIVersion.maximum)")
    }
}

func dockerErrorResponse(_ error: EngineError) -> APIResponse {
    let status: HTTPResponseStatus = switch error.code {
    case .badRequest: .badRequest
    case .unauthorized: .unauthorized
    case .notFound: .notFound
    case .conflict: .conflict
    case .unsupported: .notImplemented
    case .internalError: .internalServerError
    }
    let body = (try? JSONEncoder().encode(DockerErrorBody(message: error.message))) ?? Data()
    return APIResponse(status: status, headers: ["Content-Type": "application/json"], body: body)
}

import CEngineCore
import Foundation

public struct RegistrySearchResult: Codable, Equatable, Sendable {
    public let description: String
    public let isOfficial: Bool
    public let isAutomated: Bool
    public let name: String
    public let starCount: Int

    public init(
        description: String,
        isOfficial: Bool,
        isAutomated: Bool,
        name: String,
        starCount: Int
    ) {
        self.description = description
        self.isOfficial = isOfficial
        self.isAutomated = isAutomated
        self.name = name
        self.starCount = starCount
    }

    private enum CodingKeys: String, CodingKey {
        case description
        case isOfficial = "is_official"
        case isAutomated = "is_automated"
        case name
        case starCount = "star_count"
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        description = try values.decodeIfPresent(String.self, forKey: .description) ?? ""
        isOfficial = try values.decodeIfPresent(Bool.self, forKey: .isOfficial) ?? false
        isAutomated = try values.decodeIfPresent(Bool.self, forKey: .isAutomated) ?? false
        name = try values.decodeIfPresent(String.self, forKey: .name) ?? ""
        starCount = try values.decodeIfPresent(Int.self, forKey: .starCount) ?? 0
    }
}

public struct RegistrySearchFilters: Equatable, Sendable {
    public let isAutomated: Bool?
    public let isOfficial: Bool?
    public let minimumStars: Int?

    public init(isAutomated: Bool? = nil, isOfficial: Bool? = nil, minimumStars: Int? = nil) {
        self.isAutomated = isAutomated
        self.isOfficial = isOfficial
        self.minimumStars = minimumStars
    }
}

public protocol RegistrySearching: Sendable {
    func search(
        term: String,
        limit: Int,
        filters: RegistrySearchFilters,
        credentials: RegistryCredentials?,
        headers: [String: [String]]
    ) async throws -> [RegistrySearchResult]
}

public struct RegistrySearchClient: RegistrySearching, Sendable {
    typealias RequestExecutor = @Sendable (URLRequest, Int) async throws -> (Data, HTTPURLResponse)

    private struct SearchResults: Decodable {
        let results: [RegistrySearchResult]

        private enum CodingKeys: String, CodingKey { case results }

        init(from decoder: Decoder) throws {
            let values = try decoder.container(keyedBy: CodingKeys.self)
            results = try values.decodeIfPresent([RegistrySearchResult].self, forKey: .results) ?? []
        }
    }

    private struct SearchTarget {
        let registry: String
        let host: String
        let port: Int?
        let official: Bool
        let loopback: Bool
        let term: String
    }

    private struct BearerChallenge {
        let realm: URL
        let service: String
    }

    private struct OAuthTokenResponse: Decodable {
        let accessToken: String

        private enum CodingKeys: String, CodingKey {
            case accessToken = "access_token"
        }
    }

    private static let defaultLimit = 25
    private static let maximumResponseBytes = 8 * 1_024 * 1_024
    private let execute: RequestExecutor

    public init() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 120
        configuration.timeoutIntervalForResource = 120
        let session = URLSession(
            configuration: configuration,
            delegate: RegistrySearchSessionDelegate(),
            delegateQueue: nil
        )
        execute = { request, maximumBytes in
            let operation = Task {
                let (bytes, response) = try await session.bytes(for: request)
                guard let http = response as? HTTPURLResponse else {
                    throw EngineError(.internalError, "registry search returned a non-HTTP response")
                }
                do {
                    return (try await Self.readBounded(bytes, maximumBytes: maximumBytes), http)
                } catch {
                    withUnsafeCurrentTask { $0?.cancel() }
                    throw error
                }
            }
            return try await withTaskCancellationHandler {
                try await operation.value
            } onCancel: {
                operation.cancel()
            }
        }
    }

    init(execute: @escaping RequestExecutor) {
        self.execute = execute
    }

    public func search(
        term: String,
        limit requestedLimit: Int,
        filters: RegistrySearchFilters,
        credentials: RegistryCredentials?,
        headers: [String: [String]] = [:]
    ) async throws -> [RegistrySearchResult] {
        if filters.isAutomated == true {
            return []
        }

        let limit = requestedLimit == 0 ? Self.defaultLimit : requestedLimit
        guard (1...100).contains(limit) else {
            throw EngineError(.badRequest, "limit \(requestedLimit) is outside the range of [1, 100]")
        }
        let target = try Self.searchTarget(term)
        let endpoint = try await resolvedEndpoint(for: target, headers: headers)
        var components = try requiredComponents(endpoint)
        components.path = "/v1/search"
        components.percentEncodedQuery = "q=\(Self.queryEscape(target.term))&n=\(limit)"
        guard let url = components.url else {
            throw EngineError(.badRequest, "invalid registry search URL")
        }

        let searchAuthorization = try await authorization(
            endpoint: endpoint,
            target: target,
            credentials: credentials,
            headers: headers
        )
        var request = Self.request(url: url, headers: headers)
        request.setValue("true", forHTTPHeaderField: "X-Docker-Token")
        if let searchAuthorization {
            request.setValue(searchAuthorization, forHTTPHeaderField: "Authorization")
        }

        let data: Data
        let response: HTTPURLResponse
        (data, response) = try await perform(request)
        guard response.statusCode == 200 else {
            throw EngineError(.internalError, "registry search failed (HTTP \(response.statusCode))")
        }

        let decoded: SearchResults
        do {
            decoded = try JSONDecoder().decode(SearchResults.self, from: data)
        } catch {
            throw EngineError(
                .internalError,
                "error decoding registry search results: \(EngineError.message(for: error))"
            )
        }

        return Array(decoded.results.lazy.map {
            RegistrySearchResult(
                description: $0.description,
                isOfficial: $0.isOfficial,
                isAutomated: false,
                name: $0.name,
                starCount: $0.starCount
            )
        }.filter { result in
            (filters.isOfficial == nil || filters.isOfficial == result.isOfficial)
                && filters.minimumStars.map { result.starCount >= $0 } != false
        }.prefix(limit))
    }

    private static func searchTarget(_ value: String) throws -> SearchTarget {
        guard !value.isEmpty else {
            throw EngineError(.badRequest, "term is required")
        }
        guard !value.contains("://") else {
            throw EngineError(
                .badRequest,
                "invalid repository name: repository name (\(value)) should not have a scheme"
            )
        }

        let pieces = value.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        let first = String(pieces[0])
        let hasRegistry = pieces.count == 2
            && (first.contains(".") || first.contains(":") || first == "localhost")
        let registry: String
        var remoteTerm: String
        if hasRegistry {
            guard pieces.count == 2, !pieces[1].isEmpty else {
                throw EngineError(.badRequest, "invalid repository search term \(value)")
            }
            registry = first
            remoteTerm = String(pieces[1])
        } else {
            registry = "docker.io"
            remoteTerm = value
        }

        let official = registry == "docker.io" || registry == "index.docker.io"
        if official { remoteTerm = String(remoteTerm.dropPrefix("library/")) }
        let (host, port) = try registryAuthority(official ? "index.docker.io" : registry)
        return SearchTarget(
            registry: registry,
            host: host,
            port: port,
            official: official,
            loopback: isLoopback(host),
            term: remoteTerm
        )
    }

    private static func registryAuthority(_ value: String) throws -> (String, Int?) {
        guard !value.isEmpty,
              !value.contains(where: { $0.isWhitespace }),
              value.rangeOfCharacter(from: CharacterSet(charactersIn: "@/?#")) == nil else {
            throw EngineError(.badRequest, "invalid registry \(value)")
        }
        guard let components = URLComponents(string: "https://\(value)"),
              components.scheme == "https",
              let host = components.host,
              !host.isEmpty,
              components.path.isEmpty,
              components.query == nil,
              components.fragment == nil,
              components.user == nil,
              components.password == nil else {
            throw EngineError(.badRequest, "invalid registry \(value)")
        }
        let hasExplicitPort = value.hasPrefix("[") ? value.contains("]:") : value.contains(":")
        if hasExplicitPort {
            guard let port = components.port, (1...65_535).contains(port) else {
                throw EngineError(.badRequest, "invalid registry port in \(value)")
            }
        }
        return (host, components.port)
    }

    static func isLoopback(_ host: String) -> Bool {
        let normalized = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        if normalized == "localhost" || normalized == "::1" { return true }
        let octets = normalized.split(separator: ".", omittingEmptySubsequences: false)
        return octets.count == 4
            && octets.allSatisfy { UInt8($0) != nil }
            && octets[0] == "127"
    }

    private static func basicAuthorization(_ credentials: RegistryCredentials?) -> String? {
        guard let credentials, !credentials.username.isEmpty else { return nil }
        return "Basic " + Data("\(credentials.username):\(credentials.password)".utf8).base64EncodedString()
    }

    private func resolvedEndpoint(
        for target: SearchTarget,
        headers: [String: [String]]
    ) async throws -> URL {
        let https = try Self.endpoint(scheme: "https", target: target)
        if target.official { return https }

        do {
            _ = try await perform(Self.request(
                url: https.appending(path: "v1/_ping"),
                headers: headers
            ))
            return https
        } catch {
            if Task.isCancelled || error is CancellationError { throw CancellationError() }
            guard target.loopback else {
                throw EngineError(.badRequest, "invalid registry endpoint \(target.registry): \(EngineError.message(for: error))")
            }
        }

        let http = try Self.endpoint(scheme: "http", target: target)
        do {
            _ = try await perform(Self.request(
                url: http.appending(path: "v1/_ping"),
                headers: headers
            ))
            return http
        } catch {
            if Task.isCancelled || error is CancellationError { throw CancellationError() }
            throw EngineError(.badRequest, "invalid registry endpoint \(target.registry): \(EngineError.message(for: error))")
        }
    }

    private func authorization(
        endpoint: URL,
        target: SearchTarget,
        credentials: RegistryCredentials?,
        headers: [String: [String]]
    ) async throws -> String? {
        guard let credentials,
              !credentials.username.isEmpty,
              !credentials.identityToken.isEmpty else {
            return Self.basicAuthorization(credentials)
        }

        let v2URL = endpoint.appending(path: "v2/")
        let (_, ping) = try await perform(Self.request(url: v2URL, headers: headers))
        guard let challenge = try Self.bearerChallenge(
            ping.value(forHTTPHeaderField: "WWW-Authenticate"),
            registryIsLoopback: target.loopback
        ) else {
            if ping.value(forHTTPHeaderField: "WWW-Authenticate")?.lowercased().hasPrefix("basic ") == true {
                return Self.basicAuthorization(credentials)
            }
            return nil
        }

        var form = URLComponents()
        form.queryItems = [
            .init(name: "client_id", value: "docker"),
            .init(name: "grant_type", value: "refresh_token"),
            .init(name: "refresh_token", value: credentials.identityToken),
            .init(name: "scope", value: "registry:catalog:search"),
            .init(name: "service", value: challenge.service),
        ]
        guard let encodedForm = form.percentEncodedQuery else {
            throw EngineError(.internalError, "could not encode registry token request")
        }
        var tokenRequest = Self.request(url: challenge.realm, headers: headers)
        tokenRequest.httpMethod = "POST"
        tokenRequest.httpBody = Data(encodedForm.utf8)
        tokenRequest.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        let (tokenData, tokenResponse) = try await perform(tokenRequest)
        guard (200...299).contains(tokenResponse.statusCode) else {
            throw EngineError(.internalError, "registry token request failed (HTTP \(tokenResponse.statusCode))")
        }
        let token: OAuthTokenResponse
        do {
            token = try JSONDecoder().decode(OAuthTokenResponse.self, from: tokenData)
        } catch {
            throw EngineError(.internalError, "error decoding registry token response: \(EngineError.message(for: error))")
        }
        guard !token.accessToken.isEmpty else {
            throw EngineError(.internalError, "registry token response did not include an access token")
        }
        return "Bearer \(token.accessToken)"
    }

    private func perform(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        do {
            return try await execute(request, Self.maximumResponseBytes)
        } catch let error as EngineError {
            throw error
        } catch {
            if Task.isCancelled || error is CancellationError { throw CancellationError() }
            throw EngineError(.internalError, "registry search failed: \(EngineError.message(for: error))")
        }
    }

    private static func endpoint(scheme: String, target: SearchTarget) throws -> URL {
        var components = URLComponents()
        components.scheme = scheme
        components.host = target.host
        components.port = target.port
        guard let endpoint = components.url else {
            throw EngineError(.badRequest, "invalid registry \(target.registry)")
        }
        return endpoint
    }

    private static func request(url: URL, headers: [String: [String]]) -> URLRequest {
        var request = URLRequest(url: url)
        for (name, values) in headers {
            let normalized = name.lowercased()
            guard normalized == "user-agent" || normalized.hasPrefix("x-meta-") else { continue }
            for value in values { request.addValue(value, forHTTPHeaderField: name) }
        }
        return request
    }

    private static func bearerChallenge(
        _ header: String?,
        registryIsLoopback: Bool
    ) throws -> BearerChallenge? {
        guard let header,
              let bearer = header.range(of: "Bearer ", options: [.caseInsensitive]) else { return nil }
        let parameters = challengeParameters(String(header[bearer.upperBound...]))
        guard let realmValue = parameters["realm"],
              let realm = URL(string: realmValue),
              let scheme = realm.scheme?.lowercased(),
              let host = realm.host,
              realm.user == nil,
              realm.password == nil,
              (scheme == "https" || (scheme == "http" && registryIsLoopback && isLoopback(host))) else {
            throw EngineError(.internalError, "registry returned an invalid token authentication realm")
        }
        return BearerChallenge(realm: realm, service: parameters["service"] ?? "")
    }

    private static func challengeParameters(_ input: String) -> [String: String] {
        var result: [String: String] = [:]
        var index = input.startIndex
        while index < input.endIndex {
            while index < input.endIndex && (input[index] == " " || input[index] == ",") {
                index = input.index(after: index)
            }
            let keyStart = index
            while index < input.endIndex && input[index] != "=" && input[index] != "," {
                index = input.index(after: index)
            }
            guard index < input.endIndex, input[index] == "=" else { break }
            let key = input[keyStart..<index].trimmingCharacters(in: .whitespaces).lowercased()
            index = input.index(after: index)
            var value = ""
            if index < input.endIndex, input[index] == "\"" {
                index = input.index(after: index)
                while index < input.endIndex, input[index] != "\"" {
                    if input[index] == "\\" {
                        let next = input.index(after: index)
                        guard next < input.endIndex else { break }
                        index = next
                    }
                    value.append(input[index])
                    index = input.index(after: index)
                }
                if index < input.endIndex { index = input.index(after: index) }
            } else {
                let valueStart = index
                while index < input.endIndex && input[index] != "," {
                    index = input.index(after: index)
                }
                value = input[valueStart..<index].trimmingCharacters(in: .whitespaces)
            }
            if !key.isEmpty { result[key] = value }
        }
        return result
    }

    static func readBounded<Bytes: AsyncSequence>(
        _ bytes: Bytes,
        maximumBytes: Int
    ) async throws -> Data where Bytes.Element == UInt8 {
        var data = Data()
        data.reserveCapacity(min(maximumBytes, 64 * 1_024))
        for try await byte in bytes {
            guard data.count < maximumBytes else {
                throw EngineError(.internalError, "registry search response exceeds 8 MiB")
            }
            data.append(byte)
        }
        return data
    }

    private static func queryEscape(_ value: String) -> String {
        var encoded = ""
        for byte in value.utf8 {
            switch byte {
            case 0x41...0x5A, 0x61...0x7A, 0x30...0x39, 0x2D, 0x2E, 0x5F, 0x7E:
                encoded.unicodeScalars.append(UnicodeScalar(byte))
            case 0x20:
                encoded.append("+")
            default:
                encoded.append(String(format: "%%%02X", byte))
            }
        }
        return encoded
    }

    private func requiredComponents(_ url: URL) throws -> URLComponents {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            throw EngineError(.badRequest, "invalid registry search URL")
        }
        return components
    }
}

final class RegistrySearchSessionDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let trust = challenge.protectionSpace.serverTrust,
           RegistrySearchClient.isLoopback(challenge.protectionSpace.host) {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }

    func urlSession(
        _: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection _: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        guard let original = task.originalRequest else {
            completionHandler(nil)
            return
        }
        completionHandler(Self.redirectedRequest(from: original, to: request))
    }

    static func redirectedRequest(from original: URLRequest, to proposed: URLRequest) -> URLRequest? {
        if original.httpMethod == "POST",
           original.value(forHTTPHeaderField: "Content-Type") == "application/x-www-form-urlencoded" {
            return nil
        }
        var redirected = proposed
        let preserveAuthorization = trusted(original.url) && trusted(proposed.url)
        for (name, value) in original.allHTTPHeaderFields ?? [:] where preserveAuthorization || name.lowercased() != "authorization" {
            redirected.setValue(value, forHTTPHeaderField: name)
        }
        if !preserveAuthorization {
            redirected.setValue(nil, forHTTPHeaderField: "Authorization")
        }
        return redirected
    }

    private static func trusted(_ url: URL?) -> Bool {
        guard let url, url.scheme?.lowercased() == "https", let host = url.host?.lowercased() else { return false }
        return host == "docker.com" || host.hasSuffix(".docker.com")
            || host == "docker.io" || host.hasSuffix(".docker.io")
    }
}

private extension String {
    func dropPrefix(_ prefix: String) -> Substring {
        hasPrefix(prefix) ? dropFirst(prefix.count) : self[...]
    }
}

import CEngineCore
import Foundation

public struct RegistryAuthenticationResult: Sendable {
    public let status: String
    public let identityToken: String

    public init(status: String, identityToken: String = "") {
        self.status = status
        self.identityToken = identityToken
    }
}

public protocol RegistryAuthenticating: Sendable {
    func authenticate(
        serverAddress: String,
        credentials: RegistryCredentials
    ) async throws -> RegistryAuthenticationResult
}

public struct RegistryAuthenticationClient: RegistryAuthenticating, Sendable {
    typealias RequestExecutor = @Sendable (URLRequest, Int) async throws -> (Data, HTTPURLResponse)

    private struct Target {
        let endpoints: [URL]
        let loopback: Bool
    }

    private struct TokenResponse: Decodable {
        let token: String?
        let accessToken: String?
        let refreshToken: String?

        private enum CodingKeys: String, CodingKey {
            case token
            case accessToken = "access_token"
            case refreshToken = "refresh_token"
        }
    }

    private static let maximumResponseBytes = 1 * 1_024 * 1_024
    private let execute: RequestExecutor

    public init() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 15
        configuration.httpShouldSetCookies = false
        let session = URLSession(
            configuration: configuration,
            delegate: RegistryAuthenticationSessionDelegate(),
            delegateQueue: nil
        )
        execute = { request, maximumBytes in
            let operation = Task {
                let (bytes, response) = try await session.bytes(for: request)
                guard let http = response as? HTTPURLResponse else {
                    throw EngineError(.internalError, "registry login returned a non-HTTP response")
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

    public func authenticate(
        serverAddress: String,
        credentials: RegistryCredentials
    ) async throws -> RegistryAuthenticationResult {
        do {
            let target = try Self.target(serverAddress)
            var endpoint = target.endpoints[0]
            let initial: (Data, HTTPURLResponse)
            do {
                initial = try await perform(URLRequest(url: endpoint.appending(path: "v2/")))
            } catch let error as EngineError {
                throw error
            } catch {
                if Task.isCancelled || error is CancellationError { throw CancellationError() }
                guard target.endpoints.count > 1 else { throw error }
                endpoint = target.endpoints[1]
                initial = try await perform(URLRequest(url: endpoint.appending(path: "v2/")))
            }
            return try await authenticate(
                endpoint: endpoint,
                target: target,
                initialBody: initial.0,
                initialResponse: initial.1,
                credentials: credentials
            )
        } catch let error as EngineError {
            throw error
        } catch {
            if Task.isCancelled || error is CancellationError { throw CancellationError() }
            throw EngineError(.internalError, "registry login failed: \(EngineError.message(for: error))")
        }
    }

    private func authenticate(
        endpoint: URL,
        target: Target,
        initialBody: Data,
        initialResponse: HTTPURLResponse,
        credentials: RegistryCredentials
    ) async throws -> RegistryAuthenticationResult {
        let pingURL = endpoint.appending(path: "v2/")
        if initialResponse.statusCode == 200 {
            return .init(status: "Login Succeeded", identityToken: credentials.identityToken)
        }
        guard initialResponse.statusCode == 401 else {
            throw Self.loginError(initialResponse, body: initialBody)
        }
        guard let header = initialResponse.value(forHTTPHeaderField: "WWW-Authenticate") else {
            throw Self.loginError(initialResponse, body: initialBody)
        }

        let authorization: String
        var identityToken = credentials.identityToken
        let challenges = RegistrySearchClient.authenticationChallenges(header)
        if let parameters = challenges.first(where: { $0.scheme == "bearer" })?.parameters {
            let token = try await bearerToken(
                parameters: parameters,
                target: target,
                credentials: credentials
            )
            authorization = "Bearer \(token.accessToken)"
            if let refreshToken = token.refreshToken, !refreshToken.isEmpty {
                identityToken = refreshToken
            }
        } else if challenges.contains(where: { $0.scheme == "basic" }) {
            authorization = try Self.basicAuthorization(credentials)
        } else {
            throw EngineError(.unauthorized, "registry returned an unsupported authentication challenge")
        }

        var authenticatedPing = URLRequest(url: pingURL)
        authenticatedPing.setValue(authorization, forHTTPHeaderField: "Authorization")
        let (body, response) = try await perform(authenticatedPing)
        guard response.statusCode == 200 else {
            throw Self.loginError(response, body: body)
        }
        return .init(status: "Login Succeeded", identityToken: identityToken)
    }

    private func bearerToken(
        parameters: [String: String],
        target: Target,
        credentials: RegistryCredentials
    ) async throws -> (accessToken: String, refreshToken: String?) {
        guard let realmValue = parameters["realm"],
              let realm = URL(string: realmValue),
              let scheme = realm.scheme?.lowercased(),
              let host = realm.host,
              realm.user == nil,
              realm.password == nil,
              realm.fragment == nil,
              scheme == "https" || (scheme == "http" && target.loopback && RegistrySearchClient.isLoopback(host)) else {
            throw EngineError(.internalError, "registry returned an invalid token authentication realm")
        }

        let request: URLRequest
        if credentials.identityToken.isEmpty {
            request = try Self.basicTokenRequest(
                realm: realm,
                service: parameters["service"] ?? "",
                credentials: credentials
            )
        } else {
            request = try Self.refreshTokenRequest(
                realm: realm,
                service: parameters["service"] ?? "",
                identityToken: credentials.identityToken
            )
        }

        let (data, response) = try await perform(request)
        guard (200...299).contains(response.statusCode) else {
            throw Self.loginError(response, body: data)
        }
        let token: TokenResponse
        do {
            token = try JSONDecoder().decode(TokenResponse.self, from: data)
        } catch {
            throw EngineError(
                .internalError,
                "error decoding registry login token response: \(EngineError.message(for: error))"
            )
        }
        guard let accessToken = token.accessToken ?? token.token, !accessToken.isEmpty else {
            throw EngineError(.internalError, "registry login token response did not include an access token")
        }
        return (accessToken, token.refreshToken)
    }

    private func perform(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        try await execute(request, Self.maximumResponseBytes)
    }

    private static func target(_ serverAddress: String) throws -> Target {
        let address = serverAddress.isEmpty ? "https://index.docker.io/v1/" : serverAddress
        guard !address.contains(where: { $0.isWhitespace }) else {
            throw EngineError(.badRequest, "invalid registry server address")
        }
        let hasScheme = address.contains("://")
        guard var components = URLComponents(string: hasScheme ? address : "https://\(address)"),
              let inputScheme = components.scheme?.lowercased(),
              inputScheme == "https" || inputScheme == "http",
              let inputHost = components.host,
              !inputHost.isEmpty,
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil else {
            throw EngineError(.badRequest, "invalid registry server address \(serverAddress)")
        }

        let host = inputHost.lowercased()
        let official = host == "docker.io" || host == "index.docker.io"
        let resolvedHost = official ? "registry-1.docker.io" : inputHost
        let loopback = RegistrySearchClient.isLoopback(resolvedHost)
        let scheme = official ? "https" : (hasScheme ? inputScheme : "https")
        guard scheme != "http" || loopback else {
            throw EngineError(.badRequest, "insecure registry login is only supported for loopback addresses")
        }

        components.host = resolvedHost
        components.path = ""
        components.query = nil
        components.fragment = nil
        let schemes = !hasScheme && loopback ? ["https", "http"] : [scheme]
        let endpoints = try schemes.map { scheme in
            components.scheme = scheme
            guard let endpoint = components.url else {
                throw EngineError(.badRequest, "invalid registry server address \(serverAddress)")
            }
            return endpoint
        }
        return .init(endpoints: endpoints, loopback: loopback)
    }

    private static func basicAuthorization(_ credentials: RegistryCredentials) throws -> String {
        guard !credentials.username.isEmpty, !credentials.password.isEmpty else {
            throw EngineError(.unauthorized, "registry username and password are required")
        }
        return "Basic " + Data("\(credentials.username):\(credentials.password)".utf8).base64EncodedString()
    }

    private static func basicTokenRequest(
        realm: URL,
        service: String,
        credentials: RegistryCredentials
    ) throws -> URLRequest {
        var components = try tokenComponents(realm)
        var items = components.queryItems ?? []
        if !service.isEmpty { items.append(.init(name: "service", value: service)) }
        items.append(.init(name: "offline_token", value: "true"))
        items.append(.init(name: "client_id", value: "docker"))
        if !credentials.username.isEmpty {
            items.append(.init(name: "account", value: credentials.username))
        }
        components.queryItems = items
        guard let url = components.url else {
            throw EngineError(.internalError, "could not encode registry login token request")
        }
        var request = URLRequest(url: url)
        if !credentials.username.isEmpty || !credentials.password.isEmpty {
            request.setValue(try basicAuthorization(credentials), forHTTPHeaderField: "Authorization")
        }
        return request
    }

    private static func refreshTokenRequest(
        realm: URL,
        service: String,
        identityToken: String
    ) throws -> URLRequest {
        var form = URLComponents()
        form.queryItems = [
            .init(name: "scope", value: ""),
            .init(name: "service", value: service),
            .init(name: "client_id", value: "docker"),
            .init(name: "grant_type", value: "refresh_token"),
            .init(name: "refresh_token", value: identityToken),
        ]
        guard let body = form.percentEncodedQuery else {
            throw EngineError(.internalError, "could not encode registry login token request")
        }
        var request = URLRequest(url: realm)
        request.httpMethod = "POST"
        request.httpBody = Data(body.utf8)
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        return request
    }

    private static func tokenComponents(_ realm: URL) throws -> URLComponents {
        guard let components = URLComponents(url: realm, resolvingAgainstBaseURL: false) else {
            throw EngineError(.internalError, "invalid registry login token URL")
        }
        return components
    }

    private static func loginError(_ response: HTTPURLResponse, body _: Data) -> EngineError {
        let code: EngineError.Code = response.statusCode == 401 || response.statusCode == 403
            ? .unauthorized : .internalError
        let reason = HTTPURLResponse.localizedString(forStatusCode: response.statusCode)
        return EngineError(
            code,
            "login attempt to \(response.url?.absoluteString ?? "registry") failed with status: \(response.statusCode) \(reason)"
        )
    }

    private static func readBounded<Bytes: AsyncSequence>(
        _ bytes: Bytes,
        maximumBytes: Int
    ) async throws -> Data where Bytes.Element == UInt8 {
        var data = Data()
        data.reserveCapacity(min(maximumBytes, 64 * 1_024))
        for try await byte in bytes {
            guard data.count < maximumBytes else {
                throw EngineError(.internalError, "registry login response exceeds 1 MiB")
            }
            data.append(byte)
        }
        return data
    }
}

final class RegistryAuthenticationSessionDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate, @unchecked Sendable {
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
        guard let original = task.currentRequest else {
            completionHandler(nil)
            return
        }
        completionHandler(Self.redirectedRequest(from: original, to: request))
    }

    static func redirectedRequest(from original: URLRequest, to proposed: URLRequest) -> URLRequest? {
        guard original.httpMethod != "POST",
              sameOrigin(original.url, proposed.url) else {
            return nil
        }
        var redirected = proposed
        for (name, value) in original.allHTTPHeaderFields ?? [:] {
            redirected.setValue(value, forHTTPHeaderField: name)
        }
        return redirected
    }

    private static func sameOrigin(_ lhs: URL?, _ rhs: URL?) -> Bool {
        guard let lhs, let rhs,
              lhs.scheme?.lowercased() == rhs.scheme?.lowercased(),
              lhs.host?.lowercased() == rhs.host?.lowercased() else {
            return false
        }
        func port(_ url: URL) -> Int? {
            url.port ?? (url.scheme?.lowercased() == "https" ? 443 : 80)
        }
        return port(lhs) == port(rhs)
    }
}

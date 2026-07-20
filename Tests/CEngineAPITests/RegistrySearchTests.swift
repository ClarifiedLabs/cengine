@testable import CEngineAPI
import CEngineCore
@testable import CEngineRuntime
import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import Testing

private struct RegistrySearchStub: Sendable {
    let statusCode: Int
    let responseBody: Data
    let headers: [String: String]
    let error: URLError.Code?

    init(
        statusCode: Int = 200,
        responseBody: String = "",
        headers: [String: String] = [:],
        error: URLError.Code? = nil
    ) {
        self.statusCode = statusCode
        self.responseBody = Data(responseBody.utf8)
        self.headers = headers
        self.error = error
    }
}

private actor RegistrySearchRequestRecorder {
    private(set) var requests: [URLRequest] = []
    private let stubs: [RegistrySearchStub]

    init(statusCode: Int = 200, responseBody: String, headers: [String: String] = [:]) {
        stubs = [.init(statusCode: statusCode, responseBody: responseBody, headers: headers)]
    }

    init(stubs: [RegistrySearchStub]) {
        self.stubs = stubs
    }

    func execute(_ request: URLRequest, maximumBytes _: Int) throws -> (Data, HTTPURLResponse) {
        requests.append(request)
        guard requests.count <= stubs.count else {
            throw EngineError(.internalError, "unexpected registry test request")
        }
        let stub = stubs[requests.count - 1]
        if let error = stub.error { throw URLError(error) }
        guard let url = request.url,
              let response = HTTPURLResponse(
                url: url,
                statusCode: stub.statusCode,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"].merging(stub.headers) { _, new in new }
              ) else {
            throw EngineError(.internalError, "could not create test response")
        }
        return (stub.responseBody, response)
    }

    func count() -> Int { requests.count }
    func lastRequest() -> URLRequest? { requests.last }
    func allRequests() -> [URLRequest] { requests }
}

private actor RegistrySearcherSpy: RegistrySearching {
    struct Call: Sendable {
        let term: String
        let limit: Int
        let filters: RegistrySearchFilters
        let credentials: RegistryCredentials?
        let headers: [String: [String]]
    }

    private(set) var calls: [Call] = []
    private let results: [RegistrySearchResult]

    init(results: [RegistrySearchResult] = []) {
        self.results = results
    }

    func search(
        term: String,
        limit: Int,
        filters: RegistrySearchFilters,
        credentials: RegistryCredentials?,
        headers: [String: [String]]
    ) async throws -> [RegistrySearchResult] {
        calls.append(.init(
            term: term,
            limit: limit,
            filters: filters,
            credentials: credentials,
            headers: headers
        ))
        return results
    }

    func lastCall() -> Call? { calls.last }
    func count() -> Int { calls.count }
}

private actor RegistrySearchByteCounter {
    private var consumed = 0

    func next(total: Int) -> UInt8? {
        guard consumed < total else { return nil }
        consumed += 1
        return 0x61
    }

    func count() -> Int { consumed }
}

private struct CountingRegistrySearchBytes: AsyncSequence, Sendable {
    typealias Element = UInt8

    struct Iterator: AsyncIteratorProtocol {
        let total: Int
        let counter: RegistrySearchByteCounter

        mutating func next() async -> UInt8? {
            await counter.next(total: total)
        }
    }

    let total: Int
    let counter: RegistrySearchByteCounter

    func makeAsyncIterator() -> Iterator {
        Iterator(total: total, counter: counter)
    }
}

private actor DisconnectCancellationSearcher: RegistrySearching {
    private var started = false
    private var cancelled = false

    func search(
        term _: String,
        limit _: Int,
        filters _: RegistrySearchFilters,
        credentials _: RegistryCredentials?,
        headers _: [String: [String]]
    ) async throws -> [RegistrySearchResult] {
        started = true
        do {
            try await Task.sleep(for: .seconds(30))
            return []
        } catch {
            cancelled = true
            throw error
        }
    }

    func didStart() -> Bool { started }
    func wasCancelled() -> Bool { cancelled }
}

private actor OrderedRegistrySearcher: RegistrySearching {
    private var terms: [String] = []
    private var firstRequestContinuation: CheckedContinuation<Void, Never>?

    func search(
        term: String,
        limit _: Int,
        filters _: RegistrySearchFilters,
        credentials _: RegistryCredentials?,
        headers _: [String: [String]]
    ) async throws -> [RegistrySearchResult] {
        terms.append(term)
        if term == "first" {
            await withCheckedContinuation { firstRequestContinuation = $0 }
        }
        return [.init(
            description: "result for \(term)",
            isOfficial: false,
            isAutomated: false,
            name: term,
            starCount: 0
        )]
    }

    func recordedTerms() -> [String] { terms }

    func releaseFirstRequest() {
        firstRequestContinuation?.resume()
        firstRequestContinuation = nil
    }
}

private actor ResponseBoundaryBacklogSearcher: RegistrySearching {
    private var terms: [String] = []
    private var firstRequestReleased = false
    private var secondRequestCancelled = false

    func search(
        term: String,
        limit _: Int,
        filters _: RegistrySearchFilters,
        credentials _: RegistryCredentials?,
        headers _: [String: [String]]
    ) async throws -> [RegistrySearchResult] {
        terms.append(term)
        if term == "a" {
            while !firstRequestReleased {
                try await Task.sleep(for: .milliseconds(5))
            }
        } else if term == "b" {
            do {
                try await Task.sleep(for: .seconds(30))
            } catch {
                secondRequestCancelled = true
                throw error
            }
        }
        return [.init(
            description: "result for \(term)",
            isOfficial: false,
            isAutomated: false,
            name: term,
            starCount: 0
        )]
    }

    func recordedTerms() -> [String] { terms }

    func releaseFirstRequest() {
        firstRequestReleased = true
    }

    func wasSecondRequestCancelled() -> Bool { secondRequestCancelled }
}

private final class RegistrySearchResponseCollector: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer

    private let lock = NSLock()
    private var bytes: [UInt8] = []

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let buffer = unwrapInboundIn(data)
        let received = buffer.getBytes(at: buffer.readerIndex, length: buffer.readableBytes) ?? []
        lock.lock()
        bytes.append(contentsOf: received)
        lock.unlock()
        context.fireChannelRead(data)
    }

    func text() -> String {
        lock.lock()
        let snapshot = bytes
        lock.unlock()
        return String(decoding: snapshot, as: UTF8.self)
    }
}

private func queryEncodedJSON(_ value: String) -> String {
    value.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? value
}

@Suite struct RegistrySearchClientTests {
    @Test func dockerHubSearchUsesV1EndpointAndNormalizesResults() async throws {
        let recorder = RegistrySearchRequestRecorder(responseBody: #"""
        {
            "query":"alpine","num_results":2,"results":[
                {"description":"Official Alpine","is_official":true,"is_automated":true,"name":"alpine","star_count":12000},
                {"description":"Community Alpine","is_official":false,"is_automated":true,"name":"example/alpine","star_count":42}
            ]
        }
        """#)
        let client = RegistrySearchClient(execute: { try await recorder.execute($0, maximumBytes: $1) })

        let results = try await client.search(
            term: "docker.io/library/alpine",
            limit: 0,
            filters: .init(),
            credentials: nil,
            headers: ["User-Agent": ["cengine/test"], "X-Meta-Source": ["compat"]]
        )

        #expect(results.count == 2)
        #expect(results.allSatisfy { !$0.isAutomated })
        #expect(results[0].name == "alpine")
        let request = try #require(await recorder.lastRequest())
        #expect(request.url?.scheme == "https")
        #expect(request.url?.host == "index.docker.io")
        #expect(request.url?.path == "/v1/search")
        let url = try #require(request.url)
        let query = try #require(URLComponents(url: url, resolvingAgainstBaseURL: false))
        #expect(query.queryItems?.first(where: { $0.name == "q" })?.value == "alpine")
        #expect(query.queryItems?.first(where: { $0.name == "n" })?.value == "25")
        #expect(request.value(forHTTPHeaderField: "Authorization") == nil)
        #expect(request.value(forHTTPHeaderField: "X-Docker-Token") == "true")
        #expect(request.value(forHTTPHeaderField: "X-Meta-Source") == "compat")
    }

    @Test func registryLikeSingleComponentTermsRemainDockerHubSearchTerms() async throws {
        for term in ["nginx.com", "localhost"] {
            let recorder = RegistrySearchRequestRecorder(responseBody: #"{"results":[]}"#)
            let client = RegistrySearchClient(execute: { try await recorder.execute($0, maximumBytes: $1) })

            _ = try await client.search(
                term: term,
                limit: 1,
                filters: .init(),
                credentials: nil
            )

            let requests = await recorder.allRequests()
            #expect(requests.count == 1)
            let request = try #require(requests.first)
            #expect(request.url?.host == "index.docker.io")
            #expect(request.url?.path == "/v1/search")
            let components = try #require(request.url.flatMap {
                URLComponents(url: $0, resolvingAgainstBaseURL: false)
            })
            #expect(components.queryItems?.first(where: { $0.name == "q" })?.value == term)
        }
    }

    @Test func customLocalRegistryUsesHTTPAndBasicAuthentication() async throws {
        let recorder = RegistrySearchRequestRecorder(stubs: [
            .init(error: .cannotConnectToHost),
            .init(responseBody: #"{}"#),
            .init(responseBody: #"{"query":"team/app","num_results":0,"results":[]}"#),
        ])
        let client = RegistrySearchClient(execute: { try await recorder.execute($0, maximumBytes: $1) })

        _ = try await client.search(
            term: "localhost:5000/team/app",
            limit: 4,
            filters: .init(),
            credentials: .init(username: "search-user", password: "search-pass")
        )

        let request = try #require(await recorder.lastRequest())
        #expect(request.url?.absoluteString.contains("http://localhost:5000/v1/search") == true)
        #expect(request.value(forHTTPHeaderField: "Authorization") == "Basic c2VhcmNoLXVzZXI6c2VhcmNoLXBhc3M=")
        let url = try #require(request.url)
        let query = try #require(URLComponents(url: url, resolvingAgainstBaseURL: false))
        #expect(query.queryItems?.first(where: { $0.name == "q" })?.value == "team/app")
        #expect(query.queryItems?.first(where: { $0.name == "n" })?.value == "4")
        let requests = await recorder.allRequests()
        #expect(requests.map(\.url?.scheme) == ["https", "http", "http"])
        #expect(requests[0].url?.path == "/v1/_ping")
    }

    @Test func filtersOfficialImagesAndMinimumStarsAfterSearch() async throws {
        let recorder = RegistrySearchRequestRecorder(responseBody: #"""
        {
            "query":"base","num_results":4,"results":[
                {"description":"one","is_official":true,"is_automated":false,"name":"one","star_count":9},
                {"description":"two","is_official":true,"is_automated":false,"name":"two","star_count":10},
                {"description":"three","is_official":false,"is_automated":false,"name":"org/three","star_count":100},
                {"description":"four","is_official":true,"is_automated":false,"name":"four","star_count":20}
            ]
        }
        """#)
        let client = RegistrySearchClient(execute: { try await recorder.execute($0, maximumBytes: $1) })

        let results = try await client.search(
            term: "base",
            limit: 2,
            filters: .init(isOfficial: true, minimumStars: 10),
            credentials: nil
        )

        #expect(results.map(\.name) == ["two", "four"])
    }

    @Test func deprecatedAutomatedTrueFilterReturnsEmptyWithoutNetwork() async throws {
        let recorder = RegistrySearchRequestRecorder(responseBody: #"{"results":[]}"#)
        let client = RegistrySearchClient(execute: { try await recorder.execute($0, maximumBytes: $1) })

        let results = try await client.search(
            term: "alpine",
            limit: 25,
            filters: .init(isAutomated: true),
            credentials: nil
        )

        #expect(results.isEmpty)
        #expect(await recorder.count() == 0)
    }

    @Test func rejectsInvalidTermAndLimitsBeforeNetwork() async throws {
        let recorder = RegistrySearchRequestRecorder(responseBody: #"{"results":[]}"#)
        let client = RegistrySearchClient(execute: { try await recorder.execute($0, maximumBytes: $1) })

        for (term, limit) in [("https://docker.io/alpine", 25), ("alpine", -1), ("alpine", 101)] {
            await #expect(throws: EngineError.self) {
                try await client.search(term: term, limit: limit, filters: .init(), credentials: nil)
            }
        }
        #expect(await recorder.count() == 0)
    }

    @Test func mapsUnauthorizedAndMalformedRegistryResponses() async throws {
        let unauthorized = RegistrySearchRequestRecorder(statusCode: 401, responseBody: #"{"message":"denied"}"#)
        let unauthorizedClient = RegistrySearchClient(execute: { try await unauthorized.execute($0, maximumBytes: $1) })
        do {
            _ = try await unauthorizedClient.search(term: "alpine", limit: 1, filters: .init(), credentials: nil)
            Issue.record("unauthorized registry response succeeded")
        } catch let error as EngineError {
            #expect(error.code == .internalError)
        }

        let malformed = RegistrySearchRequestRecorder(responseBody: #"{"results":"wrong"}"#)
        let malformedClient = RegistrySearchClient(execute: { try await malformed.execute($0, maximumBytes: $1) })
        do {
            _ = try await malformedClient.search(term: "alpine", limit: 1, filters: .init(), credentials: nil)
            Issue.record("malformed registry response succeeded")
        } catch let error as EngineError {
            #expect(error.code == .internalError)
        }
    }

    @Test func treatsMissingLegacyResultFieldsAsZeroValues() async throws {
        let recorder = RegistrySearchRequestRecorder(responseBody: #"{"results":[{"name":"minimal"},{"description":null,"name":"nullable"}]}"#)
        let client = RegistrySearchClient(execute: { try await recorder.execute($0, maximumBytes: $1) })

        let results = try await client.search(term: "minimal", limit: 2, filters: .init(), credentials: nil)

        #expect(results.map(\.name) == ["minimal", "nullable"])
        #expect(results.allSatisfy {
            $0.description.isEmpty && !$0.isOfficial && !$0.isAutomated && $0.starCount == 0
        })
    }

    @Test func boundedReaderStopsAtFirstByteBeyondLimit() async throws {
        let counter = RegistrySearchByteCounter()
        let bytes = CountingRegistrySearchBytes(total: 100, counter: counter)

        do {
            _ = try await RegistrySearchClient.readBounded(bytes, maximumBytes: 3)
            Issue.record("oversized registry response succeeded")
        } catch let error as EngineError {
            #expect(error.code == .internalError)
        }

        #expect(await counter.count() == 4)
    }

    @Test func identityTokenUsesScopedChallengeExchangeAndNeverDirectRegistryAuth() async throws {
        let recorder = RegistrySearchRequestRecorder(stubs: [
            .init(
                statusCode: 401,
                headers: [
                    "WWW-Authenticate": #"Bearer realm="https://auth.example.test/token",service="registry.example.test""#,
                ]
            ),
            .init(responseBody: #"{"access_token":"scoped-access"}"#),
            .init(responseBody: #"{"results":[]}"#),
        ])
        let client = RegistrySearchClient(execute: { try await recorder.execute($0, maximumBytes: $1) })

        _ = try await client.search(
            term: "alpine",
            limit: 1,
            filters: .init(),
            credentials: .init(username: "docker-user", identityToken: "refresh-secret")
        )

        let requests = await recorder.allRequests()
        #expect(requests.count == 3)
        #expect(requests[0].url?.absoluteString == "https://index.docker.io/v2/")
        #expect(requests[0].value(forHTTPHeaderField: "Authorization") == nil)
        #expect(requests[0].httpBody == nil)

        #expect(requests[1].url?.absoluteString == "https://auth.example.test/token")
        #expect(requests[1].httpMethod == "POST")
        #expect(requests[1].value(forHTTPHeaderField: "Authorization") == nil)
        let formBody = String(decoding: try #require(requests[1].httpBody), as: UTF8.self)
        let form = URLComponents(string: "?\(formBody)")?.queryItems ?? []
        #expect(form.first(where: { $0.name == "client_id" })?.value == "docker")
        #expect(form.first(where: { $0.name == "grant_type" })?.value == "refresh_token")
        #expect(form.first(where: { $0.name == "refresh_token" })?.value == "refresh-secret")
        #expect(form.first(where: { $0.name == "scope" })?.value == "registry:catalog:search")
        #expect(form.first(where: { $0.name == "service" })?.value == "registry.example.test")

        #expect(requests[2].url?.path == "/v1/search")
        #expect(requests[2].value(forHTTPHeaderField: "Authorization") == "Bearer scoped-access")
        #expect(requests[2].httpBody == nil)
        #expect(requests[2].url?.absoluteString.contains("refresh-secret") == false)
    }

    @Test func redirectsStripSecretsOutsideTrustedDockerHTTPSLocations() throws {
        var search = URLRequest(url: try #require(URL(string: "https://index.docker.io/v1/search")))
        search.setValue("Bearer scoped-access", forHTTPHeaderField: "Authorization")
        search.setValue("test", forHTTPHeaderField: "X-Meta-Source")
        let external = URLRequest(url: try #require(URL(string: "https://example.test/search")))
        let stripped = try #require(RegistrySearchSessionDelegate.redirectedRequest(from: search, to: external))
        #expect(stripped.value(forHTTPHeaderField: "Authorization") == nil)
        #expect(stripped.value(forHTTPHeaderField: "X-Meta-Source") == "test")

        let trusted = URLRequest(url: try #require(URL(string: "https://auth.docker.io/search")))
        let preserved = try #require(RegistrySearchSessionDelegate.redirectedRequest(from: search, to: trusted))
        #expect(preserved.value(forHTTPHeaderField: "Authorization") == "Bearer scoped-access")

        var token = URLRequest(url: try #require(URL(string: "https://auth.example.test/token")))
        token.httpMethod = "POST"
        token.httpBody = Data("refresh_token=refresh-secret".utf8)
        token.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        #expect(RegistrySearchSessionDelegate.redirectedRequest(from: token, to: external) == nil)
    }

    @Test func queryEscapesLiteralPlusAndSupportsBracketedIPv6Loopback() async throws {
        let plusRecorder = RegistrySearchRequestRecorder(responseBody: #"{"results":[]}"#)
        let plusClient = RegistrySearchClient(execute: { try await plusRecorder.execute($0, maximumBytes: $1) })
        _ = try await plusClient.search(term: "c++", limit: 1, filters: .init(), credentials: nil)
        #expect((await plusRecorder.lastRequest())?.url?.absoluteString.contains("q=c%2B%2B") == true)

        let ipv6Recorder = RegistrySearchRequestRecorder(stubs: [
            .init(responseBody: #"{}"#),
            .init(responseBody: #"{"results":[]}"#),
        ])
        let ipv6Client = RegistrySearchClient(execute: { try await ipv6Recorder.execute($0, maximumBytes: $1) })
        _ = try await ipv6Client.search(
            term: "[::1]:5000/team/app",
            limit: 1,
            filters: .init(),
            credentials: nil
        )
        let ipv6Requests = await ipv6Recorder.allRequests()
        #expect(ipv6Requests.map(\.url?.scheme) == ["https", "https"])
        #expect(ipv6Requests.allSatisfy { RegistrySearchClient.isLoopback($0.url?.host ?? "") })
        #expect(RegistrySearchClient.isLoopback("127.255.255.255"))
        #expect(RegistrySearchClient.isLoopback("::1"))
        #expect(!RegistrySearchClient.isLoopback("::2"))
    }
}

@Suite struct DockerRegistrySearchRouteTests {
    private func router(searcher: any RegistrySearching) async throws -> (DockerRouter, URL) {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        return (
            DockerRouter(
                runtime: try await EngineRuntime(root: root),
                root: root,
                registrySearcher: searcher
            ),
            root
        )
    }

    @Test func searchIsAvailableAcrossSupportedAPIVersionsAndUsesDockerWireShape() async throws {
        let spy = RegistrySearcherSpy(results: [.init(
            description: "A small image",
            isOfficial: true,
            isAutomated: false,
            name: "alpine",
            starCount: 100
        )])
        let (router, root) = try await router(searcher: spy)
        defer { try? FileManager.default.removeItem(at: root) }
        let auth = Data(#"{"username":"demo","password":"secret"}"#.utf8).base64EncodedString()
        let filters = "%7B%22is-official%22%3A%5B%22true%22%5D%2C%22stars%22%3A%5B%2210%22%2C%225%22%5D%7D"

        for version in ["1.44", "1.55"] {
            let response = await router.route(.init(
                method: .GET,
                uri: "/v\(version)/images/search?term=alpine&limit=12&filters=\(filters)",
                headers: ["X-Registry-Auth": auth, "X-Meta-Source": "test"]
            ))
            #expect(response.status == .ok)
            let body = try #require(JSONSerialization.jsonObject(with: response.body) as? [[String: Any]])
            #expect(body.count == 1)
            #expect(body[0]["name"] as? String == "alpine")
            #expect(body[0]["is_official"] as? Bool == true)
            #expect(body[0]["is_automated"] as? Bool == false)
            #expect(body[0]["star_count"] as? Int == 100)
            #expect(body[0]["isOfficial"] == nil)
        }

        let call = try #require(await spy.lastCall())
        #expect(call.term == "alpine")
        #expect(call.limit == 12)
        #expect(call.filters == .init(isOfficial: true, minimumStars: 10))
        #expect(call.credentials?.username == "demo")
        #expect(call.credentials?.password == "secret")
        #expect(call.headers["X-Meta-Source"] == ["test"])
        #expect(call.headers["User-Agent"]?.first?.hasPrefix("cengine/") == true)
    }

    @Test func acceptsBooleanMapFiltersAndIgnoresMalformedRegistryAuth() async throws {
        let spy = RegistrySearcherSpy()
        let (router, root) = try await router(searcher: spy)
        defer { try? FileManager.default.removeItem(at: root) }
        let filters = "%7B%22is-official%22%3A%7B%22false%22%3Atrue%7D%2C%22is-automated%22%3A%7B%22false%22%3Atrue%7D%7D"

        let response = await router.route(.init(
            method: .GET,
            uri: "/v1.55/images/search?term=team&filters=\(filters)",
            headers: ["X-Registry-Auth": "not-base64"]
        ))

        #expect(response.status == .ok)
        let call = try #require(await spy.lastCall())
        #expect(call.limit == 0)
        #expect(call.filters == .init(isAutomated: false, isOfficial: false))
        #expect(call.credentials == nil)

        let urlAuth = "eyJ1c2VybmFtZSI6IsK_eMK-IiwicGFzc3dvcmQiOiJwIn0="
        #expect(await router.route(.init(
            method: .GET,
            uri: "/v1.55/images/search?term=team",
            headers: ["X-Registry-Auth": urlAuth]
        )).status == .ok)
        #expect(await spy.lastCall()?.credentials?.username == "¿x¾")

        #expect(await router.route(.init(
            method: .GET,
            uri: "/v1.55/images/search?term=team",
            headers: ["X-Registry-Auth": "e30"]
        )).status == .ok)
        #expect(await spy.lastCall()?.credentials == nil)

        for invalid in [
            #"{"is-official":{"true":true,"false":true}}"#,
            #"{"is-official":{"true":false}}"#,
        ] {
            let filters = queryEncodedJSON(invalid)
            #expect(await router.route(.init(
                method: .GET,
                uri: "/v1.55/images/search?term=team&filters=\(filters)"
            )).status == .badRequest)
        }
    }

    @Test func starsMapEnumeratesEveryKeyWhileBooleanMapsHonorActiveFlags() async throws {
        let spy = RegistrySearcherSpy()
        let (router, root) = try await router(searcher: spy)
        defer { try? FileManager.default.removeItem(at: root) }
        let mixed = queryEncodedJSON(
            #"{"is-official":{"true":false,"false":true},"is-automated":{"true":false,"false":true},"stars":{"100":false,"5":true}}"#
        )

        #expect(await router.route(.init(
            method: .GET,
            uri: "/v1.55/images/search?term=team&filters=\(mixed)"
        )).status == .ok)
        #expect(await spy.lastCall()?.filters == .init(
            isAutomated: false,
            isOfficial: false,
            minimumStars: 100
        ))

        let falseOnly = queryEncodedJSON(#"{"stars":{"100":false}}"#)
        #expect(await router.route(.init(
            method: .GET,
            uri: "/v1.55/images/search?term=team&filters=\(falseOnly)"
        )).status == .ok)
        #expect(await spy.lastCall()?.filters == .init(minimumStars: 100))
    }

    @Test func searchTermUsesFormDecodingAtTheRouteBoundary() async throws {
        let spy = RegistrySearcherSpy()
        let (router, root) = try await router(searcher: spy)
        defer { try? FileManager.default.removeItem(at: root) }

        #expect(await router.route(.init(
            method: .GET,
            uri: "/v1.55/images/search?term=foo+bar"
        )).status == .ok)
        #expect(await spy.lastCall()?.term == "foo bar")

        #expect(await router.route(.init(
            method: .GET,
            uri: "/v1.55/images/search?term=foo%2Bbar"
        )).status == .ok)
        #expect(await spy.lastCall()?.term == "foo+bar")
    }

    @Test func formDecodedSearchTermIsEscapedExactlyOnceByRegistryClient() async throws {
        let recorder = RegistrySearchRequestRecorder(stubs: [
            .init(responseBody: #"{"results":[]}"#),
            .init(responseBody: #"{"results":[]}"#),
        ])
        let client = RegistrySearchClient(execute: { try await recorder.execute($0, maximumBytes: $1) })
        let (router, root) = try await router(searcher: client)
        defer { try? FileManager.default.removeItem(at: root) }

        #expect(await router.route(.init(
            method: .GET,
            uri: "/v1.55/images/search?term=foo+bar"
        )).status == .ok)
        #expect(await router.route(.init(
            method: .GET,
            uri: "/v1.55/images/search?term=foo%2Bbar"
        )).status == .ok)

        let requests = await recorder.allRequests()
        #expect(requests.count == 2)
        #expect(requests[0].url.flatMap {
            URLComponents(url: $0, resolvingAgainstBaseURL: false)?.percentEncodedQuery
        } == "q=foo+bar&n=25")
        #expect(requests[1].url.flatMap {
            URLComponents(url: $0, resolvingAgainstBaseURL: false)?.percentEncodedQuery
        } == "q=foo%2Bbar&n=25")
    }

    @Test func rejectsInvalidSearchQueriesWithoutCallingRegistry() async throws {
        let spy = RegistrySearcherSpy()
        let (router, root) = try await router(searcher: spy)
        defer { try? FileManager.default.removeItem(at: root) }
        let requests = [
            "/v1.55/images/search",
            "/v1.55/images/search?term=alpine&limit=-1",
            "/v1.55/images/search?term=alpine&limit=101",
            "/v1.55/images/search?term=alpine&limit=invalid",
            "/v1.55/images/search?term=alpine&filters=%7Bbad",
            "/v1.55/images/search?term=alpine&filters=%7B%22label%22%3A%5B%22x%22%5D%7D",
            "/v1.55/images/search?term=alpine&filters=%7B%22is-official%22%3A%5B%22maybe%22%5D%7D",
            "/v1.55/images/search?term=alpine&filters=%7B%22stars%22%3A%5B%22many%22%5D%7D",
        ]

        for uri in requests {
            #expect(await router.route(.init(method: .GET, uri: uri)).status == .badRequest)
        }
        #expect(await spy.count() == 0)
    }

    @Test func disconnectAfterMultiplePipelinedReadCyclesCancelsRegistrySearch() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let socket = root.appending(path: "engine.sock").path
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let searcher = DisconnectCancellationSearcher()
        let router = DockerRouter(
            runtime: try await EngineRuntime(root: root),
            root: root,
            registrySearcher: searcher
        )
        let server = DockerServer(socketPath: socket, router: router)
        try await server.start()

        let clientGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let client = try await ClientBootstrap(group: clientGroup)
            .connect(unixDomainSocketPath: socket)
            .get()
        var request = client.allocator.buffer(capacity: 128)
        request.writeString("GET /v1.55/images/search?term=slow HTTP/1.1\r\nHost: localhost\r\n\r\n")
        try await client.writeAndFlush(request).get()

        for _ in 0..<500 {
            if await searcher.didStart() { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(await searcher.didStart())

        for chunk in [
            "GET /v1.55/images/search?term=pending HTTP/1.1\r\n",
            "Host: localhost\r\nX-Pending-One: \(String(repeating: "a", count: 64))\r\n",
            "X-Pending-Two: \(String(repeating: "b", count: 64))",
        ] {
            var pending = client.allocator.buffer(capacity: chunk.utf8.count)
            pending.writeString(chunk)
            try await client.writeAndFlush(pending).get()
            try await Task.sleep(for: .milliseconds(20))
        }

        try await client.close(mode: .output).get()
        for _ in 0..<500 {
            if await searcher.wasCancelled() { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(await searcher.wasCancelled())
        try? await client.close().get()
        try await server.shutdown()
        try await clientGroup.shutdownGracefully()
    }

    @Test func excessivePipelinedBytesCloseConnectionAndCancelRegistrySearch() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let socket = root.appending(path: "engine.sock").path
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let searcher = DisconnectCancellationSearcher()
        let router = DockerRouter(
            runtime: try await EngineRuntime(root: root),
            root: root,
            registrySearcher: searcher
        )
        let server = DockerServer(
            socketPath: socket,
            router: router,
            maximumPendingRequestBytes: 128
        )
        try await server.start()

        let clientGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let client = try await ClientBootstrap(group: clientGroup)
            .connect(unixDomainSocketPath: socket)
            .get()
        var request = client.allocator.buffer(capacity: 128)
        request.writeString("GET /v1.55/images/search?term=slow HTTP/1.1\r\nHost: localhost\r\n\r\n")
        try await client.writeAndFlush(request).get()

        for _ in 0..<500 {
            if await searcher.didStart() { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(await searcher.didStart())

        for chunk in [
            "GET /v1.55/images/search?term=pending HTTP/1.1\r\nX-One: \(String(repeating: "a", count: 24))\r\n",
            "X-Two: \(String(repeating: "b", count: 80))\r\n\r\n",
        ] {
            var pending = client.allocator.buffer(capacity: chunk.utf8.count)
            pending.writeString(chunk)
            try? await client.writeAndFlush(pending).get()
            try await Task.sleep(for: .milliseconds(20))
        }

        for _ in 0..<500 {
            if await searcher.wasCancelled(), !client.isActive { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(await searcher.wasCancelled())
        #expect(!client.isActive)
        try? await client.close().get()
        try await server.shutdown()
        try await clientGroup.shutdownGracefully()
    }

    @Test func sameWritePipelinedBytesAreCappedAfterAsyncRequestBegins() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let socket = root.appending(path: "engine.sock").path
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let searcher = DisconnectCancellationSearcher()
        let router = DockerRouter(
            runtime: try await EngineRuntime(root: root),
            root: root,
            registrySearcher: searcher
        )
        let server = DockerServer(
            socketPath: socket,
            router: router,
            maximumPendingRequestBytes: 128
        )
        try await server.start()

        let clientGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let client = try await ClientBootstrap(group: clientGroup)
            .connect(unixDomainSocketPath: socket)
            .get()
        let firstRequest =
            "GET /v1.55/images/search?term=slow HTTP/1.1\r\nHost: localhost\r\n\r\n"
        let pendingBody = String(repeating: "p", count: 96)
        let pendingRequest =
            "POST /v1.55/images/search?term=pending HTTP/1.1\r\n" +
            "Host: localhost\r\nContent-Length: \(pendingBody.utf8.count)\r\n\r\n" +
            pendingBody
        var request = client.allocator.buffer(capacity: firstRequest.utf8.count + pendingRequest.utf8.count)
        request.writeString(firstRequest + pendingRequest)
        try await client.writeAndFlush(request).get()

        for _ in 0..<500 {
            if !client.isActive { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(!client.isActive)
        try? await client.close().get()
        try await server.shutdown()
        try await clientGroup.shutdownGracefully()
    }

    @Test func excessiveChunkedPipelinedPartsCloseConnectionAndCancelRegistrySearch() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let socket = root.appending(path: "engine.sock").path
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let searcher = DisconnectCancellationSearcher()
        let router = DockerRouter(
            runtime: try await EngineRuntime(root: root),
            root: root,
            registrySearcher: searcher
        )
        let server = DockerServer(
            socketPath: socket,
            router: router,
            maximumPendingRequestParts: 8
        )
        try await server.start()

        let clientGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let client = try await ClientBootstrap(group: clientGroup)
            .connect(unixDomainSocketPath: socket)
            .get()
        var request = client.allocator.buffer(capacity: 128)
        request.writeString("GET /v1.55/images/search?term=slow HTTP/1.1\r\nHost: localhost\r\n\r\n")
        try await client.writeAndFlush(request).get()

        for _ in 0..<500 {
            if await searcher.didStart() { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(await searcher.didStart())

        let chunkedRequest =
            "POST /v1.55/images/search?term=pending HTTP/1.1\r\n" +
            "Host: localhost\r\nTransfer-Encoding: chunked\r\n\r\n" +
            String(repeating: "1\r\np\r\n", count: 16) +
            "0\r\n\r\n"
        #expect(chunkedRequest.utf8.count < 1024)
        var pending = client.allocator.buffer(capacity: chunkedRequest.utf8.count)
        pending.writeString(chunkedRequest)
        try await client.writeAndFlush(pending).get()

        for _ in 0..<200 {
            if await searcher.wasCancelled(), !client.isActive { break }
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(await searcher.wasCancelled())
        #expect(!client.isActive)
        try? await client.close().get()
        try await server.shutdown()
        try await clientGroup.shutdownGracefully()
    }

    @Test func pendingPartBudgetSpansResponseBoundaries() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let socket = root.appending(path: "engine.sock").path
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let searcher = ResponseBoundaryBacklogSearcher()
        let router = DockerRouter(
            runtime: try await EngineRuntime(root: root),
            root: root,
            registrySearcher: searcher
        )
        let server = DockerServer(
            socketPath: socket,
            router: router,
            maximumPendingRequestParts: 8
        )
        try await server.start()

        let clientGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let client = try await ClientBootstrap(group: clientGroup)
            .connect(unixDomainSocketPath: socket)
            .get()
        var first = client.allocator.buffer(capacity: 128)
        first.writeString("GET /v1.55/images/search?term=a HTTP/1.1\r\nHost: localhost\r\n\r\n")
        try await client.writeAndFlush(first).get()

        for _ in 0..<500 {
            if await searcher.recordedTerms() == ["a"] { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(await searcher.recordedTerms() == ["a"])

        let firstBacklog = ["b", "c", "d", "e"].map {
            "GET /v1.55/images/search?term=\($0) HTTP/1.1\r\nHost: localhost\r\n\r\n"
        }.joined()
        var buffered = client.allocator.buffer(capacity: firstBacklog.utf8.count)
        buffered.writeString(firstBacklog)
        try await client.writeAndFlush(buffered).get()
        try await Task.sleep(for: .milliseconds(50))
        #expect(await searcher.recordedTerms() == ["a"])

        await searcher.releaseFirstRequest()
        for _ in 0..<500 {
            if await searcher.recordedTerms() == ["a", "b"] { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(await searcher.recordedTerms() == ["a", "b"])

        let secondBacklog = ["f", "g", "h", "i"].map {
            "GET /v1.55/images/search?term=\($0) HTTP/1.1\r\nHost: localhost\r\n\r\n"
        }.joined()
        var additional = client.allocator.buffer(capacity: secondBacklog.utf8.count)
        additional.writeString(secondBacklog)
        try await client.writeAndFlush(additional).get()

        for _ in 0..<200 {
            if await searcher.wasSecondRequestCancelled(), !client.isActive { break }
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(await searcher.wasSecondRequestCancelled())
        #expect(!client.isActive)
        try? await client.close().get()
        try await server.shutdown()
        try await clientGroup.shutdownGracefully()
    }

    @Test func pipelinedRegistrySearchesPreserveKeepAliveResponseOrdering() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let socket = root.appending(path: "engine.sock").path
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let searcher = OrderedRegistrySearcher()
        let router = DockerRouter(
            runtime: try await EngineRuntime(root: root),
            root: root,
            registrySearcher: searcher
        )
        let server = DockerServer(socketPath: socket, router: router)
        try await server.start()

        let collector = RegistrySearchResponseCollector()
        let clientGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let client = try await ClientBootstrap(group: clientGroup)
            .channelInitializer { $0.pipeline.addHandler(collector) }
            .connect(unixDomainSocketPath: socket)
            .get()
        var first = client.allocator.buffer(capacity: 128)
        first.writeString(
            "GET /v1.55/images/search?term=first HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n"
        )
        try await client.writeAndFlush(first).get()

        for _ in 0..<500 {
            if await searcher.recordedTerms() == ["first"] { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(await searcher.recordedTerms() == ["first"])

        for chunk in [
            "GET /v1.55/images/search?term=second HTTP/1.1\r\n",
            "Host: localhost\r\nConnection: close\r\n",
            "\r\n",
        ] {
            var second = client.allocator.buffer(capacity: chunk.utf8.count)
            second.writeString(chunk)
            try await client.writeAndFlush(second).get()
            try await Task.sleep(for: .milliseconds(20))
        }
        #expect(await searcher.recordedTerms() == ["first"])

        await searcher.releaseFirstRequest()
        for _ in 0..<500 {
            let response = collector.text()
            if response.components(separatedBy: "HTTP/1.1 200 OK").count == 3,
               response.contains(#""name":"first""#),
               response.contains(#""name":"second""#) {
                break
            }
            try await Task.sleep(for: .milliseconds(10))
        }

        let response = collector.text()
        #expect(response.components(separatedBy: "HTTP/1.1 200 OK").count == 3)
        let firstName = response.range(of: #""name":"first""#)
        let secondName = response.range(of: #""name":"second""#)
        #expect(firstName != nil)
        #expect(secondName != nil)
        if let firstName, let secondName {
            #expect(firstName.lowerBound < secondName.lowerBound)
        }
        #expect(await searcher.recordedTerms() == ["first", "second"])
        try? await client.close().get()
        try await server.shutdown()
        try await clientGroup.shutdownGracefully()
    }
}

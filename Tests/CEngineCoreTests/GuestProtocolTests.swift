import Foundation
import Testing
@testable import CEngineCore

@Suite struct GuestProtocolTests {
    @Test func execPayloadUsesVersionSixIdentityAndSecurityContext() throws {
        #expect(GuestProtocol.version == 6)
        let value = GuestProtocol.Exec(
            id: "exec-1", arguments: ["id"], environment: ["A=1"],
            workingDirectory: "/work",
            user: .init(uid: 1_000, gid: 2_000, additionalGroups: [3_000]),
            terminal: false, attachStdin: false, attachStdout: true, attachStderr: true,
            noNewPrivileges: true
        )

        let data = try JSONEncoder().encode(value)
        #expect(try JSONDecoder().decode(GuestProtocol.Exec.self, from: data) == value)
        let object = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let user = try #require(object["user"] as? [String: Any])
        #expect(user["uid"] as? Int == 1_000)
        #expect(object["noNewPrivileges"] as? Bool == true)
    }

    @Test func workloadPayloadCarriesRuntimeAnnotations() throws {
        let value = GuestProtocol.Workload(
            id: "container-1", rootDevice: "/dev/vda", arguments: ["true"],
            environment: [], workingDirectory: "/", hostname: "container-1", user: .init(),
            terminal: false, readOnlyRoot: false, stopSignal: "SIGTERM", mounts: [], networks: [],
            resources: .init(memoryBytes: 64 * 1_024 * 1_024, cpuQuota: 100_000, cpuPeriod: 100_000, pids: 0),
            annotations: ["io.example.owner": "runtime"]
        )

        let data = try JSONEncoder().encode(value)
        #expect(try JSONDecoder().decode(GuestProtocol.Workload.self, from: data) == value)
        let object = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(object["annotations"] as? [String: String] == ["io.example.owner": "runtime"])
    }

    @Test func controlEnvelopeRoundTripsWithLengthPrefix() throws {
        let envelope = GuestProtocol.Envelope(id: "request-1", operation: "ping")

        let encoded = try GuestProtocol.encode(envelope)
        let decoded = try GuestProtocol.decode(encoded)

        #expect(decoded == envelope)
    }

    @Test func controlEnvelopeEncodesPayloadAsRawJSONForTheGoGuest() throws {
        let payload = Data(#"{"status":"ready","pid":42}"#.utf8)
        let encoded = try GuestProtocol.encode(.init(id: "request-1", operation: "status", payload: payload))
        let body = try #require(try JSONSerialization.jsonObject(with: encoded.dropFirst(4)) as? [String: Any])
        let embedded = try #require(body["payload"] as? [String: Any])

        #expect(embedded["status"] as? String == "ready")
        #expect(embedded["pid"] as? Int == 42)
        let decoded = try GuestProtocol.decode(encoded)
        let decodedPayload = try #require(decoded.payload)
        let decodedObject = try #require(try JSONSerialization.jsonObject(with: decodedPayload) as? [String: Any])
        #expect(decodedObject["status"] as? String == "ready")
        #expect(decodedObject["pid"] as? Int == 42)
    }

    @Test func controlEnvelopeRejectsUnsupportedVersion() throws {
        let encoded = try GuestProtocol.encode(.init(version: GuestProtocol.version + 1, id: "request-1", operation: "ping"))

        #expect(throws: EngineError.self) {
            try GuestProtocol.decode(encoded)
        }
    }

    @Test func controlEnvelopeRejectsTruncatedFrame() {
        #expect(throws: EngineError.self) {
            try GuestProtocol.decode(Data([0, 0, 0, 2, 0]))
        }
    }
}

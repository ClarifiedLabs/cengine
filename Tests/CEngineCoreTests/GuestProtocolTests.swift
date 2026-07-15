import Foundation
import Testing
@testable import CEngineCore

@Suite struct GuestProtocolTests {
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

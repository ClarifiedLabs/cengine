import Darwin
import Foundation
import Testing
@testable import StorageControllerRuntime

@Suite struct ControlProtocolBoundaryTests {
    @Test func neutralCloseDiagnosticPreservesFailureCategoriesAndWirePhases() throws {
        typealias Diagnostic = ManagedStorageCloseDiagnostic
        let samples: [(ManagedStorageControlFailure, Diagnostic.Category)] = [
            (.invalidConfiguration, .invalidConfiguration), (.unauthorized, .unauthorized),
            (.system(EIO), .system), (.system(ETIMEDOUT), .timeout),
            (.protocolViolation, .protocolViolation), (.serviceUnavailable, .serviceUnavailable)
        ]
        #expect(Diagnostic.Phase.allCases.map(\.rawValue) == [
            "ipc-write", "ipc-read", "reply-validation", "owner-validation", "control-exchange",
            "reconnect-stream", "reconnect-status", "reconnect-connect", "decode", "close"
        ])
        for phase in Diagnostic.Phase.allCases {
            for (error, category) in samples {
                let diagnostic = Diagnostic(site: .adapter, operation: .retire, phase: phase, error: error)
                #expect(diagnostic.category == category)
                #expect(try JSONDecoder().decode(Diagnostic.self, from: JSONEncoder().encode(diagnostic)) == diagnostic)
            }
        }
        #expect(Diagnostic(site: .explicit, operation: .close, phase: .close).category == .none)
    }

}

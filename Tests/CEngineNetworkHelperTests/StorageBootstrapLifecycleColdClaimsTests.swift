import Foundation
import Testing
@testable import StorageBootstrapHelper

/// Pure lease bookkeeping used by ColdXPC itself, not native/installed acceptance.
@Suite struct StorageBootstrapLifecycleColdClaimsTests {
    private final class Lease {}

    @Test func moreThan128RetiredClaimsReleaseTheirRetainedPeers() throws {
        var claims = StorageBootstrapLifecycleColdClaims<Lease>()
        let pending = Lease(), unenrolled = Lease()
        claims["pending"] = pending; claims["latest-unenrolled"] = unenrolled
        for index in 0..<256 {
            let operation = "completed-enrolled-\(index)"
            try claims.checkCapacity(for: operation)
            weak var released: Lease?
            do {
                let peer = Lease()
                released = peer; claims[operation] = peer
            }
            #expect(released != nil)
            try claims.reconcile { ["pending", "latest-unenrolled"] }
            #expect(released == nil)
            #expect(claims.count == 2)
            #expect(claims["pending"] === pending)
            #expect(claims["latest-unenrolled"] === unenrolled)
        }
    }

    @Test func unavailableSnapshotNeverEvictsEvenAtCapacity() throws {
        var claims = StorageBootstrapLifecycleColdClaims<Lease>()
        for index in 0..<128 { claims["\(index)"] = Lease() }
        let retained = claims["0"]
        try claims.checkCapacity(for: "0") // Exact retry is still permitted.
        #expect(throws: BootstrapFailure.self) { try claims.checkCapacity(for: "new") }
        #expect(throws: BootstrapFailure.self) {
            try claims.reconcile { throw BootstrapFailure(.unavailable) }
        }
        #expect(claims.count == 128 && claims["0"] === retained)
        #expect(throws: BootstrapFailure.self) { try claims.checkCapacity(for: "new") }
        // No disconnect/time/liveness input can retire a lease. Only reachability.
        try claims.reconcile { ["0"] }
        #expect(claims.count == 1 && claims["0"] === retained)
        try claims.checkCapacity(for: "new")
    }
}

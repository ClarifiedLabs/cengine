import CEngineCore
import Foundation
import Testing
@testable import CEngineRuntime

/// The compatibility store lock keeps the physical path while the backend keeps
/// Foundation's canonical root; `/private/var` temporary stores must still be
/// recognized as the lock's own store, and foreign stores must not.
@Suite struct CompatibilityStoreLockRootTests {
    @Test func physicalTemporaryStoreMatchesItsCanonicalDataRoot() throws {
        let requested = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString, directoryHint: .isDirectory)
        defer { try? FileManager.default.removeItem(at: requested) }
        let lock = try CanonicalDataStoreLock(root: requested)
        let dataRoot = try RawVirtualizationBackend.canonicalDataRoot(lock.root)
        #expect(lock.root.path.hasPrefix("/private/") || lock.root == dataRoot)
        #expect(RawVirtualizationBackend.storeLockGuardsDataRoot(lock.root, dataRoot: dataRoot))
        #expect(RawVirtualizationBackend.storeLockGuardsDataRoot(dataRoot, dataRoot: dataRoot))
        let other = requested.deletingLastPathComponent().appending(path: UUID().uuidString, directoryHint: .isDirectory)
        #expect(!RawVirtualizationBackend.storeLockGuardsDataRoot(other, dataRoot: dataRoot))
        #expect(!RawVirtualizationBackend.storeLockGuardsDataRoot(lock.root, dataRoot: dataRoot.deletingLastPathComponent()))
    }
}

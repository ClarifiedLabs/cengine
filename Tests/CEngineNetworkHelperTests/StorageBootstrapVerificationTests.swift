import CEngineCore
import Darwin
import Foundation
import Testing
@testable import StorageBootstrapHelper

private func expectBindingFailure(_ code: StorageIdentity.ErrorCode, _ body: () throws -> Void) {
    do { try body(); Issue.record("binding unexpectedly accepted") }
    catch let failure as BootstrapFailure { #expect(failure.code == code) }
    catch { Issue.record("binding returned an unexpected error type") }
}

private enum BindingRejectionCase: CaseIterable {
    case rootMode, backingMode, owner, rootBinding, backingSize, superblockLength, superblockMagic, superblockUUID
    var diagnostic: StorageBootstrapBindingDiagnostic {
        switch self {
        case .rootMode: .init(stage: .identityMode, role: .root)
        case .backingMode: .init(stage: .identityMode, role: .backing)
        case .owner: .init(stage: .identityOwner, role: .root)
        case .rootBinding: .init(stage: .rootBinding, role: .root)
        case .backingSize: .init(stage: .backingSize, role: .backing)
        case .superblockLength: .init(stage: .superblockLength, role: .backing)
        case .superblockMagic: .init(stage: .superblockMagic, role: .backing)
        case .superblockUUID: .init(stage: .superblockUUID, role: .backing)
        }
    }
}

/// Native descriptors plus a synthetic ext4 header; no disk formatting, mounting or helper installation.
final class NativeBindingFixture {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    var root: Int32 = -1
    var backing: Int32 = -1
    var binding: StorageIdentity.StoreBinding!
    init() throws {
        try FileManager.default.createDirectory(at: url.appendingPathComponent("nested"), withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        root = open(url.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        _ = try #require(root >= 0)
        #expect(fchmod(root, 0o700) == 0)
        backing = openat(root, "nested/backing", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
        _ = try #require(backing >= 0)
        #expect(fchmod(backing, 0o600) == 0)
        var bytes = [UInt8](repeating: 0, count: 4096)
        bytes[1024 + 56] = 0x53; bytes[1024 + 57] = 0xef
        let uuid = UUID(uuidString: "11111111-1111-4111-8111-111111111111")!
        withUnsafeBytes(of: uuid.uuid) { bytes.replaceSubrange((1024 + 104)..<(1024 + 120), with: $0) }
        _ = try #require(pwrite(backing, &bytes, bytes.count, 0) == bytes.count)
        binding = try .init(storeID: .init(UUID().uuidString.lowercased()), root: Self.identity(root),
            backing: .init(identity: Self.identity(backing), size: UInt64(bytes.count)),
            expectedExt4UUID: .init(uuid.uuidString.lowercased()))
    }
    deinit {
        if backing >= 0 { close(backing) }
        if root >= 0 { close(root) }
        try? FileManager.default.removeItem(at: url)
    }
    private static func identity(_ fd: Int32) throws -> StorageIdentity.RootIdentity {
        var info = stat()
        _ = try #require(fstat(fd, &info) == 0)
        var attributes = attrlist()
        attributes.bitmapcount = UInt16(ATTR_BIT_MAP_COUNT)
        attributes.volattr = ATTR_VOL_INFO | UInt32(ATTR_VOL_UUID)
        var bytes = [UInt8](repeating: 0, count: 20)
        _ = try #require(fgetattrlist(fd, &attributes, &bytes, bytes.count, 0) == 0)
        let uuid = bytes.withUnsafeBytes { UUID(uuid: $0.loadUnaligned(fromByteOffset: 4, as: uuid_t.self)) }
        return try .init(volumeUUID: .init(uuid.uuidString.lowercased()),
                         inode: info.st_ino)
    }
}

@Suite struct StorageBootstrapVerificationTests {
    @Test(arguments: [3, 4, 5, 6, 7])
    func liveObservationChangesRejectDuringVerification(at call: Int) throws {
        let f = try NativeBindingFixture()
        var count = 0
        let verifier = StorageBootstrapBindings(ownerUID: geteuid(), diagnostic: { _ in }, observation: { actual in
            count += 1
            return count >= call ? .init(stableIdentity: actual.stableIdentity, device: actual.device &+ 1) : actual
        })
        #expect(throws: (any Error).self) { try verifier.verify(f.binding, rootFD: f.root, backingFD: f.backing) }
    }

    @Test func nativeGreetingRequiresExactLiveDeviceEvenForSameStableBacking() throws {
        let f = try NativeBindingFixture(), verifier = StorageBootstrapBindings(ownerUID: geteuid(), diagnostic: { _ in })
        let actual = try verifier.observe(f.backing, type: S_IFREG, role: .backing)
        try verifier.verify(f.binding, rootFD: f.root, backingFD: f.backing, expectedBacking: actual)
        #expect(throws: (any Error).self) {
            try verifier.verify(f.binding, rootFD: f.root, backingFD: f.backing,
                expectedBacking: .init(stableIdentity: actual.stableIdentity, device: actual.device &+ 1))
        }
    }

    @Test func rebootObservationAcceptsStableBindingButForeignVolumeRefuses() throws {
        let f = try NativeBindingFixture()
        let rebooted = StorageBootstrapBindings(ownerUID: geteuid(), diagnostic: { _ in }, observation: {
            .init(stableIdentity: $0.stableIdentity, device: 0)
        })
        try rebooted.verify(f.binding, rootFD: f.root, backingFD: f.backing)
        let foreign = try StorageIdentity.RootIdentity(volumeUUID: .init(UUID().uuidString.lowercased()), inode: f.binding.root.inode)
        let binding = StorageIdentity.StoreBinding(storeID: f.binding.storeID, root: foreign,
            backing: f.binding.backing, expectedExt4UUID: f.binding.expectedExt4UUID)
        #expect(throws: (any Error).self) { try rebooted.verify(binding, rootFD: f.root, backingFD: f.backing) }
    }

    @Test func auditProjectionRejectsReusedPIDAndWrongOwner() throws {
        var token = audit_token_t()
        token.val = (999, 501, 20, 501, 20, 1234, 777, 42)
        let audit = BootstrapAuditIdentity(token: token)
        let current = BootstrapKernelIdentity(uniqueID: 123, parentUniqueID: 100, pidVersion: 42)
        #expect(audit.pid == 1234)
        #expect(audit.effectiveUID == 501)
        #expect(audit.realUID == 501)
        #expect(audit.pidVersion == 42)
        #expect(audit.data.count == 32)
        #expect(audit.matches(current, owner: 501))
        #expect(!audit.matches(current, owner: 502))
        #expect(!audit.matches(.init(uniqueID: 124, parentUniqueID: 100, pidVersion: 43), owner: 501))
        token.val.3 = 502
        #expect(!BootstrapAuditIdentity(token: token).matches(current, owner: 501))
        #expect(!BootstrapAuditIdentity(token: audit_token_t()).matches(current, owner: 0))
    }

    @Test func parentIsOriginalUniqueIDNotPIDOrReplacementDaemon() {
        // Unsigned kernel-data seam: this does not simulate a production code signature.
        let daemon = BootstrapProcess(pid: 100, startSeconds: 1, startMicroseconds: 0,
            boot: "unsigned", signingIdentity: "unsigned", uniqueID: 999, pidVersion: 1, auditToken: Data())
        #expect(BootstrapKernelIdentity(uniqueID: 1000, parentUniqueID: 999, pidVersion: 1).hasPinnedParent(daemon))
        #expect(!BootstrapKernelIdentity(uniqueID: 1000, parentUniqueID: 100, pidVersion: 1).hasPinnedParent(daemon))
        #expect(!BootstrapKernelIdentity(uniqueID: 1000, parentUniqueID: 998, pidVersion: 1).hasPinnedParent(daemon))
        #expect(!BootstrapKernelIdentity(uniqueID: 999, parentUniqueID: 999, pidVersion: 1).hasPinnedParent(daemon))
    }
    @Test func nativeUniqueIdentifierABIWorksWithoutPrivilege() throws {
        let first = try #require(BootstrapKernelIdentity.read(getpid()))
        let second = try #require(BootstrapKernelIdentity.read(getpid()))
        #expect(first.uniqueID > 0)
        #expect(first.parentUniqueID > 0)
        #expect(first == second)
        #expect(BootstrapKernelIdentity.read(-1) == nil)
    }

    @Test func replacedFinalFIFOIsRejectedWithoutBlocking() throws {
        let path = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        #expect(mkdir(path, 0o700) == 0)
        defer { try? FileManager.default.removeItem(atPath: path) }
        let directory = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        defer { close(directory) }
        let original = openat(directory, "backing", O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0o600)
        defer { close(original) }
        #expect(unlinkat(directory, "backing", 0) == 0)
        #expect(mkfifo(path + "/backing", 0o600) == 0)
        // Watchdog writer avoids leaving the suite hung if NONBLOCK regresses.
        DispatchQueue.global().asyncAfter(deadline: .now() + 1) {
            let writer = open(path + "/backing", O_WRONLY | O_NONBLOCK | O_CLOEXEC)
            if writer >= 0 { close(writer) }
        }
        let start = ContinuousClock.now
        #expect(throws: (any Error).self) {
            let descriptor = try StorageBootstrapBindings.openComponent(directory, name: "backing", last: true)
            close(descriptor)
        }
        #expect(start.duration(to: .now) < .milliseconds(500))
    }

    @Test func validNativeBindingIsSilentAndRetainsCallerDescriptors() throws {
        let fixture = try NativeBindingFixture()
        var diagnostics: [StorageBootstrapBindingDiagnostic] = []
        let verifier = StorageBootstrapBindings(ownerUID: geteuid(), diagnostic: { diagnostics.append($0) })
        try verifier.verify(fixture.binding, rootFD: fixture.root, backingFD: fixture.backing)
        #expect(diagnostics.isEmpty)
        #expect(fcntl(fixture.root, F_GETFD) >= 0)
        #expect(fcntl(fixture.backing, F_GETFD) >= 0)
    }

    @Test(arguments: [StorageBootstrapBindingDiagnostic.Role.root, .backing])
    func invalidDescriptorRecordsCapturedErrnoAndPreservesConflict(_ role: StorageBootstrapBindingDiagnostic.Role) throws {
        let fixture = try NativeBindingFixture()
        var diagnostics: [StorageBootstrapBindingDiagnostic] = []
        let verifier = StorageBootstrapBindings(ownerUID: geteuid(), diagnostic: {
            errno = EACCES // Sink activity must not replace the captured syscall errno.
            diagnostics.append($0)
        })
        expectBindingFailure(.conflict) {
            try verifier.verify(fixture.binding, rootFD: role == .root ? -1 : fixture.root,
                                backingFD: role == .backing ? -1 : fixture.backing)
        }
        #expect(diagnostics == [.init(stage: .identityStat, role: role, syscallErrno: EBADF)])
    }

    @Test(arguments: BindingRejectionCase.allCases)
    private func nativePolicyRejectionsHaveNoStaleErrno(_ rejection: BindingRejectionCase) throws {
        let fixture = try NativeBindingFixture()
        var binding = try #require(fixture.binding)
        var owner = geteuid()
        switch rejection {
        case .rootMode: #expect(fchmod(fixture.root, 0o722) == 0)
        case .backingMode: #expect(fchmod(fixture.backing, 0o622) == 0)
        case .owner: owner = geteuid() == 0 ? 1 : 0
        case .rootBinding:
            binding = .init(storeID: binding.storeID,
                root: try .init(volumeUUID: binding.root.volumeUUID, inode: binding.root.inode + 1),
                backing: binding.backing, expectedExt4UUID: binding.expectedExt4UUID)
        case .backingSize:
            binding = .init(storeID: binding.storeID, root: binding.root,
                backing: try .init(identity: binding.backing.identity, size: binding.backing.size + 1),
                expectedExt4UUID: binding.expectedExt4UUID)
        case .superblockLength:
            #expect(ftruncate(fixture.backing, 1024) == 0)
            binding = .init(storeID: binding.storeID, root: binding.root,
                backing: try .init(identity: binding.backing.identity, size: 1024), expectedExt4UUID: binding.expectedExt4UUID)
        case .superblockMagic:
            var byte: UInt8 = 0
            #expect(pwrite(fixture.backing, &byte, 1, 1024 + 56) == 1)
        case .superblockUUID:
            var byte: UInt8 = 0
            #expect(pwrite(fixture.backing, &byte, 1, 1024 + 104) == 1)
        }
        var diagnostics: [StorageBootstrapBindingDiagnostic] = []
        let verifier = StorageBootstrapBindings(ownerUID: owner, diagnostic: { diagnostics.append($0) })
        errno = EIO
        expectBindingFailure(.conflict) {
            try verifier.verify(binding, rootFD: fixture.root, backingFD: fixture.backing)
        }
        #expect(diagnostics == [rejection.diagnostic])
        #expect(fcntl(fixture.root, F_GETFD) >= 0)
        #expect(fcntl(fixture.backing, F_GETFD) >= 0)
    }

    @Test func nativeACLRejectionPreservesRepairRequiredWithoutErrno() throws {
        let fixture = try NativeBindingFixture()
        var acl = acl_init(1)
        defer { if let acl { acl_free(UnsafeMutableRawPointer(acl)) } }
        _ = try #require(acl != nil)
        var entry: acl_entry_t?
        _ = try #require(acl_create_entry(&acl, &entry) == 0)
        let created = try #require(entry)
        _ = try #require(acl_set_tag_type(created, ACL_EXTENDED_ALLOW) == 0)
        // An arbitrary fixture qualifier suffices: the verifier rejects every nonempty ACL.
        var uuid = UUID().uuid
        _ = try #require(acl_set_qualifier(created, &uuid) == 0)
        var permissions: acl_permset_t?
        _ = try #require(acl_get_permset(created, &permissions) == 0)
        let permissionSet = try #require(permissions)
        _ = try #require(acl_add_perm(permissionSet, ACL_READ_DATA) == 0)
        let populatedACL = try #require(acl)
        _ = try #require(acl_set_fd_np(fixture.root, populatedACL, ACL_TYPE_EXTENDED) == 0)
        var diagnostics: [StorageBootstrapBindingDiagnostic] = []
        let verifier = StorageBootstrapBindings(ownerUID: geteuid(), diagnostic: { diagnostics.append($0) })
        errno = EIO
        expectBindingFailure(.repairRequired) {
            try verifier.verify(fixture.binding, rootFD: fixture.root, backingFD: fixture.backing)
        }
        #expect(diagnostics == [.init(stage: .identityACL, role: .root)])
        #expect(fcntl(fixture.root, F_GETFD) >= 0)
        #expect(fcntl(fixture.backing, F_GETFD) >= 0)
    }

    @Test func componentDiagnosticsNeverContainSuppliedNameAndPreserveNoFollow() throws {
        let fixture = try NativeBindingFixture()
        let secretName = "must-not-log-this-name"
        var diagnostics: [StorageBootstrapBindingDiagnostic] = []
        func rejected(_ expectedErrno: Int32) {
            expectBindingFailure(.conflict) {
                let fd = try StorageBootstrapBindings.openComponent(fixture.root, name: secretName, last: true,
                    diagnostic: { diagnostics.append($0) })
                close(fd)
            }
            #expect(diagnostics.last == .init(stage: .componentOpen, role: .component, syscallErrno: expectedErrno))
        }
        rejected(ENOENT)
        #expect(symlinkat("nested/backing", fixture.root, secretName) == 0)
        rejected(ELOOP)
        #expect(diagnostics.count == 2)
        #expect(diagnostics.allSatisfy { !$0.line.contains(secretName) && !$0.line.contains(fixture.url.path) })
    }

    @Test func diagnosticRenderingUsesOnlyClosedFields() {
        for stage in StorageBootstrapBindingDiagnostic.Stage.allCases {
            for role in StorageBootstrapBindingDiagnostic.Role.allCases {
                let policy = StorageBootstrapBindingDiagnostic(stage: stage, role: role)
                #expect(policy.line == "storage-bootstrap-binding-rejected stage=\(stage.rawValue) role=\(role.rawValue)\n")
                let syscall = StorageBootstrapBindingDiagnostic(stage: stage, role: role, syscallErrno: EBADF)
                #expect(syscall.line == "storage-bootstrap-binding-rejected stage=\(stage.rawValue) role=\(role.rawValue) errno=9\n")
                #expect(syscall.line.utf8.count < 128)
                #expect(syscall.line.filter { $0 == "\n" }.count == 1)
            }
        }
    }


}

/// Suspend the test task without consuming a cooperative/global executor thread
/// needed by the actual dispatch/XPC work. Keep the original semaphore deadline.
func waitForBootstrapTestSignal(_ signal: DispatchSemaphore, timeout: TimeInterval) async -> DispatchTimeoutResult {
    let deadline = DispatchTime.now() + timeout
    return await withCheckedContinuation { continuation in
        Thread.detachNewThread {
            continuation.resume(returning: signal.wait(timeout: deadline))
        }
    }
}

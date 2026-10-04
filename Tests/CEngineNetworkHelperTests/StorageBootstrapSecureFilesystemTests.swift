import Darwin
import Foundation
import Testing
@testable import StorageBootstrapHelper

@Suite struct StorageBootstrapSecureFilesystemTests {
    @Test func invalidDescriptorFailsClosed() {
        do {
            try StorageBootstrapSecureFilesystem.requireNoACL(-1)
            Issue.record("invalid descriptor accepted")
        } catch let failure as BootstrapFailure {
            #expect(failure.code == .repairRequired)
        } catch { Issue.record("unexpected error: \(error)") }
    }

    @Test(arguments: [false, true])
    func emptyACLAcceptedAndNonemptyACLRejectedWithoutClosingDescriptor(_ directory: Bool) throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: url) }
        let fd = directory
            ? open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            : open(url.appendingPathComponent("file").path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        _ = try #require(fd >= 0)
        defer { close(fd) }
        try StorageBootstrapSecureFilesystem.requireNoACL(fd)

        var acl = acl_init(1)
        defer { if let acl { acl_free(UnsafeMutableRawPointer(acl)) } }
        _ = try #require(acl != nil)
        var entry: acl_entry_t?
        _ = try #require(acl_create_entry(&acl, &entry) == 0)
        let created = try #require(entry)
        _ = try #require(acl_set_tag_type(created, ACL_EXTENDED_ALLOW) == 0)
        var uuid = UUID().uuid
        _ = try #require(acl_set_qualifier(created, &uuid) == 0)
        var permissions: acl_permset_t?
        _ = try #require(acl_get_permset(created, &permissions) == 0)
        _ = try #require(acl_add_perm(try #require(permissions), ACL_READ_DATA) == 0)
        _ = try #require(acl_set_fd_np(fd, try #require(acl), ACL_TYPE_EXTENDED) == 0)
        errno = EIO
        do {
            try StorageBootstrapSecureFilesystem.requireNoACL(fd)
            Issue.record("nonempty ACL accepted")
        } catch let failure as BootstrapFailure {
            #expect(failure.code == .repairRequired)
        }
        #expect(fcntl(fd, F_GETFD) >= 0)

        let empty = try #require(acl_init(0))
        defer { acl_free(UnsafeMutableRawPointer(empty)) }
        _ = try #require(acl_set_fd_np(fd, empty, ACL_TYPE_EXTENDED) == 0)
        try StorageBootstrapSecureFilesystem.requireNoACL(fd)
        #expect(fcntl(fd, F_GETFD) >= 0)
    }
}

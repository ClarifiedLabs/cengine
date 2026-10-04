import CEngineHelperSupport
import Darwin

/// Descriptor-only filesystem checks shared by helper storage paths.
/// These checks do not grant authority or take ownership of caller descriptors.
enum StorageBootstrapSecureFilesystem {
    static func requireNoACL(_ fd: Int32) throws {
        guard let acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) else {
            if errno == ENOENT { return }; throw BootstrapFailure(.repairRequired)
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        guard acl_get_entry(acl, ACL_FIRST_ENTRY.rawValue, &entry) == -1, errno == EINVAL else {
            throw BootstrapFailure(.repairRequired)
        }
    }
}

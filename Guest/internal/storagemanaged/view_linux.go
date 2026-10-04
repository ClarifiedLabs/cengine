//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"errors"
	"fmt"
	"unsafe"

	"dev.cengine/guest/internal/storageauthority"
	"golang.org/x/sys/unix"
)

func mountID(fd int) (uint64, error) {
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &st); err != nil {
		return 0, err
	}
	if st.Mask&unix.STATX_MNT_ID == 0 || st.Mnt_id == 0 {
		return 0, unix.EOPNOTSUPP
	}
	return st.Mnt_id, nil
}

// Linux include/uapi/linux/mount.h. x/sys has SYS_STATMOUNT but no wrapper.
// Only STATMOUNT_MNT_BASIC is requested, so no variable-length strings occur.
const statmountMountBasic = 0x00000002

type mountIDRequest struct {
	Size uint32
	_    uint32 // mnt_ns_fd = 0: current mount namespace
	ID   uint64
	Mask uint64
}

type mountStatus struct {
	Size uint32
	_    uint32
	Mask uint64
	_    [24]byte
	ID   uint64
	_    [16]byte
	Attr uint64
	_    [440]byte
}

func uniqueMountID(fd int) (uint64, error) {
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID_UNIQUE, &st); err != nil {
		return 0, err
	}
	if st.Mask&unix.STATX_MNT_ID_UNIQUE == 0 || st.Mnt_id == 0 {
		return 0, unix.EOPNOTSUPP
	}
	return st.Mnt_id, nil
}

func queryMount(req mountIDRequest) (mountStatus, error) {
	var st mountStatus
	req.Size = uint32(unsafe.Sizeof(req))
	_, _, errno := unix.Syscall6(unix.SYS_STATMOUNT, uintptr(unsafe.Pointer(&req)), uintptr(unsafe.Pointer(&st)), unsafe.Sizeof(st), 0, 0, 0)
	if errno != 0 {
		return st, errno
	}
	return st, nil
}

func validateUnmappedMount(st mountStatus, id uint64) error {
	if st.Size < uint32(unsafe.Offsetof(st.Attr)+unsafe.Sizeof(st.Attr)) || st.Size > uint32(unsafe.Sizeof(st)) || st.Mask&statmountMountBasic == 0 {
		return unix.EOPNOTSUPP
	}
	if id == 0 || st.ID != id {
		return unix.ESTALE
	}
	if st.Attr&unix.MOUNT_ATTR_IDMAP != 0 {
		return unix.EXDEV
	}
	return nil
}

// requireUnmappedMount inspects the attached canonical mount pinned by fd,
// not mountinfo (which cannot prove the absence of an idmap). Linux 6.18 can
// query it by unique ID. Missing syscalls/results, including ENOENT for detached
// mounts, fail closed; detached operation views instead use clone provenance.
func requireUnmappedMount(fd int) (uint64, error) {
	id, err := uniqueMountID(fd)
	if err != nil {
		return 0, fmt.Errorf("managed root unique mount ID: %w", err)
	}
	st, err := queryMount(mountIDRequest{ID: id, Mask: statmountMountBasic})
	if err != nil {
		return 0, fmt.Errorf("managed root statmount: %w", err)
	}
	if err = validateUnmappedMount(st, id); err != nil {
		return 0, fmt.Errorf("managed root must have a verified NOP idmap: %w", err)
	}
	return id, nil
}

// operationRoot consumes no canonical ownership. Only Guard.DupVolumeRoot's
// exact mount may seed the view; no pathname, substitute mount or idmap is used.
// Keep the canonical real descriptor separately for syncfs and final barriers.
func (s *Session) operationRoot() (int, error) {
	root := int(s.root.Fd())
	if s.binding.Mode != storageauthority.ReadOnly {
		return unix.Open(procFD(root), unix.O_PATH|unix.O_CLOEXEC, 0)
	}
	canonical, err := stat(root)
	if err != nil {
		return -1, err
	}
	// Under the namespace gate, verify the attached source immediately before
	// cloning its exact FD. Linux 6.18 clone_mnt inherits mnt_idmap; attached
	// mounts cannot change it. The clone stays private and MountSetattr below
	// never requests IDMAP, so its inherited NOP map cannot change. We do not
	// claim to query the detached clone's idmap.
	canonicalMount, err := requireUnmappedMount(root)
	if err != nil {
		return -1, err
	}
	fd, err := unix.OpenTree(root, "", unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_EMPTY_PATH)
	if err != nil {
		return -1, err
	}
	fail := func(err error) (int, error) { return -1, errors.Join(err, unix.Close(fd)) }
	if err = unix.MountSetattr(fd, "", unix.AT_EMPTY_PATH, &unix.MountAttr{
		Attr_set: unix.MOUNT_ATTR_RDONLY | unix.MOUNT_ATTR_NOATIME,
		Attr_clr: unix.MOUNT_ATTR__ATIME,
	}); err != nil {
		return fail(err)
	}
	if err = same(fd, inodeKey{s.binding.Volume, canonical.Dev, canonical.Ino}); err != nil {
		return fail(err)
	}
	viewMount, err := uniqueMountID(fd)
	if err != nil {
		return fail(err)
	}
	if viewMount == canonicalMount {
		return fail(unix.EXDEV)
	}
	var fs unix.Statfs_t
	if err = unix.Fstatfs(fd, &fs); err != nil {
		return fail(err)
	}
	if fs.Type != unix.EXT4_SUPER_MAGIC || fs.Flags&(unix.ST_RDONLY|unix.ST_NOATIME) != unix.ST_RDONLY|unix.ST_NOATIME {
		return fail(unix.EXDEV)
	}
	return fd, nil
}

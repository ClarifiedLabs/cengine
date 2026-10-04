//go:build linux

package supervisor

import (
	"fmt"

	"dev.cengine/guest/internal/copycontract"
	"golang.org/x/sys/unix"
)

const (
	maxConfinedXattrListBytes  = copycontract.MaxXattrListBytes
	maxConfinedXattrValueBytes = copycontract.MaxXattrValueBytes
	maxConfinedXattrBytes      = copycontract.MaxXattrBytes
	maxConfinedXattrEntries    = copycontract.MaxXattrEntries
)

// State distinguishes a known-empty set from a filesystem that cannot report
// xattrs. A nil snapshot is reserved for journals written before version 3.
type confinedXattrSnapshot = copycontract.XattrSnapshot

type confinedXattr = copycontract.Xattr

// Linux xattr names are bytes, not necessarily UTF-8. Encode names as base64
// just like values, so JSON never substitutes U+FFFD and changes inode metadata.
type confinedXattrName = copycontract.XattrName

// Explicit operations permit bounded fault tests without mutable syscall hooks.
type confinedXattrOperations struct {
	list   func(int, []byte) (int, error)
	get    func(int, string, []byte) (int, error)
	set    func(int, string, []byte, int) error
	remove func(int, string) error
}

func (operations confinedXattrOperations) shared() copycontract.XattrOperations {
	return copycontract.XattrOperations{
		List: operations.list, Get: operations.get,
		Set: operations.set, Remove: operations.remove,
	}
}

func confinedXattrSyscalls() confinedXattrOperations {
	return confinedXattrOperations{unix.Flistxattr, unix.Fgetxattr, unix.Fsetxattr, unix.Fremovexattr}
}

// O_PATH descriptors cannot use f*xattr. Following this trusted exact procfd
// magiclink jumps to the pinned inode, even when it is a symlink (Linux 6.18
// proc_pid_get_link/nd_jump_link). Never use l*xattr here: that would select the
// procfs link itself. Callers must retain and validate the no-follow inode pin.
func confinedSymlinkXattrSyscalls() confinedXattrOperations {
	procFD := func(fd int) string { return fmt.Sprintf("/proc/self/fd/%d", fd) }
	return confinedXattrOperations{
		list: func(fd int, buffer []byte) (int, error) {
			return unix.Listxattr(procFD(fd), buffer)
		},
		get: func(fd int, name string, buffer []byte) (int, error) {
			return unix.Getxattr(procFD(fd), name, buffer)
		},
		set: func(fd int, name string, value []byte, flags int) error {
			return unix.Setxattr(procFD(fd), name, value, flags)
		},
		remove: func(fd int, name string) error {
			return unix.Removexattr(procFD(fd), name)
		},
	}
}

func validConfinedXattrName(name string) bool {
	return copycontract.ValidateXattrs(&confinedXattrSnapshot{
		State:   "supported",
		Entries: []confinedXattr{{Name: confinedXattrName(name), Value: []byte{}}},
	}) == nil
}

func validateConfinedXattrs(snapshot *confinedXattrSnapshot) error {
	return copycontract.ValidateXattrs(snapshot)
}

func listConfinedXattrs(fd int, operations confinedXattrOperations) ([]string, bool, error) {
	return copycontract.ListXattrs(fd, operations.shared())
}

func snapshotConfinedXattrs(fd int) (*confinedXattrSnapshot, error) {
	return snapshotConfinedXattrsWith(fd, confinedXattrSyscalls())
}

func snapshotConfinedXattrsWith(fd int, operations confinedXattrOperations) (*confinedXattrSnapshot, error) {
	return copycontract.SnapshotXattrs(fd, operations.shared())
}

func restoreConfinedXattrs(fd int, snapshot *confinedXattrSnapshot) error {
	return restoreConfinedXattrsWith(fd, snapshot, confinedXattrSyscalls())
}

func restoreConfinedXattrsWith(fd int, snapshot *confinedXattrSnapshot, operations confinedXattrOperations) error {
	return copycontract.RestoreXattrs(fd, snapshot, operations.shared())
}

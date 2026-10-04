//go:build linux

package storageboot

import (
	"dev.cengine/guest/internal/vsock"
	"errors"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"time"
)

func authenticatedPeer(conn net.Conn) bool {
	addr, ok := conn.RemoteAddr().(vsock.Addr)
	return ok && addr.CID == 2
}

// Transport budget only; never proof of worker death or storage drain.
const workerCommandBudget = 5 * time.Second

func heldWorkerRoot(root *os.File) (workerRootIdentity, error) {
	if root == nil {
		return workerRootIdentity{}, errors.New("configuration")
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(root.Fd()), &fs); err != nil || uint64(fs.Type) != 0xef53 {
		return workerRootIdentity{}, errors.New("configuration")
	}
	var st unix.Statx_t
	const wanted = unix.STATX_TYPE | unix.STATX_INO | unix.STATX_MNT_ID
	if err := unix.Statx(int(root.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, wanted, &st); err != nil || st.Mask&wanted != wanted || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return workerRootIdentity{}, errors.New("configuration")
	}
	identity := workerRootIdentity{Device: unix.Mkdev(st.Dev_major, st.Dev_minor), Inode: st.Ino, MountID: st.Mnt_id}
	if identity.Device == 0 || identity.Inode == 0 || identity.MountID == 0 {
		return workerRootIdentity{}, errors.New("configuration")
	}
	return identity, nil
}

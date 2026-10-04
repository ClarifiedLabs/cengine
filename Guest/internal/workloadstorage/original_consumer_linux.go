//go:build linux

package workloadstorage

import (
	"encoding/json"
	"errors"
	"os"

	"dev.cengine/guest/internal/storagefuse"
	"golang.org/x/sys/unix"
)

// newOriginalWritableFD transfers ownership before any mount syscall starts.
// It is deliberately not reachable from an enabled case until wire admission
// and independent post-positive backing verification are implemented.
func (f *nativeFactory) newOriginalWritableFD(attachment Attachment) *retainedFDOwner {
	mounted, ok := attachment.(*storagefuse.Mounted)
	if !originalConsumerEnabled() || !ok || mounted.Err() != nil {
		return nil
	}
	select {
	case <-mounted.Done():
		return nil
	default:
	}
	// The writable owner establishes its own real WRITE+FSYNC positive. Do not
	// open/close extra directories here: their asynchronous RELEASEDIR can race
	// the exact positive trace, even after the acquisition syscall has returned.
	return newRetainedFDOwner(mounted.OriginalConsumerRoot, mounted.OriginalConsumerAbort, mounted.Done())
}

// Root READ acquisition uses the exact mount pin without any directory-fsync
// stand-in. All open/stat work remains on the retained syscall owner.
func (f *nativeFactory) newOriginalReadFD(attachment Attachment) *retainedFDOwner {
	mounted, ok := attachment.(*storagefuse.Mounted)
	if !originalConsumerEnabled() || !ok || mounted.Err() != nil {
		return nil
	}
	select {
	case <-mounted.Done():
		return nil
	default:
	}
	return newRetainedFDOwner(mounted.OriginalConsumerRoot, mounted.OriginalConsumerAbort, mounted.Done())
}

func (f *nativeFactory) originalConsumerObserver() *originalConsumer { return f.original }
func (f *nativeFactory) openOriginalMount(attachment Attachment) (*os.File, string, error) {
	mounted, ok := attachment.(*storagefuse.Mounted)
	if !ok || mounted.Err() != nil {
		return nil, "", ErrInvalidFrame
	}
	select {
	case <-mounted.Done():
		return nil, "", ErrInvalidFrame
	default:
	}
	open := func() (*os.File, error) {
		return mounted.OriginalConsumerRoot()
	}
	// FSYNCDIR is always forwarded through this existing FUSE/client path. It
	// is not a cached GETATTR or a second writer on the original DATA tls.Conn.
	positive, err := open()
	if err != nil {
		return nil, "", ErrInvalidFrame
	}
	err = positive.Sync()
	closeErr := positive.Close()
	if err != nil || closeErr != nil {
		return nil, "", ErrInvalidFrame
	}
	retained, err := open()
	if err != nil {
		return nil, "", ErrInvalidFrame
	}
	keep := false
	defer func() {
		if !keep {
			_ = retained.Close()
		}
	}()
	var fs unix.Statfs_t
	var stat unix.Statx_t
	if unix.Fstatfs(int(retained.Fd()), &fs) != nil || fs.Type != unix.FUSE_SUPER_MAGIC || unix.Statx(int(retained.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_INO|unix.STATX_MNT_ID|unix.STATX_TYPE, &stat) != nil || stat.Mask&(unix.STATX_INO|unix.STATX_MNT_ID|unix.STATX_TYPE) != unix.STATX_INO|unix.STATX_MNT_ID|unix.STATX_TYPE || stat.Mode&unix.S_IFMT != unix.S_IFDIR || retained.Sync() != nil || mounted.Err() != nil {
		return nil, "", ErrInvalidFrame
	}
	identity, _ := json.Marshal(struct {
		DeviceMajor, DeviceMinor uint32
		Inode, MountID           uint64
	}{stat.Dev_major, stat.Dev_minor, stat.Ino, stat.Mnt_id})
	keep = true
	return retained, SpecificationDigest(identity), nil
}
func originalFDError(err error) string {
	switch {
	case errors.Is(err, unix.EIO):
		return "eio"
	case errors.Is(err, unix.ENOTCONN):
		return "enotconn"
	case errors.Is(err, unix.ESTALE):
		return "estale"
	case errors.Is(err, unix.EACCES):
		return "eacces"
	}
	return "other"
}

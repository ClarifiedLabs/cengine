//go:build linux && cengine_native_faulttest

package supervisor

import (
	"encoding/json"
	"errors"
	"os"

	a "dev.cengine/guest/internal/storageauthority"
	"golang.org/x/sys/unix"
)

// Private, invocation-local, single fixed semantic stage. Only the tagged test
// constructs this value. There is no caller path/PID/key/callback or release API.
// Once held, only the exact owned initializer process's exit ends the checkpoint.
type confinedPublication struct {
	hello a.DataHello
	fired uint32
}

type nativePrepareIdentity struct {
	Filesystem [2]int32
	Device     uint64
	Inode      uint64
	HandleType int32
	Handle     []byte
}

type nativePrepareEvidence struct {
	Hello            a.DataHello
	Stage            string
	Count            uint32
	Root             nativePrepareIdentity
	Entries          map[string]nativePrepareIdentity
	InitializerError string
}

func nativePrepareIdentityAt(fd int, name string) (nativePrepareIdentity, error) {
	var st unix.Stat_t
	var fs unix.Statfs_t
	if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nativePrepareIdentity{}, err
	}
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return nativePrepareIdentity{}, err
	}
	result := nativePrepareIdentity{Filesystem: fs.Fsid.Val, Device: st.Dev, Inode: st.Ino}
	if name != "." {
		handle, _, err := unix.NameToHandleAt(fd, name, 0)
		if err != nil {
			return result, err
		}
		result.HandleType, result.Handle = handle.Type(), append([]byte(nil), handle.Bytes()...)
	}
	return result, nil
}

func nativePrepareObserve(fd int, hello a.DataHello, stage string, count uint32) (nativePrepareEvidence, error) {
	e := nativePrepareEvidence{Hello: hello, Stage: stage, Count: count, Entries: make(map[string]nativePrepareIdentity)}
	var err error
	e.Root, err = nativePrepareIdentityAt(fd, ".")
	if err != nil {
		return e, err
	}
	// Recovery deliberately interns the staged last entry before the first
	// published entry. These are fixed fixture names, not caller-selected paths.
	for _, name := range []string{confinedCopyTransactionName + "/" + confinedCopyStagingName + "/z", "a"} {
		e.Entries[name], err = nativePrepareIdentityAt(fd, name)
		if err != nil {
			return e, err
		}
	}
	return e, nil
}

func nativePrepareWriteEvidence(e nativePrepareEvidence) error {
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if len(data) > 8192 {
		return errors.New("prepare evidence bound")
	}
	file := os.NewFile(6, "owned-prepare-evidence")
	if file == nil {
		return errors.New("missing evidence descriptor")
	}
	defer file.Close()
	if _, err := file.WriteAt(data, 0); err != nil {
		return err
	}
	if err := file.Truncate(int64(len(data))); err != nil {
		return err
	}
	return file.Sync()
}

func (c *confinedPublication) afterPublication(fd int) error {
	if c == nil {
		return nil
	}
	if c.fired != 0 {
		return errors.New("first publication checkpoint fired twice")
	}
	c.fired = 1
	e, err := nativePrepareObserve(fd, c.hello, "first-publication", c.fired)
	if err != nil {
		return err
	}
	if err := nativePrepareWriteEvidence(e); err != nil {
		return err
	}
	// FD 5 is the parent's owned observation pipe, not a completion or drain ACK.
	if n, err := unix.Write(5, []byte{1}); err != nil {
		return err
	} else if n != 1 {
		return errors.New("short checkpoint observation")
	}
	select {} // no return/rollback; parent kills through its exact pidfd and Waits
}

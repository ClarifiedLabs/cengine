//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"errors"
	"unsafe"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// ext4Identity uses only a pinned inode; it never opens a handle or changes the
// ordinary session-local FUSE node, generation or ObjectID routing contract.
func ext4Identity(fd int) (a.Ext4ObjectV1, error) {
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return a.Ext4ObjectV1{}, err
	}
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		return a.Ext4ObjectV1{}, unix.EXDEV
	}
	st, err := stat(fd)
	if err != nil {
		return a.Ext4ObjectV1{}, err
	}
	handle, _, err := unix.NameToHandleAt(fd, "", unix.AT_EMPTY_PATH)
	if err != nil {
		return a.Ext4ObjectV1{}, err
	}
	return decodeExt4Identity(st.Ino, st.Mode, handle.Type(), handle.Bytes())
}

func backingUUID(fd int) ([16]byte, error) {
	// FS_IOC_GETFSUUID: _IOR(0x15, 0, struct fsuuid2), explicit UAPI bytes.
	var value [17]byte
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(0x80111500), uintptr(unsafe.Pointer(&value[0])))
	if errno != 0 {
		return [16]byte{}, errno
	}
	if value[0] != 16 {
		return [16]byte{}, unix.EOPNOTSUPP
	}
	var uuid [16]byte
	copy(uuid[:], value[1:])
	if uuid == ([16]byte{}) {
		return uuid, unix.EOPNOTSUPP
	}
	return uuid, nil
}

func (s *Session) copyRoot(guard *a.Guard) (a.CopyRootV1, error) {
	device, err := guard.CopyDeviceID()
	if err != nil {
		return a.CopyRootV1{}, err
	}
	expected, err := parseCopyDeviceUUID(device)
	if err != nil {
		return a.CopyRootV1{}, err
	}
	uuid, err := backingUUID(int(s.root.Fd()))
	if err != nil {
		return a.CopyRootV1{}, err
	}
	if uuid != expected {
		return a.CopyRootV1{}, unix.EXDEV
	}
	object, err := ext4Identity(int(s.root.Fd()))
	if err != nil {
		return a.CopyRootV1{}, err
	}
	return a.CopyRootV1{Store: s.binding.Store, Volume: s.binding.Volume, BackingUUID: uuid, Root: object}, nil
}

func copyPinAt(root int, path string, flags uint64) (int, error) {
	if !copyRelativePath(path) {
		return -1, unix.EINVAL
	}
	return unix.Openat2(root, path, &unix.OpenHow{Flags: flags | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
}

func copyIdentityAt(root int, path string) (identity a.Ext4ObjectV1, result error) {
	fd, err := copyPinAt(root, path, unix.O_PATH)
	if err != nil {
		return a.Ext4ObjectV1{}, err
	}
	defer func() { result = errors.Join(result, unix.Close(fd)) }()
	return ext4Identity(fd)
}

// prepareIntent authenticates the root grant and fences unrelated private
// actions while whole-intent DATA recovery is pending.
func (s *Session) prepareIntent(guard *a.Guard, request w.PrepareRequest) (w.PrepareReply, error) {
	if s.binding.Role != a.PrepareRole || s.binding.Mode != a.ReadWrite {
		return w.PrepareReply{}, unix.EPERM
	}
	handle, err := s.getHandle(request.Node, request.Handle, true, 1)
	if err != nil {
		return w.PrepareReply{}, err
	}
	rootStat, err := stat(int(s.root.Fd()))
	if err != nil {
		return w.PrepareReply{}, err
	}
	if err = same(handle.fd, inodeKey{s.binding.Volume, rootStat.Dev, rootStat.Ino}); err != nil {
		return w.PrepareReply{}, err
	}
	root, err := s.copyRoot(guard)
	if err != nil {
		return w.PrepareReply{}, err
	}
	reply := w.PrepareReply{Root: root}
	if request.Action != w.BeginCopy {
		reply.Intent, err = guard.InspectCopy(request.Intent, root)
		if err != nil {
			return w.PrepareReply{}, err
		}
		pending, err := guard.PendingCopyOperation(request.Intent)
		if err != nil {
			return w.PrepareReply{}, err
		}
		if (pending == a.CopyOperationRollback && request.Action != w.RollbackCopy) || (pending == a.CopyOperationDirectoryTail && request.Action != w.ResumeCopyDirectory) {
			return w.PrepareReply{}, a.ErrBlocked
		}
	}
	return reply, nil
}

// prepare executes under the namespace gate and exact live private guard.
func (s *Session) prepare(guard *a.Guard, request w.PrepareRequest) (w.ReplyBody, error) {
	reply, err := s.prepareIntent(guard, request)
	if err != nil {
		return nil, err
	}
	root := reply.Root
	switch request.Action {
	case w.BeginCopy:
		reply.Intent, err = guard.BeginCopy(root)
		if err == nil {
			var pending string
			pending, err = guard.PendingCopyOperation(reply.Intent.ID)
			if err == nil {
				switch pending {
				case "":
				case a.CopyOperationBegin:
					reply.Pending = w.BeginCopy
				case a.CopyOperationProvision:
					reply.Pending = w.BindCopyTransaction
				case a.CopyOperationSeal:
					reply.Pending = w.SealManifest
				case a.CopyOperationCleanup:
					reply.Pending = w.StartCleanup
				case a.CopyOperationFinish:
					reply.Pending = w.FinishCopy
				case a.CopyOperationRollback:
					reply.Pending = w.RollbackCopy
				case a.CopyOperationDirectoryTail:
					reply.Pending = w.ResumeCopyDirectory
				default:
					err = a.ErrRepairRequired
				}
			}
		}
	case w.IdentityAt:
		if len(request.Path) == 0 || string(request.Path) == "." {
			reply.Identity = root.Root
		} else {
			reply.Identity, err = copyIdentityAt(int(s.root.Fd()), string(request.Path))
		}
	case w.BindCopyTransaction:
		reply.Intent, err = guard.ProvisionCopyTransaction(request.Intent, ext4Identity)
		reply.Identity = reply.Intent.Transaction
	case w.SealManifest, w.AuthenticateManifest:
		reply.Intent, err = s.authenticateCopyManifest(guard, reply.Intent, request.Action == w.SealManifest)
		reply.Identity = reply.Intent.Transaction
	case w.StartCleanup:
		reply.Intent, err = s.startCopyCleanup(guard, reply.Intent)
	case w.FinishCopy:
		err = s.finishCopyCleanup(guard, reply.Intent)
		if err == nil {
			reply.Intent.Phase = a.CopyCompleted
		}
	default:
		err = unix.EINVAL
	}
	return reply, err
}

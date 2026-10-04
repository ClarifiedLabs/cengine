//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"bytes"
	"errors"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// copyDataShape is only a cheap closed-shape filter. No request operand grants
// recovery authority: copyDataRecovery subsequently checks the actual inode pins,
// exact live intent and complete authenticated undo domain under the namespace gate.
func copyDataShape(body w.RequestBody) bool {
	switch v := body.(type) {
	case w.RenameRequest:
		return v.Flags == w.RenameNoReplace && bytes.Equal(v.OldName, v.NewName)
	case w.SetAttrRequest:
		return v.Valid&w.SetSize == 0 && v.Semantics&w.MetadataOpen == 0
	case w.SetXAttrRequest, w.RemoveXAttrRequest, w.FsyncDirRequest, w.ReleaseDirRequest:
		return true
	}
	return false
}

func (s *Session) copyDataRecovery(guard *a.Guard, r w.Request) (string, a.CopyIntent, error) {
	ordinary := func() (string, a.CopyIntent, error) { return "", a.CopyIntent{}, nil }
	if s.binding.Role != a.PrepareRole || s.binding.Mode != a.ReadWrite || !copyDataShape(r.Body) {
		return ordinary()
	}
	device, err := guard.CopyDataDeviceID()
	if err == a.ErrUnauthorized { // no owned copy intent: ordinary DATA, not an exception
		return ordinary()
	}
	if err != nil {
		return "", a.CopyIntent{}, err
	}
	expected, err := parseCopyDeviceUUID(device)
	if err != nil {
		return ordinary() // non-managed legacy/test stores gain no recovery authority
	}
	uuid, err := backingUUID(int(s.root.Fd()))
	if err != nil {
		return "", a.CopyIntent{}, err
	}
	if uuid != expected {
		return "", a.CopyIntent{}, unix.EXDEV
	}
	object, err := ext4Identity(int(s.root.Fd()))
	if err != nil {
		return "", a.CopyIntent{}, err
	}
	root := a.CopyRootV1{Store: s.binding.Store, Volume: s.binding.Volume, BackingUUID: uuid, Root: object}
	intent, err := guard.CopyDataIntent(root)
	if err != nil {
		return "", a.CopyIntent{}, err
	}
	if intent.Phase != a.CopySealed && intent.Phase != a.CopyCleaning && intent.Phase != a.CopyCompleted {
		return ordinary()
	}

	action := a.CopyOperationRollback
	var nodeID w.NodeID
	var handleID *w.HandleID
	switch v := r.Body.(type) {
	case w.FsyncDirRequest:
		action, nodeID, handleID = a.CopyOperationDirectoryTail, v.Node, &v.Handle
	case w.ReleaseDirRequest:
		action, nodeID, handleID = a.CopyOperationDirectoryTail, v.Node, &v.Handle
	case w.RenameRequest:
		if intent.Phase != a.CopySealed {
			return ordinary()
		}
		old, err := s.parent(v.OldParent)
		if err != nil {
			if errors.Is(err, unix.ESTALE) || errors.Is(err, unix.ENOTDIR) {
				return ordinary() // preserve ordinary request errors without poisoning
			}
			return "", intent, err
		}
		next, err := s.parent(v.NewParent)
		if err != nil {
			if errors.Is(err, unix.ESTALE) || errors.Is(err, unix.ENOTDIR) {
				return ordinary()
			}
			return "", intent, err
		}
		parent, err := ext4Identity(next.fd)
		if err != nil {
			return "", intent, err
		}
		if parent != intent.Root.Root {
			return ordinary()
		}
		staging, err := copyIdentityAt(int(s.root.Fd()), copyTransactionPath+"/staging")
		if err != nil {
			return "", intent, err
		}
		parent, err = ext4Identity(old.fd)
		if err != nil {
			return "", intent, err
		}
		if parent != staging || staging.FileType != unix.S_IFDIR {
			return ordinary()
		}
		plan, err := planCopyRecovery(s.root, device, action, intent)
		if err != nil {
			return "", intent, err
		}
		source, err := copyIdentityAt(old.fd, string(v.OldName))
		if err != nil {
			return "", intent, err
		}
		if source != plan.expected[string(v.OldName)] {
			return "", intent, unix.ESTALE
		}
		if _, err = copyIdentityAt(next.fd, string(v.NewName)); !errors.Is(err, unix.ENOENT) {
			if err == nil {
				return ordinary() // preserve ordinary RENAME_NOREPLACE/EEXIST behavior
			}
			return "", intent, err
		}
		return action, intent, nil
	case w.SetAttrRequest:
		nodeID, handleID = v.Node, v.Handle
	case w.SetXAttrRequest:
		nodeID = v.Node
	case w.RemoveXAttrRequest:
		nodeID = v.Node
	}

	n, err := s.getNode(nodeID)
	if err != nil {
		return ordinary() // ordinary execution supplies its original ESTALE/EBADF
	}
	target, err := ext4Identity(n.fd)
	if err != nil {
		return "", intent, err
	}
	if action == a.CopyOperationRollback && (intent.Phase != a.CopySealed || target != intent.Root.Root) {
		return ordinary()
	}
	fd := n.fd
	if handleID != nil {
		h, err := s.getHandle(nodeID, *handleID, true, 1)
		if err != nil {
			return ordinary()
		}
		if h.flags&w.OpenAccessMask != w.OpenReadOnly {
			return ordinary()
		}
		fd = h.fd
	}
	target, err = ext4Identity(fd)
	if err != nil {
		return "", intent, err
	}
	if action == a.CopyOperationRollback {
		if intent.Phase != a.CopySealed || target != intent.Root.Root {
			return ordinary()
		}
	} else {
		if target.FileType != unix.S_IFDIR {
			return ordinary()
		}
		staging := intent.Cleanup.Staging
		if intent.Phase == a.CopySealed {
			staging, err = copyIdentityAt(int(s.root.Fd()), copyTransactionPath+"/staging")
			if err != nil && !errors.Is(err, unix.ENOENT) {
				return "", intent, err
			}
		}
		if target != intent.Root.Root && target != intent.Transaction && target != staging {
			return ordinary()
		}
	}
	// A qualified shape/target still needs the whole recovery preflight before
	// publishing the new obligation. No failed preflight degrades into recovery.
	if err = PreflightCopyRecovery(s.root, device, action, intent); err != nil {
		return "", intent, err
	}
	return action, intent, nil
}

func (s *Session) prepareCopyRecovery(guard *a.Guard, request w.PrepareRequest) (w.ReplyBody, []w.Event, error) {
	reply, err := s.prepareIntent(guard, request)
	if err != nil {
		return nil, nil, err
	}
	switch request.Action {
	case w.RollbackCopy:
		var events []w.Event
		reply.Intent, events, err = s.rollbackCopy(guard, reply.Intent)
		return reply, events, err
	case w.ResumeCopyDirectory:
		err = s.resumeCopyDirectory(guard, reply.Intent)
		return reply, []w.Event{}, err
	default:
		return nil, nil, unix.EINVAL
	}
}

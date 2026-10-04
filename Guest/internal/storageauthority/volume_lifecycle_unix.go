//go:build linux || darwin

package storageauthority

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// Lifecycle namespace IO holds mu from validation through terminal publication.
// All authority transactions/admission use the same mutex. Existing accepted
// work cannot overlap deletion: every A must already have a durable drain receipt,
// including completion of its resource barrier, and every PREPARE must be terminal.
// No callbacks or request-owned resources are waited on while holding this lock.
func (a *Authority) CreateVolume(p *ControllerPrincipal, req CreateVolumeRequest) (VolumeReceipt, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.control(p); err != nil {
		return VolumeReceipt{}, err
	}
	op, repeat, err := a.operation(req.Operation, "create-volume", req)
	if err != nil {
		return VolumeReceipt{}, err
	}
	if req.Store != a.s.Store.ID {
		return VolumeReceipt{}, ErrConflict
	}
	v := Volume{ID: req.Volume, Name: req.Name, Root: RootIdentity{Inode: 1}}
	if !volumeValid(v) {
		return VolumeReceipt{}, ErrInvalid
	}
	if repeat {
		life := a.s.VolumeLifecycles[req.Volume]
		if life.Create != req.Operation || life.CreatedRevision == 0 {
			return VolumeReceipt{}, ErrRepairRequired
		}
		return a.volumeReceipt(req.Volume, false), nil
	}
	if _, exists := a.s.Volumes[req.Volume]; exists {
		return VolumeReceipt{}, ErrConflict
	}
	if len(a.s.Volumes) >= a.limits.Volumes {
		return VolumeReceipt{}, ErrLimit
	}
	for id, old := range a.s.Volumes {
		if old.Name == req.Name && a.s.VolumeLifecycles[id].Phase != VolumeDeleted {
			return VolumeReceipt{}, ErrConflict
		}
	}
	if err = absent(a.j.exports, req.Name); err != nil {
		return VolumeReceipt{}, err
	}
	next := a.clone()
	v.Root = RootIdentity{}
	next.Volumes[v.ID] = v
	next.VolumeLifecycles[v.ID] = VolumeLifecycle{Phase: VolumeCreating, Create: req.Operation}
	next.Operations[req.Operation] = op
	if err = a.j.step("volume-create-before-intent", func() error { return nil }); err != nil {
		return VolumeReceipt{}, a.poison(err)
	}
	if err = a.commit(next); err != nil {
		return VolumeReceipt{}, err
	}
	if err = a.j.step("volume-create-intent", func() error { return nil }); err != nil {
		return VolumeReceipt{}, a.poison(err)
	}
	if err = a.j.step("volume-mkdir", func() error { return unix.Mkdirat(int(a.j.exports.Fd()), v.Name, 0700) }); err != nil {
		return VolumeReceipt{}, a.poison(err)
	}
	var root *os.File
	if err = a.j.step("volume-open", func() (e error) { root, e = volumeDirectory(a.j.exports, v.Name); return }); err != nil {
		return VolumeReceipt{}, a.poison(err)
	}
	defer func() {
		if root != nil {
			root.Close()
		}
	}()
	v.Root, err = identity(root)
	if err != nil {
		return VolumeReceipt{}, a.poison(err)
	}
	if v.Root.Device != a.s.Store.Root.Device {
		return VolumeReceipt{}, a.poison(ErrConflict)
	}
	// The exclusive mkdir starts private. Only this newly created, verified
	// data root gets Docker's public default, independent of the creator's umask.
	// The root-owned storage process supplies UID/GID 0:0; do not normalize
	// existing roots on replay, Open, or after workload/copy-up metadata changes.
	if err = a.j.step("volume-root-mode", func() error { return unix.Fchmod(int(root.Fd()), 0755) }); err != nil {
		return VolumeReceipt{}, a.poison(err)
	}
	if err = a.j.step("volume-root-sync", root.Sync); err != nil {
		return VolumeReceipt{}, a.poison(err)
	}
	if err = a.j.step("volume-create-parent-sync", a.j.exports.Sync); err != nil {
		return VolumeReceipt{}, a.poison(err)
	}
	next = a.clone()
	next.Volumes[v.ID] = v
	life := next.VolumeLifecycles[v.ID]
	life.Phase, life.CreatedRevision = VolumeReady, a.s.Revision+1
	next.VolumeLifecycles[v.ID] = life
	if err = a.commit(next); err != nil {
		return VolumeReceipt{}, a.retirementFailure(err)
	}
	a.roots[v.ID], root = root, nil
	if err = a.j.step("volume-create-published", func() error { return nil }); err != nil {
		return VolumeReceipt{}, a.poison(err)
	}
	return a.volumeReceipt(v.ID, false), nil
}

func (a *Authority) DeleteVolume(p *ControllerPrincipal, req DeleteVolumeRequest) (VolumeReceipt, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.control(p); err != nil {
		return VolumeReceipt{}, err
	}
	op, repeat, err := a.operation(req.Operation, "delete-volume", req)
	if err != nil {
		return VolumeReceipt{}, err
	}
	if req.Store != a.s.Store.ID {
		return VolumeReceipt{}, ErrConflict
	}
	if !validID(req.Volume) {
		return VolumeReceipt{}, ErrInvalid
	}
	v, ok := a.s.Volumes[req.Volume]
	if !ok {
		return VolumeReceipt{}, ErrUnknown
	}
	life := a.s.VolumeLifecycles[v.ID]
	if repeat {
		if life.Delete != req.Operation || life.Phase != VolumeDeleted {
			return VolumeReceipt{}, ErrRepairRequired
		}
		return a.volumeReceipt(v.ID, true), nil
	}
	if life.Phase != VolumeReady {
		return VolumeReceipt{}, ErrConflict
	}
	if reservedVolume(a.s, v.ID, "") {
		return VolumeReceipt{}, ErrBusy
	}
	for id, rec := range a.s.Attachments {
		if rec.Binding.Volume != v.ID {
			continue
		}
		rt := a.runtime[id]
		if rec.Phase != Drained || (rt != nil && rt.count != 0) {
			return VolumeReceipt{}, ErrBusy
		}
	}
	root := a.roots[v.ID]
	if root == nil {
		return VolumeReceipt{}, a.poison(ErrConflict)
	}
	if err = exactChild(a.j.exports, v.Name, v.Root); err != nil {
		return VolumeReceipt{}, a.poison(err)
	}
	next := a.clone()
	life.Phase, life.Delete = VolumeDeleting, req.Operation
	next.VolumeLifecycles[v.ID] = life
	next.Operations[req.Operation] = op
	if err = a.j.step("volume-delete-before-intent", func() error { return nil }); err != nil {
		return VolumeReceipt{}, a.poison(err)
	}
	if err = a.commit(next); err != nil {
		return VolumeReceipt{}, err
	}
	if err = a.j.step("volume-delete-intent", func() error { return nil }); err != nil {
		return VolumeReceipt{}, a.poison(err)
	}
	if err = a.j.removeContents(root, v.Root.Device); err != nil {
		return VolumeReceipt{}, a.poison(err)
	}
	if err = exactChild(a.j.exports, v.Name, v.Root); err != nil {
		return VolumeReceipt{}, a.poison(err)
	}
	if err = a.j.step("volume-rmdir", func() error { return unix.Unlinkat(int(a.j.exports.Fd()), v.Name, unix.AT_REMOVEDIR) }); err != nil {
		return VolumeReceipt{}, a.poison(err)
	}
	if err = a.j.step("volume-delete-parent-sync", a.j.exports.Sync); err != nil {
		return VolumeReceipt{}, a.poison(err)
	}
	if err = a.j.step("volume-root-close", root.Close); err != nil {
		return VolumeReceipt{}, a.poison(err)
	}
	delete(a.roots, v.ID)
	next = a.clone()
	life.Phase, life.DeletedRevision = VolumeDeleted, a.s.Revision+1
	next.VolumeLifecycles[v.ID] = life
	if err = a.commit(next); err != nil {
		return VolumeReceipt{}, a.retirementFailure(err)
	}
	if err = a.j.step("volume-delete-published", func() error { return nil }); err != nil {
		return VolumeReceipt{}, a.poison(err)
	}
	return a.volumeReceipt(v.ID, true), nil
}

func (a *Authority) volumeReceipt(id ID, deleted bool) VolumeReceipt {
	life := a.s.VolumeLifecycles[id]
	op, phase, rev := life.Create, VolumeReady, life.CreatedRevision
	if deleted {
		op, phase, rev = life.Delete, VolumeDeleted, life.DeletedRevision
	}
	return VolumeReceipt{SchemaVersion, op, a.s.Store.ID, a.s.Volumes[id], phase, rev}
}
func absent(dir *os.File, name string) error {
	var st unix.Stat_t
	err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	return ErrConflict
}
func exactChild(dir *os.File, name string, want RootIdentity) error {
	var st unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || (RootIdentity{uint64(st.Dev), uint64(st.Ino)}) != want {
		return ErrConflict
	}
	return nil
}
func (a *Authority) deletedRootAbsent(v Volume) error {
	for id, other := range a.s.Volumes {
		if id != v.ID && other.Name == v.Name && a.s.VolumeLifecycles[id].Phase != VolumeDeleted {
			return nil // Its own exact identity is checked by Open, never this tombstone.
		}
	}
	return absent(a.j.exports, v.Name)
}

// No path joins, symlink traversal, parent wipe, or external NFS deletion helper.
// The exclusively owned namespace has no live attachment to this V. Directory
// identity is rechecked before unlink; cross-device directories are rejected.
// Bounded directory batches avoid unbounded per-directory memory consumption.
func (j *journal) removeContents(dir *os.File, device uint64) error {
	// DupVolumeRoot duplicates the open file description, including its offset.
	// Every former owner has drained, so rewind both offset and Go readdir state.
	if err := j.step("volume-directory-rewind", func() error { _, e := dir.Seek(0, io.SeekStart); return e }); err != nil {
		return err
	}
	for {
		names, err := dir.Readdirnames(64)
		if err != nil && err != io.EOF {
			return err
		}
		for _, name := range names {
			var st unix.Stat_t
			if err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return err
			}
			flags := 0
			if st.Mode&unix.S_IFMT == unix.S_IFDIR {
				if uint64(st.Dev) != device {
					return ErrConflict
				}
				sub, err := volumeDirectory(dir, name)
				if err != nil {
					return err
				}
				want := RootIdentity{uint64(st.Dev), uint64(st.Ino)}
				got, e := identity(sub)
				if e == nil && got != want {
					e = ErrConflict
				}
				if e == nil {
					e = j.removeContents(sub, device)
				}
				ce := sub.Close()
				if e != nil {
					return e
				}
				if ce != nil {
					return ce
				}
				if e = exactChild(dir, name, want); e != nil {
					return e
				}
				flags = unix.AT_REMOVEDIR
			}
			if err := j.step("volume-unlink", func() error { return unix.Unlinkat(int(dir.Fd()), name, flags) }); err != nil {
				return err
			}
		}
		if err == io.EOF {
			break
		}
	}
	return j.step("volume-directory-sync", dir.Sync)
}

func (a *Authority) validateVolume(v Volume, life VolumeLifecycle) error {
	fail := func() error { return fmt.Errorf("%w: volume lifecycle", ErrInvalid) }
	if life.Create != "" {
		req := CreateVolumeRequest{life.Create, a.s.Store.ID, v.ID, v.Name}
		if !validID(life.Create) || a.s.Operations[life.Create] != digest("create-volume", req) {
			return fail()
		}
	} else if life.CreatedRevision != 0 {
		return fail()
	}
	if life.CreatedRevision > a.s.Revision || life.DeletedRevision > a.s.Revision {
		return fail()
	}
	switch life.Phase {
	case VolumeCreating:
		if life.Create == "" || life.CreatedRevision != 0 || v.Root != (RootIdentity{}) {
			return fail()
		}
	case VolumeReady, VolumeDeleting, VolumeDeleted:
		if life.Create != "" && life.CreatedRevision == 0 {
			return fail()
		}
	default:
		return fail()
	}
	if life.Phase == VolumeDeleting || life.Phase == VolumeDeleted {
		req := DeleteVolumeRequest{life.Delete, a.s.Store.ID, v.ID}
		if !validID(life.Delete) || a.s.Operations[life.Delete] != digest("delete-volume", req) {
			return fail()
		}
		if (life.Phase == VolumeDeleted) != (life.DeletedRevision != 0) || (life.DeletedRevision != 0 && life.DeletedRevision <= life.CreatedRevision) {
			return fail()
		}
	} else if life.Delete != "" || life.DeletedRevision != 0 {
		return fail()
	}
	return nil
}

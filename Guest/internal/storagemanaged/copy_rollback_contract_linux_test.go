//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"encoding/binary"
	"errors"
	"os"
	"reflect"
	"testing"

	c "dev.cengine/guest/internal/copycontract"
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// Pure plan tests need neither ext4 nor privileges. In particular a matching
// descendant under a replaced directory must not even be probed.
func TestCopyRollbackPrunesUnownedPublicAncestors(t *testing.T) {
	directory := a.Ext4ObjectV1{Inode: 10, FileType: unix.S_IFDIR}
	child := a.Ext4ObjectV1{Inode: 11, FileType: unix.S_IFREG}
	entries := []c.Entry{{Path: "a", Identity: directory}, {Path: "a/child", Identity: child}, {Path: "b", Identity: child}}
	for _, failure := range []error{nil, unix.ENOENT, unix.ENOTDIR, unix.ELOOP} {
		var probes []string
		matching, err := planCopyPublic(entries, func(relative string) (a.Ext4ObjectV1, error) {
			probes = append(probes, relative)
			if relative == "a" {
				return a.Ext4ObjectV1{Inode: 999, FileType: unix.S_IFDIR}, failure
			}
			return child, nil
		})
		if err != nil || matching["a"] || matching["a/child"] || !matching["b"] || !reflect.DeepEqual(probes, []string{"a", "b"}) {
			t.Fatalf("replacement %v: matching=%v probes=%v err=%v", failure, matching, probes, err)
		}
	}
}

// This calls the production planner, without nativeGuest, ext4 or privileges.
func TestCopyRollbackGenerationReplacementIsExcluded(t *testing.T) {
	original := a.Ext4ObjectV1{Inode: 10, Generation: 7, FileType: unix.S_IFREG, HandleType: 1, HandleSize: 8}
	binary.LittleEndian.PutUint32(original.Handle[:4], uint32(original.Inode))
	binary.LittleEndian.PutUint32(original.Handle[4:], original.Generation)
	replacement := original
	replacement.Generation++
	binary.LittleEndian.PutUint32(replacement.Handle[4:], replacement.Generation)
	entries := []c.Entry{{Path: "a", Identity: original}, {Path: "z", Identity: original}}
	var probes []string
	matching, err := planCopyPublic(entries, func(relative string) (a.Ext4ObjectV1, error) {
		probes = append(probes, relative)
		if relative == "z" {
			return replacement, nil
		}
		return original, nil
	})
	if err != nil || !reflect.DeepEqual(matching, map[string]bool{"a": true, "z": false}) || !reflect.DeepEqual(probes, []string{"a", "z"}) {
		t.Fatalf("same inode/type, different generation/handle: matching=%v probes=%v err=%v", matching, probes, err)
	}
}

func TestCopyRollbackLateUncertaintyDiscardsWholePublicPlan(t *testing.T) {
	identity := a.Ext4ObjectV1{Inode: 10, FileType: unix.S_IFREG}
	matching, err := planCopyPublic([]c.Entry{{Path: "a", Identity: identity}, {Path: "z", Identity: identity}}, func(relative string) (a.Ext4ObjectV1, error) {
		if relative == "z" {
			return a.Ext4ObjectV1{}, unix.EIO
		}
		return identity, nil
	})
	if !errors.Is(err, unix.EIO) || matching != nil {
		t.Fatalf("partial plan escaped: %v, %v", matching, err)
	}
}

func TestCopyRollbackXattrPreflightRejectsBeforeMutation(t *testing.T) {
	for _, tc := range []struct {
		name, state, names string
		failure            error
	}{
		{"supported-became-unsupported", "supported", "", unix.EOPNOTSUPP},
		{"unsupported-became-supported", "unsupported", "", nil},
		{"io-error", "supported", "", unix.EIO},
		{"duplicate", "supported", "user.a\x00user.a\x00", nil},
		{"unterminated", "supported", "user.a", nil},
		{"invalid-name", "supported", "user.\x00", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			operations := c.XattrOperations{List: func(_ int, buffer []byte) (int, error) {
				if len(buffer) != c.MaxXattrListBytes {
					t.Fatal("unbounded enumeration")
				}
				return copy(buffer, tc.names), tc.failure
			}, Set: func(int, string, []byte, int) error { t.Fatal("preflight wrote xattr"); return nil }, Remove: func(int, string) error { t.Fatal("preflight removed xattr"); return nil }}
			_, err := preflightCopyXattrsWith(-1, &c.XattrSnapshot{State: tc.state, Entries: []c.Xattr{}}, operations)
			if err == nil {
				t.Fatal("accepted uncertain xattrs")
			}
		})
	}
}

func TestCopyRollbackEventsUseRealRegistryIdentities(t *testing.T) {
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	st, err := stat(int(root.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	volume := a.ID("11111111-1111-4111-8111-111111111111")
	rootKey := inodeKey{volume, st.Dev, st.Ino}
	parentID := w.ObjectID{1}
	s := &Session{root: root, binding: a.Binding{Volume: volume}, registry: &Registry{objects: map[inodeKey]*object{rootKey: {key: rootKey, id: parentID}}, eventSequence: 9}}
	plan := copyRollbackPlan{manifest: c.Manifest{Entries: []c.Entry{{Path: "unknown-child", Identity: a.Ext4ObjectV1{Inode: st.Ino + 1}}}}}
	events, err := s.copyRollbackEvents(plan)
	if err != nil || len(events) != 3 {
		t.Fatalf("events=%v err=%v", events, err)
	}
	if s.registry.eventSequence != 9 {
		t.Fatal("helper allocated event sequence")
	}
	for _, event := range events {
		if event.EventSequence != 0 || event.Object != parentID {
			t.Fatal("invented identity or sequence", event)
		}
		event.EventSequence = 10
		if err := event.Validate(); err != nil {
			t.Fatal(err)
		}
		if event.Kind == w.InvalidateEntry && (event.Parent != parentID || string(event.Name) != "unknown-child") {
			t.Fatal("wrong dentry target", event)
		}
	}
	s.registry.eventSequence = ^uint64(0) - 1
	if _, err := s.copyRollbackEvents(plan); !errors.Is(err, unix.EOVERFLOW) {
		t.Fatal("event overflow was not preflighted", err)
	}
}

func TestCopyRollbackRejectsWrongActionAndPhaseBeforeRootInspection(t *testing.T) {
	for _, tc := range []struct{ action, phase string }{
		{a.CopyOperationRollback, a.CopyBound},
		{a.CopyOperationRollback, a.CopyCompleted},
		{a.CopyOperationDirectoryTail, a.CopyBegun},
		{a.CopyOperationSeal, a.CopySealed},
	} {
		if err := PreflightCopyRecovery(nil, "", tc.action, a.CopyIntent{Phase: tc.phase}); !errors.Is(err, unix.EINVAL) {
			t.Fatalf("action=%s phase=%s: %v", tc.action, tc.phase, err)
		}
	}
}

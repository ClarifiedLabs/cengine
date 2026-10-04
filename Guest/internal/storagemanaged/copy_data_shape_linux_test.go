//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

func TestCopyDataShapeIsOnlyNarrowCandidateFilter(t *testing.T) {
	for _, body := range []w.RequestBody{
		w.RenameRequest{OldName: []byte("z"), NewName: []byte("z"), Flags: w.RenameNoReplace},
		w.SetAttrRequest{Valid: w.SetMode | w.SetUID | w.SetGID | w.SetATime | w.SetMTime, Semantics: w.MetadataValid},
		w.SetXAttrRequest{}, w.RemoveXAttrRequest{}, w.FsyncDirRequest{}, w.ReleaseDirRequest{},
	} {
		if !copyDataShape(body) {
			t.Fatalf("excluded candidate %T", body)
		}
		for _, binding := range []a.Binding{{Role: a.RuntimeRole, Mode: a.ReadWrite}, {Role: a.PrepareRole, Mode: a.ReadOnly}} {
			// Ineligible callers never inspect even a descriptor or live intent.
			s := &Session{binding: binding}
			action, intent, err := s.copyDataRecovery(nil, w.Request{Body: body})
			if action != "" || intent != (a.CopyIntent{}) || err != nil {
				t.Fatal(binding, action, intent, err)
			}
		}
	}
	for _, body := range []w.RequestBody{
		w.RenameRequest{OldName: []byte("a"), NewName: []byte("b"), Flags: w.RenameNoReplace},
		w.RenameRequest{OldName: []byte("a"), NewName: []byte("a")},
		w.RenameRequest{OldName: []byte("a"), NewName: []byte("a"), Flags: w.RenameExchange},
		w.SetAttrRequest{Valid: w.SetSize, Semantics: w.MetadataValid},
		w.SetAttrRequest{Semantics: w.MetadataValid | w.MetadataOpen},
		w.WriteRequest{}, w.FallocateRequest{}, w.CreateRequest{}, w.UnlinkRequest{}, w.RmdirRequest{},
		w.FsyncRequest{}, w.FlushRequest{}, w.ReleaseRequest{}, w.ReadRequest{}, w.OpenRequest{},
	} {
		if copyDataShape(body) {
			t.Fatalf("broadened recovery to %T: %#v", body, body)
		}
		s := &Session{binding: a.Binding{Role: a.PrepareRole, Mode: a.ReadWrite}}
		action, intent, err := s.copyDataRecovery(nil, w.Request{Body: body})
		if action != "" || intent != (a.CopyIntent{}) || err != nil {
			t.Fatal(action, intent, err)
		}
	}
}

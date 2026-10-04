package storagemanaged

import (
	w "dev.cengine/guest/internal/storagewire"
	"testing"
)

func TestDurabilityPolicyDoesNotJournalReadsButCoversROBarriers(t *testing.T) {
	for _, body := range []w.RequestBody{w.ReadRequest{}, w.GetAttrRequest{}, w.ReadDirRequest{}, w.LookupRequest{}, w.ReadlinkRequest{}, w.GetXAttrRequest{}, w.ListXAttrRequest{}} {
		if needsDurability(w.Request{Body: body}) {
			t.Fatalf("read acquired durability obligation: %T", body)
		}
	}
	for _, body := range []w.RequestBody{w.WriteRequest{}, w.SetAttrRequest{}, w.MkdirRequest{}, w.RenameRequest{}, w.UnlinkRequest{}, w.SetXAttrRequest{}, w.RemoveXAttrRequest{}, w.FallocateRequest{}, w.CreateRequest{}, w.FlushRequest{}, w.FsyncRequest{}, w.FsyncDirRequest{}, w.ReleaseRequest{}, w.ReleaseDirRequest{}} {
		if !needsDurability(w.Request{Body: body}) {
			t.Fatalf("missing durability obligation: %T", body)
		}
	}
}

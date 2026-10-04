package storagefuse

import (
	"context"
	"errors"
	"github.com/hanwen/go-fuse/v2/fuse"
	"testing"
)

func openDirectoryReply(unique uint64) fuse.ReplyDelivery {
	return fuse.ReplyDelivery{Unique: unique, Opcode: 27, Bytes: 32, Expected: 32}
}
func TestDirectorySealJoinsAdmittedOpenAndRejectsLateGrant(t *testing.T) {
	d := directoryReleases{limit: 4}
	if err := d.beginOpen(1); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		releases []*directoryRelease
		err      error
	}
	result := make(chan outcome, 1)
	go func() { r, e := d.sealAndSnapshot(ctx, nil); result <- outcome{r, e} }()
	for {
		d.mu.Lock()
		sealed, changed := d.sealed, d.changed
		d.mu.Unlock()
		if sealed {
			break
		}
		<-changed
	}
	if err := d.beginOpen(2); !errors.Is(err, errDirectoryAdmissionClosed) {
		t.Fatal("late grant admitted", err)
	}
	if err := d.returnedOpen(1, 8, fuse.OK); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-result:
		t.Fatal("snapshot overtook OPENDIR delivery", got)
	default:
	}
	if err := d.deliveredOpen(openDirectoryReply(1)); err != nil {
		t.Fatal(err)
	}
	got := <-result
	if got.err != nil || len(got.releases) != 1 || got.releases[0].fh != 8 {
		t.Fatal(got)
	}
	if err := d.releasing(3, 8); err != nil {
		t.Fatal("seal blocked cleanup", err)
	}
	if err := d.returned(3); err != nil {
		t.Fatal(err)
	}
	if err := d.delivered(releaseReply(3), false); err != nil {
		t.Fatal(err)
	}
	if err := waitDirectoryReleases(ctx, got.releases, nil); err != nil {
		t.Fatal(err)
	}
}
func TestSealedOpenDirDoesNotCaptureOrCallClient(t *testing.T) {
	raw, client := fixture()
	fs := &lifecycleFS{rawFS: raw, life: new(mountLifecycle), directories: directoryReleases{limit: 2}}
	if _, err := fs.directories.sealAndSnapshot(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	out := fuse.OpenOut{Fh: 999}
	if s := fs.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: 7, NodeId: 1}}, &out); s != fuse.EBUSY || out.Fh != 0 {
		t.Fatal(s, out.Fh)
	}
	if len(client.captured) != 0 || client.body != nil || client.aborted != 0 {
		t.Fatal("sealed open affected client")
	}
}
func TestCompletedOwnerCannotAbortOnSimultaneousCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	close(done)
	for i := 0; i < 1000; i++ {
		err := waitGraceful(ctx, done, func() error { return nil }, func(error) { t.Fatal("aborted committed completion") }, true)
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
}

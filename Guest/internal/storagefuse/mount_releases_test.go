package storagefuse

import (
	"context"
	"errors"
	"io"
	"testing"

	c "dev.cengine/guest/internal/storageclient"
	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
)

func releaseReply(unique uint64) fuse.ReplyDelivery {
	return fuse.ReplyDelivery{Unique: unique, Opcode: 29, Status: fuse.OK, Bytes: 16, Expected: 16}
}

type delayedDirectoryClient struct {
	client
	entered, proceed chan struct{}
}

func (d *delayedDirectoryClient) Do(cred credential, auth w.AuthKind, body w.RequestBody) (c.Result, error) {
	if _, ok := body.(w.ReleaseDirRequest); ok {
		close(d.entered)
		<-d.proceed
	}
	return d.client.Do(cred, auth, body)
}

func TestDirectoryReleaseJoinsRunningCallbackBeforeDelivery(t *testing.T) {
	raw, original := fixture()
	original.result = &c.Result{Handle: 8}
	gate := &delayedDirectoryClient{client: original, entered: make(chan struct{}), proceed: make(chan struct{})}
	raw.client = gate
	fs := &lifecycleFS{rawFS: raw, life: new(mountLifecycle), directories: directoryReleases{limit: 2}}
	var out fuse.OpenOut
	if status := fs.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{NodeId: 1, Unique: 50}, Flags: 0x4000}, &out); status != fuse.OK {
		t.Fatal(status)
	}
	releases, err := fs.directories.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	original.state = none
	callbackDone := make(chan struct{})
	go func() {
		defer close(callbackDone)
		fs.ReleaseDir(&fuse.ReleaseIn{InHeader: fuse.InHeader{NodeId: 1, Unique: 51}, Fh: out.Fh})
	}()
	<-gate.entered
	select {
	case <-releases[0].done:
		t.Fatal("joined an active callback")
	default:
	}
	close(gate.proceed)
	<-callbackDone
	select {
	case <-releases[0].done:
		t.Fatal("callback was confused with response delivery")
	default:
	}
	fs.observeReply(releaseReply(51))
	if err := waitDirectoryReleases(context.Background(), releases, nil); err != nil {
		t.Fatal(err)
	}
}

func TestDirectoryReleaseWaitsForCallbackAndLateNativeDelivery(t *testing.T) {
	raw, client := fixture()
	client.result = &c.Result{Handle: 8}
	fs := &lifecycleFS{rawFS: raw, life: new(mountLifecycle), directories: directoryReleases{limit: 2}}
	in := fuse.OpenIn{InHeader: fuse.InHeader{NodeId: 1, Unique: 41}, Flags: 0x4000}
	var out fuse.OpenOut
	if status := fs.OpenDir(nil, &in, &out); status != fuse.OK {
		t.Fatal(status)
	}
	releases, err := fs.directories.snapshot()
	if err != nil || len(releases) != 1 || out.Fh != 8 {
		t.Fatal(releases, out.Fh, err)
	}
	client.state = none
	// The real callback boundary returns, but the native send observer has not
	// yet reported the captured request's reply. Do not confuse these boundaries.
	fs.ReleaseDir(&fuse.ReleaseIn{InHeader: fuse.InHeader{NodeId: 1, Unique: 42}, Fh: out.Fh})
	if !releases[0].callbackReturned {
		t.Fatal("callback did not run")
	}
	select {
	case <-releases[0].done:
		t.Fatal("callback return manufactured delivery")
	default:
	}
	result := make(chan error, 1)
	go func() { result <- waitDirectoryReleases(context.Background(), releases, nil) }()
	select {
	case err := <-result:
		t.Fatal("passed unmount boundary before native delivery", err)
	default:
	}
	fs.observeReply(releaseReply(42))
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if client.aborted != 0 || len(client.captured) != 2 || client.captured[1] != 42 {
		t.Fatal("synthetic or failed release", client)
	}
	if fs.directories.completed != 1 || len(fs.directories.handles) != 0 || len(fs.directories.requests) != 0 {
		t.Fatal("release credit retained")
	}
}

func TestDirectoryDeliveryRejectsMissingCallbackAndUnknownOutcomes(t *testing.T) {
	for _, kind := range []string{"before-callback", "unknown-unique", "wrong-op", "short", "error", "status", "suppressed", "interrupted-lost", "stopped", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			d := directoryReleases{limit: 1}
			if err := d.opened(7); err != nil {
				t.Fatal(err)
			}
			if err := d.releasing(81, 7); err != nil {
				t.Fatal(err)
			}
			if kind != "before-callback" {
				if err := d.returned(81); err != nil {
					t.Fatal(err)
				}
			}
			r := releaseReply(81)
			switch kind {
			case "unknown-unique":
				r.Unique++
			case "wrong-op":
				r.Opcode = 18
			case "short":
				r.Bytes--
			case "error":
				r.Err = io.ErrUnexpectedEOF
			case "status":
				r.Status = fuse.EIO
			case "suppressed":
				r.Suppressed = true
			case "interrupted-lost":
				r.Interrupted = true
				r.Bytes = -1
				r.Err = io.ErrUnexpectedEOF
			case "duplicate":
				if err := d.delivered(r, false); err != nil {
					t.Fatal(err)
				}
			}
			if err := d.delivered(r, kind == "stopped"); err == nil {
				t.Fatal("accepted unknown completion")
			}
			if _, err := d.snapshot(); err == nil {
				t.Fatal("failure was not sticky")
			}
		})
	}
}

func TestDirectoryReleaseCapacityCancellationAndTerminal(t *testing.T) {
	d := directoryReleases{limit: 1}
	if err := d.opened(9); err != nil {
		t.Fatal(err)
	}
	releases, _ := d.snapshot()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitDirectoryReleases(ctx, releases, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	terminal := make(chan struct{})
	close(terminal)
	if err := waitDirectoryReleases(context.Background(), releases, terminal); !errors.Is(err, c.ErrClosed) {
		t.Fatal(err)
	}
	if err := d.opened(10); !errors.Is(err, c.ErrCapacity) {
		t.Fatal(err)
	}
	if err := waitDirectoryReleases(context.Background(), releases, nil); !errors.Is(err, c.ErrCapacity) {
		t.Fatal(err)
	}
	if len(d.handles) != 1 {
		t.Fatal("unbounded grants")
	}
}

func TestDirectoryReleaseCreditsReusedOnlyAfterDelivery(t *testing.T) {
	d := directoryReleases{limit: 1}
	for id := uint64(1); id < 20; id++ {
		if err := d.opened(id); err != nil {
			t.Fatal(err)
		}
		if err := d.releasing(id+100, id); err != nil {
			t.Fatal(err)
		}
		if err := d.returned(id + 100); err != nil {
			t.Fatal(err)
		}
		if err := d.delivered(releaseReply(id+100), false); err != nil {
			t.Fatal(err)
		}
	}
	if len(d.handles) != 0 || len(d.requests) != 0 || d.completed != 19 {
		t.Fatal("leaked bookkeeping")
	}
}

func TestSecondaryGracefulTimeoutDoesNotCancelOwningAttempt(t *testing.T) {
	done := make(chan struct{})
	abortCalls := 0
	abort := func(error) { abortCalls++ }
	result := func() error { return nil }
	secondary, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitGraceful(secondary, done, result, abort, false); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if abortCalls != 0 {
		t.Fatal("secondary waiter aborted owner")
	}
	close(done)
	if err := waitGraceful(context.Background(), done, result, abort, true); err != nil {
		t.Fatal("owner could not complete", err)
	}
	owner, cancelOwner := context.WithCancel(context.Background())
	cancelOwner()
	if err := waitGraceful(owner, make(chan struct{}), result, abort, true); !errors.Is(err, context.Canceled) || abortCalls != 1 {
		t.Fatal("owner cancellation lost", err, abortCalls)
	}
}

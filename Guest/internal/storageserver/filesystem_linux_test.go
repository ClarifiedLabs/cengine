//go:build linux && (amd64 || arm64)

package storageserver

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// This test uses real TLS, authority, managed dispatch, identity workers and ext4.
// Native protocol tests use an internal executor seam, never an auth bypass.
func TestRealExt4TransportCreateWriteReadAndBarrier(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires Linux root and storageidentity capabilities")
	}
	var fs unix.Statfs_t
	must(t, unix.Statfs(t.TempDir(), &fs))
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		t.Fatal("TMPDIR must be on real ext4")
	}
	f := newFixture(t, Limits{}, true)
	c, done, b := f.connected()
	t.Cleanup(func() {
		c.NetConn().Close()
		wait(t, done)
		_, err := f.a.Retire(context.Background(), f.control, a.RetireRequest{Operation: id(t), Store: b.Store, Volume: b.Volume, Attachment: b.Attachment, Launch: b.Launch})
		must(t, err)
	})
	auth := w.Auth{Kind: w.CallerAuth, Caller: &w.Caller{FSUID: 0, FSGID: 0, Groups: []uint32{}}}
	var seq uint64
	call := func(body w.RequestBody) w.Reply {
		seq++
		r := w.Request{Sequence: seq, Auth: auth, Body: body}
		must(t, w.WriteFrame(c, &r))
		for {
			message := readMessage(t, c)
			if reply, ok := message.(*w.Reply); ok {
				must(t, w.ValidateReplyFor(r, *reply))
				if reply.Errno != 0 {
					t.Fatalf("%s errno=%d", body.Operation(), reply.Errno)
				}
				return *reply
			}
		}
	}
	created := call(w.CreateRequest{Parent: 1, Name: []byte("file"), Flags: w.OpenCreate | w.OpenReadWrite, Mode: 0600}).Body.(w.CreateReply)
	node, handle := created.Entry.Node, created.Opened.Handle
	call(w.WriteRequest{Node: node, Handle: handle, Data: []byte("actual ext4")})
	read := call(w.ReadRequest{Node: node, Handle: handle, Size: 64}).Body.(w.ReadReply)
	if string(read.Data) != "actual ext4" {
		t.Fatalf("data=%q", read.Data)
	}
	call(w.FsyncRequest{Node: node, Handle: handle})
	auth = w.Auth{Kind: w.LifecycleAuth}
	call(w.ReleaseRequest{Node: node, Handle: handle})
	call(w.ForgetRequest{Entries: []w.ForgetEntry{{Node: node, Count: 1}}})
}

func TestRealExt4TimedOutFactoryRetiresOnlyItsRegisteredSession(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires Linux root and storageidentity capabilities")
	}
	var fs unix.Statfs_t
	must(t, unix.Statfs(t.TempDir(), &fs))
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		t.Fatal("TMPDIR must be on real ext4")
	}
	limits := DefaultLimits()
	limits.HandshakeTimeout = time.Second
	f := newFixture(t, limits, true)
	b, k := f.binding()
	// Capture only descriptor ownership of this actual volume root. A second
	// same-volume session remains live to prove exact-attachment cleanup.
	volumePath, err := filepath.EvalSymlinks(filepath.Join(f.path, "volumes", "data"))
	must(t, err)
	countRoots := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		must(t, err)
		count := 0
		for _, entry := range entries {
			target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
			if err == nil && target == volumePath {
				count++
			}
		}
		return count
	}
	original := f.s.factory
	registered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	f.s.factory = func(g *a.Guard, p *a.DataPrincipal, binding a.Binding) (executor, w.Entry, error) {
		session, root, err := original(g, p, binding)
		if err != nil {
			return nil, w.Entry{}, err
		}
		if binding == b {
			close(registered)
			<-release
		}
		return session, root, nil
	}
	callbackDone := make(chan error, 1)
	operation := id(t)
	f.s.config.RequestRetirement = func(h a.DataHello, _ error) {
		if h.Binding != b {
			return
		}
		f.retired <- h
		_, err := f.a.Retire(context.Background(), f.control, a.RetireRequest{Operation: operation, Store: b.Store, Volume: b.Volume, Attachment: b.Attachment, Launch: b.Launch})
		callbackDone <- err
	}
	healthy, healthyDone, healthyBinding := f.connected()
	t.Cleanup(func() {
		healthy.NetConn().Close()
		wait(t, healthyDone)
		_, err := f.a.Retire(context.Background(), f.control, a.RetireRequest{Operation: id(t), Store: healthyBinding.Store, Volume: healthyBinding.Volume, Attachment: healthyBinding.Attachment, Launch: healthyBinding.Launch})
		must(t, err)
	})
	baseline := countRoots()
	client, done := f.start(b, k)
	defer client.NetConn().Close()
	select {
	case <-registered:
	case <-time.After(5 * time.Second):
		t.Fatal("managed factory did not register")
	}
	if countRoots() <= baseline {
		t.Fatal("managed setup did not retain its admitted root")
	}
	if h := retired(t, f.retired); h.Binding != b {
		t.Fatal(h)
	}
	select {
	case err := <-callbackDone:
		t.Fatalf("drain did not join setup guard: %v", err)
	default:
	}
	releaseOnce.Do(func() { close(release) })
	if err := wait(t, done); err == nil {
		t.Fatal("timed out setup succeeded")
	}
	must(t, wait(t, callbackDone))
	if got := countRoots(); got != baseline {
		t.Fatalf("registered session descriptor leak or unrelated cleanup: got %d want %d", got, baseline)
	}
	snapshot, err := f.a.Query(f.control)
	must(t, err)
	if snapshot.Attachments[b.Attachment].Phase != a.Drained || snapshot.Attachments[healthyBinding.Attachment].Phase != a.Active {
		t.Fatal("wrong retirement binding")
	}
	r := request(1)
	must(t, w.WriteFrame(healthy, &r))
	reply := readMessage(t, healthy).(*w.Reply)
	must(t, w.ValidateReplyFor(r, *reply))
	if reply.Errno != 0 {
		t.Fatal(reply)
	}
}

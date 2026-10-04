//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	"dev.cengine/guest/internal/storageidentity"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// This is a real Linux/ext4 Session.New + OpenDir + PREPARE bootstrap test.
// No platform body, handle, worker, UUID or inode identity is substituted. It
// requires the same explicit Linux root/ext4 environment as the managed suite.
func copyBootstrapSession(t *testing.T, path string) *copyObligationHost {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	copyHostMust(t, err)
	defer unix.Close(fd)
	uuid, err := backingUUID(fd)
	copyHostMust(t, err)
	device := fmt.Sprintf("%x-%x-%x-%x-%x", uuid[:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
	h := newCopyObligationHost(t, path, device)
	old := h.session
	session, root, err := New(h.guard, old.principal, old.binding, old.registry.gate, new(storageidentity.Worker), old.registry)
	copyHostMust(t, err)
	if root.Node != 1 || len(session.handles) != 0 {
		t.Fatal("new session did not start with only its root grant")
	}
	h.session = session
	h.root, err = session.copyRoot(h.guard)
	copyHostMust(t, err)
	t.Cleanup(func() { copyHostMust(t, session.registry.Barrier(session.binding, old.root)) })
	return h
}

func copyBootstrapDispatch(t *testing.T, h *copyObligationHost, sequence uint64, body w.RequestBody) Result {
	t.Helper()
	result, err := h.session.Dispatch(h.guard, w.Request{Sequence: sequence, Auth: w.Auth{Kind: w.CallerAuth, Caller: &w.Caller{Groups: []uint32{}}}, Body: body})
	copyHostMust(t, err)
	return result
}

func TestCopyBootstrapCrashWorker(t *testing.T) {
	path := os.Getenv("CENGINE_COPY_BOOTSTRAP_ROOT")
	if path == "" {
		return
	}
	h := copyBootstrapSession(t, path)
	opened := copyBootstrapDispatch(t, h, 1, w.OpenDirRequest{Node: 1})
	if opened.Reply.Errno != 0 {
		t.Fatal(opened)
	}
	handle := opened.Reply.Body.(w.OpenDirReply).Opened.Handle
	begun := copyBootstrapDispatch(t, h, 2, w.PrepareRequest{Node: 1, Handle: handle, Action: w.BeginCopy})
	if begun.Reply.Errno != 0 {
		t.Fatal(begun)
	}
	intent := begun.Reply.Body.(w.PrepareReply).Intent
	h.session.registry.prepareOperation = func(g *a.Guard, request w.PrepareRequest) (w.ReplyBody, error) {
		_, err := h.session.prepare(g, request)
		copyHostMust(t, err)
		// Exit after the real private provision commit and before Dispatch clears
		// its pre-syscall marker or publishes the reply. No defers/drains run.
		os.Exit(73)
		return nil, nil
	}
	copyBootstrapDispatch(t, h, 3, w.PrepareRequest{Node: 1, Handle: handle, Action: w.BindCopyTransaction, Intent: intent.ID})
	t.Fatal("crash boundary was not reached")
}

func TestCopyPendingReplayFreshSessionRootBootstrap(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires Linux root with storageidentity setup capabilities")
	}
	path := t.TempDir()
	var fs unix.Statfs_t
	copyHostMust(t, unix.Statfs(path, &fs))
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		t.Fatal("TMPDIR must be real ext4")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCopyBootstrapCrashWorker$", "-test.count=1")
	cmd.Env = append(os.Environ(), "CENGINE_COPY_BOOTSTRAP_ROOT="+path, "GORACE=atexit_sleep_ms=0")
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 73 {
		t.Fatalf("crash worker: %v\n%s", err, output)
	}

	// Reopen the actual authority; retire the dead predecessor and explicitly
	// ReplacePrepare before constructing this fresh session and root handle.
	h := copyBootstrapSession(t, path)
	if !errors.Is(h.guard.CheckCopyReplay(), a.ErrBlocked) {
		t.Fatal("lost pending replay fence")
	}
	before, err := stat(int(h.session.root.Fd()))
	copyHostMust(t, err)
	attributes := copyBootstrapDispatch(t, h, 1, w.GetAttrRequest{Node: 1})
	if attributes.Reply.Errno != 0 {
		t.Fatalf("root permission bootstrap blocked by pending replay: %+v", attributes)
	}
	opened := copyBootstrapDispatch(t, h, 2, w.OpenDirRequest{Node: 1, Flags: w.OpenDirectory | w.OpenNoFollow | w.OpenCloseOnExec})
	if opened.Reply.Errno != 0 {
		t.Fatalf("root bootstrap blocked by pending replay: %+v", opened)
	}
	handle := opened.Reply.Body.(w.OpenDirReply).Opened.Handle
	if handle == 0 {
		t.Fatal("root bootstrap returned no real handle")
	}
	for index, body := range []w.RequestBody{
		w.ReadDirRequest{Node: 1, Handle: handle, MaxBytes: 4096},
		w.LookupRequest{Parent: 1, Name: []byte(".cengine-copyup-transaction")},
		w.MkdirRequest{Parent: 1, Name: []byte("forbidden"), Mode: 0700},
	} {
		result := copyBootstrapDispatch(t, h, uint64(index+3), body)
		if result.Reply.Errno != uint32(unix.EBUSY) {
			t.Fatalf("pending replay allowed ordinary DATA: %+v", result)
		}
	}
	after, err := stat(int(h.session.root.Fd()))
	copyHostMust(t, err)
	if before.Atim != after.Atim || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		t.Fatal("bootstrap or blocked DATA changed root timestamps")
	}
	begun := copyBootstrapDispatch(t, h, 6, w.PrepareRequest{Node: 1, Handle: handle, Action: w.BeginCopy})
	if begun.Reply.Errno != 0 {
		t.Fatalf("fresh root handle failed actual PREPARE: %+v", begun)
	}
	intent := begun.Reply.Body.(w.PrepareReply).Intent
	if intent.Phase != a.CopyBound || intent.Root != h.root {
		t.Fatal("recovery adopted wrong intent or physical root")
	}
	// A different handle cannot piggyback on the allowed root bootstrap.
	bad := copyBootstrapDispatch(t, h, 7, w.PrepareRequest{Node: 1, Handle: handle + 1, Action: w.IdentityAt, Intent: intent.ID})
	if bad.Reply.Errno != uint32(unix.EBADF) {
		t.Fatalf("ungranted root handle accepted: %+v", bad)
	}
	bound := copyBootstrapDispatch(t, h, 8, w.PrepareRequest{Node: 1, Handle: handle, Action: w.BindCopyTransaction, Intent: intent.ID})
	if bound.Reply.Errno != 0 {
		t.Fatalf("exact replay failed: %+v", bound)
	}
	copyHostMust(t, h.guard.CheckCopyReplay())
	result := copyBootstrapDispatch(t, h, 9, w.ReadDirRequest{Node: 1, Handle: handle, MaxBytes: 4096})
	if result.Reply.Errno != 0 {
		t.Fatalf("successful replay did not release owner DATA: %+v", result)
	}
}

package storagefuse

import (
	"golang.org/x/sys/unix"
	"sync"
	"testing"

	c "dev.cengine/guest/internal/storageclient"
	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// Every local prepare-gate EACCES path records its closed origin; a storage
// DATA reply errno EACCES records the storage origin. Recording never changes
// the returned status, and the vocabulary stays closed.
func TestPrepareDenialOrigins(t *testing.T) {
	newGate := func(t *testing.T) (*rawFS, *fakeClient, *testPrepareProcess) {
		t.Helper()
		f, fc := fixture()
		owner := testProcess()
		f.prepare = testMountProcess(t, owner, false)
		return f, fc, owner
	}

	t.Run("gate-process", func(t *testing.T) {
		f, fc, _ := newGate(t)
		fc.state = present
		if s := gateCall(f, 1001, beginProcess()); s != fuse.EACCES {
			t.Fatal("foreign TID must be denied", s)
		}
		origin, count := f.denials.diagnostic()
		if origin != "gate-process" || count != 1 {
			t.Fatal(origin, count)
		}
	})

	t.Run("gate-credential", func(t *testing.T) {
		f, fc, _ := newGate(t)
		fc.state = none
		h := header()
		h.Pid = 999
		_, s := f.call(&h, w.OpenGrantAuth, func() w.RequestBody { return w.GetAttrRequest{Node: 101} })
		if s != fuse.EACCES {
			t.Fatal("NONE non-flush request must be denied", s)
		}
		origin, count := f.denials.diagnostic()
		if origin != "gate-credential" || count != 1 {
			t.Fatal(origin, count)
		}
	})

	t.Run("gate-order", func(t *testing.T) {
		f, fc, _ := newGate(t)
		fc.state = present
		// Owned TID and present credential, but a PREPARE action before Begin.
		if s := gateCall(f, 999, w.PrepareRequest{Node: 101, Handle: 808, Action: w.SealManifest}); s != fuse.EACCES {
			t.Fatal("pre-begun non-Begin PREPARE action must be denied", s)
		}
		origin, count := f.denials.diagnostic()
		if origin != "gate-order" || count != 1 {
			t.Fatal(origin, count)
		}
	})

	t.Run("gate-flush", func(t *testing.T) {
		f, fc, _ := newGate(t)
		f.prepare.begun = true
		fc.state = none
		h := header()
		h.Pid = 999
		h.Opcode = 25 // fuse_flush
		_, s := f.call(&h, w.OpenGrantAuth, func() w.RequestBody { return w.GetAttrRequest{Node: 101} })
		if s != fuse.EACCES {
			t.Fatal("forced-flush credential reuse on non-flush body must be denied", s)
		}
		origin, count := f.denials.diagnostic()
		if origin != "gate-flush" || count != 1 {
			t.Fatal(origin, count)
		}
	})

	t.Run("storage", func(t *testing.T) {
		f, fc, _ := newGate(t)
		fc.state = present
		fc.result = &c.Result{Reply: w.Reply{Sequence: 1, Op: w.OpGetAttr, Errno: 0}}
		if s := gateCall(f, 999, beginProcess()); s != fuse.OK {
			t.Fatal("owned BeginCopy must pass the gate", s)
		}
		if !f.prepare.begun {
			t.Fatal("gate did not begin")
		}
		fc.result = nil // default fake reply carries errno EACCES
		if s := gateCall(f, 999, w.GetAttrRequest{Node: 101}); s != fuse.EACCES {
			t.Fatal("storage errno must surface", s)
		}
		origin, count := f.denials.diagnostic()
		if origin != "storage" || count != 1 {
			t.Fatal(origin, count)
		}
	})

	t.Run("fresh-mount-none", func(t *testing.T) {
		f, _ := fixture()
		origin, count := f.denials.diagnostic()
		if origin != "none" || count != 0 {
			t.Fatal("fresh mount must report no denials", origin, count)
		}
	})
}

func TestPrepareDenialDetails(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		body                      w.RequestBody
		opcode                    uint32
		begun, readOnly, runtime  bool
		tid                       uint32
		origin, action, operation string
	}{
		{name: "pre-Begin identity", body: w.PrepareRequest{Action: w.IdentityAt}, opcode: 39, tid: 999, origin: "gate-order", action: "identity", operation: "IOCTL"},
		{name: "pre-Begin non-bootstrap", body: w.LookupRequest{Parent: 101, Name: []byte("private")}, opcode: 1, tid: 999, origin: "gate-order", action: "none", operation: "LOOKUP"},
		{name: "post-Begin storage", body: w.GetAttrRequest{Node: 101}, opcode: 3, begun: true, tid: 999, origin: "storage", action: "none", operation: "GETATTR"},
		{name: "read-only storage", body: w.GetAttrRequest{Node: 101}, opcode: 3, readOnly: true, tid: 999, origin: "storage", action: "none", operation: "GETATTR"},
		{name: "unknown enums", body: w.PrepareRequest{Action: ^w.PrepareAction(0)}, opcode: ^uint32(0), tid: 999, origin: "gate-order", action: "none", operation: "other"},
		{name: "before-build", body: w.PrepareRequest{Action: w.IdentityAt}, opcode: 39, begun: true, readOnly: true, tid: 1001, origin: "gate-process", action: "none", operation: "IOCTL"},
		{name: "runtime no gate", body: w.GetAttrRequest{Node: 101}, opcode: 3, runtime: true, tid: 999, origin: "storage", action: "none", operation: "GETATTR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := fixture()
			if !tc.runtime {
				f.prepare = testMountProcess(t, testProcess(), tc.readOnly)
				f.prepare.begun = tc.begun
			}
			h := header()
			h.Pid, h.Opcode = tc.tid, tc.opcode
			builds := 0
			_, status := f.call(&h, 0, func() w.RequestBody { builds++; return tc.body })
			if status != fuse.EACCES {
				t.Fatalf("status = %v", status)
			}
			if tc.name == "before-build" && builds != 0 {
				t.Fatal("built before process check")
			}
			want := PrepareDenialDetails{Origin: tc.origin, Count: 1, Action: tc.action, Operation: tc.operation, Begun: tc.begun, ReadOnly: tc.readOnly, ProcessStage: "none", ProcessCategory: "unavailable"}
			if tc.origin == "gate-process" {
				want.ProcessStage = "unavailable"
			}
			if got := f.denials.details(); got != want {
				t.Fatalf("got %+v, want %+v", got, want)
			}
			if f.prepare != nil {
				f.prepare.mu.Lock()
				f.prepare.begun, f.prepare.readOnly = !tc.begun, !tc.readOnly
				f.prepare.mu.Unlock()
			}
			if got := f.denials.details(); got != want {
				t.Fatalf("state was not captured: %+v", got)
			}
		})
	}
}

func TestPrepareDenialActionVocabulary(t *testing.T) {
	for action, want := range map[w.PrepareAction]string{
		w.BeginCopy: "begin", w.BindCopyTransaction: "bind", w.SealManifest: "seal",
		w.AuthenticateManifest: "authenticate", w.IdentityAt: "identity",
		w.StartCleanup: "cleanup", w.FinishCopy: "finish", 0: "none", 8: "none", ^w.PrepareAction(0): "none",
	} {
		if got := deniedPrepareAction(w.PrepareRequest{Action: action}); got != want {
			t.Fatalf("action %d: %q", action, got)
		}
	}
	if deniedPrepareAction(nil) != "none" || deniedPrepareAction(w.GetAttrRequest{}) != "none" {
		t.Fatal("non-PREPARE action")
	}
	var tracker denialTracker
	if got := tracker.details(); got != (PrepareDenialDetails{Origin: "none", Action: "none", Operation: "other", ProcessStage: "none", ProcessCategory: "unavailable"}) {
		t.Fatal(got)
	}
	tracker.record(denialOrigin(255), ^uint32(0), w.PrepareRequest{Action: 255}, false, false)
	if got := tracker.details(); got.Origin != "other" || got.Action != "none" || got.Operation != "other" {
		t.Fatal(got)
	}
}

func TestPrepareDenialCoherentConcurrentSnapshots(t *testing.T) {
	var tracker denialTracker
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				if i%2 == 0 {
					tracker.record(denialGateProcess, 39, w.PrepareRequest{Action: w.IdentityAt}, false, true, processMatchFailure{matchFinalPoll, unix.EINTR})
				} else {
					tracker.record(denialStorage, 3, w.GetAttrRequest{}, true, false)
				}
				d := tracker.details()
				if d.Count == 0 || (d.Origin == "gate-process" && (d.Action != "identity" || d.Operation != "IOCTL" || d.Begun || !d.ReadOnly || d.ProcessStage != "final-pidfd-poll" || d.ProcessCategory != "EINTR")) ||
					(d.Origin == "storage" && (d.Action != "none" || d.Operation != "GETATTR" || !d.Begun || d.ReadOnly || d.ProcessStage != "none" || d.ProcessCategory != "unavailable")) {
					t.Errorf("incoherent snapshot: %+v", d)
					return
				}
			}
		}()
	}
	wg.Wait()
	if d := tracker.details(); d.Count != 4000 {
		t.Fatal(d)
	}
}

// Lifecycle admission still bypasses the prepare gate; diagnostic state reads
// must not race with BeginCopy or teardown. The fake client is used only by the
// callback goroutine, while gate state is changed under its production mutex.
func TestPrepareDenialLifecycleSnapshotRace(t *testing.T) {
	f, fc := fixture()
	f.prepare = testMountProcess(t, testProcess(), false)
	fc.state = none
	fc.result = &c.Result{Reply: w.Reply{Errno: 13}}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			f.prepare.mu.Lock()
			f.prepare.begun, f.prepare.readOnly = i%2 == 0, i%2 == 0
			f.prepare.mu.Unlock()
		}
		f.prepare.close()
	}()
	h := header()
	h.Opcode = 18
	for i := 0; i < 1000; i++ {
		_, status := f.call(&h, w.LifecycleAuth, func() w.RequestBody { return w.ReleaseRequest{Node: 101, Handle: 808} })
		if status != fuse.EACCES {
			t.Errorf("lifecycle status %v", status)
			break
		}
		d := f.denials.details()
		if d.Origin != "storage" || d.Action != "none" || d.Operation != "RELEASE" || d.Begun != d.ReadOnly {
			t.Errorf("bad snapshot %+v", d)
			break
		}
	}
	wg.Wait()
}

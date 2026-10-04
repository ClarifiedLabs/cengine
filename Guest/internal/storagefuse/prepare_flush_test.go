package storagefuse

import (
	"errors"
	"testing"

	c "dev.cengine/guest/internal/storageclient"
	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// Linux 6.18 fuse_flush sets args.force. ABI3 therefore returns NONE, while
// fuse_force_creds still supplies the closing task's mount-namespace TID.
func TestPrepareForcedFlushPreservesGrantAndInitializer(t *testing.T) {
	for _, tid := range []uint32{999, 1000} {
		f, fc := fixture()
		owner := testProcess()
		f.prepare = testMountProcess(t, owner, false)
		f.prepare.begun = true
		fc.state = none
		fc.result = &c.Result{Reply: w.Reply{Body: w.FlushReply{}}}
		h := header()
		h.Opcode, h.Pid = 25, tid
		h.Uid, h.Gid = 4242, 4343 // header identity must never become a Caller
		if status := f.Flush(nil, &fuse.FlushIn{InHeader: h, Fh: 8}); status != fuse.OK {
			t.Fatalf("forced FLUSH from initializer thread %d: %v", tid, status)
		}
		if fc.auth != w.OpenGrantAuth || fc.body != (w.FlushRequest{Node: 101, Handle: 808}) || len(fc.captured) != 1 || fc.captured[0] != h.Unique || fc.fd != 77 || fc.validationErr != nil || fc.aborted != 0 {
			t.Fatalf("lost capture/grant provenance: %+v", fc)
		}
		if f.prepare.owner != owner || !f.prepare.begun {
			t.Fatal("flush changed initializer ownership")
		}
		// Normal kernel release remains a separate lifecycle request.
		h.Opcode, h.Pid = 18, 0
		fc.result = &c.Result{Reply: w.Reply{Body: w.ReleaseReply{}}}
		f.Release(nil, &fuse.ReleaseIn{InHeader: h, Fh: 8})
		if fc.auth != w.LifecycleAuth || fc.aborted != 0 {
			t.Fatal("flush weakened or blocked lifecycle release")
		}
	}
}

func TestPrepareForcedFlushRejectsForeignOrUnprovenProcess(t *testing.T) {
	for _, name := range []string{"foreign", "zero", "death", "reuse", "thread-exit", "before-begin", "closed", "unowned", "read-only", "wrong-opcode"} {
		t.Run(name, func(t *testing.T) {
			f, fc := fixture()
			owner := testProcess()
			f.prepare = testMountProcess(t, owner, false)
			f.prepare.begun = true
			fc.state = none
			h := header()
			h.Opcode = 25
			switch name {
			case "foreign":
				h.Pid = 1001
			case "zero":
				h.Pid = 0
			case "death":
				owner.alive = false
			case "reuse":
				owner.current++
			case "thread-exit":
				delete(owner.threads, h.Pid)
			case "before-begin":
				f.prepare.begun = false
			case "closed":
				f.prepare.close()
			case "unowned":
				f.prepare.owner = nil
			case "read-only":
				f.prepare.readOnly = true
			case "wrong-opcode":
				h.Opcode = 20
			}
			if status := f.Flush(nil, &fuse.FlushIn{InHeader: h, Fh: 8}); status != fuse.EACCES || fc.body != nil || len(fc.captured) != 1 {
				t.Fatal("unproven forced flush reached transport", status, fc.body)
			}
		})
	}
}

func TestPrepareForcedFlushDoesNotAuthorizeOtherNoneIO(t *testing.T) {
	for _, body := range []w.RequestBody{
		w.WriteRequest{Node: 101, Handle: 808, WriteFlags: w.WriteCache, Data: []byte("x")},
		w.ReadRequest{Node: 101, Handle: 808, Size: 1},
		w.FsyncRequest{Node: 101, Handle: 808},
		w.GetAttrRequest{Node: 101},
		beginProcess(),
	} {
		f, fc := fixture()
		f.prepare = testMountProcess(t, testProcess(), false)
		f.prepare.begun = true
		fc.state = none
		h := header()
		h.Opcode = 25 // even a mismatched internal builder cannot widen FLUSH
		_, status := f.call(&h, w.OpenGrantAuth, func() w.RequestBody { return body })
		if status != fuse.EACCES || fc.body != nil || len(fc.captured) != 1 {
			t.Fatal("NONE escape", body, status)
		}
	}
}

func TestPrepareForcedFlushCaptureGrantAndStorageErrorsRemainErrors(t *testing.T) {
	for _, name := range []string{"capture", "grant", "storage"} {
		t.Run(name, func(t *testing.T) {
			f, fc := fixture()
			f.prepare = testMountProcess(t, testProcess(), false)
			f.prepare.begun = true
			fc.state = none
			h := header()
			h.Opcode = 25
			switch name {
			case "capture":
				fc.captureErr = errors.New("capture failed")
			case "grant":
				fc.errorDo = c.ErrGrant
			case "storage":
				fc.result = &c.Result{Reply: w.Reply{Errno: uint32(fuse.EIO)}}
			}
			if status := f.Flush(nil, &fuse.FlushIn{InHeader: h, Fh: 8}); status != fuse.EIO {
				t.Fatal("failure became successful close", status)
			}
			if name == "capture" && fc.body != nil {
				t.Fatal("capture failure became NONE")
			}
			if name != "storage" && fc.aborted != 1 {
				t.Fatal("uncertain capture/grant did not abort")
			}
		})
	}
}

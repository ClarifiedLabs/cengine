package storagemanaged

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	"dev.cengine/guest/internal/storageidentity"
	w "dev.cengine/guest/internal/storagewire"
)

func TestPrepareRetirementKernelFlags(t *testing.T) {
	for _, abi := range []struct {
		arch                       string
		large, directory, nofollow int
	}{{"arm64", 0x20000, 0x4000, 0x8000}, {"amd64", 0x8000, 0x10000, 0x20000}} {
		t.Run(abi.arch, func(t *testing.T) {
			const nonblock, cloexec, pathFlag = 0x800, 0x80000, 0x200000
			allowed := abi.large | abi.directory | abi.nofollow | nonblock | cloexec
			// Actual native arm64 root and directory handle report 0x2c000 and
			// 0x20800. The libc O_LARGEFILE=0 mask wrongly rejected both.
			for _, flags := range []int{0, abi.large, abi.large | abi.directory | abi.nofollow, abi.large | nonblock, allowed} {
				if !prepareRetirementFlags(flags, false, abi.arch) {
					t.Fatalf("rejected read-only kernel flags %#x", flags)
				}
			}
			for bit := 1; bit > 0 && bit <= 1<<31; bit <<= 1 {
				if got := prepareRetirementFlags(bit, false, abi.arch); got != (bit&allowed != 0) {
					t.Fatalf("flag %#x: accepted=%v", bit, got)
				}
			}
			for _, flags := range []int{pathFlag, pathFlag | cloexec} {
				if !prepareRetirementFlags(flags, true, abi.arch) {
					t.Fatal("rejected canonical O_PATH pin")
				}
			}
			for _, flags := range []int{0, allowed, pathFlag | abi.large, pathFlag | abi.nofollow, pathFlag | 1, pathFlag | 2, -1} {
				if prepareRetirementFlags(flags, true, abi.arch) {
					t.Fatalf("accepted noncanonical O_PATH pin %#x", flags)
				}
			}
		})
	}
	if prepareRetirementFlags(0, false, "unknown") || prepareRetirementFlags(0x200000, true, "unknown") {
		t.Fatal("accepted unknown kernel ABI")
	}
}

func TestPrepareRetirementHistoryAllowlist(t *testing.T) {
	allowed := []w.RequestBody{
		w.GetAttrRequest{Node: 1},
		w.OpenDirRequest{Node: 1},
		w.OpenDirRequest{Node: 1, Flags: w.OpenDirectory | w.OpenNoFollow | w.OpenCloseOnExec | w.OpenLargeFile | w.OpenNonblock},
	}
	denied := []w.RequestBody{
		nil,
		w.GetAttrRequest{Node: 2},
		w.GetAttrRequest{Node: 1, Handle: new(w.HandleID)},
		w.OpenDirRequest{Node: 2},
		w.LookupRequest{Parent: 1, Name: []byte("child")},
		w.ReadDirRequest{Node: 1, Handle: 1},
		w.ReadRequest{Node: 1, Handle: 1},
		w.WriteRequest{Node: 1, Handle: 1},
		w.OpenRequest{Node: 1},
		w.GetXAttrRequest{Node: 1},
		w.ListXAttrRequest{Node: 1},
		w.ReadlinkRequest{Node: 1},
		w.StatFSRequest{Node: 1},
		w.AccessRequest{Node: 1},
		w.FlushRequest{Node: 1, Handle: 1},
		w.FsyncRequest{Node: 1, Handle: 1},
		w.FsyncDirRequest{Node: 1, Handle: 1},
		w.ReleaseRequest{Node: 1, Handle: 1},
		w.ReleaseDirRequest{Node: 1, Handle: 1},
		w.ForgetRequest{Entries: []w.ForgetEntry{{Node: 1, Count: 1}}},
		w.PrepareRequest{Node: 1, Handle: 1, Action: w.IdentityAt},
	}
	// Exercise every individual wire flag, including unknown future flags.
	for bit := uint32(1); bit != 0; bit <<= 1 {
		r := w.OpenDirRequest{Node: 1, Flags: bit}
		const harmless = w.OpenDirectory | w.OpenNoFollow | w.OpenCloseOnExec | w.OpenLargeFile | w.OpenNonblock
		if bit&harmless != 0 {
			allowed = append(allowed, r)
		} else {
			denied = append(denied, r)
		}
	}
	for _, body := range allowed {
		s := &Session{}
		s.observePrepareRetirementRequest(w.Request{Body: body})
		if s.prepareRetirementQualified.Load() {
			t.Fatal("zero/unknown session acquired qualification")
		}
		s.prepareRetirementQualified.Store(true) // model the audited New witness
		s.observePrepareRetirementRequest(w.Request{Body: body})
		if !s.prepareRetirementQualified.Load() {
			t.Fatalf("cold bootstrap rejected: %+v", body)
		}
	}
	for _, body := range denied {
		t.Run(fmt.Sprintf("%T-%v", body, body), func(t *testing.T) {
			s := &Session{}
			s.prepareRetirementQualified.Store(true)
			s.observePrepareRetirementRequest(w.Request{Body: body})
			for _, later := range append(allowed, w.FsyncDirRequest{}, w.ReleaseDirRequest{}, w.ForgetRequest{}) {
				s.observePrepareRetirementRequest(w.Request{Body: later})
				if s.prepareRetirementQualified.Load() {
					t.Fatal("disqualification was restored by later work")
				}
			}
		})
	}
}

func TestPrepareRetirementNoSessionUnknownOrOtherSession(t *testing.T) {
	root, err := os.Open(t.TempDir())
	copyHostMust(t, err)
	defer root.Close()
	b := a.Binding{Role: a.PrepareRole, Mode: a.ReadWrite}
	for _, state := range []string{"absent", "unknown", "other", "closed", "failed", "runtime", "readonly", "foreign-fault"} {
		t.Run(state, func(t *testing.T) {
			r, err := NewRegistry(new(sync.Mutex))
			copyHostMust(t, err)
			s := &Session{binding: b, registry: r}
			r.sessions[b] = s
			s.prepareRetirementQualified.Store(true)
			switch state {
			case "absent":
				delete(r.sessions, b)
			case "unknown":
				s.prepareRetirementQualified.Store(false)
			case "other":
				r.sessions[a.Binding{Role: a.RuntimeRole}] = &Session{}
			case "closed":
				s.closed = true
			case "failed":
				s.failed = true
			case "runtime", "readonly":
				delete(r.sessions, b)
				if state == "runtime" {
					s.binding.Role = a.RuntimeRole
				} else {
					s.binding.Mode = a.ReadOnly
				}
				r.sessions[s.binding] = s
			case "foreign-fault":
				r.faults[a.ID("foreign-volume")] = syscall.EIO
			}
			calls := 0
			ok, err := r.PrepareRetirementProof(s.binding, root, func() (bool, error) { calls++; return true, nil })
			if ok || calls != 0 || (state != "foreign-fault" && err != nil) || (state == "foreign-fault" && !errors.Is(err, syscall.EIO)) {
				t.Fatalf("unproved state published: %v %v calls=%d", ok, err, calls)
			}
		})
	}
}

func TestPrepareRetirementInspectionErrorsBeforePublish(t *testing.T) {
	root, err := os.Open(t.TempDir())
	copyHostMust(t, err)
	copyHostMust(t, root.Close()) // force inspection failure, never an ineligible fallback
	r, err := NewRegistry(new(sync.Mutex))
	copyHostMust(t, err)
	b := a.Binding{Role: a.PrepareRole, Mode: a.ReadWrite}
	obj := &object{id: w.ObjectID{1}, refs: 1}
	n := &node{id: 1, object: obj, lookups: 1}
	s := &Session{binding: b, registry: r, root: root, metadataFD: root, worker: &storageidentity.Worker{}, nextNode: 1, nodes: map[w.NodeID]*node{1: n}, byInode: map[inodeKey]*node{obj.key: n}}
	r.worker, r.store = s.worker, b.Store
	r.objects[obj.key], r.sessions[b] = obj, s
	s.prepareRetirementQualified.Store(true)
	calls := 0
	ok, err := r.PrepareRetirementProof(b, root, func() (bool, error) { calls++; return true, nil })
	if ok || err == nil || calls != 0 || s.prepareRetirementQualified.Load() {
		t.Fatalf("inspection error swallowed: %v %v calls=%d", ok, err, calls)
	}
}

func TestPrepareRetirementDispatchEarlyErrors(t *testing.T) {
	for _, kind := range []string{"unauthorized", "codec"} {
		t.Run(kind, func(t *testing.T) {
			h := newCopyObligationHost(t, t.TempDir())
			h.session.prepareRetirementQualified.Store(true)
			guard := h.guard
			r := w.Request{Sequence: 1, Body: w.GetAttrRequest{Node: 1}}
			if kind == "unauthorized" {
				guard = nil
			}
			_, err := h.session.Dispatch(guard, r)
			if err == nil || h.session.prepareRetirementQualified.Load() {
				t.Fatalf("early %s error retained qualification: %v", kind, err)
			}
			copyHostMust(t, h.session.root.Sync())
			if h.session.prepareRetirementQualified.Load() {
				t.Fatal("successful sync restored qualification")
			}
		})
	}
}

func TestPrepareRetirementDisqualifiedBeforePrivateCallback(t *testing.T) {
	for _, failure := range []string{"errno", "invalid-reply", "panic"} {
		t.Run(failure, func(t *testing.T) {
			h := newCopyObligationHost(t, t.TempDir())
			s := h.session
			s.prepareRetirementQualified.Store(true)
			calls := 0
			s.registry.prepareOperation = func(*a.Guard, w.PrepareRequest) (w.ReplyBody, error) {
				calls++
				if s.prepareRetirementQualified.Load() {
					t.Fatal("private operation entered before permanent disqualification")
				}
				if s.registry.gate.TryLock() {
					s.registry.gate.Unlock()
					t.Fatal("private callback escaped namespace gate")
				}
				switch failure {
				case "errno":
					return nil, syscall.EPERM
				case "panic":
					panic("retirement history test")
				default:
					return nil, nil
				}
			}
			panicked := false
			func() {
				defer func() { panicked = recover() != nil }()
				_, _ = h.dispatch(w.IdentityAt, copyHostID(t))
			}()
			if calls != 1 || panicked != (failure == "panic") || s.prepareRetirementQualified.Load() {
				t.Fatalf("lost failure witness: calls=%d panic=%v", calls, panicked)
			}
			if !s.registry.gate.TryLock() {
				t.Fatal("failure leaked gate")
			}
			s.registry.gate.Unlock()
		})
	}
}

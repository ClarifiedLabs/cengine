package storagefuse

import (
	a "dev.cengine/guest/internal/storageauthority"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type testPrepareProcess struct {
	threads        map[uint32]bool
	alive          bool
	start, current uint64
	closes         int
}

func (p *testPrepareProcess) matches(tid uint32) bool {
	return p.alive && p.start == p.current && p.threads[tid]
}
func (p *testPrepareProcess) close() { p.closes++; p.alive = false }
func testProcess() *testPrepareProcess {
	return &testPrepareProcess{threads: map[uint32]bool{999: true, 1000: true}, alive: true, start: 7, current: 7}
}
func gateCall(f *rawFS, tid uint32, body w.RequestBody) fuse.Status {
	h := header()
	h.Pid = tid
	_, s := f.call(&h, 0, func() w.RequestBody { return body })
	return s
}
func beginProcess() w.PrepareRequest {
	return w.PrepareRequest{Node: 101, Handle: 808, Action: w.BeginCopy}
}

// This fixture uses the same startup constructor as nativeMountObserved. The
// injected process models pidfd/proc evidence; no request supplies its identity.
func testMountProcess(t *testing.T, owner *testPrepareProcess, readOnly bool) *prepareProcessGate {
	t.Helper()
	owner.threads[uint32(os.Getpid())] = true
	calls := 0
	gate, err := newMountPrepareProcess(a.PrepareRole, readOnly, func(pid uint32) (prepareProcess, error) {
		calls++
		if pid != uint32(os.Getpid()) {
			t.Fatal("expected PID was not trusted mount creator", pid)
		}
		return owner, nil
	})
	if err != nil || gate == nil || calls != 1 || gate.owner != owner {
		t.Fatal(gate, err, calls)
	}
	return gate
}

func TestPrepareProcessPinsBeforeTransportAndNeverResets(t *testing.T) {
	f, fc := fixture()
	owner := testProcess()
	f.prepare = testMountProcess(t, owner, false)
	if len(fc.captured) != 0 || fc.body != nil {
		t.Fatal("startup consumed a request")
	}
	// A foreign FIRST Begin and root bootstrap must not seize the prepare gate.
	for _, body := range []w.RequestBody{beginProcess(), w.OpenDirRequest{Node: 101}, w.GetAttrRequest{Node: 101}} {
		before := len(fc.captured)
		if s := gateCall(f, 1001, body); s != fuse.EACCES || fc.body != nil || len(fc.captured) != before+1 || f.prepare.begun {
			t.Fatal("foreign first caller reached transport or seized gate", s)
		}
	}
	// Even a rejected Begin retains the already-installed expected lifetime.
	if s := gateCall(f, 999, beginProcess()); s != fuse.EACCES || f.prepare.owner != owner || !f.prepare.begun {
		t.Fatal(s)
	}
	for _, body := range []w.RequestBody{
		w.UnlinkRequest{Parent: 101, Name: []byte("entry")},
		w.PrepareRequest{Node: 101, Handle: 808, Action: w.FinishCopy, Intent: "11111111-1111-4111-8111-111111111111"}, beginProcess(),
	} {
		fc.body = nil
		gateCall(f, 1000, body)
		if fc.body == nil {
			t.Fatal("same-process thread rejected")
		}
		fc.body = nil
		before := len(fc.captured)
		if s := gateCall(f, 1001, body); s != fuse.EACCES || fc.body != nil || len(fc.captured) != before+1 {
			t.Fatal("foreign process escaped gate", s)
		}
	}
	f.prepare.close()
	f.prepare.close()
	if gateCall(f, 999, beginProcess()) != fuse.EACCES || owner.closes != 1 {
		t.Fatal("teardown adoption")
	}
}

func TestPrepareProcessRejectsDeathReuseAndFailedPin(t *testing.T) {
	for _, failure := range []string{"death", "reuse", "thread exit"} {
		t.Run(failure, func(t *testing.T) {
			f, fc := fixture()
			owner := testProcess()
			f.prepare = testMountProcess(t, owner, false)
			switch failure {
			case "death":
				owner.alive = false
			case "reuse":
				owner.current++
			case "thread exit":
				delete(owner.threads, 999)
			}
			if gateCall(f, 999, beginProcess()) != fuse.EACCES || fc.body != nil || len(fc.captured) != 1 {
				t.Fatal("stale process accepted")
			}
		})
	}
	for _, failure := range []string{"error", "nil", "mismatch", "partial"} {
		t.Run(failure, func(t *testing.T) {
			owner := testProcess()
			owner.threads = map[uint32]bool{}
			pins := 0
			gate, err := newMountPrepareProcess(a.PrepareRole, false, func(uint32) (prepareProcess, error) {
				pins++
				switch failure {
				case "error":
					return nil, errors.New("unprovable")
				case "nil":
					return nil, nil
				case "partial":
					return owner, errors.New("partial pin")
				}
				return owner, nil
			})
			if gate != nil || err == nil || pins != 1 {
				t.Fatal("startup fell back to unpinned mode", gate, err, pins)
			}
			if (failure == "partial" || failure == "mismatch") && owner.closes != 1 {
				t.Fatal("leaked rejected pin")
			}
		})
	}
	f, fc := fixture()
	f.prepare = &prepareProcessGate{}
	if gateCall(f, 999, beginProcess()) != fuse.EACCES || fc.body != nil {
		t.Fatal("zero gate adopted caller")
	}
	for _, role := range []a.Role{a.RuntimeRole, "unknown"} {
		gate, err := newMountPrepareProcess(role, false, func(uint32) (prepareProcess, error) { t.Fatal("unexpected pin"); return nil, nil })
		if gate != nil || (role == a.RuntimeRole) != (err == nil) {
			t.Fatal(role, gate, err)
		}
	}
}

func TestPrepareProcessBootstrapAndIdentitylessIO(t *testing.T) {
	for _, body := range []w.RequestBody{w.UnlinkRequest{Parent: 101, Name: []byte("entry")}, w.OpenRequest{Node: 101}, w.ReadDirRequest{Node: 101, Handle: 808}} {
		f, fc := fixture()
		f.prepare = &prepareProcessGate{}
		if gateCall(f, 999, body) != fuse.EACCES || fc.body != nil || len(fc.captured) != 1 {
			t.Fatal(body)
		}
	}
	for _, body := range []w.RequestBody{w.OpenDirRequest{Node: 101}, w.GetAttrRequest{Node: 101}, w.StatFSRequest{Node: 101}} {
		f, fc := fixture()
		f.prepare = testMountProcess(t, testProcess(), false)
		gateCall(f, 999, body)
		if fc.body == nil {
			t.Fatal("root bootstrap denied", body)
		}
	}
	for _, auth := range []w.AuthKind{w.OpenGrantAuth, w.NodeMetadataAuth} {
		f, fc := fixture()
		f.prepare = &prepareProcessGate{owner: testProcess(), begun: true}
		fc.state = none
		h := header()
		_, status := f.call(&h, auth, func() w.RequestBody { t.Fatal("NONE reached builder"); return nil })
		if status != fuse.EACCES || len(fc.captured) != 1 || fc.body != nil {
			t.Fatal(status)
		}
	}
	f, fc := fixture()
	f.prepare = &prepareProcessGate{owner: testProcess(), begun: true}
	fc.state = none
	h := header()
	h.Pid = 0
	f.ack(&h, w.LifecycleAuth, func() w.RequestBody { return w.ReleaseRequest{Node: 101, Handle: 808} })
	if fc.body == nil {
		t.Fatal("kernel release gated")
	}
	f.Forget(1, 1)
	if fc.forgotten != 1 {
		t.Fatal("kernel forget gated")
	}
}

func TestPrepareProcessRuntimeAndCrossMount(t *testing.T) {
	runtime, fc := fixture()
	gateCall(runtime, 0, w.UnlinkRequest{Parent: 101, Name: []byte("entry")})
	if fc.body == nil {
		t.Fatal("runtime routing changed")
	}
	first, _ := fixture()
	second, sc := fixture()
	first.prepare = &prepareProcessGate{owner: testProcess(), begun: true}
	foreign := testProcess()
	foreign.threads = map[uint32]bool{1001: true}
	second.prepare = &prepareProcessGate{owner: foreign, begun: true}
	if gateCall(second, 999, beginProcess()) != fuse.EACCES || sc.body != nil {
		t.Fatal("crossmount owner accepted")
	}
	gateCall(second, 1001, beginProcess())
	if sc.body == nil {
		t.Fatal("second mount owner denied")
	}
}

func TestPrepareProcessConcurrentThreadsAndFirstPin(t *testing.T) {
	owner := testProcess()
	g := testMountProcess(t, owner, false)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(tid uint32) {
			defer wg.Done()
			g.mu.Lock()
			defer g.mu.Unlock()
			if !g.check(tid, present) || g.admit(tid, 1, beginProcess()) != fuse.OK {
				t.Error("initializer thread rejected")
			}
		}(999 + uint32(i%2))
	}
	wg.Wait()
	if g.owner != owner {
		t.Fatal("owner changed")
	}
	if g.check(1001, present) {
		t.Fatal("competing process accepted")
	}
}

func TestPrepareProcessCaptureFailurePreventsPin(t *testing.T) {
	f, fc := fixture()
	f.prepare = testMountProcess(t, testProcess(), false)
	fc.captureErr = errors.New("capture")
	if gateCall(f, 999, beginProcess()) != fuse.EIO || len(fc.captured) != 1 || fc.body != nil {
		t.Fatal("capture bypass")
	}
}

func TestPrepareProcessZeroStartTime(t *testing.T) {
	// proc_pid_stat(5), field 22: clock ticks since boot can be zero for
	// early-created processes. A timestamp is not the lifetime authority.
	for _, pid := range []uint32{1, 123} {
		stat := fmt.Sprintf("%d (early process) S %s0 0\n", pid, strings.Repeat("0 ", 18))
		for _, leader := range []bool{false, true} {
			if start, ok := prepareProcIdentity(stat, pid, leader); !ok || start != 0 {
				t.Fatalf("zero starttime rejected: pid=%d leader=%v start=%d valid=%v", pid, leader, start, ok)
			}
		}
		if _, ok := prepareProcStat(stat, pid+1); ok {
			t.Fatal("zero starttime accepted a different PID")
		}
		for _, state := range []string{"Z", "X", "x"} {
			if _, ok := prepareProcStat(strings.Replace(stat, ") S ", ") "+state+" ", 1), pid); ok {
				t.Fatal("zero starttime accepted a dead requesting thread")
			}
		}
	}
}

func TestPrepareProcessZeroStartTimeRetainsLifetimeFences(t *testing.T) {
	owner := testProcess()
	owner.start, owner.current = 0, 0
	gate := testMountProcess(t, owner, false)
	if !gate.check(999, present) || gate.check(1001, present) {
		t.Fatal("zero starttime changed thread ownership")
	}
	owner.current = 1
	if gate.check(999, present) {
		t.Fatal("changed zero starttime accepted")
	}
	owner.current, owner.alive = 0, false
	if gate.check(999, present) {
		t.Fatal("dead zero-starttime owner accepted")
	}
	gate.close()
	owner.alive = true
	if gate.check(999, present) || owner.closes != 1 {
		t.Fatal("closed zero-starttime owner adopted")
	}
}

func TestPrepareProcessProcParsing(t *testing.T) {
	stat := "123 (thread ) name) S " + strings.Repeat("0 ", 18) + "456 0\n"
	if start, ok := prepareProcStat(stat, 123); !ok || start != 456 {
		t.Fatal(start, ok)
	}
	for _, data := range []string{"", strings.Replace(stat, ") S ", ") Z ", 1), strings.Replace(stat, "456", "-1", 1), strings.Replace(stat, "456", "18446744073709551616", 1), strings.Replace(stat, "456", "bad", 1), "123 (short) S"} {
		if _, ok := prepareProcStat(data, 123); ok {
			t.Fatal(data)
		}
	}
	if _, ok := prepareProcStat(stat, 124); ok {
		t.Fatal("wrong TID")
	}
	for _, id := range []uint32{1, 123, 4294967295} {
		if got, ok := prepareProcTGID(fmt.Sprintf("Name:\tthread\nTgid:\t%d\nPid:\t9\n", id)); !ok || got != id {
			t.Fatal(got, ok)
		}
	}
	for _, data := range []string{"", "Tgid: 0", "Tgid: -1", "Tgid: 4294967296"} {
		if _, ok := prepareProcTGID(data); ok {
			t.Fatal(data)
		}
	}
}

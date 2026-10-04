package storagefuse

import (
	"errors"
	"testing"

	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

type scriptedPrepareProcess struct {
	results []bool
	calls   int
	failure processMatchFailure
}

func (p *scriptedPrepareProcess) matches(uint32) bool {
	result := p.results[p.calls]
	p.calls++
	return result
}
func (*scriptedPrepareProcess) close()                                  {}
func (p *scriptedPrepareProcess) lastMatchFailure() processMatchFailure { return p.failure }

func TestPrepareProcessOriginalDenial(t *testing.T) {
	for _, tc := range []struct {
		name    string
		results []bool
		builds  int
		stage   processMatchStage
	}{
		{"prebuild false then true", []bool{false, true}, 0, matchFirstPoll},
		{"prebuild pass admit fail then true", []bool{true, false, true}, 1, matchFinalPoll},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, fc := fixture()
			p := &scriptedPrepareProcess{results: tc.results, failure: processMatchFailure{tc.stage, unix.EINTR}}
			f.prepare = &prepareProcessGate{owner: p, begun: true}
			h := header()
			h.Pid = 999
			h.Opcode = 39
			builds := 0
			_, status := f.call(&h, 0, func() w.RequestBody { builds++; return w.PrepareRequest{Action: w.FinishCopy} })
			if status != fuse.EACCES || builds != tc.builds || p.calls != tc.builds+1 || len(fc.captured) != 1 || fc.body != nil || f.stopped.Load() {
				t.Fatalf("behavior changed: status=%v builds=%d matches=%d captures=%d rpc=%v", status, builds, p.calls, len(fc.captured), fc.body)
			}
			d := f.denials.details()
			if d.Origin != "gate-process" || d.ProcessStage != tc.stage.name() || d.ProcessCategory != "EINTR" || !d.Begun || d.ReadOnly || d.Count != 1 {
				t.Fatal(d)
			}
			if (tc.builds == 0 && d.Action != "none") || (tc.builds == 1 && d.Action != "finish") {
				t.Fatal(d)
			}
			// Reading/publishing the cached diagnostic cannot consume the scripted true.
			f.prepare.mu.Lock()
			f.recordGateDenial(&h, present, nil)
			f.prepare.mu.Unlock()
			if p.calls != tc.builds+1 {
				t.Fatal("diagnostics re-evaluated ownership")
			}
		})
	}
}

func TestPrepareProcessFailureClearing(t *testing.T) {
	p := &scriptedPrepareProcess{results: []bool{false, true}, failure: processMatchFailure{matchFirstPoll, unix.EINTR}}
	g := &prepareProcessGate{owner: p}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.owns(999) || !g.owns(999) || g.lastFailure != (processMatchFailure{}) {
		t.Fatal("success retained failure")
	}
	g.closed = true
	if g.owns(999) || g.lastOwned || g.lastFailure.stage != matchClosed || g.lastFailure.cause != nil {
		t.Fatal("closed retained failure")
	}
	var tracker denialTracker
	tracker.record(denialGateProcess, 39, nil, true, false, p.failure)
	tracker.record(denialGateOrder, 39, nil, true, false, p.failure)
	if d := tracker.details(); d.ProcessStage != "none" || d.ProcessCategory != "unavailable" {
		t.Fatal("stale snapshot", d)
	}
}

func TestPrepareProcessFailureVocabulary(t *testing.T) {
	want := []string{"none", "unavailable", "closed", "zero-tid", "no-owner", "first-pidfd-poll", "first-pidfd-ready", "final-pidfd-poll", "final-pidfd-ready", "leader-stat-read", "leader-stat-parse", "leader-start-mismatch", "member-dir", "member-status-read", "member-tgid-parse", "member-tgid-mismatch", "member-stat-read", "member-stat-parse"}
	for i := 0; i < 256; i++ {
		expected := "unavailable"
		if i < len(want) {
			expected = want[i]
		}
		stage, category := (processMatchFailure{processMatchStage(i), errors.New("SECRET /proc/123/status")}).diagnostic()
		if stage != expected || category != "other" {
			t.Fatal(stage, category)
		}
	}
	for _, final := range []bool{false, true} {
		poll, ready := matchFirstPoll, matchFirstReady
		if final {
			poll, ready = matchFinalPoll, matchFinalReady
		}
		if f := processPollFailure(final, -1, 0, unix.EINTR); f.stage != poll || f.cause != unix.EINTR {
			t.Fatal(f)
		}
		for _, values := range []struct {
			n      int
			events int16
		}{{1, 0}, {0, 1}} {
			if f := processPollFailure(final, values.n, values.events, nil); f.stage != ready {
				t.Fatal(f)
			}
		}
		if f := processPollFailure(final, 0, 0, nil); f.stage != matchNone {
			t.Fatal(f)
		}
	}
	for _, tc := range []struct {
		leader          bool
		start, expected uint64
		ok              bool
		err             error
		stage           processMatchStage
	}{
		{true, 1, 1, true, unix.ENOENT, matchLeaderRead},
		{true, 1, 1, false, nil, matchLeaderParse},
		{true, 1, 2, true, nil, matchLeaderStart},
		{true, 1, 1, true, nil, matchNone},
		{false, 1, 0, true, unix.EACCES, matchMemberStatRead},
		{false, 1, 0, false, nil, matchMemberStatParse},
		{false, 1, 0, true, nil, matchNone},
	} {
		if f := processStatFailure(tc.leader, tc.start, tc.expected, tc.ok, tc.err); f.stage != tc.stage {
			t.Fatal(f)
		}
	}
}

func TestPrepareMemberFailure(t *testing.T) {
	for _, tc := range []struct {
		tgid, expected uint32
		ok             bool
		err            error
		stage          processMatchStage
	}{
		{1, 1, true, unix.EIO, matchMemberStatus},
		{1, 1, false, nil, matchMemberTGIDParse},
		{1, 2, true, nil, matchMemberTGIDMismatch},
		{1, 1, true, nil, matchNone},
	} {
		if f := processMemberFailure(tc.tgid, tc.expected, tc.ok, tc.err); f.stage != tc.stage || f.cause != tc.err {
			t.Fatal(f)
		}
	}
}

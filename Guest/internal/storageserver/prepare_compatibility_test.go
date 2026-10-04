//go:build cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageserver

import (
	"context"
	"crypto/ed25519"
	a "dev.cengine/guest/internal/storageauthority"
	m "dev.cengine/guest/internal/storagemanaged"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func fullPrepare(t *testing.T, f *fixture, stage string) (a.Binding, ed25519.PrivateKey, *a.PrepareCompatibilityWitness) {
	k := key(t)
	snapshot, err := f.a.Query(f.control)
	must(t, err)
	b := a.Binding{Store: snapshot.Store.ID, Volume: f.volume, Attachment: id(t), Prepare: id(t), Container: a.ContainerID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), Launch: id(t), Key: fingerprint(t, k), Role: a.PrepareRole, Mode: a.ReadWrite}
	must(t, f.a.ReservePrepare(f.control, a.ReserveRequest{Operation: id(t), Prepare: b.Prepare, Attachments: []a.Binding{b}}))
	must(t, f.a.RegisterAttachment(f.control, a.RegisterRequest{Operation: id(t), Binding: b}))
	witness, err := f.a.InstallPrepareCompatibility(a.PrepareCompatibilityPlan{Stage: stage, Epoch: snapshot.Epoch, Controller: snapshot.Controller, Target: b, Bindings: []a.Binding{b}, RuntimeAttachments: []a.ID{id(t)}})
	must(t, err)
	return b, k, witness
}
func untilCompatibility(t *testing.T, w *a.PrepareCompatibilityWitness, predicate func(a.PrepareCompatibilitySnapshot) bool) a.PrepareCompatibilitySnapshot {
	t.Helper()
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		snapshot := w.Snapshot()
		if predicate(snapshot) {
			return snapshot
		}
		select {
		case <-deadline:
			t.Fatal("compatibility cut not reached")
		case <-tick.C:
		}
	}
}
func TestStorageCompatibilityRealTLSAdmissionGuardsAndIndependentProgress(t *testing.T) {
	for _, stage := range []string{"full-frame-before-admit", "admitted-queued"} {
		t.Run(stage, func(t *testing.T) {
			f := newFixture(t, Limits{}, false)
			b, k, witness := fullPrepare(t, f, stage)
			var selectedCalls atomic.Int32
			f.s.factory = func(g *a.Guard, p *a.DataPrincipal, binding a.Binding) (executor, w.Entry, error) {
				must(t, g.ValidateFor(p))
				return execFunc(func(g *a.Guard, req w.Request) (m.Result, error) {
					if err := g.ValidateFor(p); err != nil {
						return m.Result{}, err
					}
					if binding == b {
						selectedCalls.Add(1)
						return m.Result{Reply: w.Reply{Sequence: req.Sequence, Op: w.OpPrepare, Errno: 16}}, nil
					}
					return m.Result{Reply: w.Reply{Sequence: req.Sequence, Op: w.OpGetAttr, Body: w.GetAttrReply{Attr: rootEntry().Attr}}}, nil
				}), rootEntry(), nil
			}
			client, done := f.start(b, k)
			var root w.RootReply
			must(t, w.ReadFrame(client, &root))
			req := w.Request{Sequence: 7, Auth: w.Auth{Kind: w.CallerAuth, Caller: &w.Caller{Groups: []uint32{}}}, Body: w.PrepareRequest{Node: 1, Handle: 1, Action: w.BeginCopy}}
			must(t, w.WriteFrame(client, &req))
			cut := untilCompatibility(t, witness, func(s a.PrepareCompatibilitySnapshot) bool { return s.State == "observed" })
			if cut.Sequence != 7 || cut.Admitted != (stage == "admitted-queued") || selectedCalls.Load() != 0 {
				t.Fatal("wrong actual cut")
			}
			if witness.Release(stage, cut.ReleaseToken) == nil {
				t.Fatal("release before real retirement")
			}
			// A held cut cannot own the service-wide dispatch lock or authority.mu.
			path := filepath.Join(f.path, "volumes", "unrelated")
			must(t, os.Mkdir(path, 0700))
			var st unix.Stat_t
			must(t, unix.Stat(path, &st))
			f.volume = id(t)
			must(t, f.a.AddVolume(f.control, a.VolumeRequest{Operation: id(t), Volume: a.Volume{ID: f.volume, Name: "unrelated", Root: a.RootIdentity{Device: uint64(st.Dev), Inode: st.Ino}}}))
			other, otherDone, _ := f.connected()
			q := request(1)
			must(t, w.WriteFrame(other, &q))
			if readMessage(t, other).(*w.Reply).Sequence != 1 {
				t.Fatal("unrelated stalled")
			}
			other.NetConn().Close()
			wait(t, otherDone)
			client.NetConn().Close() // must not abandon the already-admitted task
			retired := make(chan error, 1)
			go func() {
				_, err := f.a.Retire(context.Background(), f.control, a.RetireRequest{Operation: id(t), Store: b.Store, Volume: b.Volume, Attachment: b.Attachment, Launch: b.Launch})
				retired <- err
			}()
			pending := untilCompatibility(t, witness, func(s a.PrepareCompatibilitySnapshot) bool { return s.RetirementStarted })
			if stage == "admitted-queued" {
				if pending.AcceptedInFlight == 0 {
					t.Fatal("not actual accepted guard")
				}
				select {
				case <-retired:
					t.Fatal("retire passed held guard")
				default:
				}
			}
			if witness.Release(stage, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff") == nil {
				t.Fatal("foreign release")
			}
			must(t, witness.Release(stage, cut.ReleaseToken))
			if witness.Release(stage, cut.ReleaseToken) == nil {
				t.Fatal("release replay")
			}
			must(t, wait(t, retired))
			wait(t, done)
			final := untilCompatibility(t, witness, func(s a.PrepareCompatibilitySnapshot) bool { return s.State == "finished" })
			if stage == "full-frame-before-admit" {
				if !final.LateAdmissionRejected || selectedCalls.Load() != 0 {
					t.Fatal("late Admit was not refused")
				}
			} else if selectedCalls.Load() != 1 {
				t.Fatal("admitted request abandoned")
			}
			if !final.RetirementStarted || final.AcceptedInFlight != 0 {
				t.Fatal("finish without drain", final)
			}
			if final.Sequence != cut.Sequence || final.ReleaseToken != cut.ReleaseToken || final.Admitted != cut.Admitted {
				t.Fatal("immutable cut changed")
			}
			if len(f.s.receive) != 0 || len(f.s.connections) != 0 {
				t.Fatal("capacity leaked")
			}
		})
	}
}

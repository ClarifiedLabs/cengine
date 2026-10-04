//go:build cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageauthority

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fullCompatibilityFixture(t *testing.T, stage string) (*fixture, Volume, Binding, *DataPrincipal, *PrepareCompatibilityWitness) {
	f := newFixture(t, nil)
	v := f.volume("compatibility")
	b, k := f.binding(v, PrepareRole, ReadWrite, mustID(t))
	must(t, f.a.ReservePrepare(f.control, ReserveRequest{Operation: mustID(t), Prepare: b.Prepare, Attachments: []Binding{b}}))
	must(t, f.a.RegisterAttachment(f.control, RegisterRequest{Operation: mustID(t), Binding: b}))
	w, err := f.a.InstallPrepareCompatibility(PrepareCompatibilityPlan{Stage: stage, Epoch: f.a.Epoch(), Controller: f.a.s.Controller, Target: b, Bindings: []Binding{b}, RuntimeAttachments: []ID{mustID(t)}})
	must(t, err)
	p, err := f.a.AuthenticateData(context.Background(), f.conn(k, tls.VersionTLS13, true), DataHello{Epoch: f.a.Epoch(), Binding: b})
	must(t, err)
	return f, v, b, p, w
}
func TestStorageCompatibilityBoundRequiresDischargedRealProvision(t *testing.T) {
	f, v, b, p, w := fullCompatibilityFixture(t, "transaction-published-bind-reply-lost")
	g, err := f.a.Admit(p, v.ID, true)
	must(t, err)
	defer g.Release()
	begin, err := g.BeginCopyOperation(17, CopyOperationBegin, "")
	must(t, err)
	intent, err := g.BeginCopy(copyRoot(f, v))
	must(t, err)
	must(t, begin.CompleteRequest(nil, true))
	op, err := g.BeginCopyOperation(18, CopyOperationProvision, intent.ID)
	must(t, err)
	seen := map[string]bool{}
	f.a.j.afterStep = func(step string) { seen[step] = true }
	intent, err = g.ProvisionCopyTransaction(intent.ID, hostCopyObject)
	must(t, err)
	if !seen["copy-public-parent-sync"] || !seen["copy-source-parent-sync"] {
		t.Fatal("both parents must sync")
	}
	if g.PrepareCompatibilityBoundReply(18, intent) || w.Snapshot().Bound != nil {
		t.Fatal("observed before obligation discharge")
	}
	must(t, op.CompleteRequest(nil, true))
	f.a.j.afterStep = nil
	if g.PrepareCompatibilityBoundReply(19, intent) {
		t.Fatal("caller sequence accepted")
	}
	bad := intent
	bad.Owner.Key = "wrong"
	if g.PrepareCompatibilityBoundReply(18, bad) {
		t.Fatal("foreign bound accepted")
	}
	if !g.PrepareCompatibilityBoundReply(18, intent) || g.PrepareCompatibilityBoundReply(18, intent) {
		t.Fatal("bound must drop once")
	}
	snapshot := w.Snapshot()
	if snapshot.State != "observed" || snapshot.Bound == nil || *snapshot.Bound != intent || intent.Phase != CopyBound || !intent.InitialCaptured {
		t.Fatal("not actual BOUND")
	}
	if _, err := os.Stat(filepath.Join(f.path, "volumes", v.Name, copyTransactionName)); err != nil {
		t.Fatal("not published", err)
	}
	if _, err := os.Stat(filepath.Join(f.path, ".cengine-storage-authority", copyOperationName)); !os.IsNotExist(err) {
		t.Fatal("obligation not discharged", err)
	}
	g.Release()
	successor := copySuccessor(t, f, b)
	recovered, err := successor.InspectCopy(intent.ID, copyRoot(f, v))
	must(t, err)
	if recovered.Phase != CopyBound || recovered.Transaction != intent.Transaction || recovered.Owner == intent.Owner || !recovered.InitialCaptured {
		t.Fatal("fresh owner lost bound provenance")
	}
	if final := w.Snapshot(); final.State != "finished" || !final.RetirementStarted || final.AcceptedInFlight != 0 {
		t.Fatal("not actually drained", final)
	}
	if *w.Snapshot().Bound != intent {
		t.Fatal("observation changed on ownership transfer")
	}
}
func TestStorageCompatibilityReleaseCannotInventRetirement(t *testing.T) {
	_, _, _, _, w := fullCompatibilityFixture(t, "admitted-queued")
	if w.Release("admitted-queued", w.Snapshot().ReleaseToken) == nil {
		t.Fatal("armed release")
	}
	if w.Release("drain-durable-reply-lost", w.Snapshot().ReleaseToken) == nil {
		t.Fatal("non-admission release")
	}
}

func TestStorageCompatibilityObserveNeverTakesAuthorityMutex(t *testing.T) {
	f, _, _, _, w := fullCompatibilityFixture(t, "full-frame-before-admit")
	f.a.mu.Lock()
	finished := make(chan struct{})
	go func() { _ = w.Snapshot(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(time.Second):
		f.a.mu.Unlock()
		t.Fatal("observe queried authority")
	}
	f.a.mu.Unlock()
}

// A held admission belongs to the arming controller's carrier claim. Only a
// successor controller's Retire may release it; the arming controller's Retire
// still waits for the explicit release action.
func TestStorageCompatibilitySuccessorControllerRetireReleasesHeldAdmission(t *testing.T) {
	for _, stage := range []string{"admitted-queued", "full-frame-before-admit"} {
		for _, successor := range []bool{false, true} {
			t.Run(stage+"/successor="+map[bool]string{false: "no", true: "yes"}[successor], func(t *testing.T) {
				f, v, b, p, w := fullCompatibilityFixture(t, stage)
				var guard *Guard
				if stage == "admitted-queued" {
					g, err := f.a.Admit(p, v.ID, true)
					must(t, err)
					guard = g
				}
				held := make(chan struct{})
				go func() {
					f.a.PrepareCompatibilityAdmission(DataHello{f.a.Epoch(), b}, 7, guard)
					close(held)
				}()
				for deadline := time.Now().Add(5 * time.Second); w.Snapshot().State != "observed"; {
					if time.Now().After(deadline) {
						t.Fatal("admission never held")
					}
					time.Sleep(time.Millisecond)
				}
				control := f.control
				if successor {
					next := newKey(t)
					sp, err := f.a.AuthenticateSuccessor(context.Background(), f.conn(next, tls.VersionTLS13, true))
					must(t, err)
					g := f.takeoverGrant(1, fp(t, next))
					msg, err := LifecycleGrantSigningBytes(g)
					must(t, err)
					if _, err = f.a.TakeoverLifecycle(sp, SignedLifecycleGrant{g, ed25519.Sign(f.bootstrap, msg)}); err != nil {
						t.Fatal(err)
					}
					control = f.authControl(next, 2)
				}
				retired := make(chan Receipt, 1)
				go func() {
					r, err := f.a.Retire(context.Background(), control, RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch})
					if err != nil {
						t.Error(err)
					}
					retired <- r
				}()
				for deadline := time.Now().Add(5 * time.Second); !w.Snapshot().RetirementStarted; {
					if time.Now().After(deadline) {
						t.Fatal("retirement never started")
					}
					time.Sleep(time.Millisecond)
				}
				if successor {
					select {
					case <-held:
					case <-time.After(5 * time.Second):
						t.Fatal("successor retire did not release the held admission")
					}
					if s := w.Snapshot(); s.State != "released" {
						t.Fatal("not released", s)
					}
					if w.Release(stage, w.Snapshot().ReleaseToken) == nil {
						t.Fatal("explicit release accepted after successor release")
					}
				} else {
					select {
					case <-held:
						t.Fatal("arming controller retire released the held admission")
					case <-time.After(50 * time.Millisecond):
					}
					if s := w.Snapshot(); s.State != "observed" || !s.RetirementStarted {
						t.Fatal("hold changed", s)
					}
					must(t, w.Release(stage, w.Snapshot().ReleaseToken))
					<-held
				}
				if stage == "admitted-queued" {
					guard.Release()
				} else {
					f.a.PrepareCompatibilityAdmissionResult(DataHello{f.a.Epoch(), b}, 7, ErrBlocked)
				}
				select {
				case r := <-retired:
					if r.Attachment != b.Attachment || r.Revision == 0 {
						t.Fatal("bad receipt", r)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("retire never completed")
				}
				for deadline := time.Now().Add(5 * time.Second); w.Snapshot().State != "finished"; {
					if time.Now().After(deadline) {
						t.Fatal("witness never finished", w.Snapshot())
					}
					time.Sleep(time.Millisecond)
				}
				if final := w.Snapshot(); final.AcceptedInFlight != 0 || final.LateAdmissionRejected != (stage == "full-frame-before-admit") {
					t.Fatal("wrong drained status", final)
				}
			})
		}
	}
}

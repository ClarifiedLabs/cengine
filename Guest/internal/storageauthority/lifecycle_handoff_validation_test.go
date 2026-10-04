package storageauthority

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLifecycleHandoffMalformedPersistedFenceRefusesUnchanged(t *testing.T) {
	for _, applied := range []bool{false, true} {
		for name, mutate := range map[string]func(*diskState){
			"operation-alias": func(s *diskState) {
				s.Lifecycle.HandoffFence.Request.OperationID = s.Lifecycle.HandoffFence.Request.Pending.ID
			},
			"pending-serial": func(s *diskState) {
				s.Lifecycle.HandoffFence.Request.Pending.Serial = s.Lifecycle.HandoffFence.Request.Predecessor.Serial
			},
			"pending-epoch":    func(s *diskState) { s.Lifecycle.HandoffFence.Request.Pending.ExpectedEpoch++ },
			"pending-root-key": func(s *diskState) { s.Lifecycle.HandoffFence.Request.Pending.NewKey = s.Bootstrap },
			"identity": func(s *diskState) {
				f := s.Lifecycle.HandoffFence
				f.Request.Predecessor.Identity.Generation++
				f.Request.Pending.Identity.Generation++
				f.Applied.Grant.Identity.Generation++
			},
			"zero-open": func(s *diskState) { s.Lifecycle.HandoffFence.Request.OpenRevision = 0 },
			"open-after-fence": func(s *diskState) {
				s.Lifecycle.HandoffFence.Request.OpenRevision = s.Lifecycle.HandoffFence.FenceRevision
			},
			"future-fence":          func(s *diskState) { s.Lifecycle.HandoffFence.FenceRevision = s.Revision + 1 },
			"zero-applied-revision": func(s *diskState) { s.Lifecycle.HandoffFence.Applied.Revision = 0 },
			"applied-after-fence":   func(s *diskState) { s.Lifecycle.HandoffFence.Applied.Revision = s.Lifecycle.HandoffFence.FenceRevision },
			"foreign-applied-grant": func(s *diskState) { s.Lifecycle.HandoffFence.Applied.Grant.ID = mustID(t) },
			"changed-applied-epoch": func(s *diskState) { s.Lifecycle.HandoffFence.Applied.ServiceEpoch = mustID(t) },
		} {
			t.Run(map[bool]string{false: "unapplied", true: "applied"}[applied]+"/"+name, func(t *testing.T) {
				f, _ := newLifecycleFixture(t)
				signed, pending, principal := handoffRequest(t, f)
				if applied {
					_, err := f.a.TakeoverLifecycle(principal, pending)
					must(t, err)
				}
				_, err := f.a.FenceLifecycleHandoff(signed, make([]byte, 32))
				must(t, err)
				current, expected := f.signedCurrent(), expectedLifecycleStartup(f)
				mutated := f.a.clone()
				mutate(mutated)
				check := &Authority{s: mutated, limits: f.a.limits}
				wantErr(t, check.validate(), ErrInvalid)
				must(t, f.a.Close())
				raw, err := json.Marshal(mutated)
				must(t, err)
				must(t, os.WriteFile(filepath.Join(f.path, registryName, stateName), raw, 0600))
				lifecycleCrashRefusesUnchanged(t, f.path, func() (*Authority, error) {
					return OpenLifecycleExpected(f.c, current, expected)
				}, ErrInvalid)
			})
		}
	}
}

func TestLifecycleHandoffFenceOrdersLaterAppliedGrant(t *testing.T) {
	f, _ := newLifecycleFixture(t)
	signed, pending, _ := handoffRequest(t, f)
	_, err := f.a.FenceLifecycleHandoff(signed, make([]byte, 32))
	must(t, err)
	key := newKey(t)
	g := f.takeoverGrant(f.a.s.Controller.Epoch, fp(t, key))
	g.Serial = pending.Grant.Serial + 1
	p, err := f.a.AuthenticateSuccessor(context.Background(), f.conn(key, tls.VersionTLS13, true))
	must(t, err)
	_, err = f.a.TakeoverLifecycle(p, signLifecycle(t, f.bootstrap, g))
	must(t, err)
	must(t, f.a.validate())
	for _, kind := range []string{"serial", "revision"} {
		t.Run(kind, func(t *testing.T) {
			bad := f.a.clone()
			if kind == "serial" {
				bad.Lifecycle.Latest.Grant.Serial = pending.Grant.Serial
			} else {
				bad.Lifecycle.Latest.Revision = bad.Lifecycle.HandoffFence.FenceRevision
			}
			check := &Authority{s: bad, limits: f.a.limits}
			wantErr(t, check.validate(), ErrInvalid)
		})
	}
}

func TestLifecycleHandoffConcurrentTakeoverKeepsDataIdentity(t *testing.T) {
	f, _ := newLifecycleFixture(t)
	v := f.volume("data")
	binding, data := f.runtime(v, ReadWrite)
	signed, pending, principal := handoffRequest(t, f)
	before := f.a.clone()
	start, done := make(chan struct{}), make(chan error, 1)
	go func() {
		<-start
		_, err := f.a.TakeoverLifecycle(principal, pending)
		done <- err
	}()
	close(start)
	result, err := f.a.FenceLifecycleHandoff(signed, make([]byte, 32))
	must(t, err)
	takeoverErr := <-done
	if result.AppliedGrant == pending.Grant {
		must(t, takeoverErr)
	} else {
		wantErr(t, takeoverErr, ErrUnauthorized)
	}
	must(t, result.Validate())
	must(t, f.a.validate())
	if result.AppliedGrant != f.a.s.Lifecycle.Latest.Grant || result.AppliedRevision != f.a.s.Lifecycle.Latest.Revision ||
		before.Epoch != f.a.s.Epoch || before.Lifecycle.OpenRevision != f.a.s.Lifecycle.OpenRevision ||
		!reflect.DeepEqual(before.Attachments, f.a.s.Attachments) || !reflect.DeepEqual(before.Volumes, f.a.s.Volumes) ||
		!reflect.DeepEqual(before.Operations, f.a.s.Operations) {
		t.Fatal("concurrent fence misreported outcome or changed DATA identity/history")
	}
	files := lifecycleFiles(t, f)
	_, err = f.a.TakeoverLifecycle(principal, pending)
	wantErr(t, err, ErrUnauthorized)
	if !reflect.DeepEqual(files, lifecycleFiles(t, f)) {
		t.Fatal("late pending takeover mutated disk")
	}
	guard, err := f.a.Admit(data, v.ID, true)
	must(t, err)
	defer guard.Release()
	d, err := guard.BeginDurability(1)
	must(t, err)
	must(t, d.Complete(nil))
	if f.a.s.Attachments[binding.Attachment].Binding != binding {
		t.Fatal("original DATA principal lost its workload identity")
	}
}

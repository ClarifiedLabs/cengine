package storageauthority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func handoffRequest(t *testing.T, f *fixture) (SignedLifecycleHandoff, SignedLifecycleGrant, *SuccessorPrincipal) {
	t.Helper()
	key := newKey(t)
	g := f.takeoverGrant(f.a.s.Controller.Epoch, fp(t, key))
	p, err := f.a.AuthenticateSuccessor(context.Background(), f.conn(key, tls.VersionTLS13, true))
	must(t, err)
	r := LifecycleHandoffRequest{mustID(t), f.a.s.Lifecycle.Latest.Grant, g, f.a.s.Epoch, f.a.s.Lifecycle.OpenRevision}
	return signHandoff(t, f.bootstrap, r), signLifecycle(t, f.bootstrap, g), p
}

func signHandoff(t *testing.T, key ed25519.PrivateKey, r LifecycleHandoffRequest) SignedLifecycleHandoff {
	t.Helper()
	b, err := LifecycleHandoffSigningBytes(r)
	must(t, err)
	return SignedLifecycleHandoff{r, ed25519.Sign(key, b)}
}

func TestLifecycleHandoffActualOutcomeAndLateAuthenticatedRequest(t *testing.T) {
	for _, applied := range []bool{false, true} {
		t.Run(map[bool]string{false: "unapplied", true: "applied"}[applied], func(t *testing.T) {
			f, _ := newLifecycleFixture(t)
			v := f.volume("retained-data")
			binding, runtime := f.runtime(v, ReadWrite)
			signed, pending, principal := handoffRequest(t, f)
			if applied {
				_, err := f.a.TakeoverLifecycle(principal, pending)
				must(t, err)
			}
			before := f.a.clone()
			result, err := f.a.FenceLifecycleHandoff(signed, bytes.Repeat([]byte{1}, 32))
			must(t, err)
			must(t, result.Validate())
			if result.AppliedGrant != before.Lifecycle.Latest.Grant || result.AppliedServiceEpoch != before.Lifecycle.Latest.ServiceEpoch ||
				result.AppliedRevision != before.Lifecycle.Latest.Revision || result.FenceRevision != before.Revision+1 {
				t.Fatal("not the actual immutable applied outcome", result)
			}
			before.Revision++
			before.Lifecycle.HandoffFence = f.a.s.Lifecycle.HandoffFence
			if !reflect.DeepEqual(before, f.a.s) {
				t.Fatal("fence changed controller, live open, DATA attachments or workload state")
			}
			must(t, f.a.validate())
			// This principal was authenticated BEFORE the fence; even applied-grant
			// idempotency cannot give the abandoned controller authority afterward.
			_, err = f.a.TakeoverLifecycle(principal, pending)
			wantErr(t, err, ErrUnauthorized)
			files := lifecycleFiles(t, f)
			again, err := f.a.FenceLifecycleHandoff(signed, bytes.Repeat([]byte{2}, 32))
			must(t, err)
			result.Nonce = again.Nonce
			if !reflect.DeepEqual(result, again) || !reflect.DeepEqual(files, lifecycleFiles(t, f)) {
				t.Fatal("exact fresh-challenge retry rewrote fence/outcome")
			}
			guard, err := f.a.Admit(runtime, v.ID, true)
			must(t, err)
			d, err := guard.BeginDurability(1)
			must(t, err)
			must(t, d.Complete(nil))
			guard.Release()
			if f.a.s.Attachments[binding.Attachment].Binding != binding {
				t.Fatal("original workload identity changed")
			}
			// A new ROOT serial, fresh key and ACTUAL current epoch can proceed.
			key := newKey(t)
			g := f.takeoverGrant(f.a.s.Controller.Epoch, fp(t, key))
			g.Serial = pending.Grant.Serial + 1
			p, err := f.a.AuthenticateSuccessor(context.Background(), f.conn(key, tls.VersionTLS13, true))
			must(t, err)
			_, err = f.a.TakeoverLifecycle(p, signLifecycle(t, f.bootstrap, g))
			must(t, err)
			must(t, f.a.validate())
			_, err = f.a.FenceLifecycleHandoff(signed, make([]byte, 32))
			wantErr(t, err, ErrConflict)
			must(t, f.a.Close())
			f.a, err = f.openCurrent()
			must(t, err)
			must(t, f.a.validate())
			if f.a.s.Lifecycle.HandoffFence.Request != signed.Request {
				t.Fatal("open lost abandoned-grant fence")
			}
		})
	}
}

func TestLifecycleHandoffRefusesMixedOrUnauthenticatedStateWithoutMutation(t *testing.T) {
	f, _ := newLifecycleFixture(t)
	signed, _, _ := handoffRequest(t, f)
	for _, kind := range []string{"signature", "root", "epoch", "open", "predecessor", "pending-root", "identity", "nonce"} {
		t.Run(kind, func(t *testing.T) {
			s := signed
			nonce := make([]byte, 32)
			switch kind {
			case "epoch":
				s.Request.ServiceEpoch = mustID(t)
			case "open":
				s.Request.OpenRevision++
			case "predecessor":
				s.Request.Predecessor.ID = mustID(t)
			case "pending-root":
				s.Request.Pending.NewKey = f.a.s.Bootstrap
			case "identity":
				s.Request.Predecessor.Identity.Generation++
				s.Request.Pending.Identity.Generation++
			case "nonce":
				nonce = nil
			}
			s = signHandoff(t, f.bootstrap, s.Request)
			if kind == "signature" {
				s.Signature[0] ^= 1
			}
			if kind == "root" {
				s = signHandoff(t, newKey(t), s.Request)
			}
			before := lifecycleFiles(t, f)
			if _, err := f.a.FenceLifecycleHandoff(s, nonce); err == nil {
				t.Fatal("accepted", kind)
			}
			if !reflect.DeepEqual(before, lifecycleFiles(t, f)) {
				t.Fatal("refusal mutated disk")
			}
		})
	}
}

func TestLifecycleHandoffBusyDataAndRepeatedUnappliedFences(t *testing.T) {
	f, _ := newLifecycleFixture(t)
	v := f.volume("busy")
	_, p := f.runtime(v, ReadWrite)
	guard, err := f.a.Admit(p, v.ID, true)
	must(t, err)
	d, err := guard.BeginDurability(1)
	must(t, err)
	signed, pending, principal := handoffRequest(t, f)
	before := lifecycleFiles(t, f)
	// Reproduces the live writer collision that was previously returned as a
	// fatal controller error. This alone does not prove the production cause.
	_, err = f.a.TakeoverLifecycle(principal, pending)
	wantErr(t, err, ErrBusy)
	_, err = f.a.FenceLifecycleHandoff(signed, make([]byte, 32))
	wantErr(t, err, ErrBusy)
	if !reflect.DeepEqual(before, lifecycleFiles(t, f)) {
		t.Fatal("busy mutated")
	}
	must(t, d.Complete(nil))
	guard.Release()
	_, err = f.a.FenceLifecycleHandoff(signed, make([]byte, 32))
	must(t, err)
	first := signed
	for i := 0; i < 32; i++ {
		signed.Request.OperationID = mustID(t)
		signed.Request.Pending.ID = mustID(t)
		signed.Request.Pending.Serial++
		signed.Request.Pending.NewKey = fp(t, newKey(t))
		signed = signHandoff(t, f.bootstrap, signed.Request)
		_, err = f.a.FenceLifecycleHandoff(signed, make([]byte, 32))
		must(t, err)
		must(t, f.a.validate())
	}
	_, err = f.a.FenceLifecycleHandoff(first, make([]byte, 32))
	wantErr(t, err, ErrConflict)
	if f.a.s.Controller.Epoch != 1 {
		t.Fatal("unapplied grants advanced controller")
	}
	if b, _ := json.Marshal(f.a.s.Lifecycle.HandoffFence); len(b) > 2048 {
		t.Fatal("unbounded fence")
	}
}

func TestLifecycleHandoffCrossLanguageVector(t *testing.T) {
	data, err := os.ReadFile("../../../Tests/Fixtures/storage-bootstrap/lifecycle-handoff-v1.json")
	must(t, err)
	var vector struct {
		RootSeed      []byte                  `json:"root_seed"`
		RootPublicKey []byte                  `json:"root_public_key"`
		Request       LifecycleHandoffRequest `json:"request"`
		SigningBytes  []byte                  `json:"signing_bytes"`
		Signature     []byte                  `json:"signature"`
		Results       []struct {
			Result       LifecycleHandoffResult `json:"result"`
			SigningBytes []byte                 `json:"signing_bytes"`
		} `json:"results"`
	}
	must(t, json.Unmarshal(data, &vector))
	b, err := LifecycleHandoffSigningBytes(vector.Request)
	must(t, err)
	if !bytes.Equal(b, vector.SigningBytes) || !bytes.Equal(ed25519.Sign(ed25519.NewKeyFromSeed(vector.RootSeed), b), vector.Signature) {
		t.Fatal("request vector differs")
	}
	must(t, VerifyLifecycleHandoff(vector.RootPublicKey, SignedLifecycleHandoff{vector.Request, vector.Signature}))
	for _, row := range vector.Results {
		b, err = LifecycleHandoffResultSigningBytes(row.Result)
		must(t, err)
		if !bytes.Equal(b, row.SigningBytes) {
			t.Fatal("result vector differs")
		}
	}
}

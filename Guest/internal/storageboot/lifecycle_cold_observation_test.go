package storageboot

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
)

func coldObservationConfig(t *testing.T) (LifecycleConfiguration, a.SignedLifecycleColdObservation) {
	t.Helper()
	cfg, _ := lifecycleColdConfig(t)
	old := copyLifecycleConfiguration(cfg)
	old.Cold.Request.Launch.ShimLaunchUUID = a.ID(lifecycleTestID(t))
	lifecycleSignColdConfig(t, &old)
	subject, err := lifecycleCanonical(old.Cold)
	if err != nil {
		t.Fatal(err)
	}
	r := a.LifecycleColdObservationRequest{ObservationID: a.ID(lifecycleTestID(t)), Subject: subject, Observer: cfg.Cold.Request.Launch}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	msg, err := a.LifecycleColdObservationSigningBytes(r)
	if err != nil {
		t.Fatal(err)
	}
	auth := a.SignedLifecycleColdObservation{Request: r, Signature: ed25519.Sign(key, msg)}
	cfg.Cold.Request.Observation = &auth
	g := cfg.Signed.Grant
	g.Serial++
	g.ID = a.ID(lifecycleTestID(t))
	g.NewKey = a.Fingerprint(lifecycleTestHex(t))
	cfg.Cold.Request.OperationID = g.ID
	msg, err = a.LifecycleGrantSigningBytes(g)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Signed = a.SignedLifecycleGrant{Grant: g, Signature: ed25519.Sign(key, msg)}
	cfg.Cold.Request.Takeover = cfg.Signed
	lifecycleSignColdConfig(t, &cfg)
	return cfg, auth
}
func TestLifecycleColdObservationWireClosedShapesAndCopies(t *testing.T) {
	cfg, auth := coldObservationConfig(t)
	b := lifecycleTestBinding()
	f := lifecycleFrame("observe-cold", b)
	f.ObservationAuthorization = &auth
	f.ObservationRootPublicKey = cfg.RootPublicKey
	raw, err := EncodeLifecycleFrame(&f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ReadLifecycleFrame(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*LifecycleFrame){func(f *LifecycleFrame) { f.ObservationRootPublicKey = nil }, func(f *LifecycleFrame) { f.Configuration = &cfg }, func(f *LifecycleFrame) { f.Operation = "hello" }, func(f *LifecycleFrame) { f.ColdObservation = &a.LifecycleColdObservation{} }} {
		bad := f
		mutate(&bad)
		if _, err = EncodeLifecycleFrame(&bad); err == nil {
			t.Fatal("open observation shape")
		}
	}
	cloned := copyLifecycleConfiguration(cfg)
	cloned.Cold.Request.Observation.Signature[0] ^= 1
	cloned.Cold.Request.Observation.Request.Subject[0] ^= 1
	if cfg.validate() != nil {
		t.Fatal("observation copy aliases original")
	}
}
func TestLifecycleColdObservationSessionBeforeConfigure(t *testing.T) {
	cfg, auth := coldObservationConfig(t)
	host, guest := net.Pipe()
	defer host.Close()
	done := make(chan error, 1)
	started, observations := 0, 0
	sentinel := errors.New("stop at first worker")
	go func() {
		done <- lifecycleSessionWithObservation(context.Background(), guest, lifecycleTestBinding(), func(LifecycleConfiguration, string, workerStartGate) (lifecycleWorker, *LifecycleReady, error) {
			started++
			return nil, nil, sentinel
		}, func(key ed25519.PublicKey, s a.SignedLifecycleColdObservation) (a.LifecycleColdObservation, error) {
			observations++
			if a.VerifyLifecycleColdObservation(key, s) != nil {
				return a.LifecycleColdObservation{}, a.ErrUnauthorized
			}
			return a.LifecycleColdObservation{RequestSHA256: s.Request.Digest(), Outcome: "unchanged", Predecessor: cfg.Cold.Request.Predecessor}, nil
		}, time.Second)
	}()
	hello, err := ReadLifecycleFrame(host)
	if err != nil || hello.Operation != "hello" {
		t.Fatalf("hello: %v", err)
	}
	// Four O1/O2 proofs plus three prepare proofs, and one lost-reply retry.
	for i := 0; i < 8; i++ {
		f := lifecycleFrame("observe-cold", lifecycleTestBinding())
		f.ObservationAuthorization = &auth
		f.ObservationRootPublicKey = cfg.RootPublicKey
		if err = WriteLifecycleFrame(host, &f); err != nil {
			t.Fatal(err)
		}
		reply, e := ReadLifecycleFrame(host)
		if e != nil || reply.Operation != "cold-observed" || reply.Ready != nil || reply.ColdObservation.ValidateFor(auth.Request) != nil {
			t.Fatalf("observation: %v", e)
		}
	}
	f := lifecycleFrame("configure", lifecycleTestBinding())
	f.Configuration = &cfg
	if err = WriteLifecycleFrame(host, &f); err != nil {
		t.Fatal(err)
	}
	if err = <-done; !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	if started != 1 || observations != 8 {
		t.Fatalf("starts=%d observations=%d", started, observations)
	}
}
func TestLifecycleColdObservationSessionRefusesWithoutWorkers(t *testing.T) {
	for _, kind := range []string{"nil-callback", "binding", "observer", "changed-subject", "cap", "old-configure"} {
		t.Run(kind, func(t *testing.T) {
			cfg, auth := coldObservationConfig(t)
			host, guest := net.Pipe()
			defer host.Close()
			done := make(chan error, 1)
			callback := lifecycleColdObserver(func(_ ed25519.PublicKey, s a.SignedLifecycleColdObservation) (a.LifecycleColdObservation, error) {
				return a.LifecycleColdObservation{RequestSHA256: s.Request.Digest(), Outcome: "unchanged", Predecessor: cfg.Cold.Request.Predecessor}, nil
			})
			if kind == "nil-callback" {
				callback = nil
			}
			go func() {
				done <- lifecycleSessionWithObservation(context.Background(), guest, lifecycleTestBinding(), func(LifecycleConfiguration, string, workerStartGate) (lifecycleWorker, *LifecycleReady, error) {
					return nil, nil, errors.New("UNEXPECTED worker")
				}, callback, 5*time.Second)
			}()
			if _, err := ReadLifecycleFrame(host); err != nil {
				t.Fatal(err)
			}
			f := lifecycleFrame("observe-cold", lifecycleTestBinding())
			f.ObservationAuthorization = &auth
			f.ObservationRootPublicKey = cfg.RootPublicKey
			if kind == "binding" {
				f.Binding.GuestBootNonce = lifecycleTestID(t)
			}
			if kind == "observer" {
				auth.Request.Observer.ShimLaunchUUID = a.ID(lifecycleTestID(t))
				msg, e := a.LifecycleColdObservationSigningBytes(auth.Request)
				if e != nil {
					t.Fatal(e)
				}
				auth.Signature = ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)), msg)
			}
			if err := WriteLifecycleFrame(host, &f); err != nil {
				t.Fatal(err)
			}
			if kind == "changed-subject" || kind == "cap" || kind == "old-configure" {
				if _, err := ReadLifecycleFrame(host); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "old-configure":
					c := copyLifecycleConfiguration(cfg)
					c.Cold.Request.Observation = nil
					lifecycleSignColdConfig(t, &c)
					f = lifecycleFrame("configure", lifecycleTestBinding())
					f.Configuration = &c
				case "changed-subject":
					auth.Request.ObservationID = a.ID(lifecycleTestID(t))
					msg, _ := a.LifecycleColdObservationSigningBytes(auth.Request)
					auth.Signature = ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)), msg)
				case "cap":
					for i := 1; i < maximumColdObservationExchanges; i++ {
						if err := WriteLifecycleFrame(host, &f); err != nil {
							t.Fatal(err)
						}
						if _, err := ReadLifecycleFrame(host); err != nil {
							t.Fatal(err)
						}
					}
				}
				if err := WriteLifecycleFrame(host, &f); err != nil {
					t.Fatal(err)
				}
			}
			if err := <-done; err == nil || err.Error() == "UNEXPECTED worker" {
				t.Fatalf("unsafe session: %v", err)
			}
		})
	}
}

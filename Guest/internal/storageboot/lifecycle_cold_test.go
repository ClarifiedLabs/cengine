package storageboot

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
	s "dev.cengine/guest/internal/storageservice"
)

func lifecycleColdConfig(t *testing.T) (LifecycleConfiguration, LifecycleConfiguration) {
	t.Helper()
	initial, _ := lifecycleTestConfig(t)
	root := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	initial.Signed.Grant.Serial = 1
	signGrant := func(g a.LifecycleGrant) a.SignedLifecycleGrant {
		msg, err := a.LifecycleGrantSigningBytes(g)
		if err != nil {
			t.Fatal(err)
		}
		return a.SignedLifecycleGrant{Grant: g, Signature: ed25519.Sign(root, msg)}
	}
	initial.Signed = signGrant(initial.Signed.Grant)
	cfg := copyLifecycleConfiguration(initial)
	cfg.Action = "cold-open-takeover"
	key, err := p.NewControllerKey()
	if err != nil {
		t.Fatal(err)
	}
	pin, err := p.PublicKeyFingerprint(key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	g := initial.Signed.Grant
	g.Operation, g.ID, g.Serial, g.ExpectedEpoch, g.NewKey = a.LifecycleTakeover, a.ID(lifecycleTestID(t)), 2, 1, a.Fingerprint(pin.String())
	cfg.Signed = signGrant(g)
	bootstrap, err := p.PublicKeyFingerprint(root.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	b := lifecycleTestBinding()
	cfg.Cold = &a.SignedLifecycleColdOpen{Request: a.LifecycleColdOpenRequest{
		OperationID: g.ID, Predecessor: a.LifecycleColdPredecessor{CurrentGrant: initial.Signed.Grant, ServiceEpoch: a.ID(lifecycleTestID(t)), ControllerEpoch: 1, ControllerKey: initial.Signed.Grant.NewKey, OpenRevision: 1, BootstrapKey: a.Fingerprint(bootstrap.String())},
		Takeover: copyLifecycleSigned(cfg.Signed), Launch: a.LifecycleColdLaunch{ShimLaunchUUID: a.ID(b.ShimLaunchUUID), Ext4UUID: b.Ext4UUID, Bytes: b.Bytes, SpecSHA256: strings.Repeat("a", 64), InitramfsSHA256: strings.Repeat("b", 64)}, NowUnixSeconds: cfg.NowUnixSeconds, LifetimeSeconds: cfg.LifetimeSeconds,
	}}
	lifecycleSignColdConfig(t, &cfg)
	return cfg, initial
}
func lifecycleSignColdConfig(t *testing.T, cfg *LifecycleConfiguration) {
	t.Helper()
	msg, err := a.LifecycleColdOpenSigningBytes(cfg.Cold.Request)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Cold.Signature = ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)), msg)
}

func TestLifecycleColdBootValidationAndCopies(t *testing.T) {
	cfg, _ := lifecycleColdConfig(t)
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	frame := lifecycleFrame("configure", lifecycleTestBinding())
	frame.Configuration = &cfg
	raw, err := EncodeLifecycleFrame(&frame)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ReadLifecycleFrame(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*LifecycleConfiguration){
		"missing":       func(c *LifecycleConfiguration) { c.Cold = nil },
		"initialize":    func(c *LifecycleConfiguration) { c.Action = "initialize" },
		"open":          func(c *LifecycleConfiguration) { c.Action = "open" },
		"reopen":        func(c *LifecycleConfiguration) { c.Reopen = &p.SignedLifecycleServiceChange{} },
		"now":           func(c *LifecycleConfiguration) { c.NowUnixSeconds++ },
		"lifetime":      func(c *LifecycleConfiguration) { c.LifetimeSeconds++ },
		"signature":     func(c *LifecycleConfiguration) { c.Cold.Signature[0] ^= 1 },
		"takeover-copy": func(c *LifecycleConfiguration) { c.Signed.Signature[0] ^= 1 },
		"inner-signature": func(c *LifecycleConfiguration) {
			c.Cold.Request.Takeover.Signature[0] ^= 1
			c.Signed = copyLifecycleSigned(c.Cold.Request.Takeover)
			lifecycleSignColdConfig(t, c)
		},
		"bootstrap-pin": func(c *LifecycleConfiguration) {
			c.Cold.Request.Predecessor.BootstrapKey = a.Fingerprint(strings.Repeat("c", 64))
			lifecycleSignColdConfig(t, c)
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := copyLifecycleConfiguration(cfg)
			mutate(&bad)
			if bad.validate() == nil {
				t.Fatal("accepted")
			}
		})
	}
	if cfg.validate() != nil {
		t.Fatal("copied signature mutations reached source")
	}
	if (&LifecycleReplacementRequest{PredecessorWorkerUUID: lifecycleTestID(t), Configuration: cfg}).validate() == nil {
		t.Fatal("cold accepted as replace-service")
	}
	h := lifecycleTestStart(t)
	h.Configuration = copyLifecycleConfiguration(cfg)
	h.VerifiedFresh = false
	raw, err = encodeLifecycleWorkerStart(h)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeLifecycleWorkerStart(raw)
	if err != nil || got.Configuration.Cold == nil {
		t.Fatal(err)
	}
	h.Binding.Bytes++
	if validLifecycleWorkerStart(&h) {
		t.Fatal("worker accepted wrong disk size")
	}
}

func TestLifecycleColdSupervisorRetainsNewGrantAndDetachedHandoff(t *testing.T) {
	cfg, _ := lifecycleColdConfig(t)
	starter := &fakeLifecycleStarter{mutate: func(r *LifecycleReady) { r.Revision, r.OpenRevision = 2, 2 }}
	start := starter.start(t)
	supervisor, err := newLifecycleSupervisor(cfg, func(handoff LifecycleConfiguration, worker string, gate workerStartGate) (lifecycleWorker, *LifecycleReady, error) {
		w, ready, err := start(handoff, worker, gate)
		handoff.Signed.Signature[0] ^= 1
		handoff.Cold.Signature[0] ^= 1
		handoff.Cold.Request.Takeover.Signature[0] ^= 1
		return w, ready, err
	})
	if supervisor != nil {
		defer supervisor.close()
	}
	if err != nil {
		t.Fatal(err)
	}
	if cfg.validate() != nil || !lifecycleSignedEqual(supervisor.signed, cfg.Signed) {
		t.Fatal("worker handoff mutated configuration or retained current grant")
	}
	request := lifecycleSupervisorCommand(supervisor.ready, "reconcile-controller")
	request.Signed = &cfg.Signed
	request.Controller = &a.Controller{Epoch: cfg.Signed.Grant.ExpectedEpoch + 1, Key: cfg.Signed.Grant.NewKey}
	if reply, code := supervisor.command(request); code != "" || reply == nil || reply.Ready == nil {
		t.Fatalf("exact cold current reconciliation refused: %s", code)
	}
	if result, code := supervisor.replaceService(LifecycleReplacementRequest{PredecessorWorkerUUID: supervisor.ready.WorkerUUID, Configuration: cfg}); result != nil || code != "replacement-conflict" {
		t.Fatal("cold action entered replace-service")
	}
	if calls, _ := starter.snapshot(); calls != 1 {
		t.Fatal("cold replacement started another worker")
	}
}

func TestLifecycleColdSessionChecksObservedLaunchBeforeStart(t *testing.T) {
	for _, field := range []string{"launch", "uuid", "bytes"} {
		t.Run(field, func(t *testing.T) {
			cfg, _ := lifecycleColdConfig(t)
			switch field {
			case "launch":
				cfg.Cold.Request.Launch.ShimLaunchUUID = a.ID(lifecycleTestID(t))
			case "uuid":
				cfg.Cold.Request.Launch.Ext4UUID = lifecycleTestID(t)
			case "bytes":
				cfg.Cold.Request.Launch.Bytes++
			}
			lifecycleSignColdConfig(t, &cfg)
			host, guest := net.Pipe()
			defer host.Close()
			done := make(chan error, 1)
			go func() {
				done <- lifecycleSession(context.Background(), guest, lifecycleTestBinding(), func(LifecycleConfiguration, string, workerStartGate) (lifecycleWorker, *LifecycleReady, error) {
					t.Error("mismatched launch reached constructor")
					return nil, nil, errFrame
				}, time.Second)
			}()
			if _, err := ReadLifecycleFrame(host); err != nil {
				t.Fatal(err)
			}
			f := lifecycleFrame("configure", lifecycleTestBinding())
			f.Configuration = &cfg
			if err := WriteLifecycleFrame(host, &f); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err == nil {
				t.Fatal("mismatched launch accepted")
			}
		})
	}
}

func TestLifecycleColdWorkerPostCommitFailureRetainsEvidence(t *testing.T) {
	cfg, initial := lifecycleColdConfig(t)
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	service, err := lifecycleConstruct(root, lifecycleTestBinding(), initial, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	meta, err := service.Scope()
	if err != nil {
		t.Fatal(err)
	}
	if err = service.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.Cold.Request.Predecessor.ServiceEpoch = meta.Epoch
	cfg.Cold.Request.Predecessor.OpenRevision = meta.OpenRevision
	lifecycleSignColdConfig(t, &cfg)
	h := lifecycleTestStart(t)
	h.Configuration = cfg
	h.VerifiedFresh = false
	failure := errors.New("listener acquisition failed after commit")
	err = serveLifecycleWorker(root, &h, func(service *s.LifecycleService) (func() error, error) { return nil, failure }, func([]byte) error { t.Error("published Ready after failure"); return nil }, func() ([]byte, error) { return nil, errors.New("unused") })
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
	// The exact retry must report retained durable application, not construct a
	// second service or turn endpoint failure into another E/C advance.
	before := lifecycleBootDisk(t, root.Name())
	retry, err := lifecycleWorkerConstruct(root, &h)
	if retry != nil || !errors.Is(err, a.ErrLifecycleColdAlreadyApplied) {
		if retry != nil {
			retry.Close()
		}
		t.Fatalf("retry=%v err=%v", retry, err)
	}
	if !reflect.DeepEqual(before, lifecycleBootDisk(t, root.Name())) {
		t.Fatal("retry mutated retained journal evidence")
	}
}

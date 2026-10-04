package storageboot

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	service "dev.cengine/guest/internal/storageservice"
	"golang.org/x/sys/unix"
)

func lifecycleChallengeFixture(t *testing.T, root *os.File, cfg LifecycleConfiguration, ready *LifecycleReady) lifecycleWorkerChallenge {
	var st unix.Stat_t
	must(t, unix.Fstat(int(root.Fd()), &st))
	return lifecycleWorkerChallenge{Version: 2, Type: lifecycleWorkerType, Operation: "challenge", WorkerUUID: lifecycleTestID(t), Binding: lifecycleTestBinding(), Root: workerRootIdentity{uint64(st.Dev), st.Ino, 1}, RootPublicKey: bytes.Clone(cfg.RootPublicKey), Current: copyLifecycleSigned(cfg.Signed), NowUnixSeconds: cfg.NowUnixSeconds, LifetimeSeconds: cfg.LifetimeSeconds, Predecessor: lifecycleServiceState(ready, cfg.Signed.Grant), IsolationRequest: *lifecycleIsolationRequest(t, ready, "second-service-exclusivity").IsolationRequest}
}

func TestLifecycleChallengeCodecClosed(t *testing.T) {
	root, err := os.Open(t.TempDir())
	must(t, err)
	defer root.Close()
	sup, _, cfg := newTestLifecycleSupervisor(t)
	h := lifecycleChallengeFixture(t, root, cfg, sup.ready)
	raw, err := encodeLifecycleWorkerChallenge(h)
	must(t, err)
	got, err := decodeLifecycleWorkerChallenge(raw)
	must(t, err)
	if !reflect.DeepEqual(h, *got) {
		t.Fatal("roundtrip")
	}
	if _, err := decodeLifecycleWorkerStart(raw); err == nil {
		t.Fatal("challenge became start")
	}
	for _, mutate := range []func(*lifecycleWorkerChallenge){
		func(h *lifecycleWorkerChallenge) { h.Operation = "start" },
		func(h *lifecycleWorkerChallenge) { h.Current.Signature[0] ^= 1 },
		func(h *lifecycleWorkerChallenge) { h.Predecessor.OpenRevision = 0 },
		func(h *lifecycleWorkerChallenge) { h.Predecessor.Boot.Identity.Generation++ },
		func(h *lifecycleWorkerChallenge) { h.Predecessor.Boot.BootstrapKey = lifecycleTestHex(t) },
		func(h *lifecycleWorkerChallenge) { h.Predecessor.Grant.Serial-- },
		func(h *lifecycleWorkerChallenge) { h.IsolationRequest.RequestID = "" },
		func(h *lifecycleWorkerChallenge) { h.LifetimeSeconds = 86401 },
		func(h *lifecycleWorkerChallenge) { h.Root.MountID = 0 },
	} {
		bad, _ := decodeLifecycleWorkerChallenge(raw)
		mutate(bad)
		if _, err := encodeLifecycleWorkerChallenge(*bad); err == nil {
			t.Fatal("bad challenge")
		}
	}
	for _, bad := range [][]byte{
		append(bytes.Clone(raw), ' '),
		bytes.Replace(raw, []byte(`"version":2`), []byte(`"version":2,"version":2`), 1),
		bytes.Replace(raw, []byte(`"version":2`), []byte(`"configuration":null,"version":2`), 1),
		bytes.Replace(raw, []byte(`"open_revision":1`), []byte(`"open_revision":1.0`), 1),
	} {
		if bytes.Equal(raw, bad) {
			t.Fatal("mutation missed")
		}
		if _, err := decodeLifecycleWorkerChallenge(bad); err == nil {
			t.Fatal("noncanonical accepted")
		}
	}
	locked, err := lifecycleLockRefusalPacket(h)
	must(t, err)
	if _, err := decodeLifecycleWorkerChallenge(locked); err == nil {
		t.Fatal("locked accepted as challenge")
	}
	var tree map[string]json.RawMessage
	must(t, json.Unmarshal(locked, &tree))
	if string(tree["operation"]) != `"locked"` {
		t.Fatal("refusal")
	}
}

func lifecycleChallengeTakeover(t *testing.T, owner *service.LifecycleService, cfg LifecycleConfiguration) a.SignedLifecycleGrant {
	key, err := p.NewControllerKey()
	must(t, err)
	fp, err := p.PublicKeyFingerprint(key.PublicKey())
	must(t, err)
	g := cfg.Signed.Grant
	g.Operation = a.LifecycleTakeover
	g.ExpectedEpoch = 1
	g.Serial++
	g.ID = a.ID(lifecycleTestID(t))
	g.NewKey = a.Fingerprint(fp.String())
	msg, err := a.LifecycleGrantSigningBytes(g)
	must(t, err)
	signed := a.SignedLifecycleGrant{Grant: g, Signature: ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)), msg)}
	binding, err := p.NewControllerBinding(p.StoreID(g.Identity.Store), 2)
	must(t, err)
	csr, err := key.CSR(binding)
	must(t, err)
	cert, err := owner.AuthorizeSuccessor(signed, csr)
	must(t, err)
	identity, err := cert.WithKey(key)
	must(t, err)
	ready, err := owner.Ready()
	must(t, err)
	ca, err := p.ParseRootDER(ready.TLSRootDER)
	must(t, err)
	clientRaw, serverRaw := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- owner.ServeLifecycle(context.Background(), serverRaw) }()
	client, err := c.NewLifecycleClient(context.Background(), clientRaw, c.LifecycleClientConfig{Identity: identity, ServerRoot: ca, ServerKey: ready.ServerKey, Hello: c.LifecycleHello{Version: c.LifecycleControlVersion, Identity: g.Identity, ServiceEpoch: ready.ServiceEpoch, ControllerEpoch: 2}})
	must(t, err)
	controller, err := client.Takeover(context.Background(), signed)
	must(t, err)
	client.Close()
	<-done
	must(t, owner.ReconcileController(controller))
	return signed
}

func TestLifecycleChallengeActualConstructorLockAndTakeover(t *testing.T) {
	if pc.CurrentProfile() != pc.FullProfile {
		if b, err := lifecycleServiceLockRefusal(nil, lifecycleWorkerChallenge{}); b != nil || err == nil {
			t.Fatal("ordinary executed")
		}
		return
	}
	// Use a serial with room for a real authenticated takeover.
	_, cfg := lifecycleColdConfig(t)
	cfg.NowUnixSeconds = uint64(time.Now().Add(-time.Minute).Unix())
	root, err := os.Open(t.TempDir())
	must(t, err)
	defer root.Close()
	owner, err := lifecycleConstruct(root, lifecycleTestBinding(), cfg, func() error { return nil })
	must(t, err)
	defer owner.Close()
	for _, takeover := range []bool{false, true} {
		if takeover {
			cfg.Signed = lifecycleChallengeTakeover(t, owner, cfg)
		}
		ready, err := lifecyclePublicReady(owner, lifecycleTestID(t))
		must(t, err)
		h := lifecycleChallengeFixture(t, root, cfg, ready)
		before, err := owner.ProbeIsolation("isolation-state")
		must(t, err)
		refusal, err := lifecycleServiceLockRefusal(root, h)
		must(t, err)
		expected, err := lifecycleLockRefusalPacket(h)
		must(t, err)
		if !bytes.Equal(refusal, expected) {
			t.Fatal("not exact locked packet")
		}
		after, err := owner.ProbeIsolation("isolation-state")
		must(t, err)
		if before.RegistrySHA256 != after.RegistrySHA256 || before.Revision != after.Revision {
			t.Fatal("challenger mutated live owner")
		}
		h.Root.Inode++
		if raw, err := lifecycleServiceLockRefusal(root, h); raw != nil || err == nil {
			t.Fatal("wrong actual root")
		}
	}
	ready, err := lifecyclePublicReady(owner, lifecycleTestID(t))
	must(t, err)
	h := lifecycleChallengeFixture(t, root, cfg, ready)
	must(t, owner.Close())
	// A real unexpectedly successful reopen must close/fail, never emit locked.
	if raw, err := lifecycleServiceLockRefusal(root, h); raw != nil || err == nil {
		t.Fatal("successful reopen claimed locked")
	}
	// Empty layouts must not initialize; all non-lock errors fail closed.
	empty, err := os.Open(t.TempDir())
	must(t, err)
	defer empty.Close()
	h = lifecycleChallengeFixture(t, empty, cfg, ready)
	if raw, err := lifecycleServiceLockRefusal(empty, h); raw != nil || err == nil {
		t.Fatal("missing registry claimed locked")
	}
}

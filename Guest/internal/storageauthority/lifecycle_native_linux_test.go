//go:build linux

package storageauthority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

// RTM-113 exercises storage authority checkpoints and terminal sealing. The
// wrapper supplies its existing bounded loop ext4 at /scratch. ROOT here is a
// test-owned Ed25519 key, NOT installed ROOT or a nonexporting helper key. Real
// TLS and filesystem IO establish component byte ordering, not power-loss,
// VM-death, installed-helper authentication, host-history, or disk-deletion proof.
// This fresh empty store has no registered volumes/attachments: no DATA or
// attachment-drain claim is made.
func TestNativeLifecycleCheckpointAndTerminalSeal(t *testing.T) {
	var scratchFS unix.Statfs_t
	err := unix.Statfs("/scratch", &scratchFS)
	if os.IsNotExist(err) || (err == nil && scratchFS.Type != unix.EXT4_SUPER_MAGIC) {
		t.Skip("requires native /scratch ext4 fixture")
	}
	must(t, err)
	if scratchFS.Flags&unix.ST_RDONLY != 0 {
		t.Fatal("scratch is read-only")
	}
	var scratch unix.Stat_t
	must(t, unix.Stat("/scratch", &scratch))
	for _, path := range []string{"/", "/tmp"} {
		var other unix.Stat_t
		must(t, unix.Stat(path, &other))
		if scratch.Dev == other.Dev {
			t.Fatalf("scratch must be distinct from %s", path)
		}
	}
	base, err := os.MkdirTemp("/scratch", "rtm113-")
	must(t, err)
	t.Cleanup(func() { must(t, os.RemoveAll(base)) })
	// Reuse the real certificate/handshake fixture with a separate fresh store.
	// Both roots are owned here and live on the checked ext4.
	tlsPath := filepath.Join(base, "tls-fixture")
	must(t, os.Mkdir(tlsPath, 0700))
	f := newFixtureAt(t, nil, tlsPath)
	must(t, f.a.Close())
	f.path = filepath.Join(base, "fresh-store")
	must(t, os.Mkdir(f.path, 0700))
	must(t, os.Mkdir(filepath.Join(f.path, "volumes"), 0700))
	root, err := os.Open(f.path)
	must(t, err)
	t.Cleanup(func() { must(t, root.Close()) })
	var rootFS unix.Statfs_t
	must(t, unix.Fstatfs(int(root.Fd()), &rootFS))
	var rootStat unix.Stat_t
	must(t, unix.Fstat(int(root.Fd()), &rootStat))
	if rootFS.Type != unix.EXT4_SUPER_MAGIC || rootStat.Dev != scratch.Dev {
		t.Fatal("owned root escaped ext4 scratch")
	}
	// Explicit baseline file and directory fsyncs on the actual filesystem,
	// not a successful mock barrier or a /tmp-backed authority fixture.
	baseline := []byte("RTM-113 fresh empty lifecycle component baseline\n")
	file, err := os.OpenFile(filepath.Join(f.path, "baseline"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(t, err)
	_, err = file.Write(baseline)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	must(t, err)
	must(t, closeErr)
	for _, path := range []string{filepath.Join(f.path, "volumes"), f.path, base, "/scratch"} {
		dir, err := os.Open(path)
		must(t, err)
		err = dir.Sync()
		closeErr := dir.Close()
		must(t, err)
		must(t, closeErr)
	}
	f.c = Config{Root: root, DeviceID: "rtm113-test-owned-ext4", BootstrapKey: f.bootstrap.Public().(ed25519.PublicKey),
		Barrier: func(Binding, *os.File) error {
			t.Error("empty lifecycle store must not claim an attachment barrier")
			return ErrBlocked
		}}
	initial := signLifecycle(t, f.bootstrap, LifecycleGrant{LifecycleInitialize, mustID(t),
		LifecycleIdentity{mustID(t), 7, fp(t, newKey(t))}, 11, 0, fp(t, f.controllerKey)})
	a, err := InitializeLifecycle(f.c, initial)
	must(t, err)
	f.a = a
	control := func(key ed25519.PrivateKey, epoch uint64) *ControllerPrincipal {
		t.Helper()
		conn := f.conn(key, tls.VersionTLS13, true)
		defer conn.NetConn().Close() // no blocked close-notify on the net.Pipe peer
		p, err := f.a.AuthenticateController(context.Background(), conn, epoch)
		must(t, err)
		return p
	}
	successor := func(key ed25519.PrivateKey) *SuccessorPrincipal {
		t.Helper()
		conn := f.conn(key, tls.VersionTLS13, true)
		defer conn.NetConn().Close()
		p, err := f.a.AuthenticateSuccessor(context.Background(), conn)
		must(t, err)
		return p
	}
	unchanged := func(before map[string]string) {
		t.Helper()
		if !reflect.DeepEqual(before, lifecycleFiles(t, f)) {
			t.Fatal("refusal/retry changed retained registry files")
		}
	}
	f.control = control(f.controllerKey, 1)
	firstControl, firstKey := f.control, f.controllerKey
	var first, latest SignedLifecycleGrant
	var firstSuccessorKey ed25519.PrivateKey
	// 65 actual TLS takeovers (epoch 66) exercise bounded checkpoint history.
	for i := uint64(0); i < 65; i++ {
		key := newKey(t)
		latest = signLifecycle(t, f.bootstrap, LifecycleGrant{LifecycleTakeover, mustID(t), initial.Grant.Identity, 12 + i, 1 + i, fp(t, key)})
		if i == 0 {
			first, firstSuccessorKey = latest, key
		}
		prior := f.control
		got, err := f.a.TakeoverLifecycle(successor(key), latest)
		must(t, err)
		if got != (Controller{2 + i, latest.Grant.NewKey}) {
			t.Fatal("controller tuple did not advance")
		}
		_, err = f.a.Query(prior)
		wantErr(t, err, ErrUnauthorized)
		f.controllerKey, f.control = key, control(key, got.Epoch)
		files := lifecycleFiles(t, f)
		if len(files) != 2 || len(files[stateName]) > 2500 || f.a.s.Grants != nil || f.a.s.ControllerKeys != nil || len(f.a.s.Operations) != 0 {
			t.Fatal("checkpoint history grew beyond the bounded current tuple")
		}
		var disk diskState
		must(t, json.Unmarshal([]byte(files[stateName]), &disk))
		if disk.Schema != LifecycleSchemaVersion || disk.Controller != got || disk.Lifecycle.Latest.Grant != latest.Grant || disk.Lifecycle.Identity != initial.Grant.Identity {
			t.Fatal("durable checkpoint lost coupled identity/epoch/key/serial tuple")
		}
	}
	must(t, f.a.validate())
	latestApplied, latestController := f.a.s.Lifecycle.Latest, f.a.s.Controller
	must(t, f.a.Close())
	before := lifecycleFiles(t, f)
	refuse := func(call func() (*Authority, error)) {
		t.Helper()
		opened, err := call()
		if err == nil {
			opened.Close()
			t.Fatal("existing-store initialization or mismatched/sealed reopen accepted")
		}
		unchanged(before)
	}
	// Before retirement, an existing registry rejects initialization and any
	// reopen with a mismatched identity.
	refuse(func() (*Authority, error) { return InitializeLifecycle(f.c, initial) })
	for _, identity := range []LifecycleIdentity{
		{mustID(t), initial.Grant.Identity.Generation, initial.Grant.Identity.Binding},
		{initial.Grant.Identity.Store, initial.Grant.Identity.Generation - 1, initial.Grant.Identity.Binding},
		{initial.Grant.Identity.Store, initial.Grant.Identity.Generation, fp(t, newKey(t))},
	} {
		refuse(func() (*Authority, error) { return OpenLifecycle(f.c, identity) })
	}
	a, err = OpenLifecycle(f.c, initial.Grant.Identity)
	must(t, err)
	f.a = a
	if f.a.s.Controller != latestController || f.a.s.Lifecycle.Latest != latestApplied {
		t.Fatal("reopen lost latest coupled checkpoint")
	}
	f.control = control(f.controllerKey, latestController.Epoch)
	before = lifecycleFiles(t, f)
	_, err = f.a.TakeoverLifecycle(successor(f.controllerKey), latest)
	must(t, err) // exact latest retry is read-only, including after reopen
	unchanged(before)
	_, err = f.a.TakeoverLifecycle(successor(firstSuccessorKey), first)
	wantErr(t, err, ErrUnauthorized)
	_, err = f.a.Query(firstControl)
	wantErr(t, err, ErrUnauthorized)
	for _, item := range []struct {
		key   ed25519.PrivateKey
		epoch uint64
	}{{firstKey, 1}, {firstSuccessorKey, 2}, {f.controllerKey, latestController.Epoch - 1}} {
		conn := f.conn(item.key, tls.VersionTLS13, true)
		_, err = f.a.AuthenticateController(context.Background(), conn, item.epoch)
		conn.NetConn().Close()
		wantErr(t, err, ErrUnauthorized)
	}
	freshKey := newKey(t)
	fresh := successor(freshKey)
	next := LifecycleGrant{LifecycleTakeover, mustID(t), initial.Grant.Identity, latest.Grant.Serial + 1, latestController.Epoch, fp(t, freshKey)}
	// Isolate stale current grant ID, old generation, epoch and serial. An old
	// key cannot impersonate the fresh key, even with a valid ROOT signature.
	for _, mutate := range []func(*LifecycleGrant){
		func(g *LifecycleGrant) { g.ID = latest.Grant.ID },
		func(g *LifecycleGrant) { g.Identity.Generation-- },
		func(g *LifecycleGrant) { g.ExpectedEpoch-- },
		func(g *LifecycleGrant) { g.Serial = first.Grant.Serial },
		func(g *LifecycleGrant) { g.NewKey = first.Grant.NewKey },
	} {
		bad := next
		mutate(&bad)
		_, err = f.a.TakeoverLifecycle(fresh, signLifecycle(t, f.bootstrap, bad))
		wantErr(t, err, ErrUnauthorized)
		unchanged(before)
	}
	if len(f.a.s.Volumes) != 0 || len(f.a.s.Attachments) != 0 || len(f.a.runtime) != 0 {
		t.Fatal("component must remain an empty store")
	}
	grant := lifecycleRetirement(t, f)
	var steps []string
	f.a.j.afterStep = func(name string) {
		switch name {
		case "marker-parent-sync", "state-parent-sync", "lifecycle-exports-sync", "lifecycle-root-sync", "lifecycle-registry-sync":
			steps = append(steps, name)
		}
	}
	must(t, f.a.RetireLifecycle(f.control, grant))
	f.a.j.afterStep = nil
	if !reflect.DeepEqual(steps, []string{"marker-parent-sync", "state-parent-sync", "lifecycle-exports-sync", "lifecycle-root-sync", "lifecycle-registry-sync", "state-parent-sync"}) {
		t.Fatalf("terminal filesystem ordering: %v", steps)
	}
	must(t, f.a.validate())
	before = lifecycleFiles(t, f)
	if _, ok := before[lifecycleFenceName]; !ok || len(before) != 3 || len(before[stateName]) > 4096 || f.a.s.Lifecycle.Seal == nil {
		t.Fatal("bounded terminal fence/seal evidence not retained")
	}
	var sealed diskState
	must(t, json.Unmarshal([]byte(before[stateName]), &sealed))
	if sealed.Lifecycle == nil || sealed.Lifecycle.Seal == nil || *sealed.Lifecycle.Seal != *f.a.s.Lifecycle.Seal || sealed.Controller != latestController || sealed.Lifecycle.Latest != latestApplied {
		t.Fatal("disk seal lost coupled checkpoint/terminal receipt tuple")
	}
	_, err = f.a.Query(f.control)
	wantErr(t, err, ErrBlocked)
	wantErr(t, f.a.RetireLifecycle(f.control, grant), ErrBlocked)
	_, err = f.a.TakeoverLifecycle(fresh, signLifecycle(t, f.bootstrap, next))
	wantErr(t, err, ErrBlocked)
	conn := f.conn(f.controllerKey, tls.VersionTLS13, true)
	_, err = f.a.AuthenticateController(context.Background(), conn, latestController.Epoch)
	wantErr(t, err, ErrBlocked)
	readOnly, err := f.a.AuthenticateLifecycleResult(context.Background(), conn, latestController.Epoch)
	conn.NetConn().Close()
	must(t, err)
	_, err = f.a.Query(readOnly)
	wantErr(t, err, ErrBlocked)
	var receipt LifecycleReceipt
	for i := 0; i < 2; i++ {
		nonce := make([]byte, 32)
		_, err = rand.Read(nonce)
		must(t, err)
		got, err := f.a.LifecycleResult(readOnly, grant.Grant, nonce)
		must(t, err)
		seal := f.a.s.Lifecycle.Seal
		if got.Grant != grant.Grant || got.ServiceEpoch != seal.ServiceEpoch || got.Revision != seal.Revision || !bytes.Equal(got.Nonce, nonce) {
			t.Fatal("seal receipt lost exact durable tuple/fresh nonce")
		}
		if i > 0 && (got.ServiceEpoch != receipt.ServiceEpoch || got.Revision != receipt.Revision || got.Grant != receipt.Grant || bytes.Equal(got.Nonce, receipt.Nonce)) {
			t.Fatal("seal result not stable with fresh nonce")
		}
		receipt = got
		unchanged(before)
	}
	must(t, f.a.Close())
	for i := 0; i < 2; i++ {
		refuse(func() (*Authority, error) { return OpenLifecycle(f.c, initial.Grant.Identity) })
		refuse(func() (*Authority, error) { return InitializeLifecycle(f.c, initial) })
	}
	gotBaseline, err := os.ReadFile(filepath.Join(f.path, "baseline"))
	must(t, err)
	volumes, err := os.ReadDir(filepath.Join(f.path, "volumes"))
	must(t, err)
	rootEntries, err := os.ReadDir(f.path)
	must(t, err)
	if !bytes.Equal(gotBaseline, baseline) || len(volumes) != 0 || len(rootEntries) != 3 {
		t.Fatal("owned baseline, empty exports or root namespace changed")
	}
	t.Logf("storage authority component: 65 TLS takeovers, epoch %d, %d checkpoint bytes, terminal seal retained; no host/activation/DATA/drain/power-loss/deletion claim", latestController.Epoch, len(before[stateName]))
}

//go:build cengine_native_faulttest && linux && (arm64 || amd64)

package storageserver

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	at "dev.cengine/guest/internal/storageauthoritytest"
	p "dev.cengine/guest/internal/storagepki"
)

// Use the actual PKI constructor and authority barrier, not a literal Server:
// NewPKIWithResources binds authority before the first DATA connection.
func nativeFaultServer(t *testing.T) (*Server, *a.NativeFaultWitness) {
	t.Helper()
	r, err := NewResources()
	must(t, err)
	path := t.TempDir()
	must(t, os.Mkdir(filepath.Join(path, "volumes"), 0700))
	root, err := os.Open(path)
	must(t, err)
	t.Cleanup(func() { root.Close() })
	bootstrapPrivate := key(t)
	bootstrap := bootstrapPrivate.Public().(ed25519.PublicKey)
	owner, err := at.New(t, bootstrapPrivate, id(t), fingerprint(t, key(t))).Initialize(a.Config{Root: root, DeviceID: "native-installer-test", BootstrapKey: bootstrap, Barrier: r.Barrier})
	must(t, err)
	t.Cleanup(func() { must(t, owner.Close()) })
	meta, err := owner.StartupMetadata()
	must(t, err)
	boot, err := p.NewBootstrapPublicKey(bootstrap)
	must(t, err)
	now := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	issuer, err := p.NewIssuer(now, time.Hour, boot)
	must(t, err)
	binding, err := p.NewServerBinding(p.StoreID(meta.Store.ID), p.ServiceEpoch(meta.Epoch))
	must(t, err)
	key, err := p.NewServerKey()
	must(t, err)
	csr, err := key.CSR(binding)
	must(t, err)
	cert, err := issuer.IssueServer(csr, binding, now, time.Hour)
	must(t, err)
	identity, err := cert.WithKey(key)
	must(t, err)
	server, err := NewPKIWithResources(r, owner, PKIConfig{Identity: identity, ClientRoot: issuer.Root(), Store: meta.Store.ID, ServiceEpoch: meta.Epoch, RequestRetirement: func(a.DataHello, error) {}})
	must(t, err)
	witness, err := owner.NewNativeFaultWitness(a.NativeFaultPlan{Stage: a.NativeDataFsync, Error: a.NativeEIO, Store: meta.Store.ID, Epoch: meta.Epoch, Volume: id(t), Attachment: id(t), Sequence: 3})
	must(t, err)
	return server, witness
}

func TestNativeFaultPKIInstallClosed(t *testing.T) {
	t.Run("bound-owner-before-traffic", func(t *testing.T) {
		s, witness := nativeFaultServer(t)
		counter, err := s.InstallNativeFault(witness)
		must(t, err)
		if counter == nil || counter.Observation() != (a.NativeFaultObservation{}) {
			t.Fatal("installation must not fire or fabricate fault observations")
		}
		if _, err := s.InstallNativeFault(witness); !errors.Is(err, a.ErrConflict) {
			t.Fatalf("duplicate install: %v", err)
		}
	})
	for _, name := range []string{"nil-witness", "foreign-owner", "wrong-store", "wrong-epoch", "no-pki", "no-owner", "closed-owner"} {
		t.Run(name, func(t *testing.T) {
			s, witness := nativeFaultServer(t)
			want := a.ErrConflict
			switch name {
			case "nil-witness":
				witness, want = nil, a.ErrInvalid
			case "foreign-owner":
				_, witness = nativeFaultServer(t)
				// Match public S/E so pointer ownership is the decisive rejection.
				s.pki.Store, s.pki.ServiceEpoch = witness.Plan().Store, witness.Plan().Epoch
			case "wrong-store":
				s.pki.Store = id(t)
			case "wrong-epoch":
				s.pki.ServiceEpoch = id(t)
			case "no-pki":
				s.pki = nil
			case "no-owner":
				s.authority = nil
			case "closed-owner":
				must(t, s.authority.Close())
			}
			if counter, err := s.InstallNativeFault(witness); counter != nil || !errors.Is(err, want) {
				t.Fatalf("install returned counter=%v err=%v, want %v", counter, err, want)
			}
		})
	}
	t.Run("active-serve", func(t *testing.T) {
		s, witness := nativeFaultServer(t)
		raw, client := net.Pipe()
		defer client.Close()
		entered := make(chan struct{})
		done := make(chan error, 1)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { done <- s.Serve(ctx, s.authority, &nativeFaultReadConn{Conn: raw, entered: entered}) }()
		defer func() { cancel(); client.Close(); _ = wait(t, done) }()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("Serve did not reach TLS read")
		}
		if counter, err := s.InstallNativeFault(witness); counter != nil || !errors.Is(err, a.ErrBusy) {
			t.Fatalf("active Serve install: counter=%v err=%v", counter, err)
		}
	})
}

type nativeFaultReadConn struct {
	net.Conn
	entered chan struct{}
}

func (c *nativeFaultReadConn) Read(b []byte) (int, error) {
	if c.entered != nil {
		close(c.entered)
		c.entered = nil
	}
	return c.Conn.Read(b)
}

// A previously minted witness cannot become installable when DATA closes. This
// uses the existing authenticated transport fixture; its test executor avoids
// requiring a privileged mount merely to exercise the installation guard.
func TestNativeFaultWitnessRejectsUsedDATA(t *testing.T) {
	f := newFixture(t, Limits{}, false)
	meta, err := f.a.StartupMetadata()
	must(t, err)
	witness, err := f.a.NewNativeFaultWitness(a.NativeFaultPlan{Stage: a.NativeDataFsync, Error: a.NativeEIO, Store: meta.Store.ID, Epoch: meta.Epoch, Volume: f.volume, Attachment: id(t), Sequence: 3})
	must(t, err)
	if !witness.ReadyForInstall(f.a) {
		t.Fatal("fresh owning authority rejected")
	}
	client, done, _ := f.connected()
	if witness.ReadyForInstall(f.a) {
		t.Error("active authenticated DATA accepted")
	}
	client.NetConn().Close()
	_ = wait(t, done)
	if len(f.s.connections) != 0 || witness.ReadyForInstall(f.a) {
		t.Fatal("closed DATA reopened installation window")
	}
}

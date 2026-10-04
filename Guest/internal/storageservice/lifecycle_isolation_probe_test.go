package storageservice

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
	w "dev.cengine/guest/internal/storagewire"
)

func lifecycleIsolationListener(t *testing.T, s *LifecycleService, handler func(context.Context, net.Conn) error) (net.Listener, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	must(t, s.BindCompatibilityDataListener(listener.Addr()))
	ctx, cancel := context.WithCancel(context.Background())
	results := make(chan error, 8)
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				results <- handler(ctx, conn)
			}()
		}
	}()
	t.Cleanup(func() { listener.Close(); cancel(); workers.Wait() })
	return listener, results
}

func lifecycleIsolationResult(t *testing.T, results <-chan error) error {
	t.Helper()
	select {
	case err := <-results:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("DATA handler did not join")
		return nil
	}
}

func TestLifecycleIsolationProfileAndState(t *testing.T) {
	f := newLifecycleServiceFixture(t) // Real ROOT-signed InitializeLifecycle.
	before, err := f.s.Ready()
	must(t, err)
	journal := lifecycleServiceJournal(t, f)
	for _, kind := range []string{"", "forged", "second-service-exclusivity"} {
		if proof, err := f.s.ProbeIsolation(kind); proof != nil || !errors.Is(err, a.ErrUnauthorized) {
			t.Fatalf("unsupported %q: proof=%+v err=%v", kind, proof, err)
		}
	}
	if pc.CurrentProfile() != pc.FullProfile {
		for _, kind := range []string{"isolation-state", "legacy-connection"} {
			if proof, err := f.s.ProbeIsolation(kind); proof != nil || !errors.Is(err, a.ErrUnauthorized) {
				t.Fatalf("ordinary profile admitted %s: %+v %v", kind, proof, err)
			}
		}
		must(t, f.s.BindCompatibilityDataListener(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}))
		if f.s.owner.isolationAddress != "" {
			t.Fatal("ordinary profile retained endpoint")
		}
	} else {
		digest, err := f.s.owner.authority.CompatibilityStateDigest()
		must(t, err)
		proof, err := f.s.ProbeIsolation("isolation-state")
		must(t, err)
		want := &IsolationProof{CaseName: "isolation-state", Store: string(before.Store.ID), ServiceEpoch: string(before.ServiceEpoch), Revision: before.Revision, RegistrySHA256: digest, Result: "registry-state"}
		if !reflect.DeepEqual(proof, want) || len(digest) != 64 {
			t.Fatalf("incorrect lifecycle proof: %+v", proof)
		}
	}
	after, err := f.s.Ready()
	must(t, err)
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(journal, lifecycleServiceJournal(t, f)) {
		t.Fatal("observation changed Ready or journal")
	}
}

func TestLifecycleIsolationLegacyActualBoundDATA(t *testing.T) {
	if pc.CurrentProfile() != pc.FullProfile {
		t.Skip("full-profile observation only")
	}
	f := newLifecycleServiceFixture(t)
	for _, addr := range []net.Addr{nil, &net.UnixAddr{Name: "wrong", Net: "unix"}, &net.TCPAddr{IP: net.IPv4zero, Port: 12}, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}} {
		if err := f.s.BindCompatibilityDataListener(addr); !errors.Is(err, a.ErrInvalid) {
			t.Fatalf("accepted invalid listener %v: %v", addr, err)
		}
	}
	listener, results := lifecycleIsolationListener(t, f.s, f.s.ServeDataConnection)
	if err := f.s.BindCompatibilityDataListener(listener.Addr()); !errors.Is(err, a.ErrConflict) {
		t.Fatal("rebound DATA listener", err)
	}
	before, err := f.s.Ready()
	must(t, err)
	digest, err := f.s.owner.authority.CompatibilityStateDigest()
	must(t, err)
	proof, err := f.s.ProbeIsolation("legacy-connection")
	must(t, err)
	want := &IsolationProof{CaseName: "legacy-connection", Store: string(before.Store.ID), ServiceEpoch: string(before.ServiceEpoch), Revision: before.Revision, RegistrySHA256: digest, Result: "legacy-tls-header-rejected"}
	if !reflect.DeepEqual(proof, want) {
		t.Fatalf("wrong bound-listener proof: %+v", proof)
	}
	// Independently inspect the real TLS error's exact legacy length-prefix/header.
	// The historical canonical payload is 165 bytes and starts with '{'.
	// Keep this expected wire header independent of the producer's literal.
	header := [5]byte{0, 0, 0, 165, '{'}
	var rejected tls.RecordHeaderError
	if err := lifecycleIsolationResult(t, results); !errors.As(err, &rejected) || rejected.RecordHeader != header {
		t.Fatalf("not the exact legacy TLS header rejection: %v", err)
	}
	after, err := f.s.Ready()
	must(t, err)
	final, err := f.s.owner.authority.CompatibilityStateDigest()
	must(t, err)
	f.s.owner.mu.Lock()
	active := f.s.owner.dataActive
	f.s.owner.mu.Unlock()
	if active != 0 || !reflect.DeepEqual(before, after) || final != digest {
		t.Fatal("probe returned before cleanup or changed Ready/hidden registry")
	}
}

func TestLifecycleIsolationRejectsMissingCompletion(t *testing.T) {
	if pc.CurrentProfile() != pc.FullProfile {
		t.Skip("full-profile observation only")
	}
	for _, mode := range []string{"unbound", "refused", "eof", "timeout", "unjoined"} {
		t.Run(mode, func(t *testing.T) {
			f := newLifecycleServiceFixture(t)
			before, err := f.s.Ready()
			must(t, err)
			digest, err := f.s.owner.authority.CompatibilityStateDigest()
			must(t, err)
			if mode == "refused" {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				must(t, err)
				must(t, f.s.BindCompatibilityDataListener(listener.Addr()))
				must(t, listener.Close())
			} else if mode != "unbound" {
				lifecycleIsolationListener(t, f.s, func(ctx context.Context, conn net.Conn) error {
					defer conn.Close()
					switch mode {
					case "timeout":
						<-ctx.Done()
					case "unjoined":
						return f.s.ServeData(ctx, conn) // Real rejection, but no joined publication.
					}
					return nil
				})
			}
			if proof, err := f.s.ProbeIsolation("legacy-connection"); err == nil || proof != nil {
				t.Fatalf("%s passed as rejection: %+v %v", mode, proof, err)
			}
			after, err := f.s.Ready()
			must(t, err)
			final, err := f.s.owner.authority.CompatibilityStateDigest()
			must(t, err)
			if !reflect.DeepEqual(before, after) || final != digest {
				t.Fatal("failed probe changed authority")
			}
		})
	}
}

func TestLifecycleIsolationHiddenLedgerAndDuringProbeMutation(t *testing.T) {
	if pc.CurrentProfile() != pc.FullProfile {
		t.Skip("full-profile observation only")
	}
	for _, mode := range []string{"ledger", "side-file", "during-probe"} {
		t.Run(mode, func(t *testing.T) {
			f := newLifecycleServiceFixture(t)
			before, err := f.s.Ready()
			must(t, err)
			proof, err := f.s.ProbeIsolation("isolation-state")
			must(t, err)
			path := filepath.Join(f.cfg.Root.Name(), ".cengine-storage-authority", "state.json")
			if mode == "ledger" {
				original, err := os.ReadFile(path)
				must(t, err)
				old := []byte(`"operations":{}`)
				changed := []byte(`"operations":{"11111111-1111-4111-8111-111111111111":{"kind":"hidden-test","digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`)
				if !bytes.Contains(original, old) {
					t.Fatal("missing empty operation ledger")
				}
				must(t, os.WriteFile(path, bytes.Replace(original, old, changed, 1), 0600))
				defer os.WriteFile(path, original, 0600)
				if got, err := f.s.ProbeIsolation("isolation-state"); err == nil || got != nil {
					t.Fatal("disk/memory hidden ledger mismatch accepted")
				}
			} else {
				extra := filepath.Join(filepath.Dir(path), "hidden-side-file")
				if mode == "side-file" {
					must(t, os.WriteFile(extra, []byte("hidden"), 0600))
					got, err := f.s.ProbeIsolation("isolation-state")
					must(t, err)
					if got.RegistrySHA256 == proof.RegistrySHA256 {
						t.Fatal("digest omitted hidden side-file")
					}
				} else {
					_, results := lifecycleIsolationListener(t, f.s, func(ctx context.Context, conn net.Conn) error {
						if err := os.WriteFile(extra, []byte("hidden"), 0600); err != nil {
							conn.Close()
							return err
						}
						return f.s.ServeDataConnection(ctx, conn)
					})
					if got, err := f.s.ProbeIsolation("legacy-connection"); got != nil || !errors.Is(err, a.ErrConflict) {
						t.Fatalf("mid-probe hidden change accepted: %+v %v", got, err)
					}
					var rejected tls.RecordHeaderError
					if err := lifecycleIsolationResult(t, results); !errors.As(err, &rejected) {
						t.Fatal("did not reach real TLS rejection", err)
					}
				}
			}
			after, err := f.s.Ready()
			must(t, err)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("hidden-state test unexpectedly changed public Ready")
			}
		})
	}
}

// The wrapper must preserve current lifecycle TLS, including in ordinary builds.
// Stop at ServerHello: this is TLS coverage, not a fabricated native root grant.
func TestLifecycleIsolationJoinedHandlerPreservesTLS(t *testing.T) {
	f, controller, ready, hello, key, csr := lifecycleAttachmentFixture(t)
	raw, join := serve(t, f.s.ServeAttachmentCSR)
	cert, err := RequestLifecycleAttachmentCertificate(t.Context(), raw, controller, ready, f.initial.Grant.Identity, hello, csr)
	must(t, err)
	must(t, join())
	identity, err := cert.WithKey(key)
	must(t, err)
	root, err := p.ParseRootDER(ready.TLSRootDER)
	must(t, err)
	server, err := p.NewServerBinding(p.StoreID(ready.Store.ID), p.ServiceEpoch(ready.ServiceEpoch))
	must(t, err)
	cfg, err := p.ClientTLSConfig(identity, root, server, ready.ServerKey)
	must(t, err)
	listener, results := lifecycleIsolationListener(t, f.s, f.s.ServeDataConnection)
	raw, err = net.Dial("tcp", listener.Addr().String())
	must(t, err)
	conn := tls.Client(raw, cfg)
	defer conn.Close()
	must(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	must(t, conn.HandshakeContext(t.Context()))
	var greeting w.ServerHello
	must(t, w.ReadFrame(conn, &greeting))
	if greeting.Epoch != ready.ServiceEpoch || greeting.Version != w.Version || greeting.Profile != w.RequiredProfile() {
		t.Fatalf("wrong lifecycle DATA greeting: %+v", greeting)
	}
	conn.Close()
	if err := lifecycleIsolationResult(t, results); err == nil {
		t.Fatal("incomplete DATA protocol accepted")
	}
}

func TestLifecycleIsolationInvalidOwner(t *testing.T) {
	for _, service := range []*LifecycleService{nil, {}} {
		if proof, err := service.ProbeIsolation("isolation-state"); proof != nil || !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid owner probed", err)
		}
		if err := service.BindCompatibilityDataListener(nil); !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid owner bound", err)
		}
		left, right := net.Pipe()
		if err := service.ServeDataConnection(t.Context(), right); !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid owner served", err)
		}
		left.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := left.Read(make([]byte, 1)); err == nil {
			t.Fatal("invalid owner leaked stream")
		}
		left.Close()
	}
	f := newLifecycleServiceFixture(t)
	if err := f.s.ServeDataConnection(t.Context(), nil); !errors.Is(err, ErrConfiguration) {
		t.Fatal("nil stream accepted", err)
	}
	must(t, f.s.Close())
	if proof, err := f.s.ProbeIsolation("isolation-state"); proof != nil || err == nil {
		t.Fatal("closed service produced evidence")
	}
}

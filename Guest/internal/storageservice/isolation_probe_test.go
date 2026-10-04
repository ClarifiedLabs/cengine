//go:build cengine_storage_host_test && cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageservice

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	client "dev.cengine/guest/internal/storageclient"
	w "dev.cengine/guest/internal/storagewire"
)

// Actual Service construction/flock and DATA TLS rejection, with an actual
// issued retained Client GETATTR before/after. Host executor is not native FUSE.
func TestIsolationProbesPreserveOriginalIssuedClient(t *testing.T) {
	for _, name := range []string{"legacy-connection", "second-service-exclusivity"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			bindIsolationTestListener(t, f.s, false)
			executor, err := f.s.InstallCompatibilityHostTestExecutor()
			must(t, err)
			hello, identity := consumerIdentity(t, f)
			raw, join := serve(t, f.s.ServeData)
			cfg := consumerTLS(t, f, identity)
			transport := tls.Client(raw, cfg)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			must(t, transport.HandshakeContext(ctx))
			data, err := client.New(client.Config{Conn: transport, TLSConfig: cfg, ServerPin: a.Fingerprint(f.ready.ServerKey.String()), Authority: hello, Version: w.Version, Profile: w.RequiredProfile(), SupportedCaps: 0x1ffffffffff, Limits: client.DefaultLimits(), Timeout: time.Second, Invalidate: func(context.Context, client.Notification) error { return nil }})
			must(t, err)
			defer func() { data.Close(); join() }()
			first, err := data.OriginalConsumerRootAttempt(ctx, hello)
			must(t, err)
			before := reopenJournal(t, f)
			proof, err := f.s.ProbeIsolation(name, f.root)
			must(t, err)
			if proof == nil || proof.CaseName != name || proof.ServiceEpoch != string(hello.Epoch) || proof.Store != string(hello.Binding.Store) || len(proof.RegistrySHA256) != 64 || !reflect.DeepEqual(before, reopenJournal(t, f)) {
				t.Fatal("not exact unchanged current authority")
			}
			second, err := data.OriginalConsumerRootAttempt(ctx, hello)
			must(t, err)
			if first.Node != second.Node || second.RequestSequence <= first.RequestSequence || executor.GetAttrCalls() != 2 {
				t.Fatal("original client did not perform fresh GETATTR")
			}
			if proof, err = f.s.ProbeIsolation("forged", f.root); err == nil || proof != nil {
				t.Fatal("unknown operation admitted")
			}
			if proof, err = f.s.ProbeIsolation("second-service-exclusivity", nil); err == nil || proof != nil {
				t.Fatal("unowned root admitted")
			}
		})
	}
}

func bindIsolationTestListener(t *testing.T, service *fixtureService, eof bool) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	must(t, service.BindCompatibilityDataListener(listener.Addr()))
	ctx, cancel := context.WithCancel(context.Background())
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
				if eof {
					conn.Close()
				} else {
					_ = service.ServeDataConnection(ctx, conn)
				}
			}()
		}
	}()
	t.Cleanup(func() { listener.Close(); cancel(); workers.Wait() })
}

func TestLegacyIsolationRequiresLiveListenerCompletion(t *testing.T) {
	for _, mode := range []string{"unbound", "eof"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			if mode == "eof" {
				bindIsolationTestListener(t, f.s, true)
			}
			if proof, err := f.s.ProbeIsolation("legacy-connection", f.root); err == nil || proof != nil {
				t.Fatal("non-server rejection accepted")
			}
		})
	}
}

func TestIsolationStateIndependentlyReadsHiddenJournal(t *testing.T) {
	for _, mode := range []string{"ledger", "side-file", "symlink", "oversize", "fifo", "count64", "count65"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			before, err := f.s.ProbeIsolation("isolation-state", f.root)
			must(t, err)
			path := filepath.Join(f.root.Name(), ".cengine-storage-authority", "state.json")
			original, err := os.ReadFile(path)
			must(t, err)
			defer os.WriteFile(path, original, 0600)
			if mode == "ledger" {
				old := []byte(`"operations":{}`)
				changed := []byte(`"operations":{"11111111-1111-4111-8111-111111111111":{"kind":"hidden-test","digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`)
				if !bytes.Contains(original, old) {
					t.Fatal("fixture has no empty operation ledger")
				}
				must(t, os.WriteFile(path, bytes.Replace(original, old, changed, 1), 0600))
			}
			extra := filepath.Join(filepath.Dir(path), "extra")
			if mode == "side-file" {
				must(t, os.WriteFile(extra, []byte("hidden"), 0600))
			}
			if mode == "symlink" {
				must(t, os.Symlink(path, extra))
			}
			if mode == "oversize" {
				file, e := os.Create(extra)
				must(t, e)
				must(t, file.Truncate(1<<30))
				must(t, file.Close())
			}
			if mode == "fifo" {
				must(t, unix.Mkfifo(extra, 0600))
			}
			if mode == "count64" || mode == "count65" {
				count := 62
				if mode == "count65" {
					count++
				}
				for i := 0; i < count; i++ {
					must(t, os.WriteFile(fmt.Sprintf("%s-%d", extra, i), nil, 0600))
				}
			}
			after, err := f.s.ProbeIsolation("isolation-state", f.root)
			if mode == "side-file" || mode == "count64" {
				must(t, err)
				if after.RegistrySHA256 == before.RegistrySHA256 {
					t.Fatal("hidden file omitted")
				}
			} else if err == nil || after != nil {
				t.Fatal("unsafe or inconsistent disk accepted")
			}
		})
	}
}

//go:build cengine_storage_host_test && cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageservice

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	client "dev.cengine/guest/internal/storageclient"
	control "dev.cengine/guest/internal/storagecontrol"
	w "dev.cengine/guest/internal/storagewire"
)

// Real issued TLS, Server.ServeData, root grant, control Retire and Client.Do.
// The host executor substitutes filesystem execution only, never auth/guards.
// This proves a joined old-client local rejection, NOT native FD or Admit denial.
func TestOriginalConsumerActualClientRetireDoesNotJoinAndLossDoes(t *testing.T) {
	f := newFixture(t)
	executor, err := f.s.InstallCompatibilityHostTestExecutor()
	must(t, err)
	h, identity := consumerIdentity(t, f)
	ctx, loseService := context.WithCancel(context.Background())
	defer loseService()
	raw, wait := serve(t, func(_ context.Context, conn net.Conn) error { return f.s.ServeData(ctx, conn) })
	cfg := consumerTLS(t, f, identity)
	tlsClient := tls.Client(raw, cfg)
	handshake, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	must(t, tlsClient.HandshakeContext(handshake))
	cancel()
	data, err := client.New(client.Config{Conn: tlsClient, TLSConfig: cfg, ServerPin: a.Fingerprint(f.ready.ServerKey.String()), Authority: h, Version: w.Version, Profile: w.RequiredProfile(), SupportedCaps: 0x1ffffffffff, Limits: client.DefaultLimits(), Timeout: time.Second, Invalidate: func(context.Context, client.Notification) error { return nil }})
	must(t, err)
	defer data.Close()
	// Each observation gets its own bound, independent of handshake/retire/reopen.
	observe := func(expected a.DataHello) error {
		observation, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		return data.OriginalConsumerClosedRoot(observation, expected)
	}
	_, root := data.Root()
	if root.Node == 0 || root.Attr.Mode&0170000 != 0040000 || data.Authority() != h {
		t.Fatal("not actual old client/root grant")
	}
	if err := observe(h); !errors.Is(err, client.ErrProtocol) {
		t.Fatal("live client treated as joined", err)
	}
	// The positive is a real GETATTR on this exact issued DATA client, through
	// ServeData/AuthenticateData/Admit/Dispatch, not encoded observation JSON.
	positive, stopPositive := context.WithTimeout(context.Background(), 3*time.Second)
	must(t, data.OriginalConsumerPositiveRoot(positive, h))
	stopPositive()
	if executor.GetAttrCalls() != 1 {
		t.Fatal("positive bypassed DATA dispatch")
	}
	ctl, join := f.connect(t)
	r := call(t, ctl, control.Request{Retire: &a.RetireRequest{Operation: id(t), Store: h.Binding.Store, Volume: h.Binding.Volume, Attachment: h.Binding.Attachment, Launch: h.Binding.Launch}})
	if r.Receipt == nil {
		t.Fatal("missing real retirement")
	}
	ctl.Close()
	join()
	// Retire fences authority but DOES NOT close this original DATA transport.
	// Do not manufacture same-E evidence by timing out or writing a second TLS client.
	select {
	case <-data.Terminal():
		t.Fatal("Retire unexpectedly terminated original client")
	default:
	}
	if err := observe(h); !errors.Is(err, client.ErrProtocol) {
		t.Fatal("retirement receipt substituted for local join", err)
	}
	loseService() // actual production ServeData context shutdown closes the peer
	_ = wait()
	terminal, stopTerminal := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopTerminal()
	select {
	case <-data.Terminal():
	case <-terminal.Done():
		t.Fatal("old client did not become terminal")
	}
	stopTerminal()
	// Reopen the same real backing authority with a fresh production service E.
	// The original client remains retained; no new client can stand in for it.
	must(t, f.s.Close())
	next, err := f.open(f.cfg, f.ready.Controller)
	must(t, err)
	f.s = next
	t.Cleanup(func() { must(t, next.Close()) })
	f.refresh(t)
	if f.ready.ServiceEpoch == h.Epoch {
		t.Fatal("service replacement reused original epoch")
	}
	for _, field := range []string{"epoch", "attachment", "key", "volume", "store", "launch", "container", "role", "mode"} {
		bad := h
		switch field {
		case "epoch":
			bad.Epoch = id(t)
		case "attachment":
			bad.Binding.Attachment = id(t)
		case "key":
			bad.Binding.Key = "bad"
		case "volume":
			bad.Binding.Volume = id(t)
		case "store":
			bad.Binding.Store = id(t)
		case "launch":
			bad.Binding.Launch = id(t)
		case "container":
			bad.Binding.Container = "bad"
		case "role":
			bad.Binding.Role = a.PrepareRole
		case "mode":
			bad.Binding.Mode = a.ReadOnly
		}
		if err := data.OriginalConsumerPositiveRoot(context.Background(), bad); !errors.Is(err, client.ErrProtocol) {
			t.Fatalf("positive accepted unrelated %s: %v", field, err)
		}
		if err := observe(bad); !errors.Is(err, client.ErrProtocol) {
			t.Fatalf("accepted unrelated %s: %v", field, err)
		}
	}
	if err := observe(h); err != client.ErrClosed {
		t.Fatal("actual original Do did not reject after transport join", err)
	}
	if executor.GetAttrCalls() != 1 {
		t.Fatal("negative dispatched new work")
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if err := data.OriginalConsumerClosedRoot(canceled, h); !errors.Is(err, context.Canceled) {
		t.Fatal("expired operation counted", err)
	}
}

package storageservice

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
)

func TestInvalidLimitsNeverChangeRegistry(t *testing.T) {
	for _, kind := range []string{"data", "control"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			cfg := f.cfg
			if kind == "data" {
				cfg.DataLimits = d.DefaultLimits()
				cfg.DataLimits.Connections = -1
			} else {
				cfg.ControlLimits = c.DefaultLimits()
				cfg.ControlLimits.RequestBytes = 1
			}
			statePath := filepath.Join(f.root.Name(), ".cengine-storage-authority", "state.json")
			before, err := os.ReadFile(statePath)
			must(t, err)
			must(t, f.s.Close())
			if _, err = f.open(cfg, f.ready.Controller); err == nil {
				t.Fatal("invalid Open succeeded")
			}
			after, err := os.ReadFile(statePath)
			must(t, err)
			if !bytes.Equal(before, after) {
				t.Fatal("invalid config changed E/attachment journal")
			}
			path := t.TempDir()
			must(t, os.Mkdir(filepath.Join(path, "volumes"), 0700))
			root, err := os.Open(path)
			must(t, err)
			defer root.Close()
			cfg.Root = root
			if _, err = InitializeLifecycle(cfg, f.s.current); err == nil {
				t.Fatal("invalid Initialize succeeded")
			}
			if _, err = os.Stat(filepath.Join(path, ".cengine-storage-authority")); !os.IsNotExist(err) {
				t.Fatal("invalid config created registry", err)
			}
		})
	}
}

func TestAttachmentCSRServerRejectsSameTupleDifferentKey(t *testing.T) {
	f := newFixture(t)
	hello, _ := f.attachment(t)
	other, err := p.NewAttachmentKey(p.RuntimeRole)
	must(t, err)
	binding, err := d.AttachmentBinding(hello)
	must(t, err)
	csr, err := other.CSR(binding)
	must(t, err)
	raw, wait := serve(t, f.s.ServeAttachmentCSR)
	root, err := p.ParseRootDER(f.ready.TLSRootDER)
	must(t, err)
	server, err := p.NewServerBinding(p.StoreID(f.ready.Store.ID), p.ServiceEpoch(f.ready.ServiceEpoch))
	must(t, err)
	conn, err := p.NewControllerTLSClient(raw, f.identity, root, server, f.ready.ServerKey)
	must(t, err)
	must(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	must(t, conn.Handshake())
	must(t, writeCredential(conn, lifecycleAttachmentCSRRequest{Version: lifecycleCredentialVersion, Controller: lifecycleCredentialHello(f.s.current.Grant.Identity, f.ready.ServiceEpoch, f.ready.Controller.Epoch), Attachment: hello, CSR: csr}))
	var reply attachmentCSRReply
	if err = readCredential(conn, &reply); err == nil {
		t.Fatal("wrong-key CSR issued")
	}
	raw.Close()
	if wait() == nil {
		t.Fatal("server accepted wrong-key CSR")
	}
}

func TestServiceDataAdmissionIsBoundedBeforeTLS(t *testing.T) {
	f := newFixture(t)
	var dones []func()
	for i := 0; i < f.s.config.DataLimits.Connections; i++ {
		l, r := net.Pipe()
		defer l.Close()
		defer r.Close()
		done, err := f.s.begin(l, false)
		must(t, err)
		dones = append(dones, done)
	}
	l, r := net.Pipe()
	defer r.Close()
	if err := f.s.ServeData(context.Background(), l); err != d.ErrOverload {
		t.Fatal("data owner accepted overload", err)
	}
	for _, done := range dones {
		done()
	}
}

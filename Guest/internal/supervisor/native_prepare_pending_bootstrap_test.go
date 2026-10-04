//go:build cengine_native_faulttest

package supervisor

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
	s "dev.cengine/guest/internal/storageservice"
)

// Only public Ready/scope/signed-grant/CSR/certificate metadata uses the inherited setup stream.
// The one attachment private credential is read separately after memfd sealing.
type pendingBootstrapRequest struct {
	Ready   s.Ready
	Scope   a.LifecycleMetadata
	Current a.SignedLifecycleGrant
	CSR     []byte
}
type pendingBootstrapReply struct {
	Ready       s.Ready
	Scope       a.LifecycleMetadata
	Certificate []byte
}
type pendingBootstrapGo struct{ Sealed bool }

// Public metadata is correlated only over the inherited, owned child channel;
// it is not a substitute for ReopenLifecycle's signature/journal validation.
func pendingLifecycleScopeMatches(ready s.Ready, scope a.LifecycleMetadata, current a.LifecycleGrant) bool {
	return current.Validate() == nil && scope.Identity == current.Identity &&
		scope.CurrentGrant == current && !scope.Sealed && scope.RetirementGrant == (a.LifecycleGrant{}) &&
		scope.Store == ready.Store && scope.Store.ID == scope.Identity.Store &&
		scope.Epoch == ready.ServiceEpoch && scope.Controller == ready.Controller &&
		scope.Controller == (a.Controller{Epoch: current.ExpectedEpoch + 1, Key: current.NewKey}) &&
		scope.Bootstrap == ready.Bootstrap && scope.Revision == ready.Revision &&
		scope.OpenRevision != 0 && scope.OpenRevision <= scope.Revision
}

// Bind only the public reply certificate to the parent's non-exportable key.
// Shared with the host regression so compilation cannot hide an ExportDER failure.
func pendingControllerIdentity(certificate []byte, binding p.Binding, key p.Key) (p.Identity, error) {
	cert, err := p.ParseCertificateDER(certificate, binding)
	if err != nil {
		return p.Identity{}, err
	}
	return cert.WithKey(key)
}

func TestNativePendingBootstrapControllerKeyNeverExported(t *testing.T) {
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	bootstrap, err := p.NewBootstrapPublicKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey))
	must(err)
	now := time.Now().Add(-time.Minute)
	issuer, err := p.NewIssuer(now, time.Hour, bootstrap)
	must(err)
	key, err := p.NewControllerKey()
	must(err)
	id, err := p.NewUUID()
	must(err)
	binding, err := p.NewControllerBinding(p.StoreID(id), 1)
	must(err)
	csr, err := key.CSR(binding)
	must(err)
	cert, err := issuer.IssueController(csr, binding, now, time.Hour)
	must(err)
	identity, err := pendingControllerIdentity(cert.DER(), binding, key)
	must(err)
	if !bytes.Equal(identity.Certificate().DER(), cert.DER()) {
		t.Fatal("controller certificate changed")
	}
	if certificate, private, err := identity.ExportDER(); !errors.Is(err, p.ErrInvalid) || certificate != nil || private != nil {
		t.Fatal("controller private key became exportable")
	}
	wrongKey, err := p.NewControllerKey()
	must(err)
	wrongBinding, err := p.NewControllerBinding(p.StoreID(id), 2)
	must(err)
	for name, tc := range map[string]struct {
		cert    []byte
		binding p.Binding
		key     p.Key
	}{
		"wrong-key":           {cert.DER(), binding, wrongKey},
		"wrong-epoch":         {cert.DER(), wrongBinding, key},
		"missing-certificate": {nil, binding, key},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := pendingControllerIdentity(tc.cert, tc.binding, tc.key); err == nil {
				t.Fatal("uncorrelated controller accepted")
			}
		})
	}
}

const pendingBootstrapLimit = 32 << 10

func pendingBootstrapWrite(w io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > pendingBootstrapLimit {
		return errors.New("pending bootstrap bound")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	for _, data := range [][]byte{header[:], data} {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n != len(data) {
			return io.ErrShortWrite
		}
	}
	return nil
}
func pendingBootstrapRead(r io.Reader, value any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > pendingBootstrapLimit {
		return errors.New("pending bootstrap bound")
	}
	data := make([]byte, int(size))
	if _, err := io.ReadFull(r, data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(data, canonical) {
		return errors.New("noncanonical pending bootstrap")
	}
	return nil
}
func TestNativePendingBootstrapLifecycleCorrelation(t *testing.T) {
	root := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	key, err := p.NewControllerKey()
	if err != nil {
		t.Fatal(err)
	}
	store, err := a.NewID()
	if err != nil {
		t.Fatal(err)
	}
	current := nativeLifecycleGrant(t, store, root, key)
	epoch, err := a.NewID()
	if err != nil {
		t.Fatal(err)
	}
	ready := s.Ready{Store: a.Store{ID: store}, ServiceEpoch: epoch, Controller: a.Controller{Epoch: 1, Key: current.Grant.NewKey}, Revision: 7}
	scope := a.LifecycleMetadata{
		StartupMetadata: a.StartupMetadata{Store: ready.Store, Epoch: epoch, Controller: ready.Controller, Revision: ready.Revision},
		Identity:        current.Grant.Identity, CurrentGrant: current.Grant, OpenRevision: 3,
	}
	if !pendingLifecycleScopeMatches(ready, scope, current.Grant) {
		t.Fatal("exact current incarnation rejected")
	}
	for name, mutate := range map[string]func(*a.LifecycleMetadata){
		"generation":            func(m *a.LifecycleMetadata) { m.Identity.Generation++ },
		"binding":               func(m *a.LifecycleMetadata) { m.Identity.Binding = current.Grant.NewKey },
		"current-grant":         func(m *a.LifecycleMetadata) { m.CurrentGrant.Serial++ },
		"store":                 func(m *a.LifecycleMetadata) { m.Store.ID = epoch },
		"epoch":                 func(m *a.LifecycleMetadata) { m.Epoch = store },
		"controller":            func(m *a.LifecycleMetadata) { m.Controller.Epoch++ },
		"key":                   func(m *a.LifecycleMetadata) { m.Controller.Key = m.Identity.Binding },
		"bootstrap":             func(m *a.LifecycleMetadata) { m.Bootstrap = m.Identity.Binding },
		"revision":              func(m *a.LifecycleMetadata) { m.Revision++ },
		"missing-open-revision": func(m *a.LifecycleMetadata) { m.OpenRevision = 0 },
		"future-open-revision":  func(m *a.LifecycleMetadata) { m.OpenRevision = m.Revision + 1 },
		"sealed":                func(m *a.LifecycleMetadata) { m.Sealed = true },
		"retiring":              func(m *a.LifecycleMetadata) { m.RetirementGrant = current.Grant },
	} {
		t.Run(name, func(t *testing.T) {
			wrong := scope
			mutate(&wrong)
			if pendingLifecycleScopeMatches(ready, wrong, current.Grant) {
				t.Fatal("uncorrelated lifecycle incarnation accepted")
			}
		})
	}
}

func TestNativePendingBootstrapClosedCodec(t *testing.T) {
	var buffer bytes.Buffer
	if err := pendingBootstrapWrite(&buffer, pendingBootstrapGo{Sealed: true}); err != nil {
		t.Fatal(err)
	}
	encoded := bytes.Clone(buffer.Bytes())
	var got pendingBootstrapGo
	if err := pendingBootstrapRead(&buffer, &got); err != nil || !got.Sealed {
		t.Fatal(got, err)
	}
	for n := 0; n < len(encoded); n++ {
		if err := pendingBootstrapRead(bytes.NewReader(encoded[:n]), &got); err == nil {
			t.Fatalf("accepted truncated frame %d", n)
		}
	}
	for _, text := range []string{`{"Sealed":true,"Sealed":true}`, `{"Sealed":true,"unknown":1}`, `{"Sealed":true} `} {
		data := make([]byte, 4)
		binary.BigEndian.PutUint32(data, uint32(len(text)))
		data = append(data, text...)
		if err := pendingBootstrapRead(bytes.NewReader(data), &got); err == nil {
			t.Fatal("accepted ambiguous bootstrap")
		}
	}
	for _, size := range []uint32{0, pendingBootstrapLimit + 1, ^uint32(0)} {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], size)
		if err := pendingBootstrapRead(bytes.NewReader(header[:]), &got); err == nil {
			t.Fatal("accepted oversized bootstrap")
		}
	}
}
func TestNativePendingBootstrapOrdersIssuedEpochAndCrash(t *testing.T) {
	data, err := os.ReadFile("native_prepare_pending_v4_linux_test.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	start, end := strings.Index(source, "func TestNativePendingProvisionFreshMountReplayV4"), strings.Index(source, "func TestNativePendingProvisionMarkerWorkerV4")
	if start < 0 || end <= start {
		t.Fatal("missing exact fixture functions")
	}
	parent := source[start:end]
	ordered := []string{"service.Close()", "cmd.Start()", "pendingBootstrapRequest{Ready: ready, Scope: scope, Current: current", "pendingBootstrapRead(setup, &boot)", "pendingLifecycleScopeMatches(boot.Ready, boot.Scope, current.Grant)", "boot.Scope.OpenRevision != scope.Revision+1", "pendingControllerIdentity(boot.Certificate, controllerBinding, controllerKey)", "prepareV4Binding(t, boot.Ready, volume)", "ReservePrepare:", "RegisterAttachment:", "s.RequestLifecycleAttachmentCertificate", "unix.F_ADD_SEALS", "pendingBootstrapGo{Sealed: true}", "err = wait()", "exit.ExitCode() != 73", "evidence.Hello != old", "evidence.Scope.OpenRevision != boot.Scope.OpenRevision", "record.Before.Root != evidence.Intent.Root", "s.ReopenLifecycle(cfg", "OpenRevision: boot.Scope.OpenRevision", "prepareV4Drain(t, control, evidence.Hello)", "ReplacePrepare:", "prepareV4MountBootstrap", "prepareV4VerifyTree"}
	at := 0
	for _, token := range ordered {
		next := strings.Index(parent[at:], token)
		if next < 0 {
			t.Fatalf("missing/out-of-order %q", token)
		}
		at += next + len(token)
	}
	child := source[end:]
	for _, token := range []string{"s.ReopenLifecycle(cfg, boot.Scope.Identity, boot.Current", "OpenRevision: boot.Scope.OpenRevision", "pendingLifecycleScopeMatches(ready, scope, boot.Current.Grant)", "service.NativePendingProvision(ctx, raw, hello)", "report.Sync()", "os.Exit(73)", "begun.Pending != w.BindCopyTransaction", "unix.EBUSY", "bound.Intent != want", "again.Pending != 0"} {
		if !strings.Contains(child, token) {
			t.Fatalf("lost required marker/replay assertion %q", token)
		}
	}
	if strings.Contains(source, ".ExportDER()") || strings.Contains(source, "mustPendingKey") {
		t.Fatal("native parent attempted controller export")
	}
	if strings.Contains(child, "a.OpenExpected(") || strings.Contains(child, "hello.Epoch =") {
		t.Fatal("old attachment resurrection setup returned")
	}
}

package storagebootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	p "dev.cengine/guest/internal/storagepki"
)

func lifecyclePrivateBody(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := canonicalBytes(value)
	check(t, err)
	return raw
}
func lifecyclePrivateCommand(operation string, body []byte) lifecyclePrivateRequest {
	return lifecyclePrivateRequest{Operation: operation, Body: body, RequestID: 1, Version: p.LifecycleChildVersion}
}
func TestLifecyclePrivateInitializationCannotSupplyProcessOrGuestEpoch(t *testing.T) {
	f := newLifecycleSessionIntent(t, false)
	init := lifecycleInitialization{Binding: f.cfg.binding, ExpectedEpoch: f.cfg.expectedEpoch, IncarnationID: f.cfg.incarnation,
		RootPublicKey: f.cfg.root.PublicKey(), Store: f.cfg.store, Version: p.LifecycleChildVersion}
	raw := lifecyclePrivateBody(t, init)
	cfg, err := decodeLifecycleInitialization(raw, f.cfg.processes)
	check(t, err)
	if cfg.processes != f.cfg.processes {
		t.Fatal("lost native observation")
	}
	for _, extra := range []string{`"daemon_unique_id":101`, `"child_audit":"AA=="`, `"service_epoch":"x"`, `"receipt":{}`, `"key":"private"`} {
		bad := append([]byte("{"+extra+","), raw[1:]...)
		if _, err := decodeLifecycleInitialization(bad, f.cfg.processes); err == nil {
			t.Fatal("accepted", extra)
		}
	}
	cfg.processes = lifecycleProcesses{}
	if _, err := newLifecycleSession(cfg); err == nil {
		t.Fatal("DTO created process authority")
	}
}
func TestLifecyclePrivateClosedOperations(t *testing.T) {
	for _, operation := range []string{"proof", "sign", "query", "result", "receipt", "root-connect", "rebind-service", "export-key", "import-key", "control-request", "connect-boot"} {
		t.Run(operation, func(t *testing.T) {
			f := newLifecycleSessionIntent(t, false)
			if _, err := f.s.privateLifecycleRequest(t.Context(), lifecyclePrivateCommand(operation, nil), nil); err == nil {
				t.Fatal("accepted forbidden operation")
			}
		})
	}
	f := newLifecycleSessionIntent(t, false)
	csr, err := f.s.privateLifecycleRequest(t.Context(), lifecyclePrivateCommand("controller-csr", nil), nil)
	check(t, err)
	if len(csr) == 0 {
		t.Fatal("no public CSR")
	}
	for _, body := range [][]byte{[]byte("{}"), []byte("null")} {
		if _, err := f.s.privateLifecycleRequest(t.Context(), lifecyclePrivateCommand("controller-csr", body), nil); err == nil {
			t.Fatal("unexpected body accepted")
		}
	}
	request := lifecyclePrivateCommand("controller-csr", nil)
	request.Version = "root-proof.v1"
	if _, err := f.s.privateLifecycleRequest(t.Context(), request, nil); err == nil {
		t.Fatal("v1 cross wire")
	}
}
func TestLifecyclePrivateClosesUnexpectedStream(t *testing.T) {
	f := newLifecycleSessionIntent(t, false)
	left, right := net.Pipe()
	defer left.Close()
	if _, err := f.s.privateLifecycleRequest(t.Context(), lifecyclePrivateCommand("controller-csr", nil), right); err == nil {
		t.Fatal("unexpected FD")
	}
	left.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := left.Read(make([]byte, 1)); err == nil || strings.Contains(err.Error(), "timeout") {
		t.Fatal("stream leaked", err)
	}
}
func TestLifecyclePrivateSignedGrantCannotSkipCandidate(t *testing.T) {
	f := newLifecycleSessionIntent(t, false)
	f.owner = lifecycleSessionSign(t, f.rootPrivate, f.owner.Grant)
	body := lifecyclePrivateBody(t, f.owner)
	command := lifecyclePrivateCommand("bind-grant", body)
	if _, err := f.s.privateLifecycleRequest(t.Context(), command, nil); err == nil {
		t.Fatal("skipped native candidate prerequisite")
	}
	lifecycleSessionProof(t, f, f.challenge(t, 1, p.LifecycleChildCandidate, f.owner.Grant))
	_, err := f.s.privateLifecycleRequest(t.Context(), command, nil)
	check(t, err)
	if _, err := f.s.privateLifecycleRequest(t.Context(), command, nil); err == nil {
		t.Fatal("rebound owner")
	}
}
func TestLifecyclePrivateBootIsTypedFreshTLS(t *testing.T) {
	f := newLifecycleSessionFixture(t, false)
	f.startAuthority(t)
	wire := lifecycleBootWire{CertificateDER: f.boot.certificate.DER(), Identity: f.boot.identity, RootDER: f.boot.root.DER(),
		ServerSPKI: f.boot.serverPin.String(), ServiceEpoch: f.boot.serviceEpoch, Signed: f.boot.signed}
	body := lifecyclePrivateBody(t, wire)
	boot, err := f.s.decodePrivateBoot(body)
	check(t, err)
	if boot.identity != f.boot.identity || boot.serviceEpoch != f.boot.serviceEpoch || !bytes.Equal(boot.certificate.DER(), f.boot.certificate.DER()) {
		t.Fatal("boot binding changed")
	}
	var fields map[string]json.RawMessage
	check(t, json.Unmarshal(body, &fields))
	fields["receipt"] = json.RawMessage(`{}`)
	if _, err := f.s.decodePrivateBoot(lifecyclePrivateBody(t, fields)); err == nil {
		t.Fatal("supplied receipt accepted")
	}
	left, right := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- f.server.Serve(context.Background(), left) }()
	defer func() {
		f.s.close()
		left.Close()
		right.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("server hung")
		}
	}()
	_, err = f.s.privateLifecycleRequest(t.Context(), lifecyclePrivateCommand("connect-boot", body), right)
	check(t, err)
	challenge := f.challenge(t, 3, p.LifecycleChildResult, f.owner.Grant)
	reply := lifecycleSessionProof(t, f, challenge)
	if reply.Fields().Receipt == nil {
		t.Fatal("no fresh TLS result")
	}
}
func TestLifecyclePrivateCancellationWhileOperationGateHeld(t *testing.T) {
	f := newLifecycleSessionFixture(t, true)
	f.startAuthority(t)
	f.s.op <- struct{}{}
	defer func() { <-f.s.op }()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := f.s.privateLifecycleRequest(ctx, lifecyclePrivateCommand("takeover", nil), nil)
		done <- err
	}()
	cancel()
	f.s.close() // Disconnect never waits for the occupied operation gate.
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled request succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation blocked behind operation gate")
	}
}

func TestLifecyclePrivateCannotSupplyAuthoritativeBootChallenge(t *testing.T) {
	f := newLifecycleSessionFixture(t, false)
	challenge := f.challenge(t, 3, p.LifecycleChildResult, f.owner.Grant)
	for _, operation := range []string{"boot-proof", "boot-trust", "root-challenge", "proof", "result"} {
		if _, err := f.s.privateLifecycleRequest(t.Context(), lifecyclePrivateCommand(operation, challenge.Canonical()), nil); err == nil {
			t.Fatal("parent supplied authoritative challenge", operation)
		}
	}
	wire := lifecycleBootWire{CertificateDER: f.boot.certificate.DER(), Identity: f.boot.identity,
		RootDER: f.boot.root.DER(), ServerSPKI: f.boot.serverPin.String(), ServiceEpoch: f.boot.serviceEpoch, Signed: f.boot.signed}
	var fields map[string]json.RawMessage
	check(t, json.Unmarshal(lifecyclePrivateBody(t, wire), &fields))
	fields["boot"] = json.RawMessage(lifecyclePrivateBody(t, challenge.Fields().Boot))
	if _, err := f.s.decodePrivateBoot(lifecyclePrivateBody(t, fields)); err == nil {
		t.Fatal("parent boot trust assertion accepted")
	}
}

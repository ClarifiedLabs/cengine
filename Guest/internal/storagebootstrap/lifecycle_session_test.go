package storagebootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
)

// These are honest Go/TLS/temp-directory unit fixtures, NOT native audit-token,
// ROOT-message authentication, macOS XPC, Guest VM, drain or hardware evidence.
type lifecycleSessionFixture struct {
	s                          *lifecycleSession
	cfg                        lifecycleSessionConfig
	rootPrivate                ed25519.PrivateKey
	issuer                     p.Issuer
	now                        time.Time
	initial, owner, retirement a.SignedLifecycleGrant
	authority                  *a.Authority
	boot                       lifecycleBoot
	server                     *c.LifecycleServer
	peer                       net.Conn
	initialPin                 p.Fingerprint
}

func lifecycleSessionID(t *testing.T) a.ID {
	t.Helper()
	id, err := a.NewID()
	check(t, err)
	return id
}
func lifecycleSessionSign(t *testing.T, key ed25519.PrivateKey, grant a.LifecycleGrant) a.SignedLifecycleGrant {
	t.Helper()
	message, err := a.LifecycleGrantSigningBytes(grant)
	check(t, err)
	return a.SignedLifecycleGrant{Grant: grant, Signature: ed25519.Sign(key, message)}
}
func lifecycleSessionPin(t *testing.T, s *lifecycleSession) p.Fingerprint {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(s.greeting.Fields().ControllerSPKI)
	check(t, err)
	public, err := x509.ParsePKIXPublicKey(der)
	check(t, err)
	pin, err := p.PublicKeyFingerprint(public.(ed25519.PublicKey))
	check(t, err)
	return pin
}
func newLifecycleSessionFixture(t *testing.T, takeover bool, barrier ...func(a.Binding, *os.File) error) *lifecycleSessionFixture {
	t.Helper()
	f := newLifecycleSessionIntent(t, takeover)
	// Reserve counters 1 and 2 for mandatory owner/retirement candidates.
	lifecycleSessionProof(t, f, f.challenge(t, 1, p.LifecycleChildCandidate, f.owner.Grant))
	f.initial = lifecycleSessionSign(t, f.rootPrivate, f.initial.Grant)
	f.owner = lifecycleSessionSign(t, f.rootPrivate, f.owner.Grant)
	check(t, f.s.bindGrant(f.owner))
	lifecycleSessionProof(t, f, f.challenge(t, 2, p.LifecycleChildCandidate, f.retirement.Grant))
	f.retirement = lifecycleSessionSign(t, f.rootPrivate, f.retirement.Grant)
	f.startAuthority(t, barrier...)
	return f
}

// No signature, Guest authority, or service E exists yet. Tests can exercise the
// actual ROOT ordering: candidate -> checkpoint/sign -> bind -> boot -> result.
func newLifecycleSessionIntent(t *testing.T, takeover bool) *lifecycleSessionFixture {
	t.Helper()
	f := &lifecycleSessionFixture{now: time.Now().Add(-time.Minute).Truncate(time.Second)}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	check(t, err)
	f.rootPrivate = private
	root, err := p.NewBootstrapPublicKey(public)
	check(t, err)
	f.cfg = lifecycleSessionConfig{store: lifecycleSessionID(t), binding: a.Fingerprint(strings.Repeat("b", 64)), incarnation: string(lifecycleSessionID(t)), root: root,
		processes: lifecycleProcesses{daemonUniqueID: 101, childUniqueID: 202, daemonAudit: [32]byte{1}, childAudit: [32]byte{2}}}
	if takeover {
		f.cfg.expectedEpoch = 1
	}
	f.s, err = newLifecycleSession(f.cfg)
	check(t, err)
	t.Cleanup(f.s.close)
	pin := lifecycleSessionPin(t, f.s)
	identity := a.LifecycleIdentity{Store: f.cfg.store, Generation: 9007199254740993, Binding: f.cfg.binding}
	initialPin := pin
	if takeover {
		old, err := p.NewControllerKey()
		check(t, err)
		initialPin, err = old.Fingerprint()
		check(t, err)
	}
	f.initialPin = initialPin
	f.initial.Grant = a.LifecycleGrant{Operation: a.LifecycleInitialize, ID: lifecycleSessionID(t), Identity: identity, Serial: 9007199254740993, NewKey: a.Fingerprint(initialPin.String())}
	f.owner = f.initial
	if takeover {
		f.owner.Grant = a.LifecycleGrant{Operation: a.LifecycleTakeover, ID: lifecycleSessionID(t), Identity: identity, Serial: f.initial.Grant.Serial + 1, ExpectedEpoch: 1, NewKey: a.Fingerprint(pin.String())}
	}
	f.retirement.Grant = a.LifecycleGrant{Operation: a.LifecycleRetire, ID: lifecycleSessionID(t), Identity: identity, Serial: f.owner.Grant.Serial + 1, ExpectedEpoch: f.cfg.expectedEpoch + 1, NewKey: f.owner.Grant.NewKey}
	return f
}

func (f *lifecycleSessionFixture) startAuthority(t *testing.T, barrier ...func(a.Binding, *os.File) error) {
	t.Helper()
	var err error
	f.issuer, err = p.NewIssuer(f.now, 2*time.Hour, f.cfg.root)
	check(t, err)
	dir := t.TempDir()
	check(t, os.Mkdir(filepath.Join(dir, "volumes"), 0700))
	held, err := os.Open(dir)
	check(t, err)
	defer held.Close()
	drain := func(a.Binding, *os.File) error {
		t.Error("unexpected retained resource in empty-store fixture")
		return a.ErrBlocked
	}
	if len(barrier) != 0 {
		drain = barrier[0]
	}
	f.authority, err = a.InitializeLifecycle(a.Config{Root: held, DeviceID: "lifecycle-session-empty-host-test", BootstrapKey: f.cfg.root.PublicKey(), Barrier: drain}, f.initial)
	check(t, err)
	t.Cleanup(func() { check(t, f.authority.Close()) })
	serverKey, err := p.NewServerKey()
	check(t, err)
	serverBinding, err := p.NewServerBinding(p.StoreID(f.cfg.store), p.ServiceEpoch(f.authority.Epoch()))
	check(t, err)
	serverCSR, err := serverKey.CSR(serverBinding)
	check(t, err)
	serverCert, err := f.issuer.IssueServer(serverCSR, serverBinding, f.now, time.Hour)
	check(t, err)
	serverIdentity, err := serverCert.WithKey(serverKey)
	check(t, err)
	serverPin, err := serverKey.Fingerprint()
	check(t, err)
	controllerBinding, err := p.NewControllerBinding(p.StoreID(f.cfg.store), p.ControllerEpoch(f.cfg.expectedEpoch+1))
	check(t, err)
	csr, err := f.s.controllerCSR()
	check(t, err)
	cert, err := f.issuer.IssueController(csr, controllerBinding, f.now, time.Hour)
	check(t, err)
	f.boot = lifecycleBoot{identity: f.owner.Grant.Identity, signed: f.owner, serviceEpoch: f.authority.Epoch(), root: f.issuer.Root(), serverPin: serverPin, certificate: cert}
	sc := c.LifecycleServerConfig{Identity: serverIdentity, ClientRoot: f.issuer.Root(), ServiceEpoch: f.authority.Epoch(), CurrentGrant: f.initial.Grant, ControllerKey: f.initialPin, RetireGrant: f.retirement.Grant}
	if f.owner.Grant.Operation == a.LifecycleTakeover {
		sc.SuccessorGrant, sc.SuccessorKey = f.owner.Grant, lifecycleSessionPin(t, f.s)
	}
	f.server, err = c.NewLifecycleServer(f.authority, sc)
	check(t, err)
}
func (f *lifecycleSessionFixture) connect(t *testing.T) {
	t.Helper()
	left, right := net.Pipe()
	f.peer = left
	done := make(chan error, 1)
	go func() { done <- f.server.Serve(context.Background(), left) }()
	t.Cleanup(func() {
		right.Close()
		left.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("server did not terminate")
		}
	})
	check(t, f.s.connectTrustedBoot(context.Background(), right, f.boot))
}
func (f *lifecycleSessionFixture) challenge(t *testing.T, counter uint64, purpose p.LifecycleChildPurpose, grant a.LifecycleGrant) p.LifecycleChildChallenge {
	t.Helper()
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	check(t, err)
	var trust *p.LifecycleBootTrustFields
	if purpose == p.LifecycleChildResult {
		if f.boot.identity == (a.LifecycleIdentity{}) {
			// Shape-only pre-boot rejection fixture: no authoritative boot exists yet.
			fingerprint, err := p.PublicKeyFingerprint(f.cfg.root.PublicKey())
			check(t, err)
			trust = &p.LifecycleBootTrustFields{Identity: grant.Identity, ServiceEpoch: string(lifecycleSessionID(t)),
				TLSRootSHA256: strings.Repeat("c", 64), ServerSPKI: strings.Repeat("d", 64), BootstrapKey: fingerprint.String()}
		} else {
			derived, err := f.s.deriveBootTrust(f.boot)
			check(t, err)
			fields := derived.Fields()
			trust = &fields
		}
	}
	challenge, err := p.NewLifecycleChildChallenge(p.LifecycleChildChallengeFields{Boot: trust, Version: p.LifecycleChildVersion, Greeting: f.s.greeting.Fields(), Grant: grant,
		ChildAudit: base64.StdEncoding.EncodeToString(f.cfg.processes.childAudit[:]), ChildUniqueID: f.cfg.processes.childUniqueID,
		DaemonAudit: base64.StdEncoding.EncodeToString(f.cfg.processes.daemonAudit[:]), Counter: counter, Nonce: base64.StdEncoding.EncodeToString(nonce), Purpose: purpose, ExpiresUnixMS: uint64(time.Now().UnixMilli()) + p.LifecycleChildLifetimeMS})
	check(t, err)
	return challenge
}
func lifecycleSessionProof(t *testing.T, f *lifecycleSessionFixture, challenge p.LifecycleChildChallenge) p.LifecycleChildReply {
	t.Helper()
	reply, err := f.s.proof(context.Background(), challenge)
	check(t, err)
	if !reply.Verifies(challenge) {
		t.Fatal("uncorrelated signature")
	}
	return reply
}
func TestLifecycleSessionCandidateBeforeEAndFreshOwnedKey(t *testing.T) {
	f := newLifecycleSessionFixture(t, false)
	other, err := newLifecycleSession(f.cfg)
	check(t, err)
	defer other.close()
	if other.greeting.Fields().ChannelID == f.s.greeting.Fields().ChannelID || other.greeting.Fields().ControllerSPKI == f.s.greeting.Fields().ControllerSPKI {
		t.Fatal("key/channel reused")
	}
	csr, err := f.s.controllerCSR()
	check(t, err)
	parsed, err := x509.ParseCertificateRequest(csr)
	check(t, err)
	check(t, parsed.CheckSignature())
	if !strings.HasSuffix(parsed.URIs[0].String(), "/controller/1") {
		t.Fatal("CSR used expected, not successor epoch")
	}
	challenge := f.challenge(t, 3, p.LifecycleChildCandidate, f.owner.Grant)
	if reply := lifecycleSessionProof(t, f, challenge); reply.Fields().Receipt != nil {
		t.Fatal("candidate promoted to result")
	}
	result := f.challenge(t, 4, p.LifecycleChildResult, f.owner.Grant)
	if _, err := f.s.proof(context.Background(), result); err == nil {
		t.Fatal("result before Guest E")
	}
	if f.s.highWater != 4 {
		t.Fatal("failed IO counter not consumed")
	}
	f.connect(t)
	if _, err := f.s.proof(context.Background(), result); err == nil {
		t.Fatal("consumed counter retried after boot")
	}
	lifecycleSessionProof(t, f, f.challenge(t, 5, p.LifecycleChildResult, f.owner.Grant))
}
func TestLifecycleSessionFreshResultsConstantStateAndSeal(t *testing.T) {
	f := newLifecycleSessionFixture(t, false)
	f.connect(t)
	var previous []byte
	for n := uint64(3); n <= 98; n++ { // 96 fresh TLS results, after two candidate proofs.
		challenge := f.challenge(t, n, p.LifecycleChildResult, f.owner.Grant)
		reply := lifecycleSessionProof(t, f, challenge)
		r := reply.Fields().Receipt
		nonce, _ := base64.StdEncoding.DecodeString(challenge.Fields().Nonce)
		if r == nil || r.Grant != f.owner.Grant || r.ServiceEpoch != f.authority.Epoch() || !bytes.Equal(r.Nonce, nonce) || bytes.Equal(r.Nonce, previous) {
			t.Fatal("not fresh actual result")
		}
		previous = bytes.Clone(r.Nonce)
		r.Nonce[0] ^= 1
		if !reply.Verifies(challenge) {
			t.Fatal("reply retained caller receipt storage")
		}
	}
	if f.s.highWater != 98 {
		t.Fatal("counter high-water")
	}
	for _, field := range reflect.VisibleFields(reflect.TypeOf(f.s).Elem()) {
		if field.Type.Kind() == reflect.Map {
			t.Fatal("unbounded history", field.Name)
		}
	}
	check(t, f.s.bindRetire(f.retirement))
	check(t, f.s.retire(context.Background()))
	for n := uint64(99); n <= 101; n++ {
		lifecycleSessionProof(t, f, f.challenge(t, n, p.LifecycleChildResult, f.retirement.Grant))
	}
	if _, err := f.s.proof(context.Background(), f.challenge(t, 102, p.LifecycleChildResult, f.owner.Grant)); err == nil {
		t.Fatal("pre-seal result cached")
	}
	if err := f.s.retire(context.Background()); err == nil {
		t.Fatal("sealed mutation")
	}
}
func TestLifecycleSessionTakeoverCandidateIsNotApplied(t *testing.T) {
	f := newLifecycleSessionFixture(t, true)
	lifecycleSessionProof(t, f, f.challenge(t, 3, p.LifecycleChildCandidate, f.owner.Grant))
	f.connect(t)
	if _, err := f.s.proof(context.Background(), f.challenge(t, 4, p.LifecycleChildResult, f.owner.Grant)); err == nil {
		t.Fatal("candidate grant promoted to applied result")
	}
	check(t, f.s.takeover(context.Background()))
	lifecycleSessionProof(t, f, f.challenge(t, 5, p.LifecycleChildResult, f.owner.Grant))
	check(t, f.s.bindRetire(f.retirement))
	check(t, f.s.retire(context.Background()))
	lifecycleSessionProof(t, f, f.challenge(t, 6, p.LifecycleChildResult, f.retirement.Grant))
}
func TestLifecycleSessionChallengeRefusalsAndCounterOverflow(t *testing.T) {
	f := newLifecycleSessionFixture(t, false)
	valid := f.challenge(t, 5, p.LifecycleChildCandidate, f.owner.Grant)
	for name, change := range map[string]func(*p.LifecycleChildChallengeFields){
		"child-id":     func(v *p.LifecycleChildChallengeFields) { v.ChildUniqueID++ },
		"daemon-id":    func(v *p.LifecycleChildChallengeFields) { v.Greeting.DaemonUniqueID++ },
		"child-audit":  func(v *p.LifecycleChildChallengeFields) { v.ChildAudit = v.DaemonAudit },
		"daemon-audit": func(v *p.LifecycleChildChallengeFields) { v.DaemonAudit = v.ChildAudit },
		"channel":      func(v *p.LifecycleChildChallengeFields) { v.Greeting.ChannelID = string(lifecycleSessionID(t)) },
		"incarnation":  func(v *p.LifecycleChildChallengeFields) { v.Greeting.IncarnationID = string(lifecycleSessionID(t)) },
		"root": func(v *p.LifecycleChildChallengeFields) {
			v.Greeting.RootPublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
		},
		"generation": func(v *p.LifecycleChildChallengeFields) { v.Grant.Identity.Generation++ },
		"grant-id":   func(v *p.LifecycleChildChallengeFields) { v.Grant.ID = lifecycleSessionID(t) },
		"serial":     func(v *p.LifecycleChildChallengeFields) { v.Grant.Serial++ },
		"expiry": func(v *p.LifecycleChildChallengeFields) {
			v.ExpiresUnixMS = uint64(time.Now().Add(-time.Second).UnixMilli())
		},
		"future": func(v *p.LifecycleChildChallengeFields) { v.ExpiresUnixMS += 60000 },
	} {
		t.Run(name, func(t *testing.T) {
			fields := valid.Fields()
			change(&fields)
			bad, err := p.NewLifecycleChildChallenge(fields)
			check(t, err)
			if _, err := f.s.proof(context.Background(), bad); err == nil {
				t.Fatal("mismatch signed")
			}
		})
	}
	if _, err := f.s.proof(context.Background(), p.LifecycleChildChallenge{}); err == nil {
		t.Fatal("zero challenge")
	}
	lifecycleSessionProof(t, f, valid)
	if _, err := f.s.proof(context.Background(), valid); err == nil {
		t.Fatal("replay signed")
	}
	if _, err := f.s.proof(context.Background(), f.challenge(t, 4, p.LifecycleChildCandidate, f.owner.Grant)); err == nil {
		t.Fatal("lower counter signed")
	}
	lifecycleSessionProof(t, f, f.challenge(t, ^uint64(0), p.LifecycleChildCandidate, f.owner.Grant))
	if _, err := f.s.proof(context.Background(), f.challenge(t, 6, p.LifecycleChildCandidate, f.owner.Grant)); err == nil {
		t.Fatal("counter wrapped")
	}
}
func TestLifecycleSessionGrantAndBootAreOneShot(t *testing.T) {
	for _, kind := range []string{"generation", "grant", "signature", "root", "pin", "epoch", "certificate-key", "certificate-epoch"} {
		t.Run(kind, func(t *testing.T) {
			f := newLifecycleSessionFixture(t, false)
			boot := f.boot
			switch kind {
			case "generation":
				boot.identity.Generation++
			case "grant":
				boot.signed.Grant.Serial++
			case "signature":
				boot.signed.Signature = make([]byte, 64)
			case "root":
				boot.root = p.Root{}
			case "pin":
				boot.serverPin = lifecycleSessionPin(t, f.s)
			case "epoch":
				boot.serviceEpoch = lifecycleSessionID(t)
			case "certificate-key", "certificate-epoch":
				key, err := p.NewControllerKey()
				check(t, err)
				epoch := p.ControllerEpoch(1)
				if kind == "certificate-epoch" {
					epoch++
				}
				binding, err := p.NewControllerBinding(p.StoreID(f.cfg.store), epoch)
				check(t, err)
				csr, err := key.CSR(binding)
				check(t, err)
				boot.certificate, err = f.issuer.IssueController(csr, binding, f.now, time.Hour)
				check(t, err)
			}
			left, right := net.Pipe()
			done := make(chan error, 1)
			go func() { done <- f.server.Serve(context.Background(), left) }()
			if err := f.s.connectTrustedBoot(context.Background(), right, boot); err == nil {
				t.Fatal("bad boot accepted")
			}
			left.Close()
			right.Close()
			<-done
			if !f.s.revoked {
				t.Fatal("failed boot left owner reusable")
			}
		})
	}
	f := newLifecycleSessionFixture(t, false)
	if f.s.bindGrant(f.owner) == nil {
		t.Fatal("grant rebound")
	}
	bad := f.retirement
	bad.Grant.Identity.Generation++
	bad = lifecycleSessionSign(t, f.rootPrivate, bad.Grant)
	if f.s.bindRetire(bad) == nil {
		t.Fatal("other generation retired")
	}
	bad = f.retirement
	bad.Signature = make([]byte, 64)
	if f.s.bindRetire(bad) == nil {
		t.Fatal("unsigned retirement accepted")
	}
	check(t, f.s.bindRetire(f.retirement))
	if f.s.bindRetire(f.retirement) == nil {
		t.Fatal("retirement rebound")
	}
	f.connect(t)
	left, right := net.Pipe()
	defer left.Close()
	if f.s.connectTrustedBoot(context.Background(), right, f.boot) == nil {
		t.Fatal("boot rebound")
	}
	if _, err := left.Write([]byte{1}); err == nil {
		t.Fatal("rejected raw not owned/closed")
	}
}

// Transport-only blocking seam: the server still authenticates and obtains the
// actual authority result; no result/client/signer callback is injectable.
type lifecyclePausedConn struct {
	net.Conn
	mu      sync.Mutex
	pause   bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *lifecyclePausedConn) Write(b []byte) (int, error) {
	p.mu.Lock()
	pause := p.pause
	p.mu.Unlock()
	if pause {
		p.once.Do(func() { close(p.entered) })
		<-p.release
	}
	return p.Conn.Write(b)
}
func TestLifecycleSessionCloseInterruptsIOAndLossNeverSignsCache(t *testing.T) {
	t.Run("close-result", func(t *testing.T) {
		f := newLifecycleSessionFixture(t, false)
		left, right := net.Pipe()
		paused := &lifecyclePausedConn{Conn: left, entered: make(chan struct{}), release: make(chan struct{})}
		done := make(chan error, 1)
		go func() { done <- f.server.Serve(context.Background(), paused) }()
		t.Cleanup(func() { close(paused.release); left.Close(); right.Close(); <-done })
		check(t, f.s.connectTrustedBoot(context.Background(), right, f.boot))
		lifecycleSessionProof(t, f, f.challenge(t, 3, p.LifecycleChildResult, f.owner.Grant))
		paused.mu.Lock()
		paused.pause = true
		paused.mu.Unlock()
		challenge := f.challenge(t, 4, p.LifecycleChildResult, f.owner.Grant)
		proofDone := make(chan error, 1)
		go func() { _, err := f.s.proof(context.Background(), challenge); proofDone <- err }()
		select {
		case <-paused.entered:
		case <-time.After(3 * time.Second):
			t.Fatal("no result IO")
		}
		closed := make(chan struct{})
		go func() { f.s.close(); close(closed) }()
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("close waited for operation lock")
		}
		select {
		case err := <-proofDone:
			if err == nil {
				t.Fatal("revoked result signed")
			}
		case <-time.After(time.Second):
			t.Fatal("close did not cancel result")
		}
	})
	t.Run("loss", func(t *testing.T) {
		f := newLifecycleSessionFixture(t, false)
		f.connect(t)
		lifecycleSessionProof(t, f, f.challenge(t, 3, p.LifecycleChildResult, f.owner.Grant))
		f.peer.Close()
		for n := uint64(4); n < 6; n++ {
			if reply, err := f.s.proof(context.Background(), f.challenge(t, n, p.LifecycleChildResult, f.owner.Grant)); err == nil || len(reply.Canonical()) != 0 {
				t.Fatal("loss returned cached signed receipt")
			}
		}
	})
}

// Counts transport writes, not injected TLS results or signer callbacks.
type lifecycleCountedConn struct {
	net.Conn
	mu     sync.Mutex
	writes int
}

func (c *lifecycleCountedConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.writes++
	c.mu.Unlock()
	return c.Conn.Write(b)
}
func (c *lifecycleCountedConn) count() int { c.mu.Lock(); defer c.mu.Unlock(); return c.writes }

func TestLifecycleSessionROOTBootMismatchBeforeResultIO(t *testing.T) {
	for _, field := range []string{"service-epoch", "tls-root", "server-pin", "bootstrap-key", "store", "generation", "binding", "parent-selected-ca"} {
		t.Run(field, func(t *testing.T) {
			f := newLifecycleSessionFixture(t, false)
			challenge := f.challenge(t, 3, p.LifecycleChildResult, f.owner.Grant)
			fields := challenge.Fields()
			switch field {
			case "service-epoch":
				fields.Boot.ServiceEpoch = string(lifecycleSessionID(t))
			case "tls-root":
				fields.Boot.TLSRootSHA256 = strings.Repeat("a", 64)
			case "server-pin":
				fields.Boot.ServerSPKI = strings.Repeat("a", 64)
			case "bootstrap-key":
				fields.Boot.BootstrapKey = strings.Repeat("a", 64)
			case "store":
				fields.Boot.Identity.Store = lifecycleSessionID(t)
			case "generation":
				fields.Boot.Identity.Generation++
			case "binding":
				fields.Boot.Identity.Binding = a.Fingerprint(strings.Repeat("a", 64))
			case "parent-selected-ca":
				// A second, entirely valid service can replay the legitimate grant,
				// issue a certificate for the child's public CSR, and satisfy TLS.
				// Its CA/pin/E are NOT those of ROOT's earlier audited challenge.
				// This is a Go attacker-service fixture, not native ROOT evidence.
				f.startAuthority(t)
			}
			changed, err := p.NewLifecycleChildChallenge(fields)
			if field == "bootstrap-key" || field == "store" || field == "generation" || field == "binding" {
				if err == nil {
					t.Fatal("inconsistent ROOT challenge accepted")
				}
				return
			}
			check(t, err)
			left, right := net.Pipe()
			counted := &lifecycleCountedConn{Conn: right}
			done := make(chan error, 1)
			go func() { done <- f.server.Serve(context.Background(), left) }()
			t.Cleanup(func() { left.Close(); right.Close(); <-done })
			check(t, f.s.connectTrustedBoot(t.Context(), counted, f.boot))
			before := counted.count()
			reply, err := f.s.proof(t.Context(), changed)
			if err == nil || len(reply.Canonical()) != 0 {
				t.Fatal("mismatched boot signed")
			}
			if counted.count() != before {
				t.Fatal("mismatch reached Result TLS IO")
			}
			if !f.s.revoked {
				t.Fatal("mismatch left session reusable")
			}
		})
	}
}

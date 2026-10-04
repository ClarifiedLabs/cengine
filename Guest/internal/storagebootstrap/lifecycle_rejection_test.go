package storagebootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
)

func TestLifecycleSessionROOTCandidateBeforeSigningOrdering(t *testing.T) {
	for _, takeover := range []bool{false, true} {
		name := "initialize"
		if takeover {
			name = "takeover"
		}
		t.Run(name, func(t *testing.T) {
			f := newLifecycleSessionIntent(t, takeover)
			if len(f.owner.Signature) != 0 || f.authority != nil || f.s.owner.Grant != (a.LifecycleGrant{}) {
				t.Fatal("fixture signed or booted before candidate")
			}
			candidate := f.challenge(t, 1, p.LifecycleChildCandidate, f.owner.Grant)
			if reply := lifecycleSessionProof(t, f, candidate); reply.Fields().Receipt != nil {
				t.Fatal("candidate carried a result")
			}
			lifecycleSessionProof(t, f, f.challenge(t, 2, p.LifecycleChildCandidate, f.owner.Grant))
			if _, err := f.s.proof(context.Background(), f.challenge(t, 3, p.LifecycleChildResult, f.owner.Grant)); err == nil {
				t.Fatal("unsigned owner authorized result")
			}
			if f.s.takeover(context.Background()) == nil {
				t.Fatal("unsigned owner authorized mutation")
			}
			// Only now does the test ROOT checkpoint/sign/release its exact grant.
			f.owner = lifecycleSessionSign(t, f.rootPrivate, f.owner.Grant)
			f.initial = lifecycleSessionSign(t, f.rootPrivate, f.initial.Grant)
			check(t, f.s.bindGrant(f.owner))
			f.startAuthority(t)
			f.connect(t)
			if takeover {
				check(t, f.s.takeover(context.Background()))
			}
			lifecycleSessionProof(t, f, f.challenge(t, 4, p.LifecycleChildResult, f.owner.Grant))
			// Retirement follows the SAME candidate-before-signing ordering.
			if len(f.retirement.Signature) != 0 {
				t.Fatal("retire signed before candidate")
			}
			lifecycleSessionProof(t, f, f.challenge(t, 5, p.LifecycleChildCandidate, f.retirement.Grant))
			if f.s.retire(context.Background()) == nil {
				t.Fatal("unsigned retirement authorized mutation")
			}
			if _, err := f.s.proof(context.Background(), f.challenge(t, 6, p.LifecycleChildResult, f.retirement.Grant)); err == nil {
				t.Fatal("unsigned retirement authorized result")
			}
			f.retirement = lifecycleSessionSign(t, f.rootPrivate, f.retirement.Grant)
			check(t, f.s.bindRetire(f.retirement))
			if _, err := f.s.proof(context.Background(), f.challenge(t, 7, p.LifecycleChildResult, f.retirement.Grant)); err == nil {
				t.Fatal("signed retirement fabricated applied result")
			}
			check(t, f.s.retire(context.Background()))
			lifecycleSessionProof(t, f, f.challenge(t, 8, p.LifecycleChildResult, f.retirement.Grant))
		})
	}
}

func TestLifecycleSessionProvisionalGrantCannotBeReplaced(t *testing.T) {
	f := newLifecycleSessionIntent(t, false)
	if f.s.bindGrant(lifecycleSessionSign(t, f.rootPrivate, f.owner.Grant)) == nil {
		t.Fatal("signed owner bound before candidate proof")
	}
	lifecycleSessionProof(t, f, f.challenge(t, 1, p.LifecycleChildCandidate, f.owner.Grant))
	if _, err := f.s.proof(context.Background(), f.challenge(t, 2, p.LifecycleChildCandidate, f.retirement.Grant)); err == nil {
		t.Fatal("retirement preceded signed bound owner")
	}
	for _, retiring := range []bool{false, true} {
		grant := f.owner.Grant
		bind := f.s.bindGrant
		counter := uint64(2)
		if retiring {
			grant, bind, counter = f.retirement.Grant, f.s.bindRetire, 4
			if bind(lifecycleSessionSign(t, f.rootPrivate, grant)) == nil {
				t.Fatal("signed retirement bound before candidate proof")
			}
			for _, kind := range []string{"serial", "id", "generation"} {
				bad := grant
				switch kind {
				case "serial":
					bad.Serial = f.owner.Grant.Serial
				case "id":
					bad.ID = f.owner.Grant.ID
				case "generation":
					bad.Identity.Generation++
				}
				if _, err := f.s.proof(context.Background(), f.challenge(t, 3, p.LifecycleChildCandidate, bad)); err == nil {
					t.Fatal("invalid first retirement candidate", kind)
				}
			}
			lifecycleSessionProof(t, f, f.challenge(t, 3, p.LifecycleChildCandidate, grant))
		}
		for _, kind := range []string{"generation", "id", "serial"} {
			bad := grant
			switch kind {
			case "generation":
				bad.Identity.Generation++
			case "id":
				bad.ID = lifecycleSessionID(t)
			case "serial":
				bad.Serial++
			}
			if _, err := f.s.proof(context.Background(), f.challenge(t, counter, p.LifecycleChildCandidate, bad)); err == nil {
				t.Fatal("provisional candidate replaced", retiring, kind)
			}
			if bind(lifecycleSessionSign(t, f.rootPrivate, bad)) == nil {
				t.Fatal("signature changed provisional tuple", retiring, kind)
			}
		}
		if bind(a.SignedLifecycleGrant{Grant: grant}) == nil {
			t.Fatal("candidate bypassed signature verification")
		}
		lifecycleSessionProof(t, f, f.challenge(t, counter, p.LifecycleChildCandidate, grant))
		check(t, bind(lifecycleSessionSign(t, f.rootPrivate, grant)))
	}
}

func TestLifecycleSessionProvisionalOwnerCannotBoot(t *testing.T) {
	f := newLifecycleSessionIntent(t, false)
	lifecycleSessionProof(t, f, f.challenge(t, 1, p.LifecycleChildCandidate, f.owner.Grant))
	// Construct otherwise valid Guest PKI/authority, but never bind the signed
	// owner to this session; a boot DTO cannot promote the provisional intent.
	f.owner = lifecycleSessionSign(t, f.rootPrivate, f.owner.Grant)
	f.initial = f.owner
	f.startAuthority(t)
	left, right := net.Pipe()
	defer left.Close()
	if f.s.connectTrustedBoot(context.Background(), right, f.boot) == nil {
		t.Fatal("provisional owner booted without signed bind")
	}
	if _, err := left.Write([]byte{1}); err == nil {
		t.Fatal("failed boot leaked owned transport")
	}
}

func TestLifecycleSessionAlreadyRevokedBootClosesOwnedTransport(t *testing.T) {
	f := newLifecycleSessionIntent(t, false)
	f.s.close()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	if err := f.s.connectTrustedBoot(context.Background(), right, lifecycleBoot{}); err == nil {
		t.Fatal("revoked session accepted boot")
	}
	// acquireOperation rejects before boot validation. The named error return
	// still runs connectTrustedBoot's deferred raw.Close on this early path.
	if err := left.SetWriteDeadline(time.Now().Add(time.Second)); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if _, err := left.Write([]byte{1}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("revoked boot did not close its owned transport: %v", err)
	}
}

func TestLifecycleSessionOperationWaitHonorsContextAndClose(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		f := newLifecycleSessionIntent(t, false)
		f.s.op <- struct{}{} // Simulate an operation that has not unwound its IO yet.
		ctx := context.Background()
		cancel := func() {}
		if !revoke {
			ctx, cancel = context.WithTimeout(ctx, 20*time.Millisecond)
		}
		challenge := f.challenge(t, 1, p.LifecycleChildCandidate, f.owner.Grant)
		done := make(chan error, 1)
		go func() { _, err := f.s.proof(ctx, challenge); done <- err }()
		if revoke {
			f.s.close()
		}
		select {
		case err := <-done:
			if err == nil || (!revoke && !errors.Is(err, context.DeadlineExceeded)) {
				t.Fatal("queued proof ignored deadline/revocation", err)
			}
		case <-time.After(time.Second):
			cancel()
			<-f.s.op
			t.Fatal("queued proof blocked beyond context/close")
		}
		cancel()
		<-f.s.op
		if f.s.highWater != 0 || f.s.candidateOwner != (a.LifecycleGrant{}) {
			t.Fatal("unadmitted proof consumed state")
		}
	}
}

func TestLifecycleSessionRejectsUntrustedGrantAndInvalidConstruction(t *testing.T) {
	f := newLifecycleSessionFixture(t, false)
	for name, change := range map[string]func(*lifecycleSessionConfig){
		"root":        func(c *lifecycleSessionConfig) { c.root = p.BootstrapPublicKey{} },
		"overflow":    func(c *lifecycleSessionConfig) { c.expectedEpoch = ^uint64(0) },
		"child":       func(c *lifecycleSessionConfig) { c.processes.childUniqueID = c.processes.daemonUniqueID },
		"daemon":      func(c *lifecycleSessionConfig) { c.processes.daemonUniqueID = 0 },
		"audit":       func(c *lifecycleSessionConfig) { c.processes.childAudit = [32]byte{} },
		"store":       func(c *lifecycleSessionConfig) { c.store = "bad" },
		"binding":     func(c *lifecycleSessionConfig) { c.binding = "bad" },
		"incarnation": func(c *lifecycleSessionConfig) { c.incarnation = "bad" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := f.cfg
			change(&cfg)
			if s, err := newLifecycleSession(cfg); err == nil {
				s.close()
				t.Fatal("invalid constructor accepted")
			}
		})
	}
	for _, kind := range []string{"wrong-root", "unsigned", "store", "binding", "key", "epoch", "retire"} {
		t.Run(kind, func(t *testing.T) {
			s, err := newLifecycleSession(f.cfg)
			check(t, err)
			defer s.close()
			grant := f.owner.Grant
			grant.NewKey = a.Fingerprint(lifecycleSessionPin(t, s).String())
			candidate := &lifecycleSessionFixture{s: s, cfg: f.cfg}
			lifecycleSessionProof(t, candidate, candidate.challenge(t, 1, p.LifecycleChildCandidate, grant))
			private := f.rootPrivate
			switch kind {
			case "wrong-root":
				_, private, err = ed25519.GenerateKey(rand.Reader)
				check(t, err)
			case "store":
				grant.Identity.Store = lifecycleSessionID(t)
			case "binding":
				grant.Identity.Binding = grant.NewKey
			case "key":
				grant.NewKey = f.owner.Grant.NewKey
			case "epoch":
				grant.Operation, grant.ExpectedEpoch = a.LifecycleTakeover, 1
			case "retire":
				grant.Operation, grant.ExpectedEpoch = a.LifecycleRetire, 1
			}
			signed := lifecycleSessionSign(t, private, grant)
			if kind == "unsigned" {
				signed.Signature = nil
			}
			if s.bindGrant(signed) == nil {
				t.Fatal("untrusted grant bound")
			}
			if s.owner.Grant != (a.LifecycleGrant{}) {
				t.Fatal("rejected intent retained")
			}
		})
	}
	s, err := newLifecycleSession(f.cfg)
	check(t, err)
	defer s.close()
	grant := f.owner.Grant
	grant.NewKey = a.Fingerprint(lifecycleSessionPin(t, s).String())
	candidate := &lifecycleSessionFixture{s: s, cfg: f.cfg}
	lifecycleSessionProof(t, candidate, candidate.challenge(t, 1, p.LifecycleChildCandidate, grant))
	signed := lifecycleSessionSign(t, f.rootPrivate, grant)
	check(t, s.bindGrant(signed))
	signed.Signature[0] ^= 1
	if !s.validGrant(s.owner) {
		t.Fatal("caller mutated frozen signature")
	}
	public := f.cfg.root.PublicKey()
	public[0] ^= 1
	if !s.validGrant(s.owner) {
		t.Fatal("caller mutated frozen ROOT verifier")
	}
}

// Pauses only raw transport bytes after a successful read, allowing close to race
// an otherwise successful actual TLS Result. It does not supply any receipt.
type lifecyclePausedRead struct {
	net.Conn
	mu               sync.Mutex
	pause            bool
	entered, release chan struct{}
	once             sync.Once
}

func (r *lifecyclePausedRead) Read(b []byte) (int, error) {
	n, err := r.Conn.Read(b)
	r.mu.Lock()
	pause := r.pause
	r.mu.Unlock()
	if pause && n > 0 {
		r.once.Do(func() { close(r.entered) })
		<-r.release
	}
	return n, err
}
func TestLifecycleSessionRechecksRevocationAfterSuccessfulRead(t *testing.T) {
	f := newLifecycleSessionFixture(t, false)
	left, right := net.Pipe()
	paused := &lifecyclePausedRead{Conn: right, entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- f.server.Serve(context.Background(), left) }()
	t.Cleanup(func() { left.Close(); right.Close(); <-done })
	check(t, f.s.connectTrustedBoot(context.Background(), paused, f.boot))
	paused.mu.Lock()
	paused.pause = true
	paused.mu.Unlock()
	challenge := f.challenge(t, 3, p.LifecycleChildResult, f.owner.Grant)
	proofDone := make(chan error, 1)
	go func() { _, err := f.s.proof(context.Background(), challenge); proofDone <- err }()
	select {
	case <-paused.entered:
	case <-time.After(3 * time.Second):
		close(paused.release)
		t.Fatal("no authenticated result bytes")
	}
	f.s.close()
	close(paused.release)
	select {
	case err := <-proofDone:
		if err == nil {
			t.Fatal("signed after revocation during successful IO")
		}
	case <-time.After(time.Second):
		t.Fatal("revoked proof blocked")
	}
}
func TestLifecycleSessionCloseInterruptsHandshake(t *testing.T) {
	f := newLifecycleSessionFixture(t, false)
	left, right := net.Pipe()
	defer left.Close()
	paused := &lifecyclePausedConn{Conn: right, pause: true, entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- f.s.connectTrustedBoot(context.Background(), paused, f.boot) }()
	select {
	case <-paused.entered:
	case <-time.After(3 * time.Second):
		close(paused.release)
		t.Fatal("no handshake IO")
	}
	closed := make(chan struct{})
	go func() { f.s.close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		close(paused.release)
		t.Fatal("close waited for handshake lock")
	}
	close(paused.release)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("revoked handshake succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("handshake not interrupted")
	}
}

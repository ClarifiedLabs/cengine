package storagebootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	service "dev.cengine/guest/internal/storageservice"
)

type lifecycleRebindFixture struct {
	stops   []func()
	f       *lifecycleSessionFixture
	svc     *service.LifecycleService
	cfg     service.Config
	change  p.LifecycleServiceChangeRequest
	oldBoot lifecycleBoot
}

func newLifecycleRebindFixture(t *testing.T, wrap ...func(net.Conn) net.Conn) *lifecycleRebindFixture {
	t.Helper()
	f := newLifecycleSessionIntent(t, false)
	lifecycleSessionProof(t, f, f.challenge(t, 1, p.LifecycleChildCandidate, f.owner.Grant))
	f.owner = lifecycleSessionSign(t, f.rootPrivate, f.owner.Grant)
	check(t, f.s.bindGrant(f.owner))
	dir := t.TempDir()
	check(t, os.Mkdir(filepath.Join(dir, "volumes"), 0700))
	held, err := os.Open(dir)
	check(t, err)
	t.Cleanup(func() { held.Close() })
	r := &lifecycleRebindFixture{f: f, cfg: service.Config{Root: held, DeviceUUID: "rebind-child", Store: f.cfg.store, Bootstrap: f.cfg.root, Now: f.now, Lifetime: time.Hour}}
	r.svc, err = service.InitializeLifecycle(r.cfg, f.owner)
	check(t, err)
	t.Cleanup(func() { f.s.close(); check(t, r.svc.Close()) })
	r.setBoot(t)
	raw, join := r.stream(t, func(ctx context.Context, peer net.Conn) error {
		if len(wrap) != 0 {
			peer = wrap[0](peer)
		}
		return r.svc.ServeLifecycle(ctx, peer)
	})
	check(t, f.s.connectTrustedBoot(t.Context(), raw, f.boot))
	t.Cleanup(func() { f.s.close(); join() })
	lifecycleSessionProof(t, f, r.challenge(t, 2, p.LifecycleChildServiceResult, nil))
	r.change = p.LifecycleServiceChangeRequest{OperationID: string(lifecycleSessionID(t)), Predecessor: *f.s.serviceState}
	r.oldBoot = f.boot
	return r
}
func (r *lifecycleRebindFixture) stream(t *testing.T, serve func(context.Context, net.Conn) error) (net.Conn, func() error) {
	raw, join := credentialStream(t, serve)
	var once sync.Once
	var result error
	joined := func() error { once.Do(func() { result = join() }); return result }
	stop := func() { raw.Close(); joined() }
	r.stops = append(r.stops, stop)
	t.Cleanup(stop)
	return raw, joined
}
func (r *lifecycleRebindFixture) setBoot(t *testing.T) {
	t.Helper()
	ready, err := r.svc.Ready()
	check(t, err)
	csr, err := r.f.s.controllerCSR()
	check(t, err)
	cert, err := r.svc.IssueController(csr)
	check(t, err)
	root, err := p.ParseRootDER(ready.TLSRootDER)
	check(t, err)
	r.f.boot = lifecycleBoot{identity: r.f.owner.Grant.Identity, signed: r.f.owner, serviceEpoch: ready.ServiceEpoch, root: root, serverPin: ready.ServerKey, certificate: cert}
}
func (r *lifecycleRebindFixture) reopen(t *testing.T) {
	t.Helper()
	for _, stop := range r.stops {
		stop()
	}
	r.stops = nil
	check(t, r.svc.Close())
	var err error
	r.svc, err = service.OpenLifecycle(r.cfg, r.f.owner.Grant.Identity, r.f.owner)
	check(t, err)
	r.setBoot(t)
}
func (r *lifecycleRebindFixture) challenge(t *testing.T, counter uint64, purpose p.LifecycleChildPurpose, confirmation *p.LifecycleServiceChangeConfirmation) p.LifecycleChildChallenge {
	t.Helper()
	fields := r.f.challenge(t, counter, p.LifecycleChildResult, r.f.owner.Grant).Fields()
	fields.Purpose = purpose
	if purpose == p.LifecycleChildServiceCommit {
		fields.Confirmation = confirmation
	} else if r.f.s.pendingRebind != nil {
		fields.ChangeRequest = &r.change
	}
	value, err := p.NewLifecycleChildChallenge(fields)
	check(t, err)
	return value
}
func (r *lifecycleRebindFixture) stage(t *testing.T) net.Conn {
	return r.stageWithServer(t, r.svc.ServeLifecycle)
}
func (r *lifecycleRebindFixture) stageWithServer(t *testing.T, serve func(context.Context, net.Conn) error) net.Conn {
	t.Helper()
	raw, join := r.stream(t, serve)
	counted := &lifecycleCountedConn{Conn: raw}
	boot := r.f.boot
	body := struct {
		Boot   lifecycleBootWire               `json:"boot"`
		Change p.LifecycleServiceChangeRequest `json:"change"`
	}{
		lifecycleBootWire{CertificateDER: boot.certificate.DER(), Identity: boot.identity, RootDER: boot.root.DER(), ServerSPKI: boot.serverPin.String(), ServiceEpoch: boot.serviceEpoch, Signed: boot.signed}, r.change}
	_, err := r.f.s.privateLifecycleRequest(t.Context(), lifecyclePrivateCommand("stage-service-rebind", lifecyclePrivateBody(t, body)), counted)
	check(t, err)
	t.Cleanup(func() { r.f.s.close(); raw.Close(); join() })
	return counted
}
func TestLifecycleRebindROOTOnlyCommitAndLostReceipt(t *testing.T) {
	r := newLifecycleRebindFixture(t)
	f := r.f
	greeting, key, processes, counter := f.s.greeting, f.s.key, f.s.processes, f.s.highWater
	oldClient, oldTrust := f.s.client, f.s.bootTrust
	oldRaw, oldJoin := r.stream(t, r.svc.ServeControl)
	check(t, f.s.connectWorkload(t.Context(), oldRaw))
	t.Cleanup(func() { oldRaw.Close(); oldJoin() })
	// Real paired TLS over TCP: closing the write half forces the next encrypted
	// workload write through crypto/tls's permanentError wrapping EPIPE.
	check(t, oldRaw.(*net.TCPConn).CloseWrite())
	_, loss := f.s.workloadCommand(t.Context(), c.Request{Query: &c.Empty{}})
	var failed *lifecycleWorkloadFailed
	if !errors.As(loss, &failed) || !errors.Is(loss, syscall.EPIPE) {
		t.Fatal("broken pipe did not preserve ROOT with a fenced workload", loss)
	}
	assertLifecycleWorkloadFenced(t, f.s)
	r.reopen(t)
	counted := r.stage(t).(*lifecycleCountedConn)
	if !f.s.workloadFailed || f.s.workload != nil || f.s.pendingRebind == nil || f.s.client != oldClient || f.s.bootTrust != oldTrust {
		t.Fatal("stage promoted or did not fence")
	}
	if f.s.greeting != greeting || f.s.key != key || f.s.processes != processes || f.s.highWater != counter || !f.s.bootAttempted {
		t.Fatal("stage reset child identity/counter")
	}
	if _, err := f.s.workloadCommand(t.Context(), c.Request{Query: &c.Empty{}}); err == nil {
		t.Fatal("pending workload admitted")
	}
	left, right := net.Pipe()
	defer left.Close()
	if err := f.s.connectWorkload(t.Context(), right); err == nil {
		t.Fatal("pending workload connection admitted")
	}
	proof := r.challenge(t, 3, p.LifecycleChildServiceResult, nil)
	result := lifecycleSessionProof(t, f, proof)
	if !f.s.workloadFailed || f.s.client != oldClient || f.s.bootTrust != oldTrust || f.s.pendingRebind == nil {
		t.Fatal("result promoted")
	}
	if _, err := f.s.proof(t.Context(), proof); err == nil {
		t.Fatal("counter replay")
	}
	state, err := p.LifecycleServiceStateFromResult(*result.Fields().ServiceResult, *proof.Fields().Boot)
	check(t, err)
	if state != *f.s.pendingRebind.proven {
		t.Fatal("proof did not bind state")
	}
	confirmation := p.LifecycleServiceChangeConfirmation{Request: r.change, Successor: *f.s.pendingRebind.proven}
	// Parent cannot submit a commit, confirmation or signing operation.
	for _, op := range []string{"serviceCommit", "commit-service-rebind", "service-result", "sign", "proof"} {
		if _, err := f.s.privateLifecycleRequest(t.Context(), lifecyclePrivateCommand(op, lifecyclePrivateBody(t, confirmation)), nil); err == nil {
			t.Fatal("parent committed", op)
		}
	}
	before := counted.count()
	commit := r.challenge(t, 4, p.LifecycleChildServiceCommit, &confirmation)
	lifecycleSessionProof(t, f, commit)
	if f.s.workloadFailed || counted.count() <= before || f.s.pendingRebind != nil || f.s.client == oldClient || f.s.bootTrust == oldTrust || *f.s.latestRebind != confirmation {
		t.Fatal("commit missing fresh IO/promotion")
	}
	before = counted.count()
	retry := r.challenge(t, 5, p.LifecycleChildServiceCommit, &confirmation)
	lifecycleSessionProof(t, f, retry)
	if counted.count() <= before {
		t.Fatal("lost receipt retry used cache")
	}
	lifecycleSessionProof(t, f, r.challenge(t, 6, p.LifecycleChildServiceResult, nil))
	work, join := credentialStream(t, r.svc.ServeControl)
	check(t, f.s.connectWorkload(t.Context(), work))
	response, err := f.s.workloadCommand(t.Context(), c.Request{Query: &c.Empty{}})
	check(t, err)
	var reply c.Response
	check(t, json.Unmarshal(response, &reply))
	if reply.Snapshot == nil {
		t.Fatal("no live workload after rebind")
	}
	work.Close()
	join()
	// Losing the staged/current wire never reuses the latest commit proof.
	counted.Close()
	if _, err := f.s.proof(t.Context(), r.challenge(t, 7, p.LifecycleChildServiceCommit, &confirmation)); err == nil {
		t.Fatal("lost TLS signed cached commit")
	}
}

func TestLifecycleRebindRejectsWrongPredecessorAndTLS(t *testing.T) {
	for _, kind := range []string{"grant", "G", "E", "C", "key", "revision", "same-E", "same-CA", "same-server", "certificate-key", "reissued-old-CA-key"} {
		t.Run(kind, func(t *testing.T) {
			r := newLifecycleRebindFixture(t)
			r.reopen(t)
			change, boot := r.change, r.f.boot
			switch kind {
			case "grant":
				change.Predecessor.Grant.ID = lifecycleSessionID(t)
			case "G":
				change.Predecessor.Grant.Identity.Generation++
			case "E":
				change.Predecessor.Context.ServiceEpoch = string(lifecycleSessionID(t))
			case "C":
				change.Predecessor.Context.ControllerEpoch++
			case "key":
				change.Predecessor.Context.ControllerKey = r.oldBoot.serverPin.String()
			case "revision":
				change.Predecessor.OpenRevision++
			case "same-E":
				boot.serviceEpoch = r.oldBoot.serviceEpoch
			case "same-CA":
				boot.root = r.oldBoot.root
			case "same-server":
				boot.serverPin = r.oldBoot.serverPin
			case "certificate-key":
				boot.certificate = p.Certificate{}
			case "reissued-old-CA-key":
				// Synthetic CA input pair isolates the public-key test before any TLS IO.
				pub, private, err := ed25519.GenerateKey(rand.Reader)
				check(t, err)
				roots := make([]p.Root, 2)
				for i := range roots {
					cert := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLenZero: true}
					der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, private)
					check(t, err)
					roots[i], err = p.ParseRootDER(der)
					check(t, err)
				}
				r.f.s.privateBootConfig.ServerRoot = roots[0]
				prior := *r.f.s.serviceState
				prior.Boot.TLSRootSHA256 = p.Fingerprint(sha256.Sum256(roots[0].DER())).String()
				r.f.s.serviceState = &prior
				change.Predecessor = prior
				boot.root = roots[1]
				if bytes.Equal(roots[0].DER(), roots[1].DER()) {
					t.Fatal("fixture did not reissue")
				}
			}
			left, right := net.Pipe()
			defer left.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			if err := r.f.s.stageServiceRebind(ctx, right, change, boot); err == nil {
				t.Fatal("bad rebind admitted")
			}
			if r.f.s.pendingRebind != nil {
				t.Fatal("invalid shape reached handshake")
			}
		})
	}
}
func TestLifecycleRebindCancellationAndPendingTerminal(t *testing.T) {
	for _, phase := range []string{"stage", "result", "commit", "wrong-root-boot", "wrong-confirmation"} {
		t.Run(phase, func(t *testing.T) {
			r := newLifecycleRebindFixture(t)
			r.reopen(t)
			if phase == "stage" {
				left, right := net.Pipe()
				defer left.Close()
				ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
				defer cancel()
				start := time.Now()
				if r.f.s.stageServiceRebind(ctx, right, r.change, r.f.boot) == nil {
					t.Fatal("blocked handshake succeeded")
				}
				if time.Since(start) > time.Second || !r.f.s.revoked {
					t.Fatal("stage cancellation did not fence on original deadline")
				}
				return
			}
			paused := &lifecyclePausedConn{entered: make(chan struct{}), release: make(chan struct{})}
			r.stageWithServer(t, func(ctx context.Context, conn net.Conn) error {
				paused.Conn = conn
				return r.svc.ServeLifecycle(ctx, paused)
			})
			t.Cleanup(func() { close(paused.release) })
			var confirmation *p.LifecycleServiceChangeConfirmation
			purpose := p.LifecycleChildServiceResult
			if phase == "commit" || phase == "wrong-confirmation" {
				lifecycleSessionProof(t, r.f, r.challenge(t, 3, p.LifecycleChildServiceResult, nil))
				confirmation = &p.LifecycleServiceChangeConfirmation{Request: r.change, Successor: *r.f.s.pendingRebind.proven}
				purpose = p.LifecycleChildServiceCommit
				if phase == "wrong-confirmation" {
					confirmation.Successor.OpenRevision++
				}
			}
			challenge := r.challenge(t, 4, purpose, confirmation)
			if phase == "wrong-root-boot" {
				fields := challenge.Fields()
				fields.Boot.ServerSPKI = r.change.Predecessor.Context.ControllerKey
				var err error
				challenge, err = p.NewLifecycleChildChallenge(fields)
				check(t, err)
			} else if phase != "wrong-confirmation" {
				paused.mu.Lock()
				paused.pause = true
				paused.mu.Unlock()
			}
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			if _, err := r.f.s.proof(ctx, challenge); err == nil {
				t.Fatal("pending failure signed")
			}
			if time.Since(start) > time.Second {
				t.Fatal("proof exceeded original deadline")
			}
			if !r.f.s.revoked || r.f.s.latestRebind != nil {
				t.Fatal("pending failure promoted or reusable")
			}
		})
	}
}

func TestLifecycleRebindPriorCommitCannotPromoteNextStage(t *testing.T) {
	r := newLifecycleRebindFixture(t)
	r.reopen(t)
	r.stage(t)
	lifecycleSessionProof(t, r.f, r.challenge(t, 3, p.LifecycleChildServiceResult, nil))
	prior := p.LifecycleServiceChangeConfirmation{Request: r.change, Successor: *r.f.s.pendingRebind.proven}
	committed := r.challenge(t, 4, p.LifecycleChildServiceCommit, &prior)
	lifecycleSessionProof(t, r.f, committed)
	r.reopen(t)
	r.change.Predecessor = *r.f.s.serviceState
	left, right := net.Pipe()
	defer left.Close()
	if err := r.f.s.stageServiceRebind(t.Context(), right, r.change, r.f.boot); err == nil {
		t.Fatal("latest operation ID reused")
	}
	r.change.OperationID = string(lifecycleSessionID(t))
	r.stage(t)
	fields := committed.Fields()
	fields.Counter = 5
	replay, err := p.NewLifecycleChildChallenge(fields)
	check(t, err)
	if _, err = r.f.s.proof(t.Context(), replay); err == nil {
		t.Fatal("old full confirmation committed next stage")
	}
	if !r.f.s.revoked || *r.f.s.latestRebind != prior || r.f.s.pendingRebind == nil {
		t.Fatal("replay changed current state")
	}
}

func TestLifecycleRebindPrivateBodyClosed(t *testing.T) {
	r := newLifecycleRebindFixture(t)
	boot := r.oldBoot
	body := map[string]any{"change": r.change, "boot": lifecycleBootWire{CertificateDER: boot.certificate.DER(), Identity: boot.identity, RootDER: boot.root.DER(), ServerSPKI: boot.serverPin.String(), ServiceEpoch: boot.serviceEpoch, Signed: boot.signed}}
	for _, field := range []string{"change", "boot", "confirmation", "service_result"} {
		fields := map[string]any{}
		for k, v := range body {
			fields[k] = v
		}
		if field == "change" || field == "boot" {
			delete(fields, field)
		} else {
			fields[field] = map[string]any{}
		}
		left, right := net.Pipe()
		check(t, left.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
		_, err := r.f.s.privateLifecycleRequest(t.Context(), lifecyclePrivateCommand("stage-service-rebind", lifecyclePrivateBody(t, fields)), right)
		if err == nil {
			t.Fatal("open or missing body accepted", field)
		}
		_, err = left.Read(make([]byte, 1))
		left.Close()
		if err == nil {
			t.Fatal("invalid stage leaked descriptor")
		}
		if e, ok := err.(net.Error); ok && e.Timeout() {
			t.Fatal("descriptor was not closed")
		}
	}
}

package storageauthority

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// LifecycleSchemaVersion is deliberately incompatible even at controller epoch 1.
// Production activation uses this registry; old registries are never migrated.
const LifecycleSchemaVersion = 4
const lifecycleFenceName = "lifecycle-retiring"

// SignedLifecycleGrant carries ROOT's signature, not controller authentication.
// Key possession still requires a principal created by authenticated TLS.
type SignedLifecycleGrant struct {
	Grant     LifecycleGrant `json:"grant"`
	Signature []byte         `json:"signature"`
}

type lifecycleApplied struct {
	Grant        LifecycleGrant `json:"grant"`
	ServiceEpoch ID             `json:"service_epoch"`
	Revision     uint64         `json:"revision"`
}

type lifecycleState struct {
	Version       string                  `json:"version"`
	Identity      LifecycleIdentity       `json:"identity"`
	Latest        lifecycleApplied        `json:"latest"`
	OpenRevision  uint64                  `json:"open_revision"`
	Retiring      *LifecycleGrant         `json:"retiring,omitempty"`
	Seal          *lifecycleApplied       `json:"seal,omitempty"`
	ColdApplied   *lifecycleColdApplied   `json:"cold_applied,omitempty"`
	ResumeApplied *lifecycleResumeApplied `json:"resume_applied,omitempty"`
	HandoffFence  *lifecycleHandoffFence  `json:"handoff_fence,omitempty"`
}

type lifecycleOpen struct {
	identity LifecycleIdentity
	initial  SignedLifecycleGrant
	current  *LifecycleGrant
	expected *ExpectedLifecycleStartup
	cold     *LifecycleColdOpenRequest
	resume   *LifecycleResumeOpenRequest
}

func verifyLifecycle(key ed25519.PublicKey, signed SignedLifecycleGrant) error {
	msg, err := LifecycleGrantSigningBytes(signed.Grant)
	if err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, msg, signed.Signature) {
		return ErrUnauthorized
	}
	return nil
}

// InitializeLifecycle creates only a fresh registry after validating ROOT's
// initialize/expected-zero grant. It never adopts, upgrades or resets old bytes.
func InitializeLifecycle(c Config, signed SignedLifecycleGrant) (*Authority, error) {
	// Pin the same ROOT verifier for signature verification and durable state;
	// do not verify caller-owned key bytes and copy them only afterward.
	var err error
	c, err = configured(c)
	if err != nil {
		return nil, err
	}
	if err := verifyLifecycle(c.BootstrapKey, signed); err != nil {
		return nil, err
	}
	g := signed.Grant
	if g.Operation != LifecycleInitialize {
		return nil, ErrInvalid
	}
	initial := lifecycleInitial{g.Identity.Store, Controller{1, g.NewKey}}
	return openAuthority(c, &initial, nil, &lifecycleOpen{identity: g.Identity, initial: signed})
}

// OpenLifecycle requires the full externally reconciled identity. Any pending
// publication, namespace ambiguity or terminal intent refuses without cleanup.
func OpenLifecycle(c Config, expected LifecycleIdentity) (*Authority, error) {
	if err := expected.Validate(); err != nil {
		return nil, err
	}
	return openAuthority(c, nil, nil, &lifecycleOpen{identity: expected})
}

// OpenLifecycleCurrent checks ROOT's exact latest initialize/takeover grant under
// the journal flock before recovery, cleanup or advancing E. The signed identity
// is the expected incarnation; this API never initializes or migrates state.
func OpenLifecycleCurrent(c Config, current SignedLifecycleGrant) (*Authority, error) {
	return openLifecycleCurrent(c, current, nil)
}

// ExpectedLifecycleStartup adds the mandatory persisted live-open anchor to the
// exact predecessor S/E/C/key.
// OpenRevision is not the mutable query revision and has no default.
type ExpectedLifecycleStartup struct {
	ExpectedStartup
	OpenRevision uint64
}

// OpenLifecycleExpected additionally requires the exact reconciled predecessor
// S/E/C/key/open revision. A successful open consumes that predecessor by advancing
// E; any grant/predecessor mismatch leaves all persistent evidence unchanged.
func OpenLifecycleExpected(c Config, current SignedLifecycleGrant, expected ExpectedLifecycleStartup) (*Authority, error) {
	if !validID(expected.Store) || !validID(expected.Epoch) || expected.Controller.Epoch == 0 || !validKey(expected.Controller.Key) || expected.OpenRevision == 0 {
		return nil, ErrInvalid
	}
	return openLifecycleCurrent(c, current, &expected)
}

func openLifecycleCurrent(c Config, current SignedLifecycleGrant, expected *ExpectedLifecycleStartup) (*Authority, error) {
	var err error
	c, err = configured(c)
	if err != nil {
		return nil, err
	}
	if err = verifyLifecycle(c.BootstrapKey, current); err != nil {
		return nil, err
	}
	if current.Grant.Operation == LifecycleRetire {
		return nil, ErrConflict
	}
	var predecessor *ExpectedStartup
	if expected != nil {
		predecessor = &expected.ExpectedStartup
	}
	return openAuthority(c, nil, predecessor, &lifecycleOpen{identity: current.Grant.Identity, current: &current.Grant, expected: expected})
}

// A bounded census also catches interrupted proof publication BEFORE rename,
// including temporaries which ordinary v1 recovery intentionally leaves inert.
func (j *journal) lifecycleNamespaceClean() error {
	fd, err := unix.Openat(int(j.dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(fd), "lifecycle-census")
	defer dir.Close()
	names, err := dir.Readdirnames(3)
	if err != nil && err != io.EOF {
		return err
	}
	if len(names) != 2 {
		return ErrRepairRequired
	}
	for _, name := range names {
		if name != "lock" && name != stateName {
			return ErrRepairRequired
		}
	}
	return nil
}

func (a *Authority) validateLifecycle() error {
	s, l := a.s, a.s.Lifecycle
	if l == nil || l.OpenRevision == 0 || l.OpenRevision > s.Revision || l.Version != LifecycleVersion || l.Identity.Validate() != nil || l.Identity.Store != s.Store.ID || s.Grants != nil || s.ControllerKeys != nil || s.Controller.Key == s.Bootstrap {
		return ErrInvalid
	}
	g := l.Latest.Grant
	if g.Validate() != nil || g.Identity != l.Identity || g.NewKey != s.Controller.Key || !validID(l.Latest.ServiceEpoch) || l.Latest.Revision == 0 || l.Latest.Revision > s.Revision {
		return ErrInvalid
	}
	switch g.Operation {
	case LifecycleInitialize:
		if s.Controller.Epoch != 1 {
			return ErrInvalid
		}
	case LifecycleTakeover:
		if s.Controller.Epoch != g.ExpectedEpoch+1 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	if m := l.ColdApplied; m != nil {
		if !validKey(Fingerprint(m.RequestSHA256)) || g.Operation != LifecycleTakeover || m.GrantID != g.ID ||
			m.ServiceEpoch != l.Latest.ServiceEpoch || m.OpenRevision != l.Latest.Revision || m.OpenRevision > l.OpenRevision ||
			(m.OpenRevision == l.OpenRevision && m.ServiceEpoch != s.Epoch) ||
			(m.OpenRevision < l.OpenRevision && m.ServiceEpoch == s.Epoch) {
			return ErrInvalid
		}
	}
	if m := l.ResumeApplied; m != nil {
		// A fresh resume from the strict empty layout publishes the successor as
		// revision 1 with controller epoch 2 (the synthetic genesis never reaches
		// disk), so revision is deliberately NOT ordered against controller epoch
		// here: OpenRevision == Latest.Revision == 1 is valid for the resume
		// marker while the current epoch matches. Ordinary takeover markers are
		// unchanged and still require their applied revision to track s.Revision.
		if l.ColdApplied != nil || !validKey(Fingerprint(m.RequestSHA256)) || g.Operation != LifecycleTakeover || m.GrantID != g.ID ||
			m.ServiceEpoch != l.Latest.ServiceEpoch || m.OpenRevision != l.Latest.Revision || m.OpenRevision > l.OpenRevision ||
			(m.OpenRevision == l.OpenRevision && m.ServiceEpoch != s.Epoch) ||
			(m.OpenRevision < l.OpenRevision && m.ServiceEpoch == s.Epoch) {
			return ErrInvalid
		}
	}
	if err := a.validateHandoffFence(); err != nil {
		return err
	}
	if l.Retiring == nil {
		if l.Seal != nil {
			return ErrInvalid
		}
		return nil
	}
	r := *l.Retiring
	if r.Validate() != nil || r.Operation != LifecycleRetire || r.Identity != l.Identity || r.ExpectedEpoch != s.Controller.Epoch || r.NewKey != s.Controller.Key || r.Serial <= g.Serial || r.ID == g.ID {
		return ErrInvalid
	}
	if l.Seal != nil && (l.Seal.Grant != r || l.Seal.ServiceEpoch != s.Epoch || l.Seal.Revision != s.Revision) {
		return ErrInvalid
	}
	return a.lifecycleQuiescentState()
}

// TakeoverLifecycle retains only the latest exact applied tuple. Serial/epoch
// high-water checks, not an unbounded UUID/key blacklist, reject old grants.
// The trusted child must generate a fresh nonexporting key; TLS proves possession,
// not hardware nonexportability. There is no exported unchecked principal seam.
func (a *Authority) TakeoverLifecycle(p *SuccessorPrincipal, signed SignedLifecycleGrant) (Controller, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.available(); err != nil {
		return Controller{}, err
	}
	if a.s.Lifecycle == nil {
		return Controller{}, ErrInvalid
	}
	g := signed.Grant
	if p == nil || p.owner != a || p.key != g.NewKey {
		return Controller{}, ErrUnauthorized
	}
	if err := verifyLifecycle(a.bootstrap, signed); err != nil {
		return Controller{}, err
	}
	l := a.s.Lifecycle
	if g.Operation != LifecycleTakeover || g.Identity != l.Identity {
		return Controller{}, ErrUnauthorized
	}
	// Fence before even an exact-applied retry: abandoned recipients cannot
	// regain a successful controller result via an already-authenticated session.
	if f := l.HandoffFence; f != nil && g.Serial <= f.Request.Pending.Serial {
		return Controller{}, ErrUnauthorized
	}
	if g == l.Latest.Grant {
		return a.s.Controller, nil
	}
	if g.Serial <= l.Latest.Grant.Serial || g.ID == l.Latest.Grant.ID || g.ExpectedEpoch != a.s.Controller.Epoch || a.keyUsed(g.NewKey) {
		return Controller{}, ErrUnauthorized
	}
	if a.dataIO != nil || a.copyIO != nil {
		return Controller{}, ErrBusy
	}
	if err := a.j.lifecycleNamespaceClean(); err != nil {
		return Controller{}, err
	}
	next := a.clone()
	next.Controller = Controller{g.ExpectedEpoch + 1, g.NewKey}
	next.Lifecycle.Latest = lifecycleApplied{g, a.s.Epoch, a.s.Revision + 1}
	next.Lifecycle.ColdApplied = nil
	next.Lifecycle.ResumeApplied = nil
	if err := a.commit(next); err != nil {
		return Controller{}, err
	}
	return a.s.Controller, nil
}

func (a *Authority) lifecycleQuiescentState() error {
	for _, rec := range a.s.Attachments {
		if rec.Phase != Drained || rec.Receipt == nil {
			return ErrBusy
		}
	}
	for _, prep := range a.s.Prepares {
		if prep.Phase == Pending {
			return ErrBusy
		}
	}
	for _, life := range a.s.VolumeLifecycles {
		if life.Phase != VolumeReady && life.Phase != VolumeDeleted {
			return ErrBusy
		}
	}
	if a.s.Copy == nil || len(a.s.CopyReplay) != 0 {
		return ErrBlocked
	}
	for _, intent := range a.s.Copy.Intents {
		if intent.Phase != CopyCompleted {
			return ErrBusy
		}
	}
	return nil
}

// RetireLifecycle refuses outstanding owners; callers first use the existing
// Retire/CompletePrepare protocols. Neither a daemon assertion nor a syncfs-only
// callback can replace Config.Barrier's retained-resource contract. The permanent
// fence and terminal seal revoke this generation, NOT permission to delete it.
func (a *Authority) RetireLifecycle(p *ControllerPrincipal, signed SignedLifecycleGrant) error {
	a.barrierMu.Lock()
	defer a.barrierMu.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.control(p); err != nil {
		return err
	}
	if a.s.Lifecycle == nil {
		return ErrInvalid
	}
	if err := verifyLifecycle(a.bootstrap, signed); err != nil {
		return err
	}
	g, l := signed.Grant, a.s.Lifecycle
	if g.Operation != LifecycleRetire || g.Identity != l.Identity || g.ExpectedEpoch != a.s.Controller.Epoch || g.NewKey != a.s.Controller.Key || g.Serial <= l.Latest.Grant.Serial || g.ID == l.Latest.Grant.ID {
		return ErrUnauthorized
	}
	if err := a.validate(); err != nil {
		return err
	}
	if err := a.lifecycleQuiescentState(); err != nil {
		return err
	}
	if a.dataIO != nil || a.copyIO != nil || a.inflight != 0 || a.drains != 0 {
		return ErrBusy
	}
	for _, rt := range a.runtime {
		if rt.count != 0 || rt.err != nil {
			return ErrBusy
		}
	}
	if err := a.j.lifecycleNamespaceClean(); err != nil {
		return err
	}
	// Fence memory BEFORE IO, then permanently fence disk before the final
	// barriers. Failure never restores admission, even if intent commit fails.
	next := a.clone()
	next.Lifecycle.Retiring = &g
	a.s.Lifecycle.Retiring = &g
	a.wakeAllCopyFences()
	if err := a.j.markNamed(lifecycleFenceName); err != nil {
		return a.poison(err)
	}
	if err := a.commit(next); err != nil {
		return a.retirementFailure(err)
	}
	// No ordinary work can enter; drains pins all borrowed roots against Close.
	a.drains++
	a.mu.Unlock()
	err := a.lifecycleFinalBarrier()
	a.mu.Lock()
	a.drains--
	if err != nil {
		return a.poison(err)
	}
	if a.fault != nil {
		return fmt.Errorf("%w: %w", ErrBlocked, a.fault)
	}
	next = a.clone()
	next.Lifecycle.Seal = &lifecycleApplied{g, a.s.Epoch, a.s.Revision + 1}
	if err = a.commit(next); err != nil {
		return a.retirementFailure(err)
	}
	return nil
}

func (a *Authority) lifecycleFinalBarrier() error {
	// These same bindings already have durable Drained receipts proving the
	// original barrier. Repeat the full resource barrier under closed admission.
	for _, rec := range a.s.Attachments {
		// Deleted roots were already drained before DeleteVolume synchronized
		// their removal. Never pass a nonexistent borrowed root to a barrier.
		if a.s.VolumeLifecycles[rec.Binding.Volume].Phase == VolumeDeleted {
			continue
		}
		if err := callBarrier(a.barrier, rec.Binding, a.roots[rec.Binding.Volume]); err != nil {
			return err
		}
	}
	for id, v := range a.s.Volumes {
		if a.s.VolumeLifecycles[id].Phase == VolumeDeleted {
			if err := a.deletedRootAbsent(v); err != nil {
				return err
			}
			continue
		}
		named, err := a.j.volume(v)
		if err != nil {
			return err
		}
		if err = named.Close(); err != nil {
			return err
		}
		if a.roots[id] == nil {
			return ErrConflict
		}
		if held, err := identity(a.roots[id]); err != nil || held != v.Root {
			return ErrConflict
		}
	}
	for _, root := range a.roots {
		if err := a.j.step("lifecycle-volume-sync", root.Sync); err != nil {
			return err
		}
	}
	for _, step := range []struct {
		name string
		file *os.File
	}{
		{"lifecycle-exports-sync", a.j.exports}, {"lifecycle-root-sync", a.j.root}, {"lifecycle-registry-sync", a.j.dir},
	} {
		if err := a.j.step(step.name, step.file.Sync); err != nil {
			return err
		}
	}
	return nil
}

// AuthenticateLifecycleResult is an explicit read-only TLS path on a still-live
// instance, including after sealing. It does not reopen disk or ordinary control.
func (a *Authority) AuthenticateLifecycleResult(ctx context.Context, conn *tls.Conn, epoch uint64) (*ControllerPrincipal, error) {
	key, err := verifiedPeer(ctx, conn)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, ErrClosed
	}
	if a.fault != nil {
		return nil, ErrBlocked
	}
	if a.s.Lifecycle == nil || a.s.Controller != (Controller{epoch, key}) {
		return nil, ErrUnauthorized
	}
	return &ControllerPrincipal{a, epoch, key}, nil
}

// LifecycleServiceResult authenticates a current TLS-derived principal against
// the exact latest grant and returns this open's E/revision. It never alters the
// stable applied result and cannot attest to a retiring, sealed or poisoned owner.
func (a *Authority) LifecycleServiceResult(p *ControllerPrincipal, grant LifecycleGrant, nonce []byte) (LifecycleServiceResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.control(p); err != nil {
		return LifecycleServiceResult{}, err
	}
	l := a.s.Lifecycle
	if l == nil || len(nonce) != 32 {
		return LifecycleServiceResult{}, ErrInvalid
	}
	if l.Seal != nil {
		return LifecycleServiceResult{}, ErrBlocked
	}
	if grant != l.Latest.Grant {
		return LifecycleServiceResult{}, ErrUnauthorized
	}
	r := LifecycleServiceResult{l.Identity, grant, append([]byte(nil), nonce...), a.s.Epoch, a.s.Controller.Epoch, a.s.Controller.Key, l.OpenRevision}
	if r.Validate() != nil || l.OpenRevision > a.s.Revision {
		return LifecycleServiceResult{}, ErrInvalid
	}
	return r, nil
}

// LifecycleResult reads an exact applied result for a fresh ROOT nonce; it never
// replays a grant to mutate state. This DTO is NOT self-authenticating. The future
// direct-child adapter must authenticate its source and correlate ROOT's nonce.
func (a *Authority) LifecycleResult(p *ControllerPrincipal, grant LifecycleGrant, nonce []byte) (LifecycleReceipt, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return LifecycleReceipt{}, ErrClosed
	}
	if a.fault != nil {
		return LifecycleReceipt{}, ErrBlocked
	}
	if p == nil || p.owner != a || p.epoch != a.s.Controller.Epoch || p.key != a.s.Controller.Key {
		return LifecycleReceipt{}, ErrUnauthorized
	}
	if len(nonce) != 32 || a.s.Lifecycle == nil {
		return LifecycleReceipt{}, ErrInvalid
	}
	l := a.s.Lifecycle
	result := l.Latest
	if l.Retiring != nil {
		if l.Seal == nil {
			return LifecycleReceipt{}, ErrBlocked
		}
		result = *l.Seal
	}
	if result.Grant != grant {
		return LifecycleReceipt{}, ErrUnauthorized
	}
	return LifecycleReceipt{result.Grant, append([]byte(nil), nonce...), result.ServiceEpoch, result.Revision}, nil
}

package storageauthority

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"
)

type operation struct {
	Kind   string `json:"kind"`
	Digest string `json:"digest"`
}
type diskState struct {
	Schema     int         `json:"schema"`
	Durability int         `json:"durability"`
	Revision   uint64      `json:"revision"`
	Store      Store       `json:"store"`
	Epoch      ID          `json:"epoch"`
	Controller Controller  `json:"controller"`
	Bootstrap  Fingerprint `json:"bootstrap"`
	// Reserved null slots preserve the current schema-4 journal encoding.
	// Non-null legacy histories are never interpreted or accepted.
	ControllerKeys   *struct{}                  `json:"controller_keys"`
	Volumes          map[ID]Volume              `json:"volumes"`
	VolumeLifecycles map[ID]VolumeLifecycle     `json:"volume_lifecycles"`
	Attachments      map[ID]Attachment          `json:"attachments"`
	Prepares         map[ID]Prepare             `json:"prepares"`
	Operations       map[ID]operation           `json:"operations"`
	Grants           *struct{}                  `json:"grants"`
	Copy             *copyState                 `json:"copy,omitempty"`
	CopyReplay       map[ID]copyOperationRecord `json:"copy_replay,omitempty"`
	Lifecycle        *lifecycleState            `json:"lifecycle,omitempty"`
}

// Snapshot is an isolated copy: changing it cannot change authority.
type Snapshot struct {
	Schema           int                    `json:"schema"`
	Revision         uint64                 `json:"revision"`
	Store            Store                  `json:"store"`
	Epoch            ID                     `json:"epoch"`
	Controller       Controller             `json:"controller"`
	Volumes          map[ID]Volume          `json:"volumes"`
	VolumeLifecycles map[ID]VolumeLifecycle `json:"volume_lifecycles"`
	Attachments      map[ID]Attachment      `json:"attachments"`
	Prepares         map[ID]Prepare         `json:"prepares"`
}
type runtimeAttachment struct {
	count     int
	zero      chan struct{}
	connected bool
	done      chan struct{}
	err       error
}
type Authority struct {
	prepareCompatibility   atomic.Pointer[PrepareCompatibilityWitness]
	mu                     sync.Mutex
	s                      *diskState
	j                      *journal
	roots                  map[ID]*os.File
	runtime                map[ID]*runtimeAttachment
	copyFences             map[ID]chan struct{}
	limits                 Limits
	bootstrap              ed25519.PublicKey
	barrier                Barrier
	prepareRetirementProof func(Binding, *os.File, func() (bool, error)) (bool, error)
	fault                  error
	closed                 bool
	inflight               int
	drains                 int
	// Barriers serialize with each other, never with admission or control fencing.
	// Their independent uncertainty marker survives unrelated journal commits.
	barrierMu sync.Mutex
	dataIO    *durabilityToken // one bounded service-global namespace obligation
	copyIO    *copyOperationToken
}

func configured(c Config) (Config, error) {
	if c.Root == nil || c.DeviceID == "" || len(c.DeviceID) > 256 || !utf8.ValidString(c.DeviceID) || len(c.BootstrapKey) != ed25519.PublicKeySize || c.Barrier == nil {
		return c, ErrInvalid
	}
	if c.Limits == (Limits{}) {
		c.Limits = DefaultLimits()
	}
	l := c.Limits
	if l.Volumes < 1 || l.Attachments < 1 || l.Prepares < 1 || l.Operations < 1 || l.InFlight < 1 || l.JournalBytes < 1024 {
		return c, ErrInvalid
	}
	c.BootstrapKey = append(ed25519.PublicKey(nil), c.BootstrapKey...)
	return c, nil
}

func openAuthority(c Config, initial *lifecycleInitial, expected *ExpectedStartup, lifecycle *lifecycleOpen) (*Authority, error) {
	if lifecycle == nil {
		return nil, ErrInvalid
	}
	c, err := configured(c)
	if err != nil {
		return nil, err
	}
	boot, err := PublicKeyFingerprint(c.BootstrapKey)
	if err != nil {
		return nil, err
	}
	if initial != nil && (!validID(initial.Store) || initial.Controller.Epoch != 1 || !validKey(initial.Controller.Key) || initial.Controller.Key == boot) {
		return nil, ErrInvalid
	}
	// A fresh resume accepts only the strict closed empty layout or the exact
	// original genesis registry. Census read-only first: when the registry
	// exists, drop the synthetic genesis initializer and let exact-genesis
	// admission under the real journal flock decide. A missing volumes artifact
	// is created only now, after the census and the request signature have fully
	// admitted the layout, and before the journal opens.
	resumeInit := false
	if lifecycle != nil && lifecycle.resume != nil && initial != nil {
		census, err := probeResumeLayout(c.Root)
		if err != nil {
			return nil, err
		}
		if census == resumeCensusRegistry {
			initial = nil
		} else {
			resumeInit = true
			if census == resumeCensusEmptyNoVolumes {
				if err := createResumeVolumes(c.Root); err != nil {
					return nil, err
				}
			}
		}
	}
	j, err := openJournal(c, initial != nil)
	if err != nil {
		return nil, err
	}
	a := &Authority{j: j, limits: c.Limits, bootstrap: c.BootstrapKey, barrier: c.Barrier, prepareRetirementProof: c.PrepareRetirementProof, roots: map[ID]*os.File{}, runtime: map[ID]*runtimeAttachment{}, copyFences: map[ID]chan struct{}{}}
	ok := false
	defer func() {
		if !ok {
			for _, f := range a.roots {
				f.Close()
			}
			j.close()
		}
	}()
	root, err := identity(j.root)
	if err != nil {
		return nil, err
	}
	exports, err := identity(j.exports)
	if err != nil {
		return nil, err
	}
	if initial != nil {
		a.s = &diskState{Schema: LifecycleSchemaVersion, Durability: durabilityVersion, Store: Store{initial.Store, c.DeviceID, root, exports}, Controller: initial.Controller, Bootstrap: boot,
			Volumes: map[ID]Volume{}, VolumeLifecycles: map[ID]VolumeLifecycle{}, Attachments: map[ID]Attachment{}, Prepares: map[ID]Prepare{}, Operations: map[ID]operation{}, Copy: &copyState{Version: copySchemaVersion, Intents: map[ID]CopyIntent{}}}
		if lifecycle != nil {
			a.s.Schema = LifecycleSchemaVersion
			a.s.Lifecycle = &lifecycleState{Version: LifecycleVersion, Identity: lifecycle.identity, Latest: lifecycleApplied{Grant: lifecycle.initial.Grant}}
		}
	} else {
		a.s, err = j.load()
		if err != nil {
			return nil, err
		}
		if a.s.Schema != LifecycleSchemaVersion || a.s.Lifecycle == nil {
			return nil, ErrInvalid
		}
		if a.s.Lifecycle.Identity != lifecycle.identity {
			return nil, ErrConflict
		}
		if a.s.Lifecycle.Retiring != nil {
			return nil, ErrBlocked
		}

		if a.s.Store.DeviceID != c.DeviceID || a.s.Store.Root != root || a.s.Store.Exports != exports || a.s.Bootstrap != boot {
			return nil, ErrConflict
		}
		if err = a.validate(); err != nil {
			return nil, err
		}
		if lifecycle != nil && lifecycle.cold != nil {
			if err = a.admitColdOpen(*lifecycle.cold); err != nil {
				return nil, err
			}
		}
		if lifecycle != nil && lifecycle.resume != nil && initial == nil {
			// Distinct admission, not the weak cold predecessor: only the exact
			// original genesis registry is consumable, never recovered, cleaned
			// or reinterpreted, and no commit happens on refusal.
			if err = a.admitResumeOpen(*lifecycle.resume); err != nil {
				return nil, err
			}
		}
		// The journal flock is held and state is validated. Reject stale boot
		// intent before recovery/cleanup, generating an epoch or any mutation.
		if lifecycle != nil && lifecycle.current != nil && a.s.Lifecycle.Latest.Grant != *lifecycle.current {
			return nil, ErrConflict
		}
		if lifecycle != nil && lifecycle.expected != nil && a.s.Lifecycle.OpenRevision != lifecycle.expected.OpenRevision {
			return nil, ErrConflict
		}
		if expected != nil && (a.s.Store.ID != expected.Store || a.s.Epoch != expected.Epoch || a.s.Controller != expected.Controller) {
			return nil, ErrConflict
		}
		for id, v := range a.s.Volumes {
			phase := a.s.VolumeLifecycles[id].Phase
			if phase == VolumeCreating || phase == VolumeDeleting {
				return nil, fmt.Errorf("%w: volume %s %s", ErrRepairRequired, id, phase)
			}
			if phase == VolumeDeleted {
				if err = a.deletedRootAbsent(v); err != nil {
					return nil, err
				}
				continue
			}
			f, e := j.volume(v)
			if e != nil {
				return nil, e
			}
			a.roots[id] = f
		}
	}
	var lifecycleTemporaries []string
	if lifecycle != nil && initial == nil {
		lifecycleTemporaries, err = a.admitLifecycleRecovery(lifecycle)
		if err != nil {
			return nil, err
		}
	}
	if j.rootOnly != nil {
		// Validate the retry-only proof before copy reconstruction or ANY cleanup.
		// ExpectedStartup, state semantics and every retained root were checked above.
		if err = a.validatePrepareRetirementRecovery(); err != nil {
			return nil, err
		}
	}
	if err = a.loadCopyOperation(); err != nil {
		return nil, err
	}
	if err = a.preflightCopyRecovery(c.CopyRecoveryPreflight); err != nil {
		return nil, err
	}
	if j.retirement != nil {
		// Assess the complete retirement/metadata pair before either cleanup can
		// mutate evidence. ExpectedStartup and all retained roots are checked above.
		if err = j.validateRetirementRecovery(); err != nil {
			return nil, err
		}
	}
	// Every lifecycle artifact and all startup guards have been validated under
	// flock. Remove only transaction-bound temporaries, while their published
	// proof still survives, so a cleanup crash can retry the same admission.
	if err = j.clearLifecycleTemporaries(lifecycleTemporaries); err != nil {
		return nil, err
	}
	if j.uncertain {
		// RTM099: resolve only journal-metadata transaction uncertainty that
		// the versioned durable commit proof makes provable. This runs after
		// state, copy-operation, expected-predecessor, and volume validation,
		// so every ambiguity leaves all files untouched.
		if err = j.recoverUncertainty(); err != nil {
			return nil, err
		}
	}
	if j.retirement != nil {
		if err = j.recoverRetirement(); err != nil {
			return nil, err
		}
	}
	if j.rootOnly != nil {
		if err = j.recoverPrepareRetirement(); err != nil {
			return nil, err
		}
	}
	next := a.clone()
	next.Epoch, err = NewID()
	if err != nil {
		return nil, err
	}
	if lifecycle != nil {
		// Publish the live-open anchor in the same commit as its fresh E. Never
		// derive it from later workload/takeover revisions or repair old schemas.
		next.Lifecycle.OpenRevision = a.s.Revision + 1
		if lifecycle.cold != nil {
			g := lifecycle.cold.Takeover.Grant
			next.Controller = Controller{g.ExpectedEpoch + 1, g.NewKey}
			next.Lifecycle.Latest = lifecycleApplied{g, next.Epoch, a.s.Revision + 1}
			next.Lifecycle.ColdApplied = &lifecycleColdApplied{coldRequestDigest(*lifecycle.cold), g.ID, next.Epoch, a.s.Revision + 1}
		}
		if lifecycle.resume != nil && !resumeInit {
			g := lifecycle.resume.Takeover.Grant
			next.Controller = Controller{g.ExpectedEpoch + 1, g.NewKey}
			next.Lifecycle.Latest = lifecycleApplied{g, next.Epoch, a.s.Revision + 1}
			next.Lifecycle.ResumeApplied = &lifecycleResumeApplied{resumeRequestDigest(*lifecycle.resume), g.ID, next.Epoch, a.s.Revision + 1}
		}
		if initial != nil && !resumeInit {
			next.Lifecycle.Latest.ServiceEpoch = next.Epoch
			next.Lifecycle.Latest.Revision = 1
		}
	}
	if resumeInit {
		// The strict empty layout publishes the successor directly as the ONE
		// durable registry state: the synthetic genesis never reaches disk, the
		// old original controller key is never persisted, and exactly one journal
		// save lands (revision 1, controller epoch 2). A crash before this commit
		// leaves no registry, so the retry re-censuses the empty layout; a crash
		// after it leaves the exact applied successor, which the retry refuses as
		// already applied.
		g := lifecycle.resume.Takeover.Grant
		next.Controller = Controller{g.ExpectedEpoch + 1, g.NewKey}
		next.Lifecycle.Latest = lifecycleApplied{g, next.Epoch, next.Lifecycle.OpenRevision}
		next.Lifecycle.ResumeApplied = &lifecycleResumeApplied{resumeRequestDigest(*lifecycle.resume), g.ID, next.Epoch, next.Lifecycle.OpenRevision}
	}
	for id, rec := range next.Attachments {
		if rec.Phase == Active || rec.Phase == Reserved {
			rec.Phase = Retiring
			next.Attachments[id] = rec
		}
		a.runtime[id] = newRuntime()
	}
	if err = a.commit(next); err != nil {
		return nil, err
	}
	if err = a.clearStartupCopyOperation(); err != nil {
		return nil, a.poison(err)
	}
	for volume := range a.s.Copy.Intents {
		a.wakeCopyFence(volume)
	}
	ok = true
	return a, nil
}
func newRuntime() *runtimeAttachment {
	c := make(chan struct{})
	close(c)
	return &runtimeAttachment{zero: c}
}
func (a *Authority) clone() *diskState {
	b, _ := json.Marshal(a.s)
	var s diskState
	_ = json.Unmarshal(b, &s)
	return &s
}
func (a *Authority) available() error {
	if a.s != nil && a.s.Lifecycle != nil && a.s.Lifecycle.Retiring != nil {
		return ErrBlocked
	}
	if a.closed {
		return ErrClosed
	}
	if a.fault != nil {
		return fmt.Errorf("%w: %w", ErrBlocked, a.fault)
	}
	return nil
}
func (a *Authority) poison(err error) error {
	if a.fault == nil {
		a.fault = err
		a.wakeAllCopyFences()
		a.j.quarantine()
	}
	return fmt.Errorf("%w: %w", ErrBlocked, a.fault)
}
func (a *Authority) commit(next *diskState) error {
	if a.s.Revision == ^uint64(0) {
		return ErrLimit
	}
	next.Revision = a.s.Revision + 1
	b, err := json.Marshal(next)
	if err != nil {
		return a.poison(err)
	}
	if err = a.capacity(next, int64(len(b))); err != nil {
		return err
	}
	if err = a.j.persist(next); err != nil {
		return a.poison(err)
	}
	a.s = next
	return nil
}
func (a *Authority) control(p *ControllerPrincipal) error {
	if err := a.available(); err != nil {
		return err
	}
	if p == nil || p.owner != a || p.epoch != a.s.Controller.Epoch || p.key != a.s.Controller.Key {
		return ErrUnauthorized
	}
	return nil
}
func (a *Authority) Query(p *ControllerPrincipal) (Snapshot, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.control(p); err != nil {
		return Snapshot{}, err
	}
	s := a.clone()
	return Snapshot{s.Schema, s.Revision, s.Store, s.Epoch, s.Controller, s.Volumes, s.VolumeLifecycles, s.Attachments, s.Prepares}, nil
}

// Epoch is public handshake metadata, never proof of authority.
func (a *Authority) Epoch() ID { a.mu.Lock(); defer a.mu.Unlock(); return a.s.Epoch }
func (a *Authority) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	if a.inflight != 0 || a.drains != 0 {
		return ErrBusy
	}
	a.closed = true
	a.wakeAllCopyFences()
	for _, f := range a.roots {
		f.Close()
	}
	a.j.close()
	return nil
}
func digest(kind string, arg any) operation {
	b, _ := json.Marshal(arg)
	h := sha256.Sum256(b)
	return operation{kind, hex.EncodeToString(h[:])}
}
func (a *Authority) operation(id ID, kind string, arg any) (operation, bool, error) {
	if !validID(id) {
		return operation{}, false, ErrInvalid
	}
	op := digest(kind, arg)
	if old, ok := a.s.Operations[id]; ok {
		if old != op {
			return op, false, ErrConflict
		}
		return op, true, nil
	}
	if len(a.s.Operations) >= a.limits.Operations {
		return op, false, ErrLimit
	}
	return op, false, nil
}
func (a *Authority) keyUsed(key Fingerprint) bool {
	if key == a.s.Bootstrap || key == a.s.Controller.Key {
		return true
	}
	for _, rec := range a.s.Attachments {
		if rec.Binding.Key == key {
			return true
		}
	}
	return false
}
func volumeValid(v Volume) bool {
	return validID(v.ID) && v.Name != "" && utf8.ValidString(v.Name) && v.Name != "." && v.Name != ".." && len(v.Name) <= 255 && !strings.ContainsAny(v.Name, "/\x00") && v.Root.Inode != 0
}
func bindingValid(b Binding, s *diskState) bool {
	if b.Store != s.Store.ID || !validID(b.Volume) || !validID(b.Attachment) || !validContainerID(b.Container) || !validID(b.Launch) || !validKey(b.Key) || (b.Mode != ReadOnly && b.Mode != ReadWrite) {
		return false
	}
	if b.Role == PrepareRole {
		return validID(b.Prepare)
	}
	return b.Role == RuntimeRole && b.Prepare == ""
}
func (a *Authority) AddVolume(p *ControllerPrincipal, req VolumeRequest) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.control(p); err != nil {
		return err
	}
	if life, ok := a.s.VolumeLifecycles[req.Volume.ID]; ok && (life.Phase != VolumeReady || life.Create != "") {
		return ErrConflict
	}
	op, repeat, err := a.operation(req.Operation, "volume", req)
	if err != nil || repeat {
		return err
	}
	v := req.Volume
	if !volumeValid(v) || v.Root.Device != a.s.Store.Root.Device {
		return ErrInvalid
	}
	if old, ok := a.s.Volumes[v.ID]; ok && old != v {
		return ErrConflict
	}
	for id, old := range a.s.Volumes {
		if id != v.ID && (old.Name == v.Name || old.Root == v.Root) {
			return ErrConflict
		}
	}
	if _, ok := a.s.Volumes[v.ID]; !ok && len(a.s.Volumes) >= a.limits.Volumes {
		return ErrLimit
	}
	root, err := a.j.volume(v)
	if err != nil {
		return err
	}
	defer func() {
		if root != nil {
			root.Close()
		}
	}()
	next := a.clone()
	next.Volumes[v.ID] = v
	next.VolumeLifecycles[v.ID] = VolumeLifecycle{Phase: VolumeReady}
	next.Operations[req.Operation] = op
	if err = a.commit(next); err != nil {
		return err
	}
	if a.roots[v.ID] == nil {
		a.roots[v.ID] = root
		root = nil
	}
	return nil
}
func canonicalReserve(r ReserveRequest) ReserveRequest {
	r.Attachments = append([]Binding(nil), r.Attachments...)
	sort.Slice(r.Attachments, func(i, j int) bool { return r.Attachments[i].Volume < r.Attachments[j].Volume })
	return r
}
func reservedVolume(s *diskState, volume ID, except ID) bool {
	for id, prep := range s.Prepares {
		if id == except || prep.Phase != Pending {
			continue
		}
		for _, b := range prep.Attachments {
			if b.Volume == volume {
				return true
			}
		}
	}
	return false
}
func (a *Authority) plan(next *diskState, req ReserveRequest, except ID) error {
	if !validID(req.Prepare) || len(req.Attachments) == 0 {
		return ErrInvalid
	}
	if old, ok := next.Prepares[req.Prepare]; ok {
		if reflect.DeepEqual(old.Attachments, req.Attachments) {
			return nil
		}
		return ErrConflict
	}
	if len(next.Prepares) >= a.limits.Prepares || len(next.Attachments)+len(req.Attachments) > a.limits.Attachments {
		return ErrLimit
	}
	volumes := map[ID]bool{}
	keys := map[Fingerprint]bool{}
	ids := map[ID]bool{}
	for _, b := range req.Attachments {
		if !bindingValid(b, next) || b.Role != PrepareRole || b.Prepare != req.Prepare || volumes[b.Volume] || ids[b.Attachment] || keys[b.Key] {
			return ErrInvalid
		}
		if _, ok := next.Volumes[b.Volume]; !ok {
			return ErrUnknown
		}
		if _, ok := next.Attachments[b.Attachment]; ok || a.keyUsed(b.Key) {
			return ErrConflict
		}
		if next.VolumeLifecycles[b.Volume].Phase != VolumeReady || reservedVolume(next, b.Volume, except) {
			return ErrBlocked
		}
		volumes[b.Volume] = true
		keys[b.Key] = true
		ids[b.Attachment] = true
	}
	for _, b := range req.Attachments {
		next.Attachments[b.Attachment] = Attachment{Binding: b, Phase: Reserved}
	}
	prep := Prepare{ID: req.Prepare, Attachments: req.Attachments, Phase: Pending}
	if next.Lifecycle != nil {
		prep.Context = &PrepareContext{next.Epoch, next.Controller.Epoch, next.Controller.Key}
	}
	next.Prepares[req.Prepare] = prep
	return nil
}
func (a *Authority) ReservePrepare(p *ControllerPrincipal, req ReserveRequest) error {
	req = canonicalReserve(req)
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.control(p); err != nil {
		return err
	}
	op, repeat, err := a.operation(req.Operation, "reserve", req)
	if err != nil || repeat {
		return err
	}
	next := a.clone()
	if err = a.plan(next, req, ""); err != nil {
		return err
	}
	next.Operations[req.Operation] = op
	if err = a.commit(next); err != nil {
		return err
	}
	for _, b := range req.Attachments {
		if a.runtime[b.Attachment] == nil {
			a.runtime[b.Attachment] = newRuntime()
		}
	}
	return nil
}
func (a *Authority) RegisterAttachment(p *ControllerPrincipal, req RegisterRequest) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.control(p); err != nil {
		return err
	}
	op, repeat, err := a.operation(req.Operation, "register", req)
	if err != nil {
		return err
	}
	b := req.Binding
	if !bindingValid(b, a.s) {
		return ErrInvalid
	}
	if _, ok := a.s.Volumes[b.Volume]; !ok {
		return ErrUnknown
	}
	if a.s.VolumeLifecycles[b.Volume].Phase != VolumeReady {
		return ErrBlocked
	}
	old, exists := a.s.Attachments[b.Attachment]
	if exists && old.Binding != b {
		return ErrConflict
	}
	if exists && old.Phase != Reserved && old.Phase != Active {
		return ErrBlocked
	}
	if repeat {
		return nil
	}
	if !exists && (b.Role == PrepareRole || a.keyUsed(b.Key)) {
		return ErrConflict
	}
	if !exists && len(a.s.Attachments) >= a.limits.Attachments {
		return ErrLimit
	}
	if b.Role == RuntimeRole && reservedVolume(a.s, b.Volume, "") {
		return ErrBlocked
	}
	if b.Role == PrepareRole {
		prep, ok := a.s.Prepares[b.Prepare]
		if !ok || prep.Phase != Pending {
			return ErrBlocked
		}
	}
	next := a.clone()
	next.Attachments[b.Attachment] = Attachment{Binding: b, Phase: Active}
	next.Operations[req.Operation] = op
	if err = a.commit(next); err != nil {
		return err
	}
	if !exists {
		a.runtime[b.Attachment] = newRuntime()
	}
	return nil
}

// Guard counts a request, not a connection. Release only after EVERY request-owned
// resource and callback is finished. It is safe to Release repeatedly; copying a
// Guard value does not duplicate its one-shot ownership token.
type Guard struct{ token *guardToken }
type guardToken struct {
	once          sync.Once
	owner         *Authority
	epoch         ID
	binding       Binding
	publishedCopy ID     // real ProvisionCopyTransaction completed both parent syncs
	boundSequence uint64 // successful provision obligation discharged under owner.mu
	released      bool   // Protected by owner.mu; shared by every copy of a Guard.
}

func (g *Guard) Release() {
	if g == nil || g.token == nil {
		return
	}
	t := g.token
	t.once.Do(func() {
		a := t.owner
		a.mu.Lock()
		defer a.mu.Unlock()
		t.released = true
		if (a.dataIO != nil && a.dataIO.guard == t) || (a.copyIO != nil && a.copyIO.guard == t) {
			_ = a.poison(ErrRepairRequired) // never clear an abandoned obligation
		}
		rt := a.runtime[t.binding.Attachment]
		rt.count--
		a.inflight--
		if rt.count == 0 {
			close(rt.zero)
		}
	})
}

// Admit must precede external queues and filesystem/handle access. Every operand
// must name the principal's exact V; mutates includes metadata/namespace writes.
func (a *Authority) Admit(p *DataPrincipal, volume ID, mutates bool) (*Guard, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.available(); err != nil {
		return nil, err
	}
	if p == nil || p.owner != a || p.epoch != a.s.Epoch || p.binding.Volume != volume {
		return nil, ErrUnauthorized
	}
	rec, ok := a.s.Attachments[p.binding.Attachment]
	if !ok || rec.Binding != p.binding {
		return nil, ErrUnauthorized
	}
	if rec.Phase != Active || a.s.VolumeLifecycles[volume].Phase != VolumeReady {
		return nil, ErrBlocked
	}
	if mutates && rec.Binding.Mode != ReadWrite {
		return nil, ErrReadOnly
	}
	if a.inflight >= a.limits.InFlight {
		return nil, ErrLimit
	}
	rt := a.runtime[p.binding.Attachment]
	if rt.count == 0 {
		rt.zero = make(chan struct{})
	}
	rt.count++
	a.inflight++
	return &Guard{&guardToken{owner: a, epoch: p.epoch, binding: p.binding}}, nil
}
func (a *Authority) Retire(ctx context.Context, p *ControllerPrincipal, req RetireRequest) (Receipt, error) {
	// No locks needed by accepted requests are held while waiting for completion.
	a.mu.Lock()
	if err := a.control(p); err != nil {
		a.mu.Unlock()
		return Receipt{}, err
	}
	op, repeat, err := a.operation(req.Operation, "retire", req)
	if err != nil {
		a.mu.Unlock()
		return Receipt{}, err
	}
	rec, ok := a.s.Attachments[req.Attachment]
	if !ok {
		a.mu.Unlock()
		return Receipt{}, ErrUnknown
	}
	if req.Store != a.s.Store.ID || req.Volume != rec.Binding.Volume {
		a.mu.Unlock()
		return Receipt{}, ErrConflict
	}
	// Generation-fenced retirement: the caller must prove the exact shim launch
	// recorded in the attachment binding. This check precedes replay handling and
	// fencing in every phase; a wrong or malformed launch changes no state.
	if !validID(req.Launch) {
		a.mu.Unlock()
		return Receipt{}, ErrInvalid
	}
	if req.Launch != rec.Binding.Launch {
		a.mu.Unlock()
		return Receipt{}, ErrConflict
	}
	if !repeat || rec.Phase == Active || rec.Phase == Reserved {
		// A new operation ID may exhaust capacity even though this exact A was
		// already durably fenced. Rejecting that redundant request before IO must
		// not poison the existing retirement or immutable receipt.
		alreadyFenced := rec.Phase == Drained || (rec.Phase == Retiring && rec.Retirement != "")
		next := a.clone()
		next.Operations[req.Operation] = op
		// Fence memory BEFORE attempting IO, even if intent persistence fails.
		if rec.Phase != Drained {
			if rec.Retirement == "" {
				rec.Retirement = req.Operation
			}
			rec.Phase = Retiring
			next.Attachments[req.Attachment] = rec
			a.s.Attachments[req.Attachment] = rec
			a.compatibilityRetirementLocked(rec, req.Operation)
			a.wakeCopyFence(rec.Binding.Volume)
		}
		if err = a.prepareRetireIO("retire-intent-persist", rec, func() error { return a.commit(next) }); err != nil {
			// commit leaves fault nil only for a clean pre-IO capacity rejection.
			// Already-fenced retries made no new admission transition and remain
			// safely retryable with their original operation ID.
			if !(alreadyFenced && a.fault == nil && errors.Is(err, ErrLimit)) {
				err = a.retirementFailure(err)
			}
			a.mu.Unlock()
			return Receipt{}, err
		}
	}
	a.compatibilityRetirementLocked(rec, req.Operation)
	if rec.Phase == Drained {
		r := *rec.Receipt
		a.mu.Unlock()
		return r, nil
	}
	rt := a.runtime[req.Attachment]
	if rt.done == nil {
		rt.done = make(chan struct{})
		a.drains++
		go a.finishRetire(req.Attachment, rt)
	}
	done := rt.done
	a.mu.Unlock()
	select {
	case <-ctx.Done():
		return Receipt{}, ctx.Err()
	case <-done:
		a.mu.Lock()
		defer a.mu.Unlock()
		if rt.err != nil {
			return Receipt{}, rt.err
		}
		if err = a.available(); err != nil {
			return Receipt{}, err
		}
		return *a.s.Attachments[req.Attachment].Receipt, nil
	}
}

// A first retirement, its receipt, and PREPARE completion have reserved capacity
// under immutable configured limits. A clean pre-IO failure signals a breach, not
// EIO or ENOSPC. Keep the memory fence and quarantine conservatively in that case;
// neither an invariant breach nor a real IO failure can manufacture drain proof.
func (a *Authority) retirementFailure(err error) error {
	if a.fault == nil && errors.Is(err, ErrLimit) {
		err = fmt.Errorf("%w: %w", ErrCapacityInvariant, err)
	}
	return a.poison(err)
}
func (a *Authority) finishRetire(id ID, rt *runtimeAttachment) {
	a.mu.Lock()
	zero := rt.zero
	a.mu.Unlock()
	<-zero
	a.barrierMu.Lock()
	defer a.barrierMu.Unlock()
	a.mu.Lock()
	finish := func(err error) { rt.err = err; a.drains--; close(rt.done); a.mu.Unlock() }
	if err := a.available(); err != nil {
		finish(err)
		return
	}
	rec := a.s.Attachments[id]
	root := a.roots[rec.Binding.Volume]
	// Registry inspection takes its namespace gate before publication reacquires
	// authority.mu. Never call it while holding authority.mu (DATA lock order).
	a.mu.Unlock()
	proved, proofErr := a.tryPrepareRetirementProof(rec, root)
	a.mu.Lock()
	if proofErr != nil {
		finish(a.poison(proofErr))
		return
	}
	if err := a.available(); err != nil {
		finish(err)
		return
	}
	if !proved {
		if err := a.prepareRetireIO("retire-barrier-persist", rec, func() error { return a.j.markNamed(barrierName) }); err != nil {
			finish(a.poison(err))
			return
		}
	}
	barrier := a.barrier
	a.mu.Unlock()
	err := callBarrier(barrier, rec.Binding, root)
	a.mu.Lock()
	// An unrelated control write may have failed while the barrier was running.
	// Never erase that sticky evidence with a subsequently successful receipt.
	if blocked := a.available(); blocked != nil {
		finish(blocked)
		return
	}
	if err != nil {
		finish(a.poison(err))
		return
	}
	next := a.clone()
	receipt := Receipt{SchemaVersion, a.s.Store.ID, rec.Binding.Volume, id, rec.Binding.Launch, rec.Binding.Prepare, a.s.Revision + 1}
	rec.Phase = Drained
	rec.Receipt = &receipt
	next.Attachments[id] = rec
	// Only the complete retained-resource barrier (including sticky/close
	// failures), not a syncfs substep, can authorize this durable certificate.
	if err = a.certifyRetirement(next, rec); err != nil {
		finish(a.retirementFailure(err))
		return
	}
	if err = a.prepareRetireIO("retire-receipt-persist", rec, func() error { return a.commit(next) }); err != nil {
		finish(a.retirementFailure(err))
		return
	}
	if err = a.prepareRetireIO("retire-barrier-clear-persist", rec, a.j.clearBarrier); err != nil {
		finish(a.poison(err))
		return
	}
	a.compatibilityDrainedLocked(rec, receipt)
	finish(nil)
}
func callBarrier(barrier Barrier, binding Binding, root *os.File) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("barrier panic: %v", p)
		}
	}()
	return barrier(binding, root)
}
func canonicalReceipts(receipts []Receipt) []Receipt {
	r := append([]Receipt(nil), receipts...)
	sort.Slice(r, func(i, j int) bool { return r[i].Attachment < r[j].Attachment })
	return r
}
func (a *Authority) receipts(id ID, receipts []Receipt) (Prepare, error) {
	prep, ok := a.s.Prepares[id]
	if !ok {
		return Prepare{}, ErrUnknown
	}
	if prep.Phase != Pending {
		return Prepare{}, ErrConflict
	}
	if len(receipts) != len(prep.Attachments) {
		return Prepare{}, ErrBlocked
	}
	got := map[ID]bool{}
	for _, r := range receipts {
		rec, ok := a.s.Attachments[r.Attachment]
		if !ok || rec.Binding.Prepare != id || rec.Phase != Drained || rec.Receipt == nil || *rec.Receipt != r || got[r.Attachment] {
			return Prepare{}, ErrBlocked
		}
		got[r.Attachment] = true
	}
	for _, b := range prep.Attachments {
		if !got[b.Attachment] {
			return Prepare{}, ErrBlocked
		}
	}
	return prep, nil
}
func (a *Authority) CompletePrepare(p *ControllerPrincipal, req CompleteRequest) error {
	req.Receipts = canonicalReceipts(req.Receipts)
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.control(p); err != nil {
		return err
	}
	op, repeat, err := a.operation(req.Operation, "complete", req)
	if err != nil || repeat {
		return err
	}
	prep, err := a.receipts(req.Prepare, req.Receipts)
	if err != nil {
		return err
	}
	for _, b := range prep.Attachments {
		if intent, ok := a.s.Copy.Intents[b.Volume]; ok && (intent.Phase != CopyCompleted || a.copyReplayPending(b.Volume)) {
			return ErrBlocked
		}
	}
	if req.Attestation.Prepare != req.Prepare || !req.Attestation.Succeeded || !req.Attestation.CleanCopyUp {
		return ErrInvalid
	}
	next := a.clone()
	prep.Phase = Completed
	prep.Attestation = &req.Attestation
	next.Prepares[req.Prepare] = prep
	next.Operations[req.Operation] = op
	if err = a.commit(next); err != nil {
		return a.retirementFailure(err)
	}
	return nil
}
func (a *Authority) ReplacePrepare(p *ControllerPrincipal, req ReplaceRequest) error {
	req.Receipts = canonicalReceipts(req.Receipts)
	req.Successor = canonicalReserve(req.Successor)
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.control(p); err != nil {
		return err
	}
	op, repeat, err := a.operation(req.Operation, "replace", req)
	if err != nil || repeat {
		return err
	}
	prep, err := a.receipts(req.Prepare, req.Receipts)
	if err != nil {
		return err
	}
	if req.Successor.Prepare == req.Prepare || req.Successor.Operation == req.Operation {
		return ErrConflict
	}
	if _, exists := a.s.Prepares[req.Successor.Prepare]; exists {
		return ErrConflict
	}
	sop, exists, err := a.operation(req.Successor.Operation, "reserve", req.Successor)
	if err != nil {
		return err
	}
	if exists {
		return ErrConflict
	}
	if len(a.s.Operations)+2 > a.limits.Operations {
		return ErrLimit
	}
	// Successor must own exactly the predecessor's all-volume set, never a subset.
	if len(prep.Attachments) != len(req.Successor.Attachments) {
		return ErrConflict
	}
	for i, b := range prep.Attachments {
		if b.Volume != req.Successor.Attachments[i].Volume {
			return ErrConflict
		}
	}
	next := a.clone()
	if err = a.plan(next, req.Successor, req.Prepare); err != nil {
		return err
	}
	for _, b := range req.Successor.Attachments {
		if intent, ok := next.Copy.Intents[b.Volume]; ok && (intent.Phase != CopyCompleted || a.copyReplayPending(b.Volume)) {
			if intent.Owner.Prepare != req.Prepare || b.Mode != ReadWrite {
				return ErrBlocked
			}
			intent.Owner, intent.Epoch = b, a.s.Epoch
			next.Copy.Intents[b.Volume] = intent
		}
	}
	prep.Phase = Replaced
	prep.Successor = req.Successor.Prepare
	next.Prepares[req.Prepare] = prep
	next.Operations[req.Operation] = op
	next.Operations[req.Successor.Operation] = sop
	if err = a.commit(next); err != nil {
		return err
	}
	for _, b := range req.Successor.Attachments {
		a.runtime[b.Attachment] = newRuntime()
		a.wakeCopyFence(b.Volume)
	}
	return nil
}

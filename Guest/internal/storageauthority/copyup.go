package storageauthority

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// These DTOs are independent of the wire package. Handles are ext4's supported
// FILEID_INO32_GEN, not FUSE node IDs, and exclude request/attachment generations.
type Ext4ObjectV1 struct {
	Inode      uint64
	Generation uint32
	FileType   uint32
	HandleType uint32
	HandleSize uint32
	Handle     [8]byte
}

type CopyRootV1 struct {
	Store       ID
	Volume      ID
	BackingUUID [16]byte
	Root        Ext4ObjectV1
}

// CopyCleanupV1 is fixed-size, comparable recovery evidence, never a deletion
// instruction. Manifest/Staging are freshly observed objects supplied by the
// trusted server before cleanup. Initial uses only the metadata fields.
type CopyCleanupV1 struct {
	UID, GID, Mode             uint32
	ATimeSeconds, MTimeSeconds int64
	ATimeNanos, MTimeNanos     uint32
	Manifest, Staging          Ext4ObjectV1
}

type CopyIntent struct {
	ID              ID
	Owner           Binding
	Epoch           ID
	Root            CopyRootV1
	Transaction     Ext4ObjectV1
	ManifestDigest  [32]byte
	ManifestSize    uint64
	Phase           string
	Initial         CopyCleanupV1
	Cleanup         CopyCleanupV1
	InitialCaptured bool
}

const (
	CopyBegun            = "BEGUN"
	CopyBound            = "BOUND"
	CopySealed           = "SEALED"
	CopyCleaning         = "CLEANING"
	CopyCompleted        = "COMPLETED"
	MaxCopyManifestBytes = 64 << 20
	copySchemaVersion    = 2
)

type copyState struct {
	Version int               `json:"version"`
	Intents map[ID]CopyIntent `json:"intents"`
}

func validCopyObject(o Ext4ObjectV1) bool {
	if o.Inode == 0 || o.Inode > uint64(^uint32(0)) || o.HandleType != 1 || o.HandleSize != 8 || uint64(binary.LittleEndian.Uint32(o.Handle[:4])) != o.Inode || binary.LittleEndian.Uint32(o.Handle[4:]) != o.Generation {
		return false
	}
	switch o.FileType {
	case 0010000, 0020000, 0040000, 0060000, 0100000, 0120000, 0140000:
		return true
	}
	return false
}

func validCopyDirectory(o Ext4ObjectV1) bool { return validCopyObject(o) && o.FileType == 0040000 }

func (a *Authority) validCopyRoot(root CopyRootV1, b Binding) bool {
	v, ok := a.s.Volumes[b.Volume]
	return ok && root.Store == b.Store && root.Volume == b.Volume && root.BackingUUID != ([16]byte{}) && validCopyDirectory(root.Root) && root.Root.Inode == v.Root.Inode
}

// copyGuardLocked validates the request token, not just its attachment. Ordinary
// already-admitted DATA may finish during retirement; private controls may not.
func (g *Guard) copyGuardLocked(control bool) (*Authority, error) {
	t := g.token
	a := t.owner
	if t.released {
		return nil, ErrClosed
	}
	if err := a.available(); err != nil {
		return nil, err
	}
	rec, ok := a.s.Attachments[t.binding.Attachment]
	rt := a.runtime[t.binding.Attachment]
	if t.epoch != a.s.Epoch || t.binding.Store != a.s.Store.ID || !ok || rec.Binding != t.binding || rt == nil || rt.count <= 0 || a.s.VolumeLifecycles[t.binding.Volume].Phase != VolumeReady {
		return nil, ErrUnauthorized
	}
	if rec.Phase != Active && rec.Phase != Retiring {
		return nil, ErrUnauthorized
	}
	if control && (rec.Phase != Active || t.binding.Role != PrepareRole || t.binding.Mode != ReadWrite || a.s.Prepares[t.binding.Prepare].Phase != Pending) {
		return nil, ErrUnauthorized
	}
	return a, nil
}

func (g *Guard) copyAuthority() (*Authority, error) {
	if g == nil || g.token == nil || g.token.owner == nil {
		return nil, ErrUnauthorized
	}
	return g.token.owner, nil
}

// CopyDeviceID exposes only the independently configured backing identity, for
// the trusted server to compare with the UUID read from the real root descriptor.
func (g *Guard) CopyDeviceID() (string, error) {
	a, err := g.copyAuthority()
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err = g.copyGuardLocked(true); err != nil {
		return "", err
	}
	return a.s.Store.DeviceID, nil
}

// CopyDataDeviceID supplies the immutable backing identity for admitted DATA,
// including a retiring owner. Private controls retain CopyDeviceID's stricter
// active-only contract; a pending recovery replay must use those controls.
func (g *Guard) CopyDataDeviceID() (string, error) {
	a, err := g.copyAuthority()
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err = g.copyDataIntentLocked(); err != nil {
		return "", err
	}
	return a.s.Store.DeviceID, nil
}

// BeginCopy must run under the service namespace gate, before any copy-up DATA.
// The trusted caller supplies identity obtained from the authority-derived root
// descriptor, including an independently checked backing UUID. The durable record
// is private and never exposed by Query. Repeating Begin only resumes exact scope.
func (g *Guard) BeginCopy(root CopyRootV1) (CopyIntent, error) {
	a, err := g.copyAuthority()
	if err != nil {
		return CopyIntent{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err = g.copyGuardLocked(true); err != nil {
		return CopyIntent{}, err
	}
	if !a.validCopyRoot(root, g.token.binding) {
		return CopyIntent{}, ErrInvalid
	}
	old, exists := a.s.Copy.Intents[root.Volume]
	if exists && (old.Phase != CopyCompleted || a.copyReplayPending(root.Volume)) {
		if old.Owner != g.token.binding || old.Epoch != g.token.epoch {
			return CopyIntent{}, ErrBlocked
		}
		if old.Root != root {
			return CopyIntent{}, ErrConflict
		}
		return old, nil
	}
	id, err := NewID()
	if err != nil {
		return CopyIntent{}, err
	}
	intent := CopyIntent{ID: id, Owner: g.token.binding, Epoch: g.token.epoch, Root: root, Phase: CopyBegun}
	next := a.clone()
	next.Copy.Intents[root.Volume] = intent
	if exists && old.Phase == CopyCompleted {
		delete(next.CopyReplay, root.Volume)
	}
	if err = a.commit(next); err != nil {
		return CopyIntent{}, err
	}
	a.wakeCopyFence(root.Volume)
	return intent, nil
}

func (g *Guard) ownedCopyLocked(id ID) (CopyIntent, error) {
	a, err := g.copyGuardLocked(true)
	if err != nil {
		return CopyIntent{}, err
	}
	intent, ok := a.s.Copy.Intents[g.token.binding.Volume]
	if !validID(id) || !ok || intent.ID != id || (intent.Phase == CopyCompleted && !a.completedCopyTailPending(g.token.binding.Volume)) || intent.Owner != g.token.binding || intent.Epoch != g.token.epoch {
		return CopyIntent{}, ErrUnauthorized
	}
	return intent, nil
}

// CopyDataIntent classifies an already-admitted DATA request without creating
// authority. Unlike private controls, an admitted retiring owner may finish.
func (g *Guard) CopyDataIntent(root CopyRootV1) (CopyIntent, error) {
	a, err := g.copyAuthority()
	if err != nil {
		return CopyIntent{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	intent, err := g.copyDataIntentLocked()
	if err != nil {
		return CopyIntent{}, err
	}
	if intent.Root != root || !a.validCopyRoot(root, g.token.binding) {
		return CopyIntent{}, ErrConflict
	}
	return intent, nil
}

func (g *Guard) copyDataIntentLocked() (CopyIntent, error) {
	a, err := g.copyGuardLocked(false)
	if err != nil {
		return CopyIntent{}, err
	}
	b := g.token.binding
	intent, exists := a.s.Copy.Intents[b.Volume]
	if b.Role != PrepareRole || b.Mode != ReadWrite || a.s.Prepares[b.Prepare].Phase != Pending || !exists || intent.Owner != b || intent.Epoch != g.token.epoch {
		return CopyIntent{}, ErrUnauthorized
	}
	if a.copyReplayPending(b.Volume) {
		return CopyIntent{}, ErrBlocked
	}
	if !a.validCopyRoot(intent.Root, b) {
		return CopyIntent{}, ErrConflict
	}
	return intent, nil
}

// InspectCopy authenticates the exact live intent and freshly observed physical
// root without creating or changing authority. Every non-Begin sideband action,
// including IdentityAt, calls this before accessing a path or acknowledging work.
func (g *Guard) InspectCopy(id ID, root CopyRootV1) (CopyIntent, error) {
	a, err := g.copyAuthority()
	if err != nil {
		return CopyIntent{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	intent, err := g.ownedCopyLocked(id)
	if err != nil {
		return CopyIntent{}, err
	}
	if intent.Root != root {
		return CopyIntent{}, ErrConflict
	}
	return intent, nil
}

// BindCopyTransaction durably owns the exact transaction directory before any
// pre-manifest cleanup can be authorized. A different object is never adopted.
func (g *Guard) BindCopyTransaction(id ID, transaction Ext4ObjectV1) error {
	a, err := g.copyAuthority()
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	intent, err := g.ownedCopyLocked(id)
	if err != nil {
		return err
	}
	// Once provisioning captured Initial, only its private-directory path may
	// perform the first bind. A direct bind cannot invent private provenance.
	if intent.Phase == CopyBegun && intent.InitialCaptured {
		return ErrConflict
	}
	return a.bindCopyTransactionLocked(intent, transaction)
}

func (a *Authority) bindCopyTransactionLocked(intent CopyIntent, transaction Ext4ObjectV1) error {
	if !validCopyDirectory(transaction) || transaction == intent.Root.Root || transaction.Inode == intent.Root.Root.Inode {
		return ErrInvalid
	}
	if intent.Phase != CopyBegun {
		if intent.Transaction != transaction {
			return ErrConflict
		}
		return nil
	}
	intent.Transaction, intent.Phase = transaction, CopyBound
	next := a.clone()
	next.Copy.Intents[intent.Root.Volume] = intent
	return a.commit(next)
}

func copyManifestDigest(manifest []byte) ([32]byte, error) {
	if len(manifest) == 0 || len(manifest) > MaxCopyManifestBytes {
		return [32]byte{}, ErrInvalid
	}
	return sha256.Sum256(manifest), nil
}

// SealCopyManifest durably seals exact bounded bytes before their publication.
// A second seal must be byte-identical by digest and size; no mutable resealing.
func (g *Guard) SealCopyManifest(id ID, transaction Ext4ObjectV1, manifest []byte) error {
	digest, err := copyManifestDigest(manifest)
	if err != nil {
		return err
	}
	return g.SealCopyManifestDigest(id, transaction, digest, uint64(len(manifest)))
}

// SealCopyManifestDigest stores only a bounded digest/size. The trusted server
// computes these from the pinned, synchronized manifest before publication.
func (g *Guard) SealCopyManifestDigest(id ID, transaction Ext4ObjectV1, digest [32]byte, size uint64) error {
	a, err := g.copyAuthority()
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	intent, err := g.ownedCopyLocked(id)
	if err != nil {
		return err
	}
	if size == 0 || size > MaxCopyManifestBytes || digest == ([32]byte{}) {
		return ErrInvalid
	}
	if intent.Transaction != transaction || (intent.Phase != CopyBound && intent.Phase != CopySealed) {
		return ErrConflict
	}
	if intent.Phase == CopySealed {
		if intent.ManifestDigest != digest || intent.ManifestSize != size {
			return ErrConflict
		}
		return nil
	}
	intent.ManifestDigest, intent.ManifestSize, intent.Phase = digest, size, CopySealed
	next := a.clone()
	next.Copy.Intents[intent.Root.Volume] = intent
	return g.commitPrepareCopyIO("seal-persist", next)
}

// AuthenticateCopyManifest authenticates bytes, not deletion instructions. nil
// remains an exclusively BOUND prepublication proof; empty nonnil is invalid.
func (g *Guard) AuthenticateCopyManifest(id ID, transaction Ext4ObjectV1, manifest []byte) (CopyIntent, error) {
	if manifest == nil {
		return g.AuthenticateCopyManifestDigest(id, transaction, [32]byte{}, 0)
	}
	digest, err := copyManifestDigest(manifest)
	if err != nil {
		return CopyIntent{}, err
	}
	return g.AuthenticateCopyManifestDigest(id, transaction, digest, uint64(len(manifest)))
}

// A zero digest and size encode the nil proof, ONLY in BOUND. CLEANING permits
// exact authentication of an already sealed digest, never a new seal or nil proof.
func (g *Guard) AuthenticateCopyManifestDigest(id ID, transaction Ext4ObjectV1, digest [32]byte, size uint64) (CopyIntent, error) {
	a, err := g.copyAuthority()
	if err != nil {
		return CopyIntent{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	intent, err := g.ownedCopyLocked(id)
	if err != nil {
		return CopyIntent{}, err
	}
	if intent.Transaction != transaction || !validCopyDirectory(transaction) {
		return CopyIntent{}, ErrConflict
	}
	if intent.Phase == CopyBound && size == 0 && digest == ([32]byte{}) {
		return intent, nil
	}
	if size == 0 || size > MaxCopyManifestBytes || digest == ([32]byte{}) {
		return CopyIntent{}, ErrInvalid
	}
	if (intent.Phase != CopySealed && intent.Phase != CopyCleaning) || intent.ManifestDigest != digest || intent.ManifestSize != size {
		return CopyIntent{}, ErrConflict
	}
	return intent, nil
}

func validCopyMetadata(c CopyCleanupV1) bool {
	return c.Mode <= 07777 && c.ATimeNanos < 1e9 && c.MTimeNanos < 1e9
}

func validCopyCleanup(intent CopyIntent, c CopyCleanupV1) bool {
	if !validCopyMetadata(c) {
		return false
	}
	seen := map[uint64]bool{intent.Root.Root.Inode: true, intent.Transaction.Inode: true}
	for _, entry := range []struct {
		object   Ext4ObjectV1
		fileType uint32
	}{{c.Manifest, 0100000}, {c.Staging, 0040000}} {
		if entry.object == (Ext4ObjectV1{}) {
			continue
		}
		if !validCopyObject(entry.object) || entry.object.FileType != entry.fileType || seen[entry.object.Inode] {
			return false
		}
		seen[entry.object.Inode] = true
	}
	return intent.ManifestSize == 0 || c.Manifest != (Ext4ObjectV1{})
}

// StartCopyCleanup persists exact metadata and the remaining manifest/staging
// identities BEFORE deleting cleanup evidence or the transaction. It is a trusted
// server assertion that publication/rollback work has joined and identities were
// preflighted under the namespace gate. BOUND needs no digest: unsealed manifest
// bytes are not interpreted. Replays must match exactly; InspectCopy reads state.
func (g *Guard) StartCopyCleanup(id ID, transaction Ext4ObjectV1, cleanup CopyCleanupV1) (CopyIntent, error) {
	a, err := g.copyAuthority()
	if err != nil {
		return CopyIntent{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	intent, err := g.ownedCopyLocked(id)
	if err != nil {
		return CopyIntent{}, err
	}
	if intent.Transaction != transaction || !validCopyDirectory(transaction) {
		return CopyIntent{}, ErrConflict
	}
	if intent.Phase != CopyBound && intent.Phase != CopySealed && intent.Phase != CopyCleaning {
		return CopyIntent{}, ErrConflict
	}
	if a.copyReplayPending(intent.Root.Volume) && copyDataAction(a.s.CopyReplay[intent.Root.Volume].Action) {
		if a.copyIO == nil || a.copyIO.guard != g.token || a.copyIO.record.Action != CopyOperationRollback || a.copyIO.record.Intent != id {
			return CopyIntent{}, ErrBlocked
		}
	}
	if !validCopyCleanup(intent, cleanup) {
		return CopyIntent{}, ErrInvalid
	}
	if intent.Phase == CopyCleaning {
		if intent.Cleanup != cleanup {
			return CopyIntent{}, ErrConflict
		}
		return intent, nil
	}
	intent.Cleanup, intent.Phase = cleanup, CopyCleaning
	next := a.clone()
	next.Copy.Intents[intent.Root.Volume] = intent
	if err = g.commitPrepareCopyIO("cleaning-persist", next); err != nil {
		return CopyIntent{}, err
	}
	return intent, nil
}

// FinishCopy is a trusted-server assertion: all transaction work is joined,
// cleanup was identity-verified, and the root/transaction cleanup was synchronized.
// It also permits the fenced no-op (BEGUN) path. Retirement is never completion.
// Privately provisioned transactions must enter CLEANING first. Legacy direct
// Bind callers retain their trusted-server completion assertion contract.
// Completed IDs fail closed, including a retried completion after a lost reply.
func (g *Guard) FinishCopy(id ID) error {
	a, err := g.copyAuthority()
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	intent, err := g.ownedCopyLocked(id)
	if err != nil {
		return err
	}
	if intent.Phase == CopyCompleted {
		return ErrUnauthorized
	}
	if a.copyReplayPending(intent.Root.Volume) && copyDataAction(a.s.CopyReplay[intent.Root.Volume].Action) {
		return ErrBlocked // neither whole-intent rollback nor directory tail may finish
	}
	if intent.InitialCaptured && intent.Phase != CopyCleaning {
		return ErrConflict
	}
	intent.Phase = CopyCompleted
	next := a.clone()
	next.Copy.Intents[intent.Root.Volume] = intent
	if err = g.commitPrepareCopyIO("finish-persist", next); err != nil {
		return err
	}
	a.wakeCopyFence(intent.Root.Volume)
	return nil
}

// CopyFence is checked under the namespace gate for EVERY dispatch (reads too).
// Wait outside that gate, then retry the check. A nonnil channel is a notification,
// never permission: completion, ownership transfer, retirement, and closure wake
// it. Retiring nonowners must abort blocked work so retirement can drain it.
func (g *Guard) CopyFence() (<-chan struct{}, error) {
	a, err := g.copyAuthority()
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err = g.copyGuardLocked(false); err != nil {
		return nil, err
	}
	intent, ok := a.s.Copy.Intents[g.token.binding.Volume]
	if !ok || (intent.Phase == CopyCompleted && !a.copyReplayPending(g.token.binding.Volume)) || (intent.Owner == g.token.binding && intent.Epoch == g.token.epoch) {
		return nil, nil
	}
	if a.s.Attachments[g.token.binding.Attachment].Phase == Retiring {
		return nil, ErrUnauthorized
	}
	ch := a.copyFences[g.token.binding.Volume]
	if ch == nil {
		return nil, ErrBlocked // a missing notification must never erase a durable fence
	}
	return ch, nil
}

// Wakeups never erase the durable intent. All callers hold mu. Fresh channels are
// installed after reopen; a closed predecessor channel cannot authorize new DATA.
func (a *Authority) wakeCopyFence(volume ID) {
	if ch := a.copyFences[volume]; ch != nil {
		close(ch)
		delete(a.copyFences, volume)
	}
	if a.closed || a.fault != nil || a.s.Copy == nil {
		return
	}
	if intent, ok := a.s.Copy.Intents[volume]; ok && (intent.Phase != CopyCompleted || a.copyReplayPending(volume)) {
		a.copyFences[volume] = make(chan struct{})
	}
}

func (a *Authority) wakeAllCopyFences() {
	for volume := range a.copyFences {
		a.wakeCopyFence(volume)
	}
}

func (a *Authority) validateCopyState() error {
	s := a.s
	fail := func() error { return fmt.Errorf("%w: private copy state", ErrInvalid) }
	if s.Copy == nil || s.Copy.Version != copySchemaVersion || s.Copy.Intents == nil || len(s.Copy.Intents) > len(s.Volumes) {
		return fail()
	}
	if err := a.validateCopyReplays(); err != nil {
		return fail()
	}
	ids := map[ID]bool{}
	for volume, intent := range s.Copy.Intents {
		if !validID(intent.ID) || ids[intent.ID] || !validID(intent.Epoch) || volume != intent.Root.Volume || !a.validCopyRoot(intent.Root, intent.Owner) || intent.Owner.Role != PrepareRole || intent.Owner.Mode != ReadWrite {
			return fail()
		}
		ids[intent.ID] = true
		rec, ok := s.Attachments[intent.Owner.Attachment]
		if !ok || rec.Binding != intent.Owner {
			return fail()
		}
		if (intent.Phase != CopyCompleted || a.copyReplayPending(volume)) && (s.Prepares[intent.Owner.Prepare].Phase != Pending || s.VolumeLifecycles[volume].Phase != VolumeReady) {
			return fail()
		}
		if !validCopyMetadata(intent.Initial) || intent.Initial.Manifest != (Ext4ObjectV1{}) || intent.Initial.Staging != (Ext4ObjectV1{}) || (!intent.InitialCaptured && intent.Initial != (CopyCleanupV1{})) {
			return fail()
		}
		if intent.Phase != CopyCleaning && intent.Phase != CopyCompleted && intent.Cleanup != (CopyCleanupV1{}) {
			return fail()
		}
		bound := intent.Transaction != (Ext4ObjectV1{})
		sealed := intent.ManifestSize != 0
		if bound && (!validCopyDirectory(intent.Transaction) || intent.Transaction.Inode == intent.Root.Root.Inode) {
			return fail()
		}
		if sealed && (!bound || intent.ManifestSize > MaxCopyManifestBytes || intent.ManifestDigest == ([32]byte{})) {
			return fail()
		}
		if !sealed && intent.ManifestDigest != ([32]byte{}) {
			return fail()
		}
		switch intent.Phase {
		case CopyBegun:
			if bound || sealed {
				return fail()
			}
		case CopyBound:
			if !bound || sealed {
				return fail()
			}
		case CopySealed:
			if !bound || !sealed {
				return fail()
			}
		case CopyCleaning:
			if !bound || !validCopyCleanup(intent, intent.Cleanup) {
				return fail()
			}
		case CopyCompleted:
			if intent.InitialCaptured && (!bound || !validCopyCleanup(intent, intent.Cleanup)) {
				return fail()
			}
			if intent.Cleanup != (CopyCleanupV1{}) && (!bound || !validCopyCleanup(intent, intent.Cleanup)) {
				return fail()
			}
		default:
			return fail()
		}
	}
	return nil
}

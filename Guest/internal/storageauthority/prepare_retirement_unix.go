//go:build linux || darwin

package storageauthority

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

const prepareRetirementProofVersion = 2
const prepareRetirementProofKind = "prepare-root-only-retry"

// This is NOT a completion certificate. It authorizes only discarding this
// marker while retaining the exact RETIRING/PENDING predecessor without a receipt.
// No Next digest, receipt revision, or barrier-success claim belongs here.
type prepareRetirementProof struct {
	Version    int         `json:"version"`
	Kind       string      `json:"kind"`
	Attempt    ID          `json:"attempt"`
	Store      Store       `json:"store"`
	Epoch      ID          `json:"epoch"`
	Controller Controller  `json:"controller"`
	Bootstrap  Fingerprint `json:"bootstrap"`
	Volume     Volume      `json:"volume"`
	Binding    Binding     `json:"binding"`
	Operation  ID          `json:"operation"`
	Revision   uint64      `json:"revision"`
	Prior      string      `json:"prior_digest"`
}

// Caller holds barrierMu, NOT authority.mu. The trusted registry callback must
// inspect retained ownership while holding its namespace gate through publish.
func (a *Authority) tryPrepareRetirementProof(rec Attachment, root *os.File) (bool, error) {
	a.mu.Lock()
	callback := a.prepareRetirementProof
	a.mu.Unlock()
	if callback == nil {
		return false, nil
	}
	var active, publishing atomic.Bool
	active.Store(true)
	used, published := false, false // protected by authority.mu
	publish := func() (bool, error) {
		a.mu.Lock()
		defer a.mu.Unlock()
		if !active.Load() {
			return false, ErrInvalid // escaped closure must never mutate authority
		}
		if used {
			return false, a.poison(ErrInvalid)
		}
		used = true
		publishing.Store(true)
		defer publishing.Store(false)
		if err := a.available(); err != nil {
			return false, err
		}
		ok, err := a.publishPrepareRetirement(rec, root)
		if err != nil {
			return false, a.poison(err)
		}
		if !active.Load() {
			// An asynchronous invocation that crossed callback return cannot
			// certify gate ownership. Retain/poison any partial publication.
			return false, a.poison(ErrInvalid)
		}
		published = ok
		return ok, nil
	}
	claimed, err := func() (ok bool, err error) {
		defer func() {
			active.Store(false)
			if publishing.Load() {
				err = ErrInvalid // callback must join publication before returning
			}
			if p := recover(); p != nil {
				err = fmt.Errorf("prepare retirement proof panic: %v", p)
			}
		}()
		return callback(rec.Binding, root, publish)
	}()
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		return false, a.poison(err)
	}
	if claimed != published {
		return false, a.poison(ErrInvalid)
	}
	if err = a.available(); err != nil {
		return false, err
	}
	return published, nil
}

// All semantic relationships/receipts are validated separately by validate.
// Ineligibility is a clean false, not permission to loosen this predicate.
func prepareRetirementEligible(s *diskState, b Binding) bool {
	rec, ok := s.Attachments[b.Attachment]
	if !ok || rec.Binding != b || rec.Phase != Retiring || rec.Receipt != nil || !validID(rec.Retirement) ||
		b.Role != PrepareRole || b.Mode != ReadWrite || s.Prepares[b.Prepare].Phase != Pending ||
		s.VolumeLifecycles[b.Volume].Phase != VolumeReady || len(s.CopyReplay) != 0 || s.Copy == nil {
		return false
	}
	if s.Operations[rec.Retirement] != digest("retire", RetireRequest{rec.Retirement, b.Store, b.Volume, b.Attachment, b.Launch}) {
		return false
	}
	for id, other := range s.Attachments {
		if id != b.Attachment && (other.Phase != Drained || other.Receipt == nil) {
			return false
		}
	}
	for _, life := range s.VolumeLifecycles {
		if life.Phase != VolumeReady && life.Phase != VolumeDeleted {
			return false
		}
	}
	for _, intent := range s.Copy.Intents {
		owner, ok := s.Attachments[intent.Owner.Attachment]
		if intent.Owner.Attachment == b.Attachment || intent.Phase != CopyCompleted || !ok ||
			owner.Binding != intent.Owner || owner.Phase != Drained || owner.Receipt == nil {
			return false
		}
	}
	return true
}

// Fstatat with NOFOLLOW distinguishes absent slots from links/special files.
// ANY surviving obligation or inspection error fails closed, never generic fallback.
func (j *journal) prepareRetirementSlotsAbsent(startup bool) error {
	names := []string{quarantineName, pendingName, dataIOName, copyOperationName, commitProofName}
	if !startup {
		names = append(names, barrierName)
	}
	for _, name := range names {
		var st unix.Stat_t
		err := unix.Fstatat(int(j.dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil {
			return fmt.Errorf("%w: prepare retirement overlaps %s", ErrRepairRequired, name)
		}
		if !errors.Is(err, unix.ENOENT) {
			return err
		}
	}
	return nil
}

func (a *Authority) publishPrepareRetirement(rec Attachment, root *os.File) (bool, error) {
	if err := a.j.prepareRetirementSlotsAbsent(false); err != nil {
		return false, err
	}
	if a.dataIO != nil || a.copyIO != nil || a.j.uncertain || a.j.retirement != nil || a.j.rootOnly != nil {
		return false, ErrRepairRequired
	}
	if err := a.validate(); err != nil {
		return false, err
	}
	if a.inflight != 0 || !prepareRetirementEligible(a.s, rec.Binding) {
		return false, nil
	}
	for _, rt := range a.runtime {
		// Global zero must agree with every per-attachment count. A mismatch
		// is broken ownership accounting, not ordinary clean ineligibility.
		if rt.count != 0 {
			return false, ErrConflict
		}
	}
	if a.s.Attachments[rec.Binding.Attachment].Retirement != rec.Retirement || root == nil || root != a.roots[rec.Binding.Volume] {
		return false, ErrConflict
	}
	for _, pair := range []struct {
		file *os.File
		want RootIdentity
	}{{a.j.root, a.s.Store.Root}, {a.j.exports, a.s.Store.Exports}, {root, a.s.Volumes[rec.Binding.Volume].Root}} {
		got, err := identity(pair.file)
		if err != nil {
			return false, err
		}
		if got != pair.want {
			return false, ErrConflict
		}
	}
	// Validate every retained volume before issuing a store-global no-work proof.
	for id, v := range a.s.Volumes {
		if a.s.VolumeLifecycles[id].Phase == VolumeDeleted {
			if err := a.deletedRootAbsent(v); err != nil {
				return false, err
			}
			continue
		}
		f, err := a.j.volume(v)
		if err != nil {
			return false, err
		}
		if err = f.Close(); err != nil {
			return false, err
		}
		if a.roots[id] == nil {
			return false, ErrConflict
		}
		got, err := identity(a.roots[id])
		if err != nil {
			return false, err
		}
		if got != v.Root {
			return false, ErrConflict
		}
	}
	prior, err := json.Marshal(a.s)
	if err != nil {
		return false, err
	}
	raw, err := a.j.readStateRaw()
	if err != nil {
		return false, err
	}
	if !bytes.Equal(raw, prior) {
		return false, ErrConflict
	}
	attempt, err := NewID()
	if err != nil {
		return false, err
	}
	p := prepareRetirementProof{prepareRetirementProofVersion, prepareRetirementProofKind, attempt,
		a.s.Store, a.s.Epoch, a.s.Controller, a.s.Bootstrap, a.s.Volumes[rec.Binding.Volume],
		rec.Binding, rec.Retirement, a.s.Revision, contentDigest(prior)}
	if err = a.j.writePrepareRetirementProof(p); err != nil {
		return false, err
	}
	a.j.rootOnly = &p
	return true, nil
}

func (j *journal) writePrepareRetirementProof(p prepareRetirementProof) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if len(data) > maxRetirementProofBytes {
		return ErrLimit
	}
	temp := "prepare-retire-proof-" + string(p.Attempt) + ".tmp"
	var f *os.File
	if err = j.step("prepare-retire-proof-open", func() (e error) {
		f, e = child(j.dir, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
		return
	}); err != nil {
		return err
	}
	defer f.Close()
	for _, step := range []struct {
		name string
		call func() error
	}{
		{"prepare-retire-proof-write", func() error { return writeFull(f, data) }},
		{"prepare-retire-proof-sync", f.Sync},
		{"prepare-retire-proof-close", f.Close},
		{"prepare-retire-proof-rename", func() error { return unix.Renameat(int(j.dir.Fd()), temp, int(j.dir.Fd()), barrierName) }},
		{"prepare-retire-proof-parent-sync", j.dir.Sync},
	} {
		if err = j.step(step.name, step.call); err != nil {
			return err
		}
	}
	return nil
}

func decodePrepareRetirementProof(raw []byte) (*prepareRetirementProof, error) {
	var p prepareRetirementProof
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(p)
	if err != nil || decoder.Decode(new(any)) != io.EOF || !bytes.Equal(raw, canonical) ||
		p.Version != prepareRetirementProofVersion || p.Kind != prepareRetirementProofKind ||
		!validID(p.Attempt) || !validID(p.Epoch) || !validID(p.Store.ID) || !validID(p.Operation) ||
		!validKey(p.Bootstrap) || p.Controller.Epoch == 0 || !validKey(p.Controller.Key) ||
		!volumeValid(p.Volume) || p.Revision == 0 || !validDigest(p.Prior) {
		return nil, ErrInvalid
	}
	return &p, nil
}

func (a *Authority) validatePrepareRetirementRecovery() error {
	fail := func(err error) error { return fmt.Errorf("%w: prepare root-only retry: %v", ErrRepairRequired, err) }
	j := a.j
	p := j.rootOnly
	if p == nil || j.uncertain || j.retirement != nil || j.retirementCandidate != "" {
		return fail(ErrConflict)
	}
	if err := j.prepareRetirementSlotsAbsent(true); err != nil {
		return fail(err)
	}
	return a.validatePrepareRetirementPredecessor(p)
}

// Read-only comparison shared by published retry evidence and inert candidates.
// The caller has validated state semantics and every retained root.
func (a *Authority) validatePrepareRetirementPredecessor(p *prepareRetirementProof) error {
	fail := func(err error) error {
		return fmt.Errorf("%w: prepare root-only predecessor: %v", ErrRepairRequired, err)
	}
	s := a.s
	raw, err := a.j.readStateRaw()
	if err != nil {
		return fail(err)
	}
	canonical, err := json.Marshal(s)
	if err != nil || !bytes.Equal(raw, canonical) || contentDigest(raw) != p.Prior || s.Revision != p.Revision ||
		s.Store != p.Store || s.Epoch != p.Epoch || s.Controller != p.Controller || s.Bootstrap != p.Bootstrap ||
		s.Volumes[p.Volume.ID] != p.Volume || p.Binding.Volume != p.Volume.ID ||
		s.Attachments[p.Binding.Attachment].Retirement != p.Operation || !prepareRetirementEligible(s, p.Binding) {
		return fail(ErrConflict)
	}
	return nil
}

// Only the marker is cleared; no root sync, receipt or state rewrite pretends the
// interrupted barrier completed. All three steps precede ordinary epoch rotation.
func (j *journal) recoverPrepareRetirement() error {
	for _, step := range []struct {
		name string
		call func() error
	}{
		{"recover-prepare-retire-parent-sync", j.dir.Sync},
		{"recover-prepare-retire-unlink", func() error { return unix.Unlinkat(int(j.dir.Fd()), barrierName, 0) }},
		{"recover-prepare-retire-clear-sync", j.dir.Sync},
	} {
		if err := j.step(step.name, step.call); err != nil {
			j.quarantine()
			return fmt.Errorf("%w: %v", ErrRepairRequired, err)
		}
	}
	j.rootOnly = nil
	return nil
}

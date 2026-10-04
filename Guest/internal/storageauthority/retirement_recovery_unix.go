//go:build linux || darwin

package storageauthority

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const retirementProofVersion = 1
const maxRetirementProofBytes = 4096

// retirementProof replaces the pending barrier marker ONLY after the entire
// retained-resource barrier returned nil. It binds exactly one subsequent
// receipt commit, not a later sync, another retirement, or DATA completion.
// A generic fence alone remains fail-closed. One exact complete candidate can
// prove the earlier barrier return for the predecessor only: its first byte is
// written AFTER full barrier success, unlike metadata candidate/Ready files.
type retirementProof struct {
	Version    int         `json:"version"`
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
	Next       string      `json:"next_digest"`
}

func (p retirementProof) receipt() Receipt {
	b := p.Binding
	return Receipt{SchemaVersion, b.Store, b.Volume, b.Attachment, b.Launch, b.Prepare, p.Revision}
}

// Called with authority.mu and barrierMu held, after a successful callBarrier
// and the concurrent-fault check. Control commits may have run during the
// barrier, so bind the current durable predecessor, not its earlier revision.
func (a *Authority) certifyRetirement(next *diskState, rec Attachment) error {
	if a.s.Revision == ^uint64(0) {
		return ErrCapacityInvariant
	}
	current := a.s.Attachments[rec.Binding.Attachment]
	root, err := identity(a.roots[rec.Binding.Volume])
	if err != nil {
		return err
	}
	if current.Binding != rec.Binding || current.Phase != Retiring || current.Receipt != nil ||
		current.Retirement != rec.Retirement || root != a.s.Volumes[rec.Binding.Volume].Root {
		return ErrConflict
	}
	next.Revision = a.s.Revision + 1 // commit will use exactly this revision
	prior, err := json.Marshal(a.s)
	if err != nil {
		return err
	}
	raw, err := a.j.readStateRaw()
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, prior) {
		return ErrConflict
	}
	candidate, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err = a.capacity(next, int64(len(candidate))); err != nil {
		return err
	}
	attempt, err := NewID()
	if err != nil {
		return err
	}
	p := retirementProof{retirementProofVersion, attempt, a.s.Store, a.s.Epoch,
		a.s.Controller, a.s.Bootstrap, a.s.Volumes[rec.Binding.Volume], rec.Binding,
		rec.Retirement, next.Revision, contentDigest(prior), contentDigest(candidate)}
	return a.j.writeRetirementProof(p)
}

func (j *journal) writeRetirementProof(p retirementProof) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if len(data) > maxRetirementProofBytes {
		return ErrLimit
	}
	// Unique unpublished file: failure cannot destroy the durable pending marker.
	temp := "barrier-" + string(p.Attempt) + ".tmp"
	if j.rootOnly != nil {
		// Partial completion candidates above a retry-only proof are inert, never
		// generic barrier candidates, even after a later retirement reuses the root.
		temp = "prepare-retire-complete-" + string(p.Attempt) + ".tmp"
	}
	var f *os.File
	if err = j.step("barrier-complete-open", func() (e error) {
		f, e = child(j.dir, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
		return
	}); err != nil {
		return err
	}
	defer f.Close()
	if err = j.step("barrier-complete-write", func() error { return writeFull(f, data) }); err != nil {
		return err
	}
	if err = j.step("barrier-complete-sync", f.Sync); err != nil {
		return err
	}
	if err = j.step("barrier-complete-close", f.Close); err != nil {
		return err
	}
	if err = j.step("barrier-complete-rename", func() error {
		return unix.Renameat(int(j.dir.Fd()), temp, int(j.dir.Fd()), barrierName)
	}); err != nil {
		return err
	}
	if err = j.step("barrier-complete-parent-sync", j.dir.Sync); err != nil {
		return err
	}
	j.rootOnly = nil
	return nil
}

// This loader is also the legacy/pending fence: only the exact canonical,
// bounded completed record may defer the barrier decision until full startup
// validation. It never follows links or reads special/foreign/linked files.
func (j *journal) loadRetirementProof() (*retirementProof, error) {
	j.retirementCandidate = ""
	f, raw, err := j.openRetirementProofFile(barrierName)
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	if !bytes.Equal(raw, []byte(uncertainIOText)) {
		// The closed retry-only schema is dispatched before v1. Neither malformed
		// records nor unknown versions/kinds may fall back to candidate scanning.
		var header struct {
			Version int    `json:"version"`
			Kind    string `json:"kind"`
		}
		if err = json.Unmarshal(raw, &header); err != nil {
			return nil, err
		}
		if header.Version == prepareRetirementProofVersion || header.Kind != "" {
			j.rootOnly, err = decodePrepareRetirementProof(raw)
			return nil, err
		}
		return decodeRetirementProof(raw)
	}
	name, err := j.retirementCandidateName()
	if err != nil {
		return nil, err
	}
	f, raw, err = j.openRetirementProofFile(name)
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	p, err := decodeRetirementProof(raw)
	if err != nil {
		return nil, err
	}
	if name != "barrier-"+string(p.Attempt)+".tmp" {
		return nil, ErrConflict
	}
	j.retirementCandidate = name
	return p, nil
}

// Bounded, exact candidate census under flock. Do not search for a usable match
// among stale/malformed attempts. Fresh dir description leaves j.dir untouched.
func (j *journal) retirementCandidateName() (string, error) {
	fd, err := unix.Openat(int(j.dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	dir := os.NewFile(uintptr(fd), "retirement-candidate-census")
	defer dir.Close()
	const maxEntries = 256
	names, err := dir.Readdirnames(maxEntries + 1)
	if (err != nil && err != io.EOF) || len(names) > maxEntries {
		return "", ErrInvalid
	}
	candidate := ""
	for _, name := range names {
		if name == barrierName || !strings.HasPrefix(name, "barrier-") {
			continue
		}
		attempt := strings.TrimSuffix(strings.TrimPrefix(name, "barrier-"), ".tmp")
		if candidate != "" || !strings.HasSuffix(name, ".tmp") || !validID(ID(attempt)) {
			return "", ErrInvalid
		}
		candidate = name
	}
	if candidate == "" {
		return "", ErrMissing
	}
	return candidate, nil
}

func (j *journal) openRetirementProofFile(name string) (_ *os.File, _ []byte, err error) {
	f, err := child(j.dir, name, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			f.Close()
		}
	}()
	var st, dir unix.Stat_t
	if err = unix.Fstat(int(f.Fd()), &st); err != nil {
		return nil, nil, err
	}
	if err = unix.Fstat(int(j.dir.Fd()), &dir); err != nil {
		return nil, nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0077 != 0 || st.Uid != uint32(os.Geteuid()) ||
		st.Nlink != 1 || st.Dev != dir.Dev || st.Size <= 0 || st.Size > maxRetirementProofBytes {
		return nil, nil, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxRetirementProofBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(raw)) != st.Size {
		return nil, nil, ErrInvalid
	}
	return f, raw, nil
}

func decodeRetirementProof(raw []byte) (*retirementProof, error) {
	var p retirementProof
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(p)
	if err != nil || decoder.Decode(new(any)) != io.EOF || !bytes.Equal(raw, canonical) ||
		p.Version != retirementProofVersion || !validID(p.Attempt) || !validID(p.Epoch) ||
		!validID(p.Operation) || !validID(p.Store.ID) || !validKey(p.Bootstrap) ||
		p.Controller.Epoch == 0 || !validKey(p.Controller.Key) || !volumeValid(p.Volume) ||
		p.Revision < 2 || !validDigest(p.Prior) || !validDigest(p.Next) || p.Prior == p.Next {
		return nil, ErrInvalid
	}
	return &p, nil
}

// validateRetirementRecovery is read-only. In particular it runs BEFORE metadata
// recovery can remove a certificate. The normal caller has already checked the
// configured identity, ExpectedStartup, semantics, volume roots and copy state.
// Read the exact disk state: startup copy replay reconstruction can change the
// in-memory CopyReplay map without representing a persisted metadata change.
func (j *journal) validateRetirementRecovery() error {
	fail := func(err error) error { return fmt.Errorf("%w: retirement completion: %v", ErrRepairRequired, err) }
	p := j.retirement
	if p == nil {
		return fail(ErrInvalid)
	}
	s, err := j.load()
	if err != nil {
		return fail(err)
	}
	raw, err := j.readStateRaw()
	if err != nil {
		return fail(err)
	}
	rec, ok := s.Attachments[p.Binding.Attachment]
	if !ok || s.Store != p.Store || s.Epoch != p.Epoch || s.Controller != p.Controller ||
		s.Bootstrap != p.Bootstrap || s.Volumes[p.Volume.ID] != p.Volume ||
		p.Binding.Volume != p.Volume.ID || !bindingValid(p.Binding, s) || rec.Binding != p.Binding ||
		rec.Retirement != p.Operation || s.Operations[p.Operation] != digest("retire",
		RetireRequest{p.Operation, p.Binding.Store, p.Binding.Volume, p.Binding.Attachment, p.Binding.Launch}) {
		return fail(ErrConflict)
	}
	landed := contentDigest(raw) == p.Next
	// Candidate creation proves the earlier barrier only. It cannot authorize a
	// successor or overlap a receipt metadata transaction that requires publication.
	if j.retirementCandidate != "" && (landed || j.uncertain) {
		return fail(ErrConflict)
	}
	want := p.receipt()
	var opposite string
	if landed {
		if s.Revision != p.Revision || rec.Phase != Drained || rec.Receipt == nil || *rec.Receipt != want {
			return fail(ErrConflict)
		}
		s.Revision--
		rec.Phase, rec.Receipt = Retiring, nil
		opposite = p.Prior
	} else {
		if contentDigest(raw) != p.Prior || s.Revision != p.Revision-1 || rec.Phase != Retiring || rec.Receipt != nil {
			return fail(ErrConflict)
		}
		s.Revision++
		rec.Phase, rec.Receipt = Drained, &want
		opposite = p.Next
	}
	// The two images must differ ONLY in the selected receipt/phase and revision.
	s.Attachments[p.Binding.Attachment] = rec
	other, err := json.Marshal(s)
	if err != nil || contentDigest(other) != opposite {
		return fail(ErrConflict)
	}
	if j.uncertain {
		meta, err := j.loadCommitProof()
		if err != nil {
			return fail(err)
		}
		if meta == nil || meta.Store != p.Store.ID || meta.Epoch != p.Epoch || meta.Revision != p.Revision ||
			meta.Prior != p.Prior || meta.Next != p.Next || (landed && !meta.Ready) {
			return fail(ErrConflict)
		}
	}
	return nil
}

// Promote only the fully validated conditional witness, preserving the generic
// fence until rename. This sync establishes retryable certificate cleanup, NOT
// retroactive proof of barrier completion (which preceded candidate creation).
func (j *journal) promoteRetirementCandidate() error {
	f, raw, err := j.openRetirementProofFile(j.retirementCandidate)
	if err != nil {
		return err
	}
	defer f.Close()
	p, err := decodeRetirementProof(raw)
	if err != nil {
		return err
	}
	if j.retirement == nil || *p != *j.retirement {
		return ErrConflict
	}
	if err = j.step("recover-barrier-candidate-sync", f.Sync); err != nil {
		return err
	}
	if err = j.step("recover-barrier-candidate-close", f.Close); err != nil {
		return err
	}
	if err = j.step("recover-barrier-candidate-rename", func() error {
		return unix.Renameat(int(j.dir.Fd()), j.retirementCandidate, int(j.dir.Fd()), barrierName)
	}); err != nil {
		return err
	}
	j.retirementCandidate = ""
	return nil
}

// Recovery retains the proven visible image. It does not invoke a new barrier,
// manufacture a receipt or rewrite state.json. In the predecessor case the
// normal controller Retire retry must still perform its own complete barrier.
func (j *journal) recoverRetirement() error {
	if j.retirementCandidate != "" {
		if err := j.promoteRetirementCandidate(); err != nil {
			j.quarantine()
			return fmt.Errorf("%w: %v", ErrRepairRequired, err)
		}
	}
	for _, step := range []struct {
		name string
		call func() error
	}{
		{"recover-barrier-parent-sync", j.dir.Sync},
		{"recover-barrier-unlink", func() error { return unix.Unlinkat(int(j.dir.Fd()), barrierName, 0) }},
		{"recover-barrier-clear-sync", j.dir.Sync},
	} {
		if err := j.step(step.name, step.call); err != nil {
			j.quarantine()
			return fmt.Errorf("%w: %v", ErrRepairRequired, err)
		}
	}
	return nil
}

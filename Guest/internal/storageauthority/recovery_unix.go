//go:build linux || darwin

package storageauthority

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/sys/unix"
)

// recoverUncertainty resolves only a versioned metadata commit certificate,
// with the journal flock held and all startup identity/root/semantic checks done.
// The exact durable predecessor is safe regardless of candidate IO completion.
// The exact successor additionally requires Ready, written only after candidate
// fsync/close succeeded. Recovery stabilizes the visible namespace before
// retiring the certificate; it never rewrites state.json or creates a receipt.
// Generic/known-error/DATA/pending-barrier markers are refused by openJournal.
// If a completed retirement certificate also exists, the caller must validate
// that it binds this exact metadata transaction before starting either cleanup.
// A cleanup IO failure is quarantined; a crash before quarantine cannot discard
// acknowledged state because both permitted images already have durable bytes.
func (j *journal) validateUncertainty() error {
	fail := func(err error) error {
		if err == nil {
			return ErrRepairRequired
		}
		return fmt.Errorf("%w: %v", ErrRepairRequired, err)
	}
	proof, err := j.loadCommitProof()
	if err != nil {
		return fail(err)
	}
	if proof == nil {
		return fail(nil)
	}
	raw, err := j.readStateRaw()
	if err != nil {
		return fail(err)
	}
	switch {
	case raw != nil && contentDigest(raw) == proof.Next:
		if !proof.Ready {
			return fail(nil) // no proof of successful candidate durability IO
		}
		s, lerr := j.load()
		if lerr != nil || s.Revision != proof.Revision || s.Epoch != proof.Epoch || s.Store.ID != proof.Store {
			return fail(lerr)
		}
	case proof.Prior != "" && raw != nil && contentDigest(raw) == proof.Prior:
		s, lerr := j.load()
		if lerr != nil || s.Revision == ^uint64(0) || s.Revision+1 != proof.Revision || s.Store.ID != proof.Store {
			return fail(lerr)
		}
	default:
		return fail(nil)
	}
	return nil
}

func (j *journal) recoverUncertainty() error {
	if err := j.validateUncertainty(); err != nil {
		return err
	}
	fail := func(err error) error { return fmt.Errorf("%w: %v", ErrRepairRequired, err) }
	// Complete a possibly interrupted namespace publication before removing
	// its only recovery evidence. A crash at every cleanup edge is retryable.
	if err := j.step("recover-state-parent-sync", j.dir.Sync); err != nil {
		j.quarantine()
		return fail(err)
	}
	if err := j.step("recover-proof-unlink", func() error { return unix.Unlinkat(int(j.dir.Fd()), commitProofName, 0) }); err != nil {
		j.quarantine()
		return fail(err)
	}
	if err := j.step("recover-proof-sync", j.dir.Sync); err != nil {
		j.quarantine()
		return fail(err)
	}
	return nil
}

// loadCommitProof reads and strictly validates the durable certificate.
// A missing proof is (nil, nil); any malformed, non-canonical, wrong-version,
// or field-invalid proof is an error so recovery fails closed.
func (j *journal) loadCommitProof() (*commitProof, error) {
	f, err := child(j.dir, commitProofName, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxCommitProofBytes {
		return nil, ErrInvalid
	}
	b, err := io.ReadAll(io.LimitReader(f, maxCommitProofBytes+1))
	if err != nil {
		return nil, err
	}
	return decodeCommitProof(b)
}

func decodeCommitProof(b []byte) (*commitProof, error) {
	var p commitProof
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if dec.Decode(new(any)) != io.EOF {
		return nil, ErrInvalid
	}
	canonical, err := json.Marshal(p)
	if err != nil || !bytes.Equal(canonical, b) {
		return nil, ErrInvalid
	}
	if p.Version != commitProofVersion || !validID(p.Store) || !validID(p.Epoch) || p.Revision == 0 ||
		(p.Prior != "" && !validDigest(p.Prior)) || !validDigest(p.Next) {
		return nil, ErrInvalid
	}
	return &p, nil
}

func validDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == s
}

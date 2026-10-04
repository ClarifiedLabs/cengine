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
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const registryName = ".cengine-storage-authority"
const stateName = "state.json"
const pendingName = "uncertain"
const barrierName = "barrier-uncertain"

// quarantineName is the permanent known-IO-error marker. quarantine writes it
// durable best-effort BEFORE the generic uncertainty marker; open refuses it
// unconditionally and no path clears it automatically. It pins EIO/ENOSPC
// provenance across restart so auto recovery can apply only to clean crash
// uncertainty where the durable commit proof demonstrates the outcome.
const quarantineName = "io-quarantined"

// commitProofName is the write-ahead certificate for one metadata transaction.
// The initial certificate precedes all candidate state IO. Ready is published
// atomically only AFTER the candidate file has been synced and closed, BEFORE
// its rename. Thus an exact predecessor can be retained, or an exact Ready
// successor's namespace publication completed. Neither is inferred from JSON
// validity alone. DATA/in-progress barriers and known IO errors remain separate.
const commitProofName = "commit-proof"
const commitProofVersion = 2
const maxCommitProofBytes = 4096

// commitProof is the RTM099 durable recovery proof for one journal metadata
// transaction. Prior/Next bind the exact raw bytes of the predecessor and
// successor state.json encodings. Ready proves successful candidate fsync and
// close before publication. It is not a receipt or evidence of data-plane IO.
type commitProof struct {
	Version  int    `json:"version"`
	Store    ID     `json:"store"`
	Epoch    ID     `json:"epoch"`
	Revision uint64 `json:"revision"`
	Prior    string `json:"prior_digest"`
	Next     string `json:"next_digest"`
	Ready    bool   `json:"ready"`
}

func contentDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type journal struct {
	root, exports, dir, lock *os.File
	maxBytes                 int64
	// uncertain denotes a surviving metadata commit certificate. Generic
	// uncertainty markers never authorize automatic recovery.
	uncertain bool
	// Completed-barrier evidence still requires full startup validation. A generic
	// fence alone never reaches this state; the candidate exception is prior-only.
	retirement          *retirementProof
	retirementCandidate string
	rootOnly            *prepareRetirementProof
	// Tests inject failures before every boundary without replacing durability IO.
	fault func(string) error
	// Private full-profile IO scope, installed only while authority.mu is held.
	prepareIOFault func(string) error
	// Tests can abruptly exit after real IO without running cleanup/poison.
	afterStep func(string)
}

func identity(f *os.File) (RootIdentity, error) {
	var s unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &s); err != nil {
		return RootIdentity{}, err
	}
	if s.Mode&unix.S_IFMT != unix.S_IFDIR {
		return RootIdentity{}, ErrInvalid
	}
	return RootIdentity{uint64(s.Dev), uint64(s.Ino)}, nil
}
func dupDirectory(f *os.File) (*os.File, error) {
	if f == nil {
		return nil, ErrInvalid
	}
	n, err := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	out := os.NewFile(uintptr(n), "backing-root")
	if _, err = identity(out); err != nil {
		out.Close()
		return nil, err
	}
	return out, nil
}
func child(dir *os.File, name string, flags int, mode uint32) (*os.File, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return nil, ErrInvalid
	}
	fd, err := unix.Openat(int(dir.Fd()), name, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, mode)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
func openJournal(c Config, initialize bool) (*journal, error) {
	return openJournalMode(c, initialize, false)
}

// probeJournal opens only existing files read-only and holds the same exclusive
// flock as the writable opener. It never initializes, syncs or recovers state.
func probeJournal(c Config) (*journal, error) {
	return openJournalMode(c, false, true)
}

func openJournalMode(c Config, initialize, readOnly bool) (*journal, error) {
	root, err := dupDirectory(c.Root)
	if err != nil {
		return nil, err
	}
	j := &journal{root: root, maxBytes: c.Limits.JournalBytes}
	ok := false
	defer func() {
		if !ok {
			j.close()
		}
	}()
	if initialize {
		// Never initialize over an existing registry, including an incomplete one.
		if err = unix.Mkdirat(int(root.Fd()), registryName, 0700); err != nil {
			return nil, fmt.Errorf("initialize registry: %w", err)
		}
		if err = root.Sync(); err != nil {
			return nil, err
		}
	}
	j.dir, err = child(root, registryName, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, ErrMissing
	}
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err = unix.Fstat(int(j.dir.Fd()), &st); err != nil {
		return nil, err
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
		return nil, ErrInvalid
	}
	flags := unix.O_RDWR
	if readOnly {
		flags = unix.O_RDONLY
	}
	if initialize {
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	j.lock, err = child(j.dir, "lock", flags, 0600)
	if errors.Is(err, unix.ENOENT) {
		return nil, ErrMissing
	}
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(j.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLocked, err)
	}
	if initialize {
		if err = j.lock.Sync(); err != nil {
			return nil, err
		}
		if err = j.dir.Sync(); err != nil {
			return nil, err
		}
	}
	// The fixed exports directory must already exist.
	j.exports, err = child(root, "volumes", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	r, err := identity(root)
	if err != nil {
		return nil, err
	}
	e, err := identity(j.exports)
	if err != nil {
		return nil, err
	}
	d, err := identity(j.dir)
	if err != nil {
		return nil, err
	}
	if r.Device != e.Device || r.Device != d.Device || e == d {
		return nil, ErrInvalid
	}
	if !initialize {
		// Certificates defer only their own decision until full startup validation.
		// DATA, generic uncertainty and known-error markers always refuse. A
		// generic barrier needs exact completed evidence, never a later sync.
		for _, name := range []string{quarantineName, pendingName, barrierName, dataIOName, commitProofName} {
			f, pe := child(j.dir, name, unix.O_RDONLY|unix.O_NONBLOCK, 0)
			if pe == nil {
				f.Close()
				switch name {
				case commitProofName:
					j.uncertain = true
				case barrierName:
					j.retirement, err = j.loadRetirementProof()
					if err != nil {
						return nil, fmt.Errorf("%w: %v", ErrRepairRequired, err)
					}
				default:
					return nil, ErrRepairRequired
				}
				continue
			}
			if !errors.Is(pe, unix.ENOENT) {
				return nil, fmt.Errorf("%w: %v", ErrRepairRequired, pe)
			}
		}
	}
	ok = true
	return j, nil
}
func (j *journal) close() {
	// flock remains held until every journal/retained-root descriptor is closed.
	for _, f := range []*os.File{j.exports, j.dir, j.root, j.lock} {
		if f != nil {
			_ = f.Close()
		}
	}
}
func (j *journal) step(name string, fn func() error) error {
	if j.fault != nil {
		if err := j.fault(name); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if j.prepareIOFault != nil {
		if err := j.prepareIOFault(name); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if err := fn(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if j.afterStep != nil {
		j.afterStep(name)
	}
	return nil
}

const uncertainIOText = "Uncertain authority IO or barrier: offline repair required.\n"

func (j *journal) mark() error { return j.markNamed(pendingName) }
func (j *journal) markNamed(name string) error {
	var f *os.File
	if err := j.step("marker-open", func() (err error) { f, err = child(j.dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC, 0600); return }); err != nil {
		return err
	}
	defer f.Close()
	if err := j.step("marker-write", func() error {
		return writeFull(f, []byte(uncertainIOText))
	}); err != nil {
		return err
	}
	if err := j.step("marker-sync", f.Sync); err != nil {
		return err
	}
	if err := j.step("marker-close", f.Close); err != nil {
		return err
	}
	return j.step("marker-parent-sync", j.dir.Sync)
}

// quarantine is best-effort evidence after an IO fault, NOT a promise that a
// failed device can record new evidence. A pre-existing durable marker is kept.
// The quarantine marker precedes the generic marker; either surviving marker
// blocks recovery. A crash before either can be written is safe only where the
// metadata certificate independently proves an outcome; it is not evidence
// that no error happened. Data and barrier obligations remain fail-closed.
func (j *journal) quarantine() {
	hook := j.fault
	j.fault = nil
	_ = j.markNamed(quarantineName)
	_ = j.mark()
	j.fault = hook
}
func (j *journal) persist(s *diskState) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if int64(len(data)) > j.maxBytes {
		return ErrLimit
	}
	// Bind the exact durable predecessor bytes before publishing the certificate
	// so a later crash can be proven to have landed or not landed. The first commit
	// after Initialize has no predecessor; Prior="" records that.
	var prior string
	if err = j.step("state-read-prior", func() (e error) { prior, e = j.stateDigest(); return }); err != nil {
		return err
	}
	proof := commitProof{commitProofVersion, s.Store.ID, s.Epoch, s.Revision, prior, contentDigest(data), false}
	if err = j.writeCommitProof("proof", proof); err != nil {
		return err
	}
	id, err := NewID()
	if err != nil {
		return err
	}
	temp := "state-" + string(id) + ".tmp"
	var f *os.File
	if err = j.step("state-open", func() (e error) { f, e = child(j.dir, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600); return }); err != nil {
		return err
	}
	defer f.Close()
	if err = j.step("state-write", func() error { return writeFull(f, data) }); err != nil {
		return err
	}
	if err = j.step("state-sync", f.Sync); err != nil {
		return err
	}
	if err = j.step("state-close", f.Close); err != nil {
		return err
	}
	// Ready can only be written after successful candidate durability IO.
	// Atomic replacement keeps the prior-only certificate intact on a torn write.
	proof.Ready = true
	if err = j.writeCommitProof("proof-ready", proof); err != nil {
		return err
	}
	if err = j.step("state-rename", func() error { return unix.Renameat(int(j.dir.Fd()), temp, int(j.dir.Fd()), stateName) }); err != nil {
		return err
	}
	if err = j.step("state-parent-sync", j.dir.Sync); err != nil {
		return err
	}
	if err = j.step("proof-unlink", func() error { return unix.Unlinkat(int(j.dir.Fd()), commitProofName, 0) }); err != nil {
		return err
	}
	return j.step("proof-clear-sync", j.dir.Sync)
}

// writeCommitProof atomically publishes a complete certificate. No in-place
// rewrite may destroy the prior-only proof before Ready becomes durable.
// Unpublished UUID temporaries are never evidence and are left for offline GC.
func (j *journal) writeCommitProof(prefix string, proof commitProof) error {
	data, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	if len(data) > maxCommitProofBytes {
		return ErrLimit
	}
	id, err := NewID()
	if err != nil {
		return err
	}
	temp := "proof-" + string(id) + ".tmp"
	var f *os.File
	if err = j.step(prefix+"-open", func() (e error) { f, e = child(j.dir, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600); return }); err != nil {
		return err
	}
	defer f.Close()
	if err = j.step(prefix+"-write", func() error { return writeFull(f, data) }); err != nil {
		return err
	}
	if err = j.step(prefix+"-sync", f.Sync); err != nil {
		return err
	}
	if err = j.step(prefix+"-close", f.Close); err != nil {
		return err
	}
	if err = j.step(prefix+"-rename", func() error { return unix.Renameat(int(j.dir.Fd()), temp, int(j.dir.Fd()), commitProofName) }); err != nil {
		return err
	}
	return j.step(prefix+"-parent-sync", j.dir.Sync)
}

// stateDigest returns the content digest of the current durable state.json,
// or "" when no state exists yet (the first commit after Initialize).
func (j *journal) stateDigest() (string, error) {
	raw, err := j.readStateRaw()
	if err != nil {
		return "", err
	}
	if raw == nil {
		return "", nil
	}
	return contentDigest(raw), nil
}

// readStateRaw reads the exact current state.json bytes. A missing state is
// (nil, nil); any other error is an IO failure and must fail closed.
func (j *journal) readStateRaw() ([]byte, error) {
	f, err := child(j.dir, stateName, unix.O_RDONLY|unix.O_NONBLOCK, 0)
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
	if !info.Mode().IsRegular() || info.Size() > j.maxBytes {
		return nil, ErrInvalid
	}
	b, err := io.ReadAll(io.LimitReader(f, j.maxBytes+1))
	if err != nil {
		return nil, err
	}
	return b, nil
}
func (j *journal) clearBarrier() error {
	if err := j.step("barrier-unlink", func() error { return unix.Unlinkat(int(j.dir.Fd()), barrierName, 0) }); err != nil {
		return err
	}
	if err := j.step("barrier-clear-sync", j.dir.Sync); err != nil {
		return err
	}
	j.rootOnly = nil
	return nil
}
func (j *journal) load() (*diskState, error) {
	f, err := child(j.dir, stateName, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, ErrMissing
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > j.maxBytes {
		return nil, ErrInvalid
	}
	b, err := io.ReadAll(io.LimitReader(f, j.maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > j.maxBytes {
		return nil, ErrLimit
	}
	var s diskState
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if dec.Decode(new(any)) != io.EOF {
		return nil, ErrInvalid
	}
	// Canonical encoding rejects duplicate fields and alternate ambiguous JSON.
	canonical, err := json.Marshal(s)
	if err != nil || !bytes.Equal(canonical, b) {
		return nil, ErrInvalid
	}
	return &s, nil
}
func (j *journal) volume(v Volume) (*os.File, error) {
	f, err := volumeDirectory(j.exports, v.Name)
	if err != nil {
		return nil, err
	}
	got, err := identity(f)
	if err != nil || got != v.Root {
		f.Close()
		return nil, fmt.Errorf("%w: volume root identity", ErrConflict)
	}
	return f, nil
}

func writeFull(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

package storageauthority

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	"golang.org/x/sys/unix"
)

// admitLifecycleRecovery is read-only. The caller holds flock and has checked
// schema, ROOT, exact current signed grant, E/C/key/open revision and ALL roots.
// This is not a filename whitelist: every additional entry needs its own exact
// existing transaction proof. Live takeover/retirement keep the strict census.
func (a *Authority) admitLifecycleRecovery(open *lifecycleOpen) ([]string, error) {
	j := a.j
	fail := func(err error) ([]string, error) {
		return nil, fmt.Errorf("%w: lifecycle recovery: %v", ErrRepairRequired, err)
	}
	fd, err := unix.Openat(int(j.dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(err)
	}
	dir := os.NewFile(uintptr(fd), "lifecycle-recovery-census")
	defer dir.Close()
	// Two base entries, a metadata proof and its two temporaries, plus a
	// completed barrier or published copy obligation. Candidate retirement cannot
	// overlap metadata.
	const maxEntries = 6
	names, err := dir.Readdirnames(maxEntries + 1)
	if (err != nil && err != io.EOF) || len(names) > maxEntries {
		return fail(ErrInvalid)
	}
	if len(names) == 2 {
		// The clean fast path is not count-only: both surviving entries must be
		// the same base pair every other branch whitelists.
		for _, name := range names {
			if name != "lock" && name != stateName {
				return fail(ErrConflict)
			}
		}
		return nil, j.lifecycleNamespaceClean()
	}
	// Identity-only/current-only APIs cannot discharge recovery evidence.
	if open.current == nil || open.expected == nil {
		return fail(ErrConflict)
	}
	// A private BOUND provision directory is never a disposable temporary. Its
	// published obligation (or the exact persisted replay after startup) must
	// prove the whole standalone census before any startup mutation.
	if (len(names) == 3 || len(names) == 4) && !j.uncertain && j.rootOnly == nil && j.retirement == nil && j.retirementCandidate == "" {
		for _, name := range names {
			if strings.HasPrefix(name, "copy-") && !lifecycleTemporary(name, "copy-op-") && name != copyOperationName {
				if err := a.validateLifecyclePrivateProvision(names, name); err != nil {
					return fail(err)
				}
				return nil, nil
			}
		}
	}
	// A standalone published copy obligation has its own exact replay contract.
	// This is only namespace/file admission: loadCopyOperation and physical DATA
	// preflight below must both succeed before any cleanup or startup commit.
	// Published copy may also accompany proven same-E metadata below. Unpublished
	// candidates remain standalone and require exact read-only prestate validation.
	if len(names) == 3 && !j.uncertain && j.rootOnly == nil && j.retirement == nil && j.retirementCandidate == "" {
		standalone, artifact := true, ""
		for _, name := range names {
			switch {
			case name == "lock" || name == stateName:
			case name == copyOperationName || lifecycleTemporary(name, "copy-op-") ||
				lifecycleTemporary(name, "prepare-retire-proof-") || lifecycleTemporary(name, "proof-"):
				artifact = name
			default:
				standalone = false
			}
		}
		if standalone && artifact != "" {
			if lifecycleTemporary(artifact, "prepare-retire-proof-") || lifecycleTemporary(artifact, "proof-") {
				if err := a.validateLifecycleInitialTemporary(artifact); err != nil {
					return fail(err)
				}
				return []string{artifact}, nil
			}
			raw, err := j.readLifecycleArtifact(artifact, maxCopyOperationBytes)
			if err != nil {
				return fail(err)
			}
			if artifact == copyOperationName {
				return nil, nil // loadCopyOperation owns replay reconstruction below.
			}
			r, err := a.decodeCopyOperation(raw)
			if err != nil || r.Epoch != a.s.Epoch || r.Before != a.s.Copy.Intents[r.Binding.Volume] {
				return fail(ErrConflict)
			}
			// Caller IO cannot start before rename + directory fsync. This is
			// only an inert prestate candidate, never a new replay or receipt.
			return []string{artifact}, nil
		}
	}
	var meta *commitProof
	if j.uncertain {
		// Stronger file-identity checks are schema-4-only; no v1 format changes.
		if _, err = j.readLifecycleArtifact(commitProofName, maxCommitProofBytes); err != nil {
			return fail(err)
		}
		meta, err = j.loadCommitProof()
		if err != nil || meta == nil {
			return fail(err)
		}
		// Initial creation and a different live-open E are not workload recovery.
		// A published cold or resume startup candidate is not a same-E workload
		// commit, even when its new E is already visible in state.json.
		cold, resume := a.s.Lifecycle.ColdApplied, a.s.Lifecycle.ResumeApplied
		if meta.Prior == "" || meta.Prior == meta.Next || meta.Epoch != a.s.Epoch ||
			(cold != nil && cold.ServiceEpoch == meta.Epoch && cold.OpenRevision == meta.Revision) ||
			(resume != nil && resume.ServiceEpoch == meta.Epoch && resume.OpenRevision == meta.Revision) {
			return fail(ErrConflict)
		}
		if err = j.validateUncertainty(); err != nil {
			return fail(err)
		}
	}
	if j.rootOnly != nil {
		if err = a.validatePrepareRetirementRecovery(); err != nil {
			return fail(err)
		}
	}
	if j.retirement != nil {
		if err = j.validateRetirementRecovery(); err != nil {
			return fail(err)
		}
	}
	var stateTemp, proofTemp, prepareCompletionTemp string
	for _, name := range names {
		switch {
		case name == "lock" || name == stateName:
		case name == commitProofName && meta != nil:
		case name == copyOperationName && meta != nil && j.rootOnly == nil && j.retirement == nil && j.retirementCandidate == "":
			// Decode/replay reconstruction and mandatory DATA preflight remain in
			// openAuthority, before ANY temporary or published proof is removed.
			if _, err := j.readLifecycleArtifact(name, maxCopyOperationBytes); err != nil {
				return fail(err)
			}
		case name == barrierName && (j.rootOnly != nil || j.retirement != nil):
		case name == j.retirementCandidate && j.retirement != nil:
		case lifecycleTemporary(name, "prepare-retire-complete-") && j.rootOnly != nil && prepareCompletionTemp == "":
			prepareCompletionTemp = name
		case lifecycleTemporary(name, "state-") && meta != nil && stateTemp == "":
			stateTemp = name
		case lifecycleTemporary(name, "proof-") && meta != nil && proofTemp == "":
			proofTemp = name
		default:
			// Includes terminal, DATA, unpublished mixed copy, unknown, partial proof
			// publication, mixed attempts and unbound historical temporaries.
			return fail(ErrConflict)
		}
	}
	var temporaries []string
	if prepareCompletionTemp != "" {
		if err := a.validateLifecyclePrepareCompletionTemporary(prepareCompletionTemp); err != nil {
			return fail(err)
		}
		temporaries = append(temporaries, prepareCompletionTemp)
	}
	if stateTemp != "" {
		raw, err := j.readLifecycleArtifact(stateTemp, j.maxBytes)
		if err != nil || contentDigest(raw) != meta.Next || a.s.Revision+1 != meta.Revision {
			return fail(ErrConflict)
		}
		var next diskState
		if err = json.Unmarshal(raw, &next); err != nil {
			return fail(err)
		}
		canonical, err := json.Marshal(next)
		if err != nil || !bytes.Equal(raw, canonical) || next.Schema != LifecycleSchemaVersion ||
			next.Revision != meta.Revision || next.Epoch != a.s.Epoch || next.Store != a.s.Store ||
			next.Bootstrap != a.s.Bootstrap || next.Controller != a.s.Controller || !reflect.DeepEqual(next.Lifecycle, a.s.Lifecycle) {
			return fail(ErrConflict)
		}
		check := &Authority{s: &next, limits: a.limits}
		if err = check.validate(); err != nil {
			return fail(err)
		}
		temporaries = append(temporaries, stateTemp)
	}
	if proofTemp != "" {
		// Only the exact Ready replacement beside the still-unready published
		// proof and full candidate is bound. It NEVER supplies missing Ready.
		if stateTemp == "" || meta.Ready {
			return fail(ErrConflict)
		}
		raw, err := j.readLifecycleArtifact(proofTemp, maxCommitProofBytes)
		if err != nil {
			return fail(err)
		}
		ready := *meta
		ready.Ready = true
		canonical, err := json.Marshal(ready)
		if err != nil || !bytes.Equal(raw, canonical) {
			return fail(ErrConflict)
		}
		// Remove the dependent Ready temporary first. A crash between these
		// unlinks leaves a state candidate still bound by the published proof.
		temporaries = append([]string{proofTemp}, temporaries...)
	}
	return temporaries, nil
}

// validateLifecyclePrivateProvision admits only the completed private BOUND cut,
// not pre-bind mkdir, public publication, metadata uncertainty or mixed attempts.
// This grants no filesystem replay authority: ProvisionCopyTransaction still
// checks the complete ext4 generation/handle before publishing the retained inode.
func (a *Authority) validateLifecyclePrivateProvision(names []string, name string) error {
	published := false
	for _, entry := range names {
		switch entry {
		case "lock", stateName, name:
		case copyOperationName:
			published = true
		default:
			return ErrConflict
		}
	}
	if (published && len(names) != 4) || (!published && len(names) != 3) {
		return ErrConflict
	}
	var r copyOperationRecord
	if published {
		raw, err := a.j.readLifecycleArtifact(copyOperationName, maxCopyOperationBytes)
		if err != nil {
			return err
		}
		r, err = a.decodeCopyOperation(raw)
		if err != nil {
			return err
		}
		if prior, ok := a.s.CopyReplay[r.Binding.Volume]; ok && !reflect.DeepEqual(prior, r) {
			return ErrConflict
		}
	} else {
		// validateCopyReplays has already checked the retained original PREPARE
		// context. Do not manufacture replay from a directory name alone.
		for _, replay := range a.s.CopyReplay {
			if name == "copy-"+string(replay.Intent) {
				r = replay
				break
			}
		}
	}
	i := a.s.Copy.Intents[r.Binding.Volume]
	if r.Action != CopyOperationProvision || r.Prior != nil || !a.matchCopyOperation(r) ||
		name != "copy-"+string(r.Intent) || i.ID != r.Intent || i.Owner != r.Binding || i.Epoch != r.Epoch ||
		i.Phase != CopyBound || !i.InitialCaptured || !validCopyDirectory(i.Transaction) {
		return ErrConflict
	}
	root := a.roots[r.Binding.Volume]
	if root == nil {
		return ErrConflict
	}
	if err := absent(root, copyTransactionName); err != nil {
		return err
	}
	private, err := volumeDirectory(a.j.dir, name)
	if err != nil {
		return err
	}
	defer private.Close()
	var st, parent unix.Stat_t
	if err = unix.Fstat(int(private.Fd()), &st); err != nil {
		return err
	}
	if err = unix.Fstat(int(a.j.dir.Fd()), &parent); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&07777 != 0700 || st.Uid != uint32(os.Geteuid()) ||
		st.Dev != parent.Dev || uint64(st.Dev) != r.Root.Device || uint64(st.Ino) != i.Transaction.Inode {
		return ErrConflict
	}
	// Provision has not published yet, so no manifest, staging or DATA children
	// can belong here. Read at most one entry; never delete or adopt its contents.
	entries, err := private.Readdirnames(1)
	if err != io.EOF || len(entries) != 0 {
		return ErrConflict
	}
	return exactChild(a.j.dir, name, RootIdentity{uint64(st.Dev), uint64(st.Ino)})
}

// Initial proof publication precedes any state-candidate IO or barrier. Only a
// complete standalone candidate bound to the exact prestate can be discarded;
// it never becomes a published proof, replay authority, or completion receipt.
func (a *Authority) validateLifecycleInitialTemporary(name string) error {
	if lifecycleTemporary(name, "prepare-retire-proof-") {
		raw, err := a.j.readLifecycleArtifact(name, maxRetirementProofBytes)
		if err != nil {
			return err
		}
		p, err := decodePrepareRetirementProof(raw)
		if err != nil {
			return err
		}
		if name != "prepare-retire-proof-"+string(p.Attempt)+".tmp" {
			return ErrConflict
		}
		return a.validatePrepareRetirementPredecessor(p)
	}
	raw, err := a.j.readLifecycleArtifact(name, maxCommitProofBytes)
	if err != nil {
		return err
	}
	p, err := decodeCommitProof(raw)
	if err != nil {
		return err
	}
	prior, err := a.j.stateDigest()
	if err != nil {
		return err
	}
	if p.Ready || p.Prior != prior || p.Prior == "" || p.Prior == p.Next ||
		p.Store != a.s.Store.ID || p.Epoch != a.s.Epoch || a.s.Revision == ^uint64(0) || p.Revision != a.s.Revision+1 {
		return ErrConflict
	}
	return nil
}

// A complete unpublished candidate above the exact retry-only proof is removable,
// not promotable. Its entire hypothetical next image must be the selected receipt
// and revision only. The actual predecessor stays RETIRING/PENDING without receipt.
func (a *Authority) validateLifecyclePrepareCompletionTemporary(name string) error {
	prior := a.j.rootOnly // already checked against canonical state and all roots
	if prior == nil || a.s.Revision == ^uint64(0) {
		return ErrConflict
	}
	raw, err := a.j.readLifecycleArtifact(name, maxRetirementProofBytes)
	if err != nil {
		return err
	}
	candidate, err := decodeRetirementProof(raw)
	if err != nil {
		return err
	}
	if name != "prepare-retire-complete-"+string(candidate.Attempt)+".tmp" {
		return ErrConflict
	}
	next := a.clone()
	next.Revision++
	expected := retirementProof{retirementProofVersion, candidate.Attempt, prior.Store, prior.Epoch,
		prior.Controller, prior.Bootstrap, prior.Volume, prior.Binding, prior.Operation,
		next.Revision, prior.Prior, ""}
	rec := next.Attachments[prior.Binding.Attachment]
	receipt := expected.receipt()
	rec.Phase, rec.Receipt = Drained, &receipt
	next.Attachments[prior.Binding.Attachment] = rec
	encoded, err := json.Marshal(next)
	if err != nil {
		return err
	}
	expected.Next = contentDigest(encoded)
	if *candidate != expected {
		return ErrConflict
	}
	return nil
}

func lifecycleTemporary(name, prefix string) bool {
	return strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".tmp") &&
		validID(ID(strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".tmp")))
}

func (j *journal) readLifecycleArtifact(name string, limit int64) ([]byte, error) {
	f, err := child(j.dir, name, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var st, parent unix.Stat_t
	if err = unix.Fstat(int(f.Fd()), &st); err != nil {
		return nil, err
	}
	if err = unix.Fstat(int(j.dir.Fd()), &parent); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0077 != 0 || st.Uid != uint32(os.Geteuid()) ||
		st.Nlink != 1 || st.Dev != parent.Dev || st.Size <= 0 || st.Size > limit {
		return nil, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != st.Size {
		return nil, ErrInvalid
	}
	return raw, nil
}

func (j *journal) clearLifecycleTemporaries(names []string) error {
	for _, name := range names {
		if err := j.step("recover-lifecycle-temporary-unlink", func() error {
			return unix.Unlinkat(int(j.dir.Fd()), name, 0)
		}); err != nil {
			j.quarantine()
			return fmt.Errorf("%w: %v", ErrRepairRequired, err)
		}
		if err := j.step("recover-lifecycle-temporary-sync", j.dir.Sync); err != nil {
			j.quarantine()
			return fmt.Errorf("%w: %v", ErrRepairRequired, err)
		}
	}
	return nil
}

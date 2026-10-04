//go:build linux

package supervisor

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"dev.cengine/guest/internal/protocol"
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// Invocation-local fake sideband. Copy and Bound-recovery filesystem operations
// remain real. Sealed rollback is response-only: this fixture does not implement
// the service-owned rollback algorithm or its cleanup.
type managedCopyFixture struct {
	copy           *managedCopy
	base           string
	intent         a.CopyIntent
	calls          []w.PrepareAction
	requests       []w.PrepareRequest
	rollbackReply  *w.PrepareReply
	failure        map[w.PrepareAction]error
	identities     map[string]a.Ext4ObjectV1
	identityErrors map[string]error
	cleanupEntries []managedCopyEntry
}

var errManagedRollbackUnconfigured = errors.New("fixture RollbackCopy response not configured")

func managedTestObject(inode uint64, generation, kind uint32) a.Ext4ObjectV1 {
	v := a.Ext4ObjectV1{Inode: inode, Generation: generation, FileType: kind, HandleType: 1, HandleSize: 8}
	binary.LittleEndian.PutUint32(v.Handle[:4], uint32(inode))
	binary.LittleEndian.PutUint32(v.Handle[4:], generation)
	return v
}
func newManagedCopyFixture(t *testing.T) *managedCopyFixture {
	t.Helper()
	base := t.TempDir()
	fd, err := unix.Open(base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	id := func() string {
		value, err := a.NewID()
		if err != nil {
			t.Fatal(err)
		}
		return string(value)
	}
	scope := managedCopyScope{Store: id(), Volume: id(), Prepare: id(), Attachment: id()}
	physical := a.CopyRootV1{Store: a.ID(scope.Store), Volume: a.ID(scope.Volume), BackingUUID: [16]byte{1}, Root: managedTestObject(10, 1, unix.S_IFDIR)}
	intent := a.CopyIntent{ID: a.ID(id()), Epoch: a.ID(id()), Root: physical, Owner: a.Binding{Store: physical.Store, Volume: physical.Volume, Prepare: a.ID(scope.Prepare), Attachment: a.ID(scope.Attachment), Role: a.PrepareRole, Mode: a.ReadWrite, Container: a.ContainerID(strings.Repeat("a", 64)), Launch: a.ID(id()), Key: a.Fingerprint(strings.Repeat("b", 64))}, Phase: a.CopyBegun}
	f := &managedCopyFixture{base: base, intent: intent, failure: map[w.PrepareAction]error{}, identities: map[string]a.Ext4ObjectV1{"": physical.Root}, identityErrors: map[string]error{}}
	f.copy = &managedCopy{root: &confinedRoot{fd: fd}, scope: scope, call: f.call}
	// A fresh BeginCopy intent must not carry initial metadata until the authority
	// captures it while binding the private transaction.
	return f
}
func managedFixtureMetadata(fd int) (a.CopyCleanupV1, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return a.CopyCleanupV1{}, err
	}
	return a.CopyCleanupV1{UID: st.Uid, GID: st.Gid, Mode: st.Mode & 07777, ATimeSeconds: st.Atim.Sec, ATimeNanos: uint32(st.Atim.Nsec), MTimeSeconds: st.Mtim.Sec, MTimeNanos: uint32(st.Mtim.Nsec)}, nil
}
func (f *managedCopyFixture) object(fd int, relative string) (a.Ext4ObjectV1, error) {
	if err := f.identityErrors[relative]; err != nil {
		return a.Ext4ObjectV1{}, err
	}
	var st unix.Stat_t
	name := relative
	if name == "" {
		name = "."
	}
	if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return a.Ext4ObjectV1{}, err
	}
	if identity, ok := f.identities[relative]; ok {
		return identity, nil
	}
	return managedTestObject(st.Ino&0xffffffff, 1, st.Mode&unix.S_IFMT), nil
}
func (f *managedCopyFixture) call(fd int, request w.PrepareRequest) (w.PrepareReply, error) {
	f.calls = append(f.calls, request.Action)
	f.requests = append(f.requests, request)
	// Exercise both real request and reply codecs, including Initial/Cleanup.
	raw, err := w.EncodePrepareIoctl(request)
	if err != nil {
		return w.PrepareReply{}, err
	}
	request, err = w.DecodePrepareIoctl(raw)
	if err != nil {
		return w.PrepareReply{}, err
	}
	if err := f.failure[request.Action]; err != nil {
		return w.PrepareReply{}, err
	}
	reply, err := f.dispatch(fd, request)
	if err != nil {
		return w.PrepareReply{}, err
	}
	raw, err = w.EncodePrepareIoctlReply(reply)
	if err != nil {
		return w.PrepareReply{}, err
	}
	reply, err = w.DecodePrepareIoctlReply(raw)
	if err != nil {
		return w.PrepareReply{}, err
	}
	return reply, w.ValidatePrepareReplyFor(request, reply)
}
func (f *managedCopyFixture) dispatch(fd int, request w.PrepareRequest) (w.PrepareReply, error) {
	fail := func(err error) (w.PrepareReply, error) { return w.PrepareReply{}, err }
	if request.Action != w.BeginCopy && (request.Intent != f.intent.ID || f.intent.Phase == a.CopyCompleted) {
		return fail(unix.EPERM)
	}
	transaction := filepath.Join(f.base, confinedCopyTransactionName)
	switch request.Action {
	case w.RollbackCopy:
		if f.rollbackReply == nil {
			return fail(errManagedRollbackUnconfigured)
		}
		return *f.rollbackReply, nil
	case w.BeginCopy:
		if f.intent.Phase == a.CopyCompleted {
			id, err := a.NewID()
			if err != nil {
				return fail(err)
			}
			f.intent.ID, f.intent.Phase = id, a.CopyBegun
			f.intent.Transaction, f.intent.ManifestDigest, f.intent.ManifestSize = a.Ext4ObjectV1{}, [32]byte{}, 0
			f.intent.Cleanup, f.intent.Initial, f.intent.InitialCaptured = a.CopyCleanupV1{}, a.CopyCleanupV1{}, false
		}
	case w.IdentityAt:
		identity, err := f.object(fd, string(request.Path))
		if err != nil {
			return fail(err)
		}
		return w.PrepareReply{Identity: identity, Intent: f.intent, Root: f.intent.Root}, nil
	case w.BindCopyTransaction:
		if f.intent.Phase == a.CopyBound && f.intent.InitialCaptured {
			identity, err := f.object(fd, confinedCopyTransactionName)
			if err != nil || identity != f.intent.Transaction {
				return fail(unix.ESTALE)
			}
			break
		}
		if f.intent.Phase != a.CopyBegun {
			return fail(unix.EPERM)
		}
		if _, err := os.Lstat(transaction); !errors.Is(err, os.ErrNotExist) {
			return fail(unix.EEXIST)
		}
		initial, err := managedFixtureMetadata(fd)
		if err != nil {
			return fail(err)
		}
		private, err := os.MkdirTemp(filepath.Dir(f.base), ".private-copy-")
		if err != nil {
			return fail(err)
		}
		defer os.Remove(private)
		var st unix.Stat_t
		if err := unix.Stat(private, &st); err != nil {
			return fail(err)
		}
		// Model durable binding before the atomic public-name publication.
		f.intent.Initial, f.intent.Transaction, f.intent.Phase = initial, managedTestObject(st.Ino&0xffffffff, 1, unix.S_IFDIR), a.CopyBound
		f.intent.InitialCaptured = true
		if err := unix.Renameat2(unix.AT_FDCWD, private, fd, confinedCopyTransactionName, unix.RENAME_NOREPLACE); err != nil {
			return fail(err)
		}
		if err := syncConfinedDirectory(fd); err != nil {
			return fail(err)
		}
	case w.SealManifest, w.AuthenticateManifest:
		identity, err := f.object(fd, confinedCopyTransactionName)
		if err != nil {
			return fail(err)
		}
		if identity != f.intent.Transaction || identity == (a.Ext4ObjectV1{}) {
			return fail(unix.EPERM)
		}
		if request.Action == w.AuthenticateManifest && f.intent.Phase == a.CopyBound {
			break
		}
		raw, err := os.ReadFile(filepath.Join(transaction, confinedCopyManifestName))
		if err != nil {
			return fail(err)
		}
		if request.Action == w.SealManifest {
			if f.intent.Phase != a.CopyBound {
				return fail(unix.EPERM)
			}
			f.intent.ManifestDigest, f.intent.ManifestSize, f.intent.Phase = sha256.Sum256(raw), uint64(len(raw)), a.CopySealed
		} else if f.intent.Phase != a.CopySealed || sha256.Sum256(raw) != f.intent.ManifestDigest || uint64(len(raw)) != f.intent.ManifestSize {
			return fail(errors.New("authority digest mismatch"))
		}
	case w.StartCleanup:
		if f.intent.Phase != a.CopyBound && f.intent.Phase != a.CopySealed {
			return fail(unix.EPERM)
		}
		cleanup, err := managedFixtureMetadata(fd)
		if err != nil {
			return fail(err)
		}
		entries, err := f.copy.transactionSnapshot()
		if err != nil {
			return fail(err)
		}
		for _, entry := range entries {
			switch entry.Path {
			case confinedCopyTransactionName + "/" + confinedCopyManifestName:
				cleanup.Manifest = entry.Identity
			case confinedCopyTransactionName + "/" + confinedCopyStagingName:
				cleanup.Staging = entry.Identity
			}
		}
		f.cleanupEntries = entries
		f.intent.Cleanup, f.intent.Phase = cleanup, a.CopyCleaning
	case w.FinishCopy:
		if f.intent.Phase == a.CopyCleaning {
			// Authority-side deletion: preflight the whole remaining tree before
			// deleting anything, then restore the privately persisted root snapshot.
			for _, entry := range f.cleanupEntries {
				identity, err := f.object(fd, entry.Path)
				if errors.Is(err, unix.ENOENT) {
					continue
				}
				if err != nil {
					return fail(err)
				}
				if identity != entry.Identity {
					return fail(unix.ESTALE)
				}
			}
			for i := len(f.cleanupEntries) - 1; i >= 0; i-- {
				if err := os.Remove(filepath.Join(f.base, f.cleanupEntries[i].Path)); err != nil && !errors.Is(err, os.ErrNotExist) {
					return fail(err)
				}
			}
			metadata := f.intent.Cleanup
			if err := unix.Fchown(fd, int(metadata.UID), int(metadata.GID)); err != nil {
				return fail(err)
			}
			if err := unix.Fchmod(fd, metadata.Mode); err != nil {
				return fail(err)
			}
			if err := unix.UtimesNanoAt(fd, "", []unix.Timespec{{Sec: metadata.ATimeSeconds, Nsec: int64(metadata.ATimeNanos)}, {Sec: metadata.MTimeSeconds, Nsec: int64(metadata.MTimeNanos)}}, unix.AT_EMPTY_PATH); err != nil {
				return fail(err)
			}
		} else if f.intent.Phase != a.CopyBegun {
			return fail(unix.EPERM)
		}
		if _, err := os.Lstat(transaction); !errors.Is(err, os.ErrNotExist) {
			return fail(unix.EBUSY)
		}
		if err := syncConfinedDirectory(fd); err != nil {
			return fail(err)
		}
		f.intent.Phase = a.CopyCompleted
	default:
		return fail(unix.EINVAL)
	}
	return w.PrepareReply{Intent: f.intent, Root: f.intent.Root}, nil
}
func (f *managedCopyFixture) journal(t *testing.T) managedCopyManifest {
	t.Helper()
	if err := f.copy.control(w.BeginCopy); err != nil {
		t.Fatal(err)
	}
	if err := f.copy.control(w.BindCopyTransaction); err != nil {
		t.Fatal(err)
	}
	transaction := filepath.Join(f.base, confinedCopyTransactionName)
	if err := os.Mkdir(filepath.Join(transaction, confinedCopyStagingName), 0700); err != nil {
		t.Fatal(err)
	}
	metadata, err := confinedRootMetadata(f.copy.root.fd)
	if err != nil {
		t.Fatal(err)
	}
	manifest := managedCopyManifest{Version: 4, Intent: f.intent.ID, Physical: f.intent.Root, Root: &metadata, Entries: []managedCopyEntry{}}
	for i, name := range []string{"a", "z"} {
		if err := os.WriteFile(filepath.Join(f.base, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
		identity := managedTestObject(uint64(20+i), 2, unix.S_IFREG)
		f.identities[name] = identity
		manifest.Entries = append(manifest.Entries, managedCopyEntry{Path: name, Identity: identity})
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(transaction, confinedCopyManifestName), raw, 0600); err != nil {
		t.Fatal(err)
	}
	f.intent.ManifestDigest, f.intent.ManifestSize, f.intent.Phase = sha256.Sum256(raw), uint64(len(raw)), a.CopySealed
	f.copy.intent = f.intent
	return manifest
}

// These observation helpers never run in the fake dispatch. Explicit fixture paths
// cover published/private bytes and inode metadata, including absent IO-cut output.
// NOATIME keeps the observation itself from changing the root or file timestamps.
type managedRecoveryEntry struct {
	Stat unix.Stat_t
	Data string
}

func managedRecoveryEvidence(t *testing.T, f *managedCopyFixture, extra ...string) map[string]managedRecoveryEntry {
	t.Helper()
	tx := confinedCopyTransactionName
	paths := append([]string{".", "a", "z", tx, tx + "/" + confinedCopyStagingName,
		tx + "/" + confinedCopyManifestName, tx + "/" + confinedCopyManifestTemporary,
		tx + "/" + confinedCopyStagingName + "/a", tx + "/" + confinedCopyStagingName + "/z"}, extra...)
	result := make(map[string]managedRecoveryEntry)
	for _, name := range paths {
		var entry managedRecoveryEntry
		err := unix.Fstatat(f.copy.root.fd, name, &entry.Stat, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		managedCleanupMust(t, err)
		if entry.Stat.Mode&unix.S_IFMT == unix.S_IFREG {
			fd, err := unix.Openat(f.copy.root.fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NOATIME|unix.O_CLOEXEC, 0)
			managedCleanupMust(t, err)
			file := os.NewFile(uintptr(fd), name)
			raw, err := io.ReadAll(file)
			closeErr := file.Close()
			managedCleanupMust(t, errors.Join(err, closeErr))
			entry.Data = string(raw)
		}
		result[name] = entry
	}
	return result
}

// The reply models only the authority's returned metadata, not its filesystem
// work. Callers must not finish this fake transaction after adopting the reply.
func managedRollbackCleaningReply(t *testing.T, f *managedCopyFixture) w.PrepareReply {
	t.Helper()
	intent := f.copy.intent
	intent.Phase, intent.Cleanup = a.CopyCleaning, intent.Initial
	var err error
	intent.Cleanup.Manifest, err = f.object(f.copy.root.fd, confinedCopyTransactionName+"/"+confinedCopyManifestName)
	managedCleanupMust(t, err)
	intent.Cleanup.Staging, err = f.object(f.copy.root.fd, confinedCopyTransactionName+"/"+confinedCopyStagingName)
	managedCleanupMust(t, err)
	return w.PrepareReply{Intent: intent, Root: intent.Root}
}

func assertManagedRollbackDelegation(t *testing.T, f *managedCopyFixture, want a.CopyIntent, refusal error, extra ...string) {
	t.Helper()
	beforeIntent, authorityIntent := f.copy.intent, f.intent
	before := managedRecoveryEvidence(t, f, extra...)
	f.calls, f.requests = nil, nil
	recovered, err := f.copy.recover()
	if !recovered || !errors.Is(err, refusal) {
		t.Fatalf("rollback delegation: recovered=%v err=%v want=%v", recovered, err, refusal)
	}
	if refusal != nil && want != beforeIntent {
		t.Fatal("refusal assertion must retain original intent")
	}
	if f.copy.intent != want || f.intent != authorityIntent {
		t.Fatal("incorrect returned intent adoption or fake authority mutation", f.copy.intent)
	}
	// Exact requests exclude IdentityAt, AuthenticateManifest, StartCleanup and
	// FinishCopy, as well as duplicate RollbackCopy or a different intent ID.
	if !reflect.DeepEqual(f.calls, []w.PrepareAction{w.RollbackCopy}) ||
		!reflect.DeepEqual(f.requests, []w.PrepareRequest{{Action: w.RollbackCopy, Intent: beforeIntent.ID}}) {
		t.Fatal("sealed recovery did more than delegate current intent", f.requests)
	}
	if after := managedRecoveryEvidence(t, f, extra...); !reflect.DeepEqual(before, after) {
		t.Fatalf("supervisor changed local evidence: before=%+v after=%+v", before, after)
	}
}

func TestManagedV4SealedRecoveryRequiresConfiguredAuthorityResponse(t *testing.T) {
	f := newManagedCopyFixture(t)
	f.journal(t)
	assertManagedRollbackDelegation(t, f, f.copy.intent, errManagedRollbackUnconfigured)
}

func TestManagedV4RecoveryAuthorityRefusalRetainsWholeTransaction(t *testing.T) {
	for _, fault := range []string{"authentication", "late-identity", "wrong-physical", "missing-sealed", "legacy-v3"} {
		t.Run(fault, func(t *testing.T) {
			f := newManagedCopyFixture(t)
			f.journal(t)
			journal := filepath.Join(f.base, confinedCopyTransactionName, confinedCopyManifestName)
			if fault == "late-identity" {
				f.identityErrors["z"] = unix.EOPNOTSUPP
			}
			if fault == "wrong-physical" {
				f.copy.intent.Root.BackingUUID[0]++
			}
			if fault == "legacy-v3" {
				managedCleanupMust(t, os.WriteFile(journal, []byte(`{"version":3,"entries":[]}`), 0600))
			}
			if fault == "missing-sealed" {
				managedCleanupMust(t, os.Remove(journal))
			}
			// The service, not this fake, authenticates and preflights sealed data.
			// A distinct refusal prevents unsupported-dispatch EINVAL false positives.
			refusal := errors.New("authority refused " + fault)
			f.failure[w.RollbackCopy] = refusal
			assertManagedRollbackDelegation(t, f, f.copy.intent, refusal)
		})
	}
}

func TestManagedV4GenerationReplacementDelegatesWithoutLocalDeletion(t *testing.T) {
	f := newManagedCopyFixture(t)
	manifest := f.journal(t)
	old := manifest.Entries[1].Identity
	f.identities["z"] = managedTestObject(old.Inode, old.Generation+1, old.FileType)
	reply := managedRollbackCleaningReply(t, f)
	f.rollbackReply = &reply
	// Both matching and replacement publications stay untouched by the supervisor.
	// Production planner coverage lives in storagemanaged's rollback contract tests.
	assertManagedRollbackDelegation(t, f, reply.Intent, nil)
}
func TestManagedV4DeletionRechecksFullHandle(t *testing.T) {
	f := newManagedCopyFixture(t)
	manifest := f.journal(t)
	entry := manifest.Entries[0]
	state, err := f.copy.entryIdentity(entry.Path, entry.Identity)
	if err != nil || state != confinedManifestMatching {
		t.Fatal(state, err)
	}
	f.identities[entry.Path] = managedTestObject(entry.Identity.Inode, entry.Identity.Generation+1, entry.Identity.FileType)
	if err := f.copy.removeEntry(entry); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.base, entry.Path)); err != nil {
		t.Fatal("replacement removed during recheck", err)
	}
}
func TestManagedV4NonemptyUsesShortFenceAndFailedFinishPropagates(t *testing.T) {
	for _, fail := range []bool{false, true} {
		f := newManagedCopyFixture(t)
		if err := os.WriteFile(filepath.Join(f.base, "data"), []byte("owned"), 0600); err != nil {
			t.Fatal(err)
		}
		if fail {
			f.failure[w.FinishCopy] = unix.EIO
		}
		err := f.copy.initialize("/absent-rootfs", protocol.Mount{Destination: "/seed"})
		if (err != nil) != fail {
			t.Fatal("finish error lost", err)
		}
		if len(f.calls) == 0 || f.calls[0] != w.BeginCopy || f.calls[len(f.calls)-1] != w.FinishCopy {
			t.Fatal("wrong fence order", f.calls)
		}
		for _, action := range f.calls {
			if action == w.BindCopyTransaction || action == w.SealManifest {
				t.Fatal("nonempty volume was mutated")
			}
		}
	}
}
func TestManagedV4MissingManifestRequiresOwnedBinding(t *testing.T) {
	for _, owned := range []bool{false, true} {
		f := newManagedCopyFixture(t)
		if err := os.Mkdir(filepath.Join(f.base, confinedCopyTransactionName), 0700); err != nil {
			t.Fatal(err)
		}
		f.intent.Phase = a.CopyBound
		if owned {
			f.intent.Transaction = managedTestObject(11, 1, unix.S_IFDIR)
			f.identities[confinedCopyTransactionName] = f.intent.Transaction
		}
		f.copy.intent = f.intent
		_, err := f.copy.recover()
		if (err == nil) != owned {
			t.Fatal("unbound cleanup authorization", err)
		}
	}
}
func TestManagedV4UnsupportedIdentityNeverMeansReplacement(t *testing.T) {
	f := newManagedCopyFixture(t)
	if err := f.copy.control(w.BeginCopy); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.base, "bad"), []byte("retained"), 0600); err != nil {
		t.Fatal(err)
	}
	expected := managedTestObject(20, 2, unix.S_IFREG)
	f.identities["bad"] = a.Ext4ObjectV1{Inode: expected.Inode, HandleSize: 7}
	state, err := f.copy.entryIdentity("bad", expected)
	if err == nil || state != confinedManifestUncertain {
		t.Fatal("malformed identity accepted as replacement")
	}
}

package storageauthority

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

// Include all entry names, modes and regular-file bytes, not just state.json.
func resumeAdmissionContents(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	must(t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		var data []byte
		if info.Mode().IsRegular() {
			data, err = os.ReadFile(path)
		} else if info.Mode()&os.ModeSymlink != 0 {
			var target string
			target, err = os.Readlink(path)
			data = []byte(target)
		}
		out[path] = fmt.Sprintf("%v:%s", info.Mode(), data)
		return err
	}))
	return out
}

func checkResumeAdmission(t *testing.T, f *fixture, signed SignedLifecycleResumeOpen, accept bool) error {
	t.Helper()
	before := resumeAdmissionContents(t, f.path)
	// These callbacks must never run, even on otherwise recoverable evidence.
	f.c.Barrier = func(Binding, *os.File) error { t.Fatal("barrier invoked"); return nil }
	f.c.CopyRecoveryPreflight = func(*os.File, string, string, CopyIntent) error {
		t.Fatal("recovery invoked")
		return nil
	}
	err := AdmitLifecycleResumeReadOnly(f.c, signed)
	if (err == nil) != accept {
		t.Fatalf("admission error = %v, want accept %v", err, accept)
	}
	if !reflect.DeepEqual(before, resumeAdmissionContents(t, f.path)) {
		t.Fatal("read-only admission changed filesystem entries or bytes")
	}
	return err
}

func TestLifecycleResumeReadOnlyEmpty(t *testing.T) {
	for _, volumes := range []bool{false, true} {
		for _, lostFound := range []bool{false, true} {
			t.Run(fmt.Sprintf("volumes=%v/lost+found=%v", volumes, lostFound), func(t *testing.T) {
				f := newResumeLayoutFixture(t, volumes, lostFound)
				original := LifecycleGrant{LifecycleInitialize, mustID(t), LifecycleIdentity{mustID(t), 7, fp(t, newKey(t))}, 11, 0, fp(t, newKey(t))}
				r := resumeRequest(t, f.bootstrap, original, fp(t, newKey(t)))
				checkResumeAdmission(t, f, signResume(t, f.bootstrap, r), true)
			})
		}
	}
}

func TestLifecycleResumeReadOnlyGenesis(t *testing.T) {
	f, original := resumeGenesisFixture(t)
	r := resumeRequest(t, f.bootstrap, original, fp(t, newKey(t)))
	signed := signResume(t, f.bootstrap, r)
	wantErr(t, checkResumeAdmission(t, f, signed, false), ErrLocked)
	must(t, f.a.Close())
	checkResumeAdmission(t, f, signed, true)
	// Successful admission releases the journal lock and remains non-consuming.
	checkResumeAdmission(t, f, signed, true)
	c, err := configured(f.c)
	must(t, err)
	j, err := probeJournal(c)
	must(t, err)
	defer j.close()
	flags, err := unix.FcntlInt(j.lock.Fd(), unix.F_GETFL, 0)
	must(t, err)
	if flags&unix.O_ACCMODE != unix.O_RDONLY {
		t.Fatal("probe opened a writable journal lock")
	}
}

func TestLifecycleResumeReadOnlyRejects(t *testing.T) {
	for _, name := range []string{
		"malformed", "semantic-invalid", "foreign-store", "foreign-bootstrap",
		"foreign-device", "foreign-root", "foreign-exports", "foreign-lifecycle",
		"advanced", "missing-state", "missing-lock", "missing-volumes", "partial-registry",
		"uncertain", "temporary", "root-stray", "nonempty-volumes", "replayed",
	} {
		t.Run(name, func(t *testing.T) {
			f, original := resumeGenesisFixture(t)
			must(t, f.a.Close())
			r := resumeRequest(t, f.bootstrap, original, fp(t, newKey(t)))
			signed := signResume(t, f.bootstrap, r)
			statePath := filepath.Join(f.path, registryName, stateName)
			mutate := func(fn func(*diskState)) {
				raw, err := os.ReadFile(statePath)
				must(t, err)
				var s diskState
				must(t, json.Unmarshal(raw, &s))
				fn(&s)
				raw, err = json.Marshal(s)
				must(t, err)
				must(t, os.WriteFile(statePath, raw, 0600))
			}
			switch name {
			case "malformed":
				must(t, os.WriteFile(statePath, []byte("{"), 0600))
			case "semantic-invalid":
				mutate(func(s *diskState) { s.Epoch = "invalid"; s.Lifecycle.Latest.ServiceEpoch = s.Epoch })
			case "foreign-store":
				mutate(func(s *diskState) { s.Store.ID = mustID(t) })
			case "foreign-bootstrap":
				mutate(func(s *diskState) { s.Bootstrap = fp(t, newKey(t)) })
			case "foreign-device":
				f.c.DeviceID += "-foreign"
			case "foreign-root":
				mutate(func(s *diskState) { s.Store.Root.Inode++ })
			case "foreign-exports":
				mutate(func(s *diskState) { s.Store.Exports.Inode++ })
			case "foreign-lifecycle":
				r.Original.Identity.Generation++
				r.Takeover.Grant.Identity = r.Original.Identity
				r.Takeover = signLifecycle(t, f.bootstrap, r.Takeover.Grant)
				signed = signResume(t, f.bootstrap, r)
			case "advanced":
				mutate(func(s *diskState) { s.Revision++ })
			case "missing-state":
				must(t, os.Remove(statePath))
			case "missing-lock":
				must(t, os.Remove(filepath.Join(f.path, registryName, "lock")))
			case "missing-volumes":
				must(t, os.Remove(filepath.Join(f.path, "volumes")))
			case "partial-registry":
				must(t, os.Remove(statePath))
				must(t, os.Remove(filepath.Join(f.path, registryName, "lock")))
			case "uncertain":
				must(t, os.WriteFile(filepath.Join(f.path, registryName, commitProofName), []byte("evidence"), 0600))
			case "temporary":
				must(t, os.WriteFile(filepath.Join(f.path, registryName, "state-"+string(mustID(t))+".tmp"), []byte("evidence"), 0600))
			case "root-stray":
				must(t, os.WriteFile(filepath.Join(f.path, "stray"), []byte("evidence"), 0600))
			case "nonempty-volumes":
				must(t, os.WriteFile(filepath.Join(f.path, "volumes", "data"), []byte("evidence"), 0600))
			case "replayed":
				a, err := ResumeOpenAndTakeover(f.c, signed)
				must(t, err)
				must(t, a.Close())
			}
			err := checkResumeAdmission(t, f, signed, false)
			if name == "replayed" {
				wantErr(t, err, ErrLifecycleResumeAlreadyApplied)
			}
		})
	}
}

func TestLifecycleResumeReadOnlySignatures(t *testing.T) {
	for _, name := range []string{"outer", "inner", "wrong-root", "original-key-alias", "takeover-key-alias", "tampered-original"} {
		t.Run(name, func(t *testing.T) {
			// Keep the journal locked: signature rejection must precede its probe.
			f, original := resumeGenesisFixture(t)
			r := resumeRequest(t, f.bootstrap, original, fp(t, newKey(t)))
			signed := signResume(t, f.bootstrap, r)
			switch name {
			case "outer":
				signed.Signature[0] ^= 1
			case "inner":
				r.Takeover.Signature[0] ^= 1
				signed = signResume(t, f.bootstrap, r)
			case "wrong-root":
				signed = signResume(t, newKey(t), r)
			case "original-key-alias":
				r.Original.NewKey = fp(t, f.bootstrap)
				signed = signResume(t, f.bootstrap, r)
			case "takeover-key-alias":
				r.Takeover.Grant.NewKey = fp(t, f.bootstrap)
				r.Takeover = signLifecycle(t, f.bootstrap, r.Takeover.Grant)
				signed = signResume(t, f.bootstrap, r)
			case "tampered-original":
				signed.Request.Original.NewKey = fp(t, newKey(t))
			}
			wantErr(t, checkResumeAdmission(t, f, signed, false), ErrUnauthorized)
		})
	}
}

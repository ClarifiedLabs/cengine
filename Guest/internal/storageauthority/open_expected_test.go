package storageauthority

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func expectedStartup(f *fixture) ExpectedStartup {
	return ExpectedStartup{Store: f.a.s.Store.ID, Epoch: f.a.s.Epoch, Controller: f.a.s.Controller}
}

// Compare every journal entry, not just the decoded revision: a refused open
// must not rewrite state, add a temporary file, or create an uncertainty marker.
func journalContents(t *testing.T, path string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(path)
	must(t, err)
	contents := map[string]string{}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(path, entry.Name()))
		must(t, err)
		contents[entry.Name()] = string(data)
	}
	return contents
}

func assertJournalContents(t *testing.T, path string, before map[string]string) {
	t.Helper()
	if after := journalContents(t, path); !reflect.DeepEqual(before, after) {
		t.Fatal("refused startup changed journal contents or entries")
	}
}

func TestOpenExpectedMismatchLeavesJournalIdentical(t *testing.T) {
	for _, field := range []string{"store", "epoch", "controller", "key"} {
		t.Run(field, func(t *testing.T) {
			f := newFixture(t, nil)
			expected := expectedStartup(f)
			wrong := expected
			switch field {
			case "store":
				wrong.Store = mustID(t)
			case "epoch":
				wrong.Epoch = mustID(t)
			case "controller":
				wrong.Controller.Epoch++
			case "key":
				wrong.Controller.Key = fp(t, newKey(t))
			}
			must(t, f.a.Close())
			path := filepath.Join(f.path, registryName)
			before := journalContents(t, path)
			got, err := f.openExpected(wrong)
			wantErr(t, err, ErrConflict)
			if got != nil {
				t.Fatal("mismatch returned authority")
			}
			assertJournalContents(t, path, before)
			// Failure releases the flock, and only this exact intent advances E.
			reopened, err := f.openExpected(expected)
			must(t, err)
			defer reopened.Close()
			if reopened.s.Revision != f.a.s.Revision+1 || reopened.Epoch() == expected.Epoch {
				t.Fatal("mismatch consumed an epoch/revision")
			}
		})
	}
}

func TestOpenExpectedInvalidShapeBeforeJournalOpen(t *testing.T) {
	f := newFixture(t, nil) // predecessor retains the real journal flock
	good := expectedStartup(f)
	path := filepath.Join(f.path, registryName)
	before := journalContents(t, path)
	for name, mutate := range map[string]func(*ExpectedStartup){
		"empty-store":     func(e *ExpectedStartup) { e.Store = "" },
		"uppercase-store": func(e *ExpectedStartup) { e.Store = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA" },
		"empty-epoch":     func(e *ExpectedStartup) { e.Epoch = "" },
		"non-v4-epoch":    func(e *ExpectedStartup) { e.Epoch = "aaaaaaaa-aaaa-1aaa-8aaa-aaaaaaaaaaaa" },
		"zero-controller": func(e *ExpectedStartup) { e.Controller.Epoch = 0 },
		"empty-key":       func(e *ExpectedStartup) { e.Controller.Key = "" },
		"uppercase-key":   func(e *ExpectedStartup) { e.Controller.Key = Fingerprint(strings.Repeat("A", 64)) },
	} {
		t.Run(name, func(t *testing.T) {
			e := good
			mutate(&e)
			got, err := f.openExpected(e)
			wantErr(t, err, ErrInvalid) // not ErrLocked: no journal open
			if got != nil {
				t.Fatal("malformed startup returned authority")
			}
			assertJournalContents(t, path, before)
		})
	}
}

func TestOpenExpectedHeldPredecessorFlockRefuses(t *testing.T) {
	f := newFixture(t, nil)
	expected := expectedStartup(f)
	path := filepath.Join(f.path, registryName)
	before := journalContents(t, path)
	got, err := f.openExpected(expected)
	wantErr(t, err, ErrLocked)
	if got != nil {
		t.Fatal("adopted held predecessor")
	}
	assertJournalContents(t, path, before)
	must(t, f.a.Close())
	// Also exercise an independently opened real flock, not an Authority flag.
	lock, err := os.OpenFile(filepath.Join(path, "lock"), os.O_RDWR, 0)
	must(t, err)
	defer lock.Close()
	must(t, unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB))
	_, err = f.openExpected(expected)
	wantErr(t, err, ErrLocked)
	assertJournalContents(t, path, before)
}

func TestOpenExpectedSuccessOnlyAdvancesEpochAndFences(t *testing.T) {
	barriers := 0
	f := newFixture(t, func(Binding, *os.File) error { barriers++; return nil })
	v1, v2, v3 := f.volume("active"), f.volume("reserved"), f.volume("drained")
	active, _ := f.runtime(v1, ReadWrite)
	prepare := mustID(t)
	reserved, _ := f.binding(v2, PrepareRole, ReadWrite, prepare)
	must(t, f.a.ReservePrepare(f.control, ReserveRequest{mustID(t), prepare, []Binding{reserved}}))
	drained, _ := f.runtime(v3, ReadWrite)
	f.retire(drained)
	beforeBarriers := barriers
	expected, before := expectedStartup(f), f.a.clone()
	must(t, f.a.Close())
	reopened, err := f.openExpected(expected)
	must(t, err)
	defer reopened.Close()
	if reopened.Epoch() == before.Epoch || !validID(reopened.Epoch()) {
		t.Fatal("service epoch did not rotate")
	}
	before.Epoch = reopened.Epoch()
	before.Revision++
	before.Lifecycle.OpenRevision = before.Revision
	for _, b := range []Binding{active, reserved} {
		rec := before.Attachments[b.Attachment]
		rec.Phase = Retiring
		before.Attachments[b.Attachment] = rec
	}
	if !reflect.DeepEqual(before, reopened.s) || barriers != beforeBarriers {
		t.Fatal("startup changed evidence beyond E/revision and ACTIVE/RESERVED fencing")
	}
	must(t, reopened.Close())
	path := filepath.Join(f.path, registryName)
	bytes := journalContents(t, path)
	_, err = f.openExpected(expected)
	wantErr(t, err, ErrConflict) // consumed predecessor cannot be replayed
	assertJournalContents(t, path, bytes)
}

func TestOpenExpectedMissingNeverInitializes(t *testing.T) {
	for _, missing := range []string{"registry", "lock", "state"} {
		t.Run(missing, func(t *testing.T) {
			f := newFixture(t, nil)
			expected := expectedStartup(f)
			must(t, f.a.Close())
			path := filepath.Join(f.path, registryName)
			target := path
			if missing == "lock" {
				target = filepath.Join(path, "lock")
			} else if missing == "state" {
				target = filepath.Join(path, stateName)
			}
			must(t, os.RemoveAll(target))
			_, err := f.openExpected(expected)
			wantErr(t, err, ErrMissing)
			if _, err := os.Stat(target); !os.IsNotExist(err) {
				t.Fatal("missing state recreated", err)
			}
		})
	}
}

func TestOpenExpectedUncertaintyLeavesJournalIdentical(t *testing.T) {
	for _, marker := range []string{pendingName, barrierName, dataIOName} {
		t.Run(marker, func(t *testing.T) {
			f := newFixture(t, nil)
			expected := expectedStartup(f)
			must(t, f.a.Close())
			path := filepath.Join(f.path, registryName)
			must(t, os.WriteFile(filepath.Join(path, marker), []byte("retained uncertainty"), 0600))
			before := journalContents(t, path)
			_, err := f.openExpected(expected)
			wantErr(t, err, ErrRepairRequired)
			assertJournalContents(t, path, before)
		})
	}
}

func TestOpenExpectedUnresolvedVolumeRequiresRepair(t *testing.T) {
	for _, phase := range []VolumePhase{VolumeCreating, VolumeDeleting} {
		t.Run(string(phase), func(t *testing.T) {
			f := newFixture(t, nil)
			v := f.volume("pending")
			next := f.a.clone()
			op := mustID(t)
			if phase == VolumeCreating {
				v.Root = RootIdentity{}
				next.Volumes[v.ID] = v
				next.VolumeLifecycles[v.ID] = VolumeLifecycle{Phase: phase, Create: op}
				next.Operations[op] = digest("create-volume", CreateVolumeRequest{op, next.Store.ID, v.ID, v.Name})
			} else {
				next.VolumeLifecycles[v.ID] = VolumeLifecycle{Phase: phase, Delete: op}
				next.Operations[op] = digest("delete-volume", DeleteVolumeRequest{op, next.Store.ID, v.ID})
			}
			must(t, f.a.commit(next)) // valid durable intent without a terminal receipt
			must(t, f.a.validate())
			expected := expectedStartup(f)
			must(t, f.a.Close())
			path := filepath.Join(f.path, registryName)
			before := journalContents(t, path)
			_, err := f.openExpected(expected)
			wantErr(t, err, ErrRepairRequired)
			assertJournalContents(t, path, before)
		})
	}
}

func TestOpenExpectedValidatesStateBeforeComparison(t *testing.T) {
	f := newFixture(t, nil)
	expected := expectedStartup(f)
	expected.Store = mustID(t)
	state := f.a.clone()
	state.Revision = 0 // canonical JSON, invalid semantic state
	must(t, f.a.Close())
	path := filepath.Join(f.path, registryName)
	data, err := json.Marshal(state)
	must(t, err)
	must(t, os.WriteFile(filepath.Join(path, stateName), data, 0600))
	before := journalContents(t, path)
	_, err = f.openExpected(expected)
	wantErr(t, err, ErrInvalid)
	assertJournalContents(t, path, before)
}

func TestOpenExpectedPersistFailureReturnsNoAuthority(t *testing.T) {
	const childEnv = "CENGINE_OPEN_EXPECTED_PERSIST_CHILD"
	if os.Getenv(childEnv) == "1" {
		if os.Getuid() != 65534 || os.Geteuid() != 65534 || os.Getgid() != 65534 || os.Getegid() != 65534 {
			t.Fatal("kernel did not drop child uid/gid")
		}
		groups, err := os.Getgroups()
		must(t, err)
		if len(groups) != 0 {
			t.Fatal("unexpected child supplementary groups")
		}
	} else if os.Geteuid() == 0 {
		if runtime.GOOS != "linux" {
			t.Fatalf("root persistence-denial subprocess unsupported on %s", runtime.GOOS)
		}
		// Pin both paths: the child cannot traverse the root runner's private
		// directories. The parent retains cleanup ownership even on timeout.
		temp, err := os.Open(t.TempDir())
		must(t, err)
		defer temp.Close()
		must(t, temp.Chown(65534, 65534))
		executable, err := os.Open("/proc/self/exe")
		must(t, err)
		defer executable.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "/proc/self/fd/4", "-test.run=^TestOpenExpectedPersistFailureReturnsNoAuthority$", "-test.count=1", "-test.v")
		command.ExtraFiles = []*os.File{temp, executable}
		command.Env = []string{childEnv + "=1", "TMPDIR=/proc/self/fd/3", "GORACE=atexit_sleep_ms=0"}
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
		// CombinedOutput waits/reaps this exact child, including cancellation.
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("unprivileged persistence denial: %v\n%s", err, output)
		}
		t.Logf("unprivileged persistence denial:\n%s", output)
		return
	}
	f := newFixture(t, nil)
	expected := expectedStartup(f)
	must(t, f.a.Close())
	path := filepath.Join(f.path, registryName)
	before := journalContents(t, path)
	must(t, os.Chmod(path, 0500)) // real marker-open failure after load/validation
	defer os.Chmod(path, 0700)
	got, err := f.openExpected(expected)
	wantErr(t, err, ErrBlocked)
	wantErr(t, err, os.ErrPermission)
	if got != nil {
		t.Fatal("failed persistence returned an authority")
	}
	assertJournalContents(t, path, before)
}

func TestOpenExpectedAfterPersistFailureRequiresRepair(t *testing.T) {
	for _, boundary := range persistBoundaries {
		t.Run(boundary, func(t *testing.T) {
			f := newFixture(t, nil)
			expected := expectedStartup(f)
			f.a.j.fault = func(stage string) error {
				if stage == boundary {
					return unix.EIO
				}
				return nil
			}
			wantErr(t, f.a.commit(f.a.clone()), ErrBlocked)
			must(t, f.a.Close())
			path := filepath.Join(f.path, registryName)
			before := journalContents(t, path)
			_, err := f.openExpected(expected)
			wantErr(t, err, ErrRepairRequired)
			assertJournalContents(t, path, before)
		})
	}
}

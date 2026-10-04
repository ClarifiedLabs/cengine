package storageauthority

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Every IO edge of the proof-carrying metadata transaction, including both
// atomic certificate publications and the final namespace durability boundary.
var persistBoundaries = []string{
	"state-read-prior",
	"proof-open", "proof-write", "proof-sync", "proof-close", "proof-rename", "proof-parent-sync",
	"state-open", "state-write", "state-sync", "state-close",
	"proof-ready-open", "proof-ready-write", "proof-ready-sync", "proof-ready-close", "proof-ready-rename", "proof-ready-parent-sync",
	"state-rename", "state-parent-sync", "proof-unlink", "proof-clear-sync",
}

// abruptRecoveryOutcome classifies reopen behavior after a real abrupt exit at
// the given persist step edge. An exited process never rewrites the marker, so
// unlike injected faults some exits leave no marker at all.
func abruptRecoveryOutcome(edge, boundary string) string {
	switch boundary {
	case "state-read-prior":
		return "absent"
	case "state-rename":
		if edge == "before" {
			return "rollback"
		}
		return "landed"
	case "state-parent-sync", "proof-unlink", "proof-clear-sync":
		return "landed"
	case "barrier-unlink":
		// The receipt and complete retained-resource barrier are now certified;
		// the surviving completed marker can be safely discharged on Open.
		return "landed"
	case "barrier-clear-sync":
		// The unlink in the preceding step already removed the barrier marker;
		// only its directory sync remains, which same-host reopen cannot lose.
		return "landed"
	default:
		return "rollback" // no state publication yet; exact predecessor survives
	}
}

func TestPersistFailuresAreStickyAndRestartBlocked(t *testing.T) {
	for _, errno := range []error{unix.EIO, unix.ENOSPC} {
		for _, boundary := range persistBoundaries {
			t.Run(errno.Error()+"/"+boundary, func(t *testing.T) {
				f := newFixture(t, nil)
				v1, v2 := f.volume("first"), f.volume("second")
				p := mustID(t)
				b1, _ := f.binding(v1, PrepareRole, ReadWrite, p)
				b2, _ := f.binding(v2, PrepareRole, ReadWrite, p)
				fired := false
				f.a.j.fault = func(stage string) error {
					if stage == boundary && !fired {
						fired = true
						return errno
					}
					return nil
				}
				err := f.a.ReservePrepare(f.control, ReserveRequest{mustID(t), p, []Binding{b1, b2}})
				wantErr(t, err, ErrBlocked)
				wantErr(t, err, errno)
				if !fired {
					t.Fatal("unreached injection")
				}
				if len(f.a.s.Attachments) != 0 {
					t.Fatal("partial reservation became visible")
				}
				_, err = f.a.Query(f.control)
				wantErr(t, err, ErrBlocked)
				f.a.j.fault = nil
				must(t, f.a.Close())
				_, err = f.openCurrent()
				wantErr(t, err, ErrRepairRequired)
				if _, statErr := os.Stat(filepath.Join(f.path, registryName, quarantineName)); statErr != nil {
					t.Fatalf("known IO failure left no permanent quarantine marker: %v", statErr)
				}
			})
		}
	}
}

func TestRetirementIntentAndFinalReceiptFailuresNeverDrain(t *testing.T) {
	for _, errno := range []error{unix.EIO, unix.ENOSPC} {
		for _, phase := range []string{"intent", "receipt"} {
			for _, boundary := range persistBoundaries {
				t.Run(errno.Error()+"/"+phase+"/"+boundary, func(t *testing.T) {
					f := newFixture(t, nil)
					v := f.volume("data")
					b, p := f.runtime(v, ReadWrite)
					armed := phase == "intent"
					fired := false
					f.a.barrier = func(Binding, *os.File) error { armed = true; return nil }
					f.a.j.fault = func(stage string) error {
						if armed && !fired && stage == boundary {
							fired = true
							return errno
						}
						return nil
					}
					_, err := f.a.Retire(context.Background(), f.control, RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch})
					wantErr(t, err, ErrBlocked)
					wantErr(t, err, errno)
					if !fired {
						t.Fatal("unreached injection")
					}
					_, err = f.a.Admit(p, v.ID, true)
					wantErr(t, err, ErrBlocked)
					_, err = f.a.Query(f.control)
					wantErr(t, err, ErrBlocked)
					if f.a.s.Attachments[b.Attachment].Phase != Retiring {
						t.Fatal("memory-only drain escaped")
					}
					f.a.j.fault = nil
					must(t, f.a.Close())
					_, err = f.openCurrent()
					wantErr(t, err, ErrRepairRequired)
					if _, statErr := os.Stat(filepath.Join(f.path, registryName, quarantineName)); statErr != nil {
						t.Fatalf("known IO failure left no permanent quarantine marker: %v", statErr)
					}
				})
			}
		}
	}
}

func TestBarrierErrorsAndFinalAcknowledgmentFailure(t *testing.T) {
	for _, stage := range []string{"barrier-error", "barrier-panic", "barrier-unlink", "barrier-clear-sync"} {
		t.Run(stage, func(t *testing.T) {
			f := newFixture(t, nil)
			v := f.volume("data")
			b, _ := f.runtime(v, ReadWrite)
			f.a.barrier = func(Binding, *os.File) error {
				if stage == "barrier-panic" {
					panic("writeback failure")
				}
				if stage == "barrier-error" {
					return unix.EIO
				}
				return nil
			}
			f.a.j.fault = func(name string) error {
				if name == stage {
					return unix.ENOSPC
				}
				return nil
			}
			_, err := f.a.Retire(context.Background(), f.control, RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch})
			wantErr(t, err, ErrBlocked)
			_, err = f.a.Query(f.control)
			wantErr(t, err, ErrBlocked)
			must(t, f.a.Close())
			_, err = f.openCurrent()
			wantErr(t, err, ErrRepairRequired)
		})
	}
}

func TestExplicitInitializationLockIdentityAndMissingState(t *testing.T) {
	f := newFixture(t, nil)
	_, err := f.openCurrent()
	wantErr(t, err, ErrLocked)
	_, err = InitializeLifecycle(f.c, f.signedCurrent())
	if err == nil {
		t.Fatal("reinitialized registry")
	}
	v := f.volume("bound")
	must(t, f.a.Close())
	wrong := f.c
	wrong.DeviceID = "replacement-device"
	_, err = OpenLifecycleCurrent(wrong, f.signedCurrent())
	wantErr(t, err, ErrConflict)
	must(t, os.Rename(filepath.Join(f.path, "volumes", v.Name), filepath.Join(f.path, "volumes", "old")))
	must(t, os.Mkdir(filepath.Join(f.path, "volumes", v.Name), 0700))
	_, err = f.openCurrent()
	wantErr(t, err, ErrConflict)
	must(t, os.Remove(filepath.Join(f.path, registryName, stateName)))
	_, err = f.openCurrent()
	wantErr(t, err, ErrMissing)
	_, err = InitializeLifecycle(f.c, f.signedCurrent())
	if err == nil {
		t.Fatal("missing state silently reinitialized")
	}
}

func TestDescriptorConfinementAndInvalidJournal(t *testing.T) {
	t.Run("symlink-volume", func(t *testing.T) {
		f := newFixture(t, nil)
		external := t.TempDir()
		must(t, os.Symlink(external, filepath.Join(f.path, "volumes", "escape")))
		fd, err := os.Open(external)
		must(t, err)
		root, err := identity(fd)
		fd.Close()
		must(t, err)
		err = f.a.AddVolume(f.control, VolumeRequest{mustID(t), Volume{mustID(t), "escape", root}})
		if err == nil {
			t.Fatal("followed exported symlink")
		}
		err = f.a.AddVolume(f.control, VolumeRequest{mustID(t), Volume{mustID(t), "../escape", root}})
		wantErr(t, err, ErrInvalid)
	})
	t.Run("renamed-root", func(t *testing.T) {
		f := newFixture(t, nil)
		v := f.volume("retained")
		b, _ := f.runtime(v, ReadWrite)
		moved := f.path + "-moved"
		must(t, os.Rename(f.path, moved))
		t.Cleanup(func() { os.RemoveAll(moved) })
		f.a.barrier = func(_ Binding, fd *os.File) error {
			got, err := identity(fd)
			if err != nil {
				return err
			}
			if got != v.Root {
				return ErrConflict
			}
			return nil
		}
		f.retire(b)
	})
	for _, kind := range []string{"malformed", "schema", "dangling", "duplicate-json"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t, nil)
			v := f.volume("data")
			b, _ := f.runtime(v, ReadWrite)
			must(t, f.a.Close())
			path := filepath.Join(f.path, registryName, stateName)
			data, err := os.ReadFile(path)
			must(t, err)
			var s diskState
			must(t, json.Unmarshal(data, &s))
			switch kind {
			case "malformed":
				data = []byte("{")
			case "schema":
				s.Schema++
				data, err = json.Marshal(s)
			case "dangling":
				delete(s.Volumes, b.Volume)
				data, err = json.Marshal(s)
			case "duplicate-json":
				data = append([]byte(`{"schema":1,`), data[1:]...)
			}
			must(t, err)
			must(t, os.WriteFile(path, data, 0600))
			_, err = f.openCurrent()
			wantErr(t, err, ErrInvalid)
		})
	}
}

func TestLimitsDoNotEvictEvidenceAndUnknownIsNotDrained(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("limited")
	b, p := f.runtime(v, ReadWrite)
	f.a.limits.InFlight = 1
	guard, err := f.a.Admit(p, v.ID, true)
	must(t, err)
	_, err = f.a.Admit(p, v.ID, false)
	wantErr(t, err, ErrLimit)
	guard.Release()
	f.a.limits.Attachments = 1
	another, _ := f.binding(v, RuntimeRole, ReadWrite, "")
	wantErr(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), another}), ErrLimit)
	receipt := f.retire(b)
	wantErr(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), another}), ErrLimit)
	got, err := f.a.Retire(context.Background(), f.control, RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch})
	must(t, err)
	if got != receipt {
		t.Fatal("tombstone lost")
	}
	_, err = f.a.Retire(context.Background(), f.control, RetireRequest{mustID(t), b.Store, b.Volume, mustID(t), b.Launch})
	wantErr(t, err, ErrUnknown)
	if errors.Is(err, nil) {
		t.Fatal("unknown drained")
	}
}

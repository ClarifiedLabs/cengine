package storageauthority

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func createRequest(t *testing.T, f *fixture, name string) CreateVolumeRequest {
	return CreateVolumeRequest{mustID(t), f.a.s.Store.ID, mustID(t), name}
}
func TestVolumeLifecycleRecreateAndOldAuthority(t *testing.T) {
	f := newFixture(t, nil)
	req := createRequest(t, f, "data")
	created, err := f.a.CreateVolume(f.control, req)
	must(t, err)
	again, err := f.a.CreateVolume(f.control, req)
	must(t, err)
	if again != created {
		t.Fatal("unstable create receipt")
	}
	changed := req
	changed.Name = "other"
	_, err = f.a.CreateVolume(f.control, changed)
	wantErr(t, err, ErrConflict)
	b, peer := f.runtime(created.Volume, ReadWrite)
	del := DeleteVolumeRequest{mustID(t), req.Store, req.Volume}
	guard, err := f.a.Admit(peer, req.Volume, true)
	must(t, err)
	_, err = f.a.DeleteVolume(f.control, del)
	wantErr(t, err, ErrBusy)
	guard.Release()
	f.retire(b)
	path := filepath.Join(f.path, "volumes", req.Name)
	must(t, os.MkdirAll(filepath.Join(path, "nested", "deep"), 0700))
	must(t, os.WriteFile(filepath.Join(path, "nested", "file"), []byte("data"), 0600))
	outside := filepath.Join(t.TempDir(), "keep")
	must(t, os.WriteFile(outside, []byte("safe"), 0600))
	must(t, os.Symlink(filepath.Dir(outside), filepath.Join(path, "escape")))
	deleted, err := f.a.DeleteVolume(f.control, del)
	must(t, err)
	if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if _, err = os.Stat(outside); err != nil {
		t.Fatal(err)
	}
	must(t, f.a.Close())
	f.a, err = f.openCurrent()
	must(t, err)
	f.control = f.authControl(f.controllerKey, 1)
	if f.a.roots[req.Volume] != nil {
		t.Fatal("reopened deleted root")
	}
	again, err = f.a.DeleteVolume(f.control, del)
	must(t, err)
	if again != deleted {
		t.Fatal("unstable delete receipt")
	}
	recreated, err := f.a.CreateVolume(f.control, createRequest(t, f, req.Name))
	must(t, err)
	again, err = f.a.DeleteVolume(f.control, del)
	must(t, err)
	if again != deleted {
		t.Fatal("old delete affected replacement")
	}
	again, err = f.a.CreateVolume(f.control, req)
	must(t, err)
	if again != created {
		t.Fatal("old create changed")
	}
	_, err = f.a.Admit(peer, recreated.Volume.ID, true)
	wantErr(t, err, ErrUnauthorized)
	wantErr(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), b}), ErrBlocked)
	reused, _ := f.binding(recreated.Volume, RuntimeRole, ReadWrite, "")
	reused.Key = b.Key
	wantErr(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), reused}), ErrConflict)
	wantErr(t, f.a.AddVolume(f.control, VolumeRequest{mustID(t), created.Volume}), ErrConflict)
	reusedV := req
	reusedV.Operation = mustID(t)
	reusedV.Name = "different"
	_, err = f.a.CreateVolume(f.control, reusedV)
	wantErr(t, err, ErrConflict)
	must(t, f.a.validate())
	must(t, f.a.Close())
	f.a, err = f.openCurrent()
	must(t, err)
	f.control = f.authControl(f.controllerKey, 1)
	must(t, f.a.validate())
}

func TestVolumeLifecyclePendingPrepareAndEpochFence(t *testing.T) {
	f := newFixture(t, nil)
	req := createRequest(t, f, "prepared")
	_, err := f.a.CreateVolume(nil, req)
	wantErr(t, err, ErrUnauthorized)
	created, err := f.a.CreateVolume(f.control, req)
	must(t, err)
	prep := mustID(t)
	b, _ := f.binding(created.Volume, PrepareRole, ReadWrite, prep)
	must(t, f.a.ReservePrepare(f.control, ReserveRequest{mustID(t), prep, []Binding{b}}))
	del := DeleteVolumeRequest{mustID(t), req.Store, req.Volume}
	_, err = f.a.DeleteVolume(f.control, del)
	wantErr(t, err, ErrBusy)
	receipt := f.retire(b)
	_, err = f.a.DeleteVolume(f.control, del)
	wantErr(t, err, ErrBusy)
	must(t, f.a.CompletePrepare(f.control, CompleteRequest{mustID(t), prep, []Receipt{receipt}, Attestation{prep, true, true}}))
	old := f.control
	key := newKey(t)
	sp, err := f.a.AuthenticateSuccessor(context.Background(), f.conn(key, tls.VersionTLS13, true))
	must(t, err)
	grant := f.takeoverGrant(1, fp(t, key))
	_, err = f.a.TakeoverLifecycle(sp, signLifecycle(t, f.bootstrap, grant))
	must(t, err)
	_, err = f.a.CreateVolume(old, req)
	wantErr(t, err, ErrUnauthorized)
	_, err = f.a.DeleteVolume(old, del)
	wantErr(t, err, ErrUnauthorized)
	f.control = f.authControl(key, 2)
	_, err = f.a.DeleteVolume(f.control, del)
	must(t, err)
}

func TestVolumeLifecycleNameAndUnexpectedReplacement(t *testing.T) {
	for _, name := range []string{"", ".", "..", "../escape", "a/b", "a\x00b", strings.Repeat("x", 256), string([]byte{0xff})} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, nil)
			_, err := f.a.CreateVolume(f.control, createRequest(t, f, name))
			wantErr(t, err, ErrInvalid)
		})
	}
	f := newFixture(t, nil)
	req := createRequest(t, f, "deleted")
	_, err := f.a.CreateVolume(f.control, req)
	must(t, err)
	_, err = f.a.DeleteVolume(f.control, DeleteVolumeRequest{mustID(t), req.Store, req.Volume})
	must(t, err)
	must(t, f.a.Close())
	must(t, os.Mkdir(filepath.Join(f.path, "volumes", req.Name), 0700))
	_, err = f.openCurrent()
	wantErr(t, err, ErrConflict)
}

func TestVolumeLifecycleCompletionCapacity(t *testing.T) {
	f := newFixture(t, nil)
	req := createRequest(t, f, "capacity")
	projected := f.a.clone()
	projected.Revision++
	projected.Volumes[req.Volume] = Volume{ID: req.Volume, Name: req.Name}
	projected.VolumeLifecycles[req.Volume] = VolumeLifecycle{Phase: VolumeCreating, Create: req.Operation}
	projected.Operations[req.Operation] = digest("create-volume", req)
	limits := exactCapacity(t, projected)
	f.a.limits = limits
	got, err := f.a.CreateVolume(f.control, req)
	must(t, err)
	if got.Phase != VolumeReady {
		t.Fatal(got)
	}
	_, err = f.a.CreateVolume(f.control, req)
	must(t, err)
	// Deletion is allowed to reject BEFORE intent when its new operation cannot fit.
	_, err = f.a.DeleteVolume(f.control, DeleteVolumeRequest{mustID(t), req.Store, req.Volume})
	wantErr(t, err, ErrLimit)
	if f.a.fault != nil {
		t.Fatal("clean capacity rejection poisoned store")
	}
	del := DeleteVolumeRequest{mustID(t), req.Store, req.Volume}
	projected = f.a.clone()
	projected.Revision++
	life := projected.VolumeLifecycles[req.Volume]
	life.Phase, life.Delete = VolumeDeleting, del.Operation
	projected.VolumeLifecycles[req.Volume] = life
	projected.Operations[del.Operation] = digest("delete-volume", del)
	f.a.limits = exactCapacity(t, projected)
	_, err = f.a.DeleteVolume(f.control, del)
	must(t, err)
	_, err = f.a.DeleteVolume(f.control, del)
	must(t, err)
}

type shortWriter struct{}

func (shortWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }
func TestJournalRejectsShortWrite(t *testing.T) {
	wantErr(t, writeFull(shortWriter{}, []byte("abc")), io.ErrShortWrite)
}

func TestVolumeLifecycleFaults(t *testing.T) {
	for _, mode := range []string{"create", "delete"} {
		stages := []string{"volume-" + mode + "-before-intent", "volume-" + mode + "-intent", "volume-" + mode + "-parent-sync", "volume-" + mode + "-published"}
		if mode == "create" {
			stages = append(stages, "volume-mkdir", "volume-open", "volume-root-mode", "volume-root-sync")
		} else {
			stages = append(stages, "volume-unlink", "volume-directory-rewind", "volume-directory-sync", "volume-rmdir", "volume-root-close")
		}
		stages = append(stages, persistBoundaries...)
		for _, boundary := range persistBoundaries {
			stages = append(stages, "final:"+boundary)
		}
		for _, errno := range []error{unix.EIO, unix.ENOSPC, io.ErrShortWrite} {
			for _, stage := range stages {
				t.Run(mode+"/"+errno.Error()+"/"+stage, func(t *testing.T) {
					f := newFixture(t, nil)
					req := createRequest(t, f, "fault")
					if mode == "delete" {
						_, err := f.a.CreateVolume(f.control, req)
						must(t, err)
						must(t, os.WriteFile(filepath.Join(f.path, "volumes", req.Name, "file"), []byte("x"), 0600))
					}
					fired := false
					final := false
					f.a.j.afterStep = func(s string) {
						if s == "volume-"+mode+"-intent" {
							final = true
						}
					}
					f.a.j.fault = func(s string) error {
						target := strings.TrimPrefix(stage, "final:")
						armed := !strings.HasPrefix(stage, "final:") || final
						if s == target && armed && !fired {
							fired = true
							return errno
						}
						return nil
					}
					var err error
					if mode == "create" {
						_, err = f.a.CreateVolume(f.control, req)
					} else {
						_, err = f.a.DeleteVolume(f.control, DeleteVolumeRequest{mustID(t), req.Store, req.Volume})
					}
					wantErr(t, err, ErrBlocked)
					wantErr(t, err, errno)
					if !fired {
						t.Fatal("unreached fault")
					}
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

type volumeCrashManifest struct {
	Bootstrap ed25519.PublicKey
	Store     ID
	Create    CreateVolumeRequest
	Delete    DeleteVolumeRequest
	Current   SignedLifecycleGrant
	Expected  ExpectedLifecycleStartup
}

func TestVolumeCrashWorker(t *testing.T) {
	path := os.Getenv("CENGINE_VOLUME_CRASH_ROOT")
	if path == "" {
		return
	}
	f := newFixtureAt(t, nil, path)
	req := createRequest(t, f, "crash")
	del := DeleteVolumeRequest{mustID(t), req.Store, req.Volume}
	mode, edge := os.Getenv("CENGINE_VOLUME_CRASH_MODE"), os.Getenv("CENGINE_VOLUME_CRASH_EDGE")
	if mode == "delete" {
		_, err := f.a.CreateVolume(f.control, req)
		must(t, err)
		must(t, os.WriteFile(filepath.Join(path, "volumes", req.Name, "partial"), []byte("x"), 0600))
	}
	bytes, err := json.Marshal(volumeCrashManifest{f.c.BootstrapKey, req.Store, req, del, f.signedCurrent(), expectedLifecycleStartup(f)})
	must(t, err)
	writeCrashWitness(t, path, "volume-manifest.json", bytes)
	final := false
	f.a.j.afterStep = func(stage string) {
		if stage == "volume-"+mode+"-intent" {
			final = true
		}
		target := strings.TrimPrefix(edge, "final:")
		armed := !strings.HasPrefix(edge, "final:") || final
		if stage == target && armed {
			os.Exit(crashExit)
		}
	}
	if mode == "create" {
		_, err = f.a.CreateVolume(f.control, req)
	} else {
		_, err = f.a.DeleteVolume(f.control, del)
	}
	t.Fatalf("unreached crash: %v", err)
}
func TestVolumeLifecycleAbruptExit(t *testing.T) {
	for _, mode := range []string{"create", "delete"} {
		stages := []string{"volume-" + mode + "-before-intent", "volume-" + mode + "-intent", "volume-" + mode + "-parent-sync", "volume-" + mode + "-published"}
		if mode == "create" {
			stages = append(stages, "volume-mkdir", "volume-open", "volume-root-mode", "volume-root-sync")
		} else {
			stages = append(stages, "volume-unlink", "volume-directory-sync", "volume-rmdir", "volume-root-close")
		}
		for _, boundary := range persistBoundaries {
			if boundary != "state-read-prior" {
				stages = append(stages, "final:"+boundary)
			}
		}
		for _, edge := range stages {
			t.Run(mode+"/"+edge, func(t *testing.T) {
				path := t.TempDir()
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestVolumeCrashWorker$", "-test.count=1")
				cmd.Env = append(os.Environ(), "CENGINE_VOLUME_CRASH_ROOT="+path, "CENGINE_VOLUME_CRASH_MODE="+mode, "CENGINE_VOLUME_CRASH_EDGE="+edge, "GORACE=atexit_sleep_ms=0")
				out, err := cmd.CombinedOutput()
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != crashExit {
					t.Fatalf("%v: %s", err, out)
				}
				data, err := os.ReadFile(filepath.Join(path, "volume-manifest.json"))
				must(t, err)
				var m volumeCrashManifest
				must(t, json.Unmarshal(data, &m))
				root, err := os.Open(path)
				must(t, err)
				defer root.Close()
				open := func() (*Authority, error) {
					return OpenLifecycleExpected(Config{Root: root, DeviceID: "test-device-uuid", BootstrapKey: m.Bootstrap, Barrier: func(Binding, *os.File) error { return nil }}, m.Current, m.Expected)
				}
				terminal := strings.HasSuffix(edge, "-published")
				before := strings.HasSuffix(edge, "-before-intent")
				if strings.HasPrefix(edge, "final:") {
					switch abruptRecoveryOutcome("after", strings.TrimPrefix(edge, "final:")) {
					case "landed":
						terminal = true
					case "absent":
						before = true
					}
				}
				if !terminal && !before {
					// An incomplete volume lifecycle is neither a clean prestate nor
					// a proven terminal publication; retries must preserve its evidence.
					lifecycleCrashRefusesUnchanged(t, path, open, ErrRepairRequired)
					return
				}
				a, err := open()
				must(t, err)
				defer a.Close()
				// Internal principal only in crash recovery assertion; public auth
				// and current-controller checks are exercised above using TLS.
				p := &ControllerPrincipal{a, a.s.Controller.Epoch, a.s.Controller.Key}
				if terminal {
					if mode == "create" {
						r, err := a.CreateVolume(p, m.Create)
						must(t, err)
						if r.Phase != VolumeReady {
							t.Fatal(r)
						}
					} else {
						r, err := a.DeleteVolume(p, m.Delete)
						must(t, err)
						if r.Phase != VolumeDeleted {
							t.Fatal(r)
						}
					}
				} else if mode == "create" {
					_, err = a.CreateVolume(p, m.Create)
					must(t, err)
				} else {
					_, err = a.DeleteVolume(p, m.Delete)
					must(t, err)
				}
			})
		}
	}
}

func TestVolumeDeleteRewindsSharedRootOffset(t *testing.T) {
	f := newFixture(t, nil)
	req := createRequest(t, f, "enumerated")
	created, err := f.a.CreateVolume(f.control, req)
	must(t, err)
	b, peer := f.runtime(created.Volume, ReadWrite)
	must(t, os.WriteFile(filepath.Join(f.path, "volumes", req.Name, "keep-until-delete"), []byte("data"), 0600))
	guard, err := f.a.Admit(peer, req.Volume, false)
	must(t, err)
	dup, err := guard.DupVolumeRoot()
	must(t, err)
	names, err := dup.Readdirnames(-1)
	must(t, err)
	if len(names) != 1 {
		t.Fatal(names)
	}
	must(t, dup.Close())
	guard.Release()
	f.retire(b)
	_, err = f.a.DeleteVolume(f.control, DeleteVolumeRequest{mustID(t), req.Store, req.Volume})
	must(t, err)
}

func TestVolumeLifecycleSerializesSameControllerTransactions(t *testing.T) {
	f := newFixture(t, nil)
	req := createRequest(t, f, "serial")
	created, err := f.a.CreateVolume(f.control, req)
	must(t, err)
	b, _ := f.binding(created.Volume, RuntimeRole, ReadWrite, "")
	entered, resume := make(chan struct{}), make(chan struct{})
	f.a.j.afterStep = func(stage string) {
		if stage == "volume-delete-intent" {
			close(entered)
			<-resume
		}
	}
	deletion := make(chan error, 1)
	del := DeleteVolumeRequest{mustID(t), req.Store, req.Volume}
	go func() { _, err := f.a.DeleteVolume(f.control, del); deletion <- err }()
	await(t, entered)
	register := make(chan error, 1)
	reg := RegisterRequest{mustID(t), b}
	go func() { register <- f.a.RegisterAttachment(f.control, reg) }()
	select {
	case err := <-register:
		t.Fatalf("registration escaped transaction: %v", err)
	default:
	}
	close(resume)
	must(t, <-deletion)
	wantErr(t, <-register, ErrBlocked)
	must(t, f.a.validate())
}

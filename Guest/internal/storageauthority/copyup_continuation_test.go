//go:build linux || darwin

package storageauthority

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Real inode/device/type and real directory IO; only ext4 generation/handle
// acquisition is synthetic on the host. No ext4/VM runtime claim is made.
func hostCopyObject(fd int) (Ext4ObjectV1, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return Ext4ObjectV1{}, err
	}
	o := copyObject(uint64(st.Ino))
	o.FileType = uint32(st.Mode) & unix.S_IFMT
	return o, nil
}

func metadataAt(t *testing.T, f *os.File) CopyCleanupV1 {
	t.Helper()
	var st unix.Stat_t
	must(t, unix.Fstat(int(f.Fd()), &st))
	return copyInitialMetadata(&st)
}

func copySuccessor(t *testing.T, f *fixture, old Binding) *Guard {
	t.Helper()
	r := f.retire(old)
	p := mustID(t)
	b, k := f.binding(f.a.s.Volumes[old.Volume], PrepareRole, ReadWrite, p)
	must(t, f.a.ReplacePrepare(f.control, ReplaceRequest{mustID(t), old.Prepare, []Receipt{r}, ReserveRequest{mustID(t), p, []Binding{b}}}))
	must(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), b}))
	peer, err := f.a.AuthenticateData(context.Background(), f.conn(k, tls.VersionTLS13, true), DataHello{f.a.Epoch(), b})
	must(t, err)
	g, err := f.a.Admit(peer, b.Volume, true)
	must(t, err)
	t.Cleanup(g.Release)
	return g
}

func TestCopyContinuationProvisionAndForeignEvidence(t *testing.T) {
	for _, kind := range []string{"normal", "public-directory", "public-symlink", "private-before-initial", "bad-identity", "direct-bound"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t, nil)
			v := f.volume("provision")
			_, g := copyPrepare(t, f, v, ReadWrite)
			root := f.a.roots[v.ID]
			path := filepath.Join(f.path, "volumes", v.Name)
			must(t, os.Chtimes(path, time.Unix(17, 123456789), time.Unix(19, 987654321)))
			initial := metadataAt(t, root)
			i, err := g.BeginCopy(copyRoot(f, v))
			must(t, err)
			pub := filepath.Join(path, copyTransactionName)
			priv := filepath.Join(f.path, registryName, "copy-"+string(i.ID))
			switch kind {
			case "public-directory", "direct-bound":
				must(t, os.Mkdir(pub, 0700))
			case "public-symlink":
				must(t, os.Symlink(priv, pub))
			case "private-before-initial":
				must(t, os.Mkdir(priv, 0700))
			}
			if kind == "direct-bound" {
				fd, e := os.Open(pub)
				must(t, e)
				o, e := hostCopyObject(int(fd.Fd()))
				must(t, e)
				must(t, fd.Close())
				must(t, g.BindCopyTransaction(i.ID, o))
			}
			identify := hostCopyObject
			if kind == "bad-identity" {
				identify = func(int) (Ext4ObjectV1, error) { return copyObject(v.Root.Inode), nil }
			}
			got, err := g.ProvisionCopyTransaction(i.ID, identify)
			if kind != "normal" {
				if err == nil {
					t.Fatal("adopted foreign or forged evidence")
				}
				if kind == "bad-identity" {
					if f.a.s.Copy.Intents[v.ID].Phase != CopyBegun {
						t.Fatal("bad callback bound")
					}
					_, err = g.ProvisionCopyTransaction(i.ID, hostCopyObject)
					must(t, err)
				}
				return
			}
			must(t, err)
			if got.Phase != CopyBound || !got.InitialCaptured || got.Initial != initial {
				t.Fatal("missing original root metadata or binding")
			}
			if _, err = os.Lstat(priv); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("private entry retained", err)
			}
			fd, err := os.Open(pub)
			must(t, err)
			defer fd.Close()
			o, err := hostCopyObject(int(fd.Fd()))
			must(t, err)
			if got.Transaction != o {
				t.Fatal("not the real created object")
			}
			before := f.a.s.Revision
			again, err := g.ProvisionCopyTransaction(i.ID, hostCopyObject)
			must(t, err)
			if again != got || f.a.s.Revision != before {
				t.Fatal("replay changed durable identity or initial metadata")
			}
			must(t, os.Chmod(pub, 0755))
			_, err = g.ProvisionCopyTransaction(i.ID, hostCopyObject)
			wantErr(t, err, ErrConflict)
		})
	}
}

func TestCopyContinuationDigestCleanupValidationAndReplay(t *testing.T) {
	for _, sealed := range []bool{false, true} {
		t.Run(map[bool]string{false: "bound", true: "sealed"}[sealed], func(t *testing.T) {
			f := newFixture(t, nil)
			v := f.volume("cleanup")
			_, g := copyPrepare(t, f, v, ReadWrite)
			i, err := g.BeginCopy(copyRoot(f, v))
			must(t, err)
			tx := copyObject(v.Root.Inode + 1)
			must(t, g.BindCopyTransaction(i.ID, tx))
			c := CopyCleanupV1{UID: 123, GID: 456, Mode: 06751, ATimeSeconds: -123, MTimeSeconds: 789, ATimeNanos: 999999999, MTimeNanos: 123456789, Manifest: copyObject(tx.Inode + 1), Staging: copyObject(tx.Inode + 2)}
			c.Manifest.FileType = 0100000
			digest := sha256.Sum256([]byte("digest authority retains no manifest bytes"))
			if sealed {
				must(t, g.SealCopyManifestDigest(i.ID, tx, digest, MaxCopyManifestBytes))
				must(t, g.SealCopyManifestDigest(i.ID, tx, digest, MaxCopyManifestBytes))
			}
			for _, mutate := range []func(*CopyCleanupV1){func(c *CopyCleanupV1) { c.Mode = 010000 }, func(c *CopyCleanupV1) { c.ATimeNanos = 1e9 }, func(c *CopyCleanupV1) { c.MTimeNanos = 1e9 }, func(c *CopyCleanupV1) { c.Manifest = tx }, func(c *CopyCleanupV1) { c.Staging = c.Manifest }, func(c *CopyCleanupV1) { c.Staging.Handle[0] ^= 1 }} {
				bad := c
				mutate(&bad)
				_, err = g.StartCopyCleanup(i.ID, tx, bad)
				wantErr(t, err, ErrInvalid)
			}
			got, err := g.StartCopyCleanup(i.ID, tx, c)
			must(t, err)
			if got.Phase != CopyCleaning || got.Cleanup != c {
				t.Fatal("cleanup evidence not persisted exactly")
			}
			before := f.a.s.Revision
			again, err := g.StartCopyCleanup(i.ID, tx, c)
			must(t, err)
			if again != got || f.a.s.Revision != before {
				t.Fatal("cleanup replay changed state")
			}
			bad := c
			bad.MTimeNanos++
			_, err = g.StartCopyCleanup(i.ID, tx, bad)
			wantErr(t, err, ErrConflict)
			_, err = g.AuthenticateCopyManifest(i.ID, tx, nil)
			wantErr(t, err, ErrInvalid)
			wantErr(t, g.SealCopyManifestDigest(i.ID, tx, digest, MaxCopyManifestBytes), ErrConflict)
			if sealed {
				_, err = g.AuthenticateCopyManifestDigest(i.ID, tx, digest, MaxCopyManifestBytes)
				must(t, err)
			}
			must(t, f.a.validate())
			must(t, g.FinishCopy(i.ID))
			wantErr(t, g.FinishCopy(i.ID), ErrUnauthorized)
			_, err = g.StartCopyCleanup(i.ID, tx, c)
			wantErr(t, err, ErrUnauthorized)
			must(t, f.a.validate())
		})
	}
}

func TestCopyContinuationRoleRWControls(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("owner")
	_, runtime := f.runtime(v, ReadWrite)
	b, owner := copyPrepare(t, f, v, ReadWrite)
	i, err := owner.BeginCopy(copyRoot(f, v))
	must(t, err)
	tx := copyObject(v.Root.Inode + 1)
	must(t, owner.BindCopyTransaction(i.ID, tx))
	rg, err := f.a.Admit(runtime, v.ID, false)
	must(t, err)
	defer rg.Release()
	_, ro := copyPrepare(t, f, f.volume("ro"), ReadOnly)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	retire := RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch}
	_, err = f.a.Retire(ctx, f.control, retire)
	wantErr(t, err, context.Canceled)
	for _, g := range []*Guard{nil, {}, rg, ro, owner} {
		_, err = g.ProvisionCopyTransaction(i.ID, hostCopyObject)
		wantErr(t, err, ErrUnauthorized)
		_, err = g.StartCopyCleanup(i.ID, tx, CopyCleanupV1{})
		wantErr(t, err, ErrUnauthorized)
		wantErr(t, g.SealCopyManifestDigest(i.ID, tx, [32]byte{1}, 1), ErrUnauthorized)
		_, err = g.AuthenticateCopyManifestDigest(i.ID, tx, [32]byte{1}, 1)
		wantErr(t, err, ErrUnauthorized)
	}
	owner.Release()
	_, err = f.a.Retire(context.Background(), f.control, retire)
	must(t, err)
}

func TestCopyContinuationCapacityAndOldSchema(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("capacity")
	_, g := copyPrepare(t, f, v, ReadWrite)
	root := copyRoot(f, v)
	projected := f.a.clone()
	projected.Copy.Intents[v.ID] = CopyIntent{ID: mustID(t), Owner: g.token.binding, Epoch: g.token.epoch, Root: root, Phase: CopyBegun}
	projected.Revision++
	f.a.limits = exactCapacity(t, projected)
	i, err := g.BeginCopy(root)
	must(t, err)
	i, err = g.ProvisionCopyTransaction(i.ID, hostCopyObject)
	must(t, err)
	c := maxCopyIntent(i).Cleanup
	c.Manifest = copyObject(uint64(^uint32(0)))
	c.Manifest.FileType = 0100000
	c.Staging = copyObject(uint64(^uint32(0)) - 1)
	c.Manifest.Generation, c.Staging.Generation = ^uint32(0), ^uint32(0)
	binary.LittleEndian.PutUint32(c.Manifest.Handle[4:], c.Manifest.Generation)
	binary.LittleEndian.PutUint32(c.Staging.Handle[4:], c.Staging.Generation)
	must(t, g.SealCopyManifestDigest(i.ID, i.Transaction, [32]byte{255}, MaxCopyManifestBytes))
	wantErr(t, g.SealCopyManifestDigest(i.ID, i.Transaction, [32]byte{255}, MaxCopyManifestBytes+1), ErrInvalid)
	_, err = g.StartCopyCleanup(i.ID, i.Transaction, c)
	must(t, err)
	must(t, g.FinishCopy(i.ID))
	must(t, f.a.validate())
	g.Release()
	s := f.a.clone()
	must(t, f.a.Close())
	for _, schema := range []string{"old", "missing"} {
		t.Run(schema, func(t *testing.T) {
			if schema == "old" {
				s.Copy.Version = 1
			} else {
				s.Copy = nil
			}
			raw, err := json.Marshal(s)
			must(t, err)
			must(t, os.WriteFile(filepath.Join(f.path, registryName, stateName), raw, 0600))
			// Lifecycle opens never adopt or upgrade absent/obsolete copy state.
			lifecycleCrashRefusesUnchanged(t, f.path, f.openCurrent, ErrInvalid)
		})
	}
}

func cleanupHostCopy(t *testing.T, f *fixture, g *Guard, i CopyIntent) {
	t.Helper()
	root := f.a.roots[i.Root.Volume]
	path := filepath.Join(f.path, "volumes", f.a.s.Volumes[i.Root.Volume].Name)
	tx := filepath.Join(path, copyTransactionName)
	// Existing evidence must match; absence is permitted only by durable CLEANING.
	for _, e := range []struct {
		name   string
		object Ext4ObjectV1
	}{{"manifest.json", i.Cleanup.Manifest}, {"staging", i.Cleanup.Staging}} {
		p := filepath.Join(tx, e.name)
		fd, err := os.Open(p)
		if err == nil {
			got, err := hostCopyObject(int(fd.Fd()))
			must(t, err)
			must(t, fd.Close())
			if got != e.object {
				t.Fatal("foreign cleanup object")
			}
			must(t, os.Remove(p))
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		must(t, f.a.j.step("test-cleanup-"+e.name, func() error { return nil }))
	}
	if fd, err := os.Open(tx); err == nil {
		got, err := hostCopyObject(int(fd.Fd()))
		must(t, err)
		must(t, fd.Sync())
		must(t, fd.Close())
		if got != i.Transaction {
			t.Fatal("foreign transaction")
		}
		must(t, os.Remove(tx))
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	must(t, f.a.j.step("test-cleanup-transaction", func() error { return nil }))
	must(t, os.Chown(path, int(i.Cleanup.UID), int(i.Cleanup.GID)))
	must(t, unix.Fchmod(int(root.Fd()), i.Cleanup.Mode))
	must(t, os.Chtimes(path, time.Unix(i.Cleanup.ATimeSeconds, int64(i.Cleanup.ATimeNanos)), time.Unix(i.Cleanup.MTimeSeconds, int64(i.Cleanup.MTimeNanos))))
	must(t, root.Sync())
	must(t, f.a.j.step("test-cleanup-root-sync", func() error { return nil }))
	must(t, g.FinishCopy(i.ID))
	must(t, f.a.j.step("test-cleanup-finished", func() error { return nil }))
}

// os.Exit is intentional: no defers, poison handler or orderly Close can repair
// these boundaries. Tests re-open, drain, transfer ownership and resume real IO.
func TestCopyContinuationCrashWorker(t *testing.T) {
	path := os.Getenv("CENGINE_COPY_CONTINUATION_ROOT")
	if path == "" {
		return
	}
	boundary := os.Getenv("CENGINE_COPY_CONTINUATION_BOUNDARY")
	f := newFixtureAt(t, nil, path)
	v := f.volume("crash")
	_, g := copyPrepare(t, f, v, ReadWrite)
	must(t, os.Chtimes(filepath.Join(path, "volumes", v.Name), time.Unix(11, 123456789), time.Unix(13, 987654321)))
	i, err := g.BeginCopy(copyRoot(f, v))
	must(t, err)
	m := crashManifest{Current: f.signedCurrent(), Bootstrap: f.c.BootstrapKey, ControllerKey: f.controllerKey, CAKey: f.caKey, CACertificate: f.ca.Raw, Before: *f.a.clone()}
	data, err := json.Marshal(m)
	must(t, err)
	writeCrashWitness(t, path, crashManifestName, data)
	f.a.j.afterStep = func(step string) {
		if step == boundary {
			os.Exit(crashExit)
		}
	}
	i, err = g.ProvisionCopyTransaction(i.ID, hostCopyObject)
	must(t, err)
	if len(boundary) >= 12 && boundary[:12] == "test-cleanup" {
		tx := filepath.Join(path, "volumes", v.Name, copyTransactionName)
		must(t, os.WriteFile(filepath.Join(tx, "manifest.json"), []byte("sealed recovery bytes"), 0600))
		must(t, os.Mkdir(filepath.Join(tx, "staging"), 0700))
		c := i.Initial
		for _, e := range []struct {
			name string
			out  *Ext4ObjectV1
		}{{"manifest.json", &c.Manifest}, {"staging", &c.Staging}} {
			fd, err := os.Open(filepath.Join(tx, e.name))
			must(t, err)
			*e.out, err = hostCopyObject(int(fd.Fd()))
			must(t, err)
			must(t, fd.Sync())
			must(t, fd.Close())
		}
		if boundary != "test-cleanup-unsealed-durable" {
			must(t, g.SealCopyManifest(i.ID, i.Transaction, []byte("sealed recovery bytes")))
		}
		i, err = g.StartCopyCleanup(i.ID, i.Transaction, c)
		must(t, err)
		if boundary == "test-cleanup-unsealed-durable" {
			must(t, f.a.j.step(boundary, func() error { return nil }))
		}
		must(t, f.a.j.step("test-cleanup-durable", func() error { return nil }))
		cleanupHostCopy(t, f, g, i)
	}
	t.Fatal("crash boundary not reached", boundary)
}

func TestCopyContinuationProcessCrashResume(t *testing.T) {
	for _, boundary := range []string{"copy-initial-durable", "copy-private-mkdir", "copy-private-sync", "copy-private-parent-sync", "copy-bound-durable", "copy-private-publish", "copy-public-parent-sync", "copy-source-parent-sync", "test-cleanup-durable", "test-cleanup-unsealed-durable", "test-cleanup-manifest.json", "test-cleanup-staging", "test-cleanup-transaction", "test-cleanup-root-sync", "test-cleanup-finished"} {
		t.Run(boundary, func(t *testing.T) {
			path := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCopyContinuationCrashWorker$", "-test.count=1")
			cmd.Env = append(os.Environ(), "CENGINE_COPY_CONTINUATION_ROOT="+path, "CENGINE_COPY_CONTINUATION_BOUNDARY="+boundary, "GORACE=atexit_sleep_ms=0")
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != crashExit {
				t.Fatalf("worker: %v\n%s", err, out)
			}
			data, err := os.ReadFile(filepath.Join(path, crashManifestName))
			must(t, err)
			var m crashManifest
			must(t, json.Unmarshal(data, &m))
			root, err := os.Open(path)
			must(t, err)
			defer root.Close()
			c := Config{Root: root, DeviceID: m.Before.Store.DeviceID, BootstrapKey: m.Bootstrap, Barrier: func(Binding, *os.File) error { return nil }}
			open := func() (*Authority, error) {
				return OpenLifecycleExpected(c, m.Current, ExpectedLifecycleStartup{ExpectedStartup{m.Before.Store.ID, m.Before.Epoch, m.Before.Controller}, m.Before.Lifecycle.OpenRevision})
			}
			// This worker publishes no copy-operation obligation: even BOUND alone
			// cannot authorize admission of the private directory.
			if boundary == "copy-private-mkdir" || boundary == "copy-private-sync" || boundary == "copy-private-parent-sync" || boundary == "copy-bound-durable" {
				lifecycleCrashRefusesUnchanged(t, path, open, ErrRepairRequired)
				return
			}
			a, err := open()
			must(t, err)
			defer a.Close()
			f := &fixture{t: t, a: a, c: c, path: path, controllerKey: m.ControllerKey, caKey: m.CAKey}
			f.ca, err = x509.ParseCertificate(m.CACertificate)
			must(t, err)
			f.pool = x509.NewCertPool()
			f.pool.AddCert(f.ca)
			f.server = f.cert(newKey(t))
			f.control = f.authControl(m.ControllerKey, m.Before.Controller.Epoch)
			var i CopyIntent
			for _, value := range a.s.Copy.Intents {
				i = value
			}
			if !i.InitialCaptured || i.Initial.ATimeSeconds != 11 || i.Initial.ATimeNanos != 123456789 || i.Initial.MTimeSeconds != 13 || i.Initial.MTimeNanos != 987654321 {
				t.Fatal("lost pre-provision metadata", i.Initial)
			}
			if boundary == "test-cleanup-finished" {
				if i.Phase != CopyCompleted || a.copyFences[i.Root.Volume] != nil {
					t.Fatal("completion/fence not durable")
				}
				g := copySuccessor(t, f, i.Owner)
				wantErr(t, g.FinishCopy(i.ID), ErrUnauthorized)
				return
			}
			if a.copyFences[i.Root.Volume] == nil {
				t.Fatal("crash erased fence")
			}
			g := copySuccessor(t, f, i.Owner)
			got, err := g.InspectCopy(i.ID, i.Root)
			must(t, err)
			if got.Initial != i.Initial || got.Cleanup != i.Cleanup || got.Transaction != i.Transaction {
				t.Fatal("transfer altered recovery evidence")
			}
			if i.Phase == CopyCleaning {
				if i.ManifestSize != 0 {
					_, err = g.AuthenticateCopyManifestDigest(i.ID, i.Transaction, i.ManifestDigest, i.ManifestSize)
					must(t, err)
				} else {
					_, err = g.AuthenticateCopyManifest(i.ID, i.Transaction, nil)
					wantErr(t, err, ErrInvalid)
					// Inspect plus exact cleanup replay authenticates unsealed
					// CLEANING without treating unsealed bytes as instructions.
					again, e := g.StartCopyCleanup(i.ID, i.Transaction, i.Cleanup)
					must(t, e)
					if again != got {
						t.Fatal("unsealed cleanup replay changed state")
					}
				}
				cleanupHostCopy(t, f, g, got)
				want := i.Cleanup
				want.Manifest, want.Staging = Ext4ObjectV1{}, Ext4ObjectV1{}
				if metadataAt(t, a.roots[i.Root.Volume]) != want {
					t.Fatal("root metadata not restored exactly")
				}
			} else {
				got, err = g.ProvisionCopyTransaction(i.ID, hostCopyObject)
				must(t, err)
				if got.Phase != CopyBound || got.Initial != i.Initial || (i.Transaction != (Ext4ObjectV1{}) && got.Transaction != i.Transaction) {
					t.Fatal("resumed with different identity")
				}
				got, err = g.StartCopyCleanup(got.ID, got.Transaction, got.Initial)
				must(t, err)
				cleanupHostCopy(t, f, g, got)
				if metadataAt(t, a.roots[i.Root.Volume]) != i.Initial {
					t.Fatal("premanifest rollback lost root metadata")
				}
			}
			must(t, a.validate())
		})
	}
}

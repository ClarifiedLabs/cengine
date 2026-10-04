//go:build cengine_native_faulttest && linux && (arm64 || amd64)

package storagemanaged

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	c "dev.cengine/guest/internal/copycontract"
	a "dev.cengine/guest/internal/storageauthority"
	"dev.cengine/guest/internal/storageauthoritytest"
	"dev.cengine/guest/internal/storageidentity"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

const copyDataWorkerEnv = "CENGINE_NATIVE_COPY_DATA_RECOVERY_WORKER"

type copyDataKeys struct {
	Lifecycle  *storageauthoritytest.Fixture
	Controller ed25519.PrivateKey
	Bootstrap  ed25519.PublicKey
	Owner      ed25519.PrivateKey
}

// The parent signs genesis before passing it over the private worker pipe.
func newCopyDataKeys(t *testing.T) copyDataKeys {
	bootstrap, controller := key(t), key(t)
	return copyDataKeys{Controller: controller, Bootstrap: bootstrap.Public().(ed25519.PublicKey), Owner: key(t), Lifecycle: storageauthoritytest.New(t, bootstrap, newID(t), fingerprint(t, controller))}
}

type copyDataManifest struct {
	Lifecycle storageauthoritytest.Fixture
	Kind      string
	Before    a.Snapshot
	Stable    a.Receipt
	Intent    a.CopyIntent
	Sequence  uint64
	Manifest  c.Manifest
}
type copyDataProof struct {
	Kind     string
	Sequence uint64
	RealSync bool
	Census   [32]byte
}

// Exact canonical on-disk DATA classification, not an invented expected object.
type copyDataRecord struct {
	Prior      *copyDataRecord `json:",omitempty"`
	Version    int
	Epoch      a.ID
	Controller a.Controller
	Binding    a.Binding
	Root       a.RootIdentity
	Sequence   uint64
	Action     string
	Intent     a.ID
	Before     a.CopyIntent
}

func copyDataKind(kind string) (string, string, error) {
	switch kind {
	case "rename", "root-metadata":
		return a.CopyOperationRollback, a.CopySealed, nil
	case "sealed-tail":
		return a.CopyOperationDirectoryTail, a.CopySealed, nil
	case "cleaning-tail":
		return a.CopyOperationDirectoryTail, a.CopyCleaning, nil
	case "completed-tail":
		return a.CopyOperationDirectoryTail, a.CopyCompleted, nil
	}
	return "", "", errors.New("unknown copy DATA cut")
}

// Unlike copyObligationHost, every initialization/reopen uses Registry.Barrier.
// Only keys cross the private parent->child pipe; proofs contain public state.
func copyDataFixture(t *testing.T, path string, keys copyDataKeys, before *a.Snapshot, exact bool) *fixture {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("requires native Linux root")
	}
	f := &fixture{t: t, path: path, gate: new(sync.Mutex), worker: new(storageidentity.Worker), sequence: make(map[*Session]uint64), bootstrap: keys.Bootstrap, lifecycle: keys.Lifecycle}
	var err error
	f.root, err = os.Open(path)
	must(t, err)
	t.Cleanup(func() { must(t, f.root.Close()) })
	uuid, err := backingUUID(int(f.root.Fd()))
	must(t, err)
	device := fmt.Sprintf("%x-%x-%x-%x-%x", uuid[:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
	f.registry, err = NewRegistry(f.gate)
	must(t, err)
	f.caKey = key(t)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "copy DATA test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, f.caKey.Public(), f.caKey)
	must(t, err)
	f.ca, err = x509.ParseCertificate(der)
	must(t, err)
	f.pool = x509.NewCertPool()
	f.pool.AddCert(f.ca)
	f.server = f.cert(key(t))
	cfg := a.Config{Root: f.root, DeviceID: device, BootstrapKey: keys.Bootstrap, Barrier: f.registry.Barrier, CopyRecoveryPreflight: PreflightCopyRecovery}
	if before == nil {
		must(t, os.Chmod(path, 0755))
		must(t, os.Mkdir(filepath.Join(path, "volumes"), 0755))
		must(t, os.Mkdir(filepath.Join(path, "volumes", "data"), 0777))
		must(t, os.Chmod(filepath.Join(path, "volumes", "data"), 0777))
		f.storeID, f.volumeID = f.lifecycle.Current.Grant.Identity.Store, newID(t)
		f.authority, err = f.lifecycle.Initialize(cfg)
	} else {
		f.storeID = before.Store.ID
		for id := range before.Volumes {
			f.volumeID = id
		}
		if exact {
			f.authority, err = f.lifecycle.OpenExpected(cfg, f.lifecycle.Expected.ExpectedStartup)
		} else {
			f.authority, err = f.lifecycle.Open(cfg)
		}
	}
	must(t, err)
	t.Cleanup(func() {
		if !f.expectFaults {
			must(t, f.authority.Close())
		} else {
			_ = f.authority.Close()
		}
	})
	f.control, err = f.authority.AuthenticateController(t.Context(), f.conn(keys.Controller), 1)
	must(t, err)
	f.volume, err = os.Open(filepath.Join(path, "volumes", "data"))
	must(t, err)
	t.Cleanup(func() { must(t, f.volume.Close()) })
	if before == nil {
		st, err := stat(int(f.volume.Fd()))
		must(t, err)
		must(t, f.authority.AddVolume(f.control, a.VolumeRequest{Operation: newID(t), Volume: a.Volume{ID: f.volumeID, Name: "data", Root: a.RootIdentity{Device: st.Dev, Inode: st.Ino}}}))
	}
	return f
}

func copyDataOwner(t *testing.T, f *fixture, old *a.Binding, ownerKey ...ed25519.PrivateKey) *Session {
	t.Helper()
	k := key(t)
	if len(ownerKey) == 1 {
		k = ownerKey[0]
	}
	b := a.Binding{Store: f.storeID, Volume: f.volumeID, Attachment: newID(t), Container: a.ContainerID(strings.Repeat("a", 64)), Launch: newID(t), Key: fingerprint(t, k), Role: a.PrepareRole, Mode: a.ReadWrite, Prepare: newID(t)}
	reserve := a.ReserveRequest{Operation: newID(t), Prepare: b.Prepare, Attachments: []a.Binding{b}}
	if old == nil {
		must(t, f.authority.ReservePrepare(f.control, reserve))
	} else {
		receipt, err := f.authority.Retire(t.Context(), f.control, a.RetireRequest{Operation: newID(t), Store: old.Store, Volume: old.Volume, Attachment: old.Attachment, Launch: old.Launch})
		must(t, err)
		if len(f.registry.sessions) != 0 || len(f.registry.objects) != 0 {
			t.Fatal("predecessor drain retained resources")
		}
		must(t, f.authority.ReplacePrepare(f.control, a.ReplaceRequest{Operation: newID(t), Prepare: old.Prepare, Receipts: []a.Receipt{receipt}, Successor: reserve}))
	}
	must(t, f.authority.RegisterAttachment(f.control, a.RegisterRequest{Operation: newID(t), Binding: b}))
	p, err := f.authority.AuthenticateData(t.Context(), f.conn(k), a.DataHello{Epoch: f.authority.Epoch(), Binding: b})
	must(t, err)
	g, err := f.authority.Admit(p, b.Volume, false)
	must(t, err)
	s, _, err := New(g, p, b, f.gate, f.worker, f.registry)
	g.Release()
	must(t, err)
	t.Cleanup(func() {
		if f.expectFaults {
			err := f.registry.Barrier(b, f.volume)
			if err != nil && !errors.Is(err, ErrVolumeFault) {
				t.Error(err)
			}
			if !s.closed || len(s.nodes) != 0 || len(s.handles) != 0 || len(f.registry.objects) != 0 {
				t.Error("fault cleanup retained resources")
			}
			return
		}
		_, err := f.authority.Retire(context.Background(), f.control, a.RetireRequest{Operation: newID(t), Store: b.Store, Volume: b.Volume, Attachment: b.Attachment, Launch: b.Launch})
		must(t, err)
		if !s.closed || len(s.nodes) != 0 || len(s.handles) != 0 || len(f.registry.objects) != 0 {
			t.Error("owner cleanup retained resources")
		}
	})
	return s
}

func copyDataControl(t *testing.T, f *fixture, s *Session) func(w.PrepareAction, a.ID) w.PrepareReply {
	t.Helper()
	handle := f.call(s, caller(0, 0), w.OpenDirRequest{Node: 1}).(w.OpenDirReply).Opened.Handle
	return func(action w.PrepareAction, id a.ID) w.PrepareReply {
		t.Helper()
		return f.call(s, caller(0, 0), w.PrepareRequest{Node: 1, Handle: handle, Action: action, Intent: id}).(w.PrepareReply)
	}
}
func copyDataXattrs(t *testing.T, fd int) *c.XattrSnapshot {
	t.Helper()
	snapshot, err := c.SnapshotXattrs(fd, c.XattrOperations{List: unix.Flistxattr, Get: unix.Fgetxattr})
	must(t, err)
	return snapshot
}

func copyDataSetup(t *testing.T, f *fixture, kind string, ownerKey ...ed25519.PrivateKey) (*Session, copyDataManifest, w.RequestBody) {
	t.Helper()
	stableSession, stableRoot := f.session(a.ReadWrite)
	created := f.call(stableSession, caller(1001, 1001), w.CreateRequest{Parent: stableRoot.Node, Name: []byte("payload"), Flags: w.OpenReadWrite, Mode: 0600}).(w.CreateReply)
	written := f.call(stableSession, grantAuth, w.WriteRequest{Node: created.Entry.Node, Handle: created.Opened.Handle, Data: []byte(policyACK)}).(w.WriteReply)
	if written.Written != uint32(len(policyACK)) {
		t.Fatal("short ACK write")
	}
	stable, err := f.authority.Retire(t.Context(), f.control, a.RetireRequest{Operation: newID(t), Store: f.storeID, Volume: f.volumeID, Attachment: stableSession.binding.Attachment, Launch: stableSession.binding.Launch})
	must(t, err)
	if !stableSession.closed || len(f.registry.objects) != 0 {
		t.Fatal("ACK lacked real drain")
	}
	s := copyDataOwner(t, f, nil, ownerKey...)
	rootFD := int(s.root.Fd())
	// Original nonroot 0555 metadata makes successful private unlink after restore
	// depend on the owner's CAP_DAC_OVERRIDE, not caller-0's stripped credentials.
	must(t, unix.Fchown(rootFD, 1001, 1001))
	must(t, unix.Fchmod(rootFD, 0555))
	must(t, unix.Fsetxattr(rootFD, "user.copy-original", []byte("original"), 0))
	control := copyDataControl(t, f, s)
	original, err := copyRootCleanup(rootFD)
	must(t, err)
	st, err := stat(rootFD)
	must(t, err)
	var fs unix.Statfs_t
	must(t, unix.Fstatfs(rootFD, &fs))
	metadata := &c.RootMetadata{Filesystem: fs.Fsid.Val, Device: st.Dev, Inode: st.Ino, UID: st.Uid, GID: st.Gid, Mode: st.Mode & 07777, Xattrs: copyDataXattrs(t, rootFD)}
	intent := control(w.BeginCopy, "").Intent
	intent = control(w.BindCopyTransaction, intent.ID).Intent
	if !intent.InitialCaptured || intent.Initial != original {
		t.Fatal("provision did not capture actual initial metadata")
	}
	tx := filepath.Join(f.path, "volumes", "data", copyTransactionPath)
	must(t, os.Mkdir(filepath.Join(tx, "staging"), 0700))
	must(t, os.Mkdir(filepath.Join(tx, "staging", "tree"), 0700))
	must(t, os.WriteFile(filepath.Join(tx, "staging", "tree", "child"), []byte("copied payload\n"), 0600))
	manifest := c.Manifest{Version: 4, Intent: intent.ID, Physical: intent.Root, Root: metadata, Entries: []c.Entry{}}
	for _, name := range []string{"tree", "tree/child"} {
		identity, err := copyIdentityAt(rootFD, copyTransactionPath+"/staging/"+name)
		must(t, err)
		manifest.Entries = append(manifest.Entries, c.Entry{Path: name, Identity: identity})
	}
	must(t, c.ValidateManifest(manifest))
	raw, err := json.Marshal(manifest)
	must(t, err)
	must(t, os.WriteFile(filepath.Join(tx, "manifest.json"), raw, 0600))
	must(t, unix.Syncfs(rootFD))
	intent = control(w.SealManifest, intent.ID).Intent
	if intent.ManifestDigest != sha256.Sum256(raw) || intent.ManifestSize != uint64(len(raw)) {
		t.Fatal("seal did not bind actual shared manifest")
	}
	// Simulate source-root metadata application before the selected ordinary DATA.
	must(t, unix.Fchown(rootFD, 0, 0))
	must(t, unix.Fchmod(rootFD, 0700))
	must(t, unix.Fsetxattr(rootFD, "user.copy-original", []byte("source"), 0))
	must(t, unix.Fsetxattr(rootFD, "user.copy-extra", []byte("remove on rollback"), 0))
	transaction := f.call(s, caller(0, 0), w.LookupRequest{Parent: 1, Name: []byte(copyTransactionPath)}).(w.LookupReply).Entry
	staging := f.call(s, caller(0, 0), w.LookupRequest{Parent: transaction.Node, Name: []byte("staging")}).(w.LookupReply).Entry
	rename := w.RenameRequest{OldParent: staging.Node, NewParent: 1, OldName: []byte("tree"), NewName: []byte("tree"), Flags: w.RenameNoReplace}
	var body w.RequestBody = rename
	if kind != "rename" {
		f.call(s, caller(0, 0), rename)
	}
	switch kind {
	case "root-metadata":
		body = w.SetXAttrRequest{Node: 1, Name: []byte("user.copy-selected"), Value: []byte("selected")}
	case "sealed-tail", "cleaning-tail", "completed-tail":
		if kind != "sealed-tail" {
			intent = control(w.StartCleanup, intent.ID).Intent
		}
		if kind == "completed-tail" {
			intent = control(w.FinishCopy, intent.ID).Intent
		}
		handle := f.call(s, caller(0, 0), w.OpenDirRequest{Node: 1}).(w.OpenDirReply).Opened.Handle
		body = w.FsyncDirRequest{Node: 1, Handle: handle}
	}
	must(t, unix.Syncfs(rootFD))
	before, err := f.authority.Query(f.control)
	must(t, err)
	return s, copyDataManifest{Lifecycle: *f.lifecycle, Kind: kind, Before: before, Stable: stable, Intent: intent, Sequence: f.sequence[s] + 1, Manifest: manifest}, body
}

func copyDataValidate(m copyDataManifest, p copyDataProof, census map[string][]byte) error {
	action, phase, err := copyDataKind(m.Kind)
	if err != nil {
		return err
	}
	if p.Kind != m.Kind || !p.RealSync || p.Sequence != m.Sequence || p.Census != policyDigest(census) || m.Sequence == 0 || m.Intent.Phase != phase || !m.Intent.InitialCaptured || m.Intent.Owner.Role != a.PrepareRole || m.Intent.Owner.Mode != a.ReadWrite {
		return errors.New("unbound copy DATA proof")
	}
	if m.Manifest.Intent != m.Intent.ID || m.Manifest.Physical != m.Intent.Root {
		return errors.New("manifest/physical intent mismatch")
	}
	if err = c.ValidateManifest(m.Manifest); err != nil {
		return err
	}
	var record copyDataRecord
	if err = policyJSON(census["copy-operation"], &record); err != nil {
		return err
	}
	want := copyDataRecord{Version: 2, Epoch: m.Before.Epoch, Controller: m.Before.Controller, Binding: m.Intent.Owner, Root: m.Before.Volumes[m.Intent.Root.Volume].Root, Sequence: m.Sequence, Action: action, Intent: m.Intent.ID, Before: m.Intent}
	if record != want {
		return errors.New("ordinary DATA did not publish exact classified obligation")
	}
	state, err := policyState(census)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(state, m.Before) {
		return errors.New("held DATA changed state/receipt")
	}
	stable := state.Attachments[m.Stable.Attachment]
	if stable.Receipt == nil || *stable.Receipt != m.Stable || state.Attachments[m.Intent.Owner.Attachment].Receipt != nil {
		return errors.New("missing earlier receipt or minted receipt")
	}
	if len(census) != 3 {
		return errors.New("unexpected copy DATA census size")
	}
	for name, value := range census {
		switch name {
		case "state.json", "copy-operation":
		case "lock":
			if len(value) != 0 {
				return errors.New("nonempty registry lock")
			}
		default:
			return fmt.Errorf("unexpected %s", name)
		}
	}
	return nil
}

// Gated child is deliberately outside the closed native parent selector.
func TestNativeCopyDataRecoveryWorker(t *testing.T) {
	kind := os.Getenv(copyDataWorkerEnv)
	if kind == "" {
		return
	}
	_, _, err := copyDataKind(kind)
	must(t, err)
	root, commands, proofs := os.NewFile(3, "copy-data-root"), os.NewFile(4, "copy-data-commands"), os.NewFile(5, "copy-data-proofs")
	must(t, policyPipe(commands, unix.O_RDONLY))
	must(t, policyPipe(proofs, unix.O_WRONLY))
	left, err := stat(int(commands.Fd()))
	must(t, err)
	right, err := stat(int(proofs.Fd()))
	must(t, err)
	st, err := stat(int(root.Fd()))
	must(t, err)
	if left.Dev == right.Dev && left.Ino == right.Ino || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Geteuid()) {
		t.Fatal("unowned/aliased capabilities")
	}
	var keys copyDataKeys
	must(t, policyReceive(commands, &keys))
	f := copyDataFixture(t, "/proc/self/fd/3", keys, nil, false)
	s, m, body := copyDataSetup(t, f, kind, keys.Owner)
	must(t, policySend(proofs, m))
	policyCommand(t, commands, 'A')
	hold := func(fd int, call func(int) error) error {
		if err := call(fd); err != nil {
			return err
		}
		// FsyncDir executes on the caller's capability-stripped worker thread.
		// fstat proves this exact pinned target without requiring handle privileges.
		observed, err := stat(fd)
		if err != nil {
			return err
		}
		bound := m.Before.Volumes[m.Intent.Root.Volume].Root
		if observed.Mode&unix.S_IFMT != unix.S_IFDIR || observed.Dev != bound.Device || observed.Ino != bound.Inode {
			return errors.New("sync target is not exact bound root")
		}
		if kind == "rename" {
			published, err := copyIdentityAt(int(s.root.Fd()), "tree")
			if err != nil {
				return err
			}
			if published != m.Manifest.Entries[0].Identity {
				return errors.New("selected rename did not publish owned tree")
			}
			if _, err = copyIdentityAt(int(s.root.Fd()), copyTransactionPath+"/staging/tree"); !errors.Is(err, unix.ENOENT) {
				return errors.New("selected rename retained source")
			}
		}
		if kind == "root-metadata" {
			value := make([]byte, 32)
			n, err := unix.Fgetxattr(int(s.root.Fd()), "user.copy-selected", value)
			if err != nil {
				return err
			}
			if string(value[:n]) != "selected" {
				return errors.New("selected metadata syscall not applied")
			}
		}
		census, err := policyCensus(root)
		if err != nil {
			return err
		}
		proof := copyDataProof{Kind: kind, Sequence: f.sequence[s], RealSync: true, Census: policyDigest(census)}
		if err = copyDataValidate(m, proof, census); err != nil {
			return err
		}
		if err = policySend(proofs, proof); err != nil {
			return err
		}
		policyCommand(t, commands, '!') // parent SIGKILLs; this hold is never released
		return errors.New("parent released death-only cut")
	}
	if strings.HasSuffix(kind, "-tail") {
		f.registry.syncOps.fsync = func(fd int) error { return hold(fd, unix.Fsync) }
	} else {
		f.registry.syncOps.syncfs = func(fd int) error { return hold(fd, unix.Syncfs) }
	}
	f.call(s, caller(0, 0), body)
	t.Fatal("selected operation returned instead of remaining held")
}

// Process death only: the real ext4 filesystem and Linux kernel remain alive.
func TestNativeCopyDataRecoveryProcessDeath(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("requires Linux root and actual ext4")
	}
	for _, kind := range []string{"rename", "root-metadata", "sealed-tail", "cleaning-tail", "completed-tail"} {
		t.Run(kind, func(t *testing.T) { copyDataProcessDeath(t, kind) })
	}
}

func copyDataProcessDeath(t *testing.T, kind string) {
	path, err := os.MkdirTemp("", "native-copy-data-")
	must(t, err)
	joined := true
	t.Cleanup(func() {
		if joined && !t.Failed() {
			must(t, os.RemoveAll(path))
		} else {
			t.Logf("retained owned evidence %s (joined=%v)", path, joined)
		}
	})
	root, err := os.Open(path)
	must(t, err)
	defer root.Close()
	var fs unix.Statfs_t
	must(t, unix.Fstatfs(int(root.Fd()), &fs))
	if fs.Type != unix.EXT4_SUPER_MAGIC || uint64(fs.Blocks)*uint64(fs.Bsize) > 128<<20 || fs.Files > 4096 {
		t.Fatal("requires runner-owned bounded actual ext4")
	}
	commands, writer, err := os.Pipe()
	must(t, err)
	defer commands.Close()
	defer writer.Close()
	reader, proofs, err := os.Pipe()
	must(t, err)
	defer reader.Close()
	defer proofs.Close()
	binary, err := os.Executable()
	must(t, err)
	cmd := exec.Command(binary, "-test.run=^TestNativeCopyDataRecoveryWorker$", "-test.count=1", "-test.timeout=25s")
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, copyDataWorkerEnv+"=") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, copyDataWorkerEnv+"="+kind)
	cmd.ExtraFiles = []*os.File{root, commands, proofs}
	capture := new(policyOutput)
	cmd.Stdout, cmd.Stderr = capture, capture
	cmd.WaitDelay = 2 * time.Second
	pidfd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, PidFD: &pidfd}
	started, done := make(chan error, 1), make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := cmd.Start(); err != nil {
			started <- err
			return
		}
		started <- nil
		done <- cmd.Wait()
		if cmd.ProcessState == nil {
			select {}
		}
	}()
	must(t, <-started)
	joined = false
	defer func() {
		if !joined {
			if pidfd >= 0 {
				_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
			} else {
				_ = cmd.Process.Kill()
			}
			select {
			case <-done:
				joined = cmd.ProcessState != nil
			case <-time.After(5 * time.Second):
				t.Error("unjoined owned worker")
			}
		}
		if pidfd >= 0 {
			_ = unix.Close(pidfd)
		}
		if t.Failed() {
			t.Logf("bounded worker output: %s", capture.String())
		}
	}()
	if pidfd < 0 {
		t.Fatal("missing pidfd")
	}
	must(t, commands.Close())
	must(t, proofs.Close())
	deadline := time.Now().Add(20 * time.Second)
	must(t, reader.SetReadDeadline(deadline))
	must(t, writer.SetWriteDeadline(deadline))
	keys := newCopyDataKeys(t)
	must(t, policySend(writer, keys))
	var m copyDataManifest
	must(t, policyReceive(reader, &m))
	st, err := stat(int(root.Fd()))
	must(t, err)
	if !reflect.DeepEqual(m.Lifecycle.Current, keys.Lifecycle.Current) || m.Lifecycle.Expected.Store != m.Before.Store.ID || m.Lifecycle.Expected.Epoch != m.Before.Epoch || m.Lifecycle.Expected.Controller != m.Before.Controller || m.Lifecycle.Expected.OpenRevision == 0 {
		t.Fatal("worker lifecycle trust differs from parent grant/live predecessor")
	}
	if m.Kind != kind || m.Before.Store.Root != (a.RootIdentity{Device: st.Dev, Inode: st.Ino}) {
		t.Fatal("wrong root/kind")
	}
	initial, err := policyCensus(root)
	must(t, err)
	state, err := policyState(initial)
	must(t, err)
	if !reflect.DeepEqual(state, m.Before) {
		t.Fatal("wrong durable predecessor")
	}
	ack, err := os.OpenFile(filepath.Join(path, "parent-ack.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	must(t, err)
	must(t, policySend(ack, m))
	must(t, ack.Sync())
	must(t, ack.Close())
	must(t, root.Sync())
	ackBytes, err := policyReadPath(root, "parent-ack.json", policyLimit)
	must(t, err)
	_, err = writer.Write([]byte{'A'})
	must(t, err)
	var proof copyDataProof
	must(t, policyReceive(reader, &proof))
	cut, err := policyCensus(root)
	must(t, err)
	must(t, copyDataValidate(m, proof, cut))
	foreign := make(map[string][]byte, len(cut)+1)
	for name, value := range cut {
		foreign[name] = value
	}
	// Schema-4 PREPARE context binds version 2. A matching census hash must
	// never make a legacy classification acceptable, even with identical tuples.
	var legacy copyDataRecord
	must(t, policyJSON(cut["copy-operation"], &legacy))
	legacy.Version = 1
	foreign["copy-operation"], err = json.Marshal(legacy)
	must(t, err)
	legacyProof := proof
	legacyProof.Census = policyDigest(foreign)
	if copyDataValidate(m, legacyProof, foreign) == nil {
		t.Fatal("accepted legacy classification with a matching census digest")
	}
	foreign["copy-operation"] = cut["copy-operation"]
	foreign["unrecognized-obligation"] = []byte("unknown")
	foreignProof := proof
	foreignProof.Census = policyDigest(foreign)
	if copyDataValidate(m, foreignProof, foreign) == nil {
		t.Fatal("accepted an unknown durable obligation with a matching census digest")
	}
	held := copyDataSnapshot(t, path)
	policyLogCensus(t, kind+"-held-real-sync", cut)
	must(t, unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0))
	select {
	case err = <-done:
		joined = cmd.ProcessState != nil
		if !policyKilled(err, cmd.ProcessState) {
			t.Fatalf("not actual SIGKILL/sole Wait: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("deadline is not death evidence")
	}
	dead, err := policyCensus(root)
	must(t, err)
	if !reflect.DeepEqual(cut, dead) || !reflect.DeepEqual(held, copyDataSnapshot(t, path)) {
		t.Fatal("death changed held evidence")
	}
	retirementCheckACK(t, root, ackBytes)
	keys.Lifecycle = &m.Lifecycle
	if kind == "rename" {
		copyDataRefusedStartup(t, path, root, keys, m)
		held = copyDataSnapshot(t, path) // negative controls restored bytes, not ctime
	}
	// Recovery requires both trusted anchors; refusal must preserve all evidence.
	// Each exact open captures the new E/OpenRevision for the next admission.
	for attempt := 1; attempt <= 2; attempt++ {
		registry, err := NewRegistry(new(sync.Mutex))
		must(t, err)
		cfg := a.Config{Root: root, DeviceID: m.Before.Store.DeviceID, BootstrapKey: keys.Bootstrap, Barrier: registry.Barrier, CopyRecoveryPreflight: PreflightCopyRecovery}
		previous, err := policyState(dead)
		must(t, err)
		if attempt == 1 {
			lifecycleRecoveryRefuseUnanchored(t, cfg, keys.Lifecycle, func() {
				unchanged, err := policyCensus(root)
				must(t, err)
				if !reflect.DeepEqual(dead, unchanged) || !reflect.DeepEqual(held, copyDataSnapshot(t, path)) {
					t.Fatal("unanchored refusal changed registry/volume census")
				}
				retirementCheckACK(t, root, ackBytes)
			})
		}
		reopened := lifecycleRecoveryOpenExact(t, cfg, keys.Lifecycle)
		epoch := reopened.Epoch()
		must(t, reopened.Close())
		dead, err = policyCensus(root)
		must(t, err)
		now, err := policyState(dead)
		must(t, err)
		must(t, policyReceipts(m.Before, now, ""))
		if epoch == previous.Epoch || now.Epoch != epoch || now.Controller != m.Before.Controller {
			t.Fatal("startup lost epoch/controller fence")
		}
		if !reflect.DeepEqual(heldVolume(held, path), heldVolume(copyDataSnapshot(t, path), path)) {
			t.Fatal("startup mutated volume")
		}
	}
	previous, err := policyState(dead)
	must(t, err)
	f := copyDataFixture(t, path, keys, &previous, true)
	if stale, err := f.authority.AuthenticateData(t.Context(), f.conn(keys.Owner), a.DataHello{Epoch: m.Intent.Epoch, Binding: m.Intent.Owner}); !errors.Is(err, a.ErrUnauthorized) || stale != nil {
		t.Fatal("old epoch binding was not fenced", err)
	}
	s := copyDataOwner(t, f, &m.Intent.Owner)
	if s.binding.Prepare == m.Intent.Owner.Prepare || s.binding.Attachment == m.Intent.Owner.Attachment {
		t.Fatal("owner not replaced")
	}
	control := copyDataControl(t, f, s)
	got := control(w.BeginCopy, "")
	want := w.RollbackCopy
	if strings.HasSuffix(kind, "-tail") {
		want = w.ResumeCopyDirectory
	}
	if got.Intent.ID != m.Intent.ID || got.Intent.Root != m.Intent.Root || got.Pending != want {
		t.Fatal("fresh owner lost exact pending intent")
	}
	f.wantError(s, caller(0, 0), w.LookupRequest{Parent: 1, Name: []byte("payload")}, unix.EBUSY)
	control(want, m.Intent.ID)
	if kind == "sealed-tail" {
		control(w.RollbackCopy, m.Intent.ID)
	}
	if kind != "completed-tail" {
		control(w.FinishCopy, m.Intent.ID)
	}
	rollback := kind == "rename" || kind == "root-metadata" || kind == "sealed-tail"
	if rollback {
		metadata, err := copyRootCleanup(int(s.root.Fd()))
		must(t, err)
		if metadata != m.Intent.Initial || !reflect.DeepEqual(copyDataXattrs(t, int(s.root.Fd())), m.Manifest.Root.Xattrs) {
			t.Fatal("private recovery did not restore 0555/nonroot metadata, times and xattrs")
		}
		if _, err := os.Lstat(filepath.Join(path, "volumes", "data", "tree")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("owned publication survived rollback", err)
		}
	} else {
		metadata, err := copyRootCleanup(int(s.root.Fd()))
		must(t, err)
		want := m.Intent.Cleanup
		want.Manifest, want.Staging = a.Ext4ObjectV1{}, a.Ext4ObjectV1{}
		if metadata != want || !reflect.DeepEqual(copyDataXattrs(t, int(s.root.Fd())), held[filepath.Join(path, "volumes", "data")].Xattrs) {
			t.Fatal("directory tail changed published root metadata/xattrs")
		}
		payload, err := os.ReadFile(filepath.Join(path, "volumes", "data", "tree", "child"))
		must(t, err)
		if string(payload) != "copied payload\n" {
			t.Fatal("tail rolled back published data")
		}
	}
	if _, err := os.Lstat(filepath.Join(path, "volumes", "data", copyTransactionPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("finished recovery retained transaction", err)
	}
	fresh := control(w.BeginCopy, "").Intent
	if fresh.ID == m.Intent.ID {
		t.Fatal("new Begin reused completed intent")
	}
	copyDataRetry(t, f, s, control, fresh)
	retirementCheckACK(t, root, ackBytes)
	t.Logf("%s: real syscall -> classified obligation -> SIGKILL/Wait -> anchored OpenExpected twice -> Retire/ReplacePrepare -> private recovery", kind)
}

func heldVolume(all map[string]copyDataSnapshotEntry, root string) map[string]copyDataSnapshotEntry {
	out := map[string]copyDataSnapshotEntry{}
	for name, value := range all {
		if strings.HasPrefix(name, filepath.Join(root, "volumes")+string(os.PathSeparator)) {
			out[name] = value
		}
	}
	return out
}

// Descriptor-confined, bounded and NOATIME: observing COMPLETED must not change
// the root timestamps that its startup preflight authenticates.
type copyDataSnapshotEntry struct {
	Stat   unix.Stat_t
	Digest [32]byte
	Xattrs *c.XattrSnapshot
}

func copyDataSnapshot(t *testing.T, path string) map[string]copyDataSnapshotEntry {
	t.Helper()
	root, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NOATIME|unix.O_CLOEXEC, 0)
	must(t, err)
	defer unix.Close(root)
	result := map[string]copyDataSnapshotEntry{}
	total := 0
	var walk func(string, int)
	walk = func(name string, depth int) {
		if depth > 8 || len(result) >= 64 {
			t.Fatal("copy census entry/depth bound")
		}
		fd, err := unix.Openat2(root, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NONBLOCK | unix.O_NOFOLLOW | unix.O_NOATIME | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
		must(t, err)
		file := os.NewFile(uintptr(fd), "copy-census")
		defer file.Close()
		st, err := stat(fd)
		must(t, err)
		entry := copyDataSnapshotEntry{Stat: st, Xattrs: copyDataXattrs(t, fd)}
		entry.Stat.Atim = unix.Timespec{} // ACK readers outside this census may read payload
		if st.Mode&unix.S_IFMT == unix.S_IFREG {
			if st.Size < 0 || st.Size > policyLimit {
				t.Fatal("copy census file bound")
			}
			raw, err := io.ReadAll(io.LimitReader(file, policyLimit+1))
			must(t, err)
			total += len(raw)
			if int64(len(raw)) != st.Size || total > 2*policyLimit {
				t.Fatal("copy census byte bound")
			}
			entry.Digest = sha256.Sum256(raw)
		} else if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			t.Fatal("special file in copy census")
		}
		result[filepath.Join(path, name)] = entry
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			children, err := file.ReadDir(65)
			if err != nil && !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			if len(children) > 64 {
				t.Fatal("copy census directory bound")
			}
			for _, child := range children {
				walk(filepath.Join(name, child.Name()), depth+1)
			}
		}
	}
	walk(".", 0)
	return result
}

func copyDataRetry(t *testing.T, f *fixture, s *Session, control func(w.PrepareAction, a.ID) w.PrepareReply, fresh a.CopyIntent) {
	t.Helper()
	fd := int(s.root.Fd())
	st, err := stat(fd)
	must(t, err)
	var fs unix.Statfs_t
	must(t, unix.Fstatfs(fd, &fs))
	metadata := &c.RootMetadata{Filesystem: fs.Fsid.Val, Device: st.Dev, Inode: st.Ino, UID: st.Uid, GID: st.Gid, Mode: st.Mode & 07777, Xattrs: copyDataXattrs(t, fd)}
	rootIdentity, err := ext4Identity(fd)
	must(t, err)
	if fresh.Phase != a.CopyBegun || fresh.InitialCaptured || fresh.Owner != s.binding || fresh.Root.Root != rootIdentity {
		t.Fatal("retry did not begin with the exact owner/root")
	}
	fresh = control(w.BindCopyTransaction, fresh.ID).Intent
	transactionIdentity, err := copyIdentityAt(fd, copyTransactionPath)
	must(t, err)
	if fresh.Phase != a.CopyBound || !fresh.InitialCaptured || fresh.Transaction != transactionIdentity {
		t.Fatal("retry did not capture metadata and bind the actual transaction")
	}
	tx := filepath.Join(f.path, "volumes", "data", copyTransactionPath)
	must(t, os.Mkdir(filepath.Join(tx, "staging"), 0700))
	must(t, os.Mkdir(filepath.Join(tx, "staging", "retry"), 0700))
	must(t, os.WriteFile(filepath.Join(tx, "staging", "retry", "child"), []byte("retry payload"), 0600))
	manifest := c.Manifest{Version: 4, Intent: fresh.ID, Physical: fresh.Root, Root: metadata, Entries: []c.Entry{}}
	for _, name := range []string{"retry", "retry/child"} {
		identity, err := copyIdentityAt(fd, copyTransactionPath+"/staging/"+name)
		must(t, err)
		manifest.Entries = append(manifest.Entries, c.Entry{Path: name, Identity: identity})
	}
	must(t, c.ValidateManifest(manifest))
	raw, err := json.Marshal(manifest)
	must(t, err)
	must(t, os.WriteFile(filepath.Join(tx, "manifest.json"), raw, 0600))
	must(t, unix.Syncfs(fd))
	control(w.SealManifest, fresh.ID)
	must(t, unix.Fchown(fd, 0, 0))
	must(t, unix.Fchmod(fd, 0700))
	transaction := f.call(s, caller(0, 0), w.LookupRequest{Parent: 1, Name: []byte(copyTransactionPath)}).(w.LookupReply).Entry
	staging := f.call(s, caller(0, 0), w.LookupRequest{Parent: transaction.Node, Name: []byte("staging")}).(w.LookupReply).Entry
	f.call(s, caller(0, 0), w.RenameRequest{OldParent: staging.Node, NewParent: 1, OldName: []byte("retry"), NewName: []byte("retry"), Flags: w.RenameNoReplace})
	must(t, unix.Fchown(fd, int(metadata.UID), int(metadata.GID)))
	must(t, unix.Fchmod(fd, metadata.Mode))
	final, err := copyRootCleanup(fd)
	must(t, err)
	control(w.StartCleanup, fresh.ID)
	control(w.FinishCopy, fresh.ID)
	got, err := copyRootCleanup(fd)
	must(t, err)
	if got != final || !reflect.DeepEqual(copyDataXattrs(t, fd), metadata.Xattrs) {
		t.Fatal("retry cleanup changed root metadata/xattrs")
	}
	payload, err := os.ReadFile(filepath.Join(f.path, "volumes", "data", "retry", "child"))
	must(t, err)
	if string(payload) != "retry payload" {
		t.Fatal("retry payload missing")
	}
}

func copyDataRefuseOpen(t *testing.T, path string, cfg a.Config, trust *storageauthoritytest.Fixture) {
	t.Helper()
	census := copyDataSnapshot(t, path)
	for repeat := 0; repeat < 2; repeat++ {
		for _, exact := range []bool{false, true} {
			var reopened *a.Authority
			var err error
			if exact {
				reopened, err = trust.OpenExpected(cfg, trust.Expected.ExpectedStartup)
			} else {
				reopened, err = trust.Open(cfg)
			}
			if reopened != nil {
				_ = reopened.Close()
				t.Fatal("refused state reopened")
			}
			if !errors.Is(err, a.ErrRepairRequired) {
				t.Fatal("not repair refusal", err)
			}
			if !reflect.DeepEqual(census, copyDataSnapshot(t, path)) {
				t.Fatal("failed Open mutated whole census")
			}
		}
	}
}
func copyDataRefusedStartup(t *testing.T, path string, root *os.File, keys copyDataKeys, m copyDataManifest) {
	t.Helper()
	registry, err := NewRegistry(new(sync.Mutex))
	must(t, err)
	cfg := a.Config{Root: root, DeviceID: m.Before.Store.DeviceID, BootstrapKey: keys.Bootstrap, Barrier: registry.Barrier, CopyRecoveryPreflight: PreflightCopyRecovery}
	tx := filepath.Join(path, "volumes", "data", copyTransactionPath)
	manifest := filepath.Join(tx, "manifest.json")
	raw, err := os.ReadFile(manifest)
	must(t, err)
	must(t, os.WriteFile(manifest, append(append([]byte{}, raw...), '\n'), 0600))
	copyDataRefuseOpen(t, path, cfg, keys.Lifecycle)
	must(t, os.WriteFile(manifest, raw, 0600))
	foreign := filepath.Join(tx, "staging", "zz-foreign")
	must(t, os.WriteFile(foreign, []byte("unowned"), 0600))
	copyDataRefuseOpen(t, path, cfg, keys.Lifecycle)
	must(t, os.Remove(foreign))
	must(t, unix.Syncfs(int(root.Fd())))
}
func copyDataKnownIO(t *testing.T, fault unix.Errno, generic bool) {
	t.Helper()
	path := identity102Root(t)
	keys := newCopyDataKeys(t)
	f := copyDataFixture(t, path, keys, nil, false)
	s, m, body := copyDataSetup(t, f, "rename")
	marker := "copy-operation"
	if generic {
		body = w.MkdirRequest{Parent: 1, Name: []byte("generic-data"), Mode: 0700}
		marker = "data-uncertain"
	}
	f.expectFaults = true
	calls := 0
	f.registry.syncOps.syncfs = func(fd int) error {
		calls++
		if err := unix.Syncfs(fd); err != nil {
			return err
		}
		return fault
	}
	g, err := f.authority.Admit(s.principal, s.binding.Volume, true)
	must(t, err)
	f.sequence[s]++
	_, err = s.Dispatch(g, w.Request{Sequence: f.sequence[s], Auth: caller(0, 0), Body: body})
	g.Release()
	if !errors.Is(err, ErrVolumeFault) || !errors.Is(err, fault) || calls != 1 {
		t.Fatal("lost known IO fault", err, calls)
	}
	f.registry.syncOps = platformSyncOperations()
	_ = f.registry.Barrier(s.binding, f.volume)
	if !s.closed || len(s.nodes) != 0 || len(s.handles) != 0 || len(f.registry.objects) != 0 {
		t.Fatal("known IO drain retained resources")
	}
	_ = f.authority.Close()
	census, err := policyCensus(f.root)
	must(t, err)
	if len(census[marker]) == 0 || len(census["io-quarantined"]) == 0 {
		t.Fatal("known IO lost durable refusal evidence")
	}
	registry, err := NewRegistry(new(sync.Mutex))
	must(t, err)
	copyDataRefuseOpen(t, path, a.Config{Root: f.root, DeviceID: m.Before.Store.DeviceID, BootstrapKey: keys.Bootstrap, Barrier: registry.Barrier, CopyRecoveryPreflight: PreflightCopyRecovery}, f.lifecycle)
}

func TestNativeCopyDataRecoveryHelpers(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("requires native Linux root")
	}
	for _, kind := range []string{"rename", "root-metadata", "sealed-tail", "cleaning-tail", "completed-tail"} {
		if _, _, err := copyDataKind(kind); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := copyDataKind("generic"); err == nil {
		t.Fatal("open cut selection")
	}
	if copyDataValidate(copyDataManifest{}, copyDataProof{}, nil) == nil {
		t.Fatal("accepted unbound proof")
	}
	// Physical refusal cases share one real SEALED fixture, no synthetic identity,
	// fabricated digest, private operation callback or child cleanup shortcut.
	path := identity102Root(t)
	keys := newCopyDataKeys(t)
	f := copyDataFixture(t, path, keys, nil, false)
	s, m, _ := copyDataSetup(t, f, "rename")
	// A narrow-shape request with a stale parent keeps its ordinary errno; it
	// must neither gain rollback authority nor poison a healthy sealed intent.
	for _, parents := range [][2]w.NodeID{{^w.NodeID(0), 1}, {1, ^w.NodeID(0)}} {
		f.wantError(s, caller(0, 0), w.RenameRequest{OldParent: parents[0], NewParent: parents[1], OldName: []byte("tree"), NewName: []byte("tree"), Flags: w.RenameNoReplace}, unix.ESTALE)
	}
	tx := filepath.Join(path, "volumes", "data", copyTransactionPath)
	manifestPath := filepath.Join(tx, "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	must(t, err)
	for _, change := range []string{"altered-manifest", "foreign-staged"} {
		if change == "altered-manifest" {
			must(t, os.WriteFile(manifestPath, append(append([]byte{}, raw...), '\n'), 0600))
		} else {
			must(t, os.WriteFile(filepath.Join(tx, "staging", "zz-foreign"), []byte("never owned"), 0600))
		}
		before := copyDataSnapshot(t, path)
		for repeat := 0; repeat < 2; repeat++ {
			err := PreflightCopyRecovery(f.volume, m.Before.Store.DeviceID, a.CopyOperationRollback, m.Intent)
			if err == nil {
				t.Fatal("accepted", change)
			}
			if !reflect.DeepEqual(before, copyDataSnapshot(t, path)) {
				t.Fatal("refusal mutated whole census", change)
			}
		}
		if change == "altered-manifest" {
			must(t, os.WriteFile(manifestPath, raw, 0600))
		} else {
			must(t, os.Remove(filepath.Join(tx, "staging", "zz-foreign")))
		}
	}
	must(t, PreflightCopyRecovery(f.volume, m.Before.Store.DeviceID, a.CopyOperationRollback, m.Intent))
	// Matching hardlink under a replaced public ancestor is NOT deletion authority.
	public := filepath.Join(path, "volumes", "data")
	must(t, os.Mkdir(filepath.Join(public, "tree"), 0700))
	must(t, os.Link(filepath.Join(tx, "staging", "tree", "child"), filepath.Join(public, "tree", "child")))
	must(t, os.WriteFile(filepath.Join(public, "unknown"), []byte("preserve unknown"), 0600))
	foreign, err := copyIdentityAt(int(f.volume.Fd()), "tree")
	must(t, err)
	alias, err := copyIdentityAt(int(f.volume.Fd()), "tree/child")
	must(t, err)
	if foreign == m.Manifest.Entries[0].Identity || alias != m.Manifest.Entries[1].Identity {
		t.Fatal("not a real replaced ancestor/matching alias")
	}
	control := copyDataControl(t, f, s)
	control(w.RollbackCopy, m.Intent.ID)
	control(w.FinishCopy, m.Intent.ID)
	for name, want := range map[string]string{"tree/child": "copied payload\n", "unknown": "preserve unknown"} {
		raw, err := os.ReadFile(filepath.Join(public, name))
		must(t, err)
		if string(raw) != want {
			t.Fatal("rollback removed unowned public content", name)
		}
	}
	current, err := copyIdentityAt(int(f.volume.Fd()), "tree")
	must(t, err)
	if current != foreign {
		t.Fatal("rollback replaced foreign ancestor")
	}
	current, err = copyIdentityAt(int(f.volume.Fd()), "tree/child")
	must(t, err)
	if current != alias {
		t.Fatal("rollback replaced matching hardlink below foreign ancestor")
	}
	for _, fault := range []unix.Errno{unix.EIO, unix.ENOSPC} {
		copyDataKnownIO(t, fault, false)
	}
	copyDataKnownIO(t, unix.EIO, true)
	// Malformed framing remains a helper assertion, never process-death evidence.
	if policyReceive(bytes.NewReader([]byte{0, 0, 0, 0}), new(copyDataProof)) == nil {
		t.Fatal("accepted empty proof frame")
	}
}

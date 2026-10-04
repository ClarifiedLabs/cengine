//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	"dev.cengine/guest/internal/storageauthoritytest"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

const (
	policyWorkerEnv  = "CENGINE_NATIVE_DURABILITY_POLICY_WORKER"
	policyLimit      = 1 << 20
	policyFileLimit  = 256 << 10
	policyEntryLimit = 16
	policyACK        = "externally-acknowledged-prefix\n"
	policySuffix     = "selected-write\n"
)

type policyManifest struct {
	Lifecycle storageauthoritytest.Fixture
	Kind      string
	Bootstrap ed25519.PublicKey
	Before    a.Snapshot
	Stable    a.Receipt
	Binding   a.Binding
	Operation a.ID
	Sequence  uint64
	ACK       []byte
}

type policyProof struct {
	Kind            string
	Binding         a.Binding
	Operation       a.ID
	Sequence        uint64
	Epoch           a.ID
	Controller      a.Controller
	Revision        uint64
	RealSync        bool
	Closed          int
	ResourcesClosed bool
	Census          [32]byte
}

// Match the authority's durable DATA marker field order; the proof decoder
// deliberately rejects noncanonical encodings, including reordered fields.
type policyDataMarker struct {
	Version    int          `json:"version"`
	Epoch      a.ID         `json:"epoch"`
	Controller a.Controller `json:"controller"`
	Binding    a.Binding    `json:"binding"`
	Sequence   uint64       `json:"sequence"`
}

type policyCompletion struct {
	Sequence uint64
	Count    uint32
	Receipt  a.Receipt
}

// Fixed worker entry point; no fault-test tag, simulated barrier, or private key
// crosses this protocol. Descriptors 3/4/5 are exclusively inherited from our
// parent (owned root, command pipe, proof pipe). Stdio is not a proof channel.
func TestNativeDurabilityPolicyWorker(t *testing.T) {
	kind := os.Getenv(policyWorkerEnv)
	if kind == "" {
		return
	}
	if kind != "data" && kind != "barrier" {
		t.Fatal("invalid worker selection")
	}
	root, commands, proofs := os.NewFile(3, "policy-root"), os.NewFile(4, "policy-commands"), os.NewFile(5, "policy-proofs")
	defer root.Close()
	defer commands.Close()
	defer proofs.Close()
	must(t, policyPipe(commands, unix.O_RDONLY))
	must(t, policyPipe(proofs, unix.O_WRONLY))
	left, err := stat(int(commands.Fd()))
	must(t, err)
	right, err := stat(int(proofs.Fd()))
	must(t, err)
	if left.Dev == right.Dev && left.Ino == right.Ino {
		t.Fatal("aliased protocol pipes")
	}
	rst, err := stat(int(root.Fd()))
	must(t, err)
	if rst.Mode&unix.S_IFMT != unix.S_IFDIR || rst.Uid != uint32(os.Geteuid()) {
		t.Fatal("unowned fixture root")
	}
	// The fixture opens the inherited capability, not an environment pathname.
	f := newFixtureAt(t, "/proc/self/fd/3")
	stableSession, stableRoot := f.session(a.ReadWrite)
	created := f.call(stableSession, caller(1001, 1001), w.CreateRequest{Parent: stableRoot.Node, Name: []byte("payload"), Flags: w.OpenReadWrite, Mode: 0600}).(w.CreateReply)
	written := f.call(stableSession, grantAuth, w.WriteRequest{Node: created.Entry.Node, Handle: created.Opened.Handle, Data: []byte(policyACK)}).(w.WriteReply)
	if written.Written != uint32(len(policyACK)) {
		t.Fatal("short acknowledged write")
	}
	stable, err := f.authority.Retire(t.Context(), f.control, a.RetireRequest{Operation: newID(t), Store: f.storeID, Volume: f.volumeID, Attachment: stableSession.binding.Attachment, Launch: stableSession.binding.Launch})
	must(t, err)
	if !stableSession.closed || len(stableSession.handles) != 0 || len(stableSession.nodes) != 0 || len(f.registry.objects) != 0 {
		t.Fatal("stable receipt lacked actual resource drain")
	}
	s, entry := f.session(a.ReadWrite)
	payload := f.call(s, caller(1001, 1001), w.LookupRequest{Parent: entry.Node, Name: []byte("payload")}).(w.LookupReply)
	opened := f.call(s, caller(1001, 1001), w.OpenRequest{Node: payload.Entry.Node, Flags: w.OpenReadWrite}).(w.OpenReply)
	before, err := f.authority.Query(f.control)
	must(t, err)
	m := policyManifest{Lifecycle: *f.lifecycle, Kind: kind, Bootstrap: f.bootstrap, Before: before, Stable: stable, Binding: s.binding, Operation: newID(t), Sequence: f.sequence[s] + 1, ACK: []byte(policyACK)}
	if kind == "barrier" {
		m.Sequence = 0
	}
	must(t, policySend(proofs, m))
	policyCommand(t, commands, 'A') // parent has durably journaled the public ACK
	fds := []int{int(s.root.Fd()), int(s.metadataFD.Fd())}
	for _, h := range s.handles {
		fds = append(fds, h.fd)
	}
	for _, n := range s.nodes {
		fds = append(fds, n.fd)
	}
	for _, o := range f.registry.objects {
		fds = append(fds, o.fd)
	}
	calls := 0
	f.registry.syncOps.syncfs = func(fd int) error {
		calls++
		if calls != 1 {
			t.Error("more than one selected syncfs")
			return unix.EIO
		}
		// Success is REAL and precedes the hold. The policy marker is still live.
		if err := unix.Syncfs(fd); err != nil {
			return err
		}
		p := policyProof{Kind: kind, Binding: s.binding, Operation: m.Operation, Sequence: m.Sequence, Epoch: before.Epoch, Controller: before.Controller, RealSync: true}
		if kind == "data" {
			if f.registry.barrierBinding != nil || f.sequence[s] != m.Sequence || s.closed {
				t.Error("wrong DATA seam")
				return unix.EIO
			}
		} else {
			if f.registry.barrierBinding == nil || *f.registry.barrierBinding != s.binding || !s.closed || len(s.handles) != 0 || len(s.nodes) != 0 || len(f.registry.sessions) != 0 || len(f.registry.objects) != 0 {
				t.Error("wrong barrier/resource seam")
				return unix.EIO
			}
			for _, closed := range fds {
				if _, err := stat(closed); !errors.Is(err, unix.EBADF) {
					t.Error("barrier retained descriptor")
					return unix.EIO
				}
			}
			p.Closed, p.ResourcesClosed = len(fds), true
		}
		census, err := policyCensus(root)
		if err != nil {
			t.Error(err)
			return err
		}
		state, err := policyState(census)
		if err != nil {
			t.Error(err)
			return err
		}
		p.Revision, p.Census = state.Revision, policyDigest(census)
		if err := policyValidateProof(m, p, census); err != nil {
			t.Error(err)
			return err
		}
		if err := policySend(proofs, p); err != nil {
			t.Error(err)
			return err
		}
		policyCommand(t, commands, 'R') // uncertain case never releases this hold
		return nil
	}
	completion := policyCompletion{}
	if kind == "data" {
		body := f.call(s, grantAuth, w.WriteRequest{Node: payload.Entry.Node, Handle: opened.Opened.Handle, Offset: uint64(len(policyACK)), Data: []byte(policySuffix)}).(w.WriteReply)
		completion.Sequence, completion.Count = f.sequence[s], body.Written
	} else {
		completion.Receipt, err = f.authority.Retire(t.Context(), f.control, a.RetireRequest{Operation: m.Operation, Store: m.Binding.Store, Volume: m.Binding.Volume, Attachment: m.Binding.Attachment, Launch: m.Binding.Launch})
		must(t, err)
	}
	must(t, policySend(proofs, completion))
	// Completed controls die just as abruptly: no Authority.Close or test cleanup.
	policyCommand(t, commands, '!')
	t.Fatal("parent must SIGKILL, not release final hold")
}

// Process-death policy only: Linux and ext4 remain alive. This is deliberately
// not a VM power-loss, Docker, PREPARE, or full durability certification.
func TestNativeDurabilityPolicyProcessDeath(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires Linux root and real ext4 storageidentity capabilities")
	}
	for _, kind := range []string{"data", "barrier"} {
		t.Run(kind, func(t *testing.T) {
			for _, outcome := range []string{"uncertain", "completed"} {
				t.Run(outcome, func(t *testing.T) { policyProcessDeath(t, kind, outcome == "completed") })
			}
		})
	}
}

func policyProcessDeath(t *testing.T, kind string, completed bool) {
	t.Helper()
	path, err := os.MkdirTemp("", "native-policy-")
	must(t, err)
	joined := true // no child exists yet
	t.Cleanup(func() {
		if joined {
			must(t, os.RemoveAll(path))
		} else {
			t.Logf("unjoined child: retained owned scratch %s", path)
		}
	})
	root, err := os.Open(path)
	must(t, err)
	defer root.Close()
	var fs unix.Statfs_t
	must(t, unix.Fstatfs(int(root.Fd()), &fs))
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		t.Fatal("TMPDIR must be actual ext4")
	}
	commands, commandWriter, err := os.Pipe()
	must(t, err)
	proofReader, proofs, err := os.Pipe()
	must(t, err)
	defer commands.Close()
	defer commandWriter.Close()
	defer proofReader.Close()
	defer proofs.Close()
	binaryPath, err := os.Executable()
	must(t, err)
	cmd := exec.Command(binaryPath, "-test.run=^TestNativeDurabilityPolicyWorker$", "-test.count=1", "-test.timeout=50s")
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, policyWorkerEnv+"=") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, policyWorkerEnv+"="+kind)
	cmd.ExtraFiles = []*os.File{root, commands, proofs}
	// Neither unbounded CombinedOutput nor the child's stdout can become proof.
	capture := new(policyOutput)
	cmd.Stdout, cmd.Stderr = capture, capture
	cmd.WaitDelay = 2 * time.Second
	pidfd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, PidFD: &pidfd}
	started, done := make(chan error, 1), make(chan error, 1)
	go func() {
		runtime.LockOSThread() // PDEATHSIG is tied to this creating thread
		defer runtime.UnlockOSThread()
		if err := cmd.Start(); err != nil {
			started <- err
			return
		}
		started <- nil
		done <- cmd.Wait() // sole genuine Wait; neither EOF nor deadline is death
		if cmd.ProcessState == nil {
			select {}
		} // retain creating thread if unjoined
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
			case <-time.After(10 * time.Second):
				t.Error("owned worker unjoined (not evidence of death)")
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
		t.Fatal("owned worker missing pidfd")
	}
	must(t, commands.Close())
	must(t, proofs.Close())
	must(t, proofReader.SetReadDeadline(time.Now().Add(40*time.Second)))
	must(t, commandWriter.SetWriteDeadline(time.Now().Add(40*time.Second)))
	var m policyManifest
	must(t, policyReceive(proofReader, &m))
	must(t, policyValidateManifest(m, kind))
	st, err := stat(int(root.Fd()))
	must(t, err)
	if m.Before.Store.Root != (a.RootIdentity{Device: st.Dev, Inode: st.Ino}) {
		t.Fatal("manifest belongs to another root")
	}
	initial, err := policyCensus(root)
	must(t, err)
	initialState, err := policyState(initial)
	must(t, err)
	if !reflect.DeepEqual(initialState, m.Before) {
		t.Fatal("manifest does not match durable predecessor")
	}
	// The ACK journal is parent-owned, outside the authority registry, and fsynced
	// (including its directory) before authorizing any selected operation.
	ack, err := os.OpenFile(filepath.Join(path, "parent-ack.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	must(t, err)
	must(t, policySend(ack, m))
	must(t, ack.Sync())
	must(t, ack.Close())
	must(t, root.Sync())
	_, err = commandWriter.Write([]byte{'A'})
	must(t, err)
	var proof policyProof
	must(t, policyReceive(proofReader, &proof))
	cut, err := policyCensus(root)
	must(t, err)
	must(t, policyValidateProof(m, proof, cut))
	policyLogCensus(t, "held-after-real-syncfs", cut)
	var completion policyCompletion
	if completed {
		_, err = commandWriter.Write([]byte{'R'})
		must(t, err)
		must(t, policyReceive(proofReader, &completion))
		cut, err = policyCensus(root)
		must(t, err)
		must(t, policyValidateCompletion(m, completion, cut))
	}
	must(t, unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0))
	select {
	case err = <-done:
		joined = cmd.ProcessState != nil
		if !policyKilled(err, cmd.ProcessState) {
			t.Fatalf("expected actual SIGKILL/Wait, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SIGKILL wait deadline is NOT proof of death")
	}
	dead, err := policyCensus(root)
	must(t, err)
	if !reflect.DeepEqual(cut, dead) {
		t.Fatal("registry changed between acknowledged hold and actual death")
	}
	payload, err := policyReadPath(root, "volumes/data/payload", policyFileLimit)
	must(t, err)
	if !bytes.HasPrefix(payload, m.ACK) {
		t.Fatal("lost acknowledged payload prefix")
	}
	if completed && kind == "data" && string(payload) != policyACK+policySuffix {
		t.Fatal("completed write payload missing")
	}
	registry, err := NewRegistry(new(sync.Mutex))
	must(t, err)
	cfg := a.Config{Root: root, DeviceID: "isolated-ext4-test", BootstrapKey: m.Bootstrap, Barrier: registry.Barrier}
	if !completed {
		// Repeat both APIs: every failed real open must release its flock and leave
		// ALL bounded regular-file registry bytes, not just the marker, unchanged.
		for i := 0; i < 2; i++ {
			for _, exact := range []bool{false, true} {
				before, err := policyCensus(root)
				must(t, err)
				var reopened *a.Authority
				if exact {
					reopened, err = m.Lifecycle.OpenExpected(cfg, m.Lifecycle.Expected.ExpectedStartup)
				} else {
					reopened, err = m.Lifecycle.Open(cfg)
				}
				if reopened != nil {
					_ = reopened.Close()
					t.Fatal("uncertain registry reopened")
				}
				if !errors.Is(err, a.ErrRepairRequired) {
					t.Fatalf("Open exact=%v: %v", exact, err)
				}
				after, err := policyCensus(root)
				must(t, err)
				if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(dead, after) {
					t.Fatal("failed Open changed registry bytes")
				}
				must(t, policyValidateProof(m, proof, after))
				policyLogCensus(t, fmt.Sprintf("refused-open-%d-exact-%v", i, exact), after)
			}
		}
		return
	}
	// Completed controls perform both real APIs, each with its fresh predecessor.
	previous, err := policyState(dead)
	must(t, err)
	for _, exact := range []bool{false, true} {
		pre, err := policyCensus(root)
		must(t, err)
		policyLogCensus(t, fmt.Sprintf("before-completed-open-exact-%v", exact), pre)
		var reopened *a.Authority
		if exact {
			reopened, err = m.Lifecycle.OpenExpected(cfg, m.Lifecycle.Expected.ExpectedStartup)
		} else {
			reopened, err = m.Lifecycle.Open(cfg)
		}
		must(t, err)
		if reopened == nil {
			t.Fatal("completed Open returned nil")
		}
		epoch := reopened.Epoch()
		must(t, reopened.Close())
		post, err := policyCensus(root)
		must(t, err)
		state, err := policyState(post)
		must(t, err)
		if state.Epoch == previous.Epoch || state.Epoch != epoch || state.Controller != previous.Controller || state.Revision != previous.Revision+1 {
			t.Fatal("completed reopen did not solely advance startup epoch/revision")
		}
		must(t, policyReceipts(previous, state, ""))
		policyLogCensus(t, fmt.Sprintf("after-completed-open-exact-%v", exact), post)
		previous = state
	}
}

func policyValidateManifest(m policyManifest, kind string) error {
	if m.Kind != kind || (kind != "data" && kind != "barrier") || len(m.Bootstrap) != ed25519.PublicKeySize || string(m.ACK) != policyACK || m.Before.Revision == 0 || m.Before.Epoch == "" || m.Operation == "" || m.Binding.Store != m.Before.Store.ID || m.Binding == (a.Binding{}) {
		return errors.New("malformed public manifest")
	}
	if (kind == "data") != (m.Sequence != 0) {
		return errors.New("wrong operation sequence")
	}
	stable, ok := m.Before.Attachments[m.Stable.Attachment]
	target, exists := m.Before.Attachments[m.Binding.Attachment]
	if !ok || stable.Receipt == nil || *stable.Receipt != m.Stable || m.Stable.Revision == 0 || stable.Phase != a.Drained || !exists || target.Binding != m.Binding || target.Phase != a.Active || target.Receipt != nil {
		return errors.New("missing real stable receipt or active target")
	}
	return nil
}

func policyValidateProof(m policyManifest, p policyProof, census map[string][]byte) error {
	if err := policyValidateManifest(m, m.Kind); err != nil {
		return err
	}
	if p.Kind != m.Kind || p.Binding != m.Binding || p.Operation != m.Operation || p.Sequence != m.Sequence || p.Epoch != m.Before.Epoch || p.Controller != m.Before.Controller || !p.RealSync || p.Census != policyDigest(census) {
		return errors.New("cut proof not bound to selected operation/census")
	}
	state, err := policyState(census)
	if err != nil {
		return err
	}
	if state.Epoch != m.Before.Epoch || state.Controller != m.Before.Controller || state.Store != m.Before.Store || state.Revision != p.Revision {
		return errors.New("cut changed predecessor identity")
	}
	if err := policyReceipts(m.Before, state, ""); err != nil {
		return err
	}
	target := state.Attachments[m.Binding.Attachment]
	if target.Binding != m.Binding || target.Receipt != nil {
		return errors.New("cut selected another binding or minted receipt")
	}
	if m.Kind == "data" {
		var marker policyDataMarker
		raw := census["data-uncertain"]
		if len(raw) == 0 || len(raw) > 2048 {
			return errors.New("missing/bounded DATA marker")
		}
		if err := policyJSON(raw, &marker); err != nil {
			return err
		}
		if marker.Version != 1 || marker.Epoch != p.Epoch || marker.Controller != p.Controller || marker.Binding != p.Binding || marker.Sequence != p.Sequence || p.Closed != 0 || p.ResourcesClosed || !reflect.DeepEqual(state, m.Before) {
			return errors.New("DATA marker/state mismatch")
		}
	} else {
		if string(census["barrier-uncertain"]) != "Uncertain authority IO or barrier: offline repair required.\n" || !p.ResourcesClosed || p.Closed < 5 || target.Phase != a.Retiring || target.Retirement != m.Operation || state.Revision != m.Before.Revision+1 {
			return errors.New("barrier not proven at actual resource-close cut")
		}
	}
	return nil
}

func policyValidateCompletion(m policyManifest, c policyCompletion, census map[string][]byte) error {
	for _, name := range []string{"data-uncertain", "barrier-uncertain", "uncertain", "io-quarantined", "commit-proof"} {
		if _, ok := census[name]; ok {
			return fmt.Errorf("completed operation retains %s", name)
		}
	}
	state, err := policyState(census)
	if err != nil {
		return err
	}
	if state.Epoch != m.Before.Epoch || state.Controller != m.Before.Controller {
		return errors.New("completion changed epoch/controller")
	}
	if m.Kind == "data" {
		if c.Sequence != m.Sequence || c.Count != uint32(len(policySuffix)) || c.Receipt != (a.Receipt{}) || !reflect.DeepEqual(state, m.Before) {
			return errors.New("missing exact completed DATA reply")
		}
		return policyReceipts(m.Before, state, "")
	}
	target := state.Attachments[m.Binding.Attachment]
	want := a.Receipt{Schema: a.SchemaVersion, Store: m.Binding.Store, Volume: m.Binding.Volume, Attachment: m.Binding.Attachment, Launch: m.Binding.Launch, Revision: m.Before.Revision + 2}
	if c.Sequence != 0 || c.Count != 0 || c.Receipt != want || target.Receipt == nil || *target.Receipt != want || target.Phase != a.Drained || target.Retirement != m.Operation || state.Revision != want.Revision {
		return errors.New("missing exact completed retirement receipt")
	}
	return policyReceipts(m.Before, state, m.Binding.Attachment)
}

func policyReceipts(before, after a.Snapshot, allowed a.ID) error {
	if len(before.Attachments) != len(after.Attachments) {
		return errors.New("attachment census changed")
	}
	for id, old := range before.Attachments {
		now, ok := after.Attachments[id]
		if !ok || now.Binding != old.Binding || (old.Receipt != nil && (now.Receipt == nil || *now.Receipt != *old.Receipt)) || (old.Receipt == nil && now.Receipt != nil && id != allowed) {
			return errors.New("earlier receipt changed or unselected receipt appeared")
		}
	}
	return nil
}

func policyState(census map[string][]byte) (a.Snapshot, error) {
	var state a.Snapshot
	raw := census["state.json"]
	if len(raw) == 0 {
		return state, errors.New("missing registry state")
	}
	err := json.Unmarshal(raw, &state) // disk state includes private journal fields, not private keys
	return state, err
}

// Full registry census, bounded in entries, per-file size, and aggregate bytes.
// Every component is opened beneath an owned descriptor without following links;
// directories, devices, sockets, FIFOs, hard links, and foreign owners fail closed.
func policyCensus(root *os.File) (map[string][]byte, error) {
	fd, err := unix.Openat2(int(root.Fd()), ".cengine-storage-authority", &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), "policy-registry")
	defer dir.Close()
	st, err := stat(fd)
	if err != nil {
		return nil, err
	}
	if st.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("foreign registry directory owner")
	}
	entries, err := dir.ReadDir(policyEntryLimit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > policyEntryLimit {
		return nil, errors.New("registry entry limit")
	}
	out, total := make(map[string][]byte), 0
	for _, entry := range entries {
		name := entry.Name()
		if len(name) > 128 || strings.ContainsAny(name, "/\n\r\x00") {
			return nil, errors.New("invalid registry filename")
		}
		data, err := policyReadPath(dir, name, policyFileLimit)
		if err != nil {
			return nil, err
		}
		total += len(data)
		if total > policyLimit {
			return nil, errors.New("registry aggregate limit")
		}
		out[name] = data
	}
	return out, nil
}

func policyReadPath(root *os.File, name string, limit int64) ([]byte, error) {
	fd, err := unix.Openat2(int(root.Fd()), name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NONBLOCK | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "policy-bounded-file")
	defer f.Close()
	st, err := stat(fd)
	if err != nil {
		return nil, err
	}
	// Payload is created as uid 1001 by the real identity worker; registry files
	// alone must be parent-owned. Neither case may be a special or linked file.
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size < 0 || st.Size > limit {
		return nil, errors.New("not a bounded singly-linked regular file")
	}
	if !strings.Contains(name, "/") && st.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("foreign registry file owner")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != st.Size || int64(len(data)) > limit {
		return nil, errors.New("file grew or exceeded bound")
	}
	return data, nil
}

func policyDigest(census map[string][]byte) [32]byte {
	raw, _ := json.Marshal(census) // deterministic sorted map keys; bounded by census
	return sha256.Sum256(raw)
}

func policyLogCensus(t *testing.T, where string, census map[string][]byte) {
	t.Helper()
	names := make([]string, 0, len(census))
	for name := range census {
		names = append(names, name)
	}
	sort.Strings(names)
	// Test output retains bounded textual evidence; never dump registry contents
	// or fixture CA/controller private keys. Scratch cleanup touches only our root.
	for _, name := range names {
		t.Logf("policy census %s file=%q bytes=%d sha256=%x", where, name, len(census[name]), sha256.Sum256(census[name]))
	}
}

func policyJSON(raw []byte, value any) error {
	if len(raw) == 0 || len(raw) > policyLimit {
		return errors.New("protocol size limit")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing protocol value")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(raw, canonical) {
		return errors.New("noncanonical or duplicate protocol fields")
	}
	return nil
}

func policySend(out io.Writer, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(raw) > policyLimit {
		return errors.New("protocol size limit")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(raw)))
	for _, part := range [][]byte{size[:], raw} {
		n, err := out.Write(part)
		if err != nil {
			return err
		}
		if n != len(part) {
			return io.ErrShortWrite
		}
	}
	return nil
}

func policyReceive(in io.Reader, value any) error {
	var size [4]byte
	if _, err := io.ReadFull(in, size[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n == 0 || n > policyLimit {
		return errors.New("protocol size limit")
	}
	raw := make([]byte, int(n))
	if _, err := io.ReadFull(in, raw); err != nil {
		return err
	}
	return policyJSON(raw, value)
}

func policyPipe(f *os.File, mode int) error {
	st, err := stat(int(f.Fd()))
	if err != nil {
		return err
	}
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFIFO || st.Uid != uint32(os.Geteuid()) || flags&unix.O_ACCMODE != mode {
		return errors.New("unowned or wrong-direction protocol pipe")
	}
	return nil
}

func policyCommand(t *testing.T, in *os.File, want byte) {
	t.Helper()
	var b [1]byte
	_, err := io.ReadFull(in, b[:])
	must(t, err)
	if b[0] != want {
		t.Fatal("out-of-order parent command")
	}
}

func policyKilled(err error, state *os.ProcessState) bool {
	var exit *exec.ExitError
	if !errors.As(err, &exit) || state == nil || exit.ProcessState != state {
		return false
	}
	status, ok := state.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGKILL
}

type policyOutput struct {
	mu   sync.Mutex
	data []byte
}

func (o *policyOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := len(p)
	if left := (16 << 10) - len(o.data); left > 0 {
		if len(p) > left {
			p = p[:left]
		}
		o.data = append(o.data, p...)
	}
	return n, nil
}
func (o *policyOutput) String() string { o.mu.Lock(); defer o.mu.Unlock(); return string(o.data) }

// Helper negatives are deliberately outside the fixed seven-name native parent
// selection (main, two nested kinds, four leaves); the gated worker is separate.
func TestDurabilityPolicyHelpers(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte("{}{}"), []byte(`{"Unknown":1}`), []byte(`{"Kind":"data","Kind":"barrier"}`), []byte(`{"kind":"data"}`), []byte(`null`), bytes.Repeat([]byte("x"), policyLimit+1)} {
		if policyJSON(raw, new(policyProof)) == nil {
			t.Fatal("accepted malformed/bounded proof")
		}
	}
	var frame [4]byte
	binary.BigEndian.PutUint32(frame[:], policyLimit+1)
	if policyReceive(bytes.NewReader(frame[:]), new(policyProof)) == nil {
		t.Fatal("accepted oversized frame")
	}
	if policyValidateProof(policyManifest{}, policyProof{}, nil) == nil {
		t.Fatal("accepted unbound empty proof")
	}
	// Valid synthetic proof is only a parser/validator control, never native crash
	// evidence. Reject each independently corrupted operation/ownership field.
	binding := a.Binding{Store: newID(t), Volume: newID(t), Attachment: newID(t), Launch: newID(t)}
	stable := a.Receipt{Attachment: newID(t), Revision: 3}
	before := a.Snapshot{Revision: 4, Store: a.Store{ID: binding.Store}, Epoch: newID(t), Attachments: map[a.ID]a.Attachment{
		stable.Attachment:  {Phase: a.Drained, Receipt: &stable},
		binding.Attachment: {Binding: binding, Phase: a.Active},
	}}
	manifest := policyManifest{Kind: "data", Bootstrap: bytes.Repeat([]byte{1}, ed25519.PublicKeySize), Before: before, Stable: stable, Binding: binding, Operation: newID(t), Sequence: 3, ACK: []byte(policyACK)}
	stateBytes, err := json.Marshal(before)
	must(t, err)
	markerBytes, err := json.Marshal(policyDataMarker{Version: 1, Epoch: before.Epoch, Controller: before.Controller, Binding: binding, Sequence: manifest.Sequence})
	must(t, err)
	validCensus := map[string][]byte{"lock": {}, "state.json": stateBytes, "data-uncertain": markerBytes}
	proof := policyProof{Kind: "data", Binding: binding, Operation: manifest.Operation, Sequence: manifest.Sequence, Epoch: before.Epoch, Controller: before.Controller, Revision: before.Revision, RealSync: true, Census: policyDigest(validCensus)}
	must(t, policyValidateProof(manifest, proof, validCensus))
	// A map sorts field names rather than using the on-disk struct order. It
	// used to break this positive control; keep the reordered form negative.
	reordered, err := json.Marshal(map[string]any{"version": 1, "epoch": before.Epoch, "controller": before.Controller, "binding": binding, "sequence": manifest.Sequence})
	must(t, err)
	if policyJSON(reordered, new(policyDataMarker)) == nil {
		t.Fatal("accepted noncanonical DATA marker order")
	}
	for _, corrupt := range []func(*policyProof){
		func(p *policyProof) { p.Kind = "barrier" },
		func(p *policyProof) { p.Binding.Attachment = stable.Attachment },
		func(p *policyProof) { p.Operation = "" },
		func(p *policyProof) { p.Sequence++ },
		func(p *policyProof) { p.Epoch = "" },
		func(p *policyProof) { p.Controller.Epoch++ },
		func(p *policyProof) { p.Revision++ },
		func(p *policyProof) { p.RealSync = false },
		func(p *policyProof) { p.Census = [32]byte{} },
		func(p *policyProof) { p.Closed = 1 },
		func(p *policyProof) { p.ResourcesClosed = true },
	} {
		bad := proof
		corrupt(&bad)
		if policyValidateProof(manifest, bad, validCensus) == nil {
			t.Fatal("accepted corrupted cut proof")
		}
	}
	validCensus["data-uncertain"] = []byte("{}")
	proof.Census = policyDigest(validCensus)
	if policyValidateProof(manifest, proof, validCensus) == nil {
		t.Fatal("accepted mismatched marker with matching census hash")
	}
	for _, err := range []error{nil, io.EOF, os.ErrDeadlineExceeded, &exec.ExitError{}} {
		if policyKilled(err, nil) {
			t.Fatal("non-Wait event treated as death")
		}
	}
	path := t.TempDir()
	root, err := os.Open(path)
	must(t, err)
	defer root.Close()
	if policyPipe(root, unix.O_RDONLY) == nil {
		t.Fatal("directory accepted as proof pipe")
	}
	r, out, err := os.Pipe()
	must(t, err)
	defer r.Close()
	defer out.Close()
	must(t, policyPipe(r, unix.O_RDONLY))
	must(t, policyPipe(out, unix.O_WRONLY))
	if policyPipe(r, unix.O_WRONLY) == nil {
		t.Fatal("wrong pipe direction accepted")
	}
	registry := filepath.Join(path, ".cengine-storage-authority")
	must(t, os.Mkdir(registry, 0700))
	file := filepath.Join(registry, "entry")
	must(t, os.WriteFile(file, []byte("bounded"), 0600))
	census, err := policyCensus(root)
	must(t, err)
	if string(census["entry"]) != "bounded" {
		t.Fatal("census lost regular bytes")
	}
	must(t, os.Symlink("entry", filepath.Join(registry, "link")))
	if _, err := policyCensus(root); err == nil {
		t.Fatal("census followed symlink")
	}
	must(t, os.Remove(filepath.Join(registry, "link")))
	must(t, os.Link(file, filepath.Join(registry, "hardlink")))
	if _, err := policyCensus(root); err == nil {
		t.Fatal("census accepted hardlink")
	}
	must(t, os.Remove(filepath.Join(registry, "hardlink")))
	must(t, os.Truncate(file, policyFileLimit+1))
	if _, err := policyCensus(root); err == nil {
		t.Fatal("census accepted oversized file")
	}
	must(t, os.Remove(file))
	must(t, unix.Mkfifo(file, 0600))
	if _, err := policyCensus(root); err == nil {
		t.Fatal("census accepted FIFO")
	}
	must(t, os.Remove(file))
	if os.Geteuid() == 0 {
		must(t, os.WriteFile(file, nil, 0600))
		must(t, os.Chown(file, 1, -1))
		if _, err := policyCensus(root); err == nil {
			t.Fatal("census accepted foreign ownership")
		}
		must(t, os.Remove(file))
	}
	for i := 0; i <= policyLimit/policyFileLimit; i++ {
		name := filepath.Join(registry, fmt.Sprint(i))
		must(t, os.WriteFile(name, nil, 0600))
		must(t, os.Truncate(name, policyFileLimit))
	}
	if _, err := policyCensus(root); err == nil {
		t.Fatal("census exceeded aggregate bound")
	}
	for i := 0; i <= policyLimit/policyFileLimit; i++ {
		must(t, os.Remove(filepath.Join(registry, fmt.Sprint(i))))
	}
	for i := 0; i <= policyEntryLimit; i++ {
		must(t, os.WriteFile(filepath.Join(registry, fmt.Sprint(i)), nil, 0600))
	}
	if _, err := policyCensus(root); err == nil {
		t.Fatal("census exceeded entry bound")
	}
}

//go:build cengine_native_faulttest && linux && (arm64 || amd64)

package supervisor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	f "dev.cengine/guest/internal/storagefuse"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
	s "dev.cengine/guest/internal/storageservice"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

func TestNativeSnapshot101PreBeginRenameUnlink(t *testing.T) { snapshot101QueueCase(t, "pre-begin", 3) }
func TestNativeSnapshot101RuntimePoolSaturation(t *testing.T) {
	// Both actual capacity profiles must complete. No serialized receipts or skip.
	snapshot101QueueCase(t, "full", 2)
	if !t.Failed() {
		snapshot101QueueCase(t, "spare", 3)
	}
}
func TestNativeSnapshot101DeadInitializerConsumers(t *testing.T) { snapshot101QueueCase(t, "death", 3) }
func TestNativeSnapshot101HungAcceptedGuard(t *testing.T)        { snapshot101QueueCase(t, "hung", 3) }

// Only four finite cuts: no general syscall dispatcher, fake guard, or authority.
func snapshot101QueueCase(t *testing.T, cut string, slots int) {
	if snapshot101IOFailed.Load() {
		t.Fatal("earlier RTM101 fixture failed; parent cleanup required")
	}
	t.Cleanup(func() {
		if t.Failed() {
			snapshot101IOFailed.Store(true)
		}
	})
	prepareV4Profile(t)
	var fs unix.Statfs_t
	prepareV4Must(t, unix.Statfs("/scratch", &fs))
	if uint64(fs.Blocks)*uint64(fs.Bsize) > 128<<20 || fs.Files > 4096 {
		t.Fatal("requires bounded real ext4")
	}
	base, err := os.MkdirTemp("/scratch", "snapshot101-queue-")
	prepareV4Must(t, err)
	safe := true
	t.Cleanup(func() {
		data, err := os.ReadFile("/proc/self/mountinfo")
		if err != nil {
			safe = false
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 4 && strings.HasPrefix(fields[4], base+"/") {
				safe = false
			}
		}
		if safe && !t.Failed() {
			prepareV4Must(t, os.RemoveAll(base))
		} else {
			t.Logf("retained snapshot101 queue evidence: %s", base)
		}
	})
	for _, name := range []string{"store/volumes", "rootfs", "mounts"} {
		prepareV4Must(t, os.MkdirAll(filepath.Join(base, name), 0700))
	}
	root, err := os.Open(filepath.Join(base, "store"))
	prepareV4Must(t, err)
	defer root.Close()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	prepareV4Must(t, err)
	bootstrap, err := p.NewBootstrapPublicKey(public)
	prepareV4Must(t, err)
	key, err := p.NewControllerKey()
	prepareV4Must(t, err)
	limits := d.DefaultLimits()
	limits.ReceiveFrames = slots
	cfg := s.Config{Root: root, DeviceUUID: prepareV4BackingUUID(t, int(root.Fd())), Store: prepareV4ID(t), Bootstrap: bootstrap, Now: time.Now().Add(-time.Minute), Lifetime: time.Hour, DataLimits: limits}
	current := nativeLifecycleGrant(t, cfg.Store, private, key)
	service, err := s.InitializeLifecycle(cfg, current)
	prepareV4Must(t, err)
	t.Cleanup(func() {
		if safe && !t.Failed() {
			prepareV4Must(t, service.Close())
		}
	})
	ready, err := service.Ready()
	prepareV4Must(t, err)
	v, other := prepareV4ID(t), prepareV4ID(t)
	hello, ownerKey := prepareV4Binding(t, ready, v)
	var runtimeHello [3]a.DataHello
	var keys [3]p.Key
	for i := range runtimeHello {
		k, err := p.NewAttachmentKey(p.RuntimeRole)
		prepareV4Must(t, err)
		pin, err := k.Fingerprint()
		prepareV4Must(t, err)
		volume := v
		if i == 2 {
			volume = other
		}
		runtimeHello[i] = a.DataHello{Epoch: ready.ServiceEpoch, Binding: a.Binding{Store: ready.Store.ID, Volume: volume, Attachment: prepareV4ID(t), Container: hello.Binding.Container, Launch: prepareV4ID(t), Key: a.Fingerprint(pin.String()), Role: a.RuntimeRole, Mode: a.ReadWrite}}
		keys[i] = k
	}
	targets := [2]a.Binding{runtimeHello[0].Binding, runtimeHello[1].Binding}
	gate, err := service.InstallNativeSnapshot101Queue(ready.ServiceEpoch, targets)
	prepareV4Must(t, err)
	// Always unblock this test-only scheduling cut on failure; it does NOT release
	// an authority guard. Production readLoop/dispatch must still join it.
	defer func() { _ = gate.Release(0); _ = gate.Release(1) }()
	controller, control, closeControl := prepareV4Control(t, service, ready, key)
	defer closeControl()
	for name, volume := range map[string]a.ID{"v": v, "w": other} {
		prepareV4Call(t, control, c.Request{CreateVolume: &a.CreateVolumeRequest{Operation: prepareV4ID(t), Store: ready.Store.ID, Volume: volume, Name: name}})
	}
	backing := filepath.Join(base, "store/volumes/v")
	for _, name := range []string{"p0", "p1"} {
		prepareV4Must(t, os.WriteFile(filepath.Join(backing, name), bytes.Repeat([]byte{'A'}, 4096), 0600))
	}
	for _, name := range []string{backing, filepath.Join(backing, "p0"), filepath.Join(backing, "p1")} {
		prepareV4Must(t, unix.Setxattr(name, "user.snapshot101", []byte("retained"), 0))
	}
	var mounts [3]*f.Mounted
	var joins [3]func() error
	for i := range mounts {
		mounts[i], joins[i] = snapshot101RuntimeMount(t, base, service, ready, controller, control, runtimeHello[i], keys[i])
		m := mounts[i]
		t.Cleanup(func() {
			select {
			case <-m.Done():
				return
			default:
			}
			if err := m.Close(); err != nil {
				t.Logf("exact local mount abort: %v", err)
			}
			select {
			case <-m.Done():
			default:
				safe = false
				t.Error("unjoined runtime mount")
			}
		})
	}
	pid := os.Getpid()
	progress := func(value string) {
		if os.Getpid() != pid {
			t.Fatal("W consumer replaced")
		}
		prepareV4Must(t, snapshot101Progress(mounts[2].Mountpoint(), value))
		prepareV4ExpectBytes(t, filepath.Join(base, "store/volumes/w/progress"), value)
	}
	progress("before-" + cut)
	mode := "namespace"
	if cut == "hung" {
		mode = "namespace-retire"
	}
	var consumers [2]*snapshot101Consumer
	for i := range consumers {
		consumers[i] = snapshot101StartConsumer(t, base, mounts[i].Mountpoint(), mode, i, &safe)
	}
	if consumers[0].proof.PID == consumers[1].proof.PID {
		t.Fatal("original V consumers not distinct")
	}
	before := snapshot101Image(t, backing)
	prepareV4Call(t, control, c.Request{ReservePrepare: &a.ReserveRequest{Operation: prepareV4ID(t), Prepare: hello.Binding.Prepare, Attachments: []a.Binding{hello.Binding}}})
	owner, _, join := prepareV4MountBootstrap(t, base, service, ready, controller, control, hello, ownerKey)
	prepareV4Must(t, gate.Arm())
	var admitted [2]d.NativeSnapshot101Wait
	preBegin := func() {
		for _, child := range consumers {
			child.send(t, 'a')
			child.receive(t, "armed")
			child.send(t, 'x')
		}
		admitted = snapshot101QueueEvents(t, gate.Admissions(), targets)
		state := gate.State()
		if state.Epoch != ready.ServiceEpoch || state.Targets != targets || state.Held != [2]bool{true, true} || state.ReceiveUsed != 2 || state.ReceiveCapacity != slots {
			t.Fatal("not actual charged live admissions", state)
		}
		t.Logf("before Begin actual held guards and receive reservations: %+v events=%+v", state, admitted)
		if !reflect.DeepEqual(before, snapshot101Image(t, backing)) {
			t.Fatal("pre-Begin parked namespace mutated")
		}
	}
	var hungReceipt *a.Receipt
	held := func() {
		// This callback is reachable ONLY after the real child ioctl BeginCopy ack.
		state := gate.State()
		if state.Held != [2]bool{true, true} || state.ReceiveUsed != 2 {
			t.Fatal("Begin ack lacked retained accepted guards", state)
		}
		if cut == "full" && state.ReceiveUsed != state.ReceiveCapacity {
			t.Fatal("not full at reserved PREPARE progress")
		}
		t.Logf("reserved PREPARE progressed before W, capacity=%d used=%d", state.ReceiveCapacity, state.ReceiveUsed)
		if cut == "hung" {
			// Separate authenticated controller connection, same pinned generation: a
			// pending Retire must not serialize Query behind its own unfinished call.
			_, retireControl, closeRetire := prepareV4Control(t, service, ready, key)
			defer closeRetire()
			request := a.RetireRequest{Operation: prepareV4ID(t), Store: targets[0].Store, Volume: v, Attachment: targets[0].Attachment, Launch: targets[0].Launch}
			type result struct {
				response c.Response
				err      error
			}
			done := make(chan result, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			go func() { r, err := retireControl.Call(ctx, c.Request{Retire: &request}); done <- result{r, err} }()
			// State, not a wall timeout, is the witness that retirement really began.
			deadline := time.Now().Add(2 * time.Second)
			for {
				snap := prepareV4Call(t, control, c.Request{Query: &c.Empty{}}).Snapshot
				rec := snap.Attachments[targets[0].Attachment]
				if rec.Phase == a.Retiring {
					if rec.Receipt != nil || rec.Retirement != request.Operation || rec.Binding != targets[0] || snap.Prepares[hello.Binding.Prepare].Phase != a.Pending {
						t.Fatal("quarantine/retirement tuple differs", rec)
					}
					break
				}
				if rec.Phase == a.Drained || time.Now().After(deadline) {
					t.Fatal("held guard did not retain RETIRING quarantine", rec)
				}
				time.Sleep(5 * time.Millisecond)
			}
			snapshot101NoRetire := func() {
				select {
				case r := <-done:
					t.Fatal("hung accepted guard yielded terminal retirement", r)
				default:
				}
				if gate.State().Held != [2]bool{true, true} {
					t.Fatal("live admission gate released early")
				}
			}
			snapshot101NoRetire()
			progress("hung-retiring-no-DRAINED")
			snapshot101NoRetire()
			snap := prepareV4Call(t, control, c.Request{Query: &c.Empty{}}).Snapshot
			rec := snap.Attachments[targets[0].Attachment]
			if rec.Phase != a.Retiring || rec.Receipt != nil {
				t.Fatal("DRAINED while original accepted guard held", rec)
			}
			t.Logf("actual quarantine A=%s retirement=%s phase=%s receipt=nil guard=%+v", targets[0].Attachment, rec.Retirement, rec.Phase, gate.State())
			prepareV4Must(t, gate.Release(0))
			select {
			case r := <-done:
				prepareV4Must(t, r.err)
				hungReceipt = r.response.Receipt
			case <-time.After(5 * time.Second):
				t.Fatal("released real guard failed to join retirement")
			}
			snapshot101RuntimeReceipt(t, control, targets[0], hungReceipt)
			prepareV4Must(t, gate.Release(1))
			// Retired A0 is denied, not successful rename. A1 remains actually fenced.
			event := snapshot101QueueEvent(t, gate.Waits())
			if event != admitted[1] {
				t.Fatal("wrong surviving unlink fence", event)
			}
		} else {
			prepareV4Must(t, gate.Release(0))
			prepareV4Must(t, gate.Release(1))
			waited := snapshot101QueueEvents(t, gate.Waits(), targets)
			if waited != admitted {
				t.Fatal("fence did not retain SAME pre-Begin guards/sequences", admitted, waited)
			}
			if cut != "full" {
				progress("while-V-fenced-" + cut)
			}
		}
		if !reflect.DeepEqual(before, snapshot101Image(t, backing)) {
			t.Fatal("accepted namespace effects crossed actual BeginCopy")
		}
	}
	ownerMode := "snapshot-queue"
	if cut == "death" {
		ownerMode = "snapshot-death"
	}
	evidence, ownerMount := prepareV4OwnInitializer(t, base, hello, ownerMode, owner, &safe, preBegin, held)
	if evidence.Hello != hello || evidence.Stage != ownerMode || evidence.InitializerError != "" {
		t.Fatal("wrong actual initializer evidence", evidence)
	}
	if cut == "death" {
		ownerMount.abort(t)
		snapshot101JoinedData(t, join())
		if !reflect.DeepEqual(before, snapshot101Image(t, backing)) {
			t.Fatal("dead initializer released snapshot effects")
		}
		receipt := prepareV4Drain(t, control, hello)
		for _, child := range consumers {
			child.send(t, 'p')
			child.receive(t, "alive")
		}
		progress("after-owner-death-original-consumers-live")
		fresh, freshKey := prepareV4Binding(t, ready, v)
		if fresh.Binding.Attachment == hello.Binding.Attachment || fresh.Binding.Prepare == hello.Binding.Prepare || fresh.Binding.Key == hello.Binding.Key {
			t.Fatal("initializer successor reused credentials")
		}
		reserve := a.ReserveRequest{Operation: prepareV4ID(t), Prepare: fresh.Binding.Prepare, Attachments: []a.Binding{fresh.Binding}}
		prepareV4Call(t, control, c.Request{ReplacePrepare: &a.ReplaceRequest{Operation: prepareV4ID(t), Prepare: hello.Binding.Prepare, Receipts: []a.Receipt{receipt}, Successor: reserve}})
		freshBootstrap, _, freshJoin := prepareV4MountBootstrap(t, base, service, ready, controller, control, fresh, freshKey)
		freshEvidence, freshMount := prepareV4OwnInitializer(t, base, fresh, "snapshot-queue", freshBootstrap, &safe, func() {}, func() {
			if !reflect.DeepEqual(before, snapshot101Image(t, backing)) {
				t.Fatal("replacement crossed fence before Finish")
			}
			for _, child := range consumers {
				child.send(t, 'p')
				child.receive(t, "alive")
			}
			progress("fresh-initializer-original-consumers-live")
		})
		if freshEvidence.Hello != fresh || freshEvidence.Stage != "snapshot-queue" || freshMount.path == ownerMount.path {
			t.Fatal("wrong fresh mounted initializer")
		}
		freshMount.assertGone(t)
		snapshot101JoinedData(t, freshJoin())
		hello = fresh
	} else {
		ownerMount.assertGone(t)
		snapshot101JoinedData(t, join())
	}
	for _, child := range consumers {
		child.send(t, 'f')
		child.receive(t, "done")
		child.join(t)
	}
	snapshot101NamespaceResult(t, backing, before, cut == "hung")
	progress("after-" + cut) // full pool: W is required only AFTER reserved PREPARE completed
	receipt := prepareV4Drain(t, control, hello)
	prepareV4Complete(t, control, hello, receipt)
	for i, m := range mounts {
		if cut == "hung" && i == 0 {
			// This connection failed closed on the retired admitted Rename. Local abort
			// is NOT drain; the genuine receipt above already came from authority/barrier.
			_ = m.Close()
			prepareV4JoinedMount(t, m)
			if err := joins[i](); !errors.Is(err, a.ErrUnauthorized) {
				t.Fatal("wrong retired DATA failure", err)
			}
			snapshot101RuntimeReceipt(t, control, runtimeHello[i].Binding, hungReceipt)
		} else {
			prepareV4Must(t, m.CloseGracefully(context.Background()))
			prepareV4JoinedMount(t, m)
			snapshot101JoinedData(t, joins[i]())
			b := runtimeHello[i].Binding
			r := prepareV4Call(t, control, c.Request{Retire: &a.RetireRequest{Operation: prepareV4ID(t), Store: b.Store, Volume: b.Volume, Attachment: b.Attachment, Launch: b.Launch}}).Receipt
			snapshot101RuntimeReceipt(t, control, b, r)
		}
	}
}

func snapshot101QueueEvent(t *testing.T, events <-chan d.NativeSnapshot101Wait) d.NativeSnapshot101Wait {
	select {
	case event := <-events:
		return event
	case <-time.After(5 * time.Second):
		t.Fatal("missing exact real admitted namespace guard; prerequisite is not a substitute")
		return d.NativeSnapshot101Wait{}
	}
}
func snapshot101QueueEvents(t *testing.T, events <-chan d.NativeSnapshot101Wait, targets [2]a.Binding) (out [2]d.NativeSnapshot101Wait) {
	seen := [2]bool{}
	for range targets {
		event := snapshot101QueueEvent(t, events)
		index := -1
		for i, b := range targets {
			if b == event.Binding {
				index = i
			}
		}
		if index < 0 || seen[index] || event.Sequence == 0 || event.Operation != [2]w.Operation{w.OpRename, w.OpUnlink}[index] {
			t.Fatal("wrong exact operation witness", event)
		}
		seen[index] = true
		out[index] = event
	}
	return out
}
func snapshot101RuntimeReceipt(t *testing.T, control *c.Client, b a.Binding, r *a.Receipt) {
	if r == nil || r.Schema != a.SchemaVersion || r.Store != b.Store || r.Volume != b.Volume || r.Attachment != b.Attachment || r.Prepare != "" || r.Revision == 0 {
		t.Fatal("not an actual exact runtime receipt", r)
	}
	snap := prepareV4Call(t, control, c.Request{Query: &c.Empty{}}).Snapshot
	record := snap.Attachments[b.Attachment]
	if record.Phase != a.Drained || record.Receipt == nil || *record.Receipt != *r {
		t.Fatal("receipt not durable", record)
	}
}
func snapshot101NamespaceResult(t *testing.T, path string, before snapshot101BackingImage, retired bool) {
	name := "moved"
	if retired {
		name = "p0"
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOATIME|unix.O_CLOEXEC, 0)
	prepareV4Must(t, err)
	dir := os.NewFile(uintptr(fd), "namespace-result")
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	prepareV4Must(t, err)
	if len(entries) != 1 || entries[0].Name() != name {
		t.Fatal("wrong post-fence namespace", entries)
	}
	var root unix.Stat_t
	prepareV4Must(t, unix.Fstat(fd, &root))
	old := before.Stats[0]
	if root.Dev != old.Dev || root.Ino != old.Ino || root.Mode != old.Mode || root.Uid != old.Uid || root.Gid != old.Gid || root.Nlink != old.Nlink {
		t.Fatal("namespace changed root identity/security metadata")
	}
	filefd, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOATIME|unix.O_CLOEXEC, 0)
	prepareV4Must(t, err)
	file := os.NewFile(uintptr(filefd), "retained-namespace-result")
	defer file.Close()
	var st unix.Stat_t
	prepareV4Must(t, unix.Fstat(filefd, &st))
	old = before.Stats[1]
	if st.Dev != old.Dev || st.Ino != old.Ino || st.Mode != old.Mode || st.Uid != old.Uid || st.Gid != old.Gid || st.Nlink != old.Nlink || st.Size != 4096 {
		t.Fatal("retained renamed file differs")
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	prepareV4Must(t, err)
	if !bytes.Equal(data, bytes.Repeat([]byte{'A'}, 4096)) {
		t.Fatal("retained namespace bytes differ")
	}
	for _, fd := range []int{int(dir.Fd()), filefd} {
		buf := make([]byte, 64)
		n, err := unix.Fgetxattr(fd, "user.snapshot101", buf)
		prepareV4Must(t, err)
		if string(buf[:n]) != "retained" {
			t.Fatal("namespace xattr differs")
		}
	}
	t.Logf("post-fence namespace=%s root=%+v retained-inode=%+v full-content=4096*A", name, root, st)
}

// Same existing owned initializer bootstrap, not another launcher. Evidence is
// persisted BEFORE a possible exact-owned SIGKILL, while Begin remains held.
func snapshot101QueueOwner(t *testing.T, hello a.DataHello, mount *f.Mounted, mode string) {
	fd, err := unix.Open(mount.Mountpoint(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	prepareV4Must(t, err)
	root := &confinedRoot{fd: fd}
	copy := &managedCopy{root: root, scope: managedCopyScope{Store: string(hello.Binding.Store), Volume: string(hello.Binding.Volume), Prepare: string(hello.Binding.Prepare), Attachment: string(hello.Binding.Attachment)}, call: managedPrepareIoctl}
	prepareV4Must(t, copy.control(w.BeginCopy))
	prepareV4Must(t, nativePrepareWriteEvidence(nativePrepareEvidence{Hello: hello, Stage: mode}))
	n, err := unix.Write(5, []byte{4})
	prepareV4Must(t, err)
	if n != 1 {
		t.Fatal("short real Begin ack")
	}
	prepareV4Must(t, unix.SetNonblock(11, true))
	release := os.NewFile(11, "snapshot101-queue-release")
	defer release.Close()
	prepareV4Must(t, release.SetReadDeadline(time.Now().Add(15*time.Second)))
	var ack [1]byte
	_, err = io.ReadFull(release, ack[:])
	prepareV4Must(t, err)
	if ack[0] != 5 || mode == "snapshot-death" {
		t.Fatal("dead initializer must not finish")
	}
	prepareV4Must(t, copy.control(w.FinishCopy))
	prepareV4Must(t, root.close())
	prepareV4Must(t, mount.CloseGracefully(context.Background()))
	prepareV4JoinedMount(t, mount)
}

// Original process remains responsive on its private pipe while its real kernel
// syscall is blocked in another goroutine. Ping observes THIS PID/FD, no restart.
func snapshot101NamespaceConsumer(t *testing.T, mode string, index int) {
	name := fmt.Sprintf("p%d", index)
	fd, err := unix.Openat(3, name, unix.O_RDWR|unix.O_CLOEXEC, 0)
	prepareV4Must(t, err)
	var st unix.Stat_t
	prepareV4Must(t, unix.Fstat(fd, &st))
	proof := snapshot101ConsumerProof{PID: os.Getpid(), Parent: os.Getppid(), UID: os.Geteuid(), GID: os.Getegid(), FD: fd, Inode: st.Ino}
	prepareV4Must(t, unix.SetNonblock(4, true))
	command := os.NewFile(4, "namespace-control")
	defer command.Close()
	report := os.NewFile(5, "namespace-proof")
	defer report.Close()
	emit := func(stage string) {
		proof.Stage = stage
		proof.PID = os.Getpid()
		proof.Parent = os.Getppid()
		proof.UID = os.Geteuid()
		proof.GID = os.Getegid()
		prepareV4Must(t, json.NewEncoder(report).Encode(proof))
	}
	take := func() byte {
		prepareV4Must(t, command.SetReadDeadline(time.Now().Add(15*time.Second)))
		var b [1]byte
		_, err := io.ReadFull(command, b[:])
		prepareV4Must(t, err)
		return b[0]
	}
	// Positive real namespace operations, before the admission cut is armed.
	temp := fmt.Sprintf("positive-%d", index)
	prepareV4Must(t, unix.Renameat(3, name, 3, temp))
	prepareV4Must(t, unix.Renameat(3, temp, 3, name))
	scratch, err := unix.Openat(3, temp, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC, 0600)
	prepareV4Must(t, err)
	prepareV4Must(t, unix.Close(scratch))
	prepareV4Must(t, unix.Unlinkat(3, temp, 0))
	prepareV4Must(t, unix.Fsync(3))
	emit("ready")
	if take() != 'a' {
		t.Fatal("wrong namespace arm")
	}
	emit("armed")
	if take() != 'x' {
		t.Fatal("wrong namespace start")
	}
	result := make(chan error, 1)
	go func() {
		if index == 0 {
			result <- unix.Renameat(3, "p0", 3, "moved")
		} else {
			result <- unix.Unlinkat(3, "p1", 0)
		}
	}()
	for {
		switch take() {
		case 'p':
			emit("alive")
		case 'f':
			var operationErr error
			select {
			case operationErr = <-result:
			case <-time.After(5 * time.Second):
				t.Fatal("original namespace syscall did not join")
			}
			if mode == "namespace-retire" && index == 0 {
				if !errors.Is(operationErr, unix.EIO) {
					t.Fatal("retired admitted rename did not fail EIO", operationErr)
				}
				// The retired FUSE connection cannot serve fstat/flush; close still consumes
				// the original FD. Never retry; no success or drain is inferred here.
				if err := unix.Close(fd); !snapshot101RetiredCloseOK(err) {
					t.Fatal("unexpected retired close", err)
				}
			} else {
				prepareV4Must(t, operationErr)
				prepareV4Must(t, unix.Fstat(fd, &st))
				if st.Ino != proof.Inode {
					t.Fatal("consumer descriptor inode changed")
				}
				data := make([]byte, 4096)
				n, err := unix.Pread(fd, data, 0)
				prepareV4Must(t, err)
				if n != 4096 || !bytes.Equal(data, bytes.Repeat([]byte{'A'}, 4096)) {
					t.Fatal("original renamed/unlinked FD lost bytes")
				}
				prepareV4Must(t, unix.Fsync(fd))
				prepareV4Must(t, unix.Close(fd))
				prepareV4Must(t, unix.Fsync(3))
			}
			// FUSE directory operations have no flush callback; keep this close strict.
			prepareV4Must(t, unix.Close(3))
			emit("done")
			return
		default:
			t.Fatal("unknown finite namespace phase")
		}
	}
}

// Only for the retired regular FD, after the original Rename returned EIO.
// Linux 6.18.44 (1efe5d048a391de3ead2804b2e7f86376c356cc5):
// fs/open.c:close consumes the FD before fuse_flush; fs/fuse/dev.c returns
// ENOTCONN for a disconnected queue, ECONNABORTED for an aborted queued request.
func snapshot101RetiredCloseOK(err error) bool {
	return err == nil || errors.Is(err, unix.EIO) || errors.Is(err, unix.ENOTCONN) || errors.Is(err, unix.ECONNABORTED)
}

func TestSnapshot101RetiredCloseErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"success", nil, true},
		{"io", unix.EIO, true},
		{"disconnected", unix.ENOTCONN, true},
		{"aborted", unix.ECONNABORTED, true},
		{"bad-fd", unix.EBADF, false},
		{"interrupted", unix.EINTR, false},
		{"no-space", unix.ENOSPC, false},
		{"quota", unix.EDQUOT, false},
		{"access", unix.EACCES, false},
		{"invalid", unix.EINVAL, false},
		{"timeout", unix.ETIMEDOUT, false},
		{"reset", unix.ECONNRESET, false},
		{"no-device", unix.ENODEV, false},
		{"other", errors.New("unrelated close failure"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := snapshot101RetiredCloseOK(tc.err); got != tc.want {
				t.Fatalf("retired close(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

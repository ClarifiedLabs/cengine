//go:build cengine_native_faulttest && linux && (arm64 || amd64)

package supervisor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	cl "dev.cengine/guest/internal/storageclient"
	c "dev.cengine/guest/internal/storagecontrol"
	f "dev.cengine/guest/internal/storagefuse"
	p "dev.cengine/guest/internal/storagepki"
	ss "dev.cengine/guest/internal/storageserver"
	s "dev.cengine/guest/internal/storageservice"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

func TestNativeSnapshot101RetainedWritableFD(t *testing.T) { snapshot101IO(t, "fd") }
func TestNativeSnapshot101DirtyMmapWriteback(t *testing.T) { snapshot101IO(t, "mmap") }
func TestNativeSnapshot101ReadReaddirAtime(t *testing.T)   { snapshot101IO(t, "atime") }

// Three closed cases share real service setup only, never fake dispatch or a
// second authority. Two distinct original exec consumers retain their original
// descriptors/mappings, mounts and issued credentials through Begin/FinishCopy.
var snapshot101IOFailed atomic.Bool

func snapshot101IO(t *testing.T, mode string) {
	if snapshot101IOFailed.Load() {
		t.Fatal("prior RTM101 IO case failed; no new service until parent cleanup")
	}
	t.Cleanup(func() {
		if t.Failed() {
			snapshot101IOFailed.Store(true)
		}
	})
	prepareV4Profile(t)
	var fs unix.Statfs_t
	prepareV4Must(t, unix.Statfs("/scratch", &fs))
	if uint64(fs.Blocks)*uint64(fs.Bsize) > 128<<20 || fs.Files > 4096 || fs.Flags&unix.ST_NOATIME != 0 {
		t.Fatal("requires bounded ext4 with observable atime")
	}
	base, err := os.MkdirTemp("/scratch", "snapshot101-io-")
	prepareV4Must(t, err)
	safe := true
	t.Cleanup(func() {
		info, err := os.ReadFile("/proc/self/mountinfo")
		if err != nil {
			safe = false
		}
		for _, line := range strings.Split(string(info), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 4 && strings.HasPrefix(fields[4], base+"/") {
				safe = false
			}
		}
		if safe && !t.Failed() {
			prepareV4Must(t, os.RemoveAll(base))
		} else {
			t.Logf("retained snapshot101 IO evidence: %s", base)
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
	cfg := s.Config{Root: root, DeviceUUID: prepareV4BackingUUID(t, int(root.Fd())), Store: prepareV4ID(t), Bootstrap: bootstrap, Now: time.Now().Add(-time.Minute), Lifetime: time.Hour}
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
	var runtimeKeys [3]p.Key
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
		runtimeKeys[i] = k
	}
	observe, err := service.InstallNativeSnapshot101([2]a.Binding{runtimeHello[0].Binding, runtimeHello[1].Binding})
	prepareV4Must(t, err)
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
		mounts[i], joins[i] = snapshot101RuntimeMount(t, base, service, ready, controller, control, runtimeHello[i], runtimeKeys[i])
		m := mounts[i]
		t.Cleanup(func() {
			select {
			case <-m.Done():
				return
			default:
			}
			// Exact-owned local abort/join only, never a drain or successful operation.
			if err := m.Close(); err != nil {
				t.Logf("runtime local abort result: %v", err)
			}
			select {
			case <-m.Done():
			default:
				safe = false
				t.Error("runtime mount teardown unproven; retain quarantine")
			}
		})
	}

	originalPID := os.Getpid()
	progress := func(value string) {
		if os.Getpid() != originalPID {
			t.Fatal("W process replaced")
		}
		prepareV4Must(t, snapshot101Progress(mounts[2].Mountpoint(), value))
		prepareV4ExpectBytes(t, filepath.Join(base, "store/volumes/w/progress"), value)
	}
	progress("before")
	// Positive atime eligibility on both actual operations before resetting old
	// nanoseconds. Verification reads below exclusively use O_NOATIME.
	snapshot101OldAtime(t, backing)
	old := snapshot101Image(t, backing)
	var consumers [2]*snapshot101Consumer
	for i := range consumers {
		consumers[i] = snapshot101StartConsumer(t, base, mounts[i].Mountpoint(), mode, i, &safe)
	}
	if consumers[0].proof.PID == consumers[1].proof.PID {
		t.Fatal("V consumers must be different live processes")
	}
	positive := snapshot101Image(t, backing)
	if mode == "atime" && (positive.Stats[0].Atim == old.Stats[0].Atim || positive.Stats[1].Atim == old.Stats[1].Atim) {
		t.Fatal("actual read/readdir positive failed to update atime")
	}
	snapshot101OldAtime(t, backing)
	before := snapshot101Image(t, backing)
	prepareV4Call(t, control, c.Request{ReservePrepare: &a.ReserveRequest{Operation: prepareV4ID(t), Prepare: hello.Binding.Prepare, Attachments: []a.Binding{hello.Binding}}})
	owner, _, join := prepareV4MountBootstrap(t, base, service, ready, controller, control, hello, ownerKey)
	ops := [2]w.Operation{w.OpWrite, w.OpWrite}
	if mode == "atime" {
		ops = [2]w.Operation{w.OpRead, w.OpReadDir}
	}
	positiveReads := observe.PositiveReads()
	if mode == "atime" {
		for i, event := range positiveReads {
			if event.Binding != runtimeHello[i].Binding || event.Operation != ops[i] || event.Sequence == 0 || event.Node == 0 || event.Handle == 0 {
				t.Fatalf("missing original positive read view child=%d: %+v", i, event)
			}
			t.Logf("positive read view child=%d consumer=%+v event=%+v", i, consumers[i].proof, event)
		}
	}
	prepareV4Must(t, observe.Arm(ops))
	var fenced [2]ss.NativeSnapshot101Wait
	evidence, mount := prepareV4OwnInitializer(t, base, hello, "snapshot-"+mode, owner, &safe, func() {
		for _, consumer := range consumers {
			consumer.send(t, 'a')
			consumer.receive(t, "armed")
		}
	}, func() {
		// Pre-Begin background writeback is legal. Freeze the actual server image
		// AFTER Begin acknowledges; C is dirtied through the original mapping next.
		held := snapshot101Image(t, backing)
		if mode == "mmap" {
			for i := range before.Stats {
				x, y := before.Stats[i], held.Stats[i]
				if x.Dev != y.Dev || x.Ino != y.Ino || x.Mode != y.Mode || x.Uid != y.Uid || x.Gid != y.Gid || x.Size != y.Size || before.Xattrs[i] != held.Xattrs[i] {
					t.Fatal("pre-Begin identity drift")
				}
			}
			for _, alphabet := range held.Alphabet {
				if alphabet & ^uint8(3) != 0 {
					t.Fatal("unexpected pre-Begin writeback bytes")
				}
			}
			if held.Stats[0] != before.Stats[0] {
				t.Fatal("pre-Begin root metadata drift")
			}
			t.Logf("legal pre-Begin mmap image=%+v held image=%+v", before, held)
			before = held
		} else if !reflect.DeepEqual(before, held) {
			t.Fatal("pre-Begin backing drift", before, held)
		}
		for _, consumer := range consumers {
			consumer.send(t, 'x')
		}
		seen := map[a.ID]bool{}
		for range consumers {
			select {
			case event := <-observe.Waits():
				index := -1
				for i := range consumers {
					if event.Binding == runtimeHello[i].Binding {
						index = i
					}
				}
				if index < 0 || seen[event.Binding.Attachment] || event.Sequence == 0 || !snapshot101FenceOperation(mode, ops[index], event) {
					t.Fatalf("wrong actual accepted/fenced request: %+v", event)
				}
				if mode == "atime" && !snapshot101ReadFence(ops[index], positiveReads[index], event) {
					t.Fatalf("wrong original read view child=%d: positive=%+v fenced=%+v", index, positiveReads[index], event)
				}
				seen[event.Binding.Attachment] = true
				fenced[index] = event
				t.Logf("actual runtime fence wait E=%s S/V/A=%+v seq=%d op=%s flags=%d prerequisite=%q node=%d handle=%d child=%d consumer=%+v", ready.ServiceEpoch, event.Binding, event.Sequence, event.Operation, event.WriteFlags, event.XattrName, event.Node, event.Handle, index, consumers[index].proof)
			case <-time.After(5 * time.Second):
				t.Fatal("missing actual server wait; a blocked syscall alone is not proof")
			}
		}
		pending := func() {
			if mode == "fd" || mode == "atime" {
				for _, consumer := range consumers {
					consumer.send(t, 'p')
					if mode == "atime" {
						consumer.receive(t, "read-pending")
					} else {
						consumer.receive(t, "pwrite-pending")
					}
				}
			}
		}
		pending()
		progress("while-V-fenced")
		pending()
		if got := snapshot101Image(t, backing); !reflect.DeepEqual(before, got) {
			t.Fatalf("server effects crossed held BeginCopy: before=%+v held=%+v", before, got)
		}
	})
	if evidence.Hello != hello || evidence.Stage != "snapshot-"+mode || evidence.InitializerError != "" {
		t.Fatal("wrong fence owner evidence", evidence)
	}
	mount.assertGone(t)
	snapshot101JoinedData(t, join())
	for _, consumer := range consumers {
		if mode == "fd" || mode == "atime" {
			consumer.send(t, 'f')
		}
		consumer.receive(t, "done")
		consumer.join(t)
	}
	if mode == "fd" {
		seen := map[a.ID]bool{}
		for _, first := range fenced {
			if first.Operation != w.OpGetXAttr {
				continue
			}
			select {
			case write := <-observe.Writes():
				index := -1
				for i := range fenced {
					if write.Binding == fenced[i].Binding {
						index = i
					}
				}
				if index < 0 || seen[write.Binding.Attachment] || write.Operation != w.OpWrite || write.Sequence <= fenced[index].Sequence {
					t.Fatalf("missing same-binding subsequent WRITE: %+v", write)
				}
				seen[write.Binding.Attachment] = true
				t.Logf("post-FinishCopy original DATA WRITE E=%s binding=%+v seq=%d prerequisite-seq=%d", ready.ServiceEpoch, write.Binding, write.Sequence, fenced[index].Sequence)
			default:
				t.Fatal("completed retained Pwrite lacks subsequent actual WRITE admission")
			}
		}
	}
	if mode == "atime" && fenced[0].Operation == w.OpGetAttr {
		select {
		case read := <-observe.Reads():
			if read.Operation != w.OpRead || read.Binding != fenced[0].Binding || read.Node != fenced[0].Node || read.Handle != fenced[0].Handle || read.Sequence <= fenced[0].Sequence {
				t.Fatalf("missing same-view subsequent READ: %+v", read)
			}
			t.Logf("post-FinishCopy original DATA READ E=%s event=%+v prerequisite-seq=%d", ready.ServiceEpoch, read, fenced[0].Sequence)
		default:
			t.Fatal("completed retained Pread lacks subsequent actual READ admission")
		}
	}
	after := snapshot101Image(t, backing)
	for i := range before.Stats {
		x, y := before.Stats[i], after.Stats[i]
		if x.Dev != y.Dev || x.Ino != y.Ino || x.Mode != y.Mode || x.Nlink != y.Nlink || x.Uid != y.Uid || x.Gid != y.Gid || x.Size != y.Size || before.Xattrs[i] != after.Xattrs[i] {
			t.Fatal("retained content metadata/identity changed", before, after)
		}
	}
	if mode == "atime" {
		if after.Data != before.Data || after.Stats[0].Atim == before.Stats[0].Atim || after.Stats[1].Atim == before.Stats[1].Atim {
			t.Fatal("post-release reads missing exact data or atime effects", before, after)
		}
		for i := range before.Stats {
			x, y := before.Stats[i], after.Stats[i]
			x.Atim = unix.Timespec{}
			y.Atim = unix.Timespec{}
			if x != y {
				t.Fatal("read changed non-atime metadata", i)
			}
		}
	} else {
		value := byte('B')
		if mode == "mmap" {
			value = 'C'
		}
		want := sha256.Sum256(bytes.Repeat([]byte{value}, 4096))
		if after.Data != [2][32]byte{want, want} || after.Stats[0] != before.Stats[0] {
			t.Fatal("released retained writes missing exact contents/root metadata", before, after)
		}
	}
	t.Logf("full backing receipts before=%+v after=%+v", before, after)
	progress("after")
	receipt := prepareV4Drain(t, control, hello)
	prepareV4Complete(t, control, hello, receipt)
	for i, m := range mounts {
		prepareV4Must(t, m.CloseGracefully(context.Background()))
		prepareV4JoinedMount(t, m)
		snapshot101JoinedData(t, joins[i]())
		b := runtimeHello[i].Binding
		r := prepareV4Call(t, control, c.Request{Retire: &a.RetireRequest{Operation: prepareV4ID(t), Store: b.Store, Volume: b.Volume, Attachment: b.Attachment, Launch: b.Launch}}).Receipt
		if r == nil || r.Schema != a.SchemaVersion || r.Store != b.Store || r.Volume != b.Volume || r.Attachment != b.Attachment || r.Prepare != "" || r.Revision == 0 {
			t.Fatal("missing actual runtime drain", r)
		}
		snap := prepareV4Call(t, control, c.Request{Query: &c.Empty{}}).Snapshot
		record := snap.Attachments[b.Attachment]
		if record.Phase != a.Drained || record.Receipt == nil || *record.Receipt != *r {
			t.Fatal("runtime drain not durable")
		}
	}
}

func snapshot101RuntimeMount(t *testing.T, base string, service *s.LifecycleService, ready s.Ready, controller p.Identity, control *c.Client, hello a.DataHello, key p.Key) (*f.Mounted, func() error) {
	identity := prepareV4IssueAttachment(t, service, ready, controller, control, hello, key)
	trust, server := prepareV4Trust(t, ready)
	cfg, err := p.ClientTLSConfig(identity, trust, server, ready.ServerKey)
	prepareV4Must(t, err)
	raw, join := prepareV4TCP(t, service.ServeData)
	conn := tls.Client(raw, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = conn.HandshakeContext(ctx)
	cancel()
	prepareV4Must(t, err)
	parent := filepath.Join(base, "mounts", string(hello.Binding.Attachment))
	prepareV4Must(t, os.Mkdir(parent, 0700))
	mount, err := f.Mount(f.Config{Client: cl.Config{Conn: conn, TLSConfig: cfg, ServerPin: a.Fingerprint(ready.ServerKey.String()), Authority: hello, Version: w.Version, Profile: w.RequiredProfile(), SupportedCaps: (uint64(1) << (unix.CAP_LAST_CAP + 1)) - 1, Limits: cl.DefaultLimits(), Timeout: 15 * time.Second}, Mountpoint: filepath.Join(parent, "root"), Retire: func(error) {}})
	prepareV4Must(t, err)
	return mount, join
}

type snapshot101BackingImage struct {
	Stats    [3]unix.Stat_t
	Data     [2][32]byte
	Alphabet [2]uint8
	Xattrs   [3]string
	Names    string
}

func snapshot101Image(t *testing.T, path string) (out snapshot101BackingImage) {
	for i, name := range []string{".", "p0", "p1"} {
		flags := unix.O_RDONLY | unix.O_NOATIME | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if i == 0 {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Open(filepath.Join(path, name), flags, 0)
		prepareV4Must(t, err)
		file := os.NewFile(uintptr(fd), "backing-noatime")
		prepareV4Must(t, unix.Fstat(fd, &out.Stats[i]))
		x := make([]byte, 64)
		n, err := unix.Fgetxattr(fd, "user.snapshot101", x)
		prepareV4Must(t, err)
		out.Xattrs[i] = string(x[:n])
		if i == 0 {
			entries, err := file.ReadDir(-1)
			prepareV4Must(t, err)
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			if len(names) != 2 || !((names[0] == "p0" && names[1] == "p1") || (names[0] == "p1" && names[1] == "p0")) {
				t.Fatal("unexpected namespace", names)
			}
			out.Names = "p0,p1"
		} else {
			b, err := io.ReadAll(io.LimitReader(file, 4097))
			prepareV4Must(t, err)
			if len(b) != 4096 {
				t.Fatal("wrong bounded content size")
			}
			out.Data[i-1] = sha256.Sum256(b)
			for _, value := range b {
				switch value {
				case 'A':
					out.Alphabet[i-1] |= 1
				case 'B':
					out.Alphabet[i-1] |= 2
				case 'C':
					out.Alphabet[i-1] |= 4
				default:
					out.Alphabet[i-1] |= 8
				}
			}
		}
		prepareV4Must(t, file.Close())
	}
	return out
}
func snapshot101OldAtime(t *testing.T, path string) {
	for _, name := range []string{".", "p0", "p1"} {
		prepareV4Must(t, unix.UtimesNanoAt(unix.AT_FDCWD, filepath.Join(path, name), []unix.Timespec{{Sec: 123456789, Nsec: 123456789}, {Nsec: unix.UTIME_OMIT}}, unix.AT_SYMLINK_NOFOLLOW))
	}
}

func snapshot101FenceOwner(t *testing.T, hello a.DataHello, mount *f.Mounted, mode string) {
	fd, err := unix.Open(mount.Mountpoint(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	prepareV4Must(t, err)
	root := &confinedRoot{fd: fd}
	copy := &managedCopy{root: root, scope: managedCopyScope{Store: string(hello.Binding.Store), Volume: string(hello.Binding.Volume), Prepare: string(hello.Binding.Prepare), Attachment: string(hello.Binding.Attachment)}, call: managedPrepareIoctl}
	prepareV4Must(t, copy.control(w.BeginCopy))
	n, err := unix.Write(5, []byte{4})
	prepareV4Must(t, err)
	if n != 1 {
		t.Fatal("short BeginCopy ack")
	}
	prepareV4Must(t, unix.SetNonblock(11, true))
	release := os.NewFile(11, "snapshot101-held")
	defer release.Close()
	prepareV4Must(t, release.SetReadDeadline(time.Now().Add(15*time.Second)))
	var ack [1]byte
	_, err = io.ReadFull(release, ack[:])
	prepareV4Must(t, err)
	if ack[0] != 5 {
		t.Fatal("wrong release")
	}
	prepareV4Must(t, copy.control(w.FinishCopy))
	prepareV4Must(t, root.close())
	prepareV4Must(t, mount.CloseGracefully(context.Background()))
	prepareV4JoinedMount(t, mount)
	prepareV4Must(t, nativePrepareWriteEvidence(nativePrepareEvidence{Hello: hello, Stage: mode}))
}

// A bounded fixed-purpose child, not a generic launcher or authority carrier.
// It inherits only its already-issued runtime mount root and two private pipes.
var snapshot101ConsumerMode = flag.String("native-snapshot101-consumer", "", "private fd/mmap/atime consumer")
var snapshot101ConsumerIndex = flag.Int("native-snapshot101-index", -1, "private consumer 0/1")
var snapshot101ConsumerParent = flag.Int("native-snapshot101-parent", 0, "exact creating parent")

type snapshot101ConsumerProof struct {
	Stage                     string
	PID, Parent, UID, GID, FD int
	Inode                     uint64
}
type snapshot101Consumer struct {
	cmd             *exec.Cmd
	command, report *os.File
	done            chan error
	proof           snapshot101ConsumerProof
	joined          bool
}

func snapshot101StartConsumer(t *testing.T, base, mount, mode string, index int, safe *bool) *snapshot101Consumer {
	fd, err := unix.Open(mount, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	prepareV4Must(t, err)
	root := os.NewFile(uintptr(fd), "issued-runtime-root")
	defer root.Close()
	command, writer, err := os.Pipe()
	prepareV4Must(t, err)
	defer command.Close()
	report, output, err := os.Pipe()
	prepareV4Must(t, err)
	defer output.Close()
	log, err := os.OpenFile(filepath.Join(base, fmt.Sprintf("consumer-%d.log", index)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	prepareV4Must(t, err)
	cmd := exec.Command("/proc/self/exe", "-test.run=^TestNativeSnapshot101ConsumerProcess$", "-test.timeout=35s", "-native-snapshot101-consumer="+mode, fmt.Sprintf("-native-snapshot101-index=%d", index), fmt.Sprintf("-native-snapshot101-parent=%d", os.Getpid()))
	cmd.Env = []string{"TMPDIR=/scratch"}
	cmd.ExtraFiles = []*os.File{root, command, output}
	cmd.Stdout = &prepareV4Output{file: log, remaining: 8192}
	cmd.Stderr = cmd.Stdout
	cmd.WaitDelay = time.Second
	pidfd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, PidFD: &pidfd}
	child := &snapshot101Consumer{cmd: cmd, command: writer, report: report, done: make(chan error, 1)}
	started := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		err := cmd.Start()
		started <- err
		if err == nil {
			child.done <- cmd.Wait()
		}
	}()
	prepareV4Must(t, <-started)
	t.Cleanup(func() {
		defer writer.Close()
		defer report.Close()
		defer log.Close()
		if pidfd >= 0 {
			defer unix.Close(pidfd)
		}
		if !child.joined {
			if pidfd >= 0 {
				_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
			}
			select {
			case <-child.done:
				child.joined = cmd.ProcessState != nil
			case <-time.After(5 * time.Second):
				t.Error("unjoined original V consumer")
			}
			if !child.joined {
				*safe = false
			}
		}
	})
	if pidfd < 0 {
		t.Fatal("consumer lacks actual pidfd")
	}
	child.receive(t, "ready")
	return child
}
func (c *snapshot101Consumer) send(t *testing.T, b byte) {
	prepareV4Must(t, c.command.SetWriteDeadline(time.Now().Add(5*time.Second)))
	n, err := c.command.Write([]byte{b})
	prepareV4Must(t, err)
	if n != 1 {
		t.Fatal("short consumer command")
	}
}
func (c *snapshot101Consumer) receive(t *testing.T, stage string) {
	prepareV4Must(t, c.report.SetReadDeadline(time.Now().Add(5*time.Second)))
	// One small JSON line per fixed phase; no buffered decoder can consume the next.
	var line []byte
	var b [1]byte
	for len(line) < 1024 {
		_, err := io.ReadFull(c.report, b[:])
		prepareV4Must(t, err)
		line = append(line, b[0])
		if b[0] == '\n' {
			break
		}
	}
	var proof snapshot101ConsumerProof
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	prepareV4Must(t, decoder.Decode(&proof))
	if decoder.Decode(new(any)) != io.EOF {
		t.Fatal("extra proof")
	}
	if proof.Stage != stage || proof.PID != c.cmd.Process.Pid || proof.Parent != os.Getpid() || proof.UID != os.Geteuid() || proof.GID != os.Getegid() || proof.FD < 0 || proof.Inode == 0 {
		t.Fatal("wrong original consumer", proof)
	}
	if stage != "ready" {
		before := c.proof
		before.Stage = stage
		if proof != before {
			t.Fatal("consumer or retained FD identity replaced", proof, before)
		}
	}
	c.proof = proof
}
func (c *snapshot101Consumer) join(t *testing.T) {
	select {
	case err := <-c.done:
		c.joined = c.cmd.ProcessState != nil
		prepareV4Must(t, err)
		if !c.joined || !c.cmd.ProcessState.Success() {
			t.Fatal("consumer not cleanly joined")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("consumer Wait budget exceeded")
	}
}

func TestNativeSnapshot101ConsumerProcess(t *testing.T) {
	prepareV4Profile(t)
	mode, index := *snapshot101ConsumerMode, *snapshot101ConsumerIndex
	if (mode != "fd" && mode != "mmap" && mode != "atime" && mode != "namespace" && mode != "namespace-retire") || (index != 0 && index != 1) || *snapshot101ConsumerParent <= 0 || os.Getppid() != *snapshot101ConsumerParent {
		t.Fatal("private closed consumer selector")
	}
	var fs unix.Statfs_t
	prepareV4Must(t, unix.Fstatfs(3, &fs))
	if fs.Type != unix.FUSE_SUPER_MAGIC {
		t.Fatal("not actual managed mount")
	}
	if mode == "namespace" || mode == "namespace-retire" {
		snapshot101NamespaceConsumer(t, mode, index)
		return
	}
	name := fmt.Sprintf("p%d", index)
	flags := unix.O_RDWR | unix.O_CLOEXEC
	if mode == "atime" {
		flags = unix.O_RDONLY | unix.O_CLOEXEC | unix.O_DIRECT
		if index == 1 {
			name = "."
			flags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC
		}
	}
	fd, err := unix.Openat(3, name, flags, 0)
	prepareV4Must(t, err)
	var stat unix.Stat_t
	prepareV4Must(t, unix.Fstat(fd, &stat))
	proof := snapshot101ConsumerProof{PID: os.Getpid(), Parent: os.Getppid(), UID: os.Geteuid(), GID: os.Getegid(), FD: fd, Inode: stat.Ino}
	prepareV4Must(t, unix.Close(3))
	prepareV4Must(t, unix.SetNonblock(4, true))
	command := os.NewFile(4, "snapshot101-command")
	defer command.Close()
	report := os.NewFile(5, "snapshot101-report")
	defer report.Close()
	emit := func(stage string) { proof.Stage = stage; prepareV4Must(t, json.NewEncoder(report).Encode(proof)) }
	take := func(want byte) {
		prepareV4Must(t, command.SetReadDeadline(time.Now().Add(15*time.Second)))
		var b [1]byte
		_, err := io.ReadFull(command, b[:])
		prepareV4Must(t, err)
		if b[0] != want {
			t.Fatal("wrong consumer phase")
		}
	}
	aligned, err := unix.Mmap(-1, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	prepareV4Must(t, err)
	defer unix.Munmap(aligned)
	var mapping []byte
	if mode == "mmap" {
		mapping, err = unix.Mmap(fd, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		prepareV4Must(t, err)
		if !bytes.Equal(mapping, bytes.Repeat([]byte{'A'}, 4096)) {
			t.Fatal("mmap initial bytes")
		}
	}
	readOperation := func() error {
		if index == 0 {
			n, err := unix.Pread(fd, aligned, 0)
			if err != nil {
				return err
			}
			if n != 4096 || !bytes.Equal(aligned, bytes.Repeat([]byte{'A'}, 4096)) {
				return fmt.Errorf("wrong retained read: %d", n)
			}
		} else {
			if _, err := unix.Seek(fd, 0, 0); err != nil {
				return err
			}
			n, err := unix.Getdents(fd, aligned)
			if err != nil {
				return err
			}
			_, _, names := unix.ParseDirent(aligned[:n], -1, nil)
			if len(names) != 2 || !((names[0] == "p0" && names[1] == "p1") || (names[0] == "p1" && names[1] == "p0")) {
				return fmt.Errorf("wrong mounted readdir: %v", names)
			}
		}
		return nil
	}
	operation := func(value byte) {
		switch mode {
		case "fd":
			for i := range aligned {
				aligned[i] = value
			}
			n, err := unix.Pwrite(fd, aligned, 0)
			prepareV4Must(t, err)
			if n != 4096 {
				t.Fatal("short retained write")
			}
			prepareV4Must(t, unix.Fsync(fd))
		case "mmap":
			prepareV4Must(t, unix.Msync(mapping, unix.MS_SYNC))
			prepareV4Must(t, unix.Fsync(fd))
		case "atime":
			prepareV4Must(t, readOperation())
		}
	}
	if mode == "mmap" {
		for i := range mapping {
			mapping[i] = 'A'
		}
	}
	operation('A')
	emit("ready")
	take('a')
	if mode == "mmap" {
		for i := range mapping {
			mapping[i] = 'B'
		}
	} // cached CPU stores are explicitly allowed
	emit("armed")
	take('x')
	if mode == "mmap" {
		for i := range mapping {
			mapping[i] = 'C'
		}
	} // deterministic post-Begin writeback even if B flushed earlier
	if mode == "fd" {
		// Only the syscall runs concurrently; pending acknowledgements are sent
		// by this original process after checking the syscall result channel.
		for i := range aligned {
			aligned[i] = 'B'
		}
		type writeResult struct {
			n   int
			err error
		}
		result := make(chan writeResult, 1)
		go func() { n, err := unix.Pwrite(fd, aligned, 0); result <- writeResult{n, err} }()
		for range 2 {
			take('p')
			select {
			case r := <-result:
				t.Fatalf("Pwrite completed while fence held: %+v", r)
			default:
			}
			emit("pwrite-pending")
		}
		take('f')
		select {
		case r := <-result:
			prepareV4Must(t, r.err)
			if r.n != 4096 {
				t.Fatal("short retained Pwrite", r.n)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("retained Pwrite did not finish")
		}
		prepareV4Must(t, unix.Fsync(fd))
		n, err := unix.Pread(fd, aligned, 0)
		prepareV4Must(t, err)
		if n != 4096 || !bytes.Equal(aligned, bytes.Repeat([]byte{'B'}, 4096)) {
			t.Fatal("original retained FD bytes differ")
		}
	} else if mode == "atime" {
		// No other mounted operation runs until this original retained read completes.
		result := make(chan error, 1)
		go func() { result <- readOperation() }()
		for range 2 {
			take('p')
			select {
			case err := <-result:
				t.Fatalf("read/readdir completed while fence held: %v", err)
			default:
			}
			emit("read-pending")
		}
		take('f')
		select {
		case err := <-result:
			prepareV4Must(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("retained read/readdir did not finish")
		}
	} else {
		operation('B')
	}
	prepareV4Must(t, unix.Fstat(fd, &stat))
	if stat.Ino != proof.Inode {
		t.Fatal("retained descriptor inode changed")
	}
	if mapping != nil {
		prepareV4Must(t, unix.Munmap(mapping))
	}
	prepareV4Must(t, unix.Close(fd))
	emit("done")
}

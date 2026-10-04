//go:build cengine_native_faulttest && linux && (arm64 || amd64)

package supervisor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	cl "dev.cengine/guest/internal/storageclient"
	c "dev.cengine/guest/internal/storagecontrol"
	f "dev.cengine/guest/internal/storagefuse"
	p "dev.cengine/guest/internal/storagepki"
	s "dev.cengine/guest/internal/storageservice"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

var snapshot101ForeignPID = flag.Int("native-snapshot101-foreign", 0, "private expected mount-creator parent TGID")

// One actual mounted case, not acceptance of the other seven RTM-101 cases.
// Reuses the issued-credential/owned-initializer bootstrap; no second authority,
// replaced dispatch, synthetic credentials, or process-reader seam is installed.
func TestNativeSnapshot101SameUIDForeignTGID(t *testing.T) {
	prepareV4Profile(t)
	var fs unix.Statfs_t
	prepareV4Must(t, unix.Statfs("/scratch", &fs))
	if uint64(fs.Blocks)*uint64(fs.Bsize) > 128<<20 || fs.Files > 4096 {
		t.Fatal("requires existing bounded ext4 fixture")
	}
	base, err := os.MkdirTemp("/scratch", "snapshot101-")
	prepareV4Must(t, err)
	safe := true
	t.Cleanup(func() {
		info, err := os.ReadFile("/proc/self/mountinfo")
		if err != nil {
			safe = false
		}
		// No recursive removal through a surviving mount, even after setup failure.
		for _, line := range strings.Split(string(info), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 4 && (fields[4] == base || strings.HasPrefix(fields[4], base+"/")) {
				safe = false
			}
		}
		if safe && !t.Failed() {
			prepareV4Must(t, os.RemoveAll(base))
		} else {
			t.Logf("retained snapshot101 evidence: %s", base)
		}
	})
	for _, name := range []string{"store/volumes", "rootfs", "mounts"} {
		prepareV4Must(t, os.MkdirAll(filepath.Join(base, name), 0700))
	}
	root, err := os.Open(filepath.Join(base, "store"))
	prepareV4Must(t, err)
	t.Cleanup(func() { root.Close() })
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
		if safe {
			prepareV4Must(t, service.Close())
		}
	})
	ready, err := service.Ready()
	prepareV4Must(t, err)
	controller, control, closeControl := prepareV4Control(t, service, ready, key)
	defer closeControl()
	v, other := prepareV4ID(t), prepareV4ID(t)
	for name, volume := range map[string]a.ID{"v": v, "w": other} {
		prepareV4Call(t, control, c.Request{CreateVolume: &a.CreateVolumeRequest{Operation: prepareV4ID(t), Store: ready.Store.ID, Volume: volume, Name: name}})
	}
	backing := filepath.Join(base, "store/volumes/v")
	prepareV4Must(t, os.WriteFile(filepath.Join(backing, "probe"), []byte("pinned-owner-data"), 0600))
	hello, ownerKey := prepareV4Binding(t, ready, v)
	prepareV4Call(t, control, c.Request{ReservePrepare: &a.ReserveRequest{Operation: prepareV4ID(t), Prepare: hello.Binding.Prepare, Attachments: []a.Binding{hello.Binding}}})
	owner, _, join := prepareV4MountBootstrap(t, base, service, ready, controller, control, hello, ownerKey)

	// Independent W is a separate real mounted runtime attachment on the SAME
	// service/E. Its original process, TLS connection, key and mount persist.
	runtimeKey, err := p.NewAttachmentKey(p.RuntimeRole)
	prepareV4Must(t, err)
	pin, err := runtimeKey.Fingerprint()
	prepareV4Must(t, err)
	runtimeHello := a.DataHello{Epoch: ready.ServiceEpoch, Binding: a.Binding{Store: ready.Store.ID, Volume: other, Attachment: prepareV4ID(t), Container: hello.Binding.Container, Launch: prepareV4ID(t), Key: a.Fingerprint(pin.String()), Role: a.RuntimeRole, Mode: a.ReadWrite}}
	identity := prepareV4IssueAttachment(t, service, ready, controller, control, runtimeHello, runtimeKey)
	trust, server := prepareV4Trust(t, ready)
	config, err := p.ClientTLSConfig(identity, trust, server, ready.ServerKey)
	prepareV4Must(t, err)
	raw, runtimeJoin := prepareV4TCP(t, service.ServeData)
	conn := tls.Client(raw, config)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = conn.HandshakeContext(ctx)
	cancel()
	prepareV4Must(t, err)
	parent := filepath.Join(base, "mounts", string(runtimeHello.Binding.Attachment))
	prepareV4Must(t, os.Mkdir(parent, 0700))
	mounted, err := f.Mount(f.Config{Client: cl.Config{Conn: conn, TLSConfig: config, ServerPin: a.Fingerprint(ready.ServerKey.String()), Authority: runtimeHello, Version: w.Version, Profile: w.RequiredProfile(), SupportedCaps: (uint64(1) << (unix.CAP_LAST_CAP + 1)) - 1, Limits: cl.DefaultLimits(), Timeout: 15 * time.Second}, Mountpoint: filepath.Join(parent, "root"), Retire: func(error) {}})
	prepareV4Must(t, err)
	t.Cleanup(func() {
		if err := mounted.Close(); err != nil {
			safe = false
			t.Error(err)
		}
		prepareV4JoinedMount(t, mounted)
	})
	originalPID := os.Getpid()
	progress := func(value string) {
		if os.Getpid() != originalPID {
			t.Fatal("W consumer process replaced")
		}
		prepareV4Must(t, snapshot101Progress(mounted.Mountpoint(), value))
		prepareV4ExpectBytes(t, filepath.Join(base, "store/volumes/w/progress"), value)
	}
	progress("before")
	var before [2]unix.Stat_t
	evidence, mount := prepareV4OwnInitializer(t, base, hello, "snapshot-foreign", owner, &safe, func() {
		progress("while-V-fenced")
		before = snapshot101Stats(t, backing)
		prepareV4ExpectBytes(t, filepath.Join(backing, "probe"), "pinned-owner-data")
	})
	if evidence.Hello != hello || evidence.Stage != "snapshot-foreign" || evidence.Count != 3 || evidence.InitializerError != "" {
		t.Fatal("wrong foreign-process evidence", evidence)
	}
	mount.assertGone(t)
	snapshot101JoinedData(t, join())
	if !reflect.DeepEqual(before, snapshot101Stats(t, backing)) {
		t.Fatal("foreign attempt changed V root/file metadata")
	}
	prepareV4ExpectBytes(t, filepath.Join(backing, "probe"), "pinned-owner-data")
	progress("after")
	receipt := prepareV4Drain(t, control, hello)
	prepareV4Complete(t, control, hello, receipt)
	prepareV4Must(t, mounted.CloseGracefully(context.Background()))
	prepareV4JoinedMount(t, mounted)
	snapshot101JoinedData(t, runtimeJoin())
	r := prepareV4Call(t, control, c.Request{Retire: &a.RetireRequest{Operation: prepareV4ID(t), Store: runtimeHello.Binding.Store, Volume: other, Attachment: runtimeHello.Binding.Attachment, Launch: runtimeHello.Binding.Launch}}).Receipt
	if r == nil || r.Attachment != runtimeHello.Binding.Attachment || r.Volume != other || r.Prepare != "" || r.Revision == 0 {
		t.Fatal("missing real W drain")
	}
}

// Graceful client shutdown produces exact io.EOF in storageserver.readRequest.
// Reject every other server result, including joined errors containing EOF.
func snapshot101JoinedData(t *testing.T, err error) {
	t.Helper()
	if err != nil && err != io.EOF {
		t.Fatalf("DATA server join: %v", err)
	}
}

// atime is deliberately outside this case: independent content observation may
// update it. The separate read/readdir-atime catalogue case remains unimplemented.
func snapshot101Stats(t *testing.T, backing string) (out [2]unix.Stat_t) {
	for i, name := range []string{backing, filepath.Join(backing, "probe")} {
		prepareV4Must(t, unix.Lstat(name, &out[i]))
		out[i].Atim = unix.Timespec{}
	}
	return out
}

type snapshot101ForeignEvidence struct {
	Owner, PID, UID, GID int
	Denied               uint32
}

func snapshot101ForeignOwner(t *testing.T, hello a.DataHello, mount *f.Mounted) {
	fd, err := unix.Open(mount.Mountpoint(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	prepareV4Must(t, err)
	root := &confinedRoot{fd: fd}
	copy := &managedCopy{root: root, scope: managedCopyScope{Store: string(hello.Binding.Store), Volume: string(hello.Binding.Volume), Prepare: string(hello.Binding.Prepare), Attachment: string(hello.Binding.Attachment)}, call: managedPrepareIoctl}
	prepareV4Must(t, copy.control(w.BeginCopy))
	before, err := copy.identity("probe")
	prepareV4Must(t, err)
	prepareV4Must(t, snapshot101Readback(filepath.Join(mount.Mountpoint(), "probe"), "pinned-owner-data"))
	n, err := unix.Write(5, []byte{4})
	prepareV4Must(t, err)
	if n != 1 {
		t.Fatal("short held-fence ack")
	}
	prepareV4Must(t, unix.SetNonblock(11, true))
	release := os.NewFile(11, "snapshot101-W-progress")
	defer release.Close()
	prepareV4Must(t, release.SetReadDeadline(time.Now().Add(15*time.Second)))
	var ack [1]byte
	_, err = io.ReadFull(release, ack[:])
	prepareV4Must(t, err)
	if ack[0] != 5 {
		t.Fatal("missing independent W completion")
	}

	duplicate, err := unix.Dup(fd)
	prepareV4Must(t, err)
	inherited := os.NewFile(uintptr(duplicate), "snapshot101-root-grant")
	defer func() {
		if inherited != nil {
			inherited.Close()
		}
	}()
	report, writer, err := os.Pipe()
	prepareV4Must(t, err)
	defer report.Close()
	defer writer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Existing owned test executable, never a binary on the FUSE mount.
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestNativeSnapshot101ForeignProcess$", "-test.timeout=8s", fmt.Sprintf("-native-snapshot101-foreign=%d", os.Getpid()))
	cmd.Env = []string{"TMPDIR=/scratch"}
	// Original bootstrap ExtraFiles are not automatically CLOEXEC in this
	// initializer. Do not pass its tuple/report/ack/release descriptors to the
	// foreign process; only the two explicit grants below may cross this exec.
	for fd := 5; fd <= 11; fd++ {
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if errors.Is(err, unix.EBADF) {
			continue
		}
		prepareV4Must(t, err)
		_, err = unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags|unix.FD_CLOEXEC)
		prepareV4Must(t, err)
	}
	cmd.ExtraFiles = []*os.File{inherited, writer}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.WaitDelay = time.Second
	pidfd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, PidFD: &pidfd}
	runtime.LockOSThread()
	err = cmd.Run() // single actual Wait joins the child; timeout is never success
	runtime.UnlockOSThread()
	if pidfd >= 0 {
		defer unix.Close(pidfd)
	}
	prepareV4Must(t, err)
	if pidfd < 0 || ctx.Err() != nil || cmd.ProcessState == nil || !cmd.ProcessState.Success() {
		t.Fatal("foreign child did not cleanly join")
	}
	prepareV4Must(t, writer.Close())
	var proof snapshot101ForeignEvidence
	decoder := json.NewDecoder(io.LimitReader(report, 2049))
	decoder.DisallowUnknownFields()
	prepareV4Must(t, decoder.Decode(&proof))
	if decoder.Decode(new(any)) != io.EOF || proof.Owner != os.Getpid() || proof.PID != cmd.Process.Pid || proof.PID == proof.Owner || proof.UID != os.Geteuid() || proof.GID != os.Getegid() || proof.Denied != 3 {
		t.Fatal("not the exact same-UID foreign TGID", proof)
	}
	after, err := copy.identity("probe")
	prepareV4Must(t, err)
	if after != before {
		t.Fatal("foreign process changed physical identity")
	}
	prepareV4Must(t, snapshot101Readback(filepath.Join(mount.Mountpoint(), "probe"), "pinned-owner-data"))
	prepareV4Must(t, copy.control(w.FinishCopy))
	evidence := nativePrepareEvidence{Hello: hello, Stage: "snapshot-foreign", Count: proof.Denied}
	evidence.Root, err = nativePrepareIdentityAt(fd, ".")
	prepareV4Must(t, err)
	prepareV4Must(t, inherited.Close()) // no inherited FUSE root pin may survive graceful unmount
	inherited = nil
	prepareV4Must(t, root.close())
	prepareV4Must(t, mount.CloseGracefully(context.Background()))
	prepareV4JoinedMount(t, mount)
	prepareV4Must(t, nativePrepareWriteEvidence(evidence))
	t.Logf("original pinned owner=%d same-uid=%d foreign=%d denials=%d", proof.Owner, proof.UID, proof.PID, proof.Denied)
}

func TestNativeSnapshot101ForeignProcess(t *testing.T) {
	prepareV4Profile(t)
	if *snapshot101ForeignPID <= 0 || os.Getppid() != *snapshot101ForeignPID || os.Getpid() == *snapshot101ForeignPID {
		t.Fatal("private exact parent required")
	}
	// Actual FUSE type and exact mount are checked by the owning process; a
	// foreign Statfs itself would require denied owner-only DATA admission.
	// Even an inherited valid root grant and equal UID/GID cannot substitute
	// this different live TGID for the mount-creation-pinned initializer.
	if _, err := managedPrepareIoctl(3, w.PrepareRequest{Action: w.BeginCopy}); !errors.Is(err, unix.EACCES) {
		t.Fatal("foreign BeginCopy not denied", err)
	}
	fd, err := unix.Openat(3, "probe", unix.O_WRONLY|unix.O_TRUNC|unix.O_CLOEXEC, 0)
	if err == nil {
		unix.Close(fd)
	}
	if !errors.Is(err, unix.EACCES) {
		t.Fatal("foreign writable open not denied", err)
	}
	if err := unix.Unlinkat(3, "probe", 0); !errors.Is(err, unix.EACCES) {
		t.Fatal("foreign unlink not denied", err)
	}
	report := os.NewFile(4, "snapshot101-proof")
	defer report.Close()
	prepareV4Must(t, json.NewEncoder(report).Encode(snapshot101ForeignEvidence{Owner: os.Getppid(), PID: os.Getpid(), UID: os.Geteuid(), GID: os.Getegid(), Denied: 3}))
}

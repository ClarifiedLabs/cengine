//go:build cengine_native_faulttest && linux && (arm64 || amd64)

package supervisor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	cl "dev.cengine/guest/internal/storageclient"
	c "dev.cengine/guest/internal/storagecontrol"
	f "dev.cengine/guest/internal/storagefuse"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
	s "dev.cengine/guest/internal/storageservice"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// Narrow copies of the production-CSR/control helpers in
// storagefuse/native_stale_credentials_linux_test.go; no synthetic principals.
func prepareV4Must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func prepareV4ID(t *testing.T) a.ID {
	t.Helper()
	id, err := a.NewID()
	prepareV4Must(t, err)
	return id
}

func prepareV4Trust(t *testing.T, ready s.Ready) (p.Root, p.Binding) {
	t.Helper()
	root, err := p.ParseRootDER(ready.TLSRootDER)
	prepareV4Must(t, err)
	server, err := p.NewServerBinding(p.StoreID(ready.Store.ID), p.ServiceEpoch(ready.ServiceEpoch))
	prepareV4Must(t, err)
	return root, server
}

func prepareV4Control(t *testing.T, service *s.LifecycleService, ready s.Ready, key p.Key) (p.Identity, *c.Client, func()) {
	t.Helper()
	binding, err := p.NewControllerBinding(p.StoreID(ready.Store.ID), p.ControllerEpoch(ready.Controller.Epoch))
	prepareV4Must(t, err)
	csr, err := key.CSR(binding)
	prepareV4Must(t, err)
	cert, err := service.IssueController(csr)
	prepareV4Must(t, err)
	identity, err := cert.WithKey(key)
	prepareV4Must(t, err)
	root, _ := prepareV4Trust(t, ready)
	scope, err := service.Scope()
	prepareV4Must(t, err)
	raw, join := prepareV4TCP(t, service.ServeControl)
	client, err := c.NewPKILifecycleWorkloadClient(context.Background(), raw, c.PKILifecycleWorkloadClientConfig{Identity: identity, ServerRoot: root, ServerKey: ready.ServerKey, LifecycleIdentity: scope.Identity, ServiceEpoch: ready.ServiceEpoch, CurrentController: ready.Controller})
	prepareV4Must(t, err)
	return identity, client, func() { prepareV4Must(t, client.Close()); join() }
}

func prepareV4Call(t *testing.T, client *c.Client, request c.Request) c.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := client.Call(ctx, request)
	prepareV4Must(t, err)
	return response
}

// Only an already-issued PREPARE identity crosses this private inherited channel.
// The controller key never leaves its owner, and neither argv nor a disk file
// carries attachment key material. No production PID/configuration seam is used.
type prepareV4Bootstrap struct {
	sealed, data *os.File
	path         string
}
type prepareV4MountCredentials struct {
	Hello            a.DataHello
	Ready            s.Ready
	Certificate, Key []byte
	Pending          *a.CopyIntent `json:",omitempty"`
}

const prepareV4BootstrapSeals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL

func prepareV4IssueAttachment(t *testing.T, service *s.LifecycleService, ready s.Ready, controller p.Identity, control *c.Client, hello a.DataHello, key p.Key) p.Identity {
	t.Helper()
	prepareV4Call(t, control, c.Request{RegisterAttachment: &a.RegisterRequest{Operation: prepareV4ID(t), Binding: hello.Binding}})
	binding, err := d.AttachmentBinding(hello)
	prepareV4Must(t, err)
	csr, err := key.CSR(binding)
	prepareV4Must(t, err)
	raw, csrJoin := prepareV4TCP(t, service.ServeAttachmentCSR)
	scope, err := service.Scope()
	prepareV4Must(t, err)
	cert, err := s.RequestLifecycleAttachmentCertificate(context.Background(), raw, controller, ready, scope.Identity, hello, csr)
	prepareV4Must(t, err)
	prepareV4Must(t, csrJoin())
	identity, err := cert.WithKey(key)
	prepareV4Must(t, err)
	return identity
}

func prepareV4MountBootstrap(t *testing.T, base string, service *s.LifecycleService, ready s.Ready, controller p.Identity, control *c.Client, hello a.DataHello, key p.Key, pending ...a.CopyIntent) (*prepareV4Bootstrap, []byte, func() error) {
	t.Helper()
	identity := prepareV4IssueAttachment(t, service, ready, controller, control, hello, key)
	credentials := prepareV4Credentials(t, hello, ready, identity)
	if len(pending) > 1 {
		t.Fatal("multiple pending operations")
	}
	if len(pending) == 1 {
		credentials.Pending = &pending[0]
	}
	sealed := prepareV4SealCredentials(t, credentials)
	raw, join := prepareV4TCP(t, service.ServeData)
	data, err := raw.(*net.TCPConn).File()
	prepareV4Must(t, err)
	t.Cleanup(func() { data.Close() })
	prepareV4Must(t, raw.Close()) // the inherited descriptor is the sole client owner
	parent := filepath.Join(base, "mounts", string(hello.Binding.Attachment))
	prepareV4Must(t, os.Mkdir(parent, 0700))
	return &prepareV4Bootstrap{sealed: sealed, data: data, path: filepath.Join(parent, "root")}, identity.Certificate().DER(), join
}

func prepareV4Credentials(t *testing.T, hello a.DataHello, ready s.Ready, identity p.Identity) prepareV4MountCredentials {
	t.Helper()
	certDER, keyDER, err := identity.ExportDER()
	prepareV4Must(t, err)
	return prepareV4MountCredentials{Hello: hello, Ready: ready, Certificate: certDER, Key: keyDER}
}

func prepareV4SealCredentials(t *testing.T, credentials prepareV4MountCredentials) *os.File {
	t.Helper()
	fd, err := unix.MemfdCreate("prepare-v4-private-bootstrap", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	prepareV4Must(t, err)
	sealed := os.NewFile(uintptr(fd), "prepare-v4-private-bootstrap")
	t.Cleanup(func() { sealed.Close() })
	prepareV4Must(t, json.NewEncoder(sealed).Encode(credentials))
	_, err = sealed.Seek(0, io.SeekStart)
	prepareV4Must(t, err)
	_, err = unix.FcntlInt(sealed.Fd(), unix.F_ADD_SEALS, prepareV4BootstrapSeals)
	prepareV4Must(t, err)
	return sealed
}

func prepareV4ChildConstructMount(t *testing.T, hello a.DataHello) *f.Mounted {
	t.Helper()
	sealed := os.NewFile(8, "prepare-v4-private-bootstrap")
	defer sealed.Close()
	seals, err := unix.FcntlInt(sealed.Fd(), unix.F_GET_SEALS, 0)
	prepareV4Must(t, err)
	if seals != prepareV4BootstrapSeals {
		t.Fatal("unsealed inherited PREPARE bootstrap")
	}
	var credentials prepareV4MountCredentials
	decoder := json.NewDecoder(io.LimitReader(sealed, 32769))
	decoder.DisallowUnknownFields()
	prepareV4Must(t, decoder.Decode(&credentials))
	if decoder.Decode(new(any)) != io.EOF || credentials.Hello != hello || credentials.Ready.Store.ID != hello.Binding.Store || credentials.Ready.ServiceEpoch != hello.Epoch {
		t.Fatal("inherited mount bootstrap tuple mismatch")
	}
	binding, err := d.AttachmentBinding(hello)
	prepareV4Must(t, err)
	identity, err := p.ParseIdentityDER(credentials.Certificate, credentials.Key, binding)
	prepareV4Must(t, err)
	root, server := prepareV4Trust(t, credentials.Ready)
	cfg, err := p.ClientTLSConfig(identity, root, server, credentials.Ready.ServerKey)
	prepareV4Must(t, err)
	data := os.NewFile(9, "prepare-v4-data")
	raw, err := net.FileConn(data)
	prepareV4Must(t, err)
	prepareV4Must(t, data.Close())
	conn := tls.Client(raw, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = conn.HandshakeContext(ctx)
	cancel()
	prepareV4Must(t, err)
	// Resolve only the inherited private directory; Mount deliberately rejects
	// procfs/symlink path components. No caller-supplied pathname is accepted.
	base, err := os.Readlink("/proc/self/fd/4")
	prepareV4Must(t, err)
	mount, err := f.Mount(f.Config{Client: cl.Config{Conn: conn, TLSConfig: cfg, ServerPin: a.Fingerprint(credentials.Ready.ServerKey.String()), Authority: hello, Version: w.Version, Profile: w.RequiredProfile(), SupportedCaps: (uint64(1) << (unix.CAP_LAST_CAP + 1)) - 1, Limits: cl.DefaultLimits(), Timeout: 15 * time.Second}, Mountpoint: filepath.Join(base, string(hello.Binding.Attachment), "root"), Retire: func(error) {}})
	prepareV4Must(t, err)
	t.Cleanup(func() { prepareV4Must(t, mount.Close()); prepareV4JoinedMount(t, mount) })
	// Mount has now pinned this process before any FUSE BeginCopy request. The
	// parent may pin the exact kernel mount for post-SIGKILL cleanup, not use it.
	n, err := unix.Write(5, []byte{2})
	prepareV4Must(t, err)
	if n != 1 {
		t.Fatal("short child mount acknowledgement")
	}
	// ExtraFiles uses File.Fd(), which exports a blocking descriptor. Restore
	// pollability before NewFile so the inherited pipe supports its deadline.
	prepareV4Must(t, unix.SetNonblock(10, true))
	release := os.NewFile(10, "prepare-v4-parent-ready")
	defer release.Close()
	prepareV4Must(t, release.SetReadDeadline(time.Now().Add(30*time.Second)))
	var one [1]byte
	_, err = io.ReadFull(release, one[:])
	prepareV4Must(t, err)
	if one[0] != 3 {
		t.Fatal("invalid parent mount observation")
	}
	if credentials.Pending != nil {
		prepareV4PendingRootProbe(t, filepath.Join(base, string(hello.Binding.Attachment), "root"), hello, *credentials.Pending)
	}
	return mount
}

// This is an exact kernel mount pin, NOT a replacement/fake f.Mounted. Success
// teardown runs CloseGracefully + Done inside the child. Interrupted teardown
// uses real process Wait, this pin's unmount, mountinfo absence, and DATA join.
type prepareV4ChildMount struct {
	path string
	id   uint64
	pin  *os.File
}

func (m *prepareV4ChildMount) capture(t *testing.T) {
	t.Helper()
	fd, err := unix.Open(m.path, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	prepareV4Must(t, err)
	m.pin = os.NewFile(uintptr(fd), "prepare-v4-exact-mount")
	info, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
	prepareV4Must(t, err)
	for _, line := range strings.Split(string(info), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "mnt_id:" {
			m.id, err = strconv.ParseUint(fields[1], 10, 64)
			prepareV4Must(t, err)
		}
	}
	if m.id == 0 {
		t.Fatal("missing pinned kernel mount ID")
	}
	if !m.present(t) {
		t.Fatal("child mount pin is not the exact FUSE mount")
	}
}
func (m *prepareV4ChildMount) present(t *testing.T) bool {
	t.Helper()
	info, err := os.ReadFile("/proc/self/mountinfo")
	prepareV4Must(t, err)
	found := false
	for _, line := range strings.Split(string(info), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		sameID := fields[0] == strconv.FormatUint(m.id, 10)
		samePath := fields[4] == m.path
		if sameID || samePath {
			if !sameID || !samePath || !strings.Contains(line, " - fuse") {
				t.Fatal("pinned child mount identity changed")
			}
			found = true
		}
	}
	return found
}
func (m *prepareV4ChildMount) assertGone(t *testing.T) {
	t.Helper()
	if m.id == 0 || m.present(t) {
		t.Fatal("child mount teardown did not remove exact kernel mount")
	}
}
func (m *prepareV4ChildMount) abort(t *testing.T) {
	t.Helper()
	if m.pin == nil || !m.present(t) {
		t.Fatal("missing exact interrupted mount pin")
	}
	prepareV4Must(t, unix.Unmount(fmt.Sprintf("/proc/self/fd/%d", m.pin.Fd()), unix.MNT_FORCE|unix.MNT_DETACH))
	m.assertGone(t)
	prepareV4Must(t, m.pin.Close())
	m.pin = nil
}

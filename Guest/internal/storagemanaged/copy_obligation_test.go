package storagemanaged

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	at "dev.cengine/guest/internal/storageauthoritytest"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// Real authority, TLS admission, wire codec, Dispatch and durable journal. Only
// root ext4 identity and the platform-specific PREPARE body are host seams.
type copyObligationHost struct {
	authority      *a.Authority
	lifecycle      *at.Fixture
	config         a.Config
	session        *Session
	guard          *a.Guard
	root           a.CopyRootV1
	path           string
	prepareWitness *a.PrepareCompatibilityWitness
}

func copyHostMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func copyHostID(t *testing.T) a.ID { id, err := a.NewID(); copyHostMust(t, err); return id }
func copyHostObject(fd int) (a.Ext4ObjectV1, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return a.Ext4ObjectV1{}, err
	}
	o := a.Ext4ObjectV1{Inode: uint64(st.Ino), Generation: 1, FileType: uint32(st.Mode) & unix.S_IFMT, HandleType: 1, HandleSize: 8}
	binary.LittleEndian.PutUint32(o.Handle[:4], uint32(o.Inode))
	binary.LittleEndian.PutUint32(o.Handle[4:], o.Generation)
	return o, nil
}

type copyHostRecovery struct {
	Lifecycle  *at.Fixture
	Bootstrap  ed25519.PublicKey
	Controller ed25519.PrivateKey
	Binding    a.Binding
}

func newCopyObligationHost(t *testing.T, path string, deviceID ...string) *copyObligationHost {
	t.Helper()
	return newCopyObligationHostWithPlan(t, path, "", deviceID...)
}

func newCopyObligationHostWithPlan(t *testing.T, path, stage string, deviceID ...string) *copyObligationHost {
	t.Helper()
	h := &copyObligationHost{path: path}
	key := func() ed25519.PrivateKey { _, k, e := ed25519.GenerateKey(rand.Reader); copyHostMust(t, e); return k }
	fp := func(k ed25519.PrivateKey) a.Fingerprint {
		f, e := a.PublicKeyFingerprint(k.Public())
		copyHostMust(t, e)
		return f
	}
	caKey := key()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "host-test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, caKey.Public(), caKey)
	copyHostMust(t, err)
	ca, err := x509.ParseCertificate(der)
	copyHostMust(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	cert := func(k ed25519.PrivateKey) tls.Certificate {
		tmp := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"host.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
		der, e := x509.CreateCertificate(rand.Reader, tmp, ca, k.Public(), caKey)
		copyHostMust(t, e)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
	}
	serverCert := cert(key())
	conn := func(k ed25519.PrivateKey) *tls.Conn {
		l, r := net.Pipe()
		t.Cleanup(func() { l.Close(); r.Close() })
		server := tls.Server(l, &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true})
		client := tls.Client(r, &tls.Config{Certificates: []tls.Certificate{cert(k)}, RootCAs: pool, ServerName: "host.test", MinVersion: tls.VersionTLS13})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- client.HandshakeContext(ctx) }()
		copyHostMust(t, server.HandshakeContext(ctx))
		copyHostMust(t, <-done)
		return server
	}
	copyHostMust(t, os.MkdirAll(filepath.Join(path, "volumes", "data"), 0700))
	root, err := os.Open(path)
	copyHostMust(t, err)
	t.Cleanup(func() { root.Close() })
	backing, err := os.Open(filepath.Join(path, "volumes", "data"))
	copyHostMust(t, err)
	t.Cleanup(func() { backing.Close() })
	device := "host-copy-obligation"
	if len(deviceID) == 1 {
		device = deviceID[0]
	}
	bootstrap := key()
	h.config = a.Config{Root: root, DeviceID: device, BootstrapKey: bootstrap.Public().(ed25519.PublicKey), Barrier: func(a.Binding, *os.File) error { return nil }}
	controller := key()
	store := copyHostID(t)
	var saved copyHostRecovery
	recoveryPath := filepath.Join(path, "host-copy-recovery.json")
	data, readErr := os.ReadFile(recoveryPath)
	recovering := readErr == nil
	if recovering {
		copyHostMust(t, json.Unmarshal(data, &saved))
		controller, store, h.config.BootstrapKey = saved.Controller, saved.Binding.Store, saved.Bootstrap
		h.lifecycle = saved.Lifecycle
		h.authority, err = h.lifecycle.OpenExpected(h.config, h.lifecycle.Expected.ExpectedStartup)
	} else {
		if !errors.Is(readErr, os.ErrNotExist) {
			t.Fatal(readErr)
		}
		h.lifecycle = at.New(t, bootstrap, store, fp(controller))
		h.authority, err = h.lifecycle.Initialize(h.config)
	}
	copyHostMust(t, err)
	t.Cleanup(func() { copyHostMust(t, h.authority.Close()) })
	cp, err := h.authority.AuthenticateController(context.Background(), conn(controller), 1)
	copyHostMust(t, err)
	var st unix.Stat_t
	copyHostMust(t, unix.Fstat(int(backing.Fd()), &st))
	volume := copyHostID(t)
	if recovering {
		volume = saved.Binding.Volume
	} else {
		copyHostMust(t, h.authority.AddVolume(cp, a.VolumeRequest{Operation: copyHostID(t), Volume: a.Volume{ID: volume, Name: "data", Root: a.RootIdentity{Device: uint64(st.Dev), Inode: uint64(st.Ino)}}}))
	}
	prepare := copyHostID(t)
	ownerKey := key()
	b := a.Binding{Store: store, Volume: volume, Attachment: copyHostID(t), Container: a.ContainerID(strings.Repeat("a", 64)), Launch: copyHostID(t), Key: fp(ownerKey), Role: a.PrepareRole, Mode: a.ReadWrite, Prepare: prepare}
	reserve := a.ReserveRequest{Operation: copyHostID(t), Prepare: prepare, Attachments: []a.Binding{b}}
	if recovering {
		receipt, err := h.authority.Retire(context.Background(), cp, a.RetireRequest{Operation: copyHostID(t), Store: store, Volume: volume, Attachment: saved.Binding.Attachment, Launch: saved.Binding.Launch})
		copyHostMust(t, err)
		copyHostMust(t, h.authority.ReplacePrepare(cp, a.ReplaceRequest{Operation: copyHostID(t), Prepare: saved.Binding.Prepare, Receipts: []a.Receipt{receipt}, Successor: reserve}))
	} else {
		copyHostMust(t, h.authority.ReservePrepare(cp, reserve))
	}
	copyHostMust(t, h.authority.RegisterAttachment(cp, a.RegisterRequest{Operation: copyHostID(t), Binding: b}))
	if stage != "" {
		h.prepareWitness, err = h.authority.InstallPrepareCompatibility(a.PrepareCompatibilityPlan{Stage: stage, Epoch: h.authority.Epoch(), Controller: a.Controller{Epoch: 1, Key: fp(controller)}, Target: b, Bindings: []a.Binding{b}, RuntimeAttachments: []a.ID{copyHostID(t)}})
		copyHostMust(t, err)
	}
	p, err := h.authority.AuthenticateData(context.Background(), conn(ownerKey), a.DataHello{Epoch: h.authority.Epoch(), Binding: b})
	copyHostMust(t, err)
	h.guard, err = h.authority.Admit(p, volume, true)
	copyHostMust(t, err)
	t.Cleanup(h.guard.Release)
	gate := new(sync.Mutex)
	registry, err := NewRegistry(gate)
	copyHostMust(t, err)
	h.session = &Session{principal: p, binding: b, registry: registry, root: backing}
	obj, err := copyHostObject(int(backing.Fd()))
	copyHostMust(t, err)
	h.root = a.CopyRootV1{Store: store, Volume: volume, BackingUUID: [16]byte{1}, Root: obj}
	data, err = json.Marshal(copyHostRecovery{h.lifecycle, h.config.BootstrapKey, controller, b})
	copyHostMust(t, err)
	copyHostMust(t, os.WriteFile(recoveryPath, data, 0600))
	return h
}
func (h *copyObligationHost) dispatch(action w.PrepareAction, id a.ID) (Result, error) {
	return h.session.Dispatch(h.guard, w.Request{Sequence: 1, Auth: w.Auth{Kind: w.CallerAuth, Caller: &w.Caller{Groups: []uint32{}}}, Body: w.PrepareRequest{Node: 1, Handle: 1, Action: action, Intent: id}})
}

func TestCopyObligationDispatchFaultsRemainDurable(t *testing.T) {
	for _, kind := range []string{"eio", "enospc", "latched", "ordinary"} {
		t.Run(kind, func(t *testing.T) {
			h := newCopyObligationHost(t, t.TempDir())
			h.session.registry.prepareOperation = func(g *a.Guard, _ w.PrepareRequest) (w.ReplyBody, error) {
				if kind == "ordinary" {
					return nil, syscall.EPERM
				}
				i, err := g.BeginCopy(h.root)
				copyHostMust(t, err)
				if kind == "latched" {
					h.session.registry.latch(h.root.Volume, syscall.EIO)
					return w.PrepareReply{Intent: i, Root: h.root}, nil
				}
				if kind == "enospc" {
					return nil, syscall.ENOSPC
				}
				return nil, syscall.EIO
			}
			result, err := h.dispatch(w.BeginCopy, "")
			if kind == "ordinary" {
				if err != nil || result.Reply.Errno != uint32(syscall.EPERM) {
					t.Fatal(result, err)
				}
			} else if !errors.Is(err, ErrVolumeFault) {
				t.Fatal("lost sticky fault", err)
			}
			h.guard.Release()
			copyHostMust(t, h.authority.Close())
			reopened, err := h.lifecycle.Open(h.config)
			if kind == "ordinary" {
				copyHostMust(t, err)
				copyHostMust(t, reopened.Close())
			} else if !errors.Is(err, a.ErrRepairRequired) {
				t.Fatal("fault survived only in memory", err)
			}
		})
	}
}

func TestCopyObligationDispatchCrashWorker(t *testing.T) {
	path := os.Getenv("CENGINE_DISPATCH_COPY_ROOT")
	if path == "" {
		return
	}
	boundary := os.Getenv("CENGINE_DISPATCH_COPY_BOUNDARY")
	h := newCopyObligationHost(t, path)
	data, err := json.Marshal(h.config.BootstrapKey)
	copyHostMust(t, err)
	copyHostMust(t, os.WriteFile(filepath.Join(path, "bootstrap.json"), data, 0600))
	i, err := h.guard.BeginCopy(h.root)
	copyHostMust(t, err)
	action := w.BindCopyTransaction
	if boundary != "provision" {
		i, err = h.guard.ProvisionCopyTransaction(i.ID, copyHostObject)
		copyHostMust(t, err)
		i, err = h.guard.StartCopyCleanup(i.ID, i.Transaction, a.CopyCleanupV1{})
		copyHostMust(t, err)
		action = w.FinishCopy
	}
	h.session.registry.prepareOperation = func(g *a.Guard, _ w.PrepareRequest) (w.ReplyBody, error) {
		if boundary == "provision" {
			_, err := g.ProvisionCopyTransaction(i.ID, copyHostObject)
			copyHostMust(t, err)
			os.Exit(73)
		}
		copyHostMust(t, os.Remove(filepath.Join(path, "volumes", "data", ".cengine-copyup-transaction")))
		copyHostMust(t, h.session.root.Sync())
		if boundary == "completed" {
			copyHostMust(t, g.FinishCopy(i.ID))
		}
		os.Exit(73)
		return nil, nil
	}
	_, err = h.dispatch(action, i.ID)
	t.Fatal("crash not reached", err)
}
func TestCopyObligationRealDispatchProcessCrash(t *testing.T) {
	for _, boundary := range []string{"provision", "cleaning", "completed"} {
		t.Run(boundary, func(t *testing.T) {
			path := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCopyObligationDispatchCrashWorker$", "-test.count=1")
			cmd.Env = append(os.Environ(), "CENGINE_DISPATCH_COPY_ROOT="+path, "CENGINE_DISPATCH_COPY_BOUNDARY="+boundary, "GORACE=atexit_sleep_ms=0")
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 73 {
				t.Fatalf("worker %v\n%s", err, out)
			}
			data, err := os.ReadFile(filepath.Join(path, "bootstrap.json"))
			copyHostMust(t, err)
			var bootstrap ed25519.PublicKey
			copyHostMust(t, json.Unmarshal(data, &bootstrap))
			root, err := os.Open(path)
			copyHostMust(t, err)
			defer root.Close()
			recoveryData, err := os.ReadFile(filepath.Join(path, "host-copy-recovery.json"))
			copyHostMust(t, err)
			var saved copyHostRecovery
			copyHostMust(t, json.Unmarshal(recoveryData, &saved))
			authority, err := saved.Lifecycle.OpenExpected(a.Config{Root: root, DeviceID: "host-copy-obligation", BootstrapKey: bootstrap, Barrier: func(a.Binding, *os.File) error { return nil }}, saved.Lifecycle.Expected.ExpectedStartup)
			copyHostMust(t, err)
			copyHostMust(t, authority.Close())
		})
	}
}

func TestCopyObligationDispatchAuthorizationDoesNotPoison(t *testing.T) {
	h := newCopyObligationHost(t, t.TempDir())
	result, err := h.dispatch(w.BindCopyTransaction, copyHostID(t))
	if err != nil || result.Reply.Errno == 0 || h.session.registry.faults[h.root.Volume] != nil {
		t.Fatal("ordinary authorization rejection poisoned volume", result, err)
	}
	h.session.registry.prepareOperation = func(g *a.Guard, _ w.PrepareRequest) (w.ReplyBody, error) {
		i, err := g.BeginCopy(h.root)
		return w.PrepareReply{Intent: i, Root: h.root}, err
	}
	result, err = h.session.Dispatch(h.guard, w.Request{Sequence: 2, Auth: w.Auth{Kind: w.CallerAuth, Caller: &w.Caller{Groups: []uint32{}}}, Body: w.PrepareRequest{Node: 1, Handle: 1, Action: w.BeginCopy}})
	if err != nil || result.Reply.Errno != 0 {
		t.Fatal("rejection prevented later authorized Begin", result, err)
	}
}

func TestCopyObligationPendingReplayDispatch(t *testing.T) {
	path := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCopyObligationDispatchCrashWorker$", "-test.count=1")
	cmd.Env = append(os.Environ(), "CENGINE_DISPATCH_COPY_ROOT="+path, "CENGINE_DISPATCH_COPY_BOUNDARY=provision", "GORACE=atexit_sleep_ms=0")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 73 {
		t.Fatalf("worker %v\n%s", err, out)
	}
	h := newCopyObligationHost(t, path)
	i, err := h.guard.BeginCopy(h.root)
	copyHostMust(t, err)
	sequence := uint64(0)
	dispatch := func(body w.RequestBody) (Result, error) {
		sequence++
		return h.session.Dispatch(h.guard, w.Request{Sequence: sequence, Auth: w.Auth{Kind: w.CallerAuth, Caller: &w.Caller{Groups: []uint32{}}}, Body: body})
	}
	for _, body := range []w.RequestBody{w.ReadRequest{Node: 1, Handle: 1, Size: 1}, w.WriteRequest{Node: 1, Handle: 1, Data: []byte{1}}} {
		result, err := dispatch(body)
		if err != nil || result.Reply.Errno != uint32(syscall.EBUSY) {
			t.Fatal("pending replay executed ordinary DATA", result, err)
		}
	}
	h.session.registry.prepareOperation = func(g *a.Guard, p w.PrepareRequest) (w.ReplyBody, error) {
		switch p.Action {
		case w.BeginCopy:
			intent, err := g.BeginCopy(h.root)
			return w.PrepareReply{Intent: intent, Root: h.root}, err
		case w.IdentityAt:
			intent, err := g.InspectCopy(i.ID, h.root)
			return w.PrepareReply{Intent: intent, Root: h.root, Identity: h.root.Root}, err
		case w.BindCopyTransaction:
			return nil, syscall.EPERM
		}
		t.Fatal("wrong replay reached syscall seam")
		return nil, syscall.EIO
	}
	for _, action := range []w.PrepareAction{w.BeginCopy, w.IdentityAt, w.BindCopyTransaction, w.SealManifest} {
		p := w.PrepareRequest{Node: 1, Handle: 1, Action: action, Intent: i.ID}
		if action == w.BeginCopy {
			p.Intent = ""
		}
		if action == w.IdentityAt {
			p.Path = []byte("entry")
		}
		result, err := dispatch(p)
		if err != nil {
			t.Fatal(result, err)
		}
		if (action == w.BeginCopy || action == w.IdentityAt) && result.Reply.Errno != 0 {
			t.Fatal(result)
		}
		if (action == w.BindCopyTransaction || action == w.SealManifest) && result.Reply.Errno == 0 {
			t.Fatal("unexpected success", result)
		}
	}
	if h.session.registry.faults[h.root.Volume] != nil || h.session.failed {
		t.Fatal("authorization denial poisoned session/volume")
	}
	if !errors.Is(h.guard.CheckCopyReplay(), a.ErrBlocked) {
		t.Fatal("rejected replay erased pending")
	}
	h.session.registry.prepareOperation = func(g *a.Guard, _ w.PrepareRequest) (w.ReplyBody, error) {
		intent, err := g.ProvisionCopyTransaction(i.ID, copyHostObject)
		return w.PrepareReply{Intent: intent, Root: h.root}, err
	}
	result, err := dispatch(w.PrepareRequest{Node: 1, Handle: 1, Action: w.BindCopyTransaction, Intent: i.ID})
	if err != nil || result.Reply.Errno != 0 {
		t.Fatal(result, err)
	}
	copyHostMust(t, h.guard.CheckCopyReplay())
}

func TestCopyObligationReplayRootBootstrapIsNarrow(t *testing.T) {
	for _, tc := range []struct {
		body    w.RequestBody
		allowed bool
	}{
		{w.GetAttrRequest{Node: 1}, true},
		{w.GetAttrRequest{Node: 2}, false},
		{w.GetAttrRequest{Node: 1, Handle: new(w.HandleID)}, false},
		{w.OpenDirRequest{Node: 1}, true},
		{w.OpenDirRequest{Node: 1, Flags: 0x10000 | 0x80000 | 0x8000}, true},
		{w.OpenDirRequest{Node: 2}, false},
		{w.OpenDirRequest{Node: 1, Flags: w.OpenTruncate}, false},
		{w.OpenDirRequest{Node: 1, Flags: w.OpenWriteOnly}, false},
		{w.ReadRequest{Node: 1, Handle: 1, Size: 1}, false},
	} {
		if replayRootBootstrap(w.Request{Body: tc.body}) != tc.allowed {
			t.Fatalf("unexpected replay bootstrap: %+v", tc.body)
		}
	}
}

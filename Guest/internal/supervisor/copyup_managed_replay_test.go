//go:build darwin || linux

package supervisor

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
	"reflect"
	"strings"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	at "dev.cengine/guest/internal/storageauthoritytest"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// Actual TLS/authority/journal/marker fences and both ioctl codecs. Only the
// ext4 identity acquisition and platform-specific private control body are fake;
// no Linux, mounted FUSE, or ext4 runtime proof is claimed by these host tests.
type replayHost struct {
	guard    *a.Guard
	root     a.CopyRootV1
	binding  a.Binding
	path     string
	calls    []w.PrepareAction
	sequence uint64
	deny     w.PrepareAction
}
type replayRecovery struct {
	Lifecycle  *at.Fixture
	Bootstrap  ed25519.PublicKey
	Controller ed25519.PrivateKey
	Binding    a.Binding
}

func replayMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func replayID(t *testing.T) a.ID { t.Helper(); id, err := a.NewID(); replayMust(t, err); return id }
func replayObject(fd int) (a.Ext4ObjectV1, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return a.Ext4ObjectV1{}, err
	}
	o := a.Ext4ObjectV1{Inode: uint64(st.Ino), Generation: 1, FileType: uint32(st.Mode) & unix.S_IFMT, HandleType: 1, HandleSize: 8}
	binary.LittleEndian.PutUint32(o.Handle[:4], uint32(o.Inode))
	binary.LittleEndian.PutUint32(o.Handle[4:], 1)
	return o, nil
}
func newReplayHost(t *testing.T, path string) *replayHost {
	t.Helper()
	h := &replayHost{path: path}
	key := func() ed25519.PrivateKey { _, k, err := ed25519.GenerateKey(rand.Reader); replayMust(t, err); return k }
	fp := func(k ed25519.PrivateKey) a.Fingerprint {
		f, err := a.PublicKeyFingerprint(k.Public())
		replayMust(t, err)
		return f
	}
	caKey := key()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "replay-host"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, caKey.Public(), caKey)
	replayMust(t, err)
	ca, err := x509.ParseCertificate(der)
	replayMust(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	cert := func(k ed25519.PrivateKey) tls.Certificate {
		tmp := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"replay.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, tmp, ca, k.Public(), caKey)
		replayMust(t, err)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
	}
	serverCert := cert(key())
	conn := func(k ed25519.PrivateKey) *tls.Conn {
		l, r := net.Pipe()
		t.Cleanup(func() { l.Close(); r.Close() })
		server := tls.Server(l, &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true})
		client := tls.Client(r, &tls.Config{Certificates: []tls.Certificate{cert(k)}, RootCAs: pool, ServerName: "replay.test", MinVersion: tls.VersionTLS13})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- client.HandshakeContext(ctx) }()
		replayMust(t, server.HandshakeContext(ctx))
		replayMust(t, <-done)
		return server
	}
	replayMust(t, os.MkdirAll(filepath.Join(path, "volumes", "data"), 0700))
	root, err := os.Open(path)
	replayMust(t, err)
	t.Cleanup(func() { root.Close() })
	backing, err := os.Open(filepath.Join(path, "volumes", "data"))
	replayMust(t, err)
	t.Cleanup(func() { backing.Close() })
	bootstrap := key()
	config := a.Config{Root: root, DeviceID: "replay-host", BootstrapKey: bootstrap.Public().(ed25519.PublicKey), Barrier: func(a.Binding, *os.File) error { return nil }}
	controller, store := key(), replayID(t)
	var saved replayRecovery
	recoveryPath := filepath.Join(path, "replay-host.json")
	data, readErr := os.ReadFile(recoveryPath)
	recovering := readErr == nil
	var authority *a.Authority
	var lifecycle *at.Fixture
	if recovering {
		replayMust(t, json.Unmarshal(data, &saved))
		controller, store, config.BootstrapKey = saved.Controller, saved.Binding.Store, saved.Bootstrap
		lifecycle = saved.Lifecycle
		authority, err = lifecycle.OpenExpected(config, lifecycle.Expected.ExpectedStartup)
	} else {
		if !errors.Is(readErr, os.ErrNotExist) {
			t.Fatal(readErr)
		}
		lifecycle = at.New(t, bootstrap, store, fp(controller))
		authority, err = lifecycle.Initialize(config)
	}
	replayMust(t, err)
	t.Cleanup(func() { replayMust(t, authority.Close()) })
	cp, err := authority.AuthenticateController(context.Background(), conn(controller), 1)
	replayMust(t, err)
	var st unix.Stat_t
	replayMust(t, unix.Fstat(int(backing.Fd()), &st))
	volume := replayID(t)
	if recovering {
		volume = saved.Binding.Volume
	} else {
		replayMust(t, authority.AddVolume(cp, a.VolumeRequest{Operation: replayID(t), Volume: a.Volume{ID: volume, Name: "data", Root: a.RootIdentity{Device: uint64(st.Dev), Inode: uint64(st.Ino)}}}))
	}
	prepare, ownerKey := replayID(t), key()
	b := a.Binding{Store: store, Volume: volume, Attachment: replayID(t), Container: a.ContainerID(strings.Repeat("a", 64)), Launch: replayID(t), Key: fp(ownerKey), Role: a.PrepareRole, Mode: a.ReadWrite, Prepare: prepare}
	reserve := a.ReserveRequest{Operation: replayID(t), Prepare: prepare, Attachments: []a.Binding{b}}
	if recovering {
		receipt, err := authority.Retire(context.Background(), cp, a.RetireRequest{Operation: replayID(t), Store: store, Volume: volume, Attachment: saved.Binding.Attachment, Launch: saved.Binding.Launch})
		replayMust(t, err)
		replayMust(t, authority.ReplacePrepare(cp, a.ReplaceRequest{Operation: replayID(t), Prepare: saved.Binding.Prepare, Receipts: []a.Receipt{receipt}, Successor: reserve}))
	} else {
		replayMust(t, authority.ReservePrepare(cp, reserve))
	}
	replayMust(t, authority.RegisterAttachment(cp, a.RegisterRequest{Operation: replayID(t), Binding: b}))
	p, err := authority.AuthenticateData(context.Background(), conn(ownerKey), a.DataHello{Epoch: authority.Epoch(), Binding: b})
	replayMust(t, err)
	h.guard, err = authority.Admit(p, volume, true)
	replayMust(t, err)
	t.Cleanup(h.guard.Release)
	obj, err := replayObject(int(backing.Fd()))
	replayMust(t, err)
	h.root = a.CopyRootV1{Store: store, Volume: volume, BackingUUID: [16]byte{1}, Root: obj}
	h.binding = b
	data, err = json.Marshal(replayRecovery{lifecycle, config.BootstrapKey, controller, b})
	replayMust(t, err)
	replayMust(t, os.WriteFile(recoveryPath, data, 0600))
	return h
}
func replayAction(action w.PrepareAction) string {
	switch action {
	case w.BeginCopy:
		return a.CopyOperationBegin
	case w.BindCopyTransaction:
		return a.CopyOperationProvision
	case w.SealManifest:
		return a.CopyOperationSeal
	case w.StartCleanup:
		return a.CopyOperationCleanup
	case w.FinishCopy:
		return a.CopyOperationFinish
	}
	return ""
}
func (h *replayHost) body(request w.PrepareRequest) (w.PrepareReply, error) {
	g := h.guard
	var i a.CopyIntent
	var err error
	if request.Action != w.BeginCopy {
		i, err = g.InspectCopy(request.Intent, h.root)
		if err != nil {
			return w.PrepareReply{}, err
		}
	}
	switch request.Action {
	case w.BeginCopy:
		i, err = g.BeginCopy(h.root)
	case w.BindCopyTransaction:
		i, err = g.ProvisionCopyTransaction(request.Intent, replayObject)
	case w.SealManifest:
		err = g.SealCopyManifest(i.ID, i.Transaction, []byte("private sealed evidence"))
		if err == nil {
			i, err = g.InspectCopy(i.ID, h.root)
		}
	case w.StartCleanup:
		cleanup := i.Initial
		if i.ManifestSize != 0 {
			cleanup.Manifest = i.Transaction
			cleanup.Manifest.Inode++
			cleanup.Manifest.FileType = unix.S_IFREG
			binary.LittleEndian.PutUint32(cleanup.Manifest.Handle[:4], uint32(cleanup.Manifest.Inode))
		}
		if i.Phase == a.CopyCleaning {
			cleanup = i.Cleanup
		}
		i, err = g.StartCopyCleanup(i.ID, i.Transaction, cleanup)
	case w.FinishCopy:
		err = g.FinishCopy(i.ID)
		if err == nil {
			i.Phase = a.CopyCompleted
		}
	}
	reply := w.PrepareReply{Intent: i, Root: h.root}
	if request.Action == w.BeginCopy && err == nil {
		var pending string
		pending, err = g.PendingCopyOperation(i.ID)
		for _, action := range []w.PrepareAction{w.BeginCopy, w.BindCopyTransaction, w.SealManifest, w.StartCleanup, w.FinishCopy} {
			if pending == replayAction(action) {
				reply.Pending = action
			}
		}
	}
	return reply, err
}
func (h *replayHost) call(request w.PrepareRequest) (w.PrepareReply, error) {
	h.calls = append(h.calls, request.Action)
	raw, err := w.EncodePrepareIoctl(request)
	if err != nil {
		return w.PrepareReply{}, err
	}
	request, err = w.DecodePrepareIoctl(raw)
	if err != nil {
		return w.PrepareReply{}, err
	}
	h.sequence++
	o, err := h.guard.BeginCopyOperation(h.sequence, replayAction(request.Action), request.Intent)
	if err != nil {
		return w.PrepareReply{}, err
	}
	var reply w.PrepareReply
	if h.deny == request.Action {
		err = a.ErrUnauthorized
	} else {
		reply, err = h.body(request)
	}
	if completeErr := o.CompleteRequest(nil, err == nil); completeErr != nil {
		return w.PrepareReply{}, completeErr
	}
	if err != nil {
		return w.PrepareReply{}, err
	}
	raw, err = w.EncodePrepareIoctlReply(reply)
	if err != nil {
		return w.PrepareReply{}, err
	}
	return w.DecodePrepareIoctlReply(raw)
}
func (h *replayHost) accept(i a.CopyIntent) error {
	if i.Owner != h.binding || i.Root != h.root {
		return a.ErrUnauthorized
	}
	return nil
}

func TestManagedPendingCrashWorker(t *testing.T) {
	path := os.Getenv("CENGINE_SUPERVISOR_PENDING_ROOT")
	if path == "" {
		return
	}
	boundary := os.Getenv("CENGINE_SUPERVISOR_PENDING_BOUNDARY")
	h := newReplayHost(t, path)
	var intent a.ID
	for _, action := range []w.PrepareAction{w.BeginCopy, w.BindCopyTransaction, w.SealManifest, w.StartCleanup, w.FinishCopy} {
		h.sequence++
		o, err := h.guard.BeginCopyOperation(h.sequence, replayAction(action), intent)
		replayMust(t, err)
		if boundary == replayAction(action)+"-before" {
			os.Exit(73)
		}
		r, err := h.body(w.PrepareRequest{Action: action, Intent: intent})
		replayMust(t, err)
		intent = r.Intent.ID
		if boundary == replayAction(action)+"-after" {
			os.Exit(73)
		}
		replayMust(t, o.Complete(nil))
	}
	t.Fatal("missing crash boundary", boundary)
}
func crashedReplayHost(t *testing.T, boundary string) *replayHost {
	t.Helper()
	path := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestManagedPendingCrashWorker$", "-test.count=1")
	cmd.Env = append(os.Environ(), "CENGINE_SUPERVISOR_PENDING_ROOT="+path, "CENGINE_SUPERVISOR_PENDING_BOUNDARY="+boundary, "GORACE=atexit_sleep_ms=0")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 73 {
		t.Fatalf("crash worker: %v\n%s", err, out)
	}
	return newReplayHost(t, path)
}
func TestManagedPendingActualFenceReplay(t *testing.T) {
	for _, action := range []w.PrepareAction{w.BeginCopy, w.BindCopyTransaction, w.SealManifest, w.StartCleanup, w.FinishCopy} {
		for _, when := range []string{"before", "after"} {
			t.Run(replayAction(action)+"-"+when, func(t *testing.T) {
				h := crashedReplayHost(t, replayAction(action)+"-"+when)
				if action != w.BeginCopy && !(action == w.FinishCopy && when == "after") {
					if !errors.Is(h.guard.CheckCopyReplay(), a.ErrBlocked) {
						t.Fatal("ordinary DATA not fenced before replay")
					}
					wrong := w.SealManifest
					if action == wrong {
						wrong = w.BindCopyTransaction
					}
					i, err := h.guard.BeginCopy(h.root)
					replayMust(t, err)
					if _, err := h.call(w.PrepareRequest{Action: wrong, Intent: i.ID}); err == nil {
						t.Fatal("wrong replay accepted")
					}
					h.calls = nil
				}
				i, err := beginManagedCopy(h.call, h.accept)
				replayMust(t, err)
				replayMust(t, h.guard.CheckCopyReplay())
				want := []w.PrepareAction{w.BeginCopy, action}
				if action == w.FinishCopy && when == "after" {
					want = []w.PrepareAction{w.BeginCopy}
				}
				if action == w.FinishCopy && when == "before" {
					want = append(want, w.BeginCopy)
				}
				if !reflect.DeepEqual(h.calls, want) {
					t.Fatal("wrong private replay sequence", h.calls, want)
				}
				if action == w.FinishCopy && i.Phase != a.CopyBegun {
					t.Fatal("completion stranded fresh Begin", i.Phase)
				}
			})
		}
	}
}
func TestManagedPendingRejectsUncorrelatedReplay(t *testing.T) {
	for _, fault := range []string{"intent", "owner", "root", "epoch", "phase", "pending"} {
		t.Run(fault, func(t *testing.T) {
			h := crashedReplayHost(t, "seal-before")
			calls := 0
			call := func(request w.PrepareRequest) (w.PrepareReply, error) {
				calls++
				r, err := h.call(request)
				if err == nil && request.Action == w.SealManifest {
					switch fault {
					case "intent":
						r.Intent.ID = replayID(t)
					case "owner":
						r.Intent.Owner.Attachment = replayID(t)
					case "root":
						r.Intent.Root.BackingUUID[0]++
						r.Root = r.Intent.Root
					case "epoch":
						r.Intent.Epoch = replayID(t)
					case "phase":
						r.Intent.Phase = a.CopyBound
						r.Intent.ManifestDigest = [32]byte{}
						r.Intent.ManifestSize = 0
					case "pending":
						r.Pending = w.SealManifest
					}
					// The response remains structurally valid through the actual
					// codec; the client must reject its request/scope correlation.
					var raw []byte
					raw, err = w.EncodePrepareIoctlReply(r)
					if err == nil {
						r, err = w.DecodePrepareIoctlReply(raw)
					}
				}
				return r, err
			}
			if _, err := beginManagedCopy(call, h.accept); err == nil {
				t.Fatal("accepted", fault)
			}
			if calls != 2 {
				t.Fatal("continued after uncorrelated reply", calls)
			}
		})
	}
}

func TestManagedPendingRejectedExactReplayRetainsFence(t *testing.T) {
	for _, action := range []w.PrepareAction{w.BindCopyTransaction, w.SealManifest, w.StartCleanup, w.FinishCopy} {
		t.Run(replayAction(action), func(t *testing.T) {
			h := crashedReplayHost(t, replayAction(action)+"-before")
			h.deny = action
			if _, err := beginManagedCopy(h.call, h.accept); !errors.Is(err, a.ErrUnauthorized) {
				t.Fatal("replay denial lost", err)
			}
			if !errors.Is(h.guard.CheckCopyReplay(), a.ErrBlocked) {
				t.Fatal("rejected replay erased fence")
			}
			if !reflect.DeepEqual(h.calls, []w.PrepareAction{w.BeginCopy, action}) {
				t.Fatal("continued after failed replay", h.calls)
			}
			h.deny = 0
			_, err := beginManagedCopy(h.call, h.accept)
			replayMust(t, err)
			replayMust(t, h.guard.CheckCopyReplay())
		})
	}
}

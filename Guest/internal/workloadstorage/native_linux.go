//go:build linux

package workloadstorage

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"dev.cengine/guest/internal/diskbootstrap"
	"dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storageclient"
	"dev.cengine/guest/internal/storagefuse"
	p "dev.cengine/guest/internal/storagepki"
	w "dev.cengine/guest/internal/storagewire"
	"dev.cengine/guest/internal/supervisor"
	"dev.cengine/guest/internal/vsock"
	"golang.org/x/sys/unix"
)

// Server is constructed only from committed container evidence and trusted boot
// mode. It owns one listener, one private connection and one terminal session.
type Server struct {
	listener net.Listener
	session  *Session
	once     sync.Once
}

// NewManagedServer never listens in legacy mode. Neither a WorkloadSpec nor a
// self-reported hello can activate managed storage or mint boot evidence.
func NewManagedServer(proof diskbootstrap.VerifiedBootResult, process *supervisor.Supervisor, cancelRootFS func()) (*Server, error) {
	commandLine, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return nil, ErrInvalidFrame
	}
	managed, err := bootMode(string(commandLine))
	if err != nil || !managed {
		return nil, err
	}
	binding, err := proof.ContainerBinding()
	if err != nil || process == nil || cancelRootFS == nil {
		return nil, ErrInvalidFrame
	}
	var management string
	for _, field := range strings.Fields(string(commandLine)) {
		if strings.HasPrefix(field, "cengine.management_address=") {
			if management != "" {
				return nil, ErrInvalidFrame
			}
			management = strings.TrimPrefix(field, "cengine.management_address=")
		}
	}
	prefix, err := netip.ParsePrefix(management)
	if err != nil {
		return nil, ErrInvalidFrame
	}
	factory := &nativeFactory{management: prefix}
	if originalConsumerEnabled() {
		factory.original = &originalConsumer{}
	}
	session, err := newSession(BootBinding{binding.ShimLaunchUUID, binding.GuestBootNonce}, &supervisorWorkload{process: process, cancelRootFS: cancelRootFS}, factory)
	if err != nil {
		return nil, err
	}
	session.prepareFailureSink = emitMountFailure
	if err := process.RequireManagedBoot(); err != nil {
		return nil, ErrInvalidFrame
	}
	listener, err := vsock.Listen(Port)
	if err != nil {
		return nil, ErrInvalidFrame
	}
	return &Server{listener: listener, session: session}, nil
}

func (s *Server) Close() error {
	if f, ok := s.session.factory.(*nativeFactory); ok && f.original != nil {
		return errors.Join(f.original.stop(), s.listener.Close())
	}
	return s.listener.Close()
}

// OriginalConsumerControl is reachable only on the existing host-owned control channel.
func (s *Server) OriginalConsumerControl(operation string, payload []byte) ([]byte, error) {
	if s == nil || s.session == nil {
		return nil, ErrInvalidFrame
	}
	return s.session.originalConsumerControl(operation, payload)
}

// Serve is single-use. Reject non-host peers without consuming the sole host
// connection; close the listener before sending any public hello.
func (s *Server) Serve(ctx context.Context) error {
	used := false
	s.once.Do(func() { used = true })
	if !used {
		return ErrInvalidFrame
	}
	defer s.listener.Close()
	joined := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-ctx.Done():
			_ = s.listener.Close()
		case <-stop:
		}
	}()
	defer func() { close(stop); <-joined }()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return ErrInvalidFrame
		}
		peer, ok := conn.RemoteAddr().(vsock.Addr)
		if !ok || peer.CID != 2 {
			_ = conn.Close()
			continue
		}
		if err := s.listener.Close(); err != nil {
			_ = conn.Close()
			return ErrInvalidFrame
		}
		return s.session.Serve(ctx, conn)
	}
}

type nativeFactory struct {
	original      *originalConsumer
	management    netip.Prefix
	compatibility *preparecompat.Witness
}

func (f *nativeFactory) installPrepareCompatibility(witness *preparecompat.Witness) error {
	if f.compatibility != nil || witness == nil || !preparecompat.SupportsArm(witness.Arm()) {
		return ErrInvalidFrame
	}
	f.compatibility = witness
	return nil
}

func (f *nativeFactory) Mount(ctx context.Context, scope Scope, peer Peer, slot Slot, identity p.Identity, retire func(error)) (Attachment, error) {
	address, err := netip.ParseAddr(peer.DataAddress)
	if err != nil || address.Zone() != "" || !f.management.Contains(address) || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() {
		return nil, ErrInvalidFrame
	}
	root, err := p.ParseRootDER(peer.TLSRootDER)
	if err != nil {
		return nil, ErrInvalidFrame
	}
	server, err := p.NewServerBinding(p.StoreID(scope.Store), p.ServiceEpoch(scope.ServiceEpoch))
	if err != nil {
		return nil, ErrInvalidFrame
	}
	rawPin, err := hex.DecodeString(peer.ServerKey)
	if err != nil || len(rawPin) != 32 {
		return nil, ErrInvalidFrame
	}
	var pin p.Fingerprint
	copy(pin[:], rawPin)
	cfg, err := p.ClientTLSConfig(identity, root, server, pin)
	if err != nil {
		return nil, ErrInvalidFrame
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(address.String(), strconv.Itoa(DataPort)))
	if err != nil {
		return nil, errors.New("mount")
	}
	owned := false
	defer func() {
		if !owned {
			_ = raw.Close()
		}
	}()
	conn := tls.Client(raw, cfg)
	if err = conn.HandshakeContext(ctx); err != nil {
		return nil, errors.New("certificate")
	}
	if err = p.VerifyServer(conn.ConnectionState(), root, server, pin); err != nil {
		return nil, errors.New("certificate")
	}
	// Require the exact configured certificate as well as CA/SAN/SPKI; never fall
	// back to NFS, an alternate TLS profile, a new address or a reconnect.
	if len(conn.ConnectionState().PeerCertificates) != 1 || string(conn.ConnectionState().PeerCertificates[0].Raw) != string(peer.ServerDER) {
		return nil, errors.New("certificate")
	}
	leaf, err := x509.ParseCertificate(identity.Certificate().DER())
	if err != nil {
		return nil, errors.New("certificate")
	}
	key, err := a.PublicKeyFingerprint(leaf.PublicKey)
	if err != nil {
		return nil, errors.New("certificate")
	}
	binding := a.Binding{Store: a.ID(scope.Store), Volume: a.ID(slot.Volume), Attachment: a.ID(slot.Attachment), Container: a.ContainerID(scope.Container), Launch: a.ID(scope.Launch), Key: key, Role: a.Role(slot.Role), Mode: a.Mode(slot.Mode)}
	if slot.Role == "prepare" {
		binding.Prepare = a.ID(scope.Prepare)
	}
	var witness *preparecompat.Witness
	if f.compatibility.Selected(slot.Attachment) {
		witness = f.compatibility
		if witness.ValidateDataAuthority(a.DataHello{Epoch: a.ID(scope.ServiceEpoch), Binding: binding}, identity.Certificate().DER()) != nil {
			return nil, errors.New("certificate")
		}
	}
	diagnostic := &mountFailureReporter{emit: emitMountFailure}
	mountpoint, err := makeAttachmentDirectory(slot.Attachment)
	if err != nil {
		diagnostic.report(err, true)
		return nil, errors.New("mount")
	}
	// Mount seals this trusted PID1 process as the prepare initializer. The
	// paired supervisorWorkload.Prepare calls PrepareManagedContext in-process;
	// workload execution happens only later in StartManagedContext. No caller
	// PID or workload field supplies the expected initializer identity.
	mounted, err := storagefuse.Mount(storagefuse.Config{Client: c.Config{PrepareCompatibility: witness, Conn: conn, TLSConfig: cfg, ServerPin: a.Fingerprint(peer.ServerKey), Authority: a.DataHello{Epoch: a.ID(scope.ServiceEpoch), Binding: binding}, Version: w.Version, Profile: w.RequiredProfile(), SupportedCaps: (uint64(1) << (unix.CAP_LAST_CAP + 1)) - 1, Limits: c.DefaultLimits(), Timeout: 30 * time.Second}, Mountpoint: mountpoint, ReadOnly: slot.Mode == "read-only", Retire: diagnostic.retirement(retire)})
	if err != nil {
		diagnostic.report(err, false)
		return nil, errors.New("mount")
	}
	owned = true
	return mounted, nil
}

func makeAttachmentDirectory(attachment string) (string, error) {
	return makeAttachmentDirectoryIn("/run/cengine", attachment)
}

func makeAttachmentDirectoryIn(base, attachment string) (string, error) {
	if !id(attachment) {
		return "", ErrInvalidFrame
	}
	root, err := unix.Open(base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(root)
	if err = unix.Mkdirat(root, "managed", 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return "", err
	}
	parent, err := unix.Openat(root, "managed", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(parent)
	var stat unix.Stat_t
	if err = unix.Fstat(parent, &stat); err != nil || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0777 != 0700 {
		return "", ErrInvalidFrame
	}
	if err = unix.Mkdirat(parent, attachment, 0700); err != nil {
		return "", err
	}
	child, err := unix.Openat(parent, attachment, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(child)
	// storagefuse pins this parent, requires the final component to be absent,
	// and exclusively creates/owns that leaf for identity-checked cleanup.
	return base + "/managed/" + attachment + "/root", nil
}

type supervisorWorkload struct {
	process      *supervisor.Supervisor
	cancelRootFS func()
}

func (s *supervisorWorkload) Configure() error { return s.process.ConfigureManaged() }
func managedMounts(mounts []MountBinding, slots []Slot, role string) ([]supervisor.ManagedMount, error) {
	result := make([]supervisor.ManagedMount, 0, len(mounts))
	for _, mount := range mounts {
		attachment := ""
		for _, slot := range slots {
			if slot.Volume == mount.Volume && slot.Role == role && (role == "prepare" || slot.Mode == mount.Mode) {
				if attachment != "" {
					return nil, ErrInvalidFrame
				}
				attachment = slot.Attachment
			}
		}
		if attachment == "" {
			return nil, ErrInvalidFrame
		}
		result = append(result, supervisor.ManagedMount{Index: mount.Index, Volume: mount.Volume, Attachment: attachment, Destination: mount.Destination, Subpath: mount.Subpath, Mode: mount.Mode, NoCopy: mount.NoCopy})
	}
	return result, nil
}
func (s *supervisorWorkload) Prepare(ctx context.Context, raw []byte, claim string, scope Scope, mounts []MountBinding, slots []Slot) (result error) {
	defer func() { result = supervisor.WithPrepareFailureStage(supervisor.PrepareValidation, result) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	spec, err := decodeManagedWorkload(raw)
	if err != nil || spec.ID != scope.Container || SpecificationDigest(raw) != scope.SpecificationDigest {
		return ErrInvalidFrame
	}
	plan, err := managedMounts(mounts, slots, "prepare")
	if err != nil {
		return err
	}
	spec.IOClaim = claim
	return s.process.PrepareManagedContext(ctx, spec, supervisor.ManagedPlan{Store: scope.Store, Container: scope.Container, Prepare: scope.Prepare, SpecificationDigest: scope.SpecificationDigest, Mounts: plan})
}
func (s *supervisorWorkload) Start(ctx context.Context, scope Scope, mounts []MountBinding, slots []Slot) (uint32, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	plan, err := managedMounts(mounts, slots, "runtime")
	if err != nil {
		return 0, err
	}
	status, err := s.process.StartManagedContext(ctx, plan)
	if err != nil || status.PID <= 0 {
		return 0, errors.New("start")
	}
	return uint32(status.PID), nil
}
func (s *supervisorWorkload) Stop(ctx context.Context) error {
	s.cancelRootFS()
	// StopManaged seals trusted boot even when private configure never arrived.
	return s.process.StopManaged(ctx)
}
func (s *supervisorWorkload) Wait() { s.process.Wait() }

// Compile-time seams keep real production integration paired with the testable
// state machine; no test authority/mount constructors are exported.
var _ Workload = (*supervisorWorkload)(nil)
var _ MountFactory = (*nativeFactory)(nil)
var _ Attachment = (*storagefuse.Mounted)(nil)

func (s *supervisorWorkload) installPrepareCompatibility(w *preparecompat.Witness) error {
	return s.process.InstallPrepareCompatibility(w)
}

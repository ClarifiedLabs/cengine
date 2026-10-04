package workloadstorage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dev.cengine/guest/internal/preparecompat"
	"dev.cengine/guest/internal/storagepki"
)

// Workload is owned by one Session. Stop must unblock Prepare, Start and Wait;
// operations must honor cancellation. Implementations validate the closed workload
// schema and its mount/noCopy plan before injecting the separate IO claim.
type Workload interface {
	Configure() error
	Prepare(context.Context, []byte, string, Scope, []MountBinding, []Slot) error
	Start(context.Context, Scope, []MountBinding, []Slot) (uint32, error)
	Stop(context.Context) error
	Wait()
}

type Attachment interface {
	CloseGracefully(context.Context) error
	Close() error
	Done() <-chan struct{}
	Err() error
	Mountpoint() string
}

// Mount must honor cancellation. The callback can be called synchronously or
// concurrently; it must report retirement, not successful graceful closure.
type MountFactory interface {
	Mount(context.Context, Scope, Peer, Slot, storagepki.Identity, func(error)) (Attachment, error)
}

const sessionIOTimeout = 120 * time.Second

type sessionAttachment struct {
	slot       Slot
	binding    storagepki.Binding
	key        storagepki.Key
	identity   storagepki.Identity
	installed  bool
	attachment Attachment // guarded by Session.mu
	mounted    bool       // guarded by Session.mu
	closing    atomic.Bool
}

// Session is a single-use launch owner. Its zero value is unusable. All private
// keys remain here or in the PID1-owned MountFactory, never in protocol replies.
type Session struct {
	originalMu         sync.Mutex // serializes original-owner arm with installed-session mutation
	compatibility      *preparecompat.Witness
	prepareFailureSink func(string) // installed before Serve; fixed nonblocking console sink
	conn               net.Conn
	binding            BootBinding
	workload           Workload
	factory            MountFactory
	used               atomic.Bool
	scope              Scope
	peer               Peer
	root               storagepki.Root
	mounts             []MountBinding
	slots              []Slot
	entries            map[string]*sessionAttachment
	phase              string
	activeRole         string
	last               uint64
	mu                 sync.Mutex
	stopped            bool
	events             chan []string
	writeMu            sync.Mutex
	deadlineMu         sync.Mutex // serializes deadline setup with terminal admission
	closing            atomic.Bool
	shutdownOnce       sync.Once
	shutdownErr        error
	cancel             context.CancelFunc
	workers            sync.WaitGroup
}

// newSession is deliberately private. The production Linux constructor must
// first authenticate the sealed disk-bootstrap result and container proof.
func newSession(binding BootBinding, workload Workload, factory MountFactory) (*Session, error) {
	if !id(binding.ShimLaunchUUID) || !id(binding.GuestBootNonce) || workload == nil || factory == nil {
		return nil, errors.New("configuration")
	}
	return &Session{binding: binding, workload: workload, factory: factory, entries: make(map[string]*sessionAttachment), events: make(chan []string, 32)}, nil
}

// retire is safe from native callbacks, including callbacks made inside Mount.
// Neither logging, blocking sends, attachment methods nor locks are used here.
func (s *Session) retire(ids ...string) {
	if len(ids) > 32 {
		ids = ids[:32]
	}
	if len(ids) != 0 {
		select {
		case s.events <- append([]string(nil), ids...):
		default:
		}
	}
	s.cancel() // also fail closed on queue overflow
}

// Serve sends hello, accepts exactly one configuration, then serial commands.
// A lost connection or failed command permanently consumes this Session.
func (s *Session) Serve(parent context.Context, conn net.Conn) (result error) {
	if conn == nil || s.workload == nil || s.factory == nil || !s.used.CompareAndSwap(false, true) {
		return errors.New("terminal")
	}
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	s.conn = conn
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		// Interrupt an already blocked writer before waiting for its frame lock.
		// No subsequent writer may extend this absolute terminal deadline.
		s.deadlineMu.Lock()
		s.closing.Store(true)
		deadlineErr := conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		s.deadlineMu.Unlock()
		if deadlineErr != nil {
			_ = conn.Close()
		}
		s.writeMu.Lock()
		select {
		case ids := <-s.events:
			code := "terminal"
			event := NewFrame("terminal", s.binding, s.scope, Payload{AttachmentIDs: &ids, Code: &code})
			if deadlineErr == nil {
				_ = WriteFrame(conn, event) // preserve the terminal deadline
			}
		default: // EOF/cancellation alone has no IDs; later retirements are best-effort only.
		}
		s.writeMu.Unlock()
		_ = conn.Close()
		_ = s.shutdown()
	}()
	defer func() {
		wasCanceled := ctx.Err() != nil
		cancel()
		<-shutdownDone
		s.workers.Wait()
		if wasCanceled || s.shutdownErr != nil {
			result = errors.New("terminal")
		}
		s.originalMu.Lock()
		defer s.originalMu.Unlock()
		s.phase = "terminal"
		for _, e := range s.entries {
			e.key = storagepki.Key{}
			e.identity = storagepki.Identity{}
		}
	}()
	hello := &Frame{Version: Version, Type: Type, Operation: "hello", Binding: s.binding}
	if profile := preparecompat.CurrentProfile(); profile != "" {
		hello.Data.CompatibilityProfile = &profile
	}
	if err := s.write(conn, hello); err != nil {
		return errors.New("invalid-frame")
	}
	incoming := make(chan *Frame, 1)
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		for {
			f, err := sessionRead(conn)
			if err != nil {
				cancel()
				return
			}
			select {
			case incoming <- f:
			case <-ctx.Done():
				return
			default:
				cancel()
				return
			}
		}
	}()
	var configuration *Frame
	select {
	case configuration = <-incoming:
	case <-ctx.Done():
		return errors.New("terminal")
	}
	if configuration.Operation != "configure" || configuration.Binding != s.binding || configuration.Scope == nil {
		return errors.New("configuration")
	}
	if err := s.configure(configuration); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return errors.New("terminal")
	}
	if err := s.write(conn, NewFrame("configured", s.binding, s.scope, Payload{})); err != nil {
		return errors.New("invalid-frame")
	}
	for {
		var f *Frame
		select {
		case f = <-incoming:
		case <-ctx.Done():
			return errors.New("terminal")
		}
		code := ""
		switch {
		case f.Operation != "command":
			return errors.New("phase")
		case f.Binding != s.binding:
			code = "binding-mismatch"
		case f.Scope == nil || *f.Scope != s.scope:
			code = "scope-mismatch"
		case f.Sequence == nil || *f.Sequence <= s.last:
			code = "sequence"
		}
		var data Payload
		if code == "" {
			s.last = *f.Sequence
			data, code = s.command(ctx, f.Kind, f.Data)
		}
		if ctx.Err() != nil {
			return errors.New("terminal")
		}
		reply := NewFrame("reply", s.binding, s.scope, data)
		reply.Kind, reply.Sequence = f.Kind, f.Sequence
		if code != "" {
			reply.Data = Payload{Code: &code}
		}
		if err := s.write(conn, reply); err != nil {
			return errors.New("invalid-frame")
		}
		if code != "" {
			return errors.New(code)
		}
		if f.Kind == "abort" {
			return nil
		}
	}
}

func sessionRead(conn net.Conn) (*Frame, error) {
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, ErrInvalidFrame
	}
	var first [1]byte
	if _, err := io.ReadFull(conn, first[:]); err != nil {
		return nil, ErrInvalidFrame
	}
	if err := conn.SetReadDeadline(time.Now().Add(sessionIOTimeout)); err != nil {
		return nil, ErrInvalidFrame
	}
	return ReadFrame(io.MultiReader(bytes.NewReader(first[:]), conn))
}

func (s *Session) write(conn net.Conn, f *Frame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.deadlineMu.Lock()
	if s.closing.Load() {
		s.deadlineMu.Unlock()
		return ErrInvalidFrame
	}
	err := conn.SetWriteDeadline(time.Now().Add(sessionIOTimeout))
	s.deadlineMu.Unlock()
	if err != nil {
		return ErrInvalidFrame
	}
	if err := WriteFrame(conn, f); err != nil {
		return ErrInvalidFrame
	}
	return nil
}

func (s *Session) configure(f *Frame) error {
	s.originalMu.Lock()
	defer s.originalMu.Unlock()
	if !validScope(*f.Scope) || f.Scope.Launch != s.binding.ShimLaunchUUID || ValidateConfiguration(*f.Data.Mounts, *f.Data.Slots) != nil {
		return errors.New("configuration")
	}
	s.scope = *f.Scope
	s.peer = *f.Data.Peer
	s.peer.TLSRootDER = bytes.Clone(s.peer.TLSRootDER)
	s.peer.ServerDER = bytes.Clone(s.peer.ServerDER)
	s.mounts = append([]MountBinding{}, (*f.Data.Mounts)...)
	s.slots = append([]Slot{}, (*f.Data.Slots)...)
	root, err := storagepki.ParseRootDER(s.peer.TLSRootDER)
	if err != nil {
		return errors.New("certificate")
	}
	b, err := storagepki.NewServerBinding(storagepki.StoreID(s.scope.Store), storagepki.ServiceEpoch(s.scope.ServiceEpoch))
	if err != nil {
		return errors.New("certificate")
	}
	if _, err = storagepki.ParseCertificateDER(s.peer.ServerDER, b); err != nil {
		return errors.New("certificate")
	}
	leaf, err := verifySessionChain(s.peer.ServerDER, root, true)
	if err != nil {
		return errors.New("certificate")
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if hex.EncodeToString(sum[:]) != s.peer.ServerKey {
		return errors.New("certificate")
	}
	s.root = root
	if s.workload.Configure() != nil {
		return errors.New("configuration")
	}
	s.phase = "configured"
	return nil
}

func verifySessionChain(der []byte, root storagepki.Root, server bool) (*x509.Certificate, error) {
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.New("certificate")
	}
	ca, err := x509.ParseCertificate(root.DER())
	if err != nil {
		return nil, errors.New("certificate")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	options := x509.VerifyOptions{Roots: pool, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if server {
		options.DNSName = storagepki.ServerName
		options.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if _, err := leaf.Verify(options); err != nil {
		return nil, errors.New("certificate")
	}
	return leaf, nil
}

func sessionBinding(scope Scope, slot Slot) (storagepki.Binding, error) {
	tuple := storagepki.AttachmentTuple{Attachment: storagepki.AttachmentID(slot.Attachment), Volume: storagepki.VolumeID(slot.Volume), Role: storagepki.Role(slot.Role), Mode: storagepki.Mode(slot.Mode), Container: storagepki.ContainerID(scope.Container), Launch: storagepki.LaunchID(scope.Launch)}
	if slot.Role == "prepare" {
		tuple.Prepare = storagepki.PrepareID(scope.Prepare)
	}
	return storagepki.NewAttachmentBinding(storagepki.StoreID(scope.Store), storagepki.ServiceEpoch(scope.ServiceEpoch), tuple)
}

func (s *Session) command(ctx context.Context, kind string, p Payload) (Payload, string) {
	s.originalMu.Lock()
	defer s.originalMu.Unlock()
	if ctx.Err() != nil {
		return Payload{}, "terminal"
	}
	switch kind {
	case "prepare-compatibility-arm":
		return s.armPrepareCompatibility(ctx, p.CompatibilityArm)
	case "offer-keys":
		role := *p.Role
		if role == "prepare" && s.phase != "configured" || role == "runtime" && s.phase != "prepare-closed" {
			return Payload{}, "phase"
		}
		offers := []Offer{}
		for _, slot := range s.slots {
			if slot.Role != role {
				continue
			}
			b, err := sessionBinding(s.scope, slot)
			if err != nil {
				return Payload{}, "certificate"
			}
			key, err := storagepki.NewAttachmentKey(storagepki.Role(role))
			if err != nil {
				return Payload{}, "internal"
			}
			csr, err := key.CSR(b)
			if err != nil {
				return Payload{}, "certificate"
			}
			pin, err := key.Fingerprint()
			if err != nil {
				return Payload{}, "certificate"
			}
			e := &sessionAttachment{slot: slot, key: key, binding: b}
			s.mu.Lock()
			s.entries[slot.Attachment] = e
			s.mu.Unlock()
			offers = append(offers, Offer{Attachment: slot.Attachment, Key: pin.String(), CSRDER: csr})
		}
		s.activeRole, s.phase = role, "keys-offered"
		if len(offers) == 0 {
			s.phase = "certificates-installed"
		}
		return Payload{Offers: &offers}, ""
	case "install-certificate":
		if s.phase != "keys-offered" {
			return Payload{}, "phase"
		}
		e := s.entries[*p.Attachment]
		if e == nil || e.slot.Role != s.activeRole || e.installed {
			return Payload{}, "certificate"
		}
		cert, err := storagepki.ParseCertificateDER(*p.CertificateDER, e.binding)
		if err != nil {
			return Payload{}, "certificate"
		}
		identity, err := cert.WithKey(e.key)
		if err != nil {
			return Payload{}, "certificate"
		}
		if _, err = verifySessionChain(cert.DER(), s.root, false); err != nil {
			return Payload{}, "certificate"
		}
		e.identity, e.installed = identity, true
		complete := true
		for _, slot := range s.slots {
			if slot.Role == s.activeRole && !s.entries[slot.Attachment].installed {
				complete = false
			}
		}
		if complete {
			s.phase = "certificates-installed"
		}
		return Payload{Attachment: p.Attachment}, ""
	case "mount-phase":
		if s.phase != "certificates-installed" || *p.Role != s.activeRole {
			return Payload{}, "phase"
		}
		ids := []string{}
		for _, slot := range s.slots {
			if slot.Role != s.activeRole {
				continue
			}
			e := s.entries[slot.Attachment]
			a, err := s.factory.Mount(ctx, s.scope, s.peer, slot, e.identity, func(error) {
				if !e.closing.Load() {
					s.retire(slot.Attachment)
				}
			})
			if a != nil {
				s.mu.Lock()
				stopped := s.stopped
				e.attachment, e.mounted = a, true
				s.mu.Unlock()
				if stopped {
					_ = a.Close()
				}
			}
			if err != nil || a == nil {
				return Payload{}, "mount"
			}
			if ctx.Err() != nil || a.Err() != nil || a.Mountpoint() != "/run/cengine/managed/"+slot.Attachment+"/root" {
				return Payload{}, "mount"
			}
			s.workers.Add(1)
			go func() {
				defer s.workers.Done()
				select {
				case <-a.Done():
					if !e.closing.Load() {
						s.retire(slot.Attachment)
					}
				case <-ctx.Done():
				}
			}()
			ids = append(ids, slot.Attachment)
		}
		sort.Strings(ids)
		s.phase = s.activeRole + "-mounted"
		return Payload{AttachmentIDs: &ids}, ""
	case "prepare":
		if s.phase != "prepare-mounted" {
			return Payload{}, "phase"
		}
		raw := *p.WorkloadJSON
		if SpecificationDigest(raw) != s.scope.SpecificationDigest || !emptyEmbeddedClaim(raw) {
			s.reportPrepareFailure(prepareSpecification, ErrInvalidFrame)
			return Payload{}, "prepare"
		}
		if s.compatibility != nil {
			if err := s.compatibility.AcceptPrepare(s.last); err != nil {
				s.reportPrepareFailure(prepareCompatibility, err)
				return Payload{}, "prepare"
			}
		}
		if err := s.workload.Prepare(ctx, bytes.Clone(raw), *p.IOClaim, s.scope, append([]MountBinding{}, s.mounts...), append([]Slot{}, s.slots...)); err != nil {
			s.reportPrepareFailure(prepareWorkload, err)
			return Payload{}, "prepare"
		}
		// No armed PREPARE success without the normal observation's completed
		// write. A7 never returns from its real initializer and cannot pass here.
		if s.compatibility != nil && !s.compatibility.NormalObservationWritten() && !s.compatibility.AllowsIORetirePrepare() {
			s.reportPrepareFailure(prepareNormalObservation, ErrInvalidFrame)
			return Payload{}, "prepare"
		}
		s.phase = "prepared"
		// Only deterministic public material; neither workload bytes nor claim
		// are serialized into this evidence record.
		evidence, _ := json.Marshal(struct {
			Scope     Scope
			Mounts    []MountBinding
			Slots     []Slot
			Succeeded bool
		}{s.scope, s.mounts, s.slots, true})
		digest, yes := SpecificationDigest(evidence), true
		return Payload{Prepare: &s.scope.Prepare, ContainerInstance: &s.scope.ContainerInstance, Launch: &s.scope.Launch, Succeeded: &yes, CleanCopyUp: &yes, EvidenceDigest: &digest}, ""
	case "close-phase":
		if s.phase != "prepared" || *p.Role != "prepare" {
			return Payload{}, "phase"
		}
		ids, clean := s.closePrepare(ctx)
		if !clean {
			return Payload{}, "mount"
		}
		s.phase = "prepare-closed"
		return Payload{Role: p.Role, AttachmentIDs: &ids, Clean: &clean}, ""
	case "start":
		if s.phase != "runtime-mounted" {
			return Payload{}, "phase"
		}
		pid, err := s.workload.Start(ctx, s.scope, append([]MountBinding{}, s.mounts...), append([]Slot{}, s.slots...))
		if err != nil || pid == 0 || pid > 2147483647 {
			return Payload{}, "start"
		}
		s.workers.Add(1)
		go func() {
			defer s.workers.Done()
			// Process completion, including nonzero or signal exits, is not a
			// private-channel failure. Retain this session until the host reads
			// the real supervisor wait result and retires its attachments, or
			// genuine failure triggers containment. Keep this worker: Serve must
			// still join the owned workload even when Stop fails.
			s.workload.Wait()
		}()
		s.phase = "running"
		status := "running"
		return Payload{Status: &status, PID: &pid}, ""
	case "status":
		mounted, terminal := s.statusIDs()
		return Payload{Phase: &s.phase, MountedIDs: &mounted, TerminalIDs: &terminal}, ""
	case "abort":
		if s.shutdown() != nil {
			return Payload{}, "terminal"
		}
		s.phase = "aborted"
		_, ids := s.statusIDs()
		return Payload{TerminalIDs: &ids}, ""
	}
	return Payload{}, "phase"
}

// The adapter owns full schema validation. Here the secret boundary is checked
// before passing exact, unrewritten bytes onward, including case aliases and
// duplicate top-level fields that encoding/json would otherwise overwrite.
func emptyEmbeddedClaim(raw []byte) bool {
	if !validUnicode(raw) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	found := false
	for d.More() {
		token, err = d.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return false
		}
		seen[name] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return false
		}
		if strings.EqualFold(name, "ioClaim") {
			if name != "ioClaim" || !bytes.Equal(bytes.TrimSpace(value), []byte(`""`)) {
				return false
			}
			found = true
		}
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') {
		return false
	}
	_, err = d.Token()
	return found && err == io.EOF
}

func (s *Session) closePrepare(ctx context.Context) ([]string, bool) {
	entries := []*sessionAttachment{}
	ids := []string{}
	for _, slot := range s.slots {
		if slot.Role == "prepare" {
			e := s.entries[slot.Attachment]
			e.closing.Store(true)
			entries = append(entries, e)
			ids = append(ids, slot.Attachment)
		}
	}
	closeCtx, cancel := context.WithTimeout(ctx, sessionIOTimeout)
	defer cancel()
	results := make(chan error, len(entries))
	var graceful sync.WaitGroup
	for _, e := range entries {
		graceful.Add(1)
		go func() { defer graceful.Done(); results <- e.attachment.CloseGracefully(closeCtx) }()
	}
	clean := true
	for range entries {
		if <-results != nil {
			if clean {
				cancel()
				// Abort every peer concurrently: one failed close must not leave
				// other graceful closes waiting for work that cannot complete.
				var aborts sync.WaitGroup
				for _, e := range entries {
					aborts.Add(1)
					go func() { defer aborts.Done(); _ = e.attachment.Close() }()
				}
				aborts.Wait()
			}
			clean = false
		}
	}
	graceful.Wait()
	s.mu.Lock()
	for _, e := range entries {
		e.mounted = false
	}
	s.mu.Unlock()
	sort.Strings(ids)
	return ids, clean && closeCtx.Err() == nil
}

func (s *Session) statusIDs() ([]string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	mounted, terminal := []string{}, []string{}
	for _, slot := range s.slots {
		e := s.entries[slot.Attachment]
		if s.stopped {
			terminal = append(terminal, slot.Attachment)
		} else if e != nil && e.mounted {
			mounted = append(mounted, slot.Attachment)
		}
	}
	sort.Strings(mounted)
	sort.Strings(terminal)
	if len(terminal) > 32 {
		terminal = terminal[:32]
	}
	return mounted, terminal
}

// shutdown joins every owned cleanup exactly once. Native Mounted.Close returns
// cleanup errors (its terminal abort reason is available separately through Err),
// so a non-nil Close result must prevent an abort acknowledgement.
func (s *Session) shutdown() error {
	s.shutdownOnce.Do(func() {
		s.mu.Lock()
		s.stopped = true
		attachments := []Attachment{}
		for _, e := range s.entries {
			e.closing.Store(true)
			if e.attachment != nil {
				attachments = append(attachments, e.attachment)
			}
			e.mounted = false
		}
		s.mu.Unlock()
		var workers sync.WaitGroup
		var failed atomic.Bool
		workers.Add(1)
		go func() {
			defer workers.Done()
			ctx, cancel := context.WithTimeout(context.Background(), sessionIOTimeout)
			defer cancel()
			if s.workload.Stop(ctx) != nil {
				failed.Store(true)
			}
		}()
		for _, a := range attachments {
			workers.Add(1)
			go func() {
				defer workers.Done()
				if a.Close() != nil {
					failed.Store(true)
				}
			}()
		}
		workers.Wait()
		if failed.Load() {
			s.shutdownErr = errors.New("terminal")
		}
	})
	return s.shutdownErr
}

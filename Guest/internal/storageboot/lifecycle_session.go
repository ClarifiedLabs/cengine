package storageboot

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"os"
	"time"

	"dev.cengine/guest/internal/diskbootstrap"
	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
	s "dev.cengine/guest/internal/storageservice"
	"golang.org/x/sys/unix"
)

func lifecyclePublicReady(service *s.LifecycleService, worker string) (*LifecycleReady, error) {
	r, err := service.Ready()
	if err != nil {
		return nil, err
	}
	meta, err := service.Scope()
	if err != nil {
		return nil, err
	}
	return &LifecycleReady{meta.Identity, string(r.ServiceEpoch), worker, r.Controller.Epoch, string(r.Controller.Key), r.Revision, meta.OpenRevision, string(r.Bootstrap), r.TLSRootDER, r.ServerDER, r.ServerKey.String()}, nil
}
func lifecycleConstruct(root *os.File, b diskbootstrap.StorageBinding, c LifecycleConfiguration, fresh func() error) (*s.LifecycleService, error) {
	if c.validate() != nil || !lifecycleColdBindingValid(c, b) {
		return nil, errFrame
	}
	// Explicit ROOT authorization of the service change before any mutation.
	if c.Action == "open" && (c.Reopen == nil || c.Reopen.Verify(ed25519.PublicKey(c.RootPublicKey)) != nil) {
		return nil, a.ErrUnauthorized
	}
	pub, err := p.NewBootstrapPublicKey(ed25519.PublicKey(c.RootPublicKey))
	if err != nil {
		return nil, err
	}
	// Verify before any filesystem mutation, even creating the volumes directory.
	msg, err := a.LifecycleGrantSigningBytes(c.Signed.Grant)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(c.RootPublicKey), msg, c.Signed.Signature) {
		return nil, a.ErrUnauthorized
	}
	cfg := s.Config{Root: root, DeviceUUID: b.Ext4UUID, Store: c.Signed.Grant.Identity.Store, Bootstrap: pub, Now: time.Unix(int64(c.NowUnixSeconds), 0), Lifetime: time.Duration(c.LifetimeSeconds) * time.Second}
	if c.Action == "initialize" {
		if fresh == nil {
			return nil, errors.New("configuration")
		}
		if err = fresh(); err != nil {
			return nil, err
		}
		if err = freshRoot(root); err != nil {
			return nil, err
		}
		if err = unix.Mkdirat(int(root.Fd()), "volumes", 0700); err != nil && !errors.Is(err, unix.EEXIST) {
			return nil, err
		}
		if err = root.Sync(); err != nil {
			return nil, err
		}
		return s.InitializeLifecycle(cfg, c.Signed)
	}
	if c.Action == "cold-open-takeover" {
		return s.ColdOpenAndTakeover(cfg, *c.Cold)
	}
	if c.Action == "resume-open-takeover" {
		// The worker's authenticated PID1 handoff requires VerifiedResume:
		// signed read-only admission/census and same-lease RW promotion have
		// completed before this root FD was passed to the worker.
		return s.ResumeOpenAndTakeover(cfg, *c.Resume)
	}
	prior := c.Reopen.Request.Predecessor
	return s.ReopenLifecycle(cfg, prior.Grant.Identity, c.Signed, a.ExpectedLifecycleStartup{
		ExpectedStartup: a.ExpectedStartup{
			Store: prior.Grant.Identity.Store, Epoch: a.ID(prior.Context.ServiceEpoch),
			Controller: a.Controller{Epoch: prior.Context.ControllerEpoch, Key: a.Fingerprint(prior.Context.ControllerKey)},
		},
		OpenRevision: prior.OpenRevision,
	})
}

// Only the launch/disk facts actually observed on 4105 are compared here.
// ROOT independently verifies the signed spec/initramfs digests host-side.
func lifecycleColdBindingValid(c LifecycleConfiguration, b diskbootstrap.StorageBinding) bool {
	launch := func() (a.LifecycleColdLaunch, bool) {
		switch c.Action {
		case "cold-open-takeover":
			if c.Cold != nil {
				return c.Cold.Request.Launch, true
			}
		case "resume-open-takeover":
			if c.Resume != nil {
				return c.Resume.Request.Launch, true
			}
		}
		return a.LifecycleColdLaunch{}, false
	}
	l, ok := launch()
	if !ok {
		return c.Action != "cold-open-takeover" && c.Action != "resume-open-takeover"
	}
	return string(l.ShimLaunchUUID) == b.ShimLaunchUUID && string(l.Ext4UUID) == b.Ext4UUID && l.Bytes == b.Bytes
}

// lifecycleSession is PID1's private 4106 session. It never constructs a
// LifecycleService: after configure it builds the supervisor, whose starter
// launches a separately owned worker; every command frame is dispatched through
// the supervisor. Supervisor codes are members of the closed v2 wire Code set.
// Worker loss is a reply code, not loss of this session. Return/cancellation
// closes the supervisor (kill + positive Wait + close) and is not a drain or
// retirement receipt. An uncertain Wait is terminal containment: keep PID1 and
// every retained root/lease alive for host hard fallback.
func lifecycleSession(ctx context.Context, conn net.Conn, binding diskbootstrap.StorageBinding, start lifecycleWorkerStarter, budget time.Duration) (err error) {
	if ctx == nil || conn == nil {
		return errFrame
	}
	defer conn.Close()
	stop, joined := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stop:
		}
	}()
	defer func() { close(stop); <-joined }()
	if start == nil || !validBinding(binding) || budget <= 0 {
		return errFrame
	}
	if err = conn.SetDeadline(time.Now().Add(budget)); err != nil {
		return err
	}
	hello := lifecycleFrame("hello", binding)
	if err = WriteLifecycleFrame(conn, &hello); err != nil {
		return err
	}
	config, err := ReadLifecycleFrame(conn)
	if err != nil {
		return err
	}
	if config.Operation != "configure" || config.Binding != binding || !lifecycleColdBindingValid(*config.Configuration, binding) {
		return errFrame
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	// The supervisor verifies the ROOT signature before calling start, so no
	// filesystem mutation or fresh consumption precedes verification.
	supervisor, err := newLifecycleSupervisor(*config.Configuration, start)
	if supervisor != nil {
		defer func() {
			if errors.Is(err, ErrShutdownUncertain) {
				err = retainLifecycleShutdown(err, supervisor)
				return
			}
			if closeErr := supervisor.close(); closeErr != nil {
				err = retainLifecycleShutdown(errors.Join(err, closeErr), supervisor)
			}
		}()
	}
	if err != nil {
		return err
	}
	ready := lifecycleFrame("ready", binding)
	ready.Ready = copyLifecycleReady(supervisor.ready) // first worker Ready
	write := func(f *LifecycleFrame) error {
		if e := conn.SetWriteDeadline(time.Now().Add(budget)); e != nil {
			return e
		}
		return WriteLifecycleFrame(conn, f)
	}
	if err = write(&ready); err != nil {
		return err
	}
	// Once Ready has been published, a local frame/write fault alone cannot
	// retire a working service. Keep its worker owned until the persistent
	// shim actually closes 4106. Daemon loss does not close this connection.
	terminal := func(cause error) error {
		// Explicit cancellation by our PID1 owner is terminal too; it is
		// not a transient command error or the daemon's connection lifetime.
		// Production passes Background; the shim's private EOF owns lifetime.
		if ctx.Err() != nil {
			return errors.Join(cause, ctx.Err())
		}
		if errors.Is(cause, io.EOF) || errors.Is(cause, io.ErrUnexpectedEOF) {
			return cause
		}
		ownerErr := awaitLifecycleOwnerEOF(conn)
		if ctx.Err() != nil {
			// Cancellation can close our local transport while the peer is
			// still alive. Never erase that uncertain owner-EOF observation.
			return errors.Join(cause, ctx.Err(), ownerErr)
		}
		return errors.Join(cause, ownerErr)
	}
	for sequence := uint64(1); sequence != 0; sequence++ {
		request, e := readLifecycleCommand(conn, budget)
		if e != nil {
			return terminal(e)
		}
		if request.Binding != binding || request.Operation != "command" || *request.Sequence != sequence {
			return terminal(errFrame)
		}
		// (service_epoch, worker_uuid) is checked against the CURRENT worker by
		// the supervisor (stale-worker), since replacement changes the pair.
		reply, code := supervisor.dispatch(request)
		if code != "" || reply == nil {
			if code == "" {
				code = "service"
			}
			f := lifecycleFrame("reply", binding)
			f.Sequence, f.ServiceEpoch, f.WorkerUUID, f.Code = request.Sequence, request.ServiceEpoch, request.WorkerUUID, code
			reply = &f
		}
		if err = write(reply); err != nil {
			return terminal(err)
		}
	}
	return terminal(errFrame)
}

// No drain deadline is interpreted as owner death. The host has the bounded
// graceful/hard VM-stop budget; PID1 retains the service if EOF cannot be proved.
func awaitLifecycleOwnerEOF(conn net.Conn) error {
	deadlineErr := conn.SetReadDeadline(time.Time{})
	// Some transports reject deadline changes after peer close while Read
	// still returns the actual EOF. Only that read observation proves loss;
	// neither a deadline error nor a timeout is treated as owner death.
	if _, err := io.Copy(io.Discard, conn); err != nil {
		return retainLifecycleShutdown(errors.Join(deadlineErr, err))
	}
	return io.EOF
}

// Idle commands wait for cancellation. Once even one byte arrives, the entire
// remaining header+body has a fixed deadline, never a per-byte sliding timeout.
func readLifecycleCommand(conn net.Conn, budget time.Duration) (*LifecycleFrame, error) {
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	var first [1]byte
	if _, err := io.ReadFull(conn, first[:]); err != nil {
		return nil, err
	}
	if err := conn.SetReadDeadline(time.Now().Add(budget)); err != nil {
		return nil, err
	}
	return ReadLifecycleFrame(io.MultiReader(&oneLifecycleByte{value: first[0]}, conn))
}

type oneLifecycleByte struct {
	value byte
	read  bool
}

func (b *oneLifecycleByte) Read(p []byte) (int, error) {
	if b.read {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = b.value
	b.read = true
	return 1, nil
}

package storagefuse

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storageclient"
	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
)

var ErrProfile = errors.New("storagefuse: required native managed profile unavailable")

// Config accepts only an exclusive, already-handshaken private TLS connection.
// It offers no caller credentials, reconnect, or profile fallback. Retire must
// return without blocking and requests authority retirement, not a drain receipt.
type Config struct {
	Client     c.Config // already connected/handshaken private TLS; never dial/reconnect
	Mountpoint string
	ReadOnly   bool        // must agree exactly with the authenticated attachment mode
	Retire     func(error) // nonblocking attachment-retirement request; never a drain receipt
}

// Mount leaves TLS ownership with the caller on validation/platform preflight
// failure. Native construction then owns TLS even on partial setup failure.
func Mount(cfg Config) (*Mounted, error) {
	if err := validateMountConfig(cfg); err != nil {
		return nil, &mountFailure{stage: stagePreflight, cause: err}
	}
	return nativeMount(cfg)
}
func validateMountConfig(cfg Config) error {
	mode := cfg.Client.Authority.Binding.Mode
	role := cfg.Client.Authority.Binding.Role
	if cfg.Client.Conn == nil || cfg.Client.Profile != w.RequiredProfile() || cfg.Client.Version != w.Version || cfg.Client.Timeout <= 0 || cfg.Retire == nil ||
		(mode != a.ReadOnly && mode != a.ReadWrite) || cfg.ReadOnly != (mode == a.ReadOnly) ||
		(role != a.RuntimeRole && role != a.PrepareRole) {
		return ErrProfile
	}
	return nil
}

// Private aliases retain the native prototype tests without a second API.
type mountConfig = Config
type mounted = Mounted

func newMount(cfg mountConfig) (*mounted, error) { return Mount(cfg) }

// Local terminal state is not an authority retirement/drain receipt.
type mountLifecycle struct {
	closing, destroyed, unmounted, clean atomic.Bool
	mu                                   sync.Mutex
	err                                  error
}

func (s *mountLifecycle) fail(err error) {
	if err != nil {
		s.mu.Lock()
		s.err = errors.Join(s.err, err)
		s.mu.Unlock()
	}
}
func (s *mountLifecycle) result() error { s.mu.Lock(); defer s.mu.Unlock(); return s.err }

func (s *mountLifecycle) waitTerminal(terminal, decision <-chan struct{}, reason func() error) error {
	select {
	case <-terminal:
	case <-decision:
	}
	if err := reason(); err != nil {
		return err
	}
	if s.clean.Load() {
		return nil
	}
	return ErrProfile
}

type lifecycleFS struct {
	*rawFS
	life        *mountLifecycle
	directories directoryReleases
}

// Ordinary fuse (unlike fuseblk) does not promise DESTROY or final FORGET.
// Intent suppresses premature abort only; native normal-unmount success plus
// the full Serve join, not this callback, supplies the positive local proof.
func (f *lifecycleFS) OnUnmount() {
	if !f.life.closing.Load() || f.stopped.Load() {
		f.rawFS.OnUnmount()
	}
}
func (f *lifecycleFS) observeReply(r fuse.ReplyDelivery) {
	if r.Opcode == 27 {
		if err := f.directories.deliveredOpen(r); err != nil {
			f.stopAt(directoryDeliverySite(r), r.Opcode, err)
		}
	}
	if r.Opcode == 29 { // RELEASEDIR: the callback's return is NOT delivery proof.
		if err := f.directories.delivered(r, f.stopped.Load()); err != nil {
			f.stopAt(directoryDeliverySite(r), r.Opcode, err)
		}
	}
	if r.Opcode == 38 && f.life.closing.Load() && r.Unique != 0 && r.Expected == 16 && r.Bytes == 16 && r.Err == nil && !r.Interrupted && !r.Suppressed && r.Status == fuse.OK {
		f.life.destroyed.Store(true)
		return
	}
	if r.Opcode == 38 {
		f.stopAt(siteDestroy, r.Opcode, errors.Join(errTranslation, r.Err))
		return
	}
	f.rawFS.observeReply(r)
}

// A canceled secondary waiter cannot revoke the owning close attempt. The first
// caller owns cancellation; explicit Close remains the separate abort operation.
func waitGraceful(ctx context.Context, done <-chan struct{}, result func() error, abort func(error), owner bool) error {
	select {
	case <-done:
		return errors.Join(ctx.Err(), result())
	case <-ctx.Done():
		if owner {
			select {
			case <-done:
				return errors.Join(ctx.Err(), result())
			default:
			}
			abort(ctx.Err()) // native owner synchronizes this with clean commitment
		}
		return errors.Join(ctx.Err(), result())
	}
}

// Native callers provide only owned operations. Keep ordering independently
// testable without exposing an injected production transport or credential seam.
func completeGraceful(ctx context.Context, unmount, served, proof, closeClient func(context.Context) error) error {
	for _, step := range []func(context.Context) error{unmount, served, proof, closeClient} {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := step(ctx); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func mountModeMatches(info, path string, id uint64, readOnly bool) bool {
	for _, line := range strings.Split(info, "\n") {
		p := strings.Fields(line)
		if len(p) < 6 || p[0] != strconv.FormatUint(id, 10) || p[4] != mountPath(path) {
			continue
		}
		ro, rw := false, false
		for _, flag := range strings.Split(p[5], ",") {
			ro = ro || flag == "ro"
			rw = rw || flag == "rw"
		}
		return ro != rw && ro == readOnly
	}
	return false
}

// These are Linux UAPI bits, including when profile serialization is tested on
// Darwin. They are NOT evidence that a real kernel negotiated the profile.
const (
	capKillprivV2 uint64 = 1 << 28
	requiredCaps  uint64 = fuse.CAP_DONT_MASK | fuse.CAP_POSIX_ACL
	allowedCaps   uint64 = requiredCaps | fuse.CAP_ASYNC_READ | fuse.CAP_BIG_WRITES | fuse.CAP_FILE_OPS | fuse.CAP_PARALLEL_DIROPS | fuse.CAP_MAX_PAGES | fuse.CAP_AUTO_INVAL_DATA
	forbiddenCaps uint64 = fuse.CAP_WRITEBACK_CACHE | fuse.CAP_PASSTHROUGH | fuse.CAP_ALLOW_IDMAP | fuse.CAP_OVER_IO_URING | fuse.CAP_READDIRPLUS | fuse.CAP_READDIRPLUS_AUTO | fuse.CAP_CACHE_SYMLINKS | fuse.CAP_NO_OPEN_SUPPORT | 1<<24 | fuse.CAP_HANDLE_KILLPRIV | capKillprivV2 | fuse.CAP_ATOMIC_O_TRUNC | 1<<29
)

func mountOptions(requests int) (fuse.MountOptions, error) {
	if requests < 1 || requests > 1024 {
		return fuse.MountOptions{}, c.ErrCapacity
	}
	return fuse.MountOptions{
		Name: "managed-v3", FsName: "managed-v3", AllowOther: true, Options: []string{"request_cred", "managed_close_to_open", "default_permissions"},
		EnableAcl: true, DisableReadDirPlus: true, DisableSplice: true,
		ExtraCapabilities: requiredCaps, DisabledCapabilities: forbiddenCaps,
		// Kernel MaxBackground excludes synchronous requests, and small callbacks
		// release their large input buffer before completion. Bound native reads by
		// the same count as rawFS.slots, not just by background work or bytes.
		MaxWrite: w.MaxIO, MaxBackground: requests, MaxInflightRequests: requests,
		MaxInflightRequestBytes: requests * (w.MaxIO + 4096),
	}, nil
}
func checkNegotiated(out fuse.InitOut) error {
	flags := out.Flags64()
	if out.Major != 7 || out.Minor != 33 || flags&requiredCaps != requiredCaps || flags & ^allowedCaps != 0 || flags&forbiddenCaps != 0 || out.MaxWrite == 0 || out.MaxWrite > w.MaxIO {
		return ErrProfile
	}
	return nil
}

//go:build linux && (arm64 || amd64)

package storagefuse

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	c "dev.cengine/guest/internal/storageclient"
	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

// Mounted owns one native kernel connection and one non-reconnecting TLS client.
type Mounted struct {
	fs                          *rawFS
	lifecycle                   *lifecycleFS
	client                      *c.Client
	server                      *fuse.Server
	path                        string
	mountID                     uint64
	connection                  uint64
	abortSignal                 chan struct{}
	abortDone                   chan struct{}
	abortCancel                 chan struct{}
	serveDone                   chan struct{}
	decision                    chan struct{}
	life                        mountLifecycle
	shutdownMu                  sync.Mutex
	mountMu                     sync.Mutex // protects the exact O_PATH pin against abort fallback
	gracefulStarted, finalizing bool
	gracefulCall                sync.Once
	timeout                     time.Duration
	abortOnce                   sync.Once
	pinned                      *pinnedMountPath
	mountedRoot                 *os.File // O_PATH pin of the exact new kernel mount, never rebound
	releasePath                 func()
	attached                    bool
	abortFile                   *os.File // pinned control file for this exact connection; never reopened
	done                        chan struct{}
	once                        sync.Once
	err                         error // published on done
}

// Close aborts and joins exact-owned resources. Its return is cleanup-only, not
// successful operation completion; Err retains the terminal reason.
func (m *Mounted) Close() error {
	select {
	case <-m.done:
		return m.err
	default:
	}
	m.fs.stop(c.ErrClosed)
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()
	select {
	case <-m.done:
		return m.err
	case <-ctx.Done():
		m.life.fail(ctx.Err())
		return errors.Join(ctx.Err(), m.Err())
	}
}
func (m *Mounted) Done() <-chan struct{} { return m.done }
func (m *Mounted) Err() error            { return m.life.result() }
func (m *Mounted) Mountpoint() string    { return m.path }

// PrepareDenialDiagnostic returns the closed origin token of the most recent
// EACCES denial and the total denial count served by this mount. Diagnostic
// only: never an admission, grant or retirement input.
func (m *Mounted) PrepareDenialDiagnostic() (string, uint64) {
	d := m.PrepareDenialDiagnosticDetails()
	return d.Origin, d.Count
}

// PrepareDenialDiagnosticDetails returns state captured together at denial.
func (m *Mounted) PrepareDenialDiagnosticDetails() PrepareDenialDetails {
	if m == nil || m.fs == nil {
		return (&denialTracker{}).details()
	}
	return m.fs.denials.details()
}

// CloseGracefully proves local kernel/client completion only, never authority
// drain or backing-device durability. Normal unmount is the kernel admission
// gate for non-directory users: open users make it EBUSY. New OPENDIR admission
// is sealed after opening the sync FD, while lifecycle callbacks remain allowed until Serve
// actually returns. Client admission is sealed only afterwards. The first caller
// owns the attempt and its cancellation; later callers only wait with their own
// deadlines and cannot cancel that shared attempt.
func (m *Mounted) CloseGracefully(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	// At most one worker owns kernel shutdown. If the kernel cannot be aborted,
	// return a bounded error WITHOUT claiming a join: Done stays open and the
	// exact path/resources stay owned until that worker genuinely finishes.
	owner := false
	m.gracefulCall.Do(func() { owner = true; go func() { _ = m.closeGracefully(ctx) }() })
	return waitGraceful(ctx, m.done, m.Err, m.cancelGraceful, owner)
}

func (m *Mounted) cancelGraceful(err error) {
	m.shutdownMu.Lock()
	defer m.shutdownMu.Unlock()
	if !m.life.clean.Load() {
		m.fs.stop(err)
	}
}

func (m *Mounted) closeGracefully(ctx context.Context) error {
	m.shutdownMu.Lock()
	if m.finalizing || m.gracefulStarted {
		m.shutdownMu.Unlock()
		select {
		case <-m.done:
			return m.Err()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	m.gracefulStarted = true
	m.life.closing.Store(true)
	m.shutdownMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	fired := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(fired); m.cancelGraceful(ctx.Err()) })
	err := completeGraceful(ctx, m.normalUnmount,
		func(ctx context.Context) error {
			select {
			case <-m.serveDone:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		func(context.Context) error {
			if !m.life.unmounted.Load() || m.fs.stopped.Load() {
				return ErrProfile
			}
			return nil
		},
		m.client.CloseGracefully)
	if !stop() {
		<-fired
	}
	m.shutdownMu.Lock()
	if err == nil {
		err = errors.Join(ctx.Err(), m.life.result())
	}
	if err == nil {
		m.life.clean.Store(true)
	}
	m.shutdownMu.Unlock()
	if err != nil {
		m.fs.stop(err)
	}
	close(m.decision)
	<-m.done
	return errors.Join(err, m.Err())
}

func nativeMountFlags(readOnly bool) uintptr {
	flags := uintptr(unix.MS_NOSUID | unix.MS_NODEV)
	if readOnly {
		flags |= unix.MS_RDONLY
	}
	return flags
}

func (m *Mounted) normalUnmount(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.pinned.validate(); err != nil {
		return err
	}
	info, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	if !m.matchesMount(string(info)) {
		return ErrProfile
	}
	// Open the exact mounted root through the retained private parent. syncfs
	// flushes kernel dirty pages; DATA acknowledgements are not durable drain.
	fd, err := unix.Openat(m.pinned.parentFD(), m.pinned.name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "managed-fuse-sync")
	id, check := descriptorMountID(file)
	if check == nil && id != m.mountID {
		check = ErrProfile
	}
	if check == nil {
		check = unix.Syncfs(fd)
	}
	// Capture the actual granted handles while the sync FD is still open. close(2)
	// schedules RELEASEDIR asynchronously, so join its callback AND exact native
	// response delivery before unmount can disconnect the kernel connection.
	releases, releaseErr := m.lifecycle.directories.sealAndSnapshot(ctx, m.client.Terminal())
	err = errors.Join(check, releaseErr, file.Close())
	if err != nil {
		return err
	}
	if len(releases) == 0 {
		return ErrProfile
	} // sync FD must own a tracked grant
	if err = waitDirectoryReleases(ctx, releases, m.client.Terminal()); err != nil {
		return err
	}
	info, err = os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	if !m.matchesMount(string(info)) || m.fs.stopped.Load() {
		return ErrProfile
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	// An O_PATH reference itself makes a normal umount busy. Release only this
	// owned pin after validation, then resolve via the retained trusted parent.
	// The private PID1 namespace and path claim exclude competing mount writers.
	m.mountMu.Lock()
	err = m.mountedRoot.Close()
	m.mountedRoot = nil
	m.mountMu.Unlock()
	if err != nil {
		return err
	}
	target := fdPath(m.pinned.chain[len(m.pinned.chain)-1].file) + "/" + m.pinned.name
	err = unix.Unmount(target, 0) // NEVER force/lazy on the success path
	if err != nil {
		// Recover a pin for abort cleanup only if it is still the original mount.
		n, e := unix.Openat(m.pinned.parentFD(), m.pinned.name, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e == nil {
			pin := os.NewFile(uintptr(n), "managed-fuse-repin")
			id, e := descriptorMountID(pin)
			if e == nil && id == m.mountID {
				m.mountMu.Lock()
				m.mountedRoot = pin
				m.mountMu.Unlock()
			} else {
				_ = pin.Close()
			}
		}
		return err
	}
	m.attached = false
	info, err = os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	if hasMountAt(string(info), m.path) || hasMountID(string(info), m.mountID) {
		return ErrProfile
	}
	m.life.unmounted.Store(true)
	return nil
}

func nativeMount(cfg mountConfig) (*mounted, error) {
	return nativeMountObserved(cfg, nil)
}

// The optional observer only receives immutable post-delivery records. Native
// regression tests use it to synchronize signals with real kernel delivery;
// production construction never installs an additional observer.
func nativeMountObserved(cfg mountConfig, observe func(fuse.ReplyDelivery)) (_ *mounted, err error) {
	failure := &mountFailureTracker{}
	failure.enter(stagePreflight)
	retire := cfg.Retire
	cfg.Retire = func(cause error) { retire(failure.wrap(cause)) }
	defer func() { err = failure.wrap(err) }()
	releasePath, err := claimMountPath(cfg.Mountpoint)
	if err != nil {
		return nil, err
	}
	pinned, err := preflightMount(cfg)
	if err != nil {
		releasePath()
		return nil, err
	}
	options, err := mountOptions(cfg.Client.Limits.Requests)
	if err != nil {
		pinned.close()
		releasePath()
		return nil, err
	}
	prepare, err := newMountPrepareProcess(cfg.Client.Authority.Binding.Role, cfg.ReadOnly, pinPrepareProcess)
	if err != nil {
		pinned.close()
		releasePath()
		return nil, err
	}
	defer func() {
		if err != nil && prepare != nil {
			prepare.close()
		}
	}()
	// Ownership starts here. Even setup failure can leave remote attachment work.
	var client *c.Client
	var f *rawFS
	var m *mounted
	defer func() {
		if err != nil {
			if f != nil {
				f.stop(err)
			} else {
				cfg.Retire(err)
			}
			if client != nil {
				_ = client.Close()
			} else {
				_ = cfg.Client.Conn.NetConn().Close()
			}
			if m != nil {
				m.cleanup()
				err = errors.Join(err, m.err)
			} else {
				pinned.close()
				releasePath()
			}
		}
	}()
	f = &rawFS{RawFileSystem: fuse.NewDefaultRawFileSystem(), fd: -1, arch: runtime.GOARCH, slots: make(chan struct{}, cfg.Client.Limits.Requests), ready: make(chan struct{}), retire: cfg.Retire}
	cc := cfg.Client
	cc.Invalidate = func(ctx context.Context, n c.Notification) error {
		select {
		case <-f.ready:
			return invalidate(ctx, f.server, n)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	failure.enter(stageData)
	client, err = c.New(cc)
	if err != nil {
		f = nil
		return nil, err
	}
	f.client = clientBridge{client}
	f.prepare = prepare // fully pinned before any native mount or Serve callback
	failure.enter(stageRoot)
	rootID, root := client.Root()
	if rootID != 1 || root.Attr.Mode&0170000 != 0040000 {
		return nil, ErrProfile
	}
	if _, ok := attr(root.Attr); !ok {
		return nil, ErrProfile
	}
	m = &mounted{fs: f, client: client, path: cfg.Mountpoint, pinned: pinned, releasePath: releasePath, done: make(chan struct{}), serveDone: make(chan struct{}), decision: make(chan struct{}), timeout: cc.Timeout}
	failure.enter(stageNamespace)
	if err = pinned.create(); err != nil {
		return nil, err
	}
	// All path operations use retained descriptors, never an unchecked pathname.
	failure.enter(stageDevice)
	device, err := unix.Open("/dev/fuse", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f.fd = device
	var st unix.Stat_t
	if err = unix.Fstat(device, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFCHR || unix.Major(st.Rdev) != 10 || unix.Minor(st.Rdev) != 229 {
		return nil, ErrProfile
	}
	serverFD, err := unix.FcntlInt(uintptr(device), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if serverFD >= 0 {
			_ = unix.Close(serverFD)
		}
	}()
	data := fmt.Sprintf("fd=%d,rootmode=40000,user_id=0,group_id=0,max_read=%d,allow_other,request_cred,managed_close_to_open,default_permissions", device, w.MaxIO)
	failure.enter(stageNamespace)
	if err = pinned.validate(); err != nil {
		return nil, err
	}
	if target, e := os.Readlink(fdPath(pinned.leaf.file)); e != nil || target != m.path {
		return nil, ErrProfile
	}
	beforeMount, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	if hasMountAt(string(beforeMount), m.path) {
		return nil, ErrProfile
	}
	// request_cred is the patched kernel's init-user-namespace proof; no fallback.
	// The target is the pinned new leaf, even if an ancestor is renamed meanwhile.
	failure.enter(stageMount)
	if err = unix.Mount("managed-v3", fdPath(pinned.leaf.file), "fuse.managed-v3", nativeMountFlags(cfg.ReadOnly), data); err != nil {
		return nil, err
	}
	m.attached = true
	// O_PATH does not send GETATTR/OPEN to the not-yet-initialized FUSE server.
	failure.enter(stageMountIdentity)
	rootFD, err := unix.Openat(pinned.parentFD(), pinned.name, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	m.mountedRoot = os.NewFile(uintptr(rootFD), "managed-fuse-mount")
	kernelMountID, err := descriptorMountID(m.mountedRoot)
	if err != nil {
		return nil, err
	}
	if target, e := os.Readlink(fdPath(m.mountedRoot)); e != nil || target != m.path {
		return nil, ErrProfile
	}
	mountInfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	m.mountID, m.connection, err = bindNewMount(string(beforeMount), string(mountInfo), m.path, kernelMountID)
	if err == nil && !mountModeMatches(string(mountInfo), m.path, m.mountID, cfg.ReadOnly) {
		err = ErrProfile
	}
	if err != nil {
		return nil, err
	}
	failure.enter(stageFusectl)
	abortFD, err := unix.Open(fmt.Sprintf("/sys/fs/fuse/connections/%d/abort", m.connection), unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	var statfs unix.Statfs_t
	if err = unix.Fstatfs(abortFD, &statfs); err != nil {
		_ = unix.Close(abortFD)
		return nil, err
	}
	if statfs.Type != 0x65735543 {
		_ = unix.Close(abortFD)
		return nil, ErrProfile
	} // FUSE_CTL_SUPER_MAGIC
	m.abortFile = os.NewFile(uintptr(abortFD), "managed-fuse-abort")
	m.abortSignal = make(chan struct{})
	m.abortDone = make(chan struct{})
	m.abortCancel = make(chan struct{})
	go func() {
		select {
		case <-m.abortSignal:
			m.abort()
		case <-m.abortCancel:
		}
		close(m.abortDone)
	}()
	failure.enter(stageInit)
	// Delivery/raw callbacks only signal; they never wait on a capture or syscall.
	f.abortMount = func(err error) { m.life.fail(err); m.signalAbort() }
	// Exactly one watcher. Captures terminal failure even during INIT construction.
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		if err := m.life.waitTerminal(client.Terminal(), m.decision, client.Err); err != nil {
			f.terminalFailure(err)
		}
	}()
	defer func() {
		if err != nil {
			f.stop(err)
			<-watcherDone
		}
	}()
	timerDone := make(chan struct{})
	timer := time.AfterFunc(cc.Timeout, func() { defer close(timerDone); f.stop(errMountInitDeadline) })
	options.ManagedProtocol = true
	options.ValidateInit = func(out fuse.InitOut) error { return failure.validateInit(f, out) }
	lifecycle := &lifecycleFS{rawFS: f, life: &m.life}
	// Include bounded in-flight response credits as well as live client grants.
	lifecycle.directories.limit = cc.Limits.Handles + cc.Limits.Requests
	m.lifecycle = lifecycle
	options.ObserveReply = func(reply fuse.ReplyDelivery) {
		lifecycle.observeReply(reply)
		if observe != nil {
			observe(reply)
		}
	}
	options.Logger = log.New(io.Discard, "", 0)
	options.PanicHandler = f.panicFailure
	// go-fuse owns this duplicate, not the retained capture descriptor. No clone.
	magic := fmt.Sprintf("/dev/fd/%d", serverFD)
	serverFD = -1
	m.server, err = fuse.NewServer(lifecycle, magic, &options)
	if !timer.Stop() {
		<-timerDone
	}
	if err != nil {
		return nil, err
	}
	if f.stopped.Load() {
		m.server.Serve()
		return nil, client.Err()
	}
	failure.enter(stageActive)
	go func() { defer close(m.serveDone); m.server.Serve() }()
	go func() {
		<-watcherDone
		m.shutdownMu.Lock()
		m.finalizing = true
		graceful := m.gracefulStarted
		m.shutdownMu.Unlock()
		if graceful {
			<-m.decision
		}
		<-m.serveDone // Wait() alone does not join OnUnmount/device closure.
		if !m.life.clean.Load() {
			_ = client.Close()
		}
		m.cleanup()
		m.life.fail(m.err)
		close(m.done)
	}()
	return m, nil
}
func (m *mounted) signalAbort() { m.abortOnce.Do(func() { close(m.abortSignal) }) }
func (m *mounted) abort() {
	if m.abortFile == nil {
		return
	}
	m.fs.deviceMu.Lock()
	n, err := m.abortFile.Write([]byte("1")) // native fusectl abort; no waiting on Serve
	if err != nil || n != 1 {
		if n != 1 {
			err = errors.Join(err, io.ErrShortWrite)
		}
		m.life.fail(err)
		// Never discard failed-abort evidence or touch a replacement mount.
		info, e := os.ReadFile("/proc/self/mountinfo")
		if e != nil {
			m.life.fail(e)
		} else {
			m.mountMu.Lock()
			if m.matchesMountLocked(string(info)) {
				m.life.fail(unix.Unmount(fdPath(m.mountedRoot), unix.MNT_FORCE|unix.MNT_DETACH))
			} else {
				m.life.fail(ErrProfile)
			}
			m.mountMu.Unlock()
		}
	}
	m.fs.deviceMu.Unlock()
}
func (m *mounted) cleanup() {
	m.once.Do(func() {
		defer func() {
			if m.mountedRoot != nil {
				_ = m.mountedRoot.Close()
			}
			m.pinned.close()
			if m.err == nil {
				m.releasePath()
			} // failed teardown permanently poisons this generation path
		}()
		if m.abortSignal != nil {
			if m.life.clean.Load() && !m.fs.stopped.Load() {
				close(m.abortCancel)
			} else {
				m.signalAbort()
			}
			<-m.abortDone
		}
		m.fs.deviceMu.Lock()
		if m.fs.fd >= 0 {
			_ = unix.Close(m.fs.fd)
			m.fs.fd = -1
		}
		m.fs.deviceMu.Unlock()
		if m.fs.prepare != nil {
			m.fs.prepare.close()
		}
		if m.abortFile != nil {
			_ = m.abortFile.Close()
		}
		if m.attached {
			info, e := os.ReadFile("/proc/self/mountinfo")
			if e != nil {
				m.err = e
				return
			}
			if m.mountID == 0 || m.connection == 0 || m.mountedRoot == nil {
				m.err = ErrProfile // partial setup: never adopt/unmount any matching name
				return
			}
			if m.matchesMount(string(info)) {
				if e = unix.Unmount(fdPath(m.mountedRoot), unix.MNT_FORCE|unix.MNT_DETACH); e != nil {
					m.err = e
					return
				}
			} else if hasMountAt(string(info), m.path) || hasMountID(string(info), m.mountID) {
				m.err = ErrProfile
				return
			}
		}
		// Never remove a preexisting or replaced directory, and never recurse.
		m.err = errors.Join(m.err, m.pinned.remove())
	})
}

func descriptorMountID(file *os.File) (uint64, error) {
	info, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", file.Fd()))
	if err != nil {
		return 0, err
	}
	return parseDescriptorMountID(string(info))
}
func (m *mounted) matchesMount(info string) bool {
	m.mountMu.Lock()
	defer m.mountMu.Unlock()
	return m.matchesMountLocked(info)
}
func (m *mounted) matchesMountLocked(info string) bool {
	if m.mountedRoot == nil {
		return false
	}
	id, err := descriptorMountID(m.mountedRoot)
	if err != nil || id != m.mountID {
		return false
	}
	return matchesMount(info, m.path, m.mountID, m.connection)
}

func preflightMount(cfg mountConfig) (_ *pinnedMountPath, err error) {
	if os.Geteuid() != 0 {
		return nil, ErrProfile
	}
	pinned, err := pinMountParent(cfg.Mountpoint)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			pinned.close()
		}
	}()
	caps, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return nil, err
	}
	last, err := strconv.ParseUint(strings.TrimSpace(string(caps)), 10, 32)
	if err != nil || last != unix.CAP_LAST_CAP || last >= 63 || cfg.Client.SupportedCaps != (uint64(1)<<(last+1))-1 {
		return nil, ErrProfile
	}
	info, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	if err = privateParent(string(info), filepath.Dir(cfg.Mountpoint)); err != nil {
		return nil, err
	}
	return pinned, nil
}

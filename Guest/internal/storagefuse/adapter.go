// Package storagefuse contains the disabled managed-v3 raw FUSE translation layer.
// There is deliberately no exported constructor or production mount path.
package storagefuse

import (
	"errors"
	"sync"
	"sync/atomic"
	"syscall"

	c "dev.cengine/guest/internal/storageclient"
	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// credential is private: only clientBridge translates a successful ABI-3 capture.
// Neither FUSE header identity nor an ioctl error can produce NONE.
type credential struct {
	snapshot c.Snapshot
	state    uint8
}

const (
	present uint8 = 1
	none    uint8 = 2
)

type client interface {
	Capture(int, uint64) (credential, error)
	Do(credential, w.AuthKind, w.RequestBody) (c.Result, error)
	Node(c.LocalNode) (w.Entry, error)
	Handle(c.LocalHandle) (c.HandleGrant, error)
	Forget(c.LocalNode, uint64) error
	Abort(error)
}

type rawFS struct {
	fuse.RawFileSystem
	client     client
	fd         int    // retained duplicate of the SAME open description, never IOC_CLONE
	arch       string // Linux ABI, never the native Darwin flag values
	slots      chan struct{}
	deviceMu   sync.RWMutex // excludes retained-fd closure during both ioctl queries
	stopOnce   sync.Once
	stopped    atomic.Bool
	abortMount func(error) // must affect only the private mount owned by this adapter
	retire     func(error)
	negotiated atomic.Bool
	server     *fuse.Server // published by closing ready, before native Serve starts
	ready      chan struct{}
	prepare    *prepareProcessGate // nil on runtime mounts; immutable after construction
	denials    denialTracker       // diagnostic-only EACCES origin attribution
}

var _ fuse.RawFileSystem = (*rawFS)(nil)
var errTranslation = errors.New("storagefuse: invalid raw request or reply")

func (f *rawFS) String() string { return "managed-v3-disabled" }
func (f *rawFS) SetDebug(bool)  {} // never log credentials, names, or payloads
func (f *rawFS) stop(err error) {
	f.stopOnce.Do(func() {
		f.stopped.Store(true)
		// Callback annotations belong to mount diagnostics, not the client's
		// causal terminal identity. Strip only our own immediate annotation;
		// never unwrap arbitrary caller errors or joined cleanup failures.
		cause := err
		if failure, ok := err.(*callbackFailure); ok && failure != nil {
			cause = failure.cause
		}
		f.client.Abort(cause)
		if f.abortMount != nil {
			f.abortMount(err)
		}
		if f.retire != nil {
			f.retire(err)
		}
	})
}
func (f *rawFS) OnUnmount() {
	f.stopAt(siteServeExit, 0, errors.New("storagefuse: unmounted; retirement required"))
}

// The controlled fork's pre-reply validator, not KernelSettings, sets proof.
func (f *rawFS) Init(server *fuse.Server) {
	if !f.negotiated.Load() || f.stopped.Load() {
		f.stop(ErrProfile)
		return
	}
	f.server = server
	close(f.ready)
}
func (f *rawFS) validateInit(out fuse.InitOut) error {
	if err := checkNegotiated(out); err != nil {
		return err
	}
	f.negotiated.Store(true)
	return nil
}

// Linux permits ignoring advisory INTERRUPT requests and completing the original
// operation. The control reply has no grant; ENOENT on its EAGAIN reply means the
// original completed first. Never extend that exception to an operation reply.
func completedInterrupt(r fuse.ReplyDelivery) bool {
	if r.Opcode != 36 || r.Unique == 0 || r.Interrupted {
		return false
	}
	if r.Suppressed {
		return r.Status == fuse.OK && r.Expected == 0 && r.Bytes == 0 && r.Err == nil
	}
	return r.Status == fuse.EAGAIN && r.Expected == 16 &&
		((r.Bytes == 16 && r.Err == nil) || (r.Bytes == -1 && r.Err == syscall.ENOENT))
}

// Interrupted records a cancellation request, not a failed native send. Keep
// ownership until the original reply is actually delivered, once, in full.
func deliveredDespiteInterrupt(r fuse.ReplyDelivery) bool {
	return r.Unique != 0 && r.Opcode != 26 && r.Opcode != 36 && r.Opcode != 38 &&
		r.Status != fuse.EINTR && !r.Suppressed && r.Err == nil && r.Expected >= 16 && r.Bytes == r.Expected
}

func (f *rawFS) observeReply(r fuse.ReplyDelivery) {
	if completedInterrupt(r) {
		return
	}
	// FORGET/BATCH_FORGET/NOTIFY_REPLY are normal no-reply lifecycle messages.
	normalSuppression := r.Opcode == 2 || r.Opcode == 42 || r.Opcode == 41
	if r.Err != nil || (r.Interrupted && !deliveredDespiteInterrupt(r)) || r.Opcode == 36 || r.Status == fuse.EINTR || (r.Suppressed && !normalSuppression) || (r.Opcode == 26 && r.Status != 0) {
		site := siteReplyDelivery
		if r.Interrupted || r.Opcode == 36 || r.Status == fuse.EINTR {
			site = siteInterrupted
		} else if r.Suppressed && !normalSuppression {
			site = siteSuppressed
		} else if r.Opcode == 26 && r.Status != 0 {
			site = siteInitReply
		}
		f.stopAt(site, r.Opcode, errors.Join(errTranslation, r.Err))
	}
}
func (f *rawFS) bad() fuse.Status { return f.badAt(siteOther, 0) }
func (f *rawFS) node(id uint64) w.NodeID {
	e, err := f.client.Node(c.LocalNode(id))
	if err != nil {
		return 0
	}
	return e.Node
}
func (f *rawFS) handle(node, id uint64) w.HandleID {
	h, err := f.client.Handle(c.LocalHandle(id))
	if err != nil || h.Node != f.node(node) {
		return 0
	}
	return h.Handle
}
func (f *rawFS) optionalHandle(node, id uint64, has bool) *w.HandleID {
	if !has {
		return nil
	}
	h := f.handle(node, id)
	return &h
}

// Every admitted callback captures exact Unique before validation/RPC/response.
// No cancellation is observed after admission, and no request is replayed.
func (f *rawFS) call(h *fuse.InHeader, allowedNone w.AuthKind, build func() w.RequestBody) (c.Result, fuse.Status) {
	if f.stopped.Load() {
		return c.Result{}, fuse.EIO
	}
	select {
	case f.slots <- struct{}{}:
	default:
		return c.Result{}, f.badAt(siteAdmission, h.Opcode)
	}
	defer func() { <-f.slots }()
	f.deviceMu.RLock()
	cred, err := f.client.Capture(f.fd, h.Unique)
	f.deviceMu.RUnlock()
	if err != nil {
		f.stopAt(siteCapture, h.Opcode, err)
		return c.Result{}, fuse.EIO
	}
	auth := w.AuthKind(0)
	switch cred.state {
	case present:
		if allowedNone == w.LifecycleAuth {
			return c.Result{}, f.badAt(sitePresentLifecycle, h.Opcode)
		}
	case none:
		if allowedNone == 0 {
			return c.Result{}, f.badAt(siteNoneCaller, h.Opcode)
		}
		auth = allowedNone
	default:
		return c.Result{}, f.badAt(siteCredentialKind, h.Opcode)
	}
	// Credential capture/auth classification always precedes the additional
	// kernel-local process constraint. PID never supplies wire credentials.
	forcedPrepareFlush := false
	if f.prepare != nil && allowedNone != w.LifecycleAuth {
		f.prepare.mu.Lock()
		defer f.prepare.mu.Unlock()
		forcedPrepareFlush = f.prepare.forcedFlush(h.Pid, cred.state, auth, h.Opcode)
		if !forcedPrepareFlush && !f.prepare.check(h.Pid, cred.state) {
			f.recordGateDenial(h, cred.state, nil)
			return c.Result{}, fuse.EACCES
		}
	}
	body := build()
	if body == nil {
		return c.Result{}, fuse.EINVAL
	}
	if forcedPrepareFlush {
		// Do not let an opcode/body mismatch extend the NONE exception to data,
		// metadata, or PREPARE controls. Grants are checked by Client.Do below.
		if _, ok := body.(w.FlushRequest); !ok {
			f.recordDenial(denialGateFlush, h.Opcode, body, true)
			return c.Result{}, fuse.EACCES
		}
	}
	if f.prepare != nil && allowedNone != w.LifecycleAuth {
		if status := f.prepare.admit(h.Pid, h.NodeId, body); status != fuse.OK {
			if status == fuse.EACCES {
				f.recordGateDenial(h, cred.state, body)
			}
			return c.Result{}, status
		}
	}
	if b, ok := body.(w.WriteRequest); ok && b.WriteFlags&w.WriteCache != 0 && auth != w.OpenGrantAuth {
		return c.Result{}, f.badAt(siteWritebackProvenance, h.Opcode)
	}
	r, err := f.client.Do(cred, auth, body)
	if err != nil {
		if errors.Is(err, c.ErrCapacity) && allowedNone != w.LifecycleAuth {
			return c.Result{}, fuse.EAGAIN
		}
		if errors.Is(err, w.ErrReadOnly) && allowedNone != w.LifecycleAuth {
			return c.Result{}, fuse.EROFS
		}
		site := siteClientDo
		if errors.Is(err, c.ErrGrant) {
			site = siteClientGrant
		}
		f.stopAt(site, h.Opcode, err)
		return c.Result{}, fuse.EIO
	}
	if r.Reply.Errno > w.MaxLinuxErrno {
		return c.Result{}, f.badAt(siteReplyErrno, h.Opcode)
	}
	if r.Reply.Errno == uint32(syscall.EACCES) {
		// The storage DATA server denied the operation (server-side DAC). This is
		// distinct from every local prepare-gate rejection recorded above.
		f.recordDenial(denialStorage, h.Opcode, body, f.prepare != nil && allowedNone != w.LifecycleAuth)
	}
	return r, fuse.Status(r.Reply.Errno) // Linux errno, not host errno mapping
}

// recordGateDenial attributes a prepare-gate EACCES to its closed local origin:
// missing captured credentials vs a credential-carrying request from a process
// outside the pinned prepare owner. The gate lock is held and lastOwned is
// the admission evaluation that just rejected, never a diagnostic recheck.
func (f *rawFS) recordGateDenial(h *fuse.InHeader, state uint8, body w.RequestBody) {
	if state != present {
		f.recordDenial(denialGateCredential, h.Opcode, body, true)
		return
	}
	if !f.prepare.lastOwned {
		f.recordDenial(denialGateProcess, h.Opcode, body, true)
		return
	}
	f.recordDenial(denialGateOrder, h.Opcode, body, true)
}
func (f *rawFS) ack(h *fuse.InHeader, none w.AuthKind, build func() w.RequestBody) fuse.Status {
	_, status := f.call(h, none, build)
	return status
}
func (f *rawFS) Forget(id, count uint64) {
	if err := f.client.Forget(c.LocalNode(id), count); err != nil {
		f.stopAt(siteForget, 0, err) // callback has no header; do not invent an opcode
	}
}

func (f *rawFS) entry(r c.Result, out *fuse.EntryOut, opcodes ...uint32) fuse.Status {
	var e w.Entry
	switch b := r.Reply.Body.(type) {
	case w.LookupReply:
		e = b.Entry
	case w.CreateReply:
		e = b.Entry
	case w.MkdirReply:
		e = b.Entry
	case w.MknodReply:
		e = b.Entry
	case w.SymlinkReply:
		e = b.Entry
	case w.LinkReply:
		e = b.Entry
	default:
		return f.badAt(siteReplyEntryKind, firstOpcode(opcodes))
	}
	a, ok := attr(e.Attr)
	if !ok || r.Node == 0 {
		return f.badAt(siteReplyEntryAttr, firstOpcode(opcodes))
	}
	*out = fuse.EntryOut{NodeId: uint64(r.Node), Generation: e.Generation, Attr: a} // all TTLs zero
	return fuse.OK
}
func attr(a w.Attr) (fuse.Attr, bool) {
	// FUSE rdev is new_encode_dev (32 bits), unlike Linux userspace dev_t.
	major := (a.Rdev>>8)&0xfff | (a.Rdev>>32)&0xfffff000
	minor := a.Rdev&0xff | (a.Rdev>>12)&0xffffff00
	if major > 0xfff || minor > 0xfffff {
		return fuse.Attr{}, false
	}
	return fuse.Attr{Ino: a.Ino, Size: a.Size, Blocks: a.Blocks, Mode: a.Mode, Nlink: a.Nlink,
		Owner: fuse.Owner{Uid: a.UID, Gid: a.GID}, Rdev: uint32((minor & 0xff) | (major << 8) | ((minor &^ 0xff) << 12)), Blksize: a.BlockSize,
		Atime: uint64(a.ATime.Seconds), Atimensec: a.ATime.Nanoseconds, Mtime: uint64(a.MTime.Seconds), Mtimensec: a.MTime.Nanoseconds, Ctime: uint64(a.CTime.Seconds), Ctimensec: a.CTime.Nanoseconds}, true
}
func (f *rawFS) attrReply(r c.Result, out *fuse.AttrOut, opcodes ...uint32) fuse.Status {
	var a w.Attr
	switch b := r.Reply.Body.(type) {
	case w.GetAttrReply:
		a = b.Attr
	case w.SetAttrReply:
		a = b.Attr
	default:
		return f.badAt(siteReplyAttrKind, firstOpcode(opcodes))
	}
	value, ok := attr(a)
	if !ok {
		return f.badAt(siteReplyAttr, firstOpcode(opcodes))
	}
	*out = fuse.AttrOut{Attr: value}
	return fuse.OK
}
func (f *rawFS) opened(r c.Result, out *fuse.OpenOut, opcodes ...uint32) fuse.Status {
	if r.Handle == 0 {
		return f.badAt(siteReplyHandle, firstOpcode(opcodes))
	}
	*out = fuse.OpenOut{Fh: uint64(r.Handle)}
	return fuse.OK
}

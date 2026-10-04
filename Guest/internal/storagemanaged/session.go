// Package storagemanaged is the disabled managed-v3 ext4 session core.
// It has no listener, activation path, or legacy-storage integration.
package storagemanaged

import (
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	"dev.cengine/guest/internal/storageauthority"
	"dev.cengine/guest/internal/storageidentity"
	w "dev.cengine/guest/internal/storagewire"
)

// Limits reserve ownership records before granting resources. Live pins are never
// evicted. A Registry and its namespace gate must be shared by the whole service.
const (
	MaxNodes   = 4096
	MaxHandles = 4096
	MaxObjects = 65536
)

type inodeKey struct {
	volume   storageauthority.ID
	dev, ino uint64
}
type object struct {
	key  inodeKey
	id   w.ObjectID
	fd   int
	refs uint64
}
type node struct {
	id             w.NodeID
	object         *object
	fd             int // session/view operational pin; object.fd is identity-only
	lookups, opens uint64
}
type handle struct {
	fd        int
	node      *node
	flags     uint32
	directory bool
}

// ErrVolumeFault is terminal for every attachment of the volume. The future
// transport must stop all its volume peers and request retirement on this error.
// A later successful sync cannot erase the fault or authorize a drain receipt.
var ErrVolumeFault = errors.New("storagemanaged: terminal volume fault")

// Private per-registry syscall injection permits deterministic durability tests.
type syncOperations struct{ fsync, fdatasync, syncfs func(int) error }

// Registry owns cross-session object identities and attachment resources. Its
// zero value is not usable; use NewRegistry with the service-global writer gate.
type Registry struct {
	gate             *sync.Mutex
	objects          map[inodeKey]*object
	sessions         map[storageauthority.Binding]*Session
	eventSequence    uint64
	worker           *storageidentity.Worker
	store            storageauthority.ID
	faults           map[storageauthority.ID]error
	syncOps          syncOperations
	postNamespace    func() error                                                         // private deterministic post-syscall failure injection
	prepareOperation func(*storageauthority.Guard, w.PrepareRequest) (w.ReplyBody, error) // private portable dispatch seam

	copyCleanupCheckpoint func(string) error        // private process-crash test boundary
	barrierBinding        *storageauthority.Binding // current Barrier only; protected by gate
}

func NewRegistry(gate *sync.Mutex) (*Registry, error) {
	if gate == nil {
		return nil, syscall.EINVAL
	}
	return &Registry{gate: gate, objects: make(map[inodeKey]*object), sessions: make(map[storageauthority.Binding]*Session), faults: make(map[storageauthority.ID]error), syncOps: platformSyncOperations()}, nil
}

// Session must not be copied. Dispatch consumes neither the caller's Guard nor
// its request. The transport must invoke Dispatch in stream order and hold each
// Guard until Dispatch returns. No cancellation after enqueue is supported.
type Session struct {
	mu             sync.Mutex
	principal      *storageauthority.DataPrincipal
	binding        storageauthority.Binding
	registry       *Registry
	worker         *storageidentity.Worker
	root           *os.File
	metadataFD     *os.File // private kernel capability; never exported or used as caller identity
	nodes          map[w.NodeID]*node
	byInode        map[inodeKey]*node
	handles        map[w.HandleID]*handle
	nextNode       w.NodeID
	nextHandle     w.HandleID
	sequence       w.SequenceTracker
	closed, failed bool

	// Zero means unknown, never certified. Only audited New may set this true;
	// every store is under registry.gate. Atomic loads let rejected, unadmitted
	// calls on unknown sessions retain their no-queue admission behavior.
	prepareRetirementQualified atomic.Bool
}

type Result struct {
	Reply  w.Reply
	Events []w.Event
}

// New acquires its own canonical root from guard.DupVolumeRoot. No caller-owned
// descriptor can substitute a same-inode bind/idmapped mount with different
// provenance. Success transfers the duplicate to Barrier ownership before guard
// release; failure closes it here. Read-only operations use a detached noatime
// clone; the canonical duplicate remains separate durability-barrier ownership.
func New(guard *storageauthority.Guard, principal *storageauthority.DataPrincipal, binding storageauthority.Binding, gate *sync.Mutex, worker *storageidentity.Worker, registry *Registry) (*Session, w.Entry, error) {
	if err := guard.ValidateFor(principal); err != nil {
		return nil, w.Entry{}, err
	}
	got, err := principal.Binding()
	if err != nil {
		return nil, w.Entry{}, err
	}
	if got != binding || worker == nil || registry == nil || gate == nil || registry.gate != gate {
		return nil, w.Entry{}, syscall.EINVAL
	}
	gate.Lock()
	defer gate.Unlock()
	if err := registry.faults[binding.Volume]; err != nil {
		return nil, w.Entry{}, err
	}
	if registry.worker != nil && (registry.worker != worker || registry.store != binding.Store) {
		return nil, w.Entry{}, storageauthority.ErrConflict
	}
	if registry.sessions[binding] != nil {
		return nil, w.Entry{}, storageauthority.ErrConflict
	}
	// A root-only history cannot survive another session's resource ownership,
	// even if that session is subsequently drained and disappears from the census.
	qualify := binding.Role == storageauthority.PrepareRole && binding.Mode == storageauthority.ReadWrite && len(registry.sessions) == 0 && len(registry.objects) == 0 && len(registry.faults) == 0
	for _, other := range registry.sessions {
		other.prepareRetirementQualified.Store(false)
	}
	root, err := guard.DupVolumeRoot()
	if err != nil {
		return nil, w.Entry{}, err
	}
	s := &Session{principal: principal, binding: binding, registry: registry, worker: worker, root: root, nodes: make(map[w.NodeID]*node), byInode: make(map[inodeKey]*node), handles: make(map[w.HandleID]*handle)}
	s.metadataFD, err = platformMetadataSession()
	if err != nil {
		return nil, w.Entry{}, errors.Join(err, root.Close())
	}
	entry, err := s.initialize()
	if err != nil {
		return nil, w.Entry{}, errors.Join(err, s.metadataFD.Close(), root.Close())
	}
	registry.worker = worker
	registry.store = binding.Store
	registry.sessions[binding] = s
	// initialize only checks metadata, opens root pins and interns the initial
	// lookup. It performs no enumeration, data IO or backing mutation.
	s.prepareRetirementQualified.Store(qualify)
	return s, entry, nil
}

// Dispatch validates the exact live authority BEFORE any queue, root/node lookup
// or identity scope. The caller must not race request mutation with this call's
// initial snapshot, or release guard while this call owns admitted work.
func (s *Session) Dispatch(guard *storageauthority.Guard, request w.Request) (result Result, err error) {
	if s == nil {
		return Result{}, storageauthority.ErrUnauthorized
	}
	retirementCompleted, retirementGated := false, false
	defer func() {
		// Cover codec/admission errors and panics before acquiring the gate.
		// Unknown sessions need not join a queue merely to remain unknown.
		if !retirementGated && !retirementCompleted && s.prepareRetirementQualified.Load() {
			s.registry.gate.Lock()
			s.prepareRetirementQualified.Store(false)
			s.registry.gate.Unlock()
		}
	}()
	if err := guard.ValidateFor(s.principal); err != nil {
		return Result{}, err
	}
	// The sealed codec both validates and deep-copies every mutable DTO operand.
	data, err := w.Marshal(&request)
	if err != nil {
		return Result{}, err
	}
	var r w.Request
	if err = w.Unmarshal(data, &r); err != nil {
		return Result{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Recheck after acquiring the namespace gate: queued/admitted operations,
	// including reads which may dirty atime, cannot outrun BeginCopy. Waiters
	// retain their bounded session/guard ownership but never the global gate.
	retirementGateHeld := false
	defer func() {
		if retirementGateHeld {
			// This runs after obligation completion, but before releasing the gate.
			// Include panics in CopyFence, before ordinary dispatch has begun.
			if !retirementCompleted || err != nil || result.Reply.Errno != 0 {
				s.prepareRetirementQualified.Store(false)
			}
			s.registry.gate.Unlock()
		}
	}()
	for {
		s.registry.gate.Lock()
		retirementGateHeld = true
		// Before private recovery, obligations or any filesystem operation. No
		// later sync, release or successful request can restore qualification.
		s.observePrepareRetirementRequest(r)
		wait, fenceErr := guard.CopyFence()
		if fenceErr != nil {
			return Result{}, fenceErr
		}
		if wait == nil {
			break
		}
		retirementGateHeld = false
		s.registry.gate.Unlock()
		<-wait
	}
	retirementGated = true
	if err := s.registry.faults[s.binding.Volume]; err != nil {
		return Result{}, err
	}
	if s.closed || s.failed {
		return Result{}, storageauthority.ErrClosed
	}
	if err = s.sequence.Accept(r.Sequence); err != nil {
		s.failed = true
		return Result{}, err
	}
	result = Result{Reply: w.Reply{Sequence: r.Sequence, Op: r.Body.Operation()}, Events: []w.Event{}}
	if err = r.ValidateBinding(s.binding); err != nil {
		if errors.Is(err, w.ErrReadOnly) {
			result.Reply.Errno = 30
			return result, nil
		}
		s.failed = true
		return Result{}, err
	}
	// CopyFence admits the owner for private recovery, not ordinary DATA. Even
	// reads on its writable view can mutate atime before the exact replay finishes.
	if _, private := r.Body.(w.PrepareRequest); !private && !replayRootBootstrap(r) {
		if replayErr := guard.CheckCopyReplay(); replayErr != nil {
			if replayErr == storageauthority.ErrBlocked {
				result.Reply.Errno = uint32(syscall.EBUSY)
				return result, nil
			}
			return Result{}, replayErr
		}
	}
	completed, copySucceeded := false, false
	if needsDurability(r) {
		obligation, beginErr := s.beginRequestObligation(guard, r)
		if beginErr != nil {
			if rejectedObligation(beginErr) {
				result.Reply.Errno = uint32(syscall.EBUSY)
				return result, nil
			}
			return Result{}, s.registry.latch(s.binding.Volume, beginErr)
		}
		// Completion runs before releasing the namespace gate or publishing replies.
		// Panic/early return cannot erase the durable pre-syscall obligation.
		defer func() {
			cause := errors.Join(err, s.registry.faults[s.binding.Volume])
			if !completed {
				cause = errors.Join(cause, storageauthority.ErrRepairRequired)
			}
			finish := obligation.Complete
			if copyOp, ok := obligation.(interface{ CompleteRequest(error, bool) error }); ok {
				finish = func(cause error) error { return copyOp.CompleteRequest(cause, copySucceeded) }
			}
			if finishErr := finish(cause); finishErr != nil {
				err = s.registry.latch(s.binding.Volume, finishErr)
				result.Reply.Errno, result.Reply.Body = errno(err), nil
			}
		}()
	}
	if prepare, ok := r.Body.(w.PrepareRequest); ok {
		if prepare.Action == w.RollbackCopy || prepare.Action == w.ResumeCopyDirectory {
			result.Reply.Body, result.Events, err = s.prepareCopyRecovery(guard, prepare)
			// Recovery can mutate before any error, not just EIO. Never turn
			// partial rollback into an ordinary rejected request.
			if err != nil {
				s.registry.latch(s.binding.Volume, err)
			}
			for i := range result.Events {
				if s.registry.eventSequence == ^uint64(0) {
					return Result{}, s.registry.latch(s.binding.Volume, syscall.EOVERFLOW)
				}
				s.registry.eventSequence++
				result.Events[i].EventSequence = s.registry.eventSequence
				if eventErr := result.Events[i].Validate(); eventErr != nil {
					return Result{}, s.registry.latch(s.binding.Volume, eventErr)
				}
			}
		} else {
			run := s.prepare
			if s.registry.prepareOperation != nil {
				run = s.registry.prepareOperation
			}
			result.Reply.Body, err = run(guard, prepare)
		}
		copySucceeded = err == nil
		if err != nil {
			result.Reply.Errno, result.Reply.Body = errno(err), nil
			if errors.Is(err, syscall.EIO) || errors.Is(err, syscall.ENOSPC) {
				s.registry.latch(s.binding.Volume, err)
			}
			err = s.registry.faults[s.binding.Volume]
		}
		if fault := s.registry.faults[s.binding.Volume]; fault != nil {
			err = fault
		}
	} else {
		result, err = s.execute(r)
	}
	if err != nil {
		return result, err
	}
	if err = w.ValidateReplyFor(r, result.Reply); err != nil {
		s.failed = true
		if r.Mutates() {
			err = s.registry.latch(s.binding.Volume, err)
		}
		return result, err
	}
	copySucceeded = result.Reply.Errno == 0
	completed = true
	retirementCompleted = true
	return result, nil
}

// observePrepareRetirementRequest is a one-way history transition under gate.
// In particular, RELEASE/FORGET/sync cannot turn a once-dirty history root-only.
func (s *Session) observePrepareRetirementRequest(r w.Request) {
	if !replayRootBootstrap(r) {
		s.prepareRetirementQualified.Store(false)
	}
}

// PrepareRetirementProof is an optional authority callback, not an admission
// fence. Authority must fence this exact owner and join its guards before calling,
// without holding its mutex. The read-only census and synchronous publish share
// the namespace gate; publish must not reenter Registry. Authority checks all
// other attachments, global inflight work and historical copy state itself.
// This never replaces Barrier: real resource close and syncfs still follow.
func (r *Registry) PrepareRetirementProof(binding storageauthority.Binding, root *os.File, publish func() (bool, error)) (bool, error) {
	if r == nil || r.gate == nil || root == nil || publish == nil {
		return false, syscall.EINVAL
	}
	r.gate.Lock()
	defer r.gate.Unlock()
	s := r.sessions[binding]
	if s == nil || len(r.sessions) != 1 || s.registry != r || s.binding != binding || s.closed || s.failed || !s.prepareRetirementQualified.Load() || binding.Role != storageauthority.PrepareRole || binding.Mode != storageauthority.ReadWrite {
		return false, nil
	}
	for _, fault := range r.faults {
		if fault != nil {
			return false, fault
		}
	}
	eligible, err := s.prepareRetirementCensus(root)
	if err != nil {
		s.prepareRetirementQualified.Store(false)
		return false, err
	}
	if !eligible {
		return false, nil
	}
	return publish()
}

// Barrier is an authority callback, not an admission fence. storageauthority must
// already have fenced the attachment and joined ALL guards, including queued work.
// It synchronizes the retained ext4 filesystem and closes all attachment resources
// even on failure. A failed barrier cannot produce a successful drain receipt.
func (r *Registry) Barrier(binding storageauthority.Binding, root *os.File) error {
	if r == nil || root == nil {
		return syscall.EINVAL
	}
	r.gate.Lock()
	defer r.gate.Unlock()
	r.barrierBinding = &binding
	defer func() { r.barrierBinding = nil }()
	return r.barrier(binding, root)
}

// The namespace gate protects sticky faults. Keep the original error forever,
// even after attachment cleanup, so a fresh session cannot clear it.
func (r *Registry) latch(volume storageauthority.ID, err error) error {
	if err != nil && r.faults[volume] == nil {
		r.faults[volume] = errors.Join(ErrVolumeFault, err)
	}
	return r.faults[volume]
}
func errno(err error) uint32 {
	var e syscall.Errno
	if errors.As(err, &e) && e > 0 && uint64(e) <= uint64(w.MaxLinuxErrno) {
		return uint32(e)
	}
	return 5 // EIO, including joined worker/setup failures without a Linux errno.
}

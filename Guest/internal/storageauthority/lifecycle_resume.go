package storageauthority

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"

	"golang.org/x/sys/unix"
)

// ErrLifecycleResumeAlreadyApplied is a read-only constructor result, not a
// live authority. The resume successor state is already durable; reconcile the
// surviving service before attempting any other open.
var ErrLifecycleResumeAlreadyApplied = errors.New("lifecycle resume open already applied")

// LifecycleResumeOpenRequest authorizes one fresh resume of an original
// initialize grant. Unlike the cold request it names NO predecessor service
// epoch: no predecessor E is fabricated or trusted. The original grant is
// unsigned; ROOT's outer signature authenticates it together with the rest of
// the request. Declaration order is the frozen ROOT signing contract.
type LifecycleResumeOpenRequest struct {
	OperationID     ID                   `json:"operation_id"`
	Original        LifecycleGrant       `json:"original"`
	Takeover        SignedLifecycleGrant `json:"takeover"`
	Launch          LifecycleColdLaunch  `json:"launch"`
	NowUnixSeconds  uint64               `json:"now_unix_seconds"`
	LifetimeSeconds uint64               `json:"lifetime_seconds"`
}

type SignedLifecycleResumeOpen struct {
	Request   LifecycleResumeOpenRequest `json:"request"`
	Signature []byte                     `json:"signature"`
}

func (r LifecycleResumeOpenRequest) Validate() error {
	g, l := r.Takeover.Grant, r.Launch
	if !validID(r.OperationID) || r.OperationID != g.ID ||
		r.Original.Validate() != nil || r.Original.Operation != LifecycleInitialize ||
		g.Validate() != nil || g.Operation != LifecycleTakeover || g.ExpectedEpoch != 1 ||
		g.Identity != r.Original.Identity || g.Serial <= r.Original.Serial || g.ID == r.Original.ID ||
		g.NewKey == r.Original.NewKey || len(r.Takeover.Signature) != ed25519.SignatureSize ||
		!validID(l.ShimLaunchUUID) || !validKey(Fingerprint(l.SpecSHA256)) || !validKey(Fingerprint(l.InitramfsSHA256)) ||
		!validColdExt4UUID(l.Ext4UUID) || l.Bytes == 0 || l.Bytes > 1<<63-1 ||
		r.NowUnixSeconds == 0 || r.NowUnixSeconds > 253402300799 || r.LifetimeSeconds == 0 || r.LifetimeSeconds > 86400 ||
		r.LifetimeSeconds > 253402300799-r.NowUnixSeconds {
		return ErrInvalid
	}
	return nil
}

func (s SignedLifecycleResumeOpen) Validate() error {
	if s.Request.Validate() != nil || len(s.Signature) != ed25519.SignatureSize {
		return ErrInvalid
	}
	return nil
}

// LifecycleResumeOpenSigningBytes binds the unsigned original initialize grant
// into ROOT's request signature. json.Marshal uses declaration order, distinct
// from the sorted-key transport.
func LifecycleResumeOpenSigningBytes(r LifecycleResumeOpenRequest) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append([]byte("cengine.storageauthority.lifecycle-resume-open.v1\x00"), b...), nil
}

// VerifyLifecycleResumeOpen binds the takeover grant signature and the outer
// request signature to one copied ROOT pin. The original grant carries no
// signature of its own; the outer signature is its authentication. Launch/time
// checks are structural; callers must separately compare these signed values
// with their observed launch.
func VerifyLifecycleResumeOpen(root ed25519.PublicKey, signed SignedLifecycleResumeOpen) error {
	root = append(ed25519.PublicKey(nil), root...)
	if err := signed.Validate(); err != nil {
		return err
	}
	if len(root) != ed25519.PublicKeySize {
		return ErrUnauthorized
	}
	pin, err := PublicKeyFingerprint(root)
	if err != nil || pin == signed.Request.Takeover.Grant.NewKey || pin == signed.Request.Original.NewKey {
		return ErrUnauthorized
	}
	if err := verifyLifecycle(root, signed.Request.Takeover); err != nil {
		return err
	}
	msg, err := LifecycleResumeOpenSigningBytes(signed.Request)
	if err != nil {
		return err
	}
	if !ed25519.Verify(root, msg, signed.Signature) {
		return ErrUnauthorized
	}
	return nil
}

// ResumeOpenAndTakeover is reached through PID1's signed read-only admission
// and lease promotion gate. It accepts ONLY a strict closed empty layout (the freshly
// provisioned disk) or the exact original genesis registry this request would
// have created. It never formats, never calls FreshInitialization, and never
// manufactures a predecessor E. The empty layout publishes the successor as
// the ONE registry state: the synthetic genesis and the old original
// controller key never reach disk.
//
// Upstream precondition: the caller must own an exclusive read-only, no-replay
// clean-disk probe capability and run it BEFORE any write is allowed. The
// read-only census and this constructor's FD pin do NOT substitute for that
// capability on a shared or replayable device path; an exclusive device lock
// remains held by PID1 across worker construction and service lifetime.
func ResumeOpenAndTakeover(c Config, signed SignedLifecycleResumeOpen) (*Authority, error) {
	var err error
	c, err = configured(c)
	if err != nil {
		return nil, err
	}
	// Pin one duplicate of the caller's root BEFORE every probe. Signature
	// verification, the read-only census and the journal all derive their own
	// descriptors from this stable FD, so the caller cannot invalidate an open
	// in progress by closing or reusing c.Root. The journal re-dups it and owns
	// its copy; this pin is released when the constructor returns.
	pin, err := dupDirectory(c.Root)
	if err != nil {
		return nil, err
	}
	defer pin.Close()
	c.Root = pin
	// Own the signature slices before verification and request hashing.
	signed.Signature = append([]byte(nil), signed.Signature...)
	signed.Request.Takeover.Signature = append([]byte(nil), signed.Request.Takeover.Signature...)
	if err = VerifyLifecycleResumeOpen(c.BootstrapKey, signed); err != nil {
		return nil, err
	}
	r := signed.Request
	initial := lifecycleInitial{r.Original.Identity.Store, Controller{1, r.Original.NewKey}}
	return openAuthority(c, &initial, nil, &lifecycleOpen{identity: r.Original.Identity, initial: SignedLifecycleGrant{Grant: r.Original}, resume: &r})
}

type lifecycleResumeApplied struct {
	RequestSHA256 string `json:"request_sha256"`
	GrantID       ID     `json:"grant_id"`
	ServiceEpoch  ID     `json:"service_epoch"`
	OpenRevision  uint64 `json:"open_revision"`
}

func resumeRequestDigest(r LifecycleResumeOpenRequest) string {
	b, _ := LifecycleResumeOpenSigningBytes(r)
	return contentDigest(b)
}

// exactResumeGenesis reports whether s is byte-for-byte the registry this
// request's original initialize grant would have created: revision/open/
// latest = 1, original grant exact, controller epoch 1 under the original
// key, no retirement/cold/resume marker, no workload. Nil and empty maps are
// distinct exactly as validate requires (tables non-nil, v1 history and
// copy replay nil), and Copy carries only its empty Intents ledger.
func exactResumeGenesis(s *diskState, g LifecycleGrant) bool {
	want := &diskState{
		Schema:           LifecycleSchemaVersion,
		Durability:       durabilityVersion,
		Revision:         1,
		Store:            s.Store,
		Epoch:            s.Epoch,
		Controller:       Controller{1, g.NewKey},
		Bootstrap:        s.Bootstrap,
		ControllerKeys:   nil,
		Volumes:          map[ID]Volume{},
		VolumeLifecycles: map[ID]VolumeLifecycle{},
		Attachments:      map[ID]Attachment{},
		Prepares:         map[ID]Prepare{},
		Operations:       map[ID]operation{},
		Grants:           nil,
		Copy:             &copyState{Version: copySchemaVersion, Intents: map[ID]CopyIntent{}},
		CopyReplay:       nil,
		Lifecycle: &lifecycleState{
			Version:      LifecycleVersion,
			Identity:     g.Identity,
			Latest:       lifecycleApplied{g, s.Epoch, 1},
			OpenRevision: 1,
		},
	}
	return reflect.DeepEqual(s, want)
}

// admitResumeOpen is read-only and runs under the actual journal flock after
// full state validation and before any recovery, cleanup or commit. Only the
// exact original genesis registry is consumable; a partial, advanced,
// cold-consumed, workload-bearing or unknown registry refuses with every byte
// preserved.
func (a *Authority) admitResumeOpen(r LifecycleResumeOpenRequest) error {
	l := a.s.Lifecycle
	if m := l.ResumeApplied; m != nil {
		if m.RequestSHA256 == resumeRequestDigest(r) && l.Latest.Grant == r.Takeover.Grant {
			// An interrupted resume publication is NOT proven workload recovery.
			if err := a.j.lifecycleNamespaceClean(); err != nil {
				return err
			}
			return ErrLifecycleResumeAlreadyApplied
		}
		return ErrConflict
	}
	if !exactResumeGenesis(a.s, r.Original) {
		return ErrConflict
	}
	if a.keyUsed(r.Takeover.Grant.NewKey) {
		return ErrUnauthorized
	}
	return a.j.lifecycleNamespaceClean()
}

// resumeCensus is the closed top-level classification of a resume candidate
// root. The census is read-only and refuses any partial, stray or malformed
// entry before any mutation.
type resumeCensus int

const (
	// resumeCensusRegistry: a registry candidate exists; exact-genesis
	// admission under the journal flock decides whether it is consumable.
	resumeCensusRegistry resumeCensus = iota
	// resumeCensusEmpty: the strict closed empty layout with volumes present.
	resumeCensusEmpty
	// resumeCensusEmptyNoVolumes: the closed empty layout with volumes missing.
	// Fresh format can fail BEFORE the volumes mkdir; the directory is created
	// only after the read-only census and the request signature have fully
	// admitted the layout, immediately before the journal opens.
	resumeCensusEmptyNoVolumes
)

// probeResumeLayout reports the closed top-level classification of the target
// root. The top level may contain ONLY the registry and the pristine lost+found
// and volumes format artifacts, each optional except the registry deciding the
// branch. Every present artifact must be an empty real private directory owned
// by the euid on the root device. Accepting a minimal root here is NOT a
// substitute for the upstream fresh-format proof: the caller must still own
// the exclusive read-only, no-replay clean-disk probe capability.
func probeResumeLayout(root *os.File) (resumeCensus, error) {
	reg, err := child(root, registryName, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err == nil {
		reg.Close()
		if _, err := resumeClosedTopLevel(root, true); err != nil {
			return 0, err
		}
		return resumeCensusRegistry, nil
	}
	if !errors.Is(err, unix.ENOENT) {
		return 0, err
	}
	volumes, err := resumeClosedTopLevel(root, false)
	if err != nil {
		return 0, err
	}
	if volumes {
		return resumeCensusEmpty, nil
	}
	return resumeCensusEmptyNoVolumes, nil
}

// resumeClosedTopLevel censuses the top level of a resume candidate root. With
// registryPresent the registry entry is allowed and skipped: admission
// inspects it under the journal flock. It reports whether the volumes artifact
// is present.
func resumeClosedTopLevel(root *os.File, registryPresent bool) (bool, error) {
	fd, err := unix.Openat(int(root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	dir := os.NewFile(uintptr(fd), "resume-census")
	defer dir.Close()
	names, err := dir.Readdirnames(4)
	if err != nil && err != io.EOF {
		return false, err
	}
	// A full batch means at least four entries: registry, lost+found, volumes
	// and one stranger. A short final batch is complete on every platform
	// (some return io.EOF with it, some return nil).
	if len(names) == 4 {
		return false, ErrRepairRequired
	}
	seen := map[string]bool{}
	for _, name := range names {
		if (name != "lost+found" && name != "volumes" && !(registryPresent && name == registryName)) || seen[name] {
			return false, ErrRepairRequired
		}
		seen[name] = true
		if name != registryName {
			if err := resumeEmptyDir(root, name); err != nil {
				return false, err
			}
		}
	}
	return seen["volumes"], nil
}

// createResumeVolumes creates the missing volumes artifact of an admitted
// empty layout. It runs only after the read-only census and the request
// signature have fully admitted the layout, and before the journal creates the
// registry, so a failure here can leak one recoverable directory but never
// registry bytes.
func createResumeVolumes(root *os.File) error {
	if err := unix.Mkdirat(int(root.Fd()), "volumes", 0700); err != nil {
		return err
	}
	return root.Sync()
}

func resumeEmptyDir(root *os.File, name string) error {
	f, err := child(root, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	var st unix.Stat_t
	if err = unix.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	dev, err := identity(root)
	if err != nil {
		return err
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 || uint64(st.Dev) != dev.Device {
		return ErrInvalid
	}
	names, err := f.Readdirnames(1)
	if err != nil && err != io.EOF {
		return err
	}
	if len(names) != 0 {
		return ErrRepairRequired
	}
	return nil
}

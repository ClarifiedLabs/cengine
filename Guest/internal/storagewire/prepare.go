package storagewire

import (
	"bytes"
	"encoding/binary"
	"math"

	a "dev.cengine/guest/internal/storageauthority"
)

const OpPrepare Operation = "prepare"

type PrepareAction uint32

const (
	BeginCopy PrepareAction = iota + 1
	BindCopyTransaction
	IdentityAt
	SealManifest
	AuthenticateManifest
	FinishCopy
	StartCleanup
	RollbackCopy
	ResumeCopyDirectory
)

// PrepareRequest is a private, descriptor-rooted control operation on the
// existing authenticated DATA stream. Node/Handle are live session grants, not
// durable identity. Seal/Authenticate read the exact bounded manifest at the
// canonical server-side path; no manifest bytes or alternate pathname travel here.
type PrepareRequest struct {
	Node   NodeID        `json:"node"`
	Handle HandleID      `json:"handle"`
	Action PrepareAction `json:"action"`
	Intent a.ID          `json:"intent"`
	Path   []byte        `json:"path,omitempty"`
}

func (PrepareRequest) Operation() Operation { return OpPrepare }
func (PrepareRequest) requestBody()         {}

type PrepareReply struct {
	// Pending is an exact private replay action, not a phase-derived suggestion.
	// Zero means no actionable marker. Only Begin may return a pending action.
	Pending  PrepareAction  `json:"pending"`
	Intent   a.CopyIntent   `json:"intent"`
	Root     a.CopyRootV1   `json:"root"`
	Identity a.Ext4ObjectV1 `json:"identity"`
}

func (PrepareReply) Operation() Operation { return OpPrepare }
func (PrepareReply) replyBody()           {}

func validatePrepareRequest(r PrepareRequest) error {
	if r.Action < BeginCopy || r.Action > ResumeCopyDirectory {
		return invalid("prepare action")
	}
	if r.Action == BeginCopy {
		if r.Intent != "" {
			return invalid("begin intent")
		}
	} else if !validID(r.Intent) {
		return invalid("prepare intent")
	}
	if r.Action != IdentityAt {
		if len(r.Path) != 0 {
			return invalid("unexpected prepare path")
		}
		return nil
	}
	if len(r.Path) > MaxTarget {
		return invalid("prepare path bounds")
	}
	// Empty and dot denote the root itself; other operands are canonical and relative.
	if len(r.Path) == 0 || bytes.Equal(r.Path, []byte(".")) {
		return nil
	}
	for _, part := range bytes.Split(r.Path, []byte{'/'}) {
		if err := component(part); err != nil {
			return err
		}
	}
	return nil
}

func prepareIdentity(v a.Ext4ObjectV1) error {
	if v.Inode == 0 || v.Inode > math.MaxUint32 || v.HandleType != 1 || v.HandleSize != 8 ||
		v.FileType & ^uint32(0170000) != 0 || !fileType(v.FileType) ||
		uint64(binary.LittleEndian.Uint32(v.Handle[:4])) != v.Inode ||
		binary.LittleEndian.Uint32(v.Handle[4:]) != v.Generation {
		return invalid("ext4 identity v1")
	}
	return nil
}
func prepareRoot(v a.CopyRootV1) error {
	if !validID(v.Store) || !validID(v.Volume) || v.BackingUUID == ([16]byte{}) || v.Root.FileType != 0040000 {
		return invalid("copy root v1")
	}
	return prepareIdentity(v.Root)
}
func validatePrepareReply(v PrepareReply) error {
	if err := validatePreparePending(v); err != nil {
		return err
	}
	if v.Identity != (a.Ext4ObjectV1{}) {
		if err := prepareIdentity(v.Identity); err != nil {
			return err
		}
	}
	if v.Root != (a.CopyRootV1{}) {
		if err := prepareRoot(v.Root); err != nil {
			return err
		}
	}
	if v.Intent != (a.CopyIntent{}) {
		i := v.Intent
		if !validID(i.ID) || !validID(i.Epoch) || i.ManifestSize > a.MaxCopyManifestBytes {
			return invalid("copy intent")
		}
		switch i.Phase {
		case a.CopyBegun, a.CopyBound, a.CopySealed, a.CopyCleaning, a.CopyCompleted:
		default:
			return invalid("copy intent phase")
		}
		if err := (ClientHello{Authority: a.DataHello{Epoch: i.Epoch, Binding: i.Owner}, Profile: RequiredProfile()}).Validate(); err != nil {
			return err
		}
		if i.Owner.Role != a.PrepareRole || i.Owner.Mode != a.ReadWrite || i.Owner.Store != i.Root.Store || i.Owner.Volume != i.Root.Volume {
			return invalid("copy intent owner")
		}
		if err := prepareRoot(i.Root); err != nil {
			return err
		}
		if i.Transaction != (a.Ext4ObjectV1{}) {
			if i.Transaction.FileType != 0040000 {
				return invalid("copy transaction type")
			}
			if err := prepareIdentity(i.Transaction); err != nil {
				return err
			}
		}
		for _, metadata := range []a.CopyCleanupV1{i.Initial, i.Cleanup} {
			if metadata.ATimeNanos >= 1_000_000_000 || metadata.MTimeNanos >= 1_000_000_000 || metadata.Mode & ^uint32(07777) != 0 {
				return invalid("copy cleanup metadata")
			}
			for _, object := range []a.Ext4ObjectV1{metadata.Manifest, metadata.Staging} {
				if object != (a.Ext4ObjectV1{}) {
					if err := prepareIdentity(object); err != nil {
						return err
					}
				}
			}
		}
		if err := validatePrepareIntentState(i); err != nil {
			return err
		}
		if (i.ManifestSize == 0) != (i.ManifestDigest == ([32]byte{})) {
			return invalid("copy manifest digest/size")
		}
		if v.Root != (a.CopyRootV1{}) && v.Root != i.Root {
			return invalid("copy root disagreement")
		}
	}
	return nil
}

// ValidatePrepareReplyFor checks a decoded ioctl reply against its control request.
// It does not confer authority or substitute for authenticated DATA admission.
func ValidatePrepareReplyFor(r PrepareRequest, v PrepareReply) error {
	if err := validatePrepareRequest(r); err != nil {
		return err
	}
	if err := validatePrepareReply(v); err != nil {
		return err
	}
	if v.Pending != 0 && r.Action != BeginCopy {
		return invalid("pending action outside begin")
	}
	if v.Intent != (a.CopyIntent{}) && r.Action != BeginCopy && v.Intent.ID != r.Intent {
		return invalid("copy intent correlation")
	}
	switch r.Action {
	case BeginCopy:
		if v.Intent == (a.CopyIntent{}) || v.Root == (a.CopyRootV1{}) {
			return invalid("begin result")
		}
	case BindCopyTransaction:
		if v.Intent == (a.CopyIntent{}) || v.Intent.Transaction == (a.Ext4ObjectV1{}) {
			return invalid("bind result")
		}
	case RollbackCopy:
		if v.Intent == (a.CopyIntent{}) || v.Root != v.Intent.Root || v.Intent.Phase != a.CopyCleaning {
			return invalid("rollback result")
		}
	case ResumeCopyDirectory:
		if v.Intent == (a.CopyIntent{}) || v.Root != v.Intent.Root || (v.Intent.Phase != a.CopySealed && v.Intent.Phase != a.CopyCleaning && v.Intent.Phase != a.CopyCompleted) {
			return invalid("directory resume result")
		}
	case IdentityAt:
		if v.Identity == (a.Ext4ObjectV1{}) {
			return invalid("identity result")
		}
	}
	return nil
}

// ValidateBinding adds PREPARE-role restrictions to the mode policy. Binding
// MUST come from authenticated DATA admission. This is not itself a live guard
// or proof of the descriptor root; the server must enforce both independently.
func (r Request) ValidateBinding(binding a.Binding) error {
	if err := r.ValidatePolicy(binding.Mode); err != nil {
		return err
	}
	if r.Body.Operation() == OpPrepare && (binding.Role != a.PrepareRole || !validID(binding.Prepare)) {
		return a.ErrUnauthorized
	}
	return nil
}

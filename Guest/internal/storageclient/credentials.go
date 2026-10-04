package storageclient

import (
	"errors"
	"math"

	w "dev.cengine/guest/internal/storagewire"
)

var ErrCredentials = errors.New("storageclient: invalid or unavailable request credentials")
var ErrUnsupported = errors.New("storageclient: request credential ioctl unavailable")

// credentialHeader is the fixed, 64-byte experimental0002 ABI 3 layout.
// Groups is an aligned userspace address, never an identity or a process ID.
type credentialHeader struct {
	Version, Flags                  uint32
	Unique, Groups                  uint64
	GroupCount, FSUID, FSGID, State uint32
	Semantics, Effective, Valid     uint64
}
type credentialQuery func(fd int, h *credentialHeader, groups []uint32) error

// Snapshot is immutable and belongs to the Client that captured it. Its zero
// value is invalid, not NONE. It must be captured while Unique is unreplied on
// the exact /dev/fuse descriptor that delivered it; never use a PID lookup.
type Snapshot struct {
	owner          *Client
	valid, present bool
	caller         w.Caller
	semantics      w.MetadataSemantics
}

// SnapshotKind exposes provenance classification only, never a caller identity or
// a constructor. NONE and invalid must remain distinct at the FUSE adapter.
type SnapshotKind uint8

const (
	SnapshotInvalid SnapshotKind = iota
	SnapshotNone
	SnapshotPresent
)

// Kind is read-only classification. Do still validates the exact capturing Client
// and operation policy; this value alone grants no authority.
func (s Snapshot) Kind() SnapshotKind {
	if !s.valid || s.owner == nil {
		return SnapshotInvalid
	}
	if s.present {
		return SnapshotPresent
	}
	return SnapshotNone
}

// Capture synchronously performs both ABI queries before the adapter may reply
// to FUSE. The adapter must serialize capture against response/device closure.
// No ioctl error is converted to NONE. No credential is inferred from UID zero.
func (c *Client) Capture(deliveringFD int, unique uint64) (Snapshot, error) {
	return c.capture(nativeCredentialQuery, deliveringFD, unique)
}

func capture(query credentialQuery, fd int, unique, supported uint64) (Snapshot, error) {
	if fd < 0 || unique == 0 || supported == 0 {
		return Snapshot{}, ErrCredentials
	}
	first := credentialHeader{Version: w.CredentialABI, Unique: unique}
	if err := query(fd, &first, nil); err != nil {
		return Snapshot{}, errors.Join(ErrCredentials, err)
	}
	if !validHeader(first, unique, supported) {
		return Snapshot{}, ErrCredentials
	}
	groups := make([]uint32, first.GroupCount)
	second := credentialHeader{Version: w.CredentialABI, Unique: unique, GroupCount: first.GroupCount}
	if err := query(fd, &second, groups); err != nil {
		return Snapshot{}, errors.Join(ErrCredentials, err)
	}
	// The pointer is input/output plumbing, not part of the immutable identity.
	first.Groups, second.Groups = 0, 0
	if first != second || !validHeader(second, unique, supported) {
		return Snapshot{}, ErrCredentials
	}
	for _, g := range groups {
		if g == math.MaxUint32 {
			return Snapshot{}, ErrCredentials
		}
	}
	return Snapshot{valid: true, present: first.State == 1, semantics: w.MetadataSemantics(first.Semantics), caller: w.Caller{FSUID: first.FSUID, FSGID: first.FSGID, Groups: groups, EffectiveCaps: first.Effective}}, nil
}
func validHeader(h credentialHeader, unique, supported uint64) bool {
	if h.Version != w.CredentialABI || h.Unique != unique || h.Flags != 0 || h.Semantics & ^uint64(w.MetadataMask) != 0 || h.Semantics != 0 && h.Semantics&uint64(w.MetadataValid) == 0 || h.GroupCount > w.MaxGroups {
		return false
	}
	switch h.State {
	case 0:
		return h.FSUID == math.MaxUint32 && h.FSGID == math.MaxUint32 && h.GroupCount == 0 && h.Effective == 0 && h.Valid == 0 && h.Semantics == 0
	case 1:
		return h.FSUID != math.MaxUint32 && h.FSGID != math.MaxUint32 && h.Valid == supported && h.Effective & ^supported == 0
	}
	return false
}

func (c *Client) auth(s Snapshot, none w.AuthKind) (w.Auth, error) {
	if !s.valid || s.owner != c {
		return w.Auth{}, ErrCredentials
	}
	if s.present {
		if none != 0 {
			return w.Auth{}, ErrCredentials
		}
		caller := s.caller
		caller.Groups = append([]uint32{}, caller.Groups...)
		return w.Auth{Kind: w.CallerAuth, Caller: &caller}, nil
	}
	switch none {
	case w.OpenGrantAuth, w.NodeMetadataAuth, w.LifecycleAuth:
		return w.Auth{Kind: none}, nil
	}
	return w.Auth{}, ErrCredentials
}

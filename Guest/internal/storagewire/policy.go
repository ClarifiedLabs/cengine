package storagewire

import (
	"dev.cengine/guest/internal/storageauthority"
	"errors"
)

var ErrReadOnly = errors.New("storagewire read-only mutation")

type AuthKinds uint8

func (a AuthKinds) Allows(k AuthKind) bool {
	return k >= CallerAuth && k <= LifecycleAuth && a&(1<<k) != 0
}

type HandleRequirement uint8

const (
	NoHandle HandleRequirement = iota
	OptionalHandle
	RequiredHandle
)

type OperationPolicy struct {
	AuthKinds AuthKinds
	Handle    HandleRequirement
	Mutates   bool // Open additionally depends on flags; Access on W_OK.
}

const (
	callerKinds    AuthKinds = 1 << CallerAuth
	grantKinds     AuthKinds = callerKinds | 1<<OpenGrantAuth
	lifecycleKinds AuthKinds = 1 << LifecycleAuth
)

var policies = map[Operation]OperationPolicy{
	OpLookup:      {callerKinds, NoHandle, false},
	OpGetAttr:     {grantKinds | 1<<NodeMetadataAuth, OptionalHandle, false},
	OpSetAttr:     {callerKinds, OptionalHandle, true},
	OpCreate:      {callerKinds, NoHandle, true},
	OpOpen:        {callerKinds, NoHandle, false},
	OpRead:        {grantKinds, RequiredHandle, false},
	OpWrite:       {grantKinds, RequiredHandle, true},
	OpFlush:       {grantKinds, RequiredHandle, false},
	OpFsync:       {grantKinds, RequiredHandle, false},
	OpFsyncDir:    {grantKinds, RequiredHandle, false},
	OpRelease:     {lifecycleKinds, RequiredHandle, false},
	OpReleaseDir:  {lifecycleKinds, RequiredHandle, false},
	OpOpenDir:     {callerKinds, NoHandle, false},
	OpReadDir:     {grantKinds, RequiredHandle, false},
	OpMkdir:       {callerKinds, NoHandle, true},
	OpMknod:       {callerKinds, NoHandle, true},
	OpSymlink:     {callerKinds, NoHandle, true},
	OpReadlink:    {callerKinds, NoHandle, false},
	OpLink:        {callerKinds, NoHandle, true},
	OpRename:      {callerKinds, NoHandle, true},
	OpUnlink:      {callerKinds, NoHandle, true},
	OpRmdir:       {callerKinds, NoHandle, true},
	OpAccess:      {callerKinds, NoHandle, false},
	OpGetXAttr:    {callerKinds, NoHandle, false},
	OpListXAttr:   {callerKinds, NoHandle, false},
	OpSetXAttr:    {callerKinds, NoHandle, true},
	OpRemoveXAttr: {callerKinds, NoHandle, true},
	OpStatFS:      {callerKinds, NoHandle, false},
	OpForget:      {lifecycleKinds, NoHandle, false},
	OpFallocate:   {grantKinds, RequiredHandle, true},
	OpLseek:       {grantKinds, RequiredHandle, false},
}

// PolicyFor returns a copy, never a mutable policy table.
func PolicyFor(op Operation) (OperationPolicy, bool) {
	// Private sideband, separate from the frozen ordinary-filesystem table.
	// Even identity reads require the RW transaction fence and exact caller.
	if op == OpPrepare {
		return OperationPolicy{callerKinds, RequiredHandle, true}, true
	}
	p, ok := policies[op]
	return p, ok
}

// Mutates reports storage-mode restrictions, including write-open intent and
// W_OK access checks. Durability/lifecycle cleanup remains legal on RO sessions.
func (r Request) Mutates() bool {
	if !knownRequestBody(r.Body) {
		return true
	}
	p, ok := PolicyFor(r.Body.Operation())
	if !ok {
		return true
	}
	switch v := r.Body.(type) {
	case OpenRequest:
		return v.Flags&OpenAccessMask != OpenReadOnly || v.Flags&(OpenTruncate|OpenCreate) != 0
	case AccessRequest:
		return v.Mask&2 != 0
	}
	return p.Mutates
}

// ValidatePolicy must use the authenticated attachment mode, never request data.
// Passing validation is NOT an admission guard or proof of caller/grant origin.
func (r Request) ValidatePolicy(mode storageauthority.Mode) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if mode != storageauthority.ReadOnly && mode != storageauthority.ReadWrite {
		return invalid("attachment mode")
	}
	if mode == storageauthority.ReadOnly && r.Mutates() {
		return ErrReadOnly
	}
	return nil
}

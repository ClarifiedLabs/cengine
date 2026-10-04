// Package storagecontrol implements lifecycle and workload authenticated control
// transports. It does not listen, dial, or activate storage.
package storagecontrol

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
)

const MaxAggregate = 128 << 20

var (
	ErrConfiguration = errors.New("invalid storagecontrol configuration")
	ErrProtocol      = errors.New("invalid storagecontrol message")
	ErrLimit         = errors.New("storagecontrol capacity exhausted")
	ErrClosed        = errors.New("storagecontrol connection closed")
)

type Code string

const (
	Invalid        Code = "INVALID"
	Unauthorized   Code = "UNAUTHORIZED"
	Conflict       Code = "CONFLICT"
	Unknown        Code = "UNKNOWN"
	Blocked        Code = "BLOCKED"
	Limit          Code = "LIMIT"
	Busy           Code = "BUSY"
	Closed         Code = "CLOSED"
	Timeout        Code = "TIMEOUT"
	RepairRequired Code = "REPAIR_REQUIRED"
	Internal       Code = "INTERNAL"
)

// RemoteError intentionally contains no authority error text or filesystem paths.
type RemoteError struct{ Code Code }

func (e *RemoteError) Error() string { return "storagecontrol: " + string(e.Code) }
func errorCode(err error) Code {
	switch {
	case errors.Is(err, a.ErrUnauthorized):
		return Unauthorized
	case errors.Is(err, a.ErrInvalid), errors.Is(err, ErrProtocol):
		return Invalid
	case errors.Is(err, a.ErrConflict):
		return Conflict
	case errors.Is(err, a.ErrUnknown):
		return Unknown
	case errors.Is(err, a.ErrBlocked):
		return Blocked
	case errors.Is(err, a.ErrLimit), errors.Is(err, ErrLimit):
		return Limit
	case errors.Is(err, a.ErrBusy):
		return Busy
	case errors.Is(err, a.ErrClosed), errors.Is(err, ErrClosed):
		return Closed
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return Timeout
	case errors.Is(err, a.ErrRepairRequired), errors.Is(err, a.ErrCapacityInvariant):
		return RepairRequired
	default:
		return Internal
	}
}
func validCode(c Code) bool {
	switch c {
	case Invalid, Unauthorized, Conflict, Unknown, Blocked, Limit, Busy, Closed, Timeout, RepairRequired, Internal:
		return true
	}
	return false
}

type Role string

const (
	Controller Role = "CONTROLLER"
	Successor  Role = "SUCCESSOR"
)

type Hello struct {
	Version           int                  `json:"version"`
	Role              Role                 `json:"role"`
	ControllerEpoch   uint64               `json:"controller_epoch"`
	Store             a.ID                 `json:"store"`
	ServiceEpoch      a.ID                 `json:"service_epoch"`
	LifecycleIdentity *a.LifecycleIdentity `json:"lifecycle_identity,omitempty"`
}
type HelloReply struct {
	Version           int                  `json:"version"`
	Store             a.ID                 `json:"store"`
	ServiceEpoch      a.ID                 `json:"service_epoch"`
	Error             Code                 `json:"error,omitempty"`
	LifecycleIdentity *a.LifecycleIdentity `json:"lifecycle_identity,omitempty"`
}
type Empty struct{}

// Request is a closed union: exactly one operation must be present. ID is assigned
// by Client.Call; on the wire IDs start at 1 and advance by exactly one.
// AddVolume is deliberately absent: CreateVolume never adopts existing roots.
type Request struct {
	ID                 uint64                 `json:"id"`
	Query              *Empty                 `json:"query,omitempty"`
	ReservePrepare     *a.ReserveRequest      `json:"reserve_prepare,omitempty"`
	RegisterAttachment *a.RegisterRequest     `json:"register_attachment,omitempty"`
	Retire             *a.RetireRequest       `json:"retire,omitempty"`
	CompletePrepare    *a.CompleteRequest     `json:"complete_prepare,omitempty"`
	ReplacePrepare     *a.ReplaceRequest      `json:"replace_prepare,omitempty"`
	CreateVolume       *a.CreateVolumeRequest `json:"create_volume,omitempty"`
	DeleteVolume       *a.DeleteVolumeRequest `json:"delete_volume,omitempty"`
	// Decode-only legacy operation: lifecycle workload transport always refuses it.
	Takeover json.RawMessage `json:"takeover,omitempty"`
}

func (r Request) valid() bool {
	n := 0
	for _, present := range []bool{r.Query != nil, r.ReservePrepare != nil, r.RegisterAttachment != nil, r.Retire != nil, r.CompletePrepare != nil, r.ReplacePrepare != nil, r.CreateVolume != nil, r.DeleteVolume != nil, r.Takeover != nil} {
		if present {
			n++
		}
	}
	return r.ID != 0 && n == 1
}

type Response struct {
	ID            uint64           `json:"id"`
	Error         Code             `json:"error,omitempty"`
	OK            *Empty           `json:"ok,omitempty"`
	Snapshot      *a.Snapshot      `json:"snapshot,omitempty"`
	Receipt       *a.Receipt       `json:"receipt,omitempty"`
	VolumeReceipt *a.VolumeReceipt `json:"volume_receipt,omitempty"`
	Controller    *a.Controller    `json:"controller,omitempty"`
	// Present only beside a successful v3 Query snapshot; Snapshot deliberately
	// excludes the authority's private lifecycle journal state.
	LifecycleIdentity *a.LifecycleIdentity `json:"lifecycle_identity,omitempty"`
}

func (r Response) validForPolicy(q Request, policy workloadPolicy) bool {
	if r.ID != q.ID || (r.LifecycleIdentity != nil && (!policy.lifecycle() || q.Query == nil || r.Error != "")) {
		return false
	}
	n := 0
	for _, p := range []bool{r.OK != nil, r.Snapshot != nil, r.Receipt != nil, r.VolumeReceipt != nil, r.Controller != nil} {
		if p {
			n++
		}
	}
	if r.Error != "" {
		return validCode(r.Error) && n == 0
	}
	if n != 1 {
		return false
	}
	switch {
	case q.Query != nil:
		return policy.validSnapshot(r.Snapshot) && policy.matchesIdentity(r.LifecycleIdentity)
	case q.Retire != nil:
		v := r.Receipt
		return v != nil && v.Schema == a.SchemaVersion && v.Revision > 0 && v.Store == q.Retire.Store && v.Volume == q.Retire.Volume && v.Attachment == q.Retire.Attachment && v.Launch == q.Retire.Launch
	case q.CreateVolume != nil:
		v := r.VolumeReceipt
		return v != nil && v.Schema == a.SchemaVersion && v.Revision > 0 && v.Operation == q.CreateVolume.Operation && v.Store == q.CreateVolume.Store && v.Volume.ID == q.CreateVolume.Volume && v.Volume.Name == q.CreateVolume.Name && v.Phase == a.VolumeReady
	case q.DeleteVolume != nil:
		v := r.VolumeReceipt
		return v != nil && v.Schema == a.SchemaVersion && v.Revision > 0 && v.Operation == q.DeleteVolume.Operation && v.Store == q.DeleteVolume.Store && v.Volume.ID == q.DeleteVolume.Volume && v.Phase == a.VolumeDeleted
	case q.Takeover != nil:
		return false
	default:
		return r.OK != nil
	}
}

type Limits struct {
	Connections      int
	RequestBytes     int
	ResponseBytes    int
	HandshakeTimeout time.Duration
	// ReadTimeout bounds a server request from its first decrypted frame byte;
	// authenticated idle time is excluded. Clients bound each response in full.
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	OperationTimeout time.Duration
}

func DefaultLimits() Limits {
	return Limits{2, 1 << 20, 64 << 20, 10 * time.Second, 30 * time.Second, 10 * time.Second, 30 * time.Second}
}
func limits(l Limits) (Limits, error) {
	if l == (Limits{}) {
		l = DefaultLimits()
	}
	if l.Connections < 1 || l.Connections > 32 || l.RequestBytes < 1024 || l.RequestBytes > 2<<20 || l.ResponseBytes < 1024 || l.ResponseBytes > 64<<20 || l.HandshakeTimeout <= 0 || l.ReadTimeout <= 0 || l.WriteTimeout <= 0 || l.OperationTimeout <= 0 {
		return l, ErrConfiguration
	}
	return l, nil
}

// Private transport state, constructed only from immutable lifecycle PKI inputs.
type workloadServerConfig struct {
	TLS    *tls.Config
	Store  a.ID
	Limits Limits
}
type workloadClientConfig struct {
	ServerKey a.Fingerprint
	Hello     Hello
	Limits    Limits
}

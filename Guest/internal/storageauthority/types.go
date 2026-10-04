package storageauthority

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

// SchemaVersion is the current workload receipt/DATA contract version. It is
// distinct from LifecycleSchemaVersion, the authority registry envelope.
const SchemaVersion = 3

type ID string

func NewID() (ID, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return ID(fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])), nil
}
func validID(id ID) bool {
	s := string(id)
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' || s[14] != '4' {
		return false
	}
	if s[19] != '8' && s[19] != '9' && s[19] != 'a' && s[19] != 'b' {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ContainerID is the host cengine container identifier: exactly 64 lowercase
// hexadecimal characters. It is intentionally distinct from generation UUIDs.
// The host supplies it; this authority does not mint or reinterpret container IDs.
type ContainerID string

func validContainerID(id ContainerID) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

type Fingerprint string

func PublicKeyFingerprint(key any) (Fingerprint, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return Fingerprint(hex.EncodeToString(sum[:])), nil
}
func validKey(key Fingerprint) bool {
	b, err := hex.DecodeString(string(key))
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == string(key)
}

type Role string

const (
	PrepareRole Role = "prepare"
	RuntimeRole Role = "runtime"
)

type Mode string

const (
	ReadOnly  Mode = "read-only"
	ReadWrite Mode = "read-write"
)

type Phase string

const (
	Reserved Phase = "RESERVED"
	Active   Phase = "ACTIVE"
	Retiring Phase = "RETIRING"
	Drained  Phase = "DRAINED"
)

type PreparePhase string

const (
	Pending   PreparePhase = "PENDING"
	Completed PreparePhase = "COMPLETED"
	Replaced  PreparePhase = "REPLACED"
)

type RootIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}
type Store struct {
	ID       ID           `json:"id"`
	DeviceID string       `json:"device_id"`
	Root     RootIdentity `json:"root"`
	Exports  RootIdentity `json:"exports"`
}
type Volume struct {
	ID   ID           `json:"id"`
	Name string       `json:"name"`
	Root RootIdentity `json:"root"`
}
type Binding struct {
	Store      ID          `json:"store"`
	Volume     ID          `json:"volume"`
	Attachment ID          `json:"attachment"`
	Prepare    ID          `json:"prepare,omitempty"`
	Container  ContainerID `json:"container"`
	// Launch is a fresh, immutable UUIDv4 allocated for this shim launch. It is
	// not the host's composite process launch identity or the container ID.
	Launch ID          `json:"launch"`
	Key    Fingerprint `json:"key"`
	Role   Role        `json:"role"`
	Mode   Mode        `json:"mode"`
}
type Receipt struct {
	Schema     int    `json:"schema"`
	Store      ID     `json:"store"`
	Volume     ID     `json:"volume"`
	Attachment ID     `json:"attachment"`
	Launch     ID     `json:"launch"`
	Prepare    ID     `json:"prepare,omitempty"`
	Revision   uint64 `json:"revision"`
}
type Attachment struct {
	Binding    Binding  `json:"binding"`
	Phase      Phase    `json:"phase"`
	Receipt    *Receipt `json:"receipt,omitempty"`
	Retirement ID       `json:"retirement,omitempty"`
}
type Prepare struct {
	ID          ID           `json:"id"`
	Attachments []Binding    `json:"attachments"`
	Phase       PreparePhase `json:"phase"`
	Successor   ID           `json:"successor,omitempty"`
	Attestation *Attestation `json:"attestation,omitempty"`
	// Context is required in registry schema 4 (absent in schema 3): the exact service
	// epoch and controller that reserved this prepare. It lives only inside the
	// bounded prepare record, so Query attests every historical context still
	// owning a retained record without any separate unbounded history.
	Context *PrepareContext `json:"context,omitempty"`
}
type PrepareContext struct {
	ServiceEpoch    ID          `json:"service_epoch"`
	ControllerEpoch uint64      `json:"controller_epoch"`
	ControllerKey   Fingerprint `json:"controller_key"`
}
type Controller struct {
	Epoch uint64      `json:"epoch"`
	Key   Fingerprint `json:"key"`
}
type Limits struct {
	Volumes      int
	Attachments  int
	Prepares     int
	Operations   int
	InFlight     int
	JournalBytes int64
}

func DefaultLimits() Limits { return Limits{1024, 16384, 8192, 65536, 4096, 64 << 20} }

// Barrier must serialize with the filesystem namespace, synchronize the retained
// ext4 descriptors and close ALL attachment-owned handles/resources. It must not
// return while callbacks or writeback owners can mutate. root is borrowed for this
// call only. This includes roots/nodes/handles transferred from DupVolumeRoot
// requests to the server's attachment resource registry before Guard.Release.
// A plain syncfs is not this contract. No caller context is supplied.
type Barrier func(binding Binding, root *os.File) error

// Config takes an already-owned backing-root descriptor, never a pathname. The
// registry is a private sibling of the fixed "volumes" export, not inside it.
// DeviceID must be the independently verified backing-device UUID, not a path.
// BootstrapKey is a separately owned bootstrap signer, never the controller key.
type Config struct {
	Root         *os.File
	DeviceID     string
	BootstrapKey ed25519.PublicKey
	Barrier      Barrier
	Limits       Limits
	// CopyRecoveryPreflight is read-only, startup-only validation of whole-intent
	// DATA recovery evidence. root is borrowed; callbacks must not mutate or close it.
	// A missing callback refuses new-action replay before any startup mutation.
	CopyRecoveryPreflight func(root *os.File, deviceID string, action string, current CopyIntent) error
	// PrepareRetirementProof optionally proves root-only retained ownership under
	// the registry namespace gate. It runs without authority.mu, after request
	// drain and with barrier serialization held. root is borrowed. Invoke publish
	// synchronously, at most once, while holding the gate and return its result.
	// A clean false selects the ordinary barrier fence; any error is sticky.
	// A true result proves only that retrying the full barrier is safe, not drain.
	PrepareRetirementProof func(binding Binding, root *os.File, publish func() (bool, error)) (bool, error)
}
type lifecycleInitial struct {
	Store      ID
	Controller Controller
}

type ReserveRequest struct {
	Operation   ID        `json:"operation"`
	Prepare     ID        `json:"prepare"`
	Attachments []Binding `json:"attachments"`
}
type RegisterRequest struct {
	Operation ID      `json:"operation"`
	Binding   Binding `json:"binding"`
}
type VolumeRequest struct {
	Operation ID     `json:"operation"`
	Volume    Volume `json:"volume"`
}
type RetireRequest struct {
	Operation  ID `json:"operation"`
	Store      ID `json:"store"`
	Volume     ID `json:"volume"`
	Attachment ID `json:"attachment"`
	Launch     ID `json:"launch"`
}
type Attestation struct {
	Prepare     ID   `json:"prepare"`
	Succeeded   bool `json:"succeeded"`
	CleanCopyUp bool `json:"clean_copy_up"`
}
type CompleteRequest struct {
	Operation   ID          `json:"operation"`
	Prepare     ID          `json:"prepare"`
	Receipts    []Receipt   `json:"receipts"`
	Attestation Attestation `json:"attestation"`
}
type ReplaceRequest struct {
	Operation ID             `json:"operation"`
	Prepare   ID             `json:"prepare"`
	Receipts  []Receipt      `json:"receipts"`
	Successor ReserveRequest `json:"successor"`
}
type DataHello struct {
	Epoch   ID      `json:"epoch"`
	Binding Binding `json:"binding"`
}

var (
	ErrInvalid           = errors.New("invalid authority argument or state")
	ErrUnauthorized      = errors.New("unauthenticated or stale authority")
	ErrConflict          = errors.New("immutable identity or operation conflicts")
	ErrUnknown           = errors.New("unknown authority identity")
	ErrBlocked           = errors.New("authority is fenced or quarantined")
	ErrReadOnly          = errors.New("read-only attachment")
	ErrLimit             = errors.New("authority capacity exhausted; evidence retained")
	ErrCapacityInvariant = errors.New("reserved completion capacity invariant violated")
	ErrLocked            = errors.New("authority already exclusively owned")
	ErrMissing           = errors.New("existing authority state is missing")
	ErrRepairRequired    = errors.New("ambiguous or failed durable operation requires offline repair")
	ErrBusy              = errors.New("accepted work or retirement still owns resources")
	ErrClosed            = errors.New("authority closed")
)

// CreateVolumeRequest reserves a caller-journaled fresh V; roots are never supplied
// by the caller or adopted from an existing pathname.
type CreateVolumeRequest struct {
	Operation ID     `json:"operation"`
	Store     ID     `json:"store"`
	Volume    ID     `json:"volume"`
	Name      string `json:"name"`
}
type DeleteVolumeRequest struct {
	Operation ID `json:"operation"`
	Store     ID `json:"store"`
	Volume    ID `json:"volume"`
}
type VolumePhase string

const (
	VolumeCreating VolumePhase = "CREATING"
	VolumeReady    VolumePhase = "READY"
	VolumeDeleting VolumePhase = "DELETING"
	VolumeDeleted  VolumePhase = "DELETED"
)

// VolumeLifecycle retains both terminal results forever. Creating/deleting are
// durable reservations, NOT successful operation results or permission to adopt.
type VolumeLifecycle struct {
	Phase           VolumePhase `json:"phase"`
	Create          ID          `json:"create,omitempty"`
	Delete          ID          `json:"delete,omitempty"`
	CreatedRevision uint64      `json:"created_revision,omitempty"`
	DeletedRevision uint64      `json:"deleted_revision,omitempty"`
}
type VolumeReceipt struct {
	Schema    int         `json:"schema"`
	Operation ID          `json:"operation"`
	Store     ID          `json:"store"`
	Volume    Volume      `json:"volume"`
	Phase     VolumePhase `json:"phase"`
	Revision  uint64      `json:"revision"`
}

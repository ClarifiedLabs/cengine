// Package storagewire freezes the disabled managed FUSE/ext4 v4 data contract.
// It performs no transport setup, filesystem access, admission, or activation.
package storagewire

import (
	"dev.cengine/guest/internal/storageauthority"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const (
	Version       uint32 = 4
	CredentialABI uint32 = 3
	MaxFrame             = 1 << 20
	MaxHello             = 16 << 10
	MaxIO                = 128 << 10
	MaxXAttr             = 64 << 10
	MaxName              = 255
	MaxTarget            = 4095
	MaxGroups            = 65536
	MaxDirEntries        = 256
	MaxForget            = 256
	MaxDepth             = 16
	MaxLinuxErrno uint32 = 4095
	ErrnoERANGE   uint32 = 34
	ErrnoENOTTY   uint32 = 25 // Unknown application ioctls remain unsupported.
)

type NodeID uint64
type HandleID uint64
type ObjectID [16]byte

func (id ObjectID) MarshalJSON() ([]byte, error) { return json.Marshal(hex.EncodeToString(id[:])) }
func (id *ObjectID) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 16 || hex.EncodeToString(raw) != s {
		return fmt.Errorf("invalid object ID")
	}
	copy(id[:], raw)
	return nil
}

type Caller struct {
	FSUID         uint32   `json:"fsuid"`
	FSGID         uint32   `json:"fsgid"`
	Groups        []uint32 `json:"groups"`
	EffectiveCaps uint64   `json:"effective_caps"`
}
type AuthKind uint8

const (
	CallerAuth AuthKind = iota + 1
	OpenGrantAuth
	NodeMetadataAuth
	LifecycleAuth
)

type Auth struct {
	Kind   AuthKind `json:"kind"`
	Caller *Caller  `json:"caller,omitempty"`
}
type Timestamp struct {
	Seconds     int64  `json:"seconds"`
	Nanoseconds uint32 `json:"nanoseconds"`
}
type Attr struct {
	Ino       uint64    `json:"ino"`
	Size      uint64    `json:"size"`
	Blocks    uint64    `json:"blocks"`
	Mode      uint32    `json:"mode"`
	Nlink     uint32    `json:"nlink"`
	UID       uint32    `json:"uid"`
	GID       uint32    `json:"gid"`
	Rdev      uint64    `json:"rdev"`
	BlockSize uint32    `json:"block_size"`
	ATime     Timestamp `json:"atime"`
	MTime     Timestamp `json:"mtime"`
	CTime     Timestamp `json:"ctime"`
}
type Entry struct {
	Node       NodeID   `json:"node"`
	Generation uint64   `json:"generation"`
	Object     ObjectID `json:"object"`
	Attr       Attr     `json:"attr"`
}
type Opened struct {
	Handle HandleID `json:"handle"`
}
type DirEntry struct {
	Name       []byte `json:"name"`
	Ino        uint64 `json:"ino"`
	Mode       uint32 `json:"mode"`
	NextCookie uint64 `json:"next_cookie"`
}
type ForgetEntry struct {
	Node  NodeID `json:"node"`
	Count uint64 `json:"count"`
}
type FSStat struct {
	Blocks          uint64 `json:"blocks"`
	BlocksFree      uint64 `json:"blocks_free"`
	BlocksAvailable uint64 `json:"blocks_available"`
	Files           uint64 `json:"files"`
	FilesFree       uint64 `json:"files_free"`
	BlockSize       uint32 `json:"block_size"`
	NameLength      uint32 `json:"name_length"`
	FragmentSize    uint32 `json:"fragment_size"`
}

type Operation string

// Interfaces are sealed. Concrete bodies are values, never typed nil pointers.
type RequestBody interface {
	Operation() Operation
	requestBody()
}
type ReplyBody interface {
	Operation() Operation
	replyBody()
}
type Request struct {
	Sequence uint64
	Auth     Auth
	Body     RequestBody
}
type Reply struct {
	Sequence uint64
	Op       Operation
	Errno    uint32
	Body     ReplyBody
}

// XAttrSizeError is the only error body, permitted only for xattr ERANGE.
type XAttrSizeError struct {
	Size uint32 `json:"size"`
}

func (XAttrSizeError) Operation() Operation { return "" }
func (XAttrSizeError) replyBody()           {}

type Profile struct {
	PrepareIdentityV1  bool   `json:"prepare_identity_v1"`
	CredentialABI      uint32 `json:"credential_abi"`
	DefaultPermissions bool   `json:"default_permissions"`
	ACL                bool   `json:"acl"`
	CheckedCloseToOpen bool   `json:"checked_close_to_open"`
	NativeKernel       bool   `json:"native_kernel"`
	OpenGrants         bool   `json:"open_grants"`
	DontMask           bool   `json:"dont_mask"`
	HandleKillpriv     bool   `json:"handle_killpriv"`
	AtomicOTrunc       bool   `json:"atomic_o_trunc"`
	HandleKillprivV2   bool   `json:"handle_killpriv_v2"`
	WritebackCache     bool   `json:"writeback_cache"`
	Passthrough        bool   `json:"passthrough"`
	IDMapped           bool   `json:"idmapped"`
	ReadDirPlus        bool   `json:"readdirplus"`
	Reconnect          bool   `json:"reconnect"`
	MaxFrame           uint32 `json:"max_frame"`
	MaxIO              uint32 `json:"max_io"`
	MaxGroups          uint32 `json:"max_groups"`
	MaxXAttr           uint32 `json:"max_xattr"`
	MaxDirEntries      uint32 `json:"max_dir_entries"`
}

func RequiredProfile() Profile {
	return Profile{
		PrepareIdentityV1: true, CredentialABI: CredentialABI, DefaultPermissions: true, ACL: true,
		CheckedCloseToOpen: true, NativeKernel: true, OpenGrants: true, DontMask: true,
		MaxFrame: MaxFrame, MaxIO: MaxIO, MaxGroups: MaxGroups,
		MaxXAttr: MaxXAttr, MaxDirEntries: MaxDirEntries,
	}
}

type ServerHello struct {
	Epoch   storageauthority.ID `json:"epoch"`
	Version uint32              `json:"version"`
	Profile Profile             `json:"profile"`
}
type ClientHello struct {
	Authority storageauthority.DataHello `json:"authority"`
	Profile   Profile                    `json:"profile"`
}

// RootReply is emitted only after AuthenticateData AND admission of root setup.
type RootReply struct {
	Root Entry `json:"root"`
}
type EventKind string

const (
	InvalidateAttr  EventKind = "attr"
	InvalidateData  EventKind = "data"
	InvalidateEntry EventKind = "entry"
)

type Event struct {
	EventSequence uint64              `json:"event_sequence"`
	Volume        storageauthority.ID `json:"volume"`
	Object        ObjectID            `json:"object"`
	Parent        ObjectID            `json:"parent"`
	Kind          EventKind           `json:"kind"`
	Name          []byte              `json:"name"`
	Offset        uint64              `json:"offset"`
	Length        uint64              `json:"length"`
}

package protocol

const CEngineFSVersion = 2
const CEngineFSPort uint32 = 4101

type FSType string

const (
	FSRequest      FSType = "request"
	FSResponse     FSType = "response"
	FSInvalidation FSType = "invalidation"
)

type FSMessage struct {
	Version int             `json:"version"`
	Type    FSType          `json:"type"`
	Request *FSRequestBody  `json:"request,omitempty"`
	Reply   *FSResponseBody `json:"reply,omitempty"`
	Event   *FSInvalidationEvent `json:"event,omitempty"`
}

type FSRequestBody struct {
	ID       uint64 `json:"id"`
	Op       string `json:"op"`
	Volume   string `json:"volume,omitempty"`
	Token    string `json:"token,omitempty"`
	Node     uint64 `json:"node,omitempty"`
	Handle   uint64 `json:"handle,omitempty"`
	Name     string `json:"name,omitempty"`
	NewNode  uint64 `json:"newNode,omitempty"`
	NewName  string `json:"newName,omitempty"`
	Target   string `json:"target,omitempty"`
	Xattr    string `json:"xattr,omitempty"`
	Value    []byte `json:"value,omitempty"`
	Data     []byte `json:"data,omitempty"`
	Offset   int64  `json:"offset,omitempty"`
	Size     int64  `json:"size,omitempty"`
	ATimeNS  *int64 `json:"atimeNs,omitempty"`
	MTimeNS  *int64 `json:"mtimeNs,omitempty"`
	Mode     uint32 `json:"mode,omitempty"`
	UID      *uint32 `json:"uid,omitempty"`
	GID      *uint32 `json:"gid,omitempty"`
	Flags    uint32 `json:"flags,omitempty"`
	Lock     *FSLock `json:"lock,omitempty"`
}

type FSResponseBody struct {
	ID      uint64       `json:"id"`
	Errno   int          `json:"errno,omitempty"`
	Node    uint64       `json:"node,omitempty"`
	Handle  uint64       `json:"handle,omitempty"`
	Attr    *FSAttr      `json:"attr,omitempty"`
	Entries []FSDirEntry `json:"entries,omitempty"`
	Data    []byte       `json:"data,omitempty"`
	Names   []string     `json:"names,omitempty"`
	StatFS  *FSStatFS    `json:"statfs,omitempty"`
	Lock    *FSLock      `json:"lock,omitempty"`
	Offset  int64        `json:"offset,omitempty"`
}

type FSInvalidationEvent struct {
	Node   uint64 `json:"node,omitempty"`
	Parent uint64 `json:"parent,omitempty"`
	Name   string `json:"name,omitempty"`
}

type FSAttr struct {
	Ino     uint64 `json:"ino"`
	Size    uint64 `json:"size"`
	Blocks  uint64 `json:"blocks"`
	ATimeNS int64  `json:"atimeNs"`
	MTimeNS int64  `json:"mtimeNs"`
	CTimeNS int64  `json:"ctimeNs"`
	Mode    uint32 `json:"mode"`
	Nlink   uint32 `json:"nlink"`
	UID     uint32 `json:"uid"`
	GID     uint32 `json:"gid"`
	Rdev    uint64 `json:"rdev"`
	Blksize uint32 `json:"blksize"`
}

type FSDirEntry struct {
	Name string `json:"name"`
	Node uint64 `json:"node"`
	Mode uint32 `json:"mode"`
}

type FSStatFS struct {
	Blocks  uint64 `json:"blocks"`
	Bfree   uint64 `json:"bfree"`
	Bavail  uint64 `json:"bavail"`
	Files   uint64 `json:"files"`
	Ffree   uint64 `json:"ffree"`
	Bsize   uint32 `json:"bsize"`
	Namelen uint32 `json:"namelen"`
	Frsize  uint32 `json:"frsize"`
}

type FSLock struct {
	Type  int16  `json:"type"`
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
	PID   uint32 `json:"pid"`
}

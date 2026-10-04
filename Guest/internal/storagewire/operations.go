package storagewire

const (
	OpLookup      Operation = "lookup"
	OpGetAttr     Operation = "get_attr"
	OpSetAttr     Operation = "set_attr"
	OpCreate      Operation = "create"
	OpOpen        Operation = "open"
	OpRead        Operation = "read"
	OpWrite       Operation = "write"
	OpFlush       Operation = "flush"
	OpFsync       Operation = "fsync"
	OpFsyncDir    Operation = "fsync_dir"
	OpRelease     Operation = "release"
	OpReleaseDir  Operation = "release_dir"
	OpOpenDir     Operation = "open_dir"
	OpReadDir     Operation = "read_dir"
	OpMkdir       Operation = "mkdir"
	OpMknod       Operation = "mknod"
	OpSymlink     Operation = "symlink"
	OpReadlink    Operation = "readlink"
	OpLink        Operation = "link"
	OpRename      Operation = "rename"
	OpUnlink      Operation = "unlink"
	OpRmdir       Operation = "rmdir"
	OpAccess      Operation = "access"
	OpGetXAttr    Operation = "get_xattr"
	OpListXAttr   Operation = "list_xattr"
	OpSetXAttr    Operation = "set_xattr"
	OpRemoveXAttr Operation = "remove_xattr"
	OpStatFS      Operation = "stat_fs"
	OpForget      Operation = "forget"
	OpFallocate   Operation = "fallocate"
	OpLseek       Operation = "lseek"
)

type LookupRequest struct {
	Parent NodeID `json:"parent"`
	Name   []byte `json:"name"`
}

func (LookupRequest) Operation() Operation { return OpLookup }
func (LookupRequest) requestBody()         {}

type LookupReply struct {
	Entry Entry `json:"entry"`
}

func (LookupReply) Operation() Operation { return OpLookup }
func (LookupReply) replyBody()           {}

type GetAttrRequest struct {
	Node   NodeID    `json:"node"`
	Handle *HandleID `json:"handle,omitempty"`
}

func (GetAttrRequest) Operation() Operation { return OpGetAttr }
func (GetAttrRequest) requestBody()         {}

type GetAttrReply struct {
	Attr Attr `json:"attr"`
}

func (GetAttrReply) Operation() Operation { return OpGetAttr }
func (GetAttrReply) replyBody()           {}

type SetAttrRequest struct {
	Semantics   MetadataSemantics `json:"semantics"`
	Node        NodeID            `json:"node"`
	Handle      *HandleID         `json:"handle,omitempty"`
	Valid       uint32            `json:"valid"`
	Mode        uint32            `json:"mode"`
	UID         uint32            `json:"uid"`
	GID         uint32            `json:"gid"`
	Size        uint64            `json:"size"`
	ATime       Timestamp         `json:"atime"`
	MTime       Timestamp         `json:"mtime"`
	KillSUIDGID bool              `json:"kill_suidgid"`
}

func (SetAttrRequest) Operation() Operation { return OpSetAttr }
func (SetAttrRequest) requestBody()         {}

type SetAttrReply struct {
	Attr Attr `json:"attr"`
}

func (SetAttrReply) Operation() Operation { return OpSetAttr }
func (SetAttrReply) replyBody()           {}

type CreateRequest struct {
	Parent        NodeID `json:"parent"`
	Name          []byte `json:"name"`
	Flags         uint32 `json:"flags"`
	FuseOpenFlags uint32 `json:"fuse_open_flags"`
	Mode          uint32 `json:"mode"`
	Umask         uint32 `json:"umask"`
}

func (CreateRequest) Operation() Operation { return OpCreate }
func (CreateRequest) requestBody()         {}

type CreateReply struct {
	Entry  Entry  `json:"entry"`
	Opened Opened `json:"opened"`
}

func (CreateReply) Operation() Operation { return OpCreate }
func (CreateReply) replyBody()           {}

type OpenRequest struct {
	Node          NodeID `json:"node"`
	Flags         uint32 `json:"flags"`
	FuseOpenFlags uint32 `json:"fuse_open_flags"`
}

func (OpenRequest) Operation() Operation { return OpOpen }
func (OpenRequest) requestBody()         {}

type OpenReply struct {
	Opened Opened `json:"opened"`
}

func (OpenReply) Operation() Operation { return OpOpen }
func (OpenReply) replyBody()           {}

type ReadRequest struct {
	Node    NodeID   `json:"node"`
	Handle  HandleID `json:"handle"`
	Offset  uint64   `json:"offset"`
	Size    uint32   `json:"size"`
	IOFlags uint32   `json:"io_flags"`
}

func (ReadRequest) Operation() Operation { return OpRead }
func (ReadRequest) requestBody()         {}

type ReadReply struct {
	Data []byte `json:"data"`
}

func (ReadReply) Operation() Operation { return OpRead }
func (ReadReply) replyBody()           {}

type WriteRequest struct {
	Node       NodeID   `json:"node"`
	Handle     HandleID `json:"handle"`
	Offset     uint64   `json:"offset"`
	IOFlags    uint32   `json:"io_flags"`
	WriteFlags uint32   `json:"write_flags"`
	Data       []byte   `json:"data"`
}

func (WriteRequest) Operation() Operation { return OpWrite }
func (WriteRequest) requestBody()         {}

type WriteReply struct {
	Written uint32 `json:"written"`
}

func (WriteReply) Operation() Operation { return OpWrite }
func (WriteReply) replyBody()           {}

type FlushRequest struct {
	Node   NodeID   `json:"node"`
	Handle HandleID `json:"handle"`
}

func (FlushRequest) Operation() Operation { return OpFlush }
func (FlushRequest) requestBody()         {}

type FlushReply struct {
}

func (FlushReply) Operation() Operation { return OpFlush }
func (FlushReply) replyBody()           {}

type FsyncRequest struct {
	Node     NodeID   `json:"node"`
	Handle   HandleID `json:"handle"`
	DataOnly bool     `json:"data_only"`
}

func (FsyncRequest) Operation() Operation { return OpFsync }
func (FsyncRequest) requestBody()         {}

type FsyncReply struct {
}

func (FsyncReply) Operation() Operation { return OpFsync }
func (FsyncReply) replyBody()           {}

type FsyncDirRequest struct {
	Node     NodeID   `json:"node"`
	Handle   HandleID `json:"handle"`
	DataOnly bool     `json:"data_only"`
}

func (FsyncDirRequest) Operation() Operation { return OpFsyncDir }
func (FsyncDirRequest) requestBody()         {}

type FsyncDirReply struct {
}

func (FsyncDirReply) Operation() Operation { return OpFsyncDir }
func (FsyncDirReply) replyBody()           {}

type ReleaseRequest struct {
	Node         NodeID   `json:"node"`
	Handle       HandleID `json:"handle"`
	ReleaseFlags uint32   `json:"release_flags"`
}

func (ReleaseRequest) Operation() Operation { return OpRelease }
func (ReleaseRequest) requestBody()         {}

type ReleaseReply struct {
}

func (ReleaseReply) Operation() Operation { return OpRelease }
func (ReleaseReply) replyBody()           {}

type ReleaseDirRequest struct {
	Node         NodeID   `json:"node"`
	Handle       HandleID `json:"handle"`
	ReleaseFlags uint32   `json:"release_flags"`
}

func (ReleaseDirRequest) Operation() Operation { return OpReleaseDir }
func (ReleaseDirRequest) requestBody()         {}

type ReleaseDirReply struct {
}

func (ReleaseDirReply) Operation() Operation { return OpReleaseDir }
func (ReleaseDirReply) replyBody()           {}

type OpenDirRequest struct {
	Node  NodeID `json:"node"`
	Flags uint32 `json:"flags"`
}

func (OpenDirRequest) Operation() Operation { return OpOpenDir }
func (OpenDirRequest) requestBody()         {}

type OpenDirReply struct {
	Opened Opened `json:"opened"`
}

func (OpenDirReply) Operation() Operation { return OpOpenDir }
func (OpenDirReply) replyBody()           {}

type ReadDirRequest struct {
	Node     NodeID   `json:"node"`
	Handle   HandleID `json:"handle"`
	Cookie   uint64   `json:"cookie"`
	MaxBytes uint32   `json:"max_bytes"`
}

func (ReadDirRequest) Operation() Operation { return OpReadDir }
func (ReadDirRequest) requestBody()         {}

type ReadDirReply struct {
	Entries []DirEntry `json:"entries"`
}

func (ReadDirReply) Operation() Operation { return OpReadDir }
func (ReadDirReply) replyBody()           {}

type MkdirRequest struct {
	Parent NodeID `json:"parent"`
	Name   []byte `json:"name"`
	Mode   uint32 `json:"mode"`
	Umask  uint32 `json:"umask"`
}

func (MkdirRequest) Operation() Operation { return OpMkdir }
func (MkdirRequest) requestBody()         {}

type MkdirReply struct {
	Entry Entry `json:"entry"`
}

func (MkdirReply) Operation() Operation { return OpMkdir }
func (MkdirReply) replyBody()           {}

type MknodRequest struct {
	Parent NodeID `json:"parent"`
	Name   []byte `json:"name"`
	Mode   uint32 `json:"mode"`
	Umask  uint32 `json:"umask"`
	Rdev   uint64 `json:"rdev"`
}

func (MknodRequest) Operation() Operation { return OpMknod }
func (MknodRequest) requestBody()         {}

type MknodReply struct {
	Entry Entry `json:"entry"`
}

func (MknodReply) Operation() Operation { return OpMknod }
func (MknodReply) replyBody()           {}

type SymlinkRequest struct {
	Parent NodeID `json:"parent"`
	Name   []byte `json:"name"`
	Target []byte `json:"target"`
}

func (SymlinkRequest) Operation() Operation { return OpSymlink }
func (SymlinkRequest) requestBody()         {}

type SymlinkReply struct {
	Entry Entry `json:"entry"`
}

func (SymlinkReply) Operation() Operation { return OpSymlink }
func (SymlinkReply) replyBody()           {}

type ReadlinkRequest struct {
	Node NodeID `json:"node"`
}

func (ReadlinkRequest) Operation() Operation { return OpReadlink }
func (ReadlinkRequest) requestBody()         {}

type ReadlinkReply struct {
	Target []byte `json:"target"`
}

func (ReadlinkReply) Operation() Operation { return OpReadlink }
func (ReadlinkReply) replyBody()           {}

type LinkRequest struct {
	Source NodeID `json:"source"`
	Parent NodeID `json:"parent"`
	Name   []byte `json:"name"`
}

func (LinkRequest) Operation() Operation { return OpLink }
func (LinkRequest) requestBody()         {}

type LinkReply struct {
	Entry Entry `json:"entry"`
}

func (LinkReply) Operation() Operation { return OpLink }
func (LinkReply) replyBody()           {}

type RenameRequest struct {
	OldParent NodeID `json:"old_parent"`
	NewParent NodeID `json:"new_parent"`
	OldName   []byte `json:"old_name"`
	NewName   []byte `json:"new_name"`
	Flags     uint32 `json:"flags"`
}

func (RenameRequest) Operation() Operation { return OpRename }
func (RenameRequest) requestBody()         {}

type RenameReply struct {
}

func (RenameReply) Operation() Operation { return OpRename }
func (RenameReply) replyBody()           {}

type UnlinkRequest struct {
	Parent NodeID `json:"parent"`
	Name   []byte `json:"name"`
}

func (UnlinkRequest) Operation() Operation { return OpUnlink }
func (UnlinkRequest) requestBody()         {}

type UnlinkReply struct {
}

func (UnlinkReply) Operation() Operation { return OpUnlink }
func (UnlinkReply) replyBody()           {}

type RmdirRequest struct {
	Parent NodeID `json:"parent"`
	Name   []byte `json:"name"`
}

func (RmdirRequest) Operation() Operation { return OpRmdir }
func (RmdirRequest) requestBody()         {}

type RmdirReply struct {
}

func (RmdirReply) Operation() Operation { return OpRmdir }
func (RmdirReply) replyBody()           {}

type AccessRequest struct {
	Node NodeID `json:"node"`
	Mask uint32 `json:"mask"`
}

func (AccessRequest) Operation() Operation { return OpAccess }
func (AccessRequest) requestBody()         {}

type AccessReply struct {
}

func (AccessReply) Operation() Operation { return OpAccess }
func (AccessReply) replyBody()           {}

type GetXAttrRequest struct {
	Node NodeID `json:"node"`
	Name []byte `json:"name"`
	Size uint32 `json:"size"`
}

func (GetXAttrRequest) Operation() Operation { return OpGetXAttr }
func (GetXAttrRequest) requestBody()         {}

type GetXAttrReply struct {
	Size  uint32 `json:"size"`
	Value []byte `json:"value"`
}

func (GetXAttrReply) Operation() Operation { return OpGetXAttr }
func (GetXAttrReply) replyBody()           {}

type ListXAttrRequest struct {
	Node NodeID `json:"node"`
	Size uint32 `json:"size"`
}

func (ListXAttrRequest) Operation() Operation { return OpListXAttr }
func (ListXAttrRequest) requestBody()         {}

type ListXAttrReply struct {
	Size  uint32 `json:"size"`
	Names []byte `json:"names"`
}

func (ListXAttrReply) Operation() Operation { return OpListXAttr }
func (ListXAttrReply) replyBody()           {}

type SetXAttrRequest struct {
	Node  NodeID `json:"node"`
	Name  []byte `json:"name"`
	Value []byte `json:"value"`
	Flags uint32 `json:"flags"`
}

func (SetXAttrRequest) Operation() Operation { return OpSetXAttr }
func (SetXAttrRequest) requestBody()         {}

type SetXAttrReply struct {
}

func (SetXAttrReply) Operation() Operation { return OpSetXAttr }
func (SetXAttrReply) replyBody()           {}

type RemoveXAttrRequest struct {
	Node NodeID `json:"node"`
	Name []byte `json:"name"`
}

func (RemoveXAttrRequest) Operation() Operation { return OpRemoveXAttr }
func (RemoveXAttrRequest) requestBody()         {}

type RemoveXAttrReply struct {
}

func (RemoveXAttrReply) Operation() Operation { return OpRemoveXAttr }
func (RemoveXAttrReply) replyBody()           {}

type StatFSRequest struct {
	Node NodeID `json:"node"`
}

func (StatFSRequest) Operation() Operation { return OpStatFS }
func (StatFSRequest) requestBody()         {}

type StatFSReply struct {
	Stat FSStat `json:"stat"`
}

func (StatFSReply) Operation() Operation { return OpStatFS }
func (StatFSReply) replyBody()           {}

type ForgetRequest struct {
	Entries []ForgetEntry `json:"entries"`
}

func (ForgetRequest) Operation() Operation { return OpForget }
func (ForgetRequest) requestBody()         {}

type ForgetReply struct {
}

func (ForgetReply) Operation() Operation { return OpForget }
func (ForgetReply) replyBody()           {}

type FallocateRequest struct {
	Node   NodeID   `json:"node"`
	Handle HandleID `json:"handle"`
	Offset uint64   `json:"offset"`
	Length uint64   `json:"length"`
	Mode   uint32   `json:"mode"`
}

func (FallocateRequest) Operation() Operation { return OpFallocate }
func (FallocateRequest) requestBody()         {}

type FallocateReply struct {
}

func (FallocateReply) Operation() Operation { return OpFallocate }
func (FallocateReply) replyBody()           {}

type LseekRequest struct {
	Node   NodeID   `json:"node"`
	Handle HandleID `json:"handle"`
	Offset uint64   `json:"offset"`
	Whence uint32   `json:"whence"`
}

func (LseekRequest) Operation() Operation { return OpLseek }
func (LseekRequest) requestBody()         {}

type LseekReply struct {
	Offset uint64 `json:"offset"`
}

func (LseekReply) Operation() Operation { return OpLseek }
func (LseekReply) replyBody()           {}

func decodeRequestBody(op Operation, raw []byte) (RequestBody, error) {
	switch op {
	case OpPrepare:
		var v PrepareRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpLookup:
		var v LookupRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpGetAttr:
		var v GetAttrRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpSetAttr:
		var v SetAttrRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpCreate:
		var v CreateRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpOpen:
		var v OpenRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpRead:
		var v ReadRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpWrite:
		var v WriteRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpFlush:
		var v FlushRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpFsync:
		var v FsyncRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpFsyncDir:
		var v FsyncDirRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpRelease:
		var v ReleaseRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpReleaseDir:
		var v ReleaseDirRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpOpenDir:
		var v OpenDirRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpReadDir:
		var v ReadDirRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpMkdir:
		var v MkdirRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpMknod:
		var v MknodRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpSymlink:
		var v SymlinkRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpReadlink:
		var v ReadlinkRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpLink:
		var v LinkRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpRename:
		var v RenameRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpUnlink:
		var v UnlinkRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpRmdir:
		var v RmdirRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpAccess:
		var v AccessRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpGetXAttr:
		var v GetXAttrRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpListXAttr:
		var v ListXAttrRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpSetXAttr:
		var v SetXAttrRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpRemoveXAttr:
		var v RemoveXAttrRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpStatFS:
		var v StatFSRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpForget:
		var v ForgetRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpFallocate:
		var v FallocateRequest
		err := strictDecode(raw, &v)
		return v, err
	case OpLseek:
		var v LseekRequest
		err := strictDecode(raw, &v)
		return v, err
	default:
		return nil, invalid("unknown operation")
	}
}
func decodeReplyBody(op Operation, raw []byte) (ReplyBody, error) {
	switch op {
	case OpPrepare:
		var v PrepareReply
		err := strictDecode(raw, &v)
		return v, err
	case OpLookup:
		var v LookupReply
		err := strictDecode(raw, &v)
		return v, err
	case OpGetAttr:
		var v GetAttrReply
		err := strictDecode(raw, &v)
		return v, err
	case OpSetAttr:
		var v SetAttrReply
		err := strictDecode(raw, &v)
		return v, err
	case OpCreate:
		var v CreateReply
		err := strictDecode(raw, &v)
		return v, err
	case OpOpen:
		var v OpenReply
		err := strictDecode(raw, &v)
		return v, err
	case OpRead:
		var v ReadReply
		err := strictDecode(raw, &v)
		return v, err
	case OpWrite:
		var v WriteReply
		err := strictDecode(raw, &v)
		return v, err
	case OpFlush:
		var v FlushReply
		err := strictDecode(raw, &v)
		return v, err
	case OpFsync:
		var v FsyncReply
		err := strictDecode(raw, &v)
		return v, err
	case OpFsyncDir:
		var v FsyncDirReply
		err := strictDecode(raw, &v)
		return v, err
	case OpRelease:
		var v ReleaseReply
		err := strictDecode(raw, &v)
		return v, err
	case OpReleaseDir:
		var v ReleaseDirReply
		err := strictDecode(raw, &v)
		return v, err
	case OpOpenDir:
		var v OpenDirReply
		err := strictDecode(raw, &v)
		return v, err
	case OpReadDir:
		var v ReadDirReply
		err := strictDecode(raw, &v)
		return v, err
	case OpMkdir:
		var v MkdirReply
		err := strictDecode(raw, &v)
		return v, err
	case OpMknod:
		var v MknodReply
		err := strictDecode(raw, &v)
		return v, err
	case OpSymlink:
		var v SymlinkReply
		err := strictDecode(raw, &v)
		return v, err
	case OpReadlink:
		var v ReadlinkReply
		err := strictDecode(raw, &v)
		return v, err
	case OpLink:
		var v LinkReply
		err := strictDecode(raw, &v)
		return v, err
	case OpRename:
		var v RenameReply
		err := strictDecode(raw, &v)
		return v, err
	case OpUnlink:
		var v UnlinkReply
		err := strictDecode(raw, &v)
		return v, err
	case OpRmdir:
		var v RmdirReply
		err := strictDecode(raw, &v)
		return v, err
	case OpAccess:
		var v AccessReply
		err := strictDecode(raw, &v)
		return v, err
	case OpGetXAttr:
		var v GetXAttrReply
		err := strictDecode(raw, &v)
		return v, err
	case OpListXAttr:
		var v ListXAttrReply
		err := strictDecode(raw, &v)
		return v, err
	case OpSetXAttr:
		var v SetXAttrReply
		err := strictDecode(raw, &v)
		return v, err
	case OpRemoveXAttr:
		var v RemoveXAttrReply
		err := strictDecode(raw, &v)
		return v, err
	case OpStatFS:
		var v StatFSReply
		err := strictDecode(raw, &v)
		return v, err
	case OpForget:
		var v ForgetReply
		err := strictDecode(raw, &v)
		return v, err
	case OpFallocate:
		var v FallocateReply
		err := strictDecode(raw, &v)
		return v, err
	case OpLseek:
		var v LseekReply
		err := strictDecode(raw, &v)
		return v, err
	default:
		return nil, invalid("unknown operation")
	}
}

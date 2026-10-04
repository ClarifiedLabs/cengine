# Managed storage DATA wire v4

This package defines the DATA contract used by the managed FUSE client and ext4
server. It imports `storageauthority` identities/`DataHello` rather than defining
parallel identities.
No go-fuse, host syscall structures, or Unix types occur in its public DTOs.

Source metadata authority: `Configuration/kernel-patches/README.md`, frozen ABI3
managed implicit-killpriv and storage-session contract (experimental 0002 only).
See [`docs/storage-generation-drain.md`](../../../docs/storage-generation-drain.md)
for the service contract. Profile validation is not proof of kernel behavior;
mounted verification requires the matching managed kernel.

## PREPARE identity sideband (v4)

`RequiredProfile().PrepareIdentityV1` is mandatory; v3 and missing capability
handshakes fail closed. Ordinary filesystem routing and credential ABI 3 remain
unchanged. `OpPrepare` carries `PrepareRequest{Node, Handle, Action, Intent, Path}`
and returns `PrepareReply{Pending, Intent, Root, Identity}`. Actions are numeric:
`BeginCopy=1`, `BindCopyTransaction=2`, `IdentityAt=3`, `SealManifest=4`,
`AuthenticateManifest=5`, `FinishCopy=6`, `StartCleanup=7`, `RollbackCopy=8`,
`ResumeCopyDirectory=9`. Only Begin may return a nonzero Pending action; it
identifies an exact private recovery action, not a phase-derived suggestion.
Rollback returns a CLEANING intent; directory resume returns a SEALED, CLEANING
or COMPLETED intent with its matching root.

All actions require exact caller capture, RW PREPARE binding, and an actual live
root directory handle. `Request.ValidateBinding` checks mode/role policy; the
server must additionally enforce its current live guard, physical-root binding,
and transaction-long fence. Begin has no intent ID; subsequent actions require
one. Only IdentityAt may carry Path: a bounded canonical relative byte path,
with empty Path or `.` denoting the root. Seal/Authenticate transfer **no manifest
bytes**: the server reads exact bounded bytes from
`.cengine-copyup-transaction/manifest.json` beneath its authority-derived root.
Begin returns Intent+Root; Bind returns updated Intent; IdentityAt returns
Identity. Other result fields may be zero; nonzero values are validated and
correlated. Durable ext4 identity never changes normal FUSE IDs/generations.

The private Linux arm64/amd64 ioctl is `PrepareIoctl = 0xe000ce41`, with exactly
`PrepareIoctlSize = 8192` input **and** output bytes. Exported helpers:

```go
EncodePrepareIoctl(PrepareRequest) ([]byte, error)
DecodePrepareIoctl([]byte) (PrepareRequest, error)
EncodePrepareIoctlReply(PrepareReply) ([]byte, error)
DecodePrepareIoctlReply([]byte) (PrepareReply, error)
ValidatePrepareReplyFor(PrepareRequest, PrepareReply) error
```

At this ioctl boundary, Node/Handle must be **zero**. The adapter derives routing
only from kernel local node 1 and the actual local directory handle grant. Wire
DATA requests instead contain nonzero server tokens. The little-endian 16-byte
header contains four uint32 fields: ABI version 1, operation (1=request,
2=reply), JSON byte length, reserved zero. Strict JSON occupies the selected
length; every remaining buffer byte must be zero. All identity byte arrays have
exact numeric-array lengths. Only FUSE IOCTL_DIR is accepted, never compat,
unrestricted or retry. Success clears all IoctlOut flags/iov counts and emits the
complete fixed buffer. Other application ioctls retain ENOTTY after credential
capture. No process lookup, ioctl-supplied identity, or opener credentials confer
authority.

## Exact codec and validation interface

```go
type Message interface { Validate() error; /* package-private seal */ }
func Marshal(Message) ([]byte, error)
func Unmarshal([]byte, Message) error
func WriteFrame(io.Writer, Message) error
func ReadFrame(io.Reader, Message) error
type ServerMessage interface { Message; /* package-private seal */ }
func ReadServerFrame(io.Reader) (ServerMessage, error)
func ValidateReplyFor(Request, Reply) error
func (Request) ValidatePolicy(storageauthority.Mode) error
func (Request) Mutates() bool
func PolicyFor(Operation) (OperationPolicy, bool)
func RequiredProfile() Profile
func DirEntryBytes([]byte) uint32
func (*SequenceTracker) Accept(uint64) error
```

Messages are **pointers** to `Request`, `Reply`, `ServerHello`, `ClientHello`,
`RootReply`, or `Event`. Bodies are **values** of the exact concrete types in
`operations.go`, not pointers (including typed nil), user-defined embeddings, or
arbitrary maps. `RequestBody` and `ReplyBody` expose `Operation() Operation` plus
private seals. The explicit type whitelist also rejects embedding-based extension.
`ReadServerFrame` returns only `*Reply` or `*Event` for the post-handshake stream;
its discriminator is the required `event_sequence` field. Mixed/ambiguous shapes
are rejected by strict validation. No permissive client-side envelope is needed.

`Request{Sequence uint64, Auth Auth, Body RequestBody}` derives its JSON `op` from
the body. `Reply{Sequence uint64, Op Operation, Errno uint32, Body ReplyBody}`
requires an exact operation-specific success body, including `{}` acknowledgments.
Errors omit `body`; only get/list-xattr ERANGE may instead carry
`XAttrSizeError{Size uint32}`. Error results never carry success data.

Four-byte **uint32 big-endian** payload length, followed by one JSON object. No
compression. Frame length excludes the prefix. Keys are exact snake_case; all
fields are required, including zeroes/false/empty lists, except optional
`Auth.Caller`, get/set-attr `Handle`, error `body`, authority binding `prepare`,
and PREPARE `Path` (present only for IdentityAt).
Absent optional fields must be **omitted**, not null. Nil slices are rejected;
empty bytes use `""`, empty lists use `[]`. Byte slices are canonical standard
base64, preserving invalid-UTF8 Linux names, symlink targets and xattr bytes.
Object IDs are exactly 32 lowercase hex characters for opaque 16-byte identities;
zero is reserved for absent event parent, not a live object.

The decoder rejects duplicate keys at every depth, unknown or case-folded fields,
missing fields, nulls, wrong JSON types/ranges, malformed/noncanonical base64,
invalid unions, excessive nesting and trailing JSON values. Internal raw JSON is
only staging for a closed body; no raw/unvalidated payload escapes the decoder.
A failed `Unmarshal` leaves its destination unchanged. Use these codec functions,
not `encoding/json` on individual DTOs. The reader checks length before allocating;
aggregate receive memory, deadlines and concurrent message counts remain external.
Writers handle short writes but are not internally synchronized.

### Fixed constants

| Constant | Value |
|---|---:|
| `Version` / `CredentialABI` | 4 / 3 |
| `MaxFrame` / `MaxHello` | 1,048,576 / 16,384 bytes |
| `MaxIO` / `MaxXAttr` | 131,072 / 65,536 bytes |
| `MaxName` / `MaxTarget` | 255 / 4,095 bytes |
| `MaxGroups` | 65,536 |
| `MaxDirEntries` / `MaxForget` | 256 / 256 |
| `MaxDepth` | 16 (root at depth zero) |
| `MaxLinuxErrno` / `ErrnoERANGE` / `ErrnoENOTTY` | 4095 / 34 / 25 |

Requests, replies and events use independent positive monotonically increasing
sequence streams; these are **not FUSE Unique**. Gaps are permitted, reuse,
regression, zero and wraparound are rejected by a per-stream `SequenceTracker`.
The codec checks positivity; the transport must call the tracker and correlate
each reply with `ValidateReplyFor`, never assume JSON validation proves ordering.

## Closed operation mapping

Every row names `Op<Name>`, `<Name>Request`, `<Name>Reply`. Field spellings and fixed
Go widths are authoritative in `operations.go`; shared DTOs are in `types.go`.

| Name (JSON op) | Request | Success result |
|---|---|---|
| Lookup (`lookup`) | Parent, raw Name | Entry |
| GetAttr (`get_attr`) | Node, optional Handle | Attr |
| SetAttr (`set_attr`) | Node, optional Handle, Valid, Semantics, Mode/UID/GID/Size/ATime/MTime/KillSUIDGID | Attr |
| Create (`create`) | Parent, Name, Flags, FuseOpenFlags, Mode, Umask | Entry, Opened |
| Open (`open`) | Node, Flags, FuseOpenFlags | Opened |
| Read (`read`) | Node, Handle, Offset, Size, IOFlags | Data |
| Write (`write`) | Node, Handle, Offset, IOFlags, WriteFlags, Data | Written |
| Flush (`flush`) | Node, Handle | empty |
| Fsync / FsyncDir (`fsync`, `fsync_dir`) | Node, Handle, DataOnly | empty |
| Release / ReleaseDir (`release`, `release_dir`) | Node, Handle, ReleaseFlags | empty ack |
| OpenDir (`open_dir`) | Node, Flags | Opened |
| ReadDir (`read_dir`) | Node, Handle, Cookie, MaxBytes | Entries |
| Mkdir (`mkdir`) | Parent, Name, Mode, Umask | Entry |
| Mknod (`mknod`) | Parent, Name, Mode, Umask, Rdev | Entry |
| Symlink (`symlink`) | Parent, Name, Target | Entry |
| Readlink (`readlink`) | Node | Target |
| Link (`link`) | Source, Parent, Name | Entry |
| Rename (`rename`) | OldParent/NewParent, OldName/NewName, Flags | empty |
| Unlink / Rmdir (`unlink`, `rmdir`) | Parent, Name | empty |
| Access (`access`) | Node, Mask | empty |
| GetXAttr (`get_xattr`) | Node, Name, Size | Size, Value |
| ListXAttr (`list_xattr`) | Node, Size | Size, Names (raw NUL list) |
| SetXAttr (`set_xattr`) | Node, Name, Value, Flags | empty |
| RemoveXAttr (`remove_xattr`) | Node, Name | empty |
| StatFS (`stat_fs`) | Node | Stat (FSStat) |
| Forget (`forget`) | Entries of Node/Count | empty ack |
| Fallocate (`fallocate`) | Node, Handle, Offset, Length, Mode | empty |
| Lseek (`lseek`) | Node, Handle, Offset, Whence | Offset |

`NodeID`/`HandleID` are nonzero uint64 session tokens, separate from real `Attr.Ino`.
`Entry` carries Node, nonzero Generation, Object, Attr; `Opened` carries Handle.
Attr retains real ino, size, blocks (Linux 512-byte units), mode, nlink (including
zero after unlink), UID/GID, rdev (never st_dev), block size and signed-seconds +
0..999999999-nanoseconds atime/mtime/ctime. No arbitrary ctime assignment exists.

SETATTR uses **protocol-local** `SetMode=1`, `SetUID=2`, `SetGID=4`, `SetSize=8`,
`SetATime=16`, `SetMTime=32`, `SetATimeNow=64`, `SetMTimeNow=128`,
`SetKillSUIDGID=256` and `KillSUIDGID` remain reserved legacy schema fields,
but any nonzero legacy bit/value is rejected (not converted to ABI3 semantics).
NOW **requires** the corresponding ATIME/MTIME present bit; selected NOW values
retain the source timestamp, while the backing kernel uses current_time.
Unselected values must be zero. Mode is permission/special bits (07777).
Every SETATTR requires `Semantics MetadataSemantics` (uint64), including empty
attribute masks: `MetadataValid=1`, `MetadataKillSUID=2`, `MetadataKillSGID=4`,
`MetadataKillPriv=8`, `MetadataForce=16`, `MetadataCTime=32`,
`MetadataTimesSet=64`, `MetadataTouch=128`, `MetadataFile=256`,
`MetadataOpen=512`; `MetadataMask=1023`. Unknown bits and missing VALID fail.
MODE with KILL_SUID/KILL_SGID fails. FORCE with MODE/UID/GID, explicit timestamps,
TIMES_SET or TOUCH fails. OPEN requires zero SIZE; FILE requires an exact Handle
association (the server must enforce backing-FD authority). UINT32_MAX UID/GID
are invalid; chown(-1,-1) instead has no UID/GID fields, VALID|CTIME and kernel
kill flags. Standalone force/write kills likewise use semantic flags, not legacy
SetKillSUIDGID. CTIME transports no timestamp: the backing kernel updates now.
Only `storageclient.Client.Do` stamps captured semantics, never a caller builder.

Creation mode optionally includes the matching file type; umask is unmodified
0777 and server creation must honor default ACL inheritance via an isolated worker.

`flags.go` freezes Linux **generic** values; adapters translate architecture
constants, not host constants. Unknown flags fail closed. No O_PATH/O_TMPFILE.
Open cannot carry CREATE/EXCL; Create owns creation. OPEN rejects TRUNC in
this non-atomic profile. Linux still carries TRUNC on CREATE; the server MUST
suppress truncation during CREATE and await the subsequent semantic SETATTR. `FuseOpenKillSUIDGID=1`,
`WriteCache=1`, `WriteKillSUIDGID=4`; both legacy kill flag values are rejected,
and lock-owner flags are not forwarded.
Cache writes require explicit `OpenGrantAuth` and offset-addressed handling,
not opener capabilities or append semantics blindly replayed through pwrite.
`ReleaseFlush=1` is accepted on files only; directory release flags must be zero.
`RenameNoReplace=1` / `RenameExchange=2` are mutually exclusive.
`XAttrCreate=1` / `XAttrReplace=2` are mutually exclusive.
Fallocate accepts mode 0, KEEP_SIZE=1, PUNCH_HOLE|KEEP_SIZE=3,
ZERO_RANGE=16, ZERO_RANGE|KEEP_SIZE=17. Lseek accepts SEEK_DATA=3 and SEEK_HOLE=4.
Unsupported filesystem fallocate/seek returns the appropriate positive Linux errno,
not fabricated success. No copy-range or general file-ioctl operation exists;
only the private root-directory PREPARE ioctl above is translated. Other ioctls
return client ENOTTY. Locks stay client/kernel-local, without distributed forwarding.

Offsets and range ends must fit MaxInt64 (checked before addition); read/write are
bounded to MaxIO. Directory cookies also fit signed Linux off_t, but need not be
numerically increasing; each page has distinct nonzero next cookies, no repeated
names, and no next cookie equal to the incoming cookie. `ValidateReplyFor` checks
aligned `fuse_dirent` bytes against MaxBytes. READDIR may include `.`/`..`; namespace
component operands cannot be empty, `.`/`..`, contain slash/NUL, or exceed MaxName.
Symlink targets may contain slash but not NUL. Xattr names are not path components:
only their length/NUL constraints apply; namespaces remain a syscall decision.

For xattrs request Size=0 is a probe: return required Size and empty bytes. A
nonzero buffer returns exactly Size bytes, including Size=0 for a genuinely empty
value/list. ERANGE may carry required Size **only** when larger than a nonzero
requested capacity. NUL-separated lists must terminate each nonempty name and
cannot duplicate names. Both standalone validation and request-correlated checks
are required. FORGET batches have 1..256 distinct nodes and nonzero uint64 counts;
the server still must detect pin-count underflow before acknowledging.

## Authorization and read-only policy

`CallerAuth=1`, `OpenGrantAuth=2`, `NodeMetadataAuth=3`, `LifecycleAuth=4`.
Caller means an explicit nonnil immutable snapshot containing fsuid, fsgid, the
complete (possibly empty) supplementary groups, and the full uint64 effective
capabilities. NONE is never caller/root. UID zero with zero caps remains zero caps.
ABI 3 installation and supported capability-mask verification are server/client
obligations; a serialized snapshot alone cannot prove its kernel origin.

| Operations | Allowed auth | Handle | RO restriction |
|---|---|---|---|
| Lookup, Readlink, Get/ListXAttr, StatFS | Caller | none | read |
| GetAttr | Caller, OpenGrant, NodeMetadata | optional | read |
| SetAttr | Caller | optional | mutation |
| Create, Mkdir, Mknod, Symlink, Link, Rename, Unlink, Rmdir, Set/RemoveXAttr | Caller | none | mutation |
| Open | Caller | none | write access/TRUNC rejected on RO |
| OpenDir | Caller | none | read-only flags |
| Read, ReadDir, Flush, Fsync, FsyncDir, Lseek | Caller or OpenGrant | required | read/cleanup |
| Write, Fallocate | Caller or OpenGrant | required | mutation |
| Access | Caller | none | W_OK rejected on RO |
| Release, ReleaseDir | Lifecycle | required | cleanup |
| Forget | Lifecycle | none | cleanup |

GetAttr OpenGrant requires FH; NodeMetadata forbids FH and authorizes only a live
metadata pin. Caller GetAttr may have FH. Metadata mutation never borrows opener
credentials. All required handles must match node, authenticated attachment,
access mode and file/directory kind at the server. Per-I/O flags never upgrade a
grant. The table/`ValidatePolicy` checks syntax and authenticated mode only.

## Handshake, events, and external trust obligations

Over mutually verified TLS 1.3 with resumption/early-data disabled:

1. `ServerHello{Epoch storageauthority.ID, Version uint32, Profile Profile}`.
2. `ClientHello{Authority storageauthority.DataHello, Profile Profile}`.
3. `AuthenticateData` binds the immutable principal; admit attachment root setup.
4. `RootReply{Root Entry}` (directory) only after successful admission. Setup errors
   close the transport; no root-error/result megastruct or data reconnect exists.

Profile equality is exact, not feature-subset negotiation. Credential ABI=3;
DefaultPermissions, ACL, CheckedCloseToOpen, NativeKernel, OpenGrants and DontMask are true. HandleKillpriv, HandleKillprivV2, AtomicOTrunc,
WritebackCache, Passthrough, IDMapped, ReadDirPlus and Reconnect are false; fixed frame/I/O/groups/xattr/readdir limits are advertised.
Additionally require init-user-namespace request_cred, no FUSE-over-io_uring,
zero positive/negative/attr TTL, no KEEP_CACHE/directory/symlink caching and no
blanket DIRECT_IO (mmap is required). Killpriv/reopen must be implemented and tested
before claiming this profile. Clearing KEEP_CACHE alone is not checked invalidation.

`Event` carries EventSequence, authority Volume ID, Object/Parent object IDs, Kind,
raw Name and Offset/Length. It has **no NodeID**. Kinds `attr`, `data`, `entry` have
validated exact semantics: attr has zero range/parent and empty name; data has zero
parent/empty name, signed-safe range (Length=0 means through EOF); entry has a
nonzero parent and component name, zero range. Object identifies the affected
inode; translate it into each recipient's own live node IDs. Event volume equality
to the authenticated session is an external requirement. Invalidation workers are
separate and bounded; concurrent cross-VM mmap coherency is not claimed.

Every complete RPC must acquire `storageauthority.Admit` before identity/namespace
queues, descriptor lookup or filesystem access; hold its Guard through joined
I/O/callback cleanup. Copy authenticated `(S,V,A,E,role,mode)` into every internal
context; requests cannot override those identities. Schema validation cannot prove
admission, role/reservation state, volume confinement, Linux caller origin,
capability installation, default-permission traversal witness, immutable grants,
lookup-count ownership, or actual durability. Never truncate supplementary groups
or normalize credential-less requests to root.

One FIFO execution stream per attachment, a bounded ordered writer, and terminal
transport/protocol failure are mandatory. No retry/reconnect/replay or cancellation
after enqueue. Reserve cleanup capacity when granting nodes/handles; FORGET callback
records locally without networking; RELEASE/FORGET receive wire acknowledgments.
Delivery failure/count corruption/release failure aborts the exact mount and asks
for retirement. Never drop cleanup, LRU-evict live pins, or mistake RELEASE success
for a drain receipt. Slow reply readers cannot retain mutation ownership; executing
guards survive socket loss until completion. Global receive/identity/node/handle
budgets belong to the server/client, not this stateless schema.

Native race/vet and Linux cross-compilation are codec checks, not credential ABI,
mounted FUSE/ext4, mmap, killpriv, or drain proof.

package storagewire

// Frozen Linux generic flag values, not host syscall constants. Adapters must
// translate architecture-specific values, and may never upgrade an open grant.
const (
	OpenReadOnly        uint32 = 0
	OpenWriteOnly       uint32 = 1
	OpenReadWrite       uint32 = 2
	OpenAccessMask      uint32 = 3
	OpenCreate          uint32 = 0x40
	OpenExclusive       uint32 = 0x80
	OpenNoCTTY          uint32 = 0x100
	OpenTruncate        uint32 = 0x200
	OpenAppend          uint32 = 0x400
	OpenNonblock        uint32 = 0x800
	OpenDSync           uint32 = 0x1000
	OpenAsync           uint32 = 0x2000
	OpenDirect          uint32 = 0x4000
	OpenLargeFile       uint32 = 0x8000
	OpenDirectory       uint32 = 0x10000
	OpenNoFollow        uint32 = 0x20000
	OpenNoATime         uint32 = 0x40000
	OpenCloseOnExec     uint32 = 0x80000
	OpenSync            uint32 = 0x101000
	FuseOpenKillSUIDGID uint32 = 1
	WriteCache          uint32 = 1
	WriteKillSUIDGID    uint32 = 4
	ReleaseFlush        uint32 = 1
	RenameNoReplace     uint32 = 1
	RenameExchange      uint32 = 2
	XAttrCreate         uint32 = 1
	XAttrReplace        uint32 = 2
	FallocateKeepSize   uint32 = 1
	FallocatePunchHole  uint32 = 2
	FallocateZeroRange  uint32 = 16
	SeekData            uint32 = 3
	SeekHole            uint32 = 4
)

// Protocol-local mask: deliberately not a blind FUSE FATTR passthrough.
const (
	SetMode uint32 = 1 << iota
	SetUID
	SetGID
	SetSize
	SetATime
	SetMTime
	SetATimeNow
	SetMTimeNow
	SetKillSUIDGID // Reserved legacy bit: rejected by ABI3, as is KillSUIDGID.
)

// MetadataSemantics is the frozen source ABI3 kernel output, not caller flags.
// Only storageclient's captured snapshot may populate SetAttrRequest.Semantics.
type MetadataSemantics uint64

const (
	MetadataValid MetadataSemantics = 1 << iota
	MetadataKillSUID
	MetadataKillSGID
	MetadataKillPriv
	MetadataForce
	MetadataCTime
	MetadataTimesSet
	MetadataTouch
	MetadataFile
	MetadataOpen
	MetadataMask MetadataSemantics = 1023
)

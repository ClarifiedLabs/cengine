package storagemanaged

import w "dev.cengine/guest/internal/storagewire"

// Frozen storage-session ABI1, distinct from the source credential ABI3.
// Keep fixed-width fields and padding: the ioctl consumes exactly 80 bytes.
const (
	storageSessionIOCTL   = 0xe5f2
	storageApplyAttrIOCTL = 0x4050e5f3
)

type storageAttr struct {
	Version   uint32
	Flags     uint32
	FD        int32
	Valid     uint32
	Semantics uint64
	Mode      uint32
	UID       uint32
	GID       uint32
	Reserved  uint32
	Size      int64
	ATime     int64
	MTime     int64
	ATimeNsec uint32
	MTimeNsec uint32
	Reserved2 [2]uint32
}

// metadataAttr consumes a wire-validated, immutable request. The backing FD is
// selected locally under lifetime locks, never imported from the wire. Do not
// copy Valid wholesale: these are typed storage ABI bits, not FATTR/iattr bits.
func metadataAttr(v w.SetAttrRequest, fd int) storageAttr {
	a := storageAttr{Version: 1, FD: int32(fd), Semantics: uint64(v.Semantics)}
	if v.Valid&w.SetMode != 0 {
		a.Valid |= 1
		a.Mode = v.Mode
	}
	if v.Valid&w.SetUID != 0 {
		a.Valid |= 2
		a.UID = v.UID
	}
	if v.Valid&w.SetGID != 0 {
		a.Valid |= 4
		a.GID = v.GID
	}
	if v.Valid&w.SetSize != 0 {
		a.Valid |= 8
		a.Size = int64(v.Size)
	}
	if v.Valid&w.SetATime != 0 {
		a.Valid |= 16
		a.ATime = v.ATime.Seconds
		a.ATimeNsec = v.ATime.Nanoseconds
	}
	if v.Valid&w.SetMTime != 0 {
		a.Valid |= 32
		a.MTime = v.MTime.Seconds
		a.MTimeNsec = v.MTime.Nanoseconds
	}
	if v.Valid&w.SetATimeNow != 0 {
		a.Valid |= 64
	}
	if v.Valid&w.SetMTimeNow != 0 {
		a.Valid |= 128
	}
	return a
}

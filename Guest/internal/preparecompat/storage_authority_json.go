package preparecompat

import (
	"encoding/hex"
	"encoding/json"
	"strconv"

	a "dev.cengine/guest/internal/storageauthority"
)

// This private compatibility projection does not change authority journals or
// DATA/ioctl JSON. Every field is required, including actual zero BOUND state.
// Signed seconds use canonical Int64 decimal strings; fixed byte arrays use
// exact lowercase hex, preserving leading zeroes without lossy number coercion.
type prepareObjectDTO struct {
	Inode      uint64 `json:"inode"`
	Generation uint32 `json:"generation"`
	FileType   uint32 `json:"file_type"`
	HandleType uint32 `json:"handle_type"`
	HandleSize uint32 `json:"handle_size"`
	Handle     string `json:"handle"`
}
type prepareRootDTO struct {
	Store       a.ID             `json:"store"`
	Volume      a.ID             `json:"volume"`
	BackingUUID string           `json:"backing_uuid"`
	Root        prepareObjectDTO `json:"root"`
}
type prepareCleanupDTO struct {
	UID          uint32           `json:"uid"`
	GID          uint32           `json:"gid"`
	Mode         uint32           `json:"mode"`
	ATimeSeconds string           `json:"atime_seconds"`
	MTimeSeconds string           `json:"mtime_seconds"`
	ATimeNanos   uint32           `json:"atime_nanos"`
	MTimeNanos   uint32           `json:"mtime_nanos"`
	Manifest     prepareObjectDTO `json:"manifest"`
	Staging      prepareObjectDTO `json:"staging"`
}
type prepareIntentDTO struct {
	ID              a.ID              `json:"id"`
	Owner           a.Binding         `json:"owner"`
	Epoch           a.ID              `json:"epoch"`
	Root            prepareRootDTO    `json:"root"`
	Transaction     prepareObjectDTO  `json:"transaction"`
	ManifestDigest  string            `json:"manifest_digest"`
	ManifestSize    uint64            `json:"manifest_size"`
	Phase           string            `json:"phase"`
	Initial         prepareCleanupDTO `json:"initial"`
	InitialCaptured bool              `json:"initial_captured"`
	Cleanup         prepareCleanupDTO `json:"cleanup"`
}
type boundCutJSON struct {
	RequestSequence uint64           `json:"requestSequence"`
	Intent          prepareIntentDTO `json:"intent"`
}

func objectToDTO(o a.Ext4ObjectV1) prepareObjectDTO {
	return prepareObjectDTO{Inode: o.Inode, Generation: o.Generation, FileType: o.FileType, HandleType: o.HandleType, HandleSize: o.HandleSize, Handle: hex.EncodeToString(o.Handle[:])}
}
func exactHex(text string, out []byte) error {
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != len(out) || hex.EncodeToString(raw) != text {
		return ErrInvalidFrame
	}
	copy(out, raw)
	return nil
}
func (o prepareObjectDTO) authority() (a.Ext4ObjectV1, error) {
	result := a.Ext4ObjectV1{Inode: o.Inode, Generation: o.Generation, FileType: o.FileType, HandleType: o.HandleType, HandleSize: o.HandleSize}
	if exactHex(o.Handle, result.Handle[:]) != nil {
		return a.Ext4ObjectV1{}, ErrInvalidFrame
	}
	return result, nil
}
func signedSeconds(text string) (int64, error) {
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil || strconv.FormatInt(value, 10) != text {
		return 0, ErrInvalidFrame
	}
	return value, nil
}
func cleanupToDTO(c a.CopyCleanupV1) prepareCleanupDTO {
	return prepareCleanupDTO{UID: c.UID, GID: c.GID, Mode: c.Mode, ATimeSeconds: strconv.FormatInt(c.ATimeSeconds, 10), MTimeSeconds: strconv.FormatInt(c.MTimeSeconds, 10), ATimeNanos: c.ATimeNanos, MTimeNanos: c.MTimeNanos, Manifest: objectToDTO(c.Manifest), Staging: objectToDTO(c.Staging)}
}
func (c prepareCleanupDTO) authority() (a.CopyCleanupV1, error) {
	atime, e1 := signedSeconds(c.ATimeSeconds)
	mtime, e2 := signedSeconds(c.MTimeSeconds)
	manifest, e3 := c.Manifest.authority()
	staging, e4 := c.Staging.authority()
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return a.CopyCleanupV1{}, ErrInvalidFrame
	}
	return a.CopyCleanupV1{UID: c.UID, GID: c.GID, Mode: c.Mode, ATimeSeconds: atime, MTimeSeconds: mtime, ATimeNanos: c.ATimeNanos, MTimeNanos: c.MTimeNanos, Manifest: manifest, Staging: staging}, nil
}
func (b BoundCut) MarshalJSON() ([]byte, error) {
	i := b.Intent
	return json.Marshal(boundCutJSON{RequestSequence: b.RequestSequence, Intent: prepareIntentDTO{ID: i.ID, Owner: i.Owner, Epoch: i.Epoch, Root: prepareRootDTO{Store: i.Root.Store, Volume: i.Root.Volume, BackingUUID: hex.EncodeToString(i.Root.BackingUUID[:]), Root: objectToDTO(i.Root.Root)}, Transaction: objectToDTO(i.Transaction), ManifestDigest: hex.EncodeToString(i.ManifestDigest[:]), ManifestSize: i.ManifestSize, Phase: i.Phase, Initial: cleanupToDTO(i.Initial), InitialCaptured: i.InitialCaptured, Cleanup: cleanupToDTO(i.Cleanup)}})
}
func (b *BoundCut) UnmarshalJSON(raw []byte) error {
	var dto boundCutJSON
	if decode(raw, &dto, MaximumObservationBytes) != nil {
		return ErrInvalidFrame
	}
	i := dto.Intent
	root, e1 := i.Root.Root.authority()
	transaction, e2 := i.Transaction.authority()
	initial, e3 := i.Initial.authority()
	cleanup, e4 := i.Cleanup.authority()
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return ErrInvalidFrame
	}
	result := a.CopyIntent{ID: i.ID, Owner: i.Owner, Epoch: i.Epoch, Root: a.CopyRootV1{Store: i.Root.Store, Volume: i.Root.Volume, Root: root}, Transaction: transaction, ManifestSize: i.ManifestSize, Phase: i.Phase, Initial: initial, InitialCaptured: i.InitialCaptured, Cleanup: cleanup}
	if exactHex(i.Root.BackingUUID, result.Root.BackingUUID[:]) != nil || exactHex(i.ManifestDigest, result.ManifestDigest[:]) != nil {
		return ErrInvalidFrame
	}
	*b = BoundCut{RequestSequence: dto.RequestSequence, Intent: result}
	return nil
}

// Receipt preserves the existing lower-case schema and requires PREPARE even
// though authority also uses the type for runtime receipts without that field.
type receiptJSON struct {
	Schema     uint32 `json:"schema"`
	Store      a.ID   `json:"store"`
	Volume     a.ID   `json:"volume"`
	Attachment a.ID   `json:"attachment"`
	Launch     a.ID   `json:"launch"`
	Prepare    a.ID   `json:"prepare"`
	Revision   uint64 `json:"revision"`
}
type drainCutJSON struct {
	RetireOperation string      `json:"retireOperation"`
	Receipt         receiptJSON `json:"receipt"`
}

func (d DrainCut) MarshalJSON() ([]byte, error) {
	r := d.Receipt
	if r.Schema < 0 || uint64(r.Schema) > uint64(^uint32(0)) {
		return nil, ErrInvalidFrame
	}
	return json.Marshal(drainCutJSON{RetireOperation: d.RetireOperation, Receipt: receiptJSON{Schema: uint32(r.Schema), Store: r.Store, Volume: r.Volume, Attachment: r.Attachment, Launch: r.Launch, Prepare: r.Prepare, Revision: r.Revision}})
}
func (d *DrainCut) UnmarshalJSON(raw []byte) error {
	var dto drainCutJSON
	if decode(raw, &dto, MaximumObservationBytes) != nil {
		return ErrInvalidFrame
	}
	r := dto.Receipt
	*d = DrainCut{RetireOperation: dto.RetireOperation, Receipt: a.Receipt{Schema: int(r.Schema), Store: r.Store, Volume: r.Volume, Attachment: r.Attachment, Launch: r.Launch, Prepare: r.Prepare, Revision: r.Revision}}
	return nil
}

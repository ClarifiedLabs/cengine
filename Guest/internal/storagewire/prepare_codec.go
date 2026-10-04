package storagewire

import (
	"encoding/json"

	a "dev.cengine/guest/internal/storageauthority"
)

// Private DTOs freeze the DATA/ioctl schema independently of authority journal
// encoding. Never relax strictDecode to accommodate untagged authority fields.
type prepareObjectDTO struct {
	Inode      uint64  `json:"inode"`
	Generation uint32  `json:"generation"`
	FileType   uint32  `json:"file_type"`
	HandleType uint32  `json:"handle_type"`
	HandleSize uint32  `json:"handle_size"`
	Handle     [8]byte `json:"handle"`
}
type prepareRootDTO struct {
	Store       a.ID             `json:"store"`
	Volume      a.ID             `json:"volume"`
	BackingUUID [16]byte         `json:"backing_uuid"`
	Root        prepareObjectDTO `json:"root"`
}
type prepareCleanupDTO struct {
	UID          uint32           `json:"uid"`
	GID          uint32           `json:"gid"`
	Mode         uint32           `json:"mode"`
	ATimeSeconds int64            `json:"atime_seconds"`
	MTimeSeconds int64            `json:"mtime_seconds"`
	ATimeNanos   uint32           `json:"atime_nanos"`
	MTimeNanos   uint32           `json:"mtime_nanos"`
	Manifest     prepareObjectDTO `json:"manifest"`
	Staging      prepareObjectDTO `json:"staging"`
}

func cleanupToDTO(v a.CopyCleanupV1) prepareCleanupDTO {
	return prepareCleanupDTO{v.UID, v.GID, v.Mode, v.ATimeSeconds, v.MTimeSeconds, v.ATimeNanos, v.MTimeNanos, prepareObjectDTO(v.Manifest), prepareObjectDTO(v.Staging)}
}
func (v prepareCleanupDTO) authority() a.CopyCleanupV1 {
	return a.CopyCleanupV1{UID: v.UID, GID: v.GID, Mode: v.Mode, ATimeSeconds: v.ATimeSeconds, MTimeSeconds: v.MTimeSeconds, ATimeNanos: v.ATimeNanos, MTimeNanos: v.MTimeNanos, Manifest: a.Ext4ObjectV1(v.Manifest), Staging: a.Ext4ObjectV1(v.Staging)}
}

type prepareIntentDTO struct {
	ID              a.ID              `json:"id"`
	Owner           a.Binding         `json:"owner"`
	Epoch           a.ID              `json:"epoch"`
	Root            prepareRootDTO    `json:"root"`
	Transaction     prepareObjectDTO  `json:"transaction"`
	ManifestDigest  [32]byte          `json:"manifest_digest"`
	ManifestSize    uint64            `json:"manifest_size"`
	Phase           string            `json:"phase"`
	Initial         prepareCleanupDTO `json:"initial"`
	InitialCaptured bool              `json:"initial_captured"`
	Cleanup         prepareCleanupDTO `json:"cleanup"`
}
type prepareReplyDTO struct {
	Pending  PrepareAction    `json:"pending"`
	Intent   prepareIntentDTO `json:"intent"`
	Root     prepareRootDTO   `json:"root"`
	Identity prepareObjectDTO `json:"identity"`
}

func prepareRootToDTO(r a.CopyRootV1) prepareRootDTO {
	return prepareRootDTO{r.Store, r.Volume, r.BackingUUID, prepareObjectDTO(r.Root)}
}
func (r prepareRootDTO) authority() a.CopyRootV1 {
	return a.CopyRootV1{Store: r.Store, Volume: r.Volume, BackingUUID: r.BackingUUID, Root: a.Ext4ObjectV1(r.Root)}
}
func (r PrepareReply) MarshalJSON() ([]byte, error) {
	if err := validatePrepareReply(r); err != nil {
		return nil, err
	}
	i := r.Intent
	return json.Marshal(prepareReplyDTO{
		Pending: r.Pending,
		Intent:  prepareIntentDTO{i.ID, i.Owner, i.Epoch, prepareRootToDTO(i.Root), prepareObjectDTO(i.Transaction), i.ManifestDigest, i.ManifestSize, i.Phase, cleanupToDTO(i.Initial), i.InitialCaptured, cleanupToDTO(i.Cleanup)},
		Root:    prepareRootToDTO(r.Root), Identity: prepareObjectDTO(r.Identity),
	})
}
func (r *PrepareReply) UnmarshalJSON(raw []byte) error {
	var dto prepareReplyDTO
	if err := strictDecode(raw, &dto); err != nil {
		return err
	}
	i := dto.Intent
	value := PrepareReply{
		Pending: dto.Pending,
		Intent:  a.CopyIntent{ID: i.ID, Owner: i.Owner, Epoch: i.Epoch, Root: i.Root.authority(), Transaction: a.Ext4ObjectV1(i.Transaction), ManifestDigest: i.ManifestDigest, ManifestSize: i.ManifestSize, Phase: i.Phase, Initial: i.Initial.authority(), InitialCaptured: i.InitialCaptured, Cleanup: i.Cleanup.authority()},
		Root:    dto.Root.authority(), Identity: a.Ext4ObjectV1(dto.Identity),
	}
	if err := validatePrepareReply(value); err != nil {
		return err
	}
	*r = value
	return nil
}

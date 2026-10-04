package storageclient

import (
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

// The DATA peer cannot change the immutable authenticated scope in a sideband
// response. Durable identity is separate from ordinary local node allocation.
func (c *Client) checkPrepareReply(v w.PrepareReply) error {
	b := c.authority.Binding
	if v.Root != (a.CopyRootV1{}) && (v.Root.Store != b.Store || v.Root.Volume != b.Volume) {
		return ErrProtocol
	}
	if v.Intent != (a.CopyIntent{}) && (v.Intent.Owner != b || v.Intent.Epoch != c.authority.Epoch || v.Intent.Root.Store != b.Store || v.Intent.Root.Volume != b.Volume) {
		return ErrProtocol
	}
	return nil
}

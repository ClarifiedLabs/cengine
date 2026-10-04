package storageserver

import w "dev.cengine/guest/internal/storagewire"

// originMaintainsData identifies completions whose data cache is already maintained
// by the requesting FUSE kernel. Echoing DATA can launder its dirty mmap pages into
// another cache WRITE and repeat the notification. ATTR/ENTRY and remote DATA must
// still be delivered. The caller also requires a reply and no dispatch failure.
func originMaintainsData(request w.Request, reply w.Reply) bool {
	if reply.Errno != 0 || w.ValidateReplyFor(request, reply) != nil {
		return false
	}
	switch r := request.Body.(type) {
	case w.WriteRequest:
		// Both ordinary writes and FUSE_WRITE_CACHE are kernel-owned; a short
		// result does not establish that the complete requested data was applied.
		return int(reply.Body.(w.WriteReply).Written) == len(r.Data)
	case w.SetAttrRequest:
		return r.Valid&w.SetSize != 0
	default:
		return false
	}
}

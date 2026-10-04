package storagewire

func knownRequestBody(v RequestBody) bool {
	switch v.(type) {
	case PrepareRequest, LookupRequest, GetAttrRequest, SetAttrRequest, CreateRequest, OpenRequest, ReadRequest, WriteRequest, FlushRequest, FsyncRequest, FsyncDirRequest, ReleaseRequest, ReleaseDirRequest, OpenDirRequest, ReadDirRequest, MkdirRequest, MknodRequest, SymlinkRequest, ReadlinkRequest, LinkRequest, RenameRequest, UnlinkRequest, RmdirRequest, AccessRequest, GetXAttrRequest, ListXAttrRequest, SetXAttrRequest, RemoveXAttrRequest, StatFSRequest, ForgetRequest, FallocateRequest, LseekRequest:
		return true
	default:
		return false
	}
}
func knownReplyBody(v ReplyBody) bool {
	switch v.(type) {
	case PrepareReply, LookupReply, GetAttrReply, SetAttrReply, CreateReply, OpenReply, ReadReply, WriteReply, FlushReply, FsyncReply, FsyncDirReply, ReleaseReply, ReleaseDirReply, OpenDirReply, ReadDirReply, MkdirReply, MknodReply, SymlinkReply, ReadlinkReply, LinkReply, RenameReply, UnlinkReply, RmdirReply, AccessReply, GetXAttrReply, ListXAttrReply, SetXAttrReply, RemoveXAttrReply, StatFSReply, ForgetReply, FallocateReply, LseekReply:
		return true
	default:
		return false
	}
}

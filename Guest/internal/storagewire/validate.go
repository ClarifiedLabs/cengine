package storagewire

import (
	"bytes"
	"dev.cengine/guest/internal/storageauthority"
	"encoding/hex"
	"math"
	"reflect"
)

func (a Auth) Validate() error {
	if a.Kind < CallerAuth || a.Kind > LifecycleAuth {
		return invalid("auth kind")
	}
	if a.Kind != CallerAuth {
		if a.Caller != nil {
			return invalid("caller on noncaller auth")
		}
		return nil
	}
	if a.Caller == nil || a.Caller.Groups == nil || len(a.Caller.Groups) > MaxGroups {
		return invalid("missing caller/groups limit")
	}
	// Zero UID and zero capabilities remain literal, not a privileged fallback.
	return nil
}
func (r Request) Validate() error {
	if r.Sequence == 0 || !knownRequestBody(r.Body) {
		return invalid("request sequence/body")
	}
	if err := r.Auth.Validate(); err != nil {
		return err
	}
	p, ok := PolicyFor(r.Body.Operation())
	if !ok || !p.AuthKinds.Allows(r.Auth.Kind) {
		return invalid("operation auth")
	}
	if err := validateNodeFields(r.Body); err != nil {
		return err
	}
	switch v := r.Body.(type) {
	case PrepareRequest:
		return validatePrepareRequest(v)
	case LookupRequest:
		return component(v.Name)
	case GetAttrRequest:
		if r.Auth.Kind == OpenGrantAuth && v.Handle == nil || r.Auth.Kind == NodeMetadataAuth && v.Handle != nil {
			return invalid("getattr provenance/handle")
		}
	case SetAttrRequest:
		const mask = SetMode | SetUID | SetGID | SetSize | SetATime | SetMTime | SetATimeNow | SetMTimeNow
		if v.Semantics&MetadataValid == 0 || v.Semantics & ^MetadataMask != 0 || v.Valid & ^uint32(mask) != 0 || v.KillSUIDGID {
			return invalid("setattr semantics/legacy flags")
		}
		if v.Mode & ^uint32(07777) != 0 || v.Size > math.MaxInt64 || !timestamp(v.ATime) || !timestamp(v.MTime) || v.Valid&SetUID != 0 && v.UID == math.MaxUint32 || v.Valid&SetGID != 0 && v.GID == math.MaxUint32 {
			return invalid("setattr value")
		}
		if v.Valid&SetMode == 0 && v.Mode != 0 || v.Valid&SetUID == 0 && v.UID != 0 || v.Valid&SetGID == 0 && v.GID != 0 || v.Valid&SetSize == 0 && v.Size != 0 {
			return invalid("unselected setattr field")
		}
		// NOW retains the source timestamp payload; backing notify_change uses now.
		if v.Valid&SetATime == 0 && (v.ATime != (Timestamp{}) || v.Valid&SetATimeNow != 0) || v.Valid&SetMTime == 0 && (v.MTime != (Timestamp{}) || v.Valid&SetMTimeNow != 0) {
			return invalid("setattr time selection")
		}
		if v.Semantics&(MetadataKillSUID|MetadataKillSGID) != 0 && v.Valid&SetMode != 0 {
			return invalid("setattr mode with kill")
		}
		if v.Semantics&MetadataForce != 0 && (v.Valid&(SetMode|SetUID|SetGID) != 0 || v.Semantics&(MetadataTimesSet|MetadataTouch) != 0 || v.Valid&SetATime != 0 && v.Valid&SetATimeNow == 0 || v.Valid&SetMTime != 0 && v.Valid&SetMTimeNow == 0) {
			return invalid("setattr force with user metadata")
		}
		if v.Semantics&MetadataOpen != 0 && (v.Valid&SetSize == 0 || v.Size != 0) || v.Semantics&MetadataFile != 0 && v.Handle == nil {
			return invalid("setattr open/file association")
		}
	case CreateRequest:
		if !openFlags(v.Flags) || v.Flags&OpenDirectory != 0 || v.FuseOpenFlags != 0 || !creationMode(v.Mode, 0100000) || v.Umask & ^uint32(0777) != 0 {
			return invalid("create flags/mode")
		}
		return component(v.Name)
	case OpenRequest:
		if !openFlags(v.Flags) || v.Flags&(OpenCreate|OpenExclusive) != 0 || v.FuseOpenFlags != 0 || v.Flags&OpenTruncate != 0 {
			return invalid("open flags")
		}

	case ReadRequest:
		if !ioRange(v.Offset, uint64(v.Size)) || v.Size > MaxIO || !openFlags(v.IOFlags) {
			return invalid("read bounds/flags")
		}
	case WriteRequest:
		if v.Data == nil || !ioRange(v.Offset, uint64(len(v.Data))) || len(v.Data) > MaxIO || !openFlags(v.IOFlags) || v.WriteFlags & ^uint32(WriteCache) != 0 {
			return invalid("write bounds/flags")
		}
		if v.WriteFlags&WriteCache != 0 && r.Auth.Kind != OpenGrantAuth {
			return invalid("cache write requires explicit grant provenance")
		}
	case FlushRequest, FsyncRequest, FsyncDirRequest:
	case ReleaseRequest:
		if v.ReleaseFlags & ^ReleaseFlush != 0 {
			return invalid("release flags")
		}
	case ReleaseDirRequest:
		if v.ReleaseFlags != 0 {
			return invalid("releasedir flags")
		}
	case OpenDirRequest:
		const mask = OpenNonblock | OpenDirectory | OpenLargeFile | OpenNoFollow | OpenNoATime | OpenCloseOnExec
		if v.Flags & ^uint32(mask) != 0 {
			return invalid("opendir flags")
		}
	case ReadDirRequest:
		if v.MaxBytes == 0 || v.MaxBytes > MaxIO || v.Cookie > math.MaxInt64 {
			return invalid("readdir bounds")
		}
	case MkdirRequest:
		if !creationMode(v.Mode, 0040000) || v.Umask & ^uint32(0777) != 0 {
			return invalid("mkdir mode")
		}
		return component(v.Name)
	case MknodRequest:
		if v.Mode & ^uint32(0177777) != 0 || v.Umask & ^uint32(0777) != 0 {
			return invalid("mknod mode")
		}
		switch v.Mode & 0170000 {
		case 0, 0100000, 0010000, 0140000:
			if v.Rdev != 0 {
				return invalid("nondevice rdev")
			}
		case 0020000, 0060000:
		default:
			return invalid("mknod type")
		}
		return component(v.Name)
	case SymlinkRequest:
		if err := target(v.Target); err != nil {
			return err
		}
		return component(v.Name)
	case ReadlinkRequest:
	case LinkRequest:
		return component(v.Name)
	case RenameRequest:
		if v.Flags != 0 && v.Flags != RenameNoReplace && v.Flags != RenameExchange {
			return invalid("rename flags")
		}
		if err := component(v.OldName); err != nil {
			return err
		}
		return component(v.NewName)
	case UnlinkRequest:
		return component(v.Name)
	case RmdirRequest:
		return component(v.Name)
	case AccessRequest:
		if v.Mask & ^uint32(7) != 0 {
			return invalid("access mask")
		}
	case GetXAttrRequest:
		if v.Size > MaxXAttr {
			return invalid("xattr size")
		}
		return xattrName(v.Name)
	case ListXAttrRequest:
		if v.Size > MaxXAttr {
			return invalid("xattr size")
		}
	case SetXAttrRequest:
		if v.Value == nil || len(v.Value) > MaxXAttr || v.Flags != 0 && v.Flags != XAttrCreate && v.Flags != XAttrReplace {
			return invalid("setxattr flags/value")
		}
		return xattrName(v.Name)
	case RemoveXAttrRequest:
		return xattrName(v.Name)
	case StatFSRequest:
	case ForgetRequest:
		if len(v.Entries) == 0 || len(v.Entries) > MaxForget {
			return invalid("forget bounds")
		}
		seen := map[NodeID]bool{}
		for _, e := range v.Entries {
			if e.Node == 0 || e.Count == 0 || seen[e.Node] {
				return invalid("forget node/count")
			}
			seen[e.Node] = true
		}
	case FallocateRequest:
		if v.Length == 0 || !ioRange(v.Offset, v.Length) {
			return invalid("fallocate range")
		}
		switch v.Mode {
		case 0, FallocateKeepSize, FallocateKeepSize | FallocatePunchHole, FallocateZeroRange, FallocateZeroRange | FallocateKeepSize:
		default:
			return invalid("fallocate mode")
		}
	case LseekRequest:
		if v.Offset > math.MaxInt64 || v.Whence != SeekData && v.Whence != SeekHole {
			return invalid("lseek range/whence")
		}
	}
	return nil
}
func validateNodeFields(body RequestBody) error {
	v := reflect.ValueOf(body)
	for i := 0; i < v.NumField(); i++ {
		switch n := v.Field(i).Interface().(type) {
		case NodeID:
			if n == 0 {
				return invalid("zero node")
			}
		case HandleID:
			if n == 0 {
				return invalid("zero handle")
			}
		case *HandleID:
			if n != nil && *n == 0 {
				return invalid("zero optional handle")
			}
		}
	}
	return nil
}
func openFlags(f uint32) bool {
	const mask = OpenAccessMask | OpenCreate | OpenExclusive | OpenNoCTTY | OpenTruncate | OpenAppend | OpenNonblock | OpenDSync | OpenAsync | OpenDirect | OpenLargeFile | OpenDirectory | OpenNoFollow | OpenNoATime | OpenCloseOnExec | OpenSync
	return f & ^uint32(mask) == 0 && f&OpenAccessMask != OpenAccessMask
}
func creationMode(mode, kind uint32) bool {
	return mode & ^uint32(0177777) == 0 && (mode&0170000 == 0 || mode&0170000 == kind)
}
func ioRange(offset, length uint64) bool {
	return offset <= math.MaxInt64 && length <= math.MaxInt64-offset
}
func timestamp(t Timestamp) bool { return t.Nanoseconds < 1_000_000_000 }
func component(b []byte) error {
	if len(b) == 0 || len(b) > MaxName || bytes.IndexByte(b, 0) >= 0 || bytes.IndexByte(b, '/') >= 0 || bytes.Equal(b, []byte(".")) || bytes.Equal(b, []byte("..")) {
		return invalid("component")
	}
	return nil
}
func xattrName(b []byte) error {
	if len(b) == 0 || len(b) > MaxName || bytes.IndexByte(b, 0) >= 0 {
		return invalid("xattr name")
	}
	return nil
}
func target(b []byte) error {
	if len(b) == 0 || len(b) > MaxTarget || bytes.IndexByte(b, 0) >= 0 {
		return invalid("symlink target")
	}
	return nil
}
func attr(a Attr) error {
	if a.Ino == 0 || a.Size > math.MaxInt64 || a.Mode & ^uint32(0177777) != 0 || !timestamp(a.ATime) || !timestamp(a.MTime) || !timestamp(a.CTime) {
		return invalid("attr")
	}
	if !fileType(a.Mode) {
		return invalid("attr file type")
	}
	return nil
}
func fileType(mode uint32) bool {
	switch mode & 0170000 {
	case 0010000, 0020000, 0040000, 0060000, 0100000, 0120000, 0140000:
		return true
	}
	return false
}
func entry(e Entry) error {
	if e.Node == 0 || e.Generation == 0 || e.Object == (ObjectID{}) {
		return invalid("entry identity")
	}
	return attr(e.Attr)
}
func opened(o Opened) error {
	if o.Handle == 0 {
		return invalid("opened handle")
	}
	return nil
}
func (r Reply) Validate() error {
	if r.Sequence == 0 || r.Errno > MaxLinuxErrno {
		return invalid("reply sequence/errno")
	}
	if _, ok := PolicyFor(r.Op); !ok {
		return invalid("reply operation")
	}
	if r.Errno != 0 {
		if r.Body == nil {
			return nil
		}
		size, ok := r.Body.(XAttrSizeError)
		if !ok || r.Errno != ErrnoERANGE || r.Op != OpGetXAttr && r.Op != OpListXAttr || size.Size == 0 || size.Size > MaxXAttr {
			return invalid("error body")
		}
		return nil
	}
	if !knownReplyBody(r.Body) || r.Body.Operation() != r.Op {
		return invalid("success body/operation")
	}
	// Common nested DTOs, independent of the operation-specific result shape.
	v := reflect.ValueOf(r.Body)
	for i := 0; i < v.NumField(); i++ {
		switch f := v.Field(i).Interface().(type) {
		case Entry:
			if err := entry(f); err != nil {
				return err
			}
		case Attr:
			if err := attr(f); err != nil {
				return err
			}
		case Opened:
			if err := opened(f); err != nil {
				return err
			}
		}
	}
	switch v := r.Body.(type) {
	case PrepareReply:
		return validatePrepareReply(v)
	case CreateReply:
		if v.Entry.Attr.Mode&0170000 != 0100000 {
			return invalid("create result type")
		}
	case MkdirReply:
		if v.Entry.Attr.Mode&0170000 != 0040000 {
			return invalid("mkdir result type")
		}
	case SymlinkReply:
		if v.Entry.Attr.Mode&0170000 != 0120000 {
			return invalid("symlink result type")
		}
	case ReadReply:
		if v.Data == nil || len(v.Data) > MaxIO {
			return invalid("read reply bounds")
		}
	case WriteReply:
		if v.Written > MaxIO {
			return invalid("write reply bounds")
		}
	case ReadlinkReply:
		return target(v.Target)
	case GetXAttrReply:
		if v.Value == nil || v.Size > MaxXAttr || len(v.Value) != 0 && len(v.Value) != int(v.Size) {
			return invalid("xattr reply")
		}
	case ListXAttrReply:
		if v.Names == nil || v.Size > MaxXAttr || len(v.Names) != 0 && len(v.Names) != int(v.Size) {
			return invalid("xattr list reply")
		}
		return xattrList(v.Names)
	case ReadDirReply:
		if v.Entries == nil || len(v.Entries) > MaxDirEntries {
			return invalid("readdir reply bounds")
		}
		seenCookies := map[uint64]bool{}
		seenNames := map[string]bool{}
		for _, e := range v.Entries {
			// Unlike namespace operands, directory results may include dot entries.
			if !bytes.Equal(e.Name, []byte(".")) && !bytes.Equal(e.Name, []byte("..")) {
				if err := component(e.Name); err != nil {
					return err
				}
			}
			if e.Ino == 0 || e.NextCookie == 0 || e.NextCookie > math.MaxInt64 || seenCookies[e.NextCookie] || seenNames[string(e.Name)] || e.Mode & ^uint32(0177777) != 0 || !fileType(e.Mode) {
				return invalid("directory entry")
			}
			seenCookies[e.NextCookie] = true
			seenNames[string(e.Name)] = true
		}
	case StatFSReply:
		s := v.Stat
		if s.BlockSize == 0 || s.FragmentSize == 0 || s.NameLength == 0 || s.NameLength > MaxName || s.BlocksAvailable > s.BlocksFree || s.BlocksFree > s.Blocks || s.FilesFree > s.Files {
			return invalid("statfs")
		}
	case LseekReply:
		if v.Offset > math.MaxInt64 {
			return invalid("lseek reply")
		}
	}
	return nil
}
func xattrList(b []byte) error {
	if len(b) > MaxXAttr {
		return invalid("xattr list bounds")
	}
	seen := map[string]bool{}
	for len(b) > 0 {
		n := bytes.IndexByte(b, 0)
		if n < 1 {
			return invalid("xattr list delimiter")
		}
		if err := xattrName(b[:n]); err != nil {
			return err
		}
		if seen[string(b[:n])] {
			return invalid("duplicate xattr")
		}
		seen[string(b[:n])] = true
		b = b[n+1:]
	}
	return nil
}

// DirEntryBytes is the aligned Linux fuse_dirent size; it excludes READDIRPLUS.
func DirEntryBytes(name []byte) uint32 { return uint32((24 + len(name) + 7) &^ 7) }

// ValidateReplyFor verifies correlation and limits that require the original
// request (short IO, xattr probe versus empty value, directory buffer/cookies).
func ValidateReplyFor(request Request, reply Reply) error {
	if err := request.Validate(); err != nil {
		return err
	}
	if err := reply.Validate(); err != nil {
		return err
	}
	if request.Sequence != reply.Sequence || request.Body.Operation() != reply.Op {
		return invalid("reply correlation")
	}
	if reply.Errno != 0 {
		if size, ok := reply.Body.(XAttrSizeError); ok {
			var capacity uint32
			switch r := request.Body.(type) {
			case GetXAttrRequest:
				capacity = r.Size
			case ListXAttrRequest:
				capacity = r.Size
			}
			if capacity == 0 || size.Size <= capacity {
				return invalid("ERANGE size/probe")
			}
		}
		return nil
	}
	switch r := request.Body.(type) {
	case PrepareRequest:
		return ValidatePrepareReplyFor(r, reply.Body.(PrepareReply))
	case MknodRequest:
		kind := r.Mode & 0170000
		if kind == 0 {
			kind = 0100000
		}
		if reply.Body.(MknodReply).Entry.Attr.Mode&0170000 != kind {
			return invalid("mknod result type")
		}
	case ReadRequest:
		if len(reply.Body.(ReadReply).Data) > int(r.Size) {
			return invalid("read exceeds requested size")
		}
	case WriteRequest:
		if int(reply.Body.(WriteReply).Written) > len(r.Data) {
			return invalid("write exceeds input")
		}
	case GetXAttrRequest:
		v := reply.Body.(GetXAttrReply)
		return xattrResult(r.Size, v.Size, v.Value)
	case ListXAttrRequest:
		v := reply.Body.(ListXAttrReply)
		return xattrResult(r.Size, v.Size, v.Names)
	case ReadDirRequest:
		var size uint64
		for _, e := range reply.Body.(ReadDirReply).Entries {
			size += uint64(DirEntryBytes(e.Name))
			if e.NextCookie == r.Cookie {
				return invalid("nonprogressing directory cookie")
			}
		}
		if size > uint64(r.MaxBytes) {
			return invalid("directory exceeds buffer")
		}
	}
	return nil
}
func xattrResult(capacity, size uint32, data []byte) error {
	if capacity == 0 {
		if len(data) != 0 {
			return invalid("probe returned data")
		}
		return nil
	}
	if size > capacity || len(data) != int(size) {
		return invalid("xattr result size")
	}
	return nil
}
func validID(id storageauthority.ID) bool {
	s := string(id)
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' || s[14] != '4' || s[19] != '8' && s[19] != '9' && s[19] != 'a' && s[19] != 'b' {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func canonicalHex(s string, n int) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == n && hex.EncodeToString(b) == s
}
func (h ServerHello) Validate() error {
	if !validID(h.Epoch) || h.Version != Version || h.Profile != RequiredProfile() {
		return invalid("server hello/profile")
	}
	return nil
}
func (h ClientHello) Validate() error {
	b := h.Authority.Binding
	if h.Profile != RequiredProfile() || !validID(h.Authority.Epoch) || !validID(b.Store) || !validID(b.Volume) || !validID(b.Attachment) || !validID(b.Launch) || !canonicalHex(string(b.Container), 32) || !canonicalHex(string(b.Key), 32) {
		return invalid("client hello/identity/profile")
	}
	if b.Mode != storageauthority.ReadOnly && b.Mode != storageauthority.ReadWrite {
		return invalid("hello mode")
	}
	switch b.Role {
	case storageauthority.RuntimeRole:
		if b.Prepare != "" {
			return invalid("runtime prepare")
		}
	case storageauthority.PrepareRole:
		if !validID(b.Prepare) {
			return invalid("prepare ID")
		}
	default:
		return invalid("hello role")
	}
	return nil
}
func (r RootReply) Validate() error {
	if r.Root.Attr.Mode&0170000 != 0040000 {
		return invalid("root is not directory")
	}
	return entry(r.Root)
}
func (e Event) Validate() error {
	if e.EventSequence == 0 || !validID(e.Volume) || e.Object == (ObjectID{}) || e.Name == nil {
		return invalid("event identity")
	}
	switch e.Kind {
	case InvalidateAttr:
		if e.Parent != (ObjectID{}) || len(e.Name) != 0 || e.Offset != 0 || e.Length != 0 {
			return invalid("attribute event body")
		}
	case InvalidateData:
		if e.Parent != (ObjectID{}) || len(e.Name) != 0 || !ioRange(e.Offset, e.Length) {
			return invalid("data event body")
		}
	case InvalidateEntry:
		if e.Parent == (ObjectID{}) || e.Offset != 0 || e.Length != 0 {
			return invalid("entry event body")
		}
		return component(e.Name)
	default:
		return invalid("event kind")
	}
	return nil
}

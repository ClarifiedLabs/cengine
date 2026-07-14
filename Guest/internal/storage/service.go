package storage

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"

	"dev.cengine/guest/internal/protocol"
	"golang.org/x/sys/unix"
)

const maxFrame = 64 << 20

var volumeName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

type service struct {
	baseFD int
	secret []byte
	mu sync.Mutex
	sessions map[*session]struct{}
}

type inodeKey struct { dev, ino uint64 }
type nodeRef struct { fd int; attr protocol.FSAttr }

type session struct {
	svc *service
	conn net.Conn
	reader *bufio.Reader
	writeMu sync.Mutex
	mu sync.Mutex
	nodes map[uint64]nodeRef
	byInode map[inodeKey]uint64
	handles map[uint64]int
	nextNode uint64
	nextHandle uint64
	volume string
}

func Serve(listener net.Listener, root string, secret []byte) error {
	if len(secret) < 32 { return errors.New("storage secret must be at least 32 bytes") }
	volumes := filepath.Join(root, "volumes")
	if err := os.MkdirAll(volumes, 0o700); err != nil { return err }
	baseFD, err := unix.Open(volumes, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil { return err }
	defer unix.Close(baseFD)
	svc := &service{baseFD: baseFD, secret: append([]byte(nil), secret...), sessions: map[*session]struct{}{}}
	for {
		conn, err := listener.Accept()
		if err != nil { return err }
		go svc.serve(conn)
	}
}

func (s *service) serve(conn net.Conn) {
	sess := &session{svc: s, conn: conn, reader: bufio.NewReader(conn), nodes: map[uint64]nodeRef{}, byInode: map[inodeKey]uint64{}, handles: map[uint64]int{}, nextNode: 2, nextHandle: 1}
	defer sess.close()
	first, err := readMessage(sess.reader)
	if err != nil || first.Request == nil || first.Request.Op != "handshake" { return }
	if err := sess.handshake(first.Request); err != nil {
		sess.reply(first.Request.ID, nil, err)
		return
	}
	s.register(sess)
	defer s.unregister(sess)
	if err := sess.reply(first.Request.ID, &protocol.FSResponseBody{Node: 1}, nil); err != nil { return }
	for {
		message, err := readMessage(sess.reader)
		if err != nil { return }
		if message.Version != protocol.CEngineFSVersion || message.Type != protocol.FSRequest || message.Request == nil { return }
		reply, opErr := sess.dispatch(message.Request)
		if err := sess.reply(message.Request.ID, reply, opErr); err != nil { return }
	}
}

func (s *service) register(sess *session) { s.mu.Lock(); s.sessions[sess] = struct{}{}; s.mu.Unlock() }
func (s *service) unregister(sess *session) { s.mu.Lock(); delete(s.sessions, sess); s.mu.Unlock() }

func (s *service) invalidate(volume string, event protocol.FSInvalidationEvent) {
	s.mu.Lock()
	targets := make([]*session, 0, len(s.sessions))
	for target := range s.sessions { if target.volume == volume { targets = append(targets, target) } }
	s.mu.Unlock()
	for _, target := range targets {
		_ = target.write(protocol.FSMessage{Version: protocol.CEngineFSVersion, Type: protocol.FSInvalidation, Event: &event})
	}
}

func (s *session) handshake(req *protocol.FSRequestBody) error {
	if !volumeName.MatchString(req.Volume) { return syscall.EINVAL }
	want := hmac.New(sha256.New, s.svc.secret); _, _ = want.Write([]byte(req.Volume))
	provided, err := hex.DecodeString(req.Token)
	if err != nil || !hmac.Equal(provided, want.Sum(nil)) { return syscall.EACCES }
	if err := unix.Mkdirat(s.svc.baseFD, req.Volume, 0o755); err != nil && !errors.Is(err, syscall.EEXIST) { return err }
	fd, err := openBeneath(s.svc.baseFD, req.Volume, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil { return err }
	attr, err := statFD(fd)
	if err != nil { unix.Close(fd); return err }
	s.nodes[1] = nodeRef{fd: fd, attr: attr}
	s.byInode[inodeKey{attr.Rdev >> 32, attr.Ino}] = 1
	s.volume = req.Volume
	return nil
}

func (s *session) dispatch(req *protocol.FSRequestBody) (*protocol.FSResponseBody, error) {
	s.mu.Lock(); defer s.mu.Unlock()
	switch req.Op {
	case "lookup":
		parent, err := s.node(req.Node); if err != nil { return nil, err }
		if err := validName(req.Name); err != nil { return nil, err }
		fd, err := openBeneath(parent.fd, req.Name, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0); if err != nil { return nil, err }
		id, attr, err := s.intern(fd); if err != nil { return nil, err }
		return &protocol.FSResponseBody{Node: id, Attr: &attr}, nil
	case "getattr":
		n, err := s.node(req.Node); if err != nil { return nil, err }
		attr, err := statFD(n.fd); if err != nil { return nil, err }
		return &protocol.FSResponseBody{Attr: &attr}, nil
	case "setattr": return s.setattr(req)
	case "open": return s.open(req)
	case "release":
		fd, err := s.handle(req.Handle); if err != nil { return nil, err }; delete(s.handles, req.Handle); return &protocol.FSResponseBody{}, unix.Close(fd)
	case "read":
		fd, err := s.handle(req.Handle); if err != nil { return nil, err }
		if req.Size < 0 || req.Size > maxFrame { return nil, syscall.EINVAL }
		data := make([]byte, req.Size); n, err := unix.Pread(fd, data, req.Offset); if err != nil { return nil, err }
		return &protocol.FSResponseBody{Data: data[:n]}, nil
	case "write":
		fd, err := s.handle(req.Handle); if err != nil { return nil, err }
		n, err := unix.Pwrite(fd, req.Data, req.Offset); if err != nil { return nil, err }
		s.svc.invalidate(s.volume, protocol.FSInvalidationEvent{Node: req.Node})
		return &protocol.FSResponseBody{Data: req.Data[:n]}, nil
	case "fsync":
		fd, err := s.handle(req.Handle); if err != nil { return nil, err }
		if req.Flags != 0 { return &protocol.FSResponseBody{}, unix.Fdatasync(fd) }
		return &protocol.FSResponseBody{}, unix.Fsync(fd)
	case "fsync-node":
		n, err := s.node(req.Node); if err != nil { return nil, err }
		return &protocol.FSResponseBody{}, fsyncNode(n.fd, req.Flags)
	case "flush":
		fd, err := s.handle(req.Handle); if err != nil { return nil, err }
		dup, err := unix.Dup(fd); if err == nil { err = unix.Close(dup) }; return &protocol.FSResponseBody{}, err
	case "create": return s.create(req)
	case "mkdir": return s.mkdir(req)
	case "mknod": return s.mknod(req)
	case "unlink", "rmdir": return s.unlink(req)
	case "rename": return s.rename(req)
	case "link": return s.link(req)
	case "symlink": return s.symlink(req)
	case "readlink": return s.readlink(req)
	case "opendir": return s.openDir(req)
	case "readdir": return s.readDir(req)
	case "getxattr": return s.getxattr(req)
	case "listxattr": return s.listxattr(req)
	case "setxattr": return s.setxattr(req)
	case "removexattr": return s.removexattr(req)
	case "statfs": return s.statfs(req)
	case "delete-volume": return &protocol.FSResponseBody{}, s.svc.deleteVolume(s)
	case "fallocate": return s.fallocate(req)
	case "lseek":
		fd,err:=s.handle(req.Handle);if err!=nil{return nil,err};offset,err:=unix.Seek(fd,req.Offset,int(req.Flags));return &protocol.FSResponseBody{Offset:offset},err
	case "getlk", "setlk", "setlkw": return s.lock(req)
	default: return nil, syscall.ENOSYS
	}
}

func fsyncNode(pathFD int, flags uint32) error {
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", pathFD), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil { return err }
	defer unix.Close(fd)
	var attr unix.Stat_t
	if err := unix.Fstat(fd, &attr); err != nil { return err }
	if flags != 0 && attr.Mode&unix.S_IFMT != unix.S_IFDIR { return unix.Fdatasync(fd) }
	return unix.Fsync(fd)
}

func (s *service) deleteVolume(owner *session) error {
	s.mu.Lock()
	for candidate := range s.sessions {
		if candidate != owner && candidate.volume == owner.volume { s.mu.Unlock(); return syscall.EBUSY }
	}
	s.mu.Unlock()
	root, err := owner.node(1); if err != nil { return err }
	if err := removeDirectoryContents(root.fd); err != nil { return err }
	return unix.Unlinkat(s.baseFD, owner.volume, unix.AT_REMOVEDIR)
}

func removeDirectoryContents(directory int) error {
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", directory), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); if err != nil { return err }
	file := os.NewFile(uintptr(fd), "remove-tree")
	names, err := file.Readdirnames(-1); _ = file.Close()
	if err != nil { return err }
	for _, name := range names {
		if name == "." || name == ".." { continue }
		var stat unix.Stat_t
		if err := unix.Fstatat(directory, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil { return err }
		if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			child, err := openBeneath(directory, name, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); if err != nil { return err }
			err = removeDirectoryContents(child); _ = unix.Close(child); if err != nil { return err }
			if err := unix.Unlinkat(directory, name, unix.AT_REMOVEDIR); err != nil { return err }
		} else if err := unix.Unlinkat(directory, name, 0); err != nil { return err }
	}
	return nil
}

func (s *session) node(id uint64) (nodeRef, error) { n, ok := s.nodes[id]; if !ok { return nodeRef{}, syscall.ESTALE }; return n, nil }
func (s *session) handle(id uint64) (int, error) { fd, ok := s.handles[id]; if !ok { return -1, syscall.EBADF }; return fd, nil }

func (s *session) intern(fd int) (uint64, protocol.FSAttr, error) {
	attr, err := statFD(fd); if err != nil { unix.Close(fd); return 0, protocol.FSAttr{}, err }
	key := inodeKey{dev: attr.Rdev >> 32, ino: attr.Ino}
	if id, ok := s.byInode[key]; ok { unix.Close(fd); return id, attr, nil }
	id := s.nextNode; s.nextNode++
	s.nodes[id] = nodeRef{fd: fd, attr: attr}; s.byInode[key] = id
	return id, attr, nil
}

func (s *session) open(req *protocol.FSRequestBody) (*protocol.FSResponseBody, error) {
	n, err := s.node(req.Node); if err != nil { return nil, err }
	flags := int(req.Flags)&(unix.O_ACCMODE|unix.O_APPEND|unix.O_NONBLOCK|unix.O_SYNC|unix.O_DSYNC|unix.O_DIRECT) | unix.O_CLOEXEC
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", n.fd), flags, 0); if err != nil { return nil, err }
	id := s.nextHandle; s.nextHandle++; s.handles[id] = fd
	return &protocol.FSResponseBody{Handle: id}, nil
}

func (s *session) create(req *protocol.FSRequestBody) (*protocol.FSResponseBody, error) {
	parent, err := s.node(req.Node); if err != nil { return nil, err }; if err := validName(req.Name); err != nil { return nil, err }
	flags := int(req.Flags)&(unix.O_ACCMODE|unix.O_APPEND|unix.O_EXCL|unix.O_TRUNC) | unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW
	fd, err := unix.Openat(parent.fd, req.Name, flags, req.Mode&0o7777); if err != nil { return nil, err }
	pathFD, err := openBeneath(parent.fd, req.Name, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0); if err != nil { unix.Close(fd); return nil, err }
	id, attr, err := s.intern(pathFD); if err != nil { unix.Close(fd); return nil, err }
	h := s.nextHandle; s.nextHandle++; s.handles[h] = fd
	s.svc.invalidate(s.volume, protocol.FSInvalidationEvent{Parent: req.Node, Name: req.Name, Node: id})
	return &protocol.FSResponseBody{Node: id, Handle: h, Attr: &attr}, nil
}

func (s *session) mkdir(req *protocol.FSRequestBody) (*protocol.FSResponseBody, error) {
	parent, err := s.node(req.Node); if err != nil { return nil, err }; if err := validName(req.Name); err != nil { return nil, err }
	if err := unix.Mkdirat(parent.fd, req.Name, req.Mode&0o7777); err != nil { return nil, err }
	fd, err := openBeneath(parent.fd, req.Name, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); if err != nil { return nil, err }
	id, attr, err := s.intern(fd); if err != nil { return nil, err }
	s.svc.invalidate(s.volume, protocol.FSInvalidationEvent{Parent: req.Node, Name: req.Name, Node: id})
	return &protocol.FSResponseBody{Node: id, Attr: &attr}, nil
}

func (s *session) mknod(req *protocol.FSRequestBody) (*protocol.FSResponseBody, error) {
	parent, err := s.node(req.Node); if err != nil { return nil, err }; if err := validName(req.Name); err != nil { return nil, err }
	if err := unix.Mknodat(parent.fd, req.Name, req.Mode, int(req.Size)); err != nil { return nil, err }
	fd, err := openBeneath(parent.fd, req.Name, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0); if err != nil { return nil, err }
	id, attr, err := s.intern(fd); if err != nil { return nil, err }
	s.svc.invalidate(s.volume, protocol.FSInvalidationEvent{Parent: req.Node, Name: req.Name, Node: id})
	return &protocol.FSResponseBody{Node: id, Attr: &attr}, nil
}

func (s *session) unlink(req *protocol.FSRequestBody) (*protocol.FSResponseBody, error) {
	parent, err := s.node(req.Node); if err != nil { return nil, err }; if err := validName(req.Name); err != nil { return nil, err }
	flags := 0; if req.Op == "rmdir" { flags = unix.AT_REMOVEDIR }
	if err := unix.Unlinkat(parent.fd, req.Name, flags); err != nil { return nil, err }
	s.svc.invalidate(s.volume, protocol.FSInvalidationEvent{Parent: req.Node, Name: req.Name})
	return &protocol.FSResponseBody{}, nil
}

func (s *session) rename(req *protocol.FSRequestBody) (*protocol.FSResponseBody, error) {
	oldParent, err := s.node(req.Node); if err != nil { return nil, err }; newParent, err := s.node(req.NewNode); if err != nil { return nil, err }
	if err := validName(req.Name); err != nil { return nil, err }; if err := validName(req.NewName); err != nil { return nil, err }
	if err := unix.Renameat2(oldParent.fd, req.Name, newParent.fd, req.NewName, uint(req.Flags)); err != nil { return nil, err }
	s.svc.invalidate(s.volume, protocol.FSInvalidationEvent{Parent: req.Node, Name: req.Name}); s.svc.invalidate(s.volume, protocol.FSInvalidationEvent{Parent: req.NewNode, Name: req.NewName})
	return &protocol.FSResponseBody{}, nil
}

func (s *session) link(req *protocol.FSRequestBody) (*protocol.FSResponseBody, error) {
	target, err := s.node(req.NewNode); if err != nil { return nil, err }; parent, err := s.node(req.Node); if err != nil { return nil, err }
	if err := validName(req.Name); err != nil { return nil, err }
	if err := unix.Linkat(target.fd, "", parent.fd, req.Name, unix.AT_EMPTY_PATH); err != nil { return nil, err }
	s.svc.invalidate(s.volume, protocol.FSInvalidationEvent{Parent: req.Node, Name: req.Name, Node: req.NewNode})
	attr, err := statFD(target.fd); return &protocol.FSResponseBody{Node: req.NewNode, Attr: &attr}, err
}

func (s *session) symlink(req *protocol.FSRequestBody) (*protocol.FSResponseBody, error) {
	parent, err := s.node(req.Node); if err != nil { return nil, err }; if err := validName(req.Name); err != nil { return nil, err }
	if err := unix.Symlinkat(req.Target, parent.fd, req.Name); err != nil { return nil, err }
	fd, err := openBeneath(parent.fd, req.Name, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0); if err != nil { return nil, err }
	id, attr, err := s.intern(fd); if err != nil { return nil, err }
	s.svc.invalidate(s.volume, protocol.FSInvalidationEvent{Parent: req.Node, Name: req.Name, Node: id})
	return &protocol.FSResponseBody{Node: id, Attr: &attr}, nil
}

func (s *session) readlink(req *protocol.FSRequestBody) (*protocol.FSResponseBody, error) {
	n, err := s.node(req.Node); if err != nil { return nil, err }
	buf := make([]byte, 4096); count, err := unix.Readlinkat(n.fd, "", buf); if err != nil { return nil, err }
	return &protocol.FSResponseBody{Data: buf[:count]}, nil
}

func (s *session) openDir(req *protocol.FSRequestBody) (*protocol.FSResponseBody, error) {
	n, err := s.node(req.Node); if err != nil { return nil, err }
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", n.fd), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); if err != nil { return nil, err }
	id := s.nextHandle; s.nextHandle++; s.handles[id] = fd; return &protocol.FSResponseBody{Handle: id}, nil
}

func (s *session) readDir(req *protocol.FSRequestBody) (*protocol.FSResponseBody, error) {
	fd, err := s.handle(req.Handle); if err != nil { return nil, err }
	dup, err := unix.Dup(fd); if err != nil { return nil, err }; file := os.NewFile(uintptr(dup), "directory"); defer file.Close()
	entries, err := file.ReadDir(-1); if err != nil { return nil, err }
	sort.Slice(entries, func(i,j int) bool { return entries[i].Name() < entries[j].Name() })
	out := make([]protocol.FSDirEntry, 0, len(entries))
	parent, _ := s.node(req.Node)
	for _, entry := range entries {
		childFD, openErr := openBeneath(parent.fd, entry.Name(), unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0); if openErr != nil { continue }
		id, attr, internErr := s.intern(childFD); if internErr != nil { continue }
		out = append(out, protocol.FSDirEntry{Name: entry.Name(), Node: id, Mode: attr.Mode})
	}
	return &protocol.FSResponseBody{Entries: out}, nil
}

func (s *session) setattr(req *protocol.FSRequestBody) (*protocol.FSResponseBody, error) {
	n, err := s.node(req.Node); if err != nil { return nil, err }
	current, err := statFD(n.fd); if err != nil { return nil, err }
	if req.Flags&2 != 0 || req.Flags&4 != 0 { uid, gid := -1, -1; if req.UID != nil { uid = int(*req.UID) }; if req.GID != nil { gid = int(*req.GID) }; if err := unix.Fchownat(n.fd, "", uid, gid, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil { return nil, err } }
	if req.Flags&(16|32)!=0{times:=[]unix.Timespec{{Nsec:unix.UTIME_OMIT},{Nsec:unix.UTIME_OMIT}};if req.ATimeNS!=nil{times[0]=unix.NsecToTimespec(*req.ATimeNS)};if req.MTimeNS!=nil{times[1]=unix.NsecToTimespec(*req.MTimeNS)};if err:=unix.UtimesNanoAt(n.fd,"",times,unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW);err!=nil{return nil,err}}
	if current.Mode&unix.S_IFMT == unix.S_IFLNK {
		if req.Flags&(1|8) != 0 { return nil, syscall.EPERM }
		attr, err := statFD(n.fd); if err == nil { s.svc.invalidate(s.volume, protocol.FSInvalidationEvent{Node: req.Node}) }; return &protocol.FSResponseBody{Attr:&attr},err
	}
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", n.fd), setattrOpenFlags(req), 0); if err != nil { return nil, err }; defer unix.Close(fd)
	if req.Flags&1 != 0 { if err := unix.Fchmod(fd, req.Mode); err != nil { return nil, err } }
	if req.Flags&8 != 0 { if err := unix.Ftruncate(fd, req.Size); err != nil { return nil, err } }
	attr, err := statFD(n.fd); if err == nil { s.svc.invalidate(s.volume, protocol.FSInvalidationEvent{Node: req.Node}) }
	return &protocol.FSResponseBody{Attr: &attr}, err
}

func setattrOpenFlags(req *protocol.FSRequestBody) int {
	flags := unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC
	if req.Flags&8 != 0 {
		flags = unix.O_RDWR | unix.O_NONBLOCK | unix.O_CLOEXEC
	}
	return flags
}

func (s *session) xattrFD(node uint64) (int, error) { n, err := s.node(node); if err != nil { return -1, err }; attr,err:=statFD(n.fd);if err!=nil{return -1,err};if attr.Mode&unix.S_IFMT==unix.S_IFLNK{return -1,syscall.ENOTSUP};return unix.Open(fmt.Sprintf("/proc/self/fd/%d", n.fd), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0) }
func (s *session) nodeIsSymlink(node uint64) (bool,error) { n,err:=s.node(node);if err!=nil{return false,err};attr,err:=statFD(n.fd);return attr.Mode&unix.S_IFMT==unix.S_IFLNK,err }
func (s *session) getxattr(req *protocol.FSRequestBody) (*protocol.FSResponseBody, error) { symlink,err:=s.nodeIsSymlink(req.Node);if err!=nil{return nil,err};if symlink{return nil,syscall.ENODATA};fd, err := s.xattrFD(req.Node); if err != nil { return nil, err }; defer unix.Close(fd); size, err := unix.Fgetxattr(fd, req.Xattr, nil); if err != nil { return nil, err }; data := make([]byte,size); _, err = unix.Fgetxattr(fd,req.Xattr,data); return &protocol.FSResponseBody{Data:data},err }
func (s *session) listxattr(req *protocol.FSRequestBody) (*protocol.FSResponseBody, error) { symlink,err:=s.nodeIsSymlink(req.Node);if err!=nil{return nil,err};if symlink{return &protocol.FSResponseBody{},nil};fd, err := s.xattrFD(req.Node); if err != nil { return nil, err }; defer unix.Close(fd); size, err := unix.Flistxattr(fd,nil); if err != nil { return nil, err }; data:=make([]byte,size); _,err=unix.Flistxattr(fd,data); if err != nil{return nil,err}; names:=strings.Split(strings.TrimRight(string(data),"\x00"),"\x00"); if len(names)==1&&names[0]==""{names=nil}; return &protocol.FSResponseBody{Names:names},nil }
func (s *session) setxattr(req *protocol.FSRequestBody) (*protocol.FSResponseBody, error) { fd, err:=s.xattrFD(req.Node); if err!=nil{return nil,err}; defer unix.Close(fd); err=unix.Fsetxattr(fd,req.Xattr,req.Value,int(req.Flags)); if err==nil{s.svc.invalidate(s.volume,protocol.FSInvalidationEvent{Node:req.Node})}; return &protocol.FSResponseBody{},err }
func (s *session) removexattr(req *protocol.FSRequestBody) (*protocol.FSResponseBody, error) { fd, err:=s.xattrFD(req.Node); if err!=nil{return nil,err}; defer unix.Close(fd); err=unix.Fremovexattr(fd,req.Xattr); if err==nil{s.svc.invalidate(s.volume,protocol.FSInvalidationEvent{Node:req.Node})}; return &protocol.FSResponseBody{},err }

func (s *session) statfs(req *protocol.FSRequestBody) (*protocol.FSResponseBody,error) { n,err:=s.node(req.Node);if err!=nil{return nil,err};var st unix.Statfs_t;if err=unix.Fstatfs(n.fd,&st);err!=nil{return nil,err};return &protocol.FSResponseBody{StatFS:&protocol.FSStatFS{Blocks:st.Blocks,Bfree:st.Bfree,Bavail:st.Bavail,Files:st.Files,Ffree:st.Ffree,Bsize:uint32(st.Bsize),Namelen:uint32(st.Namelen),Frsize:uint32(st.Frsize)}},nil }
func (s *session) fallocate(req *protocol.FSRequestBody)(*protocol.FSResponseBody,error){fd,err:=s.handle(req.Handle);if err!=nil{return nil,err};err=unix.Fallocate(fd,req.Mode,req.Offset,req.Size);return &protocol.FSResponseBody{},err}
func (s *session) lock(req *protocol.FSRequestBody)(*protocol.FSResponseBody,error){fd,err:=s.handle(req.Handle);if err!=nil{return nil,err};if req.Lock==nil{return nil,syscall.EINVAL};fl:=unix.Flock_t{Type:req.Lock.Type,Whence:unix.SEEK_SET,Start:int64(req.Lock.Start),Len:int64(req.Lock.End-req.Lock.Start+1)};cmd:=unix.F_OFD_SETLK;if req.Op=="getlk"{cmd=unix.F_OFD_GETLK}else if req.Op=="setlkw"{cmd=unix.F_OFD_SETLKW};if err=unix.FcntlFlock(uintptr(fd),cmd,&fl);err!=nil{return nil,err};return &protocol.FSResponseBody{Lock:&protocol.FSLock{Type:fl.Type,Start:uint64(fl.Start),End:uint64(fl.Start+fl.Len-1),PID:uint32(max(fl.Pid,0))}},nil}

func (s *session) reply(id uint64, body *protocol.FSResponseBody, err error) error { if body==nil{body=&protocol.FSResponseBody{}};body.ID=id;if err!=nil{body.Errno=errno(err)};return s.write(protocol.FSMessage{Version:protocol.CEngineFSVersion,Type:protocol.FSResponse,Reply:body}) }
func (s *session) write(message protocol.FSMessage) error { s.writeMu.Lock();defer s.writeMu.Unlock();data,err:=json.Marshal(message);if err!=nil{return err};if len(data)>maxFrame{return syscall.E2BIG};var header [4]byte;binary.BigEndian.PutUint32(header[:],uint32(len(data)));if err=writeAll(s.conn,header[:]);err!=nil{return err};return writeAll(s.conn,data) }

func (s *session) close(){s.mu.Lock();for _,fd:=range s.handles{_ = unix.Close(fd)};for _,n:=range s.nodes{_ = unix.Close(n.fd)};s.handles=nil;s.nodes=nil;s.mu.Unlock();_ = s.conn.Close()}
func readMessage(r io.Reader)(protocol.FSMessage,error){var h[4]byte;if _,err:=io.ReadFull(r,h[:]);err!=nil{return protocol.FSMessage{},err};n:=binary.BigEndian.Uint32(h[:]);if n==0||n>maxFrame{return protocol.FSMessage{},syscall.E2BIG};data:=make([]byte,n);if _,err:=io.ReadFull(r,data);err!=nil{return protocol.FSMessage{},err};var m protocol.FSMessage;if err:=json.Unmarshal(data,&m);err!=nil{return m,err};return m,nil}
func openBeneath(dirfd int,path string,flags int,mode uint64)(int,error){how:=&unix.OpenHow{Flags:uint64(flags),Mode:mode,Resolve:unix.RESOLVE_BENEATH|unix.RESOLVE_NO_MAGICLINKS};return unix.Openat2(dirfd,path,how)}
func validName(name string)error{if name==""||name=="."||name==".."||strings.ContainsRune(name,'/')||strings.ContainsRune(name,0){return syscall.EINVAL};return nil}
func statFD(fd int)(protocol.FSAttr,error){var st unix.Stat_t;if err:=unix.Fstat(fd,&st);err!=nil{return protocol.FSAttr{},err};return protocol.FSAttr{Ino:st.Ino,Size:uint64(st.Size),Blocks:uint64(st.Blocks),ATimeNS:st.Atim.Sec*1e9+st.Atim.Nsec,MTimeNS:st.Mtim.Sec*1e9+st.Mtim.Nsec,CTimeNS:st.Ctim.Sec*1e9+st.Ctim.Nsec,Mode:st.Mode,Nlink:uint32(st.Nlink),UID:st.Uid,GID:st.Gid,Rdev:(uint64(st.Dev)<<32)|uint64(st.Rdev),Blksize:uint32(st.Blksize)},nil}
func errno(err error)int{if err==nil{return 0};var e syscall.Errno;if errors.As(err,&e){return int(e)};return int(syscall.EIO)}
func writeAll(writer io.Writer,data []byte)error{for len(data)>0{count,err:=writer.Write(data);if err!=nil{return err};if count==0{return io.ErrShortWrite};data=data[count:]};return nil}

package cenginefs

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"dev.cengine/guest/internal/protocol"
	"dev.cengine/guest/internal/vsock"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

const maxFrame = 64 << 20

type client struct {
	conn      net.Conn
	reader    *bufio.Reader
	writeMu   sync.Mutex
	pendingMu sync.Mutex
	pending   map[uint64]chan result
	next      atomic.Uint64
	serverMu  sync.RWMutex
	server    *fuse.Server
	closed    chan struct{}
	closeOnce sync.Once
}

type result struct {
	reply *protocol.FSResponseBody
	err   error
}

type node struct {
	fs.Inode
	client *client
	remote uint64
}
type fileHandle struct {
	client       *client
	remoteNode   uint64
	remoteHandle uint64
	once         sync.Once
}

func Mount(destination, volume, token string) (*fuse.Server, error) {
	if err := os.MkdirAll(destination, 0o755); err != nil {
		return nil, err
	}
	conn, err := dial(protocol.CEngineFSPort)
	if err != nil {
		return nil, err
	}
	c := &client{conn: conn, reader: bufio.NewReader(conn), pending: map[uint64]chan result{}, closed: make(chan struct{})}
	go c.receive()
	if _, err := c.call(&protocol.FSRequestBody{Op: "handshake", Volume: volume, Token: token}); err != nil {
		c.close(err)
		return nil, err
	}
	root := &node{client: c, remote: 1}
	options := mountOptions()
	server, err := fs.Mount(destination, root, options)
	if err != nil {
		c.close(err)
		return nil, err
	}
	c.serverMu.Lock()
	c.server = server
	c.serverMu.Unlock()
	go func() { server.Wait(); c.close(io.EOF) }()
	return server, nil
}

func duration(value time.Duration) *time.Duration { return &value }

func mountOptions() *fs.Options {
	return &fs.Options{
		MountOptions: fuse.MountOptions{
			AllowOther:        true,
			DirectMountStrict: true,
			Options:           []string{"default_permissions"},
		},
		EntryTimeout:    duration(0),
		AttrTimeout:     duration(0),
		NegativeTimeout: duration(0),
	}
}

func dial(port uint32) (net.Conn, error) {
	return vsock.Dial(port)
}

func (c *client) call(req *protocol.FSRequestBody) (*protocol.FSResponseBody, error) {
	id := c.next.Add(1)
	req.ID = id
	ch := make(chan result, 1)
	c.pendingMu.Lock()
	c.pending[id] = ch
	c.pendingMu.Unlock()
	if err := c.write(protocol.FSMessage{Version: protocol.CEngineFSVersion, Type: protocol.FSRequest, Request: req}); err != nil {
		c.pendingMu.Lock()
		delete(c.pending, id)
		c.pendingMu.Unlock()
		return nil, err
	}
	select {
	case got := <-ch:
		return got.reply, got.err
	case <-c.closed:
		return nil, syscall.EIO
	}
}

func (c *client) write(message protocol.FSMessage) error {
	data, err := json.Marshal(message)
	if err != nil {
		return err
	}
	if len(data) > maxFrame {
		return syscall.E2BIG
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err = writeAll(c.conn, header[:]); err != nil {
		return err
	}
	return writeAll(c.conn, data)
}

func (c *client) receive() {
	for {
		message, err := readMessage(c.reader)
		if err != nil {
			c.close(err)
			return
		}
		if message.Version != protocol.CEngineFSVersion {
			c.close(syscall.EPROTO)
			return
		}
		switch message.Type {
		case protocol.FSResponse:
			if message.Reply == nil {
				continue
			}
			c.pendingMu.Lock()
			ch := c.pending[message.Reply.ID]
			delete(c.pending, message.Reply.ID)
			c.pendingMu.Unlock()
			if ch != nil {
				if message.Reply.Errno != 0 {
					ch <- result{err: syscall.Errno(message.Reply.Errno)}
				} else {
					ch <- result{reply: message.Reply}
				}
			}
		case protocol.FSInvalidation:
			if message.Event != nil {
				c.invalidate(*message.Event)
			}
		}
	}
}

func (c *client) invalidate(event protocol.FSInvalidationEvent) {
	c.serverMu.RLock()
	server := c.server
	c.serverMu.RUnlock()
	if server == nil {
		return
	}
	if event.Parent != 0 && event.Name != "" {
		_ = server.EntryNotify(event.Parent, event.Name)
	}
	if event.Node != 0 {
		_ = server.InodeNotify(event.Node, 0, 0)
	}
}

func (c *client) close(reason error) {
	c.closeOnce.Do(func() {
		close(c.closed)
		_ = c.conn.Close()
		c.pendingMu.Lock()
		for id, ch := range c.pending {
			delete(c.pending, id)
			ch <- result{err: reason}
		}
		c.pendingMu.Unlock()
	})
}

func (n *node) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	reply, err := n.client.call(&protocol.FSRequestBody{Op: "lookup", Node: n.remote, Name: name})
	if err != nil {
		return nil, toErrno(err)
	}
	child := &node{client: n.client, remote: reply.Node}
	fillEntry(out, reply.Attr)
	out.Attr.Ino = reply.Node
	return n.NewInode(ctx, child, fs.StableAttr{Mode: reply.Attr.Mode & syscall.S_IFMT, Ino: reply.Node}), 0
}
func (n *node) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	reply, err := n.client.call(&protocol.FSRequestBody{Op: "getattr", Node: n.remote})
	if err != nil {
		return toErrno(err)
	}
	fillAttr(&out.Attr, reply.Attr)
	out.Attr.Ino = n.remote
	out.SetTimeout(0)
	return 0
}
func (n *node) Setattr(ctx context.Context, fh fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	req := &protocol.FSRequestBody{Op: "setattr", Node: n.remote}
	if mode, ok := in.GetMode(); ok {
		req.Flags |= 1
		req.Mode = mode
	}
	if uid, ok := in.GetUID(); ok {
		req.Flags |= 2
		req.UID = &uid
	}
	if gid, ok := in.GetGID(); ok {
		req.Flags |= 4
		req.GID = &gid
	}
	if size, ok := in.GetSize(); ok {
		req.Flags |= 8
		req.Size = int64(size)
	}
	if value, ok := in.GetATime(); ok {
		nanoseconds := value.UnixNano()
		req.Flags |= 16
		req.ATimeNS = &nanoseconds
	}
	if value, ok := in.GetMTime(); ok {
		nanoseconds := value.UnixNano()
		req.Flags |= 32
		req.MTimeNS = &nanoseconds
	}
	reply, err := n.client.call(req)
	if err != nil {
		return toErrno(err)
	}
	fillAttr(&out.Attr, reply.Attr)
	out.Attr.Ino = n.remote
	out.SetTimeout(0)
	return 0
}
func (n *node) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	reply, err := n.client.call(&protocol.FSRequestBody{Op: "open", Node: n.remote, Flags: flags})
	if err != nil {
		return nil, 0, toErrno(err)
	}
	return &fileHandle{client: n.client, remoteNode: n.remote, remoteHandle: reply.Handle}, fuse.FOPEN_DIRECT_IO, 0
}
func (n *node) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	reply, err := n.client.call(&protocol.FSRequestBody{Op: "create", Node: n.remote, Name: name, Flags: flags, Mode: mode})
	if err != nil {
		return nil, nil, 0, toErrno(err)
	}
	child := &node{client: n.client, remote: reply.Node}
	fillEntry(out, reply.Attr)
	out.Attr.Ino = reply.Node
	inode := n.NewInode(ctx, child, fs.StableAttr{Mode: reply.Attr.Mode & syscall.S_IFMT, Ino: reply.Node})
	handle := &fileHandle{client: n.client, remoteNode: reply.Node, remoteHandle: reply.Handle}
	return inode, handle, fuse.FOPEN_DIRECT_IO, 0
}
func (n *node) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	reply, err := n.client.call(&protocol.FSRequestBody{Op: "mkdir", Node: n.remote, Name: name, Mode: mode})
	if err != nil {
		return nil, toErrno(err)
	}
	fillEntry(out, reply.Attr)
	out.Attr.Ino = reply.Node
	return n.NewInode(ctx, &node{client: n.client, remote: reply.Node}, fs.StableAttr{Mode: reply.Attr.Mode & syscall.S_IFMT, Ino: reply.Node}), 0
}
func (n *node) Mknod(ctx context.Context, name string, mode uint32, rdev uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	reply, err := n.client.call(&protocol.FSRequestBody{Op: "mknod", Node: n.remote, Name: name, Mode: mode, Size: int64(rdev)})
	if err != nil {
		return nil, toErrno(err)
	}
	fillEntry(out, reply.Attr)
	out.Attr.Ino = reply.Node
	return n.NewInode(ctx, &node{client: n.client, remote: reply.Node}, fs.StableAttr{Mode: reply.Attr.Mode & syscall.S_IFMT, Ino: reply.Node}), 0
}
func (n *node) Unlink(ctx context.Context, name string) syscall.Errno {
	_, err := n.client.call(&protocol.FSRequestBody{Op: "unlink", Node: n.remote, Name: name})
	return toErrno(err)
}
func (n *node) Rmdir(ctx context.Context, name string) syscall.Errno {
	_, err := n.client.call(&protocol.FSRequestBody{Op: "rmdir", Node: n.remote, Name: name})
	return toErrno(err)
}
func (n *node) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	parent, ok := newParent.(*node)
	if !ok {
		return syscall.EXDEV
	}
	_, err := n.client.call(&protocol.FSRequestBody{Op: "rename", Node: n.remote, Name: name, NewNode: parent.remote, NewName: newName, Flags: flags})
	return toErrno(err)
}
func (n *node) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	source, ok := target.(*node)
	if !ok {
		return nil, syscall.EXDEV
	}
	reply, err := n.client.call(&protocol.FSRequestBody{Op: "link", Node: n.remote, Name: name, NewNode: source.remote})
	if err != nil {
		return nil, toErrno(err)
	}
	fillEntry(out, reply.Attr)
	out.Attr.Ino = reply.Node
	return n.NewInode(ctx, &node{client: n.client, remote: reply.Node}, fs.StableAttr{Mode: reply.Attr.Mode & syscall.S_IFMT, Ino: reply.Node}), 0
}
func (n *node) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	reply, err := n.client.call(&protocol.FSRequestBody{Op: "symlink", Node: n.remote, Name: name, Target: target})
	if err != nil {
		return nil, toErrno(err)
	}
	fillEntry(out, reply.Attr)
	out.Attr.Ino = reply.Node
	return n.NewInode(ctx, &node{client: n.client, remote: reply.Node}, fs.StableAttr{Mode: reply.Attr.Mode & syscall.S_IFMT, Ino: reply.Node}), 0
}
func (n *node) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	reply, err := n.client.call(&protocol.FSRequestBody{Op: "readlink", Node: n.remote})
	if err != nil {
		return nil, toErrno(err)
	}
	return reply.Data, 0
}
func (n *node) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	opened, err := n.client.call(&protocol.FSRequestBody{Op: "opendir", Node: n.remote})
	if err != nil {
		return nil, toErrno(err)
	}
	reply, err := n.client.call(&protocol.FSRequestBody{Op: "readdir", Node: n.remote, Handle: opened.Handle})
	_, _ = n.client.call(&protocol.FSRequestBody{Op: "release", Handle: opened.Handle})
	if err != nil {
		return nil, toErrno(err)
	}
	entries := make([]fuse.DirEntry, 0, len(reply.Entries))
	for _, entry := range reply.Entries {
		entries = append(entries, fuse.DirEntry{Name: entry.Name, Mode: entry.Mode, Ino: entry.Node})
	}
	return fs.NewListDirStream(entries), 0
}
func (n *node) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	reply, err := n.client.call(&protocol.FSRequestBody{Op: "getxattr", Node: n.remote, Xattr: attr})
	if err != nil {
		return 0, toErrno(err)
	}
	if len(dest) == 0 {
		return uint32(len(reply.Data)), 0
	}
	if len(dest) < len(reply.Data) {
		return uint32(len(reply.Data)), syscall.ERANGE
	}
	copy(dest, reply.Data)
	return uint32(len(reply.Data)), 0
}
func (n *node) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
	reply, err := n.client.call(&protocol.FSRequestBody{Op: "listxattr", Node: n.remote})
	if err != nil {
		return 0, toErrno(err)
	}
	size := 0
	for _, name := range reply.Names {
		size += len(name) + 1
	}
	if len(dest) == 0 {
		return uint32(size), 0
	}
	if len(dest) < size {
		return uint32(size), syscall.ERANGE
	}
	offset := 0
	for _, name := range reply.Names {
		copy(dest[offset:], name)
		offset += len(name)
		dest[offset] = 0
		offset++
	}
	return uint32(size), 0
}
func (n *node) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
	_, err := n.client.call(&protocol.FSRequestBody{Op: "setxattr", Node: n.remote, Xattr: attr, Value: data, Flags: flags})
	return toErrno(err)
}
func (n *node) Removexattr(ctx context.Context, attr string) syscall.Errno {
	_, err := n.client.call(&protocol.FSRequestBody{Op: "removexattr", Node: n.remote, Xattr: attr})
	return toErrno(err)
}
func (n *node) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	reply, err := n.client.call(&protocol.FSRequestBody{Op: "statfs", Node: n.remote})
	if err != nil {
		return toErrno(err)
	}
	st := reply.StatFS
	out.Blocks = st.Blocks
	out.Bfree = st.Bfree
	out.Bavail = st.Bavail
	out.Files = st.Files
	out.Ffree = st.Ffree
	out.Bsize = st.Bsize
	out.NameLen = st.Namelen
	out.Frsize = st.Frsize
	return 0
}

func (f *fileHandle) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	reply, err := f.client.call(&protocol.FSRequestBody{Op: "read", Node: f.remoteNode, Handle: f.remoteHandle, Offset: off, Size: int64(len(dest))})
	if err != nil {
		return nil, toErrno(err)
	}
	return fuse.ReadResultData(reply.Data), 0
}
func (f *fileHandle) Write(ctx context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	reply, err := f.client.call(&protocol.FSRequestBody{Op: "write", Node: f.remoteNode, Handle: f.remoteHandle, Offset: off, Data: data})
	if err != nil {
		return 0, toErrno(err)
	}
	return uint32(len(reply.Data)), 0
}
func (f *fileHandle) Flush(ctx context.Context) syscall.Errno {
	_, err := f.client.call(&protocol.FSRequestBody{Op: "flush", Handle: f.remoteHandle})
	return toErrno(err)
}
func (f *fileHandle) Fsync(ctx context.Context, flags uint32) syscall.Errno {
	_, err := f.client.call(&protocol.FSRequestBody{Op: "fsync", Handle: f.remoteHandle, Flags: flags})
	return toErrno(err)
}
func (f *fileHandle) Release(ctx context.Context) syscall.Errno {
	var result syscall.Errno
	f.once.Do(func() {
		_, err := f.client.call(&protocol.FSRequestBody{Op: "release", Handle: f.remoteHandle})
		result = toErrno(err)
	})
	return result
}
func (f *fileHandle) Allocate(ctx context.Context, off, size uint64, mode uint32) syscall.Errno {
	_, err := f.client.call(&protocol.FSRequestBody{Op: "fallocate", Handle: f.remoteHandle, Offset: int64(off), Size: int64(size), Mode: mode})
	return toErrno(err)
}
func (f *fileHandle) Getlk(ctx context.Context, owner uint64, lock *fuse.FileLock, flags uint32, out *fuse.FileLock) syscall.Errno {
	reply, err := f.client.call(&protocol.FSRequestBody{Op: "getlk", Handle: f.remoteHandle, Flags: flags, Lock: &protocol.FSLock{Type: int16(lock.Typ), Start: lock.Start, End: lock.End, PID: lock.Pid}})
	if err != nil {
		return toErrno(err)
	}
	if reply.Lock != nil {
		out.Typ = uint32(reply.Lock.Type)
		out.Start = reply.Lock.Start
		out.End = reply.Lock.End
		out.Pid = reply.Lock.PID
	}
	return 0
}
func (f *fileHandle) Setlk(ctx context.Context, owner uint64, lock *fuse.FileLock, flags uint32) syscall.Errno {
	_, err := f.client.call(&protocol.FSRequestBody{Op: "setlk", Handle: f.remoteHandle, Flags: flags, Lock: &protocol.FSLock{Type: int16(lock.Typ), Start: lock.Start, End: lock.End, PID: lock.Pid}})
	return toErrno(err)
}
func (f *fileHandle) Setlkw(ctx context.Context, owner uint64, lock *fuse.FileLock, flags uint32) syscall.Errno {
	_, err := f.client.call(&protocol.FSRequestBody{Op: "setlkw", Handle: f.remoteHandle, Flags: flags, Lock: &protocol.FSLock{Type: int16(lock.Typ), Start: lock.Start, End: lock.End, PID: lock.Pid}})
	return toErrno(err)
}
func (f *fileHandle) Lseek(ctx context.Context, off uint64, whence uint32) (uint64, syscall.Errno) {
	reply, err := f.client.call(&protocol.FSRequestBody{Op: "lseek", Handle: f.remoteHandle, Offset: int64(off), Flags: whence})
	if err != nil {
		return 0, toErrno(err)
	}
	return uint64(reply.Offset), 0
}

func fillEntry(out *fuse.EntryOut, attr *protocol.FSAttr) {
	fillAttr(&out.Attr, attr)
	out.SetEntryTimeout(0)
	out.SetAttrTimeout(0)
}
func fillAttr(out *fuse.Attr, attr *protocol.FSAttr) {
	if attr == nil {
		return
	}
	out.Ino = attr.Ino
	out.Size = attr.Size
	out.Blocks = attr.Blocks
	out.Atime = uint64(attr.ATimeNS / 1e9)
	out.Atimensec = uint32(attr.ATimeNS % 1e9)
	out.Mtime = uint64(attr.MTimeNS / 1e9)
	out.Mtimensec = uint32(attr.MTimeNS % 1e9)
	out.Ctime = uint64(attr.CTimeNS / 1e9)
	out.Ctimensec = uint32(attr.CTimeNS % 1e9)
	out.Mode = attr.Mode
	out.Nlink = attr.Nlink
	out.Owner.Uid = attr.UID
	out.Owner.Gid = attr.GID
	out.Rdev = uint32(attr.Rdev)
	out.Blksize = attr.Blksize
}
func toErrno(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	var value syscall.Errno
	if errors.As(err, &value) {
		return value
	}
	return syscall.EIO
}
func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
func readMessage(r io.Reader) (protocol.FSMessage, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return protocol.FSMessage{}, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > maxFrame {
		return protocol.FSMessage{}, syscall.E2BIG
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return protocol.FSMessage{}, err
	}
	var message protocol.FSMessage
	if err := json.Unmarshal(data, &message); err != nil {
		return message, err
	}
	return message, nil
}

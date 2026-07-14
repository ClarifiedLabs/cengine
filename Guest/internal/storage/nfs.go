//go:build linux

package storage

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/osfs"
	nfs "github.com/willscott/go-nfs"
	"golang.org/x/sys/unix"
)

func ServeNFS(address, root string) error {
	if err := os.MkdirAll(root, 0755); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	return nfs.Serve(listener, newVolumeNFSHandler(root))
}

type volumeNFSHandler struct {
	filesystem *volumeNFSFilesystem
	mu         sync.RWMutex
	handles    map[string][]string
}

func newVolumeNFSHandler(root string) *volumeNFSHandler {
	handler := &volumeNFSHandler{handles: make(map[string][]string)}
	handler.filesystem = &volumeNFSFilesystem{
		Filesystem: osfs.New(root, osfs.WithBoundOS()),
		root:       root,
		handles:    handler,
	}
	return handler
}

func (handler *volumeNFSHandler) Mount(context.Context, net.Conn, nfs.MountRequest) (nfs.MountStatus, billy.Filesystem, []nfs.AuthFlavor) {
	return nfs.MountStatusOk, handler.filesystem, []nfs.AuthFlavor{nfs.AuthFlavorUnix}
}

func (handler *volumeNFSHandler) Change(billy.Filesystem) billy.Change {
	return handler.filesystem
}

func (handler *volumeNFSHandler) FSStat(_ context.Context, _ billy.Filesystem, result *nfs.FSStat) error {
	var value unix.Statfs_t
	if err := unix.Statfs(handler.filesystem.root, &value); err != nil {
		return err
	}
	blockSize := uint64(value.Bsize)
	result.TotalSize = value.Blocks * blockSize
	result.FreeSize = value.Bfree * blockSize
	result.AvailableSize = value.Bavail * blockSize
	result.TotalFiles = value.Files
	result.FreeFiles = value.Ffree
	result.AvailableFiles = value.Ffree
	return nil
}

func (handler *volumeNFSHandler) ToHandle(filesystem billy.Filesystem, path []string) []byte {
	joined := filesystem.Join(path...)
	var handle [16]byte
	if info, err := filesystem.Lstat(joined); err == nil {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			binary.BigEndian.PutUint64(handle[0:8], uint64(stat.Dev))
			binary.BigEndian.PutUint64(handle[8:16], stat.Ino)
		} else {
			digest := sha256.Sum256([]byte(joined))
			copy(handle[:], digest[:16])
		}
	} else {
		digest := sha256.Sum256([]byte(joined))
		copy(handle[:], digest[:16])
	}
	result := append([]byte(nil), handle[:]...)
	handler.mu.Lock()
	handler.handles[string(result)] = append([]string(nil), path...)
	handler.mu.Unlock()
	return result
}

func (handler *volumeNFSHandler) FromHandle(handle []byte) (billy.Filesystem, []string, error) {
	handler.mu.RLock()
	path, ok := handler.handles[string(handle)]
	handler.mu.RUnlock()
	if !ok {
		return nil, nil, errors.New("stale NFS file handle")
	}
	return handler.filesystem, append([]string(nil), path...), nil
}

func (handler *volumeNFSHandler) InvalidateHandle(_ billy.Filesystem, handle []byte) error {
	handler.mu.Lock()
	delete(handler.handles, string(handle))
	handler.mu.Unlock()
	return nil
}

func (handler *volumeNFSHandler) HandleLimit() int {
	return 1_000_000
}

func (handler *volumeNFSHandler) rename(from, to string) {
	from = filepath.Clean(from)
	to = filepath.Clean(to)
	handler.mu.Lock()
	defer handler.mu.Unlock()
	for handle, elements := range handler.handles {
		path := filepath.Clean(filepath.Join(elements...))
		if path == from || strings.HasPrefix(path, from+string(filepath.Separator)) {
			replacement := to + strings.TrimPrefix(path, from)
			handler.handles[handle] = splitPath(replacement)
		}
	}
}

type volumeNFSFilesystem struct {
	billy.Filesystem
	root    string
	handles *volumeNFSHandler
}

func (filesystem *volumeNFSFilesystem) Rename(from, to string) error {
	if err := filesystem.Filesystem.Rename(from, to); err != nil {
		return err
	}
	filesystem.handles.rename(from, to)
	return nil
}

func (filesystem *volumeNFSFilesystem) Chmod(name string, mode os.FileMode) error {
	path, err := filesystem.hostPath(name)
	if err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func (filesystem *volumeNFSFilesystem) Lchown(name string, uid, gid int) error {
	path, err := filesystem.hostPath(name)
	if err != nil {
		return err
	}
	return os.Lchown(path, uid, gid)
}

func (filesystem *volumeNFSFilesystem) Chown(name string, uid, gid int) error {
	path, err := filesystem.hostPath(name)
	if err != nil {
		return err
	}
	return os.Chown(path, uid, gid)
}

func (filesystem *volumeNFSFilesystem) Chtimes(name string, atime, mtime time.Time) error {
	path, err := filesystem.hostPath(name)
	if err != nil {
		return err
	}
	return os.Chtimes(path, atime, mtime)
}

func (filesystem *volumeNFSFilesystem) Mknod(name string, mode, major, minor uint32) error {
	path, err := filesystem.hostPath(name)
	if err != nil {
		return err
	}
	return unix.Mknod(path, mode, int(unix.Mkdev(major, minor)))
}

func (filesystem *volumeNFSFilesystem) Mkfifo(name string, mode uint32) error {
	path, err := filesystem.hostPath(name)
	if err != nil {
		return err
	}
	return unix.Mkfifo(path, mode)
}

func (filesystem *volumeNFSFilesystem) Socket(name string) error {
	path, err := filesystem.hostPath(name)
	if err != nil {
		return err
	}
	descriptor, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(descriptor)
	return unix.Bind(descriptor, &unix.SockaddrUnix{Name: path})
}

func (filesystem *volumeNFSFilesystem) Link(path, link string) error {
	source, err := filesystem.hostPath(path)
	if err != nil {
		return err
	}
	destination, err := filesystem.hostPath(link)
	if err != nil {
		return err
	}
	return unix.Link(source, destination)
}

func (filesystem *volumeNFSFilesystem) hostPath(name string) (string, error) {
	clean := filepath.Clean(name)
	if filepath.IsAbs(clean) {
		relative, err := filepath.Rel(filesystem.root, clean)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return clean, nil
		}
		clean = strings.TrimPrefix(clean, string(filepath.Separator))
	}
	clean = filepath.Clean(string(filepath.Separator) + clean)
	clean = strings.TrimPrefix(clean, string(filepath.Separator))
	return filepath.Join(filesystem.root, clean), nil
}

func splitPath(path string) []string {
	clean := filepath.Clean(path)
	if clean == "." {
		return nil
	}
	return strings.Split(clean, string(filepath.Separator))
}

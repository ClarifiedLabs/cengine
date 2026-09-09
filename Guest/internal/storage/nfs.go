//go:build linux

package storage

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
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
	handler := newVolumeNFSHandler(root)
	if handler.filesystem.rootErr != nil {
		return handler.filesystem.rootErr
	}
	defer handler.filesystem.confined.Close()
	defer handler.filesystem.rootFile.Close()
	if err := handler.prepareExportRoot(); err != nil {
		return err
	}
	return nfs.Serve(listener, handler)
}

type volumeNFSHandler struct {
	filesystem    *volumeNFSFilesystem
	mu            sync.RWMutex
	handles       map[string][]string
	identitySlots chan struct{}
}

func newVolumeNFSHandler(root string) *volumeNFSHandler {
	handler := &volumeNFSHandler{handles: make(map[string][]string), identitySlots: make(chan struct{}, 64)}
	handler.filesystem = &volumeNFSFilesystem{
		Filesystem: osfs.New(root, osfs.WithBoundOS()),
		root:       root,
		handles:    handler,
	}
	handler.filesystem.confined, handler.filesystem.rootErr = os.OpenRoot(root)
	if handler.filesystem.rootErr == nil {
		handler.filesystem.rootFile, handler.filesystem.rootErr = handler.filesystem.confined.Open(".")
	}
	return handler
}

func (handler *volumeNFSHandler) prepareExportRoot() error {
	// The sibling storage service may create this ancestor with mode 0700
	// first. This service-owned export root must be searchable by AUTH_SYS
	// callers; named-volume roots below it keep their independent permissions.
	return handler.filesystem.rootFile.Chmod(0755)
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
	root     string
	confined *os.Root
	rootFile *os.File
	rootErr  error
	handles  *volumeNFSHandler
}

func (filesystem *volumeNFSFilesystem) Rename(from, to string) error {
	var err error
	if isExclusiveCopyupRename(from, to) {
		err = filesystem.renameNoReplace(from, to)
	} else {
		if filesystem.rootErr != nil {
			return filesystem.rootErr
		}
		err = filesystem.confined.Rename(filesystem.confinedName(from), filesystem.confinedName(to))
	}
	if err != nil {
		return err
	}
	filesystem.handles.rename(from, to)
	return nil
}

func isExclusiveCopyupRename(from, to string) bool {
	fromParts, fromOK := volumeNFSPathParts(from)
	toParts, toOK := volumeNFSPathParts(to)
	if !fromOK || !toOK || len(fromParts) < 3 || fromParts[0] != toParts[0] {
		return false
	}
	if len(fromParts) == 3 && len(toParts) == 3 {
		return fromParts[1] == ".cengine-copyup-transaction" &&
			fromParts[2] == "manifest.tmp" &&
			toParts[1] == ".cengine-copyup-transaction" &&
			toParts[2] == "manifest.json"
	}
	return len(fromParts) == 4 && len(toParts) == 2 &&
		fromParts[1] == ".cengine-copyup-transaction" &&
		fromParts[2] == "staging" && fromParts[3] == toParts[1]
}

func volumeNFSPathParts(name string) ([]string, bool) {
	clean := filepath.Clean(name)
	clean = strings.TrimPrefix(clean, string(filepath.Separator))
	if clean == "." || clean == "" || clean == ".." ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil, false
	}
	parts := strings.Split(clean, string(filepath.Separator))
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, false
		}
	}
	return parts, true
}

func (filesystem *volumeNFSFilesystem) renameNoReplace(from, to string) error {
	fromParts, fromOK := volumeNFSPathParts(from)
	toParts, toOK := volumeNFSPathParts(to)
	if !fromOK || !toOK {
		return os.ErrInvalid
	}
	if filesystem.rootErr != nil {
		return filesystem.rootErr
	}
	rootFD := int(filesystem.rootFile.Fd())
	openParent := func(parts []string) (int, error) {
		parent := "."
		if len(parts) > 1 {
			parent = filepath.Join(parts[:len(parts)-1]...)
		}
		return unix.Openat2(rootFD, parent, &unix.OpenHow{
			Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC),
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
		})
	}
	fromParent, err := openParent(fromParts)
	if err != nil {
		return err
	}
	defer unix.Close(fromParent)
	toParent, err := openParent(toParts)
	if err != nil {
		return err
	}
	defer unix.Close(toParent)
	if err := unix.Renameat2(
		fromParent, fromParts[len(fromParts)-1],
		toParent, toParts[len(toParts)-1],
		unix.RENAME_NOREPLACE,
	); err != nil {
		return err
	}
	if err := unix.Fsync(fromParent); err != nil {
		return err
	}
	if err := unix.Fsync(toParent); err != nil {
		return err
	}
	return nil
}

func (filesystem *volumeNFSFilesystem) Chmod(name string, mode os.FileMode) error {
	if filesystem.rootErr != nil {
		return filesystem.rootErr
	}
	return filesystem.confined.Chmod(filesystem.confinedName(name), mode)
}
func (filesystem *volumeNFSFilesystem) Lchown(name string, uid, gid int) error {
	if filesystem.rootErr != nil {
		return filesystem.rootErr
	}
	return filesystem.confined.Lchown(filesystem.confinedName(name), uid, gid)
}
func (filesystem *volumeNFSFilesystem) Chown(name string, uid, gid int) error {
	if filesystem.rootErr != nil {
		return filesystem.rootErr
	}
	return filesystem.confined.Chown(filesystem.confinedName(name), uid, gid)
}
func (filesystem *volumeNFSFilesystem) Chtimes(name string, atime, mtime time.Time) error {
	if filesystem.rootErr != nil {
		return filesystem.rootErr
	}
	return filesystem.confined.Chtimes(filesystem.confinedName(name), atime, mtime)
}
func (filesystem *volumeNFSFilesystem) Mknod(name string, mode, major, minor uint32) error {
	// A confined pathname does not confine device I/O in the storage VM.
	if mode&unix.S_IFMT != unix.S_IFIFO {
		return unix.EPERM
	}
	return filesystem.withParent(name, func(fd int, base string) error { return unix.Mknodat(fd, base, mode, int(unix.Mkdev(major, minor))) })
}
func (filesystem *volumeNFSFilesystem) Mkfifo(name string, mode uint32) error {
	return filesystem.Mknod(name, mode|unix.S_IFIFO, 0, 0)
}
func (filesystem *volumeNFSFilesystem) Socket(name string) error {
	return filesystem.withParent(name, func(fd int, base string) error {
		descriptor, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(descriptor)
		return unix.Bind(descriptor, &unix.SockaddrUnix{Name: fmt.Sprintf("/proc/self/fd/%d/%s", fd, base)})
	})
}
func (filesystem *volumeNFSFilesystem) Link(path, link string) error {
	if filesystem.rootErr != nil {
		return filesystem.rootErr
	}
	return filesystem.confined.Link(filesystem.confinedName(path), filesystem.confinedName(link))
}

func splitPath(path string) []string {
	clean := filepath.Clean(path)
	if clean == "." {
		return nil
	}
	return strings.Split(clean, string(filepath.Separator))
}

package storagefuse

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// A generation keeps its claim until exact teardown succeeds. Failed/unknown
// teardown poisons the path rather than letting another constructor adopt it.
var mountClaims = struct {
	sync.Mutex
	paths map[string]bool
}{paths: make(map[string]bool)}

func claimMountPath(path string) (func(), error) {
	mountClaims.Lock()
	defer mountClaims.Unlock()
	if mountClaims.paths[path] {
		return nil, ErrProfile
	}
	mountClaims.paths[path] = true
	var once sync.Once
	return func() { once.Do(func() { mountClaims.Lock(); delete(mountClaims.paths, path); mountClaims.Unlock() }) }, nil
}

type directoryPin struct {
	file *os.File
	stat unix.Stat_t
	name string
}
type pinnedMountPath struct {
	path, name string
	chain      []directoryPin // root through immediate parent, all retained
	leaf       *directoryPin  // underlying newly-created directory, not the mounted root
	created    bool
}

func trustedDirectory(st unix.Stat_t) bool {
	return uint32(st.Mode)&unix.S_IFMT == unix.S_IFDIR && st.Uid == 0 && uint32(st.Mode)&0022 == 0
}
func sameDirectory(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && uint32(b.Mode)&unix.S_IFMT == unix.S_IFDIR
}
func openDirectoryAt(fd int, name string) (directoryPin, error) {
	n, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return directoryPin{}, err
	}
	p := directoryPin{file: os.NewFile(uintptr(n), name), name: name}
	if err := unix.Fstat(n, &p.stat); err != nil {
		p.file.Close()
		return directoryPin{}, err
	}
	return p, nil
}
func pinMountParent(path string) (_ *pinnedMountPath, err error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, ErrProfile
	}
	p := &pinnedMountPath{path: path, name: filepath.Base(path)}
	defer func() {
		if err != nil {
			p.close()
		}
	}()
	root, err := openDirectoryAt(unix.AT_FDCWD, "/")
	if err != nil {
		return nil, err
	}
	p.chain = append(p.chain, root)
	if !trustedDirectory(root.stat) {
		return nil, ErrProfile
	}
	parent := filepath.Dir(path)
	if parent != "/" {
		for _, name := range strings.Split(strings.TrimPrefix(parent, "/"), "/") {
			next, e := openDirectoryAt(p.parentFD(), name)
			if e != nil {
				return nil, e
			}
			p.chain = append(p.chain, next)
			// Every ancestor, not merely the leaf's immediate parent, must be trusted.
			if !trustedDirectory(next.stat) {
				return nil, ErrProfile
			}
		}
	}
	var st unix.Stat_t
	if e := unix.Fstatat(p.parentFD(), p.name, &st, unix.AT_SYMLINK_NOFOLLOW); e != unix.ENOENT {
		return nil, ErrProfile
	}
	return p, nil
}
func (p *pinnedMountPath) parentFD() int { return int(p.chain[len(p.chain)-1].file.Fd()) }
func (p *pinnedMountPath) validate() error {
	for i, pin := range p.chain {
		var now unix.Stat_t
		if err := unix.Fstat(int(pin.file.Fd()), &now); err != nil {
			return err
		}
		if !sameDirectory(pin.stat, now) || !trustedDirectory(now) {
			return ErrProfile
		}
		if i > 0 {
			if err := unix.Fstatat(int(p.chain[i-1].file.Fd()), pin.name, &now, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return err
			}
			if !sameDirectory(pin.stat, now) {
				return ErrProfile
			}
		}
	}
	return nil
}
func (p *pinnedMountPath) create() error {
	if err := p.validate(); err != nil {
		return err
	}
	if err := unix.Mkdirat(p.parentFD(), p.name, 0700); err != nil {
		return err
	}
	p.created = true
	leaf, err := openDirectoryAt(p.parentFD(), p.name)
	if err != nil {
		return err
	}
	p.leaf = &leaf
	if !trustedDirectory(leaf.stat) {
		return ErrProfile
	}
	return nil
}
func fdPath(file *os.File) string { return fmt.Sprintf("/proc/self/fd/%d", file.Fd()) }
func (p *pinnedMountPath) remove() error {
	if !p.created {
		return nil
	}
	if p.leaf == nil {
		return ErrProfile
	} // never remove without captured identity
	var st unix.Stat_t
	if err := unix.Fstatat(p.parentFD(), p.name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if !sameDirectory(p.leaf.stat, st) {
		return ErrProfile
	}
	return unix.Unlinkat(p.parentFD(), p.name, unix.AT_REMOVEDIR)
}
func (p *pinnedMountPath) close() {
	if p.leaf != nil {
		_ = p.leaf.file.Close()
	}
	for i := len(p.chain) - 1; i >= 0; i-- {
		_ = p.chain[i].file.Close()
	}
}

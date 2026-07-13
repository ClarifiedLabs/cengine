//go:build linux

package rootfs

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"dev.cengine/guest/internal/disk"
	"dev.cengine/guest/internal/protocol"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/sys/unix"
)

func Apply(device string, layers []protocol.RootFSLayer, reader io.Reader) error {
	root := "/run/cengine/rootfs"
	if err := disk.EnsureExt4(device, root, "cengine-root"); err != nil { return err }
	for _, layer := range layers {
		if layer.Size < 0 { return errors.New("negative OCI layer size") }
		limited := &io.LimitedReader{R: reader, N: layer.Size}
		hash := sha256.New()
		compressed := io.TeeReader(limited, hash)
		archive, closeArchive, err := decompressor(layer.MediaType, compressed)
		if err != nil { return err }
		applyError := applyLayer(root, archive)
		closeError := closeArchive()
		if _, err := io.Copy(io.Discard, compressed); err != nil && applyError == nil { applyError = err }
		if limited.N != 0 && applyError == nil { applyError = io.ErrUnexpectedEOF }
		actual := "sha256:" + hex.EncodeToString(hash.Sum(nil))
		if actual != layer.Digest && applyError == nil { applyError = fmt.Errorf("layer digest mismatch: expected %s, received %s", layer.Digest, actual) }
		if applyError != nil { return applyError }
		if closeError != nil { return closeError }
	}
	return syncDirectory(root)
}

func decompressor(mediaType string, source io.Reader) (io.Reader, func() error, error) {
	switch {
	case strings.Contains(mediaType, "+gzip") || strings.HasSuffix(mediaType, ".gzip"):
		reader, err := gzip.NewReader(source); if err != nil { return nil, nil, err }
		return reader, reader.Close, nil
	case strings.Contains(mediaType, "+zstd"):
		reader, err := zstd.NewReader(source); if err != nil { return nil, nil, err }
		return reader, func() error { reader.Close(); return nil }, nil
	default:
		return source, func() error { return nil }, nil
	}
}

func applyLayer(root string, source io.Reader) error {
	reader := tar.NewReader(source)
	var directories []*tar.Header
	type hardlink struct { target string; source string; header *tar.Header }
	var hardlinks []hardlink
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil { return err }
	defer unix.Close(rootFD)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) { break }
		if err != nil { return err }
		relative, err := safePath(header.Name); if err != nil { return err }
		base := filepath.Base(relative); parent := filepath.Dir(relative)
		if base == ".wh..wh..opq" {
			if err := ensureParent(rootFD, filepath.Join(parent, "placeholder")); err != nil { return err }
			directory := filepath.Join(root, parent); entries, err := os.ReadDir(directory)
			if err != nil && !errors.Is(err, os.ErrNotExist) { return err }
			for _, entry := range entries { if err := os.RemoveAll(filepath.Join(directory, entry.Name())); err != nil { return err } }
			continue
		}
		if strings.HasPrefix(base, ".wh.") {
			if err := ensureParent(rootFD, filepath.Join(parent, "placeholder")); err != nil { return err }
			if err := os.RemoveAll(filepath.Join(root, parent, strings.TrimPrefix(base, ".wh."))); err != nil { return err }
			continue
		}
		target := filepath.Join(root, relative)
		if err := ensureParent(rootFD, relative); err != nil { return err }
		if header.Typeflag != tar.TypeDir { if err := removeExisting(target); err != nil { return err } }
		switch header.Typeflag {
		case tar.TypeDir:
			if info, statErr := os.Lstat(target); statErr == nil && !info.IsDir() { if err := os.RemoveAll(target); err != nil { return err } }
			if err := os.MkdirAll(target, 0755); err != nil { return err }; copy := *header; directories = append(directories, &copy)
		case tar.TypeReg, tar.TypeRegA:
			file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(header.Mode)); if err != nil { return err }
			_, copyError := io.CopyN(file, reader, header.Size); closeError := file.Close(); if copyError != nil { return copyError }; if closeError != nil { return closeError }
		case tar.TypeSymlink:
			if err := os.Symlink(header.Linkname, target); err != nil { return err }
		case tar.TypeLink:
			link, err := safePath(header.Linkname); if err != nil { return err }; if err:=ensureParent(rootFD,link);err!=nil{return err};copy := *header; hardlinks = append(hardlinks, hardlink{target: target, source: filepath.Join(root, link), header: &copy}); continue
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			mode := uint32(header.Mode); device := 0
			if header.Typeflag == tar.TypeChar { mode |= unix.S_IFCHR; device = int(unix.Mkdev(uint32(header.Devmajor), uint32(header.Devminor))) }
			if header.Typeflag == tar.TypeBlock { mode |= unix.S_IFBLK; device = int(unix.Mkdev(uint32(header.Devmajor), uint32(header.Devminor))) }
			if header.Typeflag == tar.TypeFifo { mode |= unix.S_IFIFO }
			if err := unix.Mknod(target, mode, device); err != nil { return err }
		default:
			continue
		}
		if header.Typeflag != tar.TypeDir { if err := metadata(target, header); err != nil { return err } }
	}
	for len(hardlinks) > 0 {
		remaining := hardlinks[:0]
		progress := false
		for _, link := range hardlinks {
			if err := os.Link(link.source, link.target); err != nil {
				if errors.Is(err, os.ErrNotExist) { remaining = append(remaining, link); continue }
				return err
			}
			if err := metadata(link.target, link.header); err != nil { return err }
			progress = true
		}
		if !progress && len(remaining) > 0 { return fmt.Errorf("OCI layer contains unresolved hard link %s -> %s", remaining[0].target, remaining[0].source) }
		hardlinks = remaining
	}
	for index := len(directories)-1; index >= 0; index-- { header:=directories[index]; relative,_:=safePath(header.Name); if err:=metadata(filepath.Join(root,relative),header); err!=nil{return err} }
	return nil
}

func metadata(path string, header *tar.Header) error {
	if err := os.Lchown(path, header.Uid, header.Gid); err != nil { return err }
	if header.Typeflag != tar.TypeSymlink { if err := os.Chmod(path, os.FileMode(header.Mode)); err != nil { return err } }
	for name, value := range header.Xattrs { if err := unix.Lsetxattr(path, name, []byte(value), 0); err != nil && !errors.Is(err, unix.ENOTSUP) { return err } }
	modified := unix.NsecToTimespec(header.ModTime.UnixNano())
	accessed := modified
	if !header.AccessTime.IsZero() { accessed = unix.NsecToTimespec(header.AccessTime.UnixNano()) }
	if err := unix.UtimesNanoAt(unix.AT_FDCWD, path, []unix.Timespec{accessed, modified}, unix.AT_SYMLINK_NOFOLLOW); err != nil && !errors.Is(err, unix.ENOTSUP) { return err }
	return nil
}

func ensureParent(rootFD int, relative string) error {
	parent := filepath.Dir(relative)
	if parent == "." { return nil }
	current, err := unix.Dup(rootFD); if err != nil { return err }
	defer func() { _ = unix.Close(current) }()
	for _, component := range strings.Split(parent, string(filepath.Separator)) {
		if component == "" || component == "." { continue }
		next, err := unix.Openat2(current, component, &unix.OpenHow{Flags: unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH|unix.RESOLVE_NO_MAGICLINKS|unix.RESOLVE_NO_SYMLINKS})
		if errors.Is(err, unix.ENOENT) {
			if err := unix.Mkdirat(current, component, 0755); err != nil && !errors.Is(err, unix.EEXIST) { return err }
			next, err = unix.Openat2(current, component, &unix.OpenHow{Flags: unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH|unix.RESOLVE_NO_MAGICLINKS|unix.RESOLVE_NO_SYMLINKS})
		}
		if err != nil { return fmt.Errorf("unsafe OCI layer parent %s: %w", parent, err) }
		unix.Close(current); current = next
	}
	return nil
}

func safePath(value string) (string, error) {
	cleaned := filepath.Clean(strings.TrimPrefix(value, "/")); if cleaned=="." { return cleaned,nil }
	if cleaned==".." || strings.HasPrefix(cleaned,"../") || filepath.IsAbs(cleaned) || strings.IndexByte(cleaned,0)>=0 { return "", errors.New("OCI layer path escapes rootfs") }
	return cleaned,nil
}
func removeExisting(path string) error { if _,err:=os.Lstat(path); err==nil{return os.RemoveAll(path)} else if errors.Is(err,os.ErrNotExist){return nil}else{return err} }
func syncDirectory(path string) error { fd,err:=unix.Open(path,unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC,0); if err!=nil{return err}; defer unix.Close(fd); return unix.Syncfs(fd) }

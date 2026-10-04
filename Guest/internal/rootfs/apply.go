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
	if err := disk.MountExistingExt4(device, root); err != nil {
		return err
	}
	for _, layer := range layers {
		if layer.Size < 0 {
			return errors.New("negative OCI layer size")
		}
		limited := &io.LimitedReader{R: reader, N: layer.Size}
		hash := sha256.New()
		compressed := io.TeeReader(limited, hash)
		archive, closeArchive, err := decompressor(layer.MediaType, compressed)
		if err != nil {
			return err
		}
		applyError := applyLayer(root, archive)
		closeError := closeArchive()
		if _, err := io.Copy(io.Discard, compressed); err != nil && applyError == nil {
			applyError = err
		}
		if limited.N != 0 && applyError == nil {
			applyError = io.ErrUnexpectedEOF
		}
		actual := "sha256:" + hex.EncodeToString(hash.Sum(nil))
		if actual != layer.Digest && applyError == nil {
			applyError = fmt.Errorf("layer digest mismatch: expected %s, received %s", layer.Digest, actual)
		}
		if applyError != nil {
			return applyError
		}
		if closeError != nil {
			return closeError
		}
	}
	return syncDirectory(root)
}

func decompressor(mediaType string, source io.Reader) (io.Reader, func() error, error) {
	switch {
	case strings.Contains(mediaType, "+gzip") || strings.HasSuffix(mediaType, ".gzip"):
		reader, err := gzip.NewReader(source)
		if err != nil {
			return nil, nil, err
		}
		return reader, reader.Close, nil
	case strings.Contains(mediaType, "+zstd"):
		reader, err := zstd.NewReader(source)
		if err != nil {
			return nil, nil, err
		}
		return reader, func() error { reader.Close(); return nil }, nil
	default:
		return source, func() error { return nil }, nil
	}
}

func applyLayer(root string, source io.Reader) error {
	reader := tar.NewReader(source)
	var directories []*tar.Header
	type hardlink struct {
		target string
		source string
		header *tar.Header
	}
	var hardlinks []hardlink
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		relative, err := safePath(header.Name)
		if err != nil {
			return err
		}
		base := filepath.Base(relative)
		parent := filepath.Dir(relative)
		if base == ".wh..wh..opq" {
			if err := ensureParent(rootFD, filepath.Join(parent, "placeholder")); err != nil {
				return err
			}
			directory := filepath.Join(root, parent)
			entries, err := os.ReadDir(directory)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			for _, entry := range entries {
				if err := os.RemoveAll(filepath.Join(directory, entry.Name())); err != nil {
					return err
				}
			}
			continue
		}
		if strings.HasPrefix(base, ".wh.") {
			if err := ensureParent(rootFD, filepath.Join(parent, "placeholder")); err != nil {
				return err
			}
			if err := os.RemoveAll(filepath.Join(root, parent, strings.TrimPrefix(base, ".wh."))); err != nil {
				return err
			}
			continue
		}
		target := filepath.Join(root, relative)
		if err := ensureParent(rootFD, relative); err != nil {
			return err
		}
		if header.Typeflag != tar.TypeDir {
			if err := removeExisting(target); err != nil {
				return err
			}
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if info, statErr := os.Lstat(target); statErr == nil && !info.IsDir() {
				if err := os.RemoveAll(target); err != nil {
					return err
				}
			}
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			copy := *header
			directories = append(directories, &copy)
		case tar.TypeReg, tar.TypeRegA:
			file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			_, copyError := io.CopyN(file, reader, header.Size)
			closeError := file.Close()
			if copyError != nil {
				return copyError
			}
			if closeError != nil {
				return closeError
			}
		case tar.TypeSymlink:
			if err := os.Symlink(header.Linkname, target); err != nil {
				return err
			}
		case tar.TypeLink:
			link, err := safePath(header.Linkname)
			if err != nil {
				return err
			}
			if err := ensureParent(rootFD, link); err != nil {
				return err
			}
			copy := *header
			hardlinks = append(hardlinks, hardlink{target: relative, source: link, header: &copy})
			continue
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			mode := uint32(header.Mode)
			device := 0
			if header.Typeflag == tar.TypeChar {
				mode |= unix.S_IFCHR
				device = int(unix.Mkdev(uint32(header.Devmajor), uint32(header.Devminor)))
			}
			if header.Typeflag == tar.TypeBlock {
				mode |= unix.S_IFBLK
				device = int(unix.Mkdev(uint32(header.Devmajor), uint32(header.Devminor)))
			}
			if header.Typeflag == tar.TypeFifo {
				mode |= unix.S_IFIFO
			}
			if err := unix.Mknod(target, mode, device); err != nil {
				return err
			}
		default:
			continue
		}
		if header.Typeflag != tar.TypeDir {
			if err := metadata(rootFD, relative, header); err != nil {
				return err
			}
		}
	}
	for len(hardlinks) > 0 {
		remaining := hardlinks[:0]
		progress := false
		for _, link := range hardlinks {
			if err := confinedHardlink(rootFD, link.source, link.target); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					remaining = append(remaining, link)
					continue
				}
				return err
			}
			if err := metadata(rootFD, link.target, link.header); err != nil {
				return err
			}
			progress = true
		}
		if !progress && len(remaining) > 0 {
			return fmt.Errorf("OCI layer contains unresolved hard link %s -> %s", remaining[0].target, remaining[0].source)
		}
		hardlinks = remaining
	}
	for index := len(directories) - 1; index >= 0; index-- {
		header := directories[index]
		relative, _ := safePath(header.Name)
		if err := metadata(rootFD, relative, header); err != nil {
			return err
		}
	}
	return nil
}

// Hardlinks are deferred, so the parents validated while reading the header
// may have been replaced. Pin both parents again at link time; linkat without
// AT_SYMLINK_FOLLOW links the source inode itself, never a symlink's target.
func confinedHardlink(rootFD int, source, target string) error {
	openParent := func(path string) (int, error) {
		return unix.Openat2(rootFD, filepath.Dir(path), &unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
		})
	}
	sourceParent, err := openParent(source)
	if err != nil {
		return err
	}
	defer unix.Close(sourceParent)
	targetParent, err := openParent(target)
	if err != nil {
		return err
	}
	defer unix.Close(targetParent)
	return unix.Linkat(sourceParent, filepath.Base(source), targetParent, filepath.Base(target), 0)
}

func metadata(rootFD int, relative string, header *tar.Header) error {
	fd, err := openMetadata(rootFD, relative)
	if err != nil {
		return fmt.Errorf("unsafe OCI layer metadata %s: %w", relative, err)
	}
	defer unix.Close(fd)
	return metadataFD(fd, header)
}

// O_PATH pins the inode without opening devices or blocking on FIFOs. Resolve
// every component beneath rootFD, refusing symlink parents; O_NOFOLLOW permits
// the final symlink itself, never its target. No later operation resolves an
// archive path, so parent/final-component replacements cannot redirect metadata.
func openMetadata(rootFD int, relative string) (int, error) {
	return unix.Openat2(rootFD, relative, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
}

func metadataFD(fd int, header *tar.Header) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	kind := stat.Mode & unix.S_IFMT
	var expected uint32
	switch header.Typeflag {
	case tar.TypeReg, tar.TypeRegA:
		expected = unix.S_IFREG
	case tar.TypeDir:
		expected = unix.S_IFDIR
	case tar.TypeSymlink:
		expected = unix.S_IFLNK
	case tar.TypeChar:
		expected = unix.S_IFCHR
	case tar.TypeBlock:
		expected = unix.S_IFBLK
	case tar.TypeFifo:
		expected = unix.S_IFIFO
	case tar.TypeLink:
		// A hardlink can name a symlink inode. Its actual type, not the tar
		// header's TypeLink, determines whether chmod is safe.
		if kind == unix.S_IFDIR {
			return errors.New("OCI hard link names a directory")
		}
		expected = kind
	default:
		return errors.New("unsupported OCI metadata inode type")
	}
	if kind != expected {
		return fmt.Errorf("OCI metadata inode type changed for %s", header.Name)
	}
	if err := unix.Fchownat(fd, "", header.Uid, header.Gid, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if kind != unix.S_IFLNK {
		if err := unix.Fchmodat(fd, "", uint32(header.Mode)&07777, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
	}
	// archive/tar omits empty PAX values from Header.Xattrs. They still
	// represent present, zero-length xattrs rather than absent metadata.
	xattrs := make(map[string]string, len(header.Xattrs))
	for key, value := range header.PAXRecords {
		if name, ok := strings.CutPrefix(key, "SCHILY.xattr."); ok {
			xattrs[name] = value
		}
	}
	// Preserve archive/tar's precedence for explicitly supplied Header.Xattrs.
	for name, value := range header.Xattrs {
		xattrs[name] = value
	}
	for name, value := range xattrs {
		if err := setMetadataXattr(fd, name, []byte(value)); err != nil && !errors.Is(err, unix.ENOTSUP) {
			return err
		}
	}
	modified := unix.NsecToTimespec(header.ModTime.UnixNano())
	accessed := modified
	if !header.AccessTime.IsZero() {
		accessed = unix.NsecToTimespec(header.AccessTime.UnixNano())
	}
	if err := unix.UtimesNanoAt(fd, "", []unix.Timespec{accessed, modified}, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil && !errors.Is(err, unix.ENOTSUP) {
		return err
	}
	return nil
}

// Linux fsetxattr rejects O_PATH descriptors. The extractor's trusted procfs
// magic link refers directly to the pinned inode (including a symlink inode),
// without resolving the archive path again or opening a device/FIFO for I/O.
// EPERM is intentionally propagated: Linux forbids user.* xattrs on symlinks,
// even when their value is empty.
func setMetadataXattr(fd int, name string, value []byte) error {
	return unix.Setxattr(fmt.Sprintf("/proc/self/fd/%d", fd), name, value, 0)
}

func ensureParent(rootFD int, relative string) error {
	parent := filepath.Dir(relative)
	if parent == "." {
		return nil
	}
	current, err := unix.Dup(rootFD)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(current) }()
	for _, component := range strings.Split(parent, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		next, err := unix.Openat2(current, component, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS})
		if errors.Is(err, unix.ENOENT) {
			if err := unix.Mkdirat(current, component, 0755); err != nil && !errors.Is(err, unix.EEXIST) {
				return err
			}
			next, err = unix.Openat2(current, component, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS})
		}
		if err != nil {
			return fmt.Errorf("unsafe OCI layer parent %s: %w", parent, err)
		}
		unix.Close(current)
		current = next
	}
	return nil
}

func safePath(value string) (string, error) {
	cleaned := filepath.Clean(strings.TrimPrefix(value, "/"))
	if cleaned == "." {
		return cleaned, nil
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") || filepath.IsAbs(cleaned) || strings.IndexByte(cleaned, 0) >= 0 {
		return "", errors.New("OCI layer path escapes rootfs")
	}
	return cleaned, nil
}
func removeExisting(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return os.RemoveAll(path)
	} else if errors.Is(err, os.ErrNotExist) {
		return nil
	} else {
		return err
	}
}
func syncDirectory(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Syncfs(fd)
}

//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"bytes"
	w "dev.cengine/guest/internal/storagewire"
	"encoding/binary"
	"golang.org/x/sys/unix"
)

func readDir(fd int, cookie uint64, maxBytes uint32) ([]w.DirEntry, error) {
	if _, err := unix.Seek(fd, int64(cookie), unix.SEEK_SET); err != nil {
		return nil, err
	}
	entries := []w.DirEntry{}
	// One bounded getdents page. The last returned d_off, NOT the file's current
	// position after read-ahead, is the continuation cookie. Never Readdir(-1).
	data := make([]byte, w.MaxIO)
	n, err := unix.Getdents(fd, data)
	if err != nil {
		return nil, err
	}
	data = data[:n]
	used := uint32(0)
	names := map[string]bool{}
	cookies := map[uint64]bool{}
	for len(data) > 0 {
		if len(data) < 19 {
			return nil, unix.EIO
		}
		ino := binary.NativeEndian.Uint64(data)
		next := binary.NativeEndian.Uint64(data[8:])
		size := int(binary.NativeEndian.Uint16(data[16:]))
		kind := data[18]
		if size < 20 || size > len(data) {
			return nil, unix.EIO
		}
		end := bytes.IndexByte(data[19:size], 0)
		if end < 0 {
			return nil, unix.EIO
		}
		name := data[19 : 19+end]
		data = data[size:]
		if ino == 0 {
			continue
		}
		if len(name) == 0 || len(name) > w.MaxName || bytes.IndexByte(name, '/') >= 0 || next == 0 || next > uint64(^uint64(0)>>1) || next == cookie || names[string(name)] || cookies[next] {
			return nil, unix.EIO
		}
		cost := w.DirEntryBytes(name)
		if cost > maxBytes-used {
			if len(entries) == 0 {
				return nil, unix.EINVAL
			}
			break
		}
		names[string(name)] = true
		cookies[next] = true
		used += cost
		entries = append(entries, w.DirEntry{Name: append([]byte{}, name...), Ino: ino, Mode: uint32(kind) << 12, NextCookie: next})
		if len(entries) == w.MaxDirEntries {
			break
		}
	}
	return entries, nil
}

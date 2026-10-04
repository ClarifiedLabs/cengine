package storagemanaged

import (
	a "dev.cengine/guest/internal/storageauthority"
	"encoding/binary"
	"encoding/hex"
	"golang.org/x/sys/unix"
	"strings"
)

func decodeExt4Identity(inode uint64, mode uint32, kind int32, handle []byte) (a.Ext4ObjectV1, error) {
	// ext4's FILEID_INO32_GEN is two native little-endian u32 words on both
	// supported architectures. Preserve every byte, not just the stat inode.
	if kind != 1 || len(handle) != 8 || inode == 0 || inode > uint64(^uint32(0)) || uint64(binary.LittleEndian.Uint32(handle)) != inode {
		return a.Ext4ObjectV1{}, unix.EOPNOTSUPP
	}
	fileType := mode & unix.S_IFMT
	switch fileType {
	case unix.S_IFREG, unix.S_IFDIR, unix.S_IFLNK, unix.S_IFIFO, unix.S_IFSOCK, unix.S_IFCHR, unix.S_IFBLK:
	default:
		return a.Ext4ObjectV1{}, unix.EOPNOTSUPP
	}
	identity := a.Ext4ObjectV1{Inode: inode, Generation: binary.LittleEndian.Uint32(handle[4:]), FileType: fileType, HandleType: uint32(kind), HandleSize: uint32(len(handle))}
	copy(identity.Handle[:], handle)
	return identity, nil
}

func parseCopyDeviceUUID(device string) ([16]byte, error) {
	var uuid [16]byte
	if len(device) != 36 || device[8] != '-' || device[13] != '-' || device[18] != '-' || device[23] != '-' {
		return uuid, unix.EINVAL
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(device, "-", ""))
	if err != nil || len(raw) != len(uuid) {
		return uuid, unix.EINVAL
	}
	copy(uuid[:], raw)
	if uuid == ([16]byte{}) {
		return uuid, unix.EINVAL
	}
	return uuid, nil
}

func copyRelativePath(path string) bool {
	if path == "" || len(path) > 4095 || strings.ContainsRune(path, 0) {
		return false
	}
	parts := strings.Split(path, "/")
	if len(parts) > 255 {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > 255 {
			return false
		}
	}
	return true
}

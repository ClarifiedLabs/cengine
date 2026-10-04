// Package copycontract defines the bounded managed-v4 copy-up journal contract
// and xattr algorithms. It performs no filesystem IO and grants no authority.
package copycontract

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"

	"dev.cengine/guest/internal/storageauthority"
	"golang.org/x/sys/unix"
)

const (
	MaxEntries       = 1_000_000
	MaxManifestBytes = storageauthority.MaxCopyManifestBytes
	TransactionName  = ".cengine-copyup-transaction"
)

// RootMetadata retains the legacy filesystem/device/inode fields for byte-exact
// journal compatibility. They are metadata, not managed-v4 identity authority.
// Only Xattrs is optional in the encoding; managed-v4 validation requires it.
type RootMetadata struct {
	Filesystem [2]int32       `json:"filesystem"`
	Device     uint64         `json:"device"`
	Inode      uint64         `json:"inode"`
	UID        uint32         `json:"uid"`
	GID        uint32         `json:"gid"`
	Mode       uint32         `json:"mode"`
	Xattrs     *XattrSnapshot `json:"xattrs,omitempty"`
}

type Entry struct {
	Path     string                        `json:"path"`
	Identity storageauthority.Ext4ObjectV1 `json:"identity"`
}

// Manifest field order and tags are part of the persisted managed-v4 encoding.
// Physical is authenticated against the authority's CopyIntent by the caller.
type Manifest struct {
	Version  uint32                      `json:"version"`
	Intent   storageauthority.ID         `json:"intent"`
	Physical storageauthority.CopyRootV1 `json:"physical"`
	Root     *RootMetadata               `json:"root"`
	Entries  []Entry                     `json:"entries"`
}

// ValidateRootMetadata validates the required managed-v4 metadata and xattrs.
// It deliberately does not treat the legacy identity fields as authority.
func ValidateRootMetadata(root *RootMetadata) error {
	if root == nil || root.Mode & ^uint32(07777) != 0 || root.UID == ^uint32(0) || root.GID == ^uint32(0) {
		return errors.New("copy-up manifest has invalid root metadata")
	}
	return ValidateXattrs(root.Xattrs)
}

func validObject(object storageauthority.Ext4ObjectV1) bool {
	if object.Inode == 0 || object.HandleType != 1 || object.HandleSize != 8 || object.Inode != uint64(binary.LittleEndian.Uint32(object.Handle[:4])) || object.Generation != binary.LittleEndian.Uint32(object.Handle[4:]) {
		return false
	}
	switch object.FileType {
	case unix.S_IFDIR, unix.S_IFREG, unix.S_IFLNK:
		return true
	}
	return false
}

func validIntent(value string) bool {
	if len(value) != 36 || value[14] != '4' || !strings.ContainsRune("89ab", rune(value[19])) {
		return false
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

func validPath(value string) ([]string, bool) {
	// These are the Linux contract's PATH_MAX, NAME_MAX and depth bound, not
	// host-dependent constants (Darwin's PATH_MAX differs).
	if value == "" || strings.HasPrefix(value, "/") || strings.IndexByte(value, 0) >= 0 || len(value) >= 4096 {
		return nil, false
	}
	parts := strings.Split(value, "/")
	if len(parts) > 255 {
		return nil, false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > 255 {
			return nil, false
		}
	}
	return parts, true
}

// ValidateManifest validates the managed-v4 schema and ordered, confined entry
// tree, without IO. Physical provenance and persisted-byte digest/size must be
// authenticated by the caller; this function does not validate a CopyIntent.
func ValidateManifest(manifest Manifest) error {
	if manifest.Version != 4 || !validIntent(string(manifest.Intent)) || manifest.Root == nil || manifest.Entries == nil || len(manifest.Entries) > MaxEntries {
		return errors.New("unsupported managed journal variant")
	}
	if err := ValidateRootMetadata(manifest.Root); err != nil {
		return err
	}
	seen := make(map[string]uint32, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		parts, ok := validPath(entry.Path)
		if !ok || len(parts) == 0 || parts[0] == TransactionName || !validObject(entry.Identity) {
			return errors.New("invalid managed journal entry")
		}
		if _, exists := seen[entry.Path]; exists {
			return errors.New("duplicate managed journal entry")
		}
		if len(parts) > 1 && seen[path.Dir(entry.Path)] != unix.S_IFDIR {
			return errors.New("managed journal missing parent")
		}
		seen[entry.Path] = entry.Identity.FileType
	}
	return nil
}

// DecodeManifest strictly decodes and validates at most MaxManifestBytes. The
// caller must bound reads before constructing raw, authenticate those exact
// bytes (including any trailing whitespace), and compare Intent and Physical
// against the trusted CopyIntent before using the manifest for recovery.
func DecodeManifest(raw []byte) (Manifest, error) {
	var manifest Manifest
	if len(raw) > MaxManifestBytes {
		return manifest, errors.New("managed copy-up manifest byte bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return manifest, errors.New("managed journal trailing content")
	}
	if err := ValidateManifest(manifest); err != nil {
		return manifest, err
	}
	return manifest, nil
}

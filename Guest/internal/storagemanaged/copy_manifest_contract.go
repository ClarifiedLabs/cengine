package storagemanaged

import (
	a "dev.cengine/guest/internal/storageauthority"
	"encoding/json"
	"golang.org/x/sys/unix"
	"io"
	"path"
	"strings"
)

const copyTransactionPath = ".cengine-copyup-transaction"
const maxCopyEntries = 1_000_000
const maxCopyManifestBytes = a.MaxCopyManifestBytes

type copyCleanupManifest struct {
	Version  uint32       `json:"version"`
	Intent   a.ID         `json:"intent"`
	Physical a.CopyRootV1 `json:"physical"`
	Entries  []struct {
		Path     string         `json:"path"`
		Identity a.Ext4ObjectV1 `json:"identity"`
	} `json:"entries"`
}

func copyExpectedEntries(reader io.Reader, intent a.CopyIntent) (map[string]a.Ext4ObjectV1, error) {
	var manifest copyCleanupManifest
	dec := json.NewDecoder(io.LimitReader(reader, maxCopyManifestBytes+1))
	if err := dec.Decode(&manifest); err != nil {
		return nil, err
	}
	if dec.Decode(new(any)) != io.EOF || manifest.Version != 4 || manifest.Intent != intent.ID || manifest.Physical != intent.Root || manifest.Entries == nil || len(manifest.Entries) > maxCopyEntries {
		return nil, unix.EINVAL
	}
	expected := make(map[string]a.Ext4ObjectV1, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		if !copyRelativePath(entry.Path) || entry.Path == copyTransactionPath || strings.HasPrefix(entry.Path, copyTransactionPath+"/") {
			return nil, unix.EINVAL
		}
		got, err := decodeExt4Identity(entry.Identity.Inode, entry.Identity.FileType, int32(entry.Identity.HandleType), entry.Identity.Handle[:])
		if err != nil || got != entry.Identity {
			return nil, unix.EINVAL
		}
		name := "staging/" + entry.Path
		if _, exists := expected[name]; exists {
			return nil, unix.EINVAL
		}
		if parent := path.Dir(entry.Path); parent != "." && expected["staging/"+parent].FileType != unix.S_IFDIR {
			return nil, unix.EINVAL
		}
		expected[name] = entry.Identity
	}
	return expected, nil
}

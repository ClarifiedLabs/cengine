package storagefuse

import (
	"strconv"
	"strings"
)

func mountPath(path string) string {
	return strings.NewReplacer("\\", "\\134", " ", "\\040", "\t", "\\011", "\n", "\\012").Replace(path)
}
func ownedMount(info, path string) (id, connection uint64, err error) {
	for _, line := range strings.Split(info, "\n") {
		p := strings.Fields(line)
		if len(p) < 10 || p[4] != mountPath(path) {
			continue
		}
		sep := 0
		for i := 6; i < len(p); i++ {
			if p[i] == "-" {
				sep = i
				break
			}
		}
		if sep == 0 || sep+3 >= len(p) || p[sep+1] != "fuse.managed-v3" {
			return 0, 0, ErrProfile
		}
		if id != 0 {
			return 0, 0, ErrProfile
		}
		dev := strings.Split(p[2], ":")
		if len(dev) != 2 || dev[0] != "0" {
			return 0, 0, ErrProfile
		}
		id, err = strconv.ParseUint(p[0], 10, 64)
		if err != nil || id == 0 {
			return 0, 0, ErrProfile
		}
		connection, err = strconv.ParseUint(dev[1], 10, 64)
		if err != nil || connection == 0 {
			return 0, 0, ErrProfile
		}
	}
	if id == 0 {
		return 0, 0, ErrProfile
	}
	return id, connection, nil
}

// Bind once to the O_PATH descriptor's mount ID, proving that neither its ID nor
// device/connection existed before our mount. Never infer ownership from a name.
func bindNewMount(before, after, path string, descriptorID uint64) (uint64, uint64, error) {
	id, connection, err := ownedMount(after, path)
	if err != nil || descriptorID == 0 || id != descriptorID || hasMountID(before, id) {
		return 0, 0, ErrProfile
	}
	device := "0:" + strconv.FormatUint(connection, 10)
	for _, line := range strings.Split(before, "\n") {
		p := strings.Fields(line)
		if len(p) > 2 && p[2] == device {
			return 0, 0, ErrProfile
		}
	}
	return id, connection, nil
}
func matchesMount(info, path string, id, connection uint64) bool {
	if id == 0 || connection == 0 {
		return false
	}
	gotID, gotConnection, err := ownedMount(info, path)
	return err == nil && gotID == id && gotConnection == connection
}
func hasMountID(info string, id uint64) bool {
	for _, line := range strings.Split(info, "\n") {
		p := strings.Fields(line)
		if len(p) > 0 && p[0] == strconv.FormatUint(id, 10) {
			return true
		}
	}
	return false
}
func parseDescriptorMountID(info string) (uint64, error) {
	var id uint64
	for _, line := range strings.Split(info, "\n") {
		p := strings.Fields(line)
		if len(p) == 0 || p[0] != "mnt_id:" {
			continue
		}
		if len(p) != 2 || id != 0 {
			return 0, ErrProfile
		}
		var err error
		id, err = strconv.ParseUint(p[1], 10, 64)
		if err != nil || id == 0 {
			return 0, ErrProfile
		}
	}
	if id == 0 {
		return 0, ErrProfile
	}
	return id, nil
}
func hasMountAt(info, path string) bool {
	for _, line := range strings.Split(info, "\n") {
		p := strings.Fields(line)
		if len(p) > 4 && p[4] == mountPath(path) {
			return true
		}
	}
	return false
}
func privateParent(info, parent string) error {
	best := -1
	private := false
	encoded := mountPath(parent)
	for _, line := range strings.Split(info, "\n") {
		p := strings.Fields(line)
		if len(p) < 10 {
			continue
		}
		if p[4] != "/" && encoded != p[4] && !strings.HasPrefix(encoded, p[4]+"/") {
			continue
		}
		if len(p[4]) < best {
			continue
		}
		best = len(p[4])
		private = true
		for i := 6; i < len(p) && p[i] != "-"; i++ {
			if strings.HasPrefix(p[i], "shared:") || strings.HasPrefix(p[i], "master:") {
				private = false
			}
		}
	}
	if best < 0 || !private {
		return ErrProfile
	}
	return nil
}

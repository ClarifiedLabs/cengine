package workloadstorage

import "strings"

// bootMode reads a trusted immutable kernel command line, never workload fields.
// Missing means legacy; duplicate, bare, empty or unknown values fail closed.
func bootMode(commandLine string) (bool, error) {
	const key = "cengine.workload_storage_mode"
	found, managed := false, false
	for _, field := range strings.Fields(commandLine) {
		if field != key && !strings.HasPrefix(field, key+"=") {
			continue
		}
		if found {
			return false, ErrInvalidFrame
		}
		found = true
		switch field {
		case key + "=managed":
			managed = true
		case key + "=legacy":
		default:
			return false, ErrInvalidFrame
		}
	}
	return managed, nil
}

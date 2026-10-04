//go:build !linux

package workloadstorage

// Native mounted descriptors are never selectable on component-test hosts.
func originalFDError(error) string { return "other" }

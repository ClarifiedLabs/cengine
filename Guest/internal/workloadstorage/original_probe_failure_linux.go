//go:build linux

package workloadstorage

// Reuse PID1's existing single-write, nonblocking, best-effort console sink.
func emitOriginalProbeFailure(line string) { emitMountFailure(line) }

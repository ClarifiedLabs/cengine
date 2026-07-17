//go:build linux

package operations

import (
	"errors"
	"os"
	"testing"
)

func TestPrepareMemoryReclaimCompactsBeforeReadingAvailability(t *testing.T) {
	compacted := false
	status, err := prepareMemoryReclaim(
		func(path string, data []byte, mode os.FileMode) error {
			if path != "/proc/sys/vm/compact_memory" || string(data) != "1\n" {
				t.Fatalf("unexpected compaction write: %q %q", path, data)
			}
			compacted = true
			return nil
		},
		func(path string) ([]byte, error) {
			if !compacted {
				t.Fatal("meminfo read before compaction")
			}
			if path != "/proc/meminfo" {
				t.Fatalf("unexpected read path %q", path)
			}
			return []byte("MemTotal:       1048576 kB\nMemAvailable:    524288 kB\n"), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if status.TotalBytes != 1_073_741_824 || status.AvailableBytes != 536_870_912 {
		t.Fatalf("unexpected memory status: %+v", status)
	}
}

func TestPrepareMemoryReclaimFailsWhenCompactionFails(t *testing.T) {
	want := errors.New("read-only sysctl")
	_, err := prepareMemoryReclaim(
		func(string, []byte, os.FileMode) error { return want },
		func(string) ([]byte, error) {
			t.Fatal("meminfo should not be read after compaction failure")
			return nil, nil
		},
	)
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func TestParseMemoryStatusRequiresBothFields(t *testing.T) {
	if _, err := parseMemoryStatus([]byte("MemTotal: 1024 kB\n")); err == nil {
		t.Fatal("expected missing MemAvailable error")
	}
}

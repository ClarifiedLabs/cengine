//go:build linux

package operations

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
)

type MemoryStatus struct {
	TotalBytes     uint64 `json:"totalBytes"`
	AvailableBytes uint64 `json:"availableBytes"`
}

func PrepareMemoryReclaim() (MemoryStatus, error) {
	return prepareMemoryReclaim(os.WriteFile, os.ReadFile)
}

func prepareMemoryReclaim(
	writeFile func(string, []byte, os.FileMode) error,
	readFile func(string) ([]byte, error),
) (MemoryStatus, error) {
	if err := writeFile("/proc/sys/vm/compact_memory", []byte("1\n"), 0o644); err != nil {
		return MemoryStatus{}, fmt.Errorf("compact guest memory: %w", err)
	}
	data, err := readFile("/proc/meminfo")
	if err != nil {
		return MemoryStatus{}, fmt.Errorf("read guest memory status: %w", err)
	}
	return parseMemoryStatus(data)
}

func parseMemoryStatus(data []byte) (MemoryStatus, error) {
	var result MemoryStatus
	var foundTotal, foundAvailable bool
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		var destination *uint64
		switch fields[0] {
		case "MemTotal:":
			destination = &result.TotalBytes
			foundTotal = true
		case "MemAvailable:":
			destination = &result.AvailableBytes
			foundAvailable = true
		default:
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || value > math.MaxUint64/1024 {
			return MemoryStatus{}, fmt.Errorf("invalid %s value %q", fields[0], fields[1])
		}
		*destination = value * 1024
	}
	if err := scanner.Err(); err != nil {
		return MemoryStatus{}, err
	}
	if !foundTotal || !foundAvailable {
		return MemoryStatus{}, errors.New("guest memory status is missing MemTotal or MemAvailable")
	}
	return result, nil
}

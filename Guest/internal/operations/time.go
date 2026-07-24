//go:build linux

package operations

import (
	"fmt"

	"golang.org/x/sys/unix"
)

type settimeofdayFunc func(*unix.Timeval) error

func SetTime(seconds, microseconds int64) error {
	return setTime(seconds, microseconds, unix.Settimeofday)
}

func setTime(seconds, microseconds int64, setter settimeofdayFunc) error {
	if microseconds < 0 || microseconds >= 1_000_000 {
		return fmt.Errorf("microseconds must be between 0 and 999999")
	}
	value := unix.Timeval{Sec: seconds, Usec: microseconds}
	if err := setter(&value); err != nil {
		return fmt.Errorf("set realtime clock: %w", err)
	}
	return nil
}

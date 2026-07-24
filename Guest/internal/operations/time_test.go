//go:build linux

package operations

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSetTimeValidatesAndAppliesWallClockValue(t *testing.T) {
	var observed unix.Timeval
	err := setTime(1_784_920_000, 123_456, func(value *unix.Timeval) error {
		observed = *value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if observed.Sec != 1_784_920_000 || observed.Usec != 123_456 {
		t.Fatalf("settimeofday value = %#v", observed)
	}
}

func TestSetTimeRejectsInvalidMicroseconds(t *testing.T) {
	for _, value := range []int64{-1, 1_000_000} {
		called := false
		err := setTime(1, value, func(*unix.Timeval) error {
			called = true
			return nil
		})
		if err == nil {
			t.Fatalf("setTime accepted microseconds %d", value)
		}
		if called {
			t.Fatalf("setTime invoked syscall for microseconds %d", value)
		}
	}
}

func TestSetTimePropagatesSyscallFailure(t *testing.T) {
	failure := errors.New("settimeofday failed")
	err := setTime(1, 2, func(*unix.Timeval) error { return failure })
	if !errors.Is(err, failure) {
		t.Fatalf("setTime error = %v, want %v", err, failure)
	}
}

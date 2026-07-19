//go:build linux

package supervisor

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"dev.cengine/guest/internal/protocol"
	"golang.org/x/sys/unix"
)

func TestApplyRlimitsMapsEveryDockerResourceAndPreservesOrder(t *testing.T) {
	names := []string{
		"core", "cpu", "data", "fsize", "locks", "memlock", "msgqueue", "nice",
		"nofile", "nproc", "rss", "rtprio", "rttime", "sigpending", "stack",
	}
	limits := make([]protocol.Rlimit, 0, len(names))
	for index, name := range names {
		limits = append(limits, protocol.Rlimit{Type: name, Soft: uint64(index), Hard: unix.RLIM_INFINITY})
	}
	var resources []int
	var values []unix.Rlimit
	if err := applyRlimits(limits, func(resource int, limit *unix.Rlimit) error {
		resources = append(resources, resource)
		values = append(values, *limit)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	wantResources := make([]int, 0, len(names))
	for _, name := range names {
		wantResources = append(wantResources, linuxRlimitResources[name])
	}
	if !reflect.DeepEqual(resources, wantResources) {
		t.Fatalf("resources = %v, want %v", resources, wantResources)
	}
	for index, value := range values {
		if value.Cur != uint64(index) || value.Max != unix.RLIM_INFINITY {
			t.Fatalf("limit %d = %#v", index, value)
		}
	}
}

func TestApplyRlimitsRejectsInvalidGuestPayloads(t *testing.T) {
	cases := [][]protocol.Rlimit{
		{{Type: "as", Soft: 1, Hard: 1}},
		{{Type: "nofile", Soft: 2, Hard: 1}},
		{{Type: "nofile", Soft: 1, Hard: 1}, {Type: "nofile", Soft: 1, Hard: 1}},
	}
	for _, limits := range cases {
		if err := applyRlimits(limits, func(int, *unix.Rlimit) error { return nil }); err == nil {
			t.Fatalf("accepted invalid limits %#v", limits)
		}
	}
}

func TestApplyRlimitsReturnsContextualSetError(t *testing.T) {
	err := applyRlimits(
		[]protocol.Rlimit{{Type: "nofile", Soft: 1, Hard: 2}},
		func(int, *unix.Rlimit) error { return errors.New("denied") },
	)
	if err == nil || !strings.Contains(err.Error(), "set rlimit nofile: denied") {
		t.Fatalf("unexpected error %v", err)
	}
}

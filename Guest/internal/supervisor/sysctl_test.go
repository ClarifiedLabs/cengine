//go:build linux

package supervisor

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestWorkloadSysctlPathSupportsRuncSeparators(t *testing.T) {
	tests := map[string]string{
		"net.ipv4.ip_forward":              "/proc/sys/net/ipv4/ip_forward",
		"fs/mqueue/msg_max":                "/proc/sys/fs/mqueue/msg_max",
		"net/ipv4/conf/eth0.100/rp_filter": "/proc/sys/net/ipv4/conf/eth0/100/rp_filter",
		"net.ipv4.conf.eth0/100.rp_filter": "/proc/sys/net/ipv4/conf/eth0/100/rp_filter",
		"kernel.shm_rmid_forced":           "/proc/sys/kernel/shm_rmid_forced",
		"kernel/domainname":                "/proc/sys/kernel/domainname",
	}
	for name, want := range tests {
		got, err := workloadSysctlPath("/proc/sys", name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != want {
			t.Fatalf("%s path = %q, want %q", name, got, want)
		}
	}
}

func TestWorkloadSysctlValidationRejectsUnsafeAndGlobalSettings(t *testing.T) {
	for _, name := range []string{
		"", "kernel.hostname", "user.max_user_namespaces", "vm.swappiness",
		"fs.file-max", "kernel.randomize_va_space", "net..ipv4", "net/../ipv4/ip_forward",
		"/net/ipv4/ip_forward", "net.ipv4.ip_forward\nother",
	} {
		if _, err := workloadSysctlPath("/proc/sys", name); err == nil {
			t.Fatalf("unsafe sysctl %q unexpectedly accepted", name)
		}
	}
	for _, value := range []string{"one\ntwo", "one\x00two", "one\rtwo"} {
		if err := validateWorkloadSysctls(map[string]string{"net.ipv4.ip_forward": value}); err == nil {
			t.Fatalf("unsafe value %q unexpectedly accepted", value)
		}
	}
}

func TestApplyWorkloadSysctlsIsSortedAndFailsOnWrite(t *testing.T) {
	root := t.TempDir()
	paths := []string{
		filepath.Join(root, "net/ipv4/ip_forward"),
		filepath.Join(root, "kernel/domainname"),
	}
	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var writes []string
	err := applyWorkloadSysctls(root, map[string]string{
		"net.ipv4.ip_forward": "1", "kernel.domainname": "example.test",
	}, os.Lstat, func(path string, value []byte, _ os.FileMode) error {
		writes = append(writes, strings.TrimPrefix(path, root+string(filepath.Separator))+"="+string(value))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"kernel/domainname=example.test", "net/ipv4/ip_forward=1"}
	if !reflect.DeepEqual(writes, want) {
		t.Fatalf("writes = %#v, want %#v", writes, want)
	}

	failure := errors.New("read-only")
	err = applyWorkloadSysctls(root, map[string]string{"net.ipv4.ip_forward": "1"}, os.Lstat,
		func(string, []byte, os.FileMode) error { return failure })
	if !errors.Is(err, failure) {
		t.Fatalf("write failure = %v, want %v", err, failure)
	}
}

func TestApplyWorkloadSysctlsRejectsNonregularTargetBeforeWriting(t *testing.T) {
	root := t.TempDir()
	regular := filepath.Join(root, "kernel/domainname")
	if err := os.MkdirAll(filepath.Dir(regular), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(regular, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	nonregular := filepath.Join(root, "net/ipv4/ip_forward")
	if err := os.MkdirAll(nonregular, 0o755); err != nil {
		t.Fatal(err)
	}
	writes := 0
	err := applyWorkloadSysctls(root, map[string]string{
		"kernel.domainname": "example.test", "net.ipv4.ip_forward": "1",
	}, os.Lstat, func(string, []byte, os.FileMode) error {
		writes++
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "not a regular") {
		t.Fatalf("nonregular target error = %v", err)
	}
	if writes != 0 {
		t.Fatalf("writes before target validation = %d, want 0", writes)
	}
}

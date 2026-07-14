//go:build linux

package supervisor

import (
	"reflect"
	"testing"
)

func TestProcessEnvironmentProvidesDockerDefaultsAndConfiguredOverrides(t *testing.T) {
	actual := processEnvironment(
		[]string{"PATH=/custom/bin", "HOME=/workspace", "VALUE=present"},
		"container-name",
		"/root",
		true,
	)
	expected := []string{
		"PATH=/custom/bin",
		"HOSTNAME=container-name",
		"HOME=/workspace",
		"TERM=xterm",
		"VALUE=present",
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("process environment = %q, want %q", actual, expected)
	}
}

func TestProcessEnvironmentOmitsTerminalDefaultWithoutTTY(t *testing.T) {
	actual := processEnvironment(nil, "container-name", "/root", false)
	for _, entry := range actual {
		if entry == "TERM=xterm" {
			t.Fatal("non-terminal workload received TERM default")
		}
	}
}

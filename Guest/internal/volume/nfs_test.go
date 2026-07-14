//go:build linux

package volume

import (
	"strings"
	"testing"
)

func TestNFSMountOptionsBypassAmbientPortmapper(t *testing.T) {
	options, err := nfsMountOptions("100.64.0.1")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"vers=3", "addr=100.64.0.1", "port=2049", "mountport=2049", "sec=sys", "nolock", "hard"} {
		if !strings.Contains(options, expected) {
			t.Fatalf("mount options %q omit %q", options, expected)
		}
	}
}

func TestNFSMountOptionsRejectInvalidServer(t *testing.T) {
	for _, server := range []string{"", "storage", "100.64.0.999", "100.64.0.1/10"} {
		if _, err := nfsMountOptions(server); err == nil {
			t.Fatalf("expected %q to fail", server)
		}
	}
}

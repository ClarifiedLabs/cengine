package main

import (
	"os"
	"strings"
	"testing"
)

// This source check also runs on macOS without booting a storage VM.
func TestLifecycleEntrypointRequiresRealDiskBootstrap(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	verified := strings.Index(source, `verified, err = diskbootstrap.RunVerified("storage")`)
	run := strings.Index(source, "storageboot.RunLifecycle(context.Background(), verified, managementIP.String())")
	if verified < 0 || run < verified || !strings.Contains(source[verified:run], "guestnetwork.ConfigureManagement(") {
		t.Fatal("lifecycle must follow verified disk bootstrap and management setup")
	}
	for _, obsolete := range []string{"--managed-worker\"", "storageboot.Run(", "storageKernelMode", "ServeNFS", "volume_secret", "CheckLegacy"} {
		if strings.Contains(source, obsolete) {
			t.Fatalf("obsolete activation remains: %s", obsolete)
		}
	}
	if !strings.Contains(source, `os.Args[1] == "--managed-lifecycle-worker"`) || !strings.Contains(source, "storageboot.RunLifecycleWorker()") {
		t.Fatal("fixed lifecycle worker entry missing")
	}
}

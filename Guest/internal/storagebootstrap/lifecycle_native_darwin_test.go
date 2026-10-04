//go:build darwin && cgo

package storagebootstrap

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeLifecyclePolicyAndProcesses(t *testing.T) {
	for _, namespace := range []string{"production", "compatibility"} {
		t.Run(namespace, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			binary := filepath.Join(t.TempDir(), "lifecycle-native")
			args := []string{"-fblocks", "-Wall", "-Wextra", "-Werror", "-framework", "Security", "-framework", "CoreFoundation", "testdata/lifecycle_native_darwin.c", "-o", binary}
			if namespace == "compatibility" {
				args = append(args, "-DCE_STORAGE_LIFECYCLE_COMPATIBILITY=1")
			}
			if output, err := exec.CommandContext(ctx, "clang", args...).CombinedOutput(); err != nil {
				t.Fatalf("compile: %v\n%s", err, output)
			}
			for _, args := range [][]string{nil, {"sender"}, {"waiting"}} {
				if output, err := exec.CommandContext(ctx, binary, args...).CombinedOutput(); err != nil {
					t.Fatalf("native %v: %v\n%s", args, err, output)
				}
			}
		})
	}
}

func TestNativeLifecyclePolicyParity(t *testing.T) {
	v2, err := os.ReadFile("lifecycle_xpc_darwin.c")
	check(t, err)
	// The source contains CLOSED namespace and qualification branches; the preprocessed
	// default policy must still contain no compatibility namespace or override.
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	production, err := exec.CommandContext(ctx, "clang", "-E", "-P", "-fblocks", "lifecycle_xpc_darwin.c").CombinedOutput()
	if err != nil {
		t.Fatalf("preprocess default policy: %v\n%s", err, production)
	}
	if strings.Contains(string(production), "test-compat") || strings.Contains(string(v2), "CE_STORAGE_TEST_ENDPOINT") || strings.Contains(string(v2), "getenv(") {
		t.Fatal("default v2 acquired test/compatibility fallback")
	}
	compatibility, err := exec.CommandContext(ctx, "clang", "-E", "-P", "-fblocks", "-DCE_STORAGE_LIFECYCLE_COMPATIBILITY=1", "lifecycle_xpc_darwin.c").CombinedOutput()
	if err != nil {
		t.Fatalf("preprocess compatibility policy: %v\n%s", err, compatibility)
	}
	for _, role := range []string{"network-helper", "engine", "storage-control"} {
		if !strings.Contains(string(compatibility), `"dev.cengine.`+role+`.test-compat"`) || strings.Contains(string(compatibility), `"dev.cengine.`+role+`"`) {
			t.Fatal("compatibility namespace is not exact", role)
		}
	}
	if strings.Contains(string(compatibility), "qualification_fields") || strings.Contains(string(compatibility), "CEngineStorageLifecycleSourcePin") {
		t.Fatal("ordinary compatibility acquired qualification pin policy")
	}
	helper, err := os.ReadFile("../../../Sources/CEngineNetworkHelper/StorageBootstrapLifecycleChildXPC.swift")
	check(t, err)
	for _, operation := range []string{"storage-lifecycle-child", "storage-lifecycle-root-challenge"} {
		if !strings.Contains(string(v2), `"`+operation+`"`) || !strings.Contains(string(helper), `"`+operation+`"`) {
			t.Fatal("helper wire mismatch", operation)
		}
	}
}

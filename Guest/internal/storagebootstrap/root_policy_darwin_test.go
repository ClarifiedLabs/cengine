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

func TestNativeRootPeerPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for _, namespace := range []string{"production", "compatibility"} {
		binary := filepath.Join(t.TempDir(), "root-policy")
		args := []string{"-fblocks", "-Wall", "-Wextra", "-Werror", "-framework", "Security", "-framework", "CoreFoundation", "testdata/root_policy_darwin.c", "-o", binary}
		if namespace == "compatibility" {
			args = append(args, "-DCE_STORAGE_LIFECYCLE_COMPATIBILITY=1")
		}
		if output, err := exec.CommandContext(ctx, "clang", args...).CombinedOutput(); err != nil {
			t.Fatalf("compile native policy %s: %v\n%s", namespace, err, output)
		}
		if output, err := exec.CommandContext(ctx, binary).CombinedOutput(); err != nil {
			t.Fatalf("native policy %s: %v\n%s", namespace, err, output)
		}
	}
}

// Static parity complements native negative tests: when the sealed Swift policy
// changes, the mirrored C rejection list must change in the same reviewed patch.
func TestNativeRootEntitlementPolicyMatchesSwift(t *testing.T) {
	source, err := os.ReadFile("lifecycle_xpc_darwin.c")
	check(t, err)
	swift, err := os.ReadFile("../../../Sources/CEngineCore/SignedStorageIdentity.swift")
	check(t, err)
	extract := func(source, prefix, suffix string) map[string]bool {
		t.Helper()
		start := strings.Index(source, prefix)
		if start < 0 {
			t.Fatal("entitlement policy missing", prefix)
		}
		policy := source[start+len(prefix):]
		end := strings.Index(policy, suffix)
		if end < 0 {
			t.Fatal("entitlement policy malformed", prefix)
		}
		keys := make(map[string]bool)
		for _, part := range strings.Split(policy[:end], "\"") {
			if strings.HasPrefix(part, "com.apple.security.") {
				if keys[part] {
					t.Fatal("duplicate entitlement policy", part)
				}
				keys[part] = true
			}
		}
		return keys
	}
	swiftKeys := extract(string(swift), "forbiddenControllerEntitlements: Set<String> = [", "]")
	cKeys := extract(string(source), "const CFStringRef forbidden[] = {", "};")
	if len(swiftKeys) == 0 || len(swiftKeys) != len(cKeys) {
		t.Fatal("Swift/C entitlement set mismatch")
	}
	for key := range swiftKeys {
		if !cKeys[key] {
			t.Fatalf("C policy missing %s", key)
		}
	}
}

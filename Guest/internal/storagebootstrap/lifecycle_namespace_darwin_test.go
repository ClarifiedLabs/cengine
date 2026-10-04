//go:build darwin && cgo

package storagebootstrap

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Native policy tests exercise all compiled policies, not a runtime selector.
// Synthetic signing dictionaries only test rejection rules, never mint authority.
func TestNativeLifecycleNamespace(t *testing.T) {
	for _, policy := range []struct{ name, define string }{
		{"production", ""},
		{"compatibility", "CE_STORAGE_LIFECYCLE_COMPATIBILITY"},
		{"qualification", "CE_STORAGE_LIFECYCLE_QUALIFICATION"},
	} {
		t.Run(policy.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			dir := t.TempDir()
			source := filepath.Join(dir, "namespace.c")
			if err := os.WriteFile(source, []byte(nativeLifecycleNamespaceFixture), 0600); err != nil {
				t.Fatal(err)
			}
			cwd, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			binary := filepath.Join(dir, "namespace")
			args := []string{"-fblocks", "-Wall", "-Wextra", "-Werror", "-framework", "Security", "-framework", "CoreFoundation", "-I", cwd, source, "-o", binary}
			if policy.define != "" {
				args = append(args, "-D"+policy.define+"=1")
			}
			if output, err := exec.CommandContext(ctx, "clang", args...).CombinedOutput(); err != nil {
				t.Fatalf("compile: %v\n%s", err, output)
			}
			if output, err := exec.CommandContext(ctx, binary).CombinedOutput(); err != nil {
				t.Fatalf("native: %v\n%s", err, output)
			}
		})
	}
	t.Logf("Go package qualification namespace: %v", lifecycleQualificationNamespace)
}

const nativeLifecycleNamespaceFixture = `
#include "lifecycle_xpc_darwin.c"
#include <stdio.h>
#define CHECK(v) do { if (!(v)) { fprintf(stderr, "namespace line %d: %s\n", __LINE__, #v); exit(1); } } while (0)
static void set_flags(CFMutableDictionaryRef info, int64_t flags) {
    CFNumberRef number = CFNumberCreate(NULL, kCFNumberSInt64Type, &flags);
    CFDictionarySetValue(info, kSecCodeInfoFlags, number); CFRelease(number);
}
int main(void) {
    ce_lifecycle_root r = {0}; memcpy(r.team, "ABCDEFGHIJ", 11); pthread_mutex_init(&r.lock, NULL);
    CFMutableDictionaryRef info = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFMutableDictionaryRef plist = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    set_flags(info, CE_CS_RUNTIME);
    CFDictionarySetValue(info, kSecCodeInfoIdentifier, root_identifier(&r));
    CFDictionarySetValue(info, kSecCodeInfoTeamIdentifier, CFSTR("ABCDEFGHIJ"));
    CFDictionarySetValue(info, kSecCodeInfoPList, plist);
    CFDictionarySetValue(plist, CFSTR("CFBundleIdentifier"), root_identifier(&r));
    CFDictionarySetValue(plist, CFSTR("CEngineTeamIdentifier"), CFSTR("ABCDEFGHIJ"));
    CFDictionarySetValue(plist, CFSTR("CEngineNetworkHelperServiceName"), root_identifier(&r));
    CFDictionarySetValue(plist, CFSTR("CEngineNetworkHelperClientIdentifier"), CFSTR(CE_LIFECYCLE_ENGINE));
#if defined(CE_STORAGE_LIFECYCLE_COMPATIBILITY) || defined(CE_STORAGE_LIFECYCLE_QUALIFICATION)
    CHECK(!strcmp(CE_LIFECYCLE_ROOT, "dev.cengine.network-helper.test-compat"));
    CHECK(!strcmp(CE_LIFECYCLE_ENGINE, "dev.cengine.engine.test-compat"));
    CHECK(!strcmp(CE_LIFECYCLE_CONTROLLER, "dev.cengine.storage-control.test-compat"));
#ifdef CE_STORAGE_LIFECYCLE_QUALIFICATION
    const CFStringRef profile_key = CFSTR("CEngineStorageLifecycleQualification");
    const CFStringRef pin_key = CFSTR("CEngineStorageLifecycleSourcePin");
    const CFStringRef assets_key = CFSTR("CEngineStorageLifecycleAssetsSHA256");
    const CFStringRef pin = CFSTR("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CHECK(!root_information(&r, info));
    CFDictionarySetValue(plist, profile_key, CFSTR("lifecycle-v2-native-v1"));
    CHECK(!root_information(&r, info));
    CFDictionarySetValue(plist, pin_key, pin);
    CHECK(!root_information(&r, info)); // Uninitialized expected pin cannot admit ROOT.
    CHECK(!qualification_fields(plist, r.source_pin, r.assets_sha256));
    CFDictionarySetValue(plist, assets_key, pin);
    CHECK(!root_information(&r, info)); // Uninitialized assets cannot admit ROOT.
    CHECK(qualification_fields(plist, r.source_pin, r.assets_sha256));
    CHECK(root_information(&r, info));
    CFDictionarySetValue(plist, profile_key, kCFBooleanTrue); CHECK(!root_information(&r, info));
    CFDictionarySetValue(plist, profile_key, CFSTR("lifecycle-v2-native-v2")); CHECK(!root_information(&r, info));
    CFDictionarySetValue(plist, profile_key, CFSTR("lifecycle-v2-native-v1"));
    const CFTypeRef bad_pins[] = { kCFBooleanTrue, CFSTR(""), CFSTR("abc"),
        CFSTR("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeF"),
        CFSTR("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"),
        CFSTR("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"),
        CFSTR("1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") };
    for (size_t i=0;i<sizeof(bad_pins)/sizeof(bad_pins[0]);i++) {
        CFDictionarySetValue(plist, pin_key, bad_pins[i]); CHECK(!root_information(&r, info));
    }
    CFDictionarySetValue(plist, pin_key, pin);
    for (size_t i=0;i<sizeof(bad_pins)/sizeof(bad_pins[0]);i++) {
        CFDictionarySetValue(plist, assets_key, bad_pins[i]); CHECK(!root_information(&r, info));
    }
    CFDictionaryRemoveValue(plist, assets_key); CHECK(!root_information(&r, info));
    CFDictionarySetValue(plist, assets_key, pin); CHECK(root_information(&r, info));
#else
    CHECK(root_information(&r, info)); // Ordinary compatibility requires no qualification receipt.
#endif
    CFDictionarySetValue(info, kSecCodeInfoIdentifier, CFSTR("dev.cengine.network-helper")); CHECK(!root_information(&r, info));
#else
    CHECK(!strcmp(CE_LIFECYCLE_ROOT, "dev.cengine.network-helper"));
    CHECK(!strcmp(CE_LIFECYCLE_ENGINE, "dev.cengine.engine"));
    CHECK(!strcmp(CE_LIFECYCLE_CONTROLLER, "dev.cengine.storage-control"));
    CHECK(root_information(&r, info));
    CFDictionarySetValue(info, kSecCodeInfoIdentifier, CFSTR("dev.cengine.network-helper.test-compat")); CHECK(!root_information(&r, info));
#endif
    CFDictionarySetValue(info, kSecCodeInfoIdentifier, root_identifier(&r)); CHECK(root_information(&r, info));
    CFStringRef requirement = root_requirement(&r); CHECK(requirement);
    CHECK(CFStringFind(requirement, root_identifier(&r), 0).location != kCFNotFound);
    SecRequirementRef compiled = NULL;
    CHECK(SecRequirementCreateWithString(requirement, 0, &compiled) == errSecSuccess);
    CFRelease(compiled); CFRelease(requirement);
    CFDictionarySetValue(info, kSecCodeInfoTeamIdentifier, CFSTR("ZYXWVUTSRQ")); CHECK(!root_information(&r, info));
    CFDictionarySetValue(info, kSecCodeInfoTeamIdentifier, CFSTR("ABCDEFGHIJ"));
    CFDictionarySetValue(plist, CFSTR("CFBundleIdentifier"), CFSTR("wrong")); CHECK(!root_information(&r, info));
    CFDictionarySetValue(plist, CFSTR("CFBundleIdentifier"), root_identifier(&r));
    CFDictionarySetValue(plist, CFSTR("CEngineTeamIdentifier"), CFSTR("ZYXWVUTSRQ")); CHECK(!root_information(&r, info));
    CFDictionarySetValue(plist, CFSTR("CEngineTeamIdentifier"), CFSTR("ABCDEFGHIJ"));
    CFDictionarySetValue(info, kSecCodeInfoIdentifier, CFSTR(CE_LIFECYCLE_CONTROLLER)); CHECK(!root_information(&r, info));
    CFDictionarySetValue(info, kSecCodeInfoIdentifier, CFSTR(CE_LIFECYCLE_ENGINE)); CHECK(!root_information(&r, info));
    CFDictionarySetValue(info, kSecCodeInfoIdentifier, root_identifier(&r));
    CFDictionarySetValue(plist, CFSTR("CEngineNetworkHelperClientIdentifier"), CFSTR("wrong")); CHECK(!root_information(&r, info));
    CFDictionarySetValue(plist, CFSTR("CEngineNetworkHelperClientIdentifier"), CFSTR(CE_LIFECYCLE_ENGINE));
    CFDictionarySetValue(plist, CFSTR("CEngineNetworkHelperServiceName"), CFSTR("wrong")); CHECK(!root_information(&r, info));
    CFDictionarySetValue(plist, CFSTR("CEngineNetworkHelperServiceName"), root_identifier(&r));
    set_flags(info, CE_CS_RUNTIME | CE_CS_ADHOC); CHECK(!root_information(&r, info));
    set_flags(info, 0); CHECK(!root_information(&r, info)); set_flags(info, CE_CS_RUNTIME);
    CFMutableDictionaryRef entitlements = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(info, kSecCodeInfoEntitlementsDict, entitlements);
    CFDictionarySetValue(entitlements, CFSTR("com.apple.security.get-task-allow"), kCFBooleanFalse); CHECK(!root_information(&r, info));
    CFDictionaryRemoveAllValues(entitlements); CHECK(root_information(&r, info));
    xpc_object_t forged = xpc_dictionary_create(NULL, NULL, 0);
    audit_token_t fake = {{0}}; fake.val[5] = getpid();
    xpc_dictionary_set_data(forged, "audit_token", &fake, sizeof(fake));
    CHECK(!root_message(&r, forged)); CHECK(!r.root_unique); xpc_release(forged);
    ce_lifecycle_root own = {0}; CHECK(!self_identity(&own)); // Unsigned/ad-hoc fixture cannot derive signed authority.
    CHECK(!ce_lifecycle_open("{}", 2));
    CFRelease(entitlements); CFRelease(plist); CFRelease(info); pthread_mutex_destroy(&r.lock);
    return 0;
}
`

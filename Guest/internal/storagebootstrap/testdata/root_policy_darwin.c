// Standalone native policy fixture: no installed service, elevation, or keys.
// Includes the real C implementation so tests cannot drift to a copied checker.
#include "../lifecycle_xpc_darwin.c"
#include <stdio.h>

#define CHECK(v) do { if (!(v)) { fprintf(stderr, "root policy check failed at line %d: %s\n", __LINE__, #v); exit(1); } } while (0)
static CFMutableDictionaryRef dictionary(void) {
    return CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
}
static void flags(CFMutableDictionaryRef info, int64_t value) {
    CFNumberRef number = CFNumberCreate(NULL, kCFNumberSInt64Type, &value);
    CFDictionarySetValue(info, kSecCodeInfoFlags, number); CFRelease(number);
}
static void pure_policy(void) {
    const CFStringRef forbidden[] = {
        CFSTR("com.apple.security.get-task-allow"), CFSTR("com.apple.security.cs.debugger"),
        CFSTR("com.apple.security.cs.disable-library-validation"), CFSTR("com.apple.security.cs.allow-unsigned-executable-memory"),
        CFSTR("com.apple.security.cs.allow-dyld-environment-variables"), CFSTR("com.apple.security.cs.allow-jit"),
        CFSTR("com.apple.security.cs.disable-executable-page-protection")
    };
    {
        struct ce_lifecycle_root r = {0}; memcpy(r.team, "ABCDEFGHIJ", 11);
        CFStringRef expression = root_requirement(&r); CHECK(expression);
        CHECK(CFStringFind(expression, CFSTR("certificate 1[field.1.2.840.113635.100.6.2.6] exists"), 0).location != kCFNotFound);
        CHECK(CFStringFind(expression, CFSTR("certificate leaf[field.1.2.840.113635.100.6.1.13] exists"), 0).location != kCFNotFound);
        SecRequirementRef requirement = NULL;
        CHECK(SecRequirementCreateWithString(expression, kSecCSDefaultFlags, &requirement) == errSecSuccess);
        CFRelease(requirement); CFRelease(expression);
        r.team[0]='"'; CHECK(!root_requirement(&r)); r.team[0]='A';
        CFMutableDictionaryRef info = dictionary(), plist = dictionary();
        CFDictionarySetValue(info, kSecCodeInfoIdentifier, root_identifier(&r));
        CFDictionarySetValue(info, kSecCodeInfoTeamIdentifier, CFSTR("ABCDEFGHIJ"));
        flags(info, CE_CS_RUNTIME);
        const CFStringRef keys[] = {CFSTR("CFBundleIdentifier"), CFSTR("CEngineTeamIdentifier"), CFSTR("CEngineNetworkHelperServiceName"), CFSTR("CEngineNetworkHelperClientIdentifier")};
        const CFStringRef values[] = {root_identifier(&r), CFSTR("ABCDEFGHIJ"), root_identifier(&r), CFSTR(CE_LIFECYCLE_ENGINE)};
        for (size_t i=0;i<4;i++) CFDictionarySetValue(plist, keys[i], values[i]);
        CFDictionarySetValue(info, kSecCodeInfoPList, plist);
        CHECK(root_information(&r, info));
        const int64_t invalid_flags[] = {0, CE_CS_ADHOC, CE_CS_RUNTIME|CE_CS_ADHOC, -1, (int64_t)UINT32_MAX+1};
        for (size_t i=0;i<sizeof(invalid_flags)/sizeof(invalid_flags[0]);i++) { flags(info, invalid_flags[i]); CHECK(!root_information(&r, info)); }
        CFDictionarySetValue(info, kSecCodeInfoFlags, kCFBooleanTrue); CHECK(!root_information(&r, info));
        CFDictionaryRemoveValue(info, kSecCodeInfoFlags); CHECK(!root_information(&r, info)); flags(info, CE_CS_RUNTIME);
        for (size_t i=0;i<4;i++) {
            CFDictionarySetValue(plist, keys[i], CFSTR("wrong")); CHECK(!root_information(&r, info));
            CFDictionarySetValue(plist, keys[i], kCFBooleanTrue); CHECK(!root_information(&r, info));
            CFDictionaryRemoveValue(plist, keys[i]); CHECK(!root_information(&r, info));
            CFDictionarySetValue(plist, keys[i], values[i]); CHECK(root_information(&r, info));
        }
        CFDictionarySetValue(info, kSecCodeInfoPList, CFSTR("not a dictionary")); CHECK(!root_information(&r, info));
        CFDictionaryRemoveValue(info, kSecCodeInfoPList); CHECK(!root_information(&r, info)); CFDictionarySetValue(info, kSecCodeInfoPList, plist);
        CFDictionarySetValue(info, kSecCodeInfoTeamIdentifier, CFSTR("ZZZZZZZZZZ")); CHECK(!root_information(&r, info)); CFDictionarySetValue(info, kSecCodeInfoTeamIdentifier, CFSTR("ABCDEFGHIJ"));
        CFDictionarySetValue(info, kSecCodeInfoIdentifier, CFSTR("dev.cengine.storage-control.test-compat")); CHECK(!root_information(&r, info)); CFDictionarySetValue(info, kSecCodeInfoIdentifier, root_identifier(&r));
        CFMutableDictionaryRef entitlements = dictionary(); CFDictionarySetValue(info, kSecCodeInfoEntitlementsDict, entitlements);
        CFDictionarySetValue(entitlements, CFSTR("com.apple.security.virtualization"), kCFBooleanTrue); CHECK(root_information(&r, info));
        for (size_t i=0;i<sizeof(forbidden)/sizeof(forbidden[0]);i++) {
            CFDictionarySetValue(entitlements, forbidden[i], kCFBooleanFalse); CHECK(!root_information(&r, info));
            CFDictionarySetValue(entitlements, forbidden[i], kCFBooleanTrue); CHECK(!root_information(&r, info));
            CFDictionaryRemoveValue(entitlements, forbidden[i]); CHECK(root_information(&r, info));
        }
        CFDictionarySetValue(entitlements, kCFBooleanTrue, kCFBooleanTrue); CHECK(!root_information(&r, info));
        CFDictionarySetValue(info, kSecCodeInfoEntitlementsDict, CFSTR("not a dictionary")); CHECK(!root_information(&r, info));
        xpc_object_t forged = xpc_dictionary_create(NULL, NULL, 0);
        unsigned char fake[32] = {0}; xpc_dictionary_set_data(forged, "audit_token", fake, sizeof(fake));
        CHECK(!root_message(&r, forged)); xpc_release(forged);
        CFRelease(entitlements); CFRelease(plist); CFRelease(info);
    }
}
int main(void) {
    pure_policy();
    puts("root peer policy PASS"); return 0;
}

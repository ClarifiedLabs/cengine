//go:build darwin && cgo

// The build selects the native lifecycle policy's compatibility namespace from
// its exact signing identifier. Qualification separately requires sealed pins;
// no runtime value can select either policy.
#include "lifecycle_xpc_darwin.h"
#include <xpc/xpc.h>
#include <Security/Security.h>
#include <bsm/audit.h>
#include <dispatch/dispatch.h>
#include <libproc.h>
#include <mach/mach.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
extern void xpc_dictionary_get_audit_token(xpc_object_t, audit_token_t *);
extern int csops(pid_t, unsigned int, void *, size_t);
#define CE_BOUND (64U << 10)
#define CE_CS_ADHOC 0x00000002U
#define CE_CS_RUNTIME 0x00010000U
#if defined(CE_STORAGE_LIFECYCLE_COMPATIBILITY) || defined(CE_STORAGE_LIFECYCLE_QUALIFICATION)
#define CE_LIFECYCLE_CONTROLLER "dev.cengine.storage-control.test-compat"
#define CE_LIFECYCLE_ENGINE "dev.cengine.engine.test-compat"
#define CE_LIFECYCLE_ROOT "dev.cengine.network-helper.test-compat"
#else
#define CE_LIFECYCLE_CONTROLLER "dev.cengine.storage-control"
#define CE_LIFECYCLE_ENGINE "dev.cengine.engine"
#define CE_LIFECYCLE_ROOT "dev.cengine.network-helper"
#endif
struct ce_lifecycle_root {
    xpc_connection_t connection;
    dispatch_queue_t queue;
    dispatch_semaphore_t ready, closed, ended;
    dispatch_group_t pending;
    pthread_mutex_t lock;
    unsigned char payload[CE_BOUND];
    size_t length;
    xpc_object_t reply;
    int failed, acknowledged;
    dispatch_time_t greeting_deadline;
    char team[11];
#ifdef CE_STORAGE_LIFECYCLE_QUALIFICATION
    char source_pin[65], assets_sha256[65]; // Derived only from this process's validated signed plist.
#endif
    audit_token_t root_audit;
    uint64_t root_unique;
};
static int unique(pid_t pid, uint64_t *id, uint64_t *parent, uint32_t *version) {
    unsigned char b[56];
    if (proc_pidinfo(pid, 17, 0, b, sizeof(b)) != sizeof(b)) return 0;
    memcpy(id, b+16, 8); memcpy(parent, b+24, 8); memcpy(version, b+32, 4);
    return *id != 0;
}
// Keep this rejection policy aligned with SignedCompatibilityIdentity.validatePeer
// and SignedStorageIdentity.forbiddenControllerEntitlements. None of these
// helpers creates an identity proof; root_message still requires the Mach trailer.
static CFStringRef root_identifier(const struct ce_lifecycle_root *r) {
    (void)r;
    return CFSTR(CE_LIFECYCLE_ROOT);
}
static CFStringRef identity_requirement(const struct ce_lifecycle_root *r, CFStringRef identifier) {
    if (strnlen(r->team, sizeof(r->team)) != 10) return NULL;
    for (int i=0;i<10;i++) if (!((r->team[i]>='A' && r->team[i]<='Z') || (r->team[i]>='0' && r->team[i]<='9'))) return NULL;
    return CFStringCreateWithFormat(NULL, NULL,
        CFSTR("anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and (identifier \"%@\") and certificate leaf[subject.OU] = \"%s\""),
        identifier, r->team);
}
static CFStringRef root_requirement(const struct ce_lifecycle_root *r) {
    return identity_requirement(r, root_identifier(r));
}
static int string_field(CFDictionaryRef values, CFStringRef key, CFStringRef expected) {
    CFTypeRef value = CFDictionaryGetValue(values, key);
    return value && CFGetTypeID(value) == CFStringGetTypeID() && CFEqual(value, expected);
}
static void entitlement_key(const void *key, const void *value, void *context) {
    (void)value;
    if (CFGetTypeID(key) != CFStringGetTypeID()) *(int *)context = 0;
}
static int code_flags(CFDictionaryRef info) {
    if (!info || CFGetTypeID(info) != CFDictionaryGetTypeID()) return 0;
    CFTypeRef raw_flags = CFDictionaryGetValue(info, kSecCodeInfoFlags);
    int64_t flags = 0;
    if (!raw_flags || CFGetTypeID(raw_flags) != CFNumberGetTypeID() ||
        !CFNumberGetValue(raw_flags, kCFNumberSInt64Type, &flags) || flags < 0 || flags > UINT32_MAX ||
        !(flags & CE_CS_RUNTIME) || (flags & CE_CS_ADHOC)) return 0;
    CFDictionaryRef entitlements = CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict);
    if (entitlements) {
        if (CFGetTypeID(entitlements) != CFDictionaryGetTypeID()) return 0;
        int keys_valid = 1;
        CFDictionaryApplyFunction(entitlements, entitlement_key, &keys_valid);
        if (!keys_valid) return 0;
        const CFStringRef forbidden[] = {
            CFSTR("com.apple.security.get-task-allow"), CFSTR("com.apple.security.cs.debugger"),
            CFSTR("com.apple.security.cs.disable-library-validation"), CFSTR("com.apple.security.cs.allow-unsigned-executable-memory"),
            CFSTR("com.apple.security.cs.allow-dyld-environment-variables"), CFSTR("com.apple.security.cs.allow-jit"),
            CFSTR("com.apple.security.cs.disable-executable-page-protection")
        };
        for (size_t i=0;i<sizeof(forbidden)/sizeof(forbidden[0]);i++)
            if (CFDictionaryContainsKey(entitlements, forbidden[i])) return 0; // Even false is forbidden.
    }
    return 1;
}
#ifdef CE_STORAGE_LIFECYCLE_QUALIFICATION
// Rejection policy only. Authentication callers must validate the actual running
// and static signatures before relying on these signed plist fields.
static int sha256_field(CFDictionaryRef plist, CFStringRef key, char pin[65]) {
    CFStringRef value = CFDictionaryGetValue(plist, key);
    if (!value || CFGetTypeID(value) != CFStringGetTypeID() || CFStringGetLength(value) != 64 ||
        !CFStringGetCString(value, pin, 65, kCFStringEncodingASCII)) return 0;
    for (int i=0;i<64;i++) if (!((pin[i]>='0' && pin[i]<='9') || (pin[i]>='a' && pin[i]<='f'))) return 0;
    return 1;
}
static int qualification_fields(CFDictionaryRef plist, char pin[65], char assets[65]) {
    return plist && CFGetTypeID(plist) == CFDictionaryGetTypeID() &&
        string_field(plist, CFSTR("CEngineStorageLifecycleQualification"), CFSTR("lifecycle-v2-native-v1")) &&
        sha256_field(plist, CFSTR("CEngineStorageLifecycleSourcePin"), pin) &&
        sha256_field(plist, CFSTR("CEngineStorageLifecycleAssetsSHA256"), assets);
}
#endif
static int root_information(const struct ce_lifecycle_root *r, CFDictionaryRef info) {
    if (!code_flags(info)) return 0;
    CFStringRef team = CFStringCreateWithCString(NULL, r->team, kCFStringEncodingASCII);
    if (!team) return 0;
    int ok = string_field(info, kSecCodeInfoTeamIdentifier, team) &&
        string_field(info, kSecCodeInfoIdentifier, root_identifier(r));
    CFDictionaryRef plist = CFDictionaryGetValue(info, kSecCodeInfoPList);
    ok = ok && plist && CFGetTypeID(plist) == CFDictionaryGetTypeID() &&
        string_field(plist, CFSTR("CFBundleIdentifier"), root_identifier(r)) &&
        string_field(plist, CFSTR("CEngineTeamIdentifier"), team) &&
        string_field(plist, CFSTR("CEngineNetworkHelperServiceName"), root_identifier(r)) &&
        string_field(plist, CFSTR("CEngineNetworkHelperClientIdentifier"),
            CFSTR(CE_LIFECYCLE_ENGINE));
#ifdef CE_STORAGE_LIFECYCLE_QUALIFICATION
    char pin[65], assets[65];
    ok = ok && qualification_fields(plist, pin, assets) && !memcmp(pin, r->source_pin, sizeof(pin)) &&
        !memcmp(assets, r->assets_sha256, sizeof(assets));
#endif
    CFRelease(team);
    return ok;
}
static int self_identity(struct ce_lifecycle_root *r) {
    SecCodeRef code = NULL; SecStaticCodeRef stat = NULL; CFDictionaryRef info = NULL;
#ifdef CE_STORAGE_LIFECYCLE_QUALIFICATION
    CFStringRef expression = NULL; SecRequirementRef requirement = NULL; uint32_t status = 0;
#endif
    int ok = 0;
    if (SecCodeCopySelf(kSecCSDefaultFlags, &code) != errSecSuccess ||
        SecCodeCopyStaticCode(code, kSecCSDefaultFlags, &stat) != errSecSuccess ||
        SecCodeCopySigningInformation(stat, kSecCSSigningInformation, &info) != errSecSuccess) goto out;
    CFStringRef t = CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier);
    if (!t || CFGetTypeID(t) != CFStringGetTypeID() || CFStringGetLength(t) != 10 ||
        !CFStringGetCString(t, r->team, sizeof(r->team), kCFStringEncodingASCII) ||
        !string_field(info, kSecCodeInfoIdentifier, CFSTR(CE_LIFECYCLE_CONTROLLER))) goto out;
    for (int i=0;i<10;i++) if (!((r->team[i]>='A' && r->team[i]<='Z') || (r->team[i]>='0' && r->team[i]<='9'))) goto out;
#ifdef CE_STORAGE_LIFECYCLE_QUALIFICATION
    expression = identity_requirement(r, CFSTR(CE_LIFECYCLE_CONTROLLER));
    if (!expression || SecRequirementCreateWithString(expression, kSecCSDefaultFlags, &requirement) != errSecSuccess ||
        SecCodeCheckValidity(code, kSecCSStrictValidate, requirement) != errSecSuccess ||
        SecStaticCodeCheckValidity(stat, kSecCSStrictValidate, requirement) != errSecSuccess || !code_flags(info) ||
        csops(getpid(), 0, &status, sizeof(status)) != 0 || !(status & CE_CS_RUNTIME) ||
        !qualification_fields(CFDictionaryGetValue(info, kSecCodeInfoPList), r->source_pin, r->assets_sha256)) goto out;
#endif
    ok = 1;
out:
#ifdef CE_STORAGE_LIFECYCLE_QUALIFICATION
    if (requirement) CFRelease(requirement); if (expression) CFRelease(expression);
#endif
    if (info) CFRelease(info); if (stat) CFRelease(stat); if (code) CFRelease(code);
    return ok;
}
static int root_message(struct ce_lifecycle_root *r, xpc_object_t message) {
    audit_token_t audit = {{0}};
    xpc_dictionary_get_audit_token(message, &audit);
    uid_t owner = 0;
    if (audit.val[1] != owner || audit.val[3] != owner || audit.val[5] == 0) return 0;
    uint64_t id, parent, after, after_parent; uint32_t version, after_version;
    if (!unique((pid_t)audit.val[5], &id, &parent, &version) || version != audit.val[7]) return 0;
    CFStringRef expression = root_requirement(r);
    SecRequirementRef requirement = NULL; SecCodeRef code = NULL; SecStaticCodeRef stat = NULL;
    CFDictionaryRef info = NULL; uint32_t status = 0;
    CFDataRef data = CFDataCreate(NULL, (const UInt8 *)&audit, sizeof(audit));
    const void *keys[] = { kSecGuestAttributeAudit }; const void *values[] = { data };
    CFDictionaryRef attributes = data ? CFDictionaryCreate(NULL, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks) : NULL;
    int ok = expression && data && attributes &&
        SecRequirementCreateWithString(expression, kSecCSDefaultFlags, &requirement) == errSecSuccess &&
        SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code) == errSecSuccess &&
        SecCodeCheckValidity(code, kSecCSStrictValidate, requirement) == errSecSuccess &&
        SecCodeCopyStaticCode(code, kSecCSDefaultFlags, &stat) == errSecSuccess &&
        SecStaticCodeCheckValidity(stat, kSecCSStrictValidate, requirement) == errSecSuccess &&
        SecCodeCopySigningInformation(stat, kSecCSSigningInformation, &info) == errSecSuccess &&
        root_information(r, info) &&
        csops((pid_t)audit.val[5], 0, &status, sizeof(status)) == 0 && (status & CE_CS_RUNTIME) != 0 &&
        unique((pid_t)audit.val[5], &after, &after_parent, &after_version) &&
        id == after && parent == after_parent && version == after_version;
    if (info) CFRelease(info); if (stat) CFRelease(stat);
    if (code) CFRelease(code); if (requirement) CFRelease(requirement);
    if (attributes) CFRelease(attributes); if (data) CFRelease(data); if (expression) CFRelease(expression);
    if (ok) {
        pthread_mutex_lock(&r->lock);
        if (r->root_unique == 0) { r->root_unique = id; r->root_audit = audit; }
        else ok = r->root_unique == id && !memcmp(&r->root_audit, &audit, sizeof(audit));
        pthread_mutex_unlock(&r->lock);
    }
    return ok;
}

static void fail(ce_lifecycle_root *r) {
    pthread_mutex_lock(&r->lock);
    int first = !r->failed; r->failed = 1;
    pthread_mutex_unlock(&r->lock);
    if (first) { dispatch_semaphore_signal(r->ready); dispatch_semaphore_signal(r->closed); }
}
void ce_lifecycle_cancel(ce_lifecycle_root *r) {
    if (!r) return;
    fail(r); xpc_connection_cancel(r->connection);
}
static void received(ce_lifecycle_root *r, xpc_object_t message) {
    if (xpc_get_type(message) == XPC_TYPE_ERROR) {
        fail(r);
        if (message == XPC_ERROR_CONNECTION_INVALID) dispatch_semaphore_signal(r->ended);
        return;
    }
    if (xpc_get_type(message) != XPC_TYPE_DICTIONARY) { ce_lifecycle_cancel(r); return; }
    const char *operation = xpc_dictionary_get_string(message, "operation");
    size_t n = 0;
    const void *bytes = xpc_dictionary_get_data(message, "request", &n);
    if (!operation || strcmp(operation, "storage-lifecycle-root-challenge") ||
        !bytes || !n || n > CE_BOUND || !root_message(r, message)) { ce_lifecycle_cancel(r); return; }
    pthread_mutex_lock(&r->lock);
    int invalid = r->failed || r->reply;
    if (!invalid) {
        r->reply = xpc_dictionary_create_reply(message);
        invalid = !r->reply;
        if (!invalid) { memcpy(r->payload, bytes, n); r->length = n; }
    }
    pthread_mutex_unlock(&r->lock);
    if (invalid) ce_lifecycle_cancel(r); else dispatch_semaphore_signal(r->ready);
}
// Called only after the greeting reply passes ROOT authentication. Expiry and
// cancellation must be checked under the same lock as acknowledgement publication.
static void acknowledge_greeting(ce_lifecycle_root *r) {
    pthread_mutex_lock(&r->lock);
    int invalid = r->failed || dispatch_time(DISPATCH_TIME_NOW, 0) >= r->greeting_deadline;
    if (!invalid) r->acknowledged = 1;
    pthread_mutex_unlock(&r->lock);
    if (invalid) ce_lifecycle_cancel(r); else dispatch_semaphore_signal(r->ready);
}
ce_lifecycle_root *ce_lifecycle_open(const void *greeting, size_t length) {
    if (!greeting || !length || length > CE_BOUND) return NULL;
    ce_lifecycle_root *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    if (!self_identity(r)) { free(r); return NULL; }
    pthread_mutex_init(&r->lock, NULL);
    r->queue = dispatch_queue_create("dev.cengine.storage-lifecycle.root", DISPATCH_QUEUE_SERIAL);
    r->ready = dispatch_semaphore_create(0); r->closed = dispatch_semaphore_create(0); r->ended = dispatch_semaphore_create(0);
    r->pending = dispatch_group_create();
    r->greeting_deadline = dispatch_time(DISPATCH_TIME_NOW, 5*NSEC_PER_SEC);
    r->connection = xpc_connection_create_mach_service(CE_LIFECYCLE_ROOT, r->queue, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    xpc_connection_set_event_handler(r->connection, ^(xpc_object_t message) { received(r, message); });
    xpc_connection_resume(r->connection);
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_int64(message, "version", 5);
    xpc_dictionary_set_string(message, "operation", "storage-lifecycle-child");
    xpc_dictionary_set_string(message, "role", "controller-child");
    xpc_dictionary_set_data(message, "request", greeting, length);
    dispatch_group_enter(r->pending);
    xpc_connection_send_message_with_reply(r->connection, message, r->queue, ^(xpc_object_t reply) {
        if (xpc_get_type(reply) != XPC_TYPE_DICTIONARY || !root_message(r, reply) ||
            !xpc_dictionary_get_value(reply, "ok") || xpc_get_type(xpc_dictionary_get_value(reply, "ok")) != XPC_TYPE_BOOL || !xpc_dictionary_get_bool(reply, "ok")) ce_lifecycle_cancel(r);
        else acknowledge_greeting(r);
        dispatch_group_leave(r->pending);
    });
    xpc_release(message);
    return r;
}
int ce_lifecycle_next(ce_lifecycle_root *r, void *bytes, size_t capacity, size_t *length) {
    if (!r || !bytes || !length) return -1;
    pthread_mutex_lock(&r->lock);
    dispatch_time_t deadline = r->acknowledged ? DISPATCH_TIME_FOREVER : r->greeting_deadline;
    int failed = r->failed;
    pthread_mutex_unlock(&r->lock);
    // Ack, request and cancellation all signal ready, including a transition
    // between this snapshot and the wait. Established idle owners do not poll.
    if (!failed) dispatch_semaphore_wait(r->ready, deadline);
    pthread_mutex_lock(&r->lock);
    int expired = !r->acknowledged && dispatch_time(DISPATCH_TIME_NOW, 0) >= r->greeting_deadline;
    int result = r->failed || expired ? -1 : 0;
    if (!result && r->reply && r->length) {
        if (r->length > capacity) result = -1;
        else { memcpy(bytes, r->payload, r->length); *length = r->length; r->length = 0; result = 1; }
    }
    pthread_mutex_unlock(&r->lock);
    if (result < 0) ce_lifecycle_cancel(r);
    return result;
}
int ce_lifecycle_reply(ce_lifecycle_root *r, const void *bytes, size_t length) {
    if (!r || !bytes || !length || length > CE_BOUND) return -1;
    pthread_mutex_lock(&r->lock);
    if (r->failed || !r->reply) { pthread_mutex_unlock(&r->lock); return -1; }
    xpc_dictionary_set_data(r->reply, "reply", bytes, length);
    xpc_connection_send_message(r->connection, r->reply);
    xpc_release(r->reply); r->reply = NULL;
    pthread_mutex_unlock(&r->lock);
    return 0;
}
void ce_lifecycle_wait_closed(ce_lifecycle_root *r) {
    dispatch_semaphore_wait(r->closed, DISPATCH_TIME_FOREVER);
}
void ce_lifecycle_destroy(ce_lifecycle_root *r) {
    if (!r) return;
    ce_lifecycle_cancel(r);
    // A stalled Security/XPC callback leaks this single context, never UAF or
    // an unbounded shutdown wait, and is never interpreted as process death.
    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, 5*NSEC_PER_SEC);
    if (dispatch_semaphore_wait(r->ended, deadline) || dispatch_group_wait(r->pending, deadline)) return;
    dispatch_group_async(r->pending, r->queue, ^{});
    if (dispatch_group_wait(r->pending, deadline)) return;
    if (r->reply) xpc_release(r->reply);
    xpc_release(r->connection);
    dispatch_release(r->ready); dispatch_release(r->closed); dispatch_release(r->ended);
    dispatch_release(r->pending); dispatch_release(r->queue);
    pthread_mutex_destroy(&r->lock); free(r);
}
int ce_lifecycle_parent(int fd, ce_lifecycle_processes *out) {
    if (!out) return -1;
    struct stat st; int kind = 0; socklen_t size = sizeof(kind);
    struct sockaddr_un address; socklen_t address_size = sizeof(address);
    audit_token_t peer = {{0}}, own = {{0}}; socklen_t peer_size = sizeof(peer);
    pid_t parent = getppid(), child = getpid();
    uint64_t pu, pp, cu, cp, pu2, pp2, cu2, cp2; uint32_t pv, cv, pv2, cv2;
    if (fd != 3 || getuid() != geteuid() || fstat(fd, &st) || !S_ISSOCK(st.st_mode) || st.st_uid != geteuid() ||
        getsockopt(fd, SOL_SOCKET, SO_TYPE, &kind, &size) || kind != SOCK_STREAM ||
        getpeername(fd, (struct sockaddr *)&address, &address_size) || address.sun_family != AF_UNIX ||
        getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &peer, &peer_size) || peer_size != sizeof(peer) ||
        peer.val[5] != (uint32_t)parent || peer.val[1] != geteuid() || peer.val[3] != getuid() ||
        !unique(parent, &pu, &pp, &pv) || !unique(child, &cu, &cp, &cv) || cp != pu || peer.val[7] != pv) return -1;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&own, &count) != KERN_SUCCESS || count != TASK_AUDIT_TOKEN_COUNT ||
        own.val[5] != (uint32_t)child || own.val[7] != cv || own.val[1] != geteuid() || own.val[3] != getuid() ||
        !unique(parent, &pu2, &pp2, &pv2) || !unique(child, &cu2, &cp2, &cv2) || getppid() != parent ||
        pu != pu2 || pp != pp2 || pv != pv2 || cu != cu2 || cp != cp2 || cv != cv2 ||
        fcntl(fd, F_SETFD, FD_CLOEXEC)) return -1;
    ce_lifecycle_processes observed = { .daemon_unique = pu, .child_unique = cu };
    memcpy(observed.daemon_audit, &peer, 32); memcpy(observed.child_audit, &own, 32);
    *out = observed;
    return 0;
}

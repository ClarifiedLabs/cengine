// Native regression fixture; no installed service, signing identity or elevation.
#include "../lifecycle_xpc_darwin.c"
#include <stdio.h>
#include <sys/wait.h>
#define CHECK(v) do { if (!(v)) { fprintf(stderr, "lifecycle check line %d: %s\n", __LINE__, #v); exit(1); } } while (0)

static void policy(void) {
    ce_lifecycle_root r = {0}; memcpy(r.team, "ABCDEFGHIJ", 11); pthread_mutex_init(&r.lock, NULL);
    CFStringRef expression = root_requirement(&r); CHECK(expression);
    SecRequirementRef requirement = NULL;
    CHECK(SecRequirementCreateWithString(expression, kSecCSDefaultFlags, &requirement) == errSecSuccess);
    CFRelease(requirement); CFRelease(expression);
    r.team[0] = '"'; CHECK(!root_requirement(&r)); r.team[0] = 'A';
    CFMutableDictionaryRef info = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFMutableDictionaryRef plist = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    int64_t flags = CE_CS_RUNTIME;
    CFNumberRef number = CFNumberCreate(NULL, kCFNumberSInt64Type, &flags);
    CFDictionarySetValue(info, kSecCodeInfoFlags, number); CFRelease(number);
    CFDictionarySetValue(info, kSecCodeInfoIdentifier, root_identifier(&r));
    CFDictionarySetValue(info, kSecCodeInfoTeamIdentifier, CFSTR("ABCDEFGHIJ"));
    CFDictionarySetValue(info, kSecCodeInfoPList, plist);
    CFDictionarySetValue(plist, CFSTR("CFBundleIdentifier"), root_identifier(&r));
    CFDictionarySetValue(plist, CFSTR("CEngineTeamIdentifier"), CFSTR("ABCDEFGHIJ"));
    CFDictionarySetValue(plist, CFSTR("CEngineNetworkHelperServiceName"), root_identifier(&r));
    CFDictionarySetValue(plist, CFSTR("CEngineNetworkHelperClientIdentifier"), CFSTR(CE_LIFECYCLE_ENGINE));
    CHECK(root_information(&r, info));
#ifdef CE_STORAGE_LIFECYCLE_COMPATIBILITY
    CFDictionarySetValue(info, kSecCodeInfoIdentifier, CFSTR("dev.cengine.network-helper"));
#else
    CFDictionarySetValue(info, kSecCodeInfoIdentifier, CFSTR("dev.cengine.network-helper.test-compat"));
#endif
    CHECK(!root_information(&r, info));
    CFDictionarySetValue(info, kSecCodeInfoIdentifier, root_identifier(&r));
    CFMutableDictionaryRef entitlements = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(entitlements, CFSTR("com.apple.security.get-task-allow"), kCFBooleanFalse);
    CFDictionarySetValue(info, kSecCodeInfoEntitlementsDict, entitlements);
    CHECK(!root_information(&r, info));
    xpc_object_t forged = xpc_dictionary_create(NULL, NULL, 0);
    audit_token_t fake = {{0}}; fake.val[5] = getpid();
    xpc_dictionary_set_data(forged, "audit_token", &fake, sizeof(fake));
    CHECK(!root_message(&r, forged)); CHECK(!r.root_unique); xpc_release(forged);
    CFRelease(entitlements); CFRelease(plist); CFRelease(info); pthread_mutex_destroy(&r.lock);
}

// An actual unprivileged Mach message with forged ROOT dictionary fields MUST
// be rejected by the production trailer checker. There is no test auth override.
static void native_sender(void) {
    ce_lifecycle_root *root = calloc(1, sizeof(*root)); CHECK(root);
    memcpy(root->team, "ABCDEFGHIJ", 11); pthread_mutex_init(&root->lock, NULL);
    dispatch_queue_t queue = dispatch_queue_create("lifecycle.fixture", DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    xpc_connection_t listener = xpc_connection_create(NULL, queue);
    xpc_connection_set_event_handler(listener, ^(xpc_object_t peer) {
        CHECK(xpc_get_type(peer) == XPC_TYPE_CONNECTION);
        xpc_connection_set_event_handler(peer, ^(xpc_object_t message) {
            if (xpc_get_type(message) == XPC_TYPE_DICTIONARY) {
                CHECK(!root_message(root, message)); CHECK(!root->root_unique);
                dispatch_semaphore_signal(done);
            }
        });
        xpc_connection_resume(peer);
    });
    xpc_connection_resume(listener);
    xpc_endpoint_t endpoint = xpc_endpoint_create(listener);
    xpc_connection_t client = xpc_connection_create_from_endpoint(endpoint);
    xpc_release(endpoint); xpc_connection_set_event_handler(client, ^(xpc_object_t ignored) { (void)ignored; });
    xpc_connection_resume(client);
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    audit_token_t fake = {{0}}; fake.val[5] = getpid();
    xpc_dictionary_set_data(message, "audit_token", &fake, sizeof(fake));
    xpc_dictionary_set_string(message, "operation", "storage-lifecycle-root-challenge");
    xpc_dictionary_set_data(message, "request", "{}", 2);
    xpc_connection_send_message(client, message); xpc_release(message);
    CHECK(!dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 5*NSEC_PER_SEC)));
    // Fixture process exits immediately; callbacks retain process-lifetime memory.
}
static ce_lifecycle_root *transport_fixture(int64_t greeting_timeout) {
    ce_lifecycle_root *r = calloc(1, sizeof(*r)); CHECK(r);
    pthread_mutex_init(&r->lock, NULL);
    r->queue = dispatch_queue_create("lifecycle.reject", DISPATCH_QUEUE_SERIAL);
    r->ready = dispatch_semaphore_create(0); r->closed = dispatch_semaphore_create(0); r->ended = dispatch_semaphore_create(0);
    r->pending = dispatch_group_create(); r->greeting_deadline = dispatch_time(DISPATCH_TIME_NOW, greeting_timeout);
    r->connection = xpc_connection_create(NULL, r->queue);
    xpc_connection_set_event_handler(r->connection, ^(xpc_object_t message) { received(r, message); });
    xpc_connection_resume(r->connection);
    return r;
}
static void transport_rejection(const char *operation, size_t length) {
    ce_lifecycle_root *r = transport_fixture(5*NSEC_PER_SEC);
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(message, "operation", operation);
    unsigned char *bytes = calloc(1, length); CHECK(bytes);
    xpc_dictionary_set_data(message, "request", bytes, length);
    CHECK(ce_lifecycle_reply(r, bytes, CE_BOUND+1) == -1);
    received(r, message); // Negative policy only; no native sender is fabricated.
    ce_lifecycle_wait_closed(r); // Cancellation is signalled without a Go operation.
    size_t count = 99; CHECK(ce_lifecycle_next(r, bytes, length, &count) == -1); CHECK(count == 99);
    CHECK(ce_lifecycle_reply(r, bytes, length) == -1);
    free(bytes); xpc_release(message); ce_lifecycle_destroy(r);
}
struct next_wait {
    dispatch_semaphore_t done;
    int result;
    size_t length;
    unsigned char bytes[4];
};
static void start_next(ce_lifecycle_root *r, struct next_wait *wait) {
    wait->done = dispatch_semaphore_create(0); wait->length = 99;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        wait->result = ce_lifecycle_next(r, wait->bytes, sizeof(wait->bytes), &wait->length);
        dispatch_semaphore_signal(wait->done);
    });
}
static void finish_next(struct next_wait *wait, int result, size_t length) {
    CHECK(!dispatch_semaphore_wait(wait->done, dispatch_time(DISPATCH_TIME_NOW, 5*NSEC_PER_SEC)));
    CHECK(wait->result == result); CHECK(wait->length == length);
    dispatch_release(wait->done);
}
static void still_waiting(struct next_wait *wait) {
    // Exceeds the removed 100 ms poll: no idle result may escape to the caller.
    CHECK(dispatch_semaphore_wait(wait->done, dispatch_time(DISPATCH_TIME_NOW, 250*NSEC_PER_MSEC)));
}
static void check_greeting_state(ce_lifecycle_root *r, int failed, int acknowledged) {
    pthread_mutex_lock(&r->lock);
    CHECK(r->failed == failed && r->acknowledged == acknowledged);
    pthread_mutex_unlock(&r->lock);
}
static void transport_waiting(void) {
    // Exercise the real C waiting/acknowledgement seam, not ROOT authentication.
    // Only the production callback authenticates native greeting replies.
    ce_lifecycle_root *r = transport_fixture(5*NSEC_PER_SEC);
    struct next_wait wait;
    start_next(r, &wait); still_waiting(&wait);
    acknowledge_greeting(r); finish_next(&wait, 0, 99);
    check_greeting_state(r, 0, 1);

    // An acknowledged owner remains idle even beyond its greeting deadline.
    pthread_mutex_lock(&r->lock);
    r->greeting_deadline = dispatch_time(DISPATCH_TIME_NOW, -1);
    pthread_mutex_unlock(&r->lock);
    start_next(r, &wait); still_waiting(&wait);
    // Inject only the post-authentication bounded queue state, never a fake
    // native sender/proof. Request publication must wake the indefinite wait.
    pthread_mutex_lock(&r->lock);
    r->reply = xpc_dictionary_create(NULL, NULL, 0);
    memcpy(r->payload, "{}", 2); r->length = 2;
    pthread_mutex_unlock(&r->lock);
    dispatch_semaphore_signal(r->ready);
    finish_next(&wait, 1, 2); CHECK(!memcmp(wait.bytes, "{}", 2));

    start_next(r, &wait); still_waiting(&wait);
    ce_lifecycle_cancel(r); finish_next(&wait, -1, 99);
    // Cancellation remains terminal even after its semaphore signal is consumed.
    start_next(r, &wait); finish_next(&wait, -1, 99);
    ce_lifecycle_destroy(r);

    r = transport_fixture(250*NSEC_PER_MSEC);
    start_next(r, &wait); finish_next(&wait, -1, 99);
    check_greeting_state(r, 1, 0);
    ce_lifecycle_destroy(r);

    // A late authenticated ack cannot win merely because no reader has yet
    // observed expiry. It must fail before publishing acknowledged.
    r = transport_fixture(-1);
    acknowledge_greeting(r); check_greeting_state(r, 1, 0);
    start_next(r, &wait); finish_next(&wait, -1, 99);
    ce_lifecycle_destroy(r);

    r = transport_fixture(5*NSEC_PER_SEC);
    start_next(r, &wait); still_waiting(&wait);
    ce_lifecycle_cancel(r); finish_next(&wait, -1, 99);
    acknowledge_greeting(r); check_greeting_state(r, 1, 0);
    ce_lifecycle_destroy(r);
}
static void parent_child(const char *binary) {
    int pair[2]; CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    ce_lifecycle_processes observed = {0};
    CHECK(ce_lifecycle_parent(pair[0], &observed) != 0); // Socket's peer is self, not parent.
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        close(pair[0]); CHECK(dup2(pair[1], 3) == 3);
        if (pair[1] != 3) close(pair[1]);
        execl(binary, binary, "child", NULL); _exit(127);
    }
    close(pair[1]); int status; CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0); close(pair[0]);
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "child")) {
        ce_lifecycle_processes observed = {0}; CHECK(ce_lifecycle_parent(3, &observed) == 0);
        CHECK(observed.daemon_unique && observed.child_unique && observed.daemon_unique != observed.child_unique);
        audit_token_t parent, child;
        memcpy(&parent, observed.daemon_audit, 32); memcpy(&child, observed.child_audit, 32);
        CHECK(parent.val[5] == (uint32_t)getppid() && child.val[5] == (uint32_t)getpid());
        CHECK(memcmp(&parent, &child, sizeof(parent)));
        CHECK(fcntl(3, F_GETFD) & FD_CLOEXEC); return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "sender")) { native_sender(); return 0; }
    if (argc == 2 && !strcmp(argv[1], "waiting")) { transport_waiting(); return 0; }
    policy(); parent_child(argv[0]);
    transport_rejection("root-challenge", 2);
    transport_rejection("storage-lifecycle-root-challenge", CE_BOUND+1);
    return 0;
}

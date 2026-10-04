// SPDX-License-Identifier: GPL-2.0-only
// Linux-only raw /dev/fuse regression probe. No libfuse or /proc PID lookup.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/aio_abi.h>
#include <linux/capability.h>
#include <linux/fuse.h>
#include <linux/fanotify.h>
#include <linux/landlock.h>
#include <signal.h>
#include <linux/io_uring.h>
#include <poll.h>
#include <sched.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <endian.h>
#include <unistd.h>

/* musl's sys/fanotify.h duplicates older UAPI structs. Use pinned linux UAPI
 * above and libc's functions (which split the 64-bit mark mask on compat32). */
extern int fanotify_init(unsigned int flags, unsigned int event_f_flags);
extern int fanotify_mark(int fd, unsigned int flags, uint64_t mask, int dirfd, const char *path);

#ifndef FUSE_DEV_IOC_REQUEST_CRED
#error Build with the patched kernel UAPI headers (see kernel-patches/README.md)
#endif
_Static_assert(FUSE_REQUEST_CRED_VERSION == 3, "v3 required, no fallback");
_Static_assert(sizeof(struct fuse_request_cred) == 64, "stable compat ABI v3");
_Static_assert(offsetof(struct fuse_request_cred, cap_effective) == 48, "capability ABI offset");
_Static_assert(offsetof(struct fuse_request_cred, cap_valid) == 56, "valid-mask ABI offset");
_Static_assert(offsetof(struct fuse_request_cred, semantics) == 40, "semantic ABI offset");
_Static_assert(FUSE_REQUEST_META_MASK == 1023, "frozen source semantic vocabulary");
_Static_assert(FUSE_DEV_IOC_REQUEST_CRED == 0xc040e5f0, "source ioctl number");
_Static_assert(FUSE_STORAGE_VERSION == 1, "storage session ABI v1");
_Static_assert(FUSE_STORAGE_ATTR_MASK == 255, "frozen storage attribute vocabulary");
_Static_assert(sizeof(struct fuse_storage_attr) == 80, "storage compat ABI size");
_Static_assert(offsetof(struct fuse_storage_attr, semantics) == 16, "storage semantics offset");
_Static_assert(offsetof(struct fuse_storage_attr, size) == 40, "storage size offset");
_Static_assert(offsetof(struct fuse_storage_attr, atime_nsec) == 64, "storage nanoseconds offset");
_Static_assert(FUSE_DEV_IOC_STORAGE_SESSION == 0xe5f2, "mint ioctl number");
_Static_assert(FUSE_STORAGE_IOC_APPLY_ATTR == 0x4050e5f3, "apply ioctl number");
_Static_assert(CAP_LAST_CAP < 63, "64-bit capability ABI");
#define EXPECT_CAP_VALID ((UINT64_C(1) << (CAP_LAST_CAP + 1)) - 1)
#define CAP_BIT(cap) (UINT64_C(1) << (cap))

enum expectation_kind { ORDINARY, SYNCER, ROOT_NO_CAPS, NONROOT_WITH_CAPS };
struct credential_expectation {
    uint32_t fsuid, fsgid, count, group_base;
    uint64_t cap_effective;
    uint32_t kind, padding;
};

static int device = -1, clone_device = -1;
static char mountpoint[] = "/tmp/cengine-fuse-cred-XXXXXX";
static int mounted;
static pid_t child = -1;
static unsigned int group_count = 65536;
static uint64_t reject_init_flag;
#define KILL_CASES 16
static char backing_dir[4096];
static int backing[KILL_CASES], metadata_pin[KILL_CASES];
static int storage_session = -1;
static int kill_mode;

static void cleanup(void)
{
    /* Disconnect before killing a child that may be waiting on a FUSE reply. */
    if (storage_session >= 0)
        close(storage_session);
    if (clone_device >= 0)
        close(clone_device);
    if (device >= 0)
        close(device);
    if (mounted)
        umount2(mountpoint, MNT_DETACH);
    if (child > 0) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
    }
    rmdir(mountpoint);
    if (kill_mode) {
        for (int n = 0; n < KILL_CASES; n++) {
            char path[4200];
            if (backing[n] >= 0)
                close(backing[n]);
            if (metadata_pin[n] >= 0)
                close(metadata_pin[n]);
            snprintf(path, sizeof(path), "%s/%d", backing_dir, n);
            unlink(path);
            snprintf(path, sizeof(path), "%s/%d.pending", backing_dir, n);
            unlink(path);
        }
        rmdir(backing_dir);
    }
}

static void check(int condition, const char *what)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s (errno=%d: %s)\n", what, errno, strerror(errno));
        exit(1);
    }
}

static void ready(int fd)
{
    struct pollfd p = { .fd = fd, .events = POLLIN };
    check(poll(&p, 1, 15000) == 1 && (p.revents & POLLIN), "15s request/child timeout");
}

/* One raw SQE128 submission, no liburing. SINGLE_MMAP is required by this
 * Linux 6.18 probe. All errors/timeouts fail rather than skip the gate.
 */
static int uring_one(int file_fd, unsigned char opcode, unsigned char flags,
                     unsigned int command, void *buffer, unsigned int length)
{
    struct io_uring_params p = { .flags = IORING_SETUP_SQE128 };
    int ring = syscall(SYS_io_uring_setup, 2, &p);
    check(ring >= 0, "io_uring_setup (required, not a skipped test)");
    check(p.features & IORING_FEAT_SINGLE_MMAP, "io_uring SINGLE_MMAP");
    size_t sq_size = p.sq_off.array + p.sq_entries * sizeof(uint32_t);
    size_t cq_size = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    size_t ring_size = sq_size > cq_size ? sq_size : cq_size;
    unsigned char *mapping = mmap(NULL, ring_size, PROT_READ | PROT_WRITE,
                                  MAP_SHARED, ring, IORING_OFF_SQ_RING);
    check(mapping != MAP_FAILED, "map io_uring rings");
    struct io_uring_sqe *sqe = mmap(NULL, p.sq_entries * 128, PROT_READ | PROT_WRITE,
                                   MAP_SHARED, ring, IORING_OFF_SQES);
    check(sqe != MAP_FAILED, "map SQE128 entries");
    memset(sqe, 0, 128);
    sqe->opcode = opcode;
    sqe->flags = flags;
    sqe->fd = file_fd;
    sqe->cmd_op = command;
    sqe->addr = (uintptr_t)buffer;
    sqe->len = length;
    sqe->user_data = 1;
    /* REGISTER deliberately has qid=0 and no buffers. The credential-mode
     * exclusion must run BEFORE buffer validation/ring or queue creation.
     * Unpatched, enabled FUSE gets past the gate and returns EINVAL, not
     * EOPNOTSUPP, after creating the ring/queue.
     */
    *(uint32_t *)(mapping + p.sq_off.array) = 0;
    __atomic_store_n((uint32_t *)(mapping + p.sq_off.tail), 1, __ATOMIC_RELEASE);
    check(syscall(SYS_io_uring_enter, ring, 1, 0, 0, NULL, 0) == 1, "submit io_uring SQE");
    ready(ring);
    check(syscall(SYS_io_uring_enter, ring, 0, 1, IORING_ENTER_GETEVENTS, NULL, 0) == 0,
          "complete io_uring SQE");
    uint32_t head = *(uint32_t *)(mapping + p.cq_off.head);
    check(__atomic_load_n((uint32_t *)(mapping + p.cq_off.tail), __ATOMIC_ACQUIRE) != head,
          "io_uring completion available");
    struct io_uring_cqe *cqes = (void *)(mapping + p.cq_off.cqes);
    struct io_uring_cqe cqe = cqes[head & *(uint32_t *)(mapping + p.cq_off.ring_mask)];
    check(cqe.user_data == 1, "io_uring completion identity");
    __atomic_store_n((uint32_t *)(mapping + p.cq_off.head), head + 1, __ATOMIC_RELEASE);
    munmap(sqe, p.sq_entries * 128);
    munmap(mapping, ring_size);
    close(ring);
    return cqe.res;
}

static void reject_uring_registration(void)
{
    char enabled = 0;
    int fd = open("/sys/module/fuse/parameters/enable_uring", O_RDONLY | O_CLOEXEC);
    check(fd >= 0 && read(fd, &enabled, 1) == 1 && (enabled == 'Y' || enabled == '1'),
          "FUSE io_uring must be globally enabled to test the real bypass");
    close(fd);
    check(uring_one(device, IORING_OP_URING_CMD, 0,
                    FUSE_IO_URING_CMD_REGISTER, NULL, 0) == -EOPNOTSUPP,
          "reject REGISTER after successful INIT without FUSE_OVER_IO_URING");
}

static uint64_t effective_caps(void)
{
    struct __user_cap_header_struct h = { .version = _LINUX_CAPABILITY_VERSION_3 };
    struct __user_cap_data_struct caps[2] = {{0}};
    check(syscall(SYS_capget, &h, caps) == 0, "CAPGET current effective capabilities");
    return caps[0].effective | ((uint64_t)caps[1].effective << 32);
}

static void install_caps(uint64_t permitted, uint64_t effective)
{
    struct __user_cap_header_struct h = { .version = _LINUX_CAPABILITY_VERSION_3 };
    struct __user_cap_data_struct caps[2] = {
        { .permitted = permitted, .effective = effective },
        { .permitted = permitted >> 32, .effective = effective >> 32 }
    };
    check(syscall(SYS_capset, &h, caps) == 0, "CAPSET exact effective/permitted masks");
    check(effective_caps() == effective, "CAPGET verifies CAPSET result");
}

static struct credential_expectation capture_expected(unsigned int count,
                                                       unsigned int base,
                                                       enum expectation_kind kind)
{
    struct credential_expectation e = {
        .fsuid = (uint32_t)setfsuid((uid_t)-1),
        .fsgid = (uint32_t)setfsgid((gid_t)-1),
        .count = count, .group_base = base,
        .cap_effective = effective_caps(), .kind = kind
    };
    return e;
}

static void publish_expected(int fd, const struct credential_expectation *e)
{
    check(write(fd, e, sizeof(*e)) == (ssize_t)sizeof(*e), "publish pre-allocation CAPGET expectation");
}

static struct credential_expectation receive_expected(int fd)
{
    struct credential_expectation e;
    ready(fd);
    check(read(fd, &e, sizeof(e)) == (ssize_t)sizeof(e), "read originating-task credential expectation");
    return e;
}

static struct fuse_request_cred query(uint64_t unique)
{
    struct fuse_request_cred q = {
        .version = FUSE_REQUEST_CRED_VERSION, .unique = unique
    };
    check(ioctl(device, FUSE_DEV_IOC_REQUEST_CRED, &q) == 0, "size query");
    return q;
}

static void absent(uint64_t unique)
{
    struct fuse_request_cred q = {
        .version = FUSE_REQUEST_CRED_VERSION, .unique = unique,
        .cap_effective = UINT64_MAX, .cap_valid = UINT64_MAX
    };
    check(ioctl(device, FUSE_DEV_IOC_REQUEST_CRED, &q) == 0, "NONE overwrites capability sentinels");
    check(q.state == FUSE_REQUEST_CRED_NONE && q.fsuid == UINT32_MAX &&
          q.fsgid == UINT32_MAX && q.group_count == 0 &&
          q.cap_effective == 0 && q.cap_valid == 0 && q.semantics == 0, "explicit no identity, not root or valid empty caps");
}

static void expect_error(int fd, struct fuse_request_cred *q, int error)
{
    errno = 0;
    check(ioctl(fd, FUSE_DEV_IOC_REQUEST_CRED, q) == -1 && errno == error,
          "expected ioctl failure");
}

static void snapshot(uint64_t unique, const struct credential_expectation *e)
{
    struct fuse_request_cred q = query(unique);
    unsigned int count = e->count;
    uint32_t *groups = calloc(count ? count : 1, sizeof(*groups));
    check(groups != NULL, "allocate groups");
    check(q.state == FUSE_REQUEST_CRED_PRESENT && q.fsuid == e->fsuid &&
          q.fsgid == e->fsgid && q.group_count == count, "original fs IDs and full count");
    check(q.cap_valid == EXPECT_CAP_VALID && q.cap_effective == e->cap_effective,
          "same-snapshot exact effective capabilities and valid mask");
    q.groups = (uintptr_t)groups;
    if (count) {
        q.group_count = count - 1;
        expect_error(device, &q, ENOSPC);
        check(q.group_count == count, "short-buffer required count");
    }
    q.group_count = count;
    check(ioctl(device, FUSE_DEV_IOC_REQUEST_CRED, &q) == 0, "full group query");
    check(q.cap_valid == EXPECT_CAP_VALID && q.cap_effective == e->cap_effective,
          "full query preserves exact capability snapshot");
    for (unsigned int n = 0; n < count; n++)
        check(groups[n] == e->group_base + n, "all original supplementary groups, no truncation");
    q.groups = 0;
    q.group_count = 0;
    expect_error(clone_device, &q, ENOENT);
    q.unique = UINT64_MAX;
    expect_error(device, &q, ENOENT);
    q.unique = unique;
    q.version++;
    expect_error(device, &q, EINVAL);
    q.version = 1;
    expect_error(device, &q, EINVAL);
    q.version = 2;
    expect_error(device, &q, EINVAL);
    q.version = FUSE_REQUEST_CRED_VERSION;
    errno = 0;
    check(ioctl(device, _IOC(_IOC_READ | _IOC_WRITE, FUSE_DEV_IOC_MAGIC, 240, 48), &q) == -1 &&
          errno == ENOTTY, "old 48-byte ioctl rejected, never fallback");
    q.group_count = 65537;
    expect_error(device, &q, EINVAL);
    free(groups);
}

static void reply(uint64_t unique, int error, const void *payload, size_t size)
{
    unsigned char buf[8192];
    struct fuse_out_header h = { .len = sizeof(h) + size, .unique = unique, .error = error };
    check(h.len <= sizeof(buf), "reply size");
    memcpy(buf, &h, sizeof(h));
    if (size)
        memcpy(buf + sizeof(h), payload, size);
    check(write(device, buf, h.len) == (ssize_t)h.len, "write FUSE reply");
}

static struct fuse_attr attr(uint64_t ino)
{
    struct fuse_attr a = {
        .ino = ino, .size = ino == 1 ? 0 : 4096, .nlink = 1,
        .mode = ino == 1 ? S_IFDIR | 0777 : S_IFREG | 0666,
        .blksize = 4096
    };
    return a;
}

static void set_original(gid_t *groups)
{
    setfsuid(0);
    for (unsigned int n = 0; n < group_count; n++)
        groups[n] = 10000 + n;
    check(setgroups(group_count, groups) == 0, "set original groups");
    setfsgid(2345);
    uint64_t before_fsuid = effective_caps();
    setfsuid(1234);
    uint64_t fs_caps = CAP_BIT(CAP_CHOWN) | CAP_BIT(CAP_MKNOD) |
        CAP_BIT(CAP_DAC_OVERRIDE) | CAP_BIT(CAP_DAC_READ_SEARCH) | CAP_BIT(CAP_FOWNER) |
        CAP_BIT(CAP_FSETID) | CAP_BIT(CAP_MAC_OVERRIDE) | CAP_BIT(CAP_LINUX_IMMUTABLE);
    check(effective_caps() == (before_fsuid & ~fs_caps), "CAPGET accounts for Linux setfsuid effects");
    check(setfsuid((uid_t)-1) == 1234 && setfsgid((gid_t)-1) == 2345, "set original fs IDs");
}

static void capability_case(int fd, int expected_fd, enum expectation_kind kind)
{
    aio_context_t context = 0;
    void *buffer = NULL;
    struct iocb cb = {0}, *list[] = { &cb };
    struct io_event event;
    check(posix_memalign(&buffer, 4096, 4096) == 0, "capability-case AIO buffer");
    check(syscall(SYS_io_setup, 2, &context) == 0, "capability-case io_setup");
    setfsuid(0);
    if (kind == ROOT_NO_CAPS) {
        check(setgroups(0, NULL) == 0, "root capdrop empty groups");
        setfsgid(0);
        install_caps(0, 0);
        check(getuid() == 0 && geteuid() == 0, "root retains UID 0 with zero caps");
    } else {
        gid_t group = 9993;
        check(prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == 0, "retain permitted caps across UID change");
        check(setgroups(1, &group) == 0 && setresgid(9992, 9992, 9992) == 0 &&
              setresuid(9991, 9991, 9991) == 0, "actual nonroot UID/GID transition");
        install_caps(CAP_BIT(CAP_DAC_OVERRIDE), CAP_BIT(CAP_DAC_OVERRIDE));
        check(getuid() == 9991 && geteuid() == 9991, "nonroot effective-capability task");
    }
    struct credential_expectation e = capture_expected(kind == ROOT_NO_CAPS ? 0 : 1,
                                                       kind == ROOT_NO_CAPS ? 0 : 9993, kind);
    cb.aio_lio_opcode = IOCB_CMD_PREAD;
    cb.aio_fildes = fd;
    cb.aio_buf = (uintptr_t)buffer;
    cb.aio_nbytes = 4096;
    check(syscall(SYS_io_submit, context, 1, list) == 1, "queue capability-case actual READ");
    if (kind == NONROOT_WITH_CAPS)
        install_caps(CAP_BIT(CAP_DAC_OVERRIDE), 0); // snapshot must retain the previous bit
    publish_expected(expected_fd, &e);
    check(syscall(SYS_io_getevents, context, 1, 1, &event, NULL) == 1 && event.res == 4096,
          "complete capability-case READ");
    check(syscall(SYS_io_destroy, context) == 0, "capability-case io_destroy");
    free(buffer);
}

static void origin(int changed_fd)
{
    gid_t *groups = calloc(group_count ? group_count : 1, sizeof(*groups));
    char path[256];
    void *buffer = NULL;
    aio_context_t context = 0;
    struct io_event event;
    struct iocb cb = {0}, *list[] = { &cb };
    gid_t new_group = 9876;
    int fd;

    /* Do not let the originating task keep the server connection alive. */
    close(device);
    close(clone_device);
    device = clone_device = -1;
    mounted = 0;
    check(groups != NULL, "child groups");
    set_original(groups);
    snprintf(path, sizeof(path), "%s/file", mountpoint);
    fd = open(path, O_RDWR | O_DIRECT);
    if (reject_init_flag) {
        check(fd == -1 && errno == ECONNREFUSED, "server selecting forbidden INIT flag fails closed");
        _exit(0);
    }
    check(fd >= 0, "open direct file");
    check(posix_memalign(&buffer, 4096, 4096) == 0, "aligned AIO buffer");
    check(syscall(SYS_io_setup, 2, &context) == 0, "io_setup");
    memset(buffer, 0, 4096);
    for (int writing = 0; writing < 2; writing++) {
        set_original(groups);
        struct credential_expectation expected = capture_expected(group_count, 10000, ORDINARY);
        cb.aio_lio_opcode = writing ? IOCB_CMD_PWRITE : IOCB_CMD_PREAD;
        cb.aio_fildes = fd;
        cb.aio_buf = (uintptr_t)buffer;
        cb.aio_nbytes = 4096;
        check(syscall(SYS_io_submit, context, 1, list) == 1, "queue actual asynchronous FUSE_READ/WRITE");

        /* Change THIS originating task while READ/WRITE remains pending. */
        setfsuid(0);
        check(setgroups(1, &new_group) == 0, "change originating groups");
        setfsgid(8765);
        setfsuid(7654);
        check(setfsuid((uid_t)-1) == 7654 && setfsgid((gid_t)-1) == 8765,
              "verify changed originating fs IDs");
        check(getgroups(1, groups) == 1 && groups[0] == new_group, "verify changed groups");
        publish_expected(changed_fd, &expected);
        check(syscall(SYS_io_getevents, context, 1, 1, &event, NULL) == 1 &&
              event.res == 4096, "complete pending read/write");
    }
    check(syscall(SYS_io_destroy, context) == 0, "io_destroy");

    /* IOSQE_ASYNC forces the io-wq worker path, which this prototype excludes.
     * The daemon must reject its missing identity, not borrow a header UID.
     */
    check(uring_one(fd, IORING_OP_READ, IOSQE_ASYNC, 0, buffer, 4096) == -EACCES,
          "native client io_uring worker is rejected by credential gate");

    /* A different task fsyncs the inherited handle: FSYNC itself is that
     * task's operation, not the original writer's. No writeback cache is on.
     */
    pid_t syncer = fork();
    check(syncer >= 0, "fork different fsync task");
    if (!syncer) {
        gid_t group = 8883;
        setfsuid(0);
        check(setgroups(1, &group) == 0, "fsync task groups");
        setfsgid(8882);
        setfsuid(8881);
        struct credential_expectation expected = capture_expected(1, 8883, SYNCER);
        publish_expected(changed_fd, &expected);
        check(fsync(fd) == 0, "different task fsync");
        _exit(0);
    }
    int sync_status;
    check(waitpid(syncer, &sync_status, 0) == syncer && WIFEXITED(sync_status) &&
          WEXITSTATUS(sync_status) == 0, "fsync task succeeded");
    for (int kind = ROOT_NO_CAPS; kind <= NONROOT_WITH_CAPS; kind++) {
        pid_t task = fork();
        check(task >= 0, "fork isolated capability case");
        if (!task) {
            capability_case(fd, changed_fd, kind);
            _exit(0);
        }
        int cap_status;
        check(waitpid(task, &cap_status, 0) == task && WIFEXITED(cap_status) &&
              WEXITSTATUS(cap_status) == 0, "capability-case task succeeded");
    }
    close(fd);
    free(groups);
    free(buffer);
    close(changed_fd);
    _exit(0);
}


/* Standalone semantic gate, deliberately separate from the AIO credential gate.
 * Files must live on disposable init-userns, non-idmapped ext4 storage.
 */
static int case_exec(int n) { return n % 4 == 0 || n % 4 == 2; }
static int case_fsetid(int n) { return n % 4 == 2; }
static int case_member(int n) { return n % 4 != 3; }

static void become_owner(int n)
{
    check(prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == 0, "keep permitted test caps");
    check(setgroups(0, NULL) == 0 &&
          setresgid(case_member(n) ? 2345 : 2346, case_member(n) ? 2345 : 2346,
                    case_member(n) ? 2345 : 2346) == 0 &&
          setresuid(1234, 1234, 1234) == 0, "install actual nonroot owner");
    uint64_t caps = case_fsetid(n) ? CAP_BIT(CAP_FSETID) : 0;
    install_caps(caps, caps);
}

/* Return a real current-caller open description, never a root setup FD. */
static int owner_open(int n, const struct fuse_request_cred *q)
{
    check(q->state == FUSE_REQUEST_CRED_PRESENT && q->fsuid == 1234 &&
          q->fsgid == (case_member(n) ? 2345U : 2346U) && !q->group_count &&
          q->cap_effective == (case_fsetid(n) ? CAP_BIT(CAP_FSETID) : 0) &&
          q->cap_valid == EXPECT_CAP_VALID && !q->semantics, "actual OPEN caller");
    int pair[2];
    check(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, pair) == 0, "open grant channel");
    pid_t worker = fork();
    check(worker >= 0, "fork checked backing opener");
    if (!worker) {
        close(pair[0]); close(device); close(clone_device); close(storage_session);
        become_owner(n);
        char path[64]; snprintf(path, sizeof(path), "/proc/self/fd/%d", metadata_pin[n]);
        int fd = open(path, O_RDWR | O_CLOEXEC);
        check(fd >= 0, "backing OPEN checked as actual source owner");
        char payload = 0, control[CMSG_SPACE(sizeof(int))] = {0};
        struct iovec iov = { .iov_base = &payload, .iov_len = 1 };
        struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
            .msg_control = control, .msg_controllen = sizeof(control) };
        struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
        c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS; c->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c), &fd, sizeof(fd));
        check(sendmsg(pair[1], &msg, 0) == 1, "transfer exact checked open grant");
        _exit(0);
    }
    close(pair[1]); ready(pair[0]);
    char payload, control[CMSG_SPACE(sizeof(int))] = {0};
    struct iovec iov = { .iov_base = &payload, .iov_len = 1 };
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control) };
    check(recvmsg(pair[0], &msg, MSG_CMSG_CLOEXEC) == 1 && !(msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)), "receive checked grant");
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    check(c && c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
          c->cmsg_len == CMSG_LEN(sizeof(int)), "exactly one checked FD");
    int fd, status; memcpy(&fd, CMSG_DATA(c), sizeof(fd)); close(pair[0]);
    check(waitpid(worker, &status, 0) == worker && WIFEXITED(status) && !WEXITSTATUS(status), "opener passed");
    struct stat pin, opened;
    check(fstat(fd, &opened) == 0 && fstat(metadata_pin[n], &pin) == 0 &&
          opened.st_dev == pin.st_dev && opened.st_ino == pin.st_ino, "grant pins the exact lookup inode");
    return fd;
}

static void kill_client(void)
{
    close(storage_session);
    storage_session = -1;
    for (int n = 0; n < KILL_CASES; n++) {
        close(backing[n]);
        close(metadata_pin[n]);
    }
    close(device);
    close(clone_device);
    device = clone_device = -1;
    mounted = 0;
    for (int n = 0; n < KILL_CASES; n++) {
        pid_t task = fork();
        check(task >= 0, "fork isolated owner semantic case");
        if (!task) {
            char path[256];
            struct stat before, after;
            unsigned char cap[64];
            become_owner(n);
            snprintf(path, sizeof(path), "%s/%d", mountpoint, n);
            int fd;
            if (n >= 12) {
                /* No stat/open first: force negative LOOKUP -> raced CREATE. */
                memset(&before, 0, sizeof(before));
                before.st_uid = 1234; before.st_gid = 2345; before.st_size = 4096;
                fd = open(path, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
                check(fd >= 0, "actual raced O_CREAT|O_TRUNC succeeds");
                goto after_action;
            }
            fd = open(path, O_RDWR | O_CLOEXEC);
            check(fd >= 0 && fstat(fd, &before) == 0, "open seeded managed file");
            check((before.st_mode & (S_ISUID | S_ISGID)) == (S_ISUID | S_ISGID),
                  "seed set-ID bits visible");
            check(getxattr(path, "security.capability", cap, sizeof(cap)) > 0,
                  "seed capability visible to owner");
            errno = 0;
            check(removexattr(path, "security.capability") == -1 && errno == EPERM,
                  "explicit removexattr denied without CAP_SETFCAP");
            check(getxattr(path, "security.capability", cap, sizeof(cap)) > 0,
                  "denied explicit removal leaves capability intact");
            usleep(20000);
            if (n / 4 == 0)
                check(chown(path, (uid_t)-1, (gid_t)-1) == 0, "actual chown(-1,-1)");
            else if (n / 4 == 1)
                check(pwrite(fd, "x", 1, 0) == 1, "actual owner write");
            else
                check(ftruncate(fd, 123) == 0, "actual owner truncate");
after_action:
            check(fstat(fd, &after) == 0, "stat after semantic action");
            check(getxattr(path, "security.capability", cap, sizeof(cap)) == -1 && errno == ENODATA,
                  "implicit action clears capability without CAP_SETFCAP");
            int keep_suid = n / 4 != 0 && case_fsetid(n);
            int keep_sgid = (!case_exec(n) && case_member(n)) ||
                            (n / 4 != 0 && case_fsetid(n));
            check(!!(after.st_mode & S_ISUID) == keep_suid &&
                  !!(after.st_mode & S_ISGID) == keep_sgid,
                  "SGID executable/nonexecutable, group and CAP_FSETID semantics");
            check(after.st_uid == before.st_uid && after.st_gid == before.st_gid,
                  "no-op chown/write/truncate never changes owner");
            check(after.st_ctim.tv_sec > before.st_ctim.tv_sec ||
                  (after.st_ctim.tv_sec == before.st_ctim.tv_sec &&
                   after.st_ctim.tv_nsec > before.st_ctim.tv_nsec), "ctime advances");
            check(after.st_size == (n >= 12 ? 0 : n / 4 == 2 ? 123 : before.st_size),
                  "no dummy truncate or data-size mutation");
            close(fd);
            _exit(0);
        }
        int status;
        check(waitpid(task, &status, 0) == task && WIFEXITED(status) && !WEXITSTATUS(status),
              "owner semantic case passed");
    }
    _exit(0);
}

static struct fuse_attr backing_attr(uint64_t node)
{
    if (node == 1)
        return attr(1);
    check(node >= 2 && node < KILL_CASES + 2, "bounded backing inode");
    struct stat st;
    check(fstat(backing[node - 2], &st) == 0, "exact backing inode stat");
    struct fuse_attr a = {
        .ino = node, .size = st.st_size, .blocks = st.st_blocks,
        .atime = st.st_atim.tv_sec, .atimensec = st.st_atim.tv_nsec,
        .mtime = st.st_mtim.tv_sec, .mtimensec = st.st_mtim.tv_nsec,
        .ctime = st.st_ctim.tv_sec, .ctimensec = st.st_ctim.tv_nsec,
        .mode = st.st_mode, .nlink = st.st_nlink, .uid = st.st_uid,
        .gid = st.st_gid, .blksize = st.st_blksize
    };
    return a;
}

static void apply_error(int fd, struct fuse_storage_attr *a, int error)
{
    errno = 0;
    check(ioctl(fd, FUSE_STORAGE_IOC_APPLY_ATTR, a) == -1 && errno == error,
          "metadata apply rejects invalid token/attributes/authority");
}

/* This is the trusted wire adapter, NOT a second credential proof. Its inputs
 * are the source kernel's live-unique ABI3 query and the exact SETATTR message.
 */
static struct fuse_storage_attr storage_attr(const struct fuse_setattr_in *in,
                                            uint64_t semantics, int pin)
{
    const uint32_t supported = FATTR_MODE | FATTR_UID | FATTR_GID | FATTR_SIZE |
        FATTR_ATIME | FATTR_MTIME | FATTR_ATIME_NOW | FATTR_MTIME_NOW | FATTR_CTIME |
        FATTR_FH | FATTR_LOCKOWNER;
    check(!(in->valid & ~supported) && (semantics & FUSE_REQUEST_META_VALID) &&
          !(semantics & ~FUSE_REQUEST_META_MASK), "sanitize authenticated typed metadata");
    check(!!(in->valid & FATTR_CTIME) == !!(semantics & FUSE_REQUEST_META_CTIME),
          "wire ctime agrees with kernel provenance");
    struct fuse_storage_attr a = { .version = FUSE_STORAGE_VERSION, .fd = pin,
                                  .semantics = semantics };
    if (in->valid & FATTR_MODE) a.valid |= FUSE_STORAGE_ATTR_MODE, a.mode = in->mode & 07777;
    if (in->valid & FATTR_UID) a.valid |= FUSE_STORAGE_ATTR_UID, a.uid = in->uid;
    if (in->valid & FATTR_GID) a.valid |= FUSE_STORAGE_ATTR_GID, a.gid = in->gid;
    if (in->valid & FATTR_SIZE) a.valid |= FUSE_STORAGE_ATTR_SIZE, a.size = in->size;
    if (in->valid & FATTR_ATIME) {
        a.valid |= FUSE_STORAGE_ATTR_ATIME;
        a.atime = (int64_t)in->atime; a.atime_nsec = in->atimensec;
    }
    if (in->valid & FATTR_MTIME) {
        a.valid |= FUSE_STORAGE_ATTR_MTIME;
        a.mtime = (int64_t)in->mtime; a.mtime_nsec = in->mtimensec;
    }
    if (in->valid & FATTR_ATIME_NOW) a.valid |= FUSE_STORAGE_ATTR_ATIME_NOW;
    if (in->valid & FATTR_MTIME_NOW) a.valid |= FUSE_STORAGE_ATTR_MTIME_NOW;
    return a;
}

/* These calls deliberately supply trusted source intent to test the local
 * enforcement boundary. They are not substitutes for an ABI3 source query. */
static struct fuse_storage_attr size_attr(int fd, int retained)
{
    return (struct fuse_storage_attr){ .version = FUSE_STORAGE_VERSION,
        .fd = fd, .valid = FUSE_STORAGE_ATTR_SIZE, .size = 17,
        .semantics = FUSE_REQUEST_META_VALID | (retained ? FUSE_REQUEST_META_FILE : 0) };
}
static void child_ok(pid_t task, const char *what)
{
    int status;
    check(waitpid(task, &status, 0) == task && WIFEXITED(status) && !WEXITSTATUS(status), what);
}
static void unchanged(int fd, const struct stat *before)
{
    struct stat after;
    check(fstat(fd, &after) == 0 && before->st_mode == after.st_mode &&
          before->st_size == after.st_size && before->st_uid == after.st_uid &&
          before->st_gid == after.st_gid && before->st_ctim.tv_sec == after.st_ctim.tv_sec &&
          before->st_ctim.tv_nsec == after.st_ctim.tv_nsec, "denial leaves exact inode metadata unchanged");
}
static void authority_probe(int dirfd)
{
    pid_t task = fork();
    check(task >= 0, "fork retained-vs-path authority worker");
    if (!task) {
        alarm(20);
        become_owner(0);
        int fd = openat(dirfd, "authority", O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
        int pin = openat(dirfd, "authority", O_PATH | O_CLOEXEC);
        int rd = openat(dirfd, "authority", O_RDONLY | O_CLOEXEC);
        check(fd >= 0 && pin >= 0 && rd >= 0 && write(fd, "contents", 8) == 8 &&
              fchmod(fd, 04500) == 0, "owner opens exact writable FD before removing DAC write bits");
        struct stat before;
        check(fstat(fd, &before) == 0 && (before.st_mode & S_ISUID), "seed retained setuid file");
        struct fuse_storage_attr a = { .version = FUSE_STORAGE_VERSION, .fd = pin,
            .semantics = FUSE_REQUEST_META_VALID | FUSE_REQUEST_META_FORCE | FUSE_REQUEST_META_KILL_SUID };
        apply_error(storage_session, &a, EACCES); unchanged(fd, &before);
        a.semantics |= FUSE_REQUEST_META_FILE; /* An asserted FILE on O_PATH is not write authority. */
        apply_error(storage_session, &a, EACCES); unchanged(fd, &before);
        a.fd = rd; apply_error(storage_session, &a, EACCES); unchanged(fd, &before);
        a.fd = fd;
        check(ioctl(storage_session, FUSE_STORAGE_IOC_APPLY_ATTR, &a) == 0 &&
              fstat(fd, &before) == 0 && !(before.st_mode & S_ISUID),
              "exact retained writable FILE authorizes FORCE despite chmod after open");
        a = size_attr(pin, 0); apply_error(storage_session, &a, EACCES); unchanged(fd, &before);
        a = size_attr(fd, 0); apply_error(storage_session, &a, EACCES); unchanged(fd, &before);
        a = size_attr(fd, 1);
        check(ioctl(storage_session, FUSE_STORAGE_IOC_APPLY_ATTR, &a) == 0 &&
              fstat(fd, &before) == 0 && before.st_size == 17, "retained ftruncate authority survives mode change");
        close(rd); close(pin); close(fd);
        _exit(0);
    }
    child_ok(task, "retained-vs-path current-identity authorization");
    check(unlinkat(dirfd, "authority", 0) == 0, "remove authority fixture");
    puts("PASS: FORCE O_PATH/read-only denial; exact retained writable FILE survives chmod; pathname does not");
}
static void landlock_probe(int dirfd)
{
    int abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0 && (errno == ENOSYS || errno == EOPNOTSUPP)) {
        printf("SKIP: Landlock unavailable/disabled (errno=%d); truncate LSM gate NOT tested\n", errno);
        return;
    }
    check(abi >= 0, "query Landlock ABI (unexpected errors are failures)");
    if (abi < 3) { puts("SKIP: Landlock ABI < 3 lacks TRUNCATE; truncate LSM gate NOT tested"); return; }
    pid_t task = fork();
    check(task >= 0, "fork Landlock worker");
    if (!task) {
        alarm(20);
        become_owner(0);
        int before = openat(dirfd, "landlock", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        check(before >= 0 && write(before, "contents", 8) == 8, "open unrestricted retained file");
        struct landlock_ruleset_attr rules = { .handled_access_fs = LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE };
        int rulesfd = syscall(SYS_landlock_create_ruleset, &rules, sizeof(rules), 0);
        struct landlock_path_beneath_attr rule = { .parent_fd = dirfd, .allowed_access = LANDLOCK_ACCESS_FS_WRITE_FILE };
        check(rulesfd >= 0 && syscall(SYS_landlock_add_rule, rulesfd, LANDLOCK_RULE_PATH_BENEATH, &rule, 0) == 0 &&
              prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 &&
              syscall(SYS_landlock_restrict_self, rulesfd, 0) == 0, "Landlock allows WRITE but denies TRUNCATE");
        close(rulesfd);
        int fd = openat(dirfd, "landlock", O_WRONLY | O_CLOEXEC);
        int pin = openat(dirfd, "landlock", O_PATH | O_CLOEXEC);
        check(fd >= 0 && pin >= 0 && pwrite(fd, "x", 1, 0) == 1, "restricted-open FD really permits WRITE");
        struct stat st;
        check(fstat(fd, &st) == 0 && ftruncate(fd, 17) == -1 && errno == EACCES,
              "ordinary ftruncate denied on WRITE-allowed TRUNCATE-denied retained FD");
        struct fuse_storage_attr a = size_attr(fd, 1);
        apply_error(storage_session, &a, EACCES); unchanged(fd, &st);
        a = size_attr(pin, 0); apply_error(storage_session, &a, EACCES); unchanged(fd, &st);
        a = size_attr(before, 1);
        check(ioctl(storage_session, FUSE_STORAGE_IOC_APPLY_ATTR, &a) == 0,
              "pre-sandbox retained file keeps its open-time Landlock truncate permission");
        close(pin); close(fd); close(before);
        _exit(0);
    }
    child_ok(task, "Landlock file and path hooks, without revoking previously opened FD");
    check(unlinkat(dirfd, "landlock", 0) == 0, "remove Landlock fixture");
    puts("PASS: Landlock WRITE without TRUNCATE rejects retained FD and O_PATH; open-time authorization preserved");
}
static void lease_probe(int dirfd)
{
    int seed = openat(dirfd, "lease", O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    check(seed >= 0 && write(seed, "contents", 8) == 8 && fchown(seed, 1234, 2345) == 0, "seed own lease fixture");
    close(seed); /* Any retained writable descriptor would prevent a read lease. */
    int fd = openat(dirfd, "lease", O_RDONLY | O_CLOEXEC);
    int pin = openat(dirfd, "lease", O_PATH | O_CLOEXEC);
    check(fd >= 0 && pin >= 0, "lease and O_PATH descriptors");
    sigset_t set, old;
    sigemptyset(&set); sigaddset(&set, SIGIO);
    check(sigprocmask(SIG_BLOCK, &set, &old) == 0 && fcntl(fd, F_SETOWN, getpid()) == 0, "synchronous lease break notification");
    int result = fcntl(fd, F_SETLEASE, F_RDLCK);
    if (result < 0 && (errno == EINVAL || errno == ENOSYS || errno == EOPNOTSUPP)) {
        printf("SKIP: file leases unavailable (CONFIG_FILE_LOCKING/filesystem, errno=%d); lease gate NOT tested\n", errno);
    } else {
        check(result == 0, "establish actual ext4 read lease (EPERM is not a skip)");
        pid_t task = fork(); check(task >= 0, "fork lease-blocked worker");
        if (!task) {
            alarm(20); close(fd); become_owner(0);
            struct fuse_storage_attr a = size_attr(pin, 0);
            check(ioctl(storage_session, FUSE_STORAGE_IOC_APPLY_ATTR, &a) == 0, "O_PATH truncate completes after lease release");
            _exit(0);
        }
        struct timespec timeout = { .tv_sec = 5 };
        check(sigtimedwait(&set, NULL, &timeout) == SIGIO, "O_PATH truncate requests a real lease break before mutation");
        struct stat st; int status;
        check(fstat(fd, &st) == 0 && st.st_size == 8 && waitpid(task, &status, WNOHANG) == 0,
              "lease blocks truncate, unchanged size until holder releases");
        check(fcntl(fd, F_SETLEASE, F_UNLCK) == 0, "release read lease");
        child_ok(task, "lease-blocked truncate completed");
        check(fstat(fd, &st) == 0 && st.st_size == 17, "size changes only after lease release");
        puts("PASS: O_PATH truncate requests O_WRONLY lease break before mutation");
    }
    check(sigprocmask(SIG_SETMASK, &old, NULL) == 0, "restore signal mask");
    close(fd); close(pin); check(unlinkat(dirfd, "lease", 0) == 0, "remove lease fixture");
}
static void fanotify_probe(int dirfd)
{
    int fan = fanotify_init(FAN_CLOEXEC | FAN_NONBLOCK | FAN_CLASS_PRE_CONTENT, O_RDONLY | O_CLOEXEC);
    if (fan < 0 && (errno == ENOSYS || errno == EOPNOTSUPP)) {
        printf("SKIP: fanotify pre-content permissions unavailable (errno=%d); permission watcher NOT tested\n", errno);
        return;
    }
    check(fan >= 0, "fanotify pre-content group (EPERM is not a skip)");
    int fd = openat(dirfd, "fanotify", O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    int pin = openat(dirfd, "fanotify", O_PATH | O_CLOEXEC);
    check(fd >= 0 && pin >= 0 && write(fd, "contents", 8) == 8 && fchown(fd, 1234, 2345) == 0, "seed own fanotify fixture");
    int mark = fanotify_mark(fan, FAN_MARK_ADD, FAN_PRE_ACCESS, dirfd, "fanotify");
    if (mark < 0 && errno == EINVAL) {
        /* CONFIG_FANOTIFY_ACCESS_PERMISSIONS=n excludes all permission masks.
         * Require the old OPEN_PERM mask to be absent too, not just this hook. */
        check(fanotify_mark(fan, FAN_MARK_ADD, FAN_OPEN_PERM, dirfd, "fanotify") == -1 && errno == EINVAL,
              "permission masks unavailable, not an unexplained PRE_ACCESS failure");
        puts("SKIP: CONFIG_FANOTIFY_ACCESS_PERMISSIONS unavailable; watcher NOT tested");
    } else if (mark < 0 && errno == EOPNOTSUPP) {
        puts("SKIP: filesystem/kernel lacks FAN_PRE_ACCESS HSM permission hooks; watcher NOT tested");
    } else {
        check(mark == 0, "install actual pre-content mark");
        for (int retained = 0; retained <= 1; retained++) {
            struct stat st; check(fstat(fd, &st) == 0, "snapshot before watcher denial");
            pid_t task = fork(); check(task >= 0, "fork watched truncate worker");
            if (!task) {
                alarm(20); close(fan); become_owner(0);
                struct fuse_storage_attr a = size_attr(retained ? fd : pin, retained);
                apply_error(storage_session, &a, EPERM);
                _exit(0);
            }
            ready(fan);
            union { uint64_t align; char bytes[4096]; } event;
            ssize_t length = read(fan, event.bytes, sizeof(event.bytes));
            struct fanotify_event_metadata *m = (void *)event.bytes;
            check(length >= (ssize_t)sizeof(*m) && m->vers == FANOTIFY_METADATA_VERSION &&
                  m->event_len == (uint32_t)length && (m->mask & FAN_PRE_ACCESS) &&
                  m->pid == task && m->fd >= 0, "actual truncate permission event identifies worker");
            /* A chmod needs inode_lock. If ioctl holds it while waiting for us,
             * this must time out rather than pretending the watcher passed. */
            pid_t reenter = fork(); check(reenter >= 0, "fork permission watcher lock reentry");
            if (!reenter) { alarm(5); close(fan); become_owner(0); check(fchmod(fd, st.st_mode & 07777) == 0, "watcher can take inode lock"); _exit(0); }
            child_ok(reenter, "fsnotify permission hook is outside inode lock");
            struct fanotify_response response = { .fd = m->fd, .response = FAN_DENY };
            check(write(fan, &response, sizeof(response)) == sizeof(response), "deny truncate from permission watcher");
            close(m->fd); child_ok(task, "fanotify denial reaches apply caller");
            struct stat after; check(fstat(fd, &after) == 0 && after.st_size == st.st_size, "denied truncate preserves size");
        }
        puts("PASS: fanotify denies path and retained SIZE; watcher reenters inode lock without deadlock");
    }
    close(fan); close(fd); close(pin); check(unlinkat(dirfd, "fanotify", 0) == 0, "remove fanotify fixture");
}

/* No mounted FUSE, no source unique, no captured kernel cred exists here.
 * This independently exercises the storage-VM half of the API, not transport.
 */
static void session_probe(void)
{
    int mint_device = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    check(mint_device >= 0, "unmounted device for independent session mint");
    storage_session = ioctl(mint_device, FUSE_DEV_IOC_STORAGE_SESSION, 0);
    check(storage_session >= 0 && (fcntl(storage_session, F_GETFD) & FD_CLOEXEC),
          "privileged mint returns CLOEXEC anonymous session before mount");
    struct fuse_storage_attr a = { .version = FUSE_STORAGE_VERSION,
        .fd = metadata_pin[0], .valid = FUSE_STORAGE_ATTR_MODE, .mode = 0600,
        .semantics = FUSE_REQUEST_META_VALID };
    apply_error(mint_device, &a, ENOTTY);
    errno = 0;
    check(ioctl(mint_device, _IOC(_IOC_WRITE, FUSE_DEV_IOC_MAGIC, 241, 24), &a) == -1 &&
          errno == ENOTTY, "removed same-kernel command241 rejected");
    a.flags = 1; apply_error(storage_session, &a, EINVAL); a.flags = 0;
    a.fd = -1; apply_error(storage_session, &a, EBADF); a.fd = metadata_pin[0];
    a.semantics |= FUSE_REQUEST_META_FORCE;
    apply_error(storage_session, &a, EINVAL);
    a.semantics = FUSE_REQUEST_META_VALID;
    a.valid |= 1U << 31; apply_error(storage_session, &a, EINVAL);
    a.valid = FUSE_STORAGE_ATTR_MODE;
    a.semantics |= 1ULL << 63; apply_error(storage_session, &a, EINVAL);
    a.semantics = FUSE_REQUEST_META_VALID;

    char dir[4200], linkpath[4200], fifo[4200], ro[4200], rofile[4300];
    snprintf(dir, sizeof(dir), "%s/directory", backing_dir);
    snprintf(linkpath, sizeof(linkpath), "%s/symlink", backing_dir);
    snprintf(fifo, sizeof(fifo), "%s/fifo", backing_dir);
    snprintf(ro, sizeof(ro), "%s/readonly", backing_dir);
    check(mkdir(dir, 0700) == 0 && chown(dir, 1234, 2345) == 0 &&
          symlink("0", linkpath) == 0 && lchown(linkpath, 1234, 2345) == 0 &&
          mkfifo(fifo, 0600) == 0 && mkdir(ro, 0700) == 0, "seed inode-kind and RO fixtures");
    int d = open(dir, O_PATH | O_DIRECTORY | O_CLOEXEC);
    int l = open(linkpath, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    int f = open(fifo, O_PATH | O_CLOEXEC);
    check(d >= 0 && l >= 0 && f >= 0, "exact directory/symlink/FIFO pins");
    check(mount(backing_dir, ro, NULL, MS_BIND, NULL) == 0 &&
          mount(NULL, ro, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) == 0,
          "read-only bind of the exact backing filesystem");
    snprintf(rofile, sizeof(rofile), "%s/0", ro);
    int r = open(rofile, O_PATH | O_CLOEXEC);
    check(r >= 0, "O_PATH pin on read-only bind");
    int otherfs = open("/dev/null", O_PATH | O_CLOEXEC);
    check(otherfs >= 0, "unsupported filesystem pin");
    pid_t task = fork();
    check(task >= 0, "fork identity-installed session worker");
    if (!task) {
        become_owner(0); /* no effective CAP_SYS_ADMIN; inherited token remains valid */
        errno = 0;
        check(ioctl(mint_device, FUSE_DEV_IOC_STORAGE_SESSION, 0) == -1 && errno == EPERM,
              "unprivileged caller cannot mint even with privileged-open /dev/fuse FD");
        close(mint_device);
        a.fd = r; apply_error(storage_session, &a, EROFS);
        a.fd = f; apply_error(storage_session, &a, EOPNOTSUPP);
        a.fd = otherfs; apply_error(storage_session, &a, EOPNOTSUPP);
        a.fd = l;
        struct stat link_before;
        check(fstat(l, &link_before) == 0, "snapshot exact symlink");
        apply_error(storage_session, &a, EOPNOTSUPP); unchanged(l, &link_before);
        a.mode = link_before.st_mode & 07777; /* unchanged MODE is still chmod intent */
        apply_error(storage_session, &a, EOPNOTSUPP); unchanged(l, &link_before);
        a.mode = 0600;
        a.fd = d; a.mode = 0700; /* later owned-file probes need directory search */
        check(ioctl(storage_session, FUSE_STORAGE_IOC_APPLY_ATTR, &a) == 0,
              "O_PATH directory chmod uses CURRENT nonroot credentials");
        a.fd = l; a.valid = FUSE_STORAGE_ATTR_UID; a.mode = 0; a.uid = 1234;
        a.semantics |= FUSE_REQUEST_META_CTIME;
        check(ioctl(storage_session, FUSE_STORAGE_IOC_APPLY_ATTR, &a) == 0,
              "O_PATH NOFOLLOW exact symlink chown allowed by notify_change");
        a.fd = metadata_pin[0]; a.uid = 0;
        apply_error(storage_session, &a, EPERM); /* token does not borrow minting root. */
        a.uid = 0; a.valid = FUSE_STORAGE_ATTR_SIZE; a.size = 4096;
        check(ioctl(storage_session, FUSE_STORAGE_IOC_APPLY_ATTR, &a) == 0,
              "writable O_PATH file passes CURRENT write permission");
        close(storage_session);
        apply_error(storage_session, &a, EBADF); /* possession, not UID, grants access to API. */
        _exit(0);
    }
    int status;
    check(waitpid(task, &status, 0) == task && WIFEXITED(status) && !WEXITSTATUS(status),
          "storage-only identity/RO/type/token checks passed");
    /* Different actual unprivileged identity cannot chmod an unowned inode,
     * even when deliberately handed a session capability by this trusted test.
     */
    task = fork();
    check(task >= 0, "fork nonowner session negative");
    if (!task) {
        check(setgroups(0, NULL) == 0 && setresgid(9999, 9999, 9999) == 0 &&
              setresuid(9999, 9999, 9999) == 0, "actual nonowner identity");
        install_caps(0, 0);
        apply_error(storage_session, &a, EPERM);
        a.valid = FUSE_STORAGE_ATTR_SIZE; a.mode = 0; a.size = 4096;
        apply_error(storage_session, &a, EACCES);
        struct stat before;
        check(fstat(a.fd, &before) == 0, "snapshot unowned FORCE target");
        a.valid = 0; a.size = 0;
        a.semantics = FUSE_REQUEST_META_VALID | FUSE_REQUEST_META_FORCE |
                      FUSE_REQUEST_META_KILL_SUID | FUSE_REQUEST_META_KILL_SGID | FUSE_REQUEST_META_KILL_PRIV;
        apply_error(storage_session, &a, EACCES); unchanged(a.fd, &before);
        a.semantics |= FUSE_REQUEST_META_FILE;
        apply_error(storage_session, &a, EACCES); unchanged(a.fd, &before);
        _exit(0);
    }
    check(waitpid(task, &status, 0) == task && WIFEXITED(status) && !WEXITSTATUS(status),
          "session does not authorize unowned chmod/truncate");
    authority_probe(d);
    landlock_probe(d);
    lease_probe(d);
    fanotify_probe(d);
    close(mint_device); close(d); close(l); close(f); close(r); close(otherfs);
    check(umount(ro) == 0 && rmdir(ro) == 0 && unlink(fifo) == 0 &&
          unlink(linkpath) == 0 && rmdir(dir) == 0, "remove session-only fixtures");
    puts("PASS: independent storage session mint; current nonroot authorization; exact O_PATH directory/symlink; RO and malformed/type negatives");
}

static int killpriv_probe(const char *directory, int storage_only)
{
    char options[256];
    unsigned seen = 0;
    unsigned int applied[KILL_CASES] = {0}, raced[KILL_CASES] = {0};
    union { uint64_t align; unsigned char bytes[131072]; } request;
    kill_mode = 1;
    for (int n = 0; n < KILL_CASES; n++)
        backing[n] = metadata_pin[n] = -1;
    check(snprintf(backing_dir, sizeof(backing_dir), "%s/cengine-killpriv-XXXXXX", directory)
          < (int)sizeof(backing_dir), "backing directory length");
    check(geteuid() == 0 && unshare(CLONE_NEWNS) == 0, "private root mount namespace");
    check(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0, "private propagation");
    check(mkdtemp(backing_dir) != NULL && chmod(backing_dir, 0777) == 0, "create disposable backing directory");
    atexit(cleanup);
    struct statfs fs;
    check(statfs(backing_dir, &fs) == 0 && fs.f_type == EXT4_SUPER_MAGIC, "backing must be ext4");
    for (int n = 0; n < KILL_CASES; n++) {
        char path[4200], data[4096] = {0};
        snprintf(path, sizeof(path), "%s/%d", backing_dir, n);
        backing[n] = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
        check(backing[n] >= 0 && write(backing[n], data, sizeof(data)) == sizeof(data), "seed file data");
        check(fchown(backing[n], 1234, 2345) == 0 &&
              fchmod(backing[n], 06600 | (case_exec(n) ? 0010 : 0)) == 0, "seed owner and set-ID bits");
        struct vfs_cap_data cap = { .magic_etc = htole32(VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE) };
        cap.data[0].permitted = htole32(1U << CAP_NET_BIND_SERVICE);
        check(fsetxattr(backing[n], "security.capability", &cap, XATTR_CAPS_SZ_2, 0) == 0,
              "seed actual security.capability (requires CAP_SETFCAP)");
        metadata_pin[n] = open(path, O_PATH | O_NOFOLLOW | O_CLOEXEC);
        check(metadata_pin[n] >= 0, "pin exact metadata inode with O_PATH");
        if (n >= 12) {
            char pending[4300]; snprintf(pending, sizeof(pending), "%s.pending", path);
            check(rename(path, pending) == 0, "hide future collision before source LOOKUP");
        }
    }
    session_probe();
    if (storage_only) return 0;
    check(mkdtemp(mountpoint) && chmod(mountpoint, 0777) == 0, "private FUSE mountpoint");
    device = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    check(device >= 0, "open semantic FUSE device");
    snprintf(options, sizeof(options), "fd=%d,rootmode=40777,user_id=0,group_id=0,allow_other,"
             "request_cred,default_permissions,managed_close_to_open", device);
    check(mount("killpriv-probe", mountpoint, "fuse", MS_NOSUID | MS_NODEV, options) == 0,
          "mount managed semantic profile");
    mounted = 1;
    clone_device = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    uint32_t source = device;
    check(clone_device >= 0 && ioctl(clone_device, FUSE_DEV_IOC_CLONE, &source) == 0,
          "clone for source-query device isolation");
    child = fork();
    check(child >= 0, "fork semantic client");
    if (!child)
        kill_client();
    while (seen != (1U << KILL_CASES) - 1) {
        ready(device);
        ssize_t length = read(device, request.bytes, sizeof(request.bytes));
        check(length >= (ssize_t)sizeof(struct fuse_in_header), "semantic request framing");
        struct fuse_in_header *h = (void *)request.bytes;
        check(h->len == (uint32_t)length, "semantic request length");
        int n = h->nodeid >= 2 && h->nodeid < KILL_CASES + 2 ? (int)h->nodeid - 2 : -1;
        switch (h->opcode) {
        case FUSE_INIT: {
            const struct fuse_init_in *in = (void *)(h + 1);
            check(!(in->flags & (FUSE_HANDLE_KILLPRIV | FUSE_HANDLE_KILLPRIV_V2 | FUSE_ATOMIC_O_TRUNC)),
                  "no alternative killpriv delegation offered");
            struct fuse_init_out out = { .major = FUSE_KERNEL_VERSION, .minor = FUSE_KERNEL_MINOR_VERSION,
                .flags = FUSE_BIG_WRITES, .max_write = 4096, .max_background = 16 };
            reply(h->unique, 0, &out, sizeof(out));
            break;
        }
        case FUSE_LOOKUP: {
            char *end;
            long index = strtol((char *)(h + 1), &end, 10);
            check(!*end && index >= 0 && index < KILL_CASES, "known fixture filename");
            if (index >= 12 && !raced[index]) {
                char path[4200], pending[4300]; struct stat st;
                snprintf(path, sizeof(path), "%s/%ld", backing_dir, index);
                snprintf(pending, sizeof(pending), "%s.pending", path);
                check(lstat(path, &st) == -1 && errno == ENOENT, "actual negative backing LOOKUP");
                check(rename(pending, path) == 0, "publish concurrent inode before CREATE");
                raced[index] = 1;
                reply(h->unique, -ENOENT, NULL, 0);
                break;
            }
            if (index >= 12) check(raced[index] >= 2, "fresh LOOKUP follows CREATE EEXIST");
            struct fuse_entry_out out = { .nodeid = index + 2, .generation = 1,
                .attr = backing_attr(index + 2) };
            reply(h->unique, 0, &out, sizeof(out));
            break;
        }
        case FUSE_GETATTR: {
            struct fuse_attr_out out = { .attr = backing_attr(h->nodeid) };
            reply(h->unique, 0, &out, sizeof(out));
            break;
        }
        case FUSE_CREATE: {
            const struct fuse_create_in *in = (void *)(h + 1);
            char *end; long index = strtol((const char *)(in + 1), &end, 10);
            check(!*end && index >= 12 && index < KILL_CASES && raced[index] == 1 &&
                  !(in->flags & O_EXCL) && (in->flags & O_TRUNC), "nonexclusive truncating CREATE collision");
            struct fuse_request_cred q = query(h->unique);
            check(q.state == FUSE_REQUEST_CRED_PRESENT && q.fsuid == 1234 && !q.semantics &&
                  q.cap_effective == (case_fsetid(index) ? CAP_BIT(CAP_FSETID) : 0), "CREATE caller not host authority");
            int dirfd = open(backing_dir, O_PATH | O_DIRECTORY | O_CLOEXEC);
            check(dirfd >= 0, "pin CREATE parent");
            pid_t worker = fork(); check(worker >= 0, "fork backing-exclusive CREATE");
            if (!worker) {
                close(device); close(clone_device); close(storage_session); become_owner(index);
                int fd = openat(dirfd, (const char *)(in + 1), O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
                check(fd == -1 && errno == EEXIST, "real backing O_EXCL collision without mutation");
                _exit(0);
            }
            child_ok(worker, "exclusive CREATE worker"); close(dirfd);
            raced[index] = 2;
            reply(h->unique, -EEXIST, NULL, 0);
            break;
        }
        case FUSE_OPEN: {
            check(n >= 0, "OPEN on known inode");
            const struct fuse_open_in *in = (void *)(h + 1);
            check(!(in->flags & O_TRUNC), "non-atomic OPEN cannot truncate backing");
            struct fuse_request_cred q = query(h->unique);
            int grant = owner_open(n, &q);
            close(backing[n]); backing[n] = grant;
            if (n >= 12) { check(raced[n] == 2, "normal OPEN after collision lookup"); raced[n] = 3; }
            struct fuse_open_out out = { .fh = h->nodeid, .open_flags = FOPEN_KEEP_CACHE };
            reply(h->unique, 0, &out, sizeof(out));
            break;
        }
        case FUSE_GETXATTR: {
            check(n >= 0, "xattr on file");
            const struct fuse_getxattr_in *in = (void *)(h + 1);
            const char *name = (void *)(in + 1);
            char value[256];
            ssize_t size = fgetxattr(backing[n], name, in->size ? value : NULL,
                                    in->size ? sizeof(value) : 0);
            if (size < 0)
                reply(h->unique, -errno, NULL, 0);
            else if (in->size)
                reply(h->unique, 0, value, size);
            else {
                struct fuse_getxattr_out out = { .size = size };
                reply(h->unique, 0, &out, sizeof(out));
            }
            break;
        }
        case FUSE_SETATTR: {
            check(n >= 0, "metadata on file");
            struct fuse_request_cred q = query(h->unique);
            uint64_t bits = FUSE_REQUEST_META_VALID | FUSE_REQUEST_META_KILL_PRIV;
            if (n / 4 == 0 || !case_fsetid(n))
                bits |= FUSE_REQUEST_META_KILL_SUID;
            if ((case_exec(n) || !case_member(n)) && (n / 4 == 0 || !case_fsetid(n)))
                bits |= FUSE_REQUEST_META_KILL_SGID;
            if (n / 4 == 0 || n / 4 >= 2)
                bits |= FUSE_REQUEST_META_CTIME;
            if (n / 4 != 0)
                bits |= FUSE_REQUEST_META_FORCE;
            if (n / 4 >= 2)
                bits |= FUSE_REQUEST_META_FILE;
            if (n >= 12)
                bits |= FUSE_REQUEST_META_OPEN;
            check(q.state == FUSE_REQUEST_CRED_PRESENT && q.fsuid == 1234 &&
                  q.fsgid == (case_member(n) ? 2345U : 2346U) && !q.group_count &&
                  q.cap_effective == (case_fsetid(n) ? CAP_BIT(CAP_FSETID) : 0) &&
                  q.cap_valid == EXPECT_CAP_VALID && q.semantics == bits,
                  "exact same-caller and kernel-origin kill/force/ctime snapshot");
            struct fuse_request_cred again = { .version = FUSE_REQUEST_CRED_VERSION,
                .unique = h->unique };
            check(ioctl(device, FUSE_DEV_IOC_REQUEST_CRED, &again) == 0 &&
                  again.semantics == bits, "immutable semantic query");
            expect_error(device, &again, EINVAL); /* Output semantics must be zeroed on input. */
            again.semantics = 0;
            expect_error(clone_device, &again, ENOENT);
            const struct fuse_setattr_in *in = (void *)(h + 1);
            check(!(in->valid & (FATTR_MODE | FATTR_UID | FATTR_GID)), "no synthetic chmod/chown fields");
            if (n / 4 == 0)
                check((in->valid & FATTR_CTIME) && !(in->valid & FATTR_SIZE), "no-op chown ctime survives");
            if (q.semantics & FUSE_REQUEST_META_FILE)
                check((in->valid & FATTR_FH) && in->fh == h->nodeid, "FILE requires exact actual OPEN FH");
            if (n >= 12)
                check(raced[n] == 3 && (in->valid & FATTR_SIZE) && in->size == 0,
                      "non-created VFS open emits actual semantic truncate after collision");
            struct fuse_storage_attr a = storage_attr(in, q.semantics,
                q.semantics & FUSE_REQUEST_META_FILE ? backing[n] : metadata_pin[n]);
            apply_error(device, &a, ENOTTY); /* apply is session-only, not FUSE-connection authority. */
            if (n == 0) {
                char path[4200];
                snprintf(path, sizeof(path), "%s/0", backing_dir);
                check(unlink(path) == 0, "unlink before apply: only exact O_PATH pin survives");
            }
            pid_t worker = fork();
            check(worker >= 0, "fork isolated identity-installed metadata worker");
            if (!worker) {
                close(device); close(clone_device);
                become_owner(n);
                check(effective_caps() == q.cap_effective &&
                      (uint32_t)setfsuid((uid_t)-1) == q.fsuid &&
                      (uint32_t)setfsgid((gid_t)-1) == q.fsgid && getgroups(0, NULL) == 0,
                      "CURRENT identity exactly matches authenticated source snapshot");
                check(ioctl(storage_session, FUSE_STORAGE_IOC_APPLY_ATTR, &a) == 0,
                      "actual notify_change under CURRENT worker, no live unique or elevated repair");
                _exit(0);
            }
            int status;
            check(waitpid(worker, &status, 0) == worker && WIFEXITED(status) && !WEXITSTATUS(status),
                  "identity-installed metadata worker passed");
            applied[n]++;
            struct fuse_attr_out out = { .attr = backing_attr(h->nodeid) };
            if (in->valid & FATTR_CTIME)
                check(out.attr.ctime > in->ctime ||
                      (out.attr.ctime == in->ctime && out.attr.ctimensec >= in->ctimensec),
                      "backing notify_change preserves ctime update, not delegated timestamp merge");
            reply(h->unique, 0, &out, sizeof(out));
            struct fuse_request_cred completed = { .version = FUSE_REQUEST_CRED_VERSION,
                .unique = h->unique };
            expect_error(device, &completed, ENOENT);
            break;
        }
        case FUSE_READ: {
            check(n >= 0, "buffered read on fixture file");
            const struct fuse_read_in *in = (void *)(h + 1);
            char data[4096];
            check(in->size <= sizeof(data), "bounded buffered read");
            ssize_t size = pread(backing[n], data, in->size, in->offset);
            check(size >= 0, "read initialized backing data");
            reply(h->unique, 0, data, size);
            break;
        }
        case FUSE_WRITE: {
            check(n >= 0 && applied[n], "write follows real implicit metadata removal");
            char value[64];
            check(fgetxattr(backing[n], "security.capability", value, sizeof(value)) == -1 &&
                  errno == ENODATA, "metadata cleared capability before data write");
            const struct fuse_write_in *in = (void *)(h + 1);
            struct fuse_request_cred q = query(h->unique);
            check(q.state == FUSE_REQUEST_CRED_PRESENT && !q.semantics && q.fsuid == 1234,
                  "ordinary WRITE has no fabricated metadata provenance");
            pid_t writer = fork();
            check(writer >= 0, "fork exact-caller backing write");
            if (!writer) {
                become_owner(n);
                check(effective_caps() == q.cap_effective &&
                      pwrite(backing[n], in + 1, in->size, in->offset) == (ssize_t)in->size,
                      "ordinary backing write under captured owner");
                _exit(0);
            }
            int status;
            check(waitpid(writer, &status, 0) == writer && WIFEXITED(status) && !WEXITSTATUS(status),
                  "backing writer passed");
            struct fuse_write_out out = { .size = in->size };
            reply(h->unique, 0, &out, sizeof(out));
            break;
        }
        case FUSE_REMOVEXATTR:
            check(0, "implicit killpriv must not become REMOVEXATTR; explicit removal denied in VFS");
            break;
        case FUSE_RELEASE:
            check(n >= 0 && applied[n] == 1, "exactly one metadata action per case");
            seen |= 1U << n;
            reply(h->unique, 0, NULL, 0);
            break;
        case FUSE_FLUSH:
        case FUSE_FSYNC:
            reply(h->unique, 0, NULL, 0);
            break;
        case FUSE_FORGET:
        case FUSE_BATCH_FORGET:
            break;
        default:
            reply(h->unique, -ENOSYS, NULL, 0);
        }
    }
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
          "all standalone semantic cases passed");
    child = -1;
    printf("PASS: ABI3 no-op chown/write/truncate and negative-LOOKUP/CREATE-EEXIST/open-truncate race; exact FILE FH; CAP_SETFCAP negative; SGID exec/nonexec/group/CAP_FSETID; VFS ctime; CURRENT-worker session-FD metadata apply\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && (!strcmp(argv[1], "--killpriv") || !strcmp(argv[1], "--storage-session")))
        return killpriv_probe(argv[2], !strcmp(argv[1], "--storage-session"));
    char options[256];
    int pipefd[2], status, saw_read = 0, saw_write = 0, saw_release = 0;
    int saw_worker = 0, saw_fsync = 0, saw_bad_init = 0;
    int saw_root_caps = 0, saw_nonroot_caps = 0, saw_open = 0, saw_open_getattr = 0;
    union { uint64_t align; unsigned char bytes[131072]; } request;

    if (argc == 2) {
        char *end;
        unsigned long n = strtoul(argv[1], &end, 10);
        check(*argv[1] && !*end && n <= 65536, "group count 0..65536");
        group_count = n;
    } else {
        check(argc == 1, "usage: probe [group-count, default 65536] | --killpriv/--storage-session EXT4_DIRECTORY");
    }
    const char *reject = getenv("FUSE_CRED_REJECT_INIT");
    if (reject) {
        if (!strcmp(reject, "writeback"))
            reject_init_flag = FUSE_WRITEBACK_CACHE;
        else if (!strcmp(reject, "idmap"))
            reject_init_flag = FUSE_ALLOW_IDMAP;
        else if (!strcmp(reject, "uring"))
            reject_init_flag = FUSE_OVER_IO_URING;
        else if (!strcmp(reject, "passthrough"))
            reject_init_flag = FUSE_PASSTHROUGH;
        else if (!strcmp(reject, "killpriv"))
            reject_init_flag = FUSE_HANDLE_KILLPRIV;
        else if (!strcmp(reject, "killpriv-v2"))
            reject_init_flag = FUSE_HANDLE_KILLPRIV_V2;
        else if (!strcmp(reject, "atomic-trunc"))
            reject_init_flag = FUSE_ATOMIC_O_TRUNC;
        else
            check(0, "FUSE_CRED_REJECT_INIT: writeback/idmap/uring/passthrough/killpriv/killpriv-v2/atomic-trunc");
    }
    check(geteuid() == 0, "requires Linux init-namespace root with CAP_SYS_ADMIN/SETUID/SETGID");
    check(unshare(CLONE_NEWNS) == 0, "private mount namespace");
    check(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0, "private propagation");
    check(mkdtemp(mountpoint) != NULL && chmod(mountpoint, 0777) == 0, "private mountpoint");
    atexit(cleanup);
    device = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    check(device >= 0, "open /dev/fuse");
    const char *bad_mount = getenv("FUSE_CRED_BAD_MOUNT");
    if (bad_mount)
        check(!strcmp(bad_mount, "missing-creds") || !strcmp(bad_mount, "missing-permissions"),
              "FUSE_CRED_BAD_MOUNT: missing-creds/missing-permissions");
    snprintf(options, sizeof(options),
             "fd=%d,rootmode=40777,user_id=0,group_id=0,allow_other%s%s,managed_close_to_open", device,
             bad_mount && !strcmp(bad_mount, "missing-creds") ? "" : ",request_cred",
             bad_mount && !strcmp(bad_mount, "missing-permissions") ? "" : ",default_permissions");
    int mount_result = mount("credential-probe", mountpoint, "fuse", MS_NOSUID | MS_NODEV, options);
    if (bad_mount) {
        check(mount_result == -1 && errno == EINVAL, "managed profile dependencies enforced");
        printf("PASS: managed mount rejected %s\n", bad_mount);
        return 0;
    }
    check(mount_result == 0, "mount required native managed credential profile");
    mounted = 1;
    snprintf(options, sizeof(options),
             "fd=%d,rootmode=40777,user_id=0,group_id=0,allow_other,request_cred,default_permissions", device);
    check(mount("credential-probe", mountpoint, "fuse", MS_NOSUID | MS_NODEV, options) == -1 &&
          errno == EINVAL, "connection reuse cannot drop managed_close_to_open");
    clone_device = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    check(clone_device >= 0, "open second fuse_dev");
    uint32_t source = device;
    check(ioctl(clone_device, FUSE_DEV_IOC_CLONE, &source) == 0, "clone same connection, distinct fuse_dev");
    check(pipe(pipefd) == 0, "child handshake pipe");
    child = fork();
    check(child >= 0, "fork originating process");
    if (!child) {
        close(pipefd[0]);
        origin(pipefd[1]);
    }
    close(pipefd[1]);

    while (!saw_release && !saw_bad_init) {
        ready(device);
        ssize_t length = read(device, request.bytes, sizeof(request.bytes));
        check(length >= (ssize_t)sizeof(struct fuse_in_header), "read FUSE request");
        struct fuse_in_header *h = (void *)request.bytes;
        check(h->len == (unsigned int)length, "request framing");
        switch (h->opcode) {
        case FUSE_INIT: {
            struct fuse_init_out init = {
                .major = FUSE_KERNEL_VERSION, .minor = FUSE_KERNEL_MINOR_VERSION,
                .flags = FUSE_ASYNC_DIO | FUSE_BIG_WRITES | FUSE_INIT_EXT |
                         (uint32_t)reject_init_flag,
                .flags2 = reject_init_flag >> 32,
                .max_write = 4096, .max_background = 16
            };
            check(length >= (ssize_t)(sizeof(*h) + sizeof(struct fuse_init_in)), "full INIT offer");
            const struct fuse_init_in *offered = (void *)(h + 1);
            uint64_t flags = offered->flags | ((uint64_t)offered->flags2 << 32);
            check(!(flags & (FUSE_WRITEBACK_CACHE | FUSE_ALLOW_IDMAP |
                             FUSE_OVER_IO_URING | FUSE_PASSTHROUGH | FUSE_HANDLE_KILLPRIV |
                             FUSE_HANDLE_KILLPRIV_V2 | FUSE_ATOMIC_O_TRUNC)), "unsupported features not offered");
            absent(h->unique);
            reply(h->unique, 0, &init, sizeof(init));
            if (reject_init_flag)
                saw_bad_init = 1;
            else
                reject_uring_registration();
            break;
        }
        case FUSE_LOOKUP: {
            struct fuse_entry_out entry = { .nodeid = 2, .generation = 1, .attr = attr(2) };
            reply(h->unique, 0, &entry, sizeof(entry));
            break;
        }
        case FUSE_GETATTR: {
            if (saw_open)
                saw_open_getattr = 1;
            struct fuse_attr_out out = { .attr = attr(h->nodeid) };
            reply(h->unique, 0, &out, sizeof(out));
            break;
        }
        case FUSE_OPEN: {
            saw_open = 1;
            struct fuse_open_out out = { .fh = 1, .open_flags = FOPEN_DIRECT_IO };
            reply(h->unique, 0, &out, sizeof(out));
            break;
        }
        case FUSE_READ:
        case FUSE_WRITE: {
            char data[4096] = {0};
            check(saw_open_getattr, "managed open forced GETATTR before first I/O");
            if (h->opcode == FUSE_READ && saw_read && !saw_worker) {
                struct fuse_request_cred q = {
                    .version = FUSE_REQUEST_CRED_VERSION, .unique = h->unique
                };
                expect_error(device, &q, EOPNOTSUPP);
                reply(h->unique, -EACCES, NULL, 0);
                saw_worker = 1;
                break;
            }
            if (h->opcode == FUSE_WRITE) {
                const struct fuse_write_in *write_in = (void *)(h + 1);
                check(!(write_in->write_flags & FUSE_WRITE_CACHE), "direct write, not synthesized writeback");
            }
            struct credential_expectation expected = receive_expected(pipefd[0]);
            if (expected.kind == ROOT_NO_CAPS) {
                check(expected.fsuid == 0 && expected.fsgid == 0 && !expected.count &&
                      !expected.cap_effective, "root capdrop is exact zero, not implied privilege");
                saw_root_caps = 1;
            } else if (expected.kind == NONROOT_WITH_CAPS) {
                check(expected.fsuid == 9991 && expected.fsgid == 9992 && expected.count == 1 &&
                      expected.cap_effective == CAP_BIT(CAP_DAC_OVERRIDE), "nonroot retains exact capability bit");
                saw_nonroot_caps = 1;
            } else {
                check(expected.kind == ORDINARY && expected.fsuid == 1234 &&
                      expected.fsgid == 2345 && expected.count == group_count, "ordinary request expectation");
            }
            snapshot(h->unique, &expected);
            if (h->opcode == FUSE_WRITE) {
                struct fuse_write_out out = { .size = 4096 };
                reply(h->unique, 0, &out, sizeof(out));
                saw_write = 1;
            } else {
                reply(h->unique, 0, data, sizeof(data));
                saw_read = 1;
            }
            struct fuse_request_cred q = {
                .version = FUSE_REQUEST_CRED_VERSION, .unique = h->unique
            };
            expect_error(device, &q, ENOENT);
            break;
        }
        case FUSE_FSYNC: {
            struct credential_expectation expected = receive_expected(pipefd[0]);
            check(expected.kind == SYNCER && expected.fsuid == 8881 && expected.fsgid == 8882 &&
                  expected.count == 1 && expected.group_base == 8883, "FSYNC belongs to different syncing task");
            snapshot(h->unique, &expected);
            reply(h->unique, 0, NULL, 0);
            saw_fsync = 1;
            break;
        }
        case FUSE_RELEASE:
            absent(h->unique);
            reply(h->unique, 0, NULL, 0);
            saw_release = 1;
            break;
        case FUSE_FORGET:
        case FUSE_BATCH_FORGET: {
            struct fuse_request_cred q = {
                .version = FUSE_REQUEST_CRED_VERSION, .unique = h->unique
            };
            expect_error(device, &q, ENOENT); // no reply-bearing request exists
            break;
        }
        default:
            reply(h->unique, -ENOSYS, NULL, 0);
        }
    }
    check(reject_init_flag ? saw_bad_init : (saw_read && saw_write && saw_worker && saw_fsync &&
                                            saw_root_caps && saw_nonroot_caps && saw_open_getattr),
          "all required request gates observed");
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "originating process succeeded");
    child = -1;
    close(pipefd[0]);
    if (reject_init_flag)
        printf("PASS: forbidden INIT feature %s rejected\n", reject);
    else
        printf("PASS: ABI3 exact capabilities and %u immutable groups; managed-profile sanity; READ/WRITE/FSYNC; root-capdrop/nonroot-capability; worker/REGISTER exclusions; pending-only/device isolation/NONE\n",
               group_count);
    return 0;
}

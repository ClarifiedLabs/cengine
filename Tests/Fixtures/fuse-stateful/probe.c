// SPDX-License-Identifier: GPL-2.0-only
// Disposable Linux experiment, not a filesystem implementation or profile claim.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/fuse.h>
#include <linux/magic.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#ifndef FUSE_DEV_IOC_REQUEST_CRED
#error Use the experimental 0002 patched kernel UAPI headers; no stock-header fallback
#endif
_Static_assert(FUSE_REQUEST_CRED_VERSION == 3, "credential ABI v3 required");
_Static_assert(sizeof(struct fuse_request_cred) == 64, "credential ABI size");
_Static_assert(offsetof(struct fuse_request_cred, semantics) == 40, "ABI3 semantics offset");
_Static_assert(offsetof(struct fuse_request_cred, cap_effective) == 48 &&
               offsetof(struct fuse_request_cred, cap_valid) == 56, "credential capability offsets");
_Static_assert(FUSE_REQUEST_META_MASK == 1023 && FUSE_DEV_IOC_REQUEST_CRED == 0xc040e5f0,
               "pinned ABI3 vocabulary and ioctl; no private fallback");
_Static_assert(FUSE_STORAGE_VERSION == 1 && sizeof(struct fuse_storage_attr) == 80 &&
               FUSE_STORAGE_ATTR_MASK == 255, "storage metadata ABI");
_Static_assert(FUSE_DEV_IOC_STORAGE_SESSION == 0xe5f2 && FUSE_STORAGE_IOC_APPLY_ATTR == 0x4050e5f3,
               "pinned storage session ioctl numbers");
_Static_assert(sizeof(struct fuse_in_header) == 40 &&
               offsetof(struct fuse_in_header, total_extlen) == 36, "Linux 6.18 input header");
_Static_assert(sizeof(struct fuse_write_in) == 40 && offsetof(struct fuse_write_in, offset) == 8,
               "raw WRITE data and file-offset framing");
#define LIMIT 64
#define BUFFER (1024 * 1024)
#define TTL 3600

struct object { int fd; uint64_t ino, lookups, opens; };
struct handle { int fd, flags; uint64_t node; int checked; };
struct evidence {
    uint64_t opens, releases, checked, nofh_unlinked, buffered, writeback, fsyncs;
    uint64_t getattr_errors, fsync_errors, failed_releases;
    uint64_t write_errors, getxattrs, setattrs, open_truncates;
};
enum command { SNAPSHOT = 1, REWRITE, ARM_GETATTR, ARM_FSYNC, ARM_WRITE,
               CHECK_BACKING, FINISH };
struct message {
    uint32_t command, byte;
    uint64_t size;
    char name[32];
    struct evidence evidence;
    struct stat stat;
};
static struct object objects[LIMIT];
static struct handle handles[LIMIT];
static struct evidence evidence;
static uint64_t next_node = 2, next_handle = 1, expected_caps;
static uint64_t failing_handle, failure_node, retained_failure_handle;
static int inject_getattr, inject_fsync, inject_write;
static int device = -1, backing = -1, channel = -1, storage_session = -1, mounted;
static pid_t child = -1;
static char work[4096], mountpoint[4096], backingpath[4096], client_mountpoint[4096];
static long page_size;
static int finishing;

static void check(int yes, const char *what)
{
    if (!yes) {
        fprintf(stderr, "FAIL: %s (errno=%d %s)\n", what, errno, strerror(errno));
        exit(1);
    }
}
static void timeout_handler(int sig)
{
    (void)sig;
    static const char text[] = "FAIL: 90s process deadline\n";
    (void)write(STDERR_FILENO, text, sizeof(text) - 1);
    _exit(124); // private namespace dies with the processes; parent has its own deadline
}
static void cleanup(void)
{
    if (device >= 0) close(device);
    if (storage_session >= 0) close(storage_session);
    if (channel >= 0) close(channel);
    if (child > 0) {
        kill(child, SIGKILL);
        for (int n = 0; n < 100; n++) {
            if (waitpid(child, NULL, WNOHANG) == child) { child = -1; break; }
            usleep(10000);
        }
    }
    if (mounted) umount2(mountpoint, MNT_DETACH);
    if (backing >= 0) {
        int directory_fd = dup(backing);
        DIR *dir = directory_fd >= 0 ? fdopendir(directory_fd) : NULL;
        if (!dir && directory_fd >= 0) close(directory_fd);
        if (dir) {
            struct dirent *entry;
            while ((entry = readdir(dir)))
                if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
                    unlinkat(backing, entry->d_name, 0);
            closedir(dir);
        }
    }
    for (int n = 0; n < LIMIT; n++) {
        if (handles[n].fd >= 0) close(handles[n].fd);
        if (objects[n].fd >= 0) close(objects[n].fd);
    }
    if (backing >= 0) close(backing);
    if (*mountpoint) rmdir(mountpoint);
    if (*backingpath) rmdir(backingpath);
    if (*work) rmdir(work);
}
static void wait_readable(int fd)
{
    struct pollfd p = { .fd = fd, .events = POLLIN };
    check(poll(&p, 1, 10000) == 1 && (p.revents & POLLIN), "10s control deadline");
}
static void send_message(const struct message *m)
{
    check(send(channel, m, sizeof(*m), MSG_NOSIGNAL) == sizeof(*m), "control send");
}
static struct message receive_message(void)
{
    struct message m;
    wait_readable(channel);
    check(recv(channel, &m, sizeof(m), 0) == sizeof(m), "control receive");
    return m;
}
static struct message control(enum command cmd, const char *name, size_t size, int byte)
{
    struct message m = { .command = cmd, .size = size, .byte = byte };
    if (name) check(snprintf(m.name, sizeof(m.name), "%s", name) < (int)sizeof(m.name), "control name");
    send_message(&m);
    m = receive_message();
    check(m.command == (uint32_t)cmd, "control response identity");
    return m;
}
static struct object *object(uint64_t node)
{
    check(node > 0 && node < next_node && objects[node].fd >= 0, "live retained node");
    return &objects[node];
}
static struct handle *handle(uint64_t fh, uint64_t node)
{
    check(fh > 0 && fh < next_handle && handles[fh].fd >= 0 && handles[fh].node == node,
          "live opened FH belongs to node");
    return &handles[fh];
}
static void maybe_forget(uint64_t node)
{
    struct object *o = object(node);
    if (node != 1 && !o->lookups && !o->opens) {
        close(o->fd);
        o->fd = -1;
    }
}
static struct fuse_attr attributes(uint64_t node)
{
    struct stat s;
    check(fstat(object(node)->fd, &s) == 0, "authoritative pinned ext4 fstat");
    check((uint64_t)s.st_ino == object(node)->ino, "backing identity never replaced");
    return (struct fuse_attr){
        .ino = s.st_ino, .size = s.st_size, .blocks = s.st_blocks,
        .atime = s.st_atim.tv_sec, .mtime = s.st_mtim.tv_sec, .ctime = s.st_ctim.tv_sec,
        .atimensec = s.st_atim.tv_nsec, .mtimensec = s.st_mtim.tv_nsec,
        .ctimensec = s.st_ctim.tv_nsec, .mode = s.st_mode, .nlink = s.st_nlink,
        .uid = s.st_uid, .gid = s.st_gid, .blksize = s.st_blksize
    };
}
static void reply(uint64_t unique, int error, const void *data, size_t length)
{
    unsigned char bytes[BUFFER + sizeof(struct fuse_out_header)];
    struct fuse_out_header h = { .len = sizeof(h) + length, .error = -error, .unique = unique };
    check(length <= BUFFER, "reply length");
    memcpy(bytes, &h, sizeof(h));
    if (length) memcpy(bytes + sizeof(h), data, length);
    check(write(device, bytes, h.len) == (ssize_t)h.len, "FUSE reply");
}
static void getattr_reply(uint64_t unique, uint64_t node)
{
    struct fuse_attr_out out = { .attr_valid = TTL, .attr = attributes(node) };
    reply(unique, 0, &out, sizeof(out));
}
static const char *name_arg(const struct fuse_in_header *h, size_t prefix)
{
    check(h->len > sizeof(*h) + prefix, "name argument present");
    const char *name = (const char *)(h + 1) + prefix;
    size_t length = h->len - sizeof(*h) - prefix;
    check(memchr(name, 0, length) && *name && !strchr(name, '/') &&
          strcmp(name, ".") && strcmp(name, ".."), "single-component backing name");
    return name;
}
static uint64_t lookup(const char *name)
{
    int fd = openat(backing, name, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 0;
    struct stat st;
    check(fstat(fd, &st) == 0 && S_ISREG(st.st_mode), "lookup real regular inode");
    for (uint64_t node = 2; node < next_node; node++) {
        if (objects[node].fd >= 0 && objects[node].ino == (uint64_t)st.st_ino) {
            close(fd);
            objects[node].lookups++;
            return node;
        }
    }
    check(next_node < LIMIT, "bounded object table");
    uint64_t node = next_node++;
    objects[node] = (struct object){ .fd = fd, .ino = st.st_ino, .lookups = 1 };
    return node;
}
static void entry_reply(uint64_t unique, uint64_t node)
{
    struct fuse_entry_out out = { .nodeid = node, .generation = 1,
        .entry_valid = TTL, .attr_valid = TTL, .attr = attributes(node) };
    reply(unique, 0, &out, sizeof(out));
}
static uint64_t credentials(const struct fuse_in_header *h)
{
    struct fuse_request_cred q = { .version = FUSE_REQUEST_CRED_VERSION, .unique = h->unique };
    check(ioctl(device, FUSE_DEV_IOC_REQUEST_CRED, &q) == 0, "required pending-request credential ioctl");
    if (q.state == FUSE_REQUEST_CRED_NONE) {
        int lifecycle = h->opcode == FUSE_INIT || h->opcode == FUSE_RELEASE ||
            h->opcode == FUSE_RELEASEDIR || h->opcode == FUSE_FLUSH || h->opcode == FUSE_DESTROY;
        int writeback = h->opcode == FUSE_WRITE &&
            (((const struct fuse_write_in *)(h + 1))->write_flags & FUSE_WRITE_CACHE);
        check((lifecycle || writeback) && q.fsuid == UINT32_MAX && q.fsgid == UINT32_MAX &&
              !q.group_count && !q.cap_effective && !q.cap_valid && !q.semantics,
              "NONE only explicit lifecycle/retained-FH writeback");
    } else {
        check(q.state == FUSE_REQUEST_CRED_PRESENT && !q.fsuid && !q.fsgid &&
              !q.group_count && q.cap_effective == expected_caps &&
              q.cap_valid == ((UINT64_C(1) << (CAP_LAST_CAP + 1)) - 1),
              "sole root driver exact credentials; no identity fallback");
        if (h->opcode == FUSE_SETATTR)
            check((q.semantics & FUSE_REQUEST_META_VALID) && !(q.semantics & ~FUSE_REQUEST_META_MASK),
                  "managed SETATTR requires known kernel metadata semantics");
        else check(!q.semantics, "nonmetadata request has no metadata intent");
    }
    return q.semantics;
}
static void backing_bytes(int fd, size_t size, unsigned char byte);
static void setattr_reply(const struct fuse_in_header *h, const struct fuse_setattr_in *in,
                          uint64_t semantics)
{
    const uint32_t supported = FATTR_MODE | FATTR_UID | FATTR_GID | FATTR_SIZE |
        FATTR_ATIME | FATTR_MTIME | FATTR_ATIME_NOW | FATTR_MTIME_NOW |
        FATTR_CTIME | FATTR_FH | FATTR_LOCKOWNER;
    check(!(in->valid & ~supported) && (semantics & FUSE_REQUEST_META_VALID),
          "supported managed SETATTR fields; never skip a valid-mask mismatch");
    check(!!(in->valid & FATTR_CTIME) == !!(semantics & FUSE_REQUEST_META_CTIME),
          "wire ctime matches captured intent");
    int fd = object(h->nodeid)->fd;
    if (semantics & FUSE_REQUEST_META_FILE) {
        check(in->valid & FATTR_FH, "FILE intent requires actual OPEN FH");
        struct handle *fh = handle(in->fh, h->nodeid);
        check(fh->checked && (!(in->valid & FATTR_SIZE) || (fh->flags & O_ACCMODE) != O_RDONLY),
              "metadata binds exact checked writable retained FH");
        fd = fh->fd;
    } else check(!(in->valid & FATTR_FH), "no invented FILE authority from a node pin");
    if (semantics & FUSE_REQUEST_META_OPEN) {
        check((semantics & FUSE_REQUEST_META_FILE) && (in->valid & FATTR_SIZE) && !in->size &&
              in->fh == next_handle - 1,
              "non-atomic OPEN truncate has exact new FILE/FH and zero SIZE");
        // The one successful O_TRUNC case must flush the old dirty mapping first.
        backing_bytes(fd, page_size, 'Y');
    }
    struct fuse_storage_attr a = { .version = FUSE_STORAGE_VERSION, .fd = fd,
                                  .semantics = semantics };
    if (in->valid & FATTR_MODE) a.valid |= FUSE_STORAGE_ATTR_MODE, a.mode = in->mode & 07777;
    if (in->valid & FATTR_UID) a.valid |= FUSE_STORAGE_ATTR_UID, a.uid = in->uid;
    if (in->valid & FATTR_GID) a.valid |= FUSE_STORAGE_ATTR_GID, a.gid = in->gid;
    if (in->valid & FATTR_SIZE) {
        check(in->size <= INT64_MAX, "nonnegative bounded signed size");
        a.valid |= FUSE_STORAGE_ATTR_SIZE; a.size = in->size;
    }
    if (in->valid & FATTR_ATIME) {
        a.valid |= FUSE_STORAGE_ATTR_ATIME; a.atime = in->atime; a.atime_nsec = in->atimensec;
    }
    if (in->valid & FATTR_MTIME) {
        a.valid |= FUSE_STORAGE_ATTR_MTIME; a.mtime = in->mtime; a.mtime_nsec = in->mtimensec;
    }
    if (in->valid & FATTR_ATIME_NOW) a.valid |= FUSE_STORAGE_ATTR_ATIME_NOW;
    if (in->valid & FATTR_MTIME_NOW) a.valid |= FUSE_STORAGE_ATTR_MTIME_NOW;
    // Single root driver with an exact validated credential tuple, not remote replay.
    // Let notify_change apply captured kill/time intent; ftruncate would recompute it.
    check(ioctl(storage_session, FUSE_STORAGE_IOC_APPLY_ATTR, &a) == 0,
          "real ext4 metadata on exact retained FD under validated sole-driver identity");
    evidence.setattrs++;
    if (semantics & FUSE_REQUEST_META_OPEN) evidence.open_truncates++;
    getattr_reply(h->unique, h->nodeid);
}
static void serve_request(void)
{
    union { uint64_t align; unsigned char bytes[BUFFER]; } buffer;
    ssize_t length = read(device, buffer.bytes, sizeof(buffer.bytes));
    check(length >= (ssize_t)sizeof(struct fuse_in_header), "FUSE request header");
    struct fuse_in_header *h = (void *)buffer.bytes;
    check(h->len == (uint32_t)length && !h->total_extlen, "FUSE request framing without unnegotiated extensions");
    void *arg = h + 1;
#define ARG(type) (check(h->len >= sizeof(*h) + sizeof(type), "FUSE argument size"), (type *)arg)
    // FORGET has no reply-bearing fuse_req and is not credential-queryable.
    // The separate fuse-credentials probe checks its ioctl ENOENT contract.
    if (h->opcode == FUSE_FORGET) {
        struct fuse_forget_in *in = ARG(struct fuse_forget_in);
        struct object *o = object(h->nodeid);
        check(o->lookups >= in->nlookup, "FORGET reference balance");
        o->lookups -= in->nlookup;
        maybe_forget(h->nodeid);
        return;
    }
    if (h->opcode == FUSE_BATCH_FORGET) {
        struct fuse_batch_forget_in *in = ARG(struct fuse_batch_forget_in);
        check(h->len == sizeof(*h) + sizeof(*in) + (uint64_t)in->count * sizeof(struct fuse_forget_one), "batch framing");
        struct fuse_forget_one *one = (void *)(in + 1);
        for (uint32_t n = 0; n < in->count; n++) {
            struct object *o = object(one[n].nodeid);
            check(o->lookups >= one[n].nlookup, "batch reference balance");
            o->lookups -= one[n].nlookup;
            maybe_forget(one[n].nodeid);
        }
        return;
    }
    if (h->opcode == FUSE_WRITE) (void)ARG(struct fuse_write_in);
    uint64_t semantics = credentials(h);
    switch (h->opcode) {
    case FUSE_INIT: {
        struct fuse_init_in *in = ARG(struct fuse_init_in);
        uint64_t offered = in->flags | ((uint64_t)in->flags2 << 32);
        check(in->major == FUSE_KERNEL_VERSION && in->minor >= 38, "required modern FUSE protocol");
        check(!(offered & (FUSE_WRITEBACK_CACHE | FUSE_ALLOW_IDMAP | FUSE_PASSTHROUGH | FUSE_OVER_IO_URING)),
              "experimental credential exclusions offered fail closed");
        check(!(offered & (FUSE_ATOMIC_O_TRUNC | FUSE_HANDLE_KILLPRIV | FUSE_HANDLE_KILLPRIV_V2)),
              "ABI3 managed metadata excludes atomic truncate and alternate killpriv");
        struct fuse_init_out out = { .major = FUSE_KERNEL_VERSION, .minor = in->minor,
            .flags = FUSE_BIG_WRITES, .max_write = 65536,
            .max_background = 16, .time_gran = 1 };
        reply(h->unique, 0, &out, sizeof(out));
        break;
    }
    case FUSE_LOOKUP: {
        check(h->nodeid == 1, "flat lookup root");
        const char *name = name_arg(h, 0);
        uint64_t node = lookup(name);
        if (node && !strcmp(name, "failure")) {
            check(!failure_node || failure_node == node, "failure pathname retains its known node");
            failure_node = node;
        }
        if (node) entry_reply(h->unique, node);
        else reply(h->unique, errno, NULL, 0);
        break;
    }
    case FUSE_GETATTR: {
        struct fuse_getattr_in *in = ARG(struct fuse_getattr_in);
        struct fuse_attr a = attributes(h->nodeid);
        if (!(in->getattr_flags & FUSE_GETATTR_FH) && !a.nlink) {
            check(object(h->nodeid)->opens && object(h->nodeid)->lookups, "unlinked node retained by real references");
            evidence.nofh_unlinked++;
        }
        if (in->getattr_flags & FUSE_GETATTR_FH) {
            struct handle *fh = handle(in->fh, h->nodeid);
            if (!fh->checked) {
                fh->checked = 1;
                evidence.checked++;
                if (inject_getattr) {
                    inject_getattr = 0;
                    failing_handle = in->fh;
                    evidence.getattr_errors++;
                    reply(h->unique, EIO, NULL, 0);
                    break;
                }
            }
        }
        getattr_reply(h->unique, h->nodeid);
        break;
    }
    case FUSE_GETXATTR: {
        struct fuse_getxattr_in *in = ARG(struct fuse_getxattr_in);
        check(in->size <= BUFFER, "bounded real backing xattr read");
        unsigned char bytes[BUFFER];
        ssize_t n = fgetxattr(object(h->nodeid)->fd, name_arg(h, sizeof(*in)), bytes, in->size);
        evidence.getxattrs++;
        struct fuse_getxattr_out out = { .size = n < 0 ? 0 : (uint32_t)n };
        if (n < 0) reply(h->unique, errno, NULL, 0);
        else if (!in->size) reply(h->unique, 0, &out, sizeof(out));
        else reply(h->unique, 0, bytes, n);
        break;
    }
    case FUSE_SETATTR:
        setattr_reply(h, ARG(struct fuse_setattr_in), semantics);
        break;
    case FUSE_OPEN:
    case FUSE_OPENDIR: {
        struct fuse_open_in *in = ARG(struct fuse_open_in);
        struct object *o = object(h->nodeid);
        check(next_handle < LIMIT, "bounded handle table");
        uint64_t fh = next_handle++;
        handles[fh] = (struct handle){ .fd = dup(o->fd), .flags = in->flags, .node = h->nodeid };
        check(handles[fh].fd >= 0, "open retained backing descriptor");
        if (h->opcode == FUSE_OPEN && h->nodeid == failure_node && !retained_failure_handle) {
            check(!inject_getattr && !inject_write && (in->flags & O_ACCMODE) == O_RDWR,
                  "record original writable OPEN of the known failure pathname");
            retained_failure_handle = fh;
        }
        if (inject_write) {
            check(h->opcode == FUSE_OPEN && h->nodeid == failure_node &&
                  retained_failure_handle && fh != retained_failure_handle && !failing_handle,
                  "checked-flush failure opens a distinct new FH on the retained failure inode");
            failing_handle = fh;
        }
        check(!(in->flags & O_TRUNC), "non-atomic profile strips O_TRUNC from OPEN");
        o->opens++;
        evidence.opens++;
        struct fuse_open_out out = { .fh = fh, .open_flags = FOPEN_KEEP_CACHE };
        reply(h->unique, 0, &out, sizeof(out));
        break;
    }
    case FUSE_READ: {
        struct fuse_read_in *in = ARG(struct fuse_read_in);
        struct handle *fh = handle(in->fh, h->nodeid);
        check(fh->checked && in->size <= BUFFER, "buffered READ after checked GETATTR");
        unsigned char bytes[BUFFER];
        ssize_t n = pread(fh->fd, bytes, in->size, in->offset);
        reply(h->unique, n < 0 ? errno : 0, bytes, n < 0 ? 0 : (size_t)n);
        break;
    }
    case FUSE_WRITE: {
        struct fuse_write_in *in = ARG(struct fuse_write_in);
        struct handle *fh = handle(in->fh, h->nodeid);
        check(fh->checked && (fh->flags & O_ACCMODE) != O_RDONLY &&
              h->len == sizeof(*h) + sizeof(*in) + in->size, "WRITE valid retained writable FH");
        if (in->write_flags & FUSE_WRITE_CACHE) evidence.writeback++;
        else evidence.buffered++;
        if (inject_write) {
            check((in->write_flags & FUSE_WRITE_CACHE) && failing_handle &&
                  h->nodeid == failure_node && in->fh == retained_failure_handle &&
                  in->fh != failing_handle && in->offset == 0 && in->size == (uint32_t)page_size,
                  "injected writeback uses original retained FH and exact dirty page after distinct new OPEN");
            inject_write = 0;
            evidence.write_errors++;
            reply(h->unique, EIO, NULL, 0);
            break;
        }
        ssize_t n = pwrite(fh->fd, in + 1, in->size, in->offset);
        struct fuse_write_out out = { .size = n < 0 ? 0 : (uint32_t)n };
        reply(h->unique, n < 0 ? errno : 0, n < 0 ? NULL : &out, n < 0 ? 0 : sizeof(out));
        break;
    }
    case FUSE_FSYNC: {
        struct fuse_fsync_in *in = ARG(struct fuse_fsync_in);
        struct handle *fh = handle(in->fh, h->nodeid);
        evidence.fsyncs++;
        if (inject_fsync) {
            inject_fsync = 0;
            evidence.fsync_errors++;
            reply(h->unique, EIO, NULL, 0);
        } else reply(h->unique, fsync(fh->fd) < 0 ? errno : 0, NULL, 0);
        break;
    }
    case FUSE_FLUSH: {
        struct fuse_flush_in *in = ARG(struct fuse_flush_in);
        (void)handle(in->fh, h->nodeid);
        reply(h->unique, 0, NULL, 0); // no invented durability acknowledgment: FSYNC does that
        break;
    }
    case FUSE_RELEASE:
    case FUSE_RELEASEDIR: {
        struct fuse_release_in *in = ARG(struct fuse_release_in);
        struct handle *fh = handle(in->fh, h->nodeid);
        check(close(fh->fd) == 0, "close actual opened backing FH");
        fh->fd = -1;
        object(h->nodeid)->opens--;
        evidence.releases++;
        if (failing_handle == in->fh) { evidence.failed_releases++; failing_handle = 0; }
        maybe_forget(h->nodeid);
        reply(h->unique, 0, NULL, 0);
        break;
    }
    case FUSE_LINK: {
        struct fuse_link_in *in = ARG(struct fuse_link_in);
        check(h->nodeid == 1, "flat hardlink destination");
        struct object *o = object(in->oldnodeid);
        if (linkat(o->fd, "", backing, name_arg(h, sizeof(*in)), AT_EMPTY_PATH) < 0)
            reply(h->unique, errno, NULL, 0);
        else { o->lookups++; entry_reply(h->unique, in->oldnodeid); }
        break;
    }
    case FUSE_UNLINK:
        check(h->nodeid == 1, "flat unlink parent");
        reply(h->unique, unlinkat(backing, name_arg(h, 0), 0) < 0 ? errno : 0, NULL, 0);
        break;
    case FUSE_READDIR: {
        struct fuse_read_in *in = ARG(struct fuse_read_in);
        (void)handle(in->fh, h->nodeid);
        check(h->nodeid == 1 && in->size <= BUFFER, "root READDIR");
        int directory_fd = openat(backing, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        check(directory_fd >= 0, "open authoritative backing namespace");
        DIR *dir = fdopendir(directory_fd);
        check(dir != NULL, "read authoritative backing namespace");
        unsigned char bytes[BUFFER];
        size_t used = 0;
        uint64_t index = 0;
        struct dirent *entry;
        while ((entry = readdir(dir))) {
            if (index++ < in->offset) continue;
            size_t length = strlen(entry->d_name);
            size_t size = FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + length);
            if (used + size > in->size) break;
            struct fuse_dirent *out = (void *)(bytes + used);
            memset(out, 0, size);
            out->ino = entry->d_ino; out->off = index;
            out->namelen = length; out->type = entry->d_type;
            memcpy(out->name, entry->d_name, length);
            used += size;
        }
        closedir(dir);
        reply(h->unique, 0, bytes, used);
        break;
    }
    default:
        fprintf(stderr, "strict unsupported opcode=%u\n", h->opcode);
        reply(h->unique, EOPNOTSUPP, NULL, 0);
        break;
    }
#undef ARG
}

static void backing_bytes(int fd, size_t size, unsigned char byte)
{
    struct stat st;
    check(fstat(fd, &st) == 0 && st.st_size == (off_t)size, "exact backing size");
    unsigned char bytes[65536];
    check(size <= sizeof(bytes), "bounded backing check");
    check(pread(fd, bytes, sizeof(bytes), 0) == (ssize_t)size, "backing data and EOF");
    for (size_t n = 0; n < size; n++) check(bytes[n] == byte, "exact authoritative backing bytes");
}
static void serve_control(void)
{
    struct message m = receive_message();
    check(memchr(m.name, 0, sizeof(m.name)) != NULL, "control name terminated");
    if (*m.name) check(!strchr(m.name, '/') && strcmp(m.name, ".") && strcmp(m.name, ".."), "control flat name");
    int fd = -1;
    if (m.command == REWRITE || m.command == CHECK_BACKING) {
        fd = openat(backing, m.name, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
        check(fd >= 0, "control backing file");
    }
    switch (m.command) {
    case REWRITE: {
        struct stat before, after;
        unsigned char bytes[65536];
        check(m.size <= sizeof(bytes) && fstat(fd, &before) == 0, "bounded rewrite");
        memset(bytes, m.byte, m.size);
        check(pwrite(fd, bytes, m.size, 0) == (ssize_t)m.size && ftruncate(fd, m.size) == 0, "out-of-band same-inode rewrite");
        struct timespec times[2] = { before.st_atim, before.st_mtim };
        check(futimens(fd, times) == 0 && fsync(fd) == 0 && fstat(fd, &after) == 0, "restore exact mtime and synchronize rewrite");
        check(before.st_ino == after.st_ino && before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
              before.st_mtim.tv_nsec == after.st_mtim.tv_nsec, "same inode and nanosecond mtime");
        m.stat = after;
        break;
    }
    case CHECK_BACKING:
        backing_bytes(fd, m.size, m.byte);
        check(fstat(fd, &m.stat) == 0, "return backing stat");
        break;
    case SNAPSHOT: break;
    case ARM_GETATTR:
        check(!inject_getattr && !failing_handle, "one GETATTR failure at a time");
        inject_getattr = 1;
        break;
    case ARM_FSYNC: inject_fsync = 1; break;
    case ARM_WRITE:
        check(!inject_write && !failing_handle, "one writeback failure");
        check(handle(retained_failure_handle, failure_node)->checked,
              "writeback injection requires the original live, checked failure FH");
        inject_write = 1;
        break;
    case FINISH:
        finishing = 1;
        break;
    default: check(0, "known control command");
    }
    if (fd >= 0) close(fd);
    m.evidence = evidence;
    send_message(&m);
}

static int open_file(const char *name, int flags)
{
    char path[4096];
    check(snprintf(path, sizeof(path), "%s/%s", client_mountpoint, name) < (int)sizeof(path), "file path");
    return open(path, flags | O_CLOEXEC);
}
static void close_file(int fd) { check(close(fd) == 0, "client close"); }
static struct stat forced_stat(int fd, int nofh)
{
    char path[64];
    struct statx sx;
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    check(statx(nofh ? AT_FDCWD : fd, nofh ? path : "",
                AT_STATX_FORCE_SYNC | (nofh ? 0 : AT_EMPTY_PATH), STATX_BASIC_STATS, &sx) == 0,
          "forced GETATTR via retained dentry or FH");
    struct stat s;
    check(fstat(fd, &s) == 0 && s.st_ino == sx.stx_ino && s.st_nlink == sx.stx_nlink &&
          s.st_size == (off_t)sx.stx_size, "fstat matches forced authoritative GETATTR");
    return s;
}
static void read_bytes(int fd, size_t size, unsigned char byte)
{
    unsigned char bytes[65536];
    check(size <= sizeof(bytes), "bounded read");
    check(pread(fd, bytes, sizeof(bytes), 0) == (ssize_t)size, "buffered exact size and EOF");
    for (size_t n = 0; n < size; n++) check(bytes[n] == byte, "fresh buffered bytes");
    if (size) {
        unsigned char *map = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
        check(map != MAP_FAILED, "read mmap");
        for (size_t n = 0; n < size; n++) check(map[n] == byte, "fresh mmap bytes");
        check(munmap(map, size) == 0, "unmap read view");
    }
}
static void exact_namespace(void)
{
    DIR *dir = opendir(client_mountpoint);
    check(dir != NULL, "client readdir");
    struct dirent *entry;
    unsigned seen = 0;
    errno = 0;
    while ((entry = readdir(dir))) {
        const char *name = entry->d_name;
        if (!strcmp(name, ".") || !strcmp(name, "..")) continue;
        check(strncmp(name, ".nfs", 4) != 0, "no hidden .nfs entry (never filtered)");
        if (!strcmp(name, "cache")) seen |= 1;
        else if (!strcmp(name, "trunc")) seen |= 2;
        else if (!strcmp(name, "failure")) seen |= 4;
        else check(0, "exact namespace contains no held name, alias, or hidden entry");
    }
    check(errno == 0 && seen == 7 && closedir(dir) == 0, "complete exact backing-derived directory listing");
}
static void require_failed_release(struct evidence before, int checked)
{
    struct evidence now = control(SNAPSHOT, NULL, 0, 0).evidence;
    check(now.opens == before.opens + 1 && now.checked == before.checked + checked &&
          now.failed_releases == before.failed_releases + 1,
          "failed checked-open synchronously RELEASEs exactly the newly opened FH");
}
static void client(void)
{
    close(device); device = -1;
    close(storage_session); storage_session = -1;
    close(backing); backing = -1;
    close(objects[1].fd); objects[1].fd = -1;
    mounted = 0;
    signal(SIGALRM, timeout_handler);
    alarm(90);
    int held = open_file("held", O_RDWR);
    check(held >= 0, "open held inode");
    struct stat original = forced_stat(held, 0);
    check(original.st_nlink == 1 && original.st_size == 12 && (original.st_mode & 07777) == 0600,
          "ORC-020 exact initial mode/size/link count");
    char oldpath[4096], aliaspath[4096];
    check(snprintf(oldpath, sizeof(oldpath), "%s/held", client_mountpoint) < (int)sizeof(oldpath) &&
          snprintf(aliaspath, sizeof(aliaspath), "%s/alias", client_mountpoint) < (int)sizeof(aliaspath), "link paths");
    check(link(oldpath, aliaspath) == 0, "real ext4 hardlink through FUSE");
    int alias = open_file("alias", O_RDWR);
    check(alias >= 0, "open hardlink alias");
    struct stat linked = forced_stat(alias, 0);
    check(linked.st_ino == original.st_ino && linked.st_nlink == 2 &&
          forced_stat(held, 0).st_nlink == 2, "hardlink retained inode identity and authoritative nlink2");
    check(unlink(oldpath) == 0 && forced_stat(held, 0).st_nlink == 1, "unlink first alias nlink1");
    check(unlink(aliaspath) == 0, "unlink last namespace alias");
    struct stat unlinked = forced_stat(held, 1);
    check(unlinked.st_ino == original.st_ino && unlinked.st_nlink == 0 &&
          unlinked.st_size == 12 && (unlinked.st_mode & 07777) == 0600 &&
          unlinked.st_uid == 0 && unlinked.st_gid == 0,
          "ORC-020 retained fstat exact identity/nlink0/12-byte/mode0600/root");
    read_bytes(held, 12, 'H');
    check(pwrite(held, "UUUUUUUUUUUU", 12, 0) == 12 && fsync(held) == 0, "write+fsync after unlink");
    read_bytes(alias, 12, 'U');
    check(forced_stat(alias, 1).st_nlink == 0, "both retained aliases nlink0 without FH");
    exact_namespace();
    close_file(alias); close_file(held);
    puts("PASS: exact held-unlink subcase; authoritative nlink0/no hidden names/hardlink identity/no-FH GETATTR");

    int fd = open_file("cache", O_RDWR);
    check(fd >= 0, "buffered cache file");
    unsigned char *map = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check(map != MAP_FAILED, "writable buffered mmap");
    memset(map, 'M', page_size);
    check(msync(map, page_size, MS_SYNC) == 0 && fsync(fd) == 0, "mmap msync + real backing fsync");
    control(CHECK_BACKING, "cache", page_size, 'M');
    unsigned char bytes[65536];
    memset(bytes, 'B', page_size);
    check(pwrite(fd, bytes, page_size, 0) == page_size && fsync(fd) == 0, "buffered write+fsync");
    check(munmap(map, page_size) == 0, "unmap before coordinated peer rewrite");
    control(CHECK_BACKING, "cache", page_size, 'B');
    read_bytes(fd, page_size, 'B');
    // Keep this old FD alive so the inode and cache cannot disappear between opens.
    size_t sizes[] = { (size_t)page_size, (size_t)page_size * 3 + 17, 31, 0, (size_t)page_size + 9 };
    for (size_t n = 0; n < sizeof(sizes) / sizeof(sizes[0]); n++) {
        struct message mutation = control(REWRITE, "cache", sizes[n], 'a' + n);
        struct evidence before = mutation.evidence;
        int fresh = open_file("cache", O_RDONLY);
        check(fresh >= 0, "reopen after same-inode/same-mtime peer mutation");
        struct evidence after = control(SNAPSHOT, NULL, 0, 0).evidence;
        check(after.checked == before.checked + 1, "forced post-OPEN GETATTR despite TTL and KEEP_CACHE");
        struct stat s = forced_stat(fresh, 0);
        check(s.st_ino == mutation.stat.st_ino && s.st_size == (off_t)sizes[n] &&
              s.st_mtim.tv_sec == mutation.stat.st_mtim.tv_sec &&
              s.st_mtim.tv_nsec == mutation.stat.st_mtim.tv_nsec, "reopen exact authoritative metadata");
        read_bytes(fresh, sizes[n], 'a' + n);
        close_file(fresh);
    }
    close_file(fd);
    puts("PASS: mmap/buffered fsync; KEEP_CACHE same-size/same-mtime rewrite, growth, shrink, empty/regrowth");

    fd = open_file("failure", O_RDWR);
    check(fd >= 0, "failure retained file");
    struct evidence before = control(ARM_GETATTR, NULL, 0, 0).evidence;
    errno = 0;
    check(open_file("failure", O_RDWR) == -1 && errno == EIO, "checked GETATTR EIO reaches open caller");
    require_failed_release(before, 1);
    control(ARM_FSYNC, NULL, 0, 0);
    errno = 0;
    check(fsync(fd) == -1 && errno == EIO, "backing service FSYNC EIO reaches caller");
    check(fsync(fd) == 0, "FSYNC retry is a new real backing sync");

    map = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check(map != MAP_FAILED, "writeback failure mapping");
    before = control(ARM_WRITE, NULL, 0, 0).evidence;
    map[0] = 'D'; // leave a real dirty page for checked open's filemap_write_and_wait
    errno = 0;
    check(open_file("failure", O_RDWR) == -1 && errno == EIO, "real writeback failure reaches checked open before GETATTR");
    require_failed_release(before, 0);
    control(CHECK_BACKING, "failure", page_size, 'F');
    errno = 0;
    check(fsync(fd) == -1 && errno == EIO, "retained original FH observes mmap writeback errseq");
    check(fsync(fd) == 0, "consumed writeback error permits a later successful sync");
    map[0] = 'R';
    check(msync(map, page_size, MS_SYNC) == 0 && fsync(fd) == 0 && munmap(map, page_size) == 0,
          "retained mapping usable after failed reopen");
    int retry = open_file("failure", O_RDONLY);
    check(retry >= 0, "clean-cache reopen succeeds after writeback failure");
    check(pread(retry, bytes, 1, 0) == 1 && bytes[0] == 'R', "new write preserved by retained handle fsync");
    close_file(retry); close_file(fd);
    puts("PASS: GETATTR/FSYNC/writeback errors; pre-GETATTR flush failure; failed-open FH cleanup and retry");

    fd = open_file("trunc", O_RDWR);
    check(fd >= 0, "non-atomic truncate retained original handle");
    map = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check(map != MAP_FAILED, "old truncate mapping");
    memset(map, 'X', page_size); // checked open must flush this before GETATTR; SETATTR is not reached
    before = control(ARM_GETATTR, NULL, 0, 0).evidence;
    errno = 0;
    check(open_file("trunc", O_RDWR | O_TRUNC) == -1 && errno == EIO, "non-atomic OPEN GETATTR fails before truncate SETATTR");
    require_failed_release(before, 1);
    check(control(SNAPSHOT, NULL, 0, 0).evidence.setattrs == before.setattrs,
          "failed checked OPEN never reaches truncate SETATTR");
    control(CHECK_BACKING, "trunc", page_size, 'X');
    // DONT_SYNC sees local size: asking the server first would hide incorrect ordering.
    struct statx local;
    check(statx(fd, "", AT_EMPTY_PATH | AT_STATX_DONT_SYNC, STATX_SIZE, &local) == 0 &&
          local.stx_size == (uint64_t)page_size, "failed non-atomic open leaves local size unchanged");
    check(fsync(fd) == 0, "fsync original FH after pre-truncate open failure");
    check(munmap(map, page_size) == 0, "unmap retained nontruncated view");
    control(CHECK_BACKING, "trunc", page_size, 'X');
    retry = open_file("trunc", O_RDWR);
    check(retry >= 0, "normal reopen after pre-truncate failure");
    read_bytes(retry, page_size, 'X');
    close_file(retry);
    puts("PASS: ABI3 non-atomic truncate open failure precedes SETATTR; dirty data flushed; size preserved; FH released");

    map = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check(map != MAP_FAILED, "retained mapping for successful non-atomic truncate");
    memset(map, 'Y', page_size);
    before = control(SNAPSHOT, NULL, 0, 0).evidence;
    int truncated = open_file("trunc", O_RDWR | O_TRUNC);
    check(truncated >= 0, "non-atomic checked OPEN then real truncate SETATTR");
    struct evidence after = control(SNAPSHOT, NULL, 0, 0).evidence;
    check(after.checked == before.checked + 1 && after.open_truncates == before.open_truncates + 1 &&
          after.writeback > before.writeback, "dirty flush and checked FH precede FILE/OPEN truncate");
    check(statx(fd, "", AT_EMPTY_PATH | AT_STATX_DONT_SYNC, STATX_SIZE, &local) == 0 &&
          !local.stx_size, "successful non-atomic truncate updates retained local size");
    control(CHECK_BACKING, "trunc", 0, 0);
    check(msync(map, page_size, MS_SYNC) == 0 && fsync(fd) == 0 && fsync(truncated) == 0,
          "old mapping and both actual FDs sync without resurrecting truncated data");
    check(munmap(map, page_size) == 0, "unmap truncated view without accessing beyond EOF");
    close_file(truncated);
    control(CHECK_BACKING, "trunc", 0, 0);
    retry = open_file("trunc", O_RDONLY);
    check(retry >= 0, "clean reopen after non-atomic truncate");
    read_bytes(retry, 0, 0); read_bytes(fd, 0, 0);
    close_file(retry); close_file(fd);
    puts("PASS: ABI3 non-atomic truncate FILE/OPEN SETATTR; dirty flush before truncation; retained mmap/fsync no rebirth");
    control(FINISH, NULL, 0, 0);
    fflush(stdout);
    _exit(0);
}

int main(int argc, char **argv)
{
    check(argc == 3 && !strcmp(argv[1], "--disposable-vm"), "usage: probe --disposable-vm /absolute/ext4/scratch-parent");
    check(geteuid() == 0 && getuid() == 0 && getegid() == 0 && getgid() == 0, "native Linux root driver required");
    check(argv[2][0] == '/', "absolute ext4 scratch parent required");
    page_size = sysconf(_SC_PAGESIZE);
    check(page_size > 0 && page_size * 3 + 17 <= 65536, "bounded page size");
    for (int n = 0; n < LIMIT; n++) objects[n].fd = handles[n].fd = -1;
    check(setgroups(0, NULL) == 0, "sole driver empty groups");
    struct __user_cap_header_struct caph = { .version = _LINUX_CAPABILITY_VERSION_3 };
    struct __user_cap_data_struct caps[2] = {{0}};
    check(syscall(SYS_capget, &caph, caps) == 0, "driver effective capability snapshot");
    expected_caps = caps[0].effective | ((uint64_t)caps[1].effective << 32);
    check(unshare(CLONE_NEWNS) == 0 && mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0,
          "own mount namespace with private propagation");
    check(snprintf(work, sizeof(work), "%s/fuse-stateful-XXXXXX", argv[2]) < (int)sizeof(work), "scratch path");
    check(mkdtemp(work) != NULL, "create only private owned scratch");
    atexit(cleanup);
    check(snprintf(mountpoint, sizeof(mountpoint), "%s/mount", work) < (int)sizeof(mountpoint) &&
          snprintf(backingpath, sizeof(backingpath), "%s/backing", work) < (int)sizeof(backingpath), "private subdirectories");
    check(mkdir(mountpoint, 0700) == 0 && mkdir(backingpath, 0700) == 0, "private directories");
    backing = open(backingpath, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    check(backing >= 0, "backing directory fd");
    struct statfs fs;
    check(fstatfs(backing, &fs) == 0 && fs.f_type == EXT4_SUPER_MAGIC, "real ext4-family backing required (also verify ext4 mount type)");
    // ext2/ext3 share the magic: check this superblock's actual mount type too.
    FILE *mounts = fopen("/proc/self/mountinfo", "r");
    check(mounts != NULL, "mountinfo required");
    struct stat backingstat;
    check(fstat(backing, &backingstat) == 0, "backing device identity");
    char *line = NULL;
    size_t capacity = 0;
    int ext4 = 0;
    while (getline(&line, &capacity, mounts) >= 0) {
        unsigned device_major, device_minor;
        char *separator = strstr(line, " - ");
        if (sscanf(line, "%*u %*u %u:%u", &device_major, &device_minor) == 2 &&
            device_major == major(backingstat.st_dev) && device_minor == minor(backingstat.st_dev) && separator)
            ext4 = !strncmp(separator + 3, "ext4 ", 5);
    }
    free(line); fclose(mounts);
    check(ext4, "backing mount is exactly ext4, not ext2/ext3/tmpfs/overlay");
    const char *names[] = { "held", "cache", "trunc", "failure" };
    const char fills[] = { 'H', 'C', 'T', 'F' };
    unsigned char bytes[65536];
    for (size_t n = 0; n < 4; n++) {
        int fd = openat(backing, names[n], O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        size_t size = n ? (size_t)page_size : 12;
        memset(bytes, fills[n], size);
        check(fd >= 0 && fchmod(fd, 0600) == 0 && write(fd, bytes, size) == (ssize_t)size && fsync(fd) == 0,
              "seed real backing regular file with durable data");
        close(fd);
    }
    struct stat rootstat;
    check(fstat(backing, &rootstat) == 0, "root backing stat");
    objects[1] = (struct object){ .fd = dup(backing), .ino = rootstat.st_ino, .lookups = 1 };
    check(objects[1].fd >= 0, "root object pin");
    device = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    check(device >= 0, "required /dev/fuse");
    storage_session = ioctl(device, FUSE_DEV_IOC_STORAGE_SESSION, 0);
    check(storage_session >= 0, "required ABI1 trusted local metadata session; no fallback");
    int session_flags = fcntl(storage_session, F_GETFD);
    check(session_flags >= 0 && (session_flags & FD_CLOEXEC), "metadata session is CLOEXEC");
    char options[256];
    snprintf(options, sizeof(options), "fd=%d,rootmode=40700,user_id=0,group_id=0,request_cred,default_permissions,managed_close_to_open", device);
    check(mount("fuse-stateful-experimental", mountpoint, "fuse", MS_NOSUID | MS_NODEV, options) == 0,
          "experimental 0002 required mount options; never fallback");
    mounted = 1;
    int sockets[2];
    check(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) == 0, "private control socket");
    child = fork();
    check(child >= 0, "fork bounded client");
    if (!child) {
        // Failures must not run the parent's cleanup or mutate its owned paths.
        close(sockets[0]); channel = sockets[1];
        child = -1;
        memcpy(client_mountpoint, mountpoint, sizeof(client_mountpoint));
        *work = *backingpath = *mountpoint = 0;
        client();
    }
    close(sockets[1]); channel = sockets[0];
    struct timespec start, now;
    check(clock_gettime(CLOCK_MONOTONIC, &start) == 0, "monotonic deadline");
    int status = 0, exited = 0;
    while (!exited || evidence.releases != evidence.opens) {
        check(clock_gettime(CLOCK_MONOTONIC, &now) == 0 && now.tv_sec - start.tv_sec < 95, "95s server total deadline");
        struct pollfd fds[2] = { { .fd = device, .events = POLLIN }, { .fd = finishing ? -1 : channel, .events = POLLIN } };
        int n = poll(fds, 2, 100);
        check(n >= 0 || errno == EINTR, "server poll");
        if (fds[0].revents & POLLIN) serve_request();
        if (fds[1].revents & POLLIN) serve_control();
        if (!exited) {
            pid_t result = waitpid(child, &status, WNOHANG);
            check(result >= 0, "bounded child wait");
            if (result == child) {
                child = -1; exited = 1;
                check(WIFEXITED(status) && WEXITSTATUS(status) == 0 && finishing, "all child assertions passed");
            }
        }
    }
    check(evidence.nofh_unlinked >= 2 && evidence.buffered && evidence.writeback && evidence.fsyncs &&
          evidence.getattr_errors == 2 && evidence.fsync_errors == 1 && evidence.failed_releases == 3 &&
          evidence.write_errors == 1 && evidence.setattrs >= 1 && evidence.open_truncates == 1 &&
          !inject_getattr && !inject_fsync && !inject_write && !failing_handle,
          "mandatory complete wire evidence, no skip or unused injection");
    printf("PASS: all required fixture assertions; opens=%llu releases=%llu checked=%llu nofh_unlinked=%llu buffered=%llu writeback=%llu fsync=%llu\n",
           (unsigned long long)evidence.opens, (unsigned long long)evidence.releases,
           (unsigned long long)evidence.checked, (unsigned long long)evidence.nofh_unlinked,
           (unsigned long long)evidence.buffered, (unsigned long long)evidence.writeback,
           (unsigned long long)evidence.fsyncs);
    printf("PASS: ABI3 metadata evidence; getxattr=%llu setattr=%llu open_truncate=%llu\n",
           (unsigned long long)evidence.getxattrs, (unsigned long long)evidence.setattrs,
           (unsigned long long)evidence.open_truncates);
    return 0;
}

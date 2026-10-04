/* Local bounded launcher, not an upstream filesystem test. */
#define _GNU_SOURCE
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif

#define EVIDENCE_BYTES 32768
#define SAMPLE_SECONDS 20

static volatile sig_atomic_t child_pid;
static void deadline(int sig)
{
    (void)sig;
    if (child_pid > 0) kill(-(pid_t)child_pid, SIGKILL);
    _exit(124);
}

static int seed_ok(const char *text)
{
    char *end;
    if (!text[0] || text[0] == '0' || strspn(text, "0123456789") != strlen(text)) return 0;
    unsigned long seed = strtoul(text, &end, 10);
    return !*end && seed > 0 && seed <= 1000000;
}

static int token_ok(const char *token)
{
    return strlen(token) == 32 && strspn(token, "0123456789abcdef") == 32;
}

static int work_ok(const char *work)
{
    return strlen(work) == 5 && work[0] == 'e' && work[1] >= '1' && work[1] <= '8' &&
        work[2] == '-' && work[3] == 'w' && work[4] >= '0' && work[4] <= '1';
}

static int fsx_ok(int argc, char **argv, const char *work)
{
    /* TESTONLY diagnostics: pilot seed 1, or the exact soak epoch/seed pair.
       Neither arbitrary work paths/seeds nor alternate fsx flags are accepted. */
    static const char *seeds[] = {"101", "202", "303", "404", "505", "606", "707", "808"};
    const char *seed = "1";
    if (work) {
        if (!work_ok(work)) return 0;
        seed = seeds[work[1] - '1'];
    }
    static const char *expected[] = {"/fsx", "-d", "-S", "1", "-N", "1000",
        "-l", "4194304", "-o", "65536", "fsx-file"};
    if (argc != (int)(sizeof(expected) / sizeof(expected[0]))) return 0;
    for (int i = 0; i < argc; i++)
        if (strcmp(i == 3 ? seed : expected[i], argv[i])) return 0;
    return 1;
}

static int evidence_open(const char *token, int create)
{
    char name[64];
    snprintf(name, sizeof(name), "cengine-fsx-%s.wait", token);
    int directory = open("/tmp", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) return -1;
    int fd = openat(directory, name, O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK |
                    (create ? O_WRONLY | O_CREAT | O_EXCL : O_RDONLY), 0600);
    int saved = errno;
    close(directory);
    errno = saved;
    return fd;
}

static void evidence_write(int fd, size_t *total, const char *data, size_t size)
{
    if (size > EVIDENCE_BYTES - *total) size = EVIDENCE_BYTES - *total;
    while (size) {
        ssize_t n = write(fd, data, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return;
        *total += (size_t)n; data += n; size -= (size_t)n;
    }
}

static void evidence_errno(int fd, size_t *total, const char *name, int error)
{
    char line[128];
    int n = snprintf(line, sizeof(line), "%s errno=%d\n", name, error);
    evidence_write(fd, total, line, (size_t)n);
}

static void evidence_proc(int output, size_t *total, int proc, const char *name)
{
    char data[4096];
    /* Fixed fields only. These reads run ONLY in the descriptor-only collector:
       proc's lock_trace can wait killably and ignore a handled SIGALRM. The
       parent stays out of that wait and sends fatal SIGKILL at its deadline. */
    int fd = openat(proc, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    int error = fd < 0 ? errno : 0;
    evidence_errno(output, total, name, error);
    if (fd < 0) return;
    size_t remaining = 6144; /* Four fields plus identity/errno framing <32 KiB. */
    while (remaining) {
        ssize_t n = read(fd, data, remaining < sizeof(data) ? remaining : sizeof(data));
        if (n < 0) { evidence_errno(output, total, "read", errno); break; }
        if (!n) break;
        evidence_write(output, total, data, (size_t)n);
        remaining -= (size_t)n;
    }
    if (!remaining) evidence_errno(output, total, "field-limit", EFBIG);
    evidence_write(output, total, "\n", 1);
    close(fd);
}

struct evidence_reader {
    int proc, output;
    size_t total;
};

static void *collect_evidence(void *argument)
{
    struct evidence_reader *reader = argument;
    /* Same process as fsx's direct parent (also for ptrace/Yama checks), but
       never the alarm owner. A fatal exit_group interrupts killable proc waits;
       a handled SIGALRM delivered to a synchronous reader would not. */
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);
    int error = pthread_sigmask(SIG_BLOCK, &mask, NULL);
    evidence_errno(reader->output, &reader->total, "collector_sigmask", error);
    if (!error) {
        evidence_write(reader->output, &reader->total, "snapshot-at-20s\n", 16);
        if (reader->proc >= 0) {
            static const char *fields[] = {"stat", "wchan", "syscall", "stack"};
            for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
                evidence_proc(reader->output, &reader->total, reader->proc, fields[i]);
        }
        evidence_write(reader->output, &reader->total, "snapshot-complete\n", 18);
    }
    if (reader->output >= 0) close(reader->output);
    if (reader->proc >= 0) close(reader->proc);
    free(reader);
    return NULL;
}

static int native_pidfd(pid_t child)
{
#if defined(__linux__) && defined(SYS_pidfd_open)
    return (int)syscall(SYS_pidfd_open, child, 0);
#else
    (void)child;
    errno = ENOSYS;
    return -1;
#endif
}

static void fsx_evidence(pid_t child, const char *token)
{
    /* Called only by the fork parent, BEFORE its single waitpid/reap. An
       unreaped direct child cannot have its PID recycled. Never inspect PID 1,
       a frontend, an exec-inspect PID, or a caller-supplied PID. */
    if (child <= 1) return;
    struct timespec start, now;
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return;
    int pidfd = native_pidfd(child);
    int pidfd_error = pidfd < 0 ? errno : 0;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld", (long)child);
    int proc = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int proc_error = proc < 0 ? errno : 0;
    int output = evidence_open(token, 1);
    size_t total = 0;
    char identity[128];
    int n = snprintf(identity, sizeof(identity), "fsx-wait-v1 direct-child=%ld parent=%ld sample-seconds=20\n",
                     (long)child, (long)getpid());
    evidence_write(output, &total, identity, (size_t)n);
    evidence_errno(output, &total, "pidfd_open", pidfd_error);
    evidence_errno(output, &total, "proc_open", proc_error);
    for (;;) {
        if (clock_gettime(CLOCK_MONOTONIC, &now)) goto done;
        long elapsed = (now.tv_sec - start.tv_sec) * 1000 +
                       (now.tv_nsec - start.tv_nsec) / 1000000;
        if (elapsed >= SAMPLE_SECONDS * 1000) break;
        if (pidfd >= 0) {
            struct pollfd owned = {pidfd, POLLIN, 0};
            int ready = poll(&owned, 1, SAMPLE_SECONDS * 1000 - (int)elapsed);
            if (ready > 0 && (owned.revents & POLLIN)) goto done;
            if (ready < 0 && errno == EINTR) continue;
            if (ready < 0 || (ready > 0 && owned.revents)) {
                evidence_errno(output, &total, "pidfd_poll", ready < 0 ? errno : EIO);
                close(pidfd); pidfd = -1;
            }
        } else {
            /* Denied/unavailable pidfd: observe only our child without reaping.
               Preserve its proc identity until the one waitpid below. */
            siginfo_t info = {0};
            if (waitid(P_PID, (id_t)child, &info, WEXITED | WNOHANG | WNOWAIT)) {
                evidence_errno(output, &total, "waitid", errno); goto done;
            }
            if (info.si_pid == child) goto done;
            struct timespec pause_time = {0, 100000000};
            nanosleep(&pause_time, NULL);
        }
    }
    /* Transfer only pinned descriptors, never a PID/path lookup. The alarm
       owner immediately proceeds to its single fsx wait/reap; it never joins
       a proc reader. stat field 22 records the owned child's native starttime. */
    struct evidence_reader *reader = malloc(sizeof(*reader));
    if (!reader) evidence_errno(output, &total, "collector_alloc", ENOMEM);
    else {
        *reader = (struct evidence_reader){proc, output, total};
        pthread_t collector;
        int error = pthread_create(&collector, NULL, collect_evidence, reader);
        if (error) {
            evidence_errno(output, &total, "collector_create", error);
            free(reader);
        } else {
            pthread_detach(collector);
            proc = output = -1; /* Reader owns these, including on partial exit. */
        }
    }
 done:
    if (output >= 0) close(output);
    if (proc >= 0) close(proc);
    if (pidfd >= 0) close(pidfd);
}

static int retrieve_evidence(const char *token)
{
    int fd = evidence_open(token, 0);
    if (fd < 0) return errno == ENOENT ? 2 : 125;
    struct stat info;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || (info.st_mode & 0777) != 0600 ||
        info.st_uid != geteuid() || info.st_nlink != 1 || info.st_size < 0 ||
        info.st_size > EVIDENCE_BYTES) { close(fd); return 125; }
    char data[EVIDENCE_BYTES + 1];
    ssize_t n = read(fd, data, sizeof(data));
    close(fd);
    if (n < 0 || n > EVIDENCE_BYTES || n != info.st_size) return 125;
    size_t total = 0;
    evidence_write(STDOUT_FILENO, &total, data, (size_t)n);
    return total == (size_t)n ? 0 : 125;
}

static int stress_ok(int argc, char **argv)
{
    /* Exact grammar: -c bypasses upstream system("rm -rf ..."). No -d,
       data writes, truncate, XFS ioctls, subprocesses or ambient random seed. */
    static const char *args[] = {"/fsstress", "-X", "-c", "-p", "1", "-l", "1",
        "-n", "128", "-s", NULL, "-v", "-z", "-f", "creat=4", "-f", "mkdir=2",
        "-f", "rename=2", "-f", "link=1", "-f", "symlink=1", "-f", "unlink=2",
        "-f", "rmdir=1", "-f", "stat=1", "-f", "getdents=1", "-f", "readlink=1"};
    if (argc != (int)(sizeof(args) / sizeof(args[0]))) return 0;
    for (int i = 0; i < argc; i++)
        if (args[i] ? strcmp(args[i], argv[i]) != 0 : !seed_ok(argv[i])) return 0;
    return 1;
}

int main(int argc, char **argv)
{
    struct rlimit size = {4 * 1024 * 1024, 4 * 1024 * 1024};
    struct rlimit core = {0, 0};
    struct rlimit cpu = {30, 30};
    struct rlimit memory = {256 * 1024 * 1024, 256 * 1024 * 1024};
    if (setrlimit(RLIMIT_FSIZE, &size) || setrlimit(RLIMIT_CORE, &core) ||
        setrlimit(RLIMIT_CPU, &cpu) || setrlimit(RLIMIT_AS, &memory)) {
        perror("setrlimit"); return 125;
    }
    if (argc == 2 && strcmp(argv[1], "keeper") == 0) {
        for (;;) pause(); /* No volume writes before backend proof. */
    }
    if (argc == 2 && strcmp(argv[1], "mountinfo") == 0) {
        FILE *file = fopen("/proc/self/mountinfo", "r");
        if (!file) { perror("mountinfo"); return 125; }
        char buf[4096];
        size_t total = 0, n;
        while ((n = fread(buf, 1, sizeof(buf), file))) {
            total += n;
            if (total > 1024 * 1024 || fwrite(buf, 1, n, stdout) != n) return 125;
        }
        int failed = ferror(file);
        fclose(file);
        return failed ? 125 : 0;
    }
    if (argc == 3 && strcmp(argv[1], "fsx-evidence") == 0 && token_ok(argv[2])) {
        signal(SIGALRM, deadline);
        alarm(5);
        return retrieve_evidence(argv[2]);
    }
    const char *work = NULL, *diagnostics = NULL;
    argc--; argv++;
    if (argc >= 2 && strcmp(argv[0], "--fsx-diagnostics") == 0) {
        diagnostics = argv[1];
        if (!token_ok(diagnostics)) return 125;
        argc -= 2; argv += 2;
    }
    if (argc >= 2 && strcmp(argv[0], "--work") == 0) {
        work = argv[1];
        if (!work_ok(work)) return 125;
        argc -= 2; argv += 2;
    }
    if (argc < 1) return 125;
    if (strcmp(argv[0], "/fsstress") == 0) {
        if (!work || !stress_ok(argc, argv)) return 125;
    } else if (strcmp(argv[0], "/fsx") && strcmp(argv[0], "/pjdfstest")) return 125;
    if (diagnostics && !fsx_ok(argc, argv, work)) return 125;
    /* Watchdog owns a separate process group: kill descendants, not just exec. */
    pid_t child = fork();
    if (child < 0) { perror("fork"); return 125; }
    if (child > 0) {
        int status;
        child_pid = child;
        setpgid(child, child);
        struct sigaction action = {0};
        action.sa_handler = deadline;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGALRM, &action, NULL)) { kill(-child, SIGKILL); return 125; }
        /* fsx wall calibrated 2026-09-19: shared managed-FUSE two-worker runs
           reached op ~700/1000 in the former 60 s bound with continuous
           progress; RTM-085 accepts 150 s for this exact fsx invocation. */
        alarm(strcmp(argv[0], "/fsx") == 0 ? 150 : 30); /* Fixed per executable, including soak. */
        /* Never cancel, rearm, extend or mask during diagnostics. */
        if (diagnostics) fsx_evidence(child, diagnostics);
        if (waitpid(child, &status, 0) < 0) { kill(-child, SIGKILL); return 125; }
        alarm(0);
        /* Terminate any reader with the process; no join can defer fsx's result.
           Raw evidence uses write(), not buffered stdio, so partial data survives. */
        _exit(WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status));
    }
    if (setpgid(0, 0)) { perror("setpgid"); return 125; }
    if (mkdir("/data/corpus", 0755) && errno != EEXIST) { perror("mkdir corpus"); return 125; }
    if (chdir("/data/corpus")) { perror("chdir corpus"); return 125; }
    if (work) {
        if (mkdir(work, 0755) && errno != EEXIST) { perror("mkdir work"); return 125; }
        if (chdir(work)) { perror("chdir work"); return 125; }
    }
    if (strcmp(argv[0], "/fsstress") == 0) {
        /* Upstream requires -d; inject only the already-confined cwd. The
           caller cannot supply an alternate directory or disable -c. */
        char *native[argc + 3];
        for (int i = 0; i < argc; i++) native[i] = argv[i];
        native[argc] = "-d";
        native[argc + 1] = ".";
        native[argc + 2] = NULL;
        execv(argv[0], native);
    } else {
        execv(argv[0], argv);
    }
    perror("execv");
    return 125;
}

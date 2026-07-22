//go:build linux && arm64

package supervisor

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	seccompDataNumberOffset       = 0
	seccompDataArchitectureOffset = 4
	seccompDataArgumentsOffset    = 16
	seccompNamespaceCloneFlags    = unix.CLONE_NEWNS | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC |
		unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET | unix.CLONE_NEWCGROUP
)

// dockerDefaultSeccompSyscalls is the arm64 subset of Moby's built-in default
// profile at f9bc03ec19b2dc4c091449b08e88f85c0caa9f0b. Syscalls with argument or
// capability conditions are appended below.
var dockerDefaultSeccompSyscalls = []uint32{
	unix.SYS_ACCEPT, unix.SYS_ACCEPT4, unix.SYS_ADJTIMEX, unix.SYS_BIND, unix.SYS_BRK, unix.SYS_CACHESTAT,
	unix.SYS_CAPGET, unix.SYS_CAPSET, unix.SYS_CHDIR, unix.SYS_CLOCK_ADJTIME, unix.SYS_CLOCK_GETRES, unix.SYS_CLOCK_GETTIME,
	unix.SYS_CLOCK_NANOSLEEP, unix.SYS_CLOSE, unix.SYS_CLOSE_RANGE, unix.SYS_CONNECT, unix.SYS_COPY_FILE_RANGE, unix.SYS_DUP,
	unix.SYS_DUP3, unix.SYS_EPOLL_CREATE1, unix.SYS_EPOLL_CTL, unix.SYS_EPOLL_PWAIT, unix.SYS_EPOLL_PWAIT2, unix.SYS_EVENTFD2,
	unix.SYS_EXECVE, unix.SYS_EXECVEAT, unix.SYS_EXIT, unix.SYS_EXIT_GROUP, unix.SYS_FACCESSAT, unix.SYS_FACCESSAT2,
	unix.SYS_FADVISE64, unix.SYS_FALLOCATE, unix.SYS_FANOTIFY_MARK, unix.SYS_FCHDIR, unix.SYS_FCHMOD, unix.SYS_FCHMODAT,
	unix.SYS_FCHMODAT2, unix.SYS_FCHOWN, unix.SYS_FCHOWNAT, unix.SYS_FCNTL, unix.SYS_FDATASYNC, unix.SYS_FGETXATTR,
	unix.SYS_FLISTXATTR, unix.SYS_FLOCK, unix.SYS_FREMOVEXATTR, unix.SYS_FSETXATTR, unix.SYS_FSTAT, unix.SYS_FSTATFS,
	unix.SYS_FSYNC, unix.SYS_FTRUNCATE, unix.SYS_FUTEX, unix.SYS_FUTEX_REQUEUE, unix.SYS_FUTEX_WAIT, unix.SYS_FUTEX_WAITV,
	unix.SYS_FUTEX_WAKE, unix.SYS_GETCPU, unix.SYS_GETCWD, unix.SYS_GETDENTS64, unix.SYS_GETEGID, unix.SYS_GETEUID,
	unix.SYS_GETGID, unix.SYS_GETGROUPS, unix.SYS_GETITIMER, unix.SYS_GETPEERNAME, unix.SYS_GETPGID, unix.SYS_GETPID,
	unix.SYS_GETPPID, unix.SYS_GETPRIORITY, unix.SYS_GETRANDOM, unix.SYS_GETRESGID, unix.SYS_GETRESUID, unix.SYS_GETRLIMIT,
	unix.SYS_GET_ROBUST_LIST, unix.SYS_GETRUSAGE, unix.SYS_GETSID, unix.SYS_GETSOCKNAME, unix.SYS_GETSOCKOPT, unix.SYS_GETTID,
	unix.SYS_GETTIMEOFDAY, unix.SYS_GETUID, unix.SYS_GETXATTR, unix.SYS_GETXATTRAT, unix.SYS_INOTIFY_ADD_WATCH, unix.SYS_INOTIFY_INIT1,
	unix.SYS_INOTIFY_RM_WATCH, unix.SYS_IO_CANCEL, unix.SYS_IOCTL, unix.SYS_IO_DESTROY, unix.SYS_IO_GETEVENTS, unix.SYS_IO_PGETEVENTS,
	unix.SYS_IOPRIO_GET, unix.SYS_IOPRIO_SET, unix.SYS_IO_SETUP, unix.SYS_IO_SUBMIT, unix.SYS_KILL, unix.SYS_LANDLOCK_ADD_RULE,
	unix.SYS_LANDLOCK_CREATE_RULESET, unix.SYS_LANDLOCK_RESTRICT_SELF, unix.SYS_LGETXATTR, unix.SYS_LINKAT, unix.SYS_LISTEN, unix.SYS_LISTMOUNT,
	unix.SYS_LISTXATTR, unix.SYS_LISTXATTRAT, unix.SYS_LLISTXATTR, unix.SYS_LREMOVEXATTR, unix.SYS_LSEEK, unix.SYS_LSETXATTR,
	unix.SYS_MADVISE, unix.SYS_MAP_SHADOW_STACK, unix.SYS_MEMBARRIER, unix.SYS_MEMFD_CREATE, unix.SYS_MEMFD_SECRET, unix.SYS_MINCORE,
	unix.SYS_MKDIRAT, unix.SYS_MKNODAT, unix.SYS_MLOCK, unix.SYS_MLOCK2, unix.SYS_MLOCKALL, unix.SYS_MMAP,
	unix.SYS_MPROTECT, unix.SYS_MQ_GETSETATTR, unix.SYS_MQ_NOTIFY, unix.SYS_MQ_OPEN, unix.SYS_MQ_TIMEDRECEIVE, unix.SYS_MQ_TIMEDSEND,
	unix.SYS_MQ_UNLINK, unix.SYS_MREMAP, unix.SYS_MSEAL, unix.SYS_MSGCTL, unix.SYS_MSGGET, unix.SYS_MSGRCV,
	unix.SYS_MSGSND, unix.SYS_MSYNC, unix.SYS_MUNLOCK, unix.SYS_MUNLOCKALL, unix.SYS_MUNMAP, unix.SYS_NAME_TO_HANDLE_AT,
	unix.SYS_NANOSLEEP, unix.SYS_NEWFSTATAT, unix.SYS_OPENAT, unix.SYS_OPENAT2, unix.SYS_PIDFD_OPEN, unix.SYS_PIDFD_SEND_SIGNAL,
	unix.SYS_PIPE2, unix.SYS_PKEY_ALLOC, unix.SYS_PKEY_FREE, unix.SYS_PKEY_MPROTECT, unix.SYS_PPOLL, unix.SYS_PRCTL,
	unix.SYS_PREAD64, unix.SYS_PREADV, unix.SYS_PREADV2, unix.SYS_PRLIMIT64, unix.SYS_PROCESS_MRELEASE, unix.SYS_PSELECT6,
	unix.SYS_PWRITE64, unix.SYS_PWRITEV, unix.SYS_PWRITEV2, unix.SYS_READ, unix.SYS_READAHEAD, unix.SYS_READLINKAT,
	unix.SYS_READV, unix.SYS_RECVFROM, unix.SYS_RECVMMSG, unix.SYS_RECVMSG, unix.SYS_REMAP_FILE_PAGES, unix.SYS_REMOVEXATTR,
	unix.SYS_REMOVEXATTRAT, unix.SYS_RENAMEAT, unix.SYS_RENAMEAT2, unix.SYS_RESTART_SYSCALL, unix.SYS_RSEQ, unix.SYS_RT_SIGACTION,
	unix.SYS_RT_SIGPENDING, unix.SYS_RT_SIGPROCMASK, unix.SYS_RT_SIGQUEUEINFO, unix.SYS_RT_SIGRETURN, unix.SYS_RT_SIGSUSPEND, unix.SYS_RT_SIGTIMEDWAIT,
	unix.SYS_RT_TGSIGQUEUEINFO, unix.SYS_SCHED_GETAFFINITY, unix.SYS_SCHED_GETATTR, unix.SYS_SCHED_GETPARAM, unix.SYS_SCHED_GET_PRIORITY_MAX, unix.SYS_SCHED_GET_PRIORITY_MIN,
	unix.SYS_SCHED_GETSCHEDULER, unix.SYS_SCHED_RR_GET_INTERVAL, unix.SYS_SCHED_SETAFFINITY, unix.SYS_SCHED_SETATTR, unix.SYS_SCHED_SETPARAM, unix.SYS_SCHED_SETSCHEDULER,
	unix.SYS_SCHED_YIELD, unix.SYS_SECCOMP, unix.SYS_SEMCTL, unix.SYS_SEMGET, unix.SYS_SEMOP, unix.SYS_SEMTIMEDOP,
	unix.SYS_SENDFILE, unix.SYS_SENDMMSG, unix.SYS_SENDMSG, unix.SYS_SENDTO, unix.SYS_SETFSGID, unix.SYS_SETFSUID,
	unix.SYS_SETGID, unix.SYS_SETGROUPS, unix.SYS_SETITIMER, unix.SYS_SETPGID, unix.SYS_SETPRIORITY, unix.SYS_SETREGID,
	unix.SYS_SETRESGID, unix.SYS_SETRESUID, unix.SYS_SETREUID, unix.SYS_SETRLIMIT, unix.SYS_SET_ROBUST_LIST, unix.SYS_SETSID,
	unix.SYS_SETSOCKOPT, unix.SYS_SET_TID_ADDRESS, unix.SYS_SETUID, unix.SYS_SETXATTR, unix.SYS_SETXATTRAT, unix.SYS_SHMAT,
	unix.SYS_SHMCTL, unix.SYS_SHMDT, unix.SYS_SHMGET, unix.SYS_SHUTDOWN, unix.SYS_SIGALTSTACK, unix.SYS_SIGNALFD4,
	unix.SYS_SOCKETPAIR, unix.SYS_SPLICE, unix.SYS_STATFS, unix.SYS_STATMOUNT, unix.SYS_STATX, unix.SYS_SYMLINKAT,
	unix.SYS_SYNC, unix.SYS_SYNC_FILE_RANGE, unix.SYS_SYNCFS, unix.SYS_SYSINFO, unix.SYS_TEE, unix.SYS_TGKILL,
	unix.SYS_TIMER_CREATE, unix.SYS_TIMER_DELETE, unix.SYS_TIMER_GETOVERRUN, unix.SYS_TIMER_GETTIME, unix.SYS_TIMER_SETTIME, unix.SYS_TIMERFD_CREATE,
	unix.SYS_TIMERFD_GETTIME, unix.SYS_TIMERFD_SETTIME, unix.SYS_TIMES, unix.SYS_TKILL, unix.SYS_TRUNCATE, unix.SYS_UMASK,
	unix.SYS_UNAME, unix.SYS_UNLINKAT, unix.SYS_UTIMENSAT, unix.SYS_VMSPLICE, unix.SYS_WAIT4, unix.SYS_WAITID,
	unix.SYS_WRITE, unix.SYS_WRITEV, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_PTRACE,
}

func applyDefaultSeccomp(enabled bool, capabilities uint64) error {
	if !enabled {
		return nil
	}
	filters := defaultSeccompFilter(capabilities)
	if len(filters) == 0 || len(filters) > int(^uint16(0)) {
		return fmt.Errorf("invalid default seccomp filter length %d", len(filters))
	}
	program := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
	if err := unix.Prctl(
		unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER,
		uintptr(unsafe.Pointer(&program)), 0, 0,
	); err != nil {
		return fmt.Errorf("install default seccomp profile: %w", err)
	}
	runtime.KeepAlive(filters)
	return nil
}

func defaultSeccompFilter(capabilities uint64) []unix.SockFilter {
	filters := []unix.SockFilter{
		seccompStatement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompDataArchitectureOffset),
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.AUDIT_ARCH_AARCH64, 1, 0),
		seccompStatement(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_KILL_PROCESS),
		seccompStatement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompDataNumberOffset),
	}
	for _, number := range dockerDefaultSeccompSyscalls {
		filters = appendSeccompAllow(filters, number)
	}

	conditional := make([]uint32, 0, 48)
	appendForCapability := func(capability int, syscalls ...uint32) {
		if capabilities&(uint64(1)<<capability) != 0 {
			conditional = append(conditional, syscalls...)
		}
	}
	appendForCapability(unix.CAP_DAC_READ_SEARCH, unix.SYS_OPEN_BY_HANDLE_AT)
	appendForCapability(
		unix.CAP_SYS_ADMIN,
		unix.SYS_BPF, unix.SYS_CLONE, unix.SYS_CLONE3, unix.SYS_FANOTIFY_INIT,
		unix.SYS_FSCONFIG, unix.SYS_FSMOUNT, unix.SYS_FSOPEN, unix.SYS_FSPICK,
		unix.SYS_LOOKUP_DCOOKIE, unix.SYS_LSM_GET_SELF_ATTR, unix.SYS_LSM_LIST_MODULES,
		unix.SYS_LSM_SET_SELF_ATTR, unix.SYS_MOUNT, unix.SYS_MOUNT_SETATTR,
		unix.SYS_MOVE_MOUNT, unix.SYS_OPEN_TREE, unix.SYS_PERF_EVENT_OPEN,
		unix.SYS_QUOTACTL, unix.SYS_QUOTACTL_FD, unix.SYS_SETDOMAINNAME,
		unix.SYS_SETHOSTNAME, unix.SYS_SETNS, unix.SYS_SYSLOG, unix.SYS_UMOUNT2,
		unix.SYS_UNSHARE,
	)
	appendForCapability(unix.CAP_SYS_BOOT, unix.SYS_REBOOT)
	appendForCapability(unix.CAP_SYS_CHROOT, unix.SYS_CHROOT)
	appendForCapability(
		unix.CAP_SYS_MODULE, unix.SYS_DELETE_MODULE, unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE,
	)
	appendForCapability(unix.CAP_SYS_PACCT, unix.SYS_ACCT)
	appendForCapability(
		unix.CAP_SYS_PTRACE, unix.SYS_KCMP, unix.SYS_PIDFD_GETFD, unix.SYS_PROCESS_MADVISE,
		unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_PTRACE,
	)
	appendForCapability(
		unix.CAP_SYS_TIME, unix.SYS_SETTIMEOFDAY, unix.SYS_CLOCK_SETTIME, unix.SYS_ADJTIMEX,
	)
	appendForCapability(unix.CAP_SYS_TTY_CONFIG, unix.SYS_VHANGUP)
	appendForCapability(
		unix.CAP_SYS_NICE, unix.SYS_GET_MEMPOLICY, unix.SYS_MBIND, unix.SYS_SET_MEMPOLICY,
		unix.SYS_SET_MEMPOLICY_HOME_NODE,
	)
	appendForCapability(unix.CAP_SYSLOG, unix.SYS_SYSLOG)
	appendForCapability(unix.CAP_BPF, unix.SYS_BPF)
	appendForCapability(unix.CAP_PERFMON, unix.SYS_PERF_EVENT_OPEN)
	for _, number := range conditional {
		filters = appendSeccompAllow(filters, number)
	}

	filters = appendSocketSeccompRule(filters)
	filters = appendPersonalitySeccompRule(filters)
	if capabilities&(uint64(1)<<unix.CAP_SYS_ADMIN) == 0 {
		filters = appendCloneSeccompRule(filters)
		filters = appendSeccompSyscallBlock(filters, unix.SYS_CLONE3, []unix.SockFilter{
			seccompStatement(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ERRNO|uint32(unix.ENOSYS)),
		})
	}
	return append(filters,
		seccompStatement(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM)),
	)
}

func appendSeccompAllow(filters []unix.SockFilter, number uint32) []unix.SockFilter {
	return append(filters,
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, number, 0, 1),
		seccompStatement(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ALLOW),
	)
}

func appendSeccompSyscallBlock(
	filters []unix.SockFilter, number uint32, body []unix.SockFilter,
) []unix.SockFilter {
	filters = append(filters,
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, number, 1, 0),
		seccompStatement(unix.BPF_JMP|unix.BPF_JA, uint32(len(body))),
	)
	return append(filters, body...)
}

func appendSocketSeccompRule(filters []unix.SockFilter) []unix.SockFilter {
	// Moby permits every socket family except AF_ALG (38) and AF_VSOCK (40).
	return appendSeccompSyscallBlock(filters, unix.SYS_SOCKET, []unix.SockFilter{
		seccompStatement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompDataArgumentsOffset),
		seccompJump(unix.BPF_JMP|unix.BPF_JGE|unix.BPF_K, unix.AF_ALG, 1, 0),
		seccompStatement(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ALLOW),
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.AF_ALG+1, 0, 1),
		seccompStatement(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ALLOW),
		seccompJump(unix.BPF_JMP|unix.BPF_JGT|unix.BPF_K, unix.AF_VSOCK, 0, 1),
		seccompStatement(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ALLOW),
		seccompStatement(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM)),
	})
}

func appendPersonalitySeccompRule(filters []unix.SockFilter) []unix.SockFilter {
	body := []unix.SockFilter{
		seccompStatement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompDataArgumentsOffset),
	}
	for _, value := range []uint32{0, 0x0008, 0x20000, 0x20008, 0xffffffff} {
		body = append(body,
			seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, value, 0, 1),
			seccompStatement(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ALLOW),
		)
	}
	body = append(body,
		seccompStatement(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM)),
	)
	return appendSeccompSyscallBlock(filters, unix.SYS_PERSONALITY, body)
}

func appendCloneSeccompRule(filters []unix.SockFilter) []unix.SockFilter {
	return appendSeccompSyscallBlock(filters, unix.SYS_CLONE, []unix.SockFilter{
		seccompStatement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompDataArgumentsOffset),
		seccompStatement(unix.BPF_ALU|unix.BPF_AND|unix.BPF_K, seccompNamespaceCloneFlags),
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, 0, 0, 1),
		seccompStatement(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ALLOW),
		seccompStatement(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM)),
	})
}

func seccompStatement(code uint16, value uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, K: value}
}

func seccompJump(code uint16, value uint32, whenTrue, whenFalse uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: whenTrue, Jf: whenFalse, K: value}
}

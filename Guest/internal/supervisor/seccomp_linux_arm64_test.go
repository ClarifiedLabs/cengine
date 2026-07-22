//go:build linux && arm64

package supervisor

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDefaultSeccompFilterRepresentativeDockerPolicyRules(t *testing.T) {
	filter := defaultSeccompFilter(0)
	if action := evaluateSeccompFilter(filter, unix.SYS_GETPID, nil, unix.AUDIT_ARCH_AARCH64); action != unix.SECCOMP_RET_ALLOW {
		t.Fatalf("getpid action = %#x, want allow", action)
	}
	if action := evaluateSeccompFilter(filter, unix.SYS_KEYCTL, nil, unix.AUDIT_ARCH_AARCH64); action != unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM) {
		t.Fatalf("keyctl action = %#x, want EPERM", action)
	}
	if action := evaluateSeccompFilter(filter, unix.SYS_CLONE, []uint64{uint64(unix.SIGCHLD)}, unix.AUDIT_ARCH_AARCH64); action != unix.SECCOMP_RET_ALLOW {
		t.Fatalf("ordinary clone action = %#x, want allow", action)
	}
	if action := evaluateSeccompFilter(filter, unix.SYS_CLONE, []uint64{unix.CLONE_NEWNS}, unix.AUDIT_ARCH_AARCH64); action != unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM) {
		t.Fatalf("namespace clone action = %#x, want EPERM", action)
	}
	if action := evaluateSeccompFilter(filter, unix.SYS_CLONE3, nil, unix.AUDIT_ARCH_AARCH64); action != unix.SECCOMP_RET_ERRNO|uint32(unix.ENOSYS) {
		t.Fatalf("clone3 action = %#x, want ENOSYS", action)
	}
	if action := evaluateSeccompFilter(filter, unix.SYS_SOCKET, []uint64{unix.AF_INET}, unix.AUDIT_ARCH_AARCH64); action != unix.SECCOMP_RET_ALLOW {
		t.Fatalf("AF_INET socket action = %#x, want allow", action)
	}
	for _, family := range []uint64{unix.AF_ALG, unix.AF_VSOCK} {
		if action := evaluateSeccompFilter(filter, unix.SYS_SOCKET, []uint64{family}, unix.AUDIT_ARCH_AARCH64); action != unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM) {
			t.Fatalf("socket family %d action = %#x, want EPERM", family, action)
		}
	}
	if action := evaluateSeccompFilter(filter, unix.SYS_SOCKET, []uint64{unix.AF_VSOCK + 1}, unix.AUDIT_ARCH_AARCH64); action != unix.SECCOMP_RET_ALLOW {
		t.Fatalf("future socket family action = %#x, want allow", action)
	}
	for _, architecture := range []uint32{unix.AUDIT_ARCH_ARM, 0} {
		if action := evaluateSeccompFilter(filter, unix.SYS_GETPID, nil, architecture); action != unix.SECCOMP_RET_KILL_PROCESS {
			t.Fatalf("foreign architecture %#x action = %#x, want kill", architecture, action)
		}
	}
}

func TestDefaultSeccompFilterHonorsCapabilityRules(t *testing.T) {
	withoutCapabilities := defaultSeccompFilter(0)
	withBPF := defaultSeccompFilter(uint64(1) << unix.CAP_BPF)
	withAdmin := defaultSeccompFilter(uint64(1) << unix.CAP_SYS_ADMIN)

	if action := evaluateSeccompFilter(withoutCapabilities, unix.SYS_BPF, nil, unix.AUDIT_ARCH_AARCH64); action != unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM) {
		t.Fatalf("BPF without capability action = %#x, want EPERM", action)
	}
	if action := evaluateSeccompFilter(withBPF, unix.SYS_BPF, nil, unix.AUDIT_ARCH_AARCH64); action != unix.SECCOMP_RET_ALLOW {
		t.Fatalf("BPF with CAP_BPF action = %#x, want allow", action)
	}
	if action := evaluateSeccompFilter(withAdmin, unix.SYS_CLONE3, nil, unix.AUDIT_ARCH_AARCH64); action != unix.SECCOMP_RET_ALLOW {
		t.Fatalf("clone3 with CAP_SYS_ADMIN action = %#x, want allow", action)
	}
}

func TestDefaultSeccompFilterInstallsInKernel(t *testing.T) {
	if os.Getenv("CENGINE_SECCOMP_HELPER") == "1" {
		runDefaultSeccompKernelHelper(t)
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestDefaultSeccompFilterInstallsInKernel$")
	command.Env = append(os.Environ(), "CENGINE_SECCOMP_HELPER=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("seccomp helper failed: %v\n%s", err, output)
	}
}

func runDefaultSeccompKernelHelper(t *testing.T) {
	before, err := seccompFilterCount()
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatalf("set no_new_privs: %v", err)
	}
	if err := applyDefaultSeccomp(true, 0); err != nil {
		t.Fatal(err)
	}
	after, err := seccompFilterCount()
	if err != nil {
		t.Fatal(err)
	}
	if after != before+1 {
		t.Fatalf("Seccomp_filters = %d after install, want %d", after, before+1)
	}
	_, _, errno := unix.Syscall(unix.SYS_CLONE3, 0, 0, 0)
	if errno != unix.ENOSYS {
		t.Fatalf("clone3 errno = %v, want ENOSYS", errno)
	}
	_, _, errno = unix.Syscall6(unix.SYS_KEYCTL, 0, 0, 0, 0, 0, 0)
	if errno != unix.EPERM {
		t.Fatalf("keyctl errno = %v, want EPERM", errno)
	}
}

func seccompFilterCount() (int, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "Seccomp_filters:"); ok {
			return strconv.Atoi(strings.TrimSpace(value))
		}
	}
	return 0, fmt.Errorf("Seccomp_filters is missing from /proc/self/status")
}

func evaluateSeccompFilter(
	filter []unix.SockFilter, number uint32, arguments []uint64, architecture uint32,
) uint32 {
	accumulator := uint32(0)
	for instruction := 0; instruction < len(filter); instruction++ {
		current := filter[instruction]
		switch current.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			switch current.K {
			case seccompDataNumberOffset:
				accumulator = number
			case seccompDataArchitectureOffset:
				accumulator = architecture
			default:
				index := int(current.K-seccompDataArgumentsOffset) / 8
				if index >= 0 && index < len(arguments) {
					accumulator = uint32(arguments[index])
				} else {
					accumulator = 0
				}
			}
		case unix.BPF_ALU | unix.BPF_AND | unix.BPF_K:
			accumulator &= current.K
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if accumulator == current.K {
				instruction += int(current.Jt)
			} else {
				instruction += int(current.Jf)
			}
		case unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K:
			if accumulator >= current.K {
				instruction += int(current.Jt)
			} else {
				instruction += int(current.Jf)
			}
		case unix.BPF_JMP | unix.BPF_JGT | unix.BPF_K:
			if accumulator > current.K {
				instruction += int(current.Jt)
			} else {
				instruction += int(current.Jf)
			}
		case unix.BPF_JMP | unix.BPF_JA:
			instruction += int(current.K)
		case unix.BPF_RET | unix.BPF_K:
			return current.K
		default:
			panic(fmt.Sprintf("unsupported BPF instruction %#x", current.Code))
		}
	}
	panic("seccomp filter did not return an action")
}

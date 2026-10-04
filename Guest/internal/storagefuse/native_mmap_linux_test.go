//go:build linux && (arm64 || amd64)

package storagefuse

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func nativeExecMmap(t *testing.T, base string, mount *mounted, backing string, safeToRemove *bool) {
	t.Helper()
	// Pin the running image, not os.Executable's replaceable source pathname.
	executable, err := os.Open("/proc/self/exe")
	nativeMust(t, err)
	defer executable.Close()
	childPath := filepath.Join(base, "mmap-child.test")
	childFile, err := os.OpenFile(childPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	nativeMust(t, err)
	defer childFile.Close()
	_, err = io.Copy(childFile, executable)
	nativeMust(t, err)
	nativeMust(t, childFile.Close())
	// Executable and cwd are actual ext4, never this process's FUSE mount. No
	// ExtraFiles or pre-exec FUSE operations: see go-fuse fs/api.go Deadlocks 1.
	cmd := exec.Command(childPath, "-test.run=^TestNativeMountedMmapChild$", "-test.v", "--", mount.path, backing)
	cmd.Dir = base
	cmd.Env = []string{"TMPDIR=/scratch", "STORAGEFUSE_MMAP_CHILD=1", "GOTRACEBACK=all", "GOMAXPROCS=1"}
	out := newNativeChildOutput(os.Stdout)
	t.Logf("mmap exec start: parent=%d mountID=%d connection=%d", os.Getpid(), mount.mountID, mount.connection)
	joined, err := nativeRunChild(cmd, 20*time.Second, out, func(pid int) string {
		return nativeMmapDiagnostics(pid, mount.connection)
	}, func() { mount.fs.stop(context.DeadlineExceeded) })
	if !joined {
		*safeToRemove = false
	}
	if err != nil {
		t.Fatalf("mmap exec joined=%t: %v\n%s", joined, err, out.String())
	}
	t.Log("mmap exec completed and reaped")
}

func TestNativeMountedMmapChild(t *testing.T) {
	if os.Getenv("STORAGEFUSE_MMAP_CHILD") != "1" {
		t.Skip("internal mmap subprocess only")
	}
	if os.Geteuid() != 0 || filepath.Clean(os.TempDir()) != "/scratch" {
		t.Fatal("mmap child must retain root and /scratch")
	}
	args := os.Args
	if len(args) < 4 || args[len(args)-3] != "--" {
		t.Fatal("invalid mmap child arguments")
	}
	root, backing := args[len(args)-2], args[len(args)-1]
	var stat unix.Statfs_t
	t.Logf("mmap phase=verify-fuse-ext4 begin pid=%d", os.Getpid())
	nativeMust(t, unix.Statfs(root, &stat))
	if stat.Type != unix.FUSE_SUPER_MAGIC {
		t.Fatal("mmap child must access actual FUSE")
	}
	nativeMust(t, unix.Statfs(backing, &stat))
	if stat.Type != unix.EXT4_SUPER_MAGIC {
		t.Fatal("mmap child backing must be actual ext4")
	}
	t.Log("mmap phase=verify-fuse-ext4 done")
	nativeMmap(t, root, backing)
}

// Read only procfs/fusectl for our two PIDs and the exact owned connection. The
// runner bounds this whole callback too; missing ptrace/proc permissions are
// evidence, not a reason to substitute simulated credentials or a stock kernel.
func nativeMmapDiagnostics(child int, connection uint64) string {
	var out strings.Builder
	read := func(path string) {
		f, err := os.Open(path)
		if err != nil {
			fmt.Fprintf(&out, "%s: %v\n", path, err)
			return
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, 2048))
		fmt.Fprintf(&out, "%s: %s [err=%v]\n", path, data, err)
	}
	read(fmt.Sprintf("/sys/fs/fuse/connections/%d/waiting", connection))
	for _, pid := range []int{child, os.Getpid()} {
		start := out.Len() // reserve diagnostics for both processes, not just the child
		tasks := fmt.Sprintf("/proc/%d/task", pid)
		entries, err := os.ReadDir(tasks)
		if err != nil {
			fmt.Fprintf(&out, "%s: %v\n", tasks, err)
			continue
		}
		for i, entry := range entries {
			if i == 32 || out.Len()-start >= 16<<10 {
				fmt.Fprintf(&out, "%s: remaining threads omitted\n", tasks)
				break
			}
			for _, name := range []string{"wchan", "syscall", "stack"} {
				read(filepath.Join(tasks, entry.Name(), name))
			}
		}
	}
	return out.String()
}

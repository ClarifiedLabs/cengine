//go:build linux

// Secret-free RTM-073 syscall reporter; no dependency on Guest or an image shell.
// Python owns the assertions: failed syscalls are reported, never self-certified.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// Use Linux l*xattr explicitly. Following the final symlink is opt-in and only
// used as a read control; no set operation in this probe follows a symlink.
func xattr(path, name string, value []byte, set, follow bool) (int, syscall.Errno) {
	p, err := syscall.BytePtrFromString(path)
	must(err)
	n, err := syscall.BytePtrFromString(name)
	must(err)
	var data unsafe.Pointer
	if len(value) != 0 {
		data = unsafe.Pointer(&value[0])
	}
	op := uintptr(syscall.SYS_LGETXATTR)
	if set {
		op = syscall.SYS_LSETXATTR
	} else if follow {
		op = syscall.SYS_GETXATTR
	}
	r, _, errno := syscall.Syscall6(op, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(n)), uintptr(data), uintptr(len(value)), 0, 0)
	runtime.KeepAlive(p)
	runtime.KeepAlive(n)
	runtime.KeepAlive(value)
	if errno != 0 {
		return 0, errno
	}
	return int(r), 0
}

// Closed fixture selectors keep batch operations bounded and prevent a caller
// from turning the capability controls into arbitrary-path mutations.
func linkPaths(selector string) []string {
	switch selector {
	case "populated":
		return []string{"/populated/link", "/populated/cap-live", "/populated/cap-dangling"}
	case "empty":
		return []string{"/links/live", "/links/dangling"}
	default:
		panic("unknown symlink selector")
	}
}

func inodeProof(path string, link bool) map[string]any {
	var st syscall.Stat_t
	must(syscall.Lstat(path, &st))
	out := map[string]any{"mode": st.Mode, "owner": st.Uid, "group": st.Gid,
		"mtime_ns": st.Mtim.Nano(), "ctime_ns": st.Ctim.Nano()}
	if link {
		target, err := os.Readlink(path)
		must(err)
		out["target"] = target
	}
	buffer := make([]byte, 65536)
	p, err := syscall.BytePtrFromString(path)
	must(err)
	n, _, errno := syscall.Syscall(syscall.SYS_LLISTXATTR, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	runtime.KeepAlive(p)
	out["list_errno"] = int(errno)
	attrs := map[string]string{}
	if errno == 0 && n != 0 {
		if n > uintptr(len(buffer)) || buffer[n-1] != 0 {
			panic("invalid xattr list")
		}
		names := strings.Split(string(buffer[:n-1]), "\x00")
		if len(names) > 16 {
			panic("fixture xattr count bound")
		}
		total := 0
		for _, name := range names {
			value := make([]byte, 65536)
			length, getErrno := xattr(path, name, value, false, false)
			if getErrno != 0 {
				panic(fmt.Sprintf("listed xattr read: %d", getErrno))
			}
			total += length + len(name)
			if total > 65536 {
				panic("fixture xattr byte bound")
			}
			attrs[name] = hex.EncodeToString(value[:length])
		}
	}
	out["attrs"] = attrs
	return out
}

func outsideProof() map[string]any {
	out := inodeProof("/sentinel", false)
	value, err := os.ReadFile("/sentinel")
	must(err)
	if len(value) > 4096 {
		panic("sentinel bound")
	}
	out["value"] = hex.EncodeToString(value)
	return out
}

type capabilityHeader struct {
	Version uint32
	PID     int32
}
type capabilityWord struct{ Effective, Permitted, Inheritable uint32 }

func capabilities(clear bool) uint64 {
	header := capabilityHeader{Version: 0x20080522}
	var words [2]capabilityWord
	op := uintptr(syscall.SYS_CAPGET)
	if clear {
		op = syscall.SYS_CAPSET
	}
	_, _, errno := syscall.RawSyscall(op, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&words[0])), 0)
	must(errnoError(errno))
	if clear {
		return capabilities(false)
	}
	return uint64(words[0].Effective) | uint64(words[1].Effective)<<32
}

func errnoError(errno syscall.Errno) error {
	if errno == 0 {
		return nil
	}
	return errno
}

func capabilityControls() []map[string]any {
	// Credential changes belong only to this short-lived probe's locked main
	// thread. Drop permitted/inheritable too; uid 0 must not regain SETFCAP.
	runtime.LockOSThread()
	phases := []string{"caller"}
	if os.Geteuid() == 0 {
		phases = append(phases, "uid-zero-no-caps")
	}
	results := []map[string]any{}
	original := make([]byte, 20)
	binary.LittleEndian.PutUint32(original, 0x02000001)
	binary.LittleEndian.PutUint32(original[4:], 1<<10)
	changed := append([]byte{}, original...)
	binary.LittleEndian.PutUint32(changed[4:], 1) // permitted CAP_CHOWN
	for _, phase := range phases {
		caps := capabilities(phase == "uid-zero-no-caps")
		for _, path := range linkPaths("populated")[1:] {
			before := outsideProof()
			_, errno := xattr(path, "security.capability", changed, true, false)
			row := map[string]any{"phase": phase, "path": path, "caps": caps,
				"errno": int(errno), "link": inodeProof(path, true),
				"outside_before": before, "outside_after": outsideProof()}
			if errno == 0 {
				_, restoreErrno := xattr(path, "security.capability", original, true, false)
				row["restore_errno"] = int(restoreErrno)
				row["restored"] = inodeProof(path, true)
				row["outside_restored"] = outsideProof()
			}
			results = append(results, row)
		}
	}
	return results
}

func main() {
	a := os.Args[1:]
	if len(a) == 0 {
		panic("missing operation")
	}
	out := map[string]any{"uid": os.Geteuid(), "gid": os.Getegid()}
	switch a[0] {
	case "serve":
		for {
			time.Sleep(time.Hour)
		}
	case "symlink-proof":
		if len(a) != 2 {
			panic("symlink-proof SELECTOR")
		}
		links := map[string]any{}
		for _, path := range linkPaths(a[1]) {
			links[path] = inodeProof(path, true)
		}
		out["links"], out["outside"] = links, outsideProof()
	case "capability-controls":
		if len(a) != 2 || a[1] != "populated" {
			panic("capability-controls populated")
		}
		out["controls"] = capabilityControls()
	case "empty-directory":
		if len(a) != 2 || a[1] != "links" {
			panic("empty-directory links")
		}
		entries, err := os.ReadDir("/links")
		must(err)
		if len(entries) > 16 {
			panic("directory count bound")
		}
		names := []string{}
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		out["entries"], out["outside"] = names, outsideProof()
	case "get", "get-follow":
		if len(a) != 3 {
			panic("get PATH NAME")
		}
		value := make([]byte, 65536)
		n, errno := xattr(a[1], a[2], value, false, a[0] == "get-follow")
		out["errno"], out["value"] = int(errno), hex.EncodeToString(value[:n])
	case "set":
		if len(a) != 4 {
			panic("set PATH NAME HEX")
		}
		value, err := hex.DecodeString(a[3])
		must(err)
		_, errno := xattr(a[1], a[2], value, true, false)
		out["errno"] = int(errno)
	case "stat":
		if len(a) != 2 {
			panic("stat PATH")
		}
		var stat syscall.Stat_t
		must(syscall.Lstat(a[1], &stat))
		out["owner"], out["group"], out["mode"] = stat.Uid, stat.Gid, stat.Mode
		out["dev"], out["rdev"] = stat.Dev, stat.Rdev
		if stat.Mode&syscall.S_IFMT == syscall.S_IFLNK {
			target, err := os.Readlink(a[1])
			must(err)
			out["target"] = target
		}
	case "fs":
		if len(a) != 2 {
			panic("fs PATH")
		}
		var fs syscall.Statfs_t
		must(syscall.Statfs(a[1], &fs))
		mounts, err := os.ReadFile("/proc/self/mountinfo")
		must(err)
		out["magic"], out["mountinfo"] = fs.Type, string(mounts)
	case "read":
		if len(a) != 2 {
			panic("read PATH")
		}
		value, err := os.ReadFile(a[1])
		errno := syscall.Errno(0)
		if err != nil {
			pathError, ok := err.(*os.PathError)
			if !ok {
				panic(err)
			}
			errno, ok = pathError.Err.(syscall.Errno)
			if !ok {
				panic(err)
			}
		}
		out["errno"], out["value"] = int(errno), hex.EncodeToString(value)
	default:
		panic(fmt.Sprintf("unknown operation %q", a[0]))
	}
	must(json.NewEncoder(os.Stdout).Encode(out))
}

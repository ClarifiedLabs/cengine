// RTM096 observer/emptying and RTM103 fixed writer helper. Never an initializer or fault hook.
// Build offline for linux/arm64; execute ONLY via actual Docker runtime exec.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func must(err error) {
	if err != nil {
		panic("closed RTM096 helper failure")
	}
}
func open(path string, directory bool) *os.File {
	flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NOATIME
	if directory {
		flags |= syscall.O_DIRECTORY
	}
	fd, err := syscall.Open(path, flags, 0)
	must(err)
	return os.NewFile(uintptr(fd), path)
}
func metadata(file *os.File, regular bool) map[string]any {
	info, err := file.Stat()
	must(err)
	st := info.Sys().(*syscall.Stat_t)
	attrs := make(map[string][]byte)
	// Fixed no-symlink paths opened above; no concurrent workload writers exist.
	list := make([]byte, 4096)
	count, err := syscall.Listxattr(file.Name(), list)
	must(err)
	for _, name := range strings.Split(string(list[:count]), "\x00") {
		if name == "" {
			continue
		}
		value := make([]byte, 4096)
		n, err := syscall.Getxattr(file.Name(), name, value)
		must(err)
		attrs[name] = value[:n]
	}
	result := map[string]any{"mode": st.Mode, "uid": st.Uid, "gid": st.Gid,
		"atimeNS": st.Atim.Sec*1e9 + st.Atim.Nsec, "mtimeNS": st.Mtim.Sec*1e9 + st.Mtim.Nsec, "xattrs": attrs}
	if regular {
		if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
			panic("not regular")
		}
		data, err := io.ReadAll(io.LimitReader(file, 4097))
		must(err)
		if len(data) > 4096 {
			panic("byte bound")
		}
		hash := sha256.Sum256(data)
		result["size"], result["sha256"], result["nlink"] = st.Size, hex.EncodeToString(hash[:]), st.Nlink
	}
	return result
}
func entries(root *os.File) []string {
	values, err := root.Readdirnames(4)
	if err != nil && err != io.EOF {
		must(err)
	}
	if len(values) > 3 {
		panic("entry bound")
	}
	if values == nil {
		values = []string{}
	}
	sort.Strings(values)
	return values
}

// Only the fixed mounted /data directory and marker are used. No path, mount,
// authority or payload is accepted from the caller. Failure never emits an ACK.
func writer(root *os.File) {
	const marker = ".rtm103-writer"
	const payload = "rtm103-authorized-writer\n"
	var before syscall.Stat_t
	must(syscall.Fstat(int(root.Fd()), &before))
	fd, err := syscall.Openat(int(root.Fd()), marker,
		syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	must(err)
	file := os.NewFile(uintptr(fd), "/data/"+marker)
	defer file.Close()
	n, err := file.Write([]byte(payload))
	must(err)
	if n != len(payload) {
		panic("complete fixed writer payload required")
	}
	must(file.Sync())
	_, err = file.Seek(0, io.SeekStart)
	must(err)
	raw, err := io.ReadAll(io.LimitReader(file, int64(len(payload)+1)))
	must(err)
	if string(raw) != payload {
		panic("exact writer readback required")
	}
	must(file.Close())
	must(syscall.Unlinkat(int(root.Fd()), marker))
	// Creating/unlinking our marker changes the parent times, not a/z. Restore
	// only the captured parent atime/mtime, then durably commit the cleanup.
	// ctime is not part of the fixture's snapshot preservation claim.
	must(syscall.UtimesNano("/data", []syscall.Timespec{before.Atim, before.Mtim}))
	must(root.Sync())
}

// Retained observations deliberately have their own schema: the original
// snapshot/empty commands and their timestamp expectations remain unchanged.
func retainedMetadata(file *os.File, regular bool) map[string]any {
	info, err := file.Stat()
	must(err)
	st := info.Sys().(*syscall.Stat_t)
	mode := uint32(syscall.S_IFDIR | 0750)
	if regular {
		mode = syscall.S_IFREG | 0640
	}
	if st.Mode != mode || st.Uid != 10001 || st.Gid != 10002 ||
		(regular && (st.Nlink != 1 || st.Size < 1 || st.Size > 4096)) {
		panic("exact retained owner/mode/bounds required")
	}
	result := metadata(file, regular)
	result["ctimeNS"] = st.Ctim.Sec*1e9 + st.Ctim.Nsec
	return result
}

func retainedOpen(root *os.File, name string, writable bool) *os.File {
	flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NOATIME | syscall.O_NONBLOCK
	if writable {
		flags |= syscall.O_RDWR // O_RDONLY is zero on Linux.
	}
	fd, err := syscall.Openat(int(root.Fd()), name, flags, 0)
	must(err)
	// xattrs in metadata() resolve the pinned inode, not a mutable pathname.
	return os.NewFile(uintptr(fd), "/proc/self/fd/"+strconv.Itoa(fd))
}

func retainedMountinfo() string { return managedMountinfo([]string{"/data"}) }

func managedMountinfo(paths []string) string {
	mount, err := os.Open("/proc/self/mountinfo")
	must(err)
	defer mount.Close()
	raw, err := io.ReadAll(io.LimitReader(mount, 65537))
	must(err)
	if len(raw) > 65536 {
		panic("mountinfo bound")
	}
	matches := make(map[string]int)
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		selected := false
		for _, path := range paths {
			if fields[4] == path {
				selected = true
			}
		}
		if !selected {
			continue
		}
		matches[fields[4]]++
		separator := -1
		for i, field := range fields {
			if field == "-" {
				separator = i
				break
			}
		}
		if separator < 6 || len(fields) != separator+4 ||
			fields[separator+1] != "fuse.managed-v3" || fields[separator+2] != "managed-v3" ||
			!strings.Contains(","+fields[5]+",", ",rw,") || strings.Contains(","+fields[5]+",", ",ro,") {
			panic("exact writable managed mount required")
		}
	}
	for _, path := range paths {
		if matches[path] != 1 {
			panic("one exact managed mount required")
		}
	}
	return string(raw)
}

func retained(command string) map[string]any {
	mountinfo := retainedMountinfo() // Reject a wrong mount before any write.
	fd, err := syscall.Open("/data", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NOATIME, 0)
	must(err)
	root := os.NewFile(uintptr(fd), "/proc/self/fd/"+strconv.Itoa(fd))
	defer root.Close()
	rootMetadata := retainedMetadata(root, false)
	names := entries(root)
	if len(names) != 2 || names[0] != "a" || names[1] != "z" {
		panic("exact retained tree required")
	}
	files := make(map[string]any)
	// Exactly one existing O_RDWR descriptor is used for WriteAt and Sync.
	// No create, truncate, or retry/reopen path exists.
	a := retainedOpen(root, "a", command == "retained-write")
	defer a.Close()
	files["a"] = retainedMetadata(a, true)
	z := retainedOpen(root, "z", false)
	files["z"] = retainedMetadata(z, true)
	must(z.Close())
	if command == "retained-write" {
		written, err := a.WriteAt([]byte{0x5a}, 0)
		must(err)
		if written != 1 {
			panic("exact one-byte write required")
		}
		must(a.Sync())
		// The independent noatime reader runs only after the real Sync returns.
		result := retained("retained-snapshot")
		result["command"] = command
		result["written"], result["completed"] = written, true
		return result
	}
	return map[string]any{"command": command, "entries": names, "files": files,
		"root": rootMetadata, "mountinfo": mountinfo, "parentFsynced": false}
}

// This exec is started before ordinary admission closes. It accepts one fixed
// byte only over its already-owned stdin; no new exec is needed after Arm.
func rootSnapshot() map[string]any {
	const name = "rtm103-root-object"
	mountinfo := managedMountinfo([]string{"/data", "/other"})
	roots := make(map[string]any)
	for _, path := range []string{"/data", "/other"} {
		fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NOATIME, 0)
		must(err)
		root := os.NewFile(uintptr(fd), "/proc/self/fd/"+strconv.Itoa(fd))
		defer root.Close()
		var before syscall.Stat_t
		must(syscall.Fstat(fd, &before))
		names := entries(root)
		if len(names) != 1 || names[0] != name {
			panic("exclusive root object required")
		}
		file := retainedOpen(root, name, false)
		defer file.Close()
		var original, after syscall.Stat_t
		must(syscall.Fstat(int(file.Fd()), &original))
		if original.Size != 32 || original.Dev != before.Dev {
			panic("fixed same-mount root object required")
		}
		object := retainedMetadata(file, true)
		must(syscall.Fstat(int(file.Fd()), &after))
		if !reflect.DeepEqual(original, after) {
			panic("root object changed during independent read")
		}
		rootMetadata := retainedMetadata(root, false)
		must(syscall.Fstat(fd, &after))
		if !reflect.DeepEqual(before, after) {
			panic("root directory changed during independent read")
		}
		roots[path] = map[string]any{"entries": names, "root": rootMetadata, "object": object}
		must(file.Close())
		must(root.Close())
	}
	return map[string]any{"command": "root-snapshot", "roots": roots, "mountinfo": mountinfo, "completed": true}
}

// superviseReader owns the prestarted snapshot child through actual Wait. The
// engine's exec status is fenced before Arm and cannot attest this guest join.
// This function is also executed by the engine-free subprocess regressions.
func superviseReader(child *exec.Cmd, output io.Writer) (failure error) {
	pipe, err := child.StdoutPipe()
	if err != nil {
		return err
	}
	if err = child.Start(); err != nil {
		_ = pipe.Close()
		return err
	}
	joined := false
	defer func() {
		if !joined {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	reader := bufio.NewReaderSize(pipe, 4096)
	ready, err := reader.ReadSlice('\n')
	if err != nil || !bytes.Equal(ready, []byte("{\"ready\":true}\n")) || reader.Buffered() != 0 {
		return errors.New("reader readiness rejected")
	}
	pid := child.Process.Pid
	if err = json.NewEncoder(output).Encode(struct {
		Ready bool `json:"ready"`
		PID   int  `json:"readerPID"`
	}{true, pid}); err != nil {
		return err
	}
	const maximum = 120000
	raw, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil || len(raw) == 0 || len(raw) > maximum {
		return errors.New("reader output bound")
	}
	err = child.Wait()
	joined = true
	if err != nil || child.ProcessState == nil || !child.ProcessState.Exited() || !child.ProcessState.Success() {
		return errors.New("reader did not exit successfully")
	}
	var snapshot map[string]json.RawMessage
	if json.Unmarshal(raw, &snapshot) != nil || snapshot == nil {
		return errors.New("reader snapshot rejected")
	}
	return json.NewEncoder(output).Encode(struct {
		Version  int             `json:"version"`
		PID      int             `json:"readerPID"`
		ExitCode int             `json:"exitCode"`
		Snapshot json.RawMessage `json:"snapshot"`
	}{1, pid, child.ProcessState.ExitCode(), json.RawMessage(raw)})
}

func retainedWait(command string) {
	// One budget begins before child startup. A blocked syscall is never joined
	// by this timer: nonzero wrapper exit forces the runner's owned VM containment.
	timer := time.AfterFunc(10*time.Second, func() { os.Exit(124) })
	defer timer.Stop()
	child := exec.Command("/proc/self/exe", command+"-child")
	child.Stdin, child.Stderr = os.Stdin, os.Stderr
	must(superviseReader(child, os.Stdout))
}

func retainedWaitChild(command string) {
	must(json.NewEncoder(os.Stdout).Encode(map[string]bool{"ready": true}))
	token := make([]byte, 1)
	_, err := io.ReadFull(os.Stdin, token)
	must(err)
	if token[0] != 0x01 {
		panic("fixed baseline trigger required")
	}
	if command == "root-wait-child" {
		must(json.NewEncoder(os.Stdout).Encode(rootSnapshot()))
	} else {
		must(json.NewEncoder(os.Stdout).Encode(retained("retained-snapshot")))
	}
}

func main() {
	if len(os.Args) != 2 {
		panic("fixed command required")
	}
	command := os.Args[1]
	if command == "serve" {
		for {
			time.Sleep(time.Hour)
		} // no synthetic PREPARE deadline or self-exit
	}
	if command == "retained-wait" || command == "root-wait" {
		retainedWait(command)
		return
	}
	if command == "retained-wait-child" || command == "root-wait-child" {
		retainedWaitChild(command)
		return
	}
	if command == "root-snapshot" {
		must(json.NewEncoder(os.Stdout).Encode(rootSnapshot()))
		return
	}
	if command == "retained-snapshot" || command == "retained-write" {
		must(json.NewEncoder(os.Stdout).Encode(retained(command)))
		return
	}
	if command != "snapshot" && command != "empty" && command != "writer" {
		panic("fixed command required")
	}
	root := open("/data", true)
	defer root.Close()
	before := entries(root)
	if len(before) != 2 || before[0] != "a" || before[1] != "z" {
		panic("exact initial tree required")
	}
	files := make(map[string]any)
	for _, name := range before {
		file := open("/data/"+name, false)
		files[name] = metadata(file, true)
		must(file.Close())
	}
	if command == "writer" {
		writer(root)
		must(root.Close())
		root = open("/data", true)
		defer root.Close()
		before = entries(root)
		if len(before) != 2 || before[0] != "a" || before[1] != "z" {
			panic("writer must preserve exact original tree")
		}
		after := make(map[string]any)
		for _, name := range before {
			file := open("/data/"+name, false)
			after[name] = metadata(file, true)
			must(file.Close())
		}
		if !reflect.DeepEqual(files, after) {
			panic("writer changed original file bytes or metadata")
		}
		files = after // Report fresh observations, not the pre-write snapshot.
	}
	if command == "empty" {
		// These are runtime-mounted volume files, never image source paths.
		must(syscall.Unlinkat(int(root.Fd()), "a"))
		must(syscall.Unlinkat(int(root.Fd()), "z"))
		must(root.Sync())
		must(root.Close())
		root = open("/data", true)
		defer root.Close()
		before = entries(root)
		if len(before) != 0 {
			panic("empty directory required")
		}
		files = make(map[string]any)
	}
	mount, err := os.Open("/proc/self/mountinfo")
	must(err)
	defer mount.Close()
	raw, err := io.ReadAll(io.LimitReader(mount, 65537))
	must(err)
	if len(raw) > 65536 {
		panic("mountinfo bound")
	}
	result := map[string]any{"command": command, "entries": before, "files": files,
		"root": metadata(root, false), "mountinfo": string(raw), "parentFsynced": command == "empty" || command == "writer"}
	must(json.NewEncoder(os.Stdout).Encode(result))
}

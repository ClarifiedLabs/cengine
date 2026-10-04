//go:build linux

// Offline, stdlib-only bounded reference fixture. read/splice/mmap NEVER stat
// their input before the first read (same contract as bind-reopen.go).
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const maxBytes = 1024 * 1024

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func check(ok bool, text string) {
	if !ok {
		panic(text)
	}
}
func emit(value any) { must(json.NewEncoder(os.Stdout).Encode(value)) }
func summary(data []byte) map[string]any {
	sum := sha256.Sum256(data)
	return map[string]any{"size": len(data), "sha256": hex.EncodeToString(sum[:])}
}

// Raw syscalls avoid os.ReadFile's pre-read fstat and any cache-repair retry.
func rawRead(path string) []byte {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	must(err)
	defer syscall.Close(fd)
	return readFD(fd)
}
func readFD(fd int) []byte {
	data := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		n, err := syscall.Read(fd, buf)
		if err == syscall.EINTR {
			continue
		}
		must(err)
		if n == 0 {
			return data
		}
		check(len(data)+n <= maxBytes, "read bound exceeded")
		data = append(data, buf[:n]...)
	}
}
func reopened(mode, path string, length int) []byte {
	check(length >= 0 && length <= maxBytes, "length bound")
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	must(err)
	defer syscall.Close(fd)
	if mode == "read" {
		return readFD(fd)
	}
	if mode == "mmap" {
		data := []byte{}
		if length > 0 {
			mapping, err := syscall.Mmap(fd, 0, length, syscall.PROT_READ, syscall.MAP_SHARED)
			must(err)
			data = append(data, mapping...)
			must(syscall.Munmap(mapping))
		}
		_, err = syscall.Seek(fd, int64(length), 0)
		must(err)
		// Check actual EOF AFTER faulting every mapped byte, including empty.
		tail := readFD(fd)
		check(len(data)+len(tail) <= maxBytes, "mmap output bound")
		return append(data, tail...)
	}
	check(mode == "splice", "reader mode")
	pipe := make([]int, 2)
	must(syscall.Pipe2(pipe, syscall.O_CLOEXEC))
	defer syscall.Close(pipe[0])
	defer syscall.Close(pipe[1])
	data := []byte{}
	buf := make([]byte, 4096)
	for {
		n, err := syscall.Splice(fd, nil, pipe[1], nil, len(buf), 0)
		if err == syscall.EINTR {
			continue
		}
		must(err)
		if n == 0 {
			return data
		}
		check(len(data)+int(n) <= maxBytes, "splice output bound")
		for remaining := int(n); remaining > 0; {
			count, err := syscall.Read(pipe[0], buf[:remaining])
			if err == syscall.EINTR {
				continue
			}
			must(err)
			check(count > 0, "short splice pipe")
			data = append(data, buf[:count]...)
			remaining -= count
		}
	}
}
func syncPath(path string) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	must(err)
	defer syscall.Close(fd)
	must(syscall.Fsync(fd))
}
func writeNew(path string, data []byte) {
	check(len(data) <= maxBytes, "write bound")
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	must(err)
	f := os.NewFile(uintptr(fd), path)
	n, err := f.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	must(err)
	must(closeErr)
	syncPath(filepath.Dir(path))
}
func backend(root string) map[string]any {
	var fs syscall.Statfs_t
	must(syscall.Statfs(root, &fs))
	var uts syscall.Utsname
	must(syscall.Uname(&uts))
	release := []byte{}
	for _, c := range uts.Release {
		if c == 0 {
			break
		}
		release = append(release, byte(c))
	}
	return map[string]any{"statfs": fmt.Sprintf("%x", fs.Type), "mountinfo": string(rawRead("/proc/self/mountinfo")), "kernel": string(release), "boot_id": strings.TrimSpace(string(rawRead("/proc/sys/kernel/random/boot_id")))}
}
func payload(token, name string) []byte {
	switch name {
	case "empty":
		return []byte{}
	case "small":
		return []byte(token + "\x00durable\xff\n")
	case "page":
		return bytes.Repeat([]byte(token+"|"), 113)
	case "large":
		return bytes.Repeat([]byte(token+"|"), 16000)
	}
	panic("unknown payload")
}

var names = []string{"empty", "small", "page", "large"}
var attrs = map[string][]byte{"user.volume-reference": {'r', 0, 255}, "user.volume-reference-empty": {}}

func inspectSeed(root, token string) map[string]any {
	// Read-only verification: no chmod, sync, setxattr, create, or repair here.
	expected := map[string]bool{"data": true, "hard": true, "literal": true}
	entries, err := os.ReadDir(root)
	must(err)
	check(len(entries) == len(expected), "unexpected root namespace")
	for _, entry := range entries {
		check(expected[entry.Name()], "unexpected root name")
	}
	children, err := os.ReadDir(filepath.Join(root, "data"))
	must(err)
	check(len(children) == len(names), "unexpected data namespace")
	files := map[string]any{}
	for _, name := range names {
		path := filepath.Join(root, "data", name)
		data := rawRead(path)
		check(bytes.Equal(data, payload(token, name)), "checksum mismatch: "+name)
		var st syscall.Stat_t
		must(syscall.Lstat(path, &st))
		check(st.Mode&syscall.S_IFMT == syscall.S_IFREG && st.Mode&0777 == 0600, "file metadata mismatch")
		files[name] = map[string]any{"content": summary(data), "mode": st.Mode, "uid": st.Uid, "gid": st.Gid, "nlink": st.Nlink, "ino": st.Ino}
	}
	var first, hard, dir syscall.Stat_t
	must(syscall.Lstat(filepath.Join(root, "data", "large"), &first))
	must(syscall.Lstat(filepath.Join(root, "hard"), &hard))
	must(syscall.Lstat(filepath.Join(root, "data"), &dir))
	check(first.Ino == hard.Ino && first.Dev == hard.Dev && first.Nlink == 2 && hard.Mode == first.Mode, "hardlink mismatch")
	check(dir.Mode&syscall.S_IFMT == syscall.S_IFDIR && dir.Mode&0777 == 0700, "directory metadata mismatch")
	target, err := os.Readlink(filepath.Join(root, "literal"))
	must(err)
	check(target == "data/../data/small", "literal symlink mismatch")
	observed := map[string]string{}
	for key, want := range attrs {
		buf := make([]byte, 128)
		n, err := syscall.Getxattr(root, key, buf)
		must(err)
		check(bytes.Equal(buf[:n], want), "root xattr mismatch")
		observed[key] = base64.StdEncoding.EncodeToString(buf[:n])
	}
	var st syscall.Stat_t
	must(syscall.Lstat(root, &st))
	return map[string]any{"token": token, "files": files, "root_xattrs": observed, "root_mode": st.Mode, "root_uid": st.Uid, "root_gid": st.Gid, "directory_mode": dir.Mode, "symlink": target, "hardlink": true}
}
func seed(root, token string) map[string]any {
	proof := backend(root)
	check(proof["statfs"] == "ef53", "seed requires actual ext4")
	entries, err := os.ReadDir(root)
	must(err)
	check(len(entries) == 0, "seed requires empty NEW volume; never retry")
	temp := filepath.Join(root, "pending")
	must(os.Mkdir(temp, 0700))
	for _, name := range names {
		writeNew(filepath.Join(temp, name), payload(token, name))
	}
	syncPath(temp)
	must(os.Rename(temp, filepath.Join(root, "data")))
	syncPath(root)
	must(os.Link(filepath.Join(root, "data", "large"), filepath.Join(root, "hard")))
	must(os.Symlink("data/../data/small", filepath.Join(root, "literal")))
	for key, value := range attrs {
		must(syscall.Setxattr(root, key, value, 1))
	}
	syncPath(filepath.Join(root, "data", "large"))
	syncPath(filepath.Join(root, "data"))
	syncPath(root)
	return map[string]any{"ACK": true, "manifest": inspectSeed(root, token), "backend": proof, "operation_bytes": len(payload(token, "small")) + len(payload(token, "page")) + len(payload(token, "large"))}
}
func pathArg(root, name string) string {
	check(name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\\\x00"), "single owned filename required")
	return filepath.Join(root, name)
}
func run() {
	check(len(os.Args) >= 2, "mode required")
	mode := os.Args[1]
	if mode == "serve" {
		check(len(os.Args) == 2, "serve arguments")
		time.Sleep(590 * time.Second)
		return
	}
	check(len(os.Args) >= 3, "root required")
	root := os.Args[2]
	check(root == "/work", "only /work is authorized")
	switch mode {
	case "backend":
		check(len(os.Args) == 3, "backend arguments")
		emit(backend(root))
	case "read", "splice", "mmap":
		check(len(os.Args) == 5, "read arguments")
		n, err := strconv.Atoi(os.Args[4])
		must(err)
		emit(summary(reopened(mode, pathArg(root, os.Args[3]), n)))
	case "write":
		check(len(os.Args) == 5, "write arguments")
		data, err := base64.StdEncoding.DecodeString(os.Args[4])
		must(err)
		writeNew(pathArg(root, os.Args[3]), data)
		emit(summary(data))
	case "sync":
		check(len(os.Args) == 3, "sync arguments")
		syncPath(root)
		emit(map[string]bool{"synced": true})
	case "namespace":
		check(len(os.Args) == 3, "namespace arguments")
		check(string(rawRead(pathArg(root, "renamed"))) == "namespace", "host rename not visible")
		_, err := syscall.Open(pathArg(root, "removed"), syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
		check(err == syscall.ENOENT, "host unlink not visible")
		target, err := os.Readlink(pathArg(root, "literal"))
		must(err)
		check(target == "./renamed", "host literal symlink")
		must(os.Rename(pathArg(root, "renamed"), pathArg(root, "guest-renamed")))
		must(os.Remove(pathArg(root, "literal")))
		must(os.Symlink("./guest-renamed", pathArg(root, "guest-literal")))
		syncPath(root)
		emit(map[string]bool{"namespace": true})
	case "seed", "verify":
		check(len(os.Args) == 4 && len(os.Args[3]) == 36, "token arguments")
		if mode == "seed" {
			emit(seed(root, os.Args[3]))
			return
		}
		proof := backend(root)
		check(proof["statfs"] == "ef53", "verify requires actual ext4")
		emit(map[string]any{"verified": true, "manifest": inspectSeed(root, os.Args[3]), "backend": proof})
	default:
		panic("unsupported mode")
	}
}
func main() {
	defer func() {
		if err := recover(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}()
	if len(os.Args) < 2 || os.Args[1] != "serve" {
		time.AfterFunc(50*time.Second, func() { os.Exit(124) })
	}
	run()
}

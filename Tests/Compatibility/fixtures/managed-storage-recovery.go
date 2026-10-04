// RTM-079: linked durable ACK, never open-unlink or physical power-loss proof.
// Offline Linux/arm64 fixture; fixed operations and bounded output only.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func metadata(f *os.File) map[string]any {
	info, err := f.Stat()
	must(err)
	st := info.Sys().(*syscall.Stat_t)
	return map[string]any{"mode": uint32(st.Mode), "uid": st.Uid, "gid": st.Gid,
		"nlink": st.Nlink, "size": st.Size, "mtime": st.Mtim.Sec}
}
func main() {
	if len(os.Args) != 2 {
		panic("fixed command required")
	}
	time.AfterFunc(165*time.Second, func() { os.Exit(124) })
	command := os.Args[1]
	worker := strings.HasPrefix(command, "worker-")
	if worker {
		command = strings.TrimPrefix(command, "worker-")
	}
	if command == "serve" {
		select {}
	}
	if command != "ack" && command != "verify" && command != "write" && !(worker && command == "ack-peer") {
		panic("command not allowed")
	}
	root, err := os.Open("/data")
	must(err)
	defer root.Close()
	if command == "ack" || command == "write" {
		flags := os.O_WRONLY | os.O_TRUNC
		data := []byte("rtm079-post-recovery-write\n")
		if command == "ack" {
			flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
			data = []byte("rtm079-acknowledged-linked-payload\n")
		}
		if worker {
			data = []byte("rtm084-post-worker-write\n")
			if command == "ack" {
				must(os.Link("/data/seed", "/data/payload"))
				data = []byte("rtm084-acknowledged-hardlink-payload\n")
			}
			flags = os.O_WRONLY | os.O_TRUNC
		}
		file, err := os.OpenFile("/data/payload", flags|syscall.O_NOFOLLOW, 0600)
		must(err)
		n, err := file.Write(data)
		must(err)
		if n != len(data) {
			panic("short write")
		}
		must(file.Chown(10001, 10002))
		must(file.Chmod(0640))
		stamp := []syscall.Timespec{{Sec: 1700000000}, {Sec: 1700000000}}
		must(syscall.UtimesNano("/data/payload", stamp))
		if worker {
			for _, path := range []string{"/data", "/data/payload"} {
				must(syscall.Setxattr(path, "user.rtm084.binary", []byte{0, 255, 128, 'r', 't', 'm', '0', '8', '4'}, 0))
				must(syscall.Setxattr(path, "user.rtm084.empty", []byte{}, 0))
			}
			must(syscall.UtimesNano("/data", stamp))
		}
		must(file.Sync()) // ACK includes the linked file AND containing directory.
		must(root.Sync())
		must(file.Close())
	}
	entries, err := root.Readdirnames(17)
	if err != nil && err != io.EOF {
		panic(err)
	}
	if len(entries) > 16 {
		panic("directory bound")
	}
	sort.Strings(entries)
	file, err := os.OpenFile("/data/payload", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	must(err)
	defer file.Close()
	if worker && command == "ack-peer" {
		must(file.Sync())
		must(root.Sync())
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	must(err)
	if len(data) > 4096 {
		panic("payload bound")
	}
	hash := sha256.Sum256(data)
	mount, err := os.Open("/proc/self/mountinfo")
	must(err)
	defer mount.Close()
	raw, err := io.ReadAll(io.LimitReader(mount, 65537))
	must(err)
	if len(raw) > 65536 {
		panic("mountinfo bound")
	}
	acknowledged := command == "ack" || command == "write" || worker && command == "ack-peer"
	result := map[string]any{"command": command, "ack": acknowledged,
		"file_fsynced": acknowledged, "parent_fsynced": acknowledged,
		"entries": entries, "root": metadata(root), "file": metadata(file), "sha256": hex.EncodeToString(hash[:]), "mountinfo": string(raw)}
	if worker {
		result["command"] = "worker-" + command
		result["root_xattrs"] = xattrs("/data")
		result["file_xattrs"] = xattrs("/data/payload")
		seed, err := os.OpenFile("/data/seed", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		must(err)
		defer seed.Close()
		seedData, err := io.ReadAll(io.LimitReader(seed, 4097))
		must(err)
		if len(seedData) > 4096 {
			panic("seed bound")
		}
		seedHash := sha256.Sum256(seedData)
		result["seed"] = metadata(seed)
		result["seed_sha256"] = hex.EncodeToString(seedHash[:])
		for key, f := range map[string]*os.File{"inode": file, "seed_inode": seed} {
			info, err := f.Stat()
			must(err)
			result[key] = info.Sys().(*syscall.Stat_t).Ino
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "encode failed")
		os.Exit(1)
	}
}

// Fixed user namespaces only; preserve raw binary bytes and a present empty value.
func xattrs(path string) map[string][]byte {
	result := map[string][]byte{}
	for _, name := range []string{"user.rtm084.binary", "user.rtm084.empty"} {
		value := make([]byte, 128)
		n, err := syscall.Getxattr(path, name, value)
		must(err)
		result[name] = value[:n]
	}
	return result
}

// RTM-078: fixed operations only; descriptors belong to the two workload processes.
// Built offline for Linux by the compatibility test, never executed on the host.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
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
func snapshot(held *os.File) map[string]any {
	root, err := os.Open("/data")
	must(err)
	defer root.Close()
	entries, err := root.Readdirnames(16)
	if err != nil && err != io.EOF {
		panic(err)
	}
	if entries == nil {
		entries = []string{}
	}
	result := map[string]any{"root": metadata(root), "entries": entries}
	mount, err := os.Open("/proc/self/mountinfo")
	must(err)
	raw, err := io.ReadAll(io.LimitReader(mount, 65537))
	mount.Close()
	must(err)
	if len(raw) > 65536 {
		panic("mountinfo bound")
	}
	result["mountinfo"] = string(raw)
	file := held
	if file == nil {
		file, err = os.Open("/data/seed")
		if os.IsNotExist(err) {
			return result
		}
		must(err)
		defer file.Close()
	}
	result["file"] = metadata(file)
	data := make([]byte, 4097)
	n, err := file.ReadAt(data, 0)
	if err != nil && err != io.EOF {
		panic(err)
	}
	if n > 4096 {
		panic("data bound")
	}
	hash := sha256.Sum256(data[:n])
	result["sha256"] = hex.EncodeToString(hash[:])
	return result
}
func main() {
	if len(os.Args) != 2 {
		panic("fixed command required")
	}
	if os.Args[1] != "serve" {
		deadline := time.Now().Add(3 * time.Second)
		var conn net.Conn
		var err error
		for time.Now().Before(deadline) {
			conn, err = net.DialTimeout("unix", "/run/probe.sock", time.Until(deadline))
			if err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		must(err)
		defer conn.Close()
		must(conn.SetDeadline(deadline))
		_, err = fmt.Fprintln(conn, os.Args[1])
		must(err)
		var result json.RawMessage
		must(json.NewDecoder(io.LimitReader(conn, 131072)).Decode(&result))
		must(json.NewEncoder(os.Stdout).Encode(result))
		return
	}
	listener, err := net.Listen("unix", "/run/probe.sock")
	must(err)
	defer listener.Close()
	// A stuck filesystem syscall cannot keep the test process alive indefinitely.
	time.AfterFunc(80*time.Second, func() { os.Exit(124) })
	var held *os.File
	defer func() {
		if held != nil {
			held.Close()
		}
	}()
	for {
		conn, err := listener.Accept()
		must(err)
		must(conn.SetDeadline(time.Now().Add(3 * time.Second)))
		var command string
		_, err = fmt.Fscanln(io.LimitReader(conn, 32), &command)
		must(err)
		switch command {
		case "snapshot":
		case "open":
			if held != nil {
				panic("duplicate open")
			}
			held, err = os.OpenFile("/data/seed", os.O_RDWR, 0)
			must(err)
		case "unlink":
			must(syscall.Unlink("/data/seed"))
		case "write":
			if held == nil {
				panic("missing fd")
			}
			_, err = held.WriteAt([]byte("retained-write\n"), 0)
			must(err)
			must(held.Truncate(15))
			must(held.Sync())
		case "close":
			if held == nil {
				panic("missing fd")
			}
			must(held.Close())
			held = nil
		default:
			panic("command not allowed")
		}
		err = json.NewEncoder(conn).Encode(snapshot(held))
		conn.Close()
		must(err)
	}
}

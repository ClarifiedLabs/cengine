// Stdlib-only scratch-image fixture. Control traffic never uses the tested volume.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type request struct {
	Op   string `json:"op"`
	Kind string `json:"kind"`
	Path string `json:"path"`
}

func lock(file *os.File, kind string) error {
	switch kind {
	case "flock":
		return syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	case "fcntl":
		region := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0, Start: 0, Len: 0}
		return syscall.FcntlFlock(file.Fd(), syscall.F_SETLK, &region)
	default:
		return fmt.Errorf("unknown lock kind %q", kind)
	}
}

func outcome(err error) map[string]any {
	result := map[string]any{"errno": 0}
	if err != nil {
		var number syscall.Errno
		if errors.As(err, &number) {
			result["errno"] = int(number)
		} else {
			result["error"] = err.Error()
		}
	}
	return result
}

func acquire(kind, path string) (*os.File, map[string]any) {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err == nil {
		err = lock(file, kind)
		if err != nil {
			file.Close()
			file = nil
		}
	}
	return file, outcome(err)
}

func serve(socket string) error {
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	idle := time.AfterFunc(10*time.Minute, func() {
		fmt.Fprintln(os.Stderr, "lock owner idle lease expired")
		os.Exit(124)
	})
	defer idle.Stop()
	var held *os.File
	defer func() {
		if held != nil {
			held.Close()
		}
	}()
	fmt.Println(`{"ready":true}`) // Docker logs: out-of-band readiness evidence.
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		idle.Reset(10 * time.Minute)
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		var input request
		result := map[string]any{}
		if err = json.NewDecoder(io.LimitReader(conn, 4096)).Decode(&input); err != nil {
			result["error"] = err.Error()
		} else {
			switch input.Op {
			case "status":
				result["held"] = held != nil
			case "lock":
				if held != nil {
					result["error"] = "owner already holds a lock"
				} else {
					held, result = acquire(input.Kind, input.Path)
				}
			case "release":
				if held != nil {
					err = held.Close() // releases both flock and process-associated fcntl
					held = nil
				}
				result = outcome(err)
			default:
				result["error"] = "unknown control request"
			}
		}
		json.NewEncoder(conn).Encode(result)
		conn.Close()
	}
}

func mountinfo() error {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil {
		return err
	}
	if len(data) > 65536 {
		return fmt.Errorf("mountinfo exceeds bound")
	}
	return json.NewEncoder(os.Stdout).Encode(string(data))
}

func snapshot(root string) error {
	entries := map[string]any{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if len(entries) >= 300 {
			return fmt.Errorf("unexpected tree size")
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		stat := info.Sys().(*syscall.Stat_t)
		entry := map[string]any{"uid": stat.Uid, "gid": stat.Gid, "mode": stat.Mode & 07777}
		if info.IsDir() {
			entry["type"] = "directory"
		} else if info.Mode().IsRegular() && info.Size() <= 4096 {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			entry["type"], entry["sha256"] = "file", fmt.Sprintf("%x", sha256.Sum256(data))
		} else {
			return fmt.Errorf("unexpected entry %s", name)
		}
		entries[name] = entry
		return nil
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(entries)
}

func run() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("expected serve/request/try/snapshot and arguments")
	}
	switch os.Args[1] {
	case "serve":
		return serve(os.Args[2])
	case "request":
		if len(os.Args) != 4 {
			return fmt.Errorf("request requires socket and JSON")
		}
		deadline := time.Now().Add(5 * time.Second)
		var conn net.Conn
		var err error
		for time.Now().Before(deadline) {
			conn, err = net.DialTimeout("unix", os.Args[2], time.Second)
			if err == nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if err != nil {
			return err
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := fmt.Fprintln(conn, os.Args[3]); err != nil {
			return err
		}
		_, err = io.Copy(os.Stdout, io.LimitReader(conn, 4096))
		return err
	case "try":
		if len(os.Args) != 4 {
			return fmt.Errorf("try requires kind and path")
		}
		file, result := acquire(os.Args[2], os.Args[3])
		if file != nil {
			defer file.Close()
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	case "snapshot":
		// Proof is separate; the exact tree remains the final JSON record.
		if err := mountinfo(); err != nil {
			return err
		}
		return snapshot(os.Args[2])
	case "mountinfo":
		return mountinfo()
	case "mounts":
		data, err := os.ReadFile("/proc/mounts")
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(string(data))
	default:
		return fmt.Errorf("unknown operation")
	}
}

func watchdogLimit(operation string) time.Duration {
	switch operation {
	case "snapshot":
		return 45 * time.Second // DGN-003 full metadata/checksum completion calibration.
	case "serve":
		return 2 * time.Hour // Hard bound in addition to the renewable 10-minute idle lease.
	default:
		return 20 * time.Second
	}
}

func main() {
	operation := ""
	if len(os.Args) > 1 {
		operation = os.Args[1]
	}
	time.AfterFunc(watchdogLimit(operation), func() {
		fmt.Fprintln(os.Stderr, "volume-lock fixture deadline exceeded")
		os.Exit(124)
	})
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
